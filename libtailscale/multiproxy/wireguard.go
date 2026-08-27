package multiproxy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// WireGuard upstream: a userspace WireGuard tunnel terminated in-process.
//
// This is the second real transport behind the Provider interface, and exists as
// much to prove the abstraction generalises as to be useful on its own. It
// reuses the wireguard-go the Tailscale core already depends on, so it adds no
// new module to the build.
//
// The tunnel gets its own gVisor netstack, entirely separate from the one that
// serves the TUN. Flows arriving from the device are re-originated into this
// second stack, which is the same shape as the tailnet upstreams: terminate,
// then re-originate.

// WireGuardPeer is one peer in a WireGuard tunnel.
type WireGuardPeer struct {
	// PublicKey is the peer's public key, base64 as it appears in a wg config.
	PublicKey string
	// PresharedKey is optional, base64.
	PresharedKey string
	// Endpoint is the peer's host:port.
	Endpoint string
	// AllowedIPs are the prefixes routed to this peer. For an upstream carrying
	// general traffic this is usually 0.0.0.0/0 and ::/0.
	AllowedIPs []netip.Prefix
	// PersistentKeepalive is in seconds; 0 disables it. Behind NAT, 25 is the
	// conventional value.
	PersistentKeepalive uint16
}

// WireGuardConfig describes a WireGuard upstream.
type WireGuardConfig struct {
	ID UpstreamID
	// PrivateKey is this end's private key, base64 as it appears in a wg config.
	PrivateKey string
	// Addresses are the tunnel-local addresses assigned to this end.
	Addresses []netip.Addr
	// DNS servers reachable inside the tunnel. Optional; the multiproxy resolver
	// handles DNS itself, so this only matters for lookups made by the tunnel's
	// own netstack.
	DNS []netip.Addr
	// MTU defaults to 1420, the usual WireGuard value, when zero.
	MTU int
	// ListenPort is the UDP port the tunnel binds locally. Zero picks a random
	// one, which is what a client wants: it only ever initiates, and a fixed
	// port would just be a stable fingerprint. Set it when peers must be able to
	// reach this end unprompted - which requires a bind that actually listens,
	// so it is ignored by Engine.NewWireGuardUpstream.
	ListenPort uint16
	// Via names another upstream to carry this tunnel's own packets, chaining
	// it behind that one. Empty means handshakes and transport messages leave
	// from the device. Build with Engine.NewWireGuardUpstream to have it
	// resolved. See chain.go and wireguard_bind.go.
	Via UpstreamID

	Peers []WireGuardPeer
}

type wireguardProvider struct {
	id    UpstreamID
	via   UpstreamID
	dev   *device.Device
	stack *stack.Stack
	tun   *wgNetTun

	mu     sync.Mutex
	closed bool
}

// wgKeyToHex converts a base64 WireGuard key to the hex form the UAPI expects.
func wgKeyToHex(key, what string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return "", fmt.Errorf("wireguard: %s is not valid base64: %w", what, err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("wireguard: %s must be 32 bytes, got %d", what, len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// uapiConfig renders the configuration in wireguard-go's IpcSet format.
func (cfg WireGuardConfig) uapiConfig() (string, error) {
	privHex, err := wgKeyToHex(cfg.PrivateKey, "private key")
	if err != nil {
		return "", err
	}

	// Device-level settings must all precede the first peer: IpcSet applies
	// lines in order, and anything after a public_key= belongs to that peer.
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if cfg.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}

	for i, p := range cfg.Peers {
		pubHex, err := wgKeyToHex(p.PublicKey, fmt.Sprintf("peer %d public key", i))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "public_key=%s\n", pubHex)

		if p.PresharedKey != "" {
			pskHex, err := wgKeyToHex(p.PresharedKey, fmt.Sprintf("peer %d preshared key", i))
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", pskHex)
		}
		if p.Endpoint != "" {
			if _, _, err := net.SplitHostPort(p.Endpoint); err != nil {
				return "", fmt.Errorf("wireguard: peer %d endpoint %q: %w", i, p.Endpoint, err)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		for _, ip := range p.AllowedIPs {
			if !ip.IsValid() {
				return "", fmt.Errorf("wireguard: peer %d has an invalid allowed IP", i)
			}
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
		}
	}
	return b.String(), nil
}

// endpointResolveTimeout bounds the name lookups done while bringing a tunnel
// up. It is generous because this runs once at configuration time, not on the
// datapath, and a slow resolver should not be mistaken for a bad config.
const endpointResolveTimeout = 10 * time.Second

// lookupEndpointIP resolves a peer endpoint host. It is a variable so tests can
// substitute one without a network.
var lookupEndpointIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveEndpoints returns a copy of cfg with every peer endpoint given as a
// literal address.
//
// wg-quick configs name their endpoint by host - that is what a provider hands
// out, and it is how the peer is found again after its address changes - but
// wireguard-go's UAPI takes only a literal, rejecting anything else with an
// opaque IPC error. So the lookup happens here, once, where it can be reported
// as what it is.
//
// The address is fixed for the life of the upstream. A peer that moves is not
// followed, because nothing re-runs this; reconfiguring the upstream does. That
// is the same bargain wg-quick makes, and acceptable for a client tunnel whose
// far end is a server.
func (cfg WireGuardConfig) resolveEndpoints() (WireGuardConfig, error) {
	needsLookup := false
	for _, p := range cfg.Peers {
		if p.Endpoint != "" {
			if _, err := netip.ParseAddrPort(p.Endpoint); err != nil {
				needsLookup = true
				break
			}
		}
	}
	if !needsLookup {
		return cfg, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), endpointResolveTimeout)
	defer cancel()

	peers := make([]WireGuardPeer, len(cfg.Peers))
	copy(peers, cfg.Peers)
	for i, p := range peers {
		if p.Endpoint == "" {
			continue
		}
		if _, err := netip.ParseAddrPort(p.Endpoint); err == nil {
			continue
		}
		host, port, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			return WireGuardConfig{}, fmt.Errorf("wireguard: peer %d endpoint %q: %w", i, p.Endpoint, err)
		}
		addrs, err := lookupEndpointIP(ctx, host)
		if err != nil {
			return WireGuardConfig{}, fmt.Errorf("wireguard: resolving peer %d endpoint %q: %w", i, host, err)
		}
		if len(addrs) == 0 {
			return WireGuardConfig{}, fmt.Errorf("wireguard: peer %d endpoint %q resolved to no addresses", i, host)
		}
		peers[i].Endpoint = net.JoinHostPort(addrs[0].Unmap().String(), port)
	}
	cfg.Peers = peers
	return cfg, nil
}

// NewWireGuardUpstream brings up a WireGuard tunnel and returns it as a
// Provider.
//
// bind supplies the UDP socket the tunnel uses to reach its peers; pass nil for
// the default. On Android it should be a bind whose sockets are
// VpnService-protected, or the tunnel's own packets would be routed back into
// the TUN they are meant to leave.
func NewWireGuardUpstream(cfg WireGuardConfig, bind conn.Bind, logf func(string, ...any)) (Provider, error) {
	if cfg.ID == "" {
		return nil, errors.New("wireguard: upstream needs an id")
	}
	if cfg.PrivateKey == "" {
		return nil, errors.New("wireguard: upstream needs a private key")
	}
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("wireguard: upstream needs at least one tunnel address")
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("wireguard: upstream needs at least one peer")
	}

	cfg, err := cfg.resolveEndpoints()
	if err != nil {
		return nil, err
	}

	uapi, err := cfg.uapiConfig()
	if err != nil {
		return nil, err
	}

	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1420
	}

	tunDev, tstack, err := newWireGuardNetTun(cfg.Addresses, mtu)
	if err != nil {
		return nil, err
	}

	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { logf("wireguard/"+string(cfg.ID)+": "+format, args...) },
		Errorf:   func(format string, args ...any) { logf("wireguard/"+string(cfg.ID)+": "+format, args...) },
	}

	dev := device.NewDevice(tunDev, bind, logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: applying configuration: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: bringing up device: %w", err)
	}

	return &wireguardProvider{id: cfg.ID, via: cfg.Via, dev: dev, stack: tstack, tun: tunDev}, nil
}

func (p *wireguardProvider) ID() UpstreamID     { return p.id }
func (p *wireguardProvider) Kind() UpstreamKind { return UpstreamKindWireGuard }
func (p *wireguardProvider) Via() UpstreamID    { return p.via }

func (p *wireguardProvider) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed
}

func (p *wireguardProvider) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	// Closing the device stops its goroutines and closes the TUN it was given,
	// which tears down the channel endpoint feeding the stack.
	p.dev.Close()
	return nil
}

// PeerPathInfo reports the tunnel's handshake state rather than a path, which is
// the nearest useful equivalent: a peer with no recent handshake is the
// WireGuard analogue of a relayed or dead path.
func (p *wireguardProvider) PeerPathInfo(context.Context, string) string {
	if !p.Ready() {
		return "unknown"
	}
	state, err := p.dev.IpcGet()
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(state, "\n") {
		if after, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if after != "0" {
				return "wireguard:established"
			}
			return "wireguard:no-handshake"
		}
	}
	return "wireguard"
}

func (p *wireguardProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("%w: wireguard %q", ErrUpstreamNotReady, p.id)
	}
	// The tunnel's netstack has no resolver of its own, and needs none: the
	// multiproxy DNS server has already resolved the name by the time the
	// datapath dials, so destinations always arrive as literal IP:port.
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("wireguard: destination %q must be a literal address:port: %w", address, err)
	}

	addr := ap.Addr().Unmap()
	proto := ipv6.ProtocolNumber
	if addr.Is4() {
		proto = ipv4.ProtocolNumber
	}
	full := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: ap.Port(),
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, p.stack, full, proto)
	case "udp", "udp4", "udp6":
		// No context-aware UDP dial exists, and none is needed: opening a UDP
		// endpoint on the netstack is bookkeeping, not a round trip.
		return gonet.DialUDP(p.stack, nil, &full, proto)
	default:
		return nil, fmt.Errorf("wireguard: unsupported network %q", network)
	}
}
