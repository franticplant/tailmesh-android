// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"golang.org/x/crypto/curve25519"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// wgKeypair returns a base64 private/public pair in the form a wg config uses.
func wgKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// The clamping wireguard-go applies internally; doing it here keeps the
	// public key we derive consistent with the one the device will use.
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sk[:]), base64.StdEncoding.EncodeToString(pk)
}

// newRealBind returns the UDP bind a device uses off the shelf, so the two test
// devices talk over a genuine socket rather than a stub. Which port it lands on
// is decided by WireGuardConfig.ListenPort, not here.
func newRealBind() conn.Bind { return conn.NewDefaultBind() }

// learningBind is a bind that reports where each packet came from.
//
// Stock WireGuard learns a peer's endpoint from the packets it receives, which
// is how a responder can reply to a client on an ephemeral port - or, in the
// chained case, to a SOCKS5 relay socket whose address nobody could have
// configured in advance. Tailscale's wireguard-go fork removes that learning
// because Tailscale picks endpoints itself, so a test acting as the responder
// has to put it back. It wraps a real bind and hands each source address to
// onSource, which the test turns into a UAPI endpoint update.
//
// Only the far end of these tests needs this. The upstream under test is always
// the initiator, with its peer endpoint configured, exactly as it is in the app.
type learningBind struct {
	conn.Bind
	onSource func(conn.Endpoint)
}

func (b *learningBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if eps[j] != nil && b.onSource != nil {
					b.onSource(eps[j])
				}
			}
			return n, err
		}
	}
	return wrapped, actual, nil
}

// newLearningResponder builds the far end of a tunnel: a device that learns its
// peer's endpoint the way stock WireGuard would. peerPub is the peer whose
// endpoint gets updated.
func newLearningResponder(t *testing.T, cfg WireGuardConfig, peerPub string) Provider {
	t.Helper()

	pubHex, err := wgKeyToHex(peerPub, "peer public key")
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}

	var (
		mu      sync.Mutex
		dev     *device.Device
		current string
	)
	bind := &learningBind{Bind: conn.NewDefaultBind(), onSource: func(ep conn.Endpoint) {
		src := ep.DstToString()
		mu.Lock()
		defer mu.Unlock()
		if dev == nil || src == current || src == "" {
			return
		}
		current = src
		// update_only keeps this from creating a peer if the key ever drifts.
		_ = dev.IpcSet("public_key=" + pubHex + "\nupdate_only=true\nendpoint=" + src + "\n")
	}}

	p, err := NewWireGuardUpstream(cfg, bind, testLogf(t, "responder"))
	if err != nil {
		t.Fatalf("responder upstream: %v", err)
	}
	mu.Lock()
	dev = p.(*wireguardProvider).dev
	mu.Unlock()
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// listenInTunnel starts a TCP echo server on a provider's tunnel-side netstack.
func listenInTunnel(t *testing.T, p Provider, addr netip.Addr, port uint16) {
	t.Helper()
	ln, err := gonet.ListenTCP(p.(*wireguardProvider).stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: port,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen inside tunnel: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
}

// echoThroughTunnel dials the far end's echo server and checks a round trip.
// The first dial can lose a race with the handshake, so it retries until ctx
// expires rather than flaking.
func echoThroughTunnel(t *testing.T, ctx context.Context, p Provider, target, msg string) {
	t.Helper()

	var (
		c   net.Conn
		err error
	)
	for {
		c, err = p.Dial(ctx, "tcp", target)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("dial %s through tunnel: %v", target, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("echoed %q, want %q", buf, msg)
	}
}

// freeUDPPort picks a port nothing is listening on. There is an unavoidable gap
// between releasing it and the device binding it, but a fixed port would collide
// far more often than that race fires.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probing for a free port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// testLogf routes device logging into the test output, where it is only shown
// for a failing test and is exactly what one needs when a handshake does not
// complete.
//
// A device's worker goroutines keep logging for a moment after Close returns,
// and testing panics on a log that arrives after the test finishes. The guard
// below is registered before anything that closes a device, so - cleanups being
// LIFO - it is the last thing to run and stragglers are dropped rather than
// crashing the run.
func testLogf(t *testing.T, who string) func(string, ...any) {
	t.Helper()

	var (
		mu   sync.Mutex
		done bool
	)
	t.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})

	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		t.Logf(who+": "+format, args...)
	}
}

func TestWireGuardConfigValidation(t *testing.T) {
	priv, pub := wgKeypair(t)
	valid := WireGuardConfig{
		ID:         "wg",
		PrivateKey: priv,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.0.2")},
		Peers: []WireGuardPeer{{
			PublicKey:  pub,
			Endpoint:   "127.0.0.1:51820",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	}

	tests := []struct {
		name string
		mut  func(*WireGuardConfig)
		want string
	}{
		{"no id", func(c *WireGuardConfig) { c.ID = "" }, "needs an id"},
		{"no key", func(c *WireGuardConfig) { c.PrivateKey = "" }, "needs a private key"},
		{"no address", func(c *WireGuardConfig) { c.Addresses = nil }, "tunnel address"},
		{"no peers", func(c *WireGuardConfig) { c.Peers = nil }, "at least one peer"},
		{"bad key", func(c *WireGuardConfig) { c.PrivateKey = "not base64!" }, "base64"},
		{"short key", func(c *WireGuardConfig) {
			c.PrivateKey = base64.StdEncoding.EncodeToString([]byte("too short"))
		}, "32 bytes"},
		{"bad peer endpoint", func(c *WireGuardConfig) { c.Peers[0].Endpoint = "no-port" }, "endpoint"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			cfg.Peers = append([]WireGuardPeer(nil), valid.Peers...)
			tt.mut(&cfg)
			_, err := NewWireGuardUpstream(cfg, nil, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestWireGuardUAPIConfig(t *testing.T) {
	priv, pub := wgKeypair(t)
	psk, _ := wgKeypair(t)

	cfg := WireGuardConfig{
		ID:         "wg",
		PrivateKey: priv,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.0.2")},
		Peers: []WireGuardPeer{{
			PublicKey:           pub,
			PresharedKey:        psk,
			Endpoint:            "203.0.113.7:51820",
			PersistentKeepalive: 25,
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		}},
	}

	uapi, err := cfg.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}

	privHex, _ := wgKeyToHex(priv, "")
	pubHex, _ := wgKeyToHex(pub, "")
	for _, want := range []string{
		"private_key=" + privHex,
		"public_key=" + pubHex,
		"endpoint=203.0.113.7:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("uapi config is missing %q\ngot:\n%s", want, uapi)
		}
	}
	// The private key has to come before any peer, which is what IpcSet
	// requires; a peer line first would be applied to no device key.
	if strings.Index(uapi, "private_key=") > strings.Index(uapi, "public_key=") {
		t.Error("private_key must precede the first peer")
	}
}

// ---------------------------------------------------------------------------
// upstreamBind
// ---------------------------------------------------------------------------

// TestUpstreamBindCarriesPacketsThroughDialer is the core chaining claim for
// WireGuard: the tunnel's own packets go out over whatever dialer it was given,
// and replies come back on the same flow.
func TestUpstreamBindCarriesPacketsThroughDialer(t *testing.T) {
	// A UDP echo server standing in for the peer.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()

	dialed := make(chan string, 4)
	b := newUpstreamBind(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed <- network + "|" + address
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	})

	fns, port, err := b.Open(51820)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	if port != 51820 {
		t.Errorf("Open reported port %d, want the requested 51820", port)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d receive funcs, want 1", len(fns))
	}

	peer := netip.MustParseAddrPort(pc.LocalAddr().String())
	ep, err := b.ParseEndpoint(peer.String())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}

	// A nonzero offset is the normal case: the device leaves room ahead of the
	// payload, and the bind must not send that padding.
	const offset = 4
	payload := append(make([]byte, offset), []byte("handshake")...)
	if err := b.Send([][]byte{payload}, ep, offset); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-dialed:
		if got != "udp|"+peer.String() {
			t.Fatalf("bind dialed %q, want udp|%s", got, peer)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bind never dialed the peer through the supplied dialer")
	}

	packets := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)

	recvDone := make(chan error, 1)
	go func() {
		_, err := fns[0](packets, sizes, eps)
		recvDone <- err
	}()

	select {
	case err := <-recvDone:
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if got := string(packets[0][:sizes[0]]); got != "echo:handshake" {
			t.Fatalf("received %q, want %q", got, "echo:handshake")
		}
		if eps[0] == nil || eps[0].DstToString() != peer.String() {
			t.Fatalf("receive reported endpoint %v, want %s", eps[0], peer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no packet came back through the bind")
	}
}

// TestUpstreamBindCloseUnblocksReceive checks the contract conn.Bind states
// explicitly: every ReceiveFunc must return net.ErrClosed after Close.
func TestUpstreamBindCloseUnblocksReceive(t *testing.T) {
	b := newUpstreamBind(nil)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- func() error {
			_, err := fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
			return err
		}()
	}()

	// Give the receive a moment to actually block before closing under it.
	time.Sleep(50 * time.Millisecond)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errCh:
		if err != net.ErrClosed {
			t.Fatalf("receive returned %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the receive func")
	}

	// Close is documented as safe to call more than once.
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestUpstreamBindSendFailsClosedWithoutParent(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	b := newUpstreamBind(e.chainDialer("missing", nil))
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()

	ep, err := b.ParseEndpoint("203.0.113.7:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if err := b.Send([][]byte{[]byte("x")}, ep, 0); err == nil {
		t.Fatal("sending through a missing chain parent should fail")
	}
}

// ---------------------------------------------------------------------------
// end-to-end tunnel
// ---------------------------------------------------------------------------

// TestWireGuardTunnelCarriesTCP stands up two WireGuard peers back to back over
// localhost and runs a TCP session between them. It proves the whole upstream
// works - the purpose-built gVisor TUN, the UAPI config, and Dial - rather than
// only its parts.
func TestWireGuardTunnelCarriesTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two WireGuard devices")
	}

	clientPriv, clientPub := wgKeypair(t)
	serverPriv, serverPub := wgKeypair(t)

	const (
		clientIP = "10.9.0.2"
		serverIP = "10.9.0.1"
		echoPort = 8080
	)
	serverPort := freeUDPPort(t)

	// The far end: a WireGuard device on localhost with a TCP echo server inside
	// the tunnel.
	server := newLearningResponder(t, WireGuardConfig{
		ID:         "wg-server",
		PrivateKey: serverPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(serverIP)},
		MTU:        1420,
		ListenPort: uint16(serverPort),
		Peers: []WireGuardPeer{{
			PublicKey:  clientPub,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + "/32")},
		}},
	}, clientPub)
	listenInTunnel(t, server, netip.MustParseAddr(serverIP), echoPort)

	client, err := NewWireGuardUpstream(WireGuardConfig{
		ID:         "wg-client",
		PrivateKey: clientPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(clientIP)},
		MTU:        1420,
		Peers: []WireGuardPeer{{
			PublicKey:           serverPub,
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix(serverIP + "/32")},
			PersistentKeepalive: 1,
		}},
	}, newRealBind(), testLogf(t, "client"))
	if err != nil {
		t.Fatalf("client upstream: %v", err)
	}
	defer client.Close()

	if !client.Ready() {
		t.Fatal("client upstream reports not ready")
	}
	if client.Kind() != UpstreamKindWireGuard {
		t.Fatalf("kind is %q", client.Kind())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	target := net.JoinHostPort(serverIP, strconv.Itoa(echoPort))
	echoThroughTunnel(t, ctx, client, target, "through the tunnel")

	if info := client.PeerPathInfo(ctx, serverIP); info != "wireguard:established" {
		t.Errorf("PeerPathInfo = %q, want wireguard:established", info)
	}

	// A closed upstream must refuse to dial rather than half-work.
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if client.Ready() {
		t.Fatal("closed upstream still reports ready")
	}
	if _, err := client.Dial(context.Background(), "tcp", target); err == nil {
		t.Fatal("closed upstream still dials")
	}
}

// TestWireGuardChainedOverSOCKS5 runs the same tunnel with its outer packets
// carried by a SOCKS5 UDP association - the chaining case, end to end.
func TestWireGuardChainedOverSOCKS5(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two WireGuard devices and a SOCKS5 proxy")
	}

	proxy := startTestSOCKS5(t)
	e := NewEngine(t.TempDir(), &MockCallback{})
	if _, err := e.AddUpstream(e.NewSOCKS5Upstream(SOCKS5Config{
		ID:      "proxy",
		Address: proxy.Addr(),
	}, nil)); err != nil {
		t.Fatalf("register proxy: %v", err)
	}

	clientPriv, clientPub := wgKeypair(t)
	serverPriv, serverPub := wgKeypair(t)

	const (
		clientIP = "10.9.1.2"
		serverIP = "10.9.1.1"
		echoPort = 8080
	)
	serverPort := freeUDPPort(t)

	server := newLearningResponder(t, WireGuardConfig{
		ID:         "wg-server",
		PrivateKey: serverPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(serverIP)},
		MTU:        1420,
		ListenPort: uint16(serverPort),
		Peers: []WireGuardPeer{{
			PublicKey:  clientPub,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + "/32")},
		}},
	}, clientPub)
	listenInTunnel(t, server, netip.MustParseAddr(serverIP), echoPort)

	// The client's Via points at the proxy, so its handshakes leave through the
	// SOCKS5 UDP association rather than from a socket of its own.
	client, err := e.NewWireGuardUpstream(WireGuardConfig{
		ID:         "wg-chained",
		Via:        "proxy",
		PrivateKey: clientPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(clientIP)},
		MTU:        1420,
		Peers: []WireGuardPeer{{
			PublicKey:           serverPub,
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix(serverIP + "/32")},
			PersistentKeepalive: 1,
		}},
	}, nil, testLogf(t, "client"))
	if err != nil {
		t.Fatalf("chained client upstream: %v", err)
	}
	defer client.Close()

	if via := providerVia(client); via != "proxy" {
		t.Fatalf("chained upstream reports via %q", via)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	echoThroughTunnel(t, ctx, client,
		net.JoinHostPort(serverIP, strconv.Itoa(echoPort)), "wireguard over socks5")
}

// ---------------------------------------------------------------------------
// config JSON
// ---------------------------------------------------------------------------

func TestParseWireGuardConfigJSON(t *testing.T) {
	cfg, err := ParseWireGuardConfigJSON("wg-home", `{
		"privateKey":"cHJpdmF0ZQ==",
		"addresses":["10.9.0.2/32"," fd00::2 "],
		"dns":["1.1.1.1"],
		"mtu":1380,
		"listenPort":51820,
		"via":"proxy",
		"peers":[{
			"publicKey":"cHVibGlj",
			"presharedKey":"cHNr",
			"endpoint":"vpn.example:51820",
			"allowedIPs":["0.0.0.0/0","::/0"],
			"persistentKeepalive":25
		}]
	}`)
	if err != nil {
		t.Fatalf("ParseWireGuardConfigJSON: %v", err)
	}

	if cfg.ID != "wg-home" {
		t.Errorf("ID = %q", cfg.ID)
	}
	if cfg.Via != "proxy" {
		t.Errorf("Via = %q", cfg.Via)
	}
	if cfg.MTU != 1380 || cfg.ListenPort != 51820 {
		t.Errorf("MTU/ListenPort = %d/%d", cfg.MTU, cfg.ListenPort)
	}
	// A prefixed address keeps only the address, and surrounding space is
	// tolerated because these are pasted out of wg-quick configs by hand.
	want := []netip.Addr{netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("fd00::2")}
	if len(cfg.Addresses) != len(want) {
		t.Fatalf("addresses = %v", cfg.Addresses)
	}
	for i := range want {
		if cfg.Addresses[i] != want[i] {
			t.Errorf("address %d = %v, want %v", i, cfg.Addresses[i], want[i])
		}
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0] != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("dns = %v", cfg.DNS)
	}

	if len(cfg.Peers) != 1 {
		t.Fatalf("peers = %v", cfg.Peers)
	}
	p := cfg.Peers[0]
	if p.PublicKey != "cHVibGlj" || p.PresharedKey != "cHNr" {
		t.Errorf("peer keys = %q/%q", p.PublicKey, p.PresharedKey)
	}
	if p.Endpoint != "vpn.example:51820" || p.PersistentKeepalive != 25 {
		t.Errorf("peer endpoint/keepalive = %q/%d", p.Endpoint, p.PersistentKeepalive)
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("allowed IPs = %v", p.AllowedIPs)
	}
}

func TestParseWireGuardConfigJSONRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"not json", `{`, "parsing config"},
		{"bad address", `{"addresses":["10.9.0.2.5"]}`, "tunnel address"},
		{"prefix as address is fine but bad prefix is not", `{"addresses":["10.9.0.2/64"]}`, "tunnel address"},
		{"bad dns", `{"dns":["nope"]}`, "DNS address"},
		{"bad allowed ip", `{"peers":[{"allowedIPs":["0.0.0.0"]}]}`, "allowed IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWireGuardConfigJSON("wg", tt.in)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// An empty config parses cleanly and is then refused by the constructor, rather
// than being half-accepted here.
func TestParseWireGuardConfigJSONEmptyIsRejectedOnUse(t *testing.T) {
	cfg, err := ParseWireGuardConfigJSON("wg", `{}`)
	if err != nil {
		t.Fatalf("parsing an empty config should succeed: %v", err)
	}
	if _, err := NewWireGuardUpstream(cfg, nil, nil); err == nil {
		t.Fatal("an empty config should not produce a usable upstream")
	}
}

// ---------------------------------------------------------------------------
// endpoint resolution
// ---------------------------------------------------------------------------

// stubEndpointLookup replaces the resolver for one test.
func stubEndpointLookup(t *testing.T, answers map[string][]netip.Addr) *[]string {
	t.Helper()
	asked := []string{}
	original := lookupEndpointIP
	lookupEndpointIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		asked = append(asked, host)
		addrs, ok := answers[host]
		if !ok {
			return nil, fmt.Errorf("no such host: %s", host)
		}
		return addrs, nil
	}
	t.Cleanup(func() { lookupEndpointIP = original })
	return &asked
}

// A peer endpoint given by name has to be resolved before it reaches the UAPI,
// which takes only a literal and rejects anything else with an opaque IPC
// error. Provider configs name their endpoint, so this is the normal case.
func TestWireGuardResolvesNamedEndpoint(t *testing.T) {
	asked := stubEndpointLookup(t, map[string][]netip.Addr{
		"vpn.example.com": {netip.MustParseAddr("203.0.113.9")},
	})

	priv, pub := wgKeypair(t)
	cfg := WireGuardConfig{
		ID:         "wg",
		PrivateKey: priv,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.0.2")},
		Peers: []WireGuardPeer{{
			PublicKey:  pub,
			Endpoint:   "vpn.example.com:51820",
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		}},
	}

	resolved, err := cfg.resolveEndpoints()
	if err != nil {
		t.Fatalf("resolveEndpoints: %v", err)
	}
	if got := resolved.Peers[0].Endpoint; got != "203.0.113.9:51820" {
		t.Fatalf("endpoint = %q", got)
	}
	if len(*asked) != 1 || (*asked)[0] != "vpn.example.com" {
		t.Fatalf("resolver was asked for %v", *asked)
	}

	// The original must be untouched: the caller's config is not ours to edit.
	if cfg.Peers[0].Endpoint != "vpn.example.com:51820" {
		t.Fatal("resolveEndpoints mutated its receiver's peers")
	}

	// And the whole path has to work, not just the helper.
	up, err := NewWireGuardUpstream(cfg, newRealBind(), nil)
	if err != nil {
		t.Fatalf("building an upstream with a named endpoint: %v", err)
	}
	_ = up.Close()
}

// A literal endpoint must not cost a lookup - that would put a resolver on the
// path of a config that never needed one.
func TestWireGuardSkipsLookupForLiteralEndpoint(t *testing.T) {
	asked := stubEndpointLookup(t, nil)

	priv, pub := wgKeypair(t)
	cfg := WireGuardConfig{
		ID:         "wg",
		PrivateKey: priv,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.0.2")},
		Peers: []WireGuardPeer{
			{PublicKey: pub, Endpoint: "203.0.113.9:51820"},
			{PublicKey: pub, Endpoint: "[2001:db8::1]:51820"},
			{PublicKey: pub},
		},
	}

	resolved, err := cfg.resolveEndpoints()
	if err != nil {
		t.Fatalf("resolveEndpoints: %v", err)
	}
	if len(*asked) != 0 {
		t.Fatalf("resolver was asked for %v", *asked)
	}
	if resolved.Peers[0].Endpoint != "203.0.113.9:51820" ||
		resolved.Peers[1].Endpoint != "[2001:db8::1]:51820" ||
		resolved.Peers[2].Endpoint != "" {
		t.Fatalf("endpoints changed: %v", resolved.Peers)
	}
}

// A name that does not resolve is reported as such, rather than surfacing later
// as a handshake that silently never completes.
func TestWireGuardReportsUnresolvableEndpoint(t *testing.T) {
	stubEndpointLookup(t, map[string][]netip.Addr{})

	priv, pub := wgKeypair(t)
	cfg := WireGuardConfig{
		ID:         "wg",
		PrivateKey: priv,
		Addresses:  []netip.Addr{netip.MustParseAddr("10.9.0.2")},
		Peers:      []WireGuardPeer{{PublicKey: pub, Endpoint: "nowhere.invalid:51820"}},
	}

	_, err := NewWireGuardUpstream(cfg, newRealBind(), nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "resolving peer 0 endpoint") {
		t.Fatalf("error %q does not name the endpoint that failed", err)
	}
}
