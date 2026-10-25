// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"golang.org/x/crypto/curve25519"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// A WireGuard listener: a WireGuard server on the phone. Peers (a laptop,
// another phone) connect to it on a UDP port, and every TCP connection and
// UDP flow they send through the tunnel leaves through one upstream, like a
// SOCKS5 listener's. The tunnel's packets go into a userspace gVisor stack
// that accepts any destination; nothing touches the VPN interface.
//
// Configs, keys included, persist in <dataDir>/wireguard-listeners.json
// (0600, in the app's private storage, like the tsnet state next to it), so
// the engine brings them back by itself (RestoreWireGuardListeners).

const wgListenersFile = "wireguard-listeners.json"

// WireGuardListenerPeer is one client of a listener.
type WireGuardListenerPeer struct {
	Name      string     `json:"name"`
	PublicKey string     `json:"publicKey"` // base64
	Address   netip.Addr `json:"address"`   // the peer's tunnel address
}

// WireGuardListenerConfig is one listener, as stored.
type WireGuardListenerConfig struct {
	ID         string                  `json:"id"`
	ListenPort uint16                  `json:"listenPort"`
	PrivateKey string                  `json:"privateKey"` // base64
	Subnet     netip.Prefix            `json:"subnet"`     // the server is its first address
	Upstream   UpstreamID              `json:"upstream"`
	MTU        int                     `json:"mtu"`
	DNS        string                  `json:"dns"` // put into peers' configs
	Enabled    bool                    `json:"enabled"`
	Peers      []WireGuardListenerPeer `json:"peers"`
}

func (c WireGuardListenerConfig) serverAddr() netip.Addr { return c.Subnet.Masked().Addr().Next() }

type wgListener struct {
	cfg   WireGuardListenerConfig
	dev   *device.Device
	tun   *wgNetTun
	stack *stack.Stack
	err   string
}

func (l *wgListener) close() {
	if l.dev != nil {
		l.dev.Close()
	}
	if l.stack != nil {
		l.stack.Destroy()
	}
}

type wgListeners struct {
	mu      sync.Mutex
	configs map[string]WireGuardListenerConfig
	running map[string]*wgListener
	loaded  bool
}

func newWGKeypair() (priv, pub string, err error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

func wgPublicKey(priv string) string {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return ""
	}
	p, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(p)
}

func (e *Engine) wgListenersPath() string { return filepath.Join(e.dataDir, wgListenersFile) }

// loadLocked reads the stored configs once.
func (e *Engine) wgListenersLoadLocked() {
	w := &e.wgListeners
	if w.loaded {
		return
	}
	w.loaded = true
	w.configs = map[string]WireGuardListenerConfig{}
	w.running = map[string]*wgListener{}
	b, err := os.ReadFile(e.wgListenersPath())
	if err != nil {
		return
	}
	var list []WireGuardListenerConfig
	if err := json.Unmarshal(b, &list); err != nil {
		log.Printf("wireguard-listener: reading %s: %v", wgListenersFile, err)
		return
	}
	for _, c := range list {
		w.configs[c.ID] = c
	}
}

func (e *Engine) wgListenersSaveLocked() error {
	list := make([]WireGuardListenerConfig, 0, len(e.wgListeners.configs))
	for _, c := range e.wgListeners.configs {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.wgListenersPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.wgListenersPath())
}

// SaveWireGuardListener creates (empty id) or edits a listener and starts or
// stops it to match. A new listener gets a fresh server key.
func (e *Engine) SaveWireGuardListener(id string, port uint16, upstream UpstreamID, subnet netip.Prefix, dns string, enabled bool) (WireGuardListenerConfig, error) {
	if port == 0 {
		return WireGuardListenerConfig{}, errors.New("wireguard-listener: needs a port")
	}
	if upstream == "" {
		return WireGuardListenerConfig{}, errors.New("wireguard-listener: needs an upstream")
	}
	if !subnet.IsValid() {
		subnet = netip.MustParsePrefix("10.66.66.0/24")
	}
	if !subnet.Addr().Is4() || subnet.Bits() > 30 {
		return WireGuardListenerConfig{}, errors.New("wireguard-listener: subnet must be IPv4, /30 or larger")
	}
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	var c WireGuardListenerConfig
	if id != "" {
		var ok bool
		if c, ok = e.wgListeners.configs[id]; !ok {
			return c, fmt.Errorf("wireguard-listener: no listener %q", id)
		}
	} else {
		priv, _, err := newWGKeypair()
		if err != nil {
			return c, err
		}
		c = WireGuardListenerConfig{ID: "wglistener-" + randomHex8(), PrivateKey: priv, MTU: 1280}
	}
	if c.Subnet.IsValid() && c.Subnet != subnet && len(c.Peers) > 0 {
		return c, errors.New("wireguard-listener: remove its peers before changing the subnet")
	}
	c.ListenPort, c.Upstream, c.Subnet, c.DNS, c.Enabled = port, upstream, subnet.Masked(), dns, enabled
	e.wgListeners.configs[c.ID] = c
	if err := e.wgListenersSaveLocked(); err != nil {
		return c, err
	}
	return c, e.wgListenerApplyLocked(c.ID)
}

// AddWireGuardListenerPeer adds a client with a fresh key and the next free
// address, and returns its wg-quick config. The client's private key is in
// that config only; it is not stored.
func (e *Engine) AddWireGuardListenerPeer(id, name, endpointHost string) (string, error) {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	c, ok := e.wgListeners.configs[id]
	if !ok {
		return "", fmt.Errorf("wireguard-listener: no listener %q", id)
	}
	used := map[netip.Addr]bool{c.serverAddr(): true}
	for _, p := range c.Peers {
		used[p.Address] = true
	}
	addr := c.serverAddr().Next()
	for used[addr] {
		addr = addr.Next()
	}
	if !c.Subnet.Contains(addr) || addr == netipBroadcast(c.Subnet) {
		return "", errors.New("wireguard-listener: subnet is full")
	}
	priv, pub, err := newWGKeypair()
	if err != nil {
		return "", err
	}
	if name == "" {
		name = "peer-" + addr.String()
	}
	c.Peers = append(c.Peers, WireGuardListenerPeer{Name: name, PublicKey: pub, Address: addr})
	e.wgListeners.configs[id] = c
	if err := e.wgListenersSaveLocked(); err != nil {
		return "", err
	}
	if err := e.wgListenerApplyLocked(id); err != nil {
		return "", err
	}
	if endpointHost == "" {
		endpointHost = "PHONE_ADDRESS"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n# %s, for Tailmesh WireGuard listener %s\nPrivateKey = %s\nAddress = %s/32\n", name, id, priv, addr)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	fmt.Fprintf(&b, "MTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\nPersistentKeepalive = 25\n",
		c.MTU, wgPublicKey(c.PrivateKey), net.JoinHostPort(endpointHost, strconv.Itoa(int(c.ListenPort))))
	return b.String(), nil
}

// RemoveWireGuardListenerPeer drops a client by name or public key.
func (e *Engine) RemoveWireGuardListenerPeer(id, peer string) error {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	c, ok := e.wgListeners.configs[id]
	if !ok {
		return fmt.Errorf("wireguard-listener: no listener %q", id)
	}
	kept := c.Peers[:0:0]
	for _, p := range c.Peers {
		if p.Name != peer && p.PublicKey != peer {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(c.Peers) {
		return fmt.Errorf("wireguard-listener: no peer %q", peer)
	}
	c.Peers = kept
	e.wgListeners.configs[id] = c
	if err := e.wgListenersSaveLocked(); err != nil {
		return err
	}
	return e.wgListenerApplyLocked(id)
}

// DeleteWireGuardListener stops and forgets a listener.
func (e *Engine) DeleteWireGuardListener(id string) error {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	if l := e.wgListeners.running[id]; l != nil {
		l.close()
		delete(e.wgListeners.running, id)
	}
	delete(e.wgListeners.configs, id)
	return e.wgListenersSaveLocked()
}

// RestoreWireGuardListeners starts every stored, enabled listener that isn't
// running. The app calls it whenever it applies its configuration.
func (e *Engine) RestoreWireGuardListeners() {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	for id, c := range e.wgListeners.configs {
		if l := e.wgListeners.running[id]; c.Enabled && (l == nil || l.dev == nil) {
			if err := e.wgListenerApplyLocked(id); err != nil {
				log.Printf("wireguard-listener[%s]: %v", id, err)
			}
		}
	}
}

func (e *Engine) closeAllWireGuardListeners() {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	for id, l := range e.wgListeners.running {
		l.close()
		delete(e.wgListeners.running, id)
	}
}

// WireGuardListenerInfo is listeners.wireguard.list's row. No private key.
type WireGuardListenerInfo struct {
	ID         string                  `json:"id"`
	ListenPort uint16                  `json:"listenPort"`
	Upstream   string                  `json:"upstream"`
	Subnet     string                  `json:"subnet"`
	ServerAddr string                  `json:"serverAddress"`
	PublicKey  string                  `json:"publicKey"`
	DNS        string                  `json:"dns,omitempty"`
	Enabled    bool                    `json:"enabled"`
	Running    bool                    `json:"running"`
	LastError  string                  `json:"lastError,omitempty"`
	Peers      []WireGuardListenerPeer `json:"peers"`
	// Handshakes per peer, from the device.
	PeerState []WireGuardPeerDetails `json:"peerState,omitempty"`
}

func (e *Engine) WireGuardListenersSnapshot() []WireGuardListenerInfo {
	e.wgListeners.mu.Lock()
	defer e.wgListeners.mu.Unlock()
	e.wgListenersLoadLocked()
	out := []WireGuardListenerInfo{}
	for id, c := range e.wgListeners.configs {
		info := WireGuardListenerInfo{
			ID: id, ListenPort: c.ListenPort, Upstream: string(c.Upstream), Subnet: c.Subnet.String(),
			ServerAddr: c.serverAddr().String(), PublicKey: wgPublicKey(c.PrivateKey), DNS: c.DNS,
			Enabled: c.Enabled, Peers: c.Peers,
		}
		if info.Peers == nil {
			info.Peers = []WireGuardListenerPeer{}
		}
		if l := e.wgListeners.running[id]; l != nil {
			info.LastError = l.err
			if l.dev != nil {
				info.Running = true
				if uapi, err := l.dev.IpcGet(); err == nil {
					info.PeerState = parseWireGuardPeers(uapi, time.Now())
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// wgListenerApplyLocked (re)starts id from its config, or stops it if disabled.
func (e *Engine) wgListenerApplyLocked(id string) error {
	if old := e.wgListeners.running[id]; old != nil {
		old.close()
		delete(e.wgListeners.running, id)
	}
	c, ok := e.wgListeners.configs[id]
	if !ok || !c.Enabled {
		return nil
	}
	l, err := e.startWGListener(c)
	if err != nil {
		e.wgListeners.running[id] = &wgListener{cfg: c, err: err.Error()}
		return err
	}
	e.wgListeners.running[id] = l
	return nil
}

func (e *Engine) startWGListener(c WireGuardListenerConfig) (*wgListener, error) {
	server := c.serverAddr()
	tunDev, s, err := newWireGuardNetTunOpts([]netip.Addr{server}, c.MTU, false)
	if err != nil {
		return nil, err
	}
	// Accept connections to any address: every destination a peer sends to
	// is handed to the forwarders below.
	s.SetPromiscuousMode(1, true)
	s.SetSpoofing(1, true)
	l := &wgListener{cfg: c, tun: tunDev, stack: s}
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 256, func(r *tcp.ForwarderRequest) {
		e.wgListenerTCP(c, r)
	}).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		return e.wgListenerUDP(c, r)
	}).HandlePacket)

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			if !quietWireGuardLine(format) {
				log.Printf("wireguard-listener/"+c.ID+": "+format, args...)
			}
		},
		Errorf: func(format string, args ...any) { log.Printf("wireguard-listener/"+c.ID+": "+format, args...) },
	}
	bind := newRoamingBind(conn.NewDefaultBind())
	dev := device.NewDevice(tunDev, bind, logger)
	bind.dev.Store(dev)
	var uapi strings.Builder
	privHex, err := wgKeyToHex(c.PrivateKey, "private key")
	if err != nil {
		dev.Close()
		return nil, err
	}
	fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\n", privHex, c.ListenPort)
	for _, p := range c.Peers {
		pubHex, err := wgKeyToHex(p.PublicKey, "peer key")
		if err != nil {
			continue
		}
		fmt.Fprintf(&uapi, "public_key=%s\nallowed_ip=%s/32\n", pubHex, p.Address)
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		s.Destroy()
		return nil, fmt.Errorf("wireguard-listener: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		s.Destroy()
		return nil, fmt.Errorf("wireguard-listener: %w", err)
	}
	l.dev = dev
	log.Printf("wireguard-listener[%s]: listening on UDP %d, %s via %s, %d peers", c.ID, c.ListenPort, c.Subnet, c.Upstream, len(c.Peers))
	return l, nil
}

func (e *Engine) wgListenerTCP(c WireGuardListenerConfig, r *tcp.ForwarderRequest) {
	id := r.ID()
	p, upID, dst, ok := e.wgListenerRoute(c, id.LocalAddress.String(), id.LocalPort)
	if !ok {
		r.Complete(true)
		return
	}
	go func() {
		defer recoverAndLog("wgListenerTCP")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		up, err := p.Dial(ctx, "tcp", dst)
		cancel()
		if err != nil {
			log.Printf("wireguard-listener[%s]: dial %s via %s: %v", c.ID, dst, upID, err)
			r.Complete(true)
			return
		}
		defer up.Close()
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		client := gonet.NewTCPConn(&wq, ep)
		defer client.Close()
		stats := e.statsFor(upID)
		stats.beginTCPFlow()
		defer stats.endTCPFlow()
		done := make(chan struct{}, 2)
		go func() {
			_, _ = copyCounting(up, client, stats.addBytesOut)
			if cw, ok := up.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
			done <- struct{}{}
		}()
		go func() {
			_, _ = copyCounting(client, up, stats.addBytesIn)
			client.CloseWrite()
			done <- struct{}{}
		}()
		<-done
		<-done
	}()
}

func (e *Engine) wgListenerUDP(c WireGuardListenerConfig, r *udp.ForwarderRequest) bool {
	id := r.ID()
	p, upID, dst, ok := e.wgListenerRoute(c, id.LocalAddress.String(), id.LocalPort)
	if !ok {
		return false
	}
	var wq waiter.Queue
	ep, udpErr := r.CreateEndpoint(&wq)
	if udpErr != nil {
		return false
	}
	client := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer recoverAndLog("wgListenerUDP")
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		up, err := p.Dial(ctx, "udp", dst)
		cancel()
		if err != nil {
			log.Printf("wireguard-listener[%s]: udp %s via %s: %v", c.ID, dst, upID, err)
			return
		}
		defer up.Close()
		stats := e.statsFor(upID)
		stats.beginUDPFlow()
		defer stats.endUDPFlow()
		_ = runUDPAssociation(client, up, udpAssociationIdleTimeout, stats, nil, nil)
	}()
	return true
}

// AutoUpstreamID as a listener's upstream routes each flow the way the
// engine routes the phone's own traffic with no app rule: a tailnet address
// to its tailnet, accepted subnet routes, then the default route.
const AutoUpstreamID UpstreamID = "@auto"

// wgListenerRoute picks the upstream for one flow from a peer.
func (e *Engine) wgListenerRoute(c WireGuardListenerConfig, host string, port uint16) (Upstream, UpstreamID, string, bool) {
	if c.Upstream == AutoUpstreamID {
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, "", "", false
		}
		d, ok := e.resolveFlow(FlowInfo{Dst: netip.AddrPortFrom(ip, port), AppUID: UnknownAppUID})
		if !ok || d.Upstream == nil {
			return nil, "", "", false
		}
		dest := d.Destination
		if dest == "" {
			dest = host
		}
		return d.Upstream, d.UpstreamID, net.JoinHostPort(dest, strconv.Itoa(int(port))), true
	}
	p, ok := e.readyProvider(c.Upstream)
	if !ok {
		return nil, "", "", false
	}
	return p, c.Upstream, net.JoinHostPort(host, strconv.Itoa(int(port))), true
}

func netipBroadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func randomHex8() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
