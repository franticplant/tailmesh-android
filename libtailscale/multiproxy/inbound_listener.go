// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"

	"tailscale.com/tsnet"
)

// InboundListenerConfig describes a tailnet-facing listener: connections a
// tailnet peer opens to one port on an enabled tailnet's node are forwarded to
// a local target on the device.
//
// This is the ingress counterpart to the TUN datapath (nat_router.go). The
// datapath is one-way outbound: an app dials a synthetic address and the
// engine picks a tailnet. A listener lets a tailnet peer reach a local
// service, which the synthetic-address model cannot do on its own because no
// tailnet address is ever assigned to the Android TUN.
//
// The forward is a userspace proxy, not packet injection: each tailnet is a
// separate tsnet.Server (its own node and netstack), so several tailnets can
// listen on the same port and forward to the same local target with no
// address-space collision - the exact overlap problem that makes transparent
// multi-tailnet ingress impossible. The cost is that the local target sees the
// engine's loopback address as the peer, not the real tailnet peer; set
// ProxyProtocol to convey the real peer in a PROXY protocol v2 header.
type InboundListenerConfig struct {
	// ID identifies this listener for AddInboundListener/
	// RemoveInboundListener/GetInboundListenersJSON. Adding with an ID that
	// already exists replaces the existing listener, matching
	// AddSOCKS5Listener's convention.
	ID string
	// Upstream names the enabled tailnet whose tsnet.Server accepts the
	// connection. Looked up at add time (a listener needs a live node to
	// Listen on); unlike AddSOCKS5Listener's Upstream, this cannot be
	// deferred to dial time.
	Upstream UpstreamID
	// ListenPort is the port accepted on the tailnet node. Must be nonzero.
	ListenPort uint16
	// LocalTarget is the host:port accepted connections are forwarded to,
	// e.g. "127.0.0.1:22". Loopback is the intended default: it stays within
	// the device and sidesteps Android's local-network access restrictions,
	// which apply to LAN targets rather than loopback.
	LocalTarget string
	// ProxyProtocol, when true, prepends a PROXY protocol v2 header carrying
	// the real tailnet peer address to each forwarded connection, so the
	// local target can recover the true source. The target must opt in to
	// reading it.
	ProxyProtocol bool
	// Network is "tcp" (the default when empty) or "udp".
	Network string
}

// inboundAcceptor is the tailnet-side half of a listener: something that can
// Listen on a tailnet node. Production uses tsnetAcceptor wrapping
// *tsnet.Server; tests substitute an acceptor backed by an ordinary local
// net.Listener so the entire forward path is exercisable on the host with no
// device, emulator, or tailnet.
type inboundAcceptor interface {
	Listen(network, addr string) (net.Listener, error)
}

type tsnetAcceptor struct{ srv *tsnet.Server }

func (a tsnetAcceptor) Listen(network, addr string) (net.Listener, error) {
	return a.srv.Listen(network, addr)
}

type inboundListener struct {
	cfg  InboundListenerConfig
	ln   net.Listener
	dial func(network, addr string) (net.Conn, error)

	closeOnce sync.Once
	doneCh    chan struct{}

	// connsMu/conns track every accepted connection still being served so
	// close() can force them shut - closing ln alone only stops new Accepts,
	// it does nothing to a handleConn already blocked in an io.Copy. Same
	// rationale (and the same leak) as socks5Listener.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
}

// inboundAcceptorFor resolves the acceptor for an upstream. Only enabled
// tailnets currently expose an inbound path; every other upstream kind
// (SOCKS5, WireGuard, direct) is a client and has no listening node.
func (e *Engine) inboundAcceptorFor(id UpstreamID) (inboundAcceptor, error) {
	srv, ok := e.activeTailnetServer(id)
	if !ok {
		return nil, fmt.Errorf("inbound-listener: upstream %q is not an enabled tailnet", id)
	}
	return tsnetAcceptor{srv: srv}, nil
}

// AddInboundListener starts (or, if id is already in use, replaces) a
// tailnet-facing listener. See InboundListenerConfig for what each field
// controls.
func (e *Engine) AddInboundListener(cfg InboundListenerConfig) error {
	if cfg.ID == "" {
		return errors.New("inbound-listener: needs an id")
	}
	if cfg.Upstream == "" {
		return errors.New("inbound-listener: needs an upstream")
	}
	if cfg.ListenPort == 0 {
		return errors.New("inbound-listener: needs a nonzero listen port")
	}
	network := cfg.Network
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" {
		// UDP ingress needs association tracking and a per-datagram mapping
		// the TCP path does not; deliberately not half-built here.
		return fmt.Errorf("inbound-listener: unsupported network %q (only \"tcp\")", network)
	}
	if _, _, err := net.SplitHostPort(cfg.LocalTarget); err != nil {
		return fmt.Errorf("inbound-listener: bad local target %q: %w", cfg.LocalTarget, err)
	}

	acceptor, err := e.inboundAcceptorFor(cfg.Upstream)
	if err != nil {
		return err
	}
	ln, err := acceptor.Listen(network, ":"+strconv.Itoa(int(cfg.ListenPort)))
	if err != nil {
		return fmt.Errorf("inbound-listener: listen on %s:%d: %w", cfg.Upstream, cfg.ListenPort, err)
	}
	cfg.Network = network

	l := newInboundListener(cfg, ln, net.Dial)

	e.mu.Lock()
	if e.inboundListeners == nil {
		e.inboundListeners = make(map[string]*inboundListener)
	}
	old := e.inboundListeners[cfg.ID]
	e.inboundListeners[cfg.ID] = l
	e.mu.Unlock()

	if old != nil {
		old.close()
	}

	go l.serve()
	log.Printf("[inbound-%s] listening on %s:%d -> %s", cfg.ID, cfg.Upstream, cfg.ListenPort, cfg.LocalTarget)
	return nil
}

// RemoveInboundListener stops the named listener. Removing one that does not
// exist is a no-op.
func (e *Engine) RemoveInboundListener(id string) error {
	e.mu.Lock()
	l := e.inboundListeners[id]
	delete(e.inboundListeners, id)
	e.mu.Unlock()
	if l != nil {
		l.close()
	}
	return nil
}

// closeAllInboundListeners stops every listener. Called from Engine.Close();
// safe to call repeatedly.
func (e *Engine) closeAllInboundListeners() {
	e.mu.Lock()
	ls := e.inboundListeners
	e.inboundListeners = nil
	e.mu.Unlock()
	for _, l := range ls {
		l.close()
	}
}

type inboundListenerInfo struct {
	ID            string `json:"id"`
	Upstream      string `json:"upstream"`
	ListenPort    int    `json:"listenPort"`
	LocalTarget   string `json:"localTarget"`
	ProxyProtocol bool   `json:"proxyProtocol"`
	Network       string `json:"network"`
}

// GetInboundListenersJSON lists every configured listener, ordered by id, as
// a JSON array - the same shape GetSOCKS5ListenersJSON uses.
func (e *Engine) GetInboundListenersJSON() string {
	e.mu.RLock()
	ids := make([]string, 0, len(e.inboundListeners))
	for id := range e.inboundListeners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]inboundListenerInfo, 0, len(ids))
	for _, id := range ids {
		cfg := e.inboundListeners[id].cfg
		out = append(out, inboundListenerInfo{
			ID:            cfg.ID,
			Upstream:      string(cfg.Upstream),
			ListenPort:    int(cfg.ListenPort),
			LocalTarget:   cfg.LocalTarget,
			ProxyProtocol: cfg.ProxyProtocol,
			Network:       cfg.Network,
		})
	}
	e.mu.RUnlock()
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// newInboundListener is the constructor shared by AddInboundListener and
// tests. dial is injectable so a test can point the forward at an in-process
// echo server (or a failing dialer) without any Android or tailnet involved.
func newInboundListener(cfg InboundListenerConfig, ln net.Listener, dial func(network, addr string) (net.Conn, error)) *inboundListener {
	return &inboundListener{
		cfg:    cfg,
		ln:     ln,
		dial:   dial,
		doneCh: make(chan struct{}),
		conns:  make(map[net.Conn]struct{}),
	}
}

func (l *inboundListener) serve() {
	defer close(l.doneCh)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handleConn(conn)
	}
}

func (l *inboundListener) close() {
	l.closeOnce.Do(func() {
		l.ln.Close()
		l.connsMu.Lock()
		for c := range l.conns {
			c.Close()
		}
		l.connsMu.Unlock()
		<-l.doneCh
	})
}

func (l *inboundListener) trackConn(conn net.Conn, add bool) {
	l.connsMu.Lock()
	defer l.connsMu.Unlock()
	if add {
		l.conns[conn] = struct{}{}
	} else {
		delete(l.conns, conn)
	}
}

func (l *inboundListener) handleConn(conn net.Conn) {
	l.trackConn(conn, true)
	defer l.trackConn(conn, false)
	defer conn.Close()

	target, err := l.dial("tcp", l.cfg.LocalTarget)
	if err != nil {
		log.Printf("[inbound-%s] forward %s -> %s failed: %v", l.cfg.ID, conn.RemoteAddr(), l.cfg.LocalTarget, err)
		return
	}
	defer target.Close()

	if l.cfg.ProxyProtocol {
		hdr, err := proxyV2Header(conn.RemoteAddr(), conn.LocalAddr())
		if err != nil {
			log.Printf("[inbound-%s] proxy-protocol header: %v", l.cfg.ID, err)
			return
		}
		if _, err := target.Write(hdr); err != nil {
			return
		}
	}

	// Bidirectional relay. Whichever direction finishes first tears the whole
	// connection down (both deferred Closes), matching socks5Listener's
	// handleConnect: a half-closed peer that keeps the other direction idle
	// open must not outlive the listener's own accounting of the connection.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

// proxyV2Header builds a PROXY protocol v2 header (binary format) describing
// src and dst. Only the TCP-over-IPv4 (0x11) and TCP-over-IPv6 (0x21)
// families are produced, which is all a stream listener can see. Pure
// function, unit-tested directly.
func proxyV2Header(src, dst net.Addr) ([]byte, error) {
	sa, ok := src.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("unsupported source address type %T", src)
	}
	da, ok := dst.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("unsupported destination address type %T", dst)
	}
	sip, dip := sa.IP, da.IP
	if s4, d4 := sip.To4(), dip.To4(); s4 != nil && d4 != nil {
		hdr := make([]byte, 16+12)
		copy(hdr, proxyV2Signature)
		hdr[12] = 0x21 // version 2, command PROXY
		hdr[13] = 0x11 // AF_INET, STREAM
		binary.BigEndian.PutUint16(hdr[14:16], 12)
		copy(hdr[16:20], s4)
		copy(hdr[20:24], d4)
		binary.BigEndian.PutUint16(hdr[24:26], uint16(sa.Port))
		binary.BigEndian.PutUint16(hdr[26:28], uint16(da.Port))
		return hdr, nil
	}
	s16, d16 := sip.To16(), dip.To16()
	if s16 == nil || d16 == nil {
		return nil, fmt.Errorf("addresses are not usable IPs: %v, %v", sip, dip)
	}
	hdr := make([]byte, 16+36)
	copy(hdr, proxyV2Signature)
	hdr[12] = 0x21 // version 2, command PROXY
	hdr[13] = 0x21 // AF_INET6, STREAM
	binary.BigEndian.PutUint16(hdr[14:16], 36)
	copy(hdr[16:32], s16)
	copy(hdr[32:48], d16)
	binary.BigEndian.PutUint16(hdr[48:50], uint16(sa.Port))
	binary.BigEndian.PutUint16(hdr[50:52], uint16(da.Port))
	return hdr, nil
}

// proxyV2Signature is the fixed 12-byte PROXY protocol v2 preamble.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
