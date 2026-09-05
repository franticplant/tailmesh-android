// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5ListenerConfig describes an inbound SOCKS5 server that routes every
// connection it accepts through one fixed upstream, chosen at configuration
// time rather than by the connecting app's Android UID.
//
// This is deliberately unlike the TUN datapath (nat_router.go), where a flow
// is routed by policy keyed on the app that opened it. A listener exists so a
// tailnet (or any other upstream - a chained SOCKS5 proxy, WireGuard, an exit
// node) can be handed to another app on the device, or to a process reached
// via `adb forward`, explicitly by which listener port it connects to. An app
// pointed at listener A gets tailnet A's routing regardless of its own UID;
// nothing about the connecting process is consulted.
type SOCKS5ListenerConfig struct {
	// ID identifies this listener for AddSOCKS5Listener/RemoveSOCKS5Listener/
	// GetSOCKS5ListenersJSON. Adding with an ID that already exists replaces
	// the existing listener, matching AddWireGuardUpstream's convention.
	ID string
	// BindAddr is the local address to listen on, e.g. "127.0.0.1" for
	// loopback-only or "0.0.0.0" to accept connections from elsewhere on the
	// device's networks (still never from the internet - this is a listening
	// socket on the device, not something exposed through the tailnet).
	BindAddr string
	// Port is the TCP port to listen on. Must be nonzero: unlike an outbound
	// dial, a listener's whole purpose is to be found at a known address, so
	// there is no reasonable behavior for "any free port" that a caller could
	// discover afterward without an extra round trip this API doesn't have.
	Port uint16
	// Upstream names the upstream every accepted connection is routed
	// through, looked up at dial time rather than validated here - an
	// upstream added after its listener, or removed and re-added, works
	// without recreating the listener. A missing or not-ready upstream fails
	// the individual connection, not the listener.
	Upstream UpstreamID
	// Username and Password enable RFC 1929 auth on this listener when
	// Username is non-empty. Unrelated to any auth the upstream itself might
	// need to reach a further-out proxy - see SOCKS5Config for that.
	Username string
	Password string
}

type socks5Listener struct {
	cfg SOCKS5ListenerConfig
	e   *Engine
	ln  net.Listener

	closeOnce sync.Once
	doneCh    chan struct{}
}

// AddSOCKS5Listener starts (or, if id is already in use, replaces) an inbound
// SOCKS5 listener. See SOCKS5ListenerConfig for what each field controls.
func (e *Engine) AddSOCKS5Listener(cfg SOCKS5ListenerConfig) error {
	if cfg.ID == "" {
		return errors.New("socks5-listener: needs an id")
	}
	if cfg.Port == 0 {
		return errors.New("socks5-listener: needs a nonzero port")
	}
	if net.ParseIP(cfg.BindAddr) == nil {
		return fmt.Errorf("socks5-listener: bad bind address %q", cfg.BindAddr)
	}
	if cfg.Upstream == "" {
		return errors.New("socks5-listener: needs an upstream")
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
		return errors.New("socks5-listener: username and password must each be at most 255 bytes")
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindAddr, strconv.Itoa(int(cfg.Port))))
	if err != nil {
		return fmt.Errorf("socks5-listener: %w", err)
	}

	l := &socks5Listener{cfg: cfg, e: e, ln: ln, doneCh: make(chan struct{})}

	e.mu.Lock()
	if e.socks5Listeners == nil {
		e.socks5Listeners = make(map[string]*socks5Listener)
	}
	old := e.socks5Listeners[cfg.ID]
	e.socks5Listeners[cfg.ID] = l
	e.mu.Unlock()

	if old != nil {
		old.close()
	}

	go l.serve()
	return nil
}

// RemoveSOCKS5Listener stops the named listener. Removing one that does not
// exist is not an error, matching RemoveUpstream's tolerance for a caller
// that raced a config change against its own earlier removal.
func (e *Engine) RemoveSOCKS5Listener(id string) error {
	e.mu.Lock()
	l := e.socks5Listeners[id]
	delete(e.socks5Listeners, id)
	e.mu.Unlock()

	if l != nil {
		l.close()
	}
	return nil
}

// SOCKS5ListenerInfo is a listener's config without its password, for a
// settings UI to render a list from - see SOCKS5ListenersSnapshot.
type SOCKS5ListenerInfo struct {
	ID       string `json:"id"`
	BindAddr string `json:"bindAddr"`
	Port     int    `json:"port"`
	Upstream string `json:"upstream"`
	HasAuth  bool   `json:"hasAuth"`
}

// SOCKS5ListenersSnapshot lists every configured listener, ordered by ID -
// matching UpstreamSnapshot's convention for a stable UI list order.
func (e *Engine) SOCKS5ListenersSnapshot() []SOCKS5ListenerInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.socks5Listeners) == 0 {
		return nil
	}
	out := make([]SOCKS5ListenerInfo, 0, len(e.socks5Listeners))
	for _, l := range e.socks5Listeners {
		out = append(out, SOCKS5ListenerInfo{
			ID:       l.cfg.ID,
			BindAddr: l.cfg.BindAddr,
			Port:     int(l.cfg.Port),
			Upstream: string(l.cfg.Upstream),
			HasAuth:  l.cfg.Username != "",
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// closeAllSOCKS5Listeners stops every listener. Called from Engine.Close();
// listeners are not tied to VPN lifecycle, since their entire purpose is
// serving connections from other local apps whether or not the TUN is up.
func (e *Engine) closeAllSOCKS5Listeners() {
	e.mu.Lock()
	listeners := e.socks5Listeners
	e.socks5Listeners = nil
	e.mu.Unlock()

	for _, l := range listeners {
		l.close()
	}
}

func (l *socks5Listener) close() {
	l.closeOnce.Do(func() {
		l.ln.Close()
		<-l.doneCh
	})
}

func (l *socks5Listener) serve() {
	defer close(l.doneCh)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go l.handleConn(conn)
	}
}

func (l *socks5Listener) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout)); err != nil {
		return
	}
	if err := l.negotiateAuth(conn); err != nil {
		log.Printf("socks5-listener[%s]: %v", l.cfg.ID, err)
		return
	}
	cmd, host, port, err := l.readRequest(conn)
	if err != nil {
		log.Printf("socks5-listener[%s]: %v", l.cfg.ID, err)
		return
	}

	p, ok := l.e.readyProvider(l.cfg.Upstream)
	if !ok {
		log.Printf("socks5-listener[%s]: upstream %s not ready", l.cfg.ID, l.cfg.Upstream)
		_ = l.sendReply(conn, 0x01, "0.0.0.0", 0)
		return
	}

	switch cmd {
	case socks5CmdConnect:
		l.handleConnect(conn, p, host, port)
	case socks5CmdUDPAssociate:
		l.handleUDPAssociate(conn, p)
	default:
		_ = l.sendReply(conn, 0x07, "0.0.0.0", 0)
	}
}

// negotiateAuth is the server side of the exchange socks5Provider.negotiateAuth
// drives as a client: read the offered methods, pick one, and - if this
// listener requires a username/password - run the RFC 1929 subnegotiation.
func (l *socks5Listener) negotiateAuth(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5-listener: reading greeting: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("socks5-listener: client greeted with version 0x%02x", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("socks5-listener: reading offered methods: %w", err)
	}

	wantAuth := l.cfg.Username != ""
	want := byte(socks5AuthNone)
	if wantAuth {
		want = socks5AuthUserPass
	}
	selected := byte(socks5AuthNoAcceptable)
	for _, m := range methods {
		if m == want {
			selected = m
			break
		}
	}
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return fmt.Errorf("socks5-listener: sending method selection: %w", err)
	}
	if selected == socks5AuthNoAcceptable {
		return errors.New("socks5-listener: client offered no acceptable auth method")
	}
	if !wantAuth {
		return nil
	}
	return l.authUserPass(conn)
}

func (l *socks5Listener) authUserPass(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5-listener: reading auth version: %w", err)
	}
	uBuf := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, uBuf); err != nil {
		return fmt.Errorf("socks5-listener: reading username: %w", err)
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("socks5-listener: reading password length: %w", err)
	}
	pBuf := make([]byte, plenBuf[0])
	if _, err := io.ReadFull(conn, pBuf); err != nil {
		return fmt.Errorf("socks5-listener: reading password: %w", err)
	}

	// Constant-time comparison: this is an authentication check, not a data
	// lookup, so a timing side channel that reveals how many leading bytes of
	// a guess were correct is worth closing even though the whole exchange is
	// itself unauthenticated-transport (SOCKS5 has no TLS of its own).
	userOK := subtle.ConstantTimeCompare(uBuf, []byte(l.cfg.Username)) == 1
	passOK := subtle.ConstantTimeCompare(pBuf, []byte(l.cfg.Password)) == 1
	status := byte(0x01)
	if userOK && passOK {
		status = socks5AuthUserPassSuccess
	}
	if _, err := conn.Write([]byte{socks5AuthUserPassVersion, status}); err != nil {
		return fmt.Errorf("socks5-listener: sending auth reply: %w", err)
	}
	if status != socks5AuthUserPassSuccess {
		return errors.New("socks5-listener: client sent wrong credentials")
	}
	return nil
}

func (l *socks5Listener) readRequest(conn net.Conn) (cmd byte, host string, port uint16, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return 0, "", 0, fmt.Errorf("socks5-listener: reading request: %w", err)
	}
	if hdr[0] != socks5Version {
		return 0, "", 0, fmt.Errorf("socks5-listener: request version 0x%02x", hdr[0])
	}
	host, port, err = readAddr(conn, hdr[3])
	if err != nil {
		return 0, "", 0, fmt.Errorf("socks5-listener: reading request address: %w", err)
	}
	return hdr[1], host, port, nil
}

func (l *socks5Listener) sendReply(conn net.Conn, code byte, host string, port uint16) error {
	addrBytes, err := encodeAddr(host, port)
	if err != nil {
		addrBytes, _ = encodeAddr("0.0.0.0", 0)
	}
	reply := append([]byte{socks5Version, code, 0x00}, addrBytes...)
	_, err = conn.Write(reply)
	return err
}

func (l *socks5Listener) handleConnect(conn net.Conn, p Provider, host string, port uint16) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	upstreamConn, err := p.Dial(ctx, "tcp", dialAddr)
	if err != nil {
		log.Printf("socks5-listener[%s]: dial %s via %s failed: %v", l.cfg.ID, dialAddr, l.cfg.Upstream, err)
		_ = l.sendReply(conn, 0x04, "0.0.0.0", 0)
		return
	}
	defer upstreamConn.Close()

	replyHost, replyPort := "0.0.0.0", uint16(0)
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		replyHost, replyPort = tcpAddr.IP.String(), uint16(tcpAddr.Port)
	}
	if err := l.sendReply(conn, socks5ReplySucceeded, replyHost, replyPort); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, conn)
		if cw, ok := upstreamConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, upstreamConn)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// UDP ASSOCIATE (server side)
// ---------------------------------------------------------------------------

// socks5UDPAssociation serves one client's UDP ASSOCIATE for as long as its
// control TCP connection stays open (RFC 1928 §7). Unlike the client-side
// socks5UDPConn (one fixed destination per association, matching the
// datapath's one-flow-per-destination model), a listener's client can send to
// several different destinations over the same association - an ordinary
// SOCKS5 client (e.g. a DNS-over-UDP resolver list) is not required to open a
// new association per destination the way our own datapath is - so this
// tracks one upstream UDP conn per destination seen, keyed by "host:port".
type socks5UDPAssociation struct {
	relay      *net.UDPConn
	upstream   Provider
	clientAddr atomic.Pointer[net.UDPAddr]

	mu    sync.Mutex
	dests map[string]net.Conn

	closeOnce sync.Once
	doneCh    chan struct{}
}

func (l *socks5Listener) handleUDPAssociate(conn net.Conn, p Provider) {
	bindIP := net.ParseIP(l.cfg.BindAddr)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: 0})
	if err != nil {
		log.Printf("socks5-listener[%s]: opening UDP relay: %v", l.cfg.ID, err)
		_ = l.sendReply(conn, 0x01, "0.0.0.0", 0)
		return
	}

	a := &socks5UDPAssociation{
		relay:    relay,
		upstream: p,
		dests:    make(map[string]net.Conn),
		doneCh:   make(chan struct{}),
	}
	go a.serve()
	defer a.close()

	relayAddr := relay.LocalAddr().(*net.UDPAddr)
	replyHost := relayAddr.IP.String()
	if relayAddr.IP.IsUnspecified() {
		// Most SOCKS5 clients cannot send to 0.0.0.0/::; report the control
		// connection's own address instead, which is reachable the same way
		// the client just reached us.
		if tcpHost, _, splitErr := net.SplitHostPort(conn.LocalAddr().String()); splitErr == nil {
			replyHost = tcpHost
		}
	}
	if err := l.sendReply(conn, socks5ReplySucceeded, replyHost, uint16(relayAddr.Port)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	// The control connection carries no further data; its only remaining job
	// is telling us, by closing, when to tear the association down.
	var discard [1]byte
	_, _ = conn.Read(discard[:])
}

func (a *socks5UDPAssociation) serve() {
	defer close(a.doneCh)
	buf := make([]byte, 65535+262)
	for {
		n, from, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !a.acceptFrom(from) {
			continue
		}
		if n < 4 || buf[2] != 0x00 {
			continue // too short to have a header, or fragmented (unsupported)
		}
		host, port, payload, err := parseSOCKS5UDPHeader(buf[3:n])
		if err != nil {
			continue
		}
		uc := a.destConn(host, port)
		if uc == nil {
			continue
		}
		_, _ = uc.Write(payload)
	}
}

// acceptFrom reports whether from is this association's client, learning it
// from the first datagram received (the request's own DST fields are commonly
// 0.0.0.0:0, meaning "I don't know my own source port yet" - see
// socks5Provider.dialUDP's matching comment on the client side).
func (a *socks5UDPAssociation) acceptFrom(from *net.UDPAddr) bool {
	for {
		cur := a.clientAddr.Load()
		if cur != nil {
			return cur.IP.Equal(from.IP) && cur.Port == from.Port
		}
		if a.clientAddr.CompareAndSwap(nil, from) {
			return true
		}
	}
}

func (a *socks5UDPAssociation) destConn(host string, port uint16) net.Conn {
	dest := net.JoinHostPort(host, strconv.Itoa(int(port)))

	a.mu.Lock()
	uc, ok := a.dests[dest]
	a.mu.Unlock()
	if ok {
		return uc
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.upstream.Dial(ctx, "udp", dest)
	if err != nil {
		return nil
	}

	a.mu.Lock()
	if existing, ok := a.dests[dest]; ok {
		// Lost a race with another datagram to the same destination; keep the
		// one already stored and discard this one instead of leaking it.
		a.mu.Unlock()
		conn.Close()
		return existing
	}
	a.dests[dest] = conn
	a.mu.Unlock()

	go a.pumpResponses(conn, host, port)
	return conn
}

func (a *socks5UDPAssociation) pumpResponses(conn net.Conn, host string, port uint16) {
	header, err := encodeAddr(host, port)
	if err != nil {
		return
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		clientAddr := a.clientAddr.Load()
		if clientAddr == nil {
			continue
		}
		packet := append([]byte{0x00, 0x00, 0x00}, header...)
		packet = append(packet, buf[:n]...)
		_, _ = a.relay.WriteToUDP(packet, clientAddr)
	}
}

func (a *socks5UDPAssociation) close() {
	a.closeOnce.Do(func() {
		a.relay.Close()
		a.mu.Lock()
		for _, c := range a.dests {
			c.Close()
		}
		a.mu.Unlock()
	})
}

// parseSOCKS5UDPHeader decodes a UDP ASSOCIATE datagram's RFC 1928 §7 header
// (everything after the two RSV bytes and FRAG, which the caller has already
// checked), returning the destination and the payload that follows it.
func parseSOCKS5UDPHeader(b []byte) (host string, port uint16, payload []byte, err error) {
	if len(b) < 1 {
		return "", 0, nil, errors.New("socks5-listener: empty UDP header")
	}
	switch atyp := b[0]; atyp {
	case socks5AtypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, nil, errors.New("socks5-listener: truncated IPv4 UDP header")
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:7]), b[7:], nil
	case socks5AtypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, nil, errors.New("socks5-listener: truncated IPv6 UDP header")
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:19]), b[19:], nil
	case socks5AtypDomain:
		if len(b) < 2 {
			return "", 0, nil, errors.New("socks5-listener: truncated domain UDP header")
		}
		n := int(b[1])
		if len(b) < 2+n+2 {
			return "", 0, nil, errors.New("socks5-listener: truncated domain UDP header")
		}
		return string(b[2 : 2+n]), binary.BigEndian.Uint16(b[2+n : 4+n]), b[4+n:], nil
	default:
		return "", 0, nil, fmt.Errorf("socks5-listener: unsupported UDP address type 0x%02x", atyp)
	}
}
