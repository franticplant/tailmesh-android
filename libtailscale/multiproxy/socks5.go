// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// SOCKS5 (RFC 1928) upstream.
//
// This is the generic pluggability point. Xray-core, sing-box, v2ray, hysteria
// and shadowsocks all expose a local SOCKS5 listener, so supporting this one
// protocol makes every one of them usable as an upstream without vendoring any
// of their dependency trees into the app.
//
// golang.org/x/net/proxy is deliberately not used: it implements CONNECT only,
// and a VPN upstream that cannot carry UDP is not much of an upstream. Both
// CONNECT and UDP ASSOCIATE are implemented here so the two share one
// address-encoding and handshake path.

const (
	socks5Version = 0x05

	socks5AuthNone         = 0x00
	socks5AuthUserPass     = 0x02
	socks5AuthNoAcceptable = 0xFF

	socks5AuthUserPassVersion = 0x01
	socks5AuthUserPassSuccess = 0x00

	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03

	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	socks5ReplySucceeded = 0x00
)

// socks5HandshakeTimeout bounds the control-channel exchange. A proxy that
// accepts a TCP connection but never completes the handshake would otherwise
// hold a datapath flow open indefinitely.
const socks5HandshakeTimeout = 10 * time.Second

var socks5ReplyMessages = map[byte]string{
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

func socks5ReplyError(code byte) error {
	if msg, ok := socks5ReplyMessages[code]; ok {
		return fmt.Errorf("socks5: %s (0x%02x)", msg, code)
	}
	return fmt.Errorf("socks5: unknown reply code 0x%02x", code)
}

// SOCKS5Config describes a SOCKS5 upstream.
type SOCKS5Config struct {
	// ID is the upstream identifier used by policy rules.
	ID UpstreamID
	// Address is the proxy's host:port, e.g. "127.0.0.1:10808" for a local
	// Xray/sing-box instance.
	Address string
	// Username and Password enable RFC 1929 auth when Username is non-empty.
	Username string
	Password string
	// Via names another upstream to reach the proxy through, chaining this one
	// behind it. Empty means the proxy is reached from the device. See chain.go.
	Via UpstreamID
}

type socks5Provider struct {
	cfg SOCKS5Config
	// dial reaches the proxy itself. It is a field so tests can substitute one,
	// and so the Android side can supply a protected dialer that does not loop
	// back into the TUN.
	dial UpstreamDialer

	mu     sync.Mutex
	closed bool
}

// NewSOCKS5Upstream builds a SOCKS5-backed upstream. proxyDial reaches the proxy
// itself and may be nil for a plain net.Dialer; on Android it should be a
// VpnService-protected dialer so traffic to a remote proxy does not re-enter the
// TUN it came from.
//
// To chain this upstream behind another, set cfg.Via and build the provider
// with Engine.NewSOCKS5Upstream, which resolves the parent at dial time.
func NewSOCKS5Upstream(cfg SOCKS5Config, proxyDial UpstreamDialer) (Provider, error) {
	if cfg.ID == "" {
		return nil, errors.New("socks5: upstream needs an id")
	}
	if cfg.Address == "" {
		return nil, errors.New("socks5: upstream needs an address")
	}
	if _, _, err := net.SplitHostPort(cfg.Address); err != nil {
		return nil, fmt.Errorf("socks5: bad address %q: %w", cfg.Address, err)
	}
	if len(cfg.Username) > 255 || len(cfg.Password) > 255 {
		return nil, errors.New("socks5: username and password must each be at most 255 bytes")
	}
	if proxyDial == nil {
		var d net.Dialer
		proxyDial = d.DialContext
	}
	return &socks5Provider{cfg: cfg, dial: proxyDial}, nil
}

func (p *socks5Provider) ID() UpstreamID     { return p.cfg.ID }
func (p *socks5Provider) Kind() UpstreamKind { return UpstreamKindSOCKS5 }
func (p *socks5Provider) Via() UpstreamID    { return p.cfg.Via }

func (p *socks5Provider) Ready() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed
}

func (p *socks5Provider) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

// PeerPathInfo has no meaningful answer for a proxy: there is no path
// information to report beyond "it went through the proxy".
func (p *socks5Provider) PeerPathInfo(context.Context, string) string { return "socks5" }

func (p *socks5Provider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !p.Ready() {
		return nil, fmt.Errorf("%w: socks5 %q", ErrUpstreamNotReady, p.cfg.ID)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return p.dialTCP(ctx, address)
	case "udp", "udp4", "udp6":
		return p.dialUDP(ctx, address)
	default:
		return nil, fmt.Errorf("socks5: unsupported network %q", network)
	}
}

// handshake opens a control connection and authenticates.
func (p *socks5Provider) handshake(ctx context.Context) (net.Conn, error) {
	conn, err := p.dial(ctx, "tcp", p.cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("socks5: dialing proxy %s: %w", p.cfg.Address, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	}

	if err := p.negotiateAuth(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (p *socks5Provider) negotiateAuth(conn net.Conn) error {
	methods := []byte{socks5AuthNone}
	if p.cfg.Username != "" {
		methods = []byte{socks5AuthUserPass, socks5AuthNone}
	}

	greeting := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("socks5: sending greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: reading method selection: %w", err)
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5: proxy replied with version 0x%02x", resp[0])
	}

	switch resp[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthUserPass:
		if p.cfg.Username == "" {
			return errors.New("socks5: proxy demanded username/password but none is configured")
		}
		return p.authUserPass(conn)
	case socks5AuthNoAcceptable:
		return errors.New("socks5: proxy rejected every offered auth method")
	default:
		return fmt.Errorf("socks5: proxy selected unsupported auth method 0x%02x", resp[1])
	}
}

func (p *socks5Provider) authUserPass(conn net.Conn) error {
	req := []byte{socks5AuthUserPassVersion, byte(len(p.cfg.Username))}
	req = append(req, p.cfg.Username...)
	req = append(req, byte(len(p.cfg.Password)))
	req = append(req, p.cfg.Password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5: sending credentials: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: reading auth reply: %w", err)
	}
	if resp[1] != socks5AuthUserPassSuccess {
		return errors.New("socks5: proxy rejected the credentials")
	}
	return nil
}

// encodeAddr writes an address in SOCKS5 form. A host that is not an IP literal
// is sent as a domain name and resolved by the proxy, which is what makes remote
// DNS work.
func encodeAddr(host string, port uint16) ([]byte, error) {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, socks5AtypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, socks5AtypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5: hostname too long (%d bytes)", len(host))
		}
		out = append(out, socks5AtypDomain, byte(len(host)))
		out = append(out, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	return append(out, portBytes[:]...), nil
}

func splitHostPort(address string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("socks5: bad destination %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("socks5: bad port in %q: %w", address, err)
	}
	return host, uint16(port), nil
}

// sendRequest issues a SOCKS5 command and returns the bound address from the
// reply.
func sendRequest(conn net.Conn, cmd byte, host string, port uint16) (string, uint16, error) {
	addrBytes, err := encodeAddr(host, port)
	if err != nil {
		return "", 0, err
	}
	req := append([]byte{socks5Version, cmd, 0x00}, addrBytes...)
	if _, err := conn.Write(req); err != nil {
		return "", 0, fmt.Errorf("socks5: sending request: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", 0, fmt.Errorf("socks5: reading reply: %w", err)
	}
	if head[0] != socks5Version {
		return "", 0, fmt.Errorf("socks5: reply had version 0x%02x", head[0])
	}
	if head[1] != socks5ReplySucceeded {
		return "", 0, socks5ReplyError(head[1])
	}
	return readAddr(conn, head[3])
}

func readAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	default:
		return "", 0, fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

func (p *socks5Provider) dialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	conn, err := p.handshake(ctx)
	if err != nil {
		return nil, err
	}
	if _, _, err := sendRequest(conn, socks5CmdConnect, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	// Clear the handshake deadline; the caller owns timeouts from here.
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// ---------------------------------------------------------------------------
// UDP ASSOCIATE
// ---------------------------------------------------------------------------

// socks5UDPConn presents a SOCKS5 UDP association as a connected net.Conn.
//
// The association's lifetime is tied to the TCP control connection (RFC 1928
// §7), so that is held open for as long as the conn lives and closing either
// tears down both.
type socks5UDPConn struct {
	control net.Conn
	relay   net.Conn

	// destHeader is the encoded destination prepended to every datagram. The
	// datapath dials one destination per association, so it never changes.
	destHeader []byte

	// readBuf/writeBuf are scratch space reused across calls instead of
	// allocating a fresh 64KB+ buffer per datagram. Safe unsynchronized:
	// runUDPAssociation's pumpUDPAssociation pairing guarantees exactly one
	// goroutine ever calls Read on a given conn and a different single
	// goroutine ever calls Write, never both from the same goroutine or
	// either concurrently with itself.
	readBuf  []byte
	writeBuf []byte

	closeOnce sync.Once
}

func (p *socks5Provider) dialUDP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	control, err := p.handshake(ctx)
	if err != nil {
		return nil, err
	}

	// 0.0.0.0:0 tells the proxy we do not know in advance which source address
	// our datagrams will come from, which is the normal case behind NAT.
	bndHost, bndPort, err := sendRequest(control, socks5CmdUDPAssociate, "0.0.0.0", 0)
	if err != nil {
		control.Close()
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})

	// A proxy may legitimately return an unspecified bound address, meaning
	// "same host as the control connection".
	if ip := net.ParseIP(bndHost); ip != nil && ip.IsUnspecified() {
		proxyHost, _, splitErr := net.SplitHostPort(control.RemoteAddr().String())
		if splitErr == nil {
			bndHost = proxyHost
		}
	}

	relayAddr := net.JoinHostPort(bndHost, strconv.Itoa(int(bndPort)))
	relay, err := p.dial(ctx, "udp", relayAddr)
	if err != nil {
		control.Close()
		return nil, fmt.Errorf("socks5: dialing UDP relay %s: %w", relayAddr, err)
	}

	destHeader, err := encodeAddr(host, port)
	if err != nil {
		control.Close()
		relay.Close()
		return nil, err
	}

	c := &socks5UDPConn{
		control:    control,
		relay:      relay,
		destHeader: destHeader,
		readBuf:    make([]byte, 65535+262),
		writeBuf:   make([]byte, 0, 3+len(destHeader)+65535),
	}

	// The control connection carries no data; reading it only detects teardown.
	// When the proxy drops the association, close the relay so the datapath sees
	// the failure instead of writing into a dead association.
	go func() {
		var discard [1]byte
		_, _ = control.Read(discard[:])
		c.Close()
	}()

	return c, nil
}

// Write wraps the payload in a SOCKS5 UDP request header. FRAG is always 0:
// fragmentation is optional in RFC 1928 and universally unimplemented.
func (c *socks5UDPConn) Write(b []byte) (int, error) {
	packet := append(c.writeBuf[:0], 0x00, 0x00, 0x00) // RSV RSV FRAG
	packet = append(packet, c.destHeader...)
	packet = append(packet, b...)

	if _, err := c.relay.Write(packet); err != nil {
		return 0, err
	}
	// Report the caller's payload length, not the wire length; a short count
	// would look like a partial write to callers that check.
	return len(b), nil
}

// Read strips the SOCKS5 UDP header and returns the payload.
func (c *socks5UDPConn) Read(b []byte) (int, error) {
	// Sized for a jumbo datagram plus header so nothing is silently truncated.
	buf := c.readBuf
	n, err := c.relay.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, errors.New("socks5: short UDP datagram")
	}
	if buf[2] != 0x00 {
		// A fragmented datagram cannot be reassembled here; dropping is better
		// than handing a fragment up as a whole packet.
		return 0, errors.New("socks5: fragmented UDP datagrams are not supported")
	}

	payload, err := skipAddr(buf[3:n], buf[3])
	if err != nil {
		return 0, err
	}
	return copy(b, payload), nil
}

// skipAddr advances past an encoded address and returns the remainder.
func skipAddr(b []byte, atyp byte) ([]byte, error) {
	var addrLen int
	switch atyp {
	case socks5AtypIPv4:
		addrLen = 1 + 4
	case socks5AtypIPv6:
		addrLen = 1 + 16
	case socks5AtypDomain:
		if len(b) < 2 {
			return nil, errors.New("socks5: truncated domain address")
		}
		addrLen = 1 + 1 + int(b[1])
	default:
		return nil, fmt.Errorf("socks5: unsupported address type 0x%02x in UDP datagram", atyp)
	}
	if len(b) < addrLen+2 {
		return nil, errors.New("socks5: truncated UDP address header")
	}
	return b[addrLen+2:], nil
}

func (c *socks5UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		relayErr := c.relay.Close()
		controlErr := c.control.Close()
		if relayErr != nil {
			err = relayErr
		} else {
			err = controlErr
		}
	})
	return err
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.relay.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.relay.RemoteAddr() }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.relay.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.relay.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.relay.SetWriteDeadline(t) }
