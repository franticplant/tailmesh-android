package multiproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSOCKS5Server is a minimal RFC 1928 server supporting CONNECT and UDP
// ASSOCIATE. Testing the client against a real implementation of the protocol
// catches encoding mistakes that a hand-rolled mock would happily agree with.
type testSOCKS5Server struct {
	ln net.Listener

	requireAuth bool
	user, pass  string

	// forceReply, when non-zero, makes every request fail with that reply code.
	forceReply byte

	mu       sync.Mutex
	conns    []net.Conn
	udpConns []net.PacketConn
	wg       sync.WaitGroup
}

func startTestSOCKS5(t *testing.T) *testSOCKS5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSOCKS5Server{ln: ln}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

func (s *testSOCKS5Server) Addr() string { return s.ln.Addr().String() }

func (s *testSOCKS5Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	for _, c := range s.udpConns {
		_ = c.Close()
	}
	s.conns = nil
	s.udpConns = nil
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *testSOCKS5Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(conn)
		}()
	}
}

func (s *testSOCKS5Server) handle(conn net.Conn) {
	if err := s.doAuth(conn); err != nil {
		return
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	if head[0] != socks5Version {
		return
	}
	host, port, err := readAddr(conn, head[3])
	if err != nil {
		return
	}

	if s.forceReply != 0 {
		_, _ = conn.Write(append([]byte{socks5Version, s.forceReply, 0x00, socks5AtypIPv4}, 0, 0, 0, 0, 0, 0))
		return
	}

	switch head[1] {
	case socks5CmdConnect:
		s.handleConnect(conn, net.JoinHostPort(host, itoa(port)))
	case socks5CmdUDPAssociate:
		s.handleUDPAssociate(conn)
	default:
		_, _ = conn.Write(append([]byte{socks5Version, 0x07, 0x00, socks5AtypIPv4}, 0, 0, 0, 0, 0, 0))
	}
}

func (s *testSOCKS5Server) doAuth(conn net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	want := byte(socks5AuthNone)
	if s.requireAuth {
		want = socks5AuthUserPass
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
		}
	}
	if !offered {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return errors.New("no acceptable method")
	}
	if _, err := conn.Write([]byte{socks5Version, want}); err != nil {
		return err
	}
	if !s.requireAuth {
		return nil
	}

	verLen := make([]byte, 2)
	if _, err := io.ReadFull(conn, verLen); err != nil {
		return err
	}
	user := make([]byte, verLen[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	pLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLen); err != nil {
		return err
	}
	pass := make([]byte, pLen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(user) != s.user || string(pass) != s.pass {
		_, _ = conn.Write([]byte{socks5AuthUserPassVersion, 0x01})
		return errors.New("bad credentials")
	}
	_, err := conn.Write([]byte{socks5AuthUserPassVersion, socks5AuthUserPassSuccess})
	return err
}

func (s *testSOCKS5Server) handleConnect(conn net.Conn, target string) {
	remote, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		_, _ = conn.Write(append([]byte{socks5Version, 0x05, 0x00, socks5AtypIPv4}, 0, 0, 0, 0, 0, 0))
		return
	}
	defer remote.Close()

	_, _ = conn.Write(append([]byte{socks5Version, socks5ReplySucceeded, 0x00, socks5AtypIPv4}, 127, 0, 0, 1, 0, 0))

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, remote); done <- struct{}{} }()
	<-done
}

// handleUDPAssociate binds a relay socket, tells the client where it is, and
// forwards datagrams both ways until the control connection closes.
func (s *testSOCKS5Server) handleUDPAssociate(conn net.Conn) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_, _ = conn.Write(append([]byte{socks5Version, 0x01, 0x00, socks5AtypIPv4}, 0, 0, 0, 0, 0, 0))
		return
	}
	defer pc.Close()
	s.mu.Lock()
	s.udpConns = append(s.udpConns, pc)
	s.mu.Unlock()

	relayPort := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], relayPort)
	reply := append([]byte{socks5Version, socks5ReplySucceeded, 0x00, socks5AtypIPv4}, 127, 0, 0, 1)
	reply = append(reply, portBytes[:]...)
	if _, err := conn.Write(reply); err != nil {
		return
	}

	go func() {
		buf := make([]byte, 65535)
		for {
			n, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 4 || buf[2] != 0 {
				continue
			}
			host, port, err := readAddr(bytes.NewReader(buf[4:n]), buf[3])
			if err != nil {
				continue
			}
			payload, err := skipAddr(buf[3:n], buf[3])
			if err != nil {
				continue
			}

			target, err := net.Dial("udp", net.JoinHostPort(host, itoa(port)))
			if err != nil {
				continue
			}
			_, _ = target.Write(payload)
			_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp := make([]byte, 65535)
			rn, err := target.Read(resp)
			target.Close()
			if err != nil {
				continue
			}

			hdr, err := encodeAddr(host, port)
			if err != nil {
				continue
			}
			out := append([]byte{0, 0, 0}, hdr...)
			out = append(out, resp[:rn]...)
			_, _ = pc.WriteTo(out, clientAddr)
		}
	}()

	// Hold the association open until the client hangs up, per RFC 1928 §7.
	var discard [1]byte
	_, _ = conn.Read(discard[:])
}

func itoa(v uint16) string { return strconv.Itoa(int(v)) }

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func newSOCKS5(t *testing.T, cfg SOCKS5Config) Provider {
	t.Helper()
	p, err := NewSOCKS5Upstream(cfg, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Upstream: %v", err)
	}
	return p
}

func TestSOCKS5ConnectRelaysTCP(t *testing.T) {
	// Target echo server.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	srv := startTestSOCKS5(t)
	p := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.Dial(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	want := []byte("hello through the proxy")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echoed %q, want %q", got, want)
	}
}

func TestSOCKS5UDPAssociateRelaysDatagrams(t *testing.T) {
	// Target UDP echo server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
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

	srv := startTestSOCKS5(t)
	p := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.Dial(ctx, "udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Dial udp: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "echo:ping" {
		t.Fatalf("got %q, want %q", buf[:n], "echo:ping")
	}
}

func TestSOCKS5UserPassAuth(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	srv := startTestSOCKS5(t)
	srv.requireAuth = true
	srv.user, srv.pass = "u", "p"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	good := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr(), Username: "u", Password: "p"})
	conn, err := good.Dial(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("authenticated dial: %v", err)
	}
	conn.Close()

	bad := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr(), Username: "u", Password: "wrong"})
	if _, err := bad.Dial(ctx, "tcp", echo.Addr().String()); err == nil {
		t.Fatal("dial with wrong credentials should fail")
	}

	none := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})
	if _, err := none.Dial(ctx, "tcp", echo.Addr().String()); err == nil {
		t.Fatal("dial with no credentials should fail against an auth-requiring proxy")
	}
}

func TestSOCKS5ReplyErrorsAreSurfaced(t *testing.T) {
	srv := startTestSOCKS5(t)
	srv.forceReply = 0x05 // connection refused

	p := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := p.Dial(ctx, "tcp", "192.0.2.1:80")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error should name the reply code, got %v", err)
	}
}

// A hostname destination must be sent as a domain, not pre-resolved locally:
// resolving at the proxy is what makes remote DNS work.
func TestSOCKS5SendsHostnamesAsDomains(t *testing.T) {
	for _, tc := range []struct {
		host string
		want byte
	}{
		{"example.com", socks5AtypDomain},
		{"1.2.3.4", socks5AtypIPv4},
		{"2001:db8::1", socks5AtypIPv6},
	} {
		got, err := encodeAddr(tc.host, 443)
		if err != nil {
			t.Fatalf("encodeAddr(%q): %v", tc.host, err)
		}
		if got[0] != tc.want {
			t.Fatalf("encodeAddr(%q) atyp = 0x%02x, want 0x%02x", tc.host, got[0], tc.want)
		}
	}
}

func TestSOCKS5ConfigValidation(t *testing.T) {
	cases := map[string]SOCKS5Config{
		"no id":       {Address: "127.0.0.1:1080"},
		"no address":  {ID: "p"},
		"bad address": {ID: "p", Address: "not-a-host-port"},
		"long user":   {ID: "p", Address: "127.0.0.1:1080", Username: strings.Repeat("x", 256)},
	}
	for name, cfg := range cases {
		if _, err := NewSOCKS5Upstream(cfg, nil); err == nil {
			t.Fatalf("%s: expected a validation error", name)
		}
	}
}

func TestSOCKS5UnsupportedNetworkRejected(t *testing.T) {
	srv := startTestSOCKS5(t)
	p := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})
	if _, err := p.Dial(context.Background(), "sctp", "1.2.3.4:80"); err == nil {
		t.Fatal("unsupported network should be rejected")
	}
}

func TestSOCKS5ClosedProviderRefusesDial(t *testing.T) {
	srv := startTestSOCKS5(t)
	p := newSOCKS5(t, SOCKS5Config{ID: "proxy", Address: srv.Addr()})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if p.Ready() {
		t.Fatal("closed provider should not report ready")
	}
	if _, err := p.Dial(context.Background(), "tcp", "1.2.3.4:80"); !errors.Is(err, ErrUpstreamNotReady) {
		t.Fatalf("closed provider should return ErrUpstreamNotReady, got %v", err)
	}
}

// The whole point of the SOCKS5 upstream is that it plugs into policy like any
// other, so a rule can route an app through Xray or sing-box.
func TestSOCKS5UpstreamIsRoutableByPolicy(t *testing.T) {
	srv := startTestSOCKS5(t)
	e := NewEngine(t.TempDir(), &MockCallback{})
	p := newSOCKS5(t, SOCKS5Config{ID: "xray", Address: srv.Addr()})
	if err := e.RegisterUpstream(p); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "app via xray", Selector: Selector{AppUIDs: []int32{10123}}, Action: ActionRoute, Upstream: "xray"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", 10123))
	if !ok {
		t.Fatal("policy should route the bound app through the SOCKS5 upstream")
	}
	if d.UpstreamID != "xray" {
		t.Fatalf("routed via %q, want xray", d.UpstreamID)
	}
	if d.Upstream.PeerPathInfo(context.Background(), "1.1.1.1") != "socks5" {
		t.Fatal("path info should identify the upstream kind")
	}
}
