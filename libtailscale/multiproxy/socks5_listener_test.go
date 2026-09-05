// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// freeTCPPort grabs an ephemeral port and releases it immediately. There is
// an unavoidable, vanishingly small race between the Close and the caller's
// own Listen - the standard tradeoff for testing a listener that (unlike a
// production caller, which has a fixed configured port) needs one nobody
// else is using yet.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// socks5TestClient drives the client side of the wire protocol by hand,
// deliberately not reusing socks5Provider - that would test the listener
// against itself rather than against an independent implementation of RFC
// 1928.
type socks5TestClient struct {
	t    *testing.T
	conn net.Conn
}

func dialSOCKS5Listener(t *testing.T, port int) *socks5TestClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dialing listener: %v", err)
	}
	return &socks5TestClient{t: t, conn: conn}
}

func (c *socks5TestClient) greet(methods ...byte) byte {
	c.t.Helper()
	greeting := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := c.conn.Write(greeting); err != nil {
		c.t.Fatalf("sending greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		c.t.Fatalf("reading method selection: %v", err)
	}
	if resp[0] != socks5Version {
		c.t.Fatalf("server replied with version 0x%02x", resp[0])
	}
	return resp[1]
}

func (c *socks5TestClient) authUserPass(username, password string) byte {
	c.t.Helper()
	req := []byte{socks5AuthUserPassVersion, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := c.conn.Write(req); err != nil {
		c.t.Fatalf("sending credentials: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, resp); err != nil {
		c.t.Fatalf("reading auth reply: %v", err)
	}
	return resp[1]
}

// request sends a CONNECT or UDP ASSOCIATE and returns the reply code plus
// the bound address the server reports.
func (c *socks5TestClient) request(cmd byte, host string, port uint16) (code byte, bndHost string, bndPort uint16) {
	c.t.Helper()
	addrBytes, err := encodeAddr(host, port)
	if err != nil {
		c.t.Fatalf("encoding address: %v", err)
	}
	req := append([]byte{socks5Version, cmd, 0x00}, addrBytes...)
	if _, err := c.conn.Write(req); err != nil {
		c.t.Fatalf("sending request: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, head); err != nil {
		c.t.Fatalf("reading reply header: %v", err)
	}
	if head[0] != socks5Version {
		c.t.Fatalf("reply had version 0x%02x", head[0])
	}
	if head[1] != socks5ReplySucceeded {
		return head[1], "", 0
	}
	h, p, err := readAddr(c.conn, head[3])
	if err != nil {
		c.t.Fatalf("reading bound address: %v", err)
	}
	return head[1], h, p
}

func (c *socks5TestClient) Close() { c.conn.Close() }

func newDirectEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	return e
}

func newTCPEchoServer(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr()
}

func newUDPEchoServer(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo server: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr()
}

func TestSOCKS5ListenerConnectRelaysTCP(t *testing.T) {
	e := newDirectEngine(t)
	echoAddr := newTCPEchoServer(t).(*net.TCPAddr)
	port := freeTCPPort(t)

	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port), Upstream: DirectUpstreamID,
	}); err != nil {
		t.Fatalf("AddSOCKS5Listener: %v", err)
	}

	c := dialSOCKS5Listener(t, port)
	defer c.Close()

	if selected := c.greet(socks5AuthNone); selected != socks5AuthNone {
		t.Fatalf("server selected method 0x%02x, want no-auth", selected)
	}
	code, _, _ := c.request(socks5CmdConnect, echoAddr.IP.String(), uint16(echoAddr.Port))
	if code != socks5ReplySucceeded {
		t.Fatalf("CONNECT reply code = 0x%02x, want success", code)
	}

	want := []byte("hello through the tailmesh socks5 listener")
	if _, err := c.conn.Write(want); err != nil {
		t.Fatalf("writing payload: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c.conn, got); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echoed payload = %q, want %q", got, want)
	}
}

func TestSOCKS5ListenerRejectsWrongCredentials(t *testing.T) {
	e := newDirectEngine(t)
	port := freeTCPPort(t)

	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port), Upstream: DirectUpstreamID,
		Username: "alice", Password: "correct-horse",
	}); err != nil {
		t.Fatalf("AddSOCKS5Listener: %v", err)
	}

	t.Run("no acceptable method offered", func(t *testing.T) {
		c := dialSOCKS5Listener(t, port)
		defer c.Close()
		if selected := c.greet(socks5AuthNone); selected != socks5AuthNoAcceptable {
			t.Fatalf("server selected 0x%02x, want no-acceptable-methods", selected)
		}
	})

	t.Run("wrong password rejected", func(t *testing.T) {
		c := dialSOCKS5Listener(t, port)
		defer c.Close()
		if selected := c.greet(socks5AuthUserPass); selected != socks5AuthUserPass {
			t.Fatalf("server selected 0x%02x, want user/pass", selected)
		}
		if status := c.authUserPass("alice", "wrong"); status == socks5AuthUserPassSuccess {
			t.Fatal("server accepted wrong credentials")
		}
	})

	t.Run("correct credentials accepted", func(t *testing.T) {
		echoAddr := newTCPEchoServer(t).(*net.TCPAddr)
		c := dialSOCKS5Listener(t, port)
		defer c.Close()
		if selected := c.greet(socks5AuthUserPass); selected != socks5AuthUserPass {
			t.Fatalf("server selected 0x%02x, want user/pass", selected)
		}
		if status := c.authUserPass("alice", "correct-horse"); status != socks5AuthUserPassSuccess {
			t.Fatalf("server rejected correct credentials: status 0x%02x", status)
		}
		code, _, _ := c.request(socks5CmdConnect, echoAddr.IP.String(), uint16(echoAddr.Port))
		if code != socks5ReplySucceeded {
			t.Fatalf("CONNECT after successful auth = 0x%02x, want success", code)
		}
	})
}

func TestSOCKS5ListenerUnreadyUpstreamFailsFast(t *testing.T) {
	e := newDirectEngine(t)
	port := freeTCPPort(t)

	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port), Upstream: "does-not-exist",
	}); err != nil {
		t.Fatalf("AddSOCKS5Listener: %v", err)
	}

	c := dialSOCKS5Listener(t, port)
	defer c.Close()
	c.greet(socks5AuthNone)
	code, _, _ := c.request(socks5CmdConnect, "127.0.0.1", 1)
	if code == socks5ReplySucceeded {
		t.Fatal("CONNECT through a nonexistent upstream reported success")
	}
}

func TestSOCKS5ListenerReplacesExistingID(t *testing.T) {
	e := newDirectEngine(t)
	port1 := freeTCPPort(t)
	port2 := freeTCPPort(t)

	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port1), Upstream: DirectUpstreamID,
	}); err != nil {
		t.Fatalf("first AddSOCKS5Listener: %v", err)
	}
	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port2), Upstream: DirectUpstreamID,
	}); err != nil {
		t.Fatalf("replacing AddSOCKS5Listener: %v", err)
	}

	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port1)), 500*time.Millisecond); err == nil {
		t.Fatal("old listener port still accepting connections after replacement")
	}

	c := dialSOCKS5Listener(t, port2)
	defer c.Close()
	if selected := c.greet(socks5AuthNone); selected != socks5AuthNone {
		t.Fatalf("new listener selected 0x%02x, want no-auth", selected)
	}

	infos := e.SOCKS5ListenersSnapshot()
	if len(infos) != 1 || infos[0].Port != port2 {
		t.Fatalf("SOCKS5ListenersSnapshot = %+v, want exactly one listener on port %d", infos, port2)
	}
}

func TestSOCKS5ListenerUDPAssociateRelaysDatagrams(t *testing.T) {
	e := newDirectEngine(t)
	echoAddr := newUDPEchoServer(t).(*net.UDPAddr)
	port := freeTCPPort(t)

	if err := e.AddSOCKS5Listener(SOCKS5ListenerConfig{
		ID: "l1", BindAddr: "127.0.0.1", Port: uint16(port), Upstream: DirectUpstreamID,
	}); err != nil {
		t.Fatalf("AddSOCKS5Listener: %v", err)
	}

	c := dialSOCKS5Listener(t, port)
	defer c.Close()
	c.greet(socks5AuthNone)
	code, relayHost, relayPort := c.request(socks5CmdUDPAssociate, "0.0.0.0", 0)
	if code != socks5ReplySucceeded {
		t.Fatalf("UDP ASSOCIATE reply code = 0x%02x, want success", code)
	}

	udpConn, err := net.Dial("udp", net.JoinHostPort(relayHost, strconv.Itoa(int(relayPort))))
	if err != nil {
		t.Fatalf("dialing relay: %v", err)
	}
	defer udpConn.Close()

	destHeader, err := encodeAddr(echoAddr.IP.String(), uint16(echoAddr.Port))
	if err != nil {
		t.Fatalf("encoding dest header: %v", err)
	}
	payload := []byte("udp through the listener")
	packet := append([]byte{0x00, 0x00, 0x00}, destHeader...)
	packet = append(packet, payload...)
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatalf("writing UDP datagram: %v", err)
	}

	_ = udpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 65535)
	n, err := udpConn.Read(buf)
	if err != nil {
		t.Fatalf("reading UDP reply: %v", err)
	}
	if n < 4 || buf[2] != 0x00 {
		t.Fatalf("short or fragmented reply, n=%d", n)
	}
	gotHost, gotPort, gotPayload, err := parseSOCKS5UDPHeader(buf[3:n])
	if err != nil {
		t.Fatalf("parsing reply header: %v", err)
	}
	if gotPort != uint16(echoAddr.Port) {
		t.Fatalf("reply source port = %d, want %d", gotPort, echoAddr.Port)
	}
	_ = gotHost
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("echoed UDP payload = %q, want %q", gotPayload, payload)
	}
}

func TestSOCKS5ListenerConfigValidation(t *testing.T) {
	e := newDirectEngine(t)
	cases := []struct {
		name string
		cfg  SOCKS5ListenerConfig
	}{
		{"empty id", SOCKS5ListenerConfig{BindAddr: "127.0.0.1", Port: 1080, Upstream: DirectUpstreamID}},
		{"zero port", SOCKS5ListenerConfig{ID: "l", BindAddr: "127.0.0.1", Upstream: DirectUpstreamID}},
		{"bad bind addr", SOCKS5ListenerConfig{ID: "l", BindAddr: "not-an-ip", Port: 1080, Upstream: DirectUpstreamID}},
		{"empty upstream", SOCKS5ListenerConfig{ID: "l", BindAddr: "127.0.0.1", Port: 1080}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.AddSOCKS5Listener(tc.cfg); err == nil {
				t.Fatal("expected a validation error, got nil")
			}
		})
	}
}
