// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// newFakeAcceptorListener returns an ordinary local TCP listener standing in
// for a tsnet.Server's Listen. newInboundListener takes any net.Listener, so
// the whole forward path is exercised here with no tailnet, device, or
// emulator - the tier-1 harness.
func newFakeAcceptorListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake acceptor: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestInboundListenerForwardsToLocalTarget(t *testing.T) {
	echo := newTCPEchoServer(t)
	ln := newFakeAcceptorListener(t)
	l := newInboundListener(InboundListenerConfig{ID: "l1", LocalTarget: echo.String()}, ln, net.Dial)
	go l.serve()
	t.Cleanup(l.close)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial fake tailnet listener: %v", err)
	}
	defer c.Close()

	if _, err := c.Write([]byte("hello ingress")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("hello ingress"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(got) != "hello ingress" {
		t.Fatalf("echo = %q, want %q", got, "hello ingress")
	}
}

// TestInboundListenerMultipleForwardToSameTarget is the core multi-tailnet
// property: several independent listeners (standing in for several tailnet
// nodes) can all forward into one local service concurrently, with no
// address-space collision - because each is a separate userspace node.
func TestInboundListenerMultipleForwardToSameTarget(t *testing.T) {
	echo := newTCPEchoServer(t)
	for _, id := range []string{"tailnetA", "tailnetB", "tailnetC"} {
		id := id
		ln := newFakeAcceptorListener(t)
		l := newInboundListener(InboundListenerConfig{ID: id, LocalTarget: echo.String()}, ln, net.Dial)
		go l.serve()
		t.Cleanup(l.close)

		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: dial: %v", id, err)
		}
		msg := "via " + id
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("%s: write: %v", id, err)
		}
		got := make([]byte, len(msg))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("%s: read: %v", id, err)
		}
		c.Close()
		if string(got) != msg {
			t.Fatalf("%s: echo = %q, want %q", id, got, msg)
		}
	}
}

// TestInboundListenerProxyProtocol verifies the PROXY v2 header the local
// target receives carries the real peer address, and that the payload follows
// it intact.
func TestInboundListenerProxyProtocol(t *testing.T) {
	// Target reads the 28-byte IPv4 PROXY v2 header (16 fixed + 12 addr),
	// sends it straight back so the test can inspect it, then echoes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target: %v", err)
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
				hdr := make([]byte, 28)
				if _, err := io.ReadFull(conn, hdr); err != nil {
					return
				}
				if _, err := conn.Write(hdr); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()

	fake := newFakeAcceptorListener(t)
	l := newInboundListener(InboundListenerConfig{ID: "pp", LocalTarget: ln.Addr().String(), ProxyProtocol: true}, fake, net.Dial)
	go l.serve()
	t.Cleanup(l.close)

	c, err := net.Dial("tcp", fake.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	hdr := make([]byte, 28)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, hdr); err != nil {
		t.Fatalf("read proxy header: %v", err)
	}
	if string(hdr[:12]) != string(proxyV2Signature) {
		t.Fatalf("signature = % x, want % x", hdr[:12], proxyV2Signature)
	}
	if hdr[12] != 0x21 || hdr[13] != 0x11 {
		t.Fatalf("ver/fam = 0x%02x/0x%02x, want 0x21/0x11", hdr[12], hdr[13])
	}
	if n := binary.BigEndian.Uint16(hdr[14:16]); n != 12 {
		t.Fatalf("addr len = %d, want 12", n)
	}
	// Source is the client side of the fake listener connection (loopback);
	// destination is the fake listener's own address.
	wantSrc := c.LocalAddr().(*net.TCPAddr)
	wantDst := fake.Addr().(*net.TCPAddr)
	if got := net.IP(hdr[16:20]); !got.Equal(wantSrc.IP.To4()) {
		t.Fatalf("src ip = %v, want %v", got, wantSrc.IP)
	}
	if got := net.IP(hdr[20:24]); !got.Equal(wantDst.IP.To4()) {
		t.Fatalf("dst ip = %v, want %v", got, wantDst.IP)
	}
	if p := binary.BigEndian.Uint16(hdr[24:26]); int(p) != wantSrc.Port {
		t.Fatalf("src port = %d, want %d", p, wantSrc.Port)
	}
	if p := binary.BigEndian.Uint16(hdr[26:28]); int(p) != wantDst.Port {
		t.Fatalf("dst port = %d, want %d", p, wantDst.Port)
	}

	if _, err := c.Write([]byte("after-header")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len("after-header"))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != "after-header" {
		t.Fatalf("payload = %q, want %q", got, "after-header")
	}
}

func TestProxyV2HeaderIPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.IPv4(100, 64, 1, 2), Port: 40000}
	dst := &net.TCPAddr{IP: net.IPv4(100, 64, 1, 3), Port: 22}
	hdr, err := proxyV2Header(src, dst)
	if err != nil {
		t.Fatalf("proxyV2Header: %v", err)
	}
	if len(hdr) != 28 {
		t.Fatalf("len = %d, want 28", len(hdr))
	}
	if hdr[13] != 0x11 {
		t.Fatalf("fam = 0x%02x, want 0x11 (AF_INET/STREAM)", hdr[13])
	}
	if binary.BigEndian.Uint16(hdr[24:26]) != 40000 || binary.BigEndian.Uint16(hdr[26:28]) != 22 {
		t.Fatalf("ports = %d/%d, want 40000/22", binary.BigEndian.Uint16(hdr[24:26]), binary.BigEndian.Uint16(hdr[26:28]))
	}
}

func TestProxyV2HeaderIPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("fd7a:115c:a1e0::1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("fd7a:115c:a1e0::2"), Port: 443}
	hdr, err := proxyV2Header(src, dst)
	if err != nil {
		t.Fatalf("proxyV2Header: %v", err)
	}
	if len(hdr) != 52 {
		t.Fatalf("len = %d, want 52", len(hdr))
	}
	if hdr[13] != 0x21 {
		t.Fatalf("fam = 0x%02x, want 0x21 (AF_INET6/STREAM)", hdr[13])
	}
	if got := net.IP(hdr[16:32]); !got.Equal(src.IP.To16()) {
		t.Fatalf("src ip = %v, want %v", got, src.IP)
	}
}

// TestInboundListenerCloseForceClosesInFlight guards the same leak
// socks5Listener had: closing the listener must tear down connections already
// relaying, not just stop new Accepts.
func TestInboundListenerCloseForceClosesInFlight(t *testing.T) {
	hang, openCount := newTCPHangServer(t)
	ln := newFakeAcceptorListener(t)
	l := newInboundListener(InboundListenerConfig{ID: "l1", LocalTarget: hang.String()}, ln, net.Dial)
	go l.serve()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for openCount() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("target never saw the forwarded connection")
		}
		time.Sleep(10 * time.Millisecond)
	}

	l.close()

	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client connection still open after listener close")
	}
	deadline = time.Now().Add(3 * time.Second)
	for openCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("target connection still open after listener close")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAddInboundListenerValidation(t *testing.T) {
	e := &Engine{}
	cases := []struct {
		name string
		cfg  InboundListenerConfig
	}{
		{"no id", InboundListenerConfig{Upstream: "t", ListenPort: 22, LocalTarget: "127.0.0.1:22"}},
		{"no upstream", InboundListenerConfig{ID: "x", ListenPort: 22, LocalTarget: "127.0.0.1:22"}},
		{"no port", InboundListenerConfig{ID: "x", Upstream: "t", LocalTarget: "127.0.0.1:22"}},
		{"udp unsupported", InboundListenerConfig{ID: "x", Upstream: "t", ListenPort: 22, LocalTarget: "127.0.0.1:22", Network: "udp"}},
		{"bad target", InboundListenerConfig{ID: "x", Upstream: "t", ListenPort: 22, LocalTarget: "not-a-host-port"}},
		{"upstream not a tailnet", InboundListenerConfig{ID: "x", Upstream: "direct", ListenPort: 22, LocalTarget: "127.0.0.1:22"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := e.AddInboundListener(tc.cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestGetInboundListenersJSON(t *testing.T) {
	e := &Engine{}
	e.inboundListeners = map[string]*inboundListener{
		"b": {cfg: InboundListenerConfig{ID: "b", Upstream: "tailnetB", ListenPort: 22, LocalTarget: "127.0.0.1:22", Network: "tcp"}},
		"a": {cfg: InboundListenerConfig{ID: "a", Upstream: "tailnetA", ListenPort: 80, LocalTarget: "127.0.0.1:8080", ProxyProtocol: true, Network: "tcp"}},
	}
	got := e.GetInboundListenersJSON()
	want := `[{"id":"a","upstream":"tailnetA","listenPort":80,"localTarget":"127.0.0.1:8080","proxyProtocol":true,"network":"tcp"},` +
		`{"id":"b","upstream":"tailnetB","listenPort":22,"localTarget":"127.0.0.1:22","proxyProtocol":false,"network":"tcp"}]`
	if got != want {
		t.Fatalf("GetInboundListenersJSON =\n%s\nwant\n%s", got, want)
	}
}
