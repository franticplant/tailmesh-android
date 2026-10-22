// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// TestDirectDialResolvesHostnames is the SOCKS5-with-a-hostname case: @direct
// must look the name up through the engine's DNS server, since Go's resolver
// has none on Android.
func TestDirectDialResolvesHostnames(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Name == "target.test." && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "target.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			})
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		if c, err := target.Accept(); err == nil {
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(target.Addr().String())

	e := NewEngine(t.TempDir(), nil)
	defer e.Close()
	e.SetUpstreamDNS(pc.LocalAddr().String())

	p, ok := e.readyProvider(DirectUpstreamID)
	if !ok {
		t.Fatal("no @direct")
	}
	c, err := p.Dial(context.Background(), "tcp", net.JoinHostPort("target.test", port))
	if err != nil {
		t.Fatalf("dial by name through @direct: %v", err)
	}
	c.Close()

	if _, err := p.Dial(context.Background(), "tcp", "missing.test:80"); err == nil {
		t.Fatal("a name with no records dialed")
	}
}

func TestDialResolvedTriesEachAddress(t *testing.T) {
	var tried []string
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		if addr == "192.0.2.2:80" {
			a, b := net.Pipe()
			b.Close()
			return a, nil
		}
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("refused")}
	}
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}, nil
	}
	c, err := dialResolved(context.Background(), dial, resolve, "tcp", "host.test:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(tried) != 2 {
		t.Fatalf("tried %v", tried)
	}
	// An IP literal is not looked up.
	tried = nil
	dialResolved(context.Background(), dial, resolve, "tcp", "192.0.2.9:80")
	if len(tried) != 1 || tried[0] != "192.0.2.9:80" {
		t.Fatalf("literal dial tried %v", tried)
	}
}
