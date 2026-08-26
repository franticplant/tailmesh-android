package multiproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resetBootstrapState clears the process-wide bootstrap cache/config so tests
// don't leak resolver state into each other.
func resetBootstrapState(t *testing.T) {
	t.Helper()
	reset := func() {
		bootstrapState.mu.Lock()
		bootstrapState.plainDNS = ""
		bootstrapState.dohBase = ""
		bootstrapState.cache = nil
		bootstrapState.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// startStubResolver runs a tiny UDP DNS server answering A queries for one
// name, standing in for the underlying network's resolver.
func startStubResolver(t *testing.T, name string, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc}
	srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 1 && r.Question[0].Name == dns.Fqdn(name) && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(dns.Fqdn(name) + " A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestBootstrapResolveUsesUnderlyingResolver is the regression test for the
// DoH bootstrap deadlock: resolving the DoH server's hostname must go to the
// underlying network's resolver, never back through our own DNS server.
func TestBootstrapResolveUsesUnderlyingResolver(t *testing.T) {
	resetBootstrapState(t)
	addr := startStubResolver(t, "doh.example.", "203.0.113.7")
	setBootstrapPlainDNS(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := bootstrapResolve(ctx, "doh.example")
	if err != nil {
		t.Fatalf("bootstrapResolve: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("got %v, want [203.0.113.7]", ips)
	}
}

// TestBootstrapResolveUsesKnownIPsWithoutResolver covers the case where no
// underlying resolver is known yet: a well-known provider must still resolve
// from the built-in table, so DoH isn't dead on arrival at startup.
func TestBootstrapResolveUsesKnownIPsWithoutResolver(t *testing.T) {
	resetBootstrapState(t)
	setBootstrapDoHBase("https://cloudflare-dns.com/dns-query")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := bootstrapResolve(ctx, "cloudflare-dns.com")
	if err != nil {
		t.Fatalf("bootstrapResolve: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected known IPs for cloudflare-dns.com")
	}
	for _, ip := range ips {
		if !ip.Is4() {
			t.Fatalf("expected IPv4 bootstrap addresses, got %v", ip)
		}
	}
}

// TestBootstrapResolveFailsClosedWithoutSources asserts the failure domain is
// an explicit error rather than a hang or a silent fall back to the device
// resolver (which is our own server, and would deadlock).
func TestBootstrapResolveFailsClosedWithoutSources(t *testing.T) {
	resetBootstrapState(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := bootstrapResolve(ctx, "custom.example"); err == nil {
		t.Fatal("expected error with no known IPs and no underlying resolver")
	}
}

// TestBootstrapResolveCachesResults ensures a flapping or slow underlying
// resolver isn't queried on every single DoH request.
func TestBootstrapResolveCachesResults(t *testing.T) {
	resetBootstrapState(t)
	addr := startStubResolver(t, "doh.example.", "203.0.113.9")
	setBootstrapPlainDNS(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := bootstrapResolve(ctx, "doh.example"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// Point the resolver at nothing; a cached answer must still be returned.
	setBootstrapPlainDNS("127.0.0.1:1")

	ips, err := bootstrapResolve(ctx, "doh.example")
	if err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("got %v, want cached [203.0.113.9]", ips)
	}
}

// TestSetBootstrapDNSRejectsSyntheticResolver guards the loop directly: our
// own synthetic DNS address must never be accepted as the bootstrap resolver.
func TestSetBootstrapDNSRejectsSyntheticResolver(t *testing.T) {
	resetBootstrapState(t)
	e, _ := newPacketTestEngine(t)

	e.SetBootstrapDNS(net.JoinHostPort(SyntheticIPv6DNS.String(), "53"))

	bootstrapState.mu.RLock()
	got := bootstrapState.plainDNS
	bootstrapState.mu.RUnlock()

	if got != "" {
		t.Fatalf("synthetic resolver was accepted as bootstrap: %q", got)
	}
}
