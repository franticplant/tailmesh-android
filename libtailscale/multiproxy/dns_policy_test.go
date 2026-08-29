package multiproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func appRule(name string, uids []int32, action Action, upstream UpstreamID) Rule {
	return Rule{
		Name:     name,
		Selector: Selector{AppUIDs: uids},
		Action:   action,
		Upstream: upstream,
	}
}

func TestMatchAppOnlySkipsDestinationScopedRules(t *testing.T) {
	policy := Policy{Rules: []Rule{
		// A rule about a destination cannot be evaluated for a query whose
		// destination is not yet known, so it must be passed over rather than
		// matched on its app selector alone.
		{
			Name:     "https to a range",
			Selector: Selector{AppUIDs: []int32{1000}, DstPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
			Action:   ActionRoute,
			Upstream: "wrong",
		},
		{
			Name:     "a port rule",
			Selector: Selector{AppUIDs: []int32{1000}, DstPorts: []PortRange{{Lo: 443, Hi: 443}}},
			Action:   ActionRoute,
			Upstream: "wrong",
		},
		{
			Name:     "a protocol rule",
			Selector: Selector{AppUIDs: []int32{1000}, Protocols: []string{"tcp"}},
			Action:   ActionRoute,
			Upstream: "wrong",
		},
		appRule("the app's own route", []int32{1000}, ActionRoute, "right"),
	}}

	rule, ok := policy.MatchAppOnly(1000)
	if !ok {
		t.Fatal("expected a match")
	}
	if rule.Upstream != "right" {
		t.Fatalf("matched %q (%s)", rule.Upstream, rule.Name)
	}
}

func TestMatchAppOnlyOrderingAndWildcards(t *testing.T) {
	policy := Policy{Rules: []Rule{
		appRule("bound app", []int32{1000}, ActionRoute, "proxy"),
		{Name: "default", Action: ActionRoute, Upstream: "fallback"},
	}}

	if rule, ok := policy.MatchAppOnly(1000); !ok || rule.Upstream != "proxy" {
		t.Fatalf("bound app matched %v %v", rule, ok)
	}
	// An app with no rule of its own falls to the wildcard default.
	if rule, ok := policy.MatchAppOnly(2000); !ok || rule.Upstream != "fallback" {
		t.Fatalf("unbound app matched %v %v", rule, ok)
	}
	// An unattributed query may only widen what matches, never narrow it: it
	// must reach the default and never the UID-scoped rule.
	if rule, ok := policy.MatchAppOnly(UnknownAppUID); !ok || rule.Upstream != "fallback" {
		t.Fatalf("unattributed query matched %v %v", rule, ok)
	}
}

func TestMatchAppOnlyNoRules(t *testing.T) {
	if _, ok := (Policy{}).MatchAppOnly(1000); ok {
		t.Fatal("an empty policy should match nothing")
	}
}

func TestDNSRouteFor(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	up := newFake("proxy", true)
	if err := e.RegisterUpstream(up); err != nil {
		t.Fatal(err)
	}
	if err := e.RegisterUpstream(newFake("down", false)); err != nil {
		t.Fatal(err)
	}

	flow := func(uid int32) FlowInfo { return FlowInfo{Protocol: "udp", AppUID: uid} }

	t.Run("no policy leaves from the device", func(t *testing.T) {
		r := e.dnsRouteFor(flow(1000))
		if r.provider != nil || r.blocked || r.failed {
			t.Fatalf("got %+v", r)
		}
	})

	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("routed", []int32{1000}, ActionRoute, "proxy"),
		appRule("blocked", []int32{1001}, ActionBlock, ""),
		appRule("direct", []int32{1002}, ActionDirect, ""),
		appRule("via the direct upstream", []int32{1003}, ActionRoute, DirectUpstreamID),
		appRule("via something switched off", []int32{1004}, ActionRoute, "down"),
		appRule("via something absent", []int32{1005}, ActionRoute, "gone"),
		{Name: "data tunnels, DNS stays direct", Selector: Selector{AppUIDs: []int32{1006}}, Action: ActionRoute, Upstream: "proxy", DNSUpstream: DirectUpstreamID},
		{Name: "direct data, DNS via a different upstream", Selector: Selector{AppUIDs: []int32{1007}}, Action: ActionDirect, DNSUpstream: "proxy"},
	}}); err != nil {
		t.Fatal(err)
	}

	t.Run("routed app uses its upstream", func(t *testing.T) {
		r := e.dnsRouteFor(flow(1000))
		if r.provider == nil || r.provider.ID() != "proxy" {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("blocked app is refused", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1001)); !r.blocked {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("direct action leaves from the device", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1002)); r.provider != nil || r.blocked || r.failed {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("routing to @direct leaves from the device", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1003)); r.provider != nil || r.blocked || r.failed {
			t.Fatalf("got %+v", r)
		}
	})
	// A named upstream that cannot carry the query must fail, not quietly fall
	// back to the device - that is the leak this whole path exists to close.
	t.Run("disabled upstream fails closed", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1004)); !r.failed || r.provider != nil {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("missing upstream fails closed", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1005)); !r.failed || r.provider != nil {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("unmatched app leaves from the device", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(9999)); r.provider != nil || r.blocked || r.failed {
			t.Fatalf("got %+v", r)
		}
	})
	// DNSUpstream splits the DNS path from the data path: data tunnels through
	// the app's Upstream, but DNS explicitly leaves from the device instead of
	// auto-following it.
	t.Run("DNSUpstream overrides Upstream for the data-tunnels-DNS-direct case", func(t *testing.T) {
		if r := e.dnsRouteFor(flow(1006)); r.provider != nil || r.blocked || r.failed {
			t.Fatalf("got %+v, want DNS to leave from the device despite data routing via proxy", r)
		}
	})
	// The reverse split: data leaves the device directly, but DNS still follows
	// a chosen upstream.
	t.Run("DNSUpstream applies even when the data path is direct", func(t *testing.T) {
		r := e.dnsRouteFor(flow(1007))
		if r.provider == nil || r.provider.ID() != "proxy" {
			t.Fatalf("got %+v, want DNS routed via proxy despite direct data", r)
		}
	})
}

// testDNSServer answers every A query with one fixed address, so a test can
// tell which resolver produced an answer.
type testDNSServer struct {
	pc     net.PacketConn
	answer string
}

func startTestDNS(t *testing.T, answer string) *testDNSServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testDNSServer{pc: pc, answer: answer}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			for _, q := range req.Question {
				if q.Qtype != dns.TypeA {
					continue
				}
				rr, err := dns.NewRR(q.Name + " 60 IN A " + s.answer)
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			out, err := m.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	return s
}

func (s *testDNSServer) Addr() string { return s.pc.LocalAddr().String() }

// dialProvider carries a dial to wherever dial says, and records that it did.
// It stands in for a proxy or tunnel without needing one.
type dialProvider struct {
	id    UpstreamID
	dials chan string
}

func (p *dialProvider) ID() UpstreamID     { return p.id }
func (p *dialProvider) Kind() UpstreamKind { return UpstreamKindSOCKS5 }
func (p *dialProvider) Ready() bool        { return true }
func (p *dialProvider) Close() error       { return nil }

func (p *dialProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case p.dials <- network + "|" + address:
	default:
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (p *dialProvider) PeerPathInfo(context.Context, string) string { return "test" }

// The point of the whole exercise: a query from a routed app must be forwarded
// through that app's upstream, and must reach the resolver on the far side of
// it rather than the device's own.
func TestForwardedQueryFollowsTheAppsRoute(t *testing.T) {
	viaUpstream := startTestDNS(t, "203.0.113.1")

	e := NewEngine(t.TempDir(), &MockCallback{})
	provider := &dialProvider{id: "proxy", dials: make(chan string, 4)}
	if err := e.RegisterUpstream(provider); err != nil {
		t.Fatal(err)
	}
	e.SetUpstreamDNS(viaUpstream.Addr())

	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("routed", []int32{1000}, ActionRoute, "proxy"),
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 1000})
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %v", resp)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %v", resp.Answer)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.1" {
		t.Fatalf("answer = %v", resp.Answer[0])
	}

	select {
	case got := <-provider.dials:
		if got != "udp|"+viaUpstream.Addr() {
			t.Fatalf("upstream was dialed for %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the query did not go through the app's upstream")
	}
}

// An app with no rule keeps the previous behaviour exactly: the forward is not
// routed through anything, and no upstream is dialed.
func TestUnroutedQueryDoesNotTouchAnUpstream(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	provider := &dialProvider{id: "proxy", dials: make(chan string, 4)}
	if err := e.RegisterUpstream(provider); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("someone else", []int32{1000}, ActionRoute, "proxy"),
	}}); err != nil {
		t.Fatal(err)
	}
	// No upstream resolver configured, so the forward cannot succeed - which is
	// fine, because what is under test is that the upstream is not consulted.
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 2000})

	select {
	case got := <-provider.dials:
		t.Fatalf("an unrouted query was sent through an upstream: %q", got)
	default:
	}
}

func TestBlockedAppGetsRefused(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	e.SetUpstreamDNS("192.0.2.53:53")
	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("blocked", []int32{1000}, ActionBlock, ""),
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp := e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 1000})
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestRouteToUnusableUpstreamServfails(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	e.SetUpstreamDNS("192.0.2.53:53")
	if err := e.RegisterUpstream(newFake("down", false)); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("routed", []int32{1000}, ActionRoute, "down"),
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp := e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 1000})
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

// An unattributed query must not silently fall through to the default/direct
// route when some app has an explicit binding - that would leak whichever
// app's lookup this actually was outside the route the user configured for
// it. It fails closed (SERVFAIL) instead, and counts the occurrence rather
// than guessing. See dns.go's fail-closed branch and
// flowinfo.go/observability.go's attributionFailures counter.
func TestUnattributedQueryFailsClosedWhenPolicyUsesAppUID(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	e.SetUpstreamDNS("192.0.2.53:53")
	provider := &dialProvider{id: "proxy", dials: make(chan string, 4)}
	if err := e.RegisterUpstream(provider); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("someone's route", []int32{1000}, ActionRoute, "proxy"),
		{Name: "default", Action: ActionDirect},
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	resp := e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: UnknownAppUID})
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	select {
	case got := <-provider.dials:
		t.Fatalf("unattributed query reached an upstream instead of failing closed: %q", got)
	default:
	}
	if got := e.obs.dp.dnsAttributionFailClosed; got != 1 {
		t.Fatalf("dnsAttributionFailClosed = %d, want 1", got)
	}
}

// With no UID-scoped rule in the policy at all, an unattributed query keeps
// today's behaviour (falls through to the default/no-op forward) - there is
// nothing it could be leaking out of, since nothing is app-scoped.
func TestUnattributedQueryStillWorksWithNoUIDScopedRules(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	// No SetUpstreamDNS call: the forward's early "no upstream configured"
	// check returns SERVFAIL by itself, before ever reaching the fail-closed
	// branch under test - what matters here is that the fail-closed branch
	// specifically did not fire (a real dial isn't needed either way).
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "default", Action: ActionDirect},
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: UnknownAppUID})
	if got := e.obs.dp.dnsAttributionFailClosed; got != 0 {
		t.Fatalf("dnsAttributionFailClosed = %d, want 0 (no rule is UID-scoped)", got)
	}
}

// The cached client is per upstream and resolves the provider at dial time, so
// a replaced or disabled upstream is observed rather than dialed around.
func TestDoHClientIsCachedPerUpstreamAndFailsClosed(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	first := e.dohClientFor("proxy")
	if second := e.dohClientFor("proxy"); second != first {
		t.Fatal("a second query built a new client instead of reusing one")
	}
	if other := e.dohClientFor("elsewhere"); other == first {
		t.Fatal("two upstreams share one client")
	}

	// No such upstream is registered, so the transport must refuse rather than
	// fall back to dialing from the device.
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	_, err := e.exchangeDoHVia("proxy", "https://192.0.2.1/dns-query", req)
	if err == nil {
		t.Fatal("expected the DoH request to fail")
	}
	if !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("error %q does not say the upstream was unusable", err)
	}
}

// literalOnlyProvider mimics wireguardProvider.Dial's real constraint: it
// only ever succeeds when given a literal address:port, exactly like a
// WireGuard tunnel's own netstack, which has no resolver of its own.
type literalOnlyProvider struct {
	id       UpstreamID
	lastAddr string
}

func (p *literalOnlyProvider) ID() UpstreamID                              { return p.id }
func (p *literalOnlyProvider) Kind() UpstreamKind                          { return UpstreamKindWireGuard }
func (p *literalOnlyProvider) Ready() bool                                 { return true }
func (p *literalOnlyProvider) Close() error                                { return nil }
func (p *literalOnlyProvider) PeerPathInfo(context.Context, string) string { return "wireguard" }

func (p *literalOnlyProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, fmt.Errorf("literalOnlyProvider: destination %q must be a literal address:port", address)
	}
	p.lastAddr = address
	client, server := net.Pipe()
	go server.Close()
	return client, nil
}

// A DoH resolver's own hostname (not an app's destination) must still work
// when the query is forwarded through an upstream whose transport - like a
// WireGuard tunnel's own netstack - cannot resolve a hostname itself. See
// dns_policy.go's dohClientFor: on a literal-address dial failure, it
// resolves the hostname off-tunnel (the same bootstrap path the
// device-direct DoH client already used) and retries once with the literal
// IP, rather than failing every query through that upstream.
func TestDoHDialResolvesHostnameForLiteralOnlyUpstream(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	// security.cloudflare-dns.com is in the built-in known-IP table
	// (publicdns.DoHIPsOfBase), so this needs no real network access -
	// exactly the same lookup dialUpstreamDNS already relies on for the
	// device-direct DoH path.
	const dohBase = "https://security.cloudflare-dns.com/dns-query"
	setBootstrapDoHBase(dohBase)
	defer setBootstrapDoHBase("")

	fp := &literalOnlyProvider{id: "wg"}
	if err := e.RegisterUpstream(fp); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}

	transport, ok := e.dohClientFor("wg").Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected the DoH client to use an *http.Transport")
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "security.cloudflare-dns.com:443")
	if err != nil {
		t.Fatalf("DialContext through a literal-only upstream failed: %v", err)
	}
	conn.Close()

	host, _, err := net.SplitHostPort(fp.lastAddr)
	if err != nil {
		t.Fatalf("provider was dialed with an unparseable address %q: %v", fp.lastAddr, err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		t.Fatalf("provider was dialed with %q, want a literal IP", fp.lastAddr)
	}
}
