// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// fakeProvider is a registerable upstream that records dials instead of making
// them. It stands in for any non-tailnet upstream (SOCKS5, WireGuard).
type fakeProvider struct {
	id    UpstreamID
	kind  UpstreamKind
	ready bool
	dials []string
}

func (p *fakeProvider) ID() UpstreamID     { return p.id }
func (p *fakeProvider) Kind() UpstreamKind { return p.kind }
func (p *fakeProvider) Ready() bool        { return p.ready }
func (p *fakeProvider) Close() error       { return nil }

func (p *fakeProvider) Dial(_ context.Context, network, address string) (net.Conn, error) {
	if !p.ready {
		return nil, ErrUpstreamNotReady
	}
	p.dials = append(p.dials, network+"|"+address)
	return nil, errors.New("fakeProvider: no real connection")
}

func (p *fakeProvider) PeerPathInfo(context.Context, string) string { return "fake" }

func newFake(id UpstreamID, ready bool) *fakeProvider {
	return &fakeProvider{id: id, kind: UpstreamKindSOCKS5, ready: ready}
}

func tcpFlow(dst string, uid int32) FlowInfo {
	return FlowInfo{
		Protocol: "tcp",
		Src:      netip.MustParseAddrPort("198.18.0.1:40000"),
		Dst:      netip.MustParseAddrPort(dst),
		AppUID:   uid,
	}
}

// The most important guarantee of the policy layer: with no rules, every
// destination resolves exactly as it did before policy existed.
func TestEmptyPolicyPreservesLegacyRouting(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	// Synthetic address with no target record -> fail closed, unchanged.
	synthetic := netip.MustParseAddr("fd9b:8d7c:6a5e::dead:beef")
	if _, ok := e.resolveRoute(synthetic); ok {
		t.Fatal("unmapped synthetic address should still fail closed")
	}

	// Address outside every namespace and with no subnet route or exit node.
	if _, ok := e.resolveRoute(netip.MustParseAddr("1.1.1.1")); ok {
		t.Fatal("public address with no route should still fail closed")
	}

	// And nothing above depended on a policy being present.
	if _, _, ok := e.matchPolicy(tcpFlow("1.1.1.1:443", UnknownAppUID)); ok {
		t.Fatal("empty policy should match nothing")
	}
}

func TestPolicyRoutesToRegisteredUpstream(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	wg := newFake("wg-home", true)
	if err := e.RegisterUpstream(wg); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "default", Action: ActionRoute, Upstream: "wg-home"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID))
	if !ok {
		t.Fatal("policy should have produced a route")
	}
	if d.UpstreamID != "wg-home" {
		t.Fatalf("routed via %q, want wg-home", d.UpstreamID)
	}
	if d.Destination != "1.1.1.1" {
		t.Fatalf("destination %q, want 1.1.1.1", d.Destination)
	}
}

func TestPolicyBlockDenies(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.RegisterUpstream(newFake("wg-home", true)); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "block doc range", Selector: Selector{DstPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, Action: ActionBlock},
		{Name: "default", Action: ActionRoute, Upstream: "wg-home"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	if _, ok := e.resolveFlow(tcpFlow("192.0.2.5:443", UnknownAppUID)); ok {
		t.Fatal("blocked destination should not resolve")
	}
	// Everything else still routes, i.e. block did not become a catch-all.
	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID)); !ok || d.UpstreamID != "wg-home" {
		t.Fatalf("unblocked destination should route via wg-home, got %+v ok=%v", d, ok)
	}
}

func TestPolicyDirectUsesBuiltInDirectUpstream(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetPolicy(Policy{Rules: []Rule{{Action: ActionDirect}}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID))
	if !ok {
		t.Fatal("direct action should resolve")
	}
	if d.UpstreamID != DirectUpstreamID {
		t.Fatalf("direct routed via %q, want %q", d.UpstreamID, DirectUpstreamID)
	}
}

// A matched rule is final. If its upstream is down the flow must be denied, not
// quietly sent somewhere the user never named.
func TestMatchedRuleWithDownUpstreamFailsClosed(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.RegisterUpstream(newFake("wg-down", false)); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	// A subnet route that would otherwise catch this destination, to prove the
	// denial is not simply "nothing else matched either".
	e.mu.Lock()
	e.exitNodeTailnet = "tn-fallback"
	e.mu.Unlock()

	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "via down upstream", Action: ActionRoute, Upstream: "wg-down"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID)); ok {
		t.Fatalf("rule naming a down upstream should fail closed, got %+v", d)
	}
}

func TestRuleNamingAbsentUpstreamFailsClosed(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Action: ActionRoute, Upstream: "never-registered"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if _, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID)); ok {
		t.Fatal("rule naming an absent upstream should fail closed")
	}
}

func TestPerAppRuleSelectsUpstreamPerUID(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	for _, id := range []UpstreamID{"wg-a", "wg-b"} {
		if err := e.RegisterUpstream(newFake(id, true)); err != nil {
			t.Fatalf("RegisterUpstream(%s): %v", id, err)
		}
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "app 10123", Selector: Selector{AppUIDs: []int32{10123}}, Action: ActionRoute, Upstream: "wg-a"},
		{Name: "default", Action: ActionRoute, Upstream: "wg-b"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", 10123)); !ok || d.UpstreamID != "wg-a" {
		t.Fatalf("bound app should use wg-a, got %+v ok=%v", d, ok)
	}
	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", 10999)); !ok || d.UpstreamID != "wg-b" {
		t.Fatalf("other app should use wg-b, got %+v ok=%v", d, ok)
	}
	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:443", UnknownAppUID)); !ok || d.UpstreamID != "wg-b" {
		t.Fatalf("unattributed flow should use the default, got %+v ok=%v", d, ok)
	}
}

// A synthetic address encodes which upstream minted it. A route rule must not be
// able to send it somewhere the address means nothing.
func TestRouteRuleCannotRepointSyntheticDestination(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.RegisterUpstream(newFake("wg-home", true)); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}

	rec := realIPRecord("tn-a", "peer-1", "peer-1", netip.MustParseAddr("100.64.10.5"))
	e.targetMutex.Lock()
	e.targets[rec.SyntheticIPv6] = rec
	e.targetMutex.Unlock()

	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "everything via wireguard", Action: ActionRoute, Upstream: "wg-home"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// tn-a is not running, so the identity-bound route fails closed. The point is
	// that it did NOT get re-pointed at wg-home.
	d, ok := e.resolveFlow(tcpFlow(netip.AddrPortFrom(rec.SyntheticIPv6, 443).String(), UnknownAppUID))
	if ok && d.UpstreamID == "wg-home" {
		t.Fatal("a route rule must not re-point a synthetic destination")
	}
}

// Blocking is always safe to honour, including for identity-bound destinations.
func TestBlockRuleAppliesToSyntheticDestination(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	rec := realIPRecord("tn-a", "peer-1", "peer-1", netip.MustParseAddr("100.64.10.5"))
	e.targetMutex.Lock()
	e.targets[rec.SyntheticIPv6] = rec
	e.targetMutex.Unlock()

	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Name: "quarantine app", Selector: Selector{AppUIDs: []int32{10123}}, Action: ActionBlock},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	if _, ok := e.resolveFlow(tcpFlow(netip.AddrPortFrom(rec.SyntheticIPv6, 443).String(), 10123)); ok {
		t.Fatal("block rule should apply to a synthetic destination too")
	}
}

func TestPolicySelectsByProtocolAndPort(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	for _, id := range []UpstreamID{"sip-path", "default-path"} {
		if err := e.RegisterUpstream(newFake(id, true)); err != nil {
			t.Fatalf("RegisterUpstream: %v", err)
		}
	}
	if err := e.SetPolicy(Policy{Rules: []Rule{
		{
			Name:     "sip signalling",
			Selector: Selector{Protocols: []string{"udp"}, DstPorts: []PortRange{{Lo: 5060, Hi: 5061}}},
			Action:   ActionRoute, Upstream: "sip-path",
		},
		{Name: "default", Action: ActionRoute, Upstream: "default-path"},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	udp5060 := FlowInfo{Protocol: "udp", Src: netip.MustParseAddrPort("198.18.0.1:40000"), Dst: netip.MustParseAddrPort("1.1.1.1:5060"), AppUID: UnknownAppUID}
	if d, ok := e.resolveFlow(udp5060); !ok || d.UpstreamID != "sip-path" {
		t.Fatalf("udp/5060 should use sip-path, got %+v ok=%v", d, ok)
	}
	// Same port over TCP must not match the udp-scoped rule.
	if d, ok := e.resolveFlow(tcpFlow("1.1.1.1:5060", UnknownAppUID)); !ok || d.UpstreamID != "default-path" {
		t.Fatalf("tcp/5060 should fall through to default-path, got %+v ok=%v", d, ok)
	}
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

func TestDirectUpstreamIsAlwaysPresentAndUndeletable(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	p, ok := e.readyProvider(DirectUpstreamID)
	if !ok {
		t.Fatal("direct upstream should always be available")
	}
	if p.Kind() != UpstreamKindDirect {
		t.Fatalf("kind %q, want %q", p.Kind(), UpstreamKindDirect)
	}
	if err := e.UnregisterUpstream(DirectUpstreamID); err == nil {
		t.Fatal("direct upstream should not be removable")
	}
}

func TestRegisteringTailnetKindThroughRegistryIsRejected(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	p := &fakeProvider{id: "tn-x", kind: UpstreamKindTailnet, ready: true}
	if err := e.RegisterUpstream(p); err == nil {
		t.Fatal("tailnets must go through the tailnet lifecycle, not the registry")
	}
}

func TestRegisterReplacesAndUnregisterRemoves(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	first := newFake("wg", true)
	second := newFake("wg", false)

	if err := e.RegisterUpstream(first); err != nil {
		t.Fatalf("register first: %v", err)
	}
	if err := e.RegisterUpstream(second); err != nil {
		t.Fatalf("register second: %v", err)
	}
	if _, ready := e.readyProvider("wg"); ready {
		t.Fatal("replacement provider is not ready, so lookup should not report ready")
	}
	if err := e.UnregisterUpstream("wg"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if _, ok := e.lookupProvider("wg"); ok {
		t.Fatal("unregistered provider should be gone")
	}
}

func TestUpstreamSnapshotListsRegistryAndTailnets(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.RegisterUpstream(newFake("wg-home", true)); err != nil {
		t.Fatalf("RegisterUpstream: %v", err)
	}
	e.mu.Lock()
	e.tailnets["tn-a"] = &TailnetRuntime{Enabled: false}
	e.mu.Unlock()

	got := map[string]UpstreamInfo{}
	for _, info := range e.UpstreamSnapshot() {
		got[info.ID] = info
	}

	if _, ok := got[string(DirectUpstreamID)]; !ok {
		t.Fatal("snapshot should include the direct upstream")
	}
	if info, ok := got["wg-home"]; !ok || info.Kind != string(UpstreamKindSOCKS5) || !info.Ready {
		t.Fatalf("wg-home missing or wrong: %+v", info)
	}
	// A configured-but-disabled tailnet must appear, and appear as not ready, so
	// the UI can distinguish "off" from "absent".
	if info, ok := got["tn-a"]; !ok || info.Kind != string(UpstreamKindTailnet) || info.Ready {
		t.Fatalf("tn-a should be listed as a not-ready tailnet, got %+v ok=%v", info, ok)
	}
}

// ---------------------------------------------------------------------------
// app attribution
// ---------------------------------------------------------------------------

type stubUIDResolver struct {
	uid   int32
	calls int
	block chan struct{}
}

func (r *stubUIDResolver) ResolveUID(string, string, int32, string, int32) int32 {
	r.calls++
	if r.block != nil {
		<-r.block
	}
	return r.uid
}

func TestResolveAppUIDWithoutResolverIsUnknown(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	got := e.resolveAppUID("tcp", netip.MustParseAddrPort("198.18.0.1:1234"), netip.MustParseAddrPort("1.1.1.1:443"))
	if got != UnknownAppUID {
		t.Fatalf("got %d, want UnknownAppUID", got)
	}
}

func TestResolveAppUIDUsesResolver(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	e.SetUIDResolver(&stubUIDResolver{uid: 10123})
	got := e.resolveAppUID("tcp", netip.MustParseAddrPort("198.18.0.1:1234"), netip.MustParseAddrPort("1.1.1.1:443"))
	if got != 10123 {
		t.Fatalf("got %d, want 10123", got)
	}
}

// A wedged platform call must degrade to "unknown", which can only widen which
// rule matches - never stall the flow that triggered it.
func TestResolveAppUIDTimesOutToUnknown(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	blocked := make(chan struct{})
	defer close(blocked)
	e.SetUIDResolver(&stubUIDResolver{uid: 10123, block: blocked})

	got := e.resolveAppUID("tcp", netip.MustParseAddrPort("198.18.0.1:1234"), netip.MustParseAddrPort("1.1.1.1:443"))
	if got != UnknownAppUID {
		t.Fatalf("a blocked resolver should yield UnknownAppUID, got %d", got)
	}
}

// Attribution crosses JNI, so it must not be paid for when no rule could use it.
func TestAttributionSkippedWhenNoRuleIsUIDScoped(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	stub := &stubUIDResolver{uid: 10123}
	e.SetUIDResolver(stub)

	if err := e.SetPolicy(Policy{Rules: []Rule{{Action: ActionDirect}}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if e.policyUsesAppUID() {
		t.Fatal("a policy with no UID-scoped rule should not require attribution")
	}

	if err := e.SetPolicy(Policy{Rules: []Rule{
		{Selector: Selector{AppUIDs: []int32{10123}}, Action: ActionDirect},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if !e.policyUsesAppUID() {
		t.Fatal("a UID-scoped rule should require attribution")
	}
}
