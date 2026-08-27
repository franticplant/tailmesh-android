package multiproxy

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func flow(proto, dst string, uid int32) FlowInfo {
	return FlowInfo{
		Protocol: proto,
		Src:      netip.MustParseAddrPort("198.18.0.1:44444"),
		Dst:      netip.MustParseAddrPort(dst),
		AppUID:   uid,
	}
}

func TestWildcardSelectorMatchesEverything(t *testing.T) {
	var s Selector
	if !s.IsWildcard() {
		t.Fatal("zero Selector should be a wildcard")
	}
	for _, f := range []FlowInfo{
		flow("tcp", "1.1.1.1:443", UnknownAppUID),
		flow("udp", "[2606:4700::1111]:53", 10123),
	} {
		if !s.matches(f) {
			t.Fatalf("wildcard selector did not match %+v", f)
		}
	}
}

// The central fail-safe: a rule scoped to specific apps must never match a flow
// whose owner could not be determined. Otherwise a failed platform lookup would
// silently apply an app-specific route to arbitrary traffic.
func TestUIDScopedRuleNeverMatchesUnattributedFlow(t *testing.T) {
	s := Selector{AppUIDs: []int32{10123}}
	if s.matches(flow("tcp", "1.1.1.1:443", UnknownAppUID)) {
		t.Fatal("UID-scoped selector matched a flow with UnknownAppUID")
	}
	if !s.matches(flow("tcp", "1.1.1.1:443", 10123)) {
		t.Fatal("UID-scoped selector did not match its own UID")
	}
	if s.matches(flow("tcp", "1.1.1.1:443", 10999)) {
		t.Fatal("UID-scoped selector matched a different UID")
	}
}

func TestSelectorFieldsAreConjunctive(t *testing.T) {
	s := Selector{
		AppUIDs:     []int32{10123},
		Protocols:   []string{"tcp"},
		DstPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		DstPorts:    []PortRange{{Lo: 443, Hi: 443}},
	}
	if !s.matches(flow("tcp", "10.1.2.3:443", 10123)) {
		t.Fatal("all-fields-satisfied flow should match")
	}
	for name, f := range map[string]FlowInfo{
		"wrong uid":    flow("tcp", "10.1.2.3:443", 10999),
		"wrong proto":  flow("udp", "10.1.2.3:443", 10123),
		"wrong prefix": flow("tcp", "192.168.1.5:443", 10123),
		"wrong port":   flow("tcp", "10.1.2.3:8443", 10123),
	} {
		if s.matches(f) {
			t.Fatalf("%s: selector matched when it should not", name)
		}
	}
}

func TestSelectorPortRangeIsInclusive(t *testing.T) {
	s := Selector{DstPorts: []PortRange{{Lo: 5060, Hi: 5061}}}
	for _, p := range []string{"1.1.1.1:5060", "1.1.1.1:5061"} {
		if !s.matches(flow("udp", p, UnknownAppUID)) {
			t.Fatalf("port range should include %s", p)
		}
	}
	for _, p := range []string{"1.1.1.1:5059", "1.1.1.1:5062"} {
		if s.matches(flow("udp", p, UnknownAppUID)) {
			t.Fatalf("port range should exclude %s", p)
		}
	}
}

// A v4-mapped v6 destination must still match a v4 prefix, or a rule written as
// 10.0.0.0/8 would silently miss traffic the stack handed us in v6 form.
func TestV4MappedDestinationMatchesV4Prefix(t *testing.T) {
	s := Selector{DstPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:10.1.2.3"), 443)
	if !s.matches(FlowInfo{Protocol: "tcp", Dst: mapped, AppUID: UnknownAppUID}) {
		t.Fatal("v4-mapped destination did not match v4 prefix")
	}
}

func TestPolicyIsFirstMatchWins(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Name: "app-specific", Selector: Selector{AppUIDs: []int32{10123}}, Action: ActionRoute, Upstream: "tn-a"},
		{Name: "default", Action: ActionRoute, Upstream: "tn-b"},
	}}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	r, idx, ok := p.Match(flow("tcp", "1.1.1.1:443", 10123))
	if !ok || idx != 0 || r.Upstream != "tn-a" {
		t.Fatalf("bound app should hit rule 0 -> tn-a, got idx=%d rule=%+v ok=%v", idx, r, ok)
	}

	r, idx, ok = p.Match(flow("tcp", "1.1.1.1:443", 10999))
	if !ok || idx != 1 || r.Upstream != "tn-b" {
		t.Fatalf("other app should fall to the default rule, got idx=%d rule=%+v ok=%v", idx, r, ok)
	}

	// And an unattributed flow lands on the default, never the app rule.
	_, idx, ok = p.Match(flow("tcp", "1.1.1.1:443", UnknownAppUID))
	if !ok || idx != 1 {
		t.Fatalf("unattributed flow should hit the default rule, got idx=%d ok=%v", idx, ok)
	}
}

func TestPolicyNoMatchWhenNoRuleApplies(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Selector: Selector{Protocols: []string{"udp"}}, Action: ActionBlock},
	}}
	if _, _, ok := p.Match(flow("tcp", "1.1.1.1:443", UnknownAppUID)); ok {
		t.Fatal("tcp flow should not match a udp-only rule")
	}
}

func TestPolicyValidateRejectsMalformedRules(t *testing.T) {
	cases := map[string]Policy{
		"route without upstream": {Rules: []Rule{{Action: ActionRoute}}},
		"missing action":         {Rules: []Rule{{Name: "x"}}},
		"unknown action":         {Rules: []Rule{{Action: Action("teleport")}}},
		"inverted port range":    {Rules: []Rule{{Action: ActionBlock, Selector: Selector{DstPorts: []PortRange{{Lo: 100, Hi: 10}}}}}},
		"unknown protocol":       {Rules: []Rule{{Action: ActionBlock, Selector: Selector{Protocols: []string{"sctp"}}}}},
		"invalid prefix":         {Rules: []Rule{{Action: ActionBlock, Selector: Selector{DstPrefixes: []netip.Prefix{{}}}}}},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: expected a validation error, got nil", name)
		}
	}
}

// A policy is edited and stored independently of which upstreams happen to be
// running, so naming an absent one must not make the whole policy unloadable.
// It fails closed later, at resolution time.
func TestPolicyValidateAcceptsUnknownUpstream(t *testing.T) {
	p := Policy{Rules: []Rule{{Action: ActionRoute, Upstream: "not-registered-yet"}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy naming an absent upstream should still validate: %v", err)
	}
}

func TestPolicyBlockAndDirectNeedNoUpstream(t *testing.T) {
	p := Policy{Rules: []Rule{
		{Action: ActionBlock},
		{Action: ActionDirect},
	}}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestPolicyJSONRoundTrip(t *testing.T) {
	original := Policy{Rules: []Rule{
		{
			Name: "signal via wireguard",
			Selector: Selector{
				AppUIDs:     []int32{10123, 10124},
				Protocols:   []string{"udp"},
				DstPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				DstPorts:    []PortRange{{Lo: 5060, Hi: 5061}},
			},
			Action:   ActionRoute,
			Upstream: "wg-home",
		},
		{Name: "block ads", Selector: Selector{DstPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, Action: ActionBlock},
		{Name: "default direct", Action: ActionDirect},
	}}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetPolicyJSON(string(encoded)); err != nil {
		t.Fatalf("SetPolicyJSON: %v", err)
	}

	var got Policy
	if err := json.Unmarshal([]byte(e.PolicyJSON()), &got); err != nil {
		t.Fatalf("unmarshal round trip: %v", err)
	}
	if len(got.Rules) != len(original.Rules) {
		t.Fatalf("rule count: got %d want %d", len(got.Rules), len(original.Rules))
	}
	for i := range got.Rules {
		if got.Rules[i].Name != original.Rules[i].Name ||
			got.Rules[i].Action != original.Rules[i].Action ||
			got.Rules[i].Upstream != original.Rules[i].Upstream {
			t.Fatalf("rule %d: got %+v want %+v", i, got.Rules[i], original.Rules[i])
		}
	}
	// The selector must survive intact, or a per-app rule silently widens.
	if len(got.Rules[0].Selector.AppUIDs) != 2 || got.Rules[0].Selector.AppUIDs[0] != 10123 {
		t.Fatalf("AppUIDs did not survive the round trip: %+v", got.Rules[0].Selector.AppUIDs)
	}
	if len(got.Rules[0].Selector.DstPorts) != 1 || got.Rules[0].Selector.DstPorts[0].Hi != 5061 {
		t.Fatalf("DstPorts did not survive the round trip: %+v", got.Rules[0].Selector.DstPorts)
	}
}

func TestSetPolicyRejectsInvalidWholesale(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	good := Policy{Rules: []Rule{{Name: "keep", Action: ActionBlock}}}
	if err := e.SetPolicy(good); err != nil {
		t.Fatalf("SetPolicy(good): %v", err)
	}

	bad := Policy{Rules: []Rule{
		{Name: "fine", Action: ActionBlock},
		{Name: "broken", Action: ActionRoute}, // no upstream
	}}
	if err := e.SetPolicy(bad); err == nil {
		t.Fatal("SetPolicy should reject a policy containing an invalid rule")
	}

	// The previous policy must still be in force: a rejected edit that partially
	// applied would leave traffic following half a ruleset.
	var current Policy
	if err := json.Unmarshal([]byte(e.PolicyJSON()), &current); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(current.Rules) != 1 || current.Rules[0].Name != "keep" {
		t.Fatalf("rejected policy leaked into the active one: %+v", current.Rules)
	}
}

func TestSetPolicyJSONEmptyClearsPolicy(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetPolicy(Policy{Rules: []Rule{{Action: ActionBlock}}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	if err := e.SetPolicyJSON("   "); err != nil {
		t.Fatalf("SetPolicyJSON(empty): %v", err)
	}
	if _, _, ok := e.matchPolicy(flow("tcp", "1.1.1.1:443", UnknownAppUID)); ok {
		t.Fatal("cleared policy should match nothing")
	}
}

func TestSetPolicyJSONRejectsGarbage(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetPolicyJSON("{not json"); err == nil {
		t.Fatal("expected a parse error")
	}
}
