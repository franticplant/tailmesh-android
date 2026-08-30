// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"net/netip"
	"testing"

	"tailscale.com/tsnet"
)

func realIPTestEngine(t *testing.T, upstreams ...UpstreamID) *Engine {
	t.Helper()
	e := NewEngine(t.TempDir(), &MockCallback{})
	e.mu.Lock()
	for _, id := range upstreams {
		e.tailnets[id] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	}
	e.mu.Unlock()
	return e
}

func realIPRecord(upstream UpstreamID, stableID, hostname string, addr netip.Addr) TargetRecord {
	rec := TargetRecord{
		Key:              TargetKey{upstream, TargetKindTailscaleNode, stableID},
		Hostname:         hostname,
		RequiredUpstream: upstream,
	}
	if addr.Is4() {
		rec.CurrentIPv4 = addr
	} else {
		rec.CurrentIPv6 = addr
	}
	rec.SyntheticIPv6 = rec.Key.SyntheticIPv6()
	return rec
}

func conflictsOf(t *testing.T, e *Engine) []AddressConflictExport {
	t.Helper()
	var out []AddressConflictExport
	if err := json.Unmarshal([]byte(e.GetAddressConflictsJSON()), &out); err != nil {
		t.Fatalf("conflict export is not valid JSON: %v", err)
	}
	return out
}

// TestRealTailscaleRangesAreDisjointFromSynthetic is the invariant the whole
// scheme rests on: if a synthetic prefix ever overlapped real Tailscale
// space, resolveRoute's "inside synthetic namespace -> fail closed" branch
// would swallow real peer addresses before they ever reached the real-IP
// index.
func TestRealTailscaleRangesAreDisjointFromSynthetic(t *testing.T) {
	if RealTailscaleIPv4Prefix.Overlaps(SyntheticIPv4Prefix) {
		t.Fatalf("%v overlaps synthetic v4 pool %v", RealTailscaleIPv4Prefix, SyntheticIPv4Prefix)
	}
	if RealTailscaleIPv6Prefix.Overlaps(SyntheticIPv6Prefix) {
		t.Fatalf("%v overlaps synthetic v6 pool %v", RealTailscaleIPv6Prefix, SyntheticIPv6Prefix)
	}
	for _, addr := range []netip.Addr{
		netip.MustParseAddr("100.64.0.1"),
		netip.MustParseAddr("100.127.255.254"),
		netip.MustParseAddr("fd7a:115c:a1e0::1"),
	} {
		if !IsRealTailscaleAddr(addr) {
			t.Fatalf("%v not recognized as real Tailscale space", addr)
		}
	}
	for _, addr := range []netip.Addr{
		SyntheticIPv4Interface,
		SyntheticIPv6Interface,
		netip.MustParseAddr("192.168.1.5"),
	} {
		if IsRealTailscaleAddr(addr) {
			t.Fatalf("%v wrongly classified as real Tailscale space", addr)
		}
	}
}

// TestUnambiguousRealIPIsNotAConflict guards the common case: with one
// tailnet claiming an address, the conflicts list must stay empty, so the UI
// doesn't cry wolf on every peer.
func TestUnambiguousRealIPIsNotAConflict(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	addr := netip.MustParseAddr("100.90.1.1")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "peer-a.", addr)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{
		realIPRecord("tn-b", "peer-b", "peer-b.", netip.MustParseAddr("100.90.1.2")),
	})

	if got := conflictsOf(t, e); len(got) != 0 {
		t.Fatalf("expected no conflicts, got %+v", got)
	}
	if _, ok := e.resolveRoute(addr); !ok {
		t.Fatal("unambiguous real IP should route")
	}
}

// TestConflictExportMatchesRoutingDecision is the point of the export: what
// the user is shown as the winning tailnet has to be the tailnet the
// dataplane actually dials, or the list is worse than useless.
func TestConflictExportMatchesRoutingDecision(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	shared := netip.MustParseAddr("100.90.1.1")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "alpha.", shared)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{realIPRecord("tn-b", "peer-b", "beta.", shared)})

	conflicts := conflictsOf(t, e)
	if len(conflicts) != 1 {
		t.Fatalf("expected exactly 1 conflict, got %+v", conflicts)
	}
	c := conflicts[0]
	if c.IP != shared.String() {
		t.Fatalf("conflict reported for %s, want %s", c.IP, shared)
	}
	if len(c.Candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %+v", c.Candidates)
	}
	if c.Candidates[0].Hostname != "alpha." || c.Candidates[1].Hostname != "beta." {
		t.Fatalf("candidates lack usable hostnames: %+v", c.Candidates)
	}

	decision, ok := e.resolveRoute(shared)
	if !ok {
		t.Fatal("ambiguous real IP should still route best-effort")
	}
	if string(decision.UpstreamID) != c.ChosenTailnetID {
		t.Fatalf("export says %q wins but routing chose %q", c.ChosenTailnetID, decision.UpstreamID)
	}
}

// TestConflictSkipsInactiveUpstream covers the failure domain that matters
// most here: one of two claimants going away. The address must resolve to the
// tailnet that's still up, not fail because the deterministic winner happens
// to be the one that stopped.
func TestConflictSkipsInactiveUpstream(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	shared := netip.MustParseAddr("100.90.1.1")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "alpha.", shared)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{realIPRecord("tn-b", "peer-b", "beta.", shared)})

	// tn-a would win on the tie-break; take it out of service.
	e.mu.Lock()
	e.tailnets["tn-a"].Enabled = false
	e.mu.Unlock()

	decision, ok := e.resolveRoute(shared)
	if !ok {
		t.Fatal("address should still route via the remaining active tailnet")
	}
	if decision.UpstreamID != "tn-b" {
		t.Fatalf("routed via %q, want the still-active tn-b", decision.UpstreamID)
	}

	conflicts := conflictsOf(t, e)
	if len(conflicts) != 1 {
		t.Fatalf("expected the conflict to remain listed, got %+v", conflicts)
	}
	if conflicts[0].ChosenTailnetID != "tn-b" {
		t.Fatalf("export chose %q, want tn-b", conflicts[0].ChosenTailnetID)
	}
	for _, cand := range conflicts[0].Candidates {
		if cand.TailnetID == "tn-a" && cand.Active {
			t.Fatal("disabled tn-a still reported as active")
		}
	}
}

// TestConflictWithNoActiveClaimantFailsClosed: if nothing claiming the
// address is up, guessing an upstream would send traffic to a tailnet that
// never had that peer. Fail instead, and say so in the export.
func TestConflictWithNoActiveClaimantFailsClosed(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	shared := netip.MustParseAddr("100.90.1.1")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "alpha.", shared)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{realIPRecord("tn-b", "peer-b", "beta.", shared)})

	e.mu.Lock()
	e.tailnets["tn-a"].Enabled = false
	e.tailnets["tn-b"].Enabled = false
	e.mu.Unlock()

	if decision, ok := e.resolveRoute(shared); ok {
		t.Fatalf("expected fail-closed, got route via %q", decision.UpstreamID)
	}
	conflicts := conflictsOf(t, e)
	if len(conflicts) != 1 || conflicts[0].ChosenTailnetID != "" {
		t.Fatalf("expected a listed conflict with no winner, got %+v", conflicts)
	}
}

// TestRealIPv6ConflictIsTracked confirms the ULA side is indexed too, not
// just CGNAT v4 - a peer's v6 address is just as likely to be handed to an
// app literally.
func TestRealIPv6ConflictIsTracked(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	shared := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "alpha.", shared)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{realIPRecord("tn-b", "peer-b", "beta.", shared)})

	conflicts := conflictsOf(t, e)
	if len(conflicts) != 1 || conflicts[0].IP != shared.String() {
		t.Fatalf("expected the v6 address to be listed as a conflict, got %+v", conflicts)
	}
	if _, ok := e.resolveRoute(shared); !ok {
		t.Fatal("ambiguous real v6 address should route best-effort")
	}
}

// TestRealIPConflictClearsWhenPeerLeaves: a conflict that has gone away must
// stop being reported, otherwise the list accumulates stale warnings that
// train the user to ignore it.
func TestRealIPConflictClearsWhenPeerLeaves(t *testing.T) {
	e := realIPTestEngine(t, "tn-a", "tn-b")
	shared := netip.MustParseAddr("100.90.1.1")
	e.updateTailnetSnapshot("tn-a", []TargetRecord{realIPRecord("tn-a", "peer-a", "alpha.", shared)})
	e.updateTailnetSnapshot("tn-b", []TargetRecord{realIPRecord("tn-b", "peer-b", "beta.", shared)})
	if len(conflictsOf(t, e)) != 1 {
		t.Fatal("precondition: expected a conflict")
	}

	e.updateTailnetSnapshot("tn-b", nil)

	if got := conflictsOf(t, e); len(got) != 0 {
		t.Fatalf("conflict should have cleared, got %+v", got)
	}
	decision, ok := e.resolveRoute(shared)
	if !ok || decision.UpstreamID != "tn-a" {
		t.Fatalf("expected an unambiguous route via tn-a, got %+v ok=%v", decision, ok)
	}
}
