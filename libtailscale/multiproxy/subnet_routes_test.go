// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func testSubnetEngine(t *testing.T) *Engine {
	t.Helper()
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	return e
}

func addTestTailnet(e *Engine, id string, enabled, accept bool, routes map[string]string) {
	prefixes := make(map[netip.Prefix]string, len(routes))
	for prefix, peer := range routes {
		prefixes[netip.MustParsePrefix(prefix)] = peer
	}
	e.tailnets[UpstreamID(id)] = &TailnetRuntime{
		Enabled:          enabled,
		AcceptRoutes:     accept,
		AdvertisedRoutes: prefixes,
	}
	e.rebuildSubnetsLocked()
}

func subnetByPrefix(e *Engine, prefix string) (subnetRoute, bool) {
	want := netip.MustParsePrefix(prefix)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, sr := range e.subnets {
		if sr.Prefix == want {
			return sr, true
		}
	}
	return subnetRoute{}, false
}

func TestSubnetRoutesOnlyWhenEnabledAndAccepted(t *testing.T) {
	e := testSubnetEngine(t)
	addTestTailnet(e, "regular-a", true, false, map[string]string{
		"192.168.1.0/24": "router-a",
	})
	if _, ok := subnetByPrefix(e, "192.168.1.0/24"); ok {
		t.Fatal("route accepted while the switch is off")
	}

	if err := e.SetTailnetAcceptRoutes("regular-a", true); err != nil {
		t.Fatal(err)
	}
	sr, ok := subnetByPrefix(e, "192.168.1.0/24")
	if !ok {
		t.Fatal("route not accepted after enabling the switch")
	}
	if sr.TailnetID != "regular-a" || sr.Peer != "router-a" {
		t.Fatalf("wrong route owner: %+v", sr)
	}

	if err := e.SetTailnetAcceptRoutes("regular-a", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := subnetByPrefix(e, "192.168.1.0/24"); ok {
		t.Fatal("route still present after disabling the switch")
	}
}

func TestSubnetRoutesConflictPicksLowestTailnet(t *testing.T) {
	e := testSubnetEngine(t)
	addTestTailnet(e, "regular-b", true, true, map[string]string{
		"10.20.0.0/16": "router-b",
	})
	addTestTailnet(e, "regular-a", true, true, map[string]string{
		"10.20.0.0/16": "router-a",
	})

	sr, ok := subnetByPrefix(e, "10.20.0.0/16")
	if !ok {
		t.Fatal("conflicting route missing")
	}
	if sr.TailnetID != "regular-a" {
		t.Fatalf("conflict resolved to %q, want regular-a", sr.TailnetID)
	}

	var got SubnetRoutesExport
	if err := json.Unmarshal([]byte(e.GetSubnetRoutesJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Accepted) != 1 || got.Accepted[0].TailnetID != "regular-a" {
		t.Fatalf("accepted = %+v, want only regular-a", got.Accepted)
	}
	if len(got.Conflicts) != 1 || got.Conflicts[0].Prefix != "10.20.0.0/16" {
		t.Fatalf("conflicts = %+v", got.Conflicts)
	}
	if len(got.Conflicts[0].Candidates) != 2 {
		t.Fatalf("candidates = %+v", got.Conflicts[0].Candidates)
	}
	for _, c := range got.Conflicts[0].Candidates {
		if c.TailnetID == "regular-a" && !c.Chosen {
			t.Fatal("regular-a is the chosen route but not marked chosen")
		}
		if c.TailnetID == "regular-b" && c.Chosen {
			t.Fatal("regular-b is not the chosen route but marked chosen")
		}
	}
}

func TestSubnetRoutesDisabledTailnetIsNotAConflict(t *testing.T) {
	e := testSubnetEngine(t)
	addTestTailnet(e, "regular-a", true, true, map[string]string{
		"10.30.0.0/16": "router-a",
	})
	addTestTailnet(e, "regular-b", false, true, map[string]string{
		"10.30.0.0/16": "router-b",
	})

	var got SubnetRoutesExport
	if err := json.Unmarshal([]byte(e.GetSubnetRoutesJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Conflicts) != 0 {
		t.Fatalf("stopped tailnet produced a conflict: %+v", got.Conflicts)
	}
	if len(got.Accepted) != 1 || got.Accepted[0].TailnetID != "regular-a" {
		t.Fatalf("accepted = %+v", got.Accepted)
	}
}

func TestSubnetRoutesKeepLongestPrefix(t *testing.T) {
	e := testSubnetEngine(t)
	addTestTailnet(e, "regular-a", true, true, map[string]string{
		"10.40.0.0/16": "router-a",
	})
	addTestTailnet(e, "regular-b", true, true, map[string]string{
		"10.40.5.0/24": "router-b",
	})

	var got SubnetRoutesExport
	if err := json.Unmarshal([]byte(e.GetSubnetRoutesJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Accepted) != 2 {
		t.Fatalf("accepted = %+v, want both overlapping routes", got.Accepted)
	}
	if len(got.Conflicts) != 0 {
		t.Fatalf("overlapping prefixes reported as conflicts: %+v", got.Conflicts)
	}
}
