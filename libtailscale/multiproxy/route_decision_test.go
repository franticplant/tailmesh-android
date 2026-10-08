// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestFamilyOf(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1", "4"},
		{"172.27.85.178", "4"},
		{"::1", "6"},
		{"fd7a:115c:a1e0::1", "6"},
		// An IPv4-mapped IPv6 address is really IPv4 for this purpose.
		{"::ffff:127.0.0.1", "4"},
	}
	for _, tc := range cases {
		if got := familyOf(netip.MustParseAddr(tc.in)); got != tc.want {
			t.Errorf("familyOf(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRouteDecisionMetaJSON locks the fields the off-device attribution checklist depends on, so a
// future change to the telemetry cannot silently drop one.
func TestRouteDecisionMetaJSON(t *testing.T) {
	flow := FlowInfo{
		Protocol: "tcp",
		Src:      netip.MustParseAddrPort("10.0.0.5:1234"),
		Dst:      netip.MustParseAddrPort("[fd9b:8d7c:6a5e:1:2:3:4:5]:443"),
		AppUID:   4242,
	}
	target := netip.MustParseAddr("2a06:98c1:3121::1")
	meta := routeDecisionMetaJSON(
		flow, target,
		"100.64.10.11", "[2a06:98c1:3121::1]:443", 1234*time.Millisecond,
		[]string{"matched known peer target", "upstream @direct ready"},
	)

	var m map[string]any
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		t.Fatalf("metaJSON is not valid JSON: %v\n%s", err, meta)
	}
	for _, key := range []string{
		"virtualSrc", "virtualDst", "targetIP", "realDest",
		"dialNetwork", "dialAddr", "dialDurationMs", "trace",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("metaJSON missing key %q:\n%s", key, meta)
		}
	}
	if got := m["targetIP"]; got != "2a06:98c1:3121::1" {
		t.Errorf("targetIP = %v, want 2a06:98c1:3121::1", got)
	}
	if got := m["dialNetwork"]; got != "tcp" {
		t.Errorf("dialNetwork = %v, want tcp", got)
	}
	if got := m["dialDurationMs"]; got != float64(1234) {
		t.Errorf("dialDurationMs = %v, want 1234", got)
	}
	if trace, _ := m["trace"].([]any); len(trace) != 2 {
		t.Errorf("trace = %v, want 2 entries", m["trace"])
	}
}

// TestRouteDecisionMetaJSONOmitsAbsentDialFields: a no-route decision has no dial, so the dial
// fields must be absent rather than present-but-empty, which would misread as a real dial.
func TestRouteDecisionMetaJSONOmitsAbsentDialFields(t *testing.T) {
	flow := FlowInfo{Protocol: "tcp", Src: netip.MustParseAddrPort("10.0.0.5:1"), Dst: netip.MustParseAddrPort("10.0.0.1:443")}
	meta := routeDecisionMetaJSON(flow, netip.MustParseAddr("10.0.0.1"), "", "", 0, nil)
	var m map[string]any
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dialNetwork", "dialAddr", "dialDurationMs", "trace", "realDest"} {
		if _, ok := m[key]; ok {
			t.Errorf("metaJSON unexpectedly has %q for a no-dial decision: %s", key, meta)
		}
	}
}
