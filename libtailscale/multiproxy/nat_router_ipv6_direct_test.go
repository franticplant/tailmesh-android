// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
	"testing"
)

// TestRejectDoomedDirectIPv6 is the regression test for the gap left open by
// §93 (validation_and_gaps.md): dialWithRetry fails an unusable-IPv6 @direct
// dial fast, but only after gVisor has already accepted the flow and ACKed
// the client's TLS ClientHello into its local receive buffer - the client
// still sees a completed handshake and an accepted ClientHello before the
// reset, which is enough to fool an app's Happy-Eyeballs/connection-pool
// logic into a rapid reconnect storm (the exact pattern in
// capture-20260908-054013.pcapng: ~40 new connections in ~1.2s, each doing a
// full ClientHello before an RST). rejectDoomedDirectIPv6 lets
// handleTCPConnection answer the same question before ever calling
// r.CreateEndpoint, so the flow is never accepted at all.
func TestRejectDoomedDirectIPv6(t *testing.T) {
	v6 := netip.MustParseAddr("2a06:98c1:3109::6812:2929")
	v4 := netip.MustParseAddr("172.64.146.215")
	unusable := func() bool { return false }
	usable := func() bool { return true }

	tests := []struct {
		name       string
		decision   RouteDecision
		targetIP   netip.Addr
		ipv6Usable *func() bool
		want       bool
	}{
		{
			name:       "no hook installed - never rejects (dial-time check remains the fallback)",
			decision:   RouteDecision{UpstreamID: DirectUpstreamID},
			targetIP:   v6,
			ipv6Usable: nil,
			want:       false,
		},
		{
			name:       "direct IPv6 with unusable network - rejected",
			decision:   RouteDecision{UpstreamID: DirectUpstreamID},
			targetIP:   v6,
			ipv6Usable: &unusable,
			want:       true,
		},
		{
			name:       "direct IPv6 with usable network - not rejected",
			decision:   RouteDecision{UpstreamID: DirectUpstreamID},
			targetIP:   v6,
			ipv6Usable: &usable,
			want:       false,
		},
		{
			name:       "direct IPv4 - never rejected on this account, even with an unusable-IPv6 hook",
			decision:   RouteDecision{UpstreamID: DirectUpstreamID},
			targetIP:   v4,
			ipv6Usable: &unusable,
			want:       false,
		},
		{
			name:       "IPv6 routed through a tailnet, not @direct - never rejected on this account",
			decision:   RouteDecision{UpstreamID: "some-tailnet"},
			targetIP:   v6,
			ipv6Usable: &unusable,
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rejectDoomedDirectIPv6(tc.decision, tc.targetIP, tc.ipv6Usable)
			if got != tc.want {
				t.Fatalf("rejectDoomedDirectIPv6() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSetDirectIPv6UsableFunc confirms the Engine-level setter round-trips
// through directIPv6Usable the way rejectDoomedDirectIPv6 expects to read
// it, and that nil disables the check again (matching SetDirectDialer's own
// nil-disables convention).
func TestSetDirectIPv6UsableFunc(t *testing.T) {
	e := newDirectEngine(t)

	if p := e.directIPv6Usable.Load(); p != nil {
		t.Fatalf("directIPv6Usable = %v before SetDirectIPv6UsableFunc, want nil", p)
	}

	e.SetDirectIPv6UsableFunc(func() bool { return false })
	p := e.directIPv6Usable.Load()
	if p == nil || (*p)() != false {
		t.Fatalf("directIPv6Usable after SetDirectIPv6UsableFunc(false-returning) = %v, want a func returning false", p)
	}

	e.SetDirectIPv6UsableFunc(nil)
	if p := e.directIPv6Usable.Load(); p != nil {
		t.Fatalf("directIPv6Usable = %v after SetDirectIPv6UsableFunc(nil), want nil", p)
	}
}
