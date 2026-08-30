// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

type flakyResolver struct {
	calls    atomic.Int32
	failFor  int32 // number of leading calls that report unknown
	uidAfter int32
}

func (r *flakyResolver) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	n := r.calls.Add(1)
	if n <= r.failFor {
		return UnknownAppUID
	}
	return r.uidAfter
}

func TestResolveAppUIDRetriesOnFailure(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &flakyResolver{failFor: 1, uidAfter: 4242}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != 4242 {
		t.Fatalf("uid = %d, want 4242 (should have succeeded on retry)", uid)
	}
	if got := r.calls.Load(); got != 3 {
		t.Fatalf("resolver called %d times, want 3 (one failure + one retry that succeeded + one corroboration)", got)
	}
}

// churningResolver simulates a local port being reused by a different app
// between the first lookup for a 5-tuple and the corroborating one right
// after it: the first call sees the original owner, every call after that
// sees the new one - modeling a short-lived socket closing and its port
// being reassigned mid-attribution.
type churningResolver struct {
	calls    atomic.Int32
	firstUID int32
	laterUID int32
}

func (r *churningResolver) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	if r.calls.Add(1) == 1 {
		return r.firstUID
	}
	return r.laterUID
}

func TestResolveAppUIDRejectsMismatchedCorroboration(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &churningResolver{firstUID: 1111, laterUID: 2222}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != UnknownAppUID {
		t.Fatalf("uid = %d, want UnknownAppUID (corroboration disagreed, must not trust either answer)", uid)
	}
}

func TestResolveAppUIDAcceptsAgreeingCorroboration(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &churningResolver{firstUID: 4242, laterUID: 4242}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != 4242 {
		t.Fatalf("uid = %d, want 4242 (two calls agreed)", uid)
	}
}

func TestResolveAppUIDGivesUpAfterMaxAttempts(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &flakyResolver{failFor: 100, uidAfter: 4242}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != UnknownAppUID {
		t.Fatalf("uid = %d, want UnknownAppUID", uid)
	}
	if got := r.calls.Load(); got != uidResolveMaxAttempts {
		t.Fatalf("resolver called %d times, want %d", got, uidResolveMaxAttempts)
	}
}
