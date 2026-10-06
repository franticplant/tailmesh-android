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
	// 3, though for a different reason than it looks: this is UDP, so the
	// first exact-5-tuple miss (call 1) falls through to the dst-port-zeroed
	// variant within the *same* attempt (call 2, which succeeds here since
	// failFor only fails the very first raw call) - the outer attempt loop
	// never needs a second attempt. Call 3 is the usual corroboration call.
	if got := r.calls.Load(); got != 3 {
		t.Fatalf("resolver called %d times, want 3 (one miss on the exact tuple + one success on the dst-port-zeroed variant + one corroboration)", got)
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
	// 3x: this is UDP, so each attempt that finds nothing on the exact
	// 5-tuple also retries the dst-port-zeroed and dst-unspecified variants
	// (see resolveAppUIDOnce) before giving up on that attempt.
	want := int32(uidResolveMaxAttempts) * 3
	if got := r.calls.Load(); got != want {
		t.Fatalf("resolver called %d times, want %d", got, want)
	}
}

// variantAwareResolver reports which literal (dstIP, dstPort) each call was
// made with, so a test can pin down exactly which rung of the UDP retry
// ladder (resolveAppUIDOnce) succeeded - the exact tuple, the tuple with its
// port zeroed, or the tuple with an unspecified destination address.
type variantAwareResolver struct {
	calls      atomic.Int32
	succeedsAt func(dstIP string, dstPort int32) bool
	uid        int32
}

func (r *variantAwareResolver) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	r.calls.Add(1)
	if r.succeedsAt(dstIP, dstPort) {
		return r.uid
	}
	return UnknownAppUID
}

func TestResolveAppUIDUDPFallsBackToPortZeroedVariant(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &variantAwareResolver{
		uid: 4242,
		succeedsAt: func(dstIP string, dstPort int32) bool {
			return dstIP == "10.0.0.1" && dstPort == 0
		},
	}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != 4242 {
		t.Fatalf("uid = %d, want 4242 (should have succeeded on the dst-port-zeroed variant)", uid)
	}
}

func TestResolveAppUIDUDPFallsBackToUnspecifiedDstVariant(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &variantAwareResolver{
		uid: 4242,
		succeedsAt: func(dstIP string, dstPort int32) bool {
			return dstIP == "0.0.0.0" && dstPort == 0
		},
	}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:53")
	uid := e.resolveAppUID("udp", src, dst)
	if uid != 4242 {
		t.Fatalf("uid = %d, want 4242 (should have succeeded on the unspecified-dst variant)", uid)
	}
}

// TestResolveAppUIDTCPHasNoVariantFallback pins down that the retry ladder
// is UDP-only: getConnectionOwnerUid's own contract requires an exact match
// for a connected TCP socket, so trying zeroed/unspecified variants for TCP
// would only add latency for no possible gain.
func TestResolveAppUIDTCPHasNoVariantFallback(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	r := &variantAwareResolver{
		uid: 4242,
		succeedsAt: func(dstIP string, dstPort int32) bool {
			return dstPort == 0 // would only match a variant call
		},
	}
	e.SetUIDResolver(r)

	src := netip.MustParseAddrPort("10.0.0.5:12345")
	dst := netip.MustParseAddrPort("10.0.0.1:443")
	uid := e.resolveAppUID("tcp", src, dst)
	if uid != UnknownAppUID {
		t.Fatalf("uid = %d, want UnknownAppUID (TCP must not fall back to dst variants)", uid)
	}
	// One call per attempt, no variants: uidResolveMaxAttempts, not x3.
	if got := r.calls.Load(); got != int32(uidResolveMaxAttempts) {
		t.Fatalf("resolver called %d times, want %d (TCP should never try the UDP variant ladder)", got, uidResolveMaxAttempts)
	}
}
