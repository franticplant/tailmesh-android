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
	if got := r.calls.Load(); got != 2 {
		t.Fatalf("resolver called %d times, want 2 (one failure + one retry)", got)
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
