package multiproxy

import (
	"testing"

	"tailscale.com/tsnet"
)

func registerFakeUpstream(t *testing.T, e *Engine, uid UpstreamID) {
	t.Helper()
	e.mu.Lock()
	e.tailnets[uid] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	e.mu.Unlock()
}

// TestSyntheticV4RoutesToOwningUpstream verifies the address handed out by DNS
// is actually routable back to the peer that owns it.
func TestSyntheticV4RoutesToOwningUpstream(t *testing.T) {
	e, _ := newPacketTestEngine(t)
	uid := UpstreamID("tn")
	rec := mustAddTarget(t, e, uid, "box.", "A")

	e.targetMutex.RLock()
	v4 := e.syntheticV4ByKey[rec.Key]
	e.targetMutex.RUnlock()

	if !v4.IsValid() {
		t.Fatal("target got no synthetic v4 address")
	}

	if _, ok := e.resolveRoute(v4); ok {
		t.Fatal("expected no route while the upstream is inactive")
	}

	registerFakeUpstream(t, e, uid)

	decision, ok := e.resolveRoute(v4)
	if !ok {
		t.Fatal("synthetic v4 address did not resolve to a route")
	}
	if decision.UpstreamID != uid {
		t.Fatalf("routed to %q, want %q", decision.UpstreamID, uid)
	}
	if decision.Destination != rec.CurrentIPv4.String() {
		t.Fatalf("destination %q, want the peer's real v4 %q", decision.Destination, rec.CurrentIPv4)
	}
}

// TestSyntheticV4StaleAddressFailsClosed guards the same invariant the v6 side
// has: an address inside the pool that no longer maps to a peer must not fall
// through to subnet or exit-node routing.
func TestSyntheticV4StaleAddressFailsClosed(t *testing.T) {
	e, _ := newPacketTestEngine(t)
	uid := UpstreamID("tn")
	registerFakeUpstream(t, e, uid)

	stale := syntheticV4At(12345)
	if _, ok := e.resolveRoute(stale); ok {
		t.Fatalf("stale synthetic v4 address %v resolved to a route", stale)
	}
}
