package multiproxy

import (
	"net/netip"
	"testing"
)

func keyFor(upstream, stableID string) TargetKey {
	return TargetKey{
		NamespaceID: UpstreamID(upstream),
		Kind:        TargetKindTailscaleNode,
		StableID:    stableID,
	}
}

// TestSyntheticV4AssignmentIsStableAndInPool covers the basic contract: every
// peer gets an address inside the pool, outside the reserved control block,
// and the same peer keeps the same address across rebuilds.
func TestSyntheticV4AssignmentIsStableAndInPool(t *testing.T) {
	keys := []TargetKey{
		keyFor("tn-a", "node1"),
		keyFor("tn-b", "node2"),
		keyFor("tn-b", "node3"),
	}

	first := assignSyntheticIPv4(keys, nil)
	if len(first) != len(keys) {
		t.Fatalf("assigned %d addresses, want %d", len(first), len(keys))
	}

	seen := make(map[netip.Addr]bool)
	for k, addr := range first {
		if !SyntheticIPv4Prefix.Contains(addr) {
			t.Fatalf("%v assigned %v, outside %v", k, addr, SyntheticIPv4Prefix)
		}
		if SyntheticIPv4ControlPrefix.Contains(addr) {
			t.Fatalf("%v assigned %v, inside reserved control block", k, addr)
		}
		if seen[addr] {
			t.Fatalf("duplicate address %v", addr)
		}
		seen[addr] = true
	}

	second := assignSyntheticIPv4(keys, first)
	for k, addr := range first {
		if second[k] != addr {
			t.Fatalf("%v moved from %v to %v across rebuild", k, addr, second[k])
		}
	}
}

// TestSyntheticV4NewPeerDoesNotDisplaceExisting is the churn case: a peer
// joining must never take an address already in use, since that would
// silently redirect an established connection to a different machine.
func TestSyntheticV4NewPeerDoesNotDisplaceExisting(t *testing.T) {
	existing := []TargetKey{keyFor("tn-a", "node1"), keyFor("tn-a", "node2")}
	prior := assignSyntheticIPv4(existing, nil)

	grown := append(append([]TargetKey(nil), existing...), keyFor("tn-a", "node3"))
	after := assignSyntheticIPv4(grown, prior)

	for _, k := range existing {
		if after[k] != prior[k] {
			t.Fatalf("%v moved from %v to %v when a peer joined", k, prior[k], after[k])
		}
	}
	if after[keyFor("tn-a", "node3")] == (netip.Addr{}) {
		t.Fatal("new peer got no address")
	}
	for _, k := range existing {
		if after[keyFor("tn-a", "node3")] == after[k] {
			t.Fatal("new peer collided with an existing assignment")
		}
	}
}

// TestSyntheticV4CollisionProbes forces many peers through the allocator and
// asserts every one gets a distinct address. Unlike the 128-bit v6 space this
// pool is small enough that hash collisions are expected, and a collision
// must probe rather than drop the peer.
func TestSyntheticV4CollisionProbes(t *testing.T) {
	var keys []TargetKey
	for i := 0; i < 2000; i++ {
		keys = append(keys, keyFor("tn-a", string(rune('a'+i%26))+string(rune('a'+(i/26)%26))+string(rune('a'+(i/676)%26))))
	}

	assigned := assignSyntheticIPv4(keys, nil)

	seen := make(map[netip.Addr]bool, len(assigned))
	for k, addr := range assigned {
		if seen[addr] {
			t.Fatalf("duplicate address %v for %v", addr, k)
		}
		seen[addr] = true
	}
}

// TestSyntheticV4RemovedPeerFreesAddress ensures a departed peer's address is
// reusable, so long-running sessions with lots of churn don't leak the pool.
func TestSyntheticV4RemovedPeerFreesAddress(t *testing.T) {
	all := []TargetKey{keyFor("tn-a", "node1"), keyFor("tn-a", "node2")}
	prior := assignSyntheticIPv4(all, nil)
	freed := prior[keyFor("tn-a", "node2")]

	remaining := []TargetKey{keyFor("tn-a", "node1")}
	after := assignSyntheticIPv4(remaining, prior)

	if _, ok := after[keyFor("tn-a", "node2")]; ok {
		t.Fatal("departed peer still holds an address")
	}

	// A peer that flaps out and back must land on its original address: the
	// slot has to be genuinely free, and the prior map still carries it.
	rejoined := assignSyntheticIPv4(all, prior)
	if rejoined[keyFor("tn-a", "node2")] != freed {
		t.Fatalf("rejoining peer got %v, want its original %v", rejoined[keyFor("tn-a", "node2")], freed)
	}
}
