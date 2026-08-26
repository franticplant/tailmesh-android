package multiproxy

import (
	"encoding/binary"
	"log"
	"net/netip"
)

// syntheticV4Span is the number of addresses in SyntheticIPv4Prefix that can
// be handed to peers: everything except the reserved control block holding
// our own interface and DNS addresses.
var syntheticV4Span = func() uint32 {
	total := uint32(1) << (32 - SyntheticIPv4Prefix.Bits())
	control := uint32(1) << (32 - SyntheticIPv4ControlPrefix.Bits())
	return total - control
}()

// syntheticV4At returns the nth assignable address in the synthetic v4 pool,
// skipping the reserved control block at the base of the prefix.
func syntheticV4At(n uint32) netip.Addr {
	baseBytes := SyntheticIPv4Prefix.Addr().As4()
	base := binary.BigEndian.Uint32(baseBytes[:])
	control := uint32(1) << (32 - SyntheticIPv4ControlPrefix.Bits())

	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], base+control+(n%syntheticV4Span))
	return netip.AddrFrom4(raw)
}

// syntheticV4Seed derives a target's preferred slot in the pool. It reuses the
// synthetic v6 address as the hash input so a peer's v4 and v6 assignments
// move together and stay stable for as long as its identity does.
func syntheticV4Seed(key TargetKey) uint32 {
	v6 := key.SyntheticIPv6().As16()
	return binary.BigEndian.Uint32(v6[12:16])
}

// assignSyntheticIPv4 gives key a stable address from the synthetic v4 pool.
//
// Unlike the v6 case there is no room to hash collisions away: the pool holds
// about 131k addresses against a 128-bit identity, so distinct peers will
// eventually want the same slot. Colliding peers are probed to the next free
// address instead of being dropped, because a v6 collision merely costs one
// peer its (redundant) v6 address while a v4 collision would silently make a
// peer unreachable to every v4-only app on the device.
//
// prior carries assignments from the previous rebuild so addresses survive
// netmap churn; a peer whose address changed mid-session would strand any
// connection an app had already opened to it.
func assignSyntheticIPv4(keys []TargetKey, prior map[TargetKey]netip.Addr) map[TargetKey]netip.Addr {
	assigned := make(map[TargetKey]netip.Addr, len(keys))
	used := make(map[netip.Addr]bool, len(keys))

	// Re-seat everything that already had an address before considering new
	// peers, so an arriving peer can never displace an established one.
	pending := keys[:0:0]
	for _, k := range keys {
		if addr, ok := prior[k]; ok && !used[addr] {
			assigned[k] = addr
			used[addr] = true
			continue
		}
		pending = append(pending, k)
	}

	exhausted := false
	for _, k := range pending {
		if uint32(len(used)) >= syntheticV4Span {
			// Pool exhausted. Fail closed for this peer rather than reusing
			// an address: a duplicate would route one peer's traffic to
			// another, which is far worse than having no v4 address.
			exhausted = true
			continue
		}

		seed := syntheticV4Seed(k)
		for i := uint32(0); i < syntheticV4Span; i++ {
			addr := syntheticV4At(seed + i)
			if used[addr] {
				continue
			}
			assigned[k] = addr
			used[addr] = true
			break
		}
	}

	if exhausted {
		log.Printf("multiproxy: synthetic IPv4 pool exhausted (%d addresses); some peers have no A record", syntheticV4Span)
	}
	return assigned
}
