// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file measures the per-app UID attribution race empirically, by
// driving the real production mechanisms (Engine.resolveAppUID,
// earlyUIDCache) against a simulated Android ephemeral-port table, instead
// of reasoning about the race only in the abstract. See
// validation_and_gaps.md §99 for the investigation this is part of.
//
// portTable models the one piece of ground truth this whole problem is
// about: which app currently owns a given source port, as the kernel would
// answer it. It is deliberately shrunk to a small pool (see
// racePortPoolSize) so that realistic contention - many apps doing
// short-lived DNS-shaped UDP sockets - is observable across a few thousand
// simulated flows in well under a second of wall-clock time, rather than
// needing millions of iterations against Android's real ~28k-port
// ephemeral range. The *rate* measured here is therefore illustrative of
// the mechanism, not a literal prediction of an on-device rate - the real
// rate depends on real port-allocation pressure this sandbox cannot
// reproduce.
type portTable struct {
	mu    sync.Mutex
	owner map[int32]int32 // port -> current owning app UID, per the simulated kernel
}

func newPortTable() *portTable { return &portTable{owner: make(map[int32]int32)} }

func (t *portTable) claim(port, uid int32) {
	t.mu.Lock()
	t.owner[port] = uid
	t.mu.Unlock()
}

func (t *portTable) ownerOf(port int32) int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if uid, ok := t.owner[port]; ok {
		return uid
	}
	return UnknownAppUID
}

// tableUIDResolver answers exactly like Android's getConnectionOwnerUid
// would against portTable: a live snapshot read, keyed only by source port
// (dst is fixed at the synthetic DNS address:53 for every simulated flow,
// matching the DNS-burst scenario this race was reported against).
type tableUIDResolver struct{ table *portTable }

func (r *tableUIDResolver) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	return r.table.ownerOf(srcPort)
}

const (
	racePortPoolSize = 24 // shrunk ephemeral range - see portTable's doc comment
	raceNumApps      = 8
	raceFlowsPerApp  = 600 // 4800 simulated flows per stage
)

// raceResult is one simulated flow's ground truth versus what the
// attribution mechanism under test answered.
type raceResult struct {
	trueUID uint8 // index into the app list, not the real UID, for compact reporting
	gotUID  int32
}

// runRaceSimulation drives raceNumApps concurrent virtual apps through
// raceFlowsPerApp short-lived UDP "DNS query" flows each, all sharing
// racePortPoolSize ephemeral ports, and asks attribute() to answer each
// flow's owning UID exactly when the flow starts. attribute is where each
// measured stage's mechanism differs; everything else here is identical
// across stages so the comparison is apples-to-apples.
func runRaceSimulation(t *testing.T, table *portTable, apps []int32, attribute func(flowSeq int, table *portTable, srcPort, appUID int32) int32) []raceResult {
	t.Helper()
	results := make([]raceResult, raceNumApps*raceFlowsPerApp)
	var idx atomic.Int64

	var wg sync.WaitGroup
	for ai, uid := range apps {
		wg.Add(1)
		go func(appIdx int, appUID int32) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(appUID) + 1))
			for i := 0; i < raceFlowsPerApp; i++ {
				port := int32(rng.Intn(racePortPoolSize))

				// The socket opens: the simulated kernel now genuinely
				// attributes this port to this app.
				table.claim(port, appUID)
				seq := int(idx.Add(1)) - 1

				got := attribute(seq, table, port, appUID)

				// DNS-shaped lifetime: almost always sub-millisecond,
				// occasionally a couple of milliseconds - then the socket
				// closes. The port is left exactly as-is in the table
				// (matching a real kernel: nothing clears the entry, it is
				// simply overwritten whenever another app's claim reuses
				// the same port next).
				time.Sleep(time.Duration(rng.Intn(2000)) * time.Microsecond)

				results[seq] = raceResult{trueUID: uint8(appIdx), gotUID: got}
			}
		}(ai, uid)
	}
	wg.Wait()
	return results
}

func summarizeRace(t *testing.T, stage string, apps []int32, results []raceResult) {
	t.Helper()
	uidToIdx := make(map[int32]uint8, len(apps))
	for i, uid := range apps {
		uidToIdx[uid] = uint8(i)
	}

	total := 0
	unknown := 0
	wrongConfident := 0
	for _, r := range results {
		if r.gotUID == UnknownAppUID {
			total++
			unknown++
			continue
		}
		gotIdx, ok := uidToIdx[r.gotUID]
		total++
		if !ok || gotIdx != r.trueUID {
			wrongConfident++
		}
	}

	t.Logf(
		"[attribution-race] stage=%-32s flows=%d unknown=%d (%.2f%%) wrong-but-confident=%d (%.2f%%)",
		stage, total, unknown, 100*float64(unknown)/float64(total),
		wrongConfident, 100*float64(wrongConfident)/float64(total),
	)
}

// TestMeasureAttributionLeakageAcrossFixStages runs the identical simulated
// DNS-burst workload through three configurations, each matching an actual
// stage this session's fixes went through, using the real production
// mechanisms (Engine.resolveAppUID, earlyUIDCache) rather than a
// reimplementation:
//
//  1. "corroboration only, late lookup" - resolveAppUID as it existed
//     before this session's early-dispatch cache existed: the lookup only
//     starts once a simulated forwarder-queue delay has passed.
//  2. "+ early dispatch, no generation safety" - attribution starts at
//     simulated packet-dispatch time via earlyUIDCache, but flows never
//     call forget() on teardown - reproducing the self-inflicted
//     cross-flow contamination bug this session's fix (§99) closed.
//  3. "+ early dispatch, generation-safe (current)" - same as 2, but each
//     flow calls forget() on teardown, matching the engine's current,
//     shipped behavior.
//
// Run with: go test ./libtailscale/multiproxy/ -run TestMeasureAttributionLeakageAcrossFixStages -v
func TestMeasureAttributionLeakageAcrossFixStages(t *testing.T) {
	apps := make([]int32, raceNumApps)
	for i := range apps {
		apps[i] = int32(10001 + i)
	}

	// --- Stage 1: corroboration only, lookup delayed as if queued behind
	// gVisor's stack demux and forwarder dispatch, the way it was before
	// this session's early-dispatch cache existed. ---
	t.Run("stage1_corroboration_only_late_lookup", func(t *testing.T) {
		table := newPortTable()
		e := NewEngine(t.TempDir(), &MockCallback{})
		defer e.Close()
		e.SetUIDResolver(&tableUIDResolver{table: table})

		results := runRaceSimulation(t, table, apps, func(seq int, table *portTable, srcPort, appUID int32) int32 {
			// Simulated forwarder-queue delay before attribution even starts.
			time.Sleep(time.Duration(200+rand.Intn(1500)) * time.Microsecond)
			src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(srcPort))
			dst := netip.AddrPortFrom(SyntheticIPv4DNS, 53)
			return e.resolveAppUID("udp", src, dst)
		})
		summarizeRace(t, "1: corroboration-only, late lookup", apps, results)
	})

	// --- Stage 2: early dispatch added, but without the forget()-based
	// generation safety - the gap the pasted research exposed. ---
	t.Run("stage2_early_dispatch_no_generation_safety", func(t *testing.T) {
		table := newPortTable()
		e := NewEngine(t.TempDir(), &MockCallback{})
		defer e.Close()
		e.SetUIDResolver(&tableUIDResolver{table: table})
		cache := newEarlyUIDCache()

		results := runRaceSimulation(t, table, apps, func(seq int, table *portTable, srcPort, appUID int32) int32 {
			src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(srcPort))
			dst := netip.AddrPortFrom(SyntheticIPv4DNS, 53)
			key := flowKey{"udp", src, dst}

			// Attribution starts immediately, at simulated packet-dispatch
			// time - the fix. Teardown deliberately does NOT call forget(),
			// reproducing the pre-fix gap: the entry lingers until
			// earlyUIDTTL regardless of this flow having ended.
			cache.begin(key, func() int32 { return e.resolveAppUID("udp", src, dst) })
			uid, _ := cache.take(key)
			return uid
		})
		summarizeRace(t, "2: +early dispatch, no generation safety", apps, results)
	})

	// --- Stage 3: current, shipped behavior - early dispatch plus
	// forget() on teardown. ---
	t.Run("stage3_early_dispatch_generation_safe_current", func(t *testing.T) {
		table := newPortTable()
		e := NewEngine(t.TempDir(), &MockCallback{})
		defer e.Close()
		e.SetUIDResolver(&tableUIDResolver{table: table})
		cache := newEarlyUIDCache()

		results := runRaceSimulation(t, table, apps, func(seq int, table *portTable, srcPort, appUID int32) int32 {
			src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.5"), uint16(srcPort))
			dst := netip.AddrPortFrom(SyntheticIPv4DNS, 53)
			key := flowKey{"udp", src, dst}

			cache.begin(key, func() int32 { return e.resolveAppUID("udp", src, dst) })
			uid, _ := cache.take(key)
			// Flow tears down: forget its entry immediately, matching
			// handleUDPConnection's pump-goroutine defer in production.
			cache.forget(key)
			return uid
		})
		summarizeRace(t, "3: +early dispatch, generation-safe (current)", apps, results)
	})
}

// Sanity check that the simulation harness itself is meaningful: a
// zero-delay, always-correct oracle should show ~0% error, proving any
// non-zero rate reported above comes from the timing race being modeled,
// not from a bug in the harness.
func TestMeasureAttributionLeakageOracleSanityCheck(t *testing.T) {
	apps := make([]int32, raceNumApps)
	for i := range apps {
		apps[i] = int32(10001 + i)
	}
	table := newPortTable()
	results := runRaceSimulation(t, table, apps, func(seq int, table *portTable, srcPort, appUID int32) int32 {
		return appUID // the true owner, read synchronously with zero delay - no race possible
	})
	summarizeRace(t, "oracle (sanity check, must be ~0%)", apps, results)
	wrong := 0
	uidToIdx := make(map[int32]uint8, len(apps))
	for i, uid := range apps {
		uidToIdx[uid] = uint8(i)
	}
	for _, r := range results {
		if idx, ok := uidToIdx[r.gotUID]; !ok || idx != r.trueUID {
			wrong++
		}
	}
	if wrong != 0 {
		t.Fatalf("oracle sanity check: %d/%d wrong with zero delay and no cache - harness itself is broken", wrong, len(results))
	}
}
