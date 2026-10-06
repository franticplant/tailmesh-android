// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import "testing"

// TestAtomicCountersWhenEmbedded is the regression test for issue #4: on
// 32-bit ARM (armeabi-v7a), a raw uint64 atomic field embedded after a
// pointer could land at an address congruent to 4 mod 8, and the first 64-bit
// atomic op on it aborts the process with "unaligned 64-bit atomic
// operation" - observed live on a Moto G Play as
// multiproxy.(*observability).sampleOnce reading o.dp.tunRxBytes. Typed
// atomic.Uint64/atomic.Int64 fields carry their own alignment guarantee, so
// this exercises exactly the embedded layouts that used to fail: counters
// after a leading byte/pointer and after the 32-bit readiness flag.
func TestAtomicCountersWhenEmbedded(t *testing.T) {
	h := new(struct {
		prefix byte
		dp     dataplaneCounters
		obs    observability
		stats  UpstreamStats
		uid    uidStats
		usage  upstreamUsage
		engine Engine
	})
	h.dp.addRx(17)
	h.dp.addTx(9)
	h.obs.dp.addRx(23)
	h.obs.intervalNs.Store(1000)
	h.stats.beginTCPFlow()
	h.stats.beginUDPFlow()
	h.uid.addBytesIn(7)
	h.usage.addBytesOut(11)
	h.engine.flowCounter.Add(1)
	if h.dp.tunRxBytes.Load() != 17 || h.obs.dp.tunRxBytes.Load() != 23 ||
		h.obs.intervalNs.Load() != 1000 || h.stats.activeTCP.Load() != 1 ||
		h.stats.activeUDP.Load() != 1 || h.uid.bytesIn.Load() != 7 ||
		h.usage.bytesOut.Load() != 11 || h.engine.flowCounter.Load() != 1 {
		t.Fatal("embedded atomic counters did not retain independent values")
	}
	h.dp.reset()
	h.stats.endTCPFlow()
	h.stats.endUDPFlow()
	if h.dp.tunRxBytes.Load() != 0 || h.stats.activeTCP.Load() != 0 || h.stats.activeUDP.Load() != 0 {
		t.Fatal("embedded counters did not reset or close correctly")
	}
}
