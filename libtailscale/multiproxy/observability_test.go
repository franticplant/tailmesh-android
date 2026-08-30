// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"strings"
	"testing"
	"time"
)

func TestDataplaneCountersAddRxTx(t *testing.T) {
	var dp dataplaneCounters
	dp.addRx(100)
	dp.addRx(50)
	dp.addTx(30)

	if dp.tunRxBytes != 150 {
		t.Fatalf("tunRxBytes = %d, want 150", dp.tunRxBytes)
	}
	if dp.tunRxPackets != 2 {
		t.Fatalf("tunRxPackets = %d, want 2", dp.tunRxPackets)
	}
	if dp.tunTxBytes != 30 {
		t.Fatalf("tunTxBytes = %d, want 30", dp.tunTxBytes)
	}
	if dp.tunTxPackets != 1 {
		t.Fatalf("tunTxPackets = %d, want 1", dp.tunTxPackets)
	}
}

func TestUIDRegistryIsolation(t *testing.T) {
	r := newUIDRegistry()

	a := r.forUID(1001)
	b := r.forUID(1002)
	if a == b {
		t.Fatalf("distinct UIDs got the same uidStats object")
	}

	a.addBytesIn(100)
	a.addBytesOut(10)
	b.addBytesIn(5)

	if a.bytesIn != 100 || a.bytesOut != 10 {
		t.Fatalf("uid 1001 counters wrong: in=%d out=%d", a.bytesIn, a.bytesOut)
	}
	if b.bytesIn != 5 || b.bytesOut != 0 {
		t.Fatalf("uid 1002 counters wrong (bled from uid 1001?): in=%d out=%d", b.bytesIn, b.bytesOut)
	}

	// Re-fetching the same UID must return the same object, not a new one.
	again := r.forUID(1001)
	if again != a {
		t.Fatalf("forUID(1001) returned a different object on second call")
	}

	snap := r.snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
}

func TestUpstreamStatsFlowCounters(t *testing.T) {
	s := &UpstreamStats{}

	s.beginTCPFlow()
	s.beginTCPFlow()
	if s.activeTCP != 2 || s.tcpFlowsTotal != 2 {
		t.Fatalf("after 2 begins: activeTCP=%d tcpFlowsTotal=%d, want 2,2", s.activeTCP, s.tcpFlowsTotal)
	}
	s.endTCPFlow()
	if s.activeTCP != 1 || s.tcpFlowsTotal != 2 {
		t.Fatalf("after 1 end: activeTCP=%d tcpFlowsTotal=%d, want 1,2", s.activeTCP, s.tcpFlowsTotal)
	}

	s.beginUDPFlow()
	if s.activeUDP != 1 || s.udpFlowsTotal != 1 {
		t.Fatalf("after 1 UDP begin: activeUDP=%d udpFlowsTotal=%d, want 1,1", s.activeUDP, s.udpFlowsTotal)
	}
	s.endUDPFlow()
	if s.activeUDP != 0 || s.udpFlowsTotal != 1 {
		t.Fatalf("after 1 UDP end: activeUDP=%d udpFlowsTotal=%d, want 0,1", s.activeUDP, s.udpFlowsTotal)
	}

	// TCP and UDP counters must not interfere with each other.
	if s.activeTCP != 1 {
		t.Fatalf("UDP begin/end affected activeTCP: got %d, want 1", s.activeTCP)
	}
}

// TestNoteExitNodePathDeduplication verifies transition events fire only on
// an actual state change, matching PHASE 8's "do not repeatedly emit
// identical events while state remains unchanged" rule.
func TestNoteExitNodePathDeduplication(t *testing.T) {
	cb := &MockCallback{}
	e := NewEngine(t.TempDir(), cb)
	defer e.Close()

	const id = "tn1"

	// First observation with an exit node, direct path: connected + no
	// direct/DERP transition (there was no known prior state to transition
	// from).
	e.noteExitNodePath(id, true, true, "")
	waitForObsEventCount(t, cb, 1)

	// Same state again: must not fire another event.
	e.noteExitNodePath(id, true, true, "")
	waitForObsEventCount(t, cb, 1)

	// Flip to DERP: exactly one new event (the path transition).
	e.noteExitNodePath(id, true, false, "sfo")
	waitForObsEventCount(t, cb, 2)

	// Same DERP state again: no new event.
	e.noteExitNodePath(id, true, false, "sfo")
	waitForObsEventCount(t, cb, 2)

	// Exit node goes away: one disconnect event.
	e.noteExitNodePath(id, false, false, "")
	waitForObsEventCount(t, cb, 3)

	// Repeated "no exit node": no new event.
	e.noteExitNodePath(id, false, false, "")
	waitForObsEventCount(t, cb, 3)

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.obsEvents[0].eventType != ObsEventExitNodeConnected {
		t.Fatalf("event 0 = %s, want %s", cb.obsEvents[0].eventType, ObsEventExitNodeConnected)
	}
	if cb.obsEvents[1].eventType != ObsEventPathDirectToDERP {
		t.Fatalf("event 1 = %s, want %s", cb.obsEvents[1].eventType, ObsEventPathDirectToDERP)
	}
	if cb.obsEvents[2].eventType != ObsEventExitNodeDisconnect {
		t.Fatalf("event 2 = %s, want %s", cb.obsEvents[2].eventType, ObsEventExitNodeDisconnect)
	}
}

func waitForObsEventCount(t *testing.T, cb *MockCallback, want int) {
	t.Helper()
	deadlineChecks := 200
	for i := 0; i < deadlineChecks; i++ {
		cb.mu.Lock()
		got := len(cb.obsEvents)
		cb.mu.Unlock()
		if got == want {
			return
		}
		if got > want {
			t.Fatalf("got %d observability events, want %d (over-fired)", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	t.Fatalf("got %d observability events after waiting, want %d", len(cb.obsEvents), want)
}

func TestObservabilitySnapshotJSONIsValid(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	// Generate a little traffic so Apps has at least one entry.
	uid := e.uidStatsFor(4242)
	uid.addBytesIn(1000)
	uid.addBytesOut(500)
	uid.tcpFlows = 1

	js := e.GetObservabilitySnapshotJSON()
	if js == "" || js == "{}" {
		t.Fatalf("GetObservabilitySnapshotJSON returned empty/degenerate JSON: %q", js)
	}
	if !containsAll(js, `"apps"`, `"process"`, `"dataplane"`, `"uid":4242`) {
		t.Fatalf("snapshot JSON missing expected fields: %s", js)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
