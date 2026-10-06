// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestEarlyUIDCacheBeginTake(t *testing.T) {
	c := newEarlyUIDCache()
	key := flowKey{"udp", netip.MustParseAddrPort("10.0.0.5:1234"), netip.MustParseAddrPort("10.0.0.1:53")}

	calls := 0
	resolve := func() int32 {
		calls++
		return 4242
	}

	c.begin(key, resolve)
	uid, ok := c.take(key)
	if !ok {
		t.Fatalf("take: not ok, want a result from begin")
	}
	if uid != 4242 {
		t.Fatalf("uid = %d, want 4242", uid)
	}

	// A second packet on the same still-active flow must not restart
	// resolution - this is the common case (every packet after a flow's
	// first) and must stay a cache hit.
	c.begin(key, resolve)
	if calls != 1 {
		t.Fatalf("resolve called %d times, want 1 (second begin should have reused the cached entry)", calls)
	}
}

// TestEarlyUIDCacheForgetPreventsStaleReuseAcrossFlows is the regression
// case for the gap this cache originally had: a flow ends, its 5-tuple
// (most commonly a DNS query's ephemeral source port) is reused by a
// *different* app's *new* flow within the old entry's TTL, and without an
// explicit forget on teardown, begin() for the new flow would see the old,
// still-unexpired entry and skip resolution entirely - handing the new
// flow the previous flow's (wrong) app over take(), with no fresh lookup
// ever attempted. forget (called from handleTCPConnection/
// handleUDPConnection's pump-goroutine teardown, alongside
// e.capture.unregisterFlow) must close that gap.
func TestEarlyUIDCacheForgetPreventsStaleReuseAcrossFlows(t *testing.T) {
	c := newEarlyUIDCache()
	key := flowKey{"udp", netip.MustParseAddrPort("10.0.0.5:54321"), netip.MustParseAddrPort("10.0.0.1:53")}

	// Flow 1: app A's query.
	c.begin(key, func() int32 { return 1111 })
	uid, ok := c.take(key)
	if !ok || uid != 1111 {
		t.Fatalf("flow 1: uid = %d, ok = %v, want 1111, true", uid, ok)
	}

	// Flow 1 tears down - the port is now free for reuse.
	c.forget(key)

	// Flow 2: a different app, app B, reuses the identical 5-tuple well
	// within earlyUIDTTL. Without forget, begin() below would have been a
	// no-op against the stale entry and take() would still return 1111.
	c.begin(key, func() int32 { return 2222 })
	uid, ok = c.take(key)
	if !ok || uid != 2222 {
		t.Fatalf("flow 2: uid = %d, ok = %v, want 2222, true (must not inherit flow 1's stale attribution)", uid, ok)
	}
}

func TestEarlyUIDCacheTakeMissWhenNeverBegun(t *testing.T) {
	c := newEarlyUIDCache()
	key := flowKey{"tcp", netip.MustParseAddrPort("10.0.0.5:1234"), netip.MustParseAddrPort("10.0.0.1:443")}
	if _, ok := c.take(key); ok {
		t.Fatalf("take: ok, want a miss for a key nothing ever began")
	}
}

func TestEarlyUIDCacheExpiryRestartsResolution(t *testing.T) {
	c := newEarlyUIDCache()
	key := flowKey{"udp", netip.MustParseAddrPort("10.0.0.5:1234"), netip.MustParseAddrPort("10.0.0.1:53")}

	calls := 0
	resolve := func() int32 {
		calls++
		return 4242
	}
	c.begin(key, resolve)
	c.take(key)

	// Force the entry to look expired without waiting out the real TTL.
	c.mu.Lock()
	c.entries[key].expires = time.Now().Add(-time.Second)
	c.mu.Unlock()

	c.begin(key, resolve)
	c.take(key)
	if calls != 2 {
		t.Fatalf("resolve called %d times, want 2 (expired entry should restart resolution)", calls)
	}
}

// TestBeginEarlyAttributionFeedsFlowFromEndpointID is the end-to-end case:
// a packet dispatched off the TUN (simulated here by calling
// beginEarlyAttribution directly, the same call attributionDispatcher makes)
// starts attribution before the forwarder ever asks for it, and
// flowFromEndpointID picks up that same answer instead of starting a fresh
// lookup.
func TestBeginEarlyAttributionFeedsFlowFromEndpointID(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	defer e.Close()

	e.policy = &policyStore{}
	e.policy.Set(Policy{Rules: []Rule{{Selector: Selector{AppUIDs: []int32{999}}, Action: ActionBlock}}})

	r := &flakyResolver{failFor: 0, uidAfter: 4242}
	e.SetUIDResolver(r)

	raw := buildIPv4UDPPacket(t, "10.0.0.5", 5000, "10.0.0.1", 53, []byte("hi"))
	e.beginEarlyAttribution(raw)

	// gVisor names endpoints from the stack's own point of view (see
	// flowFromEndpointID's doc comment): LocalAddress/Port is this packet's
	// IP destination, RemoteAddress/Port is its IP source.
	id := stack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(netip.MustParseAddr("10.0.0.1").AsSlice()),
		LocalPort:     53,
		RemoteAddress: tcpip.AddrFromSlice(netip.MustParseAddr("10.0.0.5").AsSlice()),
		RemotePort:    5000,
	}
	flow := e.flowFromEndpointID("udp", id)

	if flow.AppUID != 4242 {
		t.Fatalf("flow.AppUID = %d, want 4242", flow.AppUID)
	}
	// 2, not 1: one logical resolveAppUID call, which itself makes a second
	// raw ResolveUID call to corroborate the first before trusting it (see
	// resolveAppUID's own doc comment). The point of this test is that
	// exactly one *logical* attribution ran - if flowFromEndpointID had
	// started its own fresh resolveAppUID instead of reusing the early one,
	// this would be 4, not 2.
	if got := r.calls.Load(); got != 2 {
		t.Fatalf("resolver called %d times, want 2 (flowFromEndpointID should have reused the early attribution's one logical resolveAppUID call, not started a second one)", got)
	}
}
