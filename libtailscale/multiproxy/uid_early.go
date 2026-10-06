// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"sync"
	"time"
)

// earlyUIDTTL bounds how long a completed (or still-pending) early
// attribution entry is trusted before a later packet on the same 5-tuple
// starts a fresh lookup instead of reusing it. Long enough to cover a DNS
// query's entire round trip (query, resolve, response, socket close) many
// times over; short enough that a long-lived TCP connection's occasional
// re-resolution stays occasional rather than never, in case anything about
// how it was attributed the first time turns out to have been wrong.
const earlyUIDTTL = 10 * time.Second

// earlyUIDSweepThreshold is how many live entries earlyUIDCache tolerates
// before paying for a full expired-entry sweep on insert. Ordinary traffic
// keeps this map small (one entry per recently-seen flow, refreshed rather
// than duplicated - see begin); it only grows large under something like a
// port scan or a burst of connections that get rejected before reaching a
// normal cleanup path, and even then this bounds the cost to an occasional
// O(n) sweep rather than unbounded growth.
const earlyUIDSweepThreshold = 2048

// earlyUIDCache lets attribution for a flow start at the earliest possible
// moment - when its first packet is read off the TUN and dispatched into
// gVisor, before the stack queues it for TCP/UDP forwarder handling - so
// that by the time flowFromEndpointID actually needs an answer, it can
// often reuse a lookup already in flight (or already finished) instead of
// starting a brand new, later one.
//
// This exists because of a race documented in resolveAppUID's own comment:
// Android's getConnectionOwnerUid answers from a live connection table that
// can move on before attribution finishes, most visibly for a short-lived
// UDP DNS "send and close" socket whose ephemeral port a different app can
// reuse in the interim. Starting the lookup as early as possible shrinks
// that window by however long gVisor's own stack demux and forwarder
// dispatch would otherwise have added on top of the OS lookup's own
// latency - a delay that grows under load, since forwarder dispatch
// competes with every other flow's packets for the same processing, right
// when many concurrent DNS queries also make the underlying port-reuse race
// itself more likely. It does not eliminate the race (nothing can, short of
// the OS tagging packets with their owning UID at send time) - it only
// removes the part of the delay this engine controls. See
// validation_and_gaps.md for the investigation this closes and a
// comparison against how a comparable Android VPN engine (Firestack)
// attributes flows.
type earlyUIDCache struct {
	mu      sync.Mutex
	entries map[flowKey]*earlyUIDEntry
}

type earlyUIDEntry struct {
	done    chan struct{}
	uid     int32 // valid only after done is closed
	expires time.Time
}

func newEarlyUIDCache() *earlyUIDCache {
	return &earlyUIDCache{entries: make(map[flowKey]*earlyUIDEntry)}
}

// begin starts attribution for key by calling resolve in its own goroutine,
// unless an unexpired entry already exists for it - true for every packet
// on a flow after its first, which is the common case and must stay a
// single cheap map lookup under lock, not a repeated resolution.
func (c *earlyUIDCache) begin(key flowKey, resolve func() int32) {
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return
	}
	if len(c.entries) >= earlyUIDSweepThreshold {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
	}
	e := &earlyUIDEntry{done: make(chan struct{}), expires: now.Add(earlyUIDTTL)}
	c.entries[key] = e
	c.mu.Unlock()

	go func() {
		defer func() { recover() }() // resolve is e.resolveAppUID in production; never expected to panic, but this must not take the goroutine's caller down either way.
		e.uid = resolve()
		close(e.done)
	}()
}

// forget removes key's entry, if any, so a future begin for the same
// 5-tuple starts a genuinely fresh lookup instead of reusing this flow's
// answer. Called once a flow's teardown is known (handleTCPConnection/
// handleUDPConnection's pump goroutines, alongside the existing
// e.capture.unregisterFlow call), so the common case - a flow closes
// cleanly and its 5-tuple, especially an ephemeral DNS source port, is
// reused for a *different* app's *different* flow shortly after - gets an
// immediate, correct fresh lookup rather than silently inheriting the
// previous flow's answer for however long was left on earlyUIDTTL. TTL
// expiry remains as a backstop for entries this never reaches - a flow
// rejected before it has a teardown path to call this from (no route,
// policy block, a doomed-IPv6 reject, a failed dynamic-address grab), or a
// packet that never became a tracked flow at all.
func (c *earlyUIDCache) forget(key flowKey) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// take returns the attribution started for key, if any, blocking until it
// finishes - bounded by resolveAppUID's own attempt/timeout budget, since
// that is what resolve (as passed to begin) always is in production. The
// entry is left in place (not consumed) so later packets on the same still
// active flow reuse it instead of restarting a lookup, until whichever
// comes first of earlyUIDTTL or an explicit forget once the flow tears
// down.
func (c *earlyUIDCache) take(key flowKey) (int32, bool) {
	c.mu.Lock()
	e, ok := c.entries[key]
	c.mu.Unlock()
	if !ok {
		return UnknownAppUID, false
	}
	<-e.done
	return e.uid, true
}

// beginEarlyAttribution parses data (a raw IP packet as read off the TUN,
// in either direction) and, if this engine's policy actually uses app UIDs,
// starts attribution for its flow via e.earlyUID. Cheap no-op otherwise -
// the same policyUsesAppUID gate flowFromEndpointID itself uses, so a
// policy with no UID-scoped rules pays only the cost of that one check.
func (e *Engine) beginEarlyAttribution(data []byte) {
	if !e.policyUsesAppUID() {
		return
	}
	proto, src, dst, ok := parseFiveTuple(data)
	if !ok {
		return
	}
	key := flowKey{proto, src, dst}
	e.earlyUID.begin(key, func() int32 {
		return e.resolveAppUID(proto, src, dst)
	})
}
