// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Per-upstream observability.
//
// Every real dial made through a Provider - from the flow router, from DNS
// forwarding, or from another upstream's own chained transport - passes
// through readyProvider (upstream.go), which wraps the Provider it returns in
// a statsProvider. That is the single instrumentation point: call sites need
// no awareness of stats, and nothing here can be bypassed by a code path that
// forgets to record something, because there is no other way to get a dialable
// Provider.
//
// Counters are real counts of what happened, not samples or estimates - the
// cost of an atomic increment per dial and per Read/Write call is negligible
// next to the cost of the I/O itself.

// UpstreamStats holds live counters for one upstream. All fields are either
// atomic or guarded by mu; dials happen concurrently across many flows.
type UpstreamStats struct {
	dialAttempts  uint64
	dialSuccesses uint64
	dialFailures  uint64
	notReadyCount uint64
	bytesIn       uint64
	bytesOut      uint64
	lastLatencyNs int64
	ready         int32 // 0 or 1: this stats object's last observed readiness

	// Flow counts, for the observability diagnostics screen (see
	// observability.go). tcpFlowsTotal/udpFlowsTotal only ever increase;
	// activeTCP/activeUDP are incremented when nat_router.go creates a flow
	// through this upstream and decremented when it ends, so they reflect
	// concurrency, not history. All plain atomics - same rationale as the
	// byte counters above.
	tcpFlowsTotal uint64
	udpFlowsTotal uint64
	activeTCP     int64
	activeUDP     int64

	// dnsQueriesForwarded/dnsQueriesFailed count DNS lookups this upstream
	// specifically carried, per dnsRouteFor's routing decision in
	// dns_policy.go/dns.go. These are separate from dialAttempts/dialFailures
	// above: every DNS forward also dials (and so also moves those counters),
	// but a general dial success only means the TLS/TCP connection to the
	// resolver came up, not that a usable DNS answer came back - and
	// dialAttempts mixes DNS dials in with every other kind of traffic this
	// upstream carries, so it cannot answer "is DNS specifically working
	// through this upstream" on its own.
	dnsQueriesForwarded uint64
	dnsQueriesFailed    uint64

	mu            sync.Mutex
	lastError     string
	lastErrorAt   time.Time
	lastSuccessAt time.Time
	lastAttemptAt time.Time
}

func (s *UpstreamStats) recordAttempt() {
	atomic.AddUint64(&s.dialAttempts, 1)
	s.mu.Lock()
	s.lastAttemptAt = time.Now()
	s.mu.Unlock()
}

func (s *UpstreamStats) recordSuccess(latency time.Duration) {
	atomic.AddUint64(&s.dialSuccesses, 1)
	atomic.StoreInt64(&s.lastLatencyNs, int64(latency))
	s.mu.Lock()
	s.lastSuccessAt = time.Now()
	s.mu.Unlock()
}

func (s *UpstreamStats) recordFailure(err error) {
	atomic.AddUint64(&s.dialFailures, 1)
	s.mu.Lock()
	s.lastError = err.Error()
	s.lastErrorAt = time.Now()
	s.mu.Unlock()
}

// recordNotReady records that a rule or flow wanted this upstream while it was
// not ready - a distinct count from dialFailures, since no dial was even
// attempted; the transport itself refused to try.
func (s *UpstreamStats) recordNotReady() {
	atomic.AddUint64(&s.notReadyCount, 1)
	s.mu.Lock()
	s.lastError = "upstream not ready"
	s.lastErrorAt = time.Now()
	s.mu.Unlock()
}

func (s *UpstreamStats) addBytesIn(n int64) {
	if n > 0 {
		atomic.AddUint64(&s.bytesIn, uint64(n))
	}
}

func (s *UpstreamStats) addBytesOut(n int64) {
	if n > 0 {
		atomic.AddUint64(&s.bytesOut, uint64(n))
	}
}

// beginTCPFlow/endTCPFlow and beginUDPFlow/endUDPFlow bracket one flow's
// lifetime through this upstream. Callers (nat_router.go) must call the
// matching end exactly once per begin, on every exit path (typically via
// defer), or activeTCP/activeUDP will drift.
func (s *UpstreamStats) beginTCPFlow() {
	atomic.AddUint64(&s.tcpFlowsTotal, 1)
	atomic.AddInt64(&s.activeTCP, 1)
}
func (s *UpstreamStats) endTCPFlow() { atomic.AddInt64(&s.activeTCP, -1) }

// recordDNSForwarded/recordDNSFailed are dns.go's hooks for a DNS query
// specifically routed through this upstream - see dnsRouteFor.
func (s *UpstreamStats) recordDNSForwarded() {
	atomic.AddUint64(&s.dnsQueriesForwarded, 1)
}
func (s *UpstreamStats) recordDNSFailed() {
	atomic.AddUint64(&s.dnsQueriesFailed, 1)
}

func (s *UpstreamStats) beginUDPFlow() {
	atomic.AddUint64(&s.udpFlowsTotal, 1)
	atomic.AddInt64(&s.activeUDP, 1)
}
func (s *UpstreamStats) endUDPFlow() { atomic.AddInt64(&s.activeUDP, -1) }

// Health-observation states for UpstreamStats.ready. healthUnknown is the
// zero value, distinct from both outcomes, so the very first observation -
// even if it is a failure - is always a transition worth an event. Without a
// third state, a provider whose first-ever dial fails would coincide with
// the field's zero value and never fire "became unreachable".
const (
	healthUnknown int32 = iota
	healthReady
	healthNotReady
)

// setReady records the readiness this stats object last observed and reports
// whether that is a change. A health event fires only on a change - one on
// every dial would be noise, one on every transition is signal.
func (s *UpstreamStats) setReady(ready bool) (changed bool) {
	want := healthNotReady
	if ready {
		want = healthReady
	}
	return atomic.SwapInt32(&s.ready, want) != want
}

// statsRegistry owns one UpstreamStats per upstream ID ever seen, created
// lazily on first dial or first not-ready observation. Entries are kept for
// the engine's lifetime even if the upstream is later removed, so its
// last-known stats stay visible until the engine restarts - the same
// lifetime MultiProxySessionCoordinator's lastErrors already has on the
// Kotlin side.
type statsRegistry struct {
	mu    sync.Mutex
	stats map[UpstreamID]*UpstreamStats
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{stats: make(map[UpstreamID]*UpstreamStats)}
}

func (r *statsRegistry) forID(id UpstreamID) *UpstreamStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.stats[id]
	if !ok {
		s = &UpstreamStats{}
		r.stats[id] = s
	}
	return s
}

func (r *statsRegistry) snapshot() map[UpstreamID]*UpstreamStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[UpstreamID]*UpstreamStats, len(r.stats))
	for id, s := range r.stats {
		out[id] = s
	}
	return out
}

func (e *Engine) statsFor(id UpstreamID) *UpstreamStats {
	return e.stats.forID(id)
}

// resetAll drops every per-upstream UpstreamStats entry, for the diagnostics
// "reset stats" action. Same in-flight-flow caveat as uidRegistry.resetAll:
// a dial already holding a stale *UpstreamStats keeps updating it harmlessly,
// and the next dial for that upstream gets a fresh entry via forID.
func (r *statsRegistry) resetAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats = make(map[UpstreamID]*UpstreamStats)
}

// recordNotReady is readyProvider's hook for the "exists but not ready" case,
// which never reaches wrapWithStats because there is nothing to dial.
func (e *Engine) recordNotReady(id UpstreamID) {
	s := e.statsFor(id)
	s.recordNotReady()
	if s.setReady(false) {
		e.enqueueUpstreamHealthEvent(id, false, "not ready")
	}
}

// ---------------------------------------------------------------------------
// stats-recording Provider wrapper
// ---------------------------------------------------------------------------

// statsProvider wraps a Provider so every real Dial through it is recorded.
// Every method but Dial is promoted from the embedded Provider unchanged, so
// callers that check Kind() or call PeerPathInfo() see the same behaviour as
// the provider it wraps.
type statsProvider struct {
	Provider
	engine *Engine
	id     UpstreamID
	stats  *UpstreamStats
}

// wrapWithStats is readyProvider's only caller; nothing else should construct
// a statsProvider; wrapping happens exactly once per successful readyProvider
// call, right before the Provider is handed to whatever will dial it.
func (e *Engine) wrapWithStats(p Provider) Provider {
	if p == nil {
		return p
	}
	id := p.ID()
	return &statsProvider{Provider: p, engine: e, id: id, stats: e.statsFor(id)}
}

// Dial does not wrap the net.Conn it returns. A decorator around net.Conn
// looks tempting for byte counting, but several things downstream depend on
// the dialed conn's own concrete type: the miekg/dns package decides
// datagram- vs. stream-framing by type-asserting *net.UDPConn, and
// nat_router.go's TCP pump asserts CloseWrite() on the concrete type. Hiding
// either behind a wrapper struct breaks it silently rather than loudly - this
// was caught by TestForwardedQueryFollowsTheAppsRoute failing (UDP DNS
// forwarding tried to speak length-prefixed TCP framing over a real UDP
// socket once wrapped). Byte counters are instead fed from nat_router.go's
// TCP pump and UDP association pump, both of which already know exactly how
// many bytes crossed in each direction without needing to touch the conn's
// type at all. DNS forwards (dns_policy.go) are not counted this way: unlike
// the raw pumps, exchangePlainVia/exchangeDoHVia only see whole dns.Msg
// values, not a byte count from the wire - approximating one via
// dns.Msg.Len() would be an estimate, not the real count this file's
// counters are meant to be (see the package doc comment above), so it was
// deliberately left out rather than added as a rough approximation.
func (s *statsProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	s.stats.recordAttempt()
	start := time.Now()
	conn, err := s.Provider.Dial(ctx, network, address)
	if err != nil {
		s.stats.recordFailure(err)
		if s.stats.setReady(false) {
			s.engine.enqueueUpstreamHealthEvent(s.id, false, err.Error())
		}
		return nil, err
	}
	s.stats.recordSuccess(time.Since(start))
	if s.stats.setReady(true) {
		s.engine.enqueueUpstreamHealthEvent(s.id, true, "")
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// snapshot for the UI
// ---------------------------------------------------------------------------

// UpstreamStatsInfo is a UI-facing snapshot of one upstream's live stats,
// alongside the same identity fields UpstreamInfo carries so the UI does not
// need to join two lists to render one row.
type UpstreamStatsInfo struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Ready bool   `json:"ready"`
	Via   string `json:"via,omitempty"`

	DialAttempts  uint64 `json:"dialAttempts"`
	DialSuccesses uint64 `json:"dialSuccesses"`
	DialFailures  uint64 `json:"dialFailures"`
	NotReadyCount uint64 `json:"notReadyCount"`
	BytesIn       uint64 `json:"bytesIn"`
	BytesOut      uint64 `json:"bytesOut"`

	TCPFlowsTotal uint64 `json:"tcpFlowsTotal"`
	UDPFlowsTotal uint64 `json:"udpFlowsTotal"`
	ActiveTCP     int64  `json:"activeTcp"`
	ActiveUDP     int64  `json:"activeUdp"`

	// DNSQueriesForwarded/DNSQueriesFailed are the subset of dial traffic
	// through this upstream that was specifically DNS lookups a policy rule
	// routed here - see UpstreamStats.dnsQueriesForwarded's doc comment for
	// why this is not derivable from DialAttempts/DialFailures above.
	DNSQueriesForwarded uint64 `json:"dnsQueriesForwarded,omitempty"`
	DNSQueriesFailed    uint64 `json:"dnsQueriesFailed,omitempty"`

	LastLatencyMs       int64  `json:"lastLatencyMs,omitempty"`
	LastError           string `json:"lastError,omitempty"`
	LastErrorAtMillis   int64  `json:"lastErrorAtMillis,omitempty"`
	LastSuccessAtMillis int64  `json:"lastSuccessAtMillis,omitempty"`
	LastAttemptAtMillis int64  `json:"lastAttemptAtMillis,omitempty"`

	// PeerPath is the current peer-connection state, generic across upstream
	// kinds - "direct"/"derp:<region>" for a Tailnet/exit-node's peer,
	// "wireguard:established"/"wireguard:no-handshake" for a WireGuard
	// tunnel, "socks5"/"direct-bypass" for the kinds that have no
	// meaningful path, or "unknown" if it could not be determined. See
	// Engine.peerPathFor.
	PeerPath string `json:"peerPath,omitempty"`
}

// UpstreamStatsSnapshot lists live stats for every upstream currently known:
// every upstream UpstreamSnapshot would list, plus any upstream that has
// recorded stats even if it has since been removed, so its last-known state
// stays visible rather than disappearing along with the row that explains it.
func (e *Engine) UpstreamStatsSnapshot() []UpstreamStatsInfo {
	infoByID := make(map[UpstreamID]UpstreamInfo)
	if e.upstreams != nil {
		for _, p := range e.upstreams.List() {
			infoByID[p.ID()] = UpstreamInfo{
				ID:    string(p.ID()),
				Kind:  string(p.Kind()),
				Ready: p.Ready(),
				Via:   string(providerVia(p)),
			}
		}
	}

	statsByID := e.stats.snapshot()

	ids := make(map[UpstreamID]bool, len(infoByID)+len(statsByID))
	for id := range infoByID {
		ids[id] = true
	}
	for id := range statsByID {
		ids[id] = true
	}

	out := make([]UpstreamStatsInfo, 0, len(ids))
	for id := range ids {
		info := infoByID[id]
		if info.ID == "" {
			info.ID = string(id)
		}
		item := UpstreamStatsInfo{ID: info.ID, Kind: info.Kind, Ready: info.Ready, Via: info.Via}
		if info.Kind != "" {
			item.PeerPath = e.peerPathFor(id, UpstreamKind(info.Kind))
		}

		if s := statsByID[id]; s != nil {
			item.DialAttempts = atomic.LoadUint64(&s.dialAttempts)
			item.DialSuccesses = atomic.LoadUint64(&s.dialSuccesses)
			item.DialFailures = atomic.LoadUint64(&s.dialFailures)
			item.NotReadyCount = atomic.LoadUint64(&s.notReadyCount)
			item.BytesIn = atomic.LoadUint64(&s.bytesIn)
			item.BytesOut = atomic.LoadUint64(&s.bytesOut)
			item.TCPFlowsTotal = atomic.LoadUint64(&s.tcpFlowsTotal)
			item.UDPFlowsTotal = atomic.LoadUint64(&s.udpFlowsTotal)
			item.ActiveTCP = atomic.LoadInt64(&s.activeTCP)
			item.DNSQueriesForwarded = atomic.LoadUint64(&s.dnsQueriesForwarded)
			item.DNSQueriesFailed = atomic.LoadUint64(&s.dnsQueriesFailed)
			item.ActiveUDP = atomic.LoadInt64(&s.activeUDP)
			if ns := atomic.LoadInt64(&s.lastLatencyNs); ns > 0 {
				item.LastLatencyMs = ns / int64(time.Millisecond)
			}

			s.mu.Lock()
			item.LastError = s.lastError
			if !s.lastErrorAt.IsZero() {
				item.LastErrorAtMillis = s.lastErrorAt.UnixMilli()
			}
			if !s.lastSuccessAt.IsZero() {
				item.LastSuccessAtMillis = s.lastSuccessAt.UnixMilli()
			}
			if !s.lastAttemptAt.IsZero() {
				item.LastAttemptAtMillis = s.lastAttemptAt.UnixMilli()
			}
			s.mu.Unlock()
		}

		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
