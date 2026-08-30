// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Observability - production-safe metrics, samples and events.
//
// Design constraints (see docs/multi_tailnet_proxy_app/observability.md for
// the full writeup):
//
//   - Nothing on the packet hot path allocates, logs, formats strings, reads
//     a clock, or calls into Android. Hot-path code only ever does a plain
//     atomic add against a field that already exists (dataplaneCounters,
//     uidStats, UpstreamStats in stats.go).
//   - Anything that costs more than an atomic add (process CPU time,
//     runtime.ReadMemStats, JSON marshaling) runs on a low-frequency ticker
//     in its own goroutine, never inline in a flow handler.
//   - Discrete events (path transitions, restarts) reuse the engine's
//     existing bounded, non-blocking event channel (api.go's e.events) -
//     the same mechanism OnUpstreamHealthChanged already uses - rather than
//     a second delivery path.

// ---------------------------------------------------------------------------
// Dataplane counters (global, TUN-level and DNS-level)
// ---------------------------------------------------------------------------

// dataplaneCounters holds process-lifetime, atomic-only counters. Every
// field is written with exactly one atomic op and never allocates.
type dataplaneCounters struct {
	tunRxBytes   uint64
	tunTxBytes   uint64
	tunRxPackets uint64
	tunTxPackets uint64

	dnsQueries  uint64
	dnsFailures uint64

	vpnRestarts uint64

	// attributionFailures counts new flows where a UID-scoped policy rule
	// exists (policyUsesAppUID() was true) but resolveAppUID could not
	// attribute the flow to an app, so it fell through to a broader rule
	// than the one the user may have actually configured for it. See
	// uid.go's resolveAppUID and dns.go's fail-closed handling - this is
	// the "conscious fail open" tracking called for in
	// docs/multi_tailnet_proxy_app/observability.md's DNS-attribution
	// section: it does not by itself change any routing decision, it only
	// counts how often the ambiguity happens so that can be judged from
	// real numbers rather than guessed at.
	attributionFailures uint64

	// dnsAttributionFailClosed counts DNS queries refused (ServFail)
	// specifically because attribution failed while a UID-scoped rule
	// existed - the subset of attributionFailures where DNS chose to fail
	// closed rather than silently use the default route. See dns.go.
	dnsAttributionFailClosed uint64

	// dnsForwardFailures counts DNS queries that were correctly routed to a
	// specific upstream (route.provider != nil in dns.go's handleDNSMsg) but
	// then failed to get an answer through it - both UDP and, where
	// attempted, the TCP-truncation-retry failed too. This is deliberately
	// scoped to "a chosen upstream stopped answering DNS", separate from the
	// broader dnsFailures counter (which also includes blocked/attribution
	// outcomes): a WireGuard/SOCKS5/exit-node upstream can carry ordinary
	// traffic fine while its network silently drops DNS (a VPN provider
	// restricting port 53 to their own resolver is a common real case) -
	// this makes that failure mode visible on-device instead of only in
	// logcat, without having to guess from the generic counter.
	dnsForwardFailures uint64
}

// reset zeroes every dataplane counter, for the diagnostics "reset stats"
// action. Cumulative-since-VPN-start counters have no time axis to scope a
// partial reset against, so this always resets the full running total; only
// the Kotlin-side history tables (samples/events/app_samples) support
// resetting just a recent time window.
func (d *dataplaneCounters) reset() {
	atomic.StoreUint64(&d.tunRxBytes, 0)
	atomic.StoreUint64(&d.tunTxBytes, 0)
	atomic.StoreUint64(&d.tunRxPackets, 0)
	atomic.StoreUint64(&d.tunTxPackets, 0)
	atomic.StoreUint64(&d.dnsQueries, 0)
	atomic.StoreUint64(&d.dnsFailures, 0)
	atomic.StoreUint64(&d.vpnRestarts, 0)
	atomic.StoreUint64(&d.attributionFailures, 0)
	atomic.StoreUint64(&d.dnsAttributionFailClosed, 0)
	atomic.StoreUint64(&d.dnsForwardFailures, 0)
}

func (d *dataplaneCounters) addAttributionFailure() {
	atomic.AddUint64(&d.attributionFailures, 1)
}

func (d *dataplaneCounters) addDNSAttributionFailClosed() {
	atomic.AddUint64(&d.dnsAttributionFailClosed, 1)
}

func (d *dataplaneCounters) addDNSForwardFailure() {
	atomic.AddUint64(&d.dnsForwardFailures, 1)
}

func (d *dataplaneCounters) addRx(nbytes uint64) {
	atomic.AddUint64(&d.tunRxBytes, nbytes)
	atomic.AddUint64(&d.tunRxPackets, 1)
}

func (d *dataplaneCounters) addTx(nbytes uint64) {
	atomic.AddUint64(&d.tunTxBytes, nbytes)
	atomic.AddUint64(&d.tunTxPackets, 1)
}

// AddDNSQuery records one DNS query outcome. Called once per query from
// dns.go/dns_policy.go's existing completion points - not per packet, since
// a DNS exchange is already a single logical operation there.
func (e *Engine) AddDNSQuery(failed bool) {
	atomic.AddUint64(&e.obs.dp.dnsQueries, 1)
	if failed {
		atomic.AddUint64(&e.obs.dp.dnsFailures, 1)
	}
}

// AddVPNRestart records that the VPN/TUN was rebuilt (StartVPN called again
// after a prior StopVPN), for the "reconnect/restart events" counter.
func (e *Engine) AddVPNRestart() {
	atomic.AddUint64(&e.obs.dp.vpnRestarts, 1)
}

// ---------------------------------------------------------------------------
// Per-app (Android UID) accounting
// ---------------------------------------------------------------------------

// uidStats holds live counters for one Android app UID. Numeric fields are
// atomic; lastUpstream/byUpstream are guarded by mu since they're written
// once per new flow (not per packet) and read only by the low-frequency
// snapshot path, so a mutex here costs nothing that matters.
type uidStats struct {
	bytesIn  uint64
	bytesOut uint64
	tcpFlows uint64
	udpFlows uint64

	mu           sync.Mutex
	lastUpstream string
	byUpstream   map[UpstreamID]*upstreamUsage
}

// upstreamUsage holds one app UID's live counters against one specific
// upstream, so the UI can show "this app sent N bytes via upstream X" rather
// than just a single lastUpstream label. Same generic per-upstream shape
// regardless of upstream kind (SOCKS5, WireGuard, exit node, tailnet,
// direct) - kind-specific detail (direct/DERP path, region) is layered on
// separately in runtime_state.go/pathState, keyed by the same UpstreamID.
type upstreamUsage struct {
	bytesIn  uint64
	bytesOut uint64
	tcpFlows uint64
	udpFlows uint64
}

func (s *uidStats) addBytesIn(n int64) {
	if n > 0 {
		atomic.AddUint64(&s.bytesIn, uint64(n))
	}
}

func (s *uidStats) addBytesOut(n int64) {
	if n > 0 {
		atomic.AddUint64(&s.bytesOut, uint64(n))
	}
}

func (u *upstreamUsage) addBytesIn(n int64) {
	if n > 0 {
		atomic.AddUint64(&u.bytesIn, uint64(n))
	}
}

func (u *upstreamUsage) addBytesOut(n int64) {
	if n > 0 {
		atomic.AddUint64(&u.bytesOut, uint64(n))
	}
}

// noteUpstream records that a new flow for this app UID is using upstream
// id, and returns the per-upstream counters that flow's byte-copy loops
// should add to (in addition to the app-wide totals) for the lifetime of
// that flow. Called once per flow, not per packet.
func (s *uidStats) noteUpstream(id UpstreamID) *upstreamUsage {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUpstream = string(id)
	if s.byUpstream == nil {
		s.byUpstream = make(map[UpstreamID]*upstreamUsage)
	}
	u, ok := s.byUpstream[id]
	if !ok {
		u = &upstreamUsage{}
		s.byUpstream[id] = u
	}
	return u
}

// uidRegistry owns one uidStats per Android app UID ever seen on a flow,
// created lazily on first use - the same lifetime/creation pattern as
// statsRegistry (stats.go), so a UID's last-known usage stays visible after
// the app that generated it exits.
type uidRegistry struct {
	mu    sync.Mutex
	stats map[int32]*uidStats
}

func newUIDRegistry() *uidRegistry {
	return &uidRegistry{stats: make(map[int32]*uidStats)}
}

func (r *uidRegistry) forUID(uid int32) *uidStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.stats[uid]
	if !ok {
		s = &uidStats{}
		r.stats[uid] = s
	}
	return s
}

func (r *uidRegistry) snapshot() map[int32]*uidStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int32]*uidStats, len(r.stats))
	for uid, s := range r.stats {
		out[uid] = s
	}
	return out
}

func (e *Engine) uidStatsFor(uid int32) *uidStats {
	return e.uids.forUID(uid)
}

// resetAll drops every per-app UID entry, for the diagnostics "reset stats"
// action. A flow in flight at the moment of reset still holds a pointer to
// its old *uidStats/*upstreamUsage and will keep adding to it harmlessly;
// the next new flow for that UID gets a fresh entry via forUID.
func (r *uidRegistry) resetAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats = make(map[int32]*uidStats)
}

// ---------------------------------------------------------------------------
// Observability event types (dispatched via the existing e.events channel)
// ---------------------------------------------------------------------------

const (
	ObsEventPathDirectToDERP   = "TAILNET_DIRECT_TO_DERP"
	ObsEventPathDERPToDirect   = "TAILNET_DERP_TO_DIRECT"
	ObsEventExitNodeConnected  = "EXIT_NODE_CONNECTED"
	ObsEventExitNodeDisconnect = "EXIT_NODE_DISCONNECTED"
	ObsEventTailnetRestarted   = "TAILNET_RESTARTED"
	ObsEventVPNRestarted       = "VPN_RESTARTED"
	ObsEventBackendError       = "BACKEND_ERROR"
	ObsEventDNSQuery           = "DNS_QUERY"
)

// SetDNSQueryLogEnabled turns per-query DNS event logging on or off - the
// "toggleable heavier" tier of DNS observability (see
// docs/multi_tailnet_proxy_app/observability.md): which upstream a specific
// name resolved through, and with what outcome, at the cost of one event -
// and on the Kotlin side, one SQLite insert - per DNS lookup instead of per
// rare transition. Off by default (see observability.dnsQueryLogEnabled);
// the diagnostics UI's Network tab is expected to be the only caller,
// enabling this only while a developer/user is actively looking at it.
func (e *Engine) SetDNSQueryLogEnabled(enabled bool) {
	e.obs.dnsQueryLogEnabled.Store(enabled)
}

func (e *Engine) DNSQueryLogEnabled() bool {
	return e.obs.dnsQueryLogEnabled.Load()
}

// logDNSQuery records one DNS lookup's outcome, if and only if
// SetDNSQueryLogEnabled(true) is in effect - a single atomic load when it is
// not, so dns.go can call this unconditionally on every query without
// worrying about the cost. upstreamID is empty for a synthetic answer or a
// query that never reached routing (blocked/ambiguous/fail-closed).
func (e *Engine) logDNSQuery(qname, qtype string, appUID int32, upstreamID, outcome string) {
	if !e.obs.dnsQueryLogEnabled.Load() {
		return
	}
	e.enqueueObservabilityEvent(ObsEventDNSQuery, upstreamID, appUID, qtype, qname, outcome, "")
}

// enqueueObservabilityEvent is the single place any discrete observability
// event is emitted. Bounded and non-blocking, same as every other
// e.events send - a full buffer drops the event rather than stalling the
// caller, which for path/lifecycle transitions (rare, low-rate) should
// never actually happen in practice.
func (e *Engine) enqueueObservabilityEvent(eventType, upstreamID string, appUID int32, networkSource, prevState, newState, metaJSON string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != StateOpen {
		return
	}
	select {
	case e.events <- engineEvent{
		kind:          eventObservability,
		obsType:       eventType,
		obsUpstreamID: upstreamID,
		obsAppUID:     appUID,
		obsNetSource:  networkSource,
		obsPrevState:  prevState,
		obsNewState:   newState,
		obsMetaJSON:   metaJSON,
	}:
	default:
	}
}

// ---------------------------------------------------------------------------
// Per-upstream path state (direct vs DERP), derived from the same tsnet
// Status() call runtime_state.go's poller already makes - no extra polling.
// ---------------------------------------------------------------------------

// pathState tracks the last-observed direct/DERP state for one upstream, so
// a transition event fires only on an actual change, not on every poll.
type pathState struct {
	mu         sync.Mutex
	known      bool
	direct     bool
	derpRegion string
}

// noteExitNodePath is called by runtime_state.go's existing per-tailnet poll
// with what the same Status() call already told it about the exit node
// path, if any (PeerStatus.CurAddr non-empty means direct; PeerStatus.Relay
// is the DERP region code when relayed). It fires
// ObsEventPathDirectToDERP/ObsEventPathDERPToDirect only on a genuine
// change, and ObsEventExitNodeConnected/Disconnected when hasExitNode
// itself flips.
func (e *Engine) noteExitNodePath(upstreamID string, hasExitNode, direct bool, derpRegion string) {
	ps := e.obs.pathFor(upstreamID)
	ps.mu.Lock()
	wasKnown, wasDirect, wasDerp := ps.known, ps.direct, ps.derpRegion
	if !hasExitNode {
		if ps.known {
			ps.known = false
			ps.mu.Unlock()
			e.enqueueObservabilityEvent(ObsEventExitNodeDisconnect, upstreamID, UnknownAppUID, "", "connected", "disconnected", "")
			return
		}
		ps.mu.Unlock()
		return
	}
	// A transition event only makes sense once there was a prior known
	// state to transition from - the very first observation after
	// connecting is "connected", not itself a direct<->DERP transition.
	changed := wasKnown && wasDirect != direct
	ps.known, ps.direct, ps.derpRegion = true, direct, derpRegion
	ps.mu.Unlock()

	if !wasKnown {
		e.enqueueObservabilityEvent(ObsEventExitNodeConnected, upstreamID, UnknownAppUID, "", "disconnected", "connected", "")
	}
	if changed {
		if direct {
			e.enqueueObservabilityEvent(ObsEventPathDERPToDirect, upstreamID, UnknownAppUID, "", "derp:"+wasDerp, "direct", "")
		} else {
			e.enqueueObservabilityEvent(ObsEventPathDirectToDERP, upstreamID, UnknownAppUID, "", "direct", "derp:"+derpRegion, "")
		}
	}
}

// ---------------------------------------------------------------------------
// Periodic process/runtime sampler
// ---------------------------------------------------------------------------

// ProcessSample is a point-in-time snapshot of process/runtime health,
// cheap enough to compute every few seconds but not worth computing per
// packet. CPUSeconds is exact (read from the kernel's own accounting, not
// derived from wall-clock handler duration); everything else is exact too
// except where noted.
type ProcessSample struct {
	AtMillis int64 `json:"atMillis"`

	// CPUSeconds is this process's total (user+system) CPU time since it
	// started, from /proc/self/stat. -1 if unavailable (non-Linux, or the
	// proc file could not be read) - callers must treat -1 as "unknown", not
	// zero.
	CPUSeconds float64 `json:"cpuSeconds"`

	// CPUPercent is CPUSeconds delta over wall-clock delta between this
	// sample and the previous one, i.e. average utilization over the sample
	// interval - never computed inside packet handling. -1 if unavailable or
	// this is the first sample.
	CPUPercent float64 `json:"cpuPercent"`

	GoHeapAllocBytes uint64 `json:"goHeapAllocBytes"`
	GoHeapSysBytes   uint64 `json:"goHeapSysBytes"`
	GoNumGC          uint32 `json:"goNumGc"`
	GoGCPauseTotalNs uint64 `json:"goGcPauseTotalNs"`
	GoroutineCount   int    `json:"goroutineCount"`

	EngineUptimeSeconds int64 `json:"engineUptimeSeconds"`
	VPNUptimeSeconds    int64 `json:"vpnUptimeSeconds"` // -1 if VPN not running

	// CPUSecondsPerGiB is a derived efficiency metric: cumulative process
	// CPU seconds divided by cumulative dataplane bytes (TUN RX+TX),
	// expressed per GiB. -1 until at least one GiB has moved, to avoid a
	// wildly noisy ratio over a tiny denominator.
	CPUSecondsPerGiB float64 `json:"cpuSecondsPerGiB"`
}

// observability owns the engine-wide dataplane counters, the per-UID
// registry's parent Engine reference, the periodic sampler, and per-upstream
// path state. One instance per Engine, created in NewEngineWithStateStore
// and stopped in Engine.Close.
type observability struct {
	engine *Engine
	dp     dataplaneCounters

	startTime time.Time

	pathsMu sync.Mutex
	paths   map[string]*pathState

	// Sampler state. intervalNs is read by the sampler goroutine every tick
	// (so a change takes effect within one tick) and written by
	// SetObservabilitySampleIntervalSeconds - plain atomic, no lock needed
	// for a single int64.
	intervalNs int64
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup

	lastMu       sync.Mutex
	lastSample   ProcessSample
	haveLast     bool
	lastCPUSecs  float64
	lastSampleAt time.Time

	vpnStartedAt atomic.Int64 // unix millis, 0 if VPN not running

	// Advanced diagnostics: off by default, explicit opt-in only, never a
	// background profiler. See CaptureCPUProfile/CaptureHeapProfile/
	// CaptureGoroutineDump below.
	advancedMu sync.Mutex
	advanced   bool

	// dnsQueryLogEnabled gates per-query DNS event logging (see logDNSQuery
	// below). Unlike every other observability event, one of these fires per
	// DNS lookup rather than per rare transition - the UI persists every
	// event it receives (SQLite insert, see MultiProxySessionCoordinator.
	// recordObservabilityEvent on the Kotlin side), so leaving this on by
	// default would mean writing to disk on every DNS query an app makes.
	// atomic.Bool so the hot path (every DNS query, on or off) only ever
	// costs one atomic load when this is off.
	dnsQueryLogEnabled atomic.Bool
}

// defaultSampleIntervalSeconds is used whenever the diagnostics UI is not
// visible - infrequent enough that the sampler's own cost (a MemStats call,
// a /proc read, a JSON-free struct copy) is nowhere near "continuous
// profiling" territory. The UI raises this via
// SetObservabilitySampleIntervalSeconds while visible and restores it on
// close (PHASE 17: coarse sampling when the screen is closed).
const defaultSampleIntervalSeconds = 60

func newObservability(e *Engine) *observability {
	o := &observability{
		engine:     e,
		startTime:  time.Now(),
		paths:      make(map[string]*pathState),
		intervalNs: int64(defaultSampleIntervalSeconds * time.Second),
		stopCh:     make(chan struct{}),
	}
	o.wg.Add(1)
	go o.samplerLoop()
	return o
}

func (o *observability) pathFor(upstreamID string) *pathState {
	o.pathsMu.Lock()
	defer o.pathsMu.Unlock()
	p, ok := o.paths[upstreamID]
	if !ok {
		p = &pathState{}
		o.paths[upstreamID] = p
	}
	return p
}

// peerPathFor reports the current peer-connection state for id, generically
// across every upstream kind:
//
//   - Tailnet/exit-node: the last-known direct/DERP path this upstream's
//     exit-node peer was observed at, read from the cached pathState that
//     runtime_state.go's existing per-tailnet poller already keeps up to
//     date via noteExitNodePath (piggybacking on a Status() call it makes
//     anyway). This snapshot deliberately does not make its own tsnet
//     Status() call - it would be redundant work on every UI poll, and
//     would need a per-destination peer, which a "current state of this
//     upstream" summary does not have.
//   - WireGuard: the tunnel's own handshake state (wireguardProvider's
//     PeerPathInfo just inspects its already-open device, no I/O).
//   - SOCKS5/direct: a fixed, kind-describing string, since neither has a
//     meaningful "path" the way a Tailscale peer connection does.
func (e *Engine) peerPathFor(id UpstreamID, kind UpstreamKind) string {
	switch kind {
	case UpstreamKindTailnet, UpstreamKindExitNode:
		ps := e.obs.pathFor(string(id))
		ps.mu.Lock()
		defer ps.mu.Unlock()
		if !ps.known {
			return "unknown"
		}
		if ps.direct {
			return "direct"
		}
		return "derp:" + ps.derpRegion
	default:
		p, ok := e.lookupProvider(id)
		if !ok {
			return ""
		}
		return p.PeerPathInfo(context.Background(), "")
	}
}

func (o *observability) stop() {
	o.stopOnce.Do(func() { close(o.stopCh) })
	o.wg.Wait()
}

// SetObservabilitySampleIntervalSeconds changes the sampler's cadence. The
// diagnostics UI calls this with a short interval (e.g. 1s) only while it is
// visible, and restores defaultSampleIntervalSeconds (or calls this with 0,
// equivalent) when it closes - see PHASE 17. secs <= 0 restores the default.
func (e *Engine) SetObservabilitySampleIntervalSeconds(secs int32) {
	if secs <= 0 {
		secs = defaultSampleIntervalSeconds
	}
	atomic.StoreInt64(&e.obs.intervalNs, int64(secs)*int64(time.Second))
}

func (o *observability) samplerLoop() {
	defer o.wg.Done()
	// Sample once immediately so the UI has something to show before the
	// first tick elapses, then honor whatever interval is currently set,
	// re-reading it every cycle so a UI-driven change takes effect promptly.
	o.sampleOnce()
	for {
		interval := time.Duration(atomic.LoadInt64(&o.intervalNs))
		if interval <= 0 {
			interval = defaultSampleIntervalSeconds * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-o.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			o.sampleOnce()
		}
	}
}

func (o *observability) sampleOnce() {
	now := time.Now()
	cpuSecs := readProcessCPUSeconds()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	vpnUptime := int64(-1)
	if started := o.vpnStartedAt.Load(); started != 0 {
		vpnUptime = (now.UnixMilli() - started) / 1000
	}

	o.lastMu.Lock()
	cpuPercent := -1.0
	if o.haveLast && cpuSecs >= 0 && o.lastCPUSecs >= 0 {
		wallDelta := now.Sub(o.lastSampleAt).Seconds()
		if wallDelta > 0 {
			cpuPercent = 100 * (cpuSecs - o.lastCPUSecs) / wallDelta
		}
	}
	o.lastCPUSecs = cpuSecs
	o.lastSampleAt = now
	o.haveLast = true

	cpuPerGiB := -1.0
	totalBytes := atomic.LoadUint64(&o.dp.tunRxBytes) + atomic.LoadUint64(&o.dp.tunTxBytes)
	const gib = 1 << 30
	if cpuSecs >= 0 && totalBytes >= gib {
		cpuPerGiB = cpuSecs / (float64(totalBytes) / gib)
	}

	sample := ProcessSample{
		AtMillis:            now.UnixMilli(),
		CPUSeconds:          cpuSecs,
		CPUPercent:          cpuPercent,
		GoHeapAllocBytes:    mem.HeapAlloc,
		GoHeapSysBytes:      mem.HeapSys,
		GoNumGC:             mem.NumGC,
		GoGCPauseTotalNs:    mem.PauseTotalNs,
		GoroutineCount:      runtime.NumGoroutine(),
		EngineUptimeSeconds: int64(now.Sub(o.startTime).Seconds()),
		VPNUptimeSeconds:    vpnUptime,
		CPUSecondsPerGiB:    cpuPerGiB,
	}
	o.lastSample = sample
	o.lastMu.Unlock()
}

// readProcessCPUSeconds reads this process's cumulative user+system CPU
// time from /proc/self/stat (fields 14 and 15, in clock ticks). Returns -1
// if unavailable. This is real kernel accounting, not a wall-clock
// approximation - see the package doc comment's "do not label wall-clock
// handler duration as CPU time" rule.
func readProcessCPUSeconds() float64 {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return -1
	}
	// The comm field (2nd, parenthesized) can itself contain spaces/parens,
	// so split on the last ')' rather than by field index from the start.
	closeParen := bytes.LastIndexByte(data, ')')
	if closeParen < 0 || closeParen+2 >= len(data) {
		return -1
	}
	fields := strings.Fields(string(data[closeParen+2:]))
	// After the comm field, index 0 is field 3 (state); utime is field 14,
	// stime is field 15 -> indices 11 and 12 here.
	if len(fields) < 13 {
		return -1
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return -1
	}
	clkTck := 100.0 // USER_HZ is 100 on essentially every Android/Linux kernel.
	return float64(utime+stime) / clkTck
}

// ---------------------------------------------------------------------------
// TUN counting link endpoint
// ---------------------------------------------------------------------------
//
// wrapCountingEndpoint decorates the real stack.LinkEndpoint (fdbased, in
// production; an in-memory channel.Endpoint in host tests) so every packet
// gVisor writes to or reads from the TUN is counted with a single atomic
// add, with no allocation and no per-packet formatting. It is defined in
// tun_interceptor.go, next to where the endpoint is constructed, since the
// stack.LinkEndpoint interface's exact method set lives there.

// ---------------------------------------------------------------------------
// Snapshot for the UI
// ---------------------------------------------------------------------------

// UIDStatsInfo is a UI-facing snapshot of one Android app UID's counters.
// The engine only ever sees the UID (see uid.go's doc comment on
// UIDResolver) - package name and human-readable label resolution happens
// entirely on the Kotlin side, once per UID and cached there, never here and
// never per-flow (PHASE 6).
type UIDStatsInfo struct {
	UID          int32  `json:"uid"`
	BytesIn      uint64 `json:"bytesIn"`
	BytesOut     uint64 `json:"bytesOut"`
	TCPFlows     uint64 `json:"tcpFlows"`
	UDPFlows     uint64 `json:"udpFlows"`
	LastUpstream string `json:"lastUpstream,omitempty"`

	// ByUpstream breaks this app's totals down per upstream it has actually
	// used, so the UI can show real per-upstream-type byte counts (e.g.
	// "app consumption distribution on a tailnet") instead of inferring it
	// from LastUpstream alone.
	ByUpstream []UpstreamUsageInfo `json:"byUpstream,omitempty"`
}

// UpstreamUsageInfo is one app UID's counters against one specific upstream.
type UpstreamUsageInfo struct {
	UpstreamID string `json:"upstreamId"`
	BytesIn    uint64 `json:"bytesIn"`
	BytesOut   uint64 `json:"bytesOut"`
	TCPFlows   uint64 `json:"tcpFlows"`
	UDPFlows   uint64 `json:"udpFlows"`
}

// DataplaneSnapshot is the UI-facing snapshot of global TUN/DNS counters.
type DataplaneSnapshot struct {
	TunRxBytes   uint64 `json:"tunRxBytes"`
	TunTxBytes   uint64 `json:"tunTxBytes"`
	TunRxPackets uint64 `json:"tunRxPackets"`
	TunTxPackets uint64 `json:"tunTxPackets"`
	DNSQueries   uint64 `json:"dnsQueries"`
	DNSFailures  uint64 `json:"dnsFailures"`
	VPNRestarts  uint64 `json:"vpnRestarts"`

	// AttributionFailures/DNSAttributionFailClosed - see dataplaneCounters'
	// doc comments. Exact counts, not estimates: every increment corresponds
	// to a real resolveAppUID call that returned UnknownAppUID while a
	// UID-scoped policy rule existed.
	AttributionFailures      uint64 `json:"attributionFailures"`
	DNSAttributionFailClosed uint64 `json:"dnsAttributionFailClosed"`

	// DNSForwardFailures - see dataplaneCounters.dnsForwardFailures' doc
	// comment: a query was routed to a specific upstream but got no answer
	// through it (that upstream's own network dropped/blocked DNS).
	DNSForwardFailures uint64 `json:"dnsForwardFailures"`
}

// ObservabilitySnapshot is the single JSON payload the diagnostics UI polls
// at low frequency (PHASE 9/11). It bundles everything that isn't already
// covered by GetUpstreamStatsJSON/GetTailnetStatesJSON (which the UI polls
// separately at its own existing 1s cadence - see
// MultiProxySessionCoordinator.kt) so this call stays cheap: no new locks
// beyond the small maps/mutexes already used for hot-path counters.
type ObservabilitySnapshot struct {
	Process   ProcessSample     `json:"process"`
	Dataplane DataplaneSnapshot `json:"dataplane"`
	Apps      []UIDStatsInfo    `json:"apps"`
}

// ResetObservabilityCounters zeroes the selected live counter groups, for
// the diagnostics "reset stats" action. Each group is independently
// selectable so the UI can offer scoped resets (e.g. "just per-app, keep
// dataplane totals"). This only affects the live in-memory counters this
// snapshot is built from; the Kotlin-side history tables (samples/events/
// app_samples) are reset separately and can be scoped to a recent time
// window, since they carry timestamps and these cumulative counters don't.
func (e *Engine) ResetObservabilityCounters(dataplane, apps, upstreams bool) {
	if dataplane {
		e.obs.dp.reset()
	}
	if apps {
		e.uids.resetAll()
	}
	if upstreams {
		e.stats.resetAll()
	}
}

// GetObservabilitySnapshotJSON returns the current ObservabilitySnapshot as
// JSON. Safe to call at any cadence the caller likes; the work it does
// (copying already-computed atomics/maps) is itself cheap, but the Kotlin
// side should still only call this at the sampler's own cadence (default
// 60s, or 1s while the diagnostics screen is visible) rather than every
// existing 1s session-state tick, to avoid doing this work when nothing new
// has been sampled.
func (e *Engine) GetObservabilitySnapshotJSON() string {
	o := e.obs

	o.lastMu.Lock()
	proc := o.lastSample
	o.lastMu.Unlock()

	dp := DataplaneSnapshot{
		TunRxBytes:   atomic.LoadUint64(&o.dp.tunRxBytes),
		TunTxBytes:   atomic.LoadUint64(&o.dp.tunTxBytes),
		TunRxPackets: atomic.LoadUint64(&o.dp.tunRxPackets),
		TunTxPackets: atomic.LoadUint64(&o.dp.tunTxPackets),
		DNSQueries:   atomic.LoadUint64(&o.dp.dnsQueries),
		DNSFailures:  atomic.LoadUint64(&o.dp.dnsFailures),
		VPNRestarts:  atomic.LoadUint64(&o.dp.vpnRestarts),

		AttributionFailures:      atomic.LoadUint64(&o.dp.attributionFailures),
		DNSAttributionFailClosed: atomic.LoadUint64(&o.dp.dnsAttributionFailClosed),
		DNSForwardFailures:       atomic.LoadUint64(&o.dp.dnsForwardFailures),
	}

	uidSnap := e.uids.snapshot()
	apps := make([]UIDStatsInfo, 0, len(uidSnap))
	for uid, s := range uidSnap {
		s.mu.Lock()
		lastUpstream := s.lastUpstream
		byUpstream := make([]UpstreamUsageInfo, 0, len(s.byUpstream))
		for id, u := range s.byUpstream {
			byUpstream = append(byUpstream, UpstreamUsageInfo{
				UpstreamID: string(id),
				BytesIn:    atomic.LoadUint64(&u.bytesIn),
				BytesOut:   atomic.LoadUint64(&u.bytesOut),
				TCPFlows:   atomic.LoadUint64(&u.tcpFlows),
				UDPFlows:   atomic.LoadUint64(&u.udpFlows),
			})
		}
		s.mu.Unlock()
		apps = append(apps, UIDStatsInfo{
			UID:          uid,
			BytesIn:      atomic.LoadUint64(&s.bytesIn),
			BytesOut:     atomic.LoadUint64(&s.bytesOut),
			TCPFlows:     atomic.LoadUint64(&s.tcpFlows),
			UDPFlows:     atomic.LoadUint64(&s.udpFlows),
			LastUpstream: lastUpstream,
			ByUpstream:   byUpstream,
		})
	}

	snap := ObservabilitySnapshot{Process: proc, Dataplane: dp, Apps: apps}
	b, err := json.Marshal(snap)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Advanced diagnostics (PHASE 14) - explicit opt-in only, never continuous.
// ---------------------------------------------------------------------------

// SetAdvancedDiagnostics turns higher-frequency sampling on/off. This alone
// does not start any profiler - it only shortens the sampler's interval
// (still just cheap atomic/MemStats work) so the diagnostics screen feels
// live. Actual profiling only ever happens via the explicit Capture*
// methods below, each a single bounded action, never a background loop.
func (e *Engine) SetAdvancedDiagnostics(on bool) {
	e.obs.advancedMu.Lock()
	e.obs.advanced = on
	e.obs.advancedMu.Unlock()
	if on {
		e.SetObservabilitySampleIntervalSeconds(5)
	} else {
		e.SetObservabilitySampleIntervalSeconds(defaultSampleIntervalSeconds)
	}
}

func (e *Engine) AdvancedDiagnosticsEnabled() bool {
	e.obs.advancedMu.Lock()
	defer e.obs.advancedMu.Unlock()
	return e.obs.advanced
}

// CaptureCPUProfileToFile runs Go's standard CPU profiler for exactly
// durationSeconds (bounded, capped at 60s) and writes the result to path.
// This is the only way CPU profiling ever runs in this engine - there is no
// HTTP pprof listener anywhere in production code, satisfying PHASE 14's
// "do not expose net/http/pprof over a production listening socket" rule.
// The caller (the diagnostics UI's explicit "Capture 30-second CPU profile"
// action) is responsible for exporting/sharing the resulting file.
func (e *Engine) CaptureCPUProfileToFile(path string, durationSeconds int32) error {
	if durationSeconds <= 0 {
		durationSeconds = 30
	}
	if durationSeconds > 60 {
		durationSeconds = 60
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := pprof.StartCPUProfile(f); err != nil {
		return err
	}
	time.Sleep(time.Duration(durationSeconds) * time.Second)
	pprof.StopCPUProfile()
	return nil
}

// CaptureHeapProfileToFile writes a single point-in-time heap profile. Cheap
// and instantaneous - no sleep, no ongoing cost.
func (e *Engine) CaptureHeapProfileToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	runtime.GC() // as recommended by pprof.WriteHeapProfile's own doc comment
	return pprof.WriteHeapProfile(f)
}

// CaptureGoroutineDumpToFile writes the current goroutine stacks. Cheap and
// instantaneous, same as the heap profile.
func (e *Engine) CaptureGoroutineDumpToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pprof.Lookup("goroutine").WriteTo(f, 1)
}
