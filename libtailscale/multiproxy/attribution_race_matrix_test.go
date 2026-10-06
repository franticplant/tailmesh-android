// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file extends attribution_race_measurement_test.go's single 3-stage
// run into a small, seeded, repeated-run matrix, in response to a direct
// request for more rigor than one percentage per stage: classified wrong-UID
// causes, an explicit attribution-delay sweep, a port-pool-size sweep (to
// test whether error genuinely tracks reuse pressure, the causal claim
// underlying this whole investigation), and an exact-lookup-only vs
// exact+UDP-fallback A/B.
//
// Deliberately NOT built, and worth being explicit about: the full
// Cartesian tier matrix requested (CPU-pressure tiers, QUIC-like/TCP-churn
// protocol modeling, an explicit independent "concurrent active flows" cap,
// the full 6-way wrong-UID taxonomy, and - the one that actually matters
// most - a real Android device tier). None of the synthetic work here
// establishes an absolute on-device rate; it establishes whether the
// mechanism responds to its causal variables the way the theory predicts,
// which is what §99's device-verification gap has always depended on
// eventually being checked against real hardware.
//
// wrong-UID classification here is two-way, not the requested six-way:
//
//   - stale_cache: earlyUIDCache answered from an existing entry without
//     calling resolve at all this time (only possible in stage 2/3, and
//     precisely what §99's forget() fix targets - instrumented directly,
//     not inferred).
//   - live_lookup_wrong: resolve *did* run (in every stage 1 case, and in
//     stage 2/3 whenever the cache had no unexpired entry) and the OS's own
//     live-table answer was simply wrong. This merges "exact query
//     returned the wrong app" and "the UDP fallback variant returned the
//     wrong app" - splitting those two apart precisely would need
//     per-call variant tracing through resolveAppUIDOnce's retry ladder,
//     which was not built this pass. The separate exact-only-vs-fallback
//     A/B below answers the same underlying question a different way: by
//     comparing whole-run error rates with the fallback ladder disabled
//     outright, rather than attributing individual wrong answers to it.
//
// "unresolved" is also not split into "genuinely no answer" vs
// "corroboration disagreement (correctly rejected)" - both already fail
// safe to UnknownAppUID in production and are conflated here for the same
// reason: distinguishing them needs the same per-call tracing.

// simPortTable models an Android kernel's port-ownership table with a
// recording lag: a claimed port is immediately visible to a
// variant-tolerant query (modeling getConnectionOwnerUid's dst-port-zeroed/
// unspecified-dst retry, which - per §99 - exists specifically because an
// *unconnected* UDP socket can be recorded incompletely for a short window)
// but only visible to an *exact* query once "recorded". Without this, the
// exact-vs-fallback A/B below would be meaningless: in a table with no
// recording lag, the fallback path is never exercised at all, because the
// exact query never misses.
// portKey is (srcIP, srcPort) - Android's getConnectionOwnerUid (and
// Tailmesh's real resolveAppUID) keys on the full local socket address, not
// port alone. An earlier version of this table and matrixResolver keyed on
// port only, silently ignoring the srcIP argument ResolveUID was actually
// given - fine as long as every simulated flow shared one hardcoded source
// IP (which every test in this file did, until srcIPPool below), wrong in
// general: two apps "reusing the same port" while on different source IPs
// (a real possibility - see matrixProfile.srcIPPool's doc comment) do not
// collide in Android's real live table at all, since it's a different key
// entirely.
func portKey(ip string, port int32) string {
	return ip + "|" + strconv.Itoa(int(port))
}

type simPortTable struct {
	mu           sync.Mutex
	pending      map[string]int32
	recorded     map[string]int32
	recordingLag time.Duration
	rng          *rand.Rand
	// crossAppClaims counts every claim() that landed on a key another app
	// had already claimed (pending or recorded still held a different UID)
	// - direct proof that a "wrong" answer traces back to an actual
	// cross-app collision on the identical (srcIP, srcPort) key, not some
	// other source of noise. See TestAttributionMatrixWrongAnswersAreRaces.
	crossAppClaims atomic.Int64
}

func newSimPortTable(seed int64, recordingLag time.Duration) *simPortTable {
	return &simPortTable{
		pending:      make(map[string]int32),
		recorded:     make(map[string]int32),
		recordingLag: recordingLag,
		rng:          rand.New(rand.NewSource(seed)),
	}
}

func (t *simPortTable) claim(ip string, port, uid int32) {
	key := portKey(ip, port)
	t.mu.Lock()
	if prev, ok := t.pending[key]; ok && prev != uid {
		t.crossAppClaims.Add(1)
	} else if prev, ok := t.recorded[key]; ok && prev != uid {
		t.crossAppClaims.Add(1)
	}
	t.pending[key] = uid
	var lag time.Duration
	if t.recordingLag > 0 {
		lag = time.Duration(t.rng.Int63n(int64(t.recordingLag)))
	}
	t.mu.Unlock()

	if lag == 0 {
		t.mu.Lock()
		t.recorded[key] = uid
		t.mu.Unlock()
		return
	}
	go func() {
		time.Sleep(lag)
		t.mu.Lock()
		t.recorded[key] = uid
		t.mu.Unlock()
	}()
}

func (t *simPortTable) exact(ip string, port int32) int32 {
	key := portKey(ip, port)
	t.mu.Lock()
	defer t.mu.Unlock()
	if uid, ok := t.recorded[key]; ok {
		return uid
	}
	return UnknownAppUID
}

func (t *simPortTable) variant(ip string, port int32) int32 {
	key := portKey(ip, port)
	t.mu.Lock()
	defer t.mu.Unlock()
	if uid, ok := t.recorded[key]; ok {
		return uid
	}
	if uid, ok := t.pending[key]; ok {
		return uid
	}
	return UnknownAppUID
}

// matrixResolver answers like AppUidResolver.kt does against simPortTable,
// with fallbackEnabled controlling whether the dst-port-zeroed/
// unspecified-dst retry variants (resolveAppUIDOnce, uid.go) are allowed to
// find anything - the A/B toggle.
type matrixResolver struct {
	table           *simPortTable
	fallbackEnabled bool
}

func (r *matrixResolver) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	isVariant := dstPort == 0 || dstIP == "0.0.0.0" || dstIP == "::"
	if isVariant {
		if !r.fallbackEnabled {
			return UnknownAppUID
		}
		return r.table.variant(srcIP, srcPort)
	}
	return r.table.exact(srcIP, srcPort)
}

// matrixProfile is one deliberately constructed load/contention point -
// see the file doc comment for why this is a small, named set rather than
// the full requested grid.
type matrixProfile struct {
	name         string
	protocol     string // "udp" or "tcp" - passed straight through to Engine.resolveAppUID
	dstPort      uint16
	apps         int
	portPool     int32
	srcIPPool    int // number of distinct source IPs flows are drawn from; 0 or 1 = every flow shares one IP
	flowsPerApp  int
	recordingLag time.Duration
	lifetimeMin  time.Duration
	lifetimeMax  time.Duration
}

// Flow counts match the scale of the original single-run measurement
// (attribution_race_measurement_test.go: 600 flows/app) rather than a
// timeout-driven cut-down - wall-clock cost is flowsPerApp * (delay + avg
// lifetime), run matrixRunsPerCell times per cell, across 3 stages and (for
// the matrix test) 3 profiles, and is allowed to take however long it
// takes.
//
// All three of these are UDP, deliberately: the DNS send-and-close pattern
// is what the user originally reported, and it's what every earlier
// measurement in this session (attribution_race_measurement_test.go, and
// the first three sections of this file) has been modeling. See
// matrixProfilesTCP below for TCP's own version of this same question -
// don't assume from these numbers alone that TCP behaves the same way, and
// don't assume it doesn't; that assumption is exactly what the TCP profiles
// exist to check instead of asserting.
var matrixProfiles = []matrixProfile{
	{name: "A1_low_contention", protocol: "udp", dstPort: 53, apps: 4, portPool: 8192, flowsPerApp: 300, recordingLag: 150 * time.Microsecond, lifetimeMin: 0, lifetimeMax: 2 * time.Millisecond},
	{name: "B1_moderate", protocol: "udp", dstPort: 53, apps: 8, portPool: 1024, flowsPerApp: 500, recordingLag: 150 * time.Microsecond, lifetimeMin: 0, lifetimeMax: 2 * time.Millisecond},
	{name: "C2_heavy_reuse", protocol: "udp", dstPort: 53, apps: 8, portPool: 64, flowsPerApp: 500, recordingLag: 150 * time.Microsecond, lifetimeMin: 0, lifetimeMax: 2 * time.Millisecond},
}

// matrixProfilesTCP mirrors matrixProfiles' three contention tiers, but
// models a TCP connection instead of a UDP send-and-close DNS query:
//
//   - recordingLag is far smaller (20us vs UDP's 150us): the UDP fallback
//     ladder (§99, "Also added") exists specifically because an
//     *unconnected* UDP socket can be recorded in the kernel's owner table
//     before its destination fields are populated - connect()'s blocking
//     three-way handshake means a TCP socket has no equivalent
//     half-recorded state by the time it could plausibly be queried, and
//     resolveAppUIDOnce (uid.go) never even attempts the variant ladder for
//     TCP, matching that. A small nonzero lag is kept rather than zero
//     because *some* scheduling/table-update latency is real even for a
//     fully-connected socket - it's a hypothesis being modeled here, not a
//     verified number, since nothing in this sandbox can measure Android's
//     actual conntrack update latency either.
//   - lifetimeMin/Max is far longer (5-100ms vs UDP's 0-2ms): a TCP
//     connection is held open for the duration of a request/response, not
//     a single send-and-close - so the port stays claimed by the same app
//     far longer, directly reducing the odds another app's flow reuses it
//     before this one's attribution completes. Still compressed relative
//     to a real HTTP connection's actual lifetime (could be seconds), for
//     the same wall-clock reasons as everywhere else in this file - the
//     ratio to UDP's lifetime, not the absolute number, is what's meant to
//     be representative.
//
// Everything else - app count, port pool, flow count - is held identical
// to matrixProfiles so the UDP-vs-TCP comparison isolates protocol-specific
// behavior rather than also varying load.
// flowsPerApp and lifetimeMax are both smaller here than a first pass used
// (500/app, 5-100ms) - that combination made a single profile/stage/run
// cost tens of seconds, and the full profile matrix (3 profiles x 3 stages
// x 10 runs) blew well past a 20-minute test timeout outright. Lifetime is
// still 10-20x longer than the UDP profiles' 0-2ms, which is the actual
// point being modeled (a TCP connection stays open, a DNS UDP socket
// doesn't) - just compressed further for wall-clock, same as every other
// profile in this file.
var matrixProfilesTCP = []matrixProfile{
	{name: "T1_tcp_low_contention", protocol: "tcp", dstPort: 443, apps: 4, portPool: 8192, flowsPerApp: 150, recordingLag: 20 * time.Microsecond, lifetimeMin: 2 * time.Millisecond, lifetimeMax: 20 * time.Millisecond},
	{name: "T2_tcp_moderate", protocol: "tcp", dstPort: 443, apps: 8, portPool: 1024, flowsPerApp: 200, recordingLag: 20 * time.Microsecond, lifetimeMin: 2 * time.Millisecond, lifetimeMax: 20 * time.Millisecond},
	{name: "T3_tcp_heavy_reuse", protocol: "tcp", dstPort: 443, apps: 8, portPool: 64, flowsPerApp: 200, recordingLag: 20 * time.Microsecond, lifetimeMin: 2 * time.Millisecond, lifetimeMax: 20 * time.Millisecond},
}

// runResult is one seeded run's raw counts - kept raw, per direct
// instruction not to report only averaged percentages.
type runResult struct {
	seed           int64
	total          int
	correct        int
	unresolved     int
	wrongStale     int
	wrongLive      int
	crossAppClaims int64   // see simPortTable.crossAppClaims - proof each wrong answer traces to a real collision
	lookupNanos    []int64 // one entry per flow, for percentile reporting
}

// attributeOnce runs one flow's attribution attempt under the given stage
// (1: corroboration-only, late lookup; 2: early dispatch, no forget; 3:
// early dispatch + forget - see attribution_race_measurement_test.go for
// the full description of each) and delay (time between the simulated
// socket opening and the first resolution attempt starting - the
// "attribution delay" controlled variable). Returns the resolved UID and
// whether resolve() actually ran (false only means "answered from an
// unexpired cache entry with no fresh lookup" - stage 2/3 only).
func attributeOnce(protocol string, stage int, e *Engine, cache *earlyUIDCache, delay time.Duration, src, dst netip.AddrPort) (int32, bool) {
	var called int32
	resolve := func() int32 {
		atomic.AddInt32(&called, 1)
		return e.resolveAppUID(protocol, src, dst)
	}

	if delay > 0 {
		time.Sleep(delay)
	}

	switch stage {
	case 1:
		return resolve(), true
	case 2, 3:
		key := flowKey{protocol, src, dst}
		cache.begin(key, resolve)
		uid, _ := cache.take(key)
		if stage == 3 {
			cache.forget(key)
		}
		return uid, atomic.LoadInt32(&called) > 0
	default:
		panic("unknown stage")
	}
}

// runProfile executes one full seeded run of p under stage, returning raw
// counts. fallbackEnabled toggles the UDP-variant retry ladder's ability to
// find anything at all - the exact-only-vs-fallback experiment.
func runProfile(p matrixProfile, stage int, delay time.Duration, fallbackEnabled bool, seed int64) runResult {
	table := newSimPortTable(seed, p.recordingLag)
	e := NewEngine(fmt.Sprintf("%s/matrix-%d", os.TempDir(), seed), &MockCallback{})
	defer e.Close()
	e.SetUIDResolver(&matrixResolver{table: table, fallbackEnabled: fallbackEnabled})
	cache := newEarlyUIDCache()

	apps := make([]int32, p.apps)
	for i := range apps {
		apps[i] = int32(10001 + i)
	}
	dst := netip.AddrPortFrom(SyntheticIPv4DNS, p.dstPort)

	ipPoolSize := p.srcIPPool
	if ipPoolSize < 1 {
		ipPoolSize = 1
	}
	srcIPs := make([]netip.Addr, ipPoolSize)
	for i := range srcIPs {
		// 10.0.<i/256>.<i%256>, up to 65536 distinct addresses - plenty for
		// any sweep this file runs.
		srcIPs[i] = netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})
	}

	total := p.apps * p.flowsPerApp
	trueUIDs := make([]int32, total)
	gotUIDs := make([]int32, total)
	resolveRan := make([]bool, total)
	lookupNanos := make([]int64, total)
	var idx atomic.Int64

	var wg sync.WaitGroup
	for _, uid := range apps {
		wg.Add(1)
		go func(appUID int32) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed ^ int64(appUID)))
			lifetimeSpan := int64(p.lifetimeMax - p.lifetimeMin)
			for i := 0; i < p.flowsPerApp; i++ {
				port := int32(rng.Int31n(p.portPool))
				ip := srcIPs[rng.Intn(ipPoolSize)]
				table.claim(ip.String(), port, appUID)
				src := netip.AddrPortFrom(ip, uint16(port))

				start := time.Now()
				got, ran := attributeOnce(p.protocol, stage, e, cache, delay, src, dst)
				elapsed := time.Since(start).Nanoseconds()

				seq := int(idx.Add(1)) - 1
				trueUIDs[seq] = appUID
				gotUIDs[seq] = got
				resolveRan[seq] = ran
				lookupNanos[seq] = elapsed

				lifetime := p.lifetimeMin
				if lifetimeSpan > 0 {
					lifetime += time.Duration(rng.Int63n(lifetimeSpan))
				}
				if lifetime > 0 {
					time.Sleep(lifetime)
				}
			}
		}(uid)
	}
	wg.Wait()

	r := runResult{seed: seed, total: total, lookupNanos: lookupNanos, crossAppClaims: table.crossAppClaims.Load()}
	for i := 0; i < total; i++ {
		switch {
		case gotUIDs[i] == UnknownAppUID:
			r.unresolved++
		case gotUIDs[i] == trueUIDs[i]:
			r.correct++
		case !resolveRan[i]:
			r.wrongStale++
		default:
			r.wrongLive++
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// aggregation
// ---------------------------------------------------------------------------

type aggregate struct {
	mean, median, min, max, stddev float64
}

func aggregatePercent(vals []float64) aggregate {
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	n := float64(len(sorted))
	sum := 0.0
	for _, v := range sorted {
		sum += v
	}
	mean := sum / n
	variance := 0.0
	for _, v := range sorted {
		variance += (v - mean) * (v - mean)
	}
	stddev := math.Sqrt(variance / n)
	median := sorted[len(sorted)/2]
	return aggregate{mean: mean, median: median, min: sorted[0], max: sorted[len(sorted)-1], stddev: stddev}
}

func percentile(sortedNanos []int64, p float64) int64 {
	if len(sortedNanos) == 0 {
		return 0
	}
	idx := int(p * float64(len(sortedNanos)-1))
	return sortedNanos[idx]
}

const matrixRunsPerCell = 10

// runCellRepeated runs runProfile runs times with distinct seeds and
// returns the raw per-run results plus aggregated wrong-live% and
// unresolved%.
func runCellRepeated(t *testing.T, p matrixProfile, stage int, delay time.Duration, fallbackEnabled bool, baseSeed int64, runs int) ([]runResult, aggregate, aggregate) {
	t.Helper()
	results := make([]runResult, runs)
	wrongLivePct := make([]float64, runs)
	unresolvedPct := make([]float64, runs)
	for i := 0; i < runs; i++ {
		seed := baseSeed + int64(i)
		r := runProfile(p, stage, delay, fallbackEnabled, seed)
		results[i] = r
		wrongLivePct[i] = 100 * float64(r.wrongStale+r.wrongLive) / float64(r.total)
		unresolvedPct[i] = 100 * float64(r.unresolved) / float64(r.total)
	}
	return results, aggregatePercent(wrongLivePct), aggregatePercent(unresolvedPct)
}

func writeCSV(t *testing.T, name string, runs map[string][]runResult) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "tailmesh-attribution-matrix")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("csv: mkdir failed: %v", err)
		return
	}
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Logf("csv: create failed: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, "cell,seed,total,correct,unresolved,wrong_stale,wrong_live")
	for cell, rs := range runs {
		for _, r := range rs {
			fmt.Fprintf(f, "%s,%d,%d,%d,%d,%d,%d\n", cell, r.seed, r.total, r.correct, r.unresolved, r.wrongStale, r.wrongLive)
		}
	}
	t.Logf("raw per-run counts written to %s", path)
}

// ---------------------------------------------------------------------------
// 1. Profile matrix: 3 profiles x 3 stages x 10 seeded runs, raw + aggregate
// ---------------------------------------------------------------------------

func TestAttributionMatrixProfiles(t *testing.T) {
	allRuns := make(map[string][]runResult)
	t.Log("cell                              | wrong-live% (mean/median/min/max/sd) | unresolved% (mean/median/min/max/sd)")
	for _, p := range matrixProfiles {
		for _, stage := range []int{1, 2, 3} {
			cell := fmt.Sprintf("%s/stage%d", p.name, stage)
			runs, wrongAgg, unkAgg := runCellRepeated(t, p, stage, 500*time.Microsecond, true, int64(len(cell))*7919, matrixRunsPerCell)
			allRuns[cell] = runs
			t.Logf("%-33s | %5.2f / %5.2f / %5.2f / %5.2f / %5.2f      | %5.2f / %5.2f / %5.2f / %5.2f / %5.2f",
				cell,
				wrongAgg.mean, wrongAgg.median, wrongAgg.min, wrongAgg.max, wrongAgg.stddev,
				unkAgg.mean, unkAgg.median, unkAgg.min, unkAgg.max, unkAgg.stddev)
			// One raw sample line per cell, per the "don't only report
			// averages" instruction - the full set goes to the CSV.
			r0 := runs[0]
			t.Logf("  sample run: seed=%d flows=%d correct=%d unresolved=%d wrong_stale=%d wrong_live=%d",
				r0.seed, r0.total, r0.correct, r0.unresolved, r0.wrongStale, r0.wrongLive)
		}
	}
	writeCSV(t, "profile_matrix.csv", allRuns)
}

// ---------------------------------------------------------------------------
// 2. Attribution-delay sweep, stage 3 only, B1 profile - tests the causal
//    claim directly: does error track how long attribution takes to run?
// ---------------------------------------------------------------------------

func TestAttributionMatrixDelaySweep(t *testing.T) {
	delays := []time.Duration{
		0, 50 * time.Microsecond, 100 * time.Microsecond, 250 * time.Microsecond,
		500 * time.Microsecond, 1 * time.Millisecond, 2 * time.Millisecond,
		5 * time.Millisecond, 10 * time.Millisecond,
	}
	p := matrixProfiles[1]
	p.flowsPerApp = 200
	allRuns := make(map[string][]runResult)
	t.Log("delay      | wrong-live% (mean/sd) | unresolved% (mean/sd)")
	for _, d := range delays {
		cell := fmt.Sprintf("delay_%s", d)
		runs, wrongAgg, unkAgg := runCellRepeated(t, p, 3, d, true, int64(d)+13, matrixRunsPerCell)
		allRuns[cell] = runs
		t.Logf("%-10s | %5.2f / %5.2f          | %5.2f / %5.2f", d, wrongAgg.mean, wrongAgg.stddev, unkAgg.mean, unkAgg.stddev)
	}
	writeCSV(t, "delay_sweep.csv", allRuns)
}

// ---------------------------------------------------------------------------
// 3. Port-pool sweep, stage 2 (positive control) vs stage 3, fixed delay -
//    tests whether error genuinely tracks reuse pressure.
// ---------------------------------------------------------------------------

func TestAttributionMatrixPortPoolSweep(t *testing.T) {
	pools := []int32{16, 32, 64, 128, 256, 512, 1024, 4096, 8192}
	base := matrixProfiles[1] // B1_moderate, apps/flows held constant
	base.flowsPerApp = 300
	allRuns := make(map[string][]runResult)
	t.Log("pool   | stage2 wrong-live% (mean/sd) | stage3 wrong-live% (mean/sd)")
	for _, pool := range pools {
		p := base
		p.portPool = pool
		cell2 := fmt.Sprintf("pool_%d_stage2", pool)
		cell3 := fmt.Sprintf("pool_%d_stage3", pool)
		runs2, wrong2, _ := runCellRepeated(t, p, 2, 500*time.Microsecond, true, int64(pool)*3+1, matrixRunsPerCell)
		runs3, wrong3, _ := runCellRepeated(t, p, 3, 500*time.Microsecond, true, int64(pool)*3+2, matrixRunsPerCell)
		allRuns[cell2] = runs2
		allRuns[cell3] = runs3
		t.Logf("%-6d | %5.2f / %5.2f                  | %5.2f / %5.2f", pool, wrong2.mean, wrong2.stddev, wrong3.mean, wrong3.stddev)
	}
	writeCSV(t, "port_pool_sweep.csv", allRuns)
}

// ---------------------------------------------------------------------------
// 3b. Source-IP diversity sweep. Every profile and sweep above (and the
//     original single-run measurement before this file existed) hardcoded
//     one shared source IP for every flow, every app - challenged directly:
//     Android's real getConnectionOwnerUid, and matrixResolver.ResolveUID
//     here, key on the full local socket address, not port alone, so two
//     flows "reusing the same port" on genuinely different source IPs don't
//     collide at all in the real live table. Whether that matters in
//     practice depends on whether real devices actually present multiple
//     source IPs to concurrent flows: the common case (all apps on one
//     Wi-Fi/cellular connection, plain IPv4) is a single shared local IP -
//     which is exactly what every other test in this file already models,
//     not a worst-case artifact of the simulation. Diversity shows up
//     mainly under IPv6 privacy/temporary addressing (RFC 4941) or
//     multi-network apps genuinely split across Wi-Fi and cellular at once.
//     This sweep brackets both ends rather than assuming one: srcIPPool=1
//     reproduces every earlier result unchanged (a regression check on its
//     own), and larger pools show how much diversity would have to exist
//     before it meaningfully changes the picture.
// ---------------------------------------------------------------------------

func TestAttributionMatrixSourceIPSweep(t *testing.T) {
	ipPools := []int{1, 2, 4, 8, 16, 64}
	base := matrixProfiles[2] // C2_heavy_reuse: where port contention alone is worst, so where IP diversity should matter most if it matters at all
	base.flowsPerApp = 300
	allRuns := make(map[string][]runResult)
	t.Log("srcIPs | stage2 wrong-live% (mean/sd) | stage3 wrong-live% (mean/sd)")
	for _, n := range ipPools {
		p := base
		p.srcIPPool = n
		cell2 := fmt.Sprintf("srcip_%d_stage2", n)
		cell3 := fmt.Sprintf("srcip_%d_stage3", n)
		runs2, wrong2, _ := runCellRepeated(t, p, 2, 500*time.Microsecond, true, int64(n)*97+1, matrixRunsPerCell)
		runs3, wrong3, _ := runCellRepeated(t, p, 3, 500*time.Microsecond, true, int64(n)*97+2, matrixRunsPerCell)
		allRuns[cell2] = runs2
		allRuns[cell3] = runs3
		t.Logf("%-6d | %5.2f / %5.2f                  | %5.2f / %5.2f", n, wrong2.mean, wrong2.stddev, wrong3.mean, wrong3.stddev)
	}
	writeCSV(t, "source_ip_sweep.csv", allRuns)
}

// TestAttributionMatrixRealisticPortRange asks the actual question behind
// the port-pool and source-IP sweeps, directly, instead of extrapolating
// from the pool sizes those swept: at Linux/Android's real default
// ephemeral port range (net.ipv4.ip_local_port_range, 32768-60999 =
// 28,232 ports - not independently confirmed for Android/AOSP specifically,
// but the Linux default this almost certainly inherits) and a realistic
// number of concurrently-active source IPs, what does the mechanism
// actually show? Two points, not a sweep: srcIPPool=1 (the common case - a
// single network, IPv4, no per-socket IP randomization - see the
// discussion this responds to) and srcIPPool=2 (the IPv6 case: privacy
// addresses rotate roughly daily with a brief overlap where at most two are
// concurrently valid, not "many" - RFC 4941).
func TestAttributionMatrixRealisticPortRange(t *testing.T) {
	const realisticPortRange = 28232
	base := matrixProfiles[2] // C2_heavy_reuse: 8 apps, the contention side of things
	base.portPool = realisticPortRange
	base.flowsPerApp = 300
	allRuns := make(map[string][]runResult)
	t.Log("srcIPs | stage2 wrong-live% (mean/sd) | stage3 wrong-live% (mean/sd)")
	for _, n := range []int{1, 2} {
		p := base
		p.srcIPPool = n
		cell2 := fmt.Sprintf("realistic_srcip_%d_stage2", n)
		cell3 := fmt.Sprintf("realistic_srcip_%d_stage3", n)
		runs2, wrong2, _ := runCellRepeated(t, p, 2, 500*time.Microsecond, true, int64(n)*577+1, matrixRunsPerCell)
		runs3, wrong3, _ := runCellRepeated(t, p, 3, 500*time.Microsecond, true, int64(n)*577+2, matrixRunsPerCell)
		allRuns[cell2] = runs2
		allRuns[cell3] = runs3
		t.Logf("%-6d | %5.2f / %5.2f                  | %5.2f / %5.2f", n, wrong2.mean, wrong2.stddev, wrong3.mean, wrong3.stddev)
	}
	writeCSV(t, "realistic_port_range.csv", allRuns)
}

// ---------------------------------------------------------------------------
// 4. Exact-only vs exact+UDP-fallback A/B, stage 3, two profiles.
// ---------------------------------------------------------------------------

func TestAttributionMatrixFallbackAB(t *testing.T) {
	allRuns := make(map[string][]runResult)
	t.Log("profile              | mode         | wrong-live% (mean/sd) | unresolved% (mean/sd)")
	for _, p := range []matrixProfile{matrixProfiles[1], matrixProfiles[2]} { // B1, C2
		for _, mode := range []struct {
			name    string
			enabled bool
		}{{"exact+fallback", true}, {"exact-only", false}} {
			cell := fmt.Sprintf("%s/%s", p.name, mode.name)
			runs, wrongAgg, unkAgg := runCellRepeated(t, p, 3, 500*time.Microsecond, mode.enabled, int64(len(cell))*911, matrixRunsPerCell)
			allRuns[cell] = runs
			t.Logf("%-21s | %-12s | %5.2f / %5.2f          | %5.2f / %5.2f",
				p.name, mode.name, wrongAgg.mean, wrongAgg.stddev, unkAgg.mean, unkAgg.stddev)
		}
	}
	writeCSV(t, "fallback_ab.csv", allRuns)
}

// ---------------------------------------------------------------------------
// 5. Lookup latency percentiles, B1/stage3, reported alongside error rates.
// ---------------------------------------------------------------------------

func TestAttributionMatrixLatencyPercentiles(t *testing.T) {
	p := matrixProfiles[1]
	r := runProfile(p, 3, 500*time.Microsecond, true, 42)
	sorted := append([]int64(nil), r.lookupNanos...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	toMicros := func(ns int64) float64 { return float64(ns) / 1000 }
	t.Logf("B1/stage3 lookup latency (us): p50=%.1f p95=%.1f p99=%.1f max=%.1f (n=%d)",
		toMicros(percentile(sorted, 0.50)), toMicros(percentile(sorted, 0.95)), toMicros(percentile(sorted, 0.99)),
		toMicros(sorted[len(sorted)-1]), len(sorted))
}

// ---------------------------------------------------------------------------
// 6. TCP: does the "TCP doesn't really have this problem" claim hold up
//    against the real production code, or is it just an assumption? This
//    was never measured until directly asked - every other test in this
//    file, and the original single-run measurement before it, is UDP-only.
// ---------------------------------------------------------------------------

func TestAttributionMatrixTCPProfiles(t *testing.T) {
	allRuns := make(map[string][]runResult)
	t.Log("cell                              | wrong-live% (mean/median/min/max/sd) | unresolved% (mean/median/min/max/sd)")
	for _, p := range matrixProfilesTCP {
		for _, stage := range []int{1, 2, 3} {
			cell := fmt.Sprintf("%s/stage%d", p.name, stage)
			runs, wrongAgg, unkAgg := runCellRepeated(t, p, stage, 500*time.Microsecond, true, int64(len(cell))*104729, matrixRunsPerCell)
			allRuns[cell] = runs
			t.Logf("%-33s | %5.2f / %5.2f / %5.2f / %5.2f / %5.2f      | %5.2f / %5.2f / %5.2f / %5.2f / %5.2f",
				cell,
				wrongAgg.mean, wrongAgg.median, wrongAgg.min, wrongAgg.max, wrongAgg.stddev,
				unkAgg.mean, unkAgg.median, unkAgg.min, unkAgg.max, unkAgg.stddev)
			r0 := runs[0]
			t.Logf("  sample run: seed=%d flows=%d correct=%d unresolved=%d wrong_stale=%d wrong_live=%d",
				r0.seed, r0.total, r0.correct, r0.unresolved, r0.wrongStale, r0.wrongLive)
		}
	}
	writeCSV(t, "tcp_profile_matrix.csv", allRuns)
}

// TestAttributionMatrixTCPvsUDPDelaySweep runs the identical delay sweep as
// TestAttributionMatrixDelaySweep, but on the moderate-contention TCP
// profile instead of UDP's - same causal question (does error track how
// much time attribution gets to run), asked of TCP specifically instead of
// assumed to transfer over from the UDP result.
func TestAttributionMatrixTCPDelaySweep(t *testing.T) {
	delays := []time.Duration{
		0, 50 * time.Microsecond, 100 * time.Microsecond, 250 * time.Microsecond,
		500 * time.Microsecond, 1 * time.Millisecond, 2 * time.Millisecond,
		5 * time.Millisecond, 10 * time.Millisecond,
	}
	p := matrixProfilesTCP[1] // T2_tcp_moderate
	p.flowsPerApp = 100
	allRuns := make(map[string][]runResult)
	t.Log("delay      | wrong-live% (mean/sd) | unresolved% (mean/sd)")
	for _, d := range delays {
		cell := fmt.Sprintf("tcp_delay_%s", d)
		runs, wrongAgg, unkAgg := runCellRepeated(t, p, 3, d, true, int64(d)+29, matrixRunsPerCell)
		allRuns[cell] = runs
		t.Logf("%-10s | %5.2f / %5.2f          | %5.2f / %5.2f", d, wrongAgg.mean, wrongAgg.stddev, unkAgg.mean, unkAgg.stddev)
	}
	writeCSV(t, "tcp_delay_sweep.csv", allRuns)
}

// TestAttributionMatrixWrongAnswersAreRaces directly answers the question
// "do these percentages represent actual misattribution caused by racing,
// or could they be some other artifact of the simulation" - by construction
// of simPortTable, a query can only ever return a UID that some claim()
// call actually wrote to that exact (srcIP, srcPort) key; there is no other
// source of "wrong" answers available to the code. So every wrong_stale/
// wrong_live flow must trace back to a real cross-app collision on the
// identical key (simPortTable.crossAppClaims). This doesn't just assert
// that structural fact - it measures both counters from the same run and
// checks the bound holds.
func TestAttributionMatrixWrongAnswersAreRaces(t *testing.T) {
	p := matrixProfiles[2] // C2_heavy_reuse: most collisions, easiest to see the correlation clearly
	p.flowsPerApp = 500
	for _, stage := range []int{1, 2, 3} {
		r := runProfile(p, stage, 500*time.Microsecond, true, 909090+int64(stage))
		wrong := r.wrongStale + r.wrongLive
		t.Logf("stage %d: flows=%d cross-app key collisions=%d wrong-stale=%d wrong-live=%d (wrong-total=%d)",
			stage, r.total, r.crossAppClaims, r.wrongStale, r.wrongLive, wrong)
		if int64(wrong) > r.crossAppClaims {
			t.Fatalf("stage %d: %d wrong answers but only %d cross-app key collisions occurred - a wrong answer happened with no colliding claim to explain it, which should be structurally impossible in simPortTable", stage, wrong, r.crossAppClaims)
		}
		if wrong > 0 && r.crossAppClaims == 0 {
			t.Fatalf("stage %d: %d wrong answers reported but zero collisions recorded - contradicts the claim that wrong answers require a collision", stage, wrong)
		}
	}
}
