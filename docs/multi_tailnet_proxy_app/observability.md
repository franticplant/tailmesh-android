**Multi-Tailnet Observability — Architecture**

This document describes the observability system added to MULTIPROXY: what it measures, where each measurement is taken, what it costs, and — critically — which numbers are exact, which are estimates, and which are not available at all. See `architecture.md` for the surrounding data path this instruments.

## 1. Design constraint

The dataplane's hot path (per-packet TUN read/write, per-flow byte pump) must not be measurably slower because of this feature. Concretely, nothing in the hot path may: allocate, format a string, resolve a package name, call an Android system service, read the wall clock unnecessarily, or take a lock beyond a plain atomic add. Everything more expensive than an atomic counter update happens off the hot path, at a bounded, low frequency.

```text
dataplane (TUN read/write, flow byte pump)
        |  atomic counter updates only
        v
per-flow / per-UID / per-upstream counters (stats.go, observability.go)
        |  periodic snapshot (default 60s background, 1s while diagnostics UI open)
        v
observability sampler (Go, observability.go: samplerLoop)
        |  JSON snapshot over the gomobile boundary
        v
MultiProxySessionCoordinator (Kotlin poll job)
        |
        +--> in-memory StateFlow (live UI)
        +--> ObservabilityDatabaseHelper (bounded SQLite: samples + events)
```

Nothing routes through the database on the hot path. Hot-path code only ever touches counters; only the background sampler and event-dispatch paths touch the database or the UI's StateFlows.

## 2. Always-on metrics (production, no opt-in)

### Process / runtime (`observability.go: ProcessSample`)
- **CPU seconds** — exact. Parsed from `/proc/self/stat` (`utime+stime`), real kernel accounting, not wall-clock handler duration.
- **CPU percent**, **CPU-seconds-per-GiB** — derived. Computed from the CPU-seconds delta and the sampler's own interval, or from bytes processed. Explicitly *not* the same as "processing time" (see §5).
- **Go heap alloc/sys, GC count/pause, goroutine count** — exact, from `runtime.ReadMemStats`/`runtime.NumGoroutine`, read only once per sampler tick (not per packet).
- **Engine / VPN uptime** — exact, timestamp arithmetic.

### Dataplane (`observability.go: dataplaneCounters`, `tun_interceptor.go`)
- TUN RX/TX bytes and packets — exact, one atomic add per packet at the existing `gvisor.dev/gvisor` `stack.LinkEndpoint`/`NetworkDispatcher` wrap point (`countingLinkEndpoint`/`countingDispatcher`). No allocation, no per-packet logging.
- DNS queries/failures — exact, incremented once per completed query at `dns.go`'s existing `ServeDNSUDP`/`ServeDNSTCP` completion points.
- VPN restarts — exact, incremented on `StartVPN` when a previous start timestamp is already set.

### Per-upstream / per-Tailnet (`stats.go`)
- Dial attempts/successes/failures, not-ready count, byte counters, last latency/error — exact; this is the pre-existing `UpstreamStats`/`statsRegistry`, extended (not replaced) with TCP/UDP flow counts (`tcpFlowsTotal`, `udpFlowsTotal`, `activeTCP`, `activeUDP`).
- A broken/unhealthy Tailnet does not stop metric collection for others: each upstream has its own `UpstreamStats`, and `GetTailnetStatesJSON` fans out one goroutine per tailnet with a 2s timeout per call, so one stuck tailnet cannot block another's status read.

### Per-app (UID) (`observability.go: uidStats`/`uidRegistry`)
- Bytes in/out, TCP/UDP flow counts, last upstream used — exact. UID is resolved once per flow (at the existing `flowFromEndpointID`/`resolveFlow` call in `nat_router.go`, which already does this resolution for routing), never per packet, and reused for the lifetime of that flow.
- **Not measured**: per-app CPU cost, per-app battery/energy use. The dataplane processes all UIDs' packets through the same gVisor stack and goroutines; attributing CPU time to a specific UID's traffic would require per-packet timing (an explicitly forbidden hot-path cost) and would still be an estimate, not a measurement. This is intentionally left unavailable rather than fabricated.

### Path / exit-node (`observability.go: pathState`/`noteExitNodePath`, `runtime_state.go`)
- Direct vs. DERP, DERP region, exit-node connect/disconnect — derived from the peer entry already returned by the existing 1s `GetTailnetStatesJSON` poll (which already calls `tsnet`'s `LocalClient().Status(ctx)` per tailnet); no new polling was added.
- Transitions are deduplicated: an event fires only when the *previous known* state differs from the new one (`changed := wasKnown && wasDirect != direct`). The very first observation after a tailnet/exit-node becomes active is represented once, as a connect event, not as a spurious transition.

### Network source (`NetworkChangeCallback.kt`)
- Wi-Fi/cellular/ethernet/VPN/other, default-network transitions — event-driven, from the existing `ConnectivityManager.NetworkCallback` singleton (`recomputeDefaultNetworkLocked`), not polled. Deduplicated the same way as path transitions: an event fires only when the resolved network-source label actually changes.

## 3. Storage (`ObservabilityDatabaseHelper.kt`)

Plain `SQLiteOpenHelper` (matching the project's existing convention — see `TailnetDatabaseHelper.kt`; no Room dependency was introduced, since two bounded tables with a handful of columns don't justify one).

- `samples`: one row per sampler tick (CPU%, CPU-seconds, heap, goroutines, TUN RX/TX bytes, DNS failures). Kept at full (sampler) resolution for 6h, downsampled to one row per 15-minute bucket beyond that, dropped entirely beyond 7 days.
- `events`: discrete lifecycle events (path transitions, exit-node connect/disconnect, VPN restarts, network-source changes, upstream health changes). Kept for 7 days, hard-capped at 5000 rows regardless of age.

Both bounds are enforced by `prune()`, called from the Kotlin poll loop at most once a minute — cheap indexed `DELETE`s, not a recompute.

## 4. Diagnostics UI (`DiagnosticsView.kt`)

Overview / Tailnets / Apps / Network sections, a 1h/6h/24h/7d range selector reading only the aggregated `samples`/`events` tables, and a dependency-free `Canvas`-based line chart (no charting library — the data is already bounded to at most a few thousand points even at 7-day/15-minute resolution, so a handful of `drawLine` calls is cheaper and simpler than a general-purpose charting dependency). Event markers are overlaid on the CPU graph from the same bounded event list — not every event, to avoid clutter.

Sampling cadence is visibility-driven: `MultiProxySessionCoordinator.setDiagnosticsUiVisible(true/false)` switches both the Kotlin poll interval and the Go-side sampler interval (`SetObservabilitySampleIntervalSeconds`) between ~1s while the screen is open and 60s in the background. No 1-second timer runs while the screen is closed.

A "Telemetry: Standard / Advanced" label reflects `AdvancedDiagnosticsEnabled()`.

## 5. Advanced diagnostics (opt-in, off by default)

Toggled via `SetAdvancedDiagnostics(bool)`. Off by default; when off, nothing beyond the always-on metrics above runs — no continuous profiler, no trace collection, no per-component timers.

When on, three explicit, user-triggered, bounded captures are available, each writing to a local file (never an HTTP listener — `net/http/pprof` is never imported or served in this codebase):
- `CaptureCPUProfileToFile(path, durationSeconds)` — `runtime/pprof` CPU profile, bounded duration (UI offers 30s).
- `CaptureHeapProfileToFile(path)` — one-shot heap profile.
- `CaptureGoroutineDumpToFile(path)` — one-shot goroutine stack dump.

No component in this codebase reports a wall-clock "Processing time" as "CPU time." If a future addition wants to show per-component timing, it must either be real CPU-profiling-derived data (labeled "Profiled CPU share") or explicitly labeled "Processing time" — never presented as CPU cost.

## 6. Exact vs. estimated vs. unavailable — summary

| Metric | Status |
|---|---|
| Process CPU seconds | Exact (`/proc/self/stat`) |
| CPU % / CPU-seconds-per-GiB | Derived from exact CPU seconds + interval/bytes |
| Go heap / GC / goroutines | Exact (`runtime` package) |
| TUN RX/TX bytes/packets | Exact (atomic counters at the link-endpoint wrap point) |
| DNS query/failure counts | Exact |
| Per-upstream dial stats, byte counters | Exact |
| Per-app (UID) bytes/flows | Exact |
| Per-app CPU cost | **Unavailable** — not measured, not estimated |
| Per-app battery/energy | **Unavailable** — not claimed |
| Direct/DERP path, DERP region | Exact, from existing tsnet status |
| Exit-node connect/disconnect | Exact, derived from same status |
| Network source (Wi-Fi/cellular/...) | Exact, from `ConnectivityManager` |
| Advanced: CPU/heap profiles | Exact (`runtime/pprof`), but only while explicitly captured |

## 7. Performance findings

- Hot-path additions are one atomic add per packet (TUN RX/TX) and one atomic add per DNS query/flow open-close — no allocation, no locks beyond the atomic itself, verified by code review of `tun_interceptor.go`'s `countingLinkEndpoint`/`countingDispatcher` and `nat_router.go`'s flow accounting.
- The Go test suite (`go test ./libtailscale/multiproxy/...`) passes, including new tests asserting counter correctness, per-UID isolation, and event deduplication (`observability_test.go`).
- The periodic sampler (`/proc/self/stat` read + `runtime.ReadMemStats`) runs at most once per second, only while the diagnostics screen is open; 60s otherwise. `ReadMemStats` briefly stops the world in old Go runtimes, but is O(heap objects tracked), not O(traffic), and is called at most once/second — an existing, well-understood cost, not new to this design.
- No unbounded growth: both SQLite tables are pruned on a bounded schedule with hard caps independent of age (`EVENT_MAX_ROWS`), so a pathological flapping condition cannot grow storage without limit between prune calls.
- No load/soak benchmark harness exists in this repo for the dataplane, so the above is verified by code-path review and unit tests rather than a measured throughput comparison; see `validation_and_gaps.md` for the standing gap this shares with the rest of MULTIPROXY's performance claims.

## 8. DNS attribution and fail-closed routing (added after initial ship)

Device testing after the first pass of this feature surfaced a real leak: `Policy.Match`/`Selector.matches` treats an unattributed flow (`AppUID == UnknownAppUID`) as only able to satisfy a UID-*unscoped* rule - by design, so a failed lookup can only widen what matches, never narrow it (`policy.go`'s own doc comment). The problem is this is not scoped to genuinely-unbound apps: it's the same code path an app *with* an explicit per-app route hits whenever `resolveAppUID`'s `getConnectionOwnerUid` call flakes (a real, expected failure mode - short-lived UDP sockets in particular can already be closed by the time the lookup runs). That app's traffic then silently falls through to the default/direct rule instead of the route the user configured - a leak, not a bug in the fallback logic itself.

This affects both DNS (`dns_policy.go`) and general data-plane routing (`nat_router.go`) identically, since both go through the same `Policy.Match`. Blanket fail-closed (refuse every unattributed flow whenever any per-app rule exists) was considered and rejected: it would also catch every genuinely-unbound app's traffic on the same device any time attribution has a transient hiccup, since there's no way to distinguish "this flow's app has no rule" from "this flow's app has a rule but we couldn't find out which UID it is" without the UID itself. That trade was judged worse than the leak it would close - see `validation_and_gaps.md` for the fuller writeup if one exists at time of reading.

What shipped instead, scoped narrowly:

- **`resolveAppUID` retries** (`uid.go`): up to `uidResolveMaxAttempts` (2) attempts, each bounded by `uidResolveAttemptTimeout` (90ms), instead of one 150ms attempt - cuts the transient-failure rate before it ever reaches a fallback decision, at a modest (~30ms worst case) increase to new-flow latency, paid once per flow, never per packet.
- **DNS fails closed** (`dns.go`, in `handleDNSMsg`): when a query's flow is unattributed (`AppUID == UnknownAppUID`) *and* the active policy has at least one UID-scoped rule, the query is refused (`SERVFAIL`) rather than silently using the default/direct route. Scoped to DNS specifically because a refused lookup is cheap and recoverable (the OS resolver or app retries, or the user sees "can't find site") - unlike dropping an already-established data connection, which is why general data-plane routing was *not* changed the same way.
- **Violation tracking regardless of the above** (`dataplaneCounters.attributionFailures` / `.dnsAttributionFailClosed`, exposed in `DataplaneSnapshot` as `attributionFailures`/`dnsAttributionFailClosed`): every flow where a UID-scoped rule exists but attribution failed is counted, whether or not that particular query then failed closed. This is what would inform tightening general data-plane routing the same way later - real numbers instead of a guess.

Both counters are exact (real per-flow events, atomic counters, no sampling), visible in the Diagnostics screen's Overview section and in `GetObservabilitySnapshotJSON`.

## 9. Known limitations

- **General (non-DNS) data-plane routing does not fail closed.** An app with an explicit per-app route can still have ordinary TCP/UDP traffic (not just DNS) fall through to the default/direct rule if `resolveAppUID` fails after retries - see §9. `attributionFailures` tracks how often this ambiguity occurs; whether to extend fail-closed to the data plane too is an open decision pending those numbers.
- **Peer relay is not distinguished from "neither direct nor DERP."** The vendored engine (`wgengine/magicsock/relaymanager.go`) supports a third connectivity tier - a control-plane-supplied peer acting as a UDP relay, used when direct NAT traversal fails and DERP would be worse - exposed as `ipnstate.PeerStatus.PeerRelay` (distinct from `CurAddr`/direct and `Relay`/DERP). `runtime_state.go`'s `pathInfo`/`observedTailnetState` currently reads only `CurAddr` and `Relay`, so a peer connected via peer relay shows as `direct=false, derpRegion=""` - silently uncategorized rather than mislabeled, but not surfaced as its own state in the Diagnostics screen. Fixing this is a small, contained addition (read `PeerRelay`, add a third `pathState` value and transition event) - deferred, not implemented this pass.

- Per-app CPU/battery attribution is not available (see §2, §6) — by design, not as an oversight.
- The `samples` table's 15-minute downsample keeps the *last* observed sample per bucket rather than an average; this is cheap (a `DELETE`, not a recompute) and adequate for "what happened around here" at that zoom level, but is not a true statistical aggregate.
- Advanced-diagnostics captures are files written to the app's cache directory; there is no export/share UI wired up yet — the file path is only shown as text in the Diagnostics screen.
- No on-device throughput benchmark was run as part of this change; overhead claims rest on the hot-path code review and the atomic-only instrumentation pattern already established elsewhere in this codebase (`stats.go`).
