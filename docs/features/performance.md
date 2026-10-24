# Performance and battery

Tailmesh runs all day in VPN mode with several tailnets, so what it costs while nothing is
happening matters more than peak throughput. This page says how to measure that cost, lists every
periodic job in the app, and records measurements.

## Measuring

`perf.stats` (remote control, read-only) returns the process's own cost, read on demand from
`/proc` and the Go runtime. Nothing in it runs between calls; a periodic job pays one atomic add per
run for its counter.

| Field | What it is |
|---|---|
| `cpuSeconds`, `userCpuSeconds`, `sysCpuSeconds` | Process CPU time since start (`/proc/self/stat`) |
| `processUptimeSeconds`, `cpuSecondsPerHour` | Since the process started; the average rate |
| `voluntarySwitches` | Summed over threads: how often a thread slept and was woken. The closest thing to "wakeups" an app can read about itself |
| `topThreads`, `threadsByName` | CPU time and switches per thread. Go's threads are named `Thread-N` or after the process (`.ipn.multiproxy`); Kotlin coroutines run on `DefaultDispatch` |
| `rssBytes`, `pssBytes`, `javaHeapUsedBytes` | Memory |
| `go` | `runtime/metrics`: live heap, heap goal, GC cycles, goroutines, cgo calls |
| `jobs`, `kotlinJobs` | How many times each periodic job has run (table below) |
| `screenOn`, `runtimeMode` | Context for the reading |

Compare two readings for a rate. `tailmesh-ctl profile` gives Go CPU, heap and goroutine profiles
and an execution trace (`-kind trace`), which shows what wakes goroutines.

```sh
tailmesh-ctl call perf.stats top=10
tailmesh-ctl profile -seconds 60 -o cpu.pprof && go tool pprof -top cpu.pprof
tailmesh-ctl profile -kind trace -seconds 5 -o trace.out
```

Battery: `dumpsys batterystats` would show wakelocks, radio wakeups and the app's estimated drain,
but needs adb, which needs USB debugging enabled for the phone's user and this laptop authorised on
the phone.

## Periodic jobs

"Screen off" says whether the job keeps running with the screen off; "No UI" whether it runs when no
Tailmesh screen is visible. Counter names are the `jobs` / `kotlinJobs` keys in `perf.stats`.

### App (Kotlin)

| Job | Where | Interval | Screen off | No UI | Counter |
|---|---|---|---|---|---|
| Multi-Tailnet state poll: tailnet and exit-node states, subnet routes, upstream stats (four JNI calls returning JSON) | `MultiProxySessionCoordinator.bind` | 1 s | yes | yes | `kt.statePoll` |
| Observability snapshot (and its SQLite samples) | `MultiProxySessionCoordinator.bind` | 60 s, 1 s while Diagnostics is open | yes | yes | `kt.observabilityPoll` |
| Multi-Tailnet notification rebuild | `IPNService.startMultiProxyNotificationRefresh` | 30 s | yes | yes | `kt.notificationRefresh` |
| Speed meter (when turned on) | `SpeedMeterService.run` | 1 s screen on, 5 s screen off | yes (5 s) | yes | `kt.speedMeterTick` |
| Peer list for the Multi-Tailnet screen | `MultiProxyViewModel` | 2 s | while the activity lives | while the activity lives | `kt.ui.peersPoll` |
| Diagnostics charts, expanded rows | `DiagnosticsView` | 2 s | — | no | `kt.ui.diagnosticsPoll`, `kt.ui.diagnosticsRowPoll` |
| Logs screen | `LogsView` | 1 s (app log), 2 s (access, shell) | — | no | `kt.ui.logsPoll` |
| Packet capture stats | `PacketCaptureView` | 3 s while capturing | — | no | — |

### Engine (Go, `libtailscale`)

| Job | Where | Interval | Counter |
|---|---|---|---|
| Tailnet status poll, per tailnet: full `Status()` with every peer, VIP services, peer paths, subnet routes | `multiproxy/api.go pollTailnetStatus` | 10 s | `go.tailnetStatusPoll` |
| Observability sampler: CPU time, `ReadMemStats`, goroutines | `multiproxy/observability.go samplerLoop` | 60 s, 1 s while Diagnostics is open | `go.observabilitySample` |
| Remote control janitor: expire sessions and approvals | `remotectl janitor` | 15 s, only while remote control runs | `go.remoteJanitor` |
| Log ring: every log line kept for remote control and the Logs screen | `remotectl/logbuf.go` | per line | `go.logRingLines` |

The Kotlin state poll's calls also run Go code: `GetTailnetStatesJSON` makes one
`StatusWithoutPeers` LocalAPI call per tailnet (over an in-memory HTTP pipe, JSON both ways), plus a
full `Status()` for a tailnet with an exit node set; `GetExitNodeStatesJSON` one per exit-node
upstream.

### Tailscale core, per tsnet node

Each tailnet, and each exit-node upstream, is its own tsnet node with its own magicsock, DERP
connections, control client and logger. These are upstream Tailscale's, unchanged:

| Job | Interval |
|---|---|
| DERP keepalive on each DERP connection (home region, plus any region a peer is reached through) | 60 s |
| Control long-poll: the server sends keepalives and netmap updates | server-driven, about 1 min |
| magicsock heartbeat per peer with an active session | 3 s, stops 45 s after traffic stops |
| magicsock periodic re-STUN | 20–26 s while traffic flows, stops when idle |
| Port list poll (`feature/portlist`) | ticker per node; polls only if the tailnet collects services |
| logtail upload to `log.tailscale.io` | when there are logs, batched |
| WireGuard keepalive (WireGuard upstreams with `PersistentKeepalive`) | as configured (25 s on the phone's two) |

Official Tailscale on Android runs one such node; Tailmesh in the phone's setup runs three.

## Measurements

### Baseline, 2026-10-24 (dev build of `main` after `a464f53`)

Pixel 8, Multi-Tailnet in VPN mode, three tailnets (Homelab with 113 peers, 32 online), two
WireGuard and two SOCKS5 upstreams, two SOCKS5 listeners, remote control on and polled every 2 min
for the reading. The screen stayed on throughout (the phone is on USB power); no Tailmesh screen was
open and there was no traffic beyond the phone's own background.

Over 32 minutes (16 readings two minutes apart):

| Measure | Value |
|---|---|
| CPU | **305 s per hour** (8.5% of one core): 205 user, 100 system; two-minute windows ranged 260–380 |
| Of which Go-side threads | 255 s/h (Go names its threads `Thread-N` / `.ipn.multiproxy`) |
| Of which Kotlin dispatchers | 46 s/h (`DefaultDispatch`) |
| Voluntary context switches | 235 per second (150 of them on the `.ipn.multiproxy` threads) |
| RSS / PSS | 150–240 MB / 125–145 MB |
| Go live heap / goroutines | 10–13 MB / 570–700 |
| `kt.statePoll` | 3506 per hour (once a second) |
| `go.tailnetStatusPoll` | 1083 per hour (three tailnets, every 10 s) |
| `go.logRingLines` | 1675 per hour |

A 60 s CPU profile (Go's profiler samples every thread, so Java shows up as `libart`/`libc`):

- the 1 s state poll's `GetTailnetStatesJSON` → `StatusWithoutPeers` per tailnet, through the
  LocalAPI's in-memory HTTP and JSON on both ends: about 30% of samples, client and server side
  together;
- the 10 s per-tailnet full `Status()` in `pollTailnetStatus` (113 peers in Homelab), with
  `rebuildTargetsUnlocked`: about 10%;
- JSON encoding and decoding overall: about 25%;
- Java/ART and SQLite: about 15%.

A 5 s execution trace counted about 60 goroutine wakeups a second in Go: mostly the LocalAPI's
in-memory pipes and HTTP client/server goroutines (the polls above), the port-list poll loops and
GC workers.

For comparison, official Tailscale on Android idles at a small fraction of this: it runs one node
and its UI polls nothing while closed. The polls, not the tunnels, dominate here.
