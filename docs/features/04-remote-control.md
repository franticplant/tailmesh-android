# Remote Control and Debugging

Tailmesh can expose an authenticated HTTP API that does everything its own screens can, so the phone
can be operated and debugged from another machine: a laptop on the other end of a USB tether, a
host reaching it over a tailnet, or an agent investigating a failure. It is off by default.

Turn it on under **Settings → Remote control & debugging**.

---

## 1. What it can do

Every button, toggle, selection and addition in the Multi-Tailnet screens, plus the standard-mode
Tailscale client through its LocalAPI:

| Area | Read | Change |
|---|---|---|
| Overview | `app.status` (`mode`: multi-tailnet, standard or off; `vpnInterface`; Multi-Tailnet tailnet counts by state; a one-line `summary`), `perf.stats` (the app's own CPU, wakeups, memory and periodic-job counts; see [performance](performance.md)) | `multitailnet.start` / `stop` / `reconcile`, `standard.connect` / `disconnect`, `vpn.restart` |
| Tailnets | `tailnets.list` (accepted routes and conflicts included), `peers`, `peerPaths` (direct, DERP, peer relay or idle per peer), `states`, `addressConflicts`, `subnetRoutes`, `exitNodeCandidates`, `identities` (every node identity's state directory, owner, stored profiles and live node; leftovers have no owner) | `tailnets.add`, `importRegular`, `setEnabled`, `setAcceptRoutes`, `rename`, `forget`, `setExitNode` |
| Upstreams | `upstreams.list` (secrets redacted), `routable`, `stats` (with `peerPath`: a tailnet's peer summary, an exit node's direct/DERP path, a WireGuard handshake state; WireGuard upstreams also list each peer's endpoint, last handshake, bytes, and handshake attempts, timeouts and the last error), `exitNodeStates` | `upstreams.probe` (see below), `upstreams.saveSocks5`, `saveWireGuard`, `saveExitNode`, `setEnabled`, `delete` |
| Routing | `routing.get`, `directLinks` (direct tailnet connections over cable or hotspot: setting, effective state, IPv6 check) | `routing.setDefaultUpstream`, `setDefaultDNSUpstream`, `setBroadCapture`, `setLanExclusion`, `setDirectLinks` |
| Apps | `apps.list` | `apps.bind`, `unbind`, `setDNSUpstream`, `setTunnelLAN` |
| Listeners | `listeners.socks5.list`, `listeners.inbound.list` (why one is not registered; inbound forward counts and last error) | `…save`, `…setEnabled`, `…delete` for both |
| Device | `device.networks` (Android's networks and routes, and which one a destination would use), `device.traffic` (what the speed meter counts) | |
| Diagnostics | `diagnostics.snapshot`, `events`, `dnsLog`, `routeDecisions`, `exports` | `diagnostics.setDNSQueryLog`, `setAdvanced`, `setSampleInterval`, `reset`, `exportBundle` |
| Packet capture | `capture.status`, `capture.list` | `capture.start` (all / apps / listeners), `capture.stop`, `capture.delete` |
| Settings | `settings.get` | `settings.setPublicDoH`, `settings.setDebugLogging`, `settings.setProxyOnly`, `settings.setSpeedMeter` |
| Standard mode | `tailscale.localapi.get` | `tailscale.localapi.call` (prefs, profiles, exit nodes, login, logout, …) |

`upstreams.probe upstream=<id or @direct> target=host:port [udp=true [reply=true] [payload=hex]]
[timeout=3s]` dials through that upstream from the engine, exactly as an app's connection would, and
reports `ok` or the error with the `stage` it stopped at (lookup, dial, send, reply), the
`remoteAddr` connected to, the `localAddr` (for `@direct`, which network it left on), `connectMs`,
and the `path` where the upstream knows it (a tailnet peer's direct/DERP path, a WireGuard handshake
state). TCP is a connect only; UDP sends one datagram of at most 64 bytes and optionally waits for
one back. The timeout is at most 15 s. It takes control (it sends traffic) and is not counted in the
upstream's stats.

`GET /v1/methods` returns the live catalog, with each method's parameters and whether it changes
state. A call with an argument the method does not take is refused, with the accepted ones listed,
rather than run with a default. Beyond the catalog:

- `GET /v1/status` (`tailmesh-ctl status`) — the session, and the server's health: uptime,
  requests served, client and server errors, requests in flight, latency of the last 64 quick
  requests (p50, p95, max), the slowest recent one, the last error, and how long until remote
  control turns itself off. Counted per request; nothing runs in between.
- `GET /v1/logs` — app and Go engine logs, and with `follow=1` a live stream. Filters: `since` (a
  sequence number, a duration such as `10m`, or an RFC 3339 time), `level` (`error`, `warn`,
  `info`, `debug`, `verbose`: that level and more severe), `component` (comma-separated prefixes:
  an app log tag, or `flow`, `wireguard`, `magicsock`, `control`, …) and `grep`. Each line carries
  its `level` and `component`. App lines have their real level; Go's logger has none, so a Go
  line counts as `error` when it mentions an error or failure and `info` otherwise. The methods
  `logs.clear` empties the buffer, and `logs.mute components=flow,wireguard` keeps noisy
  components out of it until the app restarts (`logs.muted` lists them; logcat is unaffected).
- `GET /v1/files?path=` — download a capture or a diagnostics export.
- `/debug/pprof/*` — Go CPU, heap, goroutine, allocation, block, mutex profiles and traces, for the
  whole process.
- `GET /v1/access-log` — the access log (read-only).
- `POST /v1/app/update` — development builds only: upload an APK (the raw request body) for the app
  to install over itself; see [Updating the app](#updating-the-app).
- `/v1/shell/*` — development builds only: run shell commands as the app, each shell approved on the
  phone; see [Remote shell](#remote-shell).

### Updating the app

**Development builds only.** The APKs CI builds for each push to `main` (named `tailmesh-dev-…`,
version name ending in `-dev`) have this; releases and pre-releases have neither the feature nor
the install permissions. `scripts/check-release-apk.sh` checks that on every release APK before it is
published, and on a release-configuration build in CI for every push. A dev build is signed with the release key, so installing a later release
over it keeps the app's data (Android simply drops the install permission).

`tailmesh-ctl update tailmesh-dev-….apk` installs a newer build without anyone touching the phone.
It needs a session with control **and** two switches on the phone, both off until the user turns
them on: **Allow remote updates** on the Remote control screen, and Android's **Install unknown apps**
for Tailmesh (turning on the first opens the second).

Before installing, the app refuses an APK that is another package, signed with another key, or an
older version (a lower `versionCode`). Android would refuse the first two too; the only way past any
of them is an uninstall, which wipes the app's data, so the update says why instead. A build signed
with the release key and not older keeps every tailnet and setting, whichever way it is installed.

On Android 12 and later the install needs no tap (the app is updating itself); otherwise a
notification asks for one. The app restarts on install, ending every session. Afterwards remote
control comes back by itself if its auto-off time has not passed, and so does the VPN or
Multi-Tailnet session that was running. The access log records each upload's SHA-256.

### Remote shell

**Development builds only**, and off until **Allow remote shell** is turned on on the Remote control
screen. It runs commands as the app (`sh -c`, working directory and `HOME` in the app's private
storage), so it can read and change everything the app holds, tailnet keys included.

It is gated more tightly than a control session:

- **Approved on the phone.** By default (**Approve each command**) every command waits for **Run**
  on the phone, which shows the command itself; approving one lets nothing else through. With that
  switch off, one approval opens a shell instead (`tailmesh-ctl shell open`; the phone shows who is
  asking and a code). Either way approving works only with the phone unlocked, and a password alone
  never runs anything.
- **Limited in time.** An opened shell lasts at most 30 minutes (15 by default). A shell also ends when its session ends,
  when control is switched off, when remote control stops, or when **End** is tapped in the ongoing
  notification or on the Remote control screen. Ending it kills what it is running.
- **One command at a time.** `POST /v1/shell/exec {"cmd", "timeoutSeconds", "stdin"}` runs one
  command and returns its exit status and output (up to 1 MiB per stream). Nothing persists between
  commands (`cd`, variables). The timeout defaults to 60 s, at most 10 minutes, and kills the
  command's whole process group.
- **Logged before it runs.** The shell log records every request, approval, denial, command (before
  it starts: if it cannot be logged, it does not run), result (exit status, duration, output sizes
  and SHA-256) and end.

The shell runs as the app, so nothing on the device can stop it writing the log file. It cannot
change the log *unnoticed*, though: each entry carries the SHA-256 of the one before (a hash chain),
the newest hash is kept in the app's memory, and every entry is also written to logcat (tag
`RemoteShell`), which an app cannot rewrite. The Remote control screen verifies the file against
the in-memory head, so an edited, removed or truncated entry shows as **FAILED verification**; the
logcat copy shows what the real entries were. After the app restarts only the chain itself can be
checked, and its break, if any, is recorded as the first new entry.

```sh
tailmesh-ctl shell exec 'ls -la files'   # then Run on the phone (approve-each mode)
tailmesh-ctl shell open -minutes 10     # approve-a-shell mode: Allow on the phone first
tailmesh-ctl shell exec -stdin conf.json 'cat > shell-home/conf.json'
tailmesh-ctl shell                      # one command per line; "exit" ends the shell
tailmesh-ctl shell log                  # entries and the verification result
tailmesh-ctl shell end
```

Every change goes through the same code as the matching control in the UI (`MultiProxyControls`,
`MultiProxySessionCoordinator`, `PacketCaptures`), so it is validated, persisted and applied
identically, and the screens show it. A capture started remotely appears on the Packet capture
screen, and the reverse.

## 2. What it cannot do

Remote control cannot change itself. There is no method for its settings, the global control
switch, sessions, approvals, or the access log. Those exist only on the phone, so a client can never
widen its own access, extend its own lifetime, disconnect another client, or hide what it did.

The one exception is by design, and only in development builds: an app update replaces the app's
code, remote control's included. That is why it has its own switch, **Allow remote updates**, which
only the phone can set, and why only builds signed with the same key are accepted. The remote shell
is the other, with its own switch and an approval on the phone for every shell.

---

## 3. Signing in

Two methods, usable together. Either produces a **session token** sent as
`Authorization: Bearer <token>` on every later request.

### Approval on the phone

```text
client                               phone
  │ POST /v1/auth/request {client}     │
  │ ─────────────────────────────────▶ │  notification: "<client> wants to connect"
  │ ◀── {requestId, code: "482-913"}   │  shows the same code
  │                                    │  [Allow]  [Read-only]  [Deny]
  │ GET /v1/auth/request/{requestId}   │
  │ ─────────────────────────────────▶ │  (long-polls ~25 s per call)
  │ ◀── {status: approved, token}      │
```

Check that the code on the phone matches the one the client printed before tapping Allow. A request
expires after two minutes, the request ID is the only key to collect its token, and the token is
handed out once.

### Password

`POST /v1/auth/login {"client": "...", "password": "..."}`. Whether a password session may change
things or only read is a separate setting.

### Rate limit

Authentication attempts share **one global budget** (2 per second, burst 10) across every client:
logins, approval requests, and requests with an unknown token. A per-address limit would let an
attacker who controls many addresses guess in parallel. The cost of a global limit is that anyone
on the network who floods the endpoint locks everyone out of signing in for as long as the flood
lasts. Existing sessions keep working. This trades availability for brute-force resistance on
purpose; if it matters, bind to loopback and reach the port over a tailnet.

### Sessions and control

- A session is **read-only** unless it was granted control (Allow rather than Read-only, or a
  password with "sessions may make changes") **and** "Allow changes" is on.
- Turning "Allow changes" off makes every session read-only immediately, without disconnecting
  anyone.
- Sessions expire after an hour unused. The phone lists them and can disconnect any one.
- Remote control as a whole turns itself off after the chosen time (15 min to 24 h, or never).

---

## 4. Access log

Every request is logged, reads included, along with every authentication attempt, approval
decision, revocation and server start or stop. Each entry records the time, remote address,
session, client name, action, argument **names** (never values, since those carry keys and
passwords), status and error. The log is an append-only JSON-lines file in the app's private
storage, rotated at 4 MiB to one previous generation. The API can read it but not write to it. The
phone can clear it, but only while remote control is off.

---

## 5. Exposure

The listen address is chosen on the phone:

- **This device only (`127.0.0.1`)**, the default. Reach it with `adb forward tcp:7373 tcp:7373`, or
  from a tailnet by adding an inbound listener (Settings → Inbound listeners) that forwards a
  tailnet port to `127.0.0.1:7373`. Tailnet traffic is end-to-end encrypted by WireGuard.
- **All networks (`0.0.0.0`)**, or **a specific address**, such as the USB-tether address.

The API is **plain HTTP**. On anything but a private link (loopback, USB tether, a tailnet), tokens
and data can be observed in transit.

While remote control is on, an ongoing notification says so and has a Turn off button.

---

## 6. `tailmesh-ctl`

A small CLI in `cmd/tailmesh-ctl`:

```bash
go build -o tailmesh-ctl ./cmd/tailmesh-ctl
export TAILMESH_ADDR=10.146.109.63:7373

tailmesh-ctl login                       # approve on the phone (or: login -password)
tailmesh-ctl methods
tailmesh-ctl call diagnostics.snapshot
tailmesh-ctl call diagnostics.routeDecisions outcome=dial-error sinceMinutes=30
tailmesh-ctl call diagnostics.setDNSQueryLog enabled=true
tailmesh-ctl call diagnostics.dnsLog grep=geeksforgeeks
tailmesh-ctl call apps.bind packageName=com.android.chrome upstreamId=upstream-...
tailmesh-ctl call upstreams.saveWireGuard label=laptop config=@phone-tether.conf
tailmesh-ctl call capture.start mode=apps packages='["com.android.chrome"]'
tailmesh-ctl call capture.stop           # prints the path
tailmesh-ctl pull <path>                 # then open it in Wireshark
tailmesh-ctl logs -f -grep flow-
tailmesh-ctl logs -since 10m -level warn -v      # level and component on each line
tailmesh-ctl logs -since 14:30 -component magicsock,MultiProxySession
tailmesh-ctl logs -clear
tailmesh-ctl profile -kind heap -o heap.pprof
tailmesh-ctl call tailscale.localapi.get path=status
```

Argument values are parsed as JSON when they can be (`true`, `3`, `["a"]`) and taken as strings
otherwise. `@file` reads a value from a file and `@-` from stdin. The session token is cached per
address under the user config directory.

## 7. Raw HTTP

```bash
curl -s -X POST $A/v1/auth/login -d '{"client":"curl","password":"..."}'
curl -s -H "Authorization: Bearer $T" $A/v1/status
curl -s -H "Authorization: Bearer $T" -X POST $A/v1/call/upstreams.list -d '{}'
curl -s -H "Authorization: Bearer $T" "$A/v1/logs?follow=1&grep=DNS"
```

Calls return `{"ok":true,"result":...}`; failures return `{"ok":false,"error":"..."}` with 401 (no
or expired session), 403 (read-only session or control switched off), 404 (unknown method), 422 (the
action itself failed, with the same message the UI would show), or 429 (authentication rate limit).

---

## 8. Limits

- The server runs inside the app process. Android may stop that process when no VPN is running and
  the app is in the background; it starts again with the app, and remote control comes back with it
  if it is still within its time limit.
- `multitailnet.start` launches the VPN service, which Android only permits while the app is allowed
  to start foreground services. Starting it from the background may be refused on recent Android
  versions; the call then fails with that error.
- Approval needs notification permission to show its buttons. Without it, pending requests still
  appear on the Remote control screen and can be answered there.
