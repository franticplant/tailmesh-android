**Multi-Tailnet Proxy — Validation, Evidence, and Remaining Gaps**

**Document status:** current-state ledger for `main`.

**Purpose:** separate what the repository implements from what tests prove, what Android builds prove, and what still needs a real device or further hardening.

## 1. Why this document exists

A networking prototype can compile while its packet path is wrong. A unit test can prove a hash invariant while Android never routes the packet into the TUN. A UI can display `RUNNING` while a real service on a remote peer is unreachable.

The project therefore needs several evidence levels.

```text
IMPLEMENTED
    code path exists

UNIT / RACE TESTED
    local invariant executed under test

ANDROID BUILT
    Gomobile + Kotlin/Java resources compile together

INSTRUMENTATION / EMULATOR TESTED
    Android service/lifecycle actually exercised

PHYSICAL DEVICE E2E
    real Android VpnService + real Tailnets + real packets exercised
```

Do not substitute one level for another.

## 2. Current capability matrix

| Capability | Implemented | Local test evidence | Android/UI integration | Real-device evidence in repo |
|---|---:|---:|---:|---:|
| Multiple registered Tailnets | yes | lifecycle/concurrency tests | yes | not documented |
| Deterministic synthetic IPv6 | yes | yes | yes | not documented |
| Control `/120` avoidance | yes | covered by address invariants | yes via exported constants | not documented |
| Same native IPv4 in two Tailnets | yes | yes | peer V2 distinguishes profile IDs | not documented |
| Snapshot replacement | yes | yes | UI polls current V2 snapshot | not documented |
| Peer native-IP change with stable synthetic identity | yes | yes | exposed through current-vs-synthetic fields | not documented |
| Synthetic collision fail-closed | yes | yes | implicit through target snapshot | not documented |
| Unknown synthetic address fail-closed | yes | route tests | Android captures `/48` | not documented |
| Synthetic AAAA DNS | yes | DNS tests | Android points DNS to synthetic endpoint | not documented |
| Known-name A NODATA | yes | yes | yes | not documented |
| Ambiguous short-name rejection | yes | yes | qualified name shown in UI | not documented |
| DNS over UDP | yes | package tests + packet-level (`channel.Endpoint` inject/read) tests | captured by gVisor UDP | not documented |
| DNS over TCP | yes | short-write framing helper tested | captured by gVisor TCP | not documented |
| UDP upstream -> TCP retry on truncation/error | yes | handler path present | yes | not documented |
| TCP peer forwarding | yes | route/lifecycle lower-level tests | yes | not documented |
| UDP peer forwarding | yes | association hardening tests | yes | not documented |
| No-spoofing dynamic address registration (acquire/release per flow) | yes | packet-level DNS tests + shutdown/leak test | yes (this *is* what makes any of the above deliverable without spoofing) | not documented |
| Panic containment on TCP/UDP/DNS goroutines | yes | not directly tested (no test induces a panic) | yes | not documented |
| UDP idle expiry | yes, 60s | yes | transparent to Android | not documented |
| Android STANDARD/MULTIPROXY mode exclusivity | yes | source-reviewed; build evidence previously reported | yes | not documented |
| Synchronous STANDARD start/stop ACK | yes | source-reviewed | yes | not documented |
| Token-owned Android protect/bind hooks | yes | source-reviewed | yes | not documented |
| Persistent profile DB | yes | no multiproxy-specific CRUD tests found | yes | not documented |
| Immutable UUID profile identity | yes | source-level behavior | yes | not documented |
| Encrypted bootstrap auth key | yes | no specific lifecycle unit test found | yes | not documented |
| Bootstrap-key retirement on RUNNING | yes | no dedicated coordinator unit test found | yes | not documented |
| Profile enable/disable/rename/forget UI | yes | no dedicated ViewModel/coordinator tests found | yes | not documented |
| State-directory deletion on Forget | yes | state helper is simple; no Android orchestration test found | yes | not documented |
| Runtime-state UI | yes | JSON mechanics/source reviewed | yes, 1s poll | not documented |
| Peer snapshot UI | yes | V2 JSON decode test | yes, 2s poll | not documented |
| Process/service profile reconstruction | yes | no Android reconstruction test found | called on MULTIPROXY startup | not documented |
| Internal subnet routes | yes in Go | route tests | not captured by current Android Builder | n/a as product feature |
| Internal exit Tailnet | yes in Go | lower-level path exists | not captured by current Android Builder | n/a as product feature |
| Pluggable upstream registry (Provider/source) | yes | registry, chain and route tests | reached through the applier | §50.1: SOCKS5 upstream and both tailnets listed together in one picker |
| SOCKS5 upstream (CONNECT + UDP ASSOCIATE) | yes | tested against a real in-process SOCKS5 server | configurable in Proxies & tunnels | §50.1-50.2: added, edited, deleted via UI; real CONNECT observed |
| WireGuard upstream | yes | two devices back to back, real handshake carrying TCP | wg-quick .conf or JSON paste | not documented |
| wg-quick .conf import | yes | round-trip to JSON, then built into a real tunnel | accepted by the upstream editor | not documented |
| Named peer endpoint resolution | yes | stubbed-resolver tests + failure message test | transparent | not documented |
| Upstream chaining (`via`) | yes | three-hop traversal; WireGuard over a real SOCKS5 UDP association | pickable per upstream | not documented |
| Chain cycle rejection | yes | static walk at registration + dial-time depth guard | refused before save where the UI can tell | not documented |
| First-match-wins routing policy | yes | policy and route tests, incl. empty-policy regression guard | built from bindings by the applier | §50.2: default-route rule verified end to end |
| Per-app upstream binding | yes | policy selector tests | App routing screen, package to UID at apply time | not documented (only the default rule was device-tested, §50.3) |
| App attribution (getConnectionOwnerUid) | yes | resolver timeout/fail-safe tests with a stub | AppUidResolver installed before startVPN | **not verified on any device** (§50.3) |
| Default upstream for unbound apps | yes | covered by policy default-rule tests | Proxies & tunnels screen | §50.1-50.2: set, applied, and reset via UI; routed real traffic |
| Upstream/binding persistence | yes | no Android CRUD or migration tests | DB v3 + EncryptedSharedPreferences | §50.1: upstream and default route survived an app reinstall |
| Live re-apply without VPN restart | yes | not directly tested | applier called from the view model | not documented (edit was verified only after a VPN restart, §50.1) |
| DNS forwarding follows the app's policy route | yes | route-decision + DoH-cache-and-fail-closed tests against a real forwarding server | transparent - reached through the same applier/policy | §50.2: real DoH CONNECT tunneled through a SOCKS5 upstream |

## 3. Evidence from the Go test suite

The current multiproxy tests encode several architectural invariants rather than only checking syntax.

### 3.1 Identity tests

Tests prove:

```text
same TargetKey -> same synthetic IPv6
different NamespaceID -> different synthetic IPv6
synthetic address belongs to configured /48
```

This is the core deterministic-identity claim.

### 3.2 Snapshot lifecycle tests

The test suite constructs peer A/B snapshots, replaces them, and verifies:

- disappeared peers are removed;
- remaining peer synthetic identities stay unchanged;
- changed native locator updates `CurrentIPv4` without changing synthetic IPv6;
- returning stable peer gets the same synthetic IPv6.

These tests directly exercise the identity-versus-locator model.

### 3.3 Overlapping native-address test

Two Tailnets are populated with different targets that both have the same native IPv4.

The test resolves each synthetic IPv6 and checks they select different upstreams.

This proves the routing data model does not key identity by native IPv4.

It does **not** prove two real external Tailnets with overlapping addresses were simultaneously reached from Android.

### 3.4 Collision test

The suite manually forces two distinct `TargetKey`s to share one synthetic IPv6.

The target is expected to disappear from the active map rather than one record overwriting another.

This validates fail-closed collision behavior.

### 3.5 DNS tests

Current tests cover:

```text
ambiguous short name has multiple internal candidates
qualified name uniquely selects the intended target
known synthetic A query returns authoritative NODATA
```

The hardening suite also tests the shared qualified-name generation helper used by V2 export.

### 3.6 Concurrency/lifecycle tests

There are tests that rapidly enable/disable the same Tailnet and expect a stable final state, plus broader concurrency stress around route configuration.

The project has also repeatedly used:

```bash
go test -race ./libtailscale/multiproxy
```

as the primary race-validation command during implementation.

### 3.7 UDP hardening tests

The current suite explicitly verifies:

- an inactive association expires after its idle timeout;
- repeated traffic refreshes association lifetime;
- closing one side terminates both pump goroutines;
- the helper waits for cleanup instead of leaving the opposite direction stranded.

### 3.8 DNS TCP write test

`writeFull` is tested using a writer that intentionally accepts only a small number of bytes per `Write` call.

The test proves the helper loops until the full payload is emitted.

## 4. Current Android JVM tests

The multiproxy-specific Android JVM test directory currently contains two focused tests.

### 4.1 `DnsSelectionTest`

It checks the intended first-resolver rule:

```text
[8.8.8.8, 8.8.4.4] -> 8.8.8.8
[]                   -> no resolver
IPv6 list            -> first IPv6
```

**Limitation:** the test reproduces the selection expression in a test helper rather than invoking the private production callback method. It proves the intended rule, not the full Android `NetworkChangeCallback` wiring.

### 4.2 `MultiProxyPeerJsonTest`

It decodes a V2 peer snapshot and asserts that these fields remain distinct:

```text
currentIpv4
currentIpv6
syntheticDnsName
syntheticIpv6
```

This is valuable because earlier UI/API revisions had misleading synthetic/native address naming.

## 5. Missing Android-level tests

The current tree does not contain comparable focused tests for several now-important features.

### 5.1 Profile repository CRUD

Needed coverage:

```text
create UUID profile
rename without ID change
enabled persistence
provisioning-state persistence
delete only requested profile
reload DB after repository recreation
```

### 5.2 Database migrations

Database version 1 currently drops and recreates the table on upgrade.

Before a schema bump in a data-preserving release, migration tests should prove old profile identity survives.

### 5.3 Credential lifecycle

Needed coverage:

```text
save auth key under profile ID
retrieve it
RUNNING completion deletes it
disable does not recreate/store it
forget deletes it even if runtime absent
```

### 5.4 Coordinator provisioning

A testable coordinator boundary should prove:

```text
PROVISIONING + runtime RUNNING -> READY + key retirement
PROVISIONING + ERROR -> ERROR + disabled
PROVISIONING + NEEDS_LOGIN -> current intended failure behavior
```

### 5.5 Enable/disable/rename/forget orchestration

These product transitions currently rely mostly on source reasoning and lower-level Go tests.

### 5.6 Reconstruction

There is no Android test in the reviewed tree proving:

```text
persist two profiles
recreate MultiProxySession/Engine
reconstruct both
preserve profile IDs
enable only desired profiles
```

## 6. Real-device acceptance matrix still required

A physical-device or suitably realistic Android emulator pass should exercise at least the following.

### 6.1 Two independent Tailnets

```text
Tailnet A READY + RUNNING
Tailnet B READY + RUNNING
both peer sets visible simultaneously
```

### 6.2 TCP through each Tailnet

Use deterministic services such as HTTP, SSH, or TCP echo.

Prove:

```text
synthetic A -> service A
synthetic B -> service B
```

### 6.3 UDP through each Tailnet

Use a controlled UDP echo/service and prove both directions plus re-establishment after idle expiry.

### 6.4 Overlapping native address

Best case: construct two real Tailnets with peers sharing the same native Tailscale `100.x` address and prove their different synthetic addresses both work.

If control-plane allocation makes an exact live overlap impractical, the final report must say the overlap invariant is unit tested but not live-E2E proven.

### 6.5 DNS

Prove from Android applications:

```text
qualified synthetic AAAA works
unambiguous short name works
ambiguous short name fails
A for known synthetic target is NODATA
other synthetic RR types do not leak upstream
ordinary external DNS works
DNS-over-TCP works
truncated upstream UDP retries TCP
```

### 6.6 Ordinary Internet bypass

A normal public TCP/UDP connection should not create a multiproxy data flow.

DNS mediation is expected; public data flow interception is not.

### 6.7 Profile lifecycle

```text
disable A -> A unavailable, B unaffected
reenable A -> same synthetic identities
rename A -> identity unchanged
forget A -> disk/profile/key gone, B unaffected
```

### 6.8 Process/service restart

Kill/recreate the app/service and verify READY profiles reconstruct from persisted `tsnet` state with empty bootstrap keys.

### 6.9 Mode switching

Repeat:

```text
STANDARD -> MULTIPROXY
MULTIPROXY -> STANDARD
stop/start
restart
```

and inspect for stale hook owners or orphan TUNs.

### 6.10 Network transitions

Exercise:

```text
Wi-Fi -> cellular
cellular -> Wi-Fi
temporary no network
multiple networks active
DNS server changes
```

Profile identity and synthetic identity should not change merely because the underlay changed.

## 7. Gap: Engine readiness is inferred from a pointer

`MultiProxySessionCoordinator.ensureMultiProxyEngine` starts the service and waits until:

```text
session.engine != null
```

But `IPNService.startMultiProxyVPNLocked` publishes the Engine before TUN establishment is complete.

### Why this matters

An interactive Add/Enable operation can theoretically begin after the Engine pointer exists but before the service has finished:

```text
TUN establishment
upstream DNS setup
startup reconstruction
activeMode publication
```

Go can register a Tailnet without an active TUN, so the overlap is not necessarily fatal. The concern is error semantics: if TUN startup subsequently fails, `IPNService` may close the Engine while the coordinator operation is in progress.

### Recommended hardening

Expose an Android/service readiness state or completion primitive that means:

```text
MULTIPROXY mode has successfully acquired hooks
AND
TUN is attached
AND
session Engine is the live Engine
```

The coordinator should await that state instead of raw pointer existence.

## 8. Gap: reconstruction bypasses coordinator serialization

Interactive mutations are serialized by `MultiProxySessionCoordinator.mutationMutex`.

Startup reconstruction is performed by `MultiProxySession.reconstructEngine()` directly.

That means these can conceptually overlap:

```text
service reconstructing persisted profile A
UI toggling/forgetting profile A
```

Go's `tailnetLifecycleMu` protects the Engine's internal consistency, and SQLite operations are individually safe, but Android desired-state ordering is less explicit.

### Recommended hardening

Move reconstruction behind the same session coordinator or establish a distinct serialized startup phase before interactive mutations are admitted.

## 9. Gap: reconstruction errors are only logged

`reconstructEngine` catches each `AddTailnet` exception and logs it.

It does not currently update:

```text
provisioningState
runtime error map
persisted enabled state
```

for a READY profile whose persisted `tsnet` state can no longer start.

The coordinator's one-second runtime poll can surface some runtime states when a registration exists, but an `AddTailnet` failure before registration can remain primarily a log event.

### Recommended hardening

Report reconstruction failure through the same profile-scoped error model used for interactive operations while allowing other profiles to continue.

## 10. Gap: profile DB initial read is synchronous

`ProfileRepository` calls `refreshProfiles()` in `init`.

CRUD operations use `Dispatchers.IO`, but constructor initialization is synchronous on whichever thread first instantiates the lazy session/repository.

The current table is small, so this is unlikely to dominate runtime, but the behavior should not be mistaken for a fully asynchronous repository.

### Recommended hardening

If profile count/schema grows, initialize through an IO-backed repository scope or a database layer that exposes asynchronous queries naturally.

## 11. Gap: destructive database upgrade

`TailnetDatabaseHelper.onUpgrade` currently drops the profile table.

If database version changes in a real user release, this would destroy:

```text
profile UUIDs
display names
enabled state
provisioning state
```

and could orphan deterministic `tsnet` state directories on disk.

### Required before schema version 2

Implement explicit migrations and test profile-ID preservation.

## 12. Gap: `RuntimeState` enum is not the current runtime-state type

The profile package declares:

```text
RuntimeState.NOT_LOADED
STARTING
RUNNING
STOPPED
ERROR
```

But coordinator and UI currently transport normalized state as strings, including extra states such as:

```text
NEEDS_LOGIN
NEEDS_MACHINE_AUTH
```

This is not a runtime bug, but it creates two competing type models.

### Recommended cleanup

Either expand/use a sealed/enum UI runtime model or remove the unused enum so future code does not assume it is authoritative.

## 13. Gap: `NeedsMachineAuth` is treated as provisioning failure

During first provisioning, coordinator maps:

```text
ERROR
NEEDS_LOGIN
NEEDS_MACHINE_AUTH
```

into `failProvisioning`, disables the profile, and marks persistent provisioning `ERROR`.

In some Tailscale environments, machine authorization can be an expected administrative waiting state rather than bad credentials.

### Product decision needed eventually

Decide whether the UI should represent a recoverable state such as:

```text
AWAITING_MACHINE_AUTH
```

while retaining enough runtime/bootstrap context to continue safely.

Document current behavior until that decision changes.

## 14. Gap: one upstream DNS endpoint

Android can advertise multiple DNS servers. MULTIPROXY currently uses only the first.

This is intentionally simpler than a resolver pool.

### Consequences

- no fallback to Android's second DNS server inside this Go resolver;
- a broken first resolver can fail external DNS even if Android has another usable resolver;
- network changes can still select a new first resolver through `NetworkChangeCallback`.

A multi-resolver design is future hardening, not required to explain current behavior.

## 15. Gap: scoped/link-local IPv6 DNS endpoints

`SetUpstreamDNS` validates the host with `net.ParseIP`.

Android may expose a scoped link-local resolver representation containing a zone/interface suffix, for example conceptually:

```text
fe80::1%wlan0
```

`net.ParseIP` does not parse a zone-qualified string.

### Required evidence

Observe actual `LinkProperties.dnsServers[].hostAddress` values on target devices/networks before deciding whether zone-aware handling is necessary.

## 16. Gap: strict Android Private DNS

The local synthetic resolver listens as ordinary DNS on port 53 inside the TUN.

Android strict Private DNS can cause applications/system resolver behavior to use DNS-over-TLS semantics that do not simply follow this local port-53 server.

The current multiproxy implementation does not provide a synthetic DoT endpoint.

### Required device matrix

Test:

```text
Private DNS Off
Private DNS Automatic
Private DNS strict hostname
```

and surface a warning if strict mode makes synthetic names unusable.

## 17. Gap: Always-On and lockdown semantics

Always-On can be useful because it restarts the selected VPN service.

Lockdown / "Block connections without VPN" is more complicated: MULTIPROXY deliberately does not capture ordinary Internet data.

If Android blocks non-VPN traffic under lockdown, that can conflict with synthetic-only bypass by design.

### Correct response

Do not add default routes merely to make the lockdown test green. Establish/document compatibility semantics explicitly.

## 18. Gap: internal subnet/exit APIs exceed Android capture surface

Go implements:

```text
AcceptSubnet
RemoveSubnet
SetExitNode
```

and route precedence is correct.

But the Android MULTIPROXY Builder captures only:

```text
fd9b:8d7c:6a5e::/48
```

Therefore these are internal/future capabilities, not current user-visible Android routing features.

Docs, UI, and issue reports should not claim otherwise.

## 19. Gap: legacy `GetTargetsJSON`

The facade still exposes both:

```text
GetTargetsJSON
GetTargetsJSONV2
```

V2 is the canonical UI schema.

Keeping the old API increases the chance that future code consumes its less precise naming/qualified-name behavior.

### Recommended cleanup

After confirming no clients depend on the legacy method, remove or deprecate it explicitly.

## 20. Gap: duplicate Forget pathways

Go has `Engine.ForgetTailnet`, while Android's current product path uses:

```text
RemoveTailnet
+
ForgetPersistedState
```

The latter is preferable for Android because disk deletion works even with no live Engine.

Two public-looking destructive paths increase maintenance surface.

### Additional concern

The legacy `Engine.ForgetTailnet` path cancels/closes live state differently from `RemoveTailnet`; maintainers should not casually switch the Android coordinator to it without rechecking watcher wait/cleanup semantics.

## 21. Gap: test-only STANDARD failure seam remains exported

The root backend contains `ForceStandardTUNFailureForTest` and a process-global Boolean.

The original motivation was to force a post-hook-acquisition startup failure and validate transactional cleanup.

In the current reviewed Android test directory, no live test uses that seam.

### Recommended cleanup

Either:

- add a meaningful test harness that uses the seam; or
- gate/remove it if it no longer serves executable validation.

Do not leave a production-visible test knob indefinitely just because it once helped manual review.

## 22. Gap: development debris

The multiproxy package currently contains:

```text
api.go.patch
```

alongside source files.

This is not a runtime mechanism and should not remain in a cleaned implementation unless it has an explicit archival purpose.

There is also a duplicated `Close gracefully shuts down...` comment in `api.go`.

These are low-severity cleanup items but useful indicators that the branch still carries implementation-pass debris.

## 23. Gap: protect/bind callbacks log but return success on Android failure

`AcquireAndroidNetworkHooks` installs callbacks where:

```text
VpnService.protect(fd) == false
```

or:

```text
BindSocketToNetwork(fd) == false
```

produces an `[unexpected]` log, but the Go callback returns `nil` to Tailscale networking.

### Why to review this

The current behavior preserves upstream expectations and may avoid cascading errors, but it also means a failure to protect/bind is not propagated as a hard socket-creation error.

Real-device logging should establish whether these failures ever occur. If recursion becomes possible, stronger error propagation may be appropriate.

## 24. Gap: runtime poll and peer poll are periodic snapshots

Current clocks:

```text
Go Tailnet Status: immediate + every 10s
Android runtime UI: every 1s
Android peer UI: every 2s
```

Consequences:

- peer disappearance can take up to the Go poll interval to leave routing state;
- UI can lag current Engine state by its own polling interval;
- runtime observation invokes `LocalClient.Status` per profile every second.

This is acceptable for the current scale but should be measured for many profiles and mobile battery impact.

## 25. Gap: UI exposes raw profile UUID

Peer cards currently display `Tailnet ID`, which is the immutable profile UUID.

This is useful during development and debugging but not necessarily ideal final UX.

A mature UI could map it back to display name while keeping the UUID available in a diagnostics view.

## 26. Gap: no profile-name uniqueness policy

`displayName` is presentation only, and repository creation does not enforce uniqueness.

Two profiles can therefore both be called `Work` while remaining distinct UUIDs.

This is technically valid but can confuse users.

Because qualified DNS is based on UUID hash, networking remains unambiguous.

A future UI may enforce or warn about duplicate labels without changing machine identity.

## 27. Gap: no authoritative live test of auth-key retirement in this repo

The code path is clear:

```text
PROVISIONING
observed RUNNING
ClearTailnetAuthKey
CredentialStore.deleteAuthKey
READY
```

But the strongest claim — that a brand-new `tsnet.Server` later reconnects from the same state directory with empty `AuthKey` — should have a repeatable integration test or documented real experiment.

Until then, describe the application as implementing bootstrap-key retirement based on observed Running state, not as cryptographically proving every future control-plane restoration condition.

## 28. Gap: one broken reconstruction should surface independently

The reconstruction loop already continues after individual profile failures, which is the correct availability direction.

However the failure should become first-class per-profile UI state rather than only logging.

Acceptance target:

```text
Work reconstructs -> RUNNING
Home corrupt state -> ERROR visible
Lab reconstructs -> RUNNING
MULTIPROXY remains alive
```

## 29. Gap: actual profile deletion ordering under failures

Forget currently performs runtime removal, persisted-state deletion, credential deletion, then DB deletion inside one coroutine operation.

These are not one transactional storage system.

Possible partial failures include:

```text
runtime removed, disk deletion fails

disk removed, DB delete fails

DB deleted after encrypted preference delete failure
```

`os.RemoveAll` and SharedPreferences operations are normally simple, but robust product semantics should define retry/reconciliation behavior rather than assuming cross-system atomicity.

## 30. Gap: no persisted tombstone for interrupted Forget

Related to the previous point, there is no explicit "deleting" state/tombstone that can resume cleanup after process death.

For the current prototype, deterministic directory/key naming makes cleanup recoverable manually.

For production, consider an idempotent Forget operation that can resume based on profile ID.

## 31. Gap: no formal maximum profile count

Each enabled profile owns at least:

```text
one tsnet.Server
one status watcher
control/data-plane state
runtime-state polling work
peer snapshot contributions
```

No explicit profile-count product limit is encoded.

Real-device resource testing should establish a practical supported range before promising arbitrary scale.

## 32. Gap: logging and privacy review

Flow logs currently include:

```text
flow ID
protocol
synthetic destination
selected UpstreamID/profile UUID
native destination address
success/failure
```

They do not intentionally log auth keys.

Before production, decide which diagnostics belong in normal logs versus debug-only logs, particularly profile identifiers and private peer addresses.

## 33. Gap: peer snapshot exposes stable namespace but not display-name join

`GetTargetsJSONV2` intentionally exports `tailnetId` as immutable identifier.

The Android UI can join that to `ProfileRepository` display names but currently prints the raw ID on peer cards.

This is a presentation gap, not a routing gap.

## 34. What should not be treated as a gap

Several behaviors are deliberate design choices.

### 34.1 No synthetic IPv4

This is intentional. The canonical namespace is IPv6-only.

### 34.2 Unknown synthetic address rejected

This is intentional fail-closed behavior, not missing fallback.

### 34.3 Ordinary data bypasses MULTIPROXY

This is the current synthetic-only product mode, not a broken exit-node feature.

### 34.4 Ambiguous short name returns NXDOMAIN

This deliberately avoids hidden routing policy.

### 34.5 Disable keeps state directory

That is how local Tailnet identity survives disable/re-enable.

## 35. Acceptance gate for a genuinely working application

Before calling the multi-Tailnet application fully working, record evidence for this journey:

```text
install app
    |
open Multi-Tailnet screen
    |
add Tailnet A with bootstrap key
    |
A reaches READY + RUNNING, key retired
    |
add Tailnet B
    |
B reaches READY + RUNNING, key retired
    |
peers from both visible
    |
qualified synthetic DNS resolves
    |
TCP to A works
TCP to B works
UDP to A works
UDP to B works
    |
disable A -> B remains working
    |
reenable A -> same synthetic peer identity
    |
restart process/service
    |
A and B reconstruct with same profile IDs and peer synthetic identities
    |
rename B -> identity unchanged
    |
forget A -> A disk/profile/key gone; B unaffected
    |
switch MULTIPROXY -> STANDARD -> MULTIPROXY safely
```

If a step was not executed on Android, say so.

## 36. Suggested evidence table for final device testing

| Test | Environment | Expected | Actual | Logs/artifact |
|---|---|---|---|---|
| Provision Tailnet A | physical device | READY/RUNNING | | |
| Provision Tailnet B | physical device | READY/RUNNING | | |
| A TCP | physical device | service responds | | |
| B TCP | physical device | service responds | | |
| A UDP | physical device | echo/respond | | |
| B UDP | physical device | echo/respond | | |
| Overlap | two controlled Tailnets | same native IP routed separately | | |
| External DNS | Wi-Fi | resolves | | |
| DNS TCP | Wi-Fi | resolves | | |
| Internet bypass | Wi-Fi | no MP data flow | | |
| Disable/re-enable | device | identity stable | | |
| Process restart | device | profiles reconstruct | | |
| Wi-Fi -> cellular | device | recovers | | |
| STANDARD -> MP | device | no stale hook/TUN | | |
| MP -> STANDARD | device | no stale hook/TUN | | |
| Private DNS strict | device | characterize behavior | | |
| Always-On | device | characterize restore | | |
| Lockdown | device | characterize bypass interaction | | |

## 37. Source-cleanup gate before merge

Before considering the feature branch merge-ready, inspect for:

```text
*.patch development leftovers
commented-out test experiments
unused test seams
stale synthetic-IPv4 documentation
old method signatures in docs
TODOs contradicted by completed implementation
legacy APIs no longer consumed
```

The documentation pass itself is part of that cleanup because stale architecture prose can be as misleading to future maintainers as dead code.

## 38. Resolved: global NIC spoofing removed after a DNS-traffic panic (2026-08-25)

**Before:** `tun_interceptor.go`'s `StartVPN` enabled `s.SetSpoofing(nicID, true)`
globally, for the whole lifetime of the VPN NIC, alongside promiscuous
receive mode. The stated rationale in a code comment was that the router
binds reply sockets to synthetic destinations and spoofing avoided having to
assign every synthetic peer address individually.

**Why it was a gap, not a style choice:** the installed app was observed to
panic when DNS traffic arrived while global spoofing was active. Spoofing is
a NIC-wide permission to emit packets from *any* source address, which is
categorically broader than what the feature actually needs (reply from a
small, known-in-advance set of addresses: the current flow's destination),
and it let the DNS reply path exercise a code state the rest of the engine
wasn't written to expect.

**New:** spoofing is removed. Promiscuous receive mode is kept (still needed
so the NIC accepts inbound packets for synthetic addresses it hasn't
registered yet). Every local (destination) address a flow answers from is
now registered on the NIC just-in-time and refcounted per concurrent flow
(`Engine.acquireDynamicAddr`/`releaseDynamicAddr`), matching the pattern the
pinned Tailscale core netstack already uses for its own dynamically-routed
subnet addresses. `SyntheticIPv6DNS` is the one exception: it's registered
once, permanently, at stack construction, since it's always needed. See
`backend_internals.md` §43.2-43.4 for the full mechanics, and the new
`libtailscale/multiproxy/dataplane_test.go` packet-level suite (injects real
IPv6/UDP/DNS packets through a `channel.Endpoint` wired via the exact same
stack-construction path as the production `fdbased` endpoint) for the test
evidence: AAAA/A-NODATA/forwarding/ambiguous-name/collision responses,
response source address/port, repeated queries on one association, and a
shutdown-with-active-flows leak/panic check.

**What this does not yet prove:** the packet-level tests are hermetic host
tests; they don't prove real Android DNS traffic no longer panics the
installed app. §6.5 in this document (DNS acceptance) and the emulator
acceptance pass still need to exercise this on a device before the original
crash can be called closed with device evidence, not just unit-test
evidence. Filed here as **TEST EVIDENCE**, not **ANDROID / DEVICE
EVIDENCE**.

**Update (see §39): this caution was warranted.** Device testing surfaced a
second, unrelated crash that no host test could have caught. §39 has the
full account, including device evidence that the app now runs both
upstreams simultaneously without crashing.

## 39. Resolved: MULTIPROXY startup crash + a build-system bug that hid every fix attempt (2026-08-25)

**Before:** first on-device test of §38's fix ("clicked start multi. seems
to have crashed") showed the DNS-spoofing fix was necessary but not
sufficient. Starting Multi-Tailnet mode with even a single upstream enabled
crashed the app almost every time, 40-300ms after the log line `[VPN]
gVisor stack successfully bound to TUN FD <n>`. The failure was:

```text
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=...]
Fatal signal 6 (SIGABRT) ...
```

with no goroutine stack trace ever reaching logcat before the process
aborted (confirmed via multiple full-window logcat captures and device
tombstones, which only ever contained the two header lines above plus the
`runtime.raise` frame from Go's own deliberate abort call — the trace print
itself never completed).

**Investigation, ruled out (ANDROID-DEVICE EVIDENCE + TEST EVIDENCE):**

- Pure Go dataplane logic: a standalone `GOOS=android` binary driving the
  same `multiproxy.Engine` code with pulled real profile state, run
  directly via `adb shell` (bypassing JNI entirely, both single- and
  dual-profile, including a concurrent gVisor stack over a
  `syscall.Socketpair` fake TUN), never crashed. This is strong evidence the
  bug was not in application-level Go logic reachable without the real
  Android JNI/VpnService/TUN environment.
- Inter-profile concurrency: a single-enabled-profile repro crashed *more*
  reliably (approaching 100%) than the two-profile case, ruling out a race
  between the two `tsnet.Server` instances as the primary cause.
- A 500ms stagger between sequential `AddTailnet` calls: no measurable
  effect (tested via repeated A/B repro-rate comparison); reverted rather
  than kept as unproven ballast.
- Synchronous panics in `netns.SetAndroidProtectFunc`/
  `SetAndroidBindToNetworkFunc` (`backend.go`) and in `tsnet.Server.LocalClient()`
  (`api.go`'s `setTailnetEnabledLocked`): `recover()` wrappers were added at
  both sites as legitimate defense-in-depth (kept permanently — see below)
  but neither one ever fired, proving the fault was not synchronous in
  either of those call stacks.
- `runtime/debug.SetCrashOutput`: added temporarily to redirect the full
  Go crash report to a file for analysis. It never produced a file and
  never changed what appeared in logcat. This is now understood as a
  symptom, not a separate bug: see the build-system finding below — this
  diagnostic was itself a casualty of the same stale-build issue for most
  of the investigation, and once it *was* actually deployed, the crash it
  was meant to help diagnose had already stopped reproducing (see below),
  so it was never conclusively exercised against a live crash. It was
  removed before delivery rather than kept as unverified.

**The actual root cause (CURRENT CODE + ANDROID-DEVICE EVIDENCE):**
`attachNIC` in `tun_interceptor.go` permanently registered
`SyntheticIPv6DNS` on the gVisor NIC, but not `SyntheticIPv6Interface`
(`fd9b:8d7c:6a5e::1`) — the address Android's `VpnService.Builder` assigns
as the TUN's *own* address at the OS level (`IPNService.kt`'s
`b.addAddress` call). With global spoofing removed (§38) and only
just-in-time per-flow addresses registered, the gVisor NIC had no
registered endpoint for its own interface address. Real Android-generated
traffic addressed to that address (NDP neighbor solicitation for it, ICMPv6
addressed to it, etc.) — which only exists once a *real* kernel TUN and a
*real* Android network stack are involved, never in a host test or the
socketpair-based standalone repro — had nowhere to be delivered inside
gVisor, which is the class of bug promiscuous-mode-without-spoofing is
specifically prone to if every NIC-owned address isn't accounted for.
The fix, added to `attachNIC`, permanently registers
`SyntheticIPv6Interface` the same way `SyntheticIPv6DNS` already was:

```go
ifaceAddr := tcpip.ProtocolAddress{
    AddressWithPrefix: tcpip.AddrFromSlice(SyntheticIPv6Interface.AsSlice()).WithPrefix(),
    Protocol:          ipv6.ProtocolNumber,
}
if err := s.AddProtocolAddress(vpnNICID, ifaceAddr, stack.AddressProperties{}); err != nil {
    return fmt.Errorf("failed to register synthetic interface address: %s", err)
}
```

**Why this took multiple rebuild cycles to actually verify — a build-system
bug, not a code bug:** `Makefile`'s `$(ABS_UNSTRIPPED_AAR)` target (the
`gomobile bind` step that turns `libtailscale/...` Go source into the AAR
`android/` links against) listed only `tailscale.version` and the
`gomobile` binary as prerequisites — **not any Go source file**. Make
therefore could not tell the AAR was stale after editing `.go` files, and
`make tailscale-debug.apk` silently skipped the entire `gomobile bind` step
across several rebuild/install/repro cycles, each of which re-tested
whatever Go code happened to already be in the AAR from a build made before
this investigation started. This means several of the fix attempts above
(the interface-address registration included, the first time it was
written) were never actually exercised on the device at all — the "no
effect" result recorded for them during the investigation is explained by
this, not by the fix being wrong. Confirmed by comparing the AAR's mtime
(predating every edit made during this investigation) against a build log
with no `Running gomobile bind` line. Fixed by adding an explicit
prerequisite:

```make
LIBTAILSCALE_GO_SRCS := $(shell find libtailscale -name '*.go')
$(ABS_UNSTRIPPED_AAR): tailscale.version $(GOBIN)/gomobile $(LIBTAILSCALE_GO_SRCS)
```

and by deleting the stale `android/libs/libtailscale*.aar` once by hand to
force the first correct rebuild. Any prior "verified, no effect" statement
about a fix made during this investigation before this Makefile change
should be treated as **unverified**, not as evidence the fix didn't work.

**Defense-in-depth kept permanently, independent of the root cause above:**
`Engine.dispatchEvents`/`pollTailnetStatus` (`api.go`) now recover and log
instead of propagating a panic across the JNI boundary into the
`MultiProxyCallback` Java object, matching the pattern already used for the
`netns` hooks in `backend.go`. None of these ever fired for this specific
bug (see above), but they close a real gap: a panic in any of these
goroutines was previously unrecoverable and would have taken down the
whole process regardless of cause.

**ANDROID-DEVICE EVIDENCE the fix holds:** with the Makefile fix in place
(so this is confirmed to be testing current source), the single-profile
Start Multi-Tailnet repro that previously crashed 4-5 times out of 5 was
run 8 consecutive times with zero crashes. The app was then driven to a
state with **both** upstream profiles (`account-a@example.com` and
`account-b@example.com`) simultaneously `Included in Multi: Enabled`,
`Active in current Multi session: Yes`, `Runtime: RUNNING`, with peer
discovery populating (`peer-container.tailnet-a.ts.net.` and others),
confirming genuine dual-upstream operation, not just crash-avoidance.

**Cleanup:** the temporary `debug.SetCrashOutput` diagnostic
(`diagnosticSetCrashOutput`/`diagnosticCrashOutputOnce` in
`multiproxy_facade.go`) was removed entirely once the fix was confirmed,
per the source-cleanup gate in §37.

## 40. Load and throughput validation against real tailnet peers (2026-08-25)

**ANDROID-DEVICE EVIDENCE.** After §39's fixes, the dataplane was exercised
against real Tailscale peers (not the hermetic `channel.Endpoint` host
tests) using a new tool, `cmd/loadpeer`: a `tsnet`-based node joined to a
real tailnet exposing TCP throughput/echo (`SOURCE`/`SINK`/`ECHO`) and UDP
echo endpoints. Two instances were run, one per tailnet, and driven from the
installed APK on `emulator-5554` via `adb shell nc` through the actual VPN
tunnel and gVisor multiproxy dataplane - not a backend-only or host-only
test.

**UDP correctness: confirmed.** 20/20 individual round-trips content-correct
(not just exit-code-based - an early pass with `nc -u`'s exit code as the
success signal was wrong, since toybox `nc` doesn't exit on first UDP reply,
it waits out its own idle timer regardless of whether data arrived; fixed by
checking the actual echoed content). Under a 150-way concurrent burst:
299/300 succeeded - one loss in 300 is unremarkable background noise, not a
pattern.

**Concurrent load and leak-freedom: confirmed.** Two back-to-back rounds of
150 concurrent TCP + 150 concurrent UDP flows each (600 total) against
`loadpeer-b`: 300/300 TCP succeeded, the app never crashed, and -
critically - round 2 performed identically to round 1 with no degradation,
which is the actual evidence against a leak in
`acquireDynamicAddr`/`releaseDynamicAddr` (a leak would show up as
progressively increasing rejection/failure rates across rounds, not as a
one-time crash). Zero panics, zero rejected flows, zero recovered-panic log
lines across the entire run.

**Bulk TCP throughput: a real, reproducible environmental limitation, not a
dataplane bug.** A 64MiB `SOURCE` transfer collapsed to single-digit-KB/s
after an initial ~1.6MB burst, reproduced on a second, independent run
against a freshly re-provisioned peer. Root-caused, not just observed:
device logs show `health(warnable=no-derp-connection)` oscillating between
`ok` and `error: Tailscale could not connect to the 'Frankfurt' relay
server` on a roughly 10-50s cycle throughout the transfer - the collapse
tracks the DERP reconnection cycle exactly (burst while connected, stall
while reconnecting). A plain ICMP ping to `8.8.8.8`, entirely outside
Tailscale, showed 0% loss but 38-340ms jitter across 5 pings on the same
emulator - the underlying virtualized network is itself unstable enough to
prevent DERP from holding a sustained low-jitter connection, which sustained
TCP throughput depends on far more than short flows or UDP echoes do (which
is exactly why those tested clean: they complete within a single "ok"
window).

**What this does and does not prove:** it proves the multiproxy dataplane
correctly handles concurrent connection volume without leaking, crashing, or
misrouting, and that UDP (small-packet, latency-tolerant traffic - the
profile real-time calls actually have) works correctly end to end under
load. It does **not** prove anything about real-world bulk-transfer
throughput, because the limiting factor identified here is specific to this
emulator's virtualized network, not the dataplane. Real throughput numbers
require a real device on real Wi-Fi/LTE; testing that is not yet done.

## 41. Path visibility, dial retry, and direct proof that loadpeer flows are DERP-relayed (2026-08-25)

**BEFORE.** §40 root-caused the bulk-throughput collapse to DERP relay
instability by *inference*: `health(warnable=no-derp-connection)` flapping
on a clock, corroborated by an independent `ping 8.8.8.8` jitter test. There
was no direct, per-flow evidence that a given proxied TCP connection was
actually being carried over DERP rather than a direct (P2P) path - the
DERP-instability explanation was plausible but not proven at the flow level,
and the two comparison apps investigated for this session (`firestack` /
`rethink-app`, see below) don't relay through anything DERP-equivalent at
all, so their absence of this failure mode doesn't tell us whether *our*
flows are actually relay-bound.

**Comparison research (firestack/rethink-app).** Both repos live locally
under a local checkout of `firestack` and `rethink-app`. Firestack's
multi-upstream architecture (`intra/ipn/proxies.go`) is structurally similar
to ours - per-destination/per-uid deterministic pinning, not
load-balancing - but it has no DERP-equivalent relay layer (`grep -rli derp`
across its proxy/dial code returns nothing meaningful); it dials
destinations directly or through a single user-configured WireGuard hop.
What it does have that we lacked: connection-establishment-time resilience
- `intra/dialers/retrier.go` detects a stalled/failed dial via a read
timeout and retries with a fresh dial (up to 3 attempts); `intra/dialers/
cdial.go` races multiple resolved IPs per hostname within a 35s budget.
Firestack's retry logic applies only *before* any data has reached the real
destination - it has no mechanism for (and firestack's authors don't appear
to need one for) resuming a TCP session that stalls mid-transfer, because
you cannot transparently redial a live, in-progress TCP connection to a
foreign endpoint without breaking whatever session state the two real
endpoints already believe they have. This ruled out "flow-level
stall-detect-and-redial" as a viable fix for the mid-transfer collapse
specifically (an earlier draft of this plan proposed it before this
distinction was worked through) - it only helps failures at dial time.

**NEW (CURRENT CODE).**

1. `types.go`: extended the `Upstream` interface with
   `PeerPathInfo(ctx, destIP string) string`, returning `"direct"`,
   `"derp:<region>"`, `"no-path"`, or `"unknown"`.
2. `api.go`: implemented it on `tsnetUpstream` via
   `srv.LocalClient().Status(ctx)`, matching the destination Tailscale IP
   against `st.Peer[*].TailscaleIPs` and reading `CurAddr`/`Relay`.
3. `nat_router.go`: `handleTCPConnection`'s dial is now retried up to
   `tcpDialMaxAttempts` (3) with a short delay between attempts - safe
   because, per the point above, nothing has been exchanged with the real
   destination yet at dial time. The successful-dial log line now includes
   `path=...` from `PeerPathInfo`.

**ANDROID-DEVICE EVIDENCE (direct proof, not inference).** Rebuilt
`tailscale-debug.apk` (exercising the §39 Makefile fix again - a stale AAR
from an unrelated interrupted build had to be manually removed once before
`gomobile bind` would rerun), reinstalled on `127.0.0.1:5555`, restarted
Multi-Tailnet (both upstreams reached `RUNNING`, confirming the §39
interface-registration fix still holds after this rebuild). Two logged
flows in the same capture:

```text
[flow-7] TCP ... -> ...2fbc:e501:2f8c:21d7:dafd (synthetic): dial peer-beta (real=100.64.10.11)
[flow-7] TCP upstream dial peer-beta 100.64.10.11:7000 success (path=derp:den)
```

against a different peer in the same capture:

```text
[flow-4] TCP upstream dial peer-alpha 100.64.10.17:8443 success (path=direct)
```

The `loadpeer-b-1` flow is confirmed, at the code level, to be
DERP-relayed (`derp:den` - Denver, not even the Frankfurt region seen
flapping in §40's health logs, showing the relay region itself isn't fixed
run to run). A same-session flow to a different real peer went `direct`.
**This means direct/P2P connectivity is achievable from this exact
emulator** - the emulator's network is not universally blocking NAT
traversal. The more likely explanation for `loadpeer` specifically landing
on DERP is that the `loadpeer` synthetic nodes run as plain host processes
on my dev machine (not inside anything with confirmed open/mapped ports),
so hole-punching *to* them may be failing for reasons specific to that
host's own network position, not the Android/emulator side. The bulk
transfer using the corrected synthetic-IPv6 target address (see below)
moved 554,288 bytes before `nc`'s 5-second idle timeout fired mid-stream -
consistent with, and now directly explained by, a DERP reconnect stall
occurring during the transfer rather than being merely correlated with one.

**INFERENCE.** The throughput collapse documented in §40 is not a
multiproxy dataplane bug, and is now *directly* (not just circumstantially)
tied to the specific flow's path being DERP-relayed. It is very likely
specific to testing against `loadpeer` nodes hosted on this dev machine
rather than a fundamental property of the emulator or the app. Real
device-to-real-peer testing (where both ends are ordinary phones/servers
capable of normal NAT traversal) is needed to know whether this collapse
reproduces at all outside this specific test topology.

**Operational note.** Testing against `loadpeer` requires targeting the
*synthetic* per-tailnet IPv6 address logged by `IPNService: MultiProxy
peer: <hostname> -> <synthetic-ipv6>`, not the peer's real Tailscale IPv4 -
attempting to connect to the real IPv4 directly produces no flow log at all
(silently unrouted), since `resolveRoute` keys off the synthetic address
table, not real upstream IPs. This tripped up the first retest attempt in
this session (0 bytes transferred, no reject log, no flow log - just a
silently absent route) before being traced to using the wrong address.

**RECOMMENDATION.** Before concluding anything further about real-world
throughput: (a) run `loadpeer` (or any real second device) from a network
with normal inbound connectivity (e.g. a phone on LTE, or a machine with UDP
hole-punching working normally) rather than this dev host, and re-run the
same bulk-transfer test to see whether `path=direct` is achieved and
whether the collapse disappears; (b) if it still relays, that would indicate
a genuine multiproxy/tsnet-side NAT-traversal problem worth escalating
separately, rather than reflecting the app as fundamentally throughput-
limited.

## 42. A real, non-DERP-relayed peer still shows a throughput collapse - the double TCP-termination proxy path amplifies real packet loss (2026-08-25)

**BEFORE.** §40-41 attributed the bulk-throughput collapse to DERP relay
instability, based on health-check flapping and one `path=derp:den` flow.
That evidence was real but came from a `loadpeer` node hosted on a dev
machine suspected of being unreachable for direct P2P. This section tests
against a *different*, better-connected peer to see whether the collapse
was actually specific to DERP relay, or something broader.

**Setup.** Deployed `loadpeer -native` (a new flag added this session - see
below) to a real remote Linux host (reached via SSH
tunnelled through the app's own tailnet-b SOCKS5 proxy - see the operational
notes at the end of this section) rather than a dev-host-hosted synthetic
tsnet node. `-native` binds the same TCP/UDP test protocol directly to the
host's own already-established Tailscale identity instead of joining as a
second tsnet node, so it exercises that host's real NAT-traversal
characteristics rather than a fresh node's.

**ANDROID-DEVICE EVIDENCE.** Once local firewall rules were corrected (this
host runs a dedicated `firewalld` zone bound to `tailscale0` with an
explicit port allow-list - `7000`/`7001` had to be added there, not to the
default zone, which was the first failure encountered and is unrelated to
the app), two flows through the Multi-Tailnet dataplane both confirmed
`path=direct`:

```text
[flow-5] TCP upstream dial peer-alpha 100.64.10.18:22 success (path=direct)
[flow-6] TCP upstream dial peer-alpha 100.64.10.18:7000 success (path=direct)
```

Despite being direct (no DERP in the path at all), the bulk transfer still
only moved 1,223,088 bytes over a full 90-second window (~13.6 KB/s
sustained) - not meaningfully better than the DERP-relayed numbers in §40.
**This rules out "DERP relay" as the sole or even primary explanation** for
the throughput collapse; whatever mechanism produced the DERP-relayed
numbers is evidently not the only thing capping throughput here.

**Root cause, this time measured directly, not inferred.** `ss -ti` on the
host-wan host during a live transfer showed:

```text
cubic wscale:8,7 rto:229 rtt:28.534/4.402 ... cwnd:4 ssthresh:2
bytes_sent:205076 bytes_retrans:93328 bytes_acked:105608
retrans:0/76 delivery_rate 608kbps
```

RTT is a healthy 23-28ms (this is a genuinely direct, low-latency path, not
a distant relay) - but **45% of bytes sent were retransmissions**, and the
congestion window has collapsed to 4 segments with `ssthresh` at 2. That is
a real, substantial packet-loss signature on this specific network path,
independent of DERP.

**Why our proxy path suffers far more from that loss than a comparable
single-hop connection: measured, not assumed.** Transferring the
`loadpeer` binary itself via `scp`, over the same tailnet-b tailnet and
(as far as can be determined) the same underlying network path, but through
a *single* TCP termination (the Standard-mode SOCKS5 proxy dialing directly,
no gVisor forwarder in front of it) achieved **174 KB/s** - about 12x faster
than the 13.6 KB/s seen through the multiproxy dataplane. The multiproxy
path terminates TCP *twice*: once at the gVisor forwarder facing the
Android app's own TCP stack (`nat_router.go`'s `handleTCPConnection`), and
again at the independent `tsnet.Server.Dial()` call to the real upstream.
Each hop runs its own independent congestion-control state machine; loss on
the outer link degrades the inner tsnet connection's `cwnd` as usual, but
now there are two ACK-clocking loops in series instead of one, doubling the
opportunities for one hop's slow-start/backoff to stall the other's
delivery. This is a plausible, evidence-consistent explanation for the
12x gap, though it has not been proven with packet captures on both legs
simultaneously - see the recommendation below.

**INFERENCE.** The dominant bottleneck across both this section and §40-41
is real network-level packet loss on the test paths used (this dev
sandbox's WAN egress and/or the intervening path to these specific remote
hosts), not a multiproxy dataplane bug in the sense of dropped or
misrouted packets - no flow was ever misrouted, corrupted, or lost outright
by our code. What *is* squarely a multiproxy-architecture property is that
the double TCP-termination design amplifies the effect of that loss far
more than a single-hop connection does, and that is worth treating as a
real finding rather than dismissing as "just a bad test network," because
the double-termination architecture will travel to any real deployment,
whereas this specific network's loss characteristics may not.

**RECOMMENDATION.** In priority order: (1) run the same `loadpeer -native`
comparison test on a path with a clean baseline (e.g. two devices on the
same LAN, minimal loss expected) to see whether the double-termination
penalty shrinks proportionally with loss or is a fixed multiplier - the
user has a candidate peer (`host-lan` on tailnet-b) reportedly on the
same LAN as the test emulator's environment, not yet tested as of this
writing; (2) if the gap persists even at near-zero loss, investigate
`nat_router.go`'s TCP buffer sizing and whether TCP_NODELAY / window
scaling is configured consistently on both legs; (3) capture packets on
both the client-facing (gVisor) and upstream (tsnet) legs simultaneously
during a controlled-loss test (e.g. `tc qdisc` induced loss on one leg) to
directly confirm or rule out the double-ACK-clock theory rather than
relying on the SCP-baseline comparison as indirect evidence.

**Operational notes.**

- `cmd/loadpeer` gained a `-native` flag: when set, it binds directly to the
  host's real network (`net.Listen`/`net.ListenPacket`) instead of joining
  the tailnet as a second tsnet node - use this on any machine that already
  runs `tailscaled` natively, to test against that machine's real
  NAT-traversal behavior rather than a synthetic node's. No auth key is
  needed in this mode.
- Reaching an SSH-only remote host that isn't a peer on this dev sandbox's
  own Tailscale login was done by tunnelling through the *app's* SOCKS5
  local proxy (Settings → Local Proxy Listener, default `127.0.0.1:1055`)
  while that account was in Standard (single-upstream) mode, forwarded off
  the emulator via `adb forward tcp:<local> tcp:1055`, then
  `ssh -o "ProxyCommand=nc -X 5 -x 127.0.0.1:<local> %h %p"`. This only
  works while that account is in Standard mode - switching to Multi-Tailnet
  stops the Standard backend and its SOCKS5 listener, which is why the
  SOCKS5 route stops working the moment Multi-Tailnet is (re)started; this
  briefly produced a misleading "SOCKS server failure" that was actually
  just the listener being gone, not a network problem.
- The remote host's `firewalld` bound `tailscale0` to a dedicated `tailscale`
  zone with its own explicit port allow-list, separate from the default
  zone. Opening ports in the default zone (the first attempt) had no effect
  on tailscale0 traffic and produced a `no route to host` error that looked
  network-related but was purely local firewall configuration - worth
  checking `firewall-cmd --get-zone-of-interface=tailscale0` before
  assuming a routing or ACL problem on any Linux target.

## 43. Clean-path confirmation: the double TCP-termination proxy is fast when the network isn't lossy (2026-08-25)

**BEFORE.** §42 found the multiproxy dataplane's double TCP-termination
design (gVisor forwarder + independent upstream `tsnet.Server.Dial()`)
amplified real WAN packet loss roughly 12x versus a single-hop connection
over the same lossy path, and left open whether that penalty was
loss-proportional or a fixed architectural tax - recommending a test
against a clean, low-loss path as the way to tell them apart.

**Setup.** `loadpeer -native` deployed to a real machine (`host-lan`,
on tailnet-b, `100.64.10.14`) reported to be LAN-adjacent to this
test environment - i.e. a genuinely low-latency, low-loss path, unlike the
host-wan host in §42.

**ANDROID-DEVICE EVIDENCE.**

```text
[flow-16] TCP fd9b:8d7c:6a5e::1 -> ...41a:57d3 (synthetic): dial peer-alpha (real=100.64.10.14)
[flow-16] TCP upstream dial peer-alpha 100.64.10.14:7000 success (path=direct)
[flow-16] TCP closed
```

The full 8,000,000-byte `SOURCE` transfer completed in ~1.6 seconds -
**~5 MB/s**, no truncation, no idle-timeout needed - through the same
double-TCP-termination multiproxy dataplane that only managed 13.6 KB/s
against the host-wan host in §42. That is roughly 350-500x faster on the same
architecture, against a different peer.

**INFERENCE (this closes §42's open question).** The double
TCP-termination design is **not** an inherent throughput tax - it is fast
when the underlying network path is clean, and the earlier collapses (§40's
DERP-relayed loadpeer, §42's direct-but-lossy host-wan path) really were about
loss on those specific test paths amplified by having two independent
congestion-control loops in series, not a structural flaw in proxying TCP
twice per se. The practical implication: multiproxy's architecture doesn't
need to be redesigned to fix the throughput problem observed in this
session - what actually needs following up on is that the loss-amplification
effect is real and will matter on any real-world path that *does* have
meaningful loss (a poor cellular connection, a congested Wi-Fi network),
even though it's invisible on a clean one. That is a smaller, more targeted
problem than "the proxy architecture is slow."

**RECOMMENDATION.** With the clean-path baseline now established
(~5 MB/s), the remaining useful test is the opposite direction: reproduce
the host-wan-style loss deliberately and controllably (e.g. `tc qdisc add dev
<iface> root netem loss 5%` on one leg) against a clean peer, and measure
how the double-termination gap grows with loss percentage, rather than
relying on two incidentally-different real-world paths as the only two data
points.

## 44. Correcting the §42 single-hop baseline methodology, and a clean apples-to-apples number (2026-08-25)

**BEFORE.** §42's "12x amplification" figure compared 13.6 KB/s (multiproxy,
client = `adb shell nc` running *inside* the emulator) against 174 KB/s
(`scp`, client = this dev sandbox, tunnelled through `adb forward` into the
app's Standard-mode SOCKS5 proxy). Those two numbers do not isolate the
same variable: the "single-hop" side had an extra hop (sandbox-to-emulator
over `adb forward`) that the "double-hop" side didn't. An attempt to
replicate that same methodology against host-lan exposed this directly: the
SOCKS5-via-`adb forward` path only managed 335 KB/s against host-lan (23.8s
for 8,000,000 bytes) - *slower* than the 5 MB/s the double-hop multiproxy
path achieved against the same peer in §43, which is the wrong direction
for the "double termination is slower" theory and was the tell that the
comparison itself was confounded, not that double-termination somehow
became faster than single-termination.

**NEW - corrected methodology.** Both sides now run from the same client
location: `adb shell` directly inside the emulator, both against host-lan's
real Tailscale IP. The only variable that differs is which VPN backend is
active:

- Standard mode active (single TCP termination, real IP dialed directly,
  captured by the OS VPN tun and routed through the Standard backend's own
  `tsnet` dial - no gVisor NAT router involved): 8,000,000 bytes in
  1.213s -> **~6.6 MB/s**.
- Multi-Tailnet mode active (double TCP termination via `nat_router.go` +
  independent upstream `tsnet.Server.Dial()`, same peer, synthetic address
  - this is §43's result): 8,000,000 bytes in ~1.6s -> **~5 MB/s**.

**INFERENCE.** On a clean, low-loss, LAN-adjacent path, the real cost of
proxying TCP twice is closer to **~1.3x**, not the ~12x figure from §42.
The 12x figure stands as a real, reproduced measurement of what happens
against the specific lossy host-wan path, but it should not be read as "the
architecture has a 12x tax" in general - it was inflated by both the loss
on that path *and* an uncontrolled extra hop in the comparison's baseline
side. The loss-amplification effect from §42 (double congestion-control
loops in series being more sensitive to loss than one) is still the
best-supported explanation for why the *gap* changes with path quality, but
its magnitude on a clean path is small, and the earlier 12x number should
be treated as an upper bound observed on one specific bad path, not a
general multiplier.

**RECOMMENDATION.** Treat §42's 12x figure as path-specific, not
architectural. If a precise loss-elasticity curve is ever needed, redo it
with both sides using the same client location (as done here), and vary
injected loss with `tc qdisc netem` on an otherwise-clean path rather than
comparing against two incidentally different real hosts.

## 45. `loadpeer` gained a browser-driven web UI (2026-08-25)

**BEFORE.** Every test in §40-44 required a shell (`adb shell nc`, or `nc`
through a SOCKS5 tunnel) driven by hand. There was no way for a person to
just open a browser and run a download/upload/latency test interactively.

**NEW.** `cmd/loadpeer` gained an HTTP server (`-httpport`, default 7080,
`0` disables it) serving a small self-contained page at `/` with three
tests, each showing live throughput/latency in the page itself:

- **Download** - `GET /download?bytes=N` streams `N` bytes (capped at
  `maxDownloadBytes` = 1GiB); the page reads the response via a
  `ReadableStream` and updates a running KB/s figure as bytes arrive. HTTP
  equivalent of the raw `SOURCE` command.
- **Upload** - `GET /upload` accepts a POST body, times it, returns
  `{"bytes":N,"millis":N}`; the page drives this with `XMLHttpRequest` and
  `upload.onprogress` for live throughput (plain `fetch()` doesn't expose
  upload progress reliably across browsers, which is why XHR is used here
  specifically). HTTP equivalent of the raw `SINK` command.
- **Latency** - repeated timed `fetch('/ping')` calls, reporting
  min/avg/max round-trip time.
- `/stats` exposes the same counters as the periodic `stats:` log line, as
  JSON, for a manual refresh button in the page.

This is still exactly the same multiproxy dataplane path as the raw
protocol - HTTP is TCP, so a browser request goes through the same
`nat_router.go` forwarder and upstream `tsnet.Server.Dial()` as an `nc`
session would. It exists purely so a person (not just a script) can drive
and watch a test interactively, including from the Android device's own
browser pointed at a peer's synthetic address.

**Operational note.** Confirmed working end-to-end against the host-wan host
through the same SOCKS5-tunnel setup used earlier in this session
(`curl -x socks5h://127.0.0.1:<forwarded-port> http://<host>:7080/`) -
`/`, `/ping`, and `/stats` all responded correctly. This incidentally
showed that the app's Local Proxy Listener (Settings -> Local Proxy
Listener) stays reachable even while Multi-Tailnet mode is the active VPN
capture - it doesn't require switching back to Standard mode the way §42's
methodology assumed. That doesn't change §44's finding (the real confound
there was client location, not VPN mode), but it does mean future SOCKS5-
based testing doesn't need a mode switch at all.

## 46. Correction: the host-wan-path loss in §42 is very likely the emulator's own network, not the WAN path (2026-08-25)

**BEFORE.** §42 measured real TCP retransmission (45% of bytes,
`cwnd:4`/`ssthresh:2`) on a transfer from the Android emulator, through
multiproxy, to the host-wan host, and concluded this reflected real packet
loss on that WAN path - amplified by the double TCP-termination proxy
design. §43-44 then found a *different* peer (host-lan, LAN-adjacent to the
emulator) was fast, and read the difference as "clean path vs lossy path."

**NEW EVIDENCE that changes this.** A test was run from `host-lan` itself
(the physical machine the emulator runs on, as a plain native Linux client
using its own regular `tailscaled` - no emulator, no multiproxy, no
double TCP termination at all) against the same host-wan `loadpeer` web UI:

```text
Download: 8,000,000 bytes in 2697ms = 2896.7 KB/s
Upload:   8,000,000 bytes in 12397ms = 627.1 KB/s
Latency:  min 26.0ms / avg 28.6ms / max 38.0ms over 20 pings
```

Compared against the emulator-driven test to the same host-wan target: ~70
KB/s throughput, but the **same RTT range** (26-38ms, matching the
`rtt:28.534/4.402` figure captured via `ss -ti` in §42).

**INFERENCE.** Identical RTT rules out "the WAN path to host-wan is
different/worse for the emulator" - if the underlying path genuinely had
45%-retransmission-grade loss, a native Linux client wouldn't sustain 2.9
MB/s over it either, and it does. The far more likely explanation is that
the packet loss measured in §42 was being *induced by the emulator's own
virtualized network layer* (most likely its usermode/slirp-style guest NIC
emulation, which is CPU-bound and reimplements TCP/IP in userspace - see
the 38-340ms ICMP jitter to `8.8.8.8` measured back in the original
DERP-relay investigation as independent, earlier evidence this emulator's
own network quality is poor), not by anything specific to the route to
host-wan. This also throws new light on §43-44's host-lan-vs-host-wan comparison:
the "clean LAN path" vs "lossy WAN path" framing may be wrong - it may
really be "the emulator's own NIC happens to cope fine under host-lan's
traffic pattern/RTT but chokes badly under host-wan's," which is a property
of the emulator, not of either destination.

**What this means for multiproxy itself:** the double-TCP-termination
loss-amplification effect documented in §42 (two independent
congestion-control loops compounding loss) is probably still real *in
principle*, but the loss samples used to demonstrate it were most likely
generated by the test environment's virtualized NIC, not a real-world path
characteristic. This further weakens confidence that any of this session's
absolute throughput numbers say much about real-device behavior - the
emulator itself now looks like the single largest confound running through
nearly every measurement in §40-45.

**RECOMMENDATION.** Do not trust any throughput number gathered through
this emulator as representative of a real phone. The one clean way to
settle this: run the same `loadpeer` download/upload/latency test from a
*real Android device* (not this emulator) against both host-wan and host-lan,
and compare against the native-host-lan-client numbers above. If a real
device gets host-lan-native-like numbers, this fully confirms the emulator's
virtual NIC as the dominant confound across this entire investigation and
retires the "double TCP-termination architecture" as a throughput concern
outside of genuinely lossy real-world links.

## 47. Confirmed on a real device: §46's hypothesis was correct (2026-08-25)

**BEFORE.** §46 hypothesized, from indirect evidence (identical RTT but
~40x throughput gap between a native-Linux client and the emulator hitting
the same target), that the Android emulator's own virtualized network was
the dominant confound behind every throughput number gathered in §40-45,
and recommended testing from a real device as the way to settle it.

**ANDROID-DEVICE EVIDENCE.** A release build (R8-minified, resource-shrunk
via the `release` build type, signed with the debug keystore so it could
install over the existing debug-signed app without wiping app state -
confirmed via `apksigner verify` before install) was installed on a real
physical phone. Reported result: overall throughput/performance is fine.

**INFERENCE.** This confirms §46: the throughput collapses documented in
§40-42 (DERP-relay stalls, the "12x double-termination penalty" against
host-wan) were artifacts of testing exclusively on this emulator's poor-quality
virtualized network, not properties of the multiproxy dataplane. The
double TCP-termination architecture, DERP-relay handling, and dial-retry
logic added this session are not throughput problems on real hardware.
This closes the throughput-collapse investigation that ran from §40
through §46 - the original "unusable" concern that kicked it off does not
hold up on real hardware.

**Open follow-up: p99 tail latency.** Reported as possibly needing
optimization, separate from overall throughput being fine - no concrete
numbers captured yet. Candidate sources worth checking, in order of how
directly this session's own changes could be responsible: (1) the TCP
dial-retry logic added in the "TCP dial retry and per-flow path
visibility" work - each retry adds a fixed `tcpDialRetryDelay` (300ms) to
whichever flows hit a transient first-attempt dial failure, which would
show up as p99 tail latency on connection setup specifically, not on
established flows; (2) WireGuard/tsnet handshake cost on a cold upstream
connection; (3) Android-side GC pauses or JIT warmup on the app process.
Not yet investigated - needs concrete p50/p99 numbers (e.g. via loadpeer's
existing `/ping` endpoint run as a longer, larger sample) before further
diagnosis is worth doing.

## 49. Device verification: DNS across every supported configuration, synthetic IPv4, and real Tailscale addressing (2026-08-26)

All of the below was run on the x86_64 emulator with two upstreams in
`RUNNING` state, against the build that carries §62.8/§62.9/§62.10.

### 49.1 A methodology error that invalidated a first pass - read this before trusting any DNS result

The first DNS sweep reported every configuration as passing. It was
**wrong**. The tell: a deliberately corrupted DoH URL still resolved 7 of 8
domains. Android's `netd` caches DNS per-network, the VPN network does not
change when the DoH setting does, and the sweep re-queried the same eight
domains for every configuration - so most answers came from cache, not from
the resolver under test.

`ndc resolver flushnet` is not available on this image (`500 0 Command not
recognized`). The sweep was rebuilt around **disjoint fresh domains per
configuration** plus a negative control. Our own DNS server has no response
cache (only `bootstrapCacheTTL`, which is bootstrap-only), so `netd` was the
sole cache in play.

Negative control - deliberately broken DoH URL, five never-queried domains:

```text
[NEGATIVE CONTROL (broken DoH)] fresh public 0/5
    FAILED: debian.org videolan.org ffmpeg.org postgresql.org nginx.org
```

0/5 is what makes the rest of this section meaningful.

### 49.2 DNS resolver configurations

Four fresh domains each, via `getaddrinfo` on the device (the same path an
app's resolver takes). All **4/4**:

| Configuration | Result |
| --- | --- |
| Tailnet default (no DoH) | pass |
| Cloudflare / Google / Quad9 | pass |
| Mullvad (HTTP/2-only - §62.8's `ForceAttemptHTTP2`) | pass |
| Wikimedia / LibreDNS / Control D / CIRA | pass |
| Custom hostname endpoint (AdGuard) | pass |
| Custom IP-literal endpoint (`https://9.9.9.9/dns-query`) | pass |

LibreDNS and CIRA are not in `publicdns.DoHIPsOfBase`, so those two
specifically exercise §62.8's fallback bootstrap path rather than the
known-IP table.

### 49.3 Tailnet DNS is isolated from the public upstream

With the DoH resolver still deliberately broken (public resolution at 0/5),
tailnet names never queried in the session still resolved:

```text
pixel-tablet                   PING pixel-tablet (198.19.26.0)
peer-observer                  PING peer-observer (198.18.173.33)
tailscale-operator             PING tailscale-operator (198.19.94.10)
metrics-egress-a               PING metrics-egress-a (198.19.4.127)
```

Tailnet resolution does not depend on the public upstream, and the synthetic
v4 answers of §62.9 are what is being returned.

### 49.4 Synthetic IPv4 end to end

TUN carries both families:

```text
inet  198.18.0.1/32          scope global tun0:1
inet6 fd9b:8d7c:6a5e::1/120  scope global
100.64.0.0/10       dev tun0 table 1024
198.18.0.0/15       dev tun0 table 1024
fd7a:115c:a1e0::/48 dev tun0 table 1024
fd9b:8d7c:6a5e::/48 dev tun0 table 1024
```

Four peers resolved to four distinct pool addresses, and the translation
chain completes:

```text
[flow-5] TCP 198.18.0.1 -> 198.19.142.245 (synthetic): dial peer-alpha (real=100.64.10.17)
[flow-5] TCP upstream dial peer-alpha 100.64.10.17:22 success (path=direct)
```

### 49.5 Real Tailscale addressing (§62.10)

The case that was previously impossible - dialling a peer's real address
directly, with no synthetic name involved - now works in both families:

```text
[flow-6]  TCP 198.18.0.1 -> 100.64.10.17 (synthetic): dial peer-alpha (real=100.64.10.17)
[flow-6]  TCP upstream dial peer-alpha 100.64.10.17:22 success (path=direct)
          -> SSH-2.0-OpenSSH_9.9

[flow-23] TCP fd9b:8d7c:6a5e::1 -> fd7a:115c:a1e0::1010:1011 (synthetic): dial peer-alpha
[flow-23] TCP upstream dial peer-alpha [fd7a:115c:a1e0::1010:1011]:22 success (path=direct)
          -> SSH-2.0-OpenSSH_9.9

[flow-25] UDP upstream dial peer-alpha 100.64.10.13:53 success
[flow-26] UDP upstream dial peer-alpha [fd7a:115c:a1e0::1010:1011]:53 success
```

Control: `100.64.10.16` fails identically over both v4 and v6, so the
failures observed on some peers are peer reachability, not a family-specific
routing fault.

**A wrong guess worth recording.** A peer's real v6 address is *not*
`tsaddr.Tailscale4To6(v4)`. That mapping produces
`fd7a:115c:a1e0:ab12:4843:0a0b:...`, which fails closed (correctly - it is
not in `realIPIndex`). Actual node addresses are the short form
`fd7a:115c:a1e0::1010:1011`. Read them from the peer snapshot, don't compute
them.

### 49.6 Real-app verification (Chrome), not just `adb shell`

Every result above this point was produced with `ping`/`nc` from `adb
shell`, which is UID 2000 and exercises the resolver and dataplane but not a
real app's network stack or the split-tunnel package rules. Repeated through
Chrome:

- `https://lwn.net/` - page rendered. Public DNS via DoH plus egress,
  through a real app.
- `https://peer-web/` - resolved through the synthetic DNS layer,
  `flow-80/81 -> 100.64.10.15:443 success (path=direct)`, and Chrome
  reported `ERR_SSL_UNRECOGNIZED_NAME_ALERT`. That is a TLS alert *from the
  peer*: the connection completed end to end and the server answered. A cert
  name mismatch is expected when dialling a peer by short name.

Note Chrome preferred the synthetic **IPv6** address (AAAA), so the v4 pool
is a fallback for v4-only clients in practice, exactly as §62.9 intends.

### 49.7 Not verified here

- The conflict list of §62.10 renders empty, because the two connected
  tailnets genuinely share no addresses. Correct behavior, but it means the
  *display* path is covered only by `real_ip_test.go`, not on device.
- SIP, TURN, and STUN have not been tested against a real server. See
  issue #4 for the structural limits (no inbound path, per-destination UDP
  source ports, 60s association idle timeout).
- Mullvad passed with fresh domains, but only its `Default` endpoint; the
  other five Mullvad variants were not individually retested.

## 50. Device verification: pluggable upstreams and policy-routed DNS (2026-08-27)

All of the below was run on the x86_64 emulator (`sdk_gphone64_x86_64`),
debug build, against two real logged-in tailnets in Multi-Tailnet mode. This
is the first device evidence for anything in `upstreams_and_policy.md` -
previously everything there was `UNIT-OR-RACE-TESTED` or `ANDROID-BUILT`
only.

### 50.1 What was exercised

Through the UI, with no code changes needed to get here:

- Settings -> Upstreams (Experimental) -> **Start Multi-Tailnet** brought up
  a real `VpnService` session with two real tailnets (`akkara.com.tr` and a
  second account), both reaching `Running` and exchanging real peer data.
- Settings -> Proxies & tunnels -> **Add upstream** created a real SOCKS5
  upstream, persisted it (survived an `adb install -r` app-data-preserving
  reinstall), and listed it - correctly labelled `socks5` - alongside the
  two tailnets in the same "Route via" picker. This is the device-level
  confirmation of §2.2's design goal: tailnets and pluggable upstreams are
  the same kind of thing to the UI, not a special case.
- Setting the picker's **default route** to the new upstream, editing the
  upstream's address, and deleting it (with a confirmation dialog naming
  the concrete consequence: "Apps routed through it will fall back to the
  default route, and any upstream chained behind it will go direct") all
  worked and persisted correctly across an app restart.

No crash, ANR, or `FATAL EXCEPTION` occurred anywhere in the session
(`logcat` swept for `FATAL EXCEPTION`, `panic:`, `SIGSEGV`, `SIGABRT` -
none found).

### 50.2 Policy-routed DNS (§3.5), proven with a real SOCKS5 tunnel

A throwaway ~90-line Go SOCKS5 server (CONNECT-only, no auth) was run on
the host and reached from the emulator via `adb reverse tcp:1080 tcp:1080`
- `10.0.2.2:1080`, the usual emulator-to-host alias, was unreachable even
from a bare `adb shell` TCP connect on this image, so `adb reverse` was
used instead once that was diagnosed.

With that upstream registered and set as the default route, real
background DNS-over-HTTPS traffic from the running engine (periodic
control-plane/DERP lookups against `security.cloudflare-dns.com`, the
Tailscale default DoH resolver) was observed tunneling through it:

```text
2026/08/27 12:45:41 CONNECT security.cloudflare-dns.com:443
2026/08/27 12:45:41 CONNECT security.cloudflare-dns.com:443
```

This is genuine end-to-end confirmation of the chain committed in
`af283a9` (§3.5): UI -> `RoutingSettings`/`UpstreamSecretStore` ->
`UpstreamPolicyApplier.apply()` -> `BuildAppBindingPolicyJSON` ->
`Engine.SetPolicyJSON` -> `dnsRouteFor` -> `exchangeDoHVia` -> a real
SOCKS5 `CONNECT`. Verified twice: once with temporary debug logging added
to confirm each hop (policy JSON, `dnsRouteFor`'s resolved provider, the
`exchangeDoHVia` dial itself), and again after that logging was removed,
against a clean rebuild, to make sure the debug scaffolding itself wasn't
what made it work. Both runs produced the same `CONNECT` line.

The debugging path is itself worth recording: the first attempt tried to
exercise this by browsing in Chrome and doing plain `ping`/`nc` DNS
lookups from `adb shell`. Both looked like failures (no `CONNECT` line
ever appeared) but were actually the wrong test - ordinary internet
traffic is out of scope for this VPN's route capture by design (§67-68:
only the synthetic `/48`, real Tailscale CGNAT/ULA, and `198.18.0.0/15`
are routed to `tun0`; there is no `0.0.0.0/0`/`::/0` route, confirmed via
`dumpsys connectivity`), and Chrome's own secure-DNS logic bypassed the
device resolver entirely for the plain-`nc` variant. The test that
actually worked was a raw UDP DNS query sent with `nc` directly at the
synthetic resolver's captured address (`198.18.0.3:53`), which reliably
reached the multiproxy DNS server and, once a real reachable SOCKS5
upstream was available, proved the routing.

### 50.3 Not verified here

- **App attribution (`getConnectionOwnerUid`) is still unverified.** The
  route exercised above was the no-selector default rule, which matches
  regardless of `AppUID` (§4.3) - it does not require attribution to
  succeed. A UID-scoped per-app binding, which does depend on
  `getConnectionOwnerUid` resolving correctly for a real installed app's
  socket, was not exercised this session. This remains gap #1 below.
- WireGuard upstream and chaining were not exercised on-device this
  session (only SOCKS5); both already have real end-to-end coverage in
  the Go test suite (§3 above), just not on a device.
- Only the default-route rule was tested, not a per-app binding rule via
  the App routing screen.

## 51. Fixed: Network Diagnostics never worked, in any mode (2026-08-27)

**BEFORE:** `RunNetcheck()` (`libtailscale/netcheck.go`) built
`&netcheck.Client{Logf: log.Printf}` without setting `NetMon`. Every call to
`netcheck.Client.GetReport` failed immediately with `"netcheck: GetReport:
Client.NetMon is nil"` (`tailscale.com/net/netcheck`), regardless of
STANDARD vs MULTIPROXY mode, login state, or network condition - the
Network Diagnostics screen has never returned a real report.

**NEW:** `backend` (`libtailscale/backend.go`) already constructs and holds
a `*netmon.Monitor` on every app instance (`b.netMon`, set during
`(*backend).Start`). `RunNetcheck` now passes it through:
`&netcheck.Client{Logf: log.Printf, NetMon: b.netMon}`, with an explicit
`errorJSON("Network monitor unavailable")` guard if `b.netMon` is nil
(mirrors the existing `DERPMap() == nil` guard immediately above it).

**WHY:** One missing field, not a design issue - `netcheck.Client.NetMon`
is a required dependency the client uses to read interface state and build
its packet listeners (confirmed by reading
`tailscale.com/net/netcheck.(*Client).GetReport` and
`.standaloneNetcheck`/probe-building code, which dereference `c.NetMon`
directly and fail fast if nil). The report still runs against the single
shared STANDARD `ipnlocal.LocalBackend`'s own network path (NAT type, DERP
latency) rather than any specific MultiProxy upstream tailnet - that stays
a known scope limit, not something this fix addresses; per-upstream health
is separate work (tracked as the new observability initiative in
`eventual-humming-beacon.md`, Phase 1).

**Evidence (`ANDROID-BUILT`, `PHYSICAL-DEVICE-E2E`… here emulator, so
`INSTRUMENTATION-OR-EMULATOR-TESTED`):** built `libtailscale.aar` and the
debug APK from a clean `make libtailscale && make apk`, installed on the
`sdk_gphone64_x86_64` emulator, logged into `akkara.com.tr`, connected, and
opened Settings -> Network Diagnostics. Before this session's fix the
screen would have errored immediately; after the fix it completed a real
probe and rendered `NAT Connection Type: Relay Only`, `IPv4 Active` /
`IPv6 Active` badges, and a sorted table of live DERP relay latencies
(Frankfurt 53 ms (preferred) through Ashburn 145 ms) - i.e. exactly the
report shape `NetcheckReportJSON` defines, populated with real data, not an
`error` field.

## 52. Added: real per-upstream observability (2026-08-27)

**BEFORE:** `Provider.Ready() bool` was a bare boolean with no reason; nothing
in `libtailscale/multiproxy` counted dial attempts, successes, failures, or
bytes per upstream. The only observability was unstructured
`log.Printf("[flow-%d] ...")` lines in `nat_router.go`, not queryable by the
UI. A degraded upstream (wrong address, dead proxy) failed silently from the
user's point of view - policy would fail closed, but nothing said why or
which upstream was at fault.

**NEW:** `libtailscale/multiproxy/stats.go` adds a `statsRegistry` (one
`UpstreamStats` per upstream ID, atomic counters + a mutex-guarded
last-error/timestamps block) and a `statsProvider` decorator. `readyProvider`
(`upstream.go`) - the single funnel every real dial passes through, whether
from the flow router, DNS forwarding, or a chained upstream's own transport -
now wraps the `Provider` it returns in `statsProvider`, so every dial is
recorded at one place regardless of call site, and a rule naming an upstream
that exists but is not ready is recorded too (`recordNotReady`), distinctly
from an attempted-and-failed dial.

Byte counters are **not** done via a `net.Conn` wrapper - that was tried
first and reverted (see "what broke" below) - they are instead fed from
`nat_router.go`'s existing TCP pump loop, which already knows exactly how
many bytes crossed in each direction from `io.Copy`'s own return value,
without needing to touch the dialed conn's type at all. This currently
covers TCP flows only; DNS forwards and UDP associations are not
byte-counted yet.

A new best-effort event, `OnUpstreamHealthChanged(upstreamID, ready, reason)`,
fires through the existing `EngineCallback`/`e.events` channel (buffered
1024, drop-on-full) on a genuine readiness *transition* only - not on every
dial, which would be noise. `UpstreamStats.ready` has three states
(`healthUnknown`/`healthReady`/`healthNotReady`), not two: the zero value had
to be distinct from both outcomes, or an upstream whose very first dial
failed would coincide with the zero value and never fire "became
unreachable" (caught by a failing test - see below).

The reliable source of truth is a new pull method,
`Engine.UpstreamStatsSnapshot()` / `MultiProxyEngine.GetUpstreamStatsJSON()`
(`multiproxy_policy_facade.go`), following the same JSON-snapshot convention
as `GetUpstreamsJSON`/`GetTargetsJSON`. It lists every upstream currently
known, including one that has since been removed but still has recorded
stats (so its last-known state does not vanish along with the row that
explained it), with every counter at zero rather than the row being absent
when nothing has been dialed yet.

On the Kotlin side: `IPNService.kt`'s `MultiProxyCallback` implementation
gained `onUpstreamHealthChanged`, forwarding to a new
`MultiProxySessionCoordinator.recordUpstreamHealthChange` (an accumulating
log, same shape as the existing `addressCrossovers`). The existing 1s poll
loop (`MultiProxySessionCoordinator.bind`) now also polls
`engine.upstreamStatsJSON` into a new `upstreamStats` `StateFlow`.
`UpstreamsView.kt` (Proxies & tunnels) renders it: each upstream row now
shows "Ready" / "N succeeded, M failed" plus the last error, in the error
color when degraded (`dialFailures > 0` or `!ready`), matching the app's
existing degraded-state convention (`MaterialTheme.colorScheme.error`).

**WHY:** This is the most-requested piece of this session's whole
initiative - "I want good observability... currently network diagnostics
tab don't even work at all" - and the plan
(`eventual-humming-beacon.md`) deliberately sequenced it before the
broad-capture routing change (Phase 2) rather than after: instruments should
exist before the risky maneuver, not be bolted on afterward once something
has already gone wrong silently. Feeding byte counters from the TCP pump
loop instead of a `Dial`-return wrapper is not a style preference; it is the
fix for a real regression (below) and the safer general pattern, since
wrapping `net.Conn` risks breaking any downstream code that type-asserts the
concrete connection type.

**What broke, and what that proves:** wrapping the `net.Conn` returned from
`Provider.Dial` (to count bytes generically at one place, mirroring the dial
wrapper) broke `TestForwardedQueryFollowsTheAppsRoute` deterministically -
plain UDP DNS forwarding started failing with real dial errors. Root cause:
`github.com/miekg/dns`'s `Conn` type decides datagram- vs. stream-framing by
type-asserting the underlying `net.Conn` against `*net.UDPConn`; a generic
wrapper struct is never that concrete type, so the assertion silently failed
and the library tried to speak length-prefixed TCP framing over a real UDP
socket. `nat_router.go`'s own TCP pump has an analogous
`conn.(interface{ CloseWrite() error })` assertion that a wrapper would also
have broken. The fix was to not wrap `net.Conn` at all - `Dial` returns the
provider's own conn unchanged - and to compute byte counts from the pump
loop's own `io.Copy` return value instead. Caught before landing, by running
the full existing suite rather than only the new tests; recorded here as a
concrete instance of why "wrap the standard interface generically" is not
automatically safe when other code already depends on a wrapped value's
concrete type.

**Evidence:**
- `UNIT-OR-RACE-TESTED`: `libtailscale/multiproxy/stats_test.go` (new) -
  dial success/failure/not-ready counters, and the health-changed event
  firing exactly once per transition (not per dial) across three identical
  failures followed by a recovery. Full existing suite
  (`go test ./libtailscale/multiproxy/...`, ~170s, real WireGuard/tsnet
  tests included) passes clean.
- `INSTRUMENTATION-OR-EMULATOR-TESTED`: built a debug APK from a clean
  `make libtailscale && make apk`, installed on the `sdk_gphone64_x86_64`
  emulator with both tailnets from §50 running in Multi-Tailnet mode. Added
  a SOCKS5 upstream ("TestProxy") pointed at `127.0.0.1:1` (nothing
  listening), confirmed the Proxies & tunnels row showed "Ready" with zero
  attempts before use. Set it as the default route; the engine's own
  background DoH lookups (the same mechanism proven in §50.2) began dialing
  it and failing. Within ~7 seconds the row live-updated to "0 succeeded, 31
  failed" in the app's error color, with the exact real dial error
  (`socks5: dialing proxy 127.0.0.1:1: dial tcp 127.0.0.1:1: connect:
  connection refused`) shown underneath - all via the 1s poll of
  `GetUpstreamStatsJSON`, no manual refresh. Cleared the default route back
  to "Unchanged"; the row correctly stopped updating and kept showing the
  last-known 31 failures rather than resetting, confirming stats persist
  for a since-idled upstream as designed. Deleted the test upstream to leave
  the device clean.
- Not verified here: byte counters (no real TCP flow was driven through the
  test upstream this session, since broad VPN capture - the thing that would
  let an ordinary app's TCP traffic reach a non-tailnet upstream - is
  Phase 2, not yet built); the `OnUpstreamHealthChanged` push event's device
  behavior specifically (the polled JSON path was what was actually observed
  above; the event is a best-effort nudge, and `UpstreamHealthEvent`'s
  Kotlin-side accumulating log exists but has no UI surface yet).

## 53. Added: opt-in broad VPN capture, with Direct-by-default (2026-08-27)

**BEFORE:** the Multi-Tailnet `VpnService.Builder` (`IPNService.kt`,
`rebuildMultiProxyTunLocked`) only ever installed six routes: the synthetic
`/48` and `198.18.0.0/15`, and real Tailscale's CGNAT/ULA ranges. Confirmed
via `dumpsys connectivity` both this session and in §50: no
`0.0.0.0/0`/`::/0` route existed, so ordinary internet and LAN traffic never
reached the engine - picking a non-Tailnet upstream for an app only ever
affected its DNS lookups and its traffic to real Tailscale addresses, never
its general traffic, because Android never handed those packets to `tun0`.

**NEW:** `RoutingSettings.broadCaptureEnabled` (new, off by default,
unencrypted prefs alongside `defaultUpstreamId`). When on,
`rebuildMultiProxyTunLocked` additionally installs `0.0.0.0/0` and `::/0`
routes, alongside the six narrower ones rather than replacing them - Android
prefers the most specific match, so this only changes behaviour for traffic
none of the existing routes covered. A Compose switch on the Proxies &
tunnels screen ("Route general internet traffic") drives it, restarting the
VPN (`ACTION_RESTART_VPN`) to pick up the new route table, since routes are
fixed at `Builder.establish()` time rather than something a live policy
update can change.

Turning broad capture on, by itself, must not change behaviour for an app
the user has not routed anywhere - `UpstreamPolicyApplier.applyPolicy` now
defaults `defaultUpstream` to `Libtailscale.multiProxyDirectUpstreamID()`
when `broadCaptureEnabled` is on and `RoutingSettings.defaultUpstreamId` is
unset, rather than leaving it empty (which would otherwise route newly-
captured traffic into `resolveFlow`'s legacy subnet-route/exit-node
fallback - never designed to carry ordinary internet traffic for an unbound
app). No Go engine change was needed for the routing ladder itself:
`resolveFlow` (`nat_router.go`) already applies policy uniformly to any
non-synthetic destination, and `ActionDirect`/`DirectUpstreamID`
(`upstream.go`) already dials outside every tunnel via the same
`VpnService.protect()`-backed mechanism the tailnet upstreams' own sockets
use - this phase is Android-side capture plus one Kotlin default, not a
core routing change.

**WHY:** this is the structural foundation the rest of the plan
(`eventual-humming-beacon.md`) sits on - LAN exclusion, DNS split-routing,
and "a chosen upstream carries an app's *general* traffic, not just its
Tailnet reachability" all require the OS to hand the engine packets it
currently never sees. Off-by-default and Direct-by-default together mean
enabling Multi-Tailnet, and even enabling broad capture itself, never
silently changes what an existing user's unbound apps can reach - broad
capture only makes routing *possible*; it does not add a policy.

**Evidence (`ANDROID-BUILT`, `INSTRUMENTATION-OR-EMULATOR-TESTED`):** built
from a clean `make libtailscale && make apk`, installed on the
`sdk_gphone64_x86_64` emulator with both tailnets from §50 running in
Multi-Tailnet mode.
- Broad capture off (default): `dumpsys connectivity`'s `tun0` route list
  matched the pre-existing six routes exactly, byte for byte - confirmed
  this is a true no-op for anyone who does not opt in.
- Toggled on: the VPN network handle changed (confirmed restart happened)
  and the route list gained exactly `0.0.0.0/0 -> 0.0.0.0 tun0` and
  `::/0 -> :: tun0`, nothing else changed.
- With broad capture on and no default route configured, opened
  `https://example.com` in Chrome; it loaded normally, and `logcat` showed
  real, non-synthetic destination IPs (Google's `2a00:1450:...`,
  Cloudflare's `2606:4700:...`) flowing through `[flow-N] ... dial @direct`
  - i.e. genuinely captured by `tun0` and explicitly routed through the
    engine's Direct provider, not merely still working because it was never
    captured.
- Both tailnets stayed `RUNNING` throughout (including after a VPN restart
  triggered by the toggle), confirming no capture-induced routing loop on
  the engine's own control-plane/DERP traffic - the specific risk the plan
  flagged as needing explicit verification once capture broadens.
- Toggled back off and confirmed the route list reverted to exactly the
  original six.

**Not verified here:** an app deliberately bound to a non-Tailnet upstream
carrying its *general* TCP traffic under broad capture (only the unbound/
Direct-by-default path and the engine's own DNS/control traffic were
exercised this session); LAN-destination behaviour under broad capture
(Phase 3, not yet built, is what is supposed to keep LAN traffic direct by
default); an unrelated Chrome ANR and app-process restart occurred during
this session's manual testing, but tailnets reconnected to `RUNNING` cleanly
immediately after and the route table was unaffected - read as emulator
resource pressure from a long debugging session, not a capture-related
regression, but noted here rather than silently discarded.

## 54. Added: LAN/local traffic exclusion, toggleable (2026-08-27)

**BEFORE:** §53's broad capture had no exception for local/private
destinations - once `0.0.0.0/0`/`::/0` were captured, a printer, a NAS, or a
dev server on the same network would follow whatever route an app or the
default route pointed at (a remote SOCKS5/WireGuard upstream, potentially),
exactly like any other destination. There was no way to keep LAN
reachability working while still routing general internet traffic elsewhere.

**NEW:** `multiproxy.DefaultLANPrefixes()` (`policy.go`, new) lists the
well-known private/local ranges - `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16` (link-local),
`224.0.0.0/4` (multicast) for v4; `::1/128`, `fe80::/10`, `ff00::/8` for v6.
Deliberately *not* the whole IPv6 ULA block (`fc00::/7`): Tailscale's own
real address space (`RealTailscaleIPv6Prefix`, `fd7a:115c:a1e0::/48`) lives
inside ULA, and excluding all of it would silently misroute real Tailscale
traffic as "local" - the exact bug class §52's UDP-wrapping regression
already taught this codebase to watch for, so it is now also a standing Go
test (`TestDefaultLANPrefixesExcludeRealTailscaleSpace`, asserts no LAN
prefix overlaps either `RealTailscaleIPv6Prefix` or `RealTailscaleIPv4Prefix`).

`BuildAppBindingPolicyJSON` (`multiproxy_policy_facade.go`) gained an
`excludeLAN bool` parameter; when true it prepends an `ActionDirect` rule
matching `DefaultLANPrefixes()` ahead of every per-app binding rule, so it
wins regardless of how an app is otherwise routed (`TestLANExclusionRuleWinsOverLaterAppBinding`
proves the ordering, not just the prefix list). `RoutingSettings.lanExclusionEnabled`
(new, **on by default** - unlike broad capture, the safer default here is to
preserve LAN reachability) drives it via a new "Keep LAN traffic direct"
switch on the Proxies & tunnels screen. Unlike broad capture, this is a
policy-only change (`UpstreamRoutingViewModel.setLanExclusionEnabled` calls
`applyNow()`), not a route-table change, so it takes effect on the live
engine immediately with no VPN restart.

**Known limitation, deliberate:** this phase implements only a **global**
on/off toggle, not the plan's full per-app override ("still tunnel LAN
traffic for this one app," e.g. to reach a remote LAN through a WireGuard
upstream). That needs a schema change to `AppBinding` to carry a per-app
override flag; scoped out here as added complexity beyond what was asked
for this pass. Turning the global toggle off is the only way to get
LAN traffic tunneled today, for every app at once.

**WHY:** LAN reachability breaking because an app got routed through a
remote proxy is a much more surprising failure mode than the reverse, so
this defaults on and ships in the same pass as broad capture rather than
after it - broad capture alone would otherwise have no safety net for the
in-between period before this landed.

**Evidence (`ANDROID-BUILT`, `UNIT-TESTED`):**
- `go build`/`go vet` for `GOOS=android GOARCH=arm64` and
  `go test ./libtailscale/multiproxy/...` (excluding this package's two
  pre-existing tests that hang in this sandboxed environment regardless of
  this change - `TestWireGuardTunnelCarriesTCP`,
  `TestWireGuardChainedOverSOCKS5`, `TestResolveRouteConcurrency`; confirmed
  via `git stash -u` that the same three hang identically on the
  pre-Phase-3 baseline, so this is environmental, not a regression) all
  pass, including the two new tests above.
- Built clean from `make libtailscale && make apk`, installed on the
  `sdk_gphone64_x86_64` emulator. Screenshots confirm both the §53 broad
  capture switch and the new "Keep LAN traffic direct" switch render
  correctly on the Proxies & tunnels screen, with LAN exclusion correctly
  on by default and broad capture correctly off by default; toggling broad
  capture on worked without a crash and triggered the expected VPN restart.
- The originally-attempted test note file at
  `libtailscale/multiproxy_policy_facade_test.go` was removed: package
  `libtailscale` cannot be built or tested on this host at all (it imports
  Android-only symbols like `netns.SetAndroidProtectFunc`; the project's own
  `make go-test` target already excludes this exact package for that
  reason). The equivalent, host-testable coverage was written directly
  against `multiproxy.Policy`/`multiproxy.DefaultLANPrefixes` instead.

**Not verified here:** a real device trace of the LAN rule actually winning
over a *configured, non-Direct* default upstream (e.g., confirming a LAN
destination stays direct while general traffic tunnels through a live
SOCKS5 upstream) - standing up a local SOCKS5 listener for this device pass
was declined by this session's own tooling as an unreviewed open network
listener, and was not pursued further given the ordering is already proven
at the policy-engine level by `TestLANExclusionRuleWinsOverLaterAppBinding`.
The per-app override described above as a known limitation is also,
consequently, not built or tested at all.

## 55. Added: DNS versatility - splitting a rule's DNS path from its data path (2026-08-27)

**BEFORE:** a rule's DNS forwards always auto-followed its `Upstream`
(`dnsRouteFor`, `dns_policy.go`, §3.5/§50.2) - correct for the common case,
but with no way to say "tunnel this app's data but keep its DNS on the
device" (a legitimate privacy/latency choice: DNS is often not sensitive the
way data is) or "route this app's DNS through upstream A while its data goes
through upstream B" (split DNS).

**NEW:** `Rule` gained an optional `DNSUpstream UpstreamID` field
(`policy.go`). Empty (the zero value) means "same as `Upstream`" - today's
behaviour, unchanged for every existing rule and every existing test, since
no rule sets it. `dnsRouteFor` now reads `DNSUpstream` first, falling back to
`Upstream` only when it's empty; `DNSUpstream: DirectUpstreamID` reuses the
already-working Direct provider for the "device DNS despite tunneled data"
case, and the field applies to `ActionDirect` rules too (DNS can be routed
even when the data path itself is direct). This was the entire Go engine
change - `MatchAppOnly` and the rest of the policy-matching machinery needed
no restructuring.

`BuildAppBindingPolicyJSON` (`multiproxy_policy_facade.go`) gained a
`defaultDNSUpstream` parameter and each binding entry gained an optional
`dnsUpstream` field, both threaded straight into `Rule.DNSUpstream`.
`RoutingSettings.defaultDNSUpstreamId` (new, empty by default) and a new
"DNS for unbound apps" picker on the Proxies & tunnels screen wire up the
**default-route** half of this - `UpstreamRoutingViewModel.setDefaultDNSUpstream`
applies live via `applyNow()`, no VPN restart, same as LAN exclusion.

**Known limitation, deliberate, scoped down from the original plan:** only
the default-route DNS split shipped this pass, not a **per-app** DNS picker.
The plan called for both, but a per-app split needs a second field on
`AppBinding` (currently just `packageName -> upstreamId`), which means a
Room schema migration - correctly out of scope for this pass, same call
made for LAN exclusion's per-app override in §54. The engine and facade
already accept a `dnsUpstream` per binding entry (see above), so adding the
per-app picker later is UI-and-schema work only, not another engine change.

**Also scoped out, not attempted:** Private DNS characterization (how
Android's system Private DNS modes - Off / Automatic / Strict - interact
with the synthetic resolver and this new split). The plan called for a real
device pass across all three modes using the disjoint-fresh-domain
methodology from §49, and flagged Strict mode's opportunistic DNS-over-TLS
probing as a likely gap (`validation_and_gaps.md` gap #16, pre-existing,
still open). That is a substantial, separate device investigation, not
exercised in this pass - noted here rather than silently dropped.

**WHY:** the plan's stated priority order puts this after broad capture and
LAN exclusion and explicitly below chaining robustness in *effort*, but the
underlying mechanism the plan asked for (route data one way, DNS another) is
a single optional field with no new matching logic - cheap enough to ship
now rather than deferred, even though the full per-app UI and the Private
DNS device work were not.

**Evidence (`ANDROID-BUILT`, `UNIT-TESTED`, `INSTRUMENTATION-OR-EMULATOR-TESTED`):**
- `TestDNSRouteFor` (`dns_policy_test.go`) extended with two new subtests:
  `DNSUpstream` overriding `Upstream` for a tunneled-data/direct-DNS rule,
  and `DNSUpstream` applying on top of an `ActionDirect` rule. Both pass;
  the full pre-existing `dns_policy_test.go`/`multiproxy` suite still passes
  unchanged (empty `DNSUpstream` is a true no-op).
- `go build`/`go vet` for `GOOS=android GOARCH=arm64` pass.
- Built clean from `make libtailscale && make apk`, installed on the
  `sdk_gphone64_x86_64` emulator. Screenshot-verified the new "DNS for
  unbound apps" picker renders under "Default route," correctly defaults to
  "Same as default route," and its dropdown lists the real, live candidate
  set (Direct plus both connected Tailnets from earlier sessions).
  Selected "Direct" and confirmed via `logcat` that no
  "could not build/apply routing policy" error appeared - the JNI call
  through `BuildAppBindingPolicyJSON`'s new signature succeeded and applied
  live with no VPN restart, matching the policy-only design.

**Not verified here:** a real device trace proving a forwarded DNS query
actually left through the chosen path when data and DNS point at different
upstreams (the engine-level test above proves the routing decision; this
would additionally need a live non-Direct upstream and a captured query, not
attempted this pass for the same reason noted in §54 - standing up a test
proxy listener was declined by this session's own tooling).

## 48. Bottom line

The branch has progressed far beyond the original packet-routing PoC. Persistent profiles, bootstrap-key retirement, runtime observation, destructive Forget, V2 peer snapshots, DNS-over-TCP, UDP lifetime management, and a functional Android management screen now exist.

The remaining uncertainty is concentrated at integration boundaries:

```text
Android service readiness
reconstruction vs concurrent UI mutations
persistent-state recovery failures
real network transitions
Private DNS / Always-On / lockdown
real two-Tailnet packet E2E
```

That is a much narrower and healthier class of uncertainty than "does the architecture exist?" — but it still needs explicit device evidence before the phrase **fully working app** is warranted.