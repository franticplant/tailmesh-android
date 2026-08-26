**Multi-Tailnet Proxy for Android — Documentation Map**

This directory is the canonical engineering documentation for the multi-Tailnet work on `main`.

The documents are repository-first. They describe the current implementation, separate implemented behavior from device validation, and call out gaps rather than silently preserving older design assumptions.

## 1. What the system currently is

MULTIPROXY is a second Android VPN operating mode built around:

```text
one Android VpnService
        |
one synthetic IPv6 /48
        |
one gVisor userspace stack
        |
exact synthetic target lookup
        |
one required UpstreamID
        |
one of several independent tsnet.Server runtimes
```

Its core purpose is to let one Android device address peers in multiple independent Tailnets simultaneously, including cases where those Tailnets overlap in native Tailscale IP space.

The canonical Android-facing peer identity is deterministic IPv6 under:

```text
fd9b:8d7c:6a5e::/48
```

The first `/120` is reserved for local control addresses:

```text
fd9b:8d7c:6a5e::1   VPN interface
fd9b:8d7c:6a5e::3   synthetic DNS
```

There is no active synthetic IPv4 peer namespace.

## 2. Read these documents in order

### 2.1 `architecture.md`

The whole-system model.

Read this first for:

- why native Tailnet addresses are insufficient identity;
- `UpstreamID`, `TargetKey`, and deterministic synthetic IPv6;
- identity versus current locator;
- Android capture versus gVisor versus Tailnet route policy;
- STANDARD/MULTIPROXY arbitration;
- persistent profile, bootstrap-secret, runtime, Engine, and TUN lifetimes;
- profile provisioning, reconstruction, and Forget semantics;
- major architectural invariants.

### 2.2 `backend_internals.md`

The Go implementation manual.

It follows:

- every important `Engine` state field and lock;
- Tailnet registration/enable/disable/remove/forget/close;
- `tsnet.Server` creation;
- immediate + ten-second status polling;
- snapshot replacement and collision rejection;
- DNS tables and DNS UDP/TCP behavior;
- exact/subnet/exit route precedence;
- TCP forwarding;
- 60-second idle UDP association lifecycle;
- gVisor/TUN FD ownership;
- runtime/peer snapshot APIs;
- Gomobile facade;
- shared Android network-hook ownership.

### 2.3 `android_profiles_and_ui.md`

The Android product/lifecycle manual.

It covers:

- `App` and `MultiProxySession` lifetime;
- `IPNService` modes and transitions;
- synchronous STANDARD ACK barriers;
- MULTIPROXY TUN construction;
- physical/non-VPN `Network` selection;
- SQLite profile schema;
- immutable profile UUID;
- Android encrypted bootstrap-key storage;
- `MultiProxySessionCoordinator`;
- provisioning `PROVISIONING -> READY/ERROR`;
- auth-key retirement after observed `RUNNING`;
- enable/disable/rename/Forget;
- service/process reconstruction;
- runtime-state and peer snapshot polling;
- Compose management UI.

### 2.4 `data_path_and_dns.md`

The flow manual.

Use it when debugging or learning how a connection actually moves.

It traces:

- peer discovery becoming a target route;
- synthetic DNS AAAA;
- ambiguous short names;
- authoritative NODATA;
- ordinary DNS forwarding;
- UDP-to-TCP DNS retry;
- direct DNS-over-TCP framing;
- synthetic TCP;
- synthetic UDP;
- overlapping native IPs;
- stale synthetic addresses;
- native-IP changes;
- Tailnet disable/re-enable;
- process reconstruction;
- ordinary Internet bypass;
- Tailscale underlay socket protection;
- Wi-Fi/cellular and DNS changes.

### 2.5 `validation_and_gaps.md`

The evidence ledger.

It distinguishes:

```text
implemented
unit/race tested
Android built
instrumentation/emulator tested
physical-device E2E
```

It also records the real remaining seams, including service-ready signalling, reconstruction serialization/error surfacing, Android test coverage, database migration policy, Private DNS, Always-On/lockdown, scoped IPv6 DNS, legacy API cleanup, and physical-device two-Tailnet validation.

## 3. Current feature state

| Area | Current branch state |
|---|---|
| Multiple independent `tsnet.Server` runtimes | implemented |
| Immutable Android profile UUID -> `UpstreamID` | implemented |
| Deterministic synthetic IPv6 | implemented |
| Overlapping native IPv4 separation | locally tested |
| Peer snapshot replacement | implemented and locally tested |
| Synthetic collision fail-closed | implemented and tested |
| Unknown synthetic `/48` address fail-closed | implemented |
| Synthetic AAAA DNS | implemented |
| Known synthetic A/unsupported RR NODATA | implemented/tested |
| Ambiguous short-name rejection | implemented/tested |
| Qualified `.proxy.` names | implemented |
| Local DNS over UDP | implemented |
| Local DNS over TCP | implemented |
| Upstream UDP -> TCP retry | implemented |
| TCP peer proxy | implemented |
| UDP peer proxy | implemented |
| UDP idle expiry | implemented, 60 seconds |
| One Android TUN | implemented |
| Go ownership of detached TUN FD | implemented |
| STANDARD/MULTIPROXY serialized ownership | implemented |
| Tokenized process-global protect/bind hooks | implemented |
| Non-VPN physical underlay tracking | implemented |
| Persistent profile SQLite DB | implemented |
| Encrypted bootstrap key | implemented |
| Provisioning state machine | implemented |
| Bootstrap-key retirement on `RUNNING` | implemented |
| Runtime-state snapshot/UI | implemented |
| Canonical V2 peer snapshot/UI | implemented |
| Enable/disable/rename/Forget UI | implemented |
| Persisted state deletion on Forget | implemented |
| Process/service profile reconstruction | implemented, with documented orchestration seams |
| Internal Go subnet/exit route APIs | implemented internally, not exposed by current Android capture |
| Physical Android two-Tailnet E2E | not established by repository evidence reviewed here |

## 4. Four state domains to keep separate

### 4.1 Persistent desired profile

```text
SQLite TailnetProfile
    id
    displayName
    enabled
    provisioningState
    timestamps
```

### 4.2 Bootstrap secret

```text
encrypted SharedPreferences auth_key_<profileId>
```

Expected to be deleted after first successful `RUNNING` state.

### 4.3 Live Tailnet runtime

```text
TailnetRuntime
    tsnet.Server
    watcher
    Enabled
```

Observed through `GetTailnetStatesJSON()`.

### 4.4 TUN attachment

```text
Android PFD -> detached FD -> gVisor stack
```

This can be replaced without changing the conceptual profile identity.

## 5. Three routing planes to debug separately

```text
A. Android capture
   app eligibility + /48 Builder route

B. userspace transport and target routing
   gVisor + target directory + resolveRoute

C. Tailnet egress
   selected tsnet.Server + current native locator
```

A failure in C is not evidence that Android route capture failed. A failure in A cannot be fixed by changing `tsnet.Dial`.

## 6. Current identity chain

```text
Android TailnetProfile.id
        |
        v
Go UpstreamID
        |
        +-----------------------------+
        |                             |
        v                             v
profile state-dir hash          TargetKey.NamespaceID
                                      |
                     Tailscale StableNodeID + kind
                                      |
                                      v
                             deterministic IPv6
```

Display name is intentionally absent from this chain.

## 7. Current provisioning chain

```text
Add profile
    |
create UUID + PROVISIONING + enabled
    |
encrypted bootstrap auth key
    |
ensure MULTIPROXY Engine
    |
AddTailnet(id, key, true)
    |
observe runtime every 1s
    |
RUNNING
    |
READY
    |
clear Go AuthKey
    |
delete encrypted auth key
```

A READY profile is expected to reconstruct from its deterministic `tsnet` state directory with an empty auth key.

## 8. Current observation clocks

| Owner | Interval | Meaning |
|---|---:|---|
| Go Tailnet watcher | immediate then 10s | rebuild routing/DNS peer truth and report backend state |
| Android coordinator | 1s | observe Tailnet runtime state and complete provisioning |
| Android ViewModel | 2s | display current V2 peer snapshot |

Callbacks remain useful observations but are not the authoritative UI database.

## 9. Disable versus Forget

**Disable** preserves identity:

```text
stop runtime
clear active targets/DNS
keep profile UUID
keep profile row
keep tsnet state directory
```

**Forget** destroys local profile identity:

```text
remove live runtime
remove persisted tsnet state directory
remove encrypted auth key
remove SQLite profile row
```

A future re-add therefore creates a new UUID and may produce different synthetic peer identities.

## 10. Canonical source-reading map

```text
libtailscale/multiproxy/types.go
    stable identity and route types

libtailscale/multiproxy/api.go
    Engine and Tailnet lifecycle

libtailscale/multiproxy/dns.go
    snapshots, collision handling, DNS UDP/TCP

libtailscale/multiproxy/nat_router.go
    exact/subnet/exit routing and TCP/UDP flows

libtailscale/multiproxy/tun_interceptor.go
    gVisor stack and FD ownership

libtailscale/multiproxy/runtime_state.go
    observed runtime snapshots and key clearing

libtailscale/multiproxy/state_path.go
    persisted state path/deletion

libtailscale/multiproxy/targets_export.go
    canonical V2 peer snapshot

libtailscale/multiproxy_facade.go
    Gomobile API

android/.../IPNService.kt
    mode/TUN/service lifecycle

android/.../NetworkChangeCallback.kt
    non-VPN physical underlay and DNS selection

android/.../multiproxy/db/
    persistent desired profile state

android/.../multiproxy/CredentialStore.kt
    encrypted bootstrap secrets

android/.../MultiProxySessionCoordinator.kt
    product-level runtime/profile orchestration

android/.../MultiProxyViewModel.kt
android/.../MultiProxyView.kt
    current management/peer UI

libtailscale/backend.go
    STANDARD backend and shared process-global Android hooks
```

## 11. Source discipline

When extending these docs, label statements mentally as one of:

```text
CURRENT CODE
    direct behavior in current branch

TEST EVIDENCE
    executable local proof

ANDROID / DEVICE EVIDENCE
    actual platform execution

INFERENCE
    conclusion from surrounding implementation

RECOMMENDATION
    proposed change, not current behavior
```

Do not turn a recommendation into a description of current code.

## 12. Known important gaps

The detailed ledger is in `validation_and_gaps.md`, but the main remaining areas are:

- explicit MULTIPROXY service-ready acknowledgement instead of waiting only for `session.engine != null`;
- serialization of startup reconstruction with interactive coordinator mutations;
- profile-scoped surfacing of reconstruction failures;
- Android tests for profile/credential/coordinator/reconstruction behavior;
- non-destructive future SQLite migrations;
- strict Private DNS behavior;
- Always-On and lockdown behavior;
- scoped/link-local IPv6 DNS observation;
- real Wi-Fi/cellular recovery;
- two live Tailnets and real TCP/UDP E2E on Android;
- legacy/debug API/development debris cleanup before merge.

## 13. Bottom line

The current branch is no longer only an architecture PoC. It contains a persistent multi-profile Android control plane, temporary encrypted provisioning credentials, runtime reconstruction, a single synthetic-only Android VPN, deterministic peer identity, collision-safe snapshots, TCP/UDP userspace proxying, DNS over UDP/TCP, bounded UDP associations, explicit mode/hook ownership, and a functional settings UI.

The remaining work is best thought of as **integration proof and lifecycle hardening**, not invention of the core multi-Tailnet mechanism.