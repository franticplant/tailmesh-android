**Android / Go Source Evidence Map**

**Document status:** current repository evidence index for `main`.

This file is intentionally narrower than the full manuals under `docs/multi_tailnet_proxy_app/`. Its job is to answer:

> Which current source files establish each major Android/Go lifecycle claim?

Older versions of this file described MULTIPROXY integration as a future inference. That is no longer accurate: the integration, persistent profiles, runtime coordinator, DNS TCP path, UDP lifetime, and UI now exist in the branch.

## 1. Normal STANDARD VPN startup

**Android**

- `android/src/main/java/com/tailscale/ipn/IPNService.kt`
  - `ACTION_START_VPN` persists `selectedMode=STANDARD` and `wantRunning=true`.
  - `transitionTo(VpnRuntimeMode.STANDARD)` serializes mode ownership with `transitionMutex`.
  - Kotlin calls `Libtailscale.requestVPN(this)` and only publishes `activeMode=STANDARD` when Go returns success.
  - `newBuilder()` supplies the ordinary Tailscale `VPNServiceBuilder`, including existing MDM/user app-selection behavior.

**Go**

- `libtailscale/callbacks.go`
  - owns `onVPNRequested`, `onDisconnect`, and their completion acknowledgement channels.
- `libtailscale/backend.go`
  - receives the STANDARD request;
  - acquires token `STANDARD-<IPNService.ID>` through `AcquireAndroidNetworkHooks`;
  - calls `DebugRebind()` after hook installation;
  - associates the service;
  - runs `updateTUN` when required;
  - acknowledges success only after immediate startup work succeeds;
  - acknowledges failure if hook acquisition or TUN startup fails.
- `libtailscale/net.go`
  - contains the normal Tailscale Android TUN configuration/update path consumed by STANDARD mode.

## 2. STANDARD teardown completion

**Android**

`IPNService.transitionTo` calls blocking `Libtailscale.serviceDisconnect(this)` before another mode can start.

**Go**

`backend.go` handles the matching disconnect by:

```text
devices.Down()
CloseTUNs()
ReleaseAndroidNetworkHooks("STANDARD-" + service.ID)
vpnService.service = nil
onDisconnectAck <- true
```

The acknowledgement therefore acts as a teardown barrier, not merely channel delivery acknowledgement.

## 3. Shared socket-protection boundary

**Go**

`libtailscale/backend.go` defines process-global:

```text
hookOwner
hookMu
AcquireAndroidNetworkHooks
ReleaseAndroidNetworkHooks
```

Only one owner token may control Tailscale's Android `netns` callbacks at a time.

Installed callbacks call:

```text
IPNService.Protect(fd)
AppContext.BindSocketToNetwork(fd)
```

**Android**

- `IPNService` subclasses `android.net.VpnService`, satisfying the protect callback across Gomobile.
- `App` implements `BindSocketToNetwork` using the selected `android.net.Network` maintained by `NetworkChangeCallback`.

**Interpretation**

`protect(fd)` prevents Tailscale's own socket from being routed through the VPN. Binding to a chosen Android `Network` directs the socket to the selected non-VPN underlay. They solve related but distinct routing problems.

## 4. Physical underlay selection

**Android**

`android/src/main/java/com/tailscale/ipn/NetworkChangeCallback.kt`:

- registers for `NET_CAPABILITY_INTERNET` + `NET_CAPABILITY_NOT_VPN`;
- keeps all active candidate `Network` objects in `activeNetworks`;
- updates capabilities and `LinkProperties` independently;
- recomputes a preferred physical/non-VPN network;
- caches the selected `Network` and interface name;
- retains the normal Tailscale DNS/gateway notification path;
- exposes the first DNS server as the simpler MULTIPROXY upstream resolver.

This source establishes that the multiproxy extension did not replace the original multi-network selection algorithm with a single last-callback cache.

## 5. MULTIPROXY mode ownership

**Android**

`IPNService.kt` defines runtime modes:

```text
STOPPED
STANDARD
MULTIPROXY
```

`transitionMutex` serializes mode changes.

For MULTIPROXY startup:

1. acquire `MULTIPROXY-<service ID>` hooks;
2. create `MultiProxyEngine` if absent;
3. build/establish the synthetic-only Android TUN;
4. detach its raw FD;
5. call `engine.startVPN(fd, 1280)`;
6. initialize upstream DNS;
7. reconstruct persisted Tailnet profiles.

For full MULTIPROXY stop:

```text
engine.stopVPN()
engine.close()
engine = null
clear descriptor bookkeeping
release exact MULTIPROXY token
```

## 6. MULTIPROXY Android TUN configuration

**Android**

`IPNService.rebuildMultiProxyTunLocked` reads Go-owned addressing constants through the Gomobile facade.

Current Builder state includes:

```text
interface address  fd9b:8d7c:6a5e::1/120
route              fd9b:8d7c:6a5e::/48
DNS                fd9b:8d7c:6a5e::3
MTU                1280
```

It also applies the app-selection logic derived from MDM configuration or normal user package preferences.

No default IPv4 or IPv6 route is installed in MULTIPROXY mode.

## 7. TUN FD ownership

**Android**

The `ParcelFileDescriptor` returned by `Builder.establish()` is detached before crossing into Go.

**Go**

`libtailscale/multiproxy/tun_interceptor.go` explicitly documents that `StartVPN` takes ownership of the raw FD.

It closes that FD when:

- initialization fails after ownership transfer;
- an Engine is closed/invalid;
- another VPN stack is already running;
- `StopVPN()` destroys the current attachment.

This file is the canonical evidence for:

```text
PFD ownership before detach
        ->
Go ownership after detach
```

## 8. gVisor userspace stack

`libtailscale/multiproxy/tun_interceptor.go` constructs:

- IPv4 and IPv6 network protocol factories;
- TCP and UDP transport protocol factories;
- one `fdbased` link endpoint backed by the Android TUN FD;
- NIC ID 1;
- a userspace route for the synthetic IPv6 `/48`;
- TCP and UDP forwarders.

The existence of IPv4 protocol support does not imply a current synthetic IPv4 peer namespace. Android captures only the synthetic IPv6 `/48` for MULTIPROXY data.

## 9. Canonical target identity

`libtailscale/multiproxy/types.go` defines:

```text
UpstreamID
TargetKind
TargetKey
TargetRecord
```

A Tailscale peer's key is:

```text
immutable profile UpstreamID
+
tailscale-node kind
+
Tailscale StableNodeID
```

`TargetKey.SyntheticIPv6()` hashes the canonical key and places 80 hash-derived bits behind:

```text
fd9b:8d7c:6a5e::/48
```

The generator rejects the reserved `/120` control range.

This file is the source evidence that synthetic identity is deterministic and Tailnet-qualified rather than based on discovery order or native `100.x` address.

## 10. Identity versus current locator

`TargetRecord` stores both:

```text
SyntheticIPv6 / TargetKey       stable logical identity
CurrentIPv4 / CurrentIPv6       current native Tailscale locator
RequiredUpstream                required Tailnet namespace
```

The status-polling code in `api.go` rebuilds the current locator fields from `PeerStatus.TailscaleIPs` while retaining deterministic identity from `peer.ID`.

## 11. Tailnet runtime creation

`libtailscale/multiproxy/api.go` defines `TailnetConfig` and `TailnetRuntime`.

`AddTailnet(identifier, authKey, enabled)`:

- verifies Engine state;
- rejects duplicate identifier;
- derives stable profile hash;
- creates a mode-0700 state directory;
- registers a disabled runtime;
- optionally enables it.

`setTailnetEnabledLocked(true)` constructs:

```go
tsnet.Server{
    Dir:      deterministic profile state directory,
    AuthKey:  bootstrap key or empty,
    Hostname: "mp-" + stable profile hash,
}
```

then starts the Tailnet status watcher.

## 12. Tailnet disable and remove

`api.go` establishes different operations.

**Disable:**

```text
cancel/wait watcher
close tsnet.Server
Enabled=false
remove peer snapshot
rebuild DNS/targets
keep registration
keep state directory
```

**RemoveTailnet:**

```text
remove runtime registration
stop live server/watcher
remove subnet/exit ownership
remove snapshot
keep persisted state directory
```

This is source evidence for the product distinction between temporary disable and destructive Forget.

## 13. Persistent state deletion

`libtailscale/multiproxy/state_path.go` defines:

```text
StateDirForIdentifier(dataDir, profileId)
ForgetPersistedState(dataDir, profileId)
```

The state path is derived only from the stable profile identifier hash.

`multiproxy_facade.go` exposes this as `ForgetMultiProxyPersistedState` for Android even when no Engine is live.

## 14. Peer status reconciliation

`api.go:pollTailnetStatus`:

- obtains a `LocalClient`;
- performs an immediate first `Status` call;
- repeats every ten seconds;
- converts each peer with non-empty stable ID into a `TargetRecord`;
- atomically replaces the Tailnet snapshot;
- publishes accepted peer observations.

The immediate first poll is current behavior; the older "wait up to ten seconds for first snapshot" description is obsolete.

## 15. Collision and DNS table rebuild

`libtailscale/multiproxy/dns.go` owns `updateTailnetSnapshot` and `rebuildTargetsUnlocked`.

If two distinct keys produce the same synthetic IPv6, the address is marked collided and removed rather than last-writer-wins.

Only accepted targets contribute DNS entries.

## 16. Synthetic DNS names

`dns.go` creates:

```text
reported lower-cased FQDN
first-label short name
<first-label>.<profile-hash>.proxy.
```

`targets_export.go:syntheticQualifiedName` uses the same first-label rule for the canonical Android V2 peer snapshot.

This is why V2 should be preferred over the legacy target export.

## 17. DNS protocol behavior

`dns.go` currently implements both:

```text
ServeDNSUDP
ServeDNSTCP
```

For a recognized synthetic name:

```text
AAAA -> synthetic IPv6
other record types -> authoritative NODATA
```

Ambiguous names return `NXDOMAIN`.

Unknown/external names are sent to the configured physical resolver.

For a UDP request, upstream exchange falls back to TCP when the UDP exchange errors or returns `TC=1`.

DNS-over-TCP uses two-byte framing, `io.ReadFull`, and `writeFull` for short writes.

## 18. Exact route precedence

`libtailscale/multiproxy/nat_router.go:resolveRoute` implements:

```text
1. exact active synthetic target
2. if inside synthetic /48 but unknown -> reject
3. longest-prefix configured subnet
4. configured exit Tailnet
5. reject
```

The explicit synthetic-prefix rejection prevents stale synthetic destinations from falling through into broader routing classes.

## 19. Active runtime synchronization

`nat_router.go:activeTailnetServer` snapshots `rt.Enabled` and `rt.Srv` while holding `Engine.mu.RLock`.

Exact, subnet, and exit routing paths call this synchronized accessor rather than reading runtime publication fields independently.

## 20. TCP path

`nat_router.go:handleTCPConnection`:

- creates a gVisor TCP endpoint;
- intercepts synthetic DNS port 53 as DNS-over-TCP;
- resolves the target;
- dials the selected `Upstream` with a ten-second setup timeout;
- creates the gVisor connection;
- copies bytes both directions;
- attempts half-close semantics;
- logs flow close.

The Tailnet-side connection is a new `tsnet.Server.Dial` connection. This is userspace transport proxying, not kernel packet NAT.

## 21. UDP path and lifetime

`nat_router.go:handleUDPConnection` intercepts DNS port 53 or resolves an ordinary target and dials UDP through the selected upstream.

`runUDPAssociation` gives each association:

```text
60-second idle timeout
shared deadline refresh on activity
bidirectional pumps
first error closes both connections
wait for both pumps before exit
```

The old statement that UDP has no idle lifecycle is obsolete.

## 22. Runtime-state export

`libtailscale/multiproxy/runtime_state.go` provides `GetTailnetStatesJSON`.

It snapshots Tailnet runtime pointers under the Engine lock, then performs potentially blocking `LocalClient.Status` calls after releasing it.

It reports:

```text
STOPPED
ERROR
STARTING
or actual tsnet BackendState
```

`ClearTailnetAuthKey` removes the bootstrap key from the in-memory Go config after successful provisioning.

## 23. Canonical peer export

`targets_export.go:GetTargetsJSONV2` exports:

```text
tailnetId
hostname
currentIpv4
currentIpv6
syntheticDnsName
syntheticIpv6
kind
```

It sorts output for stable presentation and encodes absent native locators as empty strings.

This is the current Android UI source. `GetTargetsJSON` remains only as a legacy facade method.

## 24. Persistent Android profile model

`android/src/main/java/com/tailscale/ipn/multiproxy/db/` contains:

- `TailnetProfile.kt`
- `TailnetDatabaseHelper.kt`
- `ProfileRepository.kt`

The database model stores:

```text
immutable UUID
mutable display name
desired enabled state
provisioning state
created/updated timestamps
```

The UUID is passed into Go as `UpstreamID`.

## 25. Encrypted bootstrap credentials

`CredentialStore.kt` stores auth keys in the same Android encrypted preference facility used by the application, under:

```text
auth_key_<profileId>
```

`App.getEncryptedPrefs()` uses AndroidX `MasterKey` and `EncryptedSharedPreferences`.

SQLite does not contain the auth key.

## 26. Provisioning coordinator

`MultiProxySessionCoordinator.kt` is the current product-level mutation boundary.

It:

- serializes interactive profile/runtime mutations with a coroutine mutex;
- creates profiles and marks them `PROVISIONING`;
- saves bootstrap keys encrypted;
- starts MULTIPROXY when needed;
- adds/enables/disables/removes Tailnet runtimes;
- polls runtime state every second;
- marks provisioning `READY` when runtime becomes `RUNNING`;
- clears the in-memory and encrypted auth key at that point;
- records per-profile errors;
- composes runtime removal + persisted-state/key/database deletion for Forget.

## 27. Profile reconstruction

`IPNService.startMultiProxyVPNLocked` calls `MultiProxySession.reconstructEngine` after TUN establishment.

The reconstruction path reads persisted profiles and calls:

```text
AddTailnet(profile.id, savedAuthKeyOrEmpty, profile.enabled)
```

This is the source evidence for process/service restoration of configured profiles.

It is also a current seam: reconstruction is separate from the coordinator's interactive mutation mutex and errors are primarily logged. The validation document tracks that limitation explicitly.

## 28. Android runtime-state UI

`MultiProxyViewModel.kt` combines:

```text
ProfileRepository.profiles
MultiProxySessionCoordinator.runtimeStates
MultiProxySessionCoordinator.lastErrors
```

into one `TailnetProfileUiState` per profile.

It separately polls `GetTargetsJSONV2` every two seconds for current peers.

Thus the current UI does not infer runtime state from the persisted `enabled` flag alone.

## 29. Compose management surface

`MultiProxyView.kt` currently exposes:

```text
start / stop MULTIPROXY
add profile with display name + auth key
provisioning and runtime state
enable / disable
rename
Forget with destructive confirmation
peer list
synthetic DNS
synthetic IPv6
current native Tailnet IPv4/IPv6
```

`MainActivity.kt` wires this screen into the existing Settings navigation graph.

## 30. Evidence boundaries

The source files above establish implementation behavior.

They do not, by themselves, establish:

- physical-device Android packet capture;
- two live independent Tailnets working simultaneously;
- real overlapping `100.x` addresses working E2E;
- Private DNS compatibility;
- Always-On/lockdown semantics;
- Wi-Fi/cellular transition recovery;
- persistent `tsnet` restart behavior across every control-plane condition.

Those require executable Android/device evidence and are tracked separately in:

```text
docs/multi_tailnet_proxy_app/validation_and_gaps.md
```

## 31. Where to read next

For system reasoning:

```text
docs/multi_tailnet_proxy_app/architecture.md
```

For detailed Go mechanics:

```text
docs/multi_tailnet_proxy_app/backend_internals.md
```

For Android persistence/provisioning/UI:

```text
docs/multi_tailnet_proxy_app/android_profiles_and_ui.md
```

For packet-by-packet flows:

```text
docs/multi_tailnet_proxy_app/data_path_and_dns.md
```

For evidence and remaining integration risks:

```text
docs/multi_tailnet_proxy_app/validation_and_gaps.md
```

## 32. Bottom line

The current source no longer represents a hypothetical multiproxy integration. It contains the complete architectural chain from persisted Android profile, through mode ownership and TUN establishment, into deterministic synthetic peer identity, gVisor transport termination, Tailnet-qualified route selection, embedded `tsnet.Server` connectivity, synthetic DNS, bounded UDP flow lifetime, and Android runtime/peer presentation.

The unresolved questions are now chiefly validation and lifecycle-hardening questions rather than missing core architecture.