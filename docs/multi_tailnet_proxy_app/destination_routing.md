# Destination-aware direct routing: attribution checklist

Status: **attribution not yet complete**. Do not change the bind path until the
steps below are run and the failure is attributed. Background and the proposed
(not yet approved) fix are at the end.

## Symptom

Traffic to a host on a directly-connected local network is allegedly forced out
the default route instead of that network. Reported case:

```
172.27.85.178  ->  USB tether network  ->  Fedora
public internet ->  default network
tailnet         ->  a tailnet
```

with General Traffic set to **Direct** (broad capture on).

## What is already confirmed in code

- `@direct` binds every IPv4 dial to the cached default network:
  `NetworkChangeCallback.pickNetworkForDial(false)` returns
  `cachedDefaultNetwork` unconditionally (`NetworkChangeCallback.kt`), and
  `App.bindSocketToNetwork` binds the fd to it (`App.kt`). A directly-connected
  subnet that is not the default network is therefore not used for the dial.
- "Keep LAN traffic direct" (`RoutingSettings.lanExclusionEnabled`) is a
  **policy** decision only. The VPN still captures `0.0.0.0/0` under broad
  capture (`IPNService.kt`) and the flow still enters gVisor → `@direct` →
  bind. It does not change *which interface* the direct socket uses.

The open question is whether that is what actually happened, or whether Fedora
simply did not answer.

## Critical qualification

A Fedora `tcpdump` showing phone-originated SYNs proves the physical path can
work. It does **not** prove Tailmesh caused the failures. Fedora's missing
SYN-ACK must be explained first. Attribute before building.

## Checklist

### 0. Build/install the debug APK with this tree's changes

```
make libtailscale
(cd android && ./gradlew installDebug)   # or assembleDebug + adb install
```

### 1. Record the phone's view of networks and routes

```
adb logcat -c
adb shell dumpsys connectivity | sed -n '1,200p'      # managed networks + routes
adb shell ip -4 route show table all                  # every routing table
adb shell ip -6 route show table all
```

The inventory is also logged automatically (tag `NetworkChangeCallback`) on
every default-network change and on Multi-Tailnet start:

```
adb logcat -s NetworkChangeCallback | grep -E "network inventory|destination "
```

The JSON lists each `Network` Android knows about with `interfaceName`,
`transports`, `bindable`, and every route (`cidr`, `gateway`, `onLink`). **Key
question for step 3:** does the USB-tether subnet appear at all? If the tether
downstream is not a managed `Network`, it will be absent, and no
`Network.bindSocket` can select it.

### 2. Same listener + firewall, both modes

With the same Fedora HTTP listener and firewall for both runs:

- **OFF:** stop Multi-Tailnet (STANDARD/off). From the phone, request
  `http://172.27.85.178:8081`.
- **ON:** start Multi-Tailnet with General Traffic = Direct (broad capture on).
  Repeat the request.

On Fedora, on both runs:

```
sudo tcpdump -ni any host <phone-tether-ip> and port 8081
```

Record presence/absence of SYN from the phone and of SYN-ACK from Fedora.

### 3. Read the route-decision telemetry for the dial (ON run)

`MultiProxyEngine.setRouteDecisionLogEnabled(true, "")` (facade) turns on the
per-flow routing trace. For each `@direct` flow it emits `virtualDst`,
`realDest`, `dialAddr`, `dialNetwork`, `dialDurationMs`, `outcome`
(`success` / `no-route` / `no-usable-network-for-family` / `dial-error`) and the
decision `trace`. If the dial **succeeds** and the SYN still reaches Fedora with
no SYN-ACK, this is not a Tailmesh routing bug.

### 4. Interpret

| Phone SYN reaches Fedora | Fedora SYN-ACK | Phone sees SYN-ACK | Conclusion |
| --- | --- | --- | --- |
| no (ON), yes (OFF) | (OFF only) | — | Tailmesh routing failure — proceed |
| yes | no | — | Fedora firewall/listener, not Tailmesh |
| yes | yes | no | return-path/routing, investigate further |
| no (both) | — | — | tether/L2 problem, not Tailmesh |

## Host-test coverage already in place (no device)

- `DestinationRoutingTest` (12): the pure longest-prefix, on-link-preferred
  selector, including the exact tether-vs-cellular-default case.
- `NetworkInventoryTest` (5): the inventory shaping and per-destination lookup.

Only the actual kernel bind/route behaviour is un-testable here — no emulator
path (no `/dev/kvm` for this user, no AVD) and unprivileged netns is blocked.

## Proposed minimal fix (NOT yet implemented)

If, and only if, step 4 concludes "Tailmesh routing failure":

- **Decision logic is pure and already written** (`DestinationRouting`): pick the
  most-specific containing route, preferring on-link. Unit-tested.
- **Mechanism:** for a destination verified on-link, make the `@direct` socket
  *protected-but-unbound* so the kernel's main table routes it (which contains
  the on-link tether route), instead of force-binding it to the cached default.
  Keep the existing bind for everything else, and for IPv6 family-awareness.
- **Requires a cross-layer change:** `netns`'s `controlC` receives the
  destination but discards it (`SetAndroidBindToNetworkFunc(f func(fd int))`);
  passing it through touches the patched core
  (`net/netns/netns_android.go`), the exported `AppContext` interface,
  `libtailscale/backend.go`, and `App.kt`. It must not alter STANDARD mode and
  must not become a blanket IPv4 binding bypass.
- **Device-validate** the actual routing on real hardware; there is no host
  substitute.
