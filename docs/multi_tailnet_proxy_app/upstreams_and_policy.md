**Pluggable Upstreams and Routing Policy**

This document covers the upstream abstraction, the policy engine that selects
between upstreams, per-app attribution, and upstream chaining.

It follows the source discipline described in `README.md`: every claim is tagged
`CURRENT CODE`, `TEST EVIDENCE`, `ANDROID / DEVICE EVIDENCE`, `INFERENCE`, or
`RECOMMENDATION`. Evidence levels are the ones defined in
`validation_and_gaps.md`.

Read `architecture.md` first. This document assumes the synthetic-addressing
model, `UpstreamID`, and the terminate-and-re-originate datapath.

---

## 1. What changed, and why

### 1.1 Before

`CURRENT CODE` (prior to this work)

An upstream was a Tailnet, and only a Tailnet. `Engine.tailnets` held every
`TailnetRuntime`, and the datapath reached one through
`activeTailnetServer(id)` followed by a `tsnetUpstream` wrapper. Route
resolution in `nat_router.go:resolveRoute` took a single argument - the
destination IP - and worked through a fixed ladder:

```text
exact synthetic target match
        |
inside the synthetic /48 but unmapped  ->  fail closed
        |
longest-prefix match against e.subnets
        |
e.exitNodeTailnet
        |
fail
```

Everything about that ladder was destination-driven. There was no way to
express "this app goes somewhere else", no way to attach a non-Tailscale
transport, and the only exit-node concept available was a Tailnet exit node,
which does nothing for traffic the user wants carried by a commercial VPN, a
WireGuard peer, or a locally-run proxy core.

### 1.2 New

`CURRENT CODE`

Three layers were added beneath the existing behavior, none of which changes it
when unconfigured:

1. **`Provider`** (`upstream.go`) - a registrable, dialable upstream with an
   identity, a kind, a readiness state, and a lifecycle. Tailnets, SOCKS5
   proxies, WireGuard tunnels, and the built-in direct upstream are all
   Providers.
2. **`Policy`** (`policy.go`) - an ordered, first-match-wins rule list matching
   on app UID, destination prefix, destination port, and protocol, with actions
   `route`, `block`, and `direct`.
3. **Chaining** (`chain.go`) - a Provider's own transport may itself run over
   another upstream, so a proxy can be reached through a tunnel or a tunnel
   through a proxy.

Route resolution became flow-driven. `resolveFlow(FlowInfo)` replaces
`resolveRoute(addr)`, and policy is consulted at one specific point in the
ladder:

```text
exact synthetic target match           (a block rule may still veto)
        |
inside the synthetic /48 but unmapped  ->  fail closed
        |
POLICY                                 <- new
        |
longest-prefix match against e.subnets
        |
e.exitNodeTailnet
        |
fail
```

`resolveRoute(addr)` still exists and is now a thin wrapper that builds a
`FlowInfo` with an unknown app UID, so callers that genuinely have only an
address are unchanged.

### 1.3 Why

The requirement was exit-node selection for non-Tailnet traffic, on a per-app
basis, with the transport pluggable - explicitly naming WireGuard and Xray-core
as things that should be able to plug in.

Three consequences followed from taking that seriously:

- **The datapath must not know what kind of thing it is dialing.** If it
  switched on upstream kind, every new transport would mean touching the
  forwarder. `Upstream` (Dial + PeerPathInfo) stayed the narrow datapath
  interface, and `Provider` added registry/policy/UI concerns on top, so the hot
  path never learned about registration.

- **SOCKS5 is the pluggability lever.** Xray-core, sing-box, v2ray, and hysteria
  all expose a local SOCKS5 listener. Supporting one well-specified protocol
  (RFC 1928, plus RFC 1929 auth) makes all of them pluggable without vendoring
  any of their dependency trees into this build. WireGuard was implemented as a
  second, structurally different transport specifically to check that the
  abstraction was not accidentally SOCKS5-shaped.

- **Per-app selection needs attribution the datapath does not have.** gVisor
  sees IP/TCP/UDP headers off the TUN and no notion of a process. That gap is
  covered by `UIDResolver` (§4), not by guessing.

---

## 2. The upstream layer

### 2.1 Provider and Upstream

`CURRENT CODE` (`upstream.go`, `types.go`)

```go
type Upstream interface {           // types.go - what the datapath needs
    Dial(ctx, network, address) (net.Conn, error)
    PeerPathInfo(ctx, destIP) string
}

type Provider interface {           // upstream.go - what the registry needs
    Upstream
    ID() UpstreamID
    Kind() UpstreamKind
    Ready() bool
    Close() error
}
```

`UpstreamKind` is one of `tailnet`, `socks5`, `wireguard`, `direct`. The
datapath never switches on it; it exists for the policy layer, the UI, and
diagnostics.

`Ready()` distinguishes "configured but not usable" from "absent". That
distinction is load-bearing: a policy rule naming a disabled upstream fails
closed rather than falling through to a different one, which would silently send
traffic somewhere the user did not choose.

`ErrUpstreamNotReady` is the sentinel for the first case.

### 2.2 Tailnets as a provider source

`CURRENT CODE` (`upstream_tailnet.go`)

**Before:** `lookupProvider` checked the registry, then separately checked
`Engine.tailnets` and synthesised a `tailnetProvider` on the spot.
`UpstreamSnapshot` repeated the same two-source merge by hand. Every new
consumer would have had to repeat it again.

**New:** the registry accepts `providerSource` implementations:

```go
type providerSource interface {
    Get(id UpstreamID) (Provider, bool)
    List() []Provider
}
```

`tailnetSource` reads `Engine.tailnets` on demand, and is installed once in
`NewEngineWithStateStore`. `Engine.lookupProvider` is now a single call to
`upstreams.Get`, and `UpstreamSnapshot` a single call to `upstreams.List`.

**Why:** a tailnet is dialable like any other upstream, but unlike the others it
does not *belong* to the registry - it is created, enabled, disabled and torn
down by the tailnet machinery. Copying tailnets into the registry would create
two things to keep in sync on every add and forget. A source keeps the tailnet
lifecycle as the single source of truth while still giving everything downstream
one uniform set of upstreams.

`tailnetProvider` deliberately holds the `Engine` and an ID rather than a
`*tsnet.Server`, so enabling, disabling, or replacing a tailnet is observed on
the next dial instead of being captured at registration. Its `Close()` is a
no-op for the same reason: the server is not the provider's to close.

`RegisterUpstream` rejects `UpstreamKindTailnet`, so the two paths cannot be
confused.

### 2.3 The direct upstream

`CURRENT CODE`

`DirectUpstreamID` (`"@direct"`) is always registered and always ready. It dials
from the device, outside every tunnel, and is how a policy expresses "this app
does not go through the VPN". It cannot be unregistered.

On Android the resulting socket is `VpnService.protect`ed by the same mechanism
the tailnet upstreams' sockets use, so it does not loop back into gVisor.

### 2.4 SOCKS5

`CURRENT CODE` (`socks5.go`)

A complete RFC 1928 client: CONNECT for TCP, UDP ASSOCIATE (§7) for UDP,
optional RFC 1929 user/password auth, IPv4/IPv6/domain address forms.

The UDP path returns a `socks5UDPConn` that holds the TCP control connection
open for the life of the association, as §7 requires, and prepends/strips the
3-byte RSV+FRAG header plus destination address on each datagram.

`TEST EVIDENCE` (`socks5_test.go`): tested against a real in-process SOCKS5
server implementing both CONNECT and UDP ASSOCIATE, including auth negotiation,
auth failure, every reply code, and both address families. The test server's UDP
relay keeps one persistent socket per target for the life of the association -
a request/response relay would have passed the SOCKS5 tests and failed anything
long-lived (see §5.3).

### 2.5 WireGuard

`CURRENT CODE` (`wireguard.go`, `wireguard_tun.go`, `wireguard_bind.go`,
`wireguard_config.go`)

A userspace WireGuard tunnel terminated in-process, reusing the `wireguard-go`
the Tailscale core already depends on, so it adds no module to the build.

The tunnel gets its own gVisor netstack, entirely separate from the one serving
the TUN. That is the same shape as a tailnet upstream: terminate the flow, then
re-originate it inside the tunnel.

**A purpose-built TUN.** `wireguard-go` ships `tun/netstack`, which does exactly
this job, but it is written against an older gVisor than this project resolves:
it calls `(*stack.PacketBuffer).IsNil`, which no longer exists. Building with
`-gcflags=-e` confirmed that was the *only* incompatibility. The options were to
pin gVisor back for the whole build, vendor a ~400-line file for one call, or
write the minimal equivalent. `wireguard_tun.go` is the third: a channel-endpoint
`tun.Device` with no listeners, no ICMP ping support and no resolver, because the
upstream only ever dials.

**Configuration** is rendered into `wireguard-go`'s `IpcSet` (UAPI) format by
`uapiConfig()`. Device-level lines precede the first `public_key=`, since IpcSet
applies lines in order and anything after a peer key belongs to that peer.

`TEST EVIDENCE` (`wireguard_test.go`): two devices stood up back to back over
localhost, completing a real handshake and carrying a TCP echo session through
the tunnel; plus config validation, UAPI rendering, and JSON parsing tests.

### 2.6 A limitation worth knowing: no endpoint learning

`CURRENT CODE` / `INFERENCE`

Stock WireGuard learns a peer's endpoint from the packets it receives. Tailscale's
`wireguard-go` fork removes that - endpoints come only from UAPI configuration
and `device.go`'s `conf.Endpoint` - because Tailscale chooses endpoints itself.

For this upstream that is fine: it is always the initiator, with its peer
endpoint configured, exactly as a wg-quick client is. It would *not* be fine for
an upstream expected to act as a responder to a roaming peer.

`TEST EVIDENCE`: the test suite's far end wraps a real bind and turns each
observed source address into a UAPI `endpoint=` update, restoring stock
behaviour for the responder side only. That shim exists in the test file, not in
the product.

---

## 3. The policy engine

### 3.1 Shape

`CURRENT CODE` (`policy.go`)

```go
type Selector struct {
    AppUIDs     []int32
    DstPrefixes []netip.Prefix
    DstPorts    []PortRange
    Protocols   []string
}

type Rule struct {
    Name     string
    Selector Selector
    Action   Action        // "route" | "block" | "direct"
    Upstream UpstreamID    // required for "route"
}
```

Rules are evaluated in order, first match wins. Within one selector field the
values are disjunctive (any UID in the list matches); across fields they are
conjunctive (UID *and* port *and* protocol must all match). An absent or empty
field is a wildcard, so a rule with no selector is a default.

Destination addresses are `Unmap()`ed before prefix comparison, so a
v4-mapped-v6 destination matches an IPv4 prefix.

### 3.2 Validation and failure behaviour

`CURRENT CODE`

`Policy.Validate` checks structure: known action, `route` names an upstream,
port ranges ordered, protocols known. It deliberately does **not** check that
the named upstream exists.

**Why:** upstreams come and go at runtime. Validating existence at set time
would either reject a policy written before its upstream is registered, or give
a false assurance that the upstream will still be there at dial time. Instead
resolution fails closed: a rule naming a missing or not-ready upstream drops the
flow rather than falling through to the next rule or to the legacy ladder.

An invalid policy is rejected whole and the previous one stays in force, so a
bad edit cannot half-apply.

### 3.3 Interaction with synthetic addressing

`CURRENT CODE` (`nat_router.go`)

Synthetic addresses are identity-bound: the address itself encodes which
upstream minted it. A `route` rule must therefore never re-point a synthetic
destination - doing so would hand a flow addressed to peer X on tailnet A to
tailnet B, where that address means something else or nothing at all.

So policy sits *below* the synthetic branches in the ladder:

- An exact synthetic match resolves to its own upstream. A `block` rule may
  still veto it - blocking is always safe.
- A synthetic address with no record still fails closed, before policy is
  consulted.
- Policy applies only to destinations outside the synthetic namespace.

`TEST EVIDENCE` (`route_policy_test.go`): `TestEmptyPolicyPreservesLegacyRouting`
asserts that with no rules, every destination resolves exactly as it did before
policy existed. That is the regression guarantee for the whole feature.

### 3.4 Locking

`CURRENT CODE`

`policyStore` has its own `sync.RWMutex`, separate from `Engine.mu`. Policy is
read on the datapath for every new flow; sharing the Engine lock would put flow
setup behind tailnet lifecycle operations.

---

## 4. App attribution

### 4.1 The problem

`CURRENT CODE`

gVisor sees raw IP/TCP/UDP headers off the TUN fd. There is no UID in a packet.
Per-app rules therefore need an out-of-band lookup.

### 4.2 The mechanism

`CURRENT CODE` (`uid.go`, `flowinfo.go`, `AppUidResolver.kt`)

```go
type UIDResolver interface {
    ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32
}
```

The Android implementation calls `ConnectivityManager.getConnectionOwnerUid`
(API 29+), which takes the same 5-tuple the gVisor forwarder request already
has. The platform only answers it for the app currently holding the VPN, which
is us while MULTIPROXY is running.

Three details matter:

- **Endpoint naming is inverted between the two sides.** gVisor names ends from
  the stack's point of view, so `LocalAddress`/`LocalPort` in a
  `stack.TransportEndpointID` is the *destination* and `RemoteAddress`/
  `RemotePort` is the *app's source*. `getConnectionOwnerUid` names them from
  the querying app's point of view, where "local" is the app's source.
  `flowFromEndpointID` and `AppUidResolver` are written to that, and it is the
  single easiest thing to get backwards here.

- **Attribution is skipped entirely when no rule is UID-scoped**
  (`policyUsesAppUID`). No per-flow JNI round trip is paid for a policy that
  does not need one.

- **Resolution is bounded.** `resolveAppUID` runs the resolver on a goroutine
  with a buffered result channel and a `recover()`, and gives up after
  `uidResolveTimeout` (150ms), returning `UnknownAppUID`. A slow or wedged
  platform call degrades the flow to "unattributed" rather than stalling it.

### 4.3 Failing safe

`CURRENT CODE`

`UnknownAppUID` is `-1`. A selector listing specific UIDs never matches an
unattributed flow:

```go
if f.AppUID == UnknownAppUID { return false }
```

**Why:** an unattributed flow must only ever be able to match a *broader* rule,
never a narrower one. If a failed lookup could match a UID-scoped rule, a
transient platform failure would route arbitrary traffic through whatever
upstream that rule names.

The Kotlin side also maps `Process.myUid()` to unknown, so a rule written for
"the VPN app" cannot capture traffic the app is merely carrying, and disables
itself permanently on `SecurityException` (raised when we are not the active
VPN, which does not resolve itself mid-session).

`ANDROID-BUILT`: `AppUidResolver` compiles against the generated AAR and binds
to `libtailscale.MultiProxyUIDResolver`. It has no device evidence yet - see
`validation_and_gaps.md`.

---

## 5. Chaining

### 5.1 What it is

`CURRENT CODE` (`chain.go`)

Every upstream has to reach its own far end somehow: a SOCKS5 upstream connects
to the proxy's listener, a WireGuard upstream gets handshakes to the peer
endpoint. By default that leaves from the device. `Via` points it at another
upstream instead.

```text
app flow  ->  wg-home (Via: xray)  ->  xray (Via: "")  ->  device
```

The link is an `UpstreamID` resolved at dial time, not a pointer captured at
construction, so a parent can be reconfigured, disabled or replaced and its
children observe the change on their next dial.

A provider opts in by implementing `ChainedProvider` (`Via() UpstreamID`).
Providers that can only dial from the device simply do not implement it.

### 5.2 Fail-closed, and two cycle guards

`CURRENT CODE`

A chained dial whose parent is missing or not ready returns
`ErrUpstreamNotReady`. It does **not** fall back to the device dialer - the
entire point of the chain is that this traffic does not leave that way.

Chaining through `@direct` is the explicit way to say "leave from the device",
and lands on the base dialer rather than the direct provider's own `net.Dialer`,
so it stays VpnService-protected on Android.

Cycles are caught twice:

- `checkChainLocked` walks the `Via` graph at registration and rejects a
  self-reference or a cycle, so a configuration that would deadlock is never
  installed.
- Dials carry a depth counter in the context and fail with `ErrChainTooDeep`
  past `maxChainDepth` (8). This catches anything the static check could not
  see - a parent replaced between check and dial, or a cycle formed through a
  provider source.

`TEST EVIDENCE` (`chain_test.go`): a three-hop chain is traversed hop by hop and
each hop's dial recorded; self-cycles, two-hop and three-hop cycles are rejected
at registration; a cycle installed behind the registry's back is stopped by the
depth guard.

### 5.3 WireGuard over another upstream

`CURRENT CODE` (`wireguard_bind.go`)

Chaining WireGuard means replacing its UDP socket. `upstreamBind` implements
`conn.Bind` over an `UpstreamDialer`: one connected UDP flow per peer endpoint,
dialed lazily on first send, with a reader goroutine per flow feeding a shared
receive queue.

It is outbound-only, which suits a client that always initiates. A peer whose
source address changes is still handled, because replies arrive on the flow they
were sent on rather than being matched by source address.

Two deliberate choices:

- **`BatchSize()` is 1.** Batching amortises syscalls on a real UDP socket; these
  conns are already an abstraction over something else, and a SOCKS5 UDP
  association has no batch form.
- **The receive queue drops when full** rather than growing. This is UDP
  underneath and WireGuard retransmits what matters.

`Engine.NewWireGuardUpstream` uses `upstreamBind` in *both* the chained and
unchained cases. That is not only for chaining: it is the only way to get a
protected socket on Android. `wireguard-go` applies its socket options from an
unexported `controlFns` list with no hook to add the `VpnService.protect` call,
whereas the base dialer already has it.

**Cost:** the tunnel has no listening socket, so `ListenPort` is ignored by
`Engine.NewWireGuardUpstream` and peers cannot reach it unprompted. An upstream
is a client. If that ever needs to change, the package-level
`NewWireGuardUpstream` still accepts a real `conn.Bind`.

`TEST EVIDENCE` (`wireguard_test.go`): `TestWireGuardChainedOverSOCKS5` runs a
full WireGuard handshake and a TCP echo session with the tunnel's outer packets
carried by a real SOCKS5 UDP association. This is the end-to-end proof that both
chaining and the WireGuard upstream work, and that the abstraction generalises
past its first implementation.

---

## 6. The gomobile surface

`CURRENT CODE` (`libtailscale/multiproxy_policy_facade.go`)

gomobile carries no maps, no slices of structs, and no named non-basic types, so
everything structured crosses as JSON - the convention `GetTargetsJSON` already
established.

| Binding | Purpose |
|---|---|
| `SetPolicyJSON` / `PolicyJSON` | replace / read the routing policy |
| `GetUpstreamsJSON` | list every routable upstream: `id`, `kind`, `ready`, `via` |
| `AddSOCKS5Upstream` | register a SOCKS5 proxy |
| `AddSOCKS5UpstreamVia` | the same, chained behind another upstream |
| `AddWireGuardUpstream` | register a WireGuard tunnel from a wg-quick-shaped JSON config |
| `RemoveUpstream` | unregister a non-tailnet upstream |
| `SetUIDResolver` | install the per-flow app attribution hook |
| `MultiProxyDirectUpstreamID` | the reserved `@direct` id |
| `MultiProxyUnknownAppUID` | the `-1` sentinel |
| `BuildAppBindingPolicyJSON` | assemble the common per-app policy shape from UI state |

Config parsing lives in `multiproxy/wireguard_config.go`, not in the binding
layer. **Why:** the `libtailscale` package cannot be compiled for the host
(`netns.SetAndroidProtectFunc` and friends are `//go:build android`), so nothing
in it can be unit-tested here. Parsing is where the mistakes are, so it was put
somewhere it can be.

`protectedDialContext` reaches upstreams through the dialer the backend
publishes once it has a netmon, applying the same Android protect hook the
tailnet upstreams use. netns skips protection for loopback, so a proxy core
running on the device works unchanged.

---

## 7. Invariants

These are the properties the tests exist to protect. Breaking any of them is a
correctness bug, not a behaviour change.

1. **An empty policy changes nothing.** With no rules, every destination
   resolves exactly as it did before the policy engine existed.
2. **A route rule never re-points a synthetic address.** Synthetic addresses are
   identity-bound. A block rule may still apply.
3. **A synthetic address with no record fails closed**, before policy runs.
4. **An unattributed flow can only widen which rule matches, never narrow it.**
5. **A rule naming a missing or not-ready upstream fails closed**, rather than
   falling through.
6. **A chained upstream never falls back to leaving from the device.**
7. **The chain graph is acyclic at registration, and bounded at dial time.**
8. **The datapath never switches on `UpstreamKind`.** It only calls `Dial`.

---

## 8. Known gaps

`RECOMMENDATION` / evidence levels per `validation_and_gaps.md`.

1. **No persistence.** Upstreams and policy live only in the running Engine.
   They need a DB table mirroring `ProfileRepository`, and re-registration on
   VPN rebuild. Until then, everything configured is lost on restart.
2. **No UI.** Nothing in the Android app currently calls the policy or upstream
   bindings. Per-app upstream selection is the intended surface -
   `SplitTunnelAppPickerView` is the natural home.
3. **No device evidence.** Everything here is `UNIT-OR-RACE-TESTED` and
   `ANDROID-BUILT`. Nothing is `PHYSICAL-DEVICE-E2E`. In particular
   `getConnectionOwnerUid` has never been exercised against this TUN on a real
   device, across API levels or OEMs.
4. **WireGuard cannot act as a responder** through `Engine.NewWireGuardUpstream`
   (§2.6, §5.3). Acceptable for a client upstream; a blocker if inbound is ever
   wanted.
5. **DNS inside a WireGuard upstream is unused.** `WireGuardConfig.DNS` is
   parsed and carried but the multiproxy resolver handles DNS itself, so it only
   affects lookups made by the tunnel's own netstack - of which there are
   currently none.
