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

**Importing a config.** A WireGuard config reaches a user as an INI-ish
`.conf`: that is what every provider hands out, what `wg-quick` reads, and what
a QR code encodes. `ParseWireGuardQuickConfig` converts one into the same JSON
the binding already takes, so the two paths converge immediately and cannot
drift.

It reads the `[Interface]` and `[Peer]` settings that describe a client tunnel,
recognises and ignores wg-quick's host routing and shell hooks (`Table`,
`PostUp` and friends) because those describe a machine's routing table rather
than an in-process tunnel, and uses the first `[Peer]` only - a multi-peer file
describes a mesh, which an upstream is not. An unrecognised setting is an error
rather than being dropped: a directive the user believed they had set going
silently missing is worse than being told it is unsupported.

**Endpoints are resolved once, up front.** `resolveEndpoints` turns a named
peer endpoint into a literal before the config reaches the UAPI.

- *Before:* the endpoint was passed through as written.
- *New:* a name is resolved once, with a 10s bound, and reported by name if it
  fails.
- *Why:* wireguard-go's `IpcSet` accepts only a literal address and rejects a
  hostname with an opaque `IPC error -22`. Since essentially every provider
  config names its endpoint, the previous behaviour meant a correct, pasted
  config failed with a message that pointed nowhere. This was found by a test
  that built a tunnel from an imported `.conf` rather than only parsing one -
  parsing alone would have passed.

The resolved address is fixed for the life of the upstream; a peer that moves is
not followed until the upstream is reconfigured. That is the same bargain
wg-quick makes, and acceptable for a client tunnel whose far end is a server.

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

### 3.5 DNS follows the same route

`CURRENT CODE` (`dns_policy.go`, `dns.go`, `nat_router.go`)

**Before:** a forwarded DNS query always left from the device, regardless of
which upstream the querying app was routed through. For an app deliberately
sent through a proxy or tunnel, that leaked every name it looked up to the
device's resolver outside the transport chosen precisely to avoid that - and
could return the wrong answer for a name that resolves differently inside the
proxy's network.

**New:** `nat_router.go`'s DNS dispatch now attributes the flow
(`e.flowFromEndpointID`) before serving it, and `handleDNSMsg` asks
`e.dnsRouteFor(flow)` how the forward should leave:

```go
type dnsRoute struct {
    provider Provider // carries the query, or nil to leave from the device as before
    blocked  bool      // policy blocks this app outright: refuse, don't answer
    failed   bool       // named upstream missing or not ready: fail closed
}
```

`dnsRouteFor` matches policy with `Policy.MatchAppOnly`, a variant of the usual
match that **skips** any rule scoped by destination, port or protocol rather
than partially applying it. A DNS query's destination is the synthetic
resolver, not the name's eventual address, so a destination-scoped selector
cannot be evaluated yet, and matching it against the resolver's own address
would silently capture or miss lookups a rule was never written about. What
remains is exactly the per-app-or-default shape that already governs
everything else.

The three outcomes:

- `ActionBlock` / `ActionDirect` / no match → unchanged: `RcodeRefused`, or the
  original device-resolver path.
- `ActionRoute` to a ready upstream → the query is exchanged through that
  upstream's `Dial`, plain DNS via `exchangePlainVia` (with the usual UDP→TCP
  retry on truncation) or DoH via `exchangeDoHVia`.
- `ActionRoute` to a missing or not-ready upstream → SERVFAIL. Consistent with
  every other resolution in this package: a named upstream that cannot be used
  fails the flow, it never falls back to the device.

DoH needs one HTTP client per upstream, cached in `dohClientCache` and keyed by
`UpstreamID` rather than by provider value - a `tailnetProvider` is built fresh
on every lookup (§2.2), so caching against the value would miss on every
lookup. The cached transport's `DialContext` resolves the provider at dial
time, so a reconfigured or disabled upstream is observed on the next query,
exactly as everywhere else in this design.

**Why:** the whole point of routing an app through an upstream is that its
traffic - all of it, not just the parts after a name is resolved - takes that
path. DNS is part of that traffic.

`UNIT-OR-RACE-TESTED` (`dns_policy_test.go`): `MatchAppOnly` skip behaviour,
`dnsRouteFor`'s three outcomes end to end against a real forwarding server, and
`TestDoHClientIsCachedPerUpstreamAndFailsClosed`.

**Splitting DNS from data (`validation_and_gaps.md` §55):** `Rule` also
carries an optional `DNSUpstream`, read by `dnsRouteFor` ahead of `Upstream`
and falling back to it when empty - so a rule can send an app's data one way
and its DNS another (`DNSUpstream: DirectUpstreamID` for "tunnel the data,
keep DNS on the device"; any other upstream id for split DNS). The default
route gained the same split via `RoutingSettings.defaultDNSUpstreamId` and a
"DNS for unbound apps" picker; per-app `DNSUpstream` is accepted by
`BuildAppBindingPolicyJSON` already but has no UI yet - see gap 10.

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
depth guard. Each hop's `ErrUpstreamNotReady` wraps the specific parent id
that failed (`fmt.Errorf("%w: chain parent %q", ...)`), and because each hop
only ever names its own immediate parent, a failure several hops down
already bubbles up naming the actual failing upstream, not the outermost
one - `TestChainErrorAttributesTheActualFailingHop` is a permanent
regression guard for this (`validation_and_gaps.md` §56).

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
| `AddWireGuardUpstream` | register a WireGuard tunnel from a JSON config |
| `MultiProxyWireGuardConfigFromQuick` | convert a wg-quick `.conf` into that JSON |
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

## 7. The Android layer

### 7.1 Where configuration lives

`CURRENT CODE`

The engine holds no configuration across restarts. Three stores are the source
of truth, and `UpstreamPolicyApplier` reconciles a running engine with them.

| Store | Holds | Backing |
|---|---|---|
| `UpstreamRepository` | id, kind, label, `via`, enabled, timestamps | `multiproxy_profiles.db`, table `upstreams` (schema v3) |
| `UpstreamSecretStore` | the whole configuration blob per upstream | EncryptedSharedPreferences |
| `AppBindingRepository` | package name to upstream id | `multiproxy_profiles.db`, table `app_bindings` |
| `RoutingSettings` | the default upstream for unbound apps | unencrypted prefs, alongside the split-tunnel selection |

**Why the split.** A WireGuard config contains a private key and a SOCKS5 one
may contain a password, so no configuration is written to the database at all.
Splitting a config *within* itself - secret parts encrypted, the rest not -
was rejected: it would put a WireGuard config half in each store, with the
reassembly, and the chance of writing a key to the wrong half, repeated at every
call site.

**Why package names, not UIDs.** A UID is stable only until the app is
reinstalled; the user's choice is about the app. The UID is resolved from the
package at apply time via `PackageManager.getPackageUid`, and a binding whose
package is no longer installed is dropped for that session. The row stays, so
reinstalling the app restores the binding.

### 7.2 When it is applied

`CURRENT CODE` (`IPNService.rebuildMultiProxyTunLocked`)

`UpstreamPolicyApplier.apply(engine)` runs immediately after `startVPN`, so a
registered upstream is never dialable before the datapath it belongs to exists.
It also runs from the UI on every change, because upstream registration and
policy are both designed to be replaced live - a routing change takes effect on
the next flow rather than needing the VPN restarted.

`apply` does three things:

1. Unregisters SOCKS5/WireGuard upstreams the engine still holds that are no
   longer configured or have been disabled. Without this a deleted upstream
   would keep carrying traffic until the process restarted - the one case where
   the UI and the datapath could disagree about whether traffic is still
   flowing through something. Tailnets and `@direct` are skipped; neither is
   the applier's to remove.
2. Registers the configured upstreams, parents before children
   (`registrationOrder`). Ordering is not required for correctness - `via` is
   resolved at dial time - but it means the cycle check sees the real graph.
3. Resolves bindings to UIDs and installs the policy via
   `BuildAppBindingPolicyJSON`.

Nothing in it is fatal. A misconfigured upstream is logged and skipped, which
costs its own traffic - policy rules naming it then fail closed - rather than
taking the VPN down.

### 7.3 The screens

`CURRENT CODE` (`UpstreamsView`, `AppRoutingView`, `UpstreamRoutingViewModel`)

- **Proxies & tunnels** manages SOCKS5 and WireGuard upstreams, their chaining,
  and the default route for unbound apps.
- **App routing** lists installed apps with a "Route via" picker each.

Both are backed by one view model, because they share every repository and would
otherwise keep two copies of the same state - which is exactly the bug that
matters here: a picker offering an upstream the list has just deleted.

The pickers flatten Tailnets, configured upstreams, and `@direct` into one list.
To the user these are the same decision - where does this app's traffic go -
even though they have nothing in common underneath. A disabled upstream is still
listed, marked off, so a binding to something currently switched off never looks
lost.

App routing is deliberately a separate screen from split tunnelling, which
answers a different question: whether an app uses the VPN at all, rather than
where its traffic exits.

`ANDROID-BUILT`: the whole layer compiles and links into a debug APK. There is
no instrumentation or device evidence for any of it.

### 7.4 Broad capture

`CURRENT CODE` (`RoutingSettings.broadCaptureEnabled`,
`IPNService.rebuildMultiProxyTunLocked`, `UpstreamPolicyApplier`)

By default the Multi-Tailnet `VpnService` only ever captures Tailscale-shaped
traffic: the synthetic ranges and real Tailscale's own CGNAT/ULA space (§1.2).
A non-Tailnet upstream selected for an app therefore only ever carried that
app's DNS lookups and its real-Tailscale traffic - never its general internet
or LAN traffic - because Android never handed those packets to the TUN in the
first place.

`RoutingSettings.broadCaptureEnabled` (off by default) changes what the TUN
captures, not how routing decides where captured traffic goes:
`rebuildMultiProxyTunLocked` additionally installs `0.0.0.0/0` and `::/0`
alongside the existing narrower routes. `resolveFlow` (`nat_router.go`)
needed no change - it already applies policy uniformly to any non-synthetic
destination. The one behavioural coupling is in `UpstreamPolicyApplier`:
with broad capture on and no explicit default route configured, it defaults
unbound apps to the direct upstream rather than the legacy subnet-route/
exit-node fallback, so enabling broad capture never by itself changes what
an unbound app can reach - it only makes routing that traffic *possible*.

Device-verified in `validation_and_gaps.md` §53: off is a byte-for-byte
no-op on the route table; on adds exactly the two routes; a real browser
page load under broad capture with no configured default route was observed
in `logcat` dialing through the direct provider, proving the traffic was
genuinely captured and explicitly routed, not merely still working because
it was never captured.

---

## 8. Invariants

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

## 9. Known gaps

`RECOMMENDATION` / evidence levels per `validation_and_gaps.md`.

1. **Growing device evidence; the most consequential gap now has a first
   positive result, with one loose end.** `validation_and_gaps.md` §50 has
   real emulator evidence for the upstream registry, SOCKS5 add/edit/delete,
   the default-route policy rule, and policy-routed DNS (a real DoH
   `CONNECT` observed tunneling through a SOCKS5 upstream) - but that only
   exercised the no-selector default rule. `getConnectionOwnerUid` itself is
   no longer entirely unverified: §58 bound one app (Termux) explicitly to a
   SOCKS5 upstream under broad capture and confirmed, via a relay-side log
   and a negative control (an unbound app, Chrome, produced zero connections
   on the same relay while loading a real page directly), that the flow
   router's UID lookup correctly attributed traffic to the named app and
   only that app. This is a single emulator, one API level, so the broader
   API-level/OEM-variation concern is not closed - and §58.4 records an
   unreconciled anomaly where a bound app's traffic once appeared to reach
   its target despite the named upstream being unreachable, contradicted by
   a controlled repeat that showed correct fail-closed behavior. Re-testing
   cleanly (single relay process, no restarts mid-test) is needed before the
   fail-closed axis specifically is considered closed. WireGuard specifically
   remains device-unverified as a chain hop (only proven at the Go level,
   `TestWireGuardChainedOverSOCKS5`) - but chaining *itself* is no longer
   device-unverified: a real two-hop SOCKS5-over-SOCKS5 chain was set up on
   the emulator and traced end to end, including `VpnService.protect()`
   coverage for the chained hop, `validation_and_gaps.md` §57.1. Chaining
   combined with UID-scoped attribution specifically (a chained rule that
   also names an app) now has Go-level coverage proving the two compose
   correctly through the real `resolveFlow` path -
   `validation_and_gaps.md` §68 - but still lacks the device-level evidence
   §58 gave the non-chained case (that combination needs a live tailnet
   login this pass didn't have credentials to set up).
2. ~~No Android tests for the new stores.~~ **Closed** - see
   `validation_and_gaps.md` §66. 22 `androidTest` instrumented tests (real
   on-device SQLite, not Robolectric - see that section for why) now cover
   every schema version's migration path, the preserve-the-other-column
   upsert behaviour `UpstreamRepository`/`AppBindingRepository` depend on,
   the two stale-snapshot races fixed in §65/this pass, and basic
   `ProfileRepository` CRUD (the original `validation_and_gaps.md`
   §5.1/§5.2 gap, closed in the same pass).
3. **No QR import for WireGuard.** A `.conf` can be pasted (§2.5), but the QR
   code providers print encodes the same text and would save the paste. Nothing
   in the design depends on how the text arrives.
4. **WireGuard cannot act as a responder** through `Engine.NewWireGuardUpstream`
   (§2.6, §5.3). Acceptable for a client upstream; a blocker if inbound is ever
   wanted.
5. **DNS inside a WireGuard upstream is unused.** `WireGuardConfig.DNS` is
   parsed and carried but the multiproxy resolver handles DNS itself, so it only
   affects lookups made by the tunnel's own netstack - of which there are
   currently none.
6. ~~DNS is not policy-routed.~~ **Closed** - see §3.5. A forwarded query now
   follows the querying app's route: refused if policy blocks the app,
   SERVFAIL if the named upstream is missing or not ready, otherwise exchanged
   through that upstream. `UNIT-OR-RACE-TESTED` and, as of
   `validation_and_gaps.md` §50.2, device-verified: a real DoH request was
   observed tunneling through a SOCKS5 upstream on a running emulator.
7. ~~The VPN only ever captured Tailscale-shaped traffic; a non-Tailnet
   upstream could only ever carry an app's DNS lookups and its real-Tailscale
   traffic, never its general internet or LAN traffic.~~ **Closed** - see
   §7.4 below and `validation_and_gaps.md` §53. Opt-in
   (`RoutingSettings.broadCaptureEnabled`, off by default) broad capture adds
   `0.0.0.0/0`/`::/0` routes alongside the existing narrower ones, with
   `UpstreamPolicyApplier` defaulting unbound apps to the direct upstream
   when it is on, so turning it on never by itself changes what an unbound
   app can reach. `INSTRUMENTATION-OR-EMULATOR-TESTED`. LAN-destination
   default-exclusion behaviour under broad capture is now closed - see gap 9
   below.
8. ~~`Provider.Ready()` was a bare bool with no per-upstream stats or
   history; a degraded upstream failed silently from the user's point of
   view.~~ **Closed** - see `validation_and_gaps.md` §52. Every real dial
   (flow router, DNS forwarding, chained upstreams) is now counted via
   `readyProvider`'s stats wrapper (`stats.go`): attempts, successes,
   failures, not-ready observations, TCP byte counts, last error and
   latency, exposed via `GetUpstreamStatsJSON` and a best-effort
   `OnUpstreamHealthChanged` event on readiness transitions. Surfaced on the
   Proxies & tunnels screen. `UNIT-OR-RACE-TESTED` and
   `INSTRUMENTATION-OR-EMULATOR-TESTED`: a SOCKS5 upstream pointed at a
   closed port went from "Ready" to a live "N succeeded, M failed" with the
   real dial error, on-device. Byte counts now cover TCP flows and UDP
   associations both (`validation_and_gaps.md` §67); DNS forwards remain
   uncounted deliberately - `exchangePlainVia`/`exchangeDoHVia` only see
   whole `dns.Msg` values, not a wire byte count, and estimating one via
   `dns.Msg.Len()` would conflict with these counters' "real counts, not
   estimates" design.
9. ~~With broad capture on, LAN destinations (a printer, a NAS, a dev
   server) would follow whatever route an app or the default route pointed
   at, same as any other destination - there was no way to keep LAN
   reachability working while routing general internet traffic
   elsewhere.~~ **Closed, partially** - see `validation_and_gaps.md` §54.
   `RoutingSettings.lanExclusionEnabled` (on by default) prepends an
   `ActionDirect` rule over `multiproxy.DefaultLANPrefixes()` ahead of every
   per-app binding, via a "Keep LAN traffic direct" switch on the Proxies &
   tunnels screen; a policy-only change, applied live with no VPN restart.
   `UNIT-TESTED` (rule-ordering and the ULA/real-Tailscale non-overlap
   guard) and `ANDROID-BUILT`; the toggle itself is
   `INSTRUMENTATION-OR-EMULATOR-TESTED` (renders correctly, correct
   defaults), but a live device trace of the rule winning over a
   *configured, non-Direct* default upstream was not done. **Closed in
   full** - see `validation_and_gaps.md` §69 - with the per-app override
   ("still tunnel LAN traffic for this one app") the original plan
   described: `AppBinding` gained a `tunnelLan` column (schema v6), a
   per-app "Tunnel LAN traffic for this app" switch on the App routing
   screen (shown only once the app has a data route *and* the global
   exclusion is on - otherwise there's nothing to override), and
   `BuildAppBindingPolicyJSON` now emits per-app override rules ahead of
   the global exclusion rule, ahead of the regular per-app binding rules,
   ahead of the default - the ordering the original plan called out as
   needing explicit test coverage, which it now has
   (`TestPerAppLANOverrideWinsOverGlobalExclusionForThatAppOnly`).
10. ~~DNS/data split has no per-app UI yet~~ **Closed** - see
    `validation_and_gaps.md` §64. `AppBinding` gained a `dnsUpstreamId`
    column (the schema change this gap and gap 9 both pointed at), and
    `AppRoutingView` now shows a second picker per bound app ("DNS via: ...")
    beneath its data-route picker, shown only once the app has a non-empty
    data route - `BuildAppBindingPolicyJSON` skips a binding rule entirely
    when `upstream` is empty, so a DNS-only override with no data route has
    nothing to attach to, and the UI now reflects that constraint rather
    than offering a picker that would silently do nothing.
    **Private DNS Strict mode remains uncharacterized** (Off/Automatic are
    confirmed) - that half of this gap is still open.
    `validation_and_gaps.md` §55: `Rule.DNSUpstream` and
    `BuildAppBindingPolicyJSON`'s per-binding `dnsUpstream` are implemented
    and `UNIT-TESTED`; only the **default-route** picker ("DNS for unbound
    apps") had shipped a UI before this pass, `INSTRUMENTATION-OR-EMULATOR-TESTED`.
    Separately, `validation_and_gaps.md` §57.2 device-tested Android's three
    Private DNS modes against the synthetic resolver: Off and Automatic
    both confirmed working (fresh MagicDNS names resolved correctly in
    both). Strict mode's result is **inconclusive**, not negative or
    positive - this test sandbox's own network cannot complete a DoT
    handshake to any strict-mode server at all, confirmed independent of
    this app (Android itself reported no internet access with the VPN
    stopped entirely), so gap #16's prediction that Strict mode breaks
    MagicDNS resolution remains untested rather than confirmed.
11. ~~§1.3 named "exit-node selection for non-Tailnet traffic" as an original
    requirement, but Multi-Tailnet's UI never wired it up: `Engine.SetExitNode`
    (the legacy Tailnet-exit-node fallback used at the bottom of
    `resolveFlow`'s ladder) was never called from Kotlin, and STANDARD mode's
    own exit-node picker had no Multi-Tailnet equivalent.~~ **Closed** - see
    `validation_and_gaps.md` §59. Two paths now exist, deliberately different
    in cost: `Engine.SetTailnetExitNode` (`upstream_tailnet.go`) edits an
    already-running tailnet's own `Prefs.ExitNodeIP` in place - no new auth,
    no new device slot, but only one exit node active per tailnet at a time,
    surfaced as an "Exit node" picker on each tailnet's card in the
    Multi-Tailnet screen. `Engine.AddExitNodeUpstream`
    (`upstream_exitnode.go`) stands up a second, independently-authenticated
    `tsnet.Server` pinned to one peer via `EditPrefs`, registered as a new
    `UpstreamKind.EXITNODE` upstream with full parity to SOCKS5/WireGuard
    (chainable via `via`, poolable as a default route, its own row in the
    Upstreams screen) - the only way to get two or more simultaneously-active
    exit nodes out of the *same* tailnet, since one node identity can only
    hold one `ExitNodeIP` preference. `UNIT-TESTED` (13 Go tests in
    `upstream_exitnode_test.go`, full `multiproxy` suite still green) and
    `ANDROID-BUILT` (`compileDebugKotlin` and a full `assembleDebug` both
    succeed). Building with `-PtestAbi=x86_64` (this emulator's native ABI,
    since `make libtailscale` produces every gomobile-bind ABI, not only
    arm64-v8a) sidesteps a separate arm64-translation `SIGILL` crash and gave
    `INSTRUMENTATION-OR-EMULATOR-TESTED` confirmation that both new dialogs
    (the exitnode `Add upstream` form and the tailnet card's "Exit node"
    picker) render correctly; a real second identity reaching `RUNNING`
    against a live tailnet is still unverified - no multi-device credentials
    exist in this sandbox. `validation_and_gaps.md` §60 also hardens Path B
    directly against the concern that motivated it ("can the backend really
    handle several new auths against the same tailnet"): a stuck
    `NeedsMachineAuth`/`NeedsLogin` identity was previously indistinguishable
    from a working one (`AddExitNodeUpstream`'s `EditPrefs` succeeds locally
    regardless of control-plane approval) - now surfaced live via
    `GetExitNodeStatesJSON` and an "Identity: ..." line per row; the
    per-runtime status polling this relies on was parallelized so it does not
    fall behind its own 1s poll interval as the number of simultaneous
    identities grows; and `AddExitNodeUpstream` now enforces
    `maxExitNodeUpstreams = 8` so a mistake or a script cannot spin up an
    unbounded number of real tsnet.Server processes. Whether Tailscale's
    control plane itself rate-limits or flags rapid multi-device registration
    from one account remains untested - that needs real multi-device
    credentials this sandbox does not have.

    A closer read-through of this feature after the above landed found two
    more real bugs, both fixed (see `validation_and_gaps.md` §61, §62): a
    bootstrap `AuthKey` (tailnet's and exit-node's alike) stayed resident in
    the Go engine's in-memory `Config` indefinitely - `ClearTailnetAuthKey`
    existed but was dead code, called from nowhere - now wired into the
    existing state-poll paths so it clears the moment a real `Running` state
    is observed; and disabling an exit-node upstream from the UI actually
    called `ForgetExitNodeUpstream`, permanently destroying its device
    identity and demanding a fresh auth key on every re-enable, rather than
    `SetExitNodeUpstreamEnabled(false)` (which existed but, before the fix,
    was never called with `false` from anywhere in Kotlin) - directly
    reproducing the multi-auth-churn concern this whole feature pass was
    trying to guard against.

12. **The encrypted Kotlin-side secret store still keeps the raw auth key
    forever.** `UpstreamSecretStore` (`android/.../multiproxy/UpstreamSecretStore.kt`)
    persists an exit-node upstream's full config JSON - including the
    bootstrap `authKey` - in `EncryptedSharedPreferences`, with no code path
    that ever strips the key back out after the identity is confirmed
    running. `registerExitNode` (`UpstreamPolicyApplier.kt`) reads that same
    stored config and passes the key to `AddExitNodeUpstream` again on every
    VPN rebuild, which is why it has to still be there - tsnet only actually
    needs the key on first login and should ignore it once the state
    directory already holds a valid one, but nothing on the Kotlin side
    currently distinguishes "still needed" from "already provisioned,
    keeping this around is just unnecessary secret retention." Closing this
    properly needs a small Go-side API change (an `AddExitNodeUpstream`
    variant, or an added query, that lets Kotlin tell whether the key is
    still required) plus a live `Running` signal reaching the Kotlin secret
    store (`OnTailnetStateChange` already exists as an event but is
    currently just logged, not wired to anything - see `IPNService.kt`) to
    know when to actually purge the field. Deliberately not attempted
    tonight: it changes a public Go/gomobile method signature other callers
    depend on, and verifying it does not break re-registration after a real
    app restart needs live auth credentials this sandbox does not have -
    the same recurring constraint as the items above. Flagged here rather
    than rushed.
