## 1. Tailmesh

Tailmesh is an independent Android networking client focused on using multiple Tailnet identities concurrently behind one Android `VpnService`.

It is derived from the BSD-3-Clause [Tailscale Android client](https://github.com/tailscale/tailscale-android) and builds against a separately maintained, patched checkout of the BSD-3-Clause [`tailscale.com` core](https://github.com/tailscale/tailscale).

**Tailmesh is not affiliated with, sponsored by, or endorsed by Tailscale Inc.** Tailscale is a trademark of Tailscale Inc.

## 2. What this fork adds

The main fork-specific mode is the multi-Tailnet proxy:

```text
one Android VpnService / TUN
        |
one synthetic IPv6 /48
        |
one gVisor userspace stack
        |
synthetic target lookup + DNS
        |
one required profile / upstream
        |
multiple independent tsnet.Server runtimes
```

The implementation includes one Android VPN/TUN, deterministic synthetic IPv6 peer identity, collision-safe DNS/target mapping, TCP/UDP userspace proxying, multiple independent `tsnet.Server` runtimes, persistent Android profiles, runtime reconstruction, and the patched-core DNS integration used by this fork.

The canonical engineering documentation starts at [`docs/multi_tailnet_proxy_app/README.md`](docs/multi_tailnet_proxy_app/README.md).

## 3. Repository pair and pinned core

This Android tree intentionally builds with a sibling checkout:

```text
parent/
|-- tailscale-android/   # this repository
`-- tailscale/           # patched Tailscale core
```

`go.mod` contains:

```go
replace tailscale.com => ../tailscale
```

For `main`, the exact compatibility core and Tailscale Go toolchain are documented in [`docs/patches/build-and-maintenance.md`](docs/patches/build-and-maintenance.md). Do not silently substitute `franticplant/tailscale:main`; the Android wrapper, patched core, and Tailscale Go toolchain form one compatibility unit.

## 4. Building

In a correctly paired two-tree checkout, normal development paths include:

```sh
make androidsdk
make build-unstripped-aar
make libtailscale
make tailscale-debug.apk
```

The build targets, Kotlin source namespace, module path, and some internal identifiers still retain inherited Tailscale names. Internal compatibility naming is different from the public Tailmesh product identity.

There is currently no official Tailmesh Play Store, F-Droid, Amazon Appstore, or other binary distribution channel. Official Tailscale package/store links are not Tailmesh download links.

## 5. Android application identity

**Current code:** the installed application ID is still:

```text
com.tailscale.ipn.multiproxy
```

**Planned OSS action:** migrate it to an independent ID such as:

```text
io.github.franticplant.tailmesh
```

That migration is intentionally tracked separately because the application ID is part of Android state and test tooling, not merely a display string. It must update ADB/emulator integration paths and be validated as one unit. The Kotlin source namespace can remain `com.tailscale.ipn` initially; moving all Kotlin packages, source directories, `R`, and `BuildConfig` references is a larger optional refactor.

Changing the application ID will make Android treat the result as a different application. Existing development installs will not upgrade in place, and the new ID gets separate app data and VPN authorization.

## 6. Tailscale-hosted services

The code license and the hosted Tailscale service are separate things.

Unless an alternate control server is configured, inherited behavior can use Tailscale-operated control/login infrastructure, DERP, documentation/support, and diagnostic/logging infrastructure. Use of those services is governed separately by applicable Tailscale terms and policies. The BSD-3-Clause code license is not itself a grant to use Tailscale trademarks or hosted services.

Before wide binary distribution, the hosted-service/Terms-of-Service questions in [`docs/oss-readiness.md`](docs/oss-readiness.md) must be resolved.

## 7. Licensing and notices

The inherited Android code is BSD-3-Clause. The root [`LICENSE`](LICENSE) is retained unchanged. The repository also contains the upstream [`PATENTS`](PATENTS) grant; its application to third-party modifications is an explicit legal-review item rather than something Tailmesh assumes.

A pre-release dependency/attribution inventory is in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). It does not replace generating and reviewing exact notices from the resolved Go and Gradle release graphs before distributing binaries.

Inherited source keeps upstream copyright/SPDX notices. The owner still needs a consistent copyright-header policy for wholly fork-authored files.

## 8. Support and issues

Tailmesh project bugs belong in this repository's issue tracker:

https://github.com/franticplant/tailmesh-android/issues

Questions about a user's Tailscale-hosted account, billing, hosted service, or account deletion remain matters for Tailscale's own service/support channels.

## 9. Publication status

This repository is undergoing OSS-readiness work. See [`docs/oss-readiness.md`](docs/oss-readiness.md) for the evidence ledger and release gates.

A public source push or binary release should not be treated as cleared until the full-history secret scan, public/reproducible patched-core dependency, exact dependency-license generation, remaining brand-asset cleanup, application-ID migration, post-change build/device validation, hosted-service review, trademark review, and patent-scope review are complete.

WireGuard is a registered trademark of Jason A. Donenfeld.
