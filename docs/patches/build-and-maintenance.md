# Build and Maintenance Notes

## Repository Pair

Tailmesh currently builds from two sibling working trees:

```text
parent/
├── tailscale-android/   # this repository
└── tailscale/           # franticplant/tailscale patched core
```

The Android repository intentionally contains:

```go
replace tailscale.com => ../tailscale
```

For `main`, the required core is:

```text
repository: franticplant/tailscale
branch:     tailmesh-android-base
commit:     c36d08c12ef5a6eb3c057db203fbc6cee982ed5c
base:       25877455e79d9e3ebd5e99200ca86fd62bcc0ed9
```

Do not build this Android branch against `franticplant/tailscale:main`. The custom
`main` had advanced 47 upstream commits beyond the Android client's intended core
revision. `tailmesh-android-base` instead starts at the exact Tailscale revision
expected by this Android source tree and carries only the required patches:

```text
net/dns/config.go              # DNS config mutation hook
net/dns/manager.go             # DNS config mutation hook
net/dns/resolver/forwarder.go  # selectable DoH fallback resolvers
feature/taildrop/ext.go        # don't call the nil newFileOps hook on Android
```

The Taildrop patch is a crash fix rather than a feature hook: `fileops_fs.go`
is `//go:build !android`, so `newFileOps` is nil on Android and calling it
panics whenever a profile change reaches that path with no SAF `FileOps`
installed.

The compatibility core and Android wrapper both use Tailscale Go toolchain:

```text
63ae404c8203317fd3c82d972e5dc8f0fcb425cb
```

`tool/go` checks the sibling core's `go.toolchain.rev` before compiling and
refuses normal builds that inherit `TOOLCHAINDIR`, because either mismatch can
produce a `libgojni.so` that aborts during Tailscale initialization.

## What the Compatibility Problem Actually Was

There are three related but separate things in this build:

```text
1. tailscale-android
   Android/Kotlin app plus the Gomobile wrapper.

2. tailscale.com core
   The Go networking implementation that is compiled into libgojni.so.

3. tailscale/go
   Tailscale's patched Go compiler/toolchain used to build that core.
```

They need to come from compatible generations.

The confusing part is that `tailscale-android/go.mod` contains a normal
`tailscale.com` pseudo-version, but the line:

```go
replace tailscale.com => ../tailscale
```

wins over that version during a local build. In other words, the source actually
compiled into the APK is whatever commit is checked out in the sibling
`../tailscale` directory.

The broken setup had this shape:

```text
tailscale-android
  based around core commit 25877455...
  originally paired with toolchain 63ae404c...

        +

../tailscale on custom main
  47 upstream commits newer
  expected toolchain 7275f792...

        +

native build still using toolchain 63ae404c...
```

That combination could compile successfully. However, Tailscale deliberately
embeds the expected `go.toolchain.rev` in the core and the compiler revision in
Go build metadata. During Go package initialization it checks the two values.
The resulting APK therefore aborted immediately with:

```text
binary toolchain: 63ae404c...
core expects:      7275f792...
```

This was not an Android 17 compatibility failure and not a multiproxy runtime
failure. Android successfully loaded `libgojni.so`; the Tailscale core then
intentionally panicked because its source and compiler did not match.

The fix is not to disable the assertion. The fix is to keep one coherent
upstream generation. For the current Tailmesh branch we chose the Android
client's original generation:

```text
Tailscale core base 25877455...
        │
        ├── tailscale-android + Tailmesh/multiproxy changes
        │
        └── franticplant/tailscale:tailmesh-android-base
              + only the required DNS patches

Both sides use tailscale/go revision 63ae404c...
```

The custom core is still required. `tailmesh-android-base` is not stock
Tailscale: it retains the DNS hooks and diagnostics consumed by the Android
fork. What was removed was unrelated upstream drift, not our required custom
functionality.

A future Tailscale upgrade should therefore update the Android wrapper, patched
core base, and Tailscale Go toolchain deliberately as one compatibility unit.
Do not independently move `../tailscale` to a newer `main` and assume the
Android wrapper will remain compatible.

## Why the Core Patch Exists

The Android public-DoH feature must alter `dns.Config.DefaultResolvers` before
Tailscale compiles resolver and OS DNS policy. The patched core provides:

```go
dns.HookModifyConfig
resolver.AndroidDNSConfigLogEnabled
resolver.AndroidDNSQueryLogEnabled
```

and the related route-aware DoH diagnostics used by
`libtailscale/control_doh.go`.

Changing only Android's final DNS-server list would be too late and could break
MagicDNS, split-DNS routing, or exit-node DNS semantics.

## Clean Build

Before a native rebuild, make sure both repositories are on the required refs:

```sh
cd ../tailscale
git checkout tailmesh-android-base
git reset --hard origin/tailmesh-android-base
cd ../tailscale-android
git checkout main
git reset --hard origin/main
```

Verify the toolchain contract:

```sh
cat go.toolchain.rev
cat ../tailscale/go.toolchain.rev
```

Both must print:

```text
63ae404c8203317fd3c82d972e5dc8f0fcb425cb
```

For a forensic clean rebuild after native changes:

```sh
unset TOOLCHAINDIR
unset TS_ANDROID_ALLOW_EXTERNAL_TOOLCHAIN
cd android && ./gradlew --stop && cd ..
rm -rf android/build/go temp_aar
rm -f android/libs/libtailscale.aar android/libs/libtailscale_unstripped.aar
rm -f libgojni.so.unstripped libgojni.so.stripped libgojni.so.debug
rm -f tailscale-debug.apk
./tool/go clean -cache
make build-unstripped-aar
make libtailscale
make tailscale-debug.apk
```

A Gradle-only rebuild is not sufficient after Go or patched-core changes.

## Native Provenance Check

Before installing an APK, inspect the actual native library that will ship:

```sh
unzip -p tailscale-debug.apk lib/arm64-v8a/libgojni.so > /tmp/tailmesh-libgojni.so
./tool/go version -m /tmp/tailmesh-libgojni.so
readelf -n /tmp/tailmesh-libgojni.so | grep -A3 -i 'build.id' || true
```

The embedded `tailscale.toolchain.rev` must be:

```text
63ae404c8203317fd3c82d972e5dc8f0fcb425cb
```

Do not use `TS_PERMIT_TOOLCHAIN_MISMATCH=1`. A mismatch is a build defect, not a
runtime condition to suppress.

## Tests

At minimum:

```sh
./tool/go test -race ./libtailscale/multiproxy
cd ../tailscale && ./tool/go test ./net/dns/resolver && cd ../tailscale-android
cd android && ./gradlew --stop && ./gradlew clean testDebugUnitTest && cd ..
```

If a physical Android device is connected, install the freshly inspected APK,
clear logcat, launch Tailmesh, and verify the process stays alive before starting
multi-Tailnet E2E testing.

## Common Failure Modes

### Stale AAR or native library

If Android/Kotlin changes appear but Go behavior does not, compare the SHA256 and
ELF BuildId of `libgojni.so` in the unstripped AAR, stripped AAR, final APK, and
installed APK. A fresh Android versionCode does not prove the native library was
rebuilt.

### Wrong sibling core

If `../tailscale` is on `main`, switch it to `tailmesh-android-base`. The relative
`replace` directive makes the checked-out sibling source authoritative regardless
of the pseudo-version shown in `go.mod`.

### External Go toolchain

Normal Tailmesh builds must leave `TOOLCHAINDIR` unset. `tool/go` deliberately
fails closed if an external toolchain is inherited. Deliberate packaging systems
may opt in with `TS_ANDROID_ALLOW_EXTERNAL_TOOLCHAIN=1`, but then they own proving
that the produced binary satisfies Tailscale's toolchain assertion.

## Public DoH Runtime Verification

With DNS diagnostics enabled, selected public DoH queries should log
`ANDROID_DNS_USAGE` and distinguish route-aware from system-route dialing. Test
MagicDNS, split DNS, and exit-node DNS semantics after the basic application and
multi-Tailnet startup tests pass.

## Release Notes

Current limitations to retain in release documentation:

- Manual HTTP proxy does not proxy direct WireGuard UDP.
- Manual HTTP proxy does not proxy STUN/netcheck UDP.
- Public DoH override depends on the patched compatibility core.
- Arbitrary DoH URLs are not supported.
- DNS query logs can reveal visited domains and should remain off by default.
