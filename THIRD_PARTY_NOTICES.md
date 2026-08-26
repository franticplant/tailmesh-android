# Third-party notices (pre-release inventory)

Tailmesh is derived from and incorporates third-party open-source software. This file is an OSS-readiness inventory, not yet the final machine-generated binary notice bundle.

## Tailscale Android and Tailscale core

Tailmesh contains software derived from:

- `tailscale/tailscale-android`
- `tailscale/tailscale`

Copyright (c) 2020 Tailscale Inc. and contributors/authors, as stated in the respective source files and license texts.

Those projects are distributed under the BSD 3-Clause License. The inherited license text is preserved in this repository's `LICENSE`, and the patched Tailscale core repository carries its own license text.

Neither the name of Tailscale Inc. nor the names of its contributors may be used to endorse or promote derived products without specific prior written permission.

Tailmesh is an independent project and is not affiliated with, sponsored by, or endorsed by Tailscale Inc. Tailscale is a trademark of Tailscale Inc.

## gVisor

The multi-Tailnet userspace networking path uses `gvisor.dev/gvisor`, licensed under Apache License 2.0 with additional per-file permissive notices in the gVisor source tree. Apache-2.0 includes copyright, redistribution, notice, trademark, and patent provisions that remain applicable to the portions used by Tailmesh.

## WireGuard implementations

The Go dependency graph includes `github.com/tailscale/wireguard-go`, distributed under the MIT License at the version selected by `go.mod`.

WireGuard is a registered trademark of Jason A. Donenfeld.

## Other dependencies

The current Go and Android dependency graphs include software under permissive licenses including BSD-2-Clause, BSD-3-Clause, MIT, ISC, and Apache-2.0. Test tooling also includes software under licenses such as Eclipse Public License 1.0.

Before a public binary release, regenerate this inventory from the exact resolved release graphs and include the full license/NOTICE material required by every dependency actually shipped in the APK/AAB. In particular:

- generate the Go package license inventory for the exact packages linked into the Gomobile AAR;
- resolve Gradle `releaseRuntimeClasspath` and inventory licenses for packaged Android/JVM artifacts;
- review Apache-2.0 NOTICE obligations and modified-file notices where applicable;
- verify that test-only dependencies are not inadvertently shipped;
- investigate any unknown or unclassified dependency licenses.

The inherited `.github/licenses.tmpl` and upstream Tailscale-hosted license pages are useful source material, but they are not a complete Tailmesh release notice by themselves.
