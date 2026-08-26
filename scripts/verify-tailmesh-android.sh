#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cache_root=${CACHE_ROOT:-$repo_dir/.cache}
export GOCACHE="$cache_root/go-build"
export GOMODCACHE="$cache_root/gomod"
export GRADLE_USER_HOME="$cache_root/gradle"
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}
export JAVA_HOME=${JAVA_HOME:-$HOME/jdk17}
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
unset TOOLCHAINDIR TS_ANDROID_ALLOW_EXTERNAL_TOOLCHAIN TS_PERMIT_TOOLCHAIN_MISMATCH
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GRADLE_USER_HOME"
cd "$repo_dir"

expected_toolchain=63ae404c8203317fd3c82d972e5dc8f0fcb425cb
test "$(tr -d '\n' < go.toolchain.rev)" = "$expected_toolchain"
test "$(tr -d '\n' < ../tailscale/go.toolchain.rev)" = "$expected_toolchain"
rg -q '^replace tailscale.com => ../tailscale$' go.mod
./tool/go version
./tool/go list -m -json tailscale.com
rm -rf android/build/go temp_aar android/libs/libtailscale.aar android/libs/libtailscale_unstripped.aar libgojni.so.* tailscale-debug.apk
./tool/go clean -cache
./tool/go test -race ./libtailscale/multiproxy
(cd ../tailscale && ./tool/go test ./net/dns/resolver)
make build-unstripped-aar
make libtailscale
(cd android && ./gradlew --stop && ./gradlew clean testDebugUnitTest assembleDebug)
cp android/build/outputs/apk/debug/android-debug.apk tailscale-debug.apk
unzip -p tailscale-debug.apk lib/arm64-v8a/libgojni.so > /tmp/tailmesh-apk-check.so
./tool/go version -m /tmp/tailmesh-apk-check.so
rg -a -q "$expected_toolchain" /tmp/tailmesh-apk-check.so
sha256sum tailscale-debug.apk

if [[ -n ${TAILMESH_ADB_SERIAL:-} ]]; then
  adb -s "$TAILMESH_ADB_SERIAL" install -r tailscale-debug.apk
  adb -s "$TAILMESH_ADB_SERIAL" logcat -c
  adb -s "$TAILMESH_ADB_SERIAL" shell monkey -p com.tailscale.ipn.multiproxy 1
  adb -s "$TAILMESH_ADB_SERIAL" shell pidof com.tailscale.ipn.multiproxy
  adb -s "$TAILMESH_ADB_SERIAL" logcat -d -t 500 | rg -i 'panic|toolchain|SIGABRT|FATAL|AndroidRuntime' || true
fi
