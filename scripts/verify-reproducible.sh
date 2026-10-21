#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Rebuilds a Tailmesh release from source and checks that every APK is
# byte-for-byte the published one, apart from the signature: the release's
# signature is copied onto the rebuilt, unsigned APK, which must then verify.
#
# Usage: scripts/verify-reproducible.sh <tag> [dir]
#   dir        the release's APKs; downloaded from the GitHub release if omitted
# Environment:
#   CORE_SHA   franticplant/tailscale commit to build against; read from the
#              release notes if unset
#   WORK_DIR   where to clone and build (default: a new temporary directory)
#   TAILMESH_URL, CORE_URL  repositories to clone (default: GitHub)
#
# Needs git, gh (unless dir and CORE_SHA are both given), JDK 17, the Android
# SDK with the NDK the Makefile pins, and apksigcopier (pip install apksigcopier).
set -euo pipefail

tag=${1:?usage: $0 <tag> [dir-with-release-apks]}
repo=franticplant/tailmesh-android
tailmesh_url=${TAILMESH_URL:-https://github.com/$repo}
core_url=${CORE_URL:-https://github.com/franticplant/tailscale}
work=${WORK_DIR:-$(mktemp -d)}
official=$(realpath -m "${2:-$work/official}")
export ANDROID_HOME=${ANDROID_HOME:-$HOME/Android/Sdk}

command -v apksigcopier > /dev/null || { echo "apksigcopier not found: pip install apksigcopier" >&2; exit 1; }

if [[ -z ${2:-} ]]; then
	mkdir -p "$official"
	gh release download "$tag" -R "$repo" -p '*.apk' -D "$official"
fi
if [[ -z ${CORE_SHA:-} ]]; then
	CORE_SHA=$(gh release view "$tag" -R "$repo" --json body --jq .body |
		grep -oE 'franticplant/tailscale@[0-9a-f]{40}' | head -1 | cut -d@ -f2)
	[[ -n $CORE_SHA ]] || { echo "no core commit in the $tag release notes; set CORE_SHA" >&2; exit 1; }
fi

# Releases made before versionCode came from the commit used the build time,
# so take it from the release itself; all of a release's APKs share it.
build_tools=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
apks=("$official"/tailmesh-"$tag"-*.apk)
[[ -f ${apks[0]} ]] || { echo "no tailmesh-$tag-*.apk in $official" >&2; exit 1; }
version_code=$("$build_tools/aapt2" dump badging "${apks[0]}" | sed -nE "s/.*versionCode='([0-9]+)'.*/\1/p")

echo "Rebuilding $tag (core $CORE_SHA, versionCode $version_code) in $work"
rm -rf "$work/tailmesh-android" "$work/tailscale"
git clone -q --branch "$tag" "$tailmesh_url" "$work/tailmesh-android"
git clone -q "$core_url" "$work/tailscale"
git -C "$work/tailscale" checkout -q --detach "$CORE_SHA"

cd "$work/tailmesh-android"
# A fresh Go build cache, so nothing is reused from an earlier build, and no
# release signing, whatever this machine has configured.
export GOCACHE="$work/gocache"
unset TAILMESH_KEYSTORE TAILMESH_KEYSTORE_PASSWORD TAILMESH_KEY_ALIAS TAILMESH_KEY_PASSWORD
export TAILMESH_SIGNING_PROPERTIES=/nonexistent
make version android/libs/libtailscale.aar
(cd android && ./gradlew --no-build-cache -q assembleRelease -PsplitAbis -PVERSION_CODE_BASE="$version_code")

failed=0
for apk in "${apks[@]}"; do
	abi=${apk##*/tailmesh-"$tag"-}
	abi=${abi%.apk}
	rebuilt=android/build/outputs/apk/release/android-$abi-release-unsigned.apk
	if apksigcopier compare "$apk" --unsigned "$rebuilt"; then
		echo "reproduced: ${apk##*/}"
	else
		echo "DIFFERS:    ${apk##*/} (rebuilt: $work/tailmesh-android/$rebuilt)"
		failed=1
	fi
done
exit $failed
