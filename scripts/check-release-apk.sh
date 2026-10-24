#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Checks that APKs carry none of the development-only features (remote app
# updates and the remote shell, BuildConfig.DEV_TOOLS / -PdevTools), so a
# release or pre-release can't ship them by mistake.
#
# Usage: scripts/check-release-apk.sh [--expect-dev] APK...
#   --expect-dev  the opposite: every check must find its dev-only piece. CI
#                 runs it on the dev builds, so a check that stops seeing what
#                 it looks for fails there instead of passing silently.
#
# What it looks at, per APK:
#   manifest  no REQUEST_INSTALL_PACKAGES or UPDATE_PACKAGES_WITHOUT_USER_ACTION
#             permission and no AppUpdater$AppUpdateReceiver (the devTools
#             manifest overlay); the version name does not end in -dev
#   dex       BuildConfig.DEV_TOOLS is false, and no code calls the entry
#             points that turn the features on: AppUpdater.install and
#             .updateDir (app.update, the server's update directory),
#             RemoteShell.configure (the shell part of the server config) and
#             RemoteShell.onRequest (a shell request reaching the phone).
#             DEV_TOOLS is a compile-time constant, so in a release these
#             call sites are compiled out.
#
# What it does not cover: the RemoteShell and AppUpdater classes stay in the
# dex (proguard-rules.pro keeps all of com.tailscale.ipn.**), unreachable
# without those call sites; and the Go shell and update code is in the shared
# AAR, off unless the app passes Config.Shell / Config.UpdateDir, which the
# call sites above are the only way to do (see DevToolsGateTest for the
# Kotlin side and remotectl's tests for the server).
#
# Needs the Android SDK build-tools (aapt2, dexdump) under $ANDROID_HOME.
set -euo pipefail

expect_dev=false
if [[ ${1:-} == --expect-dev ]]; then
	expect_dev=true
	shift
fi
[[ $# -gt 0 ]] || { echo "usage: $0 [--expect-dev] APK..." >&2; exit 2; }

sdk=${ANDROID_HOME:-$HOME/Android/Sdk}
bt=$(ls -d "$sdk"/build-tools/* 2> /dev/null | sort -V | tail -1)
aapt2=$bt/aapt2
dexdump=$bt/dexdump
[[ -x $aapt2 && -x $dexdump ]] || { echo "aapt2/dexdump not found under $sdk/build-tools" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
# found NAME FOUND: FOUND is "yes" if the dev-only piece is in the APK.
found() {
	local name=$1 got=$2
	if $expect_dev; then
		if [[ $got == yes ]]; then echo "  ok    $name (present, as expected in a dev build)"; else
			echo "  FAIL  $name: not found in a dev build; the check no longer sees it"
			fail=1
		fi
	else
		if [[ $got == no ]]; then echo "  ok    no $name"; else
			echo "  FAIL  $name is present"
			fail=1
		fi
	fi
}

yesno() { if "$@"; then echo yes; else echo no; fi; }

for apk in "$@"; do
	echo "$apk"
	badging=$("$aapt2" dump badging "$apk")
	manifest=$("$aapt2" dump xmltree --file AndroidManifest.xml "$apk")
	found "REQUEST_INSTALL_PACKAGES permission" \
		"$(yesno grep -q "uses-permission: name='android.permission.REQUEST_INSTALL_PACKAGES'" <<< "$badging")"
	found "UPDATE_PACKAGES_WITHOUT_USER_ACTION permission" \
		"$(yesno grep -q "uses-permission: name='android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION'" <<< "$badging")"
	found 'AppUpdater$AppUpdateReceiver receiver' \
		"$(yesno grep -qF 'remote.AppUpdater$AppUpdateReceiver' <<< "$manifest")"
	found "-dev version name" "$(yesno grep -qE "^package: .* versionName='[^']*-dev'" <<< "$badging")"

	rm -rf "${work:?}"/*
	unzip -q -o "$apk" 'classes*.dex' -d "$work"
	dump=$work/dump.txt
	for dex in "$work"/classes*.dex; do
		"$dexdump" -d "$dex" 2> /dev/null >> "$dump"
	done
	value=$(grep -A4 "name          : 'DEV_TOOLS'" "$dump" | grep -m1 -oE 'value +: (true|false)' | awk '{print $NF}' || true)
	if [[ -z $value ]]; then
		echo "  FAIL  BuildConfig.DEV_TOOLS not found in the dex"
		fail=1
	else
		found "BuildConfig.DEV_TOOLS=true" "$([[ $value == true ]] && echo yes || echo no)"
	fi
	for m in 'AppUpdater;.install' 'AppUpdater;.updateDir' 'RemoteShell;.configure' 'RemoteShell;.onRequest'; do
		found "call to ${m/;./.}" \
			"$(yesno grep -qE "invoke-[a-z/]+ \{[^}]*\}, Lcom/tailscale/ipn/remote/${m//./\\.}:" "$dump")"
	done
done

if [[ $fail != 0 ]]; then
	if $expect_dev; then
		echo "the release check no longer recognises a dev build; update $0" >&2
	else
		echo "development-only features found; releases must be built without -PdevTools" >&2
	fi
	exit 1
fi
