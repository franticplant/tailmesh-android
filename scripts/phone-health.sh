#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# One-screen health snapshot of a phone through remote control: mode, each
# tailnet's state, every upstream's readiness and path, listeners'
# registration and last errors, direct-links state, remote control's own
# health and the app's process uptime. Read-only.
#
# Usage: scripts/phone-health.sh [-o file] [-wait seconds]
#   -o file     also save the raw JSON of every call to file (for diffing)
#   -wait N     first wait until all enabled tailnets are Running, up to N s
#               (after a restart); exits 1 if they don't get there
#
# As a before/after check:
#   scripts/phone-health.sh > before.txt
#   ...restart, network change...
#   scripts/phone-health.sh -wait 120 > after.txt; diff before.txt after.txt
#
# Needs tailmesh-ctl logged in (TAILMESH_ADDR, a session), and jq.
set -euo pipefail

out=""
wait_s=0
while [[ $# -gt 0 ]]; do
	case $1 in
	-o) out=$2; shift 2 ;;
	-wait) wait_s=$2; shift 2 ;;
	*) echo "usage: $0 [-o file] [-wait seconds]" >&2; exit 2 ;;
	esac
done
ctl=${TAILMESH_CTL:-tailmesh-ctl}
call() { "$ctl" call "$@"; }

if [[ $wait_s -gt 0 ]]; then
	deadline=$((SECONDS + wait_s))
	until st=$(call app.status 2> /dev/null) &&
		[[ $(jq -r '(.tailnets.enabledNotRunning // [1]) | length' <<< "$st") == 0 ]]; do
		if [[ $SECONDS -ge $deadline ]]; then
			echo "not all tailnets Running after ${wait_s}s:" >&2
			jq -c '.tailnets // .summary' <<< "${st:-null}" >&2 || true
			break
		fi
		sleep 3
	done
fi

status=$(call app.status)
tailnets=$(call tailnets.states)
upstreams=$(call upstreams.list)
stats=$(call upstreams.stats)
socks=$(call listeners.socks5.list)
inbound=$(call listeners.inbound.list)
direct=$(call routing.directLinks)
server=$("$ctl" status)
perf=$(call perf.stats top=0)

if [[ -n $out ]]; then
	jq -n --argjson status "$status" --argjson tailnets "$tailnets" --argjson upstreams "$upstreams" \
		--argjson stats "$stats" --argjson socks "$socks" --argjson inbound "$inbound" \
		--argjson direct "$direct" --argjson server "$server" --argjson perf "$perf" \
		'{status: $status, tailnets: $tailnets, upstreams: $upstreams, stats: $stats, socks5: $socks,
		  inbound: $inbound, directLinks: $direct, server: $server, perf: $perf}' > "$out"
fi

jq -r '"mode:      \(.summary)"' <<< "$status"
jq -r '"process:   up \(.processUptimeSeconds | floor)s, \(.cpuSeconds) CPU s"' <<< "$perf"
jq -r '"remote:    up \(.health.uptimeSeconds)s, \(.health.requests) requests, p95 \(.health.latency.p95Ms) ms\(if .health.lastError then ", last error: " + .health.lastError.action + " " + (.health.lastError.error // "") else "" end)"' <<< "$server"
jq -r '"direct:    \(.reason) (unbound=\(.unbound), default \(.defaultNetwork))"' <<< "$direct"
echo "tailnets:"
jq -r '.[] | "  \(.tailnetId)  \(.state)\(if .enabled then "" else " (disabled)" end)  \(.machineName // "")"' <<< "$tailnets"
echo "upstreams:"
jq -r --argjson s "$stats" '
	($s | map({key: .id, value: .}) | from_entries) as $by
	| .[] | . as $u | ($by[$u.id] // {}) as $st
	| "  \($u.label // $u.id)  \($u.kind)  \(if $u.enabled then (if $st.ready then "ready" else "NOT READY" end) else "disabled" end)  path=\($st.peerPath // "-")\(if $st.lastError then "  last error: " + $st.lastError else "" end)"' <<< "$upstreams"
echo "listeners:"
jq -r '.[] | "  socks5 :\(.port) -> \(.upstream)  \(if .enabled then (if .registered then "registered" else "NOT REGISTERED" end) else "disabled" end)\(if .lastError then "  " + .lastError else "" end)"' <<< "$socks"
jq -r '.[] | "  inbound \(.upstream):\(.listenPort) -> \(.localTarget)  \(if .enabled then (if .registered then "registered" else "NOT REGISTERED" end) else "disabled" end)\(if .lastError then "  " + .lastError else "" end)"' <<< "$inbound"
