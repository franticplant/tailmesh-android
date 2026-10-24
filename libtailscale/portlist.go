// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import "tailscale.com/envknob"

// disablePortList turns off the core's port-list extension for every node
// this process runs (the standard backend and each Multi-Tailnet tsnet
// node). On Linux it ticks every second per node, and on Android it can't
// do its job anyway: since Android 10 apps can't read /proc/net/tcp, so
// there are no listening ports to report to the tailnet.
func disablePortList() { envknob.Setenv("TS_PORTLIST", "false") }
