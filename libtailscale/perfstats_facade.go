// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"

	"github.com/tailscale/tailscale-android/libtailscale/perfstats"
)

// PerfStatsJSON returns the process's cost (see package perfstats): CPU
// time overall and for the top threads, context switches, memory, Go
// runtime metrics, and how often each periodic Go job ran. Read on demand
// only; nothing in it runs periodically.
func PerfStatsJSON(topThreads int32) string {
	b, err := json.Marshal(perfstats.Snapshot(int(topThreads)))
	if err != nil {
		return "{}"
	}
	return string(b)
}
