// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"
	"time"
)

func TestSinceParam(t *testing.T) {
	loc := time.FixedZone("TRT", 3*3600)
	now := time.Date(2026, 10, 24, 17, 30, 0, 0, loc)
	cases := map[string]string{
		"42":                   "42",
		"10m":                  "10m",
		"15:04":                "2026-10-24T12:04:00Z",
		"15:04:05":             "2026-10-24T12:04:05Z",
		"2026-10-24T10:00:00Z": "2026-10-24T10:00:00Z",
	}
	for in, want := range cases {
		got, err := sinceParam(in, now)
		if err != nil || got != want {
			t.Errorf("sinceParam(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := sinceParam("yesterday", now); err == nil {
		t.Error("yesterday: want an error")
	}
}
