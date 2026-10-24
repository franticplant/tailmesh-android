// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package perfstats

import (
	"runtime"
	"testing"
)

func TestCounter(t *testing.T) {
	c := NewCounter("test.job")
	if NewCounter("test.job") != c {
		t.Fatal("NewCounter returned a second counter for the same name")
	}
	c.Inc()
	c.Inc()
	if got := Counts()["test.job"]; got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
}

func TestSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	// Burn a little CPU so it is not zero.
	x := 0
	for i := 0; i < 50_000_000; i++ {
		x += i
	}
	_ = x
	s := Snapshot(3)
	if s.CPU <= 0 || s.UserCPU <= 0 {
		t.Errorf("cpu = %v (user %v)", s.CPU, s.UserCPU)
	}
	if s.ProcessUptimeSec <= 0 || s.RSSBytes == 0 || s.Threads == 0 {
		t.Errorf("uptime %v rss %v threads %v", s.ProcessUptimeSec, s.RSSBytes, s.Threads)
	}
	if len(s.TopThreads) == 0 || len(s.TopThreads) > 3 {
		t.Errorf("top threads = %d", len(s.TopThreads))
	}
	if s.Go["goroutines"] == 0 || s.Go["heapGoalBytes"] == 0 {
		t.Errorf("go metrics = %v", s.Go)
	}
	if s.Voluntary == 0 {
		t.Errorf("no context switches")
	}
}

func TestStatusValue(t *testing.T) {
	st := []byte("Name:\tx\nVmRSS:\t  1234 kB\nnonvoluntary_ctxt_switches:\t3\nvoluntary_ctxt_switches:\t7\n")
	if v, ok := statusValue(st, "VmRSS:"); !ok || v != 1234 {
		t.Errorf("VmRSS = %d %v", v, ok)
	}
	if v, _ := statusValue(st, "voluntary_ctxt_switches:"); v != 7 {
		t.Errorf("voluntary = %d", v)
	}
	if v, _ := statusValue(st, "nonvoluntary_ctxt_switches:"); v != 3 {
		t.Errorf("nonvoluntary = %d", v)
	}
	if got := commOf([]byte("12 (a b) S 1")); got != "a b" {
		t.Errorf("comm = %q", got)
	}
}
