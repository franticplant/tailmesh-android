// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tsnet"
)

// A tailnet whose node fails to start comes back by itself once starting
// works again, and reports ERROR with the reason meanwhile, not STOPPED.
func TestTailnetStartIsRetried(t *testing.T) {
	var fails atomic.Int32
	fails.Store(2)
	oldStart, oldDelays := startTsnet, tailnetStartRetryDelays
	startTsnet = func(srv *tsnet.Server) error {
		if fails.Add(-1) >= 0 {
			return errors.New("storage not ready")
		}
		return nil // don't start a real node
	}
	tailnetStartRetryDelays = []time.Duration{50 * time.Millisecond}
	t.Cleanup(func() { startTsnet, tailnetStartRetryDelays = oldStart, oldDelays })

	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	if err := e.AddTailnet("regular-a", "", true); err == nil {
		t.Fatal("first start: want the injected error")
	}

	var states []TailnetRuntimeExport
	if err := json.Unmarshal([]byte(e.GetTailnetStatesJSON()), &states); err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].State != "ERROR" || states[0].StartError != "storage not ready" || states[0].StartFailures != 1 {
		t.Errorf("while failing: %+v", states)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.RLock()
		up := e.tailnets["regular-a"].Enabled
		e.mu.RUnlock()
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tailnet never started after the injected failures")
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.mu.RLock()
	rt := e.tailnets["regular-a"]
	failures, lastErr := rt.StartFailures, rt.LastStartError
	e.mu.RUnlock()
	if failures != 0 || lastErr != "" {
		t.Errorf("after starting: failures %d, error %q", failures, lastErr)
	}
}

// Turning a failing tailnet off stops the retries.
func TestTailnetStartRetryStopsWhenDisabled(t *testing.T) {
	var calls atomic.Int32
	oldStart, oldDelays := startTsnet, tailnetStartRetryDelays
	startTsnet = func(*tsnet.Server) error {
		calls.Add(1)
		return errors.New("still broken")
	}
	tailnetStartRetryDelays = []time.Duration{30 * time.Millisecond}
	t.Cleanup(func() { startTsnet, tailnetStartRetryDelays = oldStart, oldDelays })

	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	_ = e.AddTailnet("regular-a", "", true)
	time.Sleep(100 * time.Millisecond) // a retry or two
	if err := e.SetTailnetEnabled("regular-a", false); err != nil {
		t.Fatal(err)
	}
	n := calls.Load()
	if n < 2 {
		t.Errorf("only %d start attempts before disabling; retries not running", n)
	}
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != n {
		t.Errorf("start attempts went on after disabling: %d -> %d", n, got)
	}
	var states []TailnetRuntimeExport
	_ = json.Unmarshal([]byte(e.GetTailnetStatesJSON()), &states)
	if len(states) != 1 || states[0].State != "STOPPED" {
		t.Errorf("disabled: %+v", states)
	}
}

func TestTailnetStartRetryDelay(t *testing.T) {
	if tailnetStartRetryDelay(1) != 5*time.Second || tailnetStartRetryDelay(100) != 5*time.Minute {
		t.Error("backoff schedule")
	}
}
