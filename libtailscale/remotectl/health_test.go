// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"net/http"
	"testing"
	"time"
)

func TestStatusHealth(t *testing.T) {
	expires := time.Now().Add(30 * time.Minute).Unix()
	_, _, _, base := start(t, Config{Password: "correct horse", AllowControl: true, ExpiresAtUnix: expires})
	tok := login(t, base, "correct horse")

	do(t, "POST", base+"/v1/call/echo", tok, map[string]any{})
	do(t, "POST", base+"/v1/call/fail", tok, map[string]any{})
	do(t, "GET", base+"/v1/status", "", nil) // 401

	code, out := do(t, "GET", base+"/v1/status", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	h, ok := out["health"].(map[string]any)
	if !ok {
		t.Fatalf("no health in %v", out)
	}
	num := func(k string) float64 { v, _ := h[k].(float64); return v }
	// login, echo, fail, the refused status; this status is still in flight.
	if num("requests") < 4 {
		t.Errorf("requests = %v, want >= 4", h["requests"])
	}
	if num("clientErrors") < 1 {
		t.Errorf("clientErrors = %v, want the 401", h["clientErrors"])
	}
	if num("inFlight") != 1 {
		t.Errorf("inFlight = %v, want 1 (this request)", h["inFlight"])
	}
	if e := num("expiresInSeconds"); e < 29*60 || e > 30*60 {
		t.Errorf("expiresInSeconds = %v", e)
	}
	lat, _ := h["latency"].(map[string]any)
	if s, _ := lat["samples"].(float64); s < 2 {
		t.Errorf("latency samples = %v, want the two calls", lat)
	}
	le, _ := h["lastError"].(map[string]any)
	if le == nil || le["action"] == nil || le["error"] == "" {
		t.Errorf("lastError = %v", h["lastError"])
	}
	if h["slowestRecent"] == nil {
		t.Error("no slowestRecent")
	}
	if num("sessions") != 1 {
		t.Errorf("sessions = %v", h["sessions"])
	}
}

func TestHealthLatencyRing(t *testing.T) {
	var h health
	at := time.Now()
	for i := 1; i <= 100; i++ {
		h.recordLatency("x", at, time.Duration(i)*time.Millisecond)
	}
	s := &Server{started: at}
	s.health.nLat = h.nLat
	s.health.latencies = h.latencies
	hi := s.healthInfo()
	// The ring holds the last 64: 37..100 ms.
	if hi.Latency.Samples != latencyRing || hi.Latency.MaxMs != 100 || hi.Latency.P50Ms < 60 || hi.Latency.P50Ms > 70 {
		t.Errorf("latency = %+v", hi.Latency)
	}
	if h.slowest == nil || h.slowest.Ms != 100 {
		t.Errorf("slowest = %+v", h.slowest)
	}
}
