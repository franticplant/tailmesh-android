// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The server's own health, for GET /v1/status: whether it is answering, how
// fast, and what last went wrong, so a wedged server can be told from a
// dead network. Recorded per request with a counter add and, for quick
// requests, one entry in a small ring; nothing runs between requests.

// latencyRing is how many recent request latencies are kept.
const latencyRing = 64

type health struct {
	requests     atomic.Uint64
	clientErrors atomic.Uint64 // 4xx
	serverErrors atomic.Uint64 // 5xx
	inFlight     atomic.Int64

	mu        sync.Mutex
	latencies [latencyRing]time.Duration
	nLat      int // total recorded; the ring holds the last latencyRing
	slowest   *slowRequest
	lastError *lastError
}

type slowRequest struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Ms     int64     `json:"ms"`
}

type lastError struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Status int       `json:"status"`
	Error  string    `json:"error"`
}

// HealthInfo is the "health" object in GET /v1/status.
type HealthInfo struct {
	UptimeSeconds int64  `json:"uptimeSeconds"`
	Requests      uint64 `json:"requests"`
	ClientErrors  uint64 `json:"clientErrors"`
	ServerErrors  uint64 `json:"serverErrors"`
	// InFlight counts requests being served now, this one included. Long
	// ones (log follow, profiles, shell commands) count while they run.
	InFlight int64 `json:"inFlight"`
	// Latency is over the last few quick requests (status, methods, calls);
	// long-running ones are left out.
	Latency   LatencyInfo  `json:"latency"`
	Slowest   *slowRequest `json:"slowestRecent,omitempty"`
	LastError *lastError   `json:"lastError,omitempty"`
	// ExpiresInSeconds is when remote control turns itself off; 0 when it
	// doesn't.
	ExpiresInSeconds int64 `json:"expiresInSeconds"`
	LogRingLines     int   `json:"logRingLines"`
	Sessions         int   `json:"sessions"`
}

type LatencyInfo struct {
	Samples int     `json:"samples"`
	P50Ms   float64 `json:"p50Ms"`
	P95Ms   float64 `json:"p95Ms"`
	MaxMs   float64 `json:"maxMs"`
}

// quickRequest reports whether a request's duration says something about
// the server's responsiveness, rather than about how long it was asked to
// wait (log follow, approval polls, profiles, shell commands, uploads).
func quickRequest(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/v1/status", p == "/v1/methods", p == "/v1/access-log":
		return true
	case p == "/v1/logs":
		return r.URL.Query().Get("follow") == ""
	case strings.HasPrefix(p, "/v1/call/"):
		return true
	}
	return false
}

// measure wraps the whole API: every request is counted, quick ones timed.
func (s *Server) measure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.health.inFlight.Add(1)
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			s.health.inFlight.Add(-1)
			s.health.requests.Add(1)
			switch {
			case sw.status >= 500:
				s.health.serverErrors.Add(1)
			case sw.status >= 400:
				s.health.clientErrors.Add(1)
			}
			if quickRequest(r) {
				s.health.recordLatency(r.Method+" "+r.URL.Path, start, time.Since(start))
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

func (h *health) recordLatency(action string, at time.Time, d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.latencies[h.nLat%latencyRing] = d
	h.nLat++
	// The slowest of roughly the last ten minutes.
	if h.slowest == nil || d.Milliseconds() >= h.slowest.Ms || time.Since(h.slowest.At) > 10*time.Minute {
		h.slowest = &slowRequest{At: at, Action: action, Ms: d.Milliseconds()}
	}
}

// noteError records an access-log entry that carries an error.
func (h *health) noteError(e AccessEntry) {
	if e.Error == "" && e.Status < 500 {
		return
	}
	h.mu.Lock()
	h.lastError = &lastError{At: e.Time, Action: e.Action, Status: e.Status, Error: e.Error}
	h.mu.Unlock()
}

func (s *Server) healthInfo() HealthInfo {
	now := time.Now()
	hi := HealthInfo{
		UptimeSeconds: int64(now.Sub(s.started).Seconds()),
		Requests:      s.health.requests.Load(),
		ClientErrors:  s.health.clientErrors.Load(),
		ServerErrors:  s.health.serverErrors.Load(),
		InFlight:      s.health.inFlight.Load(),
	}
	if s.cfg.ExpiresAtUnix != 0 {
		hi.ExpiresInSeconds = max(0, s.cfg.ExpiresAtUnix-now.Unix())
	}
	s.health.mu.Lock()
	n := min(s.health.nLat, latencyRing)
	lat := slices.Clone(s.health.latencies[:n])
	if sl := s.health.slowest; sl != nil {
		c := *sl
		hi.Slowest = &c
	}
	if le := s.health.lastError; le != nil {
		c := *le
		hi.LastError = &c
	}
	s.health.mu.Unlock()
	if n > 0 {
		slices.Sort(lat)
		ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
		hi.Latency = LatencyInfo{
			Samples: n,
			P50Ms:   ms(lat[(n-1)/2]),
			P95Ms:   ms(lat[(n-1)*95/100]),
			MaxMs:   ms(lat[n-1]),
		}
	}
	logs.mu.Lock()
	hi.LogRingLines = len(logs.lines)
	logs.mu.Unlock()
	s.mu.Lock()
	hi.Sessions = len(s.sessions)
	s.mu.Unlock()
	return hi
}
