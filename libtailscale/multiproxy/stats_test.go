// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// statsFake is a Provider whose Dial can be told to succeed or fail on
// demand, so tests can drive readyProvider's stats recording (upstream.go)
// through both outcomes.
type statsFake struct {
	id    UpstreamID
	ready bool
	fail  error // non-nil: Dial fails with this error
}

func (p *statsFake) ID() UpstreamID     { return p.id }
func (p *statsFake) Kind() UpstreamKind { return UpstreamKindSOCKS5 }
func (p *statsFake) Ready() bool        { return p.ready }
func (p *statsFake) Close() error       { return nil }

func (p *statsFake) Dial(context.Context, string, string) (net.Conn, error) {
	if p.fail != nil {
		return nil, p.fail
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func (p *statsFake) PeerPathInfo(context.Context, string) string { return "fake" }

func statsFor(t *testing.T, e *Engine, id string) UpstreamStatsInfo {
	t.Helper()
	for _, s := range e.UpstreamStatsSnapshot() {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no stats snapshot for %q", id)
	return UpstreamStatsInfo{}
}

func TestReadyProviderRecordsDialSuccess(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	p := &statsFake{id: "proxy", ready: true}
	if err := e.RegisterUpstream(p); err != nil {
		t.Fatal(err)
	}

	got, ok := e.readyProvider("proxy")
	if !ok {
		t.Fatal("expected a ready provider")
	}
	conn, err := got.Dial(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	s := statsFor(t, e, "proxy")
	if s.DialAttempts != 1 || s.DialSuccesses != 1 || s.DialFailures != 0 {
		t.Fatalf("stats = %+v", s)
	}
	if !s.Ready {
		t.Fatalf("stats.Ready = false, want true")
	}
}

func TestReadyProviderRecordsDialFailure(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	dialErr := errors.New("connection refused")
	p := &statsFake{id: "proxy", ready: true, fail: dialErr}
	if err := e.RegisterUpstream(p); err != nil {
		t.Fatal(err)
	}

	got, ok := e.readyProvider("proxy")
	if !ok {
		t.Fatal("expected a ready provider")
	}
	if _, err := got.Dial(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("expected a dial error")
	}

	s := statsFor(t, e, "proxy")
	if s.DialAttempts != 1 || s.DialSuccesses != 0 || s.DialFailures != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if s.LastError != dialErr.Error() {
		t.Fatalf("LastError = %q, want %q", s.LastError, dialErr.Error())
	}
}

// A rule naming an upstream that exists but is not ready must count as such,
// distinctly from a dial that was attempted and failed - no dial was even
// tried here.
func TestReadyProviderRecordsNotReady(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	p := &statsFake{id: "proxy", ready: false}
	if err := e.RegisterUpstream(p); err != nil {
		t.Fatal(err)
	}

	if _, ok := e.readyProvider("proxy"); ok {
		t.Fatal("expected readyProvider to report not-ready")
	}

	s := statsFor(t, e, "proxy")
	if s.NotReadyCount != 1 || s.DialAttempts != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// OnUpstreamHealthChanged must fire on a genuine transition and stay silent
// across repeats of the same outcome - a callback on every dial would be
// noise the UI cannot act on.
func TestUpstreamHealthChangedFiresOnlyOnTransition(t *testing.T) {
	cb := &MockCallback{}
	e := NewEngine(t.TempDir(), cb)
	dialErr := errors.New("connection refused")
	p := &statsFake{id: "proxy", ready: true, fail: dialErr}
	if err := e.RegisterUpstream(p); err != nil {
		t.Fatal(err)
	}

	dial := func() {
		got, ok := e.readyProvider("proxy")
		if !ok {
			t.Fatal("expected a ready provider")
		}
		got.Dial(context.Background(), "tcp", "example.com:443")
	}

	// Three failures in a row: one transition (ready -> not ready).
	dial()
	dial()
	dial()

	deadline := time.Now().Add(2 * time.Second)
	for cb.healthEventCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := cb.healthEventCount(); got != 1 {
		t.Fatalf("health events after 3 identical failures = %d, want 1", got)
	}

	// Recover: a second transition (not ready -> ready).
	p.fail = nil
	dial()

	deadline = time.Now().Add(2 * time.Second)
	for cb.healthEventCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := cb.healthEventCount(); got != 2 {
		t.Fatalf("health events after recovery = %d, want 2", got)
	}
}
