// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// fakeDialUpstream is a minimal Upstream whose Dial returns queued results in
// order and records every call, so dialWithRetry's attempt count and timing
// can be asserted directly without a real network, gVisor, or Android.
type fakeDialUpstream struct {
	errs  []error
	calls int
}

func (f *fakeDialUpstream) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	i := f.calls
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func (f *fakeDialUpstream) PeerPathInfo(context.Context, string) string { return "unknown" }

// TestDialWithRetryStopsImmediatelyOnNoUsableNetwork is the regression test
// for the ~600ms IPv6 hang documented in validation_and_gaps.md §93: before
// this fix, a dial failing with ErrNoUsableNetworkForFamily (the Android
// side declining to bind because no active network carries the dialed
// address's family) was retried like any other error, burning
// 2*tcpDialRetryDelay (600ms) before the caller ever saw the failure - long
// enough for the real remote's TLS session to look alive and then die,
// exactly the symptom the original packet capture showed. dialWithRetry must
// now recognize that error as permanent-for-this-dial and return after a
// single attempt.
func TestDialWithRetryStopsImmediatelyOnNoUsableNetwork(t *testing.T) {
	up := &fakeDialUpstream{
		errs: []error{
			fmt.Errorf("bind fd 9: %w", ErrNoUsableNetworkForFamily),
			errors.New("should never be dialed"),
			errors.New("should never be dialed"),
		},
	}

	start := time.Now()
	_, err := dialWithRetry(context.Background(), up, "tcp", "[2a01:4f8::1000]:443", func(attempt int, err error) {
		t.Errorf("onRetry called (attempt %d, err %v) - a permanent error must not retry", attempt, err)
	})
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNoUsableNetworkForFamily) {
		t.Fatalf("dialWithRetry error = %v, want it to wrap ErrNoUsableNetworkForFamily", err)
	}
	if up.calls != 1 {
		t.Fatalf("Dial called %d times, want exactly 1 (no retry on a permanent failure)", up.calls)
	}
	if elapsed >= tcpDialRetryDelay {
		t.Fatalf("dialWithRetry took %v, want well under tcpDialRetryDelay (%v) since it must not sleep before giving up", elapsed, tcpDialRetryDelay)
	}
}

// TestDialWithRetryRetriesTransientErrors is the companion case: an ordinary
// (non-permanent) dial error - a timeout, a refused connection, anything not
// wrapping ErrNoUsableNetworkForFamily - must still be retried up to
// tcpDialMaxAttempts, since the whole point of distinguishing the permanent
// case is to keep this retry behavior for everything else.
func TestDialWithRetryRetriesTransientErrors(t *testing.T) {
	up := &fakeDialUpstream{
		errs: []error{
			errors.New("connection refused"),
			errors.New("connection refused"),
			nil, // succeeds on the third attempt
		},
	}

	var retries []int
	conn, err := dialWithRetry(context.Background(), up, "tcp", "93.184.216.34:443", func(attempt int, err error) {
		retries = append(retries, attempt)
	})
	if err != nil {
		t.Fatalf("dialWithRetry error = %v, want nil (third attempt succeeds)", err)
	}
	defer conn.Close()
	if up.calls != 3 {
		t.Fatalf("Dial called %d times, want exactly 3 (transient errors are retried up to tcpDialMaxAttempts)", up.calls)
	}
	if len(retries) != 2 {
		t.Fatalf("onRetry called %d times, want 2 (once before each of the two retried attempts)", len(retries))
	}
}

// TestDialWithRetryExhaustsAttemptsOnPersistentTransientError confirms the
// unchanged behavior for a transient error that never clears: all
// tcpDialMaxAttempts are used, with tcpDialRetryDelay between them, and the
// final error is returned as-is.
func TestDialWithRetryExhaustsAttemptsOnPersistentTransientError(t *testing.T) {
	wantErr := errors.New("connection refused")
	up := &fakeDialUpstream{errs: []error{wantErr, wantErr, wantErr}}

	start := time.Now()
	_, err := dialWithRetry(context.Background(), up, "tcp", "93.184.216.34:443", nil)
	elapsed := time.Since(start)

	if !errors.Is(err, wantErr) {
		t.Fatalf("dialWithRetry error = %v, want %v", err, wantErr)
	}
	if up.calls != tcpDialMaxAttempts {
		t.Fatalf("Dial called %d times, want tcpDialMaxAttempts (%d)", up.calls, tcpDialMaxAttempts)
	}
	wantMinElapsed := 2 * tcpDialRetryDelay
	if elapsed < wantMinElapsed {
		t.Fatalf("dialWithRetry took %v, want at least %v (two inter-attempt delays)", elapsed, wantMinElapsed)
	}
}
