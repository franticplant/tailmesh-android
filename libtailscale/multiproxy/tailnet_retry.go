// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"log"
	"time"

	"tailscale.com/tsnet"
)

// A tailnet whose tsnet node fails to start used to stay down: the engine
// reported it STOPPED and nothing tried again until the user restarted
// Multi-Tailnet. Starting can fail transiently, most likely right after a
// reboot or an app restart (storage or networking not ready yet), which is
// when "Tailnets STOPPED after an automatic restart" was seen. Now a failed
// start is retried with backoff for as long as the tailnet is wanted.

// startTsnet starts a node; a variable so tests can make it fail.
var startTsnet = func(srv *tsnet.Server) error {
	_, err := srv.LocalClient()
	return err
}

// tailnetStartRetryDelays is the wait before each retry; the last repeats.
var tailnetStartRetryDelays = []time.Duration{
	5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute,
}

func tailnetStartRetryDelay(attempt int) time.Duration {
	i := min(max(attempt-1, 0), len(tailnetStartRetryDelays)-1)
	return tailnetStartRetryDelays[i]
}

// scheduleTailnetStartRetry tries to start identifier again after a delay,
// if by then it still exists, is still wanted, is not running and has not
// failed again in between.
func (e *Engine) scheduleTailnetStartRetry(identifier string, attempt int) {
	time.AfterFunc(tailnetStartRetryDelay(attempt), func() {
		e.tailnetLifecycleMu.Lock()
		defer e.tailnetLifecycleMu.Unlock()
		e.mu.RLock()
		rt, ok := e.tailnets[UpstreamID(identifier)]
		retry := ok && e.state == StateOpen && rt.WantEnabled && !rt.Enabled && rt.StartFailures == attempt
		e.mu.RUnlock()
		if !retry {
			return
		}
		log.Printf("[VPN] retrying tailnet %s", identifier)
		_ = e.setTailnetEnabledLocked(identifier, true)
	})
}
