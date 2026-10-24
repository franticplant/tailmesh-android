// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WireGuard handshake details for upstreams.stats: why a tunnel says
// no-handshake. Counted from wireguard-go's own log calls (matching the
// format string, not the formatted line), and read from the device's UAPI
// state only when asked.

type wgEvents struct {
	initiations atomic.Uint64 // handshake initiations sent
	responses   atomic.Uint64 // handshake responses received
	timeouts    atomic.Uint64 // "did not complete after 5 seconds, retrying"

	mu        sync.Mutex
	lastError string
	lastErrAt time.Time
}

func (ev *wgEvents) setError(at time.Time, msg string) {
	ev.mu.Lock()
	ev.lastError, ev.lastErrAt = msg, at
	ev.mu.Unlock()
}

// observe is called with every wireguard-go log call.
func (ev *wgEvents) observe(isError bool, format string, args ...any) {
	switch format {
	case "%v - Sending handshake initiation":
		ev.initiations.Add(1)
		return
	case "%v - Received handshake response":
		ev.responses.Add(1)
		return
	case "%s - Handshake did not complete after %d seconds, retrying (try %d)":
		ev.timeouts.Add(1)
		if len(args) == 3 {
			ev.setError(time.Now(), fmt.Sprintf("no handshake response within %v s (try %v)", args[1], args[2]))
		}
		return
	case "%s - Handshake did not complete after %d attempts, giving up":
		ev.setError(time.Now(), fmt.Sprintf("no handshake response after %v attempts; gave up until there is traffic", args[len(args)-1]))
		return
	}
	if isError {
		ev.setError(time.Now(), fmt.Sprintf(format, args...))
	}
}

// WireGuardPeerDetails is one peer of a WireGuard upstream.
type WireGuardPeerDetails struct {
	PublicKey string `json:"publicKey"`
	// Endpoint is the address the tunnel sends to (after resolving the
	// configured host, and as roaming updated it).
	Endpoint string `json:"endpoint,omitempty"`
	// LastHandshakeAtMillis is 0 if there has never been one.
	LastHandshakeAtMillis int64  `json:"lastHandshakeAtMillis"`
	LastHandshakeAgoSec   int64  `json:"lastHandshakeAgoSeconds,omitempty"`
	RxBytes               uint64 `json:"rxBytes"`
	TxBytes               uint64 `json:"txBytes"`
	KeepaliveSeconds      int    `json:"persistentKeepaliveSeconds,omitempty"`
}

// WireGuardDetails is the "wireguard" object in a WireGuard upstream's
// upstreams.stats entry.
type WireGuardDetails struct {
	Peers []WireGuardPeerDetails `json:"peers"`
	// Handshake initiations sent and responses received since the tunnel
	// came up, and how many initiations went unanswered for 5 s.
	HandshakeInitiations uint64 `json:"handshakeInitiations"`
	HandshakeResponses   uint64 `json:"handshakeResponses"`
	HandshakeTimeouts    uint64 `json:"handshakeTimeouts"`
	LastError            string `json:"lastError,omitempty"`
	LastErrorAtMillis    int64  `json:"lastErrorAtMillis,omitempty"`
}

// parseWireGuardPeers reads the peers out of a UAPI "get" dump.
func parseWireGuardPeers(uapi string, now time.Time) []WireGuardPeerDetails {
	var peers []WireGuardPeerDetails
	var cur *WireGuardPeerDetails
	var hsSec, hsNsec int64
	flush := func() {
		if cur == nil {
			return
		}
		if hsSec > 0 {
			at := time.Unix(hsSec, hsNsec)
			cur.LastHandshakeAtMillis = at.UnixMilli()
			cur.LastHandshakeAgoSec = int64(now.Sub(at).Seconds())
		}
		peers = append(peers, *cur)
		cur, hsSec, hsNsec = nil, 0, 0
	}
	for line := range strings.SplitSeq(uapi, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			cur = &WireGuardPeerDetails{PublicKey: wgHexToBase64(v)}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			hsSec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			hsNsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				cur.KeepaliveSeconds, _ = strconv.Atoi(v)
			}
		}
	}
	flush()
	return peers
}

// details reads the tunnel's peers and the handshake counters.
func (p *wireguardProvider) details() *WireGuardDetails {
	d := &WireGuardDetails{
		HandshakeInitiations: p.events.initiations.Load(),
		HandshakeResponses:   p.events.responses.Load(),
		HandshakeTimeouts:    p.events.timeouts.Load(),
	}
	p.events.mu.Lock()
	d.LastError = p.events.lastError
	if !p.events.lastErrAt.IsZero() {
		d.LastErrorAtMillis = p.events.lastErrAt.UnixMilli()
	}
	p.events.mu.Unlock()
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return d
	}
	if uapi, err := p.dev.IpcGet(); err == nil {
		d.Peers = parseWireGuardPeers(uapi, time.Now())
	}
	return d
}
