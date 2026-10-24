// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"strings"
	"testing"
	"time"
)

func TestParseWireGuardPeers(t *testing.T) {
	now := time.Unix(1_800_000_100, 0)
	uapi := strings.Join([]string{
		"private_key=" + strings.Repeat("11", 32),
		"listen_port=51820",
		"public_key=" + strings.Repeat("ab", 32),
		"preshared_key=" + strings.Repeat("22", 32),
		"endpoint=169.150.218.80:51820",
		"last_handshake_time_sec=1800000000",
		"last_handshake_time_nsec=500000000",
		"tx_bytes=1234",
		"rx_bytes=5678",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"public_key=" + strings.Repeat("cd", 32),
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"errno=0",
	}, "\n")
	peers := parseWireGuardPeers(uapi, now)
	if len(peers) != 2 {
		t.Fatalf("peers = %+v", peers)
	}
	p := peers[0]
	if p.PublicKey != wgHexToBase64(strings.Repeat("ab", 32)) || p.Endpoint != "169.150.218.80:51820" ||
		p.LastHandshakeAtMillis != 1_800_000_000_500 || p.LastHandshakeAgoSec != 99 ||
		p.TxBytes != 1234 || p.RxBytes != 5678 || p.KeepaliveSeconds != 25 {
		t.Errorf("first peer: %+v", p)
	}
	if peers[1].LastHandshakeAtMillis != 0 || peers[1].Endpoint != "" {
		t.Errorf("second peer: %+v", peers[1])
	}
	for _, p := range peers {
		if strings.Contains(p.PublicKey, "11") && len(p.PublicKey) == 64 {
			t.Error("private key leaked")
		}
	}
}

func TestWireGuardEvents(t *testing.T) {
	var ev wgEvents
	ev.observe(false, "%v - Sending handshake initiation", "peer(x)")
	ev.observe(false, "%v - Sending handshake initiation", "peer(x)")
	ev.observe(false, "%s - Handshake did not complete after %d seconds, retrying (try %d)", "peer(x)", 5, 2)
	ev.observe(false, "%v - Received handshake response", "peer(x)")
	ev.observe(false, "%v - Sending keepalive packet", "peer(x)")
	if ev.initiations.Load() != 2 || ev.timeouts.Load() != 1 || ev.responses.Load() != 1 {
		t.Errorf("counts: %d %d %d", ev.initiations.Load(), ev.timeouts.Load(), ev.responses.Load())
	}
	if !strings.Contains(ev.lastError, "try 2") {
		t.Errorf("lastError = %q", ev.lastError)
	}
	ev.observe(true, "%v - Failed to send handshake initiation: %v", "peer(x)", "network is unreachable")
	if ev.lastError != "peer(x) - Failed to send handshake initiation: network is unreachable" || ev.lastErrAt.IsZero() {
		t.Errorf("lastError = %q", ev.lastError)
	}
}
