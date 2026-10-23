// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestPeerPathOf(t *testing.T) {
	tests := []struct {
		name string
		ps   ipnstate.PeerStatus
		want string
	}{
		{"direct while active", ipnstate.PeerStatus{Active: true, CurAddr: "10.29.103.139:41641", Relay: "fra"}, PeerPathDirect},
		// magicsock only reports CurAddr while the UDP path is trusted, so it
		// stays direct for a moment after traffic stops.
		{"direct while idle", ipnstate.PeerStatus{CurAddr: "10.29.103.139:41641", Relay: "fra"}, PeerPathDirect},
		{"derp", ipnstate.PeerStatus{Active: true, Relay: "fra"}, PeerPathDERP},
		{"peer relay", ipnstate.PeerStatus{Active: true, PeerRelay: "203.0.113.5:7777:vni:3", Relay: "fra"}, PeerPathPeerRelay},
		{"idle with home region", ipnstate.PeerStatus{Relay: "fra"}, PeerPathIdle},
		{"never contacted", ipnstate.PeerStatus{}, PeerPathIdle},
		{"active but no region", ipnstate.PeerStatus{Active: true}, PeerPathIdle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerPathOf(&tt.ps); got != tt.want {
				t.Errorf("peerPathOf = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPeerRelayIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.5:7777:vni:3":   "203.0.113.5",
		"[2001:db8::1]:7777:vni:3": "2001:db8::1",
		"garbage":                  "invalid IP",
		"[broken":                  "invalid IP",
	} {
		if got := peerRelayIP(in).String(); got != want {
			t.Errorf("peerRelayIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func testStatus() *ipnstate.Status {
	k1, k2, k3 := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	return &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		k1: {
			ID: "n1", HostName: "fedora", DNSName: "fedora.tailee10c1.ts.net.", OS: "linux",
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")},
			Online:       true, Active: true, Relay: "fra",
			LastHandshake: time.UnixMilli(1000), LastWrite: time.UnixMilli(2000),
			RxBytes: 10, TxBytes: 20,
		},
		k2: {
			ID: "n2", DNSName: "relayer.tailee10c1.ts.net.", Online: true,
			Addrs: []string{"203.0.113.5:41641"},
		},
		k3: {
			ID: "n3", HostName: "nas", Online: true, Active: true,
			PeerRelay: "203.0.113.5:7777:vni:3", Relay: "ams",
		},
	}}
}

func TestTailnetPeersFromStatus(t *testing.T) {
	peers := tailnetPeersFromStatus(testStatus())
	if len(peers) != 3 {
		t.Fatalf("got %d peers, want 3", len(peers))
	}
	// Active peers first, then by name.
	if peers[0].Name != "fedora" || peers[1].Name != "nas" || peers[2].Name != "relayer" {
		t.Fatalf("order = %s, %s, %s", peers[0].Name, peers[1].Name, peers[2].Name)
	}
	f := peers[0]
	if f.Path != PeerPathDERP || f.DERPRegion != "fra" || f.Addr != "" {
		t.Errorf("fedora: path %q region %q addr %q", f.Path, f.DERPRegion, f.Addr)
	}
	if f.DNSName != "fedora.tailee10c1.ts.net" || len(f.TailnetIPs) != 2 || f.TailnetIPs[0] != "100.64.0.1" {
		t.Errorf("fedora: dns %q ips %v", f.DNSName, f.TailnetIPs)
	}
	if f.LastHandshakeMillis != 1000 || f.LastWriteMillis != 2000 || f.RxBytes != 10 || f.TxBytes != 20 {
		t.Errorf("fedora counters: %+v", f)
	}
	nas := peers[1]
	if nas.Path != PeerPathPeerRelay || nas.PeerRelayNode != "relayer" || nas.PeerRelay == "" {
		t.Errorf("nas: path %q relay %q node %q", nas.Path, nas.PeerRelay, nas.PeerRelayNode)
	}
	if peers[2].Path != PeerPathIdle {
		t.Errorf("relayer: path %q, want idle", peers[2].Path)
	}
	if tailnetPeersFromStatus(nil) != nil {
		t.Error("nil status should give nil")
	}
}

func TestSummarizePeerPaths(t *testing.T) {
	p := func(path, region string) TailnetPeer { return TailnetPeer{Path: path, DERPRegion: region} }
	tests := []struct {
		name  string
		peers []TailnetPeer
		want  string
	}{
		{"no peers", nil, PeerPathIdle},
		{"all idle", []TailnetPeer{p(PeerPathIdle, "fra")}, PeerPathIdle},
		{"direct", []TailnetPeer{p(PeerPathDirect, "fra"), p(PeerPathIdle, "")}, PeerPathDirect},
		{"one region", []TailnetPeer{p(PeerPathDERP, "fra"), p(PeerPathDERP, "fra")}, "derp:fra"},
		{"two regions", []TailnetPeer{p(PeerPathDERP, "fra"), p(PeerPathDERP, "ams")}, PeerPathDERP},
		{"peer relay", []TailnetPeer{p(PeerPathPeerRelay, "")}, PeerPathPeerRelay},
		{"mixed", []TailnetPeer{p(PeerPathDirect, ""), p(PeerPathDERP, "fra")}, "mixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarizePeerPaths(tt.peers); got != tt.want {
				t.Errorf("summarizePeerPaths = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTailnetPeerPathInStats(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	id := UpstreamID("regular-a")
	e.mu.Lock()
	e.tailnets[id] = &TailnetRuntime{Enabled: true}
	e.mu.Unlock()

	if got := e.peerPathFor(id, UpstreamKindTailnet); got != "unknown" {
		t.Errorf("before the first poll: %q, want unknown", got)
	}

	e.setTailnetPeers(id, tailnetPeersFromStatus(testStatus()), time.UnixMilli(5000))
	if got := e.peerPathFor(id, UpstreamKindTailnet); got != "mixed" {
		t.Errorf("after a poll: %q, want mixed", got)
	}

	raw, err := e.GetTailnetPeersJSON(string(id))
	if err != nil {
		t.Fatal(err)
	}
	var got TailnetPeersExport
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary != "mixed" || got.UpdatedAtMillis != 5000 || len(got.Peers) != 3 {
		t.Errorf("export: %+v", got)
	}

	// An exit node's own path wins over the peer summary.
	e.noteExitNodePath(string(id), true, PeerPathDirect, "fra")
	if got := e.peerPathFor(id, UpstreamKindTailnet); got != PeerPathDirect {
		t.Errorf("with exit node: %q, want direct", got)
	}
	e.noteExitNodePath(string(id), true, PeerPathIdle, "fra")
	if got := e.peerPathFor(id, UpstreamKindTailnet); got != PeerPathIdle {
		t.Errorf("with idle exit node: %q, want idle", got)
	}

	if _, err := e.GetTailnetPeersJSON("missing"); err == nil {
		t.Error("unknown tailnet: want an error")
	}
	e.mu.Lock()
	e.tailnets["regular-off"] = &TailnetRuntime{}
	e.mu.Unlock()
	if _, err := e.GetTailnetPeersJSON("regular-off"); err == nil {
		t.Error("stopped tailnet: want an error")
	}
}
