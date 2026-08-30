// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseWireGuardQuickConfig(t *testing.T) {
	// The config below names its endpoint, as a provider's would; keep the
	// lookup off the network.
	stubEndpointLookup(t, map[string][]netip.Addr{
		"vpn.example.com": {netip.MustParseAddr("203.0.113.9")},
	})

	priv, pub := wgKeypair(t)
	psk, _ := wgKeypair(t)

	conf := `
# A config as a provider would hand it out.
[Interface]
PrivateKey = ` + priv + `
Address = 10.9.0.2/32, fd00::2/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1380
PostUp = iptables -A FORWARD -i %i -j ACCEPT   ; ignored
Table = off

[Peer]
PublicKey = ` + pub + `
PresharedKey = ` + psk + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`

	encoded, err := ParseWireGuardQuickConfig(conf)
	if err != nil {
		t.Fatalf("ParseWireGuardQuickConfig: %v", err)
	}

	// Round-tripping through the JSON path is the real assertion: the two forms
	// must produce the same WireGuardConfig, or a .conf import would behave
	// differently from a JSON one.
	cfg, err := ParseWireGuardConfigJSON("wg", encoded)
	if err != nil {
		t.Fatalf("re-parsing the generated JSON: %v", err)
	}

	if cfg.PrivateKey != priv {
		t.Errorf("private key did not survive")
	}
	if cfg.MTU != 1380 {
		t.Errorf("MTU = %d", cfg.MTU)
	}
	wantAddrs := []netip.Addr{netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("fd00::2")}
	if len(cfg.Addresses) != 2 || cfg.Addresses[0] != wantAddrs[0] || cfg.Addresses[1] != wantAddrs[1] {
		t.Errorf("addresses = %v", cfg.Addresses)
	}
	if len(cfg.DNS) != 2 {
		t.Errorf("dns = %v", cfg.DNS)
	}

	if len(cfg.Peers) != 1 {
		t.Fatalf("peers = %v", cfg.Peers)
	}
	p := cfg.Peers[0]
	if p.PublicKey != pub || p.PresharedKey != psk {
		t.Errorf("peer keys did not survive")
	}
	if p.Endpoint != "vpn.example.com:51820" {
		t.Errorf("endpoint = %q", p.Endpoint)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d", p.PersistentKeepalive)
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("allowed IPs = %v", p.AllowedIPs)
	}

	// And the whole thing has to actually build a tunnel, not merely parse.
	up, err := NewWireGuardUpstream(cfg, newRealBind(), nil)
	if err != nil {
		t.Fatalf("building an upstream from the imported config: %v", err)
	}
	_ = up.Close()
}

func TestParseWireGuardQuickConfigMinimal(t *testing.T) {
	priv, pub := wgKeypair(t)

	encoded, err := ParseWireGuardQuickConfig(
		"[Interface]\nPrivateKey=" + priv + "\nAddress=10.0.0.2/32\n" +
			"[Peer]\nPublicKey=" + pub + "\nAllowedIPs=0.0.0.0/0\n")
	if err != nil {
		t.Fatalf("ParseWireGuardQuickConfig: %v", err)
	}
	cfg, err := ParseWireGuardConfigJSON("wg", encoded)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint != "" {
		t.Fatalf("peers = %v", cfg.Peers)
	}
}

// A peer-less or key-less config is refused here rather than at handshake time,
// where the failure would be a silent timeout.
func TestParseWireGuardQuickConfigRejectsIncomplete(t *testing.T) {
	priv, pub := wgKeypair(t)

	tests := []struct {
		name string
		conf string
		want string
	}{
		{"no private key", "[Interface]\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=" + pub + "\n", "no [Interface] PrivateKey"},
		{"no peer", "[Interface]\nPrivateKey=" + priv + "\n", "no [Peer] section"},
		{"peer without key", "[Interface]\nPrivateKey=" + priv + "\n[Peer]\nAllowedIPs=0.0.0.0/0\n", "no PublicKey"},
		{"not key = value", "[Interface]\nPrivateKey\n", "not key = value"},
		{"setting before any section", "PrivateKey=" + priv + "\n", "before any"},
		{"unknown section", "[Network]\nFoo=1\n", "unknown section"},
		{"unknown interface setting", "[Interface]\nPrivateKey=" + priv + "\nBanana=1\n", "unsupported [Interface] setting"},
		{"unknown peer setting", "[Interface]\nPrivateKey=" + priv + "\n[Peer]\nBanana=1\n", "unsupported [Peer] setting"},
		{"bad mtu", "[Interface]\nPrivateKey=" + priv + "\nMTU=big\n", "MTU"},
		{"bad keepalive", "[Interface]\nPrivateKey=" + priv + "\n[Peer]\nPersistentKeepalive=often\n", "PersistentKeepalive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWireGuardQuickConfig(tt.conf)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

// A mesh config still parses; only its first peer is used, because an upstream
// is a single tunnel and the datapath has no way to express the rest.
func TestParseWireGuardQuickConfigUsesFirstPeerOnly(t *testing.T) {
	priv, first := wgKeypair(t)
	_, second := wgKeypair(t)

	encoded, err := ParseWireGuardQuickConfig(
		"[Interface]\nPrivateKey=" + priv + "\nAddress=10.0.0.2/32\n" +
			"[Peer]\nPublicKey=" + first + "\nAllowedIPs=10.0.0.1/32\nEndpoint=a.example:51820\n" +
			"[Peer]\nPublicKey=" + second + "\nAllowedIPs=10.0.0.3/32\nEndpoint=b.example:51820\n")
	if err != nil {
		t.Fatalf("ParseWireGuardQuickConfig: %v", err)
	}
	cfg, err := ParseWireGuardConfigJSON("wg", encoded)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("expected one peer, got %v", cfg.Peers)
	}
	if cfg.Peers[0].PublicKey != first {
		t.Fatalf("kept the wrong peer")
	}
}

// Comments, blank lines, mixed-case keys and CRLF line endings all appear in
// configs people paste out of a provider's web UI.
func TestParseWireGuardQuickConfigTolerance(t *testing.T) {
	priv, pub := wgKeypair(t)

	encoded, err := ParseWireGuardQuickConfig(
		"\r\n# leading comment\r\n\r\n[interface]\r\nprivatekey = " + priv + "\r\n" +
			"ADDRESS = 10.0.0.2/32 # inline comment\r\n\r\n" +
			"[PEER]\r\nPublicKey= " + pub + "\r\nallowedips =0.0.0.0/0\r\n")
	if err != nil {
		t.Fatalf("ParseWireGuardQuickConfig: %v", err)
	}
	cfg, err := ParseWireGuardConfigJSON("wg", encoded)
	if err != nil {
		t.Fatalf("re-parsing: %v", err)
	}
	if cfg.PrivateKey != priv || len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey != pub {
		t.Fatalf("config did not survive: %+v", cfg)
	}
	if len(cfg.Addresses) != 1 || cfg.Addresses[0] != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("addresses = %v", cfg.Addresses)
	}
}
