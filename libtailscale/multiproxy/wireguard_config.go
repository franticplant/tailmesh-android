// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// JSON form of a WireGuard upstream's configuration.
//
// This is what crosses the JNI boundary, so it lives here rather than in the
// binding layer: gomobile can only carry strings, and parsing is where the
// mistakes are, so it belongs somewhere it can be tested. It follows the shape
// of a wg-quick config closely enough that a user can transcribe one field by
// field.

// wireGuardConfigJSON is the wire form. It is separate from WireGuardConfig
// because that one holds parsed netip types, which do not survive JSON in the
// spelling a wg config uses.
type wireGuardConfigJSON struct {
	PrivateKey string   `json:"privateKey"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns"`
	MTU        int      `json:"mtu"`
	ListenPort uint16   `json:"listenPort"`
	Via        string   `json:"via"`
	Peers      []struct {
		PublicKey           string   `json:"publicKey"`
		PresharedKey        string   `json:"presharedKey"`
		Endpoint            string   `json:"endpoint"`
		AllowedIPs          []string `json:"allowedIPs"`
		PersistentKeepalive uint16   `json:"persistentKeepalive"`
	} `json:"peers"`
}

// ParseWireGuardConfigJSON turns the JSON form into a WireGuardConfig.
//
// Keys are base64 exactly as a wg config writes them. Tunnel addresses may carry
// a prefix ("10.9.0.2/32") or not ("10.9.0.2"), because wg-quick writes the
// first and people paste those configs verbatim; the prefix length is discarded,
// as the tunnel's netstack routes by the peers' allowed IPs rather than by an
// on-link prefix.
//
// It validates only what it can see - that addresses and prefixes parse. Whether
// the keys are usable and the peers reachable is settled by
// NewWireGuardUpstream, which is the only thing that can tell.
func ParseWireGuardConfigJSON(id, configJSON string) (WireGuardConfig, error) {
	var raw wireGuardConfigJSON
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return WireGuardConfig{}, fmt.Errorf("wireguard: parsing config: %w", err)
	}

	cfg := WireGuardConfig{
		ID:         UpstreamID(id),
		PrivateKey: raw.PrivateKey,
		MTU:        raw.MTU,
		ListenPort: raw.ListenPort,
		Via:        UpstreamID(raw.Via),
	}

	for _, s := range raw.Addresses {
		addr, err := parseAddrMaybePrefixed(s)
		if err != nil {
			return WireGuardConfig{}, fmt.Errorf("wireguard: tunnel address %q: %w", s, err)
		}
		cfg.Addresses = append(cfg.Addresses, addr)
	}
	for _, s := range raw.DNS {
		addr, err := parseAddrMaybePrefixed(s)
		if err != nil {
			return WireGuardConfig{}, fmt.Errorf("wireguard: DNS address %q: %w", s, err)
		}
		cfg.DNS = append(cfg.DNS, addr)
	}

	for i, p := range raw.Peers {
		peer := WireGuardPeer{
			PublicKey:           p.PublicKey,
			PresharedKey:        p.PresharedKey,
			Endpoint:            p.Endpoint,
			PersistentKeepalive: p.PersistentKeepalive,
		}
		for _, s := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return WireGuardConfig{}, fmt.Errorf("wireguard: peer %d allowed IP %q: %w", i, s, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, pfx)
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg, nil
}

func parseAddrMaybePrefixed(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, err
		}
		return pfx.Addr(), nil
	}
	return netip.ParseAddr(s)
}
