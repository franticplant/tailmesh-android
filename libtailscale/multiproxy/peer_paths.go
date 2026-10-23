// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
)

// Per-peer connection paths of a tailnet.
//
// pollTailnetStatus already asks each tailnet's tsnet node for its full peer
// list every 10s; the path of every peer is derived from that same Status()
// call and cached on the TailnetRuntime, so neither the per-peer view nor the
// peerPath summary in upstreams.stats adds any tsnet work.

// Peer path values, matching what `tailscale status` prints.
const (
	PeerPathDirect    = "direct"     // a UDP path is in use (TailnetPeer.Addr)
	PeerPathDERP      = "derp"       // relayed through DERP (TailnetPeer.DERPRegion)
	PeerPathPeerRelay = "peer-relay" // relayed through a Tailscale peer relay
	PeerPathIdle      = "idle"       // nothing sent recently, so no path is chosen
)

// TailnetPeer is one row of GetTailnetPeersJSON.
type TailnetPeer struct {
	Name       string   `json:"name"`
	DNSName    string   `json:"dnsName,omitempty"`
	OS         string   `json:"os,omitempty"`
	TailnetIPs []string `json:"tailnetIps"`
	Online     bool     `json:"online"`
	Active     bool     `json:"active"`
	ExitNode   bool     `json:"exitNode,omitempty"`
	Path       string   `json:"path"`
	// Addr is the UDP address in use when Path is direct.
	Addr string `json:"addr,omitempty"`
	// DERPRegion is the peer's home DERP region code. It is the relay in use
	// when Path is derp.
	DERPRegion string `json:"derpRegion,omitempty"`
	// PeerRelay is the relay address (ip:port:vni) when Path is peer-relay;
	// PeerRelayNode names the peer serving it, when it is one of this
	// tailnet's peers.
	PeerRelay           string `json:"peerRelay,omitempty"`
	PeerRelayNode       string `json:"peerRelayNode,omitempty"`
	LastHandshakeMillis int64  `json:"lastHandshakeMillis,omitempty"`
	LastWriteMillis     int64  `json:"lastWriteMillis,omitempty"`
	RxBytes             int64  `json:"rxBytes"`
	TxBytes             int64  `json:"txBytes"`
}

// TailnetPeersExport is the shape of GetTailnetPeersJSON.
type TailnetPeersExport struct {
	TailnetID string `json:"tailnetId"`
	// Summary is the same value upstreams.stats reports as peerPath.
	Summary string `json:"summary"`
	// UpdatedAtMillis is when the peer list was last read from tsnet, 0 if
	// it has not been yet.
	UpdatedAtMillis int64         `json:"updatedAtMillis"`
	Peers           []TailnetPeer `json:"peers"`
}

// peerPathOf maps one PeerStatus to its path, the same way `tailscale status`
// does. magicsock only fills CurAddr/PeerRelay while that UDP path is trusted,
// so a non-empty CurAddr is a live direct path even if the peer is idle.
func peerPathOf(ps *ipnstate.PeerStatus) string {
	switch {
	case ps.CurAddr != "":
		return PeerPathDirect
	case ps.PeerRelay != "":
		return PeerPathPeerRelay
	case ps.Active && ps.Relay != "":
		return PeerPathDERP
	default:
		return PeerPathIdle
	}
}

// tailnetPeersFromStatus builds the per-peer rows from a full Status().
func tailnetPeersFromStatus(st *ipnstate.Status) []TailnetPeer {
	if st == nil {
		return nil
	}
	// A peer relay is addressed by one of the relaying peer's endpoints.
	nodeByEndpointIP := make(map[netip.Addr]string)
	for _, ps := range st.Peer {
		if ps == nil {
			continue
		}
		for _, a := range ps.Addrs {
			if ap, err := netip.ParseAddrPort(a); err == nil {
				nodeByEndpointIP[ap.Addr().Unmap()] = peerName(ps)
			}
		}
	}

	out := make([]TailnetPeer, 0, len(st.Peer))
	for _, ps := range st.Peer {
		if ps == nil || ps.ID == "" {
			continue
		}
		p := TailnetPeer{
			Name:       peerName(ps),
			DNSName:    strings.TrimSuffix(ps.DNSName, "."),
			OS:         ps.OS,
			TailnetIPs: make([]string, 0, len(ps.TailscaleIPs)),
			Online:     ps.Online,
			Active:     ps.Active,
			ExitNode:   ps.ExitNode,
			Path:       peerPathOf(ps),
			DERPRegion: ps.Relay,
			RxBytes:    ps.RxBytes,
			TxBytes:    ps.TxBytes,
		}
		for _, ip := range ps.TailscaleIPs {
			p.TailnetIPs = append(p.TailnetIPs, ip.String())
		}
		switch p.Path {
		case PeerPathDirect:
			p.Addr = ps.CurAddr
		case PeerPathPeerRelay:
			p.PeerRelay = ps.PeerRelay
			p.PeerRelayNode = nodeByEndpointIP[peerRelayIP(ps.PeerRelay)]
		}
		if !ps.LastHandshake.IsZero() {
			p.LastHandshakeMillis = ps.LastHandshake.UnixMilli()
		}
		if !ps.LastWrite.IsZero() {
			p.LastWriteMillis = ps.LastWrite.UnixMilli()
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func peerName(ps *ipnstate.PeerStatus) string {
	if ps.HostName != "" {
		return ps.HostName
	}
	name, _, _ := strings.Cut(ps.DNSName, ".")
	return name
}

// peerRelayIP extracts the IP from magicsock's "ip:port:vni:N" peer relay
// address form (IPv6 is bracketed: "[::1]:port:vni:N").
func peerRelayIP(s string) netip.Addr {
	if strings.HasPrefix(s, "[") {
		if end := strings.Index(s, "]"); end > 0 {
			ip, _ := netip.ParseAddr(s[1:end])
			return ip.Unmap()
		}
		return netip.Addr{}
	}
	host, _, _ := strings.Cut(s, ":")
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

// summarizePeerPaths turns the per-peer rows into the single peerPath value
// upstreams.stats shows for a tailnet: "direct", "derp:<region>" (or "derp"
// when peers are relayed through more than one region), "peer-relay",
// "mixed" when peers use different kinds of path, and "idle" when no peer
// has a path at the moment (including a tailnet with no peers).
func summarizePeerPaths(peers []TailnetPeer) string {
	kinds := make(map[string]bool)
	regions := make(map[string]bool)
	for _, p := range peers {
		if p.Path == PeerPathIdle {
			continue
		}
		kinds[p.Path] = true
		if p.Path == PeerPathDERP {
			regions[p.DERPRegion] = true
		}
	}
	switch len(kinds) {
	case 0:
		return PeerPathIdle
	case 1:
	default:
		return "mixed"
	}
	switch {
	case kinds[PeerPathDirect]:
		return PeerPathDirect
	case kinds[PeerPathPeerRelay]:
		return PeerPathPeerRelay
	}
	if len(regions) == 1 {
		for r := range regions {
			if r != "" {
				return "derp:" + r
			}
		}
	}
	return PeerPathDERP
}

// setTailnetPeers records the per-peer rows from pollTailnetStatus.
func (e *Engine) setTailnetPeers(id UpstreamID, peers []TailnetPeer, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rt, ok := e.tailnets[id]
	if !ok || !rt.Enabled {
		return
	}
	rt.Peers = peers
	rt.PeersAt = at
}

// tailnetPeerSummary is the peerPath value for a tailnet upstream with no exit
// node set: "unknown" until the first poll succeeded.
func (e *Engine) tailnetPeerSummary(id UpstreamID) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rt, ok := e.tailnets[id]
	if !ok || !rt.Enabled || rt.PeersAt.IsZero() {
		return "unknown"
	}
	return summarizePeerPaths(rt.Peers)
}

// GetTailnetPeersJSON returns the cached per-peer paths of one tailnet as a
// TailnetPeersExport, or an error if the tailnet is unknown or not running.
func (e *Engine) GetTailnetPeersJSON(identifier string) (string, error) {
	e.mu.RLock()
	rt, ok := e.tailnets[UpstreamID(identifier)]
	if !ok {
		e.mu.RUnlock()
		return "", errors.New("tailnet not found")
	}
	if !rt.Enabled {
		e.mu.RUnlock()
		return "", errors.New("tailnet is not running")
	}
	out := TailnetPeersExport{
		TailnetID: identifier,
		Peers:     append([]TailnetPeer(nil), rt.Peers...),
	}
	if !rt.PeersAt.IsZero() {
		out.UpdatedAtMillis = rt.PeersAt.UnixMilli()
	}
	e.mu.RUnlock()

	out.Summary = e.peerPathFor(UpstreamID(identifier), UpstreamKindTailnet)
	if out.Peers == nil {
		out.Peers = []TailnetPeer{}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
