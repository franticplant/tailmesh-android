package multiproxy

import (
	"context"
	"crypto/sha256"
	"net"
	"net/netip"

	"tailscale.com/net/tsaddr"
)

type UpstreamID string

type TargetKind string

const (
	TargetKindTailscaleNode TargetKind = "tailscale-node"
)

type TargetKey struct {
	NamespaceID UpstreamID
	Kind        TargetKind
	// StableID is the stable Tailscale node identity within its control-plane lifecycle (e.g. tailcfg.StableNodeID).
	// Uniqueness is defined by UpstreamID + StableID.
	StableID    string
}

var SyntheticIPv6Prefix = netip.MustParsePrefix("fd9b:8d7c:6a5e::/48")
var SyntheticIPv6ControlPrefix = netip.MustParsePrefix("fd9b:8d7c:6a5e::/120")
var SyntheticIPv6Interface = netip.MustParseAddr("fd9b:8d7c:6a5e::1")
var SyntheticIPv6DNS = netip.MustParseAddr("fd9b:8d7c:6a5e::3")

// Synthetic IPv4 space. Plenty of software still can't use an IPv6 literal -
// it hardcodes AF_INET, parses with inet_addr, or just asks for an A record
// and gives up - so tailnet peers need a v4 address here too, for the same
// reason they need a synthetic v6 one: real Tailscale addresses are drawn
// from one pool shared by every tailnet, so they can't disambiguate peers
// while several upstreams are active at once.
//
// 198.18.0.0/15 is the RFC 2544 benchmarking range: routable-looking, but
// reserved, so it won't be mistaken for a LAN (10/8, 172.16/12, 192.168/16),
// for real Tailscale space (100.64.0.0/10), or for anything a peer might
// legitimately advertise as a subnet route.
var SyntheticIPv4Prefix = netip.MustParsePrefix("198.18.0.0/15")
var SyntheticIPv4ControlPrefix = netip.MustParsePrefix("198.18.0.0/24")
var SyntheticIPv4Interface = netip.MustParseAddr("198.18.0.1")
var SyntheticIPv4DNS = netip.MustParseAddr("198.18.0.3")

// Real Tailscale address space: the CGNAT v4 range and the Tailscale ULA v6
// range that a node's own addresses are actually drawn from. Some apps are
// handed a peer's real IP directly rather than a hostname - SIP and TURN/STUN
// both put literal addresses in their payloads - so those addresses never
// pass through our synthetic DNS and have to be routable on their own.
//
// Taken from tsaddr rather than written out here so they can't drift from
// what the upstream nodes actually assign.
var RealTailscaleIPv4Prefix = tsaddr.CGNATRange()
var RealTailscaleIPv6Prefix = tsaddr.TailscaleULARange()

// IsRealTailscaleAddr reports whether addr is in real Tailscale space, i.e.
// an address a peer genuinely holds rather than one we minted.
func IsRealTailscaleAddr(addr netip.Addr) bool {
	return RealTailscaleIPv4Prefix.Contains(addr) || RealTailscaleIPv6Prefix.Contains(addr)
}

func (k TargetKey) SyntheticIPv6() netip.Addr {
	namespace := string(k.NamespaceID)
	kind := string(k.Kind)
	stableID := k.StableID

	data := []byte(namespace + "\x00" + kind + "\x00" + stableID)

	for {
		hash := sha256.Sum256(data)

		var addr [16]byte
		prefixBytes := SyntheticIPv6Prefix.Addr().As16()
		copy(addr[:6], prefixBytes[:6])
		copy(addr[6:], hash[:10])

		ip := netip.AddrFrom16(addr)
		if !SyntheticIPv6ControlPrefix.Contains(ip) {
			return ip
		}
		
		data = append(data, 1)
	}
}

type TargetRecord struct {
	Key              TargetKey
	SyntheticIPv6    netip.Addr
	Hostname         string
	CurrentIPv4      netip.Addr
	CurrentIPv6      netip.Addr
	RequiredUpstream UpstreamID
}

type Upstream interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)

	// PeerPathInfo reports whether the path to destIP (a Tailscale IP on
	// this upstream) is currently direct or DERP-relayed, e.g. "direct" or
	// "derp:fra". It never blocks meaningfully or returns an error; on
	// failure to determine the path it returns "unknown". This exists so
	// throughput problems can be diagnosed as relay-path instability rather
	// than guessed at from symptoms alone (see validation_and_gaps.md §40).
	PeerPathInfo(ctx context.Context, destIP string) string
}

type RouteDecision struct {
	Upstream    Upstream
	UpstreamID  UpstreamID
	Destination string
}
