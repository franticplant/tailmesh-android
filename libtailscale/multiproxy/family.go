// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
)

// Address-family capability of upstreams.
//
// The TUN advertises both IPv4 and IPv6 to Android, so a dual-stack app picks
// IPv6 whenever a name has an AAAA record. That is only safe if the upstream the
// flow is routed through can actually carry IPv6. A WireGuard tunnel configured
// with nothing but "Address = 10.77.0.2/32" cannot: its netstack has no IPv6
// address and no IPv6 route, so every IPv6 dial fails instantly. Because gVisor
// has already completed the client's handshake by the time the dial is
// attempted, the app sees an accepted connection that is then closed
// (Chrome: ERR_CONNECTION_CLOSED) and never falls back to IPv4 - Happy Eyeballs
// only races connects, and from its point of view the IPv6 connect succeeded.
//
// The same accept-then-reset problem was fixed for @direct in §93/§96 using
// Engine.directIPv6Usable. FamilyCarrier generalizes it: any provider that
// knows its own family support up front reports it, and the datapath rejects
// a flow it cannot carry before accepting it (a RST to the SYN, or an ICMP
// unreachable for UDP), which is exactly what lets the client fall back. The
// DNS forwarder additionally answers AAAA with NODATA for an app whose route
// cannot carry IPv6, so most such flows are never attempted at all.

// FamilyCarrier is implemented by providers that know, without dialing,
// whether they can carry each address family. A provider that does not
// implement it is assumed to carry both, which is the pre-existing behaviour:
// a SOCKS5 proxy or a tailnet exit node resolves reachability at the far end,
// and only a dial can tell.
type FamilyCarrier interface {
	CarriesFamily(ipv6 bool) bool
}

// providerCarriesFamily reports whether p can carry dials of the given family,
// looking through the stats wrapper readyProvider adds.
func providerCarriesFamily(p Upstream, ipv6 bool) bool {
	if sp, ok := p.(*statsProvider); ok {
		p = sp.Provider
	}
	if fc, ok := p.(FamilyCarrier); ok {
		return fc.CarriesFamily(ipv6)
	}
	return true
}

// isIPv6Dest reports whether addr is a real IPv6 address, as opposed to IPv4 or
// an IPv4-mapped IPv6 address.
func isIPv6Dest(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6()
}

// rejectUncarriableFamily reports whether a routed flow should be refused
// before it is accepted, because the upstream it resolved to cannot carry the
// family of the address it would dial. The address that matters is
// decision.Destination - for a tailnet peer that is the native locator, which
// may be IPv4 even when the app dialed a synthetic IPv6 identity.
func rejectUncarriableFamily(decision RouteDecision, targetIP netip.Addr, directIPv6Usable *func() bool) bool {
	if rejectDoomedDirectIPv6(decision, targetIP, directIPv6Usable) {
		return true
	}
	if decision.Upstream == nil || decision.UpstreamID == DirectUpstreamID {
		return false
	}
	dest, err := netip.ParseAddr(decision.Destination)
	if err != nil {
		return false
	}
	return !providerCarriesFamily(decision.Upstream, isIPv6Dest(dest))
}

// appRouteCarriesIPv6 reports whether the data route of an app, as far as it
// can be decided from the app alone, can carry IPv6. It answers true whenever
// that cannot be known - no app-only rule, an upstream that does not report
// its families, no direct-network hook - so it only ever suppresses AAAA
// answers that would certainly lead to a dead flow.
func (e *Engine) appRouteCarriesIPv6(appUID int32) bool {
	if e.policy == nil {
		return true
	}
	rule, ok := e.policy.Get().MatchAppOnly(appUID)
	if !ok {
		return true
	}
	switch rule.Action {
	case ActionDirect:
		return e.directCarriesIPv6()
	case ActionRoute:
		if rule.Upstream == DirectUpstreamID {
			return e.directCarriesIPv6()
		}
		p, ok := e.lookupProvider(rule.Upstream)
		if !ok {
			return true
		}
		return providerCarriesFamily(p, true)
	default:
		return true
	}
}

func (e *Engine) directCarriesIPv6() bool {
	f := e.directIPv6Usable.Load()
	if f == nil {
		return true
	}
	return (*f)()
}
