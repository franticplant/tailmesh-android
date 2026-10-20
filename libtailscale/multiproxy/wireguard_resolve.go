// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Hostname resolution inside a WireGuard tunnel.
//
// The datapath never needs it - destinations reach it as literals - but two
// callers hand a WireGuard upstream a hostname: the inbound SOCKS5 listener
// (a client using socks5h / remote resolution) and the DoH client (whose
// resolver URL is usually a name such as cloudflare-dns.com). Before this, both
// failed with "must be a literal address:port"; the DoH client recovered by
// bootstrapping the name off-tunnel, but every attempt was still counted as a
// failed dial on the upstream, which filled the Upstreams screen with errors.
//
// Names are resolved through the tunnel's own "DNS =" servers, over the
// tunnel, so the lookup leaves the same way the connection will. Only the
// families the tunnel can carry are asked for, IPv4 first.

// HostnameResolver is implemented by providers whose Dial may or may not
// accept a hostname depending on configuration. A provider that does not
// implement it is assumed to resolve hostnames itself (SOCKS5 at the far end,
// tailnets through tsnet).
type HostnameResolver interface {
	ResolvesHostnames() bool
}

// providerResolvesHostnames reports whether p's Dial accepts a hostname,
// looking through the stats wrapper readyProvider adds.
func providerResolvesHostnames(p Upstream) bool {
	if sp, ok := p.(*statsProvider); ok {
		p = sp.Provider
	}
	if hr, ok := p.(HostnameResolver); ok {
		return hr.ResolvesHostnames()
	}
	return true
}

const (
	tunnelLookupTimeout = 4 * time.Second
	tunnelCacheMinTTL   = 30 * time.Second
	tunnelCacheMaxTTL   = 5 * time.Minute
)

type tunnelResolver struct {
	p *wireguardProvider

	mu    sync.Mutex
	cache map[string]tunnelCacheEntry
}

type tunnelCacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

func newTunnelResolver(p *wireguardProvider) *tunnelResolver {
	return &tunnelResolver{p: p, cache: make(map[string]tunnelCacheEntry)}
}

// lookup returns the addresses of host the tunnel can dial, IPv4 first.
func (r *tunnelResolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	now := time.Now()
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && now.Before(e.expires) {
		r.mu.Unlock()
		return e.addrs, nil
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, tunnelLookupTimeout)
	defer cancel()

	var qtypes []uint16
	if r.p.v4 {
		qtypes = append(qtypes, dns.TypeA)
	}
	if r.p.v6 {
		qtypes = append(qtypes, dns.TypeAAAA)
	}

	var (
		addrs  []netip.Addr
		minTTL = tunnelCacheMaxTTL
		errs   []error
	)
	for _, qt := range qtypes {
		got, ttl, err := r.query(ctx, host, qt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		addrs = append(addrs, got...)
		if len(got) > 0 && ttl < minTTL {
			minTTL = ttl
		}
	}
	if len(addrs) == 0 {
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
		return nil, fmt.Errorf("no usable addresses for %q", host)
	}
	minTTL = max(minTTL, tunnelCacheMinTTL)

	r.mu.Lock()
	r.cache[host] = tunnelCacheEntry{addrs: addrs, expires: now.Add(minTTL)}
	r.mu.Unlock()
	return addrs, nil
}

// query asks each tunnel DNS server the tunnel can reach in turn, over UDP and
// then TCP on truncation, and returns the first answer.
func (r *tunnelResolver) query(ctx context.Context, host string, qtype uint16) ([]netip.Addr, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true

	var lastErr error
	for _, server := range r.p.dns {
		server = server.Unmap()
		if !r.p.CarriesFamily(isIPv6Dest(server)) {
			continue
		}
		ap := netip.AddrPortFrom(server, 53)
		resp, err := r.exchange(ctx, "udp", ap, m)
		if err == nil && resp.Truncated {
			resp, err = r.exchange(ctx, "tcp", ap, m)
		}
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: %s", ap, dns.RcodeToString[resp.Rcode])
			continue
		}
		return answerAddrs(resp, qtype)
	}
	if lastErr == nil {
		lastErr = errors.New("no tunnel DNS server reachable in a carried address family")
	}
	return nil, 0, lastErr
}

func (r *tunnelResolver) exchange(ctx context.Context, network string, server netip.AddrPort, m *dns.Msg) (*dns.Msg, error) {
	conn, err := r.p.dialAddrPort(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	co := &dns.Conn{Conn: conn}
	if err := co.WriteMsg(m); err != nil {
		return nil, fmt.Errorf("%s: writing query: %w", server, err)
	}
	resp, err := co.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("%s: reading reply: %w", server, err)
	}
	return resp, nil
}

// answerAddrs extracts the A or AAAA records of resp, following nothing: a
// recursive resolver already flattens CNAME chains into the answer section.
func answerAddrs(resp *dns.Msg, qtype uint16) ([]netip.Addr, time.Duration, error) {
	var (
		addrs []netip.Addr
		ttl   = tunnelCacheMaxTTL
	)
	for _, rr := range resp.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ip = v.A
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ip = v.AAAA
			}
		}
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addrs = append(addrs, a.Unmap())
		if d := time.Duration(rr.Header().Ttl) * time.Second; d < ttl {
			ttl = d
		}
	}
	return addrs, ttl, nil
}
