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

	"github.com/miekg/dns"
)

// resolveDirect looks up a hostname for a dial through @direct.
//
// A SOCKS5 client that sends a hostname (remote DNS, as browsers and curl
// --socks5-hostname do) leaves the lookup to the dial. Go's resolver has no
// DNS server to ask on Android - there is no /etc/resolv.conf - so every such
// dial failed with "no such host". Apps on the VPN never hit this: they look
// names up themselves, through handleDNSMsg. This asks the same DNS server
// handleDNSMsg forwards to (the user's DoH resolver, or the network's own),
// directly: the route is @direct, so there is no per-app DNS route to follow.
//
// IPv4 addresses come first, and AAAA is asked for only when IPv6 can be
// dialed directly at all (see directIPv6Usable).
func (e *Engine) resolveDirect(ctx context.Context, host string) ([]netip.Addr, error) {
	e.mu.RLock()
	server := e.upstreamDNS
	e.mu.RUnlock()
	if server == "" {
		return nil, fmt.Errorf("lookup %s: no DNS server known yet", host)
	}
	types := []uint16{dns.TypeA}
	if e.directIPv6UsableNow() {
		types = append(types, dns.TypeAAAA)
	}
	var out []netip.Addr
	var lastErr error
	for _, t := range types {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(host), t)
		var resp *dns.Msg
		var err error
		if strings.HasPrefix(server, "https://") {
			resp, err = exchangeDoH(server, q)
		} else {
			c := &dns.Client{Net: "udp", Dialer: plainDNSDialer, Timeout: dohTimeout}
			resp, _, err = c.ExchangeContext(ctx, q, server)
			if err == nil && resp.Truncated {
				c.Net = "tcp"
				resp, _, err = c.ExchangeContext(ctx, q, server)
			}
		}
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				if ip, ok := netip.AddrFromSlice(rr.A.To4()); ok {
					out = append(out, ip)
				}
			case *dns.AAAA:
				if ip, ok := netip.AddrFromSlice(rr.AAAA); ok {
					out = append(out, ip)
				}
			}
		}
	}
	if len(out) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("lookup %s via %s: %w", host, server, lastErr)
		}
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	return out, nil
}

// directIPv6UsableNow reports whether a direct IPv6 dial can work; true when
// the platform has not said.
func (e *Engine) directIPv6UsableNow() bool {
	if f := e.directIPv6Usable.Load(); f != nil {
		return (*f)()
	}
	return true
}

// dialResolved dials address, looking its host up with resolve first when it
// is a name, and trying each address in turn.
func dialResolved(ctx context.Context, dial UpstreamDialer, resolve func(context.Context, string) ([]netip.Addr, error), network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || resolve == nil {
		return dial(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return dial(ctx, network, address)
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ip := range ips {
		c, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}
