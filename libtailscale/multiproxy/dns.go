// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

// dnsIdleTimeout bounds how long a DNS UDP/TCP association may sit idle
// before we tear it down, so a stalled or malicious peer can't pin a
// synthetic association (and its resources) open indefinitely.
const dnsIdleTimeout = 30 * time.Second

// dohTimeout bounds a single DNS-over-HTTPS upstream query. This is
// deliberately short: a DoH resolver that's this slow to answer a single
// query isn't usable as a DNS resolver regardless, and the querying app is
// already waiting on this synchronously.
const dohTimeout = 5 * time.Second

// dohHTTPClient must dial via netns.NewDialer rather than the default
// transport: once our VPN is up, a socket opened by the default (unprotected)
// dialer gets routed back into our own TUN instead of reaching the real
// internet, so every DoH request would hang until dohTimeout (or fail DNS
// resolution outright) regardless of network quality. netns.NewDialer routes
// through the same VpnService.protect() hook tsnet's own dials use.
var dohHTTPClient = &http.Client{
	Timeout: dohTimeout,
	Transport: &http.Transport{
		DialContext: dialUpstreamDNS,
		// Setting DialContext suppresses net/http's automatic HTTP/2
		// negotiation. Some DoH providers (Mullvad among them) serve HTTP/2
		// only, and answer an HTTP/1.1 request with a raw SETTINGS frame that
		// the client then reports as a malformed response.
		ForceAttemptHTTP2: true,
		// See dohIdleConnTimeout's doc comment (dns_policy.go) - bounds the
		// pooled-connection accumulation the same way for the device-direct
		// DoH path as for the per-upstream one.
		IdleConnTimeout:     dohIdleConnTimeout,
		MaxIdleConnsPerHost: dohMaxIdleConnsPerHost,
	},
}

// dialUpstreamDNS dials the DoH server, resolving its hostname without going
// through the device resolver.
//
// This is the bootstrap problem: our own VPN installs the synthetic DNS server
// as the device resolver, so asking the device to resolve the DoH server's
// hostname routes the query straight back into handleDNSMsg, which tries to
// answer it by making this very request. The lookup deadlocks against itself
// and every DoH query fails until dohTimeout, no matter which provider is
// selected or how healthy the network is. A DoH URL written with an IP literal
// works fine, which is what isolated the loop.
//
// IPv4 is preferred for the same reason Standard mode prefers it: public
// resolvers publish AAAA records, and on a network whose IPv6 egress is
// advertised but dead the v6 attempt stalls out the whole query budget.
func dialUpstreamDNS(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6":
		network = "tcp4"
	case "udp", "udp6":
		network = "udp4"
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netnsDialer.DialContext(ctx, network, address)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return netnsDialer.DialContext(ctx, network, address)
	}

	ips, err := bootstrapResolve(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := netnsDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses for %q", host)
	}
	return nil, fmt.Errorf("bootstrap dial %q: %w", host, lastErr)
}

var netnsDialer = netns.NewDialer(log.Printf, netmon.NewStatic())

// bootstrapState carries what dialUpstreamDNS needs to resolve a DoH hostname
// without recursing through our own resolver: the plain upstream the device
// was using before we took DNS over, and the DoH base URL (so the known-IP
// table can answer for well-known providers even with no plain resolver).
var bootstrapState struct {
	mu       sync.RWMutex
	plainDNS string
	dohBase  string
	cache    map[string]bootstrapEntry
}

type bootstrapEntry struct {
	ips []netip.Addr
	at  time.Time
}

const bootstrapCacheTTL = 5 * time.Minute

func setBootstrapPlainDNS(addr string) {
	bootstrapState.mu.Lock()
	defer bootstrapState.mu.Unlock()
	bootstrapState.plainDNS = addr
}

func setBootstrapDoHBase(base string) {
	bootstrapState.mu.Lock()
	defer bootstrapState.mu.Unlock()
	bootstrapState.dohBase = base
}

// bootstrapResolve maps a DoH hostname to addresses using, in order: a short
// cache, the built-in table of well-known public resolver IPs, and finally a
// direct plain-DNS query to whatever resolver the underlying network handed us
// before our VPN replaced it. The last step is what makes arbitrary custom DoH
// URLs work, since those are absent from the known-IP table.
func bootstrapResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	bootstrapState.mu.RLock()
	entry, cached := bootstrapState.cache[host]
	plainDNS := bootstrapState.plainDNS
	dohBase := bootstrapState.dohBase
	bootstrapState.mu.RUnlock()

	if cached && time.Since(entry.at) < bootstrapCacheTTL && len(entry.ips) > 0 {
		return entry.ips, nil
	}

	var ips []netip.Addr
	if dohBase != "" {
		if u, err := url.Parse(dohBase); err == nil && u.Hostname() == host {
			for _, ip := range publicdns.DoHIPsOfBase(dohBase) {
				if ip.Is4() {
					ips = append(ips, ip)
				}
			}
		}
	}

	if len(ips) == 0 && plainDNS != "" {
		resolved, err := bootstrapQuery(ctx, plainDNS, host)
		if err != nil {
			return nil, fmt.Errorf("bootstrap lookup %q via %s: %w", host, plainDNS, err)
		}
		ips = resolved
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no bootstrap address for %q (no known IPs, no underlying resolver)", host)
	}

	bootstrapState.mu.Lock()
	if bootstrapState.cache == nil {
		bootstrapState.cache = make(map[string]bootstrapEntry)
	}
	bootstrapState.cache[host] = bootstrapEntry{ips: ips, at: time.Now()}
	bootstrapState.mu.Unlock()

	return ips, nil
}

func bootstrapQuery(ctx context.Context, resolver, host string) ([]netip.Addr, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)

	c := &dns.Client{Net: "udp", Dialer: plainDNSDialer, Timeout: dohTimeout}
	resp, _, err := c.ExchangeContext(ctx, m, resolver)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(a.A.To4()); ok {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records")
	}
	return ips, nil
}

// plainDNSDialer is the same self-capture fix as dohHTTPClient above, applied
// to the plain (non-DoH) upstream forward path in handleDNSMsg: a
// *net.Dialer with no Control func would have its socket routed back into
// our own TUN once the VPN is up, so every non-DoH upstream DNS query (the
// default underlying-network resolver, or a plain host:port custom one)
// would silently fail exactly like the DoH path did before it was protected.
var plainDNSDialer = func() *net.Dialer {
	d := &net.Dialer{}
	netns.FromDialer(log.Printf, netmon.NewStatic(), d)
	return d
}()

// exchangeDoH sends req to a DNS-over-HTTPS resolver per RFC 8484 (the
// POST/application-dns-message form, which every public DoH provider we
// list supports) and returns its parsed response.
func exchangeDoH(resolverURL string, req *dns.Msg) (*dns.Msg, error) {
	return exchangeDoHWith(dohHTTPClient, resolverURL, req)
}

// exchangeDoHWith is exchangeDoH with the client supplied, so a query routed
// through an upstream can use one that dials through it. See dns_policy.go.
func exchangeDoHWith(client *http.Client, resolverURL string, req *dns.Msg) (*dns.Msg, error) {
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DoH query: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, resolverURL, bytes.NewReader(packed))
	if err != nil {
		return nil, fmt.Errorf("building DoH request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request to %s: %w", resolverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH resolver %s returned HTTP %d", resolverURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading DoH response from %s: %w", resolverURL, err)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking DoH response from %s: %w", resolverURL, err)
	}
	return respMsg, nil
}

func (e *Engine) updateTailnetSnapshot(uid UpstreamID, snapshot []TargetRecord) []TargetRecord {
	e.targetMutex.Lock()
	defer e.targetMutex.Unlock()

	e.tailnetSnapshots[uid] = snapshot
	e.rebuildTargetsUnlocked()

	var accepted []TargetRecord
	for _, rec := range snapshot {
		if mapped, ok := e.targets[rec.SyntheticIPv6]; ok && mapped.Key == rec.Key {
			accepted = append(accepted, rec)
		}
	}
	return accepted
}

func (e *Engine) rebuildTargetsUnlocked() {
	e.targets = make(map[netip.Addr]TargetRecord)
	collided := make(map[netip.Addr]bool)
	e.realIPIndex = make(map[netip.Addr][]TargetRecord)

	for _, records := range e.tailnetSnapshots {
		for _, r := range records {
			if collided[r.SyntheticIPv6] {
				continue
			}

			if existing, exists := e.targets[r.SyntheticIPv6]; exists {
				if existing.Key != r.Key {
					collided[r.SyntheticIPv6] = true
					delete(e.targets, r.SyntheticIPv6)
				}
				continue
			}

			e.targets[r.SyntheticIPv6] = r

			// Real Tailscale address space is shared across every tailnet,
			// so - unlike the synthetic table above - a real IP legitimately
			// belonging to more than one upstream at once is not a
			// collision to discard; every candidate is kept and the choice
			// among them is made (and surfaced) at resolve time.
			if r.CurrentIPv4.IsValid() {
				e.realIPIndex[r.CurrentIPv4] = append(e.realIPIndex[r.CurrentIPv4], r)
			}
			if r.CurrentIPv6.IsValid() {
				e.realIPIndex[r.CurrentIPv6] = append(e.realIPIndex[r.CurrentIPv6], r)
			}
		}
	}

	// Assign synthetic v4 addresses over the same set of targets that
	// survived collision handling above, so the two families always describe
	// the same peers.
	keys := make([]TargetKey, 0, len(e.targets))
	for _, r := range e.targets {
		keys = append(keys, r.Key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].NamespaceID != keys[j].NamespaceID {
			return keys[i].NamespaceID < keys[j].NamespaceID
		}
		return keys[i].StableID < keys[j].StableID
	})

	e.syntheticV4ByKey = assignSyntheticIPv4(keys, e.syntheticV4ByKey)
	e.syntheticV4 = make(map[netip.Addr]TargetRecord, len(e.syntheticV4ByKey))
	for _, r := range e.targets {
		if addr, ok := e.syntheticV4ByKey[r.Key]; ok {
			e.syntheticV4[addr] = r
		}
	}

	e.dnsTable = make(map[string][]netip.Addr)
	e.baseDnsTable = make(map[string][]netip.Addr)
	e.dnsTableV4 = make(map[string][]netip.Addr)
	e.baseDnsTableV4 = make(map[string][]netip.Addr)

	for _, r := range e.targets {
		hashID := getStableHash(string(r.RequiredUpstream))
		if r.Hostname == "" {
			continue
		}

		fqdn := strings.ToLower(r.Hostname)
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}

		parts := strings.Split(fqdn, ".")
		baseName := parts[0] + "."

		e.dnsTable[fqdn] = append(e.dnsTable[fqdn], r.SyntheticIPv6)
		e.baseDnsTable[baseName] = append(e.baseDnsTable[baseName], r.SyntheticIPv6)

		qualified := fmt.Sprintf("%s.%s.proxy.", strings.TrimSuffix(baseName, "."), hashID)
		e.dnsTable[qualified] = append(e.dnsTable[qualified], r.SyntheticIPv6)

		// A peer with no v4 slot (only possible once the pool is exhausted)
		// is simply absent from the v4 tables, so it answers NODATA for A
		// rather than handing out an address that routes somewhere else.
		if v4, ok := e.syntheticV4ByKey[r.Key]; ok {
			e.dnsTableV4[fqdn] = append(e.dnsTableV4[fqdn], v4)
			e.baseDnsTableV4[baseName] = append(e.baseDnsTableV4[baseName], v4)
			e.dnsTableV4[qualified] = append(e.dnsTableV4[qualified], v4)
		}
	}
}

func (e *Engine) ServeDNSUDP(conn net.Conn, flow FlowInfo) {
	defer recoverAndLog("ServeDNSUDP")
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}

		resp := e.handleDNSMsg(req, "udp", flow)
		e.AddDNSQuery(resp.Rcode != dns.RcodeSuccess)
		out, err := resp.Pack()
		if err != nil {
			continue
		}
		if err := conn.SetWriteDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (e *Engine) ServeDNSTCP(conn net.Conn, flow FlowInfo) {
	defer recoverAndLog("ServeDNSTCP")
	defer conn.Close()

	for {
		if err := conn.SetDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(lenBuf))
		if length == 0 {
			continue
		}

		buf := make([]byte, length)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			continue
		}

		resp := e.handleDNSMsg(req, "tcp", flow)
		e.AddDNSQuery(resp.Rcode != dns.RcodeSuccess)
		out, err := resp.Pack()
		if err != nil || len(out) > 0xffff {
			continue
		}

		if err := conn.SetWriteDeadline(time.Now().Add(dnsIdleTimeout)); err != nil {
			return
		}
		binary.BigEndian.PutUint16(lenBuf, uint16(len(out)))
		if err := writeFull(conn, lenBuf); err != nil {
			return
		}
		if err := writeFull(conn, out); err != nil {
			return
		}
	}
}

func (e *Engine) handleDNSMsg(r *dns.Msg, netType string, flow FlowInfo) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)

	// qname/qtype for logDNSQuery below - computed once regardless of whether
	// logging is enabled (cheap: just reading the first question, which every
	// call site already has), the enabled check happens inside logDNSQuery
	// itself so callers never need to guard it.
	qname, qtype := "", ""
	if len(r.Question) > 0 {
		qname = strings.ToLower(r.Question[0].Name)
		qtype = dns.TypeToString[r.Question[0].Qtype]
	}
	logDNS := func(upstreamID, outcome string) { e.logDNSQuery(qname, qtype, flow.AppUID, upstreamID, outcome) }

	hasAnswer := false
	ambiguous := false
	nodata := false

	e.targetMutex.RLock()
	for _, q := range r.Question {
		qName := strings.ToLower(q.Name)
		ips, ok := e.dnsTable[qName]
		if !ok {
			ips, ok = e.baseDnsTable[qName]
		}

		if !ok {
			continue
		}

		// The name is ours either way; ambiguity is decided on the v6 table
		// because it holds every target, v4-assigned or not.
		if len(ips) > 1 {
			ambiguous = true
			continue
		}

		switch q.Qtype {
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(fmt.Sprintf("%s AAAA %s", qName, ips[0].String()))
			m.Answer = append(m.Answer, rr)
			hasAnswer = true
		case dns.TypeA:
			v4, okV4 := e.dnsTableV4[qName]
			if !okV4 {
				v4, okV4 = e.baseDnsTableV4[qName]
			}
			if okV4 && len(v4) == 1 {
				rr, _ := dns.NewRR(fmt.Sprintf("%s A %s", qName, v4[0].String()))
				m.Answer = append(m.Answer, rr)
				hasAnswer = true
			} else {
				// Known name, no usable v4 address: NODATA, never NXDOMAIN,
				// so a dual-stack client still falls through to AAAA.
				nodata = true
				hasAnswer = true
			}
		default:
			nodata = true
			hasAnswer = true
		}
	}
	e.targetMutex.RUnlock()

	if ambiguous {
		logDNS("", "ambiguous")
		m.Rcode = dns.RcodeNameError
		return m
	}

	if !hasAnswer && !nodata {
		e.mu.RLock()
		upstream := e.upstreamDNS
		e.mu.RUnlock()

		if upstream == "" {
			logDNS("", "no-upstream-configured")
			m.Rcode = dns.RcodeServerFailure
			return m
		}

		// A UID-scoped policy rule exists (this app, or some app, has an
		// explicit route) but this query's flow could not be attributed -
		// see uid.go's resolveAppUID and flowinfo.go's attributionFailures
		// counter. Falling through to the default/direct route here would
		// silently leak this app's lookups outside the route it - or
		// another app - was deliberately given, so this fails closed
		// instead: refuse rather than guess. General (non-DNS) data
		// traffic does not fail closed the same way yet (see
		// docs/multi_tailnet_proxy_app/observability.md) - deliberately
		// scoped to DNS first, since a refused lookup is cheap and
		// recoverable (the app/OS resolver retries or surfaces "can't find
		// site"), unlike dropping an already-established data connection.
		if flow.AppUID == UnknownAppUID && e.policyUsesAppUID() {
			e.obs.dp.addDNSAttributionFailClosed()
			logDNS("", "fail-closed")
			m.Rcode = dns.RcodeServerFailure
			return m
		}

		// Where the forward leaves from follows the asking app's own route, so a
		// proxied app does not announce its lookups to the device resolver. See
		// dns_policy.go.
		route := e.dnsRouteFor(flow)
		switch {
		case route.blocked:
			logDNS("", "blocked")
			m.Rcode = dns.RcodeRefused
			return m
		case route.failed:
			logDNS("", "route-failed")
			m.Rcode = dns.RcodeServerFailure
			return m
		}

		if strings.HasPrefix(upstream, "https://") {
			var (
				resp *dns.Msg
				err  error
			)
			if route.provider != nil {
				resp, err = e.exchangeDoHVia(route.provider.ID(), upstream, r)
			} else {
				resp, err = exchangeDoH(upstream, r)
			}
			if err != nil {
				log.Printf("multiproxy DNS: %v", err)
				upstreamID := ""
				if route.provider != nil {
					upstreamID = string(route.provider.ID())
					e.obs.dp.addDNSForwardFailure()
					e.statsFor(route.provider.ID()).recordDNSFailed()
				}
				logDNS(upstreamID, "forward-fail")
				m.Rcode = dns.RcodeServerFailure
				return m
			}
			upstreamID := ""
			if route.provider != nil {
				upstreamID = string(route.provider.ID())
				e.statsFor(route.provider.ID()).recordDNSForwarded()
			}
			logDNS(upstreamID, "forward-ok")
			resp.Id = r.Id
			return resp
		}

		if route.provider != nil {
			resp, err := exchangePlainVia(route.provider, r, netType, upstream)
			// Truncation is answered the same way as on the device path: retry
			// over TCP rather than handing the client a clipped answer.
			if netType == "udp" && (err != nil || (resp != nil && resp.Truncated)) {
				resp, err = exchangePlainVia(route.provider, r, "tcp", upstream)
			}
			if err != nil || resp == nil {
				if err != nil {
					log.Printf("multiproxy DNS: %v", err)
				}
				e.obs.dp.addDNSForwardFailure()
				e.statsFor(route.provider.ID()).recordDNSFailed()
				logDNS(string(route.provider.ID()), "forward-fail")
				m.Rcode = dns.RcodeServerFailure
				return m
			}
			e.statsFor(route.provider.ID()).recordDNSForwarded()
			logDNS(string(route.provider.ID()), "forward-ok")
			resp.Id = r.Id
			return resp
		}

		c := new(dns.Client)
		c.Net = netType
		c.Dialer = plainDNSDialer
		resp, _, err := c.Exchange(r, upstream)
		if netType == "udp" && (err != nil || (resp != nil && resp.Truncated)) {
			c.Net = "tcp"
			resp, _, err = c.Exchange(r, upstream)
		}
		if err == nil && resp != nil {
			logDNS("", "device-ok")
			resp.Id = r.Id
			return resp
		}

		logDNS("", "device-fail")
		m.Rcode = dns.RcodeServerFailure
		return m
	}

	logDNS("", "synthetic")
	m.Authoritative = true
	return m
}
