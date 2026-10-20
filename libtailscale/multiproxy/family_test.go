// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func TestWireGuardCarriedFamilies(t *testing.T) {
	v4addr := netip.MustParseAddr("10.77.0.2")
	v6addr := netip.MustParseAddr("fd00::2")
	all4 := netip.MustParsePrefix("0.0.0.0/0")
	all6 := netip.MustParsePrefix("::/0")

	tests := []struct {
		name           string
		addrs          []netip.Addr
		allowed        []netip.Prefix
		wantV4, wantV6 bool
	}{
		{"v4 address, dual-stack routes (the reported config)", []netip.Addr{v4addr}, []netip.Prefix{all4, all6}, true, false},
		{"v4 address, v4 route", []netip.Addr{v4addr}, []netip.Prefix{all4}, true, false},
		{"dual-stack address and routes", []netip.Addr{v4addr, v6addr}, []netip.Prefix{all4, all6}, true, true},
		{"dual-stack address, v4 route only", []netip.Addr{v4addr, v6addr}, []netip.Prefix{all4}, true, false},
		{"v6 only", []netip.Addr{v6addr}, []netip.Prefix{all6}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := WireGuardConfig{Addresses: tc.addrs, Peers: []WireGuardPeer{{AllowedIPs: tc.allowed}}}
			v4, v6 := cfg.carriedFamilies()
			if v4 != tc.wantV4 || v6 != tc.wantV6 {
				t.Fatalf("carriedFamilies() = %v, %v; want %v, %v", v4, v6, tc.wantV4, tc.wantV6)
			}
		})
	}
}

// newIdleWireGuard builds a tunnel whose peer never answers. Enough for
// anything decided before a packet is sent.
func newIdleWireGuard(t *testing.T, cfg WireGuardConfig) *wireguardProvider {
	t.Helper()
	priv, _ := wgKeypair(t)
	_, peerPub := wgKeypair(t)
	cfg.PrivateKey = priv
	for i := range cfg.Peers {
		cfg.Peers[i].PublicKey = peerPub
		cfg.Peers[i].Endpoint = net.JoinHostPort("127.0.0.1", strconv.Itoa(freeUDPPort(t)))
	}
	p, err := NewWireGuardUpstream(cfg, newRealBind(), testLogf(t, "idle"))
	if err != nil {
		t.Fatalf("NewWireGuardUpstream: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p.(*wireguardProvider)
}

// The reported failure: a v4-only tunnel handed an IPv6 destination must fail
// immediately with the non-retryable family error, not a generic one.
func TestWireGuardV4OnlyRefusesIPv6Dial(t *testing.T) {
	p := newIdleWireGuard(t, WireGuardConfig{
		ID:        "wg",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.0.2")},
		Peers: []WireGuardPeer{{AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		}}},
	})
	if p.CarriesFamily(true) || !p.CarriesFamily(false) {
		t.Fatalf("CarriesFamily(v6)=%v CarriesFamily(v4)=%v, want false/true", p.CarriesFamily(true), p.CarriesFamily(false))
	}

	start := time.Now()
	_, err := p.Dial(context.Background(), "tcp", "[2600:9000:26a1:3200:16:97f7:5900:93a1]:443")
	if !errors.Is(err, ErrNoUsableNetworkForFamily) {
		t.Fatalf("Dial(IPv6) error = %v, want ErrNoUsableNetworkForFamily", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Dial(IPv6) took %v, want an immediate failure", d)
	}
}

func TestWireGuardHostnameWithoutDNSFailsClearly(t *testing.T) {
	p := newIdleWireGuard(t, WireGuardConfig{
		ID:        "wg",
		Addresses: []netip.Addr{netip.MustParseAddr("10.77.0.2")},
		Peers:     []WireGuardPeer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}},
	})
	if p.ResolvesHostnames() {
		t.Fatal("a tunnel with no DNS servers claims to resolve hostnames")
	}
	if _, err := p.Dial(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("hostname dial without tunnel DNS succeeded")
	}
}

// familyProvider is a fake upstream with fixed family support.
type familyProvider struct {
	dialProvider
	v4, v6 bool
}

func (p *familyProvider) CarriesFamily(ipv6 bool) bool {
	if ipv6 {
		return p.v6
	}
	return p.v4
}

func TestRejectUncarriableFamily(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	v4only := &familyProvider{dialProvider: dialProvider{id: "wg4", dials: make(chan string, 1)}, v4: true}
	dual := &dialProvider{id: "socks", dials: make(chan string, 1)}
	for _, p := range []Provider{v4only, dual} {
		if err := e.RegisterUpstream(p); err != nil {
			t.Fatal(err)
		}
	}
	ready := func(id UpstreamID) Upstream {
		p, ok := e.readyProvider(id)
		if !ok {
			t.Fatalf("%s not ready", id)
		}
		return p
	}

	v6 := netip.MustParseAddr("2606:4700:10::6814:179a")
	v4 := netip.MustParseAddr("104.20.23.154")
	unusable := func() bool { return false }

	tests := []struct {
		name     string
		decision RouteDecision
		target   netip.Addr
		direct6  *func() bool
		want     bool
	}{
		{"IPv6 via v4-only tunnel (through the stats wrapper)", RouteDecision{Upstream: ready("wg4"), UpstreamID: "wg4", Destination: v6.String()}, v6, nil, true},
		{"IPv4 via v4-only tunnel", RouteDecision{Upstream: ready("wg4"), UpstreamID: "wg4", Destination: v4.String()}, v4, nil, false},
		{"IPv6 via provider that does not report families", RouteDecision{Upstream: ready("socks"), UpstreamID: "socks", Destination: v6.String()}, v6, nil, false},
		{"synthetic IPv6 target whose native locator is IPv4", RouteDecision{Upstream: ready("wg4"), UpstreamID: "wg4", Destination: v4.String()}, v6, nil, false},
		{"direct IPv6 on a network without IPv6 still rejected", RouteDecision{UpstreamID: DirectUpstreamID, Destination: v6.String()}, v6, &unusable, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejectUncarriableFamily(tc.decision, tc.target, tc.direct6); got != tc.want {
				t.Fatalf("rejectUncarriableFamily() = %v, want %v", got, tc.want)
			}
		})
	}
}

// An app routed through a v4-only tunnel must get NODATA for AAAA, without the
// query being forwarded at all, while its A queries are forwarded normally.
func TestAAAASuppressedForAppOnV4OnlyRoute(t *testing.T) {
	viaUpstream := startTestDNS(t, "203.0.113.1")

	e := NewEngine(t.TempDir(), &MockCallback{})
	provider := &familyProvider{dialProvider: dialProvider{id: "wg4", dials: make(chan string, 4)}, v4: true}
	if err := e.RegisterUpstream(provider); err != nil {
		t.Fatal(err)
	}
	e.SetUpstreamDNS(viaUpstream.Addr())
	if err := e.SetPolicy(Policy{Rules: []Rule{
		appRule("routed", []int32{1000}, ActionRoute, "wg4"),
	}}); err != nil {
		t.Fatal(err)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.geeksforgeeks.org.", dns.TypeAAAA)
	resp := e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 1000})
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("AAAA response = %v, want NOERROR with no answers", resp)
	}
	select {
	case got := <-provider.dials:
		t.Fatalf("suppressed AAAA query was still forwarded (%s)", got)
	default:
	}
	if got := e.obs.dp.dnsAAAASuppressed.Load(); got != 1 {
		t.Fatalf("dnsAAAASuppressed = %d, want 1", got)
	}

	req = new(dns.Msg)
	req.SetQuestion("www.geeksforgeeks.org.", dns.TypeA)
	resp = e.handleDNSMsg(req, "udp", FlowInfo{Protocol: "udp", AppUID: 1000})
	if resp == nil || len(resp.Answer) != 1 {
		t.Fatalf("A response = %v, want the forwarded answer", resp)
	}

	// An app on a route that can carry IPv6 is unaffected.
	if !e.appRouteCarriesIPv6(2000) {
		t.Fatal("an app with no rule had its AAAA answers suppressed")
	}
}

// countingLiteralProvider is literalOnlyProvider that also reports, as a real
// DNS-less WireGuard tunnel does, that it cannot resolve hostnames - and counts
// any hostname dial it receives anyway.
type countingLiteralProvider struct {
	literalOnlyProvider
	hostnameDials int
}

func (p *countingLiteralProvider) ResolvesHostnames() bool { return false }

func (p *countingLiteralProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(address)
	if _, err := netip.ParseAddr(host); err != nil {
		p.hostnameDials++
	}
	return p.literalOnlyProvider.Dial(ctx, network, address)
}

// The flood of "must be a literal address:port" errors on the Upstreams
// screen: every DoH connection through a DNS-less tunnel first tried the
// hostname, failed (recorded as an upstream failure), then bootstrapped.
func TestDoHDialDoesNotAttemptHostnameOnLiteralOnlyUpstream(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	const dohBase = "https://security.cloudflare-dns.com/dns-query"
	setBootstrapDoHBase(dohBase)
	defer setBootstrapDoHBase("")

	fp := &countingLiteralProvider{literalOnlyProvider: literalOnlyProvider{id: "wg"}}
	if err := e.RegisterUpstream(fp); err != nil {
		t.Fatal(err)
	}
	transport, ok := e.dohClientFor("wg").Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected the DoH client to use an *http.Transport")
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "security.cloudflare-dns.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
	if fp.hostnameDials != 0 {
		t.Fatalf("upstream received %d hostname dials, want 0", fp.hostnameDials)
	}
	if got := e.statsFor("wg").dialFailures.Load(); got != 0 {
		t.Fatalf("upstream recorded %d dial failures, want 0", got)
	}
}

// A hostname destination - a socks5h client of the inbound listener, or a DoH
// resolver URL - is resolved through the tunnel's own DNS server, inside the
// tunnel, and then dialed.
func TestWireGuardResolvesHostnameInsideTunnel(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two WireGuard devices")
	}

	clientPriv, clientPub := wgKeypair(t)
	serverPriv, serverPub := wgKeypair(t)
	const (
		clientIP = "10.9.0.2"
		serverIP = "10.9.0.1"
		echoPort = 8080
	)
	serverPort := freeUDPPort(t)

	server := newLearningResponder(t, WireGuardConfig{
		ID:         "wg-server",
		PrivateKey: serverPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(serverIP)},
		MTU:        1420,
		ListenPort: uint16(serverPort),
		Peers: []WireGuardPeer{{
			PublicKey:  clientPub,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(clientIP + "/32")},
		}},
	}, clientPub)
	listenInTunnel(t, server, netip.MustParseAddr(serverIP), echoPort)
	serveDNSInTunnel(t, server, netip.MustParseAddr(serverIP), map[string]string{"echo.tunnel.test.": serverIP})

	client, err := NewWireGuardUpstream(WireGuardConfig{
		ID:         "wg-client",
		PrivateKey: clientPriv,
		Addresses:  []netip.Addr{netip.MustParseAddr(clientIP)},
		DNS:        []netip.Addr{netip.MustParseAddr(serverIP)},
		MTU:        1420,
		Peers: []WireGuardPeer{{
			PublicKey:           serverPub,
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
			AllowedIPs:          []netip.Prefix{netip.MustParsePrefix(serverIP + "/32")},
			PersistentKeepalive: 1,
		}},
	}, newRealBind(), testLogf(t, "client"))
	if err != nil {
		t.Fatalf("client upstream: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	echoThroughTunnel(t, ctx, client, net.JoinHostPort("echo.tunnel.test", strconv.Itoa(echoPort)), "resolved in the tunnel")
}

// serveDNSInTunnel answers A queries for names on a provider's tunnel-side
// netstack.
func serveDNSInTunnel(t *testing.T, p Provider, addr netip.Addr, records map[string]string) {
	t.Helper()
	pc, err := gonet.DialUDP(p.(*wireguardProvider).stack, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
		Port: 53,
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen DNS inside tunnel: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil || len(req.Question) != 1 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			if ip, ok := records[q.Name]; ok && q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip).To4(),
				})
			}
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()
}
