package multiproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/tsnet"
)

// testClientAddr is an arbitrary IPv6 address standing in for the device's
// own address, as seen from inside the VPN stack. It is never registered on
// the NIC - only local (destination) addresses need registration now that
// spoofing is disabled, and this address is always the remote/source side.
const testClientAddr = "fd9b:8d7c:6a5e::c11e:1"

// newPacketTestEngine wires an Engine to an in-memory channel.Endpoint using
// exactly the stack-construction path (bindVPNStackLocked) that StartVPN
// uses for the production fdbased endpoint. That's the point of splitting
// stack construction from FD creation: these tests exercise the real
// forwarder wiring, promiscuous mode, and permanent DNS address
// registration without touching a TUN fd at all.
func newPacketTestEngine(t *testing.T) (*Engine, *channel.Endpoint) {
	t.Helper()
	e := NewEngine(t.TempDir(), &MockCallback{})
	ep := channel.New(256, 1500, "")

	e.vpnMu.Lock()
	err := e.bindVPNStackLocked(ep)
	e.vpnMu.Unlock()
	if err != nil {
		t.Fatalf("bindVPNStackLocked: %v", err)
	}
	t.Cleanup(e.StopVPN)
	return e, ep
}

func buildUDPv6Packet(t *testing.T, srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, payload []byte) []byte {
	t.Helper()
	src := tcpip.AddrFromSlice(netip.MustParseAddr(srcAddr).AsSlice())
	dst := tcpip.AddrFromSlice(netip.MustParseAddr(dstAddr).AsSlice())

	udpLen := header.UDPMinimumSize + len(payload)
	buf := make([]byte, header.IPv6MinimumSize+udpLen)

	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})

	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(u.Payload(), payload)

	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(0)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	return buf
}

func injectUDPv6DNSQuery(t *testing.T, ep *channel.Endpoint, qname string, qtype uint16, srcPort uint16) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = true
	payload, err := m.Pack()
	if err != nil {
		t.Fatalf("pack dns query: %v", err)
	}
	raw := buildUDPv6Packet(t, testClientAddr, srcPort, SyntheticIPv6DNS.String(), 53, payload)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	defer pkt.DecRef()
	ep.InjectInbound(ipv6.ProtocolNumber, pkt)
}

// readUDPv6DNSResponse blocks (bounded by ctx) for the next outbound packet
// on ep and parses it as an IPv6/UDP/DNS response, also returning the
// packet's source address and source port so callers can assert on them.
func readUDPv6DNSResponse(t *testing.T, ctx context.Context, ep *channel.Endpoint) (msg *dns.Msg, srcAddr netip.Addr, srcPort uint16) {
	t.Helper()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		t.Fatalf("timed out waiting for outbound packet")
	}
	defer pkt.DecRef()

	buf := pkt.ToBuffer()
	raw := buf.Flatten()
	if len(raw) < header.IPv6MinimumSize+header.UDPMinimumSize {
		t.Fatalf("outbound packet too short: %d bytes", len(raw))
	}
	ip := header.IPv6(raw)
	udp := header.UDP(raw[header.IPv6MinimumSize:])

	srcAddr = netip.AddrFrom16(ip.SourceAddress().As16())
	srcPort = udp.SourcePort()

	msg = new(dns.Msg)
	if err := msg.Unpack(udp.Payload()); err != nil {
		t.Fatalf("unpack dns response: %v", err)
	}
	return msg, srcAddr, srcPort
}

func mustAddTarget(t *testing.T, e *Engine, uid UpstreamID, hostname string, id string) TargetRecord {
	t.Helper()
	rec := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, id},
		Hostname:         hostname,
		RequiredUpstream: uid,
		CurrentIPv4:      netip.MustParseAddr("100.64.0.1"),
	}
	rec.SyntheticIPv6 = rec.Key.SyntheticIPv6()
	e.updateTailnetSnapshot(uid, append(existingSnapshot(e, uid), rec))
	return rec
}

func existingSnapshot(e *Engine, uid UpstreamID) []TargetRecord {
	e.targetMutex.RLock()
	defer e.targetMutex.RUnlock()
	return append([]TargetRecord(nil), e.tailnetSnapshots[uid]...)
}

// TestDNSPacketLevelAAAAResponse covers a AAAA response for a known,
// fully-qualified MagicDNS name.
func TestDNSPacketLevelAAAAResponse(t *testing.T) {
	e, ep := newPacketTestEngine(t)
	uid := UpstreamID("tn")
	rec := mustAddTarget(t, e, uid, "box.", "A")

	injectUDPv6DNSQuery(t, ep, "box.", dns.TypeAAAA, 40001)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, srcAddr, srcPort := readUDPv6DNSResponse(t, ctx, ep)

	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("expected 1 AAAA answer, got rcode=%d answers=%d", msg.Rcode, len(msg.Answer))
	}
	aaaa, ok := msg.Answer[0].(*dns.AAAA)
	if !ok || netip.MustParseAddr(aaaa.AAAA.String()) != rec.SyntheticIPv6 {
		t.Fatalf("unexpected AAAA answer: %+v", msg.Answer[0])
	}
	if srcAddr != SyntheticIPv6DNS {
		t.Fatalf("response source address = %s, want %s", srcAddr, SyntheticIPv6DNS)
	}
	if srcPort != 53 {
		t.Fatalf("response source port = %d, want 53", srcPort)
	}
}

// TestDNSPacketLevelASyntheticAddress covers an A response for a tailnet name.
// v4-only clients depend on this: the resolver used to answer NODATA here, so
// such a peer was unreachable to them even though it resolved over v6.
func TestDNSPacketLevelASyntheticAddress(t *testing.T) {
	e, ep := newPacketTestEngine(t)
	uid := UpstreamID("tn")
	mustAddTarget(t, e, uid, "onlyv6.", "A")

	injectUDPv6DNSQuery(t, ep, "onlyv6.", dns.TypeA, 40002)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, _, _ := readUDPv6DNSResponse(t, ctx, ep)

	if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
		t.Fatalf("expected one A answer, got rcode=%d answers=%d", msg.Rcode, len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected an A record, got %T", msg.Answer[0])
	}
	addr, ok := netip.AddrFromSlice(a.A.To4())
	if !ok || !SyntheticIPv4Prefix.Contains(addr) {
		t.Fatalf("A answer %v is not in the synthetic v4 pool %v", a.A, SyntheticIPv4Prefix)
	}
	if SyntheticIPv4ControlPrefix.Contains(addr) {
		t.Fatalf("A answer %v is inside the reserved control block", addr)
	}
}

// TestDNSPacketLevelUnknownNameForwards covers forwarding a query for a name
// we have no record of to the configured upstream DNS resolver.
func TestDNSPacketLevelUnknownNameForwards(t *testing.T) {
	upstreamAddr, cleanup := startFakeUpstreamDNS(t, func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		if q.Name == "example.com." && q.Qtype == dns.TypeA {
			rr, _ := dns.NewRR("example.com. A 93.184.216.34")
			m.Answer = append(m.Answer, rr)
		}
		return m
	})
	defer cleanup()

	e, ep := newPacketTestEngine(t)
	e.SetUpstreamDNS(upstreamAddr)

	injectUDPv6DNSQuery(t, ep, "example.com.", dns.TypeA, 40003)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, _, _ := readUDPv6DNSResponse(t, ctx, ep)

	if len(msg.Answer) != 1 {
		t.Fatalf("expected forwarded answer, got %d answers (rcode=%d)", len(msg.Answer), msg.Rcode)
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected forwarded answer: %+v", msg.Answer[0])
	}
}

// TestDNSPacketLevelUnknownNameForwardsViaDoH covers forwarding a query for
// an unknown name to a DNS-over-HTTPS upstream (e.g. a user-selected public
// DoH provider), rather than a plain host:port resolver.
func TestDNSPacketLevelUnknownNameForwardsViaDoH(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "unexpected content-type", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR("example.com. A 93.184.216.34")
			m.Answer = append(m.Answer, rr)
		}
		out, err := m.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	}))
	defer srv.Close()

	// httptest's TLS server uses a self-signed cert; swap in a client that
	// trusts it for the duration of this test rather than the real DoH
	// client's default transport.
	origClient := dohHTTPClient
	dohHTTPClient = srv.Client()
	dohHTTPClient.Timeout = dohTimeout
	t.Cleanup(func() { dohHTTPClient = origClient })

	e, ep := newPacketTestEngine(t)
	e.SetUpstreamDNS(srv.URL + "/dns-query")

	injectUDPv6DNSQuery(t, ep, "example.com.", dns.TypeA, 40010)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, _, _ := readUDPv6DNSResponse(t, ctx, ep)

	if len(msg.Answer) != 1 {
		t.Fatalf("expected forwarded DoH answer, got %d answers (rcode=%d)", len(msg.Answer), msg.Rcode)
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("unexpected forwarded DoH answer: %+v", msg.Answer[0])
	}
}

// TestDNSPacketLevelAmbiguousShortName covers two different tailnets
// exposing the same short (unqualified) hostname: the short name must fail
// closed (NXDOMAIN) rather than pick one arbitrarily.
func TestDNSPacketLevelAmbiguousShortName(t *testing.T) {
	e, ep := newPacketTestEngine(t)
	mustAddTarget(t, e, "tn1", "shared.", "A")
	mustAddTarget(t, e, "tn2", "shared.", "B")

	injectUDPv6DNSQuery(t, ep, "shared.", dns.TypeAAAA, 40004)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, _, _ := readUDPv6DNSResponse(t, ctx, ep)

	if msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for ambiguous short name, got rcode=%d", msg.Rcode)
	}
}

// TestDNSPacketLevelRepeatedQueriesSameAssociation sends several queries
// from the same source port (the same gVisor UDP forwarder association) and
// confirms each gets an independent, correct response - the association
// isn't single-shot.
func TestDNSPacketLevelRepeatedQueriesSameAssociation(t *testing.T) {
	e, ep := newPacketTestEngine(t)
	mustAddTarget(t, e, "tn", "repeat.", "A")

	for i := 0; i < 5; i++ {
		injectUDPv6DNSQuery(t, ep, "repeat.", dns.TypeAAAA, 40005)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		msg, srcAddr, srcPort := readUDPv6DNSResponse(t, ctx, ep)
		cancel()
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 {
			t.Fatalf("query %d: expected 1 answer, got rcode=%d answers=%d", i, msg.Rcode, len(msg.Answer))
		}
		if srcAddr != SyntheticIPv6DNS || srcPort != 53 {
			t.Fatalf("query %d: unexpected response source %s:%d", i, srcAddr, srcPort)
		}
	}
}

// TestDNSPacketLevelSyntheticCollision covers two records that hash to the
// same synthetic address: the collision must fail closed at the DNS layer
// too (SERVFAIL, since the address itself becomes unroutable) rather than
// silently resolving to whichever record won the race.
func TestDNSPacketLevelSyntheticCollision(t *testing.T) {
	e, ep := newPacketTestEngine(t)
	uid := UpstreamID("tn")

	recA := TargetRecord{Key: TargetKey{uid, TargetKindTailscaleNode, "A"}, Hostname: "collide.", RequiredUpstream: uid}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()
	recB := TargetRecord{Key: TargetKey{uid, TargetKindTailscaleNode, "B"}, Hostname: "other.", RequiredUpstream: uid}
	recB.SyntheticIPv6 = recA.SyntheticIPv6 // forced collision

	e.updateTailnetSnapshot(uid, []TargetRecord{recA, recB})

	injectUDPv6DNSQuery(t, ep, "collide.", dns.TypeAAAA, 40006)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, _, _ := readUDPv6DNSResponse(t, ctx, ep)

	if msg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL for colliding synthetic address with no upstream configured, got rcode=%d answers=%d", msg.Rcode, len(msg.Answer))
	}
}

// TestVPNShutdownWithActiveFlowsNoLeak simulates TCP- and UDP-style flows
// that are mid-registration when StopVPN is called: it verifies dynamic
// address registration is torn down cleanly with no panics and no leaked
// refcounts, matching what handleTCPConnection/handleUDPConnection do
// around every real flow. (A full wire-level TCP handshake needs a live
// upstream to answer it, which isn't available in a hermetic host test;
// that path is covered by the emulator acceptance pass instead.)
func TestVPNShutdownWithActiveFlowsNoLeak(t *testing.T) {
	e, _ := newPacketTestEngine(t)

	tcpAddr := netip.MustParseAddr("fd9b:8d7c:6a5e::1234")
	udpAddr := netip.MustParseAddr("fd9b:8d7c:6a5e::5678")

	if err := e.acquireDynamicAddr(tcpAddr); err != nil {
		t.Fatalf("acquireDynamicAddr(tcp): %v", err)
	}
	if err := e.acquireDynamicAddr(udpAddr); err != nil {
		t.Fatalf("acquireDynamicAddr(udp): %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		e.StopVPN()
	}()
	go func() {
		defer wg.Done()
		e.releaseDynamicAddr(tcpAddr)
		e.releaseDynamicAddr(udpAddr)
	}()
	wg.Wait()

	e.vpnMu.Lock()
	stackNil := e.vpnStack == nil
	refCountNil := e.addrRefCount == nil
	e.vpnMu.Unlock()
	if !stackNil {
		t.Fatalf("vpnStack not cleared after StopVPN")
	}
	if !refCountNil {
		t.Fatalf("addrRefCount not cleared after StopVPN")
	}

	// A second StopVPN and a release after shutdown must both be no-ops.
	e.StopVPN()
	e.releaseDynamicAddr(tcpAddr)
}

// TestConcurrentDispatchToDistinctUpstreams is a fake-upstream routing test:
// two synthetic destinations backed by two different tailnets must resolve,
// concurrently, to distinct RouteDecision.UpstreamID/Upstream values - one
// destination's traffic must never bleed into the other's upstream runtime.
// This drives the router (resolveRoute) directly rather than through a full
// TCP dial, since exercising real dials needs a live tsnet control-plane
// connection unavailable in a hermetic host test.
func TestConcurrentDispatchToDistinctUpstreams(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	uidA := UpstreamID("upstream-a")
	uidB := UpstreamID("upstream-b")

	e.mu.Lock()
	e.tailnets[uidA] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	e.tailnets[uidB] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	e.mu.Unlock()

	recA := mustAddTarget(t, e, uidA, "hostA.", "A")
	recB := mustAddTarget(t, e, uidB, "hostB.", "B")

	var wg sync.WaitGroup
	errs := make(chan string, 200)
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d, ok := e.resolveRoute(recA.SyntheticIPv6)
			if !ok || d.UpstreamID != uidA {
				errs <- "destination A dispatched to wrong upstream"
			}
		}()
		go func() {
			defer wg.Done()
			d, ok := e.resolveRoute(recB.SyntheticIPv6)
			if !ok || d.UpstreamID != uidB {
				errs <- "destination B dispatched to wrong upstream"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}

// startFakeUpstreamDNS starts a loopback UDP DNS server for
// TestDNSPacketLevelUnknownNameForwards and returns its host:port and a
// cleanup func.
func startFakeUpstreamDNS(t *testing.T, answer func(dns.Question) *dns.Msg) (addr string, cleanup func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen fake upstream dns: %v", err)
	}

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, raddr, err := conn.ReadFromUDP(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := answer(req.Question[0])
			resp.SetReply(req)
			out, err := resp.Pack()
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDP(out, raddr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		close(done)
		conn.Close()
	}
}
