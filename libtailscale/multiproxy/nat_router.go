// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/tsnet"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// udpAssociationIdleTimeout bounds how long a UDP association may sit with no
// traffic in either direction before it is torn down. It is refreshed on every
// packet (see runUDPAssociation), so it measures idleness, not total lifetime.
//
// RFC 4787 REQ-5 requires a NAT's UDP mapping timer to be at least 2 minutes and
// recommends 5. Re-originating flows from a tsnet upstream makes this a NAT, so
// the same floor applies. The previous 60s sat below it and expired bindings
// that protocols legitimately leave idle for longer - notably SIP between
// registration refreshes, where the binding an inbound INVITE would arrive on
// could be torn down between calls.
const udpAssociationIdleTimeout = 5 * time.Minute

const (
	tcpDialMaxAttempts = 3
	tcpDialRetryDelay  = 300 * time.Millisecond
)

func (e *Engine) activeTailnetServer(id UpstreamID) (*tsnet.Server, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rt, exists := e.tailnets[id]
	if exists && rt.Enabled && rt.Srv != nil {
		return rt.Srv, true
	}
	return nil, false
}

// resolveRoute resolves a destination with no flow context. Equivalent to
// resolveFlow for an unattributed flow, so UID-scoped rules cannot match.
func (e *Engine) resolveRoute(targetIP netip.Addr) (RouteDecision, bool) {
	return e.resolveFlow(FlowInfo{
		Dst:    netip.AddrPortFrom(targetIP, 0),
		AppUID: UnknownAppUID,
	})
}

// resolveFlow decides where a flow goes.
//
// The order is deliberate:
//
//  1. A synthetic destination is identity-bound - the address itself encodes
//     which upstream minted it - so no rule may re-point it somewhere the
//     address is meaningless. Policy is still consulted, but only to block.
//  2. Everything else (a peer's real Tailscale address, a LAN address, the
//     public internet) is policy's to decide.
//  3. With no matching rule, the pre-policy behaviour applies unchanged:
//     real-IP resolution, then advertised subnet routes, then the exit-node
//     tailnet. An empty policy therefore routes exactly as it did before the
//     policy layer existed.
func (e *Engine) resolveFlow(f FlowInfo) (RouteDecision, bool) {
	targetIP := f.Dst.Addr().Unmap()
	if !targetIP.IsValid() {
		return RouteDecision{}, false
	}

	e.targetMutex.RLock()
	rec, found := e.targets[targetIP]
	if !found {
		rec, found = e.syntheticV4[targetIP]
	}
	e.targetMutex.RUnlock()

	if found {
		// A block rule still applies: refusing to send traffic is always a
		// safe thing to honour, even for an identity-bound destination.
		if rule, _, ok := e.matchPolicy(f); ok && rule.Action == ActionBlock {
			return RouteDecision{}, false
		}

		destIP := rec.CurrentIPv6
		if rec.CurrentIPv4.IsValid() {
			destIP = rec.CurrentIPv4
		}
		if !destIP.IsValid() {
			return RouteDecision{}, false
		}

		if p, ready := e.readyProvider(rec.RequiredUpstream); ready {
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  rec.RequiredUpstream,
				Destination: destIP.String(),
			}, true
		}
		return RouteDecision{}, false
	}

	if SyntheticIPv6Prefix.Contains(targetIP) || SyntheticIPv4Prefix.Contains(targetIP) {
		// Inside synthetic namespace but no exact target -> fail closed.
		// A synthetic address that no longer maps to a peer is stale (the
		// peer left, or the netmap moved on); falling through to the
		// real-IP or subnet logic below would route it somewhere unrelated.
		return RouteDecision{}, false
	}

	// Not a synthetic address at all: this is a peer's real Tailscale IP,
	// handed to some app directly rather than resolved through our synthetic
	// DNS (e.g. a TURN/STUN server config, which is almost always a literal
	// IP:port). Real Tailscale address space is drawn from the same pool for
	// every tailnet, so the same IP can genuinely belong to different peers
	// on different simultaneously-active upstreams - that ambiguity can't be
	// resolved from the address alone. Rather than failing closed here (the
	// old behavior), pick the candidate deterministically and tell the user
	// it happened, so a real-IP destination that used to be silently
	// unreachable at least has a chance of working, with the tradeoff
	// visible instead of hidden.

	// Policy first for everything outside the synthetic namespace. This is where
	// per-app binding, a selected exit upstream for ordinary internet traffic,
	// and firewall rules all take effect. A matching rule is final - it does not
	// fall through to the legacy chain below - so a rule naming an upstream that
	// is down fails closed rather than quietly using a different one.
	if decision, matched, ok := e.applyPolicy(f, targetIP); matched {
		return decision, ok
	}

	if decision, ok := e.resolveRealIPRoute(targetIP); ok {
		return decision, true
	}

	e.mu.RLock()
	var longestMatch subnetRoute
	var maxBits int = -1

	for _, sr := range e.subnets {
		if sr.Prefix.Contains(targetIP) {
			if sr.Prefix.Bits() > maxBits {
				maxBits = sr.Prefix.Bits()
				longestMatch = sr
			}
		}
	}
	exitNode := e.exitNodeTailnet
	e.mu.RUnlock()

	if maxBits >= 0 {
		uid := UpstreamID(longestMatch.TailnetID)
		if p, ready := e.readyProvider(uid); ready {
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true
		}
		return RouteDecision{}, false
	}

	if exitNode != "" {
		uid := UpstreamID(exitNode)
		if p, ready := e.readyProvider(uid); ready {
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true
		}
	}

	return RouteDecision{}, false
}

// matchPolicy evaluates the active policy against a flow.
func (e *Engine) matchPolicy(f FlowInfo) (Rule, int, bool) {
	if e.policy == nil {
		return Rule{}, -1, false
	}
	return e.policy.Match(f)
}

// applyPolicy evaluates the policy and, when a rule matches, turns it into a
// decision.
//
// The second return value says whether a rule matched at all; the third says
// whether that produced a usable route. The two are distinct on purpose: a
// matched rule is always final, so "matched but not routable" must deny rather
// than fall through to the legacy chain and reach an upstream the rule did not
// name.
func (e *Engine) applyPolicy(f FlowInfo, targetIP netip.Addr) (RouteDecision, bool, bool) {
	rule, _, ok := e.matchPolicy(f)
	if !ok {
		return RouteDecision{}, false, false
	}

	switch rule.Action {
	case ActionBlock:
		return RouteDecision{}, true, false

	case ActionDirect:
		p, ready := e.readyProvider(DirectUpstreamID)
		if !ready {
			return RouteDecision{}, true, false
		}
		return RouteDecision{
			Upstream:    p,
			UpstreamID:  DirectUpstreamID,
			Destination: targetIP.String(),
		}, true, true

	case ActionRoute:
		p, ready := e.readyProvider(rule.Upstream)
		if !ready {
			return RouteDecision{}, true, false
		}
		// Note this also disambiguates a real Tailscale address that several
		// tailnets claim: the rule names which upstream to use, so
		// resolveRealIPRoute's deterministic guess is never reached.
		return RouteDecision{
			Upstream:    p,
			UpstreamID:  rule.Upstream,
			Destination: targetIP.String(),
		}, true, true
	}

	return RouteDecision{}, true, false
}

// resolveRealIPRoute looks up targetIP (a real, non-synthetic Tailscale IP)
// in the cross-upstream real-IP index. If it belongs to exactly one active
// upstream, that's an unambiguous route. If it belongs to more than one, the
// choice is made deterministically (lowest UpstreamID, so repeated lookups
// for the same address are stable across the life of the process) and a
// crossover event is emitted so the user can see the ambiguity happened
// instead of it being silently guessed at.
func (e *Engine) resolveRealIPRoute(targetIP netip.Addr) (RouteDecision, bool) {
	candidates := e.realIPCandidates(targetIP)
	if len(candidates) == 0 {
		return RouteDecision{}, false
	}

	chosen, ok := e.chooseRealIPCandidate(candidates)
	if !ok {
		return RouteDecision{}, false
	}

	if len(candidates) > 1 {
		ids := make([]UpstreamID, len(candidates))
		for i, c := range candidates {
			ids[i] = c.RequiredUpstream
		}
		e.enqueueAddressCrossover(targetIP.String(), ids, chosen.RequiredUpstream)
	}

	p, ready := e.readyProvider(chosen.RequiredUpstream)
	if !ready {
		return RouteDecision{}, false
	}
	return RouteDecision{
		Upstream:    p,
		UpstreamID:  chosen.RequiredUpstream,
		Destination: targetIP.String(),
	}, true
}

func (e *Engine) handleTCPConnection(r *tcp.ForwarderRequest) {
	defer recoverAndLog("handleTCPConnection")
	flowID := atomic.AddUint64(&e.flowCounter, 1)

	// r.ID() dereferences gVisor's internal segment, which r.Complete() nils
	// out with no nil check on the read side (see forwarder.go's
	// ForwarderRequest.ID/Complete) - capture everything we need from it
	// once, up front, before any Complete() call, rather than calling it
	// again afterward.
	id := r.ID()
	targetIPStr := id.LocalAddress.String()
	targetIP, err := netip.ParseAddr(targetIPStr)
	if err != nil {
		r.Complete(true)
		return
	}
	targetPort := id.LocalPort
	remoteAddr := id.RemoteAddress
	isDNS := isSyntheticDNSAddr(targetIPStr) && targetPort == 53

	var decision RouteDecision
	var flow FlowInfo
	if !isDNS {
		var ok bool
		flow = e.flowFromEndpointID("tcp", id)
		decision, ok = e.resolveFlow(flow)
		if !ok {
			log.Printf("[flow-%d] TCP %v -> %v (synthetic): reject (no route)", flowID, remoteAddr, targetIP)
			r.Complete(true)
			return
		}
		// The synthetic DNS address is permanently registered; every other
		// destination address must be registered before we let gVisor
		// complete the handshake, since it needs the address assigned to
		// the NIC to send the SYN-ACK (spoofing is disabled).
		if err := e.acquireDynamicAddr(targetIP); err != nil {
			log.Printf("[flow-%d] TCP %v -> %v: reject (%v)", flowID, remoteAddr, targetIP, err)
			r.Complete(true)
			return
		}
	}

	wq := new(waiter.Queue)
	ep, tcpErr := r.CreateEndpoint(wq)
	if tcpErr != nil {
		r.Complete(true)
		if !isDNS {
			e.releaseDynamicAddr(targetIP)
		}
		return
	}
	r.Complete(false)

	if isDNS {
		gvisorConn := gonet.NewTCPConn(wq, ep)
		// The flow is attributed here so a forwarded query can follow the asking
		// app's own route rather than always leaving from the device.
		go e.ServeDNSTCP(gvisorConn, e.flowFromEndpointID("tcp", id))
		return
	}

	log.Printf("[flow-%d] TCP %v -> %v (synthetic): dial %s (real=%s)", flowID, remoteAddr, targetIP, decision.UpstreamID, decision.Destination)

	dialAddr := fmt.Sprintf("%s:%d", decision.Destination, targetPort)
	if net.ParseIP(decision.Destination).To4() == nil {
		dialAddr = fmt.Sprintf("[%s]:%d", decision.Destination, targetPort)
	}

	e.capture.registerFlow("tcp", flow.Src, flow.Dst, flow.AppUID)

	go func() {
		defer recoverAndLog("handleTCPConnection.pump")
		defer e.capture.unregisterFlow("tcp", flow.Src, flow.Dst)
		defer e.releaseDynamicAddr(targetIP)
		defer ep.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// The dial itself (unlike the data that flows after it) hasn't
		// exchanged anything with the real destination yet, so retrying it
		// is safe - unlike a mid-transfer stall, which can't be transparently
		// resumed without breaking whatever session state the two real
		// endpoints already believe they have. See validation_and_gaps.md §41
		// for why this is bounded to dial-time only.
		var conn net.Conn
		var dialErr error
		for attempt := 1; attempt <= tcpDialMaxAttempts; attempt++ {
			conn, dialErr = decision.Upstream.Dial(ctx, "tcp", dialAddr)
			if dialErr == nil {
				break
			}
			if ctx.Err() != nil {
				break
			}
			if attempt < tcpDialMaxAttempts {
				log.Printf("[flow-%d] TCP upstream dial %s %s attempt %d/%d failed: %v, retrying", flowID, decision.UpstreamID, dialAddr, attempt, tcpDialMaxAttempts, dialErr)
				time.Sleep(tcpDialRetryDelay)
			}
		}
		if dialErr != nil {
			log.Printf("[flow-%d] TCP upstream dial %s %s failed after %d attempts: %v", flowID, decision.UpstreamID, dialAddr, tcpDialMaxAttempts, dialErr)
			return
		}
		defer conn.Close()
		// e.peerPathFor reads an already-cached path (or, for kinds like
		// WireGuard, inspects local state with no I/O) instead of
		// decision.Upstream.PeerPathInfo's own tsnet Status()/IpcGet() round
		// trip - this line runs on the connection-setup critical path for
		// every new TCP flow, so a live upstream query here was on the
		// latency-sensitive side of "success", not just logging overhead.
		path := "unknown"
		if p, ok := e.lookupProvider(decision.UpstreamID); ok {
			path = e.peerPathFor(decision.UpstreamID, p.Kind())
		}
		log.Printf("[flow-%d] TCP upstream dial %s %s success (path=%s)", flowID, decision.UpstreamID, dialAddr, path)

		gonetConn := gonet.NewTCPConn(wq, ep)
		defer gonetConn.Close()

		stats := e.statsFor(decision.UpstreamID)
		stats.beginTCPFlow()
		defer stats.endTCPFlow()

		uid := e.uidStatsFor(flow.AppUID)
		uu := uid.noteUpstream(decision.UpstreamID)
		atomic.AddUint64(&uid.tcpFlows, 1)
		atomic.AddUint64(&uu.tcpFlows, 1)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(conn, gonetConn)
			stats.addBytesOut(n)
			uid.addBytesOut(n)
			uu.addBytesOut(n)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			n, _ := io.Copy(gonetConn, conn)
			stats.addBytesIn(n)
			uid.addBytesIn(n)
			uu.addBytesIn(n)
			gonetConn.CloseRead()
		}()
		wg.Wait()
		log.Printf("[flow-%d] TCP closed", flowID)
	}()
}

func pumpUDPAssociation(dst, src net.Conn, touch func(), onBytes func(n int)) error {
	buf := make([]byte, 64*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		touch()

		written, err := dst.Write(buf[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		touch()
		if onBytes != nil {
			onBytes(written)
		}
	}
}

// runUDPAssociation forwards a connected UDP flow in both directions. Activity
// in either direction refreshes the deadline for the whole association. The
// first terminal error or idle timeout closes both sides, which unblocks the
// opposite pump, and the function waits for both pumps before returning.
//
// stats, uid, and uu may all be nil (existing tests exercise the
// timeout/activity/close behaviour directly over net.Pipe with no real
// Engine, upstream, or app attribution involved); a is the app/gVisor side
// and b is the upstream side, matching the TCP path's addBytesOut/addBytesIn
// direction convention (app->upstream is "out", upstream->app is "in").
func runUDPAssociation(a, b net.Conn, idleTimeout time.Duration, stats *UpstreamStats, uid *uidStats, uu *upstreamUsage) error {
	touch := func() {
		deadline := time.Now().Add(idleTimeout)
		_ = a.SetDeadline(deadline)
		_ = b.SetDeadline(deadline)
	}
	touch()

	var onOut, onIn func(n int)
	if stats != nil || uid != nil || uu != nil {
		onOut = func(n int) {
			if stats != nil {
				stats.addBytesOut(int64(n))
			}
			if uid != nil {
				uid.addBytesOut(int64(n))
			}
			if uu != nil {
				uu.addBytesOut(int64(n))
			}
		}
		onIn = func(n int) {
			if stats != nil {
				stats.addBytesIn(int64(n))
			}
			if uid != nil {
				uid.addBytesIn(int64(n))
			}
			if uu != nil {
				uu.addBytesIn(int64(n))
			}
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- pumpUDPAssociation(b, a, touch, onOut) }()
	go func() { errCh <- pumpUDPAssociation(a, b, touch, onIn) }()

	firstErr := <-errCh
	_ = a.Close()
	_ = b.Close()
	<-errCh
	return firstErr
}

func (e *Engine) handleUDPConnection(r *udp.ForwarderRequest) bool {
	defer recoverAndLog("handleUDPConnection")
	targetIPStr := r.ID().LocalAddress.String()
	targetIP, err := netip.ParseAddr(targetIPStr)
	if err != nil {
		return false
	}
	targetPort := r.ID().LocalPort

	if isSyntheticDNSAddr(targetIPStr) && targetPort == 53 {
		var wq waiter.Queue
		ep, udpErr := r.CreateEndpoint(&wq)
		if udpErr != nil {
			return false
		}
		gvisorConn := gonet.NewUDPConn(&wq, ep)
		go e.ServeDNSUDP(gvisorConn, e.flowFromEndpointID("udp", r.ID()))
		return true
	}

	flow := e.flowFromEndpointID("udp", r.ID())
	decision, ok := e.resolveFlow(flow)
	if !ok {
		return false
	}

	// See handleTCPConnection: every non-DNS destination address must be
	// registered on the NIC before gVisor can send replies from it, since
	// spoofing is disabled.
	if err := e.acquireDynamicAddr(targetIP); err != nil {
		log.Printf("UDP %v: reject (%v)", targetIP, err)
		return false
	}

	var wq waiter.Queue
	ep, udpErr := r.CreateEndpoint(&wq)
	if udpErr != nil {
		e.releaseDynamicAddr(targetIP)
		return false
	}

	gvisorConn := gonet.NewUDPConn(&wq, ep)
	flowID := atomic.AddUint64(&e.flowCounter, 1)

	e.capture.registerFlow("udp", flow.Src, flow.Dst, flow.AppUID)

	go func() {
		defer recoverAndLog("handleUDPConnection.pump")
		defer e.capture.unregisterFlow("udp", flow.Src, flow.Dst)
		defer e.releaseDynamicAddr(targetIP)
		defer gvisorConn.Close()

		dialAddr := fmt.Sprintf("%s:%d", decision.Destination, targetPort)
		if net.ParseIP(decision.Destination).To4() == nil {
			dialAddr = fmt.Sprintf("[%s]:%d", decision.Destination, targetPort)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		tsnetConn, err := decision.Upstream.Dial(ctx, "udp", dialAddr)
		if err != nil {
			log.Printf("[flow-%d] UDP upstream dial %s %s failed: %v", flowID, decision.UpstreamID, dialAddr, err)
			return
		}
		defer tsnetConn.Close()

		log.Printf("[flow-%d] UDP upstream dial %s %s success", flowID, decision.UpstreamID, dialAddr)

		stats := e.statsFor(decision.UpstreamID)
		stats.beginUDPFlow()
		defer stats.endUDPFlow()
		uid := e.uidStatsFor(flow.AppUID)
		uu := uid.noteUpstream(decision.UpstreamID)
		atomic.AddUint64(&uid.udpFlows, 1)
		atomic.AddUint64(&uu.udpFlows, 1)

		err = runUDPAssociation(gvisorConn, tsnetConn, udpAssociationIdleTimeout, stats, uid, uu)
		log.Printf("[flow-%d] UDP closed: %v", flowID, err)
	}()

	return true
}

// isSyntheticDNSAddr reports whether addr is one of the two addresses our
// resolver answers on. Both families are accepted because a v4-only client
// will send its queries to the v4 address advertised on the TUN.
func isSyntheticDNSAddr(addr string) bool {
	return addr == SyntheticIPv6DNS.String() || addr == SyntheticIPv4DNS.String()
}
