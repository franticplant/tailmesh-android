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

func (e *Engine) resolveRoute(targetIP netip.Addr) (RouteDecision, bool) {
	e.targetMutex.RLock()
	rec, found := e.targets[targetIP]
	if !found {
		rec, found = e.syntheticV4[targetIP]
	}
	e.targetMutex.RUnlock()

	if found {
		destIP := rec.CurrentIPv6
		if rec.CurrentIPv4.IsValid() {
			destIP = rec.CurrentIPv4
		}
		if !destIP.IsValid() {
			return RouteDecision{}, false
		}

		if srv, active := e.activeTailnetServer(rec.RequiredUpstream); active {
			return RouteDecision{
				Upstream:    &tsnetUpstream{srv: srv},
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
		if srv, active := e.activeTailnetServer(uid); active {
			return RouteDecision{
				Upstream:    &tsnetUpstream{srv: srv},
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true
		}
		return RouteDecision{}, false
	}

	if exitNode != "" {
		uid := UpstreamID(exitNode)
		if srv, active := e.activeTailnetServer(uid); active {
			return RouteDecision{
				Upstream:    &tsnetUpstream{srv: srv},
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true
		}
	}

	return RouteDecision{}, false
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

	srv, active := e.activeTailnetServer(chosen.RequiredUpstream)
	if !active {
		return RouteDecision{}, false
	}
	return RouteDecision{
		Upstream:    &tsnetUpstream{srv: srv},
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
	if !isDNS {
		var ok bool
		decision, ok = e.resolveRoute(targetIP)
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
		go e.ServeDNSTCP(gvisorConn)
		return
	}

	log.Printf("[flow-%d] TCP %v -> %v (synthetic): dial %s (real=%s)", flowID, remoteAddr, targetIP, decision.UpstreamID, decision.Destination)

	dialAddr := fmt.Sprintf("%s:%d", decision.Destination, targetPort)
	if net.ParseIP(decision.Destination).To4() == nil {
		dialAddr = fmt.Sprintf("[%s]:%d", decision.Destination, targetPort)
	}

	go func() {
		defer recoverAndLog("handleTCPConnection.pump")
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
		log.Printf("[flow-%d] TCP upstream dial %s %s success (path=%s)", flowID, decision.UpstreamID, dialAddr, decision.Upstream.PeerPathInfo(ctx, decision.Destination))

		gonetConn := gonet.NewTCPConn(wq, ep)
		defer gonetConn.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(conn, gonetConn)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			io.Copy(gonetConn, conn)
			gonetConn.CloseRead()
		}()
		wg.Wait()
		log.Printf("[flow-%d] TCP closed", flowID)
	}()
}

func pumpUDPAssociation(dst, src net.Conn, touch func()) error {
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
	}
}

// runUDPAssociation forwards a connected UDP flow in both directions. Activity
// in either direction refreshes the deadline for the whole association. The
// first terminal error or idle timeout closes both sides, which unblocks the
// opposite pump, and the function waits for both pumps before returning.
func runUDPAssociation(a, b net.Conn, idleTimeout time.Duration) error {
	touch := func() {
		deadline := time.Now().Add(idleTimeout)
		_ = a.SetDeadline(deadline)
		_ = b.SetDeadline(deadline)
	}
	touch()

	errCh := make(chan error, 2)
	go func() { errCh <- pumpUDPAssociation(b, a, touch) }()
	go func() { errCh <- pumpUDPAssociation(a, b, touch) }()

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
		go e.ServeDNSUDP(gvisorConn)
		return true
	}

	decision, ok := e.resolveRoute(targetIP)
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

	go func() {
		defer recoverAndLog("handleUDPConnection.pump")
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
		err = runUDPAssociation(gvisorConn, tsnetConn, udpAssociationIdleTimeout)
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
