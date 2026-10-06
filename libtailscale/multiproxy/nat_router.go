// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/json"
	"errors"
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

// ErrNoUsableNetworkForFamily is returned (wrapped) by an Upstream's Dial
// when the Android side has already determined, before attempting to
// connect, that no active network can carry a socket of the dialed address
// family - see App.bindSocketToNetwork / NetworkChangeCallback.pickNetworkForDial
// in the Android source, and the netns.SetAndroidBindToNetworkFunc callback
// in libtailscale/backend.go that turns a false return from that Java method
// into this Go error.
//
// It is a permanent failure for the current dial, not a transient one:
// nothing about which networks the device has changes between one dial
// attempt and the next inside the same handleTCPConnection call, so
// retrying the identical dial tcpDialMaxAttempts times cannot succeed - it
// only spends tcpDialRetryDelay twice for no benefit, which used to show up
// as a ~600ms delay before the caller (and the peer app's own TCP stack)
// ever saw the connection fail. dialWithRetry treats this error as terminal
// so that delay is gone; see validation_and_gaps.md §93.
var ErrNoUsableNetworkForFamily = errors.New("multiproxy: no active network can carry this socket's address family")

// dialWithRetry dials upstream up to tcpDialMaxAttempts times, sleeping
// tcpDialRetryDelay between attempts, on the assumption (documented at
// nat_router.go's call site) that retrying a dial that hasn't exchanged any
// application data yet is safe. onRetry, if non-nil, is called before each
// sleep so the caller can log per-attempt failures with its own context
// (flow ID, upstream, address) without dialWithRetry needing to know about
// any of that.
//
// A dial error that wraps ErrNoUsableNetworkForFamily aborts immediately,
// without sleeping or retrying - see that error's doc comment for why.
func dialWithRetry(
	ctx context.Context,
	upstream Upstream,
	network, addr string,
	onRetry func(attempt int, err error),
) (net.Conn, error) {
	var conn net.Conn
	var dialErr error
	for attempt := 1; attempt <= tcpDialMaxAttempts; attempt++ {
		conn, dialErr = upstream.Dial(ctx, network, addr)
		if dialErr == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, dialErr
		}
		if errors.Is(dialErr, ErrNoUsableNetworkForFamily) {
			return nil, dialErr
		}
		if attempt < tcpDialMaxAttempts {
			if onRetry != nil {
				onRetry(attempt, dialErr)
			}
			time.Sleep(tcpDialRetryDelay)
		}
	}
	return nil, dialErr
}

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
	d, ok, _ := e.resolveFlowTraced(f)
	return d, ok
}

// resolveFlowTraced is resolveFlow's implementation, plus a step-by-step
// trace of which of resolveFlow's decision stages were tried and why each
// one did or didn't produce a route - the "what decisions were made for it
// to have gone there" detail the routing-decision telemetry (logRouteDecision)
// exists to surface. resolveFlow itself is the thin, trace-free wrapper every
// existing call site keeps using unchanged; only handleTCPConnection, which
// already pays for per-flow logRouteDecision bookkeeping, calls this
// directly. The trace is built unconditionally rather than gated on whether
// telemetry is currently enabled - a handful of string formats once per new
// connection (not per packet) is not worth a second, duplicate code path to
// avoid, and it means turning telemetry on retroactively costs nothing on
// this function.
func (e *Engine) resolveFlowTraced(f FlowInfo) (RouteDecision, bool, []string) {
	var trace []string
	step := func(format string, args ...any) {
		trace = append(trace, fmt.Sprintf(format, args...))
	}

	targetIP := f.Dst.Addr().Unmap()
	if !targetIP.IsValid() {
		step("invalid destination address")
		return RouteDecision{}, false, trace
	}

	e.targetMutex.RLock()
	rec, found := e.targets[targetIP]
	if !found {
		rec, found = e.syntheticV4[targetIP]
	}
	e.targetMutex.RUnlock()

	if found {
		step("matched known peer target -> upstream %s", rec.RequiredUpstream)
		// A block rule still applies: refusing to send traffic is always a
		// safe thing to honour, even for an identity-bound destination.
		if rule, _, ok := e.matchPolicy(f); ok && rule.Action == ActionBlock {
			step("policy rule blocks this flow despite the peer-target match")
			return RouteDecision{}, false, trace
		}

		destIP := rec.CurrentIPv6
		if rec.CurrentIPv4.IsValid() {
			destIP = rec.CurrentIPv4
		}
		if !destIP.IsValid() {
			step("peer target has no current address (offline/no handshake yet)")
			return RouteDecision{}, false, trace
		}

		if p, ready := e.readyProvider(rec.RequiredUpstream); ready {
			step("upstream %s ready -> dial %s", rec.RequiredUpstream, destIP)
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  rec.RequiredUpstream,
				Destination: destIP.String(),
			}, true, trace
		}
		step("upstream %s not ready -> fail closed", rec.RequiredUpstream)
		return RouteDecision{}, false, trace
	}

	if SyntheticIPv6Prefix.Contains(targetIP) || SyntheticIPv4Prefix.Contains(targetIP) {
		// Inside synthetic namespace but no exact target -> fail closed.
		// A synthetic address that no longer maps to a peer is stale (the
		// peer left, or the netmap moved on); falling through to the
		// real-IP or subnet logic below would route it somewhere unrelated.
		step("inside synthetic address space but no target registered (stale synthetic address) -> fail closed")
		return RouteDecision{}, false, trace
	}
	step("not a synthetic address - treating as a real destination")

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
		if ok {
			step("policy rule matched (action=%s) -> upstream %s", policyActionName(decision.UpstreamID, ok), decision.UpstreamID)
		} else {
			step("policy rule matched but is not currently routable (blocked, or its upstream isn't ready) -> fail closed")
		}
		return decision, ok, trace
	}
	step("no policy rule matched")

	if decision, ok := e.resolveRealIPRoute(targetIP); ok {
		step("resolved via real-IP index -> upstream %s", decision.UpstreamID)
		return decision, true, trace
	}
	step("no real-IP index match")

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
			step("matched advertised subnet route %s (upstream %s)", longestMatch.Prefix, uid)
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true, trace
		}
		step("matched advertised subnet route %s but upstream %s not ready -> fail closed", longestMatch.Prefix, uid)
		return RouteDecision{}, false, trace
	}
	step("no subnet route match")

	if exitNode != "" {
		uid := UpstreamID(exitNode)
		if p, ready := e.readyProvider(uid); ready {
			step("falling back to configured exit node upstream %s", uid)
			return RouteDecision{
				Upstream:    p,
				UpstreamID:  uid,
				Destination: targetIP.String(),
			}, true, trace
		}
		step("configured exit node upstream %s not ready", uid)
	} else {
		step("no exit node configured")
	}

	step("no route found -> reject")
	return RouteDecision{}, false, trace
}

// policyActionName is a small logging helper: applyPolicy already collapsed
// its rule into a RouteDecision by the time resolveFlowTraced sees it, so
// this just names what kind of route resulted, for the trace line.
func policyActionName(upstreamID UpstreamID, ok bool) string {
	if !ok {
		return "deny"
	}
	if upstreamID == DirectUpstreamID {
		return "direct"
	}
	return "route"
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

// rejectDoomedDirectIPv6 reports whether a flow should be rejected before
// gVisor accepts it, because it is an IPv6 destination that would resolve to
// the @direct upstream and the device's current network cannot carry an
// IPv6 dial right now - see Engine.directIPv6Usable's doc comment.
//
// Extracted as a pure function (decision + targetIP in, bool out, no gVisor
// or gomobile involved) so the policy is unit-testable without constructing
// a tcp.ForwarderRequest - the same reason dialWithRetry was pulled out of
// handleTCPConnection in §93.
func rejectDoomedDirectIPv6(decision RouteDecision, targetIP netip.Addr, ipv6Usable *func() bool) bool {
	if ipv6Usable == nil || decision.UpstreamID != DirectUpstreamID || !targetIP.Is6() {
		return false
	}
	return !(*ipv6Usable)()
}

// familyOf reports "4" or "6" for use as a route-decision event's
// networkSource field (see logRouteDecision).
func familyOf(ip netip.Addr) string {
	if ip.Is6() && !ip.Is4In6() {
		return "6"
	}
	return "4"
}

// routeDecisionMetaJSON builds logRouteDecision's metaJSON payload. Fields
// are the ones the IPv6-direct-dial investigation asked to have logged per
// flow: the virtual (app-facing) src/dst, the decoded real destination, the
// exact dial network/address, the dial's wall-clock duration, and trace -
// resolveFlowTraced's ordered list of which routing stages were tried and
// why each one did or didn't produce a route, i.e. the "what decisions were
// made for it to have gone there" detail, not just the final answer.
// Marshaling failure (none of these types can actually fail to marshal)
// falls back to an empty object rather than losing the event entirely.
func routeDecisionMetaJSON(flow FlowInfo, targetIP netip.Addr, realDest, dialAddr string, dialDuration time.Duration, trace []string) string {
	meta := map[string]any{
		"virtualSrc": flow.Src.String(),
		"virtualDst": flow.Dst.String(),
		"targetIP":   targetIP.String(),
	}
	if realDest != "" {
		meta["realDest"] = realDest
	}
	if dialAddr != "" {
		meta["dialNetwork"] = "tcp"
		meta["dialAddr"] = dialAddr
		meta["dialDurationMs"] = dialDuration.Milliseconds()
	}
	if len(trace) > 0 {
		meta["trace"] = trace
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return "{}"
	}
	return string(b)
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
	var trace []string
	if !isDNS {
		var ok bool
		flow = e.flowFromEndpointID("tcp", id)
		decision, ok, trace = e.resolveFlowTraced(flow)
		if !ok {
			log.Printf("[flow-%d] TCP %v -> %v (synthetic): reject (no route)", flowID, remoteAddr, targetIP)
			e.logRouteDecision(flowID, flow.AppUID, "", familyOf(targetIP), "no-route", "", routeDecisionMetaJSON(flow, targetIP, "", "", 0, trace))
			r.Complete(true)
			return
		}
		if rejectDoomedDirectIPv6(decision, targetIP, e.directIPv6Usable.Load()) {
			log.Printf("[flow-%d] TCP %v -> %v (synthetic): reject (no active network can carry IPv6 for %s right now)", flowID, remoteAddr, targetIP, decision.UpstreamID)
			trace = append(trace, fmt.Sprintf("rejected before accept: no active network can carry IPv6 for %s right now", decision.UpstreamID))
			e.logRouteDecision(flowID, flow.AppUID, decision.UpstreamID, familyOf(targetIP), "no-usable-network-for-family", "", routeDecisionMetaJSON(flow, targetIP, decision.Destination, "", 0, trace))
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

	e.capture.registerFlow("tcp", flow.Src, flow.Dst, flow.AppUID, flowID)

	go func() {
		defer recoverAndLog("handleTCPConnection.pump")
		defer e.capture.unregisterFlow("tcp", flow.Src, flow.Dst)
		defer e.earlyUID.forget(flowKey{"tcp", flow.Src, flow.Dst})
		defer e.releaseDynamicAddr(targetIP)
		defer ep.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// The dial itself (unlike the data that flows after it) hasn't
		// exchanged anything with the real destination yet, so retrying it
		// is safe - unlike a mid-transfer stall, which can't be transparently
		// resumed without breaking whatever session state the two real
		// endpoints already believe they have. See validation_and_gaps.md §41
		// for why this is bounded to dial-time only, and §93 for why a dial
		// that fails with ErrNoUsableNetworkForFamily doesn't get retried at
		// all despite that.
		dialStart := time.Now()
		conn, dialErr := dialWithRetry(ctx, decision.Upstream, "tcp", dialAddr, func(attempt int, err error) {
			log.Printf("[flow-%d] TCP upstream dial %s %s attempt %d/%d failed: %v, retrying", flowID, decision.UpstreamID, dialAddr, attempt, tcpDialMaxAttempts, err)
		})
		dialDuration := time.Since(dialStart)
		if dialErr != nil {
			outcome, errStr := "dial-error", dialErr.Error()
			if errors.Is(dialErr, ErrNoUsableNetworkForFamily) {
				outcome = "no-usable-network-for-family"
				log.Printf("[flow-%d] TCP upstream dial %s %s failed: %v (not retrying - no active network can carry this address family right now)", flowID, decision.UpstreamID, dialAddr, dialErr)
			} else {
				log.Printf("[flow-%d] TCP upstream dial %s %s failed after %d attempts: %v", flowID, decision.UpstreamID, dialAddr, tcpDialMaxAttempts, dialErr)
			}
			e.logRouteDecision(flowID, flow.AppUID, decision.UpstreamID, familyOf(targetIP), outcome, errStr, routeDecisionMetaJSON(flow, targetIP, decision.Destination, dialAddr, dialDuration, trace))
			return
		}
		e.logRouteDecision(flowID, flow.AppUID, decision.UpstreamID, familyOf(targetIP), "success", "", routeDecisionMetaJSON(flow, targetIP, decision.Destination, dialAddr, dialDuration, trace))
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

	e.capture.registerFlow("udp", flow.Src, flow.Dst, flow.AppUID, flowID)

	go func() {
		defer recoverAndLog("handleUDPConnection.pump")
		defer e.capture.unregisterFlow("udp", flow.Src, flow.Dst)
		defer e.earlyUID.forget(flowKey{"udp", flow.Src, flow.Dst})
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
