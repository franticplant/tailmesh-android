package multiproxy

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"tailscale.com/tsnet"
	"testing"
	"time"
)

type MockCallback struct {
	mu           sync.Mutex
	crossovers   []crossoverCall
	healthEvents []healthCall
	obsEvents    []obsCall
}

type crossoverCall struct {
	ip, candidates, chosen string
}

type healthCall struct {
	upstreamID string
	ready      bool
	reason     string
}

type obsCall struct {
	eventType, upstreamID                  string
	appUID                                 int32
	networkSource, previousState, newState string
	metadataJSON                           string
}

func (m *MockCallback) OnPeerDiscovered(h, v4, v6, t string) {}
func (m *MockCallback) OnTailnetStateChange(t, s string)     {}
func (m *MockCallback) OnAddressCrossover(ip, candidates, chosen string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crossovers = append(m.crossovers, crossoverCall{ip, candidates, chosen})
}

func (m *MockCallback) OnUpstreamHealthChanged(upstreamID string, ready bool, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthEvents = append(m.healthEvents, healthCall{upstreamID, ready, reason})
}

func (m *MockCallback) OnObservabilityEvent(eventType, upstreamID string, appUID int32, networkSource, previousState, newState, metadataJSON string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obsEvents = append(m.obsEvents, obsCall{eventType, upstreamID, appUID, networkSource, previousState, newState, metadataJSON})
}

func (m *MockCallback) crossoverCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.crossovers)
}

func (m *MockCallback) healthEventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.healthEvents)
}

// waitForCrossoverCount polls up to a second for the async event-dispatch
// goroutine to deliver the expected number of OnAddressCrossover calls,
// since enqueueAddressCrossover only queues onto a channel drained by a
// separate goroutine (see Engine.dispatchEvents).
func waitForCrossoverCount(t *testing.T, m *MockCallback, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if m.crossoverCount() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("Expected %d crossover events, got %d after waiting", want, m.crossoverCount())
}

func assertFDBad(t *testing.T, fd int) {
	t.Helper()
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != syscall.EBADF {
		t.Fatalf("Expected EBADF for fd %d, got errno %d", fd, errno)
	}
}

func TestCanonicalTargetKey(t *testing.T) {
	// 1. same TargetKey -> same IPv6
	k1 := TargetKey{"tn1", TargetKindTailscaleNode, "node123"}
	k2 := TargetKey{"tn1", TargetKindTailscaleNode, "node123"}
	if k1.SyntheticIPv6() != k2.SyntheticIPv6() {
		t.Fatalf("Same TargetKey generated different IPs")
	}

	// 2. different namespace -> different IPv6
	k3 := TargetKey{"tn2", TargetKindTailscaleNode, "node123"}
	if k1.SyntheticIPv6() == k3.SyntheticIPv6() {
		t.Fatalf("Different NamespaceID generated same IP")
	}
}

func TestSnapshotLifecycle(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	uid := UpstreamID("test-tn")

	// Initial snapshot with A and B
	recA := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "A"}.SyntheticIPv6(),
		Hostname:         "hostA.",
		CurrentIPv4:      netip.MustParseAddr("100.0.0.1"),
		RequiredUpstream: uid,
	}
	recB := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "B"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "B"}.SyntheticIPv6(),
		Hostname:         "hostB.",
		CurrentIPv4:      netip.MustParseAddr("100.0.0.2"),
		RequiredUpstream: uid,
	}

	engine.updateTailnetSnapshot(uid, []TargetRecord{recA, recB})

	// Verify A and B exist
	engine.targetMutex.RLock()
	if len(engine.targets) != 2 {
		t.Fatalf("Expected 2 targets, got %d", len(engine.targets))
	}
	e_addrA := recA.SyntheticIPv6
	_, ok := engine.targets[e_addrA]
	engine.targetMutex.RUnlock()
	if !ok {
		t.Fatalf("Target A not found")
	}

	// 3. Adding another node does not change existing addresses
	// 4. Removing another node does not change existing addresses
	// Update snapshot with B and C (A is gone)
	recC := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "C"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "C"}.SyntheticIPv6(),
		Hostname:         "hostC.",
		CurrentIPv4:      netip.MustParseAddr("100.0.0.3"),
		RequiredUpstream: uid,
	}
	engine.updateTailnetSnapshot(uid, []TargetRecord{recB, recC})

	engine.targetMutex.RLock()
	if len(engine.targets) != 2 {
		t.Fatalf("Expected 2 targets after replace, got %d", len(engine.targets))
	}
	if _, ok := engine.targets[e_addrA]; ok {
		t.Fatalf("Target A should have been removed (disappearing node becomes unroutable)")
	}
	// B should remain unchanged
	if _, ok := engine.targets[recB.SyntheticIPv6]; !ok {
		t.Fatalf("Target B should remain unchanged")
	}
	engine.targetMutex.RUnlock()

	// 5. same stable node ID with changed current IPv4 keeps same synthetic IPv6
	recB_updated := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "B"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "B"}.SyntheticIPv6(),
		Hostname:         "hostB.",
		CurrentIPv4:      netip.MustParseAddr("100.0.0.99"), // Changed IP
		RequiredUpstream: uid,
	}
	engine.updateTailnetSnapshot(uid, []TargetRecord{recB_updated, recC})

	engine.targetMutex.RLock()
	updatedRecB, ok := engine.targets[recB.SyntheticIPv6]
	engine.targetMutex.RUnlock()
	if !ok || updatedRecB.CurrentIPv4.String() != "100.0.0.99" {
		t.Fatalf("Target B IPv4 did not update while keeping same synthetic IPv6")
	}

	// 7. returning same stable node gets same address
	engine.updateTailnetSnapshot(uid, []TargetRecord{recA})
	engine.targetMutex.RLock()
	_, ok = engine.targets[e_addrA]
	engine.targetMutex.RUnlock()
	if !ok {
		t.Fatalf("Returning target A did not get same address")
	}
}

func TestDisableTailnet(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.AddTailnet("tn", "key", true)

	uid := UpstreamID("tn")
	engine.updateTailnetSnapshot(uid, []TargetRecord{{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "A"}.SyntheticIPv6(),
		Hostname:         "hostA.",
		RequiredUpstream: uid,
	}})

	engine.targetMutex.RLock()
	numTargs := len(engine.targets)
	engine.targetMutex.RUnlock()
	if numTargs != 1 {
		t.Fatalf("Expected 1 target")
	}

	engine.SetTailnetEnabled("tn", false)

	engine.targetMutex.RLock()
	numTargs = len(engine.targets)
	engine.targetMutex.RUnlock()
	if numTargs != 0 {
		t.Fatalf("Expected 0 targets after disable, got %d", numTargs)
	}

	engine.mu.RLock()
	if _, exists := engine.tailnets[uid]; !exists {
		t.Fatalf("Disabled tailnet should still exist in configuration")
	}
	engine.mu.RUnlock()
}

func TestDistinctTargetsSameIPv4Routing(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	uid1 := UpstreamID("tn1")
	uid2 := UpstreamID("tn2")

	engine.mu.Lock()
	engine.tailnets[uid1] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.tailnets[uid2] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	recA := TargetRecord{
		Key:              TargetKey{uid1, TargetKindTailscaleNode, "A"},
		CurrentIPv4:      netip.MustParseAddr("100.1.2.3"),
		RequiredUpstream: uid1,
	}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()

	recB := TargetRecord{
		Key:              TargetKey{uid2, TargetKindTailscaleNode, "B"},
		CurrentIPv4:      netip.MustParseAddr("100.1.2.3"),
		RequiredUpstream: uid2,
	}
	recB.SyntheticIPv6 = recB.Key.SyntheticIPv6()

	engine.updateTailnetSnapshot(uid1, []TargetRecord{recA})
	engine.updateTailnetSnapshot(uid2, []TargetRecord{recB})

	d1, ok1 := engine.resolveRoute(recA.SyntheticIPv6)
	d2, ok2 := engine.resolveRoute(recB.SyntheticIPv6)

	if !ok1 || !ok2 {
		t.Fatalf("Failed to resolve distinct targets")
	}
	if d1.Upstream == d2.Upstream {
		t.Fatalf("Same IPv4 across Tailnets routed to same upstream!")
	}
}

func TestForcedCollisionFailsClosed(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	uid := UpstreamID("tn")

	// Force a collision manually
	recA := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		Hostname:         "hostA.",
		RequiredUpstream: uid,
	}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()

	recB := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "B"},
		Hostname:         "hostB.",
		RequiredUpstream: uid,
	}
	// FORCE COLLISION
	recB.SyntheticIPv6 = recA.SyntheticIPv6

	engine.updateTailnetSnapshot(uid, []TargetRecord{recA, recB})

	engine.targetMutex.RLock()
	defer engine.targetMutex.RUnlock()

	if _, ok := engine.targets[recA.SyntheticIPv6]; ok {
		t.Fatalf("Collision did not fail closed, target was still routable")
	}
}

func TestDNSAmbiguityAndQualified(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})

	uid1 := UpstreamID("tn1")
	uid2 := UpstreamID("tn2")

	recA := TargetRecord{
		Key:              TargetKey{uid1, TargetKindTailscaleNode, "A"},
		SyntheticIPv6:    TargetKey{uid1, TargetKindTailscaleNode, "A"}.SyntheticIPv6(),
		Hostname:         "shared.",
		RequiredUpstream: uid1,
	}
	recB := TargetRecord{
		Key:              TargetKey{uid2, TargetKindTailscaleNode, "B"},
		SyntheticIPv6:    TargetKey{uid2, TargetKindTailscaleNode, "B"}.SyntheticIPv6(),
		Hostname:         "shared.",
		RequiredUpstream: uid2,
	}

	engine.updateTailnetSnapshot(uid1, []TargetRecord{recA})
	engine.updateTailnetSnapshot(uid2, []TargetRecord{recB})

	engine.targetMutex.RLock()
	ips := engine.dnsTable["shared."]
	if len(ips) != 2 {
		t.Fatalf("Expected 2 IPs for ambiguous name 'shared.', got %d", len(ips))
	}

	hash1 := getStableHash("tn1")
	qualified1 := "shared." + hash1 + ".proxy."
	ips1 := engine.dnsTable[qualified1]
	if len(ips1) != 1 || ips1[0] != recA.SyntheticIPv6 {
		t.Fatalf("Expected qualified name to resolve uniquely to A")
	}
	engine.targetMutex.RUnlock()
}

func TestPrefixContainment(t *testing.T) {
	k := TargetKey{"tn", TargetKindTailscaleNode, "X"}
	ip := k.SyntheticIPv6()

	if !SyntheticIPv6Prefix.Contains(ip) {
		t.Fatalf("Generated IP %v is not contained in SyntheticIPv6Prefix %v", ip, SyntheticIPv6Prefix)
	}
}

func TestSyntheticDNSAnswersBothFamilies(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	uid := UpstreamID("tn")
	rec := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		SyntheticIPv6:    TargetKey{uid, TargetKindTailscaleNode, "A"}.SyntheticIPv6(),
		Hostname:         "onlyv6.",
		RequiredUpstream: uid,
	}
	engine.updateTailnetSnapshot(uid, []TargetRecord{rec})

	// Test AAAA query
	reqAAAA := new(dns.Msg)
	reqAAAA.SetQuestion("onlyv6.", dns.TypeAAAA)
	respAAAA := engine.handleDNSMsg(reqAAAA, "udp", FlowInfo{AppUID: UnknownAppUID})
	if respAAAA.Rcode != dns.RcodeSuccess || len(respAAAA.Answer) != 1 {
		t.Fatalf("Expected 1 answer for AAAA, got %d", len(respAAAA.Answer))
	}

	// Test A query -> should hand out a synthetic v4 address so v4-only
	// clients can reach this peer too.
	reqA := new(dns.Msg)
	reqA.SetQuestion("onlyv6.", dns.TypeA)
	respA := engine.handleDNSMsg(reqA, "udp", FlowInfo{AppUID: UnknownAppUID})
	if respA.Rcode != dns.RcodeSuccess || len(respA.Answer) != 1 {
		t.Fatalf("Expected 1 answer for A query, got rcode=%d answers=%d", respA.Rcode, len(respA.Answer))
	}
	aRR, ok := respA.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Expected an A record, got %T", respA.Answer[0])
	}
	if addr, ok := netip.AddrFromSlice(aRR.A.To4()); !ok || !SyntheticIPv4Prefix.Contains(addr) {
		t.Fatalf("A answer %v is not in the synthetic v4 pool %v", aRR.A, SyntheticIPv4Prefix)
	}
}

type mockUpstream struct{ dialAddr string }

func (m *mockUpstream) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	m.dialAddr = address
	return nil, nil // we just record it
}

func TestConcurrentEnableDisable(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.AddTailnet("tn", "key", true)

	// Rapidly disable and enable
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()
			engine.SetTailnetEnabled("tn", false)
			engine.SetTailnetEnabled("tn", true)
		}(i)
	}
	wg.Wait()

	// End state verify
	engine.SetTailnetEnabled("tn", true)

	engine.mu.RLock()
	rt, exists := engine.tailnets["tn"]
	engine.mu.RUnlock()

	if !exists || !rt.Enabled || rt.Srv == nil {
		t.Fatalf("Tailnet failed to stabilize in enabled state")
	}

	engine.SetTailnetEnabled("tn", false)
	engine.mu.RLock()
	rt, _ = engine.tailnets["tn"]
	engine.mu.RUnlock()

	if rt.Enabled || rt.Srv != nil {
		t.Fatalf("Tailnet failed to stabilize in disabled state")
	}
}

func TestRouteDecisionUpstreamSelection(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})

	uid := UpstreamID("tn-mock")
	engine.mu.Lock()
	engine.tailnets[uid] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	recA := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		Hostname:         "hostA.",
		CurrentIPv4:      netip.MustParseAddr("100.0.0.5"),
		RequiredUpstream: uid,
	}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()

	engine.updateTailnetSnapshot(uid, []TargetRecord{recA})

	decision, ok := engine.resolveRoute(recA.SyntheticIPv6)
	if !ok {
		t.Fatalf("Failed to resolve route")
	}
	if decision.Destination != "100.0.0.5" {
		t.Fatalf("Expected destination 100.0.0.5, got %s", decision.Destination)
	}
	if decision.UpstreamID != uid {
		t.Fatalf("Expected UpstreamID %s, got %s", uid, decision.UpstreamID)
	}
}

func TestDisableReenableIdentity(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.AddTailnet("tn", "key", true)

	uid := UpstreamID("tn")
	recA := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "A"},
		RequiredUpstream: uid,
	}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()
	engine.updateTailnetSnapshot(uid, []TargetRecord{recA})

	engine.SetTailnetEnabled("tn", false)
	engine.SetTailnetEnabled("tn", true)

	// Add it back in snapshot (simulate connection returning)
	engine.updateTailnetSnapshot(uid, []TargetRecord{recA})

	engine.targetMutex.RLock()
	defer engine.targetMutex.RUnlock()
	if _, ok := engine.targets[recA.SyntheticIPv6]; !ok {
		t.Fatalf("Target did not retain identity/routable status across disable/reenable")
	}
}

func TestStaleSyntheticRouting(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.mu.Lock()
	engine.tailnets["exit-node"] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	engine.SetExitNode("exit-node")
	engine.AcceptSubnet("::/0", "exit-node")

	// Create an address that is inside SyntheticIPv6Prefix but has no TargetRecord
	staleIP := SyntheticIPv6Prefix.Addr()

	_, ok := engine.resolveRoute(staleIP)
	if ok {
		t.Fatalf("Stale synthetic route fell through to subnet/exit node rather than failing closed!")
	}

	// Random IP outside synthetic prefix should fall through to exit node
	outsideIP := netip.MustParseAddr("2001:4860:4860::8888")
	decision, ok2 := engine.resolveRoute(outsideIP)
	if !ok2 || decision.UpstreamID != "exit-node" {
		t.Fatalf("Outside IP failed to fall through to exit node")
	}
}

func TestRealIPRoutingUnambiguous(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.mu.Lock()
	engine.tailnets["tn-a"] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	realIP := netip.MustParseAddr("100.90.1.1")
	rec := TargetRecord{
		Key:              TargetKey{"tn-a", TargetKindTailscaleNode, "peer-a"},
		Hostname:         "peer-a.",
		CurrentIPv4:      realIP,
		RequiredUpstream: "tn-a",
	}
	rec.SyntheticIPv6 = rec.Key.SyntheticIPv6()
	engine.updateTailnetSnapshot("tn-a", []TargetRecord{rec})

	decision, ok := engine.resolveRoute(realIP)
	if !ok {
		t.Fatalf("Real IP handed directly (not via synthetic address) failed to route")
	}
	if decision.UpstreamID != "tn-a" || decision.Destination != realIP.String() {
		t.Fatalf("Unexpected route decision: %+v", decision)
	}

	// Give any errant async event a moment to arrive, then confirm none did.
	time.Sleep(50 * time.Millisecond)
	cb := engine.callback.(*MockCallback)
	if got := cb.crossoverCount(); got != 0 {
		t.Fatalf("Unambiguous real-IP route should not fire a crossover event, got %d", got)
	}
}

func TestRealIPRoutingCrossoverResolvesAndLogs(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.mu.Lock()
	engine.tailnets["tn-a"] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.tailnets["tn-b"] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	// Same real IP claimed by two simultaneously-active upstreams - this is
	// expected and legitimate given Tailscale's shared CGNAT pool, not a bug.
	sharedIP := netip.MustParseAddr("100.90.1.1")
	recA := TargetRecord{
		Key:              TargetKey{"tn-a", TargetKindTailscaleNode, "peer-a"},
		CurrentIPv4:      sharedIP,
		RequiredUpstream: "tn-a",
	}
	recA.SyntheticIPv6 = recA.Key.SyntheticIPv6()
	recB := TargetRecord{
		Key:              TargetKey{"tn-b", TargetKindTailscaleNode, "peer-b"},
		CurrentIPv4:      sharedIP,
		RequiredUpstream: "tn-b",
	}
	recB.SyntheticIPv6 = recB.Key.SyntheticIPv6()
	engine.updateTailnetSnapshot("tn-a", []TargetRecord{recA})
	engine.updateTailnetSnapshot("tn-b", []TargetRecord{recB})

	decision, ok := engine.resolveRoute(sharedIP)
	if !ok {
		t.Fatalf("Ambiguous real IP should still resolve best-effort, not fail closed")
	}
	// Deterministic tie-break: lowest UpstreamID string wins.
	if decision.UpstreamID != "tn-a" {
		t.Fatalf("Expected deterministic pick of tn-a, got %s", decision.UpstreamID)
	}

	cb := engine.callback.(*MockCallback)
	waitForCrossoverCount(t, cb, 1)

	// Same lookup again should reach the same deterministic decision.
	decision2, ok2 := engine.resolveRoute(sharedIP)
	if !ok2 || decision2.UpstreamID != "tn-a" {
		t.Fatalf("Repeated lookup of an ambiguous address should be stable, got %+v", decision2)
	}
}

func TestRealIPRoutingUnaffectedInsideSyntheticNamespace(t *testing.T) {
	// Regression guard: bindings/real-IP resolution must never weaken the
	// in-namespace fail-closed behavior for a stale/unknown synthetic address.
	engine := NewEngine("/tmp", &MockCallback{})
	engine.mu.Lock()
	engine.tailnets["tn-a"] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	staleIP := SyntheticIPv6Prefix.Addr()
	if _, ok := engine.resolveRoute(staleIP); ok {
		t.Fatalf("Stale synthetic address must still fail closed")
	}
}

func TestResolveRouteConcurrency(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.AddTailnet("tn-race", "key", true)

	uid := UpstreamID("tn-race")
	rec := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "RACE"},
		CurrentIPv4:      netip.MustParseAddr("100.1.2.3"),
		RequiredUpstream: uid,
	}
	rec.SyntheticIPv6 = rec.Key.SyntheticIPv6()
	engine.updateTailnetSnapshot(uid, []TargetRecord{rec})

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Each enable spins up a real tsnet.Server that attempts a real
		// login round-trip before the disable/re-enable can proceed, so a
		// handful of cycles is enough to exercise the enable/disable-vs-
		// resolveRoute race without the test taking minutes.
		for i := 0; i < 5; i++ {
			engine.SetTailnetEnabled("tn-race", false)
			engine.SetTailnetEnabled("tn-race", true)
		}
		close(done)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				engine.resolveRoute(rec.SyntheticIPv6)
			}
		}
	}()

	wg.Wait()
}

func TestSyntheticDNSNoDataForUnsupported(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	uid := UpstreamID("tn-dns")

	engine.mu.Lock()
	engine.tailnets[uid] = &TailnetRuntime{Enabled: true, Srv: &tsnet.Server{}}
	engine.mu.Unlock()

	rec := TargetRecord{
		Key:              TargetKey{uid, TargetKindTailscaleNode, "DNS"},
		Hostname:         "dns-test.",
		CurrentIPv4:      netip.MustParseAddr("100.1.2.3"),
		RequiredUpstream: uid,
	}
	rec.SyntheticIPv6 = rec.Key.SyntheticIPv6()

	engine.updateTailnetSnapshot(uid, []TargetRecord{rec})

	hashID := getStableHash(string(uid))
	qualified := fmt.Sprintf("dns-test.%s.proxy.", hashID)

	req := new(dns.Msg)
	req.SetQuestion(qualified, dns.TypeTXT)

	resp := engine.handleDNSMsg(req, "udp", FlowInfo{AppUID: UnknownAppUID})

	if len(resp.Answer) != 0 {
		t.Fatalf("Expected NODATA (0 answers) for TXT, got %d", len(resp.Answer))
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("Expected RcodeSuccess, got %v", resp.Rcode)
	}
	if !resp.Authoritative {
		t.Fatalf("Expected authoritative response")
	}
}

func TestDNSNormalization(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})
	engine.SetUpstreamDNS("192.168.1.1")
	if engine.upstreamDNS != "192.168.1.1:53" {
		t.Fatalf("Expected 192.168.1.1:53, got %s", engine.upstreamDNS)
	}

	engine.SetUpstreamDNS("2001:db8::1")
	if engine.upstreamDNS != "[2001:db8::1]:53" {
		t.Fatalf("Expected [2001:db8::1]:53, got %s", engine.upstreamDNS)
	}

	engine.SetUpstreamDNS(SyntheticIPv6DNS.String())
	if engine.upstreamDNS != "[2001:db8::1]:53" { // Should be unchanged from previous
		t.Fatalf("Expected [2001:db8::1]:53 after rejecting self-DNS, got %s", engine.upstreamDNS)
	}

	engine.SetUpstreamDNS("[2001:db8::2]:5353")
	if engine.upstreamDNS != "[2001:db8::2]:5353" {
		t.Fatalf("Expected [2001:db8::2]:5353, got %s", engine.upstreamDNS)
	}
}

func TestSetUpstreamDNSAcceptsDoHURL(t *testing.T) {
	engine := NewEngine("/tmp", &MockCallback{})

	engine.SetUpstreamDNS("https://cloudflare-dns.com/dns-query")
	if engine.upstreamDNS != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("Expected DoH URL to be stored verbatim, got %s", engine.upstreamDNS)
	}

	// Malformed DoH-shaped URL is ignored, not silently swapped in.
	engine.SetUpstreamDNS("https://")
	if engine.upstreamDNS != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("Malformed DoH URL should be ignored, got %s", engine.upstreamDNS)
	}

	// Switching back to a plain resolver still works after a DoH URL was set.
	engine.SetUpstreamDNS("192.168.1.1")
	if engine.upstreamDNS != "192.168.1.1:53" {
		t.Fatalf("Expected 192.168.1.1:53 after switching off DoH, got %s", engine.upstreamDNS)
	}
}
