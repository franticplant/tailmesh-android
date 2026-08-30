// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tailscale.com/tsnet"
)

// TestExitNodeGeneralDial exercises the fix in ../../tailscale/tsnet/tsnet.go
// (UseNetstackForIP) against two real tailnets: it sets a real exit node on
// one tailnet, then dials a real general-internet destination through that
// tailnet's own tsnet.Server, exactly the way tailnetProvider.Dial does when
// a tailnet is selected as the app's default route for general traffic.
//
// Before the fix, UseNetstackForIP only recognized this tailnet's own peers,
// so this destination fell through to SystemDial and bypassed the exit node
// (and Tailscale) entirely - conn.LocalAddr() would show a real host address,
// not a Tailscale IP, and no traffic would ever reach the exit peer. After
// the fix, an exit node being configured makes non-peer destinations
// netstack-eligible too, so wgengine's own default-route forwarding (the
// same mechanism every other Tailscale client relies on for exit nodes)
// actually gets a chance to handle it: LocalAddr() should be this tailnet's
// own Tailscale IP, and the dial should complete.
//
// This intentionally runs against real tailnets rather than a mock, because
// the bug lives in real tsnet/wgengine routing behavior that a mock upstream
// can't reproduce. Requires:
//   - TAILMESH_TEST_AUTHKEYS_FILE: path to a file with two reusable auth
//     keys, one per line, for two different real tailnets. Neither key is
//     read from this repo - keep it outside, same as the release keystore
//     password.
//   - a real exit-node-capable peer already online in the first tailnet.
//
// Skipped under -short and whenever that env var isn't set, so it never runs
// as part of a normal `go test ./...` - this is for deliberate, manual
// verification only, and each run adds a real (non-ephemeral) device to
// both tailnets' admin console.
func TestExitNodeGeneralDial(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two real tsnet.Server tailnet logins")
	}
	keysFile := os.Getenv("TAILMESH_TEST_AUTHKEYS_FILE")
	if keysFile == "" {
		t.Skip("TAILMESH_TEST_AUTHKEYS_FILE not set")
	}
	keys := readAuthKeys(t, keysFile)
	if len(keys) < 2 {
		t.Skipf("need 2 auth keys in %s, found %d", keysFile, len(keys))
	}

	dir := t.TempDir()
	engine := NewEngine(dir, &MockCallback{})
	defer engine.Close()

	const tnA = "exit-a"
	const tnB = "exit-b"
	// k3s-agent-3 (the exit node used below, when TAILMESH_TEST_EXIT_NODE_IP
	// is set) lives in the tailnet unlocked by keys[1], so that key drives
	// srvA/tnA here.
	if err := engine.AddTailnet(tnA, keys[1], true); err != nil {
		t.Fatalf("AddTailnet A: %v", err)
	}
	if err := engine.AddTailnet(tnB, keys[0], true); err != nil {
		t.Fatalf("AddTailnet B: %v", err)
	}

	srvA := waitForTailnetRunning(t, engine, tnA, 60*time.Second)
	_ = waitForTailnetRunning(t, engine, tnB, 60*time.Second)

	exitPeer := os.Getenv("TAILMESH_TEST_EXIT_NODE_IP")
	if exitPeer == "" {
		exitPeer = findExitNodeCapablePeer(t, srvA, 30*time.Second)
	}
	t.Logf("using exit node peer %s", exitPeer)

	if err := engine.SetTailnetExitNode(tnA, exitPeer); err != nil {
		t.Fatalf("SetTailnetExitNode: %v", err)
	}
	waitForExitNodeOnline(t, srvA, 30*time.Second)

	v4, v6 := srvA.TailscaleIPs()
	t.Logf("tailnet A's own Tailscale IPs: v4=%s v6=%s", v4, v6)

	// Ground-truth check: does the control server actually grant a
	// default-route AllowedIPs entry for the exit peer in this device's own
	// netmap? A brand-new device's first-ever request to use a given exit
	// node can require admin-console approval of the advertised route before
	// the server includes it - if that hasn't happened, PeerForIP-style
	// local checks can look optimistic while wgengine has no real route and
	// silently drops the packet, producing exactly a hang/timeout with no
	// error. This is unrelated to any app code and would explain a false
	// positive from this specific fresh test device without indicting the
	// user's real-phone identity, which was presumably approved long ago.
	lb := tsnet.TestHooks.LocalBackend(srvA)
	nm := lb.NetMapWithPeers()
	if nm == nil {
		t.Logf("WARNING: NetMapWithPeers() returned nil, cannot verify route grant")
	} else {
		found := false
		for _, p := range nm.Peers {
			if p.Addresses().Len() == 0 {
				continue
			}
			var isExit bool
			for _, a := range p.Addresses().All() {
				if a.Addr().String() == exitPeer {
					isExit = true
					break
				}
			}
			if !isExit {
				continue
			}
			found = true
			var allowed []string
			hasDefaultV4 := false
			for _, aip := range p.AllowedIPs().All() {
				allowed = append(allowed, aip.String())
				if aip.Bits() == 0 && aip.Addr().Is4() {
					hasDefaultV4 = true
				}
			}
			t.Logf("exit peer %s AllowedIPs (ground truth from netmap): %v", exitPeer, allowed)
			if !hasDefaultV4 {
				t.Logf("*** exit peer's netmap AllowedIPs do NOT include a 0.0.0.0/0 default route. " +
					"This strongly suggests the control server has not granted this route to this device " +
					"(often requires one-time admin-console approval for a new device's first use of a given " +
					"exit node), not a bug in this app or in tsnet/wgengine. ***")
			}
			break
		}
		if !found {
			t.Logf("WARNING: could not find exit peer %s in netmap peer list", exitPeer)
		}
	}

	// Sanity check: dial the exit peer itself directly (a real peer of this
	// tailnet, nothing to do with exit-node route forwarding) to confirm
	// netstack dialing works at all in this environment before blaming exit-
	// node forwarding specifically for anything that fails below.
	sanityCtx, sanityCancel := context.WithTimeout(context.Background(), 10*time.Second)
	sanityConn, sanityErr := srvA.Dial(sanityCtx, "tcp", exitPeer+":22")
	sanityCancel()
	if sanityConn != nil {
		sanityConn.Close()
	}
	t.Logf("sanity dial to exit peer %s:22 (expect either a connection or a fast refusal, not a timeout): err=%v", exitPeer, sanityErr)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const dest = "1.1.1.1:443"
	conn, err := srvA.Dial(ctx, "tcp", dest)
	if err != nil {
		t.Fatalf("Dial(%s) via tailnet A (exit node set) failed: %v\n"+
			"This is exactly the failure the user reported: general traffic through a tailnet with its own exit node set does not work.", dest, err)
	}
	defer conn.Close()

	local := conn.LocalAddr().String()
	t.Logf("dial to %s succeeded, LocalAddr=%s", dest, local)

	localHost, _, err := net.SplitHostPort(local)
	if err != nil {
		t.Fatalf("parsing LocalAddr %q: %v", local, err)
	}
	if localHost != v4.String() && localHost != v6.String() {
		t.Errorf("dial succeeded but did NOT go through the tailnet: LocalAddr=%s matches neither tailnet A's v4 (%s) nor v6 (%s) Tailscale IP - "+
			"this means it took the SystemDial bypass path, silently ignoring the configured exit node, which is the bug this test is meant to catch.",
			local, v4, v6)
	} else {
		t.Logf("confirmed: dial went through tailnet A's own netstack (LocalAddr matches its Tailscale IP), i.e. via the exit node as configured")
	}
}

// TestExitNodeAppPolicyRouting exercises the exact scenario from the bug
// report, through the app's own routing layer rather than calling
// tsnet.Server.Dial directly (as TestExitNodeGeneralDial does): a wildcard
// policy rule sets one tailnet as the default route for both general traffic
// and DNS (mirroring "default route for traffic and DNS" in the Proxy and
// Tunnels UI), that tailnet has its own exit node set (mirroring the
// per-tailnet exit-node picker), and both the data path (resolveFlow ->
// applyPolicy -> RouteDecision.Upstream.Dial) and the DNS forwarding path
// (dnsRouteFor -> exchangePlainVia) are driven exactly as nat_router.go and
// dns_policy.go drive them for a real connection/query - the only thing not
// exercised is the raw gVisor TUN/forwarder plumbing upstream of resolveFlow.
//
// Same requirements and side effects as TestExitNodeGeneralDial.
func TestExitNodeAppPolicyRouting(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two real tsnet.Server tailnet logins")
	}
	keysFile := os.Getenv("TAILMESH_TEST_AUTHKEYS_FILE")
	if keysFile == "" {
		t.Skip("TAILMESH_TEST_AUTHKEYS_FILE not set")
	}
	keys := readAuthKeys(t, keysFile)
	if len(keys) < 2 {
		t.Skipf("need 2 auth keys in %s, found %d", keysFile, len(keys))
	}

	dir := t.TempDir()
	engine := NewEngine(dir, &MockCallback{})
	defer engine.Close()

	const tnA = "policy-a"
	const tnB = "policy-b"
	if err := engine.AddTailnet(tnA, keys[1], true); err != nil {
		t.Fatalf("AddTailnet A: %v", err)
	}
	if err := engine.AddTailnet(tnB, keys[0], true); err != nil {
		t.Fatalf("AddTailnet B: %v", err)
	}

	srvA := waitForTailnetRunning(t, engine, tnA, 60*time.Second)
	waitForTailnetRunning(t, engine, tnB, 60*time.Second)

	exitPeer := os.Getenv("TAILMESH_TEST_EXIT_NODE_IP")
	if exitPeer == "" {
		exitPeer = findExitNodeCapablePeer(t, srvA, 30*time.Second)
	}
	t.Logf("using exit node peer %s", exitPeer)

	if err := engine.SetTailnetExitNode(tnA, exitPeer); err != nil {
		t.Fatalf("SetTailnetExitNode: %v", err)
	}
	waitForExitNodeOnline(t, srvA, 30*time.Second)

	// Wildcard rule: everything routes through tnA, and (DNSUpstream unset)
	// DNS follows the same upstream - this is the exact shape "default route
	// for traffic and DNS" produces in the app.
	if err := engine.SetPolicy(Policy{Rules: []Rule{
		{Name: "default-via-tnA", Selector: Selector{}, Action: ActionRoute, Upstream: tnA},
	}}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// Data path: resolveFlow -> applyPolicy -> RouteDecision, then dial
	// through the resolved upstream exactly as handleTCPConnection would.
	decision, ok := engine.resolveRoute(netip.MustParseAddr("1.1.1.1"))
	if !ok {
		t.Fatal("resolveRoute(1.1.1.1) did not resolve; expected the wildcard policy rule to route it via tnA")
	}
	if decision.UpstreamID != tnA {
		t.Fatalf("resolveRoute(1.1.1.1) resolved to upstream %q, want %q", decision.UpstreamID, tnA)
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dialCancel()
	conn, err := decision.Upstream.Dial(dialCtx, "tcp", "1.1.1.1:443")
	if err != nil {
		t.Fatalf("policy-resolved dial to 1.1.1.1:443 via tnA failed: %v\n"+
			"This is the app's own routing path (resolveFlow -> applyPolicy -> Dial), the exact one the UI's "+
			"\"default route for traffic and DNS\" setting drives.", err)
	}
	conn.Close()
	t.Log("data path confirmed: policy-resolved dial through the exit-node tailnet succeeded")

	// DNS path: dnsRouteFor -> exchangePlainVia, mirroring how a forwarded
	// query that the synthetic resolver can't answer actually leaves.
	route := engine.dnsRouteFor(FlowInfo{AppUID: UnknownAppUID})
	if route.blocked {
		t.Fatal("dnsRouteFor reported blocked, expected the route-via-tnA rule to apply")
	}
	if route.failed {
		t.Fatal("dnsRouteFor reported failed (upstream not ready)")
	}
	if route.provider == nil {
		t.Fatal("dnsRouteFor returned a nil provider; expected the wildcard rule's upstream (tnA) since DNSUpstream is unset")
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, err := exchangePlainVia(route.provider, q, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("DNS query via tnA's exit node failed: %v\n"+
			"This is exactly the DNS symptom from the bug report: DNS never works when a multi-tailnet exit node is the default route.", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("DNS query via tnA's exit node returned no answers: %+v", resp)
	}
	t.Logf("DNS path confirmed: query for example.com via tnA's exit node returned %d answer(s)", len(resp.Answer))
}

func readAuthKeys(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			keys = append(keys, line)
		}
	}
	return keys
}

func waitForTailnetRunning(t *testing.T, engine *Engine, uid UpstreamID, timeout time.Duration) *tsnet.Server {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if srv, ok := engine.activeTailnetServer(uid); ok {
			lc, err := srv.LocalClient()
			if err == nil {
				if st, err := lc.Status(context.Background()); err == nil && st.BackendState == "Running" {
					return srv
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("tailnet %s did not reach Running within %s", uid, timeout)
	return nil
}

// waitForExitNodeOnline polls until the backend itself reports the exit
// node as accepted and online, not just that EditPrefs returned - the
// netmap update carrying the exit peer's expanded AllowedIPs (the actual
// default-route grant this test is exercising) can land after EditPrefs
// does.
func waitForExitNodeOnline(t *testing.T, srv *tsnet.Server, timeout time.Duration) {
	t.Helper()
	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("LocalClient: %v", err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := lc.Status(context.Background())
		if err == nil && st.ExitNodeStatus != nil {
			t.Logf("ExitNodeStatus: ID=%s Online=%v IPs=%v", st.ExitNodeStatus.ID, st.ExitNodeStatus.Online, st.ExitNodeStatus.TailscaleIPs)
			if st.ExitNodeStatus.Online {
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("exit node did not come online within %s", timeout)
}

// findExitNodeCapablePeer polls the tailnet's status until at least one
// online peer advertises exit-node capability, and returns its Tailscale IP.
func findExitNodeCapablePeer(t *testing.T, srv *tsnet.Server, timeout time.Duration) string {
	t.Helper()
	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("LocalClient: %v", err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := lc.Status(context.Background())
		if err == nil {
			for _, p := range st.Peer {
				if p.ExitNodeOption && p.Online && len(p.TailscaleIPs) > 0 {
					return p.TailscaleIPs[0].String()
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("no online exit-node-capable peer found within %s", timeout)
	return ""
}
