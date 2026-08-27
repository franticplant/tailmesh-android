package multiproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

type EngineState int

const (
	StateOpen EngineState = iota
	StateClosing
	StateClosed
)

type EngineCallback interface {
	OnPeerDiscovered(hostname, ipv4, ipv6, tailnetID string)
	OnTailnetStateChange(tailnetID, state string)

	// OnAddressCrossover fires when a real (non-synthetic) Tailscale IP
	// resolved during routing belongs to more than one simultaneously-active
	// upstream's peer set. candidateTailnetIDsCSV is a comma-separated list
	// of every upstream that claims this address; chosenTailnetID is the one
	// resolveRoute picked. This is a best-effort disambiguation, not an
	// error, but the user should be able to see it happened - a silent wrong
	// choice here is a worse failure mode than a visible one.
	OnAddressCrossover(ip, candidateTailnetIDsCSV, chosenTailnetID string)

	// OnUpstreamHealthChanged fires when an upstream's dial-level readiness
	// changes: the first failure after a run of successes, or the first
	// success (or first ready result) after a run of failures/not-ready
	// observations. reason is the triggering dial's error string, or empty on
	// a recovery. This is a best-effort, near-real-time notification (see
	// events below) - UpstreamStatsSnapshot (stats.go) is the reliable source
	// of truth for anything this channel drops.
	OnUpstreamHealthChanged(upstreamID string, ready bool, reason string)
}

type subnetRoute struct {
	Prefix    netip.Prefix
	TailnetID string
}

type engineEventKind int

const (
	eventPeerDiscovered engineEventKind = iota
	eventTailnetStateChange
	eventAddressCrossover
	eventUpstreamHealthChanged
)

type engineEvent struct {
	kind      engineEventKind
	hostname  string
	ipv4      string
	ipv6      string
	tailnetID string
	stateStr  string

	// used by eventAddressCrossover only
	crossoverIP         string
	crossoverCandidates string
	crossoverChosen     string

	// used by eventUpstreamHealthChanged only
	healthUpstreamID string
	healthReady      bool
	healthReason     string
}

type tsnetUpstream struct {
	srv *tsnet.Server
}

func (u *tsnetUpstream) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return u.srv.Dial(ctx, network, address)
}

func (u *tsnetUpstream) PeerPathInfo(ctx context.Context, destIP string) string {
	lc, err := u.srv.LocalClient()
	if err != nil {
		return "unknown"
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return "unknown"
	}
	for _, ps := range st.Peer {
		for _, ip := range ps.TailscaleIPs {
			if ip.String() != destIP {
				continue
			}
			if ps.CurAddr != "" {
				return "direct"
			}
			if ps.Relay != "" {
				return "derp:" + ps.Relay
			}
			return "no-path"
		}
	}
	return "unknown"
}

type TailnetRuntime struct {
	Config  TailnetConfig
	Srv     *tsnet.Server
	Cancel  context.CancelFunc
	Wg      *sync.WaitGroup
	Enabled bool
}

type TailnetConfig struct {
	Identifier string
	AuthKey    string
	HashID     string
	StateDir   string
}

type Engine struct {
	mu                 sync.RWMutex
	flowCounter        uint64
	tailnetLifecycleMu sync.Mutex
	state              EngineState

	tailnets map[UpstreamID]*TailnetRuntime

	// exitNodes holds every exit-node upstream: a dedicated tsnet.Server
	// pinned to one peer of some tailnet via Prefs.ExitNodeIP. See
	// upstream_exitnode.go. Guarded by mu, lifecycle guarded by
	// tailnetLifecycleMu, same as tailnets.
	exitNodes map[UpstreamID]*ExitNodeRuntime

	// upstreams holds every non-tailnet upstream (SOCKS5, WireGuard, direct).
	// Tailnets stay in the map above with their own lifecycle; lookupProvider
	// presents both behind one interface.
	upstreams *upstreamRegistry

	// stats holds live per-upstream dial/byte counters, recorded by every real
	// dial regardless of call site. See stats.go.
	stats *statsRegistry

	// policy is the ordered rule list consulted for flows that synthetic
	// addressing has not already bound to a specific upstream.
	policy *policyStore

	// dohCache holds one HTTP client per upstream for DoH queries routed
	// through it, built on first use. See dns_policy.go.
	dohOnce  sync.Once
	dohCache *dohClientCache

	// uidResolver attributes a flow to an application, or nil when the platform
	// has not installed one. Guarded by uidMu.
	uidMu       sync.RWMutex
	uidResolver UIDResolver

	dataDir         string
	stateStoreFor   func(string) ipn.StateStore
	callback        EngineCallback
	exitNodeTailnet string

	subnets []subnetRoute

	events   chan engineEvent
	eventsWg sync.WaitGroup

	// VPN Lifecycle
	vpnMu        sync.Mutex
	vpnStack     *stack.Stack
	vpnFD        int
	addrRefCount map[netip.Addr]int

	upstreamDNS string

	// Target Directory & DNS State
	targetMutex      sync.RWMutex
	tailnetSnapshots map[UpstreamID][]TargetRecord
	targets          map[netip.Addr]TargetRecord
	dnsTable         map[string][]netip.Addr
	baseDnsTable     map[string][]netip.Addr
	dnsTableV4       map[string][]netip.Addr
	baseDnsTableV4   map[string][]netip.Addr

	// syntheticV4 maps a peer's synthetic IPv4 address to its record, and
	// syntheticV4ByKey is the reverse, kept across rebuilds so a peer's v4
	// address doesn't move while apps hold connections to it.
	syntheticV4      map[netip.Addr]TargetRecord
	syntheticV4ByKey map[TargetKey]netip.Addr

	// realIPIndex maps a peer's real (non-synthetic) Tailscale IP to every
	// upstream that currently reports a peer at that address. Real Tailscale
	// address space (the 100.64.0.0/10 CGNAT range and Tailscale's IPv6 ULA
	// range) is drawn from the same pool for every tailnet, so the same real
	// IP can legitimately belong to different peers on different
	// simultaneously-active upstreams; a >1-length entry here is a genuine
	// crossover, not a bug, and is resolved best-effort in resolveRoute (see
	// validation_and_gaps.md for why this exists: some apps are handed a
	// peer's real IP directly - e.g. TURN/STUN server config - rather than a
	// hostname that would resolve through our synthetic DNS).
	realIPIndex map[netip.Addr][]TargetRecord
}

func NewEngine(dataDir string, cb EngineCallback) *Engine {
	return NewEngineWithStateStore(dataDir, cb, nil)
}

// NewEngineWithStateStore configures an optional isolated StateStore for each upstream.
func NewEngineWithStateStore(dataDir string, cb EngineCallback, stateStoreFor func(string) ipn.StateStore) *Engine {
	e := &Engine{
		state:         StateOpen,
		tailnets:      make(map[UpstreamID]*TailnetRuntime),
		exitNodes:     make(map[UpstreamID]*ExitNodeRuntime),
		subnets:       make([]subnetRoute, 0),
		dataDir:       dataDir,
		stateStoreFor: stateStoreFor,
		callback:      cb,
		vpnFD:         -1,
		events:        make(chan engineEvent, 1024),

		tailnetSnapshots: make(map[UpstreamID][]TargetRecord),
		targets:          make(map[netip.Addr]TargetRecord),
		syntheticV4:      make(map[netip.Addr]TargetRecord),
		syntheticV4ByKey: make(map[TargetKey]netip.Addr),
		dnsTable:         make(map[string][]netip.Addr),
		dnsTableV4:       make(map[string][]netip.Addr),
		baseDnsTableV4:   make(map[string][]netip.Addr),
		baseDnsTable:     make(map[string][]netip.Addr),
		realIPIndex:      make(map[netip.Addr][]TargetRecord),

		upstreams: newUpstreamRegistry(),
		stats:     newStatsRegistry(),
		policy:    &policyStore{},
	}

	// Tailnets are dialable upstreams too, but their lifecycle belongs to the
	// tailnet machinery rather than the registry, so they plug in as a source
	// instead of being registered. See upstream_tailnet.go.
	e.upstreams.AddSource(&tailnetSource{engine: e})

	// Exit-node upstreams have their own lifecycle too, for the same reason
	// tailnets do - see upstream_exitnode.go.
	e.upstreams.AddSource(&exitNodeSource{engine: e})

	e.eventsWg.Add(1)
	go e.dispatchEvents()

	return e
}

func (e *Engine) dispatchEvents() {
	defer e.eventsWg.Done()
	for ev := range e.events {
		e.mu.RLock()
		cb := e.callback
		e.mu.RUnlock()

		if cb == nil {
			continue
		}

		e.dispatchOneEvent(cb, ev)
	}
}

// dispatchOneEvent invokes the single callback method for ev. This crosses
// the gomobile/JNI boundary into Java on every call, on whatever OS thread
// this goroutine currently happens to be scheduled on; it is wrapped in its
// own recover so that a panic on the Java side (or in the generated JNI glue
// itself) is logged and dropped instead of taking down the whole process,
// the same containment already applied to every other JNI entry point in
// this engine (see AcquireAndroidNetworkHooks in backend.go).
func (e *Engine) dispatchOneEvent(cb EngineCallback, ev engineEvent) {
	defer recoverAndLog("dispatchEvents callback")
	switch ev.kind {
	case eventPeerDiscovered:
		cb.OnPeerDiscovered(ev.hostname, ev.ipv4, ev.ipv6, ev.tailnetID)
	case eventAddressCrossover:
		cb.OnAddressCrossover(ev.crossoverIP, ev.crossoverCandidates, ev.crossoverChosen)
	case eventUpstreamHealthChanged:
		cb.OnUpstreamHealthChanged(ev.healthUpstreamID, ev.healthReady, ev.healthReason)
	default:
		cb.OnTailnetStateChange(ev.tailnetID, ev.stateStr)
	}
}

func (e *Engine) enqueueStateEvent(tailnetID, state string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != StateOpen {
		return
	}
	select {
	case e.events <- engineEvent{
		kind:      eventTailnetStateChange,
		tailnetID: tailnetID,
		stateStr:  state,
	}:
	default:
	}
}

func (e *Engine) enqueuePeerEvent(hostname, v4, v6, tailnetID string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != StateOpen {
		return
	}
	select {
	case e.events <- engineEvent{
		kind:      eventPeerDiscovered,
		hostname:  hostname,
		ipv4:      v4,
		ipv6:      v6,
		tailnetID: tailnetID,
	}:
	default:
	}
}

// enqueueAddressCrossover records that a real Tailscale IP was found on more
// than one active upstream at once during routing, and which one was picked.
// candidates is every UpstreamID that claimed the address, already
// deterministically ordered by the caller.
func (e *Engine) enqueueAddressCrossover(ip string, candidates []UpstreamID, chosen UpstreamID) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != StateOpen {
		return
	}

	strs := make([]string, len(candidates))
	for i, c := range candidates {
		strs[i] = string(c)
	}

	select {
	case e.events <- engineEvent{
		kind:                eventAddressCrossover,
		crossoverIP:         ip,
		crossoverCandidates: strings.Join(strs, ","),
		crossoverChosen:     string(chosen),
	}:
	default:
	}
}

// enqueueUpstreamHealthEvent records that an upstream's readiness changed.
// See UpstreamStats.setReady (stats.go): callers only reach here on an actual
// transition, so this does not need its own throttling.
func (e *Engine) enqueueUpstreamHealthEvent(id UpstreamID, ready bool, reason string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state != StateOpen {
		return
	}
	select {
	case e.events <- engineEvent{
		kind:             eventUpstreamHealthChanged,
		healthUpstreamID: string(id),
		healthReady:      ready,
		healthReason:     reason,
	}:
	default:
	}
}

// SetUpstreamDNS sets the resolver used for names that aren't answered from
// the synthetic peer table - either a plain "host[:port]" DNS server (e.g.
// the network's own resolver, port defaults to 53) or a DNS-over-HTTPS
// resolver URL (e.g. a user-selected public DoH provider like
// "https://cloudflare-dns.com/dns-query"). Everything else in this engine
// only ever needs a Tailscale peer's own resolver setup for tailnet names;
// this is specifically the escape hatch for non-tailnet names, which is why
// it's the one place DoH matters here.
func (e *Engine) SetUpstreamDNS(dns string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return
	}

	dns = strings.TrimSpace(dns)
	if dns == "" {
		e.upstreamDNS = ""
		return
	}

	if strings.HasPrefix(dns, "https://") {
		u, err := url.Parse(dns)
		if err != nil || u.Host == "" {
			// Invalid DoH URL, ignore rather than silently disabling
			// upstream DNS entirely for an obviously malformed value.
			return
		}
		e.upstreamDNS = dns
		setBootstrapDoHBase(dns)
		return
	}

	host, port, err := net.SplitHostPort(dns)
	if err != nil {
		// Missing port
		host = dns
		port = "53"
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Invalid IP/Host, ignore
		return
	}

	if ip.String() == SyntheticIPv6DNS.String() {
		// Reject self-DNS
		return
	}

	e.upstreamDNS = net.JoinHostPort(ip.String(), port)
	setBootstrapDoHBase("")
	setBootstrapPlainDNS(e.upstreamDNS)
}

// SetBootstrapDNS records the plain resolver the underlying network was using
// before our VPN replaced the device's DNS. It must keep being called even
// when a DoH resolver is selected, because resolving that DoH server's own
// hostname cannot go through our synthetic resolver without deadlocking
// against the very query it is trying to answer.
func (e *Engine) SetBootstrapDNS(dns string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return
	}

	dns = strings.TrimSpace(dns)
	if dns == "" {
		return
	}

	host, port, err := net.SplitHostPort(dns)
	if err != nil {
		host = dns
		port = "53"
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.String() == SyntheticIPv6DNS.String() {
		return
	}

	setBootstrapPlainDNS(net.JoinHostPort(ip.String(), port))
}

func (e *Engine) SetExitNode(tailnetID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return
	}
	e.exitNodeTailnet = tailnetID
}

func (e *Engine) AcceptSubnet(cidr string, tailnetID string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	prefix = prefix.Masked()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return errors.New("engine is closing or closed")
	}

	for _, sr := range e.subnets {
		if sr.Prefix == prefix {
			if sr.TailnetID == tailnetID {
				return nil
			}
			return fmt.Errorf("exact prefix %s already owned by %s", cidr, sr.TailnetID)
		}
	}

	e.subnets = append(e.subnets, subnetRoute{Prefix: prefix, TailnetID: tailnetID})
	return nil
}

func (e *Engine) RemoveSubnet(cidr string) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	prefix = prefix.Masked()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return
	}

	filtered := e.subnets[:0]
	for _, sr := range e.subnets {
		if sr.Prefix != prefix {
			filtered = append(filtered, sr)
		}
	}
	e.subnets = filtered
}

func getStableHash(identifier string) string {
	h := sha256.Sum256([]byte(identifier))
	return hex.EncodeToString(h[:16]) // 32 characters
}

func (e *Engine) AddTailnet(identifier string, authKey string, enabled bool) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	e.mu.Lock()
	if e.state != StateOpen {
		e.mu.Unlock()
		return errors.New("engine is closing or closed")
	}
	uid := UpstreamID(identifier)
	if _, exists := e.tailnets[uid]; exists {
		e.mu.Unlock()
		return errors.New("tailnet already exists with this identifier")
	}

	hashID := getStableHash(identifier)
	stateDir := fmt.Sprintf("%s/state-%s", e.dataDir, hashID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		e.mu.Unlock()
		return fmt.Errorf("failed to create state dir: %v", err)
	}

	e.tailnets[uid] = &TailnetRuntime{
		Config: TailnetConfig{
			Identifier: identifier,
			AuthKey:    authKey,
			HashID:     hashID,
			StateDir:   stateDir,
		},
		Enabled: false,
	}
	e.mu.Unlock()

	if enabled {
		return e.setTailnetEnabledLocked(identifier, true)
	}
	return nil
}

func (e *Engine) SetTailnetEnabled(identifier string, enabled bool) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()
	return e.setTailnetEnabledLocked(identifier, enabled)
}

func (e *Engine) setTailnetEnabledLocked(identifier string, enabled bool) error {
	e.mu.Lock()
	if e.state != StateOpen {
		e.mu.Unlock()
		return errors.New("engine is closing or closed")
	}

	uid := UpstreamID(identifier)
	rt, exists := e.tailnets[uid]
	if !exists {
		e.mu.Unlock()
		return errors.New("tailnet not found")
	}

	if rt.Enabled == enabled {
		e.mu.Unlock()
		return nil
	}

	if !enabled {
		if rt.Cancel != nil {
			rt.Cancel()
			rt.Cancel = nil
		}
		wg := rt.Wg
		rt.Wg = nil
		srv := rt.Srv
		rt.Srv = nil
		rt.Enabled = false
		e.mu.Unlock()

		if wg != nil {
			wg.Wait()
		}
		if srv != nil {
			srv.Close()
		}

		e.targetMutex.Lock()
		delete(e.tailnetSnapshots, uid)
		e.rebuildTargetsUnlocked()
		e.targetMutex.Unlock()

		e.enqueueStateEvent(identifier, "STOPPED")
		return nil
	}

	rt.Srv = &tsnet.Server{
		Dir:      rt.Config.StateDir,
		AuthKey:  rt.Config.AuthKey,
		Hostname: fmt.Sprintf("mp-%s", rt.Config.HashID),
		Logf:     func(fmt string, args ...any) {},
	}
	if e.stateStoreFor != nil {
		rt.Srv.Store = e.stateStoreFor(identifier)
	}

	// A panic synchronous with this call (as opposed to one in a goroutine
	// tsnet spins up internally, which this can't catch) is treated as a
	// startup failure for this upstream rather than taking down the whole
	// multi-tailnet process.
	localClientErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				trace := debug.Stack()
				if len(trace) > 4096 {
					trace = trace[:4096]
				}
				log.Printf("[VPN] recovered panic starting tsnet for %s: %v\n%s", identifier, r, trace)
				err = fmt.Errorf("recovered panic in tsnet startup: %v", r)
			}
		}()
		_, err = rt.Srv.LocalClient()
		return err
	}()
	if localClientErr != nil {
		rt.Srv.Close()
		rt.Srv = nil
		e.mu.Unlock()
		e.enqueueStateEvent(identifier, "ERROR")
		return fmt.Errorf("failed to start tsnet: %v", localClientErr)
	}

	rt.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	rt.Cancel = cancel

	wg := &sync.WaitGroup{}
	wg.Add(1)
	rt.Wg = wg

	srv := rt.Srv
	e.mu.Unlock()

	e.enqueueStateEvent(identifier, "STARTING")
	go e.pollTailnetStatus(ctx, wg, uid, srv)

	return nil
}

func (e *Engine) RemoveTailnet(identifier string) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	uid := UpstreamID(identifier)
	e.mu.Lock()
	rt, exists := e.tailnets[uid]
	if !exists {
		e.mu.Unlock()
		return errors.New("tailnet not found")
	}
	delete(e.tailnets, uid)
	e.mu.Unlock()

	if rt.Enabled {
		if rt.Cancel != nil {
			rt.Cancel()
		}
		if rt.Wg != nil {
			rt.Wg.Wait()
		}
		if rt.Srv != nil {
			rt.Srv.Close()
		}
	}

	e.mu.Lock()
	filtered := e.subnets[:0]
	for _, sr := range e.subnets {
		if sr.TailnetID != identifier {
			filtered = append(filtered, sr)
		}
	}
	e.subnets = filtered

	if e.exitNodeTailnet == identifier {
		e.exitNodeTailnet = ""
	}
	e.mu.Unlock()

	e.targetMutex.Lock()
	delete(e.tailnetSnapshots, uid)
	e.rebuildTargetsUnlocked()
	e.targetMutex.Unlock()

	e.enqueueStateEvent(identifier, "REMOVED")

	return nil
}

func (e *Engine) pollTailnetStatus(ctx context.Context, wg *sync.WaitGroup, uid UpstreamID, srv *tsnet.Server) {
	defer wg.Done()
	defer recoverAndLog("pollTailnetStatus")
	lc, err := srv.LocalClient()
	if err != nil {
		return
	}
	lastState := ""

	doPoll := func() {
		status, err := lc.Status(ctx)
		if err == nil && status != nil {
			if status.BackendState != lastState {
				lastState = status.BackendState
				e.enqueueStateEvent(string(uid), status.BackendState)
				if status.BackendState == ipn.Running.String() {
					// One-time bootstrap credential, never read again once
					// this Tailnet's tsnet.Server has actually reached
					// Running - see ClearTailnetAuthKey's doc comment.
					e.ClearTailnetAuthKey(string(uid))
				}
			}

			var snapshot []TargetRecord
			for _, peer := range status.Peer {
				if peer.ID == "" {
					continue
				}

				key := TargetKey{
					NamespaceID: uid,
					Kind:        TargetKindTailscaleNode,
					StableID:    string(peer.ID),
				}

				rec := TargetRecord{
					Key:              key,
					SyntheticIPv6:    key.SyntheticIPv6(),
					Hostname:         peer.DNSName,
					RequiredUpstream: uid,
				}

				for _, ip := range peer.TailscaleIPs {
					if ip.Is4() {
						rec.CurrentIPv4 = ip
					} else if ip.Is6() {
						rec.CurrentIPv6 = ip
					}
				}

				snapshot = append(snapshot, rec)
			}

			accepted := e.updateTailnetSnapshot(uid, snapshot)

			for _, rec := range accepted {
				e.enqueuePeerEvent(rec.Hostname, "", rec.SyntheticIPv6.String(), string(uid))
			}
		}
	}

	doPoll()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doPoll()
		}
	}
}

// Close gracefully shuts down the Engine and all its components.
// Close gracefully shuts down the Engine and all its components.
func (e *Engine) Close() {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	e.mu.Lock()
	if e.state != StateOpen {
		e.mu.Unlock()
		return
	}
	e.state = StateClosing
	var ids []string
	for uid := range e.tailnets {
		ids = append(ids, string(uid))
	}
	var exitIDs []string
	for uid := range e.exitNodes {
		exitIDs = append(exitIDs, string(uid))
	}
	e.mu.Unlock()

	e.StopVPN()

	for _, id := range ids {
		uid := UpstreamID(id)
		e.mu.Lock()
		rt := e.tailnets[uid]
		delete(e.tailnets, uid)
		e.mu.Unlock()

		if rt.Enabled {
			if rt.Cancel != nil {
				rt.Cancel()
			}
			if rt.Wg != nil {
				rt.Wg.Wait()
			}
			if rt.Srv != nil {
				rt.Srv.Close()
			}
		}
	}

	for _, id := range exitIDs {
		uid := UpstreamID(id)
		e.mu.Lock()
		rt := e.exitNodes[uid]
		delete(e.exitNodes, uid)
		e.mu.Unlock()

		if rt.Enabled {
			if rt.Cancel != nil {
				rt.Cancel()
			}
			if rt.Wg != nil {
				rt.Wg.Wait()
			}
			if rt.Srv != nil {
				rt.Srv.Close()
			}
		}
	}

	e.mu.Lock()
	close(e.events)
	e.mu.Unlock()

	e.eventsWg.Wait()

	e.mu.Lock()
	e.callback = nil
	e.state = StateClosed
	e.mu.Unlock()
}

// GetTargetsJSON returns the current targets across all tailnets.
func (e *Engine) GetTargetsJSON() string {
	e.targetMutex.RLock()
	defer e.targetMutex.RUnlock()

	type PeerExport struct {
		TailnetID        string `json:"tailnetId"`
		Hostname         string `json:"hostname"`
		CurrentIPv4      string `json:"currentIpv4"`
		CurrentIPv6      string `json:"currentIpv6"`
		SyntheticDNSName string `json:"syntheticDnsName"`
		SyntheticIPv6    string `json:"syntheticIpv6"`
		Kind             string `json:"kind"`
	}

	var out []PeerExport
	for _, rec := range e.targets {
		out = append(out, PeerExport{
			TailnetID:        string(rec.RequiredUpstream),
			Hostname:         rec.Hostname,
			CurrentIPv4:      rec.CurrentIPv4.String(),
			CurrentIPv6:      rec.CurrentIPv6.String(),
			SyntheticDNSName: fmt.Sprintf("%s.%s.proxy.", rec.Hostname, getStableHash(string(rec.RequiredUpstream))),
			SyntheticIPv6:    rec.SyntheticIPv6.String(),
			Kind:             string(rec.Key.Kind),
		})
	}

	b, _ := json.Marshal(out)
	return string(b)
}

// ForgetTailnet disables the tailnet, removes it from the engine, and permanently deletes its state directory.
func (e *Engine) ForgetTailnet(identifier string) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	e.mu.Lock()
	uid := UpstreamID(identifier)
	rt, exists := e.tailnets[uid]
	if !exists {
		e.mu.Unlock()
		return errors.New("tailnet not found")
	}

	// Disable it to stop the watcher and server
	rt.Enabled = false
	if rt.Cancel != nil {
		rt.Cancel()
	}
	if rt.Srv != nil {
		rt.Srv.Close()
	}

	delete(e.tailnets, uid)
	e.mu.Unlock()

	e.updateTailnetSnapshot(uid, nil)

	stateDir := fmt.Sprintf("%s/state-%s", e.dataDir, getStableHash(identifier))
	return os.RemoveAll(stateDir)
}
