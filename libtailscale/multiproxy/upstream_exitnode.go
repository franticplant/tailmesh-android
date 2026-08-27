package multiproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"sort"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// Exit-node upstreams.
//
// A configured Tailnet upstream reaches that tailnet's own peers, but nothing
// about it lets an app route ordinary internet traffic through one specific
// peer acting as an exit node - Tailscale's own exit-node selection
// (Prefs.ExitNodeIP) is a whole-node preference, one at a time, so the
// tailnet's own tsnet.Server can't simultaneously be "my route to peer A" and
// "my route to the internet via exit node B" for two different apps.
//
// So an exit-node upstream is its own dedicated tsnet.Server - a second node
// identity logged into a tailnet (its own AuthKey, its own state directory,
// its own device slot in the admin console), whose only preference of note is
// ExitNodeIP pinned to the chosen peer. That makes it a Dial-only conduit,
// exactly like a WireGuard upstream: it does not participate in synthetic
// addressing or peer discovery (unlike a real Tailnet upstream), it is just
// something the policy engine can point a rule at.
//
// This means each exit-node upstream costs a real device slot on whichever
// tailnet it is added against - a cost worth surfacing in the UI, not hiding.

// ExitNodeConfig is what an exit-node upstream is configured with.
type ExitNodeConfig struct {
	Identifier      string
	SourceTailnetID string // which existing tailnet this peer was picked from; informational only
	AuthKey         string // a fresh key for this upstream's own dedicated node identity
	PeerAddr        string // the exit-node peer's Tailscale IP, as text
	HashID          string
	StateDir        string
}

// ExitNodeRuntime is the live state of one exit-node upstream, mirroring
// TailnetRuntime.
type ExitNodeRuntime struct {
	Config  ExitNodeConfig
	Srv     *tsnet.Server
	Cancel  context.CancelFunc
	Enabled bool
}

// maxExitNodeUpstreams bounds how many dedicated exit-node identities
// (upstream_exitnode.go's Option B) may be configured at once. Each one is a
// full tsnet.Server - its own netstack, magicsock, DERP connections and
// control-plane session - which is real memory, CPU and battery cost on a
// mobile device, unlike the free, in-place SetTailnetExitNode path
// (upstream_tailnet.go). Mirrors maxChainDepth (chain.go) as a familiar,
// generous-but-not-unbounded limit: enough for genuinely wanting several
// exit nodes live at once, not enough to let a mistake (or a script) spin up
// an unbounded number of new devices against the same tailnet's admin
// console.
const maxExitNodeUpstreams = 8

// AddExitNodeUpstream registers a new exit-node upstream. sourceTailnetID
// names the already-configured tailnet the peer was picked from (see
// GetExitNodeCandidatesJSON); it is not consulted again after this call, so
// removing that tailnet later does not affect an exit-node upstream already
// built from one of its peers.
func (e *Engine) AddExitNodeUpstream(identifier, sourceTailnetID, authKey, peerAddr string, enabled bool) error {
	if _, err := netip.ParseAddr(peerAddr); err != nil {
		return fmt.Errorf("invalid exit node peer address %q: %w", peerAddr, err)
	}

	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	e.mu.Lock()
	if e.state != StateOpen {
		e.mu.Unlock()
		return errors.New("engine is closing or closed")
	}
	uid := UpstreamID(identifier)
	if _, exists := e.exitNodes[uid]; exists {
		e.mu.Unlock()
		return errors.New("exit node upstream already exists with this identifier")
	}
	if _, exists := e.tailnets[uid]; exists {
		e.mu.Unlock()
		return errors.New("identifier collides with a tailnet")
	}
	if len(e.exitNodes) >= maxExitNodeUpstreams {
		e.mu.Unlock()
		return fmt.Errorf("multiproxy: at most %d exit-node upstreams may be configured at once", maxExitNodeUpstreams)
	}

	hashID := getStableHash("exitnode-" + identifier)
	stateDir := fmt.Sprintf("%s/state-%s", e.dataDir, hashID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		e.mu.Unlock()
		return fmt.Errorf("failed to create state dir: %v", err)
	}

	e.exitNodes[uid] = &ExitNodeRuntime{
		Config: ExitNodeConfig{
			Identifier:      identifier,
			SourceTailnetID: sourceTailnetID,
			AuthKey:         authKey,
			PeerAddr:        peerAddr,
			HashID:          hashID,
			StateDir:        stateDir,
		},
		Enabled: false,
	}
	e.mu.Unlock()

	if enabled {
		return e.setExitNodeEnabledLocked(identifier, true)
	}
	return nil
}

func (e *Engine) SetExitNodeUpstreamEnabled(identifier string, enabled bool) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()
	return e.setExitNodeEnabledLocked(identifier, enabled)
}

func (e *Engine) setExitNodeEnabledLocked(identifier string, enabled bool) error {
	e.mu.Lock()
	if e.state != StateOpen {
		e.mu.Unlock()
		return errors.New("engine is closing or closed")
	}

	uid := UpstreamID(identifier)
	rt, exists := e.exitNodes[uid]
	if !exists {
		e.mu.Unlock()
		return errors.New("exit node upstream not found")
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
		srv := rt.Srv
		rt.Srv = nil
		rt.Enabled = false
		e.mu.Unlock()

		if srv != nil {
			srv.Close()
		}
		e.enqueueStateEvent(identifier, "STOPPED")
		return nil
	}

	rt.Srv = &tsnet.Server{
		Dir:      rt.Config.StateDir,
		AuthKey:  rt.Config.AuthKey,
		Hostname: fmt.Sprintf("mp-exit-%s", rt.Config.HashID),
		Logf:     func(fmt string, args ...any) {},
	}
	if e.stateStoreFor != nil {
		rt.Srv.Store = e.stateStoreFor("exitnode-" + identifier)
	}

	// Mirrors the tailnet startup path in setTailnetEnabledLocked: a panic
	// synchronous with this call is a startup failure for this one upstream,
	// not the whole engine.
	localClientErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				trace := debug.Stack()
				if len(trace) > 4096 {
					trace = trace[:4096]
				}
				log.Printf("[VPN] recovered panic starting exit node tsnet for %s: %v\n%s", identifier, r, trace)
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
	srv := rt.Srv
	peerAddr := rt.Config.PeerAddr
	e.mu.Unlock()

	// Pin this node's exit-node preference to the chosen peer. This is a
	// local prefs write, not a control-plane round trip, so it does not need
	// connectivity to succeed - but it can still be slow or fail (a corrupt
	// state store, e.g.), so it is bounded and its failure is reported
	// rather than left to surface later as an unexplained "not ready".
	go func() {
		editCtx, editCancel := context.WithTimeout(ctx, 10*time.Second)
		defer editCancel()
		lc, err := srv.LocalClient()
		if err != nil {
			e.enqueueStateEvent(identifier, "ERROR")
			return
		}
		addr, err := netip.ParseAddr(peerAddr)
		if err != nil {
			e.enqueueStateEvent(identifier, "ERROR")
			return
		}
		_, err = lc.EditPrefs(editCtx, &ipn.MaskedPrefs{
			Prefs: ipn.Prefs{
				ExitNodeIP:  addr,
				WantRunning: true,
			},
			ExitNodeIPSet:  true,
			WantRunningSet: true,
		})
		if err != nil {
			e.enqueueStateEvent(identifier, "ERROR")
			return
		}
		e.enqueueStateEvent(identifier, "RUNNING")
	}()

	return nil
}

// ForgetExitNodeUpstream disables the exit-node upstream, removes it from the
// engine, and permanently deletes its state directory - including the node
// identity it logged into the tailnet with, which the admin console will
// still show as a stale device until removed there too.
func (e *Engine) ForgetExitNodeUpstream(identifier string) error {
	e.tailnetLifecycleMu.Lock()
	defer e.tailnetLifecycleMu.Unlock()

	e.mu.Lock()
	uid := UpstreamID(identifier)
	rt, exists := e.exitNodes[uid]
	if !exists {
		e.mu.Unlock()
		return errors.New("exit node upstream not found")
	}
	rt.Enabled = false
	if rt.Cancel != nil {
		rt.Cancel()
	}
	if rt.Srv != nil {
		rt.Srv.Close()
	}
	delete(e.exitNodes, uid)
	stateDir := rt.Config.StateDir
	e.mu.Unlock()

	return os.RemoveAll(stateDir)
}

// ExitNodeCandidate is one peer of an already-configured, ready tailnet that
// is eligible to be used as an exit node.
type ExitNodeCandidate struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	DNSName  string `json:"dnsName"`
	IP       string `json:"ip"`
}

// GetExitNodeCandidatesJSON lists the peers of an already-configured, running
// tailnet that offer to be an exit node (advertised and approved). The
// tailnet named by tailnetIdentifier must already be enabled and connected;
// this does not start one.
//
// This only reflects what that tailnet's own netmap currently reports, which
// means it can be empty even when a peer really is eligible, if that peer's
// exit-node advertisement hasn't propagated yet - a transient gap, not a
// wrong answer.
func (e *Engine) GetExitNodeCandidatesJSON(tailnetIdentifier string) string {
	e.mu.RLock()
	rt, exists := e.tailnets[UpstreamID(tailnetIdentifier)]
	e.mu.RUnlock()
	if !exists || !rt.Enabled || rt.Srv == nil {
		return "[]"
	}

	lc, err := rt.Srv.LocalClient()
	if err != nil {
		return "[]"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil {
		return "[]"
	}

	var out []ExitNodeCandidate
	for _, ps := range st.Peer {
		if !ps.ExitNodeOption || len(ps.TailscaleIPs) == 0 {
			continue
		}
		out = append(out, ExitNodeCandidate{
			ID:       string(ps.ID),
			Hostname: ps.HostName,
			DNSName:  ps.DNSName,
			IP:       ps.TailscaleIPs[0].String(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })

	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

func (e *Engine) activeExitNodeServer(id UpstreamID) (*tsnet.Server, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rt, exists := e.exitNodes[id]
	if exists && rt.Enabled && rt.Srv != nil {
		return rt.Srv, true
	}
	return nil, false
}

// exitNodeProvider adapts one exit-node upstream's dedicated tsnet.Server to
// Provider. Like tailnetProvider it holds the Engine and an id rather than the
// server itself, so enabling, disabling or forgetting it at runtime is
// observed on the next dial. Unlike tailnetProvider it does not participate
// in synthetic addressing: it exists purely to be Dialed.
type exitNodeProvider struct {
	engine *Engine
	id     UpstreamID
}

func (p *exitNodeProvider) ID() UpstreamID     { return p.id }
func (p *exitNodeProvider) Kind() UpstreamKind { return UpstreamKindExitNode }
func (p *exitNodeProvider) Close() error       { return nil }

func (p *exitNodeProvider) Ready() bool {
	_, ok := p.engine.activeExitNodeServer(p.id)
	return ok
}

func (p *exitNodeProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	srv, ok := p.engine.activeExitNodeServer(p.id)
	if !ok {
		return nil, fmt.Errorf("%w: exit node %q", ErrUpstreamNotReady, p.id)
	}
	return srv.Dial(ctx, network, address)
}

func (p *exitNodeProvider) PeerPathInfo(ctx context.Context, destIP string) string {
	srv, ok := p.engine.activeExitNodeServer(p.id)
	if !ok {
		return "unknown"
	}
	return (&tsnetUpstream{srv: srv}).PeerPathInfo(ctx, destIP)
}

// exitNodeSource exposes the Engine's configured exit-node upstreams to the
// registry, the same way tailnetSource does for tailnets.
type exitNodeSource struct {
	engine *Engine
}

func (s *exitNodeSource) Get(id UpstreamID) (Provider, bool) {
	e := s.engine
	e.mu.RLock()
	_, ok := e.exitNodes[id]
	e.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return &exitNodeProvider{engine: e, id: id}, true
}

func (s *exitNodeSource) List() []Provider {
	e := s.engine
	e.mu.RLock()
	out := make([]Provider, 0, len(e.exitNodes))
	for id := range e.exitNodes {
		out = append(out, &exitNodeProvider{engine: e, id: id})
	}
	e.mu.RUnlock()
	return out
}
