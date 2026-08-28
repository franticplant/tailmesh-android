package multiproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// Tailnet upstreams.
//
// A tailnet is an upstream like any other as far as the datapath and the policy
// engine are concerned: something you can Dial through. It differs in who owns
// it. SOCKS5 and WireGuard upstreams are created by, and belong to, the
// registry; tailnets are created, enabled, disabled and torn down by the
// tailnet machinery in api.go and merely happen to also be dialable.
//
// So rather than the registry holding tailnets - which would mean two places to
// keep in sync every time a tailnet is added or forgotten - it holds a source
// that reads Engine.tailnets on demand. The tailnet lifecycle stays the single
// source of truth, and everything downstream still sees one uniform set of
// upstreams.
//
// Tailnets are also the one kind that participates in synthetic addressing and
// peer discovery. That asymmetry lives in the routing layer, which knows about
// synthetic namespaces; it is deliberately not visible through Provider.

// tailnetProvider adapts a tsnet.Server to Provider. It holds the Engine and an
// id rather than the server itself, so that enabling, disabling or replacing a
// tailnet at runtime is observed on the next dial instead of being captured at
// registration time.
type tailnetProvider struct {
	engine *Engine
	id     UpstreamID
}

func (p *tailnetProvider) ID() UpstreamID     { return p.id }
func (p *tailnetProvider) Kind() UpstreamKind { return UpstreamKindTailnet }

// Close is a no-op: the tsnet.Server behind this provider belongs to the
// Engine's tailnet lifecycle, not to whoever holds the provider.
func (p *tailnetProvider) Close() error { return nil }

func (p *tailnetProvider) server() (*tsnet.Server, bool) {
	return p.engine.activeTailnetServer(p.id)
}

func (p *tailnetProvider) Ready() bool {
	_, ok := p.server()
	return ok
}

func (p *tailnetProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	srv, ok := p.server()
	if !ok {
		return nil, fmt.Errorf("%w: tailnet %q", ErrUpstreamNotReady, p.id)
	}
	return srv.Dial(ctx, network, address)
}

func (p *tailnetProvider) PeerPathInfo(ctx context.Context, destIP string) string {
	srv, ok := p.server()
	if !ok {
		return "unknown"
	}
	return (&tsnetUpstream{srv: srv}).PeerPathInfo(ctx, destIP)
}

// SetTailnetExitNode points an already-running tailnet upstream's own general
// (non-tailnet-destination) traffic at one of its peers, in place - no second
// node identity, no extra device slot, unlike an exit-node upstream
// (upstream_exitnode.go). This is the cheap path: it works for exactly one
// active exit node per tailnet, because Prefs.ExitNodeIP is a whole-server
// preference. Reach for AddExitNodeUpstream instead when a second,
// simultaneously-active exit node is needed out of the same tailnet.
//
// An empty peerAddr clears the exit node, so the tailnet upstream goes back
// to only being usable for its own peers.
func (e *Engine) SetTailnetExitNode(tailnetIdentifier, peerAddr string) error {
	e.mu.RLock()
	rt, exists := e.tailnets[UpstreamID(tailnetIdentifier)]
	e.mu.RUnlock()
	if !exists || !rt.Enabled || rt.Srv == nil {
		return fmt.Errorf("tailnet %q is not running", tailnetIdentifier)
	}

	lc, err := rt.Srv.LocalClient()
	if err != nil {
		return err
	}

	// Setting ExitNodeIDSet alongside ExitNodeIPSet is how localAPI callers
	// explicitly *clear* the exit node (ipnlocal's adjustEditPrefsLocked
	// treats ExitNodeIDSet+empty-ID as "zero the exit node"), so it must only
	// be set for the clear case. Selecting a real exit node by IP must set
	// only ExitNodeIPSet and leave ExitNodeIDSet unset, letting the backend
	// resolve ExitNodeID from the netmap - the same pattern ipn/conf.go uses
	// for IP-based exit node selection. Setting both together (as this code
	// used to) stamped ExitNodeID back to "" in the same edit that set the
	// IP, so the selection was cleared the instant it was made.
	mp := &ipn.MaskedPrefs{}
	if peerAddr == "" {
		mp.ExitNodeIDSet = true
	} else {
		addr, err := netip.ParseAddr(peerAddr)
		if err != nil {
			return fmt.Errorf("invalid exit node peer address %q: %w", peerAddr, err)
		}
		mp.Prefs.ExitNodeIP = addr
		mp.ExitNodeIPSet = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

// tailnetSource exposes the Engine's configured tailnets to the registry.
type tailnetSource struct {
	engine *Engine
}

func (s *tailnetSource) Get(id UpstreamID) (Provider, bool) {
	e := s.engine
	e.mu.RLock()
	_, ok := e.tailnets[id]
	e.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return &tailnetProvider{engine: e, id: id}, true
}

func (s *tailnetSource) List() []Provider {
	e := s.engine
	e.mu.RLock()
	out := make([]Provider, 0, len(e.tailnets))
	for id := range e.tailnets {
		out = append(out, &tailnetProvider{engine: e, id: id})
	}
	e.mu.RUnlock()
	return out
}
