package multiproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"

	"tailscale.com/tsnet"
)

// UpstreamKind names the transport an upstream provides. The datapath never
// switches on it - it only ever calls Dial - but the UI and the policy layer
// need to tell a tailnet apart from a plain proxy, and diagnostics read better
// when a route says what kind of thing it went through.
type UpstreamKind string

const (
	// UpstreamKindTailnet is a tsnet.Server: a full Tailscale node with its own
	// netmap, peers and DERP paths. Only this kind participates in synthetic
	// addressing and peer discovery.
	UpstreamKindTailnet UpstreamKind = "tailnet"

	// UpstreamKindSOCKS5 is any SOCKS5 proxy reachable from the device. This is
	// deliberately the generic escape hatch: Xray-core, sing-box, v2ray and
	// hysteria all expose a local SOCKS5 listener, so supporting this one kind
	// makes every one of them pluggable without vendoring their dependency trees.
	UpstreamKindSOCKS5 UpstreamKind = "socks5"

	// UpstreamKindWireGuard is a userspace WireGuard tunnel terminated in-process.
	UpstreamKindWireGuard UpstreamKind = "wireguard"

	// UpstreamKindDirect dials from the device itself, bypassing every tunnel.
	// It is how a policy expresses "this app does not go through the VPN".
	UpstreamKindDirect UpstreamKind = "direct"
)

// ErrUpstreamNotReady is returned by a Provider whose transport exists but is
// not currently usable, e.g. a tailnet that is configured but disabled. It is
// distinct from "no such upstream" so the policy layer can fail closed on a
// deliberately-disabled upstream instead of silently falling through to a
// different one.
var ErrUpstreamNotReady = errors.New("multiproxy: upstream not ready")

// Provider is a registered, dialable upstream with an identity and a lifecycle.
//
// Upstream (types.go) is the narrow thing the datapath needs - Dial and a path
// hint. Provider adds the parts the registry, policy engine and UI need. Keeping
// them separate means the hot path stays unaware of registration and lifecycle.
type Provider interface {
	Upstream

	ID() UpstreamID
	Kind() UpstreamKind

	// Ready reports whether Dial can be expected to work right now. A provider
	// that is configured but down returns false rather than failing every dial.
	Ready() bool

	// Close releases the provider's resources. It must be safe to call more than
	// once. Closing a tailnet provider does not stop the underlying tsnet.Server,
	// which the Engine owns separately.
	Close() error
}

// ---------------------------------------------------------------------------
// tailnet provider
// ---------------------------------------------------------------------------

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
func (p *tailnetProvider) Close() error       { return nil }

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

// ---------------------------------------------------------------------------
// direct provider
// ---------------------------------------------------------------------------

// DirectUpstreamID is the reserved identifier for the built-in direct upstream.
// It is always registered and always ready.
const DirectUpstreamID UpstreamID = "@direct"

// directProvider dials straight from the device, outside every tunnel.
//
// Note this leaves the VPN: the resulting socket is protected from the TUN by
// the Android side (VpnService.protect) exactly as the tailnet upstreams' own
// sockets are, so it does not loop back into gVisor.
type directProvider struct {
	dialer net.Dialer
}

func (p *directProvider) ID() UpstreamID     { return DirectUpstreamID }
func (p *directProvider) Kind() UpstreamKind { return UpstreamKindDirect }
func (p *directProvider) Ready() bool        { return true }
func (p *directProvider) Close() error       { return nil }

func (p *directProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return p.dialer.DialContext(ctx, network, address)
}

func (p *directProvider) PeerPathInfo(context.Context, string) string { return "direct-bypass" }

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

// upstreamRegistry holds every non-tailnet provider. Tailnets are not stored
// here: they live in Engine.tailnets with their own lifecycle, and are exposed
// as providers on demand by lookupProvider. Keeping one source of truth per
// upstream kind avoids the two going out of sync when a tailnet is added or
// forgotten.
type upstreamRegistry struct {
	mu        sync.RWMutex
	providers map[UpstreamID]Provider
}

func newUpstreamRegistry() *upstreamRegistry {
	r := &upstreamRegistry{providers: make(map[UpstreamID]Provider)}
	r.providers[DirectUpstreamID] = &directProvider{}
	return r
}

// Register adds or replaces a provider. Replacing closes the old one, so a
// reconfigured upstream does not leak its previous transport.
func (r *upstreamRegistry) Register(p Provider) error {
	if p == nil {
		return errors.New("multiproxy: nil provider")
	}
	id := p.ID()
	if id == "" {
		return errors.New("multiproxy: provider has empty id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, exists := r.providers[id]; exists && old != p {
		_ = old.Close()
	}
	r.providers[id] = p
	return nil
}

// Unregister removes and closes a provider. The built-in direct provider cannot
// be removed.
func (r *upstreamRegistry) Unregister(id UpstreamID) error {
	if id == DirectUpstreamID {
		return errors.New("multiproxy: cannot unregister the direct upstream")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, exists := r.providers[id]
	if !exists {
		return nil
	}
	delete(r.providers, id)
	return p.Close()
}

func (r *upstreamRegistry) Get(id UpstreamID) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// List returns every registered provider, ordered by ID so callers and tests
// see a stable sequence.
func (r *upstreamRegistry) List() []Provider {
	r.mu.RLock()
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

func (r *upstreamRegistry) CloseAll() {
	r.mu.Lock()
	providers := make([]Provider, 0, len(r.providers))
	for id, p := range r.providers {
		if id == DirectUpstreamID {
			continue
		}
		providers = append(providers, p)
		delete(r.providers, id)
	}
	r.mu.Unlock()
	for _, p := range providers {
		_ = p.Close()
	}
}

// ---------------------------------------------------------------------------
// Engine integration
// ---------------------------------------------------------------------------

// lookupProvider resolves an UpstreamID to a Provider, checking the registry
// first and then the tailnet runtimes. A tailnet is only returned when it is
// enabled and running, so a disabled tailnet reads as "exists but not ready"
// rather than being absent.
func (e *Engine) lookupProvider(id UpstreamID) (Provider, bool) {
	if id == "" {
		return nil, false
	}
	if e.upstreams != nil {
		if p, ok := e.upstreams.Get(id); ok {
			return p, true
		}
	}
	e.mu.RLock()
	_, isTailnet := e.tailnets[id]
	e.mu.RUnlock()
	if isTailnet {
		return &tailnetProvider{engine: e, id: id}, true
	}
	return nil, false
}

// readyProvider resolves id and requires it to be usable now. Callers that must
// not silently fall through to a different upstream use this.
func (e *Engine) readyProvider(id UpstreamID) (Provider, bool) {
	p, ok := e.lookupProvider(id)
	if !ok || !p.Ready() {
		return nil, false
	}
	return p, true
}

// RegisterUpstream adds a non-tailnet upstream. Tailnets are added through the
// tailnet lifecycle instead.
func (e *Engine) RegisterUpstream(p Provider) error {
	if e.upstreams == nil {
		return errors.New("multiproxy: engine has no upstream registry")
	}
	if p != nil && p.Kind() == UpstreamKindTailnet {
		return errors.New("multiproxy: register tailnets through the tailnet lifecycle")
	}
	return e.upstreams.Register(p)
}

// UnregisterUpstream removes a non-tailnet upstream.
func (e *Engine) UnregisterUpstream(id UpstreamID) error {
	if e.upstreams == nil {
		return nil
	}
	return e.upstreams.Unregister(id)
}

// UpstreamInfo is a UI-facing snapshot of one upstream.
type UpstreamInfo struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Ready bool   `json:"ready"`
}

// UpstreamSnapshot lists every upstream the policy layer can route to, tailnets
// included, ordered by ID.
func (e *Engine) UpstreamSnapshot() []UpstreamInfo {
	var out []UpstreamInfo
	if e.upstreams != nil {
		for _, p := range e.upstreams.List() {
			out = append(out, UpstreamInfo{ID: string(p.ID()), Kind: string(p.Kind()), Ready: p.Ready()})
		}
	}
	e.mu.RLock()
	ids := make([]UpstreamID, 0, len(e.tailnets))
	for id := range e.tailnets {
		ids = append(ids, id)
	}
	e.mu.RUnlock()
	for _, id := range ids {
		p := &tailnetProvider{engine: e, id: id}
		out = append(out, UpstreamInfo{ID: string(id), Kind: string(p.Kind()), Ready: p.Ready()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
