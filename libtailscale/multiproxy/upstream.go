// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"sync/atomic"
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

	// UpstreamKindExitNode is a dedicated tsnet.Server pinned, via its own
	// Prefs.ExitNodeIP, to route through one specific peer of some tailnet.
	// See upstream_exitnode.go for why this needs its own node identity
	// rather than reusing an existing Tailnet upstream's.
	UpstreamKindExitNode UpstreamKind = "exitnode"
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

// ChainedProvider is a Provider whose own transport runs over another upstream
// rather than straight off the device - a SOCKS5 proxy reached through a
// WireGuard tunnel, say, or a WireGuard tunnel whose handshakes leave through
// an Xray SOCKS5 listener.
//
// Providers that can only ever dial from the device simply do not implement it.
// The registry uses Via to keep the chain graph acyclic; see chain.go.
type ChainedProvider interface {
	Provider

	// Via reports the upstream this provider's own connections are made
	// through. An empty ID means "from the device".
	Via() UpstreamID
}

// providerVia reports p's chain parent, or "" if it has none.
func providerVia(p Provider) UpstreamID {
	if c, ok := p.(ChainedProvider); ok {
		return c.Via()
	}
	return ""
}

// ---------------------------------------------------------------------------
// direct provider
// ---------------------------------------------------------------------------

// DirectUpstreamID is the reserved identifier for the built-in direct upstream.
// It is always registered and always ready.
const DirectUpstreamID UpstreamID = "@direct"

// directProvider dials straight from the device, outside every tunnel.
//
// This must leave through a VpnService-protected socket, exactly like every
// other upstream's own dials (SOCKS5, WireGuard, tailnet) - otherwise, once
// broad capture (RoutingSettings.broadCaptureEnabled) has the VPN intercepting
// ordinary internet traffic, a "direct" dial's own packets get swept back into
// the TUN it was trying to leave, re-enter gVisor as a new, unrelated flow,
// and the original socket sees that as a reset - so the connection dies
// almost immediately after "succeeding" and the caller (an app's own retry
// logic) reconnects in a tight loop. protectedDial is nil until the Android
// side has installed one (see SetDirectDialer); before that, dialing falls
// back to a plain, unprotected net.Dialer; broad capture is off by default,
// so that window matters only if this upstream is dialed before startup
// finishes wiring up the real one.
type directProvider struct {
	protectedDial atomic.Pointer[UpstreamDialer]
}

func (p *directProvider) ID() UpstreamID     { return DirectUpstreamID }
func (p *directProvider) Kind() UpstreamKind { return UpstreamKindDirect }
func (p *directProvider) Ready() bool        { return true }
func (p *directProvider) Close() error       { return nil }

func (p *directProvider) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d := p.protectedDial.Load(); d != nil {
		return (*d)(ctx, network, address)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

func (p *directProvider) PeerPathInfo(context.Context, string) string { return "direct-bypass" }

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

// providerSource supplies providers the registry does not own.
//
// Upstreams whose lifecycle belongs to something else - tailnets, above all,
// which are created, enabled and torn down by the tailnet machinery and merely
// happen to also be dialable - plug in here instead of being special-cased at
// every lookup. Everything downstream of the registry then sees one uniform set
// of upstreams, and adding a new kind of upstream that owns its own lifecycle
// costs one source rather than a branch in each of Get, List and Snapshot.
type providerSource interface {
	// Get resolves an ID this source is responsible for.
	Get(id UpstreamID) (Provider, bool)
	// List returns every provider this source currently offers, in any order.
	List() []Provider
}

// upstreamRegistry is the single lookup path for every upstream, whatever owns
// it. Providers registered directly (SOCKS5, WireGuard, the built-in direct
// upstream) live in providers and are closed by the registry; providers reached
// through a source are owned by that source and are never closed here.
type upstreamRegistry struct {
	mu        sync.RWMutex
	providers map[UpstreamID]Provider
	sources   []providerSource
	direct    *directProvider
}

func newUpstreamRegistry() *upstreamRegistry {
	direct := &directProvider{}
	r := &upstreamRegistry{providers: make(map[UpstreamID]Provider), direct: direct}
	r.providers[DirectUpstreamID] = direct
	return r
}

// SetDirectDialer installs the dial function the built-in @direct upstream
// uses to leave the device. On Android this must be a VpnService-protected
// dialer (see directProvider's doc comment for why) - the same one every
// other upstream already uses. Passing nil reverts to a plain, unprotected
// net.Dialer, which is only correct when the VPN is not capturing ordinary
// internet traffic (broad capture off).
func (e *Engine) SetDirectDialer(dial UpstreamDialer) {
	if dial == nil {
		e.upstreams.direct.protectedDial.Store(nil)
		return
	}
	e.upstreams.direct.protectedDial.Store(&dial)
}

// AddSource plugs in a provider source. Sources are consulted after the
// registry's own providers, so a directly-registered upstream always wins a
// name collision and no source can shadow the direct upstream.
func (r *upstreamRegistry) AddSource(s providerSource) {
	if s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources = append(r.sources, s)
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
	if err := r.checkChainLocked(p); err != nil {
		return err
	}
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
	if id == "" {
		return nil, false
	}
	r.mu.RLock()
	p, ok := r.providers[id]
	sources := r.sources
	r.mu.RUnlock()
	if ok {
		return p, true
	}
	for _, s := range sources {
		if p, ok := s.Get(id); ok {
			return p, true
		}
	}
	return nil, false
}

// List returns every provider from the registry and its sources, ordered by ID
// so callers and tests see a stable sequence.
func (r *upstreamRegistry) List() []Provider {
	r.mu.RLock()
	out := make([]Provider, 0, len(r.providers))
	seen := make(map[UpstreamID]bool, len(r.providers))
	for id, p := range r.providers {
		out = append(out, p)
		seen[id] = true
	}
	sources := r.sources
	r.mu.RUnlock()

	for _, s := range sources {
		for _, p := range s.List() {
			if p == nil || seen[p.ID()] {
				continue
			}
			seen[p.ID()] = true
			out = append(out, p)
		}
	}
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

// lookupProvider resolves an UpstreamID to a Provider. Tailnets reach this
// through the registry's tailnet source like any other upstream; a configured
// but disabled tailnet resolves and reports Ready() == false, so it reads as
// "exists but not usable" rather than as absent.
func (e *Engine) lookupProvider(id UpstreamID) (Provider, bool) {
	if e.upstreams == nil {
		return nil, false
	}
	return e.upstreams.Get(id)
}

// readyProvider resolves id and requires it to be usable now. Callers that must
// not silently fall through to a different upstream use this.
//
// The Provider it returns is wrapped for stats (stats.go): every real dial
// through it, from whichever call site, is recorded transparently, so
// instrumentation lives in one place rather than at each of the several sites
// that call this.
func (e *Engine) readyProvider(id UpstreamID) (Provider, bool) {
	p, ok := e.lookupProvider(id)
	if !ok {
		return nil, false
	}
	if !p.Ready() {
		e.recordNotReady(id)
		return nil, false
	}
	return e.wrapWithStats(p), true
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
	if p != nil && p.Kind() == UpstreamKindExitNode {
		return errors.New("multiproxy: register exit node upstreams through AddExitNodeUpstream")
	}
	err := e.upstreams.Register(p)
	if err == nil && p != nil {
		// A reconfigured upstream (same ID, new provider) shouldn't keep
		// pooled DoH connections dialed under the old configuration.
		e.dohClients().evict(p.ID())
	}
	return err
}

// UnregisterUpstream removes a non-tailnet upstream.
func (e *Engine) UnregisterUpstream(id UpstreamID) error {
	if e.upstreams == nil {
		return nil
	}
	err := e.upstreams.Unregister(id)
	e.dohClients().evict(id)
	return err
}

// UpstreamInfo is a UI-facing snapshot of one upstream.
type UpstreamInfo struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Ready bool   `json:"ready"`
	// Via names this upstream's chain parent, empty when it dials from the
	// device. The UI renders a chain from these.
	Via string `json:"via,omitempty"`
}

// UpstreamSnapshot lists every upstream the policy layer can route to, tailnets
// included, ordered by ID.
func (e *Engine) UpstreamSnapshot() []UpstreamInfo {
	if e.upstreams == nil {
		return nil
	}
	var out []UpstreamInfo
	for _, p := range e.upstreams.List() {
		out = append(out, UpstreamInfo{
			ID:    string(p.ID()),
			Kind:  string(p.Kind()),
			Ready: p.Ready(),
			Via:   string(providerVia(p)),
		})
	}
	return out
}
