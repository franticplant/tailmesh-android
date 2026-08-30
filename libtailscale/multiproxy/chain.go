// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Upstream chaining.
//
// An upstream's own transport has to reach its far end somehow: a SOCKS5
// upstream must connect to the proxy's listener, a WireGuard upstream must get
// its handshakes to the peer endpoint. By default that connection leaves from
// the device. Chaining points it at another upstream instead, so a SOCKS5 proxy
// can be reached through a WireGuard tunnel, or a WireGuard peer through an
// Xray SOCKS5 listener.
//
// The link is an UpstreamID, resolved at dial time rather than captured at
// construction. That way a parent can be reconfigured, disabled or replaced and
// its children observe the change on their next dial, exactly as tailnet
// providers already observe enable/disable.
//
// Two guards keep this from going wrong:
//
//   - The registry rejects a provider whose Via chain contains a cycle, so a
//     configuration that would deadlock never gets installed.
//   - Dials carry a depth counter and give up past maxChainDepth, which catches
//     any cycle the static check could not see - one formed through a provider
//     source, or by a parent replaced between the check and the dial.

// maxChainDepth bounds how many upstreams one connection may traverse. Real
// chains are two or three long; this is set well above that so it only ever
// fires on a genuine mistake.
const maxChainDepth = 8

// ErrChainTooDeep is returned when a dial traverses more than maxChainDepth
// upstreams, which in practice means the chain graph has a cycle.
var ErrChainTooDeep = errors.New("multiproxy: upstream chain too deep")

// UpstreamDialer is how a provider makes its own outbound connections. It has
// the shape of net.Dialer.DialContext so a provider can take one without
// knowing whether it dials from the device or through another upstream.
type UpstreamDialer func(ctx context.Context, network, address string) (net.Conn, error)

type chainDepthKey struct{}

// withChainStep returns ctx with the chain depth incremented, and an error once
// the chain has gone deeper than maxChainDepth.
func withChainStep(ctx context.Context) (context.Context, error) {
	depth, _ := ctx.Value(chainDepthKey{}).(int)
	depth++
	if depth > maxChainDepth {
		return ctx, ErrChainTooDeep
	}
	return context.WithValue(ctx, chainDepthKey{}, depth), nil
}

// chainDialer returns the dialer a provider should use for its own transport.
//
// With an empty via it returns base, the device-level dialer. Otherwise it
// returns a dialer that resolves via at call time and dials through it, failing
// closed if that upstream is missing or not ready - a chained upstream must
// never quietly fall back to leaving from the device, since the whole point of
// the chain is that its traffic does not.
func (e *Engine) chainDialer(via UpstreamID, base UpstreamDialer) UpstreamDialer {
	if base == nil {
		var d net.Dialer
		base = d.DialContext
	}
	if via == "" {
		return base
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		ctx, err := withChainStep(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w (via %q)", err, via)
		}
		p, ok := e.readyProvider(via)
		if !ok {
			return nil, fmt.Errorf("%w: chain parent %q", ErrUpstreamNotReady, via)
		}
		if p.Kind() == UpstreamKindDirect {
			return base(ctx, network, address)
		}
		return p.Dial(ctx, network, address)
	}
}

// ---------------------------------------------------------------------------
// chain-aware constructors
// ---------------------------------------------------------------------------
//
// The plain New*Upstream constructors take whatever dialer or bind they are
// given and know nothing about the registry, which keeps them testable in
// isolation. These wrappers are the ones callers normally want: they resolve
// cfg.Via against this Engine, so the provider's own transport goes wherever the
// chain says.

// NewSOCKS5Upstream builds a SOCKS5 upstream whose proxy is reached through
// cfg.Via, or through base when Via is empty. base may be nil for a plain
// dialer; on Android it should be a VpnService-protected one.
func (e *Engine) NewSOCKS5Upstream(cfg SOCKS5Config, base UpstreamDialer) (Provider, error) {
	return NewSOCKS5Upstream(cfg, e.chainDialer(cfg.Via, base))
}

// NewWireGuardUpstream builds a WireGuard upstream whose peer endpoints are
// reached through cfg.Via, or through base when Via is empty.
//
// The tunnel's packets always travel over an upstreamBind rather than
// wireguard-go's own UDP socket. That is what makes chaining possible, and it is
// also the only way to get a protected socket on Android: wireguard-go's bind
// applies its socket options from an unexported list with no hook to add the
// VpnService protect call, whereas base is a dialer that already has it.
//
// The cost is that the tunnel has no listening socket, so cfg.ListenPort is
// ignored and peers cannot reach it unprompted. An upstream is a client; if that
// ever needs to change, pass a real bind to the package-level constructor.
func (e *Engine) NewWireGuardUpstream(cfg WireGuardConfig, base UpstreamDialer, logf func(string, ...any)) (Provider, error) {
	cfg.ListenPort = 0
	return NewWireGuardUpstream(cfg, newUpstreamBind(e.chainDialer(cfg.Via, base)), logf)
}

// AddUpstream registers a provider and reports it, so a caller can construct and
// install in one step.
func (e *Engine) AddUpstream(p Provider, err error) (Provider, error) {
	if err != nil {
		return nil, err
	}
	if err := e.RegisterUpstream(p); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

// checkChainLocked rejects a provider whose Via chain does not terminate.
//
// It walks from the candidate's parent through the providers already
// registered, treating the candidate as if it were installed under its own ID
// so that a self-reference or a cycle closed by this very registration is
// caught. Called with r.mu held for writing.
func (r *upstreamRegistry) checkChainLocked(candidate Provider) error {
	via := providerVia(candidate)
	if via == "" {
		return nil
	}
	id := candidate.ID()
	if via == id {
		return fmt.Errorf("multiproxy: upstream %q cannot chain through itself", id)
	}

	seen := map[UpstreamID]bool{id: true}
	for steps := 0; via != ""; steps++ {
		if steps >= maxChainDepth {
			return fmt.Errorf("multiproxy: upstream %q chains more than %d deep", id, maxChainDepth)
		}
		if seen[via] {
			return fmt.Errorf("multiproxy: upstream %q would create a chain cycle at %q", id, via)
		}
		seen[via] = true

		// Only the registry's own providers can be chain parents with a Via of
		// their own; a source-provided upstream (a tailnet) is always a leaf, so
		// an unresolvable ID simply ends the walk. Resolving through sources
		// here would also mean taking the Engine lock under the registry lock.
		next, ok := r.providers[via]
		if !ok {
			return nil
		}
		via = providerVia(next)
	}
	return nil
}
