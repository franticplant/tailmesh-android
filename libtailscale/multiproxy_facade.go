// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"errors"
	"path/filepath"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/types/logger"

	"github.com/tailscale/tailscale-android/libtailscale/multiproxy"
)

type MultiProxyCallback interface {
	OnPeerDiscovered(hostname, syntheticIPv4, syntheticIPv6, tailnetID string)
	OnTailnetStateChange(tailnetID, state string)

	// OnAddressCrossover fires when a real (non-synthetic) Tailscale IP was
	// found on more than one simultaneously-active tailnet at once during
	// routing, and one was picked best-effort. candidateTailnetIDsCSV is a
	// comma-separated list of every tailnet identifier that claimed the
	// address; chosenTailnetID is the one that was used.
	OnAddressCrossover(ip, candidateTailnetIDsCSV, chosenTailnetID string)

	// OnUpstreamHealthChanged fires when an upstream's dial-level readiness
	// changes: the first failure after a run of successes, or the first
	// success/ready result after a run of failures. reason is the triggering
	// dial's error string, or empty on a recovery. Best-effort - GetUpstreamStatsJSON
	// (multiproxy_policy_facade.go) is the reliable source of truth for
	// anything this drops.
	OnUpstreamHealthChanged(upstreamID string, ready bool, reason string)

	// OnObservabilityEvent fires on a discrete observability lifecycle event
	// (path transitions, restarts, etc). See multiproxy.EngineCallback's own
	// doc comment for the full rationale - this simply forwards it.
	OnObservabilityEvent(eventType, upstreamID string, appUID int32, networkSource, previousState, newState, metadataJSON string)
}

type MultiProxyEngine struct {
	inner *multiproxy.Engine
}

func NewMultiProxyEngine(dataDir string, cb MultiProxyCallback) *MultiProxyEngine {
	e := multiproxy.NewEngine(dataDir, cb)
	// The built-in @direct upstream must leave through the same
	// VpnService-protected dialer every other upstream uses (see
	// AddSOCKS5UpstreamVia/AddWireGuardUpstream below), or a "direct" dial
	// loops back into the TUN once broad capture has the VPN intercepting
	// ordinary internet traffic. protectedDialContext checks the published
	// dialer on every call, so wiring it in now is correct even though
	// setUpstreamProtectedDialer (backend.go) publishes the real one later,
	// once netmon exists.
	e.SetDirectDialer(protectedDialContext)
	return &MultiProxyEngine{inner: e}
}

// NewMultiProxyEngineForApp uses tsnet's established per-upstream file stores.
// Profile data is copied into and merged out of those stores at mode boundaries.
func NewMultiProxyEngineForApp(dataDir string, appCtx AppContext, cb MultiProxyCallback) *MultiProxyEngine {
	return NewMultiProxyEngine(dataDir, cb)
}

func (e *MultiProxyEngine) StartVPN(fd int32, mtu int32) error { return e.inner.StartVPN(fd, mtu) }
func (e *MultiProxyEngine) StopVPN()                           { e.inner.StopVPN() }

func (e *MultiProxyEngine) AddTailnet(identifier string, authKey string, enabled bool) error {
	return e.inner.AddTailnet(identifier, authKey, enabled)
}

func (e *MultiProxyEngine) RemoveTailnet(identifier string) error {
	return e.inner.RemoveTailnet(identifier)
}

func (e *MultiProxyEngine) Close() { e.inner.Close() }

func (e *MultiProxyEngine) SetUpstreamDNS(dns string) { e.inner.SetUpstreamDNS(dns) }

// SetBootstrapDNS supplies the underlying network's plain resolver, used only
// to resolve a DoH server's own hostname. See multiproxy.Engine.SetBootstrapDNS.
func (e *MultiProxyEngine) SetBootstrapDNS(dns string) { e.inner.SetBootstrapDNS(dns) }

func (e *MultiProxyEngine) SetTailnetEnabled(identifier string, enabled bool) error {
	if e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.SetTailnetEnabled(identifier, enabled)
}

// SetTailnetExitNode points a running tailnet upstream's own general internet
// traffic at one of its peers, using that tailnet's existing node identity -
// no extra auth, no extra device slot. Pass an empty peerAddr to clear it.
//
// This only supports one active exit node per tailnet at a time; for a
// second, simultaneously-active exit node out of the same tailnet, use
// AddExitNodeUpstream (multiproxy_policy_facade.go) instead, which is a
// dedicated identity and does cost an extra device slot.
func (e *MultiProxyEngine) SetTailnetExitNode(identifier, peerAddr string) error {
	if e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.SetTailnetExitNode(identifier, peerAddr)
}

func MultiProxySyntheticIPv6Prefix() string       { return multiproxy.SyntheticIPv6Prefix.String() }
func MultiProxySyntheticInterfaceAddress() string { return multiproxy.SyntheticIPv6Interface.String() }
func MultiProxySyntheticDNSAddress() string       { return multiproxy.SyntheticIPv6DNS.String() }

func MultiProxySyntheticIPv4Prefix() string { return multiproxy.SyntheticIPv4Prefix.String() }
func MultiProxySyntheticIPv4InterfaceAddress() string {
	return multiproxy.SyntheticIPv4Interface.String()
}
func MultiProxySyntheticIPv4DNSAddress() string { return multiproxy.SyntheticIPv4DNS.String() }

// Real Tailscale space. The TUN has to carry routes for these too, otherwise
// an app handed a peer's literal address (SIP and TURN/STUN both do this)
// sends to it over the underlying network, where nothing answers.
func MultiProxyRealTailscaleIPv4Prefix() string {
	return multiproxy.RealTailscaleIPv4Prefix.String()
}
func MultiProxyRealTailscaleIPv6Prefix() string {
	return multiproxy.RealTailscaleIPv6Prefix.String()
}

func AcquireMultiProxyNetworkHooks(token string, s IPNService, appCtx AppContext) bool {
	return AcquireAndroidNetworkHooks(token, s, appCtx)
}

func ReleaseMultiProxyNetworkHooks(token string) { ReleaseAndroidNetworkHooks(token) }

func (e *MultiProxyEngine) GetTargetsJSON() string { return e.inner.GetTargetsJSON() }

// GetObservabilitySnapshotJSON returns the current process/dataplane/per-app
// observability snapshot as JSON. See multiproxy.Engine.GetObservabilitySnapshotJSON.
func (e *MultiProxyEngine) GetObservabilitySnapshotJSON() string {
	if e == nil || e.inner == nil {
		return "{}"
	}
	return e.inner.GetObservabilitySnapshotJSON()
}

// ResetObservabilityCounters zeroes the selected live observability counter
// groups. See multiproxy.Engine.ResetObservabilityCounters.
func (e *MultiProxyEngine) ResetObservabilityCounters(dataplane, apps, upstreams bool) {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.ResetObservabilityCounters(dataplane, apps, upstreams)
}

// SetObservabilitySampleIntervalSeconds changes the periodic process/runtime
// sampler's cadence. Call with a short interval (e.g. 1) only while the
// diagnostics screen is visible, and with 0 (or the same default the app
// uses elsewhere) when it closes - see PHASE 17 in the design doc for why
// this must not default to a fast interval.
func (e *MultiProxyEngine) SetObservabilitySampleIntervalSeconds(secs int32) {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.SetObservabilitySampleIntervalSeconds(secs)
}

// SetDNSQueryLogEnabled turns per-DNS-query event logging on/off - which
// upstream a specific name resolved through and with what outcome, at the
// cost of one event (and one SQLite insert on the Kotlin side) per DNS
// lookup instead of per rare transition. Off by default; call with true only
// while the diagnostics screen's DNS log toggle is actually on, and false
// when it closes, the same on/off-while-visible pattern as
// SetObservabilitySampleIntervalSeconds above.
func (e *MultiProxyEngine) SetDNSQueryLogEnabled(enabled bool) {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.SetDNSQueryLogEnabled(enabled)
}

// StartPacketCaptureAll begins a global PCAP capture of every packet
// crossing the TUN, written to path and bounded to maxBytes (pass 0 for a
// sane default). Any previous capture session is stopped and discarded
// first. See multiproxy/capture.go for the format and filtering details.
func (e *MultiProxyEngine) StartPacketCaptureAll(path string, maxBytes int64) error {
	if e == nil || e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.StartPacketCaptureAll(path, maxBytes)
}

// StartPacketCaptureApps is StartPacketCaptureAll's per-app counterpart:
// only packets attributed to one of appUIDsCSV (comma-separated Android
// UIDs) are captured. A flow whose owning app couldn't be resolved is never
// captured in this mode.
func (e *MultiProxyEngine) StartPacketCaptureApps(appUIDsCSV, path string, maxBytes int64) error {
	if e == nil || e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.StartPacketCaptureApps(appUIDsCSV, path, maxBytes)
}

// StopPacketCapture ends the active capture session, if any, and closes its
// file so the UI can read/share it immediately. Safe to call when no
// capture is running.
func (e *MultiProxyEngine) StopPacketCapture() {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.StopPacketCapture()
}

func (e *MultiProxyEngine) PacketCaptureBytesWritten() int64 {
	if e == nil || e.inner == nil {
		return 0
	}
	return e.inner.PacketCaptureBytesWritten()
}

func (e *MultiProxyEngine) PacketCapturePacketCount() int64 {
	if e == nil || e.inner == nil {
		return 0
	}
	return e.inner.PacketCapturePacketCount()
}

// PacketCaptureCapacityReached reports whether the active session hit its
// maxBytes limit and has been silently dropping packets since - the UI
// should surface this rather than let a suspiciously quiet capture read as
// "the bug didn't recur."
func (e *MultiProxyEngine) PacketCaptureCapacityReached() bool {
	if e == nil || e.inner == nil {
		return false
	}
	return e.inner.PacketCaptureCapacityReached()
}

// SetAdvancedDiagnostics turns higher-frequency sampling on/off. Off by
// default. Does not itself start any profiler - see Capture* below.
func (e *MultiProxyEngine) SetAdvancedDiagnostics(on bool) {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.SetAdvancedDiagnostics(on)
}

func (e *MultiProxyEngine) AdvancedDiagnosticsEnabled() bool {
	if e == nil || e.inner == nil {
		return false
	}
	return e.inner.AdvancedDiagnosticsEnabled()
}

// CaptureCPUProfileToFile runs a bounded (<=60s) CPU profile and writes it
// to path. The only way CPU profiling ever runs in this engine - there is
// no HTTP pprof listener anywhere in production code.
func (e *MultiProxyEngine) CaptureCPUProfileToFile(path string, durationSeconds int32) error {
	if e == nil || e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.CaptureCPUProfileToFile(path, durationSeconds)
}

func (e *MultiProxyEngine) CaptureHeapProfileToFile(path string) error {
	if e == nil || e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.CaptureHeapProfileToFile(path)
}

func (e *MultiProxyEngine) CaptureGoroutineDumpToFile(path string) error {
	if e == nil || e.inner == nil {
		return errors.New("engine not initialized")
	}
	return e.inner.CaptureGoroutineDumpToFile(path)
}

// GetAddressConflictsJSON lists real Tailscale IPs claimed by more than one
// upstream at once, so the UI can show them before traffic hits one rather
// than only after.
func (e *MultiProxyEngine) GetAddressConflictsJSON() string {
	if e == nil || e.inner == nil {
		return "[]"
	}
	return e.inner.GetAddressConflictsJSON()
}

func (e *MultiProxyEngine) GetTargetsJSONV2() string {
	if e == nil || e.inner == nil {
		return "[]"
	}
	return e.inner.GetTargetsJSONV2()
}

func (e *MultiProxyEngine) ForgetTailnet(identifier string) error {
	return e.inner.ForgetTailnet(identifier)
}

func (e *MultiProxyEngine) GetTailnetStatesJSON() string {
	if e == nil || e.inner == nil {
		return "[]"
	}
	return e.inner.GetTailnetStatesJSON()
}

// GetExitNodeStatesJSON is GetTailnetStatesJSON's counterpart for exit-node
// upstreams (upstream_exitnode.go): the observed tsnet backend state of each
// one's own dedicated node identity, not the peer it routes through. Needed
// because AddExitNodeUpstream's EditPrefs call succeeds locally regardless
// of whether that identity is actually approved/logged in on its tailnet -
// this is the only way to see a stuck NeedsMachineAuth/NeedsLogin state.
func (e *MultiProxyEngine) GetExitNodeStatesJSON() string {
	if e == nil || e.inner == nil {
		return "[]"
	}
	return e.inner.GetExitNodeStatesJSON()
}

func (e *MultiProxyEngine) ClearTailnetAuthKey(identifier string) {
	if e == nil || e.inner == nil {
		return
	}
	e.inner.ClearTailnetAuthKey(identifier)
}

func ForgetMultiProxyPersistedState(dataDir, identifier string) error {
	return multiproxy.ForgetPersistedState(dataDir, identifier)
}

// PrepareRegularProfileForMultiProxy seeds a per-upstream tsnet file store.
func PrepareRegularProfileForMultiProxy(dataDir string, appCtx AppContext, profileID, upstreamID string) error {
	dst, err := multiProxyFileStore(dataDir, upstreamID)
	if err != nil {
		return err
	}
	return prepareProfileForMultiProxy(newStateStore(appCtx), dst, ipn.ProfileID(profileID))
}

// RestoreRegularProfileFromMultiProxy merges a stopped upstream back into regular state.
func RestoreRegularProfileFromMultiProxy(dataDir string, appCtx AppContext, profileID, upstreamID string) error {
	src, err := multiProxyFileStore(dataDir, upstreamID)
	if err != nil {
		return err
	}
	return restoreProfileFromMultiProxy(src, newStateStore(appCtx), ipn.ProfileID(profileID))
}

func multiProxyFileStore(dataDir, upstreamID string) (ipn.StateStore, error) {
	return store.NewFileStore(logger.Discard, filepath.Join(multiproxy.StateDirForIdentifier(dataDir, upstreamID), "tailscaled.state"))
}
