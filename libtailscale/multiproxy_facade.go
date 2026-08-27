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
}

type MultiProxyEngine struct {
	inner *multiproxy.Engine
}

func NewMultiProxyEngine(dataDir string, cb MultiProxyCallback) *MultiProxyEngine {
	return &MultiProxyEngine{inner: multiproxy.NewEngine(dataDir, cb)}
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
