package libtailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"tailscale.com/net/netns"

	"github.com/tailscale/tailscale-android/libtailscale/multiproxy"
)

// upstreamDialer is the protected dialer published by the backend once it has a
// netmon (see backend.go). It is stored rather than constructed on demand
// because netns.NewDialer requires the netmon, which is built during backend
// startup.
var upstreamDialer atomic.Pointer[netns.Dialer]

func setUpstreamProtectedDialer(d netns.Dialer) { upstreamDialer.Store(&d) }

// protectedDialContext reaches a proxy without the connection re-entering the
// TUN it is meant to carry traffic out of.
//
// The published dialer applies the Android protect hook installed in backend.go
// (netns.SetAndroidProtectFunc), the same mechanism the tailnet upstreams' own
// sockets use, and netns skips protection for loopback so a proxy core running
// on the device works unchanged.
//
// Before the backend has started there is no protected dialer to use. Falling
// back to a plain one keeps a loopback proxy working, which is the case that can
// occur that early; a remote proxy dialed in that window would not be protected,
// so it is logged rather than failing silently.
func protectedDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dp := upstreamDialer.Load(); dp != nil {
		return (*dp).DialContext(ctx, network, address)
	}
	if !isLoopbackAddress(address) {
		log.Printf("multiproxy: dialing upstream %s before the protected dialer exists; connection is unprotected", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// gomobile bindings for the upstream registry and routing policy.
//
// gomobile can only carry a narrow set of types across the JNI boundary - no
// maps, no slices of structs, no named non-basic types - so everything
// structured is passed as JSON, matching the convention already used by
// GetTargetsJSON and friends.

// SetPolicyJSON replaces the routing policy.
//
// The JSON is an object with an ordered "rules" array, evaluated
// first-match-wins:
//
//	{"rules":[
//	  {"name":"work apps via office",
//	   "selector":{"appUids":[10123,10124]},
//	   "action":"route","upstream":"tailnet-office"},
//	  {"name":"block the doc range",
//	   "selector":{"dstPrefixes":["192.0.2.0/24"]},
//	   "action":"block"},
//	  {"name":"everything else via xray",
//	   "action":"route","upstream":"xray-local"}
//	]}
//
// A selector field that is absent or empty is a wildcard, so a rule with no
// selector is a default. Actions are "route" (needs "upstream"), "block" and
// "direct". An invalid policy is rejected whole and the previous one stays in
// force, so a bad edit cannot half-apply.
func (e *MultiProxyEngine) SetPolicyJSON(policyJSON string) error {
	return e.inner.SetPolicyJSON(policyJSON)
}

// PolicyJSON returns the active policy in the same form SetPolicyJSON accepts.
func (e *MultiProxyEngine) PolicyJSON() string { return e.inner.PolicyJSON() }

// GetUpstreamsJSON lists every upstream a policy rule can name, tailnets
// included, as [{"id","kind","ready","via"}...] ordered by id. "kind" is one of
// "tailnet", "socks5", "wireguard" or "direct". A configured but stopped
// upstream is listed with ready=false, so the UI can tell "off" from "absent".
// "via", when present, is the upstream this one is chained behind.
func (e *MultiProxyEngine) GetUpstreamsJSON() string {
	infos := e.inner.UpstreamSnapshot()
	if infos == nil {
		infos = []multiproxy.UpstreamInfo{}
	}
	b, err := json.Marshal(infos)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// GetUpstreamStatsJSON reports live per-upstream dial and byte counters, as
// [{"id","kind","ready","via","dialAttempts","dialSuccesses","dialFailures",
//   "notReadyCount","bytesIn","bytesOut","lastLatencyMs","lastError",
//   "lastErrorAtMillis","lastSuccessAtMillis","lastAttemptAtMillis"}...]
// ordered by id. Every count is a real observation from an actual dial or
// readiness check, not a sample or an estimate - see stats.go. An upstream
// that has never been dialed appears with every counter at zero, not absent,
// so the UI does not need to distinguish "no data yet" from "not present".
func (e *MultiProxyEngine) GetUpstreamStatsJSON() string {
	infos := e.inner.UpstreamStatsSnapshot()
	if infos == nil {
		infos = []multiproxy.UpstreamStatsInfo{}
	}
	b, err := json.Marshal(infos)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// AddSOCKS5Upstream registers a SOCKS5 proxy as an upstream, replacing any
// existing upstream with the same id.
//
// This is how a locally-run proxy core is plugged in: Xray-core, sing-box,
// v2ray and hysteria all expose a SOCKS5 listener, so pointing this at
// 127.0.0.1:<their port> makes them routable by policy without the app taking
// on their dependencies.
//
// Pass an empty username for no authentication.
//
// The proxy is reached through a VpnService-protected dialer, so traffic to a
// remote proxy does not loop back into the TUN it came from.
func (e *MultiProxyEngine) AddSOCKS5Upstream(id, address, username, password string) error {
	return e.AddSOCKS5UpstreamVia(id, address, username, password, "")
}

// AddSOCKS5UpstreamVia is AddSOCKS5Upstream with chaining: the proxy itself is
// reached through the upstream named by via, instead of from the device.
//
// An empty via is the unchained case. A chain that would loop is rejected here
// rather than at dial time, and a chained upstream whose parent is missing or
// stopped fails closed rather than falling back to leaving from the device.
func (e *MultiProxyEngine) AddSOCKS5UpstreamVia(id, address, username, password, via string) error {
	p, err := e.inner.NewSOCKS5Upstream(multiproxy.SOCKS5Config{
		ID:       multiproxy.UpstreamID(id),
		Address:  address,
		Username: username,
		Password: password,
		Via:      multiproxy.UpstreamID(via),
	}, protectedDialContext)
	if err != nil {
		return err
	}
	return e.inner.RegisterUpstream(p)
}

// AddWireGuardUpstream brings up a userspace WireGuard tunnel as an upstream,
// replacing any existing upstream with the same id.
//
// configJSON describes the tunnel in the shape of a wg-quick config, with keys
// base64 exactly as they appear there:
//
//	{"privateKey":"...",
//	 "addresses":["10.9.0.2/32"],
//	 "mtu":1420,
//	 "listenPort":0,
//	 "via":"",
//	 "peers":[{"publicKey":"...","presharedKey":"",
//	           "endpoint":"vpn.example:51820",
//	           "allowedIPs":["0.0.0.0/0","::/0"],
//	           "persistentKeepalive":25}]}
//
// Addresses accept either a bare address or one with a prefix, since that is how
// wg-quick writes them; the prefix length is not used, as the tunnel's netstack
// routes by the peers' allowed IPs.
//
// With via empty the tunnel's own packets leave through a VpnService-protected
// socket. With via naming another upstream - a SOCKS5 proxy, say - they are
// carried by that upstream instead, which is how WireGuard is chained behind a
// proxy core.
//
// "listenPort" is accepted for symmetry with a wg config but has no effect: the
// tunnel is a client, and the transport it is built on has no listening socket.
func (e *MultiProxyEngine) AddWireGuardUpstream(id, configJSON string) error {
	cfg, err := multiproxy.ParseWireGuardConfigJSON(id, configJSON)
	if err != nil {
		return err
	}
	p, err := e.inner.NewWireGuardUpstream(cfg, protectedDialContext, log.Printf)
	if err != nil {
		return err
	}
	return e.inner.RegisterUpstream(p)
}

// MultiProxyWireGuardConfigFromQuick converts a wg-quick .conf - what a VPN
// provider hands out, and what a WireGuard QR code encodes - into the JSON that
// AddWireGuardUpstream takes.
//
// It reads the [Interface] and [Peer] settings that describe a client tunnel,
// ignores wg-quick's host routing and shell hooks (Table, PostUp and friends),
// and uses the first [Peer] only. An unrecognised setting is an error rather
// than being dropped: a directive the user believed they had set going silently
// missing is worse than being told it is unsupported.
func MultiProxyWireGuardConfigFromQuick(conf string) (string, error) {
	return multiproxy.ParseWireGuardQuickConfig(conf)
}

// RemoveUpstream unregisters a non-tailnet upstream. Removing one that policy
// rules still name is allowed: those rules then fail closed, which is safer
// than silently rerouting their traffic somewhere else. The same goes for an
// upstream chained behind it.
func (e *MultiProxyEngine) RemoveUpstream(id string) error {
	return e.inner.UnregisterUpstream(multiproxy.UpstreamID(id))
}

// MultiProxyDirectUpstreamID is the reserved id of the built-in upstream that
// dials outside every tunnel. Use it in a rule to exempt an app from the VPN.
func MultiProxyDirectUpstreamID() string { return string(multiproxy.DirectUpstreamID) }

// MultiProxyUnknownAppUID is the UID reported for a flow whose owning app could
// not be determined. A rule naming specific UIDs never matches such a flow.
func MultiProxyUnknownAppUID() int32 { return multiproxy.UnknownAppUID }

// ---------------------------------------------------------------------------
// app attribution
// ---------------------------------------------------------------------------

// MultiProxyUIDResolver is implemented on the Android side to attribute a flow
// to an application, normally via ConnectivityManager.getConnectionOwnerUid.
//
// It is called once per new flow, on the datapath, and must return promptly.
// Return -1 when the owner cannot be determined; the engine also applies its own
// timeout, so a slow implementation degrades to "unknown" rather than stalling
// the flow.
type MultiProxyUIDResolver interface {
	ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32
}

// uidResolverShim adapts the exported gomobile interface to the engine's
// internal one. The two are kept separate so the multiproxy package does not
// depend on the binding layer.
type uidResolverShim struct{ inner MultiProxyUIDResolver }

func (s uidResolverShim) ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32 {
	if s.inner == nil {
		return multiproxy.UnknownAppUID
	}
	return s.inner.ResolveUID(protocol, srcIP, srcPort, dstIP, dstPort)
}

// SetUIDResolver installs the per-flow app attribution hook. Without one, every
// flow is unattributed and UID-scoped rules never match, so only broader rules
// apply.
func (e *MultiProxyEngine) SetUIDResolver(r MultiProxyUIDResolver) {
	if r == nil {
		e.inner.SetUIDResolver(nil)
		return
	}
	e.inner.SetUIDResolver(uidResolverShim{inner: r})
}

// ---------------------------------------------------------------------------
// convenience builders
// ---------------------------------------------------------------------------

// BuildAppBindingPolicyJSON assembles the common shape of a policy from the
// pieces the settings UI naturally has, so the Kotlin side does not have to
// hand-assemble JSON.
//
// bindingsJSON is [{"appUid":10123,"upstream":"tailnet-office","dnsUpstream":""}...];
// each entry becomes a rule ahead of the default. dnsUpstream is optional and,
// when set, splits where that app's DNS lookups go from where its data goes
// (multiproxy.Rule.DNSUpstream) - pass the direct upstream's id for "tunnel
// the data but keep DNS on the device", or a different upstream's id for split
// DNS. Leaving it empty keeps today's behaviour: DNS auto-follows upstream.
//
// defaultUpstream, when non-empty, becomes a trailing catch-all routing
// everything else - this is the exit-node selection for ordinary non-tailnet
// traffic. Pass the direct upstream's id to have unbound apps bypass the VPN,
// or leave it empty to keep today's behaviour of falling through to subnet
// routes and the exit-node tailnet. defaultDNSUpstream is the same DNS split
// applied to that catch-all rule.
//
// excludeLAN, when true, prepends a rule sending traffic to well-known local/
// private destinations (multiproxy.DefaultLANPrefixes) direct, ahead of every
// binding below - so LAN reachability (a printer, a NAS, a dev server on the
// same network) survives an app being routed through a proxy or tunnel,
// unless that app is explicitly bound to something else that itself names a
// LAN destination (which cannot happen through this builder, since bindings
// here are per-app, not per-destination - a future per-app "still tunnel LAN
// traffic" override would need its own rule ahead of this one).
func BuildAppBindingPolicyJSON(bindingsJSON, defaultUpstream, defaultDNSUpstream string, excludeLAN bool) (string, error) {
	var bindings []struct {
		AppUID      int32  `json:"appUid"`
		Upstream    string `json:"upstream"`
		DNSUpstream string `json:"dnsUpstream"`
	}
	if bindingsJSON != "" {
		if err := json.Unmarshal([]byte(bindingsJSON), &bindings); err != nil {
			return "", fmt.Errorf("parsing app bindings: %w", err)
		}
	}

	policy := multiproxy.Policy{}
	if excludeLAN {
		policy.Rules = append(policy.Rules, multiproxy.Rule{
			Name:     "LAN traffic stays direct",
			Selector: multiproxy.Selector{DstPrefixes: multiproxy.DefaultLANPrefixes()},
			Action:   multiproxy.ActionDirect,
		})
	}
	for _, b := range bindings {
		if b.Upstream == "" {
			continue
		}
		policy.Rules = append(policy.Rules, multiproxy.Rule{
			Name:        fmt.Sprintf("app %d", b.AppUID),
			Selector:    multiproxy.Selector{AppUIDs: []int32{b.AppUID}},
			Action:      multiproxy.ActionRoute,
			Upstream:    multiproxy.UpstreamID(b.Upstream),
			DNSUpstream: multiproxy.UpstreamID(b.DNSUpstream),
		})
	}
	if defaultUpstream != "" {
		rule := multiproxy.Rule{Name: "default", DNSUpstream: multiproxy.UpstreamID(defaultDNSUpstream)}
		if multiproxy.UpstreamID(defaultUpstream) == multiproxy.DirectUpstreamID {
			rule.Action = multiproxy.ActionDirect
		} else {
			rule.Action = multiproxy.ActionRoute
			rule.Upstream = multiproxy.UpstreamID(defaultUpstream)
		}
		policy.Rules = append(policy.Rules, rule)
	}

	if err := policy.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
