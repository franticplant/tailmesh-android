// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
)

// Direct tailnet connections over a USB tether or hotspot.
//
// On Android, Tailscale binds every socket (including each tsnet node's
// magicsock UDP socket) to the active Wi-Fi or mobile network. A peer on the
// phone's own tether or hotspot subnet is not on that network, so disco
// probes and their replies never meet over the cable and the peer is reached
// through DERP instead. Leaving the sockets unbound (still VPN-protected)
// lets the kernel route each packet, so a tether peer is reached directly.
//
// Upstream added the binding because unbound sockets sent IPv6 over mobile
// data while the phone was on Wi-Fi without IPv6 (tailscale#6152). So the
// binding is only dropped when the user turned the setting on and that
// cannot happen: the default network has usable IPv6, or no other network
// offers it.
//
// The switch is process-wide (netns), shared by every tailnet, and only
// affects sockets created after it changes, so every running node's
// magicsock is rebound when the effective value flips.

// Reasons reported in DirectLinksState.Reason.
const (
	DirectLinksOn           = "on"
	DirectLinksOffSetting   = "off-setting"
	DirectLinksOffIPv6      = "off-ipv6-unsafe"
	DirectLinksOffNoNetwork = "off-no-network-info"
)

// InventoryNetwork is one entry of the Android network inventory, as the app's
// NetworkInventory.toJson writes it (the same shape device.networks returns).
type InventoryNetwork struct {
	NetworkKey            string           `json:"networkKey"`
	InterfaceName         string           `json:"interfaceName"`
	Transports            []string         `json:"transports"`
	IsDefault             bool             `json:"isDefault"`
	HasInternetCapability bool             `json:"hasInternetCapability"`
	IsVPN                 bool             `json:"isVpn"`
	Routes                []InventoryRoute `json:"routes"`
}

// InventoryRoute is one route of an InventoryNetwork.
type InventoryRoute struct {
	CIDR      string `json:"cidr"`
	IsDefault bool   `json:"isDefault"`
}

// hasIPv6DefaultRoute is the app's definition of "usable IPv6" (the same one
// NetworkChangeCallback.hasUsableIPv6 uses to pick a network for IPv6 dials):
// an IPv6 default route, not just an IPv6 address.
func (n InventoryNetwork) hasIPv6DefaultRoute() bool {
	for _, r := range n.Routes {
		if !r.IsDefault {
			continue
		}
		if p, err := netip.ParsePrefix(r.CIDR); err == nil && p.Addr().Is6() && p.Bits() == 0 {
			return true
		}
	}
	return false
}

func (n InventoryNetwork) label() string {
	if n.InterfaceName != "" {
		return n.InterfaceName
	}
	return n.NetworkKey
}

// DirectLinksDecision is the outcome of DecideDirectLinks.
type DirectLinksDecision struct {
	Unbind bool   `json:"unbind"`
	Reason string `json:"reason"`
	// DefaultNetwork is the default network's interface, empty if none.
	DefaultNetwork string `json:"defaultNetwork,omitempty"`
	DefaultHasIPv6 bool   `json:"defaultHasIpv6"`
	// OtherIPv6Networks are the non-default networks that offer IPv6: have
	// the INTERNET capability, are not a VPN, and have an IPv6 default route.
	OtherIPv6Networks []string `json:"otherIpv6Networks"`
	// IgnoredIPv6Networks have an IPv6 default route but no INTERNET
	// capability (an IMS or carrier-services network, for example), so
	// Android never uses them for app traffic and they don't count.
	IgnoredIPv6Networks []string `json:"ignoredIpv6Networks,omitempty"`
}

// DecideDirectLinks decides whether sockets may be left unbound. It is safe
// when the default network has usable IPv6, or no other network offers IPv6:
// then an unbound IPv6 socket either uses the default network, as a bound one
// would, or has nowhere else to go.
func DecideDirectLinks(settingOn bool, nets []InventoryNetwork) DirectLinksDecision {
	d := DirectLinksDecision{OtherIPv6Networks: []string{}}
	for _, n := range nets {
		if n.IsVPN {
			continue
		}
		if n.IsDefault {
			d.DefaultNetwork = n.label()
			d.DefaultHasIPv6 = n.hasIPv6DefaultRoute()
			continue
		}
		if !n.hasIPv6DefaultRoute() {
			continue
		}
		if n.HasInternetCapability {
			d.OtherIPv6Networks = append(d.OtherIPv6Networks, n.label())
		} else {
			d.IgnoredIPv6Networks = append(d.IgnoredIPv6Networks, n.label())
		}
	}
	sort.Strings(d.OtherIPv6Networks)
	sort.Strings(d.IgnoredIPv6Networks)

	switch {
	case !settingOn:
		d.Reason = DirectLinksOffSetting
	case len(nets) == 0:
		// No inventory (ConnectivityManager not available yet): keep the
		// binding rather than guess.
		d.Reason = DirectLinksOffNoNetwork
	case d.DefaultHasIPv6 || len(d.OtherIPv6Networks) == 0:
		d.Unbind = true
		d.Reason = DirectLinksOn
	default:
		d.Reason = DirectLinksOffIPv6
	}
	return d
}

// DirectLinksState is what ApplyDirectLinks returns and DirectLinksJSON
// reports: the decision plus the effective netns state.
type DirectLinksState struct {
	Setting bool `json:"setting"`
	DirectLinksDecision
	// Unbound is the effective state: true when new sockets are left
	// unbound, either by this decision or by a tailnet's
	// disable-android-bind-to-active-network node attribute.
	Unbound bool `json:"unbound"`
	// ByNodeAttr is true when the node attribute alone disables binding.
	// It is one process-wide value set by whichever tailnet's netmap arrived
	// last, not per tailnet.
	ByNodeAttr         bool  `json:"byNodeAttr"`
	ChangedAtMillis    int64 `json:"changedAtMillis,omitempty"`
	ReboundAtMillis    int64 `json:"reboundAtMillis,omitempty"`
	ReboundNodes       int   `json:"reboundNodes,omitempty"`
	ReboundFailedNodes int   `json:"reboundFailedNodes,omitempty"`
}

type directLinksTracker struct {
	mu      sync.Mutex
	applied bool // the app flag has been set at least once
	state   DirectLinksState
}

// ApplyDirectLinks evaluates the setting against the current network
// inventory (inventoryJSON, the app's NetworkInventory.toJson output), sets
// the app's netns flag, and when the effective value changes, rebinds every
// running tailnet and exit-node so their UDP sockets pick it up. Rebinding
// runs in the background; the returned JSON is the new DirectLinksState.
func (e *Engine) ApplyDirectLinks(settingOn bool, inventoryJSON string) string {
	var nets []InventoryNetwork
	if inventoryJSON != "" {
		if err := json.Unmarshal([]byte(inventoryJSON), &nets); err != nil {
			log.Printf("multiproxy: direct links: bad network inventory: %v", err)
			nets = nil
		}
	}
	d := DecideDirectLinks(settingOn, nets)

	t := &e.directLinks
	t.mu.Lock()
	before, _ := netns.AndroidBindToActiveNetworkDisabled()
	netns.SetAppDisableAndroidBindToActiveNetwork(log.Printf, d.Unbind)
	after, byAttr := netns.AndroidBindToActiveNetworkDisabled()
	prev := t.state
	t.state = DirectLinksState{
		Setting:             settingOn,
		DirectLinksDecision: d,
		Unbound:             after,
		ByNodeAttr:          byAttr,
		ChangedAtMillis:     prev.ChangedAtMillis,
		ReboundAtMillis:     prev.ReboundAtMillis,
		ReboundNodes:        prev.ReboundNodes,
		ReboundFailedNodes:  prev.ReboundFailedNodes,
	}
	if !t.applied || prev.Reason != d.Reason {
		log.Printf("multiproxy: direct links: %s (default %q ipv6=%v, other ipv6 %v, ignored %v), unbound=%v",
			d.Reason, d.DefaultNetwork, d.DefaultHasIPv6, d.OtherIPv6Networks, d.IgnoredIPv6Networks, after)
	}
	t.applied = true
	rebind := before != after
	if rebind {
		t.state.ChangedAtMillis = time.Now().UnixMilli()
	}
	out := t.state
	t.mu.Unlock()

	if rebind {
		go e.rebindAllNodes()
	}
	return marshalDirectLinks(out)
}

// DirectLinksJSON returns the last DirectLinksState, with the effective netns
// state read fresh (a netmap may have changed the node attribute since).
func (e *Engine) DirectLinksJSON() string {
	t := &e.directLinks
	t.mu.Lock()
	out := t.state
	t.mu.Unlock()
	out.Unbound, out.ByNodeAttr = netns.AndroidBindToActiveNetworkDisabled()
	if out.OtherIPv6Networks == nil {
		out.OtherIPv6Networks = []string{}
	}
	if out.Reason == "" {
		out.Reason = DirectLinksOffSetting
	}
	return marshalDirectLinks(out)
}

func marshalDirectLinks(s DirectLinksState) string {
	b, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// rebindAllNodes closes and re-opens every running node's magicsock UDP
// sockets (the LocalAPI "rebind" debug action, which is magicsock.Conn.Rebind)
// and re-STUNs, so the sockets are created again under the current netns
// binding choice. This keeps the nodes, their netmaps and their TCP
// connections; restarting the tailnets would also work but drops every flow.
func (e *Engine) rebindAllNodes() {
	defer recoverAndLog("rebindAllNodes")
	e.mu.RLock()
	var nodes []*tsnet.Server
	for _, rt := range e.tailnets {
		if rt.Enabled && rt.Srv != nil {
			nodes = append(nodes, rt.Srv)
		}
	}
	for _, rt := range e.exitNodes {
		if rt.Enabled && rt.Srv != nil {
			nodes = append(nodes, rt.Srv)
		}
	}
	e.mu.RUnlock()

	var ok, failed int
	var errs []string
	for _, srv := range nodes {
		if err := rebindNode(srv); err != nil {
			failed++
			errs = append(errs, err.Error())
			continue
		}
		ok++
	}
	if len(errs) > 0 {
		log.Printf("multiproxy: direct links: rebind failed on %d node(s): %s", failed, strings.Join(errs, "; "))
	}
	log.Printf("multiproxy: direct links: rebound %d node(s)", ok)

	t := &e.directLinks
	t.mu.Lock()
	t.state.ReboundAtMillis = time.Now().UnixMilli()
	t.state.ReboundNodes = ok
	t.state.ReboundFailedNodes = failed
	t.mu.Unlock()
}

func rebindNode(srv *tsnet.Server) error {
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := lc.DebugAction(ctx, "rebind"); err != nil {
		return err
	}
	// magicsock.Conn.Rebind's doc: "It should be followed by a call to
	// ReSTUN", which also refreshes the endpoints peers are told about.
	return lc.DebugAction(ctx, "restun")
}

// resetDirectLinks drops the app's netns flag when the engine closes, so a
// Standard-mode session started afterwards in the same process binds sockets
// as upstream does.
func (e *Engine) resetDirectLinks() {
	t := &e.directLinks
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.applied {
		netns.SetAppDisableAndroidBindToActiveNetwork(log.Printf, false)
		t.applied = false
	}
}

// IPv6PathProbe is ProbeIPv6Path's result.
type IPv6PathProbe struct {
	// Unbound is whether the probe socket was left unbound (the effective
	// state at the time of the probe).
	Unbound bool `json:"unbound"`
	// LocalAddr is the source address the kernel picked, empty on error.
	LocalAddr string `json:"localAddr,omitempty"`
	// Network is the inventory network whose on-link IPv6 prefix contains
	// LocalAddr, if any.
	Network string `json:"network,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ProbeIPv6Path asks the kernel which way an IPv6 packet from a socket made
// like magicsock's (netns: VPN-protected, bound or not per the current
// setting) would go: it connects a UDP socket to a public IPv6 address, which
// sends nothing, and reports the source address chosen and which network it
// belongs to. An error such as "network is unreachable", or the app refusing
// to bind an IPv6 socket, means IPv6 has nowhere to go.
func ProbeIPv6Path(inventoryJSON string) IPv6PathProbe {
	var p IPv6PathProbe
	p.Unbound, _ = netns.AndroidBindToActiveNetworkDisabled()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The monitor is only a required argument; Android's netns ignores it.
	d := netns.FromDialer(log.Printf, netmon.NewStatic(), &net.Dialer{})
	c, err := d.DialContext(ctx, "udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		p.Error = err.Error()
		return p
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		p.LocalAddr = c.LocalAddr().String()
		return p
	}
	p.LocalAddr = ap.Addr().String()
	var nets []InventoryNetwork
	_ = json.Unmarshal([]byte(inventoryJSON), &nets)
	p.Network = networkForAddr(nets, ap.Addr())
	return p
}

// networkForAddr returns the label of the network with a non-default route
// prefix containing a, or "".
func networkForAddr(nets []InventoryNetwork, a netip.Addr) string {
	best, bestBits := "", -1
	for _, n := range nets {
		for _, r := range n.Routes {
			pfx, err := netip.ParsePrefix(r.CIDR)
			if err != nil || pfx.Bits() == 0 || !pfx.Contains(a) {
				continue
			}
			if pfx.Bits() > bestBits {
				best, bestBits = n.label(), pfx.Bits()
			}
		}
	}
	return best
}
