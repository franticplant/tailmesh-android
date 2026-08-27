package multiproxy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// UnknownAppUID marks a flow whose owning application could not be determined.
//
// gVisor sees only raw IP/TCP/UDP headers off the TUN, which carry no UID, so
// attribution depends on an out-of-band lookup that can legitimately fail (the
// socket closed between the SYN and the query, the platform refused, no resolver
// is installed). A rule that names specific UIDs never matches such a flow, so a
// failed lookup can only ever fall through to a broader rule - never silently
// satisfy a narrower one.
const UnknownAppUID int32 = -1

// Action is what a policy rule does with a matching flow.
type Action string

const (
	// ActionRoute sends the flow to the rule's Upstream.
	ActionRoute Action = "route"

	// ActionBlock drops the flow. This is the firewall half of the policy: it
	// fails closed and never falls through to a later rule.
	ActionBlock Action = "block"

	// ActionDirect dials from the device, outside every tunnel. Equivalent to
	// routing to DirectUpstreamID, spelled separately because "do not tunnel
	// this app" is a distinct intent from "tunnel it via that upstream".
	ActionDirect Action = "direct"
)

// PortRange is an inclusive port range. A single port is Lo == Hi.
type PortRange struct {
	Lo uint16 `json:"lo"`
	Hi uint16 `json:"hi"`
}

func (r PortRange) contains(p uint16) bool { return p >= r.Lo && p <= r.Hi }

func (r PortRange) valid() bool { return r.Lo <= r.Hi }

// Selector decides which flows a rule applies to. Every field is a disjunction
// within itself and a conjunction across fields: a flow matches when it satisfies
// every non-empty field. An empty field is a wildcard, so the zero Selector
// matches everything - which is exactly what a default rule wants.
type Selector struct {
	// AppUIDs restricts the rule to specific Android application UIDs. This is
	// the per-app dimension: bind an app to an upstream by naming its UID here.
	AppUIDs []int32 `json:"appUids,omitempty"`

	// DstPrefixes restricts the rule by destination address.
	DstPrefixes []netip.Prefix `json:"dstPrefixes,omitempty"`

	// DstPorts restricts the rule by destination port.
	DstPorts []PortRange `json:"dstPorts,omitempty"`

	// Protocols restricts the rule to "tcp" or "udp".
	Protocols []string `json:"protocols,omitempty"`
}

// IsWildcard reports whether the selector constrains nothing.
func (s Selector) IsWildcard() bool {
	return len(s.AppUIDs) == 0 && len(s.DstPrefixes) == 0 &&
		len(s.DstPorts) == 0 && len(s.Protocols) == 0
}

// Rule is one entry in an ordered policy.
type Rule struct {
	// Name is for diagnostics and the UI. It has no effect on matching.
	Name     string   `json:"name,omitempty"`
	Selector Selector `json:"selector"`
	Action   Action   `json:"action"`
	// Upstream is the destination for ActionRoute. It is ignored by the other
	// actions.
	Upstream UpstreamID `json:"upstream,omitempty"`
	// DNSUpstream overrides where a forwarded DNS query for this rule's app
	// goes, independent of where its data goes (Upstream). Empty means "same
	// as the data path" - today's auto-follow behaviour, unchanged for any
	// rule that doesn't set this. Set to DirectUpstreamID for the common
	// "use device DNS despite tunneling the data" case; set to any other
	// upstream for split DNS. Ignored by ActionBlock.
	DNSUpstream UpstreamID `json:"dnsUpstream,omitempty"`
}

// FlowInfo describes one flow being resolved.
type FlowInfo struct {
	// Protocol is "tcp" or "udp".
	Protocol string
	Src      netip.AddrPort
	Dst      netip.AddrPort
	// AppUID owns the flow, or UnknownAppUID.
	AppUID int32
}

// Policy is an ordered rule list evaluated first-match-wins.
//
// Order is the whole semantic: a specific per-app rule placed above a broad
// default is how "this app goes via X, everything else via Y" is expressed. The
// engine does not reorder rules or try to find a "best" match.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Validate reports the first structural problem in the policy. It deliberately
// does not check that named upstreams exist: policies are edited and persisted
// independently of which upstreams happen to be running, and a rule naming a
// currently-absent upstream must fail closed at resolution time rather than make
// the whole policy unloadable.
func (p Policy) Validate() error {
	for i, r := range p.Rules {
		switch r.Action {
		case ActionRoute:
			if r.Upstream == "" {
				return fmt.Errorf("rule %d (%q): action %q requires an upstream", i, r.Name, r.Action)
			}
		case ActionBlock, ActionDirect:
			// no upstream needed
		case "":
			return fmt.Errorf("rule %d (%q): missing action", i, r.Name)
		default:
			return fmt.Errorf("rule %d (%q): unknown action %q", i, r.Name, r.Action)
		}
		for _, pr := range r.Selector.DstPorts {
			if !pr.valid() {
				return fmt.Errorf("rule %d (%q): invalid port range %d-%d", i, r.Name, pr.Lo, pr.Hi)
			}
		}
		for _, proto := range r.Selector.Protocols {
			switch strings.ToLower(proto) {
			case "tcp", "udp":
			default:
				return fmt.Errorf("rule %d (%q): unknown protocol %q", i, r.Name, proto)
			}
		}
		for _, pfx := range r.Selector.DstPrefixes {
			if !pfx.IsValid() {
				return fmt.Errorf("rule %d (%q): invalid destination prefix", i, r.Name)
			}
		}
	}
	return nil
}

// matches reports whether the selector accepts the flow.
func (s Selector) matches(f FlowInfo) bool {
	if len(s.AppUIDs) > 0 {
		// An unattributed flow can never satisfy a UID-scoped rule.
		if f.AppUID == UnknownAppUID {
			return false
		}
		if !containsInt32(s.AppUIDs, f.AppUID) {
			return false
		}
	}

	if len(s.Protocols) > 0 {
		proto := strings.ToLower(f.Protocol)
		found := false
		for _, p := range s.Protocols {
			if strings.ToLower(p) == proto {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(s.DstPrefixes) > 0 {
		addr := f.Dst.Addr()
		if !addr.IsValid() {
			return false
		}
		// Unmap so a v4-mapped-v6 destination still matches a v4 prefix.
		addr = addr.Unmap()
		found := false
		for _, pfx := range s.DstPrefixes {
			if pfx.Contains(addr) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(s.DstPorts) > 0 {
		port := f.Dst.Port()
		found := false
		for _, pr := range s.DstPorts {
			if pr.contains(port) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func containsInt32(haystack []int32, needle int32) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// Match returns the first rule accepting the flow, and its index.
func (p Policy) Match(f FlowInfo) (Rule, int, bool) {
	for i, r := range p.Rules {
		if r.Selector.matches(f) {
			return r, i, true
		}
	}
	return Rule{}, -1, false
}

// ---------------------------------------------------------------------------
// engine-held policy
// ---------------------------------------------------------------------------

// policyStore holds the active policy behind its own lock. It is deliberately
// separate from Engine.mu: policy is read on every new flow, and must not
// contend with tailnet lifecycle operations that hold Engine.mu for as long as a
// tsnet server takes to start.
type policyStore struct {
	mu     sync.RWMutex
	policy Policy
}

func (s *policyStore) Set(p Policy) {
	s.mu.Lock()
	s.policy = p
	s.mu.Unlock()
}

func (s *policyStore) Get() Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy
}

func (s *policyStore) Match(f FlowInfo) (Rule, int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy.Match(f)
}

// SetPolicy replaces the routing policy. An invalid policy is rejected whole, so
// a bad edit cannot partially apply and leave traffic following half a ruleset.
func (e *Engine) SetPolicy(p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if e.policy == nil {
		return fmt.Errorf("multiproxy: engine has no policy store")
	}
	e.policy.Set(p)
	return nil
}

// SetPolicyJSON replaces the routing policy from its JSON encoding. This is the
// form the Android side sends, since gomobile cannot carry the struct across.
func (e *Engine) SetPolicyJSON(encoded string) error {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return e.SetPolicy(Policy{})
	}
	var p Policy
	if err := json.Unmarshal([]byte(trimmed), &p); err != nil {
		return fmt.Errorf("multiproxy: parsing policy: %w", err)
	}
	return e.SetPolicy(p)
}

// PolicyJSON returns the active policy's JSON encoding.
func (e *Engine) PolicyJSON() string {
	if e.policy == nil {
		return `{"rules":[]}`
	}
	b, err := json.Marshal(e.policy.Get())
	if err != nil {
		return `{"rules":[]}`
	}
	return string(b)
}

// DefaultLANPrefixes lists the well-known local/private destination ranges a
// "keep LAN traffic off the tunnel" rule should match: RFC 1918 private space,
// loopback, link-local, and multicast, for both address families.
//
// This deliberately does not include the whole IPv6 ULA block (fc00::/7):
// Tailscale's own real address space (RealTailscaleIPv6Prefix,
// fd7a:115c:a1e0::/48) lives inside it, and a rule that excluded all of ULA
// would silently misroute real Tailscale traffic along with genuine LAN
// traffic. Only the specific ranges below are "local" in the sense this rule
// means.
func DefaultLANPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}
