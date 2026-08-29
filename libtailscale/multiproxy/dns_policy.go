package multiproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Policy-routed DNS forwarding.
//
// A query that the synthetic resolver cannot answer is forwarded to the
// configured upstream resolver. Before this, that forward always left from the
// device, whichever upstream the querying app was routed through. Two things
// were wrong with that:
//
//   - It leaks. An app deliberately routed through a proxy or tunnel still
//     announced every name it looked up to the device's resolver, outside the
//     transport the user chose precisely so that would not happen.
//   - It can be wrong. A name that resolves differently inside the proxy's
//     network - a corporate host, a provider's own service - gets the answer
//     from the wrong side of the tunnel.
//
// So the forward now follows the app's own route.

// dnsForwardTimeout bounds one forwarded query. It matches dohTimeout for the
// same reason: a resolver slower than this is not usable, and the querying app
// is already blocked on it.
const dnsForwardTimeout = 5 * time.Second

// MatchAppOnly finds the first rule that decides where an app's traffic goes
// without reference to a destination.
//
// A DNS query's destination is the synthetic resolver, not the address the name
// will eventually resolve to, so destination-scoped selectors cannot be
// evaluated yet - and matching them against the resolver's own address would be
// worse than not matching at all, since a rule written about the wider Internet
// would silently capture, or fail to capture, every lookup.
//
// Rules carrying any destination, port or protocol constraint are therefore
// skipped rather than partially applied. What remains is exactly the shape the
// per-app bindings and the default rule take: "this app goes here".
func (p Policy) MatchAppOnly(appUID int32) (Rule, bool) {
	for _, rule := range p.Rules {
		s := rule.Selector
		if len(s.DstPrefixes) > 0 || len(s.DstPorts) > 0 || len(s.Protocols) > 0 {
			continue
		}
		if len(s.AppUIDs) > 0 {
			// An unattributed query must not match a rule written for specific
			// apps, for the same reason an unattributed flow must not: a failed
			// lookup may only ever widen what matches, never narrow it.
			if appUID == UnknownAppUID {
				continue
			}
			found := false
			for _, uid := range s.AppUIDs {
				if uid == appUID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		return rule, true
	}
	return Rule{}, false
}

// dnsRoute is how one forwarded query should leave.
type dnsRoute struct {
	// provider carries the query, or nil to leave from the device as before.
	provider Provider
	// blocked reports that policy blocks this app outright, so its lookups are
	// refused too. Answering them would be an odd half-measure: the app cannot
	// use the addresses for anything.
	blocked bool
	// failed reports that policy named an upstream that is missing or not ready.
	// The query fails rather than falling back to the device, matching how the
	// datapath treats the same situation.
	failed bool
}

// dnsRouteFor decides how a forwarded query leaves, given the app that asked.
func (e *Engine) dnsRouteFor(flow FlowInfo) dnsRoute {
	if e.policy == nil {
		return dnsRoute{}
	}
	policy := e.policy.Get()
	if len(policy.Rules) == 0 {
		return dnsRoute{}
	}

	rule, ok := policy.MatchAppOnly(flow.AppUID)
	if !ok {
		return dnsRoute{}
	}

	switch rule.Action {
	case ActionBlock:
		return dnsRoute{blocked: true}
	case ActionDirect, ActionRoute:
		upstream := rule.DNSUpstream
		if upstream == "" {
			if rule.Action == ActionDirect {
				return dnsRoute{}
			}
			upstream = rule.Upstream
		}
		if upstream == DirectUpstreamID {
			return dnsRoute{}
		}
		p, ok := e.readyProvider(upstream)
		if !ok {
			return dnsRoute{failed: true}
		}
		return dnsRoute{provider: p}
	default:
		return dnsRoute{}
	}
}

// exchangePlainVia forwards a plain DNS query through an upstream.
func exchangePlainVia(p Provider, r *dns.Msg, netType, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsForwardTimeout)
	defer cancel()

	conn, err := p.Dial(ctx, netType, server)
	if err != nil {
		return nil, fmt.Errorf("dialing %s through %s: %w", server, p.ID(), err)
	}
	defer conn.Close()

	// The deadline covers the whole exchange, not each half, which is what the
	// caller's timeout means.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	co := &dns.Conn{Conn: conn}
	if err := co.WriteMsg(r); err != nil {
		return nil, fmt.Errorf("writing query to %s: %w", server, err)
	}
	resp, err := co.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("reading reply from %s: %w", server, err)
	}
	return resp, nil
}

// dohClientCache holds one HTTP client per upstream.
//
// A client per query would mean a TLS handshake per name looked up, which is
// exactly the cost DoH keep-alives exist to avoid.
//
// The cached transport dials by upstream *id*, resolving the provider at dial
// time rather than capturing one. That matters because a provider value is not
// a stable identity - a tailnet's is built fresh on every lookup, so caching
// against the value would miss every time - and because an upstream that is
// reconfigured or disabled must be observed on the next dial, exactly as it is
// everywhere else.
type dohClientCache struct {
	mu      sync.Mutex
	entries map[UpstreamID]*http.Client
}

// dohClients returns this engine's cache, built on first use so that an Engine
// constructed without one still works.
func (e *Engine) dohClients() *dohClientCache {
	e.dohOnce.Do(func() {
		e.dohCache = &dohClientCache{entries: make(map[UpstreamID]*http.Client)}
	})
	return e.dohCache
}

func (e *Engine) dohClientFor(id UpstreamID) *http.Client {
	c := e.dohClients()
	c.mu.Lock()
	defer c.mu.Unlock()

	if client, ok := c.entries[id]; ok {
		return client
	}
	client := &http.Client{
		Timeout: dohTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				p, ok := e.readyProvider(id)
				if !ok {
					return nil, fmt.Errorf("%w: %q", ErrUpstreamNotReady, id)
				}
				conn, err := p.Dial(ctx, network, address)
				if err == nil {
					return conn, nil
				}
				// Some upstreams (WireGuard's own netstack, which has no
				// resolver of its own - see wireguardProvider.Dial's doc
				// comment) can only dial a literal address:port, unlike
				// SOCKS5/Tailnet upstreams which resolve a hostname at the
				// far end. If the address wasn't already literal, resolve
				// the DoH resolver's own hostname off-tunnel (the same
				// bootstrap path the device-direct DoH client uses for the
				// same reason) and retry once with the literal IP. A
				// provider that can already resolve hostnames itself
				// succeeds on the first attempt and never reaches this
				// fallback, so its leak properties (letting the far end
				// resolve, not the device) are unchanged.
				host, port, splitErr := net.SplitHostPort(address)
				if splitErr != nil {
					return nil, err
				}
				if _, parseErr := netip.ParseAddr(host); parseErr == nil {
					return nil, err
				}
				ips, resolveErr := bootstrapResolve(ctx, host)
				if resolveErr != nil || len(ips) == 0 {
					return nil, err
				}
				return p.Dial(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
			// Same reason as dohHTTPClient: setting DialContext otherwise
			// suppresses HTTP/2, and some providers serve HTTP/2 only.
			ForceAttemptHTTP2: true,
		},
	}
	c.entries[id] = client
	return client
}

// exchangeDoHVia forwards a DoH query through an upstream.
//
// Name resolution for the resolver's own hostname is left to the upstream: a
// SOCKS5 proxy resolves it at the far end, which is the behaviour a user
// choosing a proxy would expect. An upstream that cannot - a WireGuard tunnel,
// which needs a literal - reports that plainly, and a DoH URL written with an IP
// literal works everywhere.
func (e *Engine) exchangeDoHVia(id UpstreamID, resolverURL string, req *dns.Msg) (*dns.Msg, error) {
	return exchangeDoHWith(e.dohClientFor(id), resolverURL, req)
}
