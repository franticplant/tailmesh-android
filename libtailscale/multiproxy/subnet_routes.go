// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
)

// Subnet-route acceptance.
//
// A tailnet's peers advertise the prefixes they serve as subnet routers in
// PeerStatus.PrimaryRoutes. Accepting them is opt-in per tailnet (Tailscale's
// --accept-routes equivalent): a peer advertising 192.168.1.0/24 should not
// silently pull that range into this device's routing table. pollTailnetStatus
// already asks tsnet for the full peer list every 10s, so the routes are
// collected there and this file only turns the enabled tailnets' advertised
// prefixes into the engine's longest-prefix route table.
//
// The table is rebuilt rather than patched incrementally: a netmap can add,
// remove and move a prefix between peers in one update, and rebuilding is the
// only way to make the result independent of the order the tailnets' pollers
// happened to run in.

// SetTailnetAcceptRoutes turns the per-tailnet "use subnet routes" switch on
// or off. Routes advertised by a tailnet that is not running are kept in
// AdvertisedRoutes (so enabling later does not wait for the next poll) but are
// only included while the tailnet is enabled and this switch is on.
func (e *Engine) SetTailnetAcceptRoutes(identifier string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		return errors.New("engine is closing or closed")
	}
	rt, ok := e.tailnets[UpstreamID(identifier)]
	if !ok {
		return errors.New("tailnet not found")
	}
	if rt.AcceptRoutes == enabled {
		return nil
	}
	rt.AcceptRoutes = enabled
	e.rebuildSubnetsLocked()
	return nil
}

// setTailnetAdvertisedRoutes records the prefixes a running tailnet's peers
// currently serve. It is called by pollTailnetStatus with the peer list from
// the Status() call it already makes, so this adds no extra tsnet work.
func (e *Engine) setTailnetAdvertisedRoutes(identifier UpstreamID, routes map[netip.Prefix]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rt, ok := e.tailnets[identifier]
	if !ok || !rt.Enabled {
		return
	}
	rt.AdvertisedRoutes = routes
	e.rebuildSubnetsLocked()
}

// rebuildSubnetsLocked recomputes the engine's route table from every enabled
// tailnet that has "use subnet routes" on. e.mu must be held.
//
// Exact-prefix conflicts are resolved to the lexicographically lowest tailnet
// id, matching the deterministic tie-break real-IP conflicts use. Overlapping
// (but not equal) prefixes are not conflicts: the NAT router's longest-prefix
// match picks the more specific one.
func (e *Engine) rebuildSubnetsLocked() {
	// Routes that do not belong to a managed tailnet are left alone. There is
	// no production caller of AcceptSubnet today, but keeping them means a
	// future explicit/manual route is not silently dropped by the next poll.
	next := make([]subnetRoute, 0, len(e.subnets))
	for _, sr := range e.subnets {
		if _, managed := e.tailnets[UpstreamID(sr.TailnetID)]; !managed {
			next = append(next, sr)
		}
	}

	type candidate struct {
		tailnetID string
		peer      string
	}
	best := make(map[netip.Prefix]candidate)
	for id, rt := range e.tailnets {
		if !rt.Enabled || !rt.AcceptRoutes {
			continue
		}
		for prefix, peer := range rt.AdvertisedRoutes {
			current, ok := best[prefix]
			if !ok ||
				string(id) < current.tailnetID ||
				(string(id) == current.tailnetID && peer < current.peer) {
				best[prefix] = candidate{tailnetID: string(id), peer: peer}
			}
		}
	}
	for prefix, c := range best {
		next = append(next, subnetRoute{
			Prefix:    prefix,
			TailnetID: c.tailnetID,
			Peer:      c.peer,
		})
	}

	sort.Slice(next, func(i, j int) bool {
		if next[i].Prefix != next[j].Prefix {
			return next[i].Prefix.String() < next[j].Prefix.String()
		}
		return next[i].TailnetID < next[j].TailnetID
	})
	e.subnets = next
}

// SubnetRouteExport is one accepted route in GetSubnetRoutesJSON's "accepted"
// list.
type SubnetRouteExport struct {
	Prefix    string `json:"prefix"`
	TailnetID string `json:"tailnetId"`
	Peer      string `json:"peer,omitempty"`
}

// SubnetConflictCandidate is one tailnet advertising a conflicting prefix.
type SubnetConflictCandidate struct {
	TailnetID string `json:"tailnetId"`
	Peer      string `json:"peer,omitempty"`
	Chosen    bool   `json:"chosen"`
}

// SubnetConflict is one prefix advertised by more than one tailnet with "use
// subnet routes" on.
type SubnetConflict struct {
	Prefix     string                    `json:"prefix"`
	Candidates []SubnetConflictCandidate `json:"candidates"`
}

// SubnetRoutesExport is the shape of GetSubnetRoutesJSON.
type SubnetRoutesExport struct {
	Accepted  []SubnetRouteExport `json:"accepted"`
	Conflicts []SubnetConflict    `json:"conflicts"`
}

// GetSubnetRoutesJSON lists the routes currently accepted from tailnet peers
// and every exact-prefix conflict between enabled tailnets. The chosen route
// in "accepted" is by construction the same one the dataplane uses.
func (e *Engine) GetSubnetRoutesJSON() string {
	e.mu.RLock()
	accepted := make([]SubnetRouteExport, 0, len(e.subnets))
	for _, sr := range e.subnets {
		accepted = append(accepted, SubnetRouteExport{
			Prefix:    sr.Prefix.String(),
			TailnetID: sr.TailnetID,
			Peer:      sr.Peer,
		})
	}

	// prefix -> tailnet -> advertising peer, limited to tailnets whose switch
	// is on. A prefix advertised by two peers of the same tailnet is not a
	// conflict; AdvertisedRoutes has already collapsed those.
	advertised := make(map[netip.Prefix]map[string]string)
	for id, rt := range e.tailnets {
		if !rt.Enabled || !rt.AcceptRoutes {
			continue
		}
		for prefix, peer := range rt.AdvertisedRoutes {
			byTailnet := advertised[prefix]
			if byTailnet == nil {
				byTailnet = make(map[string]string)
				advertised[prefix] = byTailnet
			}
			byTailnet[string(id)] = peer
		}
	}
	e.mu.RUnlock()

	conflicts := make([]SubnetConflict, 0)
	for prefix, byTailnet := range advertised {
		if len(byTailnet) < 2 {
			continue
		}
		candidates := make([]SubnetConflictCandidate, 0, len(byTailnet))
		chosen := ""
		for id := range byTailnet {
			if chosen == "" || id < chosen {
				chosen = id
			}
		}
		for id, peer := range byTailnet {
			candidates = append(candidates, SubnetConflictCandidate{
				TailnetID: id,
				Peer:      peer,
				Chosen:    id == chosen,
			})
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].TailnetID < candidates[j].TailnetID
		})
		conflicts = append(conflicts, SubnetConflict{
			Prefix:     prefix.String(),
			Candidates: candidates,
		})
	}

	sort.Slice(accepted, func(i, j int) bool {
		if accepted[i].Prefix != accepted[j].Prefix {
			return accepted[i].Prefix < accepted[j].Prefix
		}
		return accepted[i].TailnetID < accepted[j].TailnetID
	})
	sort.Slice(conflicts, func(i, j int) bool {
		return conflicts[i].Prefix < conflicts[j].Prefix
	})

	b, err := json.Marshal(SubnetRoutesExport{
		Accepted:  accepted,
		Conflicts: conflicts,
	})
	if err != nil {
		return `{"accepted":[],"conflicts":[]}`
	}
	return string(b)
}
