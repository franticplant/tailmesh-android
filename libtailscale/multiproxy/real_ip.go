// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"net/netip"
	"sort"
)

// AddressConflictCandidate is one peer laying claim to a real Tailscale IP.
type AddressConflictCandidate struct {
	TailnetID string `json:"tailnetId"`
	Hostname  string `json:"hostname"`
	Active    bool   `json:"active"`
}

// AddressConflictExport describes one real Tailscale IP that more than one
// currently-known upstream reports a peer at.
type AddressConflictExport struct {
	IP         string                     `json:"ip"`
	Candidates []AddressConflictCandidate `json:"candidates"`
	// ChosenTailnetID is the upstream traffic to this IP will actually be
	// sent to, or "" if none of the claimants is currently active (in which
	// case the address fails closed rather than being guessed at).
	ChosenTailnetID string `json:"chosenTailnetId"`
}

// sortRealIPCandidates orders claimants deterministically, so the same
// address resolves to the same upstream for as long as the netmap holds
// still. Sorting by UpstreamID (rather than, say, netmap arrival order) is
// what makes the choice stable across engine restarts too.
func sortRealIPCandidates(candidates []TargetRecord) {
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].RequiredUpstream != candidates[j].RequiredUpstream {
			return candidates[i].RequiredUpstream < candidates[j].RequiredUpstream
		}
		return candidates[i].Key.StableID < candidates[j].Key.StableID
	})
}

// chooseRealIPCandidate applies the tie-break: lowest UpstreamID among the
// claimants whose upstream is currently active. Inactive upstreams are
// skipped rather than chosen-and-failed, so a conflict with one live tailnet
// and one stopped one resolves cleanly to the live one.
//
// Both resolveRealIPRoute and the conflict export go through here, so what
// the user is shown as "using X" is by construction the same decision the
// dataplane makes.
func (e *Engine) chooseRealIPCandidate(candidates []TargetRecord) (TargetRecord, bool) {
	for i := range candidates {
		if _, active := e.activeTailnetServer(candidates[i].RequiredUpstream); active {
			return candidates[i], true
		}
	}
	return TargetRecord{}, false
}

// realIPCandidates returns a private copy of the claimants for addr.
func (e *Engine) realIPCandidates(addr netip.Addr) []TargetRecord {
	e.targetMutex.RLock()
	candidates := append([]TargetRecord(nil), e.realIPIndex[addr]...)
	e.targetMutex.RUnlock()
	sortRealIPCandidates(candidates)
	return candidates
}

// GetAddressConflictsJSON lists every real Tailscale IP that is currently
// claimed by more than one upstream, along with which upstream would win.
//
// This is deliberately computed from the netmap rather than from observed
// traffic: the OnAddressCrossover events only fire once something actually
// dials an ambiguous address, which means a user could be one connection away
// from silently reaching the wrong machine and have no way to know it. This
// call lets the UI show the conflicts up front instead.
func (e *Engine) GetAddressConflictsJSON() string {
	e.targetMutex.RLock()
	byIP := make(map[netip.Addr][]TargetRecord, len(e.realIPIndex))
	for addr, recs := range e.realIPIndex {
		if len(recs) < 2 {
			continue
		}
		byIP[addr] = append([]TargetRecord(nil), recs...)
	}
	e.targetMutex.RUnlock()

	out := make([]AddressConflictExport, 0, len(byIP))
	for addr, candidates := range byIP {
		sortRealIPCandidates(candidates)

		// A single peer holding both a v4 and a v6 address is not a
		// conflict; only distinct peers are. Two records for the same
		// TargetKey can't reach the same map entry (one key yields one v4
		// and one v6 address), but distinct upstreams reporting the same
		// key would, so filter on the key rather than trusting length.
		distinct := make(map[TargetKey]bool, len(candidates))
		for _, c := range candidates {
			distinct[c.Key] = true
		}
		if len(distinct) < 2 {
			continue
		}

		export := AddressConflictExport{IP: addr.String()}
		for _, c := range candidates {
			_, active := e.activeTailnetServer(c.RequiredUpstream)
			export.Candidates = append(export.Candidates, AddressConflictCandidate{
				TailnetID: string(c.RequiredUpstream),
				Hostname:  c.Hostname,
				Active:    active,
			})
		}
		if chosen, ok := e.chooseRealIPCandidate(candidates); ok {
			export.ChosenTailnetID = string(chosen.RequiredUpstream)
		}
		out = append(out, export)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })

	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}
