package multiproxy

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

type TailnetRuntimeExport struct {
	TailnetID   string `json:"tailnetId"`
	Enabled     bool   `json:"enabled"`
	State       string `json:"state"`
	MachineName string `json:"machineName,omitempty"`
	// ExitNodeIP is the peer address SetTailnetExitNode currently has this
	// tailnet pointed at, or empty if none is set. Read back from a live
	// Status() call (status.ExitNodeStatus), the same source of truth
	// EditPrefs writes to and the only place that can say what is *actually*
	// active, as opposed to what a picker UI last had selected before it was
	// closed and its local state discarded - see GetExitNodeCandidatesJSON's
	// doc comment for why the UI otherwise has no way to know this.
	ExitNodeIP string `json:"exitNodeIp,omitempty"`
}

type tailnetStateProbe struct {
	id      string
	enabled bool
	srv     *tsnet.Server
}

// pathInfo is the direct/DERP observation observedTailnetState derives from
// the same Status() call it already makes for exitNodeIP - no extra polling
// beyond what GetTailnetStatesJSON's existing 1s cadence already does (see
// observability.go's noteExitNodePath, which this feeds).
type pathInfo struct {
	hasExitNode bool
	direct      bool
	derpRegion  string
}

func observedTailnetState(enabled bool, srv *tsnet.Server) (state, machineName, exitNodeIP string, path pathInfo) {
	if !enabled || srv == nil {
		return "STOPPED", "", "", path
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return "ERROR", "", "", path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := lc.Status(ctx)
	if err != nil || status == nil {
		return "STARTING", "", "", path
	}
	if status.BackendState == "" {
		return "STARTING", "", "", path
	}
	if status.Self != nil {
		machineName = status.Self.HostName
	}
	if status.ExitNodeStatus != nil && len(status.ExitNodeStatus.TailscaleIPs) > 0 {
		exitNodeIP = status.ExitNodeStatus.TailscaleIPs[0].Addr().String()
		path.hasExitNode = true
		for _, peer := range status.Peer {
			if peer == nil || peer.ID != status.ExitNodeStatus.ID {
				continue
			}
			path.direct = peer.CurAddr != ""
			path.derpRegion = peer.Relay
			break
		}
	}
	return status.BackendState, machineName, exitNodeIP, path
}

// GetTailnetStatesJSON returns a stable snapshot of registered Tailnet runtimes
// including observed tsnet backend state. Runtime pointers are snapshotted while
// holding Engine.mu; potentially blocking LocalClient/Status calls occur after
// releasing the lock, one goroutine per runtime so N runtimes cost one
// Status() round trip's worth of wall time, not N of them - this is polled
// every second (MultiProxySessionCoordinator.refreshRuntimeState), so a
// sequential scan would fall behind its own poll interval once more than a
// couple of tailnets (and, since GetExitNodeStatesJSON below is polled the
// same way, exit-node upstreams) are configured at once.
func (e *Engine) GetTailnetStatesJSON() string {
	e.mu.RLock()
	probes := make([]tailnetStateProbe, 0, len(e.tailnets))
	for id, rt := range e.tailnets {
		probes = append(probes, tailnetStateProbe{
			id:      string(id),
			enabled: rt.Enabled,
			srv:     rt.Srv,
		})
	}
	e.mu.RUnlock()

	out := make([]TailnetRuntimeExport, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p tailnetStateProbe) {
			defer wg.Done()
			state, machineName, exitNodeIP, path := observedTailnetState(p.enabled, p.srv)
			out[i] = TailnetRuntimeExport{
				TailnetID:   p.id,
				Enabled:     p.enabled,
				State:       state,
				MachineName: machineName,
				ExitNodeIP:  exitNodeIP,
			}
			e.noteExitNodePath(p.id, path.hasExitNode, path.direct, path.derpRegion)
		}(i, p)
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].TailnetID < out[j].TailnetID })
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ExitNodeRuntimeExport is GetExitNodeStatesJSON's per-upstream row. Mirrors
// TailnetRuntimeExport; MachineName is this upstream's own dedicated node
// identity, not the peer it routes through.
type ExitNodeRuntimeExport struct {
	ID              string `json:"id"`
	SourceTailnetID string `json:"sourceTailnetId"`
	PeerAddr        string `json:"peerAddr"`
	Enabled         bool   `json:"enabled"`
	State           string `json:"state"`
	MachineName     string `json:"machineName,omitempty"`
}

type exitNodeStateProbe struct {
	id              string
	sourceTailnetID string
	peerAddr        string
	enabled         bool
	srv             *tsnet.Server
}

// GetExitNodeStatesJSON returns a stable snapshot of registered exit-node
// upstreams, including observed tsnet backend state.
//
// Surfacing this matters specifically because a dedicated exit-node identity
// (see upstream_exitnode.go) is a brand new device on its source tailnet: if
// that tailnet requires device approval, or the auth key was already
// consumed elsewhere, the node can sit in NeedsMachineAuth or NeedsLogin
// indefinitely - a state AddExitNodeUpstream's EditPrefs call cannot detect
// (it is a local prefs write, not a control-plane round trip, so it succeeds
// regardless of approval state). Without this, that stuck state was
// invisible: the upstream looked "RUNNING" because EditPrefs succeeded
// locally, while every dial through it actually failed.
func (e *Engine) GetExitNodeStatesJSON() string {
	e.mu.RLock()
	probes := make([]exitNodeStateProbe, 0, len(e.exitNodes))
	for id, rt := range e.exitNodes {
		probes = append(probes, exitNodeStateProbe{
			id:              string(id),
			sourceTailnetID: rt.Config.SourceTailnetID,
			peerAddr:        rt.Config.PeerAddr,
			enabled:         rt.Enabled,
			srv:             rt.Srv,
		})
	}
	e.mu.RUnlock()

	// One goroutine per upstream - see GetTailnetStatesJSON's doc comment.
	// This is the function that matters most for that: a user wanting several
	// simultaneous exit nodes (the whole point of AddExitNodeUpstream) is
	// exactly the case that would otherwise serialize the most Status() calls
	// onto one 1-second poll tick.
	out := make([]ExitNodeRuntimeExport, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p exitNodeStateProbe) {
			defer wg.Done()
			state, machineName, _, _ := observedTailnetState(p.enabled, p.srv)
			out[i] = ExitNodeRuntimeExport{
				ID:              p.id,
				SourceTailnetID: p.sourceTailnetID,
				PeerAddr:        p.peerAddr,
				Enabled:         p.enabled,
				State:           state,
				MachineName:     machineName,
			}
		}(i, p)
	}
	wg.Wait()

	// An exit-node identity's AuthKey is a one-time bootstrap credential -
	// once tsnet has actually reached Running (not just "EditPrefs
	// succeeded locally", which upstream_exitnode.go's optimistic RUNNING
	// event cannot distinguish from a stuck NeedsMachineAuth/NeedsLogin -
	// see this function's doc comment), it is never read again: a later
	// disable/enable cycle restarts the same tsnet.Server against its own
	// persisted state directory. Drop it from memory here, the one place
	// that already confirms real backend state via a live Status() call.
	var toClear []UpstreamID
	for _, exp := range out {
		if exp.State == "Running" {
			toClear = append(toClear, UpstreamID(exp.ID))
		}
	}
	if len(toClear) > 0 {
		e.mu.Lock()
		for _, id := range toClear {
			if rt := e.exitNodes[id]; rt != nil {
				rt.Config.AuthKey = ""
			}
		}
		e.mu.Unlock()
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// ClearTailnetAuthKey drops the bootstrap auth key from the in-memory runtime
// after the Tailnet has successfully established persistent tsnet state.
func (e *Engine) ClearTailnetAuthKey(identifier string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rt := e.tailnets[UpstreamID(identifier)]; rt != nil {
		rt.Config.AuthKey = ""
	}
}
