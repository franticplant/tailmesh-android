package multiproxy

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"tailscale.com/tsnet"
)

type TailnetRuntimeExport struct {
	TailnetID   string `json:"tailnetId"`
	Enabled     bool   `json:"enabled"`
	State       string `json:"state"`
	MachineName string `json:"machineName,omitempty"`
}

type tailnetStateProbe struct {
	id      string
	enabled bool
	srv     *tsnet.Server
}

func observedTailnetState(enabled bool, srv *tsnet.Server) (state, machineName string) {
	if !enabled || srv == nil {
		return "STOPPED", ""
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return "ERROR", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := lc.Status(ctx)
	if err != nil || status == nil {
		return "STARTING", ""
	}
	if status.BackendState == "" {
		return "STARTING", ""
	}
	if status.Self != nil {
		machineName = status.Self.HostName
	}
	return status.BackendState, machineName
}

// GetTailnetStatesJSON returns a stable snapshot of registered Tailnet runtimes
// including observed tsnet backend state. Runtime pointers are snapshotted while
// holding Engine.mu; potentially blocking LocalClient/Status calls occur after
// releasing the lock.
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

	out := make([]TailnetRuntimeExport, 0, len(probes))
	for _, p := range probes {
		state, machineName := observedTailnetState(p.enabled, p.srv)
		out = append(out, TailnetRuntimeExport{
			TailnetID:   p.id,
			Enabled:     p.enabled,
			State:       state,
			MachineName: machineName,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].TailnetID < out[j].TailnetID })
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
