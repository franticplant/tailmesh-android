// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

// The node identities this device holds: one tsnet state directory per
// tailnet and per exit-node upstream, each with the login profiles its
// tailscaled.state remembers. Read-only, on demand. Only the profile list is
// read from a state file, never the keys next to it.

// IdentityProfile is one login profile stored in a state directory.
type IdentityProfile struct {
	ProfileID string `json:"profileId"`
	NodeID    string `json:"nodeId,omitempty"`
	// Tailnet is the tailnet's name (NetworkProfile.DomainName).
	Tailnet    string `json:"tailnet,omitempty"`
	DNSName    string `json:"dnsName,omitempty"`
	LoginName  string `json:"loginName,omitempty"`
	ControlURL string `json:"controlUrl,omitempty"`
	Current    bool   `json:"current"`
}

// IdentityLive is what the running node reports about itself.
type IdentityLive struct {
	State    string   `json:"state"`
	NodeID   string   `json:"nodeId,omitempty"`
	HostName string   `json:"hostName,omitempty"`
	DNSName  string   `json:"dnsName,omitempty"`
	IPs      []string `json:"ips,omitempty"`
}

// Identity is one state directory.
type Identity struct {
	StateDir string `json:"stateDir"`
	// Owner is the tailnet or exit-node upstream id the directory belongs
	// to; empty if none configured now does (a leftover).
	Owner     string `json:"owner,omitempty"`
	OwnerKind string `json:"ownerKind,omitempty"` // tailnet, exit-node
	// MachineName is the hostname this app gives the node (mp-<hash>,
	// mp-exit-<hash>), as the admin console shows it.
	MachineName     string            `json:"machineName,omitempty"`
	ModifiedAtMilli int64             `json:"modifiedAtMillis,omitempty"`
	Profiles        []IdentityProfile `json:"profiles"`
	Live            *IdentityLive     `json:"live,omitempty"`
	Error           string            `json:"error,omitempty"`
}

type identityOwner struct {
	id, kind, machine string
	srv               *tsnet.Server
}

// IdentitiesJSON lists every state directory under the engine's data
// directory with its profiles, owner and, for a running node, its live
// identity.
func (e *Engine) IdentitiesJSON(ctx context.Context) string {
	owners := map[string]identityOwner{}
	e.mu.RLock()
	for id, rt := range e.tailnets {
		owners[filepath.Base(rt.Config.StateDir)] = identityOwner{string(id), "tailnet", "mp-" + rt.Config.HashID, rt.Srv}
	}
	for id, rt := range e.exitNodes {
		owners[filepath.Base(rt.Config.StateDir)] = identityOwner{string(id), "exit-node", "mp-exit-" + rt.Config.HashID, rt.Srv}
	}
	e.mu.RUnlock()

	ids := readIdentities(e.dataDir)
	for i := range ids {
		o, ok := owners[filepath.Base(ids[i].StateDir)]
		if !ok {
			continue
		}
		ids[i].Owner, ids[i].OwnerKind, ids[i].MachineName = o.id, o.kind, o.machine
		if o.srv != nil {
			ids[i].Live = liveIdentity(ctx, o.srv)
		}
	}
	b, err := json.Marshal(ids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// readIdentities reads every state-* directory under dataDir.
func readIdentities(dataDir string) []Identity {
	dirs, _ := filepath.Glob(filepath.Join(dataDir, "state-*"))
	out := make([]Identity, 0, len(dirs))
	for _, d := range dirs {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			continue
		}
		id := Identity{StateDir: d, Profiles: []IdentityProfile{}}
		path := filepath.Join(d, "tailscaled.state")
		if fi, err := os.Stat(path); err == nil {
			id.ModifiedAtMilli = fi.ModTime().UnixMilli()
		}
		profiles, err := readStateProfiles(path)
		if err != nil {
			id.Error = err.Error()
		} else {
			id.Profiles = profiles
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StateDir < out[j].StateDir })
	return out
}

// readStateProfiles reads the login profiles from a tsnet FileStore file:
// a JSON object of state keys to base64 values. Only _profiles and
// _current-profile are decoded.
func readStateProfiles(path string) ([]IdentityProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []IdentityProfile{}, nil
		}
		return nil, err
	}
	var kv map[ipn.StateKey][]byte
	if err := json.Unmarshal(b, &kv); err != nil {
		return nil, err
	}
	current := string(kv[ipn.CurrentProfileStateKey])
	var known map[ipn.ProfileID]*ipn.LoginProfile
	if raw := kv[ipn.KnownProfilesStateKey]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &known); err != nil {
			return nil, err
		}
	}
	out := make([]IdentityProfile, 0, len(known))
	for pid, p := range known {
		if p == nil {
			continue
		}
		out = append(out, IdentityProfile{
			ProfileID:  string(pid),
			NodeID:     string(p.NodeID),
			Tailnet:    p.NetworkProfile.DomainName,
			DNSName:    strings.TrimSuffix(p.NetworkProfile.MagicDNSName, "."),
			LoginName:  p.UserProfile.LoginName,
			ControlURL: p.ControlURL,
			Current:    string(p.Key) == current || string(pid) == current,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID < out[j].ProfileID })
	return out, nil
}

func liveIdentity(ctx context.Context, srv *tsnet.Server) *IdentityLive {
	lc, err := srv.LocalClient()
	if err != nil {
		return &IdentityLive{State: "ERROR"}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil || st == nil {
		return &IdentityLive{State: "STARTING"}
	}
	l := &IdentityLive{State: st.BackendState}
	if st.Self != nil {
		l.NodeID = string(st.Self.ID)
		l.HostName = st.Self.HostName
		l.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
		for _, ip := range st.Self.TailscaleIPs {
			l.IPs = append(l.IPs, ip.String())
		}
	}
	return l
}
