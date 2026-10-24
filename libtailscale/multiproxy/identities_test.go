// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

func writeTestState(t *testing.T, dir string, current ipn.StateKey, profiles map[ipn.ProfileID]*ipn.LoginProfile) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pj, _ := json.Marshal(profiles)
	kv := map[ipn.StateKey][]byte{
		ipn.KnownProfilesStateKey:  pj,
		ipn.CurrentProfileStateKey: []byte(current),
		"profile-a":                []byte(`{"PrivateNodeKey":"privkey:SECRET"}`),
		"_machinekey":              []byte("privkey:SECRET"),
	}
	b, _ := json.Marshal(kv)
	if err := os.WriteFile(filepath.Join(dir, "tailscaled.state"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentities(t *testing.T) {
	data := t.TempDir()
	e := NewEngine(data, &MockCallback{})
	t.Cleanup(e.Close)

	ownedDir := filepath.Join(data, "state-aaaa")
	writeTestState(t, ownedDir, "profile-a", map[ipn.ProfileID]*ipn.LoginProfile{
		"a": {
			ID: "a", Key: "profile-a", NodeID: "nNode1CNTRL",
			NetworkProfile: ipn.NetworkProfile{DomainName: "example.ts.net", MagicDNSName: "mp-aaaa.example.ts.net."},
			UserProfile:    tailcfg.UserProfile{LoginName: "fran@example.com"},
			ControlURL:     "https://controlplane.tailscale.com",
		},
		"b": {ID: "b", Key: "profile-b", NodeID: "nOldCNTRL"},
	})
	writeTestState(t, filepath.Join(data, "state-bbbb"), "", nil) // a leftover with no profiles
	if err := os.MkdirAll(filepath.Join(data, "state-cccc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "state-cccc", "tailscaled.state"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	e.mu.Lock()
	e.tailnets["regular-a"] = &TailnetRuntime{Config: TailnetConfig{HashID: "aaaa", StateDir: ownedDir}}
	e.mu.Unlock()

	raw := e.IdentitiesJSON(context.Background())
	if strings.Contains(raw, "SECRET") {
		t.Fatalf("keys leaked: %s", raw)
	}
	var got []Identity
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d identities: %s", len(got), raw)
	}
	a := got[0]
	if a.Owner != "regular-a" || a.OwnerKind != "tailnet" || a.MachineName != "mp-aaaa" || len(a.Profiles) != 2 || a.Live != nil {
		t.Errorf("owned: %+v", a)
	}
	p := a.Profiles[0]
	if !p.Current || p.NodeID != "nNode1CNTRL" || p.Tailnet != "example.ts.net" || p.DNSName != "mp-aaaa.example.ts.net" || p.LoginName != "fran@example.com" {
		t.Errorf("current profile: %+v", p)
	}
	if a.Profiles[1].Current {
		t.Errorf("old profile marked current: %+v", a.Profiles[1])
	}
	if got[1].Owner != "" || len(got[1].Profiles) != 0 || got[1].Error != "" {
		t.Errorf("leftover: %+v", got[1])
	}
	if got[2].Error == "" {
		t.Errorf("broken state file: %+v", got[2])
	}
}
