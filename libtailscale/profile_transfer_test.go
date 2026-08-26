// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
)

func TestProfileMultiProxyRoundTrip(t *testing.T) {
	base := new(mem.Store)
	dst := new(mem.Store)
	p1 := ipn.LoginProfile{ID: "p1", Key: "profile-p1", Name: "one"}
	p2 := ipn.LoginProfile{ID: "p2", Key: "profile-p2", Name: "two"}
	known, err := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{"p1": p1, "p2": p2})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[ipn.StateKey][]byte{
		ipn.KnownProfilesStateKey: known,
		p1.Key:                    []byte("prefs-one"),
		p2.Key:                    []byte("prefs-two"),
		ipn.MachineKeyStateKey:    []byte("machine"),
	} {
		if err := base.WriteState(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareProfileForMultiProxy(base, dst, p1.ID); err != nil {
		t.Fatal(err)
	}
	gotProfiles, err := readLoginProfiles(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotProfiles) != 1 || gotProfiles[p1.ID].Name != p1.Name {
		t.Fatalf("seeded profiles = %#v", gotProfiles)
	}
	if _, err := dst.ReadState(p2.Key); err != ipn.ErrStateNotExist {
		t.Fatalf("unselected profile copied: %v", err)
	}
	if err := dst.WriteState(p1.Key, []byte("prefs-updated")); err != nil {
		t.Fatal(err)
	}
	if err := restoreProfileFromMultiProxy(dst, base, p1.ID); err != nil {
		t.Fatal(err)
	}
	got, err := base.ReadState(p1.Key)
	if err != nil || string(got) != "prefs-updated" {
		t.Fatalf("restored p1 = %q, %v", got, err)
	}
	got, err = base.ReadState(p2.Key)
	if err != nil || string(got) != "prefs-two" {
		t.Fatalf("preserved p2 = %q, %v", got, err)
	}
}
