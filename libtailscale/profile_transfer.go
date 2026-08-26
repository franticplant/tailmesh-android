// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"
	"fmt"

	"tailscale.com/ipn"
)

// prepareProfileForMultiProxy copies one persisted regular profile into an
// isolated single-profile store. It never modifies the source store.
func prepareProfileForMultiProxy(base, dst ipn.StateStore, profileID ipn.ProfileID) error {
	profiles, err := readLoginProfiles(base)
	if err != nil {
		return err
	}
	profile, ok := profiles[profileID]
	if !ok || profile.Key == "" {
		return fmt.Errorf("login profile %q not found or not persisted", profileID)
	}
	prefs, err := base.ReadState(profile.Key)
	if err != nil {
		return fmt.Errorf("read profile %q state: %w", profileID, err)
	}
	single, err := json.Marshal(map[ipn.ProfileID]ipn.LoginProfile{profileID: profile})
	if err != nil {
		return fmt.Errorf("marshal profile %q: %w", profileID, err)
	}
	for key, value := range map[ipn.StateKey][]byte{
		ipn.KnownProfilesStateKey:  single,
		ipn.CurrentProfileStateKey: []byte(profile.Key),
		profile.Key:                prefs,
	} {
		if err := dst.WriteState(key, value); err != nil {
			return fmt.Errorf("seed multiproxy state %q: %w", key, err)
		}
	}
	if machineKey, err := base.ReadState(ipn.MachineKeyStateKey); err == nil {
		if err := dst.WriteState(ipn.MachineKeyStateKey, machineKey); err != nil {
			return fmt.Errorf("seed multiproxy machine key: %w", err)
		}
	}
	return nil
}

// restoreProfileFromMultiProxy merges one stopped tsnet profile into the
// regular profile index without replacing any other regular profile.
func restoreProfileFromMultiProxy(src, base ipn.StateStore, profileID ipn.ProfileID) error {
	srcProfiles, err := readLoginProfiles(src)
	if err != nil {
		return err
	}
	profile, ok := srcProfiles[profileID]
	if !ok || profile.Key == "" {
		return fmt.Errorf("multiproxy profile %q not found", profileID)
	}
	prefs, err := src.ReadState(profile.Key)
	if err != nil {
		return fmt.Errorf("read multiproxy profile %q state: %w", profileID, err)
	}
	baseProfiles, err := readLoginProfiles(base)
	if err != nil {
		return err
	}
	baseProfiles[profileID] = profile
	known, err := json.Marshal(baseProfiles)
	if err != nil {
		return fmt.Errorf("marshal regular profiles: %w", err)
	}
	if err := base.WriteState(profile.Key, prefs); err != nil {
		return fmt.Errorf("restore regular profile %q state: %w", profileID, err)
	}
	if err := base.WriteState(ipn.KnownProfilesStateKey, known); err != nil {
		return fmt.Errorf("restore regular profile index: %w", err)
	}
	return nil
}

func readLoginProfiles(store ipn.StateStore) (map[ipn.ProfileID]ipn.LoginProfile, error) {
	b, err := store.ReadState(ipn.KnownProfilesStateKey)
	if err != nil {
		return nil, fmt.Errorf("read login profiles: %w", err)
	}
	profiles := map[ipn.ProfileID]ipn.LoginProfile{}
	if err := json.Unmarshal(b, &profiles); err != nil {
		return nil, fmt.Errorf("decode login profiles: %w", err)
	}
	return profiles, nil
}
