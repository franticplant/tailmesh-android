// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/json"
	"reflect"
	"testing"

	"tailscale.com/net/netns"
)

func invNet(iface string, isDefault, internet bool, routes ...string) InventoryNetwork {
	n := InventoryNetwork{NetworkKey: iface + "-key", InterfaceName: iface, IsDefault: isDefault, HasInternetCapability: internet}
	for _, r := range routes {
		n.Routes = append(n.Routes, InventoryRoute{CIDR: r, IsDefault: r == "0.0.0.0/0" || r == "::/0"})
	}
	return n
}

func TestDecideDirectLinks(t *testing.T) {
	v4 := "0.0.0.0/0"
	v6 := "::/0"
	tests := []struct {
		name       string
		setting    bool
		nets       []InventoryNetwork
		wantUnbind bool
		wantReason string
		wantOther  []string
		wantIgnore []string
	}{
		{
			name:       "setting off",
			setting:    false,
			nets:       []InventoryNetwork{invNet("wlan0", true, true, v4, v6)},
			wantReason: DirectLinksOffSetting,
		},
		{
			name:       "no inventory",
			setting:    true,
			wantReason: DirectLinksOffNoNetwork,
		},
		{
			name:       "default has IPv6",
			setting:    true,
			nets:       []InventoryNetwork{invNet("wlan0", true, true, v4, v6), invNet("rmnet0", false, true, v4, v6)},
			wantUnbind: true,
			wantReason: DirectLinksOn,
			wantOther:  []string{"rmnet0"},
		},
		{
			name:       "IPv4-only default, nothing else",
			setting:    true,
			nets:       []InventoryNetwork{invNet("wlan0", true, true, v4, "192.168.1.0/24")},
			wantUnbind: true,
			wantReason: DirectLinksOn,
		},
		{
			// tailscale#6152: Wi-Fi without IPv6 while mobile data has it.
			name:       "IPv4-only Wi-Fi, mobile data with IPv6",
			setting:    true,
			nets:       []InventoryNetwork{invNet("wlan0", true, true, v4), invNet("rmnet0", false, true, v4, v6)},
			wantReason: DirectLinksOffIPv6,
			wantOther:  []string{"rmnet0"},
		},
		{
			// The Pixel 8 on mobile data: the internet APN is IPv4-only and
			// IPv6 lives on a second cellular network without INTERNET.
			name:    "IPv4-only mobile data, IPv6 only on a non-internet network",
			setting: true,
			nets: []InventoryNetwork{
				invNet("rmnet1", true, true, v4, "10.36.206.29/32"),
				invNet("rmnet2", false, false, v6, "2a02:2010:14b4:9f43::/64"),
				invNet("ncm0", false, false, "10.29.103.0/24"),
			},
			wantUnbind: true,
			wantReason: DirectLinksOn,
			wantIgnore: []string{"rmnet2"},
		},
		{
			name:    "a VPN's IPv6 does not count",
			setting: true,
			nets: []InventoryNetwork{
				invNet("rmnet1", true, true, v4),
				func() InventoryNetwork { n := invNet("tun0", false, true, v6); n.IsVPN = true; return n }(),
			},
			wantUnbind: true,
			wantReason: DirectLinksOn,
		},
		{
			name:       "no default network, IPv6 elsewhere",
			setting:    true,
			nets:       []InventoryNetwork{invNet("rmnet0", false, true, v6)},
			wantReason: DirectLinksOffIPv6,
			wantOther:  []string{"rmnet0"},
		},
		{
			name:       "an IPv6 address route is not a default route",
			setting:    true,
			nets:       []InventoryNetwork{invNet("wlan0", true, true, v4), invNet("rmnet0", false, true, v4, "2001:db8::/64")},
			wantUnbind: true,
			wantReason: DirectLinksOn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DecideDirectLinks(tt.setting, tt.nets)
			if d.Unbind != tt.wantUnbind || d.Reason != tt.wantReason {
				t.Errorf("unbind=%v reason=%q, want %v %q", d.Unbind, d.Reason, tt.wantUnbind, tt.wantReason)
			}
			if want := append([]string{}, tt.wantOther...); !reflect.DeepEqual(d.OtherIPv6Networks, want) {
				t.Errorf("other IPv6 networks %v, want %v", d.OtherIPv6Networks, want)
			}
			if !reflect.DeepEqual(d.IgnoredIPv6Networks, tt.wantIgnore) {
				t.Errorf("ignored IPv6 networks %v, want %v", d.IgnoredIPv6Networks, tt.wantIgnore)
			}
		})
	}
}

func TestApplyDirectLinks(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(func() { netns.SetAppDisableAndroidBindToActiveNetwork(t.Logf, false) })

	inv := func(nets ...InventoryNetwork) string {
		b, _ := json.Marshal(nets)
		return string(b)
	}
	state := func(raw string) DirectLinksState {
		t.Helper()
		var s DirectLinksState
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	safe := inv(invNet("rmnet1", true, true, "0.0.0.0/0"))
	unsafe := inv(invNet("wlan0", true, true, "0.0.0.0/0"), invNet("rmnet0", false, true, "::/0"))

	if s := state(e.DirectLinksJSON()); s.Unbound || s.Reason != DirectLinksOffSetting {
		t.Errorf("initial: %+v", s)
	}
	s := state(e.ApplyDirectLinks(true, safe))
	if !s.Unbound || s.Reason != DirectLinksOn || s.ChangedAtMillis == 0 {
		t.Errorf("on: %+v", s)
	}
	if d, _ := netns.AndroidBindToActiveNetworkDisabled(); !d {
		t.Error("netns flag not set")
	}
	if s := state(e.ApplyDirectLinks(true, unsafe)); s.Unbound || s.Reason != DirectLinksOffIPv6 {
		t.Errorf("unsafe: %+v", s)
	}
	e.ApplyDirectLinks(true, safe)
	if s := state(e.ApplyDirectLinks(false, safe)); s.Unbound || s.Reason != DirectLinksOffSetting {
		t.Errorf("off: %+v", s)
	}
	if s := state(e.ApplyDirectLinks(true, "not json")); s.Unbound || s.Reason != DirectLinksOffNoNetwork {
		t.Errorf("bad inventory: %+v", s)
	}

	e.ApplyDirectLinks(true, safe)
	e.Close()
	if d, _ := netns.AndroidBindToActiveNetworkDisabled(); d {
		t.Error("Close left the netns flag set")
	}
}
