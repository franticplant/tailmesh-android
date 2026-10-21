// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"errors"
	"net"
	"testing"
)

func TestIsLocalNetworkAddress(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.29.103.139:51820":        true, // USB tether
		"192.168.43.10:1080":         true, // hotspot
		"172.20.0.5:443":             true,
		"169.254.10.1:80":            true,
		"[fd12::1]:51820":            true,
		"[fe80::1]:51820":            true,
		"[::ffff:192.168.1.2]:51820": true,
		"169.150.218.80:51820":       false, // a commercial VPN endpoint
		"100.105.158.102:51820":      false, // a tailnet address
		"127.0.0.1:1080":             false, // loopback keeps its own path
		"[2a07:b944::2:1]:51820":     false,
		"vpn.example.com:51820":      false,
		"10.0.0.1":                   false, // no port
	} {
		if got := IsLocalNetworkAddress(addr); got != want {
			t.Errorf("IsLocalNetworkAddress(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestProtectOnlyDialerProtectsEachSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var protected []int
	c, err := ProtectOnlyDialer(func(fd int) error {
		protected = append(protected, fd)
		return nil
	}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	c.Close()
	if len(protected) != 1 {
		t.Fatalf("protect called %d times, want 1", len(protected))
	}

	refused := errors.New("protect refused")
	if _, err := ProtectOnlyDialer(func(int) error { return refused }).Dial("tcp", ln.Addr().String()); !errors.Is(err, refused) {
		t.Fatalf("Dial with failing protect = %v, want it to fail with the protect error", err)
	}
}
