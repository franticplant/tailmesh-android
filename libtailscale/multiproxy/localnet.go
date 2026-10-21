// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net"
	"net/netip"
	"syscall"
)

// IsLocalNetworkAddress reports whether address (host:port) is an IP literal
// in a private (RFC 1918, IPv6 ULA) or link-local range: an upstream that may
// sit on a network the device does not reach the internet through, such as a
// laptop on the phone's USB tether or hotspot. Hostnames are not resolved, so
// they report false.
func IsLocalNetworkAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// ProtectOnlyDialer dials with protect applied to each socket (on Android,
// VpnService.protect: keep it out of the VPN) and nothing else - in
// particular without binding it to a network, so the kernel's routing picks
// the interface.
func ProtectOnlyDialer(protect func(fd int) error) *net.Dialer {
	return &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var perr error
			if err := c.Control(func(fd uintptr) { perr = protect(int(fd)) }); err != nil {
				return err
			}
			return perr
		},
	}
}
