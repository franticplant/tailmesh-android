// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A peer connects to the listener with an ordinary WireGuard client and
// reaches a TCP echo server on the host through @direct.
func TestWireGuardListenerCarriesTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two WireGuard devices")
	}
	data := t.TempDir()
	e := NewEngine(data, &MockCallback{})
	t.Cleanup(e.Close)

	// Not loopback: the listener's stack, like any router, drops packets
	// addressed to 127.0.0.0/8.
	hostIP := ""
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			hostIP = n.IP.String()
			break
		}
	}
	if hostIP == "" {
		t.Skip("no non-loopback IPv4 address to reach")
	}
	echo, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	port := freeUDPPort(t)
	cfg, err := e.SaveWireGuardListener("", uint16(port), DirectUpstreamID, netip.Prefix{}, "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := e.AddWireGuardListenerPeer(cfg.ID, "laptop", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "Endpoint = 127.0.0.1:"+strconv.Itoa(port)) || !strings.Contains(conf, "Address = 10.66.66.2/32") {
		t.Fatalf("client config:\n%s", conf)
	}

	js, err := ParseWireGuardQuickConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ParseWireGuardConfigJSON("client", js)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWireGuardUpstream(clientCfg, newRealBind(), testLogf(t, "client"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("dial through the listener: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("hello through the phone\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello through the phone\n" {
		t.Fatalf("echo: %q %v", line, err)
	}

	// DNS: every port-53 query from a peer is answered by the phone's
	// resolver, whatever server the peer asked.
	fake, err := net.ListenPacket("udp", net.JoinHostPort(hostIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := fake.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(dns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(q)
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 7)})
			out, _ := m.Pack()
			fake.WriteTo(out, from)
		}
	}()
	e.SetUpstreamDNS(fake.LocalAddr().String())
	for _, server := range []string{"10.66.66.1:53", "9.9.9.9:53"} {
		dc, err := client.Dial(ctx, "udp", server)
		if err != nil {
			t.Fatalf("dns dial %s: %v", server, err)
		}
		q := new(dns.Msg)
		q.SetQuestion("example.test.", dns.TypeA)
		out, _ := q.Pack()
		dc.SetDeadline(time.Now().Add(5 * time.Second))
		dc.Write(out)
		buf := make([]byte, 1500)
		n, err := dc.Read(buf)
		dc.Close()
		if err != nil {
			t.Fatalf("dns via %s: %v", server, err)
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.0.2.7" {
			t.Errorf("dns via %s: %v %v", server, r, err)
		}
	}
	if list := e.WireGuardListenersSnapshot(); list[0].DNSMode != "phone" || list[0].PeerDNS != "10.66.66.1" {
		t.Errorf("dns info: %+v", list[0])
	}

	list := e.WireGuardListenersSnapshot()
	if len(list) != 1 || !list[0].Running || len(list[0].Peers) != 1 || len(list[0].PeerState) != 1 || list[0].PeerState[0].LastHandshakeAtMillis == 0 {
		t.Errorf("snapshot: %+v", list)
	}
	b, _ := os.ReadFile(e.wgListenersPath())
	if !strings.Contains(string(b), cfg.ID) {
		t.Error("config not stored")
	}

	// A second engine on the same data directory brings it back.
	e.Close()
	e2 := NewEngine(data, &MockCallback{})
	t.Cleanup(e2.Close)
	e2.RestoreWireGuardListeners()
	if l := e2.WireGuardListenersSnapshot(); len(l) != 1 || !l[0].Running {
		t.Errorf("restored: %+v", l)
	}
	if err := e2.DeleteWireGuardListener(cfg.ID); err != nil {
		t.Fatal(err)
	}
	if l := e2.WireGuardListenersSnapshot(); len(l) != 0 {
		t.Errorf("after delete: %+v", l)
	}
}

func TestWireGuardKeypair(t *testing.T) {
	priv, pub, err := newWGKeypair()
	if err != nil || wgPublicKey(priv) != pub {
		t.Fatalf("%v %v", err, pub)
	}
	if b := netipBroadcast(netip.MustParsePrefix("10.66.66.0/24")); b.String() != "10.66.66.255" {
		t.Error(b)
	}
}
