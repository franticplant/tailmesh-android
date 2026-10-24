// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeDirectTCPAndUDP(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	r := e.Probe(context.Background(), ProbeRequest{Upstream: "@direct", Target: ln.Addr().String()})
	if !r.OK || r.Kind != "direct" || r.RemoteAddr != ln.Addr().String() || r.LocalAddr == "" || r.Path != "direct-bypass" {
		t.Errorf("tcp: %+v", r)
	}

	// A closed port is refused, at the dial stage.
	addr := ln.Addr().String()
	ln.Close()
	r = e.Probe(context.Background(), ProbeRequest{Upstream: "@direct", Target: addr})
	if r.OK || r.Stage != "dial" || r.Error == "" {
		t.Errorf("refused: %+v", r)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	payload, _ := ParseProbePayload("0102")
	r = e.Probe(context.Background(), ProbeRequest{Upstream: "@direct", Target: pc.LocalAddr().String(), UDP: true, WaitReply: true, Payload: payload})
	if !r.OK || r.SentBytes != 2 || r.ReplyBytes != 5 || r.ReplyHex != "72653a0102" {
		t.Errorf("udp echo: %+v", r)
	}
	// Send only: ok once sent.
	r = e.Probe(context.Background(), ProbeRequest{Upstream: "@direct", Target: pc.LocalAddr().String(), UDP: true})
	if !r.OK || r.SentBytes != 1 {
		t.Errorf("udp send: %+v", r)
	}
}

func TestProbeUDPNoReplyTimesOut(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close() // never answers
	start := time.Now()
	r := e.Probe(context.Background(), ProbeRequest{Upstream: "@direct", Target: pc.LocalAddr().String(), UDP: true, WaitReply: true, Timeout: 300 * time.Millisecond})
	if r.OK || r.Stage != "reply" {
		t.Errorf("no reply: %+v", r)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestProbeRefusals(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	t.Cleanup(e.Close)
	for _, c := range []struct {
		req  ProbeRequest
		want string
	}{
		{ProbeRequest{Upstream: "nope", Target: "1.2.3.4:80"}, "no such upstream"},
		{ProbeRequest{Upstream: "@direct", Target: "1.2.3.4"}, "host:port"},
		{ProbeRequest{Upstream: "@direct", Target: "1.2.3.4:53", UDP: true, Payload: make([]byte, 65)}, "at most"},
	} {
		r := e.Probe(context.Background(), c.req)
		if r.OK || !strings.Contains(r.Error, c.want) {
			t.Errorf("%+v: %+v, want error containing %q", c.req, r, c.want)
		}
	}
	if _, err := ParseProbePayload(strings.Repeat("00", 65)); err == nil {
		t.Error("65-byte payload accepted")
	}
	if _, err := ParseProbePayload("zz"); err == nil {
		t.Error("bad hex accepted")
	}
}
