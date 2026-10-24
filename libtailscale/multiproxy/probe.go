// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Probing an upstream: "can upstream X reach host:port", answered from the
// engine with the same Dial every flow through that upstream uses. Nothing
// runs unless asked.

const (
	probeDefaultTimeout = 5 * time.Second
	probeMaxTimeout     = 15 * time.Second
	// probeMaxPayload caps what a UDP probe sends: enough for a protocol's
	// one-packet hello, not enough to move data.
	probeMaxPayload = 64
	// probeMaxReply is how much of a UDP reply is read and shown.
	probeMaxReply = 64
)

// ProbeRequest is one probe.
type ProbeRequest struct {
	Upstream string
	Target   string // host:port
	UDP      bool
	// WaitReply (UDP): wait for one datagram back.
	WaitReply bool
	Timeout   time.Duration
	// Payload (UDP) is sent as one datagram; a single zero byte if empty.
	Payload []byte
}

// ProbeResult is upstreams.probe's answer.
type ProbeResult struct {
	Upstream string `json:"upstream"`
	Kind     string `json:"kind,omitempty"`
	Via      string `json:"via,omitempty"`
	Target   string `json:"target"`
	Network  string `json:"network"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	// Stage is where it stopped: lookup, dial, send or reply.
	Stage string `json:"stage,omitempty"`
	// RemoteAddr is the address actually connected to (after any
	// resolution); LocalAddr the local end, which for @direct shows which
	// network the socket left on. Upstreams that tunnel (SOCKS5, the
	// tailnets) may report their own view of these.
	RemoteAddr string `json:"remoteAddr,omitempty"`
	LocalAddr  string `json:"localAddr,omitempty"`
	ConnectMs  int64  `json:"connectMs"`
	// UDP only.
	SentBytes  int    `json:"sentBytes,omitempty"`
	ReplyBytes int    `json:"replyBytes,omitempty"`
	ReplyHex   string `json:"replyHex,omitempty"`
	ReplyMs    int64  `json:"replyMs,omitempty"`
	// Path is how the upstream reaches the target where it knows: the
	// tailnet peer's direct/DERP path, a WireGuard handshake state.
	Path string `json:"path,omitempty"`
}

// ParseProbePayload decodes a hex payload, refusing more than probeMaxPayload bytes.
func ParseProbePayload(h string) ([]byte, error) {
	if h == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if len(b) > probeMaxPayload {
		return nil, fmt.Errorf("payload is %d bytes; at most %d", len(b), probeMaxPayload)
	}
	return b, nil
}

// Probe dials req.Target through req.Upstream and reports what happened. The
// dial is not counted in the upstream's stats.
func (e *Engine) Probe(ctx context.Context, req ProbeRequest) ProbeResult {
	network := "tcp"
	if req.UDP {
		network = "udp"
	}
	res := ProbeResult{Upstream: req.Upstream, Target: req.Target, Network: network}
	fail := func(stage string, err error) ProbeResult {
		res.Stage, res.Error = stage, err.Error()
		return res
	}
	if _, _, err := net.SplitHostPort(req.Target); err != nil {
		return fail("lookup", fmt.Errorf("target %q: want host:port", req.Target))
	}
	if len(req.Payload) > probeMaxPayload {
		return fail("lookup", fmt.Errorf("payload is %d bytes; at most %d", len(req.Payload), probeMaxPayload))
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = probeDefaultTimeout
	}
	timeout = min(timeout, probeMaxTimeout)

	p, ok := e.lookupProvider(UpstreamID(req.Upstream))
	if !ok {
		return fail("lookup", errors.New("no such upstream"))
	}
	res.Kind, res.Via = string(p.Kind()), string(providerVia(p))
	if !p.Ready() {
		return fail("lookup", errors.New("upstream is not ready"))
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	conn, err := p.Dial(ctx, network, req.Target)
	res.ConnectMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Path = e.probePath(ctx, p, req.Target, nil)
		return fail("dial", err)
	}
	defer conn.Close()
	if a := conn.RemoteAddr(); a != nil {
		res.RemoteAddr = a.String()
	}
	if a := conn.LocalAddr(); a != nil {
		res.LocalAddr = a.String()
	}
	res.Path = e.probePath(ctx, p, req.Target, conn.RemoteAddr())

	if !req.UDP {
		res.OK = true
		return res
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = []byte{0}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	n, err := conn.Write(payload)
	res.SentBytes = n
	if err != nil {
		return fail("send", err)
	}
	if !req.WaitReply {
		res.OK = true
		return res
	}
	sent := time.Now()
	buf := make([]byte, probeMaxReply)
	n, err = conn.Read(buf)
	res.ReplyMs = time.Since(sent).Milliseconds()
	if err != nil {
		return fail("reply", err)
	}
	res.ReplyBytes = n
	res.ReplyHex = hex.EncodeToString(buf[:n])
	res.OK = true
	return res
}

// probePath asks the upstream how it reaches the target: for a tailnet or
// exit node, the path to the peer holding the target IP (or the exit node);
// for others, their usual peerPath.
func (e *Engine) probePath(ctx context.Context, p Provider, target string, remote net.Addr) string {
	switch p.Kind() {
	case UpstreamKindTailnet, UpstreamKindExitNode:
		ip := ""
		if host, _, err := net.SplitHostPort(target); err == nil {
			if a, err := netip.ParseAddr(host); err == nil {
				ip = a.String()
			}
		}
		if ip == "" && remote != nil {
			if ap, err := netip.ParseAddrPort(remote.String()); err == nil {
				ip = ap.Addr().String()
			}
		}
		if ip != "" && IsRealTailscaleAddr(netip.MustParseAddr(ip)) {
			if path := p.PeerPathInfo(ctx, ip); path != "" && path != "unknown" {
				return path
			}
		}
		return e.peerPathFor(p.ID(), p.Kind())
	case UpstreamKindDirect:
		return "direct-bypass"
	}
	return p.PeerPathInfo(ctx, "")
}
