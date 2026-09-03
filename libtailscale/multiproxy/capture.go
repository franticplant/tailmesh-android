// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// captureMode selects what packetCapture writes to the active pcap file.
// Filtering happens per-packet against flowUIDs (see below), so switching
// modes takes effect on the next packet with no need to restart a flow.
type captureMode int32

const (
	captureOff captureMode = iota
	captureAll
	captureApps
)

// defaultCaptureMaxBytes bounds a single capture file. 32MB is generous for
// a "catch the bug happening right now" session (the use case here, not
// long-haul traffic auditing) while staying well within what the Android UI
// can hold in memory to size/share afterward.
const defaultCaptureMaxBytes = 32 << 20

// flowKey identifies one flow the same way flowFromEndpointID's FlowInfo
// does (protocol + both endpoints as seen at the TUN, i.e. app-facing
// addressing, before any upstream dial) - the exact address space packets
// crossing the TUN link endpoint are already in, so no translation is
// needed between the two.
type flowKey struct {
	proto string
	src   netip.AddrPort
	dst   netip.AddrPort
}

// packetCapture holds all state for the optional PCAP feature: the current
// mode, which app UIDs are of interest in captureApps mode, a live registry
// mapping in-flight flows to their owning UID (populated by
// handleTCPConnection/handleUDPConnection, the same place flow attribution
// already happens for policy/stats purposes), and the bounded pcap file
// itself when a capture is running.
//
// A packetCapture is safe for concurrent use; every method may be called
// from the hot dataplane path (captureLinkEndpoint) concurrently with
// flow-registry updates and UI-driven mode changes.
type packetCapture struct {
	mode int32 // captureMode, accessed via sync/atomic

	mu      sync.RWMutex
	appUIDs map[int32]bool
	file    *pcapFile

	flowsMu sync.RWMutex
	flows   map[flowKey]int32 // -> AppUID
}

func newPacketCapture() *packetCapture {
	return &packetCapture{
		appUIDs: make(map[int32]bool),
		flows:   make(map[flowKey]int32),
	}
}

// start begins a new capture session, replacing (and discarding) any
// previous one. mode must be captureAll or captureApps; appUIDsCSV is
// consulted only for captureApps and may be empty (matches nothing, i.e. a
// no-op capture - the caller's UI should prevent this, but it's not this
// layer's job to second-guess an empty selection).
func (c *packetCapture) start(mode captureMode, appUIDsCSV, path string, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = defaultCaptureMaxBytes
	}
	f, err := openPcapFile(path, maxBytes)
	if err != nil {
		return err
	}

	uids := make(map[int32]bool)
	for _, tok := range strings.Split(appUIDsCSV, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if v, err := strconv.ParseInt(tok, 10, 32); err == nil {
			uids[int32(v)] = true
		}
	}

	c.mu.Lock()
	old := c.file
	c.file = f
	c.appUIDs = uids
	c.mu.Unlock()

	storeCaptureMode(&c.mode, mode)
	if old != nil {
		old.close()
	}
	return nil
}

// stop ends the active capture session, if any, closing its file so it's
// safe to read/share immediately.
func (c *packetCapture) stop() {
	storeCaptureMode(&c.mode, captureOff)
	c.mu.Lock()
	f := c.file
	c.file = nil
	c.mu.Unlock()
	if f != nil {
		f.close()
	}
}

// stats reports the active (or most recently stopped) session's size, in
// case the UI is showing them after stop() already closed the file.
func (c *packetCapture) stats() (bytesWritten, packetCount int64, capacityReached bool) {
	c.mu.RLock()
	f := c.file
	c.mu.RUnlock()
	if f == nil {
		return 0, 0, false
	}
	return f.stats()
}

func loadCaptureMode(mode *int32) captureMode {
	return captureMode(atomic.LoadInt32(mode))
}

func storeCaptureMode(mode *int32, v captureMode) {
	atomic.StoreInt32(mode, int32(v))
}

// registerFlow records the owning UID for a flow that's about to start
// dialing out, so packets on it can be attributed once they reach the
// capture point. Called once per flow from handleTCPConnection/
// handleUDPConnection, mirroring where stats/policy attribution already
// happens - deliberately not gated on capture being enabled, since the
// registry is cheap (one map entry per live flow, already bounded by
// however many concurrent flows the engine allows) and gating it would
// mean a capture started mid-flow could never attribute that flow's
// packets correctly.
func (c *packetCapture) registerFlow(proto string, src, dst netip.AddrPort, uid int32) {
	c.flowsMu.Lock()
	c.flows[flowKey{proto, src, dst}] = uid
	c.flowsMu.Unlock()
}

func (c *packetCapture) unregisterFlow(proto string, src, dst netip.AddrPort) {
	c.flowsMu.Lock()
	delete(c.flows, flowKey{proto, src, dst})
	c.flowsMu.Unlock()
}

func (c *packetCapture) uidForFlow(proto string, src, dst netip.AddrPort) (int32, bool) {
	c.flowsMu.RLock()
	uid, ok := c.flows[flowKey{proto, src, dst}]
	c.flowsMu.RUnlock()
	return uid, ok
}

// observe is the hot-path entry point: given one raw IP packet as it
// crosses the TUN link endpoint (either direction), decide whether the
// active session wants it and, if so, append it. Cheap no-op when capture
// is off (a single atomic load), and the 5-tuple parse only happens in
// captureApps mode - captureAll never needs to know which flow a packet
// belongs to.
func (c *packetCapture) observe(data []byte) {
	mode := loadCaptureMode(&c.mode)
	if mode == captureOff {
		return
	}
	if mode == captureApps {
		proto, src, dst, ok := parseFiveTuple(data)
		if !ok {
			return
		}
		uid, ok := c.uidForFlow(proto, src, dst)
		if !ok {
			// Packets can arrive slightly before registerFlow runs (SYN
			// racing the forwarder goroutine) or slightly after
			// unregisterFlow (final ACK/FIN after the pump loop returns) -
			// both sides of that race are answered the same way as an
			// unattributed flow anywhere else in this engine: excluded
			// from a UID-scoped view rather than guessed at. Also tries
			// the reverse direction, since a reply's src/dst are swapped
			// relative to how the flow was registered.
			uid, ok = c.uidForFlow(proto, dst, src)
		}
		if !ok || !c.appUIDs[uid] {
			return
		}
	}

	c.mu.RLock()
	f := c.file
	c.mu.RUnlock()
	if f == nil {
		return
	}
	f.write(data, time.Now())
}

// parseFiveTuple extracts (protocol, src, dst) from a raw IPv4 or IPv6
// packet, understanding just enough of each header to find the TCP/UDP
// ports - sufficient for flow attribution, not a general packet parser.
// Any packet that isn't well-formed IPv4/IPv6 carrying TCP or UDP (already
// the only two transport protocols this engine's gVisor stack registers,
// see newVPNStack) is reported as unparseable rather than guessed at.
func parseFiveTuple(data []byte) (proto string, src, dst netip.AddrPort, ok bool) {
	if len(data) < 1 {
		return "", netip.AddrPort{}, netip.AddrPort{}, false
	}
	version := data[0] >> 4
	var transportProto tcpip.TransportProtocolNumber
	var payload []byte
	var srcAddr, dstAddr netip.Addr

	switch version {
	case 4:
		if len(data) < header.IPv4MinimumSize {
			return "", netip.AddrPort{}, netip.AddrPort{}, false
		}
		ip := header.IPv4(data)
		if !ip.IsValid(len(data)) {
			return "", netip.AddrPort{}, netip.AddrPort{}, false
		}
		transportProto = ip.TransportProtocol()
		payload = ip.Payload()
		srcAddr, _ = netip.AddrFromSlice(ip.SourceAddressSlice())
		dstAddr, _ = netip.AddrFromSlice(ip.DestinationAddressSlice())
	case 6:
		if len(data) < header.IPv6MinimumSize {
			return "", netip.AddrPort{}, netip.AddrPort{}, false
		}
		ip := header.IPv6(data)
		transportProto = ip.TransportProtocol()
		payload = ip.Payload()
		srcAddr, _ = netip.AddrFromSlice(ip.SourceAddressSlice())
		dstAddr, _ = netip.AddrFromSlice(ip.DestinationAddressSlice())
	default:
		return "", netip.AddrPort{}, netip.AddrPort{}, false
	}

	switch transportProto {
	case header.TCPProtocolNumber:
		if len(payload) < header.TCPMinimumSize {
			return "", netip.AddrPort{}, netip.AddrPort{}, false
		}
		t := header.TCP(payload)
		return "tcp",
			netip.AddrPortFrom(srcAddr, t.SourcePort()),
			netip.AddrPortFrom(dstAddr, t.DestinationPort()),
			true
	case header.UDPProtocolNumber:
		if len(payload) < header.UDPMinimumSize {
			return "", netip.AddrPort{}, netip.AddrPort{}, false
		}
		u := header.UDP(payload)
		return "udp",
			netip.AddrPortFrom(srcAddr, u.SourcePort()),
			netip.AddrPortFrom(dstAddr, u.DestinationPort()),
			true
	default:
		return "", netip.AddrPort{}, netip.AddrPort{}, false
	}
}

// captureLinkEndpoint decorates a stack.LinkEndpoint exactly the way
// countingLinkEndpoint does (see tun_interceptor.go, which this is
// deliberately kept parallel to), feeding every packet crossing the TUN in
// either direction to a packetCapture instead of a counter.
type captureLinkEndpoint struct {
	stack.LinkEndpoint
	cap *packetCapture
}

func wrapCaptureEndpoint(real stack.LinkEndpoint, cap *packetCapture) stack.LinkEndpoint {
	return &captureLinkEndpoint{LinkEndpoint: real, cap: cap}
}

func (c *captureLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if loadCaptureMode(&c.cap.mode) != captureOff {
		for _, pkt := range pkts.AsSlice() {
			c.cap.observe(pkt.ToView().AsSlice())
		}
	}
	return c.LinkEndpoint.WritePackets(pkts)
}

type captureDispatcher struct {
	stack.NetworkDispatcher
	cap *packetCapture
}

func (c *captureDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if loadCaptureMode(&c.cap.mode) != captureOff {
		c.cap.observe(pkt.ToView().AsSlice())
	}
	c.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (c *captureLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		c.LinkEndpoint.Attach(nil)
		return
	}
	c.LinkEndpoint.Attach(&captureDispatcher{NetworkDispatcher: dispatcher, cap: c.cap})
}

// --- Engine-facing API, exposed to Android via gomobile. ---

// StartPacketCaptureAll begins capturing every packet crossing the TUN to
// path, bounded to maxBytes (0 uses a sane default). Any previous capture
// is stopped first.
func (e *Engine) StartPacketCaptureAll(path string, maxBytes int64) error {
	return e.capture.start(captureAll, "", path, maxBytes)
}

// StartPacketCaptureApps begins capturing only packets attributed to one of
// appUIDsCSV (comma-separated Android UIDs, matching the CSV convention
// used elsewhere in this API - see onAddressCrossover's
// candidateTailnetIDsCSV on the Kotlin side). A flow whose UID can't be
// resolved (see FlowInfo.AppUID's UnknownAppUID) is never captured in this
// mode, the same way it's excluded from any other UID-scoped view.
func (e *Engine) StartPacketCaptureApps(appUIDsCSV, path string, maxBytes int64) error {
	return e.capture.start(captureApps, appUIDsCSV, path, maxBytes)
}

// StopPacketCapture ends the active capture session, if any, and closes its
// file. Safe to call when no capture is running.
func (e *Engine) StopPacketCapture() {
	e.capture.stop()
}

// PacketCaptureBytesWritten reports the active (or just-stopped) session's
// file size, so the UI can show it without re-stat'ing the file.
func (e *Engine) PacketCaptureBytesWritten() int64 {
	b, _, _ := e.capture.stats()
	return b
}

// PacketCapturePacketCount reports the active (or just-stopped) session's
// packet count.
func (e *Engine) PacketCapturePacketCount() int64 {
	_, n, _ := e.capture.stats()
	return n
}

// PacketCaptureCapacityReached reports whether the active session hit its
// maxBytes limit and has been silently dropping packets since - the UI
// should surface this rather than let the user assume a suspiciously quiet
// capture means the bug didn't recur.
func (e *Engine) PacketCaptureCapacityReached() bool {
	_, _, full := e.capture.stats()
	return full
}
