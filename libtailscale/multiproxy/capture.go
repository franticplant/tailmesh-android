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
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
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
	// captureListeners captures traffic through one or more SOCKS5
	// listeners (see socks5_listener.go), selected by listener ID rather
	// than app UID - a listener-originated connection has no owning
	// Android app to attribute. See observeListenerConn's doc comment for
	// how this differs from captureAll/captureApps under the hood.
	captureListeners
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

	mu          sync.RWMutex
	appUIDs     map[int32]bool
	appNames    map[int32]string // UID -> human-readable app name/label, for per-packet comments
	listenerIDs map[string]bool  // selected SOCKS5 listener IDs, captureListeners mode only
	file        *pcapFile

	flowsMu sync.RWMutex
	flows   map[flowKey]int32 // -> AppUID
}

func newPacketCapture() *packetCapture {
	return &packetCapture{
		appUIDs:     make(map[int32]bool),
		appNames:    make(map[int32]string),
		listenerIDs: make(map[string]bool),
		flows:       make(map[flowKey]int32),
	}
}

// start begins a new capture session, replacing (and discarding) any
// previous one. mode must be captureAll or captureApps; appUIDsCSV is
// consulted only for captureApps and may be empty (matches nothing, i.e. a
// no-op capture - the caller's UI should prevent this, but it's not this
// layer's job to second-guess an empty selection). appNamesLines maps UID
// to a human-readable app name/label, one "uid:name" pair per line
// (newline-separated rather than comma-separated, since app names may
// themselves contain commas) - used to label every captured packet's
// per-packet comment regardless of mode, so "All traffic" captures are just
// as attributable as "Selected apps" ones once opened in a pcapng-aware
// tool. A UID with no entry falls back to "uid:N" in the comment.
func (c *packetCapture) start(mode captureMode, appUIDsCSV, listenerIDsCSV, appNamesLines, path string, maxBytes int64) error {
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

	listenerIDs := make(map[string]bool)
	for _, tok := range strings.Split(listenerIDsCSV, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		listenerIDs[tok] = true
	}

	names := make(map[int32]string)
	for _, line := range strings.Split(appNamesLines, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if uid, err := strconv.ParseInt(strings.TrimSpace(k), 10, 32); err == nil {
			names[int32(uid)] = strings.TrimSpace(v)
		}
	}

	c.mu.Lock()
	old := c.file
	c.file = f
	c.appUIDs = uids
	c.appNames = names
	c.listenerIDs = listenerIDs
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
// active session wants it and, if so, append it with a per-packet comment
// naming the owning app. Cheap no-op when capture is off (a single atomic
// load). The 5-tuple parse now runs in both modes - captureAll needs it too
// for attribution comments, not just captureApps for filtering - a
// deliberate cost accepted for the per-packet naming this exists to
// provide; capture is already an opt-in debug feature, not a
// steady-state-always-on one.
func (c *packetCapture) observe(data []byte) {
	mode := loadCaptureMode(&c.mode)
	if mode == captureOff {
		return
	}

	proto, src, dst, parsed := parseFiveTuple(data)
	var uid int32
	var attributed bool
	if parsed {
		uid, attributed = c.uidForFlow(proto, src, dst)
		if !attributed {
			// Packets can arrive slightly before registerFlow runs (SYN
			// racing the forwarder goroutine) or slightly after
			// unregisterFlow (final ACK/FIN after the pump loop returns) -
			// both sides of that race are answered the same way as an
			// unattributed flow anywhere else in this engine: excluded
			// from a UID-scoped view rather than guessed at. Also tries
			// the reverse direction, since a reply's src/dst are swapped
			// relative to how the flow was registered.
			uid, attributed = c.uidForFlow(proto, dst, src)
		}
	}

	c.mu.RLock()
	if mode == captureApps && (!attributed || !c.appUIDs[uid]) {
		c.mu.RUnlock()
		return
	}
	f := c.file
	comment := ""
	if attributed {
		if name, ok := c.appNames[uid]; ok && name != "" {
			comment = name
		} else {
			comment = "uid:" + strconv.Itoa(int(uid))
		}
	}
	c.mu.RUnlock()
	if f == nil {
		return
	}
	f.write(data, time.Now(), comment)
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

// syntheticTCPStream tracks per-direction TCP sequence/ack state for one
// SOCKS5-listener connection's synthesized capture, and the connection's two
// real endpoint addresses. See observeListenerConn for why this exists.
type syntheticTCPStream struct {
	clientAddr   netip.AddrPort
	upstreamAddr netip.AddrPort
	clientSeq    atomic.Uint32 // bytes sent client -> upstream so far
	upstreamSeq  atomic.Uint32 // bytes sent upstream -> client so far
	ipID         atomic.Uint32
}

// newSyntheticTCPStream starts a synthesized capture stream for one SOCKS5
// listener connection. clientAddr and upstreamAddr are the real observed
// endpoints (the accepted client conn's RemoteAddr, and the dialed upstream
// conn's own address pair) - only the IP/TCP framing around them is
// synthesized, not the addresses or payload bytes.
func newSyntheticTCPStream(clientAddr, upstreamAddr netip.AddrPort) *syntheticTCPStream {
	return &syntheticTCPStream{clientAddr: clientAddr, upstreamAddr: upstreamAddr}
}

// observeListenerConn feeds one direction's copied bytes from a SOCKS5
// listener connection into the active capture session, if it is in
// captureListeners mode and this listener is selected.
//
// Unlike observe() (the TUN dataplane hot path used by captureAll/
// captureApps), a SOCKS5 listener's traffic never crosses this engine's own
// VPN TUN/captureLinkEndpoint at all: each listener dials its configured
// upstream directly - a tailnet's own tsnet.Server netstack, or the
// protected dialer for @direct/WireGuard - which is a separate network
// stack from the one captureLinkEndpoint wraps. There is no real wire
// packet available to tap for this traffic.
//
// So each call here synthesizes one IPv4/TCP segment carrying the copied
// bytes, addressed with the real observed endpoints (the SOCKS5 client's
// address and the upstream dial's own address) and a monotonically
// increasing per-direction sequence number, so the result is still a
// normal, Wireshark-openable pcapng capture with an accurate byte-for-byte
// payload - it is a synthesized reconstruction of the byte stream, not a
// passive tap of packets that existed on some wire. See
// validation_and_gaps.md for the explicit call-out. IPv6 endpoints are
// skipped (not supported yet) rather than mis-encoded.
func (c *packetCapture) observeListenerConn(listenerID string, stream *syntheticTCPStream, payload []byte, clientToUpstream bool) {
	if loadCaptureMode(&c.mode) != captureListeners || len(payload) == 0 {
		return
	}
	if !stream.clientAddr.Addr().Is4() || !stream.upstreamAddr.Addr().Is4() {
		return
	}

	c.mu.RLock()
	selected := c.listenerIDs[listenerID]
	f := c.file
	c.mu.RUnlock()
	if !selected || f == nil {
		return
	}

	pkt := buildSyntheticTCPSegment(stream, payload, clientToUpstream)
	if pkt == nil {
		return
	}
	f.write(pkt, time.Now(), "listener:"+listenerID)
}

// buildSyntheticTCPSegment builds one IPv4/TCP segment (valid header
// checksums included) carrying payload in the given direction of stream,
// advancing that direction's sequence number by len(payload). See
// observeListenerConn's doc comment for why this is synthesized rather than
// captured from a real wire.
func buildSyntheticTCPSegment(stream *syntheticTCPStream, payload []byte, clientToUpstream bool) []byte {
	var srcAddr, dstAddr netip.AddrPort
	var seq, ack *atomic.Uint32
	if clientToUpstream {
		srcAddr, dstAddr = stream.clientAddr, stream.upstreamAddr
		seq, ack = &stream.clientSeq, &stream.upstreamSeq
	} else {
		srcAddr, dstAddr = stream.upstreamAddr, stream.clientAddr
		seq, ack = &stream.upstreamSeq, &stream.clientSeq
	}

	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize + len(payload)
	buf := make([]byte, totalLen)
	srcTCPIP := tcpip.AddrFrom4(srcAddr.Addr().As4())
	dstTCPIP := tcpip.AddrFrom4(dstAddr.Addr().As4())

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		ID:          uint16(stream.ipID.Add(1)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcTCPIP,
		DstAddr:     dstTCPIP,
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^checksum.Checksum(ip[:header.IPv4MinimumSize], 0))

	seqNum := seq.Add(uint32(len(payload))) - uint32(len(payload))
	tcpHdr := header.TCP(buf[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcAddr.Port(),
		DstPort:    dstAddr.Port(),
		SeqNum:     seqNum,
		AckNum:     ack.Load(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 65535,
	})
	copy(buf[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)

	tcpHdr.SetChecksum(0)
	pseudo := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcTCPIP, dstTCPIP, uint16(header.TCPMinimumSize+len(payload)))
	xsum := checksum.Checksum(buf[header.IPv4MinimumSize:], pseudo)
	tcpHdr.SetChecksum(^xsum)

	return buf
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
			v := pkt.ToView()
			c.cap.observe(v.AsSlice())
			v.Release()
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
		v := pkt.ToView()
		c.cap.observe(v.AsSlice())
		v.Release()
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
// path, bounded to maxBytes (0 uses a sane default). appNamesLines maps
// Android UID to a human-readable app name/label, one "uid:name" pair per
// line (not comma-separated - app names may contain commas), used to label
// every packet's pcapng comment with its owning app; a UID with no entry
// here falls back to "uid:N" in the comment. Any previous capture is
// stopped first.
func (e *Engine) StartPacketCaptureAll(path string, maxBytes int64, appNamesLines string) error {
	return e.capture.start(captureAll, "", "", appNamesLines, path, maxBytes)
}

// StartPacketCaptureApps begins capturing only packets attributed to one of
// appUIDsCSV (comma-separated Android UIDs, matching the CSV convention
// used elsewhere in this API - see onAddressCrossover's
// candidateTailnetIDsCSV on the Kotlin side). A flow whose UID can't be
// resolved (see FlowInfo.AppUID's UnknownAppUID) is never captured in this
// mode, the same way it's excluded from any other UID-scoped view.
// appNamesLines is the same "uid:name" per-line mapping StartPacketCaptureAll
// takes, used for per-packet comments.
func (e *Engine) StartPacketCaptureApps(appUIDsCSV, path string, maxBytes int64, appNamesLines string) error {
	return e.capture.start(captureApps, appUIDsCSV, "", appNamesLines, path, maxBytes)
}

// StartPacketCaptureSOCKS5Listeners begins capturing only traffic through
// one of listenerIDsCSV (comma-separated SOCKS5ListenerConfig.IDs, the same
// CSV convention StartPacketCaptureApps uses for UIDs). See
// observeListenerConn for why this capture is synthesized from each
// listener connection's copied bytes rather than tapped from the TUN the
// way captureAll/captureApps are, and why it currently only supports IPv4
// listener/upstream endpoints.
func (e *Engine) StartPacketCaptureSOCKS5Listeners(listenerIDsCSV, path string, maxBytes int64) error {
	return e.capture.start(captureListeners, "", listenerIDsCSV, "", path, maxBytes)
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
