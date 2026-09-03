// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

func buildIPv4UDPPacket(t *testing.T, srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, payload []byte) []byte {
	t.Helper()
	src := tcpip.AddrFromSlice(netip.MustParseAddr(srcAddr).AsSlice())
	dst := tcpip.AddrFromSlice(netip.MustParseAddr(dstAddr).AsSlice())

	udpLen := header.UDPMinimumSize + len(payload)
	buf := make([]byte, header.IPv4MinimumSize+udpLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(u.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(0)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	return buf
}

func buildIPv4TCPPacket(t *testing.T, srcAddr string, srcPort uint16, dstAddr string, dstPort uint16, payload []byte) []byte {
	t.Helper()
	src := tcpip.AddrFromSlice(netip.MustParseAddr(srcAddr).AsSlice())
	dst := tcpip.AddrFromSlice(netip.MustParseAddr(dstAddr).AsSlice())

	tcpLen := header.TCPMinimumSize + len(payload)
	buf := make([]byte, header.IPv4MinimumSize+tcpLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tc := header.TCP(buf[header.IPv4MinimumSize:])
	tc.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	copy(tc.Payload(), payload)

	return buf
}

func TestParseFiveTupleUDPv4(t *testing.T) {
	raw := buildIPv4UDPPacket(t, "10.0.0.1", 5000, "10.0.0.2", 53, []byte("hi"))
	proto, src, dst, ok := parseFiveTuple(raw)
	if !ok {
		t.Fatalf("parseFiveTuple: not ok")
	}
	if proto != "udp" {
		t.Fatalf("proto = %q, want udp", proto)
	}
	if src.String() != "10.0.0.1:5000" || dst.String() != "10.0.0.2:53" {
		t.Fatalf("src=%v dst=%v, want 10.0.0.1:5000 / 10.0.0.2:53", src, dst)
	}
}

func TestParseFiveTupleTCPv4(t *testing.T) {
	raw := buildIPv4TCPPacket(t, "10.0.0.5", 44000, "93.184.216.34", 443, nil)
	proto, src, dst, ok := parseFiveTuple(raw)
	if !ok {
		t.Fatalf("parseFiveTuple: not ok")
	}
	if proto != "tcp" {
		t.Fatalf("proto = %q, want tcp", proto)
	}
	if src.String() != "10.0.0.5:44000" || dst.String() != "93.184.216.34:443" {
		t.Fatalf("src=%v dst=%v", src, dst)
	}
}

func TestParseFiveTupleRejectsGarbage(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0x00},
		{0x45, 0x00, 0x00}, // truncated IPv4 header
	} {
		if _, _, _, ok := parseFiveTuple(raw); ok {
			t.Fatalf("parseFiveTuple(%v) = ok, want rejected", raw)
		}
	}
}

func TestPcapFileWritesValidHeaderAndRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	f, err := openPcapFile(path, 1<<20)
	if err != nil {
		t.Fatalf("openPcapFile: %v", err)
	}
	pkt1 := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("one"))
	pkt2 := buildIPv4UDPPacket(t, "10.0.0.2", 53, "10.0.0.1", 1000, []byte("two"))
	at := time.Unix(1700000000, 123000)
	f.write(pkt1, at)
	f.write(pkt2, at)

	bytesWritten, packets, full := f.stats()
	if full {
		t.Fatalf("full = true, want false")
	}
	if packets != 2 {
		t.Fatalf("packets = %d, want 2", packets)
	}
	wantBytes := int64(24 + 16 + len(pkt1) + 16 + len(pkt2))
	if bytesWritten != wantBytes {
		t.Fatalf("bytesWritten = %d, want %d", bytesWritten, wantBytes)
	}
	if err := f.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	if len(raw) != int(wantBytes) {
		t.Fatalf("file size = %d, want %d", len(raw), wantBytes)
	}
	if magic := binary.LittleEndian.Uint32(raw[0:4]); magic != 0xa1b2c3d4 {
		t.Fatalf("magic = %#x, want 0xa1b2c3d4", magic)
	}
	if linktype := binary.LittleEndian.Uint32(raw[20:24]); linktype != pcapLinkTypeRaw {
		t.Fatalf("linktype = %d, want %d", linktype, pcapLinkTypeRaw)
	}
	rec1 := raw[24:]
	inclLen := binary.LittleEndian.Uint32(rec1[8:12])
	origLen := binary.LittleEndian.Uint32(rec1[12:16])
	if int(inclLen) != len(pkt1) || int(origLen) != len(pkt1) {
		t.Fatalf("record1 incl=%d orig=%d, want %d", inclLen, origLen, len(pkt1))
	}
	gotPkt1 := rec1[16 : 16+inclLen]
	if string(gotPkt1) != string(pkt1) {
		t.Fatalf("record1 payload mismatch")
	}
}

func TestPcapFileStopsAtCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	// Global header (24) + exactly one small record fits; a second must not.
	pkt := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x"))
	maxBytes := int64(24 + 16 + len(pkt))
	f, err := openPcapFile(path, maxBytes)
	if err != nil {
		t.Fatalf("openPcapFile: %v", err)
	}
	defer f.close()

	f.write(pkt, time.Now())
	if _, _, full := f.stats(); full {
		t.Fatalf("full = true after first packet, want false")
	}
	f.write(pkt, time.Now())
	bytesWritten, packets, full := f.stats()
	if !full {
		t.Fatalf("full = false after exceeding capacity, want true")
	}
	if packets != 1 {
		t.Fatalf("packets = %d after dropped packet, want 1", packets)
	}
	if bytesWritten != maxBytes {
		t.Fatalf("bytesWritten = %d, want %d (capped)", bytesWritten, maxBytes)
	}

	// Once full, further writes are also dropped, not just the one that
	// tipped it over.
	f.write(pkt, time.Now())
	bytesWritten2, packets2, _ := f.stats()
	if bytesWritten2 != bytesWritten || packets2 != packets {
		t.Fatalf("write after full changed stats: %d/%d -> %d/%d", bytesWritten, packets, bytesWritten2, packets2)
	}
}

func TestPacketCaptureAllModeIgnoresFlowRegistry(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := c.start(captureAll, "", path, 1<<20); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.stop()

	pkt := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x"))
	c.observe(pkt) // No flow registered for this 5-tuple at all.

	_, packets, _ := c.stats()
	if packets != 1 {
		t.Fatalf("packets = %d, want 1 (captureAll should not consult the flow registry)", packets)
	}
}

func TestPacketCaptureAppsModeFiltersByUID(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := c.start(captureApps, "1001, 1002", path, 1<<20); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.stop()

	src := netip.MustParseAddrPort("10.0.0.1:5000")
	dst := netip.MustParseAddrPort("10.0.0.2:53")
	c.registerFlow("udp", src, dst, 1001)

	matching := buildIPv4UDPPacket(t, "10.0.0.1", 5000, "10.0.0.2", 53, []byte("a"))
	c.observe(matching)

	// Reverse-direction packet (a reply) must also be attributed via the
	// same registered flow.
	reply := buildIPv4UDPPacket(t, "10.0.0.2", 53, "10.0.0.1", 5000, []byte("b"))
	c.observe(reply)

	// A flow for an app not in the selection: registered but must not be
	// captured.
	otherSrc := netip.MustParseAddrPort("10.0.0.9:6000")
	otherDst := netip.MustParseAddrPort("10.0.0.2:53")
	c.registerFlow("udp", otherSrc, otherDst, 9999)
	notSelected := buildIPv4UDPPacket(t, "10.0.0.9", 6000, "10.0.0.2", 53, []byte("c"))
	c.observe(notSelected)

	// An entirely unregistered flow must not be captured either.
	unregistered := buildIPv4UDPPacket(t, "192.168.1.1", 7000, "10.0.0.2", 53, []byte("d"))
	c.observe(unregistered)

	_, packets, _ := c.stats()
	if packets != 2 {
		t.Fatalf("packets = %d, want 2 (only the two packets on the selected app's flow)", packets)
	}
}

func TestPacketCaptureOffDropsEverything(t *testing.T) {
	c := newPacketCapture()
	pkt := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x"))
	c.observe(pkt)
	b, packets, _ := c.stats()
	if b != 0 || packets != 0 {
		t.Fatalf("observe with capture off wrote something: bytes=%d packets=%d", b, packets)
	}
}

func TestPacketCaptureStopClosesFile(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := c.start(captureAll, "", path, 1<<20); err != nil {
		t.Fatalf("start: %v", err)
	}
	c.observe(buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x")))
	c.stop()

	// stop() must close the file so the UI can read/share it immediately,
	// and a subsequent observe() must be a no-op rather than panicking or
	// reopening it.
	c.observe(buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("y")))
	if _, _, full := c.stats(); full {
		t.Fatalf("stats reports full after stop, want the pre-stop snapshot")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture file after stop: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("capture file is empty after stop")
	}
}

func TestPacketCaptureRestartDiscardsPreviousSession(t *testing.T) {
	c := newPacketCapture()
	path1 := filepath.Join(t.TempDir(), "one.pcap")
	path2 := filepath.Join(t.TempDir(), "two.pcap")

	if err := c.start(captureAll, "", path1, 1<<20); err != nil {
		t.Fatalf("start 1: %v", err)
	}
	c.observe(buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x")))

	if err := c.start(captureAll, "", path2, 1<<20); err != nil {
		t.Fatalf("start 2: %v", err)
	}
	defer c.stop()

	_, packets, _ := c.stats()
	if packets != 0 {
		t.Fatalf("packets = %d after restart, want 0 (new session)", packets)
	}
}

// TestCaptureLinkEndpointSeesRealTraffic wires wrapCaptureEndpoint into a
// live gVisor stack exactly as StartVPN does for the production fdbased
// endpoint, and confirms a real DNS query/response round-trip through
// ServeDNSUDP is actually captured in both directions - the standalone
// packetCapture tests above cover the filtering logic in isolation, but not
// whether the endpoint wrapper is wired into the packet path correctly.
func TestCaptureLinkEndpointSeesRealTraffic(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	ep := channel.New(256, 1500, "")
	captured := wrapCaptureEndpoint(ep, e.capture)

	e.vpnMu.Lock()
	err := e.bindVPNStackLocked(captured)
	e.vpnMu.Unlock()
	if err != nil {
		t.Fatalf("bindVPNStackLocked: %v", err)
	}
	t.Cleanup(e.StopVPN)

	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := e.capture.start(captureAll, "", path, 1<<20); err != nil {
		t.Fatalf("start capture: %v", err)
	}
	defer e.capture.stop()

	injectUDPv6DNSQuery(t, ep, "box.", dns.TypeA, 40002)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readUDPv6DNSResponse(t, ctx, ep)

	bytesWritten, packets, full := e.capture.stats()
	if full {
		t.Fatalf("capture reported full unexpectedly")
	}
	// One inbound (the query, via DeliverNetworkPacket) and one outbound
	// (the response, via WritePackets) - both directions must be captured.
	if packets != 2 {
		t.Fatalf("packets = %d, want 2 (query + response)", packets)
	}
	if bytesWritten <= 24 {
		t.Fatalf("bytesWritten = %d, want more than just the global header", bytesWritten)
	}
}

func TestFlowRegistryRegisterUnregister(t *testing.T) {
	c := newPacketCapture()
	src := netip.MustParseAddrPort("10.0.0.1:1234")
	dst := netip.MustParseAddrPort("10.0.0.2:443")

	if _, ok := c.uidForFlow("tcp", src, dst); ok {
		t.Fatalf("uidForFlow found an entry before registerFlow")
	}
	c.registerFlow("tcp", src, dst, 42)
	uid, ok := c.uidForFlow("tcp", src, dst)
	if !ok || uid != 42 {
		t.Fatalf("uidForFlow = (%d, %v), want (42, true)", uid, ok)
	}
	c.unregisterFlow("tcp", src, dst)
	if _, ok := c.uidForFlow("tcp", src, dst); ok {
		t.Fatalf("uidForFlow found an entry after unregisterFlow")
	}
}
