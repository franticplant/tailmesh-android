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

// pcapngPacket is one parsed Enhanced Packet Block, as read back by
// readPcapngFile - just enough to assert on in tests, not a general pcapng
// reader.
type pcapngPacket struct {
	data    []byte
	comment string
}

// readPcapngFile parses a file written by pcapFile/openPcapFile back into
// its Section Header, Interface Description, and packet blocks, asserting
// on the framing invariants (block type, matching leading/trailing length,
// 4-byte alignment) along the way so a malformed file fails the test
// immediately rather than via a confusing slice-bounds panic.
func readPcapngFile(t *testing.T, raw []byte) (linkType uint32, snapLen uint32, packets []pcapngPacket) {
	t.Helper()
	off := 0
	readBlock := func() (blockType uint32, body []byte) {
		if off+8 > len(raw) {
			t.Fatalf("truncated block header at offset %d", off)
		}
		blockType = binary.LittleEndian.Uint32(raw[off : off+4])
		total := binary.LittleEndian.Uint32(raw[off+4 : off+8])
		if off+int(total) > len(raw) {
			t.Fatalf("block claims length %d past end of file at offset %d", total, off)
		}
		trailing := binary.LittleEndian.Uint32(raw[off+int(total)-4 : off+int(total)])
		if trailing != total {
			t.Fatalf("block trailing length %d != leading length %d at offset %d", trailing, total, off)
		}
		body = raw[off+8 : off+int(total)-4]
		off += int(total)
		return blockType, body
	}

	bt, body := readBlock()
	if bt != pcapngBlockSectionHeader {
		t.Fatalf("first block type = %#x, want Section Header Block", bt)
	}
	if magic := binary.LittleEndian.Uint32(body[0:4]); magic != pcapngByteOrderMagic {
		t.Fatalf("byte-order magic = %#x, want %#x", magic, pcapngByteOrderMagic)
	}

	bt, body = readBlock()
	if bt != pcapngBlockInterfaceDesc {
		t.Fatalf("second block type = %#x, want Interface Description Block", bt)
	}
	linkType = uint32(binary.LittleEndian.Uint16(body[0:2]))
	snapLen = binary.LittleEndian.Uint32(body[4:8])

	for off < len(raw) {
		bt, body := readBlock()
		if bt != pcapngBlockEnhancedPkt {
			t.Fatalf("unexpected block type %#x among packets", bt)
		}
		capLen := binary.LittleEndian.Uint32(body[12:16])
		data := body[20 : 20+capLen]
		rest := body[20+pad4(int(capLen)):]

		var comment string
		for len(rest) >= 4 {
			code := binary.LittleEndian.Uint16(rest[0:2])
			length := binary.LittleEndian.Uint16(rest[2:4])
			if code == pcapngOptEndOfOpt {
				break
			}
			val := rest[4 : 4+int(length)]
			if code == pcapngOptComment {
				comment = string(val)
			}
			rest = rest[4+pad4(int(length)):]
		}
		packets = append(packets, pcapngPacket{data: append([]byte(nil), data...), comment: comment})
	}
	return linkType, snapLen, packets
}

func TestPcapFileWritesValidHeaderAndRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	f, err := openPcapFile(path, 1<<20)
	if err != nil {
		t.Fatalf("openPcapFile: %v", err)
	}
	pkt1 := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("one"))
	pkt2 := buildIPv4UDPPacket(t, "10.0.0.2", 53, "10.0.0.1", 1000, []byte("two"))
	at := time.Unix(1700000000, 123000)
	f.write(pkt1, at, "com.example.one")
	f.write(pkt2, at, "")

	bytesWritten, packets, full := f.stats()
	if full {
		t.Fatalf("full = true, want false")
	}
	if packets != 2 {
		t.Fatalf("packets = %d, want 2", packets)
	}
	if err := f.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	if int64(len(raw)) != bytesWritten {
		t.Fatalf("file size = %d, want %d (bytesWritten)", len(raw), bytesWritten)
	}

	linkType, snapLen, pkts := readPcapngFile(t, raw)
	if linkType != pcapLinkTypeRaw {
		t.Fatalf("linktype = %d, want %d", linkType, pcapLinkTypeRaw)
	}
	if snapLen != pcapSnapLen {
		t.Fatalf("snaplen = %d, want %d", snapLen, pcapSnapLen)
	}
	if len(pkts) != 2 {
		t.Fatalf("parsed %d packets, want 2", len(pkts))
	}
	if string(pkts[0].data) != string(pkt1) {
		t.Fatalf("packet 1 payload mismatch")
	}
	if pkts[0].comment != "com.example.one" {
		t.Fatalf("packet 1 comment = %q, want %q", pkts[0].comment, "com.example.one")
	}
	if string(pkts[1].data) != string(pkt2) {
		t.Fatalf("packet 2 payload mismatch")
	}
	if pkts[1].comment != "" {
		t.Fatalf("packet 2 comment = %q, want empty (none written)", pkts[1].comment)
	}
}

func TestPcapFileStopsAtCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	pkt := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x"))
	f, err := openPcapFile(path, 1<<20)
	if err != nil {
		t.Fatalf("openPcapFile: %v", err)
	}
	// Cap exactly at the header blocks plus one record, computed the same
	// way pcapFile.write does, so a second write must be rejected.
	base, _, _ := f.stats()
	f.maxBytes = base + pcapngRecordSize(len(pkt), "")
	maxBytes := f.maxBytes
	defer f.close()

	f.write(pkt, time.Now(), "")
	if _, _, full := f.stats(); full {
		t.Fatalf("full = true after first packet, want false")
	}
	f.write(pkt, time.Now(), "")
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
	f.write(pkt, time.Now(), "")
	bytesWritten2, packets2, _ := f.stats()
	if bytesWritten2 != bytesWritten || packets2 != packets {
		t.Fatalf("write after full changed stats: %d/%d -> %d/%d", bytesWritten, packets, bytesWritten2, packets2)
	}
}

func TestPacketCaptureAllModeIgnoresFlowRegistry(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := c.start(captureAll, "", "", path, 1<<20); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.stop()

	pkt := buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x"))
	c.observe(pkt) // No flow registered for this 5-tuple at all.

	_, packets, _ := c.stats()
	if packets != 1 {
		t.Fatalf("packets = %d, want 1 (captureAll should not consult appUIDs)", packets)
	}
}

func TestPacketCaptureAppsModeFiltersByUID(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := c.start(captureApps, "1001, 1002", "", path, 1<<20); err != nil {
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

// TestPacketCaptureAttributesEveryPacketWithAppName confirms the pcapng
// migration's actual point: even in "All traffic" mode (no UID filtering),
// every packet on a registered flow gets a per-packet comment naming its
// owning app when a name is supplied via appNamesLines, falls back to
// "uid:N" when the UID has no name entry, and is left uncommented when the
// flow can't be attributed at all.
func TestPacketCaptureAttributesEveryPacketWithAppName(t *testing.T) {
	c := newPacketCapture()
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := c.start(captureAll, "", "1001:com.example.named\n1002:  com.example.spaced  ", path, 1<<20); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.stop()

	namedSrc := netip.MustParseAddrPort("10.0.0.1:5000")
	namedDst := netip.MustParseAddrPort("10.0.0.2:53")
	c.registerFlow("udp", namedSrc, namedDst, 1001)
	c.observe(buildIPv4UDPPacket(t, "10.0.0.1", 5000, "10.0.0.2", 53, []byte("named")))

	unnamedSrc := netip.MustParseAddrPort("10.0.0.3:5001")
	unnamedDst := netip.MustParseAddrPort("10.0.0.2:53")
	c.registerFlow("udp", unnamedSrc, unnamedDst, 4242)
	c.observe(buildIPv4UDPPacket(t, "10.0.0.3", 5001, "10.0.0.2", 53, []byte("unnamed")))

	c.observe(buildIPv4UDPPacket(t, "192.168.1.1", 7000, "10.0.0.2", 53, []byte("unattributed")))

	c.stop()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	_, _, pkts := readPcapngFile(t, raw)
	if len(pkts) != 3 {
		t.Fatalf("parsed %d packets, want 3", len(pkts))
	}
	if pkts[0].comment != "com.example.named" {
		t.Fatalf("packet 1 comment = %q, want %q", pkts[0].comment, "com.example.named")
	}
	if pkts[1].comment != "uid:4242" {
		t.Fatalf("packet 2 comment = %q, want %q (no name entry, falls back to uid)", pkts[1].comment, "uid:4242")
	}
	if pkts[2].comment != "" {
		t.Fatalf("packet 3 comment = %q, want empty (unattributed flow)", pkts[2].comment)
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
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := c.start(captureAll, "", "", path, 1<<20); err != nil {
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
	path1 := filepath.Join(t.TempDir(), "one.pcapng")
	path2 := filepath.Join(t.TempDir(), "two.pcapng")

	if err := c.start(captureAll, "", "", path1, 1<<20); err != nil {
		t.Fatalf("start 1: %v", err)
	}
	c.observe(buildIPv4UDPPacket(t, "10.0.0.1", 1000, "10.0.0.2", 53, []byte("x")))

	if err := c.start(captureAll, "", "", path2, 1<<20); err != nil {
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

	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := e.capture.start(captureAll, "", "", path, 1<<20); err != nil {
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
	if bytesWritten <= 32 {
		t.Fatalf("bytesWritten = %d, want more than just the pcapng header blocks", bytesWritten)
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
