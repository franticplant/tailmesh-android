// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"time"
)

// pcapLinkTypeRaw is LINKTYPE_RAW (101): the file holds bare IP packets, no
// link-layer header - a direct match for fdbased's EthernetHeader: false
// (see StartVPN in tun_interceptor.go), so no synthetic Ethernet framing
// needs to be invented just to satisfy the file format.
const pcapLinkTypeRaw = 101

const pcapSnapLen = 1 << 16 // Larger than any MTU this engine accepts (StartVPN caps at 65535).

// pcapng block types (https://pcapng.com/).
const (
	pcapngBlockSectionHeader = 0x0A0D0D0A
	pcapngBlockInterfaceDesc = 0x00000001
	pcapngBlockEnhancedPkt   = 0x00000006
)

const pcapngByteOrderMagic = 0x1A2B3C4D

// pcapngOptComment is the standard per-block "opt_comment" option code,
// valid on an Enhanced Packet Block - this is the mechanism used to attach
// a human-readable app name to each individual packet, since the classic
// libpcap format this replaced has no per-packet metadata at all.
const pcapngOptComment = 1
const pcapngOptEndOfOpt = 0

// writePcapngSectionHeader and writePcapngInterfaceDesc are written once, at
// the start of every capture file, establishing the file as pcapng (not
// classic libpcap) and describing the single synthetic "interface" (the
// TUN) every packet in the file arrived on.
func writePcapngSectionHeader(w io.Writer) error {
	// Section Header Block: type, total_len, byte-order magic, version
	// 1.0, section_length = -1 (unknown/unbounded), no options, total_len.
	body := make([]byte, 0, 16)
	body = binary.LittleEndian.AppendUint32(body, pcapngByteOrderMagic)
	body = binary.LittleEndian.AppendUint16(body, 1) // major
	body = binary.LittleEndian.AppendUint16(body, 0) // minor
	body = binary.LittleEndian.AppendUint64(body, 0xFFFFFFFFFFFFFFFF)
	return writePcapngBlock(w, pcapngBlockSectionHeader, body)
}

func writePcapngInterfaceDesc(w io.Writer) error {
	body := make([]byte, 0, 8)
	body = binary.LittleEndian.AppendUint16(body, pcapLinkTypeRaw)
	body = binary.LittleEndian.AppendUint16(body, 0) // reserved
	body = binary.LittleEndian.AppendUint32(body, pcapSnapLen)
	return writePcapngBlock(w, pcapngBlockInterfaceDesc, body)
}

// writePcapngBlock wraps body with the generic pcapng block framing: type,
// total_length, body, total_length again (the trailing repeat lets a
// consumer walk the file backward too - part of the format, not something
// this writer invented).
func writePcapngBlock(w io.Writer, blockType uint32, body []byte) error {
	total := 12 + len(body) // type(4) + len(4) + body + len(4)
	buf := make([]byte, 0, total)
	buf = binary.LittleEndian.AppendUint32(buf, blockType)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(total))
	buf = append(buf, body...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(total))
	_, err := w.Write(buf)
	return err
}

// pad4 rounds n up to the next multiple of 4, the block-alignment pcapng
// requires for both packet data and option values.
func pad4(n int) int {
	return (n + 3) &^ 3
}

// writePcapngPacket appends one Enhanced Packet Block: the packet itself,
// truncated to pcapSnapLen (orig_len still reports the true length, same
// convention the old classic-pcap writer used), plus an optional
// opt_comment carrying the owning app's name when known - this is the
// actual per-packet attribution the pcapng migration exists for. comment
// may be empty, in which case no comment option is written at all.
func writePcapngPacket(w io.Writer, data []byte, at time.Time, comment string) error {
	incl := data
	if len(incl) > pcapSnapLen {
		incl = incl[:pcapSnapLen]
	}
	tsUnitsPerSec := uint64(1_000_000) // microsecond resolution, matching the classic format's precision
	ts := uint64(at.Unix())*tsUnitsPerSec + uint64(at.Nanosecond()/1000)

	dataPad := pad4(len(incl)) - len(incl)

	body := make([]byte, 0, 20+len(incl)+dataPad+8+len(comment)+4)
	body = binary.LittleEndian.AppendUint32(body, 0) // interface_id (the one and only interface, IDB index 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(ts>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(ts))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(incl)))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(data)))
	body = append(body, incl...)
	body = append(body, make([]byte, dataPad)...)

	if comment != "" {
		optPad := pad4(len(comment)) - len(comment)
		body = binary.LittleEndian.AppendUint16(body, pcapngOptComment)
		body = binary.LittleEndian.AppendUint16(body, uint16(len(comment)))
		body = append(body, comment...)
		body = append(body, make([]byte, optPad)...)
		body = binary.LittleEndian.AppendUint16(body, pcapngOptEndOfOpt)
		body = binary.LittleEndian.AppendUint16(body, 0)
	}

	return writePcapngBlock(w, pcapngBlockEnhancedPkt, body)
}

// pcapngRecordSize returns the exact byte count writePcapngPacket will add
// for the given payload/comment, so pcapFile.write can enforce maxBytes
// without actually formatting the block first.
func pcapngRecordSize(dataLen int, comment string) int64 {
	if dataLen > pcapSnapLen {
		dataLen = pcapSnapLen
	}
	size := 12 + 20 + pad4(dataLen) // block header/trailer + EPB fixed fields + padded data
	if comment != "" {
		size += 4 + pad4(len(comment)) + 4 // opt_comment header+value(padded) + opt_endofopt
	}
	return int64(size)
}

// pcapFile is a size-bounded pcapng writer backing one capture session. It
// stops accepting packets once maxBytes is reached rather than truncating
// or rotating - a short-but-valid pcapng file is useful, a rotated/truncated
// one risks landing mid-block and being unreadable by every pcap tool.
type pcapFile struct {
	mu       sync.Mutex
	f        *os.File
	written  int64
	maxBytes int64
	packets  int64
	full     bool
}

// openPcapFile creates (truncating any existing) the file at path and
// writes the Section Header + Interface Description blocks every pcapng
// file needs before any packet data. maxBytes bounds total file size
// including those blocks; callers should pass a sane minimum (at least a
// few KB) or every write will immediately report capacityReached.
func openPcapFile(path string, maxBytes int64) (*pcapFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := writePcapngSectionHeader(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := writePcapngInterfaceDesc(f); err != nil {
		f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &pcapFile{f: f, written: info.Size(), maxBytes: maxBytes}, nil
}

// write appends one packet (with an optional per-packet app-name comment)
// if it fits within maxBytes, silently dropping it (and marking full)
// otherwise. Errors from the underlying file are swallowed after marking
// full - a capture feature must never be allowed to take down the
// dataplane, so callers ignore this return value in the hot path and only
// surface it through PCAPCaptureStats.
func (p *pcapFile) write(data []byte, at time.Time, comment string) {
	if len(data) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil || p.full {
		return
	}
	recSize := pcapngRecordSize(len(data), comment)
	if p.written+recSize > p.maxBytes {
		p.full = true
		return
	}
	if err := writePcapngPacket(p.f, data, at, comment); err != nil {
		p.full = true
		return
	}
	p.written += recSize
	p.packets++
}

func (p *pcapFile) stats() (bytesWritten, packetCount int64, full bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.written, p.packets, p.full
}

func (p *pcapFile) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil {
		return nil
	}
	err := p.f.Close()
	p.f = nil
	return err
}
