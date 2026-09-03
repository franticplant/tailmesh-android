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

// pcapGlobalHeader is the 24-byte classic libpcap file header, written once
// at the start of every capture file. Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
func writePcapGlobalHeader(w io.Writer) error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4) // magic (little-endian, microsecond resolution)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)          // version major
	binary.LittleEndian.PutUint16(hdr[6:8], 4)          // version minor
	// hdr[8:12] thiszone = 0, hdr[12:16] sigfigs = 0 (left zero)
	binary.LittleEndian.PutUint32(hdr[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(hdr[20:24], pcapLinkTypeRaw)
	_, err := w.Write(hdr[:])
	return err
}

// writePcapRecord appends one packet record (16-byte header + payload,
// truncated to pcapSnapLen if longer - orig_len still reports the true
// length, matching what a real capture tool does when snaplen is hit).
func writePcapRecord(w io.Writer, data []byte, at time.Time) error {
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:4], uint32(at.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(at.Nanosecond()/1000))
	incl := data
	if len(incl) > pcapSnapLen {
		incl = incl[:pcapSnapLen]
	}
	binary.LittleEndian.PutUint32(rec[8:12], uint32(len(incl)))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(len(data)))
	if _, err := w.Write(rec[:]); err != nil {
		return err
	}
	_, err := w.Write(incl)
	return err
}

// pcapFile is a size-bounded libpcap writer backing one capture session. It
// stops accepting packets once maxBytes is reached rather than truncating
// or rotating - a short-but-valid pcap file is useful, a rotated/truncated
// one risks landing mid-record and being unreadable by every pcap tool.
type pcapFile struct {
	mu       sync.Mutex
	f        *os.File
	written  int64
	maxBytes int64
	packets  int64
	full     bool
}

// openPcapFile creates (truncating any existing) the file at path and
// writes the global header. maxBytes bounds total file size including the
// header; callers should pass a sane minimum (at least a few KB) or every
// write will immediately report capacityReached.
func openPcapFile(path string, maxBytes int64) (*pcapFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := writePcapGlobalHeader(f); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapFile{f: f, written: 24, maxBytes: maxBytes}, nil
}

// write appends one packet if it fits within maxBytes, silently dropping it
// (and marking full) otherwise. Errors from the underlying file are
// swallowed after logging via the caller's discretion - a capture feature
// must never be allowed to take down the dataplane, so callers ignore this
// return value in the hot path and only surface it through PCAPStats.
func (p *pcapFile) write(data []byte, at time.Time) {
	if len(data) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.f == nil || p.full {
		return
	}
	recSize := int64(16 + len(data))
	if len(data) > pcapSnapLen {
		recSize = int64(16 + pcapSnapLen)
	}
	if p.written+recSize > p.maxBytes {
		p.full = true
		return
	}
	if err := writePcapRecord(p.f, data, at); err != nil {
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
