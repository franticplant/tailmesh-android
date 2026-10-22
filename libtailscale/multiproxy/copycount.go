// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"errors"
	"io"
	"sync"
)

var copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}

// copyCounting is io.Copy that reports each write to add as it happens,
// rather than the total once the stream ends. Byte counters are read live
// (diagnostics, remote control); counted at the end, a long download showed
// nothing until it finished, and a connection that never closes never counted
// at all.
func copyCounting(dst io.Writer, src io.Reader, add func(int64)) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	buf := *bp
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			if nw < 0 || nw > nr {
				nw = 0
				if werr == nil {
					werr = errors.New("invalid write result")
				}
			}
			if nw > 0 {
				total += int64(nw)
				add(int64(nw))
			}
			if werr != nil {
				return total, werr
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}
