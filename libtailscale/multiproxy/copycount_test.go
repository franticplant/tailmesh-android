// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"bytes"
	"io"
	"testing"
)

// TestCopyCountingReportsWhileCopying checks counts arrive per write, before
// the stream ends, and add up to what was copied.
func TestCopyCountingReportsWhileCopying(t *testing.T) {
	pr, pw := io.Pipe()
	var dst bytes.Buffer
	var counted int64
	seen := make(chan int64, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := copyCounting(&dst, pr, func(n int64) { counted += n; seen <- counted })
		if err != nil || n != 7 {
			t.Errorf("copyCounting = %d, %v; want 7, nil", n, err)
		}
	}()
	pw.Write([]byte("abc"))
	if got := <-seen; got != 3 {
		t.Fatalf("counted %d after first write, want 3 (before the stream ended)", got)
	}
	pw.Write([]byte("defg"))
	<-seen
	pw.Close()
	<-done
	if counted != 7 || dst.String() != "abcdefg" {
		t.Fatalf("counted %d, copied %q", counted, dst.String())
	}
}
