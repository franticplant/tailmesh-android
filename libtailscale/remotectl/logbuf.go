// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Log capture for /v1/logs.
//
// The process's log output is teed through TeeLogs. Lines are only buffered
// while a server is running, so the cost when the feature is off is one atomic
// load per write - unless CaptureLogsFromStart was called, which buffers from
// then on, so a client can see what happened before remote control started.

const logRingSize = 5000

// LogLine is one captured log line.
type LogLine struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Source string    `json:"source"`
	Text   string    `json:"text"`
}

type logRing struct {
	on     atomic.Bool
	always atomic.Bool // set by CaptureLogsFromStart; servers stopping leave it on

	mu      sync.Mutex
	lines   []LogLine
	nextSeq uint64
	wake    chan struct{}
}

var logs = &logRing{nextSeq: 1, wake: make(chan struct{})}

func (r *logRing) enable() { r.on.Store(true) }

func (r *logRing) disable() {
	if r.always.Load() {
		return
	}
	r.on.Store(false)
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}

func (r *logRing) add(source, text string) {
	if !r.on.Load() {
		return
	}
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return
	}
	r.mu.Lock()
	if source == "go" && r.echoesAppLocked(text) {
		r.mu.Unlock()
		return
	}
	r.lines = append(r.lines, LogLine{Seq: r.nextSeq, Time: time.Now(), Source: source, Text: text})
	r.nextSeq++
	if len(r.lines) > logRingSize {
		r.lines = slices.Delete(r.lines, 0, len(r.lines)-logRingSize)
	}
	close(r.wake)
	r.wake = make(chan struct{})
	r.mu.Unlock()
}

// appEchoWindow is how far back a "go" line is compared with "app" lines.
const appEchoWindow = 64

// echoesAppLocked reports whether a "go" line is a recent "app" line coming
// back: the app's logging also goes to Go's logger (Libtailscale.sendLog),
// which writes it again, with its own prefix, through TeeLogs. Without this
// every app line was in /v1/logs twice.
func (r *logRing) echoesAppLocked(text string) bool {
	for i := len(r.lines) - 1; i >= 0 && i >= len(r.lines)-appEchoWindow; i-- {
		if l := r.lines[i]; l.Source == "app" && strings.HasSuffix(text, l.Text) {
			return true
		}
	}
	return false
}

// since returns the buffered lines with Seq > after, the sequence number to
// pass next time, and a channel closed when another line arrives.
func (r *logRing) since(after uint64) ([]LogLine, uint64, <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, _ := slices.BinarySearchFunc(r.lines, after+1, func(l LogLine, seq uint64) int {
		switch {
		case l.Seq < seq:
			return -1
		case l.Seq > seq:
			return 1
		}
		return 0
	})
	out := slices.Clone(r.lines[i:])
	next := after
	if len(out) > 0 {
		next = out[len(out)-1].Seq
	}
	return out, next, r.wake
}

// TeeLogs returns a writer that writes to w and, while a server is running,
// also captures each write as a log line from source "go".
func TeeLogs(w io.Writer) io.Writer { return teeWriter{w} }

type teeWriter struct{ w io.Writer }

func (t teeWriter) Write(p []byte) (int, error) {
	if logs.on.Load() {
		for _, line := range strings.Split(string(p), "\n") {
			logs.add("go", line)
		}
	}
	return t.w.Write(p)
}

// AddLog captures a log line from another source, such as the app's own
// Kotlin logging.
func AddLog(source, text string) { logs.add(source, text) }

// CaptureLogsFromStart buffers log lines from now on, whether or not a server
// is running, so start-up (and anything before remote control was turned on)
// is in /v1/logs. Development builds call it at process start.
func CaptureLogsFromStart() {
	logs.always.Store(true)
	logs.enable()
}

func sortedStrings(s []string) []string {
	slices.Sort(s)
	return s
}
