// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Log levels, most severe first. App lines carry the level they were logged
// at (TSLog); Go's log lines have none, so a "go" line that mentions an
// error or a failure counts as E and the rest as I.
const levels = "EWIDV"

var goErrorWords = regexp.MustCompile(`(?i)\b(error|errors|failed|failure|panic|fatal)\b`)

// lineLevel is a line's level letter.
func lineLevel(l LogLine) string {
	if l.Level != "" {
		return l.Level
	}
	if goErrorWords.MatchString(l.Text) {
		return "E"
	}
	return "I"
}

// lineComponent is the part of the app or engine a line comes from: the
// Kotlin log tag for app lines; for Go lines the logger prefix ("magicsock",
// "wireguard", "control", ...), "flow" for per-connection lines, else "go".
func lineComponent(l LogLine) string {
	t := l.Text
	if l.Source != "go" {
		if tag, _, ok := strings.Cut(t, ": "); ok && tag != "" && !strings.Contains(tag, " ") {
			return tag
		}
		return l.Source
	}
	for strings.HasPrefix(t, "[v") { // "[v1] magicsock: ..."
		_, rest, ok := strings.Cut(t, "] ")
		if !ok {
			break
		}
		t = rest
	}
	if strings.HasPrefix(t, "[flow-") {
		return "flow"
	}
	if strings.HasPrefix(t, "wireguard/") {
		return "wireguard"
	}
	if word, _, ok := strings.Cut(t, ":"); ok && word != "" && len(word) <= 32 && !strings.ContainsAny(word, " []()") {
		return strings.ToLower(word)
	}
	return "go"
}

// logFilter is what GET /v1/logs selects on, beyond the sequence number.
type logFilter struct {
	after      uint64    // only lines with Seq > after
	since      time.Time // only lines at or after this time
	maxLevel   int       // index into levels: lines at most this verbose
	components []string  // lowercase; a line's component must start with one
	grep       string
}

func parseLevel(s string) (int, error) {
	switch strings.ToLower(s) {
	case "", "v", "verbose", "all":
		return 4, nil
	case "e", "error":
		return 0, nil
	case "w", "warn", "warning":
		return 1, nil
	case "i", "info":
		return 2, nil
	case "d", "debug":
		return 3, nil
	}
	return 0, fmt.Errorf("unknown level %q: use error, warn, info, debug or verbose", s)
}

// parseLogFilter reads since (a sequence number, a duration such as 10m, or
// an RFC 3339 time), level, component (comma-separated) and grep.
func parseLogFilter(q url.Values, now time.Time) (logFilter, error) {
	var f logFilter
	if s := q.Get("since"); s != "" {
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			f.after = n
		} else if d, err := time.ParseDuration(s); err == nil {
			f.since = now.Add(-d)
		} else if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.since = t
		} else {
			return f, fmt.Errorf("since %q: want a sequence number, a duration (10m) or an RFC 3339 time", s)
		}
	}
	lvl, err := parseLevel(q.Get("level"))
	if err != nil {
		return f, err
	}
	f.maxLevel = lvl
	for c := range strings.SplitSeq(q.Get("component"), ",") {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			f.components = append(f.components, c)
		}
	}
	f.grep = q.Get("grep")
	return f, nil
}

// match reports whether l passes the filter (the sequence number aside).
func (f *logFilter) match(l LogLine) bool {
	if !f.since.IsZero() && l.Time.Before(f.since) {
		return false
	}
	if f.maxLevel < 4 && strings.Index(levels, lineLevel(l)) > f.maxLevel {
		return false
	}
	if len(f.components) > 0 {
		c := strings.ToLower(lineComponent(l))
		if !slices.ContainsFunc(f.components, func(p string) bool { return strings.HasPrefix(c, p) }) {
			return false
		}
	}
	if f.grep != "" && !strings.Contains(l.Text, f.grep) {
		return false
	}
	return true
}

// ClearLogs empties the log ring. Sequence numbers keep counting.
func ClearLogs() int {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	n := len(logs.lines)
	logs.lines = nil
	return n
}

// SetMutedComponents stops lines from these components (see lineComponent;
// prefix match, case-insensitive) from entering the ring from now on. They
// still go to logcat. Empty unmutes everything.
func SetMutedComponents(components []string) []string {
	var m []string
	for _, c := range components {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			m = append(m, c)
		}
	}
	slices.Sort(m)
	m = slices.Compact(m)
	if len(m) == 0 {
		logs.muted.Store(nil)
		return []string{}
	} else {
		logs.muted.Store(&m)
	}
	return m
}

// MutedComponents returns the muted components.
func MutedComponents() []string {
	if m := logs.muted.Load(); m != nil {
		return slices.Clone(*m)
	}
	return []string{}
}

func (r *logRing) mutedLine(l LogLine) bool {
	m := r.muted.Load()
	if m == nil {
		return false
	}
	c := strings.ToLower(lineComponent(l))
	return slices.ContainsFunc(*m, func(p string) bool { return strings.HasPrefix(c, p) })
}
