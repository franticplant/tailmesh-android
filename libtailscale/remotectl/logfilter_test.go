// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLineLevelAndComponent(t *testing.T) {
	cases := []struct {
		l          LogLine
		level, cmp string
	}{
		{LogLine{Source: "app", Level: "W", Text: "MultiProxySession: Upstream x became unreachable"}, "W", "MultiProxySession"},
		{LogLine{Source: "go", Text: "[flow-64] TCP closed"}, "I", "flow"},
		{LogLine{Source: "go", Text: "[flow-66] TCP upstream dial regular-2e2c 100.122.40.91:8443 failed after 3 attempts"}, "E", "flow"},
		{LogLine{Source: "go", Text: "wireguard/upstream-424f: peer(D+12…iYB8) - Sending keepalive packet"}, "I", "wireguard"},
		{LogLine{Source: "go", Text: "[v1] magicsock: disco: node [abc] now using 1.2.3.4:41641"}, "I", "magicsock"},
		{LogLine{Source: "go", Text: "control: map response long-poll timed out!"}, "I", "control"},
		{LogLine{Source: "go", Text: "something without a prefix"}, "I", "go"},
	}
	for _, c := range cases {
		if got := lineLevel(c.l); got != c.level {
			t.Errorf("level(%q) = %q, want %q", c.l.Text, got, c.level)
		}
		if got := lineComponent(c.l); got != c.cmp {
			t.Errorf("component(%q) = %q, want %q", c.l.Text, got, c.cmp)
		}
	}
}

func TestParseLogFilter(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	f, err := parseLogFilter(url.Values{"since": {"42"}}, now)
	if err != nil || f.after != 42 || !f.since.IsZero() {
		t.Errorf("seq: %+v %v", f, err)
	}
	f, err = parseLogFilter(url.Values{"since": {"10m"}, "level": {"warn"}, "component": {"Flow, magicsock"}}, now)
	if err != nil || !f.since.Equal(now.Add(-10*time.Minute)) || f.maxLevel != 1 || len(f.components) != 2 || f.components[0] != "flow" {
		t.Errorf("duration: %+v %v", f, err)
	}
	f, err = parseLogFilter(url.Values{"since": {"2026-10-24T11:00:00Z"}}, now)
	if err != nil || !f.since.Equal(now.Add(-time.Hour)) {
		t.Errorf("time: %+v %v", f, err)
	}
	for _, bad := range []url.Values{{"since": {"yesterday"}}, {"level": {"loud"}}} {
		if _, err := parseLogFilter(bad, now); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
}

func TestLogFiltersClearAndMute(t *testing.T) {
	_, _, _, base := start(t, Config{Password: "correct horse", AllowControl: true})
	tok := login(t, base, "correct horse")
	t.Cleanup(func() { SetMutedComponents(nil) })

	ClearLogs()
	AddLogLevel("app", "D", "Tagged: debug line")
	AddLogLevel("app", "E", "Tagged: bad thing")
	AddLog("go", "[flow-1] TCP upstream dial x failed after 3 attempts")
	AddLog("go", "wireguard/u1: peer(abc) - Sending keepalive packet")

	get := func(q string) []LogLine {
		t.Helper()
		req, _ := http.NewRequest("GET", base+"/v1/logs?"+q, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", q, resp.StatusCode)
		}
		var out []LogLine
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var l LogLine
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
				t.Fatal(err)
			}
			out = append(out, l)
		}
		return out
	}
	texts := func(ls []LogLine) (s []string) {
		for _, l := range ls {
			s = append(s, l.Text)
		}
		return
	}

	if got := get("level=error"); len(got) != 2 {
		t.Errorf("level=error: %q", texts(got))
	}
	if got := get("component=wireguard"); len(got) != 1 || got[0].Component != "wireguard" {
		t.Errorf("component=wireguard: %+v", got)
	}
	if got := get("component=tagged&level=debug"); len(got) != 2 {
		t.Errorf("component=tagged: %q", texts(got))
	}
	if got := get("since=1m"); len(got) != 4 {
		t.Errorf("since=1m: %q", texts(got))
	}
	if code, _ := do(t, "GET", base+"/v1/logs?level=loud", tok, nil); code != http.StatusBadRequest {
		t.Errorf("bad level: %d", code)
	}

	SetMutedComponents([]string{"wire"})
	AddLog("go", "wireguard/u1: peer(abc) - Sending keepalive packet")
	AddLog("go", "magicsock: still here")
	if got := get("component=wireguard,magicsock"); len(got) != 2 {
		t.Errorf("muted wireguard: %q", texts(got))
	}

	if n := ClearLogs(); n != 5 {
		t.Errorf("cleared %d, want 5", n)
	}
	if got := get(""); len(got) != 0 {
		t.Errorf("after clear: %q", texts(got))
	}
}
