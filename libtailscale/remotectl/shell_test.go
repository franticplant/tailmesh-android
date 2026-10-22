// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type shellFakeEvents struct {
	*fakeEvents
	shellReqs chan ShellRequest
	mu        sync.Mutex
	entries   []ShellEntry
}

func (e *shellFakeEvents) OnShellRequest(r ShellRequest) { e.shellReqs <- r }
func (e *shellFakeEvents) OnShellEntry(x ShellEntry) {
	e.mu.Lock()
	e.entries = append(e.entries, x)
	e.mu.Unlock()
}
func (e *shellFakeEvents) OnShellChanged() {}

func startShell(t *testing.T) (*Server, *shellFakeEvents, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		Addr:                  "127.0.0.1:0",
		Password:              "correct horse",
		PasswordGrantsControl: true,
		AllowControl:          true,
		AuthBurst:             100,
		AccessLogPath:         filepath.Join(dir, "access.log"),
		Shell:                 true,
		ShellLogPath:          filepath.Join(dir, "shell.log"),
		ShellDir:              filepath.Join(dir, "home"),
		ShellPath:             "/bin/sh",
		Methods:               testMethods,
	}
	os.MkdirAll(cfg.ShellDir, 0o700)
	ev := &shellFakeEvents{fakeEvents: newFakeEvents(), shellReqs: make(chan ShellRequest, 4)}
	s, err := Start(cfg, &fakeHandler{}, ev)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s, ev, "http://" + s.Addr().String(), cfg.ShellLogPath
}

// openShell requests a shell and approves it the way the phone would.
func openShell(t *testing.T, s *Server, ev *shellFakeEvents, base, tok string) {
	t.Helper()
	code, out := do(t, "POST", base+"/v1/shell/request", tok, map[string]int{"minutes": 5})
	if code != http.StatusAccepted {
		t.Fatalf("shell request: %d %v", code, out)
	}
	req := <-ev.shellReqs
	if err := s.ApproveShell(req.ID); err != nil {
		t.Fatalf("ApproveShell: %v", err)
	}
	code, out = do(t, "GET", base+"/v1/shell/request/"+req.ID, tok, nil)
	if code != http.StatusOK || out["status"] != "approved" {
		t.Fatalf("shell poll: %d %v", code, out)
	}
}

func TestShellNeedsPhoneApproval(t *testing.T) {
	s, ev, base, _ := startShell(t)
	tok := login(t, base, "correct horse")

	// A control session alone cannot run anything.
	code, _ := do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "echo hi"})
	if code != http.StatusForbidden {
		t.Fatalf("exec without a grant = %d, want 403", code)
	}

	// Denied on the phone: still nothing.
	do(t, "POST", base+"/v1/shell/request", tok, nil)
	req := <-ev.shellReqs
	s.DenyShell(req.ID)
	if _, out := do(t, "GET", base+"/v1/shell/request/"+req.ID, tok, nil); out["status"] != "denied" {
		t.Fatalf("poll after deny = %v", out)
	}
	if code, _ := do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "echo hi"}); code != http.StatusForbidden {
		t.Fatalf("exec after deny = %d, want 403", code)
	}

	openShell(t, s, ev, base, tok)
	code, out := do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "echo hi; echo err >&2; exit 3"})
	if code != http.StatusOK {
		t.Fatalf("exec: %d %v", code, out)
	}
	if out["stdout"] != "hi\n" || out["stderr"] != "err\n" || out["exit"].(float64) != 3 {
		t.Fatalf("exec result = %v", out)
	}
}

func TestShellReadOnlySessionCannotAsk(t *testing.T) {
	s, _, base, _ := startShell(t)
	tok := login(t, base, "correct horse")
	s.SetAllowControl(false)
	if code, _ := do(t, "POST", base+"/v1/shell/request", tok, nil); code != http.StatusForbidden {
		t.Fatalf("read-only shell request = %d, want 403", code)
	}
	if code, _ := do(t, "POST", base+"/v1/shell/request", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated shell request = %d, want 401", code)
	}
}

func TestShellEndsWithSessionAndKillsCommand(t *testing.T) {
	s, ev, base, _ := startShell(t)
	tok := login(t, base, "correct horse")
	openShell(t, s, ev, base, tok)

	done := make(chan map[string]any, 1)
	go func() {
		_, out := do(t, "POST", base+"/v1/shell/exec", tok, map[string]any{"cmd": "sleep 30", "timeoutSeconds": 60})
		done <- out
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		g := s.ShellGrants()
		if len(g) == 1 && g[0].Running == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, sess := range s.Sessions() {
		s.RevokeSession(sess.ID)
	}
	select {
	case out := <-done:
		if !strings.Contains(out["note"].(string), "closed") {
			t.Fatalf("killed command note = %v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command not killed when its session was revoked")
	}
	if len(s.ShellGrants()) != 0 {
		t.Fatal("grant outlived its session")
	}
}

func TestShellTimeout(t *testing.T) {
	s, ev, base, _ := startShell(t)
	tok := login(t, base, "correct horse")
	openShell(t, s, ev, base, tok)
	began := time.Now()
	_, out := do(t, "POST", base+"/v1/shell/exec", tok, map[string]any{"cmd": "sleep 30 & sleep 30", "timeoutSeconds": 1})
	if time.Since(began) > 5*time.Second {
		t.Fatalf("timeout took %v", time.Since(began))
	}
	if !strings.Contains(out["note"].(string), "timed out") {
		t.Fatalf("note = %v", out)
	}
}

func TestShellLogIsChainedAndTamperEvident(t *testing.T) {
	s, ev, base, path := startShell(t)
	tok := login(t, base, "correct horse")
	openShell(t, s, ev, base, tok)
	do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "echo one"})
	do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "echo two"})

	if v := s.VerifyShellLog(); !v.OK {
		t.Fatalf("fresh log fails verification: %+v", v)
	}
	entries, _ := ReadShellLog(path, 0)
	var kinds []string
	for _, e := range entries {
		kinds = append(kinds, e.Kind)
	}
	want := "log-opened request grant exec result exec result"
	if got := strings.Join(kinds, " "); got != want {
		t.Fatalf("log kinds = %q, want %q", got, want)
	}
	// The command is logged before it runs.
	if entries[3].Cmd != "echo one" || entries[4].Exit == nil || *entries[4].Exit != 0 {
		t.Fatalf("exec/result entries = %+v %+v", entries[3], entries[4])
	}
	ev.mu.Lock()
	mirrored := len(ev.entries)
	ev.mu.Unlock()
	if mirrored != len(entries)-1 { // log-opened is written before events exist
		t.Fatalf("mirrored %d entries to the app, log has %d", mirrored, len(entries))
	}

	data, _ := os.ReadFile(path)

	// Editing a command is detected.
	os.WriteFile(path, []byte(strings.Replace(string(data), "echo two", "echo TWO", 1)), 0o600)
	if v := s.VerifyShellLog(); v.OK || !strings.Contains(v.Problem, "altered") {
		t.Fatalf("edited log verified: %+v", v)
	}

	// Dropping the last entries keeps a valid chain, but not the head.
	lines := strings.SplitAfter(string(data), "\n")
	os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-3], "")), 0o600)
	if v := s.VerifyShellLog(); v.OK || !strings.Contains(v.Problem, "does not end") {
		t.Fatalf("truncated log verified: %+v", v)
	}
	if v := VerifyShellLogFile(path); !v.OK {
		t.Fatalf("truncated log should still chain on its own: %+v", v)
	}

	// Restored, it verifies again.
	os.WriteFile(path, data, 0o600)
	if v := s.VerifyShellLog(); !v.OK {
		t.Fatalf("restored log fails: %+v", v)
	}
}

func TestShellLogReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shell.log")
	l, err := openShellLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.append(ShellEntry{Kind: "exec", Cmd: "true"})
	l.close()
	l, err = openShellLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.close()
	if v := VerifyShellLogFile(path); !v.OK || v.Entries != 3 {
		t.Fatalf("reopened log: %+v", v)
	}
	entries, _ := ReadShellLog(path, 0)
	if !strings.Contains(entries[2].Note, "2 earlier entries verified") {
		t.Fatalf("reopen note = %q", entries[2].Note)
	}

	// A broken file is still opened, and the break is recorded.
	data, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(data), `"true"`, `"false"`, 1)), 0o600)
	l, err = openShellLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.close()
	entries, _ = ReadShellLog(path, 0)
	if !strings.Contains(entries[len(entries)-1].Note, "FAILED") {
		t.Fatalf("break not recorded: %q", entries[len(entries)-1].Note)
	}
}

func TestShellDisabledWithoutConfig(t *testing.T) {
	_, _, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true})
	tok := login(t, base, "correct horse")
	if code, _ := do(t, "POST", base+"/v1/shell/request", tok, nil); code != http.StatusNotFound {
		t.Fatalf("shell request without Shell = %d, want 404", code)
	}
	if code, _ := do(t, "POST", base+"/v1/shell/exec", tok, map[string]string{"cmd": "true"}); code != http.StatusNotFound {
		t.Fatalf("exec without Shell = %d, want 404", code)
	}
}
