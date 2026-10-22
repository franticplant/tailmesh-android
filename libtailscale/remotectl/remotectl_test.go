// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHandler struct {
	mu    sync.Mutex
	calls []string
}

func (h *fakeHandler) Call(method, args string) (string, error) {
	h.mu.Lock()
	h.calls = append(h.calls, method)
	h.mu.Unlock()
	switch method {
	case "fail":
		return "", errors.New("it failed")
	case "echo":
		return args, nil
	}
	return `{"done":true}`, nil
}

type fakeEvents struct {
	mu       sync.Mutex
	requests chan ApprovalRequest
	access   []AccessEntry
	stopped  chan string
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{requests: make(chan ApprovalRequest, 8), stopped: make(chan string, 1)}
}

func (e *fakeEvents) OnApprovalRequest(r ApprovalRequest) { e.requests <- r }
func (e *fakeEvents) OnAccess(a AccessEntry) {
	e.mu.Lock()
	e.access = append(e.access, a)
	e.mu.Unlock()
}
func (e *fakeEvents) OnSessionsChanged() {}
func (e *fakeEvents) OnStopped(r string) { e.stopped <- r }

func (e *fakeEvents) actions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, a := range e.access {
		out = append(out, a.Action)
	}
	return out
}

var testMethods = []Method{
	{Name: "status.get"},
	{Name: "echo"},
	{Name: "fail", Mutating: true},
	{Name: "upstreams.delete", Mutating: true},
}

func start(t *testing.T, cfg Config) (*Server, *fakeHandler, *fakeEvents, string) {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	if cfg.AccessLogPath == "" {
		cfg.AccessLogPath = filepath.Join(t.TempDir(), "access.log")
	}
	if cfg.Methods == nil {
		cfg.Methods = testMethods
	}
	h := &fakeHandler{}
	ev := newFakeEvents()
	s, err := Start(cfg, h, ev)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(s.Stop)
	return s, h, ev, "http://" + s.Addr().String()
}

func do(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func login(t *testing.T, base, password string) string {
	t.Helper()
	code, out := do(t, "POST", base+"/v1/auth/login", "", map[string]string{"client": "test", "password": password})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, out)
	}
	return out["token"].(string)
}

func TestStartRequiresAnAuthMethod(t *testing.T) {
	_, err := Start(Config{Addr: "127.0.0.1:0", AccessLogPath: filepath.Join(t.TempDir(), "a")}, &fakeHandler{}, nil)
	if err == nil {
		t.Fatal("started with neither approval nor password")
	}
	_, err = Start(Config{Addr: "127.0.0.1:0", Password: "short", AccessLogPath: filepath.Join(t.TempDir(), "a")}, &fakeHandler{}, nil)
	if err == nil {
		t.Fatal("started with a too-short password")
	}
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	_, h, _, base := start(t, Config{Password: "correct horse", AuthBurst: 100})
	for _, path := range []string{"/v1/status", "/v1/methods", "/v1/logs", "/v1/access-log", "/debug/pprof/"} {
		if code, _ := do(t, "GET", base+path, "", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s without token = %d, want 401", path, code)
		}
		if code, _ := do(t, "GET", base+path, "forged-token", nil); code != http.StatusUnauthorized {
			t.Errorf("GET %s with forged token = %d, want 401", path, code)
		}
	}
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", "", map[string]any{}); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated call = %d, want 401", code)
	}
	if len(h.calls) != 0 {
		t.Fatalf("handler ran for unauthenticated requests: %v", h.calls)
	}
}

func TestPasswordLogin(t *testing.T) {
	_, h, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true})

	if code, _ := do(t, "POST", base+"/v1/auth/login", "", map[string]string{"password": "wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d, want 401", code)
	}
	tok := login(t, base, "correct horse")

	code, out := do(t, "POST", base+"/v1/call/echo", tok, map[string]any{"x": 1})
	if code != http.StatusOK || out["result"].(map[string]any)["x"].(float64) != 1 {
		t.Fatalf("echo = %d %v", code, out)
	}
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, map[string]any{"id": "u"}); code != http.StatusOK {
		t.Fatalf("mutating call with control session = %d", code)
	}
	if code, out := do(t, "POST", base+"/v1/call/fail", tok, nil); code != http.StatusUnprocessableEntity || out["error"] != "it failed" {
		t.Fatalf("failing call = %d %v", code, out)
	}
	if code, _ := do(t, "POST", base+"/v1/call/nope", tok, nil); code != http.StatusNotFound {
		t.Fatalf("unknown method = %d", code)
	}

	if code, _ := do(t, "POST", base+"/v1/auth/logout", tok, nil); code != http.StatusOK {
		t.Fatal("logout failed")
	}
	if code, _ := do(t, "GET", base+"/v1/status", tok, nil); code != http.StatusUnauthorized {
		t.Fatal("token still valid after logout")
	}
	if strings.Join(h.calls, ",") != "echo,upstreams.delete,fail" {
		t.Fatalf("handler calls = %v", h.calls)
	}
}

func TestPasswordLoginDisabledWhenNoPassword(t *testing.T) {
	_, _, _, base := start(t, Config{ApprovalEnabled: true})
	if code, _ := do(t, "POST", base+"/v1/auth/login", "", map[string]string{"password": ""}); code != http.StatusForbidden {
		t.Fatalf("login with password disabled = %d, want 403", code)
	}
}

func TestReadOnlySessionCannotMutate(t *testing.T) {
	_, h, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: false, AllowControl: true})
	tok := login(t, base, "correct horse")

	if code, _ := do(t, "POST", base+"/v1/call/echo", tok, nil); code != http.StatusOK {
		t.Fatal("read call refused for read-only session")
	}
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusForbidden {
		t.Fatalf("mutating call from read-only session = %d, want 403", code)
	}
	if code, _ := do(t, "GET", base+"/debug/pprof/", tok, nil); code != http.StatusForbidden {
		t.Fatalf("pprof from read-only session = %d, want 403", code)
	}
	for _, c := range h.calls {
		if c == "upstreams.delete" {
			t.Fatal("read-only session reached a mutating handler")
		}
	}
}

func TestGlobalControlSwitchAppliesToLiveSessions(t *testing.T) {
	s, _, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true})
	tok := login(t, base, "correct horse")
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusOK {
		t.Fatal("control session refused while control enabled")
	}
	s.SetAllowControl(false)
	if code, out := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusForbidden || !strings.Contains(out["error"].(string), "switched off") {
		t.Fatalf("mutating call after control switched off = %d %v", code, out)
	}
	if code, _ := do(t, "POST", base+"/v1/call/echo", tok, nil); code != http.StatusOK {
		t.Fatal("reads stopped working when control was switched off")
	}
	s.SetAllowControl(true)
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusOK {
		t.Fatal("control not restored")
	}
}

func TestDeviceApproval(t *testing.T) {
	s, _, ev, base := start(t, Config{ApprovalEnabled: true, AllowControl: true})

	code, out := do(t, "POST", base+"/v1/auth/request", "", map[string]string{"client": "laptop"})
	if code != http.StatusAccepted {
		t.Fatalf("request = %d %v", code, out)
	}
	id := out["requestId"].(string)
	var req ApprovalRequest
	select {
	case req = <-ev.requests:
	case <-time.After(2 * time.Second):
		t.Fatal("app was not asked to approve")
	}
	if req.ID != id || req.Client != "laptop" || req.Code != out["code"] {
		t.Fatalf("approval request %+v does not match response %v", req, out)
	}
	if len(s.PendingApprovals()) != 1 {
		t.Fatal("request not listed as pending")
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		if err := s.Approve(id, true); err != nil {
			t.Errorf("Approve: %v", err)
		}
	}()
	code, out = do(t, "GET", base+"/v1/auth/request/"+id, "", nil)
	if code != http.StatusOK || out["status"] != "approved" {
		t.Fatalf("poll = %d %v", code, out)
	}
	tok := out["token"].(string)
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusOK {
		t.Fatal("approved control session cannot mutate")
	}

	// The token is handed out exactly once.
	if code, _ := do(t, "GET", base+"/v1/auth/request/"+id, "", nil); code != http.StatusNotFound {
		t.Fatalf("second poll = %d, want 404", code)
	}
	if len(s.Sessions()) != 1 {
		t.Fatalf("sessions = %v", s.Sessions())
	}
	s.RevokeSession(s.Sessions()[0].ID)
	if code, _ := do(t, "GET", base+"/v1/status", tok, nil); code != http.StatusUnauthorized {
		t.Fatal("revoked session still works")
	}
}

func TestDeviceApprovalDeniedAndReadOnly(t *testing.T) {
	s, _, ev, base := start(t, Config{ApprovalEnabled: true, AllowControl: true})

	_, out := do(t, "POST", base+"/v1/auth/request", "", map[string]string{"client": "a"})
	<-ev.requests
	if err := s.Deny(out["requestId"].(string)); err != nil {
		t.Fatal(err)
	}
	if code, out := do(t, "GET", base+"/v1/auth/request/"+out["requestId"].(string), "", nil); code != http.StatusForbidden || out["status"] != "denied" {
		t.Fatalf("poll after deny = %d %v", code, out)
	}

	_, out = do(t, "POST", base+"/v1/auth/request", "", map[string]string{"client": "b"})
	<-ev.requests
	if err := s.Approve(out["requestId"].(string), false); err != nil {
		t.Fatal(err)
	}
	_, polled := do(t, "GET", base+"/v1/auth/request/"+out["requestId"].(string), "", nil)
	tok := polled["token"].(string)
	if code, _ := do(t, "POST", base+"/v1/call/upstreams.delete", tok, nil); code != http.StatusForbidden {
		t.Fatalf("read-only approval could mutate (%d)", code)
	}
}

func TestApprovalDisabled(t *testing.T) {
	_, _, _, base := start(t, Config{Password: "correct horse"})
	if code, _ := do(t, "POST", base+"/v1/auth/request", "", map[string]string{"client": "x"}); code != http.StatusForbidden {
		t.Fatalf("approval request with approval disabled = %d, want 403", code)
	}
}

// The limit is global: attempts from any client draw on one budget, so a
// correct password is refused once the budget is spent.
func TestAuthRateLimitIsGlobal(t *testing.T) {
	_, _, _, base := start(t, Config{Password: "correct horse", AuthAttemptsPerSecond: 0.001, AuthBurst: 3})
	for i := 0; i < 3; i++ {
		if code, _ := do(t, "POST", base+"/v1/auth/login", "", map[string]string{"password": fmt.Sprint("guess", i)}); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i, code)
		}
	}
	if code, _ := do(t, "POST", base+"/v1/auth/login", "", map[string]string{"password": "correct horse"}); code != http.StatusTooManyRequests {
		t.Fatalf("login after budget spent = %d, want 429", code)
	}
	// Forged session tokens draw on the same budget.
	if code, _ := do(t, "GET", base+"/v1/status", "forged", nil); code != http.StatusTooManyRequests {
		t.Fatalf("forged token after budget spent = %d, want 429", code)
	}
}

func TestEveryAccessIsLogged(t *testing.T) {
	s, _, ev, base := start(t, Config{Password: "correct horse", AllowControl: true, PasswordGrantsControl: true})
	do(t, "POST", base+"/v1/auth/login", "", map[string]string{"password": "nope"})
	tok := login(t, base, "correct horse")
	do(t, "GET", base+"/v1/status", tok, nil)
	do(t, "POST", base+"/v1/call/echo", tok, map[string]any{"privateKey": "SECRET-VALUE", "id": "x"})
	do(t, "GET", base+"/v1/status", "forged", nil)

	got := strings.Join(ev.actions(), "|")
	for _, want := range []string{"server.start", "auth.login", "GET /v1/status", "call echo"} {
		if !strings.Contains(got, want) {
			t.Errorf("access log missing %q: %s", want, got)
		}
	}

	entries := s.access.tail(100)
	var sawEcho bool
	for _, e := range entries {
		if e.Action == "call echo" {
			sawEcho = true
			if e.Args != "id,privateKey" {
				t.Errorf("echo args logged as %q, want argument names only", e.Args)
			}
		}
	}
	if !sawEcho {
		t.Fatal("call not persisted to the access log file")
	}
	raw, _ := os.ReadFile(s.cfg.AccessLogPath)
	if bytes.Contains(raw, []byte("SECRET-VALUE")) || bytes.Contains(raw, []byte("correct horse")) {
		t.Fatal("a secret value was written to the access log")
	}

	// The access log is readable through the API, never writable: there is
	// no route that modifies it.
	code, _ := do(t, "GET", base+"/v1/access-log", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("reading access log = %d", code)
	}
	for _, m := range []string{"DELETE", "POST", "PUT"} {
		if code, _ := do(t, m, base+"/v1/access-log", tok, nil); code != http.StatusMethodNotAllowed {
			t.Errorf("%s /v1/access-log = %d, want 405", m, code)
		}
	}
}

func TestAccessLogRotatesAndClears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	a, err := openAccessLog(path)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 1024)
	for i := 0; i < accessLogMaxSize/1024+50; i++ {
		a.append(AccessEntry{Action: big})
	}
	a.append(AccessEntry{Action: "last"})
	a.close()
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("log did not rotate")
	}
	tail := ReadAccessLog(path, 1)
	if len(tail) != 1 || tail[0].Action != "last" {
		t.Fatalf("tail = %v", tail)
	}
	if err := ClearAccessLog(path); err != nil {
		t.Fatal(err)
	}
	if len(ReadAccessLog(path, 10)) != 0 {
		t.Fatal("log not cleared")
	}
}

func TestFileDownloadIsConfinedToRoots(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	inside := filepath.Join(root, "capture.pcapng")
	os.WriteFile(inside, []byte("pcap"), 0o600)
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("nope"), 0o600)
	os.Symlink(secret, filepath.Join(root, "link"))

	_, _, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true, FileRoots: []string{root}})
	tok := login(t, base, "correct horse")

	get := func(p string) (int, string) {
		req, _ := http.NewRequest("GET", base+"/v1/files?path="+p, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get(inside); code != http.StatusOK || body != "pcap" {
		t.Fatalf("download inside root = %d %q", code, body)
	}
	for _, p := range []string{secret, filepath.Join(root, "link"), root + "/../" + filepath.Base(outside) + "/secret", "relative/path", root} {
		if code, _ := get(p); code == http.StatusOK {
			t.Errorf("download of %q allowed", p)
		}
	}
}

func TestExpiryStopsServer(t *testing.T) {
	cfg := Config{
		Addr:          "127.0.0.1:0",
		Password:      "correct horse",
		ExpiresAtUnix: time.Now().Add(1500 * time.Millisecond).Unix(),
		AccessLogPath: filepath.Join(t.TempDir(), "access.log"),
	}
	ev := newFakeEvents()
	s, err := Start(cfg, &fakeHandler{}, ev)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case reason := <-ev.stopped:
		if reason != "expired" {
			t.Fatalf("stopped with %q", reason)
		}
	case <-time.After(5 * time.Second):
		s.Stop()
		t.Fatal("server did not expire")
	}
}

func TestLogsCaptureOnlyWhileRunning(t *testing.T) {
	var sink bytes.Buffer
	w := TeeLogs(&sink)
	fmt.Fprintln(w, "before start")

	_, _, _, base := start(t, Config{Password: "correct horse"})
	tok := login(t, base, "correct horse")
	fmt.Fprintln(w, "while running: needle")
	AddLog("kotlin", "from the app")

	req, _ := http.NewRequest("GET", base+"/v1/logs", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("needle")) || !bytes.Contains(body, []byte("from the app")) {
		t.Fatalf("logs = %s", body)
	}
	if bytes.Contains(body, []byte("before start")) {
		t.Fatal("captured a line written before the server started")
	}
	if !strings.Contains(sink.String(), "before start") || !strings.Contains(sink.String(), "needle") {
		t.Fatal("tee did not pass writes through")
	}
}

func TestAppUpdateUpload(t *testing.T) {
	upload := func(t *testing.T, base, tok string, apk []byte) int {
		t.Helper()
		req, _ := http.NewRequest("POST", base+"/v1/app/update", bytes.NewReader(apk))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	called := func(h *fakeHandler) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, c := range h.calls {
			if c == "app.update" {
				return true
			}
		}
		return false
	}
	apk := []byte("PK\x03\x04 pretend this is an APK")

	t.Run("off without UpdateDir", func(t *testing.T) {
		_, h, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true})
		if code := upload(t, base, login(t, base, "correct horse"), apk); code != http.StatusNotFound {
			t.Fatalf("upload with no UpdateDir = %d, want 404", code)
		}
		if called(h) {
			t.Fatal("app.update reached with updates disabled")
		}
	})

	t.Run("read-only session refused", func(t *testing.T) {
		dir := t.TempDir()
		_, h, _, base := start(t, Config{Password: "correct horse", AllowControl: true, UpdateDir: dir})
		if code := upload(t, base, login(t, base, "correct horse"), apk); code != http.StatusForbidden {
			t.Fatalf("upload from read-only session = %d, want 403", code)
		}
		if called(h) {
			t.Fatal("read-only session reached app.update")
		}
	})

	t.Run("control session hands the APK to app.update", func(t *testing.T) {
		dir := t.TempDir()
		_, h, _, base := start(t, Config{Password: "correct horse", PasswordGrantsControl: true, AllowControl: true, UpdateDir: dir})
		if code := upload(t, base, login(t, base, "correct horse"), apk); code != http.StatusOK {
			t.Fatalf("upload = %d, want 200", code)
		}
		if !called(h) {
			t.Fatal("app.update not called")
		}
		got, err := os.ReadFile(filepath.Join(dir, "update.apk"))
		if err != nil || !bytes.Equal(got, apk) {
			t.Fatalf("saved APK = %q, %v; want the upload", got, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Fatalf("update dir holds %d files, want only update.apk", len(entries))
		}
	})
}

func TestCaptureLogsFromStart(t *testing.T) {
	t.Cleanup(func() {
		logs.always.Store(false)
		logs.disable()
	})
	w := TeeLogs(io.Discard)
	CaptureLogsFromStart()
	fmt.Fprintln(w, "start-up line")

	s, _, _, base := start(t, Config{Password: "correct horse"})
	tok := login(t, base, "correct horse")
	read := func() string {
		req, _ := http.NewRequest("GET", base+"/v1/logs", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if !strings.Contains(read(), "start-up line") {
		t.Fatal("a line logged before the server started is missing")
	}

	s.Stop()
	fmt.Fprintln(w, "after a server stopped")
	if !logs.on.Load() {
		t.Fatal("stopping a server turned capture off")
	}
}

func TestAppLinesAreNotDuplicatedByGo(t *testing.T) {
	r := &logRing{nextSeq: 1, wake: make(chan struct{})}
	r.enable()
	r.add("app", "IPNService: MultiProxy peer: a -> fd7a::1")
	r.add("go", "2026/10/22 18:00:00 IPNService: MultiProxy peer: a -> fd7a::1")
	r.add("go", "magicsock: derp-3 connected")
	lines, _, _ := r.since(0)
	if len(lines) != 2 || lines[1].Text != "magicsock: derp-3 connected" {
		t.Fatalf("lines = %+v", lines)
	}
}
