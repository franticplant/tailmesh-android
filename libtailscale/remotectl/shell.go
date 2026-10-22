// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package remotectl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The remote shell: development builds only (the app sets Config.Shell only
// there), and only with the user's "Allow remote shell" switch on.
//
// A shell is far more than the method catalog, so it is gated more tightly
// than a control session:
//
//   - By default (Config.ShellApproveEach) every command is approved on the
//     phone, which shows the command itself. Otherwise a shell is approved
//     once and stays open for a while. Either way the session must already
//     be a control session; a password alone never runs anything.
//   - A grant lasts at most ShellMaxMinutes and ends early when the session
//     ends, the server stops or the user taps End on the phone; running
//     commands are killed with it.
//   - Commands run one at a time (POST /v1/shell/exec), not as an interactive
//     terminal, so each one is a discrete, logged event.
//   - Each command is written to the shell log before it starts, and its
//     result (exit status, duration, output sizes and SHA-256) after.
//
// The shell runs as the app, so it can write the app's files, the shell log
// included; nothing on the device can stop that. What it cannot do is change
// the log without it showing: every entry carries the SHA-256 of the one
// before (a hash chain), the newest hash is held in this process's memory,
// and the app mirrors each entry to logcat, which apps cannot rewrite.
// VerifyShellLog checks the file against the in-memory head.

// ShellRequest is a session asking to open a shell, awaiting the user.
type ShellRequest struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	Client  string `json:"client"`
	Remote  string `json:"remote"`
	Code    string `json:"code"`
	Minutes int    `json:"minutes,omitempty"`
	// Cmd is set when this asks to run one command (Config.ShellApproveEach),
	// not to open a shell.
	Cmd            string    `json:"cmd,omitempty"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
	Time           time.Time `json:"time"`
}

// ShellGrant is an open shell.
type ShellGrant struct {
	Session string    `json:"session"`
	Client  string    `json:"client"`
	Remote  string    `json:"remote"`
	Until   time.Time `json:"until"`
	Running int       `json:"running"`
	// Cmd is set for a grant that runs one approved command.
	Cmd string `json:"cmd,omitempty"`
}

// ShellEntry is one line of the shell log.
type ShellEntry struct {
	Seq  int64     `json:"seq"`
	Time time.Time `json:"time"`
	// Prev is the previous entry's Hash; empty for the first.
	Prev    string `json:"prev"`
	Kind    string `json:"kind"` // request, grant, deny, exec, result, end, log-opened
	Session string `json:"session,omitempty"`
	Client  string `json:"client,omitempty"`
	Remote  string `json:"remote,omitempty"`
	Cmd     string `json:"cmd,omitempty"`
	// Result fields, on kind "result".
	Exit        *int   `json:"exit,omitempty"`
	DurationMs  int64  `json:"durationMs,omitempty"`
	StdoutBytes int64  `json:"stdoutBytes,omitempty"`
	StderrBytes int64  `json:"stderrBytes,omitempty"`
	StdoutSHA   string `json:"stdoutSha256,omitempty"`
	StderrSHA   string `json:"stderrSha256,omitempty"`
	Note        string `json:"note,omitempty"`
	// Hash is SHA-256 over this entry's JSON encoding with Hash empty.
	Hash string `json:"hash,omitempty"`
}

// ShellEvents is the optional part of Events for the shell. An Events value
// that does not implement it cannot be asked for a shell, so requests fail.
type ShellEvents interface {
	// OnShellRequest asks the user to allow a shell. The app answers with
	// Server.ApproveShell or Server.DenyShell.
	OnShellRequest(req ShellRequest)
	// OnShellEntry is called for every shell log entry, after it is written.
	OnShellEntry(e ShellEntry)
	// OnShellChanged is called when a grant opens or ends.
	OnShellChanged()
}

const (
	defaultShellMaxMinutes = 30
	defaultShellTimeout    = 60 * time.Second
	maxShellTimeout        = 10 * time.Minute
	maxShellOutput         = 1 << 20 // per stream, returned to the client
	maxShellCmd            = 16 << 10
	maxShellStdin          = 1 << 20
	maxShellPending        = 2
)

type shellPending struct {
	req       ShellRequest
	expires   time.Time
	decided   chan struct{}
	isDecided bool // guarded by Server.mu until decided is closed
	approved  bool
	expired   bool
	until     time.Time
	grant     *shellGrant // the one-command grant, once approved
}

type shellGrant struct {
	key     string // its key in shellState.grants
	info    ShellGrant
	ctx     context.Context
	cancel  context.CancelFunc
	running int
}

// shellState is the Server's shell bookkeeping, guarded by Server.mu.
type shellState struct {
	pending map[string]*shellPending
	// grants is keyed by session ID for an open shell, and by "cmd-" and the
	// request ID for one approved command.
	grants map[string]*shellGrant
}

// ---------------------------------------------------------------------------
// The hash-chained log
// ---------------------------------------------------------------------------

type shellLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	seq  int64
	head string
}

// openShellLog opens (creating) the log and continues its chain. A file that
// fails verification is not refused - the app still needs its shell log - but
// the break is recorded as the first new entry, so it stays visible.
func openShellLog(path string) (*shellLog, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	res := verifyShellFile(path, "")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("remotectl: shell log: %w", err)
	}
	l := &shellLog{path: path, f: f, seq: res.Entries, head: res.LastHash}
	note := fmt.Sprintf("%d earlier entries verified", res.Entries)
	if !res.OK {
		note = "earlier entries FAILED verification: " + res.Problem
	}
	if _, err := l.append(ShellEntry{Kind: "log-opened", Note: note}); err != nil {
		f.Close()
		return nil, err
	}
	return l, nil
}

func (l *shellLog) append(e ShellEntry) (ShellEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return e, errors.New("shell log closed")
	}
	e.Seq = l.seq + 1
	e.Time = time.Now().UTC()
	e.Prev = l.head
	e.Hash = ""
	e.Hash = entryHash(e)
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return e, fmt.Errorf("shell log write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return e, fmt.Errorf("shell log sync: %w", err)
	}
	l.seq, l.head = e.Seq, e.Hash
	return e, nil
}

func (l *shellLog) state() (int64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.head
}

func (l *shellLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

func entryHash(e ShellEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ShellLogVerification is the result of checking the shell log's chain.
type ShellLogVerification struct {
	OK       bool   `json:"ok"`
	Entries  int64  `json:"entries"`
	LastHash string `json:"lastHash"`
	// ExpectedHead is the head this process last wrote, when known; OK
	// requires the file to end exactly there.
	ExpectedHead string `json:"expectedHead,omitempty"`
	Problem      string `json:"problem,omitempty"`
}

// verifyShellFile walks the chain. expectedHead, if non-empty, must be the
// last entry's hash: that catches truncation and a rewritten tail that is
// internally consistent, which the chain alone cannot.
func verifyShellFile(path, expectedHead string) ShellLogVerification {
	res := ShellLogVerification{OK: true, ExpectedHead: expectedHead}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if expectedHead != "" {
			res.OK, res.Problem = false, "log file is missing"
		}
		return res
	}
	if err != nil {
		res.OK, res.Problem = false, err.Error()
		return res
	}
	prev := ""
	for i, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var e ShellEntry
		if err := json.Unmarshal(line, &e); err != nil {
			res.OK, res.Problem = false, fmt.Sprintf("line %d is not a log entry", i+1)
			return res
		}
		if e.Prev != prev {
			res.OK, res.Problem = false, fmt.Sprintf("entry %d does not follow the one before it", e.Seq)
			return res
		}
		if e.Seq != res.Entries+1 {
			res.OK, res.Problem = false, fmt.Sprintf("entry %d is out of sequence (expected %d)", e.Seq, res.Entries+1)
			return res
		}
		if entryHash(e) != e.Hash {
			res.OK, res.Problem = false, fmt.Sprintf("entry %d was altered", e.Seq)
			return res
		}
		prev = e.Hash
		res.Entries = e.Seq
		res.LastHash = e.Hash
	}
	if expectedHead != "" && res.LastHash != expectedHead {
		res.OK = false
		res.Problem = "the log does not end where this app last wrote it (entries removed or replaced)"
	}
	return res
}

// ReadShellLog returns the last n entries of the log at path.
func ReadShellLog(path string, n int) ([]ShellEntry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []ShellEntry
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		var e ShellEntry
		if len(line) == 0 || json.Unmarshal(line, &e) != nil {
			continue
		}
		out = append(out, e)
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

func (s *Server) shellEvents() ShellEvents {
	se, _ := s.ev.(ShellEvents)
	return se
}

// shellLogEntry appends to the shell log and mirrors the entry to the app.
// A failed write is returned so exec can refuse to run unlogged.
func (s *Server) shellLogEntry(e ShellEntry) (ShellEntry, error) {
	if s.shellLog == nil {
		return e, errors.New("no shell log")
	}
	e, err := s.shellLog.append(e)
	if err != nil {
		return e, err
	}
	if se := s.shellEvents(); se != nil {
		se.OnShellEntry(e)
	}
	return e, nil
}

// ApproveShell opens the shell a session asked for.
func (s *Server) ApproveShell(id string) error { return s.decideShell(id, true) }

// DenyShell refuses it.
func (s *Server) DenyShell(id string) error { return s.decideShell(id, false) }

func (s *Server) decideShell(id string, approve bool) error {
	s.mu.Lock()
	p, ok := s.shell.pending[id]
	if !ok || p.isDecided {
		s.mu.Unlock()
		return errors.New("remotectl: no such shell request (it may have expired)")
	}
	p.isDecided = true
	p.approved = approve
	p.expires = time.Now().Add(approvalLifetime)
	if approve {
		// The session must still exist; it may have ended while the user
		// was deciding.
		if !s.sessionExistsLocked(p.req.Session) {
			p.approved = false
			s.mu.Unlock()
			close(p.decided)
			return errors.New("remotectl: that session has ended")
		}
		if p.req.Cmd != "" {
			// One command: the grant lasts as long as the command may run,
			// and handleShellExec removes it when the command ends.
			until := time.Now().Add(time.Duration(p.req.TimeoutSeconds)*time.Second + 5*time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), until)
			g := &shellGrant{
				key:    "cmd-" + p.req.ID,
				info:   ShellGrant{Session: p.req.Session, Client: p.req.Client, Remote: p.req.Remote, Until: until, Cmd: p.req.Cmd},
				ctx:    ctx,
				cancel: cancel,
			}
			s.shell.grants[g.key] = g
			p.grant = g
			p.until = until
		} else {
			until := time.Now().Add(time.Duration(p.req.Minutes) * time.Minute)
			if old := s.shell.grants[p.req.Session]; old != nil {
				old.cancel()
			}
			ctx, cancel := context.WithDeadline(context.Background(), until)
			g := &shellGrant{
				key:    p.req.Session,
				info:   ShellGrant{Session: p.req.Session, Client: p.req.Client, Remote: p.req.Remote, Until: until},
				ctx:    ctx,
				cancel: cancel,
			}
			s.shell.grants[g.key] = g
			p.until = until
			time.AfterFunc(time.Until(until), func() { s.endShellGrant(g.key, g, "time is up") })
		}
	}
	s.mu.Unlock()
	close(p.decided)

	kind := "deny"
	if approve {
		kind = "grant"
	}
	note := fmt.Sprintf("%d minutes", p.req.Minutes)
	if p.req.Cmd != "" {
		note = "one command"
	}
	s.shellLogEntry(ShellEntry{Kind: kind, Session: p.req.Session, Client: p.req.Client, Remote: p.req.Remote,
		Cmd: p.req.Cmd, Note: note})
	s.logAccess(AccessEntry{Remote: p.req.Remote, Client: p.req.Client, Session: p.req.Session,
		Action: "shell." + kind, Status: http.StatusOK})
	if se := s.shellEvents(); approve && se != nil {
		se.OnShellChanged()
	}
	return nil
}

func (s *Server) sessionExistsLocked(id string) bool {
	for _, sess := range s.sessions {
		if sess.info.ID == id {
			return true
		}
	}
	return false
}

// EndShell closes a session's shell and any command of it still running.
func (s *Server) EndShell(sessionID string) { s.endShell(sessionID, "ended on the phone") }

// endShell ends every grant of the session.
func (s *Server) endShell(sessionID, why string) {
	s.mu.Lock()
	var keys []string
	for k, g := range s.shell.grants {
		if g.info.Session == sessionID {
			keys = append(keys, k)
		}
	}
	s.mu.Unlock()
	for _, k := range keys {
		s.endShellGrant(k, nil, why)
	}
}

// endShellGrant ends the grant under key; if only is set, only when that is
// still the grant (an old timer must not end a newer one).
func (s *Server) endShellGrant(key string, only *shellGrant, why string) {
	s.mu.Lock()
	g := s.shell.grants[key]
	if g == nil || (only != nil && g != only) {
		s.mu.Unlock()
		return
	}
	delete(s.shell.grants, key)
	s.mu.Unlock()
	g.cancel()
	s.shellLogEntry(ShellEntry{Kind: "end", Session: g.info.Session, Client: g.info.Client, Remote: g.info.Remote, Cmd: g.info.Cmd, Note: why})
	s.logAccess(AccessEntry{Remote: g.info.Remote, Client: g.info.Client, Session: g.info.Session, Action: "shell.end", Status: http.StatusOK, Error: why})
	if se := s.shellEvents(); se != nil {
		se.OnShellChanged()
	}
}

// endShellsWithoutSession ends grants whose session is gone (revoked, idle,
// logged out). Called after any session removal.
func (s *Server) endShellsWithoutSession() {
	s.mu.Lock()
	var gone []string
	for k, g := range s.shell.grants {
		if !s.sessionExistsLocked(g.info.Session) {
			gone = append(gone, k)
		}
	}
	s.mu.Unlock()
	for _, k := range gone {
		s.endShellGrant(k, nil, "session ended")
	}
}

func (s *Server) endAllShells(why string) {
	s.mu.Lock()
	keys := make([]string, 0, len(s.shell.grants))
	for k := range s.shell.grants {
		keys = append(keys, k)
	}
	s.mu.Unlock()
	for _, k := range keys {
		s.endShellGrant(k, nil, why)
	}
}

// ShellGrants lists open shells.
func (s *Server) ShellGrants() []ShellGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ShellGrant, 0, len(s.shell.grants))
	for _, g := range s.shell.grants {
		info := g.info
		info.Running = g.running
		out = append(out, info)
	}
	return out
}

// PendingShellRequests lists shell requests awaiting the user.
func (s *Server) PendingShellRequests() []ShellRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ShellRequest
	for _, p := range s.shell.pending {
		if !p.isDecided {
			out = append(out, p.req)
		}
	}
	return out
}

// ShellEnabled reports whether this server has the shell.
func (s *Server) ShellEnabled() bool { return s.shellLog != nil }

// VerifyShellLog checks the shell log's chain and that it ends at the head
// this process last wrote.
func (s *Server) VerifyShellLog() ShellLogVerification {
	if s.shellLog == nil {
		return ShellLogVerification{OK: false, Problem: "the shell is not enabled"}
	}
	_, head := s.shellLog.state()
	return verifyShellFile(s.shellLog.path, head)
}

// VerifyShellLogFile checks a shell log with no running server (no known
// head, so only the chain itself is checked).
func VerifyShellLogFile(path string) ShellLogVerification { return verifyShellFile(path, "") }

func (s *Server) shellEnabled(w http.ResponseWriter, ri *reqInfo) bool {
	if s.shellLog == nil {
		ri.err = "shell disabled"
		writeError(w, http.StatusNotFound, "the remote shell exists only in development builds, with \"Allow remote shell\" on")
		return false
	}
	if s.shellEvents() == nil {
		ri.err = "shell unavailable"
		writeError(w, http.StatusNotFound, "the remote shell is not available")
		return false
	}
	return true
}

func (s *Server) handleShellRequest(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	ri.action = "shell.request"
	if !s.shellEnabled(w, ri) {
		return
	}
	if s.cfg.ShellApproveEach {
		ri.err = "approve-each mode"
		writeError(w, http.StatusConflict, "this phone approves each command: POST /v1/shell/exec directly and approve it there")
		return
	}
	var body struct {
		Minutes int `json:"minutes"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&body)
	max := s.cfg.ShellMaxMinutes
	if max <= 0 {
		max = defaultShellMaxMinutes
	}
	if body.Minutes <= 0 {
		body.Minutes = 15
	}
	if body.Minutes > max {
		body.Minutes = max
	}
	ri.args = "minutes=" + strconv.Itoa(body.Minutes)

	s.mu.Lock()
	n := 0
	for _, p := range s.shell.pending {
		if !p.isDecided {
			n++
		}
	}
	if n >= maxShellPending {
		s.mu.Unlock()
		ri.err = "too many pending"
		writeError(w, http.StatusTooManyRequests, "a shell request is already waiting on the phone")
		return
	}
	req := ShellRequest{
		ID:      randomHex(8),
		Session: ri.sess.ID,
		Client:  ri.sess.Client,
		Remote:  r.RemoteAddr,
		Code:    randomCode(),
		Minutes: body.Minutes,
		Time:    time.Now(),
	}
	s.shell.pending[req.ID] = &shellPending{req: req, expires: time.Now().Add(approvalLifetime), decided: make(chan struct{})}
	s.mu.Unlock()

	s.shellLogEntry(ShellEntry{Kind: "request", Session: req.Session, Client: req.Client, Remote: req.Remote,
		Note: fmt.Sprintf("%d minutes, code %s", req.Minutes, req.Code)})
	s.shellEvents().OnShellRequest(req)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id": req.ID, "code": req.Code, "minutes": req.Minutes,
		"expiresInSeconds": int(approvalLifetime.Seconds()),
		"hint":             "approve on the phone (check the code), then poll GET /v1/shell/request/" + req.ID,
	})
}

func (s *Server) handleShellPoll(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	ri.action = "shell.poll"
	id := r.PathValue("id")
	s.mu.Lock()
	p, ok := s.shell.pending[id]
	if ok && p.req.Session != ri.sess.ID {
		ok = false // another session's request
	}
	s.mu.Unlock()
	if !ok {
		ri.err = "unknown request"
		writeError(w, http.StatusNotFound, "no such shell request (it may have expired)")
		return
	}
	select {
	case <-p.decided:
	case <-time.After(approvalPollWait):
	case <-r.Context().Done():
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !p.isDecided:
		writeJSON(w, http.StatusOK, map[string]any{"status": "pending"})
	case p.expired:
		delete(s.shell.pending, id)
		writeJSON(w, http.StatusOK, map[string]any{"status": "expired"})
	case p.approved:
		delete(s.shell.pending, id)
		writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "until": p.until})
	default:
		delete(s.shell.pending, id)
		writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
	}
}

func (s *Server) handleShellEnd(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	ri.action = "shell.end"
	s.endShell(ri.sess.ID, "ended by the client")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleShellLog(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	ri.action = "shell.log"
	if !s.shellEnabled(w, ri) {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 200
	}
	entries, err := ReadShellLog(s.shellLog.path, n)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "verification": s.VerifyShellLog()})
}

// cappedHash keeps the first max bytes, counts and hashes everything.
type cappedHash struct {
	buf   bytes.Buffer
	max   int
	total int64
	h     hash.Hash
}

func newCappedHash(max int) *cappedHash { return &cappedHash{max: max, h: sha256.New()} }

func (c *cappedHash) Write(p []byte) (int, error) {
	c.total += int64(len(p))
	c.h.Write(p)
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedHash) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

func (s *Server) handleShellExec(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	ri.action = "shell.exec"
	if !s.shellEnabled(w, ri) {
		return
	}
	var body struct {
		Cmd            string `json:"cmd"`
		TimeoutSeconds int    `json:"timeoutSeconds"`
		Stdin          string `json:"stdin"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxShellCmd+maxShellStdin+4096)).Decode(&body); err != nil {
		ri.err = "bad body"
		writeError(w, http.StatusBadRequest, "body must be JSON: {\"cmd\": \"...\", \"timeoutSeconds\": n, \"stdin\": \"...\"}")
		return
	}
	if body.Cmd == "" || len(body.Cmd) > maxShellCmd {
		ri.err = "bad cmd"
		writeError(w, http.StatusBadRequest, fmt.Sprintf("cmd must be 1 to %d bytes", maxShellCmd))
		return
	}
	timeout := defaultShellTimeout
	if body.TimeoutSeconds > 0 {
		timeout = min(time.Duration(body.TimeoutSeconds)*time.Second, maxShellTimeout)
	}

	var g *shellGrant
	if s.cfg.ShellApproveEach {
		if g = s.awaitCommandApproval(w, r, ri, body.Cmd, timeout); g == nil {
			return // refused, expired or abandoned; already answered
		}
		defer s.finishCommandGrant(g)
	}
	s.mu.Lock()
	if g == nil {
		g = s.shell.grants[ri.sess.ID]
	}
	if g != nil && g.ctx.Err() == nil {
		g.running++
	}
	s.mu.Unlock()
	if g == nil || g.ctx.Err() != nil {
		ri.err = "no shell grant"
		writeError(w, http.StatusForbidden, "no open shell for this session; POST /v1/shell/request and approve it on the phone")
		return
	}
	defer func() {
		s.mu.Lock()
		g.running--
		s.mu.Unlock()
	}()

	// Logged before it runs: if the log cannot take it, it does not run.
	start, err := s.shellLogEntry(ShellEntry{Kind: "exec", Session: ri.sess.ID, Client: ri.sess.Client, Remote: r.RemoteAddr,
		Cmd: body.Cmd, Note: fmt.Sprintf("timeout %s, stdin %d bytes", timeout, len(body.Stdin))})
	if err != nil {
		ri.err = "shell log failed"
		writeError(w, http.StatusInternalServerError, "the shell log could not be written, so the command was not run: "+err.Error())
		return
	}
	ri.args = "seq=" + strconv.FormatInt(start.Seq, 10)

	ctx, cancel := context.WithTimeout(g.ctx, timeout)
	defer cancel()
	shell := s.cfg.ShellPath
	if shell == "" {
		shell = "/system/bin/sh"
	}
	cmd := exec.CommandContext(ctx, shell, "-c", body.Cmd)
	cmd.Dir = s.cfg.ShellDir
	cmd.Env = append(os.Environ(), "HOME="+s.cfg.ShellDir, "TMPDIR="+filepath.Join(s.cfg.ShellDir, "tmp"))
	if body.Stdin != "" {
		cmd.Stdin = bytes.NewReader([]byte(body.Stdin))
	}
	stdout, stderr := newCappedHash(maxShellOutput), newCappedHash(maxShellOutput)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Its own process group, so a timeout or End kills what it started too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	_ = os.MkdirAll(filepath.Join(s.cfg.ShellDir, "tmp"), 0o700)

	began := time.Now()
	runErr := cmd.Run()
	dur := time.Since(began)
	exit := -1
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	note := ""
	switch {
	case g.ctx.Err() != nil:
		note = "killed: the shell was closed"
	case ctx.Err() != nil:
		note = "killed: timed out after " + timeout.String()
	case runErr != nil && exit < 0:
		note = runErr.Error()
	}
	resultNote := fmt.Sprintf("for entry %d", start.Seq)
	if note != "" {
		resultNote += "; " + note
	}
	s.shellLogEntry(ShellEntry{Kind: "result", Session: ri.sess.ID, Client: ri.sess.Client,
		Exit: &exit, DurationMs: dur.Milliseconds(),
		StdoutBytes: stdout.total, StderrBytes: stderr.total,
		StdoutSHA: stdout.sum(), StderrSHA: stderr.sum(),
		Note: resultNote})

	writeJSON(w, http.StatusOK, map[string]any{
		"seq":             start.Seq,
		"exit":            exit,
		"durationMs":      dur.Milliseconds(),
		"stdout":          stdout.buf.String(),
		"stderr":          stderr.buf.String(),
		"stdoutTruncated": stdout.total > int64(stdout.buf.Len()),
		"stderrTruncated": stderr.total > int64(stderr.buf.Len()),
		"note":            note,
	})
}

// expireShellPendingLocked drops lapsed shell requests. Called by the janitor
// with Server.mu held.
func (s *Server) expireShellPendingLocked(now time.Time) {
	for id, p := range s.shell.pending {
		if now.After(p.expires) {
			delete(s.shell.pending, id)
			if !p.isDecided {
				p.isDecided, p.expired = true, true
				close(p.decided)
			}
		}
	}
}

// awaitCommandApproval asks the phone to approve one command and waits for
// the answer. It returns the command's grant, or nil after answering the
// client with why not.
func (s *Server) awaitCommandApproval(w http.ResponseWriter, r *http.Request, ri *reqInfo, cmd string, timeout time.Duration) *shellGrant {
	s.mu.Lock()
	n := 0
	for _, p := range s.shell.pending {
		if !p.isDecided {
			n++
		}
	}
	if n >= maxShellPending {
		s.mu.Unlock()
		ri.err = "too many pending"
		writeError(w, http.StatusTooManyRequests, "a command is already waiting for approval on the phone")
		return nil
	}
	req := ShellRequest{
		ID:             randomHex(8),
		Session:        ri.sess.ID,
		Client:         ri.sess.Client,
		Remote:         r.RemoteAddr,
		Code:           randomCode(),
		Cmd:            cmd,
		TimeoutSeconds: int(timeout.Seconds()),
		Time:           time.Now(),
	}
	p := &shellPending{req: req, expires: time.Now().Add(approvalLifetime), decided: make(chan struct{})}
	s.shell.pending[req.ID] = p
	s.mu.Unlock()

	if _, err := s.shellLogEntry(ShellEntry{Kind: "request", Session: req.Session, Client: req.Client, Remote: req.Remote,
		Cmd: cmd, Note: "code " + req.Code}); err != nil {
		s.dropPending(req.ID)
		ri.err = "shell log failed"
		writeError(w, http.StatusInternalServerError, "the shell log could not be written, so the command was not offered: "+err.Error())
		return nil
	}
	s.shellEvents().OnShellRequest(req)

	select {
	case <-p.decided:
	case <-r.Context().Done():
		// The client gave up; the phone's prompt goes stale and approving it
		// later finds nothing.
		s.dropPending(req.ID)
		return nil
	}
	s.mu.Lock()
	delete(s.shell.pending, req.ID)
	approved, expired, g := p.approved, p.expired, p.grant
	s.mu.Unlock()
	switch {
	case expired:
		ri.err = "approval expired"
		writeError(w, http.StatusForbidden, "nobody approved the command on the phone in time")
	case !approved || g == nil:
		ri.err = "denied"
		writeError(w, http.StatusForbidden, "the command was denied on the phone")
	default:
		return g
	}
	return nil
}

// finishCommandGrant removes a one-command grant once its command is done.
func (s *Server) finishCommandGrant(g *shellGrant) {
	s.mu.Lock()
	if s.shell.grants[g.key] == g {
		delete(s.shell.grants, g.key)
	}
	s.mu.Unlock()
	g.cancel()
	if se := s.shellEvents(); se != nil {
		se.OnShellChanged()
	}
}

func (s *Server) dropPending(id string) {
	s.mu.Lock()
	if p := s.shell.pending[id]; p != nil && !p.isDecided {
		p.isDecided, p.expired = true, true
		close(p.decided)
	}
	delete(s.shell.pending, id)
	s.mu.Unlock()
}
