// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package remotectl is Tailmesh's opt-in remote control and debugging
// endpoint: an authenticated HTTP API that can do everything the app's own UI
// can, from another machine.
//
// It exists because debugging the dataplane from the outside - a laptop on
// the other end of a USB tether, or an agent investigating a failure - kept
// needing the phone in hand to read a counter, flip a setting, or start a
// capture. The server is deliberately thin. Everything stateful (upstreams,
// bindings, tailnets, captures) is delegated to a Handler the Android app
// implements, so a remote action goes through exactly the same code path as
// tapping the same control in the UI and the two never disagree. What lives
// here is what only Go can do well or what must not depend on the app's
// state: authentication, sessions, the access log, live log streaming, pprof,
// and file download.
//
// Security model (see docs/features/04-remote-control.md):
//   - Off unless the user turns it on in the app.
//   - Two ways to obtain a session, usable together: approval on the device
//     (the app shows Allow / Allow read-only / Deny) and a password.
//   - Authentication attempts share one global rate limit. That bounds
//     password guessing regardless of how many addresses an attacker uses,
//     at the cost that a flood of attempts can lock legitimate clients out
//     for as long as it lasts - availability is traded for brute-force
//     resistance deliberately.
//   - Sessions are read-only unless both the user allowed control for that
//     session and control is enabled globally. The global switch applies to
//     existing sessions immediately.
//   - Every request and every authentication attempt is written to an
//     append-only access log. Nothing reachable through the API can modify
//     or clear it, revoke sessions, or change remote-control settings: those
//     are only exposed to the app.
//   - Plain HTTP, bound to loopback by default. On an untrusted network it
//     should be reached through a tailnet (an inbound listener forwarding to
//     the loopback port) or an adb/SSH tunnel.
package remotectl

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Handler executes app-level methods. Implemented by the Android app.
type Handler interface {
	// Call runs method with JSON-encoded args and returns a JSON-encoded
	// result. A returned error is reported to the client as the call's
	// failure.
	Call(method string, argsJSON string) (resultJSON string, err error)
}

// Method describes one Handler method, as published by the app.
type Method struct {
	Name        string `json:"name"`
	Mutating    bool   `json:"mutating"`
	Description string `json:"description"`
	// Params maps each argument name to a short description.
	Params map[string]string `json:"params,omitempty"`
}

// Config configures a Server.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:7373".
	Addr string `json:"addr"`

	// ApprovalEnabled lets a client request a session that the user approves
	// on the device.
	ApprovalEnabled bool `json:"approvalEnabled"`
	// Password, if non-empty, lets a client obtain a session by presenting it.
	Password string `json:"password,omitempty"`
	// PasswordGrantsControl reports whether a password session may control
	// (subject to AllowControl) or is read-only.
	PasswordGrantsControl bool `json:"passwordGrantsControl"`
	// AllowControl is the global switch: when false every session is
	// read-only. Changeable at runtime with SetAllowControl.
	AllowControl bool `json:"allowControl"`

	// AuthAttemptsPerSecond and AuthBurst size the global authentication rate
	// limit, shared by every client. Defaults: 2/s, burst 10.
	AuthAttemptsPerSecond float64 `json:"authAttemptsPerSecond,omitempty"`
	AuthBurst             int     `json:"authBurst,omitempty"`

	// SessionIdleSeconds expires a session unused this long. Default 1 hour.
	SessionIdleSeconds int64 `json:"sessionIdleSeconds,omitempty"`
	// ExpiresAtUnix, if non-zero, is when the whole server stops itself.
	ExpiresAtUnix int64 `json:"expiresAtUnix,omitempty"`

	// AccessLogPath is the append-only access log. Required.
	AccessLogPath string `json:"accessLogPath"`
	// FileRoots are directories whose files may be downloaded.
	FileRoots []string `json:"fileRoots,omitempty"`
	// Version is reported by /v1/status.
	Version string `json:"version,omitempty"`
	// Methods is the Handler's method catalog.
	Methods []Method `json:"methods"`
}

// Events is notified of things the app must surface to the user.
type Events interface {
	// OnApprovalRequest asks the user to approve a new client. The app
	// answers with Server.Approve or Server.Deny.
	OnApprovalRequest(req ApprovalRequest)
	// OnAccess is called for every access-log entry.
	OnAccess(entry AccessEntry)
	// OnSessionsChanged is called when a session is created or ends.
	OnSessionsChanged()
	// OnStopped is called once when the server stops, with the reason.
	OnStopped(reason string)
}

// ApprovalRequest is a client waiting for the user's decision.
type ApprovalRequest struct {
	ID     string    `json:"id"`
	Client string    `json:"client"`
	Remote string    `json:"remote"`
	Code   string    `json:"code"`
	Time   time.Time `json:"time"`
}

// AccessEntry is one line of the access log.
type AccessEntry struct {
	Time    time.Time `json:"time"`
	Remote  string    `json:"remote"`
	Session string    `json:"session,omitempty"`
	Client  string    `json:"client,omitempty"`
	Action  string    `json:"action"`
	// Args lists argument names only, never values: values carry auth keys,
	// private keys and passwords.
	Args   string `json:"args,omitempty"`
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// SessionInfo describes a live session.
type SessionInfo struct {
	ID       string    `json:"id"`
	Client   string    `json:"client"`
	Remote   string    `json:"remote"`
	Via      string    `json:"via"`
	Control  bool      `json:"control"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
}

const (
	maxRequestBody   = 1 << 20
	handlerTimeout   = 60 * time.Second
	approvalLifetime = 2 * time.Minute
	approvalPollWait = 25 * time.Second
	maxPending       = 8
	maxSessions      = 32
	maxClientName    = 64
	accessLogMaxSize = 4 << 20
)

type session struct {
	info SessionInfo
}

type pending struct {
	req     ApprovalRequest
	expires time.Time
	decided chan struct{}
	// Set once decided; guarded by Server.mu until decided is closed.
	isDecided bool
	expired   bool
	approved  bool
	control   bool
	token     string
}

// Server is a running remote-control endpoint.
type Server struct {
	cfg      Config
	h        Handler
	ev       Events
	methods  map[string]Method
	ln       net.Listener
	srv      *http.Server
	started  time.Time
	limiter  *rate.Limiter
	idle     time.Duration
	pwDigest [32]byte
	access   *accessLog

	mu           sync.Mutex
	allowControl bool
	sessions     map[[32]byte]*session // keyed by sha256(token)
	pending      map[string]*pending
	stopped      bool
	stopTimer    *time.Timer
	done         chan struct{}
}

// Start validates cfg, starts listening, and serves until Stop or expiry.
func Start(cfg Config, h Handler, ev Events) (*Server, error) {
	if !cfg.ApprovalEnabled && cfg.Password == "" {
		return nil, errors.New("remotectl: enable device approval, a password, or both")
	}
	if cfg.Password != "" && len(cfg.Password) < 8 {
		return nil, errors.New("remotectl: password must be at least 8 characters")
	}
	if h == nil {
		return nil, errors.New("remotectl: no handler")
	}
	if cfg.AccessLogPath == "" {
		return nil, errors.New("remotectl: no access log path")
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:7373"
	}
	if cfg.AuthAttemptsPerSecond <= 0 {
		cfg.AuthAttemptsPerSecond = 2
	}
	if cfg.AuthBurst <= 0 {
		cfg.AuthBurst = 10
	}
	idle := time.Hour
	if cfg.SessionIdleSeconds > 0 {
		idle = time.Duration(cfg.SessionIdleSeconds) * time.Second
	}
	var expires time.Time
	if cfg.ExpiresAtUnix != 0 {
		expires = time.Unix(cfg.ExpiresAtUnix, 0)
		if !time.Now().Before(expires) {
			return nil, errors.New("remotectl: expiry is in the past")
		}
	}

	access, err := openAccessLog(cfg.AccessLogPath)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		access.close()
		return nil, fmt.Errorf("remotectl: listen %s: %w", cfg.Addr, err)
	}

	s := &Server{
		cfg:          cfg,
		h:            h,
		ev:           ev,
		methods:      make(map[string]Method, len(cfg.Methods)),
		ln:           ln,
		started:      time.Now(),
		limiter:      rate.NewLimiter(rate.Limit(cfg.AuthAttemptsPerSecond), cfg.AuthBurst),
		idle:         idle,
		access:       access,
		allowControl: cfg.AllowControl,
		sessions:     make(map[[32]byte]*session),
		pending:      make(map[string]*pending),
		done:         make(chan struct{}),
	}
	if cfg.Password != "" {
		s.pwDigest = sha256.Sum256([]byte(cfg.Password))
	}
	for _, m := range cfg.Methods {
		s.methods[m.Name] = m
	}
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if !expires.IsZero() {
		s.mu.Lock()
		s.stopTimer = time.AfterFunc(time.Until(expires), func() { s.stop("expired") })
		s.mu.Unlock()
	}
	logs.enable()
	go func() {
		err := s.srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.stop("serve error: " + err.Error())
		}
	}()
	go s.janitor()
	s.logAccess(AccessEntry{Action: "server.start", Remote: ln.Addr().String(), Status: http.StatusOK})
	log.Printf("remotectl: listening on %s (approval=%v password=%v control=%v expires=%v)",
		ln.Addr(), cfg.ApprovalEnabled, cfg.Password != "", cfg.AllowControl, expires)
	return s, nil
}

// Addr returns the address actually listened on.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Stop shuts the server down, ending every session.
func (s *Server) Stop() { s.stop("stopped by user") }

// Done is closed once the server has stopped.
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) stop(reason string) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	if s.stopTimer != nil {
		s.stopTimer.Stop()
	}
	s.sessions = map[[32]byte]*session{}
	for id, p := range s.pending {
		delete(s.pending, id)
		if !p.isDecided {
			p.isDecided, p.expired = true, true
			close(p.decided)
		}
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = s.srv.Shutdown(ctx)
	cancel()
	_ = s.srv.Close()
	logs.disable()
	s.logAccess(AccessEntry{Action: "server.stop", Error: reason, Status: http.StatusOK})
	s.access.close()
	close(s.done)
	log.Printf("remotectl: stopped (%s)", reason)
	if s.ev != nil {
		s.ev.OnStopped(reason)
	}
}

// janitor expires idle sessions and stale approval requests.
func (s *Server) janitor() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		now := time.Now()
		changed := false
		s.mu.Lock()
		for k, sess := range s.sessions {
			if now.Sub(sess.info.LastUsed) > s.idle {
				delete(s.sessions, k)
				changed = true
			}
		}
		for id, p := range s.pending {
			if now.After(p.expires) {
				delete(s.pending, id)
				if !p.isDecided {
					p.isDecided, p.expired = true, true
					close(p.decided)
				}
			}
		}
		s.mu.Unlock()
		if changed && s.ev != nil {
			s.ev.OnSessionsChanged()
		}
	}
}

// ---------------------------------------------------------------------------
// App-side controls. None of these are reachable through HTTP.
// ---------------------------------------------------------------------------

// Approve grants the pending request id a session. control is honoured only
// while control is enabled globally.
func (s *Server) Approve(id string, control bool) error { return s.decide(id, true, control) }

// Deny rejects the pending request id.
func (s *Server) Deny(id string) error { return s.decide(id, false, false) }

func (s *Server) decide(id string, approve, control bool) error {
	s.mu.Lock()
	p, ok := s.pending[id]
	if !ok || p.isDecided {
		s.mu.Unlock()
		return errors.New("remotectl: no such pending request (it may have expired)")
	}
	// Kept until the client collects the outcome or the window lapses.
	p.isDecided = true
	p.expires = time.Now().Add(approvalLifetime)
	p.approved = approve
	p.control = control
	var tok string
	if approve {
		var err error
		tok, err = s.newSessionLocked(p.req.Client, p.req.Remote, "approval", control)
		if err != nil {
			p.approved = false
			s.mu.Unlock()
			close(p.decided)
			return err
		}
		p.token = tok
	}
	s.mu.Unlock()
	close(p.decided)

	action := "auth.approval.denied"
	if approve {
		action = "auth.approval.approved"
		if control {
			action += " (control)"
		} else {
			action += " (read-only)"
		}
	}
	s.logAccess(AccessEntry{Remote: p.req.Remote, Client: p.req.Client, Action: action, Status: http.StatusOK})
	if approve && s.ev != nil {
		s.ev.OnSessionsChanged()
	}
	return nil
}

// RevokeSession ends one session by its ID.
func (s *Server) RevokeSession(id string) {
	s.mu.Lock()
	var found *session
	for k, sess := range s.sessions {
		if sess.info.ID == id {
			delete(s.sessions, k)
			found = sess
		}
	}
	s.mu.Unlock()
	if found != nil {
		s.logAccess(AccessEntry{Remote: found.info.Remote, Client: found.info.Client, Session: id, Action: "session.revoked", Status: http.StatusOK})
		if s.ev != nil {
			s.ev.OnSessionsChanged()
		}
	}
}

// SetAllowControl flips the global control switch. Takes effect immediately
// for existing sessions.
func (s *Server) SetAllowControl(allow bool) {
	s.mu.Lock()
	s.allowControl = allow
	s.mu.Unlock()
	s.logAccess(AccessEntry{Action: fmt.Sprintf("server.allowControl=%v", allow), Status: http.StatusOK})
}

// Sessions lists live sessions.
func (s *Server) Sessions() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionInfo, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess.info)
	}
	return out
}

// PendingApprovals lists requests awaiting a decision.
func (s *Server) PendingApprovals() []ApprovalRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ApprovalRequest, 0, len(s.pending))
	for _, p := range s.pending {
		if !p.isDecided {
			out = append(out, p.req)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/request", s.handleApprovalRequest)
	mux.HandleFunc("GET /v1/auth/request/{id}", s.handleApprovalPoll)
	mux.HandleFunc("POST /v1/auth/logout", s.need(false, s.handleLogout))

	mux.HandleFunc("GET /v1/status", s.need(false, s.handleStatus))
	mux.HandleFunc("GET /v1/methods", s.need(false, s.handleMethods))
	mux.HandleFunc("POST /v1/call/{method}", s.need(false, s.handleCall))
	mux.HandleFunc("GET /v1/logs", s.need(false, s.handleLogs))
	mux.HandleFunc("GET /v1/access-log", s.need(false, s.handleAccessLog))
	mux.HandleFunc("GET /v1/files", s.need(true, s.handleFile))

	// Profiling costs CPU on the device and exposes memory contents, so it
	// takes control.
	mux.HandleFunc("/debug/pprof/", s.need(true, pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", s.need(true, pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", s.need(true, pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", s.need(true, pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", s.need(true, pprof.Trace))
	return mux
}

type ctxKey struct{}

type reqInfo struct {
	sess    SessionInfo
	control bool
	// Filled in by handlers for the access log.
	action string
	args   string
	err    string
}

// statusWriter records the response status for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// need authenticates the session token and, when control is true, requires a
// control session. Every request through it is access-logged.
func (s *Server) need(control bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		ri := &reqInfo{action: r.Method + " " + r.URL.Path}
		defer func() {
			s.logAccess(AccessEntry{
				Remote:  r.RemoteAddr,
				Session: ri.sess.ID,
				Client:  ri.sess.Client,
				Action:  ri.action,
				Args:    ri.args,
				Status:  sw.status,
				Error:   ri.err,
			})
		}()

		sess, ctl, ok := s.lookupSession(r)
		if !ok {
			// A bad session token is an authentication attempt like any
			// other, so guessing tokens is bounded by the same limit.
			if !s.limiter.Allow() {
				ri.err = "rate limited"
				writeError(sw, http.StatusTooManyRequests, "authentication rate limit reached; try again shortly")
				return
			}
			ri.err = "no valid session"
			sw.Header().Set("WWW-Authenticate", `Bearer realm="tailmesh"`)
			writeError(sw, http.StatusUnauthorized, "missing or expired session token; authenticate via /v1/auth/request or /v1/auth/login")
			return
		}
		ri.sess = sess
		ri.control = ctl
		if control && !ctl {
			ri.err = "read-only session"
			writeError(sw, http.StatusForbidden, readOnlyMessage(s))
			return
		}
		h(sw, r.WithContext(context.WithValue(r.Context(), ctxKey{}, ri)))
	}
}

func readOnlyMessage(s *Server) string {
	s.mu.Lock()
	allow := s.allowControl
	s.mu.Unlock()
	if !allow {
		return "control is switched off on the device; this session is read-only"
	}
	return "this session is read-only"
}

func info(r *http.Request) *reqInfo { return r.Context().Value(ctxKey{}).(*reqInfo) }

func (s *Server) lookupSession(r *http.Request) (SessionInfo, bool, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return SessionInfo{}, false, false
	}
	key := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[key]
	if !ok {
		return SessionInfo{}, false, false
	}
	if time.Since(sess.info.LastUsed) > s.idle {
		delete(s.sessions, key)
		return SessionInfo{}, false, false
	}
	sess.info.LastUsed = time.Now()
	return sess.info, sess.info.Control && s.allowControl, true
}

func (s *Server) newSessionLocked(client, remote, via string, control bool) (string, error) {
	if len(s.sessions) >= maxSessions {
		return "", errors.New("too many active sessions; revoke one in the app")
	}
	tok := randomToken(32)
	now := time.Now()
	s.sessions[sha256.Sum256([]byte(tok))] = &session{info: SessionInfo{
		ID:       randomHex(4),
		Client:   client,
		Remote:   remote,
		Via:      via,
		Control:  control,
		Created:  now,
		LastUsed: now,
	}}
	return tok, nil
}

type authBody struct {
	Client   string `json:"client"`
	Password string `json:"password"`
}

func readAuthBody(r *http.Request) authBody {
	var b authBody
	_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b)
	b.Client = strings.TrimSpace(b.Client)
	if len(b.Client) > maxClientName {
		b.Client = b.Client[:maxClientName]
	}
	if b.Client == "" {
		b.Client = "unnamed client"
	}
	return b
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body := readAuthBody(r)
	entry := AccessEntry{Remote: r.RemoteAddr, Client: body.Client, Action: "auth.login"}
	defer func() { s.logAccess(entry) }()

	if !s.limiter.Allow() {
		entry.Status, entry.Error = http.StatusTooManyRequests, "rate limited"
		writeError(w, entry.Status, "authentication rate limit reached; try again shortly")
		return
	}
	if s.cfg.Password == "" {
		entry.Status, entry.Error = http.StatusForbidden, "password login disabled"
		writeError(w, entry.Status, "password login is disabled on the device")
		return
	}
	got := sha256.Sum256([]byte(body.Password))
	if subtle.ConstantTimeCompare(got[:], s.pwDigest[:]) != 1 {
		entry.Status, entry.Error = http.StatusUnauthorized, "wrong password"
		writeError(w, entry.Status, "wrong password")
		return
	}
	s.mu.Lock()
	tok, err := s.newSessionLocked(body.Client, r.RemoteAddr, "password", s.cfg.PasswordGrantsControl)
	s.mu.Unlock()
	if err != nil {
		entry.Status, entry.Error = http.StatusServiceUnavailable, err.Error()
		writeError(w, entry.Status, err.Error())
		return
	}
	entry.Status = http.StatusOK
	if s.ev != nil {
		s.ev.OnSessionsChanged()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": tok, "control": s.cfg.PasswordGrantsControl})
}

func (s *Server) handleApprovalRequest(w http.ResponseWriter, r *http.Request) {
	body := readAuthBody(r)
	entry := AccessEntry{Remote: r.RemoteAddr, Client: body.Client, Action: "auth.approval.request"}
	defer func() { s.logAccess(entry) }()

	if !s.limiter.Allow() {
		entry.Status, entry.Error = http.StatusTooManyRequests, "rate limited"
		writeError(w, entry.Status, "authentication rate limit reached; try again shortly")
		return
	}
	if !s.cfg.ApprovalEnabled {
		entry.Status, entry.Error = http.StatusForbidden, "approval disabled"
		writeError(w, entry.Status, "device approval is disabled on the device")
		return
	}
	s.mu.Lock()
	undecided := 0
	for _, p := range s.pending {
		if !p.isDecided {
			undecided++
		}
	}
	if undecided >= maxPending {
		s.mu.Unlock()
		entry.Status, entry.Error = http.StatusServiceUnavailable, "too many pending requests"
		writeError(w, entry.Status, "too many requests are already waiting for approval")
		return
	}
	// The request id is the client's secret for collecting its token: it is
	// unguessable, so another client on the network cannot poll for it.
	p := &pending{
		req: ApprovalRequest{
			ID:     randomToken(24),
			Client: body.Client,
			Remote: r.RemoteAddr,
			Code:   randomCode(),
			Time:   time.Now(),
		},
		expires: time.Now().Add(approvalLifetime),
		decided: make(chan struct{}),
	}
	s.pending[p.req.ID] = p
	s.mu.Unlock()

	entry.Status = http.StatusAccepted
	if s.ev != nil {
		s.ev.OnApprovalRequest(p.req)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok":        true,
		"requestId": p.req.ID,
		"code":      p.req.Code,
		"expiresAt": p.expires,
		"hint":      "Confirm the same code is shown on the device, approve there, then GET /v1/auth/request/{requestId} to collect the session token.",
	})
}

func (s *Server) handleApprovalPoll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	p, ok := s.pending[id]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "unknown or expired request")
		return
	}
	select {
	case <-p.decided:
	case <-time.After(approvalPollWait):
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "pending"})
		return
	case <-r.Context().Done():
		return
	}
	// The outcome is handed out once.
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
	switch {
	case p.token != "":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "approved", "token": p.token, "control": p.control})
	case p.approved:
		writeError(w, http.StatusServiceUnavailable, "approved, but no session could be created")
	case p.expired:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "status": "expired"})
	default:
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "status": "denied"})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	key := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
	if s.ev != nil {
		s.ev.OnSessionsChanged()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	var expires *time.Time
	if s.cfg.ExpiresAtUnix != 0 {
		t := time.Unix(s.cfg.ExpiresAtUnix, 0)
		expires = &t
	}
	s.mu.Lock()
	allow := s.allowControl
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"version":      s.cfg.Version,
		"startedAt":    s.started,
		"expiresAt":    expires,
		"session":      ri.sess,
		"control":      ri.control,
		"allowControl": allow,
		"methods":      len(s.methods),
	})
}

func (s *Server) handleMethods(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.cfg.Methods)
}

func (s *Server) handleCall(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	name := r.PathValue("method")
	ri.action = "call " + name
	m, ok := s.methods[name]
	if !ok {
		ri.err = "unknown method"
		writeError(w, http.StatusNotFound, fmt.Sprintf("unknown method %q; GET /v1/methods lists them", name))
		return
	}
	if m.Mutating && !ri.control {
		ri.err = "read-only session"
		writeError(w, http.StatusForbidden, name+" changes state: "+readOnlyMessage(s))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		ri.err = err.Error()
		writeError(w, http.StatusBadRequest, "reading body: "+err.Error())
		return
	}
	if len(body) > maxRequestBody {
		ri.err = "body too large"
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	args := strings.TrimSpace(string(body))
	if args == "" {
		args = "{}"
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(args), &obj) != nil {
		ri.err = "invalid args"
		writeError(w, http.StatusBadRequest, "body must be a JSON object of arguments")
		return
	}
	ri.args = argNames(obj)

	result, err := s.callWithTimeout(name, args)
	if err != nil {
		ri.err = err.Error()
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if result == "" {
		result = "null"
	}
	if !json.Valid([]byte(result)) {
		ri.err = "handler returned invalid JSON"
		writeError(w, http.StatusInternalServerError, ri.err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":true,"result":%s}`+"\n", result)
}

func (s *Server) callWithTimeout(name, args string) (string, error) {
	type res struct {
		out string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- res{err: fmt.Errorf("handler panicked: %v", p)}
			}
		}()
		out, err := s.h.Call(name, args)
		ch <- res{out, err}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(handlerTimeout):
		return "", fmt.Errorf("%s did not finish within %v", name, handlerTimeout)
	}
}

func argNames(m map[string]json.RawMessage) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(sortedStrings(keys), ",")
}

// handleLogs returns buffered log lines after ?since=<seq>, optionally
// filtered by ?grep=. With ?follow=1 it keeps the response open and streams
// new lines as they are written, one JSON object per line.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	grep := r.URL.Query().Get("grep")
	follow := r.URL.Query().Get("follow") == "1"

	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)

	for {
		lines, next, wait := logs.since(since)
		for _, l := range lines {
			if grep != "" && !strings.Contains(l.Text, grep) {
				continue
			}
			if err := enc.Encode(l); err != nil {
				return
			}
		}
		since = next
		if !follow {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case <-wait:
		case <-time.After(15 * time.Second):
			// Keep idle proxies from timing the stream out.
			if _, err := w.Write([]byte("\n")); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 2000 {
		n = 200
	}
	writeJSON(w, http.StatusOK, s.access.tail(n))
}

// handleFile streams one file from under a configured root.
func (s *Server) handleFile(w http.ResponseWriter, r *http.Request) {
	ri := info(r)
	path := r.URL.Query().Get("path")
	ri.args = filepath.Base(path)
	resolved, err := s.allowedFile(path)
	if err != nil {
		ri.err = err.Error()
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	f, err := os.Open(resolved)
	if err != nil {
		ri.err = err.Error()
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		ri.err = "not a regular file"
		writeError(w, http.StatusNotFound, "not a regular file")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(resolved)))
	http.ServeContent(w, r, filepath.Base(resolved), st.ModTime(), f)
}

func (s *Server) allowedFile(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", errors.New("no such file")
	}
	for _, root := range s.cfg.FileRoots {
		rootResolved, err := filepath.EvalSymlinks(filepath.Clean(root))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(rootResolved, resolved)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return resolved, nil
		}
	}
	return "", errors.New("path is outside the downloadable directories")
}

func (s *Server) logAccess(e AccessEntry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	s.access.append(e)
	if s.ev != nil {
		s.ev.OnAccess(e)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// randomCode is a short code shown both to the requesting client and on the
// device, so the user approves the client they think they are approving.
func randomCode() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	n := (int(b[0])<<16 | int(b[1])<<8 | int(b[2])) % 1000000
	return fmt.Sprintf("%03d-%03d", n/1000, n%1000)
}
