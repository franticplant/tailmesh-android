// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/tailscale/tailscale-android/libtailscale/remotectl"
)

// Gomobile surface of the remote-control endpoint (see package remotectl).
//
// Only the app reaches these functions. They are the controls the HTTP API
// deliberately cannot touch: starting and stopping the server, approving and
// revoking clients, the global control switch, and clearing the access log.

// RemoteControlHandler is implemented by the app. Call executes one method of
// the catalog passed in the start configuration; the rest are notifications
// the app surfaces to the user. Callbacks arrive on Go goroutines.
type RemoteControlHandler interface {
	Call(method, argsJSON string) (string, error)
	OnApprovalRequest(requestJSON string)
	OnAccess(entryJSON string)
	OnSessionsChanged()
	OnStopped(reason string)
}

var remoteCtl struct {
	mu  sync.Mutex
	srv *remotectl.Server
}

type remoteEvents struct{ h RemoteControlHandler }

func (e remoteEvents) OnApprovalRequest(r remotectl.ApprovalRequest) {
	b, _ := json.Marshal(r)
	e.h.OnApprovalRequest(string(b))
}

func (e remoteEvents) OnAccess(a remotectl.AccessEntry) {
	b, _ := json.Marshal(a)
	e.h.OnAccess(string(b))
}

func (e remoteEvents) OnSessionsChanged() { e.h.OnSessionsChanged() }

func (e remoteEvents) OnStopped(reason string) { e.h.OnStopped(reason) }

// StartRemoteControl starts the endpoint with a JSON remotectl.Config, stopping
// any previous instance first. It returns the address listened on.
func StartRemoteControl(configJSON string, h RemoteControlHandler) (string, error) {
	if h == nil {
		return "", errors.New("remote control: no handler")
	}
	var cfg remotectl.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", err
	}
	remoteCtl.mu.Lock()
	defer remoteCtl.mu.Unlock()
	if remoteCtl.srv != nil {
		remoteCtl.srv.Stop()
		remoteCtl.srv = nil
	}
	srv, err := remotectl.Start(cfg, h, remoteEvents{h})
	if err != nil {
		return "", err
	}
	remoteCtl.srv = srv
	go func() {
		<-srv.Done()
		remoteCtl.mu.Lock()
		if remoteCtl.srv == srv {
			remoteCtl.srv = nil
		}
		remoteCtl.mu.Unlock()
	}()
	return srv.Addr().String(), nil
}

func remoteServer() *remotectl.Server {
	remoteCtl.mu.Lock()
	defer remoteCtl.mu.Unlock()
	return remoteCtl.srv
}

// StopRemoteControl stops the endpoint, ending every session.
func StopRemoteControl() {
	if s := remoteServer(); s != nil {
		s.Stop()
	}
}

// RemoteControlRunning reports whether the endpoint is up.
func RemoteControlRunning() bool { return remoteServer() != nil }

// RemoteControlApprove answers a pending approval request.
func RemoteControlApprove(requestID string, control bool) error {
	s := remoteServer()
	if s == nil {
		return errors.New("remote control is not running")
	}
	return s.Approve(requestID, control)
}

// RemoteControlDeny rejects a pending approval request.
func RemoteControlDeny(requestID string) error {
	s := remoteServer()
	if s == nil {
		return errors.New("remote control is not running")
	}
	return s.Deny(requestID)
}

// RemoteControlRevokeSession ends one session.
func RemoteControlRevokeSession(sessionID string) {
	if s := remoteServer(); s != nil {
		s.RevokeSession(sessionID)
	}
}

// RemoteControlSetAllowControl flips the global control switch live.
func RemoteControlSetAllowControl(allow bool) {
	if s := remoteServer(); s != nil {
		s.SetAllowControl(allow)
	}
}

// RemoteControlSessionsJSON lists live sessions.
func RemoteControlSessionsJSON() string {
	var out []remotectl.SessionInfo
	if s := remoteServer(); s != nil {
		out = s.Sessions()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// RemoteControlPendingJSON lists approval requests awaiting a decision.
func RemoteControlPendingJSON() string {
	var out []remotectl.ApprovalRequest
	if s := remoteServer(); s != nil {
		out = s.PendingApprovals()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// RemoteControlAccessLogJSON returns the last n access-log entries at path.
func RemoteControlAccessLogJSON(path string, n int32) string {
	b, _ := json.Marshal(remotectl.ReadAccessLog(path, int(n)))
	return string(b)
}

// RemoteControlClearAccessLog deletes the access log at path. It refuses
// while the endpoint is running, so the log of a live session cannot be
// erased under it.
func RemoteControlClearAccessLog(path string) error {
	if remoteServer() != nil {
		return errors.New("stop remote control before clearing its access log")
	}
	return remotectl.ClearAccessLog(path)
}

// RemoteControlLog adds a line from the app's own logging to /v1/logs. A no-op
// while the endpoint is off.
func RemoteControlLog(source, line string) { remotectl.AddLog(source, line) }
