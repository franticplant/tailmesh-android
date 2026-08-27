package multiproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAddExitNodeUpstreamValidatesPeerAddr(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	err := e.AddExitNodeUpstream("exit1", "tn", "key", "not-an-ip", false)
	if err == nil || !strings.Contains(err.Error(), "invalid exit node peer address") {
		t.Fatalf("got %v, want an invalid-address rejection", err)
	}
}

func TestAddExitNodeUpstreamRejectsDuplicateID(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("first add: %v", err)
	}
	err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.6", false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v, want a duplicate-id rejection", err)
	}
}

func TestAddExitNodeUpstreamRejectsCollisionWithTailnet(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddTailnet("shared", "key", false); err != nil {
		t.Fatalf("AddTailnet: %v", err)
	}
	err := e.AddExitNodeUpstream("shared", "tn", "key", "100.64.0.5", false)
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("got %v, want a collision rejection", err)
	}
}

// A disabled exit-node upstream is still listed - "off" must read differently
// from "absent" - and reports not ready, matching the tailnet convention.
func TestExitNodeUpstreamListedButNotReadyWhenDisabled(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("AddExitNodeUpstream: %v", err)
	}

	p, ok := e.lookupProvider("exit1")
	if !ok {
		t.Fatal("exit node upstream not found in registry")
	}
	if p.Kind() != UpstreamKindExitNode {
		t.Fatalf("got kind %q, want %q", p.Kind(), UpstreamKindExitNode)
	}
	if p.Ready() {
		t.Fatal("a disabled exit node upstream must not report ready")
	}

	if _, err := p.Dial(context.Background(), "tcp", "1.1.1.1:80"); err == nil {
		t.Fatal("dialing a not-ready exit node upstream must fail")
	}
}

func TestExitNodeUpstreamAppearsInSnapshot(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("AddExitNodeUpstream: %v", err)
	}

	found := false
	for _, info := range e.UpstreamSnapshot() {
		if info.ID == "exit1" {
			found = true
			if info.Kind != "exitnode" {
				t.Fatalf("got kind %q, want exitnode", info.Kind)
			}
			if info.Ready {
				t.Fatal("disabled exit node upstream should not be ready")
			}
		}
	}
	if !found {
		t.Fatal("exit1 missing from UpstreamSnapshot")
	}
}

func TestForgetExitNodeUpstreamRemovesIt(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("AddExitNodeUpstream: %v", err)
	}
	if err := e.ForgetExitNodeUpstream("exit1"); err != nil {
		t.Fatalf("ForgetExitNodeUpstream: %v", err)
	}
	if _, ok := e.lookupProvider("exit1"); ok {
		t.Fatal("exit1 should be gone after Forget")
	}
	if err := e.ForgetExitNodeUpstream("exit1"); err == nil {
		t.Fatal("forgetting an already-forgotten exit node upstream should error")
	}
}

func TestRegisterUpstreamRejectsExitNodeKind(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	err := e.RegisterUpstream(&exitNodeProvider{engine: e, id: "exit1"})
	if err == nil || !strings.Contains(err.Error(), "AddExitNodeUpstream") {
		t.Fatalf("got %v, want a rejection pointing at AddExitNodeUpstream", err)
	}
}

// GetExitNodeCandidatesJSON must not be able to start a tailnet on its own,
// and must degrade to an empty list rather than erroring when the named
// tailnet doesn't exist or isn't running yet.
func TestGetExitNodeCandidatesJSONForUnknownOrStoppedTailnet(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if got := e.GetExitNodeCandidatesJSON("nope"); got != "[]" {
		t.Fatalf("got %q for an unknown tailnet, want []", got)
	}

	if err := e.AddTailnet("tn", "key", false); err != nil {
		t.Fatalf("AddTailnet: %v", err)
	}
	if got := e.GetExitNodeCandidatesJSON("tn"); got != "[]" {
		t.Fatalf("got %q for a stopped tailnet, want []", got)
	}
}

// SetTailnetExitNode is the cheap, no-extra-auth path: it must refuse to act
// on a tailnet that isn't actually running, rather than silently no-op-ing.
func TestSetTailnetExitNodeRequiresRunningTailnet(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.SetTailnetExitNode("nope", "100.64.0.5"); err == nil {
		t.Fatal("expected an error for an unknown tailnet")
	}

	if err := e.AddTailnet("tn", "key", false); err != nil {
		t.Fatalf("AddTailnet: %v", err)
	}
	if err := e.SetTailnetExitNode("tn", "100.64.0.5"); err == nil {
		t.Fatal("expected an error for a stopped tailnet")
	}
}

func TestSetTailnetExitNodeValidatesPeerAddr(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddTailnet("tn", "key", true); err != nil {
		t.Fatalf("AddTailnet: %v", err)
	}
	err := e.SetTailnetExitNode("tn", "not-an-ip")
	if err == nil || !strings.Contains(err.Error(), "invalid exit node peer address") {
		t.Fatalf("got %v, want an invalid-address rejection", err)
	}
}

// Regression test for a real race: enabling an exit node starts a
// tsnet.Server and a background goroutine that calls LocalClient().EditPrefs
// on it (setExitNodeEnabledLocked). tsnet.Server.LocalClient() calls
// s.Start() internally, so if Forget/disable's srv.Close() won the race
// against that goroutine reaching LocalClient(), the goroutine would
// restart an already-closed Server out from under state Forget was about to
// delete. ExitNodeRuntime.Wg exists so Forget waits for that goroutine to
// actually finish first - this must pass clean under -race.
func TestForgetExitNodeUpstreamRacesEnableSafely(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", true); err != nil {
		t.Fatalf("AddExitNodeUpstream: %v", err)
	}
	// No real auth key, so the tsnet.Server sits at NeedsLogin - the
	// EditPrefs goroutine is still in flight (or about to be) when Forget
	// runs immediately after, which is exactly the interleaving that used to
	// race.
	if err := e.ForgetExitNodeUpstream("exit1"); err != nil {
		t.Fatalf("ForgetExitNodeUpstream: %v", err)
	}
	if _, ok := e.lookupProvider("exit1"); ok {
		t.Fatal("exit1 should be gone after Forget")
	}
}

// AddExitNodeUpstream must refuse a request past maxExitNodeUpstreams rather
// than let an unbounded number of dedicated tsnet.Server identities pile up -
// see maxExitNodeUpstreams' doc comment for why that is a real resource cost,
// not just a device-slot count.
func TestAddExitNodeUpstreamEnforcesCap(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	for i := 0; i < maxExitNodeUpstreams; i++ {
		id := fmt.Sprintf("exit%d", i)
		if err := e.AddExitNodeUpstream(id, "tn", "key", "100.64.0.5", false); err != nil {
			t.Fatalf("add #%d: %v", i, err)
		}
	}
	err := e.AddExitNodeUpstream("one-too-many", "tn", "key", "100.64.0.5", false)
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("got %v, want a cap-exceeded rejection", err)
	}

	// Forgetting one frees a slot back up.
	if err := e.ForgetExitNodeUpstream("exit0"); err != nil {
		t.Fatalf("ForgetExitNodeUpstream: %v", err)
	}
	if err := e.AddExitNodeUpstream("one-too-many", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("add after freeing a slot: %v", err)
	}
}

// GetExitNodeStatesJSON is what makes a stuck NeedsMachineAuth/NeedsLogin
// dedicated identity visible (see its doc comment) - a disabled upstream
// must read as the cheap, unambiguous STOPPED rather than an empty or
// missing state, matching GetTailnetStatesJSON's convention for tailnets.
func TestGetExitNodeStatesJSONReportsDisabled(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if got := e.GetExitNodeStatesJSON(); got != "[]" {
		t.Fatalf("got %q with no exit nodes configured, want []", got)
	}

	if err := e.AddExitNodeUpstream("exit1", "tn", "key", "100.64.0.5", false); err != nil {
		t.Fatalf("AddExitNodeUpstream: %v", err)
	}

	var rows []ExitNodeRuntimeExport
	if err := json.Unmarshal([]byte(e.GetExitNodeStatesJSON()), &rows); err != nil {
		t.Fatalf("could not decode GetExitNodeStatesJSON: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.ID != "exit1" || row.SourceTailnetID != "tn" || row.PeerAddr != "100.64.0.5" {
		t.Fatalf("unexpected row: %+v", row)
	}
	if row.Enabled {
		t.Fatalf("row reports Enabled, want false: %+v", row)
	}
	if row.State != "STOPPED" {
		t.Fatalf("got state %q, want STOPPED: %+v", row.State, row)
	}
}
