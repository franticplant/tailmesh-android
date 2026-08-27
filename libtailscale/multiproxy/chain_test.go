package multiproxy

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// chainFake is a fakeProvider that also declares a chain parent, and that
// records the connections handed to it so a test can prove a dial really
// traversed it.
type chainFake struct {
	fakeProvider
	via UpstreamID
	// dialer, when set, is what this provider uses for its own transport. A
	// chained provider is built with one by the Engine; recording what comes
	// back through it is how the tests observe the chain.
	dialer UpstreamDialer
}

func (p *chainFake) Via() UpstreamID { return p.via }

func (p *chainFake) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !p.ready {
		return nil, ErrUpstreamNotReady
	}
	p.dials = append(p.dials, network+"|"+address)
	if p.dialer != nil {
		// Reaching "our own far end" is what a real provider would do here: a
		// SOCKS5 provider connects to the proxy, a WireGuard one to the peer.
		return p.dialer(ctx, network, string(p.id)+".upstream:1080")
	}
	return nil, errors.New("chainFake: no real connection")
}

func newChainFake(id, via UpstreamID, ready bool) *chainFake {
	return &chainFake{
		fakeProvider: fakeProvider{id: id, kind: UpstreamKindSOCKS5, ready: ready},
		via:          via,
	}
}

func TestChainDialerWithoutViaUsesBase(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	var got string
	base := func(_ context.Context, network, address string) (net.Conn, error) {
		got = network + "|" + address
		return nil, errors.New("base: no real connection")
	}

	d := e.chainDialer("", base)
	if _, err := d(context.Background(), "tcp", "proxy.example:1080"); err == nil {
		t.Fatal("expected the base dialer's error")
	}
	if got != "tcp|proxy.example:1080" {
		t.Fatalf("base dialer saw %q", got)
	}
}

func TestChainDialerRoutesThroughParent(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	parent := newFake("parent", true)
	if err := e.RegisterUpstream(parent); err != nil {
		t.Fatal(err)
	}

	baseCalled := false
	base := func(context.Context, string, string) (net.Conn, error) {
		baseCalled = true
		return nil, errors.New("base should not be used")
	}

	d := e.chainDialer("parent", base)
	if _, err := d(context.Background(), "tcp", "proxy.example:1080"); err == nil {
		t.Fatal("expected the parent's error")
	}
	if baseCalled {
		t.Fatal("a chained dial must not fall back to the device dialer")
	}
	if len(parent.dials) != 1 || parent.dials[0] != "tcp|proxy.example:1080" {
		t.Fatalf("parent saw %v", parent.dials)
	}
}

// A chained upstream whose parent is missing or disabled must fail rather than
// leave from the device: the point of the chain is that its traffic does not.
func TestChainDialerFailsClosedOnUnusableParent(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	base := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("device dialer must not be reached")
		return nil, nil
	}

	t.Run("missing", func(t *testing.T) {
		_, err := e.chainDialer("nope", base)(context.Background(), "tcp", "x:1")
		if !errors.Is(err, ErrUpstreamNotReady) {
			t.Fatalf("got %v, want ErrUpstreamNotReady", err)
		}
	})

	t.Run("not ready", func(t *testing.T) {
		if err := e.RegisterUpstream(newFake("down", false)); err != nil {
			t.Fatal(err)
		}
		_, err := e.chainDialer("down", base)(context.Background(), "tcp", "x:1")
		if !errors.Is(err, ErrUpstreamNotReady) {
			t.Fatalf("got %v, want ErrUpstreamNotReady", err)
		}
	})
}

// Chaining through @direct is the explicit way to say "this one leaves from the
// device", and must land on the base dialer rather than on the direct
// provider's own net.Dialer, which on Android is not the protected one.
func TestChainDialerViaDirectUsesBase(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	var got string
	base := func(_ context.Context, network, address string) (net.Conn, error) {
		got = network + "|" + address
		return nil, errors.New("base: no real connection")
	}

	if _, err := e.chainDialer(DirectUpstreamID, base)(context.Background(), "tcp", "a:1"); err == nil {
		t.Fatal("expected the base dialer's error")
	}
	if got != "tcp|a:1" {
		t.Fatalf("base dialer saw %q", got)
	}
}

func TestChainOfThreeTraversesEveryHop(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	// bottom <- middle <- top, i.e. top's own connection goes through middle,
	// whose own connection goes through bottom.
	bottom := newFake("bottom", true)
	if err := e.RegisterUpstream(bottom); err != nil {
		t.Fatal(err)
	}
	middle := newChainFake("middle", "bottom", true)
	middle.dialer = e.chainDialer(middle.via, nil)
	if err := e.RegisterUpstream(middle); err != nil {
		t.Fatal(err)
	}
	top := newChainFake("top", "middle", true)
	top.dialer = e.chainDialer(top.via, nil)
	if err := e.RegisterUpstream(top); err != nil {
		t.Fatal(err)
	}

	// A datapath dial into top should walk top -> middle -> bottom.
	if _, err := top.Dial(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		t.Fatal("expected the innermost provider's error")
	}
	if len(top.dials) != 1 || top.dials[0] != "tcp|10.0.0.1:443" {
		t.Fatalf("top saw %v", top.dials)
	}
	if len(middle.dials) != 1 || middle.dials[0] != "tcp|top.upstream:1080" {
		t.Fatalf("middle saw %v", middle.dials)
	}
	if len(bottom.dials) != 1 || bottom.dials[0] != "tcp|middle.upstream:1080" {
		t.Fatalf("bottom saw %v", bottom.dials)
	}
}

func TestRegisterRejectsChainCycles(t *testing.T) {
	t.Run("self", func(t *testing.T) {
		e := NewEngine(t.TempDir(), &MockCallback{})
		err := e.RegisterUpstream(newChainFake("a", "a", true))
		if err == nil || !strings.Contains(err.Error(), "chain through itself") {
			t.Fatalf("got %v, want a self-chain rejection", err)
		}
	})

	t.Run("two hops", func(t *testing.T) {
		e := NewEngine(t.TempDir(), &MockCallback{})
		// a -> b is fine on its own: b does not exist yet, so the walk ends.
		if err := e.RegisterUpstream(newChainFake("a", "b", true)); err != nil {
			t.Fatal(err)
		}
		// b -> a closes the loop and must be refused.
		err := e.RegisterUpstream(newChainFake("b", "a", true))
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("got %v, want a cycle rejection", err)
		}
		if _, ok := e.lookupProvider("b"); ok {
			t.Fatal("a rejected provider must not be installed")
		}
	})

	t.Run("three hops", func(t *testing.T) {
		e := NewEngine(t.TempDir(), &MockCallback{})
		if err := e.RegisterUpstream(newChainFake("a", "b", true)); err != nil {
			t.Fatal(err)
		}
		if err := e.RegisterUpstream(newChainFake("b", "c", true)); err != nil {
			t.Fatal(err)
		}
		err := e.RegisterUpstream(newChainFake("c", "a", true))
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("got %v, want a cycle rejection", err)
		}
	})
}

// The static check cannot see a cycle formed after registration - a parent
// replaced, say - so the dial-time depth guard has to catch it too.
func TestChainDepthGuardStopsRuntimeCycle(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})

	a := newChainFake("a", "b", true)
	a.dialer = e.chainDialer("b", nil)
	b := newChainFake("b", "a", true)
	b.dialer = e.chainDialer("a", nil)

	// Installed behind the registry's back, exactly as a racing replacement
	// would leave things.
	e.upstreams.mu.Lock()
	e.upstreams.providers["a"] = a
	e.upstreams.providers["b"] = b
	e.upstreams.mu.Unlock()

	_, err := a.Dial(context.Background(), "tcp", "10.0.0.1:443")
	if !errors.Is(err, ErrChainTooDeep) {
		t.Fatalf("got %v, want ErrChainTooDeep", err)
	}
	if len(a.dials) > maxChainDepth+1 {
		t.Fatalf("cycle ran %d hops, past the depth bound", len(a.dials))
	}
}

func TestUpstreamSnapshotReportsVia(t *testing.T) {
	e := NewEngine(t.TempDir(), &MockCallback{})
	if err := e.RegisterUpstream(newFake("base", true)); err != nil {
		t.Fatal(err)
	}
	if err := e.RegisterUpstream(newChainFake("chained", "base", true)); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, u := range e.UpstreamSnapshot() {
		got[u.ID] = u.Via
	}
	if got["chained"] != "base" {
		t.Fatalf("chained upstream reports via %q", got["chained"])
	}
	if got["base"] != "" {
		t.Fatalf("unchained upstream reports via %q", got["base"])
	}
	if _, ok := got[string(DirectUpstreamID)]; !ok {
		t.Fatal("snapshot is missing the built-in direct upstream")
	}
}
