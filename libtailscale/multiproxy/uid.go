package multiproxy

import (
	"net/netip"
	"time"
)

// UIDResolver attributes a flow to the application that owns it.
//
// gVisor reads raw IP packets off the TUN, which carry no notion of a process,
// so per-app policy needs an out-of-band lookup. On Android that is
// ConnectivityManager.getConnectionOwnerUid, which takes the same 5-tuple the
// forwarder request already gives us.
//
// The signature uses only strings and int32 because this crosses the gomobile
// boundary, which cannot carry netip types.
//
// Implementations must return UnknownAppUID rather than an error when the owner
// cannot be determined, and must not block for long: this is called once per new
// flow, on the datapath.
type UIDResolver interface {
	ResolveUID(protocol, srcIP string, srcPort int32, dstIP string, dstPort int32) int32
}

// uidResolveTimeout bounds how long the datapath will wait for an attribution.
//
// The resolver call crosses JNI into the Android framework. A slow or wedged
// platform call must degrade to "unknown app" - which can only ever widen which
// rule matches, never narrow it - instead of stalling the flow that triggered it.
const uidResolveTimeout = 150 * time.Millisecond

// SetUIDResolver installs (or with nil, removes) the per-flow app attribution
// hook. Without one every flow resolves as UnknownAppUID, so UID-scoped rules
// never match and only broader rules apply.
func (e *Engine) SetUIDResolver(r UIDResolver) {
	e.uidMu.Lock()
	e.uidResolver = r
	e.uidMu.Unlock()
}

func (e *Engine) currentUIDResolver() UIDResolver {
	e.uidMu.RLock()
	defer e.uidMu.RUnlock()
	return e.uidResolver
}

// resolveAppUID attributes a flow, returning UnknownAppUID when no resolver is
// installed, the lookup fails, or it does not answer within uidResolveTimeout.
func (e *Engine) resolveAppUID(protocol string, src, dst netip.AddrPort) int32 {
	r := e.currentUIDResolver()
	if r == nil {
		return UnknownAppUID
	}
	if !src.Addr().IsValid() || !dst.Addr().IsValid() {
		return UnknownAppUID
	}

	// Buffered so the goroutine can always finish and be collected even if we
	// stopped waiting for it.
	result := make(chan int32, 1)
	go func() {
		defer func() {
			// A panic crossing back from JNI must not take down the datapath.
			if rec := recover(); rec != nil {
				select {
				case result <- UnknownAppUID:
				default:
				}
			}
		}()
		result <- r.ResolveUID(
			protocol,
			src.Addr().Unmap().String(), int32(src.Port()),
			dst.Addr().Unmap().String(), int32(dst.Port()),
		)
	}()

	timer := time.NewTimer(uidResolveTimeout)
	defer timer.Stop()
	select {
	case uid := <-result:
		if uid < 0 {
			return UnknownAppUID
		}
		return uid
	case <-timer.C:
		return UnknownAppUID
	}
}
