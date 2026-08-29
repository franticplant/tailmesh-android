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

// uidResolveAttemptTimeout bounds a single attribution attempt, and
// uidResolveMaxAttempts is how many attempts resolveAppUID makes before
// giving up. A UDP DNS query's own socket in particular can already be gone
// by the time a first getConnectionOwnerUid call lands (send-and-close is
// common), so one retry meaningfully cuts the false-negative rate without
// materially changing new-flow latency - worst case is
// uidResolveMaxAttempts*uidResolveAttemptTimeout, a modest increase over the
// old single 150ms budget, paid once per new flow, never per packet.
const (
	uidResolveAttemptTimeout = 90 * time.Millisecond
	uidResolveMaxAttempts    = 2
)

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
// installed, or every attempt fails or times out. It retries up to
// uidResolveMaxAttempts times - see that constant's doc comment for why a
// single attempt has a real, expected false-negative rate.
func (e *Engine) resolveAppUID(protocol string, src, dst netip.AddrPort) int32 {
	r := e.currentUIDResolver()
	if r == nil {
		return UnknownAppUID
	}
	if !src.Addr().IsValid() || !dst.Addr().IsValid() {
		return UnknownAppUID
	}

	for attempt := 0; attempt < uidResolveMaxAttempts; attempt++ {
		uid := e.resolveAppUIDOnce(r, protocol, src, dst)
		if uid == UnknownAppUID {
			continue
		}
		// A successful lookup is corroborated with one more immediate call
		// for the same 5-tuple before it's trusted. getConnectionOwnerUid
		// answers from the OS's live connection table, which can move on
		// between one lookup and the next - most commonly a short-lived UDP
		// DNS socket (the same "send-and-close" pattern the retry above
		// exists for) closing and its local port being reused by a
		// *different* app before this flow's own attribution finishes. The
		// retry loop was making that race worse, not better: the longer
		// attribution takes to succeed, the more time a reused port has had
		// to change owners, and a UID-scoped policy would then route (or,
		// for DNS, forward) this flow under the wrong app's rule - not a
		// failure, a misattribution. Two calls for the same 5-tuple agreeing
		// is a far smaller window for that than trusting one call after
		// possibly waiting through a prior failed attempt, and a mismatch is
		// treated as unknown (fails closed on a UID-scoped DNS rule, per
		// dns.go) rather than risking it. This is still once per new flow,
		// never per packet - the same cost class as the retry it replaces
		// the trust model of, not an added one.
		if confirm := e.resolveAppUIDOnce(r, protocol, src, dst); confirm == uid {
			return uid
		}
		return UnknownAppUID
	}
	return UnknownAppUID
}

// resolveAppUIDOnce makes one attribution attempt, bounded by
// uidResolveAttemptTimeout.
func (e *Engine) resolveAppUIDOnce(r UIDResolver, protocol string, src, dst netip.AddrPort) int32 {
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

	timer := time.NewTimer(uidResolveAttemptTimeout)
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
