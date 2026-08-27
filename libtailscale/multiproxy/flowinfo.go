package multiproxy

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// flowFromEndpointID builds the policy input for a gVisor forwarder request.
//
// gVisor names the two ends from the stack's point of view, which is the reverse
// of the app's: LocalAddress/LocalPort is where the app is dialing *to*, and
// RemoteAddress/RemotePort is the app's own source. Getting these the wrong way
// round would attribute the flow to the wrong socket and silently match the
// wrong rules, so the mapping is done here once rather than at each call site.
//
// The app UID is resolved here too, which is a blocking call bounded by
// uidResolveTimeout. It happens once per new flow, not per packet.
func (e *Engine) flowFromEndpointID(protocol string, id stack.TransportEndpointID) FlowInfo {
	dst := addrPortFrom(id.LocalAddress, id.LocalPort)
	src := addrPortFrom(id.RemoteAddress, id.RemotePort)

	f := FlowInfo{
		Protocol: protocol,
		Src:      src,
		Dst:      dst,
		AppUID:   UnknownAppUID,
	}
	// Skip the lookup entirely when no rule could use it. Attribution crosses
	// JNI, so not paying for it when the policy has no UID-scoped rule keeps the
	// common case free.
	if e.policyUsesAppUID() {
		f.AppUID = e.resolveAppUID(protocol, src, dst)
	}
	return f
}

func addrPortFrom(a tcpip.Address, port uint16) netip.AddrPort {
	addr, ok := netip.AddrFromSlice(a.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), port)
}

// policyUsesAppUID reports whether any rule is UID-scoped.
func (e *Engine) policyUsesAppUID() bool {
	if e.policy == nil {
		return false
	}
	for _, r := range e.policy.Get().Rules {
		if len(r.Selector.AppUIDs) > 0 {
			return true
		}
	}
	return false
}
