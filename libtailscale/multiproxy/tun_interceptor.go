package multiproxy

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// vpnNICID is the single NIC every VPN gVisor stack instance uses, whether
// backed by the production fdbased endpoint or an in-memory channel.Endpoint
// in host tests.
const vpnNICID = tcpip.NICID(1)

// newVPNStack builds a gVisor stack configured for the multiproxy dataplane.
// It has no NIC attached yet; callers attach a link endpoint separately, via
// bindVPNStackLocked (production and test code share that one path).
func newVPNStack() *stack.Stack {
	return stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
}

// attachNIC wires linkEP into s as the sole NIC, puts it in promiscuous
// receive mode (so packets addressed to synthetic peers we haven't
// registered yet are still delivered to us), permanently registers the
// synthetic DNS address, and adds the synthetic /48 route. It deliberately
// does NOT enable spoofing: every other local (destination) address a flow
// needs to answer from must be registered via acquireDynamicAddr before the
// corresponding TCP/UDP endpoint is created, and released when the last
// flow using it closes. This mirrors the pinned upstream pattern in
// wgengine/netstack/netstack.go (addSubnetAddress/removeSubnetAddress).
func attachNIC(s *stack.Stack, linkEP stack.LinkEndpoint) error {
	if err := s.CreateNIC(vpnNICID, linkEP); err != nil {
		return fmt.Errorf("failed to create NIC: %v", err)
	}
	s.SetPromiscuousMode(vpnNICID, true)

	// Android's VpnService.Builder assigns SyntheticIPv6Interface (::1) as
	// the TUN's own address at the OS level (see IPNService.kt's
	// b.addAddress call). The gVisor NIC must own that same address too:
	// without spoofing, any inbound packet the kernel/other stacks address
	// to it (NDP neighbor solicitation for it, ICMPv6 destined to it, etc.)
	// has no registered endpoint to be handled against.
	ifaceAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(SyntheticIPv6Interface.AsSlice()).WithPrefix(),
		Protocol:          ipv6.ProtocolNumber,
	}
	if err := s.AddProtocolAddress(vpnNICID, ifaceAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to register synthetic interface address: %s", err)
	}

	dnsAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(SyntheticIPv6DNS.AsSlice()).WithPrefix(),
		Protocol:          ipv6.ProtocolNumber,
	}
	if err := s.AddProtocolAddress(vpnNICID, dnsAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to register synthetic DNS address: %s", err)
	}

	subnetV6, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(SyntheticIPv6Prefix.Addr().AsSlice()),
		tcpip.MaskFrom("\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	)
	if err != nil {
		return fmt.Errorf("failed to build synthetic subnet: %v", err)
	}
	s.AddRoute(tcpip.Route{
		Destination: subnetV6,
		NIC:         vpnNICID,
	})

	// Same three registrations again for the synthetic v4 pool. Without
	// these an A-record answer would resolve but never connect: the stack
	// would have no local v4 address to answer from and no route covering
	// the pool.
	ifaceAddrV4 := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(SyntheticIPv4Interface.AsSlice()).WithPrefix(),
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := s.AddProtocolAddress(vpnNICID, ifaceAddrV4, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to register synthetic v4 interface address: %s", err)
	}

	dnsAddrV4 := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(SyntheticIPv4DNS.AsSlice()).WithPrefix(),
		Protocol:          ipv4.ProtocolNumber,
	}
	if err := s.AddProtocolAddress(vpnNICID, dnsAddrV4, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to register synthetic v4 DNS address: %s", err)
	}

	subnetV4, err := tcpip.NewSubnet(
		tcpip.AddrFromSlice(SyntheticIPv4Prefix.Addr().AsSlice()),
		tcpip.MaskFrom("\xff\xfe\x00\x00"),
	)
	if err != nil {
		return fmt.Errorf("failed to build synthetic v4 subnet: %v", err)
	}
	s.AddRoute(tcpip.Route{
		Destination: subnetV4,
		NIC:         vpnNICID,
	})
	return nil
}

// countingLinkEndpoint decorates a stack.LinkEndpoint so every packet
// gVisor reads from or writes to the TUN is counted (TUN RX/TX bytes and
// packets - PHASE 4) with a single atomic add per packet/batch and no
// allocation. Every method other than WritePackets and Attach is promoted
// unchanged from the embedded real endpoint.
type countingLinkEndpoint struct {
	stack.LinkEndpoint
	dp *dataplaneCounters
}

func wrapCountingEndpoint(real stack.LinkEndpoint, dp *dataplaneCounters) stack.LinkEndpoint {
	return &countingLinkEndpoint{LinkEndpoint: real, dp: dp}
}

// WritePackets counts outbound (TUN TX) packets/bytes, then delegates
// unchanged. This is the same batch gVisor was already going to write - no
// extra syscall, no extra copy, just an atomic add per packet in the list.
func (c *countingLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for _, pkt := range pkts.AsSlice() {
		c.dp.addTx(uint64(pkt.Size()))
	}
	return c.LinkEndpoint.WritePackets(pkts)
}

// countingDispatcher decorates the NetworkDispatcher the stack attaches, so
// every inbound (TUN RX) packet is counted before being handed to gVisor's
// real dispatch - the cheapest point available, since this is called
// exactly once per packet the real endpoint already read off the fd.
type countingDispatcher struct {
	stack.NetworkDispatcher
	dp *dataplaneCounters
}

func (c *countingDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	c.dp.addRx(uint64(pkt.Size()))
	c.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

// Attach wraps dispatcher in a countingDispatcher before attaching it to the
// real endpoint, instead of counting inside the real endpoint's own read
// loop - this keeps all counting logic in this file rather than needing to
// touch gVisor's fdbased package.
func (c *countingLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		c.LinkEndpoint.Attach(nil)
		return
	}
	c.LinkEndpoint.Attach(&countingDispatcher{NetworkDispatcher: dispatcher, dp: c.dp})
}

// bindVPNStackLocked constructs the gVisor stack, attaches linkEP as its
// sole NIC, and wires the TCP/UDP forwarders into this Engine. Callers must
// hold e.vpnMu and must have already verified no VPN stack is running.
// Production code reaches this through StartVPN with a real fdbased
// endpoint; host tests call it directly with an in-memory channel.Endpoint,
// which is exactly why stack construction lives here rather than inline in
// StartVPN.
func (e *Engine) bindVPNStackLocked(linkEP stack.LinkEndpoint) error {
	s := newVPNStack()
	if err := attachNIC(s, linkEP); err != nil {
		s.Destroy()
		return err
	}

	tcpForwarder := tcp.NewForwarder(s, 0, 256, e.handleTCPConnection)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, e.handleUDPConnection)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	e.vpnStack = s
	e.addrRefCount = make(map[netip.Addr]int)
	return nil
}

// StartVPN binds the Go network stack to the Android VpnService File Descriptor.
// It explicitly takes ownership of the FD and will close it unconditionally
// when it stops using it, whether due to an immediate failure or a later StopVPN().
func (e *Engine) StartVPN(fd int32, mtu int32) error {
	fdInt := int(fd)
	mtuInt := int(mtu)

	closeFD := func() {
		syscall.Close(fdInt)
	}

	if fdInt < 0 {
		return errors.New("invalid file descriptor")
	}
	if mtuInt < 1280 || mtuInt > 65535 {
		closeFD()
		return errors.New("invalid MTU size (minimum 1280 for IPv6)")
	}

	e.vpnMu.Lock()
	defer e.vpnMu.Unlock()

	e.mu.RLock()
	if e.state != StateOpen {
		e.mu.RUnlock()
		closeFD()
		return errors.New("engine is closing or closed")
	}
	e.mu.RUnlock()

	if e.vpnStack != nil {
		closeFD()
		return errors.New("VPN already running")
	}

	log.Printf("[VPN] Initializing gVisor stack on FD: %d (MTU: %d)", fdInt, mtuInt)

	macAddr, _ := net.ParseMAC("02:00:00:00:00:00")
	linkID, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fdInt},
		MTU:            uint32(mtuInt),
		EthernetHeader: false,
		Address:        tcpip.LinkAddress(macAddr),
	})
	if err != nil {
		closeFD()
		return fmt.Errorf("failed to create fdbased endpoint: %v", err)
	}

	countedLink := wrapCountingEndpoint(linkID, &e.obs.dp)
	if err := e.bindVPNStackLocked(countedLink); err != nil {
		closeFD()
		return err
	}
	e.vpnFD = fdInt
	if e.obs.vpnStartedAt.Swap(time.Now().UnixMilli()) != 0 {
		// A prior start had already run (and been stopped) before this one -
		// this is a restart, not the first start of the engine's lifetime.
		e.AddVPNRestart()
		e.enqueueObservabilityEvent(ObsEventVPNRestarted, "", UnknownAppUID, "", "", "", "")
	}

	log.Printf("[VPN] gVisor stack successfully bound to TUN FD %d", fdInt)
	return nil
}

// StopVPN stops the gVisor VPN stack and closes the associated File Descriptor.
// Destroying the stack tears down its NIC and every endpoint spun up from
// it, which unblocks any TCP/UDP/DNS goroutines still pumping data on active
// associations so they observe an error and return.
func (e *Engine) StopVPN() {
	e.vpnMu.Lock()
	defer e.vpnMu.Unlock()

	if e.vpnStack != nil {
		e.vpnStack.Destroy()
		e.vpnStack = nil
	}
	e.addrRefCount = nil
	e.obs.vpnStartedAt.Store(0)

	if e.vpnFD >= 0 {
		syscall.Close(e.vpnFD)
		e.vpnFD = -1
	}
}

// acquireDynamicAddr registers addr on the VPN NIC the first time it's
// needed as a local (destination) address for an active flow, and
// increments its reference count. Every successful call must be paired with
// exactly one releaseDynamicAddr call, on every subsequent error/close path.
func (e *Engine) acquireDynamicAddr(addr netip.Addr) error {
	e.vpnMu.Lock()
	defer e.vpnMu.Unlock()

	s := e.vpnStack
	if s == nil || e.addrRefCount == nil {
		return errors.New("vpn stack not running")
	}

	if e.addrRefCount[addr] > 0 {
		e.addrRefCount[addr]++
		return nil
	}

	pa := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	if addr.Is4() {
		pa.Protocol = ipv4.ProtocolNumber
	} else {
		pa.Protocol = ipv6.ProtocolNumber
	}
	if err := s.AddProtocolAddress(vpnNICID, pa, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("failed to register dynamic address %s: %s", addr, err)
	}
	e.addrRefCount[addr] = 1
	return nil
}

// releaseDynamicAddr decrements addr's reference count and, once no active
// flow needs it any more, removes it from the VPN NIC. It is a no-op if the
// VPN stack has already been torn down (StopVPN removes the NIC wholesale).
func (e *Engine) releaseDynamicAddr(addr netip.Addr) {
	e.vpnMu.Lock()
	defer e.vpnMu.Unlock()

	if e.addrRefCount == nil {
		return
	}
	n, ok := e.addrRefCount[addr]
	if !ok {
		return
	}
	if n > 1 {
		e.addrRefCount[addr] = n - 1
		return
	}
	delete(e.addrRefCount, addr)
	if e.vpnStack != nil {
		e.vpnStack.RemoveAddress(vpnNICID, tcpip.AddrFromSlice(addr.AsSlice()))
	}
}

// recoverAndLog runs as a deferred call in every TCP/UDP/DNS goroutine. It
// recovers any panic and logs a bounded diagnostic (the panic value and a
// truncated stack trace, never packet contents) instead of letting the
// panic take down the whole process.
func recoverAndLog(label string) {
	if r := recover(); r != nil {
		trace := debug.Stack()
		if len(trace) > 4096 {
			trace = trace[:4096]
		}
		log.Printf("[VPN] recovered panic in %s: %v\n%s", label, r, trace)
	}
}
