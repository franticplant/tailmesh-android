package multiproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// A gVisor-backed tun.Device for the WireGuard upstream.
//
// wireguard-go ships tun/netstack, which does exactly this, but it is written
// against an older gVisor than this project resolves: it calls
// (*stack.PacketBuffer).IsNil, which no longer exists. Rather than pin the whole
// build back to that gVisor, or vendor a 400-line file for the one call, this is
// a purpose-built equivalent. It is also considerably smaller, because the
// upstream only ever needs to dial - none of tun/netstack's listeners, ICMP
// ping support or resolver are used.

const wgTUNQueueDepth = 512

type wgNetTun struct {
	ep    *channel.Endpoint
	stack *stack.Stack
	mtu   int

	// incoming carries packets the stack wants to send out through WireGuard.
	incoming chan *buffer.View
	events   chan tun.Event

	closeOnce sync.Once
	closed    chan struct{}
}

// WriteNotify is called by the channel endpoint when the stack has queued a
// packet to leave through the tunnel.
func (t *wgNetTun) WriteNotify() {
	pkt := t.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()

	select {
	case t.incoming <- view:
	case <-t.closed:
	}
}

// newWireGuardNetTun builds a netstack whose only link is a channel endpoint,
// and presents that endpoint as a tun.Device for wireguard-go to drive.
func newWireGuardNetTun(localAddrs []netip.Addr, mtu int) (*wgNetTun, *stack.Stack, error) {
	if len(localAddrs) == 0 {
		return nil, nil, errors.New("wireguard: no tunnel addresses")
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	ep := channel.New(wgTUNQueueDepth, uint32(mtu), "")
	t := &wgNetTun{
		ep:       ep,
		stack:    s,
		mtu:      mtu,
		incoming: make(chan *buffer.View, wgTUNQueueDepth),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
	ep.AddNotify(t)

	const nicID = tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, nil, fmt.Errorf("wireguard: creating NIC: %v", err)
	}

	var haveV4, haveV6 bool
	for _, addr := range localAddrs {
		addr = addr.Unmap()
		var proto tcpip.NetworkProtocolNumber
		if addr.Is4() {
			proto = ipv4.ProtocolNumber
			haveV4 = true
		} else {
			proto = ipv6.ProtocolNumber
			haveV6 = true
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
		}
		if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("wireguard: adding address %s: %v", addr, err)
		}
	}

	// Default routes for whichever families the tunnel has an address in. An
	// upstream carrying general traffic needs to reach anything its peer's
	// AllowedIPs permit, and WireGuard itself does the real filtering.
	var routes []tcpip.Route
	if haveV4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if haveV6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	s.SetRouteTable(routes)

	t.events <- tun.EventUp
	return t, s, nil
}

// Read hands wireguard-go the packets the stack wants to send out.
func (t *wgNetTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case view, ok := <-t.incoming:
		if !ok {
			return 0, os.ErrClosed
		}
		defer view.Release()
		n, err := view.Read(bufs[0][offset:])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	}
}

// Write injects packets received from the tunnel into the stack.
func (t *wgNetTun) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		var proto tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			proto = header.IPv4ProtocolNumber
		case header.IPv6Version:
			proto = header.IPv6ProtocolNumber
		default:
			// Not IP: drop it rather than feeding the stack something it will
			// misparse. Counting it as written keeps wireguard-go from retrying.
			written++
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		t.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
		written++
	}
	return written, nil
}

func (t *wgNetTun) MTU() (int, error)        { return t.mtu, nil }
func (t *wgNetTun) Name() (string, error)    { return "wg-multiproxy", nil }
func (t *wgNetTun) Events() <-chan tun.Event { return t.events }
func (t *wgNetTun) BatchSize() int           { return 1 }
func (t *wgNetTun) File() *os.File           { return nil }

func (t *wgNetTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.ep.Close()
		close(t.events)
	})
	return nil
}
