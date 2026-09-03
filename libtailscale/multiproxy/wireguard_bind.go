// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// A conn.Bind that carries WireGuard's own packets through another upstream.
//
// This is what makes WireGuard chainable. Normally a WireGuard device owns a UDP
// socket and its handshakes and transport messages leave from the device;
// upstreamBind replaces that socket with one connected UDP flow per peer
// endpoint, dialed through whatever upstream sits above it in the chain. Point a
// WireGuard upstream's Via at a SOCKS5 proxy and its packets go out over that
// proxy's UDP ASSOCIATE - the tunnel runs inside the proxy rather than beside
// it.
//
// It is outbound-only: it dials peers, it does not accept unsolicited packets,
// which suits a client that always initiates. A roaming peer whose source
// address changes is still handled, because replies arrive on the flow they were
// sent on rather than being matched by source address.

// wgBindRecvQueue bounds how many received packets may wait for the device to
// collect them. WireGuard tolerates loss - it is UDP underneath - so dropping
// under a burst is better than growing without limit.
const wgBindRecvQueue = 128

var errBindClosed = net.ErrClosed

type wgReceived struct {
	data []byte
	ep   conn.Endpoint
}

// wgRecvBufPool recycles the per-packet buffers readLoop allocates to detach
// a received packet from its reused read buffer before queuing it for
// receive() - across every WireGuard upstream, not scoped per-bind, since
// buffers of this exact size are interchangeable and a pool only pays off
// with shared reuse.
var wgRecvBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, device.MaxMessageSize)
		return &b
	},
}

// bindChannels bundles the two channels a bind's open period owns. Set once
// by Open, replaced with nil by Close, and otherwise never mutated - stored
// behind an atomic.Pointer so receive() (called once per packet) and
// readLoop's startup can read it without contending with connFor/Send's
// b.mu, which guards the separately-changing conns map instead.
type bindChannels struct {
	recv chan wgReceived
	done chan struct{}
}

type upstreamBind struct {
	dial UpstreamDialer

	chans atomic.Pointer[bindChannels]

	mu     sync.Mutex
	closed bool
	// conns is one connected UDP flow per peer endpoint, dialed on first send.
	conns map[netip.AddrPort]net.Conn
	// open guards against Open being called twice without a Close between.
	open bool

	readers sync.WaitGroup
}

func newUpstreamBind(dial UpstreamDialer) *upstreamBind {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	return &upstreamBind{dial: dial}
}

func (b *upstreamBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, errors.New("wireguard: bind already open")
	}
	b.closed = false
	b.open = true
	b.conns = make(map[netip.AddrPort]net.Conn)
	b.chans.Store(&bindChannels{
		recv: make(chan wgReceived, wgBindRecvQueue),
		done: make(chan struct{}),
	})

	// The reported port is meaningless here: there is no listening socket, only
	// outbound flows through the upstream. Echoing the requested port keeps the
	// device's own bookkeeping consistent.
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *upstreamBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	ch := b.chans.Load()
	if ch == nil {
		return 0, errBindClosed
	}

	select {
	case <-ch.done:
		return 0, errBindClosed
	case pkt, ok := <-ch.recv:
		if !ok {
			return 0, errBindClosed
		}
		n := copy(packets[0], pkt.data)
		sizes[0] = n
		eps[0] = pkt.ep
		// pkt.data is readLoop's own read buffer, handed off wholesale rather
		// than copied into (see readLoop) - now that its contents are copied
		// out above, return it to the pool at full capacity for reuse.
		full := pkt.data[:cap(pkt.data)]
		wgRecvBufPool.Put(&full)
		return 1, nil
	}
}

func (b *upstreamBind) Close() error {
	b.mu.Lock()
	if b.closed || !b.open {
		b.closed = true
		b.open = false
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.open = false
	ch := b.chans.Load()
	b.chans.Store(nil)
	close(ch.done)
	conns := b.conns
	b.conns = nil
	b.mu.Unlock()

	for _, c := range conns {
		_ = c.Close()
	}
	b.readers.Wait()
	return nil
}

// SetMark is a no-op: the socket belongs to the upstream, not to us, so there is
// nothing here to mark.
func (b *upstreamBind) SetMark(uint32) error { return nil }

// BatchSize is 1. Batching exists to amortise syscalls on a real UDP socket; the
// upstream conns here are already an abstraction over something else, and a
// SOCKS5 UDP association in particular has no batch form.
func (b *upstreamBind) BatchSize() int { return 1 }

func (b *upstreamBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("wireguard: bad peer endpoint %q: %w", s, err)
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *upstreamBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	dst := netip.AddrPortFrom(ep.DstIP(), 0)
	if se, ok := ep.(*conn.StdNetEndpoint); ok {
		dst = se.AddrPort
	}
	if !dst.IsValid() || dst.Port() == 0 {
		return fmt.Errorf("wireguard: peer endpoint %q has no usable address", ep.DstToString())
	}

	c, err := b.connFor(dst)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if offset >= len(buf) {
			continue
		}
		if _, err := c.Write(buf[offset:]); err != nil {
			// Drop the flow so the next send redials. A proxy that restarted, or
			// an association that timed out, recovers on the following handshake
			// retry rather than staying wedged.
			b.dropConn(dst, c)
			return err
		}
	}
	return nil
}

// connFor returns the flow to dst, dialing one through the upstream on first
// use.
func (b *upstreamBind) connFor(dst netip.AddrPort) (net.Conn, error) {
	b.mu.Lock()
	if b.closed || !b.open {
		b.mu.Unlock()
		return nil, errBindClosed
	}
	if c, ok := b.conns[dst]; ok {
		b.mu.Unlock()
		return c, nil
	}
	dial := b.dial
	b.mu.Unlock()

	ch := b.chans.Load()
	if ch == nil {
		return nil, errBindClosed
	}

	// Dialed outside the lock: reaching the upstream can mean a SOCKS5 handshake
	// or a chain of them, and holding the bind lock through that would stall
	// every other peer.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-ch.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	c, err := dial(ctx, "udp", dst.String())
	cancel()
	if err != nil {
		return nil, fmt.Errorf("wireguard: dialing peer %s through upstream: %w", dst, err)
	}

	b.mu.Lock()
	if b.closed || !b.open {
		b.mu.Unlock()
		_ = c.Close()
		return nil, errBindClosed
	}
	// Another Send may have raced us to this peer; keep whichever landed first
	// so there is exactly one reader per flow.
	if existing, ok := b.conns[dst]; ok {
		b.mu.Unlock()
		_ = c.Close()
		return existing, nil
	}
	b.conns[dst] = c
	b.readers.Add(1)
	b.mu.Unlock()

	go b.readLoop(dst, c, ch.recv, ch.done)
	return c, nil
}

func (b *upstreamBind) dropConn(dst netip.AddrPort, c net.Conn) {
	b.mu.Lock()
	if cur, ok := b.conns[dst]; ok && cur == c {
		delete(b.conns, dst)
	}
	b.mu.Unlock()
	_ = c.Close()
}

// readLoop feeds packets arriving on one peer flow to the device. recv/done
// are the channel pair live for this readLoop's entire lifetime (a bind's
// Close always waits out every readLoop via b.readers before a subsequent
// Open can create a new pair), passed in once rather than re-read from
// b.chans on every packet.
func (b *upstreamBind) readLoop(dst netip.AddrPort, c net.Conn, recv chan wgReceived, done chan struct{}) {
	defer b.readers.Done()

	ep := &conn.StdNetEndpoint{AddrPort: dst}
	bufp := wgRecvBufPool.Get().(*[]byte)
	buf := *bufp
	for {
		n, err := c.Read(buf)
		if n > 0 {
			select {
			case recv <- wgReceived{data: buf[:n], ep: ep}:
				// Ownership of buf passed to the channel (returned to the
				// pool by receive() once its contents are copied out) - get
				// a fresh one instead of reusing a buffer we no longer own.
				bufp = wgRecvBufPool.Get().(*[]byte)
				buf = *bufp
			case <-done:
				wgRecvBufPool.Put(bufp)
				return
			default:
				// Queue full. Dropping is correct: this is UDP, and WireGuard
				// retransmits what matters. buf is still ours - keep it for
				// the next read instead of returning and re-fetching it.
			}
		}
		if err != nil {
			wgRecvBufPool.Put(bufp)
			b.dropConn(dst, c)
			return
		}
	}
}
