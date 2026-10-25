// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// roamingBind gives a WireGuard listener what a server needs and Tailscale's
// wireguard-go fork leaves out: learning each peer's address from the
// packets it sends. A peer's handshake initiation tells us its key before
// the device answers (conn.InitiationAwareEndpoint), so its endpoint is set
// in time for the response; decrypted data packets (conn.PeerAwareEndpoint)
// follow it when it moves.
type roamingBind struct {
	conn.Bind
	dev atomic.Pointer[device.Device]

	mu   sync.Mutex
	last map[[32]byte]string // the endpoint each peer was last set to
}

func newRoamingBind(inner conn.Bind) *roamingBind {
	return &roamingBind{Bind: inner, last: map[[32]byte]string{}}
}

func (b *roamingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		wrapped[i] = func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
			n, err := fn(slab, packets)
			for j := 0; j < n; j++ {
				if ep := packets[j].Endpoint; ep != nil {
					packets[j].Endpoint = &roamingEndpoint{Endpoint: ep, b: b}
				}
			}
			return n, err
		}
	}
	return wrapped, actual, nil
}

// learn points the peer with key pk at ep, if it isn't already.
func (b *roamingBind) learn(pk [32]byte, ep conn.Endpoint) {
	dst := ep.DstToString()
	b.mu.Lock()
	same := b.last[pk] == dst
	if !same {
		b.last[pk] = dst
	}
	b.mu.Unlock()
	dev := b.dev.Load()
	if same || dev == nil {
		return
	}
	_ = dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(pk[:]), dst))
}

type roamingEndpoint struct {
	conn.Endpoint
	b *roamingBind
}

func (e *roamingEndpoint) InitiationMessagePublicKey(pk [32]byte) { e.b.learn(pk, e.Endpoint) }
func (e *roamingEndpoint) FromPeer(pk [32]byte)                   { e.b.learn(pk, e.Endpoint) }
