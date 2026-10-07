// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package multiproxy

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"tailscale.com/tsnet"
)

// TestInboundListenerRealTsnet is the tier-2 integration test: it proves the
// tailnet accept half against real tsnet.Server nodes, not a fake acceptor.
// It is deliberately not part of the default suite - it needs a live tailnet,
// network egress, and a reusable auth key - and is gated on
// TAILMESH_INBOUND_TEST_AUTHKEY. Run with:
//
//	TAILMESH_INBOUND_TEST_AUTHKEY=<reusable tailnet auth key> \
//	  ./tool/go test -run TestInboundListenerRealTsnet -v ./libtailscale/multiproxy/
//
// Two ephemeral nodes are created from the same key (so the key must be
// reusable): node A runs an inbound listener forwarding to a local echo
// server, node B dials A's tailnet address. That is exactly the real-world
// path - external peer -> tailnet node -> local app - minus Android.
func TestInboundListenerRealTsnet(t *testing.T) {
	key := os.Getenv("TAILMESH_INBOUND_TEST_AUTHKEY")
	if key == "" {
		t.Skip("set TAILMESH_INBOUND_TEST_AUTHKEY to a reusable tailnet auth key to run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	newNode := func(name string) *tsnet.Server {
		return &tsnet.Server{
			Hostname:  name,
			AuthKey:   key,
			Dir:       t.TempDir(),
			Ephemeral: true,
			Logf:      t.Logf,
		}
	}

	serverNode := newNode("tailmesh-inbound-srv")
	defer serverNode.Close()
	if _, err := serverNode.Up(ctx); err != nil {
		t.Fatalf("server node Up: %v", err)
	}

	clientNode := newNode("tailmesh-inbound-cli")
	defer clientNode.Close()
	if _, err := clientNode.Up(ctx); err != nil {
		t.Fatalf("client node Up: %v", err)
	}

	// The local service the tailnet peer should reach.
	echo := newTCPEchoServer(t)

	// Real tsnet listener, wrapped by the same production path.
	const listenPort = 2222
	ln, err := (tsnetAcceptor{srv: serverNode}).Listen("tcp", ":"+strconv.Itoa(listenPort))
	if err != nil {
		t.Fatalf("tsnet Listen: %v", err)
	}
	l := newInboundListener(InboundListenerConfig{
		ID:          "real",
		Upstream:    "tailnet",
		ListenPort:  listenPort,
		LocalTarget: echo.String(),
	}, ln, net.Dial)
	go l.serve()
	defer l.close()

	v4, v6 := serverNode.TailscaleIPs()
	ip := v4
	if !ip.IsValid() {
		ip = v6
	}
	if !ip.IsValid() {
		t.Fatal("server node has no tailnet IP")
	}
	dst := net.JoinHostPort(ip.String(), strconv.Itoa(listenPort))

	conn, err := clientNode.Dial(ctx, "tcp", dst)
	if err != nil {
		t.Fatalf("client dial %s: %v", dst, err)
	}
	defer conn.Close()

	msg := "hello over a real tailnet"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}
