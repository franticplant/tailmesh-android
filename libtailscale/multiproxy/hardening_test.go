package multiproxy

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type shortWriter struct {
	buf bytes.Buffer
	max int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.buf.Write(p)
}

func TestWriteFullHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 2}
	want := []byte("abcdef")
	if err := writeFull(w, want); err != nil {
		t.Fatalf("writeFull failed: %v", err)
	}
	if got := w.buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("writeFull wrote %q, want %q", got, want)
	}
}

// Re-originating flows from a tsnet upstream makes this a NAT, so RFC 4787 REQ-5
// applies: a UDP mapping timer must be at least 2 minutes. The existing
// association tests pass the timeout in explicitly, so none of them would notice
// the shipped constant dropping back below the floor.
func TestUDPAssociationIdleTimeoutMeetsRFC4787Floor(t *testing.T) {
	const rfc4787MinimumUDPMappingTimeout = 2 * time.Minute
	if udpAssociationIdleTimeout < rfc4787MinimumUDPMappingTimeout {
		t.Fatalf("udpAssociationIdleTimeout = %v, must be >= %v (RFC 4787 REQ-5)",
			udpAssociationIdleTimeout, rfc4787MinimumUDPMappingTimeout)
	}
}

func TestRunUDPAssociationIdleTimeout(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer aPeer.Close()
	defer bPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- runUDPAssociation(a, b, 30*time.Millisecond, nil, nil, nil)
	}()

	select {
	case <-done:
		// Expected: no activity causes a deadline to expire and both pumps exit.
	case <-time.After(2 * time.Second):
		t.Fatal("UDP association did not expire after idle timeout")
	}
}

func TestRunUDPAssociationActivityRefreshesLifetime(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer aPeer.Close()
	defer bPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- runUDPAssociation(a, b, 80*time.Millisecond, nil, nil, nil)
	}()

	for i := 0; i < 3; i++ {
		if _, err := aPeer.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("write activity: %v", err)
		}
		buf := make([]byte, 1)
		if _, err := io.ReadFull(bPeer, buf); err != nil {
			t.Fatalf("read forwarded activity: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
		select {
		case err := <-done:
			t.Fatalf("association expired while active: %v", err)
		default:
		}
	}

	select {
	case <-done:
		// Expected after activity stops.
	case <-time.After(2 * time.Second):
		t.Fatal("association did not expire after activity stopped")
	}
}

func TestRunUDPAssociationCloseOneSideTerminatesBothPumps(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer bPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- runUDPAssociation(a, b, time.Second, nil, nil, nil)
	}()

	if err := aPeer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("closing one side did not terminate both UDP pumps")
	}
}

// Regression test for the stats.go pass that added byte counting to UDP
// associations (previously TCP-only). a is the app/gVisor side, b is the
// upstream side - see runUDPAssociation's doc comment for the direction
// convention this asserts.
func TestRunUDPAssociationRecordsByteCounts(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()

	stats := &UpstreamStats{}
	done := make(chan error, 1)
	go func() {
		done <- runUDPAssociation(a, b, time.Second, stats, nil, nil)
	}()

	outPayload := []byte("app-to-upstream")
	if _, err := aPeer.Write(outPayload); err != nil {
		t.Fatalf("write out: %v", err)
	}
	gotOut := make([]byte, len(outPayload))
	if _, err := io.ReadFull(bPeer, gotOut); err != nil {
		t.Fatalf("read forwarded out: %v", err)
	}

	inPayload := []byte("upstream-to-app")
	if _, err := bPeer.Write(inPayload); err != nil {
		t.Fatalf("write in: %v", err)
	}
	gotIn := make([]byte, len(inPayload))
	if _, err := io.ReadFull(aPeer, gotIn); err != nil {
		t.Fatalf("read forwarded in: %v", err)
	}

	// Wait for both pumps to fully exit (proven safe by
	// TestRunUDPAssociationCloseOneSideTerminatesBothPumps above) before
	// reading stats, so there's no race between the pump's onBytes callback
	// and this assertion.
	_ = aPeer.Close()
	_ = bPeer.Close()
	<-done

	if got := atomic.LoadUint64(&stats.bytesOut); got != uint64(len(outPayload)) {
		t.Fatalf("bytesOut = %d, want %d (app-to-upstream traffic)", got, len(outPayload))
	}
	if got := atomic.LoadUint64(&stats.bytesIn); got != uint64(len(inPayload)) {
		t.Fatalf("bytesIn = %d, want %d (upstream-to-app traffic)", got, len(inPayload))
	}
}

func TestSyntheticQualifiedNameUsesBaseHostname(t *testing.T) {
	uid := UpstreamID("profile-1")
	got := syntheticQualifiedName("Server.Example.TS.NET.", uid)
	want := "server." + getStableHash(string(uid)) + ".proxy."
	if got != want {
		t.Fatalf("syntheticQualifiedName=%q, want %q", got, want)
	}
}
