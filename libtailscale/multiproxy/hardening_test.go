package multiproxy

import (
	"bytes"
	"io"
	"net"
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

func TestRunUDPAssociationIdleTimeout(t *testing.T) {
	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer aPeer.Close()
	defer bPeer.Close()

	done := make(chan error, 1)
	go func() {
		done <- runUDPAssociation(a, b, 30*time.Millisecond)
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
		done <- runUDPAssociation(a, b, 80*time.Millisecond)
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
		done <- runUDPAssociation(a, b, time.Second)
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

func TestSyntheticQualifiedNameUsesBaseHostname(t *testing.T) {
	uid := UpstreamID("profile-1")
	got := syntheticQualifiedName("Server.Example.TS.NET.", uid)
	want := "server." + getStableHash(string(uid)) + ".proxy."
	if got != want {
		t.Fatalf("syntheticQualifiedName=%q, want %q", got, want)
	}
}
