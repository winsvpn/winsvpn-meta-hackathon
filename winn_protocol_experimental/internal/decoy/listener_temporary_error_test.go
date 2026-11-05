package decoy

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// flakyListener returns temporary accept errors (EMFILE, the error an
// exhausted descriptor table produces) before handing out connections again.
type flakyListener struct {
	net.Listener
	failures int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.failures > 0 {
		l.failures--
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	return l.Listener.Accept()
}

func TestTemporaryAcceptErrorDoesNotKillTheListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := TLSOnlyListener(&flakyListener{Listener: inner, failures: 3}, time.Second, nil)
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
		accepted <- err
	}()
	client, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{0x16}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept after a temporary error failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener stopped accepting after a temporary accept error")
	}
}

func TestFatalAcceptErrorIsReturnedOnEveryAccept(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := TLSOnlyListener(inner, time.Second, nil)
	_ = inner.Close()
	for attempt := 0; attempt < 2; attempt++ {
		done := make(chan error, 1)
		go func() { _, err := listener.Accept(); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("attempt %d: expected an error from a closed inner listener", attempt)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("attempt %d: Accept blocked after the inner listener failed", attempt)
		}
	}
}
