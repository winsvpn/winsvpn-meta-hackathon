package carrier

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestH2ClearDeadlineFencesStartedStaleCallback(t *testing.T) {
	connection := testH2PacketConn()
	defer connection.Close()

	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	connection.deadlineCallbackStarted = func() {
		close(started)
		<-release
	}
	connection.deadlineCallbackFinished = func() {
		close(finished)
	}

	if err := connection.SetDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("deadline callback did not start")
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("stale deadline callback did not finish")
	}
	if connection.closed.Load() {
		t.Fatal("stale deadline callback closed the H2 connection")
	}
	if connection.expired.Load() {
		t.Fatal("stale deadline callback marked the H2 connection expired")
	}
}

func TestH2ExpiredDeadlineWinsBeforeClear(t *testing.T) {
	connection := testH2PacketConn()

	if err := connection.SetDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !connection.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !connection.closed.Load() {
		t.Fatal("deadline did not close the H2 connection")
	}
	if err := connection.SetDeadline(time.Time{}); !errors.Is(
		err, os.ErrDeadlineExceeded,
	) {
		t.Fatalf("clear after expiry = %v, want deadline exceeded", err)
	}
}

func testH2PacketConn() *h2PacketConn {
	_, writer := io.Pipe()
	return &h2PacketConn{
		writer:    writer,
		reader:    io.NopCloser(bytes.NewReader(nil)),
		transport: &http.Transport{},
		local:     fixedAddr("h2-test-local"),
		remote:    fixedAddr("h2-test-remote"),
	}
}
