//go:build linux || android

package carrier

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadBatchFromExhaustsItsBudgetThenReturnsTheErrno pins the receive
// helper's side of the batch pump contract: a matching errno on every attempt
// is retried AsyncErrorRetries times (each counted) and then returned, so the
// pump owns the next retry. A later receive with the fault gone reads normally.
func TestReadBatchFromExhaustsItsBudgetThenReturnsTheErrno(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	injected := 0
	raw.testRecvErrno = func() syscall.Errno {
		if injected < AsyncErrorRetries+1 {
			injected++
			return unix.ECONNREFUSED
		}
		return 0
	}
	msgs := make([]BatchMsg, 4)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 2048)
	}
	before := raw.ErrorQueue().Stats().MatchingErrorRetries
	n, err := raw.ReadBatchFrom(msgs)
	retries := raw.ErrorQueue().Stats().MatchingErrorRetries - before
	if n != 0 || !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("an exhausted receive returned (%d, %v), want (0, ECONNREFUSED)", n, err)
	}
	if injected != AsyncErrorRetries+1 || retries != AsyncErrorRetries {
		t.Fatalf("%d attempts with %d counted retries; want %d attempts, %d retries",
			injected, retries, AsyncErrorRetries+1, AsyncErrorRetries)
	}

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := peer.WriteToUDP([]byte("after"), gw.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = gw.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := raw.ReadBatchFrom(msgs); n != 1 || err != nil || string(msgs[0].Payload[:msgs[0].N]) != "after" {
		t.Fatalf("the receive after the fault returned (%d, %v)", n, err)
	}
	if got := raw.ErrorQueue().Stats().MatchingErrorRetries - before; got != AsyncErrorRetries {
		t.Fatalf("a clean receive changed the retry count to %d", got)
	}
}
