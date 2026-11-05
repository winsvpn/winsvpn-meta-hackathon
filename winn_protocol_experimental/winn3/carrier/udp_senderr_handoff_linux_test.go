//go:build linux || android

package carrier

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestADrainRequestInTheReleaseWindowIsServiced is the deterministic form of
// the lost-handoff race. The test hook runs in the drain owner after its last
// round read the queue EMPTY and before it releases ownership. In that window a
// new ICMP record arrives and a second caller requests a drain, which must find
// the owner busy and return. The owner must then service that request itself:
// after the outer Drain returns the record has been read and the queue is
// empty, with no further traffic and no rescue drain by the test.
func TestADrainRequestInTheReleaseWindowIsServiced(t *testing.T) {
	gw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	raw, err := gw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	q := newSocketErrorQueue(raw)
	fd := fdOf(t, gw)
	closed := closedLoopbackPort(t)
	sa := &unix.SockaddrInet4{Port: int(closed.Port()), Addr: closed.Addr().As4()}

	hookRuns, lateRequestRead := 0, -1
	q.testBeforeRelease = func() {
		hookRuns++
		if hookRuns != 1 {
			return
		}
		// A record arrives after the owner's final empty read.
		if err := unix.Sendto(fd, []byte("late"), unix.MSG_DONTWAIT, sa); err != nil {
			t.Errorf("late send: %v", err)
			return
		}
		deadline := time.Now().Add(time.Second)
		for {
			if alloc, _ := rmemAlloc(t, fd); alloc > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Error("the late ICMP record never arrived")
				return
			}
			time.Sleep(time.Millisecond)
		}
		// Its drain request, from another goroutine, finds the owner busy.
		done := make(chan int)
		go func() { done <- q.Drain() }()
		lateRequestRead = <-done
	}

	n := q.Drain()
	st := q.Stats()
	alloc, _ := rmemAlloc(t, fd)
	t.Logf("owner read %d; late request read %d; hook ran %d times; rmem_alloc=%d stats=%+v",
		n, lateRequestRead, hookRuns, alloc, st)
	if lateRequestRead != 0 || st.DrainSkipped != 1 {
		t.Fatalf("the late request did not find the owner busy (read %d, skipped %d)", lateRequestRead, st.DrainSkipped)
	}
	if n != 1 || st.Drained != 1 || st.DrainPendingServiced != 1 {
		t.Fatalf("the late request was not serviced by the owner: owner read %d, drained %d, pending serviced %d",
			n, st.Drained, st.DrainPendingServiced)
	}
	if alloc != 0 {
		t.Fatalf("a record is still queued (rmem_alloc %d) with nobody scheduled to drain it", alloc)
	}
	if q.Draining() {
		t.Fatal("ownership was not released")
	}
}
