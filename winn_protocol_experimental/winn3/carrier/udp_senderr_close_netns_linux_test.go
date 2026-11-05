//go:build linux || android

package carrier

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// TestNetnsContinuationDropsOwnershipWhenTheSocketCloses: queue more than 4096
// records so one drain schedules a continuation, hold that continuation with a
// test hook, close the socket, then release it. The continuation must drop
// ownership and return without touching the closed descriptor: no further
// records read, no failure counted (a closed socket is not a drain failure),
// no panic. A closed queue's later requests do nothing, and a new queue on a
// new socket still drains completely.
func TestNetnsContinuationDropsOwnershipWhenTheSocketCloses(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "pfifo", "limit", "5000")
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if err := gw.SetReadBuffer(64 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	raw, err := gw.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	q := newSocketErrorQueue(raw)
	generated := queueICMP(t, fdOf(t, gw), 4300)
	if generated <= 4096 {
		t.Fatalf("setup queued only %d records; need more than 4096", generated)
	}

	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hookRuns := 0
	q.testBeforeContinue = func() {
		hookRuns++
		once.Do(func() { close(reached) })
		<-release
	}

	first := q.Drain()
	select {
	case <-reached:
	case <-time.After(2 * time.Second):
		t.Fatalf("no continuation was scheduled after the first drain read %d of %d", first, generated)
	}
	if !q.Draining() {
		t.Fatal("the pending continuation does not hold ownership")
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for q.Draining() {
		if time.Now().After(deadline) {
			t.Fatal("the continuation never dropped ownership after the socket closed")
		}
		time.Sleep(time.Millisecond)
	}
	st := q.Stats()
	t.Logf("generated=%d first drain=%d hook runs=%d stats=%+v", generated, first, hookRuns, st)
	if first != 4096 || st.Drained != uint64(first) {
		t.Fatalf("records were read after the close: first drain %d, total drained %d", first, st.Drained)
	}
	if st.DrainFailures != 0 {
		t.Fatalf("closing the socket was counted as %d drain failures", st.DrainFailures)
	}
	if hookRuns != 1 {
		t.Fatalf("the continuation ran %d attempts; it must stop at the first after close", hookRuns)
	}

	// Requests on the closed queue do nothing and count nothing.
	if n := q.Drain(); n != 0 {
		t.Fatalf("a drain on the closed queue read %d", n)
	}
	if st := q.Stats(); st.DrainFailures != 0 || q.Draining() {
		t.Fatalf("a drain on the closed queue counted a failure or took ownership: %+v", st)
	}

	// A new queue on a new socket still drains every record it is given.
	gw2 := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if err := gw2.SetReadBuffer(64 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableSendErrorReporting(gw2); err != nil {
		t.Fatal(err)
	}
	q2, err := NewSocketErrorQueue(gw2)
	if err != nil {
		t.Fatal(err)
	}
	fd2 := fdOf(t, gw2)
	gen2 := queueICMP(t, fd2, 50)
	n2 := q2.Drain()
	drained2, alloc2 := waitDrained(t, q2, fd2, gen2, 3*time.Second)
	t.Logf("new queue: generated=%d first drain=%d drained=%d rmem_alloc=%d", gen2, n2, drained2, alloc2)
	if drained2 != gen2 || alloc2 != 0 || q2.Stats().DrainFailures != 0 {
		t.Fatalf("a new queue after the close drained %d of %d (rmem_alloc %d)", drained2, gen2, alloc2)
	}
}
