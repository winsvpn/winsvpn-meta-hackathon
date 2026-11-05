//go:build linux || android

package carrier

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestNetnsTransmitRefusedCountsQdiscVerdicts: every refusal the carrier
// reports is one the qdisc counted, and the counter moves.
func TestNetnsTransmitRefusedCountsQdiscVerdicts(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "fq", "flow_limit", "8", "maxrate", "8mbit")
	rx := l4UDP(t, "l4c", l4ClientB)
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	raw, err := NewRawBatchConn(gw)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.WriteBatchTo(seqMsgs(999999, 1, 16), l4ClientB)
	readSeqs(t, rx, 300*time.Millisecond)
	plimit0 := l4QdiscStat(t, "flows_plimit")
	collect := collectSeqs(rx, 300*time.Millisecond)
	refusals := retainAndResend(t, raw, seqMsgs(0, 256, 1000), l4ClientB)
	got := collect()
	drops := l4QdiscStat(t, "flows_plimit") - plimit0
	st := raw.ErrorQueue().Stats()
	t.Logf("refusals=%d TransmitRefused=%d fq_flows_plimit=%d delivered=%d stats=%+v", refusals, st.TransmitRefused, drops, len(got), st)
	if st.TransmitRefused == 0 || st.TransmitRefused > drops || uint64(refusals) != st.TransmitRefused {
		t.Fatalf("TransmitRefused=%d, refusals seen by the caller=%d, qdisc drops=%d", st.TransmitRefused, refusals, drops)
	}
	if len(got) != 256 {
		t.Fatalf("delivered %d of 256", len(got))
	}
	if st.MatchingErrorRetries != 0 || st.Drained != 0 {
		t.Fatalf("a qdisc drop put something on the error queue or sk_err: %+v", st)
	}
}

// TestNetnsOneDrainEmptiesAFiniteBacklog is the verdict's finite-backlog
// counterexample on a real kernel: queue more than 1024 ICMP error records with
// a pending sk_err, then one Drain must clear them (via bounded continuation
// rounds) and a following send to a healthy peer must carry no leftover error.
// l4ClosedClientPort is a client-side port nothing binds, so a datagram to it
// draws an ICMP port unreachable from the client host. ICMP is unthrottled in
// the l4 netns (icmp_ratelimit=0), so a finite backlog can be queued.
var l4ClosedClientPort = netip.MustParseAddrPort("10.44.2.3:5999")

func TestNetnsOneDrainEmptiesAFiniteBacklog(t *testing.T) {
	requireL4Netns(t)
	l4Qdisc(t, "pfifo", "limit", "2000")
	// A bound receiver so a "healthy" send draws no ICMP of its own.
	healthy := l4UDP(t, "l4c", l4ClientB)
	_ = healthy
	gw := l4UDP(t, "l4g", netip.AddrPortFrom(l4Gateway, 0))
	if err := gw.SetReadBuffer(16 << 20); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableSendErrorReporting(gw); err != nil {
		t.Fatal(err)
	}
	q, err := NewSocketErrorQueue(gw)
	if err != nil {
		t.Fatal(err)
	}
	fd := fdOf(t, gw)
	sa := &unix.SockaddrInet4{Port: int(l4ClosedClientPort.Port()), Addr: l4ClosedClientPort.Addr().As4()}
	const want = 1100
	queued := 0
	for i := 0; i < want*4 && queued < want; i++ {
		if err := unix.Sendto(fd, []byte("x"), unix.MSG_DONTWAIT, sa); err == nil {
			queued++
		}
		time.Sleep(150 * time.Microsecond)
	}
	// Let the last ICMP replies land.
	time.Sleep(100 * time.Millisecond)
	n := q.Drain()
	st := q.Stats()
	t.Logf("queued~%d drained=%d stats=%+v", queued, n, st)
	if n <= 1024 {
		t.Fatalf("one Drain read %d records; >1024 must clear in a single call via continuation", n)
	}
	if st.DrainLimitHit < 4 {
		t.Fatalf("expected several full bounded rounds for >1024 records: %+v", st)
	}
	if st.DrainFailures != 0 {
		t.Fatalf("a clean drain recorded failures: %+v", st)
	}
	// No unrelated error may reach the next caller: a send to the BOUND healthy
	// peer must not carry a leftover error from the drained backlog.
	dst := &unix.SockaddrInet4{Port: int(l4ClientB.Port()), Addr: l4ClientB.Addr().As4()}
	if err := unix.Sendto(fd, []byte("clean"), unix.MSG_DONTWAIT, dst); err != nil {
		t.Fatalf("a send to a healthy peer after the drain returned %v; an unrelated error reached the caller", err)
	}
	// And a final drain returns nothing new attributable to the backlog.
	if extra := q.Drain(); extra > 2 {
		t.Fatalf("the backlog was not emptied: a later drain still read %d records", extra)
	}
}
