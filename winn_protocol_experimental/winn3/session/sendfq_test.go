package session

import (
	"runtime"
	"testing"
	"time"
)

func fqPacket(src, dst byte, proto byte, size int, tag uint16) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[9] = proto
	p[12], p[13], p[14], p[15] = 10, 0, 0, src
	p[16], p[17], p[18], p[19] = 10, 0, 1, dst
	p[20], p[21] = byte(tag>>8), byte(tag)
	return p
}

// drainFQ seals everything queued, in batches as the driver Loop does (refill
// the ready window, poll up to 32), and returns the inner packets in the order
// the peer opened them.
func drainFQ(t *testing.T, p *pair) [][]byte {
	t.Helper()
	var got [][]byte
	for i := 0; i < 100000; i++ {
		p.cli.FillSendWindow()
		out := stage5Output(p.cli, 32)
		k, err := p.cli.PollBatchInto(out)
		if err != nil {
			t.Fatal(err)
		}
		if k == 0 {
			p.cli.mu.Lock()
			left := p.cli.queuedDataLen()
			p.cli.mu.Unlock()
			if left == 0 {
				return got
			}
			continue
		}
		for _, m := range out[:k] {
			pk, err := p.gw.Deliver(m)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, pk...)
		}
	}
	t.Fatal("queue never drained")
	return nil
}

// A probe queued behind 4,000 bulk packets of another host pair is sealed
// within the first ready window, not after the bulk: the property the single
// FIFO lacked on Canada (8,192 packets, 122 to 141 ms, in front of every ping).
func TestSendQueueFQServesASparseFlowAheadOfBulk(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8192
	p.cli.SetSendQueueFQ()
	for i := 0; i < 4000; i++ {
		if err := p.cli.Enqueue(fqPacket(1, 9, 6, 1200, uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.cli.Enqueue(fqPacket(2, 9, 1, 84, 0xffff)); err != nil {
		t.Fatal(err)
	}
	got := drainFQ(t, p)
	if len(got) != 4001 {
		t.Fatalf("delivered %d of 4001", len(got))
	}
	probeAt, next := -1, uint16(0)
	for i, pk := range got {
		if pk[15] == 2 {
			probeAt = i
			continue
		}
		if tag := uint16(pk[20])<<8 | uint16(pk[21]); tag != next {
			t.Fatalf("bulk packet %d arrived as %d: FQ reordered one flow", next, tag)
		}
		next++
	}
	if probeAt < 0 || probeAt > readyWindow {
		t.Fatalf("probe sealed at position %d, want within the first ready window (%d)", probeAt, readyWindow)
	}
}

// At the cap the head of the fattest bucket is dropped and the arrival is
// admitted, so a sparse flow is never refused because bulk filled the queue.
func TestSendQueueFQAdmitsAtTheCapByDroppingTheFattestHead(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8
	p.cli.SetSendQueueFQ()
	for i := 0; i < 8; i++ {
		if err := p.cli.Enqueue(fqPacket(1, 9, 6, 1200, uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.cli.Enqueue(fqPacket(2, 9, 1, 84, 0xffff)); err != nil {
		t.Fatalf("the sparse arrival at the cap was refused: %v", err)
	}
	st := p.cli.Stats()
	if st.DataQueueOverflow != 1 || st.DataQueueDepth != 8 {
		t.Fatalf("overflow %d depth %d, want 1 and 8", st.DataQueueOverflow, st.DataQueueDepth)
	}
	got := drainFQ(t, p)
	if len(got) != 8 {
		t.Fatalf("delivered %d, want 8", len(got))
	}
	if tag := uint16(got[0][20])<<8 | uint16(got[0][21]); got[0][15] == 1 && tag == 0 {
		t.Fatal("the dropped head (bulk 0) was still sealed")
	}
}

// Every packet of a host pair hashes alike: ports and IPv4 fragment fields do
// not enter the key, so a non-first fragment cannot leave its datagram's bucket.
func TestSendQueueFQKeyIgnoresPortsAndFragmentFields(t *testing.T) {
	q := newSendFQ(16, 5*time.Millisecond, 100*time.Millisecond, 7)
	a := fqPacket(1, 9, 17, 100, 1)
	b := fqPacket(1, 9, 17, 100, 2)
	b[22], b[23] = 0x99, 0x99
	frag := fqPacket(1, 9, 17, 100, 3)
	frag[6], frag[7] = 0x00, 0xb9 // offset 185, no ports in this fragment
	if q.fqKey(a) != q.fqKey(b) || q.fqKey(a) != q.fqKey(frag) {
		t.Fatal("packets of one host pair hashed to different buckets")
	}
	v6 := make([]byte, 60)
	v6[0] = 0x60
	if q.fqKey(v6) != q.fqKey(append(v6[:40:40], make([]byte, 30)...)) {
		t.Fatal("IPv6 key depends on more than the addresses")
	}
}

// A bucket whose head has stood above target for an interval is shed by its
// own CoDel, while a sparse bucket is untouched.
func TestSendQueueFQBucketCoDelShedsStandingBulkOnly(t *testing.T) {
	p := stage5Pair(t)
	p.cli.cfg.SendQueue = 8192
	p.cli.SetSendQueueFQ()
	tag := uint16(0)
	for ms := 0; ms < 400; ms++ {
		for i := 0; i < 40; i++ {
			if err := p.cli.Enqueue(fqPacket(1, 9, 6, 1200, tag)); err != nil {
				t.Fatal(err)
			}
			tag++
		}
		if ms%20 == 0 {
			if err := p.cli.Enqueue(fqPacket(2, 9, 1, 84, 0xffff)); err != nil {
				t.Fatal(err)
			}
		}
		p.clk.Advance(time.Millisecond)
		for k := 0; k < 1; k++ {
			p.cli.FillSendWindow()
			out := stage5Output(p.cli, 32)
			n, err := p.cli.PollBatchInto(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range out[:n] {
				if _, err := p.gw.Deliver(m); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if s := p.cli.Stats().DataQueueDropped; s == 0 {
		t.Fatal("a bulk bucket standing for 400 ms was never shed")
	}
}

func TestSendQueueFQPendingWorkAndTeardownAccounting(t *testing.T) {
	p := stage5Pair(t)
	p.cli.SetSendQueueFQ()
	for i := 0; i < 5; i++ {
		if err := p.cli.Enqueue(fqPacket(byte(1+i), 9, 6, 300, uint16(i))); err != nil {
			t.Fatal(err)
		}
	}
	if !p.cli.HasPendingWork() {
		t.Fatal("HasPendingWork is false while the flow queues hold data")
	}
	before := p.cli.Stats().DataFramesDropped
	p.cli.mu.Lock()
	p.cli.terminate()
	p.cli.mu.Unlock()
	if got := p.cli.Stats().DataFramesDropped - before; got != 5 {
		t.Fatalf("teardown accounted %d of 5 queued packets", got)
	}
	if p.cli.fq.total != 0 {
		t.Fatalf("teardown left %d packets in the flow queues", p.cli.fq.total)
	}
}

// SendFQBytes is what the gateway's memory budget bills for the flow queues
// (cmd/winn3-gateway billFor). Building one at the production capacity must
// stay within it, and must allocate most of it, or the bill is not measuring
// the queue.
func TestSendFQStaysWithinSendFQBytes(t *testing.T) {
	const capacity = 8192
	live := func() uint64 {
		runtime.GC()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapInuse
	}
	const k = 8
	h0 := live()
	qs := make([]*sendFQ, k)
	for i := range qs {
		qs[i] = newSendFQ(capacity, 5*time.Millisecond, 100*time.Millisecond, uint32(i))
	}
	h1 := live()
	per := (int64(h1) - int64(h0)) / k
	bill := int64(SendFQBytes(capacity))
	t.Logf("one flow queue at capacity %d holds %d B live; billed %d B", capacity, per, bill)
	if per > bill {
		t.Fatalf("a flow queue holds %d B, above its %d B bill", per, bill)
	}
	if per < bill*8/10 {
		t.Fatalf("a flow queue holds %d B, under 80%% of its %d B bill: the bill does not describe it", per, bill)
	}
	runtime.KeepAlive(qs)
}
