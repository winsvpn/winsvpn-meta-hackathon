package session

import (
	"encoding/binary"
	"math/rand/v2"
	"runtime"
	"testing"
)

// flowPacket builds an IPv4 TCP packet of size bytes for flow f carrying seq.
// Source port is 40000+f so the packet hashes as its own inner flow, and the
// flow id and sequence ride at fixed offsets after the 40-byte headers.
func flowPacket(f int, seq uint32, size int) []byte {
	if size < 48 {
		size = 48
	}
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8] = 64
	p[9] = 6
	copy(p[12:16], []byte{10, 64, 0, 2})
	copy(p[16:20], []byte{104, 16, 0, 1})
	binary.BigEndian.PutUint16(p[20:22], uint16(40000+f))
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint32(p[40:44], uint32(f))
	binary.BigEndian.PutUint32(p[44:48], seq)
	return p
}

func flowOf(p []byte) (int, uint32) {
	return int(binary.BigEndian.Uint32(p[40:44])), binary.BigEndian.Uint32(p[44:48])
}

// moveDirection enqueues total packets over flows on tx, then drains them
// through PollBatchInto with random window sizes, splits the sealed output
// into random "sendmmsg" prefixes, and delivers through DeliverBatch with
// random batch sizes. It returns every inner packet rx produced, in order.
func moveDirection(t *testing.T, tx, rx *Driver, flows, total int, rng *rand.Rand) [][]byte {
	t.Helper()
	next := make([]uint32, flows)
	queued := 0
	var wire [][]byte
	var got [][]byte
	budget := tx.cfg.maxPayload() - frameHeaderSize
	deliver := func(final bool) {
		for len(wire) > 0 {
			k := 1 + rng.IntN(min(len(wire), MaxBatchSize))
			if !final && rng.IntN(3) == 0 {
				return // leave a suffix on the "wire" for a later call
			}
			in := stage5Input(wire[:k]...)
			off := 0
			for off < len(in) {
				n, err := rx.DeliverBatch(in[off:])
				if err != nil {
					t.Fatalf("deliver: %v", err)
				}
				if n == 0 {
					t.Fatal("deliver made no progress")
				}
				for i := off; i < off+n; i++ {
					for _, p := range in[i].Packets {
						got = append(got, append([]byte(nil), p...))
					}
				}
				off += n
			}
			wire = wire[k:]
		}
	}
	for queued < total || tx.HasPendingWork() {
		// Offer a random burst, as the tun pump and the gateway dispatch do.
		burst := rng.IntN(300)
		for i := 0; i < burst && queued < total; i++ {
			f := rng.IntN(flows)
			size := 48 + rng.IntN(budget-48)
			if rng.IntN(4) == 0 {
				size = 52 // ACK-sized, packs several to a message
			}
			if err := tx.Enqueue(flowPacket(f, next[f], size)); err != nil {
				break // full: the next poll drains it
			}
			next[f]++
			queued++
		}
		window := 1 + rng.IntN(MaxBatchSize)
		out := stage5Output(tx, window)
		n, err := tx.PollBatchInto(out)
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		for i := 0; i < n; i++ {
			wire = append(wire, append([]byte(nil), out[i]...))
		}
		deliver(false)
	}
	deliver(true)
	return got
}

// assertPerFlowOrder requires every flow's sequence numbers to rise strictly
// (no reordering, no duplicate) and the packets missing to be exactly the
// ones the sender's queue discarded on purpose.
func assertPerFlowOrder(t *testing.T, got [][]byte, flows, total int, discarded uint64) {
	t.Helper()
	if uint64(len(got))+discarded != uint64(total) {
		t.Fatalf("delivered %d inner packets and discarded %d, offered %d", len(got), discarded, total)
	}
	next := make([]uint32, flows)
	for i, p := range got {
		f, seq := flowOf(p)
		if f < 0 || f >= flows {
			t.Fatalf("packet %d: flow %d out of range", i, f)
		}
		if seq < next[f] {
			t.Fatalf("packet %d: flow %d delivered seq %d after %d (reordered or duplicated)", i, f, seq, next[f]-1)
		}
		next[f] = seq + 1
	}
}

// TestPerFlowOrderSurvivesParallelCryptoAndBatchingBothWays drives both
// directions through the batch seal path (parallel ChaCha20-Poly1305 workers,
// 32-slot windows, multi-packet messages) and the batch open path (parallel
// speculative opens, in-order commits) at GOMAXPROCS 8, with random window,
// send-prefix and receive-batch sizes. It is the attempt to reproduce inner
// reordering inside the session layer under load: every flow must arrive in
// exactly the order it was offered, with nothing lost or duplicated, and the
// receive counters must see neither reordering nor loss.
func TestPerFlowOrderSurvivesParallelCryptoAndBatchingBothWays(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(8))
	for _, seed := range []uint64{1, 2, 3, 4} {
		p := stage5Pair(t)
		rng := rand.New(rand.NewPCG(seed, 0x5eed))
		const flows, total = 32, 20000
		up := moveDirection(t, p.cli, p.gw, flows, total, rng)
		assertPerFlowOrder(t, up, flows, total, 0)
		down := moveDirection(t, p.gw, p.cli, flows, total, rng)
		assertPerFlowOrder(t, down, flows, total, 0)
		if p.cli.batch == nil || p.gw.batch == nil {
			t.Fatal("the batch crypto pool was not exercised")
		}
		for name, st := range map[string]Stats{"gateway": p.gw.Stats(), "client": p.cli.Stats()} {
			if st.OuterReordered != 0 || st.OuterLost != 0 {
				t.Fatalf("%s counted reordered %d lost %d on an in-order lossless wire",
					name, st.OuterReordered, st.OuterLost)
			}
		}
	}
}

// sealFour seals four full-size messages of flow 0, sequences 0 to 3.
func sealFour(t *testing.T, p *pair) [][]byte {
	t.Helper()
	budget := p.cli.cfg.maxPayload() - frameHeaderSize
	for i := 0; i < 4; i++ {
		if err := p.cli.Enqueue(flowPacket(0, uint32(i), budget)); err != nil {
			t.Fatal(err)
		}
	}
	out := stage5Output(p.cli, 4)
	n, err := p.cli.PollBatchInto(out)
	if err != nil || n != 4 {
		t.Fatalf("poll %d: %v", n, err)
	}
	return out
}

func innerSeqs(in []ReceiveSlot) []uint32 {
	var seqs []uint32
	for i := range in {
		for _, pkt := range in[i].Packets {
			_, s := flowOf(pkt)
			seqs = append(seqs, s)
		}
	}
	return seqs
}

// TestOuterReorderingPassesStraightThroughToInnerOrder documents the other
// half of the property: the session has no reorder buffer. Any reordering of
// the outer datagrams on the wire is delivered to the inner flow one for one,
// inside the token window, and the receiver counts it as reordering, not loss.
func TestOuterReorderingPassesStraightThroughToInnerOrder(t *testing.T) {
	p := stage5Pair(t)
	out := sealFour(t, p)
	out[1], out[2] = out[2], out[1]
	in := stage5Input(out...)
	if n, err := p.gw.DeliverBatch(in); err != nil || n != 4 {
		t.Fatalf("deliver %d: %v", n, err)
	}
	seqs := innerSeqs(in)
	if len(seqs) != 4 || seqs[0] != 0 || seqs[1] != 2 || seqs[2] != 1 || seqs[3] != 3 {
		t.Fatalf("inner order %v, want the outer order [0 2 1 3]", seqs)
	}
	if st := p.gw.Stats(); st.OuterReordered != 1 || st.OuterLost != 0 {
		t.Fatalf("OuterReordered %d OuterLost %d, want 1 and 0: one late message, nothing missing",
			st.OuterReordered, st.OuterLost)
	}
}

// TestOuterLossIsCountedApartFromReordering: a message that never arrives is
// one loss and no reordering, whether it was dropped on the wire or in a
// receive queue before it was opened.
func TestOuterLossIsCountedApartFromReordering(t *testing.T) {
	p := stage5Pair(t)
	out := sealFour(t, p)
	in := stage5Input(out[0], out[2], out[3])
	if n, err := p.gw.DeliverBatch(in); err != nil || n != 3 {
		t.Fatalf("deliver %d: %v", n, err)
	}
	if seqs := innerSeqs(in); len(seqs) != 3 || seqs[0] != 0 || seqs[1] != 2 || seqs[2] != 3 {
		t.Fatalf("inner order %v, want [0 2 3]", seqs)
	}
	if st := p.gw.Stats(); st.OuterReordered != 0 || st.OuterLost != 1 {
		t.Fatalf("OuterReordered %d OuterLost %d, want 0 and 1", st.OuterReordered, st.OuterLost)
	}
}
