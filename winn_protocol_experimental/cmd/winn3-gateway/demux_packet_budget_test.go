package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

func budgetTestSide(t *testing.T, limit int) *demuxSide {
	t.Helper()
	s := &splitUDP{done: make(chan struct{}), buffers: newDemuxBufferPool(demuxDatagramMin)}
	if demuxChanDepth != 4096 {
		t.Fatal("production side must preserve the 4096-packet capacity")
	}
	d := &demuxSide{
		split: s, incoming: make(chan []demuxDatagram, limit),
		wake: make(chan struct{}, 1), occupied: make(chan struct{}, limit),
	}
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
		d.discard()
	})
	return d
}

func budgetTestPackets(s *splitUDP, n int) []demuxDatagram {
	packets := make([]demuxDatagram, n)
	for i := range packets {
		bp := s.buffers.Get().(*[]byte)
		(*bp)[0] = byte(i)
		packets[i] = demuxDatagram{b: (*bp)[:1], poolBuf: bp}
	}
	return packets
}

func awaitBudgetEnqueue(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case n := <-done:
		return n
	case <-time.After(3 * time.Second):
		t.Fatal("bounded enqueue did not finish")
		return 0
	}
}

func TestDemuxPacketBudgetIncludesPendingReads(t *testing.T) {
	d := budgetTestSide(t, 3)
	packets := budgetTestPackets(d.split, 3)
	if n := d.enqueue(packets); n != 3 {
		t.Fatalf("enqueued %d packets", n)
	}
	var b [1]byte
	for i := 0; i < 3; i++ {
		n, _, err := d.ReadFromUDPAddrPort(b[:])
		if err != nil || n != 1 || b[0] != byte(i) {
			t.Fatalf("read %d: n=%d value=%d err=%v", i, n, b[0], err)
		}
		if got := len(d.occupied); got != 2-i {
			t.Fatalf("read %d leaves %d retained packets, want %d", i, got, 2-i)
		}
		if got := len(d.pending); got != 2-i {
			t.Fatalf("read %d leaves %d pending packets", i, got)
		}
	}
}

func TestDemuxPacketBudgetPublishesPartialBatchInOrder(t *testing.T) {
	d := budgetTestSide(t, 3)
	packets := budgetTestPackets(d.split, 5)
	done := make(chan int, 1)
	go func() { done <- d.enqueue(packets) }()
	if n := awaitBudgetEnqueue(t, done); n != 3 {
		t.Fatalf("enqueued %d packets, want immediately admitted prefix of 3", n)
	}
	// The new full-queue policy returns ownership of the unadmitted suffix.
	for _, pkt := range packets[3:] {
		d.split.buffers.Put(pkt.poolBuf)
	}
	if len(d.occupied) != 3 || len(d.incoming) != 1 {
		t.Fatal("accepted prefix did not retain exactly three credits")
	}
	var b [1]byte
	for i := 0; i < 3; i++ {
		if err := d.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := d.ReadFromUDPAddrPort(b[:])
		if err != nil || n != 1 || b[0] != byte(i) {
			t.Fatalf("read %d: n=%d value=%d err=%v", i, n, b[0], err)
		}
		if got := len(d.occupied); got != 2-i {
			t.Fatalf("read %d retained %d credits", i, got)
		}
	}
	if len(d.occupied) != 0 || len(d.pending) != 0 || len(d.incoming) != 0 {
		t.Fatal("drained side retained packet ownership")
	}
}

func TestDemuxPacketBudgetCancellationDrainsPendingAndQueued(t *testing.T) {
	d := budgetTestSide(t, 3)
	if n := d.enqueue(budgetTestPackets(d.split, 2)); n != 2 {
		t.Fatal(n)
	}
	var b [1]byte
	if _, _, err := d.ReadFromUDPAddrPort(b[:]); err != nil {
		t.Fatal(err)
	}
	extra := budgetTestPackets(d.split, 3)
	done := make(chan int, 1)
	go func() { done <- d.enqueue(extra) }()
	var queued []demuxDatagram
	select {
	case queued = <-d.incoming:
		if len(queued) != 2 {
			t.Fatalf("accepted prefix=%d, want 2", len(queued))
		}
		// Put the accepted entry back so cancellation has both queue forms.
		d.incoming <- queued
	case <-time.After(3 * time.Second):
		t.Fatal("second prefix was not published")
	}
	close(d.split.done)
	d.discard()
	n := awaitBudgetEnqueue(t, done)
	if n != 2 {
		t.Fatalf("accepted %d packets, want 2", n)
	}
	for _, pkt := range extra[n:] {
		d.split.buffers.Put(pkt.poolBuf)
	}
	if len(d.occupied) != 0 || len(d.pending) != 0 || len(d.incoming) != 0 {
		t.Fatal("cancelled side retained packet ownership")
	}
	if _, _, err := d.ReadFromUDPAddrPort(b[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-cancellation read: %v", err)
	}
	single := budgetTestPackets(d.split, 1)
	if n := d.enqueue(single); n != 0 {
		t.Fatalf("accepted %d packets after cancellation", n)
	}
	d.split.buffers.Put(single[0].poolBuf)
}

func TestDemuxPacketBudgetScalarAndReadCancellation(t *testing.T) {
	d := budgetTestSide(t, 1)
	for i := 0; i < 4; i++ {
		pkt := budgetTestPackets(d.split, 1)
		if n := d.enqueue(pkt); n != 1 {
			t.Fatal(n)
		}
		var b [1]byte
		if n, _, err := d.ReadFrom(b[:]); err != nil || n != 1 {
			t.Fatalf("scalar read: n=%d err=%v", n, err)
		}
		if len(d.occupied) != 0 {
			t.Fatal("scalar read retained its credit")
		}
	}
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, _, err := d.ReadFromUDPAddrPort(b[:])
		done <- err
	}()
	close(d.split.done)
	d.discard()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not unblock the reader")
	}
}
