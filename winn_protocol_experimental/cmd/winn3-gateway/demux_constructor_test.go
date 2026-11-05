package main

import "testing"

func TestDemuxConstructorPacketCapacity(t *testing.T) {
	if demuxChanDepth != 4096 {
		t.Fatalf("production packet capacity=%d, want 4096", demuxChanDepth)
	}
	s := &splitUDP{done: make(chan struct{})}
	d := newDemuxSide(s)
	if got := cap(d.occupied); got != demuxChanDepth {
		t.Fatalf("occupied capacity=%d, want %d", got, demuxChanDepth)
	}
	if got := cap(d.incoming); got != demuxChanDepth {
		t.Fatalf("incoming capacity=%d, want %d", got, demuxChanDepth)
	}
	if len(d.occupied) != 0 || len(d.incoming) != 0 {
		t.Fatal("new demux side must have no occupied credits or queued packets")
	}
}
