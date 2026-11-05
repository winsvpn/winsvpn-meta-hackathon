package main

import (
	"bytes"
	"testing"
	"time"
)

func TestDemuxReceiveSizingUsesValidatedMessageCeiling(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pathMTU int
		want    int
	}{
		{"default", 1450, 4096},
		{"larger", 8192, 8144},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sizing, _, err := buildServeSizing(serveOptions{pathMTU: tc.pathMTU, plan: "udp"})
			if err != nil {
				t.Fatal(err)
			}
			pool := newDemuxBufferPool(sizing.MessageSize)
			if pool.size != tc.want {
				t.Fatalf("receive capacity=%d, want %d", pool.size, tc.want)
			}
			bp := pool.Get().(*[]byte)
			defer pool.Put(bp)
			if len(*bp) != tc.want || cap(*bp) != tc.want {
				t.Fatalf("buffer len=%d cap=%d, want %d", len(*bp), cap(*bp), tc.want)
			}
		})
	}
	for _, size := range []int{4096, 65535} {
		if got := newDemuxBufferPool(size).size; got != size {
			t.Fatalf("capacity=%d, want %d", got, size)
		}
	}
}

func TestDemuxReceivePoolsPreserveOwnershipAndLargeCopy(t *testing.T) {
	for _, messageSize := range []int{1402, 8144} {
		s := admissionTestSplit(t, 2, 1)
		s.buffers = newDemuxBufferPool(messageSize)
		v3, quic := budgetTestPackets(s, 3), budgetTestPackets(s, 1)
		want := bytes.Repeat([]byte{0x42}, s.buffers.size)
		copy(*v3[0].poolBuf, want)
		v3[0].b = *v3[0].poolBuf
		if !s.publish(v3, quic) {
			t.Fatal("ordinary publication stopped")
		}
		assertDemuxSuffixReleased(t, v3[2:])
		if err := s.v3.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if n, _, err := s.v3.ReadFromUDPAddrPort(got); err != nil || n != len(want) || !bytes.Equal(got, want) {
			t.Fatalf("read n=%d err=%v, want complete %d-byte buffer", n, err, len(want))
		}
		close(s.done)
		s.v3.discard()
		s.quic.discard()
		if len(s.v3.occupied) != 0 || len(s.quic.occupied) != 0 {
			t.Fatal("cancellation retained packet credits")
		}
		// Returned buffers and fresh allocations must obey this split's size.
		for i := 0; i < 4; i++ {
			bp := s.buffers.Get().(*[]byte)
			if len(*bp) != s.buffers.size || cap(*bp) != s.buffers.size {
				t.Fatal("receive buffer crossed split size boundaries")
			}
			s.buffers.Put(bp)
		}
	}
}
