package main

import (
	"testing"
	"time"
)

func admissionTestSplit(t *testing.T, v3Limit, quicLimit int) *splitUDP {
	t.Helper()
	s := &splitUDP{done: make(chan struct{}), buffers: newDemuxBufferPool(demuxDatagramMin)}
	side := func(limit int) *demuxSide {
		return &demuxSide{
			split: s, incoming: make(chan []demuxDatagram, limit),
			wake: make(chan struct{}, 1), occupied: make(chan struct{}, limit),
		}
	}
	s.v3, s.quic = side(v3Limit), side(quicLimit)
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			close(s.done)
		}
		s.v3.discard()
		s.quic.discard()
	})
	return s
}

func awaitDemuxPublish(t *testing.T, s *splitUDP, v3, quic []demuxDatagram) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() { done <- s.publish(v3, quic) }()
	select {
	case running := <-done:
		return running
	case <-time.After(3 * time.Second):
		t.Fatal("publication waited on a congested side")
		return false
	}
}

func readAdmissionPacket(t *testing.T, d *demuxSide, want byte) {
	t.Helper()
	if err := d.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, _, err := d.ReadFromUDPAddrPort(b[:]); n != 1 || err != nil || b[0] != want {
		t.Fatalf("read n=%d value=%d err=%v, want %d", n, b[0], err, want)
	}
}

func assertDemuxSuffixReleased(t *testing.T, batch []demuxDatagram) {
	t.Helper()
	for _, pkt := range batch {
		if pkt.poolBuf != nil || pkt.b != nil {
			t.Fatal("rejected packet retained producer ownership")
		}
	}
}

func TestDemuxPublishIndependentAdmissionAndResume(t *testing.T) {
	for _, congested := range []string{"v3", "quic"} {
		t.Run(congested, func(t *testing.T) {
			s := admissionTestSplit(t, 1, 1)
			full, other := s.v3, s.quic
			if congested == "quic" {
				full, other = other, full
			}
			if n := full.enqueue(budgetTestPackets(s, 1)); n != 1 {
				t.Fatal(n)
			}
			v3, quic := budgetTestPackets(s, 1), budgetTestPackets(s, 1)
			if !awaitDemuxPublish(t, s, v3, quic) {
				t.Fatal("congestion stopped publication")
			}
			rejected := v3
			if congested == "quic" {
				rejected = quic
			}
			assertDemuxSuffixReleased(t, rejected)
			if len(full.occupied) != 1 || len(other.occupied) != 1 {
				t.Fatal("one full side prevented independent admission")
			}
			readAdmissionPacket(t, other, 0)
			readAdmissionPacket(t, full, 0)
			if !awaitDemuxPublish(t, s, budgetTestPackets(s, 1), budgetTestPackets(s, 1)) {
				t.Fatal("publication did not resume after drain")
			}
			readAdmissionPacket(t, s.v3, 0)
			readAdmissionPacket(t, s.quic, 0)
			if len(s.v3.occupied) != 0 || len(s.quic.occupied) != 0 {
				t.Fatal("draining did not return all credits")
			}
		})
	}
}

func TestDemuxPublishPrefixOwnershipAndCancellation(t *testing.T) {
	s := admissionTestSplit(t, 2, 1)
	v3, quic := budgetTestPackets(s, 3), budgetTestPackets(s, 1)
	accepted := v3[0].poolBuf
	if !awaitDemuxPublish(t, s, v3, quic) {
		t.Fatal("partial admission stopped publication")
	}
	if v3[0].poolBuf != accepted || len(s.v3.occupied) != 2 || len(s.quic.occupied) != 1 {
		t.Fatal("accepted prefix ownership or independent credits changed")
	}
	assertDemuxSuffixReleased(t, v3[2:])
	readAdmissionPacket(t, s.v3, 0)
	if len(s.v3.pending) != 1 || len(s.v3.occupied) != 1 {
		t.Fatal("pending accepted packet lost its credit")
	}
	close(s.done)
	s.v3.discard()
	s.quic.discard()
	v3, quic = budgetTestPackets(s, 1), budgetTestPackets(s, 1)
	if awaitDemuxPublish(t, s, v3, quic) {
		t.Fatal("publication continued after cancellation")
	}
	assertDemuxSuffixReleased(t, v3)
	assertDemuxSuffixReleased(t, quic)
	for _, d := range []*demuxSide{s.v3, s.quic} {
		if len(d.occupied) != 0 || len(d.pending) != 0 || len(d.incoming) != 0 {
			t.Fatal("cancelled side retained credits or packets")
		}
	}
}

func TestDemuxPublishScalarDropContinues(t *testing.T) {
	s := admissionTestSplit(t, 1, 1)
	if !awaitDemuxPublish(t, s, budgetTestPackets(s, 1), nil) {
		t.Fatal("first scalar packet was not admitted")
	}
	dropped := budgetTestPackets(s, 1)
	if !awaitDemuxPublish(t, s, dropped, nil) {
		t.Fatal("scalar congestion stopped publication")
	}
	assertDemuxSuffixReleased(t, dropped)
	if !awaitDemuxPublish(t, s, nil, budgetTestPackets(s, 1)) {
		t.Fatal("other scalar side stopped after a drop")
	}
	readAdmissionPacket(t, s.quic, 0)
	readAdmissionPacket(t, s.v3, 0)
	if !awaitDemuxPublish(t, s, budgetTestPackets(s, 1), nil) {
		t.Fatal("scalar admission did not resume")
	}
	readAdmissionPacket(t, s.v3, 0)
}
