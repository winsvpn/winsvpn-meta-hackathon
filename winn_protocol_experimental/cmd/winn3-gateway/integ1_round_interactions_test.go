package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func integ1Isolation(t *testing.T, f *authorityFixture) {
	t.Helper()
	iso, err := newForwardIsolationWith(f.registry.prefix, netip.MustParseAddr("10.10.0.1"), fakeLister("10.10.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	f.table.isolation = iso
}

func TestInteg1IsolationPrecedesFreecapDrop(t *testing.T) {
	f := freeAuthority(t)
	integ1Isolation(t, f)
	binding, _ := f.registry.policyForPeer(f.key)
	freezeBandwidth(binding.bandwidth)
	if !binding.bandwidth.allow(freeBandwidthBurstBytes(100), false) {
		t.Fatal("could not exhaust the upload bucket")
	}
	before := len(f.writer.written)
	for i := 0; i < 3; i++ {
		if _, err := f.device.WritePacket(ipv4Packet(t, f.addr.String(), "10.10.0.3")); !errors.Is(err, errGatewayDestinationRefused) {
			t.Fatalf("isolation refusal %d: %v", i, err)
		}
	}
	if _, err := f.device.WritePacket(ipv4Packet(t, "10.10.0.80", "10.10.0.3")); !errors.Is(err, errGatewayInnerSourceMismatch) {
		t.Fatalf("source refusal: %v", err)
	}
	public := ipv4Packet(t, f.addr.String(), "8.8.8.8")
	if n, err := f.device.WritePacket(public); n != len(public) || err != nil {
		t.Fatalf("freecap drop: %d %v", n, err)
	}
	st := f.table.Stats()
	if st.IntraSubnet != 3 || st.SourceMismatch != 1 || st.FreeDroppedUp != 1 || st.WriteFailed != 0 {
		t.Fatalf("refusal ordering changed: %+v", st)
	}
	if len(f.writer.written) != before {
		t.Fatal("a refused packet reached the writer")
	}
}

type integ1QueueWriter struct{ queues *tunWriteQueues }

func (w *integ1QueueWriter) write(pkt []byte) (int, error) {
	return w.queues.submit(0, nil, pkt)
}

func (w *integ1QueueWriter) asyncWrites() bool { return true }

func (w *integ1QueueWriter) writeTracked(pending *atomic.Int64, pkt []byte) (int, error) {
	return w.queues.submit(0, pending, pkt)
}

func integ1Source(pkt []byte, addr netip.Addr) {
	src := addr.As4()
	copy(pkt[12:16], src[:])
	pkt[10], pkt[11], pkt[36], pkt[37] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], ^foldChecksum(onesSum(pkt[:20], 0)))
	pseudo := onesSum(pkt[12:20], 0) + 6 + uint32(len(pkt)-20)
	binary.BigEndian.PutUint16(pkt[36:38], ^foldChecksum(onesSum(pkt[20:], pseudo)))
}

func TestInteg1FreecapAccountsMembersBeforeGSO(t *testing.T) {
	f := freeAuthority(t)
	integ1Isolation(t, f)
	binding, _ := f.registry.policyForPeer(f.key)
	bucket := &binding.bandwidth.up
	burst := freeBandwidthBurstBytes(1)
	bucket.mu.Lock()
	bucket.rate, bucket.burst, bucket.credit, bucket.last = 125000, burst, float64(burst), time.Now().Add(time.Hour)
	bucket.mu.Unlock()
	r := &gsoRecorder{t: t, holdOnce: make(chan struct{}), entered: make(chan struct{})}
	hold := r.holdOnce
	w := newTunWriteQueues(1, 256, 1600, r.write, nil)
	w.gap = time.Hour
	w.enableGSO(r.writeGSO)
	t.Cleanup(w.close)
	f.device.shared = &integ1QueueWriter{queues: w}
	marker := gsoTestSegment(1, 1, tcpFlagACK, nil, nil)
	integ1Source(marker, f.addr)
	if _, err := f.device.WritePacket(marker); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.entered:
	case <-time.After(2 * time.Second):
		close(hold)
		t.Fatal("writer did not take the marker")
	}
	pkts := gsoTestRun(16, 1321, 700, nil)
	for _, pkt := range pkts {
		integ1Source(pkt, f.addr)
	}
	frame := buildGSO(pkts, make([]byte, vnetHdrLen+gsoMaxIPTotal))
	if len(frame)-vnetHdrLen <= burst {
		close(hold)
		t.Fatal("fixture super packet does not exceed the small-rate burst")
	}
	want := [][]byte{marker}
	credit := burst - len(marker)
	dropped := uint64(0)
	for _, pkt := range pkts {
		if len(pkt) <= credit {
			want = append(want, pkt)
			credit -= len(pkt)
		} else {
			dropped++
		}
		if _, err := f.device.WritePacket(pkt); err != nil {
			close(hold)
			t.Fatal(err)
		}
	}
	blocked := bytes.Clone(pkts[0])
	copy(blocked[16:20], []byte{10, 10, 0, 3})
	if _, err := f.device.WritePacket(blocked); !errors.Is(err, errGatewayDestinationRefused) {
		close(hold)
		t.Fatalf("blocked GSO candidate: %v", err)
	}
	close(hold)
	drained(t, &f.device.pending)
	w.close()
	if r.frames == 0 || len(r.got) != len(want) {
		t.Fatalf("coalesced frames %d, packets %d, want %d", r.frames, len(r.got), len(want))
	}
	for i := range want {
		if !bytes.Equal(r.got[i], want[i]) {
			t.Fatalf("segmented packet %d differs", i)
		}
	}
	st := f.table.Stats()
	if st.FreeDroppedUp != dropped || st.IntraSubnet != 1 || bucket.credit != float64(credit) {
		t.Fatalf("member accounting: %+v credit %v want %d", st, bucket.credit, credit)
	}
}
