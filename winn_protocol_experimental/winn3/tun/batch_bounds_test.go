package tun

import (
	"context"
	"errors"
	"testing"
)

// overlongBatchDevice returns one batch whose lengths slice is longer than the
// buffers it was handed, then ends the pump.
type overlongBatchDevice struct {
	*fakeDevice
	extra int
	done  bool
	pkt   []byte
}

func (d *overlongBatchDevice) ReadBatch(bufs [][]byte) ([]int, error) {
	if d.done {
		return nil, errNoMoreReads
	}
	d.done = true
	lens := make([]int, len(bufs)+d.extra)
	for i := range lens {
		lens[i] = len(d.pkt)
		if i < len(bufs) {
			copy(bufs[i], d.pkt)
		}
	}
	return lens, nil
}

// countingBatchSink accepts every packet.
type countingBatchSink struct {
	*fakeSink
	accepted int
}

func (s *countingBatchSink) SendDataBatch(pkts [][]byte) (int, error) {
	s.accepted += len(pkts)
	return len(pkts), nil
}

// Gemini L06 F-5 (bounds part): a BatchDevice that reports more slots than it
// was given buffers is a device bug, which the scalar pump already counts
// rather than trusts; the batch pump indexed bufs[i] past its end and
// panicked, killing the process.
func TestPumpOutboundBatchCountsOverlongLengths(t *testing.T) {
	pkt := goodV4(64)
	dev := &overlongBatchDevice{fakeDevice: &fakeDevice{mtu: fixtureInnerMTU}, extra: 4, pkt: pkt}
	sink := &countingBatchSink{fakeSink: &fakeSink{}}
	f := newFixture(t, func(c *Config) {
		c.Device = dev
		c.Sink = sink
	}).carrying()

	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PumpOutbound panicked on a lengths slice longer than its buffers: %v", r)
			}
		}()
		err = f.tun.PumpOutbound(context.Background())
	}()
	if !errors.Is(err, errNoMoreReads) {
		t.Fatalf("PumpOutbound returned %v, want the device's end-of-reads", err)
	}
	st := f.tun.Stats()
	if sink.accepted != 256 || st.TxPackets != 256 {
		t.Fatalf("sink accepted %d, TxPackets %d; want the 256 real slots", sink.accepted, st.TxPackets)
	}
	if st.TxDroppedInvalid != 4 || st.TxDropMalformed != 4 {
		t.Fatalf("TxDroppedInvalid %d TxDropMalformed %d, want 4 and 4", st.TxDroppedInvalid, st.TxDropMalformed)
	}
}
