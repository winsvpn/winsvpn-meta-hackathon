package tun

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// The outbound analogue of the inbound five-way split in Inbound.
//
// TxDroppedInvalid used to be a single bucket for every validator refusal.
// That is the same shape that left the 2026-08-11 iOS carry staring at
// rx_dropped_invalid 50 with no way to tell which check fired. These tests
// pin the split: same total, attributable reason, other reasons stay zero.
//
// Four reasons, not five: ErrNotForUs and ErrReflected cannot be returned by
// validator.outbound. ErrSourceNotOurs is the outbound analogue of NotForUs.
// A test that asserted TxDropNotForUs == 0 would be a zero-clause pass.

func txReasonSum(s Stats) uint64 {
	return s.TxDropFamilyOff + s.TxDropMartian + s.TxDropSourceNotOurs + s.TxDropMalformed
}

// assertOnlyTxReason requires that exactly one outbound invalid packet was
// counted, that it is attributed to the named reason, that the per-reason
// counters sum to the total, and that the inbound invalid counters did not
// move. If the split were collapsed back to a bare TxDroppedInvalid.Add, this
// fails on `got != 1`. If a reason were miscategorised, it fails the same way.
func assertOnlyTxReason(t *testing.T, s Stats, name string, got uint64) {
	t.Helper()
	if s.TxDroppedInvalid != 1 {
		t.Fatalf("TxDroppedInvalid=%d, want 1 — the total must not change", s.TxDroppedInvalid)
	}
	if got != 1 {
		t.Fatalf("%s=%d, want 1 — the reason must be attributable", name, got)
	}
	if sum := txReasonSum(s); sum != s.TxDroppedInvalid {
		t.Fatalf("per-reason sum %d != TxDroppedInvalid %d", sum, s.TxDroppedInvalid)
	}
	if s.TxPackets != 0 {
		t.Fatalf("TxPackets=%d, want 0: a refused packet was counted as carried", s.TxPackets)
	}
	if s.RxDroppedInvalid != 0 || s.RxDropFamilyOff != 0 || s.RxDropMartian != 0 ||
		s.RxDropNotForUs != 0 || s.RxDropReflected != 0 || s.RxDropMalformed != 0 {
		t.Fatalf("an outbound drop moved an inbound counter: %+v", s)
	}
}

// TestTxDropSourceNotOursIsTheDeanonymisationRefusal is the load-bearing
// outbound reason: a packet whose source this session was never assigned.
func TestTxDropSourceNotOursIsTheDeanonymisationRefusal(t *testing.T) {
	f := newFixture(t).carrying()
	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("foreign source: %v, want ErrSourceNotOurs", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropSourceNotOurs", st.TxDropSourceNotOurs)
	if st.TxDropFamilyOff != 0 || st.TxDropMartian != 0 || st.TxDropMalformed != 0 {
		t.Fatalf("foreign source was miscategorised: familyOff=%d martian=%d malformed=%d",
			st.TxDropFamilyOff, st.TxDropMartian, st.TxDropMalformed)
	}
	f.quiet("foreign source")
}

// TestTxDropMartianIsSelfAddressedOutbound: dest == ours is ErrMartian, not
// ErrReflected (that sentinel is inbound-only).
func TestTxDropMartianIsSelfAddressedOutbound(t *testing.T) {
	f := newFixture(t).carrying()
	a := fixtureAssign()
	pkt := v4cfg{src: a.V4, dst: a.V4, payload: 32}.build()
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrMartian) {
		t.Fatalf("self-addressed outbound: %v, want ErrMartian", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMartian", st.TxDropMartian)
}

// TestTxDropFamilyOffIsUnassignedFamilyOutbound: IPv6 into a v4-only tunnel.
func TestTxDropFamilyOffIsUnassignedFamilyOutbound(t *testing.T) {
	v4only := func(c *Config) {
		c.Assign = Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
	}
	f := newFixture(t, v4only).carrying()
	if err := f.tun.Outbound(goodV6(64)); !errors.Is(err, ErrFamilyOff) {
		t.Fatalf("outbound v6 on a v4-only tunnel: %v, want ErrFamilyOff", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropFamilyOff", st.TxDropFamilyOff)
}

// TestTxDropMalformedIsABadChecksum: a structurally addressed packet whose
// IPv4 header checksum is wrong is a parse refusal, not a source check.
func TestTxDropMalformedIsABadChecksum(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 64, badChecksum: true}.build()
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrBadChecksum) {
		t.Fatalf("bad checksum: %v, want ErrBadChecksum", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMalformed", st.TxDropMalformed)
}

// TestTxDropReasonsSumAcrossAMix drives one of each reason through the SAME
// tunnel and requires the total to be 4 — the number TxDroppedInvalid would
// have been before the split — and each reason to be 1.
func TestTxDropReasonsSumAcrossAMix(t *testing.T) {
	v4only := func(c *Config) {
		c.Assign = Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
	}
	f := newFixture(t, v4only).carrying()
	a := fixtureAssign()

	if err := f.tun.Outbound(goodV6(64)); !errors.Is(err, ErrFamilyOff) {
		t.Fatalf("family off: %v", err)
	}
	self := v4cfg{src: a.V4, dst: a.V4, payload: 32}.build()
	if err := f.tun.Outbound(self); !errors.Is(err, ErrMartian) {
		t.Fatalf("martian: %v", err)
	}
	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrSourceNotOurs) {
		t.Fatalf("source not ours: %v", err)
	}
	bad := v4cfg{src: a.V4, dst: peerV4(), payload: 64, badChecksum: true}.build()
	if err := f.tun.Outbound(bad); !errors.Is(err, ErrBadChecksum) {
		t.Fatalf("malformed: %v", err)
	}

	st := f.tun.Stats()
	if st.TxDroppedInvalid != 4 {
		t.Fatalf("TxDroppedInvalid=%d, want 4 — the total must not change", st.TxDroppedInvalid)
	}
	if st.TxDropFamilyOff != 1 || st.TxDropMartian != 1 ||
		st.TxDropSourceNotOurs != 1 || st.TxDropMalformed != 1 {
		t.Fatalf("reasons: familyOff=%d martian=%d sourceNotOurs=%d malformed=%d, want 1/1/1/1",
			st.TxDropFamilyOff, st.TxDropMartian, st.TxDropSourceNotOurs, st.TxDropMalformed)
	}
	if sum := txReasonSum(st); sum != st.TxDroppedInvalid {
		t.Fatalf("per-reason sum %d != TxDroppedInvalid %d", sum, st.TxDroppedInvalid)
	}
	if st.TxPackets != 0 {
		t.Fatalf("TxPackets=%d, want 0", st.TxPackets)
	}

	if err := f.tun.Outbound(goodV4(64)); err != nil {
		t.Fatalf("a valid packet after the mix was refused: %v", err)
	}
	st = f.tun.Stats()
	if st.TxPackets != 1 {
		t.Fatalf("TxPackets=%d, want 1 after the valid packet", st.TxPackets)
	}
	if st.TxDroppedInvalid != 4 {
		t.Fatalf("the valid packet moved TxDroppedInvalid to %d", st.TxDroppedInvalid)
	}
}

// TestTxDropReasonsDoNotCountAClosedGate: fail-closed is TxDroppedClosed, and
// the parse never happens, so no invalid reason may move.
func TestTxDropReasonsDoNotCountAClosedGate(t *testing.T) {
	f := newFixture(t)
	foreign := v4cfg{src: peerV4(), dst: peerV4(), payload: 64}.build()
	if err := f.tun.Outbound(foreign); !errors.Is(err, ErrNotCarrying) {
		t.Fatalf("closed gate: %v, want ErrNotCarrying", err)
	}
	st := f.tun.Stats()
	if st.TxDroppedClosed != 1 {
		t.Fatalf("TxDroppedClosed=%d, want 1", st.TxDroppedClosed)
	}
	if st.TxDroppedInvalid != 0 || txReasonSum(st) != 0 {
		t.Fatalf("a closed-gate drop was counted as invalid: %+v", st)
	}
}

// TestTxDropReasonsDoNotCountOversize: oversize is a post-validate drop, not
// a validator refusal. Putting it in the invalid split would change the total.
func TestTxDropReasonsDoNotCountOversize(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := goodV4(2000)
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize: %v, want ErrOversize", err)
	}
	st := f.tun.Stats()
	if st.TxDroppedOversize != 1 {
		t.Fatalf("TxDroppedOversize=%d, want 1", st.TxDroppedOversize)
	}
	if st.TxDroppedInvalid != 0 || txReasonSum(st) != 0 {
		t.Fatalf("an oversize drop was counted as invalid: %+v", st)
	}
}

// TestInboundDropsDoNotMoveTxDropReasons: the split is directional.
func TestInboundDropsDoNotMoveTxDropReasons(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := v4cfg{src: peerV4(), dst: v4a(1, 1, 1, 1), payload: 64}.build()
	if err := f.tun.Inbound(pkt); !errors.Is(err, ErrNotForUs) {
		t.Fatalf("inbound foreign dest: %v, want ErrNotForUs", err)
	}
	st := f.tun.Stats()
	if st.RxDropNotForUs != 1 || st.RxDroppedInvalid != 1 {
		t.Fatalf("inbound NotForUs was not counted: %+v", st)
	}
	if st.TxDroppedInvalid != 0 || txReasonSum(st) != 0 {
		t.Fatalf("an inbound drop moved a TX reason: %+v", st)
	}
}

// TestPumpOverreportCountsAsTxDropMalformed: PumpOutbound's n>len(buf) path
// increments TxDroppedInvalid without going through validator.outbound. It
// must still land in a reason bucket or the sum invariant is a lie.
func TestPumpOverreportCountsAsTxDropMalformed(t *testing.T) {
	f := newFixture(t).carrying()
	f.dev.mu.Lock()
	f.dev.overreport = MaxIPPacket
	f.dev.mu.Unlock()
	f.dev.queue(goodV4(64))

	if err := f.tun.PumpOutbound(context.Background()); !errors.Is(err, errNoMoreReads) {
		t.Fatalf("PumpOutbound: %v, want the end-of-queue sentinel", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMalformed", st.TxDropMalformed)
	if f.sink.count() != 0 {
		t.Fatal("the pump trusted a device that reported past the end of its buffer")
	}
}

// TestAValidOutboundPacketMovesNoTxDropReason is the positive control: without
// it, "the reasons stayed zero" could be true because the tunnel carries
// nothing.
func TestAValidOutboundPacketMovesNoTxDropReason(t *testing.T) {
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(goodV4(64)); err != nil {
		t.Fatalf("valid outbound: %v", err)
	}
	st := f.tun.Stats()
	if st.TxPackets != 1 {
		t.Fatalf("TxPackets=%d, want 1", st.TxPackets)
	}
	if st.TxDroppedInvalid != 0 || txReasonSum(st) != 0 {
		t.Fatalf("a valid packet moved an invalid reason: %+v", st)
	}
}

// TestTxDropMalformedIsATruncatedHeader is a second malformed shape, so a
// mutation that special-cases only the checksum path cannot hide.
func TestTxDropMalformedIsATruncatedHeader(t *testing.T) {
	buf := make([]byte, IPv4HeaderMin)
	buf[0] = 0x4f // version 4, IHL 15 => a 60-byte header
	binary.BigEndian.PutUint16(buf[2:4], IPv4HeaderMin)
	buf[8] = 64

	f := newFixture(t).carrying()
	if err := f.tun.Outbound(buf); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("over-long IHL: %v, want ErrBadHeader", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMalformed", st.TxDropMalformed)
}

// TestTxDropMartianIsLoopbackDestination is a second martian shape: dest is
// 127.0.0.1, source is ours. Self-addressed (dst == ours) is a different
// branch of validator.outbound; a mutation that only mapped that branch to
// TxDropMartian would leave loopback dest as malformed and this would go red.
func TestTxDropMartianIsLoopbackDestination(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := v4cfg{src: fixtureAssign().V4, dst: v4a(127, 0, 0, 1), payload: 32}.build()
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrMartian) {
		t.Fatalf("loopback dest outbound: %v, want ErrMartian", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMartian", st.TxDropMartian)
	if st.TxDropSourceNotOurs != 0 || st.TxDropMalformed != 0 {
		t.Fatalf("loopback dest was miscategorised: sourceNotOurs=%d malformed=%d",
			st.TxDropSourceNotOurs, st.TxDropMalformed)
	}
}

// TestTxDropMalformedIsAShortPacket: ErrShortPacket is a parse refusal and
// must land in the default (malformed) bucket, not be left on the total
// with no reason.
func TestTxDropMalformedIsAShortPacket(t *testing.T) {
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(goodV4(64)[:19]); !errors.Is(err, ErrShortPacket) {
		t.Fatalf("truncated IPv4 header: %v, want ErrShortPacket", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMalformed", st.TxDropMalformed)
}

// TestTxDropMalformedIsBadVersion: version nibble 5 is ErrBadVersion, also
// the default bucket. Distinct from checksum and IHL so a special-case of
// either cannot hide a missing default.
func TestTxDropMalformedIsBadVersion(t *testing.T) {
	buf := []byte{0x50, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	f := newFixture(t).carrying()
	if err := f.tun.Outbound(buf); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("version 5: %v, want ErrBadVersion", err)
	}
	st := f.tun.Stats()
	assertOnlyTxReason(t, st, "TxDropMalformed", st.TxDropMalformed)
}
