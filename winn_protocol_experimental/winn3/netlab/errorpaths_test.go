package netlab

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// wellFormedFragNeeded builds an IPv4 ICMP Destination Unreachable /
// Fragmentation Needed message with correct IPv4 and ICMP checksums. It is the
// positive control for IsICMPv4FragNeeded: if this is rejected, the oracle is
// checking something a real stack does not.
func wellFormedFragNeeded(nextMTU int) []byte {
	src := V4(10, 64, 0, 1)
	dst := V4(10, 64, 0, 2)
	quote := make([]byte, 28)
	total := 20 + 8 + len(quote)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[6] = 0x40
	b[8] = 64
	b[9] = 1 // ICMP
	s := src.As4()
	d := dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	icmp := b[20:]
	icmp[0], icmp[1] = 3, 4
	binary.BigEndian.PutUint16(icmp[6:8], uint16(nextMTU))
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))
	return b
}

func TestIsICMPv4FragNeededAcceptsAWellFormedSignal(t *testing.T) {
	t.Parallel()
	const want = 1338
	pkt := wellFormedFragNeeded(want)
	if internetChecksum(pkt[:20]) != 0 {
		t.Fatal("the positive-control builder produced a bad IPv4 header checksum")
	}
	if internetChecksum(pkt[20:]) != 0 {
		t.Fatal("the positive-control builder produced a bad ICMP checksum")
	}
	mtu, ok := IsICMPv4FragNeeded(pkt)
	if !ok {
		t.Fatal("IsICMPv4FragNeeded rejected a well-formed Frag Needed; the oracle is stricter than a stack")
	}
	if mtu != want {
		t.Fatalf("next-hop MTU %d, want %d", mtu, want)
	}
}

func TestIsICMPv4FragNeededRejectsABadICMPChecksum(t *testing.T) {
	t.Parallel()
	pkt := wellFormedFragNeeded(1280)
	pkt[22] ^= 0xff // ICMP checksum high byte
	if _, ok := IsICMPv4FragNeeded(pkt); ok {
		t.Fatal("IsICMPv4FragNeeded accepted a Frag Needed with a corrupt ICMP checksum; " +
			"a real stack discards that, and the path-MTU signal becomes an invisible black hole")
	}
}

func TestIsICMPv4FragNeededRejectsABadIPv4Checksum(t *testing.T) {
	t.Parallel()
	pkt := wellFormedFragNeeded(1280)
	pkt[10] ^= 0xff
	if _, ok := IsICMPv4FragNeeded(pkt); ok {
		t.Fatal("IsICMPv4FragNeeded accepted a Frag Needed with a corrupt IPv4 header checksum")
	}
}

func TestIsICMPv4FragNeededRejectsTheEasyNegatives(t *testing.T) {
	t.Parallel()
	if _, ok := IsICMPv4FragNeeded(nil); ok {
		t.Fatal("accepted nil")
	}
	if _, ok := IsICMPv4FragNeeded(make([]byte, 10)); ok {
		t.Fatal("accepted a short slice")
	}
	v6 := wellFormedFragNeeded(1280)
	v6[0] = 0x60
	if _, ok := IsICMPv4FragNeeded(v6); ok {
		t.Fatal("accepted an IPv6 version nibble")
	}
	udp := wellFormedFragNeeded(1280)
	udp[9] = 17
	binary.BigEndian.PutUint16(udp[10:12], ipv4Checksum(udp[:20]))
	if _, ok := IsICMPv4FragNeeded(udp); ok {
		t.Fatal("accepted proto UDP")
	}
	echo := wellFormedFragNeeded(1280)
	echo[20] = 8 // echo request
	binary.BigEndian.PutUint16(echo[22:24], 0)
	binary.BigEndian.PutUint16(echo[22:24], internetChecksum(echo[20:]))
	if _, ok := IsICMPv4FragNeeded(echo); ok {
		t.Fatal("accepted ICMP echo")
	}
}

func TestIPv4PacketHeaderChecksumVerifies(t *testing.T) {
	t.Parallel()
	pkt := IPv4Packet(V4(10, 64, 0, 2), V4(10, 64, 0, 1), []byte("winn3"))
	if internetChecksum(pkt[:20]) != 0 {
		t.Fatal("IPv4Packet's header checksum does not verify under internetChecksum; " +
			"the tun layer would drop every inner packet this rig offers")
	}
	if PayloadOf(pkt) == nil || string(PayloadOf(pkt)) != "winn3" {
		t.Fatalf("PayloadOf = %q", PayloadOf(pkt))
	}
	if PayloadOf([]byte{1, 2, 3}) != nil {
		t.Fatal("PayloadOf of a short slice must be nil")
	}
}

func TestDeviceReadAndWriteReturnErrDeviceClosed(t *testing.T) {
	t.Parallel()
	d := NewDevice(1500)
	d.Close()
	if _, err := d.ReadPacket(make([]byte, 64)); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("ReadPacket after Close: %v, want ErrDeviceClosed", err)
	}
	if _, err := d.WritePacket([]byte{1}); !errors.Is(err, ErrDeviceClosed) {
		t.Fatalf("WritePacket after Close: %v, want ErrDeviceClosed", err)
	}
	if d.Offer([]byte{1, 2, 3}) {
		t.Fatal("Offer after Close returned true; the packet sits on in forever because the pump has exited")
	}
}

func TestDeviceOfferCopiesThePacket(t *testing.T) {
	t.Parallel()
	d := NewDevice(1500)
	buf := []byte{1, 2, 3, 4}
	if !d.Offer(buf) {
		t.Fatal("Offer refused an empty device")
	}
	buf[0] = 9
	got := make([]byte, 8)
	n, err := d.ReadPacket(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || got[0] != 1 {
		t.Fatalf("Offer did not copy: n=%d got=%v; a reused host buffer would corrupt the tun queue", n, got[:n])
	}
}

func TestDeviceWritePacketReturnsErrDeviceFullAndWriteDropsCountsIt(t *testing.T) {
	t.Parallel()
	d := NewDevice(1500)
	filled := 0
	for {
		if _, err := d.WritePacket([]byte{1}); err != nil {
			if !errors.Is(err, ErrDeviceFull) {
				t.Fatalf("WritePacket on a full device: %v, want ErrDeviceFull", err)
			}
			break
		}
		filled++
		if filled > 8192 {
			t.Fatal("WritePacket never returned ErrDeviceFull after more than the documented 8192 buffer")
		}
	}
	if filled != 8192 {
		t.Fatalf("output buffer accepted %d packets, want 8192 (the cap in NewDevice)", filled)
	}
	if d.WriteDrops() != 1 {
		t.Fatalf("WriteDrops = %d, want 1; the counter was previously incremented and never readable", d.WriteDrops())
	}
	if d.Drained() != 8192 {
		t.Fatalf("Drained = %d, want 8192", d.Drained())
	}
	if _, ok := d.Take(time.Second); !ok {
		t.Fatal("Take on a full device returned nothing")
	}
	if _, err := d.WritePacket([]byte{2}); err != nil {
		t.Fatalf("WritePacket after Take: %v", err)
	}
}

func TestDeviceOfferReturnsFalseWhenInputIsFull(t *testing.T) {
	t.Parallel()
	d := NewDevice(1500)
	n := 0
	for d.Offer([]byte{1}) {
		n++
		if n > 4096 {
			t.Fatal("Offer never returned false")
		}
	}
	if n != 4096 {
		t.Fatalf("input buffer accepted %d packets, want 4096", n)
	}
}

func TestLinkOfferReturnsNilOnADropAndCountsTheCause(t *testing.T) {
	t.Parallel()
	var got [][]byte
	l := NewLink(func(m []byte) error {
		got = append(got, append([]byte(nil), m...))
		return nil
	}, 1)
	l.Arm(Impairment{MaxOuterPacket: 10, OuterOverhead: 0})
	if err := l.Offer(make([]byte, 11)); err != nil {
		t.Fatalf("Offer returned %v on an oversize drop; a DF-set path reports nothing", err)
	}
	st := l.Stats()
	if st.DroppedOversize != 1 || st.Offered != 1 || st.Delivered != 0 || len(got) != 0 {
		t.Fatalf("oversize drop stats %+v delivered-to-sink %d", st, len(got))
	}
}

func TestLinkLossPermilleIsSeededAndHasTeeth(t *testing.T) {
	t.Parallel()
	run := func(permille int, seed uint64) (dropped, delivered uint64) {
		l := NewLink(func([]byte) error { return nil }, seed)
		l.Arm(Impairment{LossPermille: permille})
		for i := 0; i < 1000; i++ {
			if err := l.Offer([]byte{byte(i)}); err != nil {
				t.Fatalf("Offer: %v", err)
			}
		}
		st := l.Stats()
		return st.DroppedRandom, st.Delivered
	}

	d0, del0 := run(0, 1)
	if d0 != 0 || del0 != 1000 {
		t.Fatalf("LossPermille 0 dropped %d delivered %d; the stochastic rule fired with the impairment off", d0, del0)
	}
	dAll, delAll := run(1000, 1)
	if dAll != 1000 || delAll != 0 {
		t.Fatalf("LossPermille 1000 dropped %d delivered %d; a 1000/1000 draw must drop every message", dAll, delAll)
	}
	a1, _ := run(300, 0xC0FFEE)
	a2, _ := run(300, 0xC0FFEE)
	if a1 != a2 {
		t.Fatalf("same seed dropped %d then %d; LossPermille is not reproducible", a1, a2)
	}
	if a1 == 0 || a1 == 1000 {
		t.Fatalf("LossPermille 300 dropped %d of 1000; the rule did not fire as a partial loss", a1)
	}
}

func TestLinkArmedOfferSwallowsSinkErrorAndCountsSinkRefused(t *testing.T) {
	t.Parallel()
	boom := errors.New("inbox full")
	l := NewLink(func([]byte) error { return boom }, 1)
	l.Arm(Impairment{})
	if err := l.Offer([]byte("x")); err != nil {
		t.Fatalf("armed Offer returned %v; the UDP model is that the send succeeded", err)
	}
	st := l.Stats()
	if st.SinkRefused != 1 {
		t.Fatalf("SinkRefused = %d, want 1; a full inbox was invisible on this side of the seam", st.SinkRefused)
	}
	if st.Delivered != 1 {
		t.Fatalf("Delivered = %d, want 1 (the sender's socket accepted the bytes)", st.Delivered)
	}
}

func TestLinkUnarmedOfferReturnsTheSinkError(t *testing.T) {
	t.Parallel()
	boom := errors.New("inbox full")
	l := NewLink(func([]byte) error { return boom }, 1)
	err := l.Offer([]byte("x"))
	if !errors.Is(err, boom) {
		t.Fatalf("unarmed Offer returned %v, want the sink error; handshake traffic uses the unarmed path", err)
	}
}

func TestDuplexHandshakeReportsErrTimeoutWhenRoundsRunOut(t *testing.T) {
	t.Parallel()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDuplex(kr, DuplexConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Handshake(0); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Handshake(0) returned %v, want ErrTimeout", err)
	}
}

func TestNewPairRefusesThePathMTUDeadZone(t *testing.T) {
	t.Parallel()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewPair(kr, PairConfig{
		PathMTU: 1280,
		Plan:    []carrier.Class{carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS},
	})
	if err == nil {
		t.Fatal("NewPair accepted PathMTU 1280 on the shipping plan; driver.NewSizing must refuse the dead zone")
	}
	if !errors.Is(err, driver.ErrPathMTUDeadZone) {
		t.Fatalf("NewPair refused 1280 with %v, which does not wrap ErrPathMTUDeadZone", err)
	}
}

func TestCollectOnAGatewayWithNoTunReturnsZeroImmediately(t *testing.T) {
	t.Parallel()
	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPair(kr, PairConfig{GatewayNoTun: true, TokenWindow: netlabWindow, SendQueue: 2048})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if n := p.Collect(4, 5*time.Second); n != 0 {
		t.Fatalf("Collect returned %d with GatewayNoTun; want 0", n)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Collect with a nil gateway device waited %s; the nil-device path must return immediately, not look like loss", time.Since(start))
	}
}

func TestSettleWrapsErrLoopExitedWhenBothLoopsAreDead(t *testing.T) {
	t.Parallel()
	p := burstPair(t, PairConfig{})
	p.Stop()
	err := p.Settle(3*time.Second, time.Millisecond, func() bool { return false })
	if err == nil {
		t.Fatal("Settle succeeded on a stopped pair with a cond that never holds")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Settle returned %v, want ErrTimeout (still the wait bound)", err)
	}
	if !errors.Is(err, ErrLoopExited) {
		t.Fatalf("Settle returned %v, which does not wrap ErrLoopExited; a dead loop then reads as a protocol silent-refusal", err)
	}
}

func TestDisplacedOrderKeepsLengthN(t *testing.T) {
	t.Parallel()
	perm := DisplacedOrder(10, 2, 3)
	if len(perm) != 10 {
		t.Fatalf("len %d, want 10", len(perm))
	}
	seen := make(map[int]int, 10)
	for _, i := range perm {
		seen[i]++
	}
	for i := 0; i < 10; i++ {
		if seen[i] != 1 {
			t.Fatalf("index %d appears %d times in %v", i, seen[i], perm)
		}
	}
	late := DisplacedOrder(5, 0, 10)
	if len(late) != 5 {
		t.Fatalf("displacement past the end: len %d, want 5", len(late))
	}
}
