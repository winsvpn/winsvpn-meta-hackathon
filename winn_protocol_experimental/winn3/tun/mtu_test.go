package tun

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/winn3/core"
)

// TestOverheadMatchesCore derives the per-packet overhead from core's own
// codec instead of restating it.
//
// The failure this catches is drift. A sibling lane owns winn3/core; if the
// frame header or the transport header changes there, this package's MTU
// becomes quietly wrong — full-size packets start needing an extra carrier
// message, which either fragments or is dropped, and the symptom is "large
// downloads stall" reported from a country where nobody can attach a debugger.
// This test turns that into a failing build instead.
func TestOverheadMatchesCore(t *testing.T) {
	encoded, err := core.AppendFrame(nil, core.FrameData, make([]byte, 500))
	if err != nil {
		t.Fatal(err)
	}
	gotFrame := len(encoded) - 500
	if gotFrame != FrameOverhead {
		t.Fatalf("core's DATA frame header is %d bytes, this package assumes %d", gotFrame, FrameOverhead)
	}
	if want := core.TransportOverhead() + gotFrame; Overhead() != want {
		t.Fatalf("Overhead() = %d, core says %d", Overhead(), want)
	}
	if Overhead() != 29 {
		t.Fatalf("Overhead() = %d; the design's arithmetic and the handoff document both say 29", Overhead())
	}
}

// TestInnerMTUArithmetic is the worked table from the handoff document, kept
// where it can fail.
func TestInnerMTUArithmetic(t *testing.T) {
	cases := []struct {
		name        string
		path        int
		outer       int
		wantCarrier int
		wantInner   int
		carriesIPv6 bool
	}{
		{"ethernet, udp over ipv4", 1500, UDPOverIPv4Overhead, 1472, 1443, true},
		{"ethernet, udp over ipv6", 1500, UDPOverIPv6Overhead, 1452, 1423, true},
		{"pppoe, udp over ipv4", 1492, UDPOverIPv4Overhead, 1464, 1435, true},
		{"ipv6 floor path, udp over ipv6", 1280, UDPOverIPv6Overhead, 1232, 1203, false},
		{"ipv6 floor path, udp over ipv4", 1280, UDPOverIPv4Overhead, 1252, 1223, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			carrier := tc.path - tc.outer
			if carrier != tc.wantCarrier {
				t.Fatalf("carrier max message = %d, want %d", carrier, tc.wantCarrier)
			}
			if got := InnerMTU(carrier); got != tc.wantInner {
				t.Fatalf("InnerMTU = %d, want %d", got, tc.wantInner)
			}
			if got := InnerMTUForPath(tc.path, tc.outer); got != tc.wantInner {
				t.Fatalf("InnerMTUForPath = %d, want %d", got, tc.wantInner)
			}
			if got := CarrierMessageFor(tc.wantInner); got != carrier {
				t.Fatalf("CarrierMessageFor round trip = %d, want %d", got, carrier)
			}
			if canV6 := tc.wantInner >= IPv6MinLinkMTU; canV6 != tc.carriesIPv6 {
				t.Fatalf("inner MTU %d: carries IPv6 = %v, want %v", tc.wantInner, canV6, tc.carriesIPv6)
			}
		})
	}
	if got := MinCarrierMessageForIPv6(); got != 1309 {
		t.Fatalf("MinCarrierMessageForIPv6 = %d, want 1309", got)
	}
	if got := fixtureInnerMTU; got != InnerMTU(fixtureCarrierFloor) {
		t.Fatalf("the test fixture's inner MTU is %d but the arithmetic says %d", got, InnerMTU(fixtureCarrierFloor))
	}
}

// newSessionPair builds two real core sessions from a real handshake, so the
// MTU claims below are measured on actual sealed messages rather than on the
// arithmetic asserting itself.
func newSessionPair(t *testing.T) (*core.Session, *core.Session) {
	t.Helper()
	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	clStatic, err := core.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	admission := make([]byte, 32)
	for i := range admission {
		admission[i] = byte(i * 7)
	}
	cfg := core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{admission},
		GatewayID:     []byte("winn3-tun-mtu-test"),
	}}
	gwPub, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		t.Fatal(err)
	}
	ini, err := core.NewInitiator(cfg, clStatic, gwPub)
	if err != nil {
		t.Fatal(err)
	}
	init1, err := ini.WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := core.NewResponder(cfg, gwStatic, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	hs, err := resp.ReadInitiation(init1)
	if err != nil {
		t.Fatal(err)
	}
	respMsg, gwSess, err := hs.WriteResponse(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	clSess, _, err := ini.ReadResponse(respMsg)
	if err != nil {
		t.Fatal(err)
	}
	return clSess, gwSess
}

// TestInnerMTUFillsTheCarrierExactly is the end-to-end proof of the arithmetic.
//
// It takes the largest packet this package will accept, wraps it the way the
// session driver will — one DATA frame, one transport message, real ChaCha20 —
// and measures the bytes that come out. The claim is that they exactly fill the
// carrier's message budget and never exceed it, and that one more inner byte
// exceeds it by exactly one. A bound that is merely conservative wastes payload
// on every packet for the life of the product; a bound that is optimistic
// fragments.
func TestInnerMTUFillsTheCarrierExactly(t *testing.T) {
	cl, gw := newSessionPair(t)

	inner := make([]byte, InnerMTU(fixtureCarrierFloor))
	payload, err := core.AppendFrame(nil, core.FrameData, inner)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cl.Seal(payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != fixtureCarrierFloor {
		t.Fatalf("a full inner packet sealed to %d bytes; the carrier's budget is %d", len(msg), fixtureCarrierFloor)
	}

	// It also has to survive the trip, which proves the payload was not
	// silently clipped by any of the length fields on the way.
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := core.ParseFrames(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].Type != core.FrameData || len(frames[0].Value) != len(inner) {
		t.Fatalf("round trip produced %d frame(s), first is type %d of %d bytes", len(frames), frames[0].Type, len(frames[0].Value))
	}

	// One byte more overflows by exactly one.
	over, err := core.AppendFrame(nil, core.FrameData, make([]byte, InnerMTU(fixtureCarrierFloor)+1))
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := cl.Seal(over, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg2) != fixtureCarrierFloor+1 {
		t.Fatalf("one byte over the inner MTU sealed to %d bytes, want %d", len(msg2), fixtureCarrierFloor+1)
	}
}

// TestPaddingCannotExceedTheCarrier pins the rule the session driver has to
// follow: padding is free of per-packet overhead, so it never changes the inner
// MTU, but its top bucket must not exceed the carrier's message budget.
func TestPaddingCannotExceedTheCarrier(t *testing.T) {
	cl, gw := newSessionPair(t)

	// A tiny packet padded up to the top bucket must land exactly on it.
	small, err := core.AppendFrame(nil, core.FrameData, make([]byte, 40))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := cl.Seal(small, fixtureCarrierFloor)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != fixtureCarrierFloor {
		t.Fatalf("padded message is %d bytes, want the %d-byte bucket", len(msg), fixtureCarrierFloor)
	}
	got, err := gw.Open(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(small) {
		t.Fatalf("padding leaked into the payload: %d bytes recovered, %d sent", len(got), len(small))
	}

	// And a full-size packet cannot be padded at all, which is what keeps the
	// top bucket from ever pushing a message past the carrier.
	full, err := core.AppendFrame(nil, core.FrameData, make([]byte, InnerMTU(fixtureCarrierFloor)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Seal(full, fixtureCarrierFloor-1); err == nil {
		t.Fatal("core padded a message below its own minimum length")
	}
}

// TestOversizeIsNeverFragmented. The whole point of the drop is that no second
// packet appears — inner fragmentation would emit a two-packet burst with a
// near-fixed size ratio, which is a length signature, and it would put
// reassembly state on the gateway.
func TestOversizeIsNeverFragmented(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := goodV4(4000)
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrOversize) {
		t.Fatalf("%v, want ErrOversize", err)
	}
	if n := f.sink.count(); n != 0 {
		t.Fatalf("%d packet(s) reached the session for an oversize datagram; it must produce none", n)
	}
	st := f.tun.Stats()
	if st.TxDroppedOversize != 1 || st.TxPackets != 0 {
		t.Fatalf("counters: %+v", st)
	}
}

// TestPathMTUSignalIPv4 checks the synthesised Fragmentation Needed message
// field by field, because a signal the host silently discards is worse than no
// signal: the flow still stalls, and the counter says it was told.
func TestPathMTUSignalIPv4(t *testing.T) {
	f := newFixture(t).carrying()
	orig := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 4000, df: true}.build()
	if err := f.tun.Outbound(orig); !errors.Is(err, ErrOversize) {
		t.Fatalf("%v, want ErrOversize", err)
	}
	if f.dev.writeCount() != 1 {
		t.Fatalf("device saw %d writes, want the one path-MTU signal", f.dev.writeCount())
	}
	msg := f.dev.lastWrite()

	if len(msg) > icmpv4ErrorMaxTotal {
		t.Fatalf("the signal is %d bytes; RFC 1812 caps it at %d", len(msg), icmpv4ErrorMaxTotal)
	}
	p, err := parsePacket(msg)
	if err != nil {
		t.Fatalf("the signal does not parse as an IP packet: %v", err)
	}
	if p.src != fixtureAssign().RouterV4 {
		t.Fatalf("signal source is %v, want the inner router", p.src)
	}
	if p.dst != fixtureAssign().V4 {
		t.Fatalf("signal destination is %v, want this host's inner address", p.dst)
	}
	if p.proto != 1 {
		t.Fatalf("signal protocol is %d, want 1 (ICMP)", p.proto)
	}
	icmp := msg[p.hdrLen:]
	if icmp[0] != icmpv4TypeDestUnreachable || icmp[1] != icmpv4CodeFragNeeded {
		t.Fatalf("signal is type %d code %d, want %d/%d", icmp[0], icmp[1], icmpv4TypeDestUnreachable, icmpv4CodeFragNeeded)
	}
	if got := int(binary.BigEndian.Uint16(icmp[6:8])); got != f.tun.InnerMTU() {
		t.Fatalf("next-hop MTU is %d, want %d", got, f.tun.InnerMTU())
	}
	// The quoted packet must be the original's own header, so the host can
	// attribute the signal to the right flow.
	quoted := icmp[icmpHeaderLen:]
	if len(quoted) < IPv4HeaderMin {
		t.Fatal("the signal quotes less than an IP header")
	}
	for i := 0; i < IPv4HeaderMin; i++ {
		if quoted[i] != orig[i] {
			t.Fatalf("quoted header differs from the original at byte %d", i)
		}
	}
	if st := f.tun.Stats(); st.PMTUSignals != 1 {
		t.Fatalf("PMTUSignals=%d, want 1", st.PMTUSignals)
	}
}

func TestPathMTUSignalIPv6(t *testing.T) {
	f := newFixture(t).carrying()
	orig := v6cfg{src: fixtureAssign().V6, dst: peerV6(), payload: 4000}.build()
	if err := f.tun.Outbound(orig); !errors.Is(err, ErrOversize) {
		t.Fatalf("%v, want ErrOversize", err)
	}
	msg := f.dev.lastWrite()
	if msg == nil {
		t.Fatal("no signal was delivered")
	}
	if len(msg) > icmpv6ErrorMaxTotal {
		t.Fatalf("the signal is %d bytes; RFC 4443 caps it at %d", len(msg), icmpv6ErrorMaxTotal)
	}
	p, err := parsePacket(msg)
	if err != nil {
		t.Fatalf("the signal does not parse: %v", err)
	}
	if !p.v6 || p.proto != icmpv6NextHeader {
		t.Fatalf("signal is v6=%v next header %d", p.v6, p.proto)
	}
	if p.src != fixtureAssign().RouterV6 || p.dst != fixtureAssign().V6 {
		t.Fatalf("signal is addressed %v -> %v", p.src, p.dst)
	}
	icmp := msg[IPv6HeaderLen:]
	if icmp[0] != icmpv6TypePacketTooBig || icmp[1] != 0 {
		t.Fatalf("signal is type %d code %d, want %d/0", icmp[0], icmp[1], icmpv6TypePacketTooBig)
	}
	if got := int(binary.BigEndian.Uint32(icmp[4:8])); got != f.tun.InnerMTU() {
		t.Fatalf("advertised MTU is %d, want %d", got, f.tun.InnerMTU())
	}
}

// TestChecksumSelfVerifies checks both synthesised messages the way a receiving
// stack checks them: recompute over the buffer that already carries the
// checksum and require zero. A wrong ICMPv6 checksum — the classic being a
// forgotten pseudo-header — is discarded silently by every stack, which turns
// the path-MTU signal into an invisible black hole.
func TestChecksumSelfVerifies(t *testing.T) {
	f := newFixture(t).carrying()

	if err := f.tun.Outbound(goodV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	v4msg := f.dev.lastWrite()
	if got := checksum(v4msg[:IPv4HeaderMin]); got != 0 {
		t.Fatalf("IPv4 header checksum verifies to %#04x, want 0", got)
	}
	if got := checksum(v4msg[IPv4HeaderMin:]); got != 0 {
		t.Fatalf("ICMPv4 checksum verifies to %#04x, want 0", got)
	}

	if err := f.tun.Outbound(goodV6(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	v6msg := f.dev.lastWrite()
	var src, dst [16]byte
	copy(src[:], v6msg[8:24])
	copy(dst[:], v6msg[24:40])
	if got := icmpv6Checksum(src, dst, v6msg[IPv6HeaderLen:]); got != 0 {
		t.Fatalf("ICMPv6 checksum verifies to %#04x, want 0 — a stack would discard this signal", got)
	}

	// And the checker has teeth: corrupt one byte and it must object.
	corrupt := append([]byte(nil), v6msg...)
	corrupt[IPv6HeaderLen+9] ^= 0x01
	copy(src[:], corrupt[8:24])
	copy(dst[:], corrupt[24:40])
	if icmpv6Checksum(src, dst, corrupt[IPv6HeaderLen:]) == 0 {
		t.Fatal("the ICMPv6 checksum check accepts a corrupted message")
	}
}

// TestPathMTUSignalIsRateLimited. The trigger is usually a local
// misconfiguration producing oversize packets at line rate; answering each one
// would turn that into a livelock inside the packet loop.
func TestPathMTUSignalIsRateLimited(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.ICMPPerSecond = 4
		c.ICMPBurst = 4
	}).carrying()

	for i := 0; i < 50; i++ {
		_ = f.tun.Outbound(goodV4(4000))
	}
	st := f.tun.Stats()
	if st.PMTUSignals != 4 {
		t.Fatalf("PMTUSignals=%d, want the 4-packet burst", st.PMTUSignals)
	}
	if st.PMTUSuppressed != 46 {
		t.Fatalf("PMTUSuppressed=%d, want 46", st.PMTUSuppressed)
	}

	// The bucket refills from the injected clock and from nothing else.
	f.clock.advance(time.Second)
	for i := 0; i < 50; i++ {
		_ = f.tun.Outbound(goodV4(4000))
	}
	if got := f.tun.Stats().PMTUSignals; got != 8 {
		t.Fatalf("after one second PMTUSignals=%d, want 8", got)
	}
}

// TestNoRouterAddressMeansNoSignal. Without an inner next hop there is no
// credible source for the message, so the packet is dropped and counted rather
// than a signal being invented from an address that routes nowhere.
func TestNoRouterAddressMeansNoSignal(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.Assign = Assignment{V4: fixtureAssign().V4, V6: fixtureAssign().V6}
	}).carrying()
	if err := f.tun.Outbound(goodV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("a signal was synthesised with no router address configured")
	}
	if st := f.tun.Stats(); st.PMTUSuppressed != 1 {
		t.Fatalf("PMTUSuppressed=%d, want 1", st.PMTUSuppressed)
	}
}

// TestNoSignalWithoutDF. A Fragmentation Needed message for a packet that did
// not set DF is non-standard, and hosts ignore it — emitting one would be noise
// dressed as a fix. The real answer is the host contract: set the device MTU to
// the published value and the host stops generating these at all.
func TestNoSignalWithoutDF(t *testing.T) {
	f := newFixture(t).carrying()
	pkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: 4000, df: false}.build()
	if err := f.tun.Outbound(pkt); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("a Fragmentation Needed message was sent for a packet without DF")
	}
}

func TestDisablingTheSignalStillDrops(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.DisablePMTUSignal = true }).carrying()
	if err := f.tun.Outbound(goodV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatal(err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("a signal was written with synthesis disabled")
	}
	if st := f.tun.Stats(); st.TxDroppedOversize != 1 || st.PMTUSuppressed != 1 {
		t.Fatalf("counters: %+v", st)
	}
}

// TestInboundOversizeIsNotWritten. A peer that sends more than the device MTU
// is a bug or an attack; either way the packet is not handed to the host.
func TestInboundOversizeIsNotWritten(t *testing.T) {
	f := newFixture(t).carrying()
	if err := f.tun.Inbound(arrivingV4(4000)); !errors.Is(err, ErrOversize) {
		t.Fatalf("%v, want ErrOversize", err)
	}
	if f.dev.writeCount() != 0 {
		t.Fatal("an oversize packet was written to the host device")
	}
	if st := f.tun.Stats(); st.RxDroppedOversize != 1 {
		t.Fatalf("RxDroppedOversize=%d, want 1", st.RxDroppedOversize)
	}
}

// TestDeviceMTUIsClampedAtConstruction is the MTU-clamp assertion.
//
// The clamp is the boundary this layer publishes to the host: a device is never
// allowed to be larger than the tunnel can carry, or narrower than the family
// floor. A host that sizes a device above the inner MTU has built a black hole
// — it generates packets the tunnel can only drop, and every layer above then
// blames the censor for a link that never carried. Enforcement here is by
// REFUSAL (this package never clamps silently; see driver/params.go,
// "refuse rather than clamp"), but the observable invariant is still a clamp:
// there is no value of DeviceMTU() a caller can obtain that exceeds InnerMTU(),
// and no Tunnel whose DeviceMTU() drops below the IPv4 floor.
//
// It sweeps the device-MTU space under a v4-only assignment so the 576-byte
// floor applies, requires New to accept exactly the range the clamp allows and
// to refuse both edges, then re-checks the same boundary with inner IPv6
// assigned, where the floor moves up to RFC 8200's 1280. If the guards in New
// are weakened, a boundary value is accepted and this test goes red.
func TestDeviceMTUIsClampedAtConstruction(t *testing.T) {
	v4assign := Assignment{V4: fixtureAssign().V4, RouterV4: fixtureAssign().RouterV4}
	inner := InnerMTU(fixtureCarrierFloor) // 1423

	build := func(assign Assignment, devMTU int) (*Tunnel, error) {
		return New(Config{
			Assign:                  assign,
			Device:                  &fakeDevice{mtu: devMTU},
			Sink:                    &fakeSink{},
			Clock:                   newFakeClock(),
			CarrierFloorMessageSize: fixtureCarrierFloor,
		})
	}

	// The clamp: any accepted device MTU is reported at most the inner MTU and
	// at least the IPv4 floor.
	for _, devMTU := range []int{MinInnerMTUv4, 1000, inner} {
		tn, err := build(v4assign, devMTU)
		if err != nil {
			t.Fatalf("a device MTU of %d is inside the clamp but New refused it: %v", devMTU, err)
		}
		if got := tn.DeviceMTU(); got > inner || got < MinInnerMTUv4 {
			t.Fatalf("device MTU %d escapes the clamp [%d,%d]", got, MinInnerMTUv4, inner)
		}
		if tn.DeviceMTU() > tn.InnerMTU() {
			t.Fatalf("device MTU %d exceeds inner MTU %d", tn.DeviceMTU(), tn.InnerMTU())
		}
	}

	// The upper edge is enforced by refusal: one byte above the inner MTU must
	// not build.
	if _, err := build(v4assign, inner+1); !errors.Is(err, ErrConfig) {
		t.Fatalf("New accepted a device MTU of %d, above the %d-byte inner MTU; the clamp leaks", inner+1, inner)
	}

	// The lower edge too: one byte below the IPv4 floor must not build.
	if _, err := build(v4assign, MinInnerMTUv4-1); !errors.Is(err, ErrConfig) {
		t.Fatalf("New accepted a device MTU of %d, below the %d-byte IPv4 floor", MinInnerMTUv4-1, MinInnerMTUv4)
	}

	// With inner IPv6 assigned the floor moves up to RFC 8200's 1280, and a
	// device MTU in [1280, inner] still builds while one below 1280 is refused.
	if inner < IPv6MinLinkMTU {
		t.Fatalf("the fixture yields an inner MTU of %d, below the IPv6 floor; this test cannot exercise it", inner)
	}
	for _, devMTU := range []int{IPv6MinLinkMTU, inner} {
		if _, err := build(fixtureAssign(), devMTU); err != nil {
			t.Fatalf("with inner IPv6 a device MTU of %d is inside the clamp but New refused it: %v", devMTU, err)
		}
	}
	if _, err := build(fixtureAssign(), IPv6MinLinkMTU-1); !errors.Is(err, ErrConfig) {
		t.Fatalf("with inner IPv6 New accepted a device MTU of %d, below the %d-byte floor", IPv6MinLinkMTU-1, IPv6MinLinkMTU)
	}
}

// TestCarryPathClampsAtTheInnerMTU is the carry-path half of the MTU clamp.
//
// TestDeviceMTUIsClampedAtConstruction pins the clamp at CONSTRUCTION: New
// refuses a device whose MTU is outside the tunnel's range. This one pins the
// clamp where it actually bites — the packet loop. A packet whose total length
// is exactly InnerMTU() crosses; one byte past it is refused as ErrOversize,
// counted in TxDroppedOversize, and never written to the session. The fixture's
// device MTU equals the inner MTU (the boundary case), so this is the exact
// threshold a host must be able to rely on: any narrower enforcement drops
// packets the host is entitled to send, any wider one lets a packet through
// that the tunnel can only black hole downstream.
//
// It uses the REAL Outbound path through a gate that is carrying, so a clamp
// weakened in New's arithmetic, in Outbound's bounds test, or anywhere in
// between is caught here — the same way a host would experience it.
func TestCarryPathClampsAtTheInnerMTU(t *testing.T) {
	f := newFixture(t).carrying()
	inner := f.tun.InnerMTU()
	dev := f.tun.DeviceMTU()
	if dev != inner {
		t.Fatalf("fixture device MTU %d != inner MTU %d; the boundary claim is not exercised", dev, inner)
	}

	// payload fills the packet to exactly InnerMTU() total length.
	payload := inner - IPv4HeaderMin
	if payload < 0 {
		t.Fatalf("inner MTU %d cannot hold a 20-byte IPv4 header", inner)
	}

	full := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: payload, df: true}.build()
	if len(full) != inner {
		t.Fatalf("test packet is %d bytes, want exactly the %d-byte inner MTU", len(full), inner)
	}
	if err := f.tun.Outbound(full); err != nil {
		t.Fatalf("a packet of exactly the inner MTU was refused on the carry path: %v", err)
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("session saw %d packet(s); the exact-MTU packet must cross", n)
	}
	got := f.sink.last()
	if len(got) != inner {
		t.Fatalf("session received %d bytes, want the full %d-byte packet", len(got), inner)
	}

	// One byte past the MTU is refused, counted, and produces no second packet
	// (never fragmented) — the clamp holds at the boundary.
	over := inner + 1
	overPkt := v4cfg{src: fixtureAssign().V4, dst: peerV4(), payload: over - IPv4HeaderMin, df: true}.build()
	if len(overPkt) != over {
		t.Fatalf("test packet is %d bytes, want %d", len(overPkt), over)
	}
	if err := f.tun.Outbound(overPkt); !errors.Is(err, ErrOversize) {
		t.Fatalf("a packet %d bytes past the MTU returned %v, want ErrOversize", over-inner, err)
	}
	if n := f.sink.count(); n != 1 {
		t.Fatalf("session saw %d packets; the oversize packet must not cross", n)
	}
	st := f.tun.Stats()
	if st.TxDroppedOversize != 1 || st.TxPackets != 1 {
		t.Fatalf("counters: %+v, want TxDroppedOversize=1 TxPackets=1", st)
	}
}

// TestIPv6RefusedBelowItsMinimumMTU is the configuration half of the IPv6
// posture. A tunnel that installs an inner IPv6 route on a link narrower than
// 1280 bytes has built something that looks like working IPv6 right up until
// the first full-size packet, and then black holes without a diagnostic.
func TestIPv6RefusedBelowItsMinimumMTU(t *testing.T) {
	// 1232 is a UDP-over-IPv6 carrier on a 1280-byte path: inner MTU 1203.
	dev := &fakeDevice{mtu: 1203}
	_, err := New(Config{
		Assign:                  fixtureAssign(),
		Device:                  dev,
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: 1232,
	})
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("New accepted inner IPv6 on a %d-byte inner MTU: %v", 1203, err)
	}

	// The same carrier with no IPv6 assignment is fine: IPv4 only needs 576.
	v4only := fixtureAssign()
	v4only.V6, v4only.RouterV6 = netip.Addr{}, netip.Addr{}
	tn, err := New(Config{
		Assign:                  v4only,
		Device:                  dev,
		Sink:                    &fakeSink{},
		Clock:                   newFakeClock(),
		CarrierFloorMessageSize: 1232,
	})
	if err != nil {
		t.Fatalf("New refused an IPv4-only tunnel on the same carrier: %v", err)
	}
	if tn.InnerMTU() != 1203 {
		t.Fatalf("inner MTU %d, want 1203", tn.InnerMTU())
	}
}

// TestMtuClampAtThe1450Seam pins the advertised-MTU clamp at the fleet default
// of carrier.DefaultPathMTU (1450).
//
// The 1450 path's plan floor is a 1338-byte message (the same number
// driver/sizing_test.go derives from carrier.DefaultPathMTU and
// carrier.Floor(1450, UDP, TCP, TLS)), which leaves an inner MTU of 1309 —
// comfortably under the 1450 it is reached from. That is the whole of the host
// contract this layer publishes: the device MTU the tunnel advertises
// (DeviceMTU) is never larger than the inner MTU the seam can actually move,
// and a device that asks for more is refused rather than silently clamped.
//
// It deliberately re-derives inner1450 from InnerMTU instead of hardcoding the
// subtraction, so that a change to Overhead() that shrinks what a 1450 path can
// carry fails here rather than quietly widening the advertised MTU.
func TestMtuClampAtThe1450Seam(t *testing.T) {
	const planFloor1450 = 1338 // carrier.Floor(1450, udp, tcp, tls)
	inner1450 := InnerMTU(planFloor1450)

	if inner1450 != 1309 {
		t.Fatalf("the 1450 seam yields an inner MTU of %d, want 1309", inner1450)
	}
	if inner1450 >= 1450 {
		t.Fatalf("the 1450 seam advertises an MTU of %d, not under the 1450 path floor", inner1450)
	}

	build := func(devMTU int) (*Tunnel, error) {
		return New(Config{
			Assign:                  fixtureAssign(),
			Device:                  &fakeDevice{mtu: devMTU},
			Sink:                    &fakeSink{},
			Clock:                   newFakeClock(),
			CarrierFloorMessageSize: planFloor1450,
		})
	}

	// The clamp: a device MTU at the boundary, and one byte under it, both
	// build, and the MTU the tunnel advertises never exceeds its inner MTU.
	for _, devMTU := range []int{inner1450, inner1450 - 1} {
		tn, err := build(devMTU)
		if err != nil {
			t.Fatalf("a device MTU of %d should be inside the clamp but New refused it: %v", devMTU, err)
		}
		if got := tn.DeviceMTU(); got != devMTU {
			t.Fatalf("advertised DeviceMTU() = %d, want the configured %d", got, devMTU)
		}
		if tn.DeviceMTU() > tn.InnerMTU() {
			t.Fatalf("advertised DeviceMTU %d exceeds inner MTU %d", tn.DeviceMTU(), tn.InnerMTU())
		}
	}

	// The refusal: any value over the inner MTU — the boundary plus one, the
	// 1450 path itself, and a full 1500 ethernet frame — must not build. If the
	// clamp is silently relaxed instead of enforced by refusal, this goes red.
	for _, devMTU := range []int{inner1450 + 1, 1450, 1500} {
		if _, err := build(devMTU); !errors.Is(err, ErrConfig) {
			t.Fatalf("New accepted a device MTU of %d, over the %d-byte inner MTU at the 1450 seam", devMTU, inner1450)
		}
	}
}
