package carrier

import (
	"errors"
	"net"
	"testing"

	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/session"
)

// TestSizingDelegatesToSession is item 3 of the brief as an equality.
//
// Every size this package produces must be exactly what
// session.MaxMessageSizeForPath would produce for the same overhead. Asserting
// the equality rather than the numbers means the session lane can change the
// clamps — it owns the floor and the ceiling — without this package silently
// disagreeing with it.
func TestSizingDelegatesToSession(t *testing.T) {
	t.Parallel()
	for _, class := range []Class{ClassUnknown, ClassUDP, ClassTCP, ClassTLS} {
		for _, family := range []Family{FamilyUnknown, FamilyIPv4, FamilyIPv6} {
			for _, mtu := range []int{576, 1280, 1400, 1492, 1500, 9000} {
				want := session.MaxMessageSizeForPath(mtu, Overhead(class, family))
				if got := MaxMessageSizeFor(class, family, mtu); got != want {
					t.Fatalf("%s/%s at %d: got %d, session says %d",
						class, family, mtu, got, want)
				}
			}
		}
	}
}

// TestFrameNeverExceedsTheSinkMTU is the MTU-boundary test: it drives a real
// carrier seam, not just arithmetic, and asserts no frame it accepts is larger
// than the sink's own MTU.
//
// The sink is a Pipe sized from the negotiated path MTU — the number
// session.NegotiatedPathMTU produces for two ends that both claim a planning MTU,
// and the only number both ends of a session can carry at. A carrier is then
// asked to carry frames of exactly that size and of one byte over it. The fixture
// asserts, by the sink's own counters, that the over-MTU frame is refused and
// never delivered, so "no frame exceeds the sink MTU" is a property of the
// running wire seam and not of the constants beside it.
func TestFrameNeverExceedsTheSinkMTU(t *testing.T) {
	t.Parallel()

	const pathMTU = DefaultPathMTU // 1450, the fleet default and the negotiated value
	negotiated, both := session.NegotiatedPathMTU(pathMTU, pathMTU)
	if !both || negotiated != pathMTU {
		t.Fatalf("harness bug: %d/%d should negotiate to %d", pathMTU, pathMTU, pathMTU)
	}

	// One carrier per class. Each is sized from the negotiated MTU and its sink
	// is a real Pipe. A Pipe's path ceiling is computed for IPv6 (the wider
	// overhead the pipe may stand in for), so the sink MTU must equal
	// MaxMessageSizeFor(class, FamilyIPv6, negotiated).
	for _, class := range []Class{ClassUDP, ClassTCP, ClassTLS} {
		cfg := PipeConfig{Class: class, PathMTU: negotiated}
		sink, err := NewPipe(cfg)
		if err != nil {
			t.Fatalf("%s: NewPipe: %v", class, err)
		}
		mtu := sink.MaxMessageSize()
		want := MaxMessageSizeFor(class, FamilyIPv6, negotiated)
		if mtu != want {
			t.Fatalf("%s: sink MTU %d != MaxMessageSizeFor(IPv6, negotiated) %d",
				class, mtu, want)
		}

		// Exactly at the sink MTU is accepted and delivered: the boundary is
		// inclusive, not off-by-one narrower.
		exact := make([]byte, mtu)
		if err := sink.Deliver(exact); err != nil {
			t.Fatalf("%s: a frame exactly at sink MTU %d was refused: %v", class, mtu, err)
		}
		st := sink.Stats()
		if st.Delivered != 1 || st.RecvErrors != 0 {
			t.Fatalf("%s: boundary frame: Delivered=%d RecvErrors=%d, want 1/0",
				class, st.Delivered, st.RecvErrors)
		}

		// One byte over the sink MTU is refused and must never reach the sink
		// as a message — no frame exceeds the sink MTU.
		over := make([]byte, mtu+1)
		if err := sink.Deliver(over); !errors.Is(err, ErrMessageTooLarge) {
			t.Fatalf("%s: a frame over sink MTU (%d+1) was not refused as ErrMessageTooLarge: %v",
				class, mtu, err)
		}
		st = sink.Stats()
		if st.Delivered != 1 || st.RecvErrors != 1 {
			t.Fatalf("%s: over-MTU frame: Delivered=%d RecvErrors=%d, want 1/1 (delivered must not move)",
				class, st.Delivered, st.RecvErrors)
		}

		sink.Close()
	}
}

// TestSizingBindsPathMTU1450PayloadToTheNegotiatedLimit is silent-refusal #3's
// sizing half, made concrete at the fleet-default path MTU.
//
// Two ends that both claim 1450 negotiate to 1450 (session.NegotiatedPathMTU) —
// the only number at which a session can carry for both — and that is the number
// the driver permits a session to proceed on. So the largest datagram payload a
// carrier may emit is bound to that negotiated limit: exactly
// session.MaxMessageSizeForPath(1450, overhead), and never a payload sized to a
// wider, unreconciled local number. A payload looser than the negotiated limit
// would be the black hole that fails OPEN: the narrow end refuses the full-size
// message while both gates report carrying.
func TestSizingBindsPathMTU1450PayloadToTheNegotiatedLimit(t *testing.T) {
	t.Parallel()

	const pathMTU = DefaultPathMTU // 1450
	negotiated, both := session.NegotiatedPathMTU(pathMTU, pathMTU)
	if !both || negotiated != pathMTU {
		t.Fatalf("harness bug: %d/%d should negotiate to %d", pathMTU, pathMTU, pathMTU)
	}

	// The positive binding: at the negotiated 1450, the maximum datagram payload
	// each carrier may emit is exactly the payload that limit allows.
	for _, class := range []Class{ClassUnknown, ClassUDP, ClassTCP, ClassTLS} {
		for _, family := range []Family{FamilyUnknown, FamilyIPv4, FamilyIPv6} {
			bound := MaxMessageSizeFor(class, family, negotiated)
			want := session.MaxMessageSizeForPath(negotiated, Overhead(class, family))
			if bound != want {
				t.Fatalf("%s/%s at negotiated %d MTU: max datagram payload %d is not equal to the negotiated-limit payload %d",
					class, family, negotiated, bound, want)
			}
		}
	}

	// The negative control that makes the binding mean something: a wider local
	// planning number must not loosen it. Sizing (wrongly) to a local 1500 has
	// to grant a LARGER payload than the negotiated 1450; if the two were equal,
	// the negotiated limit would not be binding at all and a mutation that makes
	// the sizing ignore the path MTU would sail through unnoticed.
	wider, both := session.NegotiatedPathMTU(1500, pathMTU)
	if !both || wider != pathMTU {
		t.Fatalf("harness bug: 1500/1450 should negotiate down to 1450, got %d", wider)
	}
	negotiatedPayload := MaxMessageSizeFor(ClassUDP, FamilyIPv4, negotiated)
	wideOnlyPayload := MaxMessageSizeFor(ClassUDP, FamilyIPv4, 1500)
	if wideOnlyPayload <= negotiatedPayload {
		t.Fatalf("negotiated 1450 does not bind: a 1500-only sizing gives payload %d, not greater than the negotiated %d",
			wideOnlyPayload, negotiatedPayload)
	}
}

// TestFloorAtTheFleetDefaultPathMTU1450 is the same black-hole trap as
// TestFloorIsTheNarrowestNotTheDialled, at the fleet default.
//
// DefaultPathMTU is 1450, the number every host entry point resolves a missing
// path_mtu to. The floor there must be the narrowest class (TLS over IPv6), not
// the class the session dialled, or a migration onto the narrow carrier black
// holes every full-size flow while both gates report carrying.
func TestFloorAtTheFleetDefaultPathMTU1450(t *testing.T) {
	t.Parallel()
	const mtu = DefaultPathMTU // 1450
	udp4 := MaxMessageSizeFor(ClassUDP, FamilyIPv4, mtu)
	tls6 := MaxMessageSizeFor(ClassTLS, FamilyIPv6, mtu)

	floor := Floor(mtu, ClassUDP, ClassTCP, ClassTLS)
	if floor != tls6 {
		t.Fatalf("floor at the fleet default is %d, want the narrowest (%d, TLS over IPv6)", floor, tls6)
	}
	if floor >= udp4 {
		t.Fatalf("floor %d is not below the widest carrier %d; the test proves nothing", floor, udp4)
	}
	// The gap is the same 84 bytes as at any other MTU: the amount by which a
	// session sized to UDP/IPv4 overruns a TLS/IPv6 carrier.
	if got := udp4 - floor; got != 84 {
		t.Fatalf("the UDP/IPv4 to TLS/IPv6 gap at the fleet default is %d bytes, expected 84", got)
	}
	// The floor is not being masked by session.MessageFloor: at 1450 the
	// narrowest message size sits well above the floor-clamp, so the equality
	// above is about the real arithmetic and not a wall the clamp hid behind.
	if floor <= session.MessageFloor() {
		t.Fatalf("floor %d not above the message floor %d; the clamp makes the test vacuous", floor, session.MessageFloor())
	}
	// At the fleet default the floor still carries inner IPv6 — the whole point
	// of choosing 1450 over the 1421 edge. The inner MTU must meet the RFC 8200
	// 1280-byte minimum, or a fleet-default plan can never promote.
	if inner := InnerMTU(floor); inner < 1280 {
		t.Fatalf("floor inner MTU %d is below the IPv6 1280 floor; 1450 fails to promote", inner)
	}
}

// TestMaxDatagramAboveTheCeilingIsRefused pins the size ceiling the rest of the
// package depends on.
//
// The inner length field in winn3/core can express at most
// core.MaxTransportPayload bytes, so no carrier may emit a datagram above it.
// The clamp lives in session.MaxMessageSizeForPath, which MaxMessageSizeFor
// delegates to; this test makes the refusal explicit at the carrier's own
// surface and at the checkSize seam, so a widened path MTU can never loosen it.
func TestMaxDatagramAboveTheCeilingIsRefused(t *testing.T) {
	t.Parallel()
	ceiling := core.MaxTransportPayload

	// Positive: no class/family may produce a max datagram above the ceiling,
	// even for a path MTU so wide the wire could never present it.
	for _, class := range []Class{ClassUnknown, ClassUDP, ClassTCP, ClassTLS} {
		for _, family := range []Family{FamilyUnknown, FamilyIPv4, FamilyIPv6} {
			got := MaxMessageSizeFor(class, family, 1<<20)
			if got > ceiling {
				t.Fatalf("%s/%s: max datagram %d exceeds the %d-byte ceiling", class, family, got, ceiling)
			}
			if got != ceiling {
				t.Fatalf("%s/%s: max datagram %d did not clamp to the %d-byte ceiling", class, family, got, ceiling)
			}
			// Negative control: at the fleet default the same class is well
			// below the ceiling, so the clamp above is load-bearing and not a
			// constant the sizing always returns.
			atDefault := MaxMessageSizeFor(class, family, DefaultPathMTU)
			if atDefault >= ceiling {
				t.Fatalf("%s/%s: at the fleet default the max datagram %d already hit the ceiling; the clamp control is vacuous", class, family, atDefault)
			}
		}
	}

	// The same rule at the carrier seam: a size above the ceiling is refused,
	// not silently truncated, and exactly-at-the-ceiling is allowed.
	if err := checkSize(ceiling+1, ceiling); !errors.Is(err, ErrSizeAbovePath) {
		t.Fatalf("checkSize(ceiling+1, ceiling) = %v, want ErrSizeAbovePath", err)
	}
	if err := checkSize(ceiling, ceiling); err != nil {
		t.Fatalf("checkSize exactly at the ceiling was refused: %v", err)
	}
}

// TestOverheadTable pins the arithmetic that the rest of the package depends on.
//
// These numbers are load-bearing in a way that is easy to lose: 20 bytes of
// difference between the two address families is the difference between a
// message that fits the IPv6 minimum link MTU and one that fragments, and a
// fragmented Winn3 message is both widely dropped and a distinctive fingerprint.
func TestOverheadTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class  Class
		family Family
		want   int
		note   string
	}{
		{ClassUDP, FamilyIPv4, 28, "IPv4 20 + UDP 8"},
		{ClassUDP, FamilyIPv6, 48, "IPv6 40 + UDP 8"},
		{ClassTCP, FamilyIPv4, 70, "IPv4 20 + TCP 32 + sealed length 18"},
		{ClassTCP, FamilyIPv6, 90, "IPv6 40 + TCP 32 + sealed length 18"},
		{ClassTLS, FamilyIPv4, 92, "IPv4 20 + TCP 32 + TLS record 22 + sealed length 18"},
		{ClassTLS, FamilyIPv6, 112, "IPv6 40 + TCP 32 + TLS record 22 + sealed length 18"},
	}
	for _, c := range cases {
		if got := Overhead(c.class, c.family); got != c.want {
			t.Errorf("%s/%s: got %d, want %d (%s)", c.class, c.family, got, c.want, c.note)
		}
	}
	// The UDP overheads must agree with the session lane's own constants, which
	// are the numbers the DefaultMaxMessageSize the whole tree depends on was
	// derived from.
	if got, want := Overhead(ClassUDP, FamilyIPv6), session.CarrierOverheadUDPIPv6; got != want {
		t.Errorf("UDP/IPv6 overhead %d disagrees with session's %d", got, want)
	}
	if got, want := Overhead(ClassUDP, FamilyIPv4), session.CarrierOverheadUDPIPv4; got != want {
		t.Errorf("UDP/IPv4 overhead %d disagrees with session's %d", got, want)
	}
}

// TestUnknownIsChargedTheWorstCase pins the asymmetry.
//
// Over-reserving costs payload; under-reserving fragments. So an unknown class
// or family must never be cheaper than the most expensive thing it could turn
// out to be. The mistake this catches is the natural one: making ClassUnknown
// fall through to the UDP branch of a switch, which under-reserves 84 bytes.
func TestUnknownIsChargedTheWorstCase(t *testing.T) {
	t.Parallel()
	worst := Overhead(ClassTLS, FamilyIPv6)
	if got := Overhead(ClassUnknown, FamilyUnknown); got != worst {
		t.Fatalf("unknown/unknown charges %d, want the worst case %d", got, worst)
	}
	if got := Overhead(ClassUDP, FamilyUnknown); got != Overhead(ClassUDP, FamilyIPv6) {
		t.Fatal("an unknown family is not charged the IPv6 header")
	}
}

// TestFloorIsTheNarrowestNotTheDialled is §2.4 of the tun lane's handoff.
//
// This is the black-hole trap. A session sized for the carrier it dialled and
// then migrated onto a narrower one keeps reporting "up" while every full-size
// flow stalls — small packets work, large transfers do not, and the report comes
// from a country where nobody can attach a debugger.
func TestFloorIsTheNarrowestNotTheDialled(t *testing.T) {
	t.Parallel()
	const mtu = 1280
	udp := MaxMessageSizeFor(ClassUDP, FamilyIPv4, mtu)
	tls6 := MaxMessageSizeFor(ClassTLS, FamilyIPv6, mtu)

	floor := Floor(mtu, ClassUDP, ClassTLS)
	if floor != tls6 {
		t.Fatalf("floor is %d, want the narrowest (%d, TLS over IPv6)", floor, tls6)
	}
	if floor >= udp {
		t.Fatalf("floor %d is not below the widest carrier %d; the test proves nothing", floor, udp)
	}
	// The gap is the whole point: 84 bytes per full-size packet is the amount by
	// which a session sized to UDP/IPv4 would overrun a TLS/IPv6 carrier.
	if got := udp - floor; got != 84 {
		t.Fatalf("the UDP/IPv4 to TLS/IPv6 gap is %d bytes, expected 84", got)
	}
}

// TestFloorCoversBothFamilies is the same trap one layer along.
//
// A migration can change address family as easily as it changes class — a
// gateway reachable over both, or a handset moving from a v4-only cellular
// network to a v6-only one. A floor computed for the family in use black holes
// on exactly the same day.
func TestFloorCoversBothFamilies(t *testing.T) {
	t.Parallel()
	const mtu = 1500
	if got, want := Floor(mtu, ClassUDP), MaxMessageSizeFor(ClassUDP, FamilyIPv6, mtu); got != want {
		t.Fatalf("single-class floor is %d, want the IPv6 figure %d", got, want)
	}
	if Floor(mtu, ClassUDP) >= MaxMessageSizeFor(ClassUDP, FamilyIPv4, mtu) {
		t.Fatal("the floor took the IPv4 figure; a v4-to-v6 move would black hole")
	}
}

// TestFloorWithNoClassesIsConservative pins the "we do not know yet" answer.
func TestFloorWithNoClassesIsConservative(t *testing.T) {
	t.Parallel()
	const mtu = 1280
	if got, want := Floor(mtu), MaxMessageSizeFor(ClassTLS, FamilyIPv6, mtu); got != want {
		t.Fatalf("empty floor is %d, want the worst case %d", got, want)
	}
}

// TestPlanFloorAnswersTheIPv6QuestionForTheNarrowestClass.
//
// A tunnel that carried inner IPv6 until it failed over, and then black holed
// every full-size v6 packet, is the original trap wearing a v6 hat. So the
// answer is computed for the narrowest class in the plan, not the dialled one.
func TestPlanFloorAnswersTheIPv6QuestionForTheNarrowestClass(t *testing.T) {
	t.Parallel()
	pf := NewPlanFloor(1280, ClassUDP, ClassTLS)
	if pf.MessageSize != Floor(1280, ClassUDP, ClassTLS) {
		t.Fatalf("plan floor message size %d disagrees with Floor", pf.MessageSize)
	}
	if pf.InnerMTU != session.InnerMTU(pf.MessageSize) {
		t.Fatalf("plan inner MTU %d disagrees with session.InnerMTU", pf.InnerMTU)
	}
	if pf.InnerIPv6 {
		t.Fatal("inner IPv6 claimed possible at a 1280-byte outer path; it is not, for any tunnel")
	}
	if want := session.MinPathMTUForInnerIPv6(Overhead(ClassTLS, FamilyIPv6)); pf.MinPathMTUForInnerIPv6 != want {
		t.Fatalf("inner-IPv6 path requirement %d, want the narrowest class's %d",
			pf.MinPathMTUForInnerIPv6, want)
	}
	// A UDP-only plan needs less path, and the two must not be the same number
	// or the test above is not measuring the narrowest class at all.
	udpOnly := NewPlanFloor(1280, ClassUDP)
	if udpOnly.MinPathMTUForInnerIPv6 >= pf.MinPathMTUForInnerIPv6 {
		t.Fatal("a UDP-only plan does not need less path than a plan including TLS")
	}
	// A path wide enough turns the answer over.
	wide := NewPlanFloor(1600, ClassUDP, ClassTLS)
	if !wide.InnerIPv6 {
		t.Fatalf("inner IPv6 still refused at a 1600-byte path (inner MTU %d)", wide.InnerMTU)
	}
}

// TestFamilyOfReadsTheAddressNotTheNetwork.
//
// A "udp" or "tcp" network resolves to either family. A carrier that inferred
// IPv4 from the network string would under-reserve 20 bytes on every IPv6 path.
func TestFamilyOfReadsTheAddressNotTheNetwork(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr net.Addr
		want Family
	}{
		{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, FamilyIPv4},
		{&net.UDPAddr{IP: net.IPv6loopback, Port: 1}, FamilyIPv6},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, FamilyIPv4},
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 1}, FamilyIPv6},
		{&net.IPAddr{IP: net.IPv6loopback}, FamilyIPv6},
		{&net.UDPAddr{Port: 1}, FamilyUnknown},
		{nil, FamilyUnknown},
		{stringAddr("[::1]:443"), FamilyIPv6},
		{stringAddr("127.0.0.1:443"), FamilyIPv4},
		{stringAddr("not-an-address"), FamilyUnknown},
		{stringAddr("example.invalid:443"), FamilyUnknown},
	}
	for _, c := range cases {
		if got := FamilyOf(c.addr); got != c.want {
			t.Errorf("FamilyOf(%v) = %s, want %s", c.addr, got, c.want)
		}
	}
}

// stringAddr is a net.Addr that is not one of the concrete types, exercising the
// SplitHostPort fallback.
type stringAddr string

func (s stringAddr) Network() string { return "custom" }
func (s stringAddr) String() string  { return string(s) }

// TestClassPredicates pins the classification the policy layer reads.
//
// It must agree in meaning with datapath.CarrierTransportOf, which this package
// deliberately does not import: winn3/ is standalone and may not depend on
// datapath/. Unknown must not promise survival — the safe default for "we cannot
// tell" is no.
func TestClassPredicates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class    Class
		stream   bool
		survives bool
		name     string
	}{
		{ClassUnknown, false, false, "unknown"},
		{ClassUDP, false, false, "udp"},
		{ClassTCP, true, true, "tcp"},
		{ClassTLS, true, true, "tls"},
	}
	for _, c := range cases {
		if got := c.class.Stream(); got != c.stream {
			t.Errorf("%s Stream() = %v, want %v", c.name, got, c.stream)
		}
		if got := c.class.SurvivesUDPBlock(); got != c.survives {
			t.Errorf("%s SurvivesUDPBlock() = %v, want %v", c.name, got, c.survives)
		}
		if got := c.class.String(); got != c.name {
			t.Errorf("String() = %q, want %q", got, c.name)
		}
	}
}

// TestInnerMTUAndIPv6HelpersDelegate keeps the two re-exports honest.
func TestInnerMTUAndIPv6HelpersDelegate(t *testing.T) {
	t.Parallel()
	for _, n := range []int{session.MessageFloor(), 1168, 1232, 1443} {
		if got, want := InnerMTU(n), session.InnerMTU(n); got != want {
			t.Fatalf("InnerMTU(%d) = %d, session says %d", n, got, want)
		}
	}
	for _, class := range []Class{ClassUDP, ClassTCP, ClassTLS} {
		for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
			got := MinPathMTUForInnerIPv6(class, family)
			want := session.MinPathMTUForInnerIPv6(Overhead(class, family))
			if got != want {
				t.Fatalf("%s/%s: %d, session says %d", class, family, got, want)
			}
		}
	}
	// The two numbers the session lane pinned must still fall out of this.
	if got := MinPathMTUForInnerIPv6(ClassUDP, FamilyIPv6); got != 1357 {
		t.Fatalf("UDP/IPv6 inner-IPv6 path requirement is %d, want 1357", got)
	}
	if got := MinPathMTUForInnerIPv6(ClassUDP, FamilyIPv4); got != 1337 {
		t.Fatalf("UDP/IPv4 inner-IPv6 path requirement is %d, want 1337", got)
	}
}

// TestFamilyStringsAreStable keeps status output readable.
func TestFamilyStringsAreStable(t *testing.T) {
	t.Parallel()
	for f, want := range map[Family]string{
		FamilyUnknown: "unknown", FamilyIPv4: "ipv4", FamilyIPv6: "ipv6",
		Family(9): "unknown",
	} {
		if got := f.String(); got != want {
			t.Errorf("Family(%d).String() = %q, want %q", f, got, want)
		}
	}
	if got := Class(9).String(); got != "unknown" {
		t.Errorf("Class(9).String() = %q, want unknown", got)
	}
}

// TestMTUOverheadVectorAccountsForThePath pins the max-inner-datagram
// accounting as a vector over (class, family, pathMTU).
//
// A full-size Winn3 message a carrier emits wraps in Overhead(class, family)
// bytes of header before it reaches the IP layer, so the largest inner datagram
// a path of pathMTU bytes may carry is pathMTU − overhead. The accounting is
// exact when the two are equal — every reserved overhead byte plus the datagram
// itself fills the path with no byte left over and no byte overrunning it.
// Over-reserving leaves a byte undelivered on a metered connection; under-
// reserving produces a fragmented packet, both dropped by the middleboxes this
// protocol exists to get past and a distinctive fingerprint.
//
// The expected overhead for every (class, family) is HARDCODED here, an
// independent ground truth and not a call into this package's own Overhead().
// The first draft of this test derived `want` from Overhead() inside the package
// under test; a mutation that changed a header constant then shifted `want` and
// `got` together and the vector stayed green for every mutation. Deriving the
// expected datagram from a hardcoded table is what gives these rows their teeth:
// an off-by-one in ipv4HeaderBytes, ipv6HeaderBytes, udpHeaderBytes,
// tcpHeaderBytes, tlsRecordBytes or LengthRecordOverhead lands as a row off by
// exactly that number.
//
// It runs each class across both families and the whole practical MTU band — the
// RFC 8200 1280 floor, the 1280..1420 dead zone on both its edges (1421 is where
// it ends), the fleet default 1450, the classic 1500, and jumbo. Every MTU is
// chosen clear of the session floor/ceiling clamps, so a failure is arithmetic in
// this package's constants, never a clamp the session layer absorbed.
func TestMTUOverheadVectorAccountsForThePath(t *testing.T) {
	t.Parallel()

	// Independent, hardcoded overhead per class/family. Kept beside the
	// TestOverheadTable table on purpose; these are the same six totals, asserted
	// here through MaxMessageSizeFor rather than Overhead.
	var wantOverhead = map[Class]map[Family]int{
		ClassUDP: {FamilyIPv4: 28, FamilyIPv6: 48},
		ClassTCP: {FamilyIPv4: 70, FamilyIPv6: 90},
		ClassTLS: {FamilyIPv4: 92, FamilyIPv6: 112},
	}

	mtus := []int{1280, 1325, 1357, 1420, 1421, 1450, 1472, 1492, 1500, 9000}

	for class := range wantOverhead {
		for family := range wantOverhead[class] {
			ov := wantOverhead[class][family]
			if got := Overhead(class, family); got != ov {
				t.Fatalf("%s/%s: Overhead() reports %d but the vector ground truth is %d; the constant changed", class, family, got, ov)
			}
			for _, mtu := range mtus {
				// Harness guard: exact datagram == MTU − overhead only holds in
				// the unclamped band. All MTUs above sit clear of the session
				// floor (29) and ceiling (65535) by design; this catches a future
				// MTU that is not clear and would otherwise read as a real break.
				if mtu-ov < session.MessageFloor() || mtu-ov > core.MaxTransportPayload {
					t.Fatalf("harness bug: %s/%s at MTU %d overhead %d falls outside the unclamped band [%d, %d]",
						class, family, mtu, ov, session.MessageFloor(), core.MaxTransportPayload)
				}
				want := mtu - ov
				if got := MaxMessageSizeFor(class, family, mtu); got != want {
					t.Fatalf("%s/%s at MTU %d: max datagram %d, want exactly %d (MTU minus the %d-byte overhead); off by %d",
						class, family, mtu, got, want, ov, mtu-(got+ov))
				}
			}
		}
	}

	// A contiguous sweep of the deliberate 1450 size as well as isolated points,
	// so no off-by-one hides in the gap between two table rows.
	for class := range wantOverhead {
		for family := range wantOverhead[class] {
			ov := wantOverhead[class][family]
			for mtu := 1280; mtu <= 1500; mtu++ {
				if mtu-ov < session.MessageFloor() {
					t.Fatalf("harness bug: %s/%s sweep MTU %d is below the unclamped band", class, family, mtu)
				}
				want := mtu - ov
				if got := MaxMessageSizeFor(class, family, mtu); got != want {
					t.Fatalf("%s/%s sweep at MTU %d: max datagram %d, want exactly %d", class, family, mtu, got, want)
				}
			}
		}
	}
}
