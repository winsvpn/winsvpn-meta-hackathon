package core

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
)

// Tests for the Elligator2 ephemeral codec.
//
// The design document deferred Elligator2 out of v1 with a specific reason: a
// hand-rolled Elligator2 is a serious correctness risk. These tests are the
// answer to that reason, so they are written to fail rather than to pass:
// every property that could be silently wrong is checked against something that
// does not share the implementation's assumptions — the inverse map against the
// forward map, the torsion table against published constants, the uniformity
// against the detector that already has teeth, and the whole codec against a
// real key agreement.

// ellSeeded is a deterministic reader per case, so a failure is replayable.
func ellSeeded(name string) *detReader { return newDetReader("elligator-" + name) }

// --- the map -----------------------------------------------------------------

// TestElligatorMapIsTotalAndLandsOnTheCurve.
//
// Totality is the whole point of the forward direction: if any 32-byte string
// were rejected, an observer could feed candidate bytes to a decoder and learn
// something from which ones it refused. There is no such input.
//
// Landing on the curve rather than on its twist is checked at the same time
// because it is what makes the branch selection correct: g(x2) = Z r^2 g(x1)
// and Z r^2 is a non-square, so exactly one branch yields a square and the
// implementation must pick that one.
func TestElligatorMapIsTotalAndLandsOnTheCurve(t *testing.T) {
	r := ellSeeded("total")
	for i := 0; i < 600; i++ {
		wire := make([]byte, KeySize)
		if _, err := r.Read(wire); err != nil {
			t.Fatal(err)
		}
		out, err := Elligator2Codec.DecodePublic(wire)
		if err != nil {
			t.Fatalf("sample %d: the forward map refused an input: %v", i, err)
		}
		if len(out) != KeySize {
			t.Fatalf("sample %d: forward map produced %d bytes", i, len(out))
		}
		if !ellIsSquare(ellCurveG(ellFromWire(out))) {
			t.Fatalf("sample %d: mapped point is on the twist, not the curve", i)
		}
	}

	// Explicit edge inputs, including the ones a fuzzer would find first.
	for _, tc := range []struct{ name, wire string }{
		{"all zero", strings.Repeat("00", KeySize)},
		{"all ones", strings.Repeat("ff", KeySize)},
		{"top two bits only", strings.Repeat("00", KeySize-1) + "c0"},
		{"low bit only", "01" + strings.Repeat("00", KeySize-1)},
	} {
		wire := mustHex(t, tc.wire)
		out, err := Elligator2Codec.DecodePublic(wire)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !ellIsSquare(ellCurveG(ellFromWire(out))) {
			t.Fatalf("%s: mapped point is not on the curve", tc.name)
		}
	}
}

// TestElligatorTopTwoBitsAreIgnoredByTheMap: bits 254 and 255 carry sender
// randomness and nothing else, so flipping them must not move the point. If the
// map ever started reading them, the representative would silently stop being
// uniform in its top two bits.
func TestElligatorTopTwoBitsAreIgnoredByTheMap(t *testing.T) {
	r := ellSeeded("topbits")
	for i := 0; i < 64; i++ {
		wire := make([]byte, KeySize)
		if _, err := r.Read(wire); err != nil {
			t.Fatal(err)
		}
		wire[KeySize-1] &^= 0xC0
		base, err := Elligator2Codec.DecodePublic(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, top := range []byte{0x40, 0x80, 0xC0} {
			alt := append([]byte(nil), wire...)
			alt[KeySize-1] |= top
			got, err := Elligator2Codec.DecodePublic(alt)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, base) {
				t.Fatalf("sample %d: top bits %02X changed the decoded point", i, top)
			}
		}
	}
}

// TestElligatorRoundTripsBothWays checks the two directions against each other,
// which is the only check available that does not share their assumptions.
//
// Forward-then-inverse: every representative must be recoverable from the point
// it names, on at least one branch, and it must come back byte-identical.
//
// Inverse-then-forward: every representative the inverse produces must map back
// to the exact point it was derived from, on both branches, and under all four
// values of the free top bits.
func TestElligatorRoundTripsBothWays(t *testing.T) {
	r := ellSeeded("roundtrip")

	for i := 0; i < 400; i++ {
		wire := make([]byte, KeySize)
		if _, err := r.Read(wire); err != nil {
			t.Fatal(err)
		}
		wire[KeySize-1] &^= 0xC0
		want := ellFromWire(wire)

		u := ellFromWire(elligatorMap(wire))
		recovered := false
		for branch := 0; branch < 2; branch++ {
			got, ok := elligatorUnmap(u, branch)
			if ok && got.Cmp(want) == 0 {
				recovered = true
			}
		}
		if !recovered {
			t.Fatalf("sample %d: no branch recovers the representative %x", i, wire)
		}
	}

	withRep := 0
	for i := 0; i < 400; i++ {
		var seed [KeySize]byte
		if _, err := r.Read(seed[:]); err != nil {
			t.Fatal(err)
		}
		sk, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		pub := sk.PublicKey().Bytes()
		u := ellFromWire(pub)

		var okCount int
		for branch := 0; branch < 2; branch++ {
			rep, ok := elligatorUnmap(u, branch)
			if !ok {
				continue
			}
			okCount++
			if rep.Cmp(ellHalfP) > 0 {
				t.Fatalf("sample %d branch %d: representative is not canonical", i, branch)
			}
			for top := 0; top < 4; top++ {
				enc := ellToWire(rep)
				enc[KeySize-1] |= byte(top) << 6
				back, err := Elligator2Codec.DecodePublic(enc)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(back, pub) {
					t.Fatalf("sample %d branch %d top %d: forward(inverse(u)) != u", i, branch, top)
				}
			}
		}
		// The algebra says the two branches are squares together or not at all,
		// because their product is 1/Z^2. A one-branch result would mean the
		// derivation is wrong and the sender's branch bit is not free.
		if okCount == 1 {
			t.Fatalf("sample %d: exactly one branch inverted; the branch bit is not free", i)
		}
		if okCount == 2 {
			withRep++
		}
	}

	// About half of all public keys have a representative. Far from half in
	// either direction would mean the residuosity test is inverted or constant,
	// and the rejection loop would then be doing nothing.
	if withRep < 140 || withRep > 260 {
		t.Fatalf("%d/400 public keys had a representative; expected near 200", withRep)
	}
}

// TestElligatorBranchRepresentativesAreAlgebraicallyLinked pins the one
// algebraic fact the round-trip tests cannot see.
//
// The two preimages a point can have are not arbitrary: branch 0 returns
// r0 with r0^2 = -u/(Z(u+A)) and branch 1 returns r1 with r1^2 = -(u+A)/(Zu).
// Their product of squares is
//
//	r0^2 * r1^2 = u(u+A) / (Z^2 u (u+A)) = 1/Z^2   (exactly, over F_p)
//
// so for every u that has a representative at all, the two representatives are
// related by a FIXED multiplier whose square is 1/Z^2 — an algebraic rotation
// that connects the two branches. The existing round-trip test only checks that
// each branch, individually, maps back to u; it never checks the relation
// BETWEEN the two representatives. A sign error or an inverted branch formula
// in either preimage (u vs u+A, num vs den) would survive the round trip but
// break this identity.
//
// The identity is stated with the squares, not the representatives, because
// each representative is canonicalised to [0, (p-1)/2], and canonicalisation
// flips a sign independently per branch. Squaring removes both signs, so the
// identity holds before and after canonicalisation and the test is robust to
// it rather than coupled to it.

func TestElligatorBranchRepresentativesAreAlgebraicallyLinked(t *testing.T) {
	invZ2 := ellInv(ellMul(ellZ, ellZ))
	if invZ2 == nil {
		t.Fatal("1/Z^2 is degenerate; Z = 2 cannot be inverted")
	}

	r := ellSeeded("branch-link")
	checked := 0
	for i := 0; i < 400; i++ {
		var seed [KeySize]byte
		if _, err := r.Read(seed[:]); err != nil {
			t.Fatal(err)
		}
		sk, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		u := ellFromWire(sk.PublicKey().Bytes())

		r0, ok0 := elligatorUnmap(u, 0)
		r1, ok1 := elligatorUnmap(u, 1)
		if !ok0 || !ok1 {
			// The algebra says the two branches are squares together or not at
			// all (their product is 1/Z^2, a square), so a one-sided preimage
			// is impossible. Skip only the ~half of keys with no preimage.
			continue
		}
		checked++

		if r0.Cmp(r1) == 0 {
			t.Fatalf("sample %d: both branches returned the same representative; the "+
				"branch bit carries no freedom and rep0^2*rep1^2 would not be 1/Z^2", i)
		}

		got := ellMul(ellMul(r0, r0), ellMul(r1, r1))
		if got.Cmp(invZ2) != 0 {
			t.Fatalf("sample %d: r0^2*r1^2 = %x; expected %x = 1/Z^2. One of the two "+
				"preimage formulas (u vs u+A, or num vs den) has drifted, which breaks "+
				"the branch symmetry the sender's branch bit depends on", i, got, invZ2)
		}
	}

	if checked < 140 {
		t.Fatalf("only %d/400 random u-coordinates had a preimage; expected near 200. "+
			"The residuosity test is inverted or constant and this test is not exercising "+
			"the branch it exists for", checked)
	}
}

// TestElligatorTorsionTableIsTheEightTorsion checks the DERIVED table against
// facts it cannot accidentally satisfy, and then against published constants.
//
// The published cross-check is the important half. The derivation in
// ellTorsion() is original to this file; the two order-8 u-coordinates below are
// the ones that appear in every X25519 small-order-point blacklist. Agreement
// between an independent derivation and a published constant is the strongest
// evidence available here that the table is right, and a table that was subtly
// wrong — a point on the twist, say — would corrupt every ephemeral it touched
// and would look like an intermittent handshake failure rather than like a bad
// constant.
func TestElligatorTorsionTableIsTheEightTorsion(t *testing.T) {
	tab := ellTorsion()

	if !tab[0].inf {
		t.Fatal("T[0] must be the identity")
	}
	for i := 1; i < 8; i++ {
		if tab[i].inf {
			t.Fatalf("T[%d] is the identity", i)
		}
		if ellMul(tab[i].v, tab[i].v).Cmp(ellCurveG(tab[i].u)) != 0 {
			t.Fatalf("T[%d] is not on the curve", i)
		}
	}

	// 4*Q8 is the order-two point and 8*Q8 is the identity.
	if tab[4].u.Sign() != 0 || tab[4].v.Sign() != 0 {
		t.Fatalf("T[4] is %x,%x; expected the order-two point (0,0)", tab[4].u, tab[4].v)
	}
	if !ellPointAdd(tab[7], tab[1]).inf {
		t.Fatal("8*Q8 is not the identity")
	}
	// The order-four points sit at u = 1.
	for _, i := range []int{2, 6} {
		if tab[i].u.Cmp(ellOne) != 0 {
			t.Fatalf("T[%d].u is %x; the order-four points are at u = 1", i, tab[i].u)
		}
	}
	// The eight points are distinct as points.
	seen := map[string]bool{}
	for i := 1; i < 8; i++ {
		k := tab[i].u.String() + "/" + tab[i].v.String()
		if seen[k] {
			t.Fatalf("T[%d] duplicates an earlier point", i)
		}
		seen[k] = true
	}

	// Independent cross-check against the published low-order u-coordinates.
	published := map[string]bool{
		"325606250916557431795983626356110631294008115727848805560023387167927233504":   true,
		"39382357235489614581723060781553021112529911719440698176882885853963445705823": true,
	}
	got := map[string]bool{}
	for _, i := range []int{1, 3, 5, 7} {
		got[tab[i].u.String()] = true
	}
	if len(got) != 2 {
		t.Fatalf("expected two distinct order-eight u-coordinates, got %d", len(got))
	}
	for u := range got {
		if !published[u] {
			t.Fatalf("derived order-eight u-coordinate %s is not a published low-order point", u)
		}
	}
}

// --- the reason the torsion is there -----------------------------------------

// ellGroupOrder is the order of the curve25519 prime-order subgroup,
// L = 2^252 + 27742317777372353535851937790883648493.
func ellGroupOrder() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("bad group order literal")
	}
	return l
}

// ellScalarMul is double-and-add on the affine Montgomery curve. It is
// test-only and deliberately naive: it exists to measure a property of the
// codec's output, not to be fast or constant time.
func ellScalarMul(k *big.Int, p ellPoint) ellPoint {
	acc := ellPoint{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = ellPointAdd(acc, acc)
		if k.Bit(i) == 1 {
			acc = ellPointAdd(acc, p)
		}
	}
	return acc
}

// ellPointFromU lifts a u-coordinate to a point, choosing either v.
func ellPointFromU(t *testing.T, u []byte) ellPoint {
	t.Helper()
	x := ellFromWire(u)
	v := ellSqrt(ellCurveG(x))
	if v == nil {
		t.Fatalf("u %x is not on the curve", u)
	}
	return ellPoint{u: x, v: v}
}

// TestElligatorEphemeralIsNotConfinedToThePrimeOrderSubgroup is the test that
// makes the torsion addition load-bearing, and it is the one that would have
// caught the obvious way to write this codec wrong.
//
// A representative decodes to a curve point and ANYONE can decode one. A plain
// X25519 public key always lies in the prime-order subgroup; the point behind a
// genuinely random 32-byte string does so about one time in eight. So without a
// random torsion component, one scalar multiplication per packet separates a
// Winn3 ephemeral from random bytes with NO KEY AT ALL — which would leave the
// codec no better than the one-bit bias it exists to remove.
//
// The control half is what gives this teeth: raw X25519 public keys are checked
// by the same code and must come out at 100%.
func TestElligatorEphemeralIsNotConfinedToThePrimeOrderSubgroup(t *testing.T) {
	if testing.Short() {
		t.Skip("scalar multiplication over math/big is slow")
	}
	l := ellGroupOrder()
	const n = 96

	// Control: the v1 encoding. Every one of these must be in the subgroup, or
	// the measurement below means nothing.
	r := ellSeeded("subgroup-control")
	for i := 0; i < 24; i++ {
		e, err := generateEphemeral(r)
		if err != nil {
			t.Fatal(err)
		}
		if !ellScalarMul(l, ellPointFromU(t, e.public())).inf {
			t.Fatalf("control %d: a raw X25519 public key is not in the prime-order subgroup", i)
		}
	}

	// The codec's own output.
	inSubgroup := 0
	kg := Elligator2Codec.(EphemeralKeygen)
	gen := ellSeeded("subgroup")
	for i := 0; i < n; i++ {
		_, wire, err := kg.GenerateEphemeral(gen)
		if err != nil {
			t.Fatal(err)
		}
		u, err := Elligator2Codec.DecodePublic(wire)
		if err != nil {
			t.Fatal(err)
		}
		if ellScalarMul(l, ellPointFromU(t, u)).inf {
			inSubgroup++
		}
	}
	// Expected n/8 = 12, with a binomial standard deviation of about 3.2. A
	// codec that skipped the torsion addition would score n.
	if inSubgroup > n/2 {
		t.Fatalf("%d/%d elligator ephemerals decode into the prime-order subgroup; "+
			"a uniform 32-byte string does so about one time in eight, so this is a "+
			"keyless distinguisher and the torsion randomisation is not working", inSubgroup, n)
	}
	if inSubgroup == 0 {
		t.Fatalf("0/%d ephemerals landed in the prime-order subgroup; that is as "+
			"distinguishable as always landing in it", n)
	}
}

// TestElligatorDirtyKeysDoNotChangeTheSharedSecret asserts the property the
// torsion addition depends on, rather than assuming it: a peer clamps, so its
// scalar is a multiple of eight and 8k(P+T) = 8kP.
//
// If this were ever false the handshake would fail intermittently — for one
// torsion index in eight — which is exactly the kind of bug that reaches
// production because it passes a round-trip test seven times out of eight.
func TestElligatorDirtyKeysDoNotChangeTheSharedSecret(t *testing.T) {
	table := ellTorsion()
	r := ellSeeded("dirty-dh")

	for i := 0; i < 8; i++ {
		var mine, theirs [KeySize]byte
		if _, err := r.Read(mine[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Read(theirs[:]); err != nil {
			t.Fatal(err)
		}
		sk, err := ecdh.X25519().NewPrivateKey(mine[:])
		if err != nil {
			t.Fatal(err)
		}
		peer, err := ecdh.X25519().NewPrivateKey(theirs[:])
		if err != nil {
			t.Fatal(err)
		}

		clean := sk.PublicKey().Bytes()
		p := ellPointFromU(t, clean)

		// Every torsion index, not just the one this draw happened to pick.
		for j := 0; j < 8; j++ {
			dirty := ellPointAdd(p, table[j])
			if dirty.inf {
				t.Fatalf("sample %d torsion %d: P+T is the identity", i, j)
			}
			dirtyPub, err := ecdh.X25519().NewPublicKey(ellToWire(dirty.u))
			if err != nil {
				t.Fatalf("sample %d torsion %d: crypto/ecdh refused the dirty point: %v", i, j, err)
			}
			want, err := peer.ECDH(mustECDHPublic(t, clean))
			if err != nil {
				t.Fatal(err)
			}
			got, err := peer.ECDH(dirtyPub)
			if err != nil {
				t.Fatalf("sample %d torsion %d: peer DH failed against the dirty point: %v", i, j, err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("sample %d torsion %d: the torsion component changed the shared secret", i, j)
			}
			// And our own half of the agreement still matches.
			ours, err := sk.ECDH(peer.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ours, want) {
				t.Fatalf("sample %d torsion %d: our own DH disagrees", i, j)
			}
		}
	}
}

func mustECDHPublic(t *testing.T, b []byte) *ecdh.PublicKey {
	t.Helper()
	k, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// --- the claim the codec exists to make --------------------------------------

// ellFleetBodies returns the RECOVERED PLAINTEXT bodies of a fleet of
// initiations: the message with the admission layer stripped off.
//
// Stripping the layer is the whole point. §4.1 scopes the initiation's
// uniformity to holders of the admission key; this function models exactly the
// observer that scoping excludes, and it is also what "delete the entire
// admission layer" would leave behind.
func ellFleetBodies(t *testing.T, n int, codec EphemeralCodec, padTo int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-ell-%d", i), func(hh *harness) {
			hh.clientCf.Codec = codec
			hh.gwCf.Codec = codec
		})
		ini := h.initiator(t)
		msg, err := ini.WriteInitiation(nil, padTo)
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		body, _, _, err := verifyAdmission(msg, h.gwCf.Gateway, h.now)
		if err != nil {
			t.Fatalf("sample %d: could not strip the admission layer: %v", i, err)
		}
		out = append(out, body)
	}
	return out
}

// TestElligatorRemovesTheBiasWhiteningOnlyHid is the headline claim, measured.
//
// It runs the SAME detector that TestUniformityDetectorHasTeeth already proved
// can fail, over the un-whitened initiation body, under both codecs:
//
//   - v1 codec: the detector must object, and must name bit 7 of offset 31 of
//     the body — the X25519 top bit. That is the residual fingerprint, and it is
//     invisible only because the whitening is in front of it.
//   - Elligator2: the detector must find nothing.
//
// The first half is not decoration. It is what stops this test passing for the
// trivial reason that the detector cannot see anything at this layer, and it is
// the measured form of the sentence in doc.go that the whitening is a cost
// boundary rather than a security boundary.
func TestElligatorRemovesTheBiasWhiteningOnlyHid(t *testing.T) {
	const n = 400

	rawBodies := ellFleetBodies(t, n, DefaultEphemeralCodec, 300)
	rawViolations := uniformityViolations(rawBodies)
	if len(rawViolations) == 0 {
		t.Fatal("the v1 body showed no bias at all; either the detector stopped working " +
			"or these samples are not what they claim to be")
	}
	want := "bit 7 of offset 31"
	named := false
	for _, v := range rawViolations {
		if strings.Contains(v, want) {
			named = true
		}
	}
	if !named {
		t.Fatalf("expected the v1 body to fail at %q, the X25519 top bit; got %v", want, rawViolations)
	}

	ellBodies := ellFleetBodies(t, n, Elligator2Codec, 300)
	if v := uniformityViolations(ellBodies); len(v) != 0 {
		t.Errorf("with Elligator2 the un-whitened initiation body must be uniform "+
			"WITHOUT any key; the detector found: %v", v)
	}
}

// TestElligatorEphemeralFieldAloneIsUniform narrows the same claim to the field
// that changed, so a failure points at the codec rather than at the message.
func TestElligatorEphemeralFieldAloneIsUniform(t *testing.T) {
	kg := Elligator2Codec.(EphemeralKeygen)
	r := ellSeeded("field-uniform")
	samples := make([][]byte, 0, 1200)
	for i := 0; i < 1200; i++ {
		_, wire, err := kg.GenerateEphemeral(r)
		if err != nil {
			t.Fatal(err)
		}
		samples = append(samples, wire)
	}
	if v := uniformityViolations(samples); len(v) != 0 {
		t.Errorf("elligator representatives are not uniform: %v", v)
	}

	// And the control, so that a reader can see the difference the codec makes
	// in the one place it makes it.
	raw := make([][]byte, 0, 1200)
	rr := ellSeeded("field-uniform-raw")
	for i := 0; i < 1200; i++ {
		e, err := generateEphemeral(rr)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, e.public())
	}
	if len(uniformityViolations(raw)) == 0 {
		t.Fatal("raw X25519 public keys passed the uniformity detector; the control is broken")
	}
}

// TestElligatorGeneratedTopBitsAreUniform pins the one piece of sender
// randomness the other tests only quantify indirectly.
//
// GenerateEphemeral copies tweak bits 6-7 into bits 254 and 255 of the wire
// string (`out[KeySize-1] |= tweak[0] & 0xC0`). Those are the ONLY bytes of the
// representative that are fresh randomness rather than a function of the point:
// the canonical representative from elligatorUnmap is at most (p-1)/2 < 2^254,
// so bits 254 and 255 of a canonical representative are always zero. If that
// `|=` were ever dropped, every generated representative would carry top bits
// 00, and an observer who broke the top two bits off a fleet of initiations
// would see a constant where the codec promises one bit each of freedom.
//
// The existing TestElligatorTopTwoBitsAreIgnoredByTheMap proves the MAP discards
// the top bits; this test proves the GENERATOR actually randomises them, which
// is the direction the map test cannot see. A byte-level uniformity sweep would
// also catch a constant top pair, but only this test names the exact field, the
// expected 1/4, and the statistical band, so it fails with a specific diagnosis.
func TestElligatorGeneratedTopBitsAreUniform(t *testing.T) {
	kg := Elligator2Codec.(EphemeralKeygen)
	r := ellSeeded("topbits-gen")
	const n = 800
	counts := [4]int{}
	for i := 0; i < n; i++ {
		_, wire, err := kg.GenerateEphemeral(r)
		if err != nil {
			t.Fatal(err)
		}
		counts[(wire[KeySize-1]>>6)&0x03]++
	}
	if total := counts[0] + counts[1] + counts[2] + counts[3]; total != n {
		t.Fatalf("counted %d samples, expected %d", total, n)
	}
	// Each of the four values is Bernoulli(1/4) across independent draws, so
	// the count is Binomial(n, 1/4) with mean 200 and sd ~12.2. A four-sigma
	// band [152, 248] is so wide that a working codec cannot trip it by chance,
	// while a codec that stopped randomising the top bits scores 800 in one bin.
	const min, max = n/4 - 48, n/4 + 48
	for top := 0; top < 4; top++ {
		if counts[top] < min || counts[top] > max {
			t.Fatalf("top-two-bit value %02d occurred %d/%d times; expected ~%d. "+
				"If the codec stopped injecting tweak randomness (`out[..] |= tweak[0] & 0xC0`) "+
				"the top bits of every representative would be constant and the two bits of "+
				"sender freedom the codec documents would be gone", top, counts[top], n, n/4)
		}
	}
}

// --- the codec as a seam -----------------------------------------------------

// TestElligatorHandshakeRoundTrip: the whole exchange, both ends on the codec,
// through to transport traffic. Anything the codec got wrong about the point
// encoding lands here as a decryption failure.
func TestElligatorHandshakeRoundTrip(t *testing.T) {
	for i := 0; i < 16; i++ {
		h := newHarnessSeeded(t, fmt.Sprintf("-ell-rt-%d", i), func(hh *harness) {
			hh.clientCf.Codec = Elligator2Codec
			hh.gwCf.Codec = Elligator2Codec
		})
		cli, gw := h.completeHandshake(t)
		sealed, err := cli.Seal([]byte("elligator"), 0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := gw.Open(sealed)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if string(got) != "elligator" {
			t.Fatalf("run %d: payload is %q", i, got)
		}
		back, err := gw.Seal([]byte("ok"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := cli.Open(back); err != nil || string(got) != "ok" {
			t.Fatalf("run %d: reverse direction: %q %v", i, got, err)
		}
	}
}

// TestElligatorChangesNoLength: WireSize is unchanged, so every geometry
// constant in the design document still holds. A codec that changed the length
// would be a wire break dressed up as an obfuscation improvement.
func TestElligatorChangesNoLength(t *testing.T) {
	if Elligator2Codec.WireSize() != DefaultEphemeralCodec.WireSize() {
		t.Fatalf("wire size %d differs from the v1 codec's %d",
			Elligator2Codec.WireSize(), DefaultEphemeralCodec.WireSize())
	}
	h := newHarnessSeeded(t, "-ell-len", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		hh.gwCf.Codec = Elligator2Codec
	})
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 131 {
		t.Fatalf("unpadded Elligator2 initiation is %d bytes; the design document's "+
			"floor is 131", len(msg))
	}
	rh, err := h.resp.ReadInitiation(msg)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := rh.WriteResponse(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 83 {
		t.Fatalf("unpadded Elligator2 response is %d bytes; the design document's "+
			"floor is 83", len(resp))
	}
}

// TestElligatorMismatchedCodecsFailSilently: the codec is not negotiated, in
// exactly the way Freshness and Suite are not negotiated. Two ends that
// disagree must fail to decrypt, and must fail with an ordinary silent
// rejection rather than anything a prober could tell from a dropped packet.
func TestElligatorMismatchedCodecsFailSilently(t *testing.T) {
	h := newHarnessSeeded(t, "-ell-mismatch", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		// The gateway stays on the v1 codec.
	})
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The gateway reads the representative as a raw point. It is a valid
	// 32-byte string, so parsing succeeds; the inner AEAD is what refuses.
	if _, err := h.resp.ReadInitiation(msg); err == nil {
		t.Fatal("a codec mismatch must not produce a usable handshake")
	} else if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected a silent cryptographic rejection, got %v", err)
	}
}

// TestElligatorCodecSurface covers the seam's own contract.
func TestElligatorCodecSurface(t *testing.T) {
	if _, err := Elligator2Codec.EncodePublic(make([]byte, KeySize)); !errors.Is(err, ErrConfig) {
		t.Fatalf("EncodePublic must refuse rather than invent randomness, got %v", err)
	}
	if _, err := Elligator2Codec.DecodePublic(make([]byte, KeySize-1)); !errors.Is(err, ErrShortMessage) {
		t.Fatalf("expected ErrShortMessage, got %v", err)
	}
	if _, ok := Elligator2Codec.(EphemeralKeygen); !ok {
		t.Fatal("the Elligator2 codec must implement EphemeralKeygen")
	}
	if _, ok := DefaultEphemeralCodec.(EphemeralKeygen); ok {
		t.Fatal("the v1 codec must NOT implement EphemeralKeygen; the seam is opt-in")
	}
}

// TestElligatorEntropyFailurePropagates: a failing reader must surface as an
// error, never as an ephemeral built from predictable bytes. The budgets
// straddle the boundary between the scalar draw and the one-byte tweak.
func TestElligatorEntropyFailurePropagates(t *testing.T) {
	kg := Elligator2Codec.(EphemeralKeygen)
	for _, budget := range []int{0, 8, KeySize, KeySize + 1} {
		if _, _, err := kg.GenerateEphemeral(&failingReader{remaining: budget}); err == nil {
			t.Fatalf("budget %d: a failing reader must not yield an ephemeral", budget)
		}
	}
	// And through the handshake, where it must not leave a half-built state.
	h := newHarnessSeeded(t, "-ell-entropy", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		hh.clientCf.Rand = &failingReader{remaining: 12}
		hh.gwCf.Codec = Elligator2Codec
	})
	ini := h.initiator(t)
	if _, err := ini.WriteInitiation(nil, PadAuto); err == nil {
		t.Fatal("a starved reader must not yield an initiation")
	}
}

// TestElligatorRejectionLoopTerminates: a reader whose bytes are constant makes
// every attempt identical, so either every attempt succeeds or every attempt
// fails. The bound must turn the second case into an error rather than a hang.
func TestElligatorRejectionLoopTerminates(t *testing.T) {
	kg := Elligator2Codec.(EphemeralKeygen)
	for _, fill := range []byte{0x00, 0x5A, 0xFF} {
		rd := bytes.NewReader(bytes.Repeat([]byte{fill}, (KeySize+1)*(ellMaxAttempts+2)))
		_, wire, err := kg.GenerateEphemeral(rd)
		if err == nil && len(wire) != KeySize {
			t.Fatalf("fill %02X: produced a %d-byte field", fill, len(wire))
		}
		if err != nil && !errors.Is(err, ErrConfig) {
			t.Fatalf("fill %02X: expected ErrConfig or success, got %v", fill, err)
		}
	}
}

// TestElligatorDegenerateWireIsRefusedByTheCore: the all-zero representative
// decodes to u = 0, the order-two point. Nothing in the codec rejects it —
// rejecting inputs is what would make it an oracle — so the refusal must come
// from the key agreement, exactly as it does for a low-order raw ephemeral.
func TestElligatorDegenerateWireIsRefusedByTheCore(t *testing.T) {
	u, err := Elligator2Codec.DecodePublic(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("the forward map must accept every 32-byte input: %v", err)
	}
	if !bytes.Equal(u, make([]byte, KeySize)) {
		t.Fatalf("the all-zero representative decoded to %x, expected the order-two point", u)
	}

	// Mint a message carrying it, under the gateway's own admission key, so
	// that it genuinely reaches the cryptography.
	h := newHarnessSeeded(t, "-ell-degenerate", func(hh *harness) {
		hh.clientCf.Codec = Elligator2Codec
		hh.gwCf.Codec = Elligator2Codec
	})
	ini := h.initiator(t)
	msg, err := ini.WriteInitiation(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _, _, err := verifyAdmission(msg, h.gwCf.Gateway, h.now)
	if err != nil {
		t.Fatal(err)
	}
	copy(body[:KeySize], make([]byte, KeySize))
	if _, err := h.resp.ReadInitiation(resealUnder(t, body, h.gwCf.Gateway, h.now, 0)); err == nil {
		t.Fatal("a degenerate ephemeral must not produce a handshake")
	}
}

// TestElligatorFieldHelpers covers the arithmetic directly, so that a failure
// in the map points at the map rather than at the field underneath it.
//
// The three facts asserted about the parameters are the ones the construction
// actually rests on, and each would silently break a different thing:
// p = 5 (mod 8) is what makes the one-exponentiation square root valid; 2 being
// a non-residue is what makes Z a legal Elligator2 parameter and what makes
// 1 + Z r^2 non-zero; and A^2 - 4 being a non-residue is why there is exactly
// one point of order two, which the torsion derivation depends on.
func TestElligatorFieldHelpers(t *testing.T) {
	if new(big.Int).Mod(ellP, big.NewInt(8)).Int64() != 5 {
		t.Fatal("p is not 5 mod 8; the square-root exponent is wrong")
	}
	if ellIsSquare(ellZ) {
		t.Fatal("Z = 2 must be a non-residue")
	}
	if !ellIsSquare(ellNeg(ellOne)) {
		t.Fatal("-1 must be a square")
	}
	if ellIsSquare(ellSub(ellMul(ellA, ellA), big.NewInt(4))) {
		t.Fatal("A^2-4 must be a non-residue, or there is a second point of order two")
	}

	if got := ellSqrt(big.NewInt(0)); got == nil || got.Sign() != 0 {
		t.Fatalf("sqrt(0) is %v", got)
	}
	if !ellIsSquare(big.NewInt(0)) {
		t.Fatal("zero must count as a square")
	}
	if got := ellSqrt(ellZ); got != nil {
		t.Fatalf("sqrt of a non-residue returned %v", got)
	}
	if ellInv(big.NewInt(0)) != nil {
		t.Fatal("inverting zero must return nil, not a value")
	}
	for _, v := range []int64{1, 2, 3, 486662} {
		x := big.NewInt(v)
		sq := ellMul(x, x)
		root := ellSqrt(sq)
		if root == nil || (root.Cmp(x) != 0 && root.Cmp(ellSub(ellP, x)) != 0) {
			t.Fatalf("sqrt(%d^2) is %v", v, root)
		}
	}

	// Wire encoding is little-endian and round-trips.
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), ellHalfP, ellPMinus1} {
		if got := ellFromWire(ellToWire(v)); got.Cmp(v) != 0 {
			t.Fatalf("wire round trip lost %v", v)
		}
	}
	if got := ellToWire(big.NewInt(1)); got[0] != 1 {
		t.Fatalf("the encoding is not little-endian: %x", got)
	}

	// The inverse map's three refusals, each of which is a real case rather
	// than an impossibility: u = 0 and u = -A are the two points the map can
	// never name.
	for _, tc := range []struct {
		name string
		u    *big.Int
	}{
		{"zero", big.NewInt(0)},
		{"minus A", ellNeg(ellA)},
	} {
		for branch := 0; branch < 2; branch++ {
			if _, ok := elligatorUnmap(tc.u, branch); ok {
				t.Errorf("%s branch %d: must have no representative", tc.name, branch)
			}
		}
	}
}

// brokenCodec is an EphemeralCodec that implements EphemeralKeygen badly. It
// exists to prove the seam's guards fire, because the guards protect against a
// codec this package does not own.
type brokenCodec struct {
	wire int
	priv int
	err  error
}

func (b brokenCodec) WireSize() int                         { return KeySize }
func (b brokenCodec) EncodePublic(p []byte) ([]byte, error) { return p, nil }
func (b brokenCodec) DecodePublic(w []byte) ([]byte, error) { return w, nil }
func (b brokenCodec) GenerateEphemeral(io.Reader) ([]byte, []byte, error) {
	if b.err != nil {
		return nil, nil, b.err
	}
	return make([]byte, b.priv), make([]byte, b.wire), nil
}

// TestEphemeralKeygenSeamRejectsABadCodec.
//
// The seam takes a private scalar and a wire string from code outside this
// package and must not trust either. A codec that returns a field of the wrong
// width would produce a message the responder parses at the wrong offsets; a
// codec that returns a malformed scalar would produce a key agreement that
// silently disagreed. Both are caught before anything is built.
func TestEphemeralKeygenSeamRejectsABadCodec(t *testing.T) {
	cases := map[string]brokenCodec{
		"short wire":   {wire: KeySize - 1, priv: KeySize},
		"long wire":    {wire: KeySize + 1, priv: KeySize},
		"short scalar": {wire: KeySize, priv: KeySize - 1},
		"reader error": {err: errors.New("no entropy")},
	}
	for name, codec := range cases {
		if _, _, err := newEphemeralForCodec(codec, newDetReader(name)); err == nil {
			t.Errorf("%s: the seam accepted a broken codec", name)
		}
	}
	// The good case still works, and goes through the extension rather than
	// through EncodePublic.
	eph, wire, err := newEphemeralForCodec(brokenCodec{wire: KeySize, priv: KeySize}, newDetReader("ok"))
	if err != nil || eph == nil || len(wire) != KeySize {
		t.Fatalf("a well-behaved keygen codec was refused: %v", err)
	}

	// And ephemeralFromScalar's own contract.
	if _, err := ephemeralFromScalar(make([]byte, KeySize-1)); !errors.Is(err, ErrConfig) {
		t.Errorf("expected ErrConfig for a short scalar, got %v", err)
	}
	if _, err := ephemeralFromScalar(make([]byte, KeySize)); err != nil {
		t.Errorf("a 32-byte scalar must be adopted: %v", err)
	}
}

// --- known answers -----------------------------------------------------------

// Pinned Elligator2 vectors. The map has no key and no clock, so these are the
// most portable vectors in the package: a second implementation can check them
// with nothing but a bignum library.
const (
	vecEllMapZero = "0000000000000000000000000000000000000000000000000000000000000000"
	vecEllMapOne  = "01" + "00000000000000000000000000000000000000000000000000000000000000"
)

func TestKnownAnswerElligator(t *testing.T) {
	// Forward map, pinned inputs. Zero is the interesting one: it is the only
	// input whose image is a degenerate point.
	if got := hex.EncodeToString(elligatorMap(mustHex(t, vecEllMapZero))); got != vecEllMapZero {
		t.Errorf("map(0) drifted: %s", got)
	}

	// Round trip against a pinned public key, on both branches.
	sk, err := ecdh.X25519().NewPrivateKey(mustSeed("winn3-kat-elligator-scalar"))
	if err != nil {
		t.Fatal(err)
	}
	u := ellFromWire(sk.PublicKey().Bytes())
	reps := 0
	for branch := 0; branch < 2; branch++ {
		rep, ok := elligatorUnmap(u, branch)
		if !ok {
			continue
		}
		reps++
		back := elligatorMap(ellToWire(rep))
		if !bytes.Equal(back, sk.PublicKey().Bytes()) {
			t.Errorf("branch %d does not round trip", branch)
		}
	}
	if reps != 0 && reps != 2 {
		t.Errorf("%d branches inverted; expected 0 or 2", reps)
	}

	// The keygen is deterministic under a pinned reader, which is what makes
	// full-handshake Elligator2 vectors possible at all.
	kg := Elligator2Codec.(EphemeralKeygen)
	priv1, wire1, err := kg.GenerateEphemeral(newDetReader("winn3-kat-elligator"))
	if err != nil {
		t.Fatal(err)
	}
	priv2, wire2, err := kg.GenerateEphemeral(newDetReader("winn3-kat-elligator"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv1, priv2) || !bytes.Equal(wire1, wire2) {
		t.Error("the Elligator2 keygen is not deterministic under a pinned reader")
	}
	if len(wire1) != KeySize {
		t.Errorf("keygen produced a %d-byte field", len(wire1))
	}
	// The scalar the keygen returns must be the one whose public key the
	// representative names, modulo the torsion component.
	sk1, err := ecdh.X25519().NewPrivateKey(priv1)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Elligator2Codec.DecodePublic(wire1)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPrivateKey(mustSeed("winn3-kat-elligator-peer"))
	if err != nil {
		t.Fatal(err)
	}
	viaDirty, err := peer.ECDH(mustECDHPublic(t, decoded))
	if err != nil {
		t.Fatal(err)
	}
	viaClean, err := sk1.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(viaDirty, viaClean) {
		t.Error("the returned scalar does not agree with the transmitted representative")
	}
}

// --- cost --------------------------------------------------------------------

func BenchmarkElligatorGenerateEphemeral(b *testing.B) {
	kg := Elligator2Codec.(EphemeralKeygen)
	r := newDetReader("bench-gen")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := kg.GenerateEphemeral(r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkElligatorDecodePublic(b *testing.B) {
	kg := Elligator2Codec.(EphemeralKeygen)
	_, wire, err := kg.GenerateEphemeral(newDetReader("bench-dec"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Elligator2Codec.DecodePublic(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateEphemeralV1(b *testing.B) {
	r := newDetReader("bench-v1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := generateEphemeral(r); err != nil {
			b.Fatal(err)
		}
	}
}
