package core

import (
	"crypto/ecdh"
	"io"
	"math/big"
	"sync"
)

// Elligator2 for Curve25519: the v1.1 EphemeralCodec.
//
// # Why this exists, stated at the same altitude as the thing it replaces
//
// An X25519 public key is not a uniformly distributed 32-byte string. The field
// is 2^255-19, so the top bit of the last byte is always zero. That is a
// one-bit constant at a fixed offset in every initiation — failure F1 in
// miniature, the same class as the 0B 00 00 00 this protocol exists to remove.
//
// v1 covers it with the admission whitening, and admission.go and doc.go are
// both explicit that this is a COST boundary and not a security boundary: the
// initiation body is uniform only to an observer who does not hold that
// gateway's admission key.
//
// This file removes the bias from the OBJECT instead of from the OBSERVATION.
// A representative is a uniform 32-byte string with no secret anywhere in its
// construction, so the body's uniformity stops being conditional on anything.
// What that does and does not buy is set out precisely in
// docs/handoff/WINN3_ELLIGATOR_AND_KATS_20260808.md; the short form is that it
// does NOT stop an admission-key holder identifying traffic — they verify the
// tag, which is untouched — and it DOES mean the one part of the fingerprint
// that key rotation could never fix is gone, and that deleting the admission
// layer no longer reintroduces F1.
//
// # The layering rule this file must not break
//
// doc.go states a non-goal: delete the entire admission layer and the
// cryptographic core must remain exactly as sound as it is today. The ephemeral
// encoding sits INSIDE that boundary. Nothing here reads the admission key, the
// gateway identity, the freshness bucket, the tag or the tag length, and nothing
// here may ever start to. The transcript binds the WIRE encoding of the
// ephemeral (handshake.go mixes ephWire, not the point), which is what keeps
// this a change of representation and not a change of key schedule.
// TestElligatorDoesNotDependOnTheAdmissionLayer pins it.
//
// # Why math/big
//
// A hand-rolled Elligator2 is a serious correctness risk — the design document
// says so, and it is the reason this was deferred out of v1. math/big is the
// cheapest available answer to that risk: there are no limbs to carry wrong and
// no reduction to get subtly non-canonical, so the only thing left to get wrong
// is the map itself, which is small enough to check against its own inverse
// exhaustively (TestElligatorRoundTripsOverRandomRepresentatives).
//
// The usual objection — math/big is not constant time — does not apply, and the
// reason is worth stating rather than assuming. Every input to every function
// here is public: the input to the inverse map is a public key, and its output
// is the very string about to be transmitted. The ephemeral PRIVATE scalar
// never touches this file; it is drawn from the caller's reader and handed
// straight to crypto/ecdh. The rejection loop's iteration count is likewise
// public — each iteration draws a fresh independent seed, so the number of
// attempts says nothing about the seed that finally succeeded.
//
// The cost is real and is paid only on the handshake path: see
// BenchmarkElligator* and the handoff document for measured numbers. On the
// gateway it is paid strictly AFTER the admission tag check, so unauthenticated
// traffic still costs one HMAC and no asymmetric work.

// Curve and map parameters.
//
//	p = 2^255 - 19          the field
//	A = 486662              the Montgomery coefficient, v^2 = u^3 + A u^2 + u
//	Z = 2                   the map's non-square; 2 is a non-residue because
//	                        p = 5 (mod 8)
//
// These are values, not choices to be revisited: Z must be a non-square and 2
// is the conventional one.
var (
	ellP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	ellA = big.NewInt(486662)
	ellZ = big.NewInt(2)

	ellPMinus1 = new(big.Int).Sub(ellP, big.NewInt(1))

	// ellHalfP is (p-1)/2. A canonical representative is at most this, which is
	// why bits 254 and 255 of the wire encoding are free to carry randomness.
	ellHalfP = new(big.Int).Rsh(ellPMinus1, 1)

	// exponents: (p+3)/8 is the candidate square root for p = 5 (mod 8);
	// (p-1)/2 is the Legendre symbol.
	ellExpSqrt = new(big.Int).Rsh(new(big.Int).Add(ellP, big.NewInt(3)), 3)
	ellExpLeg  = new(big.Int).Rsh(ellPMinus1, 1)

	// sqrt(-1) = 2^((p-1)/4), needed for the second square-root candidate.
	ellSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(ellPMinus1, 2), ellP)

	ellOne = big.NewInt(1)
	ellTwo = big.NewInt(2)
)

func ellAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), ellP) }
func ellSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), ellP) }
func ellMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), ellP) }
func ellNeg(a *big.Int) *big.Int    { return new(big.Int).Mod(new(big.Int).Neg(a), ellP) }

// ellInv returns a^-1, or nil when a is zero. Callers must check: every place
// an inverse is taken here, a zero denominator is a real case that means "this
// value has no representative", not an impossibility.
func ellInv(a *big.Int) *big.Int { return new(big.Int).ModInverse(a, ellP) }

// ellIsSquare reports whether a is a quadratic residue. Zero counts as a square.
func ellIsSquare(a *big.Int) bool {
	if a.Sign() == 0 {
		return true
	}
	return new(big.Int).Exp(a, ellExpLeg, ellP).Cmp(ellOne) == 0
}

// ellSqrt returns a square root of a, or nil when a is not a square.
//
// It folds the Legendre test into the root computation: for p = 5 (mod 8) the
// candidate a^((p+3)/8) is a root of either a or -a, so squaring the candidate
// both finds the root and decides residuosity in one exponentiation instead of
// two. Which of the two roots is returned is unspecified; every caller that
// cares canonicalises.
func ellSqrt(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		return big.NewInt(0)
	}
	c := new(big.Int).Exp(a, ellExpSqrt, ellP)
	if ellMul(c, c).Cmp(a) == 0 {
		return c
	}
	c = ellMul(c, ellSqrtM1)
	if ellMul(c, c).Cmp(a) == 0 {
		return c
	}
	return nil
}

// ellCurveG evaluates g(u) = u^3 + A u^2 + u. A u is on the curve exactly when
// g(u) is a square.
func ellCurveG(u *big.Int) *big.Int {
	t := ellAdd(ellMul(u, u), ellMul(ellA, u))
	t = ellAdd(t, ellOne)
	return ellMul(u, t)
}

// ellFromWire reads a 32-byte little-endian field element. It does NOT mask:
// callers that need the top two bits cleared do it themselves, so that the
// masking is visible at the place it matters.
func ellFromWire(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// ellToWire writes a field element as 32 bytes little-endian.
func ellToWire(x *big.Int) []byte {
	out := make([]byte, KeySize)
	be := x.Bytes()
	for i := 0; i < len(be) && i < KeySize; i++ {
		out[len(be)-1-i] = be[i]
	}
	return out
}

// --- the map itself ---------------------------------------------------------

// elligatorMap is the FORWARD direction: a 32-byte wire field to an X25519
// public key. It is total — every 32-byte string names a point — which is the
// property that makes a representative indistinguishable from random bytes to
// an observer who tries to decode one.
//
//	r  = little-endian(wire), bits 254 and 255 discarded
//	w  = 1 + Z r^2                    never zero, because -1/Z is a non-square
//	x1 = -A / w
//	u  = x1            if g(x1) is a square
//	u  = -x1 - A       otherwise
//
// The two cases are the map's two branches. g(x2) = Z r^2 g(x1) and Z r^2 is a
// non-square, so exactly one of g(x1), g(x2) is a square and the output is
// always a point on the curve rather than on its twist.
func elligatorMap(wire []byte) []byte {
	masked := make([]byte, KeySize)
	copy(masked, wire)
	masked[KeySize-1] &^= 0xC0
	r := ellFromWire(masked)

	w := ellAdd(ellOne, ellMul(ellZ, ellMul(r, r)))
	x1 := ellMul(ellNeg(ellA), ellInv(w))
	if ellIsSquare(ellCurveG(x1)) {
		return ellToWire(x1)
	}
	return ellToWire(ellSub(ellNeg(x1), ellA))
}

// elligatorUnmap is the INVERSE direction: a point's u-coordinate to a
// representative, or false when it has none.
//
// Inverting u = x1 gives r^2 = -(u+A)/(Z u); inverting u = x2 gives
// r^2 = -u/(Z (u+A)). Their product is 1/Z^2, a square, so the two are squares
// together or non-squares together: a u either has BOTH preimages or NEITHER.
// branch therefore selects freely between two equally valid representatives —
// it is one bit of the sender's randomness, not a decision the algebra forces —
// and it is the same freedom as choosing the sign of the point's v-coordinate,
// which is why v never appears in this file.
//
// The returned r is canonicalised to [0, (p-1)/2] so that bits 254 and 255 of
// the encoding are free.
func elligatorUnmap(u *big.Int, branch int) (*big.Int, bool) {
	if u.Sign() == 0 {
		return nil, false
	}
	uPlusA := ellAdd(u, ellA)
	if uPlusA.Sign() == 0 {
		return nil, false
	}

	var num, den *big.Int
	if branch == 0 {
		num, den = ellNeg(u), ellMul(ellZ, uPlusA) // u is x2
	} else {
		num, den = ellNeg(uPlusA), ellMul(ellZ, u) // u is x1
	}
	inv := ellInv(den)
	if inv == nil {
		return nil, false
	}
	r := ellSqrt(ellMul(num, inv))
	if r == nil {
		return nil, false
	}
	if r.Cmp(ellHalfP) > 0 {
		r = ellSub(ellP, r)
	}
	return r, true
}

// --- the 8-torsion, and why the ephemeral is deliberately not a clean point --

// ellPoint is an affine Montgomery point. It exists only to build the 8-torsion
// table; nothing on the hot path does point arithmetic.
type ellPoint struct {
	u, v *big.Int
	inf  bool
}

func ellPointAdd(a, b ellPoint) ellPoint {
	if a.inf {
		return b
	}
	if b.inf {
		return a
	}
	if a.u.Cmp(b.u) == 0 {
		if ellAdd(a.v, b.v).Sign() == 0 {
			return ellPoint{inf: true}
		}
		num := ellAdd(ellAdd(
			ellMul(big.NewInt(3), ellMul(a.u, a.u)),
			ellMul(ellMul(ellTwo, ellA), a.u)), ellOne)
		lam := ellMul(num, ellInv(ellMul(ellTwo, a.v)))
		u3 := ellSub(ellSub(ellMul(lam, lam), ellA), ellMul(ellTwo, a.u))
		return ellPoint{u: u3, v: ellSub(ellMul(lam, ellSub(a.u, u3)), a.v)}
	}
	lam := ellMul(ellSub(b.v, a.v), ellInv(ellSub(b.u, a.u)))
	u3 := ellSub(ellSub(ellSub(ellMul(lam, lam), ellA), a.u), b.u)
	return ellPoint{u: u3, v: ellSub(ellMul(lam, ellSub(a.u, u3)), a.v)}
}

var (
	ellTorsionOnce  sync.Once
	ellTorsionTable [8]ellPoint
)

// ellTorsion returns the eight points of E[8], indexed by j so that
// ellTorsion()[j] = j * Q8 for a fixed generator Q8.
//
// It is DERIVED rather than transcribed. The u-coordinates of the order-8
// points are famous constants and copying them from memory is exactly the kind
// of mistake this file cannot afford: a torsion point that is silently on the
// twist would corrupt every ephemeral it touched, and the failure would look
// like an intermittent handshake failure rather than like a wrong constant.
//
// The derivation, which a second implementation can follow or replace:
// a point of order 8 doubles to the order-4 point at u = 1, and the doubling
// formula u(2Q) = (u^2-1)^2 / (4u(u^2+Au+1)) set equal to 1 is a palindromic
// quartic. Substituting w = u + 1/u reduces it to w^2 - 4w - (4+4A) = 0, so
// w = 2 +/- 2*sqrt(A+2) and u = (w +/- sqrt(w^2-4))/2. One of the two w values
// gives curve points and the other gives twist points; g(u) being a square
// picks the right one.
//
// The result is then checked against two facts it cannot accidentally satisfy:
// 4*Q8 must be the order-2 point (0,0), and 8*Q8 must be the identity.
func ellTorsion() *[8]ellPoint {
	ellTorsionOnce.Do(func() {
		s := ellSqrt(ellAdd(ellA, ellTwo))
		if s == nil {
			panic("winn3: A+2 is not a square; the curve parameters are wrong")
		}
		var q8 *ellPoint
		for _, w := range []*big.Int{
			ellAdd(ellTwo, ellMul(ellTwo, s)),
			ellSub(ellTwo, ellMul(ellTwo, s)),
		} {
			sd := ellSqrt(ellSub(ellMul(w, w), big.NewInt(4)))
			if sd == nil {
				continue
			}
			inv2 := ellInv(ellTwo)
			for _, u := range []*big.Int{
				ellMul(ellAdd(w, sd), inv2),
				ellMul(ellSub(w, sd), inv2),
			} {
				g := ellCurveG(u)
				if g.Sign() == 0 {
					continue
				}
				if v := ellSqrt(g); v != nil {
					c := ellPoint{u: u, v: v}
					q8 = &c
					break
				}
			}
			if q8 != nil {
				break
			}
		}
		if q8 == nil {
			panic("winn3: no order-8 point on curve25519; the derivation is wrong")
		}

		ellTorsionTable[0] = ellPoint{inf: true}
		cur := *q8
		for i := 1; i < 8; i++ {
			ellTorsionTable[i] = cur
			cur = ellPointAdd(cur, *q8)
		}
		if !cur.inf {
			panic("winn3: 8*Q8 is not the identity")
		}
		if ellTorsionTable[4].inf || ellTorsionTable[4].u.Sign() != 0 {
			panic("winn3: 4*Q8 is not the order-two point")
		}
	})
	return &ellTorsionTable
}

// --- the codec --------------------------------------------------------------

// ellMaxAttempts bounds the rejection loop. Roughly half of all public keys
// have a representative and every attempt draws an independent seed, so the
// chance of exhausting this is 2^-64. It is a bound against a broken reader,
// not against the mathematics.
const ellMaxAttempts = 64

// elligator2Codec renders an ephemeral X25519 public key as a uniformly
// distributed 32-byte string.
type elligator2Codec struct{}

// Elligator2Codec is the v1.1 ephemeral codec: an on-wire ephemeral that is
// indistinguishable from random bytes WITHOUT any shared secret.
//
// Set it as Config.Codec on both ends. It is not the default, because both ends
// must agree — there is no negotiation on this datapath by design (see Suite),
// and a client and gateway that disagree fail to decrypt rather than fall back.
//
// It costs one on-wire byte of nothing: WireSize is 32, exactly as the raw
// encoding. What it costs is CPU on the handshake path only; see the file
// comment.
var Elligator2Codec EphemeralCodec = elligator2Codec{}

// WireSize is 32: a representative is the same width as the point it replaces,
// so turning this codec on changes no length anywhere.
func (elligator2Codec) WireSize() int { return KeySize }

// EncodePublic is deliberately not supported.
//
// This is not an oversight and the alternative is worse. A representative needs
// three bits of sender randomness — which of the two preimages, and the two
// free top bits — and roughly half of all public keys have no representative at
// all. A codec that took only a public key would have to either invent
// randomness (making known-answer vectors impossible and hiding an entropy
// source inside a pure function) or derive it deterministically from the key,
// which would be a catastrophe: an observer could recompute the derived bits
// from the decoded point and check them, turning the representative back into a
// detector.
//
// So this codec owns key generation instead, through EphemeralKeygen, and says
// so here rather than silently producing a biased string.
func (elligator2Codec) EncodePublic([]byte) ([]byte, error) {
	return nil, errWrap(ErrConfig,
		"the elligator2 codec generates its own ephemerals; see EphemeralKeygen")
}

// DecodePublic maps a wire representative to an X25519 public key. It is total
// for any 32-byte input: an attacker cannot probe it, because there is no input
// it rejects and therefore no oracle in it.
//
// The point it returns may carry a low-order component (see GenerateEphemeral),
// and that is correct: X25519 clamps, so a co-factor component is annihilated
// by the peer's scalar multiplication. A degenerate result — the all-zero wire
// decodes to u = 0 — is refused one layer up, by crypto/ecdh's all-zero
// shared-secret check, exactly as it is for the raw codec.
func (elligator2Codec) DecodePublic(wire []byte) ([]byte, error) {
	if len(wire) != KeySize {
		return nil, errWrap(ErrShortMessage, "ephemeral field is %d bytes, need %d", len(wire), KeySize)
	}
	return elligatorMap(wire), nil
}

// GenerateEphemeral draws a one-shot key pair whose public half has a uniform
// wire representative.
//
// Per attempt it reads KeySize bytes for the private scalar and one byte of
// tweak, and uses the tweak as three independent fields:
//
//	bits 0-2   which of the eight torsion points to add
//	bit  3     which of the two preimages to return
//	bits 6-7   copied into bits 254 and 255 of the representative
//
// # Why a torsion point is added
//
// This is the part that is easy to leave out and would leave a working but
// detectable codec behind. A representative decodes to a curve point, and an
// observer can decode one too. If the ephemeral were the plain X25519 public
// key it would always lie in the prime-order subgroup, whereas the point behind
// a genuinely random 32-byte string does so only about one time in eight. One
// scalar multiplication per packet would then separate Winn3 initiations from
// random bytes with no key at all — which would leave the codec no better than
// the bias it was written to remove.
//
// Adding a uniform element of E[8] destroys that test and costs nothing, for a
// reason specific to X25519: every peer clamps, so its scalar is a multiple of
// eight, and 8k(P + T) = 8kP for any T of order dividing eight. The peer
// computes the same shared secret it would have computed from the clean point,
// and TestElligatorDirtyKeysDoNotChangeTheSharedSecret asserts exactly that
// rather than assuming it.
//
// The residual non-uniformity is the 9 field elements in
// ((p-1)/2, 2^254) that no representative can take, i.e. about 2^-250 of the
// space. It is stated here rather than rounded away.
func (elligator2Codec) GenerateEphemeral(r io.Reader) (priv, wire []byte, err error) {
	table := ellTorsion()
	for attempt := 0; attempt < ellMaxAttempts; attempt++ {
		var seed [KeySize]byte
		if _, err := io.ReadFull(r, seed[:]); err != nil {
			return nil, nil, err
		}
		var tweak [1]byte
		if _, err := io.ReadFull(r, tweak[:]); err != nil {
			return nil, nil, err
		}

		sk, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			return nil, nil, errWrap(ErrConfig, "ephemeral scalar rejected: %v", err)
		}
		u := ellFromWire(sk.PublicKey().Bytes())
		v := ellSqrt(ellCurveG(u))
		if v == nil {
			// Unreachable: a clamped scalar times the base point is on the
			// curve by construction. Treated as a rejection rather than a panic
			// so that no reachable input can ever crash a gateway.
			continue
		}

		dirty := ellPointAdd(ellPoint{u: u, v: v}, table[tweak[0]&0x07])
		if dirty.inf {
			continue
		}
		rep, ok := elligatorUnmap(dirty.u, int(tweak[0]>>3)&0x01)
		if !ok {
			continue
		}

		out := ellToWire(rep)
		out[KeySize-1] |= tweak[0] & 0xC0
		return seed[:], out, nil
	}
	return nil, nil, errWrap(ErrConfig,
		"no ephemeral with a representative in %d attempts; the reader is not random", ellMaxAttempts)
}
