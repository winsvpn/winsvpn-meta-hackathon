package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"time"
)

// This file implements the first field of every handshake message: a keyed
// admission tag, and the keystream that whitens everything after it.
//
// The decision to put a random-looking authenticator at the head of the
// initiation is inherited from internal/initauth, whose reasoning is the
// strongest single piece of prior art in this tree:
//
//   - No knock at all beats a better knock. A separate authorisation packet is
//     a separate flow, and a port that receives uniform-length maximum-entropy
//     datagrams and never answers one is a signature with essentially no
//     false-positive population to hide in.
//   - A knock authorises a SOURCE ADDRESS, and under the CGNAT this product's
//     users sit behind, that address is shared with thousands of subscribers of
//     a state-linked carrier.
//
// What changes in standalone v3 is that initauth had to hide its authenticator
// in AmneziaWG's S1 junk prefix — a field defined for another purpose — and so
// inherited AmneziaWG's constraints, including the 0B 00 00 00 header word four
// bytes later that it explicitly could not fix. Owning the header removes that
// ceiling.
//
// Two properties are preserved verbatim: the freshness bucket is an
// authenticated input and is NEVER TRANSMITTED, and the tag costs zero added
// packets and zero added bytes because it replaces mac1, mac2 and the cookie
// exchange rather than adding to them.

// tagVersion is authenticated as an input and never transmitted. It exists so
// that a future tag construction cannot be confused with this one even under
// the same key.
const tagVersion byte = 1

// admissionTag computes the tag over the PLAINTEXT (un-whitened) message body.
//
// Computing the MAC over the plaintext rather than the whitened bytes is not
// the usual encrypt-then-MAC discipline, and the reason it is safe here is
// specific: the whitening is a deterministic keystream derived from the tag
// itself, so an adversary who alters any whitened byte alters the recovered
// plaintext and the recomputed tag fails. The whitening is obfuscation, not
// confidentiality — the confidentiality in this message is the two inner AEADs,
// which are computed over the plaintext in the first place.
//
// The bucket, the tag length and the gateway identity are all authenticated
// inputs and none of them appears on the wire:
//
//   - bucket gives freshness without a transmitted timestamp, because an
//     explicit timestamp only ever takes values near true wall-clock time,
//     which is a learnable statistical shape in a field that must look random.
//   - tagLen must be bound, or a message sealed for a 32-byte-tag gateway would
//     verify at a 16-byte-tag gateway sharing the key, since one tag would be a
//     prefix of the other.
//   - gatewayID stops an initiation captured at one gateway being replayed at
//     another mid-rotation on a shared key.
func admissionTag(key, gatewayID []byte, tagLen int, bucket int64, body, out []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(labelAdmitTag))
	mac.Write([]byte{0x00})

	var hdr [1 + 2 + 8 + 1]byte
	hdr[0] = tagVersion
	binary.BigEndian.PutUint16(hdr[1:3], uint16(tagLen))
	binary.BigEndian.PutUint64(hdr[3:11], uint64(bucket))
	hdr[11] = byte(len(gatewayID))
	mac.Write(hdr[:])
	mac.Write(gatewayID)
	mac.Write(body)

	sum := mac.Sum(nil)
	copy(out, sum[:tagLen])
}

// whitenInPlace XORs the message body with a keystream derived from the
// per-gateway admission key and this packet's tag.
//
// It exists for one reason: an X25519 public key is not uniformly distributed.
// The field is 2^255-19, so the top bit of the last byte is always zero. That
// is a one-bit constant at a fixed offset in every initiation — the same class
// of failure as the 0B 00 00 00 this protocol replaces, only smaller, and it
// would have shipped had nobody looked.
//
// The honest scoping, which must not be softened in any later document: this is
// a COST boundary, not a security boundary. It moves fleet identification from
// "byte-pattern match in an ASIC at line rate" to "hold a per-gateway secret".
// An adversary who holds the key does not need the whitening removed at all —
// they can verify the tag and identify the traffic with certainty.
//
// What makes it worth having anyway is that the key is PER GATEWAY. Burning one
// gateway does not burn the fleet. The fingerprint being replaced was a
// fleet-wide constant that required no key from anyone.
//
// The unconditional fix for the underlying bias is Elligator2; see
// EphemeralCodec.
func whitenInPlace(key, tag, body []byte) {
	if len(body) == 0 {
		return
	}
	ks := expandFrom(tag, key, labelAdmitWhtn, len(body))
	subtle.XORBytes(body, body, ks)
}

// bucketIndex floors t to a bucket toward negative infinity, so the boundary
// behaviour is identical on both sides of the epoch. Go's integer division
// truncates toward zero, which would make the bucket immediately before the
// epoch twice as wide.
func bucketIndex(t time.Time, window time.Duration) int64 {
	secs := t.Unix()
	w := int64(window / time.Second)
	if secs >= 0 {
		return secs / w
	}
	return -((-secs + w - 1) / w)
}

// candidateBuckets returns the buckets to try, NEAREST FIRST, so the
// overwhelmingly common case — a client whose clock is right — costs exactly
// one HMAC rather than 2*spread+1 of them.
func candidateBuckets(centre int64, spread int) []int64 {
	out := make([]int64, 0, 2*spread+1)
	out = append(out, centre)
	for d := int64(1); d <= int64(spread); d++ {
		out = append(out, centre-d, centre+d)
	}
	return out
}

// verifyAdmission recovers the plaintext body of a handshake initiation.
//
// It is given the whole on-wire message. It un-whitens under each candidate
// key, recomputes the tag over each candidate bucket, and returns the recovered
// body plus the index of the key that matched.
//
// Authentication failures — a wrong key, a wrong gateway identity, an
// out-of-skew clock — all return ErrUnauthenticated. There is deliberately no
// distinction among those three: the caller must not be able to build an
// oracle from them, and nothing is written back on any path in any case.
//
// Two structural length bounds escape that sentinel and fire before any key
// is consulted: len(msg) <= tagLen returns ErrShortMessage, and
// len(msg) > MaxHandshakeMessage returns ErrLongMessage. They cost nothing
// and leak nothing about the key set. A Freshness that fails to resolve
// returns ErrConfig; that is a local misconfiguration, not a wire event.
// TestAdmissionGateRejectSemantics pins this split. Production callers
// (gateway.Handle, session.Driver.Deliver) drop every error identically.
//
// Ordering is keys outermost, buckets innermost and nearest first, so the live
// key with a correct clock costs one whitening expansion and one HMAC, and a
// rotation that has not finished costs more only for clients still on the old
// key.
//
// There is deliberately NO early exit on the reject path: a datagram that
// matches nothing costs len(keys) * (2*spread+1) HMACs whatever the key set
// looks like. That is the property that makes a rotation invisible. An
// optimisation that gave up early — after the newest key, say, or on some
// cheap precheck — would make "rejected under the new key" and "rejected under
// the old key" take measurably different times, which is a timing oracle for
// exactly the event Responder.SetAdmissionKeys exists to keep off the wire.
// The bound on that cost is MaxAdmissionHMACs.
func verifyAdmission(msg []byte, g GatewayParams, now time.Time) (body []byte, keyIndex int, bucket int64, err error) {
	tagLen := g.tagSize()
	if len(msg) <= tagLen {
		return nil, -1, 0, ErrShortMessage
	}
	if len(msg) > MaxHandshakeMessage {
		return nil, -1, 0, ErrLongMessage
	}
	window, spread, err := g.Fresh.resolve()
	if err != nil {
		return nil, -1, 0, err
	}

	tag := msg[:tagLen]
	buckets := candidateBuckets(bucketIndex(now, window), spread)
	computed := make([]byte, tagLen)
	scratch := make([]byte, len(msg)-tagLen)

	for ki, key := range g.AdmissionKeys {
		copy(scratch, msg[tagLen:])
		whitenInPlace(key, tag, scratch)
		for _, b := range buckets {
			admissionTag(key, g.GatewayID, tagLen, b, scratch, computed)
			if hmac.Equal(computed, tag) {
				return scratch, ki, b, nil
			}
		}
	}
	return nil, -1, 0, ErrUnauthenticated
}

// sealAdmission renders a plaintext body as a complete on-wire initiation:
// tag first, then the whitened body.
func sealAdmission(body []byte, key, gatewayID []byte, tagLen int, bucket int64) []byte {
	out := make([]byte, tagLen+len(body))
	copy(out[tagLen:], body)
	admissionTag(key, gatewayID, tagLen, bucket, out[tagLen:], out[:tagLen])
	whitenInPlace(key, out[:tagLen], out[tagLen:])
	return out
}

// responseTag and responseWhiten are the response's equivalents, keyed by
// handshake-derived material rather than by the gateway admission key.
//
// This is a real property and not just tidiness: an observer holding the
// gateway admission key can recognise an initiation, but cannot derive the
// handshake chain without the gateway's static private key, so they still
// cannot pair a response with the initiation that produced it.
func responseTag(tagKey []byte, tagLen int, body, out []byte) {
	mac := hmac.New(sha256.New, tagKey)
	mac.Write([]byte(labelRespTag))
	mac.Write([]byte{0x00, tagVersion, byte(tagLen)})
	mac.Write(body)
	sum := mac.Sum(nil)
	copy(out, sum[:tagLen])
}

func responseWhitenInPlace(whitenKey, tag, body []byte) {
	if len(body) == 0 {
		return
	}
	ks := expandFrom(tag, whitenKey, labelRespWhite, len(body))
	subtle.XORBytes(body, body, ks)
}
