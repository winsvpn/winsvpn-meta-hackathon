package core

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// chain is the Winn3 key schedule: a transcript hash h and a chaining key ck.
//
// The shape is Noise-IK-like, which is a deliberate borrowing of a construction
// that has been analysed to death. What is NOT borrowed is any label, any
// constant or any wire encoding, so Winn3 is interoperable with nothing and
// inherits nobody's fingerprint. That also means the resemblance to Noise is
// not a proof: a Noise-shaped chain that is not Noise carries a proof
// obligation, and discharging it is on the outstanding list in the design
// document.
//
// h authenticates the transcript. Every field that goes on the wire is folded
// into h before it is used as AEAD associated data, so altering any earlier
// byte makes every later AEAD fail.
//
// ck accumulates secrets. Each key agreement is folded in with HKDF-Extract
// using the previous ck as salt, so learning one stage key reveals nothing
// about the ck that produced it.
type chain struct {
	ck [hashSize]byte
	h  [hashSize]byte
}

// Domain-separation labels. Every derivation in this protocol has its own
// label. Two derivations that could ever see the same input material must not
// be able to produce the same output, and never reusing a label is the cheap
// way to guarantee it.
const (
	labelChainNext = "winn3 chain next v1"

	// handshake secret-mixing stages
	labelDHEphStatic    = "winn3 dh ephemeral-static v1"
	labelDHStaticStatic = "winn3 dh static-static v1"
	labelDHEphEph       = "winn3 dh ephemeral-ephemeral v1"
	labelDHStaticEph    = "winn3 dh static-ephemeral v1"
	labelPSK            = "winn3 preshared key v1"

	// handshake AEAD stage keys
	labelStageStatic   = "winn3 stage static v1"
	labelStagePayload  = "winn3 stage payload v1"
	labelStageResponse = "winn3 stage response v1"

	// ratchets
	labelPQ    = "winn3 pq ratchet v1"
	labelRekey = "winn3 rekey ratchet v1"

	// response obfuscation, keyed by handshake material rather than by the
	// gateway admission key, so a response cannot be paired with its initiation
	// even by an admission-key holder
	labelRespTag   = "winn3 response tag v1"
	labelRespWhite = "winn3 response whiten v1"

	// initiation obfuscation, keyed by the per-gateway admission key
	labelAdmitTag  = "winn3 admission tag v1"
	labelAdmitWhtn = "winn3 admission whiten v1"

	// traffic keys; the epoch number and direction are appended by
	// epochInfo so that no two epochs and no two directions ever share one
	labelEpoch = "winn3 epoch v1"

	// the per-packet transport demultiplexing token, which is also the implicit
	// counter and the exact replay filter
	labelDemux = "winn3 demux v1"

	// reserved for a stream carrier's encrypted record length, so that the
	// carrier never writes a cleartext length prefix (design doc section 4.2)
	labelStreamLen = "winn3 stream length v1"
)

// newChain seeds the transcript from the protocol label and the responder's
// static public key.
//
// Binding the responder identity into h before anything else means an
// initiation built for gateway A is cryptographically useless at gateway B even
// when both share an admission key mid-rotation. The gateway identity itself
// never appears on the wire.
func newChain(responderStatic []byte) chain {
	var c chain
	c.h = sha256.Sum256([]byte(protocolLabel))
	c.ck = c.h
	c.mixHash(responderStatic)
	return c
}

// mixHash folds a wire field into the transcript.
func (c *chain) mixHash(data []byte) {
	hsh := sha256.New()
	hsh.Write(c.h[:])
	hsh.Write(data)
	sum := hsh.Sum(nil)
	copy(c.h[:], sum)
}

// mixSecret folds a shared secret into the chaining key under a label.
//
// HKDF-Extract with the previous ck as salt, then Expand under the label. This
// is the only way secret material ever enters the chain, so the ordering of
// mixSecret calls IS the key schedule and a reordering is a different protocol.
func (c *chain) mixSecret(secret []byte, label string) {
	prk, err := hkdf.Extract(sha256.New, secret, c.ck[:])
	if err != nil {
		// HKDF-Extract over SHA-256 cannot fail for any input length these call
		// sites produce. Unreachable, and not a peer-observable path.
		panic("winn3: hkdf extract failed: " + err.Error())
	}
	next, err := hkdf.Expand(sha256.New, prk, label+" | "+labelChainNext, hashSize)
	if err != nil {
		panic("winn3: hkdf expand failed: " + err.Error())
	}
	copy(c.ck[:], next)
}

// stageKey derives an AEAD key from the current chaining key WITHOUT advancing
// it. Every stage key therefore depends on every secret mixed so far, including
// the optional preshared key, which is why a stolen client static key alone is
// not enough to produce a valid handshake when a PSK is configured.
func (c *chain) stageKey(label string) [KeySize]byte {
	out := c.expand(label, KeySize)
	var k [KeySize]byte
	copy(k[:], out)
	return k
}

// expand derives arbitrary keying material from the current chaining key
// without advancing it.
func (c *chain) expand(label string, n int) []byte {
	out, err := hkdf.Expand(sha256.New, c.ck[:], label, n)
	if err != nil {
		panic("winn3: hkdf expand failed: " + err.Error())
	}
	return out
}

// expandFrom derives from an explicit secret and salt under a label. Used where
// the input is not the chaining key — the admission whitening keystream, whose
// secret is the per-packet tag and whose salt is the per-gateway admission key.
func expandFrom(secret, salt []byte, label string, n int) []byte {
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		panic("winn3: hkdf extract failed: " + err.Error())
	}
	out, err := hkdf.Expand(sha256.New, prk, label, n)
	if err != nil {
		panic("winn3: hkdf expand failed: " + err.Error())
	}
	return out
}
