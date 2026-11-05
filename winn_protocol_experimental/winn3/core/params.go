package core

import (
	"errors"
	"time"
)

// Suite is the single ciphersuite this package implements. It is NEVER sent on
// the wire; it is an input to the transcript hash, so two endpoints configured
// differently fail to decrypt rather than negotiate.
//
// There is deliberately no ciphersuite negotiation on the datapath. A
// negotiable field is both a fingerprint and a downgrade surface, and the
// control plane already ships an Ed25519-signed descriptor that can tell an
// endpoint which suite to run.
const (
	// WireVersion is the protocol label component. It appears only inside the
	// transcript hash.
	WireVersion = "winn/3"

	// Suite names the primitive set: X25519 for the classical DH, ML-KEM-768
	// for the post-quantum ratchet, ChaCha20-Poly1305 for the AEAD, SHA-256 for
	// the transcript and the KDF.
	Suite = "winn3-x25519-mlkem768-chacha20poly1305-sha256"

	// protocolLabel seeds the transcript. Changing any byte of it produces a
	// protocol that cannot talk to this one, which is the intent: Winn v3 is
	// interoperable with nothing, so it inherits nobody's fingerprint.
	protocolLabel = WireVersion + " " + Suite
)

// Sizes fixed by the primitives.
const (
	// KeySize is the X25519 public and private key size, and the AEAD key size.
	KeySize = 32

	// AEADTagSize is the Poly1305 tag size.
	AEADTagSize = 16

	// AEADNonceSize is the ChaCha20-Poly1305 nonce size: a 4-byte per-direction
	// salt followed by an 8-byte big-endian counter.
	AEADNonceSize = 12

	// nonceSaltSize is the per-direction random-looking prefix of the nonce. It
	// exists so that two directions of the same session, and two epochs of the
	// same direction, never reuse a (key, nonce) pair even if a counter were
	// mishandled. It is derived, not transmitted.
	nonceSaltSize = 4

	// DemuxTokenSize is the length of the per-packet transport demultiplexing
	// token.
	//
	// Eight bytes is a deliberate balance. A collision means a lookup selects
	// the wrong session and the AEAD then rejects the packet, so a collision
	// costs a dropped packet and nothing else; at ten million live window
	// entries fleet-wide the birthday probability is on the order of 1e-6.
	// Sixteen bytes would halve the useful payload of a small packet for no
	// security gain.
	DemuxTokenSize = 8

	// hashSize is the SHA-256 output size.
	hashSize = 32
)

// Admission tag bounds.
const (
	// MinTagSize is the smallest admission tag accepted. A forged tag buys an
	// attacker exactly one datagram delivered to a state machine that rejects
	// it cryptographically anyway, so the bar is "not brute-forceable online",
	// not confidentiality. This mirrors internal/initauth's reasoning and its
	// floor.
	MinTagSize = 16

	// MaxTagSize bounds the whitening and tag work a caller-supplied config can
	// demand.
	MaxTagSize = 32

	// DefaultTagSize is the shipping default.
	DefaultTagSize = 32

	// minAdmissionKeySize is a floor against an accidentally-empty gateway
	// admission key. It is not a claim about generation; callers use
	// crypto/rand.
	minAdmissionKeySize = 32

	// MaxAdmissionHMACs bounds the work an UNAUTHENTICATED datagram can cost a
	// gateway on the reject path.
	//
	// That path is len(AdmissionKeys) * (2*spread+1) HMACs, because keys are
	// tried outermost and buckets innermost with no early exit (see
	// verifyAdmission for why there is no early exit). Both factors are
	// operator-controlled, so without a ceiling a misconfigured key set turns a
	// flood into an amplified one.
	//
	// 64 is the hub's figure and it is not arbitrary: a rotation needs exactly
	// two live keys, and at the default spread of 6 that is 2 * 13 = 26 HMACs,
	// measured at 0.292 us each — 7.6 us per rejected datagram against 3.8 us
	// with one key. The ceiling leaves room for a wider freshness window or a
	// three-key emergency overlap without leaving room for a mistake.
	//
	// It is enforced by NewResponder and by Responder.SetAdmissionKeys, which
	// share errIfAdmissionRejectOverBudget. It is deliberately NOT enforced by
	// GatewayParams.validate: an initiator does not pay the reject-path cost, so
	// a wide-skew client config is not a flood amplifier, and putting the product
	// in validate(needKeys=true) would refuse that client. Construction of a
	// Responder is the moment the bound has to hold; rotation is the other.
	MaxAdmissionHMACs = 64
)

// Handshake message geometry. Handshake messages are variable length by
// construction — padding lives inside the final AEAD and its length is implied
// by the message length — so these are minima, not sizes.
const (
	// handshakePayloadHeaderSize is flags(1) || payloadLen(2 BE), inside the
	// AEAD.
	handshakePayloadHeaderSize = 3

	// MaxHandshakePayload bounds the application payload a handshake message
	// may carry (e.g. a client hint). Kept small so that the initiation stays
	// far below any plausible path MTU.
	MaxHandshakePayload = 256

	// MaxHandshakeMessage bounds what Parse* will look at. It is well under the
	// 1280-byte IPv6 minimum MTU so that a Winn3 handshake never fragments and
	// never depends on path-MTU luck. A fragmented first packet is itself a
	// distinctive fingerprint.
	MaxHandshakeMessage = 1024
)

// Transport limits.
const (
	// RekeyAfterMessages is the soft trigger: once a direction has sent this
	// many messages the session SHOULD ratchet. Well below any nonce-reuse
	// boundary, and low enough that a compromise of one epoch's keys exposes a
	// bounded slice of traffic.
	RekeyAfterMessages uint64 = 1 << 28

	// RejectAfterMessages is the hard ceiling. Past this the session refuses to
	// seal, full stop. There is no "one more packet" path.
	RejectAfterMessages uint64 = (1 << 32) - (1 << 16)

	// RekeyAfterBytes is the second soft trigger: once a direction has sealed
	// this many on-wire bytes the session SHOULD ratchet, whether or not the
	// message count has been reached.
	//
	// It exists because RekeyAfterMessages alone bounds the wrong quantity. The
	// reason for a soft trigger is to bound how much traffic one epoch's key
	// compromise exposes, and 2^28 messages is 320 GiB of full-MTU packets but
	// only a few gigabytes of small interactive ones. Whichever bound is reached
	// first is the one that should fire, so both exist.
	//
	// 64 GiB is a deliberate choice rather than a primitive limit: nothing about
	// ChaCha20-Poly1305 is under strain here — the nonce ceiling is
	// RejectAfterMessages and it is three orders of magnitude away. This is an
	// exposure budget. At a full 1280-byte MTU it fires around 2^25.7 messages,
	// so it leads the message trigger for bulk transfer and trails it for small
	// packets, which is the intended shape.
	//
	// Like RekeyAfterMessages this counts ONE DIRECTION, the local send
	// direction, so each end must check its own. A ratchet re-keys both
	// directions, so whichever end is doing the sending is the end that trips.
	RekeyAfterBytes uint64 = 1 << 36

	// DefaultTokenWindow is how many future demux tokens a receiver
	// precomputes. It is simultaneously the reordering tolerance and the exact
	// replay filter, because a consumed token is erased.
	//
	// The reordering tolerance it buys is `size/2 − 1`, not `size/2`: the
	// force-advance rule in replay.go retires the low edge to
	// `counter − half + 1`, so at this default the measured cliff is at 511 and
	// not 512. See the note on tokenWindow.consume.
	//
	// This is the design's known scaling cost: a gateway pays roughly this many
	// map entries per session per direction. A large deployment must either
	// size it down or keep the full table only for sessions that might migrate
	// carriers, using the 5-tuple as a fast-path hint otherwise.
	DefaultTokenWindow = 1024

	// MinTokenWindow and MaxTokenWindow bound what a config may ask for.
	MinTokenWindow = 16
	MaxTokenWindow = 1 << 16

	// CallerOwnsTokenWindow is the Config.TokenWindow value that says "an
	// external index owns the demultiplexing". It exists for one deployment:
	// a gateway that already indexes every live session's tokens globally and
	// would otherwise hold each window twice.
	//
	// It moves the LOOKUP out and nothing else. The session still keeps its own
	// replay filter, its own reordering tolerance and its own force-advance
	// rule, sized at DefaultTokenWindow, because those cost one byte per counter
	// rather than the ~38 bytes an indexed token costs and because a replay
	// filter that lives in the caller is a replay filter that is one caller bug
	// away from not existing. See Session.OpenAt.
	//
	// A session in this mode cannot Open — it has no way to turn a token into a
	// counter — and says so with ErrCallerOwnsWindow. It is OpenAt or nothing.
	CallerOwnsTokenWindow = -1
)

// Freshness defaults for the admission tag's never-transmitted time bucket.
const (
	DefaultBucketWindow = 10 * time.Second
	DefaultMaxSkew      = 60 * time.Second

	// maxBucketCandidates defensively bounds the verification work a
	// caller-supplied Freshness can demand, in the same spirit as
	// internal/initauth's bound of the same name.
	maxBucketCandidates = 4096
)

// PaddingPolicy selects how a sender shapes message lengths.
//
// Uniform-random padding is NOT offered, because it is itself a signature: real
// traffic is strongly bimodal (full-MTU bulk and small interactive), not
// uniform. None of these defeat a determined traffic-analysis adversary; they
// defeat fixed-size matching and constant-overhead arithmetic. Claiming more
// than that would be dishonest.
type PaddingPolicy uint8

const (
	// PadDefault is the zero value, and it means "the caller did not choose".
	// It resolves to PadBucket, the design's default, in session.Config's
	// normalise.
	//
	// It exists because the alternative is worse. When PadNone sat at zero,
	// "the caller said nothing" and "the caller deliberately asked for no
	// length shaping" were the same value, so a config that merely forgot the
	// field silently shipped the weakest policy in the set. A default that
	// degrades security when a field is omitted is a trap, and on a
	// circumvention tunnel it is a trap that leaks inner packet sizes.
	PadDefault PaddingPolicy = iota

	// PadNone adds nothing. Fastest, and it leaks inner packet sizes, which is
	// a real and well-studied leak. For high-trust networks only, and it must
	// now be named deliberately rather than arrived at by omission.
	PadNone

	// PadBucket rounds up to the next boundary in a bucket set drawn per
	// session, so two clients do not share a length histogram. This is the
	// default, and PadDefault resolves to it.
	PadBucket

	// PadMimic defers to a target distribution supplied by the carrier, which
	// knows what its cover protocol looks like. The core does not implement the
	// distribution; it only honours the resulting target length.
	PadMimic
)

// Errors. Every one of these is LOCAL. Nothing here is ever signalled to a
// peer, and a caller that turns one into an observable response has reopened
// the probe oracle this design exists to close.
var (
	ErrConfig            = errors.New("winn3: invalid configuration")
	ErrShortMessage      = errors.New("winn3: message too short")
	ErrLongMessage       = errors.New("winn3: message too long")
	ErrUnauthenticated   = errors.New("winn3: message is not authenticated")
	ErrReplay            = errors.New("winn3: message is a replay")
	ErrDecrypt           = errors.New("winn3: decryption failed")
	ErrPeerIdentity      = errors.New("winn3: peer identity is not accepted")
	ErrStateSequence     = errors.New("winn3: operation out of sequence for this state")
	ErrCounterExhausted  = errors.New("winn3: message counter exhausted, rekey required")
	ErrPayloadTooLarge   = errors.New("winn3: payload exceeds the limit")
	ErrPQAlreadyRatchet  = errors.New("winn3: post-quantum ratchet already applied")
	ErrTargetLenTooSmall = errors.New("winn3: padding target is below the minimum message length")

	// ErrCallerOwnsWindow reports that Open was called on a session configured
	// with CallerOwnsTokenWindow, which holds no token index and therefore
	// cannot place a datagram by itself. Use OpenAt.
	//
	// It is a distinct value rather than ErrUnauthenticated because the two say
	// completely different things to an operator — one is a packet, the other is
	// a misconfiguration that would silently black-hole an entire gateway — and
	// because it is reachable only by the local caller's own config, never by
	// anything on the wire. Like every error here it is LOCAL: a caller that
	// lets a peer distinguish it has reopened the probe oracle.
	ErrCallerOwnsWindow = errors.New("winn3: this session's receive index is caller-owned; use OpenAt")

	// ErrWiped reports that Session.Wipe has zeroised this session's key
	// material. Seal, Open, OpenAt, MixPQ and Rekey all refuse afterwards.
	//
	// It is a distinct value rather than ErrStateSequence because the two say
	// different things to an operator: one is a call-order bug, the other is
	// the session having been destroyed on purpose. Like every error here it
	// is LOCAL: nothing about it is ever written to a peer.
	ErrWiped = errors.New("winn3: session key material has been wiped")
)

// Freshness carries the never-transmitted time-bucket parameters.
//
// They are NOT negotiated: there is no field to carry them and no error signal
// to report a mismatch, so a client and a gateway that disagree produce a
// rejection indistinguishable from a dropped packet. Both ends are configured
// from the same control-plane descriptor.
type Freshness struct {
	// BucketWindow is the width of one bucket. Zero means DefaultBucketWindow.
	BucketWindow time.Duration

	// MaxSkew is the clock difference tolerated in either direction. Zero means
	// DefaultMaxSkew.
	MaxSkew time.Duration
}

func (f Freshness) resolve() (window time.Duration, spread int, err error) {
	window = f.BucketWindow
	if window == 0 {
		window = DefaultBucketWindow
	}
	skew := f.MaxSkew
	if skew == 0 {
		skew = DefaultMaxSkew
	}
	if window < time.Second {
		return 0, 0, errWrap(ErrConfig, "bucket window %s is below one second", window)
	}
	if window%time.Second != 0 {
		// bucketIndex counts whole seconds (admission.go), while spread below
		// is computed from the full duration: a 1500 ms window at 60 s skew
		// would verify against 40 one-second buckets, narrower than MaxSkew.
		return 0, 0, errWrap(ErrConfig, "bucket window %s is not a whole number of seconds", window)
	}
	if skew < window {
		return 0, 0, errWrap(ErrConfig, "max skew %s is below the bucket window %s", skew, window)
	}
	spread = int((skew + window - 1) / window)
	if 2*spread+1 > maxBucketCandidates {
		return 0, 0, errWrap(ErrConfig, "%d candidate buckets exceeds the %d ceiling", 2*spread+1, maxBucketCandidates)
	}
	return window, spread, nil
}

// GatewayParams is the per-gateway wire profile. Every field here differs
// across gateways by design: a parameter shared fleet-wide is a fleet-wide
// constant, which is the exact failure this protocol replaces.
type GatewayParams struct {
	// AdmissionKeys are the gateway's admission secrets, newest first. More
	// than one may be live at a time so that a rotation can complete without an
	// outage. A client holds exactly one.
	AdmissionKeys [][]byte

	// GatewayID binds a tag to one gateway so that an initiation captured at
	// gateway A cannot be replayed at gateway B even when both are mid-rotation
	// on a shared key. It is an authenticated input to the tag and is never
	// transmitted.
	GatewayID []byte

	// TagSize is this gateway's admission tag length, in [MinTagSize,
	// MaxTagSize]. Zero means DefaultTagSize.
	TagSize int

	// Fresh carries the bucket parameters.
	Fresh Freshness
}

func (g GatewayParams) tagSize() int {
	if g.TagSize == 0 {
		return DefaultTagSize
	}
	return g.TagSize
}

// validate reports why a gateway profile is unusable, or nil.
func (g GatewayParams) validate(needKeys bool) error {
	ts := g.tagSize()
	if ts < MinTagSize || ts > MaxTagSize {
		return errWrap(ErrConfig, "tag size %d outside [%d,%d]", ts, MinTagSize, MaxTagSize)
	}
	if len(g.GatewayID) == 0 {
		return errWrap(ErrConfig, "gateway id is empty")
	}
	if len(g.GatewayID) > 255 {
		return errWrap(ErrConfig, "gateway id is %d bytes, more than 255", len(g.GatewayID))
	}
	if needKeys {
		if len(g.AdmissionKeys) == 0 {
			return errWrap(ErrConfig, "at least one admission key is required")
		}
		for i, k := range g.AdmissionKeys {
			if len(k) < minAdmissionKeySize {
				return errWrap(ErrConfig, "admission key %d is %d bytes, need at least %d", i, len(k), minAdmissionKeySize)
			}
		}
	}
	if _, _, err := g.Fresh.resolve(); err != nil {
		return err
	}
	return nil
}

// admissionRejectCost is the HMAC count verifyAdmission pays on a datagram that
// matches nothing: every key, every candidate bucket, no early exit.
func admissionRejectCost(nKeys, spread int) int {
	return nKeys * (2*spread + 1)
}

// errIfAdmissionRejectOverBudget refuses a (key count, spread) pair that would
// make an unauthenticated datagram cost more than MaxAdmissionHMACs HMACs.
func errIfAdmissionRejectOverBudget(nKeys, spread int) error {
	cost := admissionRejectCost(nKeys, spread)
	if cost > MaxAdmissionHMACs {
		return errWrap(ErrConfig,
			"%d keys at a spread of %d would cost %d HMACs on the unauthenticated reject path, ceiling %d",
			nKeys, spread, cost, MaxAdmissionHMACs)
	}
	return nil
}
