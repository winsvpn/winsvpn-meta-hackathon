// Package knock implements a fwknop-style Single Packet Authorization (SPA)
// pre-auth step for Winn's carrier listeners.
//
// # Why this exists
//
// The carrier server (cmd/winn-carrier-server) already hides *what it is*
// from an unauthenticated peer: internal/coverlisten terminates TLS with an
// ordinary-looking certificate, internal/decoy serves a plausible site, and
// mandatory ECH keeps the real SNI private. None of that hides *that it is
// there*. Every one of those defences requires completing a TCP or QUIC
// handshake first, so a censor doing bulk active probing - connect to every
// address on a candidate port list, see what talks back - always gets an
// answer. This package is an additional, opt-in layer beneath all of that:
// while enabled, a source address that has not first presented a valid
// single-packet credential gets no answer at all, on any listener, whether
// its probe is well-formed or garbage.
//
// # What this is not
//
// This is not an identity or authorization system. internal/carrierauth and
// internal/pqauth still do that job, unchanged, once a connection is let
// through. A knock only proves "holds the deployment's current SPA key",
// which - exactly like a shared fwknop key or an unlisted Tor bridge line -
// may be held by more than one person behind the same CGNAT egress address.
// See Gate's doc comment for the precise scoping.
//
// # Wire format and why it has no cleartext fields
//
// A knock is exactly PacketSize bytes:
//
//	[0:16)  nonce   - random, also the replay key
//	[16:48) tag     - HMAC-SHA256, 32 bytes
//	[48:..) padding - random, uninterpreted
//
// PacketSize is supplied by the caller, not fixed by this package. The
// recommended value is whatever the deployment's QUIC Initial packets
// already are - carrier.H3InitialPacketSize(maxOuterDatagram) - so a knock
// is byte-for-byte the same size as the only other pre-handshake datagram
// this port legitimately receives. A bespoke fixed size would itself be the
// fingerprint the task that created this package was asked to avoid.
//
// There is deliberately no version byte, timestamp, or key identifier on the
// wire. An HMAC tag and a nonce are indistinguishable from random bytes to
// anyone without the key; a plaintext timestamp field is not - it is an
// 8-byte counter that only ever takes values near true wall-clock time, and
// that regularity is itself a passive distinguisher between knock datagrams
// and both random background noise and the encrypted QUIC Initials the
// datagram is sized to match. So the protocol version and the freshness
// window are authenticated inputs to the tag, recomputed by the verifier
// from its own clock, rather than fields the client sends. Verify tries a
// bounded number of nearby time buckets instead of trusting a claimed one.
// This is the same trick TOTP uses to avoid sending a timestamp in the
// clear; it is not a new cryptographic primitive, only a different set of
// inputs to the same HMAC-SHA256 call.
//
// # Why HMAC-SHA256 and not ML-DSA
//
// Every other authentication surface in this tree (internal/pqauth,
// internal/carrierauth) signs with ML-DSA-65/87. This package deliberately
// does not, and the reason is arithmetic, not taste: this tree's
// cloudflare/circl gives SignatureSize = 3309 bytes for ML-DSA-65 and 4627
// for ML-DSA-87 (verified by direct execution against the pinned circl
// v1.6.3, not assumed from the FIPS 204 spec). Either one is already larger
// than the 1,452-byte ceiling carrier.H3InitialPacketSize enforces, before
// the nonce, tag framing, or padding are even added, so an ML-DSA-signed
// knock cannot be size-matched to a QUIC Initial in one UDP datagram without
// IP fragmentation - and a censor that already drops or flags fragmented UDP
// (a common, long-standing heuristic, precisely because fragmentation is a
// classic evasion tool) would turn the knock into a worse fingerprint than
// no SPA at all. A verifier-side cost matters too: this port is exactly the
// surface exposed to anonymous internet scanning, and HMAC verification is
// orders of magnitude cheaper than an asymmetric signature check, which
// bounds the CPU a flood of forged knocks can extract before the length
// filter and rate limiter (see Gate) even engage.
//
// SHA-256 is the one primitive this construction needs, and it is already in
// this tree's approved set (internal/pqauth imports crypto/sha256 directly).
// HMAC-SHA256 is stdlib (crypto/hmac + crypto/sha256): no new dependency.
// What SHOULD be said loudly, per the brief that created this package: the
// SPA key itself is new key material with no analogue in the existing
// device registry. It is a deployment- or gateway-scoped shared secret,
// analogous to a shared fwknop key or an unlisted bridge line, provisioned
// and rotated out of band through the same owner-controlled channel already
// used for the trust-root fingerprint and gateway manifest signing keys (see
// docs/handoff §10.4 item 1). It is not tied to, and does not replace, any
// device's ML-DSA identity. See THREAT_MODEL.md-style framing in
// SECURITY_DESIGN.md (added alongside this package) for the full comparison
// this conclusion was drawn from.
package knock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// NonceSize is the length of the random, replay-tracked nonce.
	NonceSize = 16

	// TagSize is the length of the HMAC-SHA256 authenticator.
	TagSize = sha256.Size

	// HeaderSize is the fixed, non-padding portion of a knock datagram.
	HeaderSize = NonceSize + TagSize

	// version is authenticated as an input to the tag but is never
	// transmitted; see the package doc for why.
	version = 1

	// minKeySize is a floor against accidentally configuring an
	// effectively-empty shared secret. It is not a claim about how the key
	// should be generated - callers are expected to use crypto/rand.
	minKeySize = 16

	defaultBucketWindow = 10 * time.Second
	defaultMaxSkew      = 60 * time.Second

	// maxBucketCandidates defensively bounds the work Verify can be made to
	// do by a caller-supplied Options. A real deployment needs low single
	// digits of candidates (MaxSkew/BucketWindow in each direction); this
	// only guards against a misconfiguration turning Verify into a
	// CPU-exhaustion vector in its own right.
	maxBucketCandidates = 4096
)

// Errors returned by Build and Verify. Verify intentionally collapses every
// validation failure - wrong length, expired timestamp, wrong key, tampered
// tag - into one of a small number of coarse errors. A verifier that returns
// a different error for "well-formed but wrong key" than for "garbage" hands
// an active prober a free oracle for learning the wire format one field at a
// time.
var (
	// ErrPacketSize is returned by Verify when a packet is shorter than
	// HeaderSize. Verify has no configured PacketSize and does not enforce
	// exact length; Gate.considerKnock does that check before calling Verify.
	// Checking the header floor first, before any cryptographic work, is what
	// keeps Verify cheap against the internet background noise (scanners,
	// misdirected traffic, stray retransmits) that dominates traffic to any
	// public UDP port.
	ErrPacketSize = errors.New("knock: packet has the wrong length")

	// ErrUnauthenticated covers every cryptographic failure: no configured
	// key and no nearby time bucket produced a matching tag. Deliberately
	// undifferentiated; see the package doc.
	ErrUnauthenticated = errors.New("knock: packet does not authenticate")

	errNoKeys         = errors.New("knock: at least one key is required")
	errKeyTooShort    = fmt.Errorf("knock: key must be at least %d bytes", minKeySize)
	errPacketTooBig   = errors.New("knock: packetSize exceeds a UDP-safe datagram")
	errBadSkewWindow  = errors.New("knock: MaxSkew must be >= BucketWindow")
	errTooManyBuckets = fmt.Errorf(
		"knock: MaxSkew/BucketWindow requires more than %d time-bucket candidates",
		maxBucketCandidates,
	)
)

// maxSafePacketSize is a conservative ceiling (not a recommendation) meant
// only to catch obvious misconfiguration - e.g. accidentally passing a
// megabyte "packet size". It is comfortably above any real Path MTU.
const maxSafePacketSize = 9000

// Options controls the freshness window. Both fields are policy, not
// secrets, and are safe to log or hardcode; they must match between every
// client and every server sharing a key, or verification will simply always
// fail (fail closed, not fail open).
type Options struct {
	// BucketWindow is the width of one time bucket. Must be at least one
	// second. Zero uses the default (10s).
	BucketWindow time.Duration

	// MaxSkew is the maximum clock difference, in either direction, that
	// Verify tolerates. Zero uses the default (60s). Must be >= BucketWindow.
	MaxSkew time.Duration
}

func (o Options) resolve() (Options, error) {
	if o.BucketWindow <= 0 {
		o.BucketWindow = defaultBucketWindow
	}
	if o.BucketWindow < time.Second {
		return Options{}, errors.New("knock: BucketWindow must be at least one second")
	}
	if o.MaxSkew <= 0 {
		o.MaxSkew = defaultMaxSkew
	}
	if o.MaxSkew < o.BucketWindow {
		return Options{}, errBadSkewWindow
	}
	if bucketSpread(o.MaxSkew, o.BucketWindow) > maxBucketCandidates {
		return Options{}, errTooManyBuckets
	}
	return o, nil
}

// bucketSpread returns how many buckets on *each side* of the current one
// Verify must try, so the total candidate count is 2*bucketSpread+1.
func bucketSpread(maxSkew, bucketWindow time.Duration) int64 {
	spread := int64(maxSkew / bucketWindow)
	if time.Duration(spread)*bucketWindow < maxSkew {
		spread++ // round up so the full requested skew is always covered
	}
	return spread
}

func bucketIndex(t time.Time, bucketWindow time.Duration) int64 {
	seconds := int64(bucketWindow / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	unix := t.Unix()
	// Floor toward negative infinity so bucket boundaries are stable across
	// the epoch; Go's integer division truncates toward zero, which would
	// otherwise put times just before 1970 in the wrong bucket. No real
	// deployment clock is there, but a test clock might be.
	if unix >= 0 {
		return unix / seconds
	}
	return -((-unix + seconds - 1) / seconds)
}

// tag computes HMAC-SHA256(key, version || bucket || nonce). bucket is the
// 8-byte big-endian time-bucket index, never transmitted; see package doc.
func tag(key []byte, bucket int64, nonce []byte) []byte {
	var buf [1 + 8 + NonceSize]byte
	buf[0] = version
	binary.BigEndian.PutUint64(buf[1:9], uint64(bucket))
	copy(buf[9:], nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:])
	return mac.Sum(nil)
}

// validateKey rejects an empty or suspiciously short key. It cannot and does
// not attempt to judge entropy.
func validateKey(key []byte) error {
	if len(key) < minKeySize {
		return errKeyTooShort
	}
	return nil
}

// Build constructs one SPA knock datagram authenticated under key, padded
// with random bytes to exactly packetSize.
//
// packetSize must be chosen by the caller to match this deployment's
// pre-handshake QUIC Initial size - see the package doc - not left at a
// package default, because there is no size this package could default to
// that would be correct for every deployment's carrier.DefaultMaxDatagram.
func Build(key []byte, packetSize int, now time.Time, opts Options) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if packetSize < HeaderSize {
		return nil, fmt.Errorf(
			"knock: packetSize %d is smaller than the %d-byte header",
			packetSize, HeaderSize,
		)
	}
	if packetSize > maxSafePacketSize {
		return nil, errPacketTooBig
	}
	resolved, err := opts.resolve()
	if err != nil {
		return nil, err
	}

	packet := make([]byte, packetSize)
	nonce := packet[:NonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("knock: generating nonce: %w", err)
	}
	if packetSize > HeaderSize {
		if _, err := rand.Read(packet[HeaderSize:]); err != nil {
			return nil, fmt.Errorf("knock: generating padding: %w", err)
		}
	}
	bucket := bucketIndex(now, resolved.BucketWindow)
	copy(packet[NonceSize:HeaderSize], tag(key, bucket, nonce))
	return packet, nil
}

// Verify checks packet against every key in keys, trying each nearby time
// bucket within opts.MaxSkew of now for each key. It returns the nonce (the
// caller is responsible for replay tracking - this function is stateless by
// design, see Gate) and the index into keys that matched.
//
// keys is tried in order and should list the deployment's current key
// first, since that is the common case and this loop is otherwise an
// unauthenticated peer's only cost to impose. A second (or third) entry
// supports a rotation overlap window: the previous key keeps verifying
// until every client is known to hold the new one.
func Verify(packet []byte, keys [][]byte, now time.Time, opts Options) (nonce [NonceSize]byte, keyIndex int, err error) {
	if len(keys) == 0 {
		return nonce, -1, errNoKeys
	}
	if len(packet) < HeaderSize {
		return nonce, -1, ErrPacketSize
	}
	resolved, resolveErr := opts.resolve()
	if resolveErr != nil {
		return nonce, -1, resolveErr
	}
	copy(nonce[:], packet[:NonceSize])
	gotTag := packet[NonceSize:HeaderSize]

	spread := bucketSpread(resolved.MaxSkew, resolved.BucketWindow)
	center := bucketIndex(now, resolved.BucketWindow)
	for ki, key := range keys {
		if len(key) == 0 {
			continue
		}
		for delta := -spread; delta <= spread; delta++ {
			want := tag(key, center+delta, nonce[:])
			if hmac.Equal(want, gotTag) {
				return nonce, ki, nil
			}
		}
	}
	var zero [NonceSize]byte
	return zero, -1, ErrUnauthenticated
}
