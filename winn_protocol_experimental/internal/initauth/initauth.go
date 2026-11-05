// Package initauth authorises a Winn Protocol v3 connection initiation without
// putting a single additional byte on the wire.
//
// # The problem this exists for
//
// The v3 datapath's only proven carrier is direct-awg: the engine relays each
// AmneziaWG datagram verbatim to the gateway, adding no header, no padding and
// no handshake of its own (see ../../datapath/carrier.go and
// ../../datapath/config.go). So the connection-initiation fingerprint of v3 IS
// the AmneziaWG initiation fingerprint, on raw UDP, to a bare IP literal — and
// udp/9110 has no source restriction on it at all.
//
// The obvious answer is single-packet authorisation, and this tree already
// contains a good, reviewed, tested implementation of it in ../knock. It is
// shelved, and correctly so, for reasons recorded in
// docs/handoff/SPA_DECISION_20260806.md. Two of those reasons are the ones this
// package was written to escape:
//
//   - A knock is a SEPARATE PACKET, and a separate packet is a separate flow. A
//     dedicated port that receives uniform-length maximum-entropy datagrams and
//     never answers one of them is a signature with essentially no
//     false-positive population to hide in. "Indistinguishable from ordinary
//     traffic" is not achievable for anything whose defining behaviour is
//     silence to the unauthorised.
//   - A knock authorises a SOURCE ADDRESS. Under the CGNAT this product's users
//     sit behind, that address is shared by thousands of subscribers of a
//     state-linked carrier, so an investigator with a SIM on the same carrier is
//     inside the grant without holding the key.
//
// # What this package does instead
//
// AmneziaWG prepends S1 random bytes to every handshake initiation. Both ends
// know S1; the receiver skips those bytes and parses the header word at
// packet[S1:]; nothing reads them; and they sit OUTSIDE the AEAD — upstream
// seals with a nil AAD. ../../datapath/classify.go carries the evidence chain
// for that layout across three independent implementations (amneziawg-go
// device/send.go and device/receive.go, amneziawg-tools src/config.c, and the
// kernel module's init_padding/resp_padding/cookie_padding/transport_padding).
//
// So those S1 bytes are free, guaranteed-present space on the exact packet that
// starts a session. This package fills them with a keyed authenticator over the
// rest of the datagram:
//
//	prefix = HMAC-SHA256(key, label || version || S1 || bucket || body)  [truncated to S1]
//	body   = datagram[S1:]  -- the whole 148-byte MessageInitiation
//
// The censor's view does not change: the field was uniform random before and is
// uniform random after. Same packet, same size, same offset, same count, same
// timing, same port, same flow. There is no new observable to match on, because
// there is no new anything. Zero added packets, zero added bytes.
//
// # Why the time bucket is never transmitted
//
// Freshness is a TOTP-style bucket index that is an AUTHENTICATED INPUT to the
// tag and is never sent, exactly as ../knock does it and for the same reason: an
// explicit timestamp only ever takes values near true wall-clock time, which is
// a learnable statistical shape, and this field must be indistinguishable from
// the random bytes it replaces. The verifier tries nearby buckets against its
// own clock, nearest first.
//
// # What it costs to ship
//
// Everything here is bytes on the socket the host already opened and protected.
// Android, Linux and Windows reach this module as a subprocess through
// ../../datapath/duplex; iOS and macOS reach it through the C ABI in
// ../../cdatapath. So one Go change lands on five platforms with no host work,
// no new entitlement and no new signing surface. Nothing here needs a raw
// socket or root on the client, which matters because a raw socket is
// unobtainable on iOS and on an unrooted Android device — see the ranking in
// docs/handoff/WINN3_ALT_INITIATION_20260808.md §3.2.
//
// # What it does NOT do
//
//   - It does not change the header word four bytes later. A fleet running
//     H1=11 still emits 0B 00 00 00 at offset S1. That is a separate, already
//     written, currently disabled fix (AWG_STRONG_OBFUSCATION).
//   - It does not help against a censor who drops UDP to the gateway. The gate
//     is on the server; the drop is on the path.
//   - It does not make an already-silent port quieter. amneziawg-go is already
//     silent to unauthenticated traffic. What a Gate adds is that nothing
//     unauthenticated reaches the AWG state machine at all, and — the real
//     prize — that udp/9110 becomes gateable for the first time, because the
//     authenticator is not a packet needing a carrier.
//
// # Compatibility, which is load-bearing
//
// A sealed prefix is indistinguishable from the random one to any server that
// is not checking. A sealing client therefore talks to an unmodified gateway
// with no change in behaviour whatsoever, which is what lets the client half
// ship BEFORE the server half. That is the opposite of the rollout risk that
// shelved the firewall gate, where the server had to move first and a mistake
// meant every user offline.
package initauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// AWGInitiationBodySize is the size of an AmneziaWG/WireGuard handshake
// initiation message, excluding any S1 prefix: a 4-byte type word, a 4-byte
// sender index, a 32-byte ephemeral public key, a 48-byte encrypted static key,
// a 28-byte encrypted timestamp, and two 16-byte MACs.
//
// This is the constant the measured captures agree on from three platforms: an
// initiation observed at 164 bytes under S1=16, at 176 bytes under S1=28, and
// at 230 bytes under S1=82.
const AWGInitiationBodySize = 148

const (
	// MinTagSize is the smallest S1 prefix this package will authenticate. A
	// forged tag buys an attacker one datagram delivered to a state machine
	// that will reject it cryptographically anyway, so the bar is set for
	// "not trivially brute-forceable online" rather than for confidentiality.
	// The shipping fleet profile uses S1=16, which is 128 bits.
	MinTagSize = 8

	// MaxTagSize bounds the expansion work a caller-supplied profile can ask
	// for. The per-node generator draws S1 from [16, 112]; this leaves room
	// well beyond that without letting a malformed profile turn verification
	// into its own CPU-exhaustion vector.
	MaxTagSize = 256

	// minKeySize is a floor against an accidentally-empty shared secret. It is
	// not a claim about how the key should be generated; callers are expected
	// to use crypto/rand.
	minKeySize = 16

	// version is authenticated as an input to the tag but never transmitted.
	version = 1

	// tagLabel domain-separates this construction from ../knock, whose tag is
	// HMAC-SHA256 over exactly 25 bytes of version || bucket || nonce with no
	// label. No input to that MAC can collide with an input to this one: this
	// one begins with the label below and is always longer. A knock captured
	// off the wire is therefore useless as an S1 prefix, and the reverse.
	tagLabel = "winn3-initauth-v1-awg-s1"

	defaultBucketWindow = 10 * time.Second
	defaultMaxSkew      = 60 * time.Second

	// maxBucketCandidates defensively bounds the work Verify can be made to do
	// by a caller-supplied Options, in the same spirit as ../knock's bound of
	// the same name. A real deployment needs low single digits in each
	// direction.
	maxBucketCandidates = 4096
)

// Errors returned by this package. Every one of them is a LOCAL diagnostic: the
// gate never writes anything back on any path, so none of these is ever
// observable by a peer, and callers must not attempt to signal them onward.
var (
	// ErrProfileCannotSeal reports that the deployment's obfuscation profile
	// leaves no usable room for an authenticator — most commonly S1 = 0, which
	// is plain WireGuard's layout and the behaviour of every configuration
	// written before these fields existed.
	//
	// A caller that receives this MUST fall back to not sealing, which is
	// exactly today's behaviour, and MUST NOT turn it into a connection
	// failure. A client that refuses to connect because it cannot seal is a
	// self-inflicted outage on the legacy fleet.
	ErrProfileCannotSeal = errors.New("winn initauth: obfuscation profile has no room for an authenticator")

	// ErrKeyTooShort reports a shared secret below minKeySize.
	ErrKeyTooShort = errors.New("winn initauth: key is too short")

	// ErrNoKeys reports that no key was supplied.
	ErrNoKeys = errors.New("winn initauth: at least one key is required")

	// ErrNotAnInitiation reports that the datagram is not shaped like a
	// handshake initiation under the supplied profile, so there is nothing to
	// seal or verify.
	ErrNotAnInitiation = errors.New("winn initauth: datagram is not a handshake initiation")

	// ErrUnauthenticated reports that no key and no in-skew bucket produced the
	// observed prefix.
	ErrUnauthenticated = errors.New("winn initauth: initiation is not authenticated")
)

// Profile is the slice of the deployment's AmneziaWG obfuscation configuration
// that this package needs, and no more.
//
// It deliberately does NOT import ../../datapath, which owns AwgHeaderSpec and
// the single parser for the "start-end" spelling. The dependency direction in
// this module runs datapath -> internal/..., and reversing it here would block
// the datapath from ever using this package. Callers convert; the parse, the
// bounds and the overlap rule stay in one place.
type Profile struct {
	// S1 is how many random bytes AmneziaWG prepends to a handshake
	// INITIATION, so the H1 word begins at offset S1. It is also the length of
	// the authenticator this package writes, because the authenticator IS that
	// prefix.
	S1 uint16

	// H1Start and H1End are the inclusive header-word range for a handshake
	// initiation. A scalar H1 is the degenerate range Start == End, which is
	// how the legacy 11/22/33/44 set keeps working through the identical code
	// path.
	H1Start uint32
	H1End   uint32
}

// InitiationSize is the exact on-wire length of a handshake initiation under
// this profile.
func (p Profile) InitiationSize() int {
	return int(p.S1) + AWGInitiationBodySize
}

// CanSeal reports whether the profile leaves usable room for an authenticator.
//
// Callers should branch on this rather than on an error, because "cannot seal"
// is a normal, expected state on a legacy node and must degrade to today's
// behaviour rather than to a failure.
func (p Profile) CanSeal() bool {
	return p.S1 >= MinTagSize && p.S1 <= MaxTagSize && p.H1Start <= p.H1End
}

// Validate reports why a profile is unusable, or nil.
func (p Profile) Validate() error {
	if p.H1Start > p.H1End {
		return fmt.Errorf("%w: h1 range %d-%d is inverted", ErrProfileCannotSeal, p.H1Start, p.H1End)
	}
	if p.S1 < MinTagSize {
		return fmt.Errorf("%w: s1 is %d, need at least %d", ErrProfileCannotSeal, p.S1, MinTagSize)
	}
	if p.S1 > MaxTagSize {
		return fmt.Errorf("%w: s1 is %d, more than the %d ceiling", ErrProfileCannotSeal, p.S1, MaxTagSize)
	}
	return nil
}

// IsInitiationShaped reports whether a datagram has the exact length and header
// word of a handshake initiation under this profile.
//
// This is the cheap pre-filter that runs before any cryptography, so that
// background scan noise — which is neither the right length nor carrying the
// right header word — costs nothing at all. It is a shape test and nothing
// more: a datagram can be initiation-shaped by chance and still fail
// verification, which is the ordinary rejection path.
func (p Profile) IsInitiationShaped(datagram []byte) bool {
	if p.H1Start > p.H1End {
		return false
	}
	if len(datagram) != p.InitiationSize() {
		return false
	}
	off := int(p.S1)
	word := binary.LittleEndian.Uint32(datagram[off : off+4])
	return word >= p.H1Start && word <= p.H1End
}

// Options carries the freshness parameters. They are NOT negotiated on the
// wire — there is no field to carry them and no error signal to report a
// mismatch — so a client and a gate that disagree produce a rejection that is
// indistinguishable from a dropped packet. Both ends must be configured from
// the same source.
type Options struct {
	// BucketWindow is the width of one time bucket. Must be at least one
	// second. Zero uses the default (10s).
	BucketWindow time.Duration

	// MaxSkew is the maximum clock difference, in either direction, that
	// verification tolerates. Zero uses the default (60s). Must be at least
	// BucketWindow.
	MaxSkew time.Duration
}

func (o Options) resolve() (window time.Duration, spread int, err error) {
	window = o.BucketWindow
	if window == 0 {
		window = defaultBucketWindow
	}
	skew := o.MaxSkew
	if skew == 0 {
		skew = defaultMaxSkew
	}
	if window < time.Second {
		return 0, 0, fmt.Errorf("winn initauth: bucket window %s is below one second", window)
	}
	if skew < window {
		return 0, 0, fmt.Errorf("winn initauth: max skew %s is below the bucket window %s", skew, window)
	}
	spread = int((skew + window - 1) / window)
	if 2*spread+1 > maxBucketCandidates {
		return 0, 0, fmt.Errorf("winn initauth: %d candidate buckets exceeds the %d ceiling", 2*spread+1, maxBucketCandidates)
	}
	return window, spread, nil
}

// bucketIndex floors t to a bucket, toward negative infinity so that the
// boundary behaviour is identical on both sides of the epoch. Go's integer
// division truncates toward zero, which would make the bucket immediately
// before the epoch the same width as two buckets.
func bucketIndex(t time.Time, window time.Duration) int64 {
	secs := t.Unix()
	w := int64(window / time.Second)
	if secs >= 0 {
		return secs / w
	}
	return -((-secs + w - 1) / w)
}

// candidateBuckets returns the buckets to try, NEAREST FIRST, so that the
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

// tagInto writes len(out) bytes of authenticator into out.
//
// Stage one binds every input under one HMAC. Stage two expands that result to
// the requested width in 32-byte blocks, which is needed because S1 may exceed
// SHA-256's output — the per-node generator draws it from [16, 112]. This is an
// extract-then-expand shape; it is written out rather than pulled from a KDF
// package so that the exact bytes committed to are visible at the call site.
//
// The tag LENGTH is authenticated. Without that, two nodes configured with
// different S1 values under the same key would produce prefixes where one is a
// prefix of the other, and a datagram sealed for the wider node would verify at
// the narrower one.
func tagInto(key []byte, bucket int64, s1 uint16, body []byte, out []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tagLabel))

	var hdr [1 + 2 + 8]byte
	hdr[0] = version
	binary.BigEndian.PutUint16(hdr[1:3], s1)
	binary.BigEndian.PutUint64(hdr[3:11], uint64(bucket))
	mac.Write(hdr[:])
	mac.Write(body)
	base := mac.Sum(nil)

	for i := 0; i*sha256.Size < len(out); i++ {
		blk := hmac.New(sha256.New, base)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], uint32(i+1))
		blk.Write(ctr[:])
		sum := blk.Sum(nil)
		copy(out[i*sha256.Size:], sum)
	}
}

func checkKeys(keys [][]byte) error {
	if len(keys) == 0 {
		return ErrNoKeys
	}
	for i, k := range keys {
		if len(k) < minKeySize {
			return fmt.Errorf("%w: key %d is %d bytes, need at least %d", ErrKeyTooShort, i, len(k), minKeySize)
		}
	}
	return nil
}

// Seal writes the authenticator over the datagram's S1 prefix, IN PLACE.
//
// The datagram must already be a complete handshake initiation under the
// profile — Seal does not resize it and does not move a byte of the body. The
// caller owns the buffer; Seal mutates exactly datagram[:S1].
//
// The tag is computed over the body, so a prefix captured from one initiation
// cannot be pasted onto another. If the responder issues a cookie reply and the
// client re-sends with mac2 populated, that is a different body and Seal is
// simply called again on the bytes actually being sent.
func Seal(datagram []byte, key []byte, profile Profile, now time.Time, opts Options) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if err := checkKeys([][]byte{key}); err != nil {
		return err
	}
	window, _, err := opts.resolve()
	if err != nil {
		return err
	}
	if !profile.IsInitiationShaped(datagram) {
		return ErrNotAnInitiation
	}
	s1 := int(profile.S1)
	tagInto(key, bucketIndex(now, window), profile.S1, datagram[s1:], datagram[:s1])
	return nil
}

// Verify reports whether a datagram's S1 prefix authenticates its body under
// any of the supplied keys and any in-skew bucket. It returns the index of the
// key that matched, so that a deployment mid-rotation can tell whether clients
// have moved.
//
// Verify does not consult any replay state; that belongs to the Gate, which
// owns the lifetime. Verify is a pure function of its arguments.
//
// Every failure returns the same error. There is deliberately no distinction
// between "wrong length", "wrong header word", "wrong key" and "outside the
// skew window": the caller must not be able to build an oracle out of them, and
// nothing is written back on any path in any case.
func Verify(datagram []byte, keys [][]byte, profile Profile, now time.Time, opts Options) (keyIndex int, err error) {
	if err := profile.Validate(); err != nil {
		return -1, err
	}
	if err := checkKeys(keys); err != nil {
		return -1, err
	}
	window, spread, err := opts.resolve()
	if err != nil {
		return -1, err
	}
	if !profile.IsInitiationShaped(datagram) {
		return -1, ErrUnauthenticated
	}

	s1 := int(profile.S1)
	presented := datagram[:s1]
	body := datagram[s1:]
	computed := make([]byte, s1)

	// Keys outermost, buckets innermost and nearest first: the live key with a
	// correct clock is one HMAC, and a rotation that has not finished costs one
	// more only for clients still on the old key.
	for ki, key := range keys {
		for _, bucket := range candidateBuckets(bucketIndex(now, window), spread) {
			tagInto(key, bucket, profile.S1, body, computed)
			if hmac.Equal(computed, presented) {
				return ki, nil
			}
		}
	}
	return -1, ErrUnauthenticated
}

// ReplayKey is the value the Gate tracks to refuse a captured initiation being
// replayed from a different socket.
//
// It is SHA-256 over the initiation body. The body contains WireGuard's
// per-handshake ephemeral public key, which is fresh by construction, so a
// genuine retransmission of the same initiation hashes the same and a new
// handshake attempt does not. Hashing the whole body rather than reaching into
// it at a fixed offset keeps this free of any assumption about the message's
// internal layout beyond its length.
func ReplayKey(datagram []byte, profile Profile) ([32]byte, error) {
	if !profile.IsInitiationShaped(datagram) {
		return [32]byte{}, ErrNotAnInitiation
	}
	return sha256.Sum256(datagram[int(profile.S1):]), nil
}
