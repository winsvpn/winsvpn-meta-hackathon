package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// PadAuto asks the core to draw a random padding target for this message. It is
// the recommended value.
//
// It exists because the failure mode it prevents is real and cheap to hit: if
// every caller passes 0, every initiation on the fleet has the same length, and
// a fixed length is a fingerprint just as surely as a fixed byte is. Making the
// safe value the easy one is the point.
const PadAuto = -1

// DefaultHandshakePadSpread is the width of the automatic padding draw.
//
// Uniform is the right shape HERE, unlike for data packets (see PaddingPolicy):
// a handshake is a single message per session, so what matters is that lengths
// are spread across the fleet, not that one flow's length histogram resembles
// some cover protocol.
const DefaultHandshakePadSpread = 256

// Config is the configuration shared by both roles.
type Config struct {
	// Gateway is the per-gateway wire profile. An initiator needs exactly one
	// admission key; a responder may hold several so a rotation can complete
	// without an outage.
	Gateway GatewayParams

	// PSK is an optional 32-byte per-subscriber preshared key, the one the
	// winn/2 rekey protocol rotates. When present it is mixed into the chain
	// before the payload stage key is derived, so a stolen client static key
	// alone cannot produce a valid handshake.
	//
	// It carries a second property that is easy to miss and is the reason for
	// RequirePSK below: it is what stands between a compromised GATEWAY static
	// key and key-compromise impersonation. An attacker holding the gateway's
	// private key can compute both es and ss for any client whose public key
	// they know, and can therefore impersonate that client TO THE REAL GATEWAY,
	// which then attributes the session to an innocent subscriber. The PSK is
	// the only input in that chain the attacker does not have. Forward secrecy
	// is not affected either way — epoch-0 keys are derived only after ee and se
	// are mixed, and neither is computable from the gateway static key alone.
	PSK []byte

	// RequirePSK refuses to build an endpoint that has no PSK.
	//
	// It is a deployment switch, not a protocol change, and it defaults to off
	// so that nothing existing breaks. A profile that faces a state adversary —
	// where "the gateway was seized" is a planned-for event rather than a
	// hypothetical — should set it, because without a PSK gateway-key compromise
	// buys the attacker client impersonation as well as a rogue gateway.
	//
	// It is off by default rather than on because the per-subscriber PSK is not
	// populated in the shipping deployment today; turning this on before that
	// changes would refuse every enrolled client. See
	// docs/handoff/WINN3_KEY_SCHEDULE_FINDINGS_CLOSED_20260808.md for what has
	// to be true first.
	RequirePSK bool

	// Rand supplies randomness. Nil means crypto/rand.Reader. It is injected
	// rather than reached for so that known-answer vectors are reproducible.
	Rand io.Reader

	// Now supplies the clock, for the never-transmitted freshness bucket. Nil
	// means time.Now. Injected for the same reason.
	Now func() time.Time

	// Codec renders an ephemeral public key for the wire. Nil means
	// DefaultEphemeralCodec; see EphemeralCodec for what that costs.
	Codec EphemeralCodec

	// ReplayJournal is the path of the persisted handshake replay journal
	// (F-02; see the header of replay.go). Empty is the reusable library
	// default and keeps in-process-only behavior. Production gateway serve
	// requires an absolute path and refuses WINN3_GATEWAY_REPLAY_JOURNAL=0;
	// durable replay is not an operator opt-out. When set, NewResponder loads
	// the journal fail-closed (a torn or truncated file, a symbolic link, an
	// insecure mode or foreign ownership, or an oversize file all refuse the
	// gateway start), seeds the replay window from it, and appends every
	// accepted initiation. Production wiring reads WINN3_REPLAY_JOURNAL in
	// cmd/winn3-gateway, which refuses a non-absolute path at startup.
	ReplayJournal string

	// TokenWindow is the transport demux-token window, which is simultaneously
	// the reordering tolerance and the exact replay filter. Zero means
	// DefaultTokenWindow.
	//
	// CallerOwnsTokenWindow (-1) is the one non-size value: it says an external
	// index already holds this session's tokens, so the session should keep the
	// replay filter and drop only the lookup table. Such a session must be
	// driven with OpenAt; Open returns ErrCallerOwnsWindow.
	TokenWindow int
}

func (c Config) rnd() io.Reader {
	if c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

func (c Config) clock() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c Config) codec() EphemeralCodec {
	if c.Codec == nil {
		return DefaultEphemeralCodec
	}
	return c.Codec
}

func (c Config) window() int {
	if c.TokenWindow == 0 {
		return DefaultTokenWindow
	}
	return c.TokenWindow
}

func (c Config) validate(responder bool) error {
	if err := c.Gateway.validate(true); err != nil {
		return err
	}
	if !responder && len(c.Gateway.AdmissionKeys) != 1 {
		return errWrap(ErrConfig, "an initiator holds exactly one admission key, got %d", len(c.Gateway.AdmissionKeys))
	}
	if len(c.PSK) != 0 && len(c.PSK) != KeySize {
		return errWrap(ErrConfig, "psk is %d bytes, need 0 or %d", len(c.PSK), KeySize)
	}
	if c.RequirePSK && len(c.PSK) != KeySize {
		return errWrap(ErrConfig, "this profile requires a %d-byte psk and none is configured; "+
			"without it a compromised gateway static key permits client impersonation", KeySize)
	}
	if w := c.window(); w != CallerOwnsTokenWindow && (w < MinTokenWindow || w > MaxTokenWindow) {
		return errWrap(ErrConfig, "token window %d outside [%d,%d]", w, MinTokenWindow, MaxTokenWindow)
	}
	return nil
}

// --- AEAD helpers -----------------------------------------------------------

// sealStage encrypts one handshake stage.
//
// The nonce is all zeroes and that is correct, not a shortcut: every stage key
// is derived under its own label from a chaining key that has already absorbed
// every preceding secret, so no stage key is ever used for a second message.
// A counter here would be a constant with extra steps.
func sealStage(key [KeySize]byte, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [AEADNonceSize]byte
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

func openStage(key [KeySize]byte, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [AEADNonceSize]byte
	pt, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// --- payload encoding -------------------------------------------------------

// HandshakeFlagDualAuth is the only defined handshake payload flag. The
// initiator sets it when its build supports the dual-signature session
// attestation (docs/DUAL_SIGNATURE_SPEC.md). The responder never sets flags in
// its reply: an older client checks that the flags byte is zero on receipt, so
// a nonzero response would break every shipped client.
const HandshakeFlagDualAuth uint8 = 0x01

// encodeHandshakePayload lays out flags || payloadLen || payload || padding.
//
// There is no length field on the wire. This one is INSIDE the AEAD, so the
// real payload length is invisible and the padding length is implied by the
// message length the carrier delivers. The padding bytes are left zero on
// purpose: they are inside the AEAD, so their content is unobservable, and
// filling them from the CSPRNG would spend entropy for nothing and would make
// known-answer vectors non-deterministic.
func encodeHandshakePayload(flags uint8, payload []byte, padLen int) ([]byte, error) {
	if flags&^HandshakeFlagDualAuth != 0 {
		return nil, errWrap(ErrConfig, "unknown handshake flags 0x%02x", flags)
	}
	if len(payload) > MaxHandshakePayload {
		return nil, errWrap(ErrPayloadTooLarge, "handshake payload is %d bytes, limit %d", len(payload), MaxHandshakePayload)
	}
	out := make([]byte, handshakePayloadHeaderSize+len(payload)+padLen)
	out[0] = flags
	binary.BigEndian.PutUint16(out[1:3], uint16(len(payload)))
	copy(out[handshakePayloadHeaderSize:], payload)
	return out, nil
}

func decodeHandshakePayload(plain []byte) (payload []byte, flags uint8, err error) {
	if len(plain) < handshakePayloadHeaderSize {
		return nil, 0, ErrDecrypt
	}
	if plain[0]&^HandshakeFlagDualAuth != 0 {
		return nil, 0, ErrDecrypt
	}
	flags = plain[0]
	n := int(binary.BigEndian.Uint16(plain[1:3]))
	if n > MaxHandshakePayload || handshakePayloadHeaderSize+n > len(plain) {
		return nil, 0, ErrDecrypt
	}
	out := make([]byte, n)
	copy(out, plain[handshakePayloadHeaderSize:handshakePayloadHeaderSize+n])
	return out, flags, nil
}

// randUint64 draws from the supplied reader.
func randUint64(r io.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// handshakePadding resolves a padding request into a byte count.
//
// The PadAuto draw uses a modulo reduction of a 64-bit value over a range of at
// most 257, so the modulo bias is on the order of 2^-56. That is irrelevant for
// a length that only needs to be spread, and saying so here is cheaper than a
// rejection loop that a future reader would have to re-derive the need for.
func handshakePadding(r io.Reader, minLen, padTo int) (int, error) {
	switch {
	case padTo == PadAuto:
		v, err := randUint64(r)
		if err != nil {
			return 0, err
		}
		return int(v % uint64(DefaultHandshakePadSpread+1)), nil
	case padTo == 0:
		return 0, nil
	case padTo < 0:
		return 0, errWrap(ErrConfig, "padTo %d is negative and is not PadAuto", padTo)
	case padTo < minLen:
		return 0, errWrap(ErrTargetLenTooSmall, "target %d is below the %d-byte minimum for this message", padTo, minLen)
	default:
		return padTo - minLen, nil
	}
}

// --- initiator --------------------------------------------------------------

// Initiator drives the client half of the handshake. It is single-use: one
// Initiator produces one initiation and consumes one response.
type Initiator struct {
	cfg       Config
	static    *StaticKey
	initFlags uint8
	peer      *PublicKey
	ch        chain
	eph       *ephemeral
	sentMsg   []byte
	sent      bool
	finished  bool
	wiped     bool
}

// SetInitFlags declares the initiator's handshake capability flags. Only the
// defined bits are accepted; anything else is refused at configuration time so
// a future flag typo cannot silently ship. Call before the first
// WriteInitiation.
func (i *Initiator) SetInitFlags(flags uint8) error {
	if flags&^HandshakeFlagDualAuth != 0 {
		return errWrap(ErrConfig, "unknown init flags 0x%02x", flags)
	}
	i.initFlags = flags
	return nil
}

// NewInitiator prepares a client handshake against a known gateway static key.
//
// The gateway public key is expected to have arrived inside the
// Ed25519-signed descriptor the control plane ships. That authenticates
// gateway identity only classically; the dual-signature session attestation
// (docs/DUAL_SIGNATURE_SPEC.md) adds the ML-DSA-65 leg at the session layer.
// See the package doc.
func NewInitiator(cfg Config, static *StaticKey, gatewayStatic *PublicKey) (*Initiator, error) {
	if err := cfg.validate(false); err != nil {
		return nil, err
	}
	if static == nil || gatewayStatic == nil {
		return nil, errWrap(ErrConfig, "initiator needs both a static key and a gateway public key")
	}
	return &Initiator{cfg: cfg, static: static, peer: gatewayStatic}, nil
}

// WriteInitiation builds the first message.
//
// payload may be nil; it exists for a small client hint and is bounded by
// MaxHandshakePayload. padTo is a target on-wire length, 0 for none, or PadAuto
// — which is what callers should pass.
//
// Calling it twice is a sequence error rather than a silent re-seal. A
// retransmission must be byte-identical, because a differing retransmission is
// a second handshake that burns a second slot of gateway state; use Retransmit.
func (i *Initiator) WriteInitiation(payload []byte, padTo int) ([]byte, error) {
	if i.wiped {
		return nil, ErrWiped
	}
	if i.sent {
		return nil, errWrap(ErrStateSequence, "initiation already written; use Retransmit or start a new Initiator")
	}
	cs := i.cfg.codec()
	tagLen := i.cfg.Gateway.tagSize()

	minLen := tagLen + cs.WireSize() +
		(KeySize + AEADTagSize) +
		(handshakePayloadHeaderSize + len(payload) + AEADTagSize)
	padLen, err := handshakePadding(i.cfg.rnd(), minLen, padTo)
	if err != nil {
		return nil, err
	}
	if minLen+padLen > MaxHandshakeMessage {
		return nil, errWrap(ErrLongMessage, "initiation would be %d bytes, ceiling %d", minLen+padLen, MaxHandshakeMessage)
	}

	eph, ephWire, err := newEphemeralForCodec(cs, i.cfg.rnd())
	if err != nil {
		return nil, err
	}

	ch := newChain(i.peer.Bytes())
	ch.mixHash(ephWire)

	es, err := dh(eph.priv, i.peer.pub)
	if err != nil {
		return nil, err
	}
	ch.mixSecret(es, labelDHEphStatic)
	clear(es)

	k1 := ch.stageKey(labelStageStatic)
	cstat, err := sealStage(k1, ch.h[:], i.static.Public())
	clear(k1[:])
	if err != nil {
		return nil, err
	}
	ch.mixHash(cstat)

	ss, err := dh(i.static.priv, i.peer.pub)
	if err != nil {
		return nil, err
	}
	ch.mixSecret(ss, labelDHStaticStatic)
	clear(ss)
	if len(i.cfg.PSK) > 0 {
		ch.mixSecret(i.cfg.PSK, labelPSK)
	}

	k2 := ch.stageKey(labelStagePayload)
	plain, err := encodeHandshakePayload(i.initFlags, payload, padLen)
	if err != nil {
		return nil, err
	}
	cpay, err := sealStage(k2, ch.h[:], plain)
	clear(k2[:])
	if err != nil {
		return nil, err
	}
	ch.mixHash(cpay)

	body := make([]byte, 0, len(ephWire)+len(cstat)+len(cpay))
	body = append(body, ephWire...)
	body = append(body, cstat...)
	body = append(body, cpay...)

	window, _, err := i.cfg.Gateway.Fresh.resolve()
	if err != nil {
		return nil, err
	}
	msg := sealAdmission(body,
		i.cfg.Gateway.AdmissionKeys[0], i.cfg.Gateway.GatewayID,
		tagLen, bucketIndex(i.cfg.clock(), window))

	i.ch = ch
	i.eph = eph
	i.sentMsg = msg
	i.sent = true
	return msg, nil
}

// Retransmit returns the exact bytes previously produced by WriteInitiation.
//
// The session manager, not this package, decides when to stop retransmitting.
// The rule it must follow is in the design document and is a direct answer to
// the measured 24-retries-100%-loss failure: exponential backoff with FULL
// JITTER, a hard attempt cap, and a switch of carrier CLASS rather than another
// retry. A retry schedule that never abandons a dead transport is not
// resilience; it is a beacon with a recognisable cadence.
func (i *Initiator) Retransmit() ([]byte, error) {
	if i.wiped {
		return nil, ErrWiped
	}
	if !i.sent {
		return nil, errWrap(ErrStateSequence, "nothing has been written yet")
	}
	return i.sentMsg, nil
}

// ReadResponse consumes the gateway's reply and yields the transport session.
func (i *Initiator) ReadResponse(msg []byte) (*Session, []byte, error) {
	if i.wiped {
		return nil, nil, ErrWiped
	}
	if !i.sent {
		return nil, nil, errWrap(ErrStateSequence, "no initiation has been written")
	}
	if i.finished {
		return nil, nil, errWrap(ErrStateSequence, "handshake already completed")
	}
	cs := i.cfg.codec()
	tagLen := i.cfg.Gateway.tagSize()

	minLen := tagLen + cs.WireSize() + handshakePayloadHeaderSize + AEADTagSize
	if len(msg) < minLen {
		return nil, nil, ErrShortMessage
	}
	if len(msg) > MaxHandshakeMessage {
		return nil, nil, ErrLongMessage
	}

	// The response tag and whitening are keyed by material derived from the
	// chain AFTER the initiation, which both sides already share. That removes
	// the circularity a tag-derived keystream would otherwise have, and it
	// means an observer holding the gateway admission key still cannot pair a
	// response with its initiation.
	ch := i.ch
	tagKey := ch.expand(labelRespTag, KeySize)
	whitenKey := ch.expand(labelRespWhite, KeySize)

	tag := msg[:tagLen]
	body := make([]byte, len(msg)-tagLen)
	copy(body, msg[tagLen:])
	responseWhitenInPlace(whitenKey, tag, body)

	computed := make([]byte, tagLen)
	responseTag(tagKey, tagLen, body, computed)
	if !hmac.Equal(computed, tag) {
		return nil, nil, ErrUnauthenticated
	}

	ephWire := body[:cs.WireSize()]
	cpay := body[cs.WireSize():]

	ephRRaw, err := cs.DecodePublic(ephWire)
	if err != nil {
		return nil, nil, err
	}
	ephR, err := NewPublicKey(ephRRaw)
	if err != nil {
		return nil, nil, ErrUnauthenticated
	}

	ch.mixHash(ephWire)
	ee, err := dh(i.eph.priv, ephR.pub)
	if err != nil {
		return nil, nil, err
	}
	ch.mixSecret(ee, labelDHEphEph)
	clear(ee)
	se, err := dh(i.static.priv, ephR.pub)
	if err != nil {
		return nil, nil, err
	}
	ch.mixSecret(se, labelDHStaticEph)
	clear(se)

	k3 := ch.stageKey(labelStageResponse)
	plain, err := openStage(k3, ch.h[:], cpay)
	clear(k3[:])
	if err != nil {
		return nil, nil, err
	}
	ch.mixHash(cpay)

	payload, flags, err := decodeHandshakePayload(plain)
	if err != nil {
		return nil, nil, err
	}
	// The responder never sets capability flags in its reply (a shipped client
	// rejects a nonzero flags byte on receipt). A responder that sends one is a
	// protocol error, fail closed.
	if flags != 0 {
		return nil, nil, ErrDecrypt
	}

	sess, err := newSession(RoleInitiator, ch, i.cfg.window())
	if err != nil {
		return nil, nil, err
	}
	sess.initFlags = i.initFlags
	// The handshake ephemeral is the forward-secrecy secret. Once the
	// session exists it has already been mixed into the chain; keeping it
	// here would let a later memory dump reconstruct epoch 0 from the
	// captured handshake plus this private key.
	i.eph = nil
	i.ch = chain{}
	i.finished = true
	return sess, payload, nil
}

// Wipe zeroises handshake state this Initiator still holds. It is safe
// after ReadResponse (which already drops the ephemeral) and on any abort.
//
// After Wipe, WriteInitiation, Retransmit and ReadResponse return ErrWiped.
// That is load-bearing for Driver.freshInitiation: a displaced Initiator
// must not keep serving the old initiation (Retransmit used to return
// (nil, nil) once sentMsg was cleared), and a caller that holds a pointer
// to the displaced object must be able to observe that Wipe ran.
func (i *Initiator) Wipe() {
	if i == nil {
		return
	}
	i.wiped = true
	i.ch = chain{}
	i.eph = nil
	clear(i.sentMsg)
	i.sentMsg = nil
}

// --- responder --------------------------------------------------------------

// AcceptFunc decides whether a client static public key is authorised.
// ReadInitiation calls it only after the initiation has proved possession of
// that key's private half, so it may keep per-key state.
//
// It is mandatory. A gateway with no authorisation callback accepts anyone who
// holds the admission key, and the admission key is a fleet-visible obfuscation
// secret, not an identity. Making this nilable would make that mistake easy.
type AcceptFunc func(clientStatic []byte) error

// Responder is the gateway half. One Responder serves many concurrent
// handshakes; it holds the static key, the authorisation callback, and the
// handshake replay cache, all of which are per gateway rather than per session.
//
// It is safe for concurrent use, INCLUDING concurrently with SetAdmissionKeys.
type Responder struct {
	// cfg holds the gateway profile with AdmissionKeys deliberately CLEARED.
	// The live key set is `keys` and there is no second copy of it, so no code
	// path can accidentally read a stale set after a rotation.
	cfg    Config
	static *StaticKey
	accept AcceptFunc
	replay *replayCache

	// keys is the live admission key set, behind an atomic pointer because it
	// is the one part of the profile that changes while the Responder is live.
	//
	// An atomic pointer rather than a mutex is a cost decision, and the cost in
	// question is a flood: the reject path is the path an unauthenticated packet
	// takes, and putting a lock on it would let a flood contend with itself. A
	// pointer load is unsynchronised and allocation-free, so rotation is free on
	// the hot path and costs one allocation on the rotation itself.
	keys atomic.Pointer[[][]byte]

	// spread is the resolved bucket spread. It is cached because it is NOT
	// rotatable (see SetAdmissionKeys) and because the reject-path budget is
	// computed from it.
	spread int
}

// NewResponder prepares a gateway.
func NewResponder(cfg Config, static *StaticKey, accept AcceptFunc) (*Responder, error) {
	if err := cfg.validate(true); err != nil {
		return nil, err
	}
	if static == nil {
		return nil, errWrap(ErrConfig, "responder needs a static key")
	}
	if accept == nil {
		return nil, errWrap(ErrConfig, "responder needs an authorisation callback; see AcceptFunc")
	}
	window, spread, err := cfg.Gateway.Fresh.resolve()
	if err != nil {
		return nil, err
	}
	// The reject-path HMAC bound is a product of key count and spread. SetAdmissionKeys
	// already enforced it; NewResponder did not, so a gateway constructed with
	// five keys at the default spread, or one key at a 32-second skew on a
	// one-second bucket, started as a flood amplifier and could not even rotate
	// back onto a legal set (SetAdmissionKeys of the same keys would then refuse).
	if err := errIfAdmissionRejectOverBudget(len(cfg.Gateway.AdmissionKeys), spread); err != nil {
		return nil, err
	}
	// The replay cache only needs to cover the span in which a captured
	// initiation could still verify, which is exactly the skew the bucket
	// spread admits, in both directions.
	lifetime := time.Duration(2*spread+1) * window

	keys := copyAdmissionKeys(cfg.Gateway.AdmissionKeys)
	// Clear the copy the Responder keeps, so that `keys` is the only key set
	// this object has and rotation cannot leave a stale one behind.
	cfg.Gateway.AdmissionKeys = nil

	// The cache refuses a non-positive lifetime rather than inventing one, so a
	// future change to the freshness arithmetic that drove this to zero would
	// stop the gateway starting instead of silently narrowing the replay window
	// to a constant unrelated to the acceptance span. See newReplayCache.
	var replay *replayCache
	if cfg.ReplayJournal == "" {
		replay, err = newReplayCache(lifetime)
	} else {
		// F-02: seed the window from the persisted journal. The prune instant
		// is this responder's own clock, so an injected test clock is honoured
		// and a journal written at one fixed clock instant is not expired by
		// another. Load refusal (torn file) fails the gateway start.
		replay, err = newReplayCacheWithJournal(lifetime, cfg.ReplayJournal, cfg.clock())
	}
	if err != nil {
		return nil, err
	}

	r := &Responder{
		cfg:    cfg,
		static: static,
		accept: accept,
		replay: replay,
		spread: spread,
	}
	r.keys.Store(&keys)
	return r, nil
}

// copyAdmissionKeys takes a deep copy of a key set.
//
// The Responder is documented safe for concurrent use, and a caller who kept a
// reference to the slice it passed in could otherwise mutate a key underneath a
// running verification — a data race with a security consequence rather than
// merely a crash. Copying costs one allocation per rotation and nothing per
// packet.
func copyAdmissionKeys(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, k := range in {
		out[i] = append([]byte(nil), k...)
	}
	return out
}

// gatewayParams assembles the profile for one verification: the fixed part plus
// the current key set.
//
// It is on the hot path and must stay allocation-free — the returned
// GatewayParams is a stack copy of two slice headers, an int and two durations,
// and the key set is aliased rather than copied. TestRotationSeamIsFreeOnTheHotPath
// asserts that, because a per-packet allocation here would be a flood
// amplifier and no correctness test would notice it.
func (r *Responder) gatewayParams() GatewayParams {
	g := r.cfg.Gateway
	g.AdmissionKeys = *r.keys.Load()
	return g
}

// SetAdmissionKeys swaps the gateway's admission key set IN PLACE, leaving the
// handshake replay cache and its clock untouched.
//
// # Why this exists rather than "construct a new Responder"
//
// Constructing a new Responder is the obvious way to rotate and it is a
// security defect. It discards the replay cache, and the replay cache is the
// only thing standing between a censor and a permanent gateway detector: a
// prober who captured one real initiation can replay it and watch for a
// response, and the cache is what makes the second copy silent. Rebuilding the
// Responder re-opens a (2*spread+1)*window — 130 s at the defaults — window in
// which that captured packet works again.
//
// The second consequence is worse than the first, and it is the reason this is
// a seam rather than a note. That window opens AT THE ROTATION INSTANT, so it is
// not merely a hole, it is a CLOCK. An observer who replays one captured
// initiation on a schedule learns not only that the gateway is there but when it
// rotated — and rotation is otherwise completely invisible on the wire, because
// the admission key is used only in the initiation and never again, so an
// established session never touches it and a rotation emits no packet at all.
// The rotation mechanism would have been the only thing giving rotation a
// signature.
//
// # What it deliberately cannot do
//
// It cannot change Freshness, and that is enforced structurally rather than by a
// check: there is no parameter for it. Changing the bucket window or the skew
// legitimately changes the replay-cache lifetime, the acceptance span, the
// reject-path cost and the hub's key-retirement floor all at once, so it is a
// new Responder and a maintenance event. It is not a rotation.
//
// It also cannot change the gateway identity or the tag length, for the same
// reason: those are wire parameters both ends are configured with, not secrets
// that rotate.
//
// # Cost
//
// The gateway holds two keys during an overlap, so the unauthenticated reject
// path costs len(keys) * (2*spread+1) HMACs — 26 at the defaults with two keys.
// That budget is bounded by MaxAdmissionHMACs, because an unbounded key set
// would turn a flood into an amplified one. The keys are tried OUTERMOST with no
// early exit, so a rejection costs the same whichever key is live; an
// optimisation that stopped early on the new key would be a timing oracle
// distinguishing "old key" from "new key" traffic.
//
// It is safe to call concurrently with ReadInitiation. Verifications already in
// flight complete against whichever set they loaded; there is no instant at
// which no key is live.
func (r *Responder) SetAdmissionKeys(keys [][]byte) error {
	if len(keys) == 0 {
		return errWrap(ErrConfig, "at least one admission key is required")
	}
	for i, k := range keys {
		if len(k) < minAdmissionKeySize {
			return errWrap(ErrConfig, "admission key %d is %d bytes, need at least %d",
				i, len(k), minAdmissionKeySize)
		}
	}
	if err := errIfAdmissionRejectOverBudget(len(keys), r.spread); err != nil {
		return err
	}
	next := copyAdmissionKeys(keys)
	r.keys.Store(&next)
	return nil
}

// AdmissionKeyCount reports how many admission keys are currently live. It is
// for an operator watching a rotation reach its overlap and then leave it; it
// reveals nothing a peer could not infer from the reject-path cost anyway.
func (r *Responder) AdmissionKeyCount() int { return len(*r.keys.Load()) }

// ReplayJournalError reports the first sticky persisted-journal write failure
// since this Responder started, or nil (also nil when no journal is configured,
// and nil while the live set is only at its security cap).
//
// A non-nil error means this Responder refuses every new handshake because it
// cannot prove that another restart will remember the admission. Live-set
// capacity refusals are returned from ReadInitiation for that handshake only
// and clear when expiry frees a slot. The error is operator-visible, never
// wire-visible; callers must keep the peer response silent just as they do for
// every other ReadInitiation failure.
func (r *Responder) ReplayJournalError() error { return r.replay.journalError() }

// VerifyReplayJournalPath confirms that the configured journal and WAL names
// still resolve to the descriptors owned by this Responder's active writer.
// A mismatch becomes the writer's sticky error and refuses later handshakes.
func (r *Responder) VerifyReplayJournalPath() error { return r.replay.verifyJournalPath() }

// Public returns the gateway's static public key, for publication in a signed
// descriptor.
func (r *Responder) Public() []byte { return r.static.Public() }

// IsReplayedInitiation reports whether msg is a message this Responder has
// ALREADY accepted and is still inside the freshness window for — that is,
// whether ReadInitiation would reject it with ErrReplay. It consumes nothing.
//
// It answers exactly one of ReadInitiation's three rejections and deliberately
// not the others. A message that fails the admission tag, or that would fail
// decryption or authorisation, is NOT a replay and this returns false for it.
// The question is "have I answered these bytes before", not "is this any good".
//
// # Why a peek exists at all
//
// It is for a host that demultiplexes on the TRANSPORT ADDRESS before it
// reaches the handshake — cmd/winn3-gateway is the live example. Such a host
// allocates a session, a pipe, a device and two goroutines for the first
// datagram from a new address, and only then discovers, inside the driver, that
// the datagram was a replay of one it already answered from somewhere else.
//
// The security outcome is already correct once the Responder is shared: the
// replay cache makes ReadInitiation fail and the peer is answered with silence.
// What this closes is the RESOURCE half. Without it, a censor holding ONE
// captured initiation can make such a host allocate a session per replay, from
// any address, until the session ceiling fills and the gateway refuses its real
// clients — in silence, which under this threat model reads as a censor rather
// than as a fault.
//
// It is a screen, NOT the check. Three properties make it safe to rely on:
//
//   - It is strictly narrower than ReadInitiation's rejections, so it can never
//     refuse a message ReadInitiation would have answered.
//   - It does not consume the replay slot. replayCache.seen does not insert,
//     and remember still runs only inside ReadInitiation once the message has
//     proven itself, so a peek followed by a real ReadInitiation of the same
//     bytes behaves exactly as the ReadInitiation alone would.
//   - The residual race is benign: two copies of one body arriving concurrently
//     can both peek false before either is remembered. Both then reach
//     ReadInitiation, where exactly one wins and the other gets ErrReplay. At
//     most one reply is emitted either way. The silence property is enforced by
//     ReadInitiation and NEVER by this method.
//
// A caller must answer true with SILENCE, exactly as ReadInitiation's failures
// are answered. Anything else — including an error datagram — re-opens the
// probe oracle this whole path exists to close.
func (r *Responder) IsReplayedInitiation(msg []byte) bool {
	now := r.cfg.clock()
	body, _, _, err := verifyAdmission(msg, r.gatewayParams(), now)
	if err != nil {
		// Not admissible at all, so not something this Responder ever answered.
		// It is somebody else's problem (noise, a probe, a wrong key) and the
		// caller's existing path for those is unchanged.
		return false
	}
	// Same key construction as ReadInitiation, and deliberately the same
	// expression rather than a helper call: if these two ever diverge the peek
	// silently stops screening, so they are kept adjacent and identical.
	return r.replay.seen(sha256.Sum256(body), now)
}

// ScreenInitiation is IsReplayedInitiation with the admission verdict it
// already computes made visible. admissible reports whether msg passes this
// Responder's admission tag under a current key and freshness bucket; replayed
// reports whether it is ALSO a body this Responder has already accepted inside
// the freshness window. replayed is never true when admissible is false. It
// consumes nothing, and it costs exactly what IsReplayedInitiation costs: one
// verifyAdmission and, on success, one replay-cache lookup.
//
// It exists for the same address-demultiplexing host. Such a host allocates a
// session, a pipe, a device and two goroutines for the first datagram from a
// new address. A datagram that fails the admission tag can never become a
// session, so a host that screens on admissible spends nothing on it, where
// before it spent one slot of its session ceiling for a whole handshake budget
// on one byte of noise.
//
// Like IsReplayedInitiation it is a screen and never the check. admissible
// proves possession of an admission key, not of an accepted client static key;
// ReadInitiation stays the only authority, and a caller must answer every
// refusal here with SILENCE.
func (r *Responder) ScreenInitiation(msg []byte) (admissible, replayed bool) {
	now := r.cfg.clock()
	body, _, _, err := verifyAdmission(msg, r.gatewayParams(), now)
	if err != nil {
		return false, false
	}
	// Same key construction as ReadInitiation and IsReplayedInitiation, kept
	// as the same expression for the reason given there.
	return true, r.replay.seen(sha256.Sum256(body), now)
}

// ResponderHandshake is one in-flight handshake.
type ResponderHandshake struct {
	cfg       Config
	initFlags uint8
	static    *StaticKey
	ch        chain
	tagKey    []byte
	whitenKey []byte
	peerEph   *PublicKey
	peerStat  *PublicKey
	payload   []byte
	replayKey [32]byte
	replay    *replayCache
	finished  bool
}

// ReadInitiation authenticates and parses a client's first message.
//
// EVERY failure path here returns without writing a single byte back, and the
// caller must keep it that way. There is no cookie reply, no version-mismatch
// notice and no error datagram, because any of those is an answer to an
// unauthenticated packet and therefore a probe oracle. The only way to make a
// Winn3 gateway emit a byte is a fresh initiation that authenticates under that
// gateway's admission key.
//
// The four rejections, in order and all silent:
//
//  1. admission tag fails      -> dropped before any asymmetric operation
//  2. replay of a seen body    -> dropped; this is what stops a captured
//     initiation becoming a permanent gateway detector
//  3. decryption or authorisation fails -> dropped
//  4. durable replay recording fails -> dropped. A persist, sync, or
//     identity failure is sticky: this Responder refuses every later new
//     initiation until it is replaced. A live-set capacity refusal is not
//     sticky: it fails this initiation closed and reopens when expiry
//     frees a slot.
//
// The honest exception is timing: (1) costs nanoseconds and (2)/(3) cost
// microseconds, so the branches are distinguishable to someone who can already
// pass (1), which requires the key.
func (r *Responder) ReadInitiation(msg []byte) (*ResponderHandshake, error) {
	now := r.cfg.clock()
	body, _, _, err := verifyAdmission(msg, r.gatewayParams(), now)
	if err != nil {
		return nil, err
	}

	// The replay key is SHA-256 over the recovered body. The body contains the
	// per-handshake ephemeral public key, which is fresh by construction, so a
	// genuine retransmission hashes the same and a new handshake does not.
	// Hashing the whole body rather than reaching in at a fixed offset keeps
	// this free of any assumption about internal layout. The reasoning, and the
	// construction, come from internal/initauth.ReplayKey.
	rk := sha256.Sum256(body)
	if r.replay.seen(rk, now) {
		return nil, ErrReplay
	}

	cs := r.cfg.codec()
	need := cs.WireSize() + KeySize + AEADTagSize + handshakePayloadHeaderSize + AEADTagSize
	if len(body) < need {
		return nil, ErrShortMessage
	}

	ephWire := body[:cs.WireSize()]
	cstat := body[cs.WireSize() : cs.WireSize()+KeySize+AEADTagSize]
	cpay := body[cs.WireSize()+KeySize+AEADTagSize:]

	ephRaw, err := cs.DecodePublic(ephWire)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	peerEph, err := NewPublicKey(ephRaw)
	if err != nil {
		return nil, ErrUnauthenticated
	}

	ch := newChain(r.static.Public())
	ch.mixHash(ephWire)

	es, err := dh(r.static.priv, peerEph.pub)
	if err != nil {
		return nil, err
	}
	ch.mixSecret(es, labelDHEphStatic)
	clear(es)

	k1 := ch.stageKey(labelStageStatic)
	peerStaticRaw, err := openStage(k1, ch.h[:], cstat)
	clear(k1[:])
	if err != nil {
		return nil, err
	}
	ch.mixHash(cstat)

	peerStat, err := NewPublicKey(peerStaticRaw)
	if err != nil {
		return nil, ErrUnauthenticated
	}

	ss, err := dh(r.static.priv, peerStat.pub)
	if err != nil {
		return nil, err
	}
	ch.mixSecret(ss, labelDHStaticStatic)
	clear(ss)
	if len(r.cfg.PSK) > 0 {
		ch.mixSecret(r.cfg.PSK, labelPSK)
	}

	k2 := ch.stageKey(labelStagePayload)
	plain, err := openStage(k2, ch.h[:], cpay)
	clear(k2[:])
	if err != nil {
		return nil, err
	}
	ch.mixHash(cpay)

	payload, flags, err := decodeHandshakePayload(plain)
	if err != nil {
		return nil, err
	}

	// Authorise only after Stage 2: Stage 1 is keyed by the ephemeral and the
	// gateway static alone, so anyone holding the admission key can name any
	// client's public key in cstat, and only cpay proves the sender holds the
	// matching private key. A stateful AcceptFunc (the gateway's per-key
	// session cap counts here) must never be spent by a sender that cannot.
	if err := r.accept(peerStat.Bytes()); err != nil {
		return nil, errWrap(ErrPeerIdentity, "%v", err)
	}

	// Only now, with the message proven, is the replay slot consumed. Doing it
	// earlier would let a key holder fill the cache with packets that never
	// pass the crypto.
	if err := r.replay.remember(rk, now); err != nil {
		return nil, err
	}

	return &ResponderHandshake{
		cfg:       r.cfg,
		static:    r.static,
		ch:        ch,
		tagKey:    ch.expand(labelRespTag, KeySize),
		whitenKey: ch.expand(labelRespWhite, KeySize),
		initFlags: flags,
		peerEph:   peerEph,
		peerStat:  peerStat,
		payload:   payload,
		replayKey: rk,
		replay:    r.replay,
	}, nil
}

// InitFlags returns the capability flags the initiator set in its handshake
// payload. Legacy clients send zero; a client announcing dual-signature
// support sets HandshakeFlagDualAuth.
func (h *ResponderHandshake) InitFlags() uint8 { return h.initFlags }

// InitiatorStatic returns the authenticated client identity.
func (h *ResponderHandshake) InitiatorStatic() []byte { return h.peerStat.Bytes() }

// Payload returns the client's handshake payload, which may be empty.
func (h *ResponderHandshake) Payload() []byte { return h.payload }

// WriteResponse completes the handshake and yields the transport session.
func (h *ResponderHandshake) WriteResponse(payload []byte, padTo int) ([]byte, *Session, error) {
	if h.finished {
		return nil, nil, errWrap(ErrStateSequence, "response already written")
	}
	cs := h.cfg.codec()
	tagLen := h.cfg.Gateway.tagSize()

	minLen := tagLen + cs.WireSize() + handshakePayloadHeaderSize + len(payload) + AEADTagSize
	padLen, err := handshakePadding(h.cfg.rnd(), minLen, padTo)
	if err != nil {
		return nil, nil, err
	}
	if minLen+padLen > MaxHandshakeMessage {
		return nil, nil, errWrap(ErrLongMessage, "response would be %d bytes, ceiling %d", minLen+padLen, MaxHandshakeMessage)
	}

	eph, ephWire, err := newEphemeralForCodec(cs, h.cfg.rnd())
	if err != nil {
		return nil, nil, err
	}

	ch := h.ch
	ch.mixHash(ephWire)
	ee, err := dh(eph.priv, h.peerEph.pub)
	if err != nil {
		return nil, nil, err
	}
	ch.mixSecret(ee, labelDHEphEph)
	clear(ee)
	se, err := dh(eph.priv, h.peerStat.pub)
	if err != nil {
		return nil, nil, err
	}
	ch.mixSecret(se, labelDHStaticEph)
	clear(se)

	k3 := ch.stageKey(labelStageResponse)
	plain, err := encodeHandshakePayload(0, payload, padLen)
	if err != nil {
		return nil, nil, err
	}
	cpay, err := sealStage(k3, ch.h[:], plain)
	clear(k3[:])
	if err != nil {
		return nil, nil, err
	}
	ch.mixHash(cpay)

	body := make([]byte, 0, len(ephWire)+len(cpay))
	body = append(body, ephWire...)
	body = append(body, cpay...)

	out := make([]byte, tagLen+len(body))
	copy(out[tagLen:], body)
	responseTag(h.tagKey, tagLen, out[tagLen:], out[:tagLen])
	responseWhitenInPlace(h.whitenKey, out[:tagLen], out[tagLen:])

	sess, err := newSession(RoleResponder, ch, h.cfg.window())
	if err != nil {
		return nil, nil, err
	}
	sess.initFlags = h.initFlags
	h.finished = true
	return out, sess, nil
}

// Wipe zeroises handshake secrets this object still holds after
// ReadInitiation. Call it on every abort path and after WriteResponse;
// Gateway.Handle defers it. The resulting Session is a copy of the chain
// and is not touched.
func (h *ResponderHandshake) Wipe() {
	if h == nil {
		return
	}
	h.ch = chain{}
	clear(h.tagKey)
	clear(h.whitenKey)
	h.tagKey = nil
	h.whitenKey = nil
	h.peerEph = nil
	h.peerStat = nil
	clear(h.payload)
	h.payload = nil
	h.replayKey = [32]byte{}
}
