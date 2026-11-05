package core

import (
	"crypto/cipher"
	"crypto/mlkem"
	"encoding/binary"
	"io"
	"strconv"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Role distinguishes the two ends. It selects which derived direction is the
// send direction and which is the receive direction; nothing else in the
// transport depends on it.
type Role uint8

const (
	RoleInitiator Role = iota
	RoleResponder
)

func (r Role) String() string {
	switch r {
	case RoleInitiator:
		return "initiator"
	case RoleResponder:
		return "responder"
	default:
		return "role(" + strconv.FormatUint(uint64(r), 10) + ")"
	}
}

const (
	// transportHeaderSize is payloadLen(2 BE), INSIDE the AEAD. There is no
	// length field on the wire.
	transportHeaderSize = 2

	// MaxTransportPayload is what the inner length field can express. The real
	// limit is whatever the carrier will move; this is only the encoding bound.
	MaxTransportPayload = 65535
)

// Post-quantum ratchet sizes, from FIPS 203 ML-KEM-768.
const (
	PQEncapsulationKeySize = 1184
	PQCiphertextSize       = 1088
	PQSharedKeySize        = mlkem.SharedKeySize
)

// directionKeys is one direction of one epoch.
type directionKeys struct {
	key   [KeySize]byte
	salt  [nonceSaltSize]byte
	demux [KeySize]byte
}

const (
	dirI2R = "i2r"
	dirR2I = "r2i"
)

// epochInfo builds the HKDF info string. The epoch number and the direction are
// both in it, so no two epochs and no two directions can ever derive the same
// key even if the chaining key were somehow repeated.
func epochInfo(epoch uint32, dir, what string) string {
	return labelEpoch + " e" + strconv.FormatUint(uint64(epoch), 10) + " " + dir + " " + what
}

func deriveDirection(c *chain, epoch uint32, dir string) directionKeys {
	var dk directionKeys
	copy(dk.key[:], c.expand(epochInfo(epoch, dir, "key"), KeySize))
	copy(dk.salt[:], c.expand(epochInfo(epoch, dir, "salt"), nonceSaltSize))
	copy(dk.demux[:], c.expand(epochInfo(epoch, dir, "demux"), KeySize))
	return dk
}

// Session is the transport-crypto state machine for one logical connection.
//
// It holds no address, no socket and no timer. A session survives a change of
// carrier without re-handshaking and without leaving a correlator behind,
// because nothing stable about it appears on the wire: that is what makes a
// UDP-to-TLS fallback cost a dial rather than a new session, and it is the
// structural answer to a censor who blocks UDP wholesale.
//
// Seal and Open may be called concurrently from one sender goroutine and one
// receiver goroutine. Ratchets briefly exclude both.
type Session struct {
	role Role

	// initFlags is the capability flags byte from the initiator's handshake
	// payload. Immutable after construction (set before the Session is
	// published), so InitFlags reads it without the mutexes.
	initFlags uint8

	sendMu      sync.Mutex
	sendAEAD    cipher.AEAD
	sendSalt    [nonceSaltSize]byte
	sendDemux   [KeySize]byte
	sendCounter    uint64
	sentBytes      uint64
	epochSentBytes uint64
	sendPRF        *demuxPRF
	sendNonce      [AEADNonceSize]byte

	recvMu     sync.Mutex
	recvAEAD   cipher.AEAD
	recvSalt   [nonceSaltSize]byte
	recvDemux  [KeySize]byte
	recvWindow *tokenWindow
	recvdBytes uint64
	recvNonce  [AEADNonceSize]byte

	// recvReordered and recvLost carry the counts of every receive window an
	// epoch install has retired; RecvFlow adds the live window's.
	recvReordered uint64
	recvLost      uint64
	recvDepth     ReorderDepth

	// chainMu guards the ratchet state. Acquire order is always
	// sendMu -> recvMu -> chainMu.
	chainMu    sync.Mutex
	ch         chain
	epoch      uint32
	windowSize int
	pqDone     bool
	wiped      bool
}

func newSession(role Role, ch chain, windowSize int) (*Session, error) {
	s := &Session{role: role, ch: ch, windowSize: windowSize}
	if err := s.installEpoch(0); err != nil {
		return nil, err
	}
	return s, nil
}

// installEpoch derives and installs both directions for an epoch, resetting the
// counter and the receive window. Callers hold whatever locks are needed.
func (s *Session) installEpoch(epoch uint32) error {
	if s.wiped {
		return ErrWiped
	}
	i2r := deriveDirection(&s.ch, epoch, dirI2R)
	r2i := deriveDirection(&s.ch, epoch, dirR2I)

	send, recv := i2r, r2i
	if s.role == RoleResponder {
		send, recv = r2i, i2r
	}

	sa, err := chacha20poly1305.New(send.key[:])
	if err != nil {
		return err
	}
	ra, err := chacha20poly1305.New(recv.key[:])
	if err != nil {
		return err
	}

	if s.recvWindow != nil {
		s.recvReordered += s.recvWindow.reordered
		s.recvLost += s.recvWindow.lost
		s.recvDepth.Add(s.recvWindow.depth)
		s.recvWindow.wipe()
	}

	s.sendAEAD = sa
	s.sendSalt = send.salt
	s.sendDemux = send.demux
	s.sendCounter = 0
	s.epochSentBytes = 0
	s.sendPRF = newDemuxPRF(&send.demux)

	s.recvAEAD = ra
	s.recvSalt = recv.salt
	s.recvDemux = recv.demux
	if s.windowSize == CallerOwnsTokenWindow {
		// The lookup lives in an external index; the replay filter does not
		// move. DefaultTokenWindow sizes the filter so that this session is
		// never the binding constraint on an index that is smaller (see
		// Session.OpenAt).
		s.recvWindow = newCounterWindow(DefaultTokenWindow)
	} else {
		s.recvWindow = newTokenWindow(&recv.demux, s.windowSize)
	}

	s.epoch = epoch
	// The AEAD objects hold their own copies. Zero the local direction
	// material so a stack dump at this instant does not also contain the
	// plaintext traffic keys this function just installed.
	send.key = [KeySize]byte{}
	recv.key = [KeySize]byte{}
	send.demux = [KeySize]byte{}
	recv.demux = [KeySize]byte{}
	i2r.key, r2i.key = [KeySize]byte{}, [KeySize]byte{}
	i2r.demux, r2i.demux = [KeySize]byte{}, [KeySize]byte{}
	return nil
}

// Wipe zeroises every key this Session holds in its own fields and refuses
// further Seal/Open/ratchet. It is idempotent.
//
// What it can reach: the chaining key, the transcript hash, both demux keys,
// both nonce salts, and the receive window's copy of the demux key. What it
// cannot reach: the ChaCha20-Poly1305 key copies inside the released AEAD
// objects. Those become unreachable from this package and are left to GC.
// That limitation is stated rather than papered over; see the test that
// requires RecvDemuxKey to return zeros and Seal/Open to return ErrWiped,
// which is the material this package actually owns.
//
// Callers must not turn the error into anything a peer can observe.
func (s *Session) Wipe() {
	if s == nil {
		return
	}
	s.sendMu.Lock()
	s.recvMu.Lock()
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	defer s.recvMu.Unlock()
	defer s.sendMu.Unlock()
	s.wipeLocked()
}

func (s *Session) wipeLocked() {
	s.wiped = true
	s.sendAEAD = nil
	s.recvAEAD = nil
	s.sendPRF = nil
	clear(s.sendNonce[:])
	clear(s.recvNonce[:])
	s.sendSalt = [nonceSaltSize]byte{}
	s.recvSalt = [nonceSaltSize]byte{}
	s.sendDemux = [KeySize]byte{}
	s.recvDemux = [KeySize]byte{}
	s.ch.ck = [hashSize]byte{}
	s.ch.h = [hashSize]byte{}
	if s.recvWindow != nil {
		s.recvWindow.wipe()
		s.recvWindow = nil
	}
}

// Role reports which end this is.
func (s *Session) Role() Role { return s.role }

// Epoch reports the current ratchet epoch. Epoch 0 is classical-only; epoch 1
// is normally the post-quantum ratchet.
func (s *Session) Epoch() uint32 {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.epoch
}

// PQRatcheted reports whether the post-quantum shared secret has been mixed in.
//
// A driver in the default strict mode MUST NOT put a DATA frame on the wire
// until this is true. The cost is one extra round trip before user data; the
// benefit is post-quantum forward secrecy for everything that follows. The
// epoch-0 traffic that carries the ratchet itself contains only public KEM
// values, so it needs no post-quantum protection of its own.
func (s *Session) PQRatcheted() bool {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	return s.pqDone
}

// TransportOverhead is the fixed number of bytes a transport message adds to
// its payload: the demux token, the inner length field, and the AEAD tag.
func TransportOverhead() int { return DemuxTokenSize + transportHeaderSize + AEADTagSize }

// SendCounter reports how many messages this direction has sealed.
func (s *Session) SendCounter() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sendCounter
}

// SentBytes reports how many on-wire bytes this direction has sealed, padding
// and overhead included. RecvdBytes is the mirror for messages that opened
// successfully; a message that failed to open is not counted, because it was
// not necessarily ours.
//
// These are the driver's inputs for the byte half of the rekey policy and for
// its own accounting. They are exported rather than internal because a counter
// nothing can read is a counter nobody maintains.
func (s *Session) SentBytes() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sentBytes
}

// EpochSentBytes reports how many on-wire bytes this direction has sealed in
// the current ratchet epoch. It resets to 0 upon rekeying.
func (s *Session) EpochSentBytes() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.epochSentBytes
}

// InitFlags reports the initiator's capability flags. Legacy clients report 0;
// a dual-signature-capable client reports core.HandshakeFlagDualAuth.
func (s *Session) InitFlags() uint8 { return s.initFlags }

// RecvFlow reports, across every epoch of this Session, how many
// authenticated messages this direction opened after a message with a higher
// counter (reordered), and how many counters below the highest one opened
// never arrived (lost). The tunnel has no reorder buffer, so each reordered
// message reached the inner flow as it arrived.
func (s *Session) RecvFlow() (reordered, lost uint64) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	reordered, lost = s.recvReordered, s.recvLost
	if s.recvWindow != nil {
		reordered += s.recvWindow.reordered
		lost += s.recvWindow.lost
	}
	return reordered, lost
}

// RecvReorderDepth splits RecvFlow's reordered count by displacement, across
// every epoch of this Session. See ReorderDepth.
func (s *Session) RecvReorderDepth() ReorderDepth {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	d := s.recvDepth
	if s.recvWindow != nil {
		d.Add(s.recvWindow.depth)
	}
	return d
}

// RecvdBytes reports how many on-wire bytes this direction has opened.
func (s *Session) RecvdBytes() uint64 {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	return s.recvdBytes
}

// TranscriptHash returns the current handshake transcript hash h, which commits
// the protocol label, the responder static, the ephemeral, and the sealed
// initiation. It is the session-binding material for the dual-signature
// attestation (docs/DUAL_SIGNATURE_SPEC.md) and is stable after the handshake:
// transport frames, including the PQ ratchet, fold secrets into the chain key
// but never into h.
func (s *Session) TranscriptHash() [hashSize]byte {
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	var out [hashSize]byte
	copy(out[:], s.ch.h[:])
	return out
}

// NeedsRekey reports whether either soft volume trigger has been reached: the
// message count (RekeyAfterMessages) or the byte budget (RekeyAfterBytes).
// Both bound the same thing (how much traffic one epoch's keys protect) and
// they bind at opposite ends of the packet-size range, so the first to fire
// wins.
//
// The time-based trigger is deliberately NOT here. A clock lives in the driver,
// and the rule it must follow is in the design document: a rekey interval must
// be jittered, never fixed. A fixed-interval rekey is exactly the 25.000-second
// zero-jitter metronome this protocol exists to stop emitting, only slower.
func (s *Session) NeedsRekey() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sendCounter >= RekeyAfterMessages || s.epochSentBytes >= RekeyAfterBytes
}

// Seal encrypts a payload into one transport message.
//
// padTo is a target on-wire length; 0 means no padding. The core does not
// implement PaddingPolicy: choosing a target from a bucket set or a mimic
// distribution is the driver's job, because only the driver knows the session's
// bucket draw and the carrier's cover protocol.
func (s *Session) Seal(payload []byte, padTo int) ([]byte, error) {
	return s.sealInto(nil, payload, padTo, true)
}

// SealInto writes one message into dst capacity without allocating packet storage.
// dst and payload must not overlap. On success the result aliases dst.
// An insufficient destination does not consume a nonce. Caller owns dst until Send returns.
func (s *Session) SealInto(dst, payload []byte, padTo int) ([]byte, error) {
	return s.sealInto(dst, payload, padTo, false)
}

func (s *Session) sealInto(dst, payload []byte, padTo int, allocate bool) ([]byte, error) {
	if len(payload) > MaxTransportPayload {
		return nil, errWrap(ErrPayloadTooLarge, "transport payload is %d bytes, limit %d", len(payload), MaxTransportPayload)
	}
	minLen := TransportOverhead() + len(payload)
	padLen := 0
	if padTo != 0 {
		if padTo < minLen {
			return nil, errWrap(ErrTargetLenTooSmall, "target %d is below the %d-byte minimum for this message", padTo, minLen)
		}
		padLen = padTo - minLen
	}

	if cap(dst) < minLen+padLen {
		if !allocate {
			return nil, io.ErrShortBuffer
		}
		dst = make([]byte, minLen+padLen)
	}

	s.sendMu.Lock()
	if s.wiped || s.sendAEAD == nil {
		s.sendMu.Unlock()
		return nil, ErrWiped
	}
	if s.sendCounter >= RejectAfterMessages {
		s.sendMu.Unlock()
		return nil, ErrCounterExhausted
	}

	counter := s.sendCounter
	s.sendCounter++
	token := s.sendPRF.token(counter)
	totalBytes := uint64(minLen + padLen)
	s.sentBytes += totalBytes
	s.epochSentBytes += totalBytes

	out := dst[:minLen+padLen]
	copy(out[:DemuxTokenSize], token[:])

	copy(s.sendNonce[:nonceSaltSize], s.sendSalt[:])
	binary.BigEndian.PutUint64(s.sendNonce[nonceSaltSize:], counter)

	plain := out[DemuxTokenSize : len(out)-AEADTagSize]
	binary.BigEndian.PutUint16(plain[:transportHeaderSize], uint16(len(payload)))
	copy(plain[transportHeaderSize:], payload)
	clear(plain[transportHeaderSize+len(payload):])

	sealed := s.sendAEAD.Seal(plain[:0], s.sendNonce[:], plain, out[:DemuxTokenSize])
	s.sendMu.Unlock()

	out = out[:DemuxTokenSize+len(sealed)]
	return out, nil
}

// Open decrypts one transport message.
//
// An unknown token is indistinguishable from a replay and from noise, and all
// three return the same error. That is intentional: the caller must not be able
// to build an oracle out of the distinction, and in any case nothing is ever
// written back.
//
// A message whose token is known but whose AEAD fails does NOT consume the
// token. A corrupted copy of a packet must not invalidate the genuine one that
// arrives after it.
func (s *Session) Open(msg []byte) ([]byte, error) {
	return s.openInto(nil, msg, true)
}

// OpenInto returns authenticated payload as a view of dst. dst capacity must
// cover the complete decrypted body, including inner length and padding.
// dst may start exactly at msg[DemuxTokenSize] for in-place opening; otherwise
// it must not overlap msg. Neither the token nor msg header may be overwritten.
// On failure dst contents are unspecified, and no plaintext may be delivered.
func (s *Session) OpenInto(dst, msg []byte) ([]byte, error) {
	return s.openInto(dst, msg, false)
}

func (s *Session) openInto(dst, msg []byte, allocate bool) ([]byte, error) {
	if len(msg) < TransportOverhead() {
		return nil, ErrShortMessage
	}

	if !allocate && cap(dst) < len(msg)-DemuxTokenSize-AEADTagSize {
		return nil, io.ErrShortBuffer
	}

	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if s.wiped || s.recvAEAD == nil || s.recvWindow == nil {
		return nil, ErrWiped
	}

	counter, ok := s.recvWindow.lookup(msg[:DemuxTokenSize])
	if !ok {
		// Only on the reject path, so it costs the hot path nothing: a session
		// whose index was handed to a caller cannot place ANY datagram, and
		// reporting that as "unauthenticated" would present a config mistake as
		// a wire event.
		if !s.recvWindow.indexed() {
			return nil, ErrCallerOwnsWindow
		}
		return nil, ErrUnauthenticated
	}

	return s.openIntoCounterLocked(dst, msg, counter, true)
}

// ResolveCounter maps a message's demux token to its receive counter without
// consuming anything and without decrypting: the same lookup Open performs,
// with no token use, no window movement and no flow counters moved.
//
// It exists for a receive resequencer that runs ABOVE this layer (see
// winn3/driver/reseq.go): restoring counter order needs the counter before
// delivery, and delivering must stay the only thing that consumes a token.
// Unresolved messages (noise, a scan, a replay, a datagram of an epoch this
// end has not installed, a pre-handshake message) report false; the caller
// delivers them immediately and Open decides what they are, exactly as it
// would have without the resequencer.
func (s *Session) ResolveCounter(msg []byte) (uint64, bool) {
	if len(msg) < TransportOverhead() {
		return 0, false
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.wiped || s.recvWindow == nil || !s.recvWindow.indexed() {
		return 0, false
	}
	return s.recvWindow.lookup(msg[:DemuxTokenSize])
}

// openCounterLocked is the single decryption path, shared by Open and OpenAt so
// that the two cannot drift apart. The caller holds recvMu and has already
// established that the counter is one this session will accept.
//
// Everything that decides whether the message is genuine happens here, in the
// AEAD: the counter picks the nonce, the token as it arrived on the wire is the
// AAD, and both must be exactly what the sender used or Open fails. Nothing
// above this point authenticates anything.
func (s *Session) openCounterLocked(msg []byte, counter uint64) ([]byte, error) {
	return s.openIntoCounterLocked(nil, msg, counter, false)
}

func (s *Session) openIntoCounterLocked(dst, msg []byte, counter uint64, tokenResolved bool) ([]byte, error) {
	token := msg[:DemuxTokenSize]

	copy(s.recvNonce[:nonceSaltSize], s.recvSalt[:])
	binary.BigEndian.PutUint64(s.recvNonce[nonceSaltSize:], counter)

	var dstCap []byte
	if dst != nil {
		dstCap = dst[:0]
	}
	plain, err := s.recvAEAD.Open(dstCap, s.recvNonce[:], msg[DemuxTokenSize:], token)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(plain) < transportHeaderSize {
		return nil, ErrDecrypt
	}
	n := int(binary.BigEndian.Uint16(plain[:transportHeaderSize]))
	if transportHeaderSize+n > len(plain) {
		return nil, ErrDecrypt
	}

	if tokenResolved {
		s.recvWindow.consumeKnown(counter, token)
	} else {
		s.recvWindow.consume(counter)
	}
	s.recvdBytes += uint64(len(msg))

	return plain[transportHeaderSize : transportHeaderSize+n : transportHeaderSize+n], nil
}

// --- ratchets ---------------------------------------------------------------

// ratchet folds a secret into the chain and installs the next epoch.
//
// Both ends must ratchet at the same logical point in the stream, which is the
// driver's responsibility: it is the frame exchange (PQ_EK/PQ_CT or
// REKEY_INIT/REKEY_ACK) that establishes the point, not this function.
func (s *Session) ratchet(secret []byte, label string) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if s.wiped {
		return ErrWiped
	}
	return s.ratchetLocked(secret, label)
}

// ratchetLocked is the body of ratchet. Callers hold sendMu, recvMu, chainMu
// in that order.
func (s *Session) ratchetLocked(secret []byte, label string) error {
	s.ch.mixSecret(secret, label)
	return s.installEpoch(s.epoch + 1)
}

// MixPQ folds the ML-KEM-768 shared secret into the chain and advances to the
// next epoch. Both ends call it with the same secret after exchanging PQ_EK and
// PQ_CT frames.
//
// It runs after the handshake rather than inside it because ephemeral-ephemeral
// ML-KEM-768 needs 1184 + 1088 bytes, which would push the first packet past
// the 1280-byte IPv6 minimum MTU. A fragmented first packet is a distinctive
// fingerprint and fragments are widely dropped. Carrying the KEM as ordinary
// transport frames also makes it indistinguishable from data, which putting it
// in the handshake could not be.
func (s *Session) MixPQ(sharedSecret []byte) error {
	if len(sharedSecret) != PQSharedKeySize {
		return errWrap(ErrConfig, "pq shared secret is %d bytes, need %d", len(sharedSecret), PQSharedKeySize)
	}
	// pqDone is claimed under the same locks as the ratchet. The previous
	// check-then-ratchet released chainMu in between, so two MixPQ calls could
	// both see pqDone==false, both advance the epoch, and leave the peer one
	// epoch behind: a silent desynchronisation, not an error.
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	s.chainMu.Lock()
	defer s.chainMu.Unlock()
	if s.wiped {
		return ErrWiped
	}
	if s.pqDone {
		return ErrPQAlreadyRatchet
	}
	if err := s.ratchetLocked(sharedSecret, labelPQ); err != nil {
		return err
	}
	s.pqDone = true
	return nil
}

// Rekey folds a fresh X25519 shared secret into the chain and advances the
// epoch.
//
// Winn3 rekeys IN BAND, inside the current epoch's transport AEAD, so on the
// wire a rekey is two ordinary-looking messages. The alternative (emitting a
// fresh handshake initiation every couple of minutes, as the WireGuard family
// does) is a recurring, distinctively sized packet: a static-byte failure and
// a timing failure at the same time.
func (s *Session) Rekey(sharedSecret []byte) error {
	if len(sharedSecret) != KeySize {
		return errWrap(ErrConfig, "rekey secret is %d bytes, need %d", len(sharedSecret), KeySize)
	}
	return s.ratchet(sharedSecret, labelRekey)
}

// --- post-quantum helpers ---------------------------------------------------

// PQEphemeral is one side's ML-KEM-768 ephemeral key pair for the ratchet.
type PQEphemeral struct {
	dk *mlkem.DecapsulationKey768
}

// GeneratePQEphemeral draws a fresh ML-KEM-768 key pair.
func GeneratePQEphemeral() (*PQEphemeral, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &PQEphemeral{dk: dk}, nil
}

// EncapsulationKey returns the 1184-byte public value to send in a PQ_EK frame.
func (p *PQEphemeral) EncapsulationKey() []byte { return p.dk.EncapsulationKey().Bytes() }

// Decapsulate recovers the shared secret from a peer's PQ_CT frame.
func (p *PQEphemeral) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != PQCiphertextSize {
		return nil, errWrap(ErrConfig, "pq ciphertext is %d bytes, need %d", len(ciphertext), PQCiphertextSize)
	}
	ss, err := p.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, ErrDecrypt
	}
	return ss, nil
}

// PQEncapsulate produces a ciphertext and shared secret against a peer's
// encapsulation key.
func PQEncapsulate(encapsulationKey []byte) (ciphertext, shared []byte, err error) {
	if len(encapsulationKey) != PQEncapsulationKeySize {
		return nil, nil, errWrap(ErrConfig, "pq encapsulation key is %d bytes, need %d", len(encapsulationKey), PQEncapsulationKeySize)
	}
	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, errWrap(ErrConfig, "pq encapsulation key rejected: %v", err)
	}
	ss, ct := ek.Encapsulate()
	return ct, ss, nil
}
