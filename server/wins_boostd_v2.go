//go:build linux

// Package main implements wins-boostd-v2, the parked "Smart Boost" Wi-Fi +
// mobile-data bonding daemon (see docs/SMART_BOOST_WIFI_MOBILE_PARKED.md).
//
// Wire protocol v3 (authenticated sessions)
//
// Every UDP datagram starts with a 6-byte common header:
//
//	magic[4] "WBS3" | frameType[1] | pathID[1]
//
// typeHandshakeInit (client -> server) carries, unencrypted, a
// control-plane-issued ticket followed by an ephemeral X25519 public key:
//
//	ticket[117] | clientEphemeralPub[32]
//
// The ticket (wire format v2 - see ticketVersion2) binds a random client
// ID, the client's assigned inner IP, a key ID, an expiry, a random 128-bit
// one-time ticket ID (jti), and the exact X25519 public key the client must
// present at handshake time - all signed with HMAC-SHA256 under
// BOOST_TICKET_SIGNING_KEY. It is the only thing the server trusts for
// identity; nothing inside a data packet's payload is ever treated as
// authoritative for who a peer is.
//
// Binding the public key into the signed ticket (H-6) means a network
// observer who copies a captured ticket cannot attach their own key and
// hijack the session: parseHandshakeInit rejects any handshake whose
// on-wire public key does not exactly match the ticket's bound key, so only
// whoever holds the matching private key can ever complete a handshake with
// it. Binding a single-use jti and enforcing it via an expiry-bounded
// replay cache (handleHandshakeInit) means a captured ticket cannot be
// replayed to tear down and rebuild ("supersede") the legitimate session
// either: an exact replay gets the original handshake acknowledgement
// resent instead of triggering a new session establishment, which is safe
// because only the legitimate client's private key can ever derive that
// session's AEAD keys from it. Ticket format v1 (which bound neither) is no
// longer accepted.
//
// The server verifies the ticket, generates its own ephemeral X25519 key
// pair, computes the ECDH shared secret, and derives two one-off
// AES-256-GCM session keys from it with HKDF-SHA256 (salted with the
// ticket's clientID, assignedIP and keyID; separated by direction via
// hkdfInfoClientToServer/hkdfInfoServerToClient) - one to open frames this
// session sends the server, one to seal frames the server sends back. Two
// directional keys (rather than one shared both ways) mean the client and
// server can each pick their own frame nonces with no coordination and no
// risk of an inter-direction nonce collision under the same AEAD key. The
// server replies with typeHandshakeAck:
//
//	serverEphemeralPub[32] | nonce[12] | seal(expiresUnix[8])
//
// From then on, typeData/typePing/typeProbe (client -> server) and
// typePong/typeProbeData (server -> client) share one 28-byte frame header
// (in addition to the 6-byte common header):
//
//	seq[8] | keyID[8] | nonce[12] | seal(payload)
//
// keyID selects which session (and, by direction, which of its two AEAD
// keys) applies; seq feeds a per-session sliding replay window. A session
// is bound, per pathID, to the first UDP endpoint that successfully
// authenticates on that path, and every later packet for that (session,
// pathID) pair must originate from the same endpoint. This intentionally
// binds per network path rather than per session as a whole, because
// bonding multiple concurrent real endpoints (e.g. Wi-Fi + cellular) under
// one authenticated session is this daemon's core feature.
//
// There is no live client for this parked protocol, so the legacy v2
// shared-passphrase (BOOST_KEY) data-plane authentication has been removed
// entirely rather than kept for compatibility.
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	boostVersion = "v9.0-authenticated-sessions"

	tunSetIFF = 0x400454CA
	iffTun    = 0x0001
	iffNoPI   = 0x1000

	reorderWait              = 18 * time.Millisecond
	reorderMaxPackets        = 16384
	sequenceRestartGap       = uint64(4096)
	schedulerMaxVirtualLag   = 2 * time.Second
	defaultPathRTT           = int64(220)
	defaultPathBps           = uint64(25_000_000)
	minProvenSecondaryBps    = uint64(3_750_000)
	secondaryRTTHeadroom     = int64(110)
	secondaryRTTMultiplierN  = int64(3)
	secondaryRTTMultiplierD  = int64(2)
	secondaryAbsoluteRTT     = int64(360)
	secondaryMinProbeBytes   = uint64(2_000_000)
	secondaryExploreMaxBytes = uint64(8_000_000)
	stripeExplorationBps     = uint64(50_000_000)
	singleFlowSecondaryMin   = uint64(8_000_000)
	singleFlowSecondaryMax   = uint64(96_000_000)
	singleFlowSecondaryDiv   = uint64(2)
	minStripeSecondaryBps    = uint64(6_250_000)
	stripeExploreMaxBytes    = uint64(2_000_000)
	stripeRTTHeadroom        = int64(75)
	stripeRTTMultiplierN     = int64(3)
	stripeRTTMultiplierD     = int64(2)
	stripeAbsoluteRTT        = int64(320)
	maxPacketSize            = 65535
	maxFlowCache             = 4096
	flowCacheTTL             = 60 * time.Second
	flowBondActiveWindow     = 5 * time.Second
	flowBondActiveLimit      = 16
	flowBondSlotMinBytes     = uint64(512_000)
	singleFlowStriping       = true
	globalPacketReorder      = false
	wifiBurstPackets         = 1
	secondaryBurstPackets    = 1
	wifiPathID               = uint8(1)
	wifiSubpathBaseID        = uint8(10)
	wifiSubpathCount         = uint8(1)
	txBatchFlushDelay        = 250 * time.Microsecond
	txBatchMaxPackets        = 16
	txBatchMaxPayloadBytes   = 1350
	txBatchMaxPacketBytes    = 640
	flowOrderSequenceFactor  = uint64(32)
	flowReorderTTL           = 60 * time.Second

	// --- Wire protocol v3 framing ---

	magicV3         = "WBS3"
	commonHeaderLen = 4 + 1 + 1 // magic + frameType + pathID

	authFrameSeqLen    = 8
	authFrameKeyIDLen  = 8
	authFrameNonceLen  = 12
	authFrameAADLen    = commonHeaderLen + authFrameSeqLen + authFrameKeyIDLen // 22
	authFrameHeaderLen = authFrameAADLen + authFrameNonceLen                   // 34
	aeadOverhead       = 16                                                    // AES-256-GCM tag size

	typeHandshakeInit = uint8(1)
	typeHandshakeAck  = uint8(2)
	typeData          = uint8(3)
	typePing          = uint8(4)
	typePong          = uint8(5)
	typeProbe         = uint8(6)
	typeProbeData     = uint8(7)

	dataBatchMagic     = "WSD2"
	dataBatchHeaderLen = 4 + 2 // magic + packet count

	pingPayloadLen       = 24 // rttMs[8] | downBps[8] | featureFlags[4] | featureMagic[4]
	clientFeatureBatchTx = uint32(1)
	clientFeatureMagic   = uint32(0x57424631) // "WBF1"

	// --- Ticket format (control-plane issued, HMAC-SHA256 signed) ---
	//
	// ticketVersion1 (deprecated, H-6) signed only clientID/assignedIP/
	// keyID/expiry: nothing in the signed bytes bound the ticket to a
	// specific client key pair or made it single-use, so a network
	// observer who copied a valid ticket off the wire could attach their
	// own X25519 public key and hijack the session, or replay the ticket
	// verbatim to tear down and re-establish ("supersede") the legitimate
	// session. ticketVersion2 fixes both by additionally signing a random
	// 128-bit one-time jti and the client's exact X25519 public key; only
	// v2 is accepted (see parseTicket) - there is no live v1 issuer to
	// migrate from (the control plane that issues these tickets is a
	// separate, out-of-scope service - see the package doc comment - and
	// this daemon has no deployed instance: it is actively removed by
	// remove_legacy_smart_boost in wins_data_plane_setup_ONETOUCH.sh).
	ticketVersion1      = uint8(1) // no longer accepted; kept only to document/test its rejection
	ticketVersion2      = uint8(2)
	ticketClientIDLen   = 16
	ticketAssignedIPLen = 4
	ticketKeyIDLen      = 8
	ticketExpiryLen     = 8
	ticketJTILen        = 16 // one-time ticket ID, for single-use replay rejection
	ticketClientPubLen  = 32 // X25519 public key this ticket is bound to
	ticketSignatureLen  = sha256.Size
	ticketCanonicalLen  = 1 + ticketClientIDLen + ticketAssignedIPLen + ticketKeyIDLen + ticketExpiryLen + ticketJTILen + ticketClientPubLen // 85
	ticketFixedLen      = ticketCanonicalLen + ticketSignatureLen                                                                            // 117
	maxTicketLifetime   = 24 * time.Hour

	// maxTicketReplayEntries bounds the H-6 jti replay cache (see
	// sessionTable.ticketReplay). Sized generously above maxActiveSessions
	// (rather than 1:1) because a single client can accumulate more than
	// one still-unexpired jti over a ticket's lifetime across reconnects,
	// independent of how many sessions are concurrently active.
	maxTicketReplayEntries = maxActiveSessions * 4

	x25519PubKeyLen      = 32
	handshakeInitBodyLen = ticketFixedLen + x25519PubKeyLen // 149
	handshakeAckPlainLen = 8                                // expiresUnix

	// Distinct HKDF info strings give the client->server and server->client
	// directions independently-derived AEAD keys from the same ECDH shared
	// secret. This is deliberate, not just belt-and-suspenders: each side
	// picks its own nonce (a random salt plus a local counter) with no
	// coordination between them, so sharing one AEAD key for both
	// directions would risk a nonce collision (e.g. matching random salts)
	// under the same key, which is catastrophic for AES-GCM. Separate keys
	// make that impossible regardless of how either side manages nonces.
	hkdfInfoClientToServer = "wins-boostd-v3 session-key client-to-server"
	hkdfInfoServerToClient = "wins-boostd-v3 session-key server-to-client"
	sessionAEADKeyLen      = 32 // AES-256-GCM

	// --- Session bookkeeping caps (H-10: bounded state, idle expiry) ---

	maxActiveSessions    = 4096
	maxPathsPerSession   = 8
	sessionIdleTimeout   = 90 * time.Second
	maxSessionLifetime   = 12 * time.Hour
	sessionSweepInterval = 5 * time.Second

	replayWindowBits  = 2048
	replayWindowWords = replayWindowBits / 64

	// --- Probe amplification limits (H-11) ---

	maxProbeRequestBytes        = 64 << 10 // 64 KiB hard cap per probe request
	probeDefaultBytes           = 16 << 10
	probeDefaultChunkBytes      = 1152
	probeMaxChunkBytes          = 1152
	probeSessionRateBytesPerSec = 4 << 20   // 4 MiB/s sustained per session
	probeSessionBurstBytes      = 8 << 20   // 8 MiB burst per session
	probeGlobalRateBytesPerSec  = 64 << 20  // 64 MiB/s sustained across all sessions
	probeGlobalBurstBytes       = 128 << 20 // 128 MiB burst globally
	maxProbeWorkers             = 64        // bounded goroutine pool for in-flight probe sends

	// --- Privilege drop (H-10) ---
	// Conventional "nobody"/"nogroup" ids on most Linux distributions; override
	// with BOOST_RUN_AS_UID / BOOST_RUN_AS_GID if that collides with anything.
	defaultRunAsUID = 65534
	defaultRunAsGID = 65534
)

type envConfig struct {
	iface                string
	serverCIDR           string
	port                 int
	mtu                  int
	ticketSigningKeyText string
	workers              int
	runAsUID             int
	runAsGID             int
}

// ticket is the parsed, verified form of a control-plane-issued credential.
// Identity for every session is derived exclusively from a validated ticket
// - never from any packet's self-reported contents. jti and clientPub (H-6)
// are what make a ticket single-use and non-transferable: jti lets
// handleHandshakeInit's replay cache recognize and reject a second, distinct
// use of the same ticket, and clientPub lets parseHandshakeInit refuse any
// handshake whose on-wire public key was not the one this ticket was issued
// for.
type ticket struct {
	clientID   [16]byte
	assignedIP [4]byte
	keyID      uint64
	expires    time.Time
	jti        [ticketJTILen]byte
	clientPub  [ticketClientPubLen]byte
}

// ticketCanonicalBytes builds the exact bytes signTicket/parseTicket sign
// and verify. jti and clientPub are appended after expiresUnix and are
// covered by the HMAC exactly like every other field (H-6: they must never
// be trusted unless they were part of what was signed).
func ticketCanonicalBytes(version uint8, clientID [16]byte, assignedIP [4]byte, keyID uint64, expiresUnix int64, jti [ticketJTILen]byte, clientPub [ticketClientPubLen]byte) []byte {
	buf := make([]byte, ticketCanonicalLen)
	buf[0] = version
	offset := 1
	copy(buf[offset:offset+ticketClientIDLen], clientID[:])
	offset += ticketClientIDLen
	copy(buf[offset:offset+ticketAssignedIPLen], assignedIP[:])
	offset += ticketAssignedIPLen
	binary.BigEndian.PutUint64(buf[offset:offset+8], keyID)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(expiresUnix))
	offset += 8
	copy(buf[offset:offset+ticketJTILen], jti[:])
	offset += ticketJTILen
	copy(buf[offset:offset+ticketClientPubLen], clientPub[:])
	return buf
}

// signTicket builds a signed ticket in the exact format parseTicket expects.
// The production issuer of these tickets is the control plane (a separate,
// out-of-scope service); this helper exists so the wire format is documented
// and testable in one place. jti must be a fresh random value per ticket
// issuance (never reused across tickets, even for the same client) and
// clientPub must be the exact X25519 public key the client will present at
// handshake time - parseHandshakeInit rejects any handshake whose on-wire
// key does not match it exactly.
func signTicket(signingKey []byte, clientID [16]byte, assignedIP [4]byte, keyID uint64, expires time.Time, jti [ticketJTILen]byte, clientPub [ticketClientPubLen]byte) []byte {
	canonical := ticketCanonicalBytes(ticketVersion2, clientID, assignedIP, keyID, expires.Unix(), jti, clientPub)
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	sig := mac.Sum(nil)
	out := make([]byte, 0, len(canonical)+len(sig))
	out = append(out, canonical...)
	out = append(out, sig...)
	return out
}

// parseTicket verifies the HMAC-SHA256 signature over the ticket's canonical
// bytes using signingKey (BOOST_TICKET_SIGNING_KEY) and, only on success,
// returns the parsed fields. Callers must still check expiry themselves.
//
// Only ticketVersion2 is accepted (H-6). ticketVersion1 tickets did not bind
// jti or the client's public key into the signed bytes, which let a network
// observer copy a valid ticket, attach their own key, and hijack the
// session, or replay it verbatim to supersede the legitimate session; v1 is
// rejected outright rather than accepted during a migration window, because
// there is no live v1 issuer to migrate from (see the ticketVersion1 doc
// comment).
func parseTicket(signingKey []byte, raw []byte) (ticket, bool) {
	if len(raw) != ticketFixedLen || raw[0] != ticketVersion2 {
		return ticket{}, false
	}
	canonical := raw[:ticketCanonicalLen]
	sig := raw[ticketCanonicalLen:ticketFixedLen]

	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sig) {
		return ticket{}, false
	}

	var t ticket
	offset := 1
	copy(t.clientID[:], raw[offset:offset+ticketClientIDLen])
	offset += ticketClientIDLen
	copy(t.assignedIP[:], raw[offset:offset+ticketAssignedIPLen])
	offset += ticketAssignedIPLen
	t.keyID = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	expiresUnix := int64(binary.BigEndian.Uint64(raw[offset : offset+8]))
	t.expires = time.Unix(expiresUnix, 0)
	offset += 8
	copy(t.jti[:], raw[offset:offset+ticketJTILen])
	offset += ticketJTILen
	copy(t.clientPub[:], raw[offset:offset+ticketClientPubLen])
	return t, true
}

// deriveSessionKey turns a fresh ECDH shared secret into a per-session,
// per-direction AES-256-GCM key via HKDF-SHA256 (RFC 5869), salted with the
// ticket's clientID+assignedIP+keyID for domain separation and keyed apart
// by direction via info (hkdfInfoClientToServer/hkdfInfoServerToClient).
// Using the ECDH output (rather than any long-lived secret) as HKDF's input
// keying material gives each session forward secrecy: recovering
// BOOST_TICKET_SIGNING_KEY alone does not let an attacker decrypt
// previously captured session traffic.
func deriveSessionKey(sharedSecret []byte, t ticket, info string) ([]byte, error) {
	salt := make([]byte, 0, ticketClientIDLen+ticketAssignedIPLen+8)
	salt = append(salt, t.clientID[:]...)
	salt = append(salt, t.assignedIP[:]...)
	var keyIDBytes [8]byte
	binary.BigEndian.PutUint64(keyIDBytes[:], t.keyID)
	salt = append(salt, keyIDBytes[:]...)
	return hkdf.Key(sha256.New, sharedSecret, salt, info, sessionAEADKeyLen)
}

// deriveDirectionalAEADs derives the client->server and server->client AEAD
// ciphers for a session from one ECDH shared secret. See
// hkdfInfoClientToServer/hkdfInfoServerToClient for why these must differ.
func deriveDirectionalAEADs(sharedSecret []byte, t ticket) (rx, tx cipher.AEAD, err error) {
	rxKey, err := deriveSessionKey(sharedSecret, t, hkdfInfoClientToServer)
	if err != nil {
		return nil, nil, err
	}
	txKey, err := deriveSessionKey(sharedSecret, t, hkdfInfoServerToClient)
	if err != nil {
		return nil, nil, err
	}
	rx, err = newAESGCM(rxKey)
	if err != nil {
		return nil, nil, err
	}
	tx, err = newAESGCM(txKey)
	if err != nil {
		return nil, nil, err
	}
	return rx, tx, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ReplayWindow is a bitmap-based sliding anti-replay window (the same
// construction used by IPsec/WireGuard-style protocols): it remembers which
// of the last replayWindowBits sequence numbers up to the current high-water
// mark have already been accepted, rejecting exact duplicates and anything
// older than the window while tolerating legitimate out-of-order delivery.
type ReplayWindow struct {
	mu   sync.Mutex
	seen bool
	high uint64
	bits [replayWindowWords]uint64
}

// Accept reports whether seq is new, marking it seen as a side effect.
// Sequence 0 is reserved/invalid and is always rejected.
func (w *ReplayWindow) Accept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.seen {
		w.seen = true
		w.high = seq
		w.setBit(0)
		return true
	}
	if seq > w.high {
		shift := seq - w.high
		w.shiftLeft(shift)
		w.high = seq
		w.setBit(0)
		return true
	}
	age := w.high - seq
	if age >= replayWindowBits {
		return false
	}
	if w.testBit(age) {
		return false
	}
	w.setBit(age)
	return true
}

func (w *ReplayWindow) setBit(age uint64) {
	w.bits[age/64] |= 1 << (age % 64)
}

func (w *ReplayWindow) testBit(age uint64) bool {
	return w.bits[age/64]&(1<<(age%64)) != 0
}

// shiftLeft moves every previously-seen bit to an age that is n larger,
// discarding bits that age out past the window and zero-filling the newly
// opened low-age slots (sequence numbers not yet observed).
func (w *ReplayWindow) shiftLeft(n uint64) {
	if n >= replayWindowBits {
		w.bits = [replayWindowWords]uint64{}
		return
	}
	wordShift := int(n / 64)
	bitShift := n % 64

	if wordShift > 0 {
		for i := replayWindowWords - 1; i >= 0; i-- {
			src := i - wordShift
			if src >= 0 {
				w.bits[i] = w.bits[src]
			} else {
				w.bits[i] = 0
			}
		}
	}
	if bitShift > 0 {
		var carry uint64
		for i := 0; i < replayWindowWords; i++ {
			cur := w.bits[i]
			w.bits[i] = (cur << bitShift) | carry
			carry = cur >> (64 - bitShift)
		}
	}
}

// tokenBucket is a minimal token-bucket rate limiter (the same AllowN shape
// as golang.org/x/time/rate.Limiter) implemented directly against the
// standard library so this single-file daemon needs no extra module
// dependency.
type tokenBucket struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64 // bucket capacity
	tokens  float64
	updated time.Time
}

func newTokenBucket(ratePerSecond, burst float64) *tokenBucket {
	return &tokenBucket{rate: ratePerSecond, burst: burst, tokens: burst, updated: time.Now()}
}

// AllowN reports whether n tokens are available at now, consuming them if so.
func (b *tokenBucket) AllowN(now time.Time, n int) bool {
	if n <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if elapsed := now.Sub(b.updated).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.updated = now
	}
	cost := float64(n)
	if cost > b.tokens {
		return false
	}
	b.tokens -= cost
	return true
}

type pendingPacket struct {
	payloads [][]byte
	created  time.Time
}

type reorderBuffer struct {
	expected uint64
	pending  map[uint64]pendingPacket
}

type pathState struct {
	addr              *net.UDPAddr
	lastSeen          time.Time
	lastDecay         time.Time
	failures          int
	rttMs             int64
	reportedBps       uint64
	capacityFloorBps  uint64
	sentBytes         uint64
	chosenPkts        uint64
	chosenBytes       uint64
	virtualSendFinish time.Time
}

type flowChoice struct {
	pathID         uint8
	lastUsed       time.Time
	bytes          uint64
	bonded         bool
	burstPathID    uint8
	burstRemaining int
}

// authenticatedSession is the server-side state for one control-plane
// authorized client. Identity (clientID/assignedIP/keyID) comes solely from
// a validated ticket at handshake time; the AEAD key is unique to this
// session (never shared fleet-wide); and every data/ping/probe frame must
// decrypt under that key before any of the fields below are trusted or
// mutated.
type authenticatedSession struct {
	mu sync.Mutex

	keyID      uint64
	clientID   [16]byte
	assignedIP [4]byte

	// aeadRx/aeadTx are independently-derived (see hkdfInfoClientToServer/
	// hkdfInfoServerToClient) so the two directions can never share a
	// nonce under the same key even though each direction picks nonces
	// independently.
	aeadRx    cipher.AEAD // decrypts client -> server frames
	aeadTx    cipher.AEAD // encrypts server -> client frames
	replay    *ReplayWindow
	nonceSalt [4]byte
	nonceCtr  atomic.Uint64

	created  time.Time
	expires  time.Time
	lastSeen time.Time

	paths   map[uint8]*pathState
	flows   map[uint64]flowChoice
	rx      *reorderBuffer
	flowRx  map[uint64]*reorderBuffer
	flowAt  map[uint64]time.Time
	txSeq   uint64
	lastLog time.Time
	batchTx bool

	probeLimiter *tokenBucket
}

func (sess *authenticatedSession) assignedIPAddr() net.IP {
	return net.IPv4(sess.assignedIP[0], sess.assignedIP[1], sess.assignedIP[2], sess.assignedIP[3])
}

func (sess *authenticatedSession) nextNonce() [12]byte {
	var nonce [12]byte
	copy(nonce[:4], sess.nonceSalt[:])
	binary.BigEndian.PutUint64(nonce[4:], sess.nonceCtr.Add(1))
	return nonce
}

// sealFrame encrypts payload for this session and returns a complete v3
// frame (common header + seq/keyID/nonce + ciphertext). dst is reused as
// scratch space when it has enough capacity (buffer-pool friendly).
func (sess *authenticatedSession) sealFrame(frameType, pathID uint8, seq uint64, payload []byte, dst []byte) []byte {
	needed := authFrameHeaderLen + len(payload) + aeadOverhead
	if cap(dst) < needed {
		dst = make([]byte, 0, needed)
	}
	frame := dst[:authFrameHeaderLen]
	copy(frame[0:4], magicV3)
	frame[4] = frameType
	frame[5] = pathID
	binary.BigEndian.PutUint64(frame[6:14], seq)
	binary.BigEndian.PutUint64(frame[14:22], sess.keyID)
	nonce := sess.nextNonce()
	copy(frame[22:34], nonce[:])
	return sess.aeadTx.Seal(frame, nonce[:], payload, frame[:authFrameAADLen])
}

// authenticateAndOpen validates an incoming frame against this session: the
// session must not be expired, the ciphertext must decrypt under this
// session's unique AEAD key, the sequence number must pass the replay
// window, and the source endpoint must match whichever endpoint this
// (session, pathID) pair was first observed from (auto-registering pathID on
// its first successfully authenticated packet, up to maxPathsPerSession).
// Every check happens only after AEAD authentication succeeds, so nothing an
// unauthenticated attacker sends can mutate session state.
func (sess *authenticatedSession) authenticateAndOpen(pathID uint8, seq uint64, nonce, ciphertext, aad []byte, addr *net.UDPAddr, now time.Time) ([]byte, bool) {
	sess.mu.Lock()
	expired := now.After(sess.expires)
	sess.mu.Unlock()
	if expired {
		return nil, false
	}

	plain, err := sess.aeadRx.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, false
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if !sess.replay.Accept(seq) {
		return nil, false
	}

	path := sess.paths[pathID]
	if path == nil {
		if len(sess.paths) >= maxPathsPerSession {
			return nil, false
		}
		path = &pathState{lastDecay: now, rttMs: defaultPathRTT}
		sess.paths[pathID] = path
	}
	if path.addr == nil {
		path.addr = cloneUDPAddr(addr)
	} else if !sameUDPAddr(path.addr, addr) {
		return nil, false
	}

	sess.lastSeen = now
	path.lastSeen = now
	path.failures = 0
	return plain, true
}

func (sess *authenticatedSession) nextTxSeq() uint64 {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.txSeq++
	return sess.txSeq
}

func (sess *authenticatedSession) markPathFailure(pathID uint8) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if path := sess.paths[pathID]; path != nil {
		path.failures = 9
	}
}

// updatePathMetrics folds a client's self-reported RTT/bandwidth for pathID
// into that path's smoothed stats. Trusting a client's own performance
// self-report for its own already-authenticated session is not a security
// concern (unlike trusting self-reported identity); it is the multipath
// scheduler's telemetry input.
func (sess *authenticatedSession) updatePathMetrics(pathID uint8, rttMs int64, downBps uint64, supportsBatch bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if supportsBatch {
		sess.batchTx = true
	}

	now := time.Now()
	path := sess.paths[pathID]
	if path == nil {
		if len(sess.paths) >= maxPathsPerSession {
			return
		}
		path = &pathState{rttMs: defaultPathRTT, lastDecay: now}
		sess.paths[pathID] = path
	} else if !path.lastSeen.IsZero() && now.Sub(path.lastSeen) > 5*time.Second {
		path.sentBytes = 0
		path.chosenPkts = 0
		path.chosenBytes = 0
		if path.reportedBps > defaultPathBps {
			path.reportedBps = (path.reportedBps * 8) / 10
		}
		path.lastDecay = now
	}
	path.lastSeen = now
	path.failures = 0
	if rttMs > 0 {
		if rttMs < 1 {
			rttMs = 1
		}
		if rttMs > 5000 {
			rttMs = 5000
		}
		if path.rttMs <= 0 {
			path.rttMs = rttMs
		} else {
			path.rttMs = ((path.rttMs * 3) + rttMs) / 4
		}
	}
	if downBps > 0 {
		if isWiFiPathID(pathID) {
			floor := (downBps * 7) / 10
			if floor < defaultPathBps {
				floor = defaultPathBps
			}
			if floor > path.capacityFloorBps {
				path.capacityFloorBps = floor
			}
		}
		nextBps := downBps
		if isWiFiPathID(pathID) && path.capacityFloorBps > 0 && nextBps < path.capacityFloorBps {
			nextBps = path.capacityFloorBps
		}
		if path.reportedBps == 0 || path.reportedBps == defaultPathBps {
			path.reportedBps = nextBps
		} else {
			if isWiFiPathID(pathID) && nextBps < path.reportedBps {
				minPercent := uint64(85)
				minStep := (path.reportedBps * minPercent) / 100
				if nextBps < minStep {
					nextBps = minStep
				}
			}
			path.reportedBps = ((path.reportedBps * 3) + nextBps) / 4
		}
		if isWiFiPathID(pathID) && path.capacityFloorBps > 0 && path.reportedBps < path.capacityFloorBps {
			path.reportedBps = path.capacityFloorBps
		}
	}
}

func (sess *authenticatedSession) logPathMetricsLocked(now time.Time) {
	if now.Sub(sess.lastLog) < 5*time.Second {
		return
	}
	sess.lastLog = now
	ids := make([]int, 0, len(sess.paths))
	for id := range sess.paths {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	parts := make([]string, 0, len(ids))
	for _, rawID := range ids {
		id := uint8(rawID)
		path := sess.paths[id]
		if path == nil {
			continue
		}
		ageMs := now.Sub(path.lastSeen).Milliseconds()
		parts = append(parts, fmt.Sprintf(
			"path=%d rtt=%dms bps=%d chosen_pkts=%d chosen_bytes=%d load_bytes=%d age=%dms failures=%d",
			id,
			path.rttMs,
			path.reportedBps,
			path.chosenPkts,
			path.chosenBytes,
			path.sentBytes,
			ageMs,
			path.failures,
		))
	}
	if len(parts) > 0 {
		fmt.Printf("wins-boostd session=%s path metrics: %s\n", hex.EncodeToString(sess.clientID[:]), strings.Join(parts, "; "))
	}
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	ipCopy := make(net.IP, len(addr.IP))
	copy(ipCopy, addr.IP)
	return &net.UDPAddr{IP: ipCopy, Port: addr.Port, Zone: addr.Zone}
}

// sessionTable owns the authoritative maps from keyID/clientID/assignedIP to
// authenticatedSession, and enforces the H-10 state caps (max concurrent
// sessions, idle/expired eviction). It has no dependency on networking or
// TUN setup, which keeps session-lifecycle logic (establish/lookup/evict)
// independently unit-testable.
// ticketReplayEntry is a cached record of one successfully-processed
// handshake, keyed by the ticket's jti (H-6). ack is nil while the very
// first use of that jti is still being established (see beginTicketUse) and
// populated once handleHandshakeInit finishes (see finishTicketUse); expires
// mirrors the ticket's own expiry, so an entry can never legitimately be
// replayed for longer than the ticket that produced it was ever valid.
type ticketReplayEntry struct {
	ack     []byte
	expires time.Time
}

type sessionTable struct {
	mu           sync.RWMutex
	byKeyID      map[uint64]*authenticatedSession
	byClientID   map[[16]byte]uint64
	byAssignedIP map[[4]byte]uint64
	ticketReplay map[[ticketJTILen]byte]ticketReplayEntry
}

func newSessionTable() *sessionTable {
	return &sessionTable{
		byKeyID:      map[uint64]*authenticatedSession{},
		byClientID:   map[[16]byte]uint64{},
		byAssignedIP: map[[4]byte]uint64{},
		ticketReplay: map[[ticketJTILen]byte]ticketReplayEntry{},
	}
}

var errSessionCapExceeded = errors.New("active session cap exceeded")

func (t *sessionTable) lookup(keyID uint64) *authenticatedSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byKeyID[keyID]
}

func (t *sessionTable) lookupByAssignedIP(ip [4]byte) *authenticatedSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	keyID, ok := t.byAssignedIP[ip]
	if !ok {
		return nil
	}
	return t.byKeyID[keyID]
}

func (t *sessionTable) count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byKeyID)
}

func (t *sessionTable) snapshot() []*authenticatedSession {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*authenticatedSession, 0, len(t.byKeyID))
	for _, sess := range t.byKeyID {
		out = append(out, sess)
	}
	return out
}

// establish installs a brand-new authenticated session for a freshly
// verified ticket. A validly-signed, non-expired ticket for a clientID (or
// for an assignedIP) always supersedes that clientID's/IP's previous
// session: the caller has already proven, via the ticket signature, that it
// is authorized to speak for that specific clientID, so this only ever
// narrows control to the scope of one client - it never lets one client
// affect another's session.
func (t *sessionTable) establish(tk ticket, aeadRx, aeadTx cipher.AEAD, now time.Time) (*authenticatedSession, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if existing, ok := t.byClientID[tk.clientID]; ok {
		t.removeLocked(existing)
	}
	if existing, ok := t.byAssignedIP[tk.assignedIP]; ok {
		t.removeLocked(existing)
	}

	if len(t.byKeyID) >= maxActiveSessions {
		t.evictIdleLocked(now)
		if len(t.byKeyID) >= maxActiveSessions {
			return nil, errSessionCapExceeded
		}
	}

	expires := tk.expires
	if ceiling := now.Add(maxSessionLifetime); expires.After(ceiling) {
		expires = ceiling
	}

	var nonceSalt [4]byte
	if _, err := rand.Read(nonceSalt[:]); err != nil {
		return nil, err
	}

	sess := &authenticatedSession{
		keyID:        tk.keyID,
		clientID:     tk.clientID,
		assignedIP:   tk.assignedIP,
		aeadRx:       aeadRx,
		aeadTx:       aeadTx,
		replay:       &ReplayWindow{},
		nonceSalt:    nonceSalt,
		created:      now,
		expires:      expires,
		lastSeen:     now,
		paths:        map[uint8]*pathState{},
		flows:        map[uint64]flowChoice{},
		rx:           newReorderBuffer(),
		flowRx:       map[uint64]*reorderBuffer{},
		flowAt:       map[uint64]time.Time{},
		probeLimiter: newTokenBucket(probeSessionRateBytesPerSec, probeSessionBurstBytes),
	}
	t.byKeyID[tk.keyID] = sess
	t.byClientID[tk.clientID] = tk.keyID
	t.byAssignedIP[tk.assignedIP] = tk.keyID
	return sess, nil
}

func (t *sessionTable) removeLocked(keyID uint64) {
	sess, ok := t.byKeyID[keyID]
	if !ok {
		return
	}
	delete(t.byKeyID, keyID)
	if t.byClientID[sess.clientID] == keyID {
		delete(t.byClientID, sess.clientID)
	}
	if t.byAssignedIP[sess.assignedIP] == keyID {
		delete(t.byAssignedIP, sess.assignedIP)
	}
}

func (t *sessionTable) evictIdleLocked(now time.Time) {
	for keyID, sess := range t.byKeyID {
		sess.mu.Lock()
		idle := now.Sub(sess.lastSeen) > sessionIdleTimeout || now.After(sess.expires)
		sess.mu.Unlock()
		if idle {
			t.removeLocked(keyID)
		}
	}
}

// sweep evicts idle/expired sessions and returns how many were removed. It
// is meant to be called periodically from a background loop. It also sweeps
// the H-6 ticket replay cache so that map stays bounded even without new
// handshakes pushing it over maxTicketReplayEntries.
func (t *sessionTable) sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	before := len(t.byKeyID)
	t.evictIdleLocked(now)
	t.evictTicketReplayLocked(now)
	return before - len(t.byKeyID)
}

// beginTicketUse is the entry point for the H-6 replay defense: it
// atomically checks whether jti has already been used.
//
//   - If jti is a cache hit and still within its recorded expiry, this is a
//     replay: alreadyUsed is true and ack is the original handshake's cached
//     acknowledgement (nil if that original handshake is still in flight -
//     see below), which the caller should resend verbatim instead of
//     re-running session establishment. This is what makes an exact ticket
//     replay - whether a legitimate retransmission because the client never
//     saw the first ack, or an attacker replaying a captured ticket
//     verbatim - unable to tear down and rebuild ("supersede") the
//     legitimate session: only the very first use of a jti is ever allowed
//     to reach establish().
//   - If jti is new, it is reserved here (recorded with a nil ack) and
//     alreadyUsed is false, telling the caller to proceed with a real
//     handshake and eventually call finishTicketUse or abortTicketUse. The
//     reservation closes a race that a plain "check, then insert after
//     establishing" sequence would leave open: UDP packets can be genuinely
//     duplicated by the network itself (not just retried by an idle-timeout
//     client), and without a reservation two concurrently-processed copies
//     of the identical handshake packet could both miss the cache and both
//     call establish(), with the second flapping the session's freshly
//     re-derived AEAD keys out from under the first before the legitimate
//     client ever saw either ack.
func (t *sessionTable) beginTicketUse(jti [ticketJTILen]byte, now time.Time) (ack []byte, alreadyUsed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.ticketReplay[jti]; ok && now.Before(entry.expires) {
		return entry.ack, true
	}
	// Insert first, then enforce the cap - mirroring pruneFlowCache's own
	// call convention (insert, then prune). evictTicketReplayLocked's
	// post-condition is "len <= maxTicketReplayEntries"; evicting *before*
	// this insert under a "len >= cap" gate would be off by one whenever
	// the map was sitting at exactly cap, since evictTicketReplayLocked
	// would see len == cap, correctly conclude there was nothing to trim,
	// and return right before the unconditional insert below pushed it to
	// cap+1.
	t.ticketReplay[jti] = ticketReplayEntry{expires: now.Add(maxTicketLifetime)}
	t.evictTicketReplayLocked(now)
	return nil, false
}

// finishTicketUse records the real handshake acknowledgement for jti once
// establishment succeeds, replacing the placeholder beginTicketUse reserved.
// expires should be the ticket's own (already-validated) expiry: an entry
// must never outlive the ticket that could legitimately produce a replay of
// it.
func (t *sessionTable) finishTicketUse(jti [ticketJTILen]byte, ack []byte, expires time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ticketReplay[jti] = ticketReplayEntry{ack: append([]byte(nil), ack...), expires: expires}
}

// abortTicketUse releases jti's reservation after a handshake that began
// with beginTicketUse fails before ever producing an ack (e.g. the session
// table is at capacity, or the ephemeral ECDH exchange fails). Without this,
// a single failed attempt would permanently "burn" that jti for the rest of
// its ticket's lifetime, silently blackholing every subsequent legitimate
// retry. It only clears a still-unfinished (nil-ack) reservation, so it can
// never undo a real finishTicketUse result.
func (t *sessionTable) abortTicketUse(jti [ticketJTILen]byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.ticketReplay[jti]; ok && entry.ack == nil {
		delete(t.ticketReplay, jti)
	}
}

// evictTicketReplayLocked bounds the H-6 replay cache the same two-phase way
// pruneFlowCache bounds the flow cache: drop everything past its own expiry
// first, then - only if still over the cap - drop the oldest-expiring
// entries until back within it. t.mu must already be held.
func (t *sessionTable) evictTicketReplayLocked(now time.Time) {
	for jti, entry := range t.ticketReplay {
		if now.After(entry.expires) {
			delete(t.ticketReplay, jti)
		}
	}
	if len(t.ticketReplay) <= maxTicketReplayEntries {
		return
	}
	type oldEntry struct {
		jti     [ticketJTILen]byte
		expires time.Time
	}
	oldest := make([]oldEntry, 0, len(t.ticketReplay))
	for jti, entry := range t.ticketReplay {
		oldest = append(oldest, oldEntry{jti: jti, expires: entry.expires})
	}
	sort.Slice(oldest, func(i, j int) bool {
		return oldest[i].expires.Before(oldest[j].expires)
	})
	for i := 0; i < len(oldest) && len(t.ticketReplay) > maxTicketReplayEntries; i++ {
		delete(t.ticketReplay, oldest[i].jti)
	}
}

type boostServer struct {
	cfg envConfig

	ticketSigningKey []byte

	udp *net.UDPConn
	tun *os.File

	sessions *sessionTable

	tunWrite sync.Mutex

	packetPool sync.Pool
	framePool  sync.Pool

	txBatchMu sync.Mutex
	txBatches map[string]*txBatch

	probeWorkers       chan struct{}
	globalProbeLimiter *tokenBucket
}

type txBatch struct {
	key     string
	sess    *authenticatedSession
	pathID  uint8
	addr    *net.UDPAddr
	packets [][]byte
	bytes   int
	timer   *time.Timer
}

type udpPacket struct {
	data    []byte
	addr    *net.UDPAddr
	release func()
}

type tunPacket struct {
	data    []byte
	release func()
}

func loadEnvFile(path string) map[string]string {
	out := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"`)
		out[key] = value
	}
	return out
}

func mergedEnv() map[string]string {
	out := loadEnvFile("/root/node.env")
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func envInt(env map[string]string, key string, fallback int) int {
	value := strings.TrimSpace(env[key])
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadConfig(env map[string]string) envConfig {
	workers := envInt(env, "BOOST_WORKERS", runtime.NumCPU())
	if workers < 2 {
		workers = 2
	}
	return envConfig{
		iface:                valueOr(env["BOOST_IFACE"], "winsboost0"),
		serverCIDR:           valueOr(env["BOOST_SERVER_CIDR"], "10.88.0.1/24"),
		port:                 envInt(env, "BOOST_PORT", 42110),
		mtu:                  envInt(env, "BOOST_MTU", 1420),
		ticketSigningKeyText: strings.TrimSpace(env["BOOST_TICKET_SIGNING_KEY"]),
		workers:              workers,
		runAsUID:             envInt(env, "BOOST_RUN_AS_UID", defaultRunAsUID),
		runAsGID:             envInt(env, "BOOST_RUN_AS_GID", defaultRunAsGID),
	}
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// decodeSigningKey canonicalizes BOOST_TICKET_SIGNING_KEY into HMAC key
// material. It requires strict base64 (RFC 4648 standard alphabet, correct
// padding, no trailing garbage) decoding to exactly 32 bytes.
//
// H-6: this used to fall back to SHA-256-hashing whatever raw text didn't
// decode as sufficiently-long base64, on the theory that hashing a short or
// low-entropy operator-supplied passphrase was better than using it
// directly. It is not: hashing a low-entropy input (e.g. a short human-typed
// passphrase) produces a 32-byte value with exactly the same guessable
// entropy as the input, not real 256 bits of key strength - an offline
// dictionary/brute-force attack against the resulting HMAC key is just as
// feasible as one against the original passphrase. There is no way to
// distinguish "32+ random bytes the operator generated properly" from "a
// short passphrase that happens to be long enough" from the string alone, so
// the only sound fix is to stop accepting anything but an explicit,
// exact-length, randomly-generated key (e.g. `openssl rand -base64 32`).
func decodeSigningKey(text string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(text))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("BOOST_TICKET_SIGNING_KEY must be base64 for exactly 32 random bytes")
	}
	return decoded, nil
}

func newReorderBuffer() *reorderBuffer {
	return &reorderBuffer{
		expected: 1,
		pending:  map[uint64]pendingPacket{},
	}
}

func (r *reorderBuffer) push(seq uint64, payloads [][]byte) [][]byte {
	now := time.Now()
	r.resetIfSequenceRestarted(seq)
	if seq < r.expected {
		return nil
	}
	if seq == r.expected {
		r.expected++
		ready := append([][]byte{}, payloads...)
		ready = append(ready, r.drain(now)...)
		return ready
	}
	if _, exists := r.pending[seq]; !exists {
		r.pending[seq] = pendingPacket{payloads: copyPacketBatch(payloads), created: now}
	}
	return r.drain(now)
}

func (r *reorderBuffer) resetIfSequenceRestarted(seq uint64) {
	if seq > 0 && r.expected == 1 && len(r.pending) == 0 && seq > sequenceRestartGap {
		r.expected = seq
		return
	}
	if seq > 0 && r.expected > sequenceRestartGap && seq+sequenceRestartGap < r.expected {
		for key := range r.pending {
			delete(r.pending, key)
		}
		r.expected = seq
	}
}

func (r *reorderBuffer) flushExpired() [][]byte {
	if len(r.pending) == 0 {
		return nil
	}
	now := time.Now()
	firstSeq := uint64(0)
	var first pendingPacket
	for seq, packet := range r.pending {
		if firstSeq == 0 || seq < firstSeq {
			firstSeq = seq
			first = packet
		}
	}
	if len(r.pending) > reorderMaxPackets || now.Sub(first.created) > reorderWait {
		r.expected = firstSeq
		return r.drain(now)
	}
	return nil
}

func (r *reorderBuffer) drain(now time.Time) [][]byte {
	ready := make([][]byte, 0, 8)
	for {
		packet, ok := r.pending[r.expected]
		if !ok {
			break
		}
		delete(r.pending, r.expected)
		ready = append(ready, packet.payloads...)
		r.expected++
	}
	if len(ready) == 0 && len(r.pending) > 0 {
		firstSeq := uint64(0)
		var first pendingPacket
		for seq, packet := range r.pending {
			if firstSeq == 0 || seq < firstSeq {
				firstSeq = seq
				first = packet
			}
		}
		if len(r.pending) > reorderMaxPackets || now.Sub(first.created) > reorderWait {
			r.expected = firstSeq
			return r.drain(now)
		}
	}
	return ready
}

func copyPacketBatch(payloads [][]byte) [][]byte {
	out := make([][]byte, 0, len(payloads))
	for _, payload := range payloads {
		packet := make([]byte, len(payload))
		copy(packet, payload)
		out = append(out, packet)
	}
	return out
}

// commandStep is one setup command to run against the freshly created TUN
// interface. Everything is required to succeed except where explicitly
// marked optional.
type commandStep struct {
	args     []string
	optional bool
}

// tunSetupCommands lists the interface setup commands for name/mtu/cidr.
// tc's fq qdisc is explicitly best-effort: some kernels/containers lack the
// qdisc or the permission to replace it, and failing to enable it does not
// leave the interface down or misconfigured, unlike a failed address/link/
// queue-length command, which does.
func tunSetupCommands(name string, mtu int, cidr string) []commandStep {
	return []commandStep{
		{args: []string{"ip", "addr", "replace", cidr, "dev", name}},
		{args: []string{"ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"}},
		{args: []string{"ip", "link", "set", "dev", name, "txqueuelen", "10000"}},
		{args: []string{"tc", "qdisc", "replace", "dev", name, "root", "fq"}, optional: true},
	}
}

// applyTunSetupCommands runs each step with runner, aborting on the first
// failing required step. Optional step failures are logged and tolerated.
func applyTunSetupCommands(steps []commandStep, runner func(name string, args ...string) error) error {
	for _, step := range steps {
		err := runner(step.args[0], step.args[1:]...)
		if err == nil {
			continue
		}
		if step.optional {
			fmt.Fprintf(os.Stderr, "wins-boostd-v2: warning: optional setup step failed, continuing: %v\n", err)
			continue
		}
		return err
	}
	return nil
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func openTun(name string, mtu int, cidr string) (*os.File, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifr [40]byte
	copy(ifr[:16], []byte(name))
	*(*uint16)(unsafe.Pointer(&ifr[16])) = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		file.Close()
		return nil, errno
	}

	if err := applyTunSetupCommands(tunSetupCommands(name, mtu, cidr), run); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// dropPrivileges relinquishes root after TUN/socket setup is complete: the
// TUN file descriptor and UDP socket are already open, so nothing done for
// the rest of the process's life needs elevated privileges. Group is
// dropped before user (a process can still change its gid as long as it is
// still privileged; not the other way around), and supplementary groups are
// cleared first. syscall.AllThreadsSyscall is used (rather than
// syscall.Setuid/Setgid) because Go's runtime is multi-threaded and a plain
// setuid(2)/setgid(2) only affects the calling OS thread on Linux.
//
// H-6: cfg.runAsUID/runAsGID used to be gated behind "> 0" checks that
// silently skipped the corresponding setuid/setgid call entirely for a
// zero or negative configured ID - so a config that (accidentally or
// otherwise) left BOOST_RUN_AS_UID/GID at 0 dropped nothing and the daemon
// kept running as root. dropPrivileges now refuses outright to treat a
// non-positive target ID as "nothing to do"; dropPrivilegesOrFail also
// independently re-verifies after this returns that neither the effective
// UID nor GID is still 0, so a target ID of 0 is rejected in two
// independent places, not just relied on here.
func dropPrivileges(cfg envConfig) error {
	if os.Getuid() != 0 {
		return nil
	}
	if cfg.runAsUID <= 0 || cfg.runAsGID <= 0 {
		return fmt.Errorf("refusing to drop privileges to non-positive uid=%d gid=%d", cfg.runAsUID, cfg.runAsGID)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETGROUPS, 0, 0, 0); errno != 0 {
		return fmt.Errorf("setgroups: %w", errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETGID, uintptr(cfg.runAsGID), 0, 0); errno != 0 {
		return fmt.Errorf("setgid(%d): %w", cfg.runAsGID, errno)
	}
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_SETUID, uintptr(cfg.runAsUID), 0, 0); errno != 0 {
		return fmt.Errorf("setuid(%d): %w", cfg.runAsUID, errno)
	}
	return nil
}

// dropPrivilegesOrFail validates cfg's target UID/GID, runs drop (in
// production, always dropPrivileges), and independently re-checks via
// geteuid/getegid (in production, always os.Geteuid/os.Getegid) that
// neither the effective UID nor GID is still 0 afterward - fail closed at
// every step rather than merely logging (H-6). It takes drop/geteuid/getegid
// as parameters, rather than calling dropPrivileges/os.Geteuid/os.Getegid
// directly, purely so tests can exercise every failure path (bad config, a
// failing drop, and a drop that reports success but did not actually take
// effect) without needing to be root or mutate the test process's real
// privileges.
func dropPrivilegesOrFail(cfg envConfig, drop func(envConfig) error, geteuid, getegid func() int) error {
	if cfg.runAsUID <= 0 || cfg.runAsGID <= 0 {
		return errors.New("BOOST_RUN_AS_UID/GID must be non-root positive IDs")
	}
	if err := drop(cfg); err != nil {
		return fmt.Errorf("drop privileges: %w", err)
	}
	if geteuid() == 0 || getegid() == 0 {
		return errors.New("privilege drop did not take effect")
	}
	return nil
}

func newBoostServer() (*boostServer, error) {
	env := mergedEnv()
	cfg := loadConfig(env)

	signingKey, err := decodeSigningKey(cfg.ticketSigningKeyText)
	if err != nil {
		return nil, err
	}

	tun, err := openTun(cfg.iface, cfg.mtu, cfg.serverCIDR)
	if err != nil {
		return nil, err
	}
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: cfg.port}
	udp, err := net.ListenUDP("udp4", addr)
	if err != nil {
		tun.Close()
		return nil, err
	}
	_ = udp.SetReadBuffer(8 * 1024 * 1024)
	_ = udp.SetWriteBuffer(8 * 1024 * 1024)

	// H-6: a privilege-drop failure used to be logged as a warning and
	// otherwise ignored, leaving a UDP/TUN network daemon quietly running
	// as root. Fail closed instead: close the sockets already opened above
	// and refuse to start.
	if err := dropPrivilegesOrFail(cfg, dropPrivileges, os.Geteuid, os.Getegid); err != nil {
		udp.Close()
		tun.Close()
		return nil, fmt.Errorf("wins-boostd-v2: %w", err)
	}

	server := &boostServer{
		cfg:              cfg,
		ticketSigningKey: signingKey,
		udp:              udp,
		tun:              tun,
		sessions:         newSessionTable(),
		txBatches:        map[string]*txBatch{},
		packetPool: sync.Pool{
			New: func() any {
				buffer := make([]byte, maxPacketSize)
				return &buffer
			},
		},
		framePool: sync.Pool{
			New: func() any {
				buffer := make([]byte, 0, authFrameHeaderLen+maxPacketSize+aeadOverhead)
				return &buffer
			},
		},
		probeWorkers:       make(chan struct{}, maxProbeWorkers),
		globalProbeLimiter: newTokenBucket(probeGlobalRateBytesPerSec, probeGlobalBurstBytes),
	}
	return server, nil
}

func (s *boostServer) getPacketBuffer() *[]byte {
	buffer := s.packetPool.Get().(*[]byte)
	if cap(*buffer) < maxPacketSize {
		next := make([]byte, maxPacketSize)
		return &next
	}
	*buffer = (*buffer)[:maxPacketSize]
	return buffer
}

func (s *boostServer) releasePacketBuffer(buffer *[]byte) {
	if buffer == nil {
		return
	}
	*buffer = (*buffer)[:maxPacketSize]
	s.packetPool.Put(buffer)
}

func (s *boostServer) getFrameBuffer() *[]byte {
	buffer := s.framePool.Get().(*[]byte)
	if cap(*buffer) < authFrameHeaderLen+maxPacketSize+aeadOverhead {
		next := make([]byte, 0, authFrameHeaderLen+maxPacketSize+aeadOverhead)
		return &next
	}
	*buffer = (*buffer)[:0]
	return buffer
}

func (s *boostServer) releaseFrameBuffer(buffer *[]byte) {
	if buffer == nil {
		return
	}
	*buffer = (*buffer)[:0]
	s.framePool.Put(buffer)
}

func secondaryPathCanCarryData(path *pathState, pathRTT int64, wifiRTT int64, wifiBps uint64, allowExploration bool) bool {
	if path == nil {
		return false
	}
	if wifiRTT <= 0 {
		wifiRTT = defaultPathRTT
	}
	if pathRTT <= 0 {
		pathRTT = defaultPathRTT
	}
	rttCeiling := wifiRTT + secondaryRTTHeadroom
	scaledCeiling := (wifiRTT * secondaryRTTMultiplierN) / secondaryRTTMultiplierD
	if scaledCeiling > rttCeiling {
		rttCeiling = scaledCeiling
	}
	if pathRTT > rttCeiling || pathRTT > secondaryAbsoluteRTT {
		return false
	}
	pathBps := path.reportedBps
	if pathBps > 0 {
		if pathBps >= minProvenSecondaryBps {
			return true
		}
		return allowExploration && path.chosenBytes < secondaryExploreMaxBytes
	}
	return allowExploration && path.chosenBytes < secondaryExploreMaxBytes
}

func secondaryPathCanStripeFlow(path *pathState, pathRTT int64, wifiRTT int64, wifiBps uint64, allowExploration bool) bool {
	if !secondaryPathCanCarryData(path, pathRTT, wifiRTT, wifiBps, allowExploration) {
		return false
	}
	if wifiRTT <= 0 {
		wifiRTT = defaultPathRTT
	}
	if pathRTT <= 0 {
		pathRTT = defaultPathRTT
	}
	rttCeiling := wifiRTT + stripeRTTHeadroom
	scaledCeiling := (wifiRTT * stripeRTTMultiplierN) / stripeRTTMultiplierD
	if scaledCeiling > rttCeiling {
		rttCeiling = scaledCeiling
	}
	if pathRTT > rttCeiling || pathRTT > stripeAbsoluteRTT {
		return false
	}
	if path.reportedBps > 0 {
		if path.reportedBps >= minStripeSecondaryBps {
			return true
		}
		return allowExploration && path.reportedBps >= minProvenSecondaryBps && path.chosenBytes < stripeExploreMaxBytes
	}
	return allowExploration && path.chosenBytes < stripeExploreMaxBytes/2
}

// choosePath runs the multipath scheduler for one outbound IP packet bound
// for sess, picking which authenticated path (pathID/endpoint) should carry
// it. The weighted-fair-queuing-style heuristics below are unrelated to
// authentication (they only ever operate on paths that authenticateAndOpen
// already bound to this specific session) and are unchanged from the prior
// implementation, just re-scoped from a self-asserted-IP client lookup to an
// authenticated session.
func (sess *authenticatedSession) choosePath(packet []byte) (uint8, *net.UDPAddr, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	now := time.Now()
	packetBytes := len(packet)
	candidates := make([]struct {
		id           uint8
		addr         *net.UDPAddr
		path         *pathState
		rttMs        int64
		effectiveBps uint64
		weight       uint64
		arrival      time.Time
		nextFinish   time.Time
	}, 0, len(sess.paths))
	bestRTT := int64(0)
	for id, path := range sess.paths {
		if path.addr != nil && path.failures < 8 && now.Sub(path.lastSeen) < 20*time.Second {
			if now.Sub(path.lastDecay) > time.Second {
				path.sentBytes = (path.sentBytes * 7) / 10
				if path.chosenBytes > secondaryMinProbeBytes {
					path.chosenBytes = (path.chosenBytes * 95) / 100
				}
				if now.Sub(path.lastSeen) > 3*time.Second && path.reportedBps > defaultPathBps {
					path.reportedBps = ((path.reportedBps * 7) / 10)
					if isWiFiPathID(id) && path.capacityFloorBps > 0 && path.reportedBps < path.capacityFloorBps {
						path.reportedBps = path.capacityFloorBps
					}
				}
				path.lastDecay = now
			}
			rttMs := path.rttMs
			if rttMs <= 0 {
				rttMs = defaultPathRTT
			}
			if bestRTT == 0 || rttMs < bestRTT {
				bestRTT = rttMs
			}
			candidates = append(candidates, struct {
				id           uint8
				addr         *net.UDPAddr
				path         *pathState
				rttMs        int64
				effectiveBps uint64
				weight       uint64
				arrival      time.Time
				nextFinish   time.Time
			}{id: id, addr: path.addr, path: path, rttMs: rttMs})
		}
	}
	if len(candidates) == 0 {
		return 0, nil, false
	}

	wifiIndex := -1
	for index, candidate := range candidates {
		if candidate.id == wifiPathID {
			wifiIndex = index
			break
		}
	}
	if singleFlowStriping && wifiIndex >= 0 && len(candidates) > 1 {
		wifi := candidates[wifiIndex]
		wifiBps := wifi.path.reportedBps
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if candidate.id == wifiPathID ||
				secondaryPathCanCarryData(candidate.path, candidate.rttMs, wifi.rttMs, wifiBps, true) {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) == 0 {
			filtered = append(filtered, wifi)
		}
		candidates = filtered
		bestRTT = 0
		wifiIndex = -1
		for index, candidate := range candidates {
			if bestRTT == 0 || candidate.rttMs < bestRTT {
				bestRTT = candidate.rttMs
			}
			if candidate.id == wifiPathID {
				wifiIndex = index
			}
		}
	}
	if len(candidates) == 1 {
		selected := candidates[0]
		increment := uint64(packetBytes)
		if increment == 0 {
			increment = 1
		}
		selected.path.sentBytes += increment
		selected.path.chosenPkts++
		selected.path.chosenBytes += increment
		sess.logPathMetricsLocked(now)
		return selected.id, selected.addr, true
	}
	key := flowKey(packet)
	if key != 0 {
		pruneFlowCache(sess.flows, now)
	}
	flowBondingPossible := false
	if wifiIndex >= 0 && len(candidates) > 1 {
		wifi := candidates[wifiIndex]
		wifiBps := wifi.path.reportedBps
		if wifiBps < 512_000 {
			wifiBps = defaultPathBps
		}
		for _, candidate := range candidates {
			if candidate.id == wifiPathID {
				continue
			}
			if secondaryPathCanStripeFlow(candidate.path, candidate.rttMs, wifi.rttMs, wifiBps, true) {
				flowBondingPossible = true
				break
			}
		}
	}
	flowBondingAllowed := false
	if key != 0 && flowBondingPossible {
		activeBondedSlots := activeBondedFlowSlots(sess.flows, now)
		if cached, ok := sess.flows[key]; ok {
			_, alreadyBonded := activeBondedSlots[key]
			flowBondingAllowed = len(activeBondedSlots) < flowBondActiveLimit ||
				alreadyBonded ||
				(cached.bonded && cached.bytes < flowBondSlotMinBytes)
		} else {
			flowBondingAllowed = len(activeBondedSlots) < flowBondActiveLimit
		}
	}
	if key != 0 && !flowBondingAllowed {
		if cached, ok := sess.flows[key]; ok {
			for _, candidate := range candidates {
				if candidate.id == cached.pathID {
					increment := uint64(packetBytes)
					if increment == 0 {
						increment = 1
					}
					candidate.path.sentBytes += increment
					candidate.path.chosenPkts++
					candidate.path.chosenBytes += increment
					cached.lastUsed = now
					cached.bytes += increment
					cached.bonded = false
					sess.flows[key] = cached
					sess.logPathMetricsLocked(now)
					return candidate.id, candidate.addr, true
				}
			}
		}
	}

	bondWifiBps := uint64(0)
	if flowBondingAllowed && wifiIndex >= 0 {
		bondWifiBps = candidates[wifiIndex].path.reportedBps
		if bondWifiBps < defaultPathBps {
			bondWifiBps = defaultPathBps
		}
	}
	selectedIndex := -1
	selectedWeight := uint64(0)
	usedBurst := false
	var cachedForBurst flowChoice
	if flowBondingAllowed && key != 0 {
		if cached, ok := sess.flows[key]; ok && cached.burstRemaining > 0 {
			for index, candidate := range candidates {
				if candidate.id == cached.burstPathID {
					selectedIndex = index
					cachedForBurst = cached
					usedBurst = true
					break
				}
			}
		}
	}
	if selectedIndex == -1 && !flowBondingAllowed && key == 0 {
		if wifiIndex >= 0 {
			wifi := candidates[wifiIndex]
			wifiBps := wifi.path.reportedBps
			if wifiBps < 512_000 {
				wifiBps = defaultPathBps
			}
			provenBetter := false
			for _, candidate := range candidates {
				if candidate.id == wifiPathID {
					continue
				}
				capacity := candidate.path.reportedBps
				if capacity >= minProvenSecondaryBps &&
					capacity > (wifiBps*11)/10 &&
					candidate.rttMs <= wifi.rttMs+secondaryRTTHeadroom {
					provenBetter = true
					break
				}
			}
			if !provenBetter {
				selectedIndex = wifiIndex
			}
		}
	}
	if selectedIndex == -1 {
		for index, candidate := range candidates {
			capacity := candidate.path.reportedBps
			if flowBondingAllowed && candidate.id != wifiPathID {
				if candidate.path.chosenBytes < secondaryMinProbeBytes {
					if capacity < stripeExplorationBps {
						capacity = stripeExplorationBps
					}
				} else if capacity >= minStripeSecondaryBps {
					secondaryTarget := singleFlowSecondaryMin
					if bondWifiBps > 0 {
						wifiShare := bondWifiBps / singleFlowSecondaryDiv
						if wifiShare > secondaryTarget {
							secondaryTarget = wifiShare
						}
					}
					if secondaryTarget > singleFlowSecondaryMax {
						secondaryTarget = singleFlowSecondaryMax
					}
					if capacity > 0 && secondaryTarget > (capacity*5)/4 {
						secondaryTarget = (capacity * 5) / 4
					}
					if secondaryTarget > capacity {
						capacity = secondaryTarget
					}
				} else if capacity < singleFlowSecondaryMin {
					capacity = singleFlowSecondaryMin
				}
			} else if capacity < 512_000 {
				capacity = defaultPathBps
			}
			rttPenalty := uint64(1000)
			if candidate.rttMs > bestRTT {
				rttPenalty += uint64(candidate.rttMs-bestRTT) * 20
			}
			effectiveBps := (capacity * 1000) / rttPenalty
			if effectiveBps < 256_000 {
				effectiveBps = 256_000
			}
			candidates[index].effectiveBps = effectiveBps
			base := candidate.path.virtualSendFinish
			if base.IsZero() || base.Before(now) || base.Sub(now) > schedulerMaxVirtualLag {
				base = now
			}
			serialization := time.Duration((uint64(packetBytes) * uint64(time.Second)) / effectiveBps)
			nextFinish := base.Add(serialization)
			arrival := nextFinish.Add(time.Duration(candidate.rttMs/2) * time.Millisecond)
			candidates[index].nextFinish = nextFinish
			candidates[index].arrival = arrival
			weight := (candidate.path.sentBytes * 1_000_000) / effectiveBps
			candidates[index].weight = weight
			if flowBondingAllowed {
				if selectedIndex == -1 || weight < selectedWeight ||
					(weight == selectedWeight && effectiveBps > candidates[selectedIndex].effectiveBps) {
					selectedIndex = index
					selectedWeight = weight
				}
			} else if selectedIndex == -1 || weight < selectedWeight ||
				(weight == selectedWeight && effectiveBps > candidates[selectedIndex].effectiveBps) {
				selectedIndex = index
				selectedWeight = weight
			}
		}
	}
	selected := candidates[selectedIndex]
	increment := uint64(packetBytes)
	if increment == 0 {
		increment = 1
	}
	selected.path.sentBytes += increment
	selected.path.chosenPkts++
	selected.path.chosenBytes += increment
	if !candidates[selectedIndex].nextFinish.IsZero() {
		selected.path.virtualSendFinish = candidates[selectedIndex].nextFinish
	}
	if key != 0 {
		cached := sess.flows[key]
		cached.pathID = selected.id
		cached.lastUsed = now
		cached.bytes += increment
		cached.bonded = flowBondingAllowed
		if flowBondingAllowed {
			cached.burstPathID = selected.id
			if usedBurst {
				cached.burstRemaining = cachedForBurst.burstRemaining - 1
				if cached.burstRemaining < 0 {
					cached.burstRemaining = 0
				}
			} else {
				cached.burstRemaining = burstPacketsForPath(selected.id) - 1
			}
		} else {
			cached.burstPathID = 0
			cached.burstRemaining = 0
		}
		sess.flows[key] = cached
		pruneFlowCache(sess.flows, now)
	}
	sess.logPathMetricsLocked(now)
	return selected.id, selected.addr, true
}

func burstPacketsForPath(pathID uint8) int {
	if isWiFiPathID(pathID) {
		return wifiBurstPackets
	}
	return secondaryBurstPackets
}

func isWiFiPathID(pathID uint8) bool {
	return pathID == wifiPathID ||
		(pathID >= wifiSubpathBaseID && pathID < wifiSubpathBaseID+wifiSubpathCount)
}

func txBatchKey(keyID uint64, pathID uint8, addr *net.UDPAddr) string {
	return strconv.FormatUint(keyID, 10) + "|" + strconv.Itoa(int(pathID)) + "|" + addr.String()
}

func (s *boostServer) sendTunFrame(sess *authenticatedSession, pathID uint8, addr *net.UDPAddr, payload []byte) {
	if len(payload) == 0 {
		return
	}
	frameBuffer := s.getFrameBuffer()
	defer s.releaseFrameBuffer(frameBuffer)
	frame := sess.sealFrame(typeData, pathID, sess.nextTxSeq(), payload, *frameBuffer)
	if _, err := s.udp.WriteToUDP(frame, addr); err != nil {
		sess.markPathFailure(pathID)
	}
}

func (s *boostServer) queueTunBatch(sess *authenticatedSession, pathID uint8, addr *net.UDPAddr, packet []byte) {
	if len(packet) > txBatchMaxPacketBytes || len(packet)+2 > txBatchMaxPayloadBytes {
		s.sendTunFrame(sess, pathID, addr, packet)
		return
	}
	copyPacket := make([]byte, len(packet))
	copy(copyPacket, packet)
	key := txBatchKey(sess.keyID, pathID, addr)
	var flush *txBatch
	s.txBatchMu.Lock()
	batch := s.txBatches[key]
	if batch == nil {
		batch = &txBatch{key: key, sess: sess, pathID: pathID, addr: cloneUDPAddr(addr)}
		s.txBatches[key] = batch
		batch.timer = time.AfterFunc(txBatchFlushDelay, func() {
			s.flushTunBatch(key)
		})
	}
	projectedBytes := batch.bytes + len(copyPacket) + 2
	if len(batch.packets) > 0 && projectedBytes > txBatchMaxPayloadBytes {
		delete(s.txBatches, key)
		if batch.timer != nil {
			batch.timer.Stop()
		}
		flush = batch
		batch = &txBatch{key: key, sess: sess, pathID: pathID, addr: cloneUDPAddr(addr)}
		s.txBatches[key] = batch
		batch.timer = time.AfterFunc(txBatchFlushDelay, func() {
			s.flushTunBatch(key)
		})
	}
	batch.packets = append(batch.packets, copyPacket)
	batch.bytes += len(copyPacket) + 2
	if len(batch.packets) >= txBatchMaxPackets || batch.bytes >= txBatchMaxPayloadBytes {
		delete(s.txBatches, key)
		if batch.timer != nil {
			batch.timer.Stop()
		}
		flush = batch
	}
	s.txBatchMu.Unlock()
	if flush != nil {
		s.sendTunBatch(flush)
	}
}

func (s *boostServer) flushTunBatch(key string) {
	s.txBatchMu.Lock()
	batch := s.txBatches[key]
	if batch != nil {
		delete(s.txBatches, key)
	}
	s.txBatchMu.Unlock()
	if batch != nil {
		s.sendTunBatch(batch)
	}
}

func (s *boostServer) sendTunBatch(batch *txBatch) {
	if batch == nil || len(batch.packets) == 0 || batch.addr == nil {
		return
	}
	payload := wrapDataBatchPayload(batch.packets)
	s.sendTunFrame(batch.sess, batch.pathID, batch.addr, payload)
}

func pruneFlowCache(flows map[uint64]flowChoice, now time.Time) {
	if len(flows) <= maxFlowCache {
		for key, choice := range flows {
			if now.Sub(choice.lastUsed) > flowCacheTTL {
				delete(flows, key)
			}
		}
		return
	}
	for key, choice := range flows {
		if now.Sub(choice.lastUsed) > flowCacheTTL {
			delete(flows, key)
		}
	}
	if len(flows) <= maxFlowCache {
		return
	}
	type oldFlow struct {
		key      uint64
		lastUsed time.Time
	}
	oldest := make([]oldFlow, 0, len(flows))
	for key, choice := range flows {
		oldest = append(oldest, oldFlow{key: key, lastUsed: choice.lastUsed})
	}
	sort.Slice(oldest, func(i, j int) bool {
		return oldest[i].lastUsed.Before(oldest[j].lastUsed)
	})
	for i := 0; i < len(oldest) && len(flows) > maxFlowCache; i++ {
		delete(flows, oldest[i].key)
	}
}

func activeBondedFlowSlots(flows map[uint64]flowChoice, now time.Time) map[uint64]struct{} {
	selected := make(map[uint64]struct{}, flowBondActiveLimit)
	for key, choice := range flows {
		if !choice.bonded ||
			choice.bytes < flowBondSlotMinBytes ||
			now.Sub(choice.lastUsed) > flowBondActiveWindow {
			continue
		}
		selected[key] = struct{}{}
		if len(selected) >= flowBondActiveLimit {
			break
		}
	}
	return selected
}

func pushFlowOrderedPackets(sess *authenticatedSession, frameSeq uint64, packets [][]byte, now time.Time) [][]byte {
	if len(packets) == 0 {
		return nil
	}
	ready := make([][]byte, 0, len(packets))
	for index, packet := range packets {
		key := flowKey(packet)
		if key == 0 {
			ready = append(ready, packet)
			continue
		}
		buffer := sess.flowRx[key]
		if buffer == nil {
			buffer = newReorderBuffer()
			sess.flowRx[key] = buffer
		}
		sess.flowAt[key] = now
		orderedSeq := (frameSeq * flowOrderSequenceFactor) + uint64(index) + 1
		ready = append(ready, buffer.push(orderedSeq, [][]byte{packet})...)
	}
	pruneFlowReorderBuffers(sess, now)
	return ready
}

func flushFlowOrderedPackets(sess *authenticatedSession, now time.Time) [][]byte {
	ready := make([][]byte, 0)
	for key, buffer := range sess.flowRx {
		ready = append(ready, buffer.flushExpired()...)
		if now.Sub(sess.flowAt[key]) > flowReorderTTL {
			delete(sess.flowRx, key)
			delete(sess.flowAt, key)
		}
	}
	pruneFlowReorderBuffers(sess, now)
	return ready
}

func pruneFlowReorderBuffers(sess *authenticatedSession, now time.Time) {
	for key, seen := range sess.flowAt {
		if now.Sub(seen) > flowReorderTTL {
			delete(sess.flowAt, key)
			delete(sess.flowRx, key)
		}
	}
	if len(sess.flowRx) <= maxFlowCache {
		return
	}
	type oldFlow struct {
		key  uint64
		seen time.Time
	}
	oldest := make([]oldFlow, 0, len(sess.flowAt))
	for key, seen := range sess.flowAt {
		oldest = append(oldest, oldFlow{key: key, seen: seen})
	}
	sort.Slice(oldest, func(i, j int) bool {
		return oldest[i].seen.Before(oldest[j].seen)
	})
	for i := 0; i < len(oldest) && len(sess.flowRx) > maxFlowCache; i++ {
		delete(sess.flowRx, oldest[i].key)
		delete(sess.flowAt, oldest[i].key)
	}
}

func flowKey(packet []byte) uint64 {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0
	}
	proto := packet[9]
	src := binary.BigEndian.Uint32(packet[12:16])
	dst := binary.BigEndian.Uint32(packet[16:20])
	if (proto == 6 || proto == 17) && len(packet) >= ihl+4 {
		srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
		return canonicalFlowKey(proto, src, srcPort, dst, dstPort)
	}
	return canonicalFlowKey(proto, src, 0, dst, 0)
}

func canonicalFlowKey(proto byte, src uint32, srcPort uint16, dst uint32, dstPort uint16) uint64 {
	leftIP, leftPort := src, srcPort
	rightIP, rightPort := dst, dstPort
	if leftIP > rightIP || (leftIP == rightIP && leftPort > rightPort) {
		leftIP, leftPort = dst, dstPort
		rightIP, rightPort = src, srcPort
	}
	hash := uint64(1469598103934665603)
	hash = mixFlowHash(hash, uint64(proto))
	hash = mixFlowHash(hash, uint64(leftIP))
	hash = mixFlowHash(hash, uint64(leftPort))
	hash = mixFlowHash(hash, uint64(rightIP))
	hash = mixFlowHash(hash, uint64(rightPort))
	if hash == 0 {
		return 1
	}
	return hash
}

func mixFlowHash(hash uint64, value uint64) uint64 {
	const prime = uint64(1099511628211)
	for shift := 56; shift >= 0; shift -= 8 {
		hash ^= (value >> shift) & 0xff
		hash *= prime
	}
	return hash
}

// wrapDataBatchPayload packs multiple IP packets into one v3 data payload.
// A single packet is sent as-is (no wrapper) since the outer frame already
// carries authenticated session/sequence context; there is no need for an
// inner per-packet identity prefix the way the retired v2 format had one.
func wrapDataBatchPayload(packets [][]byte) []byte {
	if len(packets) <= 1 {
		if len(packets) == 1 {
			return packets[0]
		}
		return nil
	}
	size := dataBatchHeaderLen
	for _, packet := range packets {
		size += 2 + len(packet)
	}
	payload := make([]byte, size)
	copy(payload[0:4], dataBatchMagic)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(packets)))
	offset := dataBatchHeaderLen
	for _, packet := range packets {
		binary.BigEndian.PutUint16(payload[offset:offset+2], uint16(len(packet)))
		offset += 2
		copy(payload[offset:offset+len(packet)], packet)
		offset += len(packet)
	}
	return payload
}

func unwrapDataPayloads(payload []byte) ([][]byte, bool) {
	if len(payload) >= dataBatchHeaderLen && string(payload[0:4]) == dataBatchMagic {
		count := int(binary.BigEndian.Uint16(payload[4:6]))
		if count <= 0 || count > txBatchMaxPackets {
			return nil, false
		}
		offset := dataBatchHeaderLen
		packets := make([][]byte, 0, count)
		for i := 0; i < count; i++ {
			if offset+2 > len(payload) {
				return nil, false
			}
			length := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
			offset += 2
			if length < 20 || offset+length > len(payload) {
				return nil, false
			}
			packet := payload[offset : offset+length]
			if packet[0]>>4 != 4 {
				return nil, false
			}
			packets = append(packets, packet)
			offset += length
		}
		return packets, true
	}
	if len(payload) < 20 || payload[0]>>4 != 4 {
		return nil, false
	}
	return [][]byte{payload}, true
}

// bytesEqual4 compares a variable-length byte slice (e.g. bytes sliced out
// of an IPv4 header) against a fixed 4-byte array without allocating.
func bytesEqual4(b []byte, ip [4]byte) bool {
	return len(b) == 4 && b[0] == ip[0] && b[1] == ip[1] && b[2] == ip[2] && b[3] == ip[3]
}

// packetsMatchAssignedIP reports whether every packet in the batch claims a
// source IPv4 address equal to assignedIP. This is the H-10 anti-spoofing
// check: a session may only ever tunnel traffic sourced from the inner IP
// its own ticket assigned it, so one authenticated client cannot impersonate
// another by forging the source address inside its own tunnel payload.
func packetsMatchAssignedIP(packets [][]byte, assignedIP [4]byte) bool {
	for _, packet := range packets {
		if len(packet) < 20 || packet[0]>>4 != 4 || !bytesEqual4(packet[12:16], assignedIP) {
			return false
		}
	}
	return true
}

func parsePingPayload(payload []byte) (rttMs int64, downBps uint64, supportsBatch bool) {
	if len(payload) < pingPayloadLen {
		return 0, 0, false
	}
	rttMs = clampRTT(int64(binary.BigEndian.Uint64(payload[0:8])))
	downBps = clampDownBps(binary.BigEndian.Uint64(payload[8:16]))
	flags := binary.BigEndian.Uint32(payload[16:20])
	magic := binary.BigEndian.Uint32(payload[20:24])
	supportsBatch = magic == clientFeatureMagic && flags&clientFeatureBatchTx != 0
	return
}

func clampRTT(value int64) int64 {
	if value < 1 {
		return 0
	}
	if value > 5000 {
		return 5000
	}
	return value
}

func clampDownBps(value uint64) uint64 {
	if value > 10_000_000_000 {
		return 10_000_000_000
	}
	return value
}

func probeRequest(payload []byte) (int, int) {
	desired := probeDefaultBytes
	chunk := probeDefaultChunkBytes
	if len(payload) >= 4 {
		desired = int(binary.BigEndian.Uint32(payload[0:4]))
	}
	if len(payload) >= 8 {
		chunk = int(binary.BigEndian.Uint32(payload[4:8]))
	}
	if desired <= 0 || desired > maxProbeRequestBytes {
		desired = probeDefaultBytes
	}
	if chunk < 256 || chunk > probeMaxChunkBytes {
		chunk = probeMaxChunkBytes
	}
	return desired, chunk
}

func (s *boostServer) sendProbeData(sess *authenticatedSession, pathID uint8, addr *net.UDPAddr, desiredBytes, chunkBytes int) {
	if addr == nil || desiredBytes <= 0 {
		return
	}
	payload := make([]byte, chunkBytes)
	remaining := desiredBytes
	buf := make([]byte, 0, authFrameHeaderLen+chunkBytes+aeadOverhead)
	for remaining > 0 {
		n := chunkBytes
		if remaining < n {
			n = remaining
		}
		frame := sess.sealFrame(typeProbeData, pathID, sess.nextTxSeq(), payload[:n], buf)
		if _, err := s.udp.WriteToUDP(frame, addr); err != nil {
			return
		}
		remaining -= n
		if remaining%(chunkBytes*64) == 0 {
			runtime.Gosched()
		}
	}
}

// parseHandshakeInit validates a typeHandshakeInit body in isolation (no
// server/session-table dependency): the ticket must parse and verify, must
// not be expired or claim an implausibly distant expiry, the client's
// X25519 public key must be well-formed, and - the H-6 fix - the on-wire
// public key must exactly match the public key bound inside the ticket's
// HMAC-covered bytes. Without this last check, a network observer who
// copies a captured ticket verbatim could substitute their own public key
// and hijack the victim's session; binding the key inside the signed ticket
// means only whoever holds the private key matching tk.clientPub can ever
// complete a handshake with it. The comparison is constant-time so a
// network attacker cannot use response timing to learn anything about the
// bound key byte-by-byte.
func parseHandshakeInit(signingKey []byte, body []byte, now time.Time) (ticket, *ecdh.PublicKey, bool) {
	if len(body) != handshakeInitBodyLen {
		return ticket{}, nil, false
	}
	tk, ok := parseTicket(signingKey, body[:ticketFixedLen])
	if !ok {
		return ticket{}, nil, false
	}
	if now.After(tk.expires) || tk.expires.Sub(now) > maxTicketLifetime {
		return ticket{}, nil, false
	}
	clientPub, err := ecdh.X25519().NewPublicKey(body[ticketFixedLen:handshakeInitBodyLen])
	if err != nil {
		return ticket{}, nil, false
	}
	if subtle.ConstantTimeCompare(clientPub.Bytes(), tk.clientPub[:]) != 1 {
		return ticket{}, nil, false
	}
	return tk, clientPub, true
}

// buildHandshakeAck builds the server's reply to a handshake: its ephemeral
// public key in the clear (needed by the client before it can derive
// anything), followed by an AEAD-sealed confirmation under the just-derived
// session key that also proves the server completed the exchange correctly.
func buildHandshakeAck(sess *authenticatedSession, pathID uint8, serverPub *ecdh.PublicKey, expires time.Time) ([]byte, bool) {
	pubBytes := serverPub.Bytes()
	total := commonHeaderLen + len(pubBytes) + authFrameNonceLen + handshakeAckPlainLen + aeadOverhead
	header := make([]byte, commonHeaderLen, total)
	copy(header[0:4], magicV3)
	header[4] = typeHandshakeAck
	header[5] = pathID
	header = append(header, pubBytes...)

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, false
	}
	header = append(header, nonce[:]...)

	var plain [handshakeAckPlainLen]byte
	binary.BigEndian.PutUint64(plain[:], uint64(expires.Unix()))

	sealed := sess.aeadTx.Seal(header, nonce[:], plain[:], header)
	return sealed, true
}

// handleHandshakeInit processes a client's handshake attempt. Past ticket
// and on-wire-key verification (parseHandshakeInit), it enforces the H-6
// single-use guarantee via the jti replay cache before doing any ECDH work
// or touching the session table: only the first-ever use of a given jti is
// allowed to establish (or supersede) a session. Every subsequent use of
// that same jti - whether the legitimate client retrying because it never
// saw the original ack, or an attacker replaying a captured ticket verbatim
// - gets the original cached ack resent (if it's ready yet) and nothing
// else happens. This is safe to hand back to anyone who asks, including a
// replaying attacker: its meaningful content is AEAD-sealed under a session
// key derivable only from the legitimate client's private key, so a copy of
// it grants an attacker nothing beyond what was already visible on the wire
// when the original handshake happened.
func (s *boostServer) handleHandshakeInit(pathID uint8, body []byte, addr *net.UDPAddr) {
	now := time.Now()
	tk, clientPub, ok := parseHandshakeInit(s.ticketSigningKey, body, now)
	if !ok {
		return
	}

	if cachedAck, alreadyUsed := s.sessions.beginTicketUse(tk.jti, now); alreadyUsed {
		if cachedAck != nil {
			_, _ = s.udp.WriteToUDP(cachedAck, addr)
		}
		return
	}

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		s.sessions.abortTicketUse(tk.jti)
		return
	}
	shared, err := serverPriv.ECDH(clientPub)
	if err != nil {
		s.sessions.abortTicketUse(tk.jti)
		return
	}
	aeadRx, aeadTx, err := deriveDirectionalAEADs(shared, tk)
	if err != nil {
		s.sessions.abortTicketUse(tk.jti)
		return
	}

	sess, err := s.sessions.establish(tk, aeadRx, aeadTx, now)
	if err != nil {
		s.sessions.abortTicketUse(tk.jti)
		fmt.Fprintf(os.Stderr, "wins-boostd-v2: handshake rejected for client=%s: %v\n", hex.EncodeToString(tk.clientID[:]), err)
		return
	}
	sess.mu.Lock()
	sess.paths[pathID] = &pathState{addr: cloneUDPAddr(addr), lastSeen: now, lastDecay: now, rttMs: defaultPathRTT}
	sess.mu.Unlock()

	ack, ok := buildHandshakeAck(sess, pathID, serverPriv.PublicKey(), sess.expires)
	if !ok {
		s.sessions.abortTicketUse(tk.jti)
		return
	}
	s.sessions.finishTicketUse(tk.jti, ack, tk.expires)
	_, _ = s.udp.WriteToUDP(ack, addr)
}

func (s *boostServer) handlePing(sess *authenticatedSession, pathID uint8, payload []byte, addr *net.UDPAddr) {
	rttMs, downBps, batch := parsePingPayload(payload)
	sess.updatePathMetrics(pathID, rttMs, downBps, batch)
	frame := sess.sealFrame(typePong, pathID, sess.nextTxSeq(), payload, nil)
	if _, err := s.udp.WriteToUDP(frame, addr); err != nil {
		sess.markPathFailure(pathID)
	}
}

func (s *boostServer) handleProbe(sess *authenticatedSession, pathID uint8, payload []byte) {
	desired, chunk := probeRequest(payload)
	now := time.Now()
	if desired < 1 || desired > maxProbeRequestBytes {
		return
	}
	if !sess.probeLimiter.AllowN(now, desired) {
		return
	}
	if !s.globalProbeLimiter.AllowN(now, desired) {
		return
	}

	sess.mu.Lock()
	var addr *net.UDPAddr
	if path := sess.paths[pathID]; path != nil {
		addr = path.addr
	}
	sess.mu.Unlock()
	if addr == nil {
		return
	}

	select {
	case s.probeWorkers <- struct{}{}:
		go func() {
			defer func() { <-s.probeWorkers }()
			s.sendProbeData(sess, pathID, addr, desired, chunk)
		}()
	default:
		// Busy: silently drop rather than reveal server load to the caller.
	}
}

func (s *boostServer) handleData(sess *authenticatedSession, pathID uint8, frameSeq uint64, payload []byte) {
	ipPackets, ok := unwrapDataPayloads(payload)
	if !ok || len(ipPackets) == 0 {
		return
	}
	if !packetsMatchAssignedIP(ipPackets, sess.assignedIP) {
		return
	}

	now := time.Now()
	if !globalPacketReorder {
		if singleFlowStriping {
			sess.mu.Lock()
			ready := pushFlowOrderedPackets(sess, frameSeq, ipPackets, now)
			sess.mu.Unlock()
			s.writeTunPackets(ready)
		} else {
			s.writeTunPackets(ipPackets)
		}
		return
	}
	sess.mu.Lock()
	ready := sess.rx.push(frameSeq, ipPackets)
	sess.mu.Unlock()
	s.writeTunPackets(ready)
}

func (s *boostServer) writeTunPackets(packets [][]byte) {
	if len(packets) == 0 || s.tun == nil {
		return
	}
	s.tunWrite.Lock()
	defer s.tunWrite.Unlock()
	for _, packet := range packets {
		_, _ = s.tun.Write(packet)
	}
}

func (s *boostServer) handleUDPPacket(pkt udpPacket) {
	if pkt.release != nil {
		defer pkt.release()
	}
	if len(pkt.data) < commonHeaderLen || string(pkt.data[0:4]) != magicV3 {
		return
	}
	frameType := pkt.data[4]
	pathID := pkt.data[5]
	body := pkt.data[commonHeaderLen:]

	if frameType == typeHandshakeInit {
		s.handleHandshakeInit(pathID, body, pkt.addr)
		return
	}

	switch frameType {
	case typeData, typePing, typeProbe:
	default:
		// typePong/typeProbeData/typeHandshakeAck are server->client only;
		// anything else is unknown. Either way, drop defensively.
		return
	}
	if len(body) < authFrameHeaderLen-commonHeaderLen {
		return
	}
	seq := binary.BigEndian.Uint64(body[0:8])
	keyID := binary.BigEndian.Uint64(body[8:16])
	nonce := body[16:28]
	ciphertext := body[28:]
	aad := pkt.data[:authFrameAADLen]

	sess := s.sessions.lookup(keyID)
	if sess == nil {
		return
	}
	plain, ok := sess.authenticateAndOpen(pathID, seq, nonce, ciphertext, aad, pkt.addr, time.Now())
	if !ok {
		return
	}

	switch frameType {
	case typePing:
		s.handlePing(sess, pathID, plain, pkt.addr)
	case typeProbe:
		s.handleProbe(sess, pathID, plain)
	case typeData:
		s.handleData(sess, pathID, seq, plain)
	}
}

func (s *boostServer) handleTunPacket(packet tunPacket) {
	if packet.release != nil {
		defer packet.release()
	}
	if len(packet.data) < 20 || packet.data[0]>>4 != 4 {
		return
	}
	var dstIP [4]byte
	copy(dstIP[:], packet.data[16:20])
	sess := s.sessions.lookupByAssignedIP(dstIP)
	if sess == nil {
		return
	}
	pathID, addr, ok := sess.choosePath(packet.data)
	if !ok {
		return
	}

	sess.mu.Lock()
	batch := sess.batchTx
	sess.mu.Unlock()

	if batch {
		s.queueTunBatch(sess, pathID, addr, packet.data)
		return
	}
	frameBuffer := s.getFrameBuffer()
	defer s.releaseFrameBuffer(frameBuffer)
	frame := sess.sealFrame(typeData, pathID, sess.nextTxSeq(), packet.data, *frameBuffer)
	if _, err := s.udp.WriteToUDP(frame, addr); err != nil {
		sess.markPathFailure(pathID)
	}
}

func (s *boostServer) udpReadLoop(jobs chan<- udpPacket) {
	for {
		buffer := s.getPacketBuffer()
		n, addr, err := s.udp.ReadFromUDP(*buffer)
		if err != nil {
			s.releasePacketBuffer(buffer)
			continue
		}
		jobs <- udpPacket{
			data: (*buffer)[:n],
			addr: addr,
			release: func() {
				s.releasePacketBuffer(buffer)
			},
		}
	}
}

func (s *boostServer) tunReadLoop(jobs chan<- tunPacket) {
	for {
		buffer := s.getPacketBuffer()
		n, err := s.tun.Read(*buffer)
		if err != nil || n <= 0 {
			s.releasePacketBuffer(buffer)
			continue
		}
		jobs <- tunPacket{
			data: (*buffer)[:n],
			release: func() {
				s.releasePacketBuffer(buffer)
			},
		}
	}
}

// flushExpiredLoop periodically (a) flushes any reorder buffers that have
// waited long enough and (b) sweeps idle/expired sessions so memory stays
// bounded even without new handshakes (H-10 idle-session expiry).
func (s *boostServer) flushExpiredLoop() {
	reorderTicker := time.NewTicker(15 * time.Millisecond)
	defer reorderTicker.Stop()
	sweepTicker := time.NewTicker(sessionSweepInterval)
	defer sweepTicker.Stop()
	for {
		select {
		case <-reorderTicker.C:
			now := time.Now()
			for _, sess := range s.sessions.snapshot() {
				sess.mu.Lock()
				ready := sess.rx.flushExpired()
				if singleFlowStriping {
					ready = append(ready, flushFlowOrderedPackets(sess, now)...)
				}
				sess.mu.Unlock()
				s.writeTunPackets(ready)
			}
		case <-sweepTicker.C:
			s.sessions.sweep(time.Now())
		}
	}
}

func (s *boostServer) serve() {
	runtime.GOMAXPROCS(s.cfg.workers)
	udpJobs := make(chan udpPacket, s.cfg.workers*256)
	tunJobs := make(chan tunPacket, s.cfg.workers*256)

	udpReaders := s.cfg.workers / 2
	if udpReaders < 1 {
		udpReaders = 1
	}
	if udpReaders > 4 {
		udpReaders = 4
	}
	for i := 0; i < udpReaders; i++ {
		go s.udpReadLoop(udpJobs)
	}
	go s.tunReadLoop(tunJobs)
	go s.flushExpiredLoop()

	for i := 0; i < s.cfg.workers; i++ {
		go func() {
			for packet := range udpJobs {
				s.handleUDPPacket(packet)
			}
		}()
		go func() {
			for packet := range tunJobs {
				s.handleTunPacket(packet)
			}
		}()
	}

	fmt.Printf("wins-boostd-v2 %s listening udp/%d iface=%s workers=%d mtu=%d\n", boostVersion, s.cfg.port, s.cfg.iface, s.cfg.workers, s.cfg.mtu)
	select {}
}

func main() {
	server, err := newBoostServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wins-boostd-v2 startup failed: %v\n", err)
		os.Exit(1)
	}
	server.serve()
}
