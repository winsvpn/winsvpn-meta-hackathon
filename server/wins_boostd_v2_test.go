//go:build linux

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Shared test helpers
// -----------------------------------------------------------------------

func testSigningKey() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

// randomJTI returns a fresh random ticket ID, matching what a real
// control-plane ticket issuer must generate per-ticket (H-6: jti must never
// be reused across distinct tickets, even for the same client).
func randomJTI(t *testing.T) [ticketJTILen]byte {
	t.Helper()
	var jti [ticketJTILen]byte
	if _, err := rand.Read(jti[:]); err != nil {
		t.Fatalf("random jti: %v", err)
	}
	return jti
}

// clientPubArray adapts an *ecdh.PublicKey to the fixed-size array
// signTicket/ticketCanonicalBytes take for the ticket's bound client key.
func clientPubArray(pub *ecdh.PublicKey) [ticketClientPubLen]byte {
	var out [ticketClientPubLen]byte
	copy(out[:], pub.Bytes())
	return out
}

func newTestAEAD(t *testing.T, seed byte) cipher.AEAD {
	t.Helper()
	key := bytes.Repeat([]byte{seed}, sessionAEADKeyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

// newTestSession builds a fully-formed authenticatedSession for tests that
// exercise session-level logic (replay, endpoint binding, path caps)
// without going through a real ECDH handshake. aeadRx/aeadTx are distinct
// keys, mirroring the real directional-key design.
func newTestSession(t *testing.T, keyID uint64) *authenticatedSession {
	t.Helper()
	return &authenticatedSession{
		keyID:        keyID,
		aeadRx:       newTestAEAD(t, byte(keyID*2+1)),
		aeadTx:       newTestAEAD(t, byte(keyID*2+2)),
		replay:       &ReplayWindow{},
		nonceSalt:    [4]byte{1, 2, 3, 4},
		created:      time.Now(),
		expires:      time.Now().Add(time.Hour),
		lastSeen:     time.Now(),
		paths:        map[uint8]*pathState{},
		flows:        map[uint64]flowChoice{},
		rx:           newReorderBuffer(),
		flowRx:       map[uint64]*reorderBuffer{},
		flowAt:       map[uint64]time.Time{},
		probeLimiter: newTokenBucket(probeSessionRateBytesPerSec, probeSessionBurstBytes),
	}
}

// sealClientFrame builds a v3 auth frame (common header + seq/keyID/nonce +
// AEAD-sealed payload) exactly like sess.sealFrame does, but parameterized
// over which AEAD to use. This lets tests play either side of the
// directional-key design: pass a session's aeadRx to simulate a real
// client's outbound frame, or aeadTx to simulate the server's.
func sealClientFrame(aead cipher.AEAD, frameType, pathID uint8, seq, keyID uint64, payload []byte) []byte {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	frame := make([]byte, authFrameHeaderLen, authFrameHeaderLen+len(payload)+aeadOverhead)
	copy(frame[0:4], magicV3)
	frame[4] = frameType
	frame[5] = pathID
	binary.BigEndian.PutUint64(frame[6:14], seq)
	binary.BigEndian.PutUint64(frame[14:22], keyID)
	copy(frame[22:34], nonce[:])
	return aead.Seal(frame, nonce[:], payload, frame[:authFrameAADLen])
}

// splitAuthFrameBody extracts the pieces authenticateAndOpen expects from a
// frame built by sealClientFrame.
func splitAuthFrameBody(frame []byte) (nonce, ciphertext, aad []byte) {
	return frame[22:34], frame[34:], frame[:authFrameAADLen]
}

func buildIPv4Packet(src, dst [4]byte, extraLen int) []byte {
	packet := make([]byte, 20+extraLen)
	packet[0] = 0x45 // version 4, IHL 5 words
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64 // TTL
	packet[9] = 17 // UDP
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	return packet
}

func readUDPWithTimeout(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a UDP reply but got none: %v", err)
	}
	return buf[:n]
}

func assertNoUDPWithinTimeout(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("expected no reply, but got %d bytes", n)
	}
}

// newTestBoostServer builds a boostServer against a real loopback UDP
// socket (no TUN device, no root required), suitable for exercising
// handleUDPPacket/handleHandshakeInit/handlePing/handleProbe end to end.
func newTestBoostServer(t *testing.T, signingKey []byte) *boostServer {
	t.Helper()
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	t.Cleanup(func() { serverUDP.Close() })

	return &boostServer{
		ticketSigningKey: signingKey,
		udp:              serverUDP,
		sessions:         newSessionTable(),
		txBatches:        map[string]*txBatch{},
		packetPool: sync.Pool{
			New: func() any {
				b := make([]byte, maxPacketSize)
				return &b
			},
		},
		framePool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, authFrameHeaderLen+maxPacketSize+aeadOverhead)
				return &b
			},
		},
		probeWorkers:       make(chan struct{}, maxProbeWorkers),
		globalProbeLimiter: newTokenBucket(probeGlobalRateBytesPerSec, probeGlobalBurstBytes),
	}
}

func newTestClientUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// testClientHandshake plays the client side of a v3 handshake in tests: it
// holds a signed ticket's inputs and an ephemeral X25519 key pair, and can
// build the wire-format init packet and independently derive the same two
// directional AEAD keys the server derives, from the ack the server sends
// back. jti is fixed at construction time (mirroring one control-plane
// ticket issuance) so repeated calls to initPacket produce byte-identical
// packets, letting tests simulate exact retransmission/replay of the same
// ticket; use newTestClientHandshake again (a fresh call, not a second
// initPacket) to simulate a genuinely new ticket for the same client.
type testClientHandshake struct {
	clientID   [16]byte
	assignedIP [4]byte
	keyID      uint64
	expires    time.Time
	jti        [ticketJTILen]byte
	priv       *ecdh.PrivateKey
}

func newTestClientHandshake(t *testing.T, keyID uint64, assignedIP [4]byte) *testClientHandshake {
	t.Helper()
	var clientID [16]byte
	if _, err := rand.Read(clientID[:]); err != nil {
		t.Fatalf("random client id: %v", err)
	}
	return newTestClientHandshakeWithID(t, keyID, clientID, assignedIP)
}

// newTestClientHandshakeWithID is like newTestClientHandshake but lets the
// caller pin clientID, so a test can simulate the same client legitimately
// re-handshaking with a brand-new control-plane-issued ticket - a different
// keyID/jti/key pair under the same identity - which must still supersede
// that client's old session (unlike a replay of the same ticket, which must
// not).
func newTestClientHandshakeWithID(t *testing.T, keyID uint64, clientID [16]byte, assignedIP [4]byte) *testClientHandshake {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client ecdh key: %v", err)
	}
	return &testClientHandshake{
		clientID:   clientID,
		assignedIP: assignedIP,
		keyID:      keyID,
		expires:    time.Now().Add(time.Hour),
		jti:        randomJTI(t),
		priv:       priv,
	}
}

func (c *testClientHandshake) initPacket(signingKey []byte, pathID uint8) []byte {
	ticketBytes := signTicket(signingKey, c.clientID, c.assignedIP, c.keyID, c.expires, c.jti, clientPubArray(c.priv.PublicKey()))
	packet := make([]byte, commonHeaderLen, commonHeaderLen+handshakeInitBodyLen)
	copy(packet[0:4], magicV3)
	packet[4] = typeHandshakeInit
	packet[5] = pathID
	packet = append(packet, ticketBytes...)
	packet = append(packet, c.priv.PublicKey().Bytes()...)
	return packet
}

// initPacketWithForeignKey builds a handshake init packet using this
// client's genuine ticket bytes but a caller-supplied on-wire public key
// instead of c.priv's own - simulating an attacker who copied a captured
// ticket and attached their own key (H-6). The ticket itself still (validly)
// signs c.priv's public key, so this only diverges at the appended
// clientEphemeralPub field.
func (c *testClientHandshake) initPacketWithForeignKey(signingKey []byte, pathID uint8, foreignPub []byte) []byte {
	ticketBytes := signTicket(signingKey, c.clientID, c.assignedIP, c.keyID, c.expires, c.jti, clientPubArray(c.priv.PublicKey()))
	packet := make([]byte, commonHeaderLen, commonHeaderLen+handshakeInitBodyLen)
	copy(packet[0:4], magicV3)
	packet[4] = typeHandshakeInit
	packet[5] = pathID
	packet = append(packet, ticketBytes...)
	packet = append(packet, foreignPub...)
	return packet
}

// deriveFromAck parses a typeHandshakeAck reply, independently derives the
// two directional session keys, and verifies the sealed confirmation - the
// same cross-check a real client would need before trusting the session.
// It returns the client's send (tx) and receive (rx) AEADs.
func (c *testClientHandshake) deriveFromAck(t *testing.T, ack []byte) (aeadTx, aeadRx cipher.AEAD, expires time.Time) {
	t.Helper()
	minLen := commonHeaderLen + x25519PubKeyLen + authFrameNonceLen + handshakeAckPlainLen + aeadOverhead
	if len(ack) < minLen {
		t.Fatalf("handshake ack too short: got %d bytes, want at least %d", len(ack), minLen)
	}
	if string(ack[0:4]) != magicV3 || ack[4] != typeHandshakeAck {
		t.Fatalf("unexpected ack header: %x", ack[:6])
	}
	serverPubBytes := ack[commonHeaderLen : commonHeaderLen+x25519PubKeyLen]
	nonceStart := commonHeaderLen + x25519PubKeyLen
	nonce := ack[nonceStart : nonceStart+authFrameNonceLen]
	aad := ack[:nonceStart+authFrameNonceLen]
	ciphertext := ack[nonceStart+authFrameNonceLen:]

	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatalf("parse server pub key: %v", err)
	}
	shared, err := c.priv.ECDH(serverPub)
	if err != nil {
		t.Fatalf("client ecdh: %v", err)
	}

	tk := ticket{clientID: c.clientID, assignedIP: c.assignedIP, keyID: c.keyID}
	// From the client's perspective, the key it uses to send (tx) is
	// derived under hkdfInfoClientToServer - the same info string the
	// server used to derive its *rx* key. See hkdfInfoClientToServer's doc.
	clientTxKey, err := deriveSessionKey(shared, tk, hkdfInfoClientToServer)
	if err != nil {
		t.Fatalf("derive client tx key: %v", err)
	}
	clientRxKey, err := deriveSessionKey(shared, tk, hkdfInfoServerToClient)
	if err != nil {
		t.Fatalf("derive client rx key: %v", err)
	}
	if aeadTx, err = newAESGCM(clientTxKey); err != nil {
		t.Fatalf("client tx aead: %v", err)
	}
	if aeadRx, err = newAESGCM(clientRxKey); err != nil {
		t.Fatalf("client rx aead: %v", err)
	}

	plain, err := aeadRx.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("client failed to open handshake ack confirmation (keys did not match server's): %v", err)
	}
	if len(plain) != handshakeAckPlainLen {
		t.Fatalf("unexpected ack plaintext length: %d", len(plain))
	}
	expiresUnix := int64(binary.BigEndian.Uint64(plain))
	return aeadTx, aeadRx, time.Unix(expiresUnix, 0)
}

// -----------------------------------------------------------------------
// Ticket format: sign/parse, tamper and key-mismatch rejection (H-10)
// -----------------------------------------------------------------------

// testTicketPub is a fixed, well-formed X25519 public key for tests that
// only care about the non-clientPub fields of a ticket.
func testTicketPub(t *testing.T) [ticketClientPubLen]byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdh key: %v", err)
	}
	return clientPubArray(priv.PublicKey())
}

func TestTicketSignParseRoundTrip(t *testing.T) {
	signingKey := testSigningKey()
	var clientID [16]byte
	copy(clientID[:], "client-0123456")
	assignedIP := [4]byte{10, 88, 0, 42}
	keyID := uint64(12345)
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	jti := randomJTI(t)
	clientPub := testTicketPub(t)

	raw := signTicket(signingKey, clientID, assignedIP, keyID, expires, jti, clientPub)
	if len(raw) != ticketFixedLen {
		t.Fatalf("signTicket length = %d, want %d", len(raw), ticketFixedLen)
	}

	got, ok := parseTicket(signingKey, raw)
	if !ok {
		t.Fatal("parseTicket rejected a validly-signed ticket")
	}
	if got.clientID != clientID {
		t.Errorf("clientID = %x, want %x", got.clientID, clientID)
	}
	if got.assignedIP != assignedIP {
		t.Errorf("assignedIP = %v, want %v", got.assignedIP, assignedIP)
	}
	if got.keyID != keyID {
		t.Errorf("keyID = %d, want %d", got.keyID, keyID)
	}
	if !got.expires.Equal(expires) {
		t.Errorf("expires = %v, want %v", got.expires, expires)
	}
	if got.jti != jti {
		t.Errorf("jti = %x, want %x", got.jti, jti)
	}
	if got.clientPub != clientPub {
		t.Errorf("clientPub = %x, want %x", got.clientPub, clientPub)
	}
}

func TestParseTicketRejectsTamperedSignature(t *testing.T) {
	signingKey := testSigningKey()
	raw := signTicket(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, ok := parseTicket(signingKey, tampered); ok {
		t.Fatal("parseTicket accepted a ticket with a tampered signature")
	}
}

func TestParseTicketRejectsTamperedBody(t *testing.T) {
	signingKey := testSigningKey()
	raw := signTicket(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))
	tampered := append([]byte{}, raw...)
	tampered[5] ^= 0xFF // a byte inside clientID
	if _, ok := parseTicket(signingKey, tampered); ok {
		t.Fatal("parseTicket accepted a ticket whose body no longer matches its signature")
	}
}

// TestParseTicketRejectsTamperedClientPub is the H-6 regression test at the
// ticket layer: flipping a bit inside the signed clientPub field (as
// opposed to substituting an entirely different, well-formed on-wire key -
// see TestHandshakeRejectsCopiedTicketWithAttackerKey for that) must break
// the signature check exactly like tampering with any other field.
func TestParseTicketRejectsTamperedClientPub(t *testing.T) {
	signingKey := testSigningKey()
	raw := signTicket(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))
	tampered := append([]byte{}, raw...)
	tampered[len(tampered)-ticketSignatureLen-1] ^= 0xFF // last byte of clientPub, just before the signature
	if _, ok := parseTicket(signingKey, tampered); ok {
		t.Fatal("parseTicket accepted a ticket whose bound clientPub was tampered with")
	}
}

func TestParseTicketRejectsWrongSigningKey(t *testing.T) {
	raw := signTicket(testSigningKey(), [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))
	otherKey := bytes.Repeat([]byte{0x24}, 32)
	if _, ok := parseTicket(otherKey, raw); ok {
		t.Fatal("parseTicket accepted a ticket signed under a different key")
	}
}

func TestParseTicketRejectsTruncatedOrOverLong(t *testing.T) {
	signingKey := testSigningKey()
	raw := signTicket(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))

	if _, ok := parseTicket(signingKey, raw[:len(raw)-1]); ok {
		t.Fatal("parseTicket accepted a truncated ticket")
	}
	if _, ok := parseTicket(signingKey, append(append([]byte{}, raw...), 0)); ok {
		t.Fatal("parseTicket accepted an over-long ticket")
	}
}

func TestParseTicketRejectsUnknownVersion(t *testing.T) {
	signingKey := testSigningKey()
	canonical := ticketCanonicalBytes(0xFF, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour).Unix(), randomJTI(t), testTicketPub(t))
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	raw := append(append([]byte{}, canonical...), mac.Sum(nil)...)

	if _, ok := parseTicket(signingKey, raw); ok {
		t.Fatal("parseTicket accepted a ticket with an unrecognized version byte, even though correctly signed")
	}
}

// TestParseTicketRejectsLegacyV1Version is the H-6 regression test for "v1
// is rejected outright, not accepted during a migration window": a ticket
// correctly signed but explicitly stamped with the old ticketVersion1 byte
// must be rejected exactly like any other unrecognized version.
func TestParseTicketRejectsLegacyV1Version(t *testing.T) {
	signingKey := testSigningKey()
	canonical := ticketCanonicalBytes(ticketVersion1, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour).Unix(), randomJTI(t), testTicketPub(t))
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	raw := append(append([]byte{}, canonical...), mac.Sum(nil)...)

	if _, ok := parseTicket(signingKey, raw); ok {
		t.Fatal("parseTicket accepted a ticketVersion1 ticket; v1 must be rejected outright, there is no migration path")
	}
}

// -----------------------------------------------------------------------
// Handshake-init parsing: expiry and structural validation (H-10)
// -----------------------------------------------------------------------

// buildHandshakeInitBody builds a wire-format handshake body whose ticket is
// correctly bound to clientPub (the common, non-attack-simulating case: the
// on-wire key and the ticket-bound key are the same). Use
// buildHandshakeInitBodyWithForeignKey to simulate a copied ticket paired
// with a different on-wire key.
func buildHandshakeInitBody(signingKey []byte, clientID [16]byte, assignedIP [4]byte, keyID uint64, expires time.Time, jti [ticketJTILen]byte, clientPub *ecdh.PublicKey) []byte {
	return buildHandshakeInitBodyWithForeignKey(signingKey, clientID, assignedIP, keyID, expires, jti, clientPub, clientPub.Bytes())
}

// buildHandshakeInitBodyWithForeignKey builds a handshake body whose signed
// ticket is bound to boundPub but whose on-wire clientEphemeralPub field is
// onWirePub - independently controllable, so tests can simulate a copied
// ticket paired with an attacker-substituted key (H-6).
func buildHandshakeInitBodyWithForeignKey(signingKey []byte, clientID [16]byte, assignedIP [4]byte, keyID uint64, expires time.Time, jti [ticketJTILen]byte, boundPub *ecdh.PublicKey, onWirePub []byte) []byte {
	ticketBytes := signTicket(signingKey, clientID, assignedIP, keyID, expires, jti, clientPubArray(boundPub))
	body := make([]byte, 0, handshakeInitBodyLen)
	body = append(body, ticketBytes...)
	body = append(body, onWirePub...)
	return body
}

func TestParseHandshakeInitAcceptsValid(t *testing.T) {
	signingKey := testSigningKey()
	clientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientID := [16]byte{9}
	assignedIP := [4]byte{10, 88, 0, 7}
	expires := time.Now().Add(time.Hour)
	body := buildHandshakeInitBody(signingKey, clientID, assignedIP, 77, expires, randomJTI(t), clientPriv.PublicKey())

	tk, pub, ok := parseHandshakeInit(signingKey, body, time.Now())
	if !ok {
		t.Fatal("parseHandshakeInit rejected a valid handshake body")
	}
	if tk.clientID != clientID || tk.assignedIP != assignedIP || tk.keyID != 77 {
		t.Errorf("unexpected ticket fields: %+v", tk)
	}
	if !bytes.Equal(pub.Bytes(), clientPriv.PublicKey().Bytes()) {
		t.Error("parsed client public key does not match the one sent")
	}
}

func TestParseHandshakeInitRejectsExpiredTicket(t *testing.T) {
	signingKey := testSigningKey()
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	body := buildHandshakeInitBody(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(-time.Minute), randomJTI(t), clientPriv.PublicKey())
	if _, _, ok := parseHandshakeInit(signingKey, body, time.Now()); ok {
		t.Fatal("parseHandshakeInit accepted an expired ticket")
	}
}

func TestParseHandshakeInitRejectsImplausibleExpiry(t *testing.T) {
	signingKey := testSigningKey()
	clientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	body := buildHandshakeInitBody(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(maxTicketLifetime+time.Hour), randomJTI(t), clientPriv.PublicKey())
	if _, _, ok := parseHandshakeInit(signingKey, body, time.Now()); ok {
		t.Fatal("parseHandshakeInit accepted a ticket with an implausibly distant expiry")
	}
}

func TestParseHandshakeInitRejectsWrongLength(t *testing.T) {
	signingKey := testSigningKey()
	ticketBytes := signTicket(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), testTicketPub(t))
	if _, _, ok := parseHandshakeInit(signingKey, ticketBytes, time.Now()); ok {
		t.Fatal("parseHandshakeInit accepted a body that is missing the client's public key")
	}
}

// -----------------------------------------------------------------------
// H-6: ticket/public-key binding - a copied ticket cannot be paired with an
// attacker's own key
// -----------------------------------------------------------------------

// TestParseHandshakeInitRejectsForeignPublicKey is the core H-6 regression
// test: a validly-signed, unexpired ticket presented alongside a
// well-formed X25519 public key that is NOT the one the ticket was bound to
// (as if an attacker copied a captured ticket off the wire and attached
// their own key) must be rejected, even though every other check on its own
// would pass.
func TestParseHandshakeInitRejectsForeignPublicKey(t *testing.T) {
	signingKey := testSigningKey()
	legitPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := buildHandshakeInitBodyWithForeignKey(signingKey, [16]byte{1}, [4]byte{10, 0, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), legitPriv.PublicKey(), attackerPriv.PublicKey().Bytes())

	if _, _, ok := parseHandshakeInit(signingKey, body, time.Now()); ok {
		t.Fatal("parseHandshakeInit accepted a ticket paired with a public key it was not bound to")
	}
}

// TestHandshakeRejectsCopiedTicketWithAttackerKey exercises the same attack
// end to end through handleUDPPacket/handleHandshakeInit: the attacker's
// forged packet must get no reply and must not create any session at all
// (not even one keyed to the attacker's own endpoint).
func TestHandshakeRejectsCopiedTicketWithAttackerKey(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	attackerUDP := newTestClientUDP(t)
	attackerAddr := attackerUDP.LocalAddr().(*net.UDPAddr)

	victim := newTestClientHandshake(t, 55, [4]byte{10, 88, 0, 55})
	attackerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := victim.initPacketWithForeignKey(signingKey, wifiPathID, attackerPriv.PublicKey().Bytes())

	srv.handleUDPPacket(udpPacket{data: forged, addr: attackerAddr})
	assertNoUDPWithinTimeout(t, attackerUDP)
	if srv.sessions.count() != 0 {
		t.Fatal("a copied ticket paired with an attacker-supplied key must not establish any session")
	}
}

// -----------------------------------------------------------------------
// Session key derivation: determinism, context/direction separation (H-10)
// -----------------------------------------------------------------------

func TestDeriveSessionKeyDeterministicAndLength(t *testing.T) {
	shared := bytes.Repeat([]byte{0x77}, 32)
	tk := ticket{clientID: [16]byte{1}, assignedIP: [4]byte{10, 0, 0, 1}, keyID: 1}

	k1, err := deriveSessionKey(shared, tk, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := deriveSessionKey(shared, tk, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != sessionAEADKeyLen {
		t.Fatalf("derived key length = %d, want %d", len(k1), sessionAEADKeyLen)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("deriveSessionKey must be deterministic for identical inputs")
	}
}

func TestDeriveSessionKeyDirectionsAndContextsDiffer(t *testing.T) {
	shared := bytes.Repeat([]byte{0x77}, 32)
	base := ticket{clientID: [16]byte{1}, assignedIP: [4]byte{10, 0, 0, 1}, keyID: 1}

	c2s, err := deriveSessionKey(shared, base, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	s2c, err := deriveSessionKey(shared, base, hkdfInfoServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c2s, s2c) {
		t.Fatal("client->server and server->client keys must differ (direction separation)")
	}

	otherClient := base
	otherClient.clientID = [16]byte{2}
	k, err := deriveSessionKey(shared, otherClient, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k, c2s) {
		t.Fatal("changing clientID must change the derived key (context separation)")
	}

	otherIP := base
	otherIP.assignedIP = [4]byte{10, 0, 0, 2}
	k, err = deriveSessionKey(shared, otherIP, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k, c2s) {
		t.Fatal("changing assignedIP must change the derived key (context separation)")
	}

	otherKeyID := base
	otherKeyID.keyID = 2
	k, err = deriveSessionKey(shared, otherKeyID, hkdfInfoClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k, c2s) {
		t.Fatal("changing keyID must change the derived key (context separation)")
	}
}

// TestDirectionalKeysAreIndependent confirms that a frame sealed under a
// session's server->client key cannot be opened under that same session's
// client->server key, and vice versa: the two directions are genuinely
// independent keys, not just a labeling convention over one shared key.
func TestDirectionalKeysAreIndependent(t *testing.T) {
	sess := newTestSession(t, 1)
	frame := sess.sealFrame(typeData, 1, 1, []byte("hello"), nil) // always uses aeadTx
	nonce := frame[22:34]
	ciphertext := frame[34:]
	aad := frame[:authFrameAADLen]

	if _, err := sess.aeadRx.Open(nil, nonce, ciphertext, aad); err == nil {
		t.Fatal("a frame sealed with the session's tx key must not open under its independently-derived rx key")
	}
	plain, err := sess.aeadTx.Open(nil, nonce, ciphertext, aad)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("the frame should open correctly under its own tx key: err=%v plain=%q", err, plain)
	}
}

// -----------------------------------------------------------------------
// ReplayWindow: sliding-window anti-replay (H-10)
// -----------------------------------------------------------------------

func TestReplayWindowAcceptsMonotonicSequence(t *testing.T) {
	w := &ReplayWindow{}
	for seq := uint64(1); seq <= 100; seq++ {
		if !w.Accept(seq) {
			t.Fatalf("seq %d should be accepted the first time", seq)
		}
	}
}

func TestReplayWindowRejectsZero(t *testing.T) {
	w := &ReplayWindow{}
	if w.Accept(0) {
		t.Fatal("seq 0 must always be rejected (reserved/invalid)")
	}
}

func TestReplayWindowRejectsExactDuplicate(t *testing.T) {
	w := &ReplayWindow{}
	if !w.Accept(42) {
		t.Fatal("first delivery of seq 42 should be accepted")
	}
	if w.Accept(42) {
		t.Fatal("duplicate delivery of seq 42 must be rejected")
	}
}

func TestReplayWindowAcceptsOutOfOrderWithinWindow(t *testing.T) {
	w := &ReplayWindow{}
	if !w.Accept(100) {
		t.Fatal("seq 100 should be accepted")
	}
	if !w.Accept(90) {
		t.Fatal("seq 90, delivered late but within the window, should be accepted")
	}
	if w.Accept(90) {
		t.Fatal("re-delivery of seq 90 must be rejected")
	}
	if !w.Accept(99) {
		t.Fatal("seq 99 should still be accepted")
	}
}

func TestReplayWindowRejectsTooOld(t *testing.T) {
	w := &ReplayWindow{}
	if !w.Accept(replayWindowBits + 100) {
		t.Fatal("seed sequence number should be accepted")
	}
	// Anything at or beyond replayWindowBits behind the high-water mark is
	// outside the window and must be rejected even though never seen.
	if w.Accept(100) {
		t.Fatal("a sequence number older than the window must be rejected even if never observed before")
	}
}

func TestReplayWindowSlidesForwardAndForgetsOldState(t *testing.T) {
	w := &ReplayWindow{}
	if !w.Accept(1) {
		t.Fatal("seq 1 should be accepted")
	}
	// Jump far enough forward that the window slides completely past seq 1.
	if !w.Accept(1 + replayWindowBits + 1) {
		t.Fatal("a large forward jump should be accepted as the new high-water mark")
	}
	mid := uint64(1 + replayWindowBits/2)
	if !w.Accept(mid) {
		t.Fatal("an unseen sequence number inside the new window should be accepted")
	}
	if w.Accept(mid) {
		t.Fatal("re-delivery after a window slide must still be rejected")
	}
}

func TestReplayWindowConcurrentAcceptIsRaceSafe(t *testing.T) {
	w := &ReplayWindow{}
	const n = 2000 // stays within replayWindowBits so every seq is acceptable
	var wg sync.WaitGroup
	var accepted atomic.Int64
	for i := 1; i <= n; i++ {
		wg.Add(1)
		seq := uint64(i)
		go func() {
			defer wg.Done()
			if w.Accept(seq) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != n {
		t.Fatalf("accepted = %d, want %d (every unique concurrent seq should be accepted exactly once)", got, n)
	}
}

// -----------------------------------------------------------------------
// tokenBucket: probe rate limiting primitive (H-11)
// -----------------------------------------------------------------------

func TestTokenBucketAllowsWithinBurstAndRejectsOverBurst(t *testing.T) {
	now := time.Now()
	b := newTokenBucket(10, 100)
	if !b.AllowN(now, 100) {
		t.Fatal("a request exactly at the burst size should be allowed")
	}
	if b.AllowN(now, 1) {
		t.Fatal("the bucket should be empty immediately after consuming the full burst")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	// Constructed directly (rather than via newTokenBucket, which stamps
	// its own internal time.Now()) so "now" below is exactly b.updated,
	// with no sub-microsecond gap between two separate clock reads that
	// could make the refill arithmetic land a hair under the exact
	// expected token count.
	now := time.Now()
	b := &tokenBucket{rate: 10, burst: 100, tokens: 100, updated: now} // 10 tokens/sec
	if !b.AllowN(now, 100) {
		t.Fatal("initial burst should be allowed")
	}
	if b.AllowN(now, 1) {
		t.Fatal("no tokens should remain immediately after spending the burst")
	}

	later := now.Add(500 * time.Millisecond) // 5 tokens refilled at 10/s
	if !b.AllowN(later, 5) {
		t.Fatal("5 tokens should have refilled after 500ms at a 10/s rate")
	}
	if b.AllowN(later, 1) {
		t.Fatal("no tokens should remain right after spending exactly the refilled amount")
	}
}

func TestTokenBucketNeverExceedsBurstCapacity(t *testing.T) {
	now := time.Now()
	b := newTokenBucket(1000, 50)
	farFuture := now.Add(time.Hour) // would refill far more than the burst allows
	if !b.AllowN(farFuture, 50) {
		t.Fatal("refill must be capped at burst capacity, not unbounded")
	}
	if b.AllowN(farFuture, 1) {
		t.Fatal("bucket must never exceed its configured burst capacity")
	}
}

func TestTokenBucketNonPositiveRequestAlwaysAllowed(t *testing.T) {
	b := newTokenBucket(1, 1)
	if !b.AllowN(time.Now(), 0) {
		t.Fatal("a zero-byte request should always be allowed")
	}
	if !b.AllowN(time.Now(), -5) {
		t.Fatal("a non-positive request should always be allowed")
	}
}

// -----------------------------------------------------------------------
// sessionTable: caps, supersession, idle/expired eviction (H-10)
// -----------------------------------------------------------------------

func TestSessionTableEstablishAndLookup(t *testing.T) {
	st := newSessionTable()
	tk := ticket{clientID: [16]byte{1}, assignedIP: [4]byte{10, 0, 0, 1}, keyID: 100, expires: time.Now().Add(time.Hour)}
	sess, err := st.establish(tk, newTestAEAD(t, 1), newTestAEAD(t, 2), time.Now())
	if err != nil {
		t.Fatalf("establish: %v", err)
	}

	if got := st.lookup(100); got != sess {
		t.Fatal("lookup by keyID should return the just-established session")
	}
	if got := st.lookupByAssignedIP(tk.assignedIP); got != sess {
		t.Fatal("lookupByAssignedIP should return the just-established session")
	}
	if st.count() != 1 {
		t.Fatalf("count = %d, want 1", st.count())
	}
}

func TestSessionTableNewTicketForSameClientIDSupersedesOldSession(t *testing.T) {
	st := newSessionTable()
	clientID := [16]byte{7}
	tk1 := ticket{clientID: clientID, assignedIP: [4]byte{10, 0, 0, 1}, keyID: 1, expires: time.Now().Add(time.Hour)}
	if _, err := st.establish(tk1, newTestAEAD(t, 1), newTestAEAD(t, 2), time.Now()); err != nil {
		t.Fatal(err)
	}

	tk2 := ticket{clientID: clientID, assignedIP: [4]byte{10, 0, 0, 2}, keyID: 2, expires: time.Now().Add(time.Hour)}
	sess2, err := st.establish(tk2, newTestAEAD(t, 3), newTestAEAD(t, 4), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if st.lookup(1) != nil {
		t.Fatal("the superseded session's old keyID must no longer resolve")
	}
	if st.lookup(2) != sess2 {
		t.Fatal("the new session should be reachable by its new keyID")
	}
	if st.count() != 1 {
		t.Fatalf("count = %d, want 1 (re-handshake must replace, not duplicate, a client's session)", st.count())
	}
}

func TestSessionTableNewTicketForSameAssignedIPSupersedesOldSession(t *testing.T) {
	st := newSessionTable()
	assignedIP := [4]byte{10, 0, 0, 9}
	tk1 := ticket{clientID: [16]byte{1}, assignedIP: assignedIP, keyID: 1, expires: time.Now().Add(time.Hour)}
	if _, err := st.establish(tk1, newTestAEAD(t, 1), newTestAEAD(t, 2), time.Now()); err != nil {
		t.Fatal(err)
	}
	tk2 := ticket{clientID: [16]byte{2}, assignedIP: assignedIP, keyID: 2, expires: time.Now().Add(time.Hour)}
	sess2, err := st.establish(tk2, newTestAEAD(t, 3), newTestAEAD(t, 4), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if st.lookupByAssignedIP(assignedIP) != sess2 {
		t.Fatal("assignedIP should now resolve to the newest session claiming it")
	}
	if st.lookup(1) != nil {
		t.Fatal("the old session, whose assignedIP got reclaimed by a newer ticket, must be fully removed")
	}
}

func TestSessionTableEnforcesMaxActiveSessions(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	rx, tx := newTestAEAD(t, 1), newTestAEAD(t, 2)
	for i := 0; i < maxActiveSessions; i++ {
		var clientID [16]byte
		binary.BigEndian.PutUint64(clientID[:8], uint64(i))
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], uint32(i)+1)
		tk := ticket{clientID: clientID, assignedIP: ip, keyID: uint64(i) + 1, expires: now.Add(time.Hour)}
		if _, err := st.establish(tk, rx, tx, now); err != nil {
			t.Fatalf("establish %d: %v", i, err)
		}
	}
	if st.count() != maxActiveSessions {
		t.Fatalf("count = %d, want %d", st.count(), maxActiveSessions)
	}

	overflow := ticket{
		clientID:   [16]byte{0xFE},
		assignedIP: [4]byte{254, 254, 254, 254},
		keyID:      uint64(maxActiveSessions) + 1,
		expires:    now.Add(time.Hour),
	}
	if _, err := st.establish(overflow, rx, tx, now); !errors.Is(err, errSessionCapExceeded) {
		t.Fatalf("establish past the cap: err = %v, want errSessionCapExceeded", err)
	}
	if st.count() != maxActiveSessions {
		t.Fatalf("count after rejected overflow = %d, want unchanged %d", st.count(), maxActiveSessions)
	}
}

func TestSessionTableEvictsIdleSessionsWhenAtCapacity(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	staleNow := now.Add(-2 * sessionIdleTimeout)
	rx, tx := newTestAEAD(t, 1), newTestAEAD(t, 2)
	for i := 0; i < maxActiveSessions; i++ {
		var clientID [16]byte
		binary.BigEndian.PutUint64(clientID[:8], uint64(i))
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], uint32(i)+1)
		tk := ticket{clientID: clientID, assignedIP: ip, keyID: uint64(i) + 1, expires: now.Add(time.Hour)}
		if _, err := st.establish(tk, rx, tx, staleNow); err != nil {
			t.Fatalf("establish %d: %v", i, err)
		}
	}
	if st.count() != maxActiveSessions {
		t.Fatalf("count = %d, want %d", st.count(), maxActiveSessions)
	}

	freshTk := ticket{clientID: [16]byte{0xFF}, assignedIP: [4]byte{255, 255, 255, 255}, keyID: 999999, expires: now.Add(time.Hour)}
	sess, err := st.establish(freshTk, rx, tx, now)
	if err != nil {
		t.Fatalf("establish should succeed by evicting idle sessions to make room: %v", err)
	}
	if st.lookup(999999) != sess {
		t.Fatal("the newly established session should be reachable")
	}
	if st.count() != 1 {
		t.Fatalf("count = %d, want 1 (all stale sessions evicted, one fresh one remains)", st.count())
	}
}

func TestSessionTableSweepRemovesIdleAndExpired(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	rx, tx := newTestAEAD(t, 1), newTestAEAD(t, 2)

	idleTk := ticket{clientID: [16]byte{1}, assignedIP: [4]byte{10, 0, 0, 1}, keyID: 1, expires: now.Add(time.Hour)}
	if _, err := st.establish(idleTk, rx, tx, now.Add(-2*sessionIdleTimeout)); err != nil {
		t.Fatal(err)
	}

	// establish() trusts its caller (handleHandshakeInit, via
	// parseHandshakeInit) to have already rejected expired tickets; this
	// directly exercises sweep's own independent expiry check.
	expiredTk := ticket{clientID: [16]byte{2}, assignedIP: [4]byte{10, 0, 0, 2}, keyID: 2, expires: now.Add(-time.Second)}
	if _, err := st.establish(expiredTk, rx, tx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	activeTk := ticket{clientID: [16]byte{3}, assignedIP: [4]byte{10, 0, 0, 3}, keyID: 3, expires: now.Add(time.Hour)}
	activeSess, err := st.establish(activeTk, rx, tx, now)
	if err != nil {
		t.Fatal(err)
	}

	if st.count() != 3 {
		t.Fatalf("count before sweep = %d, want 3", st.count())
	}

	removed := st.sweep(now)
	if removed != 2 {
		t.Fatalf("sweep removed %d sessions, want 2 (one idle, one expired)", removed)
	}
	if st.count() != 1 {
		t.Fatalf("count after sweep = %d, want 1", st.count())
	}
	if st.lookup(3) != activeSess {
		t.Fatal("the active session should survive the sweep")
	}
}

func TestSessionTableConcurrentEstablishLookupSweep(t *testing.T) {
	st := newSessionTable()
	rx, tx := newTestAEAD(t, 1), newTestAEAD(t, 2)
	const workers = 50
	const perWorker = 20
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				var clientID [16]byte
				binary.BigEndian.PutUint64(clientID[:8], uint64(w))
				binary.BigEndian.PutUint64(clientID[8:], uint64(i))
				var ip [4]byte
				binary.BigEndian.PutUint32(ip[:], uint32(w*1000+i)+1)
				keyID := uint64(w)*uint64(perWorker) + uint64(i) + 1
				tk := ticket{clientID: clientID, assignedIP: ip, keyID: keyID, expires: time.Now().Add(time.Hour)}
				if _, err := st.establish(tk, rx, tx, time.Now()); err != nil && !errors.Is(err, errSessionCapExceeded) {
					t.Errorf("unexpected establish error: %v", err)
				}
				st.lookup(keyID)
				st.lookupByAssignedIP(ip)
				st.sweep(time.Now())
			}
		}(w)
	}
	wg.Wait()
	if st.count() > maxActiveSessions {
		t.Fatalf("count = %d, must never exceed %d", st.count(), maxActiveSessions)
	}
}

// -----------------------------------------------------------------------
// sessionTable's H-6 ticket replay cache: reservation/race-closing,
// single-use resend, expiry, and bounded eviction (mirrors pruneFlowCache's
// two-phase expire-then-trim style, per M-5's rate-limiter fix elsewhere in
// this codebase).
// -----------------------------------------------------------------------

func TestSessionTableBeginTicketUseReservesThenFinishReturnsCachedAck(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	var jti [ticketJTILen]byte
	copy(jti[:], "jti-one")

	ack, alreadyUsed := st.beginTicketUse(jti, now)
	if alreadyUsed || ack != nil {
		t.Fatalf("first beginTicketUse: alreadyUsed=%v ack=%v, want false/nil", alreadyUsed, ack)
	}

	// A second, concurrent-in-spirit call before finishTicketUse must see
	// the reservation (in-flight, no ack yet) rather than being allowed to
	// reserve again or proceed as if it were the first use.
	ack, alreadyUsed = st.beginTicketUse(jti, now)
	if !alreadyUsed || ack != nil {
		t.Fatalf("beginTicketUse while reserved: alreadyUsed=%v ack=%v, want true/nil", alreadyUsed, ack)
	}

	realAck := []byte("the real handshake ack bytes")
	st.finishTicketUse(jti, realAck, now.Add(time.Hour))

	ack, alreadyUsed = st.beginTicketUse(jti, now)
	if !alreadyUsed {
		t.Fatal("beginTicketUse after finishTicketUse should report the jti as already used")
	}
	if !bytes.Equal(ack, realAck) {
		t.Fatalf("cached ack = %q, want %q", ack, realAck)
	}
}

func TestSessionTableFinishTicketUseCopiesAckRatherThanAliasing(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	var jti [ticketJTILen]byte
	copy(jti[:], "jti-alias")

	ackBuf := []byte("original")
	st.finishTicketUse(jti, ackBuf, now.Add(time.Hour))
	ackBuf[0] = 'X' // mutate the caller's slice after handing it off

	cached, _ := st.beginTicketUse(jti, now)
	if string(cached) != "original" {
		t.Fatalf("cached ack = %q, want it unaffected by later mutation of the caller's buffer: %q", cached, "original")
	}
}

func TestSessionTableAbortTicketUseClearsOnlyUnfinishedReservation(t *testing.T) {
	st := newSessionTable()
	now := time.Now()

	var jtiUnfinished [ticketJTILen]byte
	copy(jtiUnfinished[:], "unfinished")
	st.beginTicketUse(jtiUnfinished, now)
	st.abortTicketUse(jtiUnfinished)
	if _, alreadyUsed := st.beginTicketUse(jtiUnfinished, now); alreadyUsed {
		t.Fatal("abortTicketUse should release an unfinished reservation, allowing a fresh attempt")
	}

	var jtiFinished [ticketJTILen]byte
	copy(jtiFinished[:], "finished")
	st.beginTicketUse(jtiFinished, now)
	st.finishTicketUse(jtiFinished, []byte("real-ack"), now.Add(time.Hour))
	st.abortTicketUse(jtiFinished) // must be a no-op: this jti already finished successfully
	ack, alreadyUsed := st.beginTicketUse(jtiFinished, now)
	if !alreadyUsed || !bytes.Equal(ack, []byte("real-ack")) {
		t.Fatal("abortTicketUse must never undo a completed finishTicketUse")
	}
}

func TestSessionTableTicketReplayEntryExpires(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	var jti [ticketJTILen]byte
	copy(jti[:], "expiring")

	st.beginTicketUse(jti, now)
	st.finishTicketUse(jti, []byte("ack"), now.Add(time.Minute))

	afterExpiry := now.Add(2 * time.Minute)
	if _, alreadyUsed := st.beginTicketUse(jti, afterExpiry); alreadyUsed {
		t.Fatal("a jti whose cached entry has expired must be treated as usable again, not as a replay")
	}
}

// TestSessionTableTicketReplayCacheBoundedEviction is the H-6 analogue of
// pruneFlowCache's bound: inserting more distinct jtis than
// maxTicketReplayEntries must never let the map grow past that cap. It
// fills to the cap (cheap - no eviction runs below the cap) and then adds
// only a small number past it: like pruneFlowCache, evictTicketReplayLocked
// trims back down to (not below) the cap on each over-cap insert, so
// exercising that path thousands of times here would mean thousands of full
// O(n log n) re-sorts of an n=maxTicketReplayEntries slice for no extra
// assurance - a handful is already conclusive.
func TestSessionTableTicketReplayCacheBoundedEviction(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	const overCap = 50
	for i := 0; i < maxTicketReplayEntries+overCap; i++ {
		var jti [ticketJTILen]byte
		binary.BigEndian.PutUint64(jti[:8], uint64(i))
		st.beginTicketUse(jti, now)
		st.finishTicketUse(jti, []byte("ack"), now.Add(time.Hour))
	}
	st.mu.RLock()
	size := len(st.ticketReplay)
	st.mu.RUnlock()
	if size > maxTicketReplayEntries {
		t.Fatalf("ticket replay cache size = %d, must never exceed maxTicketReplayEntries (%d)", size, maxTicketReplayEntries)
	}
}

// TestSessionTableTicketReplayEvictsExpiredBeforeTrimmingByAge confirms the
// two-phase eviction order: already-expired entries are dropped first, and
// only unexpired ones are candidates for the oldest-first cap-trim.
func TestSessionTableTicketReplayEvictsExpiredBeforeTrimmingByAge(t *testing.T) {
	st := newSessionTable()
	now := time.Now()

	var expiredJTI [ticketJTILen]byte
	copy(expiredJTI[:], "already-expired")
	st.ticketReplay[expiredJTI] = ticketReplayEntry{ack: []byte("x"), expires: now.Add(-time.Second)}

	var freshJTI [ticketJTILen]byte
	copy(freshJTI[:], "still-fresh")
	st.ticketReplay[freshJTI] = ticketReplayEntry{ack: []byte("y"), expires: now.Add(time.Hour)}

	st.mu.Lock()
	st.evictTicketReplayLocked(now)
	st.mu.Unlock()

	if _, ok := st.ticketReplay[expiredJTI]; ok {
		t.Fatal("an already-expired replay entry should have been evicted")
	}
	if _, ok := st.ticketReplay[freshJTI]; !ok {
		t.Fatal("an unexpired replay entry should not have been evicted")
	}
}

// TestSessionTableSweepAlsoPurgesExpiredTicketReplayEntries ties the H-6
// cache into the same periodic sweep that already evicts idle/expired
// sessions, so it stays bounded without a dedicated background loop.
func TestSessionTableSweepAlsoPurgesExpiredTicketReplayEntries(t *testing.T) {
	st := newSessionTable()
	now := time.Now()
	var jti [ticketJTILen]byte
	copy(jti[:], "sweep-me")
	st.ticketReplay[jti] = ticketReplayEntry{ack: []byte("x"), expires: now.Add(-time.Second)}

	st.sweep(now)

	if _, ok := st.ticketReplay[jti]; ok {
		t.Fatal("sweep should purge expired ticket replay entries along with expired sessions")
	}
}

// -----------------------------------------------------------------------
// authenticatedSession.authenticateAndOpen: the H-10 core gate (AEAD auth,
// replay, endpoint binding, path caps, expiry)
// -----------------------------------------------------------------------

func TestAuthenticateAndOpenAcceptsValidFrame(t *testing.T) {
	sess := newTestSession(t, 1)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	frame := sealClientFrame(sess.aeadRx, typeData, 1, 1, sess.keyID, []byte("hello"))
	nonce, ciphertext, aad := splitAuthFrameBody(frame)

	plain, ok := sess.authenticateAndOpen(1, 1, nonce, ciphertext, aad, addr, time.Now())
	if !ok {
		t.Fatal("authenticateAndOpen rejected a valid first frame")
	}
	if string(plain) != "hello" {
		t.Errorf("plain = %q, want %q", plain, "hello")
	}
}

func TestAuthenticateAndOpenBindsEndpointOnFirstUseAndRejectsOtherEndpoints(t *testing.T) {
	sess := newTestSession(t, 1)
	addrA := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}
	addrB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4002}

	f1 := sealClientFrame(sess.aeadRx, typeData, 1, 1, sess.keyID, []byte("a"))
	n1, c1, a1 := splitAuthFrameBody(f1)
	if _, ok := sess.authenticateAndOpen(1, 1, n1, c1, a1, addrA, time.Now()); !ok {
		t.Fatal("first packet from addrA should bind and be accepted")
	}

	f2 := sealClientFrame(sess.aeadRx, typeData, 1, 2, sess.keyID, []byte("b"))
	n2, c2, a2 := splitAuthFrameBody(f2)
	if _, ok := sess.authenticateAndOpen(1, 2, n2, c2, a2, addrA, time.Now()); !ok {
		t.Fatal("second packet from the already-bound endpoint should be accepted")
	}

	f3 := sealClientFrame(sess.aeadRx, typeData, 1, 3, sess.keyID, []byte("c"))
	n3, c3, a3 := splitAuthFrameBody(f3)
	if _, ok := sess.authenticateAndOpen(1, 3, n3, c3, a3, addrB, time.Now()); ok {
		t.Fatal("a cryptographically valid frame from a different endpoint must still be rejected (endpoint binding)")
	}
}

func TestAuthenticateAndOpenAllowsIndependentBindingPerPath(t *testing.T) {
	// Wi-Fi + cellular bonding: two different pathIDs for the same session
	// may legitimately be bound to two different real endpoints.
	sess := newTestSession(t, 1)
	addrWifi := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	addrCell := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5002}

	f1 := sealClientFrame(sess.aeadRx, typeData, wifiPathID, 10, sess.keyID, []byte("w"))
	n1, c1, a1 := splitAuthFrameBody(f1)
	if _, ok := sess.authenticateAndOpen(wifiPathID, 10, n1, c1, a1, addrWifi, time.Now()); !ok {
		t.Fatal("wifi path's first packet should bind and be accepted")
	}

	f2 := sealClientFrame(sess.aeadRx, typeData, 2, 11, sess.keyID, []byte("c"))
	n2, c2, a2 := splitAuthFrameBody(f2)
	if _, ok := sess.authenticateAndOpen(2, 11, n2, c2, a2, addrCell, time.Now()); !ok {
		t.Fatal("a second path's first packet, from a distinct endpoint, should bind and be accepted")
	}
}

func TestAuthenticateAndOpenRejectsReplayedSequence(t *testing.T) {
	sess := newTestSession(t, 1)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}
	frame := sealClientFrame(sess.aeadRx, typeData, 1, 5, sess.keyID, []byte("x"))
	nonce, ct, aad := splitAuthFrameBody(frame)

	if _, ok := sess.authenticateAndOpen(1, 5, nonce, ct, aad, addr, time.Now()); !ok {
		t.Fatal("first delivery of seq 5 should be accepted")
	}
	if _, ok := sess.authenticateAndOpen(1, 5, nonce, ct, aad, addr, time.Now()); ok {
		t.Fatal("replayed seq 5 should be rejected")
	}
}

func TestAuthenticateAndOpenRejectsExpiredSession(t *testing.T) {
	sess := newTestSession(t, 1)
	sess.expires = time.Now().Add(-time.Second)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}
	frame := sealClientFrame(sess.aeadRx, typeData, 1, 1, sess.keyID, []byte("x"))
	nonce, ct, aad := splitAuthFrameBody(frame)
	if _, ok := sess.authenticateAndOpen(1, 1, nonce, ct, aad, addr, time.Now()); ok {
		t.Fatal("authenticateAndOpen accepted a frame for an expired session")
	}
}

func TestAuthenticateAndOpenRejectsTamperedCiphertextWithoutMutatingState(t *testing.T) {
	sess := newTestSession(t, 1)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}
	frame := sealClientFrame(sess.aeadRx, typeData, 1, 9, sess.keyID, []byte("x"))
	nonce, ct, aad := splitAuthFrameBody(frame)
	tampered := append([]byte{}, ct...)
	tampered[0] ^= 0xFF

	if _, ok := sess.authenticateAndOpen(1, 9, nonce, tampered, aad, addr, time.Now()); ok {
		t.Fatal("authenticateAndOpen accepted a tampered ciphertext")
	}
	// A rejected forgery must not have consumed the replay window or path
	// binding: the real packet, same seq, must still succeed afterwards.
	if _, ok := sess.authenticateAndOpen(1, 9, nonce, ct, aad, addr, time.Now()); !ok {
		t.Fatal("a rejected forgery must not mutate session state ahead of the real packet")
	}
}

func TestAuthenticateAndOpenRejectsWrongSessionKey(t *testing.T) {
	sessA := newTestSession(t, 1)
	sessB := newTestSession(t, 2)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4001}
	// Sealed under sessA's client->server key, but presented against sessB.
	frame := sealClientFrame(sessA.aeadRx, typeData, 1, 1, sessA.keyID, []byte("x"))
	nonce, ct, aad := splitAuthFrameBody(frame)
	if _, ok := sessB.authenticateAndOpen(1, 1, nonce, ct, aad, addr, time.Now()); ok {
		t.Fatal("a frame sealed under a different session's key must not authenticate")
	}
}

func TestAuthenticateAndOpenEnforcesMaxPathsPerSession(t *testing.T) {
	sess := newTestSession(t, 1)
	seq := uint64(1)
	for i := 0; i < maxPathsPerSession; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6000 + i}
		frame := sealClientFrame(sess.aeadRx, typeData, uint8(i), seq, sess.keyID, []byte("x"))
		nonce, ct, aad := splitAuthFrameBody(frame)
		if _, ok := sess.authenticateAndOpen(uint8(i), seq, nonce, ct, aad, addr, time.Now()); !ok {
			t.Fatalf("path %d should bind within the cap", i)
		}
		seq++
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7000}
	frame := sealClientFrame(sess.aeadRx, typeData, uint8(maxPathsPerSession), seq, sess.keyID, []byte("x"))
	nonce, ct, aad := splitAuthFrameBody(frame)
	if _, ok := sess.authenticateAndOpen(uint8(maxPathsPerSession), seq, nonce, ct, aad, addr, time.Now()); ok {
		t.Fatal("a new distinct pathID beyond maxPathsPerSession should be rejected")
	}
}

// -----------------------------------------------------------------------
// Anti-spoofing on tunneled IP packets, and data-batch framing (H-10)
// -----------------------------------------------------------------------

func TestPacketsMatchAssignedIPAcceptsMatchingSource(t *testing.T) {
	assignedIP := [4]byte{10, 88, 0, 5}
	packet := buildIPv4Packet(assignedIP, [4]byte{8, 8, 8, 8}, 0)
	if !packetsMatchAssignedIP([][]byte{packet}, assignedIP) {
		t.Fatal("a packet whose source matches the session's assigned IP should be accepted")
	}
}

func TestPacketsMatchAssignedIPRejectsSpoofedSource(t *testing.T) {
	assignedIP := [4]byte{10, 88, 0, 5}
	spoofed := buildIPv4Packet([4]byte{10, 88, 0, 99}, [4]byte{8, 8, 8, 8}, 0)
	if packetsMatchAssignedIP([][]byte{spoofed}, assignedIP) {
		t.Fatal("a packet whose source IP does not match the session's assigned IP must be rejected")
	}
}

func TestPacketsMatchAssignedIPRejectsIfAnyPacketInBatchSpoofed(t *testing.T) {
	assignedIP := [4]byte{10, 88, 0, 5}
	good := buildIPv4Packet(assignedIP, [4]byte{8, 8, 8, 8}, 0)
	spoofed := buildIPv4Packet([4]byte{10, 88, 0, 99}, [4]byte{8, 8, 8, 8}, 0)
	if packetsMatchAssignedIP([][]byte{good, spoofed}, assignedIP) {
		t.Fatal("one spoofed packet in a batch must cause the whole batch to be rejected")
	}
}

func TestPacketsMatchAssignedIPRejectsShortOrNonIPv4(t *testing.T) {
	assignedIP := [4]byte{10, 88, 0, 5}
	if packetsMatchAssignedIP([][]byte{{0x45, 0, 0, 0}}, assignedIP) {
		t.Fatal("a too-short packet must be rejected")
	}
	notIPv4 := buildIPv4Packet(assignedIP, [4]byte{8, 8, 8, 8}, 0)
	notIPv4[0] = 0x65 // version 6
	if packetsMatchAssignedIP([][]byte{notIPv4}, assignedIP) {
		t.Fatal("a non-IPv4 packet must be rejected")
	}
}

func TestUnwrapDataPayloadsSingleAndBatch(t *testing.T) {
	assignedIP := [4]byte{10, 88, 0, 5}
	p1 := buildIPv4Packet(assignedIP, [4]byte{1, 1, 1, 1}, 4)
	p2 := buildIPv4Packet(assignedIP, [4]byte{2, 2, 2, 2}, 8)

	single, ok := unwrapDataPayloads(p1)
	if !ok || len(single) != 1 || !bytes.Equal(single[0], p1) {
		t.Fatalf("a single-packet payload should unwrap to itself: ok=%v got=%v", ok, single)
	}

	batchPayload := wrapDataBatchPayload([][]byte{p1, p2})
	batch, ok := unwrapDataPayloads(batchPayload)
	if !ok || len(batch) != 2 || !bytes.Equal(batch[0], p1) || !bytes.Equal(batch[1], p2) {
		t.Fatalf("a batch payload should round-trip through wrap/unwrap: ok=%v got=%v", ok, batch)
	}
}

func TestUnwrapDataPayloadsRejectsMalformedBatch(t *testing.T) {
	zeroCount := make([]byte, dataBatchHeaderLen)
	copy(zeroCount[0:4], dataBatchMagic)
	binary.BigEndian.PutUint16(zeroCount[4:6], 0)
	if _, ok := unwrapDataPayloads(zeroCount); ok {
		t.Fatal("a batch declaring zero packets must be rejected")
	}

	tooManyCount := make([]byte, dataBatchHeaderLen)
	copy(tooManyCount[0:4], dataBatchMagic)
	binary.BigEndian.PutUint16(tooManyCount[4:6], uint16(txBatchMaxPackets+1))
	if _, ok := unwrapDataPayloads(tooManyCount); ok {
		t.Fatal("a batch declaring more packets than txBatchMaxPackets must be rejected")
	}

	truncated := make([]byte, dataBatchHeaderLen+2)
	copy(truncated[0:4], dataBatchMagic)
	binary.BigEndian.PutUint16(truncated[4:6], 1)
	binary.BigEndian.PutUint16(truncated[dataBatchHeaderLen:], 100) // claims 100 bytes but none follow
	if _, ok := unwrapDataPayloads(truncated); ok {
		t.Fatal("a batch whose declared packet length overruns the buffer must be rejected")
	}
}

// -----------------------------------------------------------------------
// TUN/interface setup command handling (L-16)
// -----------------------------------------------------------------------

func TestTunSetupCommandsOnlyTcFqIsOptional(t *testing.T) {
	steps := tunSetupCommands("wtest0", 1400, "10.88.0.1/24")
	if len(steps) == 0 {
		t.Fatal("expected at least one setup step")
	}
	for _, step := range steps {
		isTc := len(step.args) > 0 && step.args[0] == "tc"
		if isTc && !step.optional {
			t.Errorf("tc command %v should be marked optional", step.args)
		}
		if !isTc && step.optional {
			t.Errorf("non-tc command %v must not be optional", step.args)
		}
	}
}

func TestApplyTunSetupCommandsAbortsOnFirstRequiredFailure(t *testing.T) {
	var ran []string
	runner := func(name string, args ...string) error {
		ran = append(ran, name)
		if name == "ip" && len(args) > 0 && args[0] == "link" {
			return errors.New("simulated ip link failure")
		}
		return nil
	}
	steps := []commandStep{
		{args: []string{"ip", "addr", "replace"}},
		{args: []string{"ip", "link", "set"}},
		{args: []string{"ip", "link", "set2"}},
		{args: []string{"tc", "qdisc", "replace"}, optional: true},
	}
	if err := applyTunSetupCommands(steps, runner); err == nil {
		t.Fatal("a failing required step must produce an error")
	}
	if len(ran) != 2 {
		t.Fatalf("ran %d commands, want exactly 2 (must stop at the first required failure)", len(ran))
	}
}

func TestApplyTunSetupCommandsTreatsOptionalFailureAsNonFatal(t *testing.T) {
	var ran []string
	runner := func(name string, args ...string) error {
		ran = append(ran, name+":"+strings.Join(args, ","))
		if name == "tc" {
			return errors.New("simulated tc failure")
		}
		return nil
	}
	steps := tunSetupCommands("wtest0", 1400, "10.88.0.1/24")
	if err := applyTunSetupCommands(steps, runner); err != nil {
		t.Fatalf("an optional step failing must not abort setup: %v", err)
	}
	if len(ran) != len(steps) {
		t.Fatalf("ran %d of %d steps; an optional failure must not stop later required steps from running", len(ran), len(steps))
	}
}

func TestRunReturnsErrorWithCommandOutputOnFailure(t *testing.T) {
	err := run("sh", "-c", "echo simulated-stderr-message 1>&2; exit 7")
	if err == nil {
		t.Fatal("run should return an error for a nonzero exit status")
	}
	if !strings.Contains(err.Error(), "simulated-stderr-message") {
		t.Fatalf("run error should include the command's output, got: %v", err)
	}
}

func TestRunReturnsNilOnSuccess(t *testing.T) {
	if err := run("sh", "-c", "exit 0"); err != nil {
		t.Fatalf("run should return nil for a successful command, got: %v", err)
	}
}

// -----------------------------------------------------------------------
// Config/signing-key loading and privilege drop (H-10)
// -----------------------------------------------------------------------

func TestDecodeSigningKeyRejectsEmpty(t *testing.T) {
	if _, err := decodeSigningKey(""); err == nil {
		t.Fatal("decodeSigningKey should reject an empty BOOST_TICKET_SIGNING_KEY")
	}
}

func TestDecodeSigningKeyAcceptsBase64OfSufficientLength(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, 32)
	encoded := base64.StdEncoding.EncodeToString(raw)
	got, err := decodeSigningKey(encoded)
	if err != nil {
		t.Fatalf("decodeSigningKey: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("decodeSigningKey should decode a valid, sufficiently-long base64 key as-is")
	}
}

// -----------------------------------------------------------------------
// H-6: decodeSigningKey must strictly require exactly 32 decoded random
// bytes, never fall back to hashing low-entropy human-typed text.
// -----------------------------------------------------------------------

// TestDecodeSigningKeyRejectsNonBase64HumanText replaces the old behavior
// (SHA-256-hashing whatever wasn't sufficiently-long base64) with outright
// rejection: hashing a low-entropy passphrase does not manufacture real
// entropy, so a plain human-typed passphrase must now be an error, not a
// silently-accepted key.
func TestDecodeSigningKeyRejectsNonBase64HumanText(t *testing.T) {
	if _, err := decodeSigningKey("a human passphrase, not base64"); err == nil {
		t.Fatal("decodeSigningKey should reject non-base64 human-typed text instead of hashing it into a key")
	}
}

func TestDecodeSigningKeyRejectsShortBase64(t *testing.T) {
	// Valid base64, but decodes to far fewer than 32 bytes - e.g. a short
	// word or a weak passphrase someone base64-encoded thinking that alone
	// would make it a "proper" key.
	short := base64.StdEncoding.EncodeToString([]byte("hunter2"))
	if _, err := decodeSigningKey(short); err == nil {
		t.Fatal("decodeSigningKey should reject base64 that decodes to fewer than 32 bytes")
	}
}

func TestDecodeSigningKeyRejectsOverLongBase64(t *testing.T) {
	// More than 32 decoded bytes is also rejected: the doc's fix requires
	// EXACTLY 32, not "at least" - an unexpected length is more likely a
	// misconfiguration (e.g. a copy-paste including extra data) than
	// intentional extra entropy that decodeSigningKey should silently trim.
	over := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 48))
	if _, err := decodeSigningKey(over); err == nil {
		t.Fatal("decodeSigningKey should reject base64 that decodes to more than 32 bytes")
	}
}

// TestDecodeSigningKeyRejectsNonStrictPadding exercises .Strict() itself
// (not just "this string isn't base64 at all", which
// TestDecodeSigningKeyRejectsNonBase64HumanText already covers): 32 bytes
// leaves 2 leftover bytes in the final base64 group, encoded as 3
// significant characters plus one "=" pad. Per RFC 4648 section 3.5, the
// bottom 2 bits of that 3rd character are unused padding bits that a
// canonical encoder always sets to zero; a non-strict decoder ignores
// whatever is there, but Strict() requires they actually be zero. Flipping
// only those bottom 2 bits (leaving the 4 meaningful bits, and therefore
// the decoded byte value, untouched) produces a string that a non-strict
// decode still resolves to the identical 32 bytes but Strict() must refuse.
func TestDecodeSigningKeyRejectsNonStrictPadding(t *testing.T) {
	const base64StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	raw := bytes.Repeat([]byte{0x11}, 32)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	if len(encoded) < 2 || encoded[len(encoded)-1] != '=' {
		t.Fatalf("test assumes one trailing '=' pad character, got %q", encoded)
	}
	lastDataChar := len(encoded) - 2
	idx := strings.IndexByte(base64StdAlphabet, encoded[lastDataChar])
	if idx < 0 {
		t.Fatalf("byte %q not in the standard base64 alphabet", encoded[lastDataChar])
	}
	encoded[lastDataChar] = base64StdAlphabet[idx^0x01] // flip only a padding bit

	sanity, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil || !bytes.Equal(sanity, raw) {
		t.Fatalf("test setup invalid: non-strict decode of the mutated input = %x, %v; want %x, nil", sanity, err, raw)
	}

	if _, err := decodeSigningKey(string(encoded)); err == nil {
		t.Fatal("decodeSigningKey should reject non-canonical base64 padding bits (RFC 4648 strict mode)")
	}
}

func TestDecodeSigningKeyTrimsWhitespaceAroundValidKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, 32)
	encoded := base64.StdEncoding.EncodeToString(raw)
	got, err := decodeSigningKey("  " + encoded + "\n")
	if err != nil {
		t.Fatalf("decodeSigningKey should tolerate surrounding whitespace: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("decodeSigningKey should decode to the same key once whitespace is trimmed")
	}
}

func TestLoadConfigDefaultsAndOverrides(t *testing.T) {
	cfg := loadConfig(map[string]string{})
	if cfg.runAsUID != defaultRunAsUID || cfg.runAsGID != defaultRunAsGID {
		t.Fatalf("expected default run-as uid/gid, got uid=%d gid=%d", cfg.runAsUID, cfg.runAsGID)
	}
	if cfg.ticketSigningKeyText != "" {
		t.Fatalf("expected empty ticket signing key by default, got %q", cfg.ticketSigningKeyText)
	}

	env := map[string]string{
		"BOOST_TICKET_SIGNING_KEY": "  secret-value  ",
		"BOOST_RUN_AS_UID":         "1500",
		"BOOST_RUN_AS_GID":         "1600",
	}
	cfg = loadConfig(env)
	if cfg.ticketSigningKeyText != "secret-value" {
		t.Fatalf("ticketSigningKeyText = %q, want trimmed %q", cfg.ticketSigningKeyText, "secret-value")
	}
	if cfg.runAsUID != 1500 || cfg.runAsGID != 1600 {
		t.Fatalf("expected overridden uid/gid 1500/1600, got uid=%d gid=%d", cfg.runAsUID, cfg.runAsGID)
	}
}

func TestDropPrivilegesNoOpWhenNotRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: refusing to actually drop privileges of a test process running as root")
	}
	if err := dropPrivileges(envConfig{runAsUID: defaultRunAsUID, runAsGID: defaultRunAsGID}); err != nil {
		t.Fatalf("dropPrivileges should no-op (return nil) when not running as root: %v", err)
	}
}

// -----------------------------------------------------------------------
// H-6: privilege drop must fail closed - a validation, syscall, or
// verification failure must stop startup, never just warn and keep running
// as root. dropPrivilegesOrFail takes the actual drop/geteuid/getegid calls
// as parameters specifically so these paths are exercisable without being
// root or mutating the test binary's real privileges.
// -----------------------------------------------------------------------

// nonRootIDs returns effective-ID stand-ins for tests: geteuid/getegid
// implementations that report a plausible non-root process.
func nonRootIDs() (geteuid, getegid func() int) {
	return func() int { return 1000 }, func() int { return 1000 }
}

func TestDropPrivilegesOrFailRejectsNonPositiveUID(t *testing.T) {
	called := false
	drop := func(envConfig) error { called = true; return nil }
	geteuid, getegid := nonRootIDs()

	err := dropPrivilegesOrFail(envConfig{runAsUID: 0, runAsGID: defaultRunAsGID}, drop, geteuid, getegid)
	if err == nil {
		t.Fatal("dropPrivilegesOrFail should reject a zero runAsUID")
	}
	if called {
		t.Fatal("drop must not be invoked once config validation has already failed")
	}
}

func TestDropPrivilegesOrFailRejectsNonPositiveGID(t *testing.T) {
	called := false
	drop := func(envConfig) error { called = true; return nil }
	geteuid, getegid := nonRootIDs()

	err := dropPrivilegesOrFail(envConfig{runAsUID: defaultRunAsUID, runAsGID: -1}, drop, geteuid, getegid)
	if err == nil {
		t.Fatal("dropPrivilegesOrFail should reject a negative runAsGID")
	}
	if called {
		t.Fatal("drop must not be invoked once config validation has already failed")
	}
}

func TestDropPrivilegesOrFailPropagatesDropError(t *testing.T) {
	dropErr := errors.New("simulated setuid failure")
	drop := func(envConfig) error { return dropErr }
	geteuid, getegid := nonRootIDs()

	err := dropPrivilegesOrFail(envConfig{runAsUID: defaultRunAsUID, runAsGID: defaultRunAsGID}, drop, geteuid, getegid)
	if err == nil {
		t.Fatal("dropPrivilegesOrFail should fail when drop itself fails")
	}
	if !strings.Contains(err.Error(), dropErr.Error()) {
		t.Fatalf("error = %v, want it to wrap the underlying drop error %v", err, dropErr)
	}
}

// TestDropPrivilegesOrFailRejectsWhenDropReportsSuccessButIDsStillRoot
// covers the "silent no-op" failure mode directly (H-6): drop returns nil
// (as if the syscalls succeeded) but a post-drop check finds the process is
// still effectively root. This must be rejected even though drop itself
// reported no error - the whole point of the independent re-check.
func TestDropPrivilegesOrFailRejectsWhenDropReportsSuccessButIDsStillRoot(t *testing.T) {
	drop := func(envConfig) error { return nil }

	t.Run("euid still root", func(t *testing.T) {
		geteuid := func() int { return 0 }
		getegid := func() int { return 1000 }
		if err := dropPrivilegesOrFail(envConfig{runAsUID: defaultRunAsUID, runAsGID: defaultRunAsGID}, drop, geteuid, getegid); err == nil {
			t.Fatal("dropPrivilegesOrFail should fail if the effective UID is still 0 after drop reports success")
		}
	})

	t.Run("egid still root", func(t *testing.T) {
		geteuid := func() int { return 1000 }
		getegid := func() int { return 0 }
		if err := dropPrivilegesOrFail(envConfig{runAsUID: defaultRunAsUID, runAsGID: defaultRunAsGID}, drop, geteuid, getegid); err == nil {
			t.Fatal("dropPrivilegesOrFail should fail if the effective GID is still 0 after drop reports success")
		}
	})
}

func TestDropPrivilegesOrFailSucceedsWhenDropWorksAndIDsAreNonRoot(t *testing.T) {
	drop := func(envConfig) error { return nil }
	geteuid, getegid := nonRootIDs()
	if err := dropPrivilegesOrFail(envConfig{runAsUID: defaultRunAsUID, runAsGID: defaultRunAsGID}, drop, geteuid, getegid); err != nil {
		t.Fatalf("dropPrivilegesOrFail should succeed when drop works and post-drop IDs are non-root: %v", err)
	}
}

// TestDropPrivilegesRejectsNonPositiveIDsEvenAsNonRoot documents that
// dropPrivileges itself (not just the outer dropPrivilegesOrFail wrapper)
// refuses to treat a non-positive target ID as "nothing to do" - it just
// can't be observed here because the test process isn't root, so
// dropPrivileges's unconditional not-root no-op returns first. This is the
// same "refusing to actually drop privileges of a test process running as
// root" constraint TestDropPrivilegesNoOpWhenNotRoot documents; the
// non-positive-ID rejection itself is exercised without needing root via
// dropPrivilegesOrFail's config validation (see
// TestDropPrivilegesOrFailRejectsNonPositiveUID/GID above), which runs
// before dropPrivileges would ever be reached in production.
func TestDropPrivilegesRejectsNonPositiveIDsEvenAsNonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping: refusing to actually drop privileges of a test process running as root")
	}
	// Not root, so dropPrivileges no-ops before ever reaching the
	// non-positive-ID check - this call documents that fact rather than
	// exercising the check itself (see the function doc comment above).
	if err := dropPrivileges(envConfig{runAsUID: 0, runAsGID: 0}); err != nil {
		t.Fatalf("dropPrivileges should still no-op (return nil) when not root, regardless of configured IDs: %v", err)
	}
}

// -----------------------------------------------------------------------
// End-to-end: real loopback UDP sockets driving handleUDPPacket, covering
// the full handshake -> data/ping -> probe lifecycle (H-10, H-11)
// -----------------------------------------------------------------------

func TestHandshakeEndToEndPingAndReplayRejection(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 42, [4]byte{10, 88, 0, 42})
	srv.handleUDPPacket(udpPacket{data: client.initPacket(signingKey, wifiPathID), addr: clientAddr})

	ack := readUDPWithTimeout(t, clientUDP)
	aeadTx, _, expires := client.deriveFromAck(t, ack)
	if expires.Before(time.Now()) {
		t.Fatalf("handshake ack confirmed an already-past expiry: %v", expires)
	}
	if sess := srv.sessions.lookup(client.keyID); sess == nil {
		t.Fatal("server should have an established session after a valid handshake")
	}

	pingPayload := make([]byte, pingPayloadLen)
	binary.BigEndian.PutUint64(pingPayload[0:8], 50)         // rttMs
	binary.BigEndian.PutUint64(pingPayload[8:16], 1_000_000) // downBps
	binary.BigEndian.PutUint32(pingPayload[16:20], clientFeatureBatchTx)
	binary.BigEndian.PutUint32(pingPayload[20:24], clientFeatureMagic)
	pingFrame := sealClientFrame(aeadTx, typePing, wifiPathID, 1, client.keyID, pingPayload)
	srv.handleUDPPacket(udpPacket{data: pingFrame, addr: clientAddr})

	pong := readUDPWithTimeout(t, clientUDP)
	if len(pong) < commonHeaderLen {
		t.Fatalf("reply too short to be a valid frame: %d bytes", len(pong))
	}
	if pong[4] != typePong {
		t.Fatalf("expected a typePong reply, got frameType=%d", pong[4])
	}

	// Replaying the exact same ping frame must be silently dropped.
	srv.handleUDPPacket(udpPacket{data: pingFrame, addr: clientAddr})
	assertNoUDPWithinTimeout(t, clientUDP)
}

func TestHandshakeCrossClientFrameIsRejected(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	clientA := newTestClientHandshake(t, 100, [4]byte{10, 88, 0, 100})
	srv.handleUDPPacket(udpPacket{data: clientA.initPacket(signingKey, wifiPathID), addr: clientAddr})
	ackA := readUDPWithTimeout(t, clientUDP)
	aeadTxA, _, _ := clientA.deriveFromAck(t, ackA)

	clientB := newTestClientHandshake(t, 200, [4]byte{10, 88, 0, 200})
	srv.handleUDPPacket(udpPacket{data: clientB.initPacket(signingKey, wifiPathID), addr: clientAddr})
	readUDPWithTimeout(t, clientUDP) // ack B, unused beyond draining the socket

	// Client A seals a frame under its own key but claims to be keyID 200
	// (client B's session). The AEAD tag must fail to verify under B's key.
	forged := sealClientFrame(aeadTxA, typePing, wifiPathID, 1, clientB.keyID, make([]byte, pingPayloadLen))
	srv.handleUDPPacket(udpPacket{data: forged, addr: clientAddr})
	assertNoUDPWithinTimeout(t, clientUDP)
}

func TestHandshakeRejectsLowOrderClientPublicKey(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	// The ticket is bound to the same all-zero value presented on the wire,
	// so this specifically isolates the low-order-point rejection inside
	// ecdh.X25519().NewPublicKey from the separate H-6 bound-key mismatch
	// check (covered by TestParseHandshakeInitRejectsForeignPublicKey).
	var zeroPub [ticketClientPubLen]byte
	ticketBytes := signTicket(signingKey, [16]byte{1}, [4]byte{10, 88, 0, 1}, 1, time.Now().Add(time.Hour), randomJTI(t), zeroPub)
	packet := make([]byte, commonHeaderLen, commonHeaderLen+handshakeInitBodyLen)
	copy(packet[0:4], magicV3)
	packet[4] = typeHandshakeInit
	packet[5] = wifiPathID
	packet = append(packet, ticketBytes...)
	packet = append(packet, make([]byte, x25519PubKeyLen)...) // all-zero: a low-order point

	srv.handleUDPPacket(udpPacket{data: packet, addr: clientAddr})
	assertNoUDPWithinTimeout(t, clientUDP)
	if srv.sessions.count() != 0 {
		t.Fatal("a handshake with a degenerate ECDH public key must not establish a session")
	}
}

// -----------------------------------------------------------------------
// H-6: ticket expiry, exact replay vs. legitimate re-handshake, and race
// safety of the jti replay cache, all exercised end to end through
// handleUDPPacket/handleHandshakeInit.
// -----------------------------------------------------------------------

func TestHandshakeEndToEndRejectsExpiredTicket(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 61, [4]byte{10, 88, 0, 61})
	client.expires = time.Now().Add(-time.Minute)

	srv.handleUDPPacket(udpPacket{data: client.initPacket(signingKey, wifiPathID), addr: clientAddr})
	assertNoUDPWithinTimeout(t, clientUDP)
	if srv.sessions.count() != 0 {
		t.Fatal("an expired ticket must not establish a session")
	}
}

// TestHandshakeExactReplaySameClientResendsAckWithoutNewSession is the H-6
// "legitimate retransmission" case: the same client resends byte-identical
// handshake init bytes (e.g. it never saw the first ack). The server must
// resend the original ack rather than re-running session establishment -
// verified here by checking the session object itself is unchanged (same
// pointer) and that the very first ack's derived keys still work
// afterward, which would not be true if a second, independent ECDH exchange
// had silently replaced them.
func TestHandshakeExactReplaySameClientResendsAckWithoutNewSession(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 62, [4]byte{10, 88, 0, 62})
	initPacket := client.initPacket(signingKey, wifiPathID)

	srv.handleUDPPacket(udpPacket{data: initPacket, addr: clientAddr})
	firstAck := readUDPWithTimeout(t, clientUDP)
	aeadTx, _, _ := client.deriveFromAck(t, firstAck)
	sessAfterFirst := srv.sessions.lookup(client.keyID)
	if sessAfterFirst == nil {
		t.Fatal("first handshake should establish a session")
	}

	// Resend the exact same bytes - same ticket, same jti, same on-wire key.
	srv.handleUDPPacket(udpPacket{data: initPacket, addr: clientAddr})
	secondAck := readUDPWithTimeout(t, clientUDP)

	if !bytes.Equal(firstAck, secondAck) {
		t.Fatal("an exact replay must resend the identical original ack, not mint a new one")
	}
	if srv.sessions.count() != 1 {
		t.Fatalf("session count after replay = %d, want 1 (no new session)", srv.sessions.count())
	}
	if srv.sessions.lookup(client.keyID) != sessAfterFirst {
		t.Fatal("an exact replay must not replace the existing session object")
	}

	// The original session's keys must still work - proving no second,
	// independent ECDH exchange silently ran and rotated them out.
	pingPayload := make([]byte, pingPayloadLen)
	pingFrame := sealClientFrame(aeadTx, typePing, wifiPathID, 1, client.keyID, pingPayload)
	srv.handleUDPPacket(udpPacket{data: pingFrame, addr: clientAddr})
	pong := readUDPWithTimeout(t, clientUDP)
	if pong[4] != typePong {
		t.Fatalf("expected typePong using the original session's keys, got frameType=%d", pong[4])
	}
}

// TestHandshakeExactReplayFromDifferentAddressCannotHijackSession is the
// core H-6 exploit scenario end to end: an "attacker" who captured a
// legitimate client's handshake init packet off the wire (ticket and
// on-wire key both byte-identical, since a copy needs no attacker-side
// crypto capability) replays it from a different network address. The
// server may resend the cached ack to whoever asks (see
// handleHandshakeInit's doc comment for why that is safe), but must not
// establish a second session, must not rebind the victim's already-bound
// path to the attacker's address, and the resent bytes must be useless to
// the attacker - it cannot derive the session's AEAD keys from them without
// the victim's private key.
func TestHandshakeExactReplayFromDifferentAddressCannotHijackSession(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	victimUDP := newTestClientUDP(t)
	victimAddr := victimUDP.LocalAddr().(*net.UDPAddr)
	attackerUDP := newTestClientUDP(t)
	attackerAddr := attackerUDP.LocalAddr().(*net.UDPAddr)

	victim := newTestClientHandshake(t, 63, [4]byte{10, 88, 0, 63})
	capturedPacket := victim.initPacket(signingKey, wifiPathID)

	srv.handleUDPPacket(udpPacket{data: capturedPacket, addr: victimAddr})
	victimAck := readUDPWithTimeout(t, victimUDP)
	victimAeadTx, _, _ := victim.deriveFromAck(t, victimAck)
	sess := srv.sessions.lookup(victim.keyID)
	if sess == nil {
		t.Fatal("victim's handshake should establish a session")
	}

	// The attacker replays the identical captured packet from elsewhere.
	srv.handleUDPPacket(udpPacket{data: capturedPacket, addr: attackerAddr})
	attackerReply := readUDPWithTimeout(t, attackerUDP)

	if !bytes.Equal(attackerReply, victimAck) {
		t.Fatal("the replayed-to reply must be byte-identical to the original ack, never a freshly-minted one")
	}
	if srv.sessions.count() != 1 {
		t.Fatalf("session count after attacker replay = %d, want 1 (no session hijacked or duplicated)", srv.sessions.count())
	}
	if srv.sessions.lookup(victim.keyID) != sess {
		t.Fatal("the attacker's replay must not have replaced the victim's session")
	}

	// The victim's own path binding and keys must be completely unaffected:
	// a ping sealed under the victim's original keys, from the victim's
	// original address, must still be accepted.
	pingPayload := make([]byte, pingPayloadLen)
	pingFrame := sealClientFrame(victimAeadTx, typePing, wifiPathID, 1, victim.keyID, pingPayload)
	srv.handleUDPPacket(udpPacket{data: pingFrame, addr: victimAddr})
	pong := readUDPWithTimeout(t, victimUDP)
	if pong[4] != typePong {
		t.Fatalf("victim's original session should still work after the attacker's replay, got frameType=%d", pong[4])
	}

	// The attacker's copy of the ack is useless without the victim's
	// private key: independently attempting to derive session keys with the
	// attacker's own (different) private key must fail to open the sealed
	// confirmation inside it.
	attackerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPubBytes := attackerReply[commonHeaderLen : commonHeaderLen+x25519PubKeyLen]
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongShared, err := attackerPriv.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket{clientID: victim.clientID, assignedIP: victim.assignedIP, keyID: victim.keyID}
	wrongRxKey, err := deriveSessionKey(wrongShared, tk, hkdfInfoServerToClient)
	if err != nil {
		t.Fatal(err)
	}
	wrongRx, err := newAESGCM(wrongRxKey)
	if err != nil {
		t.Fatal(err)
	}
	nonceStart := commonHeaderLen + x25519PubKeyLen
	nonce := attackerReply[nonceStart : nonceStart+authFrameNonceLen]
	aad := attackerReply[:nonceStart+authFrameNonceLen]
	ciphertext := attackerReply[nonceStart+authFrameNonceLen:]
	if _, err := wrongRx.Open(nil, nonce, ciphertext, aad); err == nil {
		t.Fatal("the attacker must not be able to derive usable session keys from a replayed ack without the victim's private key")
	}
}

// TestHandshakeFreshTicketForSameClientSupersedesOldSession is the
// legitimate counterpart to the replay tests above: a genuinely new,
// distinct ticket (fresh jti/keyID, control-plane-issued after the fact -
// e.g. the app restarted and re-authenticated) for the same clientID must
// still supersede the old session, exactly as it did before the H-6 fix.
// Only same-jti replay is special-cased; ordinary re-handshake is not.
func TestHandshakeFreshTicketForSameClientSupersedesOldSession(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	var clientID [16]byte
	copy(clientID[:], "same-client-id!!")
	assignedIP := [4]byte{10, 88, 0, 64}

	first := newTestClientHandshakeWithID(t, 64, clientID, assignedIP)
	srv.handleUDPPacket(udpPacket{data: first.initPacket(signingKey, wifiPathID), addr: clientAddr})
	readUDPWithTimeout(t, clientUDP) // first ack

	second := newTestClientHandshakeWithID(t, 164, clientID, assignedIP)
	srv.handleUDPPacket(udpPacket{data: second.initPacket(signingKey, wifiPathID), addr: clientAddr})
	readUDPWithTimeout(t, clientUDP) // second ack

	if srv.sessions.lookup(first.keyID) != nil {
		t.Fatal("the superseded session's old keyID must no longer resolve")
	}
	if srv.sessions.lookup(second.keyID) == nil {
		t.Fatal("the new session should be reachable by its new keyID")
	}
	if srv.sessions.count() != 1 {
		t.Fatalf("session count = %d, want 1 (a fresh ticket for the same client replaces, not duplicates, its session)", srv.sessions.count())
	}
}

// TestHandshakeConcurrentDuplicateInitPacketsEstablishExactlyOneSession
// drives many goroutines processing byte-identical handshake init packets
// (the same jti) concurrently - simulating a UDP-level duplicate, not just
// a client-level timeout retry - and checks beginTicketUse's reservation
// actually prevents the race described in its doc comment: no matter the
// interleaving, exactly one session must exist afterward, every reply seen
// must be byte-identical, and the resulting session's keys must be fully
// usable.
func TestHandshakeConcurrentDuplicateInitPacketsEstablishExactlyOneSession(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 65, [4]byte{10, 88, 0, 65})
	initPacket := client.initPacket(signingKey, wifiPathID)

	const workers = 32
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv.handleUDPPacket(udpPacket{data: initPacket, addr: clientAddr})
		}()
	}
	wg.Wait()

	var replies [][]byte
	for {
		if err := clientUDP.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(buf)
		if err != nil {
			break
		}
		replies = append(replies, buf[:n])
	}

	if len(replies) == 0 {
		t.Fatal("at least one ack should have been sent")
	}
	for i := 1; i < len(replies); i++ {
		if !bytes.Equal(replies[0], replies[i]) {
			t.Fatal("every reply to N concurrent copies of the same handshake must be byte-identical (one real ack, resent)")
		}
	}
	if srv.sessions.count() != 1 {
		t.Fatalf("session count after concurrent duplicates = %d, want exactly 1", srv.sessions.count())
	}

	aeadTx, _, _ := client.deriveFromAck(t, replies[0])
	pingPayload := make([]byte, pingPayloadLen)
	pingFrame := sealClientFrame(aeadTx, typePing, wifiPathID, 1, client.keyID, pingPayload)
	srv.handleUDPPacket(udpPacket{data: pingFrame, addr: clientAddr})
	pong := readUDPWithTimeout(t, clientUDP)
	if pong[4] != typePong {
		t.Fatalf("the session installed by the race should still be fully usable, got frameType=%d", pong[4])
	}
}

func TestProbeEndToEndWithinBudget(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 7, [4]byte{10, 88, 0, 7})
	srv.handleUDPPacket(udpPacket{data: client.initPacket(signingKey, wifiPathID), addr: clientAddr})
	ack := readUDPWithTimeout(t, clientUDP)
	aeadTx, _, _ := client.deriveFromAck(t, ack)

	const requested = 4096
	probePayload := make([]byte, 8)
	binary.BigEndian.PutUint32(probePayload[0:4], uint32(requested))
	binary.BigEndian.PutUint32(probePayload[4:8], uint32(probeMaxChunkBytes))
	probeFrame := sealClientFrame(aeadTx, typeProbe, wifiPathID, 1, client.keyID, probePayload)
	srv.handleUDPPacket(udpPacket{data: probeFrame, addr: clientAddr})

	total := 0
	deadline := time.Now().Add(3 * time.Second)
	for total < requested {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for probe data: got %d of %d bytes", total, requested)
		}
		chunk := readUDPWithTimeout(t, clientUDP)
		if len(chunk) < authFrameHeaderLen+aeadOverhead {
			t.Fatalf("probe chunk too short: %d bytes", len(chunk))
		}
		if chunk[4] != typeProbeData {
			t.Fatalf("expected a typeProbeData chunk, got frameType=%d", chunk[4])
		}
		total += len(chunk) - authFrameHeaderLen - aeadOverhead
	}
	if total != requested {
		t.Fatalf("received %d probe bytes, want exactly %d", total, requested)
	}
}

func TestProbeRejectsUnauthenticatedRequest(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	// No handshake at all: a typeProbe frame referencing a keyID with no
	// established session must get no response whatsoever.
	fakeAEAD := newTestAEAD(t, 5)
	probeFrame := sealClientFrame(fakeAEAD, typeProbe, wifiPathID, 1, 999, make([]byte, 8))
	srv.handleUDPPacket(udpPacket{data: probeFrame, addr: clientAddr})
	assertNoUDPWithinTimeout(t, clientUDP)
}

func TestProbeOnlyRespondsToBoundEndpoint(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 9, [4]byte{10, 88, 0, 9})
	srv.handleUDPPacket(udpPacket{data: client.initPacket(signingKey, wifiPathID), addr: clientAddr})
	ack := readUDPWithTimeout(t, clientUDP)
	aeadTx, _, _ := client.deriveFromAck(t, ack)

	// An uninvolved socket stands in for a would-be reflection/amplification
	// target: nothing in the wire protocol lets a caller redirect a probe
	// reply anywhere but the session's own bound endpoint.
	victim := newTestClientUDP(t)

	probePayload := make([]byte, 8)
	binary.BigEndian.PutUint32(probePayload[0:4], 1024)
	binary.BigEndian.PutUint32(probePayload[4:8], uint32(probeMaxChunkBytes))
	probeFrame := sealClientFrame(aeadTx, typeProbe, wifiPathID, 1, client.keyID, probePayload)
	srv.handleUDPPacket(udpPacket{data: probeFrame, addr: clientAddr})

	readUDPWithTimeout(t, clientUDP) // the legitimate reply
	assertNoUDPWithinTimeout(t, victim)
}

func TestProbeDroppedWhenWorkerPoolIsFull(t *testing.T) {
	signingKey := testSigningKey()
	srv := newTestBoostServer(t, signingKey)
	clientUDP := newTestClientUDP(t)
	clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)

	client := newTestClientHandshake(t, 11, [4]byte{10, 88, 0, 11})
	srv.handleUDPPacket(udpPacket{data: client.initPacket(signingKey, wifiPathID), addr: clientAddr})
	ack := readUDPWithTimeout(t, clientUDP)
	aeadTx, _, _ := client.deriveFromAck(t, ack)

	// Saturate the bounded probe-worker semaphore so the next probe must be
	// dropped rather than spawning an unbounded goroutine.
	for i := 0; i < maxProbeWorkers; i++ {
		srv.probeWorkers <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < maxProbeWorkers; i++ {
			<-srv.probeWorkers
		}
	})

	probePayload := make([]byte, 8)
	binary.BigEndian.PutUint32(probePayload[0:4], 1024)
	binary.BigEndian.PutUint32(probePayload[4:8], uint32(probeMaxChunkBytes))
	probeFrame := sealClientFrame(aeadTx, typeProbe, wifiPathID, 1, client.keyID, probePayload)
	srv.handleUDPPacket(udpPacket{data: probeFrame, addr: clientAddr})

	assertNoUDPWithinTimeout(t, clientUDP)
}
