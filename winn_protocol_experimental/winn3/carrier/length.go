package carrier

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// The §4.2 encrypted-length layer.
//
// # What the rule is and why it is normative
//
// A stream carrier has to restore message boundaries. Writing the length in
// front of the message is the obvious way and it is the one thing a stream
// carrier must not do:
//
//	A stream carrier MUST NOT write a cleartext length prefix. It MUST encrypt
//	each length under a separate key and nonce sequence derived from the
//	session — AEAD(k_len, n_i, uint16 len), 2 bytes of plaintext and 18 on the
//	wire — exactly the Shadowsocks-2022 AEAD-length construction, so that the
//	record boundary is not readable and cannot be used to segment the stream.
//
// The reason it is normative rather than advisory: the message format above this
// layer is unconditionally uniform — a PRF-output demux token followed by
// ciphertext and a tag, with no field an observer could predict knowing the
// entire design. A cleartext length would put back a readable field at a fixed
// offset in every record and hand a censor a segmentation oracle: walk the
// stream, count messages, measure the length distribution, confirm the protocol,
// all without holding a key. That is failure F1 rebuilt one layer down, and it
// would be worse than the original, because F1 was in the initiation only and
// this would be in every packet for the life of the connection.
//
// # Where the key comes from, and the one departure from the literal rule
//
// §4.2 says "derived from the session". For the second record onward that is
// achievable and would be marginally better. For the FIRST record it is not, and
// the reason is structural rather than a shortcut: the first record on a stream
// carries the handshake initiation, and at that instant there is no session on
// either side to derive anything from.
//
// Three options were available and two are worse:
//
//   - Frame record 1 differently and switch to session-derived keys afterwards.
//     That gives record 1 a distinguishable shape — precisely a distinctive
//     first-packet fingerprint, on the packet a censor looks at hardest.
//   - Leave record 1's length in the clear and encrypt the rest. Same objection,
//     and it also leaks the initiation's padded length directly.
//   - Key the whole stream from material both ends already hold before the
//     handshake. That is the gateway's admission secret: per gateway, never
//     fleet-wide, already distributed by the control plane's ML-DSA-signed
//     descriptor and already on both ends before the first byte moves.
//
// The third is what this implements, and its scoping is stated rather than
// hidden, exactly as §4.1 scopes the initiation whitening:
//
//	The record boundaries of a stream carrier are hidden exactly as well as
//	that gateway's admission secret is kept, and no better. An adversary
//	holding the secret can segment the stream. Whitening the boundary is
//	therefore not a security boundary; it is a cost boundary, and it moves
//	stream identification from "read the two-byte length in an ASIC at line
//	rate" to "hold a per-gateway secret".
//
// That is the same trade the design already made, against the same adversary,
// with the same rotation path. It is not a new exposure.
//
// # Per-connection salt, and nonce reuse
//
// A key derived from a long-lived secret with a counter starting at zero would
// reuse a (key, nonce) pair on the second connection. So each sender draws a
// 16-byte random salt per connection and mixes it into its own key derivation,
// and sends it once, at the head of its first record. Sixteen bytes of uniform
// random are indistinguishable from the ciphertext that follows them; the salt
// is not a field an observer can find, because there is nothing to find it by.
//
// Each direction is keyed from ITS OWN sender's salt, so a sender can never
// repeat a (key, nonce) pair unless its RNG repeats — and a receiver derives the
// peer's key from the salt the peer sent. No round trip, no negotiation, and no
// shared counter to get subtly wrong.
//
//	prk = HKDF-Extract(SHA-256, ikm = carrier secret, salt = label ‖ senderSalt)
//	km  = HKDF-Expand(prk, "c2s" or "s2c", 36)     = key(32) ‖ nonceSalt(4)
//	n_i = nonceSalt(4) ‖ BE64(i)
//
// The nonce is split the same way core splits its transport nonce, for the same
// reason: a per-direction derived prefix means two directions and two
// connections cannot collide even if a counter were mishandled somewhere.

const (
	// lengthKeyBytes is the ChaCha20-Poly1305 key size.
	lengthKeyBytes = 32

	// lengthNonceSaltBytes is the derived, never-transmitted prefix of the
	// nonce.
	lengthNonceSaltBytes = 4

	// lengthKeyMaterial is what one direction draws from HKDF.
	lengthKeyMaterial = lengthKeyBytes + lengthNonceSaltBytes

	// MinSecretSize is the shortest carrier secret this package will key from.
	// It is a floor against an accidentally-empty secret, not a claim about how
	// the secret was generated; it mirrors core's minAdmissionKeySize.
	MinSecretSize = 32

	// kdfLabel seeds the extract salt. Changing any byte of it produces a stream
	// layer that cannot talk to this one, which is the intent.
	kdfLabel = "winn3 carrier length v1"

	// Direction labels. A stream is keyed differently in each direction so that
	// the two counters are independent and both may start at zero.
	dirClientToGateway = "c2s"
	dirGatewayToClient = "s2c"

	// MaxRecordsPerConnection is the hard ceiling on length records in one
	// direction of one connection.
	//
	// 2^48 records at one million per second is nine years, so this is
	// unreachable in practice and exists for the same reason core's
	// RejectAfterMessages does: the alternative to a hard refusal is a wrap, and
	// a wrapped counter is a reused nonce. There is no "one more record" path.
	MaxRecordsPerConnection = uint64(1) << 48
)

// Role selects which direction label a carrier keys its send direction from.
type Role uint8

const (
	// RoleClient is the end that dials. Its send direction is c2s.
	RoleClient Role = iota
	// RoleGateway is the end that accepts. Its send direction is s2c.
	RoleGateway
)

// String renders the role for error messages.
func (r Role) String() string {
	if r == RoleGateway {
		return "gateway"
	}
	return "client"
}

// sendLabel and recvLabel are the two direction labels for this role. Getting
// these the same way round at both ends is the whole of the direction handling,
// so it lives in one place rather than at two call sites.
func (r Role) sendLabel() string {
	if r == RoleGateway {
		return dirGatewayToClient
	}
	return dirClientToGateway
}

func (r Role) recvLabel() string {
	if r == RoleGateway {
		return dirClientToGateway
	}
	return dirGatewayToClient
}

// lengthCipher seals or opens one direction's length records.
type lengthCipher struct {
	aead      cipher.AEAD
	nonceSalt [lengthNonceSaltBytes]byte
	counter   uint64
}

// newLengthCipher derives one direction's length key from the carrier secret and
// that direction's sender salt.
func newLengthCipher(secret, salt []byte, label string) (*lengthCipher, error) {
	if len(secret) < MinSecretSize {
		return nil, wrap(ErrSecret, "%d bytes, need at least %d", len(secret), MinSecretSize)
	}
	extractSalt := make([]byte, 0, len(kdfLabel)+len(salt))
	extractSalt = append(extractSalt, kdfLabel...)
	extractSalt = append(extractSalt, salt...)

	prk, err := hkdf.Extract(sha256.New, secret, extractSalt)
	if err != nil {
		return nil, wrap(ErrConfig, "hkdf extract: %v", err)
	}
	km, err := hkdf.Expand(sha256.New, prk, label, lengthKeyMaterial)
	if err != nil {
		return nil, wrap(ErrConfig, "hkdf expand: %v", err)
	}
	aead, err := chacha20poly1305.New(km[:lengthKeyBytes])
	if err != nil {
		return nil, wrap(ErrConfig, "aead: %v", err)
	}
	lc := &lengthCipher{aead: aead}
	copy(lc.nonceSalt[:], km[lengthKeyBytes:])
	clear(km)
	clear(prk)
	return lc, nil
}

// nonce builds n_i = nonceSalt(4) ‖ BE64(counter) and advances the counter.
//
// It refuses at MaxRecordsPerConnection rather than wrapping. A wrap would reuse
// a (key, nonce) pair, which for ChaCha20-Poly1305 leaks the XOR of two
// plaintexts and — much worse here — forfeits authentication for the whole key.
func (lc *lengthCipher) nonce() ([chacha20poly1305.NonceSize]byte, error) {
	var n [chacha20poly1305.NonceSize]byte
	if lc.counter >= MaxRecordsPerConnection {
		return n, wrap(ErrStreamExhausted, "%d records", lc.counter)
	}
	copy(n[:lengthNonceSaltBytes], lc.nonceSalt[:])
	binary.BigEndian.PutUint64(n[lengthNonceSaltBytes:], lc.counter)
	lc.counter++
	return n, nil
}

// seal appends the sealed length of a msgLen-byte message to dst.
//
// The plaintext is two bytes and the output is eighteen. There is no associated
// data: the record has no header to bind to, which is the point — a header would
// be the readable field this construction exists to remove.
func (lc *lengthCipher) seal(dst []byte, msgLen int) ([]byte, error) {
	n, err := lc.nonce()
	if err != nil {
		return nil, err
	}
	var plain [2]byte
	binary.BigEndian.PutUint16(plain[:], uint16(msgLen))
	return lc.aead.Seal(dst, n[:], plain[:], nil), nil
}

// openLength opens an eighteen-byte sealed length record.
func (lc *lengthCipher) openLength(record []byte) (int, error) {
	if len(record) != LengthRecordOverhead {
		return 0, wrap(ErrStreamDesync, "record is %d bytes, expected %d",
			len(record), LengthRecordOverhead)
	}
	n, err := lc.nonce()
	if err != nil {
		return 0, err
	}
	plain, err := lc.aead.Open(nil, n[:], record, nil)
	if err != nil {
		// Deliberately does not report which record failed or what the counter
		// was. Nothing here is ever written back to the peer, and an error
		// string that travelled would be a probe oracle.
		return 0, ErrStreamDesync
	}
	return int(binary.BigEndian.Uint16(plain)), nil
}
