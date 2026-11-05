package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

// errWrap formats a local diagnostic around a sentinel. Nothing built here ever
// reaches a peer; see the package doc on silence.
func errWrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// StaticKey is a long-term X25519 identity key pair.
//
// The gateway's public half reaches a client inside the Ed25519-signed
// descriptor the control plane ships; that is classical-only authentication
// today, with the ML-DSA-65 leg added by the dual-signature session
// attestation (docs/DUAL_SIGNATURE_SPEC.md). The client's public half is
// registered with the gateway.
type StaticKey struct {
	priv *ecdh.PrivateKey
}

// GenerateStaticKey draws a new identity key pair from the system CSPRNG.
func GenerateStaticKey() (*StaticKey, error) { return GenerateStaticKeyFrom(rand.Reader) }

// Bytes returns the private scalar, for persistence by a caller that owns the
// key. There is no accessor for a peer's private key because there is no such
// thing.
func (k *StaticKey) Bytes() []byte { return k.priv.Bytes() }

// GenerateStaticKeyFrom draws an identity key pair from an explicit reader.
//
// Randomness is injected rather than reached for, so that known-answer vectors
// are reproducible and so that a caller on a platform with a supervised entropy
// source can supply it. Production callers pass crypto/rand.Reader.
//
// It reads exactly KeySize bytes and calls NewPrivateKey rather than calling
// ecdh's GenerateKey, and that is deliberate. GenerateKey routes through
// internal/randutil.MaybeReadByte, which consumes a random EXTRA byte from the
// reader precisely so that callers cannot depend on determinism — a good
// default, and fatal to a pinned test vector. X25519 needs no rejection
// sampling (every 32-byte string is a valid scalar once clamped), so reading a
// fixed 32 bytes loses nothing.
func GenerateStaticKeyFrom(r io.Reader) (*StaticKey, error) {
	priv, err := privateFrom(r)
	if err != nil {
		return nil, err
	}
	return &StaticKey{priv: priv}, nil
}

func privateFrom(r io.Reader) (*ecdh.PrivateKey, error) {
	var b [KeySize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(b[:])
}

// NewStaticKey adopts an existing 32-byte private scalar.
func NewStaticKey(private []byte) (*StaticKey, error) {
	if len(private) != KeySize {
		return nil, errWrap(ErrConfig, "static private key is %d bytes, need %d", len(private), KeySize)
	}
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, errWrap(ErrConfig, "static private key rejected: %v", err)
	}
	return &StaticKey{priv: priv}, nil
}

// Public returns the 32-byte public key.
func (k *StaticKey) Public() []byte { return k.priv.PublicKey().Bytes() }

// PublicKey is a peer's 32-byte X25519 public key.
type PublicKey struct {
	pub *ecdh.PublicKey
}

// NewPublicKey validates and adopts a 32-byte X25519 public key.
func NewPublicKey(b []byte) (*PublicKey, error) {
	if len(b) != KeySize {
		return nil, errWrap(ErrConfig, "public key is %d bytes, need %d", len(b), KeySize)
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, errWrap(ErrConfig, "public key rejected: %v", err)
	}
	return &PublicKey{pub: pub}, nil
}

// Bytes returns the 32-byte encoding.
func (p *PublicKey) Bytes() []byte { return p.pub.Bytes() }

// Equal reports whether two public keys are the same point encoding.
func (p *PublicKey) Equal(other *PublicKey) bool {
	if p == nil || other == nil {
		return false
	}
	return p.pub.Equal(other.pub)
}

// dh performs X25519.
//
// crypto/ecdh rejects a all-zero shared secret, which is what a low-order or
// otherwise degenerate peer point produces. That rejection is load-bearing: a
// handshake that silently continued with an attacker-forced zero secret would
// authenticate nothing. The error is returned to the caller and, per the
// package contract, must never be signalled to a peer.
func dh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, errWrap(ErrUnauthenticated, "key agreement rejected the peer point")
	}
	return secret, nil
}

// ephemeral is a one-shot X25519 key pair used for a single handshake or a
// single rekey ratchet.
type ephemeral struct {
	priv *ecdh.PrivateKey
}

// generateEphemeral draws a one-shot key pair. See GenerateStaticKeyFrom for
// why this reads a fixed 32 bytes rather than calling ecdh's GenerateKey.
func generateEphemeral(r io.Reader) (*ephemeral, error) {
	priv, err := privateFrom(r)
	if err != nil {
		return nil, err
	}
	return &ephemeral{priv: priv}, nil
}

// ephemeralFromScalar adopts a private scalar an EphemeralKeygen has already
// drawn, so that a codec which owns key generation still produces the same
// ephemeral type as the default path and nothing downstream can tell them
// apart.
func ephemeralFromScalar(b []byte) (*ephemeral, error) {
	if len(b) != KeySize {
		return nil, errWrap(ErrConfig, "ephemeral private key is %d bytes, need %d", len(b), KeySize)
	}
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, errWrap(ErrConfig, "ephemeral private key rejected: %v", err)
	}
	return &ephemeral{priv: priv}, nil
}

func (e *ephemeral) public() []byte { return e.priv.PublicKey().Bytes() }

// EphemeralCodec is the seam for making an on-wire ephemeral public key
// uniformly distributed WITHOUT a key.
//
// It exists because X25519 public keys are not uniform: the field is 2^255-19,
// so the top bit of the last byte is always zero. That is a one-bit constant at
// a fixed offset — the same class of failure as the 0B 00 00 00 this protocol
// replaces, only smaller. In v1 the whitening keystream in admission.go covers
// it, which means the bias is hidden only from an observer who lacks the
// gateway admission key.
//
// The unconditional fix is Elligator2, which maps the point to a uniform
// 32-byte string with no secret involved. It landed here on 2026-08-08 as
// Elligator2Codec (elligator.go) and it did not become a rewrite of
// handshake.go, which is what this seam was for.
//
// identityCodec is the v1 implementation and is a no-op. It remains the
// default: the codec is not negotiated, so both ends must be configured
// together, and that is a deployment decision rather than one this package
// makes.
//
// Whatever a codec does, the transcript binds the bytes it PRODUCED and not the
// point they decode to — handshake.go mixes ephWire — so a codec is a change of
// representation and never a change of key schedule.
type EphemeralCodec interface {
	// EncodePublic renders a 32-byte X25519 public key for the wire.
	EncodePublic(pub []byte) ([]byte, error)
	// DecodePublic recovers a 32-byte X25519 public key from the wire.
	DecodePublic(wire []byte) ([]byte, error)
	// WireSize is the on-wire length this codec produces.
	WireSize() int
}

// EphemeralKeygen is an OPTIONAL extension to EphemeralCodec, for a codec whose
// wire encoding is not defined for every key and which must therefore own key
// generation.
//
// It exists because Elligator2 needs both things: only about half of all X25519
// public keys have a representative, so a codec must be able to redraw; and a
// representative needs sender randomness that a pure EncodePublic has no honest
// way to obtain. See elligator2Codec.EncodePublic for why deriving that
// randomness from the key instead would reintroduce the very detector the codec
// removes.
//
// A codec that does NOT implement this is generated exactly as v1 does:
// 32 bytes from the reader, then EncodePublic. That is the whole of the
// compatibility story, and it is why turning Elligator2 on changes nothing for
// any caller that does not ask for it.
//
// The randomness comes from the caller's reader — the same Config.Rand every
// other draw in this package uses — so a codec implementing this stays
// reproducible under a pinned reader and known-answer vectors remain possible.
type EphemeralKeygen interface {
	// GenerateEphemeral draws a one-shot key pair and returns the 32-byte
	// private scalar together with the WireSize-byte encoding of its public
	// half. It may consume a variable number of bytes from the reader.
	GenerateEphemeral(rand io.Reader) (private, wire []byte, err error)
}

// newEphemeralForCodec draws the ephemeral for one handshake message.
//
// It is the single place the two generation paths meet, so that the choice
// between them cannot drift between the initiation and the response.
func newEphemeralForCodec(cs EphemeralCodec, r io.Reader) (*ephemeral, []byte, error) {
	if kg, ok := cs.(EphemeralKeygen); ok {
		priv, wire, err := kg.GenerateEphemeral(r)
		if err != nil {
			return nil, nil, err
		}
		if len(wire) != cs.WireSize() {
			return nil, nil, errWrap(ErrConfig,
				"codec produced a %d-byte ephemeral field, declared %d", len(wire), cs.WireSize())
		}
		eph, err := ephemeralFromScalar(priv)
		if err != nil {
			return nil, nil, err
		}
		return eph, wire, nil
	}

	eph, err := generateEphemeral(r)
	if err != nil {
		return nil, nil, err
	}
	wire, err := cs.EncodePublic(eph.public())
	if err != nil {
		return nil, nil, err
	}
	return eph, wire, nil
}

type identityCodec struct{}

func (identityCodec) EncodePublic(pub []byte) ([]byte, error) {
	if len(pub) != KeySize {
		return nil, errWrap(ErrConfig, "ephemeral public key is %d bytes, need %d", len(pub), KeySize)
	}
	return pub, nil
}

func (identityCodec) DecodePublic(wire []byte) ([]byte, error) {
	if len(wire) != KeySize {
		return nil, errWrap(ErrShortMessage, "ephemeral field is %d bytes, need %d", len(wire), KeySize)
	}
	return wire, nil
}

func (identityCodec) WireSize() int { return KeySize }

// DefaultEphemeralCodec is the v1 codec: the raw point encoding, whitened by
// admission.go. See EphemeralCodec for the honest scoping of that.
var DefaultEphemeralCodec EphemeralCodec = identityCodec{}
