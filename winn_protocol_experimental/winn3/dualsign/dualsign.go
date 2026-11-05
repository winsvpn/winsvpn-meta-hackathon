// Package dualsign implements the Winn v3 dual-signature session attestation:
// two independent signatures (Ed25519 and ML-DSA-65) over the SAME
// session-binding material — the handshake transcript hash — so that peer
// authentication survives the compromise of either algorithm family.
//
// Wire shape and negotiation are specified in docs/DUAL_SIGNATURE_SPEC.md.
// The signed message is domain-separated exactly like every other Winn
// signature: domain || 0x00 || transcriptHash.
package dualsign

import (
	"crypto/ed25519"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"winsvpn.local/winnprotocol/internal/pqauth"
)

// Domain separates the dual-signature attestation from every other signed
// object in the protocol. It is allowlisted in internal/pqauth.
const Domain = "winn3-dual-auth-v1"

// TranscriptHashSize is the size of the binding material (the chain hash h).
const TranscriptHashSize = 32

// Signature sizes, fixed by the algorithms. The driver's frame math and the
// hub's descriptor schema both derive from these, so they are compile-time
// pins, not measurements.
const (
	Ed25519SignatureSize = ed25519.SignatureSize
	Ed25519PublicKeySize = ed25519.PublicKeySize
	// Ed25519PrivateKeySize is the full 64-byte private key (seed||public),
	// the form ed25519.Sign uses. Seeds may be stored as the first 32 bytes.
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	MLDSA65SignatureSize = mldsa65.SignatureSize
	MLDSA65PublicKeySize = mldsa65.PublicKeySize
	MLDSA65SeedSize      = mldsa65.SeedSize
)

// BindMessage builds the exact signed byte string: Domain || 0x00 || hash.
// Ed25519 (below) and pqauth's SignDomainMessage/VerifyDomainMessage construct
// the identical string, so both signatures apply to one byte string.
func BindMessage(transcriptHash []byte) ([]byte, error) {
	if len(transcriptHash) != TranscriptHashSize {
		return nil, errors.New("dualsign: transcript hash must be 32 bytes")
	}
	out := make([]byte, 0, len(Domain)+1+TranscriptHashSize)
	out = append(out, Domain...)
	out = append(out, 0x00)
	out = append(out, transcriptHash...)
	return out, nil
}

// SignEd25519 signs the bound message with a standard Ed25519 private key.
func SignEd25519(private ed25519.PrivateKey, transcriptHash []byte) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("dualsign: ed25519 private key has wrong size")
	}
	bound, err := BindMessage(transcriptHash)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(private, bound), nil
}

// VerifyEd25519 verifies the Ed25519 signature over the bound message.
func VerifyEd25519(public ed25519.PublicKey, transcriptHash, signature []byte) error {
	if len(public) != ed25519.PublicKeySize {
		return errors.New("dualsign: ed25519 public key has wrong size")
	}
	bound, err := BindMessage(transcriptHash)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, bound, signature) {
		return errors.New("dualsign: ed25519 signature verification failed")
	}
	return nil
}

// SignMLDSA65 signs the bound message with a pqauth ML-DSA-65 signer.
// pqauth.SignDomainMessage applies the identical domain||0x00||message
// framing, so the two algorithms sign byte-identical material.
func SignMLDSA65(signer *pqauth.Signer, transcriptHash []byte) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("dualsign: nil ML-DSA signer")
	}
	if len(transcriptHash) != TranscriptHashSize {
		return nil, errors.New("dualsign: transcript hash must be 32 bytes")
	}
	return pqauth.SignDomainMessage(Domain, transcriptHash, signer)
}

// VerifyMLDSA65 verifies the ML-DSA-65 signature over the bound message.
func VerifyMLDSA65(verifier *pqauth.Verifier, transcriptHash, signature []byte) error {
	if verifier == nil {
		return errors.New("dualsign: nil ML-DSA verifier")
	}
	return pqauth.VerifyDomainMessage(Domain, transcriptHash, signature, verifier)
}

// VerifyBoth requires BOTH algorithms to verify, independently, against their
// own public keys. The first failure returned is not privileged order; both
// checks always run so a caller can distinguish "one family broken" from
// "both failed".
func VerifyBoth(
	edPublic ed25519.PublicKey,
	mlVerifier *pqauth.Verifier,
	transcriptHash, edSignature, mlSignature []byte,
) error {
	edErr := VerifyEd25519(edPublic, transcriptHash, edSignature)
	mlErr := VerifyMLDSA65(mlVerifier, transcriptHash, mlSignature)
	switch {
	case edErr != nil && mlErr != nil:
		return errors.New("dualsign: both signature verifications failed")
	case edErr != nil:
		return edErr
	case mlErr != nil:
		return mlErr
	}
	return nil
}