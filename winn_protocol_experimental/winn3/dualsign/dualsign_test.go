package dualsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"winsvpn.local/winnprotocol/internal/pqauth"
)

func hr(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, TranscriptHashSize)
	if _, err := rand.Read(h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSizes(t *testing.T) {
	if Ed25519SignatureSize != 64 {
		t.Fatalf("ed25519 signature size %d, want 64", Ed25519SignatureSize)
	}
	if MLDSA65SignatureSize != 3309 {
		t.Fatalf("ML-DSA-65 signature size %d, want 3309", MLDSA65SignatureSize)
	}
}

func TestRoundTripBoth(t *testing.T) {
	h := hr(t)
	// Ed25519 pair
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSig, err := SignEd25519(epriv, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEd25519(epub, h, edSig); err != nil {
		t.Fatalf("ed25519 round trip: %v", err)
	}
	// ML-DSA-65 pair (pqauth)
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	verifier, err := pqauth.NewVerifier(pqauth.MLDSA65, signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	mlSig, err := SignMLDSA65(signer, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMLDSA65(verifier, h, mlSig); err != nil {
		t.Fatalf("mldsa65 round trip: %v", err)
	}
	if err := VerifyBoth(epub, verifier, h, edSig, mlSig); err != nil {
		t.Fatalf("verify both: %v", err)
	}
}

func TestTamperTranscriptRejectsBoth(t *testing.T) {
	h := hr(t)
	epub, epriv, _ := ed25519.GenerateKey(rand.Reader)
	edSig, _ := SignEd25519(epriv, h)
	seed, _ := pqauth.GenerateSeed()
	signer, _ := pqauth.NewSigner(pqauth.MLDSA65, seed)
	defer signer.Destroy()
	verifier, _ := pqauth.NewVerifier(pqauth.MLDSA65, signer.PublicBytes())
	mlSig, _ := SignMLDSA65(signer, h)

	tampered := append([]byte(nil), h...)
	tampered[0] ^= 0x01
	if err := VerifyEd25519(epub, tampered, edSig); err == nil {
		t.Fatal("ed25519 accepted a tampered transcript")
	}
	if err := VerifyMLDSA65(verifier, tampered, mlSig); err == nil {
		t.Fatal("mldsa65 accepted a tampered transcript")
	}
}

func TestTamperSignatureRejects(t *testing.T) {
	h := hr(t)
	epub, epriv, _ := ed25519.GenerateKey(rand.Reader)
	edSig, _ := SignEd25519(epriv, h)
	seed, _ := pqauth.GenerateSeed()
	signer, _ := pqauth.NewSigner(pqauth.MLDSA65, seed)
	defer signer.Destroy()
	verifier, _ := pqauth.NewVerifier(pqauth.MLDSA65, signer.PublicBytes())
	mlSig, _ := SignMLDSA65(signer, h)

	badEd := append([]byte(nil), edSig...)
	badEd[len(badEd)-1] ^= 0x01
	if err := VerifyEd25519(epub, h, badEd); err == nil {
		t.Fatal("ed25519 accepted a flipped signature bit")
	}
	badMl := append([]byte(nil), mlSig...)
	badMl[0] ^= 0x01
	if err := VerifyMLDSA65(verifier, h, badMl); err == nil {
		t.Fatal("mldsa65 accepted a flipped signature bit")
	}
}

func TestWrongKeyRejects(t *testing.T) {
	h := hr(t)
	_, epriv, _ := ed25519.GenerateKey(rand.Reader)
	edSig, _ := SignEd25519(epriv, h)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyEd25519(otherPub, h, edSig); err == nil {
		t.Fatal("ed25519 accepted a signature under the wrong key")
	}
	seed, _ := pqauth.GenerateSeed()
	signer, _ := pqauth.NewSigner(pqauth.MLDSA65, seed)
	defer signer.Destroy()
	mlSig, _ := SignMLDSA65(signer, h)
	otherSeed, _ := pqauth.GenerateSeed()
	other, _ := pqauth.NewSigner(pqauth.MLDSA65, otherSeed)
	defer other.Destroy()
	otherVerifier, _ := pqauth.NewVerifier(pqauth.MLDSA65, other.PublicBytes())
	if err := VerifyMLDSA65(otherVerifier, h, mlSig); err == nil {
		t.Fatal("mldsa65 accepted a signature under the wrong key")
	}
}

func TestDomainSeparation(t *testing.T) {
	h := hr(t)
	seed, _ := pqauth.GenerateSeed()
	signer, _ := pqauth.NewSigner(pqauth.MLDSA65, seed)
	defer signer.Destroy()
	verifier, _ := pqauth.NewVerifier(pqauth.MLDSA65, signer.PublicBytes())
	otherDomain := "winn-carrier-auth/v3"
	sig, err := pqauth.SignDomainMessage(otherDomain, h, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMLDSA65(verifier, h, sig); err == nil {
		t.Fatal("dualsign accepted a signature minted under a different domain")
	}
}

func TestBindMessageShape(t *testing.T) {
	h := hr(t)
	bound, err := BindMessage(h)
	if err != nil {
		t.Fatal(err)
	}
	want := len(Domain) + 1 + TranscriptHashSize
	if len(bound) != want {
		t.Fatalf("bound message len %d, want %d", len(bound), want)
	}
	if !bytes.Equal(bound[:len(Domain)], []byte(Domain)) {
		t.Fatal("bound message does not start with the domain")
	}
	if bound[len(Domain)] != 0x00 {
		t.Fatal("missing domain separator")
	}
	if !bytes.Equal(bound[len(Domain)+1:], h) {
		t.Fatal("bound message does not carry the transcript hash verbatim")
	}
}