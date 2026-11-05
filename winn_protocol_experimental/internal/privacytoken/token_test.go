package privacytoken

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
)

func TestBlindIssueRedeemAndReplayProtection(t *testing.T) {
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(request.BlindedMessage, TokenFormat) ||
		strings.Contains(request.BlindedMessage, "auth_public_key") {
		t.Fatal("blind issue request exposes token payload")
	}
	response, err := BlindSign(request, issuer)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := bundle.Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	verified, err := Verify(bundle.Token, &issuer.PublicKey, keyID)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes := signer.PublicBytes()
	encodedPublic := base64.StdEncoding.EncodeToString(publicBytes)
	clear(publicBytes)
	if verified.Pseudonym == "" ||
		verified.Payload.AuthAlgorithm != signer.Algorithm() ||
		verified.Payload.AuthPublicKey != encodedPublic {
		t.Fatalf("verified token binding = %#v", verified)
	}
	_, firstSeed, err := bundle.SecretMaterial()
	if err != nil {
		t.Fatal(err)
	}
	_, secondSeed, err := bundle.SecretMaterial()
	if err != nil {
		clear(firstSeed)
		t.Fatal(err)
	}
	if len(firstSeed) != 32 || len(secondSeed) != 32 ||
		&firstSeed[0] == &secondSeed[0] {
		clear(firstSeed)
		clear(secondSeed)
		t.Fatal("bundle did not return unique owned secret material")
	}
	clear(firstSeed)
	var combined byte
	for _, current := range secondSeed {
		combined |= current
	}
	clear(secondSeed)
	if combined == 0 {
		t.Fatal("clearing one bundle seed changed another")
	}
	cache, err := NewRedemptionCache(4)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := cache.Use(verified.TokenID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Use(verified.TokenID, now.Add(time.Hour), now); err == nil {
		t.Fatal("privacy token replay was accepted")
	}
	encoded, err := EncodeTokenHeader(bundle.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || len(encoded) > maxEncodedObject {
		t.Fatalf("encoded header length %d", len(encoded))
	}
	t.Logf("MEASURED MLDSA65 EncodeTokenHeader length=%d maxEncodedObject=%d", len(encoded), maxEncodedObject)
	decoded, err := DecodeTokenHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != bundle.Token {
		t.Fatal("token header round-trip changed the token")
	}
}

func TestMemoryRedemptionStoreIsAtomicAndLabOnly(t *testing.T) {
	cache, err := NewRedemptionCache(64)
	if err != nil {
		t.Fatal(err)
	}
	if IsDurableRedemptionStore(cache) {
		t.Fatal("in-memory redemption cache claimed production durability")
	}
	var successes atomic.Int32
	var replays atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := cache.Redeem(
				context.Background(), strings.Repeat("a", 64),
				time.Now().UTC().Add(time.Hour),
			)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAlreadyRedeemed):
				replays.Add(1)
			default:
				t.Errorf("unexpected redemption error: %v", err)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || replays.Load() != 31 {
		t.Fatalf(
			"atomic redemption outcomes success=%d replay=%d",
			successes.Load(), replays.Load(),
		)
	}
}

func TestIssuerRSAProfileIsExactAcrossEntryPoints(t *testing.T) {
	if _, err := GenerateIssuerKey(3500); err == nil {
		t.Fatal("non-frozen RSA size was generated")
	}
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	badPublic := issuer.PublicKey
	badPublic.E = 3
	if _, err := IssuerKeyID(&badPublic); err == nil {
		t.Fatal("non-65537 issuer exponent produced a key ID")
	}
	badDER, err := x509.MarshalPKIXPublicKey(&badPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIssuerPublicKeyDER(badDER); err == nil {
		t.Fatal("non-65537 DER issuer key was parsed")
	}
	badPrivate := *issuer
	badPrivate.PublicKey = badPublic
	if _, _, err := MarshalIssuerKeys(&badPrivate); err == nil {
		t.Fatal("non-65537 issuer private key was marshaled")
	}
	if _, err := BlindSign(IssueRequest{}, &badPrivate); err == nil {
		t.Fatal("non-65537 issuer private key blind-signed")
	}
}

func TestTokenTamperingAndWrongIssuerFailClosed(t *testing.T) {
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	response, err := BlindSign(request, issuer)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := IssuerKeyID(&issuer.PublicKey)
	tampered := bundle.Token
	signature, err := base64.StdEncoding.DecodeString(tampered.Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[len(signature)-1] ^= 1
	tampered.Signature = base64.StdEncoding.EncodeToString(signature)
	if _, err := Verify(tampered, &issuer.PublicKey, keyID); err == nil {
		t.Fatal("tampered token verified")
	}
	otherIssuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyID, _ := IssuerKeyID(&otherIssuer.PublicKey)
	if _, err := Verify(bundle.Token, &otherIssuer.PublicKey, otherKeyID); err == nil {
		t.Fatal("token verified under a different issuer")
	}
}

func TestIssueResponseKeySubstitutionRejected(t *testing.T) {
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	response, err := BlindSign(request, issuer)
	if err != nil {
		t.Fatal(err)
	}
	response.TokenKeyID = strings.Repeat("0", 64)
	if _, err := state.Finalize(response); err == nil {
		t.Fatal("substituted issuer key ID accepted")
	}
}

func TestPayloadWithoutSignatureRejectsOversizeAndNonCanonical(t *testing.T) {
	huge := Payload{
		Format:        TokenFormat,
		TokenKeyID:    "aa",
		Nonce:         "bb",
		AuthAlgorithm: "cc",
		AuthPublicKey: strings.Repeat("A", maxEncodedObject),
	}
	hugeJSON, err := json.Marshal(huge)
	if err != nil {
		t.Fatal(err)
	}
	oversizePrepared := append(make([]byte, preparedPrefix), hugeJSON...)
	if len(oversizePrepared) <= maxEncodedObject {
		t.Fatalf("oversize fixture length %d is not above maxEncodedObject", len(oversizePrepared))
	}
	_, err = payloadWithoutSignature(Token{
		PreparedMessage: base64.StdEncoding.EncodeToString(oversizePrepared),
	})
	if err == nil || err.Error() != "invalid privacy token message" {
		t.Fatalf("oversize prepared message err=%v", err)
	}
	payload := Payload{
		Format:        TokenFormat,
		TokenKeyID:    "aa",
		Nonce:         "bb",
		AuthAlgorithm: "cc",
		AuthPublicKey: "dd",
	}
	compact, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(payload, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(compact, indented) {
		t.Fatal("indent control produced identical JSON")
	}
	indentedPrepared := append(make([]byte, preparedPrefix), indented...)
	if _, err := payloadWithoutSignature(Token{
		PreparedMessage: base64.StdEncoding.EncodeToString(indentedPrepared),
	}); err == nil {
		t.Fatal("non-canonical payload accepted")
	}
	compactPrepared := append(make([]byte, preparedPrefix), compact...)
	got, err := payloadWithoutSignature(Token{
		PreparedMessage: base64.StdEncoding.EncodeToString(compactPrepared),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != payload {
		t.Fatalf("canonical payload = %#v", got)
	}
}

func TestValidateKeyWindowHalfOpen(t *testing.T) {
	notBefore := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	if err := ValidateKeyWindow(time.Time{}, notAfter, notBefore); err == nil {
		t.Fatal("zero notBefore accepted")
	}
	if err := ValidateKeyWindow(notBefore, notBefore, notBefore); err == nil {
		t.Fatal("empty window accepted")
	}
	if err := ValidateKeyWindow(notBefore, notAfter, notBefore); err != nil {
		t.Fatalf("inclusive start rejected: %v", err)
	}
	if err := ValidateKeyWindow(notBefore, notAfter, notAfter); err == nil {
		t.Fatal("exclusive end accepted")
	}
	if err := ValidateKeyWindow(notBefore, notAfter, notBefore.Add(-time.Nanosecond)); err == nil {
		t.Fatal("timestamp before window accepted")
	}
}

func TestNewRedemptionCacheBoundsAndCapacity(t *testing.T) {
	if _, err := NewRedemptionCache(0); err == nil {
		t.Fatal("maxEntries 0 accepted")
	}
	if _, err := NewRedemptionCache(1_000_001); err == nil {
		t.Fatal("maxEntries 1000001 accepted")
	}
	cache, err := NewRedemptionCache(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := cache.Use("token-a", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Use("token-b", now.Add(time.Hour), now); err == nil {
		t.Fatal("full replay cache accepted another token")
	}
}

func TestBlindIssueMLDSA87HeaderFitsBudget(t *testing.T) {
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	request, state, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	response, err := BlindSign(request, issuer)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTokenHeader(bundle.Token)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > maxEncodedObject {
		t.Fatalf("ML-DSA-87 header length %d exceeds maxEncodedObject %d", len(encoded), maxEncodedObject)
	}
	t.Logf("MEASURED MLDSA87 EncodeTokenHeader length=%d maxEncodedObject=%d", len(encoded), maxEncodedObject)
	keyID, err := IssuerKeyID(&issuer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(bundle.Token, &issuer.PublicKey, keyID); err != nil {
		t.Fatal(err)
	}
}
