package carrier

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
)

func TestAnonymousCarrierTokenProofAndSingleUse(t *testing.T) {
	issuer, err := privacytoken.GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	bundle := issuePrivacyToken(t, issuer)
	signer, err := bundle.Signer()
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	verified, err := privacytoken.Verify(
		bundle.PublicToken(), &issuer.PublicKey, mustIssuerKeyID(t, &issuer.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://carrier.test"+H2Path, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "carrier.test"
	request.TLS = &tls.ConnectionState{}
	claims, err := carrierauth.NewRequestClaimsWithOptions(
		request, string(mobility.HTTP2), "winn.invalid:443", verified.Pseudonym,
		"00112233445566778899aabbccddeeff", "x25519-mlkem768",
		signer, time.Now().UTC(),
		carrierauth.RequestOptions{
			AuthorizationMode: carrierauth.AuthModeAnonymousToken,
			ManifestDigest:    carrierauth.LabManifestDigest,
			MaxInnerDatagram:  DefaultMaxDatagram,
			PrivacyProfile:    carrierauth.PrivacyHighRisk,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrierauth.SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	if err := addPrivacyTokenHeader(
		request.Header, carrierauth.AuthModeAnonymousToken,
		tokenPointer(bundle.PublicToken()),
	); err != nil {
		t.Fatal(err)
	}
	requestReplay, err := carrierauth.NewReplayCache(16)
	if err != nil {
		t.Fatal(err)
	}
	tokenReplay, err := privacytoken.NewRedemptionCache(16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	verifier := &carrierauth.RequestVerifier{
		Replay: requestReplay, Suite: "x25519-mlkem768",
		MaxSkew: time.Minute, Now: func() time.Time { return now },
	}
	tokenVerifier := &PrivacyTokenVerifier{
		PublicKey:   &issuer.PublicKey,
		KeyID:       mustIssuerKeyID(t, &issuer.PublicKey),
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		Redemptions: tokenReplay,
		LabMode:     true,
	}
	productionVerifier := *tokenVerifier
	productionVerifier.LabMode = false
	if _, _, err := authenticateCarrierRequest(
		request, string(mobility.HTTP2), "winn.invalid:443", verifier,
		&productionVerifier,
	); err == nil {
		t.Fatal("production carrier accepted an in-memory redemption cache")
	}
	got, principal, err := authenticateCarrierRequest(
		request, string(mobility.HTTP2), "winn.invalid:443", verifier, tokenVerifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	if principal != verified.Pseudonym ||
		got.AuthMode != carrierauth.AuthModeAnonymousToken {
		t.Fatal("anonymous request did not retain its token pseudonym and mode")
	}

	// Even a freshly signed request cannot redeem the same blind token twice.
	second := request.Clone(context.Background())
	second.Header = request.Header.Clone()
	secondClaims, err := carrierauth.NewRequestClaimsWithOptions(
		second, string(mobility.HTTP2), "winn.invalid:443", verified.Pseudonym,
		claims.SessionID, claims.Suite, signer, now,
		carrierauth.RequestOptions{
			AuthorizationMode: carrierauth.AuthModeAnonymousToken,
			ManifestDigest:    claims.Manifest,
			MaxInnerDatagram:  claims.MaxDatagram,
			PrivacyProfile:    claims.Privacy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrierauth.SignRequest(second.Header, secondClaims, signer); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authenticateCarrierRequest(
		second, string(mobility.HTTP2), "winn.invalid:443", verifier, tokenVerifier,
	); err == nil {
		t.Fatal("carrier accepted a second redemption of one privacy token")
	}
}

func TestResolvedAnonymousCredentialCleanupDestroysOnlyOwnedSigner(
	t *testing.T,
) {
	anonymousSeed := bytes.Repeat([]byte{0x51}, 32)
	anonymousSigner, err := pqauth.NewSigner(
		pqauth.MLDSA65, anonymousSeed,
	)
	clear(anonymousSeed)
	if err != nil {
		t.Fatal(err)
	}
	source := &singleAnonymousCredentialSource{
		credential: AnonymousCredential{
			Pseudonym: "anon-owned",
			Signer:    anonymousSigner,
		},
	}
	_, resolved, _, cleanup, err := resolveClientCredential(
		carrierauth.AuthModeAnonymousToken,
		"",
		nil,
		nil,
		source,
	)
	if err != nil || resolved != anonymousSigner {
		t.Fatalf("resolve anonymous credential: %v", err)
	}
	cleanup()
	cleanup()
	if !anonymousSigner.Destroyed() {
		t.Fatal("anonymous credential cleanup retained its signer")
	}

	identitySeed := bytes.Repeat([]byte{0x52}, 32)
	identitySigner, err := pqauth.NewSigner(
		pqauth.MLDSA65, identitySeed,
	)
	clear(identitySeed)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, identityCleanup, err := resolveClientCredential(
		carrierauth.AuthModeIdentity,
		"device-owned",
		identitySigner,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityCleanup()
	if identitySigner.Destroyed() {
		t.Fatal("identity cleanup destroyed caller-owned signer")
	}
	identitySigner.Destroy()
}

type singleAnonymousCredentialSource struct {
	credential AnonymousCredential
	used       bool
}

func (source *singleAnonymousCredentialSource) NextAnonymousCredential() (
	AnonymousCredential,
	error,
) {
	if source.used {
		return AnonymousCredential{},
			errors.New("single credential source exhausted")
	}
	source.used = true
	return source.credential, nil
}

func issuePrivacyToken(t *testing.T, issuer *rsa.PrivateKey) privacytoken.Bundle {
	t.Helper()
	request, state, err := privacytoken.BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	response, err := privacytoken.BlindSign(request, issuer)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := state.Finalize(response)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func mustIssuerKeyID(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	id, err := privacytoken.IssuerKeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func tokenPointer(token privacytoken.Token) *privacytoken.Token {
	return &token
}
