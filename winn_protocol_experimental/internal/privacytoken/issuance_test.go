package privacytoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

func TestIssueAuthorizationBindsBlindRequestAndRejectsReplay(t *testing.T) {
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "issuance-device-1"
	document, err := pqauth.RegistryDocument(deviceID, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	if err := securefile.AtomicWrite(registryPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := pqauth.LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	issue, state, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	response, err := BlindSign(issue, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Finalize(response); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://issuer.test"+IssuePath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := SignIssueAuthorization(request, issue, deviceID, signer, now); err != nil {
		t.Fatal(err)
	}
	replay, err := carrierauth.NewReplayCache(8)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &IssueAuthorizationVerifier{
		Registry: registry, Replay: replay, MaxSkew: time.Minute,
		Now: func() time.Time { return now },
	}
	if _, err := verifier.Verify(request, issue, deviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(request, issue, deviceID); err == nil {
		t.Fatal("privacy-token issue authorization replay was accepted")
	}

	tampered := issue
	tampered.BlindedMessage += "A"
	freshReplay, _ := carrierauth.NewReplayCache(8)
	verifier.Replay = freshReplay
	if _, err := verifier.Verify(request, tampered, deviceID); err == nil {
		t.Fatal("authorization signature accepted a substituted blind request")
	}
}

func TestIssueRequestDigestMatchesCanonicalJSON(t *testing.T) {
	issue := IssueRequest{
		Format: IssueFormat, TokenKeyID: "ab", BlindedMessage: "cd",
	}
	got, err := issueRequestDigest(issue)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(issue)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("digest=%s want=%s", got, want)
	}
	if len(got) != sha256.Size*2 {
		t.Fatalf("digest length %d", len(got))
	}
}

// TestIssueAuthorizationAcceptsInclusiveSkewBound pins the boundary
// carrierauth already handles: at now == timestamp+MaxSkew the
// timestamp is still inside the acceptance window, so a first use
// must succeed (and its replay must still be refused) instead of
// failing in ReplayCache.Use as an already-expired entry.
func TestIssueAuthorizationAcceptsInclusiveSkewBound(t *testing.T) {
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	signer, err := pqauth.NewSigner(pqauth.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "issuance-device-1"
	document, err := pqauth.RegistryDocument(deviceID, signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	if err := securefile.AtomicWrite(registryPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := pqauth.LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := GenerateIssuerKey(3072)
	if err != nil {
		t.Fatal(err)
	}
	issue, _, err := BeginIssue(&issuer.PublicKey, pqauth.MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		"https://issuer.test"+IssuePath, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	signNow := time.UnixMilli(1767225600000).UTC()
	if err := SignIssueAuthorization(request, issue, deviceID, signer, signNow); err != nil {
		t.Fatal(err)
	}
	replay, err := carrierauth.NewReplayCache(8)
	if err != nil {
		t.Fatal(err)
	}
	bound := signNow.Add(time.Minute)
	verifier := &IssueAuthorizationVerifier{
		Registry: registry, Replay: replay, MaxSkew: time.Minute,
		Now: func() time.Time { return bound },
	}
	if _, err := verifier.Verify(request, issue, deviceID); err != nil {
		t.Fatalf("first use at inclusive skew bound rejected: %v", err)
	}
	if _, err := verifier.Verify(request, issue, deviceID); err == nil {
		t.Fatal("replay at the skew bound was accepted")
	}
}
