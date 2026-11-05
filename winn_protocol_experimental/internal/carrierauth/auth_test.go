package carrierauth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
)

func TestRequestAndResponseAuthentication(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	deviceSigner := newSigner(t, pqauth.MLDSA65)
	controllerSigner := newSigner(t, pqauth.MLDSA87)
	registry := registryFor(t, "device-1", deviceSigner)
	controllerVerifier, err := pqauth.NewVerifier(controllerSigner.Algorithm(), controllerSigner.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	controllerSet, err := pqauth.NewVerifierSet(controllerVerifier)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayCache(16)
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		Host:   "vpn.example:443",
		URL:    &url.URL{Scheme: "https", Host: "vpn.example:443", Path: "/masque/winn.invalid/443/"},
		Header: make(http.Header),
	}
	claims, err := NewRequestClaims(request, string(mobility.HTTP3), "winn.invalid:443", "device-1", testSessionID, "x25519-mlkem768", deviceSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, deviceSigner); err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{
		Registry: registry, Replay: replay, Suite: "x25519-mlkem768",
		MaxSkew: time.Minute, Now: func() time.Time { return now },
	}
	verified, err := verifier.Verify(request, string(mobility.HTTP3), "winn.invalid:443", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if verified.SessionID != testSessionID {
		t.Fatal("session binding was lost")
	}
	if verified.Purpose != PurposeData {
		t.Fatalf("default carrier purpose = %q, want %q", verified.Purpose, PurposeData)
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP3), "winn.invalid:443", "device-1"); err != ErrReplay {
		t.Fatalf("replay returned %v, want ErrReplay", err)
	}

	response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	responseClaims, err := NewResponseClaims(http.StatusOK, string(mobility.HTTP3), "controller-1", "x25519-mlkem768", claims, controllerSigner, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignResponse(response.Header, responseClaims, controllerSigner); err != nil {
		t.Fatal(err)
	}
	responseVerifier := &ResponseVerifier{
		Verifiers: controllerSet, ControllerID: "controller-1", Suite: "x25519-mlkem768",
		MaxSkew: time.Minute, Now: func() time.Time { return now },
	}
	if _, err := responseVerifier.Verify(response, claims, string(mobility.HTTP3)); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTamperingRejectedBeforeReplayConsumption(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := newSigner(t, pqauth.MLDSA65)
	registry := registryFor(t, "device-1", signer)
	replay, _ := NewReplayCache(1)
	request, _ := http.NewRequest(http.MethodPost, "https://vpn.example/winn/v2/udp-stream", nil)
	claims, err := NewRequestClaims(request, string(mobility.HTTP2), "winn.invalid:443", "device-1", testSessionID, "x25519-mlkem768", signer, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(HeaderTarget, "attacker.invalid:53")
	verifier := &RequestVerifier{
		Registry: registry, Replay: replay, Suite: "x25519-mlkem768",
		MaxSkew: time.Minute, Now: func() time.Time { return now },
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err == nil {
		t.Fatal("tampered fixed target was accepted")
	}
	if replay.Len(now) != 0 {
		t.Fatal("invalid signature consumed replay capacity")
	}
	request.Header.Set(HeaderTarget, claims.UDPTarget)
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err != nil {
		t.Fatalf("original signed request rejected: %v", err)
	}
}

func TestAuthenticationOnlyPurposeIsSignedAndResponseBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	deviceSigner := newSigner(t, pqauth.MLDSA65)
	controllerSigner := newSigner(t, pqauth.MLDSA87)
	registry := registryFor(t, "device-1", deviceSigner)
	replay, _ := NewReplayCache(2)
	request, _ := http.NewRequest(
		http.MethodConnect,
		"https://vpn.example/masque/winn.invalid/443/",
		nil,
	)
	claims, err := NewRequestClaimsWithOptions(
		request,
		string(mobility.HTTP3),
		"winn.invalid:443",
		"device-1",
		testSessionID,
		"x25519-mlkem768",
		deviceSigner,
		now,
		RequestOptions{
			AuthorizationMode: AuthModeIdentity,
			ManifestDigest:    LabManifestDigest,
			MaxInnerDatagram:  1350,
			PrivacyProfile:    PrivacyStandard,
			SequenceEpoch:     testSessionID,
			Purpose:           PurposeAuthenticateOnly,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, deviceSigner); err != nil {
		t.Fatal(err)
	}
	request.Header.Set(HeaderPurpose, PurposeData)
	verifier := &RequestVerifier{
		Registry: registry,
		Replay:   replay,
		Suite:    "x25519-mlkem768",
		MaxSkew:  time.Minute,
		Now:      func() time.Time { return now },
	}
	if _, err := verifier.Verify(
		request,
		string(mobility.HTTP3),
		"winn.invalid:443",
		"device-1",
	); err == nil {
		t.Fatal("tampered carrier purpose was accepted")
	}
	if replay.Len(now) != 0 {
		t.Fatal("tampered purpose consumed replay state")
	}
	request.Header.Set(HeaderPurpose, PurposeAuthenticateOnly)
	verified, err := verifier.Verify(
		request,
		string(mobility.HTTP3),
		"winn.invalid:443",
		"device-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	responseClaims, err := NewResponseClaims(
		http.StatusOK,
		string(mobility.HTTP3),
		"controller-1",
		"x25519-mlkem768",
		verified,
		controllerSigner,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if responseClaims.Purpose != PurposeAuthenticateOnly {
		t.Fatalf(
			"response purpose = %q, want %q",
			responseClaims.Purpose,
			PurposeAuthenticateOnly,
		)
	}
}

func TestReplayCacheConcurrentSingleUse(t *testing.T) {
	cache, _ := NewReplayCache(10)
	now := time.Unix(1_800_000_000, 0)
	var wait sync.WaitGroup
	results := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- cache.Use("same", now.Add(time.Minute), now)
		}()
	}
	wait.Wait()
	close(results)
	var successes int
	for err := range results {
		if err == nil {
			successes++
		} else if err != ErrReplay {
			t.Fatalf("unexpected cache result: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("nonce accepted %d times, want once", successes)
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := newSigner(t, pqauth.MLDSA65)
	registry := registryFor(t, "device-1", signer)
	replay, _ := NewReplayCache(2)
	request, _ := http.NewRequest(http.MethodPost, "https://vpn.example/winn/v2/udp-stream", nil)
	claims, err := NewRequestClaims(request, string(mobility.HTTP2), "winn.invalid:443", "device-1", testSessionID, "x25519-mlkem768", signer, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{
		Registry: registry, Replay: replay, Suite: "x25519-mlkem768",
		MaxSkew: time.Minute, Now: func() time.Time { return now },
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err == nil {
		t.Fatal("stale timestamp was accepted")
	}
}

func newSigner(t *testing.T, algorithm string) *pqauth.Signer {
	t.Helper()
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	signer, err := pqauth.NewSigner(algorithm, seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func registryFor(t *testing.T, deviceID string, signer *pqauth.Signer) *pqauth.Registry {
	t.Helper()
	document, err := pqauth.RegistryDocument(deviceID, signer)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := pqauth.LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestSignatureEncodingIsStrict(t *testing.T) {
	header := make(http.Header)
	header[HeaderSignature] = []string{
		base64.RawStdEncoding.EncodeToString([]byte("a")),
		base64.RawStdEncoding.EncodeToString([]byte("b")),
	}
	if _, err := signatureHeader(header); err == nil {
		t.Fatal("duplicate signature header accepted")
	}
}

const testSessionID = "00112233445566778899aabbccddeeff"

func TestExactLowerSkewBoundIsAcceptedAndReplayProtected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	skew := time.Minute
	signer := newSigner(t, pqauth.MLDSA65)
	registry := registryFor(t, "device-1", signer)
	replay, err := NewReplayCache(2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://vpn.example/winn/v2/udp-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := NewRequestClaims(
		request, string(mobility.HTTP2), "winn.invalid:443", "device-1",
		testSessionID, "x25519-mlkem768", signer, now.Add(-skew),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{
		Registry: registry, Replay: replay, Suite: "x25519-mlkem768",
		MaxSkew: skew, Now: func() time.Time { return now },
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err != nil {
		t.Fatalf("timestamp at exact lower skew bound rejected: %v", err)
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err != ErrReplay {
		t.Fatalf("replay at exact lower skew bound returned %v, want ErrReplay", err)
	}
}

func TestVerifyAnonymousNilRequestDoesNotPanic(t *testing.T) {
	replay, err := NewReplayCache(1)
	if err != nil {
		t.Fatal(err)
	}
	signer := newSigner(t, pqauth.MLDSA65)
	key, err := pqauth.NewVerifier(signer.Algorithm(), signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{Replay: replay, Suite: "x25519-mlkem768"}
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("VerifyAnonymous panicked on nil request: %v", recovered)
		}
	}()
	_, err = verifier.VerifyAnonymous(
		nil, string(mobility.HTTP2), "winn.invalid:443",
		"device-1", "token-1", key,
	)
	if err == nil {
		t.Fatal("nil request was accepted")
	}
	_, err = verifier.VerifyAnonymous(
		&http.Request{Method: http.MethodPost, Header: make(http.Header)},
		string(mobility.HTTP2), "winn.invalid:443",
		"device-1", "token-1", key,
	)
	if err == nil {
		t.Fatal("request with nil URL was accepted")
	}
}

type revokeOne string

func (r revokeOne) RevokedDevice(deviceID string) bool {
	return deviceID == string(r)
}

func TestRevokedDeviceIsRejectedBeforeReplayConsumption(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := newSigner(t, pqauth.MLDSA65)
	registry := registryFor(t, "device-1", signer)
	replay, err := NewReplayCache(2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://vpn.example/winn/v2/udp-stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := NewRequestClaims(
		request, string(mobility.HTTP2), "winn.invalid:443", "device-1",
		testSessionID, "x25519-mlkem768", signer, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{
		Registry: registry, Replay: replay, Suite: "x25519-mlkem768",
		MaxSkew:     time.Minute,
		Now:         func() time.Time { return now },
		Revocations: revokeOne("device-1"),
	}
	if _, err := verifier.Verify(request, string(mobility.HTTP2), "winn.invalid:443", "device-1"); err != ErrDeviceRevoked {
		t.Fatalf("revoked device returned %v, want ErrDeviceRevoked", err)
	}
	if replay.Len(now) != 0 {
		t.Fatal("revoked device consumed replay capacity")
	}
}

func TestAnonymousRequestVerifiesAgainstCommittedKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := newSigner(t, pqauth.MLDSA65)
	key, err := pqauth.NewVerifier(signer.Algorithm(), signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplayCache(2)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodConnect,
		"https://vpn.example/masque/winn.invalid/443/",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	const pseudonym = "anon-device-1"
	claims, err := NewRequestClaimsWithOptions(
		request,
		string(mobility.HTTP3),
		"winn.invalid:443",
		pseudonym,
		testSessionID,
		"x25519-mlkem768",
		signer,
		now,
		RequestOptions{
			AuthorizationMode: AuthModeAnonymousToken,
			ManifestDigest:    LabManifestDigest,
			MaxInnerDatagram:  1350,
			PrivacyProfile:    PrivacyStandard,
			SequenceEpoch:     testSessionID,
			Purpose:           PurposeData,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(request.Header, claims, signer); err != nil {
		t.Fatal(err)
	}
	verifier := &RequestVerifier{
		Replay:  replay,
		Suite:   "x25519-mlkem768",
		MaxSkew: time.Minute,
		Now:     func() time.Time { return now },
	}
	verified, err := verifier.VerifyAnonymous(
		request, string(mobility.HTTP3), "winn.invalid:443",
		pseudonym, "token-1", key,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.AuthMode != AuthModeAnonymousToken || verified.DeviceID != pseudonym {
		t.Fatalf("anonymous claims: mode=%q device=%q", verified.AuthMode, verified.DeviceID)
	}
	if _, err := verifier.VerifyAnonymous(
		request, string(mobility.HTTP3), "winn.invalid:443",
		pseudonym, "token-1", key,
	); err != ErrReplay {
		t.Fatalf("anonymous replay returned %v, want ErrReplay", err)
	}
}

func TestReplayCacheAtLimitRejectsNewNonce(t *testing.T) {
	cache, err := NewReplayCache(1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	if err := cache.Use("a", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := cache.Use("b", now.Add(time.Minute), now); err != ErrReplayAtLimit {
		t.Fatalf("second nonce returned %v, want ErrReplayAtLimit", err)
	}
}
