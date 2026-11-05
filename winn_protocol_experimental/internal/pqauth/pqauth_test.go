package pqauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const pqTestPeer = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="

func TestSignerDestroyClearsAndDisablesPrivateKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x6d}, 32)
	signer, err := NewSigner(MLDSA65, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicOwned := signer.publicKey
	signature, err := SignDomainMessage(
		CarrierSignatureDomain, []byte("before destroy"), signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(signature)
	signer.Destroy()
	signer.Destroy()
	if !signer.Destroyed() ||
		signer.Algorithm() != "" ||
		len(signer.PublicBytes()) != 0 ||
		!allZeroTestBytes(publicOwned) {
		t.Fatal("destroyed signer retained callable or public material")
	}
	if _, err := SignDomainMessage(
		CarrierSignatureDomain, []byte("after destroy"), signer,
	); err == nil {
		t.Fatal("destroyed signer produced a signature")
	}
}

func TestSignerDestroySerializesWithConcurrentSigning(t *testing.T) {
	seed := bytes.Repeat([]byte{0x39}, 32)
	signer, err := NewSigner(MLDSA65, seed)
	clear(seed)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			<-start
			signature, signErr := SignDomainMessage(
				CarrierSignatureDomain,
				[]byte("concurrent destroy"),
				signer,
			)
			if signErr == nil {
				clear(signature)
			}
		}()
	}
	close(start)
	signer.Destroy()
	group.Wait()
	if !signer.Destroyed() {
		t.Fatal("concurrently destroyed signer remained live")
	}
}

func TestRequestAndResponseAuthenticationAllProfiles(t *testing.T) {
	for _, suite := range protocol.SupportedSuites() {
		t.Run(suite, func(t *testing.T) {
			algorithm := protocol.RequiredAuthAlgorithm(suite)
			deviceSigner := signerFor(t, algorithm, 0x11)
			controllerSigner := signerFor(t, algorithm, 0x22)
			deviceVerifier := verifierFor(t, deviceSigner)
			controllerVerifier := verifierFor(t, controllerSigner)

			request := unsignedRequest(suite)
			if err := SignRequest(&request, deviceSigner); err != nil {
				t.Fatal(err)
			}
			if err := protocol.ValidateRequest(request); err != nil {
				t.Fatalf("signed request is invalid: %v", err)
			}
			if err := VerifyRequest(request, deviceVerifier); err != nil {
				t.Fatalf("request signature did not verify: %v", err)
			}

			now := time.Now().UTC()
			psk := bytes.Repeat([]byte{0x33}, 32)
			response := protocol.RekeyResponse{
				Version:       protocol.Version,
				Suite:         suite,
				ControllerID:  request.ControllerID,
				DeviceID:      request.DeviceID,
				PeerPublicKey: request.PeerPublicKey,
				RequestID:     request.RequestID,
				Nonce:         request.Nonce,
				Generation:    1,
				KeyID: protocol.KeyID(
					request.ControllerID,
					suite,
					request.DeviceID,
					request.PeerPublicKey,
					1,
					psk,
				),
				PresharedKey: base64.StdEncoding.EncodeToString(psk),
				IssuedAt:     now.Format(time.RFC3339Nano),
				ExpiresAt:    now.Add(time.Hour).Format(time.RFC3339Nano),
				Capabilities: protocol.RequiredCapabilities(suite),
			}
			if err := SignResponse(&response, controllerSigner); err != nil {
				t.Fatal(err)
			}
			if err := VerifyResponse(response, controllerVerifier); err != nil {
				t.Fatalf("response signature did not verify: %v", err)
			}
			decoded, err := protocol.ValidateResponse(request, response, now)
			if err != nil {
				t.Fatalf("signed response is invalid: %v", err)
			}
			clear(decoded)
			clear(psk)
		})
	}
}

func TestSignaturesBindEverySecurityRelevantField(t *testing.T) {
	signer := signerFor(t, MLDSA65, 0x44)
	verifier := verifierFor(t, signer)
	request := unsignedRequest(protocol.SuiteX25519MLKEM768)
	if err := SignRequest(&request, signer); err != nil {
		t.Fatal(err)
	}
	signature, err := decodeSignature(request.AuthSignature, verifier.signatureSize)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signature)

	// RequestSigningMessage binds these fields. The previous body of this
	// test only mutated ControllerID, CurrentGeneration, and the signature
	// bytes — the test name claimed "every" field.
	cases := []struct {
		name   string
		mutate func(*protocol.RekeyRequest)
	}{
		{"version", func(r *protocol.RekeyRequest) { r.Version = "winn/1" }},
		{"suite", func(r *protocol.RekeyRequest) { r.Suite = protocol.SuiteP256MLKEM768 }},
		{"controller_id", func(r *protocol.RekeyRequest) { r.ControllerID = "other-controller" }},
		{"device_id", func(r *protocol.RekeyRequest) { r.DeviceID = "other-device" }},
		{"peer_public_key", func(r *protocol.RekeyRequest) { r.PeerPublicKey = flipBase64Byte(t, r.PeerPublicKey) }},
		{"request_id", func(r *protocol.RekeyRequest) { r.RequestID = r.RequestID[:len(r.RequestID)-1] + "A" }},
		{"nonce", func(r *protocol.RekeyRequest) { r.Nonce = r.Nonce[:len(r.Nonce)-1] + "A" }},
		{"generation", func(r *protocol.RekeyRequest) { r.CurrentGeneration++ }},
		{"capabilities", func(r *protocol.RekeyRequest) {
			r.Capabilities = append(append([]string(nil), r.Capabilities...), "extra-capability")
		}},
		{"auth_algorithm", func(r *protocol.RekeyRequest) { r.AuthAlgorithm = MLDSA87 }},
		{"auth_key_id", func(r *protocol.RekeyRequest) { r.AuthKeyID = strings.Repeat("a", 64) }},
		{"signature", func(r *protocol.RekeyRequest) { r.AuthSignature = flipBase64Byte(t, r.AuthSignature) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := request
			tampered.Capabilities = append([]string(nil), request.Capabilities...)
			tc.mutate(&tampered)
			if err := VerifyRequest(tampered, verifier); err == nil {
				t.Fatalf("VerifyRequest accepted a changed %s", tc.name)
			}
			if tc.name == "signature" {
				return
			}
			message, err := protocol.RequestSigningMessage(tampered)
			if err != nil {
				t.Fatal(err)
			}
			if verifier.verify(message, signature) {
				t.Fatalf("ML-DSA verify accepted a changed %s", tc.name)
			}
		})
	}
}

func TestValidClassicalIdentityCannotSubstitutePQKey(t *testing.T) {
	correctSigner := signerFor(t, MLDSA87, 0x55)
	wrongSigner := signerFor(t, MLDSA87, 0x66)
	correctVerifier := verifierFor(t, correctSigner)
	request := unsignedRequest(protocol.SuiteP384MLKEM1024)
	if err := SignRequest(&request, wrongSigner); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(request, correctVerifier); err == nil {
		t.Fatal("request signed by an unregistered PQ key was accepted")
	}
}

func TestRandomizedMLDSASignaturesBothVerify(t *testing.T) {
	signer := signerFor(t, MLDSA65, 0x77)
	verifier := verifierFor(t, signer)
	first := unsignedRequest(protocol.SuiteX25519MLKEM768)
	second := first
	if err := SignRequest(&first, signer); err != nil {
		t.Fatal(err)
	}
	if err := SignRequest(&second, signer); err != nil {
		t.Fatal(err)
	}
	if first.AuthSignature == second.AuthSignature {
		t.Fatal("randomized ML-DSA signatures unexpectedly matched")
	}
	if err := VerifyRequest(first, verifier); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(second, verifier); err != nil {
		t.Fatal(err)
	}
	digestFirst, err := protocol.RequestDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	digestSecond, err := protocol.RequestDigest(second)
	if err != nil {
		t.Fatal(err)
	}
	if digestFirst != digestSecond {
		t.Fatal("idempotency digest must not depend on randomized signature bytes")
	}
}

func TestRegistrySupportsOverlappingKeysForRotation(t *testing.T) {
	first := signerFor(t, MLDSA65, 0x31)
	second := signerFor(t, MLDSA65, 0x32)
	strong := signerFor(t, MLDSA87, 0x33)
	document, err := RegistryDocument("device-rotate-1", first, second, strong)
	if err != nil {
		t.Fatal(err)
	}
	if document.Format != registryFormat || len(document.Devices["device-rotate-1"][MLDSA65]) != 2 {
		t.Fatalf("unexpected registry document: %+v", document)
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := securefile.AtomicWrite(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []*Signer{first, second, strong} {
		verifier, err := registry.Verifier("device-rotate-1", signer.Algorithm(), signer.KeyID())
		if err != nil {
			t.Fatal(err)
		}
		if verifier.KeyID() != signer.KeyID() {
			t.Fatal("registry returned the wrong overlapping key")
		}
	}
	if _, err := registry.Verifier("device-rotate-1", MLDSA65, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unregistered overlapping key ID was accepted")
	}
}

func TestSignRequestLeavesRequestUnchangedOnFailure(t *testing.T) {
	signer := signerFor(t, MLDSA65, 0x11)
	request := unsignedRequest(protocol.SuiteX25519MLKEM768)
	request.AuthAlgorithm = "keep-alg"
	request.AuthKeyID = "keep-id"
	request.AuthSignature = "keep-sig"
	signer.Destroy()
	if err := SignRequest(&request, signer); err == nil {
		t.Fatal("destroyed signer signed a request")
	}
	if request.AuthAlgorithm != "keep-alg" || request.AuthKeyID != "keep-id" || request.AuthSignature != "keep-sig" {
		t.Fatalf("SignRequest mutated the request on failure: alg=%q key=%q sig=%q",
			request.AuthAlgorithm, request.AuthKeyID, request.AuthSignature)
	}

	live := signerFor(t, MLDSA65, 0x12)
	if err := SignRequest(nil, live); err == nil {
		t.Fatal("nil request was signed")
	}
	untouched := unsignedRequest(protocol.SuiteX25519MLKEM768)
	untouched.AuthAlgorithm = "keep-alg"
	if err := SignRequest(&untouched, nil); err == nil {
		t.Fatal("nil signer signed a request")
	}
	if untouched.AuthAlgorithm != "keep-alg" || untouched.AuthKeyID != "" || untouched.AuthSignature != "" {
		t.Fatalf("SignRequest mutated the request for a nil signer: alg=%q key=%q sig=%q",
			untouched.AuthAlgorithm, untouched.AuthKeyID, untouched.AuthSignature)
	}
}

func TestSignResponseLeavesResponseUnchangedOnFailure(t *testing.T) {
	signer := signerFor(t, MLDSA65, 0x13)
	now := time.Now().UTC()
	response := protocol.RekeyResponse{
		Version:       protocol.Version,
		Suite:         protocol.SuiteX25519MLKEM768,
		ControllerID:  "controller-1",
		DeviceID:      "device-1",
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339Nano),
		AuthAlgorithm: "keep-alg",
		AuthKeyID:     "keep-id",
		AuthSignature: "keep-sig",
	}
	signer.Destroy()
	if err := SignResponse(&response, signer); err == nil {
		t.Fatal("destroyed signer signed a response")
	}
	if response.AuthAlgorithm != "keep-alg" || response.AuthKeyID != "keep-id" || response.AuthSignature != "keep-sig" {
		t.Fatalf("SignResponse mutated the response on failure: alg=%q key=%q sig=%q",
			response.AuthAlgorithm, response.AuthKeyID, response.AuthSignature)
	}
}

func TestVerifyRequestAndResponseRejectNilVerifier(t *testing.T) {
	request := unsignedRequest(protocol.SuiteX25519MLKEM768)
	if err := VerifyRequest(request, nil); err == nil {
		t.Fatal("nil verifier accepted a request")
	}
	response := protocol.RekeyResponse{AuthAlgorithm: MLDSA65, AuthKeyID: strings.Repeat("a", 64)}
	if err := VerifyResponse(response, nil); err == nil {
		t.Fatal("nil verifier accepted a response")
	}
}

func TestRegistryAndVerifierSetRejectNilReceiver(t *testing.T) {
	var registry *Registry
	if _, err := registry.Verifier("device-1", MLDSA65, strings.Repeat("a", 64)); err == nil {
		t.Fatal("nil registry returned a verifier")
	}
	var set *VerifierSet
	if _, err := set.Verifier(MLDSA65, strings.Repeat("a", 64)); err == nil {
		t.Fatal("nil verifier set returned a verifier")
	}
}

func TestMLDSASignatureSizesMatchProtocolHardcodedValues(t *testing.T) {
	for _, tc := range []struct {
		algorithm string
		want      int
	}{
		{MLDSA65, 3309},
		{MLDSA87, 4627},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			signer := signerFor(t, tc.algorithm, 0x01)
			signature, err := signer.sign([]byte("size-pin"))
			if err != nil {
				t.Fatal(err)
			}
			defer clear(signature)
			if len(signature) != tc.want {
				t.Fatalf("%s signature length %d, protocol.validateAuthentication wants %d",
					tc.algorithm, len(signature), tc.want)
			}
			t.Logf("%s public_key_bytes=%d signature_bytes=%d",
				tc.algorithm, len(signer.PublicBytes()), len(signature))
		})
	}
}

func TestMLDSASignatureContextIsPinnedToTheV3Protocol(t *testing.T) {
	// The context string is domain separation for every ML-DSA signature this
	// package produces, the winn/3 dual-signature attestation included. It is
	// pinned to a LITERAL here, not to the constant: a test that compared the
	// constant to itself would move with it and survive the exact silent
	// change this exists to catch.
	if want := "Winn-Protocol-v3"; string(signatureContext) != want {
		t.Fatalf("signatureContext is %q, want %q; a change here re-keys every "+
			"ML-DSA signature in the fleet and must be a visible, reviewed change",
			signatureContext, want)
	}
}

func TestSignDomainMessageRejectsEmptyOversizedAndUnknownDomain(t *testing.T) {
	signer := signerFor(t, MLDSA65, 0x14)
	verifier := verifierFor(t, signer)
	if _, err := SignDomainMessage(CarrierSignatureDomain, nil, signer); err == nil {
		t.Fatal("empty message was signed")
	}
	if err := VerifyDomainMessage(CarrierSignatureDomain, nil, []byte{1}, verifier); err == nil {
		t.Fatal("empty message was verified")
	}
	tooBig := make([]byte, (64<<10)+1)
	tooBig[0] = 1
	if _, err := SignDomainMessage(CarrierSignatureDomain, tooBig, signer); err == nil {
		t.Fatal("oversized message was signed")
	}
	if _, err := SignDomainMessage("winn-not-a-domain", []byte("winn"), signer); err == nil {
		t.Fatal("unknown domain was signed")
	}
	if _, err := SignDomainMessage(CarrierSignatureDomain, []byte("winn"), nil); err == nil {
		t.Fatal("nil signer produced a domain signature")
	}
}

func TestVerifierSetSupportsControllerOverlapRotation(t *testing.T) {
	first := signerFor(t, MLDSA65, 0x41)
	second := signerFor(t, MLDSA65, 0x42)
	strong := signerFor(t, MLDSA87, 0x43)
	document, err := VerifierSetDocument(first, second, strong)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := securefile.AtomicWrite(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := LoadVerifierSet(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []*Signer{first, second, strong} {
		verifier, err := set.Verifier(signer.Algorithm(), signer.KeyID())
		if err != nil {
			t.Fatal(err)
		}
		if verifier.KeyID() != signer.KeyID() {
			t.Fatal("verifier set returned the wrong key")
		}
	}
}

func FuzzVerifyMLDSASignatureEncoding(f *testing.F) {
	signer := signerFor(f, MLDSA65, 0x71)
	verifier := verifierFor(f, signer)
	request := unsignedRequest(protocol.DefaultSuite)
	if err := SignRequest(&request, signer); err != nil {
		f.Fatal(err)
	}
	f.Add(request.AuthSignature)
	f.Add("not-base64")
	f.Fuzz(func(t *testing.T, signature string) {
		candidate := request
		candidate.AuthSignature = signature
		_ = VerifyRequest(candidate, verifier)
	})
}

func signerFor(t testing.TB, algorithm string, fill byte) *Signer {
	t.Helper()
	signer, err := NewSigner(algorithm, bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func verifierFor(t testing.TB, signer *Signer) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(signer.Algorithm(), signer.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func unsignedRequest(suite string) protocol.RekeyRequest {
	return protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             suite,
		ControllerID:      "controller-1",
		DeviceID:          "device-1",
		PeerPublicKey:     pqTestPeer,
		RequestID:         base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x88}, 32)),
		Nonce:             base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32)),
		CurrentGeneration: 0,
		Capabilities:      protocol.RequiredCapabilities(suite),
	}
}

func flipBase64Byte(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0] ^= 0x80
	return base64.StdEncoding.EncodeToString(decoded)
}

func allZeroTestBytes(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
