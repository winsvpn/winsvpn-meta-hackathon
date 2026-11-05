package protocol

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

const testPeerPublicKey = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="

func TestValidateRequestAllSuites(t *testing.T) {
	for _, suite := range SupportedSuites() {
		t.Run(suite, func(t *testing.T) {
			request := validRequest(suite)
			if err := ValidateRequest(request); err != nil {
				t.Fatalf("valid request rejected: %v", err)
			}
			if !slices.Contains(request.Capabilities, requiredSuiteCapability(suite)) {
				t.Fatalf("suite capability missing: %v", request.Capabilities)
			}
		})
	}
}

func TestValidateRequestRejectsMissingSuiteCapability(t *testing.T) {
	request := validRequest(SuiteP384MLKEM1024)
	request.Capabilities = []string{CapabilityMutualTLS, CapabilityAWGPSK, CapabilityMonotonic}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("request without suite capability was accepted")
	}
}

func TestValidateRequestRejectsExhaustedGeneration(t *testing.T) {
	request := validRequest(DefaultSuite)
	request.CurrentGeneration = MaxGeneration
	if err := ValidateRequest(request); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("exhausted generation error = %v", err)
	}
}

func TestValidateResponseBindsAllFields(t *testing.T) {
	now := time.Now().UTC()
	request := validRequest(DefaultSuite)
	psk := make([]byte, 32)
	for index := range psk {
		psk[index] = byte(index + 33)
	}
	response := RekeyResponse{
		Version:       Version,
		Suite:         request.Suite,
		ControllerID:  request.ControllerID,
		DeviceID:      request.DeviceID,
		PeerPublicKey: request.PeerPublicKey,
		RequestID:     request.RequestID,
		Nonce:         request.Nonce,
		Generation:    1,
		KeyID:         KeyID(request.ControllerID, request.Suite, request.DeviceID, request.PeerPublicKey, 1, psk),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339Nano),
		Capabilities:  RequiredCapabilities(request.Suite),
		AuthAlgorithm: request.AuthAlgorithm,
		AuthKeyID:     request.AuthKeyID,
		AuthSignature: dummySignature(request.Suite),
	}
	decoded, err := ValidateResponse(request, response, now)
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	clear(decoded)
	finalRequest := request
	finalRequest.CurrentGeneration = MaxGeneration - 1
	finalResponse := response
	finalResponse.Generation = MaxGeneration
	finalResponse.KeyID = KeyID(
		request.ControllerID,
		request.Suite,
		request.DeviceID,
		request.PeerPublicKey,
		MaxGeneration,
		psk,
	)
	decoded, err = ValidateResponse(finalRequest, finalResponse, now)
	if err != nil {
		t.Fatalf("final representable response generation rejected: %v", err)
	}
	clear(decoded)

	tests := map[string]func(*RekeyResponse){
		"suite":      func(value *RekeyResponse) { value.Suite = SuiteP256MLKEM768 },
		"device":     func(value *RekeyResponse) { value.DeviceID = "other-device" },
		"nonce":      func(value *RekeyResponse) { value.Nonce = token(9) },
		"generation": func(value *RekeyResponse) { value.Generation = 2 },
		"key-id":     func(value *RekeyResponse) { value.KeyID = string(make([]byte, 64)) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := response
			mutate(&changed)
			if _, err := ValidateResponse(request, changed, now); err == nil {
				t.Fatal("tampered response was accepted")
			}
		})
	}
}

func TestValidatePeerPublicKeyRejectsInvalidValues(t *testing.T) {
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, value := range []string{"", "not base64", "AQI=", zero} {
		if err := ValidatePeerPublicKey(value); err == nil {
			t.Fatalf("invalid public key accepted: %q", value)
		}
	}
}

func TestHasRequiredCapabilitiesRejectsUnknownSuite(t *testing.T) {
	for _, got := range [][]string{nil, {}, {"x"}} {
		if HasRequiredCapabilities("no-such-suite", got) {
			t.Fatalf("unknown suite accepted with got=%q", got)
		}
	}
	if !HasRequiredCapabilities(DefaultSuite, RequiredCapabilities(DefaultSuite)) {
		t.Fatal("valid suite with required capabilities was rejected")
	}
}

func TestHasRequiredCapabilitiesRejectsEmptyAndDuplicate(t *testing.T) {
	required := RequiredCapabilities(DefaultSuite)
	if HasRequiredCapabilities(DefaultSuite, []string{""}) {
		t.Fatal("empty capability was accepted")
	}
	duplicated := append(append([]string{}, required...), CapabilityMutualTLS)
	if HasRequiredCapabilities(DefaultSuite, duplicated) {
		t.Fatal("duplicate capability was accepted")
	}
	extra := append(append([]string{}, required...), "extra")
	if !HasRequiredCapabilities(DefaultSuite, extra) {
		t.Fatal("advertised extra capability was rejected")
	}
}

func TestValidateRequestRejectsUnknownVersion(t *testing.T) {
	request := validRequest(DefaultSuite)
	request.Version = "winn/3"
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "winn/2") {
		t.Fatalf("unknown version error = %v", err)
	}
}

func TestValidateRequestRejectsDuplicateCapabilities(t *testing.T) {
	request := validRequest(DefaultSuite)
	request.Capabilities = append(request.Capabilities, CapabilityMutualTLS)
	if err := ValidateRequest(request); err == nil {
		t.Fatal("duplicate capabilities were accepted")
	}
}

func TestValidateResponseRejectsUnknownSuite(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := validRequest(DefaultSuite)
	request.Suite = "no-such-suite"
	request.AuthAlgorithm = ""
	request.Capabilities = []string{"x"}
	psk := make([]byte, 32)
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	response := RekeyResponse{
		Version:       Version,
		Suite:         "no-such-suite",
		ControllerID:  request.ControllerID,
		DeviceID:      request.DeviceID,
		PeerPublicKey: request.PeerPublicKey,
		RequestID:     request.RequestID,
		Nonce:         request.Nonce,
		Generation:    1,
		KeyID:         KeyID(request.ControllerID, request.Suite, request.DeviceID, request.PeerPublicKey, 1, psk),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339Nano),
		Capabilities:  []string{"x"},
		AuthAlgorithm: "",
		AuthKeyID:     strings.Repeat("a", 64),
		AuthSignature: dummySignature(DefaultSuite),
	}
	decoded, err := ValidateResponse(request, response, now)
	clear(decoded)
	if err == nil {
		t.Fatal("unknown suite response was accepted")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("error = %v, want unsupported suite", err)
	}
}

func TestValidateResponseRejectsZeroPSKAndExpiredLifetime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := validRequest(DefaultSuite)
	psk := make([]byte, 32)
	for index := range psk {
		psk[index] = byte(index + 33)
	}
	valid := RekeyResponse{
		Version:       Version,
		Suite:         request.Suite,
		ControllerID:  request.ControllerID,
		DeviceID:      request.DeviceID,
		PeerPublicKey: request.PeerPublicKey,
		RequestID:     request.RequestID,
		Nonce:         request.Nonce,
		Generation:    1,
		KeyID:         KeyID(request.ControllerID, request.Suite, request.DeviceID, request.PeerPublicKey, 1, psk),
		PresharedKey:  base64.StdEncoding.EncodeToString(psk),
		IssuedAt:      now.Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339Nano),
		Capabilities:  RequiredCapabilities(request.Suite),
		AuthAlgorithm: request.AuthAlgorithm,
		AuthKeyID:     request.AuthKeyID,
		AuthSignature: dummySignature(request.Suite),
	}
	decoded, err := ValidateResponse(request, valid, now)
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	clear(decoded)

	zeroPSK := valid
	zeroPSK.PresharedKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	zeroPSK.KeyID = KeyID(request.ControllerID, request.Suite, request.DeviceID, request.PeerPublicKey, 1, make([]byte, 32))
	if decoded, err = ValidateResponse(request, zeroPSK, now); err == nil {
		clear(decoded)
		t.Fatal("all-zero preshared_key was accepted")
	}
	clear(decoded)

	expired := valid
	expired.IssuedAt = now.Add(-2 * time.Hour).Format(time.RFC3339Nano)
	expired.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
	if decoded, err = ValidateResponse(request, expired, now); err == nil {
		clear(decoded)
		t.Fatal("expired key was accepted")
	}
	clear(decoded)

	tooShort := valid
	tooShort.ExpiresAt = now.Add(30 * time.Second).Format(time.RFC3339Nano)
	if decoded, err = ValidateResponse(request, tooShort, now); err == nil {
		clear(decoded)
		t.Fatal("sub-minute lifetime was accepted")
	}
	clear(decoded)

	tooLong := valid
	tooLong.ExpiresAt = now.Add(MaxKeyLifetime + time.Hour).Format(time.RFC3339Nano)
	if decoded, err = ValidateResponse(request, tooLong, now); err == nil {
		clear(decoded)
		t.Fatal("lifetime above MaxKeyLifetime was accepted")
	}
	clear(decoded)
}

func FuzzValidatePeerPublicKey(f *testing.F) {
	f.Add(testPeerPublicKey)
	f.Add("not-base64")
	f.Fuzz(func(t *testing.T, value string) {
		_ = ValidatePeerPublicKey(value)
	})
}

func FuzzValidateRequest(f *testing.F) {
	f.Add(DefaultSuite, "device-1", testPeerPublicKey, token(1), token(2))
	f.Fuzz(func(t *testing.T, suite, deviceID, peer, requestID, nonce string) {
		request := RekeyRequest{
			Version:       Version,
			Suite:         suite,
			ControllerID:  "controller-1",
			DeviceID:      deviceID,
			PeerPublicKey: peer,
			RequestID:     requestID,
			Nonce:         nonce,
			Capabilities:  RequiredCapabilities(suite),
			AuthAlgorithm: RequiredAuthAlgorithm(suite),
			AuthKeyID:     strings.Repeat("a", 64),
			AuthSignature: dummySignature(suite),
		}
		_ = ValidateRequest(request)
	})
}

func FuzzValidateResponse(f *testing.F) {
	now := time.Unix(1_700_000_000, 0).UTC()
	request := validRequest(DefaultSuite)
	validPSK := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32)))
	f.Add(validPSK, strings.Repeat("a", 64), now.Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano), uint64(1))
	f.Fuzz(func(t *testing.T, psk, keyID, issuedAt, expiresAt string, generation uint64) {
		response := RekeyResponse{
			Version:       Version,
			Suite:         request.Suite,
			ControllerID:  request.ControllerID,
			DeviceID:      request.DeviceID,
			PeerPublicKey: request.PeerPublicKey,
			RequestID:     request.RequestID,
			Nonce:         request.Nonce,
			Generation:    generation,
			KeyID:         keyID,
			PresharedKey:  psk,
			IssuedAt:      issuedAt,
			ExpiresAt:     expiresAt,
			Capabilities:  RequiredCapabilities(request.Suite),
			AuthAlgorithm: request.AuthAlgorithm,
			AuthKeyID:     request.AuthKeyID,
			AuthSignature: dummySignature(request.Suite),
		}
		decoded, _ := ValidateResponse(request, response, now)
		clear(decoded)
	})
}

func validRequest(suite string) RekeyRequest {
	return RekeyRequest{
		Version:       Version,
		Suite:         suite,
		ControllerID:  "controller-1",
		DeviceID:      "device-1",
		PeerPublicKey: testPeerPublicKey,
		RequestID:     token(1),
		Nonce:         token(2),
		Capabilities:  RequiredCapabilities(suite),
		AuthAlgorithm: RequiredAuthAlgorithm(suite),
		AuthKeyID:     strings.Repeat("a", 64),
		AuthSignature: dummySignature(suite),
	}
}

func dummySignature(suite string) string {
	size := 3309
	if RequiredAuthAlgorithm(suite) == AuthMLDSA87 {
		size = 4627
	}
	return base64.StdEncoding.EncodeToString(make([]byte, size))
}

func token(value byte) string {
	data := make([]byte, 32)
	for index := range data {
		data[index] = value
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func requiredSuiteCapability(suite string) string {
	switch suite {
	case SuiteX25519MLKEM768:
		return CapabilityHybridKEX
	case SuiteP256MLKEM768:
		return CapabilityP256KEX
	case SuiteP384MLKEM1024:
		return CapabilityP384KEX
	default:
		return ""
	}
}
