package stagebreflector

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func publicKey() []byte {
	key := make([]byte, KeyLength)
	for index := range key {
		key[index] = byte(index)
	}
	return key
}

func deterministicRequest() Request {
	var request Request
	fill := func(destination []byte, first byte) {
		for index := range destination {
			destination[index] = first + byte(index)
		}
	}
	fill(request.RunID[:], 0x10)
	fill(request.AttemptNonce[:], 0x20)
	fill(request.SourceSHA256[:], 0x30)
	fill(request.ArtifactSHA256[:], 0x50)
	fill(request.WCF3SessionID[:], 0x70)
	fill(request.WCF3BindingID[:], 0x80)
	request.PSKGeneration = 7
	request.SequenceEpoch = 11
	request.CanarySequence = 13
	request.IssuedAtUnixMilliseconds = 1_800_000_000_000
	request.ExpiresAtUnixMilliseconds = 1_800_000_009_000
	request.RequestSentMonotonicNanoseconds = 9_000_000_000
	fill(request.Challenge[:], 0xa0)
	return request
}

func deterministicPathID() [16]byte {
	var pathID [16]byte
	for index := range pathID {
		pathID[index] = 0xd0 + byte(index)
	}
	return pathID
}

func testLease(request Request) AttemptLease {
	return AttemptLease{
		AttemptNonce:                    request.AttemptNonce,
		WCF3SessionID:                   request.WCF3SessionID,
		WCF3BindingID:                   request.WCF3BindingID,
		PSKGeneration:                   request.PSKGeneration,
		SequenceEpoch:                   request.SequenceEpoch,
		RequestedAtMonotonicNanoseconds: request.RequestSentMonotonicNanoseconds,
		PathID:                          deterministicPathID(),
		Active:                          true,
	}
}

func validExchange(t *testing.T) (Request, []byte, VerifiedRequest, []byte) {
	t.Helper()
	return validExchangeForRequest(t, deterministicRequest())
}

func validExchangeForRequest(
	t *testing.T,
	request Request,
) (Request, []byte, VerifiedRequest, []byte) {
	t.Helper()
	encodedRequest, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	verifiedRequest, err := VerifyRequest(
		encodedRequest,
		publicKey(),
		request.IssuedAtUnixMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := EncodeResponse(
		publicKey(),
		verifiedRequest,
		request.IssuedAtUnixMilliseconds+1,
		request.IssuedAtUnixMilliseconds+2,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request, encodedRequest, verifiedRequest, response
}

func TestRequestAndResponseExactLengthsAndAcceptance(t *testing.T) {
	request, encodedRequest, verifiedRequest, response := validExchange(t)
	if len(encodedRequest) != RequestLength {
		t.Fatalf("request length = %d", len(encodedRequest))
	}
	if len(response) != ResponseLength {
		t.Fatalf("response length = %d", len(response))
	}
	domain, err := NewClientAcceptanceDomain(
		publicKey(),
		2,
		func() uint64 {
			return request.RequestSentMonotonicNanoseconds +
				StageBDeadlineNanoseconds
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	lease := testLease(request)
	acceptor, err := domain.NewAcceptor(request, verifiedRequest.Tag, lease)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := acceptor.Accept(response, lease)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Request != request {
		t.Fatal("verified response request differs")
	}
}

func TestRequestLengthAndFixedFieldMutationsRejected(t *testing.T) {
	_, encoded, _, _ := validExchange(t)
	for _, candidate := range [][]byte{
		encoded[:len(encoded)-1],
		append(append([]byte{}, encoded...), 0),
	} {
		if _, err := VerifyRequest(candidate, publicKey(), deterministicRequest().IssuedAtUnixMilliseconds); !errors.Is(err, ErrDatagramLength) {
			t.Fatalf("length mutation: %v", err)
		}
	}
	for _, offset := range []int{0, 4, 5, 6, 7, 8} {
		candidate := append([]byte{}, encoded...)
		candidate[offset] ^= 1
		if _, err := VerifyRequest(candidate, publicKey(), deterministicRequest().IssuedAtUnixMilliseconds); !errors.Is(err, ErrFixedField) {
			t.Fatalf("fixed offset %d: %v", offset, err)
		}
	}
}

func TestSingleByteMutationOfEveryWireByteRejected(t *testing.T) {
	request, encodedRequest, verifiedRequest, response := validExchange(t)
	for offset := range encodedRequest {
		candidate := append([]byte{}, encodedRequest...)
		candidate[offset] ^= 1
		if _, err := VerifyRequest(
			candidate,
			publicKey(),
			request.IssuedAtUnixMilliseconds,
		); err == nil {
			t.Fatalf("request byte %d mutation accepted", offset)
		}
	}
	for offset := range response {
		candidate := append([]byte{}, response...)
		candidate[offset] ^= 1
		if _, err := verifyResponseCodec(
			candidate,
			publicKey(),
			request,
			verifiedRequest.Tag,
		); err == nil {
			t.Fatalf("response byte %d mutation accepted", offset)
		}
	}
}

func TestRequestEveryRequiredBindingAndCounterRejected(t *testing.T) {
	request := deterministicRequest()
	cases := map[string]func(*Request){
		"run":       func(value *Request) { value.RunID = [16]byte{} },
		"attempt":   func(value *Request) { value.AttemptNonce = [16]byte{} },
		"source":    func(value *Request) { value.SourceSHA256 = [32]byte{} },
		"artifact":  func(value *Request) { value.ArtifactSHA256 = [32]byte{} },
		"session":   func(value *Request) { value.WCF3SessionID = [16]byte{} },
		"binding":   func(value *Request) { value.WCF3BindingID = [16]byte{} },
		"psk":       func(value *Request) { value.PSKGeneration = 0 },
		"epoch":     func(value *Request) { value.SequenceEpoch = 0 },
		"sequence":  func(value *Request) { value.CanarySequence = 0 },
		"challenge": func(value *Request) { value.Challenge = [32]byte{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := request
			mutate(&candidate)
			if _, err := EncodeRequest(publicKey(), candidate); !errors.Is(err, ErrRequiredField) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRequestLifetimeClockAuthenticationAndKey(t *testing.T) {
	request := deterministicRequest()
	for name, times := range map[string][2]uint64{
		"equal":    {request.IssuedAtUnixMilliseconds, request.IssuedAtUnixMilliseconds},
		"reversed": {request.IssuedAtUnixMilliseconds + 1, request.IssuedAtUnixMilliseconds},
		"overlong": {request.IssuedAtUnixMilliseconds, request.IssuedAtUnixMilliseconds + 10_001},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.IssuedAtUnixMilliseconds = times[0]
			candidate.ExpiresAtUnixMilliseconds = times[1]
			if _, err := EncodeRequest(publicKey(), candidate); !errors.Is(err, ErrLifetime) {
				t.Fatalf("got %v", err)
			}
		})
	}
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	for name, now := range map[string]uint64{
		"stale":  request.ExpiresAtUnixMilliseconds + 1,
		"future": request.IssuedAtUnixMilliseconds - 1,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRequest(encoded, publicKey(), now); !errors.Is(err, ErrClock) {
				t.Fatalf("got %v", err)
			}
		})
	}
	for _, now := range []uint64{request.IssuedAtUnixMilliseconds, request.ExpiresAtUnixMilliseconds} {
		if _, err := VerifyRequest(encoded, publicKey(), now); err != nil {
			t.Fatalf("closed interval rejected: %v", err)
		}
	}
	maximumLifetime := request
	maximumLifetime.ExpiresAtUnixMilliseconds =
		maximumLifetime.IssuedAtUnixMilliseconds + MaxLifetimeMilliseconds
	if _, err := EncodeRequest(publicKey(), maximumLifetime); err != nil {
		t.Fatalf("maximum lifetime rejected: %v", err)
	}
	wrongKey := append([]byte{}, publicKey()...)
	wrongKey[0] ^= 1
	if _, err := VerifyRequest(encoded, wrongKey, request.IssuedAtUnixMilliseconds); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
	mutatedTag := append([]byte{}, encoded...)
	mutatedTag[len(mutatedTag)-1] ^= 1
	if _, err := VerifyRequest(mutatedTag, publicKey(), request.IssuedAtUnixMilliseconds); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tag mutation: %v", err)
	}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := EncodeRequest(key, request); !errors.Is(err, ErrKeyLength) {
			t.Fatalf("key length %d: %v", len(key), err)
		}
	}
}

func TestVerifyRequestAuthenticatesBeforeClockWindow(t *testing.T) {
	request := deterministicRequest()
	encoded, err := EncodeRequest(publicKey(), request)
	if err != nil {
		t.Fatal(err)
	}
	stale := request.ExpiresAtUnixMilliseconds + 1
	if _, err := VerifyRequest(encoded, publicKey(), stale); !errors.Is(err, ErrClock) {
		t.Fatalf("authenticated stale: %v", err)
	}
	future := request.IssuedAtUnixMilliseconds - 1
	if _, err := VerifyRequest(encoded, publicKey(), future); !errors.Is(err, ErrClock) {
		t.Fatalf("authenticated future: %v", err)
	}
	mutated := append([]byte{}, encoded...)
	mutated[len(mutated)-1] ^= 1
	if _, err := VerifyRequest(mutated, publicKey(), stale); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unauthenticated stale: %v", err)
	}
	if _, err := VerifyRequest(mutated, publicKey(), future); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unauthenticated future: %v", err)
	}
	if _, err := VerifyRequest(
		mutated,
		publicKey(),
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unauthenticated in-window: %v", err)
	}
}

func TestResponseLengthsAuthenticationBindingAndTimes(t *testing.T) {
	request, _, verifiedRequest, response := validExchange(t)
	for _, candidate := range [][]byte{
		response[:len(response)-1],
		append(append([]byte{}, response...), 0),
	} {
		if _, err := verifyResponseCodec(
			candidate,
			publicKey(),
			request,
			verifiedRequest.Tag,
		); !errors.Is(err, ErrDatagramLength) {
			t.Fatalf("length mutation: %v", err)
		}
	}
	mutatedMAC := append([]byte{}, response...)
	mutatedMAC[len(mutatedMAC)-1] ^= 1
	if _, err := verifyResponseCodec(
		mutatedMAC,
		publicKey(),
		request,
		verifiedRequest.Tag,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("response tag: %v", err)
	}
	wrongKey := append([]byte{}, publicKey()...)
	wrongKey[0] ^= 1
	if _, err := verifyResponseCodec(
		response,
		wrongKey,
		request,
		verifiedRequest.Tag,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
	wrongEcho := verifiedRequest.Tag
	wrongEcho[0] ^= 1
	if _, err := verifyResponseCodec(
		response,
		publicKey(),
		request,
		wrongEcho,
	); !errors.Is(err, ErrRequestBinding) {
		t.Fatalf("request tag echo: %v", err)
	}
	authenticatedWrongEcho := append([]byte{}, response...)
	authenticatedWrongEcho[CommonBodyLength] ^= 1
	authenticatedWrongEchoTag := authenticate(
		publicKey(),
		responseDomain,
		authenticatedWrongEcho[:270],
	)
	copy(authenticatedWrongEcho[270:], authenticatedWrongEchoTag[:])
	if _, err := verifyResponseCodec(
		authenticatedWrongEcho,
		publicKey(),
		request,
		verifiedRequest.Tag,
	); !errors.Is(err, ErrRequestBinding) {
		t.Fatalf("authenticated request tag echo mutation: %v", err)
	}

	for name, offset := range map[string]int{
		"run": 14, "attempt": 30, "source": 46, "artifact": 78,
		"session": 110, "binding": 126, "psk": 149, "epoch": 157,
		"sequence": 165, "issued": 173, "expires": 181, "monotonic": 189,
		"challenge": 190,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte{}, response...)
			candidate[offset] ^= 1
			tag := authenticate(publicKey(), responseDomain, candidate[:270])
			copy(candidate[270:], tag[:])
			_, err := verifyResponseCodec(
				candidate,
				publicKey(),
				request,
				verifiedRequest.Tag,
			)
			if !errors.Is(err, ErrRequestBinding) {
				t.Fatalf("got %v", err)
			}
		})
	}

	for name, times := range map[string][2]uint64{
		"reversed": {request.IssuedAtUnixMilliseconds + 3, request.IssuedAtUnixMilliseconds + 2},
		"before":   {request.IssuedAtUnixMilliseconds - 1, request.IssuedAtUnixMilliseconds},
		"after":    {request.ExpiresAtUnixMilliseconds, request.ExpiresAtUnixMilliseconds + 1},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte{}, response...)
			binary.BigEndian.PutUint64(candidate[254:262], times[0])
			binary.BigEndian.PutUint64(candidate[262:270], times[1])
			tag := authenticate(publicKey(), responseDomain, candidate[:270])
			copy(candidate[270:], tag[:])
			if _, err := verifyResponseCodec(
				candidate,
				publicKey(),
				request,
				verifiedRequest.Tag,
			); !errors.Is(err, ErrReflectorTime) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestResponseEncoderRejectsUnverifiedBindingAndInvalidTimes(t *testing.T) {
	request, _, verifiedRequest, _ := validExchange(t)
	mutatedBody := verifiedRequest
	mutatedBody.Body[14] ^= 1
	if _, err := EncodeResponse(
		publicKey(),
		mutatedBody,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrRequestBinding) {
		t.Fatalf("body: %v", err)
	}
	mutatedTag := verifiedRequest
	mutatedTag.Tag[0] ^= 1
	if _, err := EncodeResponse(
		publicKey(),
		mutatedTag,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tag: %v", err)
	}
	if _, err := EncodeResponse(
		publicKey(),
		verifiedRequest,
		request.IssuedAtUnixMilliseconds+1,
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrReflectorTime) {
		t.Fatalf("time: %v", err)
	}
}

func TestReplayCacheExpiryCapacityAndConcurrency(t *testing.T) {
	cache := mustCache(t, 1)
	var first, second, third [TagLength]byte
	first[0], second[0], third[0] = 1, 2, 3
	if err := cache.Use(first, 10, 5); err != nil {
		t.Fatal(err)
	}
	if err := cache.Use(second, 20, 10); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("exact expiry evicted: %v", err)
	}
	if err := cache.Use(second, 20, 11); err != nil {
		t.Fatalf("expired entry not removed: %v", err)
	}
	if err := cache.Use(first, 10, 5); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("rollback replay: %v", err)
	}
	if err := cache.Use(third, 30, 10); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("rollback new tag: %v", err)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache length = %d", cache.Len())
	}
	if _, err := NewReplayCache(0); !errors.Is(err, ErrCacheCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	if _, err := NewReplayCache(MaxReplayCacheCapacity + 1); !errors.Is(err, ErrCacheCapacity) {
		t.Fatalf("hard maximum capacity: %v", err)
	}
	maximum := mustCache(t, MaxReplayCacheCapacity)
	for index := 0; index < MaxReplayCacheCapacity; index++ {
		var tag [TagLength]byte
		binary.BigEndian.PutUint64(tag[:8], uint64(index+1))
		if err := maximum.Use(tag, 100, 1); err != nil {
			t.Fatalf("fill %d: %v", index, err)
		}
	}
	var overCapacity [TagLength]byte
	binary.BigEndian.PutUint64(overCapacity[:8], uint64(MaxReplayCacheCapacity+1))
	if err := maximum.Use(overCapacity, 100, 1); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("maximum did not fail closed: %v", err)
	}

	concurrent := mustCache(t, 8)
	results := make(chan error, 16)
	for index := 0; index < cap(results); index++ {
		go func() { results <- concurrent.Use(first, 100, 1) }()
	}
	successes := 0
	for index := 0; index < cap(results); index++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrReplay) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent successes = %d", successes)
	}
}

func TestReflectorReplayAndFailClosedCapacity(t *testing.T) {
	reflector, err := NewReflector(publicKey(), 1)
	if err != nil {
		t.Fatal(err)
	}
	request := deterministicRequest()
	first, _ := EncodeRequest(publicKey(), request)
	if _, err := reflector.Process(
		first,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := reflector.Process(
		first,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate: %v", err)
	}
	secondRequest := request
	secondRequest.AttemptNonce[0] ^= 1
	second, _ := EncodeRequest(publicKey(), secondRequest)
	if _, err := reflector.Process(
		second,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
		request.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("capacity: %v", err)
	}
}

func TestReflectorClockRollbackCannotReenablePrunedRequest(t *testing.T) {
	reflector, err := NewReflector(publicKey(), 1)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := deterministicRequest()
	firstRequest.ExpiresAtUnixMilliseconds =
		firstRequest.IssuedAtUnixMilliseconds + 100
	first, err := EncodeRequest(publicKey(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reflector.Process(
		first,
		firstRequest.IssuedAtUnixMilliseconds,
		firstRequest.IssuedAtUnixMilliseconds,
		firstRequest.IssuedAtUnixMilliseconds,
	); err != nil {
		t.Fatal(err)
	}

	secondRequest := firstRequest
	secondRequest.AttemptNonce[0] ^= 1
	secondRequest.IssuedAtUnixMilliseconds =
		firstRequest.ExpiresAtUnixMilliseconds + 1
	secondRequest.ExpiresAtUnixMilliseconds =
		secondRequest.IssuedAtUnixMilliseconds + 100
	second, err := EncodeRequest(publicKey(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reflector.Process(
		second,
		secondRequest.IssuedAtUnixMilliseconds,
		secondRequest.IssuedAtUnixMilliseconds,
		secondRequest.IssuedAtUnixMilliseconds,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := reflector.Process(
		first,
		firstRequest.IssuedAtUnixMilliseconds,
		firstRequest.IssuedAtUnixMilliseconds,
		firstRequest.IssuedAtUnixMilliseconds,
	); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("rollback replay: %v", err)
	}
}

func TestErrorsRedactSensitiveMaterial(t *testing.T) {
	request, encodedRequest, verifiedRequest, response := validExchange(t)
	pathID := deterministicPathID()
	sensitive := []string{
		base64.StdEncoding.EncodeToString(publicKey()),
		base64.StdEncoding.EncodeToString(verifiedRequest.Tag[:]),
		base64.StdEncoding.EncodeToString(request.Challenge[:]),
		base64.StdEncoding.EncodeToString(pathID[:]),
		base64.StdEncoding.EncodeToString(encodedRequest),
		base64.StdEncoding.EncodeToString(response),
		"127.0.0.1:49152",
		"APPLE-IDENTIFIER",
	}
	errorsToCheck := []error{
		ErrKeyLength, ErrDatagramLength, ErrFixedField, ErrRequiredField,
		ErrLifetime, ErrClock, ErrAuthentication, ErrRequestBinding,
		ErrClockRollback, ErrReflectorTime, ErrLease, ErrDeadline,
		ErrReplay, ErrCacheFull, ErrCacheCapacity, ErrLoopbackAddress,
		ErrRead, ErrWrite, ErrClosed, ErrCancelled, ErrTerminal,
	}
	for _, err := range errorsToCheck {
		for _, secret := range sensitive {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("%q contains sensitive material", err)
			}
		}
	}
}

type fixtureFile struct {
	Schema                            string              `json:"schema"`
	WireSchema                        string              `json:"wire_schema"`
	Protocol                          string              `json:"protocol"`
	Scope                             string              `json:"scope"`
	InputsClass                       string              `json:"inputs_class"`
	PublicTestKeyBase64               string              `json:"public_test_key_base64"`
	RequestInput                      fixtureRequestInput `json:"request_input"`
	ReflectorNowUnixMilliseconds      uint64              `json:"reflector_now_unix_milliseconds"`
	ReflectorReceivedUnixMilliseconds uint64              `json:"reflector_received_unix_milliseconds"`
	ReflectorSentUnixMilliseconds     uint64              `json:"reflector_sent_unix_milliseconds"`
	RequestBase64                     string              `json:"request_base64"`
	RequestSHA256                     string              `json:"request_sha256"`
	ResponseBase64                    string              `json:"response_base64"`
	ResponseSHA256                    string              `json:"response_sha256"`
}

type fixtureRequestInput struct {
	RunIDBase64                     string `json:"run_id_base64"`
	AttemptNonceBase64              string `json:"attempt_nonce_base64"`
	SourceSHA256Base64              string `json:"source_sha256_base64"`
	ArtifactSHA256Base64            string `json:"artifact_sha256_base64"`
	WCF3SessionIDBase64             string `json:"wcf3_session_id_base64"`
	WCF3BindingIDBase64             string `json:"wcf3_binding_id_base64"`
	PSKGeneration                   uint64 `json:"psk_generation"`
	SequenceEpoch                   uint64 `json:"sequence_epoch"`
	CanarySequence                  uint64 `json:"canary_sequence"`
	IssuedAtUnixMilliseconds        uint64 `json:"issued_at_unix_milliseconds"`
	ExpiresAtUnixMilliseconds       uint64 `json:"expires_at_unix_milliseconds"`
	RequestSentMonotonicNanoseconds uint64 `json:"request_sent_monotonic_nanoseconds"`
	ChallengeBase64                 string `json:"challenge_base64"`
}

func TestCanonicalPublicVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/stageb-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture fixtureFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatal("fixture has trailing JSON")
	}
	if fixture.Schema != "winn-stageb-reflector-vectors/1" ||
		fixture.WireSchema != "winn-stageb-reflector-wire/1" ||
		fixture.Protocol != "winn/3" ||
		fixture.Scope != "local-conformance-only" ||
		fixture.InputsClass != "deterministic-public-non-secret" {
		t.Fatal("fixture metadata")
	}
	assertFixtureInput(t, fixture.RequestInput, deterministicRequest())
	key, err := base64.StdEncoding.Strict().DecodeString(fixture.PublicTestKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := base64.StdEncoding.Strict().DecodeString(fixture.RequestBase64)
	if err != nil {
		t.Fatal(err)
	}
	responseBytes, err := base64.StdEncoding.Strict().DecodeString(fixture.ResponseBase64)
	if err != nil {
		t.Fatal(err)
	}
	expectedRequest, err := EncodeRequest(key, deterministicRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestBytes, expectedRequest) {
		t.Fatal("request bytes differ")
	}
	verifiedRequest, err := VerifyRequest(requestBytes, key, fixture.ReflectorNowUnixMilliseconds)
	if err != nil {
		t.Fatal(err)
	}
	expectedResponse, err := EncodeResponse(
		key,
		verifiedRequest,
		fixture.ReflectorReceivedUnixMilliseconds,
		fixture.ReflectorSentUnixMilliseconds,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(responseBytes, expectedResponse) {
		t.Fatal("response bytes differ")
	}
	assertDigest := func(label string, value []byte, expectedHex string) {
		t.Helper()
		sum := sha256.Sum256(value)
		if hex.EncodeToString(sum[:]) != expectedHex {
			t.Fatalf("%s digest differs", label)
		}
	}
	assertDigest("request", requestBytes, fixture.RequestSHA256)
	assertDigest("response", responseBytes, fixture.ResponseSHA256)
}

func TestCanonicalFixtureRejectsUnknownFields(t *testing.T) {
	raw, err := os.ReadFile("testdata/stageb-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"top-level": bytes.Replace(
			raw,
			[]byte(`"schema":`),
			[]byte(`"unknown_top_level": 1, "schema":`),
			1,
		),
		"request-input": bytes.Replace(
			raw,
			[]byte(`"run_id_base64":`),
			[]byte(`"unknown_request_input": 1, "run_id_base64":`),
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			var fixture fixtureFile
			decoder := json.NewDecoder(bytes.NewReader(candidate))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&fixture); err == nil {
				t.Fatal("unknown field accepted")
			}
		})
	}
}

func TestHandAuthoredWireOffsetsAndDomains(t *testing.T) {
	request, encodedRequest, verifiedRequest, response := validExchange(t)
	assertBytes := func(label string, actual, expected []byte) {
		t.Helper()
		if !bytes.Equal(actual, expected) {
			t.Fatalf("%s differs", label)
		}
	}
	assertBytes("request magic", encodedRequest[0:4], []byte{'W', 'B', 'R', '3'})
	assertBytes("request reserved", encodedRequest[6:8], []byte{0, 0})
	assertBytes("protocol", encodedRequest[8:14], []byte{'w', 'i', 'n', 'n', '/', '3'})
	if encodedRequest[4] != 1 || encodedRequest[5] != 1 {
		t.Fatal("request version/type")
	}
	assertBytes("run", encodedRequest[14:30], request.RunID[:])
	assertBytes("attempt", encodedRequest[30:46], request.AttemptNonce[:])
	assertBytes("source", encodedRequest[46:78], request.SourceSHA256[:])
	assertBytes("artifact", encodedRequest[78:110], request.ArtifactSHA256[:])
	assertBytes("session", encodedRequest[110:126], request.WCF3SessionID[:])
	assertBytes("binding", encodedRequest[126:142], request.WCF3BindingID[:])
	if binary.BigEndian.Uint64(encodedRequest[142:150]) != request.PSKGeneration ||
		binary.BigEndian.Uint64(encodedRequest[150:158]) != request.SequenceEpoch ||
		binary.BigEndian.Uint64(encodedRequest[158:166]) != request.CanarySequence ||
		binary.BigEndian.Uint64(encodedRequest[166:174]) != request.IssuedAtUnixMilliseconds ||
		binary.BigEndian.Uint64(encodedRequest[174:182]) != request.ExpiresAtUnixMilliseconds ||
		binary.BigEndian.Uint64(encodedRequest[182:190]) != request.RequestSentMonotonicNanoseconds {
		t.Fatal("request integer offset")
	}
	assertBytes("challenge", encodedRequest[190:222], request.Challenge[:])
	requestMAC := hmac.New(sha256.New, publicKey())
	_, _ = requestMAC.Write([]byte{
		'w', 'i', 'n', 'n', '-', 's', 't', 'a', 'g', 'e', 'b', '-',
		'r', 'e', 'q', 'u', 'e', 's', 't', '/', 'v', '1', 0,
	})
	_, _ = requestMAC.Write(encodedRequest[:222])
	if !hmac.Equal(requestMAC.Sum(nil), encodedRequest[222:254]) {
		t.Fatal("hand-authored request domain/HMAC")
	}

	if response[4] != 1 || response[5] != 2 {
		t.Fatal("response version/type")
	}
	responseRequestBody := append([]byte{}, response[:222]...)
	responseRequestBody[5] = 1
	assertBytes("response common binding", responseRequestBody, encodedRequest[:222])
	assertBytes("request tag echo", response[222:254], verifiedRequest.Tag[:])
	if binary.BigEndian.Uint64(response[254:262]) !=
		request.IssuedAtUnixMilliseconds+1 ||
		binary.BigEndian.Uint64(response[262:270]) !=
			request.IssuedAtUnixMilliseconds+2 {
		t.Fatal("response timestamp offset")
	}
	responseMAC := hmac.New(sha256.New, publicKey())
	_, _ = responseMAC.Write([]byte{
		'w', 'i', 'n', 'n', '-', 's', 't', 'a', 'g', 'e', 'b', '-',
		'r', 'e', 's', 'p', 'o', 'n', 's', 'e', '/', 'v', '1', 0,
	})
	_, _ = responseMAC.Write(response[:270])
	if !hmac.Equal(responseMAC.Sum(nil), response[270:302]) {
		t.Fatal("hand-authored response domain/HMAC")
	}
}

func assertFixtureInput(t *testing.T, input fixtureRequestInput, expected Request) {
	t.Helper()
	assertBytes := func(label, encoded string, expectedBytes []byte) {
		t.Helper()
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !bytes.Equal(decoded, expectedBytes) {
			t.Fatalf("%s differs", label)
		}
	}
	assertBytes("run ID", input.RunIDBase64, expected.RunID[:])
	assertBytes("attempt nonce", input.AttemptNonceBase64, expected.AttemptNonce[:])
	assertBytes("source digest", input.SourceSHA256Base64, expected.SourceSHA256[:])
	assertBytes("artifact digest", input.ArtifactSHA256Base64, expected.ArtifactSHA256[:])
	assertBytes("session ID", input.WCF3SessionIDBase64, expected.WCF3SessionID[:])
	assertBytes("binding ID", input.WCF3BindingIDBase64, expected.WCF3BindingID[:])
	assertBytes("challenge", input.ChallengeBase64, expected.Challenge[:])
	if input.PSKGeneration != expected.PSKGeneration ||
		input.SequenceEpoch != expected.SequenceEpoch ||
		input.CanarySequence != expected.CanarySequence ||
		input.IssuedAtUnixMilliseconds != expected.IssuedAtUnixMilliseconds ||
		input.ExpiresAtUnixMilliseconds != expected.ExpiresAtUnixMilliseconds ||
		input.RequestSentMonotonicNanoseconds != expected.RequestSentMonotonicNanoseconds {
		t.Fatal("numeric fixture input differs")
	}
}

func mustCache(t *testing.T, capacity int) *ReplayCache {
	t.Helper()
	cache, err := NewReplayCache(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}
