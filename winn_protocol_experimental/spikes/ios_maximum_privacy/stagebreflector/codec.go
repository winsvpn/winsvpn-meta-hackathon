// Package stagebreflector implements the local-conformance-only Stage B wire
// codec. It is not a VPN transport and does not establish or forward traffic.
package stagebreflector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	CommonBodyLength = 222
	RequestLength    = 254
	ResponseLength   = 302
	KeyLength        = 32
	TagLength        = 32

	MaxLifetimeMilliseconds   = uint64(10_000)
	StageBDeadlineNanoseconds = uint64(3_000_000_000)
)

var (
	ErrKeyLength       = errors.New("key length")
	ErrDatagramLength  = errors.New("datagram length")
	ErrFixedField      = errors.New("fixed field")
	ErrRequiredField   = errors.New("required field")
	ErrLifetime        = errors.New("lifetime")
	ErrClock           = errors.New("clock")
	ErrClockRollback   = errors.New("clock rollback")
	ErrAuthentication  = errors.New("authentication")
	ErrRequestBinding  = errors.New("request binding")
	ErrReflectorTime   = errors.New("reflector time")
	ErrLease           = errors.New("attempt lease")
	ErrDeadline        = errors.New("local deadline")
	ErrReplay          = errors.New("replay")
	ErrCacheFull       = errors.New("replay cache full")
	ErrCacheCapacity   = errors.New("replay cache capacity")
	ErrLoopbackAddress = errors.New("loopback address")
	ErrRead            = errors.New("datagram read")
	ErrWrite           = errors.New("datagram write")
	ErrClosed          = errors.New("server closed")
	ErrCancelled       = errors.New("cancelled")
	ErrTerminal        = errors.New("terminal attempt")
)

var (
	requestDomain  = []byte("winn-stageb-request/v1\x00")
	responseDomain = []byte("winn-stageb-response/v1\x00")
)

// Request is the complete request binding represented by the 222-byte common
// body. Fixed magic/version/type/protocol/reserved fields are supplied by the
// codec and are not caller-controlled.
type Request struct {
	RunID                           [16]byte
	AttemptNonce                    [16]byte
	SourceSHA256                    [32]byte
	ArtifactSHA256                  [32]byte
	WCF3SessionID                   [16]byte
	WCF3BindingID                   [16]byte
	PSKGeneration                   uint64
	SequenceEpoch                   uint64
	CanarySequence                  uint64
	IssuedAtUnixMilliseconds        uint64
	ExpiresAtUnixMilliseconds       uint64
	RequestSentMonotonicNanoseconds uint64
	Challenge                       [32]byte
}

// VerifiedRequest contains the authenticated request and its exact binding.
// Its fields are values, not aliases into the caller's datagram.
type VerifiedRequest struct {
	Request Request
	Body    [CommonBodyLength]byte
	Tag     [TagLength]byte
}

// AttemptLease is client-local state. Active must be true, and Cancelled and
// Superseded must both be false, when a response is accepted.
type AttemptLease struct {
	AttemptNonce                    [16]byte
	WCF3SessionID                   [16]byte
	WCF3BindingID                   [16]byte
	PSKGeneration                   uint64
	SequenceEpoch                   uint64
	RequestedAtMonotonicNanoseconds uint64
	PathID                          [16]byte
	Active                          bool
	Cancelled                       bool
	Superseded                      bool
}

// VerifiedResponse is returned only after authentication, full binding,
// reflector-time, lease, deadline, and response replay checks pass through a
// ClientResponseAcceptor.
type VerifiedResponse struct {
	Request                           Request
	RequestTag                        [TagLength]byte
	ReflectorReceivedUnixMilliseconds uint64
	ReflectorSentUnixMilliseconds     uint64
	ResponseTag                       [TagLength]byte
}

func EncodeRequest(key []byte, request Request) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if err := validateRequestFields(request); err != nil {
		return nil, err
	}
	body := encodeBody(request, 1)
	out := make([]byte, RequestLength)
	copy(out, body[:])
	tag := authenticate(key, requestDomain, out[:CommonBodyLength])
	copy(out[CommonBodyLength:], tag[:])
	return out, nil
}

// VerifyRequest authenticates and validates a request at the injected
// reflector wall clock. Authentication is checked before the clock window so
// an unauthenticated stale or future packet cannot manufacture ErrClock.
// It does not consult or mutate a replay cache.
func VerifyRequest(datagram, key []byte, nowUnixMilliseconds uint64) (VerifiedRequest, error) {
	var verified VerifiedRequest
	if err := validateKey(key); err != nil {
		return verified, err
	}
	if len(datagram) != RequestLength {
		return verified, ErrDatagramLength
	}
	request, body, err := decodeAndValidateBody(datagram[:CommonBodyLength], 1)
	if err != nil {
		return verified, err
	}
	expected := authenticate(key, requestDomain, datagram[:CommonBodyLength])
	if !hmac.Equal(expected[:], datagram[CommonBodyLength:RequestLength]) {
		return verified, ErrAuthentication
	}
	if nowUnixMilliseconds < request.IssuedAtUnixMilliseconds ||
		nowUnixMilliseconds > request.ExpiresAtUnixMilliseconds {
		return verified, ErrClock
	}
	verified.Request = request
	verified.Body = body
	copy(verified.Tag[:], datagram[CommonBodyLength:RequestLength])
	return verified, nil
}

// EncodeResponse returns an authenticated response for a previously verified
// request. The replay decision belongs to Reflector.Process, not this pure
// encoder.
func EncodeResponse(
	key []byte,
	request VerifiedRequest,
	receivedUnixMilliseconds uint64,
	sentUnixMilliseconds uint64,
) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if err := validateRequestFields(request.Request); err != nil {
		return nil, err
	}
	expectedRequestBody := encodeBody(request.Request, 1)
	if !hmac.Equal(expectedRequestBody[:], request.Body[:]) {
		return nil, ErrRequestBinding
	}
	expectedRequestTag := authenticate(key, requestDomain, request.Body[:])
	if !hmac.Equal(expectedRequestTag[:], request.Tag[:]) {
		return nil, ErrAuthentication
	}
	if err := validateReflectorTimes(
		request.Request,
		receivedUnixMilliseconds,
		sentUnixMilliseconds,
	); err != nil {
		return nil, err
	}

	responseBody := encodeBody(request.Request, 2)
	out := make([]byte, ResponseLength)
	copy(out[:CommonBodyLength], responseBody[:])
	copy(out[CommonBodyLength:CommonBodyLength+TagLength], request.Tag[:])
	binary.BigEndian.PutUint64(out[254:262], receivedUnixMilliseconds)
	binary.BigEndian.PutUint64(out[262:270], sentUnixMilliseconds)
	tag := authenticate(key, responseDomain, out[:270])
	copy(out[270:], tag[:])
	return out, nil
}

// verifyResponseCodec is the package-private, stateless binary/authentication
// layer. Only ClientResponseAcceptor exposes response acceptance to callers.
func verifyResponseCodec(
	datagram, key []byte,
	expectedRequest Request,
	expectedRequestTag [TagLength]byte,
) (VerifiedResponse, error) {
	var verified VerifiedResponse
	if err := validateKey(key); err != nil {
		return verified, err
	}
	if len(datagram) != ResponseLength {
		return verified, ErrDatagramLength
	}
	request, body, err := decodeAndValidateBody(datagram[:CommonBodyLength], 2)
	if err != nil {
		return verified, err
	}

	calculatedResponseTag := authenticate(key, responseDomain, datagram[:270])
	if !hmac.Equal(calculatedResponseTag[:], datagram[270:ResponseLength]) {
		return verified, ErrAuthentication
	}
	if !hmac.Equal(
		datagram[CommonBodyLength:CommonBodyLength+TagLength],
		expectedRequestTag[:],
	) {
		return verified, ErrRequestBinding
	}

	expectedBody := encodeBody(expectedRequest, 2)
	if !hmac.Equal(body[:], expectedBody[:]) {
		return verified, ErrRequestBinding
	}
	expectedRequestBody := encodeBody(expectedRequest, 1)
	calculatedRequestTag := authenticate(key, requestDomain, expectedRequestBody[:])
	if !hmac.Equal(calculatedRequestTag[:], expectedRequestTag[:]) {
		return verified, ErrRequestBinding
	}

	received := binary.BigEndian.Uint64(datagram[254:262])
	sent := binary.BigEndian.Uint64(datagram[262:270])
	if err := validateReflectorTimes(request, received, sent); err != nil {
		return verified, err
	}
	var responseTag [TagLength]byte
	copy(responseTag[:], datagram[270:ResponseLength])

	verified.Request = request
	copy(verified.RequestTag[:], datagram[CommonBodyLength:CommonBodyLength+TagLength])
	verified.ReflectorReceivedUnixMilliseconds = received
	verified.ReflectorSentUnixMilliseconds = sent
	verified.ResponseTag = responseTag
	return verified, nil
}

func encodeBody(request Request, messageType byte) [CommonBodyLength]byte {
	var body [CommonBodyLength]byte
	copy(body[0:4], "WBR3")
	body[4] = 1
	body[5] = messageType
	copy(body[8:14], "winn/3")
	copy(body[14:30], request.RunID[:])
	copy(body[30:46], request.AttemptNonce[:])
	copy(body[46:78], request.SourceSHA256[:])
	copy(body[78:110], request.ArtifactSHA256[:])
	copy(body[110:126], request.WCF3SessionID[:])
	copy(body[126:142], request.WCF3BindingID[:])
	binary.BigEndian.PutUint64(body[142:150], request.PSKGeneration)
	binary.BigEndian.PutUint64(body[150:158], request.SequenceEpoch)
	binary.BigEndian.PutUint64(body[158:166], request.CanarySequence)
	binary.BigEndian.PutUint64(body[166:174], request.IssuedAtUnixMilliseconds)
	binary.BigEndian.PutUint64(body[174:182], request.ExpiresAtUnixMilliseconds)
	binary.BigEndian.PutUint64(body[182:190], request.RequestSentMonotonicNanoseconds)
	copy(body[190:222], request.Challenge[:])
	return body
}

func decodeAndValidateBody(raw []byte, expectedType byte) (Request, [CommonBodyLength]byte, error) {
	var request Request
	var body [CommonBodyLength]byte
	if len(raw) != CommonBodyLength {
		return request, body, ErrDatagramLength
	}
	copy(body[:], raw)
	if !hmac.Equal(body[0:4], []byte("WBR3")) ||
		body[4] != 1 ||
		body[5] != expectedType ||
		body[6] != 0 ||
		body[7] != 0 ||
		!hmac.Equal(body[8:14], []byte("winn/3")) {
		return request, body, ErrFixedField
	}
	copy(request.RunID[:], body[14:30])
	copy(request.AttemptNonce[:], body[30:46])
	copy(request.SourceSHA256[:], body[46:78])
	copy(request.ArtifactSHA256[:], body[78:110])
	copy(request.WCF3SessionID[:], body[110:126])
	copy(request.WCF3BindingID[:], body[126:142])
	request.PSKGeneration = binary.BigEndian.Uint64(body[142:150])
	request.SequenceEpoch = binary.BigEndian.Uint64(body[150:158])
	request.CanarySequence = binary.BigEndian.Uint64(body[158:166])
	request.IssuedAtUnixMilliseconds = binary.BigEndian.Uint64(body[166:174])
	request.ExpiresAtUnixMilliseconds = binary.BigEndian.Uint64(body[174:182])
	request.RequestSentMonotonicNanoseconds = binary.BigEndian.Uint64(body[182:190])
	copy(request.Challenge[:], body[190:222])
	if err := validateRequestFields(request); err != nil {
		return Request{}, body, err
	}
	return request, body, nil
}

func validateRequestFields(request Request) error {
	if allZero(request.RunID[:]) ||
		allZero(request.AttemptNonce[:]) ||
		allZero(request.SourceSHA256[:]) ||
		allZero(request.ArtifactSHA256[:]) ||
		allZero(request.WCF3SessionID[:]) ||
		allZero(request.WCF3BindingID[:]) ||
		allZero(request.Challenge[:]) {
		return ErrRequiredField
	}
	if request.PSKGeneration == 0 ||
		request.SequenceEpoch == 0 ||
		request.CanarySequence == 0 {
		return ErrRequiredField
	}
	if request.ExpiresAtUnixMilliseconds <= request.IssuedAtUnixMilliseconds ||
		request.ExpiresAtUnixMilliseconds-request.IssuedAtUnixMilliseconds > MaxLifetimeMilliseconds {
		return ErrLifetime
	}
	return nil
}

func validateReflectorTimes(request Request, received, sent uint64) error {
	if received > sent ||
		received < request.IssuedAtUnixMilliseconds ||
		received > request.ExpiresAtUnixMilliseconds ||
		sent < request.IssuedAtUnixMilliseconds ||
		sent > request.ExpiresAtUnixMilliseconds {
		return ErrReflectorTime
	}
	return nil
}

func validateLeaseBinding(request Request, lease AttemptLease) error {
	if !lease.Active || lease.Cancelled || lease.Superseded ||
		allZero(lease.PathID[:]) {
		return ErrLease
	}
	if !hmac.Equal(lease.AttemptNonce[:], request.AttemptNonce[:]) ||
		!hmac.Equal(lease.WCF3SessionID[:], request.WCF3SessionID[:]) ||
		!hmac.Equal(lease.WCF3BindingID[:], request.WCF3BindingID[:]) ||
		lease.PSKGeneration != request.PSKGeneration ||
		lease.SequenceEpoch != request.SequenceEpoch {
		return ErrLease
	}
	return nil
}

func validateKey(key []byte) error {
	if len(key) != KeyLength {
		return ErrKeyLength
	}
	return nil
}

func authenticate(key, domain, body []byte) [TagLength]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(domain)
	_, _ = mac.Write(body)
	var tag [TagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func allZero(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}
