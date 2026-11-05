// Package carrierauth provides ML-DSA request and response authentication for
// Winn's data-plane carriers. Identity mode combines mTLS with a registered
// device key; anonymous mode uses a one-time blind token whose committed
// ephemeral key signs the same session-bound claims.
package carrierauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
)

const (
	Version = "3"

	AuthModeIdentity        = "identity"
	AuthModeAnonymousToken  = "anonymous-token"
	PrivacyStandard         = "standard"
	PrivacyHighRisk         = "high-risk"
	PurposeData             = "data"
	PurposeAuthenticateOnly = "authenticate-only"
	LabManifestDigest       = "0000000000000000000000000000000000000000000000000000000000000000"

	HeaderVersion       = "X-Winn-Carrier-Version"
	HeaderCarrier       = "X-Winn-Carrier"
	HeaderDeviceID      = "X-Winn-Device-Id"
	HeaderSessionID     = "X-Winn-Session-Id"
	HeaderSequenceEpoch = "X-Winn-Sequence-Epoch"
	HeaderTimestamp     = "X-Winn-Timestamp"
	HeaderNonce         = "X-Winn-Nonce"
	HeaderTarget        = "X-Winn-Udp-Target"
	HeaderSuite         = "X-Winn-Suite"
	HeaderAuthMode      = "X-Winn-Authorization-Mode"
	HeaderManifest      = "X-Winn-Manifest-Digest"
	HeaderMaxDatagram   = "X-Winn-Max-Inner-Datagram"
	HeaderPrivacy       = "X-Winn-Privacy-Profile"
	HeaderPurpose       = "X-Winn-Carrier-Purpose"
	HeaderControllerID  = "X-Winn-Controller-Id"
	HeaderAuthAlgorithm = "X-Winn-Auth-Algorithm"
	HeaderAuthKeyID     = "X-Winn-Auth-Key-Id"
	HeaderSignature     = "X-Winn-Auth-Signature"

	maxTextHeader = 512
	nonceBytes    = 24
)

type RequestClaims struct {
	Version       string `json:"version"`
	Carrier       string `json:"carrier"`
	Method        string `json:"method"`
	Authority     string `json:"authority"`
	RequestTarget string `json:"request_target"`
	UDPTarget     string `json:"udp_target"`
	DeviceID      string `json:"device_id"`
	SessionID     string `json:"session_id"`
	SequenceEpoch string `json:"sequence_epoch"`
	Timestamp     string `json:"timestamp"`
	Nonce         string `json:"nonce"`
	Suite         string `json:"suite"`
	AuthMode      string `json:"authorization_mode"`
	Manifest      string `json:"manifest_digest"`
	MaxDatagram   int    `json:"max_inner_datagram"`
	Privacy       string `json:"privacy_profile"`
	Purpose       string `json:"purpose"`
	AuthAlgorithm string `json:"auth_algorithm"`
	AuthKeyID     string `json:"auth_key_id"`
}

type ResponseClaims struct {
	Version       string `json:"version"`
	Status        int    `json:"status"`
	Carrier       string `json:"carrier"`
	ControllerID  string `json:"controller_id"`
	DeviceID      string `json:"device_id"`
	SessionID     string `json:"session_id"`
	SequenceEpoch string `json:"sequence_epoch"`
	RequestNonce  string `json:"request_nonce"`
	Timestamp     string `json:"timestamp"`
	Suite         string `json:"suite"`
	AuthMode      string `json:"authorization_mode"`
	Manifest      string `json:"manifest_digest"`
	MaxDatagram   int    `json:"max_inner_datagram"`
	Privacy       string `json:"privacy_profile"`
	Purpose       string `json:"purpose"`
	AuthAlgorithm string `json:"auth_algorithm"`
	AuthKeyID     string `json:"auth_key_id"`
}

// ErrDeviceRevoked reports that an otherwise valid identity-mode request came
// from a device the controller has revoked.
var ErrDeviceRevoked = errors.New("carrier device is revoked")

// DeviceRevocations is the carrier's view of control-plane revocation
// decisions. internal/revocation implements it over a signed, sequence-pinned
// list; the interface keeps this package free of any dependency on how that
// list is distributed.
//
// It is consulted in identity mode only. Anonymous-token mode has no stable
// device identity to revoke, which is the point of it, so VerifyAnonymous
// deliberately does not call this.
type DeviceRevocations interface {
	RevokedDevice(deviceID string) bool
}

type RequestVerifier struct {
	Registry *pqauth.Registry
	Replay   *ReplayCache
	Suite    string
	MaxSkew  time.Duration
	Now      func() time.Time
	// Revocations, when set, is consulted for every identity-mode request. A
	// nil value means revocation is not enforced on this carrier; the carrier
	// server refuses to start in that configuration outside lab mode.
	Revocations            DeviceRevocations
	RequiredManifestDigest string
}

type RequestOptions struct {
	AuthorizationMode string
	ManifestDigest    string
	MaxInnerDatagram  int
	PrivacyProfile    string
	SequenceEpoch     string
	Purpose           string
}

type ResponseVerifier struct {
	Verifiers    *pqauth.VerifierSet
	ControllerID string
	Suite        string
	MaxSkew      time.Duration
	Now          func() time.Time
}

func NewRequestClaims(request *http.Request, carrier, udpTarget, deviceID, sessionID, suite string, signer *pqauth.Signer, now time.Time) (RequestClaims, error) {
	return NewRequestClaimsWithOptions(
		request, carrier, udpTarget, deviceID, sessionID, suite, signer, now,
		RequestOptions{
			AuthorizationMode: AuthModeIdentity,
			ManifestDigest:    LabManifestDigest,
			MaxInnerDatagram:  1350,
			PrivacyProfile:    PrivacyStandard,
			SequenceEpoch:     sessionID,
			Purpose:           PurposeData,
		},
	)
}

func NewRequestClaimsWithOptions(request *http.Request, carrier, udpTarget, deviceID, sessionID, suite string, signer *pqauth.Signer, now time.Time, options RequestOptions) (RequestClaims, error) {
	if request == nil || request.URL == nil {
		return RequestClaims{}, errors.New("HTTP request URL is required")
	}
	if signer == nil {
		return RequestClaims{}, errors.New("device ML-DSA signer is required")
	}
	nonce, err := NewNonce()
	if err != nil {
		return RequestClaims{}, err
	}
	if options.SequenceEpoch == "" {
		options.SequenceEpoch = sessionID
	}
	if options.Purpose == "" {
		options.Purpose = PurposeData
	}
	claims := RequestClaims{
		Version:       Version,
		Carrier:       carrier,
		Method:        request.Method,
		Authority:     request.Host,
		RequestTarget: request.URL.RequestURI(),
		UDPTarget:     udpTarget,
		DeviceID:      deviceID,
		SessionID:     sessionID,
		SequenceEpoch: options.SequenceEpoch,
		Timestamp:     strconv.FormatInt(now.UTC().UnixMilli(), 10),
		Nonce:         nonce,
		Suite:         suite,
		AuthMode:      options.AuthorizationMode,
		Manifest:      options.ManifestDigest,
		MaxDatagram:   options.MaxInnerDatagram,
		Privacy:       options.PrivacyProfile,
		Purpose:       options.Purpose,
		AuthAlgorithm: signer.Algorithm(),
		AuthKeyID:     signer.KeyID(),
	}
	if err := validateRequestClaims(claims); err != nil {
		return RequestClaims{}, err
	}
	return claims, nil
}

func SignRequest(header http.Header, claims RequestClaims, signer *pqauth.Signer) error {
	if header == nil {
		return errors.New("HTTP header map is required")
	}
	if signer == nil || claims.AuthAlgorithm != signer.Algorithm() || claims.AuthKeyID != signer.KeyID() {
		return errors.New("request claims do not match device signer")
	}
	if err := validateRequestClaims(claims); err != nil {
		return err
	}
	message, err := canonical(claims)
	if err != nil {
		return err
	}
	signature, err := pqauth.SignCarrierMessage(message, signer)
	if err != nil {
		return err
	}
	defer clear(signature)
	setRequestHeaders(header, claims)
	header.Set(HeaderSignature, base64.RawStdEncoding.EncodeToString(signature))
	return nil
}

func (v *RequestVerifier) Verify(request *http.Request, expectedCarrier, expectedTarget, certificateDeviceID string) (RequestClaims, error) {
	if v == nil || v.Registry == nil || v.Replay == nil {
		return RequestClaims{}, errors.New("carrier request verifier is not configured")
	}
	if request == nil || request.URL == nil {
		return RequestClaims{}, errors.New("HTTP request URL is required")
	}
	claims, signature, err := requestClaimsFromHeaders(request)
	if err != nil {
		return RequestClaims{}, err
	}
	if err := validateRequestClaims(claims); err != nil {
		return RequestClaims{}, err
	}
	if claims.Method != request.Method || claims.Authority != request.Host ||
		claims.RequestTarget != request.URL.RequestURI() {
		return RequestClaims{}, errors.New("carrier signature does not bind this HTTP request")
	}
	if claims.Carrier != expectedCarrier || claims.UDPTarget != expectedTarget {
		return RequestClaims{}, errors.New("carrier or fixed UDP target mismatch")
	}
	if claims.AuthMode != AuthModeIdentity || claims.DeviceID != certificateDeviceID {
		return RequestClaims{}, errors.New("carrier device identity does not match mTLS certificate")
	}
	if claims.Suite != v.Suite {
		return RequestClaims{}, errors.New("carrier cryptographic suite mismatch")
	}
	if v.RequiredManifestDigest != "" && claims.Manifest != v.RequiredManifestDigest {
		return RequestClaims{}, errors.New("carrier gateway manifest binding mismatch")
	}
	timestamp, err := parseTimestamp(claims.Timestamp)
	if err != nil {
		return RequestClaims{}, err
	}
	now := v.now()
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = 2 * time.Minute
	}
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return RequestClaims{}, errors.New("carrier request timestamp is outside the acceptance window")
	}
	verifier, err := v.Registry.Verifier(claims.DeviceID, claims.AuthAlgorithm, claims.AuthKeyID)
	if err != nil {
		return RequestClaims{}, err
	}
	message, err := canonical(claims)
	if err != nil {
		return RequestClaims{}, err
	}
	if err := pqauth.VerifyCarrierMessage(message, signature, verifier); err != nil {
		return RequestClaims{}, err
	}
	// Revocation is checked here, after the ML-DSA signature and before the
	// replay cache, and both halves of that placement are deliberate.
	//
	// After the signature: at this point the peer has proved possession of the
	// registered device key, so the rejection is an authenticated statement
	// about a device that really is this device. Checking earlier would answer
	// "is this device ID revoked?" to anyone willing to guess an identifier in
	// a header, turning the carrier into an oracle that enumerates the
	// revocation list to an unauthenticated prober. The saved verification
	// work is not worth that, and mTLS has already run regardless.
	//
	// Before the replay cache: a revoked device is refused either way, so its
	// nonces should not consume entries in a bounded cache that legitimate
	// devices share.
	if v.Revocations != nil && v.Revocations.RevokedDevice(claims.DeviceID) {
		return RequestClaims{}, ErrDeviceRevoked
	}
	// ReplayCache.Use requires expires.After(now). At the inclusive lower
	// skew bound, timestamp.Add(maxSkew) equals now, so a 1ns remainder
	// keeps a still-valid request in the cache instead of rejecting it as
	// "invalid replay cache entry".
	if err := v.Replay.Use(claims.DeviceID+"|"+claims.Nonce, timestamp.Add(maxSkew+time.Nanosecond), now); err != nil {
		return RequestClaims{}, err
	}
	return claims, nil
}

// VerifyAnonymous verifies a request using the one-time ML-DSA key committed
// inside an already-validated blind authorization token. It deliberately does
// not consult the stable device registry or a client certificate.
func (v *RequestVerifier) VerifyAnonymous(request *http.Request, expectedCarrier, expectedTarget, pseudonym, tokenID string, verifier *pqauth.Verifier) (RequestClaims, error) {
	if v == nil || v.Replay == nil || verifier == nil || pseudonym == "" || tokenID == "" {
		return RequestClaims{}, errors.New("anonymous carrier request verifier is not configured")
	}
	if request == nil || request.URL == nil {
		return RequestClaims{}, errors.New("HTTP request URL is required")
	}
	claims, signature, err := requestClaimsFromHeaders(request)
	if err != nil {
		return RequestClaims{}, err
	}
	if err := validateRequestClaims(claims); err != nil {
		return RequestClaims{}, err
	}
	if claims.AuthMode != AuthModeAnonymousToken || claims.DeviceID != pseudonym ||
		claims.Method != request.Method || claims.Authority != request.Host ||
		claims.RequestTarget != request.URL.RequestURI() ||
		claims.Carrier != expectedCarrier || claims.UDPTarget != expectedTarget ||
		claims.Suite != v.Suite ||
		claims.AuthAlgorithm != verifier.Algorithm() ||
		claims.AuthKeyID != verifier.KeyID() {
		return RequestClaims{}, errors.New("anonymous carrier request binding mismatch")
	}
	if v.RequiredManifestDigest != "" && claims.Manifest != v.RequiredManifestDigest {
		return RequestClaims{}, errors.New("carrier gateway manifest binding mismatch")
	}
	timestamp, err := parseTimestamp(claims.Timestamp)
	if err != nil {
		return RequestClaims{}, err
	}
	now := v.now()
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = 2 * time.Minute
	}
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return RequestClaims{}, errors.New("carrier request timestamp is outside the acceptance window")
	}
	message, err := canonical(claims)
	if err != nil {
		return RequestClaims{}, err
	}
	if err := pqauth.VerifyCarrierMessage(message, signature, verifier); err != nil {
		return RequestClaims{}, err
	}
	// Same 1ns remainder as identity Verify: the inclusive lower skew bound
	// makes timestamp.Add(maxSkew) equal now, which ReplayCache.Use rejects.
	if err := v.Replay.Use(tokenID+"|"+claims.Nonce, timestamp.Add(maxSkew+time.Nanosecond), now); err != nil {
		return RequestClaims{}, err
	}
	return claims, nil
}

func NewResponseClaims(status int, carrier, controllerID, suite string, request RequestClaims, signer *pqauth.Signer, now time.Time) (ResponseClaims, error) {
	return NewResponseClaimsWithMaximum(status, carrier, controllerID, suite, request, signer, now, request.MaxDatagram)
}

func NewResponseClaimsWithMaximum(status int, carrier, controllerID, suite string, request RequestClaims, signer *pqauth.Signer, now time.Time, serverMaximum int) (ResponseClaims, error) {
	if signer == nil {
		return ResponseClaims{}, errors.New("controller ML-DSA signer is required")
	}
	claims := ResponseClaims{
		Version:       Version,
		Status:        status,
		Carrier:       carrier,
		ControllerID:  controllerID,
		DeviceID:      request.DeviceID,
		SessionID:     request.SessionID,
		SequenceEpoch: request.SequenceEpoch,
		RequestNonce:  request.Nonce,
		Timestamp:     strconv.FormatInt(now.UTC().UnixMilli(), 10),
		Suite:         suite,
		AuthMode:      request.AuthMode,
		Manifest:      request.Manifest,
		MaxDatagram:   min(request.MaxDatagram, serverMaximum),
		Privacy:       request.Privacy,
		Purpose:       request.Purpose,
		AuthAlgorithm: signer.Algorithm(),
		AuthKeyID:     signer.KeyID(),
	}
	if err := validateResponseClaims(claims); err != nil {
		return ResponseClaims{}, err
	}
	return claims, nil
}

func SignResponse(header http.Header, claims ResponseClaims, signer *pqauth.Signer) error {
	if header == nil {
		return errors.New("HTTP header map is required")
	}
	if signer == nil || claims.AuthAlgorithm != signer.Algorithm() || claims.AuthKeyID != signer.KeyID() {
		return errors.New("response claims do not match controller signer")
	}
	if err := validateResponseClaims(claims); err != nil {
		return err
	}
	message, err := canonical(claims)
	if err != nil {
		return err
	}
	signature, err := pqauth.SignCarrierMessage(message, signer)
	if err != nil {
		return err
	}
	defer clear(signature)
	setResponseHeaders(header, claims)
	header.Set(HeaderSignature, base64.RawStdEncoding.EncodeToString(signature))
	return nil
}

func (v *ResponseVerifier) Verify(response *http.Response, request RequestClaims, expectedCarrier string) (ResponseClaims, error) {
	if v == nil || v.Verifiers == nil {
		return ResponseClaims{}, errors.New("carrier response verifier is not configured")
	}
	if response == nil {
		return ResponseClaims{}, errors.New("HTTP response is required")
	}
	claims, signature, err := responseClaimsFromHeaders(response.Header, response.StatusCode)
	if err != nil {
		return ResponseClaims{}, err
	}
	if err := validateResponseClaims(claims); err != nil {
		return ResponseClaims{}, err
	}
	if claims.Status != response.StatusCode || claims.Carrier != expectedCarrier ||
		claims.ControllerID != v.ControllerID || claims.Suite != v.Suite ||
		claims.DeviceID != request.DeviceID || claims.SessionID != request.SessionID ||
		claims.SequenceEpoch != request.SequenceEpoch ||
		claims.RequestNonce != request.Nonce ||
		claims.AuthMode != request.AuthMode || claims.Manifest != request.Manifest ||
		claims.MaxDatagram <= 0 || claims.MaxDatagram > request.MaxDatagram ||
		claims.Privacy != request.Privacy ||
		claims.Purpose != request.Purpose {
		return ResponseClaims{}, errors.New("controller signature does not bind this carrier response")
	}
	timestamp, err := parseTimestamp(claims.Timestamp)
	if err != nil {
		return ResponseClaims{}, err
	}
	now := v.now()
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = 2 * time.Minute
	}
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return ResponseClaims{}, errors.New("carrier response timestamp is outside the acceptance window")
	}
	verifier, err := v.Verifiers.Verifier(claims.AuthAlgorithm, claims.AuthKeyID)
	if err != nil {
		return ResponseClaims{}, err
	}
	message, err := canonical(claims)
	if err != nil {
		return ResponseClaims{}, err
	}
	if err := pqauth.VerifyCarrierMessage(message, signature, verifier); err != nil {
		return ResponseClaims{}, err
	}
	return claims, nil
}

func NewNonce() (string, error) {
	value := make([]byte, nonceBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate carrier nonce: %w", err)
	}
	defer clear(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (v *RequestVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

// CurrentTime exposes the verifier's clock to adjacent authentication layers
// so token validity and signed-request freshness use one consistent instant.
func (v *RequestVerifier) CurrentTime() time.Time {
	if v == nil {
		return time.Now().UTC()
	}
	return v.now()
}

func (v *ResponseVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now().UTC()
	}
	return time.Now().UTC()
}

func canonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode carrier authentication message: %w", err)
	}
	return encoded, nil
}

func setRequestHeaders(header http.Header, claims RequestClaims) {
	header.Set(HeaderVersion, claims.Version)
	header.Set(HeaderCarrier, claims.Carrier)
	header.Set(HeaderDeviceID, claims.DeviceID)
	header.Set(HeaderSessionID, claims.SessionID)
	header.Set(HeaderSequenceEpoch, claims.SequenceEpoch)
	header.Set(HeaderTimestamp, claims.Timestamp)
	header.Set(HeaderNonce, claims.Nonce)
	header.Set(HeaderTarget, claims.UDPTarget)
	header.Set(HeaderSuite, claims.Suite)
	header.Set(HeaderAuthMode, claims.AuthMode)
	header.Set(HeaderManifest, claims.Manifest)
	header.Set(HeaderMaxDatagram, strconv.Itoa(claims.MaxDatagram))
	header.Set(HeaderPrivacy, claims.Privacy)
	header.Set(HeaderPurpose, claims.Purpose)
	header.Set(HeaderAuthAlgorithm, claims.AuthAlgorithm)
	header.Set(HeaderAuthKeyID, claims.AuthKeyID)
}

func setResponseHeaders(header http.Header, claims ResponseClaims) {
	header.Set(HeaderVersion, claims.Version)
	header.Set(HeaderCarrier, claims.Carrier)
	header.Set(HeaderControllerID, claims.ControllerID)
	header.Set(HeaderDeviceID, claims.DeviceID)
	header.Set(HeaderSessionID, claims.SessionID)
	header.Set(HeaderSequenceEpoch, claims.SequenceEpoch)
	header.Set(HeaderTimestamp, claims.Timestamp)
	header.Set(HeaderNonce, claims.RequestNonce)
	header.Set(HeaderSuite, claims.Suite)
	header.Set(HeaderAuthMode, claims.AuthMode)
	header.Set(HeaderManifest, claims.Manifest)
	header.Set(HeaderMaxDatagram, strconv.Itoa(claims.MaxDatagram))
	header.Set(HeaderPrivacy, claims.Privacy)
	header.Set(HeaderPurpose, claims.Purpose)
	header.Set(HeaderAuthAlgorithm, claims.AuthAlgorithm)
	header.Set(HeaderAuthKeyID, claims.AuthKeyID)
}

func requestClaimsFromHeaders(request *http.Request) (RequestClaims, []byte, error) {
	signature, err := signatureHeader(request.Header)
	if err != nil {
		return RequestClaims{}, nil, err
	}
	claims := RequestClaims{
		Version:       oneHeader(request.Header, HeaderVersion),
		Carrier:       oneHeader(request.Header, HeaderCarrier),
		Method:        request.Method,
		Authority:     request.Host,
		RequestTarget: request.URL.RequestURI(),
		UDPTarget:     oneHeader(request.Header, HeaderTarget),
		DeviceID:      oneHeader(request.Header, HeaderDeviceID),
		SessionID:     oneHeader(request.Header, HeaderSessionID),
		SequenceEpoch: oneHeader(request.Header, HeaderSequenceEpoch),
		Timestamp:     oneHeader(request.Header, HeaderTimestamp),
		Nonce:         oneHeader(request.Header, HeaderNonce),
		Suite:         oneHeader(request.Header, HeaderSuite),
		AuthMode:      oneHeader(request.Header, HeaderAuthMode),
		Manifest:      oneHeader(request.Header, HeaderManifest),
		MaxDatagram:   parsePositiveHeader(request.Header, HeaderMaxDatagram),
		Privacy:       oneHeader(request.Header, HeaderPrivacy),
		Purpose:       oneHeader(request.Header, HeaderPurpose),
		AuthAlgorithm: oneHeader(request.Header, HeaderAuthAlgorithm),
		AuthKeyID:     oneHeader(request.Header, HeaderAuthKeyID),
	}
	return claims, signature, nil
}

func responseClaimsFromHeaders(header http.Header, status int) (ResponseClaims, []byte, error) {
	signature, err := signatureHeader(header)
	if err != nil {
		return ResponseClaims{}, nil, err
	}
	claims := ResponseClaims{
		Version:       oneHeader(header, HeaderVersion),
		Status:        status,
		Carrier:       oneHeader(header, HeaderCarrier),
		ControllerID:  oneHeader(header, HeaderControllerID),
		DeviceID:      oneHeader(header, HeaderDeviceID),
		SessionID:     oneHeader(header, HeaderSessionID),
		SequenceEpoch: oneHeader(header, HeaderSequenceEpoch),
		RequestNonce:  oneHeader(header, HeaderNonce),
		Timestamp:     oneHeader(header, HeaderTimestamp),
		Suite:         oneHeader(header, HeaderSuite),
		AuthMode:      oneHeader(header, HeaderAuthMode),
		Manifest:      oneHeader(header, HeaderManifest),
		MaxDatagram:   parsePositiveHeader(header, HeaderMaxDatagram),
		Privacy:       oneHeader(header, HeaderPrivacy),
		Purpose:       oneHeader(header, HeaderPurpose),
		AuthAlgorithm: oneHeader(header, HeaderAuthAlgorithm),
		AuthKeyID:     oneHeader(header, HeaderAuthKeyID),
	}
	return claims, signature, nil
}

func signatureHeader(header http.Header) ([]byte, error) {
	values := header.Values(HeaderSignature)
	if len(values) != 1 || values[0] == "" || len(values[0]) > 16<<10 {
		return nil, errors.New("exactly one bounded carrier signature header is required")
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(values[0])
	if err != nil {
		return nil, errors.New("carrier signature encoding is invalid")
	}
	if len(signature) == 0 {
		return nil, errors.New("carrier signature is empty")
	}
	return signature, nil
}

func oneHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 || len(values[0]) > maxTextHeader {
		return ""
	}
	return values[0]
}

func validateRequestClaims(claims RequestClaims) error {
	if claims.Version != Version {
		return errors.New("unsupported carrier authentication version")
	}
	if !validCarrier(claims.Carrier) || claims.Method == "" || claims.Authority == "" ||
		claims.RequestTarget == "" || strings.ContainsAny(claims.Method, "\r\n") ||
		strings.ContainsAny(claims.Authority, "\r\n") ||
		strings.ContainsAny(claims.RequestTarget, "\r\n") {
		return errors.New("invalid carrier request binding")
	}
	if claims.UDPTarget == "" || len(claims.UDPTarget) > maxTextHeader {
		return errors.New("invalid carrier UDP target")
	}
	if !protocol.ValidDeviceID(claims.DeviceID) ||
		!mobility.ValidSessionID(claims.SessionID) ||
		!mobility.ValidSessionID(claims.SequenceEpoch) {
		return errors.New("invalid carrier device or session identity")
	}
	if _, err := parseTimestamp(claims.Timestamp); err != nil {
		return err
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(claims.Nonce)
	if err != nil || len(nonce) != nonceBytes {
		return errors.New("invalid carrier nonce")
	}
	clear(nonce)
	if claims.Suite == "" || claims.AuthAlgorithm == "" || claims.AuthKeyID == "" ||
		len(claims.Suite) > maxTextHeader || len(claims.AuthAlgorithm) > maxTextHeader ||
		len(claims.AuthKeyID) > maxTextHeader {
		return errors.New("invalid carrier cryptographic binding")
	}
	if (claims.AuthMode != AuthModeIdentity && claims.AuthMode != AuthModeAnonymousToken) ||
		!validDigest(claims.Manifest) || claims.MaxDatagram < 576 ||
		claims.MaxDatagram > 1500 ||
		(claims.Privacy != PrivacyStandard && claims.Privacy != PrivacyHighRisk) ||
		(claims.Purpose != PurposeData &&
			claims.Purpose != PurposeAuthenticateOnly) {
		return errors.New("invalid carrier authorization, manifest, or MTU binding")
	}
	return nil
}

func validateResponseClaims(claims ResponseClaims) error {
	if claims.Version != Version || claims.Status < 200 || claims.Status > 299 ||
		!validCarrier(claims.Carrier) || claims.ControllerID == "" ||
		len(claims.ControllerID) > maxTextHeader {
		return errors.New("invalid carrier response binding")
	}
	if !protocol.ValidDeviceID(claims.DeviceID) ||
		!mobility.ValidSessionID(claims.SessionID) ||
		!mobility.ValidSessionID(claims.SequenceEpoch) {
		return errors.New("invalid carrier response identity")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(claims.RequestNonce)
	if err != nil || len(nonce) != nonceBytes {
		return errors.New("invalid carrier response nonce")
	}
	clear(nonce)
	if _, err := parseTimestamp(claims.Timestamp); err != nil {
		return err
	}
	if claims.Suite == "" || claims.AuthAlgorithm == "" || claims.AuthKeyID == "" {
		return errors.New("invalid carrier response cryptographic binding")
	}
	if (claims.AuthMode != AuthModeIdentity && claims.AuthMode != AuthModeAnonymousToken) ||
		!validDigest(claims.Manifest) || claims.MaxDatagram < 576 ||
		claims.MaxDatagram > 1500 ||
		(claims.Privacy != PrivacyStandard && claims.Privacy != PrivacyHighRisk) ||
		(claims.Purpose != PurposeData &&
			claims.Purpose != PurposeAuthenticateOnly) {
		return errors.New("invalid carrier response authorization, manifest, or MTU binding")
	}
	return nil
}

func parsePositiveHeader(header http.Header, name string) int {
	value := oneHeader(header, name)
	if value == "" || strings.HasPrefix(value, "+") ||
		(len(value) > 1 && strings.HasPrefix(value, "0")) {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0
	}
	return parsed
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validCarrier(carrier string) bool {
	switch mobility.Carrier(carrier) {
	case mobility.DirectUDP, mobility.HTTP3, mobility.HTTP2:
		return true
	default:
		return false
	}
}

func parseTimestamp(value string) (time.Time, error) {
	if value == "" || len(value) > 20 || strings.HasPrefix(value, "+") ||
		(len(value) > 1 && strings.HasPrefix(value, "0")) {
		return time.Time{}, errors.New("invalid carrier timestamp")
	}
	milliseconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || milliseconds < 0 {
		return time.Time{}, errors.New("invalid carrier timestamp")
	}
	return time.UnixMilli(milliseconds).UTC(), nil
}
