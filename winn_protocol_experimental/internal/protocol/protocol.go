package protocol

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	Version   = "winn/2"
	RekeyPath = "/v2/rekeys"
	MediaType = "application/vnd.winn.rekey+json"

	CapabilityHybridKEX = "tls13-x25519-mlkem768"
	CapabilityP256KEX   = "tls13-p256-mlkem768"
	CapabilityP384KEX   = "tls13-p384-mlkem1024"
	CapabilityMutualTLS = "mutual-x509-auth"
	CapabilityAWGPSK    = "awg-preshared-key-32"
	CapabilityMonotonic = "monotonic-key-generation"
	CapabilityMLDSA65   = "dual-auth-x509-mldsa65"
	CapabilityMLDSA87   = "dual-auth-x509-mldsa87"

	SuiteX25519MLKEM768 = "x25519-mlkem768"
	SuiteP256MLKEM768   = "p256-mlkem768"
	SuiteP384MLKEM1024  = "p384-mlkem1024"
	DefaultSuite        = SuiteX25519MLKEM768
	MaxKeyLifetime      = 30 * 24 * time.Hour
	MaxGeneration       = uint64(1<<63 - 1)

	AuthMLDSA65 = "mldsa65"
	AuthMLDSA87 = "mldsa87"
)

var (
	deviceIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	baseCapabilities = []string{
		CapabilityMutualTLS,
		CapabilityAWGPSK,
		CapabilityMonotonic,
	}
)

type RekeyRequest struct {
	Version           string   `json:"version"`
	Suite             string   `json:"suite"`
	ControllerID      string   `json:"controller_id"`
	DeviceID          string   `json:"device_id"`
	PeerPublicKey     string   `json:"peer_public_key"`
	RequestID         string   `json:"request_id"`
	Nonce             string   `json:"nonce"`
	CurrentGeneration uint64   `json:"current_generation"`
	Capabilities      []string `json:"capabilities"`
	AuthAlgorithm     string   `json:"auth_algorithm"`
	AuthKeyID         string   `json:"auth_key_id"`
	AuthSignature     string   `json:"auth_signature"`
}

type RekeyResponse struct {
	Version       string   `json:"version"`
	Suite         string   `json:"suite"`
	ControllerID  string   `json:"controller_id"`
	DeviceID      string   `json:"device_id"`
	PeerPublicKey string   `json:"peer_public_key"`
	RequestID     string   `json:"request_id"`
	Nonce         string   `json:"nonce"`
	Generation    uint64   `json:"generation"`
	KeyID         string   `json:"key_id"`
	PresharedKey  string   `json:"preshared_key"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	Capabilities  []string `json:"capabilities"`
	AuthAlgorithm string   `json:"auth_algorithm"`
	AuthKeyID     string   `json:"auth_key_id"`
	AuthSignature string   `json:"auth_signature"`
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func RequiredCapabilities(suite string) []string {
	result := slices.Clone(baseCapabilities)
	switch suite {
	case SuiteX25519MLKEM768:
		result = append(result, CapabilityHybridKEX)
		result = append(result, CapabilityMLDSA65)
	case SuiteP256MLKEM768:
		result = append(result, CapabilityP256KEX)
		result = append(result, CapabilityMLDSA65)
	case SuiteP384MLKEM1024:
		result = append(result, CapabilityP384KEX)
		result = append(result, CapabilityMLDSA87)
	default:
		return nil
	}
	slices.Sort(result)
	return result
}

func SupportedSuites() []string {
	return []string{SuiteX25519MLKEM768, SuiteP256MLKEM768, SuiteP384MLKEM1024}
}

func ValidSuite(value string) bool {
	return RequiredCapabilities(value) != nil
}

func RequiredAuthAlgorithm(suite string) string {
	switch suite {
	case SuiteX25519MLKEM768, SuiteP256MLKEM768:
		return AuthMLDSA65
	case SuiteP384MLKEM1024:
		return AuthMLDSA87
	default:
		return ""
	}
}

func ValidDeviceID(value string) bool {
	return deviceIDPattern.MatchString(value)
}

func ValidatePeerPublicKey(value string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return fmt.Errorf("peer public key must be canonical base64: %w", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("peer public key decoded length is %d, want 32", len(decoded))
	}
	var nonzero byte
	for _, b := range decoded {
		nonzero |= b
	}
	if subtle.ConstantTimeByteEq(nonzero, 0) == 1 {
		return errors.New("peer public key must not be all zero")
	}
	return nil
}

// ValidateRequest checks version, suite, identifiers, token encoding,
// generation, required capabilities, and ML-DSA field framing.
// It does not verify AuthSignature; callers must use pqauth.VerifyRequest.
func ValidateRequest(req RekeyRequest) error {
	if req.Version != Version {
		return fmt.Errorf("version must be %q", Version)
	}
	if !ValidSuite(req.Suite) {
		return errors.New("unsupported cryptographic suite")
	}
	if !ValidDeviceID(req.ControllerID) {
		return errors.New("invalid controller_id")
	}
	if !ValidDeviceID(req.DeviceID) {
		return errors.New("invalid device_id")
	}
	if err := ValidatePeerPublicKey(req.PeerPublicKey); err != nil {
		return err
	}
	if err := validateRandomToken("request_id", req.RequestID); err != nil {
		return err
	}
	if err := validateRandomToken("nonce", req.Nonce); err != nil {
		return err
	}
	if req.CurrentGeneration >= MaxGeneration {
		return errors.New("generation exhausted")
	}
	if !HasRequiredCapabilities(req.Suite, req.Capabilities) {
		return errors.New("required capabilities are missing")
	}
	if err := validateAuthentication(req.Suite, req.AuthAlgorithm, req.AuthKeyID, req.AuthSignature); err != nil {
		return err
	}
	return nil
}

// HasRequiredCapabilities reports whether got includes every capability
// RequiredCapabilities(suite) names, with no empty or duplicate entries.
// Extra capabilities are allowed. An unknown suite returns false.
func HasRequiredCapabilities(suite string, got []string) bool {
	required := RequiredCapabilities(suite)
	if required == nil {
		return false
	}
	seen := make(map[string]struct{}, len(got))
	for _, capability := range got {
		if capability == "" {
			return false
		}
		if _, duplicate := seen[capability]; duplicate {
			return false
		}
		seen[capability] = struct{}{}
	}
	for _, capability := range required {
		if _, ok := seen[capability]; !ok {
			return false
		}
	}
	return true
}

// ValidateResponse checks version, suite, request binding, generation,
// capabilities, ML-DSA field framing, lifetime windows, and key_id.
// It does not verify AuthSignature; callers must use pqauth.VerifyResponse.
// On success it returns the decoded 32-byte PSK.
func ValidateResponse(req RekeyRequest, resp RekeyResponse, now time.Time) ([]byte, error) {
	if resp.Version != Version {
		return nil, fmt.Errorf("response version must be %q", Version)
	}
	if !ValidSuite(req.Suite) || !ValidSuite(resp.Suite) {
		return nil, errors.New("unsupported cryptographic suite")
	}
	if resp.Suite != req.Suite ||
		resp.ControllerID != req.ControllerID ||
		resp.DeviceID != req.DeviceID ||
		resp.PeerPublicKey != req.PeerPublicKey ||
		resp.RequestID != req.RequestID ||
		resp.Nonce != req.Nonce {
		return nil, errors.New("response request binding mismatch")
	}
	if req.CurrentGeneration >= MaxGeneration || resp.Generation != req.CurrentGeneration+1 {
		return nil, errors.New("response generation is not the next generation")
	}
	if !HasRequiredCapabilities(resp.Suite, resp.Capabilities) {
		return nil, errors.New("response is missing required capabilities")
	}
	if err := validateAuthentication(resp.Suite, resp.AuthAlgorithm, resp.AuthKeyID, resp.AuthSignature); err != nil {
		return nil, err
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, resp.IssuedAt)
	if err != nil {
		return nil, errors.New("invalid issued_at")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, resp.ExpiresAt)
	if err != nil {
		return nil, errors.New("invalid expires_at")
	}
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return nil, errors.New("issued_at is unreasonably far in the future")
	}
	if !expiresAt.After(now) || !expiresAt.After(issuedAt) {
		return nil, errors.New("key is already expired or has an invalid lifetime")
	}
	if expiresAt.Sub(issuedAt) < time.Minute {
		return nil, errors.New("key lifetime is below the protocol minimum")
	}
	if expiresAt.Sub(issuedAt) > MaxKeyLifetime {
		return nil, errors.New("key lifetime exceeds the protocol maximum")
	}
	psk, err := base64.StdEncoding.Strict().DecodeString(resp.PresharedKey)
	if err != nil || len(psk) != 32 {
		clear(psk)
		return nil, errors.New("preshared_key must be canonical base64 for 32 bytes")
	}
	var nonzero byte
	for _, b := range psk {
		nonzero |= b
	}
	if subtle.ConstantTimeByteEq(nonzero, 0) == 1 {
		clear(psk)
		return nil, errors.New("preshared_key must not be all zero")
	}
	expectedID := KeyID(req.ControllerID, req.Suite, req.DeviceID, req.PeerPublicKey, resp.Generation, psk)
	if subtle.ConstantTimeCompare([]byte(expectedID), []byte(resp.KeyID)) != 1 {
		clear(psk)
		return nil, errors.New("key_id binding mismatch")
	}
	return psk, nil
}

func RequestDigest(req RekeyRequest) ([32]byte, error) {
	encoded, err := RequestSigningMessage(req)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("winn-rekey-request-digest/v2\x00"), encoded...)), nil
}

func KeyID(controllerID, suite, deviceID, peerPublicKey string, generation uint64, psk []byte) string {
	hash := sha256.New()
	hash.Write([]byte("winn-awg-psk-id/v2\x00"))
	hash.Write([]byte(controllerID))
	hash.Write([]byte{0})
	hash.Write([]byte(suite))
	hash.Write([]byte{0})
	hash.Write([]byte(deviceID))
	hash.Write([]byte{0})
	hash.Write([]byte(peerPublicKey))
	hash.Write([]byte{0})
	var generationBytes [8]byte
	binary.BigEndian.PutUint64(generationBytes[:], generation)
	hash.Write(generationBytes[:])
	hash.Write([]byte{0})
	hash.Write(psk)
	return hex.EncodeToString(hash.Sum(nil))
}

func RequestSigningMessage(req RekeyRequest) ([]byte, error) {
	unsigned := struct {
		Version           string   `json:"version"`
		Suite             string   `json:"suite"`
		ControllerID      string   `json:"controller_id"`
		DeviceID          string   `json:"device_id"`
		PeerPublicKey     string   `json:"peer_public_key"`
		RequestID         string   `json:"request_id"`
		Nonce             string   `json:"nonce"`
		CurrentGeneration uint64   `json:"current_generation"`
		Capabilities      []string `json:"capabilities"`
		AuthAlgorithm     string   `json:"auth_algorithm"`
		AuthKeyID         string   `json:"auth_key_id"`
	}{
		Version:           req.Version,
		Suite:             req.Suite,
		ControllerID:      req.ControllerID,
		DeviceID:          req.DeviceID,
		PeerPublicKey:     req.PeerPublicKey,
		RequestID:         req.RequestID,
		Nonce:             req.Nonce,
		CurrentGeneration: req.CurrentGeneration,
		Capabilities:      req.Capabilities,
		AuthAlgorithm:     req.AuthAlgorithm,
		AuthKeyID:         req.AuthKeyID,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	return append([]byte("Winn-Protocol-v2/request\x00"), encoded...), nil
}

func ResponseSigningMessage(resp RekeyResponse) ([]byte, error) {
	unsigned := struct {
		Version       string   `json:"version"`
		Suite         string   `json:"suite"`
		ControllerID  string   `json:"controller_id"`
		DeviceID      string   `json:"device_id"`
		PeerPublicKey string   `json:"peer_public_key"`
		RequestID     string   `json:"request_id"`
		Nonce         string   `json:"nonce"`
		Generation    uint64   `json:"generation"`
		KeyID         string   `json:"key_id"`
		PresharedKey  string   `json:"preshared_key"`
		IssuedAt      string   `json:"issued_at"`
		ExpiresAt     string   `json:"expires_at"`
		Capabilities  []string `json:"capabilities"`
		AuthAlgorithm string   `json:"auth_algorithm"`
		AuthKeyID     string   `json:"auth_key_id"`
	}{
		Version:       resp.Version,
		Suite:         resp.Suite,
		ControllerID:  resp.ControllerID,
		DeviceID:      resp.DeviceID,
		PeerPublicKey: resp.PeerPublicKey,
		RequestID:     resp.RequestID,
		Nonce:         resp.Nonce,
		Generation:    resp.Generation,
		KeyID:         resp.KeyID,
		PresharedKey:  resp.PresharedKey,
		IssuedAt:      resp.IssuedAt,
		ExpiresAt:     resp.ExpiresAt,
		Capabilities:  resp.Capabilities,
		AuthAlgorithm: resp.AuthAlgorithm,
		AuthKeyID:     resp.AuthKeyID,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	return append([]byte("Winn-Protocol-v2/response\x00"), encoded...), nil
}

func validateRandomToken(name, value string) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%s must be base64url without padding for 32 bytes", name)
	}
	return nil
}

func validateAuthentication(suite, algorithm, keyID, signature string) error {
	required := RequiredAuthAlgorithm(suite)
	if algorithm != required {
		return fmt.Errorf("auth_algorithm must be %q for suite %q", required, suite)
	}
	decodedKeyID, err := hex.DecodeString(keyID)
	if err != nil || len(decodedKeyID) != sha256.Size || keyID != strings.ToLower(keyID) {
		return errors.New("auth_key_id must be 64 lowercase hexadecimal characters")
	}
	decodedSignature, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil {
		return errors.New("auth_signature must be canonical base64")
	}
	expectedSize := 3309
	if algorithm == AuthMLDSA87 {
		expectedSize = 4627
	}
	if len(decodedSignature) != expectedSize {
		return fmt.Errorf("auth_signature decoded length is %d, want %d", len(decodedSignature), expectedSize)
	}
	return nil
}
