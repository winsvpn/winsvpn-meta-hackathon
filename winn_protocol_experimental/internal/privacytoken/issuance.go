package privacytoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
)

const (
	IssuePath       = "/winn/v1/privacy-token"
	IssueMediaType  = "application/vnd.winn.privacy-token-issue+json;version=1"
	IssueAuthFormat = "winn-privacy-token-issue-auth/v1"

	HeaderIssueDeviceID  = "X-Winn-Device-Id"
	HeaderIssueTimestamp = "X-Winn-Timestamp"
	HeaderIssueNonce     = "X-Winn-Nonce"
	HeaderIssueAlgorithm = "X-Winn-Auth-Algorithm"
	HeaderIssueKeyID     = "X-Winn-Auth-Key-Id"
	HeaderIssueSignature = "X-Winn-Auth-Signature"
)

type IssueAuthorization struct {
	Format        string `json:"format"`
	Method        string `json:"method"`
	Authority     string `json:"authority"`
	RequestTarget string `json:"request_target"`
	DeviceID      string `json:"device_id"`
	Timestamp     string `json:"timestamp"`
	Nonce         string `json:"nonce"`
	TokenKeyID    string `json:"token_key_id"`
	BlindedDigest string `json:"blinded_digest"`
	AuthAlgorithm string `json:"auth_algorithm"`
	AuthKeyID     string `json:"auth_key_id"`
}

type IssueAuthorizationVerifier struct {
	Registry *pqauth.Registry
	Replay   *carrierauth.ReplayCache
	MaxSkew  time.Duration
	Now      func() time.Time
}

func SignIssueAuthorization(request *http.Request, issue IssueRequest, deviceID string, signer *pqauth.Signer, now time.Time) error {
	if request == nil || request.URL == nil || signer == nil {
		return errors.New("privacy-token issue authorization is not configured")
	}
	authorization, err := newIssueAuthorization(
		request, issue, deviceID, signer.Algorithm(), signer.KeyID(), now,
	)
	if err != nil {
		return err
	}
	message, err := json.Marshal(authorization)
	if err != nil {
		return err
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.TokenIssueSignatureDomain, message, signer,
	)
	if err != nil {
		return err
	}
	defer clear(signature)
	request.Header.Set(HeaderIssueDeviceID, authorization.DeviceID)
	request.Header.Set(HeaderIssueTimestamp, authorization.Timestamp)
	request.Header.Set(HeaderIssueNonce, authorization.Nonce)
	request.Header.Set(HeaderIssueAlgorithm, authorization.AuthAlgorithm)
	request.Header.Set(HeaderIssueKeyID, authorization.AuthKeyID)
	request.Header.Set(
		HeaderIssueSignature,
		base64.RawStdEncoding.EncodeToString(signature),
	)
	return nil
}

func (v *IssueAuthorizationVerifier) Verify(request *http.Request, issue IssueRequest, certificateDeviceID string) (IssueAuthorization, error) {
	if v == nil || v.Registry == nil || v.Replay == nil ||
		request == nil || request.URL == nil {
		return IssueAuthorization{}, errors.New("privacy-token issue verifier is not configured")
	}
	blindedDigest, err := issueRequestDigest(issue)
	if err != nil {
		return IssueAuthorization{}, err
	}
	authorization := IssueAuthorization{
		Format:        IssueAuthFormat,
		Method:        request.Method,
		Authority:     request.Host,
		RequestTarget: request.URL.RequestURI(),
		DeviceID:      oneIssueHeader(request.Header, HeaderIssueDeviceID),
		Timestamp:     oneIssueHeader(request.Header, HeaderIssueTimestamp),
		Nonce:         oneIssueHeader(request.Header, HeaderIssueNonce),
		TokenKeyID:    issue.TokenKeyID,
		BlindedDigest: blindedDigest,
		AuthAlgorithm: oneIssueHeader(request.Header, HeaderIssueAlgorithm),
		AuthKeyID:     oneIssueHeader(request.Header, HeaderIssueKeyID),
	}
	if authorization.DeviceID != certificateDeviceID {
		return IssueAuthorization{}, errors.New("privacy-token issuer identity does not match mTLS")
	}
	if err := validateIssueAuthorization(authorization); err != nil {
		return IssueAuthorization{}, err
	}
	signatures := request.Header.Values(HeaderIssueSignature)
	if len(signatures) != 1 || signatures[0] == "" || len(signatures[0]) > 16<<10 {
		return IssueAuthorization{}, errors.New("exactly one privacy-token issue signature is required")
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(signatures[0])
	if err != nil || len(signature) == 0 {
		clear(signature)
		return IssueAuthorization{}, errors.New("invalid privacy-token issue signature encoding")
	}
	defer clear(signature)
	timestampMillis, err := strconv.ParseInt(authorization.Timestamp, 10, 64)
	if err != nil {
		return IssueAuthorization{}, errors.New("invalid privacy-token issue timestamp")
	}
	timestamp := time.UnixMilli(timestampMillis).UTC()
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	maxSkew := v.MaxSkew
	if maxSkew <= 0 {
		maxSkew = 2 * time.Minute
	}
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return IssueAuthorization{}, errors.New("privacy-token issue timestamp is outside the acceptance window")
	}
	verifier, err := v.Registry.Verifier(
		authorization.DeviceID, authorization.AuthAlgorithm,
		authorization.AuthKeyID,
	)
	if err != nil {
		return IssueAuthorization{}, err
	}
	message, err := json.Marshal(authorization)
	if err != nil {
		return IssueAuthorization{}, err
	}
	if err := pqauth.VerifyDomainMessage(
		pqauth.TokenIssueSignatureDomain, message, signature, verifier,
	); err != nil {
		return IssueAuthorization{}, err
	}
	// The +1ns mirrors carrierauth: at the inclusive lower skew bound,
	// timestamp.Add(maxSkew) equals now, which ReplayCache.Use rejects
	// as an already-expired entry, refusing a still-valid first use.
	if err := v.Replay.Use(
		authorization.DeviceID+"|"+authorization.Nonce,
		timestamp.Add(maxSkew+time.Nanosecond), now,
	); err != nil {
		return IssueAuthorization{}, err
	}
	return authorization, nil
}

func newIssueAuthorization(request *http.Request, issue IssueRequest, deviceID, algorithm, keyID string, now time.Time) (IssueAuthorization, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return IssueAuthorization{}, err
	}
	defer clear(nonce)
	blindedDigest, err := issueRequestDigest(issue)
	if err != nil {
		return IssueAuthorization{}, err
	}
	authorization := IssueAuthorization{
		Format:        IssueAuthFormat,
		Method:        request.Method,
		Authority:     request.Host,
		RequestTarget: request.URL.RequestURI(),
		DeviceID:      deviceID,
		Timestamp:     strconv.FormatInt(now.UTC().UnixMilli(), 10),
		Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
		TokenKeyID:    issue.TokenKeyID,
		BlindedDigest: blindedDigest,
		AuthAlgorithm: algorithm,
		AuthKeyID:     keyID,
	}
	if err := validateIssueAuthorization(authorization); err != nil {
		return IssueAuthorization{}, err
	}
	return authorization, nil
}

func validateIssueAuthorization(authorization IssueAuthorization) error {
	if authorization.Format != IssueAuthFormat ||
		authorization.Method != http.MethodPost ||
		authorization.RequestTarget != IssuePath ||
		authorization.Authority == "" ||
		strings.ContainsAny(authorization.Authority, "\r\n") ||
		!protocol.ValidDeviceID(authorization.DeviceID) ||
		authorization.Timestamp == "" ||
		authorization.TokenKeyID == "" ||
		len(authorization.BlindedDigest) != sha256.Size*2 ||
		authorization.AuthAlgorithm == "" ||
		authorization.AuthKeyID == "" {
		return errors.New("invalid privacy-token issue authorization")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(authorization.Nonce)
	if err != nil || len(nonce) != 24 {
		clear(nonce)
		return errors.New("invalid privacy-token issue nonce")
	}
	clear(nonce)
	if _, err := hex.DecodeString(authorization.BlindedDigest); err != nil {
		return errors.New("invalid privacy-token blinded digest")
	}
	return nil
}

func issueRequestDigest(issue IssueRequest) (string, error) {
	encoded, err := json.Marshal(issue)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func oneIssueHeader(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) != 1 || len(values[0]) > 512 {
		return ""
	}
	return values[0]
}
