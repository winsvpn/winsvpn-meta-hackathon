package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
)

const maxResponseBody = 32 << 10

type Client struct {
	endpoint       string
	suite          tlsconfig.Suite
	controllerID   string
	deviceSigner   *pqauth.Signer
	deviceVerifier *pqauth.Verifier
	controllerPins *pqauth.VerifierSet
	httpClient     *http.Client
	now            func() time.Time
}

type Result struct {
	Response    protocol.RekeyResponse
	PSK         []byte
	TLSVersion  uint16
	Curve       tls.CurveID
	CipherSuite uint16
}

func NewClient(
	endpoint string,
	tlsConfig *tls.Config,
	suite tlsconfig.Suite,
	controllerID string,
	deviceSigner *pqauth.Signer,
	controllerVerifier *pqauth.Verifier,
) (*Client, error) {
	controllerPins, err := pqauth.NewVerifierSet(controllerVerifier)
	if err != nil {
		return nil, err
	}
	return NewClientWithVerifierSet(endpoint, tlsConfig, suite, controllerID, deviceSigner, controllerPins)
}

func NewClientWithVerifierSet(
	endpoint string,
	tlsConfig *tls.Config,
	suite tlsconfig.Suite,
	controllerID string,
	deviceSigner *pqauth.Signer,
	controllerPins *pqauth.VerifierSet,
) (*Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("endpoint must be an HTTPS origin without credentials, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("endpoint must not include a path")
	}
	if !protocol.ValidDeviceID(controllerID) {
		return nil, errors.New("invalid controller ID")
	}
	if deviceSigner == nil || controllerPins == nil {
		return nil, errors.New("device signer and pinned controller verifier set are required")
	}
	requiredAuth := protocol.RequiredAuthAlgorithm(suite.Name)
	if deviceSigner.Algorithm() != requiredAuth || !controllerPins.HasAlgorithm(requiredAuth) {
		return nil, errors.New("PQ authentication algorithm does not match the selected suite")
	}
	deviceVerifier, err := pqauth.NewVerifier(deviceSigner.Algorithm(), deviceSigner.PublicBytes())
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
	}
	return &Client{
		endpoint:       strings.TrimRight(endpoint, "/"),
		suite:          suite,
		controllerID:   controllerID,
		deviceSigner:   deviceSigner,
		deviceVerifier: deviceVerifier,
		controllerPins: controllerPins,
		now:            time.Now,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("redirects are forbidden for rekey requests")
			},
		},
	}, nil
}

func (c *Client) NewRequest(deviceID, peerPublicKey string, currentGeneration uint64) (protocol.RekeyRequest, error) {
	requestID, err := randomToken()
	if err != nil {
		return protocol.RekeyRequest{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return protocol.RekeyRequest{}, err
	}
	request := protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             c.suite.Name,
		ControllerID:      c.controllerID,
		DeviceID:          deviceID,
		PeerPublicKey:     peerPublicKey,
		RequestID:         requestID,
		Nonce:             nonce,
		CurrentGeneration: currentGeneration,
		Capabilities:      protocol.RequiredCapabilities(c.suite.Name),
	}
	if err := pqauth.SignRequest(&request, c.deviceSigner); err != nil {
		return protocol.RekeyRequest{}, err
	}
	if err := protocol.ValidateRequest(request); err != nil {
		return protocol.RekeyRequest{}, err
	}
	return request, nil
}

func (c *Client) Rekey(ctx context.Context, rekeyRequest protocol.RekeyRequest) (Result, error) {
	if rekeyRequest.Suite != c.suite.Name {
		return Result{}, errors.New("request suite does not match client TLS suite")
	}
	if rekeyRequest.ControllerID != c.controllerID {
		return Result{}, errors.New("request controller ID does not match the pinned controller")
	}
	if err := protocol.ValidateRequest(rekeyRequest); err != nil {
		return Result{}, err
	}
	if err := pqauth.VerifyRequest(rekeyRequest, c.deviceVerifier); err != nil {
		return Result{}, fmt.Errorf("verify locally persisted request signature: %w", err)
	}
	body, err := json.Marshal(rekeyRequest)
	if err != nil {
		return Result{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+protocol.RekeyPath, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("Content-Type", protocol.MediaType+";version=2")
	request.Header.Set("Accept", protocol.MediaType+";version=2")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return Result{}, fmt.Errorf("perform hybrid rekey request: %w", err)
	}
	defer response.Body.Close()
	if err := tlsconfig.ValidateState(response.TLS, c.suite); err != nil {
		return Result{}, fmt.Errorf("validate negotiated TLS profile: %w", err)
	}
	limited := io.LimitReader(response.Body, maxResponseBody+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, err
	}
	if len(responseBody) > maxResponseBody {
		return Result{}, errors.New("response body exceeds protocol limit")
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		var protocolError protocol.ErrorResponse
		if json.Unmarshal(responseBody, &protocolError) == nil && protocolError.Code != "" {
			return Result{}, fmt.Errorf("controller rejected rekey (%s): %s", protocolError.Code, protocolError.Message)
		}
		return Result{}, fmt.Errorf("controller rejected rekey with HTTP %d", response.StatusCode)
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != protocol.MediaType || parameters["version"] != "2" || len(parameters) != 1 {
		return Result{}, errors.New("controller returned an invalid Winn Protocol media type")
	}
	var rekeyResponse protocol.RekeyResponse
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rekeyResponse); err != nil {
		return Result{}, fmt.Errorf("decode rekey response: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Result{}, errors.New("rekey response must contain one JSON object")
	}
	controllerVerifier, err := c.controllerPins.Verifier(rekeyResponse.AuthAlgorithm, rekeyResponse.AuthKeyID)
	if err != nil {
		return Result{}, fmt.Errorf("verify controller ML-DSA key pin: %w", err)
	}
	if err := pqauth.VerifyResponse(rekeyResponse, controllerVerifier); err != nil {
		return Result{}, fmt.Errorf("verify controller ML-DSA signature: %w", err)
	}
	psk, err := protocol.ValidateResponse(rekeyRequest, rekeyResponse, c.now().UTC())
	if err != nil {
		return Result{}, fmt.Errorf("validate rekey response: %w", err)
	}
	return Result{
		Response:    rekeyResponse,
		PSK:         psk,
		TLSVersion:  response.TLS.Version,
		Curve:       response.TLS.CurveID,
		CipherSuite: response.TLS.CipherSuite,
	}, nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(value)
	clear(value)
	return encoded, nil
}
