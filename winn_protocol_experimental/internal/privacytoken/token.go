// Package privacytoken implements single-use, unlinkable Winn carrier
// authorization tokens. Issuance uses RFC 9474 blind RSA, while each token
// commits to a fresh ML-DSA public key used only for that redemption.
package privacytoken

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	TokenFormat      = "winn-privacy-token/v1"
	BundleFormat     = "winn-privacy-token-bundle/v1"
	IssueFormat      = "winn-privacy-token-issue/v1"
	ResponseFormat   = "winn-privacy-token-response/v1"
	Algorithm        = "rsabssa-sha384-pss-randomized"
	preparedPrefix   = 32
	maxEncodedObject = 32 << 10
)

type Payload struct {
	Format        string `json:"format"`
	TokenKeyID    string `json:"token_key_id"`
	Nonce         string `json:"nonce"`
	AuthAlgorithm string `json:"auth_algorithm"`
	AuthPublicKey string `json:"auth_public_key"`
}

type Token struct {
	PreparedMessage string `json:"prepared_message"`
	Signature       string `json:"signature"`
}

type Bundle struct {
	Format   string `json:"format"`
	Token    Token  `json:"token"`
	AuthSeed string `json:"auth_seed"`
}

type IssueRequest struct {
	Format         string `json:"format"`
	TokenKeyID     string `json:"token_key_id"`
	BlindedMessage string `json:"blinded_message"`
}

type IssueResponse struct {
	Format         string `json:"format"`
	TokenKeyID     string `json:"token_key_id"`
	BlindSignature string `json:"blind_signature"`
}

type ClientState struct {
	client          blindrsa.Client
	state           blindrsa.State
	preparedMessage []byte
	authSeed        []byte
	tokenKeyID      string
}

type Verified struct {
	Payload   Payload
	TokenID   string
	Pseudonym string
	Verifier  *pqauth.Verifier
}

type RedemptionCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]time.Time
	now     func() time.Time
}

var ErrAlreadyRedeemed = errors.New("privacy token was already redeemed")

// RedemptionStore atomically consumes one verified token ID until its
// authorization-key expiry.
type RedemptionStore interface {
	Redeem(context.Context, string, time.Time) error
}

// DurableRedemptionStore marks a shared persistent implementation suitable for
// production carrier authentication.
type DurableRedemptionStore interface {
	RedemptionStore
	Durable() bool
}

func IsDurableRedemptionStore(store RedemptionStore) bool {
	durable, ok := store.(DurableRedemptionStore)
	return ok && durable.Durable()
}

func GenerateIssuerKey(bits int) (*rsa.PrivateKey, error) {
	if bits != 3072 && bits != 4096 {
		return nil, errors.New("privacy token RSA key must be 3072 or 4096 bits")
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

func IssuerKeyID(publicKey *rsa.PublicKey) (string, error) {
	if err := validateIssuerPublicKey(publicKey); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	digest.Write([]byte("winn-privacy-token-key/v1\x00"))
	digest.Write(der)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func BeginIssue(publicKey *rsa.PublicKey, authAlgorithm string) (IssueRequest, *ClientState, error) {
	tokenKeyID, err := IssuerKeyID(publicKey)
	if err != nil {
		return IssueRequest{}, nil, err
	}
	seed, err := pqauth.GenerateSeed()
	if err != nil {
		return IssueRequest{}, nil, err
	}
	signer, err := pqauth.NewSigner(authAlgorithm, seed)
	if err != nil {
		clear(seed)
		return IssueRequest{}, nil, err
	}
	defer signer.Destroy()
	publicBytes := signer.PublicBytes()
	defer clear(publicBytes)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		clear(seed)
		return IssueRequest{}, nil, err
	}
	payload := Payload{
		Format:        TokenFormat,
		TokenKeyID:    tokenKeyID,
		Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
		AuthAlgorithm: signer.Algorithm(),
		AuthPublicKey: base64.StdEncoding.EncodeToString(publicBytes),
	}
	clear(nonce)
	message, err := json.Marshal(payload)
	if err != nil {
		clear(seed)
		return IssueRequest{}, nil, err
	}
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, publicKey)
	if err != nil {
		clear(seed)
		return IssueRequest{}, nil, err
	}
	prepared, err := client.Prepare(rand.Reader, message)
	if err != nil {
		clear(seed)
		return IssueRequest{}, nil, err
	}
	blinded, state, err := client.Blind(rand.Reader, prepared)
	if err != nil {
		clear(seed)
		clear(prepared)
		return IssueRequest{}, nil, err
	}
	request := IssueRequest{
		Format:         IssueFormat,
		TokenKeyID:     tokenKeyID,
		BlindedMessage: base64.StdEncoding.EncodeToString(blinded),
	}
	clear(blinded)
	return request, &ClientState{
		client: client, state: state, preparedMessage: prepared, authSeed: seed,
		tokenKeyID: tokenKeyID,
	}, nil
}

func BlindSign(request IssueRequest, privateKey *rsa.PrivateKey) (IssueResponse, error) {
	if err := validateIssuerPrivateKey(privateKey); err != nil {
		return IssueResponse{}, err
	}
	keyID, err := IssuerKeyID(&privateKey.PublicKey)
	if err != nil {
		return IssueResponse{}, err
	}
	if request.Format != IssueFormat || request.TokenKeyID != keyID {
		return IssueResponse{}, errors.New("privacy token issue request key mismatch")
	}
	blinded, err := base64.StdEncoding.Strict().DecodeString(request.BlindedMessage)
	if err != nil || len(blinded) != privateKey.Size() {
		clear(blinded)
		return IssueResponse{}, errors.New("invalid blinded privacy token request")
	}
	defer clear(blinded)
	signature, err := blindrsa.NewSigner(privateKey).BlindSign(blinded)
	if err != nil {
		return IssueResponse{}, err
	}
	defer clear(signature)
	return IssueResponse{
		Format:         ResponseFormat,
		TokenKeyID:     keyID,
		BlindSignature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func (state *ClientState) Finalize(response IssueResponse) (Bundle, error) {
	if state == nil || len(state.preparedMessage) == 0 || len(state.authSeed) != 32 {
		return Bundle{}, errors.New("privacy token client state is unavailable")
	}
	defer state.clear()
	if response.Format != ResponseFormat || response.TokenKeyID != state.tokenKeyID {
		return Bundle{}, errors.New("invalid privacy token issue response")
	}
	blindSignature, err := base64.StdEncoding.Strict().DecodeString(response.BlindSignature)
	if err != nil {
		return Bundle{}, errors.New("invalid blind signature encoding")
	}
	defer clear(blindSignature)
	signature, err := state.client.Finalize(state.state, blindSignature)
	if err != nil {
		return Bundle{}, err
	}
	defer clear(signature)
	if err := state.client.Verify(state.preparedMessage, signature); err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Format: BundleFormat,
		Token: Token{
			PreparedMessage: base64.StdEncoding.EncodeToString(state.preparedMessage),
			Signature:       base64.StdEncoding.EncodeToString(signature),
		},
		AuthSeed: base64.StdEncoding.EncodeToString(state.authSeed),
	}, nil
}

func Verify(token Token, publicKey *rsa.PublicKey, expectedKeyID string) (Verified, error) {
	if publicKey == nil {
		return Verified{}, errors.New("privacy token public key is required")
	}
	keyID, err := IssuerKeyID(publicKey)
	if err != nil {
		return Verified{}, err
	}
	if expectedKeyID == "" || keyID != expectedKeyID {
		return Verified{}, errors.New("privacy token key is not authorized for this carrier")
	}
	prepared, err := base64.StdEncoding.Strict().DecodeString(token.PreparedMessage)
	if err != nil || len(prepared) <= preparedPrefix || len(prepared) > maxEncodedObject {
		clear(prepared)
		return Verified{}, errors.New("invalid privacy token message")
	}
	defer clear(prepared)
	signature, err := base64.StdEncoding.Strict().DecodeString(token.Signature)
	if err != nil || len(signature) != publicKey.Size() {
		clear(signature)
		return Verified{}, errors.New("invalid privacy token signature")
	}
	defer clear(signature)
	verifier, err := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, publicKey)
	if err != nil {
		return Verified{}, err
	}
	if err := verifier.Verify(prepared, signature); err != nil {
		return Verified{}, errors.New("invalid privacy token")
	}
	payloadBytes := prepared[preparedPrefix:]
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.DisallowUnknownFields()
	var payload Payload
	if err := decoder.Decode(&payload); err != nil {
		return Verified{}, errors.New("invalid privacy token payload")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Verified{}, errors.New("privacy token payload contains extra JSON")
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, payloadBytes) {
		return Verified{}, errors.New("privacy token payload is not canonical")
	}
	if payload.Format != TokenFormat || payload.TokenKeyID != expectedKeyID {
		return Verified{}, errors.New("privacy token payload key mismatch")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(payload.Nonce)
	if err != nil || len(nonce) != 32 {
		clear(nonce)
		return Verified{}, errors.New("invalid privacy token nonce")
	}
	clear(nonce)
	publicAuth, err := base64.StdEncoding.Strict().DecodeString(payload.AuthPublicKey)
	if err != nil {
		return Verified{}, errors.New("invalid privacy token authentication key")
	}
	authVerifier, err := pqauth.NewVerifier(payload.AuthAlgorithm, publicAuth)
	clear(publicAuth)
	if err != nil {
		return Verified{}, err
	}
	tokenDigest := sha256.New()
	tokenDigest.Write([]byte("winn-privacy-token-id/v1\x00"))
	tokenDigest.Write(prepared)
	tokenDigest.Write(signature)
	tokenID := hex.EncodeToString(tokenDigest.Sum(nil))
	return Verified{
		Payload: payload, TokenID: tokenID,
		Pseudonym: "anon-" + tokenID[:40], Verifier: authVerifier,
	}, nil
}

func (bundle Bundle) Signer() (*pqauth.Signer, error) {
	token, seed, err := bundle.SecretMaterial()
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return NewCredentialSigner(token, seed)
}

// SecretMaterial returns the bundle's public token and a uniquely owned seed
// copy. The caller must clear the seed. This is the supported bridge into
// encrypted stores that represent secrets as destroyable byte slices.
func (bundle Bundle) SecretMaterial() (Token, []byte, error) {
	if bundle.Format != BundleFormat {
		return Token{}, nil,
			errors.New("invalid privacy token bundle format")
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(bundle.AuthSeed)
	if err != nil || len(seed) != 32 {
		clear(seed)
		return Token{}, nil,
			errors.New("invalid privacy token authentication seed")
	}
	signer, err := NewCredentialSigner(bundle.Token, seed)
	if err != nil {
		clear(seed)
		return Token{}, nil, err
	}
	signer.Destroy()
	return bundle.Token, seed, nil
}

// NewCredentialSigner reconstructs the token's committed ephemeral ML-DSA
// signer from a caller-owned seed. The returned signer must be Destroyed.
func NewCredentialSigner(
	token Token,
	seed []byte,
) (*pqauth.Signer, error) {
	if len(seed) != 32 {
		return nil, errors.New(
			"invalid privacy token authentication seed",
		)
	}
	verifiedPayload, err := payloadWithoutSignature(token)
	if err != nil {
		return nil, err
	}
	signer, err := pqauth.NewSigner(
		verifiedPayload.AuthAlgorithm, seed,
	)
	if err != nil {
		return nil, err
	}
	publicBytes := signer.PublicBytes()
	defer clear(publicBytes)
	if base64.StdEncoding.EncodeToString(publicBytes) != verifiedPayload.AuthPublicKey {
		signer.Destroy()
		return nil, errors.New("privacy token seed does not match committed public key")
	}
	return signer, nil
}

func (bundle Bundle) PublicToken() Token {
	return bundle.Token
}

func EncodeTokenHeader(token Token) (string, error) {
	encoded, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	if len(encoded) > maxEncodedObject {
		return "", errors.New("privacy token is too large")
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func DecodeTokenHeader(encoded string) (Token, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data) > maxEncodedObject {
		clear(data)
		return Token{}, errors.New("invalid privacy token header")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var token Token
	if err := decoder.Decode(&token); err != nil {
		return Token{}, errors.New("invalid privacy token header")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Token{}, errors.New("privacy token header contains extra JSON")
	}
	if token.PreparedMessage == "" || token.Signature == "" ||
		len(token.PreparedMessage) > maxEncodedObject ||
		len(token.Signature) > maxEncodedObject {
		return Token{}, errors.New("privacy token header fields are invalid")
	}
	return token, nil
}

func LoadBundle(path string) (Bundle, error) {
	data, err := securefile.ReadPrivateLimited(path, maxEncodedObject)
	if err != nil {
		return Bundle{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Bundle{}, errors.New("privacy token bundle contains extra JSON")
	}
	signer, err := bundle.Signer()
	if err != nil {
		return Bundle{}, err
	}
	signer.Destroy()
	return bundle, nil
}

func EncodeBundle(bundle Bundle) ([]byte, error) {
	signer, err := bundle.Signer()
	if err != nil {
		return nil, err
	}
	signer.Destroy()
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func LoadIssuerPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := securefile.ReadPrivateLimited(path, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid privacy token private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("privacy token private key is not RSA")
	}
	if err := validateIssuerPrivateKey(privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func LoadIssuerPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := securefile.ReadPublicIntegrity(path, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid privacy token public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("privacy token public key is not RSA")
	}
	if err := validateIssuerPublicKey(publicKey); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func ParseIssuerPublicKeyDER(der []byte) (*rsa.PublicKey, error) {
	if len(der) == 0 || len(der) > 16<<10 {
		return nil, errors.New("invalid privacy token public key DER")
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("privacy token public key is not RSA")
	}
	if err := validateIssuerPublicKey(publicKey); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func MarshalIssuerKeys(privateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	if err := validateIssuerPrivateKey(privateKey); err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), nil
}

func NewRedemptionCache(maxEntries int) (*RedemptionCache, error) {
	if maxEntries < 1 || maxEntries > 1_000_000 {
		return nil, errors.New("privacy token replay-cache limit is invalid")
	}
	return &RedemptionCache{
		max: maxEntries, entries: make(map[string]time.Time), now: time.Now,
	}, nil
}

func (cache *RedemptionCache) Use(tokenID string, expiresAt, now time.Time) error {
	if cache == nil || tokenID == "" || !expiresAt.After(now) {
		return errors.New("invalid privacy token redemption")
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for id, expiry := range cache.entries {
		if !expiry.After(now) {
			delete(cache.entries, id)
		}
	}
	if _, used := cache.entries[tokenID]; used {
		return ErrAlreadyRedeemed
	}
	if len(cache.entries) >= cache.max {
		return errors.New("privacy token replay cache is full")
	}
	cache.entries[tokenID] = expiresAt
	return nil
}

func (cache *RedemptionCache) Redeem(
	ctx context.Context,
	tokenID string,
	expiresAt time.Time,
) error {
	if ctx == nil {
		return errors.New("privacy token redemption context is required")
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	if cache != nil && cache.now != nil {
		now = cache.now().UTC()
	}
	return cache.Use(tokenID, expiresAt, now)
}

func (cache *RedemptionCache) Durable() bool {
	return false
}

func validateIssuerPublicKey(publicKey *rsa.PublicKey) error {
	if publicKey == nil || publicKey.N == nil ||
		(publicKey.N.BitLen() != 3072 && publicKey.N.BitLen() != 4096) ||
		publicKey.E != 65537 {
		return errors.New(
			"privacy token key must be RSA-3072 or RSA-4096 with exponent 65537",
		)
	}
	return nil
}

func validateIssuerPrivateKey(privateKey *rsa.PrivateKey) error {
	if privateKey == nil {
		return errors.New("privacy token issuer private key is required")
	}
	if err := validateIssuerPublicKey(&privateKey.PublicKey); err != nil {
		return err
	}
	if err := privateKey.Validate(); err != nil {
		return err
	}
	return nil
}

func payloadWithoutSignature(token Token) (Payload, error) {
	prepared, err := base64.StdEncoding.Strict().DecodeString(token.PreparedMessage)
	if err != nil || len(prepared) <= preparedPrefix || len(prepared) > maxEncodedObject {
		clear(prepared)
		return Payload{}, errors.New("invalid privacy token message")
	}
	defer clear(prepared)
	payloadBytes := prepared[preparedPrefix:]
	var payload Payload
	decoder := json.NewDecoder(bytes.NewReader(payloadBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Payload{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Payload{}, errors.New("privacy token payload contains extra JSON")
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, payloadBytes) {
		return Payload{}, errors.New("privacy token payload is not canonical")
	}
	if payload.Format != TokenFormat {
		return Payload{}, errors.New("invalid privacy token payload format")
	}
	return payload, nil
}

func (state *ClientState) clear() {
	clear(state.preparedMessage)
	clear(state.authSeed)
	state.preparedMessage = nil
	state.authSeed = nil
	state.tokenKeyID = ""
}

func ValidateKeyWindow(notBefore, notAfter, now time.Time) error {
	if notBefore.IsZero() || notAfter.IsZero() || !notAfter.After(notBefore) {
		return errors.New("invalid privacy token key window")
	}
	if now.Before(notBefore) || !now.Before(notAfter) {
		return fmt.Errorf("privacy token issuer key is not valid at %s", now.UTC().Format(time.RFC3339Nano))
	}
	return nil
}
