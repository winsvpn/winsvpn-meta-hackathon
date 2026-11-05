package pqauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	MLDSA65 = protocol.AuthMLDSA65
	MLDSA87 = protocol.AuthMLDSA87

	seedSize               = 32
	registryFormat         = "winn-pq-device-registry/v3"
	legacyRegistryFormat   = "winn-pq-device-registry/v2"
	verifierSetFormat      = "winn-pq-verifier-set/v1"
	maxRegistryDevices     = 100000
	maxRegistryKeysPerType = 4
)

// signatureContext is the ML-DSA signature context string. Both halves of
// every pair this package signs and verifies (device rekey requests, carrier
// messages, domain messages, and the winn/3 dual-signature attestation) read
// this one value, so a change here moves the whole fleet together and breaks
// no wire compatibility within a release.
var signatureContext = []byte("Winn-Protocol-v3")

const (
	CarrierSignatureDomain      = "winn-carrier-auth/v3"
	ManifestSignatureDomain     = "winn-gateway-manifest/v1"
	ManifestV2SignatureDomain   = "winn-gateway-manifest/v2/prehash-sha256"
	TransparencySignatureDomain = "winn-transparency-receipt/v1"
	TokenIssueSignatureDomain   = "winn-privacy-token-issuance/v1"

	// AuditCheckpointSignatureDomain separates the terminal audit-trail
	// checkpoint (internal/auditcheckpoint) from every other signed object.
	//
	// The keypair used under this domain is generated specifically for the
	// finalizer role and is never the device, controller, or carrier key: the
	// point of the checkpoint is to constrain the party that writes audit
	// records, so its credential must be one that party does not hold. The
	// domain is what stops a signature made for any other Winn object from
	// being replayed as a close record.
	AuditCheckpointSignatureDomain = "winn-audit-checkpoint/v1"

	// ControllerStartSignatureDomain authenticates the controller's create-once
	// start record.
	//
	// The record establishes which party owns a matrix transition. Its mere
	// existence cannot establish that: an unsigned file proves only that
	// something able to write a file wrote one. Signing it under the
	// controller's finalizer key — a credential the producing host provably
	// does not hold — is what makes "this state belongs to the controller" a
	// checkable claim rather than an assumption.
	ControllerStartSignatureDomain = "winn-phase1-controller-start/v1"

	// RevocationListSignatureDomain authenticates the signed device revocation
	// list that carries control-plane revocation decisions to the data plane
	// (internal/revocation).
	//
	// It is prehashed for the same reason the v2 manifest is: SignDomainMessage
	// bounds the signed message at 64 KiB, and a revocation list grows with the
	// number of revoked devices. Signing a SHA-256 of the canonical body keeps
	// the list unbounded in size while the signed input stays fixed-length.
	//
	// The domain is what stops a controller signature made over any other Winn
	// object from being replayed as a revocation list, and — more importantly
	// in the other direction — stops a revocation list from being replayed as a
	// manifest by a carrier that holds the same controller pins for both.
	RevocationListSignatureDomain = "winn-device-revocation/v1/prehash-sha256"

	// DualAuthSignatureDomain binds the dual-signature session attestation:
	// two signatures (Ed25519 + ML-DSA-65) over the session handshake
	// transcript hash, presented post-handshake to clients that announced the
	// capability (docs/DUAL_SIGNATURE_SPEC.md). The domain stops an
	// attestation from being replayed as any other Winn-signed object, and
	// vice versa.
	DualAuthSignatureDomain = "winn3-dual-auth-v1"
)

type Signer struct {
	mu        sync.Mutex
	algorithm string
	publicKey []byte
	signRaw   func([]byte) ([]byte, error)
	destroy   func()
	destroyed bool
}

type Verifier struct {
	algorithm     string
	publicKey     []byte
	signatureSize int
	verify        func([]byte, []byte) bool
}

type RegistryFile struct {
	Format  string                         `json:"format"`
	Devices map[string]map[string][]string `json:"devices"`
}

type Registry struct {
	devices map[string]map[string]map[string]*Verifier
}

type VerifierSetFile struct {
	Format string              `json:"format"`
	Keys   map[string][]string `json:"keys"`
}

type VerifierSet struct {
	keys map[string]map[string]*Verifier
}

func GenerateSeed() ([]byte, error) {
	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return seed, nil
}

func NewSigner(algorithm string, seed []byte) (*Signer, error) {
	if len(seed) != seedSize {
		return nil, fmt.Errorf("ML-DSA seed length is %d, want %d", len(seed), seedSize)
	}
	var fixedSeed [seedSize]byte
	copy(fixedSeed[:], seed)
	defer clear(fixedSeed[:])
	switch algorithm {
	case MLDSA65:
		publicKey, privateKey := mldsa65.NewKeyFromSeed(&fixedSeed)
		publicBytes := publicKey.Bytes()
		return &Signer{
			algorithm: algorithm,
			publicKey: publicBytes,
			signRaw: func(message []byte) ([]byte, error) {
				signature := make([]byte, mldsa65.SignatureSize)
				if err := mldsa65.SignTo(privateKey, message, signatureContext, true, signature); err != nil {
					clear(signature)
					return nil, err
				}
				return signature, nil
			},
			destroy: func() {
				*privateKey = mldsa65.PrivateKey{}
			},
		}, nil
	case MLDSA87:
		publicKey, privateKey := mldsa87.NewKeyFromSeed(&fixedSeed)
		publicBytes := publicKey.Bytes()
		return &Signer{
			algorithm: algorithm,
			publicKey: publicBytes,
			signRaw: func(message []byte) ([]byte, error) {
				signature := make([]byte, mldsa87.SignatureSize)
				if err := mldsa87.SignTo(privateKey, message, signatureContext, true, signature); err != nil {
					clear(signature)
					return nil, err
				}
				return signature, nil
			},
			destroy: func() {
				*privateKey = mldsa87.PrivateKey{}
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported PQ authentication algorithm %q", algorithm)
	}
}

func NewVerifier(algorithm string, publicKey []byte) (*Verifier, error) {
	switch algorithm {
	case MLDSA65:
		var key mldsa65.PublicKey
		if err := key.UnmarshalBinary(publicKey); err != nil {
			return nil, err
		}
		return &Verifier{
			algorithm:     algorithm,
			publicKey:     slices.Clone(publicKey),
			signatureSize: mldsa65.SignatureSize,
			verify: func(message, signature []byte) bool {
				return len(signature) == mldsa65.SignatureSize &&
					mldsa65.Verify(&key, message, signatureContext, signature)
			},
		}, nil
	case MLDSA87:
		var key mldsa87.PublicKey
		if err := key.UnmarshalBinary(publicKey); err != nil {
			return nil, err
		}
		return &Verifier{
			algorithm:     algorithm,
			publicKey:     slices.Clone(publicKey),
			signatureSize: mldsa87.SignatureSize,
			verify: func(message, signature []byte) bool {
				return len(signature) == mldsa87.SignatureSize &&
					mldsa87.Verify(&key, message, signatureContext, signature)
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported PQ authentication algorithm %q", algorithm)
	}
}

func LoadSigner(algorithm, seedPath string) (*Signer, error) {
	seed, err := securefile.ReadPrivateLimited(seedPath, 1024)
	if err != nil {
		return nil, fmt.Errorf("read PQ authentication seed: %w", err)
	}
	defer clear(seed)
	return NewSigner(algorithm, seed)
}

func LoadVerifier(algorithm, publicKeyPath string) (*Verifier, error) {
	publicKey, err := securefile.ReadPublicIntegrity(publicKeyPath, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read PQ authentication public key: %w", err)
	}
	defer clear(publicKey)
	return NewVerifier(algorithm, publicKey)
}

func (s *Signer) Algorithm() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.algorithm
}

func (s *Signer) PublicBytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.publicKey)
}

func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return ""
	}
	return KeyID(s.algorithm, s.publicKey)
}

// Destroy irreversibly clears this process's ML-DSA private/public key
// material. It is idempotent and serialized with signing.
func (s *Signer) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	if s.destroy != nil {
		s.destroy()
	}
	clear(s.publicKey)
	s.publicKey = nil
	s.algorithm = ""
	s.signRaw = nil
	s.destroy = nil
	s.destroyed = true
}

func (s *Signer) Destroyed() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.destroyed
}

func (s *Signer) sign(message []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil ML-DSA signer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed || s.signRaw == nil {
		return nil, errors.New("ML-DSA signer is destroyed")
	}
	return s.signRaw(message)
}

func (v *Verifier) Algorithm() string {
	if v == nil {
		return ""
	}
	return v.algorithm
}

func (v *Verifier) PublicBytes() []byte {
	if v == nil {
		return nil
	}
	return slices.Clone(v.publicKey)
}

func (v *Verifier) KeyID() string {
	if v == nil {
		return ""
	}
	return KeyID(v.algorithm, v.publicKey)
}

func KeyID(algorithm string, publicKey []byte) string {
	hash := sha256.New()
	hash.Write([]byte("winn-pq-auth-key/v2\x00"))
	hash.Write([]byte(algorithm))
	hash.Write([]byte{0})
	hash.Write(publicKey)
	return hex.EncodeToString(hash.Sum(nil))
}

func SignRequest(request *protocol.RekeyRequest, signer *Signer) error {
	if request == nil {
		return errors.New("nil rekey request")
	}
	algorithm, keyID, err := signerBinding(signer)
	if err != nil {
		return err
	}
	candidate := *request
	candidate.AuthAlgorithm = algorithm
	candidate.AuthKeyID = keyID
	candidate.AuthSignature = ""
	message, err := protocol.RequestSigningMessage(candidate)
	if err != nil {
		return err
	}
	signature, err := signer.sign(message)
	if err != nil {
		return err
	}
	request.AuthAlgorithm = algorithm
	request.AuthKeyID = keyID
	request.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	clear(signature)
	return nil
}

func VerifyRequest(request protocol.RekeyRequest, verifier *Verifier) error {
	if verifier == nil {
		return errors.New("nil ML-DSA verifier")
	}
	if request.AuthAlgorithm != verifier.Algorithm() || request.AuthKeyID != verifier.KeyID() {
		return errors.New("device PQ authentication key binding mismatch")
	}
	signature, err := decodeSignature(request.AuthSignature, verifier.signatureSize)
	if err != nil {
		return err
	}
	defer clear(signature)
	message, err := protocol.RequestSigningMessage(request)
	if err != nil {
		return err
	}
	if !verifier.verify(message, signature) {
		return errors.New("invalid device ML-DSA signature")
	}
	return nil
}

func SignResponse(response *protocol.RekeyResponse, signer *Signer) error {
	if response == nil {
		return errors.New("nil rekey response")
	}
	algorithm, keyID, err := signerBinding(signer)
	if err != nil {
		return err
	}
	candidate := *response
	candidate.AuthAlgorithm = algorithm
	candidate.AuthKeyID = keyID
	candidate.AuthSignature = ""
	message, err := protocol.ResponseSigningMessage(candidate)
	if err != nil {
		return err
	}
	signature, err := signer.sign(message)
	if err != nil {
		return err
	}
	response.AuthAlgorithm = algorithm
	response.AuthKeyID = keyID
	response.AuthSignature = base64.StdEncoding.EncodeToString(signature)
	clear(signature)
	return nil
}

func VerifyResponse(response protocol.RekeyResponse, verifier *Verifier) error {
	if verifier == nil {
		return errors.New("nil ML-DSA verifier")
	}
	if response.AuthAlgorithm != verifier.Algorithm() || response.AuthKeyID != verifier.KeyID() {
		return errors.New("controller PQ authentication key binding mismatch")
	}
	signature, err := decodeSignature(response.AuthSignature, verifier.signatureSize)
	if err != nil {
		return err
	}
	defer clear(signature)
	message, err := protocol.ResponseSigningMessage(response)
	if err != nil {
		return err
	}
	if !verifier.verify(message, signature) {
		return errors.New("invalid controller ML-DSA signature")
	}
	return nil
}

// SignCarrierMessage signs a canonical carrier-authentication message using a
// domain distinct from bootstrap and rekey messages.
func SignCarrierMessage(message []byte, signer *Signer) ([]byte, error) {
	return SignDomainMessage(CarrierSignatureDomain, message, signer)
}

// SignDomainMessage signs an already-canonical message in a caller-selected
// Winn protocol domain. Domain separation is mandatory so a valid signature
// for one protocol object cannot be replayed as a different object type.
func SignDomainMessage(domain string, message []byte, signer *Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("nil ML-DSA signer")
	}
	if !validSignatureDomain(domain) {
		return nil, errors.New("invalid Winn signature domain")
	}
	if len(message) == 0 || len(message) > 64<<10 {
		return nil, errors.New("winn signed message has invalid length")
	}
	domainMessage := make([]byte, 0, len(domain)+1+len(message))
	domainMessage = append(domainMessage, domain...)
	domainMessage = append(domainMessage, 0)
	domainMessage = append(domainMessage, message...)
	defer clear(domainMessage)
	return signer.sign(domainMessage)
}

// VerifyCarrierMessage verifies a message created by SignCarrierMessage.
func VerifyCarrierMessage(message, signature []byte, verifier *Verifier) error {
	return VerifyDomainMessage(CarrierSignatureDomain, message, signature, verifier)
}

// VerifyDomainMessage verifies a signature produced by SignDomainMessage.
func VerifyDomainMessage(domain string, message, signature []byte, verifier *Verifier) error {
	if verifier == nil {
		return errors.New("nil ML-DSA verifier")
	}
	if !validSignatureDomain(domain) {
		return errors.New("invalid Winn signature domain")
	}
	if len(message) == 0 || len(message) > 64<<10 {
		return errors.New("winn signed message has invalid length")
	}
	if len(signature) != verifier.signatureSize {
		return errors.New("invalid ML-DSA signature length")
	}
	domainMessage := make([]byte, 0, len(domain)+1+len(message))
	domainMessage = append(domainMessage, domain...)
	domainMessage = append(domainMessage, 0)
	domainMessage = append(domainMessage, message...)
	defer clear(domainMessage)
	if !verifier.verify(domainMessage, signature) {
		return errors.New("invalid Winn ML-DSA signature")
	}
	return nil
}

func validSignatureDomain(domain string) bool {
	switch domain {
	case CarrierSignatureDomain, ManifestSignatureDomain,
		ManifestV2SignatureDomain,
		TransparencySignatureDomain, TokenIssueSignatureDomain,
		AuditCheckpointSignatureDomain, ControllerStartSignatureDomain,
		RevocationListSignatureDomain, DualAuthSignatureDomain:
		return true
	default:
		return false
	}
}

func LoadRegistry(path string) (*Registry, error) {
	data, err := securefile.ReadPublicIntegrity(path, 64<<20)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file struct {
		Format  string                                `json:"format"`
		Devices map[string]map[string]json.RawMessage `json:"devices"`
	}
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("PQ device registry contains extra JSON")
		}
		return nil, err
	}
	if (file.Format != registryFormat && file.Format != legacyRegistryFormat) || file.Devices == nil {
		return nil, errors.New("unsupported or empty PQ device registry")
	}
	if len(file.Devices) > maxRegistryDevices {
		return nil, errors.New("PQ device registry exceeds device limit")
	}
	registry := &Registry{devices: make(map[string]map[string]map[string]*Verifier, len(file.Devices))}
	for deviceID, algorithms := range file.Devices {
		if !protocol.ValidDeviceID(deviceID) || len(algorithms) == 0 {
			return nil, fmt.Errorf("invalid registry device %q", deviceID)
		}
		registry.devices[deviceID] = make(map[string]map[string]*Verifier, len(algorithms))
		for algorithm, rawKeys := range algorithms {
			var encodedKeys []string
			if file.Format == legacyRegistryFormat {
				var encoded string
				if err := json.Unmarshal(rawKeys, &encoded); err != nil {
					return nil, fmt.Errorf("decode legacy %s key for %s: %w", algorithm, deviceID, err)
				}
				encodedKeys = []string{encoded}
			} else if err := json.Unmarshal(rawKeys, &encodedKeys); err != nil {
				return nil, fmt.Errorf("decode %s keys for %s: %w", algorithm, deviceID, err)
			}
			if len(encodedKeys) == 0 || len(encodedKeys) > maxRegistryKeysPerType {
				return nil, fmt.Errorf("%s key count for %s must be between 1 and %d", algorithm, deviceID, maxRegistryKeysPerType)
			}
			registry.devices[deviceID][algorithm] = make(map[string]*Verifier, len(encodedKeys))
			for _, encoded := range encodedKeys {
				publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil {
					return nil, fmt.Errorf("decode %s key for %s: %w", algorithm, deviceID, err)
				}
				verifier, err := NewVerifier(algorithm, publicKey)
				clear(publicKey)
				if err != nil {
					return nil, fmt.Errorf("load %s key for %s: %w", algorithm, deviceID, err)
				}
				if _, duplicate := registry.devices[deviceID][algorithm][verifier.KeyID()]; duplicate {
					return nil, fmt.Errorf("duplicate %s key for %s", algorithm, deviceID)
				}
				registry.devices[deviceID][algorithm][verifier.KeyID()] = verifier
			}
		}
	}
	return registry, nil
}

func NewVerifierSet(verifiers ...*Verifier) (*VerifierSet, error) {
	set := &VerifierSet{keys: make(map[string]map[string]*Verifier)}
	for _, verifier := range verifiers {
		if verifier == nil {
			return nil, errors.New("nil PQ verifier")
		}
		if set.keys[verifier.Algorithm()] == nil {
			set.keys[verifier.Algorithm()] = make(map[string]*Verifier)
		}
		if _, duplicate := set.keys[verifier.Algorithm()][verifier.KeyID()]; duplicate {
			return nil, errors.New("duplicate PQ verifier key")
		}
		if len(set.keys[verifier.Algorithm()]) >= maxRegistryKeysPerType {
			return nil, errors.New("too many PQ verifier keys for one algorithm")
		}
		set.keys[verifier.Algorithm()][verifier.KeyID()] = verifier
	}
	if len(set.keys) == 0 {
		return nil, errors.New("PQ verifier set is empty")
	}
	return set, nil
}

func LoadVerifierSet(path string) (*VerifierSet, error) {
	data, err := securefile.ReadPublicIntegrity(path, 16<<20)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var file VerifierSetFile
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("PQ verifier set contains extra JSON")
		}
		return nil, err
	}
	if file.Format != verifierSetFormat || len(file.Keys) == 0 {
		return nil, errors.New("unsupported or empty PQ verifier set")
	}
	var verifiers []*Verifier
	for algorithm, encodedKeys := range file.Keys {
		if len(encodedKeys) == 0 || len(encodedKeys) > maxRegistryKeysPerType {
			return nil, fmt.Errorf("%s verifier key count must be between 1 and %d", algorithm, maxRegistryKeysPerType)
		}
		for _, encoded := range encodedKeys {
			publicKey, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("decode %s verifier key: %w", algorithm, err)
			}
			verifier, err := NewVerifier(algorithm, publicKey)
			clear(publicKey)
			if err != nil {
				return nil, fmt.Errorf("load %s verifier key: %w", algorithm, err)
			}
			verifiers = append(verifiers, verifier)
		}
	}
	return NewVerifierSet(verifiers...)
}

func VerifierSetDocument(signers ...*Signer) (VerifierSetFile, error) {
	keys := make(map[string][]string)
	for _, signer := range signers {
		if signer == nil {
			return VerifierSetFile{}, errors.New("nil PQ signer")
		}
		publicKey := signer.PublicBytes()
		encoded := base64.StdEncoding.EncodeToString(publicKey)
		clear(publicKey)
		for _, existing := range keys[signer.Algorithm()] {
			if existing == encoded {
				return VerifierSetFile{}, errors.New("duplicate PQ signer key")
			}
		}
		if len(keys[signer.Algorithm()]) >= maxRegistryKeysPerType {
			return VerifierSetFile{}, errors.New("too many PQ signer keys for one algorithm")
		}
		keys[signer.Algorithm()] = append(keys[signer.Algorithm()], encoded)
	}
	if len(keys) == 0 {
		return VerifierSetFile{}, errors.New("PQ signer set is empty")
	}
	return VerifierSetFile{Format: verifierSetFormat, Keys: keys}, nil
}

func signerBinding(signer *Signer) (algorithm, keyID string, err error) {
	if signer == nil {
		return "", "", errors.New("nil ML-DSA signer")
	}
	algorithm = signer.Algorithm()
	keyID = signer.KeyID()
	if algorithm == "" || keyID == "" {
		return "", "", errors.New("ML-DSA signer is destroyed")
	}
	return algorithm, keyID, nil
}

func (s *VerifierSet) Verifier(algorithm, keyID string) (*Verifier, error) {
	if s == nil {
		return nil, errors.New("nil PQ verifier set")
	}
	algorithmKeys, ok := s.keys[algorithm]
	if !ok {
		return nil, errors.New("controller PQ authentication algorithm is not pinned")
	}
	verifier, ok := algorithmKeys[keyID]
	if !ok {
		return nil, errors.New("controller PQ authentication key binding mismatch")
	}
	return verifier, nil
}

func (s *VerifierSet) HasAlgorithm(algorithm string) bool {
	return s != nil && len(s.keys[algorithm]) > 0
}

func (r *Registry) Verifier(deviceID, algorithm, keyID string) (*Verifier, error) {
	if r == nil {
		return nil, errors.New("nil PQ device registry")
	}
	algorithms, ok := r.devices[deviceID]
	if !ok {
		return nil, errors.New("device has no registered PQ authentication key")
	}
	keys, ok := algorithms[algorithm]
	if !ok {
		return nil, errors.New("device has no registered key for the required PQ authentication algorithm")
	}
	verifier, ok := keys[keyID]
	if !ok {
		return nil, errors.New("device PQ authentication key ID is not registered")
	}
	return verifier, nil
}

func RegistryDocument(deviceID string, signers ...*Signer) (RegistryFile, error) {
	if !protocol.ValidDeviceID(deviceID) {
		return RegistryFile{}, errors.New("invalid device ID")
	}
	algorithms := make(map[string][]string, len(signers))
	for _, signer := range signers {
		if signer == nil {
			return RegistryFile{}, errors.New("nil PQ signer")
		}
		publicKey := signer.PublicBytes()
		encoded := base64.StdEncoding.EncodeToString(publicKey)
		clear(publicKey)
		for _, existing := range algorithms[signer.Algorithm()] {
			if existing == encoded {
				return RegistryFile{}, errors.New("duplicate PQ signer key")
			}
		}
		if len(algorithms[signer.Algorithm()]) >= maxRegistryKeysPerType {
			return RegistryFile{}, errors.New("too many PQ signer keys for one algorithm")
		}
		algorithms[signer.Algorithm()] = append(algorithms[signer.Algorithm()], encoded)
	}
	return RegistryFile{
		Format:  registryFormat,
		Devices: map[string]map[string][]string{deviceID: algorithms},
	}, nil
}

func decodeSignature(encoded string, expectedSize int) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("missing ML-DSA signature")
	}
	expectedEncodedSize := base64.StdEncoding.EncodedLen(expectedSize)
	if len(encoded) != expectedEncodedSize {
		return nil, errors.New("invalid ML-DSA signature length")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid ML-DSA signature encoding")
	}
	if len(signature) != expectedSize {
		clear(signature)
		return nil, errors.New("invalid ML-DSA signature length")
	}
	return signature, nil
}

func EqualKeyID(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
