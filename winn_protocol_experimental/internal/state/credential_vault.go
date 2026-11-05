package state

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const (
	credentialVaultVersion = 1
	// #nosec G101 -- this is a public encrypted-envelope format identifier.
	credentialVaultFormat     = "winn-credential-vault-aes256gcm/v1"
	credentialVaultAD         = "winn-protocol-credential-vault/v1"
	defaultCredentialMaximum  = 8192
	absoluteCredentialMaximum = 8192

	credentialAvailable  = "available"
	credentialReserved   = "reserved"
	credentialConsumed   = "consumed"
	reservationPrepared  = "prepared"
	reservationCommitted = "committed"
)

var (
	vaultIdentifierPattern = regexp.MustCompile(
		`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`,
	)
	vaultDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

	ErrCredentialUnavailable = errors.New(
		"anonymous credential inventory is unavailable",
	)
	ErrCredentialReservation = errors.New(
		"anonymous credential reservation is invalid",
	)
)

type CredentialClassBinding struct {
	TokenKeyID      string `json:"token_key_id"`
	Scope           string `json:"scope"`
	IssuerDomain    string `json:"issuer_domain"`
	IssuerPublicKey string `json:"issuer_public_key"`
	NotBefore       string `json:"not_before"`
	NotAfter        string `json:"not_after"`
}

type CredentialImport struct {
	Class  CredentialClassBinding
	Bundle privacytoken.Bundle
}

type CredentialRequirement struct {
	CandidateID string
	NodeID      string
	Class       CredentialClassBinding
	Count       int
}

type CredentialReservationRequest struct {
	Profile                  string
	ControllerID             string
	ManifestDigest           string
	ManifestSequence         uint64
	ExpiresAt                time.Time
	MinimumUnusedCredentials int
	Requirements             []CredentialRequirement
}

type CredentialClassInventory struct {
	Class             CredentialClassBinding
	UnusedCredentials int
}

type ReservedCredentialCandidate struct {
	Requirement CredentialRequirement
}

type CredentialReservation struct {
	ID                string
	Request           CredentialReservationRequest
	ObservedAt        time.Time
	ExpiresAt         time.Time
	UnusedCredentials int
	ClassInventories  []CredentialClassInventory
	Candidates        []ReservedCredentialCandidate
}

type TakenCredential struct {
	TokenID   string
	Pseudonym string
	Token     privacytoken.Token
	Signer    *pqauth.Signer
}

type CredentialVaultConfig struct {
	Path           string
	KeyPath        string
	MaxCredentials int
	Now            func() time.Time
	Random         io.Reader
}

type CredentialVault struct {
	mu     sync.Mutex
	path   string
	key    [32]byte
	max    int
	now    func() time.Time
	random io.Reader
	state  credentialVaultDiskState
	lock   *fileLock
	closed bool
}

type credentialVaultDiskState struct {
	Version      int                                    `json:"version"`
	Revision     uint64                                 `json:"revision"`
	Classes      map[string]CredentialClassBinding      `json:"classes"`
	Credentials  map[string]credentialVaultRecord       `json:"credentials"`
	Reservations map[string]credentialReservationRecord `json:"reservations"`
}

type credentialVaultRecord struct {
	TokenID       string             `json:"token_id"`
	ClassID       string             `json:"class_id"`
	Pseudonym     string             `json:"pseudonym,omitempty"`
	Token         privacytoken.Token `json:"token,omitempty"`
	AuthSeed      []byte             `json:"auth_seed,omitempty"`
	Status        string             `json:"status"`
	ReservationID string             `json:"reservation_id,omitempty"`
	CandidateID   string             `json:"candidate_id,omitempty"`
}

type credentialReservationRecord struct {
	ID         string                       `json:"id"`
	Request    CredentialReservationRequest `json:"request"`
	Status     string                       `json:"status"`
	CreatedAt  string                       `json:"created_at"`
	ExpiresAt  string                       `json:"expires_at"`
	Candidates map[string][]string          `json:"candidates"`
}

func OpenCredentialVault(
	config CredentialVaultConfig,
) (*CredentialVault, error) {
	if config.Path == "" || config.KeyPath == "" {
		return nil, errors.New(
			"credential vault path and key path are required",
		)
	}
	maximum := config.MaxCredentials
	if maximum == 0 {
		maximum = defaultCredentialMaximum
	}
	if maximum < 1 || maximum > absoluteCredentialMaximum {
		return nil, errors.New("credential vault capacity is invalid")
	}
	keyData, err := securefile.ReadPrivateLimited(
		config.KeyPath, 1024,
	)
	if err != nil {
		return nil, fmt.Errorf("read credential vault key: %w", err)
	}
	defer clear(keyData)
	if len(keyData) != 32 {
		return nil, fmt.Errorf(
			"credential vault key length is %d, want 32",
			len(keyData),
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	vault := &CredentialVault{
		path:   config.Path,
		max:    maximum,
		now:    config.Now,
		random: config.Random,
		state:  newCredentialVaultDiskState(),
	}
	copy(vault.key[:], keyData)
	lock, err := acquireFileLock(config.Path + ".lock")
	if err != nil {
		clear(vault.key[:])
		return nil, fmt.Errorf("lock credential vault: %w", err)
	}
	vault.lock = lock
	if err := vault.load(); err != nil {
		_ = vault.lock.release()
		clearCredentialVaultSecrets(&vault.state)
		clear(vault.key[:])
		return nil, err
	}
	if err := vault.reconcileAfterRestartLocked(); err != nil {
		_ = vault.lock.release()
		clearCredentialVaultSecrets(&vault.state)
		clear(vault.key[:])
		return nil, err
	}
	return vault, nil
}

// Add verifies and atomically imports a batch. Tokens are globally unique,
// bounded, issuer-bound, and encrypted before the method returns.
func (vault *CredentialVault) Add(
	ctx context.Context,
	imports []CredentialImport,
) error {
	if err := requireVaultContext(ctx); err != nil {
		return err
	}
	if len(imports) == 0 ||
		len(imports) > absoluteCredentialMaximum {
		return errors.New("credential import batch is invalid")
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return errors.New("credential vault is closed")
	}
	now := vault.now().UTC()
	next := cloneCredentialVaultState(vault.state)
	expireCredentialVaultState(next, now)
	if len(next.Credentials)+len(imports) > vault.max {
		clearCredentialVaultSecrets(&next)
		return errors.New("credential vault capacity exceeded")
	}
	for _, current := range imports {
		publicKey, _, err := validateCredentialClass(
			current.Class, now, true,
		)
		if err != nil {
			clearCredentialVaultSecrets(&next)
			return err
		}
		verified, err := privacytoken.Verify(
			current.Bundle.PublicToken(),
			publicKey,
			current.Class.TokenKeyID,
		)
		if err != nil {
			clearCredentialVaultSecrets(&next)
			return err
		}
		token, seed, err := current.Bundle.SecretMaterial()
		if err != nil {
			clearCredentialVaultSecrets(&next)
			return err
		}
		signer, err := privacytoken.NewCredentialSigner(token, seed)
		if err != nil {
			clear(seed)
			clearCredentialVaultSecrets(&next)
			return err
		}
		signer.Destroy()
		if _, duplicate := next.Credentials[verified.TokenID]; duplicate {
			clear(seed)
			clearCredentialVaultSecrets(&next)
			return errors.New(
				"privacy token is already present in credential vault",
			)
		}
		classID := credentialClassID(current.Class)
		if existing, ok := next.Classes[classID]; ok &&
			existing != current.Class {
			clear(seed)
			clearCredentialVaultSecrets(&next)
			return errors.New("credential class hash collision")
		}
		next.Classes[classID] = current.Class
		if len(next.Classes) > vault.max {
			clear(seed)
			clearCredentialVaultSecrets(&next)
			return errors.New(
				"credential vault class capacity exceeded",
			)
		}
		next.Credentials[verified.TokenID] = credentialVaultRecord{
			TokenID:   verified.TokenID,
			ClassID:   classID,
			Pseudonym: verified.Pseudonym,
			Token:     token,
			AuthSeed:  seed,
			Status:    credentialAvailable,
		}
	}
	if err := vault.saveLocked(&next); err != nil {
		clearCredentialVaultSecrets(&next)
		return err
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	return nil
}

// BeginReservation atomically moves exact credentials from available to a
// prepared reservation. A crash before Commit is reconciled on next Open.
func (vault *CredentialVault) BeginReservation(
	ctx context.Context,
	request CredentialReservationRequest,
) (CredentialReservation, error) {
	if err := requireVaultContext(ctx); err != nil {
		return CredentialReservation{}, err
	}
	now := vault.now().UTC()
	if err := validateCredentialReservationRequest(
		request, now,
	); err != nil {
		return CredentialReservation{}, err
	}
	request = cloneCredentialReservationRequest(request)
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return CredentialReservation{},
			errors.New("credential vault is closed")
	}
	next := cloneCredentialVaultState(vault.state)
	if changed := expireCredentialVaultState(next, now); changed {
		if err := vault.saveLocked(&next); err != nil {
			clearCredentialVaultSecrets(&next)
			return CredentialReservation{}, err
		}
		clearCredentialVaultSecrets(&vault.state)
		vault.state = next
		next = cloneCredentialVaultState(vault.state)
	}
	if len(next.Reservations) >= vault.max {
		clearCredentialVaultSecrets(&next)
		return CredentialReservation{},
			errors.New("credential reservation capacity exceeded")
	}

	classNeeds := make(map[string]int)
	classBindings := make(map[string]CredentialClassBinding)
	for _, requirement := range request.Requirements {
		if _, _, err := validateCredentialClass(
			requirement.Class, now, true,
		); err != nil {
			clearCredentialVaultSecrets(&next)
			return CredentialReservation{}, err
		}
		notAfter, _ := time.Parse(
			time.RFC3339Nano, requirement.Class.NotAfter,
		)
		if request.ExpiresAt.After(notAfter) {
			clearCredentialVaultSecrets(&next)
			return CredentialReservation{}, errors.New(
				"reservation outlives credential issuer key",
			)
		}
		classID := credentialClassID(requirement.Class)
		if stored, ok := next.Classes[classID]; !ok ||
			stored != requirement.Class {
			clearCredentialVaultSecrets(&next)
			return CredentialReservation{},
				ErrCredentialUnavailable
		}
		classNeeds[classID] += requirement.Count
		classBindings[classID] = requirement.Class
	}
	availableByClass := availableCredentialIDs(next)
	for classID, needed := range classNeeds {
		if len(availableByClass[classID])-needed <
			request.MinimumUnusedCredentials {
			clearCredentialVaultSecrets(&next)
			return CredentialReservation{},
				ErrCredentialUnavailable
		}
	}
	reservationID, err := vault.newReservationIDLocked(next)
	if err != nil {
		clearCredentialVaultSecrets(&next)
		return CredentialReservation{}, err
	}
	record := credentialReservationRecord{
		ID:         reservationID,
		Request:    cloneCredentialReservationRequest(request),
		Status:     reservationPrepared,
		CreatedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt:  request.ExpiresAt.UTC().Format(time.RFC3339Nano),
		Candidates: make(map[string][]string, len(request.Requirements)),
	}
	offsets := make(map[string]int)
	for _, requirement := range request.Requirements {
		classID := credentialClassID(requirement.Class)
		start := offsets[classID]
		end := start + requirement.Count
		selected := slices.Clone(
			availableByClass[classID][start:end],
		)
		offsets[classID] = end
		record.Candidates[requirement.CandidateID] = selected
		for _, tokenID := range selected {
			credential := next.Credentials[tokenID]
			credential.Status = credentialReserved
			credential.ReservationID = reservationID
			credential.CandidateID = requirement.CandidateID
			next.Credentials[tokenID] = credential
		}
	}
	next.Reservations[reservationID] = record
	if err := vault.saveLocked(&next); err != nil {
		clearCredentialVaultSecrets(&next)
		return CredentialReservation{}, err
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	return reservationSnapshot(
		record, vault.state, classBindings, now,
	), nil
}

func (vault *CredentialVault) CommitReservation(
	ctx context.Context,
	reservationID string,
) error {
	if err := requireVaultContext(ctx); err != nil {
		return err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return errors.New("credential vault is closed")
	}
	record, ok := vault.state.Reservations[reservationID]
	if !ok {
		return ErrCredentialReservation
	}
	if record.Status == reservationCommitted {
		return nil
	}
	if record.Status != reservationPrepared ||
		credentialReservationExpired(record, vault.now().UTC()) {
		return ErrCredentialReservation
	}
	next := cloneCredentialVaultState(vault.state)
	record.Status = reservationCommitted
	next.Reservations[reservationID] = record
	if err := vault.saveLocked(&next); err != nil {
		clearCredentialVaultSecrets(&next)
		return err
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	return nil
}

// TakeCredential durably consumes and removes secret material before
// returning a signer. A crash after persistence can only burn, never replay,
// the token.
func (vault *CredentialVault) TakeCredential(
	ctx context.Context,
	reservationID string,
	candidateID string,
) (TakenCredential, error) {
	if err := requireVaultContext(ctx); err != nil {
		return TakenCredential{}, err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return TakenCredential{},
			errors.New("credential vault is closed")
	}
	record, ok := vault.state.Reservations[reservationID]
	if !ok || record.Status != reservationCommitted ||
		credentialReservationExpired(record, vault.now().UTC()) {
		return TakenCredential{}, ErrCredentialReservation
	}
	tokenIDs, ok := record.Candidates[candidateID]
	if !ok {
		return TakenCredential{}, ErrCredentialReservation
	}
	var selected credentialVaultRecord
	for _, tokenID := range tokenIDs {
		current := vault.state.Credentials[tokenID]
		if current.Status == credentialReserved &&
			current.ReservationID == reservationID &&
			current.CandidateID == candidateID {
			selected = current
			break
		}
	}
	if selected.TokenID == "" {
		return TakenCredential{}, ErrCredentialUnavailable
	}
	seed := slices.Clone(selected.AuthSeed)
	token := selected.Token
	next := cloneCredentialVaultState(vault.state)
	consumed := next.Credentials[selected.TokenID]
	clear(consumed.AuthSeed)
	consumed.AuthSeed = nil
	consumed.Token = privacytoken.Token{}
	consumed.Pseudonym = ""
	consumed.Status = credentialConsumed
	consumed.ReservationID = ""
	consumed.CandidateID = ""
	next.Credentials[selected.TokenID] = consumed
	if err := vault.saveLocked(&next); err != nil {
		clear(seed)
		clearCredentialVaultSecrets(&next)
		return TakenCredential{}, err
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	signer, err := privacytoken.NewCredentialSigner(token, seed)
	clear(seed)
	if err != nil {
		return TakenCredential{}, err
	}
	return TakenCredential{
		TokenID:   selected.TokenID,
		Pseudonym: selected.Pseudonym,
		Token:     token,
		Signer:    signer,
	}, nil
}

func (vault *CredentialVault) ReleaseReservation(
	ctx context.Context,
	reservationID string,
) error {
	if err := requireVaultContext(ctx); err != nil {
		return err
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return errors.New("credential vault is closed")
	}
	if _, ok := vault.state.Reservations[reservationID]; !ok {
		return nil
	}
	next := cloneCredentialVaultState(vault.state)
	releaseCredentialReservation(next, reservationID, vault.now().UTC())
	if err := vault.saveLocked(&next); err != nil {
		clearCredentialVaultSecrets(&next)
		return err
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	return nil
}

func (vault *CredentialVault) Close() error {
	if vault == nil {
		return nil
	}
	vault.mu.Lock()
	defer vault.mu.Unlock()
	if vault.closed {
		return nil
	}
	next := cloneCredentialVaultState(vault.state)
	for reservationID := range next.Reservations {
		releaseCredentialReservation(
			next, reservationID, vault.now().UTC(),
		)
	}
	var saveErr error
	if len(vault.state.Reservations) != 0 {
		saveErr = vault.saveLocked(&next)
	}
	clearCredentialVaultSecrets(&vault.state)
	clearCredentialVaultSecrets(&next)
	clear(vault.key[:])
	vault.closed = true
	var lockErr error
	if vault.lock != nil {
		lockErr = vault.lock.release()
		vault.lock = nil
	}
	return errors.Join(saveErr, lockErr)
}

func (vault *CredentialVault) load() error {
	encrypted, err := securefile.ReadPrivateLimited(
		vault.path, 128<<20,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted credential vault: %w", err)
	}
	defer clear(encrypted)
	var container envelope
	decoder := json.NewDecoder(bytes.NewReader(encrypted))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&container); err != nil {
		return fmt.Errorf("decode credential vault envelope: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode credential vault envelope: %w", err)
	}
	if container.Format != credentialVaultFormat {
		return fmt.Errorf(
			"unsupported credential vault envelope %q",
			container.Format,
		)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(
		container.Nonce,
	)
	if err != nil {
		return errors.New("decode credential vault nonce")
	}
	defer clear(nonce)
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(
		container.Ciphertext,
	)
	if err != nil {
		return errors.New("decode credential vault ciphertext")
	}
	defer clear(ciphertext)
	aead, err := vault.aead()
	if err != nil {
		return err
	}
	if len(nonce) != aead.NonceSize() {
		return errors.New("invalid credential vault nonce length")
	}
	plaintext, err := aead.Open(
		nil, nonce, ciphertext, []byte(credentialVaultAD),
	)
	if err != nil {
		return errors.New(
			"decrypt credential vault: authentication failed",
		)
	}
	defer clear(plaintext)
	var decoded credentialVaultDiskState
	stateDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	stateDecoder.DisallowUnknownFields()
	if err := stateDecoder.Decode(&decoded); err != nil {
		clearCredentialVaultSecrets(&decoded)
		return fmt.Errorf("decode credential vault: %w", err)
	}
	if err := requireJSONEOF(stateDecoder); err != nil {
		clearCredentialVaultSecrets(&decoded)
		return fmt.Errorf("decode credential vault: %w", err)
	}
	if err := validateCredentialVaultState(
		decoded, vault.max, vault.now().UTC(),
	); err != nil {
		clearCredentialVaultSecrets(&decoded)
		return err
	}
	vault.state = decoded
	return nil
}

func (vault *CredentialVault) saveLocked(
	next *credentialVaultDiskState,
) error {
	next.Revision = vault.state.Revision + 1
	plaintext, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	aead, err := vault.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(vault.random, nonce); err != nil {
		clear(nonce)
		return err
	}
	defer clear(nonce)
	ciphertext := aead.Seal(
		nil, nonce, plaintext, []byte(credentialVaultAD),
	)
	defer clear(ciphertext)
	container := envelope{
		Format: credentialVaultFormat,
		Nonce: base64.StdEncoding.EncodeToString(
			nonce,
		),
		Ciphertext: base64.StdEncoding.EncodeToString(
			ciphertext,
		),
	}
	encoded, err := json.Marshal(container)
	if err != nil {
		return err
	}
	defer clear(encoded)
	encoded = append(encoded, '\n')
	if err := securefile.AtomicWrite(
		vault.path, encoded, 0o600,
	); err != nil {
		return err
	}
	return nil
}

func (vault *CredentialVault) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(vault.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (vault *CredentialVault) reconcileAfterRestartLocked() error {
	next := cloneCredentialVaultState(vault.state)
	now := vault.now().UTC()
	changed := expireCredentialVaultState(next, now)
	for reservationID := range next.Reservations {
		releaseCredentialReservation(next, reservationID, now)
		changed = true
	}
	if !changed {
		clearCredentialVaultSecrets(&next)
		return nil
	}
	if err := vault.saveLocked(&next); err != nil {
		clearCredentialVaultSecrets(&next)
		return fmt.Errorf("reconcile credential reservations: %w", err)
	}
	clearCredentialVaultSecrets(&vault.state)
	vault.state = next
	return nil
}

func validateCredentialVaultState(
	current credentialVaultDiskState,
	maximum int,
	now time.Time,
) error {
	if current.Version != credentialVaultVersion ||
		current.Classes == nil ||
		current.Credentials == nil ||
		current.Reservations == nil ||
		len(current.Classes) > maximum ||
		len(current.Credentials) > maximum ||
		len(current.Reservations) > maximum {
		return errors.New("credential vault state is invalid")
	}
	publicKeys := make(map[string]*rsa.PublicKey, len(current.Classes))
	for classID, class := range current.Classes {
		if classID != credentialClassID(class) {
			return errors.New("credential vault class binding is invalid")
		}
		publicKey, _, err := validateCredentialClass(
			class, now, false,
		)
		if err != nil {
			return err
		}
		publicKeys[classID] = publicKey
	}
	for tokenID, record := range current.Credentials {
		class, ok := current.Classes[record.ClassID]
		if !ok || tokenID == "" || tokenID != record.TokenID {
			return errors.New("credential vault token binding is invalid")
		}
		switch record.Status {
		case credentialAvailable, credentialReserved:
			if len(record.AuthSeed) != 32 ||
				record.Token.PreparedMessage == "" ||
				record.Token.Signature == "" ||
				record.Pseudonym == "" {
				return errors.New(
					"credential vault secret record is invalid",
				)
			}
			verified, err := privacytoken.Verify(
				record.Token,
				publicKeys[record.ClassID],
				class.TokenKeyID,
			)
			if err != nil ||
				verified.TokenID != record.TokenID ||
				verified.Pseudonym != record.Pseudonym {
				return errors.New(
					"credential vault token verification failed",
				)
			}
			signer, err := privacytoken.NewCredentialSigner(
				record.Token, record.AuthSeed,
			)
			if err != nil {
				return err
			}
			signer.Destroy()
		case credentialConsumed:
			if len(record.AuthSeed) != 0 ||
				record.Token != (privacytoken.Token{}) ||
				record.Pseudonym != "" ||
				record.ReservationID != "" ||
				record.CandidateID != "" {
				return errors.New(
					"consumed credential retained secret material",
				)
			}
		default:
			return errors.New("credential vault status is invalid")
		}
		if record.Status == credentialReserved {
			reservation, ok := current.Reservations[record.ReservationID]
			if !ok ||
				!slices.Contains(
					reservation.Candidates[record.CandidateID],
					record.TokenID,
				) {
				return errors.New(
					"reserved credential is orphaned",
				)
			}
		} else if record.ReservationID != "" ||
			record.CandidateID != "" {
			return errors.New(
				"unreserved credential has reservation metadata",
			)
		}
	}
	claimed := make(map[string]struct{})
	for reservationID, record := range current.Reservations {
		if reservationID != record.ID ||
			(record.Status != reservationPrepared &&
				record.Status != reservationCommitted) ||
			record.Candidates == nil {
			return errors.New(
				"credential reservation record is invalid",
			)
		}
		if err := validateCredentialReservationRequest(
			record.Request,
			time.Unix(0, 0).UTC(),
		); err != nil {
			return err
		}
		createdAt, createdErr := time.Parse(
			time.RFC3339Nano, record.CreatedAt,
		)
		expiresAt, expiresErr := time.Parse(
			time.RFC3339Nano, record.ExpiresAt,
		)
		if createdErr != nil || expiresErr != nil ||
			!expiresAt.After(createdAt) ||
			!expiresAt.Equal(record.Request.ExpiresAt.UTC()) ||
			len(record.Candidates) !=
				len(record.Request.Requirements) {
			return errors.New(
				"credential reservation time binding is invalid",
			)
		}
		for _, requirement := range record.Request.Requirements {
			tokenIDs, ok := record.Candidates[requirement.CandidateID]
			if !ok || len(tokenIDs) != requirement.Count {
				return errors.New(
					"credential reservation candidate count is invalid",
				)
			}
			for _, tokenID := range tokenIDs {
				if _, duplicate := claimed[tokenID]; duplicate {
					return errors.New(
						"credential token is reserved more than once",
					)
				}
				claimed[tokenID] = struct{}{}
				credential := current.Credentials[tokenID]
				if credential.ClassID !=
					credentialClassID(requirement.Class) {
					return errors.New(
						"credential reservation class is invalid",
					)
				}
				reservedHere := credential.Status ==
					credentialReserved &&
					credential.ReservationID == reservationID &&
					credential.CandidateID ==
						requirement.CandidateID
				if !reservedHere &&
					credential.Status != credentialConsumed {
					return errors.New(
						"credential reservation token is invalid",
					)
				}
			}
		}
	}
	return nil
}

func validateCredentialClass(
	class CredentialClassBinding,
	now time.Time,
	requireCurrent bool,
) (*rsa.PublicKey, time.Time, error) {
	if !vaultDigestPattern.MatchString(class.TokenKeyID) ||
		!validVaultText(class.Scope) ||
		!validVaultText(class.IssuerDomain) {
		return nil, time.Time{},
			errors.New("credential class binding is invalid")
	}
	publicDER, err := base64.StdEncoding.Strict().DecodeString(
		class.IssuerPublicKey,
	)
	if err != nil {
		clear(publicDER)
		return nil, time.Time{},
			errors.New("credential issuer public key is invalid")
	}
	publicKey, err := privacytoken.ParseIssuerPublicKeyDER(publicDER)
	clear(publicDER)
	if err != nil {
		return nil, time.Time{}, err
	}
	keyID, err := privacytoken.IssuerKeyID(publicKey)
	if err != nil || keyID != class.TokenKeyID {
		return nil, time.Time{},
			errors.New("credential issuer key ID is invalid")
	}
	notBefore, beforeErr := time.Parse(
		time.RFC3339Nano, class.NotBefore,
	)
	notAfter, afterErr := time.Parse(
		time.RFC3339Nano, class.NotAfter,
	)
	if beforeErr != nil || afterErr != nil ||
		!notAfter.After(notBefore) {
		return nil, time.Time{},
			errors.New("credential issuer key window is invalid")
	}
	if requireCurrent {
		if err := privacytoken.ValidateKeyWindow(
			notBefore, notAfter, now,
		); err != nil {
			return nil, time.Time{}, err
		}
	}
	return publicKey, notAfter.UTC(), nil
}

func validateCredentialReservationRequest(
	request CredentialReservationRequest,
	now time.Time,
) error {
	if !vaultIdentifierPattern.MatchString(request.Profile) ||
		!protocol.ValidDeviceID(request.ControllerID) ||
		!vaultDigestPattern.MatchString(request.ManifestDigest) ||
		request.ManifestSequence == 0 ||
		!request.ExpiresAt.After(now) ||
		request.MinimumUnusedCredentials < 1 ||
		request.MinimumUnusedCredentials > 1024 ||
		len(request.Requirements) > 1024 {
		return ErrCredentialReservation
	}
	seen := make(map[string]struct{}, len(request.Requirements))
	for _, requirement := range request.Requirements {
		if !vaultIdentifierPattern.MatchString(
			requirement.CandidateID,
		) ||
			!protocol.ValidDeviceID(requirement.NodeID) ||
			requirement.Count < 1 ||
			requirement.Count > 16 {
			return ErrCredentialReservation
		}
		if _, duplicate := seen[requirement.CandidateID]; duplicate {
			return ErrCredentialReservation
		}
		seen[requirement.CandidateID] = struct{}{}
	}
	return nil
}

func reservationSnapshot(
	record credentialReservationRecord,
	current credentialVaultDiskState,
	classBindings map[string]CredentialClassBinding,
	observedAt time.Time,
) CredentialReservation {
	classIDs := make([]string, 0, len(classBindings))
	for classID := range classBindings {
		classIDs = append(classIDs, classID)
	}
	sort.Strings(classIDs)
	inventories := make(
		[]CredentialClassInventory, 0, len(classIDs),
	)
	unused := record.Request.MinimumUnusedCredentials
	if len(classIDs) != 0 {
		unused = absoluteCredentialMaximum + 1
	}
	available := availableCredentialIDs(current)
	for _, classID := range classIDs {
		count := len(available[classID])
		if count < unused {
			unused = count
		}
		inventories = append(
			inventories,
			CredentialClassInventory{
				Class:             classBindings[classID],
				UnusedCredentials: count,
			},
		)
	}
	candidates := make(
		[]ReservedCredentialCandidate,
		len(record.Request.Requirements),
	)
	for index, requirement := range record.Request.Requirements {
		candidates[index] = ReservedCredentialCandidate{
			Requirement: requirement,
		}
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	return CredentialReservation{
		ID:                record.ID,
		Request:           cloneCredentialReservationRequest(record.Request),
		ObservedAt:        observedAt.UTC(),
		ExpiresAt:         expiresAt.UTC(),
		UnusedCredentials: unused,
		ClassInventories:  inventories,
		Candidates:        candidates,
	}
}

func availableCredentialIDs(
	current credentialVaultDiskState,
) map[string][]string {
	result := make(map[string][]string)
	for tokenID, record := range current.Credentials {
		if record.Status == credentialAvailable {
			result[record.ClassID] = append(
				result[record.ClassID], tokenID,
			)
		}
	}
	for classID := range result {
		sort.Strings(result[classID])
	}
	return result
}

func releaseCredentialReservation(
	current credentialVaultDiskState,
	reservationID string,
	now time.Time,
) {
	record, ok := current.Reservations[reservationID]
	if !ok {
		return
	}
	for _, tokenIDs := range record.Candidates {
		for _, tokenID := range tokenIDs {
			credential := current.Credentials[tokenID]
			if credential.Status != credentialReserved ||
				credential.ReservationID != reservationID {
				continue
			}
			class := current.Classes[credential.ClassID]
			_, notAfter, err := validateCredentialClass(
				class, now, false,
			)
			if err != nil || !notAfter.After(now) {
				clear(credential.AuthSeed)
				credential.AuthSeed = nil
				credential.Token = privacytoken.Token{}
				credential.Pseudonym = ""
				credential.Status = credentialConsumed
			} else {
				credential.Status = credentialAvailable
			}
			credential.ReservationID = ""
			credential.CandidateID = ""
			current.Credentials[tokenID] = credential
		}
	}
	delete(current.Reservations, reservationID)
}

func expireCredentialVaultState(
	current credentialVaultDiskState,
	now time.Time,
) bool {
	changed := false
	for reservationID, record := range current.Reservations {
		if credentialReservationExpired(record, now) {
			releaseCredentialReservation(
				current, reservationID, now,
			)
			changed = true
		}
	}
	for tokenID, credential := range current.Credentials {
		class := current.Classes[credential.ClassID]
		_, notAfter, err := validateCredentialClass(
			class, now, false,
		)
		if err == nil && notAfter.After(now) {
			continue
		}
		clear(credential.AuthSeed)
		delete(current.Credentials, tokenID)
		changed = true
	}
	if pruneCredentialClasses(current) {
		changed = true
	}
	return changed
}

func pruneCredentialClasses(
	current credentialVaultDiskState,
) bool {
	used := make(map[string]struct{}, len(current.Credentials))
	for _, credential := range current.Credentials {
		used[credential.ClassID] = struct{}{}
	}
	changed := false
	for classID := range current.Classes {
		if _, ok := used[classID]; !ok {
			delete(current.Classes, classID)
			changed = true
		}
	}
	return changed
}

func credentialReservationExpired(
	record credentialReservationRecord,
	now time.Time,
) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, record.ExpiresAt)
	return err != nil || !expiresAt.After(now)
}

func (vault *CredentialVault) newReservationIDLocked(
	current credentialVaultDiskState,
) (string, error) {
	var randomBytes [16]byte
	for range 8 {
		if _, err := io.ReadFull(
			vault.random, randomBytes[:],
		); err != nil {
			clear(randomBytes[:])
			return "", err
		}
		id := hex.EncodeToString(randomBytes[:])
		clear(randomBytes[:])
		if _, duplicate := current.Reservations[id]; !duplicate {
			return id, nil
		}
	}
	return "", errors.New("generate unique credential reservation ID")
}

func credentialClassID(class CredentialClassBinding) string {
	encoded, _ := json.Marshal(class)
	digest := sha256.Sum256(append(
		[]byte("winn-credential-class/v1\x00"), encoded...,
	))
	clear(encoded)
	return hex.EncodeToString(digest[:])
}

func validVaultText(value string) bool {
	return value != "" &&
		len(value) <= 256 &&
		utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func cloneCredentialReservationRequest(
	source CredentialReservationRequest,
) CredentialReservationRequest {
	source.Requirements = slices.Clone(source.Requirements)
	return source
}

func cloneCredentialVaultState(
	source credentialVaultDiskState,
) credentialVaultDiskState {
	result := newCredentialVaultDiskState()
	result.Revision = source.Revision
	for classID, class := range source.Classes {
		result.Classes[classID] = class
	}
	for tokenID, credential := range source.Credentials {
		credential.AuthSeed = slices.Clone(credential.AuthSeed)
		result.Credentials[tokenID] = credential
	}
	for reservationID, reservation := range source.Reservations {
		reservation.Request = cloneCredentialReservationRequest(
			reservation.Request,
		)
		reservation.Candidates = make(
			map[string][]string, len(reservation.Candidates),
		)
		for candidateID, tokenIDs := range source.
			Reservations[reservationID].Candidates {
			reservation.Candidates[candidateID] = slices.Clone(
				tokenIDs,
			)
		}
		result.Reservations[reservationID] = reservation
	}
	return result
}

func clearCredentialVaultSecrets(
	current *credentialVaultDiskState,
) {
	if current == nil {
		return
	}
	for tokenID, credential := range current.Credentials {
		clear(credential.AuthSeed)
		credential.AuthSeed = nil
		current.Credentials[tokenID] = credential
	}
}

func newCredentialVaultDiskState() credentialVaultDiskState {
	return credentialVaultDiskState{
		Version:      credentialVaultVersion,
		Classes:      make(map[string]CredentialClassBinding),
		Credentials:  make(map[string]credentialVaultRecord),
		Reservations: make(map[string]credentialReservationRecord),
	}
}

func requireVaultContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("credential vault context is required")
	}
	return context.Cause(ctx)
}
