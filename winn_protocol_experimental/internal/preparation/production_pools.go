package preparation

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/privacytoken"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

// PinnedHybridPSKSnapshot is the narrow boundary missing from rotation's
// current file client. An implementation must atomically snapshot and pin the
// rotation state and applied PSK across Resource's lifetime. PSK ownership is
// transferred to the adapter and is cleared before AcquireCurrentHybridPSK
// returns.
type PinnedHybridPSKSnapshot struct {
	Request    HybridPSKPoolRequest
	ObservedAt time.Time
	State      rotation.ClientState
	PSK        []byte
	Resource   Resource
}

type HybridPSKSnapshotSource interface {
	PinCurrentHybridPSK(
		context.Context,
		HybridPSKPoolRequest,
	) (PinnedHybridPSKSnapshot, error)
}

type ProductionHybridPSKPoolConfig struct {
	Source        HybridPSKSnapshotSource
	Suite         string
	DeviceID      string
	PeerPublicKey string
	Now           func() time.Time
}

// ProductionHybridPSKPool validates a source-pinned rotation snapshot using
// protocol.KeyID and exposes only generation leases, never raw PSK bytes.
type ProductionHybridPSKPool struct {
	source        HybridPSKSnapshotSource
	suite         string
	deviceID      string
	peerPublicKey string
	now           func() time.Time
}

var _ HybridPSKPool = (*ProductionHybridPSKPool)(nil)

func NewProductionHybridPSKPool(
	config ProductionHybridPSKPoolConfig,
) (*ProductionHybridPSKPool, error) {
	if isNil(config.Source) ||
		!protocol.ValidSuite(config.Suite) ||
		!protocol.ValidDeviceID(config.DeviceID) {
		return nil, errors.New(
			"production hybrid PSK snapshot configuration is invalid",
		)
	}
	if err := protocol.ValidatePeerPublicKey(
		config.PeerPublicKey,
	); err != nil {
		return nil, fmt.Errorf(
			"production hybrid PSK peer key: %w", err,
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &ProductionHybridPSKPool{
		source:        config.Source,
		suite:         config.Suite,
		deviceID:      config.DeviceID,
		peerPublicKey: config.PeerPublicKey,
		now:           config.Now,
	}, nil
}

func (pool *ProductionHybridPSKPool) AcquireCurrentHybridPSK(
	ctx context.Context,
	request HybridPSKPoolRequest,
) (HybridPSKPoolLease, error) {
	if pool == nil {
		return HybridPSKPoolLease{},
			errors.New("production hybrid PSK pool is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return HybridPSKPoolLease{}, cause
	}
	now := pool.now().UTC()
	if !identifierPattern.MatchString(request.Profile) ||
		!identifierPattern.MatchString(request.ControllerID) ||
		!digestPattern.MatchString(request.ManifestDigest) ||
		request.ManifestSequence == 0 ||
		!request.ManifestExpiresAt.After(now) {
		return HybridPSKPoolLease{},
			errors.New("hybrid PSK pool request is invalid")
	}
	snapshot, sourceErr := pool.source.PinCurrentHybridPSK(
		ctx, request,
	)
	defer clear(snapshot.PSK)
	sourceResource := ownedResource{
		name:     "pinned hybrid PSK snapshot",
		resource: snapshot.Resource,
	}
	if sourceErr != nil {
		return HybridPSKPoolLease{}, errors.Join(
			fmt.Errorf("pin hybrid PSK snapshot: %w", sourceErr),
			closeFailedPreparation([]ownedResource{sourceResource}),
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return HybridPSKPoolLease{}, errors.Join(
			cause,
			closeFailedPreparation([]ownedResource{sourceResource}),
		)
	}
	now = pool.now().UTC()
	expiresAt, err := pool.validateSnapshot(
		snapshot, request, now,
	)
	if err != nil {
		return HybridPSKPoolLease{}, errors.Join(
			err,
			closeFailedPreparation([]ownedResource{sourceResource}),
		)
	}
	shared := newSharedAssemblyResources(
		[]ownedResource{sourceResource},
	)
	root := &sharedAssemblyReference{shared: shared}
	scoped := &productionHybridPSKLeaser{
		generation: snapshot.State.Generation,
		expiresAt:  expiresAt,
		shared:     shared,
		now:        pool.now,
	}
	return HybridPSKPoolLease{
		Profile:           request.Profile,
		ControllerID:      request.ControllerID,
		ManifestDigest:    request.ManifestDigest,
		ManifestSequence:  request.ManifestSequence,
		ManifestExpiresAt: request.ManifestExpiresAt.UTC(),
		ObservedAt:        snapshot.ObservedAt.UTC(),
		Generation:        snapshot.State.Generation,
		ExpiresAt:         expiresAt,
		PSKs:              scoped,
		Resource:          root,
	}, nil
}

func (pool *ProductionHybridPSKPool) validateSnapshot(
	snapshot PinnedHybridPSKSnapshot,
	request HybridPSKPoolRequest,
	now time.Time,
) (time.Time, error) {
	state := snapshot.State
	expiresAt, err := time.Parse(time.RFC3339Nano, state.ExpiresAt)
	if err != nil {
		return time.Time{},
			errors.New("pinned hybrid PSK expiry is invalid")
	}
	if !reflect.DeepEqual(snapshot.Request, request) ||
		!freshPoolObservation(snapshot.ObservedAt, now) ||
		state.Version != 1 ||
		state.ControllerID != request.ControllerID ||
		state.Suite != pool.suite ||
		state.DeviceID != pool.deviceID ||
		state.PeerPublicKey != pool.peerPublicKey ||
		state.Generation == 0 ||
		state.Pending != nil ||
		state.KeyID == "" ||
		!expiresAt.After(now) ||
		expiresAt.After(request.ManifestExpiresAt) ||
		len(snapshot.PSK) != 32 ||
		isAllZero(snapshot.PSK) ||
		isNil(snapshot.Resource) {
		return time.Time{}, errors.New(
			"pinned hybrid PSK state differs from current verified trust",
		)
	}
	expectedKeyID := protocol.KeyID(
		request.ControllerID,
		pool.suite,
		pool.deviceID,
		pool.peerPublicKey,
		state.Generation,
		snapshot.PSK,
	)
	if state.KeyID != expectedKeyID {
		return time.Time{},
			errors.New("pinned hybrid PSK key ID is invalid")
	}
	return expiresAt.UTC(), nil
}

type productionHybridPSKLeaser struct {
	generation uint64
	expiresAt  time.Time
	shared     *sharedAssemblyResources
	now        func() time.Time
}

func (leaser *productionHybridPSKLeaser) AcquireHybridPSK(
	ctx context.Context,
	generation uint64,
) (HybridPSKLease, error) {
	if leaser == nil || leaser.shared == nil {
		return HybridPSKLease{},
			errors.New("scoped hybrid PSK leaser is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return HybridPSKLease{}, cause
	}
	if generation != leaser.generation ||
		!leaser.expiresAt.After(leaser.now().UTC()) {
		return HybridPSKLease{},
			errors.New("requested hybrid PSK generation is not pinned")
	}
	resource, err := leaser.shared.acquire()
	if err != nil {
		return HybridPSKLease{}, err
	}
	return HybridPSKLease{
		Generation: leaser.generation,
		ExpiresAt:  leaser.expiresAt,
		Resource:   resource,
	}, nil
}

// AtomicAnonymousCredentialVault is the narrow durable boundary absent from
// privacytoken's current single-bundle file API. Reserve must atomically and
// durably reserve every exact requirement before returning. Resource owns the
// vault-level pin. Each candidate Resource owns its reserved source and must
// zero that source's signer secrets on close. Returned slices transfer to the
// adapter and must not be mutated by the vault after return.
type AtomicAnonymousCredentialVault interface {
	ReserveAnonymousCredentials(
		context.Context,
		AnonymousCredentialPoolRequest,
	) (PinnedAnonymousCredentialReservation, error)
}

type PinnedAnonymousCredentialReservation struct {
	Request           AnonymousCredentialPoolRequest
	ObservedAt        time.Time
	ExpiresAt         time.Time
	UnusedCredentials int
	ClassInventories  []AnonymousCredentialClassInventory
	Candidates        []PinnedAnonymousCandidateReservation
	Durable           bool
	Resource          Resource
}

type PinnedAnonymousCandidateReservation struct {
	Requirement AnonymousCredentialRequirement
	Source      carrier.AnonymousCredentialSource
	Resource    Resource
}

type ProductionAnonymousCredentialPoolConfig struct {
	Vault AtomicAnonymousCredentialVault
	Now   func() time.Time
}

// ProductionAnonymousCredentialPool validates signed issuer facts and wraps
// every vault source with token, pseudonym, and ephemeral signer verification.
type ProductionAnonymousCredentialPool struct {
	vault AtomicAnonymousCredentialVault
	now   func() time.Time
}

var _ AnonymousCredentialPool = (*ProductionAnonymousCredentialPool)(nil)

func NewProductionAnonymousCredentialPool(
	config ProductionAnonymousCredentialPoolConfig,
) (*ProductionAnonymousCredentialPool, error) {
	if isNil(config.Vault) {
		return nil, errors.New(
			"production anonymous credential vault is required",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &ProductionAnonymousCredentialPool{
		vault: config.Vault,
		now:   config.Now,
	}, nil
}

func (pool *ProductionAnonymousCredentialPool) AcquireAnonymousCredentialInventory(
	ctx context.Context,
	request AnonymousCredentialPoolRequest,
) (AnonymousCredentialPoolLease, error) {
	if pool == nil {
		return AnonymousCredentialPoolLease{},
			errors.New("production anonymous credential pool is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return AnonymousCredentialPoolLease{}, cause
	}
	now := pool.now().UTC()
	expectedRequest := cloneAnonymousCredentialPoolRequest(request)
	if err := validateCredentialPoolRequest(expectedRequest, now); err != nil {
		return AnonymousCredentialPoolLease{}, err
	}
	vaultRequest := cloneAnonymousCredentialPoolRequest(expectedRequest)
	reservation, vaultErr := pool.vault.ReserveAnonymousCredentials(
		ctx, vaultRequest,
	)
	reservation.Request = cloneAnonymousCredentialPoolRequest(
		reservation.Request,
	)
	reservation.ClassInventories = slices.Clone(
		reservation.ClassInventories,
	)
	reservation.Candidates = slices.Clone(reservation.Candidates)
	resources := reservationOwnedResources(reservation)
	if vaultErr != nil {
		return AnonymousCredentialPoolLease{}, errors.Join(
			fmt.Errorf(
				"reserve anonymous credential inventory: %w",
				vaultErr,
			),
			closeFailedPreparation(resources),
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return AnonymousCredentialPoolLease{}, errors.Join(
			cause, closeFailedPreparation(resources),
		)
	}
	now = pool.now().UTC()
	candidates, err := validateVaultReservation(
		reservation, expectedRequest, now,
	)
	if err != nil {
		return AnonymousCredentialPoolLease{}, errors.Join(
			err, closeFailedPreparation(resources),
		)
	}
	shared := newSharedAssemblyResources(resources)
	scoped := &productionAnonymousCredentialLeaser{
		expiresAt:  reservation.ExpiresAt.UTC(),
		candidates: candidates,
		shared:     shared,
		replay:     &credentialReplaySet{seen: make(map[string]struct{})},
		now:        pool.now,
	}
	return AnonymousCredentialPoolLease{
		Profile:                  expectedRequest.Profile,
		ControllerID:             expectedRequest.ControllerID,
		ManifestDigest:           expectedRequest.ManifestDigest,
		ManifestSequence:         expectedRequest.ManifestSequence,
		ObservedAt:               reservation.ObservedAt.UTC(),
		ExpiresAt:                reservation.ExpiresAt.UTC(),
		MinimumUnusedCredentials: expectedRequest.MinimumUnusedCredentials,
		UnusedCredentials:        reservation.UnusedCredentials,
		Requirements: cloneCredentialRequirements(
			expectedRequest.Requirements,
		),
		ClassInventories: slices.Clone(reservation.ClassInventories),
		Credentials:      scoped,
		Resource:         &sharedAssemblyReference{shared: shared},
	}, nil
}

type validatedCandidateReservation struct {
	requirement AnonymousCredentialRequirement
	source      carrier.AnonymousCredentialSource
	publicKey   *rsa.PublicKey
	acquired    bool
}

func validateCredentialPoolRequest(
	request AnonymousCredentialPoolRequest,
	now time.Time,
) error {
	if !identifierPattern.MatchString(request.Profile) ||
		!identifierPattern.MatchString(request.ControllerID) ||
		!digestPattern.MatchString(request.ManifestDigest) ||
		request.ManifestSequence == 0 ||
		!request.ExpiresAt.After(now) ||
		request.MinimumUnusedCredentials <
			Phase1MinimumUnusedCredentials ||
		request.MinimumUnusedCredentials > 1024 ||
		len(request.Requirements) > 1024 {
		return errors.New(
			"anonymous credential pool request is invalid",
		)
	}
	seen := make(map[string]struct{}, len(request.Requirements))
	for _, requirement := range request.Requirements {
		if !identifierPattern.MatchString(requirement.CandidateID) ||
			!identifierPattern.MatchString(requirement.NodeID) ||
			!digestPattern.MatchString(requirement.TokenKeyID) ||
			requirement.CredentialScope == "" ||
			requirement.IssuerDomain == "" ||
			requirement.Count !=
				MinimumReservedCredentialsPerH3 {
			return errors.New(
				"anonymous credential requirement is invalid",
			)
		}
		if _, duplicate := seen[requirement.CandidateID]; duplicate {
			return errors.New(
				"anonymous credential requirement candidate is duplicated",
			)
		}
		seen[requirement.CandidateID] = struct{}{}
		if _, err := validateCredentialRequirement(
			requirement, request.ExpiresAt, now,
		); err != nil {
			return err
		}
	}
	return nil
}

func validateVaultReservation(
	reservation PinnedAnonymousCredentialReservation,
	request AnonymousCredentialPoolRequest,
	now time.Time,
) (map[string]*validatedCandidateReservation, error) {
	if !reservation.Durable ||
		!reflect.DeepEqual(reservation.Request, request) ||
		!freshPoolObservation(reservation.ObservedAt, now) ||
		!reservation.ExpiresAt.After(now) ||
		reservation.ExpiresAt.After(request.ExpiresAt) ||
		reservation.UnusedCredentials < request.MinimumUnusedCredentials ||
		reservation.UnusedCredentials > 1024 ||
		!validCredentialClassInventories(
			reservation.ClassInventories,
			request.Requirements,
			request.MinimumUnusedCredentials,
			reservation.UnusedCredentials,
		) ||
		isNil(reservation.Resource) ||
		len(reservation.Candidates) != len(request.Requirements) {
		return nil, errors.New(
			"anonymous credential vault reservation differs from verified request",
		)
	}
	expected := make(
		map[string]AnonymousCredentialRequirement,
		len(request.Requirements),
	)
	publicKeys := make(map[string]*rsa.PublicKey, len(request.Requirements))
	for _, requirement := range request.Requirements {
		if _, duplicate := expected[requirement.CandidateID]; duplicate {
			return nil, errors.New(
				"anonymous credential requirement candidate is duplicated",
			)
		}
		publicKey, err := validateCredentialRequirement(
			requirement, reservation.ExpiresAt, now,
		)
		if err != nil {
			return nil, err
		}
		expected[requirement.CandidateID] = requirement
		publicKeys[requirement.CandidateID] = publicKey
	}
	result := make(
		map[string]*validatedCandidateReservation,
		len(reservation.Candidates),
	)
	for _, candidate := range reservation.Candidates {
		requirement, ok := expected[candidate.Requirement.CandidateID]
		if !ok ||
			!reflect.DeepEqual(candidate.Requirement, requirement) ||
			isNil(candidate.Source) ||
			isNil(candidate.Resource) {
			return nil, errors.New(
				"anonymous candidate reservation is not exact",
			)
		}
		if _, duplicate := result[requirement.CandidateID]; duplicate {
			return nil, errors.New(
				"anonymous candidate reservation is duplicated",
			)
		}
		result[requirement.CandidateID] =
			&validatedCandidateReservation{
				requirement: requirement,
				source:      candidate.Source,
				publicKey:   publicKeys[requirement.CandidateID],
			}
	}
	return result, nil
}

func validateCredentialRequirement(
	requirement AnonymousCredentialRequirement,
	reservationExpiresAt time.Time,
	now time.Time,
) (*rsa.PublicKey, error) {
	publicDER, err := base64.StdEncoding.Strict().DecodeString(
		requirement.IssuerPublicKey,
	)
	if err != nil {
		clear(publicDER)
		return nil, errors.New(
			"anonymous credential issuer public key is invalid",
		)
	}
	publicKey, parseErr := privacytoken.ParseIssuerPublicKeyDER(publicDER)
	clear(publicDER)
	if parseErr != nil {
		return nil, parseErr
	}
	keyID, err := privacytoken.IssuerKeyID(publicKey)
	if err != nil || keyID != requirement.TokenKeyID {
		return nil, errors.New(
			"anonymous credential issuer key ID is invalid",
		)
	}
	notBefore, beforeErr := time.Parse(
		time.RFC3339Nano, requirement.NotBefore,
	)
	notAfter, afterErr := time.Parse(
		time.RFC3339Nano, requirement.NotAfter,
	)
	if beforeErr != nil || afterErr != nil ||
		privacytoken.ValidateKeyWindow(
			notBefore, notAfter, now,
		) != nil ||
		reservationExpiresAt.After(notAfter) {
		return nil, errors.New(
			"anonymous credential issuer window is invalid",
		)
	}
	return publicKey, nil
}

type productionAnonymousCredentialLeaser struct {
	mu         sync.Mutex
	expiresAt  time.Time
	candidates map[string]*validatedCandidateReservation
	shared     *sharedAssemblyResources
	replay     *credentialReplaySet
	now        func() time.Time
}

func (leaser *productionAnonymousCredentialLeaser) AcquireAnonymousCredentials(
	ctx context.Context,
	request AnonymousCredentialRequest,
) (AnonymousCredentialLease, error) {
	if leaser == nil || leaser.shared == nil ||
		leaser.replay == nil || leaser.now == nil {
		return AnonymousCredentialLease{},
			errors.New("scoped anonymous credential leaser is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return AnonymousCredentialLease{}, cause
	}
	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	candidate := leaser.candidates[request.CandidateID]
	if candidate == nil ||
		candidate.acquired ||
		request.NodeID != candidate.requirement.NodeID ||
		request.TokenKeyID != candidate.requirement.TokenKeyID ||
		request.CredentialScope !=
			candidate.requirement.CredentialScope ||
		request.IssuerDomain != candidate.requirement.IssuerDomain ||
		request.MinimumCredential != candidate.requirement.Count ||
		!request.ExpiresAt.UTC().Equal(leaser.expiresAt) ||
		!leaser.expiresAt.After(leaser.now().UTC()) {
		return AnonymousCredentialLease{},
			errors.New(
				"anonymous credential sublease differs from pinned reservation",
			)
	}
	resource, err := leaser.shared.acquire()
	if err != nil {
		return AnonymousCredentialLease{}, err
	}
	candidate.acquired = true
	source := &verifyingAnonymousCredentialSource{
		source:     candidate.source,
		publicKey:  candidate.publicKey,
		tokenKeyID: candidate.requirement.TokenKeyID,
		limit:      candidate.requirement.Count,
		expiresAt:  leaser.expiresAt,
		replay:     leaser.replay,
		now:        leaser.now,
	}
	return AnonymousCredentialLease{
		CandidateID:     request.CandidateID,
		NodeID:          request.NodeID,
		TokenKeyID:      request.TokenKeyID,
		CredentialScope: request.CredentialScope,
		IssuerDomain:    request.IssuerDomain,
		ExpiresAt:       leaser.expiresAt,
		Count:           candidate.requirement.Count,
		Source:          source,
		Resource:        resource,
	}, nil
}

type verifyingAnonymousCredentialSource struct {
	mu         sync.Mutex
	source     carrier.AnonymousCredentialSource
	publicKey  *rsa.PublicKey
	tokenKeyID string
	limit      int
	taken      int
	expiresAt  time.Time
	replay     *credentialReplaySet
	now        func() time.Time
}

func (source *verifyingAnonymousCredentialSource) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.taken >= source.limit ||
		source.replay == nil ||
		source.now == nil ||
		!source.expiresAt.After(source.now().UTC()) {
		return carrier.AnonymousCredential{},
			errors.New("anonymous credential reservation is exhausted")
	}
	credential, err := source.source.NextAnonymousCredential()
	if err != nil {
		return carrier.AnonymousCredential{}, err
	}
	accepted := false
	defer func() {
		if !accepted {
			credential.Destroy()
		}
	}()
	source.taken++
	if credential.Signer == nil {
		return carrier.AnonymousCredential{},
			errors.New("anonymous credential signer is absent")
	}
	verified, err := privacytoken.Verify(
		credential.Token, source.publicKey, source.tokenKeyID,
	)
	if err != nil {
		return carrier.AnonymousCredential{}, err
	}
	publicBytes := credential.Signer.PublicBytes()
	matchesSigner := credential.Signer.Algorithm() ==
		verified.Payload.AuthAlgorithm &&
		base64.StdEncoding.EncodeToString(publicBytes) ==
			verified.Payload.AuthPublicKey
	clear(publicBytes)
	if !matchesSigner ||
		credential.Pseudonym != verified.Pseudonym {
		return carrier.AnonymousCredential{},
			errors.New(
				"anonymous credential proof key or pseudonym is invalid",
			)
	}
	if !source.replay.claim(verified.TokenID) {
		return carrier.AnonymousCredential{},
			errors.New("anonymous credential token is duplicated")
	}
	accepted = true
	return credential, nil
}

type credentialReplaySet struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func (set *credentialReplaySet) claim(tokenID string) bool {
	set.mu.Lock()
	defer set.mu.Unlock()
	if _, duplicate := set.seen[tokenID]; duplicate {
		return false
	}
	set.seen[tokenID] = struct{}{}
	return true
}

func reservationOwnedResources(
	reservation PinnedAnonymousCredentialReservation,
) []ownedResource {
	resources := []ownedResource{{
		name:     "anonymous credential vault reservation",
		resource: reservation.Resource,
	}}
	for _, candidate := range reservation.Candidates {
		resources = append(resources, ownedResource{
			name:     "anonymous candidate reservation",
			resource: candidate.Resource,
		})
	}
	return resources
}

func cloneCredentialRequirements(
	source []AnonymousCredentialRequirement,
) []AnonymousCredentialRequirement {
	return slices.Clone(source)
}

func cloneAnonymousCredentialPoolRequest(
	source AnonymousCredentialPoolRequest,
) AnonymousCredentialPoolRequest {
	source.Requirements = cloneCredentialRequirements(source.Requirements)
	return source
}

func isAllZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
