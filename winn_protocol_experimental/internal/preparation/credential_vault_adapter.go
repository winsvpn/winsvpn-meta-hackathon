package preparation

import (
	"context"
	"errors"
	"sync"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/state"
)

// EncryptedAnonymousCredentialVault adapts state.CredentialVault's encrypted,
// process-locked two-phase reservations to the production preparation pool.
type EncryptedAnonymousCredentialVault struct {
	vault *state.CredentialVault
}

var _ AtomicAnonymousCredentialVault = (*EncryptedAnonymousCredentialVault)(nil)

func NewEncryptedAnonymousCredentialVault(
	vault *state.CredentialVault,
) (*EncryptedAnonymousCredentialVault, error) {
	if vault == nil {
		return nil, errors.New(
			"encrypted anonymous credential vault is required",
		)
	}
	return &EncryptedAnonymousCredentialVault{vault: vault}, nil
}

func (adapter *EncryptedAnonymousCredentialVault) ReserveAnonymousCredentials(
	ctx context.Context,
	request AnonymousCredentialPoolRequest,
) (PinnedAnonymousCredentialReservation, error) {
	if adapter == nil || adapter.vault == nil {
		return PinnedAnonymousCredentialReservation{},
			errors.New(
				"encrypted anonymous credential vault is unavailable",
			)
	}
	vaultRequest := mapCredentialVaultRequest(request)
	reservation, err := adapter.vault.BeginReservation(
		ctx, vaultRequest,
	)
	if err != nil {
		return PinnedAnonymousCredentialReservation{}, err
	}
	root := &credentialVaultReservationResource{
		vault: adapter.vault,
		id:    reservation.ID,
	}
	candidates := make(
		[]PinnedAnonymousCandidateReservation,
		len(reservation.Candidates),
	)
	sources := make([]*credentialVaultSource, len(candidates))
	for index, candidate := range reservation.Candidates {
		source := &credentialVaultSource{
			vault:       adapter.vault,
			reservation: reservation.ID,
			candidate:   candidate.Requirement.CandidateID,
			active: make(
				map[*credentialSignerResource]struct{},
			),
		}
		sources[index] = source
		candidates[index] = PinnedAnonymousCandidateReservation{
			Requirement: mapCredentialRequirementFromState(
				candidate.Requirement,
			),
			Source:   source,
			Resource: &credentialVaultSourceResource{source: source},
		}
	}
	root.sources = sources
	if err := adapter.vault.CommitReservation(
		ctx, reservation.ID,
	); err != nil {
		return PinnedAnonymousCredentialReservation{}, errors.Join(
			err, closeFailedPreparation(
				reservationAdapterResources(root, candidates),
			),
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return PinnedAnonymousCredentialReservation{}, errors.Join(
			cause,
			closeFailedPreparation(
				reservationAdapterResources(root, candidates),
			),
		)
	}
	inventories := make(
		[]AnonymousCredentialClassInventory,
		len(reservation.ClassInventories),
	)
	for index, inventory := range reservation.ClassInventories {
		inventories[index] = AnonymousCredentialClassInventory{
			TokenKeyID:        inventory.Class.TokenKeyID,
			CredentialScope:   inventory.Class.Scope,
			IssuerDomain:      inventory.Class.IssuerDomain,
			UnusedCredentials: inventory.UnusedCredentials,
		}
	}
	return PinnedAnonymousCredentialReservation{
		Request:           request,
		ObservedAt:        reservation.ObservedAt,
		ExpiresAt:         reservation.ExpiresAt,
		UnusedCredentials: reservation.UnusedCredentials,
		ClassInventories:  inventories,
		Candidates:        candidates,
		Durable:           true,
		Resource:          root,
	}, nil
}

type credentialVaultReservationResource struct {
	once    sync.Once
	vault   *state.CredentialVault
	id      string
	sources []*credentialVaultSource
	err     error
}

func (resource *credentialVaultReservationResource) Close(
	ctx context.Context,
) error {
	if resource == nil {
		return nil
	}
	resource.once.Do(func() {
		for _, source := range resource.sources {
			source.destroy()
		}
		resource.err = resource.vault.ReleaseReservation(
			nonNilContext(ctx), resource.id,
		)
	})
	return resource.err
}

type credentialVaultSourceResource struct {
	once   sync.Once
	source *credentialVaultSource
}

func (resource *credentialVaultSourceResource) Close(
	_ context.Context,
) error {
	if resource == nil {
		return nil
	}
	resource.once.Do(func() {
		resource.source.destroy()
	})
	return nil
}

type credentialVaultSource struct {
	mu          sync.Mutex
	vault       *state.CredentialVault
	reservation string
	candidate   string
	active      map[*credentialSignerResource]struct{}
	closed      bool
}

var _ carrier.AnonymousCredentialSource = (*credentialVaultSource)(nil)

func (source *credentialVaultSource) NextAnonymousCredential() (
	carrier.AnonymousCredential,
	error,
) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed {
		return carrier.AnonymousCredential{},
			errors.New("credential vault source is closed")
	}
	taken, err := source.vault.TakeCredential(
		context.Background(),
		source.reservation,
		source.candidate,
	)
	if err != nil {
		return carrier.AnonymousCredential{}, err
	}
	resource := &credentialSignerResource{
		signer: taken.Signer,
		owner:  source,
	}
	source.active[resource] = struct{}{}
	return carrier.AnonymousCredential{
		Pseudonym: taken.Pseudonym,
		Signer:    taken.Signer,
		Token:     taken.Token,
		Resource:  resource,
	}, nil
}

func (source *credentialVaultSource) destroy() {
	if source == nil {
		return
	}
	source.mu.Lock()
	if source.closed {
		source.mu.Unlock()
		return
	}
	source.closed = true
	resources := make(
		[]*credentialSignerResource, 0, len(source.active),
	)
	for resource := range source.active {
		resources = append(resources, resource)
	}
	source.active = nil
	source.mu.Unlock()
	for _, resource := range resources {
		resource.Destroy()
	}
}

func (source *credentialVaultSource) forget(
	resource *credentialSignerResource,
) {
	source.mu.Lock()
	delete(source.active, resource)
	source.mu.Unlock()
}

type credentialSignerResource struct {
	once   sync.Once
	signer interface {
		Destroy()
	}
	owner *credentialVaultSource
}

func (resource *credentialSignerResource) Destroy() {
	if resource == nil {
		return
	}
	resource.once.Do(func() {
		resource.signer.Destroy()
		resource.signer = nil
		owner := resource.owner
		resource.owner = nil
		owner.forget(resource)
	})
}

func mapCredentialVaultRequest(
	request AnonymousCredentialPoolRequest,
) state.CredentialReservationRequest {
	requirements := make(
		[]state.CredentialRequirement,
		len(request.Requirements),
	)
	for index, requirement := range request.Requirements {
		requirements[index] = mapCredentialRequirementToState(
			requirement,
		)
	}
	return state.CredentialReservationRequest{
		Profile:                  request.Profile,
		ControllerID:             request.ControllerID,
		ManifestDigest:           request.ManifestDigest,
		ManifestSequence:         request.ManifestSequence,
		ExpiresAt:                request.ExpiresAt,
		MinimumUnusedCredentials: request.MinimumUnusedCredentials,
		Requirements:             requirements,
	}
}

func mapCredentialRequirementToState(
	requirement AnonymousCredentialRequirement,
) state.CredentialRequirement {
	return state.CredentialRequirement{
		CandidateID: requirement.CandidateID,
		NodeID:      requirement.NodeID,
		Class: state.CredentialClassBinding{
			TokenKeyID:      requirement.TokenKeyID,
			Scope:           requirement.CredentialScope,
			IssuerDomain:    requirement.IssuerDomain,
			IssuerPublicKey: requirement.IssuerPublicKey,
			NotBefore:       requirement.NotBefore,
			NotAfter:        requirement.NotAfter,
		},
		Count: requirement.Count,
	}
}

func mapCredentialRequirementFromState(
	requirement state.CredentialRequirement,
) AnonymousCredentialRequirement {
	return AnonymousCredentialRequirement{
		CandidateID:     requirement.CandidateID,
		NodeID:          requirement.NodeID,
		TokenKeyID:      requirement.Class.TokenKeyID,
		CredentialScope: requirement.Class.Scope,
		IssuerDomain:    requirement.Class.IssuerDomain,
		IssuerPublicKey: requirement.Class.IssuerPublicKey,
		NotBefore:       requirement.Class.NotBefore,
		NotAfter:        requirement.Class.NotAfter,
		Count:           requirement.Count,
	}
}

func reservationAdapterResources(
	root Resource,
	candidates []PinnedAnonymousCandidateReservation,
) []ownedResource {
	resources := []ownedResource{{
		name:     "encrypted credential reservation",
		resource: root,
	}}
	for _, candidate := range candidates {
		resources = append(resources, ownedResource{
			name:     "encrypted credential candidate",
			resource: candidate.Resource,
		})
	}
	return resources
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil || context.Cause(ctx) != nil {
		return context.Background()
	}
	return ctx
}
