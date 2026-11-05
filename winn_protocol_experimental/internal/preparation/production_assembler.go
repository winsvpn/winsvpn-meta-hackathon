package preparation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
)

const maximumPoolObservationAge = 5 * time.Second

// HybridPSKPoolRequest asks a production key pool to pin its current
// generation. The returned scoped leaser must reject every other generation.
type HybridPSKPoolRequest struct {
	Profile           string
	ControllerID      string
	ManifestDigest    string
	ManifestSequence  uint64
	ManifestExpiresAt time.Time
}

// HybridPSKPoolLease pins the current generation while the assembled
// preparation generation exists.
type HybridPSKPoolLease struct {
	Profile           string
	ControllerID      string
	ManifestDigest    string
	ManifestSequence  uint64
	ManifestExpiresAt time.Time
	ObservedAt        time.Time
	Generation        uint64
	ExpiresAt         time.Time
	PSKs              HybridPSKLeaser
	Resource          Resource
}

type HybridPSKPool interface {
	AcquireCurrentHybridPSK(
		context.Context,
		HybridPSKPoolRequest,
	) (HybridPSKPoolLease, error)
}

// AnonymousCredentialRequirement is derived entirely from one selected signed
// H3 transport. Count is atomically reserved by the inventory lease.
type AnonymousCredentialRequirement struct {
	CandidateID     string
	NodeID          string
	TokenKeyID      string
	CredentialScope string
	IssuerDomain    string
	IssuerPublicKey string
	NotBefore       string
	NotAfter        string
	Count           int
}

type AnonymousCredentialPoolRequest struct {
	Profile                  string
	ControllerID             string
	ManifestDigest           string
	ManifestSequence         uint64
	ExpiresAt                time.Time
	MinimumUnusedCredentials int
	Requirements             []AnonymousCredentialRequirement
}

type AnonymousCredentialClassInventory struct {
	TokenKeyID        string
	CredentialScope   string
	IssuerDomain      string
	UnusedCredentials int
}

// AnonymousCredentialPoolLease atomically owns all Requirements and reports
// the exact unused count remaining after those reservations for every eligible
// credential class. UnusedCredentials is the minimum of ClassInventories and
// therefore the conservative readiness value. Credentials is a scoped
// sub-leaser that may hand each reservation to ProductionFactory without
// changing those pinned remaining counts.
type AnonymousCredentialPoolLease struct {
	Profile                  string
	ControllerID             string
	ManifestDigest           string
	ManifestSequence         uint64
	ObservedAt               time.Time
	ExpiresAt                time.Time
	MinimumUnusedCredentials int
	UnusedCredentials        int
	Requirements             []AnonymousCredentialRequirement
	ClassInventories         []AnonymousCredentialClassInventory
	Credentials              AnonymousCredentialLeaser
	Resource                 Resource
}

type AnonymousCredentialPool interface {
	AcquireAnonymousCredentialInventory(
		context.Context,
		AnonymousCredentialPoolRequest,
	) (AnonymousCredentialPoolLease, error)
}

type VerifiedPreparationAssemblerConfig struct {
	Deployments    []VerifiedDeploymentV2
	PSKPool        HybridPSKPool
	CredentialPool AnonymousCredentialPool
	PolicyAnchor   UnderlayPolicyAnchorLeaser
	Underlay       UnderlayMarkAuthorizationLeaser
	DirectAWG      DirectAWGPreparationBuilder
	H3             H3PreparationBuilder
	Policy         Policy
	MaxParallel    int
	CloseTimeout   time.Duration
	Now            func() time.Time
}

// VerifiedAssemblyRequest contains only local selection and policy choices.
// Manifest, PSK, endpoint, token-key, and inventory facts are derived from
// pinned verified deployments and production pools.
type VerifiedAssemblyRequest struct {
	Profile                  string
	Mode                     connectivity.Mode
	CandidateIDs             []string
	MinimumUnusedCredentials int
	ReadinessTTL             time.Duration
	RequiredCarriers         []connectivity.Carrier
	RequiredWarmCarriers     []connectivity.Carrier
	// PreconnectIdentity is populated only after a true-cold user operation
	// begins. The assembler still derives every trust and candidate field from
	// verified deployment state.
	PreconnectIdentity PreconnectIdentity
}

// PreparedAssembly is one immutable, already-prepared generation. It does not
// expose Manager.Prepare, so its verified request cannot be replaced with
// caller-authored manifest, PSK, or inventory facts.
type PreparedAssembly struct {
	manager *Manager
	request Request
}

func (assembly *PreparedAssembly) Request() Request {
	if assembly == nil {
		return Request{}
	}
	return cloneRequest(assembly.request)
}

func (assembly *PreparedAssembly) Acquire() (*Lease, error) {
	if assembly == nil || assembly.manager == nil {
		return nil, ErrNotReady
	}
	return assembly.manager.Acquire()
}

func (assembly *PreparedAssembly) Status() (Snapshot, bool) {
	if assembly == nil || assembly.manager == nil {
		return Snapshot{}, false
	}
	return assembly.manager.Status()
}

func (assembly *PreparedAssembly) Close(ctx context.Context) error {
	if assembly == nil || assembly.manager == nil {
		return nil
	}
	return assembly.manager.Close(ctx)
}

type VerifiedPreparationAssembler struct {
	deployments    []VerifiedDeploymentV2
	candidates     map[string]productionCandidateFacts
	manifestDigest string
	manifestExpiry time.Time
	sequence       uint64
	controllerID   string
	pskPool        HybridPSKPool
	credentialPool AnonymousCredentialPool
	policyAnchor   UnderlayPolicyAnchorLeaser
	underlay       UnderlayMarkAuthorizationLeaser
	directAWG      DirectAWGPreparationBuilder
	h3             H3PreparationBuilder
	policy         Policy
	maxParallel    int
	closeTimeout   time.Duration
	now            func() time.Time
}

func NewVerifiedPreparationAssembler(
	config VerifiedPreparationAssemblerConfig,
) (*VerifiedPreparationAssembler, error) {
	if len(config.Deployments) == 0 {
		return nil, errors.New("verified deployments are required")
	}
	if isNil(config.PSKPool) ||
		isNil(config.CredentialPool) ||
		isNil(config.PolicyAnchor) ||
		isNil(config.Underlay) ||
		isNil(config.DirectAWG) ||
		isNil(config.H3) {
		return nil, errors.New(
			"production preparation pools, underlay, and builders are required",
		)
	}
	if config.MaxParallel < 0 ||
		config.MaxParallel > connectivity.MaxCandidates {
		return nil, errors.New("assembly parallelism is invalid")
	}
	if config.CloseTimeout < 0 {
		return nil, errors.New("assembly close timeout is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}

	deployments := make([]VerifiedDeploymentV2, len(config.Deployments))
	candidates := make(map[string]productionCandidateFacts)
	var manifestDigest string
	var manifestExpiry time.Time
	var sequence uint64
	var controllerID string
	for index, source := range config.Deployments {
		deployment, err := cloneVerifiedDeployment(source)
		if err != nil {
			return nil, err
		}
		if index == 0 {
			manifestDigest = deployment.manifestDigest
			manifestExpiry = deployment.manifestExpiresAt.UTC()
			sequence = deployment.manifestSequence
			controllerID = deployment.controllerID
		} else if deployment.manifestDigest != manifestDigest ||
			!deployment.manifestExpiresAt.Equal(manifestExpiry) ||
			deployment.manifestSequence != sequence ||
			deployment.controllerID != controllerID {
			return nil, errors.New(
				"verified deployments do not share one manifest",
			)
		}
		deployments[index] = deployment
		for id, verified := range deployment.transports {
			if _, duplicate := candidates[id]; duplicate {
				return nil, fmt.Errorf(
					"duplicate verified transport %q", id,
				)
			}
			candidates[id] = productionCandidateFacts{
				manifestDigest:    manifestDigest,
				manifestExpiresAt: manifestExpiry,
				manifestSequence:  sequence,
				controllerID:      controllerID,
				nodeID:            deployment.nodeID,
				transport:         cloneTransportV2(verified.transport),
				tokenKey:          cloneTokenKey(verified.tokenKey),
			}
		}
	}
	return &VerifiedPreparationAssembler{
		deployments:    deployments,
		candidates:     candidates,
		manifestDigest: manifestDigest,
		manifestExpiry: manifestExpiry,
		sequence:       sequence,
		controllerID:   controllerID,
		pskPool:        config.PSKPool,
		credentialPool: config.CredentialPool,
		policyAnchor:   config.PolicyAnchor,
		underlay:       config.Underlay,
		directAWG:      config.DirectAWG,
		h3:             config.H3,
		policy:         config.Policy,
		maxParallel:    config.MaxParallel,
		closeTimeout:   config.CloseTimeout,
		now:            config.Now,
	}, nil
}

// Assemble pins current pool state, derives a Manager request from verified
// facts, prepares every candidate, and transfers pool-lease ownership to that
// prepared generation.
func (assembler *VerifiedPreparationAssembler) Assemble(
	ctx context.Context,
	request VerifiedAssemblyRequest,
) (*PreparedAssembly, error) {
	if assembler == nil {
		return nil, errors.New("verified preparation assembler is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	now := assembler.now().UTC()
	selection, requirements, err := assembler.validateSelection(request, now)
	if err != nil {
		return nil, err
	}

	pskRequest := HybridPSKPoolRequest{
		Profile:           request.Profile,
		ControllerID:      assembler.controllerID,
		ManifestDigest:    assembler.manifestDigest,
		ManifestSequence:  assembler.sequence,
		ManifestExpiresAt: assembler.manifestExpiry,
	}
	psk, err := assembler.pskPool.AcquireCurrentHybridPSK(ctx, pskRequest)
	pskResource := ownedResource{
		name: "pinned hybrid PSK pool lease", resource: psk.Resource,
	}
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("pin current hybrid PSK pool: %w", err),
			closeFailedPreparation([]ownedResource{pskResource}),
		)
	}
	now = assembler.now().UTC()
	if err := validateHybridPSKPoolLease(
		psk, pskRequest, now,
	); err != nil {
		return nil, errors.Join(
			err, closeFailedPreparation([]ownedResource{pskResource}),
		)
	}

	inventoryRequest := AnonymousCredentialPoolRequest{
		Profile:                  request.Profile,
		ControllerID:             assembler.controllerID,
		ManifestDigest:           assembler.manifestDigest,
		ManifestSequence:         assembler.sequence,
		ExpiresAt:                minimumTime(assembler.manifestExpiry, psk.ExpiresAt).UTC(),
		MinimumUnusedCredentials: request.MinimumUnusedCredentials,
		Requirements:             slices.Clone(requirements),
	}
	inventory, err := assembler.credentialPool.
		AcquireAnonymousCredentialInventory(ctx, inventoryRequest)
	inventoryResource := ownedResource{
		name:     "pinned anonymous credential inventory",
		resource: inventory.Resource,
	}
	poolResources := []ownedResource{pskResource, inventoryResource}
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("pin anonymous credential inventory: %w", err),
			closeFailedPreparation(poolResources),
		)
	}
	now = assembler.now().UTC()
	if err := validateAnonymousCredentialPoolLease(
		inventory, inventoryRequest, now,
	); err != nil {
		return nil, errors.Join(
			err, closeFailedPreparation(poolResources),
		)
	}

	trustExpiresAt := minimumTime(
		assembler.manifestExpiry,
		psk.ExpiresAt.UTC(),
		inventory.ExpiresAt.UTC(),
	)
	candidates := make(
		[]connectivity.CandidateDescriptor, len(selection),
	)
	for index, facts := range selection {
		candidates[index] = connectivity.CandidateDescriptor{
			ID:        facts.transport.ID,
			Carrier:   facts.transport.Type,
			NodeID:    facts.nodeID,
			ExpiresAt: trustExpiresAt,
		}
	}
	factory, err := NewProductionFactory(ProductionFactoryConfig{
		Deployments:  assembler.deployments,
		PSKs:         psk.PSKs,
		Credentials:  inventory.Credentials,
		PolicyAnchor: assembler.policyAnchor,
		Underlay:     assembler.underlay,
		DirectAWG:    assembler.directAWG,
		H3:           assembler.h3,
		WaitForH3PolicyAnchor: selectionContainsCarrier(
			selection, connectivity.CarrierDirectAWG,
		) && selectionContainsCarrier(
			selection, connectivity.CarrierHTTP3,
		),
		Now: assembler.now,
	})
	if err != nil {
		return nil, errors.Join(
			err, closeFailedPreparation(poolResources),
		)
	}
	shared := newSharedAssemblyResources(poolResources)
	factoryWithPools := &poolOwningFactory{
		factory: factory,
		pools:   shared,
	}
	manager, err := NewManager(Config{
		Factory:      factoryWithPools,
		Policy:       assembler.policy,
		MaxParallel:  assembler.maxParallel,
		CloseTimeout: assembler.closeTimeout,
		Now:          assembler.now,
	})
	if err != nil {
		return nil, errors.Join(err, shared.releaseRoot())
	}
	managerRequest := Request{
		Profile:                  request.Profile,
		Mode:                     request.Mode,
		ManifestDigest:           assembler.manifestDigest,
		ManifestExpiresAt:        assembler.manifestExpiry,
		PSKGeneration:            psk.Generation,
		PSKExpiresAt:             psk.ExpiresAt.UTC(),
		UnusedCredentials:        inventory.UnusedCredentials,
		MinimumUnusedCredentials: request.MinimumUnusedCredentials,
		ReadinessTTL:             request.ReadinessTTL,
		Candidates:               candidates,
		RequiredCarriers:         slices.Clone(request.RequiredCarriers),
		RequiredWarmCarriers:     slices.Clone(request.RequiredWarmCarriers),
		PreconnectIdentity:       request.PreconnectIdentity,
	}
	prepareErr := manager.Prepare(ctx, managerRequest)
	rootErr := shared.releaseRoot()
	if prepareErr != nil || rootErr != nil {
		closeErr := manager.Close(context.Background())
		return nil, errors.Join(prepareErr, rootErr, closeErr)
	}
	return &PreparedAssembly{
		manager: manager,
		request: cloneRequest(managerRequest),
	}, nil
}

func selectionContainsCarrier(
	selection []productionCandidateFacts,
	carrier connectivity.Carrier,
) bool {
	for _, current := range selection {
		if current.transport.Type == carrier {
			return true
		}
	}
	return false
}

func (assembler *VerifiedPreparationAssembler) validateSelection(
	request VerifiedAssemblyRequest,
	now time.Time,
) ([]productionCandidateFacts, []AnonymousCredentialRequirement, error) {
	if !identifierPattern.MatchString(request.Profile) ||
		!connectivity.ValidMode(request.Mode) ||
		len(request.CandidateIDs) == 0 ||
		len(request.CandidateIDs) > connectivity.MaxCandidates ||
		request.MinimumUnusedCredentials <
			Phase1MinimumUnusedCredentials ||
		request.MinimumUnusedCredentials > 1024 ||
		request.ReadinessTTL <= 0 ||
		request.ReadinessTTL > connectivity.DefaultReadinessTTL ||
		!assembler.manifestExpiry.After(now) {
		return nil, nil, errors.New("verified assembly request is invalid")
	}
	if request.PreconnectIdentity.active() {
		if !request.PreconnectIdentity.ExpiresAt.After(now) ||
			request.PreconnectIdentity.ExpiresAt.After(
				assembler.manifestExpiry,
			) {
			return nil, nil, errors.New(
				"verified cold preconnect identity is expired or outlives manifest",
			)
		}
	} else if request.PreconnectIdentity != (PreconnectIdentity{}) {
		return nil, nil, errors.New(
			"verified cold preconnect identity is incomplete",
		)
	}
	selection := make(
		[]productionCandidateFacts, 0, len(request.CandidateIDs),
	)
	requirements := make(
		[]AnonymousCredentialRequirement, 0, len(request.CandidateIDs),
	)
	seen := make(map[string]struct{}, len(request.CandidateIDs))
	for _, id := range request.CandidateIDs {
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, fmt.Errorf(
				"duplicate assembly candidate %q", id,
			)
		}
		seen[id] = struct{}{}
		facts, ok := assembler.candidates[id]
		if !ok {
			return nil, nil, fmt.Errorf(
				"assembly candidate %q is not verified", id,
			)
		}
		if !modeAllows(request.Mode, facts.transport.Type) {
			return nil, nil, fmt.Errorf(
				"mode %q does not allow verified carrier %q",
				request.Mode,
				facts.transport.Type,
			)
		}
		switch facts.transport.Type {
		case connectivity.CarrierDirectAWG:
		case connectivity.CarrierHTTP3:
			if !slices.Contains(
				facts.transport.AuthenticationModes,
				gatewaymanifest.AuthAnonymousToken,
			) || facts.transport.TokenKeyID == "" ||
				facts.tokenKey == nil {
				return nil, nil, errors.New(
					"verified H3 selection lacks anonymous credentials",
				)
			}
			requirements = append(
				requirements,
				AnonymousCredentialRequirement{
					CandidateID:     facts.transport.ID,
					NodeID:          facts.nodeID,
					TokenKeyID:      facts.transport.TokenKeyID,
					CredentialScope: facts.tokenKey.Scope,
					IssuerDomain:    facts.tokenKey.IssuerDomain,
					IssuerPublicKey: facts.tokenKey.PublicKey,
					NotBefore:       facts.tokenKey.NotBefore,
					NotAfter:        facts.tokenKey.NotAfter,
					Count:           MinimumReservedCredentialsPerH3,
				},
			)
		default:
			return nil, nil, fmt.Errorf(
				"verified carrier %q is not implemented by assembler",
				facts.transport.Type,
			)
		}
		selection = append(selection, facts)
	}
	return selection, requirements, nil
}

func validateHybridPSKPoolLease(
	lease HybridPSKPoolLease,
	request HybridPSKPoolRequest,
	now time.Time,
) error {
	if lease.Profile != request.Profile ||
		lease.ControllerID != request.ControllerID ||
		lease.ManifestDigest != request.ManifestDigest ||
		lease.ManifestSequence != request.ManifestSequence ||
		!lease.ManifestExpiresAt.UTC().Equal(request.ManifestExpiresAt) ||
		lease.Generation == 0 ||
		!lease.ExpiresAt.After(now) ||
		lease.ExpiresAt.After(request.ManifestExpiresAt) ||
		!freshPoolObservation(lease.ObservedAt, now) ||
		isNil(lease.PSKs) ||
		isNil(lease.Resource) {
		return errors.New(
			"hybrid PSK pool lease differs from verified deployment",
		)
	}
	return nil
}

func validateAnonymousCredentialPoolLease(
	lease AnonymousCredentialPoolLease,
	request AnonymousCredentialPoolRequest,
	now time.Time,
) error {
	if lease.Profile != request.Profile ||
		lease.ControllerID != request.ControllerID ||
		lease.ManifestDigest != request.ManifestDigest ||
		lease.ManifestSequence != request.ManifestSequence ||
		!lease.ExpiresAt.After(now) ||
		lease.ExpiresAt.After(request.ExpiresAt) ||
		lease.MinimumUnusedCredentials !=
			request.MinimumUnusedCredentials ||
		lease.UnusedCredentials < request.MinimumUnusedCredentials ||
		lease.UnusedCredentials > 1024 ||
		!reflect.DeepEqual(lease.Requirements, request.Requirements) ||
		!validCredentialClassInventories(
			lease.ClassInventories,
			request.Requirements,
			lease.MinimumUnusedCredentials,
			lease.UnusedCredentials,
		) ||
		!freshPoolObservation(lease.ObservedAt, now) ||
		isNil(lease.Credentials) ||
		isNil(lease.Resource) {
		return errors.New(
			"anonymous credential inventory differs from verified request",
		)
	}
	return nil
}

func validCredentialClassInventories(
	inventories []AnonymousCredentialClassInventory,
	requirements []AnonymousCredentialRequirement,
	minimum int,
	reported int,
) bool {
	type credentialClass struct {
		tokenKeyID string
		scope      string
		issuer     string
	}
	required := make(map[credentialClass]struct{})
	for _, requirement := range requirements {
		if requirement.Count < MinimumReservedCredentialsPerH3 {
			return false
		}
		required[credentialClass{
			tokenKeyID: requirement.TokenKeyID,
			scope:      requirement.CredentialScope,
			issuer:     requirement.IssuerDomain,
		}] = struct{}{}
	}
	if len(required) == 0 {
		return len(inventories) == 0 && reported >= minimum
	}
	if len(inventories) != len(required) {
		return false
	}
	seen := make(map[credentialClass]struct{}, len(inventories))
	floor := 1025
	for _, inventory := range inventories {
		current := credentialClass{
			tokenKeyID: inventory.TokenKeyID,
			scope:      inventory.CredentialScope,
			issuer:     inventory.IssuerDomain,
		}
		if _, ok := required[current]; !ok {
			return false
		}
		if _, duplicate := seen[current]; duplicate ||
			inventory.UnusedCredentials < minimum ||
			inventory.UnusedCredentials > 1024 {
			return false
		}
		seen[current] = struct{}{}
		if inventory.UnusedCredentials < floor {
			floor = inventory.UnusedCredentials
		}
	}
	return reported == floor
}

func freshPoolObservation(observedAt time.Time, now time.Time) bool {
	observedAt = observedAt.UTC()
	return !observedAt.IsZero() &&
		!observedAt.After(now) &&
		now.Sub(observedAt) <= maximumPoolObservationAge
}

func cloneVerifiedDeployment(
	source VerifiedDeploymentV2,
) (VerifiedDeploymentV2, error) {
	if source.manifestDigest == "" ||
		source.manifestExpiresAt.IsZero() ||
		source.manifestSequence == 0 ||
		source.controllerID == "" ||
		source.nodeID == "" ||
		len(source.transports) == 0 {
		return VerifiedDeploymentV2{},
			errors.New("verified deployment is incomplete")
	}
	transports := make(
		map[string]verifiedTransportV2, len(source.transports),
	)
	for id, verified := range source.transports {
		if id == "" || verified.transport.ID != id {
			return VerifiedDeploymentV2{},
				errors.New("verified transport identity is inconsistent")
		}
		transports[id] = verifiedTransportV2{
			transport: cloneTransportV2(verified.transport),
			tokenKey:  cloneTokenKey(verified.tokenKey),
		}
	}
	return VerifiedDeploymentV2{
		manifestDigest:    source.manifestDigest,
		manifestExpiresAt: source.manifestExpiresAt.UTC(),
		manifestSequence:  source.manifestSequence,
		controllerID:      source.controllerID,
		nodeID:            source.nodeID,
		transports:        transports,
	}, nil
}

// poolOwningFactory gives every successful candidate a reference to the
// pinned pool leases. The root reference is retained until Manager.Prepare
// finishes, so one failed parallel candidate cannot revoke another's pools.
type poolOwningFactory struct {
	factory CandidatePreparer
	pools   *sharedAssemblyResources
}

func (factory *poolOwningFactory) PrepareCandidate(
	ctx context.Context,
	current CandidateContext,
) (PreparedCandidate, error) {
	poolReference, err := factory.pools.acquire()
	if err != nil {
		return PreparedCandidate{}, err
	}
	prepared, err := factory.factory.PrepareCandidate(ctx, current)
	if err != nil {
		return PreparedCandidate{}, errors.Join(
			err, poolReference.Close(context.Background()),
		)
	}
	prepared.Resource = newOwnedResourceSet([]ownedResource{
		{name: "pinned preparation pools", resource: poolReference},
		{name: "prepared candidate", resource: prepared.Resource},
	})
	return prepared, nil
}

type sharedAssemblyResources struct {
	mu        sync.Mutex
	resources []ownedResource
	refs      int
	closed    bool
	err       error
}

func newSharedAssemblyResources(
	resources []ownedResource,
) *sharedAssemblyResources {
	return &sharedAssemblyResources{
		resources: slices.Clone(resources),
		refs:      1,
	}
}

func (shared *sharedAssemblyResources) acquire() (Resource, error) {
	shared.mu.Lock()
	defer shared.mu.Unlock()
	if shared.closed || shared.refs == 0 {
		return nil, errors.New("preparation pool leases are closed")
	}
	shared.refs++
	return &sharedAssemblyReference{shared: shared}, nil
}

func (shared *sharedAssemblyResources) releaseRoot() error {
	ctx, cancel := context.WithTimeout(
		context.Background(), defaultCloseTimeout,
	)
	defer cancel()
	return shared.release(ctx)
}

func (shared *sharedAssemblyResources) release(ctx context.Context) error {
	shared.mu.Lock()
	if shared.refs == 0 {
		err := shared.err
		shared.mu.Unlock()
		return err
	}
	shared.refs--
	if shared.refs != 0 {
		shared.mu.Unlock()
		return nil
	}
	shared.closed = true
	shared.mu.Unlock()

	err := closeOwnedResources(ctx, shared.resources)
	shared.mu.Lock()
	shared.err = err
	shared.mu.Unlock()
	return err
}

type sharedAssemblyReference struct {
	shared *sharedAssemblyResources
	once   sync.Once
	err    error
}

func (reference *sharedAssemblyReference) Close(ctx context.Context) error {
	if reference == nil || reference.shared == nil {
		return nil
	}
	reference.once.Do(func() {
		reference.err = reference.shared.release(ctx)
	})
	return reference.err
}

var (
	_ CandidatePreparer = (*poolOwningFactory)(nil)
	_ Resource          = (*sharedAssemblyReference)(nil)
)
