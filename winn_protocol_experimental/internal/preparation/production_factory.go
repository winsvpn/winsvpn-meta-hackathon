package preparation

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/gatewaymanifest"
)

const MinimumReservedCredentialsPerH3 = 3

// VerifiedDeploymentV2 is an immutable binding of one node returned by
// gatewaymanifest.LoadVerifiedNodeV2 to the exact signed-manifest digest.
// BindVerifiedDeploymentV2 does not replace signature, transparency, or
// rollback verification; callers must pass the outputs of that verifier.
type VerifiedDeploymentV2 struct {
	manifestDigest    string
	manifestExpiresAt time.Time
	manifestSequence  uint64
	controllerID      string
	nodeID            string
	transports        map[string]verifiedTransportV2
}

type verifiedTransportV2 struct {
	transport gatewaymanifest.TransportV2
	tokenKey  *gatewaymanifest.PrivacyTokenKey
}

// BindVerifiedDeploymentV2 snapshots verified facts and rejects a node or
// digest that does not belong to the supplied signed manifest.
func BindVerifiedDeploymentV2(
	manifest gatewaymanifest.ManifestV2,
	node gatewaymanifest.NodeV2,
	digest string,
) (VerifiedDeploymentV2, error) {
	// EncodeV2 performs full structural validation. Cryptographic and
	// transparency verification remain the caller's prerequisite.
	encoded, err := gatewaymanifest.EncodeV2(manifest)
	if err != nil {
		return VerifiedDeploymentV2{},
			fmt.Errorf("bind verified v2 deployment: %w", err)
	}
	clear(encoded)
	actualDigest, err := gatewaymanifest.DigestV2(manifest)
	if err != nil {
		return VerifiedDeploymentV2{}, err
	}
	if digest == "" || digest != actualDigest {
		return VerifiedDeploymentV2{},
			errors.New("verified deployment manifest digest mismatch")
	}
	actualNode, err := manifest.Node(node.ID)
	if err != nil {
		return VerifiedDeploymentV2{}, err
	}
	if !reflect.DeepEqual(actualNode, node) {
		return VerifiedDeploymentV2{},
			errors.New("verified deployment node differs from manifest")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
	if err != nil || expiresAt.Location() != time.UTC {
		return VerifiedDeploymentV2{},
			errors.New("verified deployment manifest expiry is invalid")
	}
	tokenKeys := make(
		map[string]gatewaymanifest.PrivacyTokenKey,
		len(manifest.PrivacyTokenKeys),
	)
	for _, key := range manifest.PrivacyTokenKeys {
		tokenKeys[key.ID] = key
	}
	transports := make(map[string]verifiedTransportV2, len(actualNode.Transports))
	for _, source := range actualNode.Transports {
		transport := cloneTransportV2(source)
		var tokenKey *gatewaymanifest.PrivacyTokenKey
		if transport.TokenKeyID != "" {
			key, ok := tokenKeys[transport.TokenKeyID]
			if !ok {
				return VerifiedDeploymentV2{},
					fmt.Errorf(
						"transport %q token key is absent",
						transport.ID,
					)
			}
			keyCopy := key
			tokenKey = &keyCopy
		}
		transports[transport.ID] = verifiedTransportV2{
			transport: transport,
			tokenKey:  tokenKey,
		}
	}
	return VerifiedDeploymentV2{
		manifestDigest:    actualDigest,
		manifestExpiresAt: expiresAt,
		manifestSequence:  manifest.Sequence,
		controllerID:      manifest.ControllerID,
		nodeID:            actualNode.ID,
		transports:        transports,
	}, nil
}

// HybridPSKLease pins the exact current AWG PSK generation for the prepared
// candidate lifetime. Resource must not expose raw key material.
type HybridPSKLease struct {
	Generation uint64
	ExpiresAt  time.Time
	Resource   Resource
}

type HybridPSKLeaser interface {
	AcquireHybridPSK(
		context.Context,
		uint64,
	) (HybridPSKLease, error)
}

type AnonymousCredentialRequest struct {
	CandidateID       string
	NodeID            string
	TokenKeyID        string
	CredentialScope   string
	IssuerDomain      string
	ExpiresAt         time.Time
	MinimumCredential int
}

// AnonymousCredentialLease pins a reservation whose source may be snapshotted
// by the H3 builder. At least three credentials are required: two independent
// one-time credentials for the adaptive fully authenticated preparation hedge
// and one for the later click-time connection. A suppressed or canceled hedge
// leaves its credential unused or durably consumed; it is never reassigned.
type AnonymousCredentialLease struct {
	CandidateID     string
	NodeID          string
	TokenKeyID      string
	CredentialScope string
	IssuerDomain    string
	ExpiresAt       time.Time
	Count           int
	Source          carrier.AnonymousCredentialSource
	Resource        Resource
}

type AnonymousCredentialLeaser interface {
	AcquireAnonymousCredentials(
		context.Context,
		AnonymousCredentialRequest,
	) (AnonymousCredentialLease, error)
}

// UnderlayPolicyAnchorRequest binds a preparation-time fail-closed policy
// reference to the exact verified H3 candidate that will consume it. The
// anchor must exist before the candidate's additional H3 socket mark is
// authorized.
type UnderlayPolicyAnchorRequest struct {
	CandidateID      string
	NodeID           string
	Carrier          connectivity.Carrier
	ManifestDigest   string
	ManifestSequence uint64
	SignedEndpoint   string
	ExpiresAt        time.Time
}

// UnderlayPolicyAnchorLease owns the persistent fail-closed policy reference
// that protects a cold H3 preparation. Resource must remain live until after
// the candidate builder and H3 mark authorization have both been closed.
type UnderlayPolicyAnchorLease struct {
	CandidateID           string
	NodeID                string
	Carrier               connectivity.Carrier
	ManifestDigest        string
	ManifestSequence      uint64
	SignedEndpoint        string
	AnchorID              string
	TableFamily           string
	TableName             string
	OutputChain           string
	InterfaceName         string
	DirectAWGFirewallMark uint32
	ExpiresAt             time.Time
	Resource              Resource
}

type UnderlayPolicyAnchorLeaser interface {
	AcquireUnderlayPolicyAnchor(
		context.Context,
		UnderlayPolicyAnchorRequest,
	) (UnderlayPolicyAnchorLease, error)
}

// UnderlayMarkAuthorizationRequest binds one pre-dial bypass authorization to
// the exact signed transport and preparation trust state. SignedEndpoint is a
// verified IP-literal endpoint or H3 endpoint template; it is never supplied
// by an unsigned runtime flag.
type UnderlayMarkAuthorizationRequest struct {
	CandidateID      string
	NodeID           string
	Carrier          connectivity.Carrier
	ManifestDigest   string
	ManifestSequence uint64
	SignedEndpoint   string
	ExpiresAt        time.Time
}

// UnderlayMarkAuthorizationLease is local privileged state. Builders may use
// its mark only while Resource remains owned by the prepared generation.
type UnderlayMarkAuthorizationLease struct {
	CandidateID      string
	NodeID           string
	Carrier          connectivity.Carrier
	ManifestDigest   string
	ManifestSequence uint64
	SignedEndpoint   string
	AuthorizationID  string
	InterfaceName    string
	FirewallMark     uint32
	ExpiresAt        time.Time
	Resource         Resource
}

type UnderlayMarkAuthorizationLeaser interface {
	AuthorizeUnderlayMark(
		context.Context,
		UnderlayMarkAuthorizationRequest,
	) (UnderlayMarkAuthorizationLease, error)
}

// UnderlayMarkAuthorization is the immutable, non-owning builder view. The
// enclosing PreparedCandidate resource owns the corresponding authorization
// lease and revokes it after builder resources are closed.
type UnderlayMarkAuthorization struct {
	AuthorizationID string
	InterfaceName   string
	FirewallMark    uint32
	ExpiresAt       time.Time
}

type DirectAWGPreparationInput struct {
	Context          CandidateContext
	ManifestSequence uint64
	ControllerID     string
	Suite            string
	Endpoint         string
	GatewayPublicKey string
	MinInnerDatagram int
	MaxInnerDatagram int
	Capabilities     []string
	UnderlayMark     UnderlayMarkAuthorization
}

type H3PreparationInput struct {
	Context              CandidateContext
	ManifestSequence     uint64
	ControllerID         string
	Suite                string
	EndpointTemplate     string
	ServerName           string
	IPv4Hints            []string
	IPv6Hints            []string
	ECHConfigList        []byte
	ALPN                 []string
	PublicTarget         string
	FixedBackend         string
	GatewayPublicKey     string
	MinInnerDatagram     int
	MaxInnerDatagram     int
	Capabilities         []string
	AuthorizationMode    string
	TokenKeyID           string
	CredentialScope      string
	IssuerDomain         string
	ReservedCredentials  int
	AnonymousCredentials carrier.AnonymousCredentialSource
	UnderlayMark         UnderlayMarkAuthorization
}

// CandidateBuild is the builder-owned preparation result. Resource must own
// all warm/probe state created by the builder.
type CandidateBuild struct {
	Candidate       connectivity.Candidate
	ProbeFreshUntil time.Time
	Warm            bool
	WarmUntil       time.Time
	Resource        Resource
}

type DirectAWGPreparationBuilder interface {
	PrepareDirectAWG(
		context.Context,
		DirectAWGPreparationInput,
	) (CandidateBuild, error)
}

// H3PreparationBuilder is deliberately narrow while concrete H3 warm-session
// construction is evolving. Implementations must snapshot the input before
// returning and must not use unsigned endpoint, ECH, auth-mode, or MTU flags.
type H3PreparationBuilder interface {
	PrepareH3(
		context.Context,
		H3PreparationInput,
	) (CandidateBuild, error)
}

type ProductionFactoryConfig struct {
	Deployments  []VerifiedDeploymentV2
	PSKs         HybridPSKLeaser
	Credentials  AnonymousCredentialLeaser
	PolicyAnchor UnderlayPolicyAnchorLeaser
	Underlay     UnderlayMarkAuthorizationLeaser
	DirectAWG    DirectAWGPreparationBuilder
	H3           H3PreparationBuilder
	// WaitForH3PolicyAnchor is required when DirectAWG and H3 are prepared
	// concurrently against the same fail-closed Linux policy. It prevents
	// the DirectAWG pre-dial authorization from observing the policy before
	// the H3-owned persistent anchor has installed it.
	WaitForH3PolicyAnchor bool
	Now                   func() time.Time
}

type productionCandidateFacts struct {
	manifestDigest    string
	manifestExpiresAt time.Time
	manifestSequence  uint64
	controllerID      string
	nodeID            string
	transport         gatewaymanifest.TransportV2
	tokenKey          *gatewaymanifest.PrivacyTokenKey
}

// ProductionFactory implements CandidatePreparer and admits only Direct AWG
// and H3 transports snapshotted from verified v2 deployments.
type ProductionFactory struct {
	candidates   map[string]productionCandidateFacts
	psks         HybridPSKLeaser
	credentials  AnonymousCredentialLeaser
	policyAnchor UnderlayPolicyAnchorLeaser
	underlay     UnderlayMarkAuthorizationLeaser
	directAWG    DirectAWGPreparationBuilder
	h3           H3PreparationBuilder
	now          func() time.Time

	waitForH3PolicyAnchor bool
	policyAnchorReady     chan struct{}
	policyAnchorOnce      sync.Once
	policyAnchorErr       error
}

var _ CandidatePreparer = (*ProductionFactory)(nil)

func NewProductionFactory(
	config ProductionFactoryConfig,
) (*ProductionFactory, error) {
	if len(config.Deployments) == 0 {
		return nil, errors.New("verified v2 deployments are required")
	}
	hasDirectAWG := false
	hasH3 := false
	if isNil(config.PSKs) || isNil(config.Credentials) ||
		isNil(config.PolicyAnchor) ||
		isNil(config.Underlay) ||
		isNil(config.DirectAWG) || isNil(config.H3) {
		return nil, errors.New(
			"production preparation leases and builders are required",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	candidates := make(map[string]productionCandidateFacts)
	for _, deployment := range config.Deployments {
		if deployment.manifestDigest == "" ||
			deployment.manifestExpiresAt.IsZero() ||
			deployment.manifestSequence == 0 ||
			deployment.controllerID == "" ||
			deployment.nodeID == "" ||
			len(deployment.transports) == 0 {
			return nil, errors.New("verified v2 deployment is incomplete")
		}
		for id, verified := range deployment.transports {
			if id == "" || verified.transport.ID != id {
				return nil, errors.New(
					"verified v2 transport identity is inconsistent",
				)
			}
			if _, duplicate := candidates[id]; duplicate {
				return nil, fmt.Errorf(
					"duplicate verified transport %q", id,
				)
			}
			candidates[id] = productionCandidateFacts{
				manifestDigest:    deployment.manifestDigest,
				manifestExpiresAt: deployment.manifestExpiresAt,
				manifestSequence:  deployment.manifestSequence,
				controllerID:      deployment.controllerID,
				nodeID:            deployment.nodeID,
				transport:         cloneTransportV2(verified.transport),
				tokenKey:          cloneTokenKey(verified.tokenKey),
			}
			switch verified.transport.Type {
			case connectivity.CarrierDirectAWG:
				hasDirectAWG = true
			case connectivity.CarrierHTTP3:
				hasH3 = true
			}
		}
	}
	if config.WaitForH3PolicyAnchor &&
		(!hasDirectAWG || !hasH3) {
		return nil, errors.New(
			"H3 policy-anchor barrier requires DirectAWG and H3 transports",
		)
	}
	var policyAnchorReady chan struct{}
	if config.WaitForH3PolicyAnchor {
		policyAnchorReady = make(chan struct{})
	}
	return &ProductionFactory{
		candidates:            candidates,
		psks:                  config.PSKs,
		credentials:           config.Credentials,
		policyAnchor:          config.PolicyAnchor,
		underlay:              config.Underlay,
		directAWG:             config.DirectAWG,
		h3:                    config.H3,
		now:                   config.Now,
		waitForH3PolicyAnchor: config.WaitForH3PolicyAnchor,
		policyAnchorReady:     policyAnchorReady,
	}, nil
}

func (factory *ProductionFactory) PrepareCandidate(
	ctx context.Context,
	candidateContext CandidateContext,
) (PreparedCandidate, error) {
	if factory == nil {
		return PreparedCandidate{}, errors.New(
			"production preparation factory is nil",
		)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return PreparedCandidate{}, cause
	}
	now := factory.now().UTC()
	candidateContext.ManifestExpiresAt =
		candidateContext.ManifestExpiresAt.UTC()
	candidateContext.PSKExpiresAt = candidateContext.PSKExpiresAt.UTC()
	candidateContext.Descriptor.ExpiresAt =
		candidateContext.Descriptor.ExpiresAt.UTC()
	facts, err := factory.validateContext(candidateContext, now)
	if err != nil {
		return PreparedCandidate{}, err
	}

	psk, err := factory.psks.AcquireHybridPSK(
		ctx, candidateContext.PSKGeneration,
	)
	pskEntry := ownedResource{name: "hybrid PSK lease", resource: psk.Resource}
	if err != nil {
		return PreparedCandidate{}, errors.Join(
			fmt.Errorf("acquire hybrid PSK lease: %w", err),
			closeFailedPreparation([]ownedResource{pskEntry}),
		)
	}
	if err := validateHybridPSKLease(psk, candidateContext, now); err != nil {
		return PreparedCandidate{}, errors.Join(
			err, closeFailedPreparation([]ownedResource{pskEntry}),
		)
	}
	resources := []ownedResource{pskEntry}
	var credentialExpiresAt time.Time
	var credential AnonymousCredentialLease

	switch facts.transport.Type {
	case connectivity.CarrierDirectAWG:
	case connectivity.CarrierHTTP3:
		credential, err = factory.acquireCredential(
			ctx, candidateContext, facts, now,
		)
		credentialExpiresAt = credential.ExpiresAt.UTC()
		credentialEntry := ownedResource{
			name:     "anonymous credential lease",
			resource: credential.Resource,
		}
		resources = append(resources, credentialEntry)
	default:
		err = fmt.Errorf(
			"verified transport %q carrier %q is not implemented",
			facts.transport.ID,
			facts.transport.Type,
		)
	}
	if err != nil {
		return PreparedCandidate{}, errors.Join(
			err, closeFailedPreparation(resources),
		)
	}

	var anchorExpiresAt time.Time
	var anchor UnderlayPolicyAnchorLease
	if facts.transport.Type == connectivity.CarrierHTTP3 {
		anchor, err = factory.acquirePolicyAnchor(
			ctx,
			candidateContext,
			facts,
			credentialExpiresAt,
			now,
		)
		factory.publishPolicyAnchorResult(err)
		anchorExpiresAt = anchor.ExpiresAt.UTC()
		anchorEntry := ownedResource{
			name:     "underlay policy anchor lease",
			resource: anchor.Resource,
		}
		resources = append(resources, anchorEntry)
		if err != nil {
			return PreparedCandidate{}, errors.Join(
				err, closeFailedPreparation(resources),
			)
		}
	}

	if facts.transport.Type == connectivity.CarrierDirectAWG {
		if err := factory.awaitPolicyAnchor(ctx); err != nil {
			return PreparedCandidate{}, errors.Join(
				err, closeFailedPreparation(resources),
			)
		}
	}
	underlay, err := factory.acquireUnderlayAuthorization(
		ctx,
		candidateContext,
		facts,
		credentialExpiresAt,
		now,
	)
	underlayEntry := ownedResource{
		name:     "underlay mark authorization lease",
		resource: underlay.Resource,
	}
	resources = append(resources, underlayEntry)
	if err != nil {
		return PreparedCandidate{}, errors.Join(
			err, closeFailedPreparation(resources),
		)
	}
	if facts.transport.Type == connectivity.CarrierHTTP3 {
		if err := validateAnchoredUnderlayAuthorization(
			anchor, underlay,
		); err != nil {
			return PreparedCandidate{}, errors.Join(
				err, closeFailedPreparation(resources),
			)
		}
	}
	underlayView := UnderlayMarkAuthorization{
		AuthorizationID: underlay.AuthorizationID,
		InterfaceName:   underlay.InterfaceName,
		FirewallMark:    underlay.FirewallMark,
		ExpiresAt:       underlay.ExpiresAt.UTC(),
	}

	var build CandidateBuild
	switch facts.transport.Type {
	case connectivity.CarrierDirectAWG:
		build, err = factory.directAWG.PrepareDirectAWG(
			ctx,
			mapDirectAWGInput(candidateContext, facts, underlayView),
		)
	case connectivity.CarrierHTTP3:
		var input H3PreparationInput
		input, err = mapH3Input(
			candidateContext, facts, credential, underlayView,
		)
		if err == nil {
			build, err = factory.h3.PrepareH3(ctx, input)
		}
	}
	if !isNil(build.Resource) {
		resources = append(resources, ownedResource{
			name: "candidate builder resource", resource: build.Resource,
		})
	}
	if err != nil {
		return PreparedCandidate{}, errors.Join(
			err, closeFailedPreparation(resources),
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return PreparedCandidate{}, errors.Join(
			cause, closeFailedPreparation(resources),
		)
	}
	evidenceLimit := minimumTime(
		candidateContext.Descriptor.ExpiresAt,
		candidateContext.ManifestExpiresAt,
		candidateContext.PSKExpiresAt,
	)
	if !credentialExpiresAt.IsZero() {
		evidenceLimit = minimumTime(
			evidenceLimit,
			credentialExpiresAt,
		)
	}
	if !anchorExpiresAt.IsZero() {
		evidenceLimit = minimumTime(evidenceLimit, anchorExpiresAt)
	}
	evidenceLimit = minimumTime(evidenceLimit, underlay.ExpiresAt.UTC())
	if err := validateCandidateBuild(
		build,
		candidateContext.Descriptor,
		now,
		evidenceLimit,
	); err != nil {
		return PreparedCandidate{}, errors.Join(
			err, closeFailedPreparation(resources),
		)
	}
	return PreparedCandidate{
		Candidate:       build.Candidate,
		ProbeFreshUntil: build.ProbeFreshUntil.UTC(),
		Warm:            build.Warm,
		WarmUntil:       build.WarmUntil.UTC(),
		Resource:        newOwnedResourceSet(resources),
	}, nil
}

func (factory *ProductionFactory) publishPolicyAnchorResult(err error) {
	if factory == nil || !factory.waitForH3PolicyAnchor {
		return
	}
	factory.policyAnchorOnce.Do(func() {
		factory.policyAnchorErr = err
		close(factory.policyAnchorReady)
	})
}

func (factory *ProductionFactory) awaitPolicyAnchor(
	ctx context.Context,
) error {
	if factory == nil || !factory.waitForH3PolicyAnchor {
		return nil
	}
	select {
	case <-factory.policyAnchorReady:
		if factory.policyAnchorErr != nil {
			return fmt.Errorf(
				"wait for H3 fail-closed policy anchor: %w",
				factory.policyAnchorErr,
			)
		}
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (factory *ProductionFactory) validateContext(
	current CandidateContext,
	now time.Time,
) (productionCandidateFacts, error) {
	if !identifierPattern.MatchString(current.Profile) ||
		!connectivity.ValidMode(current.Mode) ||
		!digestPattern.MatchString(current.ManifestDigest) ||
		current.PSKGeneration == 0 {
		return productionCandidateFacts{},
			errors.New("production candidate context is invalid")
	}
	if err := current.Descriptor.Validate(now); err != nil {
		return productionCandidateFacts{},
			fmt.Errorf("production candidate descriptor: %w", err)
	}
	if !modeAllows(current.Mode, current.Descriptor.Carrier) ||
		!current.ManifestExpiresAt.After(now) ||
		!current.PSKExpiresAt.After(now) ||
		current.Descriptor.ExpiresAt.After(current.ManifestExpiresAt) ||
		current.Descriptor.ExpiresAt.After(current.PSKExpiresAt) {
		return productionCandidateFacts{},
			errors.New("production candidate trust lifetime is invalid")
	}
	facts, ok := factory.candidates[current.Descriptor.ID]
	if !ok {
		return productionCandidateFacts{},
			fmt.Errorf(
				"candidate %q is absent from verified deployments",
				current.Descriptor.ID,
			)
	}
	if facts.nodeID != current.Descriptor.NodeID ||
		facts.transport.Type != current.Descriptor.Carrier ||
		facts.manifestDigest != current.ManifestDigest ||
		!facts.manifestExpiresAt.Equal(
			current.ManifestExpiresAt.UTC(),
		) {
		return productionCandidateFacts{},
			errors.New(
				"candidate context differs from verified deployment",
			)
	}
	return facts, nil
}

func validateHybridPSKLease(
	lease HybridPSKLease,
	current CandidateContext,
	now time.Time,
) error {
	if lease.Generation != current.PSKGeneration ||
		!lease.ExpiresAt.UTC().Equal(current.PSKExpiresAt.UTC()) ||
		!lease.ExpiresAt.After(now) ||
		isNil(lease.Resource) {
		return errors.New(
			"hybrid PSK lease differs from current preparation trust",
		)
	}
	return nil
}

func (factory *ProductionFactory) acquireCredential(
	ctx context.Context,
	current CandidateContext,
	facts productionCandidateFacts,
	now time.Time,
) (AnonymousCredentialLease, error) {
	if !slices.Contains(
		facts.transport.AuthenticationModes,
		gatewaymanifest.AuthAnonymousToken,
	) || facts.transport.TokenKeyID == "" || facts.tokenKey == nil {
		return AnonymousCredentialLease{},
			errors.New(
				"verified H3 transport lacks anonymous authorization",
			)
	}
	if facts.transport.Suite != "x25519-mlkem768" {
		return AnonymousCredentialLease{},
			errors.New(
				"production H3 preparation requires x25519-mlkem768",
			)
	}
	notBefore, err := time.Parse(
		time.RFC3339Nano, facts.tokenKey.NotBefore,
	)
	if err != nil {
		return AnonymousCredentialLease{},
			errors.New("verified credential not_before is invalid")
	}
	notAfter, err := time.Parse(
		time.RFC3339Nano, facts.tokenKey.NotAfter,
	)
	if err != nil || now.Before(notBefore) || !notAfter.After(now) {
		return AnonymousCredentialLease{},
			errors.New("verified credential key is not current")
	}
	expiresAt := minimumTime(
		current.Descriptor.ExpiresAt,
		current.ManifestExpiresAt,
		current.PSKExpiresAt,
		notAfter,
	).UTC()
	request := AnonymousCredentialRequest{
		CandidateID:       current.Descriptor.ID,
		NodeID:            current.Descriptor.NodeID,
		TokenKeyID:        facts.transport.TokenKeyID,
		CredentialScope:   facts.tokenKey.Scope,
		IssuerDomain:      facts.tokenKey.IssuerDomain,
		ExpiresAt:         expiresAt,
		MinimumCredential: MinimumReservedCredentialsPerH3,
	}
	lease, acquireErr := factory.credentials.AcquireAnonymousCredentials(
		ctx, request,
	)
	if acquireErr != nil {
		return lease, fmt.Errorf(
			"acquire anonymous credential lease: %w", acquireErr,
		)
	}
	if lease.CandidateID != request.CandidateID ||
		lease.NodeID != request.NodeID ||
		lease.TokenKeyID != request.TokenKeyID ||
		lease.CredentialScope != request.CredentialScope ||
		lease.IssuerDomain != request.IssuerDomain ||
		!lease.ExpiresAt.UTC().Equal(request.ExpiresAt) ||
		lease.Count < request.MinimumCredential ||
		isNil(lease.Source) ||
		isNil(lease.Resource) {
		return lease, errors.New(
			"anonymous credential lease differs from verified request",
		)
	}
	return lease, nil
}

func (factory *ProductionFactory) acquirePolicyAnchor(
	ctx context.Context,
	current CandidateContext,
	facts productionCandidateFacts,
	credentialExpiresAt time.Time,
	now time.Time,
) (UnderlayPolicyAnchorLease, error) {
	expiresAt := minimumTime(
		current.Descriptor.ExpiresAt,
		current.ManifestExpiresAt,
		current.PSKExpiresAt,
	)
	if !credentialExpiresAt.IsZero() {
		expiresAt = minimumTime(expiresAt, credentialExpiresAt)
	}
	request := UnderlayPolicyAnchorRequest{
		CandidateID:      current.Descriptor.ID,
		NodeID:           current.Descriptor.NodeID,
		Carrier:          current.Descriptor.Carrier,
		ManifestDigest:   current.ManifestDigest,
		ManifestSequence: facts.manifestSequence,
		SignedEndpoint:   facts.transport.Endpoint,
		ExpiresAt:        expiresAt.UTC(),
	}
	lease, acquireErr := factory.policyAnchor.AcquireUnderlayPolicyAnchor(
		ctx, request,
	)
	if acquireErr != nil {
		return lease, fmt.Errorf(
			"acquire pre-dial underlay policy anchor: %w", acquireErr,
		)
	}
	if lease.CandidateID != request.CandidateID ||
		lease.NodeID != request.NodeID ||
		lease.Carrier != request.Carrier ||
		lease.ManifestDigest != request.ManifestDigest ||
		lease.ManifestSequence != request.ManifestSequence ||
		lease.SignedEndpoint != request.SignedEndpoint ||
		!lease.ExpiresAt.UTC().Equal(request.ExpiresAt) ||
		!lease.ExpiresAt.After(now) ||
		!identifierPattern.MatchString(lease.AnchorID) ||
		lease.TableFamily != "inet" ||
		!validNftIdentifier(lease.TableName) ||
		lease.OutputChain != "output" ||
		!validUnderlayInterfaceName(lease.InterfaceName) ||
		lease.DirectAWGFirewallMark == 0 ||
		isNil(lease.Resource) {
		return lease, errors.New(
			"underlay policy anchor differs from verified request",
		)
	}
	return lease, nil
}

func (factory *ProductionFactory) acquireUnderlayAuthorization(
	ctx context.Context,
	current CandidateContext,
	facts productionCandidateFacts,
	credentialExpiresAt time.Time,
	now time.Time,
) (UnderlayMarkAuthorizationLease, error) {
	expiresAt := minimumTime(
		current.Descriptor.ExpiresAt,
		current.ManifestExpiresAt,
		current.PSKExpiresAt,
	)
	if !credentialExpiresAt.IsZero() {
		expiresAt = minimumTime(expiresAt, credentialExpiresAt)
	}
	request := UnderlayMarkAuthorizationRequest{
		CandidateID:      current.Descriptor.ID,
		NodeID:           current.Descriptor.NodeID,
		Carrier:          current.Descriptor.Carrier,
		ManifestDigest:   current.ManifestDigest,
		ManifestSequence: facts.manifestSequence,
		SignedEndpoint:   facts.transport.Endpoint,
		ExpiresAt:        expiresAt.UTC(),
	}
	lease, acquireErr := factory.underlay.AuthorizeUnderlayMark(ctx, request)
	if acquireErr != nil {
		return lease, fmt.Errorf(
			"authorize pre-dial underlay mark: %w", acquireErr,
		)
	}
	if lease.CandidateID != request.CandidateID ||
		lease.NodeID != request.NodeID ||
		lease.Carrier != request.Carrier ||
		lease.ManifestDigest != request.ManifestDigest ||
		lease.ManifestSequence != request.ManifestSequence ||
		lease.SignedEndpoint != request.SignedEndpoint ||
		!lease.ExpiresAt.UTC().Equal(request.ExpiresAt) ||
		!lease.ExpiresAt.After(now) ||
		!identifierPattern.MatchString(lease.AuthorizationID) ||
		!validUnderlayInterfaceName(lease.InterfaceName) ||
		lease.FirewallMark == 0 ||
		isNil(lease.Resource) {
		return lease, errors.New(
			"underlay mark authorization differs from verified request",
		)
	}
	return lease, nil
}

func validateAnchoredUnderlayAuthorization(
	anchor UnderlayPolicyAnchorLease,
	authorization UnderlayMarkAuthorizationLease,
) error {
	if anchor.InterfaceName != authorization.InterfaceName ||
		!anchor.ExpiresAt.UTC().Equal(authorization.ExpiresAt.UTC()) ||
		anchor.DirectAWGFirewallMark == authorization.FirewallMark {
		return errors.New(
			"underlay mark authorization differs from its policy anchor",
		)
	}
	return nil
}

func mapDirectAWGInput(
	current CandidateContext,
	facts productionCandidateFacts,
	underlay UnderlayMarkAuthorization,
) DirectAWGPreparationInput {
	return DirectAWGPreparationInput{
		Context:          current,
		ManifestSequence: facts.manifestSequence,
		ControllerID:     facts.controllerID,
		Suite:            facts.transport.Suite,
		Endpoint:         facts.transport.Endpoint,
		GatewayPublicKey: facts.transport.PublicAWGKey,
		MinInnerDatagram: facts.transport.MinInnerDatagram,
		MaxInnerDatagram: facts.transport.MaxInnerDatagram,
		Capabilities:     slices.Clone(facts.transport.Capabilities),
		UnderlayMark:     underlay,
	}
}

func mapH3Input(
	current CandidateContext,
	facts productionCandidateFacts,
	credential AnonymousCredentialLease,
	underlay UnderlayMarkAuthorization,
) (H3PreparationInput, error) {
	ech, err := base64.StdEncoding.Strict().DecodeString(
		facts.transport.ECHConfigList,
	)
	if err != nil || len(ech) == 0 {
		clear(ech)
		return H3PreparationInput{},
			errors.New("verified H3 ECH config is invalid")
	}
	return H3PreparationInput{
		Context:              current,
		ManifestSequence:     facts.manifestSequence,
		ControllerID:         facts.controllerID,
		Suite:                facts.transport.Suite,
		EndpointTemplate:     facts.transport.Endpoint,
		ServerName:           facts.transport.ServerName,
		IPv4Hints:            slices.Clone(facts.transport.IPv4Hints),
		IPv6Hints:            slices.Clone(facts.transport.IPv6Hints),
		ECHConfigList:        ech,
		ALPN:                 slices.Clone(facts.transport.ALPN),
		PublicTarget:         facts.transport.PublicTarget,
		FixedBackend:         facts.transport.FixedBackend,
		GatewayPublicKey:     facts.transport.PublicAWGKey,
		MinInnerDatagram:     facts.transport.MinInnerDatagram,
		MaxInnerDatagram:     facts.transport.MaxInnerDatagram,
		Capabilities:         slices.Clone(facts.transport.Capabilities),
		AuthorizationMode:    gatewaymanifest.AuthAnonymousToken,
		TokenKeyID:           facts.transport.TokenKeyID,
		CredentialScope:      credential.CredentialScope,
		IssuerDomain:         credential.IssuerDomain,
		ReservedCredentials:  credential.Count,
		AnonymousCredentials: credential.Source,
		UnderlayMark:         underlay,
	}, nil
}

func validUnderlayInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') &&
			(current < 'A' || current > 'Z') &&
			(current < '0' || current > '9') &&
			current != '_' && current != '-' && current != '.' {
			return false
		}
	}
	return true
}

func validateCandidateBuild(
	build CandidateBuild,
	descriptor connectivity.CandidateDescriptor,
	now time.Time,
	evidenceLimit time.Time,
) error {
	if isNil(build.Candidate) ||
		build.Candidate.Descriptor() != descriptor ||
		isNil(build.Resource) {
		return errors.New(
			"production builder returned inconsistent candidate ownership",
		)
	}
	build.ProbeFreshUntil = build.ProbeFreshUntil.UTC()
	build.WarmUntil = build.WarmUntil.UTC()
	if !build.ProbeFreshUntil.After(now) ||
		build.ProbeFreshUntil.After(evidenceLimit) {
		return errors.New(
			"production builder probe evidence exceeds trust lifetime",
		)
	}
	if build.Warm {
		if !build.WarmUntil.After(now) ||
			build.WarmUntil.After(evidenceLimit) ||
			build.WarmUntil.After(now.Add(maxWarmAge)) {
			return errors.New(
				"production builder warm state exceeds trust lifetime",
			)
		}
	} else if !build.WarmUntil.IsZero() {
		return errors.New(
			"production builder returned cold state with warm expiry",
		)
	}
	return nil
}

type ownedResource struct {
	name     string
	resource Resource
}

type ownedResourceSet struct {
	resources []ownedResource

	mu      sync.Mutex
	closing bool
	closed  bool
	done    chan struct{}
	err     error
}

func newOwnedResourceSet(resources []ownedResource) *ownedResourceSet {
	return &ownedResourceSet{
		resources: slices.Clone(resources),
		done:      make(chan struct{}),
	}
}

func (resources *ownedResourceSet) Close(ctx context.Context) error {
	if resources == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	resources.mu.Lock()
	if resources.closed {
		err := resources.err
		resources.mu.Unlock()
		return err
	}
	if resources.closing {
		done := resources.done
		resources.mu.Unlock()
		select {
		case <-done:
			resources.mu.Lock()
			err := resources.err
			resources.mu.Unlock()
			return err
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	resources.closing = true
	resources.mu.Unlock()

	err := closeOwnedResources(ctx, resources.resources)
	resources.mu.Lock()
	resources.err = err
	resources.closed = true
	close(resources.done)
	resources.mu.Unlock()
	return err
}

func closeFailedPreparation(resources []ownedResource) error {
	if len(resources) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), defaultCloseTimeout,
	)
	defer cancel()
	return closeOwnedResources(ctx, resources)
}

func closeOwnedResources(
	ctx context.Context,
	resources []ownedResource,
) error {
	var closeErrors []error
	for index := len(resources) - 1; index >= 0; index-- {
		current := resources[index]
		if isNil(current.resource) {
			continue
		}
		if err := current.resource.Close(ctx); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf(
				"close %s: %w", current.name, err,
			))
		}
	}
	return errors.Join(closeErrors...)
}

func cloneTransportV2(
	source gatewaymanifest.TransportV2,
) gatewaymanifest.TransportV2 {
	source.IPv4Hints = slices.Clone(source.IPv4Hints)
	source.IPv6Hints = slices.Clone(source.IPv6Hints)
	source.ALPN = slices.Clone(source.ALPN)
	source.AuthenticationModes = slices.Clone(source.AuthenticationModes)
	source.Capabilities = slices.Clone(source.Capabilities)
	return source
}

func cloneTokenKey(
	source *gatewaymanifest.PrivacyTokenKey,
) *gatewaymanifest.PrivacyTokenKey {
	if source == nil {
		return nil
	}
	result := *source
	return &result
}
