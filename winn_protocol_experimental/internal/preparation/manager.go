// Package preparation owns Winn v3's background preparation generations.
//
// A generation is published only after every requested carrier has produced a
// prepared candidate with fresh probe evidence. Callers acquire a lease before
// handing its immutable snapshot to the click-time connectivity coordinator.
// Replacing a generation first prevents new leases, waits for existing leases,
// and disposes every generation-owned resource.
package preparation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	defaultCloseTimeout = 5 * time.Second
	maxWarmAge          = 10 * time.Minute
)

var (
	ErrClosed     = errors.New("preparation manager is closed")
	ErrNotReady   = errors.New("no valid prepared generation is available")
	ErrSuperseded = errors.New("preparation was superseded")

	identifierPattern = regexp.MustCompile(
		`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`,
	)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Resource owns the background state associated with one prepared candidate,
// such as a protected socket, probe session, credential reservation, or warm
// carrier. Close must be idempotent.
type Resource interface {
	Close(context.Context) error
}

// PreparedCandidate is the result of background carrier preparation. Candidate
// remains dormant until its Dial method is called by the connectivity
// coordinator. Resource owns every background object that must be released
// when this generation is retired.
type PreparedCandidate struct {
	Candidate       connectivity.Candidate
	ProbeFreshUntil time.Time
	Warm            bool
	WarmUntil       time.Time
	Resource        Resource
}

// CandidateContext is an immutable copy of the trust and profile facts a
// candidate factory may use while preparing one descriptor.
type CandidateContext struct {
	Profile           string
	Mode              connectivity.Mode
	ManifestDigest    string
	ManifestExpiresAt time.Time
	PSKGeneration     uint64
	PSKExpiresAt      time.Time
	Descriptor        connectivity.CandidateDescriptor
	// PreconnectBinding is nonzero only for a true-cold attempt whose user
	// action has already allocated the final immutable connectivity identity
	// and hard deadline. A candidate may use it to perform click-bound work
	// during cold preparation. Background/warm preparation must leave it zero.
	PreconnectBinding connectivity.Binding
}

// CandidatePreparer converts a verified descriptor into one production
// candidate and its generation-owned background resource.
type CandidatePreparer interface {
	PrepareCandidate(context.Context, CandidateContext) (PreparedCandidate, error)
}

// Request describes one complete preparation generation. Candidate order is
// retained because it may encode a caller's preference, while required carrier
// collections are treated as sets.
type Request struct {
	Profile                  string
	Mode                     connectivity.Mode
	ManifestDigest           string
	ManifestExpiresAt        time.Time
	PSKGeneration            uint64
	PSKExpiresAt             time.Time
	UnusedCredentials        int
	MinimumUnusedCredentials int
	ReadinessTTL             time.Duration
	Candidates               []connectivity.CandidateDescriptor
	RequiredCarriers         []connectivity.Carrier
	RequiredWarmCarriers     []connectivity.Carrier
	PreconnectIdentity       PreconnectIdentity
}

// PreconnectIdentity reserves one final click identity at the beginning of a
// true-cold operation. It deliberately omits candidate facts; Manager derives
// a distinct immutable Binding for each verified descriptor. The zero value
// means ordinary background preparation.
type PreconnectIdentity struct {
	AttemptID     string
	SessionID     string
	SequenceEpoch uint64
	Nonce         string
	ExpiresAt     time.Time
}

func (identity PreconnectIdentity) active() bool {
	return identity != (PreconnectIdentity{})
}

func (identity PreconnectIdentity) binding(
	request Request,
	descriptor connectivity.CandidateDescriptor,
) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      identity.AttemptID,
		Profile:        request.Profile,
		Mode:           request.Mode,
		ManifestDigest: request.ManifestDigest,
		CandidateID:    descriptor.ID,
		NodeID:         descriptor.NodeID,
		SessionID:      identity.SessionID,
		PSKGeneration:  request.PSKGeneration,
		SequenceEpoch:  identity.SequenceEpoch,
		Nonce:          identity.Nonce,
		ExpiresAt:      identity.ExpiresAt.UTC(),
	}
}

func preconnectBinding(
	request Request,
	descriptor connectivity.CandidateDescriptor,
) connectivity.Binding {
	if !request.PreconnectIdentity.active() {
		return connectivity.Binding{}
	}
	return request.PreconnectIdentity.binding(request, descriptor)
}

// CandidateState carries the freshness facts that connectivity.Readiness does
// not yet expose. It is immutable once its generation is published.
type CandidateState struct {
	Descriptor      connectivity.CandidateDescriptor
	ProbeFreshUntil time.Time
	Warm            bool
	WarmUntil       time.Time
}

// Snapshot is an immutable prepared generation. Its accessors return copies.
type Snapshot struct {
	fingerprint string
	readiness   connectivity.Readiness
	candidates  []connectivity.Candidate
	states      []CandidateState
	preconnect  PreconnectIdentity
}

func (snapshot Snapshot) Fingerprint() string {
	return snapshot.fingerprint
}

func (snapshot Snapshot) Readiness() connectivity.Readiness {
	readiness := snapshot.readiness
	readiness.Candidates = slices.Clone(snapshot.readiness.Candidates)
	readiness.Blockers = slices.Clone(snapshot.readiness.Blockers)
	return readiness
}

func (snapshot Snapshot) Candidates() []connectivity.Candidate {
	return slices.Clone(snapshot.candidates)
}

func (snapshot Snapshot) CandidateStates() []CandidateState {
	return slices.Clone(snapshot.states)
}

// Valid reports whether every trust, descriptor, probe, and warm-carrier fact
// required by this prepared generation remains current.
func (snapshot Snapshot) Valid(now time.Time) bool {
	now = now.UTC()
	readiness := snapshot.readiness
	if snapshot.fingerprint == "" ||
		readiness.PreparedAt.IsZero() ||
		readiness.PreparedAt.After(now) ||
		!readiness.ExpiresAt.After(now) ||
		!readiness.ManifestExpiresAt.After(now) ||
		!readiness.PSKExpiresAt.After(now) ||
		len(readiness.Blockers) != 0 ||
		len(snapshot.candidates) == 0 ||
		len(snapshot.candidates) != len(readiness.Candidates) ||
		len(snapshot.states) != len(readiness.Candidates) {
		return false
	}
	for index, state := range snapshot.states {
		if state.Descriptor != readiness.Candidates[index] ||
			!state.Descriptor.ExpiresAt.After(now) ||
			!state.ProbeFreshUntil.After(now) {
			return false
		}
		if state.Warm {
			if !state.WarmUntil.After(now) {
				return false
			}
		} else if !state.WarmUntil.IsZero() {
			return false
		}
		candidate := snapshot.candidates[index]
		if isNil(candidate) ||
			candidate.Descriptor() != state.Descriptor {
			return false
		}
	}
	return true
}

// ConnectRequest creates a defensive click-time copy. It never performs
// preparation and therefore cannot extend the coordinator's three-second
// deadline.
func (snapshot Snapshot) ConnectRequest(
	sessionID string,
	sequenceEpoch uint64,
	deadline time.Duration,
) (connectivity.ConnectRequest, error) {
	if !snapshot.Valid(time.Now().UTC()) {
		return connectivity.ConnectRequest{}, ErrNotReady
	}
	if !sessionPattern.MatchString(sessionID) || sequenceEpoch == 0 {
		return connectivity.ConnectRequest{},
			errors.New("connection session and sequence epoch are required")
	}
	if deadline < 0 || deadline > connectivity.MaxDeadline {
		return connectivity.ConnectRequest{},
			errors.New("connection deadline is invalid")
	}
	if snapshot.preconnect.active() &&
		(sessionID != snapshot.preconnect.SessionID ||
			sequenceEpoch != snapshot.preconnect.SequenceEpoch) {
		return connectivity.ConnectRequest{},
			errors.New("connection identity differs from cold reservation")
	}
	var attemptID, nonce string
	var reservedBindings []connectivity.Binding
	if snapshot.preconnect.active() {
		attemptID = snapshot.preconnect.AttemptID
		nonce = snapshot.preconnect.Nonce
		reservedBindings = make(
			[]connectivity.Binding,
			len(snapshot.readiness.Candidates),
		)
		requestFacts := Request{
			Profile:            snapshot.readiness.Profile,
			Mode:               snapshot.readiness.Mode,
			ManifestDigest:     snapshot.readiness.ManifestDigest,
			PSKGeneration:      snapshot.readiness.PSKGeneration,
			PreconnectIdentity: snapshot.preconnect,
		}
		for index, descriptor := range snapshot.readiness.Candidates {
			reservedBindings[index] = snapshot.preconnect.binding(
				requestFacts,
				descriptor,
			)
		}
	}
	return connectivity.ConnectRequest{
		Readiness:        snapshot.Readiness(),
		Candidates:       snapshot.Candidates(),
		SessionID:        sessionID,
		SequenceEpoch:    sequenceEpoch,
		Deadline:         deadline,
		AttemptID:        attemptID,
		Nonce:            nonce,
		ReservedBindings: reservedBindings,
	}, nil
}

// Policy performs deployment- or mode-specific validation before any current
// generation is disturbed.
type Policy func(Request) error

type Config struct {
	Factory      CandidatePreparer
	Policy       Policy
	MaxParallel  int
	CloseTimeout time.Duration
	Now          func() time.Time
}

type build struct {
	fingerprint string
	cancel      context.CancelCauseFunc
	done        chan struct{}
	err         error
}

type generation struct {
	snapshot  Snapshot
	resources []Resource
	refs      int
	retiring  bool
	zero      chan struct{}
}

type Manager struct {
	mu           sync.Mutex
	operation    chan struct{}
	factory      CandidatePreparer
	policy       Policy
	maxParallel  int
	closeTimeout time.Duration
	now          func() time.Time
	current      *generation
	active       *build
	closed       bool
}

func NewManager(config Config) (*Manager, error) {
	if isNil(config.Factory) {
		return nil, errors.New("candidate preparer is required")
	}
	if config.MaxParallel == 0 {
		config.MaxParallel = connectivity.MaxCandidates
	}
	if config.MaxParallel < 1 ||
		config.MaxParallel > connectivity.MaxCandidates {
		return nil, fmt.Errorf(
			"maximum preparation parallelism must be between 1 and %d",
			connectivity.MaxCandidates,
		)
	}
	if config.CloseTimeout == 0 {
		config.CloseTimeout = defaultCloseTimeout
	}
	if config.CloseTimeout < 0 {
		return nil, errors.New("close timeout must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	manager := &Manager{
		operation:    make(chan struct{}, 1),
		factory:      config.Factory,
		policy:       config.Policy,
		maxParallel:  config.MaxParallel,
		closeTimeout: config.CloseTimeout,
		now:          config.Now,
	}
	manager.operation <- struct{}{}
	return manager, nil
}

// Prepare is idempotent for an already-current generation and coalesces
// identical concurrent work. A different request cancels an in-flight build.
func (manager *Manager) Prepare(ctx context.Context, request Request) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := manager.now().UTC()
	normalized, fingerprint, err := normalizeRequest(request, now)
	if err != nil {
		return err
	}
	if manager.policy != nil {
		if err := manager.policy(cloneRequest(normalized)); err != nil {
			return fmt.Errorf("preparation policy: %w", err)
		}
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}

	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return ErrClosed
	}
	if manager.active != nil {
		active := manager.active
		if active.fingerprint == fingerprint {
			manager.mu.Unlock()
			return waitForBuild(ctx, active)
		}
		active.cancel(ErrSuperseded)
	} else if manager.current != nil &&
		!manager.current.retiring &&
		manager.current.snapshot.fingerprint == fingerprint &&
		manager.current.snapshot.Valid(now) {
		manager.mu.Unlock()
		return nil
	}
	manager.mu.Unlock()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-manager.operation:
	}
	defer func() { manager.operation <- struct{}{} }()

	// Another caller may have completed equivalent work while this caller was
	// waiting for the serial transition token.
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return ErrClosed
	}
	if manager.current != nil &&
		!manager.current.retiring &&
		manager.current.snapshot.fingerprint == fingerprint &&
		manager.current.snapshot.Valid(manager.now().UTC()) {
		manager.mu.Unlock()
		return nil
	}
	operationContext, cancel := context.WithCancelCause(ctx)
	active := &build{
		fingerprint: fingerprint,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	manager.active = active
	manager.mu.Unlock()

	err = manager.replace(operationContext, normalized, fingerprint)
	cancel(err)

	manager.mu.Lock()
	active.err = err
	if manager.active == active {
		manager.active = nil
	}
	close(active.done)
	manager.mu.Unlock()
	return err
}

func (manager *Manager) replace(
	ctx context.Context,
	request Request,
	fingerprint string,
) error {
	if err := manager.retireCurrent(ctx); err != nil {
		return err
	}
	snapshot, resources, err := manager.buildGeneration(
		ctx, request, fingerprint,
	)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return errors.Join(
			ErrClosed,
			manager.releaseResources(resources),
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		manager.mu.Unlock()
		return errors.Join(
			cause,
			manager.releaseResources(resources),
		)
	}
	zero := make(chan struct{})
	close(zero)
	manager.current = &generation{
		snapshot:  snapshot,
		resources: resources,
		zero:      zero,
	}
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) buildGeneration(
	ctx context.Context,
	request Request,
	fingerprint string,
) (Snapshot, []Resource, error) {
	buildContext, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	type result struct {
		index    int
		prepared PreparedCandidate
		err      error
	}
	results := make(chan result, len(request.Candidates))
	semaphore := make(chan struct{}, manager.maxParallel)
	for index, descriptor := range request.Candidates {
		go func(index int, descriptor connectivity.CandidateDescriptor) {
			select {
			case semaphore <- struct{}{}:
			case <-buildContext.Done():
				results <- result{index: index, err: context.Cause(buildContext)}
				return
			}
			defer func() { <-semaphore }()
			prepared, err := manager.factory.PrepareCandidate(
				buildContext,
				CandidateContext{
					Profile:           request.Profile,
					Mode:              request.Mode,
					ManifestDigest:    request.ManifestDigest,
					ManifestExpiresAt: request.ManifestExpiresAt,
					PSKGeneration:     request.PSKGeneration,
					PSKExpiresAt:      request.PSKExpiresAt,
					Descriptor:        descriptor,
					PreconnectBinding: preconnectBinding(
						request,
						descriptor,
					),
				},
			)
			if err != nil {
				cancel(err)
			}
			results <- result{
				index: index, prepared: prepared, err: err,
			}
		}(index, descriptor)
	}

	prepared := make([]PreparedCandidate, len(request.Candidates))
	var buildErrors []error
	for range request.Candidates {
		result := <-results
		prepared[result.index] = result.prepared
		if result.err != nil {
			buildErrors = append(buildErrors, result.err)
		}
	}
	resources := collectResources(prepared)
	if len(buildErrors) != 0 {
		return Snapshot{}, nil, errors.Join(
			append(buildErrors, manager.releaseResources(resources))...,
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return Snapshot{}, nil, errors.Join(
			cause, manager.releaseResources(resources),
		)
	}

	now := manager.now().UTC()
	states := make([]CandidateState, len(prepared))
	candidates := make([]connectivity.Candidate, len(prepared))
	expiresAt := minimumTime(
		now.Add(request.ReadinessTTL),
		request.ManifestExpiresAt,
		request.PSKExpiresAt,
	)
	for index, item := range prepared {
		expected := request.Candidates[index]
		if err := validatePreparedCandidate(item, expected, now); err != nil {
			return Snapshot{}, nil, errors.Join(
				fmt.Errorf("candidate %q: %w", expected.ID, err),
				manager.releaseResources(resources),
			)
		}
		state := CandidateState{
			Descriptor:      expected,
			ProbeFreshUntil: item.ProbeFreshUntil.UTC(),
			Warm:            item.Warm,
			WarmUntil:       item.WarmUntil.UTC(),
		}
		states[index] = state
		candidates[index] = item.Candidate
		expiresAt = minimumTime(
			expiresAt,
			expected.ExpiresAt,
			state.ProbeFreshUntil,
		)
		if state.Warm {
			expiresAt = minimumTime(expiresAt, state.WarmUntil)
		}
	}
	if err := validateRequirements(request, states); err != nil {
		return Snapshot{}, nil, errors.Join(
			err, manager.releaseResources(resources),
		)
	}
	if !expiresAt.After(now) {
		return Snapshot{}, nil, errors.Join(
			errors.New("prepared generation has no positive readiness lifetime"),
			manager.releaseResources(resources),
		)
	}
	readiness := connectivity.Readiness{
		Profile:           request.Profile,
		Mode:              request.Mode,
		ManifestDigest:    request.ManifestDigest,
		ManifestExpiresAt: request.ManifestExpiresAt,
		PSKGeneration:     request.PSKGeneration,
		PSKExpiresAt:      request.PSKExpiresAt,
		UnusedCredentials: request.UnusedCredentials,
		PreparedAt:        now,
		ExpiresAt:         expiresAt,
		Candidates:        slices.Clone(request.Candidates),
	}
	snapshot := Snapshot{
		fingerprint: fingerprint,
		readiness:   readiness,
		candidates:  candidates,
		states:      states,
		preconnect:  request.PreconnectIdentity,
	}
	if !snapshot.Valid(now) {
		return Snapshot{}, nil, errors.Join(
			errors.New("prepared generation failed final validation"),
			manager.releaseResources(resources),
		)
	}
	return snapshot, resources, nil
}

// Acquire pins the current generation so it cannot be disposed while a
// click-time connection attempt uses it.
func (manager *Manager) Acquire() (*Lease, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.current == nil ||
		manager.current.retiring ||
		!manager.current.snapshot.Valid(manager.now().UTC()) {
		return nil, ErrNotReady
	}
	generation := manager.current
	if generation.refs == 0 {
		generation.zero = make(chan struct{})
	}
	generation.refs++
	return &Lease{
		manager:    manager,
		generation: generation,
		snapshot:   generation.snapshot,
	}, nil
}

// Status returns a defensive snapshot only while it is current and valid.
func (manager *Manager) Status() (Snapshot, bool) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.current == nil ||
		manager.current.retiring ||
		!manager.current.snapshot.Valid(manager.now().UTC()) {
		return Snapshot{}, false
	}
	return manager.current.snapshot, true
}

func (manager *Manager) retireCurrent(ctx context.Context) error {
	manager.mu.Lock()
	current := manager.current
	if current == nil {
		manager.mu.Unlock()
		return nil
	}
	current.retiring = true
	zero := current.zero
	manager.mu.Unlock()

	select {
	case <-zero:
	case <-ctx.Done():
		manager.mu.Lock()
		if manager.current == current && !manager.closed {
			current.retiring = false
		}
		manager.mu.Unlock()
		return context.Cause(ctx)
	}

	manager.mu.Lock()
	if manager.current != current {
		manager.mu.Unlock()
		return nil
	}
	manager.current = nil
	manager.mu.Unlock()
	return manager.releaseResources(current.resources)
}

func (manager *Manager) releaseResources(resources []Resource) error {
	if len(resources) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), manager.closeTimeout,
	)
	defer cancel()
	var closeErrors []error
	for index := len(resources) - 1; index >= 0; index-- {
		resource := resources[index]
		if isNil(resource) {
			continue
		}
		if err := resource.Close(ctx); err != nil {
			closeErrors = append(
				closeErrors,
				fmt.Errorf("close prepared resource %d: %w", index, err),
			)
		}
	}
	return errors.Join(closeErrors...)
}

// Close prevents new preparation, cancels any build, waits for leases, and
// disposes the current generation. A timed-out Close can be retried.
func (manager *Manager) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	manager.mu.Lock()
	manager.closed = true
	if manager.active != nil {
		manager.active.cancel(ErrClosed)
	}
	manager.mu.Unlock()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-manager.operation:
	}
	defer func() { manager.operation <- struct{}{} }()
	return manager.retireCurrent(ctx)
}

// Lease pins one generation. Release is idempotent.
type Lease struct {
	manager    *Manager
	generation *generation
	snapshot   Snapshot
	released   atomic.Bool
}

func (lease *Lease) Snapshot() (Snapshot, error) {
	if lease == nil || lease.released.Load() {
		return Snapshot{}, ErrNotReady
	}
	return lease.snapshot, nil
}

func (lease *Lease) ConnectRequest(
	sessionID string,
	sequenceEpoch uint64,
	deadline time.Duration,
) (connectivity.ConnectRequest, error) {
	snapshot, err := lease.Snapshot()
	if err != nil {
		return connectivity.ConnectRequest{}, err
	}
	return snapshot.ConnectRequest(sessionID, sequenceEpoch, deadline)
}

func (lease *Lease) Release() {
	if lease == nil || !lease.released.CompareAndSwap(false, true) {
		return
	}
	manager := lease.manager
	manager.mu.Lock()
	generation := lease.generation
	generation.refs--
	if generation.refs == 0 {
		close(generation.zero)
	}
	manager.mu.Unlock()
}

func normalizeRequest(
	request Request,
	now time.Time,
) (Request, string, error) {
	request = cloneRequest(request)
	request.ManifestExpiresAt = request.ManifestExpiresAt.UTC()
	request.PSKExpiresAt = request.PSKExpiresAt.UTC()
	request.PreconnectIdentity.ExpiresAt =
		request.PreconnectIdentity.ExpiresAt.UTC()
	for index := range request.Candidates {
		request.Candidates[index].ExpiresAt =
			request.Candidates[index].ExpiresAt.UTC()
	}
	slices.Sort(request.RequiredCarriers)
	request.RequiredCarriers = slices.Compact(request.RequiredCarriers)
	slices.Sort(request.RequiredWarmCarriers)
	request.RequiredWarmCarriers =
		slices.Compact(request.RequiredWarmCarriers)
	if err := validateRequest(request, now); err != nil {
		return Request{}, "", err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return Request{}, "", fmt.Errorf(
			"encode preparation request: %w", err,
		)
	}
	digest := sha256.Sum256(encoded)
	return request, hex.EncodeToString(digest[:]), nil
}

func validateRequest(request Request, now time.Time) error {
	if !identifierPattern.MatchString(request.Profile) {
		return errors.New("preparation profile is invalid")
	}
	if !connectivity.ValidMode(request.Mode) {
		return errors.New("preparation mode is invalid")
	}
	if !digestPattern.MatchString(request.ManifestDigest) {
		return errors.New("preparation manifest digest is invalid")
	}
	if !request.ManifestExpiresAt.After(now) {
		return errors.New("preparation manifest is expired")
	}
	if request.PSKGeneration == 0 ||
		!request.PSKExpiresAt.After(now) {
		return errors.New("preparation PSK is missing or expired")
	}
	if request.UnusedCredentials < 0 ||
		request.UnusedCredentials > 1024 ||
		request.MinimumUnusedCredentials < 0 ||
		request.MinimumUnusedCredentials > 1024 ||
		request.UnusedCredentials < request.MinimumUnusedCredentials {
		return errors.New("preparation credential floor is not satisfied")
	}
	if request.ReadinessTTL <= 0 ||
		request.ReadinessTTL > connectivity.DefaultReadinessTTL {
		return errors.New("preparation readiness TTL is invalid")
	}
	if len(request.Candidates) == 0 ||
		len(request.Candidates) > connectivity.MaxCandidates {
		return errors.New("preparation candidate count is invalid")
	}
	if request.PreconnectIdentity.active() {
		identity := request.PreconnectIdentity
		if !identity.ExpiresAt.After(now) ||
			identity.ExpiresAt.After(request.ManifestExpiresAt) ||
			identity.ExpiresAt.After(request.PSKExpiresAt) {
			return errors.New(
				"cold preconnect identity is expired or outlives trust",
			)
		}
	} else if request.PreconnectIdentity != (PreconnectIdentity{}) {
		return errors.New("cold preconnect identity is incomplete")
	}
	seen := make(map[string]struct{}, len(request.Candidates))
	for _, descriptor := range request.Candidates {
		if !identifierPattern.MatchString(descriptor.ID) ||
			!identifierPattern.MatchString(descriptor.NodeID) ||
			!connectivity.ValidCarrier(descriptor.Carrier) ||
			!modeAllows(request.Mode, descriptor.Carrier) ||
			!descriptor.ExpiresAt.After(now) {
			return fmt.Errorf(
				"candidate %q is invalid for mode %q",
				descriptor.ID, request.Mode,
			)
		}
		if descriptor.ExpiresAt.After(request.ManifestExpiresAt) ||
			descriptor.ExpiresAt.After(request.PSKExpiresAt) {
			return fmt.Errorf(
				"candidate %q outlives manifest or PSK", descriptor.ID,
			)
		}
		if request.PreconnectIdentity.active() {
			binding := request.PreconnectIdentity.binding(
				request,
				descriptor,
			)
			if binding.ExpiresAt.After(descriptor.ExpiresAt) {
				return fmt.Errorf(
					"candidate %q cold binding outlives descriptor",
					descriptor.ID,
				)
			}
			if err := binding.Validate(now); err != nil {
				return fmt.Errorf(
					"candidate %q cold binding: %w",
					descriptor.ID,
					err,
				)
			}
		}
		if _, duplicate := seen[descriptor.ID]; duplicate {
			return fmt.Errorf("duplicate candidate %q", descriptor.ID)
		}
		seen[descriptor.ID] = struct{}{}
	}
	for _, carrier := range append(
		slices.Clone(request.RequiredCarriers),
		request.RequiredWarmCarriers...,
	) {
		if !connectivity.ValidCarrier(carrier) ||
			!modeAllows(request.Mode, carrier) {
			return fmt.Errorf(
				"required carrier %q is invalid for mode %q",
				carrier, request.Mode,
			)
		}
	}
	return nil
}

func validatePreparedCandidate(
	prepared PreparedCandidate,
	expected connectivity.CandidateDescriptor,
	now time.Time,
) error {
	if isNil(prepared.Candidate) {
		return errors.New("prepared candidate is nil")
	}
	if prepared.Candidate.Descriptor() != expected {
		return errors.New("prepared candidate descriptor changed")
	}
	if isNil(prepared.Resource) {
		return errors.New("prepared candidate resource is nil")
	}
	if !prepared.ProbeFreshUntil.After(now) {
		return errors.New("prepared candidate probe is stale")
	}
	if prepared.Warm {
		if !prepared.WarmUntil.After(now) {
			return errors.New("prepared candidate warm state is stale")
		}
		if prepared.WarmUntil.After(now.Add(maxWarmAge)) {
			return errors.New("prepared candidate warm state exceeds maximum age")
		}
	} else if !prepared.WarmUntil.IsZero() {
		return errors.New("cold candidate has a warm-state expiry")
	}
	return nil
}

func validateRequirements(
	request Request,
	states []CandidateState,
) error {
	present := make(map[connectivity.Carrier]bool)
	warm := make(map[connectivity.Carrier]bool)
	for _, state := range states {
		present[state.Descriptor.Carrier] = true
		if state.Warm {
			warm[state.Descriptor.Carrier] = true
		}
	}
	for _, carrier := range request.RequiredCarriers {
		if !present[carrier] {
			return fmt.Errorf("required carrier %q was not prepared", carrier)
		}
	}
	for _, carrier := range request.RequiredWarmCarriers {
		if !warm[carrier] {
			return fmt.Errorf(
				"required carrier %q was not prepared warm", carrier,
			)
		}
	}
	return nil
}

func modeAllows(mode connectivity.Mode, carrier connectivity.Carrier) bool {
	switch mode {
	case connectivity.ModeFast:
		return carrier == connectivity.CarrierDirectAWG
	case connectivity.ModeAuto:
		return carrier == connectivity.CarrierDirectAWG ||
			carrier == connectivity.CarrierHTTP3 ||
			carrier == connectivity.CarrierHTTP2 ||
			carrier == connectivity.CarrierRealityXHTTP ||
			carrier == connectivity.CarrierWebSocketTLS
	case connectivity.ModeStealth:
		return carrier == connectivity.CarrierRealityXHTTP ||
			carrier == connectivity.CarrierWebSocketTLS
	case connectivity.ModePrivateRelay:
		return carrier == connectivity.CarrierNativeTwoHop
	case connectivity.ModeMaximumPrivacy:
		return carrier == connectivity.CarrierPrivacyTwoHop
	default:
		return false
	}
}

func collectResources(prepared []PreparedCandidate) []Resource {
	resources := make([]Resource, 0, len(prepared))
	for _, item := range prepared {
		if !isNil(item.Resource) {
			resources = append(resources, item.Resource)
		}
	}
	return resources
}

func cloneRequest(request Request) Request {
	request.Candidates = slices.Clone(request.Candidates)
	request.RequiredCarriers = slices.Clone(request.RequiredCarriers)
	request.RequiredWarmCarriers =
		slices.Clone(request.RequiredWarmCarriers)
	return request
}

func waitForBuild(ctx context.Context, active *build) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-active.done:
		return active.err
	}
}

func minimumTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
