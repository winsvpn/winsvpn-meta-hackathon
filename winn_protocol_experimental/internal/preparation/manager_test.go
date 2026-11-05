package preparation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

type fakeCandidate struct {
	descriptor connectivity.CandidateDescriptor
}

func (candidate *fakeCandidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.descriptor
}

func (candidate *fakeCandidate) Dial(
	context.Context,
	connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	return nil, errors.New("not used by preparation tests")
}

type fakeResource struct {
	closed atomic.Bool
	count  *atomic.Int64
}

func (resource *fakeResource) Close(context.Context) error {
	if resource.closed.CompareAndSwap(false, true) && resource.count != nil {
		resource.count.Add(1)
	}
	return nil
}

type prepareFunc func(
	context.Context,
	CandidateContext,
) (PreparedCandidate, error)

func (function prepareFunc) PrepareCandidate(
	ctx context.Context,
	candidate CandidateContext,
) (PreparedCandidate, error) {
	return function(ctx, candidate)
}

func TestManagerPublishesImmutablePhase1Snapshot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var closed atomic.Int64
	manager := newPhase1TestManager(t, now, prepareFunc(
		func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			probeFreshUntil := now.Add(50 * time.Second)
			warm := candidate.Descriptor.Carrier == connectivity.CarrierHTTP3
			warmUntil := time.Time{}
			if warm {
				probeFreshUntil = now.Add(40 * time.Second)
				warmUntil = now.Add(45 * time.Second)
			}
			return PreparedCandidate{
				Candidate: &fakeCandidate{
					descriptor: candidate.Descriptor,
				},
				ProbeFreshUntil: probeFreshUntil,
				Warm:            warm,
				WarmUntil:       warmUntil,
				Resource:        &fakeResource{count: &closed},
			}, nil
		},
	))
	request := phase1Request(now, "profile-a")
	if err := manager.Prepare(context.Background(), request); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	snapshot, ok := manager.Status()
	if !ok {
		t.Fatal("Status() did not return the prepared generation")
	}
	if got, want := snapshot.Readiness().ExpiresAt, now.Add(40*time.Second); got != want {
		t.Fatalf("readiness expiry = %v, want %v", got, want)
	}
	readiness := snapshot.Readiness()
	readiness.Candidates[0].ID = "mutated"
	states := snapshot.CandidateStates()
	states[0].Descriptor.ID = "mutated"
	candidates := snapshot.Candidates()
	candidates[0] = nil
	if got := snapshot.Readiness().Candidates[0].ID; got != "direct-a" {
		t.Fatalf("readiness mutation escaped defensive copy: %q", got)
	}
	if got := snapshot.CandidateStates()[0].Descriptor.ID; got != "direct-a" {
		t.Fatalf("state mutation escaped defensive copy: %q", got)
	}
	if snapshot.Candidates()[0] == nil {
		t.Fatal("candidate mutation escaped defensive copy")
	}

	lease, err := manager.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	connectRequest, err := lease.ConnectRequest(
		strings.Repeat("a", 32), 1, connectivity.MaxDeadline,
	)
	if err != nil {
		t.Fatalf("ConnectRequest() error = %v", err)
	}
	connectRequest.Readiness.Candidates[0].ID = "mutated"
	connectRequest.Candidates[0] = nil
	leased, err := lease.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if got := leased.Readiness().Candidates[0].ID; got != "direct-a" {
		t.Fatalf("connect request mutation escaped snapshot: %q", got)
	}
	if leased.Candidates()[0] == nil {
		t.Fatal("connect request candidate mutation escaped snapshot")
	}
	lease.Release()
	if _, err := lease.Snapshot(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("released lease error = %v, want ErrNotReady", err)
	}

	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := closed.Load(); got != 2 {
		t.Fatalf("closed resources = %d, want 2", got)
	}
}

func TestManagerCarriesOneExactColdBindingIntoPreparationAndClick(
	t *testing.T,
) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	captured := make(chan CandidateContext, 2)
	manager := newPhase1TestManager(t, now, prepareFunc(
		func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			captured <- candidate
			return preparedFor(now, candidate.Descriptor, nil), nil
		},
	))
	request := phase1Request(now, "profile-cold")
	request.PreconnectIdentity = PreconnectIdentity{
		AttemptID:     strings.Repeat("1", 32),
		SessionID:     strings.Repeat("2", 32),
		SequenceEpoch: 19,
		Nonce:         strings.Repeat("3", 32),
		ExpiresAt:     now.Add(3 * time.Second),
	}
	if err := manager.Prepare(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]connectivity.Binding, 2)
	for range 2 {
		current := <-captured
		binding := current.PreconnectBinding
		if binding.AttemptID != request.PreconnectIdentity.AttemptID ||
			binding.SessionID != request.PreconnectIdentity.SessionID ||
			binding.SequenceEpoch !=
				request.PreconnectIdentity.SequenceEpoch ||
			binding.Nonce != request.PreconnectIdentity.Nonce ||
			binding.CandidateID != current.Descriptor.ID ||
			binding.NodeID != current.Descriptor.NodeID ||
			!binding.ExpiresAt.Equal(
				request.PreconnectIdentity.ExpiresAt,
			) {
			t.Fatalf("prepared cold binding = %#v", binding)
		}
		expected[binding.CandidateID] = binding
	}
	lease, err := manager.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if _, err := lease.ConnectRequest(
		strings.Repeat("f", 32), 19, time.Second,
	); err == nil {
		t.Fatal("different cold session was accepted")
	}
	connectRequest, err := lease.ConnectRequest(
		request.PreconnectIdentity.SessionID,
		request.PreconnectIdentity.SequenceEpoch,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if connectRequest.AttemptID !=
		request.PreconnectIdentity.AttemptID ||
		connectRequest.Nonce != request.PreconnectIdentity.Nonce ||
		len(connectRequest.ReservedBindings) != len(expected) {
		t.Fatalf("cold connect request = %#v", connectRequest)
	}
	for _, binding := range connectRequest.ReservedBindings {
		if binding != expected[binding.CandidateID] {
			t.Fatalf(
				"click binding %#v differs from prepared %#v",
				binding,
				expected[binding.CandidateID],
			)
		}
	}
}

func TestEquivalentConcurrentPrepareCoalesces(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var calls atomic.Int64
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	manager := newPhase1TestManagerWithConfig(t, Config{
		Factory: prepareFunc(func(
			ctx context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			calls.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
				return PreparedCandidate{}, context.Cause(ctx)
			}
			return preparedFor(now, candidate.Descriptor, nil), nil
		}),
		MaxParallel: 1,
		Now:         func() time.Time { return now },
	})
	request := phase1Request(now, "profile-a")
	results := make(chan error, 2)
	go func() {
		results <- manager.Prepare(context.Background(), request)
	}()
	<-started
	go func() {
		results <- manager.Prepare(context.Background(), request)
	}()
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("Prepare() error = %v", err)
		}
	}
	if got := calls.Load(); got != int64(len(request.Candidates)) {
		t.Fatalf("factory calls = %d, want %d", got, len(request.Candidates))
	}
}

func TestDifferentPrepareCancelsInflightGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	oldStarted := make(chan struct{})
	var oldStartedOnce sync.Once
	manager := newPhase1TestManagerWithConfig(t, Config{
		Factory: prepareFunc(func(
			ctx context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			if candidate.Profile == "profile-old" {
				oldStartedOnce.Do(func() { close(oldStarted) })
				<-ctx.Done()
				return PreparedCandidate{}, context.Cause(ctx)
			}
			return preparedFor(now, candidate.Descriptor, nil), nil
		}),
		MaxParallel: 1,
		Now:         func() time.Time { return now },
	})
	oldResult := make(chan error, 1)
	go func() {
		oldResult <- manager.Prepare(
			context.Background(), phase1Request(now, "profile-old"),
		)
	}()
	<-oldStarted
	if err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-new"),
	); err != nil {
		t.Fatalf("replacement Prepare() error = %v", err)
	}
	if err := <-oldResult; !errors.Is(err, ErrSuperseded) {
		t.Fatalf("superseded Prepare() error = %v, want ErrSuperseded", err)
	}
	snapshot, ok := manager.Status()
	if !ok || snapshot.Readiness().Profile != "profile-new" {
		t.Fatalf("current snapshot = (%v, %v), want profile-new", snapshot, ok)
	}
}

func TestAlreadyCanceledRequestDoesNotSupersedeActiveBuild(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	manager := newPhase1TestManagerWithConfig(t, Config{
		Factory: prepareFunc(func(
			ctx context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
				return preparedFor(now, candidate.Descriptor, nil), nil
			case <-ctx.Done():
				return PreparedCandidate{}, context.Cause(ctx)
			}
		}),
		MaxParallel: 1,
		Now:         func() time.Time { return now },
	})
	activeResult := make(chan error, 1)
	go func() {
		activeResult <- manager.Prepare(
			context.Background(), phase1Request(now, "profile-active"),
		)
	}()
	<-started
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err := manager.Prepare(
		canceled, phase1Request(now, "profile-canceled"),
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Prepare() error = %v, want context.Canceled", err)
	}
	close(release)
	if err := <-activeResult; err != nil {
		t.Fatalf("active Prepare() was superseded: %v", err)
	}
	snapshot, ok := manager.Status()
	if !ok || snapshot.Readiness().Profile != "profile-active" {
		t.Fatalf("current snapshot = (%v, %v), want profile-active", snapshot, ok)
	}
}

func TestReplacementWaitsForLeaseAndDisposesBeforeBuild(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var oldClosed atomic.Int64
	newStarted := make(chan struct{})
	var newStartedOnce sync.Once
	manager := newPhase1TestManager(t, now, prepareFunc(
		func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			if candidate.Profile == "profile-new" {
				if got := oldClosed.Load(); got != 2 {
					return PreparedCandidate{}, errors.New(
						"new build began before old resources closed",
					)
				}
				newStartedOnce.Do(func() { close(newStarted) })
				return preparedFor(now, candidate.Descriptor, nil), nil
			}
			return preparedFor(now, candidate.Descriptor, &oldClosed), nil
		},
	))
	if err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-old"),
	); err != nil {
		t.Fatalf("initial Prepare() error = %v", err)
	}
	lease, err := manager.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	replacement := make(chan error, 1)
	go func() {
		replacement <- manager.Prepare(
			context.Background(), phase1Request(now, "profile-new"),
		)
	}()
	select {
	case <-newStarted:
		t.Fatal("replacement build started while old generation was leased")
	case <-time.After(50 * time.Millisecond):
	}
	lease.Release()
	select {
	case err := <-replacement:
		if err != nil {
			t.Fatalf("replacement Prepare() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("replacement did not finish after lease release")
	}
	if got := oldClosed.Load(); got != 2 {
		t.Fatalf("old resources closed = %d, want 2", got)
	}
}

func TestPartialBuildFailureReleasesSuccessfulResources(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var closed atomic.Int64
	directReady := make(chan struct{})
	var directReadyOnce sync.Once
	manager := newPhase1TestManager(t, now, prepareFunc(
		func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			if candidate.Descriptor.Carrier == connectivity.CarrierDirectAWG {
				directReadyOnce.Do(func() { close(directReady) })
				return preparedFor(
					now, candidate.Descriptor, &closed,
				), nil
			}
			<-directReady
			return PreparedCandidate{}, errors.New("H3 preparation failed")
		},
	))
	err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-a"),
	)
	if err == nil || !strings.Contains(err.Error(), "H3 preparation failed") {
		t.Fatalf("Prepare() error = %v, want H3 failure", err)
	}
	if got := closed.Load(); got != 1 {
		t.Fatalf("closed successful resources = %d, want 1", got)
	}
	if _, ok := manager.Status(); ok {
		t.Fatal("partial generation was published")
	}
}

func TestPhase1PolicyAndWarmRequirementFailClosed(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	coldFactory := prepareFunc(func(
		_ context.Context,
		candidate CandidateContext,
	) (PreparedCandidate, error) {
		prepared := preparedFor(now, candidate.Descriptor, nil)
		if candidate.Descriptor.Carrier == connectivity.CarrierHTTP3 {
			prepared.Warm = false
			prepared.WarmUntil = time.Time{}
		}
		return prepared, nil
	})
	manager := newPhase1TestManager(t, now, coldFactory)
	err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-a"),
	)
	if err == nil || !strings.Contains(err.Error(), "was not prepared warm") {
		t.Fatalf("cold H3 error = %v, want warm requirement failure", err)
	}

	tests := []struct {
		name   string
		mutate func(*Request)
	}{
		{
			name: "credential floor",
			mutate: func(request *Request) {
				request.UnusedCredentials = 7
				request.MinimumUnusedCredentials = 7
			},
		},
		{
			name: "Direct declaration",
			mutate: func(request *Request) {
				request.RequiredCarriers = []connectivity.Carrier{
					connectivity.CarrierHTTP3,
				}
			},
		},
		{
			name: "warm H3 declaration",
			mutate: func(request *Request) {
				request.RequiredWarmCarriers = nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := phase1Request(now, "profile-a")
			test.mutate(&request)
			if err := manager.Prepare(
				context.Background(), request,
			); err == nil {
				t.Fatal("Prepare() unexpectedly passed Phase-1 policy")
			}
		})
	}
}

func TestExpiredProbeMakesGenerationUnavailable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	current := now
	manager := newPhase1TestManagerWithConfig(t, Config{
		Factory: prepareFunc(func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			prepared := preparedFor(now, candidate.Descriptor, nil)
			prepared.ProbeFreshUntil = now.Add(5 * time.Second)
			return prepared, nil
		}),
		Now: func() time.Time { return current },
	})
	if err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-a"),
	); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	current = now.Add(6 * time.Second)
	if _, err := manager.Acquire(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("Acquire() error = %v, want ErrNotReady", err)
	}
	if _, ok := manager.Status(); ok {
		t.Fatal("Status() returned a generation with an expired probe")
	}
}

func TestCloseWaitsForLeaseAndCanBeRetried(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	var closed atomic.Int64
	manager := newPhase1TestManager(t, now, prepareFunc(
		func(
			_ context.Context,
			candidate CandidateContext,
		) (PreparedCandidate, error) {
			return preparedFor(now, candidate.Descriptor, &closed), nil
		},
	))
	if err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-a"),
	); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	lease, err := manager.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Close() error = %v, want deadline exceeded", err)
	}
	if got := closed.Load(); got != 0 {
		t.Fatalf("resources closed under active lease = %d", got)
	}
	lease.Release()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("retry Close() error = %v", err)
	}
	if got := closed.Load(); got != 2 {
		t.Fatalf("closed resources = %d, want 2", got)
	}
	if err := manager.Prepare(
		context.Background(), phase1Request(now, "profile-b"),
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("Prepare() after Close error = %v, want ErrClosed", err)
	}
}

func newPhase1TestManager(
	t *testing.T,
	now time.Time,
	factory CandidatePreparer,
) *Manager {
	t.Helper()
	return newPhase1TestManagerWithConfig(t, Config{
		Factory: factory,
		Now:     func() time.Time { return now },
	})
}

func newPhase1TestManagerWithConfig(t *testing.T, config Config) *Manager {
	t.Helper()
	manager, err := NewPhase1AutoManager(config)
	if err != nil {
		t.Fatalf("NewPhase1AutoManager() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(
			context.Background(), 2*time.Second,
		)
		defer cancel()
		_ = manager.Close(ctx)
	})
	return manager
}

func phase1Request(now time.Time, profile string) Request {
	trustExpiry := now.Add(30 * time.Minute)
	return Request{
		Profile:                  profile,
		Mode:                     connectivity.ModeAuto,
		ManifestDigest:           strings.Repeat("a", 64),
		ManifestExpiresAt:        trustExpiry,
		PSKGeneration:            1,
		PSKExpiresAt:             trustExpiry,
		UnusedCredentials:        Phase1MinimumUnusedCredentials,
		MinimumUnusedCredentials: Phase1MinimumUnusedCredentials,
		ReadinessTTL:             connectivity.DefaultReadinessTTL,
		Candidates: []connectivity.CandidateDescriptor{
			{
				ID:        "direct-a",
				Carrier:   connectivity.CarrierDirectAWG,
				NodeID:    "gateway-a",
				ExpiresAt: trustExpiry,
			},
			{
				ID:        "h3-a",
				Carrier:   connectivity.CarrierHTTP3,
				NodeID:    "gateway-b",
				ExpiresAt: trustExpiry,
			},
		},
		RequiredCarriers: []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
			connectivity.CarrierHTTP3,
		},
		RequiredWarmCarriers: []connectivity.Carrier{
			connectivity.CarrierHTTP3,
		},
	}
}

func preparedFor(
	now time.Time,
	descriptor connectivity.CandidateDescriptor,
	closed *atomic.Int64,
) PreparedCandidate {
	warm := descriptor.Carrier == connectivity.CarrierHTTP3
	warmUntil := time.Time{}
	if warm {
		warmUntil = now.Add(45 * time.Second)
	}
	return PreparedCandidate{
		Candidate:       &fakeCandidate{descriptor: descriptor},
		ProbeFreshUntil: now.Add(40 * time.Second),
		Warm:            warm,
		WarmUntil:       warmUntil,
		Resource:        &fakeResource{count: closed},
	}
}
