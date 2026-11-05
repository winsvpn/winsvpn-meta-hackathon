package linuxauto

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/autoconnect"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/preparation"
)

func TestAutoRuntimeJoinsPreparedGenerationToOneClick(t *testing.T) {
	var assemblyCalls atomic.Int32
	var candidateDials atomic.Int32
	resource := &runtimeResource{}
	runtime, err := newAutoRuntime(
		func(
			ctx context.Context,
			request preparation.VerifiedAssemblyRequest,
		) (autoconnect.PreparedGeneration, error) {
			assemblyCalls.Add(1)
			if request.Profile != "phase1-auto" ||
				request.Mode != connectivity.ModeAuto {
				return nil, errors.New("unexpected assembly request")
			}
			return newRuntimeGeneration(
				t, ctx, resource, &candidateDials,
				request.PreconnectIdentity,
			), nil
		},
		AutoRuntimeConfig{
			Deadline: 500 * time.Millisecond,
			Identity: func(context.Context) (
				string, uint64, error,
			) {
				return "00112233445566778899aabbccddeeff",
					7, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := runtime.Prepare(
		context.Background(),
		preparation.VerifiedAssemblyRequest{
			Profile: "phase1-auto",
			Mode:    connectivity.ModeAuto,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 16
	var wait sync.WaitGroup
	wait.Add(callers)
	results := make(chan connectivity.Result, callers)
	failures := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			result, connectErr := attempt.Connect(
				context.Background(),
			)
			results <- result
			failures <- connectErr
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	for connectErr := range failures {
		if connectErr != nil {
			t.Fatalf("connect: %v", connectErr)
		}
	}
	var attemptID string
	for result := range results {
		if !result.Success() {
			t.Fatalf("result = %+v", result)
		}
		if attemptID == "" {
			attemptID = result.AttemptID
		} else if result.AttemptID != attemptID {
			t.Fatal("concurrent clicks did not coalesce")
		}
	}
	if assemblyCalls.Load() != 1 {
		t.Fatalf("assembly calls = %d, want 1", assemblyCalls.Load())
	}
	if candidateDials.Load() != 1 {
		t.Fatalf("candidate dials = %d, want 1", candidateDials.Load())
	}
	if resource.closed.Load() {
		t.Fatal("online attempt released preparation resource")
	}
	closeContext, cancel := context.WithTimeout(
		context.Background(), time.Second,
	)
	defer cancel()
	if err := attempt.Close(closeContext); err != nil {
		t.Fatal(err)
	}
	if !resource.closed.Load() {
		t.Fatal("attempt close did not retire preparation resource")
	}
}

func TestAutoRuntimeColdReservesIdentityBeforeAssembly(t *testing.T) {
	var captured preparation.VerifiedAssemblyRequest
	resource := &runtimeResource{}
	var dials atomic.Int32
	runtime, err := newAutoRuntime(
		func(
			ctx context.Context,
			request preparation.VerifiedAssemblyRequest,
		) (autoconnect.PreparedGeneration, error) {
			captured = request
			return newRuntimeGeneration(
				t,
				ctx,
				resource,
				&dials,
				request.PreconnectIdentity,
			), nil
		},
		AutoRuntimeConfig{
			Deadline: time.Second,
			Identity: func(context.Context) (
				string, uint64, error,
			) {
				return strings.Repeat("4", 32), 23, nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	operation, cancel := context.WithTimeout(
		context.Background(),
		time.Second,
	)
	defer cancel()
	attempt, err := runtime.PrepareCold(
		operation,
		preparation.VerifiedAssemblyRequest{
			Profile: "phase1-auto",
			Mode:    connectivity.ModeAuto,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity := captured.PreconnectIdentity
	if len(identity.AttemptID) != 32 ||
		identity.SessionID != strings.Repeat("4", 32) ||
		identity.SequenceEpoch != 23 ||
		len(identity.Nonce) != 32 ||
		!identity.ExpiresAt.After(time.Now().UTC()) {
		t.Fatalf("reserved cold identity = %#v", identity)
	}
	result, err := attempt.Connect(operation)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success() || result.AttemptID != identity.AttemptID ||
		dials.Load() != 1 {
		t.Fatalf(
			"cold result = %#v, dials = %d",
			result,
			dials.Load(),
		)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAutoRuntimeRejectsInvalidConfigurationAndAssembly(t *testing.T) {
	if _, err := NewAutoRuntime(nil, AutoRuntimeConfig{}); err == nil {
		t.Fatal("nil verified assembler was accepted")
	}
	if _, err := newAutoRuntime(
		func(
			context.Context,
			preparation.VerifiedAssemblyRequest,
		) (autoconnect.PreparedGeneration, error) {
			return nil, nil
		},
		AutoRuntimeConfig{Deadline: connectivity.MaxDeadline + time.Nanosecond},
	); err == nil {
		t.Fatal("oversized click deadline was accepted")
	}
	runtime, err := newAutoRuntime(
		func(
			context.Context,
			preparation.VerifiedAssemblyRequest,
		) (autoconnect.PreparedGeneration, error) {
			return nil, nil
		},
		AutoRuntimeConfig{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Prepare(
		context.Background(),
		preparation.VerifiedAssemblyRequest{},
	); err == nil {
		t.Fatal("nil prepared generation was accepted")
	}
	cancelled, cancel := context.WithCancelCause(
		context.Background(),
	)
	cause := errors.New("owner cancelled preparation")
	cancel(cause)
	if _, err := runtime.Prepare(
		cancelled,
		preparation.VerifiedAssemblyRequest{},
	); !errors.Is(err, cause) {
		t.Fatalf("cancelled preparation returned %v", err)
	}
}

func newRuntimeGeneration(
	t *testing.T,
	ctx context.Context,
	resource *runtimeResource,
	dials *atomic.Int32,
	preconnect preparation.PreconnectIdentity,
) *preparation.Manager {
	t.Helper()
	now := time.Now().UTC()
	descriptor := connectivity.CandidateDescriptor{
		ID:        "direct-primary",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "node-a",
		ExpiresAt: now.Add(time.Minute),
	}
	manager, err := preparation.NewManager(preparation.Config{
		Factory: runtimePreparer{
			descriptor: descriptor,
			resource:   resource,
			dials:      dials,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = manager.Prepare(ctx, preparation.Request{
		Profile:                  "phase1-auto",
		Mode:                     connectivity.ModeAuto,
		ManifestDigest:           repeatRuntimeHex("a", 64),
		ManifestExpiresAt:        now.Add(2 * time.Minute),
		PSKGeneration:            1,
		PSKExpiresAt:             now.Add(2 * time.Minute),
		UnusedCredentials:        8,
		MinimumUnusedCredentials: 8,
		ReadinessTTL:             30 * time.Second,
		Candidates:               []connectivity.CandidateDescriptor{descriptor},
		RequiredCarriers: []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
		},
		PreconnectIdentity: preconnect,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type runtimePreparer struct {
	descriptor connectivity.CandidateDescriptor
	resource   *runtimeResource
	dials      *atomic.Int32
}

func (preparer runtimePreparer) PrepareCandidate(
	_ context.Context,
	_ preparation.CandidateContext,
) (preparation.PreparedCandidate, error) {
	return preparation.PreparedCandidate{
		Candidate: runtimeCandidate{
			descriptor: preparer.descriptor,
			dials:      preparer.dials,
		},
		ProbeFreshUntil: time.Now().UTC().Add(30 * time.Second),
		Resource:        preparer.resource,
	}, nil
}

type runtimeResource struct {
	closed atomic.Bool
}

func (resource *runtimeResource) Close(context.Context) error {
	resource.closed.Store(true)
	return nil
}

type runtimeCandidate struct {
	descriptor connectivity.CandidateDescriptor
	dials      *atomic.Int32
}

func (candidate runtimeCandidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.descriptor
}

func (candidate runtimeCandidate) Dial(
	context.Context,
	connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	candidate.dials.Add(1)
	return &runtimeConnection{
		health: make(chan error),
	}, nil
}

type runtimeConnection struct {
	health    chan error
	closeOnce sync.Once
}

func (*runtimeConnection) FreshAWGHandshake(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*runtimeConnection) VerifyBidirectional(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*runtimeConnection) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*runtimeConnection) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*runtimeConnection) Commit(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (connection *runtimeConnection) Health() <-chan error {
	return connection.health
}

func (connection *runtimeConnection) Close() error {
	connection.closeOnce.Do(func() {
		close(connection.health)
	})
	return nil
}

func repeatRuntimeHex(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
