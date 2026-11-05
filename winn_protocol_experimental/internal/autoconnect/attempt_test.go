package autoconnect

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/preparation"
)

func TestAttemptConnectsOnceAndOwnsPreparedLifetime(t *testing.T) {
	harness := newAttemptHarness(t, 0)
	attempt, err := New(Config{
		Generation: harness.manager,
		Identity: func(context.Context) (string, uint64, error) {
			return strings.Repeat("1", 32), 7, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 24
	results := make(chan connectivity.Result, callers)
	failures := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			result, connectErr := attempt.Connect(context.Background())
			if connectErr != nil {
				failures <- connectErr
				return
			}
			results <- result
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	for connectErr := range failures {
		t.Fatal(connectErr)
	}
	var attemptID string
	for result := range results {
		if !result.Success() {
			t.Fatalf("Auto result = %#v", result)
		}
		if attemptID == "" {
			attemptID = result.AttemptID
		} else if result.AttemptID != attemptID {
			t.Fatalf(
				"concurrent Connect returned attempt %q; want %q",
				result.AttemptID, attemptID,
			)
		}
	}
	if harness.candidate.dials.Load() != 1 {
		t.Fatalf("candidate dials = %d; want 1", harness.candidate.dials.Load())
	}
	if harness.resource.closed.Load() != 0 {
		t.Fatal("prepared generation closed while online")
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if harness.connection.closed.Load() != 1 {
		t.Fatalf(
			"connection closes = %d; want 1",
			harness.connection.closed.Load(),
		)
	}
	if harness.resource.closed.Load() != 1 {
		t.Fatalf(
			"prepared resource closes = %d; want 1",
			harness.resource.closed.Load(),
		)
	}
}

func TestAttemptDeadlineIncludesClickTimeAndCancelsCandidate(t *testing.T) {
	harness := newAttemptHarness(t, time.Second)
	attempt, err := New(Config{
		Generation: harness.manager,
		// 500ms: far above scheduler noise under parallel test load, far
		// below the 1s candidate duration, so the deadline deterministically
		// fires during the candidate phase and must cancel it.
		Deadline: 500 * time.Millisecond,
		Identity: func(context.Context) (string, uint64, error) {
			return strings.Repeat("2", 32), 9, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, err := attempt.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Failure != connectivity.FailureConnectDeadlineExceeded ||
		result.State != connectivity.StateFailed {
		t.Fatalf("deadline result = %#v", result)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("click deadline took %s", elapsed)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if harness.resource.closed.Load() != 1 {
		t.Fatal("deadline failure leaked prepared resource")
	}
}

func TestAttemptDeadlineIncludesIdentityReservation(t *testing.T) {
	harness := newAttemptHarness(t, 0)
	attempt, err := New(Config{
		Generation: harness.manager,
		Deadline:   20 * time.Millisecond,
		Identity: func(ctx context.Context) (string, uint64, error) {
			<-ctx.Done()
			return "", 0, context.Cause(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := attempt.Connect(context.Background()); !errors.Is(
		err, context.DeadlineExceeded,
	) {
		t.Fatalf("identity deadline error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("identity deadline took %s", elapsed)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if harness.candidate.dials.Load() != 0 {
		t.Fatal("expired identity reservation reached candidate dial")
	}
	if harness.resource.closed.Load() != 1 {
		t.Fatal("identity deadline leaked prepared resource")
	}
}

func TestAttemptUsesEarlierParentDeadlineForBinding(t *testing.T) {
	harness := newAttemptHarness(t, 0)
	harness.candidate.bindings = make(chan connectivity.Binding, 1)
	attempt, err := New(Config{
		Generation: harness.manager,
		Deadline:   connectivity.MaxDeadline,
		Identity: func(context.Context) (string, uint64, error) {
			return strings.Repeat("3", 32), 11, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithTimeout(
		context.Background(), 200*time.Millisecond,
	)
	defer cancel()
	result, err := attempt.Connect(parent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success() {
		t.Fatalf("parent-deadline result = %#v", result)
	}
	var binding connectivity.Binding
	select {
	case binding = <-harness.candidate.bindings:
	default:
		t.Fatal("candidate did not capture its binding")
	}
	if lifetime := binding.ExpiresAt.Sub(result.StartedAt); lifetime <= 0 || lifetime > 300*time.Millisecond {
		t.Fatalf(
			"binding lifetime = %s; parent deadline was not preserved",
			lifetime,
		)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAttemptRejectsMissingReadinessAndClosesGeneration(t *testing.T) {
	preparer := &attemptPreparer{}
	manager, err := preparation.NewManager(preparation.Config{
		Factory: preparer,
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := New(Config{Generation: manager})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attempt.Connect(context.Background()); !errors.Is(
		err, preparation.ErrNotReady,
	) {
		t.Fatalf("missing readiness error = %v", err)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAttemptCloseBeforeConnectIsTerminal(t *testing.T) {
	harness := newAttemptHarness(t, 0)
	attempt, err := New(Config{Generation: harness.manager})
	if err != nil {
		t.Fatal(err)
	}
	if err := attempt.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := attempt.Connect(context.Background()); !errors.Is(
		err, ErrAttemptClosed,
	) {
		t.Fatalf("Connect after Close error = %v", err)
	}
	if harness.resource.closed.Load() != 1 {
		t.Fatal("close-before-connect did not retire prepared generation")
	}
}

type attemptHarness struct {
	manager    *preparation.Manager
	candidate  *attemptCandidate
	connection *attemptConnection
	resource   *attemptResource
}

func newAttemptHarness(t testing.TB, dialDelay time.Duration) *attemptHarness {
	t.Helper()
	now := time.Now().UTC()
	descriptor := connectivity.CandidateDescriptor{
		ID:        "direct-auto",
		Carrier:   connectivity.CarrierDirectAWG,
		NodeID:    "gateway-auto",
		ExpiresAt: now.Add(time.Hour),
	}
	connection := &attemptConnection{health: make(chan error)}
	candidate := &attemptCandidate{
		descriptor: descriptor,
		connection: connection,
		dialDelay:  dialDelay,
	}
	resource := &attemptResource{}
	manager, err := preparation.NewManager(preparation.Config{
		Factory: &attemptPreparer{
			candidate: candidate,
			resource:  resource,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Prepare(context.Background(), preparation.Request{
		Profile:                  "auto-runtime",
		Mode:                     connectivity.ModeAuto,
		ManifestDigest:           strings.Repeat("a", 64),
		ManifestExpiresAt:        now.Add(time.Hour),
		PSKGeneration:            1,
		PSKExpiresAt:             now.Add(time.Hour),
		UnusedCredentials:        8,
		MinimumUnusedCredentials: 8,
		ReadinessTTL:             time.Minute,
		Candidates:               []connectivity.CandidateDescriptor{descriptor},
		RequiredCarriers: []connectivity.Carrier{
			connectivity.CarrierDirectAWG,
		},
	}); err != nil {
		t.Fatal(err)
	}
	return &attemptHarness{
		manager:    manager,
		candidate:  candidate,
		connection: connection,
		resource:   resource,
	}
}

type attemptPreparer struct {
	candidate *attemptCandidate
	resource  *attemptResource
}

func (preparer *attemptPreparer) PrepareCandidate(
	_ context.Context,
	_ preparation.CandidateContext,
) (preparation.PreparedCandidate, error) {
	if preparer.candidate == nil || preparer.resource == nil {
		return preparation.PreparedCandidate{},
			errors.New("attempt test preparer is empty")
	}
	return preparation.PreparedCandidate{
		Candidate:       preparer.candidate,
		ProbeFreshUntil: time.Now().Add(time.Minute),
		Resource:        preparer.resource,
	}, nil
}

type attemptCandidate struct {
	descriptor connectivity.CandidateDescriptor
	connection *attemptConnection
	dialDelay  time.Duration
	dials      atomic.Int64
	bindings   chan connectivity.Binding
}

func (candidate *attemptCandidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.descriptor
}

func (candidate *attemptCandidate) Dial(
	ctx context.Context,
	binding connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	candidate.dials.Add(1)
	if candidate.bindings != nil {
		select {
		case candidate.bindings <- binding:
		default:
		}
	}
	if candidate.dialDelay > 0 {
		timer := time.NewTimer(candidate.dialDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-timer.C:
		}
	}
	return candidate.connection, nil
}

type attemptConnection struct {
	health    chan error
	closed    atomic.Int64
	closeOnce sync.Once
}

func (*attemptConnection) FreshAWGHandshake(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*attemptConnection) VerifyBidirectional(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*attemptConnection) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*attemptConnection) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*attemptConnection) Commit(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (connection *attemptConnection) Health() <-chan error {
	return connection.health
}

func (connection *attemptConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.closed.Add(1)
		close(connection.health)
	})
	return nil
}

type attemptResource struct {
	closed atomic.Int64
}

func (resource *attemptResource) Close(context.Context) error {
	resource.closed.Add(1)
	return nil
}
