package connectivity

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCandidate struct {
	descriptor      CandidateDescriptor
	connection      CandidateConnection
	descriptorDelay time.Duration
	descriptorStart chan struct{}
	descriptorOnce  sync.Once
	descriptorBlock <-chan struct{}
	descriptors     atomic.Int32
	dialDelay       time.Duration
	dialBlock       <-chan struct{}
	dialError       error
	dials           atomic.Int32
}

func (candidate *fakeCandidate) Descriptor() CandidateDescriptor {
	candidate.descriptors.Add(1)
	candidate.descriptorOnce.Do(func() {
		if candidate.descriptorStart != nil {
			close(candidate.descriptorStart)
		}
	})
	if candidate.descriptorDelay > 0 {
		time.Sleep(candidate.descriptorDelay)
	}
	if candidate.descriptorBlock != nil {
		<-candidate.descriptorBlock
	}
	return candidate.descriptor
}

func (candidate *fakeCandidate) Dial(
	ctx context.Context,
	binding Binding,
) (CandidateConnection, error) {
	candidate.dials.Add(1)
	if candidate.dialBlock != nil {
		<-candidate.dialBlock
	}
	if err := binding.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	if candidate.dialDelay > 0 {
		timer := time.NewTimer(candidate.dialDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if candidate.dialError != nil {
		return nil, candidate.dialError
	}
	if recorder, ok := candidate.connection.(interface {
		setBinding(Binding)
	}); ok {
		recorder.setBinding(binding)
	}
	return candidate.connection, nil
}

type fakeConnection struct {
	delay              time.Duration
	handshakeBlock     <-chan struct{}
	handshakeError     error
	bidirectionalError error
	dnsError           error
	canaryError        error
	commitError        error
	commitBlock        <-chan struct{}
	closeError         error
	closeStarted       chan struct{}
	closeStartOnce     sync.Once
	closeBlock         <-chan struct{}
	commits            atomic.Int32
	closes             atomic.Int32
	activeChecks       atomic.Int32
	mu                 sync.Mutex
	bindings           []Binding
	healthOnce         sync.Once
	health             chan error
	healthMu           sync.Mutex
	healthClosed       bool
}

type retryableFakeConnection struct {
	*fakeConnection
	retries           atomic.Int32
	failuresRemaining atomic.Int32
}

func newRetryableFakeConnection(
	connection *fakeConnection,
) *retryableFakeConnection {
	return newRetryableFakeConnectionWithFailures(connection, 1)
}

func newRetryableFakeConnectionWithFailures(
	connection *fakeConnection,
	failures int32,
) *retryableFakeConnection {
	result := &retryableFakeConnection{fakeConnection: connection}
	result.failuresRemaining.Store(failures)
	return result
}

func (connection *retryableFakeConnection) RetryClose() error {
	connection.retries.Add(1)
	for {
		remaining := connection.failuresRemaining.Load()
		if remaining == 0 {
			return connection.fakeConnection.Close()
		}
		if connection.failuresRemaining.CompareAndSwap(
			remaining,
			remaining-1,
		) {
			return errors.New("synthetic transient teardown failure")
		}
	}
}

func (connection *fakeConnection) setBinding(binding Binding) {
	connection.mu.Lock()
	connection.bindings = append(connection.bindings, binding)
	connection.mu.Unlock()
}

func (connection *fakeConnection) wait(ctx context.Context) error {
	if connection.delay == 0 {
		return nil
	}
	timer := time.NewTimer(connection.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (connection *fakeConnection) check(
	ctx context.Context,
	binding Binding,
	result error,
) error {
	connection.activeChecks.Add(1)
	defer connection.activeChecks.Add(-1)
	if err := binding.Validate(time.Now().UTC()); err != nil {
		return err
	}
	if err := connection.wait(ctx); err != nil {
		return err
	}
	return result
}

func (connection *fakeConnection) FreshAWGHandshake(
	ctx context.Context,
	binding Binding,
) error {
	if connection.handshakeBlock != nil {
		<-connection.handshakeBlock
	}
	return connection.check(ctx, binding, connection.handshakeError)
}

func (connection *fakeConnection) VerifyBidirectional(
	ctx context.Context,
	binding Binding,
) error {
	return connection.check(ctx, binding, connection.bidirectionalError)
}

func (connection *fakeConnection) VerifyProtectedDNS(
	ctx context.Context,
	binding Binding,
) error {
	return connection.check(ctx, binding, connection.dnsError)
}

func (connection *fakeConnection) VerifyTunnelCanary(
	ctx context.Context,
	binding Binding,
) error {
	return connection.check(ctx, binding, connection.canaryError)
}

func (connection *fakeConnection) Commit(
	ctx context.Context,
	binding Binding,
) error {
	connection.commits.Add(1)
	if connection.commitBlock != nil {
		<-connection.commitBlock
	}
	return connection.check(ctx, binding, connection.commitError)
}

func (connection *fakeConnection) Health() <-chan error {
	connection.healthOnce.Do(func() {
		connection.health = make(chan error, 1)
	})
	return connection.health
}

func (connection *fakeConnection) failHealth(err error) {
	connection.Health()
	connection.healthMu.Lock()
	if !connection.healthClosed {
		connection.health <- err
		close(connection.health)
		connection.healthClosed = true
	}
	connection.healthMu.Unlock()
}

func (connection *fakeConnection) Close() error {
	connection.closes.Add(1)
	connection.closeStartOnce.Do(func() {
		if connection.closeStarted != nil {
			close(connection.closeStarted)
		}
	})
	if connection.closeBlock != nil {
		<-connection.closeBlock
	}
	connection.Health()
	connection.healthMu.Lock()
	if !connection.healthClosed {
		close(connection.health)
		connection.healthClosed = true
	}
	connection.healthMu.Unlock()
	return connection.closeError
}

func TestCoordinatorPublishesOnlineOnlyAfterEveryPredicate(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{delay: 5 * time.Millisecond}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "h3-primary",
			Carrier:   CarrierHTTP3,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeAuto, candidate)
	coordinator := NewCoordinator()
	result := coordinator.Connect(context.Background(), request)
	if !result.Success() {
		t.Fatalf("connection result = %#v", result)
	}
	if result.CandidateID != "h3-primary" ||
		connection.commits.Load() != 1 ||
		connection.closes.Load() != 0 {
		t.Fatalf(
			"winner = %q, commits = %d, closes = %d",
			result.CandidateID,
			connection.commits.Load(),
			connection.closes.Load(),
		)
	}
	coordinator.Stop()
	if connection.closes.Load() != 1 {
		t.Fatalf("winner close count = %d, want 1", connection.closes.Load())
	}
}

func TestCoordinatorRejectsDNSFailureAndCleansCandidate(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{dnsError: errors.New("leak blocked")}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "h3-primary",
			Carrier:   CarrierHTTP3,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	result := NewCoordinator().Connect(
		context.Background(),
		validRequest(now, ModeAuto, candidate),
	)
	if result.Success() ||
		result.Failure != FailureDNSVerificationFailed ||
		connection.commits.Load() != 0 ||
		connection.closes.Load() != 1 {
		t.Fatalf("DNS failure result = %#v", result)
	}
}

func TestCoordinatorRacesCandidatesAndClosesLoser(t *testing.T) {
	now := time.Now().UTC()
	slowConnection := &fakeConnection{delay: 100 * time.Millisecond}
	fastConnection := &fakeConnection{delay: time.Millisecond}
	slow := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct-slow",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: slowConnection,
	}
	fast := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "h3-fast",
			Carrier:   CarrierHTTP3,
			NodeID:    "node-2",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: fastConnection,
	}
	request := validRequest(now, ModeAuto, slow, fast)
	coordinator := NewCoordinator()
	result := coordinator.Connect(context.Background(), request)
	if !result.Success() || result.CandidateID != "h3-fast" {
		t.Fatalf("race result = %#v", result)
	}
	deadline := time.Now().Add(time.Second)
	for slowConnection.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if slowConnection.closes.Load() != 1 {
		t.Fatalf(
			"loser close count = %d, want 1",
			slowConnection.closes.Load(),
		)
	}
	coordinator.Stop()
}

func TestCoordinatorEnforcesHardDeadline(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{delay: time.Second}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 30 * time.Millisecond
	started := time.Now()
	result := NewCoordinator().Connect(context.Background(), request)
	elapsed := time.Since(started)
	if result.Failure != FailureConnectDeadlineExceeded {
		t.Fatalf("deadline failure = %q", result.Failure)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("deadline result took %s", elapsed)
	}
	if connection.closes.Load() != 1 {
		t.Fatalf("deadline candidate close count = %d", connection.closes.Load())
	}
}

func TestCoordinatorDeadlineCannotBeHeldByHungCandidateClose(
	t *testing.T,
) {
	now := time.Now().UTC()
	release := make(chan struct{})
	connection := &fakeConnection{
		delay:      time.Second,
		closeBlock: release,
	}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 20 * time.Millisecond
	started := time.Now()
	result := NewCoordinator().Connect(context.Background(), request)
	elapsed := time.Since(started)
	close(release)
	if result.Failure != FailureTeardownFailed {
		t.Fatalf("hung-close failure = %q", result.Failure)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("hung candidate Close held Connect for %s", elapsed)
	}
	if connection.closes.Load() != 1 {
		t.Fatalf(
			"hung candidate close count = %d, want 1",
			connection.closes.Load(),
		)
	}
}

func TestCoordinatorAbandonedVerificationRetainsCloseOwner(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	connection := &fakeConnection{
		handshakeBlock: release,
		closeStarted:   make(chan struct{}),
	}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 40 * time.Millisecond
	coordinator := NewCoordinator()
	result := coordinator.Connect(context.Background(), request)
	if result.Failure != FailureTeardownFailed {
		t.Fatalf("abandoned verification result = %#v", result)
	}
	select {
	case <-connection.closeStarted:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("abandoned verification lost its connection close owner")
	}
	close(release)
	retry := coordinator.Connect(context.Background(), request)
	if retry.Failure != FailureTeardownFailed {
		t.Fatalf("abandoned verification retry = %#v", retry)
	}
}

func TestCoordinatorDeadlineCannotBeHeldByHungCommit(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	connection := &fakeConnection{commitBlock: release}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 30 * time.Millisecond
	coordinator := NewCoordinator()
	started := time.Now()
	result := coordinator.Connect(context.Background(), request)
	elapsed := time.Since(started)
	close(release)
	if result.Failure != FailureTeardownFailed {
		t.Fatalf("hung-commit result = %#v", result)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("hung Commit held Connect for %s", elapsed)
	}
	if connection.commits.Load() != 1 ||
		connection.closes.Load() != 1 {
		t.Fatalf(
			"commits=%d closes=%d, want 1/1",
			connection.commits.Load(),
			connection.closes.Load(),
		)
	}
	deadline := time.Now().Add(time.Second)
	for connection.closes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if connection.closes.Load() != 2 {
		t.Fatalf(
			"late Commit close count = %d, want 2",
			connection.closes.Load(),
		)
	}
	retry := coordinator.Connect(context.Background(), request)
	if retry.Failure != FailureTeardownFailed ||
		connection.commits.Load() != 1 {
		t.Fatalf("poisoned retry = %#v", retry)
	}
}

func TestCoordinatorFailedVerificationRetriesTransientTeardown(t *testing.T) {
	now := time.Now().UTC()
	connection := newRetryableFakeConnectionWithFailures(
		&fakeConnection{
			handshakeError: errors.New("synthetic handshake failure"),
		},
		3,
	)
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	result := NewCoordinator().Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if result.Failure != FailureHandshakeFailed {
		t.Fatalf("verification failure = %#v", result)
	}
	if got := connection.retries.Load(); got != 4 {
		t.Fatalf("teardown retries = %d, want 4", got)
	}
	if got := connection.closes.Load(); got != 1 {
		t.Fatalf("successful teardown closes = %d, want 1", got)
	}
}

func TestCoordinatorTeardownOwnerSurvivesCallerDeadline(t *testing.T) {
	now := time.Now().UTC()
	connection := newRetryableFakeConnectionWithFailures(
		&fakeConnection{
			handshakeError: errors.New("synthetic handshake failure"),
		},
		3,
	)
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 20 * time.Millisecond
	started := time.Now()
	result := NewCoordinator().Connect(context.Background(), request)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("bounded Connect() took %s", elapsed)
	}
	if result.Failure != FailureTeardownFailed {
		t.Fatalf("deadline teardown result = %#v", result)
	}
	deadline := time.Now().Add(time.Second)
	for connection.closes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := connection.retries.Load(); got != 4 {
		t.Fatalf("persistent owner retry count = %d, want 4", got)
	}
	if got := connection.closes.Load(); got != 1 {
		t.Fatalf("persistent owner successful closes = %d, want 1", got)
	}
}

func TestCoordinatorStopRetriesTransientTeardown(t *testing.T) {
	now := time.Now().UTC()
	connection := newRetryableFakeConnection(&fakeConnection{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	coordinator := NewCoordinator()
	result := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if result.State != StateOnline || result.Failure != FailureNone {
		t.Fatalf("connect result = %#v", result)
	}
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if got := connection.retries.Load(); got != 2 {
		t.Fatalf("stop teardown retries = %d, want 2", got)
	}
	if got := connection.closes.Load(); got != 1 {
		t.Fatalf("successful stop closes = %d, want 1", got)
	}
}

func TestCoordinatorLoserCleanupDoesNotDiscardVerifiedWinner(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	winnerConnection := &fakeConnection{
		closeStarted: make(chan struct{}),
	}
	winner := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "winner",
			Carrier:   CarrierHTTP3,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: winnerConnection,
	}
	candidates := []*fakeCandidate{winner}
	var losers []*fakeConnection
	for index := 0; index < 3; index++ {
		connection := &fakeConnection{
			delay:      time.Second,
			closeBlock: release,
		}
		losers = append(losers, connection)
		candidates = append(candidates, &fakeCandidate{
			descriptor: CandidateDescriptor{
				ID:        fmt.Sprintf("loser-%d", index),
				Carrier:   CarrierHTTP3,
				NodeID:    fmt.Sprintf("node-%d", index+2),
				ExpiresAt: now.Add(time.Minute),
			},
			connection: connection,
		})
	}
	request := validRequest(now, ModeAuto, candidates...)
	coordinator := NewCoordinator()
	started := time.Now()
	result := coordinator.Connect(context.Background(), request)
	elapsed := time.Since(started)
	if !result.Success() || result.CandidateID != "winner" {
		t.Fatalf("verified winner result = %#v", result)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("loser cleanup delayed winner commit: %s", elapsed)
	}
	select {
	case <-winnerConnection.closeStarted:
		t.Fatal("slow loser cleanup discarded the verified winner")
	default:
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		started := true
		for _, loser := range losers {
			if loser.closes.Load() == 0 {
				started = false
			}
		}
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for index, loser := range losers {
		if loser.closes.Load() != 1 {
			t.Fatalf(
				"loser %d teardown owners = %d, want 1",
				index,
				loser.closes.Load(),
			)
		}
	}
	close(release)
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestCoordinatorAllowsRealisticLoserTeardownInsideThreeSecondBudget(
	t *testing.T,
) {
	now := time.Now().UTC()
	closeStarted := make(chan struct{})
	releaseClose := make(chan struct{})
	loserConnection := &fakeConnection{
		delay:        time.Second,
		closeStarted: closeStarted,
		closeBlock:   releaseClose,
	}
	winnerConnection := &fakeConnection{}
	winner := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "winner",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: winnerConnection,
	}
	loser := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "losing-real-awg",
			Carrier:   CarrierHTTP3,
			NodeID:    "node-2",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: loserConnection,
	}
	go func() {
		<-closeStarted
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		close(releaseClose)
	}()

	request := validRequest(now, ModeAuto, winner, loser)
	request.Deadline = DefaultDeadline
	coordinator := NewCoordinator()
	started := time.Now()
	result := coordinator.Connect(context.Background(), request)
	elapsed := time.Since(started)
	if !result.Success() || result.CandidateID != "winner" {
		t.Fatalf("connect result = %#v", result)
	}
	if elapsed >= DefaultDeadline {
		t.Fatalf("connect exceeded absolute three-second budget: %s", elapsed)
	}
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("loser did not retain a detached teardown owner")
	}
	if loserConnection.closes.Load() != 1 {
		t.Fatalf(
			"loser close count = %d, want 1",
			loserConnection.closes.Load(),
		)
	}
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("stop winner: %v", err)
	}
}

func TestCoordinatorRejectsModeDowngradeBeforeDial(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeStealth, candidate)
	// Preserve a structurally valid readiness record, then replace only the
	// concrete candidate to prove request validation catches substitution.
	request.Readiness.Candidates[0].Carrier = CarrierRealityXHTTP
	result := NewCoordinator().Connect(context.Background(), request)
	if result.Failure != FailureModePolicyViolation &&
		!strings.Contains(string(result.Failure), "mode") {
		t.Fatalf("mode downgrade result = %#v", result)
	}
	if connection.commits.Load() != 0 || connection.closes.Load() != 0 {
		t.Fatal("mode downgrade reached candidate connection")
	}
}

func TestCoordinatorFailedPrivacyTransitionClosesOldTunnel(t *testing.T) {
	now := time.Now().UTC()
	oldConnection := &fakeConnection{}
	oldCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "h3-old",
			Carrier:   CarrierHTTP3,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: oldConnection,
	}
	coordinator := NewCoordinator()
	oldResult := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeAuto, oldCandidate),
	)
	if !oldResult.Success() {
		t.Fatalf("initial result = %#v", oldResult)
	}

	privacyConnection := &fakeConnection{
		canaryError: errors.New("privacy canary failed"),
	}
	privacyCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "privacy-new",
			Carrier:   CarrierPrivacyTwoHop,
			NodeID:    "entry-2",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: privacyConnection,
	}
	privacyResult := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeMaximumPrivacy, privacyCandidate),
	)
	if privacyResult.Success() ||
		privacyResult.Failure != FailureCanaryFailed {
		t.Fatalf("privacy transition result = %#v", privacyResult)
	}
	if oldConnection.closes.Load() != 1 {
		t.Fatalf(
			"old tunnel close count = %d",
			oldConnection.closes.Load(),
		)
	}
	status := coordinator.Status()
	if status.State != StateFailed || status.CandidateID != "" {
		t.Fatalf("post-transition status = %#v", status)
	}
}

func TestCoordinatorReusesOnlyIdenticalTrustFingerprint(t *testing.T) {
	now := time.Now().UTC()
	firstConnection := &fakeConnection{}
	descriptor := CandidateDescriptor{
		ID:        "h3-primary",
		Carrier:   CarrierHTTP3,
		NodeID:    "entry-1",
		ExpiresAt: now.Add(time.Minute),
	}
	firstCandidate := &fakeCandidate{
		descriptor: descriptor,
		connection: firstConnection,
	}
	coordinator := NewCoordinator()
	request := validRequest(now, ModeAuto, firstCandidate)
	first := coordinator.Connect(context.Background(), request)
	reused := coordinator.Connect(context.Background(), request)
	if !first.Success() || reused.AttemptID != first.AttemptID ||
		len(first.TrustFingerprint) != 64 ||
		firstConnection.commits.Load() != 1 {
		t.Fatalf("active reuse: first=%#v reused=%#v", first, reused)
	}

	secondConnection := &fakeConnection{}
	secondCandidate := &fakeCandidate{
		descriptor: descriptor,
		connection: secondConnection,
	}
	rotated := request
	rotated.Readiness.PSKGeneration++
	rotated.Candidates = []Candidate{secondCandidate}
	second := coordinator.Connect(context.Background(), rotated)
	if !second.Success() ||
		second.AttemptID == first.AttemptID ||
		second.TrustFingerprint == first.TrustFingerprint ||
		firstConnection.closes.Load() != 1 ||
		secondConnection.commits.Load() != 1 {
		t.Fatalf("rotated trust result = %#v", second)
	}
	coordinator.Stop()
}

func TestCoordinatorStopCannotBeUndoneByLateAttempt(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{delay: 200 * time.Millisecond}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	coordinator := NewCoordinator()
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- coordinator.Connect(
			context.Background(), request,
		)
	}()
	waitForBinding(t, connection)
	coordinator.Stop()
	result := <-resultChannel
	if result.Failure != FailureStoppedByUser ||
		coordinator.Status().State != StateStopped ||
		connection.commits.Load() != 0 ||
		connection.activeChecks.Load() != 0 {
		t.Fatalf(
			"stopped result=%#v status=%#v checks=%d",
			result,
			coordinator.Status(),
			connection.activeChecks.Load(),
		)
	}
	late := coordinator.Connect(context.Background(), request)
	if late.Failure != FailureStoppedByUser ||
		connection.commits.Load() != 0 {
		t.Fatalf("late connect result = %#v", late)
	}
}

func TestCoordinatorDeadlineIncludesDescriptorValidation(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection:      connection,
		descriptorDelay: 150 * time.Millisecond,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 20 * time.Millisecond
	started := time.Now()
	result := NewCoordinator().Connect(context.Background(), request)
	if result.Failure != FailureConnectDeadlineExceeded {
		t.Fatalf("validation deadline result = %#v", result)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("validation deadline took %s", elapsed)
	}
	connection.mu.Lock()
	dials := len(connection.bindings)
	connection.mu.Unlock()
	if dials != 0 {
		t.Fatal("deadline-expired descriptor reached Dial")
	}
}

func TestCoordinatorPoisonsAfterPermanentlyBlockedDescriptor(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection:      &fakeConnection{},
		descriptorBlock: release,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 20 * time.Millisecond
	coordinator := NewCoordinator()
	first := coordinator.Connect(context.Background(), request)
	if first.Failure != FailureConnectDeadlineExceeded {
		t.Fatalf("blocked descriptor result = %#v", first)
	}
	started := time.Now()
	second := coordinator.Connect(context.Background(), request)
	elapsed := time.Since(started)
	close(release)
	if second.Failure != FailureTeardownFailed {
		t.Fatalf("poisoned descriptor retry = %#v", second)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("poisoned retry took %s", elapsed)
	}
	if candidate.descriptors.Load() != 1 ||
		candidate.dials.Load() != 0 {
		t.Fatalf(
			"descriptors=%d dials=%d, want 1/0",
			candidate.descriptors.Load(),
			candidate.dials.Load(),
		)
	}
}

func TestCoordinatorSerializesConcurrentBlockedDescriptors(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	started := make(chan struct{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection:      &fakeConnection{},
		descriptorStart: started,
		descriptorBlock: release,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 30 * time.Millisecond
	coordinator := NewCoordinator()
	const callers = 12
	results := make(chan Result, callers)
	for range callers {
		go func() {
			results <- coordinator.Connect(context.Background(), request)
		}()
	}
	<-started
	for range callers {
		result := <-results
		if result.Failure != FailureConnectDeadlineExceeded &&
			result.Failure != FailureTeardownFailed {
			t.Fatalf("concurrent descriptor result = %#v", result)
		}
	}
	close(release)
	if candidate.descriptors.Load() != 1 {
		t.Fatalf(
			"descriptor calls = %d, want exactly 1",
			candidate.descriptors.Load(),
		)
	}
}

func TestCoordinatorStopCancelsDescriptorValidation(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	started := make(chan struct{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection:      &fakeConnection{},
		descriptorStart: started,
		descriptorBlock: release,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = time.Second
	coordinator := NewCoordinator()
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- coordinator.Connect(context.Background(), request)
	}()
	<-started
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop during validation = %v", err)
	}
	select {
	case result := <-resultChannel:
		if result.Failure != FailureStoppedByUser {
			t.Fatalf("validation stop result = %#v", result)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Stop did not release Connect from descriptor validation")
	}
	close(release)
}

func TestCoordinatorPoisonsAfterPermanentlyBlockedDial(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: &fakeConnection{},
		dialBlock:  release,
	}
	request := validRequest(now, ModeFast, candidate)
	request.Deadline = 20 * time.Millisecond
	coordinator := NewCoordinator()
	first := coordinator.Connect(context.Background(), request)
	if first.Failure != FailureTeardownFailed {
		t.Fatalf("blocked Dial result = %#v", first)
	}
	second := coordinator.Connect(context.Background(), request)
	close(release)
	if second.Failure != FailureTeardownFailed ||
		candidate.dials.Load() != 1 {
		t.Fatalf(
			"poisoned Dial retry=%#v dials=%d",
			second,
			candidate.dials.Load(),
		)
	}
}

func TestCoordinatorStopTracksFailedConnectionUntilClosed(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	connection := &fakeConnection{
		handshakeError: errors.New("handshake failed"),
		closeStarted:   make(chan struct{}),
		closeBlock:     release,
	}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	coordinator := NewCoordinator()
	connectDone := make(chan Result, 1)
	go func() {
		connectDone <- coordinator.Connect(
			context.Background(),
			validRequest(now, ModeFast, candidate),
		)
	}()
	select {
	case <-connection.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("failed connection teardown did not start")
	}
	stopDone := make(chan error, 1)
	go func() { stopDone <- coordinator.Stop() }()
	select {
	case err := <-stopDone:
		t.Fatalf("Stop returned before failed connection closed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-connectDone:
	case <-time.After(time.Second):
		t.Fatal("Connect did not finish after failed teardown")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop after successful teardown = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after failed connection teardown")
	}
}

func TestCoordinatorSnapshotsRequestBeforeAsyncValidation(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{}
	started := make(chan struct{})
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection:      connection,
		descriptorDelay: 20 * time.Millisecond,
		descriptorStart: started,
	}
	request := validRequest(now, ModeFast, candidate)
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- NewCoordinator().Connect(
			context.Background(),
			request,
		)
	}()
	<-started
	request.Readiness.Candidates[0].ID = "mutated"
	request.Readiness.Blockers = append(
		request.Readiness.Blockers,
		FailureNotReady,
	)
	request.Candidates[0] = nil
	result := <-resultChannel
	if !result.Success() {
		t.Fatalf("snapshotted request result = %#v", result)
	}
}

func TestCoordinatorCoalescesIdenticalConcurrentConnect(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{delay: 40 * time.Millisecond}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	coordinator := NewCoordinator()
	firstDone := make(chan Result, 1)
	go func() {
		firstDone <- coordinator.Connect(context.Background(), request)
	}()
	waitForBinding(t, connection)
	second := coordinator.Connect(context.Background(), request)
	first := <-firstDone
	if !first.Success() || !second.Success() ||
		first.AttemptID != second.AttemptID ||
		connection.commits.Load() != 1 {
		t.Fatalf(
			"coalesced results first=%#v second=%#v commits=%d",
			first,
			second,
			connection.commits.Load(),
		)
	}
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop after coalesced connect = %v", err)
	}
}

func TestCoordinatorRejectsNilSuccessfulDial(t *testing.T) {
	now := time.Now().UTC()
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
	}
	result := NewCoordinator().Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if result.Failure != FailureNoReachableCandidate {
		t.Fatalf("nil connection result = %#v", result)
	}
}

func TestCoordinatorRevokesOnlineStateOnHealthFailure(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	coordinator := NewCoordinator()
	result := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if !result.Success() {
		t.Fatalf("online result = %#v", result)
	}
	connection.failHealth(errors.New("relay failed"))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := coordinator.Status()
		if status.Failure == FailurePostCommitHealth {
			if status.State != StateFailed {
				t.Fatalf(
					"health failure status=%#v closes=%d",
					status,
					connection.closes.Load(),
				)
			}
			if connection.closes.Load() == 1 {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("health failure was not published: %#v", coordinator.Status())
}

func TestCoordinatorWaitsForHealthTeardownBeforeReconnect(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	oldConnection := &fakeConnection{
		closeStarted: make(chan struct{}),
		closeBlock:   release,
	}
	oldCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "old",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: oldConnection,
	}
	coordinator := NewCoordinator()
	first := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, oldCandidate),
	)
	if !first.Success() {
		t.Fatalf("initial connect = %#v", first)
	}
	oldConnection.failHealth(errors.New("old path failed"))
	select {
	case <-oldConnection.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("old health teardown did not start")
	}

	newConnection := &fakeConnection{}
	newCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "new",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-2",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: newConnection,
	}
	reconnectDone := make(chan Result, 1)
	go func() {
		reconnectDone <- coordinator.Connect(
			context.Background(),
			validRequest(now, ModeFast, newCandidate),
		)
	}()
	select {
	case result := <-reconnectDone:
		t.Fatalf("reconnect overlapped health teardown: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
	if newCandidate.descriptors.Load() != 0 ||
		newConnection.commits.Load() != 0 {
		t.Fatal("reconnect reached new candidate before old teardown")
	}
	close(release)
	select {
	case result := <-reconnectDone:
		if !result.Success() {
			t.Fatalf("reconnect after teardown = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect did not resume after health teardown")
	}
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop after reconnect = %v", err)
	}
}

func TestCoordinatorHealthTeardownFailurePoisonsWaitingReconnect(
	t *testing.T,
) {
	now := time.Now().UTC()
	release := make(chan struct{})
	oldConnection := &fakeConnection{
		closeStarted: make(chan struct{}),
		closeBlock:   release,
		closeError:   errors.New("route rollback failed"),
	}
	oldCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "old",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: oldConnection,
	}
	coordinator := NewCoordinator()
	if result := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, oldCandidate),
	); !result.Success() {
		t.Fatalf("initial connect = %#v", result)
	}
	oldConnection.failHealth(errors.New("old path failed"))
	<-oldConnection.closeStarted

	newConnection := &fakeConnection{}
	newCandidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "new",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-2",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: newConnection,
	}
	reconnectDone := make(chan Result, 1)
	go func() {
		reconnectDone <- coordinator.Connect(
			context.Background(),
			validRequest(now, ModeFast, newCandidate),
		)
	}()
	close(release)
	result := <-reconnectDone
	if result.Failure != FailureTeardownFailed ||
		newCandidate.descriptors.Load() != 0 ||
		newConnection.commits.Load() != 0 {
		t.Fatalf(
			"poisoned reconnect=%#v descriptors=%d commits=%d",
			result,
			newCandidate.descriptors.Load(),
			newConnection.commits.Load(),
		)
	}
	if err := coordinator.Stop(); err == nil {
		t.Fatal("Stop hid health teardown failure")
	}
}

func TestCoordinatorSurfacesTeardownFailure(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{closeError: errors.New("route rollback")}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	coordinator := NewCoordinator()
	result := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if !result.Success() {
		t.Fatalf("online result = %#v", result)
	}
	if err := coordinator.Stop(); err == nil {
		t.Fatal("Stop hid teardown failure")
	}
}

func TestCoordinatorStopWaitsForHealthTriggeredTeardown(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	connection := &fakeConnection{
		closeStarted: make(chan struct{}),
		closeBlock:   release,
		closeError:   errors.New("health rollback failed"),
	}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "entry-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	coordinator := NewCoordinator()
	result := coordinator.Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if !result.Success() {
		t.Fatalf("online result = %#v", result)
	}
	connection.failHealth(errors.New("relay failed"))
	select {
	case <-connection.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("health-triggered teardown did not start")
	}
	stopped := make(chan error, 1)
	go func() {
		stopped <- coordinator.Stop()
	}()
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned before teardown completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopped:
		if err == nil {
			t.Fatal("Stop hid health-triggered teardown failure")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not finish after teardown")
	}
}

func TestCoordinatorIdentityEntropyFailureIsNotReady(t *testing.T) {
	previous := attemptEntropy
	t.Cleanup(func() { attemptEntropy = previous })
	attemptEntropy = func([]byte) (int, error) {
		return 0, errors.New("synthetic entropy failure")
	}
	now := time.Now().UTC()
	connection := &fakeConnection{}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-1",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	result := NewCoordinator().Connect(
		context.Background(),
		validRequest(now, ModeFast, candidate),
	)
	if result.Failure != FailureNotReady {
		t.Fatalf(
			"entropy failure = %q, want %q (must not look like an unreachable path)",
			result.Failure, FailureNotReady,
		)
	}
	if len(result.AttemptID) != 32 {
		t.Fatalf("entropy failure attempt ID = %q", result.AttemptID)
	}
	if connection.commits.Load() != 0 || connection.closes.Load() != 0 {
		t.Fatal("entropy failure reached a candidate connection")
	}
}

func TestCoordinatorEarlyFailureHasEvidenceAttemptID(t *testing.T) {
	request := ConnectRequest{Deadline: -time.Second}
	request.Readiness.Profile = "default"
	request.Readiness.Mode = ModeAuto
	result := NewCoordinator().Connect(context.Background(), request)
	if len(result.AttemptID) != 32 {
		t.Fatalf("early failure attempt ID = %q", result.AttemptID)
	}
	if len(result.TrustFingerprint) != 64 {
		t.Fatalf(
			"early failure trust fingerprint = %q",
			result.TrustFingerprint,
		)
	}
}

func TestCoordinatorCopiesExactReservedColdBinding(t *testing.T) {
	now := time.Now().UTC()
	connection := &fakeConnection{}
	candidate := &fakeCandidate{
		descriptor: CandidateDescriptor{
			ID:        "direct-cold",
			Carrier:   CarrierDirectAWG,
			NodeID:    "node-cold",
			ExpiresAt: now.Add(time.Minute),
		},
		connection: connection,
	}
	request := validRequest(now, ModeFast, candidate)
	request.AttemptID = strings.Repeat("a", 32)
	request.Nonce = strings.Repeat("b", 32)
	reserved := Binding{
		AttemptID:      request.AttemptID,
		Profile:        request.Readiness.Profile,
		Mode:           request.Readiness.Mode,
		ManifestDigest: request.Readiness.ManifestDigest,
		CandidateID:    candidate.descriptor.ID,
		NodeID:         candidate.descriptor.NodeID,
		SessionID:      request.SessionID,
		PSKGeneration:  request.Readiness.PSKGeneration,
		SequenceEpoch:  request.SequenceEpoch,
		Nonce:          request.Nonce,
		ExpiresAt:      now.Add(700 * time.Millisecond),
	}
	request.ReservedBindings = []Binding{reserved}
	coordinator := NewCoordinator()
	result := coordinator.Connect(context.Background(), request)
	if !result.Success() || result.AttemptID != request.AttemptID {
		t.Fatalf("reserved cold result = %#v", result)
	}
	connection.mu.Lock()
	if len(connection.bindings) == 0 ||
		connection.bindings[0] != reserved {
		got := append([]Binding(nil), connection.bindings...)
		connection.mu.Unlock()
		t.Fatalf("candidate bindings = %#v, want exact %#v", got, reserved)
	}
	connection.mu.Unlock()
	if err := coordinator.Stop(); err != nil {
		t.Fatal(err)
	}

	mutated := request
	mutated.ReservedBindings = slices.Clone(request.ReservedBindings)
	mutated.ReservedBindings[0].Nonce = strings.Repeat("c", 32)
	failed := NewCoordinator().Connect(context.Background(), mutated)
	if failed.Success() || failed.Failure != FailureNotReady {
		t.Fatalf("mutated cold binding result = %#v", failed)
	}
}

func waitForBinding(t *testing.T, connection *fakeConnection) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		connection.mu.Lock()
		count := len(connection.bindings)
		connection.mu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("candidate Dial was not reached")
}

func validRequest(
	now time.Time,
	mode Mode,
	candidates ...*fakeCandidate,
) ConnectRequest {
	descriptors := make([]CandidateDescriptor, 0, len(candidates))
	interfaces := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		descriptors = append(descriptors, candidate.descriptor)
		interfaces = append(interfaces, candidate)
	}
	return ConnectRequest{
		Readiness:     validReadiness(now, mode, descriptors),
		Candidates:    interfaces,
		SessionID:     strings.Repeat("1", 32),
		SequenceEpoch: 1,
		Deadline:      time.Second,
	}
}
