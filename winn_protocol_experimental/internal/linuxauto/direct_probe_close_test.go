package linuxauto

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/preparation"
)

func TestRunConcurrentBindingChecksWaitsAndCancelsOnFailure(t *testing.T) {
	binding := coldDirectTestBinding(time.Now().UTC())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var siblingCause error
	go func() {
		done <- runConcurrentBindingChecks(
			context.Background(),
			binding,
			[]bindingProbeCheck{
				{
					name: "protected DNS",
					run: func(context.Context, connectivity.Binding) error {
						return errors.New("dns failed")
					},
				},
				{
					name: "tunnel canary",
					run: func(ctx context.Context, _ connectivity.Binding) error {
						close(started)
						<-release
						siblingCause = context.Cause(ctx)
						return siblingCause
					},
				},
			},
		)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sibling probe did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("returned while sibling still blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	err := <-done
	if err == nil {
		t.Fatal("failed concurrent probe returned nil")
	}
	if siblingCause == nil {
		t.Fatal("sibling probe was not cancelled")
	}
}

func TestRunConcurrentBindingChecksRejectsEmptySet(t *testing.T) {
	if err := runConcurrentBindingChecks(
		context.Background(),
		coldDirectTestBinding(time.Now().UTC()),
		nil,
	); err == nil {
		t.Fatal("empty concurrent probe set succeeded")
	}
}

func TestNewLiveDirectProbeDefaultsAndRejectsSocketBuffers(t *testing.T) {
	probe, err := NewLiveDirectProbe(LiveDirectProbeConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return nil, errors.New("not used")
		},
	})
	if err != nil || probe == nil {
		t.Fatalf("zero SocketBufferBytes rejected: %v", err)
	}
	if _, err := NewLiveDirectProbe(LiveDirectProbeConfig{
		ControllerFactory: func(
			context.Context,
			preparation.DirectAWGPreparationInput,
		) (directawg.TunnelController, error) {
			return nil, errors.New("not used")
		},
		SocketBufferBytes: carrier.MaxRelaySocketBufferBytes + 1,
	}); err == nil {
		t.Fatal("oversized live DirectAWG socket buffer was accepted")
	}
}

func TestLiveDirectProbeCloseOwnerRecoversTransientTeardown(t *testing.T) {
	connection := newProbeCloseConnection(3)
	owner := newLiveDirectProbeCloseOwner(connection)
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := connection.callCount(); got != 4 {
		t.Fatalf("teardown calls = %d, want 4", got)
	}
}

func TestLiveDirectProbeCloseOwnerSurvivesCallerDeadline(t *testing.T) {
	connection := newProbeCloseConnection(0)
	connection.block = make(chan struct{})
	owner := newLiveDirectProbeCloseOwner(connection)
	ctx, cancel := context.WithTimeout(
		context.Background(), 25*time.Millisecond,
	)
	defer cancel()
	if err := owner.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded close error = %v, want deadline exceeded", err)
	}
	close(connection.block)
	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("caller-independent teardown owner did not finish")
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPreconnectedDirectCandidateClaimsExactBindingOnce(
	t *testing.T,
) {
	now := time.Now().UTC()
	binding := coldDirectTestBinding(now)
	underlying := newProbeCloseConnection(0)
	state := &preconnectedDirectState{
		descriptor: connectivity.CandidateDescriptor{
			ID:        binding.CandidateID,
			Carrier:   connectivity.CarrierDirectAWG,
			NodeID:    binding.NodeID,
			ExpiresAt: now.Add(time.Minute),
		},
		binding:    binding,
		connection: underlying,
		closeOwner: newLiveDirectProbeCloseOwner(underlying),
		provedAt:   now,
		now:        func() time.Time { return now },
	}
	candidate := &preconnectedDirectCandidate{state: state}
	const callers = 100
	results := make(chan connectivity.CandidateConnection, callers)
	failures := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			connection, err := candidate.Dial(
				context.Background(),
				binding,
			)
			if err != nil {
				failures <- err
				return
			}
			results <- connection
		}()
	}
	group.Wait()
	close(results)
	close(failures)
	if len(results) != 1 || len(failures) != callers-1 {
		t.Fatalf(
			"claim successes=%d failures=%d",
			len(results),
			len(failures),
		)
	}
	connection := <-results
	if err := connection.FreshAWGHandshake(
		context.Background(), binding,
	); err != nil {
		t.Fatal(err)
	}
	mutated := binding
	mutated.Nonce = strings.Repeat("f", 32)
	if err := connection.VerifyTunnelCanary(
		context.Background(), mutated,
	); err == nil {
		t.Fatal("cached predicate accepted a different binding")
	}
	if err := connection.Commit(
		context.Background(), binding,
	); err != nil {
		t.Fatal(err)
	}
	resource := &preconnectedDirectResource{state: state}
	if err := resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := underlying.callCount(); got != 1 {
		t.Fatalf("shared close calls = %d, want 1", got)
	}
}

func TestPreconnectedDirectCandidateWrongBindingDoesNotConsume(
	t *testing.T,
) {
	now := time.Now().UTC()
	binding := coldDirectTestBinding(now)
	underlying := newProbeCloseConnection(0)
	state := &preconnectedDirectState{
		descriptor: connectivity.CandidateDescriptor{
			ID:        binding.CandidateID,
			Carrier:   connectivity.CarrierDirectAWG,
			NodeID:    binding.NodeID,
			ExpiresAt: binding.ExpiresAt,
		},
		binding:    binding,
		connection: underlying,
		closeOwner: newLiveDirectProbeCloseOwner(underlying),
		provedAt:   now,
		now:        func() time.Time { return now },
	}
	candidate := &preconnectedDirectCandidate{state: state}
	mutated := binding
	mutated.AttemptID = strings.Repeat("e", 32)
	if _, err := candidate.Dial(
		context.Background(), mutated,
	); err == nil {
		t.Fatal("different binding was claimed")
	}
	if _, err := candidate.Dial(
		context.Background(), binding,
	); err != nil {
		t.Fatalf("wrong binding consumed candidate: %v", err)
	}
	if err := (&preconnectedDirectResource{state: state}).Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
}

// A cold predicate proof is only consumable while it is still fresh. Without
// this bound a proof taken early in the click budget could be spent much later
// in it, with no evidence the tunnel survived the interval.
func TestPreverifiedDirectConnectionRejectsStaleProof(t *testing.T) {
	now := time.Now().UTC()
	binding := coldDirectTestBinding(now)
	underlying := newProbeCloseConnection(0)
	connection := &preverifiedDirectConnection{
		binding:    binding,
		connection: underlying,
		provedAt:   now.Add(-coldPredicateFreshness - time.Millisecond),
		now:        func() time.Time { return now },
	}
	if err := connection.FreshAWGHandshake(
		context.Background(), binding,
	); err == nil {
		t.Fatal("a stale cold predicate proof was accepted")
	}
	if err := connection.Commit(
		context.Background(), binding,
	); err == nil {
		t.Fatal("a stale cold predicate proof reached commit")
	}
}

// The four cold predicates are cached, so a tunnel that dies between proof and
// claim would otherwise report four successes, win the race, and only fail at
// Commit — which the frozen v2 gate counts as a zero-tolerance security
// failure. Every cached predicate and Commit must fail closed instead.
func TestPreverifiedDirectConnectionRejectsLostHealth(t *testing.T) {
	now := time.Now().UTC()
	binding := coldDirectTestBinding(now)
	underlying := newProbeCloseConnection(0)
	close(underlying.health)
	connection := &preverifiedDirectConnection{
		binding:    binding,
		connection: underlying,
		provedAt:   now,
		now:        func() time.Time { return now },
	}
	checks := []struct {
		name string
		run  func(context.Context, connectivity.Binding) error
	}{
		{name: "fresh handshake", run: connection.FreshAWGHandshake},
		{name: "bidirectional", run: connection.VerifyBidirectional},
		{name: "protected DNS", run: connection.VerifyProtectedDNS},
		{name: "tunnel canary", run: connection.VerifyTunnelCanary},
		{name: "commit", run: connection.Commit},
	}
	for _, check := range checks {
		if err := check.run(
			context.Background(), binding,
		); err == nil {
			t.Fatalf(
				"%s accepted a tunnel whose health was lost",
				check.name,
			)
		}
	}
}

func coldDirectTestBinding(now time.Time) connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("1", 32),
		Profile:        "phase1-auto",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("a", 64),
		CandidateID:    "direct-primary",
		NodeID:         "node-a",
		SessionID:      strings.Repeat("2", 32),
		PSKGeneration:  1,
		SequenceEpoch:  7,
		Nonce:          strings.Repeat("3", 32),
		ExpiresAt:      now.Add(time.Minute),
	}
}

type probeCloseConnection struct {
	mu                sync.Mutex
	failuresRemaining int
	calls             int
	block             chan struct{}
	health            chan error
}

func newProbeCloseConnection(failures int) *probeCloseConnection {
	return &probeCloseConnection{
		failuresRemaining: failures,
		health:            make(chan error),
	}
}

func (*probeCloseConnection) FreshAWGHandshake(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*probeCloseConnection) VerifyBidirectional(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*probeCloseConnection) VerifyProtectedDNS(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*probeCloseConnection) VerifyTunnelCanary(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (*probeCloseConnection) Commit(
	context.Context,
	connectivity.Binding,
) error {
	return nil
}

func (connection *probeCloseConnection) Health() <-chan error {
	return connection.health
}

func (connection *probeCloseConnection) Close() error {
	if connection.block != nil {
		<-connection.block
	}
	return connection.nextCloseResult()
}

func (connection *probeCloseConnection) RetryClose() error {
	return connection.nextCloseResult()
}

func (connection *probeCloseConnection) nextCloseResult() error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.calls++
	if connection.failuresRemaining > 0 {
		connection.failuresRemaining--
		return errors.New("transient staged teardown failure")
	}
	return nil
}

func (connection *probeCloseConnection) callCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.calls
}
