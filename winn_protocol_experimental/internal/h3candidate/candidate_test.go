package h3candidate

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/yosida95/uritemplate/v3"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

var testNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

func TestWinningConnectionOutlivesRaceContext(t *testing.T) {
	binding := validBinding()
	session := newFakeSession()
	transaction := &fakeTransaction{}
	var dialContext context.Context
	candidate := mustCandidate(
		t,
		func(
			ctx context.Context,
			_ connectivity.Binding,
			_ ProtectedUnderlay,
		) (net.PacketConn, error) {
			dialContext = ctx
			return &fakePacketConn{}, nil
		},
		&fakeTunnelController{session: session},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: transaction},
		nil,
	)

	raceContext, cancelRace := context.WithCancel(context.Background())
	connection, err := candidate.Dial(raceContext, binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	cancelRace()

	select {
	case <-dialContext.Done():
		t.Fatal("winning connection lifetime was canceled with race context")
	default:
	}
	if err := connection.FreshAWGHandshake(
		context.Background(), binding,
	); err != nil {
		t.Fatalf("FreshAWGHandshake() after race cancellation = %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-dialContext.Done():
	case <-time.After(time.Second):
		t.Fatal("Close() did not cancel winning connection lifetime")
	}
}

func TestDialCancellationDuringSetupCleansUp(t *testing.T) {
	binding := validBinding()
	packet := &fakePacketConn{}
	entered := make(chan struct{})
	candidate := mustCandidate(
		t,
		func(
			ctx context.Context,
			_ connectivity.Binding,
			_ ProtectedUnderlay,
		) (net.PacketConn, error) {
			close(entered)
			<-ctx.Done()
			return packet, ctx.Err()
		},
		&fakeTunnelController{session: newFakeSession()},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := candidate.Dial(ctx, binding)
		result <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Dial() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dial() did not stop after race context cancellation")
	}
}

func TestExactBindingAndWCF3ContextRequired(t *testing.T) {
	binding := validBinding()
	session := newFakeSession()
	verifier := &fakeVerifier{}
	candidate := mustCandidate(
		t,
		successfulPacketDialer(&fakePacketConn{}),
		&fakeTunnelController{session: session},
		verifier,
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		nil,
	)
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer connection.Close()

	changed := binding
	changed.SequenceEpoch++
	if err := connection.VerifyProtectedDNS(
		context.Background(), changed,
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("VerifyProtectedDNS() error = %v, want binding mismatch", err)
	}
	if got := verifier.dnsCalls.Load(); got != 0 {
		t.Fatalf("DNS verifier called %d times for mismatched binding", got)
	}

	if err := connection.VerifyProtectedDNS(
		context.Background(), binding,
	); err != nil {
		t.Fatalf("VerifyProtectedDNS() error = %v", err)
	}
	expected, err := wcf3.ContextFromBinding(binding, testNow)
	if err != nil {
		t.Fatalf("ContextFromBinding() error = %v", err)
	}
	_, gotBinding, gotContext := verifier.recorded()
	if gotBinding != binding || gotContext != expected {
		t.Fatal("DNS verifier did not receive exact binding and WCF3 context")
	}
}

func TestCommittedConnectionUsesSessionTrustAfterWorkBindingExpires(
	t *testing.T,
) {
	// newConnection starts monitorHealth on its own goroutine, and that
	// goroutine calls this clock while the test mutates it below. testClock is
	// the shared concurrency-safe fake; see its comment for why a plain
	// captured variable is the wrong shape here.
	clock := newTestClock(testNow)
	descriptor := validDescriptor()
	candidate, err := newCandidate(
		descriptor,
		successfulPacketDialer(&fakePacketConn{}),
		nil,
		&fakeTunnelController{session: newFakeSession()},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		clock.Now,
		DefaultTeardownTimeout,
	)
	if err != nil {
		t.Fatalf("newCandidate() error = %v", err)
	}
	binding := validBinding()
	binding.ExpiresAt = testNow.Add(time.Second)
	raw, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer raw.Close()
	if err := raw.Commit(context.Background(), binding); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	clock.Set(binding.ExpiresAt.Add(time.Second))
	if err := raw.VerifyProtectedDNS(
		context.Background(), binding,
	); err != nil {
		t.Fatalf(
			"VerifyProtectedDNS() after work expiry = %v, want committed session",
			err,
		)
	}

	clock.Set(descriptor.ExpiresAt.Add(time.Nanosecond))
	if err := raw.VerifyProtectedDNS(
		context.Background(), binding,
	); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf(
			"VerifyProtectedDNS() after session expiry = %v, want %v",
			err,
			ErrSessionExpired,
		)
	}
}

func TestCoordinatorCommittedH3OutlivesConnectWorkExpiry(t *testing.T) {
	now := time.Now().UTC()
	descriptor := connectivity.CandidateDescriptor{
		ID:        "h3-primary",
		Carrier:   connectivity.CarrierHTTP3,
		NodeID:    "gateway-1",
		ExpiresAt: now.Add(3 * time.Second),
	}
	candidate, err := newCandidate(
		descriptor,
		successfulPacketDialer(&fakePacketConn{}),
		nil,
		&fakeTunnelController{session: newFakeSession()},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		time.Now,
		DefaultTeardownTimeout,
	)
	if err != nil {
		t.Fatalf("newCandidate() error = %v", err)
	}
	coordinator := connectivity.NewCoordinator()
	result := coordinator.Connect(
		context.Background(),
		connectivity.ConnectRequest{
			Readiness: connectivity.Readiness{
				Profile:           "default",
				Mode:              connectivity.ModeAuto,
				ManifestDigest:    strings.Repeat("b", 64),
				ManifestExpiresAt: now.Add(5 * time.Second),
				PSKGeneration:     7,
				PSKExpiresAt:      now.Add(5 * time.Second),
				UnusedCredentials: 2,
				PreparedAt:        now.Add(-time.Millisecond),
				ExpiresAt:         now.Add(3 * time.Second),
				Candidates:        []connectivity.CandidateDescriptor{descriptor},
			},
			Candidates:    []connectivity.Candidate{candidate},
			SessionID:     strings.Repeat("c", 32),
			SequenceEpoch: 11,
			Deadline:      400 * time.Millisecond,
		},
	)
	if !result.Success() {
		t.Fatalf("Connect() = %+v, want Online", result)
	}

	// The coordinator's candidate-work binding expires around 300 ms. The old
	// cross-package behavior killed every H3 winner at that point.
	time.Sleep(650 * time.Millisecond)
	if status := coordinator.Status(); !status.Success() {
		t.Fatalf(
			"Status() after connect-work expiry = %+v, want live session",
			status,
		)
	}
	if err := coordinator.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestDialFailureCleanup(t *testing.T) {
	t.Run("underlay returned with error", func(t *testing.T) {
		underlay := newFakeUnderlay()
		candidate := mustCandidate(
			t,
			successfulPacketDialer(&fakePacketConn{}),
			&fakeTunnelController{session: newFakeSession()},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			&fakeUnderlayFactory{
				underlay: underlay,
				openErr:  errors.New("underlay failed"),
			},
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil {
			t.Fatal("Dial() unexpectedly succeeded")
		}
		if got := underlay.closes.Load(); got != 1 {
			t.Fatalf("underlay close count = %d, want 1", got)
		}
	})

	t.Run("carrier returned with error", func(t *testing.T) {
		packet := &fakePacketConn{}
		candidate := mustCandidate(
			t,
			func(
				context.Context,
				connectivity.Binding,
				ProtectedUnderlay,
			) (net.PacketConn, error) {
				return packet, errors.New("carrier failed")
			},
			&fakeTunnelController{session: newFakeSession()},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			nil,
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil {
			t.Fatal("Dial() unexpectedly succeeded")
		}
		if got := packet.closes.Load(); got != 1 {
			t.Fatalf("carrier close count = %d, want 1", got)
		}
	})

	startFailure := errors.New("AWG start failed")
	t.Run("tunnel start", func(t *testing.T) {
		packet := &fakePacketConn{}
		session := newFakeSession()
		candidate := mustCandidate(
			t,
			successfulPacketDialer(packet),
			&fakeTunnelController{
				session:  session,
				startErr: startFailure,
			},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			nil,
		)
		_, err := candidate.Dial(context.Background(), validBinding())
		if !errors.Is(err, startFailure) {
			t.Fatalf("Dial() error = %v, want %v", err, startFailure)
		}
		if got := packet.closes.Load(); got != 1 {
			t.Fatalf("carrier close count = %d, want 1", got)
		}
		if got := session.closes.Load(); got != 1 {
			t.Fatalf("session close count = %d, want 1", got)
		}
	})

	prepareFailure := errors.New("route staging failed")
	t.Run("transaction prepare", func(t *testing.T) {
		packet := &fakePacketConn{}
		session := newFakeSession()
		transaction := &fakeTransaction{}
		candidate := mustCandidate(
			t,
			successfulPacketDialer(packet),
			&fakeTunnelController{session: session},
			&fakeVerifier{},
			&fakeTransactionFactory{
				transaction: transaction,
				prepareErr:  prepareFailure,
			},
			nil,
		)
		_, err := candidate.Dial(context.Background(), validBinding())
		if !errors.Is(err, prepareFailure) {
			t.Fatalf("Dial() error = %v, want %v", err, prepareFailure)
		}
		if got := session.closes.Load(); got != 1 {
			t.Fatalf("session close count = %d, want 1", got)
		}
		if got := packet.closes.Load(); got != 1 {
			t.Fatalf("carrier close count = %d, want 1", got)
		}
		if got := transaction.rollbacks.Load(); got != 1 {
			t.Fatalf("transaction rollback count = %d, want 1", got)
		}
	})
}

func TestTypedNilDependenciesAreRejectedWithoutPanic(t *testing.T) {
	t.Run("underlay", func(t *testing.T) {
		var underlay *fakeUnderlay
		candidate := mustCandidate(
			t,
			successfulPacketDialer(&fakePacketConn{}),
			&fakeTunnelController{session: newFakeSession()},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			&fakeUnderlayFactory{underlay: underlay},
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil || !strings.Contains(err.Error(), "underlay is nil") {
			t.Fatalf("Dial() typed-nil underlay error = %v", err)
		}
	})

	t.Run("carrier", func(t *testing.T) {
		var packet *fakePacketConn
		candidate := mustCandidate(
			t,
			successfulPacketDialer(packet),
			&fakeTunnelController{session: newFakeSession()},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			nil,
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil || !strings.Contains(err.Error(), "nil packet") {
			t.Fatalf("Dial() typed-nil carrier error = %v", err)
		}
	})

	t.Run("session", func(t *testing.T) {
		packet := &fakePacketConn{}
		var session *fakeSession
		candidate := mustCandidate(
			t,
			successfulPacketDialer(packet),
			&fakeTunnelController{session: session},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: &fakeTransaction{}},
			nil,
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil || !strings.Contains(err.Error(), "session is nil") {
			t.Fatalf("Dial() typed-nil session error = %v", err)
		}
		if got := packet.closes.Load(); got != 1 {
			t.Fatalf("carrier close count = %d, want 1", got)
		}
	})

	t.Run("transaction", func(t *testing.T) {
		packet := &fakePacketConn{}
		session := newFakeSession()
		var transaction *fakeTransaction
		candidate := mustCandidate(
			t,
			successfulPacketDialer(packet),
			&fakeTunnelController{session: session},
			&fakeVerifier{},
			&fakeTransactionFactory{transaction: transaction},
			nil,
		)
		if _, err := candidate.Dial(
			context.Background(), validBinding(),
		); err == nil || !strings.Contains(err.Error(), "transaction is nil") {
			t.Fatalf("Dial() typed-nil transaction error = %v", err)
		}
		if got := session.closes.Load(); got != 1 {
			t.Fatalf("session close count = %d, want 1", got)
		}
		if got := packet.closes.Load(); got != 1 {
			t.Fatalf("carrier close count = %d, want 1", got)
		}
	})
}

func TestPredicatesAreCandidateIsolatedAndCommitIsExplicit(t *testing.T) {
	binding := validBinding()
	order := &callOrder{}
	session := newFakeSession()
	session.order = order
	verifier := &fakeVerifier{order: order}
	transaction := &fakeTransaction{order: order}
	candidate := mustCandidate(
		t,
		successfulPacketDialer(&fakePacketConn{}),
		&fakeTunnelController{session: session},
		verifier,
		&fakeTransactionFactory{transaction: transaction},
		nil,
	)
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer connection.Close()

	if got := transaction.commits.Load(); got != 0 {
		t.Fatalf("route/DNS committed during Dial: count = %d", got)
	}
	verifications := []struct {
		name   string
		verify func(context.Context, connectivity.Binding) error
	}{
		{name: "handshake", verify: connection.FreshAWGHandshake},
		{name: "bidirectional", verify: connection.VerifyBidirectional},
		{name: "dns", verify: connection.VerifyProtectedDNS},
		{name: "canary", verify: connection.VerifyTunnelCanary},
	}
	for _, verification := range verifications {
		if err := verification.verify(
			context.Background(), binding,
		); err != nil {
			t.Fatalf("%s predicate error = %v", verification.name, err)
		}
	}
	if got := transaction.commits.Load(); got != 0 {
		t.Fatalf("route/DNS committed before coordinator Commit: count = %d", got)
	}
	if err := connection.Commit(context.Background(), binding); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if err := connection.Commit(context.Background(), binding); err != nil {
		t.Fatalf("second Commit() error = %v", err)
	}
	if got := transaction.commits.Load(); got != 1 {
		t.Fatalf("transaction commit count = %d, want 1", got)
	}
	want := []string{"handshake", "bidirectional", "dns", "canary", "commit"}
	if got := order.snapshot(); !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	gotSession, _, _ := verifier.recorded()
	if gotSession != session {
		t.Fatal("verifier received a session other than this candidate session")
	}
}

func TestHealthIsStableAndFailureTearsDown(t *testing.T) {
	binding := validBinding()
	packet := &fakePacketConn{}
	session := newFakeSession()
	transaction := &fakeTransaction{}
	candidate := mustCandidate(
		t,
		successfulPacketDialer(packet),
		&fakeTunnelController{session: session},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: transaction},
		nil,
	)
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	health := connection.Health()
	if health == nil || health != connection.Health() {
		t.Fatal("Health() did not return one stable non-nil channel")
	}

	failure := errors.New("inner AWG stopped")
	session.health <- failure
	select {
	case got, ok := <-health:
		if !ok || !errors.Is(got, failure) {
			t.Fatalf("health result = (%v, %v), want wrapped failure", got, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("health failure was not published")
	}
	select {
	case _, ok := <-health:
		if ok {
			t.Fatal("health channel published more than one terminal result")
		}
	case <-time.After(time.Second):
		t.Fatal("health channel did not close after terminal result")
	}
	eventually(t, func() bool {
		return session.closes.Load() == 1 &&
			packet.closes.Load() == 1 &&
			transaction.rollbacks.Load() == 1
	})
	if err := connection.FreshAWGHandshake(
		context.Background(), binding,
	); !errors.Is(err, ErrClosed) {
		t.Fatalf("operation after health failure = %v, want closed", err)
	}
}

func TestCloseIsSynchronousIdempotentRollback(t *testing.T) {
	packet := &fakePacketConn{}
	session := newFakeSession()
	rollbackFailure := errors.New("rollback failed")
	transaction := &fakeTransaction{rollbackErr: rollbackFailure}
	candidate := mustCandidate(
		t,
		successfulPacketDialer(packet),
		&fakeTunnelController{session: session},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: transaction},
		nil,
	)
	tunnelConnection, err := candidate.Dial(context.Background(), validBinding())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	const callers = 8
	results := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- tunnelConnection.Close()
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if !errors.Is(err, rollbackFailure) {
			t.Fatalf("Close() error = %v, want rollback failure", err)
		}
	}
	if got := transaction.rollbacks.Load(); got != 1 {
		t.Fatalf("rollback count = %d, want 1", got)
	}
	if got := session.closes.Load(); got != 1 {
		t.Fatalf("session close count = %d, want 1", got)
	}
	if got := packet.closes.Load(); got != 1 {
		t.Fatalf("carrier close count = %d, want 1", got)
	}
	transaction.rollbackErr = nil
	retryable, ok := tunnelConnection.(*connection)
	if !ok {
		t.Fatalf("connection type = %T", tunnelConnection)
	}
	if err := retryable.RetryClose(); err != nil {
		t.Fatalf("RetryClose() error = %v", err)
	}
	if got := transaction.rollbacks.Load(); got != 2 {
		t.Fatalf("retry rollback count = %d, want 2", got)
	}
	if got := session.closes.Load(); got != 2 {
		t.Fatalf("retry session close count = %d, want 2", got)
	}
	if err := tunnelConnection.Close(); err != nil {
		t.Fatalf("Close() after recovery error = %v", err)
	}
}

func TestCloseBoundsContextAwareRollback(t *testing.T) {
	const teardownTimeout = 25 * time.Millisecond
	transaction := &fakeTransaction{blockRollback: true}
	candidate := mustCandidateWithTeardown(
		t,
		successfulPacketDialer(&fakePacketConn{}),
		&fakeTunnelController{session: newFakeSession()},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: transaction},
		nil,
		teardownTimeout,
	)
	connection, err := candidate.Dial(context.Background(), validBinding())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	started := time.Now()
	err = connection.Close()
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v, want teardown deadline", err)
	}
	if elapsed > 10*teardownTimeout {
		t.Fatalf(
			"Close() took %s with %s teardown timeout",
			elapsed, teardownTimeout,
		)
	}
	if got := transaction.rollbacks.Load(); got != 1 {
		t.Fatalf("rollback count = %d, want 1", got)
	}
}

func TestCloseCancelsAndJoinsInFlightPredicate(t *testing.T) {
	binding := validBinding()
	session := newFakeSession()
	session.blockHandshake = true
	session.handshakeEntered = make(chan struct{})
	candidate := mustCandidate(
		t,
		successfulPacketDialer(&fakePacketConn{}),
		&fakeTunnelController{session: session},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		nil,
	)
	connection, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}

	predicateResult := make(chan error, 1)
	go func() {
		predicateResult <- connection.FreshAWGHandshake(
			context.Background(), binding,
		)
	}()
	<-session.handshakeEntered
	if err := connection.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case err := <-predicateResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight predicate error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() returned without predicate operation completing")
	}
}

func TestMigrationRequiresProtectedUnderlayAndExactBinding(t *testing.T) {
	binding := validBinding()
	carrierPath := &fakeMigratablePacketConn{
		fakePacketConn: fakePacketConn{},
	}
	underlay := newFakeUnderlay()
	candidate := mustCandidate(
		t,
		successfulPacketDialer(carrierPath),
		&fakeTunnelController{session: newFakeSession()},
		&fakeVerifier{},
		&fakeTransactionFactory{transaction: &fakeTransaction{}},
		&fakeUnderlayFactory{underlay: underlay},
	)
	raw, err := candidate.Dial(context.Background(), binding)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	connection := raw.(MigratableConnection)
	defer connection.Close()

	replacement := &fakePacketConn{}
	if err := connection.MigratePath(
		context.Background(), binding, replacement,
	); err != nil {
		t.Fatalf("MigratePath() error = %v", err)
	}
	if got := underlay.protects.Load(); got != 1 {
		t.Fatalf("underlay protection count = %d, want 1", got)
	}
	if got := carrierPath.migrations.Load(); got != 1 {
		t.Fatalf("carrier migration count = %d, want 1", got)
	}
	if got := replacement.closes.Load(); got != 0 {
		t.Fatalf("successful migration socket close count = %d, want 0", got)
	}

	mismatch := binding
	mismatch.Nonce = strings.Repeat("4", 32)
	rejected := &fakePacketConn{}
	if err := connection.MigratePath(
		context.Background(), mismatch, rejected,
	); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("mismatched MigratePath() error = %v", err)
	}
	if got := rejected.closes.Load(); got != 1 {
		t.Fatalf("rejected migration socket close count = %d, want 1", got)
	}
}

func TestProductionConstructorRejectsMissingHybridAndECH(t *testing.T) {
	base := Config{
		Descriptor: validDescriptor(),
		// An explicit session lifetime is mandatory: New rejects a zero value
		// rather than defaulting it, so it must be supplied here for the test
		// to reach the hybrid/ECH assertions it actually covers.
		SessionExpiresAt: validDescriptor().ExpiresAt,
		Underlay:         &fakeUnderlayFactory{underlay: newFakeUnderlay()},
		Tunnel:           &fakeTunnelController{session: newFakeSession()},
		Verifier:         &fakeVerifier{},
		Transactions:     &fakeTransactionFactory{transaction: &fakeTransaction{}},
		Now:              func() time.Time { return testNow },
	}
	base.Dialer = &carrier.H3Dialer{
		Suite: tlsconfig.Suite{
			Name:  "x25519",
			Curve: tls.X25519,
		},
		TLSConfig: &tls.Config{},
	}
	if _, err := New(base); err == nil ||
		!strings.Contains(err.Error(), "X25519 plus ML-KEM-768") {
		t.Fatalf("New() hybrid rejection error = %v", err)
	}

	hybridSuite := tlsconfig.Suite{
		Name:  "x25519-mlkem768",
		Curve: tls.X25519MLKEM768,
	}
	base.Dialer = &carrier.H3Dialer{
		Suite: hybridSuite,
		TLSConfig: &tls.Config{
			ServerName:       "cover.example",
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			CurvePreferences: tlsconfig.ClientCurvePreferences(hybridSuite),
			VerifyConnection: func(tls.ConnectionState) error { return nil },
		},
	}
	if _, err := New(base); err == nil ||
		!strings.Contains(err.Error(), "valid ECH") {
		t.Fatalf("New() ECH rejection error = %v", err)
	}
}

func TestProductionTLSVerifierIndependentlyRequiresECHAcceptance(t *testing.T) {
	configList, _, err := echconfig.Generate("cover.example", 7)
	if err != nil {
		t.Fatalf("Generate() ECH config error = %v", err)
	}
	template, err := uritemplate.New(
		"https://cover.example/.well-known/masque/udp/{target_host}/{target_port}/",
	)
	if err != nil {
		t.Fatalf("uritemplate.New() error = %v", err)
	}
	previousCalls := atomic.Int32{}
	source := &carrier.H3Dialer{
		Template:     template,
		PublicTarget: "vpn.example:51820",
		Suite: tlsconfig.Suite{
			Name:  "x25519-mlkem768",
			Curve: tls.X25519MLKEM768,
		},
		TLSConfig: &tls.Config{
			ServerName: "cover.example",
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			CurvePreferences: tlsconfig.ClientCurvePreferences(tlsconfig.Suite{
				Name: "x25519-mlkem768", Curve: tls.X25519MLKEM768,
			}),
			EncryptedClientHelloConfigList: configList,
			VerifyConnection: func(tls.ConnectionState) error {
				previousCalls.Add(1)
				return nil
			},
		},
		ResponseVerifier: &carrierauth.ResponseVerifier{},
	}
	snapshot, err := snapshotProductionDialer(source)
	if err != nil {
		t.Fatalf("snapshotProductionDialer() error = %v", err)
	}
	if err := snapshot.TLSConfig.VerifyConnection(
		tls.ConnectionState{ECHAccepted: false},
	); err == nil || !strings.Contains(err.Error(), "accepted ECH") {
		t.Fatalf("VerifyConnection() ECH rejection error = %v", err)
	}
	if err := snapshot.TLSConfig.VerifyConnection(
		tls.ConnectionState{ECHAccepted: true},
	); err != nil {
		t.Fatalf("VerifyConnection() accepted ECH error = %v", err)
	}
	if got := previousCalls.Load(); got != 2 {
		t.Fatalf("caller verifier invocation count = %d, want 2", got)
	}

	anonymous := *source
	anonymous.AuthorizationMode = carrierauth.AuthModeAnonymousToken
	anonymous.TLSConfig = source.TLSConfig.Clone()
	anonymous.TLSConfig.SessionTicketsDisabled = true
	anonymous.TLSConfig.Certificates = []tls.Certificate{{}}
	if _, err := snapshotProductionDialer(
		&anonymous,
	); err == nil || !strings.Contains(
		err.Error(),
		"stable client identity or resumption",
	) {
		t.Fatalf("anonymous stable-identity rejection error = %v", err)
	}
	anonymous.TLSConfig.Certificates = nil
	anonymous.QUICConfig = &quic.Config{
		TokenStore: quic.NewLRUTokenStore(1, 1),
	}
	if _, err := snapshotProductionDialer(
		&anonymous,
	); err == nil || !strings.Contains(
		err.Error(),
		"persistent address tokens",
	) {
		t.Fatalf("anonymous QUIC token-store rejection error = %v", err)
	}
}

func mustCandidate(
	t *testing.T,
	dial packetDialer,
	tunnel TunnelController,
	verifier CandidateVerifier,
	transactions TransactionFactory,
	underlay ProtectedUnderlayFactory,
) *Candidate {
	return mustCandidateWithTeardown(
		t,
		dial,
		tunnel,
		verifier,
		transactions,
		underlay,
		DefaultTeardownTimeout,
	)
}

func mustCandidateWithTeardown(
	t *testing.T,
	dial packetDialer,
	tunnel TunnelController,
	verifier CandidateVerifier,
	transactions TransactionFactory,
	underlay ProtectedUnderlayFactory,
	teardownTimeout time.Duration,
) *Candidate {
	t.Helper()
	candidate, err := newCandidate(
		validDescriptor(),
		dial,
		underlay,
		tunnel,
		verifier,
		transactions,
		func() time.Time { return testNow },
		teardownTimeout,
	)
	if err != nil {
		t.Fatalf("newCandidate() error = %v", err)
	}
	return candidate
}

func successfulPacketDialer(packet net.PacketConn) packetDialer {
	return func(
		context.Context,
		connectivity.Binding,
		ProtectedUnderlay,
	) (net.PacketConn, error) {
		return packet, nil
	}
}

func validDescriptor() connectivity.CandidateDescriptor {
	return connectivity.CandidateDescriptor{
		ID:        "h3-primary",
		Carrier:   connectivity.CarrierHTTP3,
		NodeID:    "gateway-1",
		ExpiresAt: testNow.Add(2 * time.Minute),
	}
}

func validBinding() connectivity.Binding {
	return connectivity.Binding{
		AttemptID:      strings.Repeat("a", 32),
		Profile:        "default",
		Mode:           connectivity.ModeAuto,
		ManifestDigest: strings.Repeat("b", 64),
		CandidateID:    "h3-primary",
		NodeID:         "gateway-1",
		SessionID:      strings.Repeat("c", 32),
		PSKGeneration:  7,
		SequenceEpoch:  11,
		Nonce:          strings.Repeat("d", 32),
		ExpiresAt:      testNow.Add(time.Minute),
	}
}

type fakePacketConn struct {
	closes atomic.Int32
}

func (packet *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (packet *fakePacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, nil
}

func (packet *fakePacketConn) Close() error {
	packet.closes.Add(1)
	return nil
}

func (*fakePacketConn) LocalAddr() net.Addr {
	return fakeAddr("fake")
}

func (*fakePacketConn) SetDeadline(time.Time) error {
	return nil
}

func (*fakePacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*fakePacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

type fakeMigratablePacketConn struct {
	fakePacketConn
	migrations atomic.Int32
}

func (packet *fakeMigratablePacketConn) MigratePath(
	context.Context,
	net.PacketConn,
) error {
	packet.migrations.Add(1)
	return nil
}

type fakeAddr string

func (address fakeAddr) Network() string {
	return string(address)
}

func (address fakeAddr) String() string {
	return string(address)
}

type fakeTunnelController struct {
	session  TunnelSession
	startErr error
}

func (controller *fakeTunnelController) Start(
	context.Context,
	net.PacketConn,
	connectivity.Binding,
	wcf3.Context,
) (TunnelSession, error) {
	if controller.startErr != nil {
		return controller.session, controller.startErr
	}
	return controller.session, nil
}

type fakeSession struct {
	health           chan error
	handshakeCalls   atomic.Int32
	bidirCalls       atomic.Int32
	closes           atomic.Int32
	order            *callOrder
	blockHandshake   bool
	handshakeEntered chan struct{}
	handshakeOnce    sync.Once
}

func newFakeSession() *fakeSession {
	return &fakeSession{health: make(chan error, 1)}
}

func (session *fakeSession) FreshAWGHandshake(
	ctx context.Context,
	_ connectivity.Binding,
	_ wcf3.Context,
) error {
	session.handshakeCalls.Add(1)
	if session.order != nil {
		session.order.add("handshake")
	}
	if session.blockHandshake {
		session.handshakeOnce.Do(func() {
			close(session.handshakeEntered)
		})
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (session *fakeSession) VerifyBidirectional(
	context.Context,
	connectivity.Binding,
	wcf3.Context,
) error {
	session.bidirCalls.Add(1)
	if session.order != nil {
		session.order.add("bidirectional")
	}
	return nil
}

func (session *fakeSession) Health() <-chan error {
	return session.health
}

func (session *fakeSession) Close(context.Context) error {
	session.closes.Add(1)
	return nil
}

type fakeVerifier struct {
	dnsCalls    atomic.Int32
	canaryCalls atomic.Int32
	order       *callOrder
	// The coordinator proves protected DNS and the tunnel canary on concurrent
	// goroutines, so these recorded values are written from both.
	mu          sync.Mutex
	lastSession TunnelSession
	lastBinding connectivity.Binding
	lastContext wcf3.Context
}

func (verifier *fakeVerifier) record(
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.lastSession = session
	verifier.lastBinding = binding
	verifier.lastContext = frameContext
}

func (verifier *fakeVerifier) recorded() (
	TunnelSession,
	connectivity.Binding,
	wcf3.Context,
) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.lastSession, verifier.lastBinding, verifier.lastContext
}

func (verifier *fakeVerifier) VerifyProtectedDNS(
	_ context.Context,
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	verifier.dnsCalls.Add(1)
	verifier.record(session, binding, frameContext)
	if verifier.order != nil {
		verifier.order.add("dns")
	}
	return nil
}

func (verifier *fakeVerifier) VerifyTunnelCanary(
	_ context.Context,
	session TunnelSession,
	binding connectivity.Binding,
	frameContext wcf3.Context,
) error {
	verifier.canaryCalls.Add(1)
	verifier.record(session, binding, frameContext)
	if verifier.order != nil {
		verifier.order.add("canary")
	}
	return nil
}

type fakeTransactionFactory struct {
	transaction RouteDNSTransaction
	prepareErr  error
}

func (factory *fakeTransactionFactory) Prepare(
	context.Context,
	TunnelSession,
	connectivity.Binding,
	wcf3.Context,
) (RouteDNSTransaction, error) {
	if factory.prepareErr != nil {
		return factory.transaction, factory.prepareErr
	}
	return factory.transaction, nil
}

type fakeTransaction struct {
	commits       atomic.Int32
	rollbacks     atomic.Int32
	commitErr     error
	rollbackErr   error
	blockRollback bool
	order         *callOrder
}

func (transaction *fakeTransaction) Commit(
	context.Context,
	connectivity.Binding,
	wcf3.Context,
) error {
	transaction.commits.Add(1)
	if transaction.order != nil {
		transaction.order.add("commit")
	}
	return transaction.commitErr
}

func (transaction *fakeTransaction) Rollback(ctx context.Context) error {
	transaction.rollbacks.Add(1)
	if transaction.blockRollback {
		<-ctx.Done()
		return ctx.Err()
	}
	return transaction.rollbackErr
}

type fakeUnderlayFactory struct {
	underlay ProtectedUnderlay
	openErr  error
}

func (factory *fakeUnderlayFactory) Open(
	context.Context,
	connectivity.Binding,
) (ProtectedUnderlay, error) {
	if factory.openErr != nil {
		return factory.underlay, factory.openErr
	}
	return factory.underlay, nil
}

type fakeUnderlay struct {
	health   chan error
	protects atomic.Int32
	closes   atomic.Int32
}

func newFakeUnderlay() *fakeUnderlay {
	return &fakeUnderlay{health: make(chan error, 1)}
}

func (*fakeUnderlay) DialQUICPath(
	context.Context,
	string,
	*tls.Config,
	*quic.Config,
) (*quic.Conn, *quic.Transport, error) {
	return nil, nil, errors.New("unused fake QUIC dial")
}

func (underlay *fakeUnderlay) ProtectMigrationSocket(
	context.Context,
	connectivity.Binding,
	net.PacketConn,
) error {
	underlay.protects.Add(1)
	return nil
}

func (underlay *fakeUnderlay) Health() <-chan error {
	return underlay.health
}

func (underlay *fakeUnderlay) Close(context.Context) error {
	underlay.closes.Add(1)
	return nil
}

type callOrder struct {
	mu    sync.Mutex
	calls []string
}

func (order *callOrder) add(value string) {
	order.mu.Lock()
	order.calls = append(order.calls, value)
	order.mu.Unlock()
}

func (order *callOrder) snapshot() []string {
	order.mu.Lock()
	defer order.mu.Unlock()
	return append([]string(nil), order.calls...)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not satisfied before timeout")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestConstructorsRejectZeroSessionExpiry pins the fail-closed contract for the
// H3 trust lifetime. A zero SessionExpiresAt must be rejected outright by every
// constructor rather than silently defaulted to the descriptor expiry.
//
// Defaulting is the exact fail-back that previously let a committed H3 session
// inherit the short candidate-work deadline and self-terminate mid-session, so
// these are regression guards, not style checks. linuxProtectedUnderlayFactory
// already rejects zero; these cover the two remaining constructors.
func TestConstructorsRejectZeroSessionExpiry(t *testing.T) {
	newBase := func() Config {
		return Config{
			Descriptor:   validDescriptor(),
			Underlay:     &fakeUnderlayFactory{underlay: newFakeUnderlay()},
			Tunnel:       &fakeTunnelController{session: newFakeSession()},
			Verifier:     &fakeVerifier{},
			Transactions: &fakeTransactionFactory{transaction: &fakeTransaction{}},
			Now:          func() time.Time { return testNow },
		}
	}

	t.Run("New rejects zero", func(t *testing.T) {
		config := newBase() // SessionExpiresAt deliberately left zero
		candidate, err := New(config)
		if err == nil {
			t.Fatal("New() accepted a zero session lifetime")
		}
		if !strings.Contains(err.Error(), "session lifetime is required") {
			t.Fatalf("New() error = %v, want session-lifetime rejection", err)
		}
		if candidate != nil {
			t.Fatal("New() returned a candidate alongside an error")
		}
	})

	t.Run("New accepts an explicit lifetime", func(t *testing.T) {
		config := newBase()
		config.SessionExpiresAt = validDescriptor().ExpiresAt
		if _, err := New(config); err != nil &&
			strings.Contains(err.Error(), "session lifetime is required") {
			t.Fatalf("New() rejected an explicit lifetime: %v", err)
		}
	})

	t.Run("PrepareWarm rejects zero", func(t *testing.T) {
		config := newBase() // SessionExpiresAt deliberately left zero
		_, err := PrepareWarm(context.Background(), config, time.Minute)
		if err == nil {
			t.Fatal("PrepareWarm() accepted a zero session lifetime")
		}
		if !strings.Contains(err.Error(), "session lifetime is required") {
			t.Fatalf("PrepareWarm() error = %v, want session-lifetime rejection", err)
		}
	})
}

// testClock is the concurrency-safe fake clock every test in this package must
// use for Config.Now. A plain captured variable plus a closure is the natural
// way to write a fake clock and is exactly the unsafe shape: newConnection
// starts monitorHealth on its own goroutine, so the clock is read there while
// the test body mutates it. That produced two intermittent -race failures
// before it was diagnosed, and intervening runs passed, so a green run is not
// evidence of safety here.
type testClock struct{ nanos atomic.Int64 }

func newTestClock(start time.Time) *testClock {
	clock := &testClock{}
	clock.Set(start)
	return clock
}

// Set advances or rewinds the clock. Safe to call while the connection's
// health monitor is running.
func (clock *testClock) Set(value time.Time) {
	clock.nanos.Store(value.UnixNano())
}

// Now satisfies Config.Now and is safe for concurrent use.
func (clock *testClock) Now() time.Time {
	return time.Unix(0, clock.nanos.Load()).UTC()
}
