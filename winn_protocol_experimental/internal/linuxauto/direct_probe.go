package linuxauto

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/preparation"
)

const (
	liveDirectProbeCloseWait    = 500 * time.Millisecond
	liveDirectProbeRetryMinimum = 10 * time.Millisecond
	liveDirectProbeRetryMaximum = 250 * time.Millisecond

	// coldPredicateFreshness bounds how long a cold predicate proof may be
	// consumed after it succeeded. The intended cold flow claims within
	// microseconds; anything materially older is treated as unproven rather
	// than trusted for the remainder of the click budget.
	coldPredicateFreshness = 750 * time.Millisecond
)

type DirectRemoteDialerFactory func(
	preparation.UnderlayMarkAuthorization,
) (directawg.RemoteDialer, error)

type LiveDirectProbeConfig struct {
	ControllerFactory DirectControllerFactory
	DialerFactory     DirectRemoteDialerFactory

	LocalRelayAddress string
	IdleTimeout       time.Duration
	SocketBufferBytes int
	PollInterval      time.Duration
	EvidenceLifetime  time.Duration
	Now               func() time.Time
}

// NewLiveDirectProbe returns the production DirectBuilder probe. Every call
// creates an isolated raw-AWG candidate, proves a fresh handshake,
// bidirectional counters, protected DNS, and the tunnel canary, then tears the
// probe tunnel down before publishing bounded immutable evidence.
func NewLiveDirectProbe(
	config LiveDirectProbeConfig,
) (DirectProbe, error) {
	if config.ControllerFactory == nil {
		return nil, errors.New(
			"live DirectAWG probe controller is required",
		)
	}
	if config.DialerFactory == nil {
		config.DialerFactory = func(
			authorization preparation.UnderlayMarkAuthorization,
		) (directawg.RemoteDialer, error) {
			return directawg.NewLinuxProtectedUDPDialer(
				directawg.LinuxProtectedUDPDialerConfig{
					InterfaceName: authorization.InterfaceName,
					FirewallMark:  authorization.FirewallMark,
				},
			)
		}
	}
	socketBufferBytes, err := normalizeDirectSocketBufferBytes(
		config.SocketBufferBytes,
	)
	if err != nil {
		return nil, err
	}
	config.SocketBufferBytes = socketBufferBytes
	if config.IdleTimeout < 0 ||
		config.PollInterval < 0 ||
		config.PollInterval > 250*time.Millisecond {
		return nil, errors.New(
			"live DirectAWG probe relay configuration is invalid",
		)
	}
	if config.EvidenceLifetime == 0 {
		config.EvidenceLifetime = 30 * time.Second
	}
	if config.EvidenceLifetime <= 0 ||
		config.EvidenceLifetime > 5*time.Minute {
		return nil, errors.New(
			"live DirectAWG evidence lifetime is invalid",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return func(
		ctx context.Context,
		input preparation.DirectAWGPreparationInput,
	) (result DirectProbeResult, resultErr error) {
		if ctx == nil {
			return DirectProbeResult{},
				errors.New("live DirectAWG probe context is required")
		}
		if cause := context.Cause(ctx); cause != nil {
			return DirectProbeResult{}, cause
		}
		now := config.Now().UTC()
		expiresAt := minimumTime(
			input.Context.Descriptor.ExpiresAt.UTC(),
			input.Context.ManifestExpiresAt.UTC(),
			input.Context.PSKExpiresAt.UTC(),
			input.UnderlayMark.ExpiresAt.UTC(),
			now.Add(config.EvidenceLifetime),
		)
		if !expiresAt.After(now) {
			return DirectProbeResult{},
				errors.New("live DirectAWG probe trust is expired")
		}
		binding := input.Context.PreconnectBinding
		cold := binding != (connectivity.Binding{})
		if !cold {
			var err error
			binding, err = newDirectProbeBinding(input, expiresAt)
			if err != nil {
				return DirectProbeResult{}, err
			}
		} else {
			if err := validateColdDirectBinding(input, binding, now); err != nil {
				return DirectProbeResult{}, err
			}
			expiresAt = minimumTime(expiresAt, binding.ExpiresAt.UTC())
		}
		controller, err := config.ControllerFactory(ctx, input)
		if err != nil {
			return DirectProbeResult{},
				fmt.Errorf(
					"construct live DirectAWG probe controller: %w",
					err,
				)
		}
		if nilInterface(controller) {
			return DirectProbeResult{},
				errors.New(
					"live DirectAWG probe controller is nil",
				)
		}
		dialer, err := config.DialerFactory(input.UnderlayMark)
		if err != nil {
			return DirectProbeResult{},
				fmt.Errorf(
					"construct live DirectAWG probe dialer: %w", err,
				)
		}
		if nilInterface(dialer) {
			return DirectProbeResult{},
				errors.New("live DirectAWG probe dialer is nil")
		}
		candidate, err := directawg.NewCandidate(
			directawg.Config{
				Descriptor:        input.Context.Descriptor,
				Endpoint:          input.Endpoint,
				GatewayPublicKey:  input.GatewayPublicKey,
				LocalRelayAddress: config.LocalRelayAddress,
				MinInnerDatagram:  input.MinInnerDatagram,
				MaxInnerDatagram:  input.MaxInnerDatagram,
				IdleTimeout:       config.IdleTimeout,
				SocketBufferBytes: config.SocketBufferBytes,
				PollInterval:      config.PollInterval,
				Controller:        controller,
				Dialer:            dialer,
				Now:               config.Now,
			},
		)
		if err != nil {
			return DirectProbeResult{}, err
		}
		connection, err := candidate.Dial(ctx, binding)
		if err != nil {
			return DirectProbeResult{},
				fmt.Errorf("dial live DirectAWG probe: %w", err)
		}
		closeOwner := newLiveDirectProbeCloseOwner(connection)
		closeOnReturn := true
		defer func() {
			if !closeOnReturn {
				return
			}
			closeErr := closeOwner.Close(ctx)
			if closeErr != nil {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf(
						"close live DirectAWG probe: %w", closeErr,
					),
				)
			}
		}()
		if cold {
			if err := verifyColdDirectPredicates(
				ctx, connection, binding,
			); err != nil {
				return DirectProbeResult{}, err
			}
			state := &preconnectedDirectState{
				descriptor: input.Context.Descriptor,
				binding:    binding,
				connection: connection,
				closeOwner: closeOwner,
				provedAt:   config.Now().UTC(),
				now:        config.Now,
			}
			closeOnReturn = false
			return DirectProbeResult{
				FreshUntil: expiresAt,
				Resource: &preconnectedDirectResource{
					state: state,
				},
				Candidate: &preconnectedDirectCandidate{
					state: state,
				},
			}, nil
		}
		if err := connection.FreshAWGHandshake(
			ctx, binding,
		); err != nil {
			return DirectProbeResult{},
				fmt.Errorf("live DirectAWG handshake probe: %w", err)
		}
		if err := connection.VerifyBidirectional(
			ctx, binding,
		); err != nil {
			return DirectProbeResult{},
				fmt.Errorf(
					"live DirectAWG bidirectional probe: %w", err,
				)
		}
		if err := runConcurrentBindingChecks(
			ctx,
			binding,
			[]bindingProbeCheck{
				{
					name: "protected DNS",
					run:  connection.VerifyProtectedDNS,
				},
				{
					name: "tunnel canary",
					run:  connection.VerifyTunnelCanary,
				},
			},
		); err != nil {
			return DirectProbeResult{}, err
		}
		return DirectProbeResult{
			FreshUntil: expiresAt,
			Resource: &directProbeEvidence{
				binding:  binding,
				provedAt: config.Now().UTC(),
			},
		}, nil
	}, nil
}

func validateColdDirectBinding(
	input preparation.DirectAWGPreparationInput,
	binding connectivity.Binding,
	now time.Time,
) error {
	if err := binding.Validate(now); err != nil {
		return fmt.Errorf("cold DirectAWG binding: %w", err)
	}
	if binding.Profile != input.Context.Profile ||
		binding.Mode != input.Context.Mode ||
		binding.ManifestDigest != input.Context.ManifestDigest ||
		binding.CandidateID != input.Context.Descriptor.ID ||
		binding.NodeID != input.Context.Descriptor.NodeID ||
		binding.PSKGeneration != input.Context.PSKGeneration ||
		binding.ExpiresAt.After(input.Context.Descriptor.ExpiresAt) ||
		binding.ExpiresAt.After(input.Context.ManifestExpiresAt) ||
		binding.ExpiresAt.After(input.Context.PSKExpiresAt) ||
		binding.ExpiresAt.After(input.UnderlayMark.ExpiresAt) {
		return errors.New(
			"cold DirectAWG binding differs from verified preparation",
		)
	}
	return nil
}

// verifyColdDirectPredicates runs only after the true-cold user operation has
// begun and uses its final immutable Binding. The four checks are concurrent,
// matching the coordinator's speculative verification and avoiding two serial
// edge RTTs. Their successes may therefore be consumed by the coordinator
// without treating pre-click background evidence as click evidence.
func verifyColdDirectPredicates(
	ctx context.Context,
	connection connectivity.CandidateConnection,
	binding connectivity.Binding,
) error {
	return runConcurrentBindingChecks(
		ctx,
		binding,
		[]bindingProbeCheck{
			{name: "fresh handshake", run: connection.FreshAWGHandshake},
			{name: "bidirectional traffic", run: connection.VerifyBidirectional},
			{name: "protected DNS", run: connection.VerifyProtectedDNS},
			{name: "tunnel canary", run: connection.VerifyTunnelCanary},
		},
	)
}

type bindingProbeCheck struct {
	name string
	run  func(context.Context, connectivity.Binding) error
}

// runConcurrentBindingChecks starts every check against the same cancellable
// child context, cancels the rest on the first failure, and does not return
// until every goroutine has finished. Returning on the first error while a
// sibling is still in flight would Close the probe tunnel underneath it.
func runConcurrentBindingChecks(
	ctx context.Context,
	binding connectivity.Binding,
	checks []bindingProbeCheck,
) error {
	if len(checks) == 0 {
		return errors.New("live DirectAWG concurrent probe set is empty")
	}
	probeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		name string
		err  error
	}
	results := make(chan result, len(checks))
	for _, check := range checks {
		check := check
		go func() {
			results <- result{
				name: check.name,
				err:  check.run(probeContext, binding),
			}
		}()
	}
	var failures []error
	for range checks {
		current := <-results
		if current.err != nil {
			cancel()
			failures = append(
				failures,
				fmt.Errorf(
					"live DirectAWG %s probe: %w",
					current.name,
					current.err,
				),
			)
		}
	}
	return errors.Join(failures...)
}

type preconnectedDirectState struct {
	mu sync.Mutex

	descriptor connectivity.CandidateDescriptor
	binding    connectivity.Binding
	connection connectivity.CandidateConnection
	closeOwner *liveDirectProbeCloseOwner
	// provedAt records when all four cold predicates succeeded. Cached
	// success is only consumable while it remains fresh.
	provedAt time.Time
	now      func() time.Time
	claimed  bool
	retired  bool
}

type preconnectedDirectCandidate struct {
	state *preconnectedDirectState
}

func (candidate *preconnectedDirectCandidate) Descriptor() connectivity.CandidateDescriptor {
	if candidate == nil || candidate.state == nil {
		return connectivity.CandidateDescriptor{}
	}
	return candidate.state.descriptor
}

func (candidate *preconnectedDirectCandidate) Dial(
	ctx context.Context,
	binding connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	if candidate == nil || candidate.state == nil {
		return nil, errors.New(
			"cold DirectAWG candidate is unavailable",
		)
	}
	if ctx == nil {
		return nil, errors.New(
			"cold DirectAWG claim context is required",
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	state := candidate.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.retired || state.claimed || state.connection == nil {
		return nil, errors.New(
			"cold DirectAWG candidate was already consumed",
		)
	}
	if binding != state.binding {
		return nil, errors.New(
			"cold DirectAWG claim differs from planned binding",
		)
	}
	if err := binding.Validate(time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("cold DirectAWG claim: %w", err)
	}
	state.claimed = true
	return &preverifiedDirectConnection{
		binding:    state.binding,
		connection: state.connection,
		provedAt:   state.provedAt,
		now:        state.now,
	}, nil
}

type preconnectedDirectResource struct {
	state *preconnectedDirectState
}

func (resource *preconnectedDirectResource) Close(
	ctx context.Context,
) error {
	if resource == nil || resource.state == nil {
		return nil
	}
	state := resource.state
	state.mu.Lock()
	state.retired = true
	owner := state.closeOwner
	state.mu.Unlock()
	if owner == nil {
		return nil
	}
	return owner.Close(ctx)
}

// preverifiedDirectConnection exposes cached predicate success only because
// all four checks ran after the true-cold user boundary with this exact final
// Binding. Commit and health remain live operations on the original tunnel.
type preverifiedDirectConnection struct {
	binding    connectivity.Binding
	connection connectivity.CandidateConnection
	provedAt   time.Time
	now        func() time.Time
}

func (connection *preverifiedDirectConnection) nowUTC() time.Time {
	if connection == nil || connection.now == nil {
		return time.Now().UTC()
	}
	return connection.now().UTC()
}

func (connection *preverifiedDirectConnection) check(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if connection == nil || nilInterface(connection.connection) {
		return errors.New("cold DirectAWG connection is unavailable")
	}
	if ctx == nil {
		return errors.New("cold DirectAWG verification context is required")
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if binding != connection.binding {
		return errors.New(
			"cold DirectAWG verification binding mismatch",
		)
	}
	current := connection.nowUTC()
	if err := binding.Validate(current); err != nil {
		return err
	}
	// A cached predicate success only means the tunnel was proved live at
	// provedAt under this exact binding. Consuming it later requires that the
	// proof is still recent and that the tunnel has not since failed. Both
	// checks are local and add no round trip, so the cold fast path keeps its
	// latency while regaining a liveness component before Commit.
	if connection.provedAt.IsZero() ||
		current.Sub(connection.provedAt) > coldPredicateFreshness {
		return errors.New(
			"cold DirectAWG predicate proof is no longer fresh",
		)
	}
	health := connection.connection.Health()
	if health == nil {
		return errors.New("cold DirectAWG connection health is unavailable")
	}
	select {
	case err, ok := <-health:
		if !ok || err == nil {
			return errors.New("cold DirectAWG connection health was lost")
		}
		return fmt.Errorf(
			"cold DirectAWG connection health was lost: %w", err,
		)
	default:
	}
	return nil
}

func (connection *preverifiedDirectConnection) FreshAWGHandshake(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	return connection.check(ctx, binding)
}

func (connection *preverifiedDirectConnection) VerifyBidirectional(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	return connection.check(ctx, binding)
}

func (connection *preverifiedDirectConnection) VerifyProtectedDNS(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	return connection.check(ctx, binding)
}

func (connection *preverifiedDirectConnection) VerifyTunnelCanary(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	return connection.check(ctx, binding)
}

func (connection *preverifiedDirectConnection) Commit(
	ctx context.Context,
	binding connectivity.Binding,
) error {
	if err := connection.check(ctx, binding); err != nil {
		return err
	}
	return connection.connection.Commit(ctx, binding)
}

func (connection *preverifiedDirectConnection) Health() <-chan error {
	if connection == nil || nilInterface(connection.connection) {
		return nil
	}
	return connection.connection.Health()
}

func (connection *preverifiedDirectConnection) Close() error {
	if connection == nil || nilInterface(connection.connection) {
		return nil
	}
	return connection.connection.Close()
}

func (connection *preverifiedDirectConnection) RetryClose() error {
	if connection == nil || nilInterface(connection.connection) {
		return nil
	}
	if retryable, ok :=
		connection.connection.(retryableCandidateConnection); ok {
		return retryable.RetryClose()
	}
	return connection.connection.Close()
}

type retryableCandidateConnection interface {
	connectivity.CandidateConnection
	RetryClose() error
}

// liveDirectProbeCloseOwner retains the only reference to a probe connection
// until staged teardown is proven. The caller waits for a bounded interval,
// while retryable Linux cleanup continues independently with capped backoff if
// that interval or the original operation deadline expires.
type liveDirectProbeCloseOwner struct {
	connection connectivity.CandidateConnection

	start sync.Once
	done  chan struct{}

	mu  sync.Mutex
	err error
}

func newLiveDirectProbeCloseOwner(
	connection connectivity.CandidateConnection,
) *liveDirectProbeCloseOwner {
	return &liveDirectProbeCloseOwner{
		connection: connection,
		done:       make(chan struct{}),
	}
}

func (owner *liveDirectProbeCloseOwner) Close(ctx context.Context) error {
	if owner == nil || nilInterface(owner.connection) {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	owner.start.Do(func() {
		go owner.recover()
	})
	waitContext, cancel := context.WithTimeout(
		ctx, liveDirectProbeCloseWait,
	)
	defer cancel()
	select {
	case <-owner.done:
		owner.mu.Lock()
		defer owner.mu.Unlock()
		return owner.err
	case <-waitContext.Done():
		return context.Cause(waitContext)
	}
}

func (owner *liveDirectProbeCloseOwner) recover() {
	err := owner.connection.Close()
	retryable, canRetry := owner.connection.(retryableCandidateConnection)
	if canRetry {
		delay := liveDirectProbeRetryMinimum
		for err != nil {
			timer := time.NewTimer(delay)
			<-timer.C
			err = retryable.RetryClose()
			if delay < liveDirectProbeRetryMaximum {
				delay *= 2
				if delay > liveDirectProbeRetryMaximum {
					delay = liveDirectProbeRetryMaximum
				}
			}
		}
	}
	owner.mu.Lock()
	owner.err = err
	owner.mu.Unlock()
	close(owner.done)
}

func newDirectProbeBinding(
	input preparation.DirectAWGPreparationInput,
	expiresAt time.Time,
) (connectivity.Binding, error) {
	attemptID, err := mobility.NewSessionID()
	if err != nil {
		return connectivity.Binding{}, err
	}
	sessionID, err := mobility.NewSessionID()
	if err != nil {
		return connectivity.Binding{}, err
	}
	nonce, err := mobility.NewSessionID()
	if err != nil {
		return connectivity.Binding{}, err
	}
	return connectivity.Binding{
		AttemptID:      attemptID,
		Profile:        input.Context.Profile,
		Mode:           input.Context.Mode,
		ManifestDigest: input.Context.ManifestDigest,
		CandidateID:    input.Context.Descriptor.ID,
		NodeID:         input.Context.Descriptor.NodeID,
		SessionID:      sessionID,
		PSKGeneration:  input.Context.PSKGeneration,
		SequenceEpoch:  1,
		Nonce:          nonce,
		ExpiresAt:      expiresAt.UTC(),
	}, nil
}

type directProbeEvidence struct {
	mu       sync.Mutex
	binding  connectivity.Binding
	provedAt time.Time
	closed   bool
}

func (evidence *directProbeEvidence) Close(
	context.Context,
) error {
	if evidence == nil {
		return nil
	}
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	if evidence.closed {
		return nil
	}
	evidence.closed = true
	evidence.binding = connectivity.Binding{}
	evidence.provedAt = time.Time{}
	return nil
}
