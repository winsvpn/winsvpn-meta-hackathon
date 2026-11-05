package h3candidate

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/carrierauth"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/echconfig"
	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/internal/wcf3"
)

var (
	ErrBindingMismatch = errors.New("H3 candidate binding mismatch")
	ErrClosed          = errors.New("H3 candidate connection is closed")
	ErrSessionExpired  = errors.New("H3 candidate session trust expired")
)

const (
	DefaultTeardownTimeout = 2 * time.Second
	MaxTeardownTimeout     = 5 * time.Second
)

// ProtectedUnderlay is a platform-owned QUIC path whose socket is constrained
// by the Winn kill switch / protected-underlay policy. DialQUICPath transfers
// QUIC transport ownership to carrier.H3Dialer; Close releases only the
// platform protection lease. Close must be idempotent and honor cancellation.
type ProtectedUnderlay interface {
	DialQUICPath(
		context.Context,
		string,
		*tls.Config,
		*quic.Config,
	) (*quic.Conn, *quic.Transport, error)
	ProtectMigrationSocket(
		context.Context,
		connectivity.Binding,
		net.PacketConn,
	) error
	Health() <-chan error
	Close(context.Context) error
}

type ProtectedUnderlayFactory interface {
	Open(
		context.Context,
		connectivity.Binding,
	) (ProtectedUnderlay, error)
}

// PreparedProtectedUnderlay may complete its protected socket and QUIC/TLS
// work before a user click, then accept exactly one click-time Binding. It must
// reject migration until Claim succeeds.
type PreparedProtectedUnderlay interface {
	ProtectedUnderlay
	Claim(connectivity.Binding) error
}

// WarmProtectedUnderlayFactory is the optional production preparation
// extension. expiresAt is the maximum trust lifetime of the prepared carrier.
type WarmProtectedUnderlayFactory interface {
	ProtectedUnderlayFactory
	Prepare(
		context.Context,
		time.Time,
	) (PreparedProtectedUnderlay, error)
}

// TunnelController attaches the real inner AWG data plane to the established
// H3 PacketConn. The adapter owns carrierPath and closes it after Session.Close.
type TunnelController interface {
	Start(
		context.Context,
		net.PacketConn,
		connectivity.Binding,
		wcf3.Context,
	) (TunnelSession, error)
}

// TunnelSession must query actual AWG runtime state. A production
// implementation must not return success from cached configuration or a
// carrier-only probe. Close must be idempotent and honor cancellation.
type TunnelSession interface {
	FreshAWGHandshake(
		context.Context,
		connectivity.Binding,
		wcf3.Context,
	) error
	VerifyBidirectional(
		context.Context,
		connectivity.Binding,
		wcf3.Context,
	) error
	Health() <-chan error
	Close(context.Context) error
}

// CandidateVerifier runs probes exclusively through the supplied candidate
// session. Canary verification receives WCF3 context so it can bind the
// request/response to this exact attempt, candidate, and sequence epoch.
type CandidateVerifier interface {
	VerifyProtectedDNS(
		context.Context,
		TunnelSession,
		connectivity.Binding,
		wcf3.Context,
	) error
	VerifyTunnelCanary(
		context.Context,
		TunnelSession,
		connectivity.Binding,
		wcf3.Context,
	) error
}

// RouteDNSTransaction is staged during Dial. Commit is invoked only after the
// coordinator has verified every online predicate. Rollback must synchronously
// remove both staged and committed state, be idempotent, and honor cancellation.
type RouteDNSTransaction interface {
	Commit(context.Context, connectivity.Binding, wcf3.Context) error
	Rollback(context.Context) error
}

type TransactionFactory interface {
	Prepare(
		context.Context,
		TunnelSession,
		connectivity.Binding,
		wcf3.Context,
	) (RouteDNSTransaction, error)
}

type Config struct {
	Descriptor connectivity.CandidateDescriptor
	// SessionExpiresAt is the trusted lifetime of an already-committed
	// connection. Binding.ExpiresAt remains the much shorter authority for
	// candidate work during the three-second connect operation.
	SessionExpiresAt time.Time
	Dialer           *carrier.H3Dialer
	Underlay         ProtectedUnderlayFactory
	Tunnel           TunnelController
	Verifier         CandidateVerifier
	Transactions     TransactionFactory
	// Now MUST be safe to call from multiple goroutines. newConnection starts
	// monitorHealth on its own goroutine, so an injected clock is read
	// concurrently with any caller that mutates it — this is not optional and
	// not a test-only concern.
	//
	// This is a caller contract, deliberately not enforced here: wrapping an
	// opaque function in a constructor mutex would serialise calls *through*
	// the wrapper while leaving a caller that mutates captured state outside it
	// unsynchronised, which is false assurance rather than safety. The natural
	// way to write a fake clock — a captured variable plus a closure — is
	// exactly the unsafe shape, and it produced two intermittent -race failures
	// before being caught. Tests must use a concurrency-safe clock; see
	// newTestClock in candidate_test.go. If compile-time enforcement is wanted
	// later, replace this with a Clock interface whose implementations own
	// their synchronisation, or drop post-construction clock mutation.
	Now func() time.Time
	// TeardownTimeout is frozen when the candidate is constructed.
	TeardownTimeout time.Duration
}

type Candidate struct {
	descriptor       connectivity.CandidateDescriptor
	sessionExpiresAt time.Time
	dial             packetDialer
	underlay         ProtectedUnderlayFactory
	tunnel           TunnelController
	verifier         CandidateVerifier
	transactions     TransactionFactory
	now              func() time.Time
	teardownTimeout  time.Duration
}

type packetDialer func(
	context.Context,
	connectivity.Binding,
	ProtectedUnderlay,
) (net.PacketConn, error)

var _ connectivity.Candidate = (*Candidate)(nil)

func New(config Config) (*Candidate, error) {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	current := now().UTC()
	if err := config.Descriptor.Validate(current); err != nil {
		return nil, fmt.Errorf("H3 candidate descriptor: %w", err)
	}
	// A zero session lifetime is rejected rather than defaulted. Substituting
	// the descriptor expiry here is the fail-back pattern that let a committed
	// H3 session inherit the short candidate-work deadline; the caller must
	// state the trusted lifetime explicitly.
	sessionExpiresAt := config.SessionExpiresAt.UTC()
	if sessionExpiresAt.IsZero() {
		return nil, errors.New("H3 candidate session lifetime is required")
	}
	if !sessionExpiresAt.After(current) ||
		sessionExpiresAt.After(config.Descriptor.ExpiresAt) {
		return nil, errors.New(
			"H3 candidate session lifetime exceeds trusted descriptor",
		)
	}
	if config.Descriptor.Carrier != connectivity.CarrierHTTP3 {
		return nil, errors.New("H3 candidate descriptor carrier is not HTTP/3")
	}
	if nilInterface(config.Underlay) {
		return nil, errors.New("production H3 candidate requires protected underlay")
	}
	if nilInterface(config.Tunnel) || nilInterface(config.Verifier) ||
		nilInterface(config.Transactions) {
		return nil, errors.New(
			"H3 candidate tunnel, verifier, and transaction controller are required",
		)
	}
	teardownTimeout := config.TeardownTimeout
	if teardownTimeout == 0 {
		teardownTimeout = DefaultTeardownTimeout
	}
	if teardownTimeout < 0 || teardownTimeout > MaxTeardownTimeout {
		return nil, fmt.Errorf(
			"H3 candidate teardown timeout must be within (0, %s]",
			MaxTeardownTimeout,
		)
	}
	snapshot, err := snapshotProductionDialer(config.Dialer)
	if err != nil {
		return nil, err
	}
	dial := func(
		ctx context.Context,
		binding connectivity.Binding,
		underlay ProtectedUnderlay,
	) (net.PacketConn, error) {
		dialer := snapshot
		dialer.SessionID = binding.SessionID
		dialer.ManifestDigest = binding.ManifestDigest
		dialer.SequenceEpoch = fmt.Sprintf("%032x", binding.SequenceEpoch)
		dialer.DialQUIC = nil
		dialer.DialQUICPath = underlay.DialQUICPath
		return dialer.Dial(ctx)
	}
	candidate, err := newCandidate(
		config.Descriptor,
		dial,
		config.Underlay,
		config.Tunnel,
		config.Verifier,
		config.Transactions,
		now,
		teardownTimeout,
	)
	if err != nil {
		return nil, err
	}
	candidate.sessionExpiresAt = sessionExpiresAt
	return candidate, nil
}

func newCandidate(
	descriptor connectivity.CandidateDescriptor,
	dial packetDialer,
	underlay ProtectedUnderlayFactory,
	tunnel TunnelController,
	verifier CandidateVerifier,
	transactions TransactionFactory,
	now func() time.Time,
	teardownTimeout time.Duration,
) (*Candidate, error) {
	if dial == nil || nilInterface(tunnel) || nilInterface(verifier) ||
		nilInterface(transactions) {
		return nil, errors.New("H3 candidate dependencies are incomplete")
	}
	if now == nil {
		now = time.Now
	}
	if teardownTimeout == 0 {
		teardownTimeout = DefaultTeardownTimeout
	}
	if teardownTimeout < 0 || teardownTimeout > MaxTeardownTimeout {
		return nil, errors.New("H3 candidate teardown timeout is invalid")
	}
	return &Candidate{
		descriptor:       descriptor,
		sessionExpiresAt: descriptor.ExpiresAt.UTC(),
		dial:             dial,
		underlay:         underlay,
		tunnel:           tunnel,
		verifier:         verifier,
		transactions:     transactions,
		now:              now,
		teardownTimeout:  teardownTimeout,
	}, nil
}

func (candidate *Candidate) Descriptor() connectivity.CandidateDescriptor {
	return candidate.descriptor
}

func (candidate *Candidate) Dial(
	raceContext context.Context,
	binding connectivity.Binding,
) (connectivity.CandidateConnection, error) {
	if raceContext == nil {
		return nil, errors.New("H3 candidate dial context is required")
	}
	now := candidate.now().UTC()
	if err := candidate.validateBinding(binding, now); err != nil {
		return nil, err
	}
	if !candidate.sessionExpiresAt.After(now) {
		return nil, ErrSessionExpired
	}
	frameContext, err := wcf3.ContextFromBinding(binding, now)
	if err != nil {
		return nil, fmt.Errorf("derive H3 WCF3 binding: %w", err)
	}

	// Preserve caller values but detach cancellation for the winning lifetime.
	// The bridge below still cancels all work while Dial is in progress.
	lifetimeContext, cancelLifetime := context.WithCancel(
		context.WithoutCancel(raceContext),
	)
	stopRaceBridge := context.AfterFunc(raceContext, cancelLifetime)
	var underlay ProtectedUnderlay
	var underlayHealth <-chan error
	if !nilInterface(candidate.underlay) {
		underlay, err = candidate.underlay.Open(lifetimeContext, binding)
		if err != nil {
			stopRaceBridge()
			cancelLifetime()
			return nil, errors.Join(
				fmt.Errorf("open protected H3 underlay: %w", err),
				candidate.cleanup(nil, nil, nil, underlay),
			)
		}
		if nilInterface(underlay) {
			stopRaceBridge()
			cancelLifetime()
			return nil, errors.New("protected H3 underlay is nil")
		}
		underlayHealth = underlay.Health()
		if underlayHealth == nil {
			stopRaceBridge()
			cancelLifetime()
			return nil, errors.Join(
				errors.New("protected H3 underlay has no health channel"),
				candidate.cleanup(nil, nil, nil, underlay),
			)
		}
	}

	carrierPath, err := candidate.dial(lifetimeContext, binding, underlay)
	if err != nil {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			fmt.Errorf("dial authenticated RFC 9298 H3 carrier: %w", err),
			candidate.cleanup(nil, nil, carrierPath, underlay),
		)
	}
	if nilInterface(carrierPath) {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			errors.New("H3 carrier returned a nil packet connection"),
			candidate.cleanup(nil, nil, nil, underlay),
		)
	}

	session, err := candidate.tunnel.Start(
		lifetimeContext, carrierPath, binding, frameContext,
	)
	if err != nil {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			fmt.Errorf("start real AWG tunnel over H3: %w", err),
			candidate.cleanup(nil, session, carrierPath, underlay),
		)
	}
	if nilInterface(session) {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			errors.New("AWG tunnel session is nil"),
			candidate.cleanup(nil, nil, carrierPath, underlay),
		)
	}
	sessionHealth := session.Health()
	if sessionHealth == nil {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			errors.New("AWG tunnel session has no health channel"),
			candidate.cleanup(nil, session, carrierPath, underlay),
		)
	}

	transaction, err := candidate.transactions.Prepare(
		lifetimeContext, session, binding, frameContext,
	)
	if err != nil {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			fmt.Errorf("stage candidate route and DNS transaction: %w", err),
			candidate.cleanup(transaction, session, carrierPath, underlay),
		)
	}
	if nilInterface(transaction) {
		stopRaceBridge()
		cancelLifetime()
		return nil, errors.Join(
			errors.New("candidate route and DNS transaction is nil"),
			candidate.cleanup(nil, session, carrierPath, underlay),
		)
	}

	connection := newConnection(connectionConfig{
		descriptor:       candidate.descriptor,
		binding:          binding,
		sessionExpiresAt: candidate.sessionExpiresAt,
		frameContext:     frameContext,
		carrierPath:      carrierPath,
		underlay:         underlay,
		underlayHealth:   underlayHealth,
		session:          session,
		sessionHealth:    sessionHealth,
		verifier:         candidate.verifier,
		transaction:      transaction,
		lifetimeContext:  lifetimeContext,
		cancelLifetime:   cancelLifetime,
		now:              candidate.now,
		teardownTimeout:  candidate.teardownTimeout,
	})

	// If the race context won concurrently, the candidate was never safely
	// handed off. Otherwise the winning connection is now independent of it.
	if !stopRaceBridge() && raceContext.Err() != nil {
		_ = connection.Close()
		return nil, context.Cause(raceContext)
	}
	return connection, nil
}

func (candidate *Candidate) cleanup(
	transaction RouteDNSTransaction,
	session TunnelSession,
	carrierPath net.PacketConn,
	underlay ProtectedUnderlay,
) error {
	return cleanupWithTimeout(
		candidate.teardownTimeout,
		transaction,
		session,
		carrierPath,
		underlay,
	)
}

func (candidate *Candidate) validateBinding(
	binding connectivity.Binding,
	now time.Time,
) error {
	if err := binding.Validate(now); err != nil {
		return fmt.Errorf("H3 candidate binding: %w", err)
	}
	if binding.CandidateID != candidate.descriptor.ID ||
		binding.NodeID != candidate.descriptor.NodeID ||
		binding.ExpiresAt.After(candidate.descriptor.ExpiresAt) {
		return ErrBindingMismatch
	}
	if !binding.Mode.Allows(connectivity.CarrierHTTP3) {
		return errors.New("H3 candidate is forbidden by binding mode")
	}
	return nil
}

func snapshotProductionDialer(
	source *carrier.H3Dialer,
) (carrier.H3Dialer, error) {
	if source == nil || source.TLSConfig == nil {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate dialer and TLS configuration are required",
		)
	}
	if source.Suite.Name != "x25519-mlkem768" ||
		source.Suite.Curve != tls.X25519MLKEM768 {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate requires X25519 plus ML-KEM-768",
		)
	}
	tlsConfiguration := source.TLSConfig.Clone()
	// The offered group list is the client's first-flight fingerprint, so it is
	// deliberately wider than the one group Winn will accept; see
	// tlsconfig.ClientCurvePreferences. What must not drift is that it is
	// exactly that list - a narrower one is the old single-group signature, a
	// wider one would put a group ahead of X25519MLKEM768 and draw a
	// HelloRetryRequest on every connection. Acceptance is unchanged and is
	// enforced by the VerifyConnection required below.
	if tlsConfiguration.InsecureSkipVerify ||
		tlsConfiguration.ServerName == "" ||
		tlsConfiguration.MinVersion != tls.VersionTLS13 ||
		tlsConfiguration.MaxVersion != tls.VersionTLS13 ||
		!slices.Equal(
			tlsConfiguration.CurvePreferences,
			tlsconfig.ClientCurvePreferences(source.Suite),
		) {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate TLS profile is not strict hybrid TLS 1.3",
		)
	}
	if err := echconfig.ValidateConfigList(
		tlsConfiguration.EncryptedClientHelloConfigList,
	); err != nil {
		return carrier.H3Dialer{}, fmt.Errorf(
			"production H3 candidate requires valid ECH: %w", err,
		)
	}
	if tlsConfiguration.VerifyConnection == nil {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate requires peer verification",
		)
	}
	previousVerifyConnection := tlsConfiguration.VerifyConnection
	tlsConfiguration.VerifyConnection = func(
		state tls.ConnectionState,
	) error {
		if err := previousVerifyConnection(state); err != nil {
			return err
		}
		if !state.ECHAccepted {
			return errors.New(
				"production H3 candidate requires accepted ECH",
			)
		}
		return nil
	}
	if source.QUICConfig != nil && source.QUICConfig.Allow0RTT {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate forbids QUIC 0-RTT",
		)
	}
	if source.Template == nil || source.PublicTarget == "" ||
		source.ResponseVerifier == nil {
		return carrier.H3Dialer{}, errors.New(
			"production H3 candidate authentication is incomplete",
		)
	}
	if source.AuthorizationMode == carrierauth.AuthModeAnonymousToken {
		if err := carrier.ValidateAnonymousClientTLS(
			tlsConfiguration,
		); err != nil {
			return carrier.H3Dialer{}, err
		}
		if err := carrier.ValidateAnonymousQUICConfig(
			source.QUICConfig,
		); err != nil {
			return carrier.H3Dialer{}, err
		}
	}
	snapshot := *source
	snapshot.TLSConfig = tlsConfiguration
	if source.QUICConfig != nil {
		snapshot.QUICConfig = source.QUICConfig.Clone()
		snapshot.QUICConfig.Allow0RTT = false
	}
	responseVerifier := *source.ResponseVerifier
	snapshot.ResponseVerifier = &responseVerifier
	if source.PrivacyToken != nil {
		token := *source.PrivacyToken
		snapshot.PrivacyToken = &token
	}
	// Production always receives its network socket through ProtectedUnderlay.
	snapshot.DialQUIC = nil
	snapshot.DialQUICPath = nil
	return snapshot, nil
}

func nilInterface(value any) bool {
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
