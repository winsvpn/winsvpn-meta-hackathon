package linuxauto

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"time"

	"winsvpn.local/winnprotocol/internal/autoconnect"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/mobility"
	"winsvpn.local/winnprotocol/internal/preparation"
)

const defaultFailedAssemblyCloseTimeout = 5 * time.Second

// AutoRuntimeConfig contains only click-bound behavior. Manifest, PSK,
// credential, carrier, and policy configuration belongs to the already
// verified preparation assembler and cannot be replaced here.
type AutoRuntimeConfig struct {
	Deadline time.Duration
	Identity autoconnect.IdentitySource
}

type preparedAssembler func(
	context.Context,
	preparation.VerifiedAssemblyRequest,
) (autoconnect.PreparedGeneration, error)

// AutoRuntime is the production Linux join between verified background
// assembly and one single-use click attempt.
type AutoRuntime struct {
	assemble preparedAssembler
	deadline time.Duration
	identity autoconnect.IdentitySource
}

func NewAutoRuntime(
	assembler *preparation.VerifiedPreparationAssembler,
	config AutoRuntimeConfig,
) (*AutoRuntime, error) {
	if assembler == nil {
		return nil, errors.New(
			"verified Linux Auto preparation assembler is required",
		)
	}
	return newAutoRuntime(
		func(
			ctx context.Context,
			request preparation.VerifiedAssemblyRequest,
		) (autoconnect.PreparedGeneration, error) {
			return assembler.Assemble(ctx, request)
		},
		config,
	)
}

func newAutoRuntime(
	assemble preparedAssembler,
	config AutoRuntimeConfig,
) (*AutoRuntime, error) {
	if assemble == nil {
		return nil, errors.New(
			"verified Linux Auto assembly function is required",
		)
	}
	if config.Deadline == 0 {
		config.Deadline = connectivity.DefaultDeadline
	}
	if config.Deadline < 0 ||
		config.Deadline > connectivity.MaxDeadline {
		return nil, fmt.Errorf(
			"linux Auto click deadline must be within (0, %s]",
			connectivity.MaxDeadline,
		)
	}
	return &AutoRuntime{
		assemble: assemble,
		deadline: config.Deadline,
		identity: config.Identity,
	}, nil
}

// Prepare completes all verified background work and returns one dormant
// single-use click attempt. No manifest, network, credential, or carrier work
// is deferred into Attempt.Connect.
func (runtime *AutoRuntime) Prepare(
	ctx context.Context,
	request preparation.VerifiedAssemblyRequest,
) (*autoconnect.Attempt, error) {
	if runtime == nil {
		return nil, errors.New("linux Auto runtime is unavailable")
	}
	if request.PreconnectIdentity != (preparation.PreconnectIdentity{}) {
		return nil, errors.New(
			"ordinary Auto preparation cannot accept a cold identity",
		)
	}
	return runtime.prepare(ctx, request, runtime.identity)
}

// PrepareCold begins only after a true-cold user action. It reserves the
// complete immutable attempt identity and a conservative candidate-work
// expiry before any network preparation, allowing a carrier to prove the
// exact click Binding without granting a second or extended click budget.
func (runtime *AutoRuntime) PrepareCold(
	ctx context.Context,
	request preparation.VerifiedAssemblyRequest,
) (*autoconnect.Attempt, error) {
	if runtime == nil || runtime.assemble == nil {
		return nil, errors.New("linux Auto runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	if request.PreconnectIdentity != (preparation.PreconnectIdentity{}) {
		return nil, errors.New(
			"cold Auto identity must be allocated by the runtime",
		)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New(
			"cold Auto preparation requires the user-operation deadline",
		)
	}
	now := time.Now().UTC()
	clickLimit := now.Add(runtime.deadline)
	if clickLimit.Before(deadline) {
		deadline = clickLimit
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 || remaining > connectivity.MaxDeadline {
		return nil, errors.New(
			"cold Auto preparation deadline is invalid",
		)
	}
	cleanupReserve := 500 * time.Millisecond
	if quarter := remaining / 4; cleanupReserve > quarter {
		cleanupReserve = quarter
	}
	expiresAt := deadline.Add(-cleanupReserve).UTC()
	identity := runtime.identity
	if identity == nil {
		identity = randomRuntimeIdentity
	}
	sessionID, sequenceEpoch, err := identity(ctx)
	if err != nil {
		return nil, fmt.Errorf("reserve cold Auto session: %w", err)
	}
	attemptID, nonce, err := randomAttemptSeed()
	if err != nil {
		return nil, fmt.Errorf("reserve cold Auto attempt: %w", err)
	}
	request.PreconnectIdentity = preparation.PreconnectIdentity{
		AttemptID:     attemptID,
		SessionID:     sessionID,
		SequenceEpoch: sequenceEpoch,
		Nonce:         nonce,
		ExpiresAt:     expiresAt,
	}
	fixedIdentity := func(
		identityContext context.Context,
	) (string, uint64, error) {
		if cause := context.Cause(identityContext); cause != nil {
			return "", 0, cause
		}
		return sessionID, sequenceEpoch, nil
	}
	return runtime.prepare(ctx, request, fixedIdentity)
}

func (runtime *AutoRuntime) prepare(
	ctx context.Context,
	request preparation.VerifiedAssemblyRequest,
	identity autoconnect.IdentitySource,
) (*autoconnect.Attempt, error) {
	if runtime == nil || runtime.assemble == nil {
		return nil, errors.New("linux Auto runtime is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, cause
	}
	generation, err := runtime.assemble(ctx, request)
	if err != nil {
		return nil, fmt.Errorf(
			"assemble verified Linux Auto generation: %w", err,
		)
	}
	if nilPreparedGeneration(generation) {
		return nil, errors.New(
			"verified Linux Auto assembler returned no generation",
		)
	}
	attempt, err := autoconnect.New(autoconnect.Config{
		Generation: generation,
		Deadline:   runtime.deadline,
		Identity:   identity,
	})
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(),
			defaultFailedAssemblyCloseTimeout,
		)
		defer cancel()
		return nil, errors.Join(
			fmt.Errorf("create Linux Auto click attempt: %w", err),
			generation.Close(cleanupContext),
		)
	}
	return attempt, nil
}

func randomRuntimeIdentity(
	ctx context.Context,
) (string, uint64, error) {
	if cause := context.Cause(ctx); cause != nil {
		return "", 0, cause
	}
	sessionID, err := mobility.NewSessionID()
	if err != nil {
		return "", 0, err
	}
	var encoded [8]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return "", 0, err
	}
	epoch := binary.BigEndian.Uint64(encoded[:])
	if epoch == 0 {
		epoch = 1
	}
	return sessionID, epoch, context.Cause(ctx)
}

func randomAttemptSeed() (string, string, error) {
	var encoded [32]byte
	if _, err := rand.Read(encoded[:]); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(encoded[:16]),
		hex.EncodeToString(encoded[16:]), nil
}

func nilPreparedGeneration(
	generation autoconnect.PreparedGeneration,
) bool {
	if generation == nil {
		return true
	}
	value := reflect.ValueOf(generation)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
