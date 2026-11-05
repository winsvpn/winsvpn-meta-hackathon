package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/protocol"
)

var (
	ErrRotationQueued      = errors.New("hybrid PSK rotation is queued")
	ErrSnapshotUnavailable = errors.New("current hybrid PSK snapshot is unavailable")
	ErrGenerationStale     = errors.New("hybrid PSK generation is stale")
	ErrRevoked             = errors.New("hybrid PSK generation is revoked")
	ErrCoordinatorClosed   = errors.New("hybrid PSK coordinator is closed")
)

// RekeyClient is implemented by bootstrap.Client. It exists so the coordinator
// state machine can be tested without weakening bootstrap verification.
type RekeyClient interface {
	NewRequest(
		deviceID string,
		peerPublicKey string,
		currentGeneration uint64,
	) (protocol.RekeyRequest, error)
	Rekey(
		context.Context,
		protocol.RekeyRequest,
	) (bootstrap.Result, error)
}

type CoordinatorConfig struct {
	Applier       awg.Applier
	StatePath     string
	DeviceID      string
	PeerPublicKey string
	Suite         string
	Now           func() time.Time
}

type Binding struct {
	Suite         string
	DeviceID      string
	PeerPublicKey string
}

// Coordinator is the single linearization boundary for client rekey/apply,
// revocation, and preparation pins. Callers that need preparation snapshots
// must retain this instance and invoke Rotate instead of the compatibility Run
// function.
type Coordinator struct {
	applier       awg.Applier
	statePath     string
	deviceID      string
	peerPublicKey string
	suite         string
	now           func() time.Time

	mu               sync.Mutex
	changed          chan struct{}
	pins             int
	waitingMutations int
	mutating         bool
	closed           bool
	loaded           bool
	state            ClientState
	currentPSK       []byte
}

type PinRequest struct {
	ControllerID       string
	Suite              string
	DeviceID           string
	PeerPublicKey      string
	ExpectedGeneration uint64
}

type PinnedSnapshot struct {
	ObservedAt time.Time
	State      ClientState
	PSK        []byte
	Resource   *PinnedPSK
}

// PinnedPSK prevents rotation and revocation until Close. Close is idempotent.
type PinnedPSK struct {
	coordinator *Coordinator
	once        sync.Once
}

func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	if isNilInterface(config.Applier) ||
		config.StatePath == "" ||
		!protocol.ValidDeviceID(config.DeviceID) ||
		!protocol.ValidSuite(config.Suite) {
		return nil, errors.New("hybrid PSK coordinator configuration is invalid")
	}
	if err := protocol.ValidatePeerPublicKey(
		config.PeerPublicKey,
	); err != nil {
		return nil, fmt.Errorf("hybrid PSK coordinator peer key: %w", err)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Coordinator{
		applier:       config.Applier,
		statePath:     config.StatePath,
		deviceID:      config.DeviceID,
		peerPublicKey: config.PeerPublicKey,
		suite:         config.Suite,
		now:           config.Now,
		changed:       make(chan struct{}),
	}, nil
}

func (coordinator *Coordinator) Binding() (Binding, bool) {
	if coordinator == nil {
		return Binding{}, false
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.changed == nil || coordinator.closed {
		return Binding{}, false
	}
	return Binding{
		Suite:         coordinator.suite,
		DeviceID:      coordinator.deviceID,
		PeerPublicKey: coordinator.peerPublicKey,
	}, true
}

func (coordinator *Coordinator) Rotate(
	ctx context.Context,
	client RekeyClient,
) (Result, error) {
	if coordinator == nil {
		return Result{}, ErrCoordinatorClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if isNilInterface(client) {
		return Result{}, errors.New("bootstrap rekey client is required")
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return Result{}, err
	}
	defer coordinator.endMutation()

	clientState, err := loadClientState(
		coordinator.statePath,
		coordinator.deviceID,
		coordinator.peerPublicKey,
	)
	if err != nil {
		return Result{}, err
	}
	coordinator.installState(clientState)

	var request protocol.RekeyRequest
	if clientState.Pending != nil {
		request = *clientState.Pending
		if request.Suite != coordinator.suite {
			return Result{}, fmt.Errorf(
				"pending request uses suite %s; retry with that suite",
				request.Suite,
			)
		}
	} else {
		request, err = client.NewRequest(
			coordinator.deviceID,
			coordinator.peerPublicKey,
			clientState.Generation,
		)
		if err != nil {
			return Result{}, err
		}
		if request.Suite != coordinator.suite ||
			request.DeviceID != coordinator.deviceID ||
			request.PeerPublicKey != coordinator.peerPublicKey ||
			request.CurrentGeneration != clientState.Generation {
			return Result{}, errors.New(
				"bootstrap request differs from coordinator binding",
			)
		}
		clientState.ControllerID = request.ControllerID
		clientState.Pending = cloneRekeyRequest(&request)
		if err := saveClientState(
			coordinator.statePath, clientState,
		); err != nil {
			return Result{}, fmt.Errorf(
				"persist pending request before transmission: %w",
				err,
			)
		}
		coordinator.installState(clientState)
	}
	if clientState.ControllerID != "" &&
		clientState.ControllerID != request.ControllerID {
		return Result{}, errors.New(
			"pending request controller differs from client state",
		)
	}
	clientState.ControllerID = request.ControllerID

	rekeyResult, err := client.Rekey(ctx, request)
	if err != nil {
		return Result{}, err
	}
	defer clear(rekeyResult.PSK)
	if cause := context.Cause(ctx); cause != nil {
		return Result{}, cause
	}
	if err := validateRekeyResult(
		rekeyResult, request, coordinator.suite,
		coordinator.now().UTC(),
	); err != nil {
		return Result{}, err
	}
	if err := coordinator.applier.Apply(
		ctx, request.PeerPublicKey, rekeyResult.PSK,
	); err != nil {
		revokeErr := coordinator.failClosed(clientState)
		return Result{}, errors.Join(
			fmt.Errorf("apply client AWG PSK: %w", err),
			revokeErr,
		)
	}
	if cause := context.Cause(ctx); cause != nil {
		revokeErr := coordinator.failClosed(clientState)
		return Result{}, errors.Join(cause, revokeErr)
	}

	clientState.ControllerID = rekeyResult.Response.ControllerID
	clientState.Suite = rekeyResult.Response.Suite
	clientState.Generation = rekeyResult.Response.Generation
	clientState.KeyID = rekeyResult.Response.KeyID
	clientState.ExpiresAt = rekeyResult.Response.ExpiresAt
	clientState.Pending = nil
	clientState.Revoked = false
	if err := saveClientState(
		coordinator.statePath, clientState,
	); err != nil {
		revokeErr := coordinator.failClosed(clientState)
		return Result{}, errors.Join(
			fmt.Errorf("persist applied generation: %w", err),
			revokeErr,
		)
	}
	coordinator.installApplied(clientState, rekeyResult.PSK)
	return Result{
		Suite:       rekeyResult.Response.Suite,
		Generation:  rekeyResult.Response.Generation,
		KeyID:       rekeyResult.Response.KeyID,
		IssuedAt:    rekeyResult.Response.IssuedAt,
		ExpiresAt:   rekeyResult.Response.ExpiresAt,
		TLSVersion:  rekeyResult.TLSVersion,
		Curve:       rekeyResult.Curve.String(),
		CipherSuite: rekeyResult.CipherSuite,
		Adapter:     coordinator.applier.Description(),
	}, nil
}

func (coordinator *Coordinator) Pin(
	ctx context.Context,
	request PinRequest,
) (PinnedSnapshot, error) {
	if coordinator == nil {
		return PinnedSnapshot{}, ErrCoordinatorClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return PinnedSnapshot{}, cause
	}
	if !protocol.ValidDeviceID(request.ControllerID) ||
		request.Suite != coordinator.suite ||
		request.DeviceID != coordinator.deviceID ||
		request.PeerPublicKey != coordinator.peerPublicKey {
		return PinnedSnapshot{}, errors.New(
			"hybrid PSK pin binding is invalid",
		)
	}

	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.closed {
		return PinnedSnapshot{}, ErrCoordinatorClosed
	}
	if coordinator.waitingMutations != 0 || coordinator.mutating {
		return PinnedSnapshot{}, ErrRotationQueued
	}
	if err := coordinator.restoreCurrentLocked(
		ctx, request.ControllerID,
	); err != nil {
		return PinnedSnapshot{}, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return PinnedSnapshot{}, cause
	}
	now := coordinator.now().UTC()
	if err := coordinator.validateCurrentLocked(
		request, now,
	); err != nil {
		return PinnedSnapshot{}, err
	}
	psk := bytes.Clone(coordinator.currentPSK)
	if len(psk) != 32 || allZeroPSK(psk) {
		clear(psk)
		return PinnedSnapshot{}, ErrSnapshotUnavailable
	}
	coordinator.pins++
	return PinnedSnapshot{
		ObservedAt: now,
		State:      cloneClientState(coordinator.state),
		PSK:        psk,
		Resource:   &PinnedPSK{coordinator: coordinator},
	}, nil
}

// Revoke waits for existing pins, blocks new pins as soon as it is queued,
// persists the fail-closed state, and clears the coordinator-owned PSK.
func (coordinator *Coordinator) Revoke(ctx context.Context) error {
	if coordinator == nil {
		return ErrCoordinatorClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		return err
	}
	defer coordinator.endMutation()
	state, err := loadClientState(
		coordinator.statePath,
		coordinator.deviceID,
		coordinator.peerPublicKey,
	)
	if err != nil {
		return err
	}
	state.Revoked = true
	saveErr := saveClientState(coordinator.statePath, state)
	coordinator.installRevoked(state)
	return saveErr
}

// Close waits for active pins and clears in-memory secret material. It does
// not revoke the durable rotation state.
func (coordinator *Coordinator) Close(ctx context.Context) error {
	if coordinator == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	coordinator.mu.Lock()
	closed := coordinator.closed
	coordinator.mu.Unlock()
	if closed {
		return nil
	}
	if err := coordinator.beginMutation(ctx); err != nil {
		if errors.Is(err, ErrCoordinatorClosed) {
			return nil
		}
		return err
	}
	coordinator.mu.Lock()
	coordinator.closed = true
	clear(coordinator.currentPSK)
	coordinator.currentPSK = nil
	coordinator.notifyLocked()
	coordinator.mu.Unlock()
	coordinator.endMutation()
	return nil
}

func (pin *PinnedPSK) Close(_ context.Context) error {
	if pin == nil || pin.coordinator == nil {
		return nil
	}
	pin.once.Do(func() {
		pin.coordinator.releasePin()
	})
	return nil
}

func (coordinator *Coordinator) beginMutation(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	coordinator.mu.Lock()
	if coordinator.closed || coordinator.changed == nil {
		coordinator.mu.Unlock()
		return ErrCoordinatorClosed
	}
	coordinator.waitingMutations++
	coordinator.notifyLocked()
	for coordinator.pins != 0 || coordinator.mutating {
		changed := coordinator.changed
		coordinator.mu.Unlock()
		select {
		case <-ctx.Done():
			coordinator.mu.Lock()
			coordinator.waitingMutations--
			coordinator.notifyLocked()
			coordinator.mu.Unlock()
			return context.Cause(ctx)
		case <-changed:
		}
		coordinator.mu.Lock()
		if coordinator.closed {
			coordinator.waitingMutations--
			coordinator.notifyLocked()
			coordinator.mu.Unlock()
			return ErrCoordinatorClosed
		}
	}
	coordinator.waitingMutations--
	coordinator.mutating = true
	coordinator.notifyLocked()
	coordinator.mu.Unlock()
	return nil
}

func (coordinator *Coordinator) endMutation() {
	coordinator.mu.Lock()
	coordinator.mutating = false
	coordinator.notifyLocked()
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) releasePin() {
	coordinator.mu.Lock()
	if coordinator.pins > 0 {
		coordinator.pins--
		coordinator.notifyLocked()
	}
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) notifyLocked() {
	close(coordinator.changed)
	coordinator.changed = make(chan struct{})
}

func (coordinator *Coordinator) restoreCurrentLocked(
	ctx context.Context,
	controllerID string,
) error {
	if coordinator.loaded {
		return nil
	}
	state, err := loadClientState(
		coordinator.statePath,
		coordinator.deviceID,
		coordinator.peerPublicKey,
	)
	if err != nil {
		return err
	}
	if state.Revoked {
		coordinator.state = cloneClientState(state)
		coordinator.loaded = true
		return ErrRevoked
	}
	if state.Generation == 0 || state.Pending != nil {
		coordinator.state = cloneClientState(state)
		coordinator.loaded = true
		return ErrSnapshotUnavailable
	}
	if state.ControllerID != "" &&
		state.ControllerID != controllerID {
		return errors.New(
			"persisted rotation state belongs to another controller",
		)
	}
	source, ok := coordinator.applier.(awg.CurrentPSKSource)
	if !ok || isNilInterface(source) {
		return fmt.Errorf(
			"%w: applier %s cannot read its applied PSK",
			ErrSnapshotUnavailable,
			coordinator.applier.Description(),
		)
	}
	psk, err := source.ReadCurrentPSK(ctx, coordinator.peerPublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSnapshotUnavailable, err)
	}
	if len(psk) != 32 || allZeroPSK(psk) {
		clear(psk)
		return ErrSnapshotUnavailable
	}
	expectedKeyID := protocol.KeyID(
		controllerID,
		coordinator.suite,
		coordinator.deviceID,
		coordinator.peerPublicKey,
		state.Generation,
		psk,
	)
	if state.KeyID != expectedKeyID {
		clear(psk)
		return errors.New(
			"persisted rotation state does not match the applied PSK",
		)
	}
	state.ControllerID = controllerID
	coordinator.state = cloneClientState(state)
	coordinator.loaded = true
	coordinator.currentPSK = psk
	return nil
}

func (coordinator *Coordinator) validateCurrentLocked(
	request PinRequest,
	now time.Time,
) error {
	state := coordinator.state
	if state.Revoked {
		return ErrRevoked
	}
	if state.Pending != nil ||
		state.Version != clientStateVersion ||
		state.ControllerID != request.ControllerID ||
		state.Suite != request.Suite ||
		state.DeviceID != request.DeviceID ||
		state.PeerPublicKey != request.PeerPublicKey ||
		state.Generation == 0 ||
		state.KeyID == "" ||
		len(coordinator.currentPSK) != 32 ||
		allZeroPSK(coordinator.currentPSK) ||
		Expired(state.ExpiresAt, now) {
		return ErrSnapshotUnavailable
	}
	if request.ExpectedGeneration != 0 &&
		state.Generation != request.ExpectedGeneration {
		return ErrGenerationStale
	}
	expectedKeyID := protocol.KeyID(
		request.ControllerID,
		request.Suite,
		request.DeviceID,
		request.PeerPublicKey,
		state.Generation,
		coordinator.currentPSK,
	)
	if state.KeyID != expectedKeyID {
		return ErrSnapshotUnavailable
	}
	return nil
}

func (coordinator *Coordinator) installState(state ClientState) {
	coordinator.mu.Lock()
	coordinator.state = cloneClientState(state)
	coordinator.loaded = true
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) installApplied(
	state ClientState,
	psk []byte,
) {
	owned := bytes.Clone(psk)
	coordinator.mu.Lock()
	clear(coordinator.currentPSK)
	coordinator.currentPSK = owned
	coordinator.state = cloneClientState(state)
	coordinator.loaded = true
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) installRevoked(state ClientState) {
	coordinator.mu.Lock()
	clear(coordinator.currentPSK)
	coordinator.currentPSK = nil
	state.Revoked = true
	coordinator.state = cloneClientState(state)
	coordinator.loaded = true
	coordinator.mu.Unlock()
}

func (coordinator *Coordinator) failClosed(state ClientState) error {
	state.Revoked = true
	err := saveClientState(coordinator.statePath, state)
	coordinator.installRevoked(state)
	if err != nil {
		return fmt.Errorf("persist fail-closed rotation state: %w", err)
	}
	return nil
}

func validateRekeyResult(
	result bootstrap.Result,
	request protocol.RekeyRequest,
	suite string,
	now time.Time,
) error {
	if len(result.PSK) != 32 || allZeroPSK(result.PSK) ||
		result.Response.Suite != suite ||
		result.Response.ControllerID != request.ControllerID ||
		result.Response.DeviceID != request.DeviceID ||
		result.Response.PeerPublicKey != request.PeerPublicKey ||
		result.Response.Generation != request.CurrentGeneration+1 ||
		result.Response.KeyID != protocol.KeyID(
			request.ControllerID,
			request.Suite,
			request.DeviceID,
			request.PeerPublicKey,
			result.Response.Generation,
			result.PSK,
		) ||
		Expired(result.Response.ExpiresAt, now) {
		return errors.New(
			"bootstrap rekey result differs from coordinator binding",
		)
	}
	return nil
}

func cloneClientState(source ClientState) ClientState {
	source.Pending = cloneRekeyRequest(source.Pending)
	return source
}

func cloneRekeyRequest(
	source *protocol.RekeyRequest,
) *protocol.RekeyRequest {
	if source == nil {
		return nil
	}
	cloned := *source
	cloned.Capabilities = append([]string(nil), source.Capabilities...)
	return &cloned
}

func allZeroPSK(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	current := reflect.ValueOf(value)
	switch current.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return current.IsNil()
	default:
		return false
	}
}

var (
	_ RekeyClient = (*bootstrap.Client)(nil)
	_ interface {
		Close(context.Context) error
	} = (*PinnedPSK)(nil)
)
