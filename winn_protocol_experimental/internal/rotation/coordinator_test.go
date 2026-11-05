package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/protocol"
)

const (
	coordinatorController = "controller-coordinator"
	coordinatorDevice     = "device-coordinator"
	coordinatorPeer       = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
)

func TestCoordinatorConcurrentPinsBlockAndResumeRotation(
	t *testing.T,
) {
	fixture := newCoordinatorFixture(t)
	const pinCount = 32
	pins := make([]PinnedSnapshot, pinCount)
	var group sync.WaitGroup
	group.Add(pinCount)
	for index := range pinCount {
		go func(current int) {
			defer group.Done()
			pinned, err := fixture.coordinator.Pin(
				context.Background(), fixture.pinRequest(1),
			)
			if err != nil {
				t.Errorf("pin %d: %v", current, err)
				return
			}
			pins[current] = pinned
		}(index)
	}
	group.Wait()
	for index, pinned := range pins {
		if pinned.State.Generation != 1 ||
			len(pinned.PSK) != 32 ||
			pinned.Resource == nil {
			t.Fatalf("pin %d changed: %#v", index, pinned)
		}
		for other := index + 1; other < len(pins); other++ {
			if &pinned.PSK[0] == &pins[other].PSK[0] {
				t.Fatal("concurrent pins shared caller-owned PSK bytes")
			}
		}
	}

	resultChannel := make(chan Result, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, err := fixture.coordinator.Rotate(
			context.Background(), fixture.client,
		)
		resultChannel <- result
		errorChannel <- err
	}()
	waitForQueuedMutation(t, fixture)
	if fixture.client.newRequestCount() != 0 {
		t.Fatal("rotation reached bootstrap while pins remained live")
	}
	for index := 0; index < len(pins)-1; index++ {
		if err := pins[index].Resource.Close(
			context.Background(),
		); err != nil {
			t.Fatal(err)
		}
		clear(pins[index].PSK)
	}
	select {
	case err := <-errorChannel:
		t.Fatalf("rotation completed before last pin release: %v", err)
	default:
	}
	if err := pins[len(pins)-1].Resource.Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
	clear(pins[len(pins)-1].PSK)
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	result := <-resultChannel
	if result.Generation != 2 {
		t.Fatalf("rotated generation = %d; want 2", result.Generation)
	}
	if !fixture.client.lastReturnedPSKIsZero() ||
		!fixture.applier.lastApplyInputIsZero() {
		t.Fatal("rotation retained a bootstrap or apply PSK buffer")
	}
	pinned, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(2),
	)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.State.Generation != 2 {
		t.Fatalf(
			"post-rotation generation = %d; want 2",
			pinned.State.Generation,
		)
	}
	clear(pinned.PSK)
	if err := pinned.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorCancelledQueuedRotationPreservesCurrentPinning(
	t *testing.T,
) {
	fixture := newCoordinatorFixture(t)
	pinned, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errorChannel := make(chan error, 1)
	go func() {
		_, rotateErr := fixture.coordinator.Rotate(
			ctx, fixture.client,
		)
		errorChannel <- rotateErr
	}()
	waitForQueuedMutation(t, fixture)
	cancel()
	if err := <-errorChannel; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled rotation error = %v", err)
	}
	if fixture.client.newRequestCount() != 0 {
		t.Fatal("cancelled queued rotation reached bootstrap")
	}
	if err := pinned.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	clear(pinned.PSK)
	replacement, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(replacement.PSK)
	if err := replacement.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorRejectsStaleGenerationAndClearsRejectedRestore(
	t *testing.T,
) {
	t.Run("expected generation", func(t *testing.T) {
		fixture := newCoordinatorFixture(t)
		if _, err := fixture.coordinator.Pin(
			context.Background(), fixture.pinRequest(2),
		); !errors.Is(err, ErrGenerationStale) {
			t.Fatalf("stale generation error = %v", err)
		}
	})

	t.Run("applied key differs from state", func(t *testing.T) {
		fixture := newCoordinatorFixture(t)
		fixture.applier.setCurrent(
			bytes.Repeat([]byte{0x7f}, 32),
		)
		if _, err := fixture.coordinator.Pin(
			context.Background(), fixture.pinRequest(1),
		); err == nil {
			t.Fatal("mismatched applied PSK was pinned")
		}
		if !fixture.applier.lastReadIsZero() {
			t.Fatal("rejected applied PSK copy was not cleared")
		}
	})
}

func TestCoordinatorApplyFailureRevokesUntilSafeRetry(
	t *testing.T,
) {
	fixture := newCoordinatorFixture(t)
	fixture.applier.setApplyFailure(true)
	if _, err := fixture.coordinator.Rotate(
		context.Background(), fixture.client,
	); err == nil {
		t.Fatal("failing apply unexpectedly rotated")
	}
	if _, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	); !errors.Is(err, ErrRevoked) {
		t.Fatalf("pin after failed apply error = %v", err)
	}
	persisted, err := loadClientState(
		fixture.statePath, coordinatorDevice, coordinatorPeer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Revoked || persisted.Pending == nil ||
		persisted.Generation != 1 {
		t.Fatalf("failed apply state = %#v", persisted)
	}

	fixture.applier.setApplyFailure(false)
	result, err := fixture.coordinator.Rotate(
		context.Background(), fixture.client,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Generation != 2 {
		t.Fatalf("retry generation = %d; want 2", result.Generation)
	}
	recovered, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(2),
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(recovered.PSK)
	if err := recovered.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorAllowsSuiteMigrationWithoutPendingRequest(
	t *testing.T,
) {
	fixture := newCoordinatorFixture(t)
	fixture.client.suite = protocol.SuiteP256MLKEM768
	coordinator, err := NewCoordinator(CoordinatorConfig{
		Applier:       fixture.applier,
		StatePath:     fixture.statePath,
		DeviceID:      coordinatorDevice,
		PeerPublicKey: coordinatorPeer,
		Suite:         protocol.SuiteP256MLKEM768,
		Now:           func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Rotate(
		context.Background(), fixture.client,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Suite != protocol.SuiteP256MLKEM768 ||
		result.Generation != 2 {
		t.Fatalf("suite migration result = %#v", result)
	}
	persisted, err := loadClientState(
		fixture.statePath, coordinatorDevice, coordinatorPeer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Suite != protocol.SuiteP256MLKEM768 ||
		persisted.Generation != 2 ||
		persisted.Pending != nil {
		t.Fatalf("suite migration state = %#v", persisted)
	}
	pinned, err := coordinator.Pin(
		context.Background(),
		PinRequest{
			ControllerID:       coordinatorController,
			Suite:              protocol.SuiteP256MLKEM768,
			DeviceID:           coordinatorDevice,
			PeerPublicKey:      coordinatorPeer,
			ExpectedGeneration: 2,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(pinned.PSK)
	if err := pinned.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorRevocationWaitsForPinsAndPersists(
	t *testing.T,
) {
	fixture := newCoordinatorFixture(t)
	pinned, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	errorChannel := make(chan error, 1)
	go func() {
		errorChannel <- fixture.coordinator.Revoke(
			context.Background(),
		)
	}()
	waitForQueuedMutation(t, fixture)
	select {
	case err := <-errorChannel:
		t.Fatalf("revocation completed with live pin: %v", err)
	default:
	}
	if err := pinned.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	clear(pinned.PSK)
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	); !errors.Is(err, ErrRevoked) {
		t.Fatalf("pin after revocation error = %v", err)
	}
	persisted, err := loadClientState(
		fixture.statePath, coordinatorDevice, coordinatorPeer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !persisted.Revoked {
		t.Fatal("revocation was not durable")
	}
}

func TestCoordinatorRejectsNewRequestThatRewindsGeneration(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	original, err := loadClientState(
		fixture.statePath, coordinatorDevice, coordinatorPeer,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.client.rewindGeneration = true
	result, err := fixture.coordinator.Rotate(
		context.Background(), fixture.client,
	)
	if err == nil {
		t.Fatalf("rotation accepted a rewound NewRequest: %#v", result)
	}
	persisted, err := loadClientState(
		fixture.statePath, coordinatorDevice, coordinatorPeer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Generation != original.Generation ||
		persisted.KeyID != original.KeyID ||
		persisted.Pending != nil ||
		persisted.Revoked {
		t.Fatalf("rewound request mutated state = %#v", persisted)
	}
}

func TestCoordinatorCloseZerosOwnedCurrentPSK(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	pinned, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(pinned.PSK)
	if err := pinned.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.coordinator.mu.Lock()
	owned := fixture.coordinator.currentPSK
	fixture.coordinator.mu.Unlock()
	if err := fixture.coordinator.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !allZeroPSK(owned) {
		t.Fatal("coordinator-owned current PSK was not cleared")
	}
	if _, err := fixture.coordinator.Pin(
		context.Background(), fixture.pinRequest(1),
	); !errors.Is(err, ErrCoordinatorClosed) {
		t.Fatalf("pin after close error = %v", err)
	}
}

type coordinatorFixture struct {
	now         time.Time
	statePath   string
	applier     *coordinatorTestApplier
	client      *coordinatorTestClient
	coordinator *Coordinator
}

func newCoordinatorFixture(t testing.TB) *coordinatorFixture {
	t.Helper()
	now := time.Date(
		2026, time.July, 24, 12, 0, 0, 0, time.UTC,
	)
	statePath := filepath.Join(t.TempDir(), "client.state")
	psk := bytes.Repeat([]byte{0x41}, 32)
	state := ClientState{
		Version:       clientStateVersion,
		ControllerID:  coordinatorController,
		Suite:         protocol.DefaultSuite,
		DeviceID:      coordinatorDevice,
		PeerPublicKey: coordinatorPeer,
		Generation:    1,
		KeyID: protocol.KeyID(
			coordinatorController,
			protocol.DefaultSuite,
			coordinatorDevice,
			coordinatorPeer,
			1,
			psk,
		),
		ExpiresAt: now.Add(2 * time.Hour).Format(
			time.RFC3339Nano,
		),
	}
	if err := saveClientState(statePath, state); err != nil {
		t.Fatal(err)
	}
	applier := &coordinatorTestApplier{
		current: bytes.Clone(psk),
	}
	client := &coordinatorTestClient{
		now:   now,
		suite: protocol.DefaultSuite,
	}
	coordinator, err := NewCoordinator(CoordinatorConfig{
		Applier:       applier,
		StatePath:     statePath,
		DeviceID:      coordinatorDevice,
		PeerPublicKey: coordinatorPeer,
		Suite:         protocol.DefaultSuite,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	clear(psk)
	return &coordinatorFixture{
		now:         now,
		statePath:   statePath,
		applier:     applier,
		client:      client,
		coordinator: coordinator,
	}
}

func (fixture *coordinatorFixture) pinRequest(
	generation uint64,
) PinRequest {
	return PinRequest{
		ControllerID:       coordinatorController,
		Suite:              protocol.DefaultSuite,
		DeviceID:           coordinatorDevice,
		PeerPublicKey:      coordinatorPeer,
		ExpectedGeneration: generation,
	}
}

func waitForQueuedMutation(
	t testing.TB,
	fixture *coordinatorFixture,
) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pinned, err := fixture.coordinator.Pin(
			context.Background(), fixture.pinRequest(1),
		)
		if errors.Is(err, ErrRotationQueued) {
			return
		}
		if err != nil {
			t.Fatalf("wait for queued mutation: %v", err)
		}
		clear(pinned.PSK)
		if err := pinned.Resource.Close(
			context.Background(),
		); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("mutation did not enter the queue")
}

type coordinatorTestApplier struct {
	mu             sync.Mutex
	current        []byte
	failApply      bool
	lastApplyInput []byte
	lastRead       []byte
}

func (applier *coordinatorTestApplier) Apply(
	_ context.Context,
	_ string,
	psk []byte,
) error {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	applier.lastApplyInput = psk
	if applier.failApply {
		return errors.New("injected apply failure")
	}
	clear(applier.current)
	applier.current = bytes.Clone(psk)
	return nil
}

func (applier *coordinatorTestApplier) Description() string {
	return "coordinator-test-applier"
}

func (applier *coordinatorTestApplier) ReadCurrentPSK(
	_ context.Context,
	_ string,
) ([]byte, error) {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	if len(applier.current) == 0 {
		return nil, errors.New("no applied PSK")
	}
	result := bytes.Clone(applier.current)
	applier.lastRead = result
	return result, nil
}

func (applier *coordinatorTestApplier) setApplyFailure(fail bool) {
	applier.mu.Lock()
	applier.failApply = fail
	applier.mu.Unlock()
}

func (applier *coordinatorTestApplier) setCurrent(psk []byte) {
	applier.mu.Lock()
	clear(applier.current)
	applier.current = bytes.Clone(psk)
	applier.mu.Unlock()
}

func (applier *coordinatorTestApplier) lastReadIsZero() bool {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	return allZeroPSK(applier.lastRead)
}

func (applier *coordinatorTestApplier) lastApplyInputIsZero() bool {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	return allZeroPSK(applier.lastApplyInput)
}

type coordinatorTestClient struct {
	mu               sync.Mutex
	now              time.Time
	suite            string
	newRequests      int
	lastReturnedPSK  []byte
	rewindGeneration bool
}

func (client *coordinatorTestClient) NewRequest(
	deviceID string,
	peerPublicKey string,
	currentGeneration uint64,
) (protocol.RekeyRequest, error) {
	client.mu.Lock()
	client.newRequests++
	rewind := client.rewindGeneration
	client.mu.Unlock()
	generation := currentGeneration
	if rewind {
		generation = 0
	}
	return protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             client.suite,
		ControllerID:      coordinatorController,
		DeviceID:          deviceID,
		PeerPublicKey:     peerPublicKey,
		RequestID:         fmt.Sprintf("%032x", generation+1),
		Nonce:             fmt.Sprintf("%032x", generation+17),
		CurrentGeneration: generation,
		Capabilities: protocol.RequiredCapabilities(
			client.suite,
		),
	}, nil
}

func (client *coordinatorTestClient) Rekey(
	_ context.Context,
	request protocol.RekeyRequest,
) (bootstrap.Result, error) {
	psk := bytes.Repeat(
		[]byte{byte(request.CurrentGeneration + 2)}, 32,
	)
	client.mu.Lock()
	client.lastReturnedPSK = psk
	client.mu.Unlock()
	generation := request.CurrentGeneration + 1
	return bootstrap.Result{
		Response: protocol.RekeyResponse{
			Version:       protocol.Version,
			Suite:         request.Suite,
			ControllerID:  request.ControllerID,
			DeviceID:      request.DeviceID,
			PeerPublicKey: request.PeerPublicKey,
			RequestID:     request.RequestID,
			Nonce:         request.Nonce,
			Generation:    generation,
			KeyID: protocol.KeyID(
				request.ControllerID,
				request.Suite,
				request.DeviceID,
				request.PeerPublicKey,
				generation,
				psk,
			),
			IssuedAt: client.now.Format(time.RFC3339Nano),
			ExpiresAt: client.now.Add(2 * time.Hour).Format(
				time.RFC3339Nano,
			),
		},
		PSK: psk,
	}, nil
}

func (client *coordinatorTestClient) newRequestCount() int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.newRequests
}

func (client *coordinatorTestClient) lastReturnedPSKIsZero() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return allZeroPSK(client.lastReturnedPSK)
}

var (
	_ RekeyClient = (*coordinatorTestClient)(nil)
	_ interface {
		Apply(context.Context, string, []byte) error
		Description() string
		ReadCurrentPSK(context.Context, string) ([]byte, error)
	} = (*coordinatorTestApplier)(nil)
)
