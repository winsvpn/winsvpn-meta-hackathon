package preparation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

func TestRotationHybridPSKSnapshotSourceRestoresAndPinsApplyBoundary(
	t *testing.T,
) {
	now := productionNow()
	statePath := filepath.Join(t.TempDir(), "rotation.state")
	applier := awg.FileApplier{
		Path: filepath.Join(t.TempDir(), "current.psk"),
	}
	client := &preparationRotationClient{now: now}
	first := newPreparationCoordinator(
		t, statePath, applier, now,
	)
	if _, err := first.Rotate(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	coordinator := newPreparationCoordinator(
		t, statePath, applier, now,
	)
	source, err := NewRotationHybridPSKSnapshotSource(
		RotationHybridPSKSnapshotSourceConfig{
			Coordinator:   coordinator,
			Suite:         protocol.DefaultSuite,
			DeviceID:      "device-preparation",
			PeerPublicKey: testPreparationPeerKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewProductionHybridPSKPool(
		ProductionHybridPSKPoolConfig{
			Source:        source,
			Suite:         protocol.DefaultSuite,
			DeviceID:      "device-preparation",
			PeerPublicKey: testPreparationPeerKey,
			Now:           func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := HybridPSKPoolRequest{
		Profile:           "auto-production",
		ControllerID:      "controller-preparation",
		ManifestDigest:    fmt.Sprintf("%064x", 71),
		ManifestSequence:  9,
		ManifestExpiresAt: now.Add(3 * time.Hour),
	}
	lease, err := pool.AcquireCurrentHybridPSK(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Generation != 1 ||
		!lease.ExpiresAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("restored PSK lease changed: %#v", lease)
	}

	resultChannel := make(chan rotation.Result, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, rotateErr := coordinator.Rotate(
			context.Background(), client,
		)
		resultChannel <- result
		errorChannel <- rotateErr
	}()
	waitForPreparationRotationQueue(t, coordinator)
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	if result := <-resultChannel; result.Generation != 2 {
		t.Fatalf(
			"resumed rotation generation = %d; want 2",
			result.Generation,
		)
	}
	replacement, err := pool.AcquireCurrentHybridPSK(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Generation != 2 {
		t.Fatalf(
			"replacement generation = %d; want 2",
			replacement.Generation,
		)
	}
	if err := replacement.Resource.Close(
		context.Background(),
	); err != nil {
		t.Fatal(err)
	}
}

func newPreparationCoordinator(
	t testing.TB,
	statePath string,
	applier awg.Applier,
	now time.Time,
) *rotation.Coordinator {
	t.Helper()
	coordinator, err := rotation.NewCoordinator(
		rotation.CoordinatorConfig{
			Applier:       applier,
			StatePath:     statePath,
			DeviceID:      "device-preparation",
			PeerPublicKey: testPreparationPeerKey,
			Suite:         protocol.DefaultSuite,
			Now:           func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func waitForPreparationRotationQueue(
	t testing.TB,
	coordinator *rotation.Coordinator,
) {
	t.Helper()
	request := rotation.PinRequest{
		ControllerID:       "controller-preparation",
		Suite:              protocol.DefaultSuite,
		DeviceID:           "device-preparation",
		PeerPublicKey:      testPreparationPeerKey,
		ExpectedGeneration: 1,
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pinned, err := coordinator.Pin(context.Background(), request)
		if errors.Is(err, rotation.ErrRotationQueued) {
			return
		}
		if err != nil {
			t.Fatalf("wait for rotation queue: %v", err)
		}
		clear(pinned.PSK)
		if err := pinned.Resource.Close(
			context.Background(),
		); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("rotation did not queue behind preparation pin")
}

type preparationRotationClient struct {
	now time.Time
}

func (client *preparationRotationClient) NewRequest(
	deviceID string,
	peerPublicKey string,
	currentGeneration uint64,
) (protocol.RekeyRequest, error) {
	return protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             protocol.DefaultSuite,
		ControllerID:      "controller-preparation",
		DeviceID:          deviceID,
		PeerPublicKey:     peerPublicKey,
		RequestID:         fmt.Sprintf("%032x", currentGeneration+1),
		Nonce:             fmt.Sprintf("%032x", currentGeneration+31),
		CurrentGeneration: currentGeneration,
		Capabilities: protocol.RequiredCapabilities(
			protocol.DefaultSuite,
		),
	}, nil
}

func (client *preparationRotationClient) Rekey(
	_ context.Context,
	request protocol.RekeyRequest,
) (bootstrap.Result, error) {
	generation := request.CurrentGeneration + 1
	psk := bytes.Repeat([]byte{byte(generation + 64)}, 32)
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

var _ rotation.RekeyClient = (*preparationRotationClient)(nil)

const testPreparationPeerKey = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
