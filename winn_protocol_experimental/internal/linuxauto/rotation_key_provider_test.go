package linuxauto

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
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

func TestRotationKeyProviderUsesExactAppliedGeneration(t *testing.T) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	coordinator := newRuntimeRotationCoordinator(t, now)
	client := &runtimeRotationClient{now: now}
	if _, err := coordinator.Rotate(
		context.Background(), client,
	); err != nil {
		t.Fatal(err)
	}
	privateKey := bytes.Repeat([]byte{0x51}, 32)
	provider, err := NewRotationKeyProvider(
		RotationKeyProviderConfig{
			Coordinator:   coordinator,
			ControllerID:  "controller-auto",
			Suite:         protocol.DefaultSuite,
			DeviceID:      "device-auto",
			PeerPublicKey: runtimeRotationPeerKey,
			PrivateKey:    privateKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	clear(privateKey)

	material, err := provider.KeyMaterial(
		context.Background(),
		connectivity.Binding{PSKGeneration: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.Generation != 1 ||
		!bytes.Equal(material.PrivateKey, bytes.Repeat([]byte{0x51}, 32)) ||
		!bytes.Equal(material.PSK, bytes.Repeat([]byte{0x71}, 32)) {
		t.Fatal("rotation-backed key material changed")
	}
	clear(material.PrivateKey)
	clear(material.PSK)

	if _, err := provider.KeyMaterial(
		context.Background(),
		connectivity.Binding{PSKGeneration: 2},
	); !errors.Is(err, rotation.ErrGenerationStale) {
		t.Fatalf("wrong generation returned %v", err)
	}
	cancelled, cancel := context.WithCancelCause(
		context.Background(),
	)
	cause := errors.New("cancel key lookup")
	cancel(cause)
	if _, err := provider.KeyMaterial(
		cancelled,
		connectivity.Binding{PSKGeneration: 1},
	); !errors.Is(err, cause) {
		t.Fatalf("cancelled lookup returned %v", err)
	}

	provider.Close()
	provider.Close()
	if _, err := provider.KeyMaterial(
		context.Background(),
		connectivity.Binding{PSKGeneration: 1},
	); err == nil {
		t.Fatal("closed provider returned key material")
	}
	if err := coordinator.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRotationKeyProviderRejectsMismatchedConfiguration(
	t *testing.T,
) {
	now := time.Date(2026, 7, 24, 20, 0, 0, 0, time.UTC)
	coordinator := newRuntimeRotationCoordinator(t, now)
	base := RotationKeyProviderConfig{
		Coordinator:   coordinator,
		ControllerID:  "controller-auto",
		Suite:         protocol.DefaultSuite,
		DeviceID:      "device-auto",
		PeerPublicKey: runtimeRotationPeerKey,
		PrivateKey:    bytes.Repeat([]byte{0x51}, 32),
	}
	cases := []struct {
		name   string
		mutate func(*RotationKeyProviderConfig)
	}{
		{"nil-coordinator", func(config *RotationKeyProviderConfig) {
			config.Coordinator = nil
		}},
		{"wrong-device", func(config *RotationKeyProviderConfig) {
			config.DeviceID = "device-other"
		}},
		{"zero-private-key", func(config *RotationKeyProviderConfig) {
			config.PrivateKey = make([]byte, 32)
		}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			config := base
			config.PrivateKey = bytes.Clone(base.PrivateKey)
			current.mutate(&config)
			if _, err := NewRotationKeyProvider(config); err == nil {
				t.Fatal("invalid key-provider configuration was accepted")
			}
			clear(config.PrivateKey)
		})
	}
	clear(base.PrivateKey)
	if err := coordinator.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func newRuntimeRotationCoordinator(
	t testing.TB,
	now time.Time,
) *rotation.Coordinator {
	t.Helper()
	root := t.TempDir()
	coordinator, err := rotation.NewCoordinator(
		rotation.CoordinatorConfig{
			Applier: awg.FileApplier{
				Path: filepath.Join(root, "current.psk"),
			},
			StatePath:     filepath.Join(root, "rotation.state"),
			DeviceID:      "device-auto",
			PeerPublicKey: runtimeRotationPeerKey,
			Suite:         protocol.DefaultSuite,
			Now:           func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

type runtimeRotationClient struct {
	now time.Time
}

func (client *runtimeRotationClient) NewRequest(
	deviceID string,
	peerPublicKey string,
	currentGeneration uint64,
) (protocol.RekeyRequest, error) {
	return protocol.RekeyRequest{
		Version:           protocol.Version,
		Suite:             protocol.DefaultSuite,
		ControllerID:      "controller-auto",
		DeviceID:          deviceID,
		PeerPublicKey:     peerPublicKey,
		RequestID:         fmt.Sprintf("%032x", currentGeneration+1),
		Nonce:             fmt.Sprintf("%032x", currentGeneration+17),
		CurrentGeneration: currentGeneration,
		Capabilities: protocol.RequiredCapabilities(
			protocol.DefaultSuite,
		),
	}, nil
}

func (client *runtimeRotationClient) Rekey(
	_ context.Context,
	request protocol.RekeyRequest,
) (bootstrap.Result, error) {
	generation := request.CurrentGeneration + 1
	psk := bytes.Repeat([]byte{byte(0x70 + generation)}, 32)
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

var _ rotation.RekeyClient = (*runtimeRotationClient)(nil)

const runtimeRotationPeerKey = "nNOe1VBs+qdVjQGHgems9Xd3SO6gsrVl7+DM8y/EZAQ="
