package preparation

import (
	"context"
	"errors"

	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

type RotationHybridPSKSnapshotSourceConfig struct {
	Coordinator   *rotation.Coordinator
	Suite         string
	DeviceID      string
	PeerPublicKey string
}

// RotationHybridPSKSnapshotSource adapts the real rotation/apply
// linearization boundary to ProductionHybridPSKPool. The returned rotation
// pin remains live through the preparation Resource.
type RotationHybridPSKSnapshotSource struct {
	coordinator   *rotation.Coordinator
	suite         string
	deviceID      string
	peerPublicKey string
}

var _ HybridPSKSnapshotSource = (*RotationHybridPSKSnapshotSource)(nil)

func NewRotationHybridPSKSnapshotSource(
	config RotationHybridPSKSnapshotSourceConfig,
) (*RotationHybridPSKSnapshotSource, error) {
	if config.Coordinator == nil ||
		!protocol.ValidSuite(config.Suite) ||
		!protocol.ValidDeviceID(config.DeviceID) {
		return nil, errors.New(
			"rotation hybrid PSK source configuration is invalid",
		)
	}
	if err := protocol.ValidatePeerPublicKey(
		config.PeerPublicKey,
	); err != nil {
		return nil, err
	}
	binding, ok := config.Coordinator.Binding()
	if !ok ||
		binding.Suite != config.Suite ||
		binding.DeviceID != config.DeviceID ||
		binding.PeerPublicKey != config.PeerPublicKey {
		return nil, errors.New(
			"rotation coordinator binding differs from PSK source",
		)
	}
	return &RotationHybridPSKSnapshotSource{
		coordinator:   config.Coordinator,
		suite:         config.Suite,
		deviceID:      config.DeviceID,
		peerPublicKey: config.PeerPublicKey,
	}, nil
}

func (source *RotationHybridPSKSnapshotSource) PinCurrentHybridPSK(
	ctx context.Context,
	request HybridPSKPoolRequest,
) (PinnedHybridPSKSnapshot, error) {
	if source == nil || source.coordinator == nil {
		return PinnedHybridPSKSnapshot{},
			errors.New("rotation hybrid PSK source is unavailable")
	}
	pinned, err := source.coordinator.Pin(
		ctx,
		rotation.PinRequest{
			ControllerID:  request.ControllerID,
			Suite:         source.suite,
			DeviceID:      source.deviceID,
			PeerPublicKey: source.peerPublicKey,
		},
	)
	if err != nil {
		return PinnedHybridPSKSnapshot{}, err
	}
	return PinnedHybridPSKSnapshot{
		Request:    request,
		ObservedAt: pinned.ObservedAt,
		State:      pinned.State,
		PSK:        pinned.PSK,
		Resource:   pinned.Resource,
	}, nil
}
