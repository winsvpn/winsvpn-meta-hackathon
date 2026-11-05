package linuxauto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/rotation"
)

type RotationKeyProviderConfig struct {
	Coordinator   *rotation.Coordinator
	ControllerID  string
	Suite         string
	DeviceID      string
	PeerPublicKey string
	PrivateKey    []byte
}

// RotationKeyProvider joins DirectAWG's ephemeral key-material request to the
// same real rotation/apply linearization boundary pinned by production
// preparation. The long-lived private key is copied on construction and
// destroyed by Close; every returned buffer is uniquely owned by the caller.
type RotationKeyProvider struct {
	mu sync.RWMutex

	coordinator   *rotation.Coordinator
	controllerID  string
	suite         string
	deviceID      string
	peerPublicKey string
	privateKey    [32]byte
	closed        bool
}

var _ directawg.LinuxKeyMaterialProvider = (*RotationKeyProvider)(nil)

func NewRotationKeyProvider(
	config RotationKeyProviderConfig,
) (*RotationKeyProvider, error) {
	if config.Coordinator == nil ||
		!protocol.ValidDeviceID(config.ControllerID) ||
		!protocol.ValidSuite(config.Suite) ||
		!protocol.ValidDeviceID(config.DeviceID) {
		return nil, errors.New(
			"rotation-backed Linux AWG key configuration is invalid",
		)
	}
	if err := protocol.ValidatePeerPublicKey(
		config.PeerPublicKey,
	); err != nil {
		return nil, fmt.Errorf(
			"rotation-backed Linux AWG peer key: %w", err,
		)
	}
	if len(config.PrivateKey) != 32 ||
		allZeroRotationKey(config.PrivateKey) {
		return nil, errors.New(
			"rotation-backed Linux AWG private key must be 32 nonzero bytes",
		)
	}
	binding, ok := config.Coordinator.Binding()
	if !ok ||
		binding.Suite != config.Suite ||
		binding.DeviceID != config.DeviceID ||
		binding.PeerPublicKey != config.PeerPublicKey {
		return nil, errors.New(
			"rotation coordinator binding differs from Linux AWG key provider",
		)
	}
	provider := &RotationKeyProvider{
		coordinator:   config.Coordinator,
		controllerID:  config.ControllerID,
		suite:         config.Suite,
		deviceID:      config.DeviceID,
		peerPublicKey: config.PeerPublicKey,
	}
	copy(provider.privateKey[:], config.PrivateKey)
	return provider, nil
}

func (provider *RotationKeyProvider) KeyMaterial(
	ctx context.Context,
	binding connectivity.Binding,
) (directawg.LinuxKeyMaterial, error) {
	if provider == nil {
		return directawg.LinuxKeyMaterial{},
			errors.New("rotation-backed Linux AWG key provider is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cause := context.Cause(ctx); cause != nil {
		return directawg.LinuxKeyMaterial{}, cause
	}
	if binding.PSKGeneration == 0 {
		return directawg.LinuxKeyMaterial{},
			errors.New("linux AWG binding has no PSK generation")
	}

	provider.mu.RLock()
	defer provider.mu.RUnlock()
	if provider.closed || provider.coordinator == nil {
		return directawg.LinuxKeyMaterial{},
			errors.New("rotation-backed Linux AWG key provider is closed")
	}
	privateKey := bytes.Clone(provider.privateKey[:])
	snapshot, err := provider.coordinator.Pin(
		ctx,
		rotation.PinRequest{
			ControllerID:       provider.controllerID,
			Suite:              provider.suite,
			DeviceID:           provider.deviceID,
			PeerPublicKey:      provider.peerPublicKey,
			ExpectedGeneration: binding.PSKGeneration,
		},
	)
	if err != nil {
		clear(privateKey)
		return directawg.LinuxKeyMaterial{},
			fmt.Errorf("pin current Linux AWG PSK: %w", err)
	}
	psk := snapshot.PSK
	snapshot.PSK = nil
	closeErr := snapshot.Resource.Close(context.Background())
	if cause := context.Cause(ctx); cause != nil || closeErr != nil {
		clear(privateKey)
		clear(psk)
		var releaseErr error
		if closeErr != nil {
			releaseErr = fmt.Errorf(
				"release Linux AWG PSK snapshot: %w", closeErr,
			)
		}
		return directawg.LinuxKeyMaterial{}, errors.Join(
			cause,
			releaseErr,
		)
	}
	if len(psk) != 32 || allZeroRotationKey(psk) {
		clear(privateKey)
		clear(psk)
		return directawg.LinuxKeyMaterial{},
			errors.New("rotation snapshot returned invalid Linux AWG PSK")
	}
	return directawg.LinuxKeyMaterial{
		Generation: binding.PSKGeneration,
		PrivateKey: privateKey,
		PSK:        psk,
	}, nil
}

// Close permanently destroys the provider-owned private-key copy.
func (provider *RotationKeyProvider) Close() {
	if provider == nil {
		return
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.closed {
		return
	}
	provider.closed = true
	clear(provider.privateKey[:])
	provider.coordinator = nil
}

func allZeroRotationKey(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}
