package rotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/awg"
	"winsvpn.local/winnprotocol/internal/bootstrap"
	"winsvpn.local/winnprotocol/internal/protocol"
	"winsvpn.local/winnprotocol/internal/securefile"
)

const clientStateVersion = 1

type ClientState struct {
	Version       int                    `json:"version"`
	ControllerID  string                 `json:"controller_id,omitempty"`
	Suite         string                 `json:"suite,omitempty"`
	DeviceID      string                 `json:"device_id"`
	PeerPublicKey string                 `json:"peer_public_key"`
	Generation    uint64                 `json:"generation"`
	KeyID         string                 `json:"key_id,omitempty"`
	ExpiresAt     string                 `json:"expires_at,omitempty"`
	Pending       *protocol.RekeyRequest `json:"pending,omitempty"`
	Revoked       bool                   `json:"revoked,omitempty"`
}

type Result struct {
	Suite       string `json:"suite"`
	Generation  uint64 `json:"generation"`
	KeyID       string `json:"key_id"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	TLSVersion  uint16 `json:"tls_version"`
	Curve       string `json:"key_exchange"`
	CipherSuite uint16 `json:"cipher_suite"`
	Adapter     string `json:"adapter"`
}

func Run(
	ctx context.Context,
	client *bootstrap.Client,
	applier awg.Applier,
	statePath, deviceID, peerPublicKey, suite string,
) (Result, error) {
	coordinator, err := NewCoordinator(CoordinatorConfig{
		Applier:       applier,
		StatePath:     statePath,
		DeviceID:      deviceID,
		PeerPublicKey: peerPublicKey,
		Suite:         suite,
	})
	if err != nil {
		return Result{}, err
	}
	result, rotateErr := coordinator.Rotate(ctx, client)
	closeErr := coordinator.Close(context.Background())
	return result, errors.Join(rotateErr, closeErr)
}

func loadClientState(path, deviceID, peerPublicKey string) (ClientState, error) {
	data, err := securefile.ReadPrivateLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return ClientState{
			Version:       clientStateVersion,
			DeviceID:      deviceID,
			PeerPublicKey: peerPublicKey,
		}, nil
	}
	if err != nil {
		return ClientState{}, fmt.Errorf("read client state: %w", err)
	}
	var state ClientState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return ClientState{}, fmt.Errorf("decode client state: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ClientState{}, fmt.Errorf("decode client state: %w", err)
	}
	if state.Version != clientStateVersion {
		return ClientState{}, errors.New("unsupported client state version")
	}
	if state.DeviceID != deviceID || state.PeerPublicKey != peerPublicKey {
		return ClientState{}, errors.New("client state belongs to a different device or peer")
	}
	if state.Pending != nil {
		if state.Pending.DeviceID != deviceID ||
			state.Pending.PeerPublicKey != peerPublicKey ||
			state.Pending.CurrentGeneration != state.Generation ||
			(state.ControllerID != "" &&
				state.Pending.ControllerID != state.ControllerID) {
			return ClientState{}, errors.New("pending request binding is invalid")
		}
	}
	return state, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}

func saveClientState(path string, state ClientState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return securefile.AtomicWrite(path, data, 0o600)
}

func TLSVersionName(version uint16) string {
	if version == tls.VersionTLS13 {
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}

func Expired(expiresAt string, now time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	return err != nil || !parsed.After(now)
}
