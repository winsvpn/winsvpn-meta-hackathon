package gatewaymanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

const TrustStateFormatV2 = "winn-gateway-manifest-trust-state/v2"

// TrustStateV2 is the caller-retained rollback pin. Callers must protect and
// atomically persist the returned next state only after the corresponding
// manifest has been installed successfully.
type TrustStateV2 struct {
	Format          string                  `json:"format"`
	HighestSequence uint64                  `json:"highest_sequence"`
	ManifestDigest  string                  `json:"manifest_digest"`
	Checkpoint      transparency.Checkpoint `json:"checkpoint"`
}

func EncodeTrustStateV2(state TrustStateV2) ([]byte, error) {
	if err := validateTrustStateV2(state); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func LoadTrustStateV2(path string) (TrustStateV2, error) {
	data, err := securefile.ReadPublicIntegrity(path, 64<<10)
	if err != nil {
		return TrustStateV2{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state TrustStateV2
	if err := decoder.Decode(&state); err != nil {
		return TrustStateV2{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return TrustStateV2{}, errors.New(
			"v2 trust state contains extra JSON",
		)
	}
	if err := validateTrustStateV2(state); err != nil {
		return TrustStateV2{}, err
	}
	return state, nil
}

// BootstrapTrustStateV2 verifies a first manifest against an out-of-band
// transparency checkpoint. It is deliberately separate from ordinary loading
// so deletion of local trust state cannot silently trigger trust-on-first-use.
func BootstrapTrustStateV2(
	manifestPath string,
	logPath string,
	expected transparency.Checkpoint,
	pins *pqauth.VerifierSet,
	now time.Time,
) (ManifestV2, string, TrustStateV2, error) {
	if manifestPath == "" || logPath == "" || pins == nil {
		return ManifestV2{}, "", TrustStateV2{},
			errors.New(
				"manifest, transparency log, and pins are required",
			)
	}
	manifest, err := LoadV2(manifestPath)
	if err != nil {
		return ManifestV2{}, "", TrustStateV2{}, err
	}
	if err := VerifyV2(
		manifest, pins, now, DefaultClockSkew,
	); err != nil {
		return ManifestV2{}, "", TrustStateV2{}, err
	}
	digest, err := DigestV2(manifest)
	if err != nil {
		return ManifestV2{}, "", TrustStateV2{}, err
	}
	checkpoint, err := transparency.VerifyInclusion(
		logPath, digest, pins, &expected,
	)
	if err != nil {
		return ManifestV2{}, "", TrustStateV2{}, err
	}
	state := TrustStateV2{
		Format:          TrustStateFormatV2,
		HighestSequence: manifest.Sequence,
		ManifestDigest:  digest,
		Checkpoint:      checkpoint,
	}
	return manifest, digest, state, nil
}

// LoadVerifiedNodeV2 performs signature, time, typed-node, transparency-prefix,
// manifest-sequence, and predecessor-digest verification. The returned next
// state is not persisted automatically.
func LoadVerifiedNodeV2(
	manifestPath string,
	nodeID string,
	logPath string,
	statePath string,
	pins *pqauth.VerifierSet,
	now time.Time,
) (
	ManifestV2,
	NodeV2,
	string,
	TrustStateV2,
	error,
) {
	if manifestPath == "" || nodeID == "" || logPath == "" ||
		statePath == "" || pins == nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
			errors.New(
				"manifest, node, transparency log, trust state, and pins are required",
			)
	}
	state, err := LoadTrustStateV2(statePath)
	if err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{}, err
	}
	manifest, err := LoadV2(manifestPath)
	if err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{}, err
	}
	if err := VerifyV2(
		manifest, pins, now, DefaultClockSkew,
	); err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{}, err
	}
	node, err := manifest.Node(nodeID)
	if err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{}, err
	}
	digest, err := DigestV2(manifest)
	if err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{}, err
	}
	switch {
	case manifest.Sequence < state.HighestSequence:
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
			errors.New("v2 manifest sequence rollback detected")
	case manifest.Sequence == state.HighestSequence:
		if digest != state.ManifestDigest {
			return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
				errors.New(
					"v2 manifest sequence was equivocated",
				)
		}
	default:
		if manifest.Sequence != state.HighestSequence+1 {
			return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
				errors.New("v2 manifest sequence gap detected")
		}
		if manifest.PreviousDigest != state.ManifestDigest {
			return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
				errors.New(
					"v2 manifest predecessor digest mismatch",
				)
		}
	}
	var checkpoint transparency.Checkpoint
	if manifest.Sequence > state.HighestSequence {
		checkpoint, err = transparency.VerifyInclusionExtension(
			logPath, digest, pins, state.Checkpoint,
		)
	} else {
		checkpoint, err = transparency.VerifyInclusion(
			logPath, digest, pins, &state.Checkpoint,
		)
	}
	if err != nil {
		return ManifestV2{}, NodeV2{}, "", TrustStateV2{},
			fmt.Errorf("v2 manifest transparency: %w", err)
	}
	next := TrustStateV2{
		Format:          TrustStateFormatV2,
		HighestSequence: manifest.Sequence,
		ManifestDigest:  digest,
		Checkpoint:      checkpoint,
	}
	return manifest, node, digest, next, nil
}

func validateTrustStateV2(state TrustStateV2) error {
	if state.Format != TrustStateFormatV2 ||
		state.HighestSequence == 0 ||
		!validDigest(state.ManifestDigest) ||
		state.Checkpoint.Size == 0 ||
		!validDigest(state.Checkpoint.ReceiptDigest) {
		return errors.New("v2 gateway trust state is invalid")
	}
	return nil
}
