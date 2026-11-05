package gatewaymanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

// LoadVerifiedNode performs the full discovery trust decision: ML-DSA
// signature and validity, node membership, append-only log inclusion, and a
// caller-retained checkpoint pin.
func LoadVerifiedNode(manifestPath, nodeID, logPath, checkpointPath string, pins *pqauth.VerifierSet, now time.Time) (Manifest, Node, string, transparency.Checkpoint, error) {
	if manifestPath == "" || nodeID == "" || logPath == "" ||
		checkpointPath == "" || pins == nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{},
			errors.New("manifest, node, transparency log, checkpoint, and pins are required")
	}
	manifest, err := Load(manifestPath)
	if err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	if err := Verify(manifest, pins, now, DefaultClockSkew); err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	node, err := manifest.Node(nodeID)
	if err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	digest, err := Digest(manifest)
	if err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	checkpoint, err := loadCheckpoint(checkpointPath)
	if err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	verifiedCheckpoint, err := transparency.VerifyInclusion(
		logPath, digest, pins, &checkpoint,
	)
	if err != nil {
		return Manifest{}, Node{}, "", transparency.Checkpoint{}, err
	}
	return manifest, node, digest, verifiedCheckpoint, nil
}

func loadCheckpoint(path string) (transparency.Checkpoint, error) {
	data, err := securefile.ReadPublicIntegrity(path, 64<<10)
	if err != nil {
		return transparency.Checkpoint{}, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var checkpoint transparency.Checkpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return transparency.Checkpoint{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return transparency.Checkpoint{}, errors.New("transparency checkpoint contains extra JSON")
	}
	if checkpoint.Size == 0 || checkpoint.ReceiptDigest == "" {
		return transparency.Checkpoint{}, errors.New("transparency checkpoint is empty")
	}
	return checkpoint, nil
}
