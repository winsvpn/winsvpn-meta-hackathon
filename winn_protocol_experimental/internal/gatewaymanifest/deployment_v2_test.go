package gatewaymanifest

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/securefile"
	"winsvpn.local/winnprotocol/internal/transparency"
)

func TestLoadVerifiedNodeV2AdvancesAndRejectsRollback(t *testing.T) {
	signer, pins := manifestTestKeys(t)
	now := time.Now().UTC()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest-v2.json")
	logPath := filepath.Join(directory, "transparency.jsonl")
	statePath := filepath.Join(directory, "trust-state-v2.json")

	first := validManifestV2(t, now)
	if err := SignV2(&first, signer); err != nil {
		t.Fatal(err)
	}
	writeManifestV2(t, manifestPath, first)
	firstDigest, err := DigestV2(first)
	if err != nil {
		t.Fatal(err)
	}
	_, firstCheckpoint, err := transparency.Append(
		logPath, firstDigest, signer, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, bootDigest, state, err := BootstrapTrustStateV2(
		manifestPath, logPath, firstCheckpoint, pins,
		now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if bootDigest != firstDigest ||
		state.HighestSequence != first.Sequence {
		t.Fatalf("bootstrap state = %#v", state)
	}
	writeTrustStateV2(t, statePath, state)

	second := validManifestV2(t, now.Add(time.Minute))
	second.Sequence = first.Sequence + 1
	second.PreviousDigest = firstDigest
	if err := SignV2(&second, signer); err != nil {
		t.Fatal(err)
	}
	writeManifestV2(t, manifestPath, second)
	secondDigest, err := DigestV2(second)
	if err != nil {
		t.Fatal(err)
	}
	_, secondCheckpoint, err := transparency.Append(
		logPath, secondDigest, signer, pins, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, node, gotDigest, next, err := LoadVerifiedNodeV2(
		manifestPath,
		"entry-nyc",
		logPath,
		statePath,
		pins,
		now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != "entry-nyc" || gotDigest != secondDigest ||
		next.HighestSequence != second.Sequence ||
		next.Checkpoint != secondCheckpoint {
		t.Fatalf("advanced v2 trust state = %#v", next)
	}
	writeTrustStateV2(t, statePath, next)

	writeManifestV2(t, manifestPath, first)
	if _, _, _, _, err := LoadVerifiedNodeV2(
		manifestPath,
		"entry-nyc",
		logPath,
		statePath,
		pins,
		now.Add(2*time.Minute),
	); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("v2 rollback error = %v", err)
	}
}

func TestLoadVerifiedNodeV2RejectsSequenceGapAndWrongPredecessor(
	t *testing.T,
) {
	signer, pins := manifestTestKeys(t)
	now := time.Now().UTC()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest-v2.json")
	logPath := filepath.Join(directory, "transparency.jsonl")
	statePath := filepath.Join(directory, "trust-state-v2.json")
	first := validManifestV2(t, now)
	if err := SignV2(&first, signer); err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := DigestV2(first)
	_, checkpoint, err := transparency.Append(
		logPath, firstDigest, signer, pins, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	writeTrustStateV2(t, statePath, TrustStateV2{
		Format:          TrustStateFormatV2,
		HighestSequence: first.Sequence,
		ManifestDigest:  firstDigest,
		Checkpoint:      checkpoint,
	})

	tests := []struct {
		name     string
		sequence uint64
		previous string
		error    string
	}{
		{"gap", 3, firstDigest, "gap"},
		{"predecessor", 2, repeatByteHex(0xee), "predecessor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := validManifestV2(t, now.Add(time.Minute))
			current.Sequence = test.sequence
			current.PreviousDigest = test.previous
			if err := SignV2(&current, signer); err != nil {
				t.Fatal(err)
			}
			writeManifestV2(t, manifestPath, current)
			digest, _ := DigestV2(current)
			testLog := filepath.Join(directory, test.name+".jsonl")
			_, _, err := transparency.Append(
				testLog, firstDigest, signer, pins, now,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = transparency.Append(
				testLog, digest, signer, pins, now.Add(time.Minute),
			)
			if err != nil {
				t.Fatal(err)
			}
			testState := filepath.Join(
				directory, test.name+"-state.json",
			)
			firstLogReceipts, firstLogCheckpoint, err :=
				transparency.ReadAndVerify(testLog, pins)
			if err != nil || len(firstLogReceipts) != 2 {
				t.Fatal(err)
			}
			_ = firstLogCheckpoint
			firstReceiptDigest, err := transparency.Digest(
				firstLogReceipts[0],
			)
			if err != nil {
				t.Fatal(err)
			}
			writeTrustStateV2(t, testState, TrustStateV2{
				Format:          TrustStateFormatV2,
				HighestSequence: first.Sequence,
				ManifestDigest:  firstDigest,
				Checkpoint: transparency.Checkpoint{
					Size:          1,
					ReceiptDigest: firstReceiptDigest,
				},
			})
			if _, _, _, _, err := LoadVerifiedNodeV2(
				manifestPath,
				"entry-nyc",
				testLog,
				testState,
				pins,
				now.Add(2*time.Minute),
			); err == nil || !strings.Contains(err.Error(), test.error) {
				t.Fatalf("%s error = %v", test.name, err)
			}
		})
	}
}

func TestLoadVerifiedNodeV2RequiresReceiptAfterRetainedCheckpoint(
	t *testing.T,
) {
	signer, pins := manifestTestKeys(t)
	now := time.Now().UTC()
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest-v2.json")
	logPath := filepath.Join(directory, "transparency.jsonl")
	statePath := filepath.Join(directory, "trust-state-v2.json")

	first := validManifestV2(t, now)
	if err := SignV2(&first, signer); err != nil {
		t.Fatal(err)
	}
	firstDigest, err := DigestV2(first)
	if err != nil {
		t.Fatal(err)
	}
	second := validManifestV2(t, now.Add(time.Minute))
	second.Sequence = first.Sequence + 1
	second.PreviousDigest = firstDigest
	if err := SignV2(&second, signer); err != nil {
		t.Fatal(err)
	}
	secondDigest, err := DigestV2(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := transparency.Append(
		logPath, firstDigest, signer, pins, now,
	); err != nil {
		t.Fatal(err)
	}
	_, retainedHead, err := transparency.Append(
		logPath, secondDigest, signer, pins, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	writeTrustStateV2(t, statePath, TrustStateV2{
		Format:          TrustStateFormatV2,
		HighestSequence: first.Sequence,
		ManifestDigest:  firstDigest,
		Checkpoint:      retainedHead,
	})
	writeManifestV2(t, manifestPath, second)

	if _, _, _, _, err := LoadVerifiedNodeV2(
		manifestPath, "entry-nyc", logPath, statePath, pins,
		now.Add(2*time.Minute),
	); err == nil || !strings.Contains(err.Error(), "extend") {
		t.Fatalf("pre-checkpoint receipt error = %v", err)
	}
}

func writeManifestV2(t testing.TB, path string, manifest ManifestV2) {
	t.Helper()
	encoded, err := EncodeV2(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTrustStateV2(t testing.TB, path string, state TrustStateV2) {
	t.Helper()
	encoded, err := EncodeTrustStateV2(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.AtomicWrite(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
