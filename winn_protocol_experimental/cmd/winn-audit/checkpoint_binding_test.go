// The command-level half of the external-binding requirement.
//
// internal/auditcheckpoint enforces the run identity and producer digest as
// hard preconditions, but this command exposes both the seal and the verify
// path directly, so an operator can reach the library without going through
// cmd/winn-phase1-matrix-verify's wrapper. These tests assert the refusals
// survive that shortcut: blank run identity and blank producer digest, on both
// paths, four combinations.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
)

const (
	bindingLogName  = "carrier-audit.jsonl"
	bindingRunID    = "winn-audit-cli-binding-run"
	bindingProducer = "" +
		"3131313131313131313131313131313131313131313131313131313131313131"
)

// newSealedEvidence builds a closed-log, sealed-manifest evidence directory and
// a runner-held finalizer seed outside it.
func newSealedEvidence(t *testing.T) (directory, seedPath string) {
	t.Helper()
	directory = t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(directory, bindingLogName), keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		if err := log.Record("carrier_event", "device", "", "detail"); err != nil {
			_ = log.Close()
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, auditcheckpoint.EnvironmentName),
		[]byte("source_digest="+bindingProducer+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	sealManifest(t, directory)

	seedPath = filepath.Join(t.TempDir(), "finalizer.seed")
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, seedPath
}

func sealManifest(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() ||
			name == "evidence-manifest.sha256" ||
			strings.Contains(name, "audit-checkpoint") {
			continue
		}
		content, err := os.ReadFile( // #nosec G304 -- test temp path
			filepath.Join(directory, name),
		)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		lines = append(lines, hex.EncodeToString(digest[:])+"  ./"+name)
	}
	sort.Strings(lines)
	if err := os.WriteFile(
		filepath.Join(directory, "evidence-manifest.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func TestSealRefusesBlankExternalBindings(t *testing.T) {
	t.Run("blank_run_id", func(t *testing.T) {
		directory, seedPath := newSealedEvidence(t)
		err := seal(
			directory, bindingLogName, "evidence-manifest.sha256",
			"", bindingProducer, seedPath,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "requires a run identity") {
			t.Fatalf(
				"sealing with no run identity: got %v, want a refusal", err,
			)
		}
		if _, statErr := os.Lstat(
			filepath.Join(directory, auditcheckpoint.FileName),
		); statErr == nil {
			t.Fatal("a checkpoint was written despite the refusal")
		}
	})

	t.Run("blank_producer_digest", func(t *testing.T) {
		directory, seedPath := newSealedEvidence(t)
		err := seal(
			directory, bindingLogName, "evidence-manifest.sha256",
			bindingRunID, "", seedPath,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "requires a producer digest") {
			t.Fatalf(
				"sealing with no producer digest: got %v, want a refusal", err,
			)
		}
		if _, statErr := os.Lstat(
			filepath.Join(directory, auditcheckpoint.FileName),
		); statErr == nil {
			t.Fatal("a checkpoint was written despite the refusal")
		}
	})
}

func TestVerifyRefusesBlankExternalBindings(t *testing.T) {
	directory, seedPath := newSealedEvidence(t)
	if err := seal(
		directory, bindingLogName, "evidence-manifest.sha256",
		bindingRunID, bindingProducer, seedPath,
	); err != nil {
		t.Fatalf("the positive control must seal: %v", err)
	}
	keyID, err := auditcheckpoint.KeyIDFromSeedFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(
		directory, bindingLogName, bindingRunID, bindingProducer, keyID,
	); err != nil {
		t.Fatalf("the positive control must verify: %v", err)
	}

	t.Run("blank_run_id", func(t *testing.T) {
		err := verify(
			directory, bindingLogName, "", bindingProducer, keyID,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "externally supplied run identity") {
			t.Fatalf(
				"verifying with no run identity: got %v, want a refusal", err,
			)
		}
	})

	t.Run("blank_producer_digest", func(t *testing.T) {
		err := verify(
			directory, bindingLogName, bindingRunID, "", keyID,
		)
		if err == nil ||
			!strings.Contains(err.Error(), "externally supplied producer digest") {
			t.Fatalf(
				"verifying with no producer digest: got %v, want a refusal", err,
			)
		}
	})

	t.Run("blank_finalizer_pin", func(t *testing.T) {
		err := verify(
			directory, bindingLogName, bindingRunID, bindingProducer, "",
		)
		if err == nil || !strings.Contains(err.Error(), "not pinned") {
			t.Fatalf(
				"verifying with no finalizer pin: got %v, want a refusal", err,
			)
		}
	})
}
