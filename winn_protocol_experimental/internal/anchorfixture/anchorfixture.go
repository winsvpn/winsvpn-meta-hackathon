// Package anchorfixture produces a REAL anchor slot by running the real
// winn-phase1-anchor-pin binary.
//
// It exists because of the batch-meta.env P0. The pin tool wrote a slot, the
// formal verifier required a slot, and both sides were thoroughly tested — each
// against its own hand-built idea of what a slot is. Nothing ever fed one side's
// actual output to the other side's actual input, so a file the verifier
// demanded and the pin tool never wrote went unnoticed until a live run. An
// independent reviewer later confirmed the underlying gap directly: no test
// anywhere executed the real pin tool.
//
// The rule this package exists to preserve: on the pin-to-consumer seam there
// are NO fakes and NO second enumeration. The slot is produced by the actual
// binary, and each consumer checks it with its actual production code. Nothing
// here states what a slot contains — that would just be a third enumeration,
// and it would agree with whichever side wrote it.
//
// What IS substituted is the anchor PROVIDER: a stub stands in for ssh so that
// no test contacts an external host. The provider is outside the seam under
// test, and its receipts are produced by the real phase1anchor.NewReceipt with
// real Ed25519 keys, so the bytes crossing the seam are genuine.
package anchorfixture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// Slot is a committed-shaped anchor slot written by the real pin tool, together
// with everything a consumer needs to verify it.
type Slot struct {
	// Directory holds the artifacts the pin tool actually wrote.
	Directory string

	Request      phase1anchor.Request
	RequestBytes []byte

	ProviderOneID     string
	ProviderTwoID     string
	ProviderOneHost   string
	ProviderTwoHost   string
	ProviderOnePublic ed25519.PublicKey
	ProviderTwoPublic ed25519.PublicKey

	KnownHosts       []byte
	KnownHostsDigest string

	PreviousOne string
	PreviousTwo string
}

// GenesisRequest returns a valid genesis request, the simplest shape that
// exercises the whole pin path.
func GenesisRequest(matrixID string) phase1anchor.Request {
	return phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               phase1anchor.KindGenesis,
		MatrixID:           matrixID,
		SourceDigest:       fill('1'),
		AutoArtifactDigest: fill('2'),
		ProfileDigest:      fill('3'),
		ScheduleDigest:     fill('4'),
		ExpectedBatchCount: 4,
		Ordinal:            0,
	}
}

// BatchRequest returns a valid batch request at the given ordinal.
func BatchRequest(matrixID, batchKey string, ordinal int) phase1anchor.Request {
	return phase1anchor.Request{
		Schema:                 phase1anchor.RequestSchema,
		Kind:                   phase1anchor.KindBatch,
		MatrixID:               matrixID,
		SourceDigest:           fill('1'),
		AutoArtifactDigest:     fill('2'),
		ProfileDigest:          fill('3'),
		ScheduleDigest:         fill('4'),
		ExpectedBatchCount:     4,
		Ordinal:                ordinal,
		BatchKey:               batchKey,
		ScheduleRowDigest:      fill('5'),
		Profile:                "envelope-edge-250ms-3pct-10mbps",
		Readiness:              "warm",
		AttemptCount:           100,
		ArchiveDigest:          fill('6'),
		EvidenceManifestDigest: fill('7'),
		AttemptLogDigest:       fill('8'),
		AttemptAnchorDigest:    fill('9'),
	}
}

func fill(character byte) string {
	value := make([]byte, sha256.Size*2)
	for index := range value {
		value[index] = character
	}
	return string(value)
}

// BuildPinTool compiles the real winn-phase1-anchor-pin and returns its path.
func BuildPinTool(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	output := filepath.Join(t.TempDir(), "winn-phase1-anchor-pin")
	command := exec.Command( // #nosec G204 -- the toolchain running this test
		goTool(t), "build", "-o", output,
		"winsvpn.local/winnprotocol/cmd/winn-phase1-anchor-pin",
	)
	command.Dir = root
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the real pin tool: %v\n%s", err, combined)
	}
	return output
}

// Options adjusts what the stub provider sends back, so a caller can prove the
// pin tool's refusals as well as its successes.
type Options struct {
	// MangleProviderOutput rewrites the bytes the stub provider emits, after
	// they have been built canonically. It is how a test poses the question
	// "what does the pin tool do with a provider that returns a semantically
	// correct but non-canonical receipt" — the case where every signature and
	// digest still matches and only the bytes differ.
	MangleProviderOutput func([]byte) []byte
	// AllowFailure lets the pin run fail without failing the test, so the
	// caller can assert on the refusal.
	AllowFailure bool
}

// Produce runs the real pin tool against a stub provider and returns the slot
// it wrote.
//
// previousOne and previousTwo are the predecessor receipt digests; use
// phase1anchor.ZeroDigest for genesis.
func Produce(
	t *testing.T,
	request phase1anchor.Request,
	previousOne, previousTwo string,
) *Slot {
	t.Helper()
	slot, err := ProduceWith(t, request, previousOne, previousTwo, Options{})
	if err != nil {
		t.Fatalf("the real pin tool failed: %v", err)
	}
	return slot
}

// ProduceWith is Produce with control over the stub provider's output.
func ProduceWith(
	t *testing.T,
	request phase1anchor.Request,
	previousOne, previousTwo string,
	options Options,
) (*Slot, error) {
	t.Helper()
	workspace := t.TempDir()

	onePublic, onePrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	twoPublic, twoPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	slot := &Slot{
		Request:           request,
		ProviderOneID:     "provider-one",
		ProviderTwoID:     "provider-two",
		ProviderOneHost:   "127.0.0.1",
		ProviderTwoHost:   "127.0.0.2",
		ProviderOnePublic: onePublic,
		ProviderTwoPublic: twoPublic,
		PreviousOne:       previousOne,
		PreviousTwo:       previousTwo,
	}

	canonical, err := request.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	slot.RequestBytes = append(append([]byte(nil), canonical...), '\n')

	// The provider receipts, built with the real constructor and real keys. The
	// timestamp is fixed so the whole fixture is deterministic; nothing in the
	// pin path or either consumer depends on it being recent.
	received := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC).
		Format(time.RFC3339Nano)
	oneReceipt, err := phase1anchor.NewReceipt(
		request, slot.ProviderOneID, previousOne, received, onePrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	twoReceipt, err := phase1anchor.NewReceipt(
		request, slot.ProviderTwoID, previousTwo, received, twoPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}

	emit := func(receipt phase1anchor.Receipt) []byte {
		bytes := canonicalReceiptBytes(t, receipt)
		if options.MangleProviderOutput != nil {
			return options.MangleProviderOutput(bytes)
		}
		return bytes
	}
	writeFile(t, filepath.Join(workspace, "one.receipt"), emit(oneReceipt), 0o600)
	writeFile(t, filepath.Join(workspace, "two.receipt"), emit(twoReceipt), 0o600)

	// Trust material the pin tool reads.
	keyOne := filepath.Join(workspace, "provider-one.ed25519.pub")
	keyTwo := filepath.Join(workspace, "provider-two.ed25519.pub")
	writeFile(t, keyOne,
		[]byte(base64.StdEncoding.EncodeToString(onePublic)+"\n"), 0o600)
	writeFile(t, keyTwo,
		[]byte(base64.StdEncoding.EncodeToString(twoPublic)+"\n"), 0o600)

	slot.KnownHosts = []byte(
		"127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTUREONE\n" +
			"127.0.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTURETWO\n",
	)
	knownHosts := filepath.Join(workspace, "known_hosts")
	writeFile(t, knownHosts, slot.KnownHosts, 0o600)
	sum := sha256.Sum256(slot.KnownHosts)
	slot.KnownHostsDigest = hex.EncodeToString(sum[:])

	sshKey := filepath.Join(workspace, "anchor.key")
	writeFile(t, sshKey, []byte("PRIVATE KEY PLACEHOLDER\n"), 0o600)

	// The stub provider transport. It selects a receipt by destination, so a pin
	// tool that contacted the wrong host, or the same host twice, produces a
	// slot whose receipts fail verification rather than one that quietly works.
	stubSSH := filepath.Join(workspace, "ssh")
	writeFile(t, stubSSH, []byte(
		"#!/bin/sh\n"+
			"dir=$(dirname \"$0\")\n"+
			"destination=\"\"\n"+
			"for argument in \"$@\"; do destination=$argument; done\n"+
			"case \"$destination\" in\n"+
			"  *@"+slot.ProviderOneHost+") exec cat \"$dir/one.receipt\" ;;\n"+
			"  *@"+slot.ProviderTwoHost+") exec cat \"$dir/two.receipt\" ;;\n"+
			"esac\n"+
			"echo 'ANCHOR_REJECT: unknown destination' >&2\n"+
			"exit 1\n",
	), 0o700)

	requestPath := filepath.Join(workspace, "request.json")
	writeFile(t, requestPath, slot.RequestBytes, 0o600)

	slot.Directory = filepath.Join(workspace, "slot")

	command := exec.Command( // #nosec G204 -- the pin tool this test just built
		BuildPinTool(t),
		"-pending-directory", slot.Directory,
		"-request", requestPath,
		"-ssh-binary", stubSSH,
		"-ssh-key", sshKey,
		"-known-hosts", knownHosts,
		"-timeout", "20s",
		"-provider-one-id", slot.ProviderOneID,
		"-provider-one-host", slot.ProviderOneHost,
		"-provider-one-public-key", keyOne,
		"-provider-one-previous-receipt", previousOne,
		"-provider-two-id", slot.ProviderTwoID,
		"-provider-two-host", slot.ProviderTwoHost,
		"-provider-two-public-key", keyTwo,
		"-provider-two-previous-receipt", previousTwo,
	)
	combined, err := command.CombinedOutput()
	if err != nil {
		if !options.AllowFailure {
			t.Fatalf("the real pin tool failed: %v\n%s", err, combined)
		}
		return slot, fmt.Errorf("%w\n%s", err, combined)
	}
	return slot, nil
}

// canonicalReceiptBytes is the exact byte form a provider is required to emit.
func canonicalReceiptBytes(t *testing.T, receipt phase1anchor.Receipt) []byte {
	t.Helper()
	canonical, err := receipt.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return append(canonical, '\n')
}

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

// moduleRoot locates the module directory from the calling package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("no go.mod above the test's working directory")
		}
		directory = parent
	}
}

func goTool(t *testing.T) string {
	t.Helper()
	found, err := exec.LookPath("go")
	if err != nil {
		// Skip would report the calling test as success without ever running
		// the real pin tool. This package exists because that gap was a P0.
		t.Fatalf("no go toolchain is reachable: %v", err)
	}
	return found
}
