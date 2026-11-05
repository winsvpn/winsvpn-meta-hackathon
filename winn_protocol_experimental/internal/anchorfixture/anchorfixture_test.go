package anchorfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/phase1anchor"
)

// TestGenesisRequestIsValid locks the fixture genesis shape against the real
// request validator. A fixture that built an invalid genesis would make every
// seam test fail inside the pin tool, or worse, skip the seam if a caller
// treated construction as proof of validity.
func TestGenesisRequestIsValid(t *testing.T) {
	request := GenesisRequest("m1")
	if err := request.Validate(); err != nil {
		t.Fatalf("GenesisRequest must satisfy phase1anchor.Request.Validate: %v", err)
	}
	if got, want := len(request.SourceDigest), 64; got != want {
		t.Fatalf("SourceDigest length %d, want %d", got, want)
	}
}

// TestBatchRequestIsValid locks AttemptCount, Readiness, Profile, and the
// digest fills against the real validator. phase1anchor.Request.Validate
// requires AttemptCount == 100; a fixture that drifted would only be caught
// here or inside a consumer, never by `go test` of this package.
func TestBatchRequestIsValid(t *testing.T) {
	request := BatchRequest("m1", "b0001-edge-warm", 1)
	if err := request.Validate(); err != nil {
		t.Fatalf("BatchRequest must satisfy phase1anchor.Request.Validate: %v", err)
	}
}

func TestBuildPinToolReturnsAnExecutable(t *testing.T) {
	path := BuildPinTool(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("BuildPinTool returned %q: %v", path, err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("BuildPinTool output is not executable: mode %s", info.Mode())
	}
	if filepath.Base(path) != "winn-phase1-anchor-pin" {
		t.Fatalf("BuildPinTool named the binary %q", filepath.Base(path))
	}
}

// TestProduceRunsTheRealPinToolAgainstAStubProvider is the in-package control
// that `go test ./internal/anchorfixture` previously lacked. It does not name
// slot members: that would be a third enumeration of the artifact set.
func TestProduceRunsTheRealPinToolAgainstAStubProvider(t *testing.T) {
	slot := Produce(
		t, GenesisRequest("m1"),
		phase1anchor.ZeroDigest, phase1anchor.ZeroDigest,
	)
	if slot.ProviderOneHost == "" || slot.ProviderTwoHost == "" {
		t.Fatal("fixture hosts are empty")
	}
	if slot.ProviderOneHost == slot.ProviderTwoHost {
		t.Fatal("same host would let the stub serve one receipt twice")
	}
	if !phase1anchor.ValidDigest(slot.KnownHostsDigest) {
		t.Fatalf("KnownHostsDigest %q is not a canonical digest", slot.KnownHostsDigest)
	}
	info, err := os.Stat(slot.Directory)
	if err != nil {
		t.Fatalf("pin tool did not create slot directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("slot path %q is not a directory", slot.Directory)
	}
	entries, err := os.ReadDir(slot.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("pin tool returned success with an empty slot directory")
	}
}

// TestProduceBatchRequestWritesNonEmptySlotDirectory runs the same pin tool
// over a batch request. The package exists because of a batch-meta.env miss;
// a genesis-only in-package test would not have caught that class of gap.
func TestProduceBatchRequestWritesNonEmptySlotDirectory(t *testing.T) {
	slot := Produce(
		t, BatchRequest("m1", "b0001-edge-warm", 1),
		strings.Repeat("a", 64), strings.Repeat("b", 64),
	)
	entries, err := os.ReadDir(slot.Directory)
	if err != nil {
		t.Fatalf("pin tool did not write a readable slot directory: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("pin tool returned success with an empty slot directory")
	}
}
