package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Provenance is the frozen identity of one soak: which snapshot, which runner,
// which verifier, which manifest, which source digest.
//
// Every field is a lowercase hex SHA-256 except SnapshotFileCount, which is
// carried because a digest alone cannot distinguish "the tree is unchanged"
// from "the tree is unreadable and both walks returned nothing". A count of
// zero is refused outright for that reason.
type Provenance struct {
	SnapshotRoot      string `json:"snapshot_root"`
	SnapshotDigest    string `json:"snapshot_digest"`
	SnapshotFileCount int    `json:"snapshot_file_count"`
	SnapshotFsType    string `json:"snapshot_filesystem_type"`
	SnapshotReadOnly  bool   `json:"snapshot_read_only"`

	RunnerPath     string `json:"runner_path"`
	RunnerDigest   string `json:"runner_digest"`
	VerifierPath   string `json:"verifier_path"`
	VerifierDigest string `json:"verifier_digest"`
	ManifestPath   string `json:"manifest_path"`
	ManifestDigest string `json:"manifest_digest"`
	SourceDigest   string `json:"source_digest"`
	// ConfigurationDigest commits to the exact canonical child environment
	// and every behavior-affecting controller option. Environment values never
	// appear in receipts, checkpoints, summaries, or logs.
	ConfigurationDigest string `json:"configuration_digest"`
}

// quarantineMarkers are file names whose mere presence in a tree means the
// tree has been set aside by something -- this project's own runner writes
// INVALID, and macOS writes .quarantine-style markers when a download is not
// trusted.
//
// The check is presence, not content. A quarantined tree is refused outright
// rather than inspected, because reading a marker to decide whether it "really"
// applies is exactly the negotiation that quarantine exists to prevent.
var quarantineMarkers = []string{
	"INVALID",
	"QUARANTINE",
	".quarantine",
	".winn-quarantine",
}

var errQuarantined = errors.New("tree is quarantined")

// mountProber is the filesystem probe gatherProvenance uses.
//
// It is a variable so a test can present an overlay mount without needing root
// and a kernel feature. Mutation testing is what put it here: with probeMount
// called directly, deleting the union-mount refusal from gatherProvenance left
// every test passing on this developer's APFS host, because no test could ever
// present a union mount to the real code path. A predicate that is only ever
// tested in isolation is a predicate nobody has checked is wired in.
var mountProber = probeMountDescriptor

// evaluateSnapshotMount is the whole decision taken on a probe's answer.
//
// Extracted so the decision and its wiring can be tested separately: the table
// of filesystem names checks the policy, and a swapped mountProber checks that
// gatherProvenance actually consults it.
func evaluateSnapshotMount(
	root string, facts mountFacts, allowWritable bool,
) error {
	if !facts.Available {
		return fmt.Errorf(
			"this platform cannot report the filesystem under %s, so the "+
				"union-mount and read-only gates cannot be enforced", root,
		)
	}
	if reason, refuse := facts.refusalReason(); refuse {
		return errors.New(reason)
	}
	if !facts.ReadOnly && !allowWritable {
		return fmt.Errorf(
			"snapshot root %s is on a writable %s mount; re-mount it "+
				"read-only, or pass -allow-writable-snapshot to accept "+
				"detection-only immutability", root, facts.FilesystemType,
		)
	}
	return nil
}

// gatherProvenance freezes the identity of the inputs and refuses everything
// that would make that identity meaningless.
//
// Ordering is deliberate. The structural refusals -- symlinked paths, union
// filesystems, quarantine -- run BEFORE any digest is computed, so a tree that
// is not allowed to be used at all is told that, rather than being told which
// digest it failed to match. Computing a digest first would also mean walking
// a possibly enormous, possibly attacker-shaped tree before deciding whether it
// was permitted to exist.
func gatherProvenance(cfg Config) (Provenance, error) {
	root := filepath.Clean(cfg.SnapshotRoot)
	if err := requireNoSymlinkInPath(root); err != nil {
		return Provenance{}, err
	}
	directory, err := openSecureDirectory(root)
	if err != nil {
		return Provenance{}, fmt.Errorf("open snapshot root: %w", err)
	}
	defer func() { _ = directory.Close() }()

	facts, err := mountProber(directory.file)
	if err != nil {
		return Provenance{}, err
	}
	if err := evaluateSnapshotMount(
		root, facts, cfg.AllowWritableSnapshot,
	); err != nil {
		return Provenance{}, err
	}
	digest, count, err := treeDigestDirectory(directory)
	if err != nil {
		return Provenance{}, fmt.Errorf("digest snapshot tree: %w", err)
	}
	if count == 0 {
		return Provenance{}, fmt.Errorf(
			"snapshot root %s contains no regular files; an empty tree "+
				"digests identically whether it is empty or unreadable", root,
		)
	}

	provenance := Provenance{
		SnapshotRoot:      root,
		SnapshotDigest:    digest,
		SnapshotFileCount: count,
		SnapshotFsType:    facts.FilesystemType,
		SnapshotReadOnly:  facts.ReadOnly,
		RunnerPath:        cfg.RunnerPath,
		VerifierPath:      cfg.VerifierPath,
		ManifestPath:      cfg.ManifestPath,
		SourceDigest:      cfg.ExpectedSourceDigest,
	}
	configuration, err := configurationDigest(cfg)
	if err != nil {
		return Provenance{}, err
	}
	provenance.ConfigurationDigest = configuration

	pins := []struct {
		label    string
		path     string
		expected string
		into     *string
	}{
		{"runner", cfg.RunnerPath, cfg.ExpectedRunnerSHA256, &provenance.RunnerDigest},
		{"verifier", cfg.VerifierPath, cfg.ExpectedVerifierSHA256, &provenance.VerifierDigest},
		{"manifest", cfg.ManifestPath, cfg.ExpectedManifestSHA256, &provenance.ManifestDigest},
	}
	for _, pin := range pins {
		if err := requireNoSymlinkInPath(pin.path); err != nil {
			return Provenance{}, fmt.Errorf("%s: %w", pin.label, err)
		}
		actual, err := fileDigest(pin.path)
		if err != nil {
			return Provenance{}, fmt.Errorf("%s: %w", pin.label, err)
		}
		if actual != pin.expected {
			return Provenance{}, fmt.Errorf(
				"%s digest mismatch: %s has %s, expected %s",
				pin.label, pin.path, actual, pin.expected,
			)
		}
		*pin.into = actual
	}
	return provenance, nil
}

// driftKind names which pin moved. The controller reports the specific one
// because "something changed" sends an operator to re-verify five artifacts,
// and because runner replacement in particular is the one that means a
// different program produced the later cycles.
type driftKind string

const (
	driftNone      driftKind = ""
	driftSnapshot  driftKind = "snapshot_tree"
	driftRunner    driftKind = "runner_binary"
	driftVerifier  driftKind = "verifier_binary"
	driftManifest  driftKind = "source_manifest"
	driftSourcePin driftKind = "source_digest"
	driftConfig    driftKind = "controller_configuration"
	driftPaths     driftKind = "pinned_paths"
)

// detectDrift compares a freshly gathered Provenance against the frozen one.
//
// It returns the FIRST difference in a fixed order rather than a set, so the
// same drift always produces the same reason string and the receipt for a given
// failure is reproducible.
func detectDrift(frozen, current Provenance) (driftKind, string) {
	switch {
	case frozen.RunnerPath != current.RunnerPath ||
		frozen.VerifierPath != current.VerifierPath ||
		frozen.ManifestPath != current.ManifestPath ||
		frozen.SnapshotRoot != current.SnapshotRoot:
		return driftPaths, fmt.Sprintf(
			"pinned paths changed: runner %q->%q, verifier %q->%q, "+
				"manifest %q->%q, snapshot %q->%q",
			frozen.RunnerPath, current.RunnerPath,
			frozen.VerifierPath, current.VerifierPath,
			frozen.ManifestPath, current.ManifestPath,
			frozen.SnapshotRoot, current.SnapshotRoot,
		)
	case frozen.RunnerDigest != current.RunnerDigest:
		return driftRunner, fmt.Sprintf(
			"runner %s is now %s, was %s",
			frozen.RunnerPath, current.RunnerDigest, frozen.RunnerDigest,
		)
	case frozen.VerifierDigest != current.VerifierDigest:
		return driftVerifier, fmt.Sprintf(
			"verifier %s is now %s, was %s",
			frozen.VerifierPath, current.VerifierDigest, frozen.VerifierDigest,
		)
	case frozen.ManifestDigest != current.ManifestDigest:
		return driftManifest, fmt.Sprintf(
			"source manifest %s is now %s, was %s",
			frozen.ManifestPath, current.ManifestDigest, frozen.ManifestDigest,
		)
	case frozen.SourceDigest != current.SourceDigest:
		return driftSourcePin, fmt.Sprintf(
			"expected source digest is now %s, was %s",
			current.SourceDigest, frozen.SourceDigest,
		)
	case frozen.ConfigurationDigest != current.ConfigurationDigest:
		return driftConfig, fmt.Sprintf(
			"canonical controller/environment digest is now %s, was %s",
			current.ConfigurationDigest, frozen.ConfigurationDigest,
		)
	case frozen.SnapshotDigest != current.SnapshotDigest ||
		frozen.SnapshotFileCount != current.SnapshotFileCount:
		return driftSnapshot, fmt.Sprintf(
			"snapshot tree is now %s over %d files, was %s over %d files",
			current.SnapshotDigest, current.SnapshotFileCount,
			frozen.SnapshotDigest, frozen.SnapshotFileCount,
		)
	}
	return driftNone, ""
}

// custodySeparationNames are the environment variable names and file names
// that would mean a signing or finalizing secret is present on this host.
//
// This list is the known ways the discipline gets broken. It is not, and is
// never reported as, proof of absence: the separation comes from never
// provisioning the seed to the producing host in the first place, and a host
// where the runner executes as root can read any root-owned file regardless of
// what this function finds. cmd/winn-audit makes the same statement about its
// own -detect-finalizer-leaks scan, and this is deliberately the weaker,
// controller-local echo of it rather than a replacement.
var custodySeparationNames = []string{
	"FINALIZER_SEED",
	"FINALIZER_KEY",
	"FINALIZER_PRIVATE_KEY",
	"WINN_FINALIZER_SEED",
	"AUDIT_FINALIZER_SEED",
	"SIGNING_KEY",
	"SIGNING_SEED",
	"SLHDSA_SECRET_KEY",
	"RELEASE_SIGNING_KEY",
	"ANCHOR_SSH_KEY",
}

// custodySeparationFiles are file basenames searched for in the directories
// this controller is given.
var custodySeparationFiles = []string{
	"finalizer.seed",
	"finalizer.key",
	"finalizer-secret.key",
	"audit-finalizer.seed",
	"signing.key",
	"slhdsa.secret",
	"release-signing.key",
}

// CustodyFinding is one reason the custody-separation invariant does not hold.
type CustodyFinding struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// checkCustodySeparation looks for finalizer and signing material where this
// controller could reach it.
//
// environment is passed in rather than read from os.Environ() so the check is
// testable against a constructed environment; the caller supplies the real one.
//
// Only NAMES are ever returned. A finding that quoted the value would write the
// secret into the very receipt log the operator then copies off the host.
func checkCustodySeparation(
	environment []string, directories []string,
) []CustodyFinding {
	var findings []CustodyFinding
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		upper := strings.ToUpper(name)
		for _, forbidden := range custodySeparationNames {
			if upper == forbidden || strings.HasSuffix(upper, "_"+forbidden) {
				findings = append(findings, CustodyFinding{
					Kind: "environment",
					Detail: fmt.Sprintf(
						"the environment defines %s (value withheld)", name,
					),
				})
				break
			}
		}
	}
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		for _, base := range custodySeparationFiles {
			candidate := filepath.Join(directory, base)
			if _, err := os.Lstat(candidate); err == nil {
				findings = append(findings, CustodyFinding{
					Kind:   "file",
					Detail: fmt.Sprintf("%s exists", candidate),
				})
			}
		}
	}
	return findings
}
