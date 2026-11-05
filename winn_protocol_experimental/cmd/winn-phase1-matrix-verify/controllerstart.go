package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
)

// Verification of the controller's signed ownership record.
//
// CONTROLLER_START is the document that says which controller performed this
// transition, over which producer state, under which anchor providers. It was
// created and signed and then never read by the formal verifier — so from an
// auditor's position it established nothing. A signature nobody checks is a
// comment.
//
// This closes that: the record is parsed strictly, its signature is verified
// against the SAME externally pinned finalizer identity the audit checkpoints
// are verified against, and its bindings are required to agree with the
// controller state and the matrix the auditor is looking at.

const (
	controllerStartName   = "CONTROLLER_START"
	controllerStartSchema = "winn-phase1-controller-start/v1"
	maximumStartRecord    = 64 << 10
	maximumControllerEnv  = 64 << 10
)

// controllerEnvKeys is the exact key set controller.env may contain.
//
// parseKeyValueFile silently truncates at 64 KiB and accepts any key. Both are
// wrong here. Truncation means an oversized file is read as a valid prefix, so
// content past the cut simply does not exist as far as the verifier is
// concerned; unknown keys mean a field smuggled in under a look-alike name
// rides along unexamined, which is exactly what the closed-schema rule in
// verifyCarrierConservation exists to prevent for the conservation snapshot.
var controllerEnvKeys = map[string]struct{}{
	"schema":                     {},
	"matrix_id":                  {},
	"source_digest":              {},
	"anchor_mode":                {},
	"anchor_schema":              {},
	"anchor_provider_one_id":     {},
	"anchor_provider_one_key_id": {},
	"anchor_provider_two_id":     {},
	"anchor_provider_two_key_id": {},
	"anchor_known_hosts_sha256":  {},
	"expected_batch_count":       {},
	"finalizer_key_id":           {},
}

// readControllerEnv parses controller.env under a real bound and a closed key
// set.
func readControllerEnv(path string) (map[string]string, error) {
	content, err := readBoundedRegular(path, maximumControllerEnv)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, len(controllerEnvKeys))
	for _, line := range strings.Split(
		strings.TrimSuffix(string(content), "\n"), "\n",
	) {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("invalid key/value line in %s", path)
		}
		if _, known := controllerEnvKeys[key]; !known {
			return nil, fmt.Errorf(
				"%s declares unknown key %q; the controller state is a closed "+
					"schema", path, key,
			)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("duplicate key %q in %s", key, path)
		}
		values[key] = value
	}
	for key := range controllerEnvKeys {
		if _, present := values[key]; !present {
			return nil, fmt.Errorf("%s omits %s", path, key)
		}
	}
	return values, nil
}

// readBoundedRegular reads a regular file through a single hardened descriptor.
//
// The earlier version did Lstat, then openSecureRegular, which resolves the
// path again through EvalSymlinks — a symlink swapped in between the two calls
// meant every property the stat established described a different file than the
// one that was read. That is the same class of gap this codebase closes
// elsewhere with a single descriptor, and it is closed the same way here:
// producersnapshot.ReadRegular opens once, re-stats the descriptor, compares
// with os.SameFile, reads bounded, and re-stats again.
//
// Oversize is a refusal rather than a truncation: returning a prefix would
// present part of a file as the whole of it.
func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	content, _, err := producersnapshot.ReadRegular(path, maximum, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return content, nil
}

type controllerStartRecord struct {
	Schema                string `json:"schema"`
	MatrixID              string `json:"matrix_id"`
	SourceDigest          string `json:"source_digest"`
	ScheduleDigest        string `json:"schedule_digest"`
	AutoArtifactDigest    string `json:"auto_artifact_digest"`
	ProfileDigest         string `json:"profile_digest"`
	ExecutionInventory    string `json:"execution_inventory_sha256"`
	ProducerAttempts      int    `json:"producer_attempts"`
	ExpectedBatchCount    int    `json:"expected_batch_count"`
	ProducerSnapshot      string `json:"producer_snapshot_sha256"`
	AnchorProviderOneID   string `json:"anchor_provider_one_id"`
	AnchorProviderOneKey  string `json:"anchor_provider_one_key_id"`
	AnchorProviderTwoID   string `json:"anchor_provider_two_id"`
	AnchorProviderTwoKey  string `json:"anchor_provider_two_key_id"`
	AnchorKnownHostsSHA   string `json:"anchor_known_hosts_sha256"`
	FinalizerAlgorithm    string `json:"finalizer_algorithm"`
	FinalizerKeyID        string `json:"finalizer_key_id"`
	FinalizerPublicKeyB64 string `json:"finalizer_public_key"`
	SignatureB64          string `json:"signature"`
}

// signingMessage mirrors the controller's canonical encoding exactly. It is
// restated here rather than imported, on the same principle the carrier schema
// token is: the two have to be edited together, and a drift produces a loud
// signature failure rather than a silent agreement.
func (r controllerStartRecord) signingMessage() []byte {
	var builder strings.Builder
	builder.WriteString(controllerStartSchema + "\n")
	for _, pair := range [][2]string{
		{"matrix_id", r.MatrixID},
		{"source_digest", r.SourceDigest},
		{"schedule_digest", r.ScheduleDigest},
		{"auto_artifact_digest", r.AutoArtifactDigest},
		{"profile_digest", r.ProfileDigest},
		{"execution_inventory_sha256", r.ExecutionInventory},
		{"producer_attempts", strconv.Itoa(r.ProducerAttempts)},
		{"expected_batch_count", strconv.Itoa(r.ExpectedBatchCount)},
		{"producer_snapshot_sha256", r.ProducerSnapshot},
		{"anchor_provider_one_id", r.AnchorProviderOneID},
		{"anchor_provider_one_key_id", r.AnchorProviderOneKey},
		{"anchor_provider_two_id", r.AnchorProviderTwoID},
		{"anchor_provider_two_key_id", r.AnchorProviderTwoKey},
		{"anchor_known_hosts_sha256", r.AnchorKnownHostsSHA},
		{"finalizer_algorithm", r.FinalizerAlgorithm},
		{"finalizer_key_id", r.FinalizerKeyID},
	} {
		builder.WriteString(pair[0] + "=" + pair[1] + "\n")
	}
	return []byte(builder.String())
}

// verifyControllerStartRecord validates the signed ownership record.
func verifyControllerStartRecord(
	root string,
	environment map[string]string,
	complete map[string]string,
	controller map[string]string,
	pinnedFinalizerKeyID string,
) error {
	if pinnedFinalizerKeyID == "" {
		return errors.New(
			"anchored evidence requires an externally pinned audit finalizer " +
				"identity to verify the controller start record against",
		)
	}
	path := filepath.Join(root, controllerStartName)
	content, err := readBoundedRegular(path, maximumStartRecord)
	if err != nil {
		return fmt.Errorf(
			"anchored evidence requires the controller's %s: %w",
			controllerStartName, err,
		)
	}
	// Duplicate keys, rejected before Decode. encoding/json keeps the LAST
	// occurrence of a repeated key, so a record could state
	// producer_snapshot_sha256 twice — one value for a reader, another for the
	// decoder — and DisallowUnknownFields would raise nothing, because neither
	// occurrence is unknown. Same standard the checkpoint parser applies.
	if err := requireUniqueStartRecordKeys(content); err != nil {
		return fmt.Errorf("%s: %w", controllerStartName, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var record controllerStartRecord
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("%s is not decodable: %w", controllerStartName, err)
	}
	if err := requireEOF(decoder); err != nil {
		return fmt.Errorf("%s carries extra JSON: %w", controllerStartName, err)
	}
	// The verifier's acceptance criteria must mirror the controller's
	// production criteria exactly. A looser independent reimplementation would
	// accept records the controller would never emit, which is the same drift
	// problem the shared snapshot package exists to prevent.
	if err := requireCanonicalStartRecord(record); err != nil {
		return fmt.Errorf("%s: %w", controllerStartName, err)
	}

	// The pinned identity decides which key verifies this, never the record's
	// own claim about which key signed it.
	if !pqauth.EqualKeyID(record.FinalizerKeyID, pinnedFinalizerKeyID) {
		return fmt.Errorf(
			"%s is signed by finalizer %s, the auditor pinned %s",
			controllerStartName, record.FinalizerKeyID, pinnedFinalizerKeyID,
		)
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(
		record.FinalizerPublicKeyB64,
	)
	if err != nil {
		return fmt.Errorf("%s has an unusable public key", controllerStartName)
	}
	verifier, err := pqauth.NewVerifier(record.FinalizerAlgorithm, publicKey)
	if err != nil {
		return fmt.Errorf("%s finalizer key is unusable: %w", controllerStartName, err)
	}
	if !pqauth.EqualKeyID(verifier.KeyID(), pinnedFinalizerKeyID) {
		return fmt.Errorf(
			"%s carries a public key whose identity is not the pinned one",
			controllerStartName,
		)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(record.SignatureB64)
	if err != nil {
		return fmt.Errorf("%s signature is not base64", controllerStartName)
	}
	if err := pqauth.VerifyDomainMessage(
		pqauth.ControllerStartSignatureDomain,
		record.signingMessage(), signature, verifier,
	); err != nil {
		return fmt.Errorf(
			"%s is not validly signed, so it establishes no ownership: %w",
			controllerStartName, err,
		)
	}

	// The bindings must describe the matrix in front of the auditor.
	for _, item := range []struct {
		label  string
		record string
		state  string
	}{
		{"matrix_id", record.MatrixID, controller["matrix_id"]},
		{"source_digest", record.SourceDigest, controller["source_digest"]},
		{
			"anchor_provider_one_id",
			record.AnchorProviderOneID, controller["anchor_provider_one_id"],
		},
		{
			"anchor_provider_one_key_id",
			record.AnchorProviderOneKey, controller["anchor_provider_one_key_id"],
		},
		{
			"anchor_provider_two_id",
			record.AnchorProviderTwoID, controller["anchor_provider_two_id"],
		},
		{
			"anchor_provider_two_key_id",
			record.AnchorProviderTwoKey, controller["anchor_provider_two_key_id"],
		},
		{
			"anchor_known_hosts_sha256",
			record.AnchorKnownHostsSHA, controller["anchor_known_hosts_sha256"],
		},
		{
			"finalizer_key_id",
			record.FinalizerKeyID, controller["finalizer_key_id"],
		},
	} {
		if item.record != item.state {
			return fmt.Errorf(
				"%s binds %s=%q, the controller state records %q",
				controllerStartName, item.label, item.record, item.state,
			)
		}
	}
	if strconv.Itoa(record.ExpectedBatchCount) !=
		controller["expected_batch_count"] {
		return fmt.Errorf(
			"%s expects %d batches, the controller state records %q",
			controllerStartName, record.ExpectedBatchCount,
			controller["expected_batch_count"],
		)
	}
	// EVERY signed field, bound to the matrix actually in front of the auditor.
	//
	// Verifying the signature alone proves the finalizer signed something. It
	// does not prove that what it signed describes THIS matrix — so a validly
	// signed but entirely false ownership record verified cleanly. Every field
	// the record commits to is therefore re-derived from the evidence and
	// required to match.
	for _, item := range []struct {
		label  string
		record string
		actual string
	}{
		{"schedule_sha256", record.ScheduleDigest, environment["schedule_sha256"]},
		{
			"auto_artifact_sha256",
			record.AutoArtifactDigest, environment["auto_artifact_sha256"],
		},
		{"profile_sha256", record.ProfileDigest, environment["profile_sha256"]},
		{
			"execution_inventory_sha256",
			record.ExecutionInventory, environment["execution_inventory_sha256"],
		},
	} {
		if item.record != item.actual {
			return fmt.Errorf(
				"%s binds %s=%q, the matrix records %q; the signed ownership "+
					"record does not describe this matrix",
				controllerStartName, item.label, item.record, item.actual,
			)
		}
	}
	if strconv.Itoa(record.ProducerAttempts) != complete["attempts"] {
		return fmt.Errorf(
			"%s binds producer_attempts=%d, the completion record states %q",
			controllerStartName, record.ProducerAttempts, complete["attempts"],
		)
	}

	// The producer snapshot, recomputed with the SAME implementation the
	// controller used to produce it. Not a second implementation of the same
	// algorithm: two independently maintained copies of one digest do not stay
	// identical, and the first divergence either rejects honest evidence or
	// accepts a record computed under different rules while reporting agreement.
	snapshot, err := producersnapshot.Digest(root)
	if err != nil {
		return fmt.Errorf(
			"%s cannot be checked because the producer state cannot be "+
				"re-measured: %w", controllerStartName, err,
		)
	}
	if snapshot != record.ProducerSnapshot {
		return fmt.Errorf(
			"%s binds producer snapshot %s, the evidence on disk hashes to %s; "+
				"the signed record describes a different producer state",
			controllerStartName, record.ProducerSnapshot, snapshot,
		)
	}

	// The frozen trust files the auditor can see must be the ones the record
	// committed to.
	anchorRoot := filepath.Join(root, "anchors")
	knownHosts, err := sha256File(filepath.Join(anchorRoot, "known_hosts"))
	if err != nil {
		return err
	}
	if knownHosts != record.AnchorKnownHostsSHA {
		return fmt.Errorf(
			"%s binds anchor host keys %s, the archived file hashes to %s",
			controllerStartName, record.AnchorKnownHostsSHA, knownHosts,
		)
	}
	return nil
}

// requireCanonicalStartRecord applies the controller's own production
// invariants: canonical schema and algorithm, safe identifiers, lower-hex
// digests, and positive counts.
func requireCanonicalStartRecord(record controllerStartRecord) error {
	if record.Schema != controllerStartSchema {
		return fmt.Errorf(
			"declares schema %q, want %q", record.Schema, controllerStartSchema,
		)
	}
	if record.FinalizerAlgorithm != auditcheckpoint.FinalizerAlgorithm {
		return fmt.Errorf(
			"declares finalizer algorithm %q, want %q",
			record.FinalizerAlgorithm, auditcheckpoint.FinalizerAlgorithm,
		)
	}
	for label, value := range map[string]string{
		"matrix_id":              record.MatrixID,
		"anchor_provider_one_id": record.AnchorProviderOneID,
		"anchor_provider_two_id": record.AnchorProviderTwoID,
	} {
		if !safeStartIdentifier.MatchString(value) {
			return fmt.Errorf("%s %q is not a safe identifier", label, value)
		}
	}
	for label, value := range map[string]string{
		"source_digest":              record.SourceDigest,
		"schedule_digest":            record.ScheduleDigest,
		"auto_artifact_digest":       record.AutoArtifactDigest,
		"profile_digest":             record.ProfileDigest,
		"execution_inventory_sha256": record.ExecutionInventory,
		"producer_snapshot_sha256":   record.ProducerSnapshot,
		"anchor_provider_one_key_id": record.AnchorProviderOneKey,
		"anchor_provider_two_key_id": record.AnchorProviderTwoKey,
		"anchor_known_hosts_sha256":  record.AnchorKnownHostsSHA,
		"finalizer_key_id":           record.FinalizerKeyID,
	} {
		if !lowerHex(value, sha256.Size*2) {
			return fmt.Errorf(
				"%s is not 64 lower-hex characters", label,
			)
		}
	}
	if record.ExpectedBatchCount <= 0 {
		return errors.New("expects no batches")
	}
	if record.ProducerAttempts <= 0 {
		return errors.New("expects no attempts")
	}
	return nil
}

// requireUniqueStartRecordKeys rejects a document containing a repeated object
// key.
func requireUniqueStartRecordKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON is nested too deeply")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON has a non-string key")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf(
						"JSON repeats the key %q; a document that states one "+
							"field twice states nothing", key,
					)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		}
		if _, err := decoder.Token(); err != nil {
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	return requireEOF(decoder)
}

// safeStartIdentifier mirrors the controller's own identifier rule EXACTLY.
//
// It was {1,256} while the controller's signingMessage enforces {1,128}, so the
// verifier accepted signed records the controller could never emit — and, worse,
// could never resume: a 200-character matrix id would pass the auditor and then
// be refused by the very tool that supposedly produced it. A verifier whose
// acceptance criteria are looser than production's is not verifying production.
//
// The bound is duplicated rather than imported because this command must not
// depend on the controller command; the two have to be edited together, which is
// the same rule applied to the carrier schema token and the anchor artifact
// names.
var safeStartIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
