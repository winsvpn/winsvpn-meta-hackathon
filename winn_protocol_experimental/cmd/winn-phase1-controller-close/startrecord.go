package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// The controller start record.
//
// WHY IT IS SIGNED.
//
// A resumed transition legitimately owns <root>/anchors, and a first run
// legitimately must not have one — so something has to distinguish "this
// controller was here before" from "the producing host anchored something",
// and the whole zero-producer-anchor proof rests on getting that right.
//
// An unsigned marker cannot do it. Its presence establishes only that
// something able to write a file wrote one, which is exactly what an adversary
// with write access to the matrix root has. Trusting it would let a forged
// marker unlock the resume path, and the resume path is the one that accepts
// pre-existing anchor state.
//
// So ownership is established by a record signed with the controller's
// finalizer key — the same ML-DSA credential the producing host provably does
// not hold, under its own domain so a checkpoint signature cannot be replayed
// as a start record. On every run the record is verified before anything is
// trusted, and a record that fails verification is a hard refusal rather than a
// fallback to the first-run path: a matrix carrying an unverifiable ownership
// claim is not a matrix anyone should continue.
//
// ORDERING. The record is published BEFORE any anchor directory exists. A crash
// after it and before the anchor root is created leaves a valid, verifiable
// ownership claim and no anchors, which the resume path handles; the reverse
// order would leave anchors with no claim, and every retry would read that as a
// producer violation and refuse forever.
const controllerStartName = "CONTROLLER_START"

const controllerStartSchema = "winn-phase1-controller-start/v1"

const maximumStartRecord = 64 << 10

// requireUniqueJSONKeys rejects a document containing a repeated object key.
func requireUniqueJSONKeys(data []byte) error {
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
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("extra JSON value")
		}
		return err
	}
	return nil
}

type controllerStart struct {
	Schema             string `json:"schema"`
	MatrixID           string `json:"matrix_id"`
	SourceDigest       string `json:"source_digest"`
	ScheduleDigest     string `json:"schedule_digest"`
	AutoArtifactDigest string `json:"auto_artifact_digest"`
	ProfileDigest      string `json:"profile_digest"`
	ExecutionInventory string `json:"execution_inventory_sha256"`
	ProducerAttempts   int    `json:"producer_attempts"`
	ExpectedBatchCount int    `json:"expected_batch_count"`
	// ProducerSnapshot is a digest over the exact producer files this
	// transition acts on. See producerSnapshotDigest.
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

// signingMessage renders the canonical, order-fixed message the finalizer
// signs. Every component is charset-restricted before it is written, so no
// value can forge a field boundary.
func (r controllerStart) signingMessage() ([]byte, error) {
	if r.Schema != controllerStartSchema {
		return nil, fmt.Errorf(
			"controller start record declares schema %q, want %q",
			r.Schema, controllerStartSchema,
		)
	}
	if !safeIdentifier.MatchString(r.MatrixID) ||
		!safeIdentifier.MatchString(r.AnchorProviderOneID) ||
		!safeIdentifier.MatchString(r.AnchorProviderTwoID) {
		return nil, errors.New("controller start record has an unsafe identifier")
	}
	for label, value := range map[string]string{
		"source_digest":              r.SourceDigest,
		"schedule_digest":            r.ScheduleDigest,
		"auto_artifact_digest":       r.AutoArtifactDigest,
		"profile_digest":             r.ProfileDigest,
		"execution_inventory_sha256": r.ExecutionInventory,
		"producer_snapshot_sha256":   r.ProducerSnapshot,
		"anchor_provider_one_key_id": r.AnchorProviderOneKey,
		"anchor_provider_two_key_id": r.AnchorProviderTwoKey,
		"anchor_known_hosts_sha256":  r.AnchorKnownHostsSHA,
		"finalizer_key_id":           r.FinalizerKeyID,
	} {
		if !lowerHex(value) {
			return nil, fmt.Errorf(
				"controller start record %s is not 64 lower-hex characters", label,
			)
		}
	}
	if r.FinalizerAlgorithm != auditcheckpoint.FinalizerAlgorithm {
		return nil, errors.New("controller start record names a foreign algorithm")
	}
	if r.ExpectedBatchCount <= 0 {
		return nil, errors.New("controller start record expects no batches")
	}
	if r.ProducerAttempts <= 0 {
		return nil, errors.New("controller start record expects no attempts")
	}
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
	return []byte(builder.String()), nil
}

// loadControllerStart reads and cryptographically verifies an existing start
// record.
//
// Three outcomes, and they are deliberately different:
//
//	(nil, nil)    no record: this is a first run
//	(record, nil) a record signed by the pinned finalizer: this is a resume
//	(nil, error)  a record that does not verify: a hard refusal
//
// The third case never degrades to the first. A matrix carrying an ownership
// claim nobody can verify is not one to continue, and treating it as "no
// record" would hand the forger the first-run path.
func (c *Controller) loadControllerStart(
	signer *pqauth.Signer,
) (*controllerStart, error) {
	path := filepath.Join(c.MatrixRoot, controllerStartName)
	// Read hardening, to the same standard as the checkpoint parser. The
	// ownership record decides whether pre-existing anchor state is trusted, so
	// every way of feeding it something other than a plain file is closed:
	// symlinks are refused rather than followed, non-regular files are refused,
	// and an oversized file is refused outright rather than read as its own
	// prefix.
	// One hardened, same-descriptor read. The previous Lstat-then-ReadFile pair
	// inspected one file and read another: between the two calls the name can
	// be repointed at a symlink, a device, or a different regular file, so
	// every property established by the inspection described something the
	// decoder never saw.
	//
	// That gap mattered more here than almost anywhere else in this package.
	// This record decides whether pre-existing anchor state is trusted, so an
	// attacker who can win that window chooses which document establishes
	// ownership. readAndHashRegular — already used in this same file for the
	// trust inputs — opens once, re-stats the descriptor, compares with
	// os.SameFile, reads bounded, and re-stats again.
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	content, _, err := producersnapshot.ReadRegular(path, maximumStartRecord, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", controllerStartName, err)
	}
	// encoding/json silently keeps the LAST occurrence of a repeated key, so a
	// record could state producer_snapshot_sha256 twice — one value for a
	// reader, another for the decoder — and DisallowUnknownFields would raise
	// nothing, because neither occurrence is unknown.
	if err := requireUniqueJSONKeys(content); err != nil {
		return nil, fmt.Errorf(
			"%s is present but undecodable, so this matrix carries an "+
				"ownership claim nobody can verify: %w",
			controllerStartName, err,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var record controllerStart
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf(
			"%s is present but undecodable, so this matrix carries an "+
				"ownership claim nobody can verify: %w", controllerStartName, err,
		)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s carries extra JSON", controllerStartName)
	}
	if !pqauth.EqualKeyID(record.FinalizerKeyID, signer.KeyID()) {
		return nil, fmt.Errorf(
			"%s claims finalizer %s, this controller holds %s; the state "+
				"belongs to a different controller",
			controllerStartName, record.FinalizerKeyID, signer.KeyID(),
		)
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(
		record.FinalizerPublicKeyB64,
	)
	if err != nil {
		return nil, errors.New("controller start record has an unusable public key")
	}
	verifier, err := pqauth.NewVerifier(
		auditcheckpoint.FinalizerAlgorithm, publicKey,
	)
	if err != nil {
		return nil, err
	}
	if !pqauth.EqualKeyID(verifier.KeyID(), record.FinalizerKeyID) {
		return nil, errors.New(
			"controller start record's key id does not match its own public key",
		)
	}
	if !pqauth.EqualKeyID(verifier.KeyID(), signer.KeyID()) {
		return nil, errors.New(
			"controller start record is signed by a foreign finalizer key",
		)
	}
	message, err := record.signingMessage()
	if err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(record.SignatureB64)
	if err != nil {
		return nil, errors.New("controller start record signature is not base64")
	}
	if err := pqauth.VerifyDomainMessage(
		pqauth.ControllerStartSignatureDomain, message, signature, verifier,
	); err != nil {
		return nil, fmt.Errorf(
			"%s is not validly signed, so it establishes no ownership at all: %w",
			controllerStartName, err,
		)
	}
	return &record, nil
}

// publishControllerStart writes the authenticated ownership claim, create-once.
// A byte-identical incumbent is an idempotent resume; a divergent one is a
// refusal, because two different ownership claims cannot both be true.
// publishControllerStart signs the snapshot the caller already measured and
// validated against the parsed state. It deliberately does NOT re-measure: a
// fresh measurement here could differ from the one the parse was validated
// against, and the record would then attest to a state this run never read.
func (c *Controller) publishControllerStart(
	state producerState,
	batches []batchRecord,
	snapshot string,
	signer *pqauth.Signer,
) (*controllerStart, error) {
	record := controllerStart{
		Schema:                controllerStartSchema,
		MatrixID:              state.matrixID,
		SourceDigest:          state.sourceDigest,
		ScheduleDigest:        state.scheduleDigest,
		AutoArtifactDigest:    state.artifactDigest,
		ProfileDigest:         state.profileDigest,
		ExecutionInventory:    state.executionInventor,
		ProducerAttempts:      state.producerAttempts,
		ProducerSnapshot:      snapshot,
		ExpectedBatchCount:    len(batches),
		AnchorProviderOneID:   c.AnchorProviderOneID,
		AnchorProviderOneKey:  c.trust.providerOneKeyID,
		AnchorProviderTwoID:   c.AnchorProviderTwoID,
		AnchorProviderTwoKey:  c.trust.providerTwoKeyID,
		AnchorKnownHostsSHA:   c.trust.knownHostsSHA,
		FinalizerAlgorithm:    auditcheckpoint.FinalizerAlgorithm,
		FinalizerKeyID:        signer.KeyID(),
		FinalizerPublicKeyB64: base64.StdEncoding.EncodeToString(signer.PublicBytes()),
	}
	message, err := record.signingMessage()
	if err != nil {
		return nil, err
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.ControllerStartSignatureDomain, message, signer,
	)
	if err != nil {
		return nil, err
	}
	record.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if err := writeCreateOnce(
		filepath.Join(c.MatrixRoot, controllerStartName), encoded,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

// requireStartAgrees checks a resumed record against this run's inputs. A
// resume that quietly adopted different provider identities or a different
// source pin would be a new transition wearing an old one's ownership.
func (c *Controller) requireStartAgrees(
	record *controllerStart,
	state producerState,
	batches []batchRecord,
) error {
	batchCount := len(batches)
	keyOne := c.trust.providerOneKeyID
	keyTwo := c.trust.providerTwoKeyID
	knownHosts := c.trust.knownHostsSHA
	switch {
	case record.MatrixID != state.matrixID:
		return errors.New("the controller start record names a different matrix")
	case record.SourceDigest != state.sourceDigest:
		return errors.New("the controller start record pins a different source")
	case record.ScheduleDigest != state.scheduleDigest:
		return errors.New("the controller start record pins a different schedule")
	case record.AutoArtifactDigest != state.artifactDigest:
		return errors.New("the controller start record pins a different Auto artifact")
	case record.ProfileDigest != state.profileDigest:
		return errors.New("the controller start record pins a different profile")
	case record.ExecutionInventory != state.executionInventor:
		return errors.New("the controller start record pins a different execution inventory")
	case record.ProducerAttempts != state.producerAttempts:
		return errors.New("the controller start record pins a different attempt total")
	case record.ExpectedBatchCount != batchCount:
		return errors.New("the controller start record expects a different batch count")
	case record.AnchorProviderOneID != c.AnchorProviderOneID,
		record.AnchorProviderTwoID != c.AnchorProviderTwoID,
		record.AnchorProviderOneKey != keyOne,
		record.AnchorProviderTwoKey != keyTwo:
		return errors.New("the controller start record pins different anchor providers")
	case record.AnchorKnownHostsSHA != knownHosts:
		return errors.New("the controller start record pins different anchor hosts")
	}
	return nil
}

// requireSnapshotStill re-measures the producer state and requires it to equal
// the digest this run signed or verified.
//
// Called immediately before the irreversible anchor step, it is what stops an
// internally consistent rewrite that lands AFTER the earlier checks from being
// checkpointed, archived, and anchored unnoticed.
func (c *Controller) requireSnapshotStill(expected string) error {
	if expected == "" {
		return errors.New("no signed producer snapshot is held")
	}
	snapshot, err := producersnapshot.Digest(c.MatrixRoot)
	if err != nil {
		return fmt.Errorf(
			"the producer state cannot be re-measured against the signed "+
				"start record: %w", err,
		)
	}
	if expected != snapshot {
		return snapshotDriftError(expected, snapshot)
	}
	return nil
}

func snapshotDriftError(expected, actual string) error {
	return fmt.Errorf(
		"the producer state changed after this transition started: the signed "+
			"start record binds snapshot %s, the files on disk hash to %s. A "+
			"valid signature over an earlier state does not authorise a later "+
			"one", expected, actual,
	)
}

// freezeAnchorRoot creates the anchor directories and the frozen provider
// identity files. It runs only after the authenticated start record exists, and
// every step is idempotent so a retry after a crash mid-freeze completes.
func (c *Controller) freezeAnchorRoot() error {
	anchorRoot := filepath.Join(c.MatrixRoot, "anchors")
	for _, directory := range []string{
		anchorRoot,
		filepath.Join(anchorRoot, "pending"),
		filepath.Join(anchorRoot, "committed"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	// The exact bytes this run read, not a re-read of the operator's paths.
	for name, content := range map[string][]byte{
		"provider-one.ed25519.pub": c.trust.providerOneKey,
		"provider-two.ed25519.pub": c.trust.providerTwoKey,
		"known_hosts":              c.trust.knownHosts,
	} {
		if err := writeCreateOnce(
			filepath.Join(anchorRoot, name), content,
		); err != nil {
			return err
		}
	}
	return nil
}

var _ = securefile.AtomicWriteNew
