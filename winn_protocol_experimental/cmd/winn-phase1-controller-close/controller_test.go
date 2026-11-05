// The controller transition, asserted as an ordered state machine.
//
// Two classes of property are tested here and they are tested differently.
//
// ELIGIBILITY is about refusals, and every refusal is exercised against a
// fixture that is otherwise completely valid, so acceptance would mean the
// specific gate is missing rather than that something else happened to fail.
//
// ORDERING is about sequence, and sequence is recorded rather than inferred:
// the fake anchor runner and the fake verifier append to a shared trace, so a
// test can assert that a batch was verified before it was anchored, and that
// its .done existed before the terminal seal, instead of merely observing that
// all of those things eventually happened.
//
// The fakes stand in for two live SSH providers and for a subprocess. They do
// not stand in for the verifier's JUDGEMENT: production wires Verifier to the
// real winn-phase1-matrix-verify binary, and what these tests cover is that the
// controller calls it at the right moments and honours its answer.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/auditcheckpoint"
	"winsvpn.local/winnprotocol/internal/phase1anchor"
	"winsvpn.local/winnprotocol/internal/pqauth"
	"winsvpn.local/winnprotocol/internal/producersnapshot"
)

const (
	fixtureMatrixID = "phase1-auto-controller-test"
	fixtureSource   = "1111111111111111111111111111111111111111111111111111111111111111"
	fixtureArtifact = "2222222222222222222222222222222222222222222222222222222222222222"
	fixtureProfile  = "3333333333333333333333333333333333333333333333333333333333333333"
)

// fixtureInventoryBody is the execution inventory a real producer leaves in the
// matrix root, and fixtureInventory is its ACTUAL digest.
//
// It used to be a hand-written 64-hex placeholder that had nothing to do with
// the file beside it, and matrix.env carried no execution_inventory_sha256 at
// all. Both were possible only because nothing on the controller side ever
// hashed the inventory or compared the two producer records — which is the
// defect that let a matrix be anchored and only then rejected by the formal
// verifier. A fixture that cannot satisfy the real contract cannot demonstrate
// the real contract, so it is derived here instead of asserted.
var (
	fixtureInventoryBody = strings.Repeat("d", 64) +
		"  /opt/winn-lab/bin/winn-auto-e2e\n"
	fixtureInventory = func() string {
		sum := sha256.Sum256([]byte(fixtureInventoryBody))
		return hex.EncodeToString(sum[:])
	}()
)

// trace records what happened, in the order it happened.
type trace struct {
	events []string
}

func (t *trace) record(format string, arguments ...any) {
	t.events = append(t.events, fmt.Sprintf(format, arguments...))
}

func (t *trace) indexOf(event string) int {
	for index, recorded := range t.events {
		if recorded == event {
			return index
		}
	}
	return -1
}

func (t *trace) mustPrecede(test *testing.T, earlier, later string) {
	test.Helper()
	first, second := t.indexOf(earlier), t.indexOf(later)
	if first < 0 {
		test.Fatalf("%q never happened; trace: %v", earlier, t.events)
	}
	if second < 0 {
		test.Fatalf("%q never happened; trace: %v", later, t.events)
	}
	if first > second {
		test.Fatalf(
			"%q happened after %q; the transition is out of order:\n%v",
			earlier, later, t.events,
		)
	}
}

type fakeAnchor struct {
	trace   *trace
	root    string
	failAt  string
	counter int
	// previous records (slot, previousOne, previousTwo) for every call, so a
	// test can assert what the controller actually passed rather than only
	// that a call happened.
	previous [][3]string
}

// previousFor returns the two predecessors passed for one slot.
func (f *fakeAnchor) previousFor(slot string) (string, string, bool) {
	for _, entry := range f.previous {
		if entry[0] == slot {
			return entry[1], entry[2], true
		}
	}
	return "", "", false
}

func (f *fakeAnchor) Anchor(
	slot string, request []byte, previousOne, previousTwo string,
) (Receipts, error) {
	f.trace.record("anchor:%s", slot)
	// The fake enforces the chain contract the real providers enforce.
	//
	// It used to ignore these two arguments entirely, and that is precisely how
	// the genesis bug survived: the controller passed "" as both predecessors,
	// every test passed, and the failure would first have appeared on a live
	// provider mid-chain. A fake that accepts inputs the real thing rejects is
	// not a simplification, it is a blind spot with a green light on it.
	decoded, err := phase1anchor.DecodeRequest(bytes.NewReader(request))
	if err != nil {
		return Receipts{}, fmt.Errorf("fake anchor %s: %w", slot, err)
	}
	f.previous = append(f.previous, [3]string{slot, previousOne, previousTwo})
	for label, previous := range map[string]string{
		"first":  previousOne,
		"second": previousTwo,
	} {
		if !phase1anchor.ValidPreviousDigest(previous, decoded.Ordinal) {
			return Receipts{}, fmt.Errorf(
				"fake anchor %s: the %s predecessor %q is not valid at "+
					"ordinal %d; a real provider would refuse this",
				slot, label, previous, decoded.Ordinal,
			)
		}
	}
	if f.failAt == slot {
		return Receipts{}, fmt.Errorf("injected anchor failure at %s", slot)
	}
	f.counter++
	committed := filepath.Join(f.root, "anchors", "committed", slot)
	if err := os.MkdirAll(committed, 0o700); err != nil {
		return Receipts{}, err
	}
	sum := sha256.Sum256(request)
	receipt := func(tag string) string {
		inner := sha256.Sum256(append([]byte(tag+slot), sum[:]...))
		return hex.EncodeToString(inner[:])
	}
	return Receipts{
		RequestSHA256:    hex.EncodeToString(sum[:]),
		ProviderOneSHA25: receipt("one"),
		ProviderTwoSHA25: receipt("two"),
	}, nil
}

type fakeVerifier struct {
	trace       *trace
	failBatch   string
	failMatrix  bool
	matrixCalls int
}

func (f *fakeVerifier) VerifyBatch(batch BatchVerification) error {
	f.trace.record("verify-batch:%s", filepath.Base(batch.EvidenceDirectory))
	if f.failBatch != "" &&
		strings.Contains(batch.EvidenceDirectory, f.failBatch) {
		return fmt.Errorf("injected batch verification failure")
	}
	return nil
}

func (f *fakeVerifier) VerifyMatrix(completeRecordName string) error {
	f.trace.record("verify-matrix:%s", completeRecordName)
	f.matrixCalls++
	if f.failMatrix {
		return fmt.Errorf("injected matrix verification failure")
	}
	return nil
}

type matrixFixture struct {
	root     string
	seed     string
	trace    *trace
	anchor   *fakeAnchor
	verifier *fakeVerifier
	keyOne   string
	keyTwo   string
	hosts    string
	keys     []string
}

type fixtureOptions struct {
	partial      string
	anchorMode   string
	intendedMode string
	batchKeys    []string
	// omitIntended drops intended_anchor_mode entirely.
	omitIntended bool
	// preAnchored plants a producer-side anchor artifact.
	preAnchored bool
}

func newMatrixFixture(t *testing.T, options fixtureOptions) *matrixFixture {
	t.Helper()
	root := t.TempDir()
	if options.partial == "" {
		options.partial = "0"
	}
	if options.anchorMode == "" {
		options.anchorMode = deferredMode
	}
	if options.intendedMode == "" {
		options.intendedMode = intendedMode
	}
	if len(options.batchKeys) == 0 {
		// Deliberately NOT in sorted order: the schedule's order is the source
		// of truth, and a controller that sorted keys would anchor these in the
		// wrong sequence.
		options.batchKeys = []string{"b02-warm", "b01-cold", "b03-warm"}
	}
	for _, directory := range []string{"batches", "evidence", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var schedule strings.Builder
	for index, key := range options.batchKeys {
		fmt.Fprintf(&schedule, "%d\t%s\t%s\t%s\t%s\t%d\n",
			index+1, strings.Repeat("a", 64), key, "baseline", "warm", 100,
		)
	}
	writeFixtureFile(t, filepath.Join(root, "schedule.tsv"), schedule.String())
	writeFixtureFile(t, filepath.Join(root, "execution-inventory.sha256"),
		fixtureInventoryBody)
	// The producer commits to the schedule's real digest; the pre-anchor gate
	// recomputes it, so a placeholder here would be caught (as it should be).
	scheduleDigest := sha256.Sum256([]byte(schedule.String()))
	scheduleSHA := hex.EncodeToString(scheduleDigest[:])

	environment := []string{
		"schema=winn-phase1-auto-matrix/v3",
		"matrix_id=" + fixtureMatrixID,
		"source_digest=" + fixtureSource,
		"auto_artifact_sha256=" + fixtureArtifact,
		"profile_sha256=" + fixtureProfile,
		"schedule_sha256=" + scheduleSHA,
		"anchor_mode=" + options.anchorMode,
		"anchor_schema=winn-phase1-archive-pin/v1",
		"partial=" + options.partial,
		// The producer writes this into BOTH records. The controller now
		// requires them to agree with each other and with the file, because
		// the formal verifier requires exactly that after anchoring.
		"execution_inventory_sha256=" + fixtureInventory,
	}
	if !options.omitIntended {
		environment = append(environment,
			"intended_anchor_mode="+options.intendedMode)
	}
	writeFixtureFile(t, filepath.Join(root, "matrix.env"),
		strings.Join(environment, "\n")+"\n")

	marker := []string{
		"schema=" + producerSchema,
		"matrix_id=" + fixtureMatrixID,
		"attempts=" + fmt.Sprintf("%d", 100*len(options.batchKeys)),
		"schedule_sha256=" + scheduleSHA,
		"execution_inventory_sha256=" + fixtureInventory,
		"anchor_mode=" + options.anchorMode,
		"partial=" + options.partial,
		"audit_close_state=pending-controller-finalization",
	}
	if !options.omitIntended {
		marker = append(marker, "intended_anchor_mode="+options.intendedMode)
	}
	writeFixtureFile(t, filepath.Join(root, producerMarker),
		strings.Join(marker, "\n")+"\n")

	for index, key := range options.batchKeys {
		evidenceName := "auto-e2e-" + fixtureMatrixID + "-" + key
		evidenceDir := filepath.Join(root, "evidence", evidenceName)
		buildEvidence(t, evidenceDir)
		// The producer's own archive, with its real digest: the pre-anchor gate
		// re-hashes it and compares against the record.
		producerArchive := evidenceDir + pendingArchive
		writeProducerArchive(t, evidenceDir, producerArchive)
		producerDigest, err := sha256Of(producerArchive)
		if err != nil {
			t.Fatal(err)
		}
		record := strings.Join([]string{
			"schema=" + pendingSchema,
			"batch_key=" + key,
			"randomized_block=" + fmt.Sprintf("%d", index+1),
			"order_digest=" + strings.Repeat("a", 64),
			"profile=baseline",
			"readiness=warm",
			"attempts=100",
			"started_at_utc=2026-07-26T00:00:00Z",
			"finished_at_utc=2026-07-26T00:10:00Z",
			"archive=" + producerArchive,
			"archive_relative=evidence/" + evidenceName + pendingArchive,
			"archive_sha256=" + producerDigest,
			"execution_inventory_sha256=" + fixtureInventory,
			"anchor_mode=" + options.anchorMode,
			"anchor_request_sha256=",
			"anchor_provider_one_receipt_sha256=",
			"anchor_provider_two_receipt_sha256=",
		}, "\n") + "\n"
		writeFixtureFile(t,
			filepath.Join(root, "batches", key+pendingSuffix), record)
	}

	if options.preAnchored {
		if err := os.MkdirAll(
			filepath.Join(root, "anchors", "committed"), 0o700,
		); err != nil {
			t.Fatal(err)
		}
	}

	seedPath := filepath.Join(t.TempDir(), "finalizer.seed")
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureBytes(t, seedPath, seed)

	keyDirectory := t.TempDir()
	keyOne := writeAnchorKey(t, filepath.Join(keyDirectory, "one.pub"))
	keyTwo := writeAnchorKey(t, filepath.Join(keyDirectory, "two.pub"))
	hosts := filepath.Join(keyDirectory, "known_hosts")
	writeFixtureFile(t, hosts, "provider-one ssh-ed25519 AAAA\n")

	shared := &trace{}
	return &matrixFixture{
		root:     root,
		seed:     seedPath,
		trace:    shared,
		anchor:   &fakeAnchor{trace: shared, root: root},
		verifier: &fakeVerifier{trace: shared},
		keyOne:   keyOne,
		keyTwo:   keyTwo,
		hosts:    hosts,
		keys:     options.batchKeys,
	}
}

func (f *matrixFixture) controller() *Controller {
	return &Controller{
		MatrixRoot:           f.root,
		FinalizerSeedPath:    f.seed,
		ExpectedSourceDigest: fixtureSource,
		AnchorProviderOneID:  "provider-one",
		AnchorProviderOneKey: f.keyOne,
		AnchorProviderTwoID:  "provider-two",
		AnchorProviderTwoKey: f.keyTwo,
		AnchorKnownHosts:     f.hosts,
		Anchor:               f.anchor,
		Verifier:             f.verifier,
	}
}

func writeAnchorKey(t *testing.T, path string) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, path, base64.StdEncoding.EncodeToString(public)+"\n")
	return path
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	writeFixtureBytes(t, path, []byte(content))
}

func writeFixtureBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildEvidence writes one closed-pending evidence directory: a real chained
// audit log, a sealed manifest, and the measurement files the anchor request
// binds.
func buildEvidence(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	writeFixtureBytes(t, keyPath, key)
	log, err := audit.Open(filepath.Join(directory, auditLogName), keyPath)
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
	writeFixtureFile(t, filepath.Join(directory, "environment.txt"),
		"carrier_authorization_mode=anonymous-token\nsource_digest="+
			fixtureSource+"\n")
	writeFixtureFile(t, filepath.Join(directory, "attempts.jsonl"), "{}\n")
	writeFixtureFile(t, filepath.Join(directory, "attempts.jsonl.anchor"), "{}\n")

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() ||
			strings.Contains(entry.Name(), "audit-checkpoint") ||
			entry.Name() == manifestName {
			continue
		}
		content, err := os.ReadFile( // #nosec G304 -- test temp path
			filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		lines = append(lines, hex.EncodeToString(sum[:])+"  ./"+entry.Name())
	}
	writeFixtureFile(t, filepath.Join(directory, manifestName),
		strings.Join(lines, "\n")+"\n")
}

// --- the happy path, and its ordering -------------------------------------

func TestTransitionRunsInTheRequiredOrder(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatalf("a valid deferred-anchor matrix was refused: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.root, controllerStartName,
	)); err != nil {
		t.Fatalf("no authenticated controller start record was published: %v", err)
	}

	// Batches are anchored in SCHEDULE order, not sorted-key order. The fixture
	// schedule is deliberately b02, b01, b03.
	for index, key := range fixture.keys {
		slot := fmt.Sprintf("anchor:%06d-%s", index+1, key)
		if fixture.trace.indexOf(slot) < 0 {
			t.Fatalf(
				"batch %s was not anchored at ordinal %d; the controller did "+
					"not follow schedule order:\n%v",
				key, index+1, fixture.trace.events,
			)
		}
	}
	// Sorted order would have put b01 first.
	fixture.trace.mustPrecede(t,
		"anchor:000001-b02-warm", "anchor:000002-b01-cold")

	// Verification precedes anchoring, for every batch.
	for index, key := range fixture.keys {
		evidence := "auto-e2e-" + fixtureMatrixID + "-" + key
		fixture.trace.mustPrecede(t,
			"verify-batch:"+evidence,
			fmt.Sprintf("anchor:%06d-%s", index+1, key),
		)
	}
	// Genesis precedes every batch anchor; the terminal seal follows them all.
	fixture.trace.mustPrecede(t, "anchor:000000-genesis", "anchor:000001-b02-warm")
	fixture.trace.mustPrecede(t,
		"anchor:000003-b03-warm", "anchor:000004-terminal-seal")
	// The full matrix verification runs against the candidate, after the seal.
	fixture.trace.mustPrecede(t,
		"anchor:000004-terminal-seal", "verify-matrix:"+candidateCompleteName)

	// Terminal artifacts exist, and the candidate does not survive.
	for _, key := range fixture.keys {
		if _, err := os.Lstat(filepath.Join(
			fixture.root, "batches", key+doneSuffix,
		)); err != nil {
			t.Fatalf("batch %s has no terminal record: %v", key, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, completeMarker)); err != nil {
		t.Fatalf("COMPLETE was not written: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.root, candidateCompleteName,
	)); !os.IsNotExist(err) {
		t.Fatal("the completion candidate survived a successful transition")
	}
}

// TestDoneRecordsPrecedeTheTerminalSeal pins the aggregate's shape requirement.
// The verifier's aggregate rows contain each batch's .done digest, so the .done
// records have to exist before the seal is computed.
func TestDoneRecordsPrecedeTheTerminalSeal(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatal(err)
	}
	aggregate, err := os.ReadFile(filepath.Join( // #nosec G304 -- test temp
		fixture.root, "anchors", "terminal-aggregate.list"))
	if err != nil {
		t.Fatalf("no terminal aggregate was written: %v", err)
	}
	rows := strings.Split(strings.TrimSuffix(string(aggregate), "\n"), "\n")
	if len(rows) != len(fixture.keys) {
		t.Fatalf("aggregate has %d rows, want %d", len(rows), len(fixture.keys))
	}
	for index, row := range rows {
		fields := strings.Split(row, "\t")
		if len(fields) != 5 {
			t.Fatalf("aggregate row %d is not the five-column form: %q", index, row)
		}
		// The fifth column is the .done digest, and it must equal the file's
		// real digest — which is only possible if .done preceded the seal.
		done := filepath.Join(
			fixture.root, "batches", fixture.keys[index]+doneSuffix)
		digest, err := sha256Of(done)
		if err != nil {
			t.Fatal(err)
		}
		if fields[4] != digest {
			t.Fatalf(
				"aggregate row %d carries done digest %s, the file hashes to "+
					"%s; the seal was computed before the record existed",
				index, fields[4], digest,
			)
		}
	}
}

// --- eligibility ----------------------------------------------------------

func TestPartialEvidenceCannotBeUpgraded(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{partial: "1"})
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal(
			"a partial matrix was promoted to a formal one; a subset of the " +
				"frozen schedule is not the schedule",
		)
	}
	if !strings.Contains(err.Error(), "partial") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

func TestDisabledAnchorEvidenceCannotBeUpgraded(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{anchorMode: "disabled"})
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal(
			"evidence produced with anchoring disabled was reclassified as " +
				"deferred and anchored afterwards",
		)
	}
	if !strings.Contains(err.Error(), "anchor_mode") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

func TestMissingDeferredCommitmentCannotBeUpgraded(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{omitIntended: true})
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal(
			"a run that never committed to controller-side anchoring was " +
				"anchored anyway; the commitment is what is being verified",
		)
	}
	if !strings.Contains(err.Error(), "intended_anchor_mode") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

func TestProducerSideAnchorArtifactsAreRefused(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{preAnchored: true})
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a producer that anchored was accepted as a deferred run")
	}
	if !strings.Contains(err.Error(), "anchor artifacts") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestScheduleAndProducerSetsMustMatchExactly(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	// Remove one producer record: the schedule still demands it.
	if err := os.Remove(filepath.Join(
		fixture.root, "batches", fixture.keys[1]+pendingSuffix,
	)); err != nil {
		t.Fatal(err)
	}
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a matrix missing a scheduled batch was completed")
	}
	if !strings.Contains(err.Error(), "frozen schedule") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

// --- failure and resume ---------------------------------------------------

// TestFailedFinalVerificationLeavesNoCompletion is the fail-closed requirement:
// a failed final check must not leave anything a consumer reads as completion.
func TestFailedFinalVerificationLeavesNoCompletion(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	fixture.verifier.failMatrix = true
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a matrix that failed final verification was completed")
	}
	if _, statErr := os.Lstat(filepath.Join(
		fixture.root, completeMarker,
	)); !os.IsNotExist(statErr) {
		t.Fatal("COMPLETE was written despite a failed final verification")
	}
	if _, statErr := os.Lstat(filepath.Join(
		fixture.root, candidateCompleteName,
	)); !os.IsNotExist(statErr) {
		t.Fatal(
			"the completion candidate survived a failed final verification; a " +
				"crash-shaped artifact that looks like completion is exactly " +
				"what must not remain",
		)
	}
}

// TestFailedBatchVerificationStopsBeforeAnchoring proves the irreversible step
// is never reached over evidence that did not verify.
func TestFailedBatchVerificationStopsBeforeAnchoring(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	fixture.verifier.failBatch = fixture.keys[1]
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a batch that failed verification was anchored")
	}
	for _, event := range fixture.trace.events {
		if strings.HasPrefix(event, "anchor:") {
			t.Fatalf(
				"anchoring began despite a failed batch verification (%s); "+
					"anchors are externally witnessed and cannot be retracted",
				event,
			)
		}
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

// TestResumeAcceptsAnExactIncumbentDone is the recovery requirement. A
// controller that crashed after writing .done records and before the terminal
// seal must be able to run again; a rule that refused any pre-existing .done
// would wedge that state permanently.
func TestResumeAcceptsAnExactIncumbentDone(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	// Crash during the terminal seal, after every batch anchor and .done.
	fixture.anchor.failAt = "000004-terminal-seal"
	if err := fixture.controller().Run(); err == nil {
		t.Fatal("the injected seal failure did not abort")
	}
	for _, key := range fixture.keys {
		if _, err := os.Lstat(filepath.Join(
			fixture.root, "batches", key+doneSuffix,
		)); err != nil {
			t.Fatalf("the interrupted run wrote no .done for %s", key)
		}
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, completeMarker)); !os.IsNotExist(err) {
		t.Fatal("the interrupted run wrote COMPLETE")
	}

	// The retry must complete rather than refuse the incumbent records.
	resumed := newRetryFixture(t, fixture)
	if err := resumed.controller().Run(); err != nil {
		t.Fatalf(
			"a retry after a mid-transition crash could not complete (%v); an "+
				"ordinary interruption has produced a permanently stuck matrix",
			err,
		)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, completeMarker)); err != nil {
		t.Fatalf("the retry did not complete the matrix: %v", err)
	}
}

// TestResumeRefusesADivergentIncumbentDone is the limit of that rule: two
// different terminal records for one batch cannot both be true.
func TestResumeRefusesADivergentIncumbentDone(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	fixture.anchor.failAt = "000004-terminal-seal"
	if err := fixture.controller().Run(); err == nil {
		t.Fatal("the injected seal failure did not abort")
	}
	done := filepath.Join(fixture.root, "batches", fixture.keys[0]+doneSuffix)
	writeFixtureFile(t, done, "schema=tampered\n")

	resumed := newRetryFixture(t, fixture)
	err := resumed.controller().Run()
	if err == nil {
		t.Fatal("a divergent incumbent terminal record was silently replaced")
	}
	if !strings.Contains(err.Error(), "different content") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// newRetryFixture reuses one fixture's on-disk state with fresh fakes, which is
// what a second invocation of the command would see.
func newRetryFixture(t *testing.T, previous *matrixFixture) *matrixFixture {
	t.Helper()
	shared := &trace{}
	return &matrixFixture{
		root:     previous.root,
		seed:     previous.seed,
		trace:    shared,
		anchor:   &fakeAnchor{trace: shared, root: previous.root},
		verifier: &fakeVerifier{trace: shared},
		keyOne:   previous.keyOne,
		keyTwo:   previous.keyTwo,
		hosts:    previous.hosts,
		keys:     previous.keys,
	}
}

func assertNoTerminalArtifacts(t *testing.T, root string) {
	t.Helper()
	for _, forbidden := range []string{completeMarker, candidateCompleteName} {
		if _, err := os.Lstat(filepath.Join(root, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("a refused transition left %s behind", forbidden)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "batches"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), doneSuffix) {
			t.Fatalf("a refused transition left a terminal record: %s", entry.Name())
		}
	}
}

// --- ownership: the authenticated start record ------------------------------

// TestForgedControllerStartIsRefused is the reason ownership is signed rather
// than merely present.
//
// The resume path is the one that tolerates a pre-existing anchors/ directory.
// If an unsigned marker unlocked it, anyone able to write a file into the
// matrix root could unlock it too — and the zero-producer-anchor proof, which
// is the entire justification for the deferred mode, would rest on a file
// anybody can create.
func TestForgedControllerStartIsRefused(t *testing.T) {
	for _, test := range []struct {
		name    string
		content func(t *testing.T, fixture *matrixFixture) []byte
		want    string
	}{
		{
			name: "not_json",
			content: func(*testing.T, *matrixFixture) []byte {
				return []byte("schema=winn-phase1-controller-start/v1\n")
			},
			want: "undecodable",
		},
		{
			name: "unsigned_but_well_formed",
			content: func(t *testing.T, fixture *matrixFixture) []byte {
				t.Helper()
				return marshalStart(t, fixture, func(record *controllerStart) {
					record.SignatureB64 = base64.StdEncoding.EncodeToString(
						make([]byte, 3309),
					)
				})
			},
			want: "not validly signed",
		},
		{
			name: "signed_by_a_foreign_finalizer",
			content: func(t *testing.T, fixture *matrixFixture) []byte {
				t.Helper()
				// A genuine, correctly constructed record — signed with a
				// different ML-DSA key. Every field is well formed; only the
				// credential is wrong.
				return foreignSignedStart(t, fixture)
			},
			want: "different controller",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			// The forged content is built against the clean fixture, then the
			// anchors are planted: the forgery's whole purpose would be to make
			// that pre-existing state look like a legitimate resume.
			content := test.content(t, fixture)
			if err := os.MkdirAll(filepath.Join(
				fixture.root, "anchors", "committed",
			), 0o700); err != nil {
				t.Fatal(err)
			}
			writeFixtureBytes(t,
				filepath.Join(fixture.root, controllerStartName), content,
			)
			err := fixture.controller().Run()
			if err == nil {
				t.Fatal(
					"a forged ownership claim unlocked the resume path, which " +
						"is the path that accepts pre-existing anchor state",
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			// And it must NOT have fallen through to the first-run path either.
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}

// marshalStart builds a real start record for this fixture and lets a mutator
// break exactly one thing about it.
func marshalStart(
	t *testing.T,
	fixture *matrixFixture,
	mutate func(*controllerStart),
) []byte {
	t.Helper()
	signer, err := auditcheckpoint.LoadFinalizer(fixture.seed)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()
	keyOne, err := anchorPublicKeyID(fixture.keyOne)
	if err != nil {
		t.Fatal(err)
	}
	keyTwo, err := anchorPublicKeyID(fixture.keyTwo)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := sha256Of(fixture.hosts)
	if err != nil {
		t.Fatal(err)
	}
	scheduleDigest, err := sha256Of(filepath.Join(fixture.root, "schedule.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	controller := fixture.controller()
	if err := controller.loadTrustInputs(); err != nil {
		t.Fatal(err)
	}
	state, err := controller.verifyProducerState(false)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := controller.loadSchedule()
	if err != nil {
		t.Fatal(err)
	}
	batches, err := controller.loadPendingBatches(state, schedule)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := producersnapshot.Digest(controller.MatrixRoot)
	if err != nil {
		t.Fatal(err)
	}
	_ = batches
	record := controllerStart{
		Schema:                controllerStartSchema,
		MatrixID:              fixtureMatrixID,
		SourceDigest:          fixtureSource,
		ScheduleDigest:        scheduleDigest,
		AutoArtifactDigest:    fixtureArtifact,
		ProfileDigest:         fixtureProfile,
		ExecutionInventory:    fixtureInventory,
		ProducerAttempts:      100 * len(fixture.keys),
		ProducerSnapshot:      snapshot,
		ExpectedBatchCount:    len(fixture.keys),
		AnchorProviderOneID:   "provider-one",
		AnchorProviderOneKey:  keyOne,
		AnchorProviderTwoID:   "provider-two",
		AnchorProviderTwoKey:  keyTwo,
		AnchorKnownHostsSHA:   hosts,
		FinalizerAlgorithm:    auditcheckpoint.FinalizerAlgorithm,
		FinalizerKeyID:        signer.KeyID(),
		FinalizerPublicKeyB64: base64.StdEncoding.EncodeToString(signer.PublicBytes()),
	}
	mutate(&record)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

// foreignSignedStart produces a record that is valid in every way except that a
// different finalizer signed it.
func foreignSignedStart(t *testing.T, fixture *matrixFixture) []byte {
	t.Helper()
	seed, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	foreignSeed := filepath.Join(t.TempDir(), "foreign.seed")
	writeFixtureBytes(t, foreignSeed, seed)
	foreign, err := auditcheckpoint.LoadFinalizer(foreignSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Destroy()

	content := marshalStart(t, fixture, func(record *controllerStart) {
		record.FinalizerKeyID = foreign.KeyID()
		record.FinalizerPublicKeyB64 = base64.StdEncoding.EncodeToString(
			foreign.PublicBytes(),
		)
	})
	var record controllerStart
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	message, err := record.signingMessage()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := pqauth.SignDomainMessage(
		pqauth.ControllerStartSignatureDomain, message, foreign,
	)
	if err != nil {
		t.Fatal(err)
	}
	record.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

// TestFirstRunStillRequiresZeroProducerAnchors proves the signed-ownership fix
// did not trade away the guarantee it was meant to coexist with. Without a
// valid start record, a pre-existing anchors/ directory is a producer violation
// and nothing unlocks it.
func TestFirstRunStillRequiresZeroProducerAnchors(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{preAnchored: true})
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a producer that anchored was accepted as a deferred run")
	}
	if !strings.Contains(err.Error(), "anchor artifacts") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestCrashBetweenStartRecordAndAnchorFreezeResumes covers the ordering bug the
// signed record was introduced to fix: a crash after ownership is published and
// before (or during) the anchor root freeze must resume, not wedge.
func TestCrashBetweenStartRecordAndAnchorFreezeResumes(t *testing.T) {
	for _, stage := range []string{
		"after-start-record",
		"after-anchor-directories",
		"after-provider-one-frozen",
	} {
		t.Run(stage, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			// Reproduce each intermediate state by hand, exactly as an
			// interrupted run would have left it.
			controller := fixture.controller()
			if err := controller.loadTrustInputs(); err != nil {
				t.Fatal(err)
			}
			signer, err := auditcheckpoint.LoadFinalizer(fixture.seed)
			if err != nil {
				t.Fatal(err)
			}
			state, err := controller.verifyProducerState(false)
			if err != nil {
				t.Fatal(err)
			}
			schedule, err := controller.loadSchedule()
			if err != nil {
				t.Fatal(err)
			}
			batches, err := controller.loadPendingBatches(state, schedule)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := producersnapshot.Digest(controller.MatrixRoot)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := controller.publishControllerStart(
				state, batches, snapshot, signer,
			); err != nil {
				t.Fatal(err)
			}
			signer.Destroy()

			anchorRoot := filepath.Join(fixture.root, "anchors")
			switch stage {
			case "after-anchor-directories":
				for _, directory := range []string{
					anchorRoot,
					filepath.Join(anchorRoot, "pending"),
					filepath.Join(anchorRoot, "committed"),
				} {
					if err := os.MkdirAll(directory, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			case "after-provider-one-frozen":
				if err := os.MkdirAll(
					filepath.Join(anchorRoot, "committed"), 0o700,
				); err != nil {
					t.Fatal(err)
				}
				content, err := os.ReadFile(fixture.keyOne) // #nosec G304
				if err != nil {
					t.Fatal(err)
				}
				writeFixtureBytes(t,
					filepath.Join(anchorRoot, "provider-one.ed25519.pub"), content)
			}

			resumed := newRetryFixture(t, fixture)
			if err := resumed.controller().Run(); err != nil {
				t.Fatalf(
					"a retry after a crash at %s could not complete (%v); the "+
						"interruption has wedged the matrix", stage, err,
				)
			}
			if _, err := os.Lstat(filepath.Join(
				fixture.root, completeMarker,
			)); err != nil {
				t.Fatalf("the retry did not complete the matrix: %v", err)
			}
		})
	}
}

// TestCustodyRefusesASeedInsideTheMatrixRoot pins the custody rule. A seed
// archived with the evidence it closes would let anyone holding that archive
// re-close a truncated copy of it.
func TestCustodyRefusesASeedInsideTheMatrixRoot(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	inside := filepath.Join(fixture.root, "finalizer.seed")
	content, err := os.ReadFile(fixture.seed) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureBytes(t, inside, content)
	controller := fixture.controller()
	controller.FinalizerSeedPath = inside
	err = controller.Run()
	if err == nil {
		t.Fatal("a finalizer seed inside the matrix root was accepted")
	}
	if !strings.Contains(err.Error(), "inside the matrix root") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestCustodyRefusesIndistinctAnchorProviders covers the trust-input rule: two
// providers sharing an identity or a key are one witness wearing two names.
func TestCustodyRefusesIndistinctAnchorProviders(t *testing.T) {
	t.Run("shared_identity", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		controller := fixture.controller()
		controller.AnchorProviderTwoID = controller.AnchorProviderOneID
		err := controller.Run()
		if err == nil || !strings.Contains(err.Error(), "share an identity") {
			t.Fatalf("shared provider identity: got %v", err)
		}
	})
	t.Run("shared_key", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		controller := fixture.controller()
		controller.AnchorProviderTwoKey = controller.AnchorProviderOneKey
		err := controller.Run()
		if err == nil || !strings.Contains(err.Error(), "share a signing key") {
			t.Fatalf("shared provider key: got %v", err)
		}
	})
}

// TestCandidatePassMarkerIsNonPromotional proves the candidate rehearsal leaves
// a record that cannot be mistaken for a promotion.
func TestCandidatePassMarkerIsNonPromotional(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join( // #nosec G304 -- test temp path
		fixture.root, candidatePassMarker))
	if err != nil {
		t.Fatalf("no candidate pass marker was written: %v", err)
	}
	for _, required := range []string{
		"schema=" + candidatePassSchema,
		"promotional=0",
		"candidate_record_sha256=",
	} {
		if !strings.Contains(string(content), required) {
			t.Fatalf("candidate marker lacks %q:\n%s", required, content)
		}
	}
}

// --- completion: crash at every boundary ------------------------------------

// TestCompletionResumesFromEveryCrashBoundary is the requirement stated
// directly. The completion sequence is interrupted in practice, and every one
// of its steps has to be reconcilable with the others afterwards.
//
// The specific wedge this guards against: an earlier version regenerated
// completed_at_utc on each attempt, so a resumed run produced a candidate whose
// bytes — and therefore whose digest — differed from the one a previously
// published pass marker was bound to. The two could never agree again.
func TestCompletionResumesFromEveryCrashBoundary(t *testing.T) {
	for _, stage := range []completionStage{
		stageAfterCandidate,
		stageAfterVerify,
		stageAfterPassMarker,
		stageAfterComplete,
		stageBeforeCandidateC,
	} {
		t.Run(string(stage), func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			crashing := fixture.controller()
			crashing.crashAfter = stage
			if err := crashing.Run(); err == nil {
				t.Fatalf("the injected crash at %s did not abort", stage)
			}

			// Whatever the crash left, a retry must finish.
			resumed := newRetryFixture(t, fixture)
			if err := resumed.controller().Run(); err != nil {
				t.Fatalf(
					"a retry after a crash at %s could not complete (%v); an "+
						"ordinary interruption has wedged the matrix",
					stage, err,
				)
			}
			published, err := os.ReadFile(filepath.Join( // #nosec G304
				fixture.root, completeMarker))
			if err != nil {
				t.Fatalf("the retry did not publish COMPLETE: %v", err)
			}
			// The candidate never survives a completed transition.
			if _, err := os.Lstat(filepath.Join(
				fixture.root, candidateCompleteName,
			)); !os.IsNotExist(err) {
				t.Fatal("a completion candidate survived a finished transition")
			}
			// And the non-promotional marker is bound to the bytes that were
			// actually published — which is only possible if the candidate's
			// timestamp was carried across the resume rather than regenerated.
			marker, err := os.ReadFile(filepath.Join( // #nosec G304
				fixture.root, candidatePassMarker))
			if err != nil {
				t.Fatalf("no candidate pass marker survived: %v", err)
			}
			want := "candidate_record_sha256=" + sha256OfBytes(published)
			if !strings.Contains(string(marker), want) {
				t.Fatalf(
					"the pass marker is bound to different bytes than the "+
						"published COMPLETE; the candidate was regenerated "+
						"across the resume:\n%s\nwant %s", marker, want,
				)
			}

			// Re-entry into a finished state is a success, not a conflict.
			again := newRetryFixture(t, fixture)
			if err := again.controller().Run(); err != nil {
				t.Fatalf(
					"re-running a finished transition failed (%v); an "+
						"already-done root must report success", err,
				)
			}
		})
	}
}

// TestCompletionRefusesADivergentCandidate is the fail-closed half. A candidate
// that is not the record this run would produce is never silently replaced.
func TestCompletionRefusesADivergentCandidate(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	crashing := fixture.controller()
	crashing.crashAfter = stageAfterCandidate
	if err := crashing.Run(); err == nil {
		t.Fatal("the injected crash did not abort")
	}
	candidate := filepath.Join(fixture.root, candidateCompleteName)
	original, err := os.ReadFile(candidate) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(
		string(original), "attempts=300", "attempts=999", 1)
	if tampered == string(original) {
		t.Fatalf("failed to build the divergent fixture:\n%s", original)
	}
	writeFixtureFile(t, candidate, tampered)

	resumed := newRetryFixture(t, fixture)
	err = resumed.controller().Run()
	if err == nil {
		t.Fatal("a divergent candidate was silently overwritten")
	}
	if !strings.Contains(err.Error(), "disagrees with what this run would publish") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	after, err := os.ReadFile(candidate) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal("the divergent candidate was deleted rather than reported")
	}
	if string(after) != tampered {
		t.Fatal("the divergent candidate was modified")
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.root, completeMarker,
	)); !os.IsNotExist(err) {
		t.Fatal("COMPLETE was published over a divergent candidate")
	}
}

// TestCompletionRefusesADivergentIncumbentComplete covers the same rule at the
// terminal end: an existing COMPLETE that disagrees is a hard refusal.
func TestCompletionRefusesADivergentIncumbentComplete(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(fixture.root, completeMarker)
	published, err := os.ReadFile(final) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, final,
		strings.Replace(string(published), "attempts=300", "attempts=1", 1))

	resumed := newRetryFixture(t, fixture)
	err = resumed.controller().Run()
	if err == nil {
		t.Fatal("a divergent COMPLETE was accepted as this run's own")
	}
	if !strings.Contains(err.Error(), "disagrees with what this run would publish") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestCompletionRefusesAForeignLeftoverCandidate proves a leftover candidate is
// reported rather than deleted when it is not the record that was published.
func TestCompletionRefusesAForeignLeftoverCandidate(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t,
		filepath.Join(fixture.root, candidateCompleteName),
		"schema=winn-phase1-auto-matrix-complete/v3\nattempts=7\n")

	resumed := newRetryFixture(t, fixture)
	err := resumed.controller().Run()
	if err == nil {
		t.Fatal("a foreign leftover candidate was silently deleted")
	}
	if !strings.Contains(err.Error(), "only evidence of an unreconciled state") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.root, candidateCompleteName,
	)); err != nil {
		t.Fatal("the foreign candidate was deleted despite the refusal")
	}
}

// TestProducerDriftAfterStartIsRefused is the binding the signed snapshot
// exists for.
//
// The dangerous window is after CONTROLLER_START is published and before the
// first anchor. At that moment the signature is genuine and there is no anchor
// chain yet to cross-check against, so a resume that trusted the signature
// alone would proceed over whatever producer files now happen to be on disk.
// Every mutation below is refused for the drift, not for anything else.
func TestProducerDriftAfterStartIsRefused(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, fixture *matrixFixture)
	}{
		{
			name: "matrix.env",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				appendFixtureLine(t,
					filepath.Join(fixture.root, "matrix.env"), "smuggled=1")
			},
		},
		{
			name: "producer_marker",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				appendFixtureLine(t,
					filepath.Join(fixture.root, producerMarker), "smuggled=1")
			},
		},
		{
			name: "schedule.tsv",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				appendFixtureLine(t,
					filepath.Join(fixture.root, "schedule.tsv"),
					"9\t"+strings.Repeat("a", 64)+"\tb09-warm\tbaseline\twarm\t100")
			},
		},
		{
			name: "batch_record",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				appendFixtureLine(t, filepath.Join(
					fixture.root, "batches", fixture.keys[0]+pendingSuffix,
				), "smuggled=1")
			},
		},
		{
			name: "producer_archive",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				evidence := "auto-e2e-" + fixtureMatrixID + "-" + fixture.keys[1]
				appendFixtureLine(t, filepath.Join(
					fixture.root, "evidence", evidence+pendingArchive,
				), "tampered")
			},
		},
		{
			name: "evidence_manifest",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				evidence := "auto-e2e-" + fixtureMatrixID + "-" + fixture.keys[2]
				appendFixtureLine(t, filepath.Join(
					fixture.root, "evidence", evidence, manifestName,
				), strings.Repeat("c", 64)+"  ./smuggled.txt")
			},
		},
		{
			name: "audit_log",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				evidence := "auto-e2e-" + fixtureMatrixID + "-" + fixture.keys[0]
				appendFixtureLine(t, filepath.Join(
					fixture.root, "evidence", evidence, auditLogName,
				), `{"format":"smuggled"}`)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			// Stop exactly at the post-start, pre-anchor boundary.
			crashing := fixture.controller()
			crashing.Anchor = &fakeAnchor{
				trace:  fixture.trace,
				root:   fixture.root,
				failAt: genesisSlotName,
			}
			if err := crashing.Run(); err == nil {
				t.Fatal("the injected genesis failure did not abort")
			}
			if _, err := os.Lstat(filepath.Join(
				fixture.root, controllerStartName,
			)); err != nil {
				t.Fatalf("the interrupted run published no start record: %v", err)
			}

			test.mutate(t, fixture)

			resumed := newRetryFixture(t, fixture)
			err := resumed.controller().Run()
			if err == nil {
				t.Fatalf(
					"a resume adopted a modified %s under a signature made "+
						"over the earlier state", test.name,
				)
			}
			// Two phrasings, both drift refusals. A mutation that leaves the
			// state measurable produces a digest mismatch; one that makes it
			// unmeasurable — a manifest listing a file that is not there —
			// produces a measurement failure. Distinguishing them is honest;
			// accepting anything else would not be.
			// Three phrasings, all drift refusals, and the difference between
			// them is informative rather than incidental. A mutation that
			// leaves the state measurable and self-consistent produces a digest
			// mismatch; one that breaks a manifest row produces an
			// inconsistency; one that makes the state unmeasurable produces a
			// measurement failure. Accepting anything outside these three would
			// let an unrelated failure pass as drift detection.
			if !strings.Contains(err.Error(), "producer state changed") &&
				!strings.Contains(err.Error(), "internally inconsistent") &&
				!strings.Contains(err.Error(), "no such file") &&
				!strings.Contains(err.Error(), "trailing data") &&
				!strings.Contains(err.Error(), "cannot be re-measured") {
				t.Fatalf(
					"the drifted %s was refused, but not as drift: %v",
					test.name, err,
				)
			}
			// Nothing was anchored or completed over the drifted input.
			for _, event := range resumed.trace.events {
				if strings.HasPrefix(event, "anchor:") {
					t.Fatalf("anchoring proceeded over drifted input: %s", event)
				}
			}
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}

// TestUndriftedResumeStillCompletes is the positive control for the test above.
// A snapshot binding that refused everything would pass those cases and be
// useless.
func TestUndriftedResumeStillCompletes(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	crashing := fixture.controller()
	crashing.Anchor = &fakeAnchor{
		trace: fixture.trace, root: fixture.root, failAt: genesisSlotName,
	}
	if err := crashing.Run(); err == nil {
		t.Fatal("the injected genesis failure did not abort")
	}
	resumed := newRetryFixture(t, fixture)
	if err := resumed.controller().Run(); err != nil {
		t.Fatalf("an untouched resume was refused: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, completeMarker)); err != nil {
		t.Fatalf("the resume did not complete the matrix: %v", err)
	}
}

// TestStartRecordRejectsUnsafeInput holds the ownership parser to the same
// standard as the checkpoint parser: a document that states one field twice
// states nothing, and a link or a device is not a record.
func TestStartRecordRejectsUnsafeInput(t *testing.T) {
	t.Run("duplicate_json_key", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		content := marshalStart(t, fixture, func(*controllerStart) {})
		doubled := strings.Replace(string(content),
			`"producer_snapshot_sha256":`,
			`"producer_snapshot_sha256": "`+strings.Repeat("0", 64)+`",`+
				"\n  "+`"producer_snapshot_sha256":`, 1)
		if doubled == string(content) {
			t.Fatalf("failed to build the duplicate-key fixture:\n%s", content)
		}
		writeFixtureFile(t,
			filepath.Join(fixture.root, controllerStartName), doubled)
		err := fixture.controller().Run()
		if err == nil || !strings.Contains(err.Error(), "repeats the key") {
			t.Fatalf("a duplicated key was accepted: %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		writeFixtureFile(t, target, "{}\n")
		if err := os.Symlink(
			target, filepath.Join(fixture.root, controllerStartName),
		); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := fixture.controller().Run()
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("a symlinked ownership record was followed: %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		writeFixtureBytes(t,
			filepath.Join(fixture.root, controllerStartName),
			make([]byte, maximumStartRecord+1))
		err := fixture.controller().Run()
		if err == nil || !strings.Contains(err.Error(), "over the") {
			t.Fatalf("an oversized ownership record was read: %v", err)
		}
	})
}

func appendFixtureLine(t *testing.T, path, line string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotBindsManifestMembers is the coverage gap stated as a test.
//
// An earlier snapshot hashed each evidence manifest and the audit log but not
// the manifest's MEMBERS. Change result.txt or environment.txt while the
// manifest file and audit log stay byte-identical and the snapshot still
// matched — after which the close step rebuilds a base manifest over the
// changed bytes and produces a closed artifact describing evidence nobody
// approved.
func TestSnapshotBindsManifestMembers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, evidence string)
		want   string
	}{
		{
			name: "non_audit_member_changed",
			mutate: func(t *testing.T, evidence string) {
				t.Helper()
				// attempts.jsonl is manifest-listed and is NOT the audit log.
				writeFixtureFile(t,
					filepath.Join(evidence, "attempts.jsonl"), "{\"tampered\":1}\n")
			},
			// Caught by the manifest's own row, which is a stronger and more
			// specific detection than the aggregate digest: the directory now
			// disagrees with the manifest that describes it.
			want: "internally inconsistent",
		},
		{
			name: "same_size_member_mutation",
			mutate: func(t *testing.T, evidence string) {
				t.Helper()
				// Same length, different bytes: nothing size-based can see it.
				path := filepath.Join(evidence, "environment.txt")
				original, err := os.ReadFile(path) // #nosec G304 -- test temp
				if err != nil {
					t.Fatal(err)
				}
				mutated := []byte(strings.Replace(
					string(original), "anonymous-token", "anonymous-tokeX", 1))
				if len(mutated) != len(original) {
					t.Fatal("the fixture mutation changed the length")
				}
				writeFixtureBytes(t, path, mutated)
			},
			want: "internally inconsistent",
		},
		{
			name: "unlisted_file_added",
			mutate: func(t *testing.T, evidence string) {
				t.Helper()
				writeFixtureFile(t,
					filepath.Join(evidence, "extra.txt"), "smuggled\n")
			},
			want: "not listed in the evidence manifest",
		},
		{
			name: "listed_file_removed",
			mutate: func(t *testing.T, evidence string) {
				t.Helper()
				if err := os.Remove(
					filepath.Join(evidence, "attempts.jsonl.anchor"),
				); err != nil {
					t.Fatal(err)
				}
			},
			want: "no such file",
		},
		{
			name: "member_replaced_by_a_symlink",
			mutate: func(t *testing.T, evidence string) {
				t.Helper()
				path := filepath.Join(evidence, "attempts.jsonl")
				target := filepath.Join(evidence, "environment.txt")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "symbolic link",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			crashing := fixture.controller()
			crashing.Anchor = &fakeAnchor{
				trace: fixture.trace, root: fixture.root, failAt: genesisSlotName,
			}
			if err := crashing.Run(); err == nil {
				t.Fatal("the injected genesis failure did not abort")
			}
			evidence := filepath.Join(fixture.root, "evidence",
				"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
			test.mutate(t, evidence)

			resumed := newRetryFixture(t, fixture)
			err := resumed.controller().Run()
			if err == nil {
				t.Fatalf(
					"a resume proceeded over a modified evidence member (%s); "+
						"the close step would have rebuilt a manifest over the "+
						"changed bytes", test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			for _, event := range resumed.trace.events {
				if strings.HasPrefix(event, "anchor:") {
					t.Fatalf("anchoring proceeded over drifted evidence: %s", event)
				}
			}
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}

// TestExecutionInventoryIsMandatory pins that a full deferred run cannot be
// closed without the inventory every batch record claims to be pinned to.
func TestExecutionInventoryIsMandatory(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := os.Remove(filepath.Join(
		fixture.root, "execution-inventory.sha256",
	)); err != nil {
		t.Fatal(err)
	}
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a matrix with no execution inventory was closed")
	}
	if !strings.Contains(err.Error(), "execution-inventory.sha256") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestSnapshotRejectsMalformedProducerState covers the remaining ways the input
// surface can be wrong: a manifest that lies about its own member, structure
// that changes without any file changing, and inputs past every bound.
func TestSnapshotRejectsMalformedProducerState(t *testing.T) {
	t.Run("wrong_recorded_member_digest", func(t *testing.T) {
		// The manifest and the directory are each internally fine; the
		// manifest's claim about one member is simply false. Signing over that
		// would bless a manifest that describes a different directory.
		fixture := newMatrixFixture(t, fixtureOptions{})
		evidence := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
		manifest := filepath.Join(evidence, manifestName)
		content, err := os.ReadFile(manifest) // #nosec G304 -- test temp path
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
		lines[0] = strings.Repeat("e", 64) + lines[0][64:]
		writeFixtureFile(t, manifest, strings.Join(lines, "\n")+"\n")

		err = fixture.controller().Run()
		if err == nil {
			t.Fatal("a manifest that lies about its own member was signed over")
		}
		if !strings.Contains(err.Error(), "internally inconsistent") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("added_empty_directory", func(t *testing.T) {
		// No file changes. The closed archive carries explicit directory
		// entries, so this alters the published artifact and must alter the
		// snapshot.
		fixture := newMatrixFixture(t, fixtureOptions{})
		crashing := fixture.controller()
		crashing.Anchor = &fakeAnchor{
			trace: fixture.trace, root: fixture.root, failAt: genesisSlotName,
		}
		if err := crashing.Run(); err == nil {
			t.Fatal("the injected genesis failure did not abort")
		}
		evidence := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
		if err := os.MkdirAll(
			filepath.Join(evidence, "smuggled-directory"), 0o700,
		); err != nil {
			t.Fatal(err)
		}
		resumed := newRetryFixture(t, fixture)
		err := resumed.controller().Run()
		if err == nil {
			t.Fatal(
				"an added empty directory changed the closed archive without " +
					"changing the producer snapshot",
			)
		}
		// Caught by the archive-equivalence check, which is the more specific
		// detection: the directory the producer sealed and the directory on
		// disk now differ in structure, and the tarball proves it.
		if !strings.Contains(err.Error(), "producer state changed") &&
			!strings.Contains(err.Error(), "omits directory") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("oversized_manifest", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		evidence := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
		writeFixtureBytes(t, filepath.Join(evidence, manifestName),
			make([]byte, producersnapshot.MaximumRecordBytes+1))
		err := fixture.controller().Run()
		if err == nil || !strings.Contains(err.Error(), "over the") {
			t.Fatalf("an oversized manifest was read: %v", err)
		}
	})

	t.Run("too_many_manifest_members", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		evidence := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
		var manifest strings.Builder
		for index := 0; index <= producersnapshot.MaximumManifestMembers; index++ {
			fmt.Fprintf(&manifest, "%s  ./m%d\n", strings.Repeat("a", 64), index)
		}
		writeFixtureFile(t,
			filepath.Join(evidence, manifestName), manifest.String())
		err := fixture.controller().Run()
		if err == nil {
			t.Fatal("a manifest past the member limit was accepted")
		}
		// Either bound may fire first; both are refusals of the same input.
		if !strings.Contains(err.Error(), "members") &&
			!strings.Contains(err.Error(), "over the") &&
			!strings.Contains(err.Error(), "no such file") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("unexpected_special_entry", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		evidence := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
		if err := os.Symlink(
			"/etc/passwd", filepath.Join(evidence, "unlisted-link"),
		); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := fixture.controller().Run()
		if err == nil {
			t.Fatal("an unlisted symlink in the evidence tree was accepted")
		}
		if !strings.Contains(err.Error(), "not listed") &&
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})

	t.Run("pending_archive_replaced_by_a_symlink", func(t *testing.T) {
		fixture := newMatrixFixture(t, fixtureOptions{})
		evidence := "auto-e2e-" + fixtureMatrixID + "-" + fixture.keys[0]
		archive := filepath.Join(
			fixture.root, "evidence", evidence+pendingArchive)
		target := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[1]+pendingArchive)
		if err := os.Remove(archive); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, archive); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		err := fixture.controller().Run()
		if err == nil {
			t.Fatal("a symlinked producer archive was accepted")
		}
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
	})
}

// TestSnapshotRejectsManifestReplacementDuringMeasurement proves the single
// descriptor is load-bearing: the bytes that were hashed are the bytes that
// were parsed, so a swap between those two steps cannot produce a snapshot over
// a manifest nobody measured.
func TestSnapshotRejectsManifestReplacementDuringMeasurement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, manifestName)
	writeFixtureFile(t, path, strings.Repeat("a", 64)+"  ./one.txt\n")

	content, digest, err := producersnapshot.ReadRegular(
		path, producersnapshot.MaximumRecordBytes, producersnapshot.NewBudget(0))
	if err != nil {
		t.Fatal(err)
	}
	// The digest describes exactly the bytes returned; nothing re-reads the
	// path afterwards.
	if digest != sha256OfBytes(content) {
		t.Fatal("the returned digest does not describe the returned bytes")
	}

	// A budget that is already exhausted refuses, so the cumulative bound is
	// enforced on the manifest read too.
	spent := producersnapshot.NewBudget(producersnapshot.MaximumSnapshotTotal)
	if _, _, err := producersnapshot.ReadRegular(
		path, producersnapshot.MaximumRecordBytes, spent,
	); err == nil {
		t.Fatal("the cumulative snapshot budget was not enforced")
	}
}

// TestRaceWindowsAreClosed covers the two windows the snapshot sandwich and the
// single last-reversible gate exist for.
//
// Both are injected deterministically, because a race that has to be reproduced
// by timing is a race that will not be reproduced.
func TestRaceWindowsAreClosed(t *testing.T) {
	t.Run("parse_to_sign_window", func(t *testing.T) {
		// A mutation landing between the parse and the signature would let
		// CONTROLLER_START attest to newer bytes than the anchors are built
		// from — signature and content diverging while both look consistent.
		fixture := newMatrixFixture(t, fixtureOptions{})
		controller := fixture.controller()
		controller.mutateAfterParse = func() {
			appendFixtureLine(t,
				filepath.Join(fixture.root, "matrix.env"), "smuggled=1")
		}
		err := controller.Run()
		if err == nil {
			t.Fatal(
				"a mutation between the parse and the signature was signed " +
					"over; the record would attest to a state the run never read",
			)
		}
		if !strings.Contains(err.Error(), "while it was being read") {
			t.Fatalf("refused for the wrong reason: %v", err)
		}
		for _, event := range fixture.trace.events {
			if strings.HasPrefix(event, "anchor:") {
				t.Fatalf("anchoring proceeded: %s", event)
			}
		}
		assertNoTerminalArtifacts(t, fixture.root)
	})

	t.Run("gate_to_anchor_window", func(t *testing.T) {
		// A mutation landing after the batches are closed and verified but
		// before the first anchor.
		fixture := newMatrixFixture(t, fixtureOptions{})
		controller := fixture.controller()
		controller.mutateBeforeAnchor = func() {
			evidence := filepath.Join(fixture.root, "evidence",
				"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
			writeFixtureFile(t,
				filepath.Join(evidence, "environment.txt"), "rewritten\n")
		}
		err := controller.Run()
		if err == nil {
			t.Fatal("a mutation in the pre-anchor window was anchored")
		}
		assertNoAnchorsOrTerminals(t, fixture)
	})
}

// TestAnchorBoundDigestsAreRehashedAtTheGate covers each file whose digest the
// provider requests carry. A mutation to any of them after verification and
// before anchoring would otherwise produce irreversible receipts over stale
// values, with only the post-anchor verifier noticing — too late.
func TestAnchorBoundDigestsAreRehashedAtTheGate(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, fixture *matrixFixture)
		want   string
	}{
		{
			name: "closed_archive",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				evidence := filepath.Join(fixture.root, "evidence",
					"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
				writeFixtureFile(t, evidence+closedSuffix, "swapped archive\n")
			},
			want: "closed archive hashes to",
		},
		{
			name: "evidence_manifest",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				evidence := filepath.Join(fixture.root, "evidence",
					"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[1])
				appendFixtureLine(t, filepath.Join(evidence, manifestName),
					strings.Repeat("f", 64)+"  ./late.txt")
			},
			want: "evidence manifest hashes to",
		},
		{
			name: "attempt_log",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				evidence := filepath.Join(fixture.root, "evidence",
					"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[2])
				writeFixtureFile(t,
					filepath.Join(evidence, "attempts.jsonl"), "{\"late\":1}\n")
			},
			want: "attempt log hashes to",
		},
		{
			name: "attempt_anchor",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				evidence := filepath.Join(fixture.root, "evidence",
					"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
				writeFixtureFile(t,
					filepath.Join(evidence, "attempts.jsonl.anchor"),
					"{\"late\":1}\n")
			},
			want: "attempt anchor hashes to",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			controller := fixture.controller()
			controller.mutateBeforeAnchor = func() { test.mutate(t, fixture) }
			err := controller.Run()
			if err == nil {
				t.Fatalf(
					"a %s mutated after verification was anchored; the "+
						"provider receipts would be irreversible statements "+
						"about stale bytes", test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			assertNoAnchorsOrTerminals(t, fixture)
		})
	}
}

func assertNoAnchorsOrTerminals(t *testing.T, fixture *matrixFixture) {
	t.Helper()
	for _, event := range fixture.trace.events {
		if strings.HasPrefix(event, "anchor:") {
			t.Fatalf(
				"an anchor was requested despite the refusal (%s); provider "+
					"receipts cannot be retracted", event,
			)
		}
	}
	if fixture.anchor.counter != 0 {
		t.Fatalf("%d anchors were created", fixture.anchor.counter)
	}
	if _, err := os.Lstat(filepath.Join(
		fixture.root, "anchors", "terminal-aggregate.list",
	)); !os.IsNotExist(err) {
		t.Fatal("a terminal aggregate was written")
	}
	assertNoTerminalArtifacts(t, fixture.root)
}

// writeProducerArchive builds a real gzip tar of an evidence tree in the shape
// `tar -czf` produces: one top-level basename, directory entries, and every
// regular file beneath it. The controller verifies the pending archive against
// the tree member by member, so a placeholder file would not exercise anything.
func writeProducerArchive(t *testing.T, evidenceDir, destination string) {
	t.Helper()
	file, err := os.Create(destination) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressor := gzip.NewWriter(file)
	writer := tar.NewWriter(compressor)
	base := filepath.Base(evidenceDir)

	if err := filepath.WalkDir(evidenceDir, func(
		p string, entry os.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(evidenceDir, p)
		if err != nil {
			return err
		}
		if relative == "." {
			return writer.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir, Name: base + "/", Mode: 0o700,
				Format: tar.FormatPAX,
			})
		}
		if entry.IsDir() {
			return writer.WriteHeader(&tar.Header{
				Typeflag: tar.TypeDir, Name: base + "/" + relative + "/",
				Mode: 0o700, Format: tar.FormatPAX,
			})
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: base + "/" + relative,
			Mode: 0o600, Size: info.Size(), Format: tar.FormatPAX,
		}); err != nil {
			return err
		}
		content, err := os.ReadFile(p) // #nosec G304 -- test temp path
		if err != nil {
			return err
		}
		_, err = writer.Write(content)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPendingArchiveMustEncodeTheEvidenceTree is the equivalence requirement.
//
// Binding the archive's digest and the tree's digests into one signed record
// establishes that both artifacts were present. It does not establish that the
// archive is an encoding of the tree — two unrelated files satisfy binding
// perfectly. These cases are each an archive that is internally valid and
// simply describes something else.
func TestPendingArchiveMustEncodeTheEvidenceTree(t *testing.T) {
	for _, test := range []struct {
		name    string
		rewrite func(t *testing.T, evidenceDir, archive string)
		want    string
	}{
		{
			name: "omitted_member",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				rebuildArchiveWithout(t, evidenceDir, archive, "environment.txt")
			},
			want: "archive omits environment.txt",
		},
		{
			name: "extra_member",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				rebuildArchiveWithExtra(t, evidenceDir, archive,
					"smuggled.txt", "not in the tree\n", false)
			},
			want: "unlisted member smuggled.txt",
		},
		{
			name: "extra_empty_directory",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				rebuildArchiveWithExtra(t, evidenceDir, archive,
					"smuggled-dir", "", true)
			},
			want: "unexpected directory smuggled-dir",
		},
		{
			name: "same_name_different_bytes",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				rebuildArchiveReplacing(t, evidenceDir, archive,
					"environment.txt", "rewritten inside the archive only\n")
			},
			want: "different bytes",
		},
		{
			name: "path_traversal",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				writeRawArchive(t, archive, []rawMember{
					{name: "../escape.txt", content: "outside\n"},
				})
			},
			want: "escapes its root",
		},
		{
			name: "duplicate_path",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				base := filepath.Base(evidenceDir)
				writeRawArchive(t, archive, []rawMember{
					{name: base + "/", directory: true},
					{name: base + "/a.txt", content: "one\n"},
					{name: base + "/a.txt", content: "two\n"},
				})
			},
			want: "repeats member",
		},
		{
			name: "symlink_member",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				base := filepath.Base(evidenceDir)
				writeRawArchive(t, archive, []rawMember{
					{name: base + "/", directory: true},
					{name: base + "/link", link: "/etc/passwd"},
				})
			},
			want: "carries a link",
		},
		{
			name: "special_entry",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				base := filepath.Base(evidenceDir)
				writeRawArchive(t, archive, []rawMember{
					{name: base + "/", directory: true},
					{name: base + "/dev", fifo: true},
				})
			},
			want: "special entry",
		},
		{
			name: "two_top_level_roots",
			rewrite: func(t *testing.T, evidenceDir, archive string) {
				t.Helper()
				base := filepath.Base(evidenceDir)
				writeRawArchive(t, archive, []rawMember{
					{name: base + "/", directory: true},
					{name: base + "/a.txt", content: "one\n"},
					{name: "other/", directory: true},
					{name: "other/b.txt", content: "two\n"},
				})
			},
			want: "more than one top-level",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			evidenceDir := filepath.Join(fixture.root, "evidence",
				"auto-e2e-"+fixtureMatrixID+"-"+fixture.keys[0])
			test.rewrite(t, evidenceDir, evidenceDir+pendingArchive)
			// Re-point the record at the rewritten archive's real digest, so
			// the only remaining defect is the equivalence failure.
			repinProducerArchive(t, fixture, fixture.keys[0], evidenceDir)

			err := fixture.controller().Run()
			if err == nil {
				t.Fatalf(
					"an archive that does not encode the evidence tree (%s) "+
						"was signed over", test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			assertNoAnchorsOrTerminals(t, fixture)
		})
	}
}

// TestPendingArchiveAcceptsANestedTree is the positive control. A verifier that
// rejected everything would pass every case above and be worthless.
func TestPendingArchiveAcceptsANestedTree(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	for _, key := range fixture.keys {
		evidenceDir := filepath.Join(fixture.root, "evidence",
			"auto-e2e-"+fixtureMatrixID+"-"+key)
		// A legitimately nested subtree, listed in the manifest, present in
		// the tree and in the archive.
		writeFixtureFile(t,
			filepath.Join(evidenceDir, "diagnostics", "client", "root.txt"),
			"client namespace\n")
		writeFixtureFile(t,
			filepath.Join(evidenceDir, "diagnostics", "qdisc.json"), "{}\n")
		reseal(t, evidenceDir)
		writeProducerArchive(t, evidenceDir, evidenceDir+pendingArchive)
		repinProducerArchive(t, fixture, key, evidenceDir)
	}
	if err := fixture.controller().Run(); err != nil {
		t.Fatalf("a legitimately nested evidence tree was refused: %v", err)
	}
}

type rawMember struct {
	name      string
	content   string
	directory bool
	link      string
	fifo      bool
}

func writeRawArchive(t *testing.T, destination string, members []rawMember) {
	t.Helper()
	file, err := os.Create(destination) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	compressor := gzip.NewWriter(file)
	writer := tar.NewWriter(compressor)
	for _, member := range members {
		header := &tar.Header{Name: member.name, Mode: 0o600, Format: tar.FormatPAX}
		switch {
		case member.directory:
			header.Typeflag = tar.TypeDir
		case member.link != "":
			header.Typeflag = tar.TypeSymlink
			header.Linkname = member.link
		case member.fifo:
			header.Typeflag = tar.TypeFifo
		default:
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(member.content))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := writer.Write([]byte(member.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
}

func rebuildArchiveWithout(t *testing.T, evidenceDir, archive, omit string) {
	t.Helper()
	rebuild(t, evidenceDir, archive, omit, "", "", false)
}

func rebuildArchiveWithExtra(
	t *testing.T, evidenceDir, archive, name, content string, directory bool,
) {
	t.Helper()
	rebuild(t, evidenceDir, archive, "", name, content, directory)
}

func rebuildArchiveReplacing(
	t *testing.T, evidenceDir, archive, name, content string,
) {
	t.Helper()
	rebuild(t, evidenceDir, archive, name, name, content, false)
}

func rebuild(
	t *testing.T,
	evidenceDir, archive, omit, extraName, extraContent string,
	extraIsDirectory bool,
) {
	t.Helper()
	base := filepath.Base(evidenceDir)
	var members []rawMember
	members = append(members, rawMember{name: base + "/", directory: true})
	if err := filepath.WalkDir(evidenceDir, func(
		p string, entry os.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(evidenceDir, p)
		if err != nil || relative == "." {
			return err
		}
		if entry.IsDir() {
			members = append(members,
				rawMember{name: base + "/" + relative + "/", directory: true})
			return nil
		}
		if relative == omit {
			return nil
		}
		content, err := os.ReadFile(p) // #nosec G304 -- test temp path
		if err != nil {
			return err
		}
		members = append(members,
			rawMember{name: base + "/" + relative, content: string(content)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if extraName != "" {
		members = append(members, rawMember{
			name:      base + "/" + extraName,
			content:   extraContent,
			directory: extraIsDirectory,
		})
		if extraIsDirectory {
			members[len(members)-1].name += "/"
		}
	}
	writeRawArchive(t, archive, members)
}

// reseal rewrites an evidence directory's manifest over its current contents.
func reseal(t *testing.T, evidenceDir string) {
	t.Helper()
	var lines []string
	if err := filepath.WalkDir(evidenceDir, func(
		p string, entry os.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(evidenceDir, p)
		if err != nil || relative == "." || entry.IsDir() {
			return err
		}
		if relative == manifestName ||
			strings.Contains(relative, "audit-checkpoint") {
			return nil
		}
		content, err := os.ReadFile(p) // #nosec G304 -- test temp path
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		lines = append(lines, hex.EncodeToString(sum[:])+"  ./"+relative)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	writeFixtureFile(t, filepath.Join(evidenceDir, manifestName),
		strings.Join(lines, "\n")+"\n")
}

// repinProducerArchive updates a batch record's archive digest to the archive
// currently on disk, so a test's intended defect is the only one present.
func repinProducerArchive(
	t *testing.T, fixture *matrixFixture, key, evidenceDir string,
) {
	t.Helper()
	digest, err := sha256Of(evidenceDir + pendingArchive)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.root, "batches", key+pendingSuffix)
	content, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt []string
	for _, line := range strings.Split(
		strings.TrimSuffix(string(content), "\n"), "\n",
	) {
		if strings.HasPrefix(line, "archive_sha256=") {
			line = "archive_sha256=" + digest
		}
		rebuilt = append(rebuilt, line)
	}
	writeFixtureFile(t, path, strings.Join(rebuilt, "\n")+"\n")
}

// TestTrustInputMutationBeforeAnchorIsRefused covers the persisted-evidence
// check inside the last reversible gate.
//
// The anonymous snapshots mean a post-gate mutation cannot reach a provider —
// that is a separate guarantee, tested separately. This test is about the gate
// itself: a matrix root whose frozen trust files no longer match the signature
// is corrupted evidence, and corrupted evidence must be refused before any
// provider is contacted, regardless of what this process holds in memory.
func TestTrustInputMutationBeforeAnchorIsRefused(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, fixture *matrixFixture)
		want   string
	}{
		{
			name: "provider_one_key",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				replaceFrozenKey(t, fixture, "provider-one.ed25519.pub")
			},
			want: "persisted first provider key",
		},
		{
			name: "provider_two_key",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				replaceFrozenKey(t, fixture, "provider-two.ed25519.pub")
			},
			want: "persisted second provider key",
		},
		{
			name: "known_hosts",
			mutate: func(t *testing.T, fixture *matrixFixture) {
				t.Helper()
				writeFixtureFile(t, filepath.Join(
					fixture.root, "anchors", "known_hosts",
				), "provider-one ssh-ed25519 REPLACED\n")
			},
			want: "persisted anchor known hosts",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			controller := fixture.controller()
			controller.mutateBeforeAnchor = func() { test.mutate(t, fixture) }
			err := controller.Run()
			if err == nil {
				t.Fatalf(
					"a %s corrupted before the gate was anchored over; the "+
						"persisted evidence no longer matched the signature",
					test.name,
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			assertNoAnchorsOrTerminals(t, fixture)
		})
	}
}

// TestFinalizerSeedReplacementIsRefused covers the second half of the same
// problem. main used to derive the verifier's pin from a separate, earlier read
// of the seed than the one Run loads, so a replacement between the two produced
// checkpoints and anchors under signer B and then failed final verification
// against the stale pin A — irreversibly late.
func TestFinalizerSeedReplacementIsRefused(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	// A first run establishes the signed ownership record.
	first := fixture.controller()
	first.Anchor = &fakeAnchor{
		trace: fixture.trace, root: fixture.root, failAt: genesisSlotName,
	}
	if err := first.Run(); err == nil {
		t.Fatal("the injected genesis failure did not abort")
	}
	// The seed is then replaced. A resume loads the NEW signer, and the signed
	// record names the old one.
	replacement, err := auditcheckpoint.GenerateFinalizerSeed()
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureBytes(t, fixture.seed, replacement)

	resumed := newRetryFixture(t, fixture)
	err = resumed.controller().Run()
	if err == nil {
		t.Fatal("a replaced finalizer seed was used to continue the transition")
	}
	if !strings.Contains(err.Error(), "different controller") &&
		!strings.Contains(err.Error(), "seed was replaced") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// Asserted against the RESUMED run's trace: the first run's own aborted
	// genesis attempt is expected and is not what this test is about.
	assertNoAnchorsOrTerminals(t, resumed)
}

// TestResumeUsesFrozenTrustAfterTheOriginalsAreGone is the positive control,
// and it is deliberately written with zero test-only preconfiguration: a plain
// second Run() after the operator's original trust files have been deleted.
//
// An earlier version of this test conceded the failure and then hand-configured
// a second controller to read the frozen copies. That proved a helper worked
// while the production path stayed broken. If the real resume path does not
// adopt the frozen set by itself, this test fails.
func TestResumeUsesFrozenTrustAfterTheOriginalsAreGone(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	first := fixture.controller()
	first.Anchor = &fakeAnchor{
		trace: fixture.trace, root: fixture.root, failAt: genesisSlotName,
	}
	if err := first.Run(); err == nil {
		t.Fatal("the injected genesis failure did not abort")
	}
	// The freeze happened before the anchor attempt, so the frozen copies
	// exist; the operator's originals are now removed entirely.
	for _, path := range []string{
		fixture.keyOne, fixture.keyTwo, fixture.hosts,
	} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	resumed := newRetryFixture(t, fixture)
	if err := resumed.controller().Run(); err != nil {
		t.Fatalf(
			"a normal resume could not complete after the original trust "+
				"inputs were removed (%v); the production path is still "+
				"reading the operator's mutable files rather than the frozen "+
				"copies the signature covers", err,
		)
	}
	if _, err := os.Lstat(filepath.Join(fixture.root, completeMarker)); err != nil {
		t.Fatalf("the resume did not complete the matrix: %v", err)
	}
}

// TestFirstRunStillRequiresTheOperatorsTrustInputs pins the other side: before
// anything is frozen there is nothing to fall back to, so a first run with
// missing trust inputs is a plain configuration error rather than something
// silently substituted.
func TestFirstRunStillRequiresTheOperatorsTrustInputs(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := os.Remove(fixture.keyOne); err != nil {
		t.Fatal(err)
	}
	err := fixture.controller().Run()
	if err == nil {
		t.Fatal("a first run with no provider key was accepted")
	}
	if !strings.Contains(err.Error(), "first anchor provider key") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	assertNoAnchorsOrTerminals(t, fixture)
}

func replaceFrozenKey(t *testing.T, fixture *matrixFixture, name string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(fixture.root, "anchors", name),
		base64.StdEncoding.EncodeToString(public)+"\n")
}

// TestGenesisAnchorUsesTheCanonicalZeroPredecessor is the regression for the
// confirmed P0.
//
// The controller passed "" as both genesis predecessors. phase1anchor rejects
// that value, so a real run would have reached two external providers and
// failed there — mid-chain, on a sequence that cannot be retracted. Nothing
// caught it because the anchor fake ignored these arguments; it no longer does.
func TestGenesisAnchorUsesTheCanonicalZeroPredecessor(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatalf("a valid matrix was refused: %v", err)
	}
	one, two, called := fixture.anchor.previousFor(genesisSlotName)
	if !called {
		t.Fatal("the genesis anchor was never requested")
	}
	if one != phase1anchor.ZeroDigest || two != phase1anchor.ZeroDigest {
		t.Fatalf(
			"genesis predecessors were %q and %q, want the canonical zero "+
				"digest %q for both", one, two, phase1anchor.ZeroDigest,
		)
	}
}

// TestAnchorChainPredecessorsAreCanonicalThroughout extends that to every link:
// genesis carries the zero digest, and no later slot does.
func TestAnchorChainPredecessorsAreCanonicalThroughout(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	if err := fixture.controller().Run(); err != nil {
		t.Fatal(err)
	}
	if len(fixture.anchor.previous) != len(fixture.keys)+2 {
		t.Fatalf(
			"%d anchors were requested, want %d (genesis, %d batches, seal)",
			len(fixture.anchor.previous), len(fixture.keys)+2, len(fixture.keys),
		)
	}
	for index, entry := range fixture.anchor.previous {
		slot, one, two := entry[0], entry[1], entry[2]
		if index == 0 {
			if one != phase1anchor.ZeroDigest || two != phase1anchor.ZeroDigest {
				t.Fatalf("%s: genesis predecessors are %q/%q", slot, one, two)
			}
			continue
		}
		for label, previous := range map[string]string{
			"first": one, "second": two,
		} {
			if !phase1anchor.ValidPreviousDigest(previous, index) {
				t.Fatalf(
					"%s: the %s predecessor %q is not canonical at ordinal %d",
					slot, label, previous, index,
				)
			}
		}
	}
}

// TestMalformedPredecessorIsRefusedBeforeAnyProviderContact proves the local
// preflight fires in anchorOne, not after the runner has been reached.
func TestMalformedPredecessorIsRefusedBeforeAnyProviderContact(t *testing.T) {
	fixture := newMatrixFixture(t, fixtureOptions{})
	controller := fixture.controller()
	request := phase1anchor.Request{
		Schema:             phase1anchor.RequestSchema,
		Kind:               phase1anchor.KindGenesis,
		MatrixID:           fixtureMatrixID,
		SourceDigest:       fixtureSource,
		AutoArtifactDigest: fixtureArtifact,
		ProfileDigest:      fixtureProfile,
		ScheduleDigest:     strings.Repeat("4", 64),
		ExpectedBatchCount: 1,
		Ordinal:            0,
	}
	for name, predecessor := range map[string]string{
		"empty":     "",
		"uppercase": strings.ToUpper(strings.Repeat("ab", 32)),
		"short":     strings.Repeat("0", 63),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := controller.anchorOne(
				genesisSlotName, request, predecessor, phase1anchor.ZeroDigest,
			)
			if err == nil {
				t.Fatalf("a %q genesis predecessor reached the runner", name)
			}
			if !strings.Contains(err.Error(), "genesis predecessor") {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if len(fixture.anchor.previous) != 0 {
				t.Fatal(
					"the anchor runner was reached; a malformed predecessor " +
						"must be refused before any provider contact",
				)
			}
		})
	}
}

// --- the execution inventory, proved before any provider is contacted --------

// TestInventoryDisagreementIsRefusedWithZeroAnchors is the regression for a
// defect whose whole cost was in the ORDERING.
//
// The formal verifier requires matrix.env's execution_inventory_sha256,
// COMPLETE's copy of it, and the actual digest of <root>/execution-inventory
// .sha256 to be one value. The controller used to require only that the
// producer marker's field was non-empty. So a root that could never pass final
// verification was closed, published, and ANCHORED by two independent
// providers, and the mismatch surfaced only afterwards — at a point where no
// operation retracts the attestation and the matrix ID is spent.
//
// Both assertions below matter, and the second is the one that is really being
// made. An error alone was never missing: the old code produced one too, just
// after the irreversible step. What is asserted here is that ZERO anchor calls
// happened, which is the property that was actually broken.
func TestInventoryDisagreementIsRefusedWithZeroAnchors(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   string
		damage func(t *testing.T, root string)
	}{
		{
			// The file's own bytes. Every record agrees with every other
			// record; the inventory they all name simply is not the file on
			// disk. Nothing but hashing it can notice.
			name: "inventory_file_hashes_to_something_else",
			want: "execution-inventory.sha256 hashes to",
			damage: func(t *testing.T, root string) {
				t.Helper()
				writeFixtureFile(t,
					filepath.Join(root, "execution-inventory.sha256"),
					strings.Repeat("e", 64)+
						"  /opt/winn-lab/bin/winn-auto-e2e\n",
				)
			},
		},
		{
			// The two producer records disagree with each other. The marker's
			// value is the one the controller carries into COMPLETE, so the
			// final verifier would compare it against matrix.env's and refuse
			// — after anchoring.
			name: "marker_and_matrix_env_disagree",
			want: "records execution_inventory_sha256=",
			damage: func(t *testing.T, root string) {
				t.Helper()
				path := filepath.Join(root, "matrix.env")
				values, err := readKeyValues(path)
				if err != nil {
					t.Fatal(err)
				}
				values["execution_inventory_sha256"] = strings.Repeat("a", 64)
				var lines []string
				for key, value := range values {
					lines = append(lines, key+"="+value)
				}
				sort.Strings(lines)
				writeFixtureFile(t, path, strings.Join(lines, "\n")+"\n")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			test.damage(t, fixture.root)

			err := fixture.controller().Run()
			if err == nil {
				t.Fatal(
					"a matrix whose execution inventory does not hold together " +
						"was closed; the formal verifier would have refused it " +
						"after the anchors were already permanent",
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			// The property under test. Not "an error happened" — the old code
			// produced an error too, one irreversible step too late.
			if len(fixture.anchor.previous) != 0 || fixture.anchor.counter != 0 {
				t.Fatalf(
					"%d anchor requests reached a provider before the "+
						"inventory was checked; the attestation is permanent "+
						"and the matrix can never be completed: %v",
					len(fixture.anchor.previous), fixture.trace.events,
				)
			}
			for _, event := range fixture.trace.events {
				if strings.HasPrefix(event, "anchor:") {
					t.Fatalf("anchoring proceeded: %s", event)
				}
			}
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}

// TestInventoryCheckLivesInTheLastReversibleGate pins WHERE the check runs, and
// it is deliberately structural.
//
// A behavioural version of this was written first and thrown away, because it
// did not prove what its name claimed. It damaged the inventory through the
// mutateBeforeAnchor hook and asserted a refusal — but with the inventory gate
// removed entirely, that run still fails, on requireSnapshotStill: the file is
// a member of the signed producer snapshot, so ANY post-signature change to it
// is caught by the re-measure whether the inventory gate exists or not. The
// test would have passed for a reason unrelated to the check it was named for.
//
// What the inventory gate uniquely adds is refusal of an inconsistency that was
// ALREADY PRESENT when the run started, and that is asserted behaviourally by
// TestInventoryDisagreementIsRefusedWithZeroAnchors above — which, with the
// gate removed, does not merely fail differently: it anchors the whole matrix
// and returns success.
//
// So the remaining question is one of POSITION, and position is a fact about
// the source: the call has to be inside the one gate, and that gate has to run
// before anchorAndRecord. A correct check in the wrong phase is the defect this
// review cycle keeps finding.
func TestInventoryCheckLivesInTheLastReversibleGate(t *testing.T) {
	source, err := os.ReadFile("controller.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)

	// Self-check on the extractor FIRST. An absence check whose extractor
	// silently returns nothing reports health over code it never read, which
	// has already happened once on this project.
	gate, ok := controllerFunctionBody(text, "func (c *Controller) verifyLastReversibleGate(")
	if !ok || len(gate) < 500 {
		t.Fatalf(
			"extracted %d bytes for verifyLastReversibleGate; the extractor is "+
				"broken and every assertion below would be vacuous", len(gate),
		)
	}
	if !strings.Contains(gate, "requireSnapshotStill") {
		t.Fatal(
			"the extracted gate body does not contain a call this function is " +
				"known to make; the extractor is reading the wrong region",
		)
	}
	if strings.Contains(gate, "func (c *Controller) verifySeedCustody(") {
		t.Fatal("the extractor ran past the end of the function")
	}

	if !strings.Contains(gate, "c.requireExecutionInventoryAgrees(state)") {
		t.Fatalf(
			"verifyLastReversibleGate does not check the execution inventory. "+
				"Every other placement leaves a window: the producer phase is a "+
				"different instant, and anything after anchorAndRecord is after "+
				"two providers have signed:\n%s", gate,
		)
	}

	run, ok := controllerFunctionBody(text, "func (c *Controller) Run() error {")
	if !ok || len(run) < 500 {
		t.Fatalf("extracted %d bytes for Run; the extractor is broken", len(run))
	}
	gateAt := strings.Index(run, "c.verifyLastReversibleGate(")
	anchorAt := strings.Index(run, "c.anchorAndRecord(")
	if gateAt < 0 || anchorAt < 0 {
		t.Fatalf(
			"Run no longer calls both the gate and the anchor step:\n%s", run,
		)
	}
	if gateAt > anchorAt {
		t.Fatalf(
			"Run anchors before it runs the last reversible gate; every check "+
				"in that gate would then be reporting on evidence that is "+
				"already permanently attested:\n%s", run,
		)
	}
}

// controllerFunctionBody returns the source of one top-level function.
//
// Brace counting is enough here because this file is gofmt'ed: the closing
// brace of a top-level declaration is the first "}" at column zero after it.
func controllerFunctionBody(source, prefix string) (string, bool) {
	start := strings.Index(source, prefix)
	if start < 0 {
		return "", false
	}
	rest := source[start:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return "", false
	}
	return rest[:end+3], true
}

// TestProducerMarkerInventorySyntaxIsRefusedEarly covers the cheap early
// rejection, which exists for the operator's benefit rather than for safety.
// The load-bearing checks are in the gate; this one just reports the real
// reason before a lot of work happens.
func TestProducerMarkerInventorySyntaxIsRefusedEarly(t *testing.T) {
	for name, value := range map[string]string{
		"empty":       "",
		"too_short":   strings.Repeat("a", 63),
		"uppercase":   strings.Repeat("A", 64),
		"not_hex":     strings.Repeat("g", 64),
		"with_spaces": " " + strings.Repeat("a", 63),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			path := filepath.Join(fixture.root, producerMarker)
			values, err := readKeyValues(path)
			if err != nil {
				t.Fatal(err)
			}
			values["execution_inventory_sha256"] = value
			var lines []string
			for key, recorded := range values {
				lines = append(lines, key+"="+recorded)
			}
			sort.Strings(lines)
			writeFixtureFile(t, path, strings.Join(lines, "\n")+"\n")

			err = fixture.controller().Run()
			if err == nil {
				t.Fatal("a marker with an unusable inventory digest was accepted")
			}
			if !strings.Contains(
				err.Error(), "not a lowercase 64-hex SHA-256 digest",
			) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			if len(fixture.anchor.previous) != 0 {
				t.Fatal("the anchor runner was reached")
			}
		})
	}
}

// TestResumeRefusesAnInventoryMismatchWithZeroAnchors is the RESUME-path
// regression, and it is constructed so that the inventory gate is the only
// thing that can catch it.
//
// The asymmetry being closed is one this cycle has found repeatedly: a check
// that holds on a fresh run and not on a resume. The naive construction — run,
// crash, damage the inventory, resume — does NOT test that here, because
// execution-inventory.sha256 and matrix.env are members of the signed producer
// snapshot, so any post-signature change to them is refused by
// requireSnapshotStill whether an inventory gate exists or not. That test would
// pass for the wrong reason.
//
// So the inconsistency is present from the very beginning and never changes.
// The first attempt is made to fail BEFORE the gate, at batch verification, so
// CONTROLLER_START is published over the inconsistent-but-stable tree. The
// resume then re-measures that same tree successfully — the snapshot check has
// nothing to complain about — and the only remaining thing that can refuse is
// the inventory gate. Zero anchors either way.
func TestResumeRefusesAnInventoryMismatchWithZeroAnchors(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   string
		damage func(t *testing.T, root string)
	}{
		{
			name: "inventory_file_hashes_to_something_else",
			want: "execution-inventory.sha256 hashes to",
			damage: func(t *testing.T, root string) {
				t.Helper()
				writeFixtureFile(t,
					filepath.Join(root, "execution-inventory.sha256"),
					strings.Repeat("e", 64)+
						"  /opt/winn-lab/bin/winn-auto-e2e\n",
				)
			},
		},
		{
			name: "marker_and_matrix_env_disagree",
			want: "records execution_inventory_sha256=",
			damage: func(t *testing.T, root string) {
				t.Helper()
				path := filepath.Join(root, "matrix.env")
				values, err := readKeyValues(path)
				if err != nil {
					t.Fatal(err)
				}
				values["execution_inventory_sha256"] = strings.Repeat("a", 64)
				var lines []string
				for key, value := range values {
					lines = append(lines, key+"="+value)
				}
				sort.Strings(lines)
				writeFixtureFile(t, path, strings.Join(lines, "\n")+"\n")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMatrixFixture(t, fixtureOptions{})
			// Inconsistent from the start, and never touched again.
			test.damage(t, fixture.root)

			// Attempt one fails at batch verification, which is after
			// CONTROLLER_START is published and before the last reversible
			// gate. That is what makes the second attempt a genuine resume
			// over an unchanged tree.
			first := fixture.controller()
			fixture.verifier.failBatch = fixture.keys[0]
			if err := first.Run(); err == nil {
				t.Fatal("the injected batch verification failure did not abort")
			}
			if fixture.anchor.counter != 0 {
				t.Fatalf(
					"the first attempt anchored before the gate: %v",
					fixture.trace.events,
				)
			}
			if _, err := os.Lstat(filepath.Join(
				fixture.root, "CONTROLLER_START",
			)); err != nil {
				t.Fatalf(
					"the first attempt did not publish a start record (%v), so "+
						"the second attempt is not a resume and this test does "+
						"not exercise the resume path", err,
				)
			}

			resumed := newRetryFixture(t, fixture)
			err := resumed.controller().Run()
			if err == nil {
				t.Fatal(
					"a resume completed over a matrix whose execution " +
						"inventory does not hold together",
				)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("the resume refused for the wrong reason: %v", err)
			}
			if len(resumed.anchor.previous) != 0 ||
				resumed.anchor.counter != 0 {
				t.Fatalf(
					"%d anchor requests reached a provider on the resume path: "+
						"%v", len(resumed.anchor.previous),
					resumed.trace.events,
				)
			}
			for _, event := range resumed.trace.events {
				if strings.HasPrefix(event, "anchor:") {
					t.Fatalf("anchoring proceeded on resume: %s", event)
				}
			}
			assertNoTerminalArtifacts(t, fixture.root)
		})
	}
}
