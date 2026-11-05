// Tests for the smoke's own self-verification layer.
//
// The point of these is narrow and specific: a smoke that grades its own
// homework is worth nothing unless the grading itself is proved to fail on the
// defects it claims to catch. Each test below constructs the sealed-trail
// shape a plausible regression would produce and requires the recomputed
// coverage to reject it. If any of these ever starts passing a bad shape, the
// AICORE run's "all assertions PASS" line stops meaning anything.
//
// Two properties of this file are themselves load-bearing, and both were
// missing until an adversarial review found them:
//
//   - Every negative case looks the assertion up through requireRejected,
//     which fails if the assertion is ABSENT as well as if it passed. Checking
//     `results[name].Passed` alone is vacuous: a deleted production assertion
//     yields the zero value, which reads exactly like a correct rejection, so
//     the whole suite would stay green while the proof it describes no longer
//     existed. TestAssertionNamesArePinned additionally pins the complete
//     canonical name list literally here, so a rename or a deletion — even one
//     applied consistently to the production canonical list — fails.
//
//   - Every case drives the REAL (*smoke).buildCoverage and (*smoke).reconcile
//     against a temp sealed carrier-audit.jsonl, parsed back by the real
//     readSealedRecords. A hand-rolled copy of the classification loop would
//     make a regression inside the production loop invisible to every test
//     here, which is the exact defect this file exists to rule out elsewhere.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
)

func TestReasonSetIsExactlyRejectsPaddedAndMissingReasons(t *testing.T) {
	enum := carrier.AbortReasons()
	if len(enum) != 5 {
		t.Fatalf("closed abort-reason enum has %d members, want 5", len(enum))
	}

	complete := map[string]int{}
	for _, reason := range enum {
		complete[reason] = 1
	}
	if exact, detail := reasonSetIsExactly(complete, enum); !exact {
		t.Fatalf("one of each must be accepted, got: %s", detail)
	}

	// The exact regression the ruling's "five abort events" phrasing would
	// miss: the aborted column adds up, but four reasons were never exercised.
	padded := map[string]int{enum[0]: 5}
	exact, detail := reasonSetIsExactly(padded, enum)
	if exact {
		t.Fatal(
			"five copies of one abort reason must not count as full coverage",
		)
	}
	if !strings.Contains(detail, "recorded 5 times") ||
		!strings.Contains(detail, "missing") {
		t.Fatalf("padded-reason detail is unhelpful: %s", detail)
	}

	missing := map[string]int{}
	for _, reason := range enum[1:] {
		missing[reason] = 1
	}
	if exact, detail := reasonSetIsExactly(missing, enum); exact {
		t.Fatalf("a missing reason must be rejected, got: %s", detail)
	}

	unknown := map[string]int{}
	for _, reason := range enum {
		unknown[reason] = 1
	}
	unknown["stream_reset_optimization_v9"] = 1
	exact, detail = reasonSetIsExactly(unknown, enum)
	if exact {
		t.Fatal("a reason outside the closed enum must be rejected")
	}
	if !strings.Contains(detail, "unknown reason") {
		t.Fatalf("unknown-reason detail is unhelpful: %s", detail)
	}

	duplicated := map[string]int{}
	for _, reason := range enum {
		duplicated[reason] = 1
	}
	duplicated[enum[2]] = 2
	if exact, _ := reasonSetIsExactly(duplicated, enum); exact {
		t.Fatal("a reason recorded twice must be rejected")
	}
}

func TestParseTerminalDetailRejectsMalformedShapes(t *testing.T) {
	valid := schemaToken +
		" class=aborted mode=anonymous-token session=" +
		strings.Repeat("a", 32) + " reason=carrier_rate_limited"
	class, mode, session, reason, err := parseTerminalDetail(valid)
	if err != nil {
		t.Fatalf("valid five-token detail rejected: %v", err)
	}
	if class != "aborted" || mode != "anonymous-token" ||
		session != strings.Repeat("a", 32) ||
		reason != "carrier_rate_limited" {
		t.Fatalf(
			"parsed %q/%q/%q/%q from a known-good detail",
			class, mode, session, reason,
		)
	}
	for name, detail := range map[string]string{
		"wrong schema":  "carrier-terminal/v2 class=open mode=m session=s reason=none",
		"missing token": schemaToken + " class=open mode=m session=s",
		"empty reason":  schemaToken + " class=open mode=m session=s reason=",
		"reordered":     schemaToken + " mode=m class=open session=s reason=none",
	} {
		if _, _, _, _, err := parseTerminalDetail(detail); err == nil {
			t.Fatalf("%s detail was accepted", name)
		}
	}
}

// --- real-path harness ----------------------------------------------------

// sealedLine is the subset of internal/audit's on-disk record that
// readSealedRecords consumes. The tests write this shape and let the real
// parser read it back, so the record classification under test is the
// production one.
type sealedLine struct {
	Sequence   uint64 `json:"sequence"`
	Event      string `json:"event"`
	DeviceHash string `json:"device_hash,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// writeSealedTrail renders records into a temp carrier-audit.jsonl in the exact
// five-token terminal encoding and returns the evidence directory holding it.
func writeSealedTrail(t *testing.T, records []sealedRecord) string {
	t.Helper()
	directory := t.TempDir()
	var builder strings.Builder
	for index, record := range records {
		detail := record.Detail
		if detail == "" && record.Terminal {
			detail = fmt.Sprintf(
				"%s class=%s mode=%s session=%s reason=%s",
				schemaToken, record.Class, record.Mode,
				record.Session, record.Reason,
			)
		}
		sequence := record.Sequence
		if sequence == 0 {
			sequence = uint64(index + 1)
		}
		encoded, err := json.Marshal(sealedLine{
			Sequence:   sequence,
			Event:      record.Event,
			DeviceHash: record.DeviceHash,
			RequestID:  record.RequestID,
			Detail:     detail,
		})
		if err != nil {
			t.Fatalf("encode sealed record %d: %v", index+1, err)
		}
		builder.Write(encoded)
		builder.WriteString("\n")
	}
	if err := os.WriteFile(
		filepath.Join(directory, auditLogName),
		[]byte(builder.String()), 0o600,
	); err != nil {
		t.Fatalf("write sealed trail: %v", err)
	}
	return directory
}

// newSealedSmoke returns a smoke rooted on a temp evidence directory holding
// exactly these records, with the reconciliation windows shortened so the real
// reconcile() can be driven in bounded test time.
func newSealedSmoke(t *testing.T, records []sealedRecord) *smoke {
	t.Helper()
	return &smoke{
		evidenceDirectory: writeSealedTrail(t, records),
		redemptions:       &countingRedemptionStore{},
		settleWindow:      10 * time.Millisecond,
		recordWait:        750 * time.Millisecond,
		binaryDigest:      strings.Repeat("1", 64),
		expectedBinary:    strings.Repeat("1", 64),
		expectedSource:    strings.Repeat("2", 64),
	}
}

// buildAssertions runs the REAL coverage recomputation over a synthetic sealed
// trail and indexes the assertions it produced by name.
func buildAssertions(
	t *testing.T,
	records []sealedRecord,
	triggers []*trigger,
	redemptions int64,
	injectors []*oneShotFailingSink,
) map[string]assertion {
	t.Helper()
	run := newSealedSmoke(t, records)
	run.triggers = triggers
	run.injectors = injectors
	run.redemptions.redeemed.Store(redemptions)
	report, err := run.buildCoverage()
	if err != nil {
		t.Fatalf("buildCoverage rejected the trail outright: %v", err)
	}
	results := map[string]assertion{}
	for _, current := range report.Assertions {
		if _, duplicate := results[current.Name]; duplicate {
			t.Fatalf("assertion %s was produced twice", current.Name)
		}
		results[current.Name] = current
	}
	return results
}

// requireRejected is the only way this file is allowed to check a negative
// case. It fails when the named assertion is missing, not merely when it
// passed: absence and rejection are indistinguishable through a bare map
// lookup, and a deleted assertion must never read as a working one.
func requireRejected(
	t *testing.T,
	results map[string]assertion,
	name string,
	why string,
) {
	t.Helper()
	current, present := results[name]
	if !present {
		t.Fatalf(
			"assertion %s does not exist, so %s is not actually checked "+
				"anywhere; a deleted assertion cannot count as a rejection",
			name, why,
		)
	}
	if current.Passed {
		t.Fatalf("%s was accepted: %s", why, current.Detail)
	}
}

// requireAccepted is its positive twin, for the cases where a test asserts
// that one specific check is deliberately still passing.
func requireAccepted(
	t *testing.T,
	results map[string]assertion,
	name string,
	why string,
) {
	t.Helper()
	current, present := results[name]
	if !present {
		t.Fatalf("assertion %s does not exist, so %s proves nothing", name, why)
	}
	if !current.Passed {
		t.Fatalf("%s: %s", why, current.Detail)
	}
}

func correlationID(index int) string {
	return fmt.Sprintf("%032x", index)
}

func terminalRecord(event, class, reason, correlation string) sealedRecord {
	return sealedRecord{
		Event:      event,
		Class:      class,
		Reason:     reason,
		Mode:       carrierAuthMode,
		RequestID:  correlation,
		DeviceHash: strings.Repeat("b", 64),
		Session:    strings.Repeat("c", 32),
		Terminal:   true,
	}
}

// canonicalInjectors returns the two pinned injectors in the state a healthy
// run leaves them: registered, wired to their canonical fail events, and having
// refused exactly one record each.
func canonicalInjectors() []*oneShotFailingSink {
	injectors := make([]*oneShotFailingSink, 0, len(expectedInjectors))
	for _, plan := range expectedInjectors {
		injector := &oneShotFailingSink{
			name: plan.Name, failEvent: plan.FailEvent,
		}
		injector.refusals.Store(plan.ExpectedRefusals)
		injectors = append(injectors, injector)
	}
	return injectors
}

// balancedRun builds the exact sealed shape a healthy run produces, plus the
// matching trigger plan, so the negative cases below differ from it in exactly
// one way.
func balancedRun() ([]sealedRecord, []*trigger) {
	var records []sealedRecord
	var triggers []*trigger
	index := 0
	add := func(family string, expected []expectedEvent) {
		index++
		correlation := correlationID(index)
		for _, event := range expected {
			records = append(records, terminalRecord(
				event.Event, event.Class, event.Reason, correlation,
			))
		}
		triggers = append(triggers, &trigger{
			Carrier:        family,
			ExpectedEvents: expected,
			Correlation:    correlation,
			Reconciled:     true,
		})
	}
	add("h3", authOnlyEvents())
	add("h3", successEvents("h3"))
	for _, reason := range carrier.AbortReasons() {
		add("h3", abortEvents("h3", reason))
	}
	add("h2", successEvents("h2"))
	for _, reason := range carrier.AbortReasons() {
		add("h2", abortEvents("h2", reason))
	}
	return records, triggers
}

// --- the assertion set itself ---------------------------------------------

// TestAssertionNamesArePinned is the answer to "a deleted assertion reads
// exactly like a rejecting one". The canonical list is repeated here as a
// literal, independently of the production variable, so deleting or renaming a
// production assertion fails this test even if the production canonical list is
// edited to agree with the change.
func TestAssertionNamesArePinned(t *testing.T) {
	pinned := []string{
		"h3_terminal_counts_exact",
		"h3_abort_reason_set_exact",
		"h3_conservation_identity",
		"h3_open_equals_closed",
		"h2_terminal_counts_exact",
		"h2_abort_reason_set_exact",
		"h2_conservation_identity",
		"h2_open_equals_closed",
		"h2_has_no_auth_only_class",
		"h3_plan_matches_expectation_table",
		"h2_plan_matches_expectation_table",
		"every_trigger_reconciled_against_the_sealed_trail",
		"every_request_has_its_own_correlation_identity",
		"sealed_correlations_match_driven_requests",
		"redemptions_equal_authenticated",
		"fault_injector_schema_exact",
		"fault_injector_fired_h3_audit_unavailable_sink",
		"fault_injector_fired_h2_audit_unavailable_sink",
		"assertion_set_is_exactly_canonical",
	}
	if len(pinned) != 19 {
		t.Fatalf("the pinned list itself has %d names, want 19", len(pinned))
	}

	records, triggers := balancedRun()
	run := newSealedSmoke(t, records)
	run.triggers = triggers
	run.injectors = canonicalInjectors()
	run.redemptions.redeemed.Store(13)
	report, err := run.buildCoverage()
	if err != nil {
		t.Fatalf("buildCoverage rejected a healthy trail: %v", err)
	}

	produced := make([]string, 0, len(report.Assertions))
	for _, current := range report.Assertions {
		produced = append(produced, current.Name)
	}
	if len(produced) != len(pinned) {
		t.Fatalf(
			"the run produced %d assertions, this test pins %d: [%s]",
			len(produced), len(pinned), strings.Join(produced, " "),
		)
	}
	for index, name := range pinned {
		if produced[index] != name {
			t.Fatalf(
				"assertion %d is %q, pinned as %q; a renamed or deleted "+
					"assertion silently shrinks the proof",
				index+1, produced[index], name,
			)
		}
	}
	// The production canonical list must agree with the literal above too, so
	// the run's own meta-assertion is checking the same thing this test is.
	if len(canonicalAssertionNames) != len(pinned) {
		t.Fatalf(
			"production canonical list has %d names, this test pins %d",
			len(canonicalAssertionNames), len(pinned),
		)
	}
	for index, name := range pinned {
		if canonicalAssertionNames[index] != name {
			t.Fatalf(
				"production canonical name %d is %q, pinned as %q",
				index+1, canonicalAssertionNames[index], name,
			)
		}
	}
}

func TestAssertionsAcceptTheBalancedRun(t *testing.T) {
	records, triggers := balancedRun()
	results := buildAssertions(t, records, triggers, 13, canonicalInjectors())
	if len(results) != len(canonicalAssertionNames) {
		t.Fatalf(
			"a healthy run produced %d assertions, canonical set has %d",
			len(results), len(canonicalAssertionNames),
		)
	}
	for name, current := range results {
		if !current.Passed {
			t.Fatalf("healthy run failed assertion %s: %s", name, current.Detail)
		}
	}
}

func TestAssertionsRejectPaddedAbortReasons(t *testing.T) {
	records, triggers := balancedRun()
	// A regression that maps four distinct failures onto one reason: the
	// aborted count is untouched, so only the reason-set check can see it.
	replaced := 0
	for index := range records {
		if records[index].Class == "aborted" &&
			strings.HasPrefix(records[index].Event, "carrier_h3_") {
			records[index].Reason = carrier.AbortReasonRateLimited
			replaced++
		}
	}
	if replaced != 5 {
		t.Fatalf("expected 5 H3 abort records, rewrote %d", replaced)
	}
	results := buildAssertions(t, records, triggers, 13, canonicalInjectors())
	requireAccepted(
		t, results, "h3_terminal_counts_exact",
		"the count check should still pass; that is the whole point",
	)
	requireRejected(
		t, results, "h3_abort_reason_set_exact",
		"five copies of carrier_rate_limited as full H3 abort coverage",
	)
}

func TestAssertionsRejectMissingAndDuplicateTerminals(t *testing.T) {
	t.Run("DroppedTerminal", func(t *testing.T) {
		records, triggers := balancedRun()
		trimmed := records[:len(records)-1]
		results := buildAssertions(
			t, trimmed, triggers, 13, canonicalInjectors(),
		)
		requireRejected(
			t, results, "h2_terminal_counts_exact",
			"a dropped H2 terminal event",
		)
		requireRejected(
			t, results, "h2_conservation_identity",
			"authenticated != auth_only+open+aborted",
		)
	})
	t.Run("DuplicateTerminal", func(t *testing.T) {
		records, triggers := balancedRun()
		records = append(records, terminalRecord(
			"carrier_h3_aborted", "aborted",
			carrier.AbortReasonRateLimited, records[0].RequestID,
		))
		results := buildAssertions(
			t, records, triggers, 13, canonicalInjectors(),
		)
		requireRejected(
			t, results, "h3_terminal_counts_exact",
			"an extra H3 terminal event",
		)
	})
	t.Run("H2AuthOnlyIsImpossible", func(t *testing.T) {
		records, triggers := balancedRun()
		records = append(records, terminalRecord(
			"carrier_h2_auth_only", "auth_only", "none",
			correlationID(99),
		))
		results := buildAssertions(
			t, records, triggers, 13, canonicalInjectors(),
		)
		requireRejected(
			t, results, "h2_has_no_auth_only_class",
			"a carrier_h2_auth_only event",
		)
	})
}

func TestAssertionsRejectRedemptionMismatch(t *testing.T) {
	records, triggers := balancedRun()
	results := buildAssertions(t, records, triggers, 12, canonicalInjectors())
	requireRejected(
		t, results, "redemptions_equal_authenticated",
		"redemptions=12 against 13 authenticated",
	)
}

func TestAssertionsRejectFaultInjectorDefects(t *testing.T) {
	t.Run("NeverFired", func(t *testing.T) {
		records, triggers := balancedRun()
		// The injector was wired up but never actually refused anything: the
		// abort record exists, so every count-based check passes, and only the
		// injector's own activation counter reveals that the mechanism under
		// test never ran.
		injectors := canonicalInjectors()
		injectors[0].refusals.Store(0)
		results := buildAssertions(t, records, triggers, 13, injectors)
		requireRejected(
			t, results,
			"fault_injector_fired_"+expectedInjectors[0].Name,
			"an injector that never fired",
		)
		requireRejected(
			t, results, "fault_injector_schema_exact",
			"an injector with the wrong refusal count",
		)
	})
	t.Run("MissingInjector", func(t *testing.T) {
		records, triggers := balancedRun()
		// One canonical injector was never registered at all. Its "fired"
		// assertion must still be produced and must fail; a silently absent
		// assertion would be indistinguishable from a passing one.
		results := buildAssertions(
			t, records, triggers, 13, canonicalInjectors()[:1],
		)
		requireRejected(
			t, results,
			"fault_injector_fired_"+expectedInjectors[1].Name,
			"a canonical injector that was never registered",
		)
		requireRejected(
			t, results, "fault_injector_schema_exact",
			"a run with only one of the two pinned injectors",
		)
	})
	t.Run("ExtraInjector", func(t *testing.T) {
		records, triggers := balancedRun()
		extra := &oneShotFailingSink{
			name: "undeclared_sink", failEvent: carrier.EventH3Open,
		}
		extra.refusals.Store(1)
		results := buildAssertions(
			t, records, triggers, 13, append(canonicalInjectors(), extra),
		)
		requireRejected(
			t, results, "fault_injector_schema_exact",
			"a third, undeclared fault injector",
		)
	})
	t.Run("WrongFailEvent", func(t *testing.T) {
		records, triggers := balancedRun()
		injectors := canonicalInjectors()
		injectors[1].failEvent = carrier.EventH2Closed
		results := buildAssertions(t, records, triggers, 13, injectors)
		requireRejected(
			t, results, "fault_injector_schema_exact",
			"an injector rewired to a different fail event",
		)
		requireRejected(
			t, results,
			"fault_injector_fired_"+expectedInjectors[1].Name,
			"an injector that refused the wrong record",
		)
	})
}

// The driven plan and the flat expectation table are two independent
// statements of the same thing. Editing one alone must fail.
func TestAssertionsRejectPlanDriftFromTheExpectationTable(t *testing.T) {
	records, triggers := balancedRun()
	triggers = triggers[:len(triggers)-1]
	results := buildAssertions(t, records, triggers, 13, canonicalInjectors())
	requireRejected(
		t, results, "h2_plan_matches_expectation_table",
		"a trigger plan short of the expectation table",
	)
	requireRejected(
		t, results, "every_trigger_reconciled_against_the_sealed_trail",
		"a 12-trigger run presented as the 13-request plan",
	)
}

func TestAssertionsRejectCorrelationReuse(t *testing.T) {
	records, triggers := balancedRun()
	// Two requests attributed to one correlation identity: the aggregate
	// counts are untouched, so only identity-level checks can see it.
	triggers[3].Correlation = triggers[2].Correlation
	results := buildAssertions(t, records, triggers, 13, canonicalInjectors())
	requireRejected(
		t, results, "every_request_has_its_own_correlation_identity",
		"two requests sharing one correlation identity",
	)
}

// --- the real reconcile path ----------------------------------------------

// reconcile is the per-request half of the self-verification and had no test at
// all. These drive the production function against a temp sealed trail.

func abortTrigger(reason string) *trigger {
	return &trigger{
		Name:           "h3_" + reason,
		Carrier:        "h3",
		ExpectedEvents: abortEvents("h3", reason),
	}
}

func TestReconcileAcceptsTheDeclaredSequence(t *testing.T) {
	correlation := correlationID(1)
	records := []sealedRecord{
		terminalRecord(
			"carrier_h3_authenticated", "authenticated", "none", correlation,
		),
		terminalRecord(
			"carrier_h3_aborted", "aborted",
			carrier.AbortReasonRateLimited, correlation,
		),
	}
	run := newSealedSmoke(t, records)
	entry := abortTrigger(carrier.AbortReasonRateLimited)
	if err := run.reconcile(entry); err != nil {
		t.Fatalf("a correctly sealed request was rejected: %v", err)
	}
	if !entry.Reconciled || entry.Correlation != correlation {
		t.Fatalf("reconcile left %+v", entry)
	}
	if len(entry.ObservedEvents) != 2 || run.consumed != 2 {
		t.Fatalf(
			"observed %d events, consumed %d",
			len(entry.ObservedEvents), run.consumed,
		)
	}
	if len(run.triggers) != 1 {
		t.Fatalf("reconcile recorded %d triggers", len(run.triggers))
	}
}

func TestReconcileRejectsTheWrongAbortReason(t *testing.T) {
	correlation := correlationID(1)
	records := []sealedRecord{
		terminalRecord(
			"carrier_h3_authenticated", "authenticated", "none", correlation,
		),
		// Driven for a rate-limit abort, but the carrier sealed a different
		// reason. Counts alone can never see this.
		terminalRecord(
			"carrier_h3_aborted", "aborted",
			carrier.AbortReasonAuditUnavailable, correlation,
		),
	}
	run := newSealedSmoke(t, records)
	err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
	if err == nil {
		t.Fatal("a request that aborted for a different reason was accepted")
	}
	if !strings.Contains(err.Error(), carrier.AbortReasonAuditUnavailable) {
		t.Fatalf("unhelpful rejection: %v", err)
	}
	if len(run.triggers) != 0 {
		t.Fatal("a rejected trigger was still recorded as reconciled")
	}
}

func TestReconcileRejectsAMissingRecord(t *testing.T) {
	correlation := correlationID(1)
	// The abort record was never sealed: the carrier authenticated the request
	// and then dropped it, which is the defect the whole conservation design
	// exists to catch.
	records := []sealedRecord{
		terminalRecord(
			"carrier_h3_authenticated", "authenticated", "none", correlation,
		),
	}
	run := newSealedSmoke(t, records)
	err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
	if err == nil {
		t.Fatal("a request missing its terminal record was accepted")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("unhelpful rejection: %v", err)
	}
}

func TestReconcileRejectsALateOrDuplicateRecord(t *testing.T) {
	correlation := correlationID(1)
	// Two terminal records for one request. The expected count is satisfied by
	// the first two lines, so only the settle window can see the third.
	records := []sealedRecord{
		terminalRecord(
			"carrier_h3_authenticated", "authenticated", "none", correlation,
		),
		terminalRecord(
			"carrier_h3_aborted", "aborted",
			carrier.AbortReasonRateLimited, correlation,
		),
		terminalRecord(
			"carrier_h3_aborted", "aborted",
			carrier.AbortReasonRateLimited, correlation,
		),
	}
	run := newSealedSmoke(t, records)
	err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
	if err == nil {
		t.Fatal("a duplicated terminal record was accepted")
	}
	if !strings.Contains(err.Error(), "expected exactly 2") {
		t.Fatalf("unhelpful rejection: %v", err)
	}
}

func TestReconcileRejectsForeignAndMalformedIdentities(t *testing.T) {
	t.Run("ForeignCorrelation", func(t *testing.T) {
		records := []sealedRecord{
			terminalRecord(
				"carrier_h3_authenticated", "authenticated", "none",
				correlationID(1),
			),
			terminalRecord(
				"carrier_h3_aborted", "aborted",
				carrier.AbortReasonRateLimited, correlationID(2),
			),
		}
		run := newSealedSmoke(t, records)
		err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
		if err == nil ||
			!strings.Contains(err.Error(), "different correlation identity") {
			t.Fatalf("two correlations were reconciled as one request: %v", err)
		}
	})
	t.Run("MalformedCorrelation", func(t *testing.T) {
		records := []sealedRecord{
			terminalRecord(
				"carrier_h3_authenticated", "authenticated", "none", "short",
			),
			terminalRecord(
				"carrier_h3_aborted", "aborted",
				carrier.AbortReasonRateLimited, "short",
			),
		}
		run := newSealedSmoke(t, records)
		err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
		if err == nil || !strings.Contains(err.Error(), "128 hex bits") {
			t.Fatalf("a malformed correlation identity was accepted: %v", err)
		}
	})
	t.Run("MalformedDeviceHash", func(t *testing.T) {
		correlation := correlationID(1)
		records := []sealedRecord{
			terminalRecord(
				"carrier_h3_authenticated", "authenticated", "none",
				correlation,
			),
			terminalRecord(
				"carrier_h3_aborted", "aborted",
				carrier.AbortReasonRateLimited, correlation,
			),
		}
		records[0].DeviceHash = ""
		records[1].DeviceHash = ""
		run := newSealedSmoke(t, records)
		err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
		if err == nil || !strings.Contains(err.Error(), "32-byte digest") {
			t.Fatalf("a malformed device hash was accepted: %v", err)
		}
	})
	t.Run("WrongAuthorizationMode", func(t *testing.T) {
		correlation := correlationID(1)
		records := []sealedRecord{
			terminalRecord(
				"carrier_h3_authenticated", "authenticated", "none",
				correlation,
			),
			terminalRecord(
				"carrier_h3_aborted", "aborted",
				carrier.AbortReasonRateLimited, correlation,
			),
		}
		records[1].Mode = "identity"
		run := newSealedSmoke(t, records)
		err := run.reconcile(abortTrigger(carrier.AbortReasonRateLimited))
		if err == nil ||
			!strings.Contains(err.Error(), "authorization mode") {
			t.Fatalf("an identity-mode record was accepted: %v", err)
		}
	})
}

// --- binding --------------------------------------------------------------

// requireBinding is the gate that has to fire before any evidence exists at
// all. These are the F4/F7 controls that live on my side of the split: the
// dedicated negative-control suite for wrong/missing digests is written
// independently.
func TestRequireBindingRefusesUnboundRuns(t *testing.T) {
	stamped := sourceDigest
	t.Cleanup(func() { sourceDigest = stamped })

	valid := strings.Repeat("a", 64)
	sourceDigest = valid
	if err := requireBinding(valid, valid); err != nil {
		t.Fatalf("a fully bound run was refused: %v", err)
	}

	for name, arguments := range map[string][2]string{
		"missing binary digest": {"", valid},
		"missing source digest": {valid, ""},
		"short binary digest":   {strings.Repeat("a", 63), valid},
		"upper-case binary":     {strings.Repeat("A", 64), valid},
		"non-hex source":        {valid, strings.Repeat("z", 64)},
		"mismatched source":     {valid, strings.Repeat("b", 64)},
	} {
		if err := requireBinding(arguments[0], arguments[1]); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	// An unstamped build — plain `go build`, no ldflags — must never be able to
	// seal evidence, whatever the runner passes in.
	for _, unstamped := range []string{"", "unstamped-non-release-build"} {
		sourceDigest = unstamped
		if err := requireBinding(valid, valid); err == nil {
			t.Fatalf("an executable stamped %q sealed evidence", unstamped)
		}
	}
}
