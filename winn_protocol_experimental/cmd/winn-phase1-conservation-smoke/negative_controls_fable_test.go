// Codex-mandated negative controls, authored independently by the Fable lane
// (2026-07-26 adjudication, F1-F7). These tests exercise the REAL production
// functions — (*smoke).buildCoverage, (*smoke).reconcile, requireBinding,
// run() — against real sealed-trail files on disk, never a hand-rolled
// reimplementation of the classification loop (the exact defect F2 flagged in
// the original suite).
//
// Independence note: ncCanonicalAssertionNames below is a deliberately
// SEPARATE copy of the canonical assertion list, maintained in this file. The
// production meta-assertion (assertion_set_is_exactly_canonical) catches a
// deleted assertion only if canonicalAssertionNames in main.go is not edited
// in the same change; this copy is the second lock, so deleting an assertion
// requires touching production code, its canonical list, AND an adversarial
// test file that exists to notice exactly that.
//
// Naming: every helper here is nc-prefixed and every test NegativeControl-
// prefixed so nothing collides with main_test.go, which a parallel lane owns.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/carrier"
)

// ncTerminalLine renders one sealed carrier-audit.jsonl line in the exact
// parse shape readSealedRecords consumes: the versioned five-token terminal
// detail under one correlation identity.
func ncTerminalLine(
	sequence int,
	event, class, reason, correlation, session string,
) string {
	entry := map[string]any{
		"sequence":    sequence,
		"event":       event,
		"device_hash": strings.Repeat("b", 64),
		"request_id":  correlation,
		"detail": schemaToken +
			" class=" + class +
			" mode=" + carrierAuthMode +
			" session=" + session +
			" reason=" + reason,
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

// ncFileTrail builds the sealed-file trail plus the matching real trigger
// plan. The abort reason lists are parameters so a negative case can differ
// from the balanced run in exactly one way.
func ncFileTrail(h3Aborts, h2Aborts []string) ([]string, []*trigger) {
	var lines []string
	var triggers []*trigger
	sequence := 0
	index := 0
	add := func(family string, expected []expectedEvent) {
		index++
		correlation := fmt.Sprintf("%032x", index)
		session := fmt.Sprintf("%032x", 1000+index)
		for _, event := range expected {
			sequence++
			lines = append(lines, ncTerminalLine(
				sequence, event.Event, event.Class, event.Reason,
				correlation, session,
			))
		}
		triggers = append(triggers, &trigger{
			Name:           fmt.Sprintf("nc_trigger_%02d", index),
			Carrier:        family,
			ExpectedEvents: expected,
			Correlation:    correlation,
			Reconciled:     true,
		})
	}
	add("h3", authOnlyEvents())
	add("h3", successEvents("h3"))
	for _, reason := range h3Aborts {
		add("h3", abortEvents("h3", reason))
	}
	add("h2", successEvents("h2"))
	for _, reason := range h2Aborts {
		add("h2", abortEvents("h2", reason))
	}
	return lines, triggers
}

func ncBalancedFileTrail() ([]string, []*trigger) {
	return ncFileTrail(carrier.AbortReasons(), carrier.AbortReasons())
}

// ncCanonicalInjectors mirrors the exact two fault injectors the production
// drive loops register, each having fired exactly once, in registration
// order.
func ncCanonicalInjectors() []*oneShotFailingSink {
	h3 := &oneShotFailingSink{
		name:      "h3_audit_unavailable_sink",
		failEvent: carrier.EventH3AuthOnly,
	}
	h2 := &oneShotFailingSink{
		name:      "h2_audit_unavailable_sink",
		failEvent: carrier.EventH2Open,
	}
	for _, sink := range []*oneShotFailingSink{h3, h2} {
		sink.fired.Store(true)
		sink.refusals.Store(1)
	}
	return []*oneShotFailingSink{h3, h2}
}

// ncSmoke builds a real smoke whose evidence directory holds the given sealed
// trail, so buildCoverage/reconcile run their genuine read-parse-classify
// paths from disk.
func ncSmoke(
	t *testing.T,
	lines []string,
	triggers []*trigger,
	injectors []*oneShotFailingSink,
	redeemed int64,
) *smoke {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, auditLogName),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	store := &countingRedemptionStore{}
	store.redeemed.Store(redeemed)
	return &smoke{
		evidenceDirectory: directory,
		triggers:          triggers,
		injectors:         injectors,
		redemptions:       store,
		binaryDigest:      strings.Repeat("d", 64),
	}
}

func ncAssertionMap(
	t *testing.T,
	report *coverageReport,
) map[string]assertion {
	t.Helper()
	results := map[string]assertion{}
	for _, current := range report.Assertions {
		if _, duplicate := results[current.Name]; duplicate {
			t.Fatalf("assertion name %q produced twice", current.Name)
		}
		results[current.Name] = current
	}
	return results
}

// ncStampSource sets the package-level ldflags stamp for the duration of one
// test. The test binary itself is an unstamped build, so binding-path tests
// must inject a stamp to exercise the comparison rather than the
// unstamped-build refusal.
func ncStampSource(t *testing.T, value string) {
	t.Helper()
	previous := sourceDigest
	sourceDigest = value
	t.Cleanup(func() { sourceDigest = previous })
}

// --- positive control -------------------------------------------------------

// The balanced sealed trail must pass the REAL buildCoverage. Every negative
// case below differs from this run in exactly one way, so a failure there is
// attributable and a pass here proves the negative cases are not rejecting
// everything indiscriminately.
func TestNegativeControlRealBuildCoverageAcceptsBalancedSealedTrail(
	t *testing.T,
) {
	lines, triggers := ncBalancedFileTrail()
	run := ncSmoke(t, lines, triggers, ncCanonicalInjectors(), 13)
	report, err := run.buildCoverage()
	if err != nil {
		t.Fatalf("real buildCoverage rejected the balanced sealed trail: %v", err)
	}
	if !report.AllAssertionsPassed {
		for _, current := range report.Assertions {
			if !current.Passed {
				t.Errorf("FAIL %s: %s", current.Name, current.Detail)
			}
		}
		t.Fatal("the balanced sealed trail must pass every recomputed assertion")
	}
	for _, family := range []string{"h3", "h2"} {
		if !report.Families[family].Matches {
			t.Fatalf("%s observed totals do not match the expectation table", family)
		}
	}
}

// --- Codex control: a deleted assertion name --------------------------------

// ncCanonicalAssertionNames is this file's INDEPENDENT copy of the exact,
// ordered assertion-name set a healthy run must emit. Do not "fix" a failure
// here by pasting from main.go's canonicalAssertionNames without reviewing
// WHAT changed: the whole point of the duplicate is that deleting or renaming
// a production assertion must force an edit in this adversarial file too.
var ncCanonicalAssertionNames = []string{
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

func TestNegativeControlDeletedAssertionNameFailsLoudly(t *testing.T) {
	// Lock one: this file's list must equal the production list, so neither
	// can drift without a cross-file, cross-owner edit.
	if !slices.Equal(canonicalAssertionNames, ncCanonicalAssertionNames) {
		t.Fatalf(
			"production canonicalAssertionNames diverged from the "+
				"independent adversarial copy:\nproduction: %v\nadversarial: %v",
			canonicalAssertionNames, ncCanonicalAssertionNames,
		)
	}

	// Lock two: what the assertion layer ACTUALLY emits for a healthy run
	// must equal this file's list, in order. A deleted, renamed, or
	// reordered production assertion fails here even if someone also edited
	// main.go's canonical list to match the deletion.
	lines, triggers := ncBalancedFileTrail()
	run := ncSmoke(t, lines, triggers, ncCanonicalInjectors(), 13)
	report, err := run.buildCoverage()
	if err != nil {
		t.Fatal(err)
	}
	produced := make([]string, 0, len(report.Assertions))
	for _, current := range report.Assertions {
		produced = append(produced, current.Name)
	}
	if !slices.Equal(produced, ncCanonicalAssertionNames) {
		t.Fatalf(
			"emitted assertion set differs from the canonical set:\n"+
				"emitted:   %v\ncanonical: %v",
			produced, ncCanonicalAssertionNames,
		)
	}
	// The meta-assertion must itself be present and passing on this run.
	meta, present := ncAssertionMap(t, report)[assertionSetName]
	if !present || !meta.Passed {
		t.Fatalf("meta-assertion %q missing or failing: %+v",
			assertionSetName, meta)
	}
}

// --- Codex control: buildCoverage reason padding -----------------------------

// Five copies of one abort reason keep every count-based column identical to
// the balanced run; only the multiset check can see it. This drives the REAL
// buildCoverage from a real sealed file, unlike the pre-F2 suite which
// reimplemented the classification loop.
func TestNegativeControlRealBuildCoverageRejectsReasonPadding(t *testing.T) {
	padded := []string{
		carrier.AbortReasonRateLimited,
		carrier.AbortReasonRateLimited,
		carrier.AbortReasonRateLimited,
		carrier.AbortReasonRateLimited,
		carrier.AbortReasonRateLimited,
	}
	lines, triggers := ncFileTrail(padded, carrier.AbortReasons())
	run := ncSmoke(t, lines, triggers, ncCanonicalInjectors(), 13)
	report, err := run.buildCoverage()
	if err != nil {
		t.Fatal(err)
	}
	results := ncAssertionMap(t, report)

	counts, present := results["h3_terminal_counts_exact"]
	if !present {
		t.Fatal("h3_terminal_counts_exact assertion is missing entirely")
	}
	if !counts.Passed {
		t.Fatalf(
			"the count column must still balance under padding — that is "+
				"the whole point of the multiset check: %s", counts.Detail,
		)
	}
	reasonSet, present := results["h3_abort_reason_set_exact"]
	if !present {
		t.Fatal(
			"h3_abort_reason_set_exact assertion is missing entirely: " +
				"deleting it would wave five copies of one reason through",
		)
	}
	if reasonSet.Passed {
		t.Fatal("five copies of carrier_rate_limited passed the real buildCoverage")
	}
	if report.AllAssertionsPassed {
		t.Fatal("AllAssertionsPassed=true on a padded run")
	}
}

// A sealed record whose class is outside the closed set must be a hard error
// from buildCoverage, not a silently skipped line.
func TestNegativeControlRealBuildCoverageRejectsUnknownTerminalClass(
	t *testing.T,
) {
	lines, triggers := ncBalancedFileTrail()
	lines = append(lines, ncTerminalLine(
		len(lines)+1, "carrier_h3_aborted", "renegotiated",
		carrier.AbortReasonRateLimited,
		fmt.Sprintf("%032x", 99), fmt.Sprintf("%032x", 1099),
	))
	run := ncSmoke(t, lines, triggers, ncCanonicalInjectors(), 13)
	if _, err := run.buildCoverage(); err == nil ||
		!strings.Contains(err.Error(), "unhandled class") {
		t.Fatalf("unknown terminal class was not rejected: %v", err)
	}
}

// A sealed record whose event name is outside the carrier_h3_/carrier_h2_
// prefixes must be a hard error from buildCoverage, not a silently skipped
// line. Measured 2026-08-12: with continue in the default arm, this trail
// produced err=<nil> and left every count-based assertion green.
func TestNegativeControlRealBuildCoverageRejectsUnknownEventName(
	t *testing.T,
) {
	lines, triggers := ncBalancedFileTrail()
	lines = append(lines, ncTerminalLine(
		len(lines)+1, "metrics_tick", "authenticated",
		"none",
		fmt.Sprintf("%032x", 99), fmt.Sprintf("%032x", 1099),
	))
	run := ncSmoke(t, lines, triggers, ncCanonicalInjectors(), 13)
	if _, err := run.buildCoverage(); err == nil ||
		!strings.Contains(err.Error(), "unhandled event") {
		t.Fatalf("unknown event name was not rejected: %v", err)
	}
}

// --- Codex control: a missing injector ---------------------------------------

// F5: the run pins exactly two injectors with canonical names, fail events,
// and refusals=1. An injector that was attached to a handler but never added
// to the tracked list must produce a present-and-FAILING entry — never a
// silently absent one — and the whole coverage must fail.
func TestNegativeControlMissingInjectorMustFailCoverage(t *testing.T) {
	renamed := ncCanonicalInjectors()
	renamed[1].name = "renamed_sink"
	extra := append(
		ncCanonicalInjectors(),
		&oneShotFailingSink{name: "third_sink", failEvent: "carrier_h3_open"},
	)
	cases := map[string][]*oneShotFailingSink{
		"H2SinkNeverRegistered":    ncCanonicalInjectors()[:1],
		"NoInjectorRegistered":     nil,
		"NonCanonicalInjectorName": renamed,
		"ThirdUnplannedInjector":   extra,
	}

	for name, injectors := range cases {
		t.Run(name, func(t *testing.T) {
			lines, triggers := ncBalancedFileTrail()
			run := ncSmoke(t, lines, triggers, injectors, 13)
			report, err := run.buildCoverage()
			if err != nil {
				// A hard error is an acceptable rejection.
				return
			}
			if report.AllAssertionsPassed {
				t.Fatal(
					"a run whose injector list is not exactly the two " +
						"canonical fault injectors produced " +
						"AllAssertionsPassed=true",
				)
			}
			results := ncAssertionMap(t, report)
			schema, present := results["fault_injector_schema_exact"]
			if !present {
				t.Fatal("fault_injector_schema_exact assertion is missing")
			}
			if schema.Passed {
				t.Fatalf(
					"injector schema pin passed over a non-canonical "+
						"injector list: %s", schema.Detail,
				)
			}
			// Both canonical injectors must have present entries even when
			// unregistered: absence must never read as success.
			for _, canonical := range []string{
				"fault_injector_fired_h3_audit_unavailable_sink",
				"fault_injector_fired_h2_audit_unavailable_sink",
			} {
				if _, ok := results[canonical]; !ok {
					t.Fatalf(
						"%s is absent from the report; a missing injector "+
							"must produce a failing entry, not no entry",
						canonical,
					)
				}
			}
		})
	}
}

// --- Codex control: reconcile wrong/late event --------------------------------

// ncReconcileSmoke returns a real smoke pointed at a temp sealed trail, with
// the production-default timing bounds shortened through the same fields the
// production run() sets, so each negative case completes in bounded time.
func ncReconcileSmoke(t *testing.T, lines []string) *smoke {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, auditLogName),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	return &smoke{
		evidenceDirectory: directory,
		settleWindow:      200 * time.Millisecond,
		recordWait:        2 * time.Second,
	}
}

func TestNegativeControlReconcileAcceptsTheExactSealedSequence(t *testing.T) {
	correlation := fmt.Sprintf("%032x", 7)
	session := fmt.Sprintf("%032x", 1007)
	run := ncReconcileSmoke(t, []string{
		ncTerminalLine(1, carrier.EventH3Authenticated,
			"authenticated", "none", correlation, session),
		ncTerminalLine(2, carrier.EventH3Aborted,
			"aborted", carrier.AbortReasonRateLimited, correlation, session),
	})
	entry := &trigger{
		Name:           "nc_exact",
		Carrier:        "h3",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonRateLimited),
	}
	if err := run.reconcile(entry); err != nil {
		t.Fatalf("real reconcile rejected an exact sealed sequence: %v", err)
	}
	if !entry.Reconciled || entry.Correlation != correlation {
		t.Fatalf("reconcile did not bind the sealed correlation: %+v", entry)
	}
	if run.consumed != 2 {
		t.Fatalf("reconcile consumed %d records, want 2", run.consumed)
	}
}

// The sealed abort reason differs from the declared one. Merely driving the
// request and printing the intended reason would pass; the real reconcile
// must compare against what was actually sealed.
func TestNegativeControlReconcileRejectsWrongSealedReason(t *testing.T) {
	correlation := fmt.Sprintf("%032x", 8)
	session := fmt.Sprintf("%032x", 1008)
	run := ncReconcileSmoke(t, []string{
		ncTerminalLine(1, carrier.EventH3Authenticated,
			"authenticated", "none", correlation, session),
		ncTerminalLine(2, carrier.EventH3Aborted,
			"aborted", carrier.AbortReasonInvalidCarrierMTU, correlation, session),
	})
	entry := &trigger{
		Name:           "nc_wrong_reason",
		Carrier:        "h3",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonRateLimited),
	}
	err := run.reconcile(entry)
	if err == nil {
		t.Fatal("a sealed reason differing from the declared one was accepted")
	}
	if !strings.Contains(err.Error(), "record 2 is") {
		t.Fatalf("rejection does not name the offending record: %v", err)
	}
}

// A late terminal record appended DURING the settle window — after the
// expected count was already satisfied — must invalidate the request. This is
// the specific duplicate-terminal race the settle window exists to catch.
func TestNegativeControlReconcileRejectsLateExtraRecord(t *testing.T) {
	correlation := fmt.Sprintf("%032x", 9)
	session := fmt.Sprintf("%032x", 1009)
	run := ncReconcileSmoke(t, []string{
		ncTerminalLine(1, carrier.EventH3Authenticated,
			"authenticated", "none", correlation, session),
		ncTerminalLine(2, carrier.EventH3Aborted,
			"aborted", carrier.AbortReasonRateLimited, correlation, session),
	})
	appended := make(chan error, 1)
	go func() {
		time.Sleep(run.settleFor() / 4)
		file, err := os.OpenFile(
			filepath.Join(run.evidenceDirectory, auditLogName),
			os.O_APPEND|os.O_WRONLY, 0o600,
		)
		if err != nil {
			appended <- err
			return
		}
		defer file.Close()
		_, err = file.WriteString(ncTerminalLine(
			3, carrier.EventH3Aborted, "aborted",
			carrier.AbortReasonRateLimited, correlation, session,
		) + "\n")
		appended <- err
	}()
	entry := &trigger{
		Name:           "nc_late_extra",
		Carrier:        "h3",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonRateLimited),
	}
	err := run.reconcile(entry)
	if writeErr := <-appended; writeErr != nil {
		t.Fatalf("late append failed to execute: %v", writeErr)
	}
	if err == nil {
		t.Fatal("a terminal record appended inside the settle window was accepted")
	}
	if !strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("late-record rejection has the wrong shape: %v", err)
	}
}

// Two sealed records under different correlation identities cannot satisfy
// one request's expectation.
func TestNegativeControlReconcileRejectsSplitCorrelation(t *testing.T) {
	session := fmt.Sprintf("%032x", 1010)
	run := ncReconcileSmoke(t, []string{
		ncTerminalLine(1, carrier.EventH3Authenticated,
			"authenticated", "none", fmt.Sprintf("%032x", 10), session),
		ncTerminalLine(2, carrier.EventH3Aborted,
			"aborted", carrier.AbortReasonRateLimited,
			fmt.Sprintf("%032x", 11), session),
	})
	entry := &trigger{
		Name:           "nc_split_correlation",
		Carrier:        "h3",
		ExpectedEvents: abortEvents("h3", carrier.AbortReasonRateLimited),
	}
	err := run.reconcile(entry)
	if err == nil {
		t.Fatal("records under two correlation identities were accepted as one request")
	}
	if !strings.Contains(err.Error(), "different correlation identity") {
		t.Fatalf("split-correlation rejection has the wrong shape: %v", err)
	}
}

// --- Codex control: wrong/missing artifact and source digests (F4 + F7) ------

// requireBinding is the smoke-side fail-closed gate: reviewed artifact digest,
// runner-computed source-manifest digest, and the executable's own ldflags
// stamp must all be present, well formed, and mutually consistent BEFORE any
// evidence exists.
func TestNegativeControlRequireBindingFailsClosed(t *testing.T) {
	stamp := strings.Repeat("ad", 32)
	valid := strings.Repeat("c", 64)

	t.Run("AllBoundAccepted", func(t *testing.T) {
		ncStampSource(t, stamp)
		if err := requireBinding(valid, stamp); err != nil {
			t.Fatalf("a fully bound invocation was refused: %v", err)
		}
	})
	t.Run("MissingBinaryDigest", func(t *testing.T) {
		ncStampSource(t, stamp)
		err := requireBinding("", stamp)
		if err == nil ||
			!strings.Contains(err.Error(), "-expected-binary-sha256 is required") {
			t.Fatalf("missing binary digest not refused: %v", err)
		}
	})
	t.Run("MalformedBinaryDigest", func(t *testing.T) {
		ncStampSource(t, stamp)
		for _, malformed := range []string{
			strings.Repeat("C", 64), // upper case
			strings.Repeat("c", 63), // short
			strings.Repeat("z", 64), // not hex
		} {
			if err := requireBinding(malformed, stamp); err == nil {
				t.Fatalf("malformed binary digest %q accepted", malformed)
			}
		}
	})
	t.Run("MissingSourceDigest", func(t *testing.T) {
		ncStampSource(t, stamp)
		err := requireBinding(valid, "")
		if err == nil ||
			!strings.Contains(err.Error(), "-expected-source-digest is required") {
			t.Fatalf("missing source digest not refused: %v", err)
		}
	})
	t.Run("WrongSourceDigest", func(t *testing.T) {
		ncStampSource(t, stamp)
		err := requireBinding(valid, strings.Repeat("0", 64))
		if err == nil ||
			!strings.Contains(err.Error(), "built from source manifest") {
			t.Fatalf("wrong source digest not refused: %v", err)
		}
	})
	t.Run("UnstampedBuildRefused", func(t *testing.T) {
		ncStampSource(t, "")
		err := requireBinding(valid, stamp)
		if err == nil || !strings.Contains(err.Error(), "not stamped") {
			t.Fatalf("unstamped build not refused: %v", err)
		}
	})
	t.Run("SentinelStampRefused", func(t *testing.T) {
		// The old honest-but-unenforced sentinel must never satisfy the gate.
		ncStampSource(t, "unstamped-non-release-build")
		if err := requireBinding(valid, stamp); err == nil {
			t.Fatal("the unstamped-non-release-build sentinel passed binding")
		}
	})
}

// A wrong runner-supplied binary digest must stop run() before ANY evidence
// exists: no directory, no partial trail a later invocation could mistake for
// a run. The loopback backend below would fail fast anyway, but the error
// must come from the digest gate, which is ordered first.
func TestNegativeControlRunRejectsWrongBinaryDigest(t *testing.T) {
	stamp := strings.Repeat("ad", 32)
	ncStampSource(t, stamp)
	base := t.TempDir()
	evidence := filepath.Join(base, "evidence")
	work := filepath.Join(base, "work")
	err := run(evidence, work, "127.0.0.1:9", strings.Repeat("0", 64), stamp)
	if err == nil {
		t.Fatal("a wrong expected binary digest was accepted")
	}
	if !strings.Contains(err.Error(), "running executable SHA-256") {
		t.Fatalf("wrong-digest rejection has the wrong shape: %v", err)
	}
	if _, statErr := os.Stat(evidence); !os.IsNotExist(statErr) {
		t.Fatal("evidence directory was created despite the digest refusal")
	}
}

// An EMPTY expected binary digest must be rejected as missing, not treated as
// "no opinion" (the pre-F4 behavior this control exists to keep dead).
func TestNegativeControlRunRequiresBinaryDigest(t *testing.T) {
	stamp := strings.Repeat("ad", 32)
	ncStampSource(t, stamp)
	base := t.TempDir()
	evidence := filepath.Join(base, "evidence")
	work := filepath.Join(base, "work")
	err := run(evidence, work, "127.0.0.1:9", "", stamp)
	if err == nil {
		t.Fatal("run() succeeded with no expected binary digest at all")
	}
	if strings.Contains(err.Error(), "reachable on this host") {
		t.Fatalf(
			"REGRESSION to pre-F4 behavior: an empty expected binary digest "+
				"was accepted and execution reached the backend gate: %v", err,
		)
	}
	if !strings.Contains(err.Error(), "-expected-binary-sha256 is required") {
		t.Fatalf("missing-digest rejection has the wrong shape: %v", err)
	}
	if _, statErr := os.Stat(evidence); !os.IsNotExist(statErr) {
		t.Fatal("evidence directory was created despite the missing digest")
	}
}

// Positive ordering control: with binding fully satisfied (the test binary's
// own digest and a matching stamp), run() must fail NEXT at the
// backend-reachability gate when handed a loopback backend — proving the
// binding gates admitted the run and are ordered before any evidence work,
// without paying for a full QUIC smoke.
func TestNegativeControlRunBindingAdmitsThroughToBackendGate(t *testing.T) {
	stamp := strings.Repeat("ad", 32)
	ncStampSource(t, stamp)
	self, err := selfDigest()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	evidence := filepath.Join(base, "evidence")
	work := filepath.Join(base, "work")
	err = run(evidence, work, "127.0.0.1:9", self, stamp)
	if err == nil {
		t.Fatal("a loopback backend was accepted as unroutable")
	}
	if !strings.Contains(err.Error(), "reachable on this host") {
		t.Fatalf(
			"expected the backend-reachability gate to speak after binding "+
				"passed, got: %v", err,
		)
	}
	if _, statErr := os.Stat(evidence); !os.IsNotExist(statErr) {
		t.Fatal("evidence directory was created before the backend precondition")
	}
}
