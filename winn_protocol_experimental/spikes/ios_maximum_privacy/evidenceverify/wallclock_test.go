package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseCanonicalWallTimeAcceptsTheEmittedSpellings(t *testing.T) {
	for _, testCase := range []struct {
		value string
		want  time.Time
	}{
		{
			// What the seconds-resolution fixture emits.
			value: "2026-07-24T00:00:00Z",
			want:  time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC),
		},
		{
			// What ISO8601DateFormatter with .withFractionalSeconds emits on
			// the device: exactly three fractional digits, trailing zeros
			// intact.
			value: "2026-07-24T00:00:01.000Z",
			want:  time.Date(2026, 7, 24, 0, 0, 1, 0, time.UTC),
		},
		{
			value: "2026-07-24T12:34:56.123456789Z",
			want: time.Date(
				2026, 7, 24, 12, 34, 56, 123456789, time.UTC,
			),
		},
	} {
		parsed, err := parseCanonicalWallTime(testCase.value)
		if err != nil {
			t.Fatalf("%q: %v", testCase.value, err)
		}
		if !parsed.Equal(testCase.want) {
			t.Fatalf("%q parsed as %s, want %s",
				testCase.value, parsed, testCase.want)
		}
	}
}

func TestParseCanonicalWallTimeRejectsNonCanonicalSpellings(t *testing.T) {
	for _, value := range []string{
		"",
		"2026-07-24T00:00:00",             // no zone
		"2026-07-24T00:00:00+00:00",       // same instant, different bytes
		"2026-07-24T00:00:00z",            // lowercase zone
		"2026-07-24t00:00:00Z",            // lowercase separator
		"2026-7-24T00:00:00Z",             // unpadded month
		"2026-07-4T00:00:00Z",             // unpadded day
		"2026-07-24 00:00:00Z",            // space separator
		"2026-07-24T00:00:00.Z",           // dot with no digits
		"2026-07-24T00:00:00.1234567890Z", // ten fractional digits
		"2026-07-24T00:00:00,000Z",        // comma fraction
		"2026-07-24T00:00:00.00aZ",        // non-digit in the fraction
		// A signed fraction is the case strconv alone would accept: it parses
		// "+12000000" happily. Only the digit-only scan refuses it.
		"2026-07-24T00:00:00.+12Z",
		"2026-07-24T00:00:00.-12Z",
		"2026-7-24T00:00:00.0Z",  // unpadded month, same overall shape
		"2026-07-24T0:00:00.00Z", // unpadded hour, same overall shape
		"2026-02-30T00:00:00Z",   // day out of range
		"2026-13-01T00:00:00Z",   // month out of range
		"2026-07-24T24:00:00Z",   // hour out of range
		"1970-01-01T00:00:00Z",   // outside the plausibility window
		"2200-01-01T00:00:00Z",   // outside the plausibility window
	} {
		if _, err := parseCanonicalWallTime(value); err == nil {
			t.Fatalf("%q was accepted as canonical", value)
		}
	}
}

func TestVerifyRequiresACanonicalWallTimeOnEveryRecord(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].WallTimeUTC = "2026-07-24T00:01:00+00:00"
	writeTestRecordsAndRepin(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "literal UTC 'Z'") {
		t.Fatalf("non-canonical wall time error = %v", err)
	}
}

func TestVerifyRejectsAWallClockThatMovesBackwards(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	// Monotonic still advances by 60 s; only the wall clock is reversed. The
	// step is small enough that the consistency allowance alone would not
	// refuse it, so the ordering check is what has to fire.
	records[0].WallTimeUTC = "2026-07-24T00:00:02.000Z"
	records[1].WallTimeUTC = "2026-07-24T00:00:01.000Z"
	writeTestRecordsAndRepin(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "wall time moves backwards") {
		t.Fatalf("reversed wall clock error = %v", err)
	}
}

func TestVerifyRejectsAWallClockThatIgnoresTheMonotonicSpan(t *testing.T) {
	for name, wall := range map[string]string{
		// Sixty monotonic seconds elapsed; the wall clock claims none.
		"stalled": "2026-07-24T00:00:00.000Z",
		// ...and here it claims twenty minutes.
		"stretched": "2026-07-24T00:20:00.000Z",
	} {
		path, cfg := writeValidRun(t)
		records := decodeTestRecords(t, path)
		records[1].WallTimeUTC = wall
		writeTestRecordsAndRepin(t, path, cfg.startReceipt, records)
		if _, err := verify(cfg); err == nil ||
			!strings.Contains(
				err.Error(), wallClockConsistencyStatement,
			) {
			t.Fatalf("%s wall clock error = %v", name, err)
		}
	}
}

// Each adjacent step carries its own fixed allowance, so consistent-looking
// small steps can accumulate into a whole-run span the pairwise checks accept.
// This fixture is built so that BOTH adjacent comparisons pass and only the
// whole-run comparison refuses it, which is what makes that comparison
// independently load-bearing rather than a restatement of the pairwise ones.
func TestVerifyRejectsAccumulatedWallClockSkewOnlyTheWholeRunSees(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	intermediate := records[1]
	intermediate.Event = "sample-window"
	intermediate.MonotonicNanoseconds = 31_000_000_000
	intermediate.ResourceWindow = nil
	intermediate.WholeRunResourceWindow = nil
	records = []metricRecord{records[0], intermediate, records[1]}
	// Monotonic: 1 s, 31 s, 61 s. Wall: +0 s, +35 s, +70 s. Each 30 s step is
	// 5 s off against a 5.15 s allowance; the 60 s run is 10 s off against a
	// 5.3 s allowance.
	records[0].WallTimeUTC = "2026-07-24T00:00:00.000Z"
	records[1].WallTimeUTC = "2026-07-24T00:00:35.000Z"
	records[2].WallTimeUTC = "2026-07-24T00:01:10.000Z"
	writeTestRecordsAndRepin(t, path, cfg.startReceipt, records)
	err := verifyWallClock(records)
	if err == nil || !strings.Contains(err.Error(), "the whole run") {
		t.Fatalf("accumulated skew error = %v", err)
	}
	if _, err := verify(cfg); err == nil ||
		!strings.Contains(err.Error(), "the whole run") {
		t.Fatalf("accumulated skew is not refused end to end: %v", err)
	}
}

// The allowance has to be wide enough for two clocks sampled microseconds
// apart, and this proves the gate does not fire on a run that is merely
// imprecise. Without it, a mutation that shrank the allowance to zero would
// still leave every rejection test green.
func TestVerifyToleratesSmallWallClockSkew(t *testing.T) {
	path, cfg := writeValidRun(t)
	records := decodeTestRecords(t, path)
	records[1].WallTimeUTC = "2026-07-24T00:01:03.400Z"
	writeTestRecordsAndRepin(t, path, cfg.startReceipt, records)
	if _, err := verify(cfg); err != nil {
		t.Fatalf("3.4 s of skew over 60 s must be tolerated: %v", err)
	}
}

// writeTestRecordsAndRepin writes records verbatim — no wall-clock
// re-derivation — and repins the start receipt to the resulting first line, so
// a wall-clock test fails on the wall clock rather than on the digest.
func writeTestRecordsAndRepin(
	t *testing.T,
	path string,
	receiptPath string,
	records []metricRecord,
) {
	t.Helper()
	writeTestRecords(t, path, records)
	writeStartReceipt(t, receiptPath, startReceiptFor(t, path, records))
}
