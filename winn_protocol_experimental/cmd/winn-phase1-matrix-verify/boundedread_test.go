// True oversize rejection for every streaming parser.
//
// The failure these guard against is specific and quiet: io.LimitReader stops
// at N and reports a clean EOF, so a parser built on it accepts the first N
// bytes as the whole file. Because the prefix of a valid document is usually
// still a valid document, the parser then reports SUCCESS over content it never
// read — a duplicate key, an extra manifest line, additional audit records, all
// invisible.
//
// Every case below is therefore a valid-looking prefix filled to the limit
// followed by a FORBIDDEN tail past it: content that would change the parser's
// verdict if it were read. A parser that accepts the prefix is accepting a
// different document than the one on disk.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// padToExactly grows head with fixed-width filler lines until the result is
// EXACTLY size bytes, absorbing the remainder into the final line's value so
// the padding stays syntactically valid for the format under test. Ragged
// padding would make the prefix invalid and the test would then pass for the
// wrong reason.
func padToExactly(
	t *testing.T,
	head string,
	size int,
	line func(index int, extra int) string,
) string {
	t.Helper()
	if len(head) > size {
		t.Fatalf("head is already %d bytes, over %d", len(head), size)
	}
	unit := len(line(0, 0))
	var builder strings.Builder
	builder.WriteString(head)
	index := 0
	for size-builder.Len() >= 2*unit {
		builder.WriteString(line(index, 0))
		index++
	}
	remaining := size - builder.Len()
	if remaining > 0 {
		if remaining < unit {
			t.Fatalf(
				"cannot land exactly on %d: %d bytes left, minimum line is %d",
				size, remaining, unit,
			)
		}
		builder.WriteString(line(index, remaining-unit))
	}
	if builder.Len() != size {
		t.Fatalf("padded to %d bytes, want exactly %d", builder.Len(), size)
	}
	return builder.String()
}

// TestParseKeyValueFileRejectsAForbiddenTailPastTheLimit covers matrix.env,
// COMPLETE, batch records and evidence key/value files.
//
// The tail is a DUPLICATE KEY — which the parser rejects when it sees it, and
// which a truncating reader would never see.
func TestParseKeyValueFileRejectsAForbiddenTailPastTheLimit(t *testing.T) {
	const limit = 64 << 10
	directory := t.TempDir()
	path := filepath.Join(directory, "matrix.env")

	head := "schema=winn-phase1-auto-matrix/v3\nmatrix_id=phase1-auto-v1\n"
	body := padToExactly(t, head, limit, func(index, extra int) string {
		return fmt.Sprintf(
			"filler%06d=%s\n", index, strings.Repeat("v", 5+extra),
		)
	})
	// Exactly at the limit: accepted, and the duplicate is absent.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeyValueFile(path); err != nil {
		t.Fatalf("a file exactly at the limit was refused: %v", err)
	}

	// The same valid prefix, plus a forbidden tail one byte past the limit.
	withTail := body + "matrix_id=IMPERSONATED\n"
	if err := os.WriteFile(path, []byte(withTail), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := parseKeyValueFile(path)
	if err == nil {
		t.Fatalf(
			"a %d-byte file was parsed as its first %d bytes; the duplicate "+
				"matrix_id past the limit was never seen, and the parser "+
				"returned matrix_id=%q as though the file said so",
			len(withTail), limit, values["matrix_id"],
		)
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestVerifyEvidenceManifestRejectsAForbiddenTailPastTheLimit covers the
// manifest scanner. The tail names a COVERED FILE THAT DOES NOT EXIST, which
// the parser rejects the moment it sees it — and which a truncating reader
// never sees.
func TestVerifyEvidenceManifestRejectsAForbiddenTailPastTheLimit(t *testing.T) {
	const limit = 4 << 20
	directory := t.TempDir()

	// Every filler line names a real file with a matching digest, so the padded
	// prefix is a perfectly valid manifest on its own. That is the condition
	// that makes a truncating reader dangerous rather than merely wrong.
	content := []byte("filler\n")
	writeCovered := func(name string) string {
		t.Helper()
		if err := os.WriteFile(
			filepath.Join(directory, name), content, 0o600,
		); err != nil {
			t.Fatal(err)
		}
		digest, err := sha256File(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	// "<64 hex>  ./<name>\n"
	lineWidth := func(name string) int { return 64 + 2 + 2 + len(name) + 1 }

	shortName := "filler.txt"
	shortDigest := writeCovered(shortName)
	shortLine := shortDigest + "  ./" + shortName + "\n"

	var builder strings.Builder
	for limit-builder.Len() >= 2*lineWidth(shortName) {
		builder.WriteString(shortLine)
	}
	// The final line's FILENAME absorbs the remainder, so the manifest lands on
	// exactly the limit with every line still valid.
	remaining := limit - builder.Len()
	tailName := "f" + strings.Repeat("x", remaining-lineWidth("f"))
	tailDigest := writeCovered(tailName)
	builder.WriteString(tailDigest + "  ./" + tailName + "\n")
	body := builder.String()
	if len(body) != limit {
		t.Fatalf("manifest is %d bytes, want exactly %d", len(body), limit)
	}

	manifest := filepath.Join(directory, "evidence-manifest.sha256")

	// Exactly at the limit: accepted.
	if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEvidenceManifest(directory); err != nil {
		t.Fatalf("a manifest exactly at the limit was refused: %v", err)
	}

	// The same valid prefix, plus a forbidden tail past the limit.
	tail := strings.Repeat("a", 64) + "  ./absent-file.txt\n"
	if err := os.WriteFile(
		manifest, []byte(body+tail), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	err := verifyEvidenceManifest(directory)
	if err == nil {
		t.Fatalf(
			"a manifest of %d bytes was accepted after reading only its first "+
				"%d; the covered-but-absent file past the limit was never "+
				"checked", len(body)+len(tail), limit,
		)
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf(
			"the manifest was refused, but not by the size bound: %v", err,
		)
	}
}

// TestBoundedReaderDistinguishesExactlyAtTheLimitFromOverIt is the primitive's
// own boundary, asserted directly so no parser test has to carry it.
func TestBoundedReaderDistinguishesExactlyAtTheLimitFromOverIt(t *testing.T) {
	const limit = 1024
	for _, test := range []struct {
		name     string
		size     int
		exceeded bool
	}{
		{"one_under", limit - 1, false},
		{"exactly_at", limit, false},
		{"one_over", limit + 1, true},
		{"far_over", limit * 8, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			bounded := newBoundedReader(
				strings.NewReader(strings.Repeat("x", test.size)), limit,
			)
			buffer := make([]byte, 128)
			for {
				_, err := bounded.Read(buffer)
				if err != nil {
					break
				}
			}
			if bounded.exceeded() != test.exceeded {
				t.Fatalf(
					"a %d-byte input over a %d-byte limit reported "+
						"exceeded=%v, want %v",
					test.size, limit, bounded.exceeded(), test.exceeded,
				)
			}
			err := bounded.check("the input")
			if test.exceeded && err == nil {
				t.Fatal("an oversized input was accepted")
			}
			if !test.exceeded && err != nil {
				t.Fatalf("an input within the limit was refused: %v", err)
			}
		})
	}
}

// TestProfileParsingRejectsAForbiddenTailPastTheLimit covers the JSON profile
// decoder.
//
// The tail is a SECOND JSON VALUE, which requireEOF rejects when it sees it. A
// truncating reader hands the decoder a complete first object followed by EOF,
// so requireEOF is satisfied and the extra document is never noticed.
func TestProfileParsingRejectsAForbiddenTailPastTheLimit(t *testing.T) {
	const limit = 1 << 20
	directory := t.TempDir()
	path := filepath.Join(directory, "profiles.json")

	document := `{"schema":"winn-phase1-auto-impairment-profiles/v1",` +
		`"protocol_version":"winn/3",` +
		`"attempts_per_readiness_per_profile":1000,` +
		`"readiness_classes":["warm","cold"],` +
		`"profiles":[{"id":"baseline","rtt_millis":0,"loss_fraction":0,` +
		`"capacity_mbps":0,"purpose":"control"}],` +
		`"score_gate":{"failures":0,"p50_millis_max":1,"p95_millis_max":1,` +
		`"p99_millis_max":1,"individual_attempt_millis_max":1},` +
		`"frozen_at_utc":"2026-07-26T00:00:00Z",` +
		`"measurement_rule":{},"traffic_control_rule":{}}`
	// Trailing whitespace after a complete JSON value is legal, so the padded
	// prefix is a perfectly valid document in its own right.
	body := document + strings.Repeat(" ", limit-len(document))
	if len(body) != limit {
		t.Fatalf("padded to %d bytes, want %d", len(body), limit)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadProfiles(path); err != nil {
		t.Fatalf("a profile document exactly at the limit was refused: %v", err)
	}

	if err := os.WriteFile(
		path, []byte(body+`{"smuggled":true}`), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadProfiles(path)
	if err == nil {
		t.Fatal(
			"a profile file carrying a second JSON document past the limit " +
				"was accepted; the decoder saw a clean EOF at the limit and " +
				"requireEOF was satisfied over content it never read",
		)
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("refused, but not by the size bound: %v", err)
	}

	// The case where the truncated remainder PARSES CLEANLY.
	//
	// The reader delivers limit+1 bytes, so the cut normally lands mid-token
	// and the parser rejects the fragment — meaning the parse-error path, not
	// the end-of-parse check, does the observable work. Here the tail begins
	// with whitespace, which is legal trailing content after a complete JSON
	// value: the decoder finishes, requireEOF is satisfied, and nothing in the
	// parse detects anything wrong. Only the end-of-parse bound check remains,
	// which is what makes it load-bearing rather than defensive decoration.
	if err := os.WriteFile(
		path, []byte(body+" "+`{"smuggled":true}`), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, _, err = loadProfiles(path)
	if err == nil {
		t.Fatal(
			"a profile file whose truncated remainder parsed cleanly was " +
				"accepted; the smuggled second document past the limit was " +
				"never seen by anything",
		)
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("refused, but not by the size bound: %v", err)
	}
}

// TestScheduleParsingRejectsAForbiddenTailPastTheLimit covers the schedule
// scanner with a GENUINELY VALID oversized schedule.
//
// Every row satisfies every rule the parser enforces — block ordering, per-block
// cell uniqueness, ascending order digests, derived batch keys, exact attempt
// counts — so the parser runs the whole file and the only thing that can reject
// it is the size bound. A fixture with invalid rows would fail on the first row
// and the test would pass for the wrong reason.
func TestScheduleParsingRejectsAForbiddenTailPastTheLimit(t *testing.T) {
	const limit = 4 << 20
	const batchSize = 100
	const blocks = 1200

	readinessClasses := []string{"warm", "cold"}
	var profileIDs []string
	for index := 0; index < 20; index++ {
		profileIDs = append(profileIDs, fmt.Sprintf("p%02d", index))
	}
	profiles := profileDocument{
		AttemptsPerReadinessPerProfile: blocks * batchSize,
		BatchSize:                      batchSize,
		ReadinessClasses:               readinessClasses,
	}
	for _, id := range profileIDs {
		profiles.Profiles = append(profiles.Profiles, networkProfile{ID: id})
	}

	type row struct {
		digest string
		text   string
	}
	var builder strings.Builder
	for block := 1; block <= blocks; block++ {
		var rows []row
		for _, id := range profileIDs {
			for _, readiness := range readinessClasses {
				sum := sha256.Sum256([]byte(fmt.Sprintf(
					"%s:%d:%s:%s",
					profiles.ScheduleSeed, block, id, readiness,
				)))
				digest := hex.EncodeToString(sum[:])
				rows = append(rows, row{
					digest: digest,
					text: fmt.Sprintf(
						"%d\t%s\t%s--%s--b%03d\t%s\t%s\t%d\n",
						block, digest, id, readiness, block,
						id, readiness, batchSize,
					),
				})
			}
		}
		// Strictly ascending order digests within the block.
		sort.Slice(rows, func(one, two int) bool {
			return rows[one].digest < rows[two].digest
		})
		for _, current := range rows {
			builder.WriteString(current.text)
		}
	}
	body := builder.String()
	if len(body) <= limit {
		t.Fatalf(
			"the fixture schedule is %d bytes, which does not exceed the "+
				"%d-byte limit under test", len(body), limit,
		)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "schedule.tsv")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadV2Schedule(path, profiles)
	if err == nil {
		t.Fatal(
			"an oversized schedule was accepted; the parser read a prefix of " +
				"it and treated the rows it happened to see as the whole " +
				"frozen schedule",
		)
	}
	if !strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf(
			"the schedule was refused, but not by the size bound: %v", err,
		)
	}

	// The same schedule truncated to a whole number of rows within the limit
	// parses without any size complaint, proving the rows themselves are valid
	// and the rejection above was genuinely the bound.
	cut := 0
	for index := 0; index < len(body) && index <= limit; index++ {
		if body[index] == '\n' {
			cut = index + 1
		}
	}
	short := filepath.Join(directory, "short.tsv")
	if err := os.WriteFile(short, []byte(body[:cut]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadV2Schedule(short, profiles); err != nil &&
		strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("a schedule within the limit was refused for size: %v", err)
	}
}

// carrierAuditLine renders one syntactically valid sealed carrier record.
func carrierAuditLine(t *testing.T, sequence int, previous string) (string, string) {
	t.Helper()
	authentication := fmt.Sprintf("%064x", sequence)
	session := fmt.Sprintf("%032x", sequence)
	line := fmt.Sprintf(
		`{"format":"winn-audit-hmac-sha256/v1","sequence":%d,`+
			`"timestamp":"2026-07-26T00:00:00.000000000Z",`+
			`"event":"carrier_h3_authenticated","device_hash":"%064x",`+
			`"request_id":"%s","detail":"carrier-terminal/v1 class=authenticated `+
			`mode=anonymous-token session=%s reason=none",`+
			`"previous_mac":"%s","authentication":"%s"}`+"\n",
		sequence, sequence, session, session, previous, authentication,
	)
	return line, authentication
}

// TestCarrierAuditScannersRejectAForbiddenTailPastTheLimit covers BOTH
// carrier-audit scanner paths with real input.
//
// The tail is an ADDITIONAL SEALED RECORD, which changes every count the
// conservation law and the abort-coverage attestation are computed from. A
// truncating reader reports a smaller, internally consistent trail — which is
// precisely the tail-truncation class this whole audit-close design exists to
// detect.
func TestCarrierAuditScannersRejectAForbiddenTailPastTheLimit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "carrier-audit.jsonl")

	// A small, valid trail; the limit is set to its exact length so the
	// production parser is driven at millisecond scale.
	var builder strings.Builder
	previous := carrierZeroMAC
	for sequence := 1; sequence <= 4; sequence++ {
		line, authentication := carrierAuditLine(t, sequence, previous)
		builder.WriteString(line)
		previous = authentication
	}
	body := builder.String()
	limit := int64(len(body))

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Exactly at the limit: both parsers read it without a size complaint.
	if _, err := recomputeCarrierAuditBounded(path, limit); err != nil &&
		strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("a trail exactly at the limit was refused for size: %v", err)
	}
	if _, err := requireForcedAbortCoverageBounded(path, limit); err != nil &&
		strings.Contains(err.Error(), "exceeds the") {
		t.Fatalf("a trail exactly at the limit was refused for size: %v", err)
	}

	// One more sealed record, past the limit.
	extra, _ := carrierAuditLine(t, 5, previous)
	if err := os.WriteFile(path, []byte(body+extra), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("recomputeCarrierAudit", func(t *testing.T) {
		_, err := recomputeCarrierAuditBounded(path, limit)
		if err == nil {
			t.Fatal(
				"an oversized trail was reconciled as though the records " +
					"within the limit were all of them",
			)
		}
		if !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("refused, but not by the size bound: %v", err)
		}
	})

	t.Run("requireForcedAbortCoverage", func(t *testing.T) {
		_, err := requireForcedAbortCoverageBounded(path, limit)
		if err == nil {
			t.Fatal(
				"an oversized trail passed abort-coverage over a prefix of " +
					"itself",
			)
		}
		if !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("refused, but not by the size bound: %v", err)
		}
	})
}

// The source-count invariant that used to live here has been REMOVED.
//
// It counted bounded-reader constructions against check calls per function. A
// mutation that deleted a required end-of-parse check while leaving a
// parse-error classify call in the same function kept the count balanced, so
// the invariant reported health over a function with a real hole in it — the
// precise false assurance it was supposed to prevent. A source check that can
// be satisfied without the property holding is worse than none, because it
// invites trusting it.
//
// The behavioural tests above are the proof: each drives the real parser with a
// valid prefix filled to the limit and a forbidden tail past it, and each is
// mutation-verified against the pre-fix parser.
