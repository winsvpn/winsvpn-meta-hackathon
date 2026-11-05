// Substrate-level adversarial coverage for scenario 6 of the 2026-07-26
// Codex/Sol ruling ("a post-auth failure concurrent with teardown") plus
// runnable demonstrations of WHY the sealed-evidence conservation law is
// mandatory: the audit HMAC chain alone cannot detect a lost or duplicated
// terminal record, so per-redemption terminal accounting must be enforced by
// the formal verifier over the sealed JSONL.
//
// These tests exercise the EXISTING internal/audit implementation (the shared
// recording substrate both the H2 and H3 carriers write terminal events
// through) and run today, independent of the parallel conservation-verifier
// implementation. Authored by the Fable 5 audit lane from the ruling text,
// not from any implementation in flight.
package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestChain(t *testing.T) (logPath, keyPath string) {
	t.Helper()
	directory := t.TempDir()
	keyPath = filepath.Join(directory, "audit.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "carrier-audit.jsonl"), keyPath
}

type chainLine struct {
	Event     string `json:"event"`
	RequestID string `json:"request_id"`
}

func readChainLines(t *testing.T, logPath string) []chainLine {
	t.Helper()
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(raw) == 1 && raw[0] == "" {
		return nil
	}
	lines := make([]chainLine, 0, len(raw))
	for index, line := range raw {
		var entry chainLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("chain line %d is not JSON: %v", index+1, err)
		}
		lines = append(lines, entry)
	}
	return lines
}

// TestConcurrentAbortAndTeardownNeverLosesAcknowledgedTerminals is the live
// race for scenario 6.
//
// Real-world failure mode: a request fails after authentication at the same
// moment the candidate/session (or the whole carrier process) is tearing
// down. The abort-recording path and the teardown/close path race into the
// shared audit sink, and the sink itself is being Closed under them. Three
// bad outcomes are possible in a broken substrate: an abort acknowledged to
// the caller yet missing from the file (lost terminal -> conservation breaks
// invisibly), a terminal present in the file that the caller was told failed
// (caller retries -> duplicate terminal), or interleaved partial writes that
// corrupt the chain.
//
// Correct behavior (asserted): recording is atomic per record and exactly
// acknowledgment-consistent — a nil return means the terminal is durably in
// the chain exactly once; an error return (including "audit log is closed"
// once teardown wins the race) means it is not there at all; and the
// resulting file always verifies as an unbroken HMAC chain.
//
// Broken behavior this would catch: torn/interleaved JSON lines, records
// acknowledged after Close raced the write, sequence discontinuities under
// contention, or double-appends for a single Record call.
//
// CONSEQUENCE PINNED HERE: when teardown wins, the abort caller receives an
// ERROR — the terminal is silently absent only if the carrier ignores that
// error. internal/carrier/h3.go:240 ignores exactly that return for
// carrier_h3_closed today, so the substrate CANNOT guarantee conservation on
// its own; the verifier-side equation is the required backstop.
func TestConcurrentAbortAndTeardownNeverLosesAcknowledgedTerminals(
	t *testing.T,
) {
	const writers = 64
	logPath, keyPath := newTestChain(t)
	log, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	acknowledged := make([]error, writers)
	var start, half sync.WaitGroup
	var finished sync.WaitGroup
	start.Add(1)
	half.Add(writers / 2)
	for index := 0; index < writers; index++ {
		finished.Add(1)
		go func(index int) {
			defer finished.Done()
			start.Wait()
			session := fmt.Sprintf("sess-%03d", index)
			event := "carrier_h3_aborted"
			if index%2 == 0 {
				event = "carrier_h3_closed"
			}
			acknowledged[index] = log.Record(
				event, "device-"+session, session, "teardown race terminal",
			)
			if index < writers/2 {
				half.Done()
			}
		}(index)
	}
	start.Done()
	// Teardown races the second half of the writers.
	half.Wait()
	closeErr := log.Close()
	finished.Wait()
	if closeErr != nil {
		t.Fatalf("teardown close failed: %v", closeErr)
	}
	// The surviving file must still be a fully valid chain.
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatalf(
			"chain is invalid after a concurrent abort/teardown race: %v",
			err,
		)
	}
	perSession := map[string]int{}
	for _, line := range readChainLines(t, logPath) {
		perSession[line.RequestID]++
	}
	for index := 0; index < writers; index++ {
		session := fmt.Sprintf("sess-%03d", index)
		present := perSession[session]
		if acknowledged[index] == nil && present != 1 {
			t.Fatalf(
				"terminal for %s was acknowledged but appears %d times; "+
					"an acknowledged terminal must be durable exactly once",
				session, present,
			)
		}
		if acknowledged[index] != nil && present != 0 {
			t.Fatalf(
				"terminal for %s returned error %v yet appears %d times; "+
					"a failed Record must leave no partial record behind",
				session, acknowledged[index], present,
			)
		}
	}
}

// TestChainAcceptsWholeRecordTruncationSoConservationMustCatchIt pins the
// substrate property that makes the ruling's conservation law load-bearing
// rather than redundant.
//
// Real-world failure mode: teardown (or a crash, or an attacker with brief
// filesystem access before sealing) removes whole trailing records from the
// audit log. Because the HMAC chain authenticates each record against its
// predecessor but carries NO termination marker, every prefix that ends on a
// record boundary is itself a perfectly valid chain.
//
// Asserted current behavior: Verify ACCEPTS the whole-record truncation
// (this is a documentation-of-gap test, not an endorsement — if a future
// change adds a sealed terminator record and this assertion starts failing,
// delete this subtest with a note, because the gap it documents is closed).
// Verify must still REJECT a mid-record truncation.
//
// Consequence: a lost terminal event at the end of the log is
// cryptographically invisible. Only recomputing
// "DB redemptions == authenticated == auth_only + open + aborted" and
// "open == closed" from the sealed JSONL can expose it. A verifier that
// says "HMAC chain verified, evidence is sound" without the equation is
// broken in exactly the way the ruling sustained.
func TestChainAcceptsWholeRecordTruncationSoConservationMustCatchIt(
	t *testing.T,
) {
	logPath, keyPath := newTestChain(t)
	log, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	script := [][3]string{
		{"carrier_h3_authenticated", "sess-A", "redeemed"},
		{"carrier_h3_open", "sess-A", "carrier open"},
		{"carrier_h3_closed", "sess-A", "carrier stream closed"},
		{"carrier_h3_authenticated", "sess-B", "redeemed"},
		{"carrier_h3_aborted", "sess-B", "awg_backend_unavailable"},
	}
	for _, entry := range script {
		if err := log.Record(
			entry[0], "device-"+entry[1], entry[1], entry[2],
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(content, []byte("\n"))
	// Drop the final record (sess-B's abort): the exact shape of a terminal
	// lost to teardown.
	truncated := bytes.Join(lines[:len(lines)-2], nil)
	if err := os.WriteFile(logPath, truncated, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatalf(
			"whole-record truncation was expected to be invisible to the "+
				"HMAC chain (no terminator record exists); if this now "+
				"fails the documented gap has been closed — update this "+
				"test and the conservation suite notes: %v",
			err,
		)
	}
	remaining := readChainLines(t, logPath)
	authenticatedCount, terminalCount := 0, 0
	for _, line := range remaining {
		switch line.Event {
		case "carrier_h3_authenticated":
			authenticatedCount++
		case "carrier_h3_auth_only", "carrier_h3_open", "carrier_h3_aborted":
			terminalCount++
		}
	}
	if authenticatedCount != 2 || terminalCount != 1 {
		t.Fatalf(
			"fixture drift: authenticated=%d terminals=%d, want 2 and 1",
			authenticatedCount, terminalCount,
		)
	}
	// Mid-record truncation, by contrast, must break the chain: cut inside
	// the final surviving record.
	if err := os.WriteFile(
		logPath, truncated[:len(truncated)-10], 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err == nil {
		t.Fatal("mid-record truncation must invalidate the chain")
	}
}

// TestChainAcceptsDuplicateTerminalRecordsSoVerifierMustReject pins that the
// substrate provides NO per-correlation exclusivity: two identical terminal
// records for one session chain perfectly. Deduplication therefore cannot be
// delegated to the HMAC layer — the conservation verifier must correlate
// per request_id and reject duplicate terminalization itself (scenario 2 of
// the ruling; the sealed-evidence tests live in
// cmd/winn-phase1-matrix-verify/conservation_adversarial_test.go).
func TestChainAcceptsDuplicateTerminalRecordsSoVerifierMustReject(
	t *testing.T,
) {
	logPath, keyPath := newTestChain(t)
	log, err := Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := log.Record(
			"carrier_h3_aborted",
			"device-sess-A",
			"sess-A",
			"carrier_rate_limited",
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Verify(logPath, keyPath); err != nil {
		t.Fatalf(
			"duplicate terminals were expected to chain cleanly "+
				"(dedup is the verifier's job, not the chain's): %v",
			err,
		)
	}
	lines := readChainLines(t, logPath)
	if len(lines) != 2 ||
		lines[0].RequestID != "sess-A" || lines[1].RequestID != "sess-A" {
		t.Fatalf("fixture drift: %+v", lines)
	}
}
