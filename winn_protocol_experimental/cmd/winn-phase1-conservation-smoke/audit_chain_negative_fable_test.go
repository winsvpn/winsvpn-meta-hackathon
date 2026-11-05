// Codex F6 negative control: HMAC/chain-integrity failure.
//
// The hardened AICORE wrapper runs cmd/winn-audit (audit.Verify) against the
// sealed carrier-audit.jsonl before the conservation report. These tests pin
// the exact rejection contract the wrapper depends on, over a carrier-shaped
// log, using the real internal/audit implementation end to end.
//
// internal/audit's own suite (TestAuditTamperingFailsClosed) already covers a
// tampered field value. It does NOT cover deletion, reordering, a torn final
// record, or — critically — tail truncation. The last test below pins the
// finding that a cleanly truncated tail is a valid chain prefix and PASSES
// audit.Verify: winn-audit alone cannot prove the log is complete. The sealed
// evidence-manifest.sha256 digest of carrier-audit.jsonl is the only defense
// against tail truncation, so the wrapper must verify the manifest as well,
// not just the HMAC chain. If audit.Verify is ever strengthened to detect
// truncation, that pin fails and this documentation must move with it.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/audit"
	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/securefile"
)

// ncAuditFixture writes a genuine five-record carrier-shaped audit chain with
// the real writer and returns its raw lines.
func ncAuditFixture(t *testing.T) (logPath, keyPath string, lines []string) {
	t.Helper()
	directory := t.TempDir()
	keyPath = filepath.Join(directory, "audit.key")
	logPath = filepath.Join(directory, auditLogName)
	if err := securefile.AtomicWrite(
		keyPath, bytes.Repeat([]byte{0x5a}, 32), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	events := []struct{ event, class, reason string }{
		{carrier.EventH3Authenticated, "authenticated", "none"},
		{carrier.EventH3AuthOnly, "auth_only", "none"},
		{carrier.EventH3Authenticated, "authenticated", "none"},
		{carrier.EventH3Aborted, "aborted", carrier.AbortReasonRateLimited},
		{carrier.EventH2Authenticated, "authenticated", "none"},
	}
	for index, current := range events {
		detail := schemaToken +
			" class=" + current.class +
			" mode=" + carrierAuthMode +
			" session=" + fmt.Sprintf("%032x", 2000+index) +
			" reason=" + current.reason
		if err := log.Record(
			current.event, labDeviceID,
			fmt.Sprintf("%032x", 3000+index), detail,
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != len(events) {
		t.Fatalf("fixture sealed %d lines, want %d", len(lines), len(events))
	}
	if err := audit.Verify(logPath, keyPath); err != nil {
		t.Fatalf("pristine fixture chain does not verify: %v", err)
	}
	return logPath, keyPath, lines
}

func ncWriteAuditLines(t *testing.T, logPath string, lines []string) {
	t.Helper()
	if err := os.WriteFile(
		logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeControlAuditVerifyRejectsTamperedRecord(t *testing.T) {
	logPath, keyPath, lines := ncAuditFixture(t)
	if !strings.Contains(lines[3], carrier.AbortReasonRateLimited) {
		t.Fatalf("fixture line 4 lacks the reason token: %s", lines[3])
	}
	lines[3] = strings.Replace(
		lines[3],
		"reason="+carrier.AbortReasonRateLimited,
		"reason="+carrier.AbortReasonAuditUnavailable,
		1,
	)
	ncWriteAuditLines(t, logPath, lines)
	err := audit.Verify(logPath, keyPath)
	if err == nil {
		t.Fatal("a rewritten abort reason passed HMAC verification")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tamper rejection has the wrong shape: %v", err)
	}
}

func TestNegativeControlAuditVerifyRejectsDeletedMiddleRecord(t *testing.T) {
	logPath, keyPath, lines := ncAuditFixture(t)
	deleted := append(append([]string{}, lines[:2]...), lines[3:]...)
	ncWriteAuditLines(t, logPath, deleted)
	if err := audit.Verify(logPath, keyPath); err == nil {
		t.Fatal("a deleted mid-log record passed chain verification")
	}
}

func TestNegativeControlAuditVerifyRejectsReorderedRecords(t *testing.T) {
	logPath, keyPath, lines := ncAuditFixture(t)
	lines[1], lines[2] = lines[2], lines[1]
	ncWriteAuditLines(t, logPath, lines)
	if err := audit.Verify(logPath, keyPath); err == nil {
		t.Fatal("reordered records passed chain verification")
	}
}

func TestNegativeControlAuditVerifyRejectsTornFinalRecord(t *testing.T) {
	logPath, keyPath, lines := ncAuditFixture(t)
	torn := strings.Join(lines[:len(lines)-1], "\n") + "\n" +
		lines[len(lines)-1][:len(lines[len(lines)-1])/2]
	if err := os.WriteFile(logPath, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := audit.Verify(logPath, keyPath); err == nil {
		t.Fatal("a torn (mid-record truncated) final record passed verification")
	}
}

// PINNED CONTRACT, deliberately: dropping whole records off the TAIL leaves a
// valid chain prefix, and audit.Verify ACCEPTS it. This is what makes the
// evidence manifest's digest of carrier-audit.jsonl load-bearing: the F6
// wrapper step (winn-audit) proves no record was altered, inserted, deleted
// mid-log, or reordered — it does NOT prove the log is complete. Completeness
// comes only from the manifest digest and the conservation equation itself.
// If this pin ever fails, audit.Verify has been strengthened; update the
// wrapper documentation and this test together.
func TestNegativeControlAuditVerifyAcceptsTailTruncationPinned(t *testing.T) {
	logPath, keyPath, lines := ncAuditFixture(t)
	ncWriteAuditLines(t, logPath, lines[:len(lines)-1])
	if err := audit.Verify(logPath, keyPath); err != nil {
		t.Fatalf(
			"audit.Verify now REJECTS a cleanly truncated tail (%v) — the "+
				"pinned contract changed; update the F6 wrapper rationale "+
				"and this pin together", err,
		)
	}
}
