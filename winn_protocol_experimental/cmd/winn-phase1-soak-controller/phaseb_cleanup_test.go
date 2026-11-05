package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainmentCleanupClosedValidation(t *testing.T) {
	validLinux := CycleContainmentCleanup{
		Schema:            linuxCgroupV2CleanupSchema,
		ChildCgroupInode:  42,
		FinalCgroupEvents: "populated 0\nfrozen 0\n",
		ChildRemoved:      true,
	}
	tests := []struct {
		name    string
		cleanup CycleContainmentCleanup
		valid   bool
	}{
		{"Linux", validLinux, true},
		{"non-applicable", nonApplicableContainmentCleanup(), true},
		{"missing", CycleContainmentCleanup{}, false},
		{"unknown schema", CycleContainmentCleanup{Schema: "unknown/v1"}, false},
		{"Linux zero inode", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, FinalCgroupEvents: "populated 0\n",
			ChildRemoved: true,
		}, false},
		{"Linux additional canonical events", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "frozen 0\npopulated 0\n", ChildRemoved: true,
		}, true},
		{"Linux empty events", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			ChildRemoved: true,
		}, false},
		{"Linux populated one", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated 1\n", ChildRemoved: true,
		}, false},
		{"Linux missing populated", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "frozen 0\n", ChildRemoved: true,
		}, false},
		{"Linux duplicate populated", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated 0\npopulated 0\n", ChildRemoved: true,
		}, false},
		{"Linux invalid populated type", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated false\n", ChildRemoved: true,
		}, false},
		{"Linux malformed spacing", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated  0\n", ChildRemoved: true,
		}, false},
		{"Linux unterminated", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated 0", ChildRemoved: true,
		}, false},
		{"Linux invalid UTF-8", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: string([]byte{'p', 'o', 'p', 'u', 'l', 'a', 't', 'e', 'd', ' ', '0', 0xff, '\n'}),
			ChildRemoved:      true,
		}, false},
		{"Linux oversized events", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: strings.Repeat("frozen 0\n", 456) + "populated 0\n",
			ChildRemoved:      true,
		}, false},
		{"Linux not removed", CycleContainmentCleanup{
			Schema: linuxCgroupV2CleanupSchema, ChildCgroupInode: 42,
			FinalCgroupEvents: "populated 0\n",
		}, false},
		{"mixed non-applicable inode", CycleContainmentCleanup{
			Schema: nonApplicableCleanupSchema, ChildCgroupInode: 42,
		}, false},
		{"mixed non-applicable events", CycleContainmentCleanup{
			Schema: nonApplicableCleanupSchema, FinalCgroupEvents: "populated 0\n",
		}, false},
		{"mixed non-applicable removal", CycleContainmentCleanup{
			Schema: nonApplicableCleanupSchema, ChildRemoved: true,
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateContainmentCleanup(test.cleanup)
			if test.valid && err != nil {
				t.Fatalf("valid cleanup refused: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatalf("invalid cleanup accepted: %+v", test.cleanup)
			}
		})
	}
}

func TestReceiptV2MemberOrderAndReplay(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "v2-order")
	if err != nil {
		t.Fatal(err)
	}
	receipt := validTestReceipt("v2-order", OutcomeSucceeded)
	if _, err := log.Append(receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(receipt); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "cycle-receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("got %d receipt lines, want 2", len(lines))
	}
	var previousIndex = -1
	for _, member := range receiptJSONMembers {
		index := bytes.Index(lines[0], []byte(`"`+member+`":`))
		if index < 0 {
			t.Fatalf("required member %q is absent from encoded receipt", member)
		}
		if index <= previousIndex {
			t.Fatalf("member %q is out of locked order in %s", member, lines[0])
		}
		previousIndex = index
	}
	if !bytes.Contains(
		lines[0],
		[]byte(`"schema":"winn-phase1-soak-cycle-receipt/v2"`),
	) {
		t.Fatalf("receipt does not carry exact v2 schema: %s", lines[0])
	}
	replayed, err := OpenReceiptLog(root, "v2-order")
	if err != nil {
		t.Fatalf("v2 chain did not replay: %v", err)
	}
	defer func() { _ = replayed.Close() }()
	if replayed.Count() != 2 {
		t.Fatalf("replayed %d v2 receipts, want 2", replayed.Count())
	}
}

func TestReceiptReplayRefusesLegacyV1AndMixedLogs(t *testing.T) {
	build := func(t *testing.T, count int) (string, []byte) {
		t.Helper()
		root := t.TempDir()
		log, err := OpenReceiptLog(root, "schema-replay")
		if err != nil {
			t.Fatal(err)
		}
		for range count {
			if _, err := log.Append(
				validTestReceipt("schema-replay", OutcomeSucceeded),
			); err != nil {
				t.Fatal(err)
			}
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "cycle-receipts.jsonl")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return path, raw
	}
	t.Run("legacy v1 cannot resume", func(t *testing.T) {
		path, raw := build(t, 1)
		legacy := bytes.Replace(
			raw,
			[]byte(`winn-phase1-soak-cycle-receipt/v2`),
			[]byte(`winn-phase1-soak-cycle-receipt/v1`),
			1,
		)
		if err := os.WriteFile(path, legacy, 0o600); err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), legacy...)
		if log, err := OpenReceiptLog(filepath.Dir(path), "schema-replay"); err == nil {
			_ = log.Close()
			t.Fatal("legacy v1 receipt log resumed")
		} else if !strings.Contains(err.Error(), "expected") {
			t.Fatalf("legacy refusal was not schema-specific: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("legacy replay refusal modified the sealed input log")
		}
	})
	t.Run("mixed v2 and v1 cannot resume", func(t *testing.T) {
		path, raw := build(t, 2)
		firstNewline := bytes.IndexByte(raw, '\n')
		if firstNewline < 0 {
			t.Fatal("two-line fixture has no line delimiter")
		}
		mixed := append([]byte(nil), raw...)
		tail := bytes.Replace(
			mixed[firstNewline+1:],
			[]byte(`winn-phase1-soak-cycle-receipt/v2`),
			[]byte(`winn-phase1-soak-cycle-receipt/v1`),
			1,
		)
		mixed = append(mixed[:firstNewline+1], tail...)
		if err := os.WriteFile(path, mixed, 0o600); err != nil {
			t.Fatal(err)
		}
		if log, err := OpenReceiptLog(filepath.Dir(path), "schema-replay"); err == nil {
			_ = log.Close()
			t.Fatal("mixed v2/v1 receipt log resumed")
		}
	})
}

func TestReceiptCleanupMemberIsExactRequiredAndBounded(t *testing.T) {
	buildLine := func(t *testing.T) (string, map[string]json.RawMessage) {
		t.Helper()
		root := t.TempDir()
		log, err := OpenReceiptLog(root, "cleanup-shape")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(
			validTestReceipt("cleanup-shape", OutcomeSucceeded),
		); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "cycle-receipts.jsonl")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(raw), &body); err != nil {
			t.Fatal(err)
		}
		return path, body
	}
	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
		want   string
	}{
		{"extra top-level member", func(body map[string]json.RawMessage) {
			body["containment_cleanup_extra"] = json.RawMessage(`true`)
		}, "unknown JSON member"},
		{"missing", func(body map[string]json.RawMessage) {
			delete(body, "containment_cleanup")
		}, `required JSON member "containment_cleanup"`},
		{"extra nested member", func(body map[string]json.RawMessage) {
			body["containment_cleanup"] = json.RawMessage(
				`{"schema":"winn-phase1-containment-not-applicable/v1",` +
					`"child_cgroup_inode":0,"final_cgroup_events":"",` +
					`"child_removed":false,"extra":true}`,
			)
		}, "unknown field"},
		{"missing nested member", func(body map[string]json.RawMessage) {
			body["containment_cleanup"] = json.RawMessage(
				`{"schema":"winn-phase1-containment-not-applicable/v1",` +
					`"child_cgroup_inode":0,"final_cgroup_events":""}`,
			)
		}, `required JSON member "child_removed"`},
		{"malformed nested type", func(body map[string]json.RawMessage) {
			body["containment_cleanup"] = json.RawMessage(
				`{"schema":"winn-phase1-containment-not-applicable/v1",` +
					`"child_cgroup_inode":"zero","final_cgroup_events":"",` +
					`"child_removed":false}`,
			)
		}, "cannot unmarshal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, body := buildLine(t)
			test.mutate(body)
			edited, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(edited, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if log, err := OpenReceiptLog(filepath.Dir(path), "cleanup-shape"); err == nil {
				_ = log.Close()
				t.Fatal("invalid cleanup member replayed")
			} else if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal %q does not contain %q", err, test.want)
			}
		})
	}

	root := t.TempDir()
	log, err := OpenReceiptLog(root, "cleanup-metadata-bound")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	receipt := validTestReceipt("cleanup-metadata-bound", OutcomeSucceeded)
	receipt.ContainmentCleanup = CycleContainmentCleanup{
		Schema: strings.Repeat("x", maximumReceiptMetadataBytes),
	}
	if _, err := log.Append(receipt); err == nil ||
		!strings.Contains(err.Error(), "metadata") {
		t.Fatalf("oversized cleanup metadata was not bounded: %v", err)
	}
}

func TestReceiptAcceptsBothClosedCleanupShapes(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "closed-cleanups")
	if err != nil {
		t.Fatal(err)
	}
	nonApplicable := validTestReceipt("closed-cleanups", OutcomeSucceeded)
	if _, err := log.Append(nonApplicable); err != nil {
		t.Fatalf("append explicit non-applicable cleanup: %v", err)
	}
	linux := validTestReceipt("closed-cleanups", OutcomeSucceeded)
	linux.ContainmentCleanup = CycleContainmentCleanup{
		Schema:            linuxCgroupV2CleanupSchema,
		ChildCgroupInode:  9842,
		FinalCgroupEvents: "populated 0\nfrozen 0\n",
		ChildRemoved:      true,
	}
	if _, err := log.Append(linux); err != nil {
		t.Fatalf("append exact Linux cleanup: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	replayed, err := OpenReceiptLog(root, "closed-cleanups")
	if err != nil {
		t.Fatalf("replay both closed cleanup shapes: %v", err)
	}
	defer func() { _ = replayed.Close() }()
	if replayed.Count() != 2 {
		t.Fatalf("replayed %d receipts, want 2", replayed.Count())
	}
}

func TestReceiptRejectsInvalidLinuxEventEvidence(t *testing.T) {
	tests := []struct {
		name   string
		events string
	}{
		{"empty", ""},
		{"missing populated", "frozen 0\n"},
		{"duplicate populated", "populated 0\npopulated 0\n"},
		{"populated one", "populated 1\n"},
		{"invalid populated type", "populated false\n"},
		{"malformed spacing", "populated  0\n"},
		{"unterminated", "populated 0"},
		{"invalid UTF-8", string([]byte{
			'p', 'o', 'p', 'u', 'l', 'a', 't', 'e', 'd', ' ', '0', 0xff, '\n',
		})},
		{"over 4 KiB", strings.Repeat("frozen 0\n", 456) + "populated 0\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			log, err := OpenReceiptLog(root, "invalid-events")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = log.Close() }()
			receipt := validTestReceipt("invalid-events", OutcomeSucceeded)
			receipt.ContainmentCleanup = CycleContainmentCleanup{
				Schema:            linuxCgroupV2CleanupSchema,
				ChildCgroupInode:  314,
				FinalCgroupEvents: test.events,
				ChildRemoved:      true,
			}
			if _, err := log.Append(receipt); err == nil {
				t.Fatalf("invalid cgroup.events %q was recorded", test.events)
			}
			if log.Count() != 0 {
				t.Fatal("receipt state advanced after event-evidence refusal")
			}
		})
	}
}

func TestControllerRefusesResultWithoutCleanupEvidence(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	runner := newFakeRunner(clock, fakeBehavior{
		Outcome: OutcomeSucceeded, Advance: time.Hour, MissingCleanup: true,
	})
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()
	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.TerminalReason != ReasonRunnerFault ||
		summary.CyclesAttempted != 0 {
		t.Fatalf("missing cleanup produced summary %+v", summary)
	}
	if _, err := os.Stat(filepath.Join(
		h.config.EvidenceRoot, "cycle-receipts.jsonl",
	)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(
		h.config.EvidenceRoot, "cycle-receipts.jsonl",
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 0 {
		t.Fatalf("missing cleanup produced a receipt: %s", raw)
	}
}

func TestControllerCopiesCleanupEvidenceIntoReceipt(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(testOrigin)
	cleanup := CycleContainmentCleanup{
		Schema:            linuxCgroupV2CleanupSchema,
		ChildCgroupInode:  7351,
		FinalCgroupEvents: "populated 0\nfrozen 0\n",
		ChildRemoved:      true,
	}
	runner := newFakeRunner(clock, fakeBehavior{
		Outcome: OutcomeSucceeded, Advance: time.Hour, Cleanup: &cleanup,
	})
	h := newHarness(t, root, runner, clock, func(cfg *Config) {
		cfg.Duration = time.Hour
		cfg.Cadence = 0
		cfg.ColdSettle = 0
	})
	defer h.close()
	summary, err := h.controller().Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.CyclesAttempted != 1 || summary.CyclesSucceeded != 1 {
		t.Fatalf("unexpected one-cycle summary: %+v", summary)
	}
	receipts := readReceipts(t, h.config.EvidenceRoot)
	if len(receipts) != 1 {
		t.Fatalf("wrote %d receipts, want 1", len(receipts))
	}
	if receipts[0].ContainmentCleanup != cleanup {
		t.Fatalf("controller did not copy cleanup evidence: %+v",
			receipts[0].ContainmentCleanup)
	}
}

func TestValidateContainmentCleanupRejectsBeforeReceiptAppend(t *testing.T) {
	root := t.TempDir()
	log, err := OpenReceiptLog(root, "semantic-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	receipt := validTestReceipt("semantic-cleanup", OutcomeSucceeded)
	receipt.ContainmentCleanup = CycleContainmentCleanup{}
	if _, err := log.Append(receipt); err == nil ||
		!strings.Contains(err.Error(), "cleanup evidence is missing") {
		t.Fatalf("missing semantic cleanup was accepted: %v", err)
	}
	if log.Count() != 0 {
		t.Fatal("receipt state advanced after cleanup semantic refusal")
	}
}
