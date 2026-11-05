package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replay-journal pathname identity.
//
// Preflight used to TrimSpace(WINN3_REPLAY_JOURNAL) and inspect the trimmed
// file, then buildSessionConfig wired os.Getenv's raw bytes into
// core.Config.ReplayJournal. A trailing space therefore vouched for
// /path/replay.journal while the process persisted /path/replay.journal and
// /path/replay.journal .wal -- two journals, two WAL directories.
//
// The remedy is one parser (parseReplayJournalPath): refuse any raw value
// that differs from TrimSpace(raw), and pass that exact string through
// requireReplayJournalPath, inspectLiveReplayJournal, serveOptions, and
// buildSessionConfig.

func replayJournalWhitespaceMatrix() []struct {
	name  string
	value func(clean string) string
} {
	return []struct {
		name  string
		value func(clean string) string
	}{
		{"one trailing space, the shape a copy-paste makes", func(c string) string { return c + " " }},
		{"one leading space", func(c string) string { return " " + c }},
		{"both ends", func(c string) string { return " " + c + " " }},
		{"a trailing tab", func(c string) string { return c + "\t" }},
		{"a trailing newline, the shape a shell heredoc makes", func(c string) string { return c + "\n" }},
		{"a trailing CRLF, the shape a Windows file makes", func(c string) string { return c + "\r\n" }},
		{"a leading no-break space", func(c string) string { return "\u00a0" + c }},
		{"a trailing ideographic space", func(c string) string { return c + "\u3000" }},
		{"a value that is nothing but whitespace once trimmed", func(string) string { return "   " }},
	}
}

func TestParseReplayJournalPathRefusesEdgeWhitespace(t *testing.T) {
	clean := filepath.Join(t.TempDir(), "replay.journal")
	for _, tc := range replayJournalWhitespaceMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.value(clean)
			if raw == strings.TrimSpace(raw) {
				t.Fatalf("fixture %q equals its TrimSpace form; this is not the defect", raw)
			}
			trimmed := strings.TrimSpace(raw)
			if trimmed+replayJournalWALSuffix == raw+replayJournalWALSuffix {
				t.Fatalf("trimmed and raw WAL names are identical for %q; the split is the defect", raw)
			}
			got, err := parseReplayJournalPath(raw)
			if err == nil {
				t.Fatalf("parseReplayJournalPath accepted %q and returned %q; it would inspect one journal and persist another", raw, got)
			}
			if !strings.Contains(err.Error(), replayJournalWhitespaceRefused) {
				t.Fatalf("refusal does not name the whitespace gate: %v", err)
			}
			if !strings.Contains(err.Error(), "WAL") {
				t.Fatalf("refusal does not name the WAL split: %v", err)
			}
		})
	}
}

func TestParseReplayJournalPathReturnsTheExactCleanValue(t *testing.T) {
	clean := filepath.Join(t.TempDir(), "replay.journal")
	got, err := parseReplayJournalPath(clean)
	if err != nil {
		t.Fatalf("a clean absolute path was refused: %v", err)
	}
	if got != clean {
		t.Fatalf("parser returned %q, want the exact input %q (no trim, no rewrite)", got, clean)
	}
	empty, err := parseReplayJournalPath("")
	if err != nil || empty != "" {
		t.Fatalf("unset path = %q, %v; empty must be unset, not a refusal", empty, err)
	}
}

func TestRequireAndInspectRefuseTheSameWhitespaceMatrix(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	clean := writeEmptyReplayJournal(t, dir)
	opts := serveOptions{
		staticPath: filepath.Join(dir, "static.key"),
		admission:  filepath.Join(dir, "admission.key"),
		gatewayID:  testGatewayID,
	}
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "1")
	for _, tc := range replayJournalWhitespaceMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.value(clean)
			t.Setenv("WINN3_REPLAY_JOURNAL", raw)

			if err := requireReplayJournalEnv(); err == nil || !strings.Contains(err.Error(), replayJournalWhitespaceRefused) {
				t.Fatalf("requireReplayJournalEnv = %v, want whitespace refusal", err)
			}
			if _, err := inspectLiveReplayJournal(raw); err == nil || !strings.Contains(err.Error(), replayJournalWhitespaceRefused) {
				t.Fatalf("inspectLiveReplayJournal = %v, want whitespace refusal", err)
			}
			if _, err := buildSessionConfig(opts); err == nil || !strings.Contains(err.Error(), replayJournalWhitespaceRefused) {
				t.Fatalf("buildSessionConfig = %v, want whitespace refusal", err)
			}
		})
	}
}

func TestRequireReplayJournalPathPassesOneExactPathThroughBuildSessionConfig(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen(dir, new(bytes.Buffer)); err != nil {
		t.Fatal(err)
	}
	clean := writeEmptyReplayJournal(t, dir)
	t.Setenv("WINN3_GATEWAY_REPLAY_JOURNAL", "1")
	t.Setenv("WINN3_REPLAY_JOURNAL", clean)

	path, err := requireReplayJournalPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != clean {
		t.Fatalf("requireReplayJournalPath returned %q, want the exact env value %q", path, clean)
	}

	// A later getenv of a whitespace-suffixed twin must not be able to
	// override the path that was already validated. That is the production
	// wiring: runServe stores the exact string on serveOptions.
	t.Setenv("WINN3_REPLAY_JOURNAL", clean+" ")
	cfg, err := buildSessionConfig(serveOptions{
		staticPath:    filepath.Join(dir, "static.key"),
		admission:     filepath.Join(dir, "admission.key"),
		gatewayID:     testGatewayID,
		replayJournal: path,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Core.ReplayJournal != path {
		t.Fatalf("Core.ReplayJournal = %q, want the exact validated path %q; env was a whitespace-suffixed twin",
			cfg.Core.ReplayJournal, path)
	}
	if cfg.Core.ReplayJournal == os.Getenv("WINN3_REPLAY_JOURNAL") {
		t.Fatal("the wired journal path equals the raw env value; the passed path did not win")
	}
}

func TestRunServeRefusesJournalWhitespaceBeforeListen(t *testing.T) {
	held, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()

	opts := operatorValueOptions(t)
	opts.listen = held.LocalAddr().String()
	clean := os.Getenv("WINN3_REPLAY_JOURNAL")
	t.Setenv("WINN3_REPLAY_JOURNAL", clean+" ")

	err = runServe(opts, new(bytes.Buffer))
	if err == nil {
		t.Fatal("runServe accepted a whitespace-suffixed WINN3_REPLAY_JOURNAL")
	}
	if !strings.Contains(err.Error(), replayJournalWhitespaceRefused) {
		t.Fatalf("runServe error = %v, want whitespace refusal before listen", err)
	}
	if strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "bind") {
		t.Fatalf("the socket was reached before the pathname gate: %v", err)
	}
}
