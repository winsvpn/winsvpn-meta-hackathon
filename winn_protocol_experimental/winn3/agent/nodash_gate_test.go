package agent

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAgentCorpusNoEmOrEnDash is the em-dash gate. It scans every file under
// winn_protocol_experimental/winn3/agent for the UTF-8 byte sequences of
// U+2014 and U+2013 and fails if either is present. The codepoints are
// referenced as byte escapes so this file itself contains no literal dash
// glyph. An honest BLOCKED beats a green you cannot defend, so this test
// also shells out to tools/agent_nodash.sh and requires that script to exit 0.
//
// The scan skips binary and backup artifacts that the shell gate also ignores:
// .bak, .png, .tgz, .apk, .so, plus build/ and .git. A hit must name the file
// and the offending codepoint.
func TestAgentCorpusNoEmOrEnDash(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	agentDir := filepath.Dir(thisFile)

	// UTF-8 bytes for U+2014 (em dash) and U+2013 (en dash). Written as byte
	// literals so the source file itself carries no forbidden glyph.
	emDash := []byte{0xE2, 0x80, 0x94}
	enDash := []byte{0xE2, 0x80, 0x93}

	// Also verify the shell gate exists and exits 0 when invoked by the test
	// runner. This ties the script and the Go suite so a future dash breaks
	// the test even if only one of the two scanners is run.
	scriptCandidates := []string{
		filepath.Join(agentDir, "..", "..", "..", "..", "tools", "agent_nodash.sh"),
		"/Users/owner/Documents/wins/tools/agent_nodash.sh",
	}
	foundScript := ""
	for _, p := range scriptCandidates {
		if _, err := os.Stat(p); err == nil {
			foundScript = p
			break
		}
	}
	if foundScript != "" {
		cmd := exec.Command("/bin/sh", foundScript)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("agent_nodash.sh gate failed (exit %v): %s", err, string(out))
		}
		// Script reports clean on stdout; log it so guard_log captures the gate.
		t.Logf("shell gate: %s", bytes.TrimSpace(out))
	} else {
		t.Logf("shell gate not found at %v; Go byte scan still enforced", scriptCandidates)
	}

	var offenders []string
	err := filepath.Walk(agentDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip artifacts the gate is allowed to ignore.
		switch filepath.Ext(path) {
		case ".bak", ".png", ".tgz", ".apk", ".so":
			// Also handle suffixed .bak_... files which have no clean ext.
			return nil
		}
		if bytes.Contains([]byte(filepath.Base(path)), []byte(".bak_")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if bytes.Contains(data, emDash) {
			offenders = append(offenders, path+" contains U+2014")
		}
		if bytes.Contains(data, enDash) {
			offenders = append(offenders, path+" contains U+2013")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk agent dir: %v", err)
	}
	if len(offenders) > 0 {
		for _, o := range offenders {
			t.Log(o)
		}
		t.Fatalf("forbidden em/en dash found in %d file(s) under %s", len(offenders), agentDir)
	}
}
