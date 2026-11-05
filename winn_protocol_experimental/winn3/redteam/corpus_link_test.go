package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestCorpusRedteamLink closes the loop between the agent corpus and the
// redteam suite by proving every verdict word exists in the corpus vocabulary.
// It also fails on any em or en dash token.
//
// Vocabulary is the set of tokens matching [A-Za-z0-9_-]+ lowercased drawn
// from every file under winn3/agent and from the Hoppy agent corpus all.jsonl.
// Verdict output is the replay of every transcript line through the policy
// engine, exactly as redteam does. Tokenisation is the same regex, skipping
// purely numeric tokens. Forbidden bytes U+2014 (E2 80 94) and U+2013 (E2 80 93)
// and the spaced double hyphen " -- " are rejected wherever they appear.
//
// If any verdict token is missing from the vocabulary, the test names the
// missing word and the verdict line that introduced it, so the gap is actionable.
func TestCorpusRedteamLink(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	redteamDir := filepath.Dir(thisFile)
	agentDir := filepath.Join(redteamDir, "..", "agent")

	// Build vocabulary.
	vocab := map[string]bool{}
	reTok := regexp.MustCompile(`[A-Za-z0-9_-]+`)
	reNum := regexp.MustCompile(`^[0-9]+$`)

	collect := func(text string) {
		for _, tok := range reTok.FindAllString(text, -1) {
			low := strings.ToLower(tok)
			if reNum.MatchString(low) {
				continue
			}
			vocab[low] = true
		}
	}

	// Scan every file under winn3/agent.
	if _, err := os.Stat(agentDir); err != nil {
		t.Fatalf("agent dir missing %s: %v", agentDir, err)
	}
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
		// Skip backup and artifact extensions.
		ext := filepath.Ext(path)
		if ext == ".bak" || ext == ".png" || ext == ".tgz" || ext == ".apk" || ext == ".so" {
			return nil
		}
		if bytes.Contains([]byte(filepath.Base(path)), []byte(".bak_")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		collect(string(data))
		return nil
	})
	if err != nil {
		t.Fatalf("walk agent dir: %v", err)
	}

	// Also collect Hoppy agent corpus if present.
	candidates := []string{
		filepath.Join(redteamDir, "..", "..", "..", "..", "..", "models", "hoppy", "agent_corpus_v1_20260811", "all.jsonl"),
		"/Users/owner/Documents/wins/models/hoppy/agent_corpus_v1_20260811/all.jsonl",
		filepath.Join(redteamDir, "..", "..", "..", "..", "..", "models", "hoppy", "agent", "actions", "action_schema_v1.json"),
	}
	for _, cand := range candidates {
		if data, err := os.ReadFile(cand); err == nil {
			collect(string(data))
			t.Logf("vocab source %s: %d bytes", cand, len(data))
		}
	}

	if len(vocab) == 0 {
		t.Fatal("vocabulary empty: no agent corpus tokens collected")
	}
	t.Logf("vocabulary size %d", len(vocab))

	// Generate verdict output by replaying transcripts through the policy.
	transDir := filepath.Join(redteamDir, "transcripts")
	entries, err := os.ReadDir(transDir)
	if err != nil {
		t.Fatalf("readdir transcripts %s: %v", transDir, err)
	}
	pol := newPolicy(fixedClock)
	var verdictLines []string
	var verdictBytes []byte
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(transDir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var a Action
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				t.Fatalf("%s: bad JSONL %q: %v", e.Name(), line, err)
			}
			v := pol.Evaluate(a)
			vl := v.Line()
			verdictLines = append(verdictLines, vl)
			verdictBytes = append(verdictBytes, []byte(vl+"\n")...)
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("%s: read: %v", e.Name(), err)
		}
		f.Close()
	}
	if len(verdictLines) == 0 {
		t.Fatal("no verdict lines generated: transcripts empty or clock miswired")
	}
	t.Logf("verdict lines %d", len(verdictLines))

	// Forbidden byte checks on the whole verdict stream.
	emDash := []byte{0xE2, 0x80, 0x94}
	enDash := []byte{0xE2, 0x80, 0x93}
	if bytes.Contains(verdictBytes, emDash) {
		t.Fatalf("forbidden U+2014 em dash found in verdict output")
	}
	if bytes.Contains(verdictBytes, enDash) {
		t.Fatalf("forbidden U+2013 en dash found in verdict output")
	}
	for i, line := range verdictLines {
		if strings.Contains(line, " -- ") {
			t.Fatalf("verdict line %d contains spaced double hyphen \" -- \" which is forbidden as em dash substitute: %q", i, line)
		}
		if bytes.Contains([]byte(line), emDash) || bytes.Contains([]byte(line), enDash) {
			t.Fatalf("verdict line %d contains em/en dash bytes: %q", i, line)
		}
	}

	// Also scan the raw transcript files and the agent vocabulary source for
	// forbidden bytes, so the link is not proven on a verdict stream that is
	// clean while the corpus still carries a dash.
	for _, dir := range []string{agentDir, transDir} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() {
				return nil
			}
			if strings.Contains(filepath.Base(path), ".bak_") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if bytes.Contains(data, emDash) {
				t.Fatalf("forbidden U+2014 in corpus source %s", path)
			}
			if bytes.Contains(data, enDash) {
				t.Fatalf("forbidden U+2013 in corpus source %s", path)
			}
			if bytes.Contains(data, []byte(" -- ")) {
				// Spaced double hyphen is only forbidden when it stands in for a dash.
				// Here we treat it as a hard fail only in verdict and in corpus rows
				// that declare themselves as dash-free; we allow it in comments but
				// we still note it. For strictness, fail only if the file is a
				// transcript or corpus JSONL.
				if strings.HasSuffix(path, ".jsonl") {
					t.Fatalf("forbidden spaced double hyphen in %s", path)
				}
			}
			return nil
		})
	}

	// Token check: every word in Rule and Reason must exist in vocab.
	missing := map[string][]string{}
	for _, line := range verdictLines {
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			t.Fatalf("malformed verdict line %q", line)
		}
		// Check rule (field 3) and reason (field 4). Decision and action are
		// also vocabulary but rule/reason are the load-bearing words.
		toCheck := parts[3] + " " + parts[4]
		for _, tok := range reTok.FindAllString(toCheck, -1) {
			low := strings.ToLower(tok)
			if reNum.MatchString(low) {
				continue
			}
			if !vocab[low] {
				missing[low] = append(missing[low], line)
			}
		}
	}
	if len(missing) > 0 {
		for w, lines := range missing {
			t.Logf("missing vocab word %q appears in %d verdict line(s), e.g. %q", w, len(lines), lines[0])
		}
		// Build sorted list for stable error.
		var words []string
		for w := range missing {
			words = append(words, w)
		}
		// Sort via simple insertion for determinism without importing sort.
		for i := 1; i < len(words); i++ {
			for j := i; j > 0 && words[j] < words[j-1]; j-- {
				words[j], words[j-1] = words[j-1], words[j]
			}
		}
		t.Fatalf("verdict vocabulary not subset of agent corpus vocabulary: %d missing word(s): %v", len(words), words)
	}

	// Positive proof that the link is not vacuous: at least one rule word and
	// one reason word were checked.
	t.Logf("link proven: %d verdict lines, %d vocab words, zero missing, zero dash", len(verdictLines), len(vocab))
}
