// Command redteam is the attack-transcript replay harness for winn/3.
//
// It reads transcript JSONL files from the transcripts directory and prints
// one verdict line per action, each carrying an explicit allow or deny. It is
// a pure, offline replay: it performs no network I/O and installs no tunnel,
// so it is safe to run on a live shared machine.
//
// Usage:
//
//	redteam -transcripts <dir|file> -policy-version <ver> -out <file>
//
// Transcripts are JSONL: one Action object per line. Verdicts go to stdout
// by default, or to -out when given. Blank lines are skipped. A line that
// is not valid JSON is a hard failure (exit 1): the harness does not skip
// it and continue, because a missing deny in an attack transcript is a
// silent degrade. A directory with no .jsonl files is a hard failure
// (exit 2): an empty replay is not a pass.
// The -policy-version flag is recorded in the summary and accepted as a
// parametrized selector for future policy revisions (currently informative).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var (
		transcriptsPath = flag.String("transcripts", "winn3/redteam/transcripts",
			"directory containing transcript JSONL files or a single JSONL file")
		outPath         = flag.String("out", "", "optional output file; default stdout")
		policyVersion   = flag.String("policy-version", "", "policy version tag; recorded in summary, reserved for future policy selection")
	)
	flag.Parse()
	os.Exit(run(*transcriptsPath, *outPath, *policyVersion, os.Stdout, os.Stderr))
}

// run is the testable CLI body. It returns the process exit code.
// 0 = replay completed with at least one verdict. 1 = I/O or parse failure.
// 2 = bad flags, a directory with no .jsonl files, or a replay that
// produced zero actions (empty file / blank-only JSONL).
func run(transcriptsPath, outPath, policyVersion string, stdout, stderr io.Writer) int {
	if code := validateFlags(transcriptsPath, outPath, policyVersion, stderr); code != 0 {
		return code
	}

	pol := newPolicy(now)

	out := stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(stderr, "redteam: create %s: %v\n", outPath, err)
			return 1
		}
		defer f.Close()
		out = f
	}

	info, err := os.Stat(transcriptsPath)
	if err != nil {
		fmt.Fprintf(stderr, "redteam: -transcripts %s: missing transcripts dir: %v\n", transcriptsPath, err)
		return 1
	}

	total, allowed, denied := 0, 0, 0
	replay := func(path, label string) int {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(stderr, "redteam: open %s: %v\n", path, err)
			return 1
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var a Action
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				fmt.Fprintf(stderr, "redteam: %s: bad JSONL: %v\n", label, err)
				return 1
			}
			v := pol.Evaluate(a)
			fmt.Fprintln(out, v.Line())
			total++
			if v.Decision == "allow" {
				allowed++
			} else {
				denied++
			}
		}
		if err := sc.Err(); err != nil {
			fmt.Fprintf(stderr, "redteam: %s: read: %v\n", label, err)
			return 1
		}
		return 0
	}

	if !info.IsDir() {
		if code := replay(transcriptsPath, filepath.Base(transcriptsPath)); code != 0 {
			return code
		}
	} else {
		entries, err := os.ReadDir(transcriptsPath)
		if err != nil {
			fmt.Fprintf(stderr, "redteam: readdir %s: %v\n", transcriptsPath, err)
			return 1
		}
		jsonlSeen := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if !strings.HasSuffix(name, ".jsonl") {
				continue
			}
			jsonlSeen++
			path := filepath.Join(transcriptsPath, name)
			if code := replay(path, name); code != 0 {
				return code
			}
		}
		if jsonlSeen == 0 {
			fmt.Fprintf(stderr, "redteam: %s: no .jsonl transcripts (empty replay is not a pass)\n", transcriptsPath)
			return 2
		}
	}

	if total == 0 {
		fmt.Fprintf(stderr, "redteam: %s: no actions (empty replay is not a pass)\n", transcriptsPath)
		return 2
	}

	if policyVersion != "" {
		fmt.Fprintf(out, "# total=%d allowed=%d denied=%d policy-version=%s\n", total, allowed, denied, policyVersion)
	} else {
		fmt.Fprintf(out, "# total=%d allowed=%d denied=%d\n", total, allowed, denied)
	}
	return 0
}

func validateFlags(transcriptsPath, outPath, policyVersion string, stderr io.Writer) int {
	if strings.TrimSpace(transcriptsPath) == "" {
		fmt.Fprintf(stderr, "redteam: -transcripts flag must not be empty (missing transcripts dir)\n")
		return 2
	}
	if outPath != "" {
		if strings.TrimSpace(outPath) == "" {
			fmt.Fprintf(stderr, "redteam: -out flag must not be empty or whitespace\n")
			return 2
		}
		dir := filepath.Dir(outPath)
		if dir != "." && dir != "" {
			if info, err := os.Stat(dir); err != nil {
				fmt.Fprintf(stderr, "redteam: -out %s: parent directory does not exist: %v\n", outPath, err)
				return 2
			} else if !info.IsDir() {
				fmt.Fprintf(stderr, "redteam: -out %s: parent %s is not a directory\n", outPath, dir)
				return 2
			}
		}
		if info, err := os.Stat(outPath); err == nil && info.IsDir() {
			fmt.Fprintf(stderr, "redteam: -out %s is a directory, expected file\n", outPath)
			return 2
		}
	}
	if policyVersion != "" {
		if strings.TrimSpace(policyVersion) == "" {
			fmt.Fprintf(stderr, "redteam: -policy-version flag must not be whitespace\n")
			return 2
		}
		if len(policyVersion) > 64 {
			fmt.Fprintf(stderr, "redteam: -policy-version too long (max 64 chars)\n")
			return 2
		}
		for _, r := range policyVersion {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
				fmt.Fprintf(stderr, "redteam: -policy-version %q contains invalid character %q (allowed: A-Za-z0-9._-)\n", policyVersion, string(r))
				return 2
			}
		}
	}
	return 0
}
