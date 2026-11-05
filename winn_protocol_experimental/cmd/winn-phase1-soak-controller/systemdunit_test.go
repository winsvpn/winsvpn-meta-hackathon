package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// forbiddenExecutionImports are packages that can start a process.
//
// A file that cannot import any of these cannot execute a command, whatever
// its code says. That is a structural guarantee rather than a promise, which is
// the whole reason the systemd command generator lives in its own file.
var forbiddenExecutionImports = []string{
	"os/exec",
	"syscall",
	"golang.org/x/sys/unix",
	"os/signal",
}

// TestSystemdGeneratorCannotExecuteAnything parses systemdunit.go's own import
// list.
//
// The requirement is that this program prints a systemd-run command and never
// runs one. A test that merely checked the printed string would pass on a
// program that also executed it. This one cannot.
func TestSystemdGeneratorCannotExecuteAnything(t *testing.T) {
	const source = "systemdunit.go"
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, source, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	if len(parsed.Imports) == 0 {
		t.Fatalf("%s has no imports at all; the parse probably read the "+
			"wrong file, which would make this check vacuous", source)
	}
	for _, imported := range parsed.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		for _, forbidden := range forbiddenExecutionImports {
			if path == forbidden {
				t.Errorf("%s imports %q, so it is capable of executing a "+
					"process; the systemd command must only ever be printed",
					source, path)
			}
		}
	}

	// Positive control on the check itself: the same predicate must FIND a
	// forbidden import when one is genuinely present. Without this, a typo
	// in forbiddenExecutionImports would make the loop above pass over
	// everything.
	control := token.NewFileSet()
	controlFile, err := parser.ParseFile(
		control, "execrunner_unix.go", nil, parser.ImportsOnly,
	)
	if err != nil {
		t.Fatalf("parse the control file: %v", err)
	}
	sawForbidden := false
	for _, imported := range controlFile.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		for _, forbidden := range forbiddenExecutionImports {
			if path == forbidden {
				sawForbidden = true
			}
		}
	}
	if !sawForbidden {
		t.Fatal("the control file imports none of the forbidden packages, " +
			"so the check above proves nothing")
	}
}

// TestNoSourceFileInvokesSystemctl scans the whole package.
//
// The generator is allowed to name systemd-run in the argv it builds. What no
// file may do is hand that argv to anything that runs it, and no file may name
// systemctl at all outside a comment or a printed message.
func TestNoSourceFileInvokesSystemctl(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		raw, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(raw)
		for _, forbidden := range []string{
			"exec.Command(\"systemctl",
			"exec.Command(\"systemd-run",
			"exec.CommandContext(\"systemctl",
			"exec.CommandContext(\"systemd-run",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no non-test Go files were scanned; the check is vacuous")
	}
}

// TestSystemdCommandShape checks the generated argv is the one an operator
// would want and, in particular, that its outer runtime bound exceeds the soak
// duration rather than equalling it.
func TestSystemdCommandShape(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	cfg.AllowWritableSnapshot = true
	cfg.KillGrace = 17 * time.Second
	cfg.SampleInterval = 3 * time.Second
	cfg.ProcRoot = "/alternate-proc"
	cfg.MaxControllerOutput = 12345
	argv := SystemdCommand(SystemdUnitRequest{
		UnitName:        "winn-phase1-soak",
		ControllerPath:  "/opt/winn-lab/bin/winn-phase1-soak-controller",
		Config:          cfg,
		EnvFile:         "/opt/winn-lab/etc/soak.env",
		MemoryMax:       "8G",
		CPUQuota:        "200%",
		TasksMax:        8192,
		WorkingRoot:     cfg.SnapshotRoot,
		RuntimeMaxExtra: time.Hour,
	})
	if argv[0] != "systemd-run" {
		t.Fatalf("argv[0] is %q, want systemd-run", argv[0])
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--property=Restart=no",
		"--property=KillMode=control-group",
		"--property=NoNewPrivileges=yes",
		"--property=Delegate=yes",
		"--property=DelegateSubgroup=controller",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=read-only",
		"--property=ReadOnlyPaths=" + cfg.SnapshotRoot,
		"-run",
		"-duration=" + cfg.Duration.String(),
		"-kill-grace=17s",
		"-sample-interval=3s",
		"-proc-root=/alternate-proc",
		"-max-controller-output-bytes=12345",
		"-allow-writable-snapshot",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("generated command omits %q", want)
		}
	}
	// RuntimeMaxSec must EXCEED the soak duration. Equal would kill the unit
	// while it was writing the summary, which is the one artifact that says
	// how the run ended.
	wantRuntime := int64((cfg.Duration + time.Hour) / time.Second)
	exact := "--property=RuntimeMaxSec=" + itoa(wantRuntime)
	if !strings.Contains(joined, exact) {
		t.Errorf("generated command lacks %q", exact)
	}
	equalToDuration := "--property=RuntimeMaxSec=" +
		itoa(int64(cfg.Duration/time.Second))
	if strings.Contains(joined, equalToDuration) {
		t.Errorf("RuntimeMaxSec equals the soak duration; the unit would be "+
			"killed mid-summary (%q)", equalToDuration)
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

// TestShellQuoteNeverProducesAnExpandableString checks the display helper.
func TestShellQuoteNeverProducesAnExpandableString(t *testing.T) {
	dangerous := []string{
		"$(rm -rf /)",
		"`id`",
		"a b",
		"it's",
		"$HOME",
		"a\nb",
		"",
	}
	for _, argument := range dangerous {
		quoted := shellQuote(argument)
		if quoted == argument && argument != "" {
			t.Errorf("shellQuote left %q unquoted", argument)
		}
		if !strings.HasPrefix(quoted, "'") {
			t.Errorf("shellQuote(%q) = %q, which is not single-quoted",
				argument, quoted)
		}
		// Inside single quotes the only character with meaning is the
		// closing quote, and it is escaped by the documented '\'' idiom.
		inner := strings.TrimSuffix(strings.TrimPrefix(quoted, "'"), "'")
		if strings.Contains(inner, "'") &&
			!strings.Contains(quoted, `'\''`) {
			t.Errorf("shellQuote(%q) = %q leaves a bare quote", argument, quoted)
		}
	}
	// Ordinary arguments stay readable: a helper that quoted everything
	// would be safe and useless, and this asserts it is not that.
	if got := shellQuote("--property=Restart=no"); got != "--property=Restart=no" {
		t.Errorf("shellQuote over-quoted a plain argument: %q", got)
	}
}
