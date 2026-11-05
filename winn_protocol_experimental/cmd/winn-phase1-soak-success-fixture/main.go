// Command winn-phase1-soak-success-fixture is a bounded synthetic cycle used
// only to exercise the soak controller's repeated-success lifecycle.
//
// It is not the Phase-1 Auto runner and cannot produce promotable evidence.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	fixtureVersion     = "success-v1"
	selfExecutablePath = "/proc/self/exe"
	childArgument      = "--child"
)

var (
	runIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	noncePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type fixtureResult struct {
	Schema    string `json:"schema"`
	RunID     string `json:"run_id"`
	Sequence  int64  `json:"sequence"`
	Readiness string `json:"readiness"`
	ChildExit int    `json:"child_exit"`
}

func main() {
	if isChildInvocation(os.Args) {
		if len(os.Environ()) != 0 {
			fatal(errors.New("child environment is not empty"))
		}
		return
	}
	if err := runFixture(
		os.Environ(),
		func() error {
			child := exec.Command(selfExecutablePath, childArgument)
			child.Env = []string{}
			return child.Run()
		},
		os.Stdout,
	); err != nil {
		fatal(err)
	}
}

func runFixture(
	environment []string,
	runChild func() error,
	output io.Writer,
) error {
	values, err := validateEnvironment(environment)
	if err != nil {
		return err
	}

	if err := runChild(); err != nil {
		return fmt.Errorf("self child failed: %w", err)
	}

	sequence, _ := strconv.ParseInt(
		values["WINN_SOAK_CYCLE_SEQUENCE"], 10, 64,
	)
	result := fixtureResult{
		Schema:    "winn-phase1-soak-success-fixture/v1",
		RunID:     values["WINN_SOAK_RUN_ID"],
		Sequence:  sequence,
		Readiness: values["READINESS"],
		ChildExit: 0,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if _, err := output.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}

func isChildInvocation(arguments []string) bool {
	return len(arguments) == 2 && arguments[1] == childArgument
}

func validateEnvironment(entries []string) (map[string]string, error) {
	expected := []string{
		"READINESS",
		"WINN_SOAK_CYCLE_SEQUENCE",
		"WINN_SOAK_FIXTURE",
		"WINN_SOAK_INSTANCE_NONCE",
		"WINN_SOAK_RUN_ID",
	}
	values := make(map[string]string, len(expected))
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			return nil, errors.New("environment contains a malformed entry")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("environment repeats %s", name)
		}
		values[name] = value
	}

	actual := make([]string, 0, len(values))
	for name := range values {
		actual = append(actual, name)
	}
	sort.Strings(actual)
	if strings.Join(actual, "\x00") != strings.Join(expected, "\x00") {
		return nil, fmt.Errorf(
			"environment names are %q, want %q", actual, expected,
		)
	}
	if values["WINN_SOAK_FIXTURE"] != fixtureVersion {
		return nil, errors.New("fixture version is not success-v1")
	}
	if values["READINESS"] != "warm" && values["READINESS"] != "cold" {
		return nil, errors.New("READINESS must be warm or cold")
	}
	if !runIDPattern.MatchString(values["WINN_SOAK_RUN_ID"]) {
		return nil, errors.New("run ID is malformed")
	}
	sequence, err := strconv.ParseInt(
		values["WINN_SOAK_CYCLE_SEQUENCE"], 10, 64,
	)
	if err != nil || sequence < 1 ||
		strconv.FormatInt(sequence, 10) !=
			values["WINN_SOAK_CYCLE_SEQUENCE"] {
		return nil, errors.New("cycle sequence is not canonical positive decimal")
	}
	if !noncePattern.MatchString(values["WINN_SOAK_INSTANCE_NONCE"]) {
		return nil, errors.New("instance nonce is not 32 lowercase hex characters")
	}
	return values, nil
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "winn soak success fixture: %v\n", err)
	os.Exit(64)
}
