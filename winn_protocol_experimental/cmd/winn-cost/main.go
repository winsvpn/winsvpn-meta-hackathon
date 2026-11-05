package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"winsvpn.local/winnprotocol/internal/costledger"
)

func main() {
	var inputPath string
	flag.StringVar(
		&inputPath,
		"input",
		"",
		"strict winn-cloud-cost/v1 inventory JSON",
	)
	flag.Parse()
	if inputPath == "" {
		exitError("-input is required")
	}
	if flag.NArg() > 0 {
		exitError(fmt.Sprintf("unexpected argument %q", flag.Arg(0)))
	}
	// #nosec G304 -- inputPath is an administrator-supplied CLI flag (-input)
	// for this single-operator local tool, not attacker-controlled input.
	input, err := os.Open(inputPath)
	if err != nil {
		exitError(err.Error())
	}
	snapshot, decodeErr := costledger.Decode(input)
	closeErr := input.Close()
	if decodeErr != nil {
		exitError(decodeErr.Error())
	}
	if closeErr != nil {
		exitError(closeErr.Error())
	}
	report, err := costledger.Project(snapshot, time.Now().UTC())
	if err != nil {
		exitError(err.Error())
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		exitError(err.Error())
	}
}

func exitError(message string) {
	fmt.Fprintln(os.Stderr, "winn-cost:", message)
	os.Exit(1)
}
