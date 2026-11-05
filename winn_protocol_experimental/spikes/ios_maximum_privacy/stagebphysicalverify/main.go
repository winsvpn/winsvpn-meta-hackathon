package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	manifestPath := flag.String(
		"manifest",
		"",
		"root-relative Stage B physical evidence manifest",
	)
	expectedManifest := flag.String(
		"expected-manifest-sha256",
		"",
		"independently pinned manifest-bytes SHA-256",
	)
	expectedContract := flag.String(
		"expected-contract-sha256",
		"",
		"independently pinned physical-contract SHA-256",
	)
	expectedSource := flag.String(
		"expected-source-sha256",
		"",
		"independently pinned source-tree SHA-256",
	)
	expectedVerifier := flag.String(
		"expected-verifier-sha256",
		"",
		"independently pinned verifier executable SHA-256",
	)
	flag.Parse()
	if flag.NArg() != 0 ||
		*manifestPath == "" ||
		*expectedManifest == "" ||
		*expectedContract == "" ||
		*expectedSource == "" ||
		*expectedVerifier == "" {
		fmt.Fprintln(
			os.Stderr,
			"STAGE_B_PHYSICAL_SCHEMA_CONFORMANCE_FAIL: "+
				"manifest and all independent expected pins are required",
		)
		os.Exit(2)
	}
	if _, err := Verify(
		*manifestPath,
		*expectedManifest,
		*expectedContract,
		*expectedSource,
		*expectedVerifier,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"STAGE_B_PHYSICAL_SCHEMA_CONFORMANCE_FAIL: %v\n",
			err,
		)
		os.Exit(1)
	}
	fmt.Println(
		"STAGE_B_PHYSICAL_SCHEMA_CONFORMANCE_PASS " +
			"schema=" + attemptSchema + " " +
			"scope=physical-first-protected-flow",
	)
}
