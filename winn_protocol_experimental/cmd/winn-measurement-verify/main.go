// Command winn-measurement-verify verifies a Winn measurement log and its
// authenticated high-water anchor without printing the HMAC key.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"winsvpn.local/winnprotocol/internal/measurement"
)

func main() {
	logPath := flag.String("log", "", "measurement JSONL path")
	keyPath := flag.String("key", "", "measurement HMAC key path")
	expectedCount := flag.Int(
		"expected-count",
		0,
		"require exactly this many records (0 disables the count check)",
	)
	requireAllSuccess := flag.Bool(
		"require-all-success",
		false,
		"fail if any measurement attempt failed",
	)
	requireSingleProvenance := flag.Bool(
		"require-single-provenance",
		true,
		"require one source, artifact, and manifest digest across the log",
	)
	flag.Parse()

	if *logPath == "" || *keyPath == "" {
		fatalf("log and key are required")
	}
	if *expectedCount < 0 {
		fatalf("expected-count cannot be negative")
	}
	if err := measurement.Verify(*logPath, *keyPath); err != nil {
		fatalf("VERIFY_FAIL: %v", err)
	}
	log, err := measurement.Open(*logPath, *keyPath)
	if err != nil {
		fatalf("open verified measurement log: %v", err)
	}
	attempts := log.Attempts()
	summary := log.Summary()
	if err := log.Close(); err != nil {
		fatalf("close verified measurement log: %v", err)
	}
	if *expectedCount > 0 && len(attempts) != *expectedCount {
		fatalf(
			"record count = %d, expected %d",
			len(attempts),
			*expectedCount,
		)
	}
	if *requireAllSuccess && summary.Failures != 0 {
		fatalf("measurement failures = %d", summary.Failures)
	}

	sources := make(map[string]struct{})
	artifacts := make(map[string]struct{})
	manifests := make(map[string]struct{})
	for _, attempt := range attempts {
		sources[attempt.SourceDigest] = struct{}{}
		artifacts[attempt.ArtifactDigest] = struct{}{}
		manifests[attempt.ManifestDigest] = struct{}{}
	}
	if *requireSingleProvenance &&
		(len(sources) != 1 || len(artifacts) != 1 || len(manifests) != 1) {
		fatalf(
			"mixed provenance: source=%d artifact=%d manifest=%d",
			len(sources),
			len(artifacts),
			len(manifests),
		)
	}

	fmt.Printf(
		"VERIFY_PASS records=%d success=%d failure=%d p50=%s p95=%s p99=%s success_p99=%s\n",
		summary.Total,
		summary.Successes,
		summary.Failures,
		summary.OutcomeP50,
		summary.OutcomeP95,
		summary.OutcomeP99,
		summary.SuccessfulOutcomeP99,
	)
	codes := make([]string, 0, len(summary.FailureCounts))
	failureCounts := make(map[string]int, len(summary.FailureCounts))
	for code, count := range summary.FailureCounts {
		text := string(code)
		codes = append(codes, text)
		failureCounts[text] = count
	}
	sort.Strings(codes)
	for _, code := range codes {
		fmt.Printf("failure_code=%s count=%d\n", code, failureCounts[code])
	}
	if len(sources) == 1 {
		fmt.Printf("source_digest=%s\n", onlyDigest(sources))
	}
	if len(artifacts) == 1 {
		fmt.Printf("artifact_digest=%s\n", onlyDigest(artifacts))
	}
	if len(manifests) == 1 {
		fmt.Printf("manifest_digest=%s\n", onlyDigest(manifests))
	}
}

func onlyDigest(values map[string]struct{}) string {
	for value := range values {
		return value
	}
	return ""
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	os.Exit(1)
}
