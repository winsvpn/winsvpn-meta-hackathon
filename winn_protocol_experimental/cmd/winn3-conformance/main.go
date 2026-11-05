// Command winn3-conformance is the driver for the winn/3 CROSS-HOST
// CONFORMANCE SUITE.
//
// Flags:
//
//	-emit <path>        write the reference vectors, computed by the same
//	                    packages the shipping engine runs, for the hosts that
//	                    cannot import Go. "-" writes stdout.
//	-emit-tasks <path>  write the line-oriented TASK LIST a non-Go harness reads.
//	-verify <paths>     comma-separated host report paths (not positional, not
//	                    space-separated). Compared against the vectors.
//	-vectors <path>     read vectors from this path instead of computing them.
//	-matrix             print the plan-floor matrix as a table.
//
// At least one of -emit, -emit-tasks, -verify, -matrix is required.
// -vectors is not an action; it only selects the reference.
// -emit and -emit-tasks must not share a path (including both "-").
// -verify must not name the same path as -emit, -emit-tasks, or -vectors.
//
// # Why a command and not only `go test`
//
// The Go hosts are covered by adapters inside their own packages, where they
// belong: a divergence in cmd/winn3-gateway should fail cmd/winn3-gateway's own
// test run. But Kotlin, Swift and C++ cannot be reached from `go test`, and a
// conformance rule that only exists inside `go test` is a rule the release
// pipeline does not have. This command is what CI runs after each platform's
// harness has emitted its report.
//
// # Exit codes
//
//	0  every host reported and every host agreed
//	1  at least one host disagreed — read the table
//	2  the run could not prove anything (no reports, unreadable vectors). Never
//	   confused with 0: "nothing was checked" and "everything passed" look the
//	   same in a green pipeline and are not the same fact.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"winsvpn.local/winnprotocol/winn3/conform"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "winn3-conformance: %v\n", err)
		os.Exit(exitCodeFor(err))
	}
}

// unprovenError marks the "nothing was checked" outcome so it can never be
// reported as success.
type unprovenError struct{ msg string }

func (e unprovenError) Error() string { return e.msg }

func unproven(format string, args ...any) error {
	return unprovenError{msg: fmt.Sprintf(format, args...)}
}

func exitCodeFor(err error) int {
	// errors.As, not a bare type assertion: a fmt.Errorf("%w") wrap used to
	// silently degrade exit 2 ("nothing was checked") into exit 1. Named in
	// WINN3_LATE_VALIDATION_SWEEP_2026-08-09.md §3.11.
	var u unprovenError
	if errors.As(err, &u) {
		return 2
	}
	return 1
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("winn3-conformance", flag.ContinueOnError)
	emit := flags.String("emit", "", "write the reference vectors to this path (- for stdout)")
	emitTasks := flags.String("emit-tasks", "",
		"write the line-oriented TASK LIST a non-Go host harness reads (- for stdout)")
	verify := flags.String("verify", "",
		"comma-separated host report paths to check (not positional operands; not space-separated)")
	vectorsPath := flags.String("vectors", "",
		"read vectors from this path instead of computing them. tools/verify_winn3_conformance.sh "+
			"passes this so harnesses and the comparer see the same bytes; do not pass a file from a "+
			"different tree or a previous emit")
	showMatrix := flags.Bool("matrix", false, "print the plan-floor matrix as a table")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := refusePositionalArgs(flags.Args(), *verify); err != nil {
		return err
	}
	var verifyPaths []string
	if *verify != "" {
		var err error
		verifyPaths, err = checkVerifyPaths(*verify)
		if err != nil {
			return err
		}
	}
	if *emit == "" && *emitTasks == "" && !*showMatrix && len(verifyPaths) == 0 {
		flags.Usage()
		if strings.TrimSpace(*vectorsPath) != "" {
			return unproven("nothing to do: -vectors only selects the reference, it is not an action. Pass -emit, -emit-tasks, -verify or -matrix")
		}
		return unproven("nothing to do: pass -emit, -emit-tasks, -verify or -matrix")
	}
	if err := refuseIOCollisions(*emit, *emitTasks, *vectorsPath, verifyPaths); err != nil {
		return err
	}

	vectors, err := loadVectors(*vectorsPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*vectorsPath) != "" {
		fmt.Fprintf(out, "vectors loaded from %s (not computed from this tree)\n", *vectorsPath)
	}

	if *emit != "" {
		if err := emitVectors(vectors, *emit, out); err != nil {
			return err
		}
	}
	if *emitTasks != "" {
		if err := emitTaskList(vectors, *emitTasks, out); err != nil {
			return err
		}
	}
	if *showMatrix {
		printMatrix(out, vectors)
	}
	if len(verifyPaths) > 0 {
		return verifyReports(out, vectors, verifyPaths)
	}
	return nil
}

// emitTaskList writes the TASK LIST a non-Go host harness reads.
//
// # Why a second, line-oriented format when the vectors are already JSON
//
// A Kotlin or Swift harness that had to parse the vector JSON would need a JSON
// parser it does not otherwise have, and a hand-rolled one is sixty lines of
// exactly the kind of code that fails quietly on the row nobody looked at. This
// format is `key value...` per line: `split(' ')` is the whole parser.
//
// It carries INPUTS ONLY — never an expected answer. A harness that could see
// the expected value could be written, honestly or accidentally, to echo it;
// this way the only thing a harness can do is run its host's real derivation.
// The comparison happens back in this command, against vectors the harness
// never saw.
//
// Byte-valued inputs are hex so that whitespace in an operator value survives
// the round trip through a line-oriented file. That is not hypothetical: the
// suite deliberately runs an operator id with a trailing space, because the Go
// gateway keys with it and every INI-reading host trims it away.
func emitTaskList(v conform.Vectors, path string, out io.Writer) error {
	var sb strings.Builder
	sb.WriteString("# winn/3 conformance task list — GENERATED by cmd/winn3-conformance.\n")
	sb.WriteString("# Inputs only. No expected value appears here, so a harness cannot echo one.\n")
	sb.WriteString("# Format: <key> <field>...   (split on spaces; '#' starts a comment line)\n")
	fmt.Fprintf(&sb, "operator_gateway_id_hex %s\n", v.Admission.GatewayIDHex)
	fmt.Fprintf(&sb, "operator_admission_file_hex %s\n", hexString(v.Operator.AdmissionFile))
	fmt.Fprintf(&sb, "operator_path_mtu %d\n", v.Operator.PathMTU)
	fmt.Fprintf(&sb, "operator_classes %s\n", strings.Join(v.Operator.CarrierClasses, ","))
	for _, row := range v.Floors {
		fmt.Fprintf(&sb, "floor %s %d\n", strings.Join(row.Classes, ","), row.PathMTU)
	}
	for _, o := range v.Overheads {
		family := "6"
		if o.IPv4 {
			family = "4"
		}
		fmt.Fprintf(&sb, "overhead %s %s\n", o.Class, family)
	}
	body := []byte(sb.String())
	if path == "-" {
		_, err := out.Write(body)
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // inputs are public
		return fmt.Errorf("-emit-tasks %q: %w", path, err)
	}
	fmt.Fprintf(out, "wrote the winn/3 conformance task list to %s\n", path)
	return nil
}

func hexString(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}

func loadVectors(path string) (conform.Vectors, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		v, err := conform.BuildVectors(conform.Reference())
		if err != nil {
			return conform.Vectors{}, unproven("the reference vectors could not be computed: %v", err)
		}
		return v, nil
	}
	if path == "-" {
		return conform.Vectors{}, unproven("-vectors does not read stdin; pass a file path (use -emit - to write vectors to stdout)")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-named
	if err != nil {
		return conform.Vectors{}, unproven("-vectors %q: %v", path, err)
	}
	var v conform.Vectors
	if err := jsonUnmarshalStrict(raw, &v); err != nil {
		return conform.Vectors{}, unproven("-vectors %q: %v", path, err)
	}
	return v, nil
}

func emitVectors(v conform.Vectors, path string, out io.Writer) error {
	body, err := v.JSON()
	if err != nil {
		return err
	}
	if path == "-" {
		_, err = out.Write(body)
		return err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // vectors are public
		return fmt.Errorf("-emit %q: %w", path, err)
	}
	fmt.Fprintf(out, "wrote %d bytes of winn/3 conformance vectors to %s\n", len(body), path)
	return nil
}

// verifyReports is the whole point of the command.
func verifyReports(out io.Writer, v conform.Vectors, paths []string) error {
	if len(paths) == 0 {
		return unproven("-verify named no report paths; pass -verify path/to/report.json (comma-separated for several)")
	}

	type outcome struct {
		report conform.HostReport
		ms     []conform.Mismatch
		err    error
	}
	outcomes := make([]outcome, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // operator-named
		if err != nil {
			outcomes = append(outcomes, outcome{err: fmt.Errorf("-verify %s: %w", p, err)})
			continue
		}
		r, err := conform.ParseHostReport(raw)
		if err != nil {
			outcomes = append(outcomes, outcome{err: fmt.Errorf("-verify %s: %w", p, err)})
			continue
		}
		outcomes = append(outcomes, outcome{report: r, ms: conform.VerifyReport(v, r)})
	}

	fmt.Fprintf(out, "\nwinn/3 CROSS-HOST CONFORMANCE\n")
	fmt.Fprintf(out, "operator configuration: gateway_id=%q admission=%d bytes path_mtu=%d classes=%v\n\n",
		v.Operator.GatewayID, v.Admission.AdmissionKeyLen, v.Operator.PathMTU,
		v.Operator.CarrierClasses)

	failed, unreadable, comparedNothing := 0, 0, 0
	for _, o := range outcomes {
		switch {
		case o.err != nil:
			unreadable++
			fmt.Fprintf(out, "  UNREADABLE  %v\n", o.err)
		case len(o.ms) > 0:
			failed++
			fmt.Fprintf(out, "  DIVERGES    %s (%s) — %d field(s)\n",
				o.report.Host, o.report.Language, len(o.ms))
		case hostReportedNoValues(o.report):
			comparedNothing++
			fmt.Fprintf(out, "  COMPARED NOTHING  %s (%s) — every compared field is empty and not_derived; that is not agreement\n",
				o.report.Host, o.report.Language)
		default:
			fmt.Fprintf(out, "  AGREES      %s (%s)\n", o.report.Host, o.report.Language)
		}
	}

	for _, o := range outcomes {
		if len(o.ms) > 0 {
			fmt.Fprint(out, conform.ExplainReport(v, o.report, o.ms))
		}
	}

	if len(v.RegressionPins) > 0 {
		fmt.Fprintf(out, "\nREGRESSION PINS (tier A′: fixed; a return FAILS the build)\n")
		for _, p := range v.RegressionPins {
			fmt.Fprintf(out, "  %s  (fixed %s)\n      %s\n      symptom: %s\n      held by: %s\n",
				p.ID, p.FixedOn, p.Defect, p.Symptom, strings.Join(p.HeldBy, ", "))
		}
	}
	if len(v.KnownDivergences) > 0 {
		fmt.Fprintf(out, "\nKNOWN DIVERGENCES (tier B: measured, named, not yet fixed)\n")
		for _, d := range v.KnownDivergences {
			fmt.Fprintf(out, "  %s\n      A: %s\n      B: %s\n      %s\n      consequence: %s\n      fix: %s\n",
				d.ID, d.A, d.B, d.Behaviour, d.Consequence, d.Fix)
		}
	}

	switch {
	case failed > 0:
		return fmt.Errorf("\n%d host(s) diverge from the reference. Every one of these produces "+
			"no session and no error on either side", failed)
	case unreadable > 0:
		return unproven("\n%d host report(s) could not be read. A conformance run that did not "+
			"reach a host proves nothing about it, and a green pipeline that skipped a platform "+
			"looks exactly like one that covered it.", unreadable)
	case comparedNothing > 0:
		return unproven("\n%d host(s) declared every field not_derived (or reported no values), so this "+
			"run compared nothing. A host that skips every field looks like agreement and is not. "+
			"Drop the not_derived declarations for fields the host actually computes, or omit that host.",
			comparedNothing)
	}
	fmt.Fprintf(out, "\nall %d host(s) derive byte-identical admission-tag inputs and identical plan floors\n",
		len(outcomes))
	return nil
}

func printMatrix(out io.Writer, v conform.Vectors) {
	fmt.Fprintf(out, "\nplan-floor matrix (message size / inner MTU / inner v6) — "+
		"'dialled' is the UDP-over-IPv4 number defect 2 shipped\n\n")
	fmt.Fprintf(out, "  %-18s %8s %10s %10s %8s %8s %7s\n",
		"plan", "path", "message", "innerMTU", "innerv6", "dialled", "gap")
	for _, row := range v.Floors {
		fmt.Fprintf(out, "  %-18s %8d %10d %10d %8t %8d %7d\n",
			"["+strings.Join(row.Classes, ",")+"]", row.PathMTU, row.MessageSize,
			row.InnerMTU, row.InnerIPv6, row.DialledUDPv4InnerMTU, row.Gap)
	}
	fmt.Fprintf(out, "\ncarrier overheads\n\n")
	rows := make([]string, 0, len(v.Overheads))
	for _, o := range v.Overheads {
		family := "IPv6"
		if o.IPv4 {
			family = "IPv4"
		}
		rows = append(rows, fmt.Sprintf("  %-4s over %-4s  %4d", o.Class, family, o.Overhead))
	}
	sort.Strings(rows)
	for _, r := range rows {
		fmt.Fprintln(out, r)
	}
	fmt.Fprintln(out)
}

func splitPaths(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// refusePositionalArgs is one accept-transit-shaped pair for this binary: Go's
// flag parser silently ignores extra operands, so
// `winn3-conformance -verify a.json b.json` used to verify a.json, drop b.json,
// and exit 0. The systemd unit that never passed -accept-transit=true with
// -forward is the same class — a required companion that was not passed, and
// the process still "started".
func refusePositionalArgs(args []string, verifyAlready string) error {
	if len(args) == 0 {
		return nil
	}
	if verifyAlready != "" {
		combined := verifyAlready + "," + strings.Join(args, ",")
		return unproven("unexpected positional arguments %q after -verify %q. -verify takes a comma-separated list, not extra operands. Pass -verify %s",
			args, verifyAlready, combined)
	}
	return unproven("unexpected positional arguments %q: this command does not take report paths as "+
		"operands. Pass -verify %s (comma-separated for several). A space-separated extra path is "+
		"ignored by the flag parser, which is how a report can go unchecked while the run still exits 0",
		args, strings.Join(args, ","))
}

// refuseIOCollisions is the other remaining pair of the -accept-transit shape:
// two flags that look configured, the process still exits 0, and one output is
// lost or the failure names the wrong cause.
//
//   - -emit and -emit-tasks against the same path used to overwrite the first
//     file and still exit 0.
//   - both "-" used to mix JSON vectors and the task list on stdout.
//   - -verify of a path also passed to -emit / -emit-tasks / -vectors used to
//     fail as "host report names no host" / unknown field — the wrong cause.
func refuseIOCollisions(emit, emitTasks, vectors string, verifyPaths []string) error {
	emit = strings.TrimSpace(emit)
	emitTasks = strings.TrimSpace(emitTasks)
	vectors = strings.TrimSpace(vectors)

	if emit != "" && emitTasks != "" && sameOutputPath(emit, emitTasks) {
		if emit == "-" {
			return unproven("-emit - and -emit-tasks - both write stdout; pass a file path for one of them so the JSON vectors and the task list are not mixed")
		}
		return unproven("-emit and -emit-tasks both write to %q; the second would overwrite the first and the run would still exit 0. Pass two different paths", emit)
	}

	check := func(flagName, path string) error {
		if path == "" || path == "-" {
			return nil
		}
		for _, v := range verifyPaths {
			if sameOutputPath(path, v) {
				return unproven("-verify %q is the same path as %s; a vector file or task list is not a host report, and the failure would say the report is unreadable rather than that the flags collide. Pass a host-report path to -verify", v, flagName)
			}
		}
		return nil
	}
	if err := check("-emit "+emit, emit); err != nil {
		return err
	}
	if err := check("-emit-tasks "+emitTasks, emitTasks); err != nil {
		return err
	}
	if err := check("-vectors "+vectors, vectors); err != nil {
		return err
	}
	return nil
}

func sameOutputPath(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == "-" || b == "-" {
		return a == b
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// checkVerifyPaths names the fix for every -verify list the binary refuses.
func checkVerifyPaths(verify string) ([]string, error) {
	paths := splitPaths(verify)
	if len(paths) == 0 {
		return nil, unproven("-verify %q named no report paths; pass -verify path/to/report.json "+
			"(comma-separated for several)", verify)
	}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if p == "-" {
			return nil, unproven("-verify does not read stdin; pass a file path (use -emit - to write "+
				"vectors to stdout)")
		}
		if _, dup := seen[p]; dup {
			return nil, unproven("-verify lists %q more than once; duplicated paths are counted as "+
				"separate hosts, so N copies of one report look like N hosts agreed. Pass each report once",
				p)
		}
		seen[p] = struct{}{}
	}
	return paths, nil
}

// hostReportedNoValues is true when a report carries no compared payload.
// Combined with zero mismatches that is the §3.11 hole: a host that puts every
// field in not_derived used to print AGREES and exit 0.
func hostReportedNoValues(r conform.HostReport) bool {
	return r.GatewayIDHex == "" && r.AdmissionKeyHex == "" && r.TagSize == 0 &&
		r.PathMTU == 0 && len(r.CarrierClasses) == 0 && r.MessageSize == 0 &&
		r.InnerMTU == 0 && !r.InnerIPv6 && !r.TransportObservedBothWays &&
		len(r.Floors) == 0 && len(r.Overheads) == 0
}
