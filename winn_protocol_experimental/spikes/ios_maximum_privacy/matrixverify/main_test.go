package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestVerifyMatrixAcceptsCompleteMatchedFixture(t *testing.T) {
	path := writeValidMatrix(t)
	summary, err := verifyFixtureMatrix(t, path)
	if err != nil {
		t.Fatal(err)
	}
	manifest := loadFixtureManifest(t, path)
	wantWorst := startLatencyFor(len(manifest.Runs) - 1)
	if summary.Pairs != 16 ||
		summary.FullFsyncEvidenceRuns != len(manifest.Runs) ||
		summary.FsyncOnlyEvidenceRuns != 0 ||
		summary.WiFiKernelMedianOverhead < 0.09 ||
		summary.WiFiKernelMedianOverhead > 0.11 ||
		summary.CellBatteryMedianOverhead < 0.09 ||
		summary.CellBatteryMedianOverhead > 0.11 ||
		summary.IdleIncrementalWakeupsSecond != 1 ||
		summary.WorstHostStartLatency != wantWorst {
		t.Fatalf("summary = %#v, want worst latency %d", summary, wantWorst)
	}
}

func TestMatrixInvokesAFreshRealEvidenceVerifier(t *testing.T) {
	path := writeValidMatrix(t)
	experimentRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	verifier := filepath.Join(t.TempDir(), "evidenceverify")
	command := exec.Command(
		"go", "build",
		"-trimpath",
		"-buildvcs=false",
		"-o", verifier,
		"./spikes/ios_maximum_privacy/evidenceverify",
	)
	command.Dir = experimentRoot
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh evidenceverify build: %v: %s", err, output)
	}
	content, err := os.ReadFile(verifier)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	_, err = verifyMatrix(path, verifier, hex.EncodeToString(digest[:]))
	if err == nil ||
		!strings.Contains(err.Error(), "single-run verifier: rejected evidence") {
		t.Fatalf("real evidenceverify integration error = %v", err)
	}
}

func TestVerifyMatrixUsesOnlyTheSealedInputSet(t *testing.T) {
	path := writeValidMatrix(t)
	manifest := loadFixtureManifest(t, path)
	base := filepath.Dir(path)
	originalHook := afterMatrixInputsSealed
	t.Cleanup(func() { afterMatrixInputsSealed = originalHook })
	afterMatrixInputsSealed = func() {
		targets := []string{
			path,
			filepath.Join(base, manifest.Runs[0].Evidence),
			filepath.Join(base, manifest.Runs[0].StartReceipt),
		}
		for _, run := range manifest.Runs {
			if run.StopReceipt != "" {
				targets = append(
					targets, filepath.Join(base, run.StopReceipt),
				)
				break
			}
		}
		for _, target := range targets {
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := verifyFixtureMatrix(t, path); err != nil {
		t.Fatalf("sealed matrix failed after source replacement: %v", err)
	}
}

func TestPublishSealedBytesRejectsDestinationTraversal(t *testing.T) {
	sealedRoot := t.TempDir()
	escaped := filepath.Join(filepath.Dir(sealedRoot), "escaped-matrix-input")
	if err := publishSealedBytes(
		sealedRoot, "../escaped-matrix-input", []byte("value"), 0o400,
	); err == nil {
		t.Fatal("destination traversal accepted")
	}
	if _, err := os.Lstat(escaped); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination traversal created %q: %v", escaped, err)
	}
}

func TestCanonicalEvidencePassIsExactlyOneLine(t *testing.T) {
	canonical := "IOS_SPIKE_VERIFY_PASS records=2 " +
		"run_id=00000001-0000-0000-0000-000000000001 " +
		"artifact=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb " +
		"evidence_barrier=f-fullfsync " +
		"resident_slope_bytes_per_hour=0.000 energy_available=true " +
		"energy_delta_nj=1 host_packet_tunnel_activation_latency_ns=1\n"
	if !canonicalEvidencePass.MatchString(canonical) {
		t.Fatal("canonical receipt rejected")
	}
	for _, malformed := range []string{
		strings.TrimSuffix(canonical, "\n"),
		canonical + "extra\n",
		"prefix\n" + canonical,
		strings.Replace(canonical, "records=2", "records=0", 1),
	} {
		if canonicalEvidencePass.MatchString(malformed) {
			t.Fatalf("non-canonical receipt accepted: %q", malformed)
		}
	}
}

func TestVerifyMatrixRefusesVerifierPinDriftAndSuccessStderr(t *testing.T) {
	path := writeValidMatrix(t)
	t.Run("wrong digest", func(t *testing.T) {
		verifier, digest := writeFixtureVerifier(t, "")
		wrong := strings.Repeat("a", 64)
		if wrong == digest {
			wrong = strings.Repeat("b", 64)
		}
		if _, err := verifyMatrix(path, verifier, wrong); err == nil ||
			!strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Fatalf("verifier pin mismatch error = %v", err)
		}
	})
	t.Run("all-zero digest", func(t *testing.T) {
		verifier, _ := writeFixtureVerifier(t, "")
		if _, err := verifyMatrix(
			path,
			verifier,
			strings.Repeat("0", 64),
		); err == nil {
			t.Fatal("all-zero verifier pin accepted")
		}
	})
	t.Run("stderr on success", func(t *testing.T) {
		verifier, digest := writeFixtureVerifier(
			t, "printf 'unexpected diagnostic\\n' >&2\n",
		)
		if _, err := verifyMatrix(path, verifier, digest); err == nil ||
			!strings.Contains(err.Error(), "wrote stderr on success") {
			t.Fatalf("success-stderr error = %v", err)
		}
	})
}

func TestVerifyMatrixRejectsStrictJSONViolationsAtEveryBoundary(t *testing.T) {
	t.Run("manifest duplicate", func(t *testing.T) {
		path := writeValidMatrix(t)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content = bytes.Replace(
			content,
			[]byte(`"schema": "winn-ios-privacy-matrix/1",`),
			[]byte(`"schema": "winn-ios-privacy-matrix/1",`+
				`"schema": "winn-ios-privacy-matrix/1",`),
			1,
		)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(err.Error(), "repeats member") {
			t.Fatalf("duplicate manifest error = %v", err)
		}
	})

	t.Run("evidence nested duplicate", func(t *testing.T) {
		path := writeValidMatrix(t)
		manifest := loadFixtureManifest(t, path)
		base := filepath.Dir(path)
		evidencePath := filepath.Join(base, manifest.Runs[0].Evidence)
		content, err := os.ReadFile(evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		content = bytes.Replace(
			content,
			[]byte(`"cellBytes":0`),
			[]byte(`"cellBytes":0,"cellBytes":0`),
			1,
		)
		if err := os.WriteFile(evidencePath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		manifest.Runs[0].EvidenceSHA256 = hex.EncodeToString(digest[:])
		writeFixtureManifest(t, path, manifest)
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(err.Error(), "repeats member") {
			t.Fatalf("duplicate evidence error = %v", err)
		}
	})

	t.Run("start receipt case variant", func(t *testing.T) {
		path := writeValidMatrix(t)
		manifest := loadFixtureManifest(t, path)
		startPath := filepath.Join(
			filepath.Dir(path), manifest.Runs[0].StartReceipt,
		)
		content, err := os.ReadFile(startPath)
		if err != nil {
			t.Fatal(err)
		}
		content = bytes.Replace(
			content, []byte(`"runID"`), []byte(`"RunID"`), 1,
		)
		if err := os.WriteFile(startPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		repinManifest(t, path)
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(err.Error(), "case variant") {
			t.Fatalf("case-variant start receipt error = %v", err)
		}
	})

	t.Run("stop receipt missing member", func(t *testing.T) {
		path := writeValidMatrix(t)
		manifest := loadFixtureManifest(t, path)
		var index int
		for index = range manifest.Runs {
			if manifest.Runs[index].StopReceipt != "" {
				break
			}
		}
		stopPath := filepath.Join(
			filepath.Dir(path), manifest.Runs[index].StopReceipt,
		)
		var receipt map[string]any
		content, err := os.ReadFile(stopPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(content, &receipt); err != nil {
			t.Fatal(err)
		}
		delete(receipt, "roundTripNanoseconds")
		content, err = json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		content = append(content, '\n')
		if err := os.WriteFile(stopPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		manifest.Runs[index].StopReceiptSHA256 =
			hex.EncodeToString(digest[:])
		writeFixtureManifest(t, path, manifest)
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(err.Error(), "missing required member") {
			t.Fatalf("missing Stop receipt member error = %v", err)
		}
	})
}

func TestVerifyMatrixRejectsTamperedEvidence(t *testing.T) {
	path := writeValidMatrix(t)
	var manifest matrixManifest
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(filepath.Dir(path), manifest.Runs[0].Evidence)
	file, err := os.OpenFile(evidence, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFixtureMatrix(t, path); err == nil ||
		!strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestVerifyMatrixRejectsEvidenceSymlinkEscape(t *testing.T) {
	path := writeValidMatrix(t)
	var manifest matrixManifest
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(path)
	evidence := filepath.Join(base, manifest.Runs[0].Evidence)
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	original, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(evidence); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFixtureMatrix(t, path); err == nil {
		t.Fatal("evidence symlink escaped the manifest root")
	}
}

func TestVerifyPairRejectsDifferentCommonWork(t *testing.T) {
	pair := syntheticPair("foreground-wifi", "low", 1, 1)
	pair.privacy.terminal.DataPath.CommonPathChecksum++
	if err := verifyPair(pair); err == nil ||
		!strings.Contains(err.Error(), "common-path") {
		t.Fatalf("pair error = %v", err)
	}
}

func TestManifestRunRejectsTraversal(t *testing.T) {
	run := syntheticPair("foreground-wifi", "low", 1, 1).core.manifest
	run.Evidence = "../outside.jsonl"
	if err := validateManifestRun(run); err == nil {
		t.Fatal("traversal path accepted")
	}
}

func TestRequiredCoverageRejectsShortNoncanonicalPair(t *testing.T) {
	pair := syntheticPair("foreground-wifi", "low", 1, 1)
	pair.core.manifest.DurationSeconds = 60
	pair.privacy.manifest.DurationSeconds = 60
	if err := verifyRequiredCoverage(
		[]matchedPair{pair},
		nil,
	); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("canonical error = %v", err)
	}
}

func TestIdleWakeupsEvaluatesEveryEligiblePair(t *testing.T) {
	safe := syntheticPair("foreground-wifi", "idle", 1, 1)
	noisy := syntheticPair("foreground-wifi", "idle", 2, 2)
	high := uint64(1_000)
	noisy.privacy.terminal.WholeRunResourceWindow.
		InterruptWakeupDelta = &high
	if _, err := verifyIdleWakeups(
		[]matchedPair{safe, noisy},
	); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("idle wakeup error = %v", err)
	}
}

func TestVerifyMatrixRejectsATamperedStartReceipt(t *testing.T) {
	path := writeValidMatrix(t)
	manifest := loadFixtureManifest(t, path)
	receipt := filepath.Join(
		filepath.Dir(path),
		manifest.Runs[0].StartReceipt,
	)
	rewriteFixtureStartReceipt(t, receipt, func(r *startReceipt) {
		r.HostStartLatencyNanoseconds++
	})
	if _, err := verifyFixtureMatrix(t, path); err == nil ||
		!strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("tampered start receipt error = %v", err)
	}
}

func TestVerifyMatrixRejectsAnUnpinnedStartReceiptMutation(t *testing.T) {
	cases := map[string]func(*startReceipt){
		"latencies do not match": func(r *startReceipt) {
			r.HostStartLatencyNanoseconds++
		},
		"exceeds": func(r *startReceipt) {
			r.HostStartLatencyNanoseconds =
				maximumHostStartLatencyNanoseconds + 1
			r.HostObservedConnectedAtMonotonicNanoseconds =
				r.RequestedAtMonotonicNanoseconds +
					r.HostStartLatencyNanoseconds
		},
		"not bound to this run": func(r *startReceipt) {
			r.RunID = fixtureUUID(777)
		},
		"schema or scope is invalid": func(r *startReceipt) {
			r.MeasurementScope = "usable-vpn-connection"
		},
		"first-record length is invalid": func(r *startReceipt) {
			r.FirstRecordBytes++
		},
		"clocks are reversed": func(r *startReceipt) {
			r.HostObservedConnectedAtMonotonicNanoseconds =
				r.ProviderReadyAtMonotonicNanoseconds - 1
			r.HostStartLatencyNanoseconds =
				r.HostObservedConnectedAtMonotonicNanoseconds -
					r.RequestedAtMonotonicNanoseconds
		},
	}
	for expected, mutate := range cases {
		path := writeValidMatrix(t)
		manifest := loadFixtureManifest(t, path)
		rewriteFixtureStartReceipt(
			t,
			filepath.Join(
				filepath.Dir(path),
				manifest.Runs[0].StartReceipt,
			),
			mutate,
		)
		repinManifest(t, path)
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(err.Error(), expected) {
			t.Fatalf("%q error = %v", expected, err)
		}
	}
}

// The activation receipt must hash the first line INCLUDING its line feed.
func TestVerifyMatrixStartReceiptDigestIncludesTheLineFeed(t *testing.T) {
	path := writeValidMatrix(t)
	manifest := loadFixtureManifest(t, path)
	base := filepath.Dir(path)
	evidence, err := os.ReadFile(
		filepath.Join(base, manifest.Runs[0].Evidence),
	)
	if err != nil {
		t.Fatal(err)
	}
	feed := bytes.IndexByte(evidence, '\n')
	if feed < 0 {
		t.Fatal("fixture evidence has no line feed")
	}
	stripped := sha256.Sum256(evidence[:feed])
	rewriteFixtureStartReceipt(
		t,
		filepath.Join(base, manifest.Runs[0].StartReceipt),
		func(r *startReceipt) {
			if r.FirstRecordSHA256 == hex.EncodeToString(stripped[:]) {
				t.Fatal("the line feed made no difference to the digest")
			}
			r.FirstRecordSHA256 = hex.EncodeToString(stripped[:])
		},
	)
	repinManifest(t, path)
	if _, err := verifyFixtureMatrix(t, path); err == nil ||
		!strings.Contains(err.Error(), "does not pin the first evidence record") {
		t.Fatalf("line-feed digest error = %v", err)
	}
}

func TestMatrixIndependentlyBindsFirstRecordActivationIdentity(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"attempt nonce": func(record map[string]any) {
			record["startAttemptNonce"] =
				"ffffffff-ffff-ffff-ffff-ffffffffffff"
		},
		"request timestamp": func(record map[string]any) {
			record["startRequestedAtMonotonicNanoseconds"] =
				float64(1_000_000_001)
		},
		"provider timestamp": func(record map[string]any) {
			record["providerReceivedAtMonotonicNanoseconds"] =
				float64(1_001_000_001)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			path := writeValidMatrix(t)
			manifest := loadFixtureManifest(t, path)
			base := filepath.Dir(path)
			run := &manifest.Runs[0]
			evidencePath := filepath.Join(base, run.Evidence)
			evidence, err := os.ReadFile(evidencePath)
			if err != nil {
				t.Fatal(err)
			}
			feed := bytes.IndexByte(evidence, '\n')
			if feed < 0 {
				t.Fatal("fixture first record has no line feed")
			}
			var first map[string]any
			if err := json.Unmarshal(evidence[:feed], &first); err != nil {
				t.Fatal(err)
			}
			mutate(first)
			firstBytes, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			firstLine := append(firstBytes, '\n')
			evidence = append(firstLine, evidence[feed+1:]...)
			if err := os.WriteFile(evidencePath, evidence, 0o600); err != nil {
				t.Fatal(err)
			}
			evidenceDigest := sha256.Sum256(evidence)
			run.EvidenceSHA256 = hex.EncodeToString(evidenceDigest[:])

			startPath := filepath.Join(base, run.StartReceipt)
			var receipt startReceipt
			startBytes, err := os.ReadFile(startPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(startBytes, &receipt); err != nil {
				t.Fatal(err)
			}
			firstDigest := sha256.Sum256(firstLine)
			receipt.FirstRecordSHA256 =
				hex.EncodeToString(firstDigest[:])
			receipt.FirstRecordBytes = uint64(len(firstLine))
			startBytes, err = json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			startBytes = append(startBytes, '\n')
			if err := os.WriteFile(startPath, startBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			startDigest := sha256.Sum256(startBytes)
			run.StartReceiptSHA256 = hex.EncodeToString(startDigest[:])
			writeFixtureManifest(t, path, manifest)

			if _, err := verifyFixtureMatrix(t, path); err == nil ||
				!strings.Contains(
					err.Error(),
					"first record identity",
				) {
				t.Fatalf("first-record identity error = %v", err)
			}
		})
	}
}

func TestVerifyMatrixRejectsInvalidReceiptArtifactAndBarrierScopes(t *testing.T) {
	mutations := map[string]func(*startReceipt){
		"evidence durability barrier is invalid": func(r *startReceipt) {
			r.EvidenceDurabilityBarrier = "fake-custom-barrier"
		},
		"artifact or host-receipt scope is invalid": func(r *startReceipt) {
			r.ArtifactScope = "attempt-success-claim"
		},
		"artifact or host-receipt scope is invalid\x00host": func(r *startReceipt) {
			r.HostReceiptDurabilityScope = "guaranteed-power-loss-safe"
		},
	}
	for expected, mutate := range mutations {
		path := writeValidMatrix(t)
		manifest := loadFixtureManifest(t, path)
		rewriteFixtureStartReceipt(
			t,
			filepath.Join(
				filepath.Dir(path),
				manifest.Runs[0].StartReceipt,
			),
			mutate,
		)
		repinManifest(t, path)
		if _, err := verifyFixtureMatrix(t, path); err == nil ||
			!strings.Contains(
				err.Error(),
				strings.Split(expected, "\x00")[0],
			) {
			t.Fatalf("%q error = %v", expected, err)
		}
	}
}

func TestVerifyMatrixAcceptsFsyncOnlyEvidenceBarrier(t *testing.T) {
	path := writeValidMatrix(t)
	manifest := loadFixtureManifest(t, path)
	rewriteFixtureStartReceipt(
		t,
		filepath.Join(
			filepath.Dir(path),
			manifest.Runs[0].StartReceipt,
		),
		func(receipt *startReceipt) {
			receipt.EvidenceDurabilityBarrier =
				evidenceDurabilityFsyncOnly
		},
	)
	repinManifest(t, path)
	summary, err := verifyFixtureMatrix(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if summary.FullFsyncEvidenceRuns != len(manifest.Runs)-1 ||
		summary.FsyncOnlyEvidenceRuns != 1 {
		t.Fatalf("barrier counts = %#v", summary)
	}
}

func TestVerifyMatrixRejectsAllZeroProvenanceDigest(t *testing.T) {
	path := writeValidMatrix(t)
	manifest := loadFixtureManifest(t, path)
	manifest.ArtifactDigest = strings.Repeat("0", 64)
	writeFixtureManifest(t, path, manifest)
	if _, err := verifyFixtureMatrix(t, path); err == nil {
		t.Fatal("all-zero matrix artifact digest accepted")
	}
}

func TestManifestRunRequiresAStartReceipt(t *testing.T) {
	run := syntheticPair("foreground-wifi", "low", 1, 1).core.manifest
	run.Evidence = "0000-run.jsonl"
	run.StartReceipt = ""
	run.StartReceiptSHA256 = ""
	if err := validateManifestRun(run); err == nil ||
		!strings.Contains(err.Error(), "start receipt") {
		t.Fatalf("absent start receipt error = %v", err)
	}
	run.StartReceipt = "../outside.start-receipt.json"
	run.StartReceiptSHA256 = strings.Repeat("a", 64)
	if err := validateManifestRun(run); err == nil {
		t.Fatal("start receipt traversal accepted")
	}
}

func TestMatrixManifestRunAndReceiptShapesMatchStructTags(t *testing.T) {
	for _, testCase := range []struct {
		shape *jsonShape
		value any
	}{
		{startReceiptShape, startReceipt{}},
		{manifestRunShape, manifestRun{}},
	} {
		gotRequired, gotOptional := matrixShapeMemberNames(testCase.shape)
		wantRequired, wantOptional := matrixStructTagNames(
			t,
			testCase.value,
		)
		if !reflect.DeepEqual(gotRequired, wantRequired) {
			t.Fatalf(
				"%s required = %v, struct = %v",
				testCase.shape.name,
				gotRequired,
				wantRequired,
			)
		}
		if !reflect.DeepEqual(gotOptional, wantOptional) {
			t.Fatalf(
				"%s optional = %v, struct = %v",
				testCase.shape.name,
				gotOptional,
				wantOptional,
			)
		}
	}
}

func matrixShapeMemberNames(shape *jsonShape) ([]string, []string) {
	required := []string{}
	optional := []string{}
	for name, member := range shape.members {
		if member.required {
			required = append(required, name)
		} else {
			optional = append(optional, name)
		}
	}
	sort.Strings(required)
	sort.Strings(optional)
	return required, optional
}

func matrixStructTagNames(t *testing.T, value any) ([]string, []string) {
	t.Helper()
	required := []string{}
	optional := []string{}
	structType := reflect.TypeOf(value)
	for index := 0; index < structType.NumField(); index++ {
		tag := structType.Field(index).Tag.Get("json")
		if tag == "" {
			continue
		}
		if tag == "-" {
			t.Fatalf(
				"%s.%s explicitly suppresses JSON",
				structType.Name(),
				structType.Field(index).Name,
			)
		}
		parts := strings.Split(tag, ",")
		if len(parts) > 1 && parts[1] == "omitempty" {
			optional = append(optional, parts[0])
			continue
		}
		required = append(required, parts[0])
	}
	sort.Strings(required)
	sort.Strings(optional)
	return required, optional
}

func writeValidMatrix(t *testing.T) string {
	t.Helper()
	manifest := matrixManifest{
		Schema:          manifestSchema,
		ProtocolVersion: protocolVersion,
		SourceDigest:    strings.Repeat("a", 64),
		ArtifactDigest:  strings.Repeat("b", 64),
		OSVersion:       "fixture-ios",
		HardwareModel:   "fixture-iphone",
	}
	var runs []checkedRun
	nextPair := 1
	addPairs := func(condition, profile string, count int) {
		for repeat := 1; repeat <= count; repeat++ {
			pair := syntheticPair(
				condition, profile, repeat, nextPair,
			)
			nextPair++
			runs = append(runs, pair.core, pair.privacy)
		}
	}
	addPairs("foreground-wifi", "idle", 1)
	addPairs("foreground-wifi", "low", 3)
	addPairs("foreground-wifi", "medium", 3)
	addPairs("foreground-wifi", "saturated", 1)
	addPairs("locked-wifi", "low", 1)
	addPairs("locked-wifi", "medium", 1)
	addPairs("unplugged-cellular", "low", 3)
	addPairs("unplugged-cellular", "medium", 3)

	runs = append(
		runs,
		syntheticSingle("low-power-mode", nextPair),
		syntheticSingle("accelerated-allocation", nextPair+1),
		syntheticSingle("eight-hour-locked", nextPair+2),
		syntheticSingle("stop-latency", nextPair+3),
	)

	base := t.TempDir()
	for index := range runs {
		run := &runs[index]
		run.terminal.SourceDigest = manifest.SourceDigest
		run.terminal.ArtifactDigest = manifest.ArtifactDigest
		run.terminal.OSVersion = manifest.OSVersion
		run.terminal.HardwareModel = manifest.HardwareModel
		run.terminal.RunID = fixtureUUID(10_000 + index)
		// The activation receipt binds `<runID>.jsonl`, which is how the host
		// names every collected file.
		run.manifest.Evidence = run.terminal.RunID + ".jsonl"
		nonceNumber := 20_000 + index
		latency := startLatencyFor(index)
		content := encodeEvidence(
			t, run.terminal, fixtureUUID(nonceNumber), latency,
		)
		digest := sha256.Sum256(content)
		run.manifest.EvidenceSHA256 =
			hex.EncodeToString(digest[:])
		if err := os.WriteFile(
			filepath.Join(base, run.manifest.Evidence),
			content,
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		writeFixtureStartReceipt(
			t,
			base,
			&run.manifest,
			run.terminal.RunID,
			manifest.SourceDigest,
			content,
			nonceNumber,
			latency,
		)
		if run.manifest.ExpectedTerminal == "stop-acknowledged" {
			evidenceDigest := sha256.Sum256(content)
			receiptObject := map[string]any{
				"schema":                                 "winn-ios-privacy-spike-stop-receipt/1",
				"protocolVersion":                        protocolVersion,
				"runID":                                  run.terminal.RunID,
				"evidenceFileName":                       run.manifest.Evidence,
				"evidenceSHA256":                         hex.EncodeToString(evidenceDigest[:]),
				"requestedAtMonotonicNanoseconds":        uint64(8_000_000_000),
				"providerReceivedAtMonotonicNanoseconds": uint64(8_010_000_000),
				"providerAcknowledgedAtMonotonicNanoseconds": uint64(8_020_000_000),
				"hostReceivedAtMonotonicNanoseconds":         uint64(8_030_000_000),
				"roundTripNanoseconds":                       uint64(30_000_000),
			}
			receipt, err := json.Marshal(receiptObject)
			if err != nil {
				t.Fatal(err)
			}
			receipt = append(receipt, '\n')
			receiptDigest := sha256.Sum256(receipt)
			run.manifest.StopReceipt =
				fmt.Sprintf("run-%02d.stop-receipt.json", index)
			run.manifest.StopReceiptSHA256 =
				hex.EncodeToString(receiptDigest[:])
			if err := os.WriteFile(
				filepath.Join(base, run.manifest.StopReceipt),
				receipt,
				0o600,
			); err != nil {
				t.Fatal(err)
			}
		}
		manifest.Runs = append(manifest.Runs, run.manifest)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "matrix.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func syntheticPair(
	condition string,
	profile string,
	repeat int,
	pairNumber int,
) matchedPair {
	pairID := fixtureUUID(pairNumber)
	duration := uint64(1_800)
	if profile == "idle" {
		duration = 300
	}
	core := syntheticRun(
		"core-baseline", condition, profile, repeat, pairID, duration,
	)
	privacy := syntheticRun(
		"maximum-privacy", condition, profile, repeat, pairID, duration,
	)
	core.terminal.DataPath.CommonPathChecksum = 42
	privacy.terminal.DataPath.CommonPathChecksum = 42
	if condition == "foreground-wifi" ||
		condition == "unplugged-cellular" {
		core.manifest.Unplugged = true
		privacy.manifest.Unplugged = true
		coreStart, coreEnd := uint64(10_000), uint64(9_900)
		privacyStart, privacyEnd := uint64(10_000), uint64(9_890)
		core.manifest.BatteryStartBasisPoints = &coreStart
		core.manifest.BatteryEndBasisPoints = &coreEnd
		privacy.manifest.BatteryStartBasisPoints = &privacyStart
		privacy.manifest.BatteryEndBasisPoints = &privacyEnd
	}
	if profile == "idle" {
		coreInterrupt, coreIdle := uint64(50), uint64(50)
		privacyInterrupt, privacyIdle := uint64(200), uint64(200)
		core.terminal.WholeRunResourceWindow.InterruptWakeupDelta =
			&coreInterrupt
		core.terminal.WholeRunResourceWindow.PackageIdleWakeupDelta =
			&coreIdle
		privacy.terminal.WholeRunResourceWindow.InterruptWakeupDelta =
			&privacyInterrupt
		privacy.terminal.WholeRunResourceWindow.PackageIdleWakeupDelta =
			&privacyIdle
	}
	return matchedPair{core: core, privacy: privacy}
}

func syntheticSingle(condition string, pairNumber int) checkedRun {
	profile := "low"
	duration := uint64(60)
	switch condition {
	case "low-power-mode":
		duration = 1_800
	case "eight-hour-locked":
		duration = 28_800
	case "stop-latency":
		profile = "idle"
	}
	run := syntheticRun(
		"maximum-privacy",
		condition,
		profile,
		1,
		fixtureUUID(pairNumber),
		duration,
	)
	switch condition {
	case "low-power-mode":
		run.manifest.LowPowerMode = "on"
		run.terminal.WholeRunResourceWindow.
			LowPowerModeAlwaysEnabled = true
	case "accelerated-allocation":
		run.manifest.RotationCadence = "accelerated-allocation"
		run.terminal.RotationCadence = "accelerated-allocation"
		run.terminal.DataPath.RotationCount = 500
	case "stop-latency":
		run.manifest.ExpectedTerminal = "stop-acknowledged"
		run.terminal.Event = "stop-acknowledged"
		run.terminal.DataPath.CommonPathUnits = 0
		run.terminal.DataPath.CommonPathActiveNanoseconds = 0
	}
	return run
}

func syntheticRun(
	mode string,
	condition string,
	profile string,
	repeat int,
	pairID string,
	duration uint64,
) checkedRun {
	energy := uint64(100)
	if mode == "maximum-privacy" {
		energy = 110
	}
	units := duration * 2 * map[string]uint64{
		"idle": 0, "low": 50, "medium": 1_250, "saturated": 5_000,
	}[profile]
	run := manifestRun{
		EvidenceSHA256:   strings.Repeat("c", 64),
		Mode:             mode,
		TrafficProfile:   profile,
		CoverSemantics:   "continuousWhileConnected",
		RotationCadence:  "protocol-15m",
		TestCondition:    condition,
		PairID:           pairID,
		Repeat:           repeat,
		DurationSeconds:  duration,
		ExpectedTerminal: "completed",
		LowPowerMode:     "off",
		StartThermal:     "nominal",
	}
	return checkedRun{
		manifest: run,
		terminal: metricRecord{
			Schema:              evidenceSchema,
			ProtocolVersion:     protocolVersion,
			Platform:            "ios",
			RunID:               fixtureUUID(9_999),
			Event:               "completed",
			Mode:                mode,
			TrafficProfile:      profile,
			CoverSemantics:      "continuousWhileConnected",
			RotationCadence:     "protocol-15m",
			TestCondition:       condition,
			PairID:              pairID,
			DurationNanoseconds: duration * 1_000_000_000,
			WholeRunResourceWindow: &resourceWindow{
				EnergyDeltaNanojoules: &energy,
			},
			DataPath: &dataPathSnapshot{
				CommonPathUnits:             units,
				CommonPathActiveNanoseconds: duration * 1_000_000_000,
				CommonPathChecksum:          42,
			},
		},
	}
}

func encodeEvidence(
	t *testing.T,
	terminal metricRecord,
	attemptNonce string,
	hostLatency uint64,
) []byte {
	t.Helper()
	started := terminal
	started.Event = "started"
	started.WholeRunResourceWindow = nil
	started.DataPath = nil
	started.MonotonicNanoseconds = 1_002_000_000
	started.StartAttemptNonce = &attemptNonce
	requested := uint64(1_000_000_000)
	providerReceived := uint64(1_001_000_000)
	started.StartRequestedAtMonotonicNanoseconds = &requested
	started.ProviderReceivedAtMonotonicNanoseconds = &providerReceived
	terminal.MonotonicNanoseconds = requested + hostLatency +
		terminal.DurationNanoseconds
	first := encodeCompleteMetricRecord(t, started)
	last := encodeCompleteMetricRecord(t, terminal)
	return append(append(append([]byte{}, first...), '\n'), append(last, '\n')...)
}

func encodeCompleteMetricRecord(t *testing.T, record metricRecord) []byte {
	t.Helper()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["frameVersion"] = "WCF3"
	object["wallTimeUTC"] = "2026-07-24T00:00:00.000000000Z"
	object["trafficActiveNanoseconds"] = record.DurationNanoseconds
	object["constants"] = requiredZeroObject(constantsShape)
	if value, present := object["wholeRunResourceWindow"]; present {
		window := requiredZeroObject(resourceWindowShape)
		overlayObject(window, value)
		object["wholeRunResourceWindow"] = window
	}
	if value, present := object["dataPath"]; present {
		data := requiredZeroObject(dataPathShape)
		overlayObject(data, value)
		object["dataPath"] = data
	}
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requiredZeroObject(shape *jsonShape) map[string]any {
	result := make(map[string]any)
	for name, member := range shape.members {
		if member.required {
			result[name] = 0
		}
	}
	return result
}

func overlayObject(destination map[string]any, source any) {
	for name, value := range source.(map[string]any) {
		destination[name] = value
	}
}

func fixtureUUID(number int) string {
	return fmt.Sprintf("%08x-0000-0000-0000-%012x", number, number)
}

// startLatencyFor spreads fixture activation latencies so the reported worst
// value is a real maximum over distinct runs rather than one repeated number.
// The fixture's provider becomes ready 3 ms after the request, so every
// activation latency must be at least that.
func startLatencyFor(index int) uint64 {
	return uint64(4_000_000 + 1_000_000*index)
}

func writeFixtureStartReceipt(
	t *testing.T,
	base string,
	run *manifestRun,
	runID string,
	sourceDigest string,
	evidence []byte,
	nonceNumber int,
	latency uint64,
) {
	t.Helper()
	feed := bytes.IndexByte(evidence, '\n')
	if feed < 0 {
		t.Fatal("fixture evidence has no line feed")
	}
	firstLine := evidence[:feed+1]
	digest := sha256.Sum256(firstLine)
	requested := uint64(1_000_000_000)
	providerReceived := requested + 1_000_000
	providerReady := providerReceived + 2_000_000
	receipt := startReceipt{
		Schema:                                 startReceiptSchema,
		ProtocolVersion:                        protocolVersion,
		RunID:                                  runID,
		AttemptNonce:                           fixtureUUID(nonceNumber),
		SourceDigest:                           sourceDigest,
		EvidenceFileName:                       runID + ".jsonl",
		FirstRecordSHA256:                      hex.EncodeToString(digest[:]),
		FirstRecordBytes:                       uint64(len(firstLine)),
		EvidenceDurabilityBarrier:              evidenceDurabilityFullFsync,
		RequestedAtMonotonicNanoseconds:        requested,
		ProviderReceivedAtMonotonicNanoseconds: providerReceived,
		ProviderReadyAtMonotonicNanoseconds:    providerReady,
		ProviderStartLatencyNanoseconds:        providerReady - providerReceived,
		HostObservedConnectedAtMonotonicNanoseconds: requested + latency,
		HostStartLatencyNanoseconds:                 latency,
		MeasurementScope:                            startMeasurementScope,
		ArtifactScope:                               startArtifactScope,
		HostReceiptDurabilityScope:                  startHostReceiptDurabilityScope,
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	run.StartReceipt = runID + ".start-receipt.json"
	receiptDigest := sha256.Sum256(encoded)
	run.StartReceiptSHA256 = hex.EncodeToString(receiptDigest[:])
	if err := os.WriteFile(
		filepath.Join(base, run.StartReceipt),
		encoded,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func loadFixtureManifest(t *testing.T, path string) matrixManifest {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest matrixManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func rewriteFixtureStartReceipt(
	t *testing.T,
	path string,
	mutate func(*startReceipt),
) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt startReceipt
	if err := json.Unmarshal(content, &receipt); err != nil {
		t.Fatal(err)
	}
	mutate(&receipt)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		append(encoded, '\n'),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

// repinManifest rewrites the manifest so a mutated start receipt is pinned by
// its new digest. Without it the run would fail on the pin rather than on the
// property under test.
func repinManifest(t *testing.T, path string) {
	t.Helper()
	manifest := loadFixtureManifest(t, path)
	base := filepath.Dir(path)
	for index := range manifest.Runs {
		content, err := os.ReadFile(
			filepath.Join(base, manifest.Runs[index].StartReceipt),
		)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		manifest.Runs[index].StartReceiptSHA256 =
			hex.EncodeToString(digest[:])
	}
	writeFixtureManifest(t, path, manifest)
}

func writeFixtureManifest(
	t *testing.T,
	path string,
	manifest matrixManifest,
) {
	t.Helper()
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		path,
		append(encoded, '\n'),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func verifyFixtureMatrix(
	t *testing.T,
	path string,
) (matrixSummary, error) {
	t.Helper()
	verifier, digest := writeFixtureVerifier(t, "")
	return verifyMatrix(path, verifier, digest)
}

func writeFixtureVerifier(
	t *testing.T,
	extra string,
) (string, string) {
	t.Helper()
	verifier := filepath.Join(t.TempDir(), "evidenceverify")
	content := []byte(
		"#!/bin/sh\n" +
			"printf '%s\\n' 'IOS_SPIKE_VERIFY_PASS records=2 " +
			"run_id=00000001-0000-0000-0000-000000000001 " +
			"artifact=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb " +
			"evidence_barrier=f-fullfsync " +
			"resident_slope_bytes_per_hour=0.000 energy_available=true " +
			"energy_delta_nj=1 host_packet_tunnel_activation_latency_ns=1'\n" +
			extra,
	)
	if err := os.WriteFile(verifier, content, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return verifier, hex.EncodeToString(digest[:])
}
