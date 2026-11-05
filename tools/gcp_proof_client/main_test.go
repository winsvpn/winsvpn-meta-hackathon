package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testChallenge    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testControlID    = "100000000000000001"
	testWinn3ID      = "100000000000000002"
	testCoverID      = "100000000000000003"
	testControlBoot  = "11111111-1111-4111-8111-111111111111"
	testWinn3Boot    = "22222222-2222-4222-8222-222222222222"
	testCoverBoot    = "33333333-3333-4333-8333-333333333333"
	testHelperRemote = "1111111111111111111111111111111111111111111111111111111111111111"
	testHelperBroker = "2222222222222222222222222222222222222222222222222222222222222222"
	testWinn3Nonce   = "abababababababababababababababab"
	testAWGKey       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="
	testXrayUser     = "proof-cover-user"
)

type fakeRunner struct {
	result commandResult
	err    error
	calls  [][]string
}

func (f *fakeRunner) run(_ context.Context, argv []string) (commandResult, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	if len(argv) >= 2 && argv[1] == "version" {
		return commandResult{stdout: []byte(`{"Google Cloud SDK":"582.0.0"}`)}, nil
	}
	return f.result, f.err
}

type orchestratorRunner struct {
	describes map[string][]byte
	ssh       [][]byte
	sshIndex  int
	calls     [][]string
}

func (r *orchestratorRunner) run(_ context.Context, argv []string) (commandResult, error) {
	r.calls = append(r.calls, append([]string(nil), argv...))
	if len(argv) >= 2 && argv[1] == "version" {
		return commandResult{stdout: []byte(`{"Google Cloud SDK":"582.0.0"}`)}, nil
	}
	if len(argv) >= 5 && argv[1] == "compute" && argv[2] == "instances" && argv[3] == "describe" {
		body, found := r.describes[argv[4]]
		if !found {
			return commandResult{}, fmt.Errorf("missing describe fixture for %s", argv[4])
		}
		return commandResult{stdout: body}, nil
	}
	if r.sshIndex >= len(r.ssh) {
		return commandResult{}, errors.New("unexpected SSH command")
	}
	body := r.ssh[r.sshIndex]
	r.sshIndex++
	return commandResult{stdout: body}, nil
}

type fakeGcloudGuard struct {
	path   string
	checks int
	failAt int
}

type commandRunnerFunc func(context.Context, []string) (commandResult, error)

func (f commandRunnerFunc) run(ctx context.Context, argv []string) (commandResult, error) {
	return f(ctx, argv)
}

type swapRestoreDescriptorRunner struct {
	maliciousExecutions int
}

func (*swapRestoreDescriptorRunner) run(context.Context, []string) (commandResult, error) {
	return commandResult{}, errors.New("pathname execution is forbidden")
}

func (r *swapRestoreDescriptorRunner) runFromCustody(ctx context.Context, executable, root, credential, subjectToken *os.File, workingDirectory string, argv []string, env []string) (commandResult, error) {
	visibleRoot := filepath.Clean(workingDirectory)
	backup := visibleRoot + ".reviewed"
	if err := os.Rename(visibleRoot, backup); err != nil {
		return commandResult{}, err
	}
	malicious := filepath.Join(visibleRoot, "bin", "gcloud")
	if err := os.MkdirAll(filepath.Dir(malicious), 0700); err != nil {
		_ = os.Rename(backup, visibleRoot)
		return commandResult{}, err
	}
	if err := os.WriteFile(malicious, []byte("#!/bin/sh\nprintf 'MALICIOUS\\n'\n"), 0700); err != nil {
		_ = os.RemoveAll(visibleRoot)
		_ = os.Rename(backup, visibleRoot)
		return commandResult{}, err
	}
	result, runErr := (subprocessRunner{}).runFromCustody(ctx, executable, root, credential, subjectToken, workingDirectory, argv, env)
	r.maliciousExecutions += bytes.Count(result.stdout, []byte("MALICIOUS"))
	removeErr := os.RemoveAll(visibleRoot)
	restoreErr := os.Rename(backup, visibleRoot)
	if runErr != nil {
		return commandResult{}, runErr
	}
	if removeErr != nil {
		return commandResult{}, removeErr
	}
	if restoreErr != nil {
		return commandResult{}, restoreErr
	}
	return result, nil
}

type gcloudCustodyFixture struct {
	root, executable, receipt, retainedArchive string
	authority, issuance                        string
	authorityOwner                             uint32
	archiveData                                []byte
	pin                                        gcloudReviewPin
	privateKey                                 ed25519.PrivateKey
}

func signTestGcloudReceipt(t *testing.T, receipt *gcloudReceipt, privateKey ed25519.PrivateKey) {
	t.Helper()
	message, err := gcloudReceiptSignatureMessage(*receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.IssuanceSignature = hex.EncodeToString(ed25519.Sign(privateKey, message))
}

func writeTestGcloudIssuance(t *testing.T, path string, receipt gcloudReceipt) {
	t.Helper()
	authorization := gcloudReceiptAuthorization(receipt)
	issuance := map[string]any{
		"contract": gcloudOwnerIssuance, "schema_version": 1,
		"issuer": gcloudOwnerIssuer, "algorithm": gcloudOwnerAlgorithm,
		"key_id": receipt.AuthorityKeyID, "receipt": authorization,
		"signature": receipt.IssuanceSignature,
	}
	encoded, err := json.Marshal(issuance)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := writeExclusiveFile(path, encoded, 0400); err != nil {
		t.Fatal(err)
	}
}

func writeTestDurableGcloudReceipt(t *testing.T, path string, receipt gcloudReceipt) {
	t.Helper()
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
}

type tarFixtureMember struct {
	name, body, link string
	typeflag         byte
	mode             int64
}

func makeGcloudArchive(t *testing.T, members []tarFixtureMember) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := &tar.Header{
			Name:     member.name,
			Linkname: member.link,
			Mode:     member.mode,
			Typeflag: member.typeflag,
			Size:     int64(len(member.body)),
		}
		if member.typeflag == tar.TypeDir || member.typeflag == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write([]byte(member.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func newGcloudCustodyFixture(t *testing.T) gcloudCustodyFixture {
	t.Helper()
	archiveData := makeGcloudArchive(t, []tarFixtureMember{
		{name: "google-cloud-sdk/", typeflag: tar.TypeDir, mode: 0755},
		{name: "google-cloud-sdk/bin/", typeflag: tar.TypeDir, mode: 0755},
		{
			name: "google-cloud-sdk/bin/gcloud", typeflag: tar.TypeReg, mode: 0755,
			body: "#!/bin/sh\nif [ \"${1:-}\" = version ]; then printf '{\"Google Cloud SDK\":\"582.0.0\"}'; else printf 'REVIEWED\\n'; fi\n",
		},
		{name: "google-cloud-sdk/component.txt", typeflag: tar.TypeReg, mode: 0644, body: "reviewed\n"},
	})
	pin := gcloudReviewPin{
		version:       "582.0.0",
		platform:      "linux_amd64",
		archiveName:   "google-cloud-cli-582.0.0-linux-x86_64.tar.gz",
		archiveSHA256: sha256Hex(archiveData),
	}
	extraction := filepath.Join(t.TempDir(), "archive")
	root, err := extractOfficialGcloudArchive(archiveData, pin.archiveName, extraction)
	if err != nil {
		t.Fatal(err)
	}
	retained := filepath.Join(root, gcloudCustodyArchiveName)
	if err := writeExclusiveFile(retained, archiveData, 0444); err != nil {
		t.Fatal(err)
	}
	tree, err := gcloudTreeSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := sha256Hex(publicKey)
	authorityOwner := uint32(os.Getuid())
	authorityRoot := t.TempDir()
	authorityPath := filepath.Join(authorityRoot, "owner-authority.json")
	issuancePath := filepath.Join(authorityRoot, "owner-issuance.json")
	authority := gcloudOwnerAuthorityDocument{
		Contract: gcloudOwnerAuthority, SchemaVersion: 1,
		Algorithm: gcloudOwnerAlgorithm, KeyID: keyID,
		PublicKey: hex.EncodeToString(publicKey), OwnerUID: authorityOwner,
	}
	authorityData, err := json.Marshal(authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExclusiveFile(authorityPath, authorityData, 0400); err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	receipt := gcloudReceipt{
		SchemaVersion: 1, Contract: gcloudReceiptContract,
		Version: pin.version, Platform: pin.platform,
		ArchiveName: pin.archiveName, ArchiveSHA256: pin.archiveSHA256,
		InstallTreeSHA256: tree, ExecutablePath: "bin/gcloud",
		InstallRootSHA256: sha256Hex([]byte(resolvedRoot)),
		IssuedUTC:         issued.Format("2006-01-02T15:04:05Z"),
		ExpiresUTC:        issued.Add(time.Hour).Format("2006-01-02T15:04:05Z"),
		IssuanceID:        strings.Repeat("a", 32), AuthorityKeyID: keyID,
		ControllerSHA256: strings.Repeat("b", 64), ManifestSHA256: strings.Repeat("c", 64),
		TrustAnchorSHA256: strings.Repeat("d", 64),
	}
	signTestGcloudReceipt(t, &receipt, privateKey)
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, gcloudReceiptName)
	if err := writeExclusiveFile(receiptPath, encoded, 0444); err != nil {
		t.Fatal(err)
	}
	writeTestGcloudIssuance(t, issuancePath, receipt)
	return gcloudCustodyFixture{
		root: root, executable: filepath.Join(root, "bin", "gcloud"),
		receipt: receiptPath, retainedArchive: retained,
		authority: authorityPath, issuance: issuancePath, authorityOwner: authorityOwner,
		archiveData: archiveData, pin: pin, privateKey: privateKey,
	}
}

func rewriteGcloudReceipt(t *testing.T, fixture gcloudCustodyFixture) {
	t.Helper()
	tree, err := gcloudTreeSHA256(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	record := gcloudReceipt{
		SchemaVersion: 1, Contract: gcloudReceiptContract,
		Version: fixture.pin.version, Platform: fixture.pin.platform,
		ArchiveName: fixture.pin.archiveName, ArchiveSHA256: fixture.pin.archiveSHA256,
		InstallTreeSHA256: tree, ExecutablePath: "bin/gcloud",
		InstallRootSHA256: func() string {
			resolved, err := filepath.EvalSymlinks(fixture.root)
			if err != nil {
				t.Fatal(err)
			}
			return sha256Hex([]byte(resolved))
		}(),
		IssuedUTC:        time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z"),
		ExpiresUTC:       time.Now().UTC().Truncate(time.Second).Add(time.Hour).Format("2006-01-02T15:04:05Z"),
		IssuanceID:       strings.Repeat("a", 32),
		AuthorityKeyID:   sha256Hex(fixture.privateKey.Public().(ed25519.PublicKey)),
		ControllerSHA256: strings.Repeat("b", 64), ManifestSHA256: strings.Repeat("c", 64),
		TrustAnchorSHA256: strings.Repeat("d", 64),
	}
	signTestGcloudReceipt(t, &record, fixture.privateKey)
	writeTestGcloudIssuance(t, fixture.issuance, record)
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.receipt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.receipt, encoded, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fixture.receipt, 0444); err != nil {
		t.Fatal(err)
	}
}

func (g *fakeGcloudGuard) verifyUnchanged() error {
	g.checks++
	if g.failAt > 0 && g.checks == g.failAt {
		return errors.New("fixture custody changed")
	}
	return nil
}

func (g *fakeGcloudGuard) bindIdentity(gcloudIdentityInput) error {
	return nil
}

func (g *fakeGcloudGuard) run(ctx context.Context, runner commandRunner, args []string) (commandResult, error) {
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	result, err := runner.run(ctx, append([]string{g.path}, args...))
	if err != nil {
		return commandResult{}, err
	}
	if err := g.verifyUnchanged(); err != nil {
		return commandResult{}, err
	}
	return result, nil
}

func bindTestIdentity(t *testing.T) {
	t.Helper()
	old := []string{releaseValue, sharedRevision, sourceSHA256, buildContractSHA256, toolchainVersion, targetValue, buildIdentity, expectedAttemptBrokerSHA256}
	releaseValue = "1.0.15+30"
	sharedRevision = "reviewed-linux-revision"
	sourceSHA256 = strings.Repeat("a", 64)
	buildContractSHA256 = strings.Repeat("b", 64)
	toolchainVersion = "go1.27.1"
	targetValue = "linux/amd64"
	buildIdentity = strings.Repeat("c", 64)
	expectedAttemptBrokerSHA256 = testHelperBroker
	oldGuard := loadGcloudGuard
	loadGcloudGuard = func(path string) (gcloudGuard, error) {
		return &fakeGcloudGuard{path: path}, nil
	}
	oldChallenge := newChallenge
	newChallenge = func() (string, error) { return testChallenge, nil }
	t.Cleanup(func() {
		releaseValue, sharedRevision, sourceSHA256, buildContractSHA256, toolchainVersion, targetValue, buildIdentity = old[0], old[1], old[2], old[3], old[4], old[5], old[6]
		expectedAttemptBrokerSHA256 = old[7]
		loadGcloudGuard = oldGuard
		newChallenge = oldChallenge
	})
}

func testOptions(action string) options {
	return options{
		action: action, project: "winsproof123", gcloudBin: "/opt/google-cloud-sdk/bin/gcloud",
		fleetID: "123456789abc", controlInstance: "proof-control-a1", controlZone: "us-east1-b",
		winn3Instance: "proof-winn3-a1", winn3Zone: "us-central1-a",
		coverInstance: "proof-cover-a1", coverZone: "us-east1-b",
		runID: "run-20260823-a", sessionID: "session-20260823-a", correlationID: "correlation-20260823-a",
	}
}

func TestResourceIdentityMatchesCanonicalRoleContract(t *testing.T) {
	o := testOptions("teardown-check")
	got := resourceIdentity(o)
	want := map[string][]string{
		"instances": {"proof-control-a1", "proof-winn3-a1", "proof-cover-a1"},
		"network":   {"pf-123456789abc-net"},
		"subnets": {
			"pf-123456789abc-sn-control",
			"pf-123456789abc-sn-data-winn3",
			"pf-123456789abc-sn-data-cover",
		},
		"firewalls": {
			"pf-123456789abc-admin-ssh",
			"pf-123456789abc-control-http",
			"pf-123456789abc-cover-in",
			"pf-123456789abc-winn3-in",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resource identity mismatch\ngot:  %#v\nwant: %#v", got, want)
	}
}

func actionArgv(o options) []string {
	return []string{
		"--winsvpn-proof-action", o.action,
		"--project", o.project,
		"--gcloud-bin", o.gcloudBin,
		"--fleet-id", o.fleetID,
		"--control-instance", o.controlInstance,
		"--control-zone", o.controlZone,
		"--winn3-data-instance", o.winn3Instance,
		"--winn3-data-zone", o.winn3Zone,
		"--cover-data-instance", o.coverInstance,
		"--cover-data-zone", o.coverZone,
		"--run-id", o.runID,
		"--session-id", o.sessionID,
		"--correlation-id", o.correlationID,
	}
}

func describeBodies(o options) map[string][]byte {
	return map[string][]byte{
		o.controlInstance: []byte(`{"id":"` + testControlID + `","name":"` + o.controlInstance + `"}`),
		o.winn3Instance:   []byte(`{"id":"` + testWinn3ID + `","name":"` + o.winn3Instance + `"}`),
		o.coverInstance:   []byte(`{"id":"` + testCoverID + `","name":"` + o.coverInstance + `"}`),
	}
}

func instanceIDFor(o options, role string) string {
	switch role {
	case "control":
		return testControlID
	case "data-winn3":
		return testWinn3ID
	default:
		return testCoverID
	}
}

func bootIDFor(role string) string {
	switch role {
	case "control":
		return testControlBoot
	case "data-winn3":
		return testWinn3Boot
	default:
		return testCoverBoot
	}
}

func stepClock(index int) (start, end string, startMono, endMono uint64) {
	starts := []string{
		"2026-08-24T12:00:00Z", "2026-08-24T12:00:06Z", "2026-08-24T12:00:21Z",
		"2026-08-24T12:00:36Z", "2026-08-24T12:00:42Z",
	}
	ends := []string{
		"2026-08-24T12:00:05Z", "2026-08-24T12:00:20Z", "2026-08-24T12:00:35Z",
		"2026-08-24T12:00:41Z", "2026-08-24T12:00:47Z",
	}
	monos := [][2]uint64{
		{11_000_000_000, 12_000_000_000},
		{13_000_000_000, 19_000_000_000},
		{20_000_000_000, 26_000_000_000},
		{27_000_000_000, 28_000_000_000},
		{29_000_000_000, 30_000_000_000},
	}
	return starts[index], ends[index], monos[index][0], monos[index][1]
}

func exerciseIndex(o options) int {
	for index, step := range observationPlan(o) {
		if step.phase == phaseExercise {
			return index
		}
	}
	return 0
}

func exerciseHandshakeUTC(o options) string {
	start, _, _, _ := stepClock(exerciseIndex(o))
	parsed, err := time.Parse(time.RFC3339, start)
	if err != nil {
		panic(err)
	}
	return parsed.Add(4 * time.Second).UTC().Format("2006-01-02T15:04:05Z")
}

func handshakeUnix(stamp string) uint64 {
	parsed, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		panic(err)
	}
	return uint64(parsed.Unix())
}

func testIdentity() compiledIdentity {
	return compiledIdentity{BuildIdentity: strings.Repeat("c", 64)}
}

func dataForAction(o options) map[string]any {
	switch o.action {
	case "route-decision":
		return map[string]any{"served_carrier": "winn3", "descriptor_node": o.winn3Instance, "selected_node": o.winn3Instance, "descriptor_sha256": strings.Repeat("d", 64), "signature_state": "verified", "canary_state": "reachable"}
	case "connect-primary":
		return map[string]any{
			"attempts": []any{map[string]any{"protocol": "winn3", "node": o.winn3Instance, "result": "connected"}},
			"bytes_rx": 2048, "bytes_tx": 1024, "interface": realWinn3Interface,
			"status_delta": map[string]any{"inner_packets_delivered": 1, "rx_device_writes": 1},
		}
	case "connect-cover-awg":
		return map[string]any{"protocol": "awg", "node": o.coverInstance, "result": "connected", "latest_handshake_utc": exerciseHandshakeUTC(o)}
	case "connect-cover-xray":
		return map[string]any{"protocol": "xray", "node": o.coverInstance, "result": "connected"}
	case "inject-awg-block":
		return map[string]any{"control_id": "negative-awg-block", "protocol": "awg", "state": "blocked"}
	case "probe-awg-block":
		events := testFallbackEvents(o)
		return map[string]any{
			"control_id": "negative-awg-block",
			"attempts": []any{
				map[string]any{"protocol": "awg", "node": o.coverInstance, "result": "blocked"},
				map[string]any{"protocol": "xray", "node": o.coverInstance, "result": "connected"},
			},
			"attempt_events": events, "awg_interface": realAWGInterface,
			"xray_bytes_rx": 4000, "xray_bytes_tx": 5000,
		}
	case "restore-awg":
		return map[string]any{"control_id": "negative-awg-block", "protocol": "awg", "state": "restored"}
	case "inject-winn3-block":
		return map[string]any{"control_id": "negative-winn3-block", "protocol": "winn3", "state": "blocked"}
	case "probe-winn3-block":
		return map[string]any{"control_id": "negative-winn3-block", "attempts": []any{
			map[string]any{"protocol": "winn3", "node": o.winn3Instance, "result": "blocked"},
			map[string]any{"protocol": "awg", "node": o.coverInstance, "result": "connected"},
		}, "attempt_events": testWinn3BlockEvents(o)}
	case "withdraw-cover":
		return map[string]any{"control_id": "negative-cover-withdrawn", "node": o.coverInstance, "state": "withdrawn"}
	case "probe-cover-withdrawn":
		return map[string]any{"control_id": "negative-cover-withdrawn", "attempts": []any{map[string]any{"protocol": "winn3", "node": o.winn3Instance, "result": "blocked"}}, "attempt_events": testCoverWithdrawnEvents(o), "refusal_code": "same_node_downgrade_refused", "same_node_downgrade_attempts": 0}
	case "restore-cover":
		return map[string]any{"control_id": "negative-cover-withdrawn", "node": o.coverInstance, "state": "restored"}
	case "restore-winn3":
		return map[string]any{"control_id": "negative-winn3-block", "protocol": "winn3", "state": "restored"}
	case "teardown-check":
		identity := resourceIdentity(o)
		resources := map[string]any{"instances": identity["instances"], "network": identity["network"][0], "subnets": identity["subnets"], "firewalls": identity["firewalls"]}
		return map[string]any{"expected_resources": resources, "observed_resources": resources, "unexpected_targets": []any{}, "foreign_resource_ids": []any{}, "credential_files_read": []any{}, "production_resources_touched": []any{}}
	default:
		panic("unknown action")
	}
}

func helperDataForAction(o options) map[string]any {
	data := dataForAction(o)
	switch o.action {
	case "connect-primary":
		delete(data, "bytes_rx")
		delete(data, "bytes_tx")
		delete(data, "interface")
		delete(data, "status_delta")
	case "connect-cover-awg":
		delete(data, "latest_handshake_utc")
	case "probe-awg-block":
		delete(data, "awg_interface")
		delete(data, "xray_bytes_rx")
		delete(data, "xray_bytes_tx")
	}
	return data
}

func TestSharedActionContractMatchesGoAssemblerAndHelperShapes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "gcp_proof_action_contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		SchemaVersion int    `json:"schema_version"`
		Contract      string `json:"contract"`
		Actions       map[string]struct {
			Final  []string `json:"final_observation_keys"`
			Helper []string `json:"remote_helper_data_keys"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.SchemaVersion != 1 || contract.Contract != "winsvpn-gcp-proof-action-data-v1" {
		t.Fatal("shared action contract identity is invalid")
	}
	for action, record := range contract.Actions {
		o := testOptions(action)
		if !exactTypedKeys(dataForAction(o), record.Final) {
			t.Fatalf("%s final observation keys drifted", action)
		}
		if !exactTypedKeys(helperDataForAction(o), record.Helper) {
			t.Fatalf("%s remote helper keys drifted", action)
		}
	}
}

func testFallbackEvents(o options) []attemptEvent {
	start, _, startMono, _ := stepClock(exerciseIndex(o))
	parsed, err := time.Parse(time.RFC3339, start)
	if err != nil {
		panic(err)
	}
	event := func(offset uint64, phase, protocol, result string) attemptEvent {
		return attemptEvent{
			Action: o.action, CorrelationID: o.correlationID,
			MonotonicNS: startMono + offset*1_000_000_000,
			Node:        o.coverInstance, Phase: phase, Protocol: protocol, Result: result,
			SessionID: o.sessionID, UTC: parsed.Add(time.Duration(offset) * time.Second).UTC().Format("2006-01-02T15:04:05Z"),
		}
	}
	return []attemptEvent{
		event(1, "started", "awg", "pending"),
		event(2, "finished", "awg", "failed"),
		event(3, "started", "xray", "pending"),
		event(4, "finished", "xray", "connected"),
	}
}

func testWinn3BlockEvents(o options) []attemptEvent {
	start, _, startMono, _ := stepClock(exerciseIndex(o))
	parsed, err := time.Parse(time.RFC3339, start)
	if err != nil {
		panic(err)
	}
	event := func(offset uint64, node, phase, protocol, result string) attemptEvent {
		return attemptEvent{
			Action: o.action, CorrelationID: o.correlationID,
			MonotonicNS: startMono + offset*1_000_000_000,
			Node:        node, Phase: phase, Protocol: protocol, Result: result,
			SessionID: o.sessionID, UTC: parsed.Add(time.Duration(offset) * time.Second).UTC().Format("2006-01-02T15:04:05Z"),
		}
	}
	return []attemptEvent{
		event(1, o.winn3Instance, "started", "winn3", "pending"),
		event(2, o.winn3Instance, "finished", "winn3", "failed"),
		event(3, o.coverInstance, "started", "awg", "pending"),
		event(4, o.coverInstance, "finished", "awg", "connected"),
	}
}

func testCoverWithdrawnEvents(o options) []attemptEvent {
	start, _, startMono, _ := stepClock(exerciseIndex(o))
	parsed, err := time.Parse(time.RFC3339, start)
	if err != nil {
		panic(err)
	}
	event := func(offset uint64, phase, result string) attemptEvent {
		return attemptEvent{
			Action: o.action, CorrelationID: o.correlationID,
			MonotonicNS: startMono + offset*1_000_000_000,
			Node:        o.winn3Instance, Phase: phase, Protocol: "winn3", Result: result,
			SessionID: o.sessionID, UTC: parsed.Add(time.Duration(offset) * time.Second).UTC().Format("2006-01-02T15:04:05Z"),
		}
	}
	return []attemptEvent{event(1, "started", "pending"), event(2, "finished", "failed")}
}

func testSingleAttemptEvents(o options, node, protocol, finalResult string) []attemptEvent {
	start, _, startMono, _ := stepClock(exerciseIndex(o))
	parsed, err := time.Parse(time.RFC3339, start)
	if err != nil {
		panic(err)
	}
	return []attemptEvent{
		{Action: o.action, CorrelationID: o.correlationID, MonotonicNS: startMono + 1_000_000_000, Node: node, Phase: "started", Protocol: protocol, Result: "pending", SessionID: o.sessionID, UTC: parsed.Add(time.Second).UTC().Format("2006-01-02T15:04:05Z")},
		{Action: o.action, CorrelationID: o.correlationID, MonotonicNS: startMono + 2_000_000_000, Node: node, Phase: "finished", Protocol: protocol, Result: finalResult, SessionID: o.sessionID, UTC: parsed.Add(2 * time.Second).UTC().Format("2006-01-02T15:04:05Z")},
	}
}

func testJournal(events []attemptEvent) *attemptJournal {
	return &attemptJournal{Contract: attemptJournalContract, Events: append([]attemptEvent{}, events...), SchemaVersion: 1}
}

func testServices(role string) serviceEvidence {
	unit := func(path string, seed string, pid uint64) serviceUnitEvidence {
		return serviceUnitEvidence{ActiveState: "active", FragmentPath: path, FragmentSHA256: strings.Repeat(seed, 64), MainPID: pid, ExecutableSHA256: strings.Repeat(seed, 64)}
	}
	value := serviceEvidence{
		Units: map[string]serviceUnitEvidence{}, Binaries: map[string]string{},
		Forbidden: forbiddenServiceEvidence{Units: map[string]forbiddenUnitEvidence{}, Binaries: map[string]forbiddenBinaryEvidence{}},
	}
	switch role {
	case "control":
		value.Units["wins-hub.service"] = unit("/lib/systemd/system/wins-hub.service", "1", 1001)
	case "data-cover":
		value.Units["xray.service"] = unit("/lib/systemd/system/xray.service", "4", 3001)
		value.Units["docker.service"] = unit("/lib/systemd/system/docker.service", "3", 3002)
		value.Binaries["/usr/local/bin/xray"] = strings.Repeat("4", 64)
	case "data-winn3":
		value.Units["winn3-gateway.service"] = unit("/lib/systemd/system/winn3-gateway.service", "6", 2001)
		value.Binaries["/usr/local/libexec/winn/winn3-gateway"] = strings.Repeat("6", 64)
		for _, name := range []string{"xray.service", "docker.service", "docker.socket"} {
			value.Forbidden.Units[name] = forbiddenUnitEvidence{LoadState: "not-found"}
		}
		for _, path := range []string{"/usr/local/bin/xray", "/usr/bin/xray", "/usr/bin/docker", "/usr/local/bin/docker", "/snap/bin/docker", "/usr/bin/dockerd", "/usr/local/bin/dockerd"} {
			value.Forbidden.Binaries[path] = forbiddenBinaryEvidence{Absent: true}
		}
	}
	return value
}

func testProcess(role string) processIdentity {
	switch role {
	case "control":
		return processIdentity{PID: 1001, ExeSHA256: strings.Repeat("1", 64), StarttimeTicks: 111, Comm: "wins-hub"}
	case "data-winn3":
		return processIdentity{PID: 2001, ExeSHA256: strings.Repeat("6", 64), StarttimeTicks: 222, Comm: "winn3-gateway"}
	default:
		return processIdentity{PID: 3001, ExeSHA256: strings.Repeat("4", 64), StarttimeTicks: 333, Comm: "xray"}
	}
}

func testWinn3Status(sequence, delivered, writes uint64, observed string) *winn3Status {
	return &winn3Status{
		SchemaVersion: winn3StatusVersion, Contract: winn3StatusContract, Event: "posture",
		Ready: true, Forward: true, ProcessID: 2001, ProcessNonce: testWinn3Nonce,
		BootID: testWinn3Boot, ProcessStartTicks: 222,
		ProcessStartedUTC: "2026-08-24T11:00:00Z", ObservedUTC: observed,
		ObservedMonotonicNS: sequence * 1_000_000_000, Sequence: sequence,
		InnerPacketsDelivered: delivered, RXDeviceWrites: writes,
	}
}

func TestValidateWinn3StatusV2BindsExtendedProcessIdentity(t *testing.T) {
	process := testProcess("data-winn3")
	base := *testWinn3Status(9, 11, 11, "2026-08-24T12:00:00Z")
	if err := validateWinn3StatusV2(base, process, testWinn3Boot); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*winn3Status)
		bootID string
	}{
		{"boot-id", func(value *winn3Status) { value.BootID = testCoverBoot }, testWinn3Boot},
		{"process-start", func(value *winn3Status) { value.ProcessStartTicks++ }, testWinn3Boot},
		{"monotonic-zero", func(value *winn3Status) { value.ObservedMonotonicNS = 0 }, testWinn3Boot},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := validateWinn3StatusV2(value, process, test.bootID); err == nil {
				t.Fatal("mismatched extended process identity was accepted")
			}
		})
	}
}

func awgPeers(rx, tx, handshake uint64) []awgPeer {
	return []awgPeer{{PublicKey: testAWGKey, LatestHandshakeUnix: handshake, RX: rx, TX: tx}}
}

func evidenceForStep(o options, step observationStep, index int) remoteEvidence {
	start, _, startMono, endMono := stepClock(index)
	value := remoteEvidence{
		StartedMonotonicNS: startMono, EndedMonotonicNS: endMono,
		Services: testServices(step.role), ProcessIdentity: testProcess(step.role),
		InstanceID: instanceIDFor(o, step.role), BootID: bootIDFor(step.role),
		Role: step.role, Instance: step.instance, ClientBuildIdentity: strings.Repeat("c", 64),
		Challenge: testChallenge, RequestSHA256: "", AttemptAcknowledgments: []protocolAttemptAck{},
	}
	observeWinn3 := step.role == "data-winn3" && (step.phase == phaseObserveBefore || step.phase == phaseObserveAfter)
	observeCover := step.role == "data-cover" && (step.phase == phaseObserveBefore || step.phase == phaseObserveAfter)
	if observeWinn3 {
		if step.phase == phaseObserveBefore {
			value.Winn3Status = testWinn3Status(9, 11, 11, start)
			value.InterfaceCounters = map[string]netCount{realWinn3Interface: {RX: 1000, TX: 2000}}
		} else {
			value.Winn3Status = testWinn3Status(10, 12, 12, start)
			value.InterfaceCounters = map[string]netCount{realWinn3Interface: {RX: 3048, TX: 3024}}
		}
		if o.action == "probe-winn3-block" || o.action == "probe-cover-withdrawn" {
			value.Winn3Status = testWinn3Status(9, 11, 11, start)
			value.InterfaceCounters = map[string]netCount{realWinn3Interface: {RX: 1000, TX: 2000}}
			if step.phase == phaseObserveAfter {
				value.Winn3Status.Sequence = 10
				value.Winn3Status.ObservedUTC = start
			}
		}
	}
	if observeCover {
		handshake := uint64(0)
		rx, tx := uint64(500), uint64(600)
		uplink, downlink := uint64(800), uint64(700)
		if step.phase == phaseObserveAfter {
			if o.action == "connect-cover-awg" || o.action == "probe-winn3-block" {
				handshake = handshakeUnix(exerciseHandshakeUTC(o))
				rx, tx = 2500, 3600
			}
			if o.action == "connect-cover-xray" || o.action == "probe-awg-block" {
				uplink, downlink = 5800, 4700
			}
			if o.action == "probe-cover-withdrawn" {
				handshake, rx, tx = 0, 500, 600
				uplink, downlink = 800, 700
			}
		}
		value.AWGPeers = awgPeers(rx, tx, handshake)
		value.XrayStats = &xrayUserStats{User: testXrayUser, Uplink: uplink, Downlink: downlink}
	}
	if step.role == "control" && step.phase == phaseExercise {
		switch o.action {
		case "connect-primary":
			events := testSingleAttemptEvents(o, o.winn3Instance, "winn3", "connected")
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{{
				Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID,
				Node: o.winn3Instance, Protocol: "winn3", SessionID: o.sessionID, State: "completed",
			}}
		case "connect-cover-awg":
			events := testSingleAttemptEvents(o, o.coverInstance, "awg", "connected")
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{{
				Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID,
				Node: o.coverInstance, Protocol: "awg", SessionID: o.sessionID, State: "completed",
			}}
		case "connect-cover-xray":
			events := testSingleAttemptEvents(o, o.coverInstance, "xray", "connected")
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{{
				Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID,
				Node: o.coverInstance, Protocol: "xray", SessionID: o.sessionID, State: "completed",
			}}
		case "probe-awg-block":
			events := testFallbackEvents(o)
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfterAWG = testJournal(events[:2])
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{
				{Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID, Node: o.coverInstance, Protocol: "awg", SessionID: o.sessionID, State: "completed"},
				{Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID, Node: o.coverInstance, Protocol: "xray", SessionID: o.sessionID, State: "completed"},
			}
		case "probe-winn3-block":
			events := testWinn3BlockEvents(o)
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfterAWG = testJournal(events[:2])
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{
				{Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID, Node: o.winn3Instance, Protocol: "winn3", SessionID: o.sessionID, State: "completed"},
				{Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID, Node: o.coverInstance, Protocol: "awg", SessionID: o.sessionID, State: "completed"},
			}
		case "probe-cover-withdrawn":
			events := testCoverWithdrawnEvents(o)
			value.AttemptJournalBefore = testJournal([]attemptEvent{})
			value.AttemptJournalAfter = testJournal(events)
			value.AttemptAcknowledgments = []protocolAttemptAck{
				{Action: o.action, Contract: attemptAckContract, CorrelationID: o.correlationID, Node: o.winn3Instance, Protocol: "winn3", SessionID: o.sessionID, State: "completed"},
			}
		}
	}
	return value
}

func helperHashesFor(o options, step observationStep) map[string]string {
	if step.role == "control" && step.phase == phaseExercise && isAttemptAckAction(o.action) {
		return map[string]string{"attempt_broker": testHelperBroker, "remote": testHelperRemote}
	}
	return map[string]string{"remote": testHelperRemote}
}

func transactionProtocolFor(o options, step observationStep) string {
	switch {
	case step.role == "data-winn3":
		return "winn3"
	case step.role == "data-cover" && o.action == "connect-cover-awg":
		return "awg"
	case step.role == "data-cover" && o.action == "connect-cover-xray":
		return "xray"
	case step.role == "data-cover" && (o.action == "probe-awg-block" || o.action == "inject-awg-block" || o.action == "restore-awg"):
		return "awg-xray-fallback"
	case step.role == "data-cover":
		return "cover"
	case o.action == "probe-awg-block" && step.phase == phaseExercise:
		return "awg-xray-fallback"
	case o.action == "connect-cover-awg":
		return "awg"
	case o.action == "connect-cover-xray":
		return "xray"
	case o.action == "teardown-check":
		return "scope"
	case o.action == "withdraw-cover" || o.action == "restore-cover" || o.action == "probe-cover-withdrawn":
		return "cover"
	default:
		return "winn3"
	}
}

func stepResponse(o options, step observationStep, index int, evidence remoteEvidence) map[string]any {
	if step.phase == phaseExercise || step.phase == phaseMutate {
		return helperDataForAction(o)
	}
	return map[string]any{
		"role": step.role, "phase": step.phase, "instance_id": evidence.InstanceID,
		"monotonic_ns": evidence.EndedMonotonicNS, "index": index,
	}
}

func encodeStep(t *testing.T, o options, step observationStep, index int, mutate func(*remoteEnvelope, *remoteEvidence, map[string]any)) []byte {
	t.Helper()
	identity := testIdentity()
	requestSHA, err := requestDigest(o, identity, step, testChallenge)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForStep(o, step, index)
	evidence.RequestSHA256 = requestSHA
	start, end, _, _ := stepClock(index)
	kind := expectedEffectKind(step.phase)
	response := stepResponse(o, step, index, evidence)
	helpers, err := json.Marshal(helperHashesFor(o, step))
	if err != nil {
		t.Fatal(err)
	}
	pack := func(startUTC, endUTC string) remoteEnvelope {
		t.Helper()
		responseBytes, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		responseDigest, err := canonicalJSONDigest(responseBytes)
		if err != nil {
			t.Fatal(err)
		}
		transactionBytes, err := json.Marshal(transactionRecord{
			Contract: transactionContract, Nonce: testChallenge, Kind: kind,
			Protocol: transactionProtocolFor(o, step), ResponseSHA256: responseDigest, Response: responseBytes,
		})
		if err != nil {
			t.Fatal(err)
		}
		data := json.RawMessage("null")
		if step.phase != phaseObserveBefore && step.phase != phaseObserveAfter {
			data = append([]byte(nil), responseBytes...)
		}
		evidenceBytes, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		stateDigest, err := canonicalJSONDigest(evidenceBytes)
		if err != nil {
			t.Fatal(err)
		}
		value := remoteEnvelope{
			SchemaVersion: remoteSchemaVersion, Contract: remoteContract, Action: o.action, Phase: step.phase,
			Project: o.project, Instance: step.instance, InstanceID: instanceIDFor(o, step.role),
			BootID: bootIDFor(step.role), Role: step.role, RunID: o.runID, SessionID: o.sessionID,
			CorrelationID: o.correlationID, Operation: actionOperations[o.action], EffectKind: kind,
			Challenge: testChallenge, RequestSHA256: requestSHA, HelperHashes: helpers,
			StartedUTC: startUTC, EndedUTC: endUTC, StateSHA256: stateDigest, Evidence: evidenceBytes,
			Transaction: transactionBytes, Data: data,
		}
		value.EffectSHA256, err = remoteEffectDigest(value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	value := pack(start, end)
	if mutate != nil {
		mutate(&value, &evidence, response)
		rebuilt := pack(value.StartedUTC, value.EndedUTC)
		rebuilt.SchemaVersion = value.SchemaVersion
		rebuilt.Contract = value.Contract
		rebuilt.Action = value.Action
		rebuilt.Phase = value.Phase
		rebuilt.Project = value.Project
		rebuilt.Instance = value.Instance
		rebuilt.InstanceID = value.InstanceID
		rebuilt.BootID = value.BootID
		rebuilt.Role = value.Role
		rebuilt.RunID = value.RunID
		rebuilt.SessionID = value.SessionID
		rebuilt.CorrelationID = value.CorrelationID
		rebuilt.Operation = value.Operation
		rebuilt.EffectKind = value.EffectKind
		rebuilt.Challenge = value.Challenge
		rebuilt.RequestSHA256 = value.RequestSHA256
		rebuilt.HelperHashes = value.HelperHashes
		var tx transactionRecord
		if err := json.Unmarshal(value.Transaction, &tx); err == nil {
			responseBytes, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			tx.Response = responseBytes
			tx.ResponseSHA256, err = canonicalJSONDigest(responseBytes)
			if err != nil {
				t.Fatal(err)
			}
			rebuilt.Transaction, err = json.Marshal(tx)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			rebuilt.Transaction = value.Transaction
		}
		rebuilt.EffectSHA256, err = remoteEffectDigest(rebuilt)
		if err != nil {
			t.Fatal(err)
		}
		if value.EffectSHA256 == strings.Repeat("f", 64) {
			rebuilt.EffectSHA256 = value.EffectSHA256
		}
		value = rebuilt
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

type stepMutator func(int, observationStep, *remoteEnvelope, *remoteEvidence, map[string]any)

func orchestrationBodies(t *testing.T, o options, mutate stepMutator) [][]byte {
	t.Helper()
	plan := observationPlan(o)
	bodies := make([][]byte, 0, len(plan))
	for index, step := range plan {
		var wrapped func(*remoteEnvelope, *remoteEvidence, map[string]any)
		if mutate != nil {
			idx, current := index, step
			wrapped = func(env *remoteEnvelope, ev *remoteEvidence, data map[string]any) {
				mutate(idx, current, env, ev, data)
			}
		}
		bodies = append(bodies, encodeStep(t, o, step, index, wrapped))
	}
	return bodies
}

func newOrchestrator(t *testing.T, o options, mutate stepMutator) *orchestratorRunner {
	t.Helper()
	return &orchestratorRunner{describes: describeBodies(o), ssh: orchestrationBodies(t, o, mutate)}
}

func rawEvidenceMutation(t *testing.T, o options, stepIndex int, mutate func(map[string]any)) [][]byte {
	t.Helper()
	bodies := orchestrationBodies(t, o, nil)
	var value remoteEnvelope
	if err := strictDecode(bodies[stepIndex], &value); err != nil {
		t.Fatal(err)
	}
	var evidence map[string]any
	if err := strictDecode(value.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	mutate(evidence)
	var err error
	value.Evidence, err = json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	value.StateSHA256, err = canonicalJSONDigest(value.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	value.EffectSHA256, err = remoteEffectDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	bodies[stepIndex] = append(encoded, '\n')
	return bodies
}

func TestIdentityModeIsExactAndRunsNoCommand(t *testing.T) {
	bindTestIdentity(t)
	runner := &fakeRunner{}
	var output bytes.Buffer
	if err := runCLI([]string{"--winsvpn-proof-identity"}, runner, &output); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("identity mode executed an external command")
	}
	var got compiledIdentity
	if err := strictDecode(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Contract != identityContract || got.BuildIdentity != strings.Repeat("c", 64) || got.Target != "linux/amd64" {
		t.Fatalf("wrong identity: %#v", got)
	}
}

func TestEveryActionUsesFixedDescribeAndRoleSSHArgv(t *testing.T) {
	bindTestIdentity(t)
	identity := testIdentity()
	for _, action := range actionNames {
		t.Run(action, func(t *testing.T) {
			o := testOptions(action)
			runner := newOrchestrator(t, o, nil)
			var output bytes.Buffer
			if err := runCLI(actionArgv(o), runner, &output); err != nil {
				t.Fatal(err)
			}
			plan := observationPlan(o)
			if len(runner.calls) != 4+len(plan) {
				t.Fatalf("got %d command calls, want %d", len(runner.calls), 4+len(plan))
			}
			version := []string{o.gcloudBin, "version", "--format=json"}
			if strings.Join(runner.calls[0], "\x00") != strings.Join(version, "\x00") {
				t.Fatalf("version argv mismatch: %#v", runner.calls[0])
			}
			describes := [][]string{
				{o.gcloudBin, "compute", "instances", "describe", o.controlInstance, "--zone=" + o.controlZone, "--quiet", "--project=" + o.project, "--format=" + describeFormat},
				{o.gcloudBin, "compute", "instances", "describe", o.winn3Instance, "--zone=" + o.winn3Zone, "--quiet", "--project=" + o.project, "--format=" + describeFormat},
				{o.gcloudBin, "compute", "instances", "describe", o.coverInstance, "--zone=" + o.coverZone, "--quiet", "--project=" + o.project, "--format=" + describeFormat},
			}
			for i, want := range describes {
				if strings.Join(runner.calls[i+1], "\x00") != strings.Join(want, "\x00") {
					t.Fatalf("describe argv mismatch:\n got %#v\nwant %#v", runner.calls[i+1], want)
				}
			}
			for i, step := range plan {
				requestSHA, err := requestDigest(o, identity, step, testChallenge)
				if err != nil {
					t.Fatal(err)
				}
				remoteCommand := strings.Join([]string{
					remoteSudo, "--non-interactive", remoteHelper,
					"--schema-version=4", "--action=" + action, "--phase=" + step.phase,
					"--project=" + o.project, "--instance=" + step.instance, "--role=" + step.role,
					"--fleet-id=" + o.fleetID, "--run-id=" + o.runID, "--session-id=" + o.sessionID,
					"--correlation-id=" + o.correlationID, "--client-build-identity=" + identity.BuildIdentity,
					"--challenge=" + testChallenge, "--request-hash=" + requestSHA,
				}, " ")
				want := []string{o.gcloudBin, "compute", "ssh", step.instance, "--zone=" + step.zone, "--quiet", "--project=" + o.project, "--command=" + remoteCommand}
				got := runner.calls[4+i]
				if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
					t.Fatalf("ssh argv mismatch:\n got %#v\nwant %#v", got, want)
				}
			}
			var got any
			if err := strictDecode(output.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVersionAndCustodyFailuresRefuseBeforeCompute(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("route-decision")
	t.Run("wrong version", func(t *testing.T) {
		bad := &scriptedRunner{results: []commandResult{{stdout: []byte(`{"Google Cloud SDK":"580.0.0"}`)}}}
		if err := runCLI(actionArgv(o), bad, &bytes.Buffer{}); err == nil {
			t.Fatal("wrong gcloud version was accepted")
		}
		if len(bad.calls) != 1 || len(bad.calls[0]) < 2 || bad.calls[0][1] != "version" {
			t.Fatalf("compute ran before version refusal: %#v", bad.calls)
		}
	})
	t.Run("replacement after version", func(t *testing.T) {
		guard := &fakeGcloudGuard{path: o.gcloudBin, failAt: 3}
		loadGcloudGuard = func(string) (gcloudGuard, error) { return guard, nil }
		runner := newOrchestrator(t, o, nil)
		if err := runCLI(actionArgv(o), runner, &bytes.Buffer{}); err == nil {
			t.Fatal("post-version executable replacement was accepted")
		}
		if len(runner.calls) != 1 || runner.calls[0][1] != "version" {
			t.Fatalf("compute ran after custody changed: %#v", runner.calls)
		}
	})
}

func TestRealCustodyVerifierUsesArchiveBackedInstallation(t *testing.T) {
	fixture := newGcloudCustodyFixture(t)
	guard, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.verifyUnchanged(); err != nil {
		t.Fatal(err)
	}
}

func TestRealCustodyVerifierRejectsForgedReceiptAndArchiveMutation(t *testing.T) {
	t.Run("arbitrary SDK with self-authored receipt", func(t *testing.T) {
		fixture := newGcloudCustodyFixture(t)
		if err := os.WriteFile(fixture.executable, []byte("#!/bin/sh\nprintf 'MALICIOUS\\n'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		rewriteGcloudReceipt(t, fixture)
		if _, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner); err == nil {
			t.Fatal("arbitrary SDK plus self-authored receipt was accepted")
		}
	})
	t.Run("retained archive mutation", func(t *testing.T) {
		fixture := newGcloudCustodyFixture(t)
		if err := os.Chmod(fixture.retainedArchive, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.retainedArchive, append(fixture.archiveData, []byte("mutated")...), 0444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fixture.retainedArchive, 0444); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner); err == nil {
			t.Fatal("mutated retained official archive was accepted")
		}
	})
	t.Run("receipt mode mutation", func(t *testing.T) {
		fixture := newGcloudCustodyFixture(t)
		if err := os.Chmod(fixture.receipt, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner); err == nil {
			t.Fatal("mutable custody receipt was accepted")
		}
	})
}

func TestOfficialArchiveTraversalIsRejected(t *testing.T) {
	cases := []tarFixtureMember{
		{name: "../escape", typeflag: tar.TypeReg, mode: 0644, body: "escape"},
		{name: "google-cloud-sdk/../escape", typeflag: tar.TypeReg, mode: 0644, body: "escape"},
		{name: "google-cloud-sdk/a/../bin/gcloud", typeflag: tar.TypeReg, mode: 0755, body: "escape"},
		{name: "google-cloud-sdk/link", typeflag: tar.TypeSymlink, mode: 0777, link: "../../escape"},
	}
	for _, member := range cases {
		t.Run(member.name, func(t *testing.T) {
			archive := makeGcloudArchive(t, []tarFixtureMember{
				{name: "google-cloud-sdk/", typeflag: tar.TypeDir, mode: 0755},
				member,
			})
			if _, err := extractOfficialGcloudArchive(archive, "google-cloud-cli-582.0.0-linux-x86_64.tar.gz", filepath.Join(t.TempDir(), "archive")); err == nil {
				t.Fatal("traversal archive was accepted")
			}
		})
	}
}

func TestSwapRunRestoreExecutesPrivateArchiveCopy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("descriptor-root execution is Linux-only and is exercised in the Linux custody suite")
	}
	fixture := newGcloudCustodyFixture(t)
	guard, err := verifyGcloudCustodyWithPinAndAuthority(fixture.executable, fixture.pin, fixture.authority, fixture.issuance, fixture.authorityOwner)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.bindIdentity(testGcloudIdentity(t)); err != nil {
		t.Fatal(err)
	}
	delegate := &swapRestoreDescriptorRunner{}
	for attempt := 0; attempt < 25; attempt++ {
		result, err := guard.run(context.Background(), delegate, []string{"probe"})
		if err != nil {
			t.Fatal(err)
		}
		if string(result.stdout) != "REVIEWED\n" || result.exitCode != 0 {
			t.Fatalf("private runtime did not execute reviewed bytes: %#v", result)
		}
	}
	if delegate.maliciousExecutions != 0 {
		t.Fatalf("substituted private runtime executed %d times", delegate.maliciousExecutions)
	}
}

type scriptedRunner struct {
	results []commandResult
	calls   [][]string
}

func (r *scriptedRunner) run(_ context.Context, argv []string) (commandResult, error) {
	r.calls = append(r.calls, append([]string(nil), argv...))
	if len(r.results) == 0 {
		return commandResult{}, errors.New("unexpected command")
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result, nil
}

func TestArgvAndRemoteSchemasFailClosedBeforeOutput(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("route-decision")
	valid := newOrchestrator(t, o, nil)
	cases := []struct {
		name string
		argv []string
		ssh  [][]byte
	}{
		{"reordered argv", func() []string { v := actionArgv(o); v[0], v[2] = v[2], v[0]; return v }(), valid.ssh},
		{"extra argv", append(actionArgv(o), "--extra", "value"), valid.ssh},
		{"unknown envelope key", actionArgv(o), [][]byte{bytes.Replace(valid.ssh[0], []byte(`{`), []byte(`{"unknown":1,`), 1)}},
		{"duplicate envelope key", actionArgv(o), [][]byte{bytes.Replace(valid.ssh[0], []byte(`{`), []byte(`{"action":"route-decision",`), 1)}},
		{"effect digest mismatch", actionArgv(o), orchestrationBodies(t, o, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
			env.EffectSHA256 = strings.Repeat("f", 64)
		})},
		{"wrong remote operation", actionArgv(o), orchestrationBodies(t, o, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
			env.Operation = "fixture"
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &orchestratorRunner{describes: describeBodies(o), ssh: tc.ssh}
			var output bytes.Buffer
			if err := runCLI(tc.argv, runner, &output); err == nil {
				t.Fatal("invalid proof action was accepted")
			}
			if output.Len() != 0 {
				t.Fatal("invalid proof action emitted output")
			}
		})
	}
}

func TestUnsetBuildIdentityRefusesBeforeCommand(t *testing.T) {
	old := releaseValue
	releaseValue = "UNSET"
	t.Cleanup(func() { releaseValue = old })
	runner := &fakeRunner{}
	if err := runCLI(actionArgv(testOptions("route-decision")), runner, &bytes.Buffer{}); err == nil {
		t.Fatal("unbound executable was accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatal("unbound executable ran a command")
	}
}

func TestUnboundAttemptBrokerIdentityRefusesBeforeCommand(t *testing.T) {
	bindTestIdentity(t)
	for name, value := range map[string]string{
		"empty": "", "unset": "UNSET", "zero": strings.Repeat("0", 64), "malformed": strings.Repeat("A", 64),
	} {
		t.Run(name, func(t *testing.T) {
			expectedAttemptBrokerSHA256 = value
			runner := &fakeRunner{}
			var output bytes.Buffer
			if err := runCLI(actionArgv(testOptions("route-decision")), runner, &output); err == nil {
				t.Fatal("unbound attempt-broker build identity was accepted")
			}
			if len(runner.calls) != 0 || output.Len() != 0 {
				t.Fatal("unbound attempt-broker build identity crossed the command or output boundary")
			}
		})
	}
}

func TestAttemptBrokerIdentityRejectsHostileRemoteDigests(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("connect-primary")
	cases := map[string]map[string]string{
		"missing":   {"remote": testHelperRemote},
		"empty":     {"attempt_broker": "", "remote": testHelperRemote},
		"zero":      {"attempt_broker": strings.Repeat("0", 64), "remote": testHelperRemote},
		"arbitrary": {"attempt_broker": strings.Repeat("9", 64), "remote": testHelperRemote},
	}
	for name, hashes := range cases {
		t.Run(name, func(t *testing.T) {
			runner := newOrchestrator(t, o, func(_ int, step observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
				if step.role == "control" && step.phase == phaseExercise {
					encoded, err := json.Marshal(hashes)
					if err != nil {
						t.Fatal(err)
					}
					env.HelperHashes = encoded
				}
			})
			var output bytes.Buffer
			if err := runCLI(actionArgv(o), runner, &output); err == nil {
				t.Fatal("hostile attempt-broker identity was accepted")
			}
			if output.Len() != 0 {
				t.Fatal("rejected attempt-broker identity emitted output")
			}
		})
	}
}

func TestAttemptBrokerIdentityParticipatesInStabilityAndProofClosure(t *testing.T) {
	bindTestIdentity(t)
	process := testProcess("control")
	evidence := remoteEvidence{BootID: testControlBoot, ProcessIdentity: process}
	stable := []validatedObservation{
		{
			step: observationStep{role: "control", phase: phaseExercise}, evidence: evidence,
			helpers: map[string]string{"attempt_broker": testHelperBroker, "remote": testHelperRemote},
		},
		{
			step: observationStep{role: "control", phase: phaseExercise}, evidence: evidence,
			helpers: map[string]string{"attempt_broker": testHelperBroker, "remote": testHelperRemote},
		},
	}
	if err := rejectUnstableInstanceIdentity(stable); err != nil {
		t.Fatalf("stable attempt-broker identity was rejected: %v", err)
	}
	unstable := append([]validatedObservation(nil), stable...)
	unstable[1].helpers = map[string]string{"attempt_broker": strings.Repeat("9", 64), "remote": testHelperRemote}
	if err := rejectUnstableInstanceIdentity(unstable); err == nil {
		t.Fatal("attempt-broker identity change escaped cross-observation stability")
	}

	o := testOptions("connect-primary")
	closure := stable[:1]
	if err := validateProofClosure(o, closure); err != nil {
		t.Fatalf("reviewed attempt-broker identity did not close proof: %v", err)
	}
	for name, helpers := range map[string]map[string]string{
		"missing":   {"remote": testHelperRemote},
		"zero":      {"attempt_broker": strings.Repeat("0", 64), "remote": testHelperRemote},
		"arbitrary": {"attempt_broker": strings.Repeat("9", 64), "remote": testHelperRemote},
	} {
		t.Run("closure-"+name, func(t *testing.T) {
			candidate := append([]validatedObservation(nil), closure...)
			candidate[0].helpers = helpers
			if err := validateProofClosure(o, candidate); err == nil {
				t.Fatal("unbound attempt-broker identity closed proof")
			}
		})
	}
}

func TestRemoteWindowWithinTwoMinuteBoundIsAccepted(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("route-decision")
	runner := newOrchestrator(t, o, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
		env.EndedUTC = time.Date(2026, 8, 24, 12, 1, 59, 0, time.UTC).Format(time.RFC3339Nano)
	})
	if err := runCLI(actionArgv(o), runner, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestExpandedRemoteEvidenceRejectsEveryFalsePassPath(t *testing.T) {
	bindTestIdentity(t)
	primary := testOptions("connect-primary")
	fallback := testOptions("probe-awg-block")
	winn3Fallback := testOptions("probe-winn3-block")
	withdrawn := testOptions("probe-cover-withdrawn")
	winn3Block := testOptions("inject-winn3-block")
	teardown := testOptions("teardown-check")
	awg := testOptions("connect-cover-awg")

	type tc struct {
		name string
		o    options
		body func() *orchestratorRunner
	}
	cases := []tc{
		{
			name: "caller supplied success",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(i int, step observationStep, _ *remoteEnvelope, _ *remoteEvidence, data map[string]any) {
					if step.phase == phaseExercise {
						data["success"] = true
					}
				})
			},
		},
		{
			name: "aggregate synthetic counters",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(i int, step observationStep, _ *remoteEnvelope, _ *remoteEvidence, data map[string]any) {
					if step.phase == phaseExercise {
						data["bytes_rx"] = 999999
					}
				})
			},
		},
		{
			name: "reflection only Winn3 status",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if evidence.Winn3Status != nil {
						evidence.Winn3Status.InnerPacketsDelivered = 0
						evidence.Winn3Status.RXDeviceWrites = 0
						evidence.Winn3Status.Reflected = 10
					}
				})
			},
		},
		{
			name: "stale positive Winn3 status",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.phase == phaseObserveAfter && evidence.Winn3Status != nil {
						*evidence.Winn3Status = *testWinn3Status(9, 11, 11, "2026-08-24T12:00:00Z")
						evidence.InterfaceCounters[realWinn3Interface] = netCount{RX: 1000, TX: 2000}
					}
				})
			},
		},
		{
			name: "synthetic winn3 interface",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if evidence.InterfaceCounters != nil {
						delete(evidence.InterfaceCounters, realWinn3Interface)
						evidence.InterfaceCounters["winn3"] = netCount{RX: 3048, TX: 3024}
					}
				})
			},
		},
		{
			name: "missing active attempt acknowledgement",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.phase == phaseExercise {
						evidence.AttemptAcknowledgments = []protocolAttemptAck{}
					}
				})
			},
		},
		{
			name: "mismatched active attempt acknowledgement",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if len(evidence.AttemptAcknowledgments) != 0 {
						evidence.AttemptAcknowledgments[0].Node = primary.coverInstance
					}
				})
			},
		},
		{
			name: "candidate build mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.ClientBuildIdentity = strings.Repeat("9", 64)
				})
			},
		},
		{
			name: "challenge mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					env.Challenge = strings.Repeat("a", 64)
					evidence.Challenge = strings.Repeat("a", 64)
				})
			},
		},
		{
			name: "instance numeric id mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					env.InstanceID = "9"
					evidence.InstanceID = "9"
				})
			},
		},
		{
			name: "missing helper hashes",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.HelperHashes = json.RawMessage(`{}`)
				})
			},
		},
		{
			name: "transaction nonce mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					var tx transactionRecord
					if err := json.Unmarshal(env.Transaction, &tx); err == nil {
						tx.Nonce = strings.Repeat("0", 64)
						env.Transaction, _ = json.Marshal(tx)
					}
				})
			},
		},
		{
			name: "absent AWG peers counted as failure",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.AWGPeers = nil
				})
			},
		},
		{
			name: "Xray before AWG",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, data map[string]any) {
					if step.phase != phaseExercise || evidence.AttemptJournalAfter == nil {
						return
					}
					events := testFallbackEvents(fallback)
					reordered := []attemptEvent{events[2], events[3], events[0], events[1]}
					evidence.AttemptJournalAfterAWG = testJournal(reordered[:2])
					evidence.AttemptJournalAfter = testJournal(reordered)
					data["attempt_events"] = reordered
				})
			},
		},
		{
			name: "no timestamped AWG attempt",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if evidence.AttemptJournalAfterAWG != nil {
						evidence.AttemptJournalAfterAWG = testJournal([]attemptEvent{})
					}
				})
			},
		},
		{
			name: "Winn3 block fallback journal reordered",
			o:    winn3Fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, winn3Fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, data map[string]any) {
					if step.phase != phaseExercise || evidence.AttemptJournalAfter == nil {
						return
					}
					events := testWinn3BlockEvents(winn3Fallback)
					reordered := []attemptEvent{events[2], events[3], events[0], events[1]}
					evidence.AttemptJournalAfterAWG = testJournal(reordered[:2])
					evidence.AttemptJournalAfter = testJournal(reordered)
					data["attempt_events"] = reordered
				})
			},
		},
		{
			name: "cover withdrawal missing timestamped refusal",
			o:    withdrawn,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, withdrawn, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.phase == phaseExercise {
						evidence.AttemptJournalAfter = testJournal([]attemptEvent{})
					}
				})
			},
		},
		{
			name: "fresh AWG handshake contradicts failure",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.phase == phaseObserveAfter && len(evidence.AWGPeers) != 0 {
						evidence.AWGPeers[0].LatestHandshakeUnix = handshakeUnix(testFallbackEvents(fallback)[1].UTC)
					}
				})
			},
		},
		{
			name: "connected AWG handshake outside action window",
			o:    awg,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, awg, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, data map[string]any) {
					if step.phase == phaseObserveAfter && len(evidence.AWGPeers) != 0 {
						evidence.AWGPeers[0].LatestHandshakeUnix = handshakeUnix("2026-08-24T12:00:21Z")
					}
					if step.phase == phaseExercise {
						data["latest_handshake_utc"] = "2026-08-24T12:00:21Z"
					}
				})
			},
		},
		{
			name: "stale Xray traffic",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.phase == phaseObserveAfter && evidence.XrayStats != nil {
						evidence.XrayStats.Uplink = 800
						evidence.XrayStats.Downlink = 700
					}
				})
			},
		},
		{
			name: "same node fallback response",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, data map[string]any) {
					if step.phase != phaseExercise {
						return
					}
					events := testFallbackEvents(fallback)
					for i := range events {
						events[i].Node = fallback.winn3Instance
					}
					evidence.AttemptJournalAfterAWG = testJournal(events[:2])
					evidence.AttemptJournalAfter = testJournal(events)
					for i := range evidence.AttemptAcknowledgments {
						evidence.AttemptAcknowledgments[i].Node = fallback.winn3Instance
					}
					data["attempt_events"] = events
					data["attempts"] = []any{
						map[string]any{"protocol": "awg", "node": fallback.winn3Instance, "result": "blocked"},
						map[string]any{"protocol": "xray", "node": fallback.winn3Instance, "result": "connected"},
					}
				})
			},
		},
		{
			name: "cross-role Winn3 status on cover",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.role == "data-cover" {
						evidence.Winn3Status = testWinn3Status(9, 11, 11, "2026-08-24T12:00:00Z")
					}
				})
			},
		},
		{
			name: "cross-role AWG peers on Winn3",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, step observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if step.role == "data-winn3" {
						evidence.AWGPeers = awgPeers(1, 1, 1)
					}
				})
			},
		},
		{
			name: "equal monotonic interval",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.EndedMonotonicNS = evidence.StartedMonotonicNS
				})
			},
		},
		{
			name: "equal UTC interval",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.EndedUTC = env.StartedUTC
				})
			},
		},
		{
			name: "noncanonical ten-digit UTC fraction",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.StartedUTC = "2026-08-24T12:00:00.1234567890Z"
				})
			},
		},
		{
			name: "excessive monotonic interval",
			o:    fallback,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, fallback, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.EndedMonotonicNS = evidence.StartedMonotonicNS + maxActionNanoseconds + 1
				})
			},
		},
		{
			name: "data-winn3 contains Xray unit",
			o:    winn3Block,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, winn3Block, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.Services.Units["xray.service"] = serviceUnitEvidence{ActiveState: "active", FragmentPath: "/lib/systemd/system/xray.service", FragmentSHA256: strings.Repeat("7", 64), MainPID: 9001, ExecutableSHA256: strings.Repeat("8", 64)}
				})
			},
		},
		{
			name: "data-winn3 Docker binary present",
			o:    winn3Block,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, winn3Block, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					evidence.Services.Forbidden.Binaries["/usr/bin/docker"] = forbiddenBinaryEvidence{Absent: false}
				})
			},
		},
		{
			name: "response action mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.Action = "route-decision"
				})
			},
		},
		{
			name: "response role mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.Role = "data-cover"
				})
			},
		},
		{
			name: "response node mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, _ *remoteEvidence, _ map[string]any) {
					env.Instance = primary.coverInstance
				})
			},
		},
		{
			name: "fleet resource substitution",
			o:    teardown,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, teardown, func(_ int, _ observationStep, _ *remoteEnvelope, _ *remoteEvidence, data map[string]any) {
					data["expected_resources"].(map[string]any)["network"] = "pf-aaaaaaaaaaaa-net"
					data["observed_resources"].(map[string]any)["network"] = "pf-aaaaaaaaaaaa-net"
				})
			},
		},
		{
			name: "unknown evidence key",
			o:    primary,
			body: func() *orchestratorRunner {
				return &orchestratorRunner{describes: describeBodies(primary), ssh: rawEvidenceMutation(t, primary, 0, func(e map[string]any) { e["unknown"] = 1 })}
			},
		},
		{
			name: "missing evidence key",
			o:    primary,
			body: func() *orchestratorRunner {
				return &orchestratorRunner{describes: describeBodies(primary), ssh: rawEvidenceMutation(t, primary, 0, func(e map[string]any) { delete(e, "role") })}
			},
		},
		{
			name: "evidence type mismatch",
			o:    primary,
			body: func() *orchestratorRunner {
				return &orchestratorRunner{describes: describeBodies(primary), ssh: rawEvidenceMutation(t, primary, 0, func(e map[string]any) { e["started_monotonic_ns"] = "11000000000" })}
			},
		},
		{
			name: "status v1 is synthetic",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if evidence.Winn3Status != nil {
						evidence.Winn3Status.SchemaVersion = 1
						evidence.Winn3Status.Contract = "winsvpn-gcp-proof-winn3-status-v1"
					}
				})
			},
		},
		{
			name: "duplicate AWG peer keys",
			o:    awg,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, awg, func(_ int, _ observationStep, _ *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					if len(evidence.AWGPeers) != 0 {
						evidence.AWGPeers = append(evidence.AWGPeers, evidence.AWGPeers[0])
					}
				})
			},
		},
		{
			name: "malformed boot id",
			o:    primary,
			body: func() *orchestratorRunner {
				return newOrchestrator(t, primary, func(_ int, _ observationStep, env *remoteEnvelope, evidence *remoteEvidence, _ map[string]any) {
					env.BootID = "not-a-boot-id"
					evidence.BootID = "not-a-boot-id"
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := tc.body()
			var output bytes.Buffer
			if err := runCLI(actionArgv(tc.o), runner, &output); err == nil {
				t.Fatal("adversarial proof response was accepted")
			}
			if output.Len() != 0 {
				t.Fatal("rejected proof response emitted output")
			}
		})
	}
}

func TestTestOnlyAndDuplicateNestedEvidenceNeverEmit(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("route-decision")
	valid := orchestrationBodies(t, o, nil)[0]
	testOnly := bytes.Replace(valid, []byte(`"contract":"`+remoteContract+`"`), []byte(`"contract":"winsvpn-gcp-proof-remote-action-test-v1"`), 1)
	duplicate := bytes.Replace(valid, []byte(`"schema_version":4`), []byte(`"schema_version":4,"schema_version":4`), 1)
	for name, body := range map[string][]byte{"TEST_ONLY": testOnly, "duplicate nested key": duplicate} {
		t.Run(name, func(t *testing.T) {
			runner := &orchestratorRunner{describes: describeBodies(o), ssh: [][]byte{body}}
			var output bytes.Buffer
			if err := runCLI(actionArgv(o), runner, &output); err == nil || output.Len() != 0 {
				t.Fatal("nonproduction or duplicate-key response was accepted")
			}
		})
	}
}

func TestSameNodeFallbackRequestIsRejectedBeforeCommand(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("probe-awg-block")
	o.coverInstance = o.winn3Instance
	runner := &fakeRunner{}
	if err := runCLI(actionArgv(o), runner, &bytes.Buffer{}); err == nil {
		t.Fatal("same-node fallback request was accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatal("same-node fallback request executed a command")
	}
}

type identityRequiredGuard struct {
	fakeGcloudGuard
}

func (g *identityRequiredGuard) bindIdentity(input gcloudIdentityInput) error {
	if input.kind == "" || input.path == "" || input.expectedAccount == "" || input.expectedProject == "" {
		return errors.New("owner blocker: Google Cloud CLI execution requires an exact descriptor-authenticated service-account credential or workload identity input")
	}
	return nil
}

func TestMissingCredentialArgvFailsClosedBeforeCommand(t *testing.T) {
	bindTestIdentity(t)
	oldGuard := loadGcloudGuard
	loadGcloudGuard = func(path string) (gcloudGuard, error) {
		return &identityRequiredGuard{fakeGcloudGuard{path: path}}, nil
	}
	t.Cleanup(func() { loadGcloudGuard = oldGuard })
	o := testOptions("route-decision")
	runner := &fakeRunner{}
	err := runCLI(actionArgv(o), runner, &bytes.Buffer{})
	if err == nil {
		t.Fatal("unbound credential argv was accepted")
	}
	if !strings.Contains(err.Error(), "owner blocker") {
		t.Fatalf("missing identity error leaked or drifted: %v", err)
	}
	assertNoSecret(t, err.Error())
	if len(runner.calls) != 0 {
		t.Fatal("unbound credential argv executed a command")
	}
}

func TestCredentialArgvBindsBeforeRemoteCommands(t *testing.T) {
	bindTestIdentity(t)
	oldGuard := loadGcloudGuard
	loadGcloudGuard = func(path string) (gcloudGuard, error) {
		return &identityRequiredGuard{fakeGcloudGuard{path: path}}, nil
	}
	t.Cleanup(func() { loadGcloudGuard = oldGuard })
	o := testOptions("route-decision")
	identity := testGcloudIdentity(t)
	argv := append(actionArgv(o),
		"--credential-kind", identity.kind,
		"--credential-path", identity.path,
		"--credential-account", identity.expectedAccount,
		"--credential-project", identity.expectedProject,
	)
	runner := newOrchestrator(t, o, nil)
	var output bytes.Buffer
	if err := runCLI(argv, runner, &output); err != nil {
		t.Fatal(err)
	}
	if output.Len() == 0 {
		t.Fatal("bound credential argv produced no observation")
	}
	assertNoSecret(t, string(output.Bytes()))
}

func TestCredentialProjectMismatchIsRejectedBeforeCommand(t *testing.T) {
	bindTestIdentity(t)
	o := testOptions("route-decision")
	identity := testGcloudIdentity(t)
	argv := append(actionArgv(o),
		"--credential-kind", identity.kind,
		"--credential-path", identity.path,
		"--credential-account", identity.expectedAccount,
		"--credential-project", "otherproof123",
	)
	runner := &fakeRunner{}
	err := runCLI(argv, runner, &bytes.Buffer{})
	if err == nil {
		t.Fatal("mismatched credential project was accepted")
	}
	assertNoSecret(t, err.Error())
	if len(runner.calls) != 0 {
		t.Fatal("mismatched credential project executed a command")
	}
}

func TestStateDigestMatchesPythonCanonicalBytesContract(t *testing.T) {
	got, err := canonicalJSONDigest([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := sha256.Sum256([]byte("{\"a\":1,\"b\":2}\n"))
	want := hex.EncodeToString(wantBytes[:])
	if got != want {
		t.Fatalf("state digest mismatch: got %s want %s", got, want)
	}
	canonical, err := canonicalJSON(map[string]any{"u": "\u00e9", "h": "<>&", "d": "\x7f"}, true)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := "{\"d\":\"\\u007f\",\"h\":\"<>&\",\"u\":\"\\u00e9\"}\n"
	if string(canonical) != wantCanonical {
		t.Fatalf("Python-compatible canonical JSON mismatch: got %q want %q", canonical, wantCanonical)
	}
	withoutLF, err := canonicalJSON(map[string]any{"b": 2, "a": 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(withoutLF) != `{"a":1,"b":2}` {
		t.Fatalf("effect canonical JSON must omit LF: %q", withoutLF)
	}
}

func TestStateDigestMatchesPythonWithoutHTMLEscaping(t *testing.T) {
	got, err := canonicalJSONDigest([]byte(`{"b":"<&>","a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	const want = "9bf946e6d8c9356d24da798d774308edd6827759ffe313608cd1809c03ce18ae"
	if got != want {
		t.Fatalf("Python canonical JSON digest mismatch: got %s want %s", got, want)
	}
}
