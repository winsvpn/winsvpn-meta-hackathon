//go:build linux && winn_incomplete_e8

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestE8RunsFourActualSealedNodeProcessesAndBuildsNonauthorizingReceipt(
	t *testing.T,
) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	workerPath := filepath.Join(t.TempDir(), "winn-local-sealed-node")
	command := exec.Command(
		"go", "build", "-tags", "winn_incomplete_e8",
		"-o", workerPath, "./cmd/winn-local-sealed-node",
	)
	command.Dir = moduleRoot
	command.Env = append(
		os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build real E8 worker: %v\n%s", err, output)
	}
	if err := os.Chmod(workerPath, 0o500); err != nil {
		t.Fatal(err)
	}
	workerBytes, err := os.ReadFile(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	workerSHA := admittedRawSHA(workerBytes)
	prepared, err := prepareLocalFourNode(
		context.Background(), workerPath, workerSHA,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	plan := e5FourNodePlan{
		RunID: "run-e8", CycleID: "cycle-e8", AttemptID: "attempt-e8",
		TopologyID: "topology-e8",
	}
	for index, role := range e5RequiredRoles {
		plan.Nodes[index] = e5PlanNode{
			Role: role, NodeID: "node-" + role, ServiceID: "service-" + role,
			ProcessID:         prepared.identities[index].ProcessID,
			ProcessStartTicks: prepared.identities[index].ProcessStartTicks,
			ExecutableSHA256:  workerSHA,
		}
	}
	e6 := e6VerificationReceipt{
		PlanSHA256:       strings.Repeat("1", 64),
		PlanObjectDigest: strings.Repeat("2", 64),
		ObjectDigest:     strings.Repeat("3", 64),
	}
	e7 := e7VerificationReceipt{ObjectDigest: strings.Repeat("4", 64)}
	grant := e8GrantResult{
		CollectionDigest:    strings.Repeat("5", 64),
		MaxRehearsalSeconds: 10,
	}
	nodeNonces := [4]string{
		strings.Repeat("a", 32),
		strings.Repeat("b", 32),
		strings.Repeat("c", 32),
		strings.Repeat("d", 32),
	}
	nodes, err := runLocalFourNode(
		context.Background(), plan, e6, e7, grant,
		strings.Repeat("6", 64), strings.Repeat("7", 64),
		workerPath, workerSHA, nodeNonces, prepared,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index, node := range nodes {
		if node.Contract.Role != e5RequiredRoles[index] ||
			node.Ready.ProcessID == 0 ||
			node.Terminal.ProcessID != node.Ready.ProcessID ||
			node.Terminal.OperationDigest == "" ||
			!node.ChannelEOFObserved || !node.ZeroSurvivorsObserved ||
			node.ExitCode != 0 {
			t.Fatalf("unsafe E8 node %d: %+v", index, node)
		}
	}
	receipt, encoded, err := encodeE8Receipt(e8Receipt{
		RunID: plan.RunID, CycleID: plan.CycleID, AttemptID: plan.AttemptID,
		TopologyID:          plan.TopologyID,
		E3ReceiptDigest:     strings.Repeat("8", 64),
		E3CheckpointAddress: strings.Repeat("9", 64),
		E3InventoryDigest:   strings.Repeat("a", 64),
		PlanSHA256:          e6.PlanSHA256, PlanObjectDigest: e6.PlanObjectDigest,
		E6ReceiptSHA256:                 strings.Repeat("6", 64),
		E6ReceiptObjectDigest:           e6.ObjectDigest,
		E7ReceiptSHA256:                 strings.Repeat("7", 64),
		E7ReceiptObjectDigest:           e7.ObjectDigest,
		RehearsalGrantSHA256:            strings.Repeat("c", 64),
		RehearsalGrantObjectDigest:      strings.Repeat("d", 64),
		RehearsalAcceptanceSHA256:       strings.Repeat("e", 64),
		RehearsalAcceptanceObjectDigest: strings.Repeat("f", 64),
		RehearsalGrantCollectionDigest:  grant.CollectionDigest,
		WorkerSHA256:                    workerSHA,
		SupervisorExecutableSHA256:      strings.Repeat("8", 64),
		SupervisorExecutableDevice:      1,
		SupervisorExecutableInode:       2,
		SupervisorExecutableSize:        4096,
		SupervisorExecutableMode:        0o500,
		SupervisorIdentityDigest:        strings.Repeat("9", 64),
		Nodes:                           nodes,
		E3RunID:                         plan.RunID, E3CycleID: plan.CycleID,
		E3AttemptID: plan.AttemptID, E3TopologyID: plan.TopologyID,
		E3Sequence:         1,
		RehearsalCompleted: true, SandboxEnforced: true,
		Mutation: "local-evidence-only",
	})
	if err != nil || len(encoded) == 0 {
		t.Fatalf("encode E8 receipt: %v", err)
	}
	if receipt.ProviderAccess || receipt.CredentialAccess ||
		receipt.NetworkAccess || receipt.LiveNodesContacted ||
		receipt.SpendAuthorized || receipt.DispatchAuthorized ||
		receipt.ExplicitAuthorityConsumed || receipt.Authority {
		t.Fatalf("E8 granted authority: %+v", receipt)
	}
	androidBound := receipt
	for index := range androidBound.Nodes {
		androidBound.Nodes[index].AndroidPackageBindingDigest =
			strings.Repeat("a", 64)
	}
	androidBound, _, err = encodeE8Receipt(androidBound)
	if err != nil {
		t.Fatalf("encode Android package-bound E8 receipt: %v", err)
	}
	androidBound.Nodes[1].AndroidPackageBindingDigest = strings.Repeat("b", 64)
	if _, _, err := encodeE8Receipt(androidBound); err == nil {
		t.Fatal("E8 accepted cross-node Android package binding drift")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledPrepared, err := prepareLocalFourNode(
		context.Background(), workerPath, workerSHA,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = canceledPrepared.Close() })
	canceledPlan := plan
	for index := range canceledPlan.Nodes {
		canceledPlan.Nodes[index].ProcessID =
			canceledPrepared.identities[index].ProcessID
		canceledPlan.Nodes[index].ProcessStartTicks =
			canceledPrepared.identities[index].ProcessStartTicks
	}
	if _, err := runLocalFourNode(
		canceled, canceledPlan, e6, e7, grant,
		strings.Repeat("6", 64), strings.Repeat("7", 64),
		workerPath, workerSHA, nodeNonces, canceledPrepared,
	); err == nil {
		t.Fatal("E8 accepted a canceled rehearsal without cleanup")
	}
	drifted := receipt
	drifted.E7ReceiptSHA256 = strings.Repeat("0", 64)
	if _, _, err := encodeE8Receipt(drifted); err == nil {
		t.Fatal("E8 accepted an outer receipt/contract binding drift")
	}
	duplicateProcess := receipt
	duplicateProcess.Nodes[1].Ready.ProcessID =
		duplicateProcess.Nodes[0].Ready.ProcessID
	duplicateProcess.Nodes[1].Start.ProcessID =
		duplicateProcess.Nodes[0].Ready.ProcessID
	duplicateProcess.Nodes[1].Terminal.ProcessID =
		duplicateProcess.Nodes[0].Ready.ProcessID
	duplicateProcess.Nodes[1].Ready, _, err =
		encodeE8LocalRehearsalFrame(duplicateProcess.Nodes[1].Ready)
	if err != nil {
		t.Fatal(err)
	}
	duplicateProcess.Nodes[1].Start, _, err =
		encodeE8LocalRehearsalFrame(duplicateProcess.Nodes[1].Start)
	if err != nil {
		t.Fatal(err)
	}
	duplicateProcess.Nodes[1].Terminal, _, err =
		encodeE8LocalRehearsalFrame(duplicateProcess.Nodes[1].Terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := encodeE8Receipt(duplicateProcess); err == nil {
		t.Fatal("E8 accepted duplicate process identity evidence")
	}
}

func TestE8PhysicalAndroidAPI35RetainedWorkerRuntime(t *testing.T) {
	if runtime.GOOS != "android" {
		t.Skip("physical Android runtime gate")
	}
	bindingBytes, err := io.ReadAll(
		io.LimitReader(os.Stdin, e8LocalRehearsalMaxBytes+1),
	)
	if err != nil || len(bindingBytes) == 0 ||
		len(bindingBytes) > e8LocalRehearsalMaxBytes {
		t.Fatal("read in-memory Android PackageManager proof")
	}
	var proof e8AndroidPackageManagerProof
	if err := decodeStrictObject(bindingBytes, &proof); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAndroidPackagedLocalFourNode(
		context.Background(), proof,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	workerPath := filepath.Join(
		proof.NativeLibraryDir, e8AndroidWorkerFilename,
	)
	workerSHA := proof.WorkerSHA256
	plan := e5FourNodePlan{
		RunID: "android-e8", CycleID: "android-cycle",
		AttemptID: "android-attempt", TopologyID: "android-topology",
	}
	for index, role := range e5RequiredRoles {
		plan.Nodes[index] = e5PlanNode{
			Role: role, NodeID: "android-node-" + role,
			ServiceID:         "android-service-" + role,
			ProcessID:         prepared.identities[index].ProcessID,
			ProcessStartTicks: prepared.identities[index].ProcessStartTicks,
			ExecutableSHA256:  workerSHA,
		}
	}
	e6 := e6VerificationReceipt{
		PlanSHA256:       strings.Repeat("1", 64),
		PlanObjectDigest: strings.Repeat("2", 64),
		ObjectDigest:     strings.Repeat("3", 64),
	}
	e7 := e7VerificationReceipt{ObjectDigest: strings.Repeat("4", 64)}
	grant := e8GrantResult{
		CollectionDigest:    strings.Repeat("5", 64),
		MaxRehearsalSeconds: 20,
	}
	nonces := [4]string{
		strings.Repeat("a", 32), strings.Repeat("b", 32),
		strings.Repeat("c", 32), strings.Repeat("d", 32),
	}
	nodes, err := runLocalFourNode(
		context.Background(), plan, e6, e7, grant,
		strings.Repeat("6", 64), strings.Repeat("7", 64),
		workerPath, workerSHA, nonces, prepared,
	)
	if err != nil {
		t.Fatal(err)
	}
	for index, node := range nodes {
		if node.Ready.ProcessID != plan.Nodes[index].ProcessID ||
			node.Ready.ProcessStart != plan.Nodes[index].ProcessStartTicks ||
			!node.PidfdReaped || node.SandboxThreadCount == 0 ||
			node.SandboxStatusDigest == "" {
			t.Fatalf("Android E8 node %d runtime proof is incomplete", index)
		}
	}
}
