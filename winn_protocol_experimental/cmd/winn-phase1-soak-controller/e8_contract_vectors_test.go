//go:build winn_incomplete_e8

package main

import (
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

// Golden vectors for the E8 local sealed four-node rehearsal contract.
//
// One positive vector proves that a fully bound four-node receipt is admitted.
// Thirteen negative vectors each mutate exactly one property of that same
// vector and prove the acceptance predicate rejects it. The vectors are
// platform neutral: they exercise the contract, not the Linux rehearsal
// runtime, so they run wherever the subsystem compiles.

func e8VectorHex(seed string) string {
	if len(seed) > 64 {
		seed = seed[:64]
	}
	return seed + strings.Repeat("0", 64-len(seed))
}

func e8VectorNonce(seed string) string {
	if len(seed) > 32 {
		seed = seed[:32]
	}
	return seed + strings.Repeat("0", 32-len(seed))
}

// e8SealVector recomputes the receipt object digest so that a mutated vector
// still satisfies the self-digest check and fails for the property under test.
func e8SealVector(t *testing.T, value e8Receipt) e8Receipt {
	t.Helper()
	value.Schema = e8ReceiptSchema
	value.Mode = e8Mode
	value.ObjectDigest = ""
	digest, err := admittedDigest(e8ReceiptDomain, value)
	if err != nil {
		t.Fatalf("seal vector: %v", err)
	}
	value.ObjectDigest = digest
	return value
}

// e8SealNode rebuilds one node so its contract digest, frame cross bindings,
// and terminal operation evidence are all internally consistent.
func e8SealNode(
	t *testing.T, node e8NodeEvidence,
) e8NodeEvidence {
	t.Helper()
	digest, err := realcycle.LocalRehearsalContractObjectDigest(node.Contract)
	if err != nil {
		t.Fatalf("seal node contract: %v", err)
	}
	node.Contract.ObjectDigest = digest
	for _, frame := range []*realcycle.LocalRehearsalNodeFrame{
		&node.Ready, &node.Start, &node.Terminal,
	} {
		frame.ContractDigest = digest
		frame.Role = node.Contract.Role
		frame.NodeID = node.Contract.NodeID
	}
	input, output, operation, err := realcycle.LocalRehearsalOperationEvidence(
		node.Contract, node.Start.StartToken,
		node.Ready.ProcessID, node.Ready.ProcessStart,
	)
	if err != nil {
		t.Fatal(err)
	}
	node.Terminal.OperationKind = realcycle.LocalRehearsalOperationKind
	node.Terminal.OperationInput = input
	node.Terminal.OperationOutput = output
	node.Terminal.OperationDigest = operation
	return node
}

// e8PositiveVector builds the exactly-one positive golden vector.
func e8PositiveVector(t *testing.T) e8Receipt {
	t.Helper()
	var (
		runID      = e8VectorHex("a1")
		cycleID    = e8VectorHex("a2")
		attemptID  = e8VectorHex("a3")
		topologyID = e8VectorHex("a4")
		planSHA    = e8VectorHex("b1")
		planObject = e8VectorHex("b2")
		e6SHA      = e8VectorHex("c1")
		e6Object   = e8VectorHex("c2")
		e7SHA      = e8VectorHex("d1")
		e7Object   = e8VectorHex("d2")
		collection = e8VectorHex("e3")
		workerSHA  = e8VectorHex("f1")
	)
	receipt := e8Receipt{
		RunID: runID, CycleID: cycleID, AttemptID: attemptID,
		TopologyID: topologyID,
		E3RunID:    runID, E3CycleID: cycleID, E3AttemptID: attemptID,
		E3TopologyID: topologyID, E3Sequence: 1,
		E3ReceiptDigest:     e8VectorHex("11"),
		E3CheckpointAddress: e8VectorHex("12"),
		E3InventoryDigest:   e8VectorHex("13"),
		PlanSHA256:          planSHA, PlanObjectDigest: planObject,
		E6ReceiptSHA256: e6SHA, E6ReceiptObjectDigest: e6Object,
		E7ReceiptSHA256: e7SHA, E7ReceiptObjectDigest: e7Object,
		RehearsalGrantSHA256:            e8VectorHex("e1"),
		RehearsalGrantObjectDigest:      e8VectorHex("e2"),
		RehearsalAcceptanceSHA256:       e8VectorHex("e4"),
		RehearsalAcceptanceObjectDigest: e8VectorHex("e5"),
		RehearsalGrantCollectionDigest:  collection,
		WorkerSHA256:                    workerSHA,
		SupervisorExecutableSHA256:      e8VectorHex("ab"),
		SupervisorExecutableDevice:      64,
		SupervisorExecutableInode:       4242,
		SupervisorExecutableSize:        8192,
		SupervisorExecutableMode:        0o500,
		SupervisorIdentityDigest:        e8VectorHex("ac"),
		RehearsalCompleted:              true,
		SandboxEnforced:                 true,
		Mutation:                        "local-evidence-only",
	}
	services := [4]string{
		"svc.control.v1", "svc.entry1.v1", "svc.entry2.v1", "svc.exit.v1",
	}
	for index, role := range e5RequiredRoles {
		contract := realcycle.LocalRehearsalNodeContract{
			RunID: runID, CycleID: cycleID, AttemptID: attemptID,
			TopologyID: topologyID,
			PlanSHA256: planSHA, PlanObjectDigest: planObject,
			E6ReceiptSHA256: e6SHA, E6ReceiptObjectDigest: e6Object,
			E7ReceiptSHA256: e7SHA, E7ReceiptObjectDigest: e7Object,
			RehearsalGrantDigest: collection,
			WorkerSHA256:         workerSHA,
			Role:                 role,
			NodeID:               "n0" + string(rune('1'+index)),
			ServiceID:            services[index],
			RehearsalNonce: e8VectorNonce(
				"9" + string(rune('a'+index)),
			),
		}
		processID := uint64(1000 + index)
		processStart := uint64(5000 + index)
		startToken := "start-token-" + string(rune('1'+index))
		node := e8NodeEvidence{
			Contract: contract,
			Ready: realcycle.LocalRehearsalNodeFrame{
				State: "ready", ProcessID: processID,
				ProcessStart: processStart,
			},
			Start: realcycle.LocalRehearsalNodeFrame{
				State: "start", ProcessID: processID,
				ProcessStart: processStart, StartToken: startToken,
			},
			Terminal: realcycle.LocalRehearsalNodeFrame{
				State: "terminal-success", ProcessID: processID,
				ProcessStart: processStart, StartToken: startToken,
			},
			ExitCode:              0,
			ChannelEOFObserved:    true,
			ZeroSurvivorsObserved: true,
			SandboxThreadCount:    1,
			SandboxStatusDigest:   e8VectorHex("5" + string(rune('a'+index))),
			PidfdRetained:         true,
			PidfdReaped:           true,
			LifecyclePolicyDigest: e8LifecyclePolicyDigest(),
			DescriptorCount:       8,
			DescriptorCensusDigest: e8VectorHex(
				"6" + string(rune('a'+index)),
			),
		}
		receipt.Nodes[index] = e8SealNode(t, node)
	}
	return e8SealVector(t, receipt)
}

func TestE8PositiveGoldenVectorIsAdmitted(t *testing.T) {
	receipt := e8PositiveVector(t)
	if err := validateE8Receipt(receipt); err != nil {
		t.Fatalf("positive golden vector was rejected: %v", err)
	}
	sealed, encoded, err := encodeE8Receipt(receipt)
	if err != nil {
		t.Fatalf("positive golden vector did not encode: %v", err)
	}
	if len(encoded) == 0 || sealed.ObjectDigest != receipt.ObjectDigest {
		t.Fatalf(
			"encode changed the sealed digest: %q vs %q",
			sealed.ObjectDigest, receipt.ObjectDigest,
		)
	}
}

func TestE8NegativeGoldenVectorsAreRejected(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*testing.T, *e8Receipt)
		wantErr string
	}{
		{
			name: "N1 duplicate node_id",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[1].Contract.NodeID = r.Nodes[0].Contract.NodeID
				r.Nodes[1] = e8SealNode(t, r.Nodes[1])
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N2 duplicate service_id",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[1].Contract.ServiceID = r.Nodes[0].Contract.ServiceID
				r.Nodes[1] = e8SealNode(t, r.Nodes[1])
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N3 duplicate rehearsal_nonce",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[1].Contract.RehearsalNonce =
					r.Nodes[0].Contract.RehearsalNonce
				r.Nodes[1] = e8SealNode(t, r.Nodes[1])
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N4 malformed contract digest",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Contract.PlanSHA256 = "not-a-digest"
			},
			wantErr: "ValidateLocalRehearsalContract: digest field is malformed",
		},
		{
			// The terminal slot holds a well formed non-terminal frame, so
			// the frame validator admits it and the receipt-level terminal
			// check is the layer that rejects the downgrade.
			name: "N5 terminal frame is not terminal-success",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Terminal.State = "start"
				r.Nodes[0].Terminal.OperationKind = ""
				r.Nodes[0].Terminal.OperationInput = ""
				r.Nodes[0].Terminal.OperationOutput = ""
				r.Nodes[0].Terminal.OperationDigest = ""
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			// The same downgrade while retaining operation evidence is
			// rejected earlier, by the frame validator, which refuses
			// operation evidence before terminal-success.
			name: "N5b state downgrade retaining operation evidence",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Terminal.State = "start"
			},
			wantErr: "ValidateLocalRehearsalFrame: operation evidence is not " +
				"admitted before terminal-success",
		},
		{
			name: "N6 terminal process_id differs from ready",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Terminal.ProcessID++
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N6b start process_id differs from ready",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Start.ProcessID++
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N6c start process_start differs from ready",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Start.ProcessStart++
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N7 role order is invalid",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Contract.Role = "exit"
				r.Nodes[0] = e8SealNode(t, r.Nodes[0])
			},
			wantErr: "E8 node role order is invalid",
		},
		{
			name: "N8 authority is asserted",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Authority = true
			},
			wantErr: "E8 receipt authority state is unsafe",
		},
		{
			name: "N9 provider access is asserted",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.ProviderAccess = true
			},
			wantErr: "E8 receipt authority state is unsafe",
		},
		{
			name:    "N10 object digest is not re-derived",
			mutate:  nil,
			wantErr: "E8 receipt object digest mismatch",
		},
		{
			name: "N11 duplicate start_token",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[1].Start.StartToken = r.Nodes[0].Start.StartToken
				r.Nodes[1].Terminal.StartToken = r.Nodes[0].Start.StartToken
				r.Nodes[1] = e8SealNode(t, r.Nodes[1])
			},
			wantErr: "E8 node terminal evidence is inconsistent",
		},
		{
			name: "N12 empty service_id",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Contract.ServiceID = ""
				r.Nodes[0] = e8SealNode(t, r.Nodes[0])
			},
			wantErr: "ValidateLocalRehearsalContract: service_id must be non-empty",
		},
		{
			name: "N13 wrong terminal operation_kind",
			mutate: func(t *testing.T, r *e8Receipt) {
				r.Nodes[0].Terminal.OperationKind = "some-other-operation"
			},
			wantErr: "ValidateLocalRehearsalFrame: operation_kind is not admitted",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			receipt := e8PositiveVector(t)
			if testCase.mutate == nil {
				// N10 mutates a bound field without resealing, so the
				// receipt object digest no longer re-derives.
				receipt.E3Sequence++
			} else {
				testCase.mutate(t, &receipt)
				receipt = e8SealVector(t, receipt)
			}
			err := validateE8Receipt(receipt)
			if err == nil {
				t.Fatalf("negative vector was admitted")
			}
			if err.Error() != testCase.wantErr {
				t.Fatalf(
					"negative vector error mismatch:\n got: %q\nwant: %q",
					err.Error(), testCase.wantErr,
				)
			}
		})
	}
}
