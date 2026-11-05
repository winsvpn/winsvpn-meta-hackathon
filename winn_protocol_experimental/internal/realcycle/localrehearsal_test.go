package realcycle

import (
	"strings"
	"testing"
)

func localRehearsalHex(seed string) string {
	if len(seed) > 64 {
		seed = seed[:64]
	}
	return seed + strings.Repeat("0", 64-len(seed))
}

func localRehearsalValidContract(t *testing.T) LocalRehearsalNodeContract {
	t.Helper()
	contract := LocalRehearsalNodeContract{
		RunID:                 localRehearsalHex("a1"),
		CycleID:               localRehearsalHex("a2"),
		AttemptID:             localRehearsalHex("a3"),
		TopologyID:            localRehearsalHex("a4"),
		PlanSHA256:            localRehearsalHex("b1"),
		PlanObjectDigest:      localRehearsalHex("b2"),
		E6ReceiptSHA256:       localRehearsalHex("c1"),
		E6ReceiptObjectDigest: localRehearsalHex("c2"),
		E7ReceiptSHA256:       localRehearsalHex("d1"),
		E7ReceiptObjectDigest: localRehearsalHex("d2"),
		RehearsalGrantDigest:  localRehearsalHex("e1"),
		WorkerSHA256:          localRehearsalHex("f1"),
		Role:                  "control",
		NodeID:                "n01",
		ServiceID:             "svc.control.v1",
		RehearsalNonce:        strings.Repeat("9", 32),
	}
	digest, err := LocalRehearsalContractObjectDigest(contract)
	if err != nil {
		t.Fatalf("contract digest: %v", err)
	}
	contract.ObjectDigest = digest
	return contract
}

func TestValidateLocalRehearsalContractAdmitsBoundContract(t *testing.T) {
	if err := ValidateLocalRehearsalContract(
		localRehearsalValidContract(t),
	); err != nil {
		t.Fatalf("bound contract was rejected: %v", err)
	}
}

func TestLocalRehearsalContractDigestIgnoresCarriedDigest(t *testing.T) {
	contract := localRehearsalValidContract(t)
	sealed := contract.ObjectDigest
	contract.ObjectDigest = strings.Repeat("f", 64)
	again, err := LocalRehearsalContractObjectDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	if again != sealed {
		t.Fatalf("digest depended on the carried value: %q vs %q", again, sealed)
	}
}

func TestValidateLocalRehearsalContractRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*LocalRehearsalNodeContract)
		reseal bool
	}{
		{"empty run id", func(c *LocalRehearsalNodeContract) {
			c.RunID = ""
		}, true},
		{"empty cycle id", func(c *LocalRehearsalNodeContract) {
			c.CycleID = ""
		}, true},
		{"empty attempt id", func(c *LocalRehearsalNodeContract) {
			c.AttemptID = ""
		}, true},
		{"empty topology id", func(c *LocalRehearsalNodeContract) {
			c.TopologyID = ""
		}, true},
		{"empty node id", func(c *LocalRehearsalNodeContract) {
			c.NodeID = ""
		}, true},
		{"empty service id", func(c *LocalRehearsalNodeContract) {
			c.ServiceID = ""
		}, true},
		{"malformed service id", func(c *LocalRehearsalNodeContract) {
			c.ServiceID = "svc control/v1"
		}, true},
		{"unadmitted role", func(c *LocalRehearsalNodeContract) {
			c.Role = "transit"
		}, true},
		{"malformed plan digest", func(c *LocalRehearsalNodeContract) {
			c.PlanSHA256 = "not-a-digest"
		}, true},
		{"uppercase digest", func(c *LocalRehearsalNodeContract) {
			c.WorkerSHA256 = strings.ToUpper(localRehearsalHex("ab"))
		}, true},
		{"malformed nonce", func(c *LocalRehearsalNodeContract) {
			c.RehearsalNonce = strings.Repeat("9", 31)
		}, true},
		{"nonce with digest length", func(c *LocalRehearsalNodeContract) {
			c.RehearsalNonce = strings.Repeat("9", 64)
		}, true},
		{"self digest mismatch", func(c *LocalRehearsalNodeContract) {
			c.ObjectDigest = localRehearsalHex("dead")
		}, false},
		{"tampered field after sealing", func(c *LocalRehearsalNodeContract) {
			c.NodeID = "n99"
		}, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			contract := localRehearsalValidContract(t)
			testCase.mutate(&contract)
			if testCase.reseal {
				digest, err := LocalRehearsalContractObjectDigest(contract)
				if err != nil {
					t.Fatal(err)
				}
				contract.ObjectDigest = digest
			}
			if err := ValidateLocalRehearsalContract(contract); err == nil {
				t.Fatal("invalid contract was admitted")
			}
		})
	}
}

func localRehearsalFrame(state string) LocalRehearsalNodeFrame {
	frame := LocalRehearsalNodeFrame{
		ContractDigest: localRehearsalHex("a1"),
		Role:           "control",
		NodeID:         "n01",
		State:          state,
		ProcessID:      1000,
		ProcessStart:   5000,
	}
	if state != "ready" {
		frame.StartToken = "start-token-1"
	}
	if state == "terminal-success" {
		frame.OperationKind = LocalRehearsalOperationKind
		frame.OperationInput = localRehearsalHex("11")
		frame.OperationOutput = localRehearsalHex("22")
		frame.OperationDigest = localRehearsalHex("33")
	}
	return frame
}

func TestValidateLocalRehearsalFrameAdmitsEachState(t *testing.T) {
	for _, state := range []string{"ready", "start", "terminal-success"} {
		if err := ValidateLocalRehearsalFrame(
			localRehearsalFrame(state),
		); err != nil {
			t.Fatalf("%s frame was rejected: %v", state, err)
		}
	}
}

func TestValidateLocalRehearsalFrameRejections(t *testing.T) {
	cases := []struct {
		name   string
		frame  LocalRehearsalNodeFrame
		mutate func(*LocalRehearsalNodeFrame)
	}{
		{"malformed contract digest", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) { f.ContractDigest = "short" }},
		{"empty role", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) { f.Role = "" }},
		{"unadmitted role", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) { f.Role = "transit" }},
		{"empty node id", localRehearsalFrame("start"),
			func(f *LocalRehearsalNodeFrame) { f.NodeID = "" }},
		{"unadmitted state", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) { f.State = "terminal" }},
		{"zero process id", localRehearsalFrame("start"),
			func(f *LocalRehearsalNodeFrame) { f.ProcessID = 0 }},
		{"zero process start", localRehearsalFrame("start"),
			func(f *LocalRehearsalNodeFrame) { f.ProcessStart = 0 }},
		{"ready carries start token", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) { f.StartToken = "leaked" }},
		{"start without token", localRehearsalFrame("start"),
			func(f *LocalRehearsalNodeFrame) { f.StartToken = "" }},
		{"terminal without token", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.StartToken = "" }},
		{"ready carries operation kind", localRehearsalFrame("ready"),
			func(f *LocalRehearsalNodeFrame) {
				f.OperationKind = LocalRehearsalOperationKind
			}},
		{"start carries operation evidence", localRehearsalFrame("start"),
			func(f *LocalRehearsalNodeFrame) {
				f.OperationDigest = localRehearsalHex("33")
			}},
		{"terminal wrong operation kind", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.OperationKind = "other" }},
		{"terminal missing operation kind", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.OperationKind = "" }},
		{"terminal malformed input", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.OperationInput = "bad" }},
		{"terminal malformed output", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.OperationOutput = "" }},
		{"terminal malformed digest", localRehearsalFrame("terminal-success"),
			func(f *LocalRehearsalNodeFrame) { f.OperationDigest = "bad" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			frame := testCase.frame
			testCase.mutate(&frame)
			if err := ValidateLocalRehearsalFrame(frame); err == nil {
				t.Fatal("invalid frame was admitted")
			}
		})
	}
}

func TestLocalRehearsalOperationEvidenceIsDeterministicAndSeparated(t *testing.T) {
	contract := localRehearsalValidContract(t)
	input, output, operation, err := LocalRehearsalOperationEvidence(
		contract, "start-token-1", 1000, 5000,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{input, output, operation} {
		if !validDigest(value) {
			t.Fatalf("evidence is not a digest: %q", value)
		}
	}
	if input == output || input == operation || output == operation {
		t.Fatal("evidence domains collapsed to the same digest")
	}
	againInput, againOutput, againOperation, err := LocalRehearsalOperationEvidence(
		contract, "start-token-1", 1000, 5000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if againInput != input || againOutput != output ||
		againOperation != operation {
		t.Fatal("evidence derivation is not deterministic")
	}
}

func TestLocalRehearsalOperationEvidenceBindsEveryInput(t *testing.T) {
	contract := localRehearsalValidContract(t)
	baseInput, baseOutput, baseOperation, err := LocalRehearsalOperationEvidence(
		contract, "start-token-1", 1000, 5000,
	)
	if err != nil {
		t.Fatal(err)
	}
	other := localRehearsalValidContract(t)
	other.NodeID = "n02"
	rebound, err := LocalRehearsalContractObjectDigest(other)
	if err != nil {
		t.Fatal(err)
	}
	other.ObjectDigest = rebound

	cases := []struct {
		name         string
		contract     LocalRehearsalNodeContract
		token        string
		processID    uint64
		processStart uint64
	}{
		{"contract digest", other, "start-token-1", 1000, 5000},
		{"start token", contract, "start-token-2", 1000, 5000},
		{"process id", contract, "start-token-1", 1001, 5000},
		{"process start", contract, "start-token-1", 1000, 5001},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input, output, operation, err := LocalRehearsalOperationEvidence(
				testCase.contract, testCase.token,
				testCase.processID, testCase.processStart,
			)
			if err != nil {
				t.Fatal(err)
			}
			if input == baseInput && output == baseOutput &&
				operation == baseOperation {
				t.Fatal("evidence did not change with a bound input")
			}
			if operation == baseOperation {
				t.Fatal("operation digest did not chain the change")
			}
		})
	}
}
