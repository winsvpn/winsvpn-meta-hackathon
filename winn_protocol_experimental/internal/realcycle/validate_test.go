package realcycle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/realtopology"
)

type cycleFixture struct {
	t            *testing.T
	directory    string
	trustPath    string
	topologyPath string
	private      map[string]ed25519.PrivateKey
	trust        TrustBundle
	cycle        Cycle
	runtime      RuntimeSet
	lease        LeaseEvidence
	terminal     TerminalSet
}

func TestValidateBundleAcceptsBoundOfflineEvidence(t *testing.T) {
	fixture := newCycleFixture(t)
	result, err := ValidateBundle(
		fixture.directory, fixture.trustPath, fixture.topologyPath,
	)
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	if result.CycleID != fixture.cycle.CycleID ||
		result.AttemptID != fixture.cycle.AttemptID ||
		result.TopologyID != fixture.cycle.TopologyID ||
		result.BindingDigest != fixture.cycle.BindingDigest ||
		result.RuntimeCount != 4 || result.TerminalCount != 1 ||
		!validDigest(result.EvidenceBundleSHA256) {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestValidateBundleRejectsSemanticallySignedDefects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*cycleFixture)
		want   string
	}{
		{
			name: "signed E0 digest repetition differs",
			mutate: func(f *cycleFixture) {
				f.cycle.BundleSHA256 = strings.Repeat("f", 64)
			},
			want: "cycle fields",
		},
		{
			name: "signed E0 deployment repetition differs",
			mutate: func(f *cycleFixture) {
				f.cycle.Deployments[1].Provider = "substituted-provider"
			},
			want: "cycle deployment",
		},
		{
			name: "runtime differs from E0",
			mutate: func(f *cycleFixture) {
				f.runtime.Attestations[1].Provider = "substituted-provider"
			},
			want: "E0 binding",
		},
		{
			name: "runtime wrong node key",
			mutate: func(f *cycleFixture) {
				f.runtime.Attestations[1].KeyID = "runtime-entry-secondary"
			},
			want: "key role or node",
		},
		{
			name: "runtime counter domain differs",
			mutate: func(f *cycleFixture) {
				f.runtime.Attestations[0].CounterDomain = "other-counter"
			},
			want: "runtime attestation 0 fields",
		},
		{
			name: "runtime occurs after lease preparation",
			mutate: func(f *cycleFixture) {
				f.runtime.Attestations[3].ObservedAt =
					"2030-01-01T10:03:30Z"
				f.runtime.Attestations[3].ObservedCounter = 130
			},
			want: "lease commit fields",
		},
		{
			name: "lease stale revision",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.VaultRevisionAfter =
					f.lease.Commit.VaultRevisionBefore
			},
			want: "lease commit fields",
		},
		{
			name: "lease secret-like invalid peer",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.PeerPublicKey = "contains whitespace"
			},
			want: "lease commit fields",
		},
		{
			name: "token node outside E0",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.TokenClasses[0].NodeID = "unknown-node"
			},
			want: "not bound to an exercised service",
		},
		{
			name: "token service differs",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.TokenClasses[0].ServiceID = "service-exit"
			},
			want: "not bound to an exercised service",
		},
		{
			name: "token consumption differs from terminal",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.TokenClasses[0].ConsumedCount = 2
			},
			want: "conservation",
		},
		{
			name: "terminal process substitution",
			mutate: func(f *cycleFixture) {
				f.terminal.Receipts[0].ProcessStartTicks++
			},
			want: "process identity mismatch",
		},
		{
			name: "missing terminal receipt",
			mutate: func(f *cycleFixture) {
				f.terminal.Receipts = nil
			},
			want: "terminal receipt set fields",
		},
		{
			name: "terminal before lease commit",
			mutate: func(f *cycleFixture) {
				f.terminal.Receipts[0].ObservedAt =
					"2030-01-01T10:03:30Z"
			},
			want: "terminal receipt chronology",
		},
		{
			name: "terminal after lease terminal",
			mutate: func(f *cycleFixture) {
				f.lease.Terminal.TerminalAt =
					"2030-01-01T10:06:00Z"
			},
			want: "terminal receipt chronology",
		},
		{
			name: "success with burned lease",
			mutate: func(f *cycleFixture) {
				f.lease.Terminal.Disposition = "burned"
			},
			want: "outcomes are incoherent",
		},
		{
			name: "lease expires before terminal",
			mutate: func(f *cycleFixture) {
				f.lease.Commit.ExpiresAt = "2030-01-01T10:06:00Z"
			},
			want: "lease terminal chronology",
		},
		{
			name: "H3 conservation",
			mutate: func(f *cycleFixture) {
				f.terminal.Receipts[0].Closed = 0
			},
			want: "conservation",
		},
		{
			name: "unexercised terminal node",
			mutate: func(f *cycleFixture) {
				f.cycle.ExercisedNodes = []string{
					f.cycle.Deployments[2].NodeID,
				}
				f.lease.Commit.TokenClasses[0].NodeID =
					f.cycle.Deployments[2].NodeID
				f.lease.Commit.TokenClasses[0].ServiceID =
					f.cycle.Deployments[2].ServiceID
			},
			want: "ordered exercised_nodes",
		},
		{
			name: "ambiently expired evidence",
			mutate: func(f *cycleFixture) {
				f.runtime.Attestations[0].ObservedAt =
					"2030-01-01T11:00:00Z"
			},
			want: "outside accepted trust",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCycleFixture(t)
			test.mutate(fixture)
			fixture.seal()
			_, err := ValidateBundle(
				fixture.directory, fixture.trustPath, fixture.topologyPath,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateBundleRejectsUnixNanoWraparoundTimestamps(t *testing.T) {
	const upperWrap = "2614-07-23T09:35:33.709551616Z"
	const lowerWrap = "1445-06-13T10:26:26.290448384Z"
	tests := []struct {
		name   string
		mutate func(*cycleFixture)
	}{
		{"trust-upper", func(f *cycleFixture) {
			f.trust.ExpiresAt = upperWrap
			f.writeTrustAndReseal()
		}},
		{"cycle-lower", func(f *cycleFixture) {
			f.cycle.AcceptedAt = lowerWrap
			f.seal()
		}},
		{"runtime-upper", func(f *cycleFixture) {
			f.runtime.Attestations[0].ObservedAt = upperWrap
			f.seal()
		}},
		{"runtime-lower", func(f *cycleFixture) {
			f.runtime.Attestations[0].ObservedAt = lowerWrap
			f.seal()
		}},
		{"lease-upper", func(f *cycleFixture) {
			f.lease.Commit.PreparedAt = upperWrap
			f.seal()
		}},
		{"terminal-lower", func(f *cycleFixture) {
			f.terminal.Receipts[0].ObservedAt = lowerWrap
			f.seal()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCycleFixture(t)
			test.mutate(fixture)
			if _, err := ValidateBundle(
				fixture.directory, fixture.trustPath, fixture.topologyPath,
			); err == nil {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestParseTimeRejectsUnixNanoOverflowBeforeConversion(t *testing.T) {
	for _, value := range []string{
		"2614-07-23T09:35:33.709551616Z",
		"1445-06-13T10:26:26.290448384Z",
	} {
		if _, err := parseTime(value); err == nil ||
			!strings.Contains(err.Error(), "safe Unix nanosecond interval") {
			t.Fatalf("parseTime(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{
		"1677-09-21T00:12:43.145224192Z",
		"2262-04-11T23:47:16.854775807Z",
	} {
		if _, err := parseTime(value); err != nil {
			t.Fatalf("parseTime(%q) rejected safe boundary: %v", value, err)
		}
	}
}

func TestUncheckedUnixNanoWouldAliasSignedRuntimeTimestamp(t *testing.T) {
	baseline, err := time.Parse(
		time.RFC3339Nano, "2030-01-01T10:01:00Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	lowerWrap, err := time.Parse(
		time.RFC3339Nano, "1445-06-13T10:26:26.290448384Z",
	)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Equal(lowerWrap) {
		t.Fatal("distinct wall-clock timestamps unexpectedly compare equal")
	}
	if baseline.UnixNano() != lowerWrap.UnixNano() {
		t.Fatalf(
			"regression premise changed: baseline=%d lower=%d",
			baseline.UnixNano(), lowerWrap.UnixNano(),
		)
	}
	if _, err := parseTime(lowerWrap.Format(time.RFC3339Nano)); err == nil {
		t.Fatal("range-bounded parser accepted aliased lower timestamp")
	}
}

func TestValidateBundleRejectsDocumentAndFilesystemDefects(t *testing.T) {
	t.Run("duplicate field", func(t *testing.T) {
		fixture := newCycleFixture(t)
		path := filepath.Join(fixture.directory, CycleFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(
			string(data), `{"schema":`, `{"schema":"duplicate","schema":`, 1,
		)
		writePrivate(t, path, []byte(edited))
		_, err = ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "duplicate JSON") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		fixture := newCycleFixture(t)
		path := filepath.Join(fixture.directory, CycleFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		edited := strings.Replace(
			string(data), `,"signature":`, `,"unexpected":false,"signature":`,
			1,
		)
		writePrivate(t, path, []byte(edited))
		_, err = ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("noncanonical whitespace", func(t *testing.T) {
		fixture := newCycleFixture(t)
		path := filepath.Join(fixture.directory, LeaseFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writePrivate(t, path, append([]byte(" "), data...))
		_, err = ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("extra entry", func(t *testing.T) {
		fixture := newCycleFixture(t)
		writePrivate(
			t, filepath.Join(fixture.directory, "extra.json"), []byte("{}\n"),
		)
		_, err := ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "entries") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("writable evidence", func(t *testing.T) {
		fixture := newCycleFixture(t)
		path := filepath.Join(fixture.directory, RuntimeFile)
		if err := os.Chmod(path, 0o620); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("hard link", func(t *testing.T) {
		fixture := newCycleFixture(t)
		source := filepath.Join(fixture.directory, RuntimeFile)
		link := filepath.Join(t.TempDir(), "alias")
		if err := os.Link(source, link); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		_, err := ValidateBundle(
			fixture.directory, fixture.trustPath, fixture.topologyPath,
		)
		if err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestFinalEvidenceReplayRejectsPostReadMutation(t *testing.T) {
	fixture := newCycleFixture(t)
	root, entries, err := openEvidenceRoot(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	snapshots := make(map[string]fileSnapshot, len(entries))
	for _, name := range entries {
		_, snapshot, err := readRootFile(
			root, name, MaxEvidenceFileBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[name] = snapshot
	}
	target := filepath.Join(fixture.directory, RuntimeFile)
	if err := os.Chmod(target, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := recheckEvidenceRoot(
		fixture.directory, root, entries, snapshots,
	); err == nil || !strings.Contains(err.Error(), "changed after validation") {
		t.Fatalf("final replay error = %v", err)
	}
}

func TestConsumeE0ValidatesRetainedRootAcrossParentRenameSwap(t *testing.T) {
	parent := t.TempDir()
	active := writeRealE0Bundle(t, parent, "active")
	replacement := filepath.Join(parent, "replacement")
	copyDirectoryFiles(t, active, replacement)

	target := filepath.Join(active, "linux-profile.json")
	rewriteSameIdentityAndRestoreMtime(t, target)

	originalHook := afterE0RootRetained
	afterE0RootRetained = func() {
		if err := os.Rename(active, filepath.Join(parent, "retained-a")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, active); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		afterE0RootRetained = originalHook
	})

	snapshot, err := consumeE0(active)
	if err == nil {
		snapshot.close()
		t.Fatal("consumeE0 accepted invalid retained A after path switched to valid B")
	}
	if !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("consumeE0 error = %v", err)
	}
}

func TestFinalByteReplayRejectsSameInodeRewriteWithRestoredMtime(t *testing.T) {
	t.Run("evidence", func(t *testing.T) {
		fixture := newCycleFixture(t)
		root, entries, err := openEvidenceRoot(fixture.directory)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		snapshots := make(map[string]fileSnapshot, len(entries))
		for _, name := range entries {
			_, snapshot, readErr := readRootFile(
				root, name, MaxEvidenceFileBytes,
			)
			if readErr != nil {
				t.Fatal(readErr)
			}
			snapshots[name] = snapshot
		}
		rewriteSameIdentityAndRestoreMtime(
			t, filepath.Join(fixture.directory, RuntimeFile),
		)
		err = recheckEvidenceRoot(
			fixture.directory, root, entries, snapshots,
		)
		if err == nil || !strings.Contains(err.Error(), "changed after validation") {
			t.Fatalf("evidence replay error = %v", err)
		}
	})

	t.Run("trust", func(t *testing.T) {
		fixture := newCycleFixture(t)
		_, snapshot, err := readStandalone(
			fixture.trustPath, MaxTrustFileBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		rewriteSameIdentityAndRestoreMtime(t, fixture.trustPath)
		err = recheckStandalone(fixture.trustPath, snapshot)
		if err == nil || !strings.Contains(err.Error(), "changed after validation") {
			t.Fatalf("trust replay error = %v", err)
		}
	})

	t.Run("E0", func(t *testing.T) {
		parent := t.TempDir()
		path := writeRealE0Bundle(t, parent, "accepted")
		snapshot, err := consumeE0(path)
		if err != nil {
			t.Fatalf("consumeE0: %v", err)
		}
		defer snapshot.close()
		rewriteSameIdentityAndRestoreMtime(
			t, filepath.Join(path, "linux-profile.json"),
		)
		err = snapshot.recheck()
		if err == nil || !strings.Contains(err.Error(), "changed after validation") {
			t.Fatalf("E0 replay error = %v", err)
		}
	})
}

func copyDirectoryFiles(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, readErr := os.ReadFile(filepath.Join(source, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(
			filepath.Join(destination, entry.Name()), data, 0o644,
		); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
}

func rewriteSameIdentityAndRestoreMtime(t *testing.T, path string) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("cannot mutate empty file")
	}
	mutated := append([]byte(nil), data...)
	mutated[len(mutated)/2] ^= 1
	if err := os.Chmod(path, before.Mode().Perm()|0o200); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(mutated); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) ||
		before.Mode() != after.Mode() {
		t.Fatalf(
			"mutation did not preserve identity metadata: before=%v after=%v",
			before, after,
		)
	}
}

func TestValidateBundleRejectsUnacceptedOrMisboundTrust(t *testing.T) {
	fixture := newCycleFixture(t)
	fixture.trust.Keys[0].PublicKey = fixture.trust.Keys[1].PublicKey
	writeCanonical(t, fixture.trustPath, fixture.trust)
	_, err := ValidateBundle(
		fixture.directory, fixture.trustPath, fixture.topologyPath,
	)
	if err == nil || !strings.Contains(err.Error(), "cycle fields") {
		t.Fatalf("error = %v", err)
	}

	fixture = newCycleFixture(t)
	fixture.trust.Keys[1].NodeID = fixture.trust.Keys[2].NodeID
	writeCanonical(t, fixture.trustPath, fixture.trust)
	_, err = ValidateBundle(
		fixture.directory, fixture.trustPath, fixture.topologyPath,
	)
	if err == nil || !strings.Contains(err.Error(), "duplicate trust role/node") {
		t.Fatalf("error = %v", err)
	}
}

func TestDirectAWGTerminalContract(t *testing.T) {
	fixture := newCycleFixture(t)
	fixture.cycle.ExpectedTransport = TransportDirect
	fixture.cycle.ExercisedNodes = []string{
		fixture.cycle.Deployments[3].NodeID,
	}
	row := &fixture.terminal.Receipts[0]
	runtime := fixture.runtime.Attestations[3]
	row.Transport = TransportDirect
	row.NodeID = runtime.NodeID
	row.ServiceID = runtime.ServiceID
	row.BootID = runtime.BootID
	row.ProcessID = runtime.ProcessID
	row.ProcessStartTicks = runtime.ProcessStartTicks
	row.KeyID = "terminal-exit"
	row.Authenticated = 0
	row.Redeemed = 0
	row.Opened = 1
	row.Closed = 1
	fixture.lease.Commit.TokenClasses = nil
	fixture.seal()
	if _, err := ValidateBundle(
		fixture.directory, fixture.trustPath, fixture.topologyPath,
	); err != nil {
		t.Fatalf("Direct AWG receipt rejected: %v", err)
	}
}

func FuzzInspectJSONRejectsDuplicateNames(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = inspectJSON(data)
	})
}

func newCycleFixture(t *testing.T) *cycleFixture {
	t.Helper()
	fixture := &cycleFixture{
		t:            t,
		directory:    filepath.Join(t.TempDir(), "evidence"),
		trustPath:    filepath.Join(t.TempDir(), "accepted-trust.json"),
		topologyPath: "/accepted/e0",
		private:      make(map[string]ed25519.PrivateKey),
	}
	if err := os.Mkdir(fixture.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := []TrustKey{
		fixture.newKey("controller", KeyRoleController, ""),
		fixture.newKey("runtime-control", KeyRoleRuntime, "node-control"),
		fixture.newKey(
			"runtime-entry-primary", KeyRoleRuntime, "node-entry-primary",
		),
		fixture.newKey(
			"runtime-entry-secondary", KeyRoleRuntime, "node-entry-secondary",
		),
		fixture.newKey("runtime-exit", KeyRoleRuntime, "node-exit"),
		fixture.newKey("lease", KeyRoleLease, ""),
		fixture.newKey(
			"terminal-entry-primary", KeyRoleTerminal, "node-entry-primary",
		),
		fixture.newKey("terminal-exit", KeyRoleTerminal, "node-exit"),
	}
	fixture.trust = TrustBundle{
		Schema: TrustSchema, AcceptanceID: "accepted-e1-root",
		AcceptedAt: "2030-01-01T10:00:00Z",
		ExpiresAt:  "2030-01-01T11:00:00Z",
		Keys:       keys,
	}
	writeCanonical(t, fixture.trustPath, fixture.trust)
	trustBytes, err := os.ReadFile(fixture.trustPath)
	if err != nil {
		t.Fatal(err)
	}
	trustDigest := sha256.Sum256(trustBytes)
	fixture.cycle = Cycle{
		Schema: CycleSchema, CycleID: "cycle-0001",
		AttemptID: "attempt-0001", TopologyID: "external-topology-0001",
		DescriptorSHA256: strings.Repeat("1", 64),
		BundleSHA256:     strings.Repeat("2", 64),
		TrustSHA256:      hex.EncodeToString(trustDigest[:]),
		Nonce:            strings.Repeat("a", 32),
		AcceptedAt:       "2030-01-01T10:01:00Z",
		CounterDomain:    "host-counter-domain-1",
		AcceptedCounter:  100, ExpectedTransport: TransportH3,
		ExercisedNodes: []string{"node-entry-primary"},
		Deployments: []DeploymentBinding{
			{
				Role:         RoleControl,
				InstanceUUID: "00000000-0000-4000-8000-000000000001",
				NodeID:       "node-control", ServiceID: "service-control",
				Provider: "provider-a", OperatorID: "operator-a",
			},
			{
				Role:         RoleEntryPrimary,
				InstanceUUID: "00000000-0000-4000-8000-000000000002",
				NodeID:       "node-entry-primary",
				ServiceID:    "service-entry-primary",
				Provider:     "provider-b", OperatorID: "operator-b",
			},
			{
				Role:         RoleEntrySecondary,
				InstanceUUID: "00000000-0000-4000-8000-000000000003",
				NodeID:       "node-entry-secondary",
				ServiceID:    "service-entry-secondary",
				Provider:     "provider-c", OperatorID: "operator-c",
			},
			{
				Role:         RoleExit,
				InstanceUUID: "00000000-0000-4000-8000-000000000004",
				NodeID:       "node-exit", ServiceID: "service-exit",
				Provider: "provider-d", OperatorID: "operator-d",
			},
		},
		ControllerKeyID: "controller",
	}
	acceptedCycle := fixture.cycle
	acceptedCycle.Deployments = append(
		[]DeploymentBinding(nil), fixture.cycle.Deployments...,
	)
	acceptedDescriptor := realtopology.Descriptor{
		Schema:     realtopology.Schema,
		TopologyID: acceptedCycle.TopologyID,
		Protocol:   realtopology.ProtocolVersion,
		Deployments: make(
			[]realtopology.Deployment, len(acceptedCycle.Deployments),
		),
	}
	for index, row := range acceptedCycle.Deployments {
		acceptedDescriptor.Deployments[index] = realtopology.Deployment{
			Role: row.Role, InstanceUUID: row.InstanceUUID,
			NodeID: row.NodeID, ServiceID: row.ServiceID,
			Provider: row.Provider, OperatorID: row.OperatorID,
		}
	}
	originalLoader := loadE0Bundle
	loadE0Bundle = func(path string) (e0Snapshot, error) {
		if path != fixture.topologyPath {
			t.Fatalf("unexpected E0 path %q", path)
		}
		return e0Snapshot{
			result: realtopology.Result{
				TopologyID:       acceptedCycle.TopologyID,
				DescriptorSHA256: acceptedCycle.DescriptorSHA256,
				BundleSHA256:     acceptedCycle.BundleSHA256,
				PublicFileCount:  len(realtopology.AllowedPublicBasenames),
			},
			descriptor: acceptedDescriptor,
		}, nil
	}
	t.Cleanup(func() {
		loadE0Bundle = originalLoader
	})
	fixture.runtime = RuntimeSet{
		Schema: RuntimeSetSchema, ControllerKeyID: "controller",
	}
	for index, deployment := range fixture.cycle.Deployments {
		fixture.runtime.Attestations = append(
			fixture.runtime.Attestations,
			RuntimeAttestation{
				Schema: RuntimeSchema, Role: deployment.Role,
				InstanceUUID: deployment.InstanceUUID,
				NodeID:       deployment.NodeID, ServiceID: deployment.ServiceID,
				Provider: deployment.Provider, OperatorID: deployment.OperatorID,
				BootID: "10000000-0000-4000-8000-00000000000" +
					string(rune('1'+index)),
				ProcessID:         uint64(2000 + index),
				ProcessStartTicks: uint64(3000 + index),
				ExecutableSHA256: strings.Repeat(
					string(rune('3'+index)), 64,
				),
				ConfigSHA256: strings.Repeat(
					[]string{"7", "8", "9", "a"}[index], 64,
				),
				CertificateSHA256: strings.Repeat(
					string(rune('b'+index)), 64,
				),
				Endpoint: "203.0.113." + string(rune('1'+index)) + ":443",
				Status:   "running", ObservedAt: "2030-01-01T10:02:00Z",
				CounterDomain:   fixture.cycle.CounterDomain,
				ObservedCounter: uint64(110 + index),
				KeyID:           runtimeKeyForRole(deployment.Role),
			},
		)
	}
	fixture.lease = LeaseEvidence{
		Commit: LeaseCommit{
			Schema: LeaseSchema, LeaseID: "lease-0001",
			ReservationID: "reservation-0001",
			AttemptID:     fixture.cycle.AttemptID, State: "committed",
			PreparedAt:      "2030-01-01T10:03:00Z",
			CounterDomain:   fixture.cycle.CounterDomain,
			PreparedCounter: 120,
			CommittedAt:     "2030-01-01T10:04:00Z", CommittedCounter: 121,
			ExpiresAt:     "2030-01-01T10:50:00Z",
			PSKGeneration: 7, PSKKeyID: "psk-generation-7",
			PeerPublicKey: base64.StdEncoding.EncodeToString(
				make([]byte, 32),
			),
			VaultRevisionBefore: 10, VaultRevisionAfter: 11,
			TokenClasses: []TokenClassCommitment{{
				CandidateID: "h3-primary", NodeID: "node-entry-primary",
				ServiceID: "service-entry-primary", Transport: TransportH3,
				TokenKeyID: "token-key-1", Scope: "carrier",
				IssuerDomain: "issuer.example", Count: 3,
				ConsumedCount: 1,
				CommitmentSHA: strings.Repeat("d", 64),
			}},
			PublisherKeyID: "lease",
		},
		Terminal: LeaseTerminal{
			Schema: LeaseEndSchema, LeaseID: "lease-0001",
			AttemptID: fixture.cycle.AttemptID, Disposition: "consumed",
			TerminalAt:      "2030-01-01T10:08:00Z",
			CounterDomain:   fixture.cycle.CounterDomain,
			TerminalCounter: 150,
			VaultRevision:   12, PublisherKeyID: "lease",
		},
	}
	fixture.terminal = TerminalSet{
		Schema: TerminalSetSchema, ControllerKeyID: "controller",
		Receipts: []TerminalReceipt{{
			Schema: TerminalSchema, AttemptID: fixture.cycle.AttemptID,
			Transport: TransportH3, NodeID: "node-entry-primary",
			ServiceID:         "service-entry-primary",
			BootID:            fixture.runtime.Attestations[1].BootID,
			ProcessID:         fixture.runtime.Attestations[1].ProcessID,
			ProcessStartTicks: fixture.runtime.Attestations[1].ProcessStartTicks,
			CorrelationID:     strings.Repeat("e", 32),
			Outcome:           "success", Reason: "none",
			Authenticated: 1, Redeemed: 1, Opened: 1, Closed: 1,
			ObservedAt:      "2030-01-01T10:07:00Z",
			CounterDomain:   fixture.cycle.CounterDomain,
			ObservedCounter: 140, KeyID: "terminal-entry-primary",
		}},
	}
	fixture.seal()
	return fixture
}

func (f *cycleFixture) newKey(
	id, role, node string,
) TrustKey {
	f.t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	f.private[id] = private
	return TrustKey{
		KeyID: id, Role: role, NodeID: node,
		PublicKey: base64.StdEncoding.EncodeToString(public),
	}
}

func (f *cycleFixture) writeTrustAndReseal() {
	f.t.Helper()
	writeCanonical(f.t, f.trustPath, f.trust)
	data, err := os.ReadFile(f.trustPath)
	if err != nil {
		f.t.Fatal(err)
	}
	f.cycle.TrustSHA256 = shaHex(data)
	f.seal()
}

func (f *cycleFixture) seal() {
	f.t.Helper()
	binding, err := digestObject(cycleBindingDomain, cycleCoreOf(f.cycle))
	if err != nil {
		f.t.Fatal(err)
	}
	f.cycle.BindingDigest = binding

	f.runtime.CycleBindingDigest = binding
	runtimeDigests := make([]string, len(f.runtime.Attestations))
	for index := range f.runtime.Attestations {
		row := &f.runtime.Attestations[index]
		row.CycleBindingDigest = binding
		row.Signature = f.sign(
			row.KeyID, runtimeSignatureDomain, runtimeUnsignedOf(*row),
		)
		runtimeDigests[index], err = digestObject(runtimeObjectDomain, *row)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	f.runtime.CollectionDigest, err = digestObject(
		runtimeCollectionDomain, runtimeDigests,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.runtime.Signature = f.sign(
		f.runtime.ControllerKeyID,
		runtimeSetSignatureDomain,
		runtimeSetUnsigned{
			Schema:             f.runtime.Schema,
			CycleBindingDigest: f.runtime.CycleBindingDigest,
			Attestations:       f.runtime.Attestations,
			CollectionDigest:   f.runtime.CollectionDigest,
			ControllerKeyID:    f.runtime.ControllerKeyID,
		},
	)

	commit := &f.lease.Commit
	commit.CycleBindingDigest = binding
	commit.RuntimeCollectionDigest = f.runtime.CollectionDigest
	commit.Signature = f.sign(
		commit.PublisherKeyID,
		leaseCommitSignatureDomain,
		leaseCommitUnsignedOf(*commit),
	)
	commitDigest, err := digestObject(leaseCommitObjectDomain, *commit)
	if err != nil {
		f.t.Fatal(err)
	}
	leaseTerminal := &f.lease.Terminal
	leaseTerminal.CycleBindingDigest = binding
	leaseTerminal.LeaseObjectDigest = commitDigest
	leaseTerminal.Signature = f.sign(
		leaseTerminal.PublisherKeyID,
		leaseTerminalSignatureDomain,
		leaseTerminalUnsignedOf(*leaseTerminal),
	)

	f.terminal.CycleBindingDigest = binding
	terminalDigests := make([]string, len(f.terminal.Receipts))
	for index := range f.terminal.Receipts {
		row := &f.terminal.Receipts[index]
		row.CycleBindingDigest = binding
		row.RuntimeCollectionDigest = f.runtime.CollectionDigest
		row.LeaseObjectDigest = commitDigest
		for runtimeIndex := range f.runtime.Attestations {
			runtime := f.runtime.Attestations[runtimeIndex]
			if runtime.NodeID == row.NodeID {
				row.RuntimeAttestationDigest =
					runtimeDigests[runtimeIndex]
			}
		}
		row.Signature = f.sign(
			row.KeyID, terminalSignatureDomain, terminalUnsignedOf(*row),
		)
		terminalDigests[index], err = digestObject(
			terminalObjectDomain, *row,
		)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	f.terminal.CollectionDigest, err = digestObject(
		terminalCollectionDomain, terminalDigests,
	)
	if err != nil {
		f.t.Fatal(err)
	}
	f.terminal.Signature = f.sign(
		f.terminal.ControllerKeyID,
		terminalSetSignatureDomain,
		terminalSetUnsigned{
			Schema:             f.terminal.Schema,
			CycleBindingDigest: f.terminal.CycleBindingDigest,
			Receipts:           f.terminal.Receipts,
			CollectionDigest:   f.terminal.CollectionDigest,
			ControllerKeyID:    f.terminal.ControllerKeyID,
		},
	)

	runtimeBytes := mustCanonical(f.t, f.runtime)
	leaseBytes := mustCanonical(f.t, f.lease)
	terminalBytes := mustCanonical(f.t, f.terminal)
	f.cycle.RuntimeSHA256 = shaHex(runtimeBytes)
	f.cycle.LeaseSHA256 = shaHex(leaseBytes)
	f.cycle.TerminalSHA256 = shaHex(terminalBytes)
	f.cycle.Signature = f.sign(
		f.cycle.ControllerKeyID,
		cycleSignatureDomain,
		cycleUnsigned{
			Schema: f.cycle.Schema, CycleID: f.cycle.CycleID,
			AttemptID: f.cycle.AttemptID, TopologyID: f.cycle.TopologyID,
			DescriptorSHA256: f.cycle.DescriptorSHA256,
			BundleSHA256:     f.cycle.BundleSHA256,
			TrustSHA256:      f.cycle.TrustSHA256, Nonce: f.cycle.Nonce,
			AcceptedAt:        f.cycle.AcceptedAt,
			CounterDomain:     f.cycle.CounterDomain,
			AcceptedCounter:   f.cycle.AcceptedCounter,
			ExpectedTransport: f.cycle.ExpectedTransport,
			ExercisedNodes:    f.cycle.ExercisedNodes,
			Deployments:       f.cycle.Deployments,
			BindingDigest:     f.cycle.BindingDigest,
			RuntimeSHA256:     f.cycle.RuntimeSHA256,
			LeaseSHA256:       f.cycle.LeaseSHA256,
			TerminalSHA256:    f.cycle.TerminalSHA256,
			ControllerKeyID:   f.cycle.ControllerKeyID,
		},
	)
	writePrivate(
		f.t, filepath.Join(f.directory, RuntimeFile), runtimeBytes,
	)
	writePrivate(f.t, filepath.Join(f.directory, LeaseFile), leaseBytes)
	writePrivate(
		f.t, filepath.Join(f.directory, TerminalFile), terminalBytes,
	)
	writeCanonical(
		f.t, filepath.Join(f.directory, CycleFile), f.cycle,
	)
}

func (f *cycleFixture) sign(
	keyID, domain string, value any,
) string {
	f.t.Helper()
	private, ok := f.private[keyID]
	if !ok {
		f.t.Fatalf("missing private key %q", keyID)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	message := append(append([]byte(domain), 0), encoded...)
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(private, message),
	)
}

func runtimeKeyForRole(role string) string {
	return "runtime-" + role
}

func mustCanonical(t *testing.T, value any) []byte {
	t.Helper()
	data, err := marshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeCanonical(t *testing.T, path string, value any) {
	t.Helper()
	writePrivate(t, path, mustCanonical(t, value))
}

func writePrivate(t *testing.T, path string, data []byte) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func shaHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
