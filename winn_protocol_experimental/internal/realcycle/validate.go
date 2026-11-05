package realcycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"

	"winsvpn.local/winnprotocol/internal/realtopology"
)

const (
	cycleBindingDomain   = "winn-real-cycle-binding/v1"
	cycleSignatureDomain = "winn-real-cycle-signature/v1"
	evidenceBundleDomain = "winn-real-cycle-evidence-bundle/v1"
)

type cycleUnsigned struct {
	Schema            string              `json:"schema"`
	CycleID           string              `json:"cycle_id"`
	AttemptID         string              `json:"attempt_id"`
	TopologyID        string              `json:"topology_id"`
	DescriptorSHA256  string              `json:"descriptor_sha256"`
	BundleSHA256      string              `json:"bundle_sha256"`
	TrustSHA256       string              `json:"trust_sha256"`
	Nonce             string              `json:"nonce"`
	AcceptedAt        string              `json:"accepted_at"`
	CounterDomain     string              `json:"counter_domain"`
	AcceptedCounter   uint64              `json:"accepted_counter"`
	ExpectedTransport string              `json:"expected_transport"`
	ExercisedNodes    []string            `json:"exercised_nodes"`
	Deployments       []DeploymentBinding `json:"deployments"`
	BindingDigest     string              `json:"binding_digest"`
	RuntimeSHA256     string              `json:"runtime_sha256"`
	LeaseSHA256       string              `json:"lease_sha256"`
	TerminalSHA256    string              `json:"terminal_sha256"`
	ControllerKeyID   string              `json:"controller_key_id"`
}

type fileSnapshot struct {
	info   os.FileInfo
	sha256 [32]byte
}

type e0Snapshot struct {
	path       string
	root       *os.Root
	directory  os.FileInfo
	entries    []string
	files      map[string]fileSnapshot
	result     realtopology.Result
	descriptor realtopology.Descriptor
}

var loadE0Bundle = consumeE0
var afterE0RootRetained = func() {}

// ValidateBundle validates one exact evidence directory, one separately
// supplied trust file, and the exact E0 topology bundle. It performs no
// network calls and writes no replay state.
func ValidateBundle(
	evidencePath, trustPath, topologyPath string,
) (Result, error) {
	if evidencePath == "" || trustPath == "" || topologyPath == "" {
		return Result{}, errors.New(
			"evidence, trust, and E0 topology paths are required",
		)
	}
	e0, err := loadE0Bundle(topologyPath)
	if err != nil {
		return Result{}, err
	}
	defer e0.close()
	trustBytes, trustSnapshot, err := readStandalone(
		trustPath, MaxTrustFileBytes,
	)
	if err != nil {
		return Result{}, fmt.Errorf("read trust bundle: %w", err)
	}
	trust, keys, err := parseTrust(trustBytes)
	if err != nil {
		return Result{}, err
	}
	trustDigest := sha256.Sum256(trustBytes)
	trustSHA := hex.EncodeToString(trustDigest[:])

	root, initial, err := openEvidenceRoot(evidencePath)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	documents := make(map[string][]byte, len(evidenceFiles))
	snapshots := make(map[string]fileSnapshot, len(evidenceFiles))
	var total int
	for _, name := range evidenceFiles {
		data, snapshot, readErr := readRootFile(
			root, name, MaxEvidenceFileBytes,
		)
		if readErr != nil {
			return Result{}, fmt.Errorf("read %s: %w", name, readErr)
		}
		total += len(data)
		if total > MaxEvidenceBytes {
			return Result{}, errors.New("evidence bundle exceeds aggregate limit")
		}
		documents[name] = data
		snapshots[name] = snapshot
	}

	var cycle Cycle
	if err := decodeCanonical(documents[CycleFile], &cycle); err != nil {
		return Result{}, fmt.Errorf("decode cycle: %w", err)
	}
	var runtime RuntimeSet
	if err := decodeCanonical(documents[RuntimeFile], &runtime); err != nil {
		return Result{}, fmt.Errorf("decode runtime: %w", err)
	}
	var lease LeaseEvidence
	if err := decodeCanonical(documents[LeaseFile], &lease); err != nil {
		return Result{}, fmt.Errorf("decode lease: %w", err)
	}
	var terminal TerminalSet
	if err := decodeCanonical(documents[TerminalFile], &terminal); err != nil {
		return Result{}, fmt.Errorf("decode terminal: %w", err)
	}
	fileSHA := make(map[string]string, len(documents))
	for name, data := range documents {
		digest := sha256.Sum256(data)
		fileSHA[name] = hex.EncodeToString(digest[:])
	}
	acceptedAt, trustExpiry, err := validateCycle(
		cycle, trust, trustSHA, fileSHA, keys,
		e0.result, e0.descriptor,
	)
	if err != nil {
		return Result{}, err
	}
	runtimeResult, err := validateRuntime(
		runtime, cycle, keys, acceptedAt, trustExpiry,
	)
	if err != nil {
		return Result{}, err
	}
	leaseResult, err := validateLease(
		lease, cycle, runtime, runtimeResult,
		keys, acceptedAt, trustExpiry,
	)
	if err != nil {
		return Result{}, err
	}
	if err := validateTerminal(
		terminal, cycle, runtime, runtimeResult, leaseResult, keys,
		acceptedAt, trustExpiry,
	); err != nil {
		return Result{}, err
	}
	if err := recheckEvidenceRoot(
		evidencePath, root, initial, snapshots,
	); err != nil {
		return Result{}, err
	}
	if err := recheckStandalone(trustPath, trustSnapshot); err != nil {
		return Result{}, fmt.Errorf("recheck trust bundle: %w", err)
	}
	if err := e0.recheck(); err != nil {
		return Result{}, fmt.Errorf("recheck E0 topology: %w", err)
	}
	bundleRows := make([]string, 0, len(evidenceFiles))
	for _, name := range evidenceFiles {
		bundleRows = append(bundleRows, name+"\x00"+fileSHA[name])
	}
	bundleDigest, err := digestObject(evidenceBundleDomain, bundleRows)
	if err != nil {
		return Result{}, err
	}
	return Result{
		CycleID: cycle.CycleID, AttemptID: cycle.AttemptID,
		TopologyID: cycle.TopologyID, BindingDigest: cycle.BindingDigest,
		EvidenceBundleSHA256: bundleDigest,
		RuntimeCount:         len(runtime.Attestations),
		TerminalCount:        len(terminal.Receipts),
	}, nil
}

func validateCycle(
	cycle Cycle,
	trust TrustBundle,
	trustSHA string,
	fileSHA map[string]string,
	keys trustIndex,
	e0Result realtopology.Result,
	e0Descriptor realtopology.Descriptor,
) (int64, int64, error) {
	if cycle.Schema != CycleSchema ||
		!validID(cycle.CycleID) || !validID(cycle.AttemptID) ||
		!validID(cycle.TopologyID) ||
		cycle.TopologyID != e0Result.TopologyID ||
		cycle.DescriptorSHA256 != e0Result.DescriptorSHA256 ||
		cycle.BundleSHA256 != e0Result.BundleSHA256 ||
		!validDigest(cycle.DescriptorSHA256) ||
		!validDigest(cycle.BundleSHA256) ||
		cycle.TrustSHA256 != trustSHA || !validNonce(cycle.Nonce) ||
		!validID(cycle.CounterDomain) ||
		cycle.AcceptedCounter == 0 ||
		!slices.Contains(
			[]string{TransportDirect, TransportH3},
			cycle.ExpectedTransport,
		) ||
		len(cycle.Deployments) != len(requiredRoles) ||
		len(cycle.ExercisedNodes) == 0 ||
		len(cycle.ExercisedNodes) > len(requiredRoles) ||
		cycle.RuntimeSHA256 != fileSHA[RuntimeFile] ||
		cycle.LeaseSHA256 != fileSHA[LeaseFile] ||
		cycle.TerminalSHA256 != fileSHA[TerminalFile] {
		return 0, 0, errors.New("cycle fields are invalid")
	}
	accepted, err := parseTime(cycle.AcceptedAt)
	if err != nil {
		return 0, 0, fmt.Errorf("cycle accepted_at: %w", err)
	}
	trustAccepted, _ := parseTime(trust.AcceptedAt)
	trustExpires, _ := parseTime(trust.ExpiresAt)
	if accepted.Before(trustAccepted) || !accepted.Before(trustExpires) {
		return 0, 0, errors.New("cycle time is outside trust interval")
	}
	roleSeen := make(map[string]struct{}, len(cycle.Deployments))
	nodeSeen := make(map[string]struct{}, len(cycle.Deployments))
	globalSeen := make(map[string]struct{}, len(cycle.Deployments)*3)
	for index, row := range cycle.Deployments {
		e0Row := e0Descriptor.Deployments[index]
		if row.Role != requiredRoles[index] ||
			row.Role != e0Row.Role ||
			row.InstanceUUID != e0Row.InstanceUUID ||
			row.NodeID != e0Row.NodeID ||
			row.ServiceID != e0Row.ServiceID ||
			row.Provider != e0Row.Provider ||
			row.OperatorID != e0Row.OperatorID ||
			!uuidPattern.MatchString(row.InstanceUUID) ||
			!validID(row.NodeID) || !validID(row.ServiceID) ||
			!validID(row.Provider) || !validID(row.OperatorID) {
			return 0, 0, fmt.Errorf(
				"cycle deployment %d is invalid", index,
			)
		}
		if _, duplicate := roleSeen[row.Role]; duplicate {
			return 0, 0, errors.New("duplicate deployment role")
		}
		if _, duplicate := nodeSeen[row.NodeID]; duplicate {
			return 0, 0, errors.New("duplicate deployment node")
		}
		for _, value := range []string{
			row.InstanceUUID, row.NodeID, row.ServiceID,
		} {
			if _, duplicate := globalSeen[value]; duplicate {
				return 0, 0, errors.New("deployment identities are not unique")
			}
			globalSeen[value] = struct{}{}
		}
		roleSeen[row.Role] = struct{}{}
		nodeSeen[row.NodeID] = struct{}{}
	}
	exercisedSeen := make(map[string]struct{}, len(cycle.ExercisedNodes))
	for _, node := range cycle.ExercisedNodes {
		if _, exists := nodeSeen[node]; !exists {
			return 0, 0, errors.New("exercised node is absent from E0")
		}
		if _, duplicate := exercisedSeen[node]; duplicate {
			return 0, 0, errors.New("duplicate exercised node")
		}
		exercisedSeen[node] = struct{}{}
	}
	expectedBinding, err := digestObject(
		cycleBindingDomain, cycleCoreOf(cycle),
	)
	if err != nil || expectedBinding != cycle.BindingDigest {
		return 0, 0, errors.New("cycle binding digest mismatch")
	}
	unsigned := cycleUnsigned{
		Schema: cycle.Schema, CycleID: cycle.CycleID,
		AttemptID: cycle.AttemptID, TopologyID: cycle.TopologyID,
		DescriptorSHA256: cycle.DescriptorSHA256,
		BundleSHA256:     cycle.BundleSHA256,
		TrustSHA256:      cycle.TrustSHA256, Nonce: cycle.Nonce,
		AcceptedAt:        cycle.AcceptedAt,
		CounterDomain:     cycle.CounterDomain,
		AcceptedCounter:   cycle.AcceptedCounter,
		ExpectedTransport: cycle.ExpectedTransport,
		ExercisedNodes:    slices.Clone(cycle.ExercisedNodes),
		Deployments:       slices.Clone(cycle.Deployments),
		BindingDigest:     cycle.BindingDigest,
		RuntimeSHA256:     cycle.RuntimeSHA256,
		LeaseSHA256:       cycle.LeaseSHA256,
		TerminalSHA256:    cycle.TerminalSHA256,
		ControllerKeyID:   cycle.ControllerKeyID,
	}
	if err := verifySignature(
		keys, cycle.ControllerKeyID, KeyRoleController, "",
		cycleSignatureDomain, cycle.Signature, unsigned,
	); err != nil {
		return 0, 0, fmt.Errorf("cycle: %w", err)
	}
	return accepted.UnixNano(), trustExpires.UnixNano(), nil
}

func consumeE0(path string) (e0Snapshot, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() ||
		info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return e0Snapshot{}, errors.New("E0 topology directory is unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return e0Snapshot{}, err
	}
	fail := func(cause error) (e0Snapshot, error) {
		_ = root.Close()
		return e0Snapshot{}, cause
	}
	retained, err := root.Stat(".")
	if err != nil || !os.SameFile(info, retained) {
		return fail(errors.New("E0 topology directory identity changed"))
	}
	afterE0RootRetained()
	initial, err := rootEntries(root)
	if err != nil {
		return fail(err)
	}
	result, err := realtopology.ValidateRetainedRoot(root)
	if err != nil {
		return fail(fmt.Errorf("validate accepted E0 bundle: %w", err))
	}
	descriptorBytes, descriptorSnapshot, err := readRootFile(
		root, realtopology.DescriptorName,
		realtopology.MaxDescriptorBytes,
	)
	if err != nil {
		return fail(fmt.Errorf("read accepted E0 descriptor: %w", err))
	}
	digest := sha256.Sum256(descriptorBytes)
	if hex.EncodeToString(digest[:]) != result.DescriptorSHA256 {
		return fail(errors.New("accepted E0 descriptor digest mismatch"))
	}
	decoder := json.NewDecoder(strings.NewReader(string(descriptorBytes)))
	decoder.DisallowUnknownFields()
	var descriptor realtopology.Descriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return fail(fmt.Errorf("decode accepted E0 descriptor: %w", err))
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fail(errors.New("accepted E0 descriptor has trailing data"))
	}
	if descriptor.TopologyID != result.TopologyID ||
		len(descriptor.Deployments) != len(requiredRoles) {
		return fail(errors.New("accepted E0 result and descriptor disagree"))
	}
	files := map[string]fileSnapshot{
		realtopology.DescriptorName: descriptorSnapshot,
	}
	for _, row := range descriptor.Files {
		_, snapshot, readErr := readRootFile(
			root, row.Name, realtopology.MaxPublicFileBytes,
		)
		if readErr != nil {
			return fail(fmt.Errorf(
				"snapshot accepted E0 file %q: %w", row.Name, readErr,
			))
		}
		files[row.Name] = snapshot
	}
	final, err := rootEntries(root)
	if err != nil || !slices.Equal(initial, final) ||
		len(files) != len(initial) {
		return fail(errors.New("accepted E0 directory census changed"))
	}
	return e0Snapshot{
		path: path, root: root, directory: info,
		entries: initial, files: files, result: result,
		descriptor: descriptor,
	}, nil
}

func (snapshot *e0Snapshot) close() {
	if snapshot != nil && snapshot.root != nil {
		_ = snapshot.root.Close()
	}
}

func (snapshot e0Snapshot) recheck() error {
	if snapshot.root == nil {
		// Tests may inject an already accepted in-memory E0 result. Production
		// always uses consumeE0 and therefore always has a retained root.
		return nil
	}
	pathInfo, err := os.Lstat(snapshot.path)
	retained, retainedErr := snapshot.root.Stat(".")
	if err != nil || retainedErr != nil ||
		!sameSnapshot(snapshot.directory, pathInfo) ||
		!os.SameFile(pathInfo, retained) ||
		pathInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("accepted E0 directory changed after validation")
	}
	final, err := rootEntries(snapshot.root)
	if err != nil || !slices.Equal(snapshot.entries, final) {
		return errors.New(
			"accepted E0 directory census changed after validation",
		)
	}
	for _, name := range snapshot.entries {
		expected, ok := snapshot.files[name]
		limit := realtopology.MaxPublicFileBytes
		if name == realtopology.DescriptorName {
			limit = realtopology.MaxDescriptorBytes
		}
		_, current, readErr := readRootFile(
			snapshot.root, name, limit,
		)
		if !ok || readErr != nil ||
			!sameSnapshot(expected.info, current.info) ||
			expected.sha256 != current.sha256 {
			return fmt.Errorf(
				"accepted E0 object %q changed after validation", name,
			)
		}
	}
	return nil
}

func openEvidenceRoot(path string) (*os.Root, []string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect evidence directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, nil, errors.New("evidence directory is unsafe")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	retained, err := root.Stat(".")
	if err != nil || !os.SameFile(info, retained) {
		return nil, nil, closeRootError(
			root, errors.New("evidence directory identity changed"),
		)
	}
	entries, err := rootEntries(root)
	if err != nil {
		return nil, nil, closeRootError(root, err)
	}
	if !slices.Equal(entries, evidenceFiles) {
		return nil, nil, closeRootError(
			root, fmt.Errorf(
				"evidence directory entries %v, want %v", entries, evidenceFiles,
			),
		)
	}
	return root, entries, nil
}

func closeRootError(root *os.Root, err error) error {
	return errors.Join(err, root.Close())
}

func rootEntries(root *os.Root) ([]string, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func readRootFile(
	root *os.Root, name string, limit int,
) ([]byte, fileSnapshot, error) {
	if strings.ContainsAny(name, `/\`) || name == "." {
		return nil, fileSnapshot{}, errors.New("invalid evidence basename")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fileSnapshot{}, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !safeRegular(before) {
		return nil, fileSnapshot{}, errors.New("evidence object is unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, fileSnapshot{},
			errors.New("evidence object exceeds limit or is unreadable")
	}
	after, err := file.Stat()
	pathInfo, pathErr := root.Stat(name)
	if err != nil || pathErr != nil || !os.SameFile(before, after) ||
		!os.SameFile(before, pathInfo) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) {
		return nil, fileSnapshot{},
			errors.New("evidence object identity changed")
	}
	return data, fileSnapshot{
		info: before, sha256: sha256.Sum256(data),
	}, nil
}

func readStandalone(
	path string, limit int,
) ([]byte, fileSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil || !safeRegular(info) {
		return nil, fileSnapshot{}, errors.New("standalone object is unsafe")
	}
	// #nosec G304 -- path is an explicit operator input that was lstat-checked
	// as a single-link regular file and is identity-rechecked after this open.
	file, err := os.Open(path)
	if err != nil {
		return nil, fileSnapshot{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fileSnapshot{},
			errors.New("standalone object identity changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, fileSnapshot{},
			errors.New("standalone object exceeds limit or is unreadable")
	}
	final, err := file.Stat()
	pathFinal, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(info, final) ||
		!os.SameFile(info, pathFinal) || info.Mode() != final.Mode() ||
		info.Size() != final.Size() ||
		!info.ModTime().Equal(final.ModTime()) {
		return nil, fileSnapshot{},
			errors.New("standalone object changed during read")
	}
	return data, fileSnapshot{
		info: info, sha256: sha256.Sum256(data),
	}, nil
}

func recheckEvidenceRoot(
	path string,
	root *os.Root,
	initial []string,
	snapshots map[string]fileSnapshot,
) error {
	pathInfo, err := os.Lstat(path)
	retained, retainedErr := root.Stat(".")
	if err != nil || retainedErr != nil || !pathInfo.IsDir() ||
		pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Mode().Perm()&0o022 != 0 ||
		!os.SameFile(pathInfo, retained) {
		return errors.New("evidence directory changed after validation")
	}
	final, err := rootEntries(root)
	if err != nil || !slices.Equal(initial, final) {
		return errors.New("evidence directory census changed after validation")
	}
	for _, name := range initial {
		snapshot, ok := snapshots[name]
		if !ok {
			return errors.New("evidence snapshot set is incomplete")
		}
		_, current, err := readRootFile(
			root, name, MaxEvidenceFileBytes,
		)
		if err != nil || !sameSnapshot(snapshot.info, current.info) ||
			snapshot.sha256 != current.sha256 {
			return fmt.Errorf(
				"evidence object %q changed after validation", name,
			)
		}
	}
	return nil
}

func recheckStandalone(path string, snapshot fileSnapshot) error {
	_, current, err := readStandalone(path, MaxTrustFileBytes)
	if err != nil || !sameSnapshot(snapshot.info, current.info) ||
		snapshot.sha256 != current.sha256 {
		return errors.New("standalone object changed after validation")
	}
	return nil
}

func sameSnapshot(before, after os.FileInfo) bool {
	return before != nil && after != nil &&
		os.SameFile(before, after) &&
		before.Mode() == after.Mode() &&
		before.Size() == after.Size() &&
		before.ModTime().Equal(after.ModTime()) &&
		linkCount(before) == linkCount(after)
}

func safeRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o022 == 0 && linkCount(info) == 1
}

func linkCount(info os.FileInfo) uint64 {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0
	}
	field := value.FieldByName("Nlink")
	if !field.IsValid() {
		return 0
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return field.Uint()
	default:
		return 0
	}
}

func marshalCanonical(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
