// Package producersnapshot computes the canonical digest that freezes exactly
// which producer files a controller transition acts on.
//
// WHY THIS IS A SHARED PACKAGE.
//
// The controller signs this digest into CONTROLLER_START, and the formal
// verifier has to recompute it to decide whether that signed record describes
// the matrix actually in front of an auditor. Two independent implementations
// of one digest algorithm do not stay identical: the moment they drift, either
// the verifier rejects honest evidence or — far worse — it accepts a record
// computed under different rules and reports the disagreement as agreement.
//
// So there is one implementation, imported by both. A change to the algorithm
// changes what the controller signs and what the verifier expects in the same
// commit, which is the only way the two can be guaranteed to agree.
//
// WHAT THE DIGEST COVERS.
//
// Every file that can change the outcome of a transition: the frozen matrix
// parameters, the producer's completion marker, the schedule, the execution
// inventory, every batch record, every producer archive, and — for each
// evidence directory — the manifest, every path and digest that manifest
// lists, and the directory structure itself. Files the controller adds later
// (the audit checkpoint and its log) are excluded, so the digest is identical
// before the first close and on every later resume.
//
// Every read is hardened: single descriptor, re-stat, os.SameFile, bounded, and
// re-stat again. This function's whole job is to notice substitution, so a
// stat-then-open race here would defeat the thing it exists for.
package producersnapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// controllerAddedEvidenceFiles are the only files the controller itself may add
// inside a producer evidence directory. They are excluded from the snapshot and
// permitted by the exact-set check, so the digest is identical before the first
// close and on every later resume.
var controllerAddedEvidenceFiles = map[string]struct{}{
	// Restated rather than imported: this package must not depend on the
	// checkpoint package, and a change to either name has to be a deliberate
	// edit in both rather than a silent inheritance.
	"audit-checkpoint.json": {},
	"audit-checkpoint.log":  {},
}

const (
	// Explicit bounds on every dimension of the snapshot input. Each of these
	// is individually satisfiable by an input that is unbounded in some other
	// dimension, which is why all four exist: a small manifest can list a
	// hundred thousand members, a short member list can name enormous files,
	// and many modest files can sum to something no controller should read.
	maximumSnapshotMember  = 512 << 20
	maximumManifestBytes   = 8 << 20
	maximumManifestMembers = 100_000
	maximumSnapshotTotal   = 8 << 30
	maximumEvidenceEntries = 200_000
)

// producerSnapshotDigest freezes the exact producer inputs this transition will
// act on.
//
// WHY THE SIGNATURE ALONE IS NOT ENOUGH.
//
// CONTROLLER_START proves who owns the transition. It does not, by itself,
// prove WHAT the transition was started over. A crash after the record is
// published and before the first anchor leaves a root with a valid signature
// and no anchors — and at that moment there is nothing else to cross-check
// against, because the anchor chain that would later expose drift does not
// exist yet. A resume would proceed under the old, genuine signature while
// reading modified producer files.
//
// WHY HASHING THE MANIFEST IS NOT ENOUGH EITHER.
//
// An earlier version bound each evidence manifest file and the audit log. That
// leaves the manifest's MEMBERS unbound: result.txt, attempts.jsonl,
// environment.txt, qdisc captures, binary inventories. Change any of those
// while the manifest file and audit log stay byte-identical and the snapshot
// still matched — and the close step then rebuilds a base manifest over the
// changed bytes, producing a closed artifact that verifies internally and
// describes evidence nobody approved.
//
// So the snapshot binds every manifest-listed path AND its digest, and requires
// the evidence directory to contain exactly that set plus the enumerated files
// the controller itself adds. A file added, removed, or swapped is a mismatch.
//
// Every read here is Lstat -> open -> fstat -> SameFile -> bounded read ->
// re-stat. A plain hash of a path after a separate Lstat is the TOCTOU pattern
// this codebase rejects elsewhere, and it would be worse here than anywhere:
// this function's entire job is to notice substitution.
// canonicalLabel joins path components for the SIGNED digest input.
//
// This is path.Join, never filepath.Join, and the difference is the whole
// reason the helper exists. filepath.Join uses the HOST's separator, so the
// same evidence tree would hash to one value on Linux and macOS and a different
// value on Windows — for a digest that is cryptographically signed and is
// supposed to be independently re-verifiable by any third party on any
// platform. Root relocatability and cross-OS verification both depend on the
// label being a protocol string rather than a local pathname.
//
// Filesystem ACCESS keeps filepath.Join, which correctly needs native
// separators. The two concerns share a similar-looking API and must not be
// conflated: one produces a value that gets signed, the other opens a file.
func canonicalLabel(elements ...string) string {
	return path.Join(elements...)
}

// Digest computes the canonical producer snapshot for one matrix root.
func Digest(matrixRoot string) (string, error) {
	var members []string
	total := &snapshotBudget{}
	add := func(label, path string) error {
		digest, err := hashRegularSafely(path, total)
		if err != nil {
			return fmt.Errorf("producer snapshot: %s: %w", label, err)
		}
		members = append(members, label+"\t"+digest)
		return nil
	}

	for _, relative := range []string{
		"matrix.env",
		producerMarker,
		"schedule.tsv",
		// Mandatory for a full deferred run. Every batch record claims to be
		// pinned to it, so a root that has none has claims nothing anchors.
		"execution-inventory.sha256",
	} {
		if err := add(relative, filepath.Join(matrixRoot, relative)); err != nil {
			return "", err
		}
	}

	batchDirectory := filepath.Join(matrixRoot, "batches")
	entries, err := os.ReadDir(batchDirectory)
	if err != nil {
		return "", err
	}
	var evidenceNames []string
	var archivePaths []string
	var archiveLabels []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() ||
			!strings.HasSuffix(entry.Name(), pendingSuffix) {
			continue
		}
		// The label is a canonical protocol path; the second argument is the
		// native path the file is actually opened through.
		relative := canonicalLabel("batches", entry.Name())
		if err := add(relative, filepath.Join(matrixRoot, relative)); err != nil {
			return "", err
		}
		values, err := readKeyValues(filepath.Join(batchDirectory, entry.Name()))
		if err != nil {
			return "", err
		}
		archiveRelative := values["archive_relative"]
		// The same confinement rule the batch loader applies, from the same
		// helper. The snapshot runs first, so a weaker check here would decide
		// the outcome and the stronger one downstream would never be reached —
		// which is how the substring test for ".." ended up being the effective
		// rule despite a better one existing.
		if err := requireEvidenceRelative(archiveRelative); err != nil {
			return "", fmt.Errorf(
				"producer snapshot: %s names an unusable producer archive "+
					"%q: %w", entry.Name(), archiveRelative, err,
			)
		}
		evidenceNames = append(
			evidenceNames, strings.TrimSuffix(archiveRelative, pendingArchive),
		)
		archivePaths = append(
			archivePaths, filepath.Join(matrixRoot, archiveRelative),
		)
		archiveLabels = append(archiveLabels, archiveRelative)
	}
	if len(evidenceNames) == 0 {
		return "", errors.New("producer snapshot: no producer batch records")
	}

	for index, evidenceRelative := range evidenceNames {
		evidenceMembers, listed, directories, err := snapshotEvidenceDirectory(
			matrixRoot, evidenceRelative, total,
		)
		if err != nil {
			return "", err
		}
		members = append(members, evidenceMembers...)
		// The second independent view, and the archive's digest, from one
		// descriptor. Both artifacts are bound; this is what proves they
		// describe the same evidence rather than merely travelling together.
		archiveDigest, err := verifyPendingArchiveMatchesTree(
			archivePaths[index],
			filepath.Base(evidenceRelative),
			listed,
			directories,
		)
		if err != nil {
			return "", fmt.Errorf(
				"producer snapshot: %s: %w", evidenceRelative, err,
			)
		}
		members = append(members, archiveLabels[index]+"\t"+archiveDigest)
	}
	sort.Strings(members)
	return sha256OfBytes([]byte(strings.Join(members, "\n") + "\n")), nil
}

// snapshotEvidenceDirectory binds one evidence directory: its manifest, every
// path and digest the manifest lists, and the requirement that the directory
// hold exactly those files plus the controller's own additions.
func snapshotEvidenceDirectory(
	matrixRoot string,
	evidenceRelative string,
	total *snapshotBudget,
) ([]string, map[string]string, map[string]struct{}, error) {
	directory := filepath.Join(matrixRoot, evidenceRelative)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, nil, fmt.Errorf(
			"producer snapshot: %s is not a real evidence directory",
			evidenceRelative,
		)
	}
	// One descriptor for both the digest and the bytes. Hashing a path and then
	// re-reading it leaves an interval in which the file can be swapped, so the
	// manifest that was measured and the manifest that was parsed would be two
	// different documents — and the parse is what decides which members get
	// bound at all.
	manifestPath := filepath.Join(directory, manifestName)
	content, manifestDigest, err := readAndHashRegular(
		manifestPath, maximumManifestBytes, total,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("producer snapshot: %s: %w", evidenceRelative, err)
	}
	members := []string{
		canonicalLabel(evidenceRelative, manifestName) + "\t" + manifestDigest,
	}
	// The manifest is part of the tree even though it does not list itself, so
	// the archive comparison expects it. Controller-added files are absent from
	// this set by construction: the producer built its archive before any of
	// them existed, and a resume must not read their presence as drift.
	listed := map[string]string{manifestName: manifestDigest}
	// Manifest member names come from a file, so they are untrusted input.
	// Validating their shape is necessary but not sufficient; opening them
	// through an os.Root anchored at the evidence directory is what makes
	// escape impossible rather than merely unlikely, because the kernel-level
	// confinement holds even for a name that passes every string check and for
	// a symlink swapped in after the check.
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, nil, nil, err
	}
	defer root.Close()
	for _, line := range strings.Split(
		strings.TrimSuffix(string(content), "\n"), "\n",
	) {
		if line == "" {
			continue
		}
		recorded, listedPath, ok := strings.Cut(line, "  ")
		if !ok || !lowerHex(recorded) {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s has an invalid manifest line",
				evidenceRelative,
			)
		}
		name := strings.TrimPrefix(listedPath, "./")
		// path, not filepath: manifest member names are canonical
		// slash-separated protocol values, and they become digest labels. A
		// filepath-based canonicality check would reject "diagnostics/x.txt"
		// on Windows while accepting it everywhere else.
		if name == "" || path.IsAbs(name) ||
			path.Clean(name) != name || strings.HasPrefix(name, "..") {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s lists an unsafe member %q",
				evidenceRelative, name,
			)
		}
		if _, duplicate := listed[name]; duplicate {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s lists %q twice", evidenceRelative, name,
			)
		}
		_ = recorded
		// The member's own bytes, hashed here rather than believed from the
		// manifest. Binding the manifest's claim about a file is not binding
		// the file.
		// Checked BEFORE the insertion below. Checking afterwards lets the
		// (max+1)th member through and only then complains, so the effective
		// limit is one higher than the stated one.
		if len(listed) >= maximumManifestMembers {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s lists more than %d members",
				evidenceRelative, maximumManifestMembers-1,
			)
		}
		digest, err := hashRegularInRoot(root, name, total)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s/%s: %w", evidenceRelative, name, err,
			)
		}
		// The manifest's own claim about this member, checked against the
		// bytes. Binding the manifest digest and the member digest separately
		// still lets a signed start bless a manifest that disagrees with its
		// own directory; the close step would then rebuild a DIFFERENT manifest
		// and every later check would compare against that one instead.
		if recorded != digest {
			return nil, nil, nil, fmt.Errorf(
				"producer snapshot: %s/%s hashes to %s, its own manifest "+
					"records %s; the producer manifest is internally "+
					"inconsistent and must not be signed over",
				evidenceRelative, name, digest, recorded,
			)
		}
		listed[name] = digest
		members = append(members,
			canonicalLabel(evidenceRelative, name)+"\t"+digest)
	}
	if len(listed) == 0 {
		return nil, nil, nil, fmt.Errorf(
			"producer snapshot: %s has an empty manifest", evidenceRelative,
		)
	}

	// Exactly the listed set, plus the controller's own additions. An unlisted
	// file is either something the producer did not seal or something added
	// afterwards, and both make the manifest a description of a different
	// directory than the one on disk.
	var structure []string
	directories := make(map[string]struct{})
	entriesSeen := 0
	if err := fs.WalkDir(
		os.DirFS(directory), ".",
		func(walked string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			entriesSeen++
			if entriesSeen > maximumEvidenceEntries {
				return fmt.Errorf(
					"producer snapshot: %s holds implausibly many entries",
					evidenceRelative,
				)
			}
			if walked == "." {
				return nil
			}
			if entry.IsDir() {
				// Directories are bound too. The closed archive carries
				// explicit directory entries, so an added empty subdirectory
				// changes the published artifact; a snapshot that ignored
				// structure would let that through unremarked.
				structure = append(structure,
					canonicalLabel(evidenceRelative, walked)+"\td")
				directories[walked] = struct{}{}
				return nil
			}
			if !entry.Type().IsRegular() {
				return fmt.Errorf(
					"producer snapshot: %s/%s is not a regular file",
					evidenceRelative, walked,
				)
			}
			if walked == manifestName {
				return nil
			}
			if _, ok := listed[walked]; ok {
				return nil
			}
			if _, ok := controllerAddedEvidenceFiles[walked]; ok {
				return nil
			}
			return fmt.Errorf(
				"producer snapshot: %s/%s is present but not listed in the "+
					"evidence manifest", evidenceRelative, walked,
			)
		},
	); err != nil {
		return nil, nil, nil, err
	}
	return append(members, structure...), listed, directories, nil
}

// readAndHashRegular returns a file's bytes and their digest from a single
// hardened descriptor, so the bytes that were hashed are exactly the bytes the
// caller goes on to parse.
// ReadRegular is the hardened single-descriptor bounded read this package uses
// everywhere, exported so callers verifying signed records hold their own reads
// to the same standard rather than reimplementing a looser one.
func ReadRegular(
	path string, maximum int64, total *Budget,
) ([]byte, string, error) {
	return readAndHashRegular(path, maximum, total)
}

// Budget caps the cumulative bytes one operation may read.
type Budget = snapshotBudget

// MaximumRecordBytes is the bound this package applies to the small key/value
// and JSON records that describe a matrix.
const MaximumRecordBytes = maximumManifestBytes

// MaximumSnapshotMember is the per-file bound for evidence members.
const MaximumSnapshotMember = maximumSnapshotMember

// MaximumManifestMembers bounds how many members one evidence manifest may
// list.
const MaximumManifestMembers = maximumManifestMembers

// MaximumSnapshotTotal bounds the cumulative bytes one snapshot may read.
const MaximumSnapshotTotal = maximumSnapshotTotal

// NewBudget returns a budget already charged the given number of bytes, so a
// caller can exercise the cumulative bound.
func NewBudget(consumed int64) *Budget {
	return &Budget{consumed: consumed}
}

// RequireEvidenceRelative enforces that a recorded archive path is canonical
// and strictly inside the matrix's evidence directory.
func RequireEvidenceRelative(recorded string) error {
	return requireEvidenceRelative(recorded)
}

func readAndHashRegular(
	path string, maximum int64, total *snapshotBudget,
) ([]byte, string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("is a symbolic link")
	}
	if !before.Mode().IsRegular() {
		return nil, "", errors.New("is not a regular file")
	}
	if before.Size() > maximum {
		return nil, "", fmt.Errorf(
			"is %d bytes, over the %d-byte limit", before.Size(), maximum,
		)
	}
	file, err := os.Open(path) // #nosec G304 -- inspected immediately above
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, "", errors.New("changed between inspection and open")
	}
	limited := &io.LimitedReader{R: file, N: opened.Size() + 1}
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, "", err
	}
	if int64(len(content)) != opened.Size() {
		return nil, "", fmt.Errorf(
			"changed while it was read: %d bytes were read, it was %d when it "+
				"was measured", len(content), opened.Size(),
		)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) {
		return nil, "", errors.New("was mutated while it was read")
	}
	if err := total.spend(int64(len(content))); err != nil {
		return nil, "", err
	}
	return content, sha256OfBytes(content), nil
}

// hashRegularInRoot is hashRegularSafely for a member named by untrusted input.
// The os.Root confines every resolution to the evidence directory, so a name
// that escapes — or a symlink planted at one — fails at the open rather than
// reaching outside.
func hashRegularInRoot(
	root *os.Root, name string, total *snapshotBudget,
) (string, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("is a symbolic link")
	}
	if !before.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	if before.Size() > maximumSnapshotMember {
		return "", fmt.Errorf(
			"is %d bytes, over the %d-byte limit",
			before.Size(), maximumSnapshotMember,
		)
	}
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashOpenFile(file, before, total)
}

// hashRegularSafely hashes a file and proves the bytes it hashed came from the
// file it inspected.
//
// Lstat decides the file is a plain regular file of a bounded size; the
// descriptor is then opened and re-stat'd and compared with os.SameFile, so a
// name swapped between the two — for a symlink, or for another regular file —
// is caught. The read is bounded to one byte past the declared size, so a file
// that grew is a rejection rather than a truncation, and the descriptor is
// stat'd once more afterwards so a same-size in-place mutation during the read
// is caught too.
func hashRegularSafely(path string, total *snapshotBudget) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("is a symbolic link")
	}
	if !before.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	if before.Size() > maximumSnapshotMember {
		return "", fmt.Errorf(
			"is %d bytes, over the %d-byte limit",
			before.Size(), maximumSnapshotMember,
		)
	}
	file, err := os.Open(path) // #nosec G304 -- inspected immediately above
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashOpenFile(file, before, total)
}

// snapshotBudget caps the cumulative bytes one snapshot may read. Per-file
// limits alone do not bound the work: many files individually within the limit
// sum to something unbounded.
type snapshotBudget struct {
	consumed int64
}

func (b *snapshotBudget) spend(size int64) error {
	if b == nil {
		return nil
	}
	b.consumed += size
	if b.consumed > maximumSnapshotTotal {
		return fmt.Errorf(
			"the producer snapshot exceeds the %d-byte cumulative limit",
			// int64: the untyped constant is 8 GiB, which does not fit in an
			// int on a 32-bit target.
			int64(maximumSnapshotTotal),
		)
	}
	return nil
}

// hashOpenFile does the bounded, re-verified read shared by both hashers.
func hashOpenFile(
	file *os.File, before os.FileInfo, total *snapshotBudget,
) (string, error) {
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", errors.New("changed between inspection and open")
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: file, N: opened.Size() + 1}
	copied, err := io.Copy(hash, limited)
	if err != nil {
		return "", err
	}
	if copied != opened.Size() {
		return "", fmt.Errorf(
			"changed while it was read: %d bytes were read, it was %d when it "+
				"was measured", copied, opened.Size(),
		)
	}
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) {
		return "", errors.New("was mutated while it was read")
	}
	if err := total.spend(copied); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// readKeyValues parses the project's key=value record format under the same
// bound and duplicate-key rule the rest of this package applies.
func readKeyValues(path string) (map[string]string, error) {
	content, _, err := readAndHashRegular(path, maximumManifestBytes, nil)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(
		strings.TrimSuffix(string(content), "\n"), "\n",
	) {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid key/value line in %s", path)
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("duplicate key %q in %s", key, path)
		}
		values[key] = value
	}
	return values, nil
}

// sha256OfBytes is the package's digest helper.
func sha256OfBytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
