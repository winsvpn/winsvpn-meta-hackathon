package producersnapshot

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

// Producer archive equivalence.
//
// The producer seals two artifacts describing one run: the evidence directory,
// and a .closed-pending.tar.gz built from it. The controller anchors digests
// derived from the DIRECTORY, and the signed start record also binds the
// tarball's digest.
//
// Binding both is not the same as proving they agree. Hashing two values into
// one signed record establishes that these two artifacts were present together;
// it says nothing about whether the tarball is a faithful encoding of the tree.
// Two entirely unrelated files would satisfy it. So the archive is opened and
// compared against the manifest-listed tree, member by member.
//
// Everything below is a rejection rather than a reconciliation. An archive that
// omits a member, adds one, carries different bytes under the same name,
// escapes its root, repeats a path, or hides a link or a device is not a
// different-but-acceptable encoding of the evidence — it is evidence of
// something nobody has explained.

const (
	maximumArchiveMembers    = 200_000
	maximumArchiveTotalBytes = 8 << 30
	maximumArchiveMemberSize = 512 << 20
	// maximumCompressedArchive bounds the file read from disk, and
	// maximumArchiveTotalBytes bounds what it expands to. Both are needed: a
	// small compressed file can expand without limit.
	maximumCompressedArchive = 2 << 30
)

// archiveLimits are the four independent bounds on one producer archive.
//
// They are a parameter rather than four constants read directly, so tests can
// drive the identical code path at a scale that runs in milliseconds. Proving a
// limiter works should not require logically expanding eight gigabytes on every
// suite run — and a test that takes half a minute is a test people start
// skipping, which is how an untested bound becomes an unnoticed broken one.
//
// Each bound is separate because each is independently reachable: a small file
// can expand without limit, a bounded expansion can still contain a single
// enormous member, and a bounded member size still permits unbounded member
// counts.
type archiveLimits struct {
	// compressedBytes bounds the file as it sits on disk.
	compressedBytes int64
	// totalBytes bounds what the whole archive expands to.
	totalBytes int64
	// memberBytes bounds any single member.
	memberBytes int64
	// members bounds how many entries the archive may contain.
	members int
}

// productionArchiveLimits are the bounds real evidence is held to.
func productionArchiveLimits() archiveLimits {
	return archiveLimits{
		compressedBytes: maximumCompressedArchive,
		totalBytes:      maximumArchiveTotalBytes,
		memberBytes:     maximumArchiveMemberSize,
		members:         maximumArchiveMembers,
	}
}

// errArchiveExpansionLimit reports that an archive expanded past its bound.
//
// It is a sentinel because the exhaustion can surface from several places —
// tar.Reader.Next, a member copy, the trailing-padding read — and archive/tar
// converts a truncated stream into io.ErrUnexpectedEOF, which is
// indistinguishable from a genuinely malformed file. Reporting "malformed"
// there would misdescribe a bomb as a corruption, so the budget records its own
// exhaustion and every error branch consults it.
var errArchiveExpansionLimit = errors.New(
	"the producer archive expands past its expansion limit",
)

// budgetReader caps total expansion and remembers that it did the capping.
type budgetReader struct {
	inner     io.Reader
	remaining int64
	exhausted bool
}

func newBudgetReader(inner io.Reader, limit int64) *budgetReader {
	// One byte past the limit, so an archive exactly at the limit reads to a
	// clean EOF and only one that exceeds it trips the budget.
	return &budgetReader{inner: inner, remaining: limit + 1}
}

func (b *budgetReader) Read(buffer []byte) (int, error) {
	if b.remaining <= 0 {
		b.exhausted = true
		return 0, errArchiveExpansionLimit
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	read, err := b.inner.Read(buffer)
	b.remaining -= int64(read)
	if b.remaining <= 0 {
		b.exhausted = true
	}
	return read, err
}

// overspent reports whether the budget consumed more than the limit allows.
func (b *budgetReader) overspent(limit int64) bool {
	return b.exhausted && b.remaining <= 0
}

// classify replaces any error with the expansion-limit sentinel when the budget
// was the cause, so exhaustion is reported identically wherever it is detected.
func (b *budgetReader) classify(err error, limit int64) error {
	if b.overspent(limit) {
		return fmt.Errorf("%w of %d bytes", errArchiveExpansionLimit, limit)
	}
	return err
}

// archiveTree is what one producer archive contains.
type archiveTree struct {
	files       map[string]string
	directories map[string]struct{}
	base        string
}

// verifyPendingArchiveMatchesTree proves the producer's pending archive encodes
// exactly the manifest-listed evidence tree.
//
// listedFiles maps each manifest-listed member name to the digest of its bytes
// as they exist on disk; treeDirectories is the directory set of the same tree.
// Both are computed by the snapshot walk, from the files themselves, so this
// compares the archive against measured reality rather than against the
// manifest's claims about it.
// VerifyPendingArchiveMatchesTree is the exported entry point.
func VerifyPendingArchiveMatchesTree(
	archivePath string,
	expectedBase string,
	listedFiles map[string]string,
	treeDirectories map[string]struct{},
) (string, error) {
	return verifyPendingArchiveMatchesTree(
		archivePath, expectedBase, listedFiles, treeDirectories,
	)
}

func verifyPendingArchiveMatchesTree(
	archivePath string,
	expectedBase string,
	listedFiles map[string]string,
	treeDirectories map[string]struct{},
) (string, error) {
	return verifyPendingArchiveWithLimits(
		archivePath, expectedBase, listedFiles, treeDirectories,
		productionArchiveLimits(),
	)
}

func verifyPendingArchiveWithLimits(
	archivePath string,
	expectedBase string,
	listedFiles map[string]string,
	treeDirectories map[string]struct{},
	limits archiveLimits,
) (string, error) {
	tree, digest, err := readPendingArchive(archivePath, limits)
	if err != nil {
		return "", err
	}
	// The archive's root must be THIS evidence directory's name, not merely a
	// consistent one. An archive whose members all agree on a different
	// top-level name is internally consistent and still maps to the wrong
	// directory, which is exactly the false mapping this check exists to catch.
	if tree.base != expectedBase {
		return "", fmt.Errorf(
			"the producer archive contains evidence directory %q, this record "+
				"maps to %q", tree.base, expectedBase,
		)
	}

	var problems []string
	for name, digest := range listedFiles {
		archived, present := tree.files[name]
		if !present {
			problems = append(problems, "archive omits "+name)
			continue
		}
		if archived != digest {
			problems = append(problems, fmt.Sprintf(
				"archive member %s holds different bytes (%s) than the "+
					"evidence tree (%s)", name, archived, digest,
			))
		}
	}
	for name := range tree.files {
		if _, expected := listedFiles[name]; !expected {
			problems = append(problems,
				"archive carries unlisted member "+name)
		}
	}
	for directory := range treeDirectories {
		if _, present := tree.directories[directory]; !present {
			problems = append(problems, "archive omits directory "+directory)
		}
	}
	for directory := range tree.directories {
		if _, expected := treeDirectories[directory]; !expected {
			problems = append(problems,
				"archive carries unexpected directory "+directory)
		}
	}
	if len(problems) == 0 {
		return digest, nil
	}
	sort.Strings(problems)
	if len(problems) > 8 {
		problems = append(problems[:8], fmt.Sprintf(
			"and %d more", len(problems)-8))
	}
	return "", fmt.Errorf(
		"the producer archive is not a faithful encoding of the evidence it "+
			"was built from: %s", strings.Join(problems, "; "),
	)
}

// readPendingArchive decodes one producer archive under strict bounds and
// returns its contents together with the digest of the exact bytes it parsed.
//
// Both come from ONE descriptor. Hashing the path and then reopening it to
// parse would leave a window in which the file can be swapped, so
// CONTROLLER_START could bind archive A while equivalence validation examined
// archive B — a signature over one artifact vouching for a different one.
func readPendingArchive(
	archivePath string, limits archiveLimits,
) (*archiveTree, string, error) {
	before, err := os.Lstat(archivePath)
	if err != nil {
		return nil, "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.New("the producer archive is a symbolic link")
	}
	if !before.Mode().IsRegular() {
		return nil, "", errors.New("the producer archive is not a regular file")
	}
	if before.Size() > limits.compressedBytes {
		return nil, "", fmt.Errorf(
			"the producer archive is %d bytes on disk, over the %d-byte "+
				"compressed limit", before.Size(), limits.compressedBytes,
		)
	}
	file, err := os.Open(archivePath) // #nosec G304 -- inspected immediately above
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, "", errors.New(
			"the producer archive changed between inspection and open",
		)
	}

	// Digest first, from this descriptor, then rewind and parse the same
	// descriptor. One open, one inode, no window.
	hash := sha256.New()
	hashed, err := io.Copy(hash, io.LimitReader(file, opened.Size()+1))
	if err != nil {
		return nil, "", err
	}
	if hashed != opened.Size() {
		return nil, "", errors.New(
			"the producer archive changed while it was being read",
		)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, "", err
	}

	// A bufio.Reader, not the *os.File directly. gzip.Reader needs an
	// io.ByteReader to avoid buffering ahead on its own; given a plain file it
	// wraps one internally and over-reads, which leaves the file positioned
	// past the end of the first member and makes the multistream check below
	// read from the wrong place. Supplying the byte reader keeps the position
	// exact, which is what lets a second concatenated stream be detected at all.
	buffered := bufio.NewReader(file)
	decompressor, err := gzip.NewReader(buffered)
	if err != nil {
		return nil, "", fmt.Errorf("the producer archive is not gzip: %w", err)
	}
	defer decompressor.Close()
	// One gzip member only. With multistream left on, a second concatenated
	// gzip+tar stream is transparently consumed and its contents never examined,
	// so an archive could carry an entire hidden payload past the first logical
	// end and still verify.
	decompressor.Multistream(false)

	tree := &archiveTree{
		files:       make(map[string]string),
		directories: make(map[string]struct{}),
	}
	// The decompression bound. A small compressed file can expand without
	// limit, so the cap is applied to the expanded stream, not the file.
	// #nosec G110 -- the reader below is explicitly bounded.
	budget := newBudgetReader(decompressor, limits.totalBytes)
	reader := tar.NewReader(budget)
	members := 0
	var declared int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Exhaustion can surface here as io.ErrUnexpectedEOF, which is
			// indistinguishable from genuine corruption. The budget knows
			// which it was, so it is asked rather than guessed at.
			if classified := budget.classify(err, limits.totalBytes); classified != err {
				return nil, "", classified
			}
			return nil, "", fmt.Errorf("the producer archive is malformed: %w", err)
		}
		members++
		if members > limits.members {
			return nil, "", fmt.Errorf(
				"the producer archive has %d members, over the %d-member limit",
				members, limits.members,
			)
		}
		name, isDirectory, err := archiveMemberName(header)
		if err != nil {
			return nil, "", err
		}
		// Exactly one top-level basename. An archive containing two roots is
		// not an encoding of one evidence directory.
		base, relative, ok := strings.Cut(name, "/")
		if !ok || relative == "" {
			if isDirectory && base != "" {
				if tree.base == "" {
					tree.base = base
				} else if tree.base != base {
					return nil, "", errors.New(
						"the producer archive contains more than one top-level " +
							"evidence directory",
					)
				}
				continue
			}
			return nil, "", fmt.Errorf(
				"the producer archive member %q is not inside an evidence "+
					"directory", header.Name,
			)
		}
		if tree.base == "" {
			tree.base = base
		} else if tree.base != base {
			return nil, "", errors.New(
				"the producer archive contains more than one top-level " +
					"evidence directory",
			)
		}

		if isDirectory {
			if _, duplicate := tree.directories[relative]; duplicate {
				return nil, "", fmt.Errorf(
					"the producer archive repeats directory %q", relative,
				)
			}
			tree.directories[relative] = struct{}{}
			continue
		}
		if _, duplicate := tree.files[relative]; duplicate {
			return nil, "", fmt.Errorf(
				"the producer archive repeats member %q", relative,
			)
		}
		if header.Size > limits.memberBytes {
			return nil, "", fmt.Errorf(
				"the producer archive member %q is %d bytes, over the "+
					"%d-byte member limit",
				relative, header.Size, limits.memberBytes,
			)
		}
		// The aggregate bound, applied to DECLARED sizes as headers arrive.
		//
		// Waiting for the actual decompressed bytes to exceed the limit means
		// expanding gigabytes before refusing, and the failure then surfaces as
		// a truncated-stream error that says nothing about what happened. A
		// header claiming more than the archive may contain is refusable on
		// sight. The byte-level bound below still stands as the backstop for a
		// header that understates its own member.
		declared += header.Size
		if declared > limits.totalBytes {
			return nil, "", fmt.Errorf(
				"%w of %d bytes: it declares %d bytes by member %q",
				errArchiveExpansionLimit, limits.totalBytes, declared, relative,
			)
		}
		hash := sha256.New()
		limited := &io.LimitedReader{R: reader, N: header.Size + 1}
		copied, err := io.Copy(hash, limited)
		if err != nil {
			return nil, "", budget.classify(err, limits.totalBytes)
		}
		if copied != header.Size {
			// A short member is the other face of exhaustion: the budget cut
			// the stream mid-copy and tar reported fewer bytes than declared.
			if budget.overspent(limits.totalBytes) {
				return nil, "", fmt.Errorf(
					"%w of %d bytes", errArchiveExpansionLimit, limits.totalBytes,
				)
			}
			return nil, "", fmt.Errorf(
				"the producer archive member %q declares %d bytes and holds %d",
				relative, header.Size, copied,
			)
		}
		tree.files[relative] = hex.EncodeToString(hash.Sum(nil))
	}
	if budget.overspent(limits.totalBytes) {
		return nil, "", fmt.Errorf(
			"%w of %d bytes", errArchiveExpansionLimit, limits.totalBytes,
		)
	}
	if tree.base == "" || len(tree.files) == 0 {
		return nil, "", errors.New("the producer archive is empty")
	}

	// Everything after the tar end-of-archive marker, inside this gzip member,
	// must be zero padding. archive/tar stops at the marker, so any real
	// content beyond it would otherwise go entirely unverified.
	trailing, err := io.ReadAll(&io.LimitedReader{R: budget, N: 1 << 20})
	if err != nil {
		return nil, "", budget.classify(err, limits.totalBytes)
	}
	for _, b := range trailing {
		if b != 0 {
			return nil, "", errors.New(
				"the producer archive carries content after its end-of-archive " +
					"marker",
			)
		}
	}
	// And there must be no second gzip member. Reset reports io.EOF at a clean
	// end; anything else means more data follows the archive.
	switch err := decompressor.Reset(buffered); {
	case errors.Is(err, io.EOF):
	case err == nil:
		return nil, "", errors.New(
			"the producer archive is a concatenation of more than one gzip " +
				"stream; the content past the first would never be examined",
		)
	default:
		return nil, "", fmt.Errorf(
			"the producer archive has trailing data: %w", err,
		)
	}

	// The descriptor still refers to the same file it did at the start.
	after, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() ||
		!after.ModTime().Equal(opened.ModTime()) {
		return nil, "", errors.New(
			"the producer archive was mutated while it was being read",
		)
	}
	return tree, digest, nil
}

// archiveMemberName validates one member's type and path.
func archiveMemberName(header *tar.Header) (string, bool, error) {
	switch header.Typeflag {
	// 0x00 is the legacy code some tar writers still emit for a plain file
	// (archive/tar's deprecated TypeRegA). Rejecting it would refuse
	// legitimate producer archives, so it is spelled as the raw byte here
	// rather than through the deprecated constant.
	case tar.TypeReg, 0x00:
	case tar.TypeDir:
	case tar.TypeSymlink, tar.TypeLink:
		return "", false, fmt.Errorf(
			"the producer archive carries a link at %q; a link is a reference "+
				"to bytes that live somewhere else, not evidence", header.Name,
		)
	default:
		return "", false, fmt.Errorf(
			"the producer archive carries a special entry at %q", header.Name,
		)
	}
	name := path.Clean(header.Name)
	if name != strings.TrimSuffix(header.Name, "/") &&
		name+"/" != header.Name {
		return "", false, fmt.Errorf(
			"the producer archive member %q is not a canonical path", header.Name,
		)
	}
	if path.IsAbs(name) || name == "." || name == ".." ||
		strings.HasPrefix(name, "../") || strings.Contains(name, "/../") ||
		strings.ContainsRune(name, 0) {
		return "", false, fmt.Errorf(
			"the producer archive member %q escapes its root", header.Name,
		)
	}
	return name, header.Typeflag == tar.TypeDir, nil
}
