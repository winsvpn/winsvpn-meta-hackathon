// Package closedarchive publishes the outer artifact that commits to a closed
// evidence directory: its base manifest and its terminal audit checkpoint,
// together, in one object.
//
// WHY THIS IS NOT A SHELL STEP.
//
// It was one, and the shell version was wrong in three ways that shell cannot
// fix.
//
//  1. It claimed to fsync the archive before publishing it and did not, because
//     POSIX sh has no fsync. A comment asserting durability that the code does
//     not provide is worse than no comment: it stops the next reader from
//     checking.
//
//  2. It published two files with two link() calls — the archive and its
//     .sha256 pin. Two atomic steps are not an atomic step. A crash between
//     them left the archive published without its pin, and because the next
//     run's preflight refuses an occupied output path, that state was
//     permanently stuck: not retryable, not recoverable, wedged.
//
//  3. Its existence checks used [ -e ], which is false for a dangling symlink.
//     A stale link left by an earlier crash therefore read as "absent" and was
//     silently clobbered or misjudged.
//
// The fix for (2) is the one that shapes this package: publication is ONE file.
// There is no separate pin sidecar to fall out of step, because the archive's
// digest is returned to the caller and recorded in the batch record and the
// anchor request — the places that actually bind it. A single os.Link of a
// single fully-written, fsynced file is the whole publication, and link()
// fails with EEXIST rather than replacing, so it is atomic AND no-replace,
// which rename() is not.
package closedarchive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Stage names each crash boundary in the publication sequence. They exist so
// tests can fail-inject at exactly the points a crash could land, and so the
// recovery argument for each one can be stated and checked rather than assumed.
type Stage string

const (
	// StageAfterBuild is after the temporary archive is fully written but
	// before it is fsynced. Recovery: nothing is published; the temporary file
	// is removed by the caller's retry, or left as garbage under a name no
	// reader consults.
	StageAfterBuild Stage = "after-build"

	// StageAfterSync is after the temporary archive is durable but before the
	// link. Recovery: identical to above. The destination name does not exist,
	// so a retry simply rebuilds.
	StageAfterSync Stage = "after-sync"

	// StageAfterLink is after the destination name exists and before the
	// temporary name is unlinked. Recovery: the archive IS published and
	// complete. A retry finds the destination occupied by a byte-identical
	// artifact and must treat that as success, which is what Publish's
	// already-published path does.
	StageAfterLink Stage = "after-link"

	// StageAfterUnlink is after the temporary name is gone and before the
	// directory fsync. Recovery: as above; the directory entry may not survive
	// a power loss, in which case the retry sees no destination and rebuilds.
	StageAfterUnlink Stage = "after-unlink"
)

const (
	maximumMemberBytes = 512 << 20
	maximumMembers     = 100_000
	// maximumArchiveBytes bounds the WHOLE archive, not just each member.
	// Per-member and per-count limits are individually satisfiable by an input
	// that is unbounded in aggregate: a hundred thousand members just under the
	// per-member ceiling is far past anything this should write.
	maximumArchiveBytes = 8 << 30
	temporaryPrefix     = ".winn-closed-"
)

// Input is one publication.
type Input struct {
	// EvidenceDirectory is the closed evidence directory to archive. It is
	// stored in the archive under its own basename, matching the producer's
	// archive layout.
	EvidenceDirectory string
	// Destination is the final archive path. It must not exist, including as a
	// dangling symlink.
	Destination string
	// crashAt, when set, aborts immediately after the named stage. Test-only,
	// passed explicitly rather than through a package variable so concurrent
	// publications cannot perturb one another.
	crashAt Stage
}

// Result reports what was published.
type Result struct {
	Destination string
	SHA256      string
	// AlreadyPublished is true when the destination already held a
	// byte-identical archive, which is the state a crash between link and
	// unlink leaves behind. It is a success, not a conflict: the artifact is
	// present and complete, and a retry that refused here would turn a
	// recoverable interruption into a permanent one.
	AlreadyPublished bool
}

// Publish writes the closed archive and publishes it atomically.
//
// The sequence, and what a crash at each point costs:
//
//	build temp   -> nothing published, retry rebuilds
//	fsync temp   -> nothing published, retry rebuilds
//	link to dest -> PUBLISHED and complete; retry recognises it and succeeds
//	unlink temp  -> published; retry recognises it
//	fsync dir    -> published durably
//
// There is exactly one point at which the artifact becomes visible, and at that
// point it is already complete and durable. That is the property two separate
// link() calls could not have.
func Publish(input Input) (Result, error) {
	evidence, err := realDirectory(input.EvidenceDirectory)
	if err != nil {
		return Result{}, err
	}
	if input.Destination == "" {
		return Result{}, errors.New("closed archive destination is required")
	}
	destination, err := filepath.Abs(input.Destination)
	if err != nil {
		return Result{}, err
	}
	directory := filepath.Dir(destination)
	// The parent must be a real directory, checked with Lstat so a symlinked
	// parent is refused rather than followed. Publication creates a temporary
	// file here and then links it into place; a parent that redirects elsewhere
	// would put both somewhere nobody intended.
	parent, err := os.Lstat(directory)
	if err != nil {
		return Result{}, fmt.Errorf("closed archive parent directory: %w", err)
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return Result{}, fmt.Errorf(
			"%s is not a real directory; refusing to publish through it",
			directory,
		)
	}

	// Existence is decided with Lstat, never with a stat that follows links. A
	// dangling symlink is a file system entry: it makes link() fail with EEXIST
	// and it makes [ -e ] say "absent". Treating it as absent is how a stale
	// link from an earlier crash gets misjudged.
	switch existing, err := os.Lstat(destination); {
	case err == nil && existing.Mode()&os.ModeSymlink != 0:
		return Result{}, fmt.Errorf(
			"%s exists as a symbolic link; refusing to publish through it. A "+
				"dangling link reads as absent to a plain existence test, which "+
				"is how a stale entry from an earlier crash gets clobbered",
			destination,
		)
	case err == nil && !existing.Mode().IsRegular():
		return Result{}, fmt.Errorf(
			"%s exists and is not a regular file", destination,
		)
	case err == nil:
		// Already published. Only a byte-identical artifact is acceptable: that
		// is the crash-between-link-and-unlink state, and recognising it is what
		// makes the interruption recoverable instead of permanent.
		published, err := sha256File(destination)
		if err != nil {
			return Result{}, err
		}
		rebuilt, cleanup, err := build(evidence, directory, input.crashAt)
		if err != nil {
			return Result{}, err
		}
		defer cleanup()
		if rebuilt.digest != published {
			return Result{}, fmt.Errorf(
				"%s already exists and holds a different archive (%s on disk, "+
					"%s rebuilt from this evidence); refusing to reconcile two "+
					"different closed artifacts",
				destination, published, rebuilt.digest,
			)
		}
		// Same durability gate as the first-publish path. A crash after link
		// (or a failed directory fsync on the first attempt) leaves dest
		// visible without a durable directory entry; returning success here
		// without fsyncing would let a retry skip the fsync the package
		// exists to perform.
		if err := syncDirectory(directory); err != nil {
			return Result{}, err
		}
		return Result{
			Destination:      destination,
			SHA256:           published,
			AlreadyPublished: true,
		}, nil
	case !errors.Is(err, os.ErrNotExist):
		return Result{}, err
	}

	built, cleanup, err := build(evidence, directory, input.crashAt)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	if err := os.Link(built.path, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return Result{}, fmt.Errorf("publish closed archive: %w", err)
		}
		// Another publication won the race while this one was building. That is
		// the same situation as a crash between link and unlink, and it gets the
		// same answer: if the incumbent is the artifact this run would itself
		// have produced, the work is done and this call succeeds. Two callers
		// closing the same evidence concurrently is ordinary — a controller
		// retry overlapping a slow first attempt, most obviously — and failing
		// the loser would turn a benign overlap into a spurious error.
		published, hashErr := sha256File(destination)
		if hashErr != nil {
			return Result{}, hashErr
		}
		if published != built.digest {
			return Result{}, fmt.Errorf(
				"%s was published concurrently with a different archive (%s on "+
					"disk, %s built here); refusing to reconcile two different "+
					"closed artifacts", destination, published, built.digest,
			)
		}
		if err := syncDirectory(directory); err != nil {
			return Result{}, err
		}
		return Result{
			Destination:      destination,
			SHA256:           published,
			AlreadyPublished: true,
		}, nil
	}
	if input.crashAt == StageAfterLink {
		return Result{}, crashError(StageAfterLink)
	}
	if err := os.Remove(built.path); err != nil {
		return Result{}, fmt.Errorf("remove temporary archive: %w", err)
	}
	if input.crashAt == StageAfterUnlink {
		return Result{}, crashError(StageAfterUnlink)
	}
	if err := syncDirectory(directory); err != nil {
		return Result{}, err
	}
	return Result{Destination: destination, SHA256: built.digest}, nil
}

type builtArchive struct {
	path   string
	digest string
}

// build writes the archive to a private temporary name in the destination's own
// directory (so the later link is a same-filesystem operation), fsyncs it, and
// hashes the bytes that are actually on disk rather than the bytes that were
// intended to be.
func build(
	evidence, directory string,
	crashAt Stage,
) (builtArchive, func(), error) {
	temporary, err := os.CreateTemp(directory, temporaryPrefix+"*.tar.gz")
	if err != nil {
		return builtArchive{}, func() {}, fmt.Errorf(
			"create temporary archive: %w", err,
		)
	}
	path := temporary.Name()
	cleanup := func() { _ = os.Remove(path) }
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return builtArchive{}, func() {}, err
	}
	if err := writeArchive(temporary, evidence); err != nil {
		cleanup()
		return builtArchive{}, func() {}, err
	}
	if crashAt == StageAfterBuild {
		cleanup()
		return builtArchive{}, func() {}, crashError(StageAfterBuild)
	}
	// The real fsync the shell version claimed and did not have. Without it the
	// link below can publish a name whose contents are still only in page
	// cache, so a power loss yields a published, referenced, empty or partial
	// archive — the one outcome atomic publication exists to prevent.
	if err := temporary.Sync(); err != nil {
		cleanup()
		return builtArchive{}, func() {}, fmt.Errorf("sync archive: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return builtArchive{}, func() {}, err
	}
	closed = true
	if crashAt == StageAfterSync {
		cleanup()
		return builtArchive{}, func() {}, crashError(StageAfterSync)
	}
	digest, err := sha256File(path)
	if err != nil {
		cleanup()
		return builtArchive{}, func() {}, err
	}
	return builtArchive{path: path, digest: digest}, cleanup, nil
}

// writeArchive produces a deterministic gzip/tar of the evidence directory:
// sorted member order, zeroed mtimes, fixed permissions, no ownership. Two
// publications of the same evidence therefore produce the same bytes, which is
// what lets the already-published path above compare digests instead of
// guessing.
//
// Nested directories are archived. The producer seals its manifest with a
// recursive walk, so evidence subdirectories are ordinary, expected content and
// an archiver that refused them would reject valid evidence outright. What is
// refused is anything whose bytes are not what they appear to be: symbolic
// links, devices, sockets, fifos. Directories are structure; those are
// indirection.
//
// Every member is opened through an os.Root anchored at the evidence
// directory. That closes the stat/open race — the name cannot be swapped for a
// link pointing outside the tree between the walk and the read — and the
// descriptor is re-stat'd and compared with os.SameFile so a swap for another
// file INSIDE the tree is caught too.
func writeArchive(destination io.Writer, evidence string) error {
	root, err := os.OpenRoot(evidence)
	if err != nil {
		return err
	}
	defer root.Close()

	directories, files, err := walkMembers(root)
	if err != nil {
		return err
	}

	compressor, err := gzip.NewWriterLevel(destination, gzip.BestCompression)
	if err != nil {
		return err
	}
	writer := tar.NewWriter(compressor)
	base := filepath.Base(evidence)

	// Directory entries first, in sorted order, so an extraction recreates the
	// tree even where a subdirectory holds nothing a manifest would list.
	for _, member := range directories {
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir,
			Name:     base + "/" + member + "/",
			Mode:     0o700,
			Format:   tar.FormatPAX,
		}); err != nil {
			return err
		}
	}

	var total int64
	for _, member := range files {
		written, err := archiveOneFile(writer, root, base, member, total)
		if err != nil {
			return err
		}
		total += written
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return compressor.Close()
}

// walkMembers returns the sorted directory and regular-file members, refusing
// anything that is neither.
func walkMembers(root *os.Root) (directories, files []string, err error) {
	err = fs.WalkDir(root.FS(), ".", func(
		path string, entry fs.DirEntry, err error,
	) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}
		switch {
		case entry.IsDir():
			directories = append(directories, path)
		case entry.Type().IsRegular():
			files = append(files, path)
		default:
			return fmt.Errorf(
				"closed evidence contains %q, which is a %s; only regular "+
					"files and directories may be archived, because anything "+
					"else is a reference to bytes that live elsewhere",
				path, describeMode(entry.Type()),
			)
		}
		if len(directories)+len(files) > maximumMembers {
			return errors.New("closed evidence has implausibly many entries")
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(directories)
	sort.Strings(files)
	return directories, files, nil
}

func archiveOneFile(
	writer *tar.Writer,
	root *os.Root,
	base, member string,
	alreadyWritten int64,
) (int64, error) {
	// Lstat first: this is the size and identity the header will claim.
	before, err := root.Lstat(member)
	if err != nil {
		return 0, err
	}
	if !before.Mode().IsRegular() {
		return 0, fmt.Errorf(
			"%s stopped being a regular file during the walk", member,
		)
	}
	if before.Size() > maximumMemberBytes {
		return 0, fmt.Errorf(
			"%s is %d bytes, over the %d-byte member limit",
			member, before.Size(), maximumMemberBytes,
		)
	}
	if alreadyWritten+before.Size() > maximumArchiveBytes {
		return 0, fmt.Errorf(
			"closed evidence exceeds the %d-byte archive limit at %s",
			// int64: the untyped constant is 8 GiB, which does not fit in an
			// int on a 32-bit target, so passing it bare would fail to
			// compile there.
			int64(maximumArchiveBytes), member,
		)
	}

	file, err := root.Open(member)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	// The descriptor that will actually be read, compared against the entry
	// that was measured. A name swapped between the two — even for another
	// file inside the tree, which the root confinement alone would allow — is
	// caught here.
	opened, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return 0, fmt.Errorf(
			"%s changed between being measured and being opened", member,
		)
	}

	// The limits are re-checked against the OPENED descriptor, not only against
	// the earlier Lstat. Those are two different observations of the file, and
	// a member that grew between them would otherwise be written at a size
	// nobody bounded.
	if opened.Size() > maximumMemberBytes {
		return 0, fmt.Errorf(
			"%s is %d bytes when opened, over the %d-byte member limit",
			member, opened.Size(), maximumMemberBytes,
		)
	}
	if alreadyWritten+opened.Size() > maximumArchiveBytes {
		return 0, fmt.Errorf(
			"closed evidence exceeds the %d-byte archive limit at %s",
			// int64: the untyped constant is 8 GiB, which does not fit in an
			// int on a 32-bit target, so passing it bare would fail to
			// compile there.
			int64(maximumArchiveBytes), member,
		)
	}

	if err := writer.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     base + "/" + member,
		Mode:     0o600,
		Size:     opened.Size(),
		Format:   tar.FormatPAX,
	}); err != nil {
		return 0, err
	}
	// A bounded copy, not an unbounded one followed by a size comparison. The
	// header has already declared opened.Size() bytes; a file that grew during
	// the read would otherwise stream past that into the next member's space
	// and corrupt the archive before the mismatch was noticed. Reading one byte
	// past the declared size is what distinguishes "exactly as declared" from
	// "longer than declared".
	limited := &io.LimitedReader{R: file, N: opened.Size() + 1}
	copied, err := io.Copy(writer, limited)
	if err != nil {
		return 0, err
	}
	if copied != opened.Size() {
		return 0, fmt.Errorf(
			"%s changed while it was being archived: %d bytes were copied, it "+
				"was %d when it was measured", member, copied, opened.Size(),
		)
	}
	// And one more observation after the copy: a file that was truncated and
	// re-extended to the same length, or otherwise mutated in place, is caught
	// by comparing the descriptor's identity and size again.
	after, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return 0, fmt.Errorf(
			"%s was mutated while it was being archived", member,
		)
	}
	return copied, nil
}

func describeMode(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSymlink != 0:
		return "symbolic link"
	case mode&fs.ModeDevice != 0:
		return "device"
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	default:
		return "special file"
	}
}

func syncDirectory(directory string) error {
	// #nosec G304 -- directory is the parent of a caller-selected destination
	// path that has already been resolved to an absolute location.
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	return handle.Close()
}

func sha256File(path string) (string, error) {
	// #nosec G304 -- path is an absolute destination or a temporary file this
	// package created in a directory it resolved.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func realDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("evidence directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("evidence directory must be a real directory")
	}
	return absolute, nil
}

func crashError(stage Stage) error {
	return fmt.Errorf("injected crash at stage %s", stage)
}

// CleanTemporaries removes leftover temporary archives abandoned by an
// interrupted build.
//
// Only files older than olderThan are removed, and that age is the entire
// safety mechanism, so it is a required argument rather than a hidden default.
// Several publications can be in flight in one directory at once; an in-flight
// temporary is being actively written, so its modification time is recent, and
// a sweep that removed by name alone would delete a file another publisher was
// still writing into. Deleting an open file would not corrupt that publisher's
// archive — the descriptor survives the unlink — but it WOULD remove the name
// the subsequent link() needs, turning a healthy concurrent publication into a
// spurious failure.
//
// The threshold must therefore exceed the longest plausible build. It is a
// heuristic, and it is stated as one: there is no way to distinguish a crashed
// publisher's leftovers from a very slow live one by inspection alone.
func CleanTemporaries(directory string, olderThan time.Duration) error {
	if olderThan <= 0 {
		return errors.New(
			"a positive age threshold is required; sweeping temporary " +
				"archives by name alone would delete files that concurrent " +
				"publications are still writing",
		)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-olderThan)
	for _, entry := range entries {
		if !entry.Type().IsRegular() ||
			!strings.HasPrefix(entry.Name(), temporaryPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
