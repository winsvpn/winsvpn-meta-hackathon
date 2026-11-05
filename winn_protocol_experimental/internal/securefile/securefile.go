package securefile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func AtomicWrite(path string, data []byte, permission os.FileMode) error {
	directory := filepath.Dir(path)
	if err := EnsurePrivateDirectory(directory); err != nil {
		return err
	}
	temp, err := os.CreateTemp(directory, ".winn-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(permission); err != nil {
		cleanup()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if err := securePrivatePath(tempPath); err != nil {
		cleanup()
		return fmt.Errorf("secure temporary file ownership: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace destination file: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func SyncFileAndParent(path string) error {
	// #nosec G304 -- callers have already validated this configured path and
	// the opened identity is rechecked by the caller.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open file for sync: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close synced file: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return syncDirectoryWith(directory, openDirectoryForSync)
}

func SyncParent(path string) error {
	return syncDirectory(filepath.Dir(path))
}

// OpenFileWithinParent opens only the final path component beneath a directory
// root. The directory handle confines the operation even if the caller-supplied
// path is changed concurrently or contains traversal components.
func OpenFileWithinParent(
	path string,
	flag int,
	permission os.FileMode,
) (*os.File, error) {
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return nil, errors.New("file path has no final component")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	file, openErr := root.OpenFile(name, flag, permission)
	closeErr := root.Close()
	if openErr != nil {
		return nil, openErr
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	return file, nil
}

type directorySyncFile interface {
	Sync() error
	Close() error
}

type rootedDirectorySyncFile struct {
	root *os.Root
	file *os.File
}

func openDirectoryForSync(path string) (directorySyncFile, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &rootedDirectorySyncFile{root: root, file: file}, nil
}

func (directory *rootedDirectorySyncFile) Sync() error {
	return directory.file.Sync()
}

func (directory *rootedDirectorySyncFile) Close() error {
	fileErr := directory.file.Close()
	rootErr := directory.root.Close()
	if fileErr != nil {
		return fileErr
	}
	return rootErr
}

func syncDirectoryWith(
	directory string,
	open func(string) (directorySyncFile, error),
) error {
	// #nosec G304 -- directory is derived from a validated destination path.
	directoryFile, err := open(directory)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close directory: %w", err)
	}
	return nil
}

// AtomicWriteNew creates a file that must not already exist.
//
// AtomicWrite above deliberately replaces its destination, which is right for a
// file that is rewritten every run. It is wrong for anything that must be
// created once and never silently superseded — a terminal audit checkpoint, or
// the finalizer seed that signs one. A check-then-write built on Lstat cannot
// provide that: between the check and the write, another process (or another
// goroutine) can create the file, and the loser's data would overwrite the
// winner's with no error anywhere.
//
// O_CREATE|O_EXCL directly on the destination is no-clobber but it is NOT
// atomic publication: a crash or a short write leaves a zero-byte or partial
// file sitting at the final path, and because that path now exists, every
// later retry is permanently refused by the very no-clobber rule that was
// supposed to protect it. An observer would also be able to see a half-written
// checkpoint at its real name.
//
// So the content is written and fsynced to a private temporary file in the SAME
// directory, and published with link(2), which fails with EEXIST when the
// destination is taken. That is the one POSIX primitive that both publishes
// atomically and refuses to replace — rename does the first but not the second.
// The temporary name is then unlinked and the directory fsynced, because
// without that the directory entry itself may not survive a crash and a
// checkpoint could be reported as written and then not exist.
//
// Failure cleanup only ever removes the caller's own uniquely-named temporary
// file. It never touches the destination, so a losing writer can never delete
// the file the winning writer just published.
func AtomicWriteNew(path string, data []byte, permission os.FileMode) error {
	directory := filepath.Dir(path)
	if err := EnsurePrivateDirectory(directory); err != nil {
		return err
	}
	// Refuse an occupied destination up front, so the common case reports the
	// real reason rather than a link failure. This is an optimisation, not the
	// guarantee: the link below is what actually resolves a concurrent race.
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf(
			"%s already exists; refusing to replace it: %w", path, os.ErrExist,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(directory, ".winn-new-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	// Removes only this caller's own temporary name, never the destination.
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(permission); err != nil {
		cleanup()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if err := securePrivatePath(tempPath); err != nil {
		cleanup()
		return fmt.Errorf("secure temporary file ownership: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Link(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf(
				"%s already exists; refusing to replace it: %w",
				path, os.ErrExist,
			)
		}
		return fmt.Errorf("publish new file: %w", err)
	}
	if err := os.Remove(tempPath); err != nil {
		return fmt.Errorf("remove temporary file: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

func ReadPrivate(path string) ([]byte, error) {
	return ReadPrivateLimited(path, 0)
}

func ReadPrivateLimited(path string, maximum int64) ([]byte, error) {
	file, data, _, err := OpenPrivateLimited(path, maximum)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		clear(data)
		return nil, fmt.Errorf("close private file: %w", err)
	}
	return data, nil
}

// OpenPrivateLimited returns the exact validated descriptor from which data
// was read. The caller owns and must close the descriptor and clear the data.
func OpenPrivateLimited(
	path string,
	maximum int64,
) (*os.File, []byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, nil, errors.New("secret path is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, nil, nil, fmt.Errorf("secret file %s has permissions %04o, want no group/other access", path, info.Mode().Perm())
	}
	if err := validatePrivatePath(path, false); err != nil {
		return nil, nil, nil, err
	}
	// #nosec G304 -- this configured path and the opened inode are both
	// identity checked before any bytes are returned.
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, nil, errors.New("validated file target changed before it was opened")
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, nil, nil, fmt.Errorf("secret file %s permissions changed before it was opened", path)
	}
	if err := validateOpenedPrivateFile(file); err != nil {
		_ = file.Close()
		return nil, nil, nil, err
	}
	var data []byte
	if maximum <= 0 {
		data, err = io.ReadAll(file)
	} else {
		data, err = io.ReadAll(io.LimitReader(file, maximum+1))
		if err == nil && int64(len(data)) > maximum {
			clear(data)
			_ = file.Close()
			return nil, nil, nil, fmt.Errorf("file %s exceeds %d-byte limit", path, maximum)
		}
	}
	if err != nil {
		clear(data)
		_ = file.Close()
		return nil, nil, nil, err
	}
	return file, data, opened, nil
}

func ReadPublicIntegrity(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("public data path is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("public data file %s is group/other writable (%04o)", path, info.Mode().Perm())
	}
	return readLimited(path, maximum, info, false)
}

func EnsurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	created := false
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create private directory: %w", err)
		}
		created = true
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("private directory path %s is not a directory", path)
	}
	if created {
		if err := securePrivatePath(path); err != nil {
			return fmt.Errorf("secure private directory ownership: %w", err)
		}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("private directory %s is group/other writable (%04o)", path, info.Mode().Perm())
	}
	if err := validatePrivatePath(path, true); err != nil {
		return err
	}
	return nil
}

func readLimited(path string, maximum int64, expected os.FileInfo, private bool) ([]byte, error) {
	// #nosec G304 -- callers accept an administrator-configured path only
	// after Lstat type/mode validation; the opened inode is rechecked below.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, errors.New("validated file target changed before it was opened")
	}
	if private && runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file %s permissions changed before it was opened", path)
	}
	if private {
		if err := validateOpenedPrivateFile(file); err != nil {
			return nil, err
		}
	}
	if !private && runtime.GOOS != "windows" && opened.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("public data file %s permissions changed before it was opened", path)
	}
	if maximum <= 0 {
		return io.ReadAll(file)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		clear(data)
		return nil, fmt.Errorf("file %s exceeds %d-byte limit", path, maximum)
	}
	return data, nil
}

// SHA256Regular hashes a regular file by streaming it, without reading it all
// into memory.
//
// This exists so that the evidence-manifest hashing in the Linux E2E harnesses
// goes through one checked implementation instead of three copies of a bare
// os.Open. Those harnesses hash artifacts an operator named on the command
// line, including multi-megabyte binaries, so a bounded whole-file read is the
// wrong shape — but "we are only hashing it" is not a reason to skip the type
// check. A symbolic link, a FIFO or a device node in that position would be
// followed, and the digest recorded in the evidence manifest would describe
// something other than the file the manifest names.
//
// WHY os.SameFile AT OPEN TIME IS NOT ENOUGH.
//
// SameFile proves the descriptor reaches the inode that was inspected. It says
// nothing about that inode's CONTENTS afterwards, and a streamed digest is not
// an instantaneous observation — it is a walk that takes as long as the file is
// large. An in-place truncate-and-rewrite keeps the inode, so every identity
// check still agrees while the walk reads the first megabytes of one generation
// and the last megabytes of another. The digest that comes out then describes a
// byte sequence the file never held: it matches neither the old content nor the
// new one, and it would be sealed into an evidence manifest as if it did.
//
// THE STABLE-READ CONTRACT THIS IMPLEMENTS.
//
// The whole read is bracketed by descriptor stats and performed TWICE:
//
//	fstat -> hash -> fstat -> rewind -> hash -> fstat
//
// Every stat must agree on inode identity, size and modification time, and the
// two digests must be equal. A rewrite that changes any of those is refused
// rather than reported, and a rewrite that changed the bytes between the passes
// makes the two digests disagree even if it forged the metadata back.
//
// WHICH HALF IS LOAD-BEARING, MEASURED RATHER THAN ASSUMED. Mutation testing
// says the SECOND DIGEST is the control and the stat bracket is not
// independently detectable. Removing only the bracket leaves every stability
// test green, because the second pass catches the same rewrites. Removing only
// the digest comparison turns the tests red — but only for the variant that
// forges size and mtime back, which is exactly the variant the bracket is blind
// to. The bracket is kept for two reasons that are real but narrower than
// "it detects rewrites": it names the size and timestamp that moved, which a
// digest disagreement cannot, and it refuses the one shape the second pass
// cannot see — a rewrite that completes entirely between the open and the first
// pass, where both passes agree on the NEW content and nothing else would
// notice that the file verified at open is not the file that was hashed.
//
// RESIDUAL LIMIT, STATED PLAINLY. This is not proof against a writer that holds
// write access to the same inode and is actively trying to defeat it. Such a
// writer can restore size with a same-length overwrite and restore the
// modification time with utimensat, and if it also arranges for BOTH passes to
// observe the identical mixed content it would go undetected. What is closed is
// the ordinary and the opportunistic case — an unsynchronised rewrite landing
// during the walk — which is the failure this function previously reported as a
// clean digest. The real control against a hostile same-inode writer is custody
// (the artifact not being writable by anyone else) and, where the content is
// small enough to hold, the anonymous unnamed-inode snapshot in
// anonymoussnapshot.go. That machinery is deliberately not used here: it takes
// the content as a []byte, and materialising a multi-megabyte binary in memory
// to copy it into a second file would defeat the reason this function streams —
// and would not close the gap either, since the read into memory is itself the
// same non-instantaneous walk.
//
// All three current callers pass os.Executable(), the running harness binary,
// which narrows the practical exposure further: on Linux a running executable
// cannot be opened for writing at all (ETXTBSY), so the in-place rewrite this
// guards against is not available there, and a replace-by-rename produces a new
// inode that the identity checks already refuse. The contract above is written
// for the general case anyway, because this is a shared helper and the next
// caller may hash something the operator can write.
func SHA256Regular(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symbolic link", path)
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	// #nosec G304 -- path is administrator-supplied harness configuration and
	// has just been Lstat'ed as a real regular file; the descriptor's own Stat
	// is compared with os.SameFile immediately below, so a swap between the
	// two is refused rather than hashed.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", fmt.Errorf(
			"%s changed between inspection and open", path,
		)
	}
	first, err := hashDescriptorFromStart(file, 1)
	if err != nil {
		return "", err
	}
	if err := requireDescriptorUnchanged(file, opened, path); err != nil {
		return "", err
	}
	second, err := hashDescriptorFromStart(file, 2)
	if err != nil {
		return "", err
	}
	if err := requireDescriptorUnchanged(file, opened, path); err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf(
			"%s was rewritten while it was being hashed: two consecutive "+
				"passes over the same descriptor produced different digests, so "+
				"neither describes a state the file actually held", path,
		)
	}
	return first, nil
}

// sha256RegularProgress is a test-only seam, nil in production.
//
// It exists because the stability property cannot otherwise be tested honestly.
// A test that starts a writer goroutine and hopes it lands inside the hashing
// window proves nothing when it does not land there: the run still finishes,
// the assertions about the RESULT still hold, and the test reports success
// without ever having exercised the interleaving it is named for. Counting
// outcomes does not fix that either — an error can come from a rewrite that
// completed entirely between the open and the first pass, which is not an
// interleaving at all.
//
// So the test drives the interleaving instead of racing it: this is called
// after every chunk, with the pass number and the bytes consumed so far, and a
// test can rewrite the file at a point it can then ASSERT was inside the
// window. Unexported and package-private, so nothing outside these tests can
// reach it, and a nil check per 64 KiB chunk is not a measurable cost.
var sha256RegularProgress func(pass int, consumed int64)

// sha256HashChunk is the streaming granularity, and also the resolution at
// which the test seam above can act.
const sha256HashChunk = 64 << 10

// hashDescriptorFromStart rewinds and streams one full SHA-256 pass.
func hashDescriptorFromStart(file *os.File, pass int) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	buffer := make([]byte, sha256HashChunk)
	var consumed int64
	for {
		read, err := file.Read(buffer)
		if read > 0 {
			if _, writeErr := hash.Write(buffer[:read]); writeErr != nil {
				return "", writeErr
			}
			consumed += int64(read)
			if sha256RegularProgress != nil {
				sha256RegularProgress(pass, consumed)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// requireDescriptorUnchanged re-stats the OPEN DESCRIPTOR and refuses any drift
// from the state observed at open time.
//
// Deliberately fstat on the descriptor rather than stat on the pathname: the
// question is whether the bytes just read came from a stable file, and a
// pathname stat would answer a different question about whatever now lives at
// that name. Size and modification time are both compared because either one
// alone leaves an obvious hole — a same-length rewrite keeps the size, and a
// truncation to a different length can be quicker than the timestamp's
// resolution.
//
// This is defence in depth, not the primary control; see SHA256Regular's note
// on what the mutation runs actually showed.
func requireDescriptorUnchanged(
	file *os.File, opened os.FileInfo, path string,
) error {
	current, err := file.Stat()
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return fmt.Errorf("%s changed identity while it was being hashed", path)
	}
	if current.Size() != opened.Size() ||
		!current.ModTime().Equal(opened.ModTime()) {
		return fmt.Errorf(
			"%s changed while it was being hashed (size %d->%d, modified "+
				"%s->%s); a streamed digest taken across a rewrite describes a "+
				"byte sequence the file never held",
			path, opened.Size(), current.Size(),
			opened.ModTime().UTC().Format("2006-01-02T15:04:05.000000000Z"),
			current.ModTime().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		)
	}
	return nil
}
