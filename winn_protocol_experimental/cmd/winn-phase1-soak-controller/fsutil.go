package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

const (
	// maximumDigestedFile bounds a single file read. A snapshot tree is
	// operator-supplied, and an unbounded read of an operator-supplied path
	// is how a controller gets killed by the OOM reaper instead of
	// reporting a refusal.
	maximumDigestedFile int64 = 2 << 30
)

func saturatingMultiply(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

func boundedUint64ToInt64(value uint64, label string) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%s exceeds the signed accounting range", label)
	}
	// #nosec G115 -- the preceding predicate proves value <= math.MaxInt64.
	return int64(value), nil
}

// ensurePrivateDirectory creates a 0700 directory and then checks that it
// really is one.
//
// MkdirAll's permission argument is masked by umask and is ignored entirely
// when the directory already exists, so creating with 0700 proves nothing
// about what is on disk. The Chmod and the re-stat are what make the name
// true.
func ensurePrivateDirectory(path string) error {
	if path == "" {
		return errors.New("directory path is empty")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	// #nosec G302 -- this is a private directory; owner execute is required.
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"directory %s is group- or world-accessible (mode %04o)",
			path, info.Mode().Perm(),
		)
	}
	return nil
}

func fileDigest(path string) (string, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symbolic link", path)
	}
	if !pathInfo.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if pathInfo.Size() > maximumDigestedFile {
		return "", fmt.Errorf(
			"%s is %d bytes, above the %d byte digest bound",
			path, pathInfo.Size(), maximumDigestedFile,
		)
	}
	file, err := openRegularNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	openedInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("stat opened %s: %w", path, err)
	}
	pathIdentity, err := identityFromInfo(pathInfo)
	if err != nil {
		return "", fmt.Errorf("identify path %s: %w", path, err)
	}
	openedIdentity, err := identityFromInfo(openedInfo)
	if err != nil {
		return "", fmt.Errorf("identify opened %s: %w", path, err)
	}
	if pathIdentity != openedIdentity {
		return "", fmt.Errorf("%s changed identity while being opened", path)
	}
	hash := sha256.New()
	// LimitReader by one byte more than the bound so a file that grew
	// between the stat and the read is detected rather than silently
	// digested at the truncated length.
	copied, err := io.Copy(hash, io.LimitReader(file, maximumDigestedFile+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	if copied > maximumDigestedFile {
		return "", fmt.Errorf("%s grew past the digest bound while reading", path)
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("restat opened %s: %w", path, err)
	}
	finalIdentity, err := identityFromInfo(finalInfo)
	if err != nil {
		return "", fmt.Errorf("re-identify opened %s: %w", path, err)
	}
	if finalIdentity != openedIdentity || finalInfo.Size() != copied {
		return "", fmt.Errorf("%s changed identity or size while being digested", path)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openAndDigestPinnedFile(path string) (*os.File, string, error) {
	file, err := openRegularNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, "", err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, "", err
	}
	if info.Size() > maximumDigestedFile {
		_ = file.Close()
		return nil, "", fmt.Errorf("%s exceeds the digest bound", path)
	}
	hash := sha256.New()
	copied, err := io.Copy(hash, io.LimitReader(file, maximumDigestedFile+1))
	if err != nil || copied != info.Size() {
		_ = file.Close()
		if err == nil {
			err = errors.New("size changed while reading")
		}
		return nil, "", fmt.Errorf("digest opened %s: %w", path, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("rewind opened %s: %w", path, err)
	}
	return file, hex.EncodeToString(hash.Sum(nil)), nil
}

func sealRunnerCopy(
	stateRoot string, source *os.File, expectedDigest string,
) (string, *os.File, func(), error) {
	directory, err := os.MkdirTemp(stateRoot, ".runner-custody-")
	if err != nil {
		return "", nil, nil, fmt.Errorf("create runner custody directory: %w", err)
	}
	cleanup := func() {
		// #nosec G302 -- this is a private directory; owner execute is required
		// so its contents can be removed.
		_ = os.Chmod(directory, 0o700)
		_ = os.RemoveAll(directory)
	}
	path := filepath.Join(directory, "accepted-runner")
	destination, err := openRegularNoFollow(
		path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500,
	)
	if err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("create sealed runner copy: %w", err)
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, nil, fmt.Errorf("rewind runner source: %w", err)
	}
	hash := sha256.New()
	copied, err := io.Copy(
		io.MultiWriter(destination, hash),
		io.LimitReader(source, maximumDigestedFile+1),
	)
	if err != nil || copied > maximumDigestedFile {
		_ = destination.Close()
		cleanup()
		if err == nil {
			err = errors.New("runner exceeds sealed-copy bound")
		}
		return "", nil, nil, fmt.Errorf("copy sealed runner: %w", err)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		cleanup()
		return "", nil, nil, fmt.Errorf("sync sealed runner: %w", err)
	}
	if err := destination.Close(); err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("close sealed runner: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		cleanup()
		return "", nil, nil, err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != expectedDigest {
		cleanup()
		return "", nil, nil, fmt.Errorf(
			"sealed runner copy hashes to %s, expected %s", actual, expectedDigest,
		)
	}
	// #nosec G302 -- this is a sealed directory; owner execute is required.
	if err := os.Chmod(directory, 0o500); err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("seal runner custody directory: %w", err)
	}
	sealed, digest, err := openAndDigestPinnedFile(path)
	if err != nil {
		cleanup()
		return "", nil, nil, fmt.Errorf("open sealed runner descriptor: %w", err)
	}
	if digest != expectedDigest {
		_ = sealed.Close()
		cleanup()
		return "", nil, nil, fmt.Errorf(
			"opened sealed runner hashes to %s, expected %s",
			digest, expectedDigest,
		)
	}
	return path, sealed, cleanup, nil
}

// treeManifest is a deterministic listing of a directory tree: one
// "sha256␠␠relative/path" line per regular file, sorted bytewise.
//
// Anything that is not a regular file or a directory is a refusal, not a
// skipped entry. A symlink, a fifo, a socket or a device node inside a tree
// that is supposed to be an immutable snapshot means the tree is not what it
// claims to be, and a manifest that quietly omitted them would hash the same
// before and after one was added.
func treeManifest(root string) ([]byte, int, error) {
	return treeManifestDescriptor(root)
}

func treeDigest(root string) (string, int, error) {
	manifest, count, err := treeManifest(root)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:]), count, nil
}

func treeDigestDirectory(directory *secureDirectory) (string, int, error) {
	manifest, count, err := treeManifestDirectory(directory)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:]), count, nil
}

// requireNoSymlinkInPath walks every prefix of an absolute path and refuses if
// any component is a symbolic link.
//
// Resolving the path with EvalSymlinks and then using the resolved value would
// be worse than useless here: it would silently accept a tree whose location
// an attacker controls, and the digest would then be a perfectly correct digest
// of the wrong tree.
func requireNoSymlinkInPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	cleaned := filepath.Clean(path)
	var walked string
	for _, component := range strings.Split(cleaned, string(filepath.Separator)) {
		if component == "" {
			walked = string(filepath.Separator)
			continue
		}
		walked = filepath.Join(walked, component)
		info, err := os.Lstat(walked)
		if err != nil {
			return fmt.Errorf("stat path component %s: %w", walked, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf(
				"path component %s is a symbolic link; the tree it names "+
					"can be redirected after it has been pinned", walked,
			)
		}
	}
	return nil
}

// requireDisjoint refuses when one directory contains another.
//
// The comparison is on cleaned absolute paths with a trailing separator, so
// "/a/bc" is not treated as living under "/a/b" -- a prefix test without the
// separator would call those nested and refuse a legitimate layout.
func requireDisjoint(labelA, a, labelB, b string) error {
	cleanA := filepath.Clean(a)
	cleanB := filepath.Clean(b)
	if cleanA == cleanB {
		return fmt.Errorf("%s and %s are the same directory (%s)",
			labelA, labelB, cleanA)
	}
	withSeparator := func(p string) string {
		return p + string(filepath.Separator)
	}
	if strings.HasPrefix(cleanB, withSeparator(cleanA)) {
		return fmt.Errorf("%s (%s) is inside %s (%s)",
			labelB, cleanB, labelA, cleanA)
	}
	if strings.HasPrefix(cleanA, withSeparator(cleanB)) {
		return fmt.Errorf("%s (%s) is inside %s (%s)",
			labelA, cleanA, labelB, cleanB)
	}
	return nil
}
