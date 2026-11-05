//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const proofStatusLeaseName = "\x00winsvpn-winn3-gateway-proof-status-v2"

func acquireProofStatusLease(path string) (io.Closer, error) {
	if path == "" {
		return noOpProofStatusLease{}, nil
	}
	if path != proofStatusPath {
		return nil, errors.New("proof status lease path is not canonical")
	}
	return net.ListenUnixgram("unixgram", &net.UnixAddr{Name: proofStatusLeaseName, Net: "unixgram"})
}

func openProofStatusDirectory(path string) (int, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return -1, "", errors.New("proof status path is not absolute")
	}
	base := filepath.Base(clean)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return -1, "", errors.New("proof status path has no filename")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(clean), string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			unix.Close(fd)
			return -1, "", errors.New("proof status path contains an unsafe component")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if openErr != nil {
			return -1, "", openErr
		}
		fd = next
	}
	return fd, base, nil
}

func safeProofStatusStat(st *unix.Stat_t, expectedSize int64) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG &&
		st.Nlink == 1 &&
		st.Uid == uint32(os.Geteuid()) &&
		st.Mode&0o777 == 0o600 &&
		(expectedSize < 0 || st.Size == expectedSize)
}

func sameProofStatusFile(a, b *unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino
}

func verifyNamedProofStatusLock(directoryFD int, expected *unix.Stat_t) error {
	var named unix.Stat_t
	if err := unix.Fstatat(directoryFD, ".status-json.lock", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !safeProofStatusStat(&named, 0) || !sameProofStatusFile(expected, &named) {
		return errors.New("proof status lock pathname changed while locked")
	}
	return nil
}

func readProofStatusAt(directoryFD int, base string, expected *unix.Stat_t) (proofStatus, error) {
	statusFD, err := unix.Openat(directoryFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return proofStatus{}, err
	}
	statusFile := os.NewFile(uintptr(statusFD), "proof-status")
	if statusFile == nil {
		_ = unix.Close(statusFD)
		return proofStatus{}, errors.New("open proof status file")
	}
	var opened unix.Stat_t
	if err := unix.Fstat(statusFD, &opened); err != nil {
		_ = statusFile.Close()
		return proofStatus{}, err
	}
	if !safeProofStatusStat(&opened, -1) || !sameProofStatusFile(expected, &opened) {
		_ = statusFile.Close()
		return proofStatus{}, errors.New("proof status file changed before it was read")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(statusFile, 8193))
	closeErr := statusFile.Close()
	if readErr != nil {
		return proofStatus{}, readErr
	}
	if closeErr != nil {
		return proofStatus{}, closeErr
	}
	if len(encoded) > 8192 {
		return proofStatus{}, errors.New("proof status file is oversized")
	}
	var current proofStatus
	if err := json.Unmarshal(encoded, &current); err != nil {
		return proofStatus{}, errors.New("proof status file is malformed")
	}
	return current, nil
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func writeProofStatusFile(path string, status proofStatus) error {
	encoded, err := json.Marshal(status)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	directoryFD, base, err := openProofStatusDirectory(path)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if err := unix.Fstat(directoryFD, &directory); err != nil {
		return err
	}
	if directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != uint32(os.Geteuid()) || directory.Mode&0o777 != 0o700 {
		return errors.New("proof status directory ownership or mode is unsafe")
	}
	lockFD, err := unix.Openat(directoryFD, ".status-json.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || !safeProofStatusStat(&lockStat, 0) {
		return errors.New("proof status lock ownership or mode is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if err := verifyNamedProofStatusLock(directoryFD, &lockStat); err != nil {
		return err
	}

	var existing unix.Stat_t
	existingPresent := false
	if err := unix.Fstatat(directoryFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		existingPresent = true
		if !safeProofStatusStat(&existing, -1) {
			return errors.New("existing proof status file ownership or mode is unsafe")
		}
		current, readErr := readProofStatusAt(directoryFD, base, &existing)
		if readErr != nil {
			return readErr
		}
		if !sameProofStatusProcess(current, status) {
			return errors.New("existing proof status belongs to another process")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := ".status-json-" + hex.EncodeToString(random[:])
	temporaryFD, err := unix.Openat(
		directoryFD,
		temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if temporaryFD >= 0 {
			_ = unix.Close(temporaryFD)
		}
		if !committed {
			_ = unix.Unlinkat(directoryFD, temporary, 0)
		}
	}()
	if err := writeAll(temporaryFD, encoded); err != nil {
		return err
	}
	if err := unix.Fchmod(temporaryFD, 0o600); err != nil {
		return err
	}
	if err := unix.Fsync(temporaryFD); err != nil {
		return err
	}
	var created unix.Stat_t
	if err := unix.Fstat(temporaryFD, &created); err != nil {
		return err
	}
	if !safeProofStatusStat(&created, int64(len(encoded))) {
		return errors.New("temporary proof status file ownership or mode is unsafe")
	}
	fdToClose := temporaryFD
	temporaryFD = -1
	if err := unix.Close(fdToClose); err != nil {
		return err
	}
	if err := verifyNamedProofStatusLock(directoryFD, &lockStat); err != nil {
		return err
	}
	var latest unix.Stat_t
	latestErr := unix.Fstatat(directoryFD, base, &latest, unix.AT_SYMLINK_NOFOLLOW)
	if existingPresent {
		if latestErr != nil || !sameProofStatusFile(&existing, &latest) {
			return errors.New("proof status file changed before replacement")
		}
		// Swap atomically so the status name never goes missing; the
		// previous status is then at the temporary name and is removed.
		if err := unix.Renameat2(directoryFD, temporary, directoryFD, base, unix.RENAME_EXCHANGE); err != nil {
			return err
		}
		if err := unix.Unlinkat(directoryFD, temporary, 0); err != nil {
			return err
		}
	} else if !errors.Is(latestErr, unix.ENOENT) {
		if latestErr == nil {
			return errors.New("proof status file appeared before publication")
		}
		return latestErr
	} else if err := unix.Renameat2(directoryFD, temporary, directoryFD, base, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	committed = true
	if err := unix.Fsync(directoryFD); err != nil {
		return err
	}
	finishedFD, err := unix.Openat(directoryFD, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(finishedFD)
	var finished unix.Stat_t
	if err := unix.Fstat(finishedFD, &finished); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(directoryFD, base, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !safeProofStatusStat(&finished, int64(len(encoded))) ||
		!sameProofStatusFile(&created, &finished) ||
		!sameProofStatusFile(&finished, &named) {
		return errors.New("published proof status file ownership or mode is unsafe")
	}
	return nil
}

func invalidateProofStatusFile(path, processNonce string, removeForeign bool) error {
	if path == "" {
		return nil
	}
	directoryFD, base, err := openProofStatusDirectory(path)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	if err := unix.Fstat(directoryFD, &directory); err != nil {
		return err
	}
	if directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != uint32(os.Geteuid()) || directory.Mode&0o777 != 0o700 {
		return errors.New("proof status directory ownership or mode is unsafe")
	}
	lockFD, err := unix.Openat(directoryFD, ".status-json.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil || !safeProofStatusStat(&lockStat, 0) {
		return errors.New("proof status lock ownership or mode is unsafe")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	if err := verifyNamedProofStatusLock(directoryFD, &lockStat); err != nil {
		return err
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(directoryFD, base, &existing, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if !safeProofStatusStat(&existing, -1) {
		return errors.New("refusing to invalidate unsafe proof status file")
	}
	current, readErr := readProofStatusAt(directoryFD, base, &existing)
	if readErr != nil {
		return readErr
	}
	if current.ProcessNonce != processNonce {
		if !removeForeign {
			return nil
		}
		live, liveErr := proofStatusProcessIsLive(current)
		if liveErr != nil {
			return liveErr
		}
		if live {
			return errors.New("active process owns the proof status file")
		}
	}
	if err := verifyNamedProofStatusLock(directoryFD, &lockStat); err != nil {
		return err
	}
	var latest unix.Stat_t
	if err := unix.Fstatat(directoryFD, base, &latest, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameProofStatusFile(&existing, &latest) {
		return errors.New("proof status file changed before invalidation")
	}
	if err := unix.Unlinkat(directoryFD, base, 0); err != nil {
		return err
	}
	return unix.Fsync(directoryFD)
}

func init() {
	if proofStatusPath != "/run/winn3-gateway/status.json" {
		panic(fmt.Sprintf("unexpected proof status path %q", proofStatusPath))
	}
}
