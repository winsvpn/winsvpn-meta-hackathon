//go:build linux && winn_incomplete_e8

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// e8FileObjectIdentity extracts the device and inode of an already-opened
// object from the descriptor's own stat result.
func e8FileObjectIdentity(info os.FileInfo) (uint64, uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	// #nosec G115 -- device and inode numbers are nonnegative kernel values.
	return uint64(stat.Dev), uint64(stat.Ino), true
}

// e8RunningSupervisorImage opens the kernel's handle to the image actually
// loaded for this process. It deliberately does not resolve os.Executable:
// that pathname can be atomically replaced after exec.
func e8RunningSupervisorImage() (*os.File, string, os.FileInfo, error) {
	fd, err := unix.Open("/proc/self/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", nil, errors.New(
			"E8 running supervisor image descriptor is unavailable",
		)
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	running := os.NewFile(uintptr(fd), "/proc/self/exe")
	if running == nil {
		_ = unix.Close(fd)
		return nil, "", nil, errors.New(
			"E8 running supervisor image descriptor is unadoptable",
		)
	}
	info, err := running.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maximumDigestedFile {
		_ = running.Close()
		return nil, "", nil, errors.New(
			"E8 running supervisor image is unmeasurable",
		)
	}
	hash := sha256.New()
	copied, err := io.Copy(
		hash,
		io.LimitReader(running, maximumDigestedFile+1),
	)
	if err != nil || copied != info.Size() {
		_ = running.Close()
		if err == nil {
			err = errors.New("size changed while reading")
		}
		return nil, "", nil, fmt.Errorf(
			"E8 running supervisor image is unreadable: %w",
			err,
		)
	}
	finalInfo, err := running.Stat()
	if err != nil || !os.SameFile(info, finalInfo) ||
		finalInfo.Size() != copied {
		_ = running.Close()
		return nil, "", nil, errors.New(
			"E8 running supervisor image changed while measured",
		)
	}
	if _, err := running.Seek(0, io.SeekStart); err != nil {
		_ = running.Close()
		return nil, "", nil, errors.New(
			"E8 running supervisor image cannot be retained",
		)
	}
	return running, hex.EncodeToString(hash.Sum(nil)), finalInfo, nil
}

// verifyE8SupervisorIdentity binds the E6-declared supervisor executable to
// the running supervisor image.
//
// The declared path is opened with a retained no-follow descriptor and
// digested. The digest must equal the E6 declaration, and the opened object
// must be the same device/inode as the running supervisor process image.
// Identical bytes at a different inode are rejected: a mutable path is never
// accepted as equivalent to the running supervisor.
//
// On success the caller owns the returned identity and must Close it exactly
// once. On any failure the retained descriptor is released here and the
// returned identity is nil.
func verifyE8SupervisorIdentity(
	receipt e6VerificationReceipt,
) (*e8SupervisorIdentity, error) {
	if err := e8SupervisorDeclaredPath(
		receipt.SupervisorExecutablePath,
	); err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(receipt.SupervisorExecutableSHA256) {
		return nil, errors.New("E8 supervisor executable digest is malformed")
	}
	running, runningDigest, runningInfo, err := e8RunningSupervisorImage()
	if err != nil {
		return nil, err
	}
	releaseRunning := func(cause error) (*e8SupervisorIdentity, error) {
		_ = running.Close()
		return nil, cause
	}
	runningDevice, runningInode, ok :=
		e8FileObjectIdentity(runningInfo)
	if !ok || runningDevice == 0 || runningInode == 0 {
		return releaseRunning(errors.New(
			"E8 running supervisor image identity is incomplete",
		))
	}
	declared, declaredDigest, err := openAndDigestPinnedFile(
		receipt.SupervisorExecutablePath,
	)
	if err != nil {
		return releaseRunning(errors.New(
			"E8 supervisor executable is unreadable",
		))
	}
	release := func(cause error) (*e8SupervisorIdentity, error) {
		_ = declared.Close()
		_ = running.Close()
		return nil, cause
	}
	if runningDigest != receipt.SupervisorExecutableSHA256 ||
		declaredDigest != receipt.SupervisorExecutableSHA256 {
		return release(errors.New("E8 supervisor executable digest mismatch"))
	}
	declaredInfo, err := declared.Stat()
	if err != nil {
		return release(errors.New("E8 supervisor executable is unmeasurable"))
	}
	device, inode, ok := e8FileObjectIdentity(declaredInfo)
	if !ok {
		return release(errors.New("E8 supervisor executable identity is unavailable"))
	}
	if device != runningDevice || inode != runningInode {
		return release(errors.New(
			"E8 supervisor executable is not the running supervisor image",
		))
	}
	if err := declared.Close(); err != nil {
		return releaseRunning(errors.New(
			"E8 supervisor executable descriptor release failed",
		))
	}
	identity, err := e8SupervisorMeasure(
		receipt,
		running,
		runningInfo,
		runningDevice,
		runningInode,
	)
	if err != nil {
		return releaseRunning(err)
	}
	return identity, nil
}
