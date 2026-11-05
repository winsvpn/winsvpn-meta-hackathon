package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// InstanceLock is the exact lock plus the instance nonce.
//
// Two mechanisms, because they answer different questions and neither answers
// both:
//
//	the lock   PREVENTS a second controller from starting while this one
//	           holds the state directory. It is an advisory kernel lock on an
//	           open descriptor, so it is released by the kernel when the
//	           process dies however it dies -- no stale lock file to clean up
//	           and no pid file to misread. It is also advisory, and it is
//	           weak-to-absent on some network filesystems.
//	the nonce  DETECTS, after the fact, that two controllers nevertheless
//	           wrote to the same evidence. Every receipt and every checkpoint
//	           carries it, and the receipt chain is verified for a single
//	           unbroken nonce lineage. It prevents nothing.
//
// Claiming the nonce prevents concurrency would be the more comfortable
// sentence and would be false. It exists so that if the lock ever fails to
// hold, the evidence says so instead of quietly interleaving two runs.
type InstanceLock struct {
	descriptor  *os.File
	nonce       string
	predecessor string
	statePath   string
	directory   *secureDirectory
}

const instanceNonceBytes = 16

var errLockHeld = errors.New(
	"another controller instance holds this state directory",
)

// AcquireInstanceLock takes the lock and mints a fresh nonce.
//
// The nonce is minted while the lock is HELD, and the previous nonce is read in
// the same critical section. That ordering is what makes the lineage a chain
// rather than a set of independent claims.
func AcquireInstanceLock(stateRoot string) (*InstanceLock, error) {
	if err := ensurePrivateDirectory(stateRoot); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(stateRoot, "soak.lock")
	// Lock the stable directory inode, not the replaceable child path. A lock
	// held on soak.lock would continue protecting only the unlinked old inode
	// if an attacker renamed a new file over it.
	directory, err := openSecureDirectory(stateRoot)
	if err != nil {
		return nil, fmt.Errorf("open state directory lock %s: %w", stateRoot, err)
	}
	descriptor := directory.file
	if err := lockExclusiveNonBlocking(descriptor); err != nil {
		_ = descriptor.Close()
		directory.file = nil
		if errors.Is(err, errLockHeld) {
			return nil, fmt.Errorf("%w (%s)", errLockHeld, lockPath)
		}
		return nil, err
	}
	// Keep a diagnostic marker, but never rely on its inode for exclusion.
	marker, markerErr := directory.Open(
		"soak.lock", os.O_CREATE|os.O_WRONLY, 0o600,
	)
	if markerErr != nil {
		_ = unlockAndClose(descriptor)
		directory.file = nil
		return nil, fmt.Errorf("open lock marker %s: %w", lockPath, markerErr)
	}
	if markerErr = marker.Close(); markerErr != nil {
		_ = unlockAndClose(descriptor)
		directory.file = nil
		return nil, fmt.Errorf("close lock marker %s: %w", lockPath, markerErr)
	}

	previous := ""
	nonceFile, err := directory.Open("instance.nonce", os.O_RDONLY, 0)
	if err == nil {
		existing, readErr := io.ReadAll(
			io.LimitReader(nonceFile, instanceNonceBytes*2+1),
		)
		closeErr := nonceFile.Close()
		if readErr != nil {
			_ = unlockAndClose(descriptor)
			return nil, fmt.Errorf("read instance nonce: %w", readErr)
		}
		if closeErr != nil {
			_ = unlockAndClose(descriptor)
			return nil, fmt.Errorf("close instance nonce: %w", closeErr)
		}
		previous = string(existing)
		if !noncePattern.MatchString(previous) {
			_ = unlockAndClose(descriptor)
			return nil, errors.New(
				"prior instance nonce is not 32 lowercase hexadecimal characters",
			)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = unlockAndClose(descriptor)
		return nil, fmt.Errorf("read instance nonce: %w", err)
	}

	raw := make([]byte, instanceNonceBytes)
	if _, err := rand.Read(raw); err != nil {
		_ = unlockAndClose(descriptor)
		return nil, fmt.Errorf("mint instance nonce: %w", err)
	}
	nonce := hex.EncodeToString(raw)
	if err := atomicWriteDirectory(
		directory, "instance.nonce", []byte(nonce), 0o600,
	); err != nil {
		_ = unlockAndClose(descriptor)
		return nil, err
	}
	return &InstanceLock{
		descriptor:  descriptor,
		nonce:       nonce,
		predecessor: previous,
		statePath:   stateRoot,
		directory:   directory,
	}, nil
}

func (l *InstanceLock) Nonce() string       { return l.nonce }
func (l *InstanceLock) Predecessor() string { return l.predecessor }

func (l *InstanceLock) Release() error {
	if l == nil || l.descriptor == nil {
		return nil
	}
	descriptor := l.descriptor
	l.descriptor = nil
	err := unlockAndClose(descriptor)
	if l.directory != nil {
		l.directory.file = nil
		l.directory = nil
	}
	return err
}

var (
	// #nosec G304 -- callers pass only the validated private lock directory
	// and immediately verify the opened descriptor identity.
	atomicOpenDir     = func(path string) (*os.File, error) { return os.Open(path) }
	syncFileOperation = func(file *os.File) error { return file.Sync() }
)

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

var writeAllOperation = writeAll

func syncDirectory(path string) error {
	directory, err := atomicOpenDir(path)
	if err != nil {
		return fmt.Errorf("open directory %s for durability: %w", path, err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("sync directory %s: %w", path, err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close directory %s after sync: %w", path, err)
	}
	return nil
}
