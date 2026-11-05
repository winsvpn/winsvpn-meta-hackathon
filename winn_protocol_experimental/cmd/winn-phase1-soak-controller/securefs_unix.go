//go:build unix

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type secureDirectory struct {
	path string
	file *os.File
	id   fileIdentity
}

var secureDirectorySyncOperation = func(
	directory *secureDirectory,
) error {
	return directory.Sync()
}

func openSecureDirectory(path string) (*secureDirectory, error) {
	fd, err := unix.Open(
		path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("open stable directory %s: %w", path, err)
	}
	// #nosec G115 -- unix.Open returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	id, err := identityFromInfo(info)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &secureDirectory{path: path, file: file, id: id}, nil
}

func (d *secureDirectory) Open(
	name string, flags int, permission os.FileMode,
) (*os.File, error) {
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("unsafe directory-relative name %q", name)
	}
	fd, err := unix.Openat(
		// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
		int(d.file.Fd()), name,
		flags|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		uint32(permission.Perm()),
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	id, err := identityFromInfo(info)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if id.nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("%s has %d hard links, expected one", name, id.nlink)
	}
	return file, nil
}

func (d *secureDirectory) OpenDirectory(name string) (*secureDirectory, error) {
	if name == "" || name != filepath.Base(name) {
		return nil, fmt.Errorf("unsafe directory-relative name %q", name)
	}
	fd, err := unix.Openat(
		// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
		int(d.file.Fd()), name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	id, err := identityFromInfo(info)
	if err != nil || id.nlink < 1 {
		_ = file.Close()
		return nil, fmt.Errorf("%s has invalid directory identity", name)
	}
	return &secureDirectory{
		path: filepath.Join(d.path, name), file: file, id: id,
	}, nil
}

func (d *secureDirectory) Mkdir(name string, permission os.FileMode) error {
	if name == "" || name != filepath.Base(name) {
		return fmt.Errorf("unsafe directory-relative name %q", name)
	}
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	return unix.Mkdirat(int(d.file.Fd()), name, uint32(permission.Perm()))
}

func (d *secureDirectory) Temp(permission os.FileMode) (*os.File, string, error) {
	for range 128 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", err
		}
		name := ".winn-soak-" + hex.EncodeToString(random)
		file, err := d.Open(
			name, os.O_CREATE|os.O_EXCL|os.O_RDWR, permission,
		)
		if os.IsExist(err) {
			continue
		}
		return file, name, err
	}
	return nil, "", fmt.Errorf("cannot allocate unique temporary file")
}

func (d *secureDirectory) Rename(from, to string) error {
	return unix.Renameat(
		// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
		int(d.file.Fd()), from, int(d.file.Fd()), to,
	)
}

func (d *secureDirectory) Remove(name string) error {
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	return unix.Unlinkat(int(d.file.Fd()), name, 0)
}

func (d *secureDirectory) Sync() error { return d.file.Sync() }

func (d *secureDirectory) FreeBytes() (int64, error) {
	var facts unix.Statfs_t
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	if err := unix.Fstatfs(int(d.file.Fd()), &facts); err != nil {
		return 0, err
	}
	availableBlocks, err := boundedUint64ToInt64(
		uint64(facts.Bavail), "available filesystem blocks",
	)
	if err != nil || facts.Bsize <= 0 {
		if err != nil {
			return 0, err
		}
		return 0, errors.New("filesystem block size is not positive")
	}
	return saturatingMultiply(availableBlocks, int64(facts.Bsize)), nil
}

func (d *secureDirectory) ReadDir() ([]os.DirEntry, error) {
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	duplicate, err := unix.Dup(int(d.file.Fd()))
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- unix.Dup returned a nonnegative live descriptor.
	file := os.NewFile(uintptr(duplicate), d.path)
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	return entries, closeErr
}

func (d *secureDirectory) Close() error {
	if d == nil || d.file == nil {
		return nil
	}
	file := d.file
	d.file = nil
	return file.Close()
}

func (d *secureDirectory) VerifyPath() error {
	info, err := os.Lstat(d.path)
	if err != nil {
		return err
	}
	id, err := identityFromInfo(info)
	if err != nil {
		return err
	}
	if id.device != d.id.device || id.inode != d.id.inode {
		return fmt.Errorf("directory %s changed device/inode identity", d.path)
	}
	return nil
}

func atomicWriteDirectory(
	directory *secureDirectory, name string, data []byte, permission os.FileMode,
) error {
	temporary, temporaryName, err := directory.Temp(permission)
	if err != nil {
		return err
	}
	abandon := func() {
		_ = temporary.Close()
		_ = directory.Remove(temporaryName)
	}
	if err := writeAllOperation(temporary, data); err != nil {
		abandon()
		return err
	}
	if err := syncFileOperation(temporary); err != nil {
		abandon()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = directory.Remove(temporaryName)
		return err
	}
	if err := directory.Rename(temporaryName, name); err != nil {
		_ = directory.Remove(temporaryName)
		return err
	}
	if err := secureDirectorySyncOperation(directory); err != nil {
		return err
	}
	return directory.VerifyPath()
}
