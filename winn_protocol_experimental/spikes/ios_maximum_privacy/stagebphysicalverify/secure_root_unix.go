//go:build darwin || linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type secureRoot struct {
	file     *os.File
	path     string
	identity os.FileInfo
}

type unixDirectoryLink struct {
	parent   int
	name     string
	identity unix.Stat_t
}

func openSecureRoot(name string) (*secureRoot, error) {
	absolute, err := filepath.Abs(name)
	if err != nil || !filepath.IsAbs(absolute) {
		return nil, errors.New("cannot resolve evidence root")
	}
	rootInfo, err := os.Lstat(absolute)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence root is a symlink or non-directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, errors.New("cannot resolve evidence-root ancestors")
	}
	absolute = filepath.Join(resolvedParent, filepath.Base(absolute))
	current, err := unix.Open(
		string(filepath.Separator),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, errors.New("cannot open evidence root")
	}
	owned := true
	defer func() {
		if owned {
			_ = unix.Close(current)
		}
	}()
	for _, component := range strings.Split(
		strings.TrimPrefix(absolute, string(filepath.Separator)),
		string(filepath.Separator),
	) {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if openErr != nil {
			return nil, errors.New("evidence root contains a symlink or non-directory")
		}
		_ = unix.Close(current)
		current = next
	}
	owned = false
	rootFile, fileErr := ownUnixDescriptor(current, absolute)
	if fileErr != nil {
		_ = unix.Close(current)
		return nil, errors.New("cannot own evidence-root descriptor")
	}
	openedInfo, err := rootFile.Stat()
	if err != nil || !os.SameFile(rootInfo, openedInfo) {
		_ = rootFile.Close()
		return nil, errors.New("evidence-root identity changed while opening")
	}
	return &secureRoot{
		file:     rootFile,
		path:     absolute,
		identity: openedInfo,
	}, nil
}

func (root *secureRoot) Close() error {
	if root == nil || root.file == nil {
		return nil
	}
	err := root.file.Close()
	root.file = nil
	if err != nil {
		return errors.New("cannot close evidence root")
	}
	return nil
}

func (root *secureRoot) readRegular(
	name string,
	maximum int64,
	hooks verificationHooks,
) ([]byte, error) {
	if root == nil || root.file == nil {
		return nil, errors.New("evidence root is closed")
	}
	if !root.identityUnchanged() {
		return nil, errors.New("evidence-root identity changed")
	}
	if err := validateRelativePath(name); err != nil {
		return nil, errors.New("path is not an allowed fixed evidence path")
	}
	components := strings.Split(name, "/")
	parent, descriptorErr := unixDescriptor(root.file.Fd())
	if descriptorErr != nil {
		return nil, errors.New("evidence-root descriptor is invalid")
	}
	var openedDirectories []int
	defer func() {
		for index := len(openedDirectories) - 1; index >= 0; index-- {
			_ = unix.Close(openedDirectories[index])
		}
	}()
	var directoryLinks []unixDirectoryLink
	for _, component := range components[:len(components)-1] {
		var before unix.Stat_t
		if err := unix.Fstatat(
			parent,
			component,
			&before,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil || before.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, errors.New("evidence path component is not a directory")
		}
		next, err := unix.Openat(
			parent,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0,
		)
		if err != nil {
			return nil, errors.New("evidence path contains a symlink or non-directory")
		}
		var opened unix.Stat_t
		if err := unix.Fstat(next, &opened); err != nil ||
			opened.Mode&unix.S_IFMT != unix.S_IFDIR ||
			!sameUnixFile(before, opened) {
			_ = unix.Close(next)
			return nil, errors.New("evidence directory identity changed while opening")
		}
		directoryLinks = append(directoryLinks, unixDirectoryLink{
			parent:   parent,
			name:     component,
			identity: opened,
		})
		openedDirectories = append(openedDirectories, next)
		parent = next
	}
	base := components[len(components)-1]
	var before unix.Stat_t
	if err := unix.Fstatat(parent, base, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, errors.New("cannot inspect evidence file")
	}
	if !boundedRegularUnix(before, maximum) {
		return nil, errors.New("evidence file is not a bounded regular file")
	}
	fd, err := unix.Openat(
		parent,
		base,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, errors.New("cannot open evidence file without following links")
	}
	file, fileErr := ownUnixDescriptor(fd, name)
	if fileErr != nil {
		_ = unix.Close(fd)
		return nil, errors.New("cannot own evidence file descriptor")
	}
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil ||
		!sameUnixFile(before, opened) ||
		!boundedRegularUnix(opened, maximum) {
		return nil, errors.New("evidence file identity changed before read")
	}
	if hooks.afterOpen != nil {
		hooks.afterOpen(name)
	}
	content, err := readBounded(file, maximum)
	if err != nil {
		return nil, err
	}
	var after, pathAfter unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil ||
		errAfterPath(parent, base, &pathAfter) != nil ||
		!sameUnixFile(opened, after) ||
		!sameUnixFile(opened, pathAfter) ||
		!boundedRegularUnix(after, maximum) ||
		after.Size != opened.Size ||
		after.Size != int64(len(content)) ||
		pathAfter.Size != after.Size {
		return nil, errors.New("evidence file identity or size changed during read")
	}
	for _, link := range directoryLinks {
		var pathAfter unix.Stat_t
		if err := unix.Fstatat(
			link.parent,
			link.name,
			&pathAfter,
			unix.AT_SYMLINK_NOFOLLOW,
		); err != nil ||
			pathAfter.Mode&unix.S_IFMT != unix.S_IFDIR ||
			!sameUnixFile(link.identity, pathAfter) {
			return nil, errors.New("evidence directory identity changed during read")
		}
	}
	if !root.identityUnchanged() {
		return nil, errors.New("evidence-root identity changed during read")
	}
	return content, nil
}

func unixDescriptor(descriptor uintptr) (int, error) {
	if descriptor > uintptr(^uint(0)>>1) {
		return 0, errors.New("descriptor exceeds platform integer range")
	}
	return int(descriptor), nil
}

func ownUnixDescriptor(descriptor int, name string) (*os.File, error) {
	if descriptor < 0 {
		return nil, errors.New("descriptor is negative")
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		return nil, errors.New("cannot own descriptor")
	}
	return file, nil
}

func (root *secureRoot) identityUnchanged() bool {
	if root == nil || root.file == nil || root.identity == nil {
		return false
	}
	descriptor, descriptorErr := root.file.Stat()
	path, pathErr := os.Lstat(root.path)
	return descriptorErr == nil &&
		pathErr == nil &&
		path.IsDir() &&
		path.Mode()&os.ModeSymlink == 0 &&
		os.SameFile(root.identity, descriptor) &&
		os.SameFile(root.identity, path)
}

func errAfterPath(parent int, name string, stat *unix.Stat_t) error {
	return unix.Fstatat(parent, name, stat, unix.AT_SYMLINK_NOFOLLOW)
}

func boundedRegularUnix(stat unix.Stat_t, maximum int64) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Size > 0 &&
		stat.Size <= maximum
}

func sameUnixFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}
