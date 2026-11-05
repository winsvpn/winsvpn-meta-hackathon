//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type secureRoot struct {
	root     *os.Root
	path     string
	identity os.FileInfo
}

func openSecureRoot(name string) (*secureRoot, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
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
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(
		strings.TrimPrefix(absolute, current),
		string(filepath.Separator),
	) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, inspectErr := os.Lstat(current)
		if inspectErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("evidence root contains a symlink or non-directory")
		}
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, errors.New("cannot open evidence root")
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(rootInfo, openedInfo) {
		_ = root.Close()
		return nil, errors.New("evidence-root identity changed while opening")
	}
	return &secureRoot{
		root:     root,
		path:     absolute,
		identity: openedInfo,
	}, nil
}

func (root *secureRoot) Close() error {
	if root == nil || root.root == nil {
		return nil
	}
	return root.root.Close()
}

func (root *secureRoot) readRegular(
	name string,
	maximum int64,
	hooks verificationHooks,
) ([]byte, error) {
	if root == nil || root.root == nil {
		return nil, errors.New("evidence root is closed")
	}
	if !root.identityUnchanged() {
		return nil, errors.New("evidence-root identity changed")
	}
	if err := validateRelativePath(name); err != nil {
		return nil, errors.New("path is not an allowed fixed evidence path")
	}
	prefixes := pathPrefixes(name)
	directoryIdentities := make([]os.FileInfo, 0, len(prefixes)-1)
	for _, component := range prefixes[:len(prefixes)-1] {
		info, err := root.root.Lstat(component)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("evidence path contains a symlink")
		}
		directoryIdentities = append(directoryIdentities, info)
	}
	before, err := root.root.Lstat(name)
	if err != nil || !boundedRegularInfo(before, maximum) {
		return nil, errors.New("evidence file is not a bounded regular file")
	}
	file, err := root.root.Open(name)
	if err != nil {
		return nil, errors.New("cannot open evidence file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) ||
		!boundedRegularInfo(opened, maximum) {
		return nil, errors.New("evidence file identity changed before read")
	}
	if hooks.afterOpen != nil {
		hooks.afterOpen(name)
	}
	content, err := readBounded(file, maximum)
	if err != nil {
		return nil, err
	}
	after, descriptorErr := file.Stat()
	pathAfter, pathErr := root.root.Lstat(name)
	if descriptorErr != nil || pathErr != nil ||
		!os.SameFile(opened, after) ||
		!os.SameFile(opened, pathAfter) ||
		!boundedRegularInfo(after, maximum) ||
		after.Size() != opened.Size() ||
		after.Size() != int64(len(content)) ||
		pathAfter.Size() != after.Size() {
		return nil, errors.New("evidence file identity or size changed during read")
	}
	for index, component := range prefixes[:len(prefixes)-1] {
		info, err := root.root.Lstat(component)
		if err != nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(directoryIdentities[index], info) {
			return nil, errors.New("evidence directory identity changed during read")
		}
	}
	if !root.identityUnchanged() {
		return nil, errors.New("evidence-root identity changed during read")
	}
	return content, nil
}

func (root *secureRoot) identityUnchanged() bool {
	if root == nil || root.root == nil || root.identity == nil {
		return false
	}
	descriptor, descriptorErr := root.root.Stat(".")
	path, pathErr := os.Lstat(root.path)
	return descriptorErr == nil &&
		pathErr == nil &&
		path.IsDir() &&
		path.Mode()&os.ModeSymlink == 0 &&
		os.SameFile(root.identity, descriptor) &&
		os.SameFile(root.identity, path)
}

func pathPrefixes(name string) []string {
	components := strings.Split(name, "/")
	prefixes := make([]string, 0, len(components))
	var current string
	for _, component := range components {
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		prefixes = append(prefixes, current)
	}
	return prefixes
}

func boundedRegularInfo(info os.FileInfo, maximum int64) bool {
	return info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maximum
}
