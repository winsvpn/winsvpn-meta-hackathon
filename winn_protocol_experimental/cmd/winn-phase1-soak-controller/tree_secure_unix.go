//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func treeManifestDescriptor(root string) ([]byte, int, error) {
	directory, err := openSecureDirectory(root)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = directory.Close() }()
	return treeManifestDirectory(directory)
}

func treeManifestDirectory(directory *secureDirectory) ([]byte, int, error) {
	rootAttributes, err := checkDescriptorQuarantine(
		directory.file, directory.path,
	)
	if err != nil {
		return nil, 0, err
	}
	var lines []string
	entries := 1
	if err := walkDescriptorTree(
		// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
		int(directory.file.Fd()), "", &entries, &lines,
	); err != nil {
		return nil, 0, err
	}
	if err := verifyDescriptorQuarantineState(
		directory.file, directory.path, rootAttributes,
	); err != nil {
		return nil, 0, err
	}
	if err := directory.VerifyPath(); err != nil {
		return nil, 0, err
	}
	sort.Strings(lines)
	var builder strings.Builder
	for _, line := range lines {
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	return []byte(builder.String()), len(lines), nil
}

func walkDescriptorTree(
	directoryFD int, prefix string, entries *int, lines *[]string,
) error {
	duplicate, err := unix.Dup(directoryFD)
	if err != nil {
		return err
	}
	// #nosec G115 -- unix.Dup returned a nonnegative live descriptor.
	directory := os.NewFile(uintptr(duplicate), prefix)
	children, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, child := range children {
		*entries++
		if *entries > maximumSnapshotEntries {
			return fmt.Errorf("snapshot exceeds %d entries", maximumSnapshotEntries)
		}
		name := child.Name()
		relative := name
		if prefix != "" {
			relative = prefix + "/" + name
		}
		if strings.Count(relative, "/") <= 1 {
			for _, marker := range quarantineMarkers {
				if name == marker {
					return fmt.Errorf(
						"%w: snapshot marker %s is present",
						errQuarantined, relative,
					)
				}
			}
		}
		var before unix.Stat_t
		if err := unix.Fstatat(
			directoryFD, name, &before, unix.AT_SYMLINK_NOFOLLOW,
		); err != nil {
			return fmt.Errorf("stat snapshot %s: %w", relative, err)
		}
		mode := before.Mode & unix.S_IFMT
		switch mode {
		case unix.S_IFDIR:
			fd, err := unix.Openat(
				directoryFD, name,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
				0,
			)
			if err != nil {
				return fmt.Errorf("open snapshot directory %s: %w", relative, err)
			}
			var opened unix.Stat_t
			if err := unix.Fstat(fd, &opened); err != nil ||
				opened.Dev != before.Dev || opened.Ino != before.Ino {
				_ = unix.Close(fd)
				return fmt.Errorf("snapshot directory %s changed identity", relative)
			}
			// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
			openedDirectory := os.NewFile(uintptr(fd), relative)
			attributes, err := checkDescriptorQuarantine(
				openedDirectory, relative,
			)
			if err == nil {
				err = walkDescriptorTree(
					// #nosec G115 -- os.File owns a live Unix descriptor
					// represented by int.
					int(openedDirectory.Fd()), filepath.ToSlash(relative),
					entries, lines,
				)
			}
			if err == nil {
				err = verifyDescriptorQuarantineState(
					openedDirectory, relative, attributes,
				)
			}
			if err == nil {
				var after unix.Stat_t
				if statErr := unix.Fstat(
					// #nosec G115 -- os.File owns a live Unix descriptor
					// represented by int.
					int(openedDirectory.Fd()), &after,
				); statErr != nil {
					err = statErr
				} else if after.Dev != opened.Dev || after.Ino != opened.Ino {
					err = fmt.Errorf(
						"snapshot directory %s changed identity", relative,
					)
				}
			}
			closeErr := openedDirectory.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		case unix.S_IFREG:
			if uint64(before.Nlink) != 1 {
				return fmt.Errorf(
					"snapshot file %s has %d hard links", relative, before.Nlink,
				)
			}
			fd, err := unix.Openat(
				directoryFD, name,
				unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
				0,
			)
			if err != nil {
				return fmt.Errorf("open snapshot file %s: %w", relative, err)
			}
			// #nosec G115 -- unix.Openat returned a nonnegative live descriptor.
			file := os.NewFile(uintptr(fd), relative)
			attributes, err := checkDescriptorQuarantine(file, relative)
			var digest string
			if err == nil {
				digest, err = digestSnapshotDescriptor(file, before)
			}
			if err == nil {
				err = verifyDescriptorQuarantineState(
					file, relative, attributes,
				)
			}
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			*lines = append(*lines, digest+"  "+filepath.ToSlash(relative))
		default:
			return fmt.Errorf(
				"snapshot %s is not a regular file or directory (mode %#o)",
				relative, mode,
			)
		}
	}
	return nil
}

func digestSnapshotDescriptor(file *os.File, before unix.Stat_t) (string, error) {
	if before.Size < 0 || before.Size > maximumDigestedFile {
		return "", fmt.Errorf("snapshot file %s exceeds digest bound", file.Name())
	}
	hash := sha256.New()
	copied, err := io.Copy(hash, io.LimitReader(file, maximumDigestedFile+1))
	if err != nil {
		return "", err
	}
	var after unix.Stat_t
	// #nosec G115 -- os.File owns a live Unix descriptor represented by int.
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return "", err
	}
	if copied != before.Size || after.Dev != before.Dev ||
		after.Ino != before.Ino || after.Size != before.Size ||
		after.Nlink != before.Nlink {
		return "", fmt.Errorf("snapshot file %s changed during digest", file.Name())
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
