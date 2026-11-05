//go:build darwin

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// mountReadOnly is MNT_RDONLY.
const mountReadOnly = 0x1

func probeMount(path string) (mountFacts, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	return darwinMountFacts(path, stat)
}

// probeMountDescriptor binds the mount decision to the exact opened snapshot
// directory rather than resolving its pathname again.
func probeMountDescriptor(file *os.File) (mountFacts, error) {
	if file == nil {
		return mountFacts{}, fmt.Errorf("fstatfs snapshot: nil directory descriptor")
	}
	var stat unix.Statfs_t
	// #nosec G115 -- os.File owns a live Darwin descriptor represented by int.
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return mountFacts{}, fmt.Errorf("fstatfs snapshot descriptor: %w", err)
	}
	return darwinMountFacts(file.Name(), stat)
}

func darwinMountFacts(label string, stat unix.Statfs_t) (mountFacts, error) {
	blockSize := int64(stat.Bsize)
	if blockSize <= 0 {
		return mountFacts{}, fmt.Errorf(
			"statfs %s reported a non-positive block size %d",
			label, blockSize,
		)
	}
	availableBlocks, err := boundedUint64ToInt64(
		stat.Bavail, "available filesystem blocks",
	)
	if err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", label, err)
	}
	totalBlocks, err := boundedUint64ToInt64(
		stat.Blocks, "total filesystem blocks",
	)
	if err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", label, err)
	}
	return mountFacts{
		FilesystemType: nullTerminated(stat.Fstypename[:]),
		ReadOnly:       int64(stat.Flags)&mountReadOnly != 0,
		FreeBytes:      saturatingMultiply(availableBlocks, blockSize),
		TotalBytes:     saturatingMultiply(totalBlocks, blockSize),
		Available:      true,
	}, nil
}

func nullTerminated(raw []byte) string {
	out := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}
