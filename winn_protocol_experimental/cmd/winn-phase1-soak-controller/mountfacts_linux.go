//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// linuxFilesystemNames maps the statfs magic numbers this controller cares
// about. The union and interposing filesystems are the ones that matter; the
// ordinary ones are named so an operator reading a refusal message can see
// that the probe worked and the answer was simply "ext4".
var linuxFilesystemNames = map[int64]string{
	0x794c7630: "overlay",
	0x61756673: "aufs",
	0x0000f15f: "ecryptfs",
	0x65735546: "fuse",
	0x01021994: "tmpfs",
	0x73717368: "squashfs",
	0x0000ef53: "ext4",
	0x58465342: "xfs",
	0x9123683e: "btrfs",
	0x2fc12fc1: "zfs",
	0x6969696a: "nfs",
	0x00006969: "nfs",
}

// statfsReadOnly is ST_RDONLY. The constant is spelled out because
// syscall.ST_RDONLY is not defined on every Linux GOARCH this must build for.
const statfsReadOnly = 1

func probeMount(path string) (mountFacts, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", path, err)
	}
	return linuxMountFacts(path, stat)
}

// probeMountDescriptor binds the mount decision to the exact snapshot
// directory inode already held by the caller. A pathname Statfs can otherwise
// inspect an attacker-swapped replacement after the directory was opened.
func probeMountDescriptor(file *os.File) (mountFacts, error) {
	if file == nil {
		return mountFacts{}, fmt.Errorf("fstatfs snapshot: nil directory descriptor")
	}
	var stat unix.Statfs_t
	// #nosec G115 -- os.File owns a live Linux kernel descriptor represented
	// by int in the Fstatfs API.
	if err := unix.Fstatfs(int(file.Fd()), &stat); err != nil {
		return mountFacts{}, fmt.Errorf("fstatfs snapshot descriptor: %w", err)
	}
	return linuxMountFacts(file.Name(), stat)
}

func linuxMountFacts(label string, stat unix.Statfs_t) (mountFacts, error) {
	// Every field below is widened explicitly. On linux/386 Type and Bsize
	// are 32-bit and Bavail is a 32-bit unsigned; on linux/amd64 they are
	// 64-bit. Widening at the point of use is what lets one file serve both
	// without an untested per-architecture copy.
	magic := int64(stat.Type)
	name, known := linuxFilesystemNames[magic]
	if !known {
		name = fmt.Sprintf("unknown-%#x", magic)
	}
	blockSize := int64(stat.Bsize)
	if blockSize <= 0 {
		return mountFacts{}, fmt.Errorf(
			"statfs %s reported a non-positive block size %d",
			label, blockSize,
		)
	}
	availableBlocks, err := boundedUint64ToInt64(
		uint64(stat.Bavail), "available filesystem blocks",
	)
	if err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", label, err)
	}
	totalBlocks, err := boundedUint64ToInt64(
		uint64(stat.Blocks), "total filesystem blocks",
	)
	if err != nil {
		return mountFacts{}, fmt.Errorf("statfs %s: %w", label, err)
	}
	return mountFacts{
		FilesystemType: name,
		ReadOnly:       int64(stat.Flags)&statfsReadOnly != 0,
		FreeBytes:      saturatingMultiply(availableBlocks, blockSize),
		TotalBytes:     saturatingMultiply(totalBlocks, blockSize),
		Available:      true,
	}, nil
}
