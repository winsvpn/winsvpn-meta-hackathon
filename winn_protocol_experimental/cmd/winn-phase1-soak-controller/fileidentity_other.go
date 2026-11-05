//go:build !unix

package main

import (
	"fmt"
	"os"
)

type fileIdentity struct {
	device uint64
	inode  uint64
	nlink  uint64
}

func identityFromInfo(_ os.FileInfo) (fileIdentity, error) {
	return fileIdentity{}, fmt.Errorf(
		"stable file identity and hardlink counts are unavailable on this platform",
	)
}
