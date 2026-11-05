//go:build !unix

package main

import "fmt"

func treeManifestDescriptor(root string) ([]byte, int, error) {
	return nil, 0, fmt.Errorf(
		"descriptor-relative snapshot traversal unsupported for %s", root,
	)
}

func treeManifestDirectory(directory *secureDirectory) ([]byte, int, error) {
	return nil, 0, fmt.Errorf(
		"descriptor-relative snapshot traversal unsupported for %s",
		directory.path,
	)
}
