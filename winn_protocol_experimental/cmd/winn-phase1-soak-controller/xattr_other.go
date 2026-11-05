//go:build !linux && !darwin

package main

import (
	"fmt"
	"os"
)

func listExtendedAttributesDescriptor(*os.File) ([]string, error) {
	return nil, fmt.Errorf(
		"this platform cannot list extended attributes through a held descriptor",
	)
}

func hasExtendedAttributeDescriptor(*os.File, string) (bool, error) {
	return false, fmt.Errorf(
		"this platform cannot inspect extended attributes through a held descriptor",
	)
}
