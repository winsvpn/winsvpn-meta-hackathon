//go:build !unix

package main

import (
	"fmt"
	"os"
)

func openRegularNoFollow(
	path string, _ int, _ os.FileMode,
) (*os.File, error) {
	return nil, fmt.Errorf(
		"no-follow exclusive file opens are unsupported for %s on this platform",
		path,
	)
}
