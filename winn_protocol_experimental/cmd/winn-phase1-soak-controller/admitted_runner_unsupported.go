//go:build !linux

package main

import (
	"context"
	"errors"
	"os"
)

func runAdmittedCommand(
	context.Context, *os.File, []*os.File, string, []string,
) ([]byte, error) {
	return nil, errors.New("admitted launcher execution is Linux-only")
}
