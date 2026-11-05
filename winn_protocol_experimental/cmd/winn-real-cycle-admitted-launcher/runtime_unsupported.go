//go:build !linux

package main

import (
	"errors"
	"time"
)

func newProductionRuntime(
	_, _, _ string,
	_ time.Duration,
) (durableRuntime, error) {
	return nil, errors.New(
		"admitted launcher requires Linux renameat2 and /proc/self/fd",
	)
}
