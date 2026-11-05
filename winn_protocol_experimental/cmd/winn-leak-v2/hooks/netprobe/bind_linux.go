//go:build linux

package main

import (
	"syscall"
)

func bindControl(interfaceName string) (func(string, string, syscall.RawConn) error, error) {
	if interfaceName == "" {
		return nil, nil
	}
	return func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			// #nosec G115 -- socket descriptors are nonnegative kernel ints.
			controlErr = syscall.SetsockoptString(
				int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName,
			)
		}); err != nil {
			return err
		}
		return controlErr
	}, nil
}
