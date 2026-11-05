//go:build !linux

package main

import (
	"errors"
	"syscall"
)

func bindControl(interfaceName string) (func(string, string, syscall.RawConn) error, error) {
	if interfaceName != "" {
		return nil, errors.New("interface binding requires Linux")
	}
	return nil, nil
}
