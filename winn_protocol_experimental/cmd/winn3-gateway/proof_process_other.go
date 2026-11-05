//go:build !linux

package main

import "errors"

func proofProcessIdentity() (string, uint64, error) {
	return "", 0, errors.New("production proof process identity is Linux-only")
}
