//go:build !linux

package main

import (
	"errors"
	"io"
)

func acquireProofStatusLease(path string) (io.Closer, error) {
	if path == "" {
		return noOpProofStatusLease{}, nil
	}
	return nil, errors.New("production proof status is Linux-only")
}

func writeProofStatusFile(path string, status proofStatus) error {
	_ = path
	_ = status
	return errors.New("production proof status is Linux-only")
}

func invalidateProofStatusFile(path, processNonce string, removeForeign bool) error {
	if path == "" {
		return nil
	}
	_ = processNonce
	_ = removeForeign
	return errors.New("production proof status is Linux-only")
}
