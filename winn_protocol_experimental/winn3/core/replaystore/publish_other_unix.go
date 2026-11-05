//go:build !windows && !darwin && !linux

package replaystore

import "errors"

var errAtomicNoReplaceUnsupported = errors.New("atomic no-replace rename is unsupported on this Unix platform")

func atomicNoReplaceSupported() bool { return false }

func renameNoReplaceAt(int, string, int, string) error {
	return errAtomicNoReplaceUnsupported
}

func renameNoReplace(string, string) error {
	return errAtomicNoReplaceUnsupported
}
