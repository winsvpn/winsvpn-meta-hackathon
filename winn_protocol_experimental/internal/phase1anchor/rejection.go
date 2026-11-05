// The portable half of this package.
//
// Anchor requests and receipts are a PROTOCOL: they are produced on a POSIX
// provider host, sealed into evidence, and then re-verified by third parties
// who had nothing to do with producing them. The provider's append-only ledger
// is a different thing entirely — a durable local store built on flock(2) and
// open(2) with O_NOFOLLOW, which exists only on a POSIX host and is not
// emulated anywhere else.
//
// Keeping the two in one file made the whole package POSIX-only, so
// `GOOS=windows go build ./cmd/winn-phase1-matrix-verify` failed on syscalls
// the verifier never calls. The verifier's cross-platform re-verifiability is
// the entire point of the canonical-path work in that binary, so the boundary
// is drawn here: everything a verifier needs is in this file and anchor.go,
// and the ledger is in ledger.go behind `//go:build unix`.
//
// There is deliberately NO non-unix ledger implementation. A stub that compiled
// and returned success would claim provider support that does not exist. On a
// non-POSIX host the ledger type is simply absent and the anchor server does
// not build, which is the truthful outcome.
package phase1anchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// zeroDigest is the package-level canonical constant, referenced by name so
// this file cannot drift from the exported symbol every other component uses.
const zeroDigest = ZeroDigest

// RejectionError marks an immutable semantic conflict or corrupted signed
// chain. Provider resource and I/O failures deliberately do not use this type
// so callers can pause and retry the identical request.
type RejectionError struct {
	Err error
}

func (current RejectionError) Error() string {
	return current.Err.Error()
}

func (current RejectionError) Unwrap() error {
	return current.Err
}

func IsRejection(err error) bool {
	var rejection RejectionError
	return errors.As(err, &rejection)
}

// decodeStrict is used by the portable request/receipt decoders as well as by
// the ledger, so it lives on this side of the boundary.
func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
