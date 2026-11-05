package main

import (
	"fmt"
	"io"
)

// True oversize rejection for the verifier's streaming parsers.
//
// io.LimitReader(file, N) STOPS at N and reports a clean EOF. Every parser
// built on it therefore treats the first N bytes as the whole file: a manifest,
// a schedule, a key/value record or an audit trail that is one byte longer is
// silently parsed as a valid-looking prefix, and whatever follows — a duplicate
// key, an extra manifest line, additional audit records — is never seen. The
// parser reports success over content it never read.
//
// That is worse than a size error, because the truncated prefix is usually
// still syntactically valid. `readSecureRegular` already got this right by
// reading N+1 and refusing when the extra byte materialises; the streaming
// parsers did not, and this type gives them the same property.
//
// The rule: read through maximum+1. A file of exactly maximum bytes reaches EOF
// at maximum and never yields the extra byte; a file with more yields it, and
// exceeded() then reports the overflow. One byte past the limit is the smallest
// observation that distinguishes "exactly at the limit" from "over it".
type boundedRead struct {
	limited *io.LimitedReader
	maximum int64
}

func newBoundedReader(reader io.Reader, maximum int64) *boundedRead {
	return &boundedRead{
		limited: &io.LimitedReader{R: reader, N: maximum + 1},
		maximum: maximum,
	}
}

func (b *boundedRead) Read(buffer []byte) (int, error) {
	return b.limited.Read(buffer)
}

// consumed reports how many bytes the parser actually received.
func (b *boundedRead) consumed() int64 {
	return b.maximum + 1 - b.limited.N
}

// exceeded reports whether the input was larger than the limit allows.
func (b *boundedRead) exceeded() bool {
	return b.consumed() > b.maximum
}

// check is called after a parser finishes. It converts "the parser stopped"
// into "the parser saw the whole file", which is the only condition under which
// its verdict describes the file rather than a prefix of it.
func (b *boundedRead) check(what string) error {
	if b.exceeded() {
		return fmt.Errorf(
			"%s exceeds the %d-byte limit; refusing to accept a prefix of it "+
				"as the whole file, because a truncated prefix is usually "+
				"still syntactically valid and would parse as a smaller, "+
				"different document", what, b.maximum,
		)
	}
	return nil
}

// classify reports the size overflow in preference to a parse error.
//
// An oversized file usually manifests FIRST as a syntax error: the reader
// delivers maximum+1 bytes, which cuts the tail mid-line, and the parser
// rejects the fragment before anything checks the bound. That rejection is
// correct but it misdescribes the problem — it reports "invalid line" for a
// file whose real defect is that it is too large, and it is fragile, because a
// tail that happened to be cut at a line boundary would parse cleanly and the
// oversize would go unreported.
//
// So every parse-error path consults the bound first.
func (b *boundedRead) classify(err error, what string) error {
	if b.exceeded() {
		return b.check(what)
	}
	return err
}
