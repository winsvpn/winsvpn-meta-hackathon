package masque

import (
	"errors"
	"fmt"

	"github.com/dunglas/httpsfv"
)

// ErrStructuredFieldPanic reports that the upstream RFC 9651 Structured Fields
// parser panicked on a header value instead of returning an error.
var ErrStructuredFieldPanic = errors.New(
	"structured field parser panicked on a malformed header value",
)

// unmarshalItemSafely wraps httpsfv.UnmarshalItem so a malformed header value
// can never take the process down.
//
// The previously pinned github.com/dunglas/httpsfv v1.1.0 panics with
// an index-out-of-range instead of returning an error when a Date marker '@' is
// the final character of a header value. parseNumber calls isNeg, and isNeg
// dereferences s.data[s.off] before parseNumber performs its s.eof() check:
//
//	integer.go:95  func isNeg(s *scanner) bool { if s.data[s.off] == '-' {
//	integer.go:40  neg := isNeg(s); if neg && s.eof() { ... }
//
// Reproducing values include "@", "1;a=@", and "a;b=@". Both Winn call sites
// feed this parser bytes that a network peer controls in full:
//
//   - ParseProxyRequest reads Capsule-Protocol from an unauthenticated
//     CONNECT-UDP request, so any client could halt a proxy goroutine.
//   - nextHopAddr reads Proxy-Status from a proxy response, so a hostile or
//     tampered response could halt the user's client. Under Winn's threat model
//     a client crash is both a denial of service and a fingerprint, which makes
//     this the more serious of the two.
//
// The recover is deliberately placed around the whole third-party parser rather
// than around the single known input shape, because the defect class is
// "unchecked index in a hand-written scanner" and one bounds check is unlikely
// to be the only one. Remove this wrapper only once go.mod requires a release
// that fixes the panic and the regression tests in sfv_test.go still pass.
func unmarshalItemSafely(values []string) (item httpsfv.Item, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			item = httpsfv.Item{}
			err = fmt.Errorf("%w: %v", ErrStructuredFieldPanic, recovered)
		}
	}()
	return httpsfv.UnmarshalItem(values)
}
