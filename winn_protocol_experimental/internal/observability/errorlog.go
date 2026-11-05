package observability

import (
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
)

// RedactedAddress replaces any peer network address removed from an
// operational log line.
const RedactedAddress = "[redacted-peer]"

// PeerRedactingWriter wraps an operational log sink and removes peer network
// addresses before they reach durable storage.
//
// net/http and golang.org/x/net/http2 emit unrecoverable-connection diagnostics
// through Server.ErrorLog with the peer address interpolated by the standard
// library, for example:
//
//	http: TLS handshake error from 203.0.113.7:44100: unexpected EOF
//
// The format string is not configurable, so the writer is the only interception
// point. On a circumvention gateway a durable record of which addresses reached
// the endpoint is a safety hazard for the people using it, and an unauthenticated
// peer can force one such line per aborted handshake. The error class is
// preserved because it carries the operational signal; the address is not.
type PeerRedactingWriter struct {
	mu    sync.Mutex
	inner io.Writer
}

// NewPeerRedactingWriter returns a writer that strips peer IP addresses from
// every line written through it.
func NewPeerRedactingWriter(inner io.Writer) *PeerRedactingWriter {
	return &PeerRedactingWriter{inner: inner}
}

// ErrorLogger builds a *log.Logger suitable for http.Server.ErrorLog.
// Addresses in the standard-library forms (whitespace-delimited host:port
// and net.OpError's local->remote glue) are replaced with RedactedAddress;
// the error class is preserved. Flags are 0: the prefix is the only
// decoration; the caller chooses a sink that supplies its own timestamps
// if it needs them.
func ErrorLogger(inner io.Writer, prefix string) *log.Logger {
	return log.New(NewPeerRedactingWriter(inner), prefix, 0)
}

func (w *PeerRedactingWriter) Write(p []byte) (int, error) {
	if w == nil || w.inner == nil {
		return len(p), nil
	}
	redacted := RedactAddresses(string(p))
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := io.WriteString(w.inner, redacted); err != nil {
		return 0, err
	}
	// Report the caller's byte count: redaction changes the length, and a short
	// write would make log.Logger report a spurious failure.
	return len(p), nil
}

// RedactAddresses replaces every field-delimited token that parses as an
// IP address, or an IP address with a port, with RedactedAddress. Tokens that
// are not addresses -- error classes, event names, DNS names -- are preserved
// so the line keeps its operational meaning.
//
// Fields are split on whitespace and on "->". net.OpError.Error glues the
// local and remote addresses with "->" and no surrounding spaces, so a
// whitespace-only split leaves both addresses in one token that does not
// parse as AddrPort and would otherwise be written through unchanged.
func RedactAddresses(line string) string {
	var builder strings.Builder
	builder.Grow(len(line))
	start := 0
	index := 0
	for index <= len(line) {
		sepLen := 0
		if index < len(line) {
			sepLen = separatorLen(line, index)
			if sepLen == 0 {
				index++
				continue
			}
		}
		builder.WriteString(redactToken(line[start:index]))
		if sepLen == 0 {
			break
		}
		builder.WriteString(line[index : index+sepLen])
		index += sepLen
		start = index
	}
	return builder.String()
}

func isFieldSeparator(character byte) bool {
	return character == ' ' || character == '\t' ||
		character == '\n' || character == '\r'
}

func separatorLen(line string, index int) int {
	if isFieldSeparator(line[index]) {
		return 1
	}
	if line[index] == '-' && index+1 < len(line) && line[index+1] == '>' {
		return 2
	}
	return 0
}

// redactToken strips trailing punctuation that the standard library's log
// formats place directly after an address (", ", ": ", ".") before testing
// whether what remains is an address, then restores that punctuation.
func redactToken(token string) string {
	trimmed := strings.TrimRight(token, ":,.;\"')]}")
	if trimmed == "" {
		return token
	}
	suffix := token[len(trimmed):]
	// A bracketed IPv6 address with a port keeps its closing bracket, which the
	// trim above may have removed along with real punctuation.
	if !isAddress(trimmed) {
		if restored := trimmed + "]"; strings.HasPrefix(token, "[") &&
			strings.HasSuffix(suffix, "]") && isAddress(restored) {
			return RedactedAddress + strings.TrimSuffix(suffix, "]")
		}
		return token
	}
	return RedactedAddress + suffix
}

func isAddress(value string) bool {
	if _, err := netip.ParseAddrPort(value); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return true
	}
	return false
}
