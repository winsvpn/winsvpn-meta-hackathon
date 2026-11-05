package carrier

import (
	"crypto/rand"
	"encoding/hex"
	"slices"

	"winsvpn.local/winnprotocol/internal/carrierauth"
)

// CarrierTerminalSchema versions the sealed carrier terminal-event encoding.
//
// A carrier request that redeems a single-use privacy token creates a durable
// row in the redemption store before the carrier has produced any HTTP result.
// The request may still fail afterwards, but it may never disappear from the
// sealed audit trail: promotional evidence reconciles
//
//	durable redemptions == authenticated == auth_only + open + aborted
//
// exactly, not as a bound. Every authenticated request therefore receives one
// correlation identity and reaches exactly one mutually exclusive terminal
// class, and every event of the request carries that identity so an offline
// verifier can rebuild the equation from the manifest-bound evidence alone.
//
// Bump the version only together with the verifier's parser
// (cmd/winn-phase1-matrix-verify/carrieraudit.go), never on its own: the
// verifier rejects any carrier terminal event whose schema token it does not
// recognise, which is what makes an unannounced encoding change fail closed
// instead of silently reclassifying events.
const CarrierTerminalSchema = "carrier-terminal/v1"

// Carrier audit event names. The event name carries the terminal class; the
// detail field carries the schema token, the class, the authorization mode,
// the session identity, and the abort reason.
const (
	EventH3Authenticated = "carrier_h3_authenticated"
	EventH3AuthOnly      = "carrier_h3_auth_only"
	EventH3Open          = "carrier_h3_open"
	EventH3Closed        = "carrier_h3_closed"
	EventH3Aborted       = "carrier_h3_aborted"

	EventH2Authenticated = "carrier_h2_authenticated"
	EventH2Open          = "carrier_h2_open"
	EventH2Closed        = "carrier_h2_closed"
	EventH2Aborted       = "carrier_h2_aborted"
)

// Terminal classes. authenticated is the denominator, not a terminal class;
// closed is the paired release of an open carrier, not a terminal class. The
// mutually exclusive terminal classes are auth_only, open, and aborted.
const (
	TerminalClassAuthenticated = "authenticated"
	TerminalClassAuthOnly      = "auth_only"
	TerminalClassOpen          = "open"
	TerminalClassClosed        = "closed"
	TerminalClassAborted       = "aborted"
)

// Closed abort-reason enum for CarrierTerminalSchema. Every post-redemption
// reject path in h3.go and h2.go maps to exactly one of these values, and the
// value equals the metric name the same path already incremented, so the
// sealed trail and the metrics registry cannot drift apart.
//
// AbortReasonNone is the reason recorded on every non-abort carrier event so
// that the detail encoding has one fixed token order in every class.
//
// Adding a reason is an interface change: it requires a new schema version and
// a verifier update, because a verifier that does not know a reason must
// reject the evidence rather than accept an event it cannot classify.
const (
	AbortReasonNone = "none"

	// AbortReasonRateLimited is the per-principal carrier rate limiter
	// rejecting a request whose token was already redeemed.
	AbortReasonRateLimited = "carrier_rate_limited"

	// AbortReasonInvalidCarrierMTU is a server envelope/datagram
	// configuration that cannot carry the negotiated inner datagram.
	AbortReasonInvalidCarrierMTU = "invalid_carrier_mtu"

	// AbortReasonResponseAuthFailed is a failure to construct or sign the
	// controller-authenticated carrier response.
	AbortReasonResponseAuthFailed = "response_auth_failed"

	// AbortReasonBackendUnavailable is a failure to reach the fixed AWG
	// backend for a data-purpose request.
	AbortReasonBackendUnavailable = "awg_backend_unavailable"

	// AbortReasonAuditUnavailable is the audit sink refusing to seal a
	// successful terminal class. The abort record is still attempted; if it
	// also fails, the request contributes to the denominator with no terminal
	// class and the conservation equation invalidates the run, which is the
	// intended fail-closed outcome for a broken evidence sink.
	AbortReasonAuditUnavailable = "audit_unavailable"
)

var abortReasons = []string{
	AbortReasonRateLimited,
	AbortReasonInvalidCarrierMTU,
	AbortReasonResponseAuthFailed,
	AbortReasonBackendUnavailable,
	AbortReasonAuditUnavailable,
}

// AbortReasons returns the closed abort-reason enum for
// CarrierTerminalSchema, sorted, excluding AbortReasonNone.
func AbortReasons() []string {
	reasons := slices.Clone(abortReasons)
	slices.Sort(reasons)
	return reasons
}

// ValidAbortReason reports whether reason is a member of the closed enum.
// AbortReasonNone is deliberately not a member: it is the absence of an abort,
// so an aborted event carrying it must fail verification.
func ValidAbortReason(reason string) bool {
	return slices.Contains(abortReasons, reason)
}

// carrierTrace is the per-request correlation identity and terminal-class
// bookkeeping for one authenticated carrier request.
//
// The correlation identity is minted by the carrier, not derived from
// client-supplied claims. The session identity is stable across a session's
// several requests, so it cannot separate two redemptions of the same session,
// and the request nonce, while unique per request, is chosen by the client:
// two distinct redemptions could be made to carry the same nonce, which would
// forge the correlation-ID collision the verifier is meant to detect. A
// server-minted 128-bit random value is unique per redemption and cannot be
// steered by a peer. It is also unlinkable: it commits to no token, device, or
// session material.
//
// A carrierTrace is confined to one request goroutine and is not safe for
// concurrent use.
type carrierTrace struct {
	correlation string
	session     string
	mode        string
	terminal    bool
}

func newCarrierTrace(claims carrierauth.RequestClaims) *carrierTrace {
	var raw [16]byte
	// crypto/rand.Read never returns an error; it terminates the process if
	// the system source fails, so there is no silent low-entropy identity.
	_, _ = rand.Read(raw[:])
	return &carrierTrace{
		correlation: hex.EncodeToString(raw[:]),
		session:     safeAuditToken(claims.SessionID),
		mode:        safeAuditToken(claims.AuthMode),
	}
}

// detail renders the fixed five-token carrier terminal encoding. The token set
// and order are identical in every class so a verifier parses one shape.
func (t *carrierTrace) detail(class, reason string) string {
	return CarrierTerminalSchema +
		" class=" + safeAuditToken(class) +
		" mode=" + t.mode +
		" session=" + t.session +
		" reason=" + safeAuditToken(reason)
}

// terminalized reports whether this request already sealed a terminal class.
func (t *carrierTrace) terminalized() bool {
	return t.terminal
}

// markTerminal is called only after a terminal event has been durably
// recorded, so a failed write leaves the request free to seal its real
// terminal class instead of silently consuming it.
func (t *carrierTrace) markTerminal() {
	t.terminal = true
}

// safeAuditToken keeps every detail token inside a single unambiguous lexical
// shape. Carrier claims are validated before a trace exists, so this cannot
// normally fire; when it does, it substitutes a value that no enum, session,
// or mode matches, which makes the verifier reject rather than mis-parse.
func safeAuditToken(value string) string {
	if value == "" {
		return "invalid"
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '_' ||
			character == '.' || character == ':':
		default:
			return "invalid"
		}
	}
	if len(value) > 128 {
		return "invalid"
	}
	return value
}
