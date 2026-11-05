// This file is the CONFIG-ISSUANCE GATE for winn/3: the single predicate that
// decides whether a client may be handed a winn/3 config document at all.
//
// Why it exists, in one sentence: a v3 gateway never answers an unauthenticated
// datagram, so a client that cannot speak winn/3 and is handed a winn/3 config
// fails silently, and that silence is indistinguishable from a censor blocking
// the path. The gate lives here, beside the one constant that defines what
// "winn/3" even means, so that the control plane that issues a config and the
// client-facing binding that reports capability both answer the same question
// from the same source of truth. A client that predates winn/3 carries the
// older protocol version, the older config grammar, or neither field at all,
// and must be refused before any winn/3 material leaves the issuer.
package connectivity

import (
	"errors"
	"fmt"
)

// ErrClientIneligible is the root refusal. A caller that would issue a winn/3
// config treats any non-nil result from Winn3ConfigEligible as "do not issue".
var (
	ErrClientIneligible    = errors.New("client is not eligible for a winn/3 config")
	ErrNotNegotiationReady = errors.New("client advertises winn/3 but cannot negotiate a session")
)

// ClientCapability is what a client advertises about itself when it asks the
// control plane for a configuration.
//
// The two fields mirror `clientbinding.TunnelBackendJSON`. ProtocolVersion is
// the winn/3 connectivity contract version the client declares
// (clientbinding.ProtocolVersion != connectivity.Version on every
// not-yet-v3 client). NegotiationReady is the boolean clientbinding reports as
// `safe_to_advertise_protocol` — whether this build can actually carry a
// session rather than merely parse one.
//
// An old client is rejected by the version check regardless of the boolean: a
// v1 AmneziaWG client and a v2 rekey-only client both report a version other
// than Version, and an even older client reports neither a version field nor
// the boolean at all, which the zero-value struct also rejects.
type ClientCapability struct {
	ProtocolVersion  string
	NegotiationReady bool
}

// Winn3ConfigEligible is the gate. It returns nil when the client may be
// issued a winn/3 config, and a non-nil error otherwise. The error names which
// property of the client failed, so the refusal is attributable rather than a
// bare "no".
//
// Both refusal directions are deliberate and both are fail-closed:
//
//   - a client whose ProtocolVersion is not exactly Version speaks an earlier
//     protocol and would fail the winn/3 negotiation silently (the whole
//     reason this gate exists);
//   - a client that advertises winn/3 but cannot negotiate (NegotiationReady
//     false) would equally be handed a config it could not use — the exact
//     silent-downgrade the clientbinding seam refuses.
//
// The zero ClientCapability is refused by the first branch: an empty version
// is never equal to Version.
func Winn3ConfigEligible(cap ClientCapability) error {
	if cap.ProtocolVersion != Version {
		return fmt.Errorf(
			"%w: client protocol version %q is not %q",
			ErrClientIneligible, cap.ProtocolVersion, Version,
		)
	}
	if !cap.NegotiationReady {
		return fmt.Errorf("%w: %w", ErrClientIneligible, ErrNotNegotiationReady)
	}
	return nil
}
