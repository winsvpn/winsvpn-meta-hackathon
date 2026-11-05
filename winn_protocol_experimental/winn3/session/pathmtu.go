package session

import "encoding/binary"

// The path-MTU notice: the responder's planning path MTU, carried inside the
// handshake response payload.
//
// ===========================================================================
// THE DEFECT THIS EXISTS FOR
// ===========================================================================
//
// Silent-refusal instance #3, and the only member of that family that fails
// OPEN. Nothing in v3 negotiated the path MTU: each end computed its own plan
// floor from its own number and neither ever learned the other's. Measured on
// 2026-08-09 against a live cmd/winn3-gateway and the shipping
// cmd/winn-datapath client over a real UDP socket, in two OS processes:
//
//   - NARROW mismatch (gateway 1400, client 1500). The session establishes
//     normally and carries small packets perfectly — a 51-byte probe
//     round-tripped with refused_datagrams:0. A 1350-byte probe then VANISHED:
//     the gateway counted refused_datagrams:2, rx_packets stayed 0, and BOTH
//     ENDS went on reporting gate_state=carrying. Nothing was logged to the
//     user and nothing was signalled to the client. That is the black hole,
//     and the user believes they are protected while it is happening.
//
//   - WIDE mismatch (gateway 1280, client 1500). No session at all: the
//     gateway sent 1 message and refused 5, the session went to "closed", and
//     the client's gate never left down.
//
// Every other instance in this family fails CLOSED and merely looks like a
// censor. This one looks like a working tunnel.
//
// ===========================================================================
// WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
// ===========================================================================
//
// It is both halves of the tree's own stated remedy, gated on whether the
// host can actually re-apply an interface MTU.
//
// The ARITHMETIC half is [NegotiatedPathMTU]: the only number a session whose
// two ends both made claims could carry at is min(local, peer).
//
// The APPLY half is [ShrinkToPeerPathMTU], consumed by refusePathMTUMismatch
// when Config.ApplyNegotiatedPathMTU is set. That flag is owned by
// winn3/driver: it is true only when there is no tun, or when tun.Device
// implements tun.MTUSetter, so a shrink here is always paired with a device
// MTU clamp before the gate opens. Applying MaxMessageSize without that clamp
// is the original black hole (small packets work, full-size vanish, both
// gates report carrying).
//
// APPLY is refused — the loud path stays — when:
//
//   - the min would put the inner MTU below IPv6MinimumLinkMTU (the dead zone
//     driver.NewSizing already refuses at construction; clamping into it is
//     "the defect wearing the fix's clothes");
//   - the peer is wider (this initiator cannot shrink the gateway; the
//     initiation still carries a nil payload);
//   - the host device cannot SetMTU.
//
// So a mismatch becomes a working session only when the min is safe and the
// host can re-clamp. Otherwise it becomes a loud one.
//
// The pair tools/verify_winn3_conformance.sh still names — gateway 1280 vs
// client 1500, UDP/IPv6 floors 1232 vs 1452 — MUST stay a loud refusal.
// min(1280, 1500) puts the inner MTU at 1203, below RFC 8200. Take-the-minimum
// is the wrong remedy for that pair. classifyPathMTUMismatch names the dead
// zone even when ApplyNegotiatedPathMTU is off, so an operator is not told to
// add SetMTU and then APPLY into the band.
//
// ===========================================================================
// WHY THE FRAME DOES NOT HAVE TO CHANGE
// ===========================================================================
//
//   - core.WriteResponse and core.ReadResponse already carry an authenticated
//     payload INSIDE the AEAD. Every caller in the tree passed nil.
//   - A peer that does not parse the payload ignores it, in both directions.
//     That backward compatibility is not optional and has its own test.
//   - encodeHandshakePayload's minLen includes the payload, so with a fixed
//     padTo the on-wire length is unchanged. Under core.PadAuto, which is what
//     the session driver passes, the length was already a random draw.
//   - The `flags` byte in the payload header MUST STAY ZERO —
//     decodeHandshakePayload returns ErrDecrypt otherwise — so the version
//     lives in these bytes and never in flags.
//
// ===========================================================================
// THE RECORD
// ===========================================================================
//
//	magic   4 bytes  "W3PM"
//	version 1 byte   1
//	mtu     2 bytes  big-endian, the responder's PLANNING path MTU
//
// A magic rather than a bare integer because the payload is a shared channel: a
// later hint that is not a path-MTU notice must not be read as one, and reading
// a foreign payload as an MTU would manufacture exactly the refusal this file
// is meant to make trustworthy.
const (
	pathMTUNoticeVersion = 1

	// pathMTUNoticeSize is the v1 PathMTU record. A longer payload whose first
	// seven bytes are a valid v1 record is still read as one, so a later
	// version may append fields without stranding this reader.
	pathMTUNoticeSize = 7

	// pathMTUNoticeFloorSize is the v1 record plus the optional plan-floor
	// suffix: MaxMessageSize as a 16-bit big-endian integer. DecodePathMTUNotice
	// ignores the suffix (TestDecodePathMTUNoticePinsEveryNoClaimShape names
	// "valid v1 with trailing bytes"). EncodePathMTUNotice MUST stay 7 bytes —
	// TestThePathMTUNoticeWireRecordIsSevenExactBytes pins that exact record.
	pathMTUNoticeFloorSize = 9
)

// pathMTUNoticeMagic is "W3PM". Kept as bytes rather than a string constant so
// that the encoder and the decoder cannot drift apart by one character.
var pathMTUNoticeMagic = [4]byte{'W', '3', 'P', 'M'}

// EncodePathMTUNotice builds the responder's notice, or nil for no claim.
//
// Nil for a zero, negative or unrepresentable path MTU, because a claim nobody
// can act on is worse than no claim: the initiator would compare against a
// number the responder never planned with. A responder whose Config carries no
// PathMTU therefore behaves EXACTLY as this package did before this file
// existed — it sends no payload — and that is the compatibility floor the whole
// change rests on.
func EncodePathMTUNotice(pathMTU int) []byte {
	if pathMTU <= 0 || pathMTU > 0xFFFF {
		return nil
	}
	out := make([]byte, pathMTUNoticeSize)
	copy(out[:4], pathMTUNoticeMagic[:])
	out[4] = pathMTUNoticeVersion
	binary.BigEndian.PutUint16(out[5:7], uint16(pathMTU))
	return out
}

// DecodePathMTUNotice reads a notice out of a handshake payload.
//
// ok is false — meaning "this peer made no path-MTU claim", never "this peer is
// wrong" — for every one of:
//
//   - an empty payload — what every peer built before this change sends, and
//     what winn3/gateway sent until 2026-08-10, when it began claiming the
//     path MTU it was constructed with;
//   - a payload too short to hold the record;
//   - a payload that is some other hint, so the magic does not match;
//   - a version this build does not know. A later version MUST keep emitting a
//     valid v1 record beside whatever it adds, precisely so that this branch
//     stays unreachable in practice; if it ever fires, the outcome is the
//     pre-2026-08-09 behaviour, which is a silent mismatch and not a false
//     refusal. Failing towards "no claim" rather than towards "refuse" is
//     deliberate: an over-firing refusal is a worse outage than the defect.
func DecodePathMTUNotice(payload []byte) (pathMTU int, ok bool) {
	if len(payload) < pathMTUNoticeSize {
		return 0, false
	}
	if string(payload[:4]) != string(pathMTUNoticeMagic[:]) {
		return 0, false
	}
	if payload[4] != pathMTUNoticeVersion {
		return 0, false
	}
	mtu := int(binary.BigEndian.Uint16(payload[5:7]))
	if mtu <= 0 {
		return 0, false
	}
	return mtu, true
}

// EncodePathMTUFloorNotice is the responder notice the session driver emits:
// the 7-byte PathMTU record plus this end's MaxMessageSize.
//
// The PathMTU half is what refusePathMTUMismatch already compared. The suffix
// is the plan floor driver.NewSizing baked into MaxMessageSize. Two ends can
// claim the same PathMTU and still black-hole: cmd/winn3-gateway defaults
// -plan udp (Floor at 1450 is 1402) while cmd/winn-datapath sizes the served
// udp,tcp,tls plan (Floor at 1450 is 1338). PathMTUs match, handshake
// proceeds, small packets carry, full-size inner packets vanish on the
// narrower tun, both gates report carrying. That is silent-refusal #3 in a
// costume the PathMTU-only notice cannot see.
//
// A zero or unrepresentable MaxMessageSize drops the suffix and emits the
// 7-byte record, which DecodePathMTUFloor reports as no floor claim — the
// compatibility path, same as an old peer.
func EncodePathMTUFloorNotice(pathMTU, maxMessageSize int) []byte {
	base := EncodePathMTUNotice(pathMTU)
	if base == nil {
		return nil
	}
	if maxMessageSize <= 0 || maxMessageSize > 0xFFFF {
		return base
	}
	out := make([]byte, pathMTUNoticeFloorSize)
	copy(out, base)
	binary.BigEndian.PutUint16(out[7:9], uint16(maxMessageSize))
	return out
}

// DecodePathMTUFloor reads the optional plan-floor suffix.
//
// ok is false — "this peer made no floor claim", never "this peer is wrong" —
// when the PathMTU record is absent or the payload is only seven bytes. An
// old gateway, winn3/gateway.New (which still encodes PathMTU alone), and
// EncodePathMTUNotice all take this branch. refusePathMTUMismatch then
// compares PathMTU only, which is the compatibility floor.
func DecodePathMTUFloor(payload []byte) (maxMessageSize int, ok bool) {
	if _, pathOK := DecodePathMTUNotice(payload); !pathOK {
		return 0, false
	}
	if len(payload) < pathMTUNoticeFloorSize {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(payload[7:9]))
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// NegotiatedPathMTU is the min-of-both-ends number the tree's stated remedy
// describes: the path MTU a session would have to plan at for BOTH ends to
// carry, when both ends make a claim.
//
// It is the pure arithmetic half of silent-refusal instance #3's second-half
// remedy, implemented 2026-08-10 to give the refusal in
// winn3/session/driver.go a number to guard on instead of a comment. The
// responder's number is already on the wire; what was missing was an explicit,
// testable statement of "the session can only carry at the smaller of the two".
// That statement is this function.
//
// It returns merged = true only when BOTH ends made a claim. A peer that made
// no claim — an old build, or a caller whose Config.PathMTU was zero — cannot
// be a party to negotiation, exactly as DecodePathMTUNotice reports it: the
// caller must then behave as this package did before the notice existed, which
// is to use its own number and make no claim of its own comparison.
//
// When both ends have claimed, the negotiated number is the minimum. That is
// NOT automatically safe here: it encodes what the session WOULD need.
// ShrinkToPeerPathMTU is the policy that decides whether that number can be
// applied; Driver.refusePathMTUMismatch is the guarded return that either
// applies it or refuses. This function is deliberately not a policy function.
//
// A zero or negative input is never "the narrowest end" — it is "no claim",
// and it leaves no negotiation behind it.
func NegotiatedPathMTU(localPathMTU, peerPathMTU int) (negotiated int, bothClaimed bool) {
	if localPathMTU <= 0 || peerPathMTU <= 0 {
		return 0, false
	}
	if peerPathMTU < localPathMTU {
		return peerPathMTU, true
	}
	return localPathMTU, true
}

// ShrinkToPeerPathMTU is the APPLY half of silent-refusal instance #3.
//
// It returns the MaxMessageSize this end would use to plan at peerPathMTU
// while keeping the same plan overhead it already sized with
// (localPathMTU - localMaxMessageSize). That subtraction is the whole of
// "the session does not know the carrier classes": whatever overhead
// driver.NewSizing baked into MaxMessageSize is preserved, so a udp-only
// floor and a udp+tcp+tls floor both shrink correctly.
//
// ok is true only when ALL of:
//
//   - both ends made a positive claim
//   - the peer is strictly narrower (otherwise this end is already at the
//     minimum, and shrinking the peer is not something an initiator can do)
//   - the implied inner MTU stays at or above IPv6MinimumLinkMTU, so the
//     shrink does not walk into the inner-IPv6 dead zone
//   - the new message size stays at or above MessageFloor()
//
// ok=false means the caller must refuse, not clamp.
func ShrinkToPeerPathMTU(localPathMTU, localMaxMessageSize, peerPathMTU int) (newMaxMessageSize int, ok bool) {
	if localPathMTU <= 0 || peerPathMTU <= 0 || localMaxMessageSize <= 0 {
		return 0, false
	}
	if peerPathMTU >= localPathMTU {
		return 0, false
	}
	overhead := localPathMTU - localMaxMessageSize
	if overhead < 0 {
		return 0, false
	}
	newMax := peerPathMTU - overhead
	if newMax < MessageFloor() {
		return 0, false
	}
	if InnerMTU(newMax) < IPv6MinimumLinkMTU {
		return 0, false
	}
	return newMax, true
}

// pathMTUMismatchKind is why refusePathMTUMismatch is refusing, when it is.
// The order is the operator-facing priority: name the reason that stays true
// even if ApplyNegotiatedPathMTU is flipped. Telling an operator to add
// SetMTU for the 1280-vs-1500 pair would lead them to APPLY into the dead
// zone — the original defect wearing the fix's clothes.
type pathMTUMismatchKind int

const (
	pathMTUMismatchNone pathMTUMismatchKind = iota
	pathMTUMismatchWiderPeer
	pathMTUMismatchDeadZone
	pathMTUMismatchNoSetter
	pathMTUMismatchUnsafe
)

// classifyPathMTUMismatch names the refusal. None means the shrink is safe
// and canApply is set, so the caller should APPLY rather than refuse.
func classifyPathMTUMismatch(localPathMTU, localMaxMessageSize, peerPathMTU int, canApply bool) pathMTUMismatchKind {
	if localPathMTU <= 0 || peerPathMTU <= 0 || localPathMTU == peerPathMTU {
		return pathMTUMismatchNone
	}
	if peerPathMTU > localPathMTU {
		return pathMTUMismatchWiderPeer
	}
	if _, ok := ShrinkToPeerPathMTU(localPathMTU, localMaxMessageSize, peerPathMTU); !ok {
		if pathMTUShrinkHitsDeadZone(localPathMTU, localMaxMessageSize, peerPathMTU) {
			return pathMTUMismatchDeadZone
		}
		return pathMTUMismatchUnsafe
	}
	if !canApply {
		return pathMTUMismatchNoSetter
	}
	return pathMTUMismatchNone
}

func pathMTUShrinkHitsDeadZone(localPathMTU, localMaxMessageSize, peerPathMTU int) bool {
	if localPathMTU <= 0 || peerPathMTU <= 0 || localMaxMessageSize <= 0 {
		return false
	}
	overhead := localPathMTU - localMaxMessageSize
	if overhead < 0 {
		return false
	}
	newMax := peerPathMTU - overhead
	if newMax < MessageFloor() {
		return false
	}
	return InnerMTU(newMax) < IPv6MinimumLinkMTU
}

// pathMTUMismatchFormat is the wrap() format for a refusal. Every variant
// keeps the same four %d (peer, local, MaxMessageSize, negotiated) so a
// test that names both ends stays true across kinds. "responder" and
// "initiator" are in the shared prefix for the same reason.
func pathMTUMismatchFormat(kind pathMTUMismatchKind) string {
	const prefix = "the responder planned this session at a path MTU of %d and this initiator " +
		"planned it at %d, so this end sized its messages to %d bytes for a path the " +
		"other end does not believe in. The min-of-both-ends number a session would " +
		"have to plan at is %d. "
	switch kind {
	case pathMTUMismatchWiderPeer:
		return prefix +
			"This initiator cannot shrink the responder: the peer planned wider and " +
			"would send full-size messages this end refuses. Configure both ends at " +
			"the same path MTU."
	case pathMTUMismatchDeadZone:
		return prefix +
			"Taking that minimum would put the inner MTU below the 1280-byte floor " +
			"RFC 8200 requires of any link carrying IPv6 — the inner-IPv6 dead zone. " +
			"Applying it is the original defect wearing the fix's clothes: the session " +
			"would establish, carry small packets, and never promote. Refusing here is " +
			"that failure made visible. Raise the narrower end above the dead zone, or " +
			"configure both ends identically."
	case pathMTUMismatchNoSetter:
		return prefix +
			"The shrink would be safe, but this host cannot re-apply its interface MTU " +
			"after the handshake (the device does not implement SetMTU), so the two " +
			"ends must be configured identically. A session built on the difference " +
			"does NOT fail: it establishes, carries small packets, and black-holes " +
			"every full-size one while both ends go on reporting the gate carrying. " +
			"Refusing here is that failure made visible."
	default:
		return prefix +
			"The shrink to the minimum is not safe on this session. Configure both " +
			"ends at the same path MTU. A session built on the difference does NOT " +
			"fail: it establishes, carries small packets, and black-holes every " +
			"full-size one while both ends go on reporting the gate carrying."
	}
}

// classifyPlanFloorMismatch names a refusal when PathMTUs already agree and
// the optional MaxMessageSize suffix disagrees. The kinds are the same
// operator-facing set as classifyPathMTUMismatch: a wider peer cannot be
// shrunk by this initiator; a floor that would put InnerMTU below 1280 is
// the dead zone; a safe shrink without SetMTU must stay loud.
func classifyPlanFloorMismatch(localMax, peerMax int, canApply bool) pathMTUMismatchKind {
	if localMax <= 0 || peerMax <= 0 || localMax == peerMax {
		return pathMTUMismatchNone
	}
	if peerMax > localMax {
		return pathMTUMismatchWiderPeer
	}
	if peerMax < MessageFloor() {
		return pathMTUMismatchUnsafe
	}
	if InnerMTU(peerMax) < IPv6MinimumLinkMTU {
		return pathMTUMismatchDeadZone
	}
	if !canApply {
		return pathMTUMismatchNoSetter
	}
	return pathMTUMismatchNone
}

// planFloorMismatchFormat is the wrap() format when PathMTUs matched and the
// plan floors did not. Four %d: shared PathMTU, responder MaxMessageSize,
// initiator MaxMessageSize, min-of-both-ends MaxMessageSize.
func planFloorMismatchFormat(kind pathMTUMismatchKind) string {
	const prefix = "the two ends claimed the same path MTU of %d but sized their messages to %d " +
		"(responder) and %d (initiator). The min-of-both-ends message size is %d. "
	switch kind {
	case pathMTUMismatchWiderPeer:
		return prefix +
			"This initiator cannot shrink the responder: the peer's plan floor is wider " +
			"(a udp-only gateway against a udp,tcp,tls client is the shipping pair). " +
			"A session built on that difference establishes, carries small packets, and " +
			"black-holes every full-size one while both ends report the gate carrying. " +
			"Configure both ends with the same migration plan."
	case pathMTUMismatchDeadZone:
		return prefix +
			"Taking that minimum would put the inner MTU below the 1280-byte floor " +
			"RFC 8200 requires of any link carrying IPv6 — the inner-IPv6 dead zone. " +
			"Refusing here is that failure made visible."
	case pathMTUMismatchNoSetter:
		return prefix +
			"The shrink to the narrower plan floor would be safe, but this host cannot " +
			"re-apply its interface MTU after the handshake (the device does not " +
			"implement SetMTU). Configure both ends with the same migration plan. A " +
			"session built on the difference does NOT fail: it establishes, carries " +
			"small packets, and black-holes every full-size one while both ends go on " +
			"reporting the gate carrying."
	default:
		return prefix +
			"The shrink to the narrower plan floor is not safe on this session. " +
			"Configure both ends with the same migration plan."
	}
}
