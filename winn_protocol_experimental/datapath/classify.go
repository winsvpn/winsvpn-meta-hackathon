package datapath

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// AWGClass is what the engine can tell about one outer datagram WITHOUT
// decrypting it, which is the only thing it is entitled to claim. Winn carries
// these datagrams; it does not hold the keys and cannot verify a single one of
// them. Classification is by header type value only.
type AWGClass uint8

const (
	// ClassUnknown covers AmneziaWG junk packets and anything else whose
	// header word matches no configured header type at that type's offset.
	ClassUnknown AWGClass = iota
	ClassHandshakeInitiation
	ClassHandshakeResponse
	ClassCookieReply
	ClassTransportData
)

// AWGHeaderTypes is the AmneziaWG classification table: the four header word
// values that replace WireGuard's message types 1..4, TOGETHER WITH the prefix
// padding sizes that decide WHERE in a datagram each of those words appears.
// Both come from the same signed deployment configuration that produces the
// "awg set ... s1 s2 s3 s4 h1 h2 h3 h4" arguments in
// internal/directawg/linux_controller_common.go, so a host that configured its
// AWG engine already has all of them.
//
// # Why the padding sizes belong here
//
// AmneziaWG PREPENDS S<n> random bytes to the message with header type H<n>.
// The header word is therefore not at offset 0; for each message class it is at
// that class's own offset. A table carrying only H1..H4 read random padding for
// every padded class and returned ClassUnknown, which under the shipping
// profile (S1=16, S2=80) meant no handshake was ever classified. That was a
// real, device-proven defect; see Status.HandshakeResponseObserved for the
// evidence. classify() is a function of the whole obfuscation profile here
// rather than of half of it.
//
// The prefix layout is confirmed in three independent upstream implementations,
// which agree: amneziawg-go writes the padding ahead of the message with
// rand.Read and then serialises the header at buf[padding:] (device/send.go for
// all four classes), its receive path reads the type word at packet[padding:]
// (device/receive.go), amneziawg-tools maps s1..s4 to
// init/response/cookie_reply/transport packet junk sizes (src/config.c), and
// the kernel module carries them as init_padding, resp_padding, cookie_padding
// and transport_padding (src/device.h, src/send.c). The padding is OUTSIDE the
// AEAD — upstream seals with a nil AAD — so these bytes are unauthenticated
// random, which is why nothing here may be worded as proof.
//
// AwgHeaderSpec is one H1..H4 value: either a single number or an
// inclusive range the engine draws from once per packet.
//
// Mirrors VpnConfigValidator.AwgHeaderSpec in lib/vpn_config_validation.dart
// and WinsAwgHeaderSpec in apple/WinsTunnelCore/WinsTunnelConfig.swift.
// AmneziaWG's device/magic-header.go accepts both spellings on these four
// fields and stores a bare value as the degenerate range Start==End. A scalar
// is therefore not a legacy special case to be tolerated -- it is the same
// object with zero width, which is what lets the legacy 11/22/33/44 set keep
// validating through the identical code path.
//
// These parameters are not negotiated, so a value the far end cannot parse is
// a fleet lockout rather than a downgrade.
//
// The contract is VpnConfigValidator.AwgHeaderSpec (Dart) is the single
// source of truth for the parse, the bounds and the overlap rule. This file
// does NOT write a second parser with different whitespace or digit rules:
// being MORE permissive than the engine (e.g. accepting "1000 - 4000" with an
// interior space) lets through a profile the far end cannot start, and nothing
// downstream can report it.
const (
	awgHeaderMin = 5
	// uint32 domain max. Typed uint64 so fmt.Errorf %d does not convert the
	// untyped constant to 32-bit int (GOARCH=arm overflow, measured 2026-08-13).
	awgHeaderMax           uint64 = 4294967295
	awgHeaderMaxRangeWidth uint64 = 4294967295
	awgHeaderSpecMaxLength        = 21
	awgHeaderFullWidthMin         = 16777216
)

type AwgHeaderSpec struct {
	Start uint32 `json:"-"`
	End   uint32 `json:"-"`
}

func (s AwgHeaderSpec) IsRange() bool { return s.End > s.Start }

func (s AwgHeaderSpec) Width() uint64 { return uint64(s.End) - uint64(s.Start) + 1 }

func (s AwgHeaderSpec) Contains(word uint32) bool { return s.Start <= word && word <= s.End }

func (s AwgHeaderSpec) Overlaps(other AwgHeaderSpec) bool {
	return s.Start <= other.End && other.Start <= s.End
}

func (s AwgHeaderSpec) String() string {
	if s.IsRange() {
		return fmt.Sprintf("%d-%d", s.Start, s.End)
	}
	return fmt.Sprintf("%d", s.Start)
}

func (s AwgHeaderSpec) MarshalJSON() ([]byte, error) {
	if s.IsRange() {
		return json.Marshal(s.String())
	}
	return json.Marshal(s.Start)
}

func (s *AwgHeaderSpec) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return errors.New("winn datapath awg header spec is empty")
	}
	if trimmed == "null" {
		return errors.New("winn datapath awg header spec is null")
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		spec, err := parseAwgHeaderSpecString(str)
		if err != nil {
			return err
		}
		*s = spec
		return nil
	}
	// JSON number path: must be decimal digits only, at most 10 digits.
	if len(trimmed) > 10 {
		return fmt.Errorf("winn datapath awg header value %q exceeds 10 digits", trimmed)
	}
	for _, c := range trimmed {
		if c < '0' || c > '9' {
			return fmt.Errorf("winn datapath awg header value %q is not a decimal integer", trimmed)
		}
	}
	v, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil {
		return err
	}
	if v < awgHeaderMin {
		return fmt.Errorf("winn datapath awg header value %d is below minimum %d", v, awgHeaderMin)
	}
	if v > awgHeaderMax {
		return fmt.Errorf("winn datapath awg header value %d exceeds maximum %d", v, awgHeaderMax)
	}
	*s = AwgHeaderSpec{Start: uint32(v), End: uint32(v)}
	return nil
}

func parseAwgHeaderSpecString(raw string) (AwgHeaderSpec, error) {
	t := strings.TrimSpace(raw)
	if t == "" || len(t) > awgHeaderSpecMaxLength || strings.ContainsAny(t, "\r\n\x00") {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header spec %q is invalid", raw)
	}
	for _, r := range t {
		if unicode.IsSpace(r) {
			return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header spec %q contains whitespace", raw)
		}
	}
	sep := strings.Index(t, "-")
	if sep < 0 {
		if len(t) > 10 {
			return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header value %q exceeds 10 digits", t)
		}
		for _, c := range t {
			if c < '0' || c > '9' {
				return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header value %q is not digits", t)
			}
		}
		v, err := strconv.ParseUint(t, 10, 32)
		if err != nil {
			return AwgHeaderSpec{}, err
		}
		if v < awgHeaderMin || v > awgHeaderMax {
			return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header value %d out of range [%d,%d]", v, awgHeaderMin, awgHeaderMax)
		}
		return AwgHeaderSpec{Start: uint32(v), End: uint32(v)}, nil
	}
	startText := t[:sep]
	endText := t[sep+1:]
	if startText == "" || endText == "" {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q has empty endpoint", t)
	}
	if strings.Contains(endText, "-") {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q has too many separators", t)
	}
	if len(startText) > 10 || len(endText) > 10 {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q endpoint exceeds 10 digits", t)
	}
	for _, part := range []string{startText, endText} {
		for _, c := range part {
			if c < '0' || c > '9' {
				return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q contains non-digit", t)
			}
		}
	}
	sVal, err := strconv.ParseUint(startText, 10, 32)
	if err != nil {
		return AwgHeaderSpec{}, err
	}
	eVal, err := strconv.ParseUint(endText, 10, 32)
	if err != nil {
		return AwgHeaderSpec{}, err
	}
	if sVal < awgHeaderMin {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q start %d below minimum %d", t, sVal, awgHeaderMin)
	}
	if eVal > awgHeaderMax {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q end %d exceeds maximum %d", t, eVal, awgHeaderMax)
	}
	if eVal < sVal {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q end before start", t)
	}
	width := eVal - sVal + 1
	if width > awgHeaderMaxRangeWidth {
		return AwgHeaderSpec{}, fmt.Errorf("winn datapath awg header range %q width %d exceeds maximum %d", t, width, awgHeaderMaxRangeWidth)
	}
	return AwgHeaderSpec{Start: uint32(sVal), End: uint32(eVal)}, nil
}

// When the configuration omits the table entirely the engine falls back to
// plain WireGuard's 1, 2, 3, 4 with no padding, and reports that in status as
// awg_classification so a reader can never mistake a default for a configured
// value.
type AWGHeaderTypes struct {
	H1 AwgHeaderSpec `json:"h1"`
	H2 AwgHeaderSpec `json:"h2"`
	H3 AwgHeaderSpec `json:"h3"`
	H4 AwgHeaderSpec `json:"h4"`

	// S1 is how many random bytes AmneziaWG prepends to a handshake
	// INITIATION, so the H1 word begins at offset S1. Zero means no prefix,
	// which is plain WireGuard's layout and the behaviour of every
	// configuration written before these fields existed.
	S1 uint16 `json:"s1,omitempty"`

	// S2 is the same for a handshake RESPONSE: the H2 word begins at offset S2.
	S2 uint16 `json:"s2,omitempty"`

	// S3 is the same for a COOKIE REPLY: the H3 word begins at offset S3.
	//
	// Applying it is free of consequence for the counters — no counter reads
	// ClassCookieReply, in either direction — so honouring it only moves padded
	// cookie replies out of ClassUnknown and into the class they actually are.
	S3 uint16 `json:"s3,omitempty"`

	// S4 is the transport-data prefix: official AmneziaWG Go v3.1.20260828
	// prepends that many random bytes to every transport message, including a
	// keepalive, so the H4 word always begins at offset S4. A nonzero value is
	// accepted and acted on. An offset-zero H4 word is not a compatibility
	// shape when S4 is nonzero; accepting it would classify wire bytes that the
	// configured engine does not produce or accept.
	S4 uint16 `json:"s4,omitempty"`
}

// wireGuardDefaultHeaderTypes is the unobfuscated WireGuard message-type set:
// types 1..4, every one of them at offset 0.
var wireGuardDefaultHeaderTypes = AWGHeaderTypes{
	H1: AwgHeaderSpec{Start: 1, End: 1},
	H2: AwgHeaderSpec{Start: 2, End: 2},
	H3: AwgHeaderSpec{Start: 3, End: 3},
	H4: AwgHeaderSpec{Start: 4, End: 4},
}

// awgTransportHeaderBytes is the WireGuard transport-data header: a 4-byte type
// word, a 4-byte receiver index and an 8-byte counter.
const awgTransportHeaderBytes = 16

// awgKeepaliveBytes is the exact size of a transport-data message with an empty
// encrypted payload: the 16-byte header plus a 16-byte Poly1305 tag. Anything
// larger carries actual tunnelled data, which is the distinction a
// transfer-proven route-promotion gate needs.
//
// Official AmneziaWG Go v3.1.20260828 applies S4 before every transport
// message. Therefore a keepalive has S4 random prefix bytes followed by these
// 32 transport bytes, and carriesTransportPayload must use S4+32 as its strict
// payload threshold.
const awgKeepaliveBytes = awgTransportHeaderBytes + 16

// classify matches a datagram against the configured header types, testing each
// message class at the offset that class's own prefix padding puts its header
// word at. WireGuard puts the message type in the first byte with three
// reserved zero bytes after it, so the whole word is the value AmneziaWG
// replaces.
//
// # Precedence, decided rather than inherited from switch-case order
//
// Each class is tested ONLY at its own offset, and TRANSPORT DATA IS TESTED
// FIRST. Three properties follow, and they are the reasons for the ordering
// rather than consequences of it:
//
//  1. A transport-data datagram can never be misread as a handshake. Its H4
//     word sits at offset S4 by construction, including for a keepalive; the
//     first test looks exactly there and returns before any handshake offset
//     is examined. That holds for every S4, so the guarantee
//     is structural rather than a property of the shipping profile. Transport
//     is the high-rate class and the one TransportObservedBothWays is built
//     from — the field a route-promotion gate is told to use — so it is the one
//     that must not be corrupted.
//
//  2. A deployment with no prefix padding classifies EXACTLY as it did before
//     these offsets existed. With S1..S4 all zero every class is tested at
//     offset 0, and Config.normalize has already forced H1..H4 to be pairwise
//     distinct, so at most one test can match and the order cannot change the
//     verdict. Plain WireGuard and any all-zero profile are unchanged.
//
//  3. Testing a class ONLY at its own offset is the smallest comparison set
//     that can decide the question, so it is also the smallest false-positive
//     surface. The alternative — testing offset 0 as well, for compatibility
//     with a profile whose padding sizes disagree with the wire — would quadruple
//     the number of random bytes compared against a header value and would mask
//     a misconfigured profile instead of leaving it visible.
//
// What no ordering fixes, stated rather than hidden: the S1 bytes in front of a
// real initiation are random, so with probability about 2^-32 the word at
// offset S4 inside them equals H4 and the initiation is counted as transport.
// This is not introduced here — the offset-0-only classifier compared those
// same bytes against all four values, a strictly larger exposure — and it falls
// on the rare, low-rate handshake classes rather than on transport.
//
// Transport data is tested only at S4. This matches official AmneziaWG Go
// v3.1.20260828 for both payload messages and keepalives, minimizes the random
// prefix false-positive surface, and preserves offset-zero behavior when S4=0.
//
// This is a header-type comparison and nothing more. It proves that a datagram
// LOOKS like a given AmneziaWG message; it does not authenticate it. The prefix
// padding is not covered by the AEAD upstream, and an on-path observer replaying
// an old transport datagram from the gateway's address would be classified the
// same way. Every claim built on this must be worded as evidence, never as
// proof.
func (types AWGHeaderTypes) classify(datagram []byte) AWGClass {
	if word, ok := headerWordAt(datagram, int(types.S4)); ok &&
		types.H4.Contains(word) {
		return ClassTransportData
	}
	if word, ok := headerWordAt(datagram, int(types.S1)); ok &&
		types.H1.Contains(word) {
		return ClassHandshakeInitiation
	}
	if word, ok := headerWordAt(datagram, int(types.S2)); ok &&
		types.H2.Contains(word) {
		return ClassHandshakeResponse
	}
	if word, ok := headerWordAt(datagram, int(types.S3)); ok &&
		types.H3.Contains(word) {
		return ClassCookieReply
	}
	return ClassUnknown
}

// carriesTransportPayload reports whether a datagram that classify() already
// called ClassTransportData carries tunnelled user data rather than being a
// keepalive. It is the ONLY thing permitted to move
// TxTransportPayloadDatagram and RxTransportPayloadDatagram, which back
// TransportObservedBothWays — the single field a route-promotion gate may read.
// A keepalive counted here would let a gate promote a route on a tunnel that
// has carried no user data at all, so this errs toward answering false.
//
// The threshold is S4 + awgKeepaliveBytes:
//
//   - A PADDED KEEPALIVE is exactly S4 + 16 header + 16 tag, so it answers
//     false on equality.
//   - A PADDED PAYLOAD datagram is S4 + 16 header + 16 tag + at least one
//     16-byte block of padded plaintext, so at least S4+48. It clears the
//     threshold by a full block.
//
// The strict comparison is the route-promotion safety boundary. It must not be
// weakened to classify a padded keepalive as user payload.
func (types AWGHeaderTypes) carriesTransportPayload(datagram []byte) bool {
	return len(datagram) > int(types.S4)+awgKeepaliveBytes
}

// headerWordAt reads the little-endian word at offset, reporting false when the
// datagram is too short to hold one there.
//
// This is the bounds check for a parser fed directly by a network peer, so it
// is written to be obviously correct rather than compactly: the test is
// offset > len(datagram)-4, which cannot be defeated by an offset near the
// integer maximum the way offset+4 > len(datagram) could. A datagram shorter
// than offset+4 — including an empty or nil one, where len(datagram)-4 is
// negative — returns false, and the caller falls through to the next class and
// ultimately to ClassUnknown. It never slices out of range and it never panics.
func headerWordAt(datagram []byte, offset int) (uint32, bool) {
	if offset < 0 || offset > len(datagram)-4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(datagram[offset : offset+4]), true
}

// distinct reports whether the four header intervals are pairwise
// non-overlapping. Two values that can produce the same word would make
// classification ambiguous, and an AmneziaWG deployment that produced them would
// be misconfigured (device/uapi.go:mergeWithDevice "headers must not overlap"),
// so it is refused at parse time rather than silently resolved by the order of
// the tests in classify.
//
// classify depends on this having been enforced: it is what makes the order of
// its four tests unable to change any verdict when the padding sizes coincide,
// which is the case for every unpadded profile and for the shipping one, where
// S1 and S3 are both 16.
//
// For scalars this degrades to equality, which is exactly the
// pairwise-distinctness rule this validator enforced before ranges existed.
func (types AWGHeaderTypes) distinct() bool {
	values := [4]AwgHeaderSpec{types.H1, types.H2, types.H3, types.H4}
	for outer := range values {
		for inner := outer + 1; inner < len(values); inner++ {
			if values[outer].Overlaps(values[inner]) {
				return false
			}
		}
	}
	return true
}

// paddingFits reports whether every configured prefix size leaves room for the
// 4-byte header word inside maxDatagram, naming the first size that does not.
//
// This is deliberately NOT the padding analogue of distinct(). Equal padding
// sizes are legal and are shipping — the deployment profile sets S1=16 and
// S3=16 — because two classes that share an offset are still told apart by
// their header VALUES, which distinct() already forces to be pairwise
// different. Equality creates no ambiguity, and refusing it would reject valid
// configurations. Upstream's own cross-class rule went the other way and was
// about message SIZES rather than padding sizes: amneziawg-go up to v0.2.15
// refused a profile whose padded message sizes were not all different, and
// v0.2.16 dropped that rule entirely. Winn is an observer of this wire format,
// not a second opinion about whether a signed deployment is well formed, so it
// does not re-litigate either rule.
//
// What IS refused is a padding size that pushes the header word past the
// largest datagram the engine will ever accept. Such a class could never be
// classified at any length — headerWordAt would return false for every datagram
// the engine is willing to receive — which silently reproduces the exact
// diagnostic trap that reading the padded offsets exists to remove: a healthy
// tunnel reporting a permanently zero counter. Refusing at parse time turns a
// silent trap into a loud configuration error.
func (types AWGHeaderTypes) paddingFits(maxDatagram int) (string, int, bool) {
	sizes := [...]struct {
		name string
		size uint16
	}{
		{"s1", types.S1},
		{"s2", types.S2},
		{"s3", types.S3},
		{"s4", types.S4},
	}
	for _, candidate := range sizes {
		if int(candidate.size)+4 > maxDatagram {
			return candidate.name, int(candidate.size), false
		}
	}
	return "", 0, true
}

// transportPayloadFits reports whether a nonzero S4 still leaves room inside
// maxDatagram for a transport datagram that carriesTransportPayload would call
// a payload datagram.
//
// This is the SAME silent-trap rule as paddingFits, applied one layer further
// in, and it exists because a nonzero S4 raises the payload threshold to
// S4+awgKeepaliveBytes. An S4 that clears paddingFits by leaving room for the
// 4-byte header word can still sit so close to maxDatagram that no datagram
// this engine would accept could ever exceed that threshold. Classification
// would look healthy — transport datagrams counted, the tunnel plainly alive —
// while TxTransportPayloadDatagram and RxTransportPayloadDatagram stayed
// permanently zero and TransportObservedBothWays stayed permanently false. A
// route-promotion gate reading that field would never promote and would have
// nothing in status pointing at why.
//
// It is scoped to a nonzero S4 deliberately. At S4=0 the rule would degenerate
// into "max_datagram must exceed awgKeepaliveBytes", which would newly refuse
// max_datagram=32 — permitted since MinDatagram was written and unrelated to
// prefix padding. Whether a 32-byte ceiling should be legal at all is a
// pre-existing question about MinDatagram and is not this rule's business; what
// this rule owes is that turning S4 on cannot silently kill the gate.
func (types AWGHeaderTypes) transportPayloadFits(maxDatagram int) bool {
	if types.S4 == 0 {
		return true
	}
	return int(types.S4)+awgKeepaliveBytes < maxDatagram
}
