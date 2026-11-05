// Package conform is the CROSS-HOST CONFORMANCE SUITE for winn/3.
//
// ===========================================================================
// WHY THIS PACKAGE EXISTS
// ===========================================================================
//
// On 2026-08-09 three defects were found in one evening and all three had the
// same shape: A CLIENT AND A GATEWAY DISAGREEING ABOUT AN ENCODING OR A SIZE,
// PRODUCING NO SESSION AND NO ERROR ON EITHER SIDE.
//
//  1. gateway_id encoding. cdatapath base64-decoded it while the four other
//     call sites used the operator string's raw bytes. Negative control:
//     gateway `wins-sea-01` against client `d2lucy1zZWEtMDE=` produced
//     session_states:["initiating"], messages_received:5, messages_sent:0,
//     refused_datagrams:0 — and a client that exhausted its handshake
//     attempts. The trigger was ordinary: `winsgw01` is eight characters of
//     the base64 alphabet, so an everyday operator name is enough.
//
//  2. Android inner MTU. WinnV3EngineConfig emitted 1443 — the dialled
//     UDP-over-IPv4 number — where the plan floor across udp+tcp+tls is 1359.
//     Too wide carries small packets perfectly and black-holes every full-size
//     flow the moment the session migrates off UDP, while the tunnel reads
//     "up" at both ends.
//
//  3. path_mtu was not negotiated at all. A gateway defaulting to 1280 against
//     a client profile of 1500 gives different plan floors (1232 vs 1452) and
//     silently refuses legitimate messages. That is now NEGOTIATED, on the
//     REFUSAL half and the arithmetic half: the responder states its planning
//     path MTU in the handshake response payload (DecodePathMTUNotice in
//     winn3/session/pathmtu.go), a mismatch refuses loudly instead of
//     establishing a tunnel that cannot carry, and the take-the-minimum number
//     is explicit and pinned (NegotiatedPathMTU in winn3/session/pathmtu.go;
//     covered by TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket
//     and the pins below). What remains
//     deliberately unshipped is APPLYING that minimum to a live tunnel — see
//     the path-mtu-not-negotiated divergence row — so the two ends must still
//     be configured identically by hand.
//
// A v3 gateway never answers an unauthenticated datagram. Under the Myanmar
// threat model every one of these is indistinguishable from a censor blocking
// the user, so none of them can be found by looking at either end alone.
//
// ===========================================================================
// WHAT THIS PACKAGE IS
// ===========================================================================
//
// ONE operator configuration, and an assertion that every host derives
// BYTE-IDENTICAL admission-tag inputs and IDENTICAL plan floors from it.
//
// The precedent it generalises is WinnV3Sizing, which was made a mirror of
// winn3/carrier/sizing.go with a comment naming the Go file and stating that
// the two are a pair. A comment asking people not to let two implementations
// drift is worth strictly less than a test that fails when they do, and that
// is the whole content of this package.
//
// Three tiers, and the distinctions are load-bearing:
//
//   - TIER A, [Derivation.MustMatch]: values that MUST be identical on every
//     host. Any difference is a defect and fails loudly, naming both values.
//   - TIER A′, [RegressionPins]: defects that HAVE BEEN FIXED. Their return
//     fails the build. Each pin names the tests that hold it, and
//     TestEveryPinNamesATestThatExists checks those tests still exist — a pin
//     whose test was renamed is a pin guarding nothing.
//   - TIER B, [KnownDivergences]: divergences that exist today and are NOT yet
//     fixed. Measured debt, not permission. Every row must state a consequence
//     and a fix, and the ROW COUNT is asserted, so adding or deleting one is a
//     decision somebody had to write down rather than a maintenance step.
//
// A caution about that last tier, because this doc claimed otherwise until
// 2026-08-09: the suite does NOT compute an observed divergence set and compare
// it to the table. Nothing here can notice that a divergence was fixed. What
// notices is the row's own named test — each divergence names one, and those
// tests are written to FAIL on the day the divergence closes and to say so in
// their failure text. [DivergenceIDs] exists for a comparison nothing performs.
//
// The pin/divergence split is the one to get right. Filing a fixed defect as a
// divergence would let it come back; filing an unfixed divergence as a pin
// would leave the build permanently red, which ends with somebody switching the
// check off — the worse failure, because a suite nobody runs is
// indistinguishable from no suite.
//
// ===========================================================================
// WHAT IT DELIBERATELY DOES NOT DO
// ===========================================================================
//
// It computes nothing itself that a host also computes. Every reference number
// here comes from winn3/carrier, winn3/session, winn3/driver and winn3/core —
// the packages the shipping engine uses — so this package cannot agree with a
// host while both disagree with the wire. The one exception is
// [DemuxTokenFromDoc], which re-implements the construction from its own
// published documentation ON PURPOSE, so that a change to core's private
// derivation that nobody updated the doc for shows up as a failure rather than
// as a wire incompatibility discovered in Yangon.
package conform

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/core"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/session"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// ---------------------------------------------------------------------------
// the one operator configuration
// ---------------------------------------------------------------------------

// Operator is the SINGLE operator configuration every host is fed.
//
// It is deliberately shaped like what an operator actually types and what
// keygen actually writes, not like any host's internal struct. A host adapter's
// job is to get from here to its own configuration document by its own real
// code path; anything it has to invent on the way is a field this type is
// missing.
type Operator struct {
	// GatewayID is the operator's own gateway name, exactly as it is typed
	// into `winn3-gateway -gateway-id` and exactly as it appears in a host
	// profile's gateway_id.
	//
	// The reference value is chosen adversarially: `winsgw01` is eight
	// characters drawn entirely from the base64 alphabet and its length is a
	// multiple of four, so it DECODES CLEANLY as base64 to six bytes of
	// binary. A host that base64-decodes this field does not error — it
	// silently derives six different bytes, computes a tag the gateway cannot
	// verify, and is answered with the silence a v3 gateway answers every
	// unauthenticated datagram with. That is defect 1, and an operator name
	// this ordinary is all it took.
	GatewayID string

	// AdmissionFile is the CONTENT OF THE ADMISSION SECRET FILE, byte for
	// byte, as `winn3-gateway -mode keygen` writes it.
	//
	// keygen writes HEX TEXT. Every consumer in the tree uses the FILE'S BYTES
	// — the ASCII of the hex — as the secret, after trimming a trailing
	// newline and nothing else. The secret is OPAQUE BYTES and is never
	// decoded. Hex-decoding it on one end only produces a different admission
	// tag, ReadInitiation fails, and the gateway answers nothing.
	//
	// This field carries the trailing newline a real file has, so that the
	// trimming rule is under test rather than assumed.
	AdmissionFile string

	// PathMTU is the OUTER path MTU the plan floor is computed at. Zero means
	// each host's own default, and the suite pins that the defaults agree —
	// see DefaultPathMTU.
	PathMTU int

	// CarrierClasses is the MIGRATION PLAN: every class the session may
	// escalate TO, never the one dialled. The floor is computed over the whole
	// list, which is the content of defect 2.
	CarrierClasses []string
}

// Reference is the operator configuration the suite runs on.
//
// Every value is chosen to make a silent failure loud:
//
//   - GatewayID decodes cleanly as base64 (defect 1's trigger).
//   - AdmissionFile is hex text with a trailing newline, so both the "do not
//     decode" rule and the "trim only \r\n" rule are exercised.
//   - PathMTU is 1500, not a default, so a host that quietly substitutes its
//     own default is caught rather than accidentally agreeing at 1280.
//   - CarrierClasses names all three, so the plan floor is 84 bytes below the
//     dialled UDP/IPv4 number (defect 2's gap).
func Reference() Operator {
	return Operator{
		GatewayID:      "winsgw01",
		AdmissionFile:  "6f39a0c1d24b7e8f5a3c9012b4d6e8f01a2b3c4d5e6f708192a3b4c5d6e7f809\n",
		PathMTU:        1500,
		CarrierClasses: []string{"udp", "tcp", "tls"},
	}
}

// AdmissionSecret is the bytes the admission tag is keyed with: the file's
// bytes with a trailing CR/LF removed and NOTHING ELSE DONE TO THEM.
//
// This is the reference implementation of the rule cmd/winn3-gateway states in
// prose at buildSessionConfig and that cmd/winn-datapath (winn3_keys.go,
// winn3_run.go) and cmd/winn3-labrig each implement separately. Four
// independent implementations of "trim and stop" is three chances to add a
// hex.DecodeString, and the failure mode of adding one is silence.
func (o Operator) AdmissionSecret() []byte {
	return bytes.TrimRight([]byte(o.AdmissionFile), "\r\n")
}

// GatewayIDBytes is the bytes the admission tag authenticates: the operator
// string's own bytes, with no decoding of any kind.
func (o Operator) GatewayIDBytes() []byte { return []byte(o.GatewayID) }

// ---------------------------------------------------------------------------
// what a host derived
// ---------------------------------------------------------------------------

// Derivation is what ONE host derived from [Operator].
//
// A host adapter fills this in from its own real configuration path — not from
// a copy of the arithmetic — and hands it to [Derivation.MustMatch]. Filling it
// in from anything other than the code the shipping host runs makes this suite
// a test of the suite.
type Derivation struct {
	// Host names the code path, precisely enough to open the file:
	// "cdatapath/winn_datapath_winn3.go:admissionProfile", not "apple".
	Host string

	// GatewayID and AdmissionKey are the two admission-tag inputs that are
	// never transmitted and therefore never checked by the wire.
	GatewayID    []byte
	AdmissionKey []byte

	// TagSize is core.GatewayParams.tagSize()'s effective value. A message
	// sealed for a 32-byte-tag gateway must not verify at a 16-byte-tag
	// gateway sharing the key, so the length is an authenticated input too and
	// a host that sets it differently is the same class of defect.
	TagSize int

	// PathMTU is the OUTER path MTU this host resolved, AFTER its own default
	// was applied. Defect 3 lives here.
	PathMTU int

	// Classes is the migration plan this host resolved, as carrier class
	// names in the order given.
	Classes []string

	// MessageSize and InnerMTU are the plan floor. Defect 2 lives here.
	MessageSize int
	InnerMTU    int

	// InnerIPv6 is whether the plan floor can carry inner IPv6 at all.
	InnerIPv6 bool
}

// Expected is the reference derivation: what every host must produce.
//
// Computed through carrier.Floor / driver.NewSizing / session.InnerMTU — the
// same functions the engine runs — so this cannot be a second opinion that
// agrees with a host while both disagree with the wire.
func Expected(o Operator) (Derivation, error) {
	classes, err := Classes(o.CarrierClasses)
	if err != nil {
		return Derivation{}, err
	}
	pathMTU := o.PathMTU
	if pathMTU == 0 {
		pathMTU = DefaultPathMTU
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return Derivation{}, err
	}
	return Derivation{
		Host:         "winn3/conform.Expected (reference)",
		GatewayID:    o.GatewayIDBytes(),
		AdmissionKey: o.AdmissionSecret(),
		TagSize:      core.DefaultTagSize,
		PathMTU:      pathMTU,
		Classes:      append([]string(nil), o.CarrierClasses...),
		MessageSize:  sizing.MessageSize,
		InnerMTU:     sizing.InnerMTU,
		InnerIPv6:    sizing.InnerIPv6,
	}, nil
}

// DefaultPathMTU is the value a host that was given no path MTU must resolve
// to. It is the FLEET DEFAULT and it moved from 1280 to 1450 on 2026-08-10.
//
// All four entry points now resolve through carrier.DefaultPathMTU and no
// other name, which TestEveryEntryPointDefaultsThroughTheOneConstant checks by
// reading the four sources. Until 2026-08-10 two of them
// (cmd/winn-datapath/winn3_create.go and cdatapath — Apple's route) went
// through tun.IPv6MinLinkMTU instead, and the two constants were equal, so the
// split was invisible. Raising one without the other would have left one
// platform planning 170 bytes away from the rest of the fleet: defect 3
// arriving by default rather than by configuration.
//
// tun.IPv6MinLinkMTU is still 1280 and is NOT this. It is RFC 8200's floor for
// a link carrying IPv6, it applies to the INNER interface, and conflating the
// two is what put the fleet default in the middle of the dead zone.
const DefaultPathMTU = carrier.DefaultPathMTU

// FromCore builds a Derivation from the core configuration a host actually
// produced, plus the sizing it actually resolved.
//
// This is the adapter every Go host uses, so that what is compared is the
// host's own core.GatewayParams — the struct that is handed to the crypto —
// and not a restatement of it.
func FromCore(host string, g core.GatewayParams, s driver.Sizing, classNames []string) Derivation {
	tagSize := g.TagSize
	if tagSize == 0 {
		tagSize = core.DefaultTagSize
	}
	var key []byte
	if len(g.AdmissionKeys) > 0 {
		key = g.AdmissionKeys[0]
	}
	return Derivation{
		Host:         host,
		GatewayID:    g.GatewayID,
		AdmissionKey: key,
		TagSize:      tagSize,
		PathMTU:      s.PathMTU,
		Classes:      append([]string(nil), classNames...),
		MessageSize:  s.MessageSize,
		InnerMTU:     s.InnerMTU,
		InnerIPv6:    s.InnerIPv6,
	}
}

// ---------------------------------------------------------------------------
// what the CONTROL PLANE serves
// ---------------------------------------------------------------------------
//
// The hub is a host too, and until 2026-08-09 it was the only one nothing in
// this suite covered — it served `enabled`, `endpoint`, `carrier` and
// `session_id` and NOT ONE of the six key-bearing fields, so no device could
// start a standalone session from a real server config regardless of how well
// the engines agreed. It now serves all of them, which makes it a fifth
// derivation of the same operator values and therefore this suite's business.
//
// IT IS THE MOST DANGEROUS HOST IN THE TABLE, and the reason is structural
// rather than a judgement about the code. Every other host derives its inputs
// from a document on the device that an operator installed and can inspect. The
// hub derives them for EVERY DEVICE AT ONCE, over the network, from a signed
// descriptor. A single encoding mistake here does not strand one handset, it
// strands the fleet — silently, because a v3 gateway never answers a datagram
// it could not authenticate.
//
// The two rules below are therefore stated as one function each rather than as
// prose, and TestTheServedSectionConformsToTheCrossHostSuite runs them through
// the same [Derivation.MustMatch] every engine goes through.

// ServedWinnSection is the `[winn]` section a control plane must emit for the
// reference operator, as key -> value in the exact ENCODINGS that travel.
//
// It is deliberately built from [Operator] plus the two per-device values,
// rather than pasted from a captured config: a fixture copied out of a running
// hub would agree with that hub by construction and could not catch it drifting.
//
// The two encoding rules that are the whole point:
//
//   - `gateway_id` is BASE64 OVER THE OPERATOR'S GATEWAY-NAME TEXT. The
//     descriptor transports it that way, the hub validates it that way, and the
//     encoding survives into the section untouched. The single decode belongs
//     to the host that reads descriptor-shaped fields; a second decode anywhere
//     is defect 1.
//   - `admission_key` is BASE64 OVER THE KEY FILE'S BYTES — the 64 ASCII hex
//     characters, after the trailing newline is trimmed and nothing else is
//     done to them. base64 of the 32 DECODED bytes is the encoding that builds
//     a session and then goes silent.
func ServedWinnSection(o Operator, node, selectedNode, innerV4, innerRouterV4, innerResolverV4, staticPrivate, gatewayStatic string) map[string]string {
	section := map[string]string{
		"enabled":           "true",
		"carrier":           "winn3",
		"endpoint":          "203.0.113.7:51820",
		"node":              node,
		"selected_node":     selectedNode,
		"inner_v4":          innerV4,
		"inner_router_v4":   innerRouterV4,
		"inner_resolver_v4": innerResolverV4,
		"static_private":    staticPrivate,
		"gateway_static":    gatewayStatic,
		"gateway_id":        base64.StdEncoding.EncodeToString(o.GatewayIDBytes()),
		"admission_key":     base64.StdEncoding.EncodeToString(o.AdmissionSecret()),
	}
	if o.PathMTU != 0 {
		section["path_mtu"] = strconv.Itoa(o.PathMTU)
	}
	if len(o.CarrierClasses) > 0 {
		section["carrier_classes"] = strings.Join(o.CarrierClasses, ",")
	}
	return section
}

// ServedWinnSectionRequiredKeys is the set a standalone start cannot proceed
// without. A served section missing any of them is refused BY NAME on Apple
// (WinsTunnelConfig.winn3StartRefusalReason) rather than started and ignored.
var ServedWinnSectionRequiredKeys = []string{
	"admission_key", "carrier", "endpoint", "gateway_id", "gateway_static",
	"inner_resolver_v4", "inner_router_v4", "inner_v4", "node",
	"selected_node", "static_private",
}

// ServedWinnSectionKeyOrder is the order lib/winn_protocol_dispatch.dart emits.
//
// Order is not cosmetic here. [ServedWinnSectionINI] is fed BYTE FOR BYTE to
// four different parsers written in four languages, and a suite that rendered
// the same map two different ways would be testing its own renderer as much as
// the hosts. Pinning the order means the document a host is handed in a test is
// the document the shipping Dart writer produces.
// `inner_resolver_v4` sits beside `inner_router_v4` because it is the same KIND
// of fact off the same signed descriptor, and the position is pinned here for
// the same reason every other position is. Format-v3 descriptors require it,
// and the Dart writer emits it only after descriptor verification.
var ServedWinnSectionKeyOrder = []string{
	"enabled", "carrier", "endpoint", "node", "selected_node",
	"inner_v4", "inner_router_v4", "inner_resolver_v4",
	"static_private", "gateway_static",
	"gateway_id", "admission_key",
	"psk", "path_mtu", "carrier_classes", "session_id",
}

// ServedWinnSectionINI renders a served section as the INI TEXT that actually
// reaches a host.
//
// ===========================================================================
// WHY THE SUITE NEEDED A DOCUMENT AND NOT ONLY A MAP
// ===========================================================================
//
// Until 2026-08-09 this package compared DERIVATIONS: it handed each host a Go
// map and asked what it computed. That found every arithmetic and encoding
// defect and could not have found the one that was actually costing the
// project four platforms, because that one lives BEFORE the arithmetic — three
// of the four hosts could not READ the document at all. Android looked for
// `v3_gateway_id` in lowercase hex; Windows looked for a `[winn3]` section
// carrying file paths; Linux had no `[winn]` reader for v3 in the tree at all.
// A map fixture skips exactly the layer where those live.
//
// So the fixture is now the bytes. Every host's own parser is fed this string,
// and a host that cannot parse it fails here rather than in Yangon.
//
// `enabled` and `carrier` lead deliberately: they are the two keys that select
// a protocol, and every host reads them before it reads anything key-shaped.
func ServedWinnSectionINI(section map[string]string) string {
	var sb strings.Builder
	sb.WriteString("[winn]\n")
	emitted := map[string]bool{}
	for _, key := range ServedWinnSectionKeyOrder {
		value, ok := section[key]
		if !ok {
			continue
		}
		emitted[key] = true
		fmt.Fprintf(&sb, "%s = %s\n", key, value)
	}
	// Anything the caller added that the order does not name is emitted after,
	// sorted. Silently dropping it would let a test build a section with a key
	// no host ever saw and still pass.
	extra := make([]string, 0, len(section))
	for key := range section {
		if !emitted[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		fmt.Fprintf(&sb, "%s = %s\n", key, section[key])
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// What a STANDALONE session's promoted posture must carry, and where it comes
// from.
// ---------------------------------------------------------------------------

// ServedWinnSectionCarriesNoPostureKey is the list of keys the `[winn]` contract
// deliberately does NOT have, checked so that adding one is a decision.
//
// ===========================================================================
// WHY THESE ARE ABSENT ON PURPOSE RATHER THAN MISSING BY OVERSIGHT
// ===========================================================================
//
// This started as an oversight and was settled as a decision on 2026-08-09.
//
// ROUTES are DERIVED. A promoted posture takes the default route
// unconditionally (windows/runner/winn3_posture.h: `plan->default_route =
// true`), and both renderers spell that as the 0.0.0.0/1 + 128.0.0.0/1 pair so
// it beats an existing default on specificity without deleting it. So the route
// set is already "everything", and a served `routes` key could only ever ADD to
// it — it cannot narrow a full tunnel and it cannot make one. What it CAN do is
// put the decision that moves a user's traffic into unsigned hub output. The
// derivation needs nothing on the wire: the bootstrap's inner next hop, which
// the section already carries as `inner_router_v4`, plus the pair.
//
// DNS is NOT derivable, and that is the finding rather than a gap in the
// derivation. There is no v3 resolver anywhere in the system: the ML-DSA-65
// descriptor's closed field set has none, the hub serves none, and
// cmd/winn3-gateway's own source says it "forwards nothing, resolves nothing
// and egresses nothing". `inner_router_v4` is documented as the inner next hop
// "for PMTU signals only", so naming it as the resolver would trade a leak for
// total name-resolution failure. It belongs in the SIGNED descriptor, beside
// `inner_router_v4`, and not here: the section is unsigned, and the resolver
// address decides where every name lookup in the session goes.
//
// `dns_are_inner` is absent for a different reason again. winn3_posture.h calls
// it "the host's own declaration", and a transported boolean asserting "this
// resolver is inside the tunnel" is a claim the host cannot check — which is
// the leak wearing a flag rather than a defence against it.
//
// ===========================================================================
// WHY `inner_resolver_v4` IS NOT ON THIS LIST, WHICH IS NOT AN EXCEPTION TO IT
// ===========================================================================
//
// Added 2026-08-12, and the distinction is the entire reason the resolver field
// took the shape it did. This list forbids six SPELLINGS OF A POSTURE
// DECISION arriving in the unsigned `[winn]` section. `inner_resolver_v4` is
// not one: it is a dotted-quad ADDRESS off the ML-DSA-65-SIGNED gateway
// descriptor, sitting beside `inner_router_v4`, carrying exactly that field's
// trust — a forged hub response cannot mint one, and a node that gains a
// resolver has its descriptor re-signed.
//
// The difference that matters is what the client does with it. A `dns_are_inner`
// boolean would be BELIEVED: it asserts a conclusion the host cannot check, so
// accepting it is the whole gate. An address is CHECKED: it is fed to the
// derivation each host already runs, and every clause still applies to it — a
// hostname, the host's own assignment, a public literal and anything outside the
// assignment's /24 are all still refused when the descriptor names them.
// Exactly one clause consults the field, and only to stop refusing the next hop
// BY NAME on the ground that nothing answers there.
//
// So this list stays as it is, and a future editor who reads "the resolver
// address is transported now, so `dns` may as well be" has read it backwards:
// the field was made an address, and put on the signed document, precisely so
// this list would not have to move.
var ServedWinnSectionCarriesNoPostureKey = []string{
	"routes", "allowed_ips", "dns", "dns_are_inner", "dns_servers", "resolvers",
}

// StandalonePostureGuards are the host-side guards that hold the promotion gate
// closed against a posture that would carry nothing.
//
// They are stated here, once, and the suite GREPS each host's own files for
// them — the same discipline TestTheServedFixtureIsTheOneEveryHostParses
// applies to the served document, and for the same reason. Comparing
// derivations could not have found this defect: a host promoting to a posture
// that captures nothing computes every number correctly on the way there.
type PostureGuard struct {
	// File is repo-relative.
	File string
	// Needle must appear in it, verbatim.
	Needle string
	// Why says what breaks if it is gone.
	Why string
}

// StandaloneCaptureGuards hold the ROUTE half.
var StandaloneCaptureGuards = []PostureGuard{
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "inline bool VerifyPromotedPostureCaptures(",
		Why: "the plan-level refusal. Without it BuildPromotedPosture returns true for a " +
			"posture with no default route and nothing but host routes, and both desktop " +
			"hosts report a promotion that moved no traffic.",
	},
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "inline bool VerifyPromotedCommandsCapture(",
		Why: "the same question asked of the RENDERED argument vectors, which is the object " +
			"that actually moves traffic. `default_route` is ONE boolean and the /1 pair is " +
			"TWO commands, so no plan-level predicate can see a renderer that emitted one.",
	},
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "if (low_half != high_half || v6_low_half != v6_high_half) {",
		Why: "both halves of the pair are required, in each family. 0.0.0.0/1 alone leaves " +
			"128.0.0.0/1 — half the address space — on the physical interface while the " +
			"plan, the status line and the user all read promoted, and a lone `::/1` is the " +
			"same leak in IPv6 (a bare `::/1` used to fall through to CapturesMoreThanOneHost " +
			"and count as capture). Updated 2026-08-10 for the ipv6linux/ipv6win extension.",
	},
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "if (!VerifyPromotedPostureCaptures(*plan, error)) {",
		Why: "the builder checks its OWN output, which is the shape VerifyBootstrapIsNarrow " +
			"gives the other posture. Mutation-tested 2026-08-09 and it SURVIVED deletion, " +
			"because `default_route = true` is unconditional so the builder cannot currently " +
			"produce a plan this rejects. It is belt-to-braces and it is kept for the edit " +
			"that makes default_route conditional — the moment it becomes live is the moment " +
			"nobody is looking for it. This grep is what holds it, since no behavioural test " +
			"can.",
	},
	{
		File:   "linux/runner/linux_winn3_host.cc",
		Needle: "if (!winsvpn::winn3::VerifyPromotedCommandsCapture(",
		Why: "Linux re-checks the DELTA it is about to execute, and REFUSES before a command " +
			"runs if the delta would not capture. Asserted as the guarded call rather than as " +
			"`VerifyPromotedCommandsCapture(route_delta,`: the argument NAME `route_delta` is " +
			"a local the host may rename without changing behaviour (it did on 2026-08-10, and " +
			"the old name-grepping needle went red), while the `if (!…` guard is the behaviour, " +
			"and it occurs exactly once in the file. A check fed a command list " +
			"the caller does not run is a check of a hypothetical. Mutation-tested " +
			"2026-08-09 and it SURVIVED deletion for the same reason as the plan-level " +
			"self-check above: nothing reachable through the shipping builder renders a " +
			"non-capturing promoted posture. It guards the RENDERER, which is shared by two " +
			"hosts and changed for one at a time, so this grep is the only thing that can " +
			"notice the call going away.",
	},
	{
		File:   "linux/runner/winn3_posture_test.cc",
		Needle: "TestAPromotionThatWouldCaptureNothingIsRefused",
		Why:    "the C++ test that exercises both, and it builds and RUNS on the development host.",
	},
}

// StandaloneRouteDerivationGuards hold the derivation itself: a promoted route
// set is the bootstrap's UNION the host's, and never an assignment over it.
var StandaloneRouteDerivationGuards = []PostureGuard{
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "if (!already) plan->included_routes.push_back(value);",
		Why: "the promoted route set is the bootstrap's UNION the host's, not the host's " +
			"alone. The assignment this replaced discarded the inner next hop for every " +
			"served config and left the plan describing a posture the machine did not have.",
	},
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "detail::RendersAsDefaultRoute(value)",
		Why: "a route set that restates the /1 pair makes both renderers emit the same " +
			"`route add` twice, and the second fails EEXIST — turning a correct promotion " +
			"into a posture command failure on a session whose datapath had just been proven.",
	},
	{
		File:   "linux/runner/winn3_posture_test.cc",
		Needle: "TestAServedRouteSetKeepsTheBootstrapsNextHop",
		Why:    "the C++ test that measures it, on the served section's own inputs.",
	},
}

// StandaloneEnforceRoutesGuards hold the APPLE route half of the same refusal.
// When a host turns on `enforceRoutes` the tunnel's promoted /0 wins over the
// physical interface whatever its specificity, and the engine's own outer socket
// is then safe only because its /32 stays in NEIPv4Settings.excludedRoutes. The
// two are a single posture: one without the other captures the transport it
// dials on. This is the platform that carries no protect()/SO_BINDTODEVICE, so
// the /32 IS "protect" (see WinsWinn3HostContract §2).
var StandaloneEnforceRoutesGuards = []PostureGuard{
	{
		File:   "ios/Runner/AppDelegate.swift",
		Needle: "tunnelProtocol.enforceRoutes = true",
		Why: "the ruled Apple posture that makes the tunnel's promoted /0 win over a MORE " +
			"SPECIFIC physical-interface route. Without it a flow that should have been " +
			"inside the tunnel leaves by the physical link in the clear. With it every route " +
			"belongs to the tunnel — which is only safe because the /32 carve-out below " +
			"still sits in excludedRoutes.",
	},
	{
		File:   "macos/Runner/MainFlutterWindow.swift",
		Needle: "tunnelProtocol.enforceRoutes = WinsMacRoutePosture.enforceRoutes",
		Why: "macOS applies the same ruled posture from the single source " +
			"(WinsMacRoutePosture.enforceRoutes = true, RULINGS.lock: macOS enforceRoutes = " +
			"true). The promoted /1 pair only wins over the physical link because " +
			"enforceRoutes is on, and it only avoids capturing the engine's outer socket " +
			"because the /32 exclusion is carried in excludedRoutes on the same settings " +
			"object (RouteAudit.log immediately before provider start).",
	},
	{
		File:   "ios/PacketTunnel/PacketTunnelProvider.swift",
		Needle: "ipv4Settings.excludedRoutes = [",
		Why: "the /32 carve-out for the engine's outer socket, installed into " +
			"NEIPv4Settings.excludedRoutes from the first bootstrap posture. On Apple this " +
			"IS 'protect': there is no VpnService.protect or SO_BINDTODEVICE, so the /32 is " +
			"the only thing that keeps the transport's own path off the tunnel once the /0 " +
			"is promoted. Remove it and enforceRoutes lets the promoted /0 capture the " +
			"engine's own outer socket — the session either dies or loops.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3HostContract.swift",
		Needle: "func winn3CarrierExclusionIsUsable",
		Why: "the refusal that a configuration whose /32 derives to loopback or nothing " +
			"excludes nothing off this device. A config like that, promoted to a /0 under " +
			"enforceRoutes, lets the /0 capture the engine's own outer socket, and the " +
			"session either dies or loops. Start must refuse it — checked before the ABI " +
			"create call (see WinsWinn3Datapath.start).",
	},
}

// StandaloneResolverGuards hold the DNS half — the one that was reachable.
var StandaloneResolverGuards = []PostureGuard{
	{
		File:   "windows/runner/winn3_posture.h",
		Needle: "if (input.dns_servers.empty()) {",
		Why: "the refusal itself. Without it a served config promotes, widens the routes onto " +
			"the tunnel, and leaves every DNS query going out the physical interface in the " +
			"clear to the resolver the censor operates.",
	},
	{
		File:   "linux/runner/winn3_posture_test.cc",
		Needle: "a promotion that would install NO resolver is refused",
		Why: "the assertion that REPLACED \"a promotion with no resolvers at all is fine\". A " +
			"test that pinned the defect shut is worse than no test, because it makes the " +
			"defect look considered.",
	},
	{
		File:   "linux/runner/linux_winn3_host.cc",
		Needle: "winsvpn::winn3::BuildPromotedPosture(",
		Why: "Linux pre-flights the promotion at START, with nothing installed and nothing to " +
			"tear down, using the real builder rather than a restatement of what it checks. " +
			"A pre-flight that re-implements the policy is a second policy, and two policies " +
			"drift. The call moved here 2026-08-10 with the privileged-runner refactor: it " +
			"now lives inside ApplyLinuxWinn3PromotedPosture, still the real builder.",
	},
}

// StandaloneMobileResolverGuards hold the SAME half on the two platforms that
// actually ship to users, where it was reachable through a served config and
// where it was WORSE than on the desktop.
//
// ===========================================================================
// WHY THESE ARE A SEPARATE LIST FROM StandaloneResolverGuards
// ===========================================================================
//
// The desktop hosts fail by OMISSION: a served `[winn3]` section names no
// resolver, `dns_servers` is empty, and BuildPromotedPosture refuses. That is
// fail-closed from the first line.
//
// Apple and Android failed by COMMISSION. Both reached for the resolver they
// had — the AmneziaWG `[Interface] DNS` line — and installed it:
//
//	Apple    NEDNSSettings(servers: config.dnsServers), where
//	         lib/main.dart:_nativeTunnelDnsServers substitutes the PUBLIC Quad9
//	         literals 9.9.9.9,149.112.112.112 on this platform whenever the
//	         served DNS carries no public literal
//	Android  parseConfigValue(awgConfig, "DNS") ?: "10.8.1.1" — a default in
//	         the v1 INNER SPACE, which the winn/3 tun layer drops
//
// So the desktop failure is "no resolver moves"; the mobile failure is "a
// resolver moves, and it is the wrong one". The second is worse in Myanmar:
// the Quad9 case hands the user's full browsing history to whatever sits
// between them and 9.9.9.9, in the clear, while the tunnel reports carrying.
//
// ===========================================================================
// THE PREDICATE IS DERIVED ON BOTH, AND THAT IS THE ROW'S WHOLE POINT
// ===========================================================================
//
// `winn3_posture.h` takes `dns_servers_are_inner` as an INPUT because a local
// `[winn3]` file on a desktop is written by somebody holding the machine.
// Neither mobile host has such a file: the only document reaching them is the
// unsigned `[winn]` section, and [ServedWinnSectionCarriesNoPostureKey] pins
// `dns` and `dns_are_inner` absent from it precisely because a transported
// boolean asserting "this resolver is inside the tunnel" is the leak wearing a
// flag. So both hosts DERIVE it, from the two inner facts the ML-DSA-65-signed
// descriptor carries — `inner_v4` and `inner_router_v4` — and from nothing
// else.
//
// The five clauses are the same on both, in the same order, because the two
// hosts are answering the same question about the same document. Neither of
// them may name `inner_router_v4`: it is the inner next hop "for PMTU signals
// only", the gateway behind it answers no queries, and pointing at it trades a
// leak for total name-resolution failure.
//
// ===========================================================================
// AMENDED 2026-08-12: ONE OF THE FIVE NARROWED, AND ONLY ONE
// ===========================================================================
//
// "The gateway behind it answers no queries" is a claim about a GATEWAY, and it
// was true of every gateway that had ever run. `cmd/winn3-gateway -resolver`
// (off by default) is one for which it is false, and it necessarily answers at
// the gateway's own `-inner-v4` — which IS the client's `inner_router_v4` —
// because winn3/tun's outbound validator refuses to carry a reply whose source
// is not the endpoint's own assignment. A resolver at a second inner address
// cannot answer through the tunnel at all. So "the resolver is the next hop" is
// the only shape this protocol permits, not a coincidence to be tolerated.
//
// The clause therefore reads "is the next hop AND the signed descriptor names no
// resolver there". The other four are untouched and still apply to the
// descriptor's own value: a signed fact about where the gateway listens is not
// permission to skip a check. The needles below pin BOTH halves — the field
// being read, and the narrowing being conditional on it — because a mutation
// that dropped the condition would widen the gate silently, and every existing
// needle in this list would still match.
var StandaloneMobileResolverGuards = []PostureGuard{
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "enum WinsWinn3Resolvers {",
		Why: "the Apple derivation itself. Without it fullTunnel installs config.dnsServers, " +
			"which is the AmneziaWG [Interface] DNS line, which lib/main.dart fills with the " +
			"PUBLIC Quad9 literals on Apple.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "guard WinsWinn3Resolvers.promotionRefusalReason(config) == nil else {",
		Why: "fullTunnel REFUSES rather than widening: it returns nil, which is " +
			"winn3_posture.h's \"every Build function returns false rather than a wider " +
			"posture\" in Swift. A builder that cannot refuse has no way to express this.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "let resolvers = WinsWinn3Resolvers.inner(config)",
		Why: "the promoted posture is built from the DERIVED set and never from " +
			"config.dnsServers. Mutation-tested 2026-08-09 and it SURVIVED replacement by " +
			"config.dnsServers -- the guard above makes the two equal on every reachable " +
			"input, so no behavioural test can tell them apart. This grep is the only thing " +
			"that can, and what it holds is the ORIGINAL DEFECT LINE not coming back.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "guard WinsWinn3PromotedPosture.evaluate(settings, config: config).usable else {",
		Why: "the builder checks its OWN output, the shape WinsWinn3BootstrapPosture gives the " +
			"narrow posture. Mutation-tested 2026-08-09 and it SURVIVED deletion for the same " +
			"reason the identical call in winn3_posture.h did: nothing reachable through the " +
			"shipping builder produces an object it rejects. Kept for the edit that makes it " +
			"reachable, and held by this grep because no behavioural test can.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "if let resolverReason = WinsWinn3Resolvers.promotionRefusalReason(config) {",
		Why: "the START pre-flight, which is linux_tunnel_backend.cc's shape: refuse while " +
			"nothing is installed and nothing has to be torn down. On Apple it also means a " +
			"session that could never promote never dials the gateway from the device, which " +
			"on this threat model is an observable connection bought for nothing.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
		Needle: "internal object WinnV3Resolvers {",
		Why: "the Android derivation. WinnV3Posture.promotion already refused an EMPTY " +
			"resolver list and that clause cannot see this defect: a resolver WAS named.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
		Needle: "WinnV3Resolvers.promotionRefusalReason(",
		Why: "the refusal has a caller inside the posture builder, so there is no path that " +
			"assembles a promoted posture without it. Asserted as the qualified CALL rather " +
			"than `…(dnsServers, innerAddress, innerNextHop)`: those three are local " +
			"parameter names the builder may rename without changing behaviour, while the " +
			"call from inside the builder is the behaviour, and the qualified form occurs " +
			"exactly once in the file.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt",
		Needle: "List<String> = parseConfigValue(awgConfig, \"DNS\")",
		Why: "the v1 fallback `?: \"10.8.1.1\"` no longer crosses into the v3 path. It stays " +
			"for the relay, where it is correct and always was. This is the line that stops a " +
			"v1 DEFAULT deciding where a v3 session resolves names. Asserted as the TYPE " +
			"`List<String>` on the v3 read (a raw parse with no default) rather than as the " +
			"earlier `val winn3ResolverCandidates …` form: that local variable name is a symbol " +
			"a refactor may rename without changing behaviour, while the `List<String> = … " +
			"parseConfigValue(awgConfig, \"DNS\")` shape is what makes this line the one that " +
			"cannot carry the `?: \"10.8.1.1\"` default. It occurs exactly once in the file " +
			"(the v1 branch reads the same key as a bare String with the default).",
	},
	{
		File:   "android/app/src/test/kotlin/org/winsvpn/app/WinnV3AdoptionTest.kt",
		Needle: "a v1 shaped resolver is refused for a standalone session",
		Why: "the Kotlin test that exercises the exact shape VpnTunnelService used to produce " +
			"-- DNS = 10.8.1.1 beside Address = 10.8.1.3, where the resolver is also the " +
			"defaulted inner next hop.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: `var winn3InnerResolverV4: String { winn3Field("inner_resolver_v4") }`,
		Why: "the SIGNED source of the resolver address on Apple. It is read from `[winn]` " +
			"beside inner_router_v4 -- the section carries descriptor fields under the " +
			"descriptor's own spellings -- and NOT from a dns key, which " +
			"ServedWinnSectionCarriesNoPostureKey still pins absent. If this accessor is " +
			"deleted the narrowing below can never fire and Apple silently returns to " +
			"refusing every gateway that runs a resolver, which reads as the gateway being " +
			"broken.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "if advertised.isEmpty || ipv4Value(advertised) != candidate {",
		Why: "THE NARROWING ITSELF on Apple, and the half no other needle can see. Delete " +
			"this line and the next-hop refusal becomes unconditional again (harmless, loud); " +
			"delete the whole `if` and it becomes unreachable, which is the dangerous " +
			"direction -- the next hop would be accepted as a resolver with no signed fact " +
			"saying anything listens there, and a promotion would go green pointing at " +
			"silence. Compared as PARSED VALUES so 10.64.0.1 and 10.64.000.1 are one address.",
	},
	{
		File:   "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Needle: "return [advertised]",
		Why: "the candidate derivation REPLACES rather than joins. When the descriptor names a " +
			"resolver, `[interface] DNS` -- which lib/main.dart fills with public Quad9 " +
			"literals on Apple -- is not appended beside it. NEDNSSettings(servers:) hands " +
			"the whole list to the resolver library and the LIBRARY picks which one answers, " +
			"so a public entry second in the list answers whenever the first is slow.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
		Needle: "if (advertised.isEmpty() || ipv4Value(advertised) != candidate) {",
		Why: "the same narrowing on Android, same position in the same clause order. The two " +
			"hosts answer one question about one document; a narrowing that landed on only " +
			"one of them would make the platforms disagree about where a session resolves " +
			"names, which is the class of divergence this whole package exists to catch.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3SessionPlan.kt",
		Needle: `const val KEY_INNER_RESOLVER_V4 = "inner_resolver_v4"`,
		Why: "the signed source on Android, read in the one object that already holds both " +
			"inner facts the derivation needs. ONE spelling only, unlike innerNextHopOf's " +
			"two: this field has no legacy name to stay compatible with, so a second " +
			"accepted spelling could only let a typo decide where every lookup goes.",
	},
	{
		File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3SessionPlan.kt",
		Needle: "listOf(innerResolver)",
		Why: "Android's candidate list REPLACES rather than joins, for VpnService.Builder the " +
			"same reason Apple's does for NEDNSSettings: addDnsServer hands every entry to " +
			"the platform resolver and the platform picks. promotionRefusalReason would " +
			"refuse a mixed list anyway; replacing means the honest configuration is never " +
			"rescued by a refusal.",
	},
}

// StandaloneResolverStagingGuards hold the remaining READINESS pins for the
// inner-resolver field: Dart still emits the `[winn]` line only when the
// verified descriptor carries it, and both desktop parsers already know the
// key. The advertisement interlock (client format version 2) was removed
// 2026-08-12 when kWinn3DescriptorFormatVersion bumped to 3; that guard's
// three preconditions had been recorded as met.
//
// These remaining needles pin CONSUMPTION, not inertness. Removing the Linux
// or Windows parser branch would delete the coverage proving those hosts can
// parse the key -- the thing that made the bump safe on desktop.
//
// Publishing a descriptor that names a resolver before one answers is now an
// operator-ordering constraint, not a client format pin. See the gateway
// deployment runbook §0.2.
var StandaloneResolverStagingGuards = []PostureGuard{
	{
		File: "lib/winn_protocol_dispatch.dart",
		// Two-line needle: the INI-safety loop at the same `if` spelling is a
		// different site (collection into _isSafeIniValue, not emission). A
		// `strings.Contains` of the `if` alone stays green if this writer is
		// deleted and the loop remains.
		Needle: "if (descriptor.innerResolverV4.isNotEmpty)\n      'inner_resolver_v4 = ${descriptor.innerResolverV4}',",
		Why: "the `[winn]` line is emitted ONLY when a verified descriptor carries a " +
			"non-empty field. Linux and Windows already know the key (the two needles " +
			"below), so unconditional emission of a known key would parse, not refuse. " +
			"What this still pins is naming a resolver the signed document does not " +
			"carry. The needle is the emission `if` plus the INI line it controls, " +
			"because the same `if` spelling also appears in the INI-safety loop.",
	},
	{
		File:   "linux/runner/linux_winn3_host.cc",
		Needle: `} else if (key == "inner_resolver_v4") {`,
		Why: "the key is KNOWN to Linux before it is ever emitted. ParseLinuxWinn3Section's " +
			"final else refuses an unrecognised [winn] key by name (\"a dropped key looks " +
			"exactly like a key that took effect\"), so without this branch the descriptor " +
			"bump would take standalone v3 down on Linux entirely. The psk branch beside it " +
			"exists for the same reason and says so.",
	},
	{
		File:   "windows/runner/winn3_supervisor.h",
		Needle: `} else if (served && key == "inner_resolver_v4") {`,
		Why: "the same protection on Windows, whose served [winn] parser has the same " +
			"unrecognised-key refusal. Stored AND consumed: the branch assigns " +
			"parsed.inner_resolver_v4, PostureInputFrom copies it onto " +
			"PostureInput.inner_resolver_v4, and winn3_posture.h derives against it. " +
			"What is still forbidden is assigning dns_servers_are_inner from this " +
			"served value — that boolean stays a local [winn3] declaration.",
	},
}

// StandaloneLinuxCallerGuards hold the wiring the second row is about.
var StandaloneLinuxCallerGuards = []PostureGuard{
	{
		File:   "linux/runner/linux_tunnel_backend.cc",
		Needle: "winsvpn::winn3host::LinuxConfigSelectsWinn3(raw_config)",
		Why: "the branch. Without it a served standalone config reaches ParseLinuxWinnSection " +
			"— the winn/1 AmneziaWG parser — and is refused in that parser's words about a " +
			"protocol it was not asked to speak.",
	},
	{
		File:   "linux/runner/linux_tunnel_backend.cc",
		Needle: "winsvpn::winn3host::ParseLinuxWinn3Section(raw_config",
		Why:    "the parser has a caller on the live start path rather than only in a test.",
	},
	{
		File:   "linux/runner/linux_tunnel_backend.cc",
		Needle: "winsvpn::winn3host::WriteLinuxWinn3KeyFiles(",
		Why:    "the served key VALUES become 0600 files, which is what the engine opens.",
	},
}

// PromotionPredicateGuards hold the ONE place the promotion gate is decided,
// and pin which counter feeds it.
//
// The brief is explicit: the promotion predicate is `Gate.State() ==
// StateCarrying && Stats().RxPackets > 0` — RxPackets, never RxOffered. The two
// counters differ meaningfully: RxPackets counts an inner packet VALIDATED and
// DELIVERED to the host device (the first moment the whole chain — carrier,
// crypto, framing, address assignment, host device — is proven); RxOffered
// counts an arrival, with nothing yet validated.
//
// The predicate is computed ONCE, next to the counters, in
// cmd/winn-datapath/winn3_status.go, precisely so that two hosts in two
// languages never each re-derive it and drift. This guard pins that single
// source so a sibling cannot widen it to `rxOffered` in the predicate body, or
// feed the correct predicate the wrong counter at the call site, without the
// conform suite noticing. The behavioural half is held by
// TestPromotionIsGatedOnDeliveriesAndNotOnArrivals and
// TestTheStatusDocumentPromotesOnlyAfterAnInnerPacketArrives in the engine
// package, which drive the two counters apart and assert PromotionReady stays
// false.
var PromotionPredicateGuards = []PostureGuard{
	{
		File:   "winn_protocol_experimental/cmd/winn-datapath/winn3_status.go",
		Needle: "return gate == tun.StateCarrying && rxPackets > 0",
		Why: "the predicate body. Reading rxOffered here would promote a tunnel that " +
			"validated nothing — the two-defect false-green a sibling lane already " +
			"caught in this protocol today.",
	},
	{
		File:   "winn_protocol_experimental/cmd/winn-datapath/winn3_status.go",
		Needle: "status.PromotionReady = winn3PromotionReady(gate, tunStats.RxPackets)",
		Why:    "the call site. A correct predicate fed RxOffered is the same false green.",
	},
	{
		File:   "winn_protocol_experimental/cmd/winn-datapath/winn3_status.go",
		Needle: "status.TxPackets = tunStats.TxPackets",
		Why: "transport observed BOTH ways. The promotion predicate reads RxPackets " +
			"(inbound deliveries), so the status document must ALSO publish TxPackets " +
			"(outbound sends) — without the outbound counter a host cannot " +
			"distinguish a tunnel that has proven the chain in both directions from " +
			"one that has only been spoken to, and a status check that sees RxPackets > 0 " +
			"but no TxPackets cannot tell 'the user's traffic went in' from 'it came back " +
			"out'. Both counters are pinned here so the document a host reasons over " +
			"carries transport evidence in both directions.",
	},
}

// RefusalSilenceGuards hold the runtime half of the v3 silence convention on
// the gateway's refusal path.
//
// A v3 gateway never answers an unauthenticated datagram — that is what makes
// the protocol resistant to probing, and in the Myanmar threat model it is what
// makes a coding disagreement look exactly like a censor. The behavioural teeth
// live in winn3/gateway/silence_test.go (TestEveryRejectionPathAnswersNothing,
// and its positive control TestOnlyAFreshAuthenticatedInitiationEmitsAByte) and
// winn3/session/credentialfault_test.go
// (TestEveryCredentialFaultIsSilentToTheClient). This guard pins the refusal
// path's structure on the gateway so a sibling that starts ANSWERING the
// unauthenticated path — turning one captured initiation into a permanent probe
// oracle — changes a line the suite holds.
var RefusalSilenceGuards = []PostureGuard{
	{
		File:   "winn_protocol_experimental/winn3/gateway/gateway.go",
		Needle: "g.unauth.Add(1)",
		Why: "the unauth refusal counter on the handshake path that cannot " +
			"authenticate. Its adjacent return is the identical-nothing every " +
			"rejection path must share; removing the counter or replacing the " +
			"silent return with a reply is exactly how a v3 gateway becomes a " +
			"probe a censor can find.",
	},
	{
		File:   "winn_protocol_experimental/winn3/gateway/gateway.go",
		Needle: "h.WriteResponse(g.notice, g.respPadTo)",
		Why: "the path-MTU notice is STATED to every client in the handshake " +
			"response. New refuses every path MTU checkPathMTU rejects, so this " +
			"package can construct a gateway that states nothing — the fail-open " +
			"half of silent-refusal #3. Pinning this call to g.notice (not nil) " +
			"keeps the 1450 fleet default honest: a gateway that sized itself at " +
			"one number and claimed another would manufacture the refusal rather " +
			"than report it.",
	},
	{
		File:   "winn_protocol_experimental/winn3/gateway/gateway.go",
		Needle: "g.refused.Add(1)",
		Why: "the capacity refusal counter on the handshake path that " +
			"authenticated but could not be served. Its adjacent return is the " +
			"identical-nothing every rejection path must share — a full table or " +
			"a broken binder must look exactly like a probe, not like a " +
			"capacity signal a censor can key on. Removing the counter or " +
			"answering the refused client is exactly how a v3 gateway becomes " +
			"findable.",
	},
}

// FleetDefaultPathMTUGate pins the fleet default path MTU value itself — the
// literal 1450 — and the gateway's resolution of its flag through that constant
// rather than a hard-coded number.
//
// The value moved from 1280 to 1450 on 2026-08-10 (the
// android-defaulted-the-path-mtu-to-1500 pin) and that row is in BOTH tables:
// the pin holds the half that was dangerous (the silent disagreement) and the
// divergence row holds the half that is still open (the two ends are not yet
// reconciled). This guard pins the VALUE that both halves revolve on, so that a
// silent edit to the constant — one that reshapes every plan floor on the fleet
// at once — fails the conform suite rather than passing it.
//
// The gateway flag half is what makes the 1450 raise load-bearing: the notice
// that closes silent-refusal #3 (pinned by RefusalSilenceGuards' WriteResponse
// needle) states whatever path MTU New was constructed with, and the -path-mtu
// flag is the operator's only way to set that number. A flag that hard-coded
// 1450 instead of naming carrier.DefaultPathMTU would survive a fleet-default
// raise on the other three entry points and leave the gateway on the old number.
var FleetDefaultPathMTUGate = []PostureGuard{
	{
		File:   "winn_protocol_experimental/winn3/carrier/sizing.go",
		Needle: "const DefaultPathMTU = 1450",
		Why: "the fleet default path MTU. Changing this constant reshapes every " +
			"plan floor on the fleet at once; pinning the literal value makes a " +
			"raise a decision this suite notices rather than a silent drift to a " +
			"dead-zone MTU.",
	},
	{
		File:   "winn_protocol_experimental/cmd/winn3-gateway/main.go",
		Needle: `"path-mtu", carrier.DefaultPathMTU`,
		Why: "the gateway's -path-mtu flag resolves its default through the ONE " +
			"fleet constant rather than a hard-coded literal. A hard-coded 1450 " +
			"here would survive a fleet-default raise on three hosts and leave " +
			"the gateway unmutually-agreeable with its clients — silent-refusal " +
			"#3 arriving by default rather than by configuration.",
	},
}

// ---------------------------------------------------------------------------
//
// ===========================================================================
// WHAT WAS WRONG
// ===========================================================================
//
// `winn3/tun.State.String()` produces six names. cmd/winn-datapath publishes
// the one that is current as `gate_state` in the engine's status document, and
// FIVE host call sites across four platforms decide whether to promote a
// tunnel by comparing that field against a copy of those names they hold
// themselves. Until 2026-08-09 nothing pinned the copies to the original.
// Android's own comment conceded the coupling in words — "The names are the Go
// `String()` values" — which is precisely the kind of promise this package
// exists to replace with a test.
//
// The Go side asserted `String() != ""` and `State(200) == "invalid"`. Both are
// true of any vocabulary at all. Every host test fed its own literal into its
// own parser, so each agreed with itself and none agreed with Go.
//
// ===========================================================================
// WHY IT IS THE WORST SHAPE THIS PROJECT HAS
// ===========================================================================
//
// Rename `carrying` in gate.go and all five hosts parse an unrecognised name.
// Every `mayCarry()` answers false. The promotion never fires. The tunnel
// handshakes, completes its post-quantum ratchet, rekeys on schedule and moves
// bytes — and never carries the user's traffic. It fails CLOSED and SILENTLY,
// no test in any language goes red, and under the Myanmar threat model it is
// indistinguishable from the censor: a v3 gateway never answers an
// unauthenticated datagram, so there is no second opinion anywhere in the
// system that could tell the two apart.
//
// It is the seventh member of the family this package was written for. The six
// before it were gateway_id encoding, Android's inner MTU, the unnegotiated
// path_mtu, the opaque admission secret, operator-value whitespace, and the
// cross-host `[winn]` key names.
//
// ===========================================================================
// THE SHAPE OF THE FIX, AND WHY IT IS THIS SHAPE
// ===========================================================================
//
// The `[winn]` key-name contract is the precedent and this copies it exactly.
// That contract works because the expectation is GENERATED by Go from the
// shipping code — ServedWinnSectionINI renders the real document — and each
// host's own source is then READ and required to carry it. Nothing is restated
// by hand on either side, and no host build has to change for the check to
// run.
//
// So here: [GateStateVocabulary] is DERIVED by walking winn3/tun's own
// DeclaredStates and calling the shipping String() on each. Nothing in this
// file spells a gate-state name. [GateStateVocabularyGuards] is a FUNCTION and
// not a var for that reason — its needles are built from the derived names, so
// renaming a state in gate.go rewrites the needles, and the host that still
// carries the old spelling is the host that fails.
//
// The check runs in BOTH directions, which is the half a needle list alone
// does not give:
//
//   - Go changes  → the derived needle no longer occurs in the host file.
//   - a host changes → [GateStateHostVocabularies] names the DECLARATION each
//     host makes, the test EXTRACTS the value the host actually assigned, and
//     compares it. A host that swapped `carrying` for `rekeying` still
//     contains the word `carrying` somewhere in its comments; extraction sees
//     the assignment, a `strings.Contains` would not.

// GateStateName is one member of the vocabulary, as Go emits it.
type GateStateName struct {
	// Ordinal is the byte value. It never crosses the boundary — the NAME
	// does — and it is carried so a report can say which state it meant.
	Ordinal uint8 `json:"ordinal"`

	// Name is `winn3/tun.State.String()` for that value. This is the string
	// that appears in the engine's `gate_state` field.
	Name string `json:"name"`

	// MayCarry is `winn3/tun.State.MayCarry()`. Exactly one is true, and the
	// suite checks that rather than assuming it.
	MayCarry bool `json:"may_carry"`
}

// GateStateVocabulary is the vocabulary winn3/tun emits, derived from
// winn3/tun.
//
// It restates nothing. If this function were to carry its own list of names it
// would be a sixth hand-written copy of the strings, which is the defect.
func GateStateVocabulary() []GateStateName {
	states := tun.DeclaredStates()
	out := make([]GateStateName, 0, len(states))
	for _, s := range states {
		out = append(out, GateStateName{
			Ordinal:  uint8(s),
			Name:     s.String(),
			MayCarry: s.MayCarry(),
		})
	}
	return out
}

// GateStateCarryingName is the ONE name in which an inner packet may move.
//
// Every host compares `gate_state` against its own copy of this string, and
// this is the copy all of them are checked against.
func GateStateCarryingName() string { return tun.StateCarrying.String() }

// GateStateUnknownName is what winn3/tun calls a value that is not a state.
//
// It is a sentinel, never a member of the vocabulary, and no host may hold it
// as one — a host that accepted it would have a seventh name that Go can emit
// for a byte it never meant to send.
func GateStateUnknownName() string { return tun.InvalidStateName }

// GateStateVocabularyDocument renders the vocabulary as the checked-in text
// artifact non-Go hosts read.
//
// One line per state, `ordinal<TAB>name<TAB>carries|holds`, ordinal order, with
// the sentinel last and marked. It goes into [Vectors] so `winn3-conformance
// -emit` publishes it beside the plan floors and the demux tokens: a host
// harness that cannot import Go still gets the vocabulary from the code that
// defines it rather than from a wiki page.
func GateStateVocabularyDocument() string {
	var sb strings.Builder
	sb.WriteString("# winn3/tun.State.String() — the gate_state vocabulary.\n")
	sb.WriteString("# GENERATED from winn3/tun. Do not hand-edit; regenerate with\n")
	sb.WriteString("# cmd/winn3-conformance -emit.\n")
	for _, entry := range GateStateVocabulary() {
		verdict := "holds"
		if entry.MayCarry {
			verdict = "carries"
		}
		fmt.Fprintf(&sb, "%d\t%s\t%s\n", entry.Ordinal, entry.Name, verdict)
	}
	fmt.Fprintf(&sb, "-\t%s\tsentinel-never-a-state\n", GateStateUnknownName())
	return sb.String()
}

// GateStateHostVocabulary is one host's copy of the vocabulary, described
// precisely enough to be EXTRACTED rather than merely grepped for.
type GateStateHostVocabulary struct {
	// File is repo-relative.
	File string

	// Language is for the failure message; a reader holding a red run needs to
	// know which platform stopped promoting.
	Language string

	// Full is true when the host enumerates the WHOLE vocabulary and false when
	// it holds only the carrying name.
	//
	// The distinction is real and is not laxness. Android parses `gate_state`
	// into an enum, so it needs every name and a name it does not know is a
	// name it must reject. Apple, Windows and Linux compare for equality
	// against the single carrying name and treat everything else — including
	// names that do not exist — as "hold the bootstrap posture". Both are
	// fail-closed; only the first can be wrong about a name that is not
	// `carrying`.
	Full bool

	// DeclPrefix is the text immediately before the value, and DeclSuffix the
	// text immediately after. For a single-name host the value between them
	// must equal [GateStateCarryingName]. For a full-vocabulary host the span
	// is the whole declaration block and CasePattern picks the pairs out of it.
	DeclPrefix string
	DeclSuffix string

	// CasePattern, for a full-vocabulary host, matches one `CASE("wire")` pair
	// inside the block: submatch 1 is the host's own case name, submatch 2 the
	// wire name.
	CasePattern string

	// CarryingClausePattern, for a full-vocabulary host, matches the clause
	// that says which case carries. Submatch 1 is that case's name. It is read
	// from the host rather than assumed, because the host's spelling of its own
	// case names is the host's business — the WIRE name is the contract.
	CarryingClausePattern string

	// ParseFunc, for a full-vocabulary host, is the declaration of the function
	// that turns a wire name into a state. Its BODY is read and refused if it
	// defaults.
	//
	// A needle cannot hold this. Mutation testing on 2026-08-09 appended
	// `?: CARRYING` to Android's fromWire and every grep stayed green, because
	// the needle they look for is a PREFIX of the fail-open line. A host that
	// defaults promotes on any name at all — which is precisely what a rename
	// on the Go side looks like from the host's side.
	ParseFunc string

	// Why says what breaks if this host's copy drifts.
	Why string
}

// GateStateHostVocabularies is every place outside Go that holds a copy of the
// gate-state vocabulary.
//
// The list is the point. A host missing from it is a host this contract does
// not cover, and a green run that skipped a platform looks exactly like one
// that checked it — so TestTheGateStateVocabularyIsTheSameOnEveryHost also
// asserts that no OTHER file in the host trees carries a bare gate-state
// literal.
var GateStateHostVocabularies = []GateStateHostVocabulary{
	{
		File:                  "android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt",
		Language:              "kotlin",
		Full:                  true,
		DeclPrefix:            "internal enum class WinnV3GateState(val wire: String) {",
		DeclSuffix:            "\n    ;",
		CasePattern:           `([A-Z][A-Z0-9_]*)\("([^"]*)"\)`,
		CarryingClausePattern: `fun mayCarry\(\): Boolean = this == ([A-Z][A-Z0-9_]*)`,
		ParseFunc:             "fun fromWire(text: String?): WinnV3GateState? {",
		Why: "the shipping Android host, and the ONLY platform v3 ships on today. Its own " +
			"comment says \"The names are the Go String() values\", which is the promise this " +
			"contract replaces with a check.",
	},
	{
		File:       "windows/runner/winn3_posture.h",
		Language:   "c++, shared with Linux",
		DeclPrefix: "inline constexpr char kCarryingGate[] = \"",
		DeclSuffix: "\"",
		Why: "kCarryingGate is compared by winn3_posture.h and winn3_supervisor.h on Windows " +
			"AND by linux_winn3_host.cc through this same header, so ONE edit here silently " +
			"changes two platforms. It is the only gate-state literal either desktop host has.",
	},
	{
		File:       "apple/WinsTunnelCore/WinsWinn3HostContract.swift",
		Language:   "swift",
		DeclPrefix: "static let carryingState = \"",
		DeclSuffix: "\"",
		Why: "WinsWinn3PromotionGate.gateIsCarrying compares the engine's winn3_gate_state " +
			"field against this and nothing else, so this literal alone decides whether an " +
			"iOS or macOS session ever promotes.",
	},
}

// GateStateVocabularyGuards are the needles, BUILT from the derived vocabulary.
//
// A function and not a var: the needles embed the names winn3/tun emits, so a
// rename in gate.go rewrites them and the hosts still carrying the old
// spelling are the ones that fail — by name, in the same run, with the reason
// attached.
//
// What they hold that value-extraction does not: the fail-closed SHAPE. A host
// can agree about every name and still default an unrecognised one to
// carrying, which is the failure that stops being theoretical the moment
// either side of the seam adds a state.
func GateStateVocabularyGuards() []PostureGuard {
	carrying := GateStateCarryingName()
	guards := []PostureGuard{
		{
			File:   "windows/runner/winn3_posture.h",
			Needle: `inline constexpr char kCarryingGate[] = "` + carrying + `";`,
			Why: "the Windows/Linux shared constant IS the Go name. If this needle is missing " +
				"the two desktop hosts are comparing gate_state against a string the engine " +
				"never emits, every promotion holds at the bootstrap posture, and nothing is " +
				"logged because holding is the correct behaviour for a gate that is not " +
				"carrying.",
		},
		{
			File:   "windows/runner/winn3_posture.h",
			Needle: "if (status.gate_state != kCarryingGate) {",
			Why: "the comparison is EQUALITY against the one carrying name, so every other " +
				"name — including one this host has never heard of — holds. A host that " +
				"switched on a vocabulary it copied would fail OPEN on a name Go added.",
		},
		{
			File:   "linux/runner/linux_winn3_host.cc",
			Needle: "if (status.gate_state != winsvpn::winn3::kCarryingGate) {",
			Why: "Linux consumes the SHARED constant rather than repeating the literal. This " +
				"is what keeps the fifth call site from becoming a fifth independent copy of " +
				"the string.",
		},
		{
			File:   "linux/runner/winn3_posture.h",
			Needle: `inline constexpr char kCarryingGate[] = "` + carrying + `";`,
			Why: "Linux ships its OWN copy of the shared posture header, so its kCarryingGate " +
				"DECLARATION carries the name just as the Windows copy does. The ValueExtraction " +
				"contract covers the single Windows declaration (Windows and Linux share one " +
				"header, but the working tree keeps a per-platform copy); this accounts for the " +
				"Linux declaration. Added 2026-08-11 when the Linux copy was first materialised " +
				"and TestNoOtherHostFileHoldsAGateStateLiteral went red on it: a DECLARATION is " +
				"the legitimate home of the string, and it was failing only because the " +
				"contract paid for the Windows copy and not the Linux one.",
		},
		{
			File:   "apple/WinsTunnelCore/WinsWinn3HostContract.swift",
			Needle: `static let carryingState = "` + carrying + `"`,
			Why: "the only gate-state literal on Apple. WinsWinn3PromotionGate.gateIsCarrying " +
				"compares against it and returns false for anything else, so a stale spelling " +
				"here means no iOS or macOS session ever promotes and none of them says why.",
		},
		{
			File:   "apple/WinsTunnelCore/WinsWinn3HostContract.swift",
			Needle: "return state == carryingState",
			Why: "equality against the single name, and a missing key is false. Apple's " +
				"fail-closed shape, held as bytes.",
		},
		{
			File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt",
			Needle: "return entries.firstOrNull { it.wire == text }",
			Why: "Android is the one host that parses the WHOLE vocabulary, so it is the one " +
				"host that could default. firstOrNull returns null for an unknown name and the " +
				"caller treats null as not carrying. A `?: DOWN` here would still fail closed; " +
				"a `?: CARRYING` would move a user's traffic on a name nothing recognised.",
		},
		{
			File:   "android/devicecheck/app/src/main/kotlin/org/winsvpn/devicecheck/V3PostureCheckService.kt",
			Needle: `{"gate_state":"` + carrying + `","rx_packets":0,"rx_offered":9}`,
			Why: "the ON-DEVICE check's synthetic status document. It is not a decision site — " +
				"it is a FIXTURE — and that is precisely why it needs pinning: it lives under " +
				"src/main, it runs on a real handset, and its green is the one somebody " +
				"believes. Feeding a stale name to a parser that also holds the stale name is " +
				"the shape of this whole defect family: both sides agree with each other and " +
				"neither agrees with the engine.",
		},
		{
			File:   "winn_protocol_experimental/cdatapath/winn_datapath.h",
			Needle: `the tun layer's gate; "` + carrying + `" is the only carrying`,
			Why: "the C ABI header is what a non-Go host reads to learn what the field MEANS. " +
				"A stale name here teaches the next host the wrong string, which is how a " +
				"sixth hand-copy gets written correctly-according-to-the-docs and is wrong.",
		},
		{
			File:   "apple/EngineWrappers/WinnTunnel.h",
			Needle: `the tun layer's gate; "` + carrying + `" is the only carrying`,
			Why:    "the Apple-side copy of the same ABI documentation, for the same reason.",
		},
		{
			File:   "winn_protocol_experimental/cdatapath/winn_datapath_winn3.go",
			Needle: `winn3_gate_state == "` + carrying + `"  is Gate.State() == StateCarrying`,
			Why: "the Go-side statement of the same equivalence, on the type that PUBLISHES " +
				"the field. Its opening line says the two fields are \"named so that no host " +
				"has to infer them\" — which is only true while the name it prints is the name " +
				"String() emits.",
		},
		{
			File:   "linux/runner/linux_winn3_host_e2e.cc",
			Needle: `probe.gate_state == winsvpn::winn3::kCarryingGate`,
			Why: "the Linux end-to-end harness's warm-up wait. Found by this contract's own " +
				"sweep on 2026-08-09, MINUTES after a sibling lane wrote it: a bare literal " +
				"where linux_winn3_host.cc — in the same directory, through the same " +
				"winn3_posture.h it already includes — uses winsvpn::winn3::kCarryingGate.\n" +
				"  The literal was replaced with the shared constant later the same day, so " +
				"this needle no longer pins a copy of the name — there is no copy left to " +
				"pin, and TestNoOtherHostFileHoldsAGateStateLiteral now accounts for zero " +
				"occurrences in this file because the needle contains none.\n" +
				"  It is kept, and deliberately not dropped, because it pins something the " +
				"sweep cannot: that this file still CONSUMES the constant. A sweep for stray " +
				"literals goes green on a file that stopped checking gate_state altogether, " +
				"and a harness that no longer waits for carrying would send from t=0 and " +
				"charge the datapath for its own race — which is exactly what an earlier run " +
				"of this driver did, 6 of 64.",
		},
	}
	// Every name on the authoritative Kotlin source, as the pair the enum
	// actually declares. android/devicecheck/build_devicecheck.sh copies this
	// file into its generated tree immediately before building; that generated,
	// gitignored output is not a second source of truth.
	for _, entry := range GateStateVocabulary() {
		guards = append(guards, PostureGuard{
			File:   "android/app/src/main/kotlin/org/winsvpn/app/WinnV3StagedStart.kt",
			Needle: `("` + entry.Name + `")`,
			Why: "the Kotlin enum must declare the wire name winn3/tun.State(" +
				strconv.Itoa(int(entry.Ordinal)) + ").String() emits. A name the enum does " +
				"not carry is a gate_state WinnV3GateState.fromWire returns null for, and " +
				"null is not carrying.",
		})
	}
	return guards
}

// ---------------------------------------------------------------------------
// the inner-resolver /24 block mask
// ---------------------------------------------------------------------------
//
// ===========================================================================
// WHY THIS SEAM NEEDS A CONTRACT OF ITS OWN
// ===========================================================================
//
// Every client family decides "is this resolver INSIDE my tunnel" by masking
// the candidate and its own signed inner assignment down to a block and
// comparing. The block is a /24 on all three, and the /24 is hard-coded rather
// than carried: the descriptor states the assignment as a BARE ADDRESS with no
// prefix, so the narrowest inner space a host can name without inventing a
// number that was never signed is the /24 around it.
//
// The three families do not share a line of code. C++ NAMES the constant
// (resolvers::kInnerBlockMask); Swift and Kotlin INLINE it, twice each, inside
// a one-expression function. Nothing in the tree made them agree. The desktop
// suite pinned its own side on 2026-08-12
// (linux/runner/winn3_posture_test.cc, TestTheInnerBlockFloorIsTheOneAppleAndAndroidUse)
// and said in its own comment that it could do no better, because a C++ program
// cannot read a .swift or a .kt file. This package can, and already does it for
// the `[winn]` key names and the gate-state vocabulary, so this is that
// mechanism pointed at this seam.
//
// The direction that hurts is WIDENING. SameInnerBlock is a REFUSAL predicate:
// a wider block (shorter prefix) calls more candidates "inside", so a /16 floor
// on one platform accepts a resolver sitting in another tenant's /24 off the
// same signed descriptor — while the platforms that kept /24 refuse it. One
// document, two answers, and the platform that guessed wider is the one that
// leaks. Narrowing only ever over-refuses, which is the safe direction and is
// what the C++ header's own comment says.
//
// ===========================================================================
// WHY THE VALUE IS EXTRACTED AND NOT GREPPED FOR
// ===========================================================================
//
// This is not a preference. windows/runner/winn3_posture.h states the number in
// PROSE twice — "a hard 0xFFFFFF00 floor", "Apple spells `0xFFFF_FF00` and
// Android spells `0xFFFFFF00L`" — in the paragraph immediately above the
// declaration. A strings.Contains needle over that file stays green after
// kInnerBlockMask is mutated to any other value, because the comment still
// carries every spelling the needle could look for. Same shape as the drifted
// Swift fixture in TestTheGateStateExtractorCanActuallyFail, and here it is not
// hypothetical: the comment is in the shipping header today.
//
// So the LITERAL each family assigns is extracted from its own source, parsed
// to a number, and compared. Needles are kept for what extraction cannot see —
// the PROSE sites, which teach the next author the number and are the way a
// sixth copy gets written correctly-according-to-the-docs and wrong.

// InnerResolverBlockMask is the /24 floor every client family masks an inner
// IPv4 address with before deciding whether a resolver is inside the tunnel.
//
// UNLIKE the gate-state vocabulary, this is not derived: there is no Go owner
// to derive it from. The engine never performs this derivation — it is a
// client-side refusal against a signed descriptor field, and the only Go code
// that mentions the number at all is cmd/winn3-gateway's
// resolverDerivationWarning, which states it as a PREFIX LENGTH and is a
// warning rather than a decision. So the suite states the reference, and the
// coordinated-move clause in
// TestTheInnerResolverBlockMaskIsTheSameInEveryClientFamily is what stops that
// statement becoming a rubber stamp: three families moving together does not
// silently re-point this constant, it fails and asks for the reasoning.
const InnerResolverBlockMask uint32 = 0xFFFFFF00

// InnerResolverBlockPrefixLen is the same number as a prefix length, which is
// the form the gateway states it in.
const InnerResolverBlockPrefixLen = 24

// InnerBlockMaskDeclaration is ONE family's declaration of the mask, described
// precisely enough to be EXTRACTED rather than merely grepped for.
type InnerBlockMaskDeclaration struct {
	// File is repo-relative.
	File string

	// Language is for the failure message; a reader holding a red run needs to
	// know which platform started answering a different question.
	Language string

	// Decl is the text that opens the declaration. It must occur EXACTLY ONCE
	// in the file — a second occurrence means a second declaration, which is
	// the defect this whole contract exists to stop, and which an extractor
	// that took the first match would read straight past.
	Decl string

	// Terminator ends the span. The text between Decl and the next Terminator
	// after it is what gets parsed.
	Terminator string

	// Literals is how many mask literals the span must contain.
	//
	// It is not decoration. C++ names the constant once and applies it by name,
	// so its span holds ONE. Swift and Kotlin inline it into BOTH operands, so
	// theirs hold TWO — and requiring two is what catches the half-mutation
	// `(a & MASK) == b`, which drops the mask from one side, leaves a correct
	// literal in the file, and turns a block comparison into an equality that
	// accepts exactly one address.
	Literals int

	// Why says what breaks if this family's copy drifts.
	Why string
}

// InnerBlockMaskDeclarations is every place the /24 floor is declared.
//
// FOUR rows for THREE families. The extra row is the per-platform copy of the
// shared C++ header, which is tracked source and can drift. The devicecheck
// Kotlin files are different: build_devicecheck.sh copies the authoritative
// Android main sources into a gitignored generated tree immediately before the
// lab build, so listing those outputs here would make a clean source archive
// fail before generation and would promote stale generated bytes to authority.
var InnerBlockMaskDeclarations = []InnerBlockMaskDeclaration{
	{
		File:       "windows/runner/winn3_posture.h",
		Language:   "c++, shared with Linux",
		Decl:       "inline constexpr uint32_t kInnerBlockMask =",
		Terminator: ";",
		Literals:   1,
		Why: "the canonical declaration, and the only one of the three families that NAMES " +
			"the constant instead of inlining it. windows/runner/winn3_supervisor.h and " +
			"linux/runner/linux_winn3_host.cc both reach the derivation through this header, " +
			"so ONE edit here moves two desktop platforms at once.",
	},
	{
		File:       "linux/runner/winn3_posture.h",
		Language:   "c++",
		Decl:       "inline constexpr uint32_t kInnerBlockMask =",
		Terminator: ";",
		Literals:   1,
		Why: "the working tree keeps a per-platform copy of the shared posture header, " +
			"byte-identical to the Windows one today. A header that is copied rather than " +
			"included is a header that can be edited on one platform, and the gate-state " +
			"contract had to add this same second row on 2026-08-11 for exactly that reason.",
	},
	{
		File:       "apple/WinsTunnelCore/WinsWinn3SessionStart.swift",
		Language:   "swift",
		Decl:       "static func sameInnerBlock(_ a: UInt32, _ b: UInt32) -> Bool {",
		Terminator: "}",
		Literals:   2,
		Why: "WinsWinn3Resolvers.notInnerReason's last clause is the only thing standing " +
			"between an iOS or macOS session and a resolver outside its own inner block. " +
			"Apple INLINES the literal into both operands, so there is no name here for a " +
			"reader to follow and no compiler anywhere that sees this file and the C++ one.",
	},
	{
		File:       "android/app/src/main/kotlin/org/winsvpn/app/WinnV3Posture.kt",
		Language:   "kotlin",
		Decl:       "fun sameInnerBlock(a: Long, b: Long): Boolean =",
		Terminator: "\n",
		Literals:   2,
		Why: "the shipping Android host — the platform v3 ships on today. Android holds the " +
			"mask as a Long because Kotlin has no unsigned 32-bit type, which is a second way " +
			"this literal can be got wrong that neither other family can reproduce.",
	},
}

// InnerBlockMaskGuards are the needles, BUILT from the reference constant so
// that changing the constant rewrites them and every site still teaching the
// old number fails.
//
// They deliberately do NOT re-pin the five declarations above. Extraction
// already holds those, and pinning their exact spelling as well would put the
// contract's foot on a tripwire it does not need: a lane that lowercases a hex
// digit or re-wraps an expression would go red for a change that moved no
// number. This file has been bitten by that once already — see the 2026-08-12
// amendment note on the Android resolver needle, where a re-wrap broke a
// contiguous substring and the fix was to re-pin to text that still exists.
//
// What these hold instead is everything extraction cannot see: the files that
// STATE the number in prose without declaring it, and the gateway's
// prefix-length form. A number that changes in five declarations and stays in
// four explanations is how the next author writes a sixth copy
// correctly-according-to-the-docs and is wrong — the same reason the gate-state
// contract pins the C ABI header's documentation.
//
// The needles are bare TOKENS rather than sentences, on purpose. A token
// survives a comment re-wrap; a sentence does not, and a needle that goes red
// on reflowed prose is a needle somebody deletes.
func InnerBlockMaskGuards() []PostureGuard {
	mask := fmt.Sprintf("0x%08X", InnerResolverBlockMask)
	return []PostureGuard{
		{
			File:   "windows/runner/winn3_supervisor.h",
			Needle: mask,
			Why: "the Windows supervisor states the floor in prose twice and declares it " +
				"nowhere — it reaches the derivation through winn3_posture.h. If the number " +
				"moves and this file is not updated, the explanation a reader is handed here " +
				"disagrees with the code it is explaining, and the reader believes the " +
				"explanation.",
		},
		{
			File:   "linux/runner/linux_winn3_host.h",
			Needle: mask,
			Why: "the Linux host header makes the same claim in prose — that it refuses " +
				"clause for clause against this floor — and likewise declares nothing.",
		},
		{
			File:   "winn_protocol_experimental/cmd/winn3-gateway/resolve.go",
			Needle: mask,
			Why: "resolverDerivationWarning's doc comment quotes Android's spelling of this " +
				"mask to explain WHY a pool wider than the floor strands clients. It is the " +
				"only place in the Go tree that states the client-side number at all, and it " +
				"is what an operator reads when the warning fires.",
		},
		{
			File:   "winn_protocol_experimental/cmd/winn3-gateway/resolve.go",
			Needle: "prefix.Bits() >= " + strconv.Itoa(InnerResolverBlockPrefixLen),
			Why: "the SAME constant as a prefix length, and the gateway's actual behaviour " +
				"rather than its prose: a -forward-cidr at or narrower than the client floor " +
				"strands nobody, so no warning is emitted. If the client families narrow their " +
				"floor and this bound does not follow, the responder goes quiet for exactly " +
				"the pool widths that now strand clients — the warning's own subject.",
		},
		{
			File:   "linux/runner/winn3_posture_test.cc",
			Needle: "TestTheInnerBlockFloorIsTheOneAppleAndAndroidUse",
			Why: "the desktop suite's own pin on the C++ side, added 2026-08-12. It builds and " +
				"RUNS, which nothing here does, so it covers the arithmetic (a /16 makes the " +
				"second pair same-block, a /28 makes the third pair different) that this " +
				"contract only covers as a number. Pinned by NAME so it cannot be renamed away " +
				"leaving the running half of this seam uncovered.",
		},
	}
}

// FromServedSection is the derivation a HOST performs on a served section.
//
// It does exactly what the host does and nothing more: ONE base64 decode of
// `gateway_id` at the descriptor boundary, and `admission_key` decoded from its
// transport base64 to the file's bytes with NO further interpretation. Running
// the result through [Derivation.MustMatch] is what proves a served config
// produces the same admission-tag inputs as every engine in the tree.
//
// A missing or empty `gateway_id` / `admission_key` is refused. encoding/base64
// DecodeString("") succeeds with empty bytes, which is not a derivation — it
// is the absence of one. Two hosts that both omitted the key would otherwise
// agree on empty admission-tag inputs. Apple already refuses the same absence
// by name (WinsTunnelConfig.winn3StartRefusalReason).
func FromServedSection(host string, section map[string]string) (Derivation, error) {
	if section["gateway_id"] == "" {
		return Derivation{}, fmt.Errorf("served gateway_id is missing")
	}
	gatewayID, err := base64.StdEncoding.DecodeString(section["gateway_id"])
	if err != nil {
		return Derivation{}, fmt.Errorf(
			"served gateway_id is not base64 over the operator name: %w", err)
	}
	if len(gatewayID) == 0 {
		return Derivation{}, fmt.Errorf("served gateway_id decodes to empty")
	}
	// The transport encoding comes off; what is underneath is OPAQUE and is
	// never hex-decoded. That second step is the one that keys 32 bytes against
	// the other end's 64.
	if section["admission_key"] == "" {
		return Derivation{}, fmt.Errorf("served admission_key is missing")
	}
	admissionKey, err := base64.StdEncoding.DecodeString(section["admission_key"])
	if err != nil {
		return Derivation{}, fmt.Errorf("served admission_key is not base64: %w", err)
	}
	if len(admissionKey) == 0 {
		return Derivation{}, fmt.Errorf("served admission_key decodes to empty")
	}

	pathMTU := DefaultPathMTU
	if raw := strings.TrimSpace(section["path_mtu"]); raw != "" {
		pathMTU, err = strconv.Atoi(raw)
		if err != nil {
			return Derivation{}, fmt.Errorf("served path_mtu is not a number: %w", err)
		}
	}
	var classNames []string
	if raw := strings.TrimSpace(section["carrier_classes"]); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				classNames = append(classNames, trimmed)
			}
		}
	}
	classes, err := Classes(classNames)
	if err != nil {
		return Derivation{}, err
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return Derivation{}, err
	}
	return Derivation{
		Host:         host,
		GatewayID:    gatewayID,
		AdmissionKey: admissionKey,
		TagSize:      core.DefaultTagSize,
		PathMTU:      pathMTU,
		Classes:      classNames,
		MessageSize:  sizing.MessageSize,
		InnerMTU:     sizing.InnerMTU,
		InnerIPv6:    sizing.InnerIPv6,
	}, nil
}

// ---------------------------------------------------------------------------
// the comparison
// ---------------------------------------------------------------------------

// Mismatch is one field on which two hosts disagree.
//
// It always carries BOTH values rendered, because "the admission tag inputs
// differ" is not actionable and "gateway_id is 77696e73677730 31 here and
// c2c8b0f34e here" is: the second tells the reader immediately that one side
// base64-decoded it.
type Mismatch struct {
	Field string
	A     string
	B     string
}

func (m Mismatch) String() string {
	return fmt.Sprintf("%s: %s != %s", m.Field, m.A, m.B)
}

// Compare returns every field on which a and b disagree, in a stable order.
//
// Nothing short-circuits. A host that has both the wrong gateway id AND the
// wrong floor should learn both in one run, because each one alone produces
// the same symptom — silence — and finding the second after fixing the first
// costs another field cycle.
func Compare(a, b Derivation) []Mismatch {
	var out []Mismatch
	add := func(field, va, vb string) {
		if va != vb {
			out = append(out, Mismatch{Field: field, A: va, B: vb})
		}
	}
	add("gateway_id (hex, the authenticated tag input)",
		hexOrEmpty(a.GatewayID), hexOrEmpty(b.GatewayID))
	add("gateway_id (as text)", quoteBytes(a.GatewayID), quoteBytes(b.GatewayID))
	add("admission_key (hex, opaque bytes — NEVER decoded)",
		hexOrEmpty(a.AdmissionKey), hexOrEmpty(b.AdmissionKey))
	add("admission_key length", fmt.Sprint(len(a.AdmissionKey)), fmt.Sprint(len(b.AdmissionKey)))
	add("tag_size", fmt.Sprint(a.TagSize), fmt.Sprint(b.TagSize))
	add("path_mtu (resolved, after defaults)", fmt.Sprint(a.PathMTU), fmt.Sprint(b.PathMTU))
	add("carrier_classes", strings.Join(a.Classes, "+"), strings.Join(b.Classes, "+"))
	add("plan floor message_size", fmt.Sprint(a.MessageSize), fmt.Sprint(b.MessageSize))
	add("plan floor inner_mtu", fmt.Sprint(a.InnerMTU), fmt.Sprint(b.InnerMTU))
	add("plan floor inner_ipv6", fmt.Sprint(a.InnerIPv6), fmt.Sprint(b.InnerIPv6))
	return out
}

// Explain renders a mismatch set as the message the suite fails with.
//
// It names both hosts, both values, and the consequence — because the whole
// reason these defects survived to production is that their consequence is
// invisible at both ends.
func Explain(a, b Derivation, ms []Mismatch) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\nwinn/3 CONFORMANCE FAILURE: %d divergence(s) between two hosts fed the SAME operator configuration\n",
		len(ms))
	fmt.Fprintf(&sb, "  A = %s\n", a.Host)
	fmt.Fprintf(&sb, "  B = %s\n", b.Host)
	for _, m := range ms {
		fmt.Fprintf(&sb, "    %s\n", m.String())
		fmt.Fprintf(&sb, "        A(%s) = %s\n", a.Host, m.A)
		fmt.Fprintf(&sb, "        B(%s) = %s\n", b.Host, m.B)
	}
	sb.WriteString(consequence(ms))
	return sb.String()
}

func consequence(ms []Mismatch) string {
	admission, sizing, transport := false, false, false
	for _, m := range ms {
		switch {
		case strings.HasPrefix(m.Field, "gateway_id"),
			strings.HasPrefix(m.Field, "admission_key"),
			m.Field == "tag_size":
			admission = true
		case strings.HasPrefix(m.Field, "transport_observed"):
			transport = true
		default:
			sizing = true
		}
	}
	var sb strings.Builder
	if admission {
		sb.WriteString("\n  CONSEQUENCE (admission): the two ends compute DIFFERENT admission tags from the\n" +
			"  same operator value. The tag inputs are never transmitted, so nothing on the\n" +
			"  wire can catch the disagreement. A v3 gateway does not answer a datagram it\n" +
			"  could not authenticate — no response, no ICMP, no log line — so the client\n" +
			"  exhausts its handshake attempts against a gateway that is working perfectly.\n" +
			"  On a censored network that is indistinguishable from the gateway being blocked.\n")
	}
	if sizing {
		sb.WriteString("\n  CONSEQUENCE (sizing): the two ends plan different message sizes. Small packets\n" +
			"  cross perfectly and every full-size flow is refused, while the tunnel reads\n" +
			"  \"up\" at both ends. The report arrives as \"large downloads stall\" from a handset\n" +
			"  nobody can attach a debugger to.\n")
	}
	if transport {
		sb.WriteString("\n  CONSEQUENCE (transport observation): the status document does not publish\n" +
			"  transport counters in both directions. The promotion predicate gates on\n" +
			"  RxPackets alone, so a document that carries inbound and not outbound cannot\n" +
			"  tell \"data went in and came back\" from \"inbound only, data never left\".\n")
	}
	return sb.String()
}

// MustMatch is TIER A: a and b must agree on every field.
//
// t is an interface rather than *testing.T so this can be driven from a command
// as well as from a test — CI runs both, and a conformance rule that only
// exists inside `go test` is a rule the release pipeline does not have.
func (d Derivation) MustMatch(t Reporter, other Derivation) {
	t.Helper()
	if ms := Compare(d, other); len(ms) > 0 {
		t.Errorf("%s", Explain(d, other, ms))
	}
}

// Reporter is the sliver of *testing.T this package needs.
type Reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// ---------------------------------------------------------------------------
// the admission round trip — the property, not a proxy for it
// ---------------------------------------------------------------------------

// AdmissionRoundTrip seals a real handshake initiation under the CLIENT's
// derived admission profile and reads it under the GATEWAY's.
//
// This is the check that fails in the same currency the defect does. Comparing
// hex strings proves the inputs match; this proves the gateway ANSWERS. A host
// that derives a gateway id six bytes long instead of eight produces an
// initiation core.Responder.ReadInitiation refuses, which is exactly what
// happened in the field, and it happens here in 20 milliseconds instead of
// after five retransmits on a handset.
//
// It uses only exported core API — NewInitiator/WriteInitiation and
// NewResponder/ReadInitiation — so it exercises the same path the engine does
// and cannot be satisfied by a test-only shortcut.
func AdmissionRoundTrip(client, gateway Derivation) error {
	gwStatic, err := core.GenerateStaticKey()
	if err != nil {
		return err
	}
	gwPublic, err := core.NewPublicKey(gwStatic.Public())
	if err != nil {
		return err
	}
	cliStatic, err := core.GenerateStaticKey()
	if err != nil {
		return err
	}

	clientCfg := core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{client.AdmissionKey},
		GatewayID:     client.GatewayID,
		TagSize:       client.TagSize,
	}}
	gatewayCfg := core.Config{Gateway: core.GatewayParams{
		AdmissionKeys: [][]byte{gateway.AdmissionKey},
		GatewayID:     gateway.GatewayID,
		TagSize:       gateway.TagSize,
	}}

	initiator, err := core.NewInitiator(clientCfg, cliStatic, gwPublic)
	if err != nil {
		return fmt.Errorf("client %s could not build an initiator: %w", client.Host, err)
	}
	responder, err := core.NewResponder(gatewayCfg, gwStatic, func([]byte) error { return nil })
	if err != nil {
		return fmt.Errorf("gateway %s could not build a responder: %w", gateway.Host, err)
	}

	msg, err := initiator.WriteInitiation(nil, 0)
	if err != nil {
		return fmt.Errorf("client %s could not seal an initiation: %w", client.Host, err)
	}
	if _, err := responder.ReadInitiation(msg); err != nil {
		return fmt.Errorf(
			"THE GATEWAY WOULD NOT HAVE ANSWERED.\n"+
				"  client  = %s\n"+
				"            gateway_id = %s (%s)\n"+
				"            admission  = %d bytes, %s…\n"+
				"  gateway = %s\n"+
				"            gateway_id = %s (%s)\n"+
				"            admission  = %d bytes, %s…\n"+
				"  core.Responder.ReadInitiation refused the client's real initiation: %w\n"+
				"  In production this is not an error anybody sees. The gateway answers\n"+
				"  nothing, the client retransmits until it gives up, and the user is told\n"+
				"  the network is blocked.",
			client.Host, quoteBytes(client.GatewayID), hexOrEmpty(client.GatewayID),
			len(client.AdmissionKey), prefixHex(client.AdmissionKey),
			gateway.Host, quoteBytes(gateway.GatewayID), hexOrEmpty(gateway.GatewayID),
			len(gateway.AdmissionKey), prefixHex(gateway.AdmissionKey),
			err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// the plan floor matrix
// ---------------------------------------------------------------------------

// FloorRow is one cell of the sizing matrix: a plan, a path MTU, and the two
// numbers every host must agree on.
type FloorRow struct {
	Classes     []string `json:"classes"`
	PathMTU     int      `json:"path_mtu"`
	MessageSize int      `json:"message_size"`
	InnerMTU    int      `json:"inner_mtu"`
	InnerIPv6   bool     `json:"inner_ipv6"`

	// DialledUDPv4InnerMTU is InnerMTUForPath(pathMTU, 28) — the number defect
	// 2 shipped. It is published NEXT TO the floor deliberately: the gap
	// between them is the black hole, and a matrix that showed only the correct
	// number would not let a reader see how large the mistake is.
	DialledUDPv4InnerMTU int `json:"dialled_udp_v4_inner_mtu"`
	Gap                  int `json:"gap_bytes"`
}

// OverheadRow is one carrier class over one address family.
type OverheadRow struct {
	Class    string `json:"class"`
	IPv4     bool   `json:"ipv4"`
	Overhead int    `json:"overhead"`
}

// MatrixPlans are the migration plans the suite sizes.
//
// [tcp tls] is included ON PURPOSE even though cmd/winn-datapath refuses it:
// the arithmetic is still defined for it, the Kotlin and cdatapath hosts still
// compute it, and the fact that one host refuses a plan the others size is
// itself a divergence this suite reports rather than hides. See
// KnownDivergences.
func MatrixPlans() [][]string {
	return [][]string{
		{"udp"},
		{"udp", "tcp"},
		{"udp", "tls"},
		{"udp", "tcp", "tls"},
		{"tcp", "tls"},
	}
}

// MatrixPathMTUs are the path MTUs the suite sizes.
//
//	1280  RFC 8200's IPv6 minimum link MTU; was the fleet default until 2026-08-10.
//	      The fleet default is now 1450 (DefaultPathMTU) and is NOT a matrix
//	      cell — it is pinned by TestEveryHostDefaultsAMissingPathMTUToTheSameNumber
//	      and TestTheFleetDefaultFloorCarriesAFullSizeInnerUnfragmented.
//	1400  a common PPPoE/tunnelled path
//	1500  ordinary Ethernet, and what a host that measured its path reports
//	1360  a value that puts the udp+tcp+tls floor either side of nothing in
//	      particular — included because arithmetic bugs cluster on round
//	      numbers and this one is not
//	 130  narrower than a TLS-over-IPv6 carrier's own 112-byte overhead leaves
//	      room for, so session.MaxMessageSizeForPath's LOWER CLAMP fires on the
//	      tls/v6 cell while the udp/v4 cell is still unclamped. Absurd as a
//	      path, deliberate as a test: the clamp is arithmetic every host copies
//	      and it is the one branch a mirror is most likely to omit, because it
//	      never fires on a real link. A host that clamps differently builds an
//	      unusable tunnel instead of refusing one.
//	9000  a jumbo path, exercising nothing clamped at all
func MatrixPathMTUs() []int { return []int{130, 1280, 1360, 1400, 1500, 9000} }

// Floor computes one matrix row through carrier.Floor, the engine's own
// function.
func Floor(classNames []string, pathMTU int) (FloorRow, error) {
	classes, err := Classes(classNames)
	if err != nil {
		return FloorRow{}, err
	}
	msg := carrier.Floor(pathMTU, classes...)
	inner := carrier.InnerMTU(msg)
	dialled := tun.InnerMTUForPath(pathMTU, tun.UDPOverIPv4Overhead)
	return FloorRow{
		Classes:              append([]string(nil), classNames...),
		PathMTU:              pathMTU,
		MessageSize:          msg,
		InnerMTU:             inner,
		InnerIPv6:            inner >= tun.IPv6MinLinkMTU,
		DialledUDPv4InnerMTU: dialled,
		Gap:                  dialled - inner,
	}, nil
}

// Matrix is every plan crossed with every path MTU.
func Matrix() ([]FloorRow, error) {
	var out []FloorRow
	for _, plan := range MatrixPlans() {
		for _, mtu := range MatrixPathMTUs() {
			row, err := Floor(plan, mtu)
			if err != nil {
				return nil, err
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// Overheads is carrier.Overhead for every class over both address families.
//
// Both families always, never the one in use: a migration can change family as
// easily as it changes class, and a floor computed for the family in use is
// defect 2 one layer along.
func Overheads() []OverheadRow {
	var out []OverheadRow
	for _, name := range []string{"udp", "tcp", "tls"} {
		class, err := ClassNamed(name)
		if err != nil {
			// These names are hardcoded. Skipping a class on error would
			// shrink the vector file, and a host that also omitted that class
			// would then agree — fail-open of the suite itself.
			panic("conform.Overheads: hardcoded class " + name + " must resolve: " + err.Error())
		}
		out = append(out,
			OverheadRow{Class: name, IPv4: true, Overhead: carrier.Overhead(class, carrier.FamilyIPv4)},
			OverheadRow{Class: name, IPv4: false, Overhead: carrier.Overhead(class, carrier.FamilyIPv6)},
		)
	}
	return out
}

// ClassNamed resolves a carrier class name with no default and no fallback.
//
// A silently-charged unknown class is a floor computed for a carrier nobody
// named, which guarantees nothing at all.
func ClassNamed(name string) (carrier.Class, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "udp":
		return carrier.ClassUDP, nil
	case "tcp":
		return carrier.ClassTCP, nil
	case "tls":
		return carrier.ClassTLS, nil
	default:
		return carrier.ClassUnknown, fmt.Errorf("%q is not a carrier class; use udp, tcp or tls", name)
	}
}

// Classes resolves a whole plan.
func Classes(names []string) ([]carrier.Class, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("a migration plan must name the classes the session may escalate to")
	}
	out := make([]carrier.Class, 0, len(names))
	for i, n := range names {
		c, err := ClassNamed(n)
		if err != nil {
			return nil, fmt.Errorf("carrier_classes[%d]: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// the demux token
// ---------------------------------------------------------------------------

// DemuxTokenFromDoc computes the transport demux token FROM ITS PUBLISHED
// DOCUMENTATION rather than from core's private implementation:
//
//	token(counter) = HMAC-SHA256(key, "winn3 demux v1" || be64(counter))[:8]
//
// winn3/core/index.go:47 states exactly this to any host building a session
// index, and cmd/winn3-gateway demultiplexes on the peer address today only
// because it has not needed the token yet. A second implementation is normally
// the bug; here it is the POINT — this is the only construction in the suite
// that a non-Go host would have to write itself, so the documented form has to
// be checked against real Seal output rather than trusted.
//
// TestTheDocumentedDemuxTokenIsTheOneOnTheWire drives this against a real
// session's real sealed bytes.
func DemuxTokenFromDoc(key []byte, counter uint64) []byte {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("winn3 demux v1"))
	mac.Write(ctr[:])
	return mac.Sum(nil)[:core.DemuxTokenSize]
}

// ---------------------------------------------------------------------------
// tier B: the divergences that exist today
// ---------------------------------------------------------------------------

// Pin is a defect that HAS BEEN FIXED and must never come back.
//
// ===========================================================================
// WHY THIS IS A SEPARATE TABLE FROM KnownDivergences
// ===========================================================================
//
// The two categories look similar and behave oppositely, and conflating them is
// how a suite quietly stops working:
//
//   - A [Divergence] is TRACKED AND UNFIXED. The suite asserts it is still
//     exactly as described. It does not fail the build; it is measured debt.
//   - A Pin is FIXED. The suite asserts it has NOT come back, and a regression
//     FAILS THE BUILD.
//
// Filing a fixed defect as a divergence would allow it to return. Filing an
// unfixed divergence as a pin would leave the build permanently red, which
// ends with somebody switching the check off — the worse of the two failures,
// because a suite nobody runs is indistinguishable from no suite.
//
// Every pin names the test that holds it. That field is checked, not
// decorative: TestEveryPinNamesATestThatExists greps the tree for it, so a pin
// whose test was renamed or deleted fails instead of silently guarding
// nothing.
type Pin struct {
	// ID is stable and greppable.
	ID string `json:"id"`

	// Defect is what went wrong, in the tree's own terms.
	Defect string `json:"defect"`

	// Symptom is what the failure looked like FROM OUTSIDE. This is the field
	// that makes a pin worth reading: every one of these defects presented as
	// "the VPN does not connect", and the symptom line is what lets somebody
	// holding a bug report recognise which one they have.
	Symptom string `json:"symptom"`

	// FixedOn is the date the fix landed.
	FixedOn string `json:"fixed_on"`

	// HeldBy names the tests that fail if it returns. Checked to exist.
	HeldBy []string `json:"held_by"`
}

// RegressionPins is the complete set of silent-refusal defects that have been
// FIXED and are held closed by this suite.
//
// Most of them share one shape — a client and a gateway disagreeing about an
// encoding or a size, producing no session and no error on either side — and
// every one of them is invisible from either end alone, because a v3 gateway
// never answers a datagram it could not authenticate.
//
// The family is ALSO numbered in prose, and the two systems do not line up.
// The numbered series is: #1 gateway_id encoding, #2 Android inner MTU,
// #3 unnegotiated path_mtu, #4 the opaque admission secret, #5 operator-value
// whitespace, #6 cross-host `[winn]` key names, #7 the gate-state vocabulary,
// #8 a gateway that bound and answered nobody, #9 the lab rig doing the same
// after it had already created a kernel interface.
//
// As of 2026-08-09 both of the numbered rows that were open have moved:
//
//   - #5 is CLOSED and is a pin here. Its divergence row is gone, on the row's
//     own instruction. What is NOT closed, and is stated in the pin rather than
//     left to be inferred, is the deployed hub — the repo refuses a
//     whitespace-bearing value at upload and the deployed control plane runs
//     older code than the repo ships, which nothing here has measured.
//   - #3 is HALF closed and is in BOTH tables, which is not a contradiction and
//     is worth reading carefully. The pin holds the half that was dangerous:
//     the mismatch is no longer silent. The divergence row holds the half that
//     is still open: the two ends are still not reconciled, so a gateway and a
//     client on different path MTUs still cannot talk. The two entries have
//     different ids for that reason.
//
// Four pins here carry no instance number at all, and the array order is not
// the instance order — so counting this slice does not answer "how many are
// closed", and neither does counting the series. Read both tables.
func RegressionPins() []Pin {
	return []Pin{
		{
			ID: "gateway-id-is-raw-operator-bytes",
			Defect: "cdatapath base64-decoded gateway_id while the four other call sites in the " +
				"tree — cmd/winn-datapath's keys and profile documents, cmd/winn3-labrig, and " +
				"cmd/winn3-gateway, the gateway that answers — took the operator string's raw " +
				"bytes. gateway_id is an authenticated input to the admission tag and is never " +
				"transmitted, so nothing on the wire can catch the disagreement.",
			Symptom: "gateway `wins-sea-01` against client `d2lucy1zZWEtMDE=` gave " +
				"session_states:[\"initiating\"], messages_received:5, messages_sent:0, " +
				"refused_datagrams:0 — a gateway receiving every packet, authenticating none, " +
				"and reporting no refusal because an unauthenticated datagram is not refused, " +
				"it is ignored — and a client that exhausted its handshake attempts. The " +
				"trigger was ordinary: `winsgw01` is eight characters of the base64 alphabet.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestGatewayIDIsStillTakenVerbatimAcrossTheConformanceFixture",
				"TestNeitherEntryPointDecodesTheGatewayID",
				"TestGatewayIDIsNotDecoded",
				"TestAdmissionRoundTripCatchesTheGatewayIDDefect",
			},
		},
		{
			ID: "inner-mtu-is-the-plan-floor-not-the-dialled-carrier",
			Defect: "WinnV3EngineConfig emitted 1443 — InnerMTUForPath(1500, 28), the dialled " +
				"UDP-over-IPv4 number — where the plan floor across udp+tcp+tls is 1359. The " +
				"floor must be the minimum across every class the session may migrate to, " +
				"across BOTH address families; the widest single carrier is not it.",
			Symptom: "84 bytes too wide. Small packets cross perfectly and every full-size flow " +
				"black-holes the moment the session migrates off UDP, while the tunnel reads " +
				"\"up\" at both ends. It arrives as \"large downloads stall\" from a handset " +
				"nobody can attach a debugger to — and since the answer to a censor who blocks " +
				"UDP is precisely to fail over, it is a likely failure and not an exotic one.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestTheReferencePlanFloorIsTheNumberDefectTwoGotWrong",
				"TestTheCreateSeamRefusesTheDialledCarrierMTUAcrossTheWholeMatrix",
				"TestCABIConformsToTheCrossHostSuite",
			},
		},
		{
			ID: "admission-secret-is-opaque-bytes",
			Defect: "The admission secret is OPAQUE BYTES. keygen writes it as hex TEXT and " +
				"every consumer keys with the file's 64 ASCII characters after trimming a " +
				"trailing CR/LF and nothing else. Hex-decoding it, or shipping base64 of the " +
				"32 DECODED bytes across the Apple create document's admission_key, keys one " +
				"end with 32 bytes against the other's 64.",
			Symptom: "Worse than a flat refusal, and this is the part that makes it hard: the " +
				"datagram passes the gateway's size pre-filter and a session is BUILT, and " +
				"then the gateway goes completely silent. A host watching for \"did the " +
				"gateway see me\" sees yes. Nothing distinguishes it from the censor.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestGatewayDoesNotDecodeTheAdmissionSecret",
				"TestNeitherEntryPointDecodesTheAdmissionSecret",
				"TestTheAdmissionKeyIsTheFilesBytesNotTheDecodedSecret",
				"TestAdmissionRoundTripCatchesTheHexDecodedSecret",
			},
		},
		{
			ID: "the-gateway-plans-with-the-path-mtu-it-was-given",
			Defect: "cmd/winn3-gateway must plan at the -path-mtu the operator typed. Nothing " +
				"in v3 negotiates that number (see the path-mtu-not-negotiated divergence), " +
				"so a gateway that ignored its own flag would be undetectable from any client.",
			Symptom: "A gateway silently planning at 1280 against a client at 1500 gives floors " +
				"of 1232 and 1452. Sessions establish and then stall on the first full-size " +
				"flow. This pin is what makes the UNFIXED divergence merely dangerous rather " +
				"than unbounded: the two numbers must at least be the two the operator chose.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestGatewayPathMTUIsWhateverTheOperatorTyped",
				"TestTheFleetDefaultPathMTUIsTheConstantTheGatewayFlagsUse",
				"TestGatewayConformsToTheCrossHostSuite",
			},
		},
		{
			ID: "served-config-key-names-differ-per-host",
			Defect: "Three of the four hosts could not READ the section the control plane " +
				"serves. Apple read `[winn]` inner_v4 / inner_router_v4 / static_private / " +
				"gateway_static / gateway_id / admission_key, every byte-valued field base64. " +
				"Android read `[winn]` v3_gateway_id / v3_static_key / v3_gateway_static_key / " +
				"v3_admission_secret, keys as lowercase HEX and the gateway id as PLAIN TEXT, " +
				"selected v3 on `protocol = 3` rather than `carrier = winn3`, and had NO " +
				"inner_v4 at all — VpnTunnelService.startWinnV3EngineThread passed " +
				"innerAddress = clientIp, the AmneziaWG address. Windows parsed a `[winn3]` " +
				"SECTION carrying router_v4 and three FILE PATHS, and nothing anywhere emits " +
				"`[winn3]`. Linux had no v3 `[winn]` reader in the tree at all.",
			Symptom: "The hub could serve exactly one of four spellings, so three platforms " +
				"refused every real server config while their engines worked perfectly. That " +
				"much was LOUD, and it was luck rather than design. The dangerous neighbour is " +
				"Android's: had its spelling been PARTIALLY satisfied it would have taken the " +
				"relay's AmneziaWG address as its inner address, and the winn/3 tun layer drops " +
				"every packet whose source does not match its assignment — a session that " +
				"starts, reports up at both ends, and carries nothing, with no error anywhere.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestTheServedFixtureIsTheOneEveryHostParses",
				"TestTheServedSectionConformsToTheCrossHostSuite",
				"TestTheServedSectionCarriesEveryFieldAStandaloneStartNeeds",
			},
		},
		{
			ID: "the-control-plane-serves-no-key-bearing-field",
			Defect: "The control plane emitted a `[winn]` section carrying enabled, endpoint, " +
				"carrier and session_id and NOT ONE of the six key-bearing fields a standalone " +
				"start needs — inner_v4, inner_router_v4, static_private, gateway_static, " +
				"gateway_id, admission_key. The signed descriptor had been served since " +
				"2026-08-08 and no client code read it, `winn3` was refused at both " +
				"supported-carrier lists, and inner_router_v4 was not in the descriptor's " +
				"closed field set at all. Four platforms carried v3 in a lab and none could " +
				"be driven by a real server config.",
			Symptom: "Not a failed session — NO session, on every platform at once, with the " +
				"engines all working. A lane measuring v3 on a handset sees it carry packets " +
				"from a hand-written document and then sees the shipping app refuse every " +
				"served config by name, which reads as an app bug rather than as a hub that " +
				"never sent the fields. It is the failure that cost the most calendar time " +
				"precisely because nothing anywhere was broken.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestTheServedSectionCarriesEveryFieldAStandaloneStartNeeds",
				"TestTheServedGatewayIDIsBase64OverTheOperatorText",
				"TestTheServedAdmissionKeyIsTheFileBytesNotTheDecodedSecret",
				"TestTheServedSectionConformsToTheCrossHostSuite",
			},
		},
		{
			ID: "android-defaulted-the-path-mtu-to-1500",
			Defect: "AS OF 2026-08-09, AND STATED IN THAT DAY'S TERMS: the fleet default " +
				"was 1280 then and is 1450 now (see DefaultPathMTU), and the two constants " +
				"below are deliberately no longer equal — the numbers here are the record of " +
				"the defect, not a description of the current tree. " +
				"WinnV3SessionPlan.DEFAULT_PATH_MTU was 1500 where every other host " +
				"resolved a missing path_mtu to 1280 — carrier.DefaultPathMTU on " +
				"cmd/winn3-gateway and cmd/winn-datapath's profile, tun.IPv6MinLinkMTU on the " +
				"create document and cdatapath, and Apple's winn3PathMTU returning zero so the " +
				"engine applies its own conservative default. The served `[winn]` section " +
				"carries path_mtu only when an operator set one, so the default is the case " +
				"that actually happens.",
			Symptom: "The WIDE mismatch regime, measured on 2026-08-09 against a live " +
				"cmd/winn3-gateway: floors of 1139 and 1359 inner MTU. The session never " +
				"carries at all — the gateway sent one message, refused five, and closed, " +
				"while the client's gate never left down. Worse than the black hole, and on " +
				"the one platform with the largest install base. Nothing is logged to the user " +
				"and nothing is signalled to the client, so it reads as 'Android does not " +
				"connect' — the most expensive possible framing, because it invites an " +
				"Android-specific investigation of something that is not Android-specific.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestEveryHostDefaultsAMissingPathMTUToTheSameNumber",
				// RENAMED 2026-08-10 from TestTheTwoDefaultsAreTheSameNumber.
				// That test asserted carrier.DefaultPathMTU == tun.IPv6MinLinkMTU;
				// the fleet default moved to 1450 and the two are deliberately no
				// longer equal, so the guard was rewritten to the invariant that
				// actually protects this pin — all four entry points resolving a
				// missing path_mtu through ONE constant.
				"TestEveryEntryPointDefaultsThroughTheOneConstant",
				"TestTheFleetDefaultPathMTUIsTheConstantTheGatewayFlagsUse",
			},
		},
		{
			ID: "a-promotion-that-captured-nothing-reported-success",
			Defect: "windows/runner/winn3_posture.h had one half of the gate. " +
				"VerifyBootstrapIsNarrow asked whether the NARROW posture stayed narrow, " +
				"and nothing asked the opposite question of the wide one: whether the " +
				"posture about to be installed would move any of the user's traffic at all. " +
				"BuildPromotedPosture could return true — and the two desktop hosts would " +
				"report a promotion — for a plan with no default route and nothing but host " +
				"routes in it. It also promoted on an EMPTY RESOLVER SET, which is the " +
				"reachable half: a served `[winn]` section carries no `dns` key, so a " +
				"desktop session started from one would widen its routes onto the tunnel " +
				"and leave name resolution pointed at whatever the network handed out. " +
				"linux/runner/winn3_posture_test.cc asserted that was fine, verbatim: \"a " +
				"promotion with no resolvers at all is fine\".",
			Symptom: "Nothing breaks, which is what makes it the expensive one. The tunnel " +
				"reads up, the gate reads carrying, pages load through the tunnel — and " +
				"every DNS query still leaves by the physical interface in the clear, to " +
				"the resolver the censor operates and applies blocking at. A user checking " +
				"whether the VPN is working sees that it is. There is no counter, no log " +
				"line and no refusal anywhere in the system that disagrees.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestNoDesktopHostPromotesToAPostureThatCapturesNothing",
				"TestNoDesktopHostPromotesWithoutMovingNameResolution",
			},
		},
		{
			ID: "promotion-discarded-the-bootstraps-only-route",
			Defect: "BuildPromotedPosture built the promoted plan from the bootstrap plan — " +
				"deliberately, so the wide posture is the narrow one PLUS the widenings — " +
				"and then ASSIGNED over its route set: `plan->included_routes = " +
				"input.full_routes`. The bootstrap's one route is the inner next hop, and " +
				"a served section supplies no route set, so the assignment turned a plan " +
				"describing {inner_router_v4/32} into a plan describing {}. Separately, a " +
				"`[winn3] routes = 0.0.0.0/1, 128.0.0.0/1` — the natural way to hand-write " +
				"a full tunnel — made both renderers emit the same `route add` twice, " +
				"because `default_route` already renders that pair.",
			Symptom: "Two shapes, both quiet. The plan stopped describing the posture the " +
				"machine actually had, so every check in the header — including the two " +
				"new ones — reasoned about an object that did not match the kernel. And a " +
				"route set spelled the obvious way made promotion fail on `RTNETLINK " +
				"answers: File exists`, which RunAll surfaces as a posture command failure " +
				"on a session whose datapath had just been proven.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestAStandalonePromotedRouteSetIsDerivedAndKeepsTheNextHop",
			},
		},
		{
			ID: "gate-state-vocabulary-crossed-the-host-boundary-by-convention",
			Defect: "`winn3/tun.State.String()` emits six names and cmd/winn-datapath " +
				"publishes the current one as `gate_state`. FIVE host call sites decided " +
				"whether to promote by comparing against their own hand-copied literal — " +
				"WinnV3StagedStart.kt (twice: app and devicecheck), winn3_posture.h's " +
				"kCarryingGate (which Linux also consumes), and " +
				"WinsWinn3HostContract.swift's carryingState — and NOTHING pinned any of " +
				"them to the Go switch. Android's comment conceded the coupling in words: " +
				"\"The names are the Go String() values\". The Go tests asserted only " +
				"`String() != \"\"` and `State(200) == \"invalid\"`, which are true of any " +
				"vocabulary whatsoever, and each host test fed its own literal into its own " +
				"parser — so every party agreed with itself and none agreed with Go.",
			Symptom: "The worst shape in this table. Rename `carrying` and all five hosts " +
				"parse an unknown name, every mayCarry() answers false, and the promotion " +
				"never fires — while the tunnel handshakes, completes the PQ ratchet, rekeys " +
				"on schedule and moves bytes. The user's traffic simply never enters it. No " +
				"test in any language goes red, nothing is logged, and because a v3 gateway " +
				"never answers an unauthenticated datagram there is no second opinion in the " +
				"system: it is indistinguishable from the censor, which is the entire threat " +
				"model.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestTheGateStateVocabularyIsTheSameOnEveryHost",
				"TestTheStateVocabularyIsExactlyThis",
				"TestEveryNamedStateIsDeclaredAndEveryDeclaredStateIsNamed",
				"TestEveryEmittedNameParsesBackToItsOwnState",
				"TestAnUnknownGateStateNameFailsClosed",
			},
		},
		{
			ID: "configuration-was-validated-later-than-the-operator-was-standing-there",
			Defect: "Silent-refusal instances #8 and #9, which are one defect at three sites. " +
				"The RULES were never wrong: winn3/tun refuses -router-v4 equal to -inner-v4 " +
				"(tun.go:169), an IPv6 literal in -inner-v4, and a martian assignment, loudly " +
				"and correctly. They fired in the wrong PLACE. Session construction is lazy, so " +
				"tun.New did not run until the first datagram arrived — and every datagram path " +
				"in this protocol discards its error with a bare `continue`, deliberately, " +
				"because a v3 gateway must never answer an unauthenticated peer. So a " +
				"permanent, operator-caused configuration error was re-made and re-discarded " +
				"once per datagram, forever. cmd/winn3-gateway bound its socket and printed " +
				"`listening` first (#8); cmd/winn3-labrig was worse, having already CREATED AND " +
				"ADDRESSED a kernel interface and parked in MSG_PEEK (#9); and " +
				"cmd/winn-datapath's -winn3-print-sizing answered `can I start this?` with a " +
				"plan floor it computed without ever constructing a session, so the host set " +
				"its interface MTU to a number for a profile the real start would refuse.",
			Symptom: "Measured 2026-08-09 with the real binaries over real UDP: the gateway " +
				"printed `listening` and NOTHING ELSE, ran to its timeout, and exited 0. " +
				"datagrams:5 — every initiation arrived — against admitted:0, sessions_built:0, " +
				"stranger_datagrams:0 and refused_datagrams:0. Every counter that could have " +
				"named a problem read zero. The client said only `handshake attempts exhausted " +
				"on this carrier`. A gateway that binds, reports healthy and answers nobody is " +
				"the exact posture a censor produces, and no counter on either end " +
				"distinguished the two.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestAGatewayThatCannotCarryTrafficRefusesToStart",
				"TestAValidConfigurationIsNotRefused",
				"TestParseAssignmentRejectsARouterEqualToTheAddress",
				"TestRunGatewayRefusesAnUnusableConfigurationBeforeItOpensADeviceOrBindsASocket",
				"TestEveryLegitimateConfigurationStillPassesEveryStartupGate",
				"TestPrintSizingRefusesAProfileTheRealStartWouldRefuse",
				"TestPrintSizingStillApprovesEveryProfileThatCanCarryTraffic",
			},
		},
		{
			ID: "a-preflight-that-restates-rules-instead-of-running-them",
			Defect: "The remedy for the row above is a startup preflight, and a preflight is " +
				"only worth its line count if it CALLS THE REAL CONSTRUCTORS. A hand-written " +
				"copy of winn3/tun's address rules would agree with itself while tun.New " +
				"rejected something else — the same defect one layer along, and harder to see " +
				"because the check looks like coverage. All three preflights therefore run " +
				"driver.NewGateway -> tun.New in the order and with the values the datagram " +
				"path uses, against a carrier.Pipe whose Out is never called and an in-process " +
				"reflector, so they open nothing, bind nothing and send nothing.",
			Symptom: "There is no user-visible symptom yet, which is exactly why this needs a " +
				"pin rather than a comment: the day somebody replaces the dry run with a list " +
				"of if-statements, every rule added downstream after that day stops being " +
				"enforced at startup and the row above comes back one rule at a time. The " +
				"failure would reappear as the family's own shape — a gateway that starts, " +
				"reports listening and answers nobody.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestThePreflightDelegatesToTheRealConstructorsInsteadOfRestatingTheirRules",
				"TestThePreflightBuildsARealSessionAndClosesIt",
				"TestThePreflightOpensNoSocketAndAdoptsNoDescriptor",
				"TestThePreflightDeviceCarriesNoPackets",
			},
		},
		{
			// Silent-refusal instance #5, the operator-value whitespace row.
			// The divergence table carried it until 2026-08-09 and its own Fix
			// line said to delete the row when the gateway refused or
			// normalised at the flag. It refuses.
			ID: "operator-value-whitespace-refused-at-the-flag",
			Defect: "cmd/winn3-gateway keyed the admission tag with []byte(opts.gatewayID) " +
				"UNTRIMMED — strings.TrimSpace appeared in buildSessionConfig for the " +
				"emptiness CHECK only — while every host that receives gateway_id as " +
				"transport text trims it. So `-gateway-id \"winsgw01 \"` here against " +
				"`winsgw01` in the hub is two ends keyed one byte apart, and nothing " +
				"anywhere compared them. Two thirds of the row were already closed and the " +
				"record did not say so: the HOST half closed by construction when Android, " +
				"Windows and Linux moved onto the served base64 spelling, so all four hosts " +
				"now trim transport text and none can reach a decoded byte. What survived " +
				"was the gateway's own flag.\n" +
				"CLOSED BY REFUSAL, NOT BY TRIMMING, and the distinction is the substance " +
				"of the fix. Trimming here would make the gateway silently disagree with a " +
				"descriptor that legitimately encodes a space, and would invent a " +
				"normalisation rule four hosts would then have to match. runServe calls " +
				"validateOperatorValues before anything is read, sized or bound — the same " +
				"placement argument the row above makes for #8 — and the value keyed with " +
				"is unchanged, which TestTheGatewayKeysWithTheOperatorValueUntrimmed and " +
				"TestTheWhitespaceCheckDoesNotChangeWhatTheGatewayKeysWith both still hold.\n" +
				"NOT CLOSED, and stated here because the pin would otherwise be read as " +
				"covering it: the hub refuses a whitespace-bearing value at upload IN THE " +
				"REPO, and the deployed control plane runs older code than the repo ships. " +
				"Nothing in this suite has measured the deployed hub. The gateway half is " +
				"what this pin holds.",
			Symptom: "The whole node blocked, at once, for every client. A gateway keyed one " +
				"byte away from its fleet authenticates nobody, and a v3 gateway does not " +
				"answer a datagram it could not authenticate — no response, no ICMP, no log " +
				"line — so it presents exactly as a censor sitting in front of that machine. " +
				"The one mercy is that it is fleet-wide rather than per-host, so the bug " +
				"report says 'the node is down' rather than 'Android is broken'. Since the " +
				"fix the same configuration fails at start-up instead, naming the flag and " +
				"printing the offending value's whitespace as code points, because the whole " +
				"defect is that a trailing space is invisible in a terminal.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestTheGatewayRefusesAGatewayIDCarryingEdgeWhitespace",
				"TestTheWhitespaceRefusalReportsWhatItActuallyMeasured",
				"TestTheOperatorValueIsRefusedBeforeTheSocketIsBound",
				"TestEveryLegitimateGatewayIDStillStartsServesAndStops",
				"TestTheWhitespaceCheckDoesNotChangeWhatTheGatewayKeysWith",
				"TestTheGatewayKeysWithTheOperatorValueUntrimmed",
			},
		},
		{
			// Silent-refusal instance #3, the REFUSAL half of the tree's own
			// remedy. The divergence row of the same name is NOT deleted: the
			// two ends still have to be configured identically, because taking
			// the minimum IS now explicit but NOT automatic — NegotiatedPathMTU
			// carries the arithmetic and refusePathMTUMismatch is a guarded
			// return on that number, and both are pinned below — yet no host in
			// v3 re-applies an interface MTU at the negotiated value, which is
			// the step the divergence row's Fix still demands. What this pin
			// holds is that the mismatch is no longer SILENT: it is refused on
			// the number both ends could agree on, which is the half that was
			// dangerous.
			ID: "a-path-mtu-mismatch-established-and-then-black-holed-in-silence",
			Defect: "Nothing in v3 carried the path MTU across the handshake. Each end " +
				"computed its own plan floor from its own number and neither ever learned " +
				"the other's, so cmd/winn3-gateway's -path-mtu and the client's own " +
				"path_mtu could differ with nothing to compare them. Every other member of " +
				"this family fails CLOSED; this one failed OPEN.\n" +
				"CLOSED BY REFUSAL. core.WriteResponse and core.ReadResponse already " +
				"carried an authenticated payload inside the AEAD and every caller passed " +
				"nil, so the frame did not have to change: the responder now states its " +
				"planning path MTU there (winn3/session/pathmtu.go), the initiator compares " +
				"it with its own, and a mismatch ends the session loudly instead of " +
				"establishing one that cannot carry. The payload header's `flags` byte stays " +
				"zero — decodeHandshakePayload returns ErrDecrypt otherwise — so the version " +
				"lives in the payload bytes.\n" +
				"RESOLVED 2026-08-10: the take-the-minimum half is now explicit as a guarded " +
				"return rather than a comment. winn3/session/pathmtu.go's NegotiatedPathMTU " +
				"is the min-of-both-ends number (implemented, unit-tested, and pinned by " +
				"TestNegotiatedPathMTUAgreesOnTheMinimum) and Driver.refusePathMTUMismatch " +
				"guards on it, refusing a session whenever the negotiated minimum differs " +
				"from EITHER end's planning number. What is still NOT implemented is " +
				"applying that minimum — re-applying a platform interface MTU on a live " +
				"tunnel across four hosts — which is why the path-mtu-not-negotiated " +
				"divergence row remains open and the two ends must still be configured " +
				"identically. The refusal itself closes the dangerous failure: a session " +
				"built on the difference would establish, carry small packets, and " +
				"black-hole every full-size one while both ends reported the gate carrying.",
			Symptom: "A tunnel the user believed was protecting them. Measured 2026-08-09 " +
				"against a live cmd/winn3-gateway and the shipping cmd/winn-datapath client " +
				"over a real UDP socket, in two OS processes: with the gateway at 1400 and " +
				"the client at 1500 the session established normally and a 51-byte probe " +
				"round-tripped with refused_datagrams:0, then a 1350-byte probe VANISHED — " +
				"the gateway counted refused_datagrams:2, rx_packets stayed 0, and BOTH ENDS " +
				"went on reporting gate_state=carrying. Nothing was logged and nothing was " +
				"signalled to the client. The wide regime (gateway 1280, client 1500) was " +
				"noisier but not clearer: 1 message sent, 5 refused, the session \"closed\" " +
				"and the client's gate never left down. In the field both read as 'the VPN " +
				"does not work in Myanmar'.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestAnOldPeerThatSendsNoHandshakePayloadStillConnects",
				"TestAPathMTUMismatchRefusesTheSessionLoudly",
				"TestTwoLoopsAtDifferentPathMTUsRefuseInsteadOfBlackHoling",
				"TestTwoLoopsAgreeingOnThePathMTUStillCarryBytes",
				"TestEveryAgreeingPathMTUStillEstablishes",
				"TestAForeignHandshakePayloadIsNotReadAsAPathMTUClaim",
				"TestALoopStatesThePathMTUItsSizingWasBuiltAt",
				"TestALoopRefusesAPathMTUSetByHand",
				"TestNegotiatedPathMTUAgreesOnTheMinimum",
				"TestNegotiatedPathMTURequiresBothClaims",
				"TestRefusePathMTUMismatchIsAGuardedReturnOnTheMinimum",
			},
		},
		{
			// Silent-refusal instance #3, the RECORD half. The row above holds
			// the REFUSAL (a mismatch must refuse loudly); nothing before this
			// row held the notice's own pixels.
			//
			// This is the classic mutation-tester survivor: the record is
			// written and read by the same package, so a sibling that flips the
			// byte order from BigEndian to LittleEndian in BOTH the encoder and
			// the decoder stays green forever, because the two halves move
			// together and no test sees the self-consistent change. The conform
			// suite is the one place that can pin the responder's EXACT bytes
			// without depending on the encoder to be its own referee.
			ID: "path-mtu-notice-wire-record-is-seven-exact-bytes",
			Defect: "The responder's planning path MTU travels inside the handshake " +
				"response payload as a seven-byte record: magic \"W3PM\" (4 bytes), version " +
				"01 (1 byte), then the 16-bit path MTU big-endian. A magic rather than a " +
				"bare integer because the payload is a shared channel, and a later hint " +
				"that is not a path-MTU notice must not be read as one.\n" +
				"NOT YET PINNED at this suite's level before this row: the on-wire record " +
				"was only ever checked by the encoder against the decoder in the same " +
				"package, so a self-consistent byte-order change (both halves together) " +
				"never went red anywhere. This row pins the exact seven bytes so a wire " +
				"change is a decision, not a silent drift.",
			Symptom: "A gateway and a client built from the same package still talk to each " +
				"other, so nothing ON THIS HOST goes red — but a wire byte-order change is " +
				"a change to the protocol that every other implementation and every captured " +
				"trace is now wrong against, and nothing noticed. The v3 gateway fleet " +
				"exists only as these binaries, so the first opposing implementation would " +
				"meet the new bytes cold.",
			FixedOn: "2026-08-10",
			HeldBy: []string{
				"TestThePathMTUNoticeWireRecordIsSevenExactBytes",
				"TestTheShippingGatewayEmitsThePathMTUNoticeOverARealSocket",
				"TestAGatewayAtEveryBoundaryTheNoticeCanStateIsConstructibleAndStatesIt",
			},
		},
		{
			// Silent-refusal family, the promotion PREDICATE half. The existing
			// `a-promotion-that-captured-nothing-reported-success` row holds the
			// POSTURE CAPTURE side (the host's route/resolver widening). Nothing
			// held the COUNTER side: the predicate must be fed RxPackets
			// (deliveries) and never RxOffered (arrivals), and it is computed in
			// exactly one place so two hosts in two languages cannot drift.
			ID: "promotion-readies-only-on-rxpackets-never-rxoffered",
			Defect: "The promotion predicate is Gate.State() == StateCarrying && " +
				"RxPackets > 0 — PROVEN first appears not when the socket connected nor " +
				"when a datagram ARRIVED, but when an inner packet was validated and " +
				"DELIVERED to the host device. RxOffered counts an arrival with nothing " +
				"validated; reading it promotes a tunnel that has proven nothing.\n" +
				"Computed once, in cmd/winn-datapath/winn3_status.go, beside the counters, " +
				"precisely so two desktop hosts never each re-derive it and drift. This " +
				"row pins that single source (predicate body AND call site) and names the " +
				"behavioural tests that drive the two counters apart.",
			Symptom: "The tunnel widens to the full posture on an ARRIVAL rather than a " +
				"DELIVERY — a default route installed on a tunnel that has carried nothing to " +
				"the host device. Fail-closed across every host at once at best (a config " +
				"that never promotes) or, at worst, user traffic pushed onto a path that has " +
				"yet to prove it can carry. The correct-predicate-fed-the-wrong-counter and " +
				"the wrong-predicate-body are the same false green and this row holds both.",
			FixedOn: "2026-08-10",
			HeldBy: []string{
				"TestThePromotionGateCountsRxPacketsNeverRxOffered",
				"TestTheStatusDocumentObservesTransportInBothDirections",
				"TestPromotionIsGatedOnDeliveriesAndNotOnArrivals",
				"TestTheStatusDocumentPromotesOnlyAfterAnInnerPacketArrives",
			},
		},
		{
			// Silent-refusal family, the runtime REFUSAL half. The
			// `configuration-was-validated-later-than-the-operator-was-standing-there`
			// row holds the STARTUP preflight (refusing to START); nothing held
			// that a running gateway never ANSWERS an unauthenticated datagram.
			// Preserving that silence is the protocol's whole resistance-to-
			// probing property, and in the Myanmar threat model it is also what
			// makes an encoding disagreement look exactly like a censor.
			ID: "an-unauthenticated-datagram-gets-no-byte-back",
			Defect: "A v3 gateway never replies to a datagram it could not authenticate — " +
				"an empty datagram, noise, a probe, a replayed or corrupted initiation, a " +
				"wrong key, a stale clock, a throttled or capacity-refused client all get " +
				"the identical nothing. Only a fresh initiation that authenticates under " +
				"the gateway's admission key ever emits a byte.\n" +
				"NOT YET PINNED at this suite's level before this row: the behavioural " +
				"teeth exist in winn3/gateway/silence_test.go and " +
				"winn3/session/credentialfault_test.go, but nothing in the conform suite " +
				"held them, and no conform guard held the gateway's refusal path. A sibling " +
				"that started answering the unauthenticated path would leave every other " +
				"conform pin green.",
			Symptom: "The protocol's one protection against being found collapses: a censor " +
				"can distinguish 'no one there' from 'gateway refusing me' by sending one " +
				"packet, and replayed/corrupted initiations become permanent detectors. It " +
				"also breaks the product's core diagnostic: a total-silence presentation is " +
				"how the whole silent-refusal family hides, and a gateway that emits " +
				"anything on the unauthenticated path stops that silence from meaning " +
				"anything.",
			FixedOn: "2026-08-09",
			HeldBy: []string{
				"TestAnUnauthenticatedDatagramGetsNoByteBack",
				"TestTheGatewayStmtsThePathMTUNoticeItPlannedAt",
				"TestTheRefusalPathIsCountedAndStaysSilent",
				"TestEveryRejectionPathAnswersNothing",
				"TestOnlyAFreshAuthenticatedInitiationEmitsAByte",
				"TestEveryCredentialFaultIsSilentToTheClient",
			},
		},
	}
}

// Divergence is one place two hosts genuinely differ today.
//
// Every field is required. A row with no Consequence is a row nobody has
// thought about, and a row with no Fix is a row that will still be here next
// year.
type Divergence struct {
	// ID is stable and greppable.
	ID string `json:"id"`

	// A and B name the two code paths, precisely enough to open the files.
	A string `json:"a"`
	B string `json:"b"`

	// Behaviour states what each side does, in that order.
	Behaviour string `json:"behaviour"`

	// Consequence states what a user sees. If the honest answer is "nothing",
	// the row does not belong here.
	Consequence string `json:"consequence"`

	// Fix states what would remove the row.
	Fix string `json:"fix"`
}

// KnownDivergences is TIER B: the complete list of divergences that exist in
// the tree today and are not yet fixed.
//
// This table is a DECLARED inventory, not an observed one. The suite does not
// compute a live divergence set and compare it here — [DivergenceIDs] exists
// for a comparison nothing performs. What notices that a row closed is the
// row's own named test, written to FAIL on the day the divergence closes.
// TestEveryKnownDivergenceIsFullyStated asserts every field is non-empty and
// that the unresolved row count is exact, so adding or deleting a row is a decision
// somebody had to write down. It cannot notice that a listed divergence was
// fixed in the tree while the row remained.
//
// A row here is not permission. It is a measured, named debt with a stated
// consequence, which is strictly more than the comment it replaces.
func KnownDivergences() []Divergence {
	rows := []Divergence{
		{
			ID: "plan-must-contain-udp",
			A:  "cmd/winn-datapath/winn3_create.go:winn3CreateClasses",
			B: "android/…/WinnV3Posture.kt:WinnV3Sizing.planFloorMessageSize and " +
				"cdatapath/winn_datapath_winn3.go:carrierClasses",
			Behaviour: "cmd/winn-datapath REFUSES a plan that does not name udp, because udp is " +
				"the only class that build can dial: a tls carrier needs a *tls.Config with the " +
				"root CA, the ECH list and the client certificate behind it, none of which " +
				"reaches that process. The Kotlin host and cdatapath both accept [tcp,tls] and " +
				"size it happily.",
			Consequence: "A host that offers the operator a tcp/tls-only plan builds a config its " +
				"own Kotlin validation accepts, hands it to the engine, and the engine refuses " +
				"the create. On Android that is a start failure on a handset instead of a failed " +
				"unit test; on Apple, cdatapath accepts the plan and then cannot dial it.",
			Fix: "Give WinnV3Sizing.planFloorMessageSize and cdatapath's carrierClasses the same " +
				"refusal cmd/winn-datapath has, or give cmd/winn-datapath the ability to dial " +
				"what it plans. Delete this row when the three agree.",
		},
		{
			ID: "empty-plan-handling",
			A:  "cmd/winn-datapath/winn3_create.go:winn3CreateClasses and winn3/driver.NewSizing",
			B:  "cdatapath/winn_datapath_winn3.go:carrierClasses",
			Behaviour: "cmd/winn-datapath and driver.NewSizing REFUSE an empty plan. cdatapath " +
				"silently substitutes {\"udp\"}.",
			Consequence: "An Apple create document that omits carrier_classes gets a udp-only floor " +
				"— 1443 inner MTU at a 1500 path — with no refusal. The moment that session " +
				"migrates, or the moment the operator adds tcp to the gateway's plan, every " +
				"full-size flow black-holes while the tunnel reads up. It is defect 2 reachable " +
				"by omission rather than by miscalculation.",
			Fix: "Make cdatapath refuse an empty carrier_classes the way winn3_create.go does. " +
				"driver.NewSizing already refuses it; cdatapath defaults before reaching it.",
		},
		// The `operator-value-whitespace-normalisation` row stood here until
		// 2026-08-09 and is GONE, on its own instruction: its Fix line read
		// "delete this row when the gateway refuses or normalises at the flag",
		// and cmd/winn3-gateway now refuses. It is the
		// `operator-value-whitespace-refused-at-the-flag` pin in RegressionPins,
		// which also records the one part of it this suite has NOT measured —
		// the deployed hub, which runs older code than the repo ships.
		{
			ID: "path-mtu-not-negotiated",
			A:  "cmd/winn3-gateway/main.go -path-mtu (default carrier.DefaultPathMTU = 1450 since 2026-08-10; was 1280)",
			B:  "the client's own path_mtu (profile, create document, or [winn] path_mtu)",
			Behaviour: "NOTHING IN v3 NEGOTIATES THE PATH MTU. Each end computes its own plan " +
				"floor from its own number, and the two are never reconciled — a session " +
				"whose ends disagree does not become a working one.\n" +
				"NARROWED, NOT CLOSED, ON 2026-08-09. The responder now STATES its planning " +
				"path MTU in the handshake response payload and the initiator refuses a " +
				"session whose peer names a different one, loudly, naming both values " +
				"(winn3/session/pathmtu.go, and the " +
				"a-path-mtu-mismatch-established-and-then-black-holed-in-silence pin). That " +
				"is the REFUSAL half of the Fix below. The TAKE-THE-MINIMUM half is not " +
				"implemented and this row exists for it.",
			Consequence: "MEASURED on 2026-08-09 against a live cmd/winn3-gateway and the " +
				"shipping cmd/winn-datapath client over a real UDP socket, two OS processes. " +
				"There are TWO regimes and they produce different bug reports:\n" +
				"  * A NARROW mismatch (gateway 1400, client 1500) establishes normally and " +
				"    carries small packets perfectly — a 51-byte probe round-tripped with " +
				"    refused_datagrams:0. A 1350-byte probe then VANISHED: the gateway " +
				"    counted refused_datagrams:2, rx_packets stayed 0, and BOTH ENDS " +
				"    continued to report gate_state=carrying. Nothing is logged to the user " +
				"    and nothing is signalled to the client. This is the black hole.\n" +
				"  * A WIDE mismatch (gateway 1280, client 1500) is worse than the black " +
				"    hole: the session never carries at all. The gateway sent 1 message, " +
				"    refused 5, and the session went to state \"closed\" while the client's " +
				"    gate never left down.\n" +
				"The plan floors are 1232 and 1452 respectively. In both regimes the client " +
				"learns nothing, so the operator sees \"the VPN does not work in Myanmar\".\n" +
				"WHAT REMAINS, since 2026-08-09: the same two configurations still produce NO " +
				"TUNNEL. They now produce a named refusal at the client instead of a black " +
				"hole and a shrug, which is a different bug report and the same outage. A " +
				"gateway on the 1280 default and a client that measured 1500 still cannot " +
				"talk to each other, and the fleet is still configured by hand.",
			Fix: "The remaining half: have the initiator TAKE THE MINIMUM of the two rather " +
				"than refuse. The responder's number is already on the wire and the minimum " +
				"itself is NOW IMPLEMENTED — session.NegotiatedPathMTU is the explicit, " +
				"tested min-of-both-ends value, and Driver.refusePathMTUMismatch is a " +
				"guarded return on it, so the arithmetic neither end could point at before " +
				"now exists and is pinned. The missing piece is APPLYING it: taking the " +
				"minimum means re-applying a platform interface MTU on a live tunnel " +
				"across four hosts, where both the client's sizing and the OS interface " +
				"are fixed before the handshake. The fleet default WAS raised to 1450 on " +
				"2026-08-10 (carrier.DefaultPathMTU); that half is no longer a proposal. " +
				"Until the minimum is APPLIED the two ends must be configured identically " +
				"by hand, which is what " +
				"TestTheGatewayAndClientPathMTUMustBeConfiguredIdentically pins.",
		},
		{
			// RE-CHARACTERISED 2026-08-09, and the previous statement of it was
			// WRONG IN THE DIRECTION THAT MATTERS. It was filed as
			// `served-config-carries-no-promotion-routes-or-resolvers` and said the
			// desktop hosts "promote to a posture with an EMPTY route set" and
			// "capture no traffic". Measured against the shipping
			// windows/runner/winn3_posture.h, they do not: BuildPromotedPosture sets
			// `default_route = true` UNCONDITIONALLY, and both renderers emit the
			// 0.0.0.0/1 + 128.0.0.0/1 pair for it. A served config's promoted posture
			// captures every IPv4 destination.
			//
			// The route half of the row was therefore a description of a defect that
			// was not there, and it hid the one that was: the RESOLVER half.
			ID: "standalone-sessions-have-no-resolver-to-name",
			A: "every other tunnel this app starts, which installs resolvers with its " +
				"routes in one step — Android `.addDnsServer(dnsServer)` beside " +
				"`addRoute`, Apple `NEDNSSettings(servers: config.dnsServers)` beside " +
				"`includedRoutes`, Windows `[winn3] dns` + `dns_are_inner`",
			B: "a STANDALONE v3 session, for which no resolver exists anywhere in the " +
				"system: the ML-DSA-65 descriptor's closed 17-field set carries none, the " +
				"hub serves only `winn3_inner_v4` and `winn3_static_private`, the served " +
				"`[winn]` section has no `dns` key, and cmd/winn3-gateway is a REFLECTOR " +
				"that \"forwards nothing, resolves nothing and egresses nothing\"",
			Behaviour: "MEASURED 2026-08-09 by building the promoted posture from a served " +
				"section's own inputs. The route set is not empty and never was. What is " +
				"empty is `dns_servers`, and until 2026-08-09 winn3_posture.h promoted " +
				"happily on it — linux/runner/winn3_posture_test.cc asserted, verbatim, " +
				"\"a promotion with no resolvers at all is fine\".\n" +
				"Where the other two hosts get theirs is the coupling the owner's " +
				"2026-08-08 ruling forbids, and neither answer survives contact with a " +
				"standalone session: Android reads `DNS` out of the AmneziaWG document and " +
				"falls back to `10.8.1.1`, an address in the v1 inner space that the winn/3 " +
				"tun layer drops; Apple reads the same document and lib/main.dart's " +
				"fallback puts the PUBLIC Quad9 literals `9.9.9.9,149.112.112.112` there, " +
				"which are not inner by any reading and which Apple has no dns_are_inner " +
				"gate to catch.\n" +
				"THE HOST HALF IS NOW CLOSED ON ALL FOUR, as of 2026-08-09. The two mobile " +
				"hosts were the ones that failed by COMMISSION rather than by omission — " +
				"they reached for the resolver they had and installed it — and both now " +
				"DERIVE the predicate the desktop hosts take as an input, from the two inner " +
				"facts the signed descriptor carries (`inner_v4` and `inner_router_v4`) and " +
				"from nothing else. Apple's `WinsWinn3Resolvers` refuses a public literal, " +
				"the PMTU-only next hop, the assignment itself, a hostname, and anything " +
				"outside the /24 around the assignment; `WinsWinn3Settings.fullTunnel` " +
				"returns nil rather than a wider posture, and the refusal is pre-flighted at " +
				"START so a session that could never promote never dials the gateway. " +
				"Android's `WinnV3Resolvers` applies the same five clauses in the same order " +
				"inside `WinnV3Posture.promotion`, and `VpnTunnelService` no longer lets its " +
				"v1 `?: \"10.8.1.1\"` default cross into the v3 path at all. Both refuse a " +
				"MIXED list rather than filtering it, because `dns_servers_are_inner` is one " +
				"boolean over the WHOLE list and both platforms hand every entry to a " +
				"resolver library that — not this code — picks which one answers.",
			Consequence: "A promotion that installs no resolver widens the ROUTES onto the " +
				"tunnel and leaves NAME RESOLUTION where it was. The /1 pair does not " +
				"capture the machine's existing resolver, because the physical link's own " +
				"connected /24 is more specific than /1 — and on the connections these " +
				"users have, the resolver is the CPE at 192.168.1.1. So every DNS query " +
				"keeps going out the physical interface, in the clear, to the resolver the " +
				"censor operates, while the tunnel carries the web traffic and the gate " +
				"reports success.\n" +
				"It is the worst symptom shape this project has: NOTHING IS BROKEN. Pages " +
				"load. The user's full browsing history is handed to the network they " +
				"installed this to hide from, and in Myanmar the resolver is also where " +
				"blocking and poisoning are applied.",
			Fix: "THE ROUTE HALF IS CLOSED and is derived rather than served — see the pins " +
				"`a-promotion-that-captured-nothing-reported-success` and " +
				"`promotion-discarded-the-bootstraps-only-route`. A standalone session's " +
				"promoted route set is the bootstrap's inner next hop UNION whatever the " +
				"host supplies, plus the /1 pair `default_route` renders; nothing about it " +
				"needs to be on the wire, because with an unconditional default route a " +
				"served `routes` key could only ever ADD capture, and it would hand the " +
				"one decision that moves a user's traffic to the least trusted component " +
				"in the chain.\n" +
				"THE RESOLVER HALF IS NOT, and it cannot be closed by deriving: there is no " +
				"v3 resolver to derive. `inner_router_v4` is documented as \"the inner next " +
				"hop, for PMTU signals only\" and the gateway behind it answers no queries, " +
				"so pointing at it would trade a leak for total name-resolution failure. " +
				"ALL FOUR HOSTS now REFUSE — the two desktop ones since 2026-08-09 and the " +
				"two mobile ones since later the same day — which is fail-closed and costs " +
				"nothing today because that gateway egresses nothing either. WHAT SURVIVES " +
				"IS THE FIELD, NOT THE GATE: a served standalone session cannot promote on " +
				"ANY platform, and every one of them now says so by name instead of one of " +
				"them installing Quad9 and another installing an address its own tun layer " +
				"drops.\n" +
				"The field belongs in the SIGNED DESCRIPTOR (format version 3, beside " +
				"`inner_router_v4`, which joined the closed set in v2 for exactly this " +
				"reason) and NOT in the `[winn]` section: the section is unsigned hub " +
				"output, and the resolver address decides where every name lookup in the " +
				"session goes. `dns_are_inner` must stay a HOST-DERIVED predicate — " +
				"winn3_posture.h calls it \"the host's own declaration\" — because a " +
				"transported boolean asserting \"this resolver is inside the tunnel\" is " +
				"unverifiable by the host and is precisely the leak wearing a flag. Delete " +
				"this row when the descriptor carries a resolver and all four hosts install " +
				"it from there.",
		},
		{
			// RE-CHARACTERISED 2026-08-09. Filed as
			// `linux-served-parser-has-no-caller`; that claim is now false.
			ID: "linux-served-start-has-no-privileged-executor",
			A: "windows/runner/windows_tunnel_backend.cpp:3483, which branches on " +
				"ConfigSelectsWinn3 and hands the raw config to a supervisor that owns a " +
				"LocalSystem tunnel service and can therefore run what it renders",
			B: "linux/runner/linux_tunnel_backend.cc, which now branches on " +
				"LinuxConfigSelectsWinn3 before either winn/1 predicate, parses with " +
				"ParseLinuxWinn3Section, writes the key files, reads the outer-path facts " +
				"and then REFUSES — because the Linux privileged surface is a root script " +
				"with exactly two actions, `start` and `stop`, both of which are awg-quick",
			Behaviour: "The parser has a caller as of 2026-08-09 and the branch is placed " +
				"where Windows places its own, so a served standalone config is no longer " +
				"claimed by the winn/1 relay parser and no longer refused in that parser's " +
				"words about a protocol it was not asked to speak. What the branch cannot " +
				"do is EXECUTE: ApplyLinuxWinn3BootstrapPosture takes a " +
				"LinuxWinn3PrivilegedRunner and nothing on this platform supplies one. The " +
				"root script speaks `winsvpn-helper start <config>` and `stop`; it has no " +
				"way to run a rendered `ip` argument vector.",
			Consequence: "Linux parses a served config, validates it, sizes it, writes its " +
				"keys 0600 and stops with a named refusal instead of a relay-parser error. " +
				"That is honest and it is not a session. Anyone reading the pin table would " +
				"otherwise conclude a served config starts a session on four platforms.",
			Fix: "Add a privileged action that executes the rendered argument vectors, and " +
				"do it AFTER the resolver row above is closed, not before: the promotion " +
				"gate refuses a resolverless posture, so a root path built today would " +
				"reach a state guaranteed to refuse, and adding privileged surface to get " +
				"there is the wrong order. The renderers are already pure and already " +
				"re-checked on the argv by VerifyLinuxWinn3BootstrapCommandsAreNarrow and " +
				"VerifyPromotedCommandsCapture, so the executor needs no policy of its own " +
				"— it needs an allowlist of `ip` and `resolvectl` and nothing else. Delete " +
				"this row when a served config starts a Linux session.",
		},
	}
	// Four entries above are retained as closure history because their measured
	// failure descriptions remain useful regression context. They are no longer
	// returned as known divergences: both shipping create paths now refuse an
	// empty or non-UDP plan, format-v3 descriptors require and serve a signed
	// inner resolver consumed by all four hosts, and Linux supplies the guarded
	// winn3-posture privileged runner. Path-MTU minimum application remains open.
	for _, row := range rows {
		if row.ID == "path-mtu-not-negotiated" {
			return []Divergence{row}
		}
	}
	panic("path-mtu-not-negotiated divergence record is missing")
}

// DivergenceIDs is the sorted id set.
//
// NOTHING CALLS THIS. It was documented as "what the suite compares" and the
// suite compares nothing to it — there is no observed divergence set to compare
// against. It is kept because it is the right shape for the day somebody builds
// one, and it is labelled honestly in the meantime so that reading it does not
// leave anyone believing a check exists that does not.
func DivergenceIDs(ds []Divergence) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.ID)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// the machine-readable vector file
// ---------------------------------------------------------------------------

// Vectors is the whole suite as data, for the hosts that are not Go.
//
// Kotlin and Swift cannot import this package, so they are fed this document
// and assert against it. It is GENERATED, never hand-maintained: a checked-in
// expectation that somebody edited to make a test pass is worth nothing, and
// cmd/winn3-conformance regenerates this from the same functions the engine
// runs.
type Vectors struct {
	Generator string `json:"generator"`
	Note      string `json:"note"`

	Operator struct {
		GatewayID      string   `json:"gateway_id"`
		AdmissionFile  string   `json:"admission_file"`
		PathMTU        int      `json:"path_mtu"`
		CarrierClasses []string `json:"carrier_classes"`
	} `json:"operator"`

	Admission struct {
		GatewayIDHex           string `json:"gateway_id_hex"`
		GatewayIDLen           int    `json:"gateway_id_len"`
		GatewayIDBase64Decoded string `json:"gateway_id_if_wrongly_base64_decoded_hex"`
		AdmissionKeyHex        string `json:"admission_key_hex"`
		AdmissionKeyLen        int    `json:"admission_key_len"`
		AdmissionIfHexDecoded  string `json:"admission_key_if_wrongly_hex_decoded_hex"`
		TagSize                int    `json:"tag_size"`
	} `json:"admission"`

	Constants struct {
		Overhead            int `json:"tun_overhead"`
		FrameOverhead       int `json:"frame_overhead"`
		TransportOverhead   int `json:"transport_overhead"`
		UDPOverIPv4Overhead int `json:"udp_over_ipv4_overhead"`
		UDPOverIPv6Overhead int `json:"udp_over_ipv6_overhead"`
		IPv6MinLinkMTU      int `json:"ipv6_min_link_mtu"`
		MinInnerMTUv4       int `json:"min_inner_mtu_v4"`
		MessageFloor        int `json:"message_floor"`
		MaxTransportPayload int `json:"max_transport_payload"`
		DefaultPathMTU      int `json:"default_path_mtu"`
		DemuxTokenSize      int `json:"demux_token_size"`
		LengthRecordOverh   int `json:"length_record_overhead"`
	} `json:"constants"`

	Overheads []OverheadRow `json:"carrier_overheads"`
	Floors    []FloorRow    `json:"plan_floors"`

	Demux []struct {
		KeyHex   string `json:"key_hex"`
		Counter  uint64 `json:"counter"`
		TokenHex string `json:"token_hex"`
	} `json:"demux_tokens"`

	// GateStates is the `gate_state` vocabulary, generated from winn3/tun.
	//
	// It is here rather than in a host's own file for the same reason every
	// other number in this document is: a host that cannot import Go still has
	// to get these names from the code that defines them. A host harness reads
	// GateStateDocument, compares it to its own copy, and fails if they differ
	// — which is the check the four hosts did not have on 2026-08-09, when all
	// five call sites held hand-copied literals and nothing anywhere compared
	// them to the switch in gate.go.
	GateStates        []GateStateName `json:"gate_states"`
	GateStateCarry    string          `json:"gate_state_that_carries"`
	GateStateUnknown  string          `json:"gate_state_sentinel_never_a_state"`
	GateStateDocument string          `json:"gate_state_vocabulary_document"`

	// The two tables, side by side and never merged. A pin is fixed and its
	// return fails the build; a divergence is unfixed and is measured debt.
	RegressionPins   []Pin        `json:"regression_pins"`
	KnownDivergences []Divergence `json:"known_divergences"`
}

// BuildVectors renders the whole suite.
func BuildVectors(o Operator) (Vectors, error) {
	var v Vectors
	v.Generator = "winn_protocol_experimental/cmd/winn3-conformance (regenerate; do not hand-edit)"
	v.Note = "Every number here is computed by winn3/carrier, winn3/session, winn3/driver and " +
		"winn3/core — the packages the shipping engine runs. A host that disagrees with this " +
		"file disagrees with the wire."

	v.Operator.GatewayID = o.GatewayID
	v.Operator.AdmissionFile = o.AdmissionFile
	v.Operator.PathMTU = o.PathMTU
	v.Operator.CarrierClasses = o.CarrierClasses

	id := o.GatewayIDBytes()
	secret := o.AdmissionSecret()
	v.Admission.GatewayIDHex = hex.EncodeToString(id)
	v.Admission.GatewayIDLen = len(id)
	v.Admission.GatewayIDBase64Decoded = wronglyBase64(o.GatewayID)
	v.Admission.AdmissionKeyHex = hex.EncodeToString(secret)
	v.Admission.AdmissionKeyLen = len(secret)
	v.Admission.AdmissionIfHexDecoded = wronglyHex(secret)
	v.Admission.TagSize = core.DefaultTagSize

	v.Constants.Overhead = tun.Overhead()
	v.Constants.FrameOverhead = tun.FrameOverhead
	v.Constants.TransportOverhead = core.TransportOverhead()
	v.Constants.UDPOverIPv4Overhead = tun.UDPOverIPv4Overhead
	v.Constants.UDPOverIPv6Overhead = tun.UDPOverIPv6Overhead
	v.Constants.IPv6MinLinkMTU = tun.IPv6MinLinkMTU
	v.Constants.MinInnerMTUv4 = tun.MinInnerMTUv4
	v.Constants.MessageFloor = session.MessageFloor()
	v.Constants.MaxTransportPayload = core.MaxTransportPayload
	v.Constants.DefaultPathMTU = DefaultPathMTU
	v.Constants.DemuxTokenSize = core.DemuxTokenSize
	v.Constants.LengthRecordOverh = carrier.LengthRecordOverhead

	v.Overheads = Overheads()

	floors, err := Matrix()
	if err != nil {
		return Vectors{}, err
	}
	v.Floors = floors

	for i := 0; i < 4; i++ {
		key := make([]byte, core.KeySize)
		for j := range key {
			key[j] = byte(0x10*i + j)
		}
		counter := uint64(i) * 65537
		v.Demux = append(v.Demux, struct {
			KeyHex   string `json:"key_hex"`
			Counter  uint64 `json:"counter"`
			TokenHex string `json:"token_hex"`
		}{
			KeyHex:   hex.EncodeToString(key),
			Counter:  counter,
			TokenHex: hex.EncodeToString(DemuxTokenFromDoc(key, counter)),
		})
	}

	v.GateStates = GateStateVocabulary()
	v.GateStateCarry = GateStateCarryingName()
	v.GateStateUnknown = GateStateUnknownName()
	v.GateStateDocument = GateStateVocabularyDocument()

	v.KnownDivergences = KnownDivergences()
	v.RegressionPins = RegressionPins()
	return v, nil
}

// JSON renders the vectors with stable key order and a trailing newline.
func (v Vectors) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ---------------------------------------------------------------------------
// rendering helpers
// ---------------------------------------------------------------------------

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	return hex.EncodeToString(b)
}

func quoteBytes(b []byte) string {
	if len(b) == 0 {
		return `""`
	}
	return fmt.Sprintf("%q", string(b))
}

func prefixHex(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	if len(b) > 8 {
		b = b[:8]
	}
	return hex.EncodeToString(b)
}

// wronglyBase64 is what a host that base64-decodes gateway_id derives.
//
// It is published in the vector file NEXT TO the correct value on purpose.
// Defect 1's whole difficulty was that the wrong answer is not an error: an
// operator name drawn from the base64 alphabet decodes cleanly to different
// bytes, so the only way to see the mistake is to see both numbers side by
// side. "<not base64>" here means the mistake would at least have been loud
// for THIS name — which is exactly the luck `wins-sea-01` did not have.
func wronglyBase64(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "<not base64: this name would have failed loudly>"
	}
	return hex.EncodeToString(raw)
}

// wronglyHex is what a host that hex-decodes the admission secret derives.
//
// Same reasoning as wronglyBase64: keygen writes hex, so hex-decoding the file
// succeeds and yields 32 bytes instead of the 64 ASCII characters every
// consumer actually keys with. The tag differs, ReadInitiation fails, and the
// gateway answers nothing.
func wronglyHex(b []byte) string {
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return "<not hex: this secret would have failed loudly>"
	}
	return hex.EncodeToString(raw)
}
