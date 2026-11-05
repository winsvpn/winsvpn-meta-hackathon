package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
	"winsvpn.local/winnprotocol/winn3/tun"
)

// The winn/3 Create frame, and the four refusals it exists for.
//
// # What is in this document and what is deliberately not
//
// Everything here is a runtime parameter the HOST is the authority on: which
// gateway, which inner address, which MTU it put on its own interface, which
// classes the session may escalate to. Nothing here is a secret, and nothing
// here is a trust anchor.
//
// KEY MATERIAL IS NOT IN THIS DOCUMENT AND MUST NOT BE. datapath/carrier.go
// records the rule for the winn/1 carrier profile — an authenticated
// configuration has no business crossing a channel whose payload is
// peer-supplied by construction — and a static private key is strictly worse
// than a carrier configuration. The keys are named by -winn3-keys, a PATH this
// process opens itself under its own uid. See winn3_keys.go.
//
// That is the one place this seam asks the Android host for an argv token it
// does not build today, and it is a smaller change than putting base64 key
// bytes into WinnV3EngineConfig.toJson.
//
// # The four refusals
//
//  1. payload must be "ip-packet". Checked FIRST, before anything about the
//     transport, because getting it wrong is the failure that puts cleartext on
//     the wire: a v1 engine fed inner packets forwards them to the gateway
//     unencrypted, and a v3 engine fed AmneziaWG datagrams double-encrypts and
//     the gateway drops everything.
//  2. owns_tun must be false. In this mode the host owns the tun device and
//     pumps inner packets over the frames; an engine that also opened one would
//     be two devices for one tunnel.
//  3. inner_mtu must equal the PLAN FLOOR's inner MTU exactly. Not the dialled
//     carrier's. This is the check that catches the 84-byte black hole.
//  4. allow_own_socket must be false unless a descriptor was supplied, or true
//     with an exclusion declared in the key document. A socket this process
//     opened is a socket the host never protected.

// winn3FramePayload is the only payload class this mode accepts. It is exactly
// the string datapath.Config refuses, and that asymmetry is the whole point.
const winn3FramePayload = "ip-packet"

// winn3RelayPayload is what the winn/1 path carries. Named here so the refusal
// can say which entry point the caller wanted.
const winn3RelayPayload = "awg-datagram"

var errWinn3Create = errors.New("winn3 create")

func winn3RefuseCreate(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWinn3Create, fmt.Sprintf(format, args...))
}

// winn3CreateDocument is the OpCreate payload in -winn3 mode.
//
// Field names and shapes are WinnV3EngineConfig.toJson's, verbatim, so that the
// Android host's hand-built JSON — which has no org.json behind it and cannot be
// reshaped cheaply — parses without a translation layer on either side.
type winn3CreateDocument struct {
	// Payload is "ip-packet" and nothing else.
	Payload string `json:"payload"`

	// GatewayEndpoint is "ip:port". A hostname is refused: resolving one here
	// is a DNS lookup on the censored path, which is the observable the staged
	// posture exists to avoid.
	GatewayEndpoint string `json:"gateway_endpoint"`

	// InnerAddress is this tunnel's inner address and InnerNextHop the inner
	// router. The next hop is optional and is used only as the source of a
	// synthesised path-MTU packet.
	InnerAddress string `json:"inner_address"`
	InnerNextHop string `json:"inner_next_hop"`

	// InnerMTU is the MTU the host has ALREADY set on its interface. It is
	// checked against the plan floor rather than trusted; see refusal 3.
	InnerMTU int `json:"inner_mtu"`

	// PathMTU is the OUTER path MTU the floor is computed at.
	PathMTU int `json:"path_mtu"`

	// CarrierClasses is every class the session may escalate TO, never the one
	// dialled. The floor is computed over this list.
	CarrierClasses []string `json:"carrier_classes"`

	// SessionID is opaque, echoed in the status document so a host can
	// correlate, and never put on the wire.
	SessionID string `json:"session_id"`

	// AllowOwnSocket permits this process to dial the outer socket when no
	// descriptor was handed over.
	AllowOwnSocket bool `json:"allow_own_socket"`

	// OwnsTun must be false: the host owns the device in this mode.
	OwnsTun bool `json:"owns_tun"`
}

// winn3CreatePlan is a decoded, checked create document with the numbers it
// implies already computed, so that no later step can recompute one of them
// differently.
type winn3CreatePlan struct {
	doc     winn3CreateDocument
	sizing  driver.Sizing
	remote  *net.UDPAddr
	assign  tun.Assignment
	classes []carrier.Class
}

// decodeWinn3Create parses and checks the Create payload.
//
// hasDescriptor says whether a protected outer socket was handed to this
// process, because refusal 4 cannot be decided from the document alone.
// exclusionDeclared says whether the key document named the exclusion that
// makes allow_own_socket safe.
//
// Unknown fields are refused rather than dropped. A host that misspells a key
// and is told nothing believes a setting took effect that did not, and on this
// document the settings that could silently not take effect are the migration
// plan, the payload class and the socket rule.
//
// decomposition that hides which one fired.
//
//nolint:gocyclo // a flat list of independent refusals reads better than a
func decodeWinn3Create(
	payload []byte, hasDescriptor, exclusionDeclared bool,
) (winn3CreatePlan, error) {
	// encoding/json.Decode of JSON null into a struct succeeds and leaves the
	// zero value. The payload-class check would then refuse payload "" as if
	// the host omitted the field, which is the wrong diagnosis: the document
	// was not an object. Same first-byte rule as decodeWinn3Status.
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return winn3CreatePlan{}, winn3RefuseCreate("decode: empty document")
	}
	if trimmed[0] != '{' {
		return winn3CreatePlan{}, winn3RefuseCreate(
			"decode: document must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var doc winn3CreateDocument
	if err := decoder.Decode(&doc); err != nil {
		return winn3CreatePlan{}, winn3RefuseCreate("decode: %v", err)
	}
	// Same rule as datapath.ParseConfig: a second JSON value after the object
	// is an under-read. encoding/json.Decoder stops at the first value.
	if decoder.More() {
		return winn3CreatePlan{}, winn3RefuseCreate(
			"document must be a single JSON object")
	}

	// (1) The payload class, before anything else.
	if doc.Payload != winn3FramePayload {
		if doc.Payload == winn3RelayPayload {
			return winn3CreatePlan{}, winn3RefuseCreate(
				"payload is %q, which is the winn/1 relay class; this process "+
					"was started with -winn3 and carries %q. Start it without "+
					"-winn3 for a relay session rather than feeding AmneziaWG "+
					"datagrams to a v3 engine, which would double-encrypt them "+
					"and be dropped by the gateway",
				winn3RelayPayload, winn3FramePayload)
		}
		return winn3CreatePlan{}, winn3RefuseCreate(
			"payload is %q; this mode carries %q only", doc.Payload, winn3FramePayload)
	}

	// (2) The device rule.
	if doc.OwnsTun {
		return winn3CreatePlan{}, winn3RefuseCreate(
			"owns_tun is true: in -winn3 frame mode the HOST owns the tun " +
				"device and pumps inner IP packets over the Inbound and " +
				"Outbound frames, so an engine that also opened one would be " +
				"two devices for one tunnel. Use -winn3-profile with " +
				"device.kind tun-fd if the engine should hold the descriptor")
	}

	// The plan, and the floor over it. Computed before the endpoint is even
	// looked at, because it is the number every later check is against.
	classes, err := winn3CreateClasses(doc.CarrierClasses)
	if err != nil {
		return winn3CreatePlan{}, err
	}
	pathMTU := doc.PathMTU
	if pathMTU == 0 {
		// carrier.DefaultPathMTU and NOT tun.IPv6MinLinkMTU. They were the same
		// number until 2026-08-10; four host entry points resolve a missing
		// path_mtu and they must all resolve it through ONE constant, or the
		// fleet default splits and every default session is a mismatch.
		pathMTU = carrier.DefaultPathMTU
	}
	if pathMTU < 0 {
		return winn3CreatePlan{}, winn3RefuseCreate("path_mtu %d is negative", pathMTU)
	}
	sizing, err := driver.NewSizing(pathMTU, classes...)
	if err != nil {
		return winn3CreatePlan{}, fmt.Errorf("%w: %w", errWinn3Create, err)
	}

	// (3) The MTU the host actually set, against the floor.
	if doc.InnerMTU != sizing.InnerMTU {
		return winn3CreatePlan{}, winn3RefuseCreate(
			"inner_mtu is %d and the plan floor over %v at a path MTU of %d is "+
				"%d (message size %d). The host's interface MTU must be EXACTLY "+
				"the floor: a larger one black-holes every full-size flow at the "+
				"first migration while the tunnel still reads up, and a smaller "+
				"one silently costs throughput the plan already paid for. If %d "+
				"came from the dialled carrier rather than from the plan, that "+
				"is the defect this refusal exists to catch",
			doc.InnerMTU, doc.CarrierClasses, pathMTU,
			sizing.InnerMTU, sizing.MessageSize, doc.InnerMTU)
	}

	// (4) The socket rule.
	switch {
	case !doc.AllowOwnSocket && !hasDescriptor:
		return winn3CreatePlan{}, winn3RefuseCreate(
			"allow_own_socket is false and no descriptor was handed over: " +
				"start this process with -receive-fd and send the protected " +
				"socket over the control channel, or set allow_own_socket and " +
				"declare the exclusion in the key document")
	case doc.AllowOwnSocket && hasDescriptor:
		return winn3CreatePlan{}, winn3RefuseCreate(
			"allow_own_socket is true and a descriptor was also handed over: " +
				"one of the two documents is wrong about who protected the " +
				"outer socket, and guessing would leave the engine's own " +
				"datagrams inside the tunnel it carries")
	case doc.AllowOwnSocket && !exclusionDeclared:
		return winn3CreatePlan{}, winn3RefuseCreate(
			"allow_own_socket is true but the key document declares no " +
				"outer_socket_exclusion: a socket this process opened is a " +
				"socket the host never excluded, and its own datagrams would " +
				"match the tunnel's default route and loop")
	}

	remote, err := winn3CreateEndpoint(doc.GatewayEndpoint)
	if err != nil {
		return winn3CreatePlan{}, err
	}

	assign, err := winn3CreateAssignment(doc)
	if err != nil {
		return winn3CreatePlan{}, err
	}
	// tun.New refuses an inner IPv6 assignment the floor cannot carry, but the
	// refusal reads better with the number that caused it.
	if assign.V6.IsValid() && !sizing.InnerIPv6 {
		return winn3CreatePlan{}, winn3RefuseCreate(
			"inner_address is IPv6 and this plan needs an outer path MTU of at "+
				"least %d to carry inner IPv6; this one is %d",
			sizing.MinPathMTUForInnerIPv6, pathMTU)
	}

	return winn3CreatePlan{
		doc:     doc,
		sizing:  sizing,
		remote:  remote,
		assign:  assign,
		classes: classes,
	}, nil
}

// winn3CreateClasses resolves the plan and insists that UDP is in it.
//
// Frame mode still dials UDP only: the Create document has no trust-anchor,
// ECH-list or client-certificate fields. The desktop -winn3-profile path
// does, and winn3DialCarrier routes class=tls through internal/tlsconfig.
// A plan without UDP is still refused here because this seam cannot open
// the other classes. Naming tcp and tls in the plan is legitimate: the
// floor is computed over them so that a later migration to one is free.
func winn3CreateClasses(names []string) ([]carrier.Class, error) {
	if len(names) == 0 {
		return nil, winn3RefuseCreate(
			"carrier_classes is empty: name every class this session may " +
				"escalate to, because the message floor is computed over the " +
				"list and a class left out of it is a class the floor did not " +
				"account for")
	}
	out := make([]carrier.Class, 0, len(names))
	hasUDP := false
	for i, name := range names {
		class, err := winn3ClassNamed(name)
		if err != nil {
			return nil, winn3RefuseCreate("carrier_classes[%d]: %v", i, err)
		}
		if class == carrier.ClassUDP {
			hasUDP = true
		}
		out = append(out, class)
	}
	if !hasUDP {
		return nil, winn3RefuseCreate(
			"carrier_classes %v does not name %s, which is the only class this "+
				"build can dial: a tls carrier needs trust anchors this process "+
				"is never given, and dialling tcp while reporting tls would be a "+
				"silent downgrade", names, carrier.ClassUDP)
	}
	return out, nil
}

// winn3CreateEndpoint refuses anything that is not an IP literal with a port.
func winn3CreateEndpoint(endpoint string) (*net.UDPAddr, error) {
	if err := winn3ValidateEndpoint(endpoint); err != nil {
		return nil, winn3RefuseCreate("gateway_endpoint: %v", err)
	}
	parsed, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, winn3RefuseCreate("gateway_endpoint: %v", err)
	}
	return net.UDPAddrFromAddrPort(parsed), nil
}

// winn3CreateAssignment parses the inner assignment.
//
// One address, because §4.1's bootstrap posture is one /32 and the host has
// already installed it by the time this document arrives. A document that
// carries neither is a tunnel with no inner identity and is refused rather than
// defaulted.
func winn3CreateAssignment(doc winn3CreateDocument) (tun.Assignment, error) {
	var out tun.Assignment
	parse := func(field, value string) (netip.Addr, error) {
		if strings.TrimSpace(value) == "" {
			return netip.Addr{}, nil
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return netip.Addr{}, winn3RefuseCreate("%s: %v", field, err)
		}
		if addr.Zone() != "" {
			return netip.Addr{}, winn3RefuseCreate(
				"%s carries a zone; the inner address space has no link-local scope",
				field)
		}
		return addr.Unmap(), nil
	}
	addr, err := parse("inner_address", doc.InnerAddress)
	if err != nil {
		return tun.Assignment{}, err
	}
	if !addr.IsValid() {
		return tun.Assignment{}, winn3RefuseCreate(
			"inner_address is empty: a tunnel with no inner address validates " +
				"nothing, because the inner-IP validator's whole job is to " +
				"refuse a packet addressed to somebody else")
	}
	hop, err := parse("inner_next_hop", doc.InnerNextHop)
	if err != nil {
		return tun.Assignment{}, err
	}
	if hop.IsValid() && hop.Is4() != addr.Is4() {
		return tun.Assignment{}, winn3RefuseCreate(
			"inner_next_hop %q is not the same family as inner_address %q",
			doc.InnerNextHop, doc.InnerAddress)
	}
	if addr.Is4() {
		out.V4, out.RouterV4 = addr, hop
	} else {
		out.V6, out.RouterV6 = addr, hop
	}
	return out, nil
}
