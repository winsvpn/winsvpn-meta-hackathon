package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

// The Winn Protocol v3 host profile.
//
// # Why this is a PATH and not a Create frame
//
// The same reasoning datapath/carrier.go records for the winn/1 carrier
// profile, and it applies with more force here. This document names the
// device's static key file and the gateway's static key file. The duplex frame
// channel's payload is peer-supplied by construction; a path is different in
// kind, because this process opens the file itself, under its own uid, and
// every trust decision is made here rather than asserted by whoever wrote the
// frame.
//
// IT CONTAINS NO KEY MATERIAL, only paths. That is the same rule
// LinuxWinnCarrierProfile already follows and it is what keeps a host that
// forwards a profile from ever holding a key.
//
// # Why this is a SEPARATE document from datapath.Config
//
// v3 is a standalone protocol: its own handshake, its own crypto, its own
// datapath. Not one field below is a field of datapath.Config, whose decoder
// rejects unknown fields, so folding these into the Create frame would be a
// hard create-time error. The two documents describe two different protocols
// and are deliberately not made to look alike.

// winn3ProfileVersion is the only version this build accepts. A host that finds
// a different value in the banner knows the binary it packaged predates or
// postdates its own writer, instead of discovering it as a decode error at
// start.
const winn3ProfileVersion = "winn3-host/1"

// maxWinn3ProfileBytes bounds the document. A host profile is a few hundred
// bytes of scalars and paths; anything larger is a mistake or an attempt to
// make this process allocate. Same ceiling as carrierhost.MaxProfileBytes,
// restated rather than imported so this file does not depend on the winn/1
// carrier profile package.
const maxWinn3ProfileBytes = 64 << 10

// maxWinn3ProfileJSONDepth is well above a legitimate document (root object
// plus one nested object or array) and well below the nesting that
// encoding/json will recurse through while skipping an unknown value — which
// is a stack overflow, which is a panic, which is a denial of service.
const maxWinn3ProfileJSONDepth = 8

// maxWinn3PathMTU is the largest path_mtu this document accepts. An IPv4
// datagram cannot be larger; a number above this is not a path MTU.
const maxWinn3PathMTU = 65535

// maxWinn3PlanEntries is the number of carrier classes this build knows.
// A longer plan is either duplicates or unknown names; both are refused
// in validate. The length check runs AFTER json.Decode has materialised
// Plan, so a hostile array can allocate one string header per element up
// to the document-size ceiling. That is bounded by maxWinn3ProfileBytes,
// not unbounded, and it is not the pre-decode cap this comment used to
// claim.
const maxWinn3PlanEntries = 3

// winn3Profile is the document -winn3-profile names.
type winn3Profile struct {
	Version string `json:"version"`

	// Role is "client" or "gateway". A desktop host is always the client; the
	// gateway value exists so that this binary can serve the lab's responding
	// half without a second command.
	Role string `json:"role"`

	// Plan is the migration plan, in the order the host intends to try it.
	// EVERY class the session may escalate TO must be named, not the one it
	// dials: the message floor is computed over this list, and a plan that
	// omits a class the host later migrates to is the 84-byte black hole the
	// carrier lane measured.
	Plan []string `json:"plan"`

	// PathMTU is the planning path MTU. Zero means carrier.DefaultPathMTU.
	PathMTU int `json:"path_mtu"`

	// GatewayID binds the admission tag to one gateway, so that an initiation
	// captured at gateway A cannot be replayed at gateway B while both are
	// mid-rotation on a shared admission key. It is authenticated but never
	// transmitted, so it is not an identifier a censor can see; it still names
	// infrastructure, so it is not echoed into the status document.
	GatewayID string `json:"gateway_id"`

	Carrier winn3CarrierSpec `json:"carrier"`
	Inner   winn3InnerSpec   `json:"inner"`
	Keys    winn3KeySpec     `json:"keys"`
	Device  winn3DeviceSpec  `json:"device"`

	// AllowOwnSocket is the desktop model, and it is the ONLY model this mode
	// supports. The engine opens the outer socket itself; the host must have
	// installed a route exclusion that keeps that socket out of the tunnel it
	// carries, or the engine's own datagrams match the tunnel's default route
	// and loop forever.
	//
	// Both Linux and Windows are exactly this case, which is why they are the
	// two hosts with no descriptor hand-off to arrange. Android's
	// VpnService.protect and Apple's NetworkExtension have to solve it a
	// different way; a desktop does not.
	AllowOwnSocket bool `json:"allow_own_socket"`

	// OuterSocketExclusion is the host's own description of the exclusion it
	// installed — an fwmark rule on Linux, an interface-scoped route or WFP
	// exception on Windows. It is NOT parsed and NOT acted on. It is required
	// to be non-empty so that a host cannot claim allow_own_socket without
	// having written down what it did, and it is echoed in the status document
	// so the claim is auditable next to the counters.
	OuterSocketExclusion string `json:"outer_socket_exclusion"`

	// FastPQ allows DATA under epoch-0 keys. Defaults to false, which is
	// StrictPQ. Harvest-now-decrypt-later is a live threat for this user
	// population, so the round trip is worth it.
	FastPQ bool `json:"fast_pq"`
}

// winn3CarrierSpec is the transport dialled first.
type winn3CarrierSpec struct {
	// Class is "udp", "tcp" or "tls". It must appear in Plan.
	//
	// tls additionally requires the trust-anchor, ECH-list and (for
	// private-ca) client-certificate fields below. Naming tls without them
	// used to load and then fail only at dial, which is how a deployment
	// sized around a phantom.
	Class string `json:"class"`

	// Endpoint is the gateway, an IP literal "host:port" or "[v6]:port".
	// Never a hostname: resolving one here would leak a DNS lookup outside the
	// tunnel, which is the observable the staged posture exists to avoid.
	Endpoint string `json:"endpoint"`

	// TrustAnchor is tlsconfig.TrustPrivateCA or tlsconfig.TrustWebPKI.
	// Required when Class is tls; forbidden otherwise. Empty is refused
	// rather than defaulted: an absent field has not stated what the client
	// verifies the server certificate against.
	TrustAnchor string `json:"trust_anchor,omitempty"`

	// RootCAPath is the PEM pool for private-ca. Forbidden under webpki.
	RootCAPath string `json:"root_ca_path,omitempty"`

	// ECHConfigListPath is mandatory for class tls: without it the
	// ClientHello is a single-probe fingerprint of the Winn TLS profile.
	ECHConfigListPath string `json:"ech_config_list_path,omitempty"`

	// ClientCertPath and ClientKeyPath are the mTLS device credential
	// private-ca requires. Forbidden under webpki: a TLS-terminating CDN is
	// the mTLS peer, so the origin never sees the certificate, and the CDN
	// would receive a persistent device identifier.
	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`

	// ServerName is the inner ClientHello name, under ECH.
	ServerName string `json:"server_name,omitempty"`

	// Suite names the hybrid post-quantum key agreement, e.g.
	// "x25519-mlkem768". tlsconfig.ParseSuite is the authority on the list.
	Suite string `json:"suite,omitempty"`

	// ALPN is the protocol the inner hello offers. Empty means
	// winn3TLSDefaultALPN.
	ALPN string `json:"alpn,omitempty"`
}

// winn3InnerSpec is the inner-IP assignment.
type winn3InnerSpec struct {
	V4       string `json:"v4"`
	V6       string `json:"v6"`
	RouterV4 string `json:"router_v4"`
	RouterV6 string `json:"router_v6"`
}

// winn3KeySpec names key files by absolute path and never their contents.
type winn3KeySpec struct {
	// StaticPath is this end's static X25519 private key: 32 raw bytes, or 64
	// lowercase hex characters with optional trailing newline.
	StaticPath string `json:"static_path"`

	// GatewayStaticPath is the gateway's static X25519 public key, in the same
	// two accepted encodings. Client only.
	GatewayStaticPath string `json:"gateway_static_path"`

	// AdmissionPath names the file holding the gateway's admission secret.
	//
	// ONE field, deliberately, although the secret is used twice: it is
	// core.GatewayParams.AdmissionKeys[0], from which the initiation's
	// admission tag is derived, and it is the key the §4.2 encrypted length
	// layer of a stream carrier is derived from. They are the same secret, and
	// two fields that must always hold the same value are two fields that will
	// eventually not.
	AdmissionPath string `json:"admission_path"`

	// DualAuthEd25519PubPath and DualAuthMLDSA65PubPath name the gateway's
	// dual-signature attestation public keys (hex). Both set together, or both
	// empty (a legacy session without the attestation).
	DualAuthEd25519PubPath string `json:"dual_auth_ed25519_pub_path"`
	DualAuthMLDSA65PubPath string `json:"dual_auth_mldsa65_pub_path"`
}

// winn3DeviceSpec selects the host device backend.
type winn3DeviceSpec struct {
	// Kind is "loopback-udp" or "tun-fd".
	//
	// loopback-udp is the portable one and is what Windows uses: the host owns
	// the Wintun adapter and relays one inner IP packet per datagram over
	// 127.0.0.1. A socket bound to 127.0.0.1 has no route off the device, so
	// the cleartext leg is contained structurally rather than by policy — the
	// same argument WinnAwgLoopbackSeam, internal/carrier.RelayLocalUDP and
	// BindLinuxWinnSeam already rest on.
	//
	// tun-fd is the Linux one: the host opens /dev/net/tun, configures the
	// interface, and passes the descriptor over the control socket's ancillary
	// data. No inner packet ever crosses a socket in cleartext at all, so it is
	// the better of the two and is the reason Linux is the cheaper host.
	Kind string `json:"kind"`

	// HostPort is the host's own loopback UDP port for kind loopback-udp. The
	// host binds it BEFORE starting this process, exactly as BindLinuxWinnSeam
	// does today, so that the first inner packets queue in a receive buffer
	// instead of drawing ICMP port-unreachable while the engine starts.
	HostPort int `json:"host_port"`

	// Name is the tun interface's name for kind tun-fd. It is used only to read
	// back the MTU the host configured, which is how the §4.2 obligation is
	// PROVEN rather than trusted.
	Name string `json:"name"`
}

const (
	winn3DeviceLoopbackUDP = "loopback-udp"
	winn3DeviceTunFD       = "tun-fd"
	winn3RoleClient        = "client"
	winn3RoleGateway       = "gateway"

	// winn3TLSDefaultALPN is the inner ClientHello ALPN a class=tls profile
	// offers when carrier.alpn is omitted. It is http2.NextProtoTLS ("h2"),
	// which is what cmd/winn3-gateway/cover.go puts on the Winn strict
	// profile. A mismatch fails the handshake after ECH is accepted — that
	// was measured: default "http/1.1" against the cover Winn profile
	// negotiated ALPN "".
	winn3TLSDefaultALPN = "h2"
)

// errWinn3Profile is the base for every refusal in this file.
var errWinn3Profile = errors.New("winn3 host profile")

func winn3Refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWinn3Profile, fmt.Sprintf(format, args...))
}

// loadWinn3Profile reads and validates the document at path.
//
// Unknown fields are refused rather than dropped. A host that misspells a key
// and is told nothing believes a setting took effect that did not, and on this
// document the settings that could silently not take effect are the migration
// plan and the socket rule.
func loadWinn3Profile(path string) (winn3Profile, error) {
	raw, err := readWinn3ProfileFile(path)
	if err != nil {
		return winn3Profile{}, err
	}
	if depth := winn3JSONNestingDepth(raw); depth > maxWinn3ProfileJSONDepth {
		return winn3Profile{}, winn3Refuse(
			"JSON nesting depth %d exceeds %d", depth, maxWinn3ProfileJSONDepth)
	}
	if key := winn3DuplicateJSONMember(raw); key != "" {
		return winn3Profile{}, winn3Refuse("duplicate JSON member %q", key)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var profile winn3Profile
	if err := decoder.Decode(&profile); err != nil {
		return winn3Profile{}, fmt.Errorf("decode winn3 profile %q: %w", path, err)
	}
	if decoder.More() {
		return winn3Profile{}, winn3Refuse("document must be a single JSON object")
	}
	if err := profile.validate(); err != nil {
		return winn3Profile{}, err
	}
	return profile, nil
}

// readWinn3ProfileFile reads at most maxWinn3ProfileBytes. os.ReadFile is
// unbounded; a named path that points at a multi-gigabyte file would make
// this process allocate that much before the decoder ran.
func readWinn3ProfileFile(path string) ([]byte, error) {
	// Stat the path before Open so a FIFO, directory, socket or device is
	// refused without blocking. os.Open of a FIFO with no writer hangs until
	// a writer appears; that is a denial of service on a path the operator
	// named, and it used to happen because Open ran first.
	//
	// Stat follows a symlink. A symlink to a regular file still loads; a
	// symlink to a directory does not. The fd Stat below is what we actually
	// read: a TOCTOU swap of the path for a FIFO between these two Stats can
	// still block in Open, and that residual is pinned by the FIFO test
	// covering the Stat-first path, not the race.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read winn3 profile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, winn3Refuse("document is not a regular file")
	}
	if info.Size() > maxWinn3ProfileBytes {
		return nil, winn3Refuse(
			"document exceeds %d bytes", maxWinn3ProfileBytes)
	}
	file, err := os.Open(path) //nolint:gosec // the operator names this path
	if err != nil {
		return nil, fmt.Errorf("read winn3 profile: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read winn3 profile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, winn3Refuse("document is not a regular file")
	}
	if info.Size() > maxWinn3ProfileBytes {
		return nil, winn3Refuse(
			"document exceeds %d bytes", maxWinn3ProfileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxWinn3ProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read winn3 profile: %w", err)
	}
	if len(raw) > maxWinn3ProfileBytes {
		return nil, winn3Refuse(
			"document exceeds %d bytes", maxWinn3ProfileBytes)
	}
	return raw, nil
}

// winn3JSONNestingDepth is the maximum unescaped object/array nesting in raw.
// It is not a JSON validator; encoding/json is. It exists so a hostile
// document cannot make Decode recurse until the stack overflows.
func winn3JSONNestingDepth(raw []byte) int {
	depth, maxDepth := 0, 0
	inString := false
	escaped := false
	for _, b := range raw {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}

// winn3DuplicateJSONMember returns the first object member name that appears
// twice at the same nesting level, or "" if the document has no duplicate
// members. encoding/json last-wins on duplicates, which is how a document
// that states the socket rule twice can silently keep the last value; the
// status parser in this package already refuses that, and the profile must
// too. Malformed JSON returns "" so Decode reports the syntax error.
func winn3DuplicateJSONMember(raw []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	key, err := winn3ScanDuplicateJSONMember(decoder)
	if err != nil {
		return ""
	}
	return key
}

func winn3ScanDuplicateJSONMember(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return "", nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return "", err
			}
			key, ok := keyToken.(string)
			if !ok {
				return "", errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return key, nil
			}
			seen[key] = struct{}{}
			dup, err := winn3ScanDuplicateJSONMember(decoder)
			if err != nil || dup != "" {
				return dup, err
			}
		}
		_, err := decoder.Token()
		return "", err
	case '[':
		for decoder.More() {
			dup, err := winn3ScanDuplicateJSONMember(decoder)
			if err != nil || dup != "" {
				return dup, err
			}
		}
		_, err := decoder.Token()
		return "", err
	default:
		return "", fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

// classes resolves Plan into carrier classes.
func (p winn3Profile) classes() ([]carrier.Class, error) {
	out := make([]carrier.Class, 0, len(p.Plan))
	for i, name := range p.Plan {
		class, err := winn3ClassNamed(name)
		if err != nil {
			return nil, winn3Refuse("plan entry %d: %v", i, err)
		}
		out = append(out, class)
	}
	return out, nil
}

// winn3ClassNamed maps a profile string onto a carrier class.
//
// carrier.Class.String() is the authority for the spellings, and this is its
// inverse. There is no default: an unrecognised class must not silently select
// an overhead, because selecting the wrong one produces fragmentation rather
// than an error.
func winn3ClassNamed(name string) (carrier.Class, error) {
	switch strings.TrimSpace(name) {
	case carrier.ClassUDP.String():
		return carrier.ClassUDP, nil
	case carrier.ClassTCP.String():
		return carrier.ClassTCP, nil
	case carrier.ClassTLS.String():
		return carrier.ClassTLS, nil
	default:
		return carrier.ClassUnknown, fmt.Errorf(
			"unknown carrier class %q; use %s, %s or %s",
			name, carrier.ClassUDP, carrier.ClassTCP, carrier.ClassTLS,
		)
	}
}

// validate refuses every configuration that would otherwise fail later, or
// worse, not fail at all.
//
// decomposition that hides which one fired.
//
//nolint:gocyclo // a flat list of independent refusals reads better than a
func (p winn3Profile) validate() error {
	if p.Version != winn3ProfileVersion {
		return winn3Refuse("version is %q, this build speaks %q",
			p.Version, winn3ProfileVersion)
	}
	if p.Role != winn3RoleClient && p.Role != winn3RoleGateway {
		return winn3Refuse("role is %q; use %q or %q",
			p.Role, winn3RoleClient, winn3RoleGateway)
	}

	// The socket rule. This is the one refusal in this file that is about
	// safety rather than about correctness, so it is stated first among the
	// substantive ones and it is unconditional.
	if !p.AllowOwnSocket {
		return winn3Refuse(
			"allow_own_socket is false: this mode opens the outer socket " +
				"itself and has no descriptor hand-off, so a host that has not " +
				"installed a route exclusion must not start it")
	}
	if strings.TrimSpace(p.OuterSocketExclusion) == "" {
		return winn3Refuse(
			"allow_own_socket is true but outer_socket_exclusion is empty: " +
				"name the exclusion that keeps the engine's own socket out of " +
				"the tunnel it carries")
	}

	if len(p.Plan) == 0 {
		return winn3Refuse(
			"plan is empty: name every carrier class this session may " +
				"escalate to, because the message floor is computed over it")
	}
	if len(p.Plan) > maxWinn3PlanEntries {
		return winn3Refuse(
			"plan has %d entries; this build knows %d carrier classes",
			len(p.Plan), maxWinn3PlanEntries)
	}
	classes, err := p.classes()
	if err != nil {
		return err
	}
	seen := make(map[carrier.Class]bool, len(classes))
	for _, class := range classes {
		if seen[class] {
			return winn3Refuse("plan names %s twice", class)
		}
		seen[class] = true
	}
	if p.PathMTU < 0 {
		return winn3Refuse("path_mtu %d is negative", p.PathMTU)
	}
	if p.PathMTU > maxWinn3PathMTU {
		return winn3Refuse(
			"path_mtu %d exceeds %d, the largest IP datagram",
			p.PathMTU, maxWinn3PathMTU)
	}

	dialled, err := winn3ClassNamed(p.Carrier.Class)
	if err != nil {
		return winn3Refuse("carrier.class: %v", err)
	}
	planned := false
	for _, c := range classes {
		if c == dialled {
			planned = true
			break
		}
	}
	if !planned {
		return winn3Refuse(
			"carrier.class %s is not named in the plan %v: the floor was not "+
				"computed over it", dialled, p.Plan)
	}
	if err := winn3ValidateEndpoint(p.Carrier.Endpoint); err != nil {
		return winn3Refuse("carrier.endpoint: %v", err)
	}
	if err := p.Carrier.validateTLS(dialled); err != nil {
		return err
	}

	if _, err := p.Inner.assignmentAddrs(); err != nil {
		return err
	}

	if strings.TrimSpace(p.GatewayID) == "" {
		return winn3Refuse(
			"gateway_id is empty: without it an initiation captured at one " +
				"gateway replays at another that shares the admission key")
	}
	if strings.TrimSpace(p.Keys.StaticPath) == "" {
		return winn3Refuse("keys.static_path is empty")
	}
	if strings.TrimSpace(p.Keys.AdmissionPath) == "" {
		return winn3Refuse("keys.admission_path is empty")
	}
	switch p.Role {
	case winn3RoleClient:
		if strings.TrimSpace(p.Keys.GatewayStaticPath) == "" {
			return winn3Refuse(
				"keys.gateway_static_path is empty: a client authenticates " +
					"the gateway by its static key and there is no anonymous mode")
		}
	case winn3RoleGateway:
		if strings.TrimSpace(p.Keys.GatewayStaticPath) != "" {
			return winn3Refuse(
				"keys.gateway_static_path is set on a gateway; it is the " +
					"client's field")
		}
	}

	switch p.Device.Kind {
	case winn3DeviceLoopbackUDP:
		if p.Device.HostPort <= 0 || p.Device.HostPort > 65535 {
			return winn3Refuse(
				"device.host_port %d is not a usable port; the host binds its "+
					"loopback seam before starting this process and names the "+
					"port here", p.Device.HostPort)
		}
		if strings.TrimSpace(p.Device.Name) != "" {
			return winn3Refuse(
				"device.name applies to %s only", winn3DeviceTunFD)
		}
	case winn3DeviceTunFD:
		if strings.TrimSpace(p.Device.Name) == "" {
			return winn3Refuse(
				"device.name is empty: the interface name is how the MTU the " +
					"host configured is read back and proven, rather than trusted")
		}
		if p.Device.HostPort != 0 {
			return winn3Refuse(
				"device.host_port applies to %s only", winn3DeviceLoopbackUDP)
		}
	default:
		return winn3Refuse("device.kind is %q; use %q or %q",
			p.Device.Kind, winn3DeviceLoopbackUDP, winn3DeviceTunFD)
	}
	return nil
}

// winn3ValidateEndpoint refuses anything that is not a unicast IP literal with a
// nonzero port.
//
// A hostname here would be resolved by this process, which is a DNS lookup on
// the censored path for a tunnel whose whole staged posture exists so that no
// resolver is touched until the datapath is proven. Unspecified, multicast and
// limited-broadcast literals parse as addresses but cannot be a gateway; they
// are refused rather than dialled.
func winn3ValidateEndpoint(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return errors.New("empty")
	}
	parsed, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf(
			"%q is not an IP literal with a port (a hostname would be a DNS "+
				"lookup on the censored path): %w", endpoint, err)
	}
	if parsed.Port() == 0 {
		return fmt.Errorf("%q has port 0", endpoint)
	}
	ip := parsed.Addr()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || winn3LimitedBroadcast(ip) {
		return fmt.Errorf("%q is not a unicast IP literal", endpoint)
	}
	return nil
}

// winn3LimitedBroadcast is 255.255.255.255. netip.Addr has no IsBroadcast;
// IsMulticast is false for this address, so the unicast check above would
// otherwise accept a destination that cannot be a gateway.
func winn3LimitedBroadcast(ip netip.Addr) bool {
	return ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}
}

// assignmentAddrs parses the inner assignment.
func (s winn3InnerSpec) assignmentAddrs() (winn3Assignment, error) {
	var out winn3Assignment
	parse := func(field, value string, want4 bool) (netip.Addr, error) {
		if strings.TrimSpace(value) == "" {
			return netip.Addr{}, nil
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Addr{}, winn3Refuse("inner.%s: %v", field, err)
		}
		if addr.Zone() != "" {
			return netip.Addr{}, winn3Refuse(
				"inner.%s carries a zone; the inner address space has no "+
					"link-local scope", field)
		}
		if want4 != addr.Is4() {
			return netip.Addr{}, winn3Refuse(
				"inner.%s is %q, which is not the expected family", field, value)
		}
		return addr, nil
	}
	var err error
	if out.V4, err = parse("v4", s.V4, true); err != nil {
		return winn3Assignment{}, err
	}
	if out.V6, err = parse("v6", s.V6, false); err != nil {
		return winn3Assignment{}, err
	}
	if out.RouterV4, err = parse("router_v4", s.RouterV4, true); err != nil {
		return winn3Assignment{}, err
	}
	if out.RouterV6, err = parse("router_v6", s.RouterV6, false); err != nil {
		return winn3Assignment{}, err
	}
	if !out.V4.IsValid() && !out.V6.IsValid() {
		return winn3Assignment{}, winn3Refuse(
			"inner carries neither an IPv4 nor an IPv6 address")
	}
	return out, nil
}

// winn3Assignment is the parsed inner assignment, kept separate from
// tun.Assignment so that this file stays a document parser.
type winn3Assignment struct {
	V4       netip.Addr
	V6       netip.Addr
	RouterV4 netip.Addr
	RouterV6 netip.Addr
}

// describeForLog renders the profile with no path and no address in it.
//
// The profile names every private file this device holds and the gateway it
// talks to. Neither belongs in a log that a support ticket may carry out of the
// country. Counts, modes and class names do.
func (p winn3Profile) describeForLog() string {
	var b strings.Builder
	b.WriteString("winn3 profile version=")
	b.WriteString(p.Version)
	b.WriteString(" role=")
	b.WriteString(p.Role)
	b.WriteString(" carrier=")
	b.WriteString(p.Carrier.Class)
	b.WriteString(" plan=")
	b.WriteString(strings.Join(p.Plan, "+"))
	fmt.Fprintf(&b, " path_mtu=%d device=%s inner_v4=%t inner_v6=%t",
		p.PathMTU, p.Device.Kind, strings.TrimSpace(p.Inner.V4) != "",
		strings.TrimSpace(p.Inner.V6) != "")
	fmt.Fprintf(&b, " allow_own_socket=%t exclusion_declared=%t fast_pq=%t",
		p.AllowOwnSocket,
		strings.TrimSpace(p.OuterSocketExclusion) != "", p.FastPQ)
	if p.Carrier.Class == carrier.ClassTLS.String() {
		fmt.Fprintf(&b, " trust=%s ech_list=%t client_cert=%t",
			strings.TrimSpace(p.Carrier.TrustAnchor),
			strings.TrimSpace(p.Carrier.ECHConfigListPath) != "",
			strings.TrimSpace(p.Carrier.ClientCertPath) != "")
	}
	return b.String()
}

// validateTLS refuses a class=tls profile that is missing the material
// internal/tlsconfig needs, and refuses that material on any other class.
//
// The previous shape accepted class=tls at load and refused it only at dial,
// so an operator could deploy a document that looked complete and discover
// the hole when the engine started. Files named here are not opened; that
// happens at dial, the same way keys.static_path is checked for emptiness
// here and read later.
func (c winn3CarrierSpec) validateTLS(dialled carrier.Class) error {
	if name := c.firstTLSFieldSet(); name != "" && dialled != carrier.ClassTLS {
		return winn3Refuse(
			"carrier.%s is set but carrier.class is %s: TLS material applies "+
				"to class tls only", name, dialled)
	}
	if dialled != carrier.ClassTLS {
		return nil
	}

	anchor := strings.TrimSpace(c.TrustAnchor)
	if anchor == "" {
		return winn3Refuse(
			"carrier.class tls requires trust_anchor: use %s or %s; an "+
				"absent field has not stated what the client verifies the "+
				"server certificate against",
			tlsconfig.TrustPrivateCA, tlsconfig.TrustWebPKI)
	}
	if strings.TrimSpace(c.ServerName) == "" {
		return winn3Refuse(
			"carrier.class tls requires server_name: it is the inner " +
				"ClientHello name, under ECH")
	}
	if strings.TrimSpace(c.Suite) == "" {
		return winn3Refuse(
			"carrier.class tls requires suite: tlsconfig.ParseSuite is the " +
				"authority on the list")
	}
	suite, err := tlsconfig.ParseSuite(c.Suite)
	if err != nil {
		return winn3Refuse("carrier.suite: %v", err)
	}
	if strings.TrimSpace(c.ECHConfigListPath) == "" {
		return winn3Refuse(
			"carrier.class tls requires ech_config_list_path: without it " +
				"the ClientHello is a single-probe fingerprint")
	}

	switch tlsconfig.TrustAnchor(anchor) {
	case tlsconfig.TrustPrivateCA:
		if strings.TrimSpace(c.RootCAPath) == "" {
			return winn3Refuse(
				"carrier.class tls with trust_anchor %s requires root_ca_path",
				tlsconfig.TrustPrivateCA)
		}
		if strings.TrimSpace(c.ClientCertPath) == "" {
			return winn3Refuse(
				"carrier.class tls with trust_anchor %s requires client_cert_path",
				tlsconfig.TrustPrivateCA)
		}
		if strings.TrimSpace(c.ClientKeyPath) == "" {
			return winn3Refuse(
				"carrier.class tls with trust_anchor %s requires client_key_path",
				tlsconfig.TrustPrivateCA)
		}
	case tlsconfig.TrustWebPKI:
		if strings.TrimSpace(c.RootCAPath) != "" {
			return fmt.Errorf("%w: %w: carrier.root_ca_path is set",
				errWinn3Profile, tlsconfig.ErrTrustRootCAConflict)
		}
		if strings.TrimSpace(c.ClientCertPath) != "" ||
			strings.TrimSpace(c.ClientKeyPath) != "" {
			return fmt.Errorf("%w: %w: carrier.client_cert_path / "+
				"carrier.client_key_path are set",
				errWinn3Profile, tlsconfig.ErrTrustWebPKIWithClientCertificate)
		}
		// ClientAnonymousTrusted is the authority on the webpki shape: a
		// fronting DOMAIN, not an address. Calling it here refuses an IP
		// server_name at load rather than at dial. It opens no files.
		if _, err := tlsconfig.ClientAnonymousTrusted(
			tlsconfig.ClientTrust{Anchor: tlsconfig.TrustWebPKI},
			c.ServerName, suite, c.tlsALPN(),
		); err != nil {
			return fmt.Errorf("%w: %w", errWinn3Profile, err)
		}
	default:
		return fmt.Errorf("%w: %w (got %q)",
			errWinn3Profile, tlsconfig.ErrTrustAnchorUnknown, anchor)
	}
	return nil
}

func (c winn3CarrierSpec) firstTLSFieldSet() string {
	fields := []struct {
		name  string
		value string
	}{
		{"trust_anchor", c.TrustAnchor},
		{"root_ca_path", c.RootCAPath},
		{"ech_config_list_path", c.ECHConfigListPath},
		{"client_cert_path", c.ClientCertPath},
		{"client_key_path", c.ClientKeyPath},
		{"server_name", c.ServerName},
		{"suite", c.Suite},
		{"alpn", c.ALPN},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.value) != "" {
			return field.name
		}
	}
	return ""
}

func (c winn3CarrierSpec) tlsALPN() string {
	if name := strings.TrimSpace(c.ALPN); name != "" {
		return name
	}
	return winn3TLSDefaultALPN
}
