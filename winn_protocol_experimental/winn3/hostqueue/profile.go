// SPDX-License-Identifier: MIT
// Derived from cmd/winn-datapath for the isolated direct-host study candidate.
// See docs/evidence/stages345_astra/windows.md for the shared and candidate paths.
package hostqueue

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"winsvpn.local/winnprotocol/internal/securefile"

	"winsvpn.local/winnprotocol/internal/tlsconfig"
	"winsvpn.local/winnprotocol/winn3/carrier"
)

const winn3ProfileVersion = "winn3-host/1"

const maxWinn3ProfileBytes = 64 << 10

const maxWinn3ProfileJSONDepth = 8

const maxWinn3PathMTU = 65535

const maxWinn3PlanEntries = 3

type winn3Profile struct {
	Version string `json:"version"`

	Role string `json:"role"`

	Plan []string `json:"plan"`

	PathMTU int `json:"path_mtu"`

	GatewayID string `json:"gateway_id"`

	Carrier winn3CarrierSpec `json:"carrier"`
	Inner   winn3InnerSpec   `json:"inner"`
	Keys    winn3KeySpec     `json:"keys"`
	Device  winn3DeviceSpec  `json:"device"`

	AllowOwnSocket bool `json:"allow_own_socket"`

	OuterSocketExclusion string `json:"outer_socket_exclusion"`

	FastPQ bool `json:"fast_pq"`
}

type winn3CarrierSpec struct {
	Class string `json:"class"`

	Endpoint string `json:"endpoint"`

	TrustAnchor string `json:"trust_anchor,omitempty"`

	RootCAPath string `json:"root_ca_path,omitempty"`

	ECHConfigListPath string `json:"ech_config_list_path,omitempty"`

	ClientCertPath string `json:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty"`

	ServerName string `json:"server_name,omitempty"`

	Suite string `json:"suite,omitempty"`

	ALPN string `json:"alpn,omitempty"`
}

type winn3InnerSpec struct {
	V4       string `json:"v4"`
	V6       string `json:"v6"`
	RouterV4 string `json:"router_v4"`
	RouterV6 string `json:"router_v6"`
}

type winn3KeySpec struct {
	StaticPath string `json:"static_path"`

	GatewayStaticPath string `json:"gateway_static_path"`

	AdmissionPath string `json:"admission_path"`

	DualAuthEd25519PubPath string `json:"dual_auth_ed25519_pub_path"`
	DualAuthMLDSA65PubPath string `json:"dual_auth_mldsa65_pub_path"`
}

type winn3DeviceSpec struct {
	Kind string `json:"kind"`

	HostPort int `json:"host_port"`

	Name string `json:"name"`
}

const (
	winn3DeviceLoopbackUDP = "loopback-udp"
	winn3DeviceTunFD       = "tun-fd"
	winn3RoleClient        = "client"
	winn3RoleGateway       = "gateway"

	winn3TLSDefaultALPN = "h2"
)

var errWinn3Profile = errors.New("winn3 host profile")

func winn3Refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWinn3Profile, fmt.Sprintf(format, args...))
}

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
	if decoder.Decode(new(any)) != io.EOF {
		return winn3Profile{}, winn3Refuse("document must be a single JSON object")
	}
	if err := profile.validate(); err != nil {
		return winn3Profile{}, err
	}
	return profile, nil
}

func readWinn3ProfileFile(path string) ([]byte, error) {
	return securefile.ReadPrivateLimited(path, maxWinn3ProfileBytes)
}

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
			if _, exists := seen[strings.ToLower(key)]; exists {
				return key, nil
			}
			seen[strings.ToLower(key)] = struct{}{}
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

func (p winn3Profile) validate() error {
	if p.Version != winn3ProfileVersion {
		return winn3Refuse("version is %q, this build speaks %q",
			p.Version, winn3ProfileVersion)
	}
	if p.Role != winn3RoleClient && p.Role != winn3RoleGateway {
		return winn3Refuse("role is %q; use %q or %q",
			p.Role, winn3RoleClient, winn3RoleGateway)
	}

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

	if p.Device.Kind != "wintun-direct" || p.Device.HostPort != 0 || p.Device.Name != "winsvpn3" {
		return winn3Refuse("direct candidate requires device.kind=wintun-direct, name=winsvpn3, and no host_port")
	}
	if p.Role != winn3RoleClient || p.FastPQ {
		return winn3Refuse("direct candidate requires client role and strict PQ")
	}
	if strings.TrimSpace(p.Keys.DualAuthEd25519PubPath) == "" || strings.TrimSpace(p.Keys.DualAuthMLDSA65PubPath) == "" {
		return winn3Refuse("direct candidate requires both gateway dual-auth public key paths")
	}

	return nil
}

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

func winn3LimitedBroadcast(ip netip.Addr) bool {
	return ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}
}

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

type winn3Assignment struct {
	V4       netip.Addr
	V6       netip.Addr
	RouterV4 netip.Addr
	RouterV6 netip.Addr
}

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
