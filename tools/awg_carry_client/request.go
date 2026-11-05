package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The CarryClientProcess contract (wins_node_dataplane_probe.py, --carry):
// one JSON object per line on stdin, one JSON object per line on stdout. The
// request is probe_carry's request plus "id", "slug" and "transport"; the
// reply echoes those three and carries "dns_reply_hex". A reply without a
// string "dns_reply_hex", or with any of the three echoes out of step, is no
// verdict: the parent kills this process and starts it again after a backoff.
// That is the fail-closed path a refused request takes on purpose.

const (
	requestVersion    = 1
	minTimeoutSeconds = 1
	maxTimeoutSeconds = 300
	minDNSQuery       = 12
	maxDNSQuery       = 512
	maxSlugLength     = 128
	maxEndpointHost   = 253
	// Resource budget for the served junk parameters. The engine builds all Jc
	// junk datagrams of up to Jmax bytes at once before every handshake
	// initiation (device.JunkPackets). No UDP datagram carries more than 65527
	// payload bytes on any IP family (65535 less the 8-byte UDP header), and 128
	// is sixteen times the largest Jc the data-plane installer draws (4 to 8),
	// so one attempt holds at most 8 MiB.
	maxJunkCount = 128
	maxJunkSize  = 65527
)

var (
	slugPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.?$`)
)

// Transports the parent may name; the request's transport must equal the
// --transport this process was started for. Stealth flavours reach this
// process as a loopback UDP endpoint through the parent's relay.
var transports = map[string]bool{"udp": true, "stealth": true, "stealth_tls": true}

// baseProfileKeys are the AmneziaWG parameters every served profile carries
// (the hub's DEFAULT_OBFUSCATION contract: parse_obfuscation refuses a
// registration without any of them). A request missing one is refused rather
// than probed with a default the node does not share: a substituted
// parameter is not a weaker tunnel, it is a tunnel that cannot handshake,
// and the verdict would then be about this process, not the node.
var baseProfileKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"}

// profileKeys maps a served-profile key to its amneziawg-go v3 UAPI key and
// the value shape accepted for it. Keys are matched case-insensitively (the
// hub serves "Jc", awg.conf spells "Jc", UAPI spells "jc"). Anything else is
// refused: an unknown parameter cannot be applied, so the probe would not run
// the served profile.
//
//	uint:  a non-negative integer that fits uint32
//	pad:   a non-negative integer that fits uint16 (S1 to S4 are uint16 in v3)
//	range: an integer or "<lo>-<hi>" string (H1 to H4 accept ranges in v3,
//	       as amneziawg-tools v3.0.20260730 reads them back)
//	chain: a non-empty string (I1 to I5 special junk packet chains)
//	bool:  true or false
//	hex:   a 64-hex-digit string (header_protection_key)
type profileKey struct {
	uapi  string
	shape string
}

var profileKeys = map[string]profileKey{
	"jc":   {"jc", "uint"},
	"jmin": {"jmin", "uint"},
	"jmax": {"jmax", "uint"},
	"s1":   {"s1", "pad"},
	"s2":   {"s2", "pad"},
	"s3":   {"s3", "pad"},
	"s4":   {"s4", "pad"},
	"h1":   {"h1", "range"},
	"h2":   {"h2", "range"},
	"h3":   {"h3", "range"},
	"h4":   {"h4", "range"},
	"i1":   {"i1", "chain"},
	"i2":   {"i2", "chain"},
	"i3":   {"i3", "chain"},
	"i4":   {"i4", "chain"},
	"i5":   {"i5", "chain"},
	// Newer v3 device parameters, by their UAPI names, in case a served
	// profile ever carries them. Passed through only when well formed.
	"header_protection_key":    {"header_protection_key", "hex"},
	"content_padding_addition": {"content_padding_addition", "range"},
	"rekey_after_time":         {"rekey_after_time", "range"},
	"rekey_timeout":            {"rekey_timeout", "range"},
	"reject_after_time":        {"reject_after_time", "range"},
	"keepalive_timeout":        {"keepalive_timeout", "range"},
	"max_handshake_attempts":   {"max_handshake_attempts", "range"},
	"random_trailers":          {"random_trailers", "bool"},
	"disable_cookies":          {"disable_cookies", "bool"},
}

// rawRequest is the wire shape. Numbers stay raw so an unquoted integer is
// told from a float or a quoted string, and the key material stays a string
// that only ever goes into the device configuration.
type rawRequest struct {
	Version        json.RawMessage `json:"version"`
	ID             json.RawMessage `json:"id"`
	Slug           string          `json:"slug"`
	Transport      string          `json:"transport"`
	PrivateKey     string          `json:"private_key"`
	PeerPublicKey  string          `json:"peer_public_key"`
	LocalAddress   string          `json:"local_address"`
	Endpoint       string          `json:"endpoint"`
	Obfuscation    json.RawMessage `json:"obfuscation"`
	DNSServer      string          `json:"dns_server"`
	DNSPort        json.RawMessage `json:"dns_port"`
	DNSQueryHex    string          `json:"dns_query_hex"`
	TimeoutSeconds json.RawMessage `json:"timeout_seconds"`
}

// Request is one validated probe. The two keys are kept in their UAPI hex
// form and never formatted into any message.
type Request struct {
	ID            int64
	Slug          string
	Transport     string
	privateKeyHex string
	peerPublicHex string
	LocalAddress  netip.Addr
	EndpointHost  string
	EndpointPort  uint16
	// UAPI "key=value" lines for the served obfuscation profile, in a fixed
	// order so the configuration is deterministic for a given profile.
	ProfileLines []string
	DNSServer    netip.Addr
	DNSPort      uint16
	DNSQuery     []byte
	Timeout      time.Duration
}

// Echo is what a reply must carry back whatever else it says. Only the parts
// of a refused request that could be read are echoed.
type Echo struct {
	ID        *int64
	Slug      string
	Transport string
}

// parseRequest validates one request line against the contract. On refusal
// the Echo carries whatever identification could be read, so the reply can
// still name the request it refuses.
func parseRequest(line []byte, transport string) (*Request, Echo, error) {
	var echo Echo
	// json.Unmarshal refuses anything after the one value, a bare "]" or "}"
	// included (json.Decoder.More reports those as no further value).
	var raw rawRequest
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, echo, errors.New("request is not a single JSON object")
	}
	// Identification first, so a refusal can be attributed by the parent.
	if id, err := integer(raw.ID, 0, math.MaxInt64); err == nil {
		echo.ID = &id
	}
	if slugPattern.MatchString(raw.Slug) {
		echo.Slug = raw.Slug
	}
	if transports[raw.Transport] {
		echo.Transport = raw.Transport
	}
	req := &Request{}
	version, err := integer(raw.Version, requestVersion, requestVersion)
	if err != nil || version != requestVersion {
		return nil, echo, fmt.Errorf("unsupported request version (want %d)", requestVersion)
	}
	if echo.ID == nil {
		return nil, echo, errors.New("id must be a non-negative integer")
	}
	req.ID = *echo.ID
	if echo.Slug == "" {
		return nil, echo, errors.New("slug is missing or malformed")
	}
	req.Slug = raw.Slug
	if echo.Transport == "" {
		return nil, echo, errors.New("transport must be udp, stealth or stealth_tls")
	}
	if raw.Transport != transport {
		return nil, echo, fmt.Errorf("transport %q is not this client's --transport %q", raw.Transport, transport)
	}
	req.Transport = raw.Transport
	if req.privateKeyHex, err = keyHex(raw.PrivateKey); err != nil {
		return nil, echo, fmt.Errorf("private_key: %w", err)
	}
	if req.peerPublicHex, err = keyHex(raw.PeerPublicKey); err != nil {
		return nil, echo, fmt.Errorf("peer_public_key: %w", err)
	}
	prefix, err := netip.ParsePrefix(raw.LocalAddress)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.Addr().IsUnspecified() {
		return nil, echo, errors.New("local_address must be one IPv4 host address with /32")
	}
	req.LocalAddress = prefix.Addr()
	if req.EndpointHost, req.EndpointPort, err = parseEndpoint(raw.Endpoint); err != nil {
		return nil, echo, fmt.Errorf("endpoint: %w", err)
	}
	if req.ProfileLines, err = profileLines(raw.Obfuscation); err != nil {
		return nil, echo, fmt.Errorf("obfuscation: %w", err)
	}
	server, err := netip.ParseAddr(raw.DNSServer)
	if err != nil || !server.Is4() || server.IsUnspecified() {
		return nil, echo, errors.New("dns_server must be an IPv4 address")
	}
	req.DNSServer = server
	port, err := integer(raw.DNSPort, 1, 65535)
	if err != nil {
		return nil, echo, errors.New("dns_port must be 1 to 65535")
	}
	req.DNSPort = uint16(port)
	if req.DNSQuery, err = dnsQuery(raw.DNSQueryHex); err != nil {
		return nil, echo, fmt.Errorf("dns_query_hex: %w", err)
	}
	seconds, err := integer(raw.TimeoutSeconds, minTimeoutSeconds, maxTimeoutSeconds)
	if err != nil {
		return nil, echo, fmt.Errorf("timeout_seconds must be %d to %d", minTimeoutSeconds, maxTimeoutSeconds)
	}
	req.Timeout = time.Duration(seconds) * time.Second
	return req, echo, nil
}

// integer accepts only an unquoted, integral JSON number inside [lo, hi]:
// a quoted "7", a float, true or null fails the integer parse of the raw
// text and is refused.
func integer(value json.RawMessage, lo, hi int64) (int64, error) {
	text := strings.TrimSpace(string(value))
	if text == "" || text == "null" {
		return 0, errors.New("missing")
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, errors.New("not an integer")
	}
	if n < lo || n > hi {
		return 0, errors.New("out of range")
	}
	return n, nil
}

// keyHex turns the base64 key the hub stores into the hex form UAPI wants.
// It is the only place a key is decoded, and the result is never formatted
// into any message.
func keyHex(value string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", errors.New("not base64")
	}
	if len(raw) != 32 {
		return "", errors.New("not a 32-byte key")
	}
	return hex.EncodeToString(raw), nil
}

func parseEndpoint(value string) (string, uint16, error) {
	host, portText, ok := strings.Cut(value, ":")
	if strings.HasPrefix(value, "[") {
		closing := strings.LastIndex(value, "]")
		if closing < 0 || closing+1 >= len(value) || value[closing+1] != ':' {
			return "", 0, errors.New("malformed bracketed address")
		}
		host, portText, ok = value[1:closing], value[closing+2:], true
	} else if strings.Count(value, ":") > 1 {
		return "", 0, errors.New("an IPv6 endpoint must be bracketed")
	}
	if !ok || host == "" {
		return "", 0, errors.New("must be host:port")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("port must be 1 to 65535")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsUnspecified() || addr.IsMulticast() {
			return "", 0, errors.New("address is not a unicast host")
		}
		return addr.String(), uint16(port), nil
	}
	if len(host) > maxEndpointHost || !hostPattern.MatchString(host) {
		return "", 0, errors.New("host is neither an IP address nor a host name")
	}
	return host, uint16(port), nil
}

// profileLines renders the served obfuscation profile as UAPI lines. Every
// base parameter must be present; every present parameter must be known and
// well formed for its shape.
func profileLines(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var profile map[string]json.RawMessage
	if err := decoder.Decode(&profile); err != nil || profile == nil {
		return nil, errors.New("not a JSON object")
	}
	values := map[string]string{}
	for key, value := range profile {
		spec, known := profileKeys[strings.ToLower(key)]
		if !known {
			return nil, fmt.Errorf("unknown parameter %q", key)
		}
		if _, dup := values[spec.uapi]; dup {
			return nil, fmt.Errorf("parameter %q given twice", spec.uapi)
		}
		rendered, err := renderValue(spec.shape, value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		values[spec.uapi] = rendered
	}
	for _, key := range baseProfileKeys {
		if _, ok := values[strings.ToLower(key)]; !ok {
			return nil, fmt.Errorf("missing parameter %s", key)
		}
	}
	// The engine draws a junk size as Jmin + rand(Jmax - Jmin) in uint32: a
	// reversed pair wraps to a multi-gigabyte allocation. The data-plane
	// installer refuses it too.
	jmin, _ := strconv.ParseUint(values["jmin"], 10, 32)
	jmax, _ := strconv.ParseUint(values["jmax"], 10, 32)
	if jmin > jmax {
		return nil, errors.New("Jmin must not exceed Jmax")
	}
	jc, _ := strconv.ParseUint(values["jc"], 10, 32)
	if jc > maxJunkCount || jmax > maxJunkSize {
		return nil, fmt.Errorf("Jc must not exceed %d and Jmax must not exceed %d", maxJunkCount, maxJunkSize)
	}
	lines := make([]string, 0, len(values))
	for _, key := range profileOrder {
		if value, ok := values[key]; ok {
			lines = append(lines, key+"="+value)
		}
	}
	return lines, nil
}

// profileOrder fixes the UAPI line order: base parameters, then special
// junk chains, then the newer device parameters.
var profileOrder = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
	"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
	"reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies",
}

var rangePattern = regexp.MustCompile(`^[0-9]{1,10}(-[0-9]{1,10})?$`)

func renderValue(shape string, raw json.RawMessage) (string, error) {
	switch shape {
	case "uint", "pad":
		limit := int64(math.MaxUint32)
		if shape == "pad" {
			limit = math.MaxUint16
		}
		n, err := integer(raw, 0, limit)
		if err != nil {
			return "", fmt.Errorf("must be an integer 0 to %d", limit)
		}
		return strconv.FormatInt(n, 10), nil
	case "range":
		if n, err := integer(raw, 0, math.MaxUint32); err == nil {
			return strconv.FormatInt(n, 10), nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || !rangePattern.MatchString(s) {
			return "", errors.New("must be an integer or a \"<lo>-<hi>\" range of integers")
		}
		lo, hi, _ := strings.Cut(s, "-")
		a, errA := strconv.ParseUint(lo, 10, 32)
		b, errB := strconv.ParseUint(hi, 10, 32)
		if hi == "" {
			b, errB = a, nil
		}
		if errA != nil || errB != nil || b < a {
			return "", errors.New("range bounds must be uint32 with lo <= hi")
		}
		return s, nil
	case "chain":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" || len(s) > 4096 || strings.ContainsAny(s, "\n\r\x00") {
			return "", errors.New("must be a non-empty single-line string")
		}
		return s, nil
	case "bool":
		// json.Unmarshal of null into a bool succeeds and leaves false.
		text := strings.TrimSpace(string(raw))
		if text != "true" && text != "false" {
			return "", errors.New("must be true or false")
		}
		return text, nil
	case "hex":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || len(s) != 64 {
			return "", errors.New("must be 64 hex digits")
		}
		if _, err := hex.DecodeString(s); err != nil {
			return "", errors.New("must be 64 hex digits")
		}
		return strings.ToLower(s), nil
	}
	return "", errors.New("unknown shape")
}

// dnsQuery accepts one plain query: a header with QR clear, exactly one
// question and no records, then that question and nothing after it: an
// uncompressed name of labels of at most 63 bytes (255 in all), a type and
// a class.
func dnsQuery(value string) ([]byte, error) {
	query, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("not hex")
	}
	if len(query) < minDNSQuery+5 || len(query) > maxDNSQuery {
		return nil, fmt.Errorf("must be %d to %d bytes", minDNSQuery+5, maxDNSQuery)
	}
	flags := uint16(query[2])<<8 | uint16(query[3])
	qd := uint16(query[4])<<8 | uint16(query[5])
	rest := uint16(query[6])<<8 | uint16(query[7]) | uint16(query[8])<<8 | uint16(query[9]) | uint16(query[10])<<8 | uint16(query[11])
	if flags&0x8000 != 0 || qd != 1 || rest != 0 {
		return nil, errors.New("must be a plain query with one question and no records")
	}
	end := 12
	for {
		if end >= len(query) {
			return nil, errors.New("question name is truncated")
		}
		size := int(query[end])
		end++
		if size == 0 {
			break
		}
		if size > 63 || size > len(query)-end {
			return nil, errors.New("question name is malformed")
		}
		end += size
	}
	if end-12 > 255 || end+4 != len(query) {
		return nil, errors.New("must contain exactly one complete question")
	}
	return query, nil
}
