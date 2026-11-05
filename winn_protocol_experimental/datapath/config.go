package datapath

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"winsvpn.local/winnprotocol/internal/carrier"
	"winsvpn.local/winnprotocol/internal/connectivity"
)

// ContractVersion identifies the shape of Config, StatusJSON and the C ABI in
// cdatapath. A host that caches a generated header can compare it against
// WinnTunnelContractVersion. It is deliberately distinct from
// connectivity.Version ("winn/3") and from clientbinding.BindingVersion.
const ContractVersion = "winn-datapath/1"

// ProtocolVersion is the v3 connectivity contract version this datapath
// belongs to. It is read from internal/connectivity so the two can never drift.
const ProtocolVersion = connectivity.Version

// MaxDatagramCeiling is the largest datagram any configuration may permit. It
// is internal/carrier's own absolute limit, not a second opinion about MTU.
const MaxDatagramCeiling = carrier.AbsoluteMaxDatagram

// MinDatagram is the smallest AmneziaWG outer datagram worth carrying. A
// WireGuard transport-data message is 32 bytes of header plus a 16-byte
// authentication tag; nothing shorter is a valid frame.
const MinDatagram = 32

// Payload modes. The value names the bytes that cross WriteInbound and
// ReadOutbound, so a host can never be wrong about what it is handing over.
const (
	// PayloadAWGDatagram means the host supplies, and receives, AmneziaWG
	// OUTER datagrams: exactly the bytes its own AWG engine would otherwise
	// have sent to and received from the gateway's UDP endpoint. This is the
	// only implemented mode. It is the same byte stream that
	// internal/carrier.RelayLocalUDP moves today on Linux.
	PayloadAWGDatagram = "awg-datagram"

	// PayloadIPPacket would mean raw IPv4/IPv6 packets straight off the host
	// tun device. It is REFUSED. See ErrPayloadUnimplemented.
	PayloadIPPacket = "ip-packet"
)

// Carrier modes.
const (
	// CarrierDirectAWG sends each datagram to the gateway endpoint over the
	// UDP socket, unmodified. This mirrors internal/directawg, whose package
	// documentation records the deliberate decision that authentication comes
	// from the AWG handshake and that "Winn does not add a second, bespoke UDP
	// authentication protocol". There is no Winn envelope on this carrier.
	//
	// It is defined from connectivity.CarrierDirectAWG rather than repeated as
	// a literal, so a rename in the v3 contract breaks the build here instead
	// of producing two carriers that only look like the same one.
	CarrierDirectAWG = string(connectivity.CarrierDirectAWG)

	// CarrierHTTP3 wraps each datagram in an authenticated Winn envelope and
	// carries it over RFC 9298 CONNECT-UDP inside one QUIC connection. This IS
	// the MASQUE carrier: internal/carrier.H3Dialer performs the CONNECT-UDP
	// exchange through internal/masque, and there is no separate MASQUE dialer
	// in this module. It rides a caller-supplied net.PacketConn.
	CarrierHTTP3 = string(connectivity.CarrierHTTP3)

	// CarrierHTTP2 carries the same envelopes over a single long-lived HTTP/2
	// POST stream. It rides a caller-supplied, connected net.Conn (TCP), not a
	// UDP socket.
	CarrierHTTP2 = string(connectivity.CarrierHTTP2)
)

// suppliedSocketCarriers are the carriers whose dialers in internal/carrier
// have actually been converted to ride a caller-supplied, already-protected
// socket, together with the socket each one needs.
//
// Membership here is a claim about real code: internal/carrier asserts
// PacketSocketDialer on H3Dialer and StreamSocketDialer on H2Dialer at compile
// time, and its supplied_socket_test.go proves each one moves real bytes over a
// supplied socket while its own-socket seam stays untouched. A carrier that has
// not been converted must NOT be added here.
var suppliedSocketCarriers = map[string]carrier.SocketKind{
	CarrierHTTP3: carrier.SocketKindPacket,
	CarrierHTTP2: carrier.SocketKindStream,
}

var (
	// ErrPayloadUnimplemented is returned by Open for payload:"ip-packet".
	//
	// It is not a stub and not a TODO placeholder: this module contains no
	// WireGuard or AmneziaWG implementation. Satisfying "ip-packet" needs all
	// of the following, none of which exist here today:
	//
	//   1. an in-process Noise_IKpsk2 implementation (handshake, transport
	//      keys, nonce and replay windows, rekey timers),
	//   2. the AmneziaWG obfuscation parameters jc/jmin/jmax, s1..s4 and
	//      h1..h4 applied to that wire format — see the "awg set" argument
	//      list in internal/directawg/linux_controller_common.go,
	//   3. a peer/allowed-ips routing table for inbound decapsulated packets.
	//
	// Every platform this datapath targets already has an AWG engine in the
	// host process (libwg-go.a on Apple, the AmneziaWG GoBackend on Android,
	// windows/awg_engine on Windows). Duplicating one inside Winn would add a
	// second, unreviewed cryptographic implementation on the data path. So the
	// boundary is drawn below AWG, not above it.
	ErrPayloadUnimplemented = errors.New(
		"winn datapath payload \"ip-packet\" is not implemented: this module " +
			"has no in-process AmneziaWG encapsulator, so accepting a raw tun " +
			"packet here would forward cleartext to the gateway; supply " +
			"payload \"awg-datagram\" from the host's existing AWG engine",
	)

	// ErrCarrierUnimplemented is returned for a carrier that internal/carrier
	// has no dialer for at all.
	//
	// reality-xhttp, websocket-tls, native-two-hop and privacy-two-hop are
	// named in internal/connectivity's contract but no dialer exists for them
	// in this module, supplied socket or otherwise. This refusal is about a
	// missing implementation, not about socket protection.
	ErrCarrierUnimplemented = errors.New(
		"winn datapath carrier has no dialer in internal/carrier: only " +
			CarrierDirectAWG + ", " + CarrierHTTP3 + " and " + CarrierHTTP2 +
			" are implemented",
	)

	// ErrCarrierNoDialer is returned by Open for a carrier that CAN ride the
	// caller-supplied socket but was not given anything to build.
	//
	// This replaced a broader refusal that said the http2/http3/masque dialers
	// "open their own transport sockets, which cannot be protected on Android".
	// That is no longer true: internal/carrier.H3Dialer and H2Dialer both
	// accept a caller-supplied, already-protected socket and refuse to open one
	// of their own once given it.
	//
	// What remains true is that those carriers need an authenticated
	// configuration this Config does not carry — a URI template or absolute
	// HTTPS URL, a public target, a device identity or anonymous credential
	// source, a TLS suite and a response verifier. None of that belongs in a
	// JSON blob crossing the C ABI, so Open builds only direct-awg and a host
	// that wants a carrier constructs the dialer itself and calls
	// OpenWithCarrier.
	ErrCarrierNoDialer = errors.New(
		"winn datapath was given a carrier that rides the caller-supplied " +
			"socket but no dialer to build it: Open constructs only " +
			CarrierDirectAWG + "; build an internal/carrier dialer and call " +
			"OpenWithCarrier",
	)

	// ErrOwnSocketRefused is returned when no descriptor was supplied and the
	// configuration did not explicitly permit the engine to open one.
	ErrOwnSocketRefused = errors.New(
		"winn datapath was given no UDP descriptor and allow_own_socket is " +
			"false: on Android the socket must be opened by the host and " +
			"passed through VpnService.protect(fd), or the outer traffic " +
			"routes back into the tunnel",
	)
)

// Config is the JSON blob passed to Open. Unknown fields are rejected so a host
// that misspells a key learns immediately instead of silently getting a
// default.
type Config struct {
	// Contract must equal ContractVersion.
	Contract string `json:"contract"`

	// Payload names the bytes crossing WriteInbound/ReadOutbound.
	Payload string `json:"payload"`

	// Carrier names how those bytes reach the gateway.
	Carrier string `json:"carrier"`

	// GatewayEndpoint is an IP literal "host:port". A hostname is refused:
	// resolving one here would leak a DNS lookup outside the tunnel before the
	// protected resolver exists, which is the same rule
	// internal/directawg.UDPDialer enforces.
	//
	// On direct-awg it is the address every datagram is sent to and the only
	// address datagrams are accepted from. On a carrier (OpenWithCarrier) the
	// carrier's own configuration names the proxy and the public target, and
	// the carrier authenticates each envelope end to end; this field is then
	// carried in status for correlation and is not used for addressing.
	GatewayEndpoint string `json:"gateway_endpoint"`

	// MaxDatagram bounds a single datagram in either direction. Zero selects
	// carrier.DefaultMaxDatagram. It may not exceed carrier.AbsoluteMaxDatagram.
	MaxDatagram int `json:"max_datagram,omitempty"`

	// QueueDepth is how many received datagrams may wait for ReadOutbound
	// before the engine starts dropping the oldest. Zero selects
	// DefaultQueueDepth.
	QueueDepth int `json:"queue_depth,omitempty"`

	// SessionID is opaque and appears in StatusJSON for correlation. It is
	// never sent on the wire by this carrier.
	SessionID string `json:"session_id,omitempty"`

	// AllowOwnSocket permits Open to create a UDP socket when no descriptor is
	// supplied. It must stay false on Android.
	AllowOwnSocket bool `json:"allow_own_socket,omitempty"`

	// AWGHeaders is the AmneziaWG classification table from the signed
	// deployment configuration: the h1..h4 header type values and the s1/s2
	// prefix padding sizes. Supplying it lets the engine classify the datagrams
	// it carries by header type, which is what makes the transport-observed
	// status fields meaningful. Omitting it falls back to plain WireGuard's
	// 1..4 with no padding and says so in status.
	//
	// Supply s1, s2, s3 and s4 whenever the deployment sets them. AmneziaWG
	// prepends that many random bytes to a handshake initiation, a handshake
	// response, a cookie reply and a payload-carrying transport message
	// respectively, so a table without them reads padding instead of the header
	// word and that class is never classified. Omitting s1/s2/s3 silently kills
	// the handshake counters; omitting a nonzero s4 silently kills the
	// transport counters, which are the ones a route-promotion gate reads.
	// They are optional only so that configurations written before the fields
	// existed keep parsing as the unpadded profiles they describe.
	//
	// Official AmneziaWG Go v3.1.20260828 prepends s4 random bytes to every
	// transport packet, including keepalives. Classification therefore looks
	// for the transport header word only at offset s4; offset zero remains
	// valid only when s4 itself is zero.
	AWGHeaders *AWGHeaderTypes `json:"awg_header_types,omitempty"`

	// Escalation is the optional carrier-escalation policy: a verdict on
	// whether the configured carrier is carrying anything, and an ordered plan
	// naming which of v3's own carriers to try if it is not.
	//
	// Omitting it selects EscalationOff, which computes nothing and adds
	// nothing to Status, so a configuration written before this field existed
	// produces a byte-for-byte identical status document. See escalation.go for
	// why the default is off and why the verdict reads no packet headers.
	Escalation EscalationConfig `json:"carrier_escalation,omitempty"`
}

// DefaultQueueDepth is deep enough to absorb a burst between host reads and
// shallow enough that a stalled host cannot pin unbounded memory.
const DefaultQueueDepth = 512

// MaxQueueDepth caps QueueDepth. At the 1500-byte absolute datagram limit this
// is a little under 12 MiB of pooled buffers, which is the most a single
// tunnel is allowed to hold.
const MaxQueueDepth = 8192

// ParseConfig decodes and validates a configuration blob.
func ParseConfig(blob []byte) (Config, error) {
	var config Config
	decoder := json.NewDecoder(strings.NewReader(string(blob)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("winn datapath configuration: %w", err)
	}
	if decoder.More() {
		return Config{}, errors.New(
			"winn datapath configuration must be a single JSON object",
		)
	}
	normalized, err := config.normalize()
	if err != nil {
		return Config{}, err
	}
	return normalized, nil
}

func (config Config) normalize() (Config, error) {
	if config.Contract != ContractVersion {
		return Config{}, fmt.Errorf(
			"winn datapath contract must be %q, got %q",
			ContractVersion, config.Contract,
		)
	}
	switch config.Payload {
	case PayloadAWGDatagram:
	case PayloadIPPacket:
		return Config{}, ErrPayloadUnimplemented
	case "":
		return Config{}, errors.New(
			"winn datapath payload is required; it names the bytes crossing " +
				"WriteInbound and ReadOutbound",
		)
	default:
		return Config{}, fmt.Errorf(
			"winn datapath payload %q is unknown", config.Payload,
		)
	}
	switch config.Carrier {
	case CarrierDirectAWG:
	case CarrierHTTP3, CarrierHTTP2:
		// Accepted at the configuration layer: both dialers really do accept a
		// caller-supplied, already-protected socket now. Whether THIS engine
		// can build one is Open's business — see ErrCarrierNoDialer — because
		// normalize is also the validator for OpenWithCarrier, where a dialer
		// is present and the carrier is genuinely available.
	case "":
		return Config{}, errors.New("winn datapath carrier is required")
	case string(connectivity.CarrierRealityXHTTP),
		string(connectivity.CarrierWebSocketTLS),
		string(connectivity.CarrierNativeTwoHop),
		string(connectivity.CarrierPrivacyTwoHop):
		return Config{}, fmt.Errorf("%w (requested %q)",
			ErrCarrierUnimplemented, config.Carrier)
	default:
		return Config{}, fmt.Errorf(
			"winn datapath carrier %q is unknown", config.Carrier,
		)
	}
	if err := validateIPLiteralEndpoint(config.GatewayEndpoint); err != nil {
		return Config{}, fmt.Errorf("winn datapath gateway endpoint: %w", err)
	}
	if config.MaxDatagram == 0 {
		config.MaxDatagram = carrier.DefaultMaxDatagram
	}
	if config.MaxDatagram < MinDatagram ||
		config.MaxDatagram > MaxDatagramCeiling {
		return Config{}, fmt.Errorf(
			"winn datapath max_datagram must be within [%d, %d], got %d",
			MinDatagram, MaxDatagramCeiling, config.MaxDatagram,
		)
	}
	if config.QueueDepth == 0 {
		config.QueueDepth = DefaultQueueDepth
	}
	if config.QueueDepth < 1 || config.QueueDepth > MaxQueueDepth {
		return Config{}, fmt.Errorf(
			"winn datapath queue_depth must be within [1, %d], got %d",
			MaxQueueDepth, config.QueueDepth,
		)
	}
	if len(config.SessionID) > 128 {
		return Config{}, errors.New(
			"winn datapath session_id exceeds 128 bytes",
		)
	}
	if config.AWGHeaders != nil {
		for _, spec := range []AwgHeaderSpec{
			config.AWGHeaders.H1,
			config.AWGHeaders.H2,
			config.AWGHeaders.H3,
			config.AWGHeaders.H4,
		} {
			if spec.Start < awgHeaderMin || uint64(spec.End) > awgHeaderMax || spec.Start > spec.End {
				return Config{}, fmt.Errorf(
					"winn datapath awg_header_types h value %s out of range [%d,%d]",
					spec.String(), awgHeaderMin, awgHeaderMax,
				)
			}
			if spec.Width() > awgHeaderMaxRangeWidth {
				return Config{}, fmt.Errorf(
					"winn datapath awg_header_types h value %s width %d exceeds maximum %d",
					spec.String(), spec.Width(), awgHeaderMaxRangeWidth,
				)
			}
		}
		// overlaps() interval check -- distinct() uses AwgHeaderSpec.Overlaps
		if !config.AWGHeaders.distinct() {
			return Config{}, errors.New(
				"winn datapath awg_header_types h1..h4 must be pairwise " +
					"distinct; equal values make datagram classification " +
					"ambiguous",
			)
		}
		// Checked after max_datagram is resolved, because the rule is about
		// whether the padded header word can fit inside a datagram this engine
		// would accept at all.
		if field, size, ok := config.AWGHeaders.paddingFits(
			config.MaxDatagram,
		); !ok {
			return Config{}, fmt.Errorf(
				"winn datapath awg_header_types %s is %d, which leaves no room "+
					"for the 4-byte header word inside max_datagram %d; that "+
					"message class could never be classified",
				field, size, config.MaxDatagram,
			)
		}
		// Also checked after max_datagram is resolved. A nonzero s4 raises the
		// payload-versus-keepalive threshold, and one that clears the rule
		// above can still leave no room for a payload-carrying transport
		// datagram at all — see transportPayloadFits.
		if !config.AWGHeaders.transportPayloadFits(config.MaxDatagram) {
			return Config{}, fmt.Errorf(
				"winn datapath awg_header_types s4 is %d, which leaves no room "+
					"for a payload-carrying transport datagram inside "+
					"max_datagram %d; tx_transport_payload_datagrams and "+
					"rx_transport_payload_datagrams could never move and "+
					"transport_observed_both_ways could never become true",
				config.AWGHeaders.S4, config.MaxDatagram,
			)
		}
	}
	// Last, because the plan is validated against the carrier and the carrier
	// checks above are what establish that config.Carrier is one this build can
	// actually run. Validating the plan first would report a plan error for a
	// configuration whose real defect is its carrier.
	escalation, err := config.Escalation.normalize(config.Carrier)
	if err != nil {
		return Config{}, err
	}
	config.Escalation = escalation
	return config, nil
}

// headerTypes resolves the classification table and reports whether it came
// from the configuration or from the WireGuard default.
func (config Config) headerTypes() (AWGHeaderTypes, bool) {
	if config.AWGHeaders != nil {
		return *config.AWGHeaders, true
	}
	return wireGuardDefaultHeaderTypes, false
}

// validateIPLiteralEndpoint applies the same rule as
// internal/directawg.validateIPLiteralEndpoint: an IP literal and a nonzero
// port, never a hostname. A hostname here would require a DNS lookup on the
// unprotected path before the tunnel exists.
func validateIPLiteralEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("endpoint is required")
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return fmt.Errorf(
			"endpoint must be an IP literal with a port, not a hostname: %w",
			err,
		)
	}
	if address.Port() == 0 {
		return errors.New("endpoint port must be nonzero")
	}
	ip := address.Addr()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("endpoint address is not a routable unicast literal")
	}
	return nil
}
