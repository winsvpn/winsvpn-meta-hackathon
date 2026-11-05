// Package clientbinding is the only supported cross-platform entry point into
// Winn Protocol v3 for the Win's VPN Flutter client.
//
// Everything the protocol implements lives under internal/, which no consumer
// outside this module can import and which gomobile cannot bind. This package
// is a deliberately thin, allocation-light facade over those internal packages
// whose exported signatures use only types gomobile can bind (string, bool,
// int, int64, []byte, error) so that the SAME source produces an Android .aar,
// an iOS .xcframework, and a C ABI shared library for desktop Dart FFI.
//
// TUNNEL ESTABLISHMENT. This facade wires a real, working carrier: the Winn v3
// relay engine, launched as a subprocess (cmd/winn-datapath with -winn3 over
// the duplex frame channel). Connect spawns it, sends the Create frame, and
// returns the CreateAck status; Disconnect sends Close and tears the subprocess
// down. This is the same shape every existing host already drives — Android
// executes the engine from nativeLibraryDir, Windows runs the standalone Go
// binary, and the Linux/Windows desktop hosts spawn it over stdio — so iOS is
// the one target where subprocesses are forbidden and the carrier is not
// available (iOS links cdatapath in-process instead).
//
// SCOPE, STATED PLAINLY. Wiring the relay carrier does NOT make a desktop or
// mobile host able to serve a full user session. It establishes the Winn v3
// datapath: handshake, encrypted tunnel, and a subprocess carrying inner IP
// packets over the frame channel. It does not install a platform tunnel device
// (VpnService / NEPacketTunnelProvider / WinTun / utun) and it does not run the
// verified preparation-assembler wiring. TunnelBackendJSON reports exactly what
// this build does and does not have, per build. TunnelSupported() is truthful
// about whether the relay carrier is present; safe_to_advertise_protocol stays
// false until the FULL path (carrier + device + preparation) is verified, so a
// client that offers winn/3 never silently downgrades a post-quantum
// negotiation to a session it cannot actually deliver.
package clientbinding

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"winsvpn.local/winnprotocol/datapath/duplex"
	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/protocol"
)

// ErrNoActiveSession is returned by Disconnect when no tunnel is up. It is a
// condition, not a bug: the caller asked to tear down something that is not
// running, and reporting that honestly is what lets a client distinguish "I am
// connected" from "I am not".
var ErrNoActiveSession = errors.New(
	"winn v3: no active session to disconnect",
)

// ErrEngineUnavailable is returned when Connect cannot find a relay engine
// subprocess to start.
var ErrEngineUnavailable = errors.New(
	"winn v3: the relay engine subprocess is not available on this build",
)

// ErrAlreadyActive is returned by Connect when a tunnel is already up; this
// session carries exactly one tunnel.
var ErrAlreadyActive = errors.New(
	"winn v3: a session is already active",
)

// BindingVersion identifies this facade's own contract, independent of the
// protocol version. A consumer that caches generated bindings can compare it.
const BindingVersion = "winn-clientbinding/1"

// ProtocolVersion is the Winn v3 connectivity contract version.
func ProtocolVersion() string { return connectivity.Version }

// RekeyProtocolVersion is the version of the PQ-authenticated preshared-key
// rekey sub-protocol. It is intentionally distinct from ProtocolVersion.
func RekeyProtocolVersion() string { return protocol.Version }

// FacadeVersion is BindingVersion, exported as a function because gomobile
// does not bind untyped string constants on all targets.
func FacadeVersion() string { return BindingVersion }

// ConfigEligibilityRefusal is the iOS/Apple-facing half of the winn/3
// config-issuance gate (connectivity.Winn3ConfigEligible). It returns "" when
// the described client may be issued a winn/3 config, and the reason when it
// must not be.
//
// An issuer must refuse to emit winn/3 config material whenever this returns
// non-empty: a client that predates winn/3 (a ProtocolVersion other than
// "winn/3"), or that declares winn/3 but cannot actually negotiate
// (negotiationReady false), would silently fail against a v3 gateway — which
// answers no unauthenticated datagram — and that silence is indistinguishable
// from censorship. This binding is the call a Flutter/iOS fabric reached by
// this package uses to gate issuance.
//
// protocolVersion is what the candidate client declares
// (ProtocolVersion() for a winn/3 build). negotiationReady is whether that
// client can complete a winn/3 negotiation. It is a distinct field from
// TunnelBackendJSON's `safe_to_advertise_protocol`, which stays false until
// the platform device and preparation assembler are verified. Do not pass
// `safe_to_advertise_protocol` as negotiationReady: that would refuse every
// current build, including ones whose relay carrier already works. Do not
// pass `negotiation_ready` as proof the client can serve a user session
// either — that JSON field is currently hardcoded true even with no engine.
func ConfigEligibilityRefusal(protocolVersion string, negotiationReady bool) string {
	err := connectivity.Winn3ConfigEligible(connectivity.ClientCapability{
		ProtocolVersion:  protocolVersion,
		NegotiationReady: negotiationReady,
	})
	if err == nil {
		return ""
	}
	return err.Error()
}

// TunnelSupported reports whether this build can actually bring up a verified
// Winn v3 tunnel. It is truthful per build: true when a relay engine subprocess
// is present and this platform can spawn it, false otherwise. Callers must
// gate any user-visible "Winn Protocol available" affordance on this and never
// on the presence of the library itself.
func TunnelSupported() bool { return backendOperational() }

type tunnelBackend struct {
	Binding           string   `json:"binding"`
	ProtocolVersion   string   `json:"protocol_version"`
	RekeyVersion      string   `json:"rekey_protocol_version"`
	GOOS              string   `json:"goos"`
	GOARCH            string   `json:"goarch"`
	TunnelSupported   bool     `json:"tunnel_supported"`
	CarrierBackends   []string `json:"carrier_backends_available"`
	MissingForTunnel  []string `json:"missing_for_tunnel"`
	NegotiationReady  bool     `json:"negotiation_ready"`
	AdvertiseProtocol bool     `json:"safe_to_advertise_protocol"`
}

// TunnelBackendJSON returns a machine-readable, per-build capability report.
// This is the call the Flutter client should make first. safe_to_advertise_
// protocol is the single field a client may use to decide whether it is
// entitled to offer winn/3 to a server. It is false while the platform device
// and preparation assembler are not verified, even when the relay carrier
// itself is present: advertising a negotiation you cannot serve to a real user
// is the silent downgrade this report exists to prevent.
func TunnelBackendJSON() string {
	operational := backendOperational()
	backends := []string{}
	if operational {
		backends = append(backends,
			"winn3-relay-subprocess (winn-datapath -winn3 stdio)")
	}
	report := tunnelBackend{
		Binding:         BindingVersion,
		ProtocolVersion: connectivity.Version,
		RekeyVersion:    protocol.Version,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		TunnelSupported: operational,
		CarrierBackends: backends,
		MissingForTunnel: []string{
			"platform tunnel provider (VpnService / NEPacketTunnelProvider / WinTun / utun)",
			"verified preparation assembler wiring (manifest, PSK pool, credential pool, policy anchor)",
		},
		NegotiationReady:  true,
		AdvertiseProtocol: false,
	}
	return mustJSON(report)
}

// SupportedSuitesJSON lists the strict hybrid post-quantum suites.
func SupportedSuitesJSON() string { return mustJSON(protocol.SupportedSuites()) }

// SupportedModesJSON lists the v3 connection modes.
func SupportedModesJSON() string {
	return mustJSON([]string{
		string(connectivity.ModeFast),
		string(connectivity.ModeAuto),
		string(connectivity.ModeStealth),
		string(connectivity.ModePrivateRelay),
		string(connectivity.ModeMaximumPrivacy),
	})
}

// CapabilitiesJSON returns the capability tokens a rekey request must carry for
// the given suite. An unknown suite is an error, never an empty list.
func CapabilitiesJSON(suite string) (string, error) {
	capabilities := protocol.RequiredCapabilities(suite)
	if capabilities == nil {
		return "", errors.New("unsupported cryptographic suite")
	}
	return mustJSON(capabilities), nil
}

// RequiredAuthAlgorithm names the ML-DSA parameter set bound to a suite.
func RequiredAuthAlgorithm(suite string) (string, error) {
	algorithm := protocol.RequiredAuthAlgorithm(suite)
	if algorithm == "" {
		return "", errors.New("unsupported cryptographic suite")
	}
	return algorithm, nil
}

// CarriersForModeJSON lists the carriers a mode is permitted to use. This is
// the client-side half of the mode policy the coordinator enforces; a client
// that offers a carrier outside this set is making an invalid attempt.
func CarriersForModeJSON(mode string) (string, error) {
	target := connectivity.Mode(mode)
	if !connectivity.ValidMode(target) {
		return "", errors.New("unsupported connection mode")
	}
	all := []connectivity.Carrier{
		connectivity.CarrierDirectAWG,
		connectivity.CarrierHTTP3,
		connectivity.CarrierHTTP2,
		connectivity.CarrierRealityXHTTP,
		connectivity.CarrierWebSocketTLS,
		connectivity.CarrierNativeTwoHop,
		connectivity.CarrierPrivacyTwoHop,
	}
	permitted := make([]string, 0, len(all))
	for _, carrier := range all {
		if target.Allows(carrier) {
			permitted = append(permitted, string(carrier))
		}
	}
	return mustJSON(permitted), nil
}

// ValidateReadinessJSON runs the real connectivity.Readiness validator over a
// JSON readiness document. It exists so a client can reject a malformed or
// expired readiness snapshot with the protocol's own rules rather than a
// reimplementation that could drift. Returns nil when the document is valid.
func ValidateReadinessJSON(document string) error {
	var readiness connectivity.Readiness
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&readiness); err != nil {
		return err
	}
	return readiness.Validate(time.Now())
}

// ValidateBindingJSON runs the real connectivity.Binding validator over a JSON
// candidate binding document.
func ValidateBindingJSON(document string) error {
	var binding connectivity.Binding
	decoder := json.NewDecoder(strings.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return err
	}
	return binding.Validate(time.Now())
}

// ValidateDeviceID applies the protocol's device identifier grammar.
func ValidateDeviceID(value string) error {
	if !protocol.ValidDeviceID(value) {
		return errors.New("device_id does not match the protocol grammar")
	}
	return nil
}

// ValidatePeerPublicKey applies the protocol's 32-byte AWG peer key rules.
func ValidatePeerPublicKey(value string) error {
	return protocol.ValidatePeerPublicKey(value)
}

// connectConfig is the JSON document Connect accepts. It names the engine and
// the key document as PATHS (the engine opens key material itself, under its
// own uid, so it never crosses this process boundary as bytes), plus the
// runtime parameters of the Create frame.
//
//	{
//	  "engine": "/abs/path/to/winn-datapath",   // optional; defaults to $WINS_WINN3_ENGINE
//	  "keys":   "/abs/path/to/winn3-keys.json",
//	  "create": { ... the winn3 Create frame document ... }
//	}
//
// engine_socket_fd, when present and >= 0, hands an already-open loopback/UDP
// descriptor to the engine as fd 3 (-udp-fd 3) instead of letting it dial its
// own socket. Omitting the field (or passing a negative value) means no
// hand-over: 0 is stdin, not "unset". It is the desktop/embedded-FFI and test
// shape; the mobile hosts hand a protected socket over differently.
type connectConfig struct {
	Engine         string          `json:"engine,omitempty"`
	Keys           string          `json:"keys"`
	EngineSocketFD int             `json:"engine_socket_fd,omitempty"`
	Create         json.RawMessage `json:"create"`
}

// Connect establishes a Winn v3 tunnel by spawning the relay engine and
// driving the Create handshake over the duplex frame channel. It returns the
// CreateAck status document (which carries the engine's own plan-floor
// numbers) on success, and an error on any failure. It never returns a
// synthetic success.
func Connect(configJSON string) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if active != nil {
		return "", ErrAlreadyActive
	}

	cfg, err := parseConnectConfig(configJSON)
	if err != nil {
		return "", fmt.Errorf("winn v3: connect config: %w", err)
	}

	engine := cfg.Engine
	if engine == "" {
		engine = enginePath()
	}
	if !engineOperational(engine) {
		return "", ErrEngineUnavailable
	}
	if cfg.Keys == "" {
		return "", errors.New(
			"winn v3: connect config requires the engine key document path (keys)")
	}

	create, err := json.Marshal(cfg.Create)
	if err != nil {
		return "", fmt.Errorf("winn v3: encode create document: %w", err)
	}

	sess, err := spawnEngine(engine, cfg.Keys, cfg.EngineSocketFD)
	if err != nil {
		return "", fmt.Errorf("winn v3: start relay engine: %w", err)
	}
	if err := sess.writer.Write(duplex.OpCreate, create); err != nil {
		_ = sess.teardown()
		return "", fmt.Errorf("winn v3: send create: %w", err)
	}

	select {
	case f := <-sess.resp:
		if f.opcode != duplex.OpCreateAck {
			_ = sess.teardown()
			return "", fmt.Errorf("winn v3: unexpected frame %s", f.opcode)
		}
		active = sess
		return string(f.payload), nil
	case err := <-sess.fatal:
		_ = sess.teardown()
		return "", fmt.Errorf("winn v3: engine refused create: %w", err)
	case <-sess.done:
		// The engine's stdout closed (it exited, e.g. on a key file it could
		// not load). Nothing further can arrive; take what route already
		// queued, and do not wait out the connect budget on a dead child.
		select {
		case f := <-sess.resp:
			if f.opcode == duplex.OpCreateAck {
				active = sess
				return string(f.payload), nil
			}
			_ = sess.teardown()
			return "", fmt.Errorf("winn v3: unexpected frame %s", f.opcode)
		case err := <-sess.fatal:
			_ = sess.teardown()
			return "", fmt.Errorf("winn v3: engine refused create: %w", err)
		default:
			_ = sess.teardown()
			return "", errors.New("winn v3: relay engine exited before CreateAck")
		}
	case <-time.After(connectTimeout):
		_ = sess.teardown()
		return "", errors.New("winn v3: no CreateAck within the connect budget")
	}
}

// SendPacket pushes one inner IP packet toward the gateway over the active
// tunnel. It returns an error when no tunnel is up. Used by a host that owns a
// device; the packet is carried inside the winn/3 ciphertext by the engine.
func SendPacket(packet string) error {
	sessionMu.Lock()
	sess := active
	sessionMu.Unlock()
	if sess == nil {
		return errors.New("winn v3: no active session to send a packet over")
	}
	return sess.writer.Write(duplex.OpInbound, []byte(packet))
}

// Status reports the live session if one is up, or the cold state when not.
func Status() string {
	sessionMu.Lock()
	sess := active
	sessionMu.Unlock()
	if sess != nil {
		if status := sess.currentStatus(); status != "" {
			return status
		}
	}
	return mustJSON(map[string]string{
		"state":   string(connectivity.StateCold),
		"failure": string(connectivity.FailureNotReady),
		"reason":  "no active winn v3 session",
	})
}

// Disconnect tears the active tunnel down. It reports a condition when there
// is nothing to tear down: ErrNoActiveSession. A clean teardown returns nil, so
// a caller can distinguish "I was connected and am now down" from "I was never
// connected".
func Disconnect() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if active == nil {
		return ErrNoActiveSession
	}
	sess := active
	active = nil
	return sess.teardown()
}

func mustJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return `{"error":"encode failed"}`
	}
	return string(encoded)
}
