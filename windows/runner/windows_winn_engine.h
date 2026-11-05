#ifndef RUNNER_WINDOWS_WINN_ENGINE_H_
#define RUNNER_WINDOWS_WINN_ENGINE_H_

// Windows host for Winn Protocol v3.
//
// This is the SAME SHAPE Android, Apple and Linux already ship, deliberately
// rather than a fourth design. The two things every mistake on this boundary
// came from are stated once, here, because a reader of this file is exactly the
// person who has to get them right.
//
// # 1. The payload boundary: where the datagrams come from
//
// The engine's Inbound/Outbound frames carry AMNEZIAWG OUTER DATAGRAMS -- what
// the host's own AWG engine would otherwise have sent to, and received from,
// the gateway's UDP endpoint. They are NOT raw tun packets. The datapath module
// contains no AmneziaWG implementation, and `payload:"ip-packet"` is refused
// there precisely because forwarding tun packets would put CLEARTEXT on the
// wire.
//
// An earlier revision of this file got that wrong: it created a SECOND WinTun
// adapter of its own and framed raw IP packets off it. That adapter is gone.
// AmneziaWG (windows/awg_engine, which calls tun.CreateTUN itself) keeps the
// one and only tunnel adapter and keeps doing all of the cryptography. The only
// thing that changes is where its outer datagrams go: the `[Peer] Endpoint` in
// the configuration handed to `awg setconf` is rewritten from the real gateway
// to `127.0.0.1:<seam port>`, a loopback-bound UDP socket this host owns.
// AmneziaWG sends its already-encrypted outer datagrams there, this host relays
// them to the engine over the framed duplex protocol, and the engine sends them
// on to the real gateway. The return path is the same in reverse.
//
// That socket needs no protection, and this is structural rather than a policy
// we enforce: a socket bound to 127.0.0.1 has no route off the device. The same
// containment already exists four times in this tree -- Android's
// WinnAwgLoopbackSeam, internal/carrier.RelayLocalUDP, the Apple wrapper's
// seam, and the Xray stealth transport's loopback pin.
//
// # 2. The outer socket: keeping it out of the tunnel it carries
//
// The engine opens ONE socket that does touch the network. Windows has no
// VpnService.protect, and datapath/carrier.go sanctions the desktop model for
// exactly this case: `transportFD < 0` plus a route exclusion, permitted only
// when the configuration sets `allow_own_socket`.
//
// The Windows exclusion is a PINNED /32 HOST ROUTE to the Winn gateway on the
// PHYSICAL interface LUID with the physical next hop, installed by
// PrepareWindowsAppExclusions() BEFORE any tunnel route exists and re-pinned
// across link changes by the physical-network monitor. Longest-prefix match
// means that /32 always beats the 0.0.0.0/0 later promoted onto the tunnel, so
// the engine's outer socket egresses the physical NIC for the whole life of the
// tunnel.
//
// It must follow `[winn] endpoint` and NOT `[Peer] Endpoint`. The Apple lane
// found that hole: the peer endpoint is rewritten to loopback at start, and the
// Winn gateway may differ from the AmneziaWG gateway anyway, so a /32 derived
// from the peer would pin 127.0.0.1 and the tunnel would dead-loop.
//
// Linux's lane found the matching trap on its own side and it is worth naming
// here so nobody "simplifies" this into the same shape: a packet MARK alone is
// not a sufficient exclusion, because the kernel picks the source address on
// the first unmarked route lookup. Windows has no equivalent hazard only
// because the pin is a real route entry, installed before the tunnel's own
// routes exist, and GetBestRoute2 is re-checked against it at commit time.
//
// # Anti-downgrade
//
// A configuration carrying `[winn] enabled = true` must NEVER start as
// classical AmneziaWG, and must never start over a carrier weaker than the one
// it named. Every failure below is fail-closed: it aborts the start and says
// why. Once WindowsConfigSelectsWinnProtocol answers true there is no path in
// InstallPrivilegedTunnel that returns "carry on without Winn".

#include <cctype>
#include <cstdint>
#include <string>

namespace winsvpn::winn {

struct WindowsAwgHeaderSpec {
  uint32_t start = 0;
  uint32_t end = 0;
  bool isRange() const { return end > start; }
  std::string spec() const {
    return isRange() ? std::to_string(start) + "-" + std::to_string(end)
                     : std::to_string(start);
  }
  bool overlaps(const WindowsAwgHeaderSpec& o) const {
    return start <= o.end && o.start <= end;
  }
  bool contains(uint32_t v) const { return start <= v && v <= end; }
};

// The AmneziaWG classification table and the seam parameters, parsed from the
// `[winn]` INI section lib/winn_protocol_dispatch.dart emits.
struct WindowsWinnParams {
  // The real gateway, an IP literal "host:port". Never a hostname: resolving
  // one here would leak a DNS lookup outside the tunnel.
  std::string endpoint;
  std::string session_id;
  int max_datagram = 0;
  WindowsAwgHeaderSpec h[4];
  uint16_t s[4] = {0, 0, 0, 0};
  // The AmneziaWG runtime's own listen_port, read from its UAPI after it
  // started. Never parsed from the served section. StartWindowsWinnEngine
  // refuses 0, because the seam admits 127.0.0.1 from exactly this port and
  // learns nothing from traffic.
  uint16_t awg_listen_port = 0;
};

// True when THIS HOST's own parsed `[winn]` section carries a complete,
// classifiable h1..h4 table -- four well-formed, pairwise non-overlapping
// header-type ranges.
//
// # Why this exists as a separate predicate
//
// It is the host-side statement of the fact the convergence gate depends on:
// the engine was handed a classification table, so its transport counters CAN
// fire. The gate used to assert that fact by substring-matching
// `"awg_classification":"configured-h1h4"` in the ENGINE'S STATUS REPLY, and
// promoted routes without proof whenever the substring was absent. That coupled
// a route-promotion decision to the engine's JSON spelling: an engine-side
// field rename, a version skew, or an encoder that emitted a space after the
// colon disabled the gate silently. The justification written beside that check
// appealed to ParseWindowsWinnSection -- to the HOST's parsed configuration --
// so the check now tests exactly what the justification claims, on this side of
// the boundary, where no reply can change the answer.
//
// A default-constructed WindowsWinnParams is deliberately FALSE here: all four
// specs are the degenerate range 0..0, which overlaps itself pairwise. A
// WindowsWinnParams that came out of ParseWindowsWinnSection is always TRUE,
// because that function refuses a section missing any of h1..h4 and refuses an
// overlapping set. The two agree by construction rather than by comment.
//
// Pure C++17 with no platform headers on purpose: it is the decision the gate
// turns on, and it is exercised by windows/runner/windows_winn_gate_test.cc on
// a development host that is not Windows.
inline bool WindowsWinnHeadersClassify(const WindowsWinnParams& params) {
  for (int a = 0; a < 4; ++a) {
    // An inverted range is not a range. WindowsAwgHeaderSpec::overlaps() is an
    // interval intersection and would answer nonsense for end < start.
    if (params.h[a].end < params.h[a].start) return false;
    for (int b = a + 1; b < 4; ++b) {
      if (params.h[a].overlaps(params.h[b])) return false;
    }
  }
  return true;
}

// Locates a substring that is a JSON object key at the top level of the
// document, then reports whether its value is the literal `true`.
//
// A whole JSON parser is not warranted for reading three fields out of a
// document this process's own child produced, but a bare `find("...:true")`
// would be too loose: it would match a key that merely ends with the name we
// asked for. Anchoring on the quoted key and stepping over whitespace is
// enough, and it is the same shape the AWG UAPI parser in
// windows_tunnel_backend.cpp already uses for its own line protocol.
//
// Moved out of windows_winn_engine.cpp's anonymous namespace so the gate
// decision below can be compiled and run off Windows. Reading a proof field out
// of an engine reply is precisely the code that must not go untested.
inline bool JsonFieldIsTrue(const std::string& json, const char* name) {
  const std::string key = std::string("\"") + name + "\"";
  size_t at = json.find(key);
  while (at != std::string::npos) {
    size_t cursor = at + key.size();
    while (cursor < json.size() &&
           std::isspace(static_cast<unsigned char>(json[cursor])) != 0) {
      ++cursor;
    }
    if (cursor < json.size() && json[cursor] == ':') {
      ++cursor;
      while (cursor < json.size() &&
             std::isspace(static_cast<unsigned char>(json[cursor])) != 0) {
        ++cursor;
      }
      return json.compare(cursor, 4, "true") == 0;
    }
    at = json.find(key, at + 1);
  }
  return false;
}

// The three fields a Create acknowledgement must echo back exactly. They are the
// anti-downgrade check on this side of the boundary (windows/runner/windows_winn
// _engine.cpp): the engine repeats what it actually built, so a binary that
// silently opened a different payload mode or a different carrier -- or a test
// double that emits no `contract` at all -- is refused instead of carrying a
// session nobody negotiated. "awg-datagram" in particular is the one that must
// never be claimed while something else is on the wire. Every value is a
// restatement of a Go constant, mirroring WinnEngineConfig.kt and
// linux_winn_host.cc, so the four hosts cannot drift.
constexpr char kWinnContractVersion[] = "winn-datapath/1";
constexpr char kWinnPayloadAwgDatagram[] = "awg-datagram";
constexpr char kWinnCarrierDirectAwg[] = "direct-awg";

// True when a top-level JSON object field equals a specific string, in either
// the compact `"name":"value"` form Go's encoder emits or the `"name": "value"`
// a pretty-printing encoder would. A future encoder that prettifies must not be
// able to silently turn this anti-downgrade gate off, so the whitespace after
// the colon is the one tolerated variation and is checked for explicitly.
//
// Moved out of windows_winn_engine.cpp's anonymous namespace alongside
// JsonFieldIsTrue: reading the acknowledgement fields out of the engine's reply
// is precisely the code that must not go untested, and it is compiled and run
// off Windows by windows_winn_gate_test.cc.
inline bool JsonFieldEquals(const std::string& json,
                            const char* name,
                            const char* expected) {
  const std::string needle =
      std::string("\"") + name + "\":\"" + expected + "\"";
  if (json.find(needle) != std::string::npos) return true;
  const std::string spaced =
      std::string("\"") + name + "\": \"" + expected + "\"";
  return json.find(spaced) != std::string::npos;
}

// True only when a Create acknowledgement from the engine proves it built
// exactly the winn-datapath/1 awg-datagram direct-awg session this host
// configured: the contract identifies the granted datapath, the payload is the
// AmneziaWG outer-datagram mode this host supplies, and the carrier is the one
// this host builds. Refused -- never downgraded -- on any mismatch. This is the
// single predicate StartWindowsWinnEngine turns on, kept inline so the refusal
// it enforces is compiled and exercised off Windows.
inline bool WinnCreateAckAccepted(const std::string& acknowledgement) {
  return JsonFieldEquals(acknowledgement, "contract", kWinnContractVersion) &&
         JsonFieldEquals(acknowledgement, "payload",
                         kWinnPayloadAwgDatagram) &&
         JsonFieldEquals(acknowledgement, "carrier", kWinnCarrierDirectAwg);
}

// The verdict of the transfer-proven half of the route-promotion gate.
//
// Three states rather than two, because "not proven yet" and "can never be
// proven" call for opposite handling and collapsing them is what produced the
// defect this replaces. The caller polls while the answer is kNotYetObserved,
// promotes on kObserved, and refuses IMMEDIATELY on kCannotObserve -- there is
// nothing to wait for when the proof is structurally unavailable, so the
// refusal costs no part of the convergence budget.
enum class WinnTransportGate {
  // A payload-carrying AmneziaWG transport datagram has crossed the carrier in
  // each direction. This is the only value that may promote routes.
  kObserved,
  // No proof yet, and nothing says there cannot be one. Keep polling until the
  // caller's deadline; the deadline itself is fail-closed.
  kNotYetObserved,
  // This session can never produce the proof. Refuse now.
  kCannotObserve,
};

// The gate decision, as a pure function of the host's own configuration and the
// engine's status reply.
//
// `host_headers_classify` is WindowsWinnHeadersClassify() over the params this
// host actually started the session with -- NOT anything read back from the
// engine. It is the only input that can produce kCannotObserve.
//
// `status_json` is consulted for exactly one decision, `transport_observed_both
// _ways`, and otherwise only for wording. In particular `awg_classification` is
// read as a DIAGNOSTIC HINT and never as a verdict: an engine that renamed or
// reformatted that field changes the text of a refusal here and changes nothing
// about whether routes are promoted. `up` is deliberately not consulted at all
// -- datapath/status.go states plainly that it means only "a socket exists".
//
// *reason, when non-null, receives a non-secret sentence naming what is
// missing. It NEVER quotes the status document, which carries the customer's
// gateway endpoint.
inline WinnTransportGate DecideWinnTransportGate(bool host_headers_classify,
                                                 const std::string& status_json,
                                                 std::string* reason) {
  const auto say = [reason](const char* text) {
    if (reason != nullptr) *reason = text;
  };
  if (!host_headers_classify) {
    // Unreachable for any configuration ParseWindowsWinnSection accepted: it
    // refuses a `[winn]` section that omits any of h1..h4 and refuses an
    // overlapping set. Reached only if some future caller builds a
    // WindowsWinnParams by hand and hands it to StartWindowsWinnEngine. It
    // refuses rather than promotes, because a gate that cannot observe has no
    // business promoting a default route.
    say("this host started the session without a complete AmneziaWG h1..h4 "
        "classification table, so the datapath's transfer-proven counters can "
        "never fire and route promotion could never be justified. h1..h4 are "
        "required for winn/3.");
    return WinnTransportGate::kCannotObserve;
  }
  if (status_json.empty()) {
    say("the Winn Protocol engine has not answered a status request yet.");
    return WinnTransportGate::kNotYetObserved;
  }
  if (JsonFieldIsTrue(status_json, "transport_observed_both_ways")) {
    if (reason != nullptr) reason->clear();
    return WinnTransportGate::kObserved;
  }
  // Wording only, from here down. Both branches return the same verdict.
  if (status_json.find("\"awg_classification\":\"configured-h1h4\"") ==
          std::string::npos &&
      status_json.find("\"awg_classification\": \"configured-h1h4\"") ==
          std::string::npos) {
    say("this host supplied a complete h1..h4 table but the engine is not "
        "reporting the matching configured-h1h4 classification, so either the "
        "engine did not apply the table or its status schema has drifted from "
        "this host's. Either way no transport datagram is being classified and "
        "the tunnel was refused rather than promoted without proof.");
  } else {
    say("no payload-carrying AmneziaWG transport datagram has yet crossed the "
        "carrier in both directions.");
  }
  return WinnTransportGate::kNotYetObserved;
}

// True only for a configuration carrying `[winn] enabled = true`.
//
// This used to select on `[winn] protocol = winn/3`, a key the Dart layer never
// emits, so the two schemas shared ZERO keys and a real served config could
// never have reached this host. `enabled` is what Android, Apple and Linux all
// read, and it is what lib/winn_protocol_dispatch.dart writes.
bool WindowsConfigSelectsWinnProtocol(const std::string& raw_config);

// Parses and validates the `[winn]` section. Mirrors WinnEngineConfig.from on
// Android and ParseLinuxWinnSection on Linux: exactly the keys those hosts
// accept, and an UNRECOGNISED KEY IS A REFUSAL rather than something to drop,
// because quietly dropping it would leave the operator believing it took
// effect.
//
// Returns false and sets *error on any violation. Never partially fills *out.
bool ParseWindowsWinnSection(const std::string& raw_config,
                             WindowsWinnParams* out,
                             std::string* error);

// Splits "1.2.3.4:51820" or "[2001:db8::1]:51820" into host and port, refusing
// anything that is not an IP literal with a nonzero port. Exposed because the
// route-pinning path must re-validate rather than trust what Dart checked.
bool SplitWindowsWinnEndpoint(const std::string& endpoint,
                              std::string* host,
                              std::string* port);

// The host part of `[winn] endpoint`, or "" when the configuration selects no
// Winn session or carries an unusable endpoint. This is the address whose /32
// must be pinned on the physical interface, and it is deliberately a separate,
// tiny entry point so windows_split_tunnel.cpp can ask the question without
// taking on the rest of this header.
std::string WindowsWinnCarrierHost(const std::string& raw_config);

// Rewrites the `[Peer] Endpoint` of an AmneziaWG configuration to the loopback
// seam. Returns false when the configuration does not have EXACTLY one endpoint
// to rewrite: zero would leave AmneziaWG with nowhere to send, and two would
// mean one of them still points at the real gateway, so its outer datagrams
// would leave this host unprotected while we believed they were carried.
bool RewriteAwgPeerEndpointToSeam(const std::string& awg_config,
                                  uint16_t seam_port,
                                  std::string* out);

// Builds the datapath.Config JSON for a Create frame.
//
// This is a REAL datapath.Config -- the document winn_protocol_experimental/
// datapath/config.go decodes with DisallowUnknownFields. The previous revision
// sent `{"protocol","mtu","config"}`, which only the test double could parse,
// and shipped the entire INI including `PrivateKey` to the subprocess. No key
// material crosses this boundary any more, because there is no longer a
// key-material-shaped field for it to cross in.
std::string BuildWindowsWinnConfigJson(const WindowsWinnParams& params);

// Framing conformance self-test. Pure computation, no privileges, no I/O; safe
// to call from either binary. See windows/runner/winn_frame_selftest.h.
bool RunWindowsWinnFramingSelfTest(std::string* error);

#if defined(WINS_TUNNEL_SERVICE_CORE)

// INVALID_SOCKET, spelled without dragging <winsock2.h> into this header.
constexpr uintptr_t kInvalidWinnSeam = static_cast<uintptr_t>(~0);

// Binds the loopback seam. On success the socket is bound to 127.0.0.1 on an
// ephemeral port and *port carries it.
//
// This happens BEFORE the awg-quick-equivalent configuration is written, for
// two reasons: the port has to be known to write it, and a bound socket means
// AmneziaWG's first handshake initiations queue in the receive buffer instead
// of drawing ICMP port-unreachable while the engine is still starting.
uintptr_t BindWindowsWinnSeam(uint16_t* port, std::string* error);

// Closes a seam that StartWindowsWinnEngine never took.
void CloseWindowsWinnSeam(uintptr_t seam);

// Starts the engine subprocess and the two pumps.
//
// OWNERSHIP OF `seam` PASSES TO THIS CALL ON EVERY OUTCOME, success or failure,
// so a caller has one rule to remember rather than two. Fail-closed: on false
// nothing is left running and *error says what happened.
bool StartWindowsWinnEngine(const std::wstring& engine_path,
                            uintptr_t seam,
                            const WindowsWinnParams& params,
                            std::string* error);

// Stops the engine and both pumps. Safe when nothing is running.
void StopWindowsWinnEngine();

// True while the engine subprocess is running AND the frame channel has not
// been torn down.
//
// Deliberately not "the process exists". A process that is alive with a dead
// channel carries nothing, and reporting that as a working tunnel is the exact
// failure mode this project has already been bitten by.
bool WindowsWinnEngineRunning();

// The engine's own status JSON, obtained with a StatusRequest frame, or "" when
// no engine is running. Non-secret counters and liveness only.
std::string WindowsWinnEngineStatusJson();

// The transfer-proven half of the route-promotion gate.
//
// datapath/status.go is explicit that `up` means only "a socket exists" and
// must not gate route promotion. The honest signal is
// `transport_observed_both_ways`, which moves only when a datagram carrying the
// AmneziaWG transport-data header type, larger than a bare keepalive, crossed
// the carrier in that direction. The other half of the gate -- a recent AWG
// handshake -- is the host's own AWG engine's business and lives in
// windows_tunnel_backend.cpp; neither alone is sufficient.
//
// Queries the running engine for its status, then answers with
// DecideWinnTransportGate() over the h1..h4 table THIS HOST latched when it
// started the session. *status_json and *reason are optional; *reason carries a
// non-secret sentence a caller can put in front of the operator.
//
// THERE IS NO PATH THROUGH THIS FUNCTION THAT REPORTS PROOF IT DOES NOT HAVE.
// It used to have one: a missing `"awg_classification":"configured-h1h4"`
// substring in the engine's reply returned "observed", promoting routes onto a
// carrier that was never proven to carry, with the only trace an
// OutputDebugStringA line no production install can see.
WinnTransportGate WindowsWinnTransportGate(std::string* status_json,
                                           std::string* reason);

// kObserved, spelled as a bool, for callers that only report liveness and have
// nothing to wait for. A caller that must DECIDE something wants the tri-state
// above, so it can tell "not yet" from "never".
bool WindowsWinnTransportObservedBothWays(std::string* status_json);

#endif  // WINS_TUNNEL_SERVICE_CORE

}  // namespace winsvpn::winn

#endif  // RUNNER_WINDOWS_WINN_ENGINE_H_
