#ifndef RUNNER_LINUX_WINN_HOST_H_
#define RUNNER_LINUX_WINN_HOST_H_

// Linux host for Winn Protocol v3.
//
// This is the Linux side of the same contract Android already ships, and it is
// deliberately the SAME SHAPE rather than a new one. The design is stated once,
// here, because every mistake this project has made on this boundary came from
// getting one of these two things wrong:
//
// # 1. The payload boundary: where the datagrams come from
//
// The engine's Inbound/Outbound frames carry AMNEZIAWG OUTER DATAGRAMS -- what
// the host's own AWG engine would otherwise have sent to, and received from,
// the gateway's UDP endpoint. They are NOT raw tun packets. The datapath module
// contains no AmneziaWG implementation, so a host that pumps its tun device
// into these frames forwards CLEARTEXT to the gateway.
//
// So AmneziaWG keeps the tun and keeps doing all of the cryptography. The only
// thing that changes is where its outer datagrams go: the peer `Endpoint` in
// the awg-quick configuration is rewritten from the real gateway to
// `127.0.0.1:<seam port>`, a loopback-bound UDP socket this host owns. AWG
// sends its already-encrypted outer datagrams there, this host relays them to
// the engine over the framed duplex protocol, and the engine sends them on to
// the real gateway. The return path is the same in reverse.
//
// That socket needs no protection, and this is structural rather than a policy
// we enforce: a socket bound to 127.0.0.1 has no route off the device. The same
// containment already exists three times in this tree -- Android's
// WinnAwgLoopbackSeam, internal/carrier.RelayLocalUDP, and the Xray stealth
// transport's `RemoteAwgHost` loopback pin in linux_tunnel_backend.cc.
//
// # 2. The outer socket: keeping it out of the tunnel it carries
//
// The engine opens ONE socket that does touch the network. On Android that
// socket is opened by the host, protected with VpnService.protect, and handed
// over; the engine runs with allow_own_socket false. Linux has no
// VpnService.protect, and datapath/carrier.go already sanctions the desktop
// model instead: `transportFD < 0` plus route exclusion, permitted only when
// the configuration sets allow_own_socket.
//
// The Linux exclusion is awg-quick's OWN fwmark, read back from
// `awg show winsvpn fwmark`. awg-quick installs `ip rule not fwmark <M> lookup
// <T>`, so a datagram carrying mark M skips the tunnel table and leaves by the
// physical route -- and the kill switch's own chain already RETURNs on that
// exact mark. Marking the engine's outer datagrams with M therefore reuses two
// mechanisms that are already load-bearing rather than adding a third.
//
// The engine has no separate uid to match on, so the mark is applied by
// DESTINATION: the gateway endpoint, which after the rewrite above is the only
// address anything on this host still sends outer datagrams to. That rule, and
// the `ip route get ... mark ...` recursion check that proves it worked, live
// in the privileged script in linux_tunnel_backend.cc, because only root can
// install them and only after awg-quick has published the mark.
//
// Without that exclusion the engine's datagrams match the tunnel's own default
// route, re-enter winsvpn, and loop forever.
//
// # Anti-downgrade
//
// A configuration carrying `[winn] enabled = true` must NEVER start as
// classical AmneziaWG. Every failure below is fail-closed: it aborts the start
// and reports why. `LinuxConfigSelectsWinnProtocol` is what the tunnel backend
// asks before it decides, and once it answers true there is no path in this
// file that returns "carry on without Winn".

#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace winsvpn::winn {

// The carrier profile document `winn-datapath -carrier-profile PATH` reads.
//
// This is a SEPARATE document from datapath.Config, and deliberately so: not
// one of these fields is a field of datapath.Config, whose decoder rejects
// unknown fields, so forwarding any of them in the Create frame would be a hard
// create-time error. It travels as a file path on argv instead.
//
// The schema authority is winn_protocol_experimental/datapath/carrierhost/
// profile.go, which also decodes with DisallowUnknownFields. The reference
// implementation this is ported from is Android's WinnCarrierProfile.kt --
// deliberately the same shape rather than a second one.
//
// IT CONTAINS NO KEY MATERIAL, only paths. The six credential files are named
// by absolute path and never opened by this host; the engine opens them. That
// is what keeps rule 5 satisfiable while still using an authenticated carrier.
// It still names every private file this device holds, so it is written 0600
// and never logged. Log DescribeLinuxWinnCarrierProfile instead.
struct LinuxWinnCarrierProfile {
  std::string carrier;  // Always kCarrierHttp3 today; see SupportedCarriers.
  std::string masque_template;
  std::string public_target;
  std::string server_name;
  std::string suite;
  std::string controller_id;
  std::string device_id;
  std::string device_pq_algorithm;
  std::string manifest_digest;
  // 32 lowercase hex, GENERATED per session by NewCarrierSessionId -- never
  // copied from `[winn] session_id`, which the server chose. See that function.
  std::string session_id;
  std::string sequence_epoch;  // Optional; omitted from the document if empty.
  int max_inner_datagram = 0;  // 0 means "not set"; normalised before emit.
  std::string privacy_profile;

  // Absolute paths to the six credential files, resolved and existence-checked
  // by ResolveLinuxWinnCarrierCredentials. Never their contents.
  std::string controller_pins_path;
  std::string root_ca_path;
  std::string ech_config_list_path;
  std::string device_seed_path;
  std::string client_cert_path;
  std::string client_key_path;

  // SINGLE PACKET AUTHORIZATION. `spa_required` false means the mechanism is
  // off and NOT ONE of the fields below is emitted. carrierhost REFUSES a
  // document carrying a NON-EMPTY spa_ field while the mode is off
  // (ErrSPAFieldWithoutMode); it does NOT refuse an empty one, because the
  // stray sweep tests TrimSpace(...) != "" for strings and != 0 for the
  // scalars, so "spa_target": "" parses fine and is indistinguishable from
  // absent. (An earlier comment here claimed otherwise; it was checked against
  // ParseProfile and is false.) Omission is still the rule because it cannot be
  // misread and because only the non-empty stray is a hard failure.
  //
  // spa_key_path is an absolute path to the knock key and never the key
  // itself. It is resolved and existence-checked by
  // ResolveLinuxWinnCarrierCredentials only when spa_required is true, and
  // never opened by this host.
  //
  // The three scalars are 0 when the served config did not name them, meaning
  // "use the engine's own derived or default value" -- the same meaning 0 has
  // in carrierhost.Profile.
  bool spa_required = false;
  std::string spa_key_path;
  std::string spa_target;
  int spa_packet_size = 0;
  int spa_bucket_window_seconds = 0;
  int spa_max_skew_seconds = 0;
};

// One H1..H4 value: either a scalar or an inclusive range the engine draws
// from once per packet. Mirrors VpnConfigValidator.AwgHeaderSpec (Dart) and
// AwgHeaderSpec (Go). A bare value is the degenerate range start==end.
struct LinuxAwgHeaderSpec {
  uint32_t start = 0;
  uint32_t end = 0;
  bool isRange() const { return end > start; }
  std::string spec() const {
    return isRange() ? std::to_string(start) + "-" + std::to_string(end)
                     : std::to_string(start);
  }
  bool overlaps(const LinuxAwgHeaderSpec& o) const {
    return start <= o.end && o.start <= end;
  }
  bool contains(uint32_t v) const { return start <= v && v <= end; }
};

// The AmneziaWG classification table and the loopback seam parameters, parsed
// from the `[winn]` INI section lib/winn_protocol_dispatch.dart emits.
struct LinuxWinnParams {
  // The real gateway, an IP literal "host:port". Never a hostname: resolving
  // one here would leak a DNS lookup outside the tunnel.
  std::string endpoint;
  std::string session_id;
  int max_datagram = 0;  // 0 selects the engine default.
  LinuxAwgHeaderSpec h[4];
  uint16_t s[4] = {0, 0, 0, 0};

  // The resolved carrier. Empty is impossible after a successful parse: it is
  // either the direct-awg default or an explicitly supported value.
  std::string carrier;

  // Meaningful only when `carrier` is not direct-awg. For direct-awg the
  // section's carrier keys are still ACCEPTED (Android folds them into
  // RESERVED_KEYS the same way) but nothing is built from them, because
  // direct-awg has no carrier profile.
  bool has_carrier_profile = false;
  LinuxWinnCarrierProfile carrier_profile;

  // The AmneziaWG engine's own source port on the loopback seam. Never parsed
  // from the served section: the caller reserves it with
  // ReserveLinuxAwgListenPort and RewriteAwgPeerEndpointToSeam writes it into
  // the AmneziaWG configuration as ListenPort. StartLinuxWinnEngine refuses 0,
  // because the seam admits 127.0.0.1 from exactly this port and learns
  // nothing from traffic.
  uint16_t awg_listen_port = 0;
};

// True when THIS HOST's own parsed `[winn]` section carries a complete,
// classifiable h1..h4 table -- four well-formed, pairwise non-overlapping
// header-type ranges.
//
// # Why this exists as a separate predicate
//
// It is the host-side statement of the fact the route-promotion gate depends
// on: the engine was handed a classification table, so its transport counters
// CAN fire. The gate used to assert that fact by substring-matching
// `"awg_classification":"configured-h1h4"` in the ENGINE'S STATUS REPLY
// (linux_tunnel_backend.cc:2759 before this change) and promoted routes
// without proof whenever the substring was absent; the health check at :2692
// did the same and switched itself off. That coupled a route-promotion
// decision to the engine's JSON spelling: an engine-side field rename, a
// version skew, or an encoder that emitted a space after the colon disabled
// the gate silently.
//
// It is a round trip through the subprocess and back, which is the worst thing
// to gate on: `awg_classification` is produced by
// winn_protocol_experimental/datapath/status.go:230-233 from
// engine.headersConfigured, which engine.go:304 sets from the
// `awg_header_types` document THIS HOST built in BuildLinuxWinnConfigJson. So
// a break anywhere along that round trip reads as "gate off" rather than as
// "something is wrong".
//
// The justification written beside the old check appealed to
// ParseLinuxWinnSection -- to the HOST's parsed configuration -- so the check
// now tests exactly what the justification claims, on this side of the
// boundary, where no reply can change the answer.
//
// A default-constructed LinuxWinnParams is deliberately FALSE here: all four
// specs are the degenerate range 0..0, which overlaps itself pairwise. A
// LinuxWinnParams that came out of ParseLinuxWinnSection is always TRUE,
// because that function refuses a section missing any of h1..h4
// (linux_winn_host.cc:1292) and refuses an overlapping set
// (linux_winn_host.cc:1296-1304). The two agree by construction rather than by
// comment.
//
// Pure C++17 with no platform headers on purpose: it is the decision the gate
// turns on, and it is exercised by linux/runner/linux_winn_gate_test.cc on a
// development host that is not Linux. This is the same predicate Windows
// carries at WindowsWinnHeadersClassify(); the two hosts must not drift.
inline bool LinuxWinnHeadersClassify(const LinuxWinnParams& params) {
  for (int a = 0; a < 4; ++a) {
    // An inverted range is not a range. LinuxAwgHeaderSpec::overlaps() is an
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
// A whole JSON parser is not warranted for reading one field out of a document
// this process's own child produced, but a bare `find("...:true")` would be too
// loose: it would match a key that merely ends with the name we asked for.
// Anchoring on the quoted key and stepping over whitespace is enough.
//
// The whitespace tolerance is not decoration. The replaced code's own comment
// argued that "Go's encoding/json emits `"field":true` with no interior space,
// so a substring test is exact here" -- an argument about the CURRENT encoder,
// not about the contract. This reads the field either way, so a future
// pretty-printer cannot change a verdict.
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
// `host_headers_classify` is LinuxWinnHeadersClassify() over the params this
// host actually started the session with -- NOT anything read back from the
// engine. It is the only input that can produce kCannotObserve.
//
// `status_json` is consulted for exactly one decision,
// `transport_observed_both_ways`, and otherwise only for wording. In particular
// `awg_classification` is read as a DIAGNOSTIC HINT and never as a verdict: an
// engine that renamed or reformatted that field changes the text of a refusal
// here and changes nothing about whether routes are promoted. `up` is
// deliberately not consulted at all -- datapath/status.go states plainly that
// it means only "a socket exists".
//
// *reason, when non-null, receives a non-secret sentence naming what is
// missing. It NEVER quotes the status document, which carries the customer's
// gateway endpoint. linux_winn_gate_test.cc asserts that.
inline WinnTransportGate DecideWinnTransportGate(bool host_headers_classify,
                                                 const std::string& status_json,
                                                 std::string* reason) {
  const auto say = [reason](const char* text) {
    if (reason != nullptr) *reason = text;
  };
  if (!host_headers_classify) {
    // Unreachable for any configuration ParseLinuxWinnSection accepted: it
    // refuses a `[winn]` section that omits any of h1..h4 and refuses an
    // overlapping set. Reached only if some future caller builds a
    // LinuxWinnParams by hand and hands it to StartLinuxWinnEngine. It refuses
    // rather than promotes, because a gate that cannot observe has no business
    // keeping a default route pointed into the tunnel.
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

// True only for a configuration carrying `[winn] enabled = true`. Every
// AmneziaWG configuration without a `[winn]` section returns false, so the
// shipping winn/1 path is untouched.
bool LinuxConfigSelectsWinnProtocol(const std::string& raw_config);

// Parses and validates the `[winn]` section. Mirrors WinnEngineConfig.from on
// Android: exactly the keys that host accepts, and an UNRECOGNISED KEY IS A
// REFUSAL rather than something to drop, because quietly dropping it would
// leave the operator believing it took effect.
//
// Returns false and sets *error on any violation. Never partially fills *out.
bool ParseLinuxWinnSection(const std::string& raw_config,
                           LinuxWinnParams* out,
                           std::string* error);

// Splits "1.2.3.4:51820" or "[2001:db8::1]:51820" into host and port, refusing
// anything that is not an IP literal with a nonzero port. Exposed for the
// privileged-script argument path, which must re-validate rather than trust
// what the Dart layer already checked.
bool SplitLinuxWinnEndpoint(const std::string& endpoint,
                            std::string* host,
                            std::string* port);

// Rewrites the `[Peer] Endpoint` of an AmneziaWG configuration to the loopback
// seam and pins AmneziaWG's own source port with `ListenPort =
// awg_listen_port` directly under `[Interface]`, dropping any ListenPort the
// configuration already carried. Returns false when the configuration does not
// have exactly one `[Peer] Endpoint` and exactly one `[Interface]`, or when
// awg_listen_port is 0, which is a refusal rather than an append: a config we
// do not understand well enough to redirect is one whose outer datagrams might
// still leave for the real gateway unprotected.
bool RewriteAwgPeerEndpointToSeam(const std::string& awg_config,
                                  uint16_t seam_port,
                                  uint16_t awg_listen_port,
                                  std::string* out);

// Resolves the six carrier credential files under the per-user private data
// directory, verifying each is a regular readable file, and fills their
// absolute paths into *profile.
//
// It NEVER OPENS THEM. The point of naming secrets by path is that this process
// does not hold them; opening one here to "check it" would defeat that.
//
// Returns false with a *error naming the FIRST missing file and what it is for.
// None of these is generated by this app -- exactly as on Android -- so an
// unprovisioned device fails closed here rather than starting an
// unauthenticated transport. That is a refusal, not a fallback.
bool ResolveLinuxWinnCarrierCredentials(LinuxWinnCarrierProfile* profile,
                                        std::string* error);

// Serialises the carrier profile document. Contains private PATHS; do not log.
std::string BuildLinuxWinnCarrierProfileJson(
    const LinuxWinnCarrierProfile& profile);

// Key names, modes and scalars only -- never a path. Safe to log.
std::string DescribeLinuxWinnCarrierProfile(
    const LinuxWinnCarrierProfile& profile);

// Writes the profile document to the private data directory with mode 0600 and
// returns its absolute path in *path. The mode is set BEFORE any bytes are
// written, so the document is never briefly world-readable.
//
// Returns false and sets *error when there is no legitimate per-user private
// directory. It never falls back to a shared location such as /tmp: a
// world-readable file naming every credential path on the device would hand an
// attacker the map even though it holds no key material itself.
bool WriteLinuxWinnCarrierProfile(const LinuxWinnCarrierProfile& profile,
                                  std::string* path,
                                  std::string* error);

// Builds the datapath.Config JSON for a Create frame. `allow_own_socket` is
// true here and only here: it is the desktop model datapath/carrier.go
// sanctions, and it is honest only because the caller has already installed the
// fwmark exclusion that keeps that socket out of the tunnel.
std::string BuildLinuxWinnConfigJson(const LinuxWinnParams& params);

// Binds the loopback seam. On success the socket is bound to 127.0.0.1 on an
// ephemeral port, *port carries it, and the caller owns the descriptor.
//
// This happens BEFORE the awg-quick configuration is written, for two reasons:
// the port has to be known to write it, and a bound socket means AmneziaWG's
// first handshake initiations queue in the receive buffer instead of drawing
// ICMP port-unreachable while the engine is still starting.
int BindLinuxWinnSeam(uint16_t* port, std::string* error);

// Chooses the UDP port the AmneziaWG engine will use as its ListenPort: one
// that is free on the IPv4 wildcard and, where IPv6 exists, on the IPv6
// wildcard, which is what AmneziaWG binds. The port is not held after return.
// A process that takes it first makes AmneziaWG's own bind fail; it never
// becomes the seam's peer, because StartLinuxWinnEngine refuses unless the
// kernel's UDP table shows the port held by a root-owned IPv4 wildcard socket
// and by no socket of any other user.
bool ReserveLinuxAwgListenPort(uint16_t* port, std::string* error);

// Starts the engine subprocess and the seam pump.
//
// `engine_path` is the winn-datapath binary, `seam_fd` the descriptor from
// BindLinuxWinnSeam. OWNERSHIP OF seam_fd PASSES TO THIS CALL ON EVERY OUTCOME,
// success or failure, so a caller has one rule to remember rather than two.
// Fail-closed: on false nothing is left running and *error says what happened.
bool StartLinuxWinnEngine(const std::string& engine_path,
                          int seam_fd,
                          const LinuxWinnParams& params,
                          std::string* error);

// Stops the engine and the pump. Safe when nothing is running.
void StopLinuxWinnEngine();

// True while the engine subprocess is running AND the pump has not torn the
// channel down.
//
// This is deliberately not "the process exists". A process that is alive with a
// dead channel carries nothing, and reporting that as a working tunnel is the
// exact failure mode this project has already been bitten by.
bool LinuxWinnEngineRunning();

// The engine's own status JSON, obtained with a StatusRequest frame, or "" when
// no engine is running. Non-secret counters and liveness only -- the engine
// never puts keys in it.
//
// IT DOES, however, carry `gateway_endpoint`. Log the COUNTERS out of this
// document, never the document itself.
std::string LinuxWinnEngineStatusJson();

// The transfer-proven half of the route-promotion gate.
//
// datapath/status.go is explicit that `up` means only "a socket exists" and
// must not gate route promotion. The honest signal is
// `transport_observed_both_ways`, which moves only when a datagram carrying the
// AmneziaWG transport-data header type, larger than a bare keepalive, crossed
// the carrier in that direction.
//
// Queries the running engine for its status, then answers with
// DecideWinnTransportGate() over the h1..h4 table THIS HOST latched when it
// started the session. *status_json and *reason are optional; *reason carries a
// non-secret sentence a caller can put in front of the operator, and never any
// part of the status document.
//
// THERE IS NO PATH THROUGH THIS FUNCTION THAT REPORTS PROOF IT DOES NOT HAVE.
// linux_tunnel_backend.cc:2759 used to have one: a missing
// `"awg_classification":"configured-h1h4"` substring in the engine's reply
// returned "converged", keeping the host's default route, DNS and IPv6 pointed
// into a carrier that was never proven to carry, with the only trace a
// g_warning line.
WinnTransportGate LinuxWinnTransportGate(std::string* status_json,
                                         std::string* reason);

// The h1..h4 classification verdict LATCHED when the running session started,
// or false when no engine is running.
//
// Exposed for the periodic datapath health check, which runs long after the
// params that started the session have left scope and must not re-derive the
// answer from anything the engine says. See linux_tunnel_backend.cc's
// WinnDatapathIsCarrying.
bool LinuxWinnEngineHeadersClassify();

// The SEAM's own counters as JSON, or "" when no engine is running.
//
// These are not the engine's counters and they are not a substitute for them.
// The engine's tx_rejected/rx_dropped count what the ENGINE REFUSED; they were
// zero throughout a 65.94% loss event because nothing ever reached the engine
// to be refused. These count what the HOST saw at the seam: how many datagrams
// arrived, how many this host dropped against its own bounded ring, how deep
// the receive backlog got, and what SO_RCVBUF the kernel actually granted.
//
// Every field is an integer this file counted itself -- no endpoint, no session
// id, no key material -- so unlike the status document this is safe to log in
// full. See docs/handoff/WINN_SEAM_BURST_BACKPRESSURE_20260805.md.
std::string LinuxWinnSeamStatsJson();

}  // namespace winsvpn::winn

#endif  // RUNNER_LINUX_WINN_HOST_H_
