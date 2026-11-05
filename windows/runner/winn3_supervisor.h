#ifndef RUNNER_WINN3_SUPERVISOR_H_
#define RUNNER_WINN3_SUPERVISOR_H_

// The Windows supervisor for Winn Protocol v3.
//
// # What was missing, stated plainly
//
// windows/winn3_engine/ is the adapter owner: it creates the Wintun adapter
// "winsvpn3" and relays RAW INNER IP PACKETS to cmd/winn-datapath's
// `device.kind: loopback-udp` seam. windows/runner/winn3_posture.h is the
// staged-posture policy: the narrow bootstrap, the promotion predicate, and the
// two per-platform command renderers. Both were written, both were tested, and
// NOTHING STARTED EITHER. RenderWindowsPostureCommands had no caller on
// Windows at all. This file is the missing middle: the party that starts the
// relay, starts the engine, tells each one the other's port, installs the
// bootstrap posture on the adapter, and widens it only when the engine says the
// datapath is proven.
//
// # This is NOT the winn/1 path and must never become it
//
// windows_winn_engine.{h,cpp} is the SHIPPING AmneziaWG path. There, the host's
// own AmneziaWG engine owns the one Wintun adapter, does all of the
// cryptography, and this process relays its ALREADY-ENCRYPTED outer datagrams
// to winn-datapath as payload class "awg-datagram". Nothing in this file
// touches that, and the two are kept apart by construction:
//
//	winn/1  windows/awg_engine   adapter "winsvpn"   payload awg-datagram
//	winn/3  windows/winn3_engine adapter "winsvpn3"  device  loopback-udp
//
// Two adapter names, two engines, two seam contracts, two config sections. The
// mistake that puts CLEARTEXT ON THE WIRE is wiring an inner-packet relay to a
// winn/1 engine, so the profile this file emits names `loopback-udp` and only
// `loopback-udp`, and the section it parses is `[winn3]` and never `[winn]`.
// ParseWinn3Section REFUSES a configuration that carries both.
//
// # THE MTU ARITHMETIC, and why one number is a trap
//
// Computed by cmd/winn-datapath, restated here because a host that gets it
// wrong produces a tunnel that reports up while every full-size flow vanishes:
//
//	tun.Overhead()                            =   29
//	carrier.Floor(1450, udp, tcp, tls)        = 1338  <- the session is pinned here
//	carrier.MaxMessageSizeFor(udp, ipv4, 1450)= 1422  <- what UDP ALONE would allow
//
//	ADAPTER MTU = 1338 - 29 = 1309   correct
//	TRAP        = 1422 - 29 = 1393   silently black-holes 1310..1393
//
// The floor is taken over EVERY class the session may escalate to, because a
// migration must never need a smaller packet than the one already in flight. An
// adapter sized from the dialled carrier accepts 84 bytes Windows will hand
// over, this supervisor will forward, and the tunnel will then drop as oversize
// -- visible only on full-size flows, only after the first migration, and in a
// country where nobody can attach a debugger.
//
// This supervisor does NOT compute the floor and does not trust the constant.
// It asks the engine, twice, and refuses on any disagreement:
//
//	1. `winn-datapath -winn3-profile P -winn3-print-sizing` publishes inner_mtu
//	   before anything touches the network. That number, not a constant, is what
//	   goes into `start mtu=<M>`.
//	2. Every subsequent status document republishes inner_mtu, and
//	   VerifyAppliedMtuStillAgrees refuses to promote if it ever differs from
//	   the number the adapter was actually built with.
//
// kShippingFloorInnerMTU is what this lane EXPECTS at the shipping floor and is
// reported for diagnosis. kDialledUdpV4InnerMTU is refused outright, by name,
// because a range check would accept it and it is the one wrong value that
// looks entirely reasonable.
//
// # 1139 < 1280 means inner IPv6 is arithmetically impossible
//
// RFC 8200's minimum link MTU is 1280. At the shipping floor the inner MTU is
// 1139, so no inner IPv6 packet can be carried at all. The bootstrap posture's
// "no IPv6" rule is therefore FORCED BY ARITHMETIC and is not a policy choice
// that a later hand may relax for convenience. BuildPromotedPosture already
// refuses IPv6 unless the engine's own `inner_ipv6` is true; this file never
// asks for IPv6 that the engine has not published.
//
// # Everything decidable lives here, in standard C++17
//
// Same rule as winn3_posture.h, winn_frame.h and windows_winn_engine.h's gate
// predicate, and for the same reason: there is no Windows host on the machine
// where this project is developed. A decision that only Windows can execute is
// a decision that does not get tested, and these decide when a user's default
// route moves. This header has no <windows.h>, no socket and no process; it
// parses, validates, renders and refuses. Its tests are
// windows/runner/winn3_supervisor_test.cc, which builds and RUNS on macOS.
//
// The Windows-only half -- the processes, the pipes, the netsh execution and
// the route pin -- is declared at the bottom under WINS_TUNNEL_SERVICE_CORE and
// implemented in winn3_supervisor.cpp.

#include <cctype>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "winn3_posture.h"

namespace winsvpn::winn3 {

// --- the numbers ------------------------------------------------------------

// kShippingFloorInnerMTU is carrier.Floor(carrier.DefaultPathMTU, udp, tcp,
// tls) minus tun.Overhead(). Expected, reported, never assumed: a wider
// measured path legitimately yields a larger one, and the engine is the
// authority.
//
// MOVED 1139 -> 1309 ON 2026-08-10 with the fleet default (1280 -> 1450). The
// old value was BELOW RFC 8200's 1280-byte minimum link MTU, which is why the
// default moved: at 1139 inner, no host could put IPv6 on the interface at all.
// This host never assigns inner IPv6 so it never met the kernel refusal — it
// simply left the user's IPv6 on the physical interface beside a promoted v4
// tunnel. See InnerIPv6IsArithmeticallyPossible below, which now answers TRUE
// on the default for the first time.
inline constexpr int kShippingFloorInnerMTU = 1309;

// kDialledUdpV4InnerMTU is the trap. Refused by name. Moved with the default;
// the GAP it describes is still 84 bytes, because that is the difference
// between TLS-over-IPv6 and UDP-over-IPv4 overhead and not a property of the
// path.
inline constexpr int kDialledUdpV4InnerMTU = 1393;

// kIPv6MinLinkMTU is RFC 8200's minimum link MTU. It is defined once, in
// winn3_posture.h, which this file includes above; a second definition here
// made this header fail to compile (redefinition error) once the sink work
// moved the constant into the posture policy. Single definition, one owner.

// Mirrors tun.MinInnerMTUv4 and tun.MaxIPPacket. Below the first the tun layer
// refuses to build at all, so accepting it here would only move the refusal
// somewhere less legible.
inline constexpr int kMinInnerMTU = 576;
inline constexpr int kMaxInnerMTU = 65535;

// --- the contract strings ---------------------------------------------------
//
// Each is a restatement of a Go constant, not an opinion. They are gathered
// here so that a drift shows up as one edit rather than as a string literal
// buried in a launch path.

// winn3_profile.go's winn3ProfileVersion.
inline constexpr char kProfileVersion[] = "winn3-host/1";
// winn3_profile.go's winn3DeviceLoopbackUDP and winn3RoleClient.
inline constexpr char kDeviceLoopbackUdp[] = "loopback-udp";
inline constexpr char kRoleClient[] = "client";
// main_windows.go's adapterName. The supervisor addresses the interface by this
// name when it installs the posture, and cross-checks it against what the relay
// reports rather than assuming.
inline constexpr char kRelayAdapterName[] = "winsvpn3";
// v1 AWG adapter alias. The tunnel-bound internet probe must bind this name
// for a live winn/1 session and must never confuse it with winsvpn3 leftovers.
inline constexpr char kWinn1AdapterName[] = "winsvpn";
// winn3_run.go's stderr announcement, verbatim up to the port.
inline constexpr char kEngineSeamPortPrefix[] =
    "winn-datapath: winn3 loopback seam engine port ";
// main_windows.go's first stdout line.
inline constexpr char kRelayHostPortPrefix[] = "host-port ";
// main_windows.go's readiness line.
inline constexpr char kRelayReadyPrefix[] = "ready ";

// Dual-signature attestation public keys (docs/DUAL_SIGNATURE_SPEC.md). The
// served `[winn]` pair is optional as a unit: both present, or both absent.
// Sizes are the raw public keys after one standard-alphabet base64 decode;
// the engine's readDualAuthPublic then hex-decodes the files this host writes.
inline constexpr size_t kDualAuthEd25519Bytes = 32;
inline constexpr size_t kDualAuthMldsa65Bytes = 1952;
inline constexpr char kDualAuthEd25519File[] = "auth_ed25519.pub";
inline constexpr char kDualAuthMldsa65File[] = "auth_mldsa65.pub";

// --- the host configuration -------------------------------------------------

// Winn3HostConfig is the `[winn3]` section, parsed.
//
// Every field maps ONE TO ONE onto winn3_profile.go's document. That is
// deliberate: a translation layer between the section a server serves and the
// profile the engine reads is a layer that can rename a field, and the field it
// would rename is the one that decides whether the tunnel encrypts.
struct Winn3HostConfig {
  // The carrier. `endpoint` is an IP literal "host:port" and NEVER a hostname:
  // resolving one here would be a DNS lookup on the censored path, for a tunnel
  // whose entire staged posture exists so that no resolver is touched until the
  // datapath is proven.
  std::string endpoint;
  std::string carrier_class;  // "udp", "tcp" or "tls"

  // Every class the session may escalate TO, in order. The message floor is
  // computed over this list, so a plan that omits a class the session later
  // migrates to is exactly the 84-byte black hole above.
  std::vector<std::string> plan;

  // Zero means carrier.DefaultPathMTU.
  int path_mtu = 0;

  // Binds the admission tag to one gateway so an initiation captured at gateway
  // A cannot be replayed at gateway B while both share an admission key.
  std::string gateway_id;

  // Node binding. Required on BOTH served `[winn] carrier = winn3` and local
  // `[winn3] enabled = true`. A served-only check was a skip: the local
  // spelling could start a session with no selected-node identity at all.
  // Values are strict ASCII slugs; Unicode is refused, not folded.
  std::string descriptor_node;
  std::string selected_node;

  std::string inner_v4;
  std::string inner_v6;
  std::string router_v4;
  std::string router_v6;

  // The gateway's inner DNS responder address, served `[winn]` spelling
  // `inner_resolver_v4`, off the same signed descriptor `router_v4` arrives on.
  //
  // Parsed, stored, and since 2026-08-12 CONSUMED -- by derivation, never by
  // assignment. PostureInputFrom hands it to winn3_posture.h, whose
  // `resolvers::NotInnerReason` checks it for inner-ness by address shape the
  // way Apple's `WinsWinn3Resolvers` and Android's `WinnV3Resolvers` already
  // do, against the same hard 0xFFFFFF00 /24 floor. Nothing anywhere sets
  // `dns_servers_are_inner` from this value: that boolean is the local
  // `[winn3]` declaration and a served session does not get to declare.
  std::string inner_resolver_v4;

  // PATHS, never key material. The engine opens these itself, under its own
  // identity; a host that forwards a profile therefore never holds a key.
  //
  // A `[winn3]` configuration names them directly. A SERVED `[winn]`
  // configuration cannot -- the control plane does not know this device's
  // filesystem -- so it carries the three values below instead and this
  // supervisor writes the files itself, with the same DACL it writes the
  // profile with. `BuildWinn3ProfileJson` still emits only paths either way,
  // which is the property that matters: the document the engine reads holds no
  // key material.
  std::string static_key_path;
  std::string gateway_static_key_path;
  std::string admission_path;
  std::string dual_auth_ed25519_pub_path;
  std::string dual_auth_mldsa65_pub_path;

  // The served `[winn]` spelling: base64 over the value itself.
  //
  //   static_private   base64 over this device's 32-byte X25519 private key
  //   gateway_static   base64 over the gateway's 32-byte X25519 public key
  //   admission_key    base64 over the admission key FILE'S BYTES -- keygen's
  //                    64 ASCII hex characters, opaque and never hex-decoded
  //   auth_ed25519     base64 over the gateway's 32-byte Ed25519 public key
  //   auth_mldsa65     base64 over the gateway's 1952-byte ML-DSA-65 public key
  //
  // Empty on a `[winn3]` configuration, and the paths are empty on a `[winn]`
  // one. ParseWinn3Section refuses a configuration that mixes them: two sources
  // for one key is a question about which one won, and the answer is invisible
  // from either end of a session. The dual-auth pair is both-or-neither.
  std::string static_private_b64;
  std::string gateway_static_b64;
  std::string admission_key_b64;
  std::string auth_ed25519_b64;
  std::string auth_mldsa65_b64;

  // Which section this came from: "winn3" or "winn". Recorded rather than
  // inferred so a diagnostic can say which document an operator actually wrote,
  // and so a test can prove the two spellings produce the SAME session.
  std::string section;

  // Applied only at promotion, ignored entirely while bootstrapping.
  std::vector<std::string> full_routes;
  std::vector<std::string> dns_servers;
  bool dns_servers_are_inner = false;

  bool fast_pq = false;
};

namespace supervisor_detail {

inline bool Fail(std::string* error, const std::string& message) {
  if (error != nullptr) {
    *error = message;
  }
  return false;
}

inline std::string Trim(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return std::string();
  }
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

inline std::string LowerAscii(std::string value) {
  for (char& c : value) {
    c = static_cast<char>(
        std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

// DecodeBase64 is STRICT standard-alphabet base64, or false.
//
// Strict is the load-bearing word, and the reason is the whole subject of this
// file's contract. Every byte-valued field on the ML-DSA-65-signed gateway
// descriptor is base64 and reaches `[winn]` untouched; a lenient decoder that
// tolerated whitespace, the URL-safe alphabet or missing padding would turn a
// mangled descriptor value into PLAUSIBLE BYTES. Plausible bytes are how every
// defect this contract exists to prevent presents: a tag the gateway cannot
// verify, and no answer from anywhere, on a network where "no answer" is what
// censorship looks like too.
inline bool DecodeBase64(const std::string& value, std::string* out) {
  if (out == nullptr || value.empty() || value.size() % 4 != 0) {
    return false;
  }
  auto sextet = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  size_t padding = 0;
  while (padding < 2 && value.size() > padding &&
         value[value.size() - 1 - padding] == '=') {
    padding++;
  }
  std::string decoded;
  decoded.reserve(value.size() / 4 * 3);
  for (size_t i = 0; i < value.size(); i += 4) {
    uint32_t block = 0;
    int bits = 0;
    for (size_t j = 0; j < 4; ++j) {
      const char c = value[i + j];
      if (c == '=') {
        // Padding is only ever the final one or two characters.
        if (i + 4 != value.size() || j < 4 - padding) {
          return false;
        }
        block <<= 6;
        continue;
      }
      const int s = sextet(c);
      if (s < 0) {
        return false;
      }
      block = (block << 6) | static_cast<uint32_t>(s);
      bits += 6;
    }
    for (int shift = 16, produced = 0; produced < bits / 8; shift -= 8, ++produced) {
      decoded.push_back(static_cast<char>((block >> shift) & 0xFF));
    }
  }
  *out = decoded;
  return true;
}

// LowerHex is the encoding winn-datapath's readDualAuthPublic decodes. The
// dual-auth public-key files are hex, not raw bytes: that decoder hex-decodes
// and has no raw-length fallback.
inline std::string LowerHex(const std::string& raw) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(raw.size() * 2);
  for (size_t i = 0; i < raw.size(); ++i) {
    const unsigned char byte = static_cast<unsigned char>(raw[i]);
    out[i * 2] = kDigits[byte >> 4];
    out[i * 2 + 1] = kDigits[byte & 0x0F];
  }
  return out;
}

// SplitList reads a comma-separated list, dropping empty elements. Whitespace
// around an element is trimmed; whitespace INSIDE one is not, so a malformed
// address stays malformed and is refused by whatever applies it rather than
// silently repaired here.
inline std::vector<std::string> SplitList(const std::string& value) {
  std::vector<std::string> out;
  size_t begin = 0;
  while (begin <= value.size()) {
    const size_t comma = value.find(',', begin);
    const size_t end = comma == std::string::npos ? value.size() : comma;
    const std::string element = Trim(value.substr(begin, end - begin));
    if (!element.empty()) {
      out.push_back(element);
    }
    if (comma == std::string::npos) {
      break;
    }
    begin = comma + 1;
  }
  return out;
}

// ParseDecimal reads a non-negative decimal integer and nothing else. A leading
// sign, embedded whitespace, a trailing unit and an overflow are all refusals:
// this reads ports and MTUs, and a partially-parsed one of either is worse than
// none.
inline bool ParseDecimal(const std::string& text, int64_t max, int64_t* out) {
  if (text.empty() || text.size() > 19) {
    return false;
  }
  int64_t value = 0;
  for (const char raw : text) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (std::isdigit(c) == 0) {
      return false;
    }
    const int64_t digit = static_cast<int64_t>(c - '0');
    if (value > (max - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  *out = value;
  return true;
}

inline bool IsTruthy(const std::string& value) {
  const std::string lowered = LowerAscii(Trim(value));
  return lowered == "true" || lowered == "1" || lowered == "yes" ||
         lowered == "y";
}

inline bool IsFalsy(const std::string& value) {
  const std::string lowered = LowerAscii(Trim(value));
  return lowered == "false" || lowered == "0" || lowered == "no" ||
         lowered == "n";
}

// EscapeJson renders a JSON string body.
//
// It exists because this document names WINDOWS PATHS, and a Windows path is
// full of backslashes. `C:\ProgramData\WinsVPN\winn3.key` emitted raw produces
// `\P`, `\W` and `\w` -- invalid JSON escapes -- and Go's decoder rejects the
// whole profile with a message about the document rather than about the path.
// Control characters are escaped numerically rather than dropped, so a value
// that should never have contained one is still visible in the refusal.
inline std::string EscapeJson(const std::string& value) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(value.size() + 8);
  for (const char raw : value) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(kHex[(c >> 4) & 0x0f]);
          out.push_back(kHex[c & 0x0f]);
        } else {
          out.push_back(raw);
        }
        break;
    }
  }
  return out;
}

inline std::string JsonString(const std::string& value) {
  return "\"" + EscapeJson(value) + "\"";
}

inline std::string JsonStringArray(const std::vector<std::string>& values) {
  std::string out = "[";
  for (size_t i = 0; i < values.size(); ++i) {
    if (i != 0) {
      out += ",";
    }
    out += JsonString(values[i]);
  }
  out += "]";
  return out;
}

// TakeTrailingPort reads the decimal port at the end of a line that begins with
// `prefix`. The prefix must match EXACTLY at position zero: these lines come
// from two different child processes on two different pipes, and a substring
// match would let one process's diagnostic be read as the other's port.
inline bool TakeTrailingPort(const std::string& line, const char* prefix,
                             int* port) {
  if (port == nullptr) {
    return false;
  }
  const std::string trimmed = Trim(line);
  const std::string expected(prefix);
  if (trimmed.size() <= expected.size() ||
      trimmed.compare(0, expected.size(), expected) != 0) {
    return false;
  }
  int64_t value = 0;
  if (!ParseDecimal(Trim(trimmed.substr(expected.size())), 65535, &value) ||
      value <= 0) {
    return false;
  }
  *port = static_cast<int>(value);
  return true;
}

}  // namespace supervisor_detail

// SplitWinn3Endpoint splits "1.2.3.4:443" or "[2001:db8::1]:443" into host and
// port, refusing anything that is not an IP literal with a nonzero port.
//
// It is the host-side restatement of winn3ValidateEndpoint. A shape test rather
// than a parser -- the engine parses it with netip and refuses authoritatively
// -- but it has to exist here, because the host part is the address this
// supervisor pins a physical /32 route to BEFORE the engine has ever been
// started, and pinning the wrong thing is how the engine's own carrier
// datagrams end up inside the tunnel they carry.
//
// A hostname is refused rather than resolved. Resolving one here would be a DNS
// lookup on the censored path, for a tunnel whose entire staged posture exists
// so that no resolver is touched until the datapath is proven.
inline bool SplitWinn3Endpoint(const std::string& endpoint, std::string* host,
                               std::string* port) {
  using namespace supervisor_detail;  // NOLINT(build/namespaces)
  const std::string value = Trim(endpoint);
  if (value.empty()) {
    return false;
  }
  std::string parsed_host;
  std::string parsed_port;
  if (value.front() == '[') {
    const auto close = value.find(']');
    if (close == std::string::npos || close + 1 >= value.size() ||
        value[close + 1] != ':') {
      return false;
    }
    parsed_host = value.substr(1, close - 1);
    parsed_port = value.substr(close + 2);
    if (parsed_host.find(':') == std::string::npos) {
      return false;  // Bracketed form is for IPv6 only.
    }
  } else {
    const auto colon = value.rfind(':');
    if (colon == std::string::npos) {
      return false;
    }
    parsed_host = value.substr(0, colon);
    parsed_port = value.substr(colon + 1);
    if (parsed_host.find(':') != std::string::npos) {
      return false;  // Unbracketed IPv6 is ambiguous with the port separator.
    }
  }
  int64_t port_number = 0;
  if (!ParseDecimal(parsed_port, 65535, &port_number) || port_number == 0) {
    return false;
  }
  if (parsed_host.empty()) {
    return false;
  }
  // An IP literal is digits, dots, colons and hex. A hostname is not. This does
  // not accept every literal netip does; it refuses everything netip would
  // refuse plus a little more, and the extra refusals are all hostnames.
  bool has_separator = false;
  for (const char raw : parsed_host) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (c == '.' || c == ':') {
      has_separator = true;
      continue;
    }
    if (std::isxdigit(c) == 0) {
      return false;
    }
  }
  if (!has_separator) {
    return false;
  }
  if (host != nullptr) {
    *host = parsed_host;
  }
  if (port != nullptr) {
    *port = parsed_port;
  }
  return true;
}

namespace supervisor_detail {

inline bool LooksLikeIpLiteralEndpoint(const std::string& endpoint) {
  return SplitWinn3Endpoint(endpoint, nullptr, nullptr);
}

}  // namespace supervisor_detail

// --- selecting the v3 path --------------------------------------------------

// kCarrierWinn3 is `[winn] carrier`'s value for a STANDALONE v3 session --
// lib/winn_protocol_dispatch.dart's kWinnCarrierWinn3 and the control plane's
// WINN3_CARRIER_WINN3.
inline constexpr char kCarrierWinn3[] = "winn3";

namespace supervisor_detail {

// SectionKeyValue reads one key out of one section, without parsing the rest.
//
// The three selection predicates below each walked the file themselves, with
// three copies of the same loop. Three copies of a loop that decides WHICH
// PROTOCOL STARTS is three chances for one of them to disagree with the others
// about a comment character or a section header, and the disagreement would be
// silent in exactly the direction that matters.
inline std::string SectionKeyValue(const std::string& raw_config,
                                   const std::string& want_section,
                                   const std::string& want_key) {
  std::string section;
  size_t begin = 0;
  while (begin <= raw_config.size()) {
    const size_t newline = raw_config.find('\n', begin);
    const size_t end =
        newline == std::string::npos ? raw_config.size() : newline;
    const std::string line = Trim(raw_config.substr(begin, end - begin));
    begin = newline == std::string::npos ? raw_config.size() + 1 : newline + 1;
    if (line.empty() || line.front() == '#' || line.front() == ';') {
      continue;
    }
    if (line.size() >= 3 && line.front() == '[' && line.back() == ']') {
      section = LowerAscii(line.substr(1, line.size() - 2));
      continue;
    }
    if (section != want_section) {
      continue;
    }
    const auto equals = line.find('=');
    if (equals != std::string::npos &&
        LowerAscii(Trim(line.substr(0, equals))) == want_key) {
      return Trim(line.substr(equals + 1));
    }
  }
  return std::string();
}

// The `[winn]` carrier, lowercased. Empty when the section or the key is absent.
inline std::string WinnSectionCarrier(const std::string& raw_config) {
  return LowerAscii(SectionKeyValue(raw_config, "winn", "carrier"));
}

}  // namespace supervisor_detail

// NormalizeWinn3NodeIdentity is the hub slug alphabet, ASCII-only.
//
// Trim ASCII whitespace, reject any byte above 0x7F, fold A-Z only, then
// require `^[a-z0-9][a-z0-9-]{1,39}$`. Returns false for Unicode, empty,
// or out-of-alphabet values. Never Unicode-folds: Dart's `toLowerCase()`
// maps U+212A KELVIN SIGN onto `k`, and `std::tolower` is locale-dependent,
// so a selected node of `K1` must not match a signed `k1`.
inline bool NormalizeWinn3NodeIdentity(const std::string& raw, std::string* out) {
  if (out == nullptr) {
    return false;
  }
  out->clear();
  for (char ch : raw) {
    if (static_cast<unsigned char>(ch) > 0x7F) {
      return false;
    }
  }
  const std::string trimmed = supervisor_detail::Trim(raw);
  if (trimmed.empty()) {
    return false;
  }
  std::string lowered;
  lowered.reserve(trimmed.size());
  for (char ch : trimmed) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c >= 'A' && c <= 'Z') {
      lowered.push_back(static_cast<char>(c + ('a' - 'A')));
    } else {
      lowered.push_back(static_cast<char>(c));
    }
  }
  if (lowered.size() < 2 || lowered.size() > 40) {
    return false;
  }
  const unsigned char first = static_cast<unsigned char>(lowered[0]);
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9'))) {
    return false;
  }
  for (size_t i = 1; i < lowered.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(lowered[i]);
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
      continue;
    }
    return false;
  }
  *out = lowered;
  return true;
}

// --- selecting the v3 path, continued ---------------------------------------
//
// ===========================================================================
// THE DISCRIMINATOR IS `carrier`, AND `[winn3]` IS THE LOCAL SPELLING
// ===========================================================================
//
// This file used to state, as a safety rule, that "the section it parses is
// `[winn3]` and never `[winn]`". The reasoning was sound and the consequence
// was not: `[winn3]` HAS NO PRODUCER. lib/winn_protocol_dispatch.dart writes
// `[winn]` with `carrier = winn3`, Apple reads it, and the control plane has
// served it since 2026-08-09. Nothing anywhere emits `[winn3]`, so this
// supervisor could be driven only by a document written by hand -- which is why
// Windows appears in the `served-config-key-names-differ-per-host` divergence.
//
// What the old rule was really protecting is REAL, and it is kept: an
// inner-packet relay must never be wired to a winn/1 engine, because that
// mistake either puts cleartext on the wire or double-encrypts everything. But
// the section name was never what protected it. `carrier` is, and it always
// was: windows_winn_engine.cpp's ParseWindowsWinnSection REFUSES any carrier
// but `direct-awg`, by name, before it sweeps a single other key. So the two
// paths are separated by the one field that already separates them, on both
// sides, and a served standalone config now selects v3 here instead of being
// handed to a winn/1 parser that refuses it.
//
//	[winn]  carrier = winn3       -> v3.  winn/1 refuses it by name.
//	[winn]  carrier = direct-awg  -> winn/1. v3 does not select.
//	[winn3] enabled = true        -> v3, the local/lab spelling.
//	both of the last two          -> REFUSED, as before.

// ConfigSelectsWinn3 is true for `[winn3] enabled = true` (the local spelling)
// or `[winn] carrier = winn3` (the served one).
//
// A configuration selecting neither selects no v3 path, which is the shipping
// AmneziaWG behaviour and is unchanged.
inline bool ConfigSelectsWinn3(const std::string& raw_config) {
  if (supervisor_detail::IsTruthy(
          supervisor_detail::SectionKeyValue(raw_config, "winn3", "enabled"))) {
    return true;
  }
  return supervisor_detail::WinnSectionCarrier(raw_config) == kCarrierWinn3;
}

// True for a configuration carrying `[winn] enabled = true` for the winn/1
// AmneziaWG path -- that is, `[winn]` enabled with a carrier that is NOT winn3.
//
// Used only to refuse the combination; the winn/1 host makes its own decision
// with its own parser and this never speaks for it. A `[winn]` section naming
// `carrier = winn3` is a v3 configuration and is NOT a winn/1 one, which is the
// whole point of reading the carrier here: without it, every served standalone
// config would look like both at once and be refused as a contradiction.
inline bool ConfigSelectsWinn1(const std::string& raw_config) {
  if (supervisor_detail::WinnSectionCarrier(raw_config) == kCarrierWinn3) {
    return false;
  }
  return supervisor_detail::IsTruthy(
      supervisor_detail::SectionKeyValue(raw_config, "winn", "enabled"));
}

// ParseWinn3Section parses and validates `[winn3]`.
//
// AN UNRECOGNISED KEY IS A REFUSAL rather than something to drop, matching
// ParseWindowsWinnSection, WinnEngineConfig.from, ParseLinuxWinnSection and
// loadWinn3Profile's DisallowUnknownFields. A host that misspells a key and is
// told nothing believes a setting took effect that did not, and the settings
// that could silently not take effect here are the migration plan and the
// resolver declaration.
//
// Never partially fills *out.
inline bool ParseWinn3Section(const std::string& raw_config,
                              Winn3HostConfig* out, std::string* error) {
  using namespace supervisor_detail;  // NOLINT(build/namespaces)
  if (out == nullptr) {
    return Fail(error, "no winn3 configuration to fill");
  }
  *out = Winn3HostConfig();
  if (!ConfigSelectsWinn3(raw_config)) {
    return Fail(error, "this configuration does not select Winn Protocol v3");
  }
  if (ConfigSelectsWinn1(raw_config)) {
    return Fail(
        error,
        "this configuration selects BOTH winn/1 and winn/3. They are "
        "different protocols with different adapters and different seam "
        "payloads -- winn/1 relays AmneziaWG outer datagrams that are already "
        "encrypted, winn/3 relays raw inner packets to the layer that encrypts "
        "them -- so a host that started both would either put cleartext on the "
        "wire or double-encrypt everything. The connection was stopped rather "
        "than one of the two being chosen silently.");
  }

  // WHICH SPELLING THIS CONFIGURATION USES. `[winn3]` is the local one and
  // names key files; `[winn]` with `carrier = winn3` is the one the control
  // plane serves and carries key VALUES. They are parsed by the same loop into
  // the same struct, so a served session and a hand-written one cannot diverge
  // in anything except where the key material came from.
  const bool served =
      !IsTruthy(SectionKeyValue(raw_config, "winn3", "enabled")) &&
      WinnSectionCarrier(raw_config) == kCarrierWinn3;
  const std::string want_section = served ? "winn" : "winn3";

  Winn3HostConfig parsed;
  parsed.section = want_section;
  bool saw_class = false;
  bool saw_descriptor_node = false;
  bool saw_selected_node = false;
  std::string section;
  size_t begin = 0;
  while (begin <= raw_config.size()) {
    const size_t newline = raw_config.find('\n', begin);
    const size_t end =
        newline == std::string::npos ? raw_config.size() : newline;
    const std::string line = Trim(raw_config.substr(begin, end - begin));
    begin = newline == std::string::npos ? raw_config.size() + 1 : newline + 1;
    if (line.empty() || line.front() == '#' || line.front() == ';') {
      continue;
    }
    if (line.size() >= 3 && line.front() == '[' && line.back() == ']') {
      section = LowerAscii(line.substr(1, line.size() - 2));
      continue;
    }
    if (section != want_section) {
      continue;
    }
    const auto equals = line.find('=');
    if (equals == std::string::npos) {
      return Fail(error, "the [" + want_section + "] line \"" + line +
                             "\" is not key = value");
    }
    const std::string key = LowerAscii(Trim(line.substr(0, equals)));
    const std::string value = Trim(line.substr(equals + 1));
    // --- the served `[winn]` spellings, handled first -----------------------
    //
    // Each maps ONE TO ONE onto a `[winn3]` field. They are separate branches
    // rather than aliases so that a `[winn3]` document naming `inner_router_v4`
    // -- or a `[winn]` one naming `router_v4` -- is still an UNRECOGNISED KEY
    // and is refused. Two names silently accepted in one section is the state
    // this whole exercise exists to end.
    if (served && key == "carrier") {
      // Already read, and already the reason this section is being parsed at
      // all. Re-checked rather than skipped so a section that named winn3 in
      // one place and something else in another cannot pass.
      if (LowerAscii(value) != kCarrierWinn3) {
        return Fail(error,
                    "[winn] carrier is \"" + value +
                        "\", which does not select Winn Protocol v3");
      }
    } else if (served && key == "inner_router_v4") {
      parsed.router_v4 = value;
    } else if (served && key == "inner_resolver_v4") {
      // KNOWN, STORED, AND CONSUMED BY DERIVATION.
      //
      // The gateway's inner DNS responder address, off the same ML-DSA-65-signed
      // descriptor `inner_router_v4` arrives on.
      //
      // The branch had to exist BEFORE the field was ever emitted, and that is
      // still why it is separate: the `else` below refuses an unrecognised
      // `[winn]` key outright, so a Windows host without this branch would not
      // degrade DNS the day the control plane emits it -- it would refuse the
      // whole served configuration and lose standalone v3 entirely. The `psk`
      // branch a few lines down was added for precisely this reason and says so
      // in the same words.
      //
      // Since 2026-08-12 the value is also USED. It is carried into
      // `PostureInput::inner_resolver_v4` by PostureInputFrom and DERIVED
      // against in winn3_posture.h's `namespace resolvers`, which mirrors
      // Apple's `WinsWinn3Resolvers` and Android's `WinnV3Resolvers` clause for
      // clause against the same 0xFFFFFF00 /24 floor.
      //
      // What is still true, and is the line that must not be crossed: nothing
      // sets `dns_servers_are_inner` from this value. That boolean is a
      // DECLARATION read from a local `[winn3]` file written by somebody
      // holding the machine, and assigning it from a served field would import
      // a transported claim into the one place that was allowed a local one.
      // The derived path does not consult the boolean at all; it re-derives.
      parsed.inner_resolver_v4 = value;
    } else if (served && key == "static_private") {
      parsed.static_private_b64 = value;
    } else if (served && key == "gateway_static") {
      parsed.gateway_static_b64 = value;
    } else if (served && key == "admission_key") {
      parsed.admission_key_b64 = value;
    } else if (served && key == "auth_ed25519") {
      parsed.auth_ed25519_b64 = value;
    } else if (served && key == "auth_mldsa65") {
      parsed.auth_mldsa65_b64 = value;
    } else if (served && key == "carrier_classes") {
      // The served name for `plan`. Same value, same meaning: EVERY class the
      // session may escalate to, which is what the message floor -- and
      // therefore the adapter MTU -- is computed over.
      parsed.plan = SplitList(LowerAscii(value));
    } else if (served && key == "psk") {
      // Optional, absent in the shipping deployment, and consumed by the engine
      // rather than by this supervisor. Named so it is a KNOWN key: an
      // unrecognised one is a refusal here, so leaving it out would turn a
      // perfectly good served config into a Windows-only failure.
    } else if (served && key == "session_id") {
      // Opaque correlation id, echoed by the engine. Same reasoning as `psk`.
    } else if (key == "node") {
      // Shared by served `[winn]` and local `[winn3]`. A `served &&` guard
      // here was the skip: the local spelling treated `node` as unknown or
      // omitted it, and started without binding the signed descriptor.
      if (saw_descriptor_node) {
        return Fail(error, "[" + want_section +
                               "] node is duplicated: an alias conflict is "
                               "refused as a node identity failure");
      }
      saw_descriptor_node = true;
      if (!NormalizeWinn3NodeIdentity(value, &parsed.descriptor_node)) {
        return Fail(error, "[" + want_section +
                               "] node is not a strict ASCII node identity");
      }
    } else if (key == "selected_node") {
      if (saw_selected_node) {
        return Fail(error, "[" + want_section +
                               "] selected_node is duplicated: an alias "
                               "conflict is refused as a node identity failure");
      }
      saw_selected_node = true;
      if (!NormalizeWinn3NodeIdentity(value, &parsed.selected_node)) {
        return Fail(error, "[" + want_section +
                               "] selected_node is not a strict ASCII node "
                               "identity");
      }
    } else if (key == "enabled") {
      if (!IsTruthy(value) && !IsFalsy(value)) {
        return Fail(error,
                    "[" + want_section + "] enabled is neither true nor false");
      }
    } else if (key == "endpoint") {
      parsed.endpoint = value;
    } else if (!served && key == "class") {
      parsed.carrier_class = LowerAscii(value);
      saw_class = true;
    } else if (!served && key == "plan") {
      parsed.plan = SplitList(LowerAscii(value));
    } else if (key == "path_mtu") {
      int64_t number = 0;
      if (!ParseDecimal(value, kMaxInnerMTU, &number)) {
        return Fail(error,
                    "[" + want_section + "] path_mtu is not a usable number");
      }
      parsed.path_mtu = static_cast<int>(number);
    } else if (key == "gateway_id") {
      parsed.gateway_id = value;
    } else if (key == "inner_v4") {
      parsed.inner_v4 = value;
    } else if (!served && key == "inner_v6") {
      parsed.inner_v6 = value;
    } else if (!served && key == "router_v4") {
      parsed.router_v4 = value;
    } else if (!served && key == "router_v6") {
      parsed.router_v6 = value;
    } else if (!served && key == "static_key_path") {
      parsed.static_key_path = value;
    } else if (!served && key == "gateway_static_key_path") {
      parsed.gateway_static_key_path = value;
    } else if (!served && key == "admission_path") {
      parsed.admission_path = value;
    } else if (!served && key == "routes") {
      parsed.full_routes = SplitList(value);
    } else if (!served && key == "dns") {
      parsed.dns_servers = SplitList(value);
    } else if (!served && key == "dns_are_inner") {
      if (!IsTruthy(value) && !IsFalsy(value)) {
        return Fail(error, "[winn3] dns_are_inner is neither true nor false");
      }
      parsed.dns_servers_are_inner = IsTruthy(value);
    } else if (!served && key == "fast_pq") {
      if (!IsTruthy(value) && !IsFalsy(value)) {
        return Fail(error, "[winn3] fast_pq is neither true nor false");
      }
      parsed.fast_pq = IsTruthy(value);
    } else {
      return Fail(error,
                  "[" + want_section + "] carries the unrecognised key \"" +
                      key +
                      "\". It is refused rather than ignored, because a "
                      "dropped key looks exactly like a key that took effect.");
    }
  }

  if (served) {
    // THE DIALLED CLASS A SERVED SECTION DOES NOT NAME.
    //
    // `carrier_classes` is the MIGRATION PLAN -- every class the session may
    // escalate TO -- and never the one dialled; the field contract has no key
    // for the dialled class because `cmd/winn-datapath` can dial exactly one.
    // A tls carrier needs a *tls.Config with the root CA, the ECH list and the
    // client certificate behind it, and none of that reaches that process.
    //
    // So udp is not a default charged here for convenience; it is the only
    // answer, and a plan that does not contain it is one this engine cannot
    // dial at all. Refusing names it while the cost is a retry.
    parsed.carrier_class = "udp";
    saw_class = true;
  }

  const std::string plan_key = served ? "carrier_classes" : "plan";
  if (!LooksLikeIpLiteralEndpoint(parsed.endpoint)) {
    return Fail(error,
                "[" + want_section +
                    "] endpoint must be an IP literal with a port. A "
                    "hostname here would be resolved on the censored path, for a "
                    "tunnel whose staged posture exists so that no resolver is "
                    "touched until the datapath is proven.");
  }
  if (!saw_class || (parsed.carrier_class != "udp" &&
                     parsed.carrier_class != "tcp" &&
                     parsed.carrier_class != "tls")) {
    return Fail(error, "[winn3] class must be udp, tcp or tls");
  }
  if (parsed.plan.empty()) {
    return Fail(error,
                "[" + want_section + "] " + plan_key +
                    " is empty. It must name EVERY class the session "
                    "may escalate to, because the message floor -- and therefore "
                    "the adapter MTU -- is computed over it.");
  }
  bool dialled_is_planned = false;
  for (const std::string& entry : parsed.plan) {
    if (entry != "udp" && entry != "tcp" && entry != "tls") {
      return Fail(error, "[" + want_section + "] " + plan_key +
                             " names the unknown class \"" + entry +
                             "\"; use udp, tcp or tls");
    }
    if (entry == parsed.carrier_class) {
      dialled_is_planned = true;
    }
  }
  if (!dialled_is_planned) {
    if (served) {
      return Fail(error,
                  "[winn] carrier_classes does not name udp, and udp is the "
                  "only class this engine can dial: a tls carrier needs a "
                  "*tls.Config with the root CA, the ECH list and the client "
                  "certificate behind it, and none of that reaches the engine "
                  "process. A plan without udp is one no session could start "
                  "from, so it is refused here rather than at create.");
    }
    return Fail(error,
                "[winn3] class \"" + parsed.carrier_class +
                    "\" is not named in the plan, so the message floor was "
                    "not computed over the carrier this session dials");
  }
  // NODE BINDING, BOTH SPELLINGS, BEFORE CREDENTIAL FILES OR SESSION START.
  //
  // A served-only conditional here was a skip: `[winn3]` could omit `node`
  // and `selected_node` entirely and still reach key-path validation. The
  // signed descriptor node and the route-selected node must both be a
  // strict ASCII identity and match on the local spelling too, or a
  // verified descriptor for gateway A can be replayed onto gateway B.
  if (parsed.descriptor_node.empty() || parsed.selected_node.empty() ||
      parsed.descriptor_node != parsed.selected_node) {
    return Fail(error,
                "[" + want_section +
                    "] signed descriptor node and selected node must both "
                    "be a strict ASCII node identity and match; a missing "
                    "identity, Unicode homoglyph, alias conflict, or "
                    "cross-node replay is refused before credential files "
                    "or session start");
  }
  if (Trim(parsed.gateway_id).empty()) {
    return Fail(error,
                "[" + want_section +
                    "] gateway_id is empty: without it an initiation "
                    "captured at one gateway replays at another that shares the "
                    "admission key");
  }
  if (served) {
    // THE DESCRIPTOR BOUNDARY, AND THE ONLY DECODE OF THIS FIELD.
    //
    // `[winn] gateway_id` is base64 over the OPERATOR'S GATEWAY NAME, because
    // the ML-DSA-65-signed descriptor carries every byte-valued field that way.
    // The engine's profile takes the name's RAW BYTES -- it is an authenticated
    // input to the admission tag and is never transmitted -- so the encoding
    // comes off exactly here, and `BuildWinn3ProfileJson` emits what is left
    // verbatim.
    //
    // A second decode anywhere is defect 1: `winsgw01` is eight characters of
    // the base64 alphabet, so the wrong answer is six entirely plausible bytes,
    // a tag the gateway cannot verify, and the silence a v3 gateway answers
    // every unauthenticated datagram with.
    std::string operator_name;
    if (!DecodeBase64(Trim(parsed.gateway_id), &operator_name) ||
        operator_name.empty()) {
      return Fail(error,
                  "[winn] gateway_id is not usable: the signed descriptor "
                  "carries it base64-encoded over the operator's gateway name, "
                  "and this value does not decode to one. The engine is handed "
                  "the decoded name, byte for byte what the gateway itself is "
                  "configured with, because the admission tag is computed over "
                  "it and is never transmitted.");
    }
    parsed.gateway_id = operator_name;
  }
  if (Trim(parsed.inner_v4).empty() && Trim(parsed.inner_v6).empty()) {
    return Fail(error, "[" + want_section +
                           "] carries neither inner_v4 nor inner_v6");
  }
  if (served) {
    // The three key VALUES. A served config cannot name paths -- the control
    // plane does not know this device's filesystem -- so it carries base64 and
    // this supervisor writes the files. Every one is required: v3 authenticates
    // with a static X25519 key pair and a gateway admission secret and has no
    // anonymous mode, so a session missing any of them cannot start.
    struct Required {
      const char* key;
      const std::string* value;
      size_t exact_bytes;  // 0 means "any non-empty length"
      const char* role;
    };
    const Required required[] = {
        {"static_private", &parsed.static_private_b64, 32,
         "this device's 32-byte X25519 private key"},
        {"gateway_static", &parsed.gateway_static_b64, 32,
         "the gateway's 32-byte X25519 public key; a client authenticates the "
         "gateway by its static key and there is no anonymous mode"},
        // NOT 32, and this is the one that matters most. The admission secret
        // is OPAQUE: keygen writes 64 ASCII hex characters and every consumer
        // keys with those characters, never with the 32 bytes they encode.
        // Requiring 32 here would enforce the exact defect -- a gateway that
        // admits the datagram, BUILDS a session, and then goes completely
        // silent, which is worse than a refusal because a host watching for
        // "did the gateway see me" sees yes.
        {"admission_key", &parsed.admission_key_b64, 0,
         "the admission secret's own bytes, opaque and never decoded again"},
    };
    const bool ed_empty =
        supervisor_detail::Trim(parsed.auth_ed25519_b64).empty();
    const bool ml_empty =
        supervisor_detail::Trim(parsed.auth_mldsa65_b64).empty();
    if (ed_empty != ml_empty) {
      return Fail(error,
                  "[winn] auth_ed25519 and auth_mldsa65 are the optional pair "
                  "and must be both present or both absent");
    }
    if (!ed_empty) {
      std::string ed_raw;
      std::string ml_raw;
      if (!DecodeBase64(supervisor_detail::Trim(parsed.auth_ed25519_b64),
                        &ed_raw) ||
          ed_raw.empty()) {
        return Fail(error,
                    "[winn] auth_ed25519 is not base64. Every byte-valued "
                    "field on the signed gateway descriptor is base64-encoded "
                    "and reaches the [winn] section untouched.");
      }
      if (!DecodeBase64(supervisor_detail::Trim(parsed.auth_mldsa65_b64),
                        &ml_raw) ||
          ml_raw.empty()) {
        return Fail(error,
                    "[winn] auth_mldsa65 is not base64. Every byte-valued "
                    "field on the signed gateway descriptor is base64-encoded "
                    "and reaches the [winn] section untouched.");
      }
      if (ed_raw.size() != kDualAuthEd25519Bytes) {
        return Fail(error,
                    "[winn] auth_ed25519 decodes to " +
                        std::to_string(ed_raw.size()) +
                        " bytes; it must be " +
                        std::to_string(kDualAuthEd25519Bytes) +
                        " -- the gateway's Ed25519 attestation public key");
      }
      if (ml_raw.size() != kDualAuthMldsa65Bytes) {
        return Fail(error,
                    "[winn] auth_mldsa65 decodes to " +
                        std::to_string(ml_raw.size()) +
                        " bytes; it must be " +
                        std::to_string(kDualAuthMldsa65Bytes) +
                        " -- the gateway's ML-DSA-65 attestation public key");
      }
    }
    for (const Required& item : required) {
      if (Trim(*item.value).empty()) {
        return Fail(error, std::string("[winn] ") + item.key +
                               " is empty: it must carry base64 over " +
                               item.role);
      }
      std::string raw;
      if (!DecodeBase64(Trim(*item.value), &raw) || raw.empty()) {
        return Fail(error,
                    std::string("[winn] ") + item.key +
                        " is not base64. Every byte-valued field on the signed "
                        "gateway descriptor is base64-encoded and reaches the "
                        "[winn] section untouched.");
      }
      if (item.exact_bytes != 0 && raw.size() != item.exact_bytes) {
        return Fail(error, std::string("[winn] ") + item.key + " decodes to " +
                               std::to_string(raw.size()) + " bytes; it must be " +
                               std::to_string(item.exact_bytes) + " -- " +
                               item.role);
      }
    }
  } else {
    if (Trim(parsed.static_key_path).empty()) {
      return Fail(error, "[winn3] static_key_path is empty");
    }
    if (Trim(parsed.gateway_static_key_path).empty()) {
      return Fail(error,
                  "[winn3] gateway_static_key_path is empty: a client "
                  "authenticates the gateway by its static key and there is no "
                  "anonymous mode");
    }
    if (Trim(parsed.admission_path).empty()) {
      return Fail(error, "[winn3] admission_path is empty");
    }
  }
  if (!parsed.dns_servers.empty() && !parsed.dns_servers_are_inner) {
    return Fail(error,
                "[winn3] names resolvers without dns_are_inner = true. A "
                "resolver reachable outside the tunnel resolves names over the "
                "censored path the moment the tunnel drops, so the declaration "
                "is required rather than assumed.");
  }
  *out = parsed;
  return true;
}

// Bind a native start to the independently selected Flutter picker slug.
// The two INI fields above are derived from one served document and therefore
// cannot establish this caller identity by comparing only with each other.
inline bool ValidateWinn3IndependentSelectedNode(
    const std::string& raw_config, const std::string& caller_selected_node,
    std::string* error) {
  Winn3HostConfig parsed;
  if (!ParseWinn3Section(raw_config, &parsed, error)) {
    return false;
  }
  std::string normalized_caller;
  if (!NormalizeWinn3NodeIdentity(caller_selected_node, &normalized_caller) ||
      normalized_caller != parsed.descriptor_node ||
      normalized_caller != parsed.selected_node) {
    return supervisor_detail::Fail(
        error,
        "independently selected node must be a strict ASCII identity and "
        "match both signed descriptor node fields; missing, conflicting, or "
        "Unicode caller identity is refused before tunnel start");
  }
  return true;
}

// --- the key files a served configuration implies ----------------------------

// Winn3KeyFile is one file this supervisor must write before the engine starts.
//
// The CONTENTS are computed here, in the testable half, and the WRITING happens
// in winn3_supervisor.cpp with the same DACL the profile is written with. That
// split is the same one the rest of this header keeps: there is no Windows host
// on the machine where this project is developed, so anything only Windows can
// execute is something nothing tests -- and these three files decide whether a
// handshake is ever answered.
struct Winn3KeyFile {
  std::string name;      // the file name inside the profile directory
  std::string contents;  // exactly what the engine must read back
};

// Winn3KeyFilesFor returns the files a SERVED configuration implies, or an
// empty vector for a `[winn3]` one, which names files somebody else wrote.
//
// ===========================================================================
// WHAT EACH FILE HOLDS, AND THE TWO MISTAKES THAT ARE SILENT
// ===========================================================================
//
//	static.key      the 32 raw private key bytes, as `winn3ReadKeyFile`
//	gateway.pub     the 32 raw public key bytes, likewise
//	admission.key   the admission secret's OWN BYTES -- keygen's 64 ASCII hex
//	                characters -- written verbatim
//
// `winn3ReadKeyFile` accepts either 64 hex characters or 32 raw bytes for the
// statics, so the raw bytes are written directly rather than re-encoded: one
// fewer encoding is one fewer place two ends can disagree about a value neither
// transmits.
//
// The admission secret is NEVER hex-decoded. `sessionConfig` reads that file
// with os.ReadFile and trims a trailing newline and nothing else. Decoding it
// keys 32 bytes against the gateway's 64, and that failure is worse than a
// refusal: the datagram passes the gateway's size pre-filter, a session is
// BUILT, and the gateway then answers nothing at all.
//
// Returns false only if the configuration did not come from ParseWinn3Section,
// which validated every one of these.
inline bool Winn3KeyFilesFor(const Winn3HostConfig& config,
                             std::vector<Winn3KeyFile>* out,
                             std::string* error) {
  if (out == nullptr) {
    return supervisor_detail::Fail(error, "no key file list to fill");
  }
  out->clear();
  if (config.section != "winn") {
    return true;
  }
  const struct {
    const char* name;
    const std::string* value;
  } files[] = {
      {"static.key", &config.static_private_b64},
      {"gateway.pub", &config.gateway_static_b64},
      {"admission.key", &config.admission_key_b64},
  };
  for (const auto& file : files) {
    std::string raw;
    if (!supervisor_detail::DecodeBase64(supervisor_detail::Trim(*file.value),
                                         &raw) ||
        raw.empty()) {
      out->clear();
      return supervisor_detail::Fail(
          error, std::string("the served key material for ") + file.name +
                     " is not base64; this configuration did not come from "
                     "ParseWinn3Section, which refuses that");
    }
    out->push_back(Winn3KeyFile{file.name, raw});
  }
  if (!supervisor_detail::Trim(config.auth_ed25519_b64).empty() ||
      !supervisor_detail::Trim(config.auth_mldsa65_b64).empty()) {
    std::string ed_raw;
    std::string ml_raw;
    if (!supervisor_detail::DecodeBase64(
            supervisor_detail::Trim(config.auth_ed25519_b64), &ed_raw) ||
        ed_raw.size() != kDualAuthEd25519Bytes ||
        !supervisor_detail::DecodeBase64(
            supervisor_detail::Trim(config.auth_mldsa65_b64), &ml_raw) ||
        ml_raw.size() != kDualAuthMldsa65Bytes) {
      out->clear();
      return supervisor_detail::Fail(
          error,
          "the served dual-auth pair is not both base64 public keys of "
          "32 and 1952 bytes; this configuration did not come from "
          "ParseWinn3Section, which refuses that");
    }
    out->push_back(
        Winn3KeyFile{kDualAuthEd25519File, supervisor_detail::LowerHex(ed_raw)});
    out->push_back(
        Winn3KeyFile{kDualAuthMldsa65File, supervisor_detail::LowerHex(ml_raw)});
  }
  return true;
}

// Winn3ConfigWithKeyPaths returns `config` with the three path fields set to
// files inside `directory`, so BuildWinn3ProfileJson emits PATHS for a served
// configuration exactly as it does for a `[winn3]` one.
//
// The profile document therefore never holds key material regardless of which
// spelling the operator's configuration used, which is the property the old
// "paths, never values" rule was really protecting. What it was NOT protecting
// is the served config carrying values: the control plane cannot name a path on
// a device it has never seen, so a host that would only read paths is a host no
// server can drive.
inline Winn3HostConfig Winn3ConfigWithKeyPaths(const Winn3HostConfig& config,
                                               const std::string& directory) {
  if (config.section != "winn") {
    return config;
  }
  const std::string separator =
      (!directory.empty() && (directory.back() == '\\' || directory.back() == '/'))
          ? ""
          : "\\";
  Winn3HostConfig out = config;
  out.static_key_path = directory + separator + "static.key";
  out.gateway_static_key_path = directory + separator + "gateway.pub";
  out.admission_path = directory + separator + "admission.key";
  if (!supervisor_detail::Trim(config.auth_ed25519_b64).empty() &&
      !supervisor_detail::Trim(config.auth_mldsa65_b64).empty()) {
    out.dual_auth_ed25519_pub_path =
        directory + separator + kDualAuthEd25519File;
    out.dual_auth_mldsa65_pub_path =
        directory + separator + kDualAuthMldsa65File;
  }
  return out;
}

// --- the profile document ---------------------------------------------------

// BuildWinn3ProfileJson renders the `-winn3-profile` document.
//
// It is a REAL winn3Profile: loadWinn3Profile decodes it with
// DisallowUnknownFields, so every key below is one that file declares and there
// is no key it does not. IT CONTAINS NO KEY MATERIAL, only paths -- the same
// rule LinuxWinnCarrierProfile follows, and what keeps a host that writes a
// profile from ever holding a key.
//
// `device.kind` is "loopback-udp" and nothing else. That single field is what
// keeps the v3 seam apart from the winn/1 one, and getting it wrong in either
// direction is the mistake that either puts cleartext on the wire or
// double-encrypts everything.
//
// `device.name` is emitted empty because loadWinn3Profile REFUSES a non-empty
// name on a loopback-udp device; it belongs to the tun-fd backend.
inline std::string BuildWinn3ProfileJson(const Winn3HostConfig& config,
                                         int host_port,
                                         const std::string& exclusion) {
  using supervisor_detail::JsonString;
  using supervisor_detail::JsonStringArray;
  std::string out = "{";
  out += "\"version\":" + JsonString(kProfileVersion);
  out += ",\"role\":" + JsonString(kRoleClient);
  out += ",\"plan\":" + JsonStringArray(config.plan);
  out += ",\"path_mtu\":" + std::to_string(config.path_mtu);
  out += ",\"gateway_id\":" + JsonString(config.gateway_id);
  out += ",\"carrier\":{\"class\":" + JsonString(config.carrier_class) +
         ",\"endpoint\":" + JsonString(config.endpoint) + "}";
  out += ",\"inner\":{\"v4\":" + JsonString(config.inner_v4) +
         ",\"v6\":" + JsonString(config.inner_v6) +
         ",\"router_v4\":" + JsonString(config.router_v4) +
         ",\"router_v6\":" + JsonString(config.router_v6) + "}";
  out += ",\"keys\":{\"static_path\":" + JsonString(config.static_key_path) +
         ",\"gateway_static_path\":" +
         JsonString(config.gateway_static_key_path) +
         ",\"admission_path\":" + JsonString(config.admission_path);
  if (!supervisor_detail::Trim(config.dual_auth_ed25519_pub_path).empty() &&
      !supervisor_detail::Trim(config.dual_auth_mldsa65_pub_path).empty()) {
    out += ",\"dual_auth_ed25519_pub_path\":" +
           JsonString(config.dual_auth_ed25519_pub_path) +
           ",\"dual_auth_mldsa65_pub_path\":" +
           JsonString(config.dual_auth_mldsa65_pub_path);
  }
  out += "}";
  out += ",\"device\":{\"kind\":" + std::string(JsonString(kDeviceLoopbackUdp)) +
         ",\"host_port\":" + std::to_string(host_port) + ",\"name\":\"\"}";
  // allow_own_socket is the desktop model and the ONLY model this mode
  // supports: the engine opens the outer socket itself, and the host must have
  // installed a route exclusion that keeps it out of the tunnel it carries.
  // This supervisor pins that /32 BEFORE it writes this document.
  out += ",\"allow_own_socket\":true";
  out += ",\"outer_socket_exclusion\":" + JsonString(exclusion);
  out += ",\"fast_pq\":";
  out += config.fast_pq ? "true" : "false";
  out += "}";
  return out;
}

// --- the two child processes' lines -----------------------------------------

// ParseRelayHostPort reads the relay's `host-port <P>`, the FIRST thing it
// prints and the port the engine's profile must name.
inline bool ParseRelayHostPort(const std::string& line, int* port) {
  return supervisor_detail::TakeTrailingPort(line, kRelayHostPortPrefix, port);
}

// ParseEngineSeamPort reads winn-datapath's stderr announcement.
//
// The port is on STDERR by design: the host needs it before the first status
// line in order to finish wiring its own half of the seam, and it is not a
// counter. Reading it therefore means the supervisor must drain the engine's
// stderr, which it does on its own thread -- an engine whose stderr pipe filled
// would block in a write and never publish a status document at all.
inline bool ParseEngineSeamPort(const std::string& line, int* port) {
  return supervisor_detail::TakeTrailingPort(line, kEngineSeamPortPrefix, port);
}

// Winn3RelayReady is the relay's readiness line, parsed.
//
// THE ADAPTER DOES NOT EXIST UNTIL THIS LINE. That is the whole point of the
// ordering: there is no window in which Windows has an interface it might route
// traffic to before the seam beneath it is wired to a running v3 engine.
struct Winn3RelayReady {
  std::string name;
  uint64_t luid = 0;
  int mtu = 0;
  int floor_mtu = 0;
  bool ipv6 = false;
};

// ParseRelayReady reads
// `ready name=<n> luid=<n> mtu=<n> floor-mtu=<n> ipv6=<bool>`.
//
// Every field is required. A missing one is a refusal rather than a default,
// because the two that would be defaulted are the interface the posture is
// installed on and the MTU it is installed with.
inline bool ParseRelayReady(const std::string& line, Winn3RelayReady* out) {
  using namespace supervisor_detail;  // NOLINT(build/namespaces)
  if (out == nullptr) {
    return false;
  }
  *out = Winn3RelayReady();
  const std::string trimmed = Trim(line);
  const std::string prefix(kRelayReadyPrefix);
  if (trimmed.size() <= prefix.size() ||
      trimmed.compare(0, prefix.size(), prefix) != 0) {
    return false;
  }
  Winn3RelayReady parsed;
  bool saw_name = false;
  bool saw_luid = false;
  bool saw_mtu = false;
  bool saw_floor = false;
  bool saw_ipv6 = false;
  size_t begin = prefix.size();
  while (begin < trimmed.size()) {
    const size_t space = trimmed.find(' ', begin);
    const size_t end = space == std::string::npos ? trimmed.size() : space;
    const std::string field = trimmed.substr(begin, end - begin);
    begin = space == std::string::npos ? trimmed.size() : space + 1;
    if (field.empty()) {
      continue;
    }
    const auto equals = field.find('=');
    if (equals == std::string::npos) {
      return false;
    }
    const std::string key = field.substr(0, equals);
    const std::string value = field.substr(equals + 1);
    int64_t number = 0;
    if (key == "name") {
      if (value.empty()) return false;
      parsed.name = value;
      saw_name = true;
    } else if (key == "luid") {
      if (!ParseDecimal(value, INT64_MAX, &number)) return false;
      parsed.luid = static_cast<uint64_t>(number);
      saw_luid = true;
    } else if (key == "mtu") {
      if (!ParseDecimal(value, kMaxInnerMTU, &number)) return false;
      parsed.mtu = static_cast<int>(number);
      saw_mtu = true;
    } else if (key == "floor-mtu") {
      if (!ParseDecimal(value, kMaxInnerMTU, &number)) return false;
      parsed.floor_mtu = static_cast<int>(number);
      saw_floor = true;
    } else if (key == "ipv6") {
      if (value == "true") {
        parsed.ipv6 = true;
      } else if (value == "false") {
        parsed.ipv6 = false;
      } else {
        return false;
      }
      saw_ipv6 = true;
    } else {
      return false;  // Unknown field: the same refusal the relay itself makes.
    }
  }
  if (!saw_name || !saw_luid || !saw_mtu || !saw_floor || !saw_ipv6) {
    return false;
  }
  *out = parsed;
  return true;
}

// RenderStartCommand renders the ONE control line the relay accepts.
//
// Byte-for-byte what parseStartCommand in windows/winn3_engine/packet.go
// expects: `start mtu=<n> engine-port=<n>`, with a trailing newline because the
// relay reads it with a line scanner and would otherwise block forever holding
// no adapter. Unknown fields are refused on that side, so this renderer emits
// exactly two and never a third.
inline std::string RenderStartCommand(int mtu, int engine_port) {
  return "start mtu=" + std::to_string(mtu) +
         " engine-port=" + std::to_string(engine_port) + "\n";
}

// --- the MTU obligations ----------------------------------------------------

// Validate the published MTU's bounds. Plan correctness is established by
// the engine; VerifyAppliedMtuStillAgrees checks the adapter against it.
inline bool VerifyPublishedInnerMtu(int mtu, std::string* error) {
  using supervisor_detail::Fail;
  if (mtu <= 0) {
    return Fail(error,
                "the engine published a non-positive inner MTU, so there is no "
                "number to build the adapter with");
  }
  if (mtu < kMinInnerMTU) {
    return Fail(error, "the inner MTU " + std::to_string(mtu) +
                           " is below the " + std::to_string(kMinInnerMTU) +
                           "-byte IPv4 minimum");
  }
  if (mtu > kMaxInnerMTU) {
    return Fail(error, "the inner MTU " + std::to_string(mtu) +
                           " is above the " + std::to_string(kMaxInnerMTU) +
                           "-byte maximum");
  }
  return true;
}

// VerifyAppliedMtuStillAgrees is the obligation packet.go names: the service
// must pass the SAME number it read from `inner_mtu`, and must refuse to
// promote if the two ever disagree.
//
// They can disagree without anybody lying. The pre-flight sizing document and
// the live session are two runs of the same computation over the same profile,
// but a profile edited between them, an engine binary replaced between them, or
// a plan whose floor moved would all produce a live inner_mtu the adapter was
// not built for -- and the adapter cannot be resized without destroying it. So
// this refuses rather than adjusts.
inline bool VerifyAppliedMtuStillAgrees(int applied, const EngineStatus& status,
                                        std::string* error) {
  using supervisor_detail::Fail;
  if (!status.valid) {
    return Fail(error,
                "refusing to act on an unparsed status document: the inner MTU "
                "it should have carried is unknown");
  }
  if (status.inner_mtu != applied) {
    return Fail(
        error,
        "the engine now publishes inner_mtu " +
            std::to_string(status.inner_mtu) +
            " but the Wintun adapter was built with MTU " +
            std::to_string(applied) +
            ". A live adapter cannot be resized, and the gap between the two "
            "is silently black-holed rather than reported, so the tunnel was "
            "stopped instead of promoted.");
  }
  return true;
}

// InnerIPv6IsArithmeticallyPossible reports whether an inner MTU can carry
// inner IPv6 at all.
//
// At the shipping floor of 1139 it cannot: RFC 8200's minimum link MTU is 1280.
// The bootstrap posture's "no IPv6" rule is therefore forced by arithmetic
// rather than chosen as policy, and this predicate is what a later hand meets
// if they try to relax it.
inline bool InnerIPv6IsArithmeticallyPossible(int inner_mtu) {
  return inner_mtu >= kIPv6MinLinkMTU;
}

// --- feeding winn3_posture.h ------------------------------------------------

// PostureInputFrom converts the parsed section into the posture policy's input.
//
// The inner IPv6 address is carried across ONLY when the engine's own numbers
// say the family can be carried. BuildPromotedPosture refuses IPv6 whose
// `inner_ipv6` is false, which is the authoritative check; dropping it here as
// well means a bootstrap posture never even names an address the tunnel cannot
// carry, and the two refusals agree rather than race.
inline PostureInput PostureInputFrom(const Winn3HostConfig& config,
                                     const std::string& exclusion,
                                     const EngineStatus& status) {
  PostureInput input;
  input.inner_v4 = config.inner_v4;
  input.router_v4 = config.router_v4;
  if (status.inner_ipv6 &&
      InnerIPv6IsArithmeticallyPossible(status.inner_mtu)) {
    input.inner_v6 = config.inner_v6;
    input.router_v6 = config.router_v6;
  }
  input.outer_socket_exclusion = exclusion;
  input.full_routes = config.full_routes;
  input.dns_servers = config.dns_servers;
  input.dns_servers_are_inner = config.dns_servers_are_inner;
  // The signed resolver, carried across so winn3_posture.h can DERIVE
  // inner-ness from it. Both fields are passed and neither is translated into
  // the other: `dns_servers_are_inner` is the local `[winn3]` declaration and
  // stays exactly that, and the derived path in BuildPromotedPosture does not
  // consult it. Empty on every descriptor signed to date, and empty selects the
  // declaration path -- which is the behaviour this function had before the
  // field existed.
  input.inner_resolver_v4 = config.inner_resolver_v4;
  return input;
}

// Winn3PromotionVerdict is what the poll loop does next.
enum class Winn3PromotionVerdict {
  // The engine has proven the datapath: the gate is carrying AND an inner
  // packet has been validated and written to the host device. Widen now.
  kPromote,
  // Nothing is wrong and nothing is proven yet. Keep polling until the
  // caller's deadline, which is itself fail-closed.
  kHold,
  // Stop. Either the engine refused, or something the supervisor can check
  // disagrees with something it already acted on.
  kRefuse,
};

// DecideWinn3Promotion is the whole promotion decision, as a pure function.
//
// It does NOT recompute promotion_ready. cmd/winn-datapath computes that once,
// in Go, beside the counters -- `Gate.State() == StateCarrying && RxPackets >
// 0` -- precisely so that two C++ hosts cannot compute it two different ways.
// The classic way to get it wrong is RxOffered for RxPackets: the difference
// between "a payload arrived" and "an inner packet was validated and reached
// the host device". A host is not asked, so a host cannot get it wrong.
//
// What this DOES add is the pair of checks only the supervisor can make,
// because only the supervisor knows what it already did:
//
//   1. the adapter's MTU still matches the engine's published inner_mtu; and
//   2. the status document does not contradict itself.
//
// *reason receives a non-secret sentence. It never quotes the endpoint.
inline Winn3PromotionVerdict DecideWinn3Promotion(const EngineStatus& status,
                                                  int applied_mtu,
                                                  std::string* reason) {
  const auto say = [reason](const std::string& text) {
    if (reason != nullptr) {
      *reason = text;
    }
  };
  if (!status.valid) {
    // A line that did not parse is indistinguishable from a line from a newer
    // engine, and both answers are the same: hold the narrow posture. This is
    // not a refusal, because a single malformed line on a stream that is
    // otherwise healthy should not tear down a working tunnel.
    say("the engine has not yet published a status document this host can "
        "parse, so the bootstrap posture is held.");
    return Winn3PromotionVerdict::kHold;
  }
  if (!status.refusal.empty()) {
    say("the Winn Protocol v3 engine refused: " + status.refusal);
    return Winn3PromotionVerdict::kRefuse;
  }
  std::string mtu_error;
  if (!VerifyAppliedMtuStillAgrees(applied_mtu, status, &mtu_error)) {
    say(mtu_error);
    return Winn3PromotionVerdict::kRefuse;
  }
  if (!status.promotion_ready) {
    // Named separately because the operator needs to know WHICH half is
    // missing: a gate that never opened is a handshake problem, and an open
    // gate with no delivered packet is a return-path problem.
    if (status.gate_state != kCarryingGate) {
      say("the session gate is '" + status.gate_state + "', not '" +
          std::string(kCarryingGate) +
          "', so no inner packet may move yet and the routes stay narrow.");
    } else {
      say("the gate is carrying but no inner packet has reached the host "
          "device yet, so the return path is unproven and the routes stay "
          "narrow.");
    }
    return Winn3PromotionVerdict::kHold;
  }
  // Belt and braces, BOTH HALVES -- and until 2026-08-12 it was one.
  //
  // promotion_ready is the engine's to compute and this host does not recompute
  // it. That is the reason stated above and it has not changed. What follows is
  // not a recomputation: it is the refusal of a document that contradicts
  // itself, which is check 2 of the two this function says it adds.
  //
  // `promotion_ready` is a conjunction -- the gate is carrying AND an inner
  // packet was delivered -- and only the delivery half was refused here. The
  // gate half was compared, in the branch above, but that branch is a
  // DIAGNOSTIC: it runs only when the field already said false, to tell a held
  // session which half it is waiting on. It stays exactly as it is. What it
  // could not do from inside that branch is refuse, because it is unreachable
  // the moment the field says true -- so ready=true beside a gate that may not
  // carry was PROMOTED, with the comparison never executed.
  //
  // The engine cannot write that document: winn3StatusFrom reads the gate ONCE
  // and derives both fields from that value, so this is defence in depth
  // against a malformed or substituted status line, not a live engine bug.
  //
  // kRefuse and not kHold, deliberately. kHold means "nothing is wrong and
  // nothing is proven yet", which is the honest answer for a document that says
  // false. A document that says TRUE while naming a gate that may not carry is
  // not unproven -- it is inconsistent, exactly as the zero-deliveries case is,
  // and the two must answer the same way or the weaker one becomes the way in.
  if (status.gate_state != kCarryingGate) {
    say("the status document claims the datapath is proven but reports the "
        "session gate as '" +
        status.gate_state + "', not '" + std::string(kCarryingGate) +
        "', so it disagrees with itself and was refused rather than "
        "believed.");
    return Winn3PromotionVerdict::kRefuse;
  }
  if (status.rx_packets == 0) {
    say("the status document claims the datapath is proven but reports zero "
        "delivered inner packets, so it disagrees with itself and was refused "
        "rather than believed.");
    return Winn3PromotionVerdict::kRefuse;
  }
  if (reason != nullptr) {
    reason->clear();
  }
  return Winn3PromotionVerdict::kPromote;
}

// --- rendering an argument vector for CreateProcess -------------------------

// QuoteWin32Argument quotes one argv element for a Windows command line.
//
// RenderWindowsPostureCommands returns ARGUMENT VECTORS and quotes for nothing,
// deliberately: a renderer that emitted shell syntax would invite a caller to
// reintroduce the quoting bug that argument vectors exist to remove. But
// CreateProcessW takes a single command line, so somebody has to join them, and
// the joining is where the bug would live. It lives here, where it is a pure
// function with tests.
//
// The rules implemented are CommandLineToArgvW's, which is what netsh's CRT
// uses to split the line back apart: a run of backslashes is doubled only when
// it precedes a quote or terminates the argument, and an interior quote is
// escaped. An argument containing whitespace, a quote or nothing at all is
// wrapped; anything else is passed through unchanged, which keeps the common
// case byte-identical to what an operator would type.
inline std::string QuoteWin32Argument(const std::string& argument) {
  bool needs_quotes = argument.empty();
  for (const char raw : argument) {
    if (raw == ' ' || raw == '\t' || raw == '\n' || raw == '\v' ||
        raw == '"') {
      needs_quotes = true;
      break;
    }
  }
  if (!needs_quotes) {
    return argument;
  }
  std::string out = "\"";
  for (size_t i = 0; i < argument.size(); ++i) {
    size_t backslashes = 0;
    while (i < argument.size() && argument[i] == '\\') {
      ++backslashes;
      ++i;
    }
    if (i == argument.size()) {
      // Trailing backslashes precede the closing quote, so they must not
      // escape it.
      out.append(backslashes * 2, '\\');
      break;
    }
    if (argument[i] == '"') {
      out.append(backslashes * 2 + 1, '\\');
    } else {
      out.append(backslashes, '\\');
    }
    out.push_back(argument[i]);
  }
  out.push_back('"');
  return out;
}

// ---------------------------------------------------------------------------
// Generation-bound typed start proof. Ordinary fallback is authorized only by
// a matching generation AND positively proven network evidence.
// ---------------------------------------------------------------------------
//
// A v3 gateway that cannot authenticate answers nothing. A censor that drops
// UDP also answers nothing. Collapsing every pre-accept failure into one
// start error is what used to turn a wrong static key, a pinning failure, a
// replay, or a malformed proof into a v1 fallback. The four wire names below
// are the closed set:

inline constexpr char kWinn3ProofOutcomeConnected[] = "connected";
inline constexpr char kWinn3ProofOutcomeOrdinaryConnectivity[] =
    "ordinary_connectivity";
inline constexpr char kWinn3ProofOutcomeTerminalSecurity[] =
    "terminal_security";
inline constexpr char kWinn3ProofOutcomeUnknownTerminal[] = "unknown_terminal";

enum class Winn3ProofOutcome {
  kConnected,
  kOrdinaryConnectivity,
  kTerminalSecurity,
  kUnknownTerminal,
};

struct Winn3StartProof {
  int64_t generation = 0;
  int64_t start_token = 0;
  std::string selection_generation;
  std::string failed_node;
  Winn3ProofOutcome outcome = Winn3ProofOutcome::kUnknownTerminal;
  bool canceled = false;
  // Exact platform OS error captured at the failing syscall. Never derived
  // from diagnostic prose. Zero means no structured OS error was captured.
  int os_error = 0;
};

inline constexpr int kWindowsWsaEnetdown = 10050;
inline constexpr int kWindowsWsaEnetunreach = 10051;
inline constexpr int kWindowsWsaEhostdown = 10064;
inline constexpr int kWindowsWsaEhostunreach = 10065;
inline constexpr int64_t kWinn3AwgXrayGrantTtlMs = 60000;

// Structured OS-error slot for a standalone v3 start. Production captures the
// exact WSA code from the gateway datagram connect and stores it here. The
// classifier consumes that integer; diagnostic prose is never parsed for it.
inline int& WindowsWinn3CapturedOsErrorSlot() {
  static thread_local int os_error = 0;
  return os_error;
}

inline void RememberWindowsWinn3OsError(int os_error) {
  WindowsWinn3CapturedOsErrorSlot() = os_error;
}

inline int PeekWindowsWinn3OsError() { return WindowsWinn3CapturedOsErrorSlot(); }

inline int TakeWindowsWinn3OsError() {
  const int os_error = WindowsWinn3CapturedOsErrorSlot();
  WindowsWinn3CapturedOsErrorSlot() = 0;
  return os_error;
}

inline bool IsWinn3SelectionGeneration(const std::string& value) {
  if (value.size() < 8 || value.size() > 64) return false;
  const unsigned char first = static_cast<unsigned char>(value[0]);
  if (!std::isalnum(first)) return false;
  for (size_t i = 1; i < value.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(value[i]);
    if (std::isalnum(c) || c == '.' || c == '_' || c == ':' || c == '-') {
      continue;
    }
    return false;
  }
  return true;
}

inline bool IsConcreteWinn3NodeSlug(const std::string& value) {
  if (value.empty()) return false;
  std::string lower = value;
  for (char& c : lower) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return lower != "auto";
}

enum class Winn3CoverLeg { kAwg, kXray };

inline bool ParseWinn3CoverLeg(const std::string& text, Winn3CoverLeg* out) {
  if (out == nullptr) return false;
  if (text == "awg") {
    *out = Winn3CoverLeg::kAwg;
    return true;
  }
  if (text == "xray") {
    *out = Winn3CoverLeg::kXray;
    return true;
  }
  return false;
}

enum class Winn3GrantConsumeResult {
  kOk,
  kEmpty,
  kExpired,
  kMismatch,
  kWrongLeg,
};

struct Winn3AwgXrayGrant {
  int64_t start_token = 0;
  int64_t start_generation = 0;
  std::string selection_generation;
  std::string failed_v3_node;
  std::string exact_v1_target;
  int64_t issued_monotonic_ms = 0;
  Winn3CoverLeg next_leg = Winn3CoverLeg::kAwg;
  bool target_bound = false;
};

inline bool Winn3AwgXrayGrantExpired(const Winn3AwgXrayGrant& grant,
                                     int64_t now_monotonic_ms) {
  if (grant.start_token <= 0 || grant.issued_monotonic_ms <= 0) return true;
  if (now_monotonic_ms < grant.issued_monotonic_ms) return true;
  return (now_monotonic_ms - grant.issued_monotonic_ms) > kWinn3AwgXrayGrantTtlMs;
}

inline bool ArmWinn3AwgXrayGrant(int64_t start_token, int64_t start_generation,
                                 const std::string& selection_generation,
                                 const std::string& failed_v3_node,
                                 int64_t issued_monotonic_ms,
                                 Winn3AwgXrayGrant* out) {
  if (out == nullptr) return false;
  if (start_token <= 0 || start_generation <= 0 || issued_monotonic_ms <= 0 ||
      !IsWinn3SelectionGeneration(selection_generation) ||
      !IsConcreteWinn3NodeSlug(failed_v3_node)) {
    *out = Winn3AwgXrayGrant();
    return false;
  }
  Winn3AwgXrayGrant grant;
  grant.start_token = start_token;
  grant.start_generation = start_generation;
  grant.selection_generation = selection_generation;
  grant.failed_v3_node = failed_v3_node;
  grant.issued_monotonic_ms = issued_monotonic_ms;
  *out = grant;
  return true;
}

inline Winn3GrantConsumeResult ConsumeWinn3AwgXrayGrant(
    Winn3AwgXrayGrant* grant, int64_t start_token, int64_t start_generation,
    const std::string& selection_generation, const std::string& failed_v3_node,
    const std::string& exact_v1_target, Winn3CoverLeg requested_leg,
    int64_t now_monotonic_ms) {
  if (grant == nullptr || grant->start_token <= 0) {
    return Winn3GrantConsumeResult::kEmpty;
  }
  if (Winn3AwgXrayGrantExpired(*grant, now_monotonic_ms)) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kExpired;
  }
  if (start_token != grant->start_token ||
      start_generation != grant->start_generation ||
      selection_generation != grant->selection_generation ||
      failed_v3_node != grant->failed_v3_node ||
      !IsConcreteWinn3NodeSlug(exact_v1_target)) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kMismatch;
  }
  if (grant->target_bound && exact_v1_target != grant->exact_v1_target) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kMismatch;
  }
  if (requested_leg != grant->next_leg) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kWrongLeg;
  }
  if (requested_leg == Winn3CoverLeg::kAwg) {
    grant->exact_v1_target = exact_v1_target;
    grant->next_leg = Winn3CoverLeg::kXray;
    grant->target_bound = true;
    return Winn3GrantConsumeResult::kOk;
  }
  *grant = Winn3AwgXrayGrant();
  return Winn3GrantConsumeResult::kOk;
}

enum class WindowsTunnelProbeAlias {
  kWinn3,
  kWinn1,
  kRefuse,
};

inline WindowsTunnelProbeAlias ClassifyWindowsTunnelProbeAlias(
    bool v3_active, bool v3_running, bool v3_promoted, bool v1_running) {
  const bool v3_live = v3_active && v3_running && v3_promoted;
  if (v3_live && v1_running) return WindowsTunnelProbeAlias::kRefuse;
  if (v3_active && !v3_live) return WindowsTunnelProbeAlias::kRefuse;
  if (v3_live) return WindowsTunnelProbeAlias::kWinn3;
  if (v1_running) return WindowsTunnelProbeAlias::kWinn1;
  return WindowsTunnelProbeAlias::kRefuse;
}

inline const char* WindowsTunnelProbeAliasName(WindowsTunnelProbeAlias alias) {
  switch (alias) {
    case WindowsTunnelProbeAlias::kWinn3:
      return kRelayAdapterName;
    case WindowsTunnelProbeAlias::kWinn1:
      return kWinn1AdapterName;
    case WindowsTunnelProbeAlias::kRefuse:
      break;
  }
  return "";
}

struct Winn3HostSessionSnapshot {
  Winn3StartProof proof;
  Winn3AwgXrayGrant grant;
  bool v3_active = false;
  bool v3_running = false;
  bool v3_promoted = false;
  bool v1_running = false;
};

class Winn3HostSessionGuard {
 public:
  void Store(const Winn3HostSessionSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot_ = snapshot;
  }

  Winn3HostSessionSnapshot Load() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
  }

 private:
  mutable std::mutex mutex_;
  Winn3HostSessionSnapshot snapshot_;
};

inline const char* Winn3ProofOutcomeName(Winn3ProofOutcome outcome) {
  switch (outcome) {
    case Winn3ProofOutcome::kConnected:
      return kWinn3ProofOutcomeConnected;
    case Winn3ProofOutcome::kOrdinaryConnectivity:
      return kWinn3ProofOutcomeOrdinaryConnectivity;
    case Winn3ProofOutcome::kTerminalSecurity:
      return kWinn3ProofOutcomeTerminalSecurity;
    case Winn3ProofOutcome::kUnknownTerminal:
      return kWinn3ProofOutcomeUnknownTerminal;
  }
  return kWinn3ProofOutcomeUnknownTerminal;
}

namespace winn3_proof_detail {

inline std::string AsciiLower(std::string value) {
  for (char& c : value) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

inline bool Contains(const std::string& lower, const char* token) {
  return lower.find(token) != std::string::npos;
}

inline bool HasSecurityEvidence(const std::string& lower) {
  return Contains(lower, "admission") || Contains(lower, "replay") ||
         Contains(lower, "pinning") || Contains(lower, "pin mismatch") ||
         Contains(lower, "descriptor pin") ||
         Contains(lower, "static key") || Contains(lower, "gateway id") ||
         Contains(lower, "gateway_id") ||
         Contains(lower, "unauthenticated") || Contains(lower, "credential") ||
         Contains(lower, "could not be opened") ||
         Contains(lower, "none of them could be opened") ||
         Contains(lower, "unopenable") || Contains(lower, "malformed") ||
         Contains(lower, "stale ack") ||
         Contains(lower, "disagrees with itself") ||
         Contains(lower, "proof integrity") ||
         Contains(lower, "not a single json") ||
         Contains(lower, "duplicate json") ||
         Contains(lower, "rx_offered but not") ||
         Contains(lower, "connection details could not be used") ||
         Contains(lower, "unexpected adapter name") ||
         Contains(lower, "node identity") ||
         Contains(lower, "selected node") ||
         Contains(lower, "descriptor node") ||
         Contains(lower, "selected_node") || Contains(lower, "cross-node");
}

inline bool IsWindowsOrdinaryNetworkOsError(int os_error) {
  return os_error == kWindowsWsaEnetdown || os_error == kWindowsWsaEnetunreach ||
         os_error == kWindowsWsaEhostdown || os_error == kWindowsWsaEhostunreach;
}

inline bool LooksCanceled(const std::string& lower) {
  return Contains(lower, "canceled") || Contains(lower, "cancelled");
}

}  // namespace winn3_proof_detail

inline Winn3ProofOutcome ClassifyWinn3ProofDiagnostic(
    const std::string& diagnostic, int os_error = 0, bool timed_out = false) {
  const std::string lower = winn3_proof_detail::AsciiLower(diagnostic);
  if (winn3_proof_detail::HasSecurityEvidence(lower)) {
    return Winn3ProofOutcome::kTerminalSecurity;
  }
  if (timed_out) return Winn3ProofOutcome::kUnknownTerminal;
  if (winn3_proof_detail::IsWindowsOrdinaryNetworkOsError(os_error)) {
    return Winn3ProofOutcome::kOrdinaryConnectivity;
  }
  return Winn3ProofOutcome::kUnknownTerminal;
}

inline Winn3StartProof ClassifyWinn3StartFailure(
    int64_t generation, bool canceled, const std::string& diagnostic,
    int os_error = 0, int64_t start_token = 0,
    const std::string& selection_generation = "",
    const std::string& failed_node = "", bool timed_out = false) {
  Winn3StartProof proof;
  proof.generation = generation;
  proof.start_token = start_token;
  proof.selection_generation = selection_generation;
  proof.failed_node = failed_node;
  proof.os_error = os_error;
  proof.canceled = canceled ||
                   winn3_proof_detail::LooksCanceled(
                       winn3_proof_detail::AsciiLower(diagnostic));
  if (proof.canceled) {
    proof.outcome = Winn3ProofOutcome::kUnknownTerminal;
    return proof;
  }
  proof.outcome =
      ClassifyWinn3ProofDiagnostic(diagnostic, os_error, timed_out);
  return proof;
}

// Production start-failure classifier. Consumes RememberWindowsWinn3OsError.
// Passing os_error=0 is the defect this helper exists to prevent.
inline Winn3StartProof ClassifyCapturedWinn3StartFailure(
    int64_t generation, bool canceled, const std::string& diagnostic,
    int64_t start_token = 0, const std::string& selection_generation = "",
    const std::string& failed_node = "", bool timed_out = false) {
  return ClassifyWinn3StartFailure(
      generation, canceled, diagnostic, TakeWindowsWinn3OsError(), start_token,
      selection_generation, failed_node, timed_out);
}

inline Winn3StartProof MakeConnectedWinn3StartProof(
    int64_t generation, int64_t start_token = 0,
    const std::string& selection_generation = "",
    const std::string& failed_node = "") {
  Winn3StartProof proof;
  proof.generation = generation;
  proof.start_token = start_token;
  proof.selection_generation = selection_generation;
  proof.failed_node = failed_node;
  proof.outcome = Winn3ProofOutcome::kConnected;
  proof.canceled = false;
  return proof;
}

inline int64_t Winn3AuthorizationToken(const Winn3StartProof& proof) {
  if (proof.canceled) return 0;
  if (proof.outcome != Winn3ProofOutcome::kOrdinaryConnectivity) return 0;
  if (proof.start_token <= 0 || proof.generation <= 0) return 0;
  return proof.start_token;
}

inline bool Winn3StartProofAuthorizesOrdinaryFallback(
    const Winn3StartProof& proof, int64_t expected_generation,
    int64_t expected_token = 0) {
  if (Winn3AuthorizationToken(proof) <= 0) return false;
  if (proof.generation != expected_generation) return false;
  if (expected_token > 0 && proof.start_token != expected_token) return false;
  return true;
}

// When a standalone v3 session is active, liveness is the v3 adapter plus
// the v3 engine in the promoted posture. Never the winn/1 `winsvpn` path.
inline bool WindowsWinn3StandaloneIsLive(bool v3_running, bool v3_promoted) {
  return v3_running && v3_promoted;
}

inline bool WindowsTunnelRunningConsideringV3(bool v3_active, bool v3_running,
                                              bool v3_promoted,
                                              bool v1_running) {
  if (v3_active) {
    return WindowsWinn3StandaloneIsLive(v3_running, v3_promoted);
  }
  return v1_running;
}

// RenderWin32CommandLine joins an argument vector.
inline std::string RenderWin32CommandLine(
    const std::vector<std::string>& argv) {
  std::string out;
  for (size_t i = 0; i < argv.size(); ++i) {
    if (i != 0) {
      out.push_back(' ');
    }
    out += QuoteWin32Argument(argv[i]);
  }
  return out;
}

// --- the Windows half -------------------------------------------------------

#if defined(WINS_TUNNEL_SERVICE_CORE)

// StartWindowsWinn3Tunnel runs the whole staged start, or leaves nothing
// running.
//
// THE ORDERING IS THE SAFETY PROPERTY, and it is the relay's, restated because
// the supervisor is the party that has to obey it:
//
//   1. start the relay; it binds 127.0.0.1:0 and prints `host-port <P>`
//   2. pin the outer socket's /32 on the PHYSICAL interface -- before any
//      tunnel route can exist -- and write the profile naming host_port = P
//   3. `-winn3-print-sizing` publishes inner_mtu with no network touched
//   4. start the engine; it prints its own seam port on stderr
//   5. write `start mtu=<M> engine-port=<E>` to the relay's stdin
//   6. the relay creates the adapter and prints `ready ...`
//   7. install the BOOTSTRAP posture on it: one /32, the inner next hop only,
//      MTU = M, no default route, no IPv6, no DNS
//   8. promote ONLY when the engine's status document reports promotion_ready
//
// THE ADAPTER DOES NOT EXIST UNTIL STEP 6, so there is no window in which
// Windows has an interface it might route traffic to before the layer that
// encrypts is reachable. And no route wider than one /32 exists until step 8,
// so there is no window in which user traffic is captured by a datapath that
// has not yet carried a single inner packet.
//
// Fail-closed on every outcome: on false, both children are dead, the adapter
// is gone with them, the posture is torn down and the /32 pin is withdrawn.
bool StartWindowsWinn3Tunnel(const Winn3HostConfig& config,
                             std::string* error);

// StopWindowsWinn3Tunnel tears the whole thing down. Safe when nothing runs.
void StopWindowsWinn3Tunnel();

// True while both children are alive and the adapter exists.
//
// Deliberately not "a process exists". A relay alive with a dead engine holds
// an adapter that carries nothing, and reporting that as a working tunnel is
// the exact failure this project has already been bitten by.
bool WindowsWinn3TunnelRunning();

// True once the promoted posture has been installed. False during bootstrap,
// which is a working tunnel that is not yet carrying the user's traffic.
bool WindowsWinn3TunnelPromoted();

// The last status document the engine published, or "" when none has been.
// Non-secret counters, an enum and two booleans; it carries no endpoint, no
// address and no session identifier, which is why it is safe to surface whole.
std::string WindowsWinn3StatusJson();

#endif  // WINS_TUNNEL_SERVICE_CORE

}  // namespace winsvpn::winn3

#endif  // RUNNER_WINN3_SUPERVISOR_H_
