#include "windows_winn_engine.h"

#include "winn_frame.h"
#include "winn_frame_selftest.h"

#if defined(WINS_TUNNEL_SERVICE_CORE)
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on

#include <atomic>
#include <cstring>
#include <mutex>
#endif  // WINS_TUNNEL_SERVICE_CORE

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace winsvpn::winn {
namespace {

// Mirrors WinnEngineConfig.kt and linux_winn_host.cc so the four hosts cannot
// drift. Every one of these is a restatement of a Go constant, not an opinion.
// The three anti-downgrade literals kWinnContractVersion / kWinnPayloadAwgDatagram
// / kWinnCarrierDirectAwg live in windows_winn_engine.h so the acknowledgement
// check that turns on them is compiled and exercised off Windows too.
constexpr int kMinDatagram = 32;
constexpr int kMaxDatagramCeiling = 1500;
constexpr size_t kMaxSessionIdBytes = 128;

std::string Trim(const std::string& value) {
  size_t begin = 0;
  size_t end = value.size();
  while (begin < end &&
         std::isspace(static_cast<unsigned char>(value[begin])) != 0) {
    ++begin;
  }
  while (end > begin &&
         std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }
  return value.substr(begin, end - begin);
}

std::string LowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::tolower(c));
                 });
  return value;
}

bool IsSectionHeaderLine(const std::string& line) {
  return line.size() >= 3 && line.front() == '[' && line.back() == ']';
}

// Minimal INI reader over the same config text the AmneziaWG path uses. It is a
// private copy on purpose: the equivalent helpers in windows_tunnel_backend.cpp
// live in an anonymous namespace, and reaching into that file would mean
// editing it.
std::map<std::string, std::string> ParseIniSection(const std::string& config,
                                                   const std::string& wanted) {
  std::map<std::string, std::string> out;
  std::istringstream stream(config);
  std::string line;
  bool in_section = false;
  const std::string target = LowerAscii(wanted);
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
      continue;
    }
    if (IsSectionHeaderLine(trimmed)) {
      in_section = LowerAscii(trimmed.substr(1, trimmed.size() - 2)) == target;
      continue;
    }
    if (!in_section) continue;
    const size_t equals = trimmed.find('=');
    if (equals == std::string::npos) continue;
    out[LowerAscii(Trim(trimmed.substr(0, equals)))] =
        Trim(trimmed.substr(equals + 1));
  }
  return out;
}

bool SectionTruthy(const std::map<std::string, std::string>& section,
                   const std::string& key) {
  const auto it = section.find(key);
  if (it == section.end()) return false;
  const std::string value = LowerAscii(Trim(it->second));
  return value == "true" || value == "1" || value == "yes" || value == "y";
}

// Parses an unsigned decimal that fits in 64 bits. Returns false on anything
// else, including a leading sign, whitespace inside, or overflow.
bool ParseUnsigned(const std::string& text, uint64_t max, uint64_t* out) {
  if (text.empty() || text.size() > 20) return false;
  uint64_t value = 0;
  for (const char raw : text) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (std::isdigit(c) == 0) return false;
    const uint64_t digit = static_cast<uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10) return false;
    value = value * 10 + digit;
  }
  if (value > max) return false;
  *out = value;
  return true;
}

bool ParseHeaderSpec(const std::string& raw, WindowsAwgHeaderSpec* out) {
  if (out == nullptr) return false;
  const std::string text = Trim(raw);
  if (text.empty() || text.size() > 21) return false;
  for (const unsigned char c : text) {
    if (c == '\r' || c == '\n' || c == '\0') return false;
    if (std::isspace(c) != 0) return false;
  }
  const size_t sep = text.find('-');
  if (sep == std::string::npos) {
    if (text.size() > 10) return false;
    uint64_t v = 0;
    if (!ParseUnsigned(text, 0xFFFFFFFFULL, &v) || v < 5) return false;
    out->start = static_cast<uint32_t>(v);
    out->end = static_cast<uint32_t>(v);
    return true;
  }
  const std::string startText = text.substr(0, sep);
  const std::string endText = text.substr(sep + 1);
  if (startText.empty() || endText.empty()) return false;
  if (endText.find('-') != std::string::npos) return false;
  if (startText.size() > 10 || endText.size() > 10) return false;
  uint64_t s = 0, e = 0;
  if (!ParseUnsigned(startText, 0xFFFFFFFFULL, &s) || s < 5) return false;
  if (!ParseUnsigned(endText, 0xFFFFFFFFULL, &e)) return false;
  if (e < s) return false;
  uint64_t width = e - s + 1;
  if (width > 0xFFFFFFFFULL || width == 0) return false;
  out->start = static_cast<uint32_t>(s);
  out->end = static_cast<uint32_t>(e);
  return true;
}

// Deliberately hand-written rather than InetPtonA, so this whole parsing layer
// compiles and can be exercised without <winsock2.h> -- the same reason
// winn_frame.h is standard C++17. It is the exact rule
// lib/winn_protocol_dispatch.dart applies, which is in turn the exact rule
// datapath.validateIPLiteralEndpoint applies: a routable unicast literal, never
// the unspecified address and never multicast.
bool IsIpv4Literal(const std::string& host) {
  size_t start = 0;
  int octets = 0;
  bool all_zero = true;
  uint32_t first = 0;
  while (start <= host.size()) {
    const size_t dot = host.find('.', start);
    const std::string part =
        dot == std::string::npos ? host.substr(start) : host.substr(start, dot - start);
    if (part.empty() || part.size() > 3) return false;
    uint64_t value = 0;
    if (!ParseUnsigned(part, 255, &value)) return false;
    if (value != 0) all_zero = false;
    if (octets == 0) first = static_cast<uint32_t>(value);
    ++octets;
    if (dot == std::string::npos) break;
    start = dot + 1;
    if (start > host.size()) return false;
  }
  if (octets != 4 || all_zero) return false;
  return first < 224 || first > 239;  // not multicast
}

bool IsIpv6Literal(const std::string& host) {
  if (host.empty() || host == "::") return false;
  for (const char c : host) {
    if (std::isxdigit(static_cast<unsigned char>(c)) == 0 && c != ':' &&
        c != '.') {
      return false;
    }
  }
  if (host.find(':') == std::string::npos) return false;
  if (LowerAscii(host).rfind("ff", 0) == 0) return false;  // ff00::/8 multicast
  size_t double_colons = 0;
  for (size_t index = 0; index + 1 < host.size(); ++index) {
    if (host[index] == ':' && host[index + 1] == ':') ++double_colons;
  }
  if (double_colons > 1) return false;
  size_t groups = 0;
  size_t start = 0;
  while (start <= host.size()) {
    const size_t colon = host.find(':', start);
    const std::string part = colon == std::string::npos
                                 ? host.substr(start)
                                 : host.substr(start, colon - start);
    if (!part.empty()) {
      if (part.size() > 4 && part.find('.') == std::string::npos) return false;
      ++groups;
    }
    if (colon == std::string::npos) break;
    start = colon + 1;
  }
  return groups >= 1 && groups <= 8;
}

std::string JsonEscape(const std::string& value) {
  std::string out;
  out.reserve(value.size() + 8);
  for (const char raw : value) {
    const unsigned char c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          static const char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out += kHex[(c >> 4) & 0xF];
          out += kHex[c & 0xF];
        } else {
          out += raw;
        }
    }
  }
  return out;
}

}  // namespace

bool WindowsConfigSelectsWinnProtocol(const std::string& raw_config) {
  return SectionTruthy(ParseIniSection(raw_config, "winn"), "enabled");
}

bool SplitWindowsWinnEndpoint(const std::string& endpoint,
                              std::string* host,
                              std::string* port) {
  if (endpoint.empty() || host == nullptr || port == nullptr) return false;
  std::string parsed_host;
  std::string parsed_port;
  if (endpoint.front() == '[') {
    const size_t end = endpoint.find(']');
    if (end == std::string::npos || end + 1 >= endpoint.size() ||
        endpoint[end + 1] != ':') {
      return false;
    }
    parsed_host = endpoint.substr(1, end - 1);
    parsed_port = endpoint.substr(end + 2);
    if (!IsIpv6Literal(parsed_host)) return false;
  } else {
    const size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon == 0) return false;
    parsed_host = endpoint.substr(0, colon);
    parsed_port = endpoint.substr(colon + 1);
    if (!IsIpv4Literal(parsed_host)) return false;
  }
  uint64_t port_value = 0;
  if (!ParseUnsigned(parsed_port, 65535, &port_value) || port_value == 0) {
    return false;
  }
  *host = parsed_host;
  *port = parsed_port;
  return true;
}

std::string WindowsWinnCarrierHost(const std::string& raw_config) {
  const std::map<std::string, std::string> section =
      ParseIniSection(raw_config, "winn");
  if (!SectionTruthy(section, "enabled")) return "";
  const auto endpoint = section.find("endpoint");
  if (endpoint == section.end()) return "";
  std::string host;
  std::string port;
  if (!SplitWindowsWinnEndpoint(Trim(endpoint->second), &host, &port)) {
    return "";
  }
  return host;
}

bool ParseWindowsWinnSection(const std::string& raw_config,
                             WindowsWinnParams* out,
                             std::string* error) {
  if (out == nullptr || error == nullptr) return false;
  const std::map<std::string, std::string> section =
      ParseIniSection(raw_config, "winn");
  if (!SectionTruthy(section, "enabled")) {
    *error = "The Winn Protocol section is not enabled.";
    return false;
  }

  WindowsWinnParams params;

  // THE CARRIER GATE, and it is checked FIRST on purpose.
  //
  // This is the native anti-downgrade check: a configuration naming a carrier
  // this host cannot build must fail, never quietly become direct-awg. It runs
  // before the unknown-key sweep below because a carrier session's `[winn]`
  // section also carries the carrier-profile keys (masque_template,
  // public_target, suite, ...) that build the separate document
  // `winn-datapath -carrier-profile` reads. Sweeping first would refuse such a
  // config for carrying "masque_template", which is true but names the wrong
  // cause; this host's actual limitation is that it builds direct-awg only.
  //
  // Windows can gain http3-connect-udp the day it writes that profile document
  // to a DACL'd path and adds `-carrier-profile <path>` to the argv below --
  // which is now an argv that already carries a flag, precisely so that is a
  // one-line change rather than a redesign.
  const auto carrier_entry = section.find("carrier");
  const std::string carrier = carrier_entry == section.end() ||
                                      Trim(carrier_entry->second).empty()
                                  ? std::string(kWinnCarrierDirectAwg)
                                  : LowerAscii(Trim(carrier_entry->second));
  if (carrier != kWinnCarrierDirectAwg) {
    *error = "This server selected the \"" + carrier +
             "\" Winn Protocol v3 transport. This Windows build carries "
             "AmneziaWG datagrams straight to the gateway and cannot build "
             "that carrier, and starting an unauthenticated transport instead "
             "would downgrade the session the server negotiated, so the "
             "connection was stopped.";
    return false;
  }

  // An UNRECOGNISED KEY IS A REFUSAL. WinnEngineConfig.from throws on one and
  // datapath.ParseConfig decodes with DisallowUnknownFields, so dropping it
  // here would be the one place in the chain that lies about what took effect.
  //
  // KNOWN DEBT, WITH A NAMED TRIGGER -- READ THIS BEFORE WIDENING THE CARRIER
  // GATE ABOVE.
  //
  // These thirteen are hand-typed, and they are the FIFTH such allowlist in the
  // repository. The other four (Kotlin, Swift, Dart, and linux_winn_host.cc)
  // were converted to a generated list derived from carrierhost.Profile's own
  // json tags, because four identical hand-typed copies is exactly how five
  // spa_ fields came to be unreachable from every platform at once with nothing
  // failing anywhere. See winn_protocol_experimental/datapath/carrierhost/
  // servedkeys.go and cmd/winn-carrier-keys.
  //
  // This list was left OUT of that scheme deliberately, and it is not a live
  // defect: the carrier gate above refuses everything but direct-awg before
  // this sweep is reached, Windows is `absent` in kWinnHostCapabilities, and
  // spa_* is only ever served with http3. It is also not the same kind of list
  // -- these are `[winn]`-SECTION HOST names (endpoint, max_datagram, h1..h4,
  // s1..s4), not carrierhost.Profile fields and not datapath.Config json tags,
  // so there is no Go declaration to generate them from. Unioning the generated
  // carrier keys in TODAY would additionally make this host silently ACCEPT and
  // ignore masque_template / spa_* on a direct-awg section, turning a loud
  // refusal into a silent drop.
  //
  // THE TRIGGER: the day this host gains carrier support it will build a
  // carrierhost.Profile document, carrierhost.Profile becomes its authority,
  // and this hand-typed list will drift from it exactly as the other four did.
  // At that point include the generated key list (see
  // linux/runner/linux_winn_carrier_profile_keys.h and how
  // linux_winn_host.cc unions kServedCarrierProfileKeys into its own sweep) and
  // register the new file in GeneratedPlatformKeyFiles().
  //
  // This is not left to memory: TestWindowsJoinsTheKeySchemeIfItEverGainsACarrier
  // in datapath/carrierhost/servedkeys_test.go FAILS the build the moment the
  // gate above stops being "everything but direct-awg is refused" while this
  // list is still hand-typed.
  static const std::array<const char*, 13> kKnownKeys = {
      "enabled", "endpoint", "session_id", "max_datagram", "carrier",
      "h1",      "h2",       "h3",         "h4",
      "s1",      "s2",       "s3",         "s4"};
  for (const auto& entry : section) {
    if (entry.first.empty()) continue;
    const bool known =
        std::find_if(kKnownKeys.begin(), kKnownKeys.end(),
                     [&entry](const char* key) {
                       return entry.first == key;
                     }) != kKnownKeys.end();
    if (!known) {
      *error = "The Winn Protocol section carries \"" + entry.first +
               "\", which is not a field of the engine's configuration; the "
               "engine rejects unknown fields.";
      return false;
    }
  }

  const auto endpoint_entry = section.find("endpoint");
  params.endpoint =
      endpoint_entry == section.end() ? "" : Trim(endpoint_entry->second);
  std::string host;
  std::string port;
  if (!SplitWindowsWinnEndpoint(params.endpoint, &host, &port)) {
    *error =
        "The Winn Protocol gateway endpoint is not an IP literal with a port. "
        "The engine will not resolve a hostname, because that lookup would "
        "leave the device outside the tunnel.";
    return false;
  }

  const auto session_entry = section.find("session_id");
  params.session_id =
      session_entry == section.end() ? "" : Trim(session_entry->second);
  if (params.session_id.size() > kMaxSessionIdBytes) {
    *error = "The Winn Protocol session identifier is too long.";
    return false;
  }

  const auto datagram_entry = section.find("max_datagram");
  if (datagram_entry != section.end() &&
      !Trim(datagram_entry->second).empty()) {
    uint64_t value = 0;
    if (!ParseUnsigned(Trim(datagram_entry->second),
                       static_cast<uint64_t>(kMaxDatagramCeiling), &value) ||
        value < static_cast<uint64_t>(kMinDatagram)) {
      *error =
          "The Winn Protocol datagram size is outside the range the engine "
          "accepts.";
      return false;
    }
    params.max_datagram = static_cast<int>(value);
  } else {
    params.max_datagram = kMaxDatagramCeiling;
  }

  // WINN_MANDATORY_HEADERS 2026-08-08: h1..h4 are REQUIRED for winn/3.
  // A blind classifier (no h1..h4) makes transport_observed_both_ways never fire
  // and keeps the convergence gate WARNED AND PROMOTED — a dead tunnel reported as
  // connected, worse than no gate. Hub always serves all four, so mandatory
  // cannot fleet-lockout. Each h1..h4 may be a scalar (44) or a range
  // (16777216-1086324735); ParseHeaderSpec handles both and the non-overlap test
  // is interval intersection rather than equality — the engine's own mergeWithDevice
  // refuses an overlapping set, so accepting one here would hand the host a config
  // it cannot start. For scalars this degrades to equality. Each header is an
  // AwgHeaderSpec (start-end) where a bare value is the degenerate range
  // start==end.
  static const std::array<const char*, 4> kHeaderKeys = {"h1", "h2", "h3",
                                                          "h4"};
  static const std::array<const char*, 4> kPaddingKeys = {"s1", "s2", "s3",
                                                           "s4"};
  int header_present = 0;
  // 0xFFFFFFFF ceiling parity
  for (size_t index = 0; index < kHeaderKeys.size(); ++index) {
    const auto entry = section.find(kHeaderKeys[index]);
    if (entry == section.end() || Trim(entry->second).empty()) continue;
    WindowsAwgHeaderSpec spec;
    if (!ParseHeaderSpec(entry->second, &spec)) {
      *error =
          "The Winn Protocol AmneziaWG header types must be 32-bit unsigned "
          "values or ranges.";
      return false;
    }
    params.h[index] = spec;
    ++header_present;
  }
  if (header_present != 4) {
    std::string missing;
    for (size_t i = 0; i < kHeaderKeys.size(); ++i) {
      const auto e = section.find(kHeaderKeys[i]);
      if (e == section.end() || Trim(e->second).empty()) {
        if (!missing.empty()) missing += ", ";
        missing += kHeaderKeys[i];
      }
    }
    *error =
        "The Winn Protocol AmneziaWG header types h1..h4 are REQUIRED for winn/3; missing " +
        (missing.empty() ? std::string("all four") : missing) +
        " — without them transport_observed_both_ways can never fire and the convergence gate cannot protect the tunnel.";
    return false;
  }
  for (int a = 0; a < 4; ++a) {
    for (int b = a + 1; b < 4; ++b) {
      if (params.h[a].overlaps(params.h[b])) {
        *error =
            "The Winn Protocol AmneziaWG header types must be pairwise "
            "distinct.";
        return false;
      }
    }
  }
  for (size_t index = 0; index < kPaddingKeys.size(); ++index) {
    const auto entry = section.find(kPaddingKeys[index]);
    if (entry == section.end() || Trim(entry->second).empty()) continue;
    uint64_t value = 0;
    if (!ParseUnsigned(Trim(entry->second), 0xFFFFull, &value)) {
      *error =
          "The Winn Protocol AmneziaWG padding sizes must be 16-bit unsigned "
          "values.";
      return false;
    }
    if (header_present != 4 && value != 0) {
      *error =
          "The Winn Protocol AmneziaWG padding sizes require the header types "
          "they are offsets into.";
      return false;
    }
    params.s[index] = static_cast<uint16_t>(value);
  }

  *out = params;
  return true;
}

bool RewriteAwgPeerEndpointToSeam(const std::string& awg_config,
                                  uint16_t seam_port,
                                  std::string* out) {
  if (out == nullptr || seam_port == 0) return false;
  std::istringstream stream(awg_config);
  std::ostringstream rewritten;
  std::string line;
  int replaced = 0;
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    const size_t equals = trimmed.find('=');
    const std::string key =
        equals == std::string::npos
            ? ""
            : LowerAscii(Trim(trimmed.substr(0, equals)));
    if (key == "endpoint") {
      ++replaced;
      rewritten << "Endpoint = 127.0.0.1:" << seam_port << "\n";
    } else {
      rewritten << line << "\n";
    }
  }
  // EXACTLY one. Zero would leave AmneziaWG with nowhere to send and two would
  // mean one of them still points at the real gateway, so its outer datagrams
  // would leave this host unprotected while we believed they were carried.
  if (replaced != 1) return false;
  *out = rewritten.str();
  return true;
}

std::string BuildWindowsWinnConfigJson(const WindowsWinnParams& params) {
  // Key order matches WinnEngineConfig.toConfigJson() and
  // BuildLinuxWinnConfigJson so the four platforms' Create payloads can be
  // compared byte for byte in review.
  std::ostringstream json;
  json << "{\"contract\":\"" << kWinnContractVersion << "\""
       << ",\"payload\":\"" << kWinnPayloadAwgDatagram << "\""
       << ",\"carrier\":\"" << kWinnCarrierDirectAwg << "\""
       << ",\"gateway_endpoint\":\"" << JsonEscape(params.endpoint) << "\""
       << ",\"max_datagram\":" << params.max_datagram;
  if (!params.session_id.empty()) {
    json << ",\"session_id\":\"" << JsonEscape(params.session_id) << "\"";
  }
  // TRUE only here, and only honestly: datapath/carrier.go permits an engine to
  // open its own socket when transportFD < 0 exactly because the desktop model
  // excludes that socket by route instead of by descriptor. The caller has
  // pinned the /32 for params.endpoint on the physical LUID before this runs.
   json << ",\"allow_own_socket\":true";
   const bool has_headers = params.h[0].start != 0 || params.h[1].start != 0 ||
                            params.h[2].start != 0 || params.h[3].start != 0;
   if (has_headers) {
     json << ",\"awg_header_types\":{";
     for (int i = 0; i < 4; ++i) {
       if (i > 0) json << ",";
       json << "\"h" << (i + 1) << "\":";
       if (params.h[i].isRange()) {
         json << "\"" << params.h[i].spec() << "\"";
       } else {
         json << params.h[i].start;
       }
     }
     json << ",\"s1\":" << params.s[0] << ",\"s2\":" << params.s[1]
          << ",\"s3\":" << params.s[2] << ",\"s4\":" << params.s[3] << "}";
   }
   json << "}";
   return json.str();
}

bool RunWindowsWinnFramingSelfTest(std::string* error) {
  std::string failure;
  if (RunWinnFrameSelfTest(&failure)) {
    return true;
  }
  if (error != nullptr) {
    *error = "Winn engine framing self-test failed: " + failure;
  }
  return false;
}

#if defined(WINS_TUNNEL_SERVICE_CORE)

namespace {

constexpr DWORD kCreateAckTimeoutMilliseconds = 10000;
constexpr DWORD kStatusTimeoutMilliseconds = 2000;
constexpr DWORD kCloseAckWaitMilliseconds = 750;
constexpr DWORD kEngineStopWaitMilliseconds = 5000;
constexpr DWORD kPumpJoinTimeoutMilliseconds = 10000;
constexpr DWORD kPipeReadChunkBytes = 65536;

struct EngineState {
  PROCESS_INFORMATION process = {};
  HANDLE job = nullptr;
  HANDLE stdin_pipe = INVALID_HANDLE_VALUE;   // host -> engine frames
  HANDLE stdout_pipe = INVALID_HANDLE_VALUE;  // engine -> host frames

  SOCKET seam = INVALID_SOCKET;
  WSAEVENT seam_readable = WSA_INVALID_EVENT;

  HANDLE quit_event = nullptr;
  HANDLE status_event = nullptr;
  HANDLE close_ack_event = nullptr;
  HANDLE inbound_thread = nullptr;   // seam -> Inbound frames
  HANDLE outbound_thread = nullptr;  // Outbound frames -> seam

  std::mutex write_mutex;
  std::mutex status_mutex;
  std::string last_status;
  std::string failure;

  std::atomic<bool> stopping{false};
  std::atomic<bool> channel_up{false};
  std::atomic<uint64_t> seam_to_engine{0};
  std::atomic<uint64_t> engine_to_seam{0};

  // The AWG engine's own source address: 127.0.0.1 and the listen_port its
  // runtime reported, set by StartWindowsWinnEngine before either pump starts
  // and never learned from traffic. Mirrors RelayConfig.ExpectedLocalPeer:
  // datagrams from any other local process are dropped, including one that
  // reaches the seam first. Written once, before either pump thread exists,
  // and published by the release store to awg_peer_known. Both pumps read it
  // per datagram without a lock: an acquire load that sees true also sees the
  // pin. Nothing may write awg_peer after that store.
  sockaddr_in awg_peer = {};
  std::atomic<bool> awg_peer_known{false};

  int max_datagram = kMaxDatagramCeiling;

  // Latched from the params this host started the session with, and never from
  // anything the engine says back. It is the input to the route-promotion gate:
  // false means the datapath's transport counters cannot fire, so no proof is
  // obtainable and the session must be refused rather than promoted. Immutable
  // for the life of the session, so the gate reads it under g_lifecycle_mutex
  // without any further synchronisation.
  bool headers_classify = false;
};

std::mutex g_lifecycle_mutex;
EngineState* g_engine = nullptr;
std::atomic<bool> g_winsock_ready{false};

bool EnsureWinsock() {
  if (g_winsock_ready.load(std::memory_order_acquire)) return true;
  WSADATA data = {};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
  g_winsock_ready.store(true, std::memory_order_release);
  return true;
}

void CloseHandleIfValid(HANDLE* handle) {
  if (handle == nullptr) return;
  if (*handle != nullptr && *handle != INVALID_HANDLE_VALUE) {
    CloseHandle(*handle);
  }
  *handle = INVALID_HANDLE_VALUE;
}

void CloseEventIfValid(HANDLE* handle) {
  if (handle == nullptr || *handle == nullptr) return;
  CloseHandle(*handle);
  *handle = nullptr;
}

bool WriteAll(HANDLE pipe, const uint8_t* bytes, size_t size) {
  size_t written_total = 0;
  while (written_total < size) {
    DWORD written = 0;
    const DWORD chunk =
        static_cast<DWORD>(std::min<size_t>(size - written_total, 1u << 20));
    if (WriteFile(pipe, bytes + written_total, chunk, &written, nullptr) ==
            FALSE ||
        written == 0) {
      return false;
    }
    written_total += written;
  }
  return true;
}

bool WriteFrame(EngineState* state,
                Opcode opcode,
                const uint8_t* payload,
                size_t size) {
  std::vector<uint8_t> frame;
  if (!EncodeFrame(opcode, payload, size, &frame)) return false;
  std::lock_guard<std::mutex> guard(state->write_mutex);
  if (state->stdin_pipe == INVALID_HANDLE_VALUE) return false;
  return WriteAll(state->stdin_pipe, frame.data(), frame.size());
}

void RecordFailure(EngineState* state, const std::string& reason) {
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    if (state->failure.empty()) state->failure = reason;
  }
  state->channel_up.store(false, std::memory_order_release);
  // Release anyone waiting on a reply that is never going to arrive.
  if (state->status_event != nullptr) SetEvent(state->status_event);
  if (state->close_ack_event != nullptr) SetEvent(state->close_ack_event);
}

// Reads engine->host frames and demultiplexes by opcode. Outbound frames
// interleave with responses at any time, so this cannot assume request/response
// ordering -- the Go duplex package says so explicitly, and a host that assumed
// otherwise would deadlock on the first datagram that overtook a status reply.
DWORD WINAPI OutboundPump(LPVOID parameter) {
  EngineState* state = static_cast<EngineState*>(parameter);
  FrameReader reader(/*accept_engine_to_host=*/true);
  std::vector<uint8_t> chunk(kPipeReadChunkBytes);
  for (;;) {
    DWORD read = 0;
    if (ReadFile(state->stdout_pipe, chunk.data(),
                 static_cast<DWORD>(chunk.size()), &read, nullptr) == FALSE ||
        read == 0) {
      if (!state->stopping.load(std::memory_order_acquire)) {
        RecordFailure(state, "the Winn engine closed its channel");
      }
      break;
    }
    reader.Append(chunk.data(), read);
    bool fatal = false;
    for (;;) {
      Frame frame;
      const DecodeStatus status = reader.Next(&frame);
      if (status == DecodeStatus::kNeedMore) break;
      if (status == DecodeStatus::kInvalid) {
        // Never resynchronize. Scanning forward for the next magic turns a
        // length confusion into an attacker-chosen frame boundary.
        RecordFailure(state, "the Winn engine sent an invalid frame");
        fatal = true;
        break;
      }
      if (frame.opcode == Opcode::kOutbound) {
        // Unreachable while StartWindowsWinnEngine pins the reported port;
        // kept so an unpinned state can never invent a destination.
        if (!state->awg_peer_known.load(std::memory_order_acquire)) continue;
        const sockaddr_in peer = state->awg_peer;
        const int sent =
            sendto(state->seam, reinterpret_cast<const char*>(
                                    frame.payload.data()),
                   static_cast<int>(frame.payload.size()), 0,
                   reinterpret_cast<const sockaddr*>(&peer),
                   static_cast<int>(sizeof(peer)));
        if (sent > 0) {
          state->engine_to_seam.fetch_add(1, std::memory_order_relaxed);
        }
        continue;
      }
      if (frame.opcode == Opcode::kCreateAck ||
          frame.opcode == Opcode::kStatusResponse) {
        {
          std::lock_guard<std::mutex> guard(state->status_mutex);
          state->last_status.assign(frame.payload.begin(),
                                    frame.payload.end());
        }
        SetEvent(state->status_event);
        continue;
      }
      if (frame.opcode == Opcode::kCloseAck) {
        SetEvent(state->close_ack_event);
        fatal = true;
        break;
      }
      if (frame.opcode == Opcode::kError) {
        std::string text(frame.payload.begin(), frame.payload.end());
        if (text.size() > 300) text.resize(300);
        RecordFailure(state, "the Winn engine reported: " + text);
        fatal = true;
        break;
      }
      RecordFailure(state, "the Winn engine sent an unexpected frame");
      fatal = true;
      break;
    }
    if (fatal) break;
  }
  // Unblock a waiter that would otherwise sit out its whole timeout.
  if (state->status_event != nullptr) SetEvent(state->status_event);
  return 0;
}

// Reads AmneziaWG's outer datagrams off the seam and frames them as Inbound.
DWORD WINAPI InboundPump(LPVOID parameter) {
  EngineState* state = static_cast<EngineState*>(parameter);
  // maxDatagram+1, exactly as internal/carrier/relay.go, the Android seam and
  // linux_winn_host.cc do, so an oversize datagram is DETECTED rather than
  // silently truncated: a truncated AWG datagram would fail authentication at
  // the gateway and look like a network fault instead of a configuration one.
  std::vector<uint8_t> buffer(static_cast<size_t>(state->max_datagram) + 1);
  const HANDLE waits[2] = {state->seam_readable, state->quit_event};
  for (;;) {
    const DWORD wait =
        WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (wait != WAIT_OBJECT_0) break;  // quit, abandoned, or failed
    // FD_READ re-arms on the next recvfrom that leaves the buffer non-empty,
    // so reset before draining rather than after.
    WSAResetEvent(state->seam_readable);
    for (;;) {
      sockaddr_in sender = {};
      int sender_size = static_cast<int>(sizeof(sender));
      const int count =
          recvfrom(state->seam, reinterpret_cast<char*>(buffer.data()),
                   static_cast<int>(buffer.size()), 0,
                   reinterpret_cast<sockaddr*>(&sender), &sender_size);
      if (count == SOCKET_ERROR) {
        const int last = WSAGetLastError();
        if (last == WSAEWOULDBLOCK) break;
        // WSAEMSGSIZE means a datagram larger than maxDatagram+1 arrived and
        // was truncated by the stack. It is dropped for the same reason the
        // explicit oversize check below drops one: a truncated AWG datagram is
        // worse than a missing one.
        if (last == WSAEMSGSIZE || last == WSAECONNRESET ||
            last == WSAEINTR) {
          continue;
        }
        if (!state->stopping.load(std::memory_order_acquire)) {
          RecordFailure(state, "the Winn seam failed while reading");
        }
        return 0;
      }
      if (count == 0) continue;
      // Structural containment, restated as a check: the seam is bound to
      // 127.0.0.1, so a non-loopback sender cannot arrive, but the pin is
      // what keeps a second local process from injecting into this tunnel.
      // The pin is the runtime's reported listen_port, set before the pumps
      // start; the first sender is never adopted, because any local process
      // can be first.
      if (sender.sin_family != AF_INET ||
          (ntohl(sender.sin_addr.s_addr) >> 24) != 127) {
        continue;
      }
      if (!state->awg_peer_known.load(std::memory_order_acquire) ||
          state->awg_peer.sin_port != sender.sin_port ||
          state->awg_peer.sin_addr.s_addr != sender.sin_addr.s_addr) {
        continue;  // not the AmneziaWG runtime's own socket
      }
      if (count > state->max_datagram) {
        continue;  // oversize: dropped, never truncated
      }
      if (!WriteFrame(state, Opcode::kInbound, buffer.data(),
                      static_cast<size_t>(count))) {
        if (!state->stopping.load(std::memory_order_acquire)) {
          RecordFailure(state, "the Winn engine channel failed while writing");
        }
        return 0;
      }
      state->seam_to_engine.fetch_add(1, std::memory_order_relaxed);
    }
  }
  return 0;
}

// Launches the engine with only the three standard handles inherited. The
// kill-on-close job mirrors StartWinsAwgEngine: if this service dies for any
// reason, the engine dies with it rather than being left holding a socket.
bool LaunchEngineProcess(EngineState* state,
                         const std::wstring& engine_path,
                         std::string* error) {
  SECURITY_ATTRIBUTES inheritable = {};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;

  HANDLE child_stdin = INVALID_HANDLE_VALUE;
  HANDLE child_stdout = INVALID_HANDLE_VALUE;
  HANDLE host_write = INVALID_HANDLE_VALUE;
  HANDLE host_read = INVALID_HANDLE_VALUE;
  HANDLE child_stderr = INVALID_HANDLE_VALUE;
  HANDLE job = nullptr;
  const auto abandon = [&](const char* message) {
    CloseHandleIfValid(&child_stdin);
    CloseHandleIfValid(&child_stdout);
    CloseHandleIfValid(&child_stderr);
    CloseHandleIfValid(&host_write);
    CloseHandleIfValid(&host_read);
    if (job != nullptr) CloseHandle(job);
    *error = message;
    return false;
  };

  if (CreatePipe(&child_stdin, &host_write, &inheritable, 0) == FALSE ||
      CreatePipe(&host_read, &child_stdout, &inheritable, 0) == FALSE) {
    return abandon("Unable to create the Winn engine duplex pipe.");
  }
  // The host ends must never reach the child, or the child would hold its own
  // read end open and teardown could not rely on a broken pipe.
  if (SetHandleInformation(host_write, HANDLE_FLAG_INHERIT, 0) == FALSE ||
      SetHandleInformation(host_read, HANDLE_FLAG_INHERIT, 0) == FALSE) {
    return abandon("Unable to secure the Winn engine pipe handles.");
  }
  // Under -transport stdio the engine's stdout carries frames and every
  // diagnostic goes to stderr. Those bytes must not land in the framed stream,
  // so stderr goes to the null device.
  child_stderr =
      CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
                  &inheritable, OPEN_EXISTING, 0, nullptr);
  job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits = {};
  job_limits.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (child_stderr == INVALID_HANDLE_VALUE || job == nullptr ||
      SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                              &job_limits, sizeof(job_limits)) == FALSE) {
    return abandon("Unable to create the Winn engine lifetime boundary.");
  }

  // Inherit exactly the three redirected handles and nothing else. In
  // particular the seam socket is created with WSA_FLAG_NO_HANDLE_INHERIT and
  // does not appear here: the engine opens its OWN outer socket and must never
  // be handed the loopback one.
  HANDLE inherited[3] = {child_stdin, child_stdout, child_stderr};
  SIZE_T attribute_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
  std::vector<uint8_t> attribute_storage(attribute_size);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes =
      reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  const bool attributes_ready =
      attribute_size != 0 &&
      InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) !=
          FALSE &&
      UpdateProcThreadAttribute(attributes, 0,
                                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                sizeof(inherited), nullptr, nullptr) != FALSE;

  STARTUPINFOEXW startup = {};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = child_stdin;
  startup.StartupInfo.hStdOutput = child_stdout;
  startup.StartupInfo.hStdError = child_stderr;
  startup.lpAttributeList = attributes;

  // The engine DOES take arguments, and this launch passes one.
  //
  // A previous revision said "the engine accepts no arguments" and launched a
  // bare image path. That was true of the test double and false of
  // cmd/winn-datapath, which already accepts -transport, -udp-fd, -receive-fd
  // and -carrier-profile; Android passes arguments today. `-transport stdio`
  // is also the engine's default, so this line changes nothing at runtime --
  // it exists so the argv is a real argv, and so adding `-carrier-profile
  // <path>` when Windows gains an authenticated carrier is one token rather
  // than a redesign. Quoting the image path keeps a space in the install
  // directory from being parsed as an argument.
  std::wstring command = L"\"" + engine_path + L"\" -transport stdio";
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  const size_t separator = engine_path.find_last_of(L"\\/");
  const std::wstring working_directory =
      separator == std::wstring::npos ? L"" : engine_path.substr(0, separator);

  PROCESS_INFORMATION process = {};
  bool created =
      attributes_ready &&
      CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | CREATE_SUSPENDED |
                         EXTENDED_STARTUPINFO_PRESENT,
                     nullptr,
                     working_directory.empty() ? nullptr
                                               : working_directory.c_str(),
                     &startup.StartupInfo, &process) != FALSE;
  if (created && (AssignProcessToJobObject(job, process.hProcess) == FALSE ||
                  ResumeThread(process.hThread) == static_cast<DWORD>(-1))) {
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, 3000);
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    process = PROCESS_INFORMATION{};
    created = false;
  }
  if (attributes_ready) DeleteProcThreadAttributeList(attributes);
  // The child owns its ends now; the host must drop them so a child exit is
  // observable as a broken pipe rather than blocking forever.
  CloseHandleIfValid(&child_stdin);
  CloseHandleIfValid(&child_stdout);
  CloseHandleIfValid(&child_stderr);

  if (!created || process.hProcess == nullptr) {
    CloseHandleIfValid(&host_write);
    CloseHandleIfValid(&host_read);
    if (job != nullptr) CloseHandle(job);
    *error = "Unable to launch the Win's VPN Winn Protocol engine.";
    return false;
  }
  CloseHandle(process.hThread);
  process.hThread = nullptr;
  state->process = process;
  state->job = job;
  state->stdin_pipe = host_write;
  state->stdout_pipe = host_read;
  return true;
}

// Tears everything down in the one order that is safe: stop producing, ask the
// engine to close, kill it, join both pumps, and only then free what the pumps
// were touching. Caller holds g_lifecycle_mutex.
void TeardownLocked(EngineState* state) {
  state->stopping.store(true, std::memory_order_release);
  state->channel_up.store(false, std::memory_order_release);

  // Ask politely first so the engine can flush and answer CloseAck.
  if (state->stdin_pipe != INVALID_HANDLE_VALUE &&
      state->process.hProcess != nullptr) {
    WriteFrame(state, Opcode::kClose, nullptr, 0);
    if (state->close_ack_event != nullptr) {
      WaitForSingleObject(state->close_ack_event, kCloseAckWaitMilliseconds);
    }
    if (WaitForSingleObject(state->process.hProcess,
                            kEngineStopWaitMilliseconds) != WAIT_OBJECT_0) {
      if (state->job != nullptr) {
        TerminateJobObject(state->job, 1);
      } else {
        TerminateProcess(state->process.hProcess, 1);
      }
      WaitForSingleObject(state->process.hProcess,
                          kEngineStopWaitMilliseconds);
    }
  }

  if (state->quit_event != nullptr) SetEvent(state->quit_event);
  // Closing the host ends releases a pump blocked in ReadFile even if the
  // engine somehow survived its job.
  {
    std::lock_guard<std::mutex> guard(state->write_mutex);
    CloseHandleIfValid(&state->stdin_pipe);
  }
  CloseHandleIfValid(&state->stdout_pipe);

  HANDLE pumps[2] = {nullptr, nullptr};
  DWORD pump_count = 0;
  if (state->inbound_thread != nullptr) {
    pumps[pump_count++] = state->inbound_thread;
  }
  if (state->outbound_thread != nullptr) {
    pumps[pump_count++] = state->outbound_thread;
  }
  if (pump_count != 0 &&
      WaitForMultipleObjects(pump_count, pumps, TRUE,
                             kPumpJoinTimeoutMilliseconds) == WAIT_TIMEOUT) {
    // A pump still inside recvfrom means closing the seam would free something
    // the pump is reading. There is no safe way to continue in-process, and the
    // engine is already dead in its kill-on-close job, so terminate
    // fail-closed. This mirrors the existing non-quiescence handling in
    // FailClosedPrivilegedTunnel and ShutdownWindowsTunnelBackend.
    TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
    ExitProcess(ERROR_TIMEOUT);
  }
  if (state->inbound_thread != nullptr) {
    CloseHandle(state->inbound_thread);
    state->inbound_thread = nullptr;
  }
  if (state->outbound_thread != nullptr) {
    CloseHandle(state->outbound_thread);
    state->outbound_thread = nullptr;
  }

  if (state->process.hProcess != nullptr) {
    CloseHandle(state->process.hProcess);
  }
  state->process = PROCESS_INFORMATION{};
  if (state->job != nullptr) {
    CloseHandle(state->job);
    state->job = nullptr;
  }
  if (state->seam != INVALID_SOCKET) {
    closesocket(state->seam);
    state->seam = INVALID_SOCKET;
  }
  if (state->seam_readable != WSA_INVALID_EVENT) {
    WSACloseEvent(state->seam_readable);
    state->seam_readable = WSA_INVALID_EVENT;
  }
  CloseEventIfValid(&state->quit_event);
  CloseEventIfValid(&state->status_event);
  CloseEventIfValid(&state->close_ack_event);
}

}  // namespace

uintptr_t BindWindowsWinnSeam(uint16_t* port, std::string* error) {
  if (port == nullptr || error == nullptr) return kInvalidWinnSeam;
  if (!EnsureWinsock()) {
    *error = "Windows Sockets was unavailable for the Winn loopback seam.";
    return kInvalidWinnSeam;
  }
  // WSA_FLAG_NO_HANDLE_INHERIT is the Windows spelling of the FD_CLOEXEC that
  // linux_winn_host.cc sets for the same reason: this service spawns helper
  // processes, and the seam must never be inherited by one of them.
  const SOCKET seam = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                                 WSA_FLAG_NO_HANDLE_INHERIT);
  if (seam == INVALID_SOCKET) {
    *error = "The Winn loopback seam socket could not be created.";
    return kInvalidWinnSeam;
  }
  sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1, never wildcard
  address.sin_port = 0;
  if (bind(seam, reinterpret_cast<const sockaddr*>(&address),
           static_cast<int>(sizeof(address))) != 0) {
    closesocket(seam);
    *error = "The Winn loopback seam socket could not be bound to 127.0.0.1.";
    return kInvalidWinnSeam;
  }
  // A Windows UDP socket that has received an ICMP port-unreachable answers the
  // next recvfrom with WSAECONNRESET rather than a datagram. That is a normal
  // transient on a seam, not a failure, and the inbound pump treats it as one.
  //
  // The usual belt for this is WSAIoctl(SIO_UDP_CONNRESET, FALSE), and it is
  // deliberately not used: SIO_UDP_CONNRESET is not declared by the Windows SDK
  // this project builds against, so using it would mean hardcoding an ioctl
  // code. The pump's explicit WSAECONNRESET handling covers the same case
  // without a magic number, and the case is close to unreachable anyway --
  // nothing sends to the seam before it is bound, and the seam sends only to an
  // address it has already received a datagram from.
  sockaddr_in bound = {};
  int bound_size = static_cast<int>(sizeof(bound));
  if (getsockname(seam, reinterpret_cast<sockaddr*>(&bound), &bound_size) !=
          0 ||
      bound.sin_port == 0) {
    closesocket(seam);
    *error = "The Winn loopback seam socket did not report a port.";
    return kInvalidWinnSeam;
  }
  *port = ntohs(bound.sin_port);
  return static_cast<uintptr_t>(seam);
}

void CloseWindowsWinnSeam(uintptr_t seam) {
  if (seam != kInvalidWinnSeam) {
    closesocket(static_cast<SOCKET>(seam));
  }
}

bool StartWindowsWinnEngine(const std::wstring& engine_path,
                            uintptr_t seam,
                            const WindowsWinnParams& params,
                            std::string* error) {
  // The seam is adopted here on EVERY outcome, not only on success. The caller
  // has one thing to remember rather than two, and the failure paths below are
  // exactly the ones a leak would hide in.
  if (error == nullptr) {
    CloseWindowsWinnSeam(seam);
    return false;
  }
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  if (g_engine != nullptr) {
    *error = "A Winn Protocol engine is already running.";
    CloseWindowsWinnSeam(seam);
    return false;
  }
  if (seam == kInvalidWinnSeam) {
    *error = "The Winn loopback seam is not open.";
    return false;
  }
  if (engine_path.empty()) {
    CloseWindowsWinnSeam(seam);
    *error = "The Win's VPN Winn Protocol engine payload is missing.";
    return false;
  }
  if (params.awg_listen_port == 0) {
    CloseWindowsWinnSeam(seam);
    *error = "Refusing to start Winn Protocol v3: the AmneziaWG runtime's own "
             "source port is unknown, so the Winn seam could not tell it from "
             "another local sender.";
    return false;
  }

  EngineState* state = new EngineState();
  state->seam = static_cast<SOCKET>(seam);
  // THE PIN, from the runtime's own report, before either pump starts.
  state->awg_peer.sin_family = AF_INET;
  state->awg_peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  state->awg_peer.sin_port = htons(params.awg_listen_port);
  state->awg_peer_known.store(true, std::memory_order_release);
  state->max_datagram =
      params.max_datagram > 0 ? params.max_datagram : kMaxDatagramCeiling;
  // Latched HERE, from the configuration this host parsed, because this is the
  // last point at which the answer is a fact about our own input rather than a
  // claim in a reply. BuildWindowsWinnConfigJson below emits awg_header_types
  // from these same four specs, so this boolean and the document the engine
  // receives cannot disagree.
  state->headers_classify = WindowsWinnHeadersClassify(params);

  const auto fail = [&](const std::string& message) {
    *error = message;
    TeardownLocked(state);
    delete state;
    return false;
  };

  state->quit_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  state->status_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  state->close_ack_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  state->seam_readable = WSACreateEvent();
  if (state->quit_event == nullptr || state->status_event == nullptr ||
      state->close_ack_event == nullptr ||
      state->seam_readable == WSA_INVALID_EVENT) {
    return fail("Unable to create the Winn engine lifecycle events.");
  }
  // WSAEventSelect also puts the socket into non-blocking mode, which is what
  // makes the inbound pump interruptible without closing a socket out from
  // under a blocked recvfrom.
  if (WSAEventSelect(state->seam, state->seam_readable, FD_READ) != 0) {
    return fail("Unable to arm the Winn loopback seam for reading.");
  }

  if (!LaunchEngineProcess(state, engine_path, error)) {
    const std::string message = *error;
    return fail(message);
  }

  // The outbound pump starts BEFORE Create is sent, so the acknowledgement has
  // a reader waiting for it.
  state->outbound_thread =
      CreateThread(nullptr, 0, OutboundPump, state, 0, nullptr);
  if (state->outbound_thread == nullptr) {
    return fail("Unable to start the Winn engine frame pump.");
  }

  const std::string config_json = BuildWindowsWinnConfigJson(params);
  if (!WriteFrame(state, Opcode::kCreate,
                  reinterpret_cast<const uint8_t*>(config_json.data()),
                  config_json.size())) {
    return fail("The Winn Protocol engine did not accept its configuration.");
  }
  if (WaitForSingleObject(state->status_event,
                          kCreateAckTimeoutMilliseconds) != WAIT_OBJECT_0) {
    return fail(
        "Winn Protocol could not start: the engine did not acknowledge its "
        "configuration in time.");
  }
  std::string acknowledgement;
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    if (!state->failure.empty()) {
      return fail("Winn Protocol could not start: " + state->failure + ".");
    }
    acknowledgement = state->last_status;
  }
  if (acknowledgement.empty()) {
    return fail(
        "Winn Protocol could not start: the engine acknowledged nothing.");
  }

  // THE CREATE ACKNOWLEDGEMENT IS CHECKED, NOT ASSUMED.
  //
  // These three fields are the anti-downgrade check on this side of the
  // boundary, decided by WinnCreateAckAccepted() in windows_winn_engine.h. The
  // engine echoes back what it actually built, so a binary that silently opened
  // a different payload mode or a different carrier -- or a test double standing
  // in for the real engine, which emits no `contract` at all -- is refused here
  // instead of carrying a session nobody negotiated. "awg-datagram" in
  // particular is the one that must never be claimed while something else is on
  // the wire. The predicate is the exact conjunction StartWindowsWinnEngine is
  // judged on, exercised off Windows by windows_winn_gate_test.cc; it is never
  // restated here.
  if (!WinnCreateAckAccepted(acknowledgement)) {
    return fail(
        "Winn Protocol could not start: the engine's acknowledgement was not "
        "the winn-datapath/1 awg-datagram direct-awg session this host "
        "configured, so the connection was refused rather than downgraded.");
  }

  state->channel_up.store(true, std::memory_order_release);
  state->inbound_thread =
      CreateThread(nullptr, 0, InboundPump, state, 0, nullptr);
  if (state->inbound_thread == nullptr) {
    return fail("Unable to start the Winn loopback seam pump.");
  }
  g_engine = state;
  return true;
}

void StopWindowsWinnEngine() {
  EngineState* state = nullptr;
  {
    std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
    state = g_engine;
    g_engine = nullptr;
    if (state == nullptr) return;
    TeardownLocked(state);
  }
  delete state;
}

bool WindowsWinnEngineRunning() {
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  if (g_engine == nullptr) return false;
  if (!g_engine->channel_up.load(std::memory_order_acquire)) return false;
  if (g_engine->process.hProcess == nullptr) return false;
  return WaitForSingleObject(g_engine->process.hProcess, 0) == WAIT_TIMEOUT;
}

std::string WindowsWinnEngineStatusJson() {
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  EngineState* state = g_engine;
  if (state == nullptr || !state->channel_up.load(std::memory_order_acquire)) {
    return "";
  }
  ResetEvent(state->status_event);
  if (!WriteFrame(state, Opcode::kStatusRequest, nullptr, 0)) return "";
  if (WaitForSingleObject(state->status_event, kStatusTimeoutMilliseconds) !=
      WAIT_OBJECT_0) {
    return "";
  }
  std::lock_guard<std::mutex> guard(state->status_mutex);
  return state->last_status;
}

WinnTransportGate WindowsWinnTransportGate(std::string* status_json,
                                           std::string* reason) {
  // WINN_FAIL_OPEN_CLOSED 2026-08-09. What used to be here returned TRUE --
  // "the transport was observed in both directions" -- whenever the engine's
  // status reply did not contain the exact substring
  // `"awg_classification":"configured-h1h4"`, and said so only through
  // OutputDebugStringA, which no production install reads. Route promotion
  // therefore turned on the SPELLING OF A FIELD IN A REPLY: an engine-side
  // rename, a version skew between the shipped host and the shipped engine, or
  // an encoder that emitted a space after the colon each disabled the gate
  // silently and promoted the user's default route onto a carrier that had
  // never been proven to carry a single datagram.
  //
  // The justification written beside it appealed to h1..h4 being mandatory in
  // ParseWindowsWinnSection (windows_winn_engine.cpp:427 and :467) -- that is,
  // to the HOST'S OWN PARSED CONFIGURATION. So the check now tests that, at
  // state->headers_classify, latched in StartWindowsWinnEngine from the params
  // this host built the Create document from. The engine's reply can no longer
  // move the gate; it can only fail to satisfy it.
  bool engine_present = false;
  bool headers_classify = false;
  {
    std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
    engine_present = g_engine != nullptr;
    headers_classify = engine_present && g_engine->headers_classify;
  }
  // Released before WindowsWinnEngineStatusJson(), which takes the same
  // non-recursive mutex.
  if (!engine_present) {
    if (status_json != nullptr) status_json->clear();
    if (reason != nullptr) {
      *reason = "the Winn Protocol engine is not running.";
    }
    return WinnTransportGate::kNotYetObserved;
  }
  // Queried ONLY when the answer can depend on it. A session whose own h1..h4
  // table cannot classify is refused whatever the engine says, so asking costs
  // up to kStatusTimeoutMilliseconds for a verdict already known -- and the
  // caller's convergence budget is the user's connect latency.
  std::string status;
  if (headers_classify) {
    status = WindowsWinnEngineStatusJson();
  }
  if (status_json != nullptr) *status_json = status;
  const WinnTransportGate verdict =
      DecideWinnTransportGate(headers_classify, status, reason);
  if (verdict == WinnTransportGate::kCannotObserve) {
    // Kept from the code this replaces, for an operator with a debugger
    // attached. It is no longer the ONLY trace: the caller puts *reason into
    // the start failure that crosses the manager pipe and reaches the app.
    OutputDebugStringA(
        "Winn datapath convergence CANNOT BE PROVEN: this host started the "
        "session without a complete h1..h4 classification table, so "
        "transport_observed_both_ways can never fire -- REFUSING promotion.\n");
  }
  return verdict;
}

bool WindowsWinnTransportObservedBothWays(std::string* status_json) {
  // `up` is deliberately NOT consulted anywhere below this line.
  // datapath/status.go states plainly that it means only "a socket exists", and
  // that promoting routes on it promotes on the strength of an open socket. The
  // transfer-proven field is the one DecideWinnTransportGate reads, and even
  // that is only half the gate -- the caller pairs it with a recent handshake
  // from the host's own AmneziaWG engine.
  return WindowsWinnTransportGate(status_json, nullptr) ==
         WinnTransportGate::kObserved;
}

#endif  // WINS_TUNNEL_SERVICE_CORE

}  // namespace winsvpn::winn
