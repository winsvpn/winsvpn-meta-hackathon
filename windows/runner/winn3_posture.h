#ifndef RUNNER_WINN3_POSTURE_H_
#define RUNNER_WINN3_POSTURE_H_

// The staged posture for Winn Protocol v3 desktop hosts.
//
// This header is WINN3_TUN_LAYER_20260808.md section 4 in code, and it is
// shared by the Linux and Windows runners rather than written twice. The
// precedent is winn_frame.h, which lives here and which linux_winn_host.cc
// includes as "../../windows/runner/winn_frame.h"; this file is deliberately
// the same shape -- standard C++17, no <windows.h>, no glib, no socket, no
// process -- so that both hosts build it and, more importantly, so that a
// development machine that is neither can RUN its tests. A posture policy that
// only the target platform can execute is a posture policy that does not get
// tested, and this one decides when a user's default route moves.
//
// # What it does and does not do
//
// It DECIDES and it RENDERS. It does not execute: no function here runs a
// command, opens a socket or touches an interface. The two hosts already own
// privileged execution -- the Linux runner through its root script, the Windows
// runner through its LocalSystem tunnel service -- and giving this header a
// second way to reach the system would put the decision and the privilege in
// the same place, which is how a policy bug becomes a root bug.
//
// # The contract, restated because it is the whole point
//
// BOOTSTRAP, installed first, before any user traffic is possible:
//
//   inner address        the assigned address, prefix /32 or /128
//   MTU                  exactly the engine's inner MTU
//   included routes      at most ONE: the inner next hop
//   default route        ABSENT
//   IPv6                 ABSENT
//   DNS                  ABSENT
//   outer-socket exclusion   PRESENT, from the first posture
//
// PROMOTION, installed only after the datapath is PROVEN: default route, IPv6,
// DNS and the full route set, in one call. And, since 2026-08-09, only if that
// posture would actually CAPTURE something and would actually move name
// resolution with it:
//
//   included routes      the bootstrap's next hop UNION the host's set, never
//                        the host's set alone -- an assignment discarded the
//                        one route the bootstrap had installed
//   capture              at least the /1 pair, checked on the plan AND on the
//                        rendered argument vectors, both halves required
//   DNS                  at least one resolver, declared inner. A promotion
//                        that widens the routes and leaves the machine's
//                        existing resolver in place is a DNS leak with a green
//                        gate, and it used to be explicitly permitted
//
// PROVEN is a property of the tun layer, not of the socket:
//
//   1. the gate is carrying -- the session driver says DATA may flow; AND
//   2. an inner packet has been validated and WRITTEN TO THE HOST DEVICE.
//
// Neither host computes that conjunction. cmd/winn-datapath computes it once,
// in Go, beside the counters, and publishes it as `promotion_ready`. This
// header only reads it -- and refuses to build a promoted posture without it.
//
// # Failure is a refusal, never a widening
//
// Every Build function below returns false and writes a diagnostic rather than
// returning a wider posture. There is no code path here that produces a default
// route, an IPv6 setting or a resolver without `promotion_ready` being true,
// and VerifyBootstrapIsNarrow re-checks the built object rather than trusting
// the function that built it -- the shape iOS already uses and which the tun
// contract asks the other four platforms to copy verbatim.

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace winsvpn::winn3 {

// kBootstrapPosture and kPromotedPosture are the two names the engine's status
// document uses. They are compared, never invented.
inline constexpr char kBootstrapPosture[] = "bootstrap";
inline constexpr char kPromotedPosture[] = "promoted";

// kCarryingGate is the only tun gate state in which an inner packet may move.
inline constexpr char kCarryingGate[] = "carrying";

// kIPv6MinLinkMTU is RFC 8200's hard floor, and on Linux it is not a policy
// anything here can waive: ipv6_add_dev() returns -EINVAL below it.
//
// MEASURED 2026-08-10 rather than cited. A tun device in a throwaway network
// namespace (Colima, kernel 6.8.0-117-generic), `ip -6 address add
// fd00:d951:1::2/128` swept across MTUs:
//
//   576 1138 1139 1279 -> "RTNETLINK answers: Invalid argument"
//   1280 1281 1309 1331 1373 1500 -> accepted
//
// 1139 is the inner MTU the fleet default USED to produce (path 1280 over the
// [udp,tcp,tls] plan). 1309 is what it produces now (path 1450). So the sink
// below became legal on the default only on 2026-08-10, and the arithmetic is
// the only thing that changed.
inline constexpr int kIPv6MinLinkMTU = 1280;

// THE GUARD IS `inner_mtu >= kIPv6MinLinkMTU`, AND THAT IS ALREADY PLAN-AWARE.
//
// The three path-MTU thresholds for inner IPv6 are plan-dependent -- 1357 for
// udp alone, 1399 for [udp,tcp], 1421 for [udp,tcp,tls] -- and a flat 1421
// check on the PATH MTU would refuse two configurations that work. It is not
// needed here: `EngineStatus::inner_mtu` is already `driver.NewSizing(...)
// .InnerMTU`, the plan floor over the classes this session may migrate to, so
// each threshold reduces to the same inner number:
//
//   udp             1357 - 77  = 1280
//   [udp,tcp]       1399 - 119 = 1280
//   [udp,tcp,tls]   1421 - 141 = 1280
//
// One comparison, on the value this host is about to put on the interface, is
// the plan-aware form of all three. Re-deriving the path-MTU thresholds here
// would be a second implementation of `carrier.Floor` in C++ -- the exact
// duplication §4.2 makes a black hole rather than an inefficiency.

// kIPv6SinkAddress is the fail-closed IPv6 sink, and it is Apple's constant
// spelled again rather than a second address: `WinsTunnelConfig.ipv6SinkAddress`
// in apple/WinsTunnelCore/WinsTunnelConfig.swift is `fd00:d951:1::2` at /128,
// and Android's promotion takes the same address through its `ipv6SinkAddress`
// parameter. Three hosts blackholing v6 at three different addresses would be
// three different behaviours wearing one name.
inline constexpr char kIPv6SinkAddress[] = "fd00:d951:1::2";
inline constexpr int kIPv6SinkPrefixLength = 128;

// kMaxStatusLineBytes bounds one status document. A legitimate line is a few
// hundred bytes of scalars; anything larger is a mistake or an attempt to
// make the host allocate. Same 64 KiB ceiling the Go profile parser uses.
inline constexpr size_t kMaxStatusLineBytes = 64 * 1024;

enum class Posture { kBootstrap, kPromoted };

// EngineStatus is one parsed line of cmd/winn-datapath's v3 status stream.
//
// `valid` is false for a line that did not parse. Every consumer treats invalid
// as "hold the bootstrap posture", which is the same answer it gives for a line
// that parsed and said not ready -- so a host that meets a status document from
// a newer engine narrows rather than guesses.
struct EngineStatus {
  bool valid = false;
  bool promotion_ready = false;
  std::string event;
  std::string posture;
  std::string gate_state;
  uint64_t rx_packets = 0;
  uint64_t rx_offered = 0;
  uint64_t tx_dropped_closed = 0;
  int inner_mtu = 0;
  int message_size = 0;
  bool inner_ipv6 = false;
  std::string refusal;
};

// PostureInput is everything the host knows before it asks for a posture.
struct PostureInput {
  // The inner assignment. Either family may be empty, in which case that family
  // is absent from every posture rather than defaulted.
  std::string inner_v4;
  std::string inner_v6;

  // The inner next hop. It is the ONE route a bootstrap posture may install.
  std::string router_v4;
  std::string router_v6;

  // The exclusion that keeps the engine's own outer socket out of the tunnel it
  // carries. On Linux this is awg-quick's fwmark rule; on Windows an
  // interface-scoped route or a WFP exception. It is required in BOTH postures,
  // and an empty one is a refusal in both.
  std::string outer_socket_exclusion;

  // The routes and resolvers a PROMOTED posture installs. Ignored entirely
  // while building a bootstrap posture -- not filtered, not partially applied,
  // ignored -- because a bootstrap posture that could carry any of this is a
  // bootstrap posture with a bug that only shows up under load.
  std::vector<std::string> full_routes;
  std::vector<std::string> dns_servers;

  // DnsServersAreInner is the host's own declaration that every resolver above
  // is reachable ONLY through the tunnel.
  //
  // It is a declaration rather than a check WHEN THERE IS NOTHING TO DERIVE
  // FROM, which is the case for a hand-written `[winn3]` document: it names
  // `dns` and `dns_are_inner` and the host holding the machine is the authority
  // on both. It is still required there, for the same reason allow_own_socket is
  // required of the engine: a host that installs resolvers it has not reasoned
  // about produces name resolution over the censored path the moment the tunnel
  // drops, which is the failure DNS-at-promotion exists to prevent.
  //
  // It is NOT the path a served `[winn]` session takes. See inner_resolver_v4
  // below and `resolvers::PromotionRefusalReason`: when the signed descriptor
  // names a resolver, this header DERIVES inner-ness from address shape the way
  // Apple and Android already do, and this boolean is not consulted at all. A
  // boolean on the wire asserting a resolver is inside the tunnel is the leak
  // wearing a flag, so nothing may ever set this field from a served value.
  bool dns_servers_are_inner = false;

  // The gateway's INNER DNS RESPONDER address, off the same ML-DSA-65-signed
  // descriptor the inner assignment and next hop arrive on
  // (`[winn] inner_resolver_v4`). Empty on every descriptor signed to date, and
  // empty is what every caller that predates the field supplies -- so an empty
  // value reproduces this header's behaviour EXACTLY as it was, and every
  // configuration served or hand-written today builds the same posture it built
  // before this field existed.
  //
  // Non-empty switches DNS-at-promotion from the declaration above to the
  // derivation in `namespace resolvers`, and the switch is total: the descriptor
  // value REPLACES the host's `dns_servers` rather than joining them, because
  // both platforms' resolver installers hand the whole list to the system and
  // the SYSTEM, not this header, picks which entry answers. A public resolver
  // sitting second in the list is a public resolver that answers whenever the
  // first is slow. Apple's `WinsWinn3Resolvers.candidates` and Android's
  // `WinnV3SessionPlan` replace for the same reason and say so.
  std::string inner_resolver_v4;

  // The fail-closed IPv6 sink address, used when the session carries no inner
  // IPv6 of its own. Empty means kIPv6SinkAddress, which is what both hosts
  // pass and what Apple and Android already install; it is settable only so a
  // test can vary it.
  std::string ipv6_sink;
};

// PosturePlan is what the host applies. It is data, and rendering it into
// commands is a separate step so that the decision can be tested without a
// shell.
struct PosturePlan {
  Posture posture = Posture::kBootstrap;

  std::string inner_v4;
  std::string inner_v6;
  int prefix_v4 = 0;  // 32 in bootstrap, 32 in promotion: the tun layer
  int prefix_v6 = 0;  // validates against the ADDRESS, never the prefix.

  int mtu = 0;

  std::vector<std::string> included_routes;
  bool default_route = false;
  bool ipv6 = false;
  std::vector<std::string> dns_servers;

  // The fail-closed IPv6 sink this posture installs INSTEAD of an inner IPv6
  // address, when the session has none. Non-empty implies `ipv6` is true; the
  // two are never both set, because a session that can carry inner IPv6 has no
  // use for a black hole.
  std::string ipv6_sink;

  // Why this promoted posture carries no IPv6 at all, when it carries none.
  //
  // It exists so the one remaining leaking case is NAMED rather than silent.
  // Below kIPv6MinLinkMTU neither shape is available -- an inner address is a
  // black hole and the sink is an -EINVAL -- so the posture promotes IPv4-only
  // and host IPv6 stays on the physical interface. That was the unconditional
  // behaviour until 2026-08-10 and it is now the exception; a host that reads
  // this string can say so instead of reporting an unqualified success.
  std::string ipv6_absent_reason;

  std::string outer_socket_exclusion;
};

namespace detail {

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

// LooksLikeIPv6 is a spelling test, not a validator. It exists only to pick the
// family of an address the host already validated; anything ambiguous is
// treated as IPv4 and will be rejected downstream by the system that applies
// it.
inline bool LooksLikeIPv6(const std::string& address) {
  return address.find(':') != std::string::npos;
}

// kDefaultRouteHalves are the two routes a promoted posture installs INSTEAD of
// a default route, and the reason is in RenderLinuxPostureCommands: the pair
// beats an existing default on specificity without deleting it, so a teardown
// that stops part way leaves the host's own default intact rather than leaving
// it with none at all.
//
// They are named here because two separate checks below need them: the one that
// asks whether a posture captures anything, and the one that asks whether a
// route set is re-stating what the renderer already emits.
inline constexpr char kDefaultRouteLowHalf[] = "0.0.0.0/1";
inline constexpr char kDefaultRouteHighHalf[] = "128.0.0.0/1";

// The IPv6 halves, for the same reason and MEASURED to be necessary rather than
// merely symmetrical.
//
// The obvious rendering is a single `::/0`. On Linux it does not work: an IPv6
// route added with no metric lands at metric 1024, which is where the host's
// own default already is, so `ip -6 route add ::/0 dev winn0` returns
// `RTNETLINK answers: File exists` and the promotion fails half-applied. Both
// escapes were tried in the namespace rig on 2026-08-10: `::/0 metric 1` works
// but wins on metric, and `::/1` + `8000::/1` works and wins on SPECIFICITY --
// which is the property kDefaultRouteLowHalf was chosen for in the first place,
// because it beats the host's default without deleting it, so a teardown that
// stops part way leaves the host with a default route rather than none.
//
// Same shape, same reason, same failure mode if only one half is rendered.
inline constexpr char kIPv6DefaultRouteLowHalf[] = "::/1";
inline constexpr char kIPv6DefaultRouteHighHalf[] = "8000::/1";

// RendersAsDefaultRoute is true for the spellings a promoted posture's
// `default_route` flag ALREADY renders, plus the literal defaults.
//
// A route set that names any of them would make the renderer emit the same
// `ip route add` twice, and the second fails EEXIST -- turning a correct
// promotion into a failed one. That is fail-closed and therefore not a leak,
// but it is a self-inflicted stall on the most natural way to spell a full
// tunnel, and `routes = 0.0.0.0/1, 128.0.0.0/1` is exactly how a hand-written
// `[winn3]` document spells it.
//
// ===========================================================================
// `::/0` WAS ON THIS LIST AND NOTHING RENDERED IT
// ===========================================================================
//
// Until 2026-08-10 this predicate returned true for `"::/0"` while both
// renderers emitted only the IPv4 pair. So an operator who wrote
// `routes = ::/0` into a local `[winn3]` file -- the one way IPv6 capture could
// be asked for at all on these two hosts -- had it silently DROPPED by the
// union loop in BuildPromotedPosture, on the strength of a comment asserting it
// was already rendered.
//
// Measured by running the shipping renderers on 2026-08-10: `full_routes =
// {"::/0"}` produced exactly the same five `ip` commands and six `netsh`
// commands as an empty route set, none of them IPv6. `2000::/3` in the same
// position SURVIVED, because it is not on this list -- so the filter turned the
// correct spelling into the broken one and left a wrong-looking one working.
//
// It stays on the list, and the claim is now true: a promoted posture that
// installs IPv6 renders kIPv6DefaultRouteLowHalf and kIPv6DefaultRouteHighHalf,
// which is `::/0` split the way the IPv4 default already is. The two halves are
// listed for the same reason their IPv4 counterparts are.
inline bool RendersAsDefaultRoute(const std::string& route) {
  const std::string value = Trim(route);
  return value == kDefaultRouteLowHalf || value == kDefaultRouteHighHalf ||
         value == kIPv6DefaultRouteLowHalf ||
         value == kIPv6DefaultRouteHighHalf || value == "0.0.0.0/0" ||
         value == "::/0" || value == "default";
}

// LooksLikeCidr is a spelling test for "this token is a route", so that a check
// walking a RENDERED argument vector does not mistake `mtu=1332` or
// `name=WinsVPN3` for a prefix. Everything before the slash must be an address
// character and everything after it a digit.
inline bool LooksLikeCidr(const std::string& token) {
  const size_t slash = token.rfind('/');
  if (slash == std::string::npos || slash == 0 ||
      slash + 1 >= token.size()) {
    return false;
  }
  for (size_t i = 0; i < slash; ++i) {
    const char c = token[i];
    const bool address_character =
        (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F') || c == '.' || c == ':';
    if (!address_character) return false;
  }
  for (size_t i = slash + 1; i < token.size(); ++i) {
    if (token[i] < '0' || token[i] > '9') return false;
  }
  return true;
}

// CapturesMoreThanOneHost is the question "would installing this route move any
// of the user's traffic?".
//
// A /32 (or /128) is one host. The inner next hop is exactly that, and it is
// the ONE route a bootstrap posture installs -- enough to prove the datapath,
// not enough to capture anything. So a promoted posture whose whole route set
// is host routes has widened nothing, and saying so is the entire point of the
// two Verify functions below.
//
// Anything that does not parse as a prefix is treated as one host, which is the
// conservative direction: an unparsable route is never counted as evidence that
// the posture captures traffic.
inline bool CapturesMoreThanOneHost(const std::string& route) {
  const std::string value = Trim(route);
  if (value == "default") return true;
  if (!LooksLikeCidr(value)) return false;
  const size_t slash = value.rfind('/');
  int bits = 0;
  for (size_t i = slash + 1; i < value.size(); ++i) {
    bits = bits * 10 + (value[i] - '0');
    if (bits > 128) return false;
  }
  return LooksLikeIPv6(value) ? bits < 128 : bits < 32;
}

// The status stream is line-delimited JSON with a flat object of scalars, and
// these two readers parse exactly that rather than pulling in a JSON library
// that neither runner links today. They are deliberately strict: a key that is
// present but malformed refuses the document. Absent means the conservative
// value -- false for the boolean, zero for the numbers.

// FindKey locates a quoted string that is a KEY of the top-level object, and
// returns the offset of its colon.
//
// WHY THIS EXISTS, found by execution on 2026-08-09. The three readers below
// used to take the FIRST occurrence of `"<key>"` anywhere in the line. The
// frame mode's own CreateAck is
//
//   {"event":"posture","session_id":"0123...","posture":"bootstrap",...}
//
// and `"posture"` occurs there twice: once as the VALUE of `event` -- which is
// literally the string "posture" for every CreateAck and StatusResponse -- and
// once as the key. The old reader matched the value, scanned forward to the
// next colon, which belongs to `session_id`, and returned the SESSION
// IDENTIFIER as the posture. Measured against the shipping cmd/winn-datapath
// binary: `posture=0123456789abcdef0123456789abcdef`.
//
// Nothing in this header decides anything from `posture` -- promotion turns on
// promotion_ready, and gate_state, refusal, rx_packets and inner_mtu never
// collide with a value -- so no tunnel was ever widened by it. But a host that
// LOGGED the posture printed a session identifier as a policy state, and a
// future reader who trusted the field would be trusting a value the peer
// chose. The fix is to anchor: a key is preceded by `{` or `,` and followed by
// `:`, and an array element or a string value is neither.
//
// WHY DEPTH IS TRACKED, found by reading on 2026-08-12. The brace-or-comma
// then-colon anchor still matches a key of a NESTED object: `"extra":{"promotion_ready":true}`
// is preceded by `{` and followed by `:`. encoding/json only unmarshals the
// top-level object, so Go's decodeWinn3Status refuses that document for a
// missing top-level promotion_ready. This reader would have accepted it as
// ready. A substituted status line of
// `{"event":"posture","nested":{"promotion_ready":true,"gate_state":<carrying>,"rx_packets":1}}`
// would then have satisfied BuildPromotedPosture's belt-and-braces as well.
// Keys are therefore accepted only at nesting depth 1. `start` still means
// "first match whose colon is at or after this offset"; the walk always
// begins at byte 0 so depth is not guessed from a mid-document cursor.
inline bool FindKey(const std::string& line, const std::string& key,
                    size_t* colon_out, size_t start = 0) {
  const std::string needle = "\"" + key + "\"";
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (c == '\\') {
        escaped = true;
        continue;
      }
      if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') {
      if (depth == 1 && i + needle.size() <= line.size() &&
          line.compare(i, needle.size(), needle) == 0) {
        size_t after = i + needle.size();
        while (after < line.size() &&
               (line[after] == ' ' || line[after] == '\t')) {
          ++after;
        }
        if (after < line.size() && line[after] == ':' && after >= start) {
          if (colon_out != nullptr) *colon_out = after;
          return true;
        }
      }
      in_string = true;
      continue;
    }
    if (c == '{' || c == '[') {
      ++depth;
      continue;
    }
    if (c == '}' || c == ']') {
      if (depth > 0) --depth;
    }
  }
  return false;
}

inline int CountKey(const std::string& line, const std::string& key) {
  int n = 0;
  size_t colon = 0;
  size_t start = 0;
  while (FindKey(line, key, &colon, start)) {
    ++n;
    start = colon + 1;
    if (n > 1) return n;
  }
  return n;
}

// IsJsonValueEnd is true at EOF or at a character that can legally follow a
// JSON true/false/number in this flat object. Without it, compare(..., "true")
// accepts `truex` and `truehood` as true -- a prefix match, not a token match.
inline bool IsJsonValueEnd(const std::string& line, size_t at) {
  if (at >= line.size()) return true;
  const char c = line[at];
  return c == ',' || c == '}' || c == ']' || c == ' ' || c == '\t' ||
         c == '\n' || c == '\r';
}

// IsSingleJsonObject is true when `line` (already trimmed) is exactly one
// JSON object. encoding/json.Decoder and this header's FindKey both keep
// scanning after the first `}`, so `{"promotion_ready":true}{"promotion_ready":false}`
// would otherwise be an under-read: both objects' keys are visible and the
// first match wins.
inline bool IsSingleJsonObject(const std::string& line) {
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  char last_non_ws = 0;
  for (size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (c == '\\') {
        escaped = true;
        continue;
      }
      if (c == '"') in_string = false;
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      continue;
    }
    if (c == '"') {
      in_string = true;
      last_non_ws = '"';
      continue;
    }
    if (c == '{' || c == '[') {
      ++depth;
      last_non_ws = c;
      continue;
    }
    if (c == '}' || c == ']') {
      if (depth == 0) return false;
      if (last_non_ws == ',') return false;
      --depth;
      if (depth == 0 && i + 1 < line.size()) return false;
      last_non_ws = c;
      continue;
    }
    last_non_ws = c;
  }
  return depth == 0 && !in_string;
}

inline bool ReadJsonBool(const std::string& line, const std::string& key,
                         bool* out) {
  size_t colon = 0;
  if (!FindKey(line, key, &colon)) {
    return false;
  }
  const auto value = line.find_first_not_of(" \t", colon + 1);
  if (value == std::string::npos) {
    return false;
  }
  if (line.compare(value, 4, "true") == 0 && IsJsonValueEnd(line, value + 4)) {
    *out = true;
    return true;
  }
  if (line.compare(value, 5, "false") == 0 &&
      IsJsonValueEnd(line, value + 5)) {
    *out = false;
    return true;
  }
  return false;
}

inline bool ReadJsonUint(const std::string& line, const std::string& key,
                         uint64_t* out) {
  size_t colon = 0;
  if (!FindKey(line, key, &colon)) {
    return false;
  }
  auto cursor = line.find_first_not_of(" \t", colon + 1);
  if (cursor == std::string::npos || line[cursor] < '0' || line[cursor] > '9') {
    return false;
  }
  // JSON numbers do not have leading zeros except the number 0 itself.
  // Accepting 01 as 1 is silent acceptance of invalid input; Go
  // encoding/json and the Android scanner both refuse it.
  if (line[cursor] == '0' && cursor + 1 < line.size() &&
      line[cursor + 1] >= '0' && line[cursor + 1] <= '9') {
    return false;
  }
  uint64_t accumulated = 0;
  while (cursor < line.size() && line[cursor] >= '0' && line[cursor] <= '9') {
    const uint64_t digit = static_cast<uint64_t>(line[cursor] - '0');
    if (accumulated > (UINT64_MAX - digit) / 10) {
      return false;  // Overflow reads as absent, which reads as zero.
    }
    accumulated = accumulated * 10 + digit;
    ++cursor;
  }
  if (!IsJsonValueEnd(line, cursor)) {
    return false;  // `1e2`, `1.5`, `12abc` are not integers.
  }
  *out = accumulated;
  return true;
}

inline int HexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// AppendJsonEscape decodes one JSON string escape at `slash` (which must
// point at '\\'). On success it appends the unescaped byte and sets
// `consumed` to the escape's length including the backslash.
//
// WHY THIS EXISTS, found by reading on 2026-08-12. The previous reader
// treated every `\X` as the literal character X. That is not JSON: `\r` is
// a carriage return, `\n` a newline, `\c` is illegal. The carrying-gate
// comparison is a byte match against kCarryingGate, so `"ca\rrying"` was
// collected as the carrying name and satisfied BuildPromotedPosture's belt-and-
// braces. encoding/json on the Go side already yields a CR and does not
// match. Unknown escapes and non-ASCII `\uXXXX` are refused; printable
// ASCII `\uXXXX` is decoded so `\u0063arrying` agrees with Go.
inline bool AppendJsonEscape(const std::string& line, size_t slash,
                             std::string* out, size_t* consumed) {
  if (slash + 1 >= line.size()) return false;
  const char e = line[slash + 1];
  switch (e) {
    case '"':
    case '\\':
    case '/':
      out->push_back(e);
      *consumed = 2;
      return true;
    case 'b':
      out->push_back('\b');
      *consumed = 2;
      return true;
    case 'f':
      out->push_back('\f');
      *consumed = 2;
      return true;
    case 'n':
      out->push_back('\n');
      *consumed = 2;
      return true;
    case 'r':
      out->push_back('\r');
      *consumed = 2;
      return true;
    case 't':
      out->push_back('\t');
      *consumed = 2;
      return true;
    case 'u': {
      if (slash + 5 >= line.size()) return false;
      unsigned cp = 0;
      for (int i = 0; i < 4; ++i) {
        const int n = HexNibble(line[slash + 2 + static_cast<size_t>(i)]);
        if (n < 0) return false;
        cp = (cp << 4) | static_cast<unsigned>(n);
      }
      if (cp < 0x20u || cp > 0x7Eu) return false;
      out->push_back(static_cast<char>(cp));
      *consumed = 6;
      return true;
    }
    default:
      return false;
  }
}

inline bool ReadJsonString(const std::string& line, const std::string& key,
                           std::string* out) {
  size_t colon = 0;
  if (!FindKey(line, key, &colon)) {
    return false;
  }
  // The first non-space after the colon MUST be the opening quote. Scanning
  // forward for any later `"` used to steal the next key's name when the
  // value was a number, a boolean, or null: `{"event":1,"posture":"bootstrap"}`
  // read event as `posture`.
  const auto open = line.find_first_not_of(" \t", colon + 1);
  if (open == std::string::npos || line[open] != '"') {
    return false;
  }
  std::string collected;
  for (size_t cursor = open + 1; cursor < line.size();) {
    if (line[cursor] == '\\') {
      size_t consumed = 0;
      if (!AppendJsonEscape(line, cursor, &collected, &consumed)) {
        return false;
      }
      cursor += consumed;
      continue;
    }
    if (line[cursor] == '"') {
      *out = collected;
      return true;
    }
    const unsigned char c = static_cast<unsigned char>(line[cursor]);
    if (c < 0x20u) {
      return false;  // unescaped control, illegal in JSON
    }
    collected.push_back(line[cursor]);
    ++cursor;
  }
  return false;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// namespace resolvers -- DNS-at-promotion, DERIVED rather than declared.
// ---------------------------------------------------------------------------
//
// This is `WinsWinn3Resolvers` (apple/WinsTunnelCore/WinsWinn3SessionStart.swift)
// and `WinnV3Resolvers` (android/.../WinnV3Posture.kt) on the desktop side, and
// it is a mirror rather than a reimplementation: same clause order, same mask,
// same refusal grounds, so that four hosts reading ONE signed descriptor cannot
// disagree about where a session resolves names. A divergence here would not be
// a cosmetic inconsistency -- it would be two platforms installing different
// resolvers off the same document, and the one that guessed wider leaks.
//
// ===========================================================================
// WHY THE FLOOR IS A /24 AND WHY IT IS HARD-CODED
// ===========================================================================
//
// The descriptor carries the inner assignment as a BARE ADDRESS with no prefix.
// So the narrowest inner space a client can NAME without inventing a number
// that was never signed is the /24 around it -- which is also the shape every
// one of these deployments has. The hub pool is pinned to a /24 precisely
// because the mobile clients derive against a hard 0xFFFFFF00 floor; desktop
// matches that constant exactly or the two families disagree about the same
// descriptor.
//
// The derivation can only ever UNDER-accept, and under-accepting REFUSES, which
// is the safe direction. Every clause below is a reason to refuse; there is no
// clause that grants.
namespace resolvers {

// kInnerBlockMask is the /24 floor, and it is the same constant Apple spells
// `0xFFFF_FF00` and Android spells `0xFFFFFF00L`. It is named rather than
// inlined so that a future prefix change is one edit with one comment, instead
// of a literal that has to be found in three languages.
inline constexpr uint32_t kInnerBlockMask = 0xFFFFFF00u;

// SameInnerBlock is two addresses in the same /24.
inline bool SameInnerBlock(uint32_t a, uint32_t b) {
  return (a & kInnerBlockMask) == (b & kInnerBlockMask);
}

// Ipv4Value parses a dotted quad into a host-order 32-bit value, and returns
// false for anything that is not one.
//
// HAND-ROLLED, and deliberately not `inet_pton`, for two reasons. This header
// is standard C++17 with no platform headers by construction -- the file
// comment at the top says so and both hosts depend on it -- and `inet_pton`
// would drag in <ws2tcpip.h> on one side and <arpa/inet.h> on the other, which
// is exactly the include a development machine that is neither cannot satisfy.
// Android hand-rolls the same parser for a related reason its comment states:
// `InetAddress.getByName` would perform a NAME LOOKUP for anything that is not
// a literal, inside the one code path whose whole subject is not leaking
// lookups. The strictness here matches Android's exactly -- four parts, one to
// three digits each, digits only, each 0..255.
inline bool Ipv4Value(const std::string& text, uint32_t* out) {
  const std::string trimmed = detail::Trim(text);
  if (trimmed.empty()) return false;
  uint32_t result = 0;
  size_t begin = 0;
  for (int part = 0; part < 4; ++part) {
    const size_t dot = trimmed.find('.', begin);
    const bool last = (part == 3);
    if (last != (dot == std::string::npos)) return false;
    const size_t end = last ? trimmed.size() : dot;
    const size_t length = end - begin;
    if (length == 0 || length > 3) return false;
    int octet = 0;
    for (size_t i = begin; i < end; ++i) {
      const char c = trimmed[i];
      if (c < '0' || c > '9') return false;
      octet = octet * 10 + (c - '0');
    }
    if (octet > 255) return false;
    result = (result << 8) | static_cast<uint32_t>(octet);
    begin = end + 1;
  }
  if (out != nullptr) *out = result;
  return true;
}

// IsPublicIPv4Literal is the same range set `lib/main.dart:_isPublicIpv4Literal`,
// Apple's `isPublicIPv4Literal` and Android's `isPublicIpv4Literal` exclude, so
// no two hosts can disagree about which literals are the ones that actually
// ship. A value that is not an IPv4 literal at all is not public -- it is
// refused one clause earlier, and answering true here would give it the wrong
// diagnostic.
inline bool IsPublicIPv4Literal(const std::string& value) {
  uint32_t parsed = 0;
  if (!Ipv4Value(value, &parsed)) return false;
  const uint32_t first = (parsed >> 24) & 0xffu;
  const uint32_t second = (parsed >> 16) & 0xffu;
  if (first == 10 || first == 127 || first == 0) return false;
  if (first == 100 && second >= 64 && second <= 127) return false;
  if (first == 169 && second == 254) return false;
  if (first == 172 && second >= 16 && second <= 31) return false;
  if (first == 192 && second == 168) return false;
  if (first >= 224) return false;
  return true;
}

// NotInnerReason is why this host cannot derive that `resolver` is inside THIS
// session's tunnel, or an empty string when it can.
//
// The clause ORDER is load-bearing and is Apple's and Android's, so the most
// specific fact wins: a value that is both the next hop and inside the
// assignment's block is refused as the next hop, because that is the actionable
// half of the diagnostic.
inline std::string NotInnerReason(const std::string& resolver,
                                  const PostureInput& input) {
  const std::string value = detail::Trim(resolver);
  if (value.empty()) {
    return "it is empty";
  }
  uint32_t candidate = 0;
  if (!Ipv4Value(value, &candidate)) {
    return value +
           " is not an IPv4 literal, and a resolver that must itself be "
           "resolved is the lookup outside the tunnel this layer exists to "
           "prevent";
  }
  // THE NARROWED CLAUSE, AND EXACTLY HOW FAR IT NARROWS.
  //
  // Not "is the next hop" -> refuse, but "is the next hop AND the signed
  // descriptor names no resolver there" -> refuse. Nothing else moves: a
  // hostname, this device's own assignment, a public literal and anything
  // outside the assignment's /24 are all still refused below, and they stay
  // refused even when the descriptor names them, because the descriptor is a
  // signed FACT about where the gateway listens and not a permission to skip a
  // check.
  //
  // The old ground was "the gateway behind it answers no queries", true of
  // every gateway that has ever run and false for one running
  // `cmd/winn3-gateway -resolver`. That responder answers at the gateway's own
  // inner address, which IS this client's next hop, because winn3/tun's
  // outbound validator requires a reply's source to equal the endpoint's own
  // assignment -- a resolver at any second inner address cannot answer through
  // the tunnel at all. So "the resolver is the next hop" is the only shape this
  // protocol permits, not a coincidence to be tolerated.
  //
  // Compared as PARSED VALUES, never as text: `10.64.0.1` and `10.64.000.1` are
  // one address, and a string compare would refuse the operator's own signed
  // resolver while quoting a value that looks identical to it.
  const std::string router = detail::Trim(input.router_v4);
  uint32_t router_value = 0;
  if (!router.empty() && Ipv4Value(router, &router_value) &&
      router_value == candidate) {
    const std::string advertised = detail::Trim(input.inner_resolver_v4);
    uint32_t advertised_value = 0;
    if (advertised.empty() || !Ipv4Value(advertised, &advertised_value) ||
        advertised_value != candidate) {
      return value +
             " is [winn] inner_router_v4, which is documented as the inner next "
             "hop for PMTU signals only and answers no queries; naming it would "
             "trade a leak for total name-resolution failure. The signed "
             "descriptor does not name a resolver there -- it carries [winn] "
             "inner_resolver_v4 = \"" +
             advertised +
             "\" -- so this host has no signed fact saying anything listens on "
             "that address";
    }
  }
  uint32_t assignment = 0;
  if (!Ipv4Value(input.inner_v4, &assignment)) {
    return value +
           " cannot be shown to be inner because [winn] inner_v4 carries no "
           "IPv4 literal to derive an inner space from";
  }
  if (candidate == assignment) {
    return value +
           " is this session's own [winn] inner_v4 assignment, which is this "
           "device; nothing answers there";
  }
  if (IsPublicIPv4Literal(value)) {
    return value +
           " is a PUBLIC resolver. It is reachable off-tunnel by construction, "
           "so it resolves over the censored path the moment the tunnel drops";
  }
  if (!SameInnerBlock(candidate, assignment)) {
    return value + " is outside the /24 around this session's [winn] inner_v4 "
                   "assignment (" +
           detail::Trim(input.inner_v4) +
           "), so this host cannot derive that it is reachable only through "
           "THIS tunnel -- a resolver in another session's inner space is "
           "dropped by the winn/3 tun layer, not carried";
  }
  return std::string();
}

// Candidates is the resolver list a promoted posture may consider.
//
// THE SIGNED FIELD WINS OUTRIGHT, AND IT REPLACES RATHER THAN JOINS. See
// PostureInput::inner_resolver_v4 for why joining is the worse half of both.
// An empty descriptor field returns exactly the host's own `dns_servers`, which
// is what this header saw before the field existed.
inline std::vector<std::string> Candidates(const PostureInput& input) {
  const std::string advertised = detail::Trim(input.inner_resolver_v4);
  if (!advertised.empty()) {
    return std::vector<std::string>{advertised};
  }
  std::vector<std::string> offered;
  for (const std::string& entry : input.dns_servers) {
    const std::string trimmed = detail::Trim(entry);
    if (!trimmed.empty()) offered.push_back(trimmed);
  }
  return offered;
}

// Inner is the candidates that survive the derivation.
inline std::vector<std::string> Inner(const PostureInput& input) {
  std::vector<std::string> derived;
  for (const std::string& entry : Candidates(input)) {
    if (NotInnerReason(entry, input).empty()) derived.push_back(entry);
  }
  return derived;
}

// PromotionRefusalReason is why a standalone session may not promote on
// resolver grounds, or an empty string.
//
// The second clause is a claim about the WHOLE LIST rather than about each
// member, and that is deliberate and matches both mobile hosts:
// `dns_servers_are_inner` is ONE boolean over the whole of `dns_servers`, and
// every resolver installer these two platforms have -- `resolvectl dns`,
// `resolvconf -a`, an /etc/resolv.conf body, `netsh ... set dnsservers` --
// hands the entire list to the system, which then picks which entry answers.
// Filtering a mixed list down to its derivable members and promoting on the
// remainder would leave a public resolver installed beside an inner one and
// call the result inner.
inline std::string PromotionRefusalReason(const PostureInput& input) {
  const std::vector<std::string> offered = Candidates(input);
  if (offered.empty()) {
    return "a standalone winn/3 session has no resolver it can justify: this "
           "posture takes the default route, and a host that widens its routes "
           "without also moving name resolution leaves every DNS query going to "
           "the resolver it was handed by the network it is hiding from -- in "
           "the clear, over the physical interface, while the tunnel reports "
           "carrying. The route set and the resolver set have to move together "
           "or neither may move";
  }
  std::vector<std::string> rejected;
  for (const std::string& entry : offered) {
    const std::string reason = NotInnerReason(entry, input);
    if (!reason.empty()) rejected.push_back(reason);
  }
  if (!rejected.empty()) {
    std::string joined;
    for (size_t i = 0; i < rejected.size(); ++i) {
      if (i != 0) joined += "; ";
      joined += rejected[i];
    }
    return "a standalone winn/3 session cannot install the " +
           std::to_string(offered.size()) +
           " resolver(s) this configuration offers, because this host cannot "
           "DERIVE that every one of them is reachable only through the "
           "tunnel: " +
           joined +
           ". The declaration is derived and never transported -- a boolean on "
           "the wire asserting a resolver is inside the tunnel is the leak "
           "wearing a flag";
  }
  return std::string();
}

// AreInner is `dns_servers_are_inner`, DERIVED: true only when there is at
// least one resolver AND every one of them is derivable.
inline bool AreInner(const PostureInput& input) {
  return PromotionRefusalReason(input).empty();
}

}  // namespace resolvers

// ParseWinn3StatusLine reads one status document.
//
// It returns false for anything it cannot make sense of, and a false return
// leaves *out at its zero value -- which is not promotion-ready. There is no
// parse outcome that widens a tunnel.
inline bool ParseWinn3StatusLine(const std::string& line, EngineStatus* out) {
  if (out == nullptr) {
    return false;
  }
  *out = EngineStatus();
  if (line.size() > kMaxStatusLineBytes) {
    return false;
  }
  const std::string trimmed = detail::Trim(line);
  if (trimmed.size() < 2 || trimmed.size() > kMaxStatusLineBytes ||
      trimmed.front() != '{' || trimmed.back() != '}') {
    return false;
  }
  if (!detail::IsSingleJsonObject(trimmed)) {
    return false;
  }
  // Duplicate keys: encoding/json last-wins, this reader first-wins. Either
  // rule silently picks one of two `promotion_ready` values. A document that
  // names the gate twice is not a document this host will guess about.
  if (detail::CountKey(trimmed, "event") != 1) {
    return false;
  }
  if (detail::CountKey(trimmed, "promotion_ready") != 1) {
    return false;
  }
  if (detail::CountKey(trimmed, "gate_state") > 1 ||
      detail::CountKey(trimmed, "rx_packets") > 1 ||
      detail::CountKey(trimmed, "rx_offered") > 1 ||
      detail::CountKey(trimmed, "tx_dropped_closed") > 1 ||
      detail::CountKey(trimmed, "inner_mtu") > 1 ||
      detail::CountKey(trimmed, "message_size") > 1 ||
      detail::CountKey(trimmed, "inner_ipv6") > 1 ||
      detail::CountKey(trimmed, "posture") > 1 ||
      detail::CountKey(trimmed, "refusal") > 1) {
    return false;
  }
  EngineStatus parsed;
  if (!detail::ReadJsonString(trimmed, "event", &parsed.event)) {
    return false;
  }
  if (parsed.event.empty()) {
    return false;
  }
  // promotion_ready must be PRESENT. A document without it is from an engine
  // that does not speak this contract, and assuming false for it would be
  // indistinguishable from an engine that said false -- which sounds safe, and
  // is, but hides a version mismatch that will never be diagnosed.
  if (!detail::ReadJsonBool(trimmed, "promotion_ready",
                            &parsed.promotion_ready)) {
    return false;
  }
  // Optional keys: absent is the conservative zero. Present-but-unreadable
  // is a malformed document, not an absent key.
  if (detail::CountKey(trimmed, "posture") == 1 &&
      !detail::ReadJsonString(trimmed, "posture", &parsed.posture)) {
    return false;
  }
  if (detail::CountKey(trimmed, "gate_state") == 1 &&
      !detail::ReadJsonString(trimmed, "gate_state", &parsed.gate_state)) {
    return false;
  }
  if (detail::CountKey(trimmed, "refusal") == 1 &&
      !detail::ReadJsonString(trimmed, "refusal", &parsed.refusal)) {
    return false;
  }

  uint64_t number = 0;
  if (detail::CountKey(trimmed, "rx_packets") == 1) {
    if (!detail::ReadJsonUint(trimmed, "rx_packets", &number)) {
      return false;
    }
    parsed.rx_packets = number;
  }
  if (detail::CountKey(trimmed, "rx_offered") == 1) {
    if (!detail::ReadJsonUint(trimmed, "rx_offered", &number)) {
      return false;
    }
    parsed.rx_offered = number;
  }
  if (detail::CountKey(trimmed, "tx_dropped_closed") == 1) {
    if (!detail::ReadJsonUint(trimmed, "tx_dropped_closed", &number)) {
      return false;
    }
    parsed.tx_dropped_closed = number;
  }
  if (detail::CountKey(trimmed, "inner_mtu") == 1) {
    if (!detail::ReadJsonUint(trimmed, "inner_mtu", &number) ||
        number > 65535u) {
      return false;
    }
    parsed.inner_mtu = static_cast<int>(number);
  }
  if (detail::CountKey(trimmed, "message_size") == 1) {
    if (!detail::ReadJsonUint(trimmed, "message_size", &number) ||
        number > 65535u) {
      return false;
    }
    parsed.message_size = static_cast<int>(number);
  }
  if (detail::CountKey(trimmed, "inner_ipv6") == 1) {
    if (!detail::ReadJsonBool(trimmed, "inner_ipv6", &parsed.inner_ipv6)) {
      return false;
    }
  }

  parsed.valid = true;
  *out = parsed;
  return true;
}

// BuildBootstrapPosture produces the narrow posture, or refuses.
//
// It never falls back. A start that cannot build a narrow bootstrap must abort
// the start rather than install the full tunnel immediately, because a
// promotion on an unproven datapath costs the user their traffic while a
// refusal costs a retry.
inline bool BuildBootstrapPosture(const PostureInput& input,
                                  const EngineStatus& status,
                                  PosturePlan* plan, std::string* error) {
  if (plan == nullptr) {
    return detail::Fail(error, "no posture plan to fill");
  }
  *plan = PosturePlan();

  const std::string v4 = detail::Trim(input.inner_v4);
  const std::string v6 = detail::Trim(input.inner_v6);
  if (v4.empty() && v6.empty()) {
    return detail::Fail(error,
                        "the assignment carries neither an inner IPv4 nor an "
                        "inner IPv6 address");
  }
  const std::string exclusion = detail::Trim(input.outer_socket_exclusion);
  if (exclusion.empty()) {
    return detail::Fail(
        error,
        "the outer-socket exclusion is required in the FIRST posture: without "
        "it the engine's own carrier datagrams match the tunnel's routes and "
        "loop, and installing it later means installing it after traffic has "
        "already been captured");
  }
  if (!status.valid) {
    return detail::Fail(error,
                        "no engine status document has been read yet, so the "
                        "inner MTU is unknown and cannot be applied");
  }
  if (status.inner_mtu <= 0) {
    return detail::Fail(error,
                        "the engine published a non-positive inner MTU");
  }

  plan->posture = Posture::kBootstrap;
  plan->mtu = status.inner_mtu;
  plan->outer_socket_exclusion = exclusion;
  if (!v4.empty()) {
    plan->inner_v4 = v4;
    plan->prefix_v4 = 32;
  }
  if (!v6.empty()) {
    plan->inner_v6 = v6;
    plan->prefix_v6 = 128;
  }

  // AT MOST ONE route, and it is the inner next hop. Enough to prove the
  // datapath, not enough to capture anything.
  const std::string router_v4 = detail::Trim(input.router_v4);
  const std::string router_v6 = detail::Trim(input.router_v6);
  if (!plan->inner_v4.empty() && !router_v4.empty()) {
    plan->included_routes.push_back(router_v4 + "/32");
  } else if (!plan->inner_v6.empty() && !router_v6.empty()) {
    plan->included_routes.push_back(router_v6 + "/128");
  }

  plan->default_route = false;
  plan->ipv6 = false;
  plan->dns_servers.clear();
  return true;
}

// VerifyBootstrapIsNarrow re-checks the object that was just built.
//
// Checking the built settings rather than trusting the builder is the shape the
// iOS provider already uses, and the tun contract asks for it verbatim: a
// builder that is wrong is exactly a builder whose own claim of narrowness
// cannot be relied on.
inline bool VerifyBootstrapIsNarrow(const PosturePlan& plan,
                                    std::string* error) {
  if (plan.posture != Posture::kBootstrap) {
    return detail::Fail(error, "this plan is not a bootstrap posture");
  }
  if (plan.default_route) {
    return detail::Fail(error, "a bootstrap posture took the default route");
  }
  if (plan.ipv6) {
    return detail::Fail(error, "a bootstrap posture installed IPv6");
  }
  if (!plan.dns_servers.empty()) {
    return detail::Fail(error, "a bootstrap posture installed a resolver");
  }
  if (plan.included_routes.size() > 1) {
    return detail::Fail(error,
                        "a bootstrap posture installed more than one route");
  }
  if (plan.inner_v4.empty() && plan.inner_v6.empty()) {
    return detail::Fail(error, "a bootstrap posture carries no inner address");
  }
  if (!plan.inner_v4.empty() && plan.prefix_v4 != 32) {
    return detail::Fail(error,
                        "the inner IPv4 prefix is wider than /32, which lets "
                        "the host originate from an address the tunnel drops");
  }
  if (!plan.inner_v6.empty() && plan.prefix_v6 != 128) {
    return detail::Fail(error, "the inner IPv6 prefix is wider than /128");
  }
  if (plan.mtu <= 0) {
    return detail::Fail(error, "a bootstrap posture has no MTU");
  }
  if (detail::Trim(plan.outer_socket_exclusion).empty()) {
    return detail::Fail(error,
                        "a bootstrap posture has no outer-socket exclusion");
  }
  return true;
}

// ===========================================================================
// THE OTHER HALF OF THE GATE: A POSTURE THAT WIDENS TO NOTHING
// ===========================================================================
//
// VerifyBootstrapIsNarrow asks "did the narrow posture stay narrow?". Until
// 2026-08-09 nothing asked the opposite question, and the opposite question is
// the one a served configuration makes reachable: "did the WIDE posture
// actually widen?".
//
// A promotion gate that reports success on a posture capturing nothing is worth
// less than no gate at all. No gate leaves an operator knowing the state is
// unproven; a gate that says success leaves them believing a proof happened.
// Every consumer downstream -- the status line, the UI, the user's decision
// about what to type into a browser -- reads that success.
//
// VerifyPromotedPostureCaptures is the plan-level check.
// VerifyPromotedCommandsCapture is the same question asked of the RENDERED
// argument vectors, and it is not redundant: the argv is what moves traffic,
// the plan is only what was intended, and this header's renderers are shared by
// two hosts so a change made for one lands on the other.
inline bool VerifyPromotedPostureCaptures(const PosturePlan& plan,
                                          std::string* error) {
  if (plan.posture != Posture::kPromoted) {
    return detail::Fail(error, "this plan is not a promoted posture");
  }
  if (plan.default_route) {
    return true;
  }
  for (const std::string& route : plan.included_routes) {
    if (detail::CapturesMoreThanOneHost(route)) {
      return true;
    }
  }
  return detail::Fail(
      error,
      "refusing to promote to a posture that would capture nothing: it takes "
      "no default route and its " +
          std::to_string(plan.included_routes.size()) +
          " route(s) are all single hosts. The session would report carrying "
          "while every packet still left by the physical interface in the "
          "clear, which is a leak rather than a stall -- and the gate would "
          "report success throughout");
}

// VerifyPromotedCommandsCapture re-checks what will actually be EXECUTED.
//
// It is the mirror of the bootstrap's rendered-argv check and it exists for the
// same stated reason: a renderer that dropped the widening for a plan whose
// `default_route` is true would sail past every plan-level check in the system.
//
// It insists on BOTH HALVES of the /1 pair when the pair is the capture
// mechanism, and that is the check worth having. `0.0.0.0/1` alone leaves
// 128.0.0.0/1 -- half the IPv4 address space, and the half holding most of the
// public internet a user in a censored network actually reaches -- on the
// physical path, while the plan, the status line and the UI all read promoted.
// No plan-level predicate can see that, because the plan carries one boolean
// for two commands.
//
// The IPv6 halves are checked the same way since 2026-08-10 (ds_ipv6linux).
// `::/1` alone is a valid prefix and would previously fall through to
// CapturesMoreThanOneHost and count as capture, on the strength of being a
// prefix at all -- half of `::/0` left on the physical interface while the
// other half is on the tunnel is exactly the leak this check exists to refuse.
// Spelled out here so a lone IPv6 half is refused by name on both hosts.
inline bool VerifyPromotedCommandsCapture(
    const std::vector<std::vector<std::string>>& commands,
    std::string* error) {
  bool low_half = false;
  bool high_half = false;
  bool v6_low_half = false;
  bool v6_high_half = false;
  bool whole = false;
  bool wide = false;
  for (const std::vector<std::string>& argv : commands) {
    for (const std::string& token : argv) {
      if (token == detail::kDefaultRouteLowHalf) {
        low_half = true;
      } else if (token == detail::kDefaultRouteHighHalf) {
        high_half = true;
      } else if (token == detail::kIPv6DefaultRouteLowHalf) {
        v6_low_half = true;
      } else if (token == detail::kIPv6DefaultRouteHighHalf) {
        v6_high_half = true;
      } else if (token == "0.0.0.0/0" || token == "::/0" ||
                 token == "default") {
        whole = true;
      } else if (detail::CapturesMoreThanOneHost(token)) {
        wide = true;
      }
    }
  }
  if (whole || wide || (low_half && high_half) ||
      (v6_low_half && v6_high_half)) {
    return true;
  }
  if (low_half != high_half || v6_low_half != v6_high_half) {
    const std::string missing =
        (low_half != high_half)
            ? std::string(low_half ? detail::kDefaultRouteHighHalf
                                   : detail::kDefaultRouteLowHalf)
            : std::string(v6_low_half ? detail::kIPv6DefaultRouteHighHalf
                                      : detail::kIPv6DefaultRouteLowHalf);
    return detail::Fail(
        error,
        std::string("a promoted posture rendered only half of a default-route "
                    "pair and not ") +
            missing +
            ". Each family's two halves are ONE decision -- they replace a "
            "default route without deleting it -- and half of them leaves half "
            "that address space on the physical interface while the plan, the "
            "status line and the user all read promoted");
  }
  return detail::Fail(
      error,
      "a promoted posture rendered no route that captures traffic. The "
      "commands would install an address and an MTU on a device nothing is "
      "routed to, the engine would keep reporting carrying, and every packet "
      "would still leave by the physical interface in the clear");
}

// BuildPromotedPosture is the only function here that can widen anything, and
// it refuses unless the engine has PROVEN the datapath.
inline bool BuildPromotedPosture(const PostureInput& input,
                                 const EngineStatus& status, PosturePlan* plan,
                                 std::string* error) {
  if (plan == nullptr) {
    return detail::Fail(error, "no posture plan to fill");
  }
  *plan = PosturePlan();

  if (!status.valid) {
    return detail::Fail(error,
                        "refusing to promote on an unparsed status document");
  }
  if (!status.refusal.empty()) {
    return detail::Fail(error,
                        "refusing to promote: the engine reported " +
                            status.refusal);
  }
  if (!status.promotion_ready) {
    // The two halves are named separately because the operator needs to know
    // WHICH one is missing: a gate that never opened is a handshake problem,
    // and an open gate with no delivered packet is a return-path problem.
    if (status.gate_state != kCarryingGate) {
      return detail::Fail(
          error, "refusing to promote: the session gate is '" +
                     status.gate_state + "', not '" + kCarryingGate + "'");
    }
    return detail::Fail(
        error,
        "refusing to promote: the gate is carrying but no inner packet has "
        "reached the host device yet");
  }
  // Belt and braces. promotion_ready is computed by the engine and this host
  // does not recompute it -- but a document that says ready while disagreeing
  // with the evidence for it is a document that disagrees with ITSELF, and
  // trusting it would mean trusting the field over the evidence for it.
  //
  // BOTH HALVES, AND UNTIL 2026-08-12 IT WAS ONE. `promotion_ready` is a
  // conjunction -- the gate is carrying AND an inner packet was delivered --
  // and only the second half was re-derived here. The first half WAS checked,
  // twenty lines up, but nested inside `if (!status.promotion_ready)`, where it
  // is a DIAGNOSTIC: it runs only once promotion has already been refused, to
  // tell the operator which half is missing. It is still there and still does
  // that. What it could not do from inside that branch is refuse, because the
  // branch is unreachable the moment the field says true.
  //
  // So a document reading ready=true, a gate state that is not the carrying
  // one, and rx_packets above zero PROMOTED -- default route, resolvers and
  // IPv6 -- with the gate comparison never executed. Confirmed by execution on
  // 2026-08-12 against a handshaking gate.
  //
  // The engine cannot write that document. cmd/winn-datapath's winn3StatusFrom
  // reads `tunnel.Gate().State()` ONCE and derives both `gate_state` and
  // `promotion_ready` from that one value, so they cannot disagree in a
  // document it produced -- in any state, transitional ones included, because
  // winn3PromotionReady is `gate == StateCarrying && rxPackets > 0` on the same
  // value that gets stringified into the field. This is therefore defence in
  // depth against a malformed, truncated or substituted status line rather than
  // a live engine bug. It has one shape that needs no attacker at all:
  // ParseWinn3StatusLine treats `gate_state` as OPTIONAL, so an engine that
  // publishes promotion_ready without it parses to an EMPTY gate state, and an
  // empty gate state is not the carrying one.
  if (status.gate_state != kCarryingGate) {
    return detail::Fail(
        error, "refusing to promote: the status document claims the datapath "
               "is proven but reports the session gate as '" +
                   status.gate_state + "', not '" + kCarryingGate +
                   "', so it disagrees with itself");
  }
  if (status.rx_packets == 0) {
    return detail::Fail(error,
                        "refusing to promote: the status document claims the "
                        "datapath is proven but reports zero delivered inner "
                        "packets");
  }

  // Build the bootstrap first and keep everything it decided, so that the
  // promoted posture is the narrow one PLUS the widenings and never a second,
  // independently assembled configuration that might differ in the address, the
  // prefix, the MTU or the exclusion.
  PosturePlan narrow;
  if (!BuildBootstrapPosture(input, status, &narrow, error)) {
    return false;
  }
  if (!VerifyBootstrapIsNarrow(narrow, error)) {
    return false;
  }
  *plan = narrow;
  plan->posture = Posture::kPromoted;
  plan->default_route = true;

  // THE ROUTE SET IS A UNION, NOT A REPLACEMENT, AND THAT IS A FIX.
  //
  // Until 2026-08-09 this line was `plan->included_routes = input.full_routes;`
  // -- an assignment, which DISCARDED the one route the bootstrap installed:
  // the inner next hop. For a served `[winn]` section, which carries no route
  // key at all, that turned a plan describing {10.10.0.1/32} into a plan
  // describing {}. Nothing leaked, because the bootstrap's route was already in
  // the kernel and neither renderer deletes anything -- but the plan STOPPED
  // DESCRIBING THE POSTURE THAT WAS INSTALLED, and every check in this header
  // reads the plan. A verifier reasoning about an object that does not match
  // the machine is a verifier that agrees with itself and nothing else.
  //
  // The union keeps the next hop, appends whatever the host supplied, and drops
  // two classes of entry:
  //   * duplicates, because both renderers emit one command per entry and the
  //     second `ip route add` of the same prefix fails EEXIST; and
  //   * anything `default_route` already renders (the /1 pair and the literal
  //     defaults), for the same reason. `routes = 0.0.0.0/1, 128.0.0.0/1` is
  //     the natural way to hand-write a full tunnel and it must not be the way
  //     to break one.
  for (const std::string& route : input.full_routes) {
    const std::string value = detail::Trim(route);
    if (value.empty() || detail::RendersAsDefaultRoute(value)) continue;
    bool already = false;
    for (const std::string& kept : plan->included_routes) {
      if (kept == value) already = true;
    }
    if (!already) plan->included_routes.push_back(value);
  }

  // ===========================================================================
  // ONE OF THE TWO IPv6 SHAPES, AND UNTIL 2026-08-10 IT WAS NEITHER
  // ===========================================================================
  //
  // Inner IPv6 is installed only if the plan floor can actually carry it.
  // Installing IPv6 settings the datapath cannot carry produces a host that
  // prefers the family that black-holes.
  //
  // But "cannot carry inner IPv6" was treated here as "install no IPv6 at
  // all", and that is the OTHER failure, one the promotion above makes
  // certain rather than likely. `default_route = true` twenty lines up moves
  // the user's IPv4 onto the tunnel; leaving IPv6 alone leaves the host's own
  // v6 address and v6 default route on the physical interface, so every
  // destination with a AAAA record is reached AROUND the tunnel while the
  // session reports carrying. Windows makes that the common case rather than
  // the exotic one: its prefix policy table gives `::/0` precedence 40 against
  // 35 for `::ffff:0:0/96`, so a dual-stack name is reached over IPv6 BY
  // DEFAULT (read off the test machine, 2026-08-10).
  //
  // MEASURED, not reasoned. The five `ip` commands this function's renderer
  // produced for a promoted posture were replayed into a throwaway network
  // namespace on 2026-08-10, against a host holding a global v6 address on its
  // physical interface:
  //
  //   ip -6 route get 2001:db8:9::1  ->  dev phy0     (the physical interface)
  //   during 5 IPv6 echo requests:       phy0 tx +7,  tun tx +1
  //   packets the tunnel received:       0 to that destination
  //
  // and the same run with the sink installed:
  //
  //   ip -6 route get 2001:db8:9::1  ->  dev winn0    (the tunnel)
  //   during 5 IPv6 echo requests:       phy0 tx +1,  tun tx +5
  //   packets the tunnel received:       2001:db8:9::1 present
  //
  // IPv6 was NOT disabled on the tun in either arm -- `disable_ipv6` read 0 on
  // every interface and the tun took a link-local of its own -- so this is a
  // leak and not an absence of traffic. Android's promotion has refused this
  // shape since 2026-08-07 and Apple installs the sink; these two hosts were
  // the ones still shipping it.
  //
  // The sink is a /128 with no route to anywhere plus a v6 default: v6 is drawn
  // into the tunnel, the winn/3 tun layer drops it as an unassigned family, and
  // v6 connectivity stops. A blackout the user can see beats a leak they
  // cannot, which is the same trade Apple's provider and the relay's own
  // settings builder already make.
  if (!plan->inner_v6.empty()) {
    if (!status.inner_ipv6) {
      return detail::Fail(
          error,
          "refusing to promote with IPv6: the engine reports that the plan "
          "floor cannot carry inner IPv6, and installing it would make the "
          "host prefer the family that black-holes");
    }
    plan->ipv6 = true;
  } else if (plan->mtu >= kIPv6MinLinkMTU) {
    // THE GUARD IS ON plan->mtu, WHICH IS THE NUMBER THAT GOES ON THE
    // INTERFACE, not on a transported boolean and not on the path MTU. See
    // kIPv6MinLinkMTU for why one comparison is the plan-aware form of all
    // three published thresholds, and for the measurement showing the kernel
    // refuses the address below it.
    const std::string sink = detail::Trim(input.ipv6_sink);
    plan->ipv6_sink = sink.empty() ? std::string(kIPv6SinkAddress) : sink;
    plan->prefix_v6 = kIPv6SinkPrefixLength;
    plan->ipv6 = true;
  } else {
    // The one case where neither shape is available: an inner address would be
    // a black hole and the sink is an -EINVAL. The posture promotes IPv4-only
    // and host IPv6 stays where it is. That is a leak, it is recorded here
    // rather than left silent, and it is unreachable on the fleet default --
    // path 1450 yields 1309 over the widest plan.
    plan->ipv6_absent_reason =
        "this posture installs no IPv6 at all: the inner MTU is " +
        std::to_string(plan->mtu) + ", below RFC 8200's " +
        std::to_string(kIPv6MinLinkMTU) +
        "-byte link floor, so an inner IPv6 address would be a black hole and "
        "the fail-closed sink is refused by the kernel (ipv6_add_dev returns "
        "-EINVAL). Host IPv6 therefore stays on the physical interface beside "
        "a promoted IPv4 tunnel. Raise the served path_mtu to at least 1357 "
        "(udp), 1399 ([udp,tcp]) or 1421 ([udp,tcp,tls]) -- the fleet default "
        "of 1450 clears all three";
  }

  // ===========================================================================
  // A PROMOTION WITH NO RESOLVER IS THE LEAK, AND IT USED TO BE ALLOWED
  // ===========================================================================
  //
  // Until 2026-08-09 an empty `dns_servers` promoted happily and installed
  // none, and linux/runner/winn3_posture_test.cc asserted that it should:
  // "a promotion with no resolvers at all is fine". It is not fine, and the
  // reason is the line above this one -- `default_route = true`.
  //
  // What actually happens when a promotion installs no resolver: the machine
  // keeps whatever resolver DHCP gave it, which on a home or cafe connection is
  // the CPE at 192.168.1.1. The /1 pair captures everything EXCEPT what a more
  // specific route already covers, and the physical link's own connected
  // /24 is more specific than /1. So every DNS query keeps going out the
  // physical interface, in the clear, to the resolver the censor operates,
  // while the tunnel carries the web traffic and the UI reads Connected.
  //
  // That is not a stall. It is the exact shape this staged posture exists to
  // prevent, arriving through the configuration rather than the datapath: the
  // user's full browsing history is handed to the network they are hiding from,
  // and it is SILENT, because the pages still load. Refusing costs a retry and
  // a named diagnostic. Accepting costs the user everything the tunnel was for.
  //
  // The refusal is deliberately unconditional rather than gated on a host flag.
  // A flag for "I have thought about resolvers" is a flag that gets set once and
  // then survives every later change to the code that set it. Both paths below
  // refuse an empty resolver set, for this reason and in these words.
  //
  // ===========================================================================
  // TWO PATHS TO A RESOLVER, AND THE SIGNED ONE DOES NOT GET TO DECLARE
  // ===========================================================================
  //
  // Which path runs is decided by ONE fact: whether the ML-DSA-65-signed
  // descriptor named an inner resolver. It is not a mode, not a flag and not a
  // host preference, because either the signed document names a resolver or it
  // does not.
  //
  //   DERIVED (`inner_resolver_v4` non-empty). The value is checked for
  //   inner-ness by address shape, exactly as Apple and Android check it, and
  //   `dns_servers_are_inner` IS NOT CONSULTED. That is the entire point: on a
  //   served session the only party who could set that boolean is the control
  //   plane, and a boolean on the wire asserting a resolver is inside the
  //   tunnel is the leak wearing a flag. Deriving is strictly more evidence
  //   than the declaration below asks for, never less.
  //
  //   DECLARED (`inner_resolver_v4` empty). Byte for byte the behaviour this
  //   function had before the field existed, for hand-written `[winn3]`
  //   documents whose `dns` and `dns_are_inner` lines were written by somebody
  //   holding the machine. This header cannot derive an inner space for those:
  //   a local document's resolvers need not sit in the assignment's /24 at all.
  //
  // Every descriptor signed to date carries no `inner_resolver_v4`, so the
  // derived path is unreachable in the field today and the declared path is
  // what every existing configuration and every existing test still takes.
  if (!detail::Trim(input.inner_resolver_v4).empty()) {
    const std::string refusal = resolvers::PromotionRefusalReason(input);
    if (!refusal.empty()) {
      return detail::Fail(error, "refusing to promote: " + refusal);
    }
    // Candidates() REPLACES rather than joins, so a host `dns_servers` list
    // full of public Quad9 literals cannot ride along beside the signed
    // resolver into an installer that hands the whole list to the system.
    plan->dns_servers = resolvers::Candidates(input);
  } else {
    if (input.dns_servers.empty()) {
      return detail::Fail(
          error,
          "refusing to promote without a resolver: this posture takes the "
          "default route, and a host that widens its routes without also moving "
          "name resolution leaves every DNS query going to the resolver it was "
          "handed by the network it is hiding from -- in the clear, over the "
          "physical interface, while the tunnel reports carrying. The route set "
          "and the resolver set have to move together or neither may move");
    }
    if (!input.dns_servers_are_inner) {
      return detail::Fail(
          error,
          "refusing to promote with resolvers the host has not declared to be "
          "inner: a resolver reachable outside the tunnel resolves names over "
          "the censored path the moment the tunnel drops");
    }
    plan->dns_servers = input.dns_servers;
  }

  if (detail::Trim(plan->outer_socket_exclusion).empty()) {
    return detail::Fail(error,
                        "refusing to promote without the outer-socket "
                        "exclusion still in place");
  }

  // The built object is checked rather than the builder trusted, which is the
  // same shape VerifyBootstrapIsNarrow gives the other posture and the same
  // shape the iOS provider uses. It is the LAST thing this function does, so
  // there is no path that returns a promoted plan this predicate would reject.
  //
  // BELT TO BRACES, AND MEASURED TO BE SO. Mutation-tested on 2026-08-09:
  // deleting this call SURVIVED the whole C++ suite, because `default_route`
  // is set true unconditionally twenty lines up and VerifyPromotedPostureCaptures
  // returns true on that alone. No input reachable through this builder can
  // produce a plan it rejects, so no behavioural test can distinguish the call
  // being here from its being gone.
  //
  // It is kept, and the reasoning is the same as the `entry.encrypted()` note
  // in core/archive: an unreachable check on the path that moves a user's
  // traffic costs one comparison, and the edit that makes it reachable -- a
  // split-tunnel mode, or any future posture whose default route is
  // conditional -- is exactly the edit during which nobody is looking for it.
  // What holds it is winn3/conform's StandaloneCaptureGuards, which greps for
  // this line, because a grep is the only thing that can.
  if (!VerifyPromotedPostureCaptures(*plan, error)) {
    return false;
  }
  return true;
}

// --- rendering ---------------------------------------------------------------
//
// The two renderers below turn a plan into the argument vectors each platform's
// privileged executor already knows how to run. They are pure string functions
// so that what a host would actually execute can be diffed in a test on a
// development machine, which is the only place these two platforms' behaviour
// can be compared side by side at all.
//
// Nothing here quotes for a shell. Both hosts execute argument vectors rather
// than command lines -- the Linux runner through its root script's positional
// arguments, the Windows service through CreateProcess -- and a renderer that
// emitted shell syntax would invite a caller to reintroduce the quoting bug
// that argument vectors exist to remove. The strings are for execution and for
// diagnosis, in that order.

// RenderLinuxPostureCommands renders `ip`/`ip -6` argument vectors.
inline std::vector<std::vector<std::string>> RenderLinuxPostureCommands(
    const std::string& interface_name, const PosturePlan& plan) {
  std::vector<std::vector<std::string>> commands;
  if (!plan.inner_v4.empty()) {
    commands.push_back({"ip", "-4", "address", "add",
                        plan.inner_v4 + "/" + std::to_string(plan.prefix_v4),
                        "dev", interface_name});
  }
  // The inner address if the session has one, the fail-closed sink if it does
  // not. Exactly one of the two, because a session that can carry inner IPv6
  // has no use for a black hole.
  const std::string v6_address =
      plan.inner_v6.empty() ? plan.ipv6_sink : plan.inner_v6;
  if (plan.ipv6 && !v6_address.empty()) {
    commands.push_back({"ip", "-6", "address", "add",
                        v6_address + "/" + std::to_string(plan.prefix_v6),
                        "dev", interface_name});
  }
  commands.push_back({"ip", "link", "set", "dev", interface_name, "mtu",
                      std::to_string(plan.mtu), "up"});
  for (const std::string& route : plan.included_routes) {
    commands.push_back({"ip", "route", "add", route, "dev", interface_name});
  }
  if (plan.default_route) {
    // Two /1 routes rather than one default, because they beat an existing
    // default route on specificity without deleting it -- so a teardown that
    // fails part way leaves the host's own default intact rather than leaving
    // it with none at all.
    commands.push_back(
        {"ip", "route", "add", detail::kDefaultRouteLowHalf, "dev", interface_name});
    commands.push_back(
        {"ip", "route", "add", detail::kDefaultRouteHighHalf, "dev", interface_name});
    if (plan.ipv6) {
      // The same decision for the other family, and NOT `ip -6 route add ::/0`:
      // that lands at metric 1024, where the host's own default already is, and
      // returns EEXIST. Measured 2026-08-10; the halves win on specificity at
      // the same metric, exactly as the IPv4 pair does.
      commands.push_back({"ip", "-6", "route", "add", detail::kIPv6DefaultRouteLowHalf,
                          "dev", interface_name});
      commands.push_back({"ip", "-6", "route", "add", detail::kIPv6DefaultRouteHighHalf,
                          "dev", interface_name});
    }
  }
  return commands;
}

// RenderWindowsPostureCommands renders `netsh` argument vectors.
inline std::vector<std::vector<std::string>> RenderWindowsPostureCommands(
    const std::string& interface_name, const PosturePlan& plan) {
  std::vector<std::vector<std::string>> commands;
  if (!plan.inner_v4.empty()) {
    commands.push_back({"netsh", "interface", "ipv4", "set", "address",
                        "name=" + interface_name, "source=static",
                        "address=" + plan.inner_v4 + "/" +
                            std::to_string(plan.prefix_v4)});
    commands.push_back({"netsh", "interface", "ipv4", "set", "subinterface",
                        interface_name, "mtu=" + std::to_string(plan.mtu),
                        "store=active"});
  }
  const std::string v6_address =
      plan.inner_v6.empty() ? plan.ipv6_sink : plan.inner_v6;
  if (plan.ipv6 && !v6_address.empty()) {
    commands.push_back({"netsh", "interface", "ipv6", "set", "address",
                        "interface=" + interface_name,
                        "address=" + v6_address + "/" +
                            std::to_string(plan.prefix_v6)});
  }
  for (const std::string& route : plan.included_routes) {
    const bool v6 = detail::LooksLikeIPv6(route);
    // store=active on EVERY route command, load-bearing and not cosmetic:
    // netsh's default store for `add route` is persistent, and a persistent
    // record outlives the Wintun adapter teardown this supervisor's stop path
    // relies on (routes die with the interface). Measured live on winpc
    // 2026-08-23: after a clean stop, `route print -4` still listed the
    // session's next-hop /32 and the two /1 halves in the persistent section,
    // and a persistent /1 stored beside a new session's default route is
    // exactly the leftover that wins lookups for half the address space. The
    // same store=active suffix the mtu command already carries is what keeps
    // the bridge "the adapter is gone, so its routes are gone" true.
    commands.push_back({"netsh", "interface", v6 ? "ipv6" : "ipv4", "add",
                        "route", route, "interface=" + interface_name,
                        "store=active"});
  }
  if (plan.default_route) {
    commands.push_back({"netsh", "interface", "ipv4", "add", "route",
                        detail::kDefaultRouteLowHalf, "interface=" + interface_name,
                        "store=active"});
    commands.push_back({"netsh", "interface", "ipv4", "add", "route",
                        detail::kDefaultRouteHighHalf, "interface=" + interface_name,
                        "store=active"});
    if (plan.ipv6) {
      commands.push_back({"netsh", "interface", "ipv6", "add", "route",
                          detail::kIPv6DefaultRouteLowHalf,
                          "interface=" + interface_name, "store=active"});
      commands.push_back({"netsh", "interface", "ipv6", "add", "route",
                          detail::kIPv6DefaultRouteHighHalf,
                          "interface=" + interface_name, "store=active"});
    }
  }
  bool primary = true;
  for (const std::string& resolver : plan.dns_servers) {
    const bool v6 = detail::LooksLikeIPv6(resolver);
    commands.push_back({"netsh", "interface", v6 ? "ipv6" : "ipv4",
                        primary ? "set" : "add", "dnsservers",
                        "name=" + interface_name, "static", resolver,
                        primary ? "primary" : "index=2", "validate=no"});
    primary = false;
  }
  return commands;
}

// PromotedCommandDelta returns the argument vectors a PROMOTED posture must
// execute that the BOOTSTRAP posture did not already execute.
//
// WHY THIS EXISTS, found by EXECUTING the shipping renderers on winpc on
// 2026-08-10: a promoted posture is the bootstrap plus its widenings, so
// `RenderWindowsPostureCommands(interface, promoted)` re-issues the bootstrap's
// `netsh interface ipv4 add route <next-hop>` (and its `set address`,
// `set subinterface`). The second `add route` on an interface that already
// holds the route answers `The object already exists.` with a non-zero exit,
// and the Windows applier stops at the first failing command -- so promotion
// failed on its FIRST command, before the IPv6 sink or any default route moved.
// That is fail-closed and therefore not a leak, but it is a session that
// bootstraps, proves its datapath and then never widens: the exact stall the
// Linux host already had to close (linux_winn3_host.cc, "the delta"),
// re-occurring on the other renderer.
//
// The DELTA is what promotion must actually execute, so this predicate exists
// to compute it and to let VerifyPromotedCommandsCapture be fed the delta
// rather than the whole posture -- a capture check on commands that were
// already executed at bootstrap and are being filtered away is a check of a
// hypothetical.
//
// IDEMPOTENT ACROSS REPEAT-APPLY (this is the whole reason it takes an
// "already" set rather than assuming the bootstrap): the first application
// runs the delta against the bootstrap; after it succeeds the interface holds
// bootstrap UNION delta, i.e. the whole promoted set, so a second promotion fed
// that genuinely-applied set yields an EMPTY delta and runs nothing. That is
// what keeps a repeat promotion from re-issuing the bootstrap's `add route
// <next-hop>` and answering "The object already exists" on winpc, and why an
// applier must accumulate the commands it has actually run rather than
// recompute against the bootstrap every time. winn3_supervisor_test.cc's
// TestPromotedCommandDeltaIsIdempotentAcrossRepeatApply pins the whole
// composition: first delta drops the next-hop and carries the widenings, the
// repeat delta is empty, and an empty re-promotion is refused by the capture
// guard rather than reported as a widening.
inline std::vector<std::vector<std::string>> PromotedCommandDelta(
    const std::vector<std::vector<std::string>>& promoted,
    const std::vector<std::vector<std::string>>& bootstrap) {
  std::vector<std::vector<std::string>> delta;
  for (const std::vector<std::string>& argv : promoted) {
    bool already = false;
    for (const std::vector<std::string>& done : bootstrap) {
      if (done == argv) {
        already = true;
        break;
      }
    }
    if (!already) delta.push_back(argv);
  }
  return delta;
}

}  // namespace winsvpn::winn3

#endif  // RUNNER_WINN3_POSTURE_H_
