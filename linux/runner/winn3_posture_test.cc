// Staged-posture tests for the Winn Protocol v3 desktop hosts.
//
// WHY THIS FILE EXISTS. The posture policy decides when a user's default route,
// their IPv6 configuration and their resolvers move onto a tunnel. Every
// mistake this class of code can make is silent: it produces a tunnel that
// looks up. The one that matters most -- promoting on "the session says DATA
// may flow" rather than on "an inner packet reached the host device" -- cannot
// be seen at all from the host side, because in both cases the interface comes
// up and the user's traffic starts moving. It is only visible as a user in
// Myanmar whose traffic left in the clear during the seconds before the tunnel
// actually worked.
//
// It is deliberately free of glib/gio and of <windows.h> -- like
// linux_winn_carrier_profile_test.cc, and for the same stated reason -- so it
// builds and RUNS on the development host as well as on either target. A test
// that only the target platform can execute is a test that does not get run,
// and neither target platform is where this project's sessions happen.
//
// Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -o /tmp/winn3_posture_test
//       linux/runner/winn3_posture_test.cc && /tmp/winn3_posture_test
//
// (one line; the continuation backslash that used to be here made GCC's
// -Wcomment fire, so `-Werror` could not build this file on the TARGET
// platform while clang on the development host was perfectly happy. A test
// that only builds on the machine it is written on is the same failure this
// file's own header complains about, one level up.)
//
// It is registered as the winn3_posture_test ctest target in
// linux/runner/CMakeLists.txt. linux_secure_store_test.cc is also registered
// there. linux_winn_carrier_profile_test.cc remains standalone-only.

#include "winn3_posture.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

int failures = 0;

// `checks` counts every assertion this program ran, and it exists so a reader
// of the output can tell "all checks passed" from "no checks ran". A harness
// that reports only failures reports the same thing for a green suite and for a
// suite whose test functions were never called from main -- and the second has
// happened in this tree. It is a reporting counter and gates nothing.
int checks = 0;

void Check(bool condition, const std::string& what) {
  ++checks;
  if (!condition) {
    ++failures;
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
  }
}

using winsvpn::winn3::BuildBootstrapPosture;
using winsvpn::winn3::BuildPromotedPosture;
using winsvpn::winn3::EngineStatus;
using winsvpn::winn3::ParseWinn3StatusLine;
using winsvpn::winn3::Posture;
using winsvpn::winn3::PostureInput;
using winsvpn::winn3::PosturePlan;
using winsvpn::winn3::PromotedCommandDelta;
using winsvpn::winn3::RenderLinuxPostureCommands;
using winsvpn::winn3::RenderWindowsPostureCommands;
using winsvpn::winn3::VerifyBootstrapIsNarrow;
using winsvpn::winn3::VerifyPromotedCommandsCapture;
using winsvpn::winn3::VerifyPromotedPostureCaptures;

// The DERIVED half of DNS-at-promotion. Aliased rather than pulled in with
// per-symbol `using` declarations because the clause-order tests below read as
// a comparison against Apple's `WinsWinn3Resolvers` and Android's
// `WinnV3Resolvers`, and keeping the qualifier makes that correspondence
// visible at every call site.
namespace resolvers = winsvpn::winn3::resolvers;

// A status line of the exact shape cmd/winn-datapath emits.
std::string StatusLine(bool ready, const std::string& gate, uint64_t rx,
                       bool inner_ipv6) {
  std::string line = "{\"event\":\"posture\",\"posture\":\"";
  line += ready ? "promoted" : "bootstrap";
  line += "\",\"promotion_ready\":";
  line += ready ? "true" : "false";
  line += ",\"gate_state\":\"" + gate + "\"";
  line += ",\"rx_packets\":" + std::to_string(rx);
  line += ",\"rx_offered\":" + std::to_string(rx);
  line += ",\"tx_packets\":0,\"tx_dropped_closed\":0,\"rx_dropped_closed\":0";
  line += ",\"messages_sent\":4,\"messages_received\":4,\"send_failed\":0";
  line += ",\"recv_failed\":0,\"migrations\":0";
  line += ",\"inner_mtu\":1190,\"message_size\":1210";
  line += ",\"inner_ipv6\":";
  line += inner_ipv6 ? "true" : "false";
  line += ",\"plan\":[\"udp\",\"tcp\"]";
  line += ",\"outer_socket_exclusion\":\"fwmark 0x1f4 lookup 51820\"}";
  return line;
}

PostureInput SampleInput() {
  PostureInput input;
  input.inner_v4 = "10.64.0.2";
  input.router_v4 = "10.64.0.1";
  input.outer_socket_exclusion = "fwmark 0x1f4 lookup 51820";
  input.full_routes = {"0.0.0.0/1", "128.0.0.0/1"};
  input.dns_servers = {"10.64.0.1"};
  input.dns_servers_are_inner = true;
  return input;
}

EngineStatus Parsed(const std::string& line) {
  EngineStatus status;
  ParseWinn3StatusLine(line, &status);
  return status;
}

void TestTheStatusParserReadsWhatTheEngineWrites() {
  const EngineStatus ready = Parsed(StatusLine(true, "carrying", 12, false));
  Check(ready.valid, "a well-formed status line parses");
  Check(ready.promotion_ready, "promotion_ready is read");
  Check(ready.gate_state == "carrying", "gate_state is read");
  Check(ready.rx_packets == 12, "rx_packets is read");
  Check(ready.inner_mtu == 1190, "inner_mtu is read");
  Check(!ready.inner_ipv6, "inner_ipv6 false is read as false");

  const EngineStatus v6 = Parsed(StatusLine(true, "carrying", 1, true));
  Check(v6.inner_ipv6, "inner_ipv6 true is read as true");
}

// A KEY IS NOT A VALUE. Found by execution on 2026-08-09, against the shipping
// cmd/winn-datapath binary rather than against a fixture.
//
// The frame mode's CreateAck and StatusResponse both carry `"event":"posture"`,
// and frame mode also carries `session_id`, which the desktop mode omits. So
// the real document contains the string `"posture"` TWICE -- once as the value
// of `event`, once as the key -- and the old reader took the first occurrence,
// scanned to the next colon, which belonged to `session_id`, and returned the
// session identifier as the posture. The measured output was
// `posture=0123456789abcdef0123456789abcdef`.
//
// No tunnel was ever widened by it: nothing here decides anything from
// `posture`. What it did do is put a peer-chosen value where an operator reads
// a policy state, and leave a trap for the next person who gates on the field
// the engine publishes precisely so a host does not have to compute it.
void TestAKeyIsNotAValue() {
  // The exact shape cmd/winn-datapath's frame mode emits: winn3Status's struct
  // order, session_id present, event == "posture".
  const std::string frame_mode_ack =
      "{\"event\":\"posture\""
      ",\"session_id\":\"0123456789abcdef0123456789abcdef\""
      ",\"posture\":\"bootstrap\",\"promotion_ready\":false"
      ",\"gate_state\":\"handshaking\",\"rx_packets\":0,\"rx_offered\":0"
      ",\"inner_mtu\":1359,\"message_size\":1388,\"inner_ipv6\":false"
      ",\"plan\":[\"udp\",\"tcp\",\"tls\"]}";
  const EngineStatus ack = Parsed(frame_mode_ack);
  Check(ack.valid, "the frame mode's own CreateAck parses");
  Check(ack.event == "posture", "the event is read");
  Check(ack.posture == "bootstrap",
        "the POSTURE is read from the key and not from the identical string "
        "sitting in the event's value");
  Check(ack.gate_state == "handshaking", "gate_state is unaffected");
  Check(ack.inner_mtu == 1359, "inner_mtu is unaffected");

  // The same collision one layer along: a value inside an array must not be
  // mistaken for a key either.
  const std::string plan_collision =
      "{\"event\":\"carrying\",\"plan\":[\"udp\",\"posture\"]"
      ",\"posture\":\"promoted\",\"promotion_ready\":true"
      ",\"gate_state\":\"carrying\",\"rx_packets\":3,\"inner_mtu\":1359}";
  const EngineStatus collided = Parsed(plan_collision);
  Check(collided.posture == "promoted",
        "an array element that happens to spell a key name is not a key");
  Check(collided.rx_packets == 3, "and the counters still read correctly");

  // A key that only APPEARS as a value must read as absent rather than as
  // whatever follows it. `promotion_ready` is the one that matters: absent
  // means the document is refused outright, which is the bootstrap posture.
  const std::string no_readiness =
      "{\"event\":\"promotion_ready\",\"gate_state\":\"carrying\"}";
  EngineStatus phantom;
  Check(!ParseWinn3StatusLine(no_readiness, &phantom),
        "a document whose only `promotion_ready` is a VALUE is refused, not "
        "read as ready");
}

void TestAnUnreadableStatusLineIsNotPromotionReady() {
  const char* rubbish[] = {
      "",
      "not json at all",
      "{\"event\":\"posture\"}",  // no promotion_ready: a version mismatch
      "{\"promotion_ready\":true}",             // no event
      "{\"event\":\"posture\",\"promotion_ready\":\"true\"}",  // string, not bool
      "{\"event\":\"posture\",\"promotion_ready\":1}",         // number, not bool
  };
  for (const char* line : rubbish) {
    EngineStatus status;
    const bool parsed = ParseWinn3StatusLine(line, &status);
    Check(!parsed, std::string("refused to parse: ") + line);
    Check(!status.valid, std::string("left invalid: ") + line);
    Check(!status.promotion_ready,
          std::string("not promotion-ready: ") + line);
  }
}

void TestTheBootstrapPostureIsNarrow() {
  PosturePlan plan;
  std::string error;
  const bool built = BuildBootstrapPosture(
      SampleInput(), Parsed(StatusLine(false, "handshaking", 0, false)), &plan,
      &error);
  Check(built, "the bootstrap posture builds: " + error);
  Check(VerifyBootstrapIsNarrow(plan, &error),
        "the bootstrap posture verifies as narrow: " + error);

  Check(plan.posture == Posture::kBootstrap, "it is the bootstrap posture");
  Check(plan.inner_v4 == "10.64.0.2", "it carries the assigned address");
  Check(plan.prefix_v4 == 32, "the prefix is /32");
  Check(plan.mtu == 1190, "the MTU is exactly the engine's inner MTU");
  Check(!plan.default_route, "there is no default route");
  Check(!plan.ipv6, "there is no IPv6");
  Check(plan.dns_servers.empty(), "there is no resolver");
  Check(plan.included_routes.size() == 1,
        "there is exactly one included route");
  Check(plan.included_routes.front() == "10.64.0.1/32",
        "and it is the inner next hop");
  Check(plan.outer_socket_exclusion == "fwmark 0x1f4 lookup 51820",
        "the outer-socket exclusion is present in the FIRST posture");
}

void TestTheBootstrapPostureRefusesRatherThanWidening() {
  PosturePlan plan;
  std::string error;
  const EngineStatus status = Parsed(StatusLine(false, "handshaking", 0, false));

  PostureInput no_exclusion = SampleInput();
  no_exclusion.outer_socket_exclusion = "   ";
  Check(!BuildBootstrapPosture(no_exclusion, status, &plan, &error),
        "a bootstrap with no outer-socket exclusion is refused");

  PostureInput no_address = SampleInput();
  no_address.inner_v4.clear();
  no_address.inner_v6.clear();
  Check(!BuildBootstrapPosture(no_address, status, &plan, &error),
        "a bootstrap with no inner address is refused");

  EngineStatus unparsed;
  Check(!BuildBootstrapPosture(SampleInput(), unparsed, &plan, &error),
        "a bootstrap with no engine status is refused");

  EngineStatus zero_mtu = status;
  zero_mtu.inner_mtu = 0;
  Check(!BuildBootstrapPosture(SampleInput(), zero_mtu, &plan, &error),
        "a bootstrap with no inner MTU is refused");
}

// THE TEST THIS FILE EXISTS FOR.
void TestACarryingGateAloneDoesNotPromote() {
  PosturePlan plan;
  std::string error;

  // The gate is carrying and the engine says so, but no inner packet has
  // reached the host device. Nothing may widen.
  EngineStatus carrying_but_empty =
      Parsed(StatusLine(false, "carrying", 0, false));
  Check(carrying_but_empty.valid, "the fixture line parses");
  Check(carrying_but_empty.gate_state == "carrying", "the gate is carrying");
  Check(!BuildPromotedPosture(SampleInput(), carrying_but_empty, &plan, &error),
        "a carrying gate with zero delivered packets does NOT promote");
  Check(error.find("no inner packet") != std::string::npos,
        "and the refusal says which half is missing: " + error);

  // A handshaking gate names the other half.
  EngineStatus handshaking = Parsed(StatusLine(false, "handshaking", 0, false));
  Check(!BuildPromotedPosture(SampleInput(), handshaking, &plan, &error),
        "a handshaking gate does not promote");
  Check(error.find("handshaking") != std::string::npos,
        "and the refusal names the gate state: " + error);

  // A document that claims ready with zero deliveries disagrees with itself.
  EngineStatus inconsistent = Parsed(StatusLine(true, "carrying", 0, false));
  Check(!BuildPromotedPosture(SampleInput(), inconsistent, &plan, &error),
        "a self-contradicting status document does not promote");

  // A document carrying a refusal does not promote whatever else it says.
  EngineStatus refused = Parsed(StatusLine(true, "carrying", 9, false));
  refused.refusal = "carrier read failed";
  Check(!BuildPromotedPosture(SampleInput(), refused, &plan, &error),
        "a status document carrying a refusal does not promote");
}

void TestPromotionWidensOnlyWhenProven() {
  PosturePlan plan;
  std::string error;
  const EngineStatus proven = Parsed(StatusLine(true, "carrying", 7, false));
  Check(BuildPromotedPosture(SampleInput(), proven, &plan, &error),
        "a proven datapath promotes: " + error);
  Check(plan.posture == Posture::kPromoted, "it is the promoted posture");
  Check(plan.default_route, "the default route is installed");
  // ONE, not two, and the change is the fix rather than a regression.
  //
  // SampleInput's route set is {0.0.0.0/1, 128.0.0.0/1} -- the natural way to
  // hand-write a full tunnel, and exactly what `default_route` already renders.
  // Until 2026-08-09 the builder ASSIGNED that set over the bootstrap's, which
  // did two things at once: it discarded the inner next hop the bootstrap had
  // installed, and it made both renderers emit `route add 0.0.0.0/1` twice,
  // where the second fails EEXIST and turns a correct promotion into an error.
  //
  // The set is now a union that drops what the default route already renders,
  // so what survives is the one route the host would otherwise have lost.
  Check(plan.included_routes.size() == 1,
        "the promoted route set keeps the bootstrap's next hop and does not "
        "restate the /1 pair the default route already renders");
  Check(plan.included_routes.front() == "10.64.0.1/32",
        "and it is the inner next hop");
  Check(plan.dns_servers.size() == 1, "the resolver is installed");
  Check(plan.mtu == 1190, "the MTU is unchanged by promotion");
  Check(plan.prefix_v4 == 32,
        "the inner prefix is unchanged by promotion: the tun layer validates "
        "against the address, not the prefix");
  Check(plan.outer_socket_exclusion == "fwmark 0x1f4 lookup 51820",
        "the outer-socket exclusion survives promotion");
  // WHY IPv6 IS ABSENT HERE CHANGED ON 2026-08-10, AND THE OLD REASON WAS THIS
  // MESSAGE. It used to read "IPv6 stays absent when the assignment has no v6
  // address", which was true of the code and is no longer: a promotion with no
  // inner IPv6 now installs the fail-closed SINK instead, because leaving host
  // IPv6 on the physical interface beside a promoted IPv4 tunnel is a leak.
  // What keeps IPv6 absent in THIS case is StatusLine's inner_mtu of 1190,
  // which is below RFC 8200's 1280-byte floor, so the kernel would refuse the
  // sink address. See TestTheSinkIsRefusedBelowTheIPv6LinkFloorAndTheReason...
  Check(!plan.ipv6,
        "IPv6 stays absent at an inner MTU of 1190: it is below the 1280-byte "
        "link floor, so neither an inner address nor the sink is installable");
}

void TestPromotionRefusesUndeclaredResolvers() {
  PosturePlan plan;
  std::string error;
  PostureInput undeclared = SampleInput();
  undeclared.dns_servers_are_inner = false;
  Check(!BuildPromotedPosture(undeclared, Parsed(StatusLine(true, "carrying", 3,
                                                            false)),
                              &plan, &error),
        "resolvers the host has not declared to be inner are refused");

  // ===========================================================================
  // THE ASSERTION THAT USED TO BE HERE WAS THE DEFECT
  // ===========================================================================
  //
  // This test read, verbatim, until 2026-08-09:
  //
  //     Check(BuildPromotedPosture(none, ..., &plan, &error),
  //           "a promotion with no resolvers at all is fine: " + error);
  //     Check(plan.dns_servers.empty(), "and installs none");
  //
  // It was not fine and the test was pinning the leak shut. `default_route` is
  // true for every promoted posture, so a promotion that installs no resolver
  // widens the ROUTES onto the tunnel and leaves NAME RESOLUTION where it was:
  // pointed at whatever the network handed out, which on the connections these
  // users have is the CPE the censor can read and rewrite. The /1 pair does not
  // capture it, because the physical link's own connected /24 is more specific
  // than /1.
  //
  // The symptom is the worst kind: nothing is broken. Pages load, the tunnel
  // reports carrying, the gate reports success -- and every hostname the user
  // visits is handed to the network they installed this to hide from.
  //
  // It became reachable the moment a SERVED `[winn]` section was allowed to
  // start a desktop session, because that section carries no `dns` key at all.
  // Before that, only a hand-written `[winn3]` document could reach it, and
  // whoever hand-wrote one had at least seen the field.
  PostureInput none = SampleInput();
  none.dns_servers.clear();
  none.dns_servers_are_inner = false;
  Check(!BuildPromotedPosture(none, Parsed(StatusLine(true, "carrying", 3,
                                                      false)),
                              &plan, &error),
        "a promotion that would install NO resolver is refused");
  Check(error.find("in the clear") != std::string::npos,
        "and the refusal names what leaves in the clear (got: " + error + ")");
  Check(error.find("default route") != std::string::npos,
        "and names the widening that makes it a leak rather than a stall");

  // Declared inner but still empty is the same refusal: the declaration is
  // about the resolvers that exist, and there is nothing for it to be about.
  PostureInput declared_but_empty = SampleInput();
  declared_but_empty.dns_servers.clear();
  declared_but_empty.dns_servers_are_inner = true;
  Check(!BuildPromotedPosture(declared_but_empty,
                              Parsed(StatusLine(true, "carrying", 3, false)),
                              &plan, &error),
        "declaring an empty resolver set inner does not make it a resolver "
        "set: the flag is not a substitute for the thing it describes");
}

// ===========================================================================
// THE DERIVED HALF OF DNS-AT-PROMOTION -- `namespace resolvers`
// ===========================================================================
//
// Everything above this comment exercises the DECLARED path: a hand-written
// `[winn3]` document whose `dns` and `dns_are_inner` lines were written by
// somebody holding the machine. The tests below exercise the other path, the
// one a SERVED `[winn]` descriptor takes when it names an inner resolver, and
// which decides inner-ness by address shape instead of by a boolean.
//
// WHY IT NEEDED ITS OWN TESTS. The derivation is a mirror of Apple's
// `WinsWinn3Resolvers` and Android's `WinnV3Resolvers` rather than an
// independent implementation, and the value of a mirror is entirely in its
// staying one. Three families reading ONE signed descriptor must not disagree
// about where a session resolves names; the family that guessed wider leaks,
// silently, because pages still load either way. So these tests pin the mask,
// the clause ORDER, and the replace-not-join rule -- the three things a
// well-meaning edit to any one platform would change first.

// Mentions is the `find(...) != npos` this file already spells inline, named
// once so the clause-order checks below read as what they assert rather than
// as string arithmetic.
bool Mentions(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

// THE /24 FLOOR, AND THAT IT IS THE SAME FLOOR ON ALL THREE FAMILIES.
//
// Confirmed by reading the other two declarations on 2026-08-12, cited by
// SYMBOL because line citations in this tree have drifted +36 to +129:
//
//   Apple    `enum WinsWinn3Resolvers` ->
//            `static func sameInnerBlock(_ a: UInt32, _ b: UInt32) -> Bool`
//            in apple/WinsTunnelCore/WinsWinn3SessionStart.swift, spelled
//            `(a & 0xFFFF_FF00) == (b & 0xFFFF_FF00)`.
//   Android  `internal object WinnV3Resolvers` ->
//            `fun sameInnerBlock(a: Long, b: Long): Boolean` in
//            android/.../WinnV3Posture.kt, spelled
//            `(a and 0xFFFFFF00L) == (b and 0xFFFFFF00L)`.
//
// Both inline the literal; only this header names it. A C++ program cannot
// read a .swift or a .kt file, so what this test can do is pin THIS side hard
// enough that a drift shows up here as a failure rather than as a difference
// nobody looks for. The boundary checks below fail for any other prefix: a /16
// makes the second pair same-block, a /28 makes the third pair different.
void TestTheInnerBlockFloorIsTheOneAppleAndAndroidUse() {
  Check(resolvers::kInnerBlockMask == 0xFFFFFF00u,
        "kInnerBlockMask is 0xFFFFFF00, the constant Apple spells 0xFFFF_FF00 "
        "and Android spells 0xFFFFFF00L");

  const uint32_t base = 0x0A400000u;  // 10.64.0.0
  Check(resolvers::SameInnerBlock(base, base + 255),
        "10.64.0.0 and 10.64.0.255 are one /24");
  Check(!resolvers::SameInnerBlock(base + 255, base + 256),
        "10.64.0.255 and 10.64.1.0 are NOT: the block ends at the third octet");
  Check(!resolvers::SameInnerBlock(base + 2, base + 257),
        "10.64.0.2 and 10.64.1.1 are different blocks -- a /16 floor would "
        "call them one and would accept another session's resolver");
  Check(resolvers::SameInnerBlock(base + 2, base + 200),
        "10.64.0.2 and 10.64.0.200 are one block -- a /28 floor would call "
        "them different and would refuse the operator's own resolver");
  Check(resolvers::SameInnerBlock(0xFFFFFFFFu, 0xFFFFFF00u),
        "the mask is applied rather than the values compared, at the top of "
        "the space where a signed shift would show");
}

// THE CLAUSE ORDER, ONE CASE PER CLAUSE, AND EVERY CASE BUILT TO BREAK ON A
// REORDER.
//
// A test that feeds each clause an input only that clause can refuse proves
// the clause exists and proves nothing about where it sits. So each case below
// feeds an input that satisfies its clause AND a LATER one, then asserts the
// earlier message is the one that comes back and the later message is not.
// Moving any clause past its neighbour turns one of these red.
//
// The order is load-bearing rather than cosmetic because the message is the
// whole product: an operator reads it and changes something. "Your resolver is
// outside the /24" invites widening the pool, and widening a pool never makes
// 8.8.8.8 inner. The clause order is Apple's and Android's, and it puts the
// most specific -- most actionable -- fact first.
void TestNotInnerReasonKeepsAppleAndAndroidsClauseOrder() {
  // --- clause 1: empty -----------------------------------------------------
  // An empty string ALSO fails clause 2, because Ipv4Value("") is false. This
  // pins 1 ahead of 2 rather than merely observing that blank is refused.
  const PostureInput sample = SampleInput();
  const std::string empty_reason = resolvers::NotInnerReason("", sample);
  Check(empty_reason == "it is empty",
        "clause 1: an empty resolver is refused as empty (got: " +
            empty_reason + ")");
  Check(!Mentions(empty_reason, "not an IPv4 literal"),
        "clause 1 sits AHEAD of clause 2: a blank field is diagnosed as blank, "
        "not as a hostname the host would have to resolve");
  Check(resolvers::NotInnerReason("   \t ", sample) == "it is empty",
        "and whitespace-only trims into the same clause rather than falling "
        "through to the literal check");

  // --- clause 2: not an IPv4 literal ---------------------------------------
  // The assignment here is ALSO unparseable, which is clause 4, so this pins
  // 2 ahead of 4. A hostname resolver is the more urgent fact: it is a lookup
  // outside the tunnel, which is the thing this layer exists to prevent.
  PostureInput no_assignment = SampleInput();
  no_assignment.inner_v4 = "not-an-address";
  const std::string hostname_reason =
      resolvers::NotInnerReason("dns.google", no_assignment);
  Check(Mentions(hostname_reason, "dns.google is not an IPv4 literal"),
        "clause 2: a hostname is refused as a hostname (got: " +
            hostname_reason + ")");
  Check(!Mentions(hostname_reason, "carries no IPv4 literal to derive"),
        "clause 2 sits AHEAD of clause 4: an unresolvable resolver outranks an "
        "unparseable assignment");
  Check(!resolvers::NotInnerReason("10.64.0.300", sample).empty(),
        "and the parser is strict about the octet ceiling");
  Check(!resolvers::NotInnerReason("10.64.0", sample).empty(),
        "and about the part count");

  // --- clause 3, refusing half: the inner next hop --------------------------
  // The next hop here sits OUTSIDE the /24 around the assignment, which is
  // clause 7, so this pins 3 ahead of 7. It is not a contrived shape: a hub
  // whose pool is wider than a /24 puts the gateway outside each client's
  // block, and telling that operator "outside the /24" sends them to fix the
  // pool geometry when what they need is a gateway running `-resolver`.
  PostureInput wide_pool = SampleInput();
  wide_pool.inner_v4 = "10.64.0.2";
  wide_pool.router_v4 = "10.64.1.1";
  wide_pool.inner_resolver_v4.clear();
  const std::string router_reason =
      resolvers::NotInnerReason("10.64.1.1", wide_pool);
  Check(Mentions(router_reason, "is [winn] inner_router_v4"),
        "clause 3: the next hop is refused as the next hop (got: " +
            router_reason + ")");
  Check(!Mentions(router_reason, "outside the /24"),
        "clause 3 sits AHEAD of clause 7: the actionable half of the "
        "diagnostic wins over the geometric one");
  Check(Mentions(router_reason, "inner_resolver_v4 = \"\""),
        "and the refusal quotes the empty descriptor field, which is the fact "
        "that makes it a refusal rather than an acceptance");

  // --- clause 3, accepting half: the descriptor names a resolver there ------
  // This is the whole reason the clause narrowed. `cmd/winn3-gateway
  // -resolver` answers at the gateway's own inner address, which IS the
  // client's next hop, because winn3/tun's outbound validator requires a
  // reply's source to equal the endpoint's own assignment. "The resolver is
  // the next hop" is the only shape the protocol permits.
  PostureInput advertised = SampleInput();
  advertised.inner_resolver_v4 = "10.64.0.1";
  Check(resolvers::NotInnerReason("10.64.0.1", advertised).empty(),
        "clause 3 ACCEPTS the next hop when the signed descriptor names a "
        "resolver there (got: " +
            resolvers::NotInnerReason("10.64.0.1", advertised) + ")");

  PostureInput padded = SampleInput();
  padded.inner_resolver_v4 = "10.64.000.1";
  Check(resolvers::NotInnerReason("10.64.0.1", padded).empty(),
        "and the match is over PARSED VALUES: 10.64.000.1 and 10.64.0.1 are "
        "one address, and a string compare would refuse the operator's own "
        "signed resolver while quoting a value that looks identical to it");

  PostureInput elsewhere = SampleInput();
  elsewhere.inner_resolver_v4 = "10.64.0.9";
  Check(Mentions(resolvers::NotInnerReason("10.64.0.1", elsewhere),
                 "is [winn] inner_router_v4"),
        "-- and a descriptor naming some OTHER inner resolver does not unlock "
        "the next hop: the acceptance is about THAT address, not about the "
        "field being populated");

  // --- clause 4: no assignment to derive an inner space from ---------------
  // The resolver here is a PUBLIC literal, which is clause 6, so this pins 4
  // ahead of 6.
  PostureInput unparseable = SampleInput();
  unparseable.inner_v4 = "";
  const std::string assignment_reason =
      resolvers::NotInnerReason("9.9.9.9", unparseable);
  Check(Mentions(assignment_reason,
                 "carries no IPv4 literal to derive an inner space from"),
        "clause 4: an unparseable [winn] inner_v4 is its own refusal (got: " +
            assignment_reason + ")");
  Check(!Mentions(assignment_reason, "PUBLIC resolver"),
        "clause 4 sits AHEAD of clause 6: with no assignment there is no inner "
        "space, and every judgement that depends on one is unavailable rather "
        "than merely unfavourable");

  // --- clause 5: this device's own assignment -------------------------------
  // The assignment here is itself a public literal, so the value satisfies
  // clause 6 too, and this pins 5 ahead of 6. "That address is this machine,
  // nothing answers there" is the fact the operator can act on.
  PostureInput public_assignment = SampleInput();
  public_assignment.inner_v4 = "203.0.113.5";
  public_assignment.router_v4 = "203.0.113.1";
  const std::string own_reason =
      resolvers::NotInnerReason("203.0.113.5", public_assignment);
  Check(Mentions(own_reason, "is this session's own [winn] inner_v4 assignment"),
        "clause 5: the device's own address is refused as its own (got: " +
            own_reason + ")");
  Check(!Mentions(own_reason, "PUBLIC resolver"),
        "clause 5 sits AHEAD of clause 6");
  Check(Mentions(resolvers::NotInnerReason("10.64.0.2", sample),
                 "is this session's own [winn] inner_v4 assignment"),
        "and the ordinary inner assignment takes the same clause");

  // --- clause 6: a public literal ------------------------------------------
  // 8.8.8.8 is also outside the /24 around 10.64.0.2, which is clause 7, so
  // this pins 6 ahead of 7.
  const std::string public_reason =
      resolvers::NotInnerReason("8.8.8.8", sample);
  Check(Mentions(public_reason, "is a PUBLIC resolver"),
        "clause 6: a public resolver is refused as public (got: " +
            public_reason + ")");
  Check(!Mentions(public_reason, "outside the /24"),
        "clause 6 sits AHEAD of clause 7: 'outside your pool' reads as a "
        "geometry problem an operator might answer by widening the pool, and "
        "widening a pool never makes 8.8.8.8 inner");
  Check(Mentions(resolvers::NotInnerReason("1.1.1.1", sample),
                 "is a PUBLIC resolver"),
        "and the other literal that actually ships takes the same clause");

  // --- clause 7: outside the /24 -------------------------------------------
  // It is the LAST clause, so what a test can pin is that it is REACHED: every
  // earlier clause has to decline this value for the block comparison to be
  // the one that answers. 10.65.0.1 is private, is not this device, and is not
  // the next hop -- it is simply in another session's inner space.
  const std::string outside_reason =
      resolvers::NotInnerReason("10.65.0.1", sample);
  Check(Mentions(outside_reason,
                 "is outside the /24 around this session's [winn] inner_v4 "
                 "assignment"),
        "clause 7: another session's inner space is refused as out-of-block "
        "(got: " + outside_reason + ")");
  Check(Mentions(outside_reason, "(10.64.0.2)"),
        "and the refusal quotes the assignment the /24 was taken around");
  Check(!Mentions(outside_reason, "PUBLIC"),
        "a 10/8 literal is never diagnosed as public: clause 6 declined it, "
        "which is what let clause 7 answer");

  // The boundary is a boundary rather than a blanket refusal.
  Check(resolvers::NotInnerReason("10.64.0.9", sample).empty(),
        "a second inner address in the assignment's own /24 is derivable");
  Check(resolvers::NotInnerReason("10.64.0.254", sample).empty(),
        "and so is the far end of that block");
  Check(!resolvers::NotInnerReason("10.64.1.0", sample).empty(),
        "and the one address past it is not");
}

// CANDIDATES REPLACES THE HOST LIST. IT DOES NOT JOIN IT, AND IT DOES NOT
// FILTER THE JOIN DOWN TO ITS ACCEPTABLE MEMBERS.
//
// The assertion that matters is the SIZE and the ABSENCE, not the presence: a
// test that checked only that the signed resolver is in the result would pass
// on a join, and a join is the leak. `resolvectl dns`, `resolvconf -a`, an
// /etc/resolv.conf body and `netsh ... set dnsservers` all hand the WHOLE list
// to the system, and the system -- not this header -- picks which entry
// answers. A public resolver sitting second answers whenever the first is slow.
void TestCandidatesReplaceTheHostListRatherThanJoiningIt() {
  PostureInput served = SampleInput();
  served.dns_servers = {"10.64.0.9", "9.9.9.9"};
  served.dns_servers_are_inner = true;
  served.inner_resolver_v4 = "10.64.0.1";

  const std::vector<std::string> candidates = resolvers::Candidates(served);
  Check(candidates.size() == 1,
        "the signed resolver REPLACES the host list: exactly one candidate, "
        "got " + std::to_string(candidates.size()) +
            " (a join would give 3, a filtered join 2)");
  Check(!candidates.empty() && candidates[0] == "10.64.0.1",
        "and it is the descriptor's value");
  for (const std::string& entry : candidates) {
    Check(entry != "9.9.9.9",
          "the host's PUBLIC resolver is not a candidate -- this is the entry "
          "a join would carry into an installer that hands the whole list to "
          "the system");
    Check(entry != "10.64.0.9",
          "and neither is the host's INNER one: replacement is total, not a "
          "join filtered down to its derivable members. This is the check "
          "that separates replace from filter, because 10.64.0.9 would "
          "survive a filter -- it is in the assignment's own /24");
  }

  const std::vector<std::string> derived = resolvers::Inner(served);
  Check(derived.size() == 1 && !derived.empty() && derived[0] == "10.64.0.1",
        "Inner() sees the replacement too, rather than re-reading dns_servers");
  Check(resolvers::AreInner(served),
        "and the whole-list judgement is over the replaced list: a public "
        "entry the host still holds does not poison it");

  // An EMPTY descriptor field returns exactly the host's own list, which is
  // this header's behaviour from before the field existed.
  PostureInput declared = SampleInput();
  declared.dns_servers = {"10.64.0.9", "  9.9.9.9  "};
  declared.inner_resolver_v4.clear();
  const std::vector<std::string> host_list = resolvers::Candidates(declared);
  Check(host_list.size() == 2,
        "an empty inner_resolver_v4 returns the host's own list untouched, got "
        + std::to_string(host_list.size()));
  Check(host_list.size() == 2 && host_list[0] == "10.64.0.9" &&
            host_list[1] == "9.9.9.9",
        "in the host's own order, trimmed but not otherwise judged");

  // Blank entries are dropped rather than carried as empty strings, on the
  // declared side only -- there is nothing to drop on the other.
  PostureInput ragged = SampleInput();
  ragged.dns_servers = {"10.64.0.9", "   ", ""};
  ragged.inner_resolver_v4.clear();
  Check(resolvers::Candidates(ragged).size() == 1,
        "and a ragged host list contributes only its real entries");
}

// THE DECLARED PATH IS EXACTLY WHAT IT WAS. THE DERIVATION DID NOT LEAK INTO IT.
//
// Every descriptor signed to date carries no `inner_resolver_v4`, so this is
// the path every existing configuration still takes, and "unchanged" has to
// mean unchanged for inputs the derivation would REFUSE -- otherwise the two
// paths are indistinguishable and the test proves nothing. Both cases below
// are chosen for that: each promotes on the declared path and each would be
// refused if the derivation ran unconditionally.
void TestTheDeclaredPathIsUntouchedByTheDerivation() {
  const EngineStatus carrying = Parsed(StatusLine(true, "carrying", 3, false));
  PosturePlan plan;
  std::string error;

  // SampleInput() is the shape a signed descriptor produces today, and its
  // `dns_servers` names the inner NEXT HOP -- which the derivation refuses
  // outright under clause 3.
  const PostureInput declared = SampleInput();
  Check(declared.inner_resolver_v4.empty(),
        "the sample input carries no inner_resolver_v4, which is the shape "
        "every descriptor signed to date has");
  Check(BuildPromotedPosture(declared, carrying, &plan, &error),
        "a configuration with no inner_resolver_v4 promotes on the declared "
        "path: " + error);
  Check(plan.dns_servers.size() == 1 && !plan.dns_servers.empty() &&
            plan.dns_servers[0] == "10.64.0.1",
        "and installs the host's declared list verbatim");
  Check(!resolvers::NotInnerReason("10.64.0.1", declared).empty(),
        "-- and the DERIVATION would refuse that very resolver, which is what "
        "makes the promotion above a guard rather than a coincidence");

  // A hand-written [winn3] document whose resolver the derivation could never
  // accept: a public literal, declared inner by the person holding the machine.
  // This header cannot derive an inner space for a local document -- its
  // resolvers need not sit in the assignment's /24 at all -- so the
  // declaration is the only evidence there is, and it still governs here.
  PostureInput hand_written = SampleInput();
  hand_written.dns_servers = {"9.9.9.9"};
  hand_written.dns_servers_are_inner = true;
  Check(BuildPromotedPosture(hand_written, carrying, &plan, &error),
        "a hand-written document's declared resolver promotes even where the "
        "derivation could not: " + error);
  Check(plan.dns_servers.size() == 1 && !plan.dns_servers.empty() &&
            plan.dns_servers[0] == "9.9.9.9",
        "and it is installed exactly as declared, in the host's order");
  Check(!resolvers::AreInner(hand_written) ||
            !hand_written.inner_resolver_v4.empty(),
        "-- while AreInner, which is the derived judgement, does NOT agree "
        "with that declaration");

  // The declared path's two refusals are untouched as well.
  PostureInput undeclared = SampleInput();
  undeclared.dns_servers_are_inner = false;
  Check(!BuildPromotedPosture(undeclared, carrying, &plan, &error),
        "the declared path still refuses an undeclared list");
  PostureInput empty_list = SampleInput();
  empty_list.dns_servers.clear();
  Check(!BuildPromotedPosture(empty_list, carrying, &plan, &error),
        "and still refuses an empty one");
}

// THE DERIVED PATH PROMOTES A SERVED SESSION THAT CARRIES NO `dns` KEY AT ALL.
//
// A served `[winn]` section has no `dns` line and no `dns_are_inner` line --
// there is nothing on the wire for either -- so `dns_servers` is empty and
// `dns_servers_are_inner` is false. Before the descriptor could name a
// resolver, that input was a refusal, and the refusal was RIGHT: there was no
// resolver to install and promoting would have widened the routes while
// leaving name resolution on the physical interface. It is now a promotion,
// and what changed is that there is evidence, not that the bar moved.
void TestTheDerivedPathPromotesAServedSessionWithNoDnsKey() {
  const EngineStatus carrying = Parsed(StatusLine(true, "carrying", 3, false));
  PosturePlan plan;
  std::string error;

  PostureInput served = SampleInput();
  served.dns_servers.clear();
  served.dns_servers_are_inner = false;
  served.inner_resolver_v4 = "10.64.0.1";

  Check(served.dns_servers.empty() && !served.dns_servers_are_inner,
        "the served shape has neither a dns key nor a dns_are_inner key");
  Check(BuildPromotedPosture(served, carrying, &plan, &error),
        "a served session with no dns key at all promotes on the descriptor's "
        "own resolver: " + error);
  Check(plan.dns_servers.size() == 1 && !plan.dns_servers.empty() &&
            plan.dns_servers[0] == "10.64.0.1",
        "and installs exactly the signed resolver, nothing beside it");
  Check(plan.posture == Posture::kPromoted && plan.default_route,
        "and it is a real promotion: default route on, resolvers moved with it");
  Check(resolvers::AreInner(served),
        "AreInner derives true for that input with the boolean left false, "
        "which is the entire point of the derived path");

  // The same shape with the responder at a second inner address rather than at
  // the next hop. It is refused by winn3/tun in the field -- a reply's source
  // must equal the endpoint's own assignment -- but the DERIVATION accepts it,
  // and that split is deliberate: this layer refuses what it cannot derive,
  // and does not attempt to model the datapath's own validator.
  PostureInput second_address = served;
  second_address.inner_resolver_v4 = "10.64.0.9";
  Check(BuildPromotedPosture(second_address, carrying, &plan, &error),
        "a signed resolver at a second address in the assignment's /24 also "
        "promotes: " + error);
  Check(plan.dns_servers.size() == 1 && !plan.dns_servers.empty() &&
            plan.dns_servers[0] == "10.64.0.9",
        "and that is the value installed");

  // A signed resolver the derivation cannot justify is a refusal even with the
  // host holding no opinion at all.
  PostureInput outside = served;
  outside.inner_resolver_v4 = "10.65.0.1";
  Check(!BuildPromotedPosture(outside, carrying, &plan, &error),
        "a signed resolver in another session's inner space is refused");
  Check(Mentions(error, "outside the /24"),
        "and the refusal names the block, not the missing dns key: " + error);
  Check(Mentions(error, "refusing to promote"),
        "and it is spelled as a promotion refusal");
}

// A HOST DECLARATION CANNOT RESCUE A SIGNED RESOLVER THAT FAILS DERIVATION.
//
// On a served session the only party who could set `dns_servers_are_inner` is
// the control plane, and a boolean on the wire asserting a resolver is inside
// the tunnel is the leak wearing a flag. So on the derived path that boolean
// is not consulted AT ALL -- not as evidence, not as a tie-breaker, not even
// when a local host sets it honestly. Deriving is strictly more evidence than
// the declaration asks for, never less, and a rescue would make it less.
//
// Each case below sets the boolean true and offers the failing value both as
// the descriptor's resolver and in the host's own list, which is the most
// generous shape a rescue could take. All four must still refuse.
void TestTheDeclarationCannotRescueAFailedDerivation() {
  const EngineStatus carrying = Parsed(StatusLine(true, "carrying", 3, false));
  PosturePlan plan;
  std::string error;

  PostureInput rescue = SampleInput();
  rescue.dns_servers_are_inner = true;

  // A public literal.
  PostureInput public_signed = rescue;
  public_signed.inner_resolver_v4 = "9.9.9.9";
  public_signed.dns_servers = {"9.9.9.9"};
  Check(!BuildPromotedPosture(public_signed, carrying, &plan, &error),
        "dns_servers_are_inner does not rescue a PUBLIC signed resolver");
  Check(Mentions(error, "is a PUBLIC resolver"),
        "and the refusal is on the derivation's ground rather than the "
        "declaration's: " + error);
  Check(plan.dns_servers.empty(),
        "and no resolver reaches the plan on a refusal");

  // Another session's inner space.
  PostureInput outside_signed = rescue;
  outside_signed.inner_resolver_v4 = "10.65.0.1";
  outside_signed.dns_servers = {"10.65.0.1"};
  Check(!BuildPromotedPosture(outside_signed, carrying, &plan, &error),
        "nor an out-of-block signed resolver");
  Check(Mentions(error, "outside the /24"), "and says so: " + error);

  // A hostname.
  PostureInput hostname_signed = rescue;
  hostname_signed.inner_resolver_v4 = "dns.google";
  hostname_signed.dns_servers = {"dns.google"};
  Check(!BuildPromotedPosture(hostname_signed, carrying, &plan, &error),
        "nor a signed resolver that is not a literal at all");
  Check(Mentions(error, "not an IPv4 literal"), "and says so: " + error);

  // The device's own assignment.
  PostureInput self_signed = rescue;
  self_signed.inner_resolver_v4 = "10.64.0.2";
  self_signed.dns_servers = {"10.64.0.2"};
  Check(!BuildPromotedPosture(self_signed, carrying, &plan, &error),
        "nor this device's own inner assignment");
  Check(Mentions(error, "which is this device; nothing answers there"),
        "and says so: " + error);

  // THE CONTRAST THAT MAKES THE FOUR ABOVE MEAN SOMETHING. The same public
  // value, the same true boolean, and the descriptor field EMPTY: that is the
  // declared path, where the boolean is the only evidence there is, and it
  // still governs. So the four refusals above are the derived path ignoring
  // the boolean, not the boolean having been broken for everybody.
  PostureInput declared_public = SampleInput();
  declared_public.dns_servers = {"9.9.9.9"};
  declared_public.dns_servers_are_inner = true;
  declared_public.inner_resolver_v4.clear();
  Check(BuildPromotedPosture(declared_public, carrying, &plan, &error),
        "the same public resolver, declared inner with no descriptor field, "
        "still promotes on the declared path: " + error);
  Check(plan.dns_servers.size() == 1 && !plan.dns_servers.empty() &&
            plan.dns_servers[0] == "9.9.9.9",
        "-- so the refusals above are the derived path declining to consult "
        "the boolean, not the boolean having stopped working");
}

// THE TEST THE ROUTE HALF OF THIS FILE EXISTS FOR.
//
// A promotion gate that reports success on a posture capturing nothing is worth
// less than no gate: no gate leaves an operator knowing the state is unproven,
// and a gate reporting success leaves them believing a proof happened.
void TestAPromotionThatWouldCaptureNothingIsRefused() {
  std::string error;

  // The plan-level predicate, over a posture assembled by hand so the check is
  // tested rather than the builder that cannot currently produce this shape.
  PosturePlan empty;
  empty.posture = Posture::kPromoted;
  empty.inner_v4 = "10.64.0.2";
  empty.prefix_v4 = 32;
  empty.mtu = 1190;
  empty.outer_socket_exclusion = "fwmark 0x1f4 lookup 51820";
  empty.default_route = false;
  Check(!VerifyPromotedPostureCaptures(empty, &error),
        "a promoted posture with no default route and no routes is refused");
  Check(error.find("capture nothing") != std::string::npos,
        "and says so: " + error);

  // A route set of nothing but HOST routes is the same posture wearing a
  // number. The inner next hop is a /32 and it is exactly what the bootstrap
  // already installed, so a promotion carrying only that has widened nothing.
  PosturePlan host_routes_only = empty;
  host_routes_only.included_routes = {"10.64.0.1/32", "10.64.0.9/32"};
  Check(!VerifyPromotedPostureCaptures(host_routes_only, &error),
        "a promoted posture whose only routes are /32s is refused");

  PosturePlan one_wide = host_routes_only;
  one_wide.included_routes.push_back("10.0.0.0/8");
  Check(VerifyPromotedPostureCaptures(one_wide, &error),
        "one route wider than a host is enough to capture: " + error);

  PosturePlan by_default = empty;
  by_default.default_route = true;
  Check(VerifyPromotedPostureCaptures(by_default, &error),
        "and the default route is enough on its own: " + error);

  // The ARGUMENT VECTORS, which is the object that actually moves traffic. The
  // plan carries ONE boolean for the /1 pair's TWO commands, so no plan-level
  // predicate can see a renderer that emitted one of them.
  using Argv = std::vector<std::string>;
  using Commands = std::vector<Argv>;
  const Argv address = {"ip", "-4", "address", "add", "10.64.0.2/32", "dev",
                        "winsvpn3"};
  const Argv mtu = {"ip", "link", "set", "dev", "winsvpn3", "mtu", "1190",
                    "up"};

  Commands nothing = {address, mtu};
  Check(!VerifyPromotedCommandsCapture(nothing, &error),
        "an address and an MTU on a device nothing routes to is not a "
        "promotion");
  Check(error.find("in the clear") != std::string::npos,
        "and the refusal names the consequence: " + error);

  Commands half = {address, mtu,
                   Argv{"ip", "route", "add", "0.0.0.0/1", "dev", "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(half, &error),
        "HALF the default pair is refused: 128.0.0.0/1 is half the address "
        "space and it would stay on the physical interface");
  Check(error.find("128.0.0.0/1") != std::string::npos,
        "and the refusal names the half that is missing: " + error);

  Commands other_half = {address, mtu, Argv{"ip", "route", "add",
                                            "128.0.0.0/1", "dev", "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(other_half, &error),
        "and so is the other half");
  Check(error.find("0.0.0.0/1") != std::string::npos,
        "naming the missing one either way: " + error);

  Commands pair = half;
  pair.push_back(Argv{"ip", "route", "add", "128.0.0.0/1", "dev", "winsvpn3"});
  Check(VerifyPromotedCommandsCapture(pair, &error),
        "the whole pair captures: " + error);

  // The IPv6 halves are the sink's capture mechanism, and the check treats
  // them the same way it treats the IPv4 pair -- a lone `::/1` is a valid
  // prefix and used to count as "captures traffic" on that alone, leaving
  // 8000::/1 -- the other half of the IPv6 address space -- on the physical
  // interface. Every net is a subnet boundary one /1 can land entirely on one
  // side of, so half of ::/0 is never a narrowing that happens to work out.
  Commands v6_one = {address, mtu,
                     Argv{"ip", "-6", "route", "add", "::/1", "dev",
                          "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(v6_one, &error),
        "HALF the IPv6 default pair is refused: 8000::/1 would stay on the "
        "physical path");
  Check(error.find("8000::/1") != std::string::npos,
        "and the refusal names the IPv6 half that is missing: " + error);

  Commands v6_other = {address, mtu,
                       Argv{"ip", "-6", "route", "add", "8000::/1", "dev",
                            "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(v6_other, &error),
        "and so is the other IPv6 half");
  Check(error.find("::/1") != std::string::npos,
        "naming the missing one either way: " + error);

  Commands v6_pair = v6_one;
  v6_pair.push_back(Argv{"ip", "-6", "route", "add", "8000::/1", "dev",
                         "winsvpn3"});
  Check(VerifyPromotedCommandsCapture(v6_pair, &error),
        "both IPv6 halves together capture: " + error);

  // A bare ::/0 accepted, and a lone IPv6 HALF accepted, while a lone IPv4
  // half was refused -- the two families must not drift. The IPv4 refusal is
  // asserted above; this asserts the sink /128 alone is NOT capture.
  Commands v6_sink_only = {address, mtu,
                           Argv{"ip", "-6", "address", "add",
                                "fd00:d951:1::2/128", "dev", "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(v6_sink_only, &error),
        "a /128 sink address with no v6 route is not a capture");

  // A host route in the argv is NOT evidence of capture, and neither is a
  // netsh token that merely contains a slash.
  Commands host_route = {address, mtu, Argv{"ip", "route", "add",
                                            "10.64.0.1/32", "dev",
                                            "winsvpn3"}};
  Check(!VerifyPromotedCommandsCapture(host_route, &error),
        "the bootstrap's own next-hop /32 does not count as capture");

  Commands windows_shaped = {
      Argv{"netsh", "interface", "ipv4", "set", "address", "name=WinsVPN3",
           "source=static", "address=10.64.0.2/32"},
      Argv{"netsh", "interface", "ipv4", "set", "subinterface", "WinsVPN3",
           "mtu=1190", "store=active"}};
  Check(!VerifyPromotedCommandsCapture(windows_shaped, &error),
        "`address=10.64.0.2/32` is an address command, not a captured prefix");
  windows_shaped.push_back(Argv{"netsh", "interface", "ipv4", "add", "route",
                                "0.0.0.0/1", "interface=WinsVPN3"});
  windows_shaped.push_back(Argv{"netsh", "interface", "ipv4", "add", "route",
                                "128.0.0.0/1", "interface=WinsVPN3"});
  Check(VerifyPromotedCommandsCapture(windows_shaped, &error),
        "and the Windows pair captures the same way: " + error);
}

// The route set a served section produces, which is the configuration this
// whole row is about: no `routes` key, no `dns` key, nothing to assign from.
void TestAServedRouteSetKeepsTheBootstrapsNextHop() {
  PosturePlan plan;
  std::string error;

  // What a served `[winn]` section fills in: the inner assignment and the
  // exclusion, and NOTHING for routes or resolvers.
  PostureInput served;
  served.inner_v4 = "10.10.4.9";
  served.router_v4 = "10.10.0.1";
  served.outer_socket_exclusion = "10.10.0.1 via 192.168.1.1 dev wlan0";
  Check(!BuildPromotedPosture(served, Parsed(StatusLine(true, "carrying", 6,
                                                        false)),
                              &plan, &error),
        "a served section promotes to nothing and is refused for the resolver "
        "it cannot name");

  // With the resolver question answered, the ROUTE half is what a standalone
  // session derives rather than what a server sends: the bootstrap's inner next
  // hop, kept, plus the /1 pair the default route renders.
  PostureInput derived = served;
  derived.dns_servers = {"10.10.0.1"};
  derived.dns_servers_are_inner = true;
  Check(BuildPromotedPosture(derived, Parsed(StatusLine(true, "carrying", 6,
                                                        false)),
                             &plan, &error),
        "and then promotes: " + error);
  Check(plan.included_routes.size() == 1,
        "the promoted route set is not empty even though nothing was served");
  Check(plan.included_routes.front() == "10.10.0.1/32",
        "it is the bootstrap's inner next hop, KEPT rather than overwritten -- "
        "the assignment that used to be here discarded it and left the plan "
        "describing a posture the machine did not have");
  Check(plan.default_route,
        "and capture comes from the /1 pair, which is derived and not served");

  // A host that DOES supply routes gets them, and the pair is not restated:
  // `routes = 0.0.0.0/1, 128.0.0.0/1` is the natural way to hand-write a full
  // tunnel, and a duplicate `ip route add` fails EEXIST.
  PostureInput supplied = derived;
  supplied.full_routes = {"0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8",
                          "10.0.0.0/8"};
  Check(BuildPromotedPosture(supplied, Parsed(StatusLine(true, "carrying", 6,
                                                         false)),
                             &plan, &error),
        "a supplied route set promotes: " + error);
  Check(plan.included_routes.size() == 2,
        "the /1 pair is not restated and the duplicate is dropped");
  Check(plan.included_routes[0] == "10.10.0.1/32" &&
            plan.included_routes[1] == "10.0.0.0/8",
        "the next hop leads and the supplied route follows");
  int emitted_low = 0;
  for (const auto& command : RenderLinuxPostureCommands("winsvpn3", plan)) {
    for (const auto& argument : command) {
      if (argument == "0.0.0.0/1") ++emitted_low;
    }
  }
  Check(emitted_low == 1,
        "and the renderer emits 0.0.0.0/1 exactly once, so the second add "
        "cannot fail EEXIST and turn a correct promotion into an error");
}

void TestPromotionRefusesIPv6TheFloorCannotCarry() {
  PosturePlan plan;
  std::string error;
  PostureInput dual = SampleInput();
  dual.inner_v6 = "fd00:64::2";
  dual.router_v6 = "fd00:64::1";

  Check(!BuildPromotedPosture(dual, Parsed(StatusLine(true, "carrying", 5,
                                                      false)),
                              &plan, &error),
        "IPv6 is refused when the plan floor cannot carry inner IPv6");
  Check(BuildPromotedPosture(dual, Parsed(StatusLine(true, "carrying", 5, true)),
                             &plan, &error),
        "IPv6 is installed when the floor can carry it: " + error);
  Check(plan.ipv6, "and the plan says so");
  Check(plan.prefix_v6 == 128, "at /128");
}

// ===========================================================================
// THE IPv6 SINK, AND WHY THESE ARE ASSERTIONS ABOUT COMMANDS
// ===========================================================================
//
// Until 2026-08-10 a promoted posture on these two hosts installed IPv4 only.
// `plan.ipv6` was false whenever the session carried no inner IPv6 of its own,
// which is every session the shipping gateway serves, so the promotion moved
// the user's IPv4 onto the tunnel and left their IPv6 address and IPv6 default
// route on the physical interface.
//
// MEASURED before these tests were written, by replaying the FIVE `ip`
// commands RenderLinuxPostureCommands then produced into a throwaway network
// namespace whose host held a global IPv6 address (Colima, 2026-08-10):
//
//                          route get 2001:db8:9::1   phy0 tx   tun tx
//   the shipped posture     dev phy0                  +6        +0
//   the same plus a sink    dev winn0                 +0        +5
//
// and the tunnel's own file descriptor saw 2001:db8:9::1 only in the second.
// IPv6 was enabled on the tun in BOTH arms -- `disable_ipv6` read 0 everywhere
// and the tun took a link-local of its own -- so the first row is a leak and
// not an absence of traffic.
//
// So these tests assert on the RENDERED ARGUMENT VECTORS as well as on the
// plan. A plan-level boolean is what was already true and insufficient: the
// old header set `plan.ipv6` correctly for the inner-IPv6 case and STILL
// rendered no IPv6 route for it, because `default_route` only ever emitted the
// IPv4 pair. Asserting `plan.ipv6` alone would have passed that.
void TestAPromotedPostureInstallsTheIPv6SinkWhenItIsLegal() {
  PosturePlan plan;
  std::string error;
  // inner_mtu 1309: the fleet default (path 1450) over the widest plan.
  EngineStatus wide = Parsed(StatusLine(true, "carrying", 6, false));
  wide.inner_mtu = 1309;

  Check(BuildPromotedPosture(SampleInput(), wide, &plan, &error),
        "a promotion with no inner IPv6 still builds: " + error);
  Check(plan.ipv6, "and it carries IPv6, because the sink is installed");
  Check(plan.ipv6_sink == "fd00:d951:1::2",
        "at the same address Apple and Android already sink to");
  Check(plan.prefix_v6 == 128, "as a /128, which routes nowhere");
  Check(plan.inner_v6.empty(),
        "and it is a SINK, not an inner address: the two are never both set");
  Check(plan.ipv6_absent_reason.empty(),
        "so there is no reason recorded for IPv6 being absent");

  const auto linux_commands = RenderLinuxPostureCommands("winsvpn3", plan);
  bool sink_address = false;
  bool low_half = false;
  bool high_half = false;
  bool whole_default = false;
  for (const auto& command : linux_commands) {
    for (const auto& argument : command) {
      if (argument == "fd00:d951:1::2/128") sink_address = true;
      if (argument == "::/1") low_half = true;
      if (argument == "8000::/1") high_half = true;
      if (argument == "::/0") whole_default = true;
    }
  }
  Check(sink_address, "the Linux renderer emits the sink address");
  Check(low_half && high_half,
        "and BOTH halves of the IPv6 default route -- half of them leaves half "
        "the address space on the physical interface while the plan, the "
        "status line and the user all read promoted");
  Check(!whole_default,
        "and never a bare ::/0, which lands at metric 1024 where the host's "
        "own default already is and returns EEXIST (measured 2026-08-10)");

  const auto windows_commands = RenderWindowsPostureCommands("WinsVPN3", plan);
  sink_address = false;
  low_half = false;
  high_half = false;
  for (const auto& command : windows_commands) {
    for (const auto& argument : command) {
      if (argument == "address=fd00:d951:1::2/128") sink_address = true;
      if (argument == "::/1") low_half = true;
      if (argument == "8000::/1") high_half = true;
    }
  }
  Check(sink_address, "the Windows renderer emits the sink address");
  Check(low_half && high_half, "and both halves of the IPv6 default route");
}

// On a live session the bootstrap is applied to the adapter FIRST, so its
// `add route <next-hop>` is already installed. A promoted posture is the
// bootstrap plus its widenings, so rendering it WHole re-issues that add, and
// the second `netsh ... add route 10.99.3.1/32` answers "The object already
// exists." with a non-zero exit. The Windows applier stops at the first failing
// command, so promotion would fail before the IPv6 sink or any default route
// moved -- the exact stall Linux closes by executing the promoted-vs-bootstrap
// delta. This test pins PromotedCommandDelta to that behaviour.
void TestPromotedCommandDeltaOmitsTheBootstrapNextHop() {
  EngineStatus wide = Parsed(StatusLine(true, "carrying", 6, false));
  wide.inner_mtu = 1309;

  PosturePlan bootstrap, promoted;
  std::string error;
  Check(BuildBootstrapPosture(SampleInput(), wide, &bootstrap, &error),
        "bootstrap builds for the delta test: " + error);
  Check(BuildPromotedPosture(SampleInput(), wide, &promoted, &error),
        "promoted builds for the delta test: " + error);

  const auto bootstrap_argv = RenderWindowsPostureCommands("WinsVPN3", bootstrap);
  const auto promoted_argv = RenderWindowsPostureCommands("WinsVPN3", promoted);
  const auto delta =
      PromotedCommandDelta(promoted_argv, bootstrap_argv);

  // The promoted delta must NOT re-issue the next-hop add (or the address or
  // MTU sets), because the bootstrap already applied them to the same adapter.
  bool delta_has_next_hop = false;
  bool delta_has_set_address = false;
  bool delta_has_set_mtu = false;
  for (const auto& argv : delta) {
    if (argv.size() == 6 && argv[0] == "netsh" &&
        argv[5] == "10.99.3.1/32") {
      delta_has_next_hop = true;
    }
    if (argv.size() >= 5 && argv[0] == "netsh" && argv[2] == "ipv4" &&
        argv[3] == "set" && argv[4] == "address") {
      delta_has_set_address = true;
    }
    if (argv.size() >= 4 && argv[0] == "netsh" && argv[3] == "subinterface") {
      delta_has_set_mtu = true;
    }
  }
  Check(!delta_has_next_hop,
        "the promoted delta omits the bootstrap next-hop route");
  Check(!delta_has_set_address,
        "and omits the bootstrap's repeated address set");
  Check(!delta_has_set_mtu, "and omits the bootstrap's repeated MTU set");

  // And the delta must still CARRY: the IPv4 /1 halves, the IPv6 sink and both
  // IPv6 defaults are widenings that only promotion emits, so all must be in
  // the delta, and capture must hold on it (not merely on the whole posture).
  bool low4 = false, high4 = false, sink = false, low6 = false, high6 = false;
  for (const auto& argv : delta) {
    for (const auto& token : argv) {
      if (token == "0.0.0.0/1") low4 = true;
      if (token == "128.0.0.0/1") high4 = true;
      if (token == "address=fd00:d951:1::2/128") sink = true;
      if (token == "::/1") low6 = true;
      if (token == "8000::/1") high6 = true;
    }
  }
  Check(low4 && high4, "the delta keeps both IPv4 default halves");
  Check(sink, "the delta keeps the IPv6 sink");
  Check(low6 && high6, "the delta keeps both IPv6 default halves");
  std::string capture_error;
  Check(VerifyPromotedCommandsCapture(delta, &capture_error),
        "the delta itself captures, so promotion applies a real widening: " +
            capture_error);

  // A straight re-apply of the WHOLE promoted set against an interface that
  // already ran the bootstrap is exactly what failed on winpc; show the delta
  // removes at least the observed collision term.
  bool collision_dropped = true;
  for (const auto& argv : promoted_argv) {
    bool is_next_hop_add =
        argv.size() == 6 && argv[0] == "netsh" && argv[5] == "10.99.3.1/32";
    if (is_next_hop_add) {
      bool in_delta = false;
      for (const auto& d : delta) {
        if (d == argv) in_delta = true;
      }
      collision_dropped = collision_dropped && !in_delta;
    }
  }
  Check(collision_dropped,
        "the specific 'add route <next-hop>' that returned 'object already "
        "exists' on winpc is dropped from the promoted delta");
}

// Below RFC 8200's floor NEITHER shape is available: an inner address is a
// black hole and the sink is refused by the kernel. Measured on 2026-08-10,
// `ip -6 address add fd00:d951:1::2/128` against a tun device: accepted at
// 1280, 1281, 1309, 1331, 1373 and 1500; "RTNETLINK answers: Invalid argument"
// at 1279, 1139, 1138 and 576.
//
// The posture therefore promotes IPv4-only, exactly as it always did -- and
// that is still a leak, which is why the reason is recorded rather than left
// silent. A host that reads it can say what happened instead of reporting an
// unqualified success.
void TestTheSinkIsRefusedBelowTheIPv6LinkFloorAndTheReasonIsRecorded() {
  PosturePlan plan;
  std::string error;
  // StatusLine's own inner_mtu is 1190, which is below the floor.
  Check(BuildPromotedPosture(SampleInput(),
                             Parsed(StatusLine(true, "carrying", 6, false)),
                             &plan, &error),
        "a promotion below the IPv6 floor still builds: " + error);
  Check(!plan.ipv6, "but installs no IPv6");
  Check(plan.ipv6_sink.empty(), "and no sink, because the kernel would refuse");
  Check(plan.ipv6_absent_reason.find("1190") != std::string::npos,
        "and it records the inner MTU that made it impossible");
  Check(plan.ipv6_absent_reason.find("1421") != std::string::npos,
        "and the plan-aware path MTU that would fix it");

  for (const auto& command : RenderLinuxPostureCommands("winsvpn3", plan)) {
    for (const auto& argument : command) {
      Check(argument != "-6",
            "and the renderer emits no IPv6 command at all below the floor");
    }
  }
}

// The threshold is plan-aware WITHOUT this header re-deriving carrier.Floor,
// because `inner_mtu` is already the plan floor. A flat check on the path MTU
// would have to be 1421 -- the [udp,tcp,tls] figure -- and would refuse the
// two narrower plans that work.
void TestTheSinkThresholdIsPlanAwareThroughTheInnerMTU() {
  struct Case {
    int inner_mtu;
    bool expect_sink;
    const char* what;
  };
  // Each inner MTU below is the plan floor at that plan's own published path
  // MTU threshold, and all three land on exactly 1280:
  //   udp            1357 - 77  = 1280
  //   [udp,tcp]      1399 - 119 = 1280
  //   [udp,tcp,tls]  1421 - 141 = 1280
  const Case cases[] = {
      {1279, false, "one byte below the floor"},
      {1280, true, "the floor itself -- all three plans' thresholds"},
      {1309, true, "the fleet default 1450 over [udp,tcp,tls]"},
      {1331, true, "the fleet default 1450 over [udp,tcp]"},
      {1373, true, "the fleet default 1450 over udp alone"},
      {1259, false, "path 1400 over [udp,tcp,tls]: below 1421, refused"},
      {1281, true, "path 1400 over [udp,tcp]: above 1399, allowed"},
  };
  for (const Case& one : cases) {
    PosturePlan plan;
    std::string error;
    EngineStatus status = Parsed(StatusLine(true, "carrying", 6, false));
    status.inner_mtu = one.inner_mtu;
    Check(BuildPromotedPosture(SampleInput(), status, &plan, &error),
          std::string("the posture builds at inner MTU ") +
              std::to_string(one.inner_mtu) + ": " + error);
    Check(plan.ipv6 == one.expect_sink,
          std::string("inner MTU ") + std::to_string(one.inner_mtu) + " (" +
              one.what + ") must " + (one.expect_sink ? "" : "not ") +
              "install the sink");
  }
}

// An operator's own `routes = ::/0` used to be SILENTLY DROPPED, on the
// strength of a comment claiming `default_route` already rendered it. Nothing
// did. Measured 2026-08-10: `full_routes = {"::/0"}` produced byte-identical
// commands to an empty route set on both platforms, while `2000::/3` in the
// same position survived -- so the filter discarded the correct spelling and
// kept a partial one.
//
// It is still filtered, and the claim is now true, which is what this asserts:
// the halves ARE rendered, so the operator gets what they asked for and the
// renderer does not emit the same prefix twice.
void TestAnOperatorsIPv6DefaultRouteIsRenderedRatherThanSwallowed() {
  PostureInput asked = SampleInput();
  asked.full_routes = {"0.0.0.0/1", "128.0.0.0/1", "::/0"};

  PosturePlan plan;
  std::string error;
  EngineStatus wide = Parsed(StatusLine(true, "carrying", 6, false));
  wide.inner_mtu = 1309;
  Check(BuildPromotedPosture(asked, wide, &plan, &error),
        "a hand-written route set naming ::/0 builds: " + error);

  int low = 0;
  int high = 0;
  int whole = 0;
  for (const auto& command : RenderLinuxPostureCommands("winsvpn3", plan)) {
    for (const auto& argument : command) {
      if (argument == "::/1") ++low;
      if (argument == "8000::/1") ++high;
      if (argument == "::/0") ++whole;
    }
  }
  Check(low == 1 && high == 1,
        "the IPv6 default the operator asked for IS rendered, exactly once per "
        "half, so the second add cannot fail EEXIST");
  Check(whole == 0, "and never as the literal ::/0");

  // AND THE HALVES SPELLED OUT, which is the other natural way to write it and
  // the one the IPv4 side has always had to defend against. Found by mutation
  // on 2026-08-10: dropping the two IPv6 halves from RendersAsDefaultRoute
  // SURVIVED the assertions above, because they only ever named `::/0`. A
  // second `ip -6 route add ::/1` fails EEXIST and turns a correct promotion
  // into a half-applied one.
  PostureInput spelled = SampleInput();
  spelled.full_routes = {"::/1", "8000::/1"};
  PosturePlan spelled_plan;
  Check(BuildPromotedPosture(spelled, wide, &spelled_plan, &error),
        "a route set naming the IPv6 halves builds: " + error);
  low = 0;
  high = 0;
  for (const auto& command :
       RenderLinuxPostureCommands("winsvpn3", spelled_plan)) {
    for (const auto& argument : command) {
      if (argument == "::/1") ++low;
      if (argument == "8000::/1") ++high;
    }
  }
  Check(low == 1 && high == 1,
        "each IPv6 half is rendered exactly once even when the operator spells "
        "it out, so the renderer cannot emit the same prefix twice");
}

// The bootstrap posture must remain narrow even when the host hands in a full
// route set and a resolver list. Ignored, not filtered: a bootstrap that
// filtered would have a size to get wrong.
void TestABootstrapIgnoresEverythingAPromotionWouldInstall() {
  PosturePlan plan;
  std::string error;
  PostureInput loaded = SampleInput();
  loaded.full_routes = {"0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"};
  loaded.dns_servers = {"10.64.0.1", "10.64.0.9"};
  loaded.inner_v6 = "fd00:64::2";
  loaded.router_v6 = "fd00:64::1";
  Check(BuildBootstrapPosture(loaded,
                              Parsed(StatusLine(false, "epoch0", 0, true)),
                              &plan, &error),
        "the bootstrap builds from a fully loaded input: " + error);
  Check(VerifyBootstrapIsNarrow(plan, &error),
        "and is still narrow: " + error);
  Check(plan.included_routes.size() == 1, "still one route");
  Check(plan.included_routes.front() == "10.64.0.1/32", "still the next hop");
  Check(!plan.ipv6, "still no IPv6 even with a v6 assignment");
  Check(plan.dns_servers.empty(), "still no resolver");
}

void TestTheRenderersEmitTheNarrowPostureNarrowly() {
  PosturePlan plan;
  std::string error;
  BuildBootstrapPosture(SampleInput(),
                        Parsed(StatusLine(false, "handshaking", 0, false)),
                        &plan, &error);

  const auto linux_commands = RenderLinuxPostureCommands("winsvpn", plan);
  bool saw_default = false;
  bool saw_mtu = false;
  for (const auto& command : linux_commands) {
    for (const auto& argument : command) {
      if (argument == "0.0.0.0/1" || argument == "128.0.0.0/1" ||
          argument == "default") {
        saw_default = true;
      }
      if (argument == "1190") {
        saw_mtu = true;
      }
    }
  }
  Check(!saw_default, "the Linux bootstrap renders no default route");
  Check(saw_mtu, "the Linux bootstrap renders the exact inner MTU");

  const auto windows_commands = RenderWindowsPostureCommands("Winn3", plan);
  bool saw_dns = false;
  saw_default = false;
  for (const auto& command : windows_commands) {
    for (const auto& argument : command) {
      if (argument == "dnsservers") {
        saw_dns = true;
      }
      if (argument == "0.0.0.0/1" || argument == "128.0.0.0/1") {
        saw_default = true;
      }
    }
  }
  Check(!saw_dns, "the Windows bootstrap renders no resolver");
  Check(!saw_default, "the Windows bootstrap renders no default route");

  // And the promoted posture does render them, so the test above is not
  // passing because the renderers emit nothing at all.
  PosturePlan promoted;
  BuildPromotedPosture(SampleInput(), Parsed(StatusLine(true, "carrying", 2,
                                                        false)),
                       &promoted, &error);
  bool promoted_default = false;
  bool promoted_dns = false;
  for (const auto& command : RenderWindowsPostureCommands("Winn3", promoted)) {
    for (const auto& argument : command) {
      if (argument == "0.0.0.0/1") {
        promoted_default = true;
      }
      if (argument == "dnsservers") {
        promoted_dns = true;
      }
    }
  }
  Check(promoted_default, "the Windows promotion renders the default route");
  Check(promoted_dns, "the Windows promotion renders the resolver");
}

// No renderer may emit shell metacharacters into an argument, because both
// hosts execute argument vectors and a renderer that produced shell syntax
// would invite a caller to build a command line out of it.
void TestNoRenderedArgumentCarriesShellSyntax() {
  PosturePlan plan;
  std::string error;
  BuildPromotedPosture(SampleInput(),
                       Parsed(StatusLine(true, "carrying", 2, false)), &plan,
                       &error);
  const std::string forbidden = ";|&$`><\n\"'\\";
  auto scan = [&](const std::vector<std::vector<std::string>>& commands,
                  const char* which) {
    for (const auto& command : commands) {
      for (const auto& argument : command) {
        Check(argument.find_first_of(forbidden) == std::string::npos,
              std::string(which) + " argument is free of shell syntax: " +
                  argument);
      }
    }
  };
  scan(RenderLinuxPostureCommands("winsvpn", plan), "linux");
  scan(RenderWindowsPostureCommands("Winn3", plan), "windows");
}

// THE OTHER HALF OF THE BELT AND BRACES, ADDED 2026-08-12.
//
// BuildPromotedPosture distrusts `promotion_ready` and re-derives from the
// evidence -- but until this date it did that for ONE of the two halves. The
// `rx_packets == 0` check ran on a ready document; the gate-state check did
// not, because it was nested inside `if (!status.promotion_ready)` and so was
// unreachable the moment the field said true. A document reading
// promotion_ready=true, gate_state=<anything not carrying>, rx_packets>0
// therefore PROMOTED: default route, resolvers and IPv6 all installed, with
// the gate comparison never executed.
//
// The engine cannot write that document -- cmd/winn-datapath's winn3StatusFrom
// reads the gate once and derives both fields from that one value, so they
// cannot disagree -- which makes this defence in depth against a malformed,
// truncated or substituted status line rather than a live engine bug. Two
// shapes are covered here and the second is the one that needs no attacker at
// all: ParseWinn3StatusLine makes `gate_state` OPTIONAL, so a document that
// simply OMITS the key parses with an empty gate state, and an empty gate
// state is not the carrying one.
void TestAReadyClaimBesideANonCarryingGateIsRefused() {
  PosturePlan plan;
  std::string error;

  // Every non-carrying name winn3/tun.State.String() can emit, plus the
  // sentinel it uses for a value it does not recognise. Deliveries are
  // nonzero, so the rx_packets half of the belt and braces cannot be what
  // refuses these -- only the gate half can.
  const std::vector<std::string> not_carrying = {
      "closed", "handshaking", "epoch0", "rekeying", "down", "invalid"};
  for (const std::string& gate : not_carrying) {
    const EngineStatus contradictory = Parsed(StatusLine(true, gate, 5, false));
    Check(contradictory.valid, "the fixture line parses: gate=" + gate);
    Check(contradictory.promotion_ready && contradictory.rx_packets == 5,
          "the fixture really does claim ready WITH deliveries: gate=" + gate);
    Check(!BuildPromotedPosture(SampleInput(), contradictory, &plan, &error),
          "promotion_ready beside a '" + gate +
              "' gate is REFUSED, not believed: a ready claim on a gate that "
              "may not carry disagrees with itself exactly as a ready claim "
              "with zero deliveries does");
    Check(error.find(gate) != std::string::npos,
          "and the refusal names the gate state it read, so the operator "
          "learns WHICH half is wrong: " + error);
  }

  // The half that needs no attacker: `gate_state` is optional to the parser,
  // so an engine that speaks promotion_ready but never learned to publish a
  // gate state produces an empty one. Empty is not carrying.
  const std::string no_gate_key =
      "{\"event\":\"posture\",\"posture\":\"promoted\""
      ",\"promotion_ready\":true,\"rx_packets\":9,\"rx_offered\":9"
      ",\"inner_mtu\":1190,\"message_size\":1210,\"inner_ipv6\":false}";
  const EngineStatus gateless = Parsed(no_gate_key);
  Check(gateless.valid, "a document with no gate_state key still parses");
  Check(gateless.gate_state.empty(), "and its gate state is empty");
  Check(!BuildPromotedPosture(SampleInput(), gateless, &plan, &error),
        "a ready document that never names a gate state does NOT promote");

  // The positive control. This is the whole point of the pair: the tightening
  // must refuse the contradiction and MUST NOT refuse the document the engine
  // really writes, or it is an outage rather than a fix.
  const EngineStatus proven = Parsed(StatusLine(true, "carrying", 7, false));
  Check(BuildPromotedPosture(SampleInput(), proven, &plan, &error),
        "and the honest document still promotes, unchanged: " + error);
}

// Table-driven adversarial cases for ParseWinn3StatusLine. A panic here is a
// denial of service of the host that decides the default route. An accepted
// malformed document is a tunnel that widens on something the engine never
// wrote. want_parse false means the line must be refused AND leave *out at
// the zero value (not promotion-ready).
void TestParseWinn3StatusLineAdversarialTable() {
  const std::string honest = StatusLine(true, "carrying", 7, false);
  const std::string bootstrap = StatusLine(false, "handshaking", 0, false);

  struct Row {
    const char* name;
    std::string input;
    bool want_parse;
    bool want_ready;
  };
  const Row rows[] = {
      {"honest carrying document", honest, true, true},
      {"honest bootstrap document", bootstrap, true, false},
      {"trailing whitespace after one object", honest + "  \n", true, true},
      {"leading whitespace", std::string("  \n") + bootstrap, true, false},
      {"empty", "", false, false},
      {"not json", "not json at all", false, false},
      {"JSON null", "null", false, false},
      {"JSON array", "[]", false, false},
      {"JSON true", "true", false, false},
      {"no promotion_ready", "{\"event\":\"posture\"}", false, false},
      {"no event", "{\"promotion_ready\":true}", false, false},
      {"promotion_ready as string",
       "{\"event\":\"posture\",\"promotion_ready\":\"true\"}", false, false},
      {"promotion_ready as 1",
       "{\"event\":\"posture\",\"promotion_ready\":1}", false, false},
      {"promotion_ready truex prefix",
       "{\"event\":\"posture\",\"promotion_ready\":truex,"
       "\"gate_state\":\"carrying\",\"rx_packets\":3}",
       false, false},
      {"inner_ipv6 truehood prefix",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"inner_ipv6\":truehood}",
       false, false},
      {"duplicate promotion_ready true then false",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":\"carrying\",\"rx_packets\":3,"
       "\"promotion_ready\":false}",
       false, false},
      {"duplicate promotion_ready false then true",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"promotion_ready\":true,\"gate_state\":\"carrying\","
       "\"rx_packets\":3}",
       false, false},
      {"concatenated second object",
       bootstrap + "{\"event\":\"carrying\",\"promotion_ready\":true}", false,
       false},
      {"event as number steals the next key name",
       "{\"event\":1,\"posture\":\"bootstrap\",\"promotion_ready\":false}",
       false, false},
      {"inner_mtu 2^32+1500 would truncate to 1500 on a 32-bit int",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"inner_mtu\":4294968796}",
       false, false},
      {"inner_mtu above the IPv4 datagram ceiling",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"inner_mtu\":65536}",
       false, false},
      {"rx_packets overflowing uint64",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":18446744073709551616}",
       false, false},
      {"rx_packets scientific notation",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":1e2}",
       false, false},
      {"rx_packets fractional",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":1.5}",
       false, false},
      {"UTF-8 BOM",
       std::string("\xEF\xBB\xBF") + bootstrap, false, false},
      {"line larger than kMaxStatusLineBytes",
       std::string(winsvpn::winn3::kMaxStatusLineBytes + 1, 'x'), false, false},
      {"nested promotion_ready is not a top-level key",
       "{\"event\":\"posture\",\"nested\":{\"promotion_ready\":true,"
       "\"gate_state\":\"carrying\",\"rx_packets\":1,\"inner_mtu\":1359}}",
       false, false},
      {"nested ready beside top-level false stays false",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"nested\":{\"promotion_ready\":true,\"gate_state\":\"carrying\","
       "\"rx_packets\":9}}",
       true, false},
      {"garbage with key-shaped text is not a JSON object",
       "gate_state\":\"carrying\",\"rx_packets\":1,\"promotion_ready\":true",
       false, false},
      {"encoding-failure fallback the engine itself emits",
       "{\"event\":\"refused\",\"posture\":\"bootstrap\","
       "\"promotion_ready\":false,\"refusal\":\"status could not be encoded\"}",
       true, false},
      {"rx_packets leading zeros are not an integer",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":01}",
       false, false},
      {"rx_packets zero is a legal parse and is not ready",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"gate_state\":\"carrying\",\"rx_packets\":0}",
       true, false},
      {"gate_state as a number is not a state name",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":1,\"rx_packets\":3}",
       false, false},
      {"gate_state as JSON null is not a state name",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":null,\"rx_packets\":3}",
       false, false},
      {"duplicate rx_offered is untrustworthy",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_offered\":0,\"rx_offered\":9}",
       false, false},
      {"whitespace only", "   \n\t", false, false},
      {"JSON string", "\"posture\"", false, false},
      {"truncated object", "{\"event\":\"posture\"", false, false},
      {"trailing comma",
       "{\"event\":\"posture\",\"promotion_ready\":false,}", false, false},
      {"event as empty string",
       "{\"event\":\"\",\"promotion_ready\":false}", false, false},
      {"event as JSON null",
       "{\"event\":null,\"promotion_ready\":false}", false, false},
      {"inner_mtu negative",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"inner_mtu\":-1}",
       false, false},
      {"promotion_ready as null",
       "{\"event\":\"posture\",\"promotion_ready\":null}", false, false},
      {"honest document wrapped in an extra object",
       "{\"wrapper\":{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":\"carrying\",\"rx_packets\":1}}",
       false, false},
      {"unknown extra field is ignored",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"diagnostic\":\"ok\"}",
       true, false},
      {"rx_packets uint64 max is a number, not a wrap",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":18446744073709551615}",
       true, false},
      {"inner_mtu zero is a legal parse",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"inner_mtu\":0}",
       true, false},
      {"duplicate event is untrustworthy",
       "{\"event\":\"posture\",\"event\":\"carrying\","
       "\"promotion_ready\":false}",
       false, false},
      {"unknown JSON escape in gate_state is not a state name",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":\"\\carrying\",\"rx_packets\":7}",
       false, false},
      {"truncated JSON escape at end of string",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"gate_state\":\"carrying\\\"}",
       false, false},
      {"unescaped control in event is not JSON",
       std::string("{\"event\":\"pos") + '\x01' +
           "ture\",\"promotion_ready\":false}",
       false, false},
      {"embedded NUL after the object is trailing garbage",
       std::string("{\"event\":\"posture\",\"promotion_ready\":false}") +
           '\0',
       false, false},
      {"rx_packets NaN is not an integer",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":NaN}",
       false, false},
      {"rx_packets Infinity is not an integer",
       "{\"event\":\"posture\",\"promotion_ready\":false,"
       "\"rx_packets\":Infinity}",
       false, false},
      {"uppercase CARRYING is not the carrying gate token",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":\"CARRYING\",\"rx_packets\":7}",
       true, true},
      {"padded carrying is not the carrying gate token",
       "{\"event\":\"posture\",\"promotion_ready\":true,"
       "\"gate_state\":\" carrying\",\"rx_packets\":7}",
       true, true},
  };

  for (const Row& row : rows) {
    EngineStatus status;
    const bool parsed = ParseWinn3StatusLine(row.input, &status);
    if (row.want_parse) {
      Check(parsed, std::string("accepted row refused: ") + row.name);
      Check(status.valid, std::string("accepted row left invalid: ") + row.name);
      Check(status.promotion_ready == row.want_ready,
            std::string("promotion_ready mismatch: ") + row.name);
    } else {
      Check(!parsed, std::string("hostile input was accepted: ") + row.name);
      Check(!status.valid, std::string("hostile input left valid: ") + row.name);
      Check(!status.promotion_ready,
            std::string("hostile input was promotion-ready: ") + row.name);
    }
  }

  EngineStatus cased;
  Check(ParseWinn3StatusLine(
            "{\"event\":\"posture\",\"promotion_ready\":true,"
            "\"gate_state\":\"CARRYING\",\"rx_packets\":7}",
            &cased),
        "uppercase CARRYING still parses as a document");
  Check(cased.gate_state != winsvpn::winn3::kCarryingGate,
        "but the stored gate is not the carrying token");
  EngineStatus padded;
  Check(ParseWinn3StatusLine(
            "{\"event\":\"posture\",\"promotion_ready\":true,"
            "\"gate_state\":\" carrying\",\"rx_packets\":7}",
            &padded),
        "padded carrying still parses as a document");
  Check(padded.gate_state != winsvpn::winn3::kCarryingGate,
        "but a leading space is not the carrying token");
}

// TestNestedStatusKeysDoNotPromote is the promotion-gate half of the nested
// FindKey fix. The adversarial table already requires ParseWinn3StatusLine to
// refuse a document whose only promotion_ready lives inside a nested object.
// This test asks the next question: even if a future edit made that line
// parse, BuildPromotedPosture must still not widen, because the top-level
// document never proved the datapath.
void TestNestedStatusKeysDoNotPromote() {
  const std::string nested_only =
      "{\"event\":\"posture\",\"nested\":{\"promotion_ready\":true,"
      "\"gate_state\":\"carrying\",\"rx_packets\":1,\"inner_mtu\":1359}}";
  EngineStatus status;
  Check(!ParseWinn3StatusLine(nested_only, &status),
        "a nested-only promotion_ready does not parse as a status document");
  Check(!status.valid, "and leaves *out invalid");
  Check(!status.promotion_ready, "and not promotion-ready");

  PosturePlan plan;
  std::string error;
  Check(!BuildPromotedPosture(SampleInput(), status, &plan, &error),
        "an unparsed nested-key document does not promote: " + error);

  const std::string nested_beside_false =
      "{\"event\":\"posture\",\"promotion_ready\":false,\"inner_mtu\":1359,"
      "\"nested\":{\"promotion_ready\":true,\"gate_state\":\"carrying\","
      "\"rx_packets\":9}}";
  Check(ParseWinn3StatusLine(nested_beside_false, &status),
        "a top-level false beside a nested true still parses");
  Check(status.valid && !status.promotion_ready,
        "and the top-level false wins; the nested true is not a key");
  Check(!BuildPromotedPosture(SampleInput(), status, &plan, &error),
        "and it does not promote: " + error);
}

// TestJsonStringEscapesDoNotSynthesizeTheCarryingGate is the promotion-gate
// half of the unescape fix. `"ca\rrying"` is valid JSON whose gate value is
// ca + CR + rrying. The previous reader collected it as "carrying" and
// BuildPromotedPosture then widened. `\u0063arrying` IS carrying (valid JSON
// for the letter c) and must still promote, or the fix is an outage on a
// document encoding/json already accepts.
void TestJsonStringEscapesDoNotSynthesizeTheCarryingGate() {
  PosturePlan plan;
  std::string error;

  const std::string cr = StatusLine(true, "ca\\rrying", 7, false);
  EngineStatus status;
  Check(ParseWinn3StatusLine(cr, &status),
        "valid JSON with \\r in the gate still parses");
  Check(status.valid, "and is marked valid");
  Check(status.promotion_ready, "the boolean is still true; hosts re-check");
  Check(status.gate_state != winsvpn::winn3::kCarryingGate,
        "\\r is a carriage return, not the letter r");
  Check(status.gate_state.size() == std::string("carrying").size() &&
            status.gate_state.find('\r') != std::string::npos,
        "the stored gate contains a CR where the JSON wrote \\r");
  Check(!BuildPromotedPosture(SampleInput(), status, &plan, &error),
        "and promotion refuses a CR-punctuated gate: " + error);

  const std::string invalid = StatusLine(true, "\\carrying", 7, false);
  Check(!ParseWinn3StatusLine(invalid, &status),
        "\\c is not a JSON escape and must be refused");
  Check(!status.valid && !status.promotion_ready,
        "a refused invalid-escape document is not promotion-ready");

  const std::string unicode_c = StatusLine(true, "\\u0063arrying", 7, false);
  Check(ParseWinn3StatusLine(unicode_c, &status),
        "\\u0063 is c, which is valid JSON for carrying");
  Check(status.gate_state == winsvpn::winn3::kCarryingGate,
        "decoded gate is the carrying token");
  Check(BuildPromotedPosture(SampleInput(), status, &plan, &error),
        "and the equivalent encoding still promotes: " + error);

  const std::string quote_u = StatusLine(true, "\\u0022carrying", 7, false);
  Check(ParseWinn3StatusLine(quote_u, &status),
        "\\u0022 is a quote character in the value, not a JSON delimiter");
  Check(status.gate_state != winsvpn::winn3::kCarryingGate,
        "a leading quote in the gate is not the carrying token");
  Check(!BuildPromotedPosture(SampleInput(), status, &plan, &error),
        "and it does not promote: " + error);
}

void TestIpv4ValueAdversarialTable() {
  using winsvpn::winn3::resolvers::Ipv4Value;
  struct Row {
    const char* name;
    const char* input;
    bool want;
    uint32_t value;
  };
  const Row rows[] = {
      {"dotted quad", "10.64.0.1", true, 0x0A400001u},
      {"broadcast", "255.255.255.255", true, 0xFFFFFFFFu},
      {"unspecified", "0.0.0.0", true, 0u},
      {"leading zeros are the same address", "10.64.000.1", true, 0x0A400001u},
      {"surrounding whitespace is trimmed", " 10.64.0.1 ", true, 0x0A400001u},
      {"empty", "", false, 0},
      {"three parts", "10.64.0", false, 0},
      {"five parts", "10.64.0.1.2", false, 0},
      {"octet 256", "256.0.0.1", false, 0},
      {"octet 999", "1.2.3.999", false, 0},
      {"four-digit octet", "1.2.3.0256", false, 0},
      {"trailing dot", "1.2.3.4.", false, 0},
      {"leading dot", ".1.2.3", false, 0},
      {"empty octet", "1.2..4", false, 0},
      {"hex prefix", "0x1.2.3.4", false, 0},
      {"letter in octet", "1.2.3.4a", false, 0},
      {"sign in octet", "1.2.3.+1", false, 0},
      {"IPv6", "fd00:d951:1::2", false, 0},
      {"hostname", "resolver.inner", false, 0},
  };
  for (const Row& row : rows) {
    uint32_t got = 0xDEADBEEFu;
    const bool parsed = Ipv4Value(row.input, &got);
    if (row.want) {
      Check(parsed, std::string("Ipv4Value refused a dotted quad: ") + row.name);
      Check(got == row.value, std::string("Ipv4Value value mismatch: ") + row.name);
    } else {
      Check(!parsed, std::string("Ipv4Value accepted hostile input: ") + row.name);
    }
  }
}

}  // namespace

// ParseFromStdin is the CROSS-LANGUAGE CONFORMANCE mode.
//
// The fixtures above are strings this file wrote, so they prove the parser is
// self-consistent and nothing more. The document that matters is the one the Go
// engine actually emits, and the two are written in different languages by
// different lanes. This mode reads one real line from cmd/winn-datapath and
// reports what this parser made of it, so the agreement can be checked rather
// than assumed:
//
//   winn-datapath -winn3-profile P -winn3-print-sizing | winn3_posture_test -parse
//
// It exits non-zero when the line does not parse, so it can be used as a gate.
int ParseFromStdin() {
  std::string line;
  int character = 0;
  while ((character = std::getchar()) != EOF && character != '\n') {
    line.push_back(static_cast<char>(character));
  }
  EngineStatus status;
  if (!ParseWinn3StatusLine(line, &status)) {
    std::fprintf(stderr,
                 "winn3_posture_test: the engine's status line did not "
                 "parse\n");
    return EXIT_FAILURE;
  }
  std::printf(
      "parsed event=%s posture=%s promotion_ready=%s gate=%s rx_packets=%llu "
      "inner_mtu=%d message_size=%d inner_ipv6=%s\n",
      status.event.c_str(), status.posture.c_str(),
      status.promotion_ready ? "true" : "false", status.gate_state.c_str(),
      static_cast<unsigned long long>(status.rx_packets), status.inner_mtu,
      status.message_size, status.inner_ipv6 ? "true" : "false");

  // A first status line must never be promotion-ready, whatever else it says.
  if (status.promotion_ready) {
    std::fprintf(stderr,
                 "winn3_posture_test: an engine that has carried nothing "
                 "reported promotion_ready\n");
    return EXIT_FAILURE;
  }
  PosturePlan plan;
  std::string error;
  if (BuildPromotedPosture(SampleInput(), status, &plan, &error)) {
    std::fprintf(stderr,
                 "winn3_posture_test: a first status line promoted the "
                 "posture\n");
    return EXIT_FAILURE;
  }
  std::printf("promotion refused, as it must be: %s\n", error.c_str());
  if (!BuildBootstrapPosture(SampleInput(), status, &plan, &error) ||
      !VerifyBootstrapIsNarrow(plan, &error)) {
    std::fprintf(stderr,
                 "winn3_posture_test: the engine's own numbers did not "
                 "produce a narrow bootstrap: %s\n",
                 error.c_str());
    return EXIT_FAILURE;
  }
  std::printf("bootstrap from the engine's own numbers: mtu=%d routes=%zu\n",
              plan.mtu, plan.included_routes.size());
  return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "-parse") {
    return ParseFromStdin();
  }
  TestTheStatusParserReadsWhatTheEngineWrites();
  TestAKeyIsNotAValue();
  TestAnUnreadableStatusLineIsNotPromotionReady();
  TestTheBootstrapPostureIsNarrow();
  TestTheBootstrapPostureRefusesRatherThanWidening();
  TestACarryingGateAloneDoesNotPromote();
  TestPromotionWidensOnlyWhenProven();
  TestPromotionRefusesUndeclaredResolvers();
  TestTheInnerBlockFloorIsTheOneAppleAndAndroidUse();
  TestNotInnerReasonKeepsAppleAndAndroidsClauseOrder();
  TestCandidatesReplaceTheHostListRatherThanJoiningIt();
  TestTheDeclaredPathIsUntouchedByTheDerivation();
  TestTheDerivedPathPromotesAServedSessionWithNoDnsKey();
  TestTheDeclarationCannotRescueAFailedDerivation();
  TestAPromotionThatWouldCaptureNothingIsRefused();
  TestAServedRouteSetKeepsTheBootstrapsNextHop();
  TestPromotionRefusesIPv6TheFloorCannotCarry();
  TestAPromotedPostureInstallsTheIPv6SinkWhenItIsLegal();
  TestPromotedCommandDeltaOmitsTheBootstrapNextHop();
  TestTheSinkIsRefusedBelowTheIPv6LinkFloorAndTheReasonIsRecorded();
  TestTheSinkThresholdIsPlanAwareThroughTheInnerMTU();
  TestAnOperatorsIPv6DefaultRouteIsRenderedRatherThanSwallowed();
  TestABootstrapIgnoresEverythingAPromotionWouldInstall();
  TestTheRenderersEmitTheNarrowPostureNarrowly();
  TestNoRenderedArgumentCarriesShellSyntax();
  TestAReadyClaimBesideANonCarryingGateIsRefused();
  TestParseWinn3StatusLineAdversarialTable();
  TestNestedStatusKeysDoNotPromote();
  TestJsonStringEscapesDoNotSynthesizeTheCarryingGate();
  TestIpv4ValueAdversarialTable();

  if (failures != 0) {
    std::fprintf(stderr, "winn3_posture_test: %d of %d check(s) failed\n",
                 failures, checks);
    return EXIT_FAILURE;
  }
  std::printf("winn3_posture_test: all %d checks passed\n", checks);
  return EXIT_SUCCESS;
}
