// Route-promotion gate tests for the Windows Winn Protocol v1 host.
//
// WHY THIS FILE EXISTS. windows_winn_engine.cpp used to answer "the transport
// was observed in both directions" -- the sentence half the route-promotion
// gate is made of -- whenever the engine's status reply did NOT contain the
// substring `"awg_classification":"configured-h1h4"`. A rename of that field on
// the engine side, a version skew between the shipped host and the shipped
// engine, or an encoder that emitted a space after the colon each turned the
// gate off and promoted the user's default route onto a carrier that had never
// been proven to carry anything. The only trace was an OutputDebugStringA line,
// which no production install reads. The symptom on a censored network is a
// tunnel that reports Connected while nothing crosses it.
//
// The decision now turns on WindowsWinnHeadersClassify() over the host's OWN
// parsed `[winn]` section, which is what the code's own justification always
// appealed to. The engine's reply is read for exactly one field,
// `transport_observed_both_ways`, and for wording.
//
// It is deliberately free of <windows.h> -- like linux_winn_carrier_profile
// _test.cc and winn3_posture_test.cc, and for the same stated reason -- so it
// builds and RUNS on the development host as well as on the target. A test that
// only Windows can execute is a test that does not get run, and this project's
// sessions do not happen on Windows.
//
// Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -o /tmp/windows_winn_gate_test \
//       windows/runner/windows_winn_gate_test.cc && /tmp/windows_winn_gate_test
//
// It is NOT in windows/runner/CMakeLists.txt, exactly as linux_secure_store
// _test.cc, linux_winn_carrier_profile_test.cc and winn3_posture_test.cc are
// not in theirs: these are standalone test programs with their own main. Both
// CMake targets there list their sources explicitly, so this file cannot reach
// the shipped binaries.

#include "windows_winn_engine.h"

#include <cstdio>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const std::string& what) {
  if (!condition) {
    ++failures;
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
  }
}

using winsvpn::winn::DecideWinnTransportGate;
using winsvpn::winn::JsonFieldIsTrue;
using winsvpn::winn::WindowsAwgHeaderSpec;
using winsvpn::winn::WindowsWinnHeadersClassify;
using winsvpn::winn::WindowsWinnParams;
using winsvpn::winn::WinnCreateAckAccepted;
using winsvpn::winn::WinnTransportGate;

WindowsWinnParams ParamsWithHeaders(uint32_t h1, uint32_t h2, uint32_t h3,
                                    uint32_t h4) {
  WindowsWinnParams params;
  const uint32_t values[4] = {h1, h2, h3, h4};
  for (int index = 0; index < 4; ++index) {
    params.h[index].start = values[index];
    params.h[index].end = values[index];
  }
  return params;
}

// A status document of the shape datapath/status.go marshals, trimmed to the
// fields this gate reads. `gateway_endpoint` is present on purpose: the refusal
// wording must never carry it.
std::string StatusJson(const char* classification, bool observed) {
  std::string json =
      "{\"contract\":\"winn/3\",\"up\":true,\"gateway_endpoint\":"
      "\"203.0.113.9:51820\",\"awg_classification\":\"";
  json += classification;
  json += "\",\"handshake_response_observed\":true,";
  json += "\"transport_observed_both_ways\":";
  json += observed ? "true" : "false";
  json += "}";
  return json;
}

void TestHeadersClassify() {
  WindowsWinnParams blank;
  Check(!WindowsWinnHeadersClassify(blank),
        "a default-constructed params has four degenerate 0..0 ranges that "
        "overlap pairwise, so it does not classify");

  Check(WindowsWinnHeadersClassify(ParamsWithHeaders(1, 2, 3, 4)),
        "vanilla WireGuard's 1/2/3/4 are four distinct scalars and classify");

  // A real served table: large, distinct, non-overlapping scalars.
  Check(WindowsWinnHeadersClassify(
            ParamsWithHeaders(1194731, 87104561, 1616794723, 1231234123)),
        "a served h1..h4 scalar table classifies");

  Check(!WindowsWinnHeadersClassify(ParamsWithHeaders(5, 5, 3, 4)),
        "two equal header types are ambiguous and must not classify");

  // Ranges, which ParseWindowsWinnSection also accepts.
  WindowsWinnParams ranges;
  ranges.h[0] = WindowsAwgHeaderSpec{16777216, 1086324735};
  ranges.h[1] = WindowsAwgHeaderSpec{1086324736, 2155872255};
  ranges.h[2] = WindowsAwgHeaderSpec{2155872256, 3225419775};
  ranges.h[3] = WindowsAwgHeaderSpec{3225419776, 4294967295u};
  Check(WindowsWinnHeadersClassify(ranges),
        "four adjacent but non-overlapping ranges classify");

  WindowsWinnParams touching = ranges;
  touching.h[1].start = touching.h[0].end;  // one shared value is an overlap
  Check(!WindowsWinnHeadersClassify(touching),
        "ranges sharing a single value overlap and must not classify");

  WindowsWinnParams inverted = ParamsWithHeaders(1, 2, 3, 4);
  inverted.h[2].start = 900;
  inverted.h[2].end = 100;
  Check(!WindowsWinnHeadersClassify(inverted),
        "an inverted range is not a range and must not classify");
}

void TestJsonFieldIsTrue() {
  Check(JsonFieldIsTrue("{\"transport_observed_both_ways\":true}",
                        "transport_observed_both_ways"),
        "the compact encoding Go emits is read");
  Check(JsonFieldIsTrue("{\"transport_observed_both_ways\" : true}",
                        "transport_observed_both_ways"),
        "whitespace around the colon is tolerated, so a pretty-printing "
        "encoder does not silently change the verdict");
  Check(!JsonFieldIsTrue("{\"transport_observed_both_ways\":false}",
                         "transport_observed_both_ways"),
        "false is false");
  Check(!JsonFieldIsTrue("{\"up\":true}", "transport_observed_both_ways"),
        "an absent field is not proof");
  Check(!JsonFieldIsTrue("{\"rx_transport_observed_both_ways\":true}",
                         "transport_observed_both_ways"),
        "a longer key that merely ENDS with the field name is not the field");
  Check(!JsonFieldIsTrue(
            "{\"note\":\"\\\"transport_observed_both_ways\\\":true\"}",
            "transport_observed_both_ways"),
        "the field name quoted inside a string value is not the field");
}

void TestGateRefusesWhatItCannotObserve() {
  std::string reason;
  // The case the replaced code promoted on: the engine is not reporting the
  // configured classification and nothing has been observed.
  const WinnTransportGate skewed = DecideWinnTransportGate(
      true, StatusJson("wireguard-default-1234", false), &reason);
  Check(skewed != WinnTransportGate::kObserved,
        "an unproven transport is NEVER reported as observed, whatever the "
        "engine says its classification is -- this is the fail-open that was "
        "closed");
  Check(skewed == WinnTransportGate::kNotYetObserved,
        "an engine whose classification field disagrees is polled to the "
        "caller's fail-closed deadline, not refused on the spot: the field is "
        "a diagnostic, and the proof field is the verdict");
  Check(reason.find("203.0.113.9") == std::string::npos,
        "the refusal wording never carries the customer's gateway endpoint");
  Check(!reason.empty(), "a refusal always says something");

  // A status document with no awg_classification key at all -- the exact
  // version-skew shape the substring match could not survive.
  std::string renamed_reason;
  Check(DecideWinnTransportGate(
            true,
            "{\"contract\":\"winn/3\",\"transport_observed_both_ways\":true}",
            &renamed_reason) == WinnTransportGate::kObserved,
        "an engine that renamed or dropped awg_classification but still "
        "reports the proof field promotes normally: the gate no longer "
        "depends on that field's spelling");

  // Pretty-printed reply: the old substring match would have missed the
  // classification and promoted WITHOUT proof. Now the proof field decides.
  std::string spaced_reason;
  Check(DecideWinnTransportGate(
            true,
            "{\"awg_classification\": \"configured-h1h4\", "
            "\"transport_observed_both_ways\": false}",
            &spaced_reason) == WinnTransportGate::kNotYetObserved,
        "a pretty-printed reply with no proof yet is not proof");
  Check(spaced_reason.find("classification") == std::string::npos,
        "a reply whose classification DOES match is not blamed for the wait");
}

void TestGateObservesRealProof() {
  std::string reason = "stale";
  Check(DecideWinnTransportGate(true, StatusJson("configured-h1h4", true),
                                &reason) == WinnTransportGate::kObserved,
        "a configured classifier reporting bidirectional transport promotes");
  Check(reason.empty(), "a passing gate leaves no refusal reason behind");

  Check(DecideWinnTransportGate(true, StatusJson("configured-h1h4", false),
                                nullptr) ==
            WinnTransportGate::kNotYetObserved,
        "a configured classifier with nothing observed yet keeps waiting");

  Check(DecideWinnTransportGate(true, "", nullptr) ==
            WinnTransportGate::kNotYetObserved,
        "an engine that has not answered yet is not a permanent refusal");
}

void TestHostSideConfigIsWhatDecidesRefusal() {
  std::string reason;
  // The ONLY input that can produce a permanent refusal is the host's own
  // configuration -- never anything in the reply.
  Check(DecideWinnTransportGate(false, StatusJson("configured-h1h4", true),
                                &reason) == WinnTransportGate::kCannotObserve,
        "a session started without a classifiable h1..h4 table is refused "
        "even when the engine claims both a configured classifier and proof");
  Check(reason.find("h1..h4") != std::string::npos,
        "the refusal names the missing thing so an operator can act on it");
  Check(reason.find("203.0.113.9") == std::string::npos,
        "the refusal wording never carries the customer's gateway endpoint");

  Check(DecideWinnTransportGate(false, "", nullptr) ==
            WinnTransportGate::kCannotObserve,
        "the permanent refusal does not depend on the engine answering, so it "
        "costs no part of the convergence budget");
}

// The two halves must agree by construction: anything ParseWindowsWinnSection
// accepts classifies, and a params that classifies is one BuildWindowsWinn
// ConfigJson emits awg_header_types for. That second property is what makes
// the host-side boolean a true statement about the document the engine got.
void TestClassifyAgreesWithTheDocumentTheEngineReceives() {
  // BuildWindowsWinnConfigJson's own condition, restated here because that
  // function needs <sstream> and lives in the .cpp.
  const auto emits_header_types = [](const WindowsWinnParams& params) {
    return params.h[0].start != 0 || params.h[1].start != 0 ||
           params.h[2].start != 0 || params.h[3].start != 0;
  };
  Check(emits_header_types(ParamsWithHeaders(1, 2, 3, 4)) &&
            WindowsWinnHeadersClassify(ParamsWithHeaders(1, 2, 3, 4)),
        "a classifying table is one the Create document carries");
  // At most one of four pairwise-distinct specs can start at zero, so a
  // classifying params always has a nonzero start somewhere.
  Check(emits_header_types(ParamsWithHeaders(0, 1, 2, 3)) &&
            WindowsWinnHeadersClassify(ParamsWithHeaders(0, 1, 2, 3)),
        "h1 = 0 is legal and still emits awg_header_types");
  WindowsWinnParams blank;
  Check(!emits_header_types(blank) && !WindowsWinnHeadersClassify(blank),
        "the empty table neither classifies nor is sent");
}

// The shape cmd/winn-datapath/winn3_run.go acknowledges with: contract, payload
// and carrier, in the key order BuildWindowsWinnConfigJson sends them. Only the
// three fields StartWindowsWinnEngine turns on are filled; everything else the
// real engine adds is irrelevant to the anti-downgrade check.
std::string Ack(const char* contract, const char* payload, const char* carrier) {
  return std::string("{\"contract\":\"") + contract + "\",\"payload\":\"" +
         payload + "\",\"carrier\":\"" + carrier +
         "\",\"status\":\"running\"}";
}

// StartWindowsWinnEngine refuses any Create acknowledgement that is not exactly
// the winn-datapath/1 awg-datagram direct-awg session this host configured.
// Three fail-open shapes must each go red: a foreign contract (notably the
// winn/3 identity the match once trusted), a foreign payload (notably ip-packet,
// raw cleartext), and a foreign carrier (which would downgrade the transport).
void TestCreateAckRefusal() {
  // The one document the host may accept.
  Check(WinnCreateAckAccepted(
            Ack("winn-datapath/1", "awg-datagram", "direct-awg")),
        "an acknowledgement echoing the configured winn-datapath/1 "
        "awg-datagram direct-awg session is accepted");

  // Each anti-downgrade field wrong on its own.
  Check(!WinnCreateAckAccepted(Ack("winn/3", "awg-datagram", "direct-awg")),
        "an acknowledgement carrying any contract other than winn-datapath/1 "
        "is refused: a binary that identifies as some other datapath -- or a "
        "test double emitting no contract at all -- never carries a session");
  Check(!WinnCreateAckAccepted(
            Ack("winn-datapath/1", "ip-packet", "direct-awg")),
        "an acknowledgement claiming any payload other than awg-datagram -- "
        "ip-packet in particular, which would put cleartext on the wire -- is "
        "refused and never carried");
  Check(!WinnCreateAckAccepted(
            Ack("winn-datapath/1", "awg-datagram", "http3-connect-udp")),
        "an acknowledgement carrying any carrier other than direct-awg is "
        "refused rather than downgraded to a weaker transport");

  // The test-double shapes named in StopWindowsWinnEngine's own justification.
  Check(!WinnCreateAckAccepted(
            "{\"payload\":\"awg-datagram\",\"carrier\":\"direct-awg\"}"),
        "an acknowledgement with no contract field at all -- the shape a test "
        "double stands in for the real engine emits -- is refused");
  Check(!WinnCreateAckAccepted(
            "{\"contract\":\"winn-datapath/1\",\"payload\":\"awg-datagram\"}"),
        "an acknowledgement that omits the carrier is refused");

  // A datagram is still refused when an accepted literal is only the VALUE of
  // some other string: the anchored field search must not let "contract" hide
  // inside a note.
  Check(!WinnCreateAckAccepted(
            "{\"note\":\"\\\"contract\\\":\\\"winn-datapath/1\\\"\","
            "\"payload\":\"awg-datagram\",\"carrier\":\"direct-awg\"}"),
        "a winn-datapath/1 literal quoted inside a different string value is "
        "not a contract field and is refused");

  // JsonFieldEquals's one tolerated variation: a pretty-printer must not be
  // able to turn the anti-downgrade gate off.
  Check(WinnCreateAckAccepted(
            "{\"contract\": \"winn-datapath/1\","
            "\"payload\": \"awg-datagram\","
            "\"carrier\": \"direct-awg\"}"),
        "whitespace after the colon is tolerated, so a pretty-printing encoder "
        "cannot silently disable the check");
}

}  // namespace

int main() {
  TestHeadersClassify();
  TestJsonFieldIsTrue();
  TestGateRefusesWhatItCannotObserve();
  TestGateObservesRealProof();
  TestHostSideConfigIsWhatDecidesRefusal();
  TestClassifyAgreesWithTheDocumentTheEngineReceives();
  TestCreateAckRefusal();
  if (failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("windows_winn_gate_test: all checks passed\n");
  return 0;
}
