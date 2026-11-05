// Route-promotion gate tests for the Linux Winn Protocol host.
//
// WHY THIS FILE EXISTS. linux_tunnel_backend.cc carried the SAME fail-open the
// Windows lane closed, in two places:
//
//   * :2759-2762, the transport-convergence gate, answered "converged" --
//     promote -- whenever the engine's status reply did NOT contain the
//     substring `"awg_classification":"configured-h1h4"`.
//   * :2692, the periodic datapath health check, answered "healthy" and
//     switched itself off for the rest of the session on the same test.
//
// Both keyed on the ENGINE'S REPLY while their comments justified themselves by
// appealing to ParseLinuxWinnSection -- to the HOST'S OWN PARSED CONFIG. The
// gap between those two things is the defect: `awg_classification` is a
// round-trip echo of the `awg_header_types` document this host itself built
// (BuildLinuxWinnConfigJson -> Create -> datapath/engine.go:304 ->
// engine.headersConfigured -> datapath/status.go:230-233), so a rename on the
// engine side, a version skew between the shipped host and the shipped engine,
// or an encoder that emitted a space after the colon each read as "gate off"
// rather than as "something is wrong", and the user's default route, DNS and
// IPv6 stayed pointed into a carrier never proven to carry one datagram. The
// only trace was a g_warning on stderr. The symptom on a censored network is a
// tunnel that reports Connected while nothing crosses it.
//
// The decision now turns on LinuxWinnHeadersClassify() over the host's OWN
// parsed `[winn]` section. The engine's reply is read for exactly one field,
// `transport_observed_both_ways`, and for wording.
//
// TestOldGateVersusNew below is the load-bearing one: it replays the PRE-FIX
// logic verbatim beside the new decision over the same inputs and shows the old
// code promoting where the new code refuses.
//
// It is deliberately free of every Linux platform header -- like
// linux_winn_carrier_profile_test.cc and winn3_posture_test.cc, and for the
// same stated reason -- so it builds and RUNS on the development host as well
// as on the target. A test that only Linux can execute is a test that does not
// get run, and this project's sessions do not happen on Linux.
//
// Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -o /tmp/linux_winn_gate_test \
//       linux/runner/linux_winn_gate_test.cc && /tmp/linux_winn_gate_test
//
// It is registered as the linux_winn_gate_test ctest target in
// linux/runner/CMakeLists.txt, with linux_winn3_host_test and
// winn3_posture_test. It can also be built standalone with its own main so it
// still runs on the development host. linux_winn_carrier_profile_test.cc
// remains standalone-only.

#include "linux_winn_host.h"

#include <cstdio>
#include <string>
#include <vector>

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
using winsvpn::winn::LinuxAwgHeaderSpec;
using winsvpn::winn::LinuxWinnHeadersClassify;
using winsvpn::winn::LinuxWinnParams;
using winsvpn::winn::WinnTransportGate;

// The customer's real gateway, as it appears in the status document. No refusal
// wording may ever contain any part of it.
constexpr char kEndpointHost[] = "203.0.113.9";
constexpr char kEndpointPort[] = "51820";
constexpr char kEndpoint[] = "203.0.113.9:51820";

LinuxWinnParams ParamsWithHeaders(uint32_t h1, uint32_t h2, uint32_t h3,
                                  uint32_t h4) {
  LinuxWinnParams params;
  const uint32_t values[4] = {h1, h2, h3, h4};
  for (int index = 0; index < 4; ++index) {
    params.h[index].start = values[index];
    params.h[index].end = values[index];
  }
  return params;
}

// A status document of the shape datapath/status.go marshals, trimmed to the
// fields these two call sites read. `gateway_endpoint` is present on purpose:
// the refusal wording must never carry it.
std::string StatusJson(const char* classification, bool observed) {
  std::string json =
      "{\"contract\":\"winn/3\",\"up\":true,\"gateway_endpoint\":\"";
  json += kEndpoint;
  json += "\",\"awg_classification\":\"";
  json += classification;
  json += "\",\"handshake_response_observed\":true,";
  json += "\"transport_observed_both_ways\":";
  json += observed ? "true" : "false";
  json += ",\"tx_transport_payload_datagrams\":41,";
  json += "\"rx_transport_payload_datagrams\":39}";
  return json;
}

// ---------------------------------------------------------------------------
// THE PRE-FIX LOGIC, transcribed verbatim from the two backups so the
// differential test compares against what actually shipped rather than against
// a description of it.
// ---------------------------------------------------------------------------

// linux_tunnel_backend.cc.bak_20260809_failopen:2747-2774, one tick of the
// loop. `true` here is "return true" from WaitForLinuxWinnTransportConvergence,
// which is PROMOTE.
bool LegacyGateTickPromotes(const std::string& status) {
  static const char kConverged[] = "\"transport_observed_both_ways\":true";
  if (!status.empty() &&
      status.find("\"awg_classification\":\"configured-h1h4\"") ==
          std::string::npos) {
    // "gate DISABLED, promoting without proof."
    return true;
  }
  if (status.find(kConverged) != std::string::npos) return true;
  return false;
}

// linux_tunnel_backend.cc.bak_20260809_failopen:2686-2697, the health check's
// own copy of the same test. `true` is "healthy, stop checking".
bool LegacyHealthShortCircuitsToHealthy(const std::string& status) {
  if (status.empty()) return true;
  return status.find("\"awg_classification\":\"configured-h1h4\"") ==
         std::string::npos;
}

// ---------------------------------------------------------------------------

void TestHeadersClassify() {
  LinuxWinnParams blank;
  Check(!LinuxWinnHeadersClassify(blank),
        "a default-constructed params has four degenerate 0..0 ranges that "
        "overlap pairwise, so it does not classify");

  Check(LinuxWinnHeadersClassify(ParamsWithHeaders(1, 2, 3, 4)),
        "vanilla WireGuard's 1/2/3/4 are four distinct scalars and classify");

  // A real served table: large, distinct, non-overlapping scalars.
  Check(LinuxWinnHeadersClassify(
            ParamsWithHeaders(1194731, 87104561, 1616794723, 1231234123)),
        "a served h1..h4 scalar table classifies");

  Check(!LinuxWinnHeadersClassify(ParamsWithHeaders(5, 5, 3, 4)),
        "two equal header types are ambiguous and must not classify");

  // Ranges, which ParseLinuxWinnSection also accepts via ParseHeaderSpec.
  LinuxWinnParams ranges;
  ranges.h[0] = LinuxAwgHeaderSpec{16777216, 1086324735};
  ranges.h[1] = LinuxAwgHeaderSpec{1086324736, 2155872255};
  ranges.h[2] = LinuxAwgHeaderSpec{2155872256, 3225419775};
  ranges.h[3] = LinuxAwgHeaderSpec{3225419776, 4294967295u};
  Check(LinuxWinnHeadersClassify(ranges),
        "four adjacent but non-overlapping ranges classify");

  LinuxWinnParams touching = ranges;
  touching.h[1].start = touching.h[0].end;  // one shared value is an overlap
  Check(!LinuxWinnHeadersClassify(touching),
        "ranges sharing a single value overlap and must not classify");

  LinuxWinnParams inverted = ParamsWithHeaders(1, 2, 3, 4);
  inverted.h[2].start = 900;
  inverted.h[2].end = 100;
  Check(!LinuxWinnHeadersClassify(inverted),
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
                                nullptr) == WinnTransportGate::kNotYetObserved,
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

  Check(DecideWinnTransportGate(false, "", nullptr) ==
            WinnTransportGate::kCannotObserve,
        "the permanent refusal does not depend on the engine answering, so it "
        "costs no part of the convergence budget");
}

// REQUIREMENT, carried over from the Windows lane: the refusal reason reaches
// the user through the method channel, and the status document carries the
// customer's `gateway_endpoint`. No reason string may contain any part of it.
//
// Swept over every reachable (host_headers_classify, status) combination rather
// than over the two or three that happen to be interesting, because the point
// is a property of the function and not of a sample.
void TestNoReasonEverQuotesTheEndpoint() {
  const std::vector<std::string> documents = {
      "",
      StatusJson("configured-h1h4", true),
      StatusJson("configured-h1h4", false),
      StatusJson("wireguard-default-1234", true),
      StatusJson("wireguard-default-1234", false),
      // Renamed field, endpoint still present.
      "{\"gateway_endpoint\":\"203.0.113.9:51820\",\"classifier\":"
      "\"configured-h1h4\",\"transport_observed_both_ways\":false}",
      // Pretty-printed, endpoint still present.
      "{\"gateway_endpoint\": \"203.0.113.9:51820\", \"awg_classification\": "
      "\"configured-h1h4\", \"transport_observed_both_ways\": false}",
      // No proof field at all.
      "{\"gateway_endpoint\":\"203.0.113.9:51820\",\"up\":true}",
  };
  int inspected = 0;
  for (const bool classifies : {true, false}) {
    for (const std::string& document : documents) {
      std::string reason = "sentinel";
      DecideWinnTransportGate(classifies, document, &reason);
      ++inspected;
      Check(reason.find(kEndpointHost) == std::string::npos,
            "no gate reason contains the gateway host address");
      Check(reason.find(kEndpointPort) == std::string::npos,
            "no gate reason contains the gateway port");
      Check(reason.find(kEndpoint) == std::string::npos,
            "no gate reason contains the gateway endpoint");
      Check(reason != "sentinel",
            "every gate outcome either writes a reason or clears it, so a "
            "caller never reports a stale one from a previous tick");
    }
  }
  Check(inspected == 16, "the endpoint sweep covered every combination");
}

// THE DIFFERENTIAL. Same inputs, old logic beside new, on the three shapes the
// substring match could not survive.
void TestOldGateVersusNew() {
  struct Case {
    const char* name;
    std::string status;
  };
  // Every one of these is a session with NO PROOF: transport_observed_both_ways
  // is false or absent in all four. A correct gate promotes on none of them.
  const Case cases[] = {
      {"blind classifier (engine reports wireguard-default-1234)",
       StatusJson("wireguard-default-1234", false)},
      {"pretty-printed reply (space after the colon)",
       "{\"gateway_endpoint\":\"203.0.113.9:51820\",\"awg_classification\": "
       "\"configured-h1h4\",\"transport_observed_both_ways\": false}"},
      {"renamed field (awg_classification -> classifier)",
       "{\"gateway_endpoint\":\"203.0.113.9:51820\",\"classifier\":"
       "\"configured-h1h4\",\"transport_observed_both_ways\":false}"},
      {"dropped field (schema skew, key absent entirely)",
       "{\"gateway_endpoint\":\"203.0.113.9:51820\",\"up\":true,"
       "\"transport_observed_both_ways\":false}"},
  };
  int old_promoted = 0;
  for (const Case& item : cases) {
    const bool legacy = LegacyGateTickPromotes(item.status);
    std::string reason;
    // true: the host DID supply a complete h1..h4 table in every one of these,
    // which is the whole point -- the config is fine, only the reply's spelling
    // differs, and the old gate turned itself off on the spelling.
    const WinnTransportGate now =
        DecideWinnTransportGate(true, item.status, &reason);
    if (legacy) ++old_promoted;
    std::printf("  %-52s  old=%-9s new=%s\n", item.name,
                legacy ? "PROMOTE" : "wait",
                now == WinnTransportGate::kObserved ? "PROMOTE" : "REFUSE");
    Check(now != WinnTransportGate::kObserved,
          std::string("the new gate refuses to promote without proof: ") +
              item.name);
    Check(reason.find(kEndpointHost) == std::string::npos,
          std::string("the differential reason carries no endpoint: ") +
              item.name);
  }
  Check(old_promoted == 4,
        "all four of these shapes made the PRE-FIX gate promote without "
        "proof -- if this ever stops holding, the transcribed legacy logic no "
        "longer matches what shipped and this differential proves nothing");

  // The health check's own copy of the defect, differentially.
  int old_switched_off = 0;
  for (const Case& item : cases) {
    if (LegacyHealthShortCircuitsToHealthy(item.status)) ++old_switched_off;
  }
  Check(old_switched_off == 4,
        "ALL FOUR shapes also switched the pre-fix health check off for the "
        "whole session -- it tested the same compact substring, so the "
        "pretty-printed reply defeated it too, and the 105 s silent blackout "
        "that check exists to catch would then have run unbounded");

  // And the case both old and new agree on, so the differential is not simply
  // "the new one always refuses".
  Check(LegacyGateTickPromotes(StatusJson("configured-h1h4", true)) &&
            DecideWinnTransportGate(true, StatusJson("configured-h1h4", true),
                                    nullptr) == WinnTransportGate::kObserved,
        "a genuinely converged session promotes under both, so the fix is a "
        "narrowing of the fail-open and not a refusal of everything");
}

// The two halves must agree by construction: anything ParseLinuxWinnSection
// accepts classifies, and a params that classifies is one BuildLinuxWinn
// ConfigJson emits awg_header_types for. That second property is what makes the
// host-side boolean a true statement about the document the engine got.
void TestClassifyAgreesWithTheDocumentTheEngineReceives() {
  // BuildLinuxWinnConfigJson's own condition (linux_winn_host.cc:1919-1920),
  // restated here because that function needs <sstream> and lives in the .cc.
  const auto emits_header_types = [](const LinuxWinnParams& params) {
    return params.h[0].start != 0 || params.h[1].start != 0 ||
           params.h[2].start != 0 || params.h[3].start != 0;
  };
  Check(emits_header_types(ParamsWithHeaders(1, 2, 3, 4)) &&
            LinuxWinnHeadersClassify(ParamsWithHeaders(1, 2, 3, 4)),
        "a classifying table is one the Create document carries");
  // At most one of four pairwise-distinct specs can start at zero, so a
  // classifying params always has a nonzero start somewhere.
  Check(emits_header_types(ParamsWithHeaders(0, 1, 2, 3)) &&
            LinuxWinnHeadersClassify(ParamsWithHeaders(0, 1, 2, 3)),
        "h1 = 0 is legal and still emits awg_header_types");
  LinuxWinnParams blank;
  Check(!emits_header_types(blank) && !LinuxWinnHeadersClassify(blank),
        "the empty table neither classifies nor is sent");
}

// The Windows and Linux predicates are the same decision written twice, and the
// two hosts must not drift. This is the property, restated over the Linux copy:
// classification is exactly "four well-formed, pairwise non-overlapping
// ranges", with no dependence on anything outside the params.
void TestPredicateIsPurelyHostSide() {
  const LinuxWinnParams served =
      ParamsWithHeaders(1194731, 87104561, 1616794723, 1231234123);
  // Every status document in the world, over one fixed params: the predicate is
  // not a function of any of them, and neither is the kCannotObserve verdict.
  const std::vector<std::string> documents = {
      "", StatusJson("configured-h1h4", true),
      StatusJson("wireguard-default-1234", false), "{}", "not json at all"};
  for (const std::string& document : documents) {
    Check(DecideWinnTransportGate(LinuxWinnHeadersClassify(served), document,
                                  nullptr) != WinnTransportGate::kCannotObserve,
          "a classifiable host config is never permanently refused, whatever "
          "the reply says");
    LinuxWinnParams unusable;
    Check(DecideWinnTransportGate(LinuxWinnHeadersClassify(unusable), document,
                                  nullptr) == WinnTransportGate::kCannotObserve,
          "an unclassifiable host config is always permanently refused, "
          "whatever the reply says");
  }
}

}  // namespace

int main() {
  TestHeadersClassify();
  TestJsonFieldIsTrue();
  TestGateRefusesWhatItCannotObserve();
  TestGateObservesRealProof();
  TestHostSideConfigIsWhatDecidesRefusal();
  TestNoReasonEverQuotesTheEndpoint();
  std::printf("differential, pre-fix logic vs the gate that replaced it:\n");
  TestOldGateVersusNew();
  TestClassifyAgreesWithTheDocumentTheEngineReceives();
  TestPredicateIsPurelyHostSide();
  if (failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("linux_winn_gate_test: all checks passed\n");
  return 0;
}
