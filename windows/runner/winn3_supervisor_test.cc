// Tests for the Windows Winn Protocol v3 supervisor's decidable half.
//
// WHY THIS FILE EXISTS. windows/winn3_engine/ (the Wintun adapter owner) and
// windows/runner/winn3_posture.h (the staged-posture policy) were both written
// and both tested, and NOTHING STARTED EITHER: RenderWindowsPostureCommands had
// no caller on Windows at all. winn3_supervisor.h is the missing middle, and
// the things it decides are the things that decide whether the tunnel encrypts
// (`device.kind`), whether full-size flows survive (the inner MTU), and when a
// user's default route moves (the promotion verdict).
//
// There is NO WINDOWS HOST on the machine this project is developed on. A
// decision that only Windows can execute is a decision that does not get
// tested, so every one of those decisions lives in a header with no
// <windows.h>, and this program exercises them here. The precedent is
// windows/runner/windows_winn_gate_test.cc, linux/runner/winn3_posture_test.cc
// and linux/runner/linux_winn_carrier_profile_test.cc -- standalone programs
// with their own main, none of them in either CMake target's explicit source
// list, so none of them can reach a shipped binary.
//
// Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -Werror -o /tmp/winn3_supervisor_test \
//       windows/runner/winn3_supervisor_test.cc && /tmp/winn3_supervisor_test
//
// The cross-language half of the contract -- that these parsers consume what
// the Go processes actually emit -- is asserted here against literals copied
// from windows/winn3_engine/main_windows.go and
// winn_protocol_experimental/cmd/winn-datapath/winn3_run.go, and is checked
// against a REAL engine document by tools/verify_winn3_windows_supervisor.sh.

#include "winn3_supervisor.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const std::string& what) {
  if (!condition) {
    ++failures;
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
  }
}

std::string EncodeStdBase64(const std::string& raw) {
  static const char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((raw.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i + 3 <= raw.size()) {
    const uint32_t block = (static_cast<uint32_t>(
                                static_cast<unsigned char>(raw[i]))
                            << 16) |
                           (static_cast<uint32_t>(
                                static_cast<unsigned char>(raw[i + 1]))
                            << 8) |
                           static_cast<uint32_t>(
                               static_cast<unsigned char>(raw[i + 2]));
    out.push_back(kTable[(block >> 18) & 63]);
    out.push_back(kTable[(block >> 12) & 63]);
    out.push_back(kTable[(block >> 6) & 63]);
    out.push_back(kTable[block & 63]);
    i += 3;
  }
  const size_t remain = raw.size() - i;
  if (remain == 1) {
    const uint32_t block =
        static_cast<uint32_t>(static_cast<unsigned char>(raw[i])) << 16;
    out.push_back(kTable[(block >> 18) & 63]);
    out.push_back(kTable[(block >> 12) & 63]);
    out += "==";
  } else if (remain == 2) {
    const uint32_t block =
        (static_cast<uint32_t>(static_cast<unsigned char>(raw[i])) << 16) |
        (static_cast<uint32_t>(static_cast<unsigned char>(raw[i + 1])) << 8);
    out.push_back(kTable[(block >> 18) & 63]);
    out.push_back(kTable[(block >> 12) & 63]);
    out.push_back(kTable[(block >> 6) & 63]);
    out.push_back('=');
  }
  return out;
}

std::string DualAuthEd25519B64() { return EncodeStdBase64(std::string(32, '\xAA')); }
std::string DualAuthMldsa65B64() {
  return EncodeStdBase64(std::string(1952, '\xBB'));
}

using winsvpn::winn3::BuildBootstrapPosture;
using winsvpn::winn3::BuildPromotedPosture;
using winsvpn::winn3::BuildWinn3ProfileJson;
using winsvpn::winn3::ClassifyWinn3ProofDiagnostic;
using winsvpn::winn3::ClassifyWinn3StartFailure;
using winsvpn::winn3::ConfigSelectsWinn1;
using winsvpn::winn3::ConfigSelectsWinn3;
using winsvpn::winn3::DecideWinn3Promotion;
using winsvpn::winn3::EngineStatus;
using winsvpn::winn3::Winn3ConfigWithKeyPaths;
using winsvpn::winn3::Winn3KeyFile;
using winsvpn::winn3::Winn3KeyFilesFor;
using winsvpn::winn3::InnerIPv6IsArithmeticallyPossible;
using winsvpn::winn3::kDialledUdpV4InnerMTU;
using winsvpn::winn3::kIPv6SinkAddress;
using winsvpn::winn3::kShippingFloorInnerMTU;
using winsvpn::winn3::NormalizeWinn3NodeIdentity;
using winsvpn::winn3::ValidateWinn3IndependentSelectedNode;
using winsvpn::winn3::ParseEngineSeamPort;
using winsvpn::winn3::ParseRelayHostPort;
using winsvpn::winn3::ParseRelayReady;
using winsvpn::winn3::ParseWinn3Section;
using winsvpn::winn3::ParseWinn3StatusLine;
using winsvpn::winn3::PostureInput;
using winsvpn::winn3::PosturePlan;
using winsvpn::winn3::PostureInputFrom;
using winsvpn::winn3::PromotedCommandDelta;
using winsvpn::winn3::QuoteWin32Argument;
using winsvpn::winn3::RenderStartCommand;
using winsvpn::winn3::RenderWin32CommandLine;
using winsvpn::winn3::RenderWindowsPostureCommands;
using winsvpn::winn3::SplitWinn3Endpoint;
using winsvpn::winn3::VerifyAppliedMtuStillAgrees;
using winsvpn::winn3::VerifyBootstrapIsNarrow;
using winsvpn::winn3::VerifyPromotedCommandsCapture;
using winsvpn::winn3::VerifyPublishedInnerMtu;
using winsvpn::winn3::Winn3HostConfig;
using winsvpn::winn3::Winn3PromotionVerdict;
using winsvpn::winn3::Winn3ProofOutcome;
using winsvpn::winn3::Winn3RelayReady;
using winsvpn::winn3::Winn3StartProofAuthorizesOrdinaryFallback;

// A complete, valid [winn3] section. Every test that wants a broken one starts
// from this and breaks exactly one thing.
const char kGoodConfig[] =
    "[Interface]\n"
    "PrivateKey = irrelevant\n"
    "\n"
    "[winn3]\n"
    "enabled = true\n"
    "endpoint = 198.51.100.7:443\n"
    "class = udp\n"
    "plan = udp, tcp, tls\n"
    "path_mtu = 1280\n"
    "gateway_id = kansas-1\n"
    "node = lab-alpha\n"
    "selected_node = lab-alpha\n"
    "inner_v4 = 10.9.0.2\n"
    "router_v4 = 10.9.0.1\n"
    "static_key_path = C:\\ProgramData\\WinsVPN\\winn3\\static.key\n"
    "gateway_static_key_path = C:\\ProgramData\\WinsVPN\\winn3\\gateway.pub\n"
    "admission_path = C:\\ProgramData\\WinsVPN\\winn3\\admission\n";

Winn3HostConfig GoodConfig() {
  Winn3HostConfig config;
  std::string error;
  if (!ParseWinn3Section(kGoodConfig, &config, &error)) {
    std::fprintf(stderr, "FATAL: the good config does not parse: %s\n",
                 error.c_str());
    ++failures;
  }
  return config;
}

// A status document with the shape winn3_status.go emits at the shipping floor.
EngineStatus CarryingStatus() {
  EngineStatus status;
  status.valid = true;
  status.promotion_ready = true;
  status.event = "carrying";
  status.posture = "promoted";
  status.gate_state = "carrying";
  status.rx_packets = 12;
  status.rx_offered = 12;
  status.inner_mtu = kShippingFloorInnerMTU;
  status.message_size = 1168;
  status.inner_ipv6 = false;
  return status;
}

// --- section parsing --------------------------------------------------------

void TestSelectionIsItsOwnSection() {
  Check(ConfigSelectsWinn3(kGoodConfig),
        "[winn3] enabled = true selects the v3 path");
  Check(!ConfigSelectsWinn1(kGoodConfig),
        "a [winn3] config does not select the winn/1 path");
  // The shipping AmneziaWG-carried path, untouched.
  const std::string v1 = "[winn]\nenabled = true\nendpoint = 1.2.3.4:51820\n";
  Check(ConfigSelectsWinn1(v1), "[winn] enabled = true still selects winn/1");
  Check(!ConfigSelectsWinn3(v1),
        "a winn/1 config must never select the v3 supervisor: it carries "
        "AmneziaWG outer datagrams, and an inner-packet relay would put "
        "cleartext on the wire");
  Check(!ConfigSelectsWinn3(""), "an empty config selects nothing");
  Check(!ConfigSelectsWinn3("[winn3]\nenabled = false\n"),
        "enabled = false selects nothing");
  Check(!ConfigSelectsWinn3("enabled = true\n"),
        "a bare enabled outside any section selects nothing");
  Check(!ConfigSelectsWinn3("[other]\nenabled = true\n"),
        "enabled = true in another section selects nothing");
  Check(ConfigSelectsWinn3("[WINN3]\nENABLED = TRUE\n"),
        "the section and key are matched case-insensitively");
  Check(!ConfigSelectsWinn3("[winn3]\n# enabled = true\n"),
        "a commented-out enabled selects nothing");
}

// ===========================================================================
// THE SERVED `[winn]` SECTION
// ===========================================================================
//
// kServedConfig is BYTE FOR BYTE what winn3/conform's ServedWinnSectionINI
// renders for the reference operator -- the same document Apple, Android and
// Linux are fed. TestTheServedFixtureIsTheOneEveryHostParses in
// winn_protocol_experimental/winn3/conform/conform_test.go greps this file for
// it, so the two cannot drift: a fixture that quietly stopped matching the
// contract would make this whole test a test of itself.
//
// The values are chosen adversarially and each one is a defect that shipped:
//
//	gateway_id      base64 over `winsgw01` -- EIGHT characters of the base64
//	                alphabet, so a host that decodes it TWICE gets six entirely
//	                plausible bytes rather than an error.
//	admission_key   base64 over the key FILE'S 64 ASCII hex characters. Base64
//	                over the 32 bytes they encode is the encoding that builds a
//	                session and then goes silent.
//	path_mtu 1500   named rather than defaulted, so a host substituting its own
//	                1280 is caught instead of accidentally agreeing.
//	three classes   so the floor is 84 bytes below the dialled UDP/IPv4 number.
constexpr char kServedConfig[] =
    "[winn]\n"
    "enabled = true\n"
    "carrier = winn3\n"
    "endpoint = 203.0.113.7:51820\n"
    "node = lab-alpha\n"
    "selected_node = lab-alpha\n"
    "inner_v4 = 10.10.0.9\n"
    "inner_router_v4 = 10.10.0.1\n"
    "inner_resolver_v4 = 10.10.0.1\n"
    "static_private = ERERERERERERERERERERERERERERERERERERERERERE=\n"
    "gateway_static = U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=\n"
    "gateway_id = d2luc2d3MDE=\n"
    "admission_key = NmYzOWEwYzFkMjRiN2U4ZjVhM2M5MDEyYjRkNmU4ZjAxYTJiM2M0ZDVl"
    "NmY3MDgxOTJhM2I0YzVkNmU3ZjgwOQ==\n"
    "path_mtu = 1500\n"
    "carrier_classes = udp,tcp,tls\n";

void TestTheServedSectionSelectsV3AndNotWinn1() {
  Check(ConfigSelectsWinn3(kServedConfig),
        "a served [winn] carrier = winn3 config selects the v3 supervisor. "
        "Until 2026-08-09 it selected NEITHER -- this file parsed [winn3], "
        "which nothing anywhere emits -- so every served standalone config was "
        "handed to the winn/1 parser instead");
  Check(!ConfigSelectsWinn1(kServedConfig),
        "and it is NOT a winn/1 config. `carrier` is the discriminator on both "
        "sides: ParseWindowsWinnSection refuses any carrier but direct-awg by "
        "name, so the two parsers cannot both claim one configuration");

  // The winn/1 path, untouched, and still refused by the v3 supervisor.
  const std::string awg =
      "[winn]\nenabled = true\ncarrier = direct-awg\nendpoint = 1.2.3.4:51820\n";
  Check(ConfigSelectsWinn1(awg), "direct-awg still selects winn/1");
  Check(!ConfigSelectsWinn3(awg),
        "an AmneziaWG-carried config must never reach the inner-packet relay: "
        "that mistake puts cleartext on the wire");
}

void TestTheServedSectionParsesIntoTheSameSession() {
  Winn3HostConfig config;
  std::string error;
  Check(ParseWinn3Section(kServedConfig, &config, &error),
        "the served section parses: " + error);
  Check(config.section == "winn", "it records which spelling it came from");
  Check(config.endpoint == "203.0.113.7:51820", "endpoint");
  Check(config.inner_v4 == "10.10.0.9", "inner_v4 is the v3 gateway's space");
  Check(config.router_v4 == "10.10.0.1",
        "inner_router_v4 lands on router_v4, which is the [winn3] name for the "
        "same field and the one the engine's profile uses");
  Check(config.path_mtu == 1500, "path_mtu is the one the section named");
  Check(config.plan.size() == 3 && config.plan[0] == "udp" &&
            config.plan[1] == "tcp" && config.plan[2] == "tls",
        "carrier_classes is the migration plan the floor is computed over");
  Check(config.carrier_class == "udp",
        "udp is the dialled class, and not a convenience default: a tls "
        "carrier needs a *tls.Config the engine process never receives, so udp "
        "is the only class it can dial at all");

  // THE ONE DECODE. The profile takes the operator's gateway NAME, byte for
  // byte what `winn3-gateway -gateway-id` was given, because the admission tag
  // is computed over it and never transmitted.
  Check(config.gateway_id == "winsgw01",
        "gateway_id is decoded exactly once, here, at the descriptor boundary");
  Check(config.gateway_id != "d2luc2d3MDE=",
        "the transport base64 does not survive into the profile");
  Check(config.descriptor_node == "lab-alpha" &&
            config.selected_node == "lab-alpha",
        "the served section binds the signed descriptor node to the selected "
        "node before any credential file is implied");

  const std::string profile = BuildWinn3ProfileJson(
      Winn3ConfigWithKeyPaths(config, "C:\\ProgramData\\WinsVPN"), 49152,
      "pinned /32");
  Check(profile.find("\"gateway_id\":\"winsgw01\"") != std::string::npos,
        "and the engine's document carries the operator name");
  // A SECOND decode would give these six bytes. `winsgw01` decodes cleanly, so
  // nothing about the wrong answer looks wrong -- which is exactly why this is
  // checked rather than assumed.
  Check(profile.find("\"gateway_id\":\"\\u00c2\\u00b1") == std::string::npos,
        "and never a doubly-decoded one");
}

void ExpectNodeBindingRefused(const std::string& raw, const char* why) {
  Winn3HostConfig config;
  std::string error;
  Check(!ParseWinn3Section(raw, &config, &error), why);
  Check(error.find("node") != std::string::npos,
        std::string(why) + ": the refusal names the node field: " + error);
  Check(config.section.empty() && config.static_private_b64.empty() &&
            config.admission_key_b64.empty() && config.static_key_path.empty(),
        std::string(why) + ": a refused parse fills no session or credentials");
  std::vector<Winn3KeyFile> files;
  std::string key_error;
  Check(Winn3KeyFilesFor(config, &files, &key_error) && files.empty(),
        std::string(why) + ": no credential files after a binding refusal");
  Check(ClassifyWinn3ProofDiagnostic(error) ==
            Winn3ProofOutcome::kTerminalSecurity,
        std::string(why) + ": node binding is terminal security, got: " +
            error);
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(
            ClassifyWinn3StartFailure(21, false, error), 21),
        std::string(why) + ": must not authorize v1 fallback");
}

void TestTheServedSectionBindsTheSelectedNode() {
  for (const std::string& raw : {
           std::string(kServedConfig)
               .replace(std::string(kServedConfig)
                            .find("selected_node = lab-alpha\n"),
                        std::strlen("selected_node = lab-alpha\n"),
                        "selected_node = lab-beta\n"),
           std::string(kServedConfig)
               .replace(std::string(kServedConfig).find("node = lab-alpha\n"),
                        std::strlen("node = lab-alpha\n"), ""),
           std::string(kServedConfig) + "node = lab-alpha\n",
       }) {
    ExpectNodeBindingRefused(
        raw, "a missing, mismatched, or duplicate served node binding is "
             "refused");
  }
}

void TestNativeStartBindsTheIndependentPickerNode() {
  std::string error;
  Check(ValidateWinn3IndependentSelectedNode(kServedConfig, "Lab-Alpha", &error),
        "the independently selected ASCII picker slug binds: " + error);
  for (const std::string& caller : {
           std::string(), std::string("lab-beta"),
           std::string("\xE2\x84\xAA") + "1",
       }) {
    error.clear();
    Check(!ValidateWinn3IndependentSelectedNode(kServedConfig, caller, &error),
          "missing, conflicting, or Unicode picker identity is refused");
    Check(error.find("independently selected node") != std::string::npos,
          "the native caller-binding refusal names its independent source: " +
              error);
  }
}

void TestBothSpellingsRequireTheSameStrictAsciiNodeIdentity() {
  std::string identity;
  Check(NormalizeWinn3NodeIdentity("Lab-Alpha", &identity) &&
            identity == "lab-alpha",
        "ASCII mixed case folds without Unicode");
  Check(NormalizeWinn3NodeIdentity(" lab-alpha ", &identity) &&
            identity == "lab-alpha",
        "ASCII trim then slug");
  Check(!NormalizeWinn3NodeIdentity("\xE2\x84\xAA""1", &identity),
        "U+212A KELVIN SIGN must not fold onto k");
  Check(NormalizeWinn3NodeIdentity("k1", &identity) && identity == "k1",
        "ASCII k1 is a node identity");
  Check(!NormalizeWinn3NodeIdentity("l\xD0\xB0""b-alpha", &identity),
        "Cyrillic a is not a node identity");
  Check(!NormalizeWinn3NodeIdentity("lab-alpha\xE2\x80\x8B", &identity),
        "zero-width space is not a node identity");
  Check(!NormalizeWinn3NodeIdentity("lab-alpha\xC2\xA0", &identity),
        "NBSP is not a node identity");
  Check(!NormalizeWinn3NodeIdentity("lab_alpha", &identity),
        "underscore is outside the slug alphabet");
  Check(!NormalizeWinn3NodeIdentity("k", &identity),
        "a one-character slug is outside the 2..40 bound");
  Check(!NormalizeWinn3NodeIdentity("", &identity), "empty is missing");
  Check(!NormalizeWinn3NodeIdentity("   ", &identity),
        "whitespace-only is missing, not a match");

  // Local [winn3] mixed-case ASCII still binds, same as served.
  std::string mixed = kGoodConfig;
  mixed.replace(mixed.find("node = lab-alpha\n"),
                std::strlen("node = lab-alpha\n"), "node = Lab-Alpha\n");
  mixed.replace(mixed.find("selected_node = lab-alpha\n"),
                std::strlen("selected_node = lab-alpha\n"),
                "selected_node = LAB-ALPHA\n");
  Winn3HostConfig config;
  std::string error;
  Check(ParseWinn3Section(mixed, &config, &error),
        "local [winn3] ASCII mixed case binds: " + error);
  Check(config.section == "winn3" && config.descriptor_node == "lab-alpha" &&
            config.selected_node == "lab-alpha",
        "both spellings store the same ASCII identity");
  std::vector<Winn3KeyFile> none;
  Check(Winn3KeyFilesFor(config, &none, &error) && none.empty(),
        "a bound [winn3] config still implies no credential files");

  // The same mixed-case pair on the served spelling.
  std::string served_mixed = kServedConfig;
  served_mixed.replace(served_mixed.find("node = lab-alpha\n"),
                       std::strlen("node = lab-alpha\n"), "node = Lab-Alpha\n");
  served_mixed.replace(served_mixed.find("selected_node = lab-alpha\n"),
                       std::strlen("selected_node = lab-alpha\n"),
                       "selected_node = LAB-ALPHA\n");
  Check(ParseWinn3Section(served_mixed, &config, &error),
        "served [winn] ASCII mixed case binds: " + error);
  Check(config.section == "winn" && config.descriptor_node == "lab-alpha" &&
            config.selected_node == "lab-alpha",
        "served mixed-case stores the same ASCII identity");

  const std::string local_missing_selected = std::string(kGoodConfig)
      .replace(std::string(kGoodConfig).find("selected_node = lab-alpha\n"),
               std::strlen("selected_node = lab-alpha\n"), "");
  const std::string local_missing_node = std::string(kGoodConfig)
      .replace(std::string(kGoodConfig).find("node = lab-alpha\n"),
               std::strlen("node = lab-alpha\n"), "");
  const std::string local_replay = std::string(kGoodConfig)
      .replace(std::string(kGoodConfig).find("selected_node = lab-alpha\n"),
               std::strlen("selected_node = lab-alpha\n"),
               "selected_node = lab-beta\n");
  const std::string local_duplicate =
      std::string(kGoodConfig) + "selected_node = lab-alpha\n";
  const std::string local_kelvin = std::string(kGoodConfig)
      .replace(std::string(kGoodConfig).find("selected_node = lab-alpha\n"),
               std::strlen("selected_node = lab-alpha\n"),
               "selected_node = \xE2\x84\xAA""1\n");
  std::string local_matching_kelvin = kGoodConfig;
  local_matching_kelvin.replace(
      local_matching_kelvin.find("node = lab-alpha\n"),
      std::strlen("node = lab-alpha\n"), "node = \xE2\x84\xAA""1\n");
  local_matching_kelvin.replace(
      local_matching_kelvin.find("selected_node = lab-alpha\n"),
      std::strlen("selected_node = lab-alpha\n"),
      "selected_node = \xE2\x84\xAA""1\n");
  const std::string served_kelvin = std::string(kServedConfig)
      .replace(std::string(kServedConfig).find("selected_node = lab-alpha\n"),
               std::strlen("selected_node = lab-alpha\n"),
               "selected_node = \xE2\x84\xAA""1\n");
  const std::string served_cyrillic = std::string(kServedConfig)
      .replace(std::string(kServedConfig).find("selected_node = lab-alpha\n"),
               std::strlen("selected_node = lab-alpha\n"),
               "selected_node = l\xD0\xB0""b-alpha\n");

  ExpectNodeBindingRefused(local_missing_selected,
                           "local [winn3] cannot skip a missing selected node");
  ExpectNodeBindingRefused(local_missing_node,
                           "local [winn3] cannot skip a missing descriptor node");
  ExpectNodeBindingRefused(local_replay,
                           "local [winn3] cross-node replay is refused");
  ExpectNodeBindingRefused(local_duplicate,
                           "local [winn3] duplicate selected_node is an alias "
                           "conflict");
  ExpectNodeBindingRefused(local_kelvin,
                           "local [winn3] Kelvin selected node cannot bind");
  ExpectNodeBindingRefused(
      local_matching_kelvin,
      "matching Unicode on both fields is still not a node identity");
  ExpectNodeBindingRefused(served_kelvin,
                           "served Kelvin selected node cannot bind to lab-alpha");
  ExpectNodeBindingRefused(served_cyrillic,
                           "served Cyrillic homoglyph cannot bind");

  // Extra INI spellings are not aliases. A first-wins or silent-accept of
  // node_slug/selectednode would be the Dart map hole; native INI refuses
  // the unrecognised key before credentials.
  for (const std::string& raw :
       {std::string(kServedConfig) + "node_slug = lab-alpha\n",
        std::string(kGoodConfig) + "selectednode = lab-alpha\n"}) {
    Winn3HostConfig extra;
    std::string extra_error;
    Check(!ParseWinn3Section(raw, &extra, &extra_error),
          "an INI alias spelling is unrecognised, not silently bound");
    Check(extra_error.find("unrecognised") != std::string::npos,
          "the alias refusal names the unrecognised key: " + extra_error);
    Check(extra.static_private_b64.empty() && extra.admission_key_b64.empty(),
          "an alias spelling fills no credentials");
    std::vector<Winn3KeyFile> extra_files;
    Check(Winn3KeyFilesFor(extra, &extra_files, &extra_error) &&
              extra_files.empty(),
          "an alias spelling implies no credential files");
    Check(!Winn3StartProofAuthorizesOrdinaryFallback(
              ClassifyWinn3StartFailure(21, false, extra_error), 21),
          "an unrecognised node alias must not authorize v1 fallback");
  }
}

void TestTheServedKeyMaterialBecomesFilesAndNeverEntersTheProfile() {
  Winn3HostConfig config;
  std::string error;
  Check(ParseWinn3Section(kServedConfig, &config, &error), "parse: " + error);

  std::vector<Winn3KeyFile> files;
  Check(Winn3KeyFilesFor(config, &files, &error),
        "the served key material yields files: " + error);
  Check(files.size() == 3, "three files: static, gateway public, admission");
  Check(files[0].name == "static.key" && files[0].contents.size() == 32,
        "the static private key is 32 RAW bytes, which winn3ReadKeyFile takes");
  Check(files[1].name == "gateway.pub" && files[1].contents.size() == 32,
        "and so is the gateway's public key");

  // THE OPAQUE ONE. 64 bytes, not 32: keygen writes 64 ASCII hex characters and
  // every consumer keys with THOSE CHARACTERS. Writing the 32 they encode gives
  // a gateway that admits the datagram, BUILDS a session, and then answers
  // nothing at all -- worse than a refusal, because a host watching for "did
  // the gateway see me" sees yes.
  Check(files[2].name == "admission.key" && files[2].contents.size() == 64,
        "the admission secret is the key file's 64 ASCII hex characters");
  Check(files[2].contents ==
            "6f39a0c1d24b7e8f5a3c9012b4d6e8f01a2b3c4d5e6f708192a3b4c5d6e7f809",
        "verbatim, and never hex-decoded");

  // And the profile the engine reads still holds NO key material. That was the
  // property the old paths-only rule protected, and it survives the change:
  // what could not survive was a host that would ONLY read paths, because the
  // control plane cannot name a path on a device it has never seen.
  const Winn3HostConfig with_paths =
      Winn3ConfigWithKeyPaths(config, "C:\\ProgramData\\WinsVPN");
  const std::string profile =
      BuildWinn3ProfileJson(with_paths, 49152, "pinned /32");
  for (const Winn3KeyFile& file : files) {
    Check(profile.find(file.contents) == std::string::npos,
          "the profile document holds no key material (" + file.name + ")");
  }
  Check(profile.find("<REDACTED_WG_KEY>") ==
            std::string::npos,
        "nor the base64 the section carried");
  Check(profile.find("static.key") != std::string::npos &&
            profile.find("gateway.pub") != std::string::npos &&
            profile.find("admission.key") != std::string::npos,
        "it names the three paths this supervisor will write");

  // A [winn3] configuration names files somebody else wrote and implies none.
  Winn3HostConfig lab = GoodConfig();
  std::vector<Winn3KeyFile> none;
  Check(Winn3KeyFilesFor(lab, &none, &error) && none.empty(),
        "a [winn3] config implies no files: it names paths directly");
}

void TestTheServedDualAuthPairIsConsumedAndBound() {
  const std::string dual = std::string(kServedConfig) +
                           "auth_ed25519 = " + DualAuthEd25519B64() +
                           "\nauth_mldsa65 = " + DualAuthMldsa65B64() + "\n";
  Winn3HostConfig config;
  std::string error;
  Check(ParseWinn3Section(dual, &config, &error),
        "a served section carrying both dual-auth keys parses: " + error);
  Check(!config.auth_ed25519_b64.empty() && !config.auth_mldsa65_b64.empty(),
        "both dual-auth values are stored");

  std::vector<Winn3KeyFile> files;
  Check(Winn3KeyFilesFor(config, &files, &error),
        "the dual-auth pair becomes files: " + error);
  Check(files.size() == 5,
        "five files: static, gateway public, admission, both dual-auth pubs");
  Check(files[3].name == "auth_ed25519.pub" && files[3].contents.size() == 64,
        "the Ed25519 pub is 64 lowercase hex characters");
  Check(files[3].contents == std::string(64, 'a'),
        "0xAA hex-encodes to sixty-four a's");
  Check(files[4].name == "auth_mldsa65.pub" && files[4].contents.size() == 3904,
        "the ML-DSA-65 pub is 3904 lowercase hex characters");
  Check(files[4].contents == std::string(3904, 'b'),
        "0xBB hex-encodes to 3904 b's");

  const Winn3HostConfig with_paths =
      Winn3ConfigWithKeyPaths(config, "C:\\ProgramData\\WinsVPN");
  Check(with_paths.dual_auth_ed25519_pub_path.find("auth_ed25519.pub") !=
            std::string::npos,
        "the profile path names auth_ed25519.pub");
  Check(with_paths.dual_auth_mldsa65_pub_path.find("auth_mldsa65.pub") !=
            std::string::npos,
        "the profile path names auth_mldsa65.pub");
  const std::string profile =
      BuildWinn3ProfileJson(with_paths, 49152, "pinned /32");
  Check(profile.find("\"dual_auth_ed25519_pub_path\"") != std::string::npos &&
            profile.find("\"dual_auth_mldsa65_pub_path\"") != std::string::npos,
        "the engine document binds both dual-auth paths");
  Check(profile.find(files[3].contents) == std::string::npos &&
            profile.find(DualAuthEd25519B64()) == std::string::npos,
        "the profile still holds no dual-auth key material");
}

void TestTheServedDualAuthPairRefusesMismatchMissingAndStale() {
  Winn3HostConfig config;
  std::string error;

  const std::string missing_ml = std::string(kServedConfig) +
                                 "auth_ed25519 = " + DualAuthEd25519B64() +
                                 "\n";
  Check(!ParseWinn3Section(missing_ml, &config, &error),
        "a missing auth_mldsa65 half is refused");
  Check(error.find("auth_ed25519") != std::string::npos &&
            error.find("auth_mldsa65") != std::string::npos,
        "the half-provision refusal names both keys: " + error);

  const std::string missing_ed = std::string(kServedConfig) +
                                 "auth_mldsa65 = " + DualAuthMldsa65B64() +
                                 "\n";
  Check(!ParseWinn3Section(missing_ed, &config, &error),
        "a missing auth_ed25519 half is refused");

  const std::string short_ed =
      std::string(kServedConfig) + "auth_ed25519 = " +
      EncodeStdBase64(std::string(31, '\xAA')) +
      "\nauth_mldsa65 = " + DualAuthMldsa65B64() + "\n";
  Check(!ParseWinn3Section(short_ed, &config, &error),
        "a 31-byte Ed25519 key is a length mismatch");
  Check(error.find("auth_ed25519") != std::string::npos,
        "the mismatch names auth_ed25519: " + error);

  const std::string swapped =
      std::string(kServedConfig) + "auth_ed25519 = " + DualAuthMldsa65B64() +
      "\nauth_mldsa65 = " + DualAuthEd25519B64() + "\n";
  Check(!ParseWinn3Section(swapped, &config, &error),
        "swapped dual-auth sizes are a mismatch");

  const std::string not_b64 = std::string(kServedConfig) +
                              "auth_ed25519 = not base64!\n"
                              "auth_mldsa65 = " +
                              DualAuthMldsa65B64() + "\n";
  Check(!ParseWinn3Section(not_b64, &config, &error),
        "a dual-auth value that is not base64 is refused");

  Check(ParseWinn3Section(kServedConfig, &config, &error),
        "a legacy served section without the pair still parses: " + error);
  Check(config.auth_ed25519_b64.empty() && config.auth_mldsa65_b64.empty(),
        "legacy parse stores no stale dual-auth values");
  std::vector<Winn3KeyFile> files;
  Check(Winn3KeyFilesFor(config, &files, &error) && files.size() == 3,
        "a legacy session implies only the three original files");
  const Winn3HostConfig with_paths =
      Winn3ConfigWithKeyPaths(config, "C:\\ProgramData\\WinsVPN");
  Check(with_paths.dual_auth_ed25519_pub_path.empty() &&
            with_paths.dual_auth_mldsa65_pub_path.empty(),
        "a legacy session does not bind leftover dual-auth paths");
  const std::string profile =
      BuildWinn3ProfileJson(with_paths, 49152, "pinned /32");
  Check(profile.find("dual_auth_") == std::string::npos,
        "a stale dual-auth pair is not rebound into the engine document");
}

void TestTheServedSectionRefusesTheEncodingMistakesThatAreSilent() {
  struct Case {
    const char* replace;
    const char* with;
    const char* names;
    const char* why;
  };
  const Case cases[] = {
      {"gateway_id = d2luc2d3MDE=", "gateway_id = not base64!", "gateway_id",
       "a gateway_id that is not base64 over an operator name"},
      {"static_private = ERERERERERERERERERERERERERERERERERERERERERE=",
       "static_private = 1f1f1f1f", "static_private",
       "a key that is not 32 bytes. X25519 has exactly one length"},
      {"static_private = ERERERERERERERERERERERERERERERERERERERERERE=",
       "static_private = not base64!", "static_private", "not base64 at all"},
      // URL-SAFE base64. The descriptor never uses it, and a decoder lenient
      // enough to accept it would produce DIFFERENT key bytes for two values an
      // operator would call the same -- silently, because both decode.
      {"static_private = ERERERERERERERERERERERERERERERERERERERERERE=",
       "static_private = ERERERERERERERERERERERERERERERERERERERERER-",
       "static_private", "URL-safe base64, which the descriptor never emits"},
      {"gateway_id = d2luc2d3MDE=", "gateway_id = d2luc2d3MD_=", "gateway_id",
       "URL-safe base64 in the gateway id"},
      // Whitespace INSIDE the value, which a wrapped copy-paste produces. A
      // decoder that skipped it would accept a value the gateway's own
      // configuration never contained.
      {"gateway_id = d2luc2d3MDE=", "gateway_id = d2lu c2d3MDE=", "gateway_id",
       "embedded whitespace"},
      {"admission_key = NmYzOWEwYzFkMjRiN2U4ZjVhM2M5MDEyYjRkNmU4ZjAxYTJiM2M0ZD"
       "VlNmY3MDgxOTJhM2I0YzVkNmU3ZjgwOQ==",
       "admission_key =", "admission_key", "absent"},
      {"carrier_classes = udp,tcp,tls", "carrier_classes = tcp,tls",
       "udp", "a plan this engine cannot dial"},
      {"carrier_classes = udp,tcp,tls", "carrier_classes =", "carrier_classes",
       "an empty plan: a floor computed over nothing guarantees nothing"},
      {"inner_v4 = 10.10.0.9", "inner_v4 =", "inner_v4",
       "no inner address at all"},
  };
  for (const Case& c : cases) {
    std::string mutated = kServedConfig;
    const auto at = mutated.find(c.replace);
    Check(at != std::string::npos,
          std::string("the fixture still contains ") + c.replace);
    mutated.replace(at, std::strlen(c.replace), c.with);
    Winn3HostConfig config;
    std::string error;
    Check(!ParseWinn3Section(mutated, &config, &error),
          std::string("refused: ") + c.why);
    Check(error.find(c.names) != std::string::npos,
          std::string("and the refusal names ") + c.names + " (got: " + error +
              ")");
  }

  // The one that must NOT be refused: an admission key of 64 bytes rather than
  // 32. Requiring 32 would enforce the exact defect this contract exists to
  // prevent, so the absence of a length check there is deliberate and is
  // asserted rather than left to be "tidied" later.
  Winn3HostConfig config;
  std::string error;
  Check(ParseWinn3Section(kServedConfig, &config, &error),
        "a 64-byte admission secret is accepted: it is OPAQUE and its length "
        "is the key file's, not a key's");

  // ===========================================================================
  // THE ONE THIS PARSER CANNOT CATCH, STATED HERE SO NOBODY LATER ASSUMES IT CAN
  // ===========================================================================
  //
  // A hub that served the operator name UNENCODED -- `gateway_id = winsgw01`,
  // which is the obvious simplification -- produces a section this parser
  // ACCEPTS, because `winsgw01` is eight characters of the base64 alphabet and
  // decodes cleanly to six entirely different bytes. No length is wrong, no
  // character is invalid, and nothing here can tell the two apart.
  //
  // That is defect 1, and it is why the encoding is pinned at the HUB
  // (TestTheServedGatewayIDIsBase64OverTheOperatorText) rather than defended
  // here. This check exists so that a later hand does not add a "validate the
  // gateway id" rule and believe the hole is closed.
  std::string raw_name = kServedConfig;
  const auto gw = raw_name.find("gateway_id = d2luc2d3MDE=");
  Check(gw != std::string::npos, "the fixture still carries the encoded id");
  raw_name.replace(gw, std::strlen("gateway_id = d2luc2d3MDE="),
                   "gateway_id = winsgw01");
  Winn3HostConfig silently_wrong;
  Check(ParseWinn3Section(raw_name, &silently_wrong, &error),
        "the unencoded operator name is ACCEPTED -- this is defect 1 and no "
        "parser can see it");
  Check(silently_wrong.gateway_id != "winsgw01",
        "and it yields DIFFERENT bytes than the gateway is configured with, "
        "which is a tag the gateway cannot verify and a datagram it answers "
        "with nothing at all");
  Check(silently_wrong.gateway_id.size() == 6,
        "six bytes rather than eight, from a name an operator would call "
        "ordinary");

  // An unrecognised key is still a refusal, in the served spelling too.
  const std::string extra = std::string(kServedConfig) + "mtu = 1223\n";
  Check(!ParseWinn3Section(extra, &config, &error),
        "an unrecognised [winn] key is refused, not dropped");
  // And EVERY [winn3]-only key name is one of those inside a served section.
  // Aliasing them "for compatibility" is the state this contract exists to end:
  // two names accepted for one field means a document can set the field twice,
  // and which one won is invisible from either end of a session.
  for (const char* lab_only : {"static_key_path = C:\\keys\\static.key",
                               "gateway_static_key_path = C:\\keys\\gw.pub",
                               "admission_path = C:\\keys\\admission",
                               "router_v4 = 10.10.0.1",
                               "plan = udp,tcp,tls",
                               "class = udp",
                               "routes = 0.0.0.0/0",
                               "dns = 10.10.0.1",
                               "inner_v6 = fd00::2",
                               "fast_pq = true"}) {
    const std::string mixed = std::string(kServedConfig) + lab_only + "\n";
    Check(!ParseWinn3Section(mixed, &config, &error),
          std::string("a [winn3] key name inside a served [winn] section is "
                      "unrecognised rather than silently aliased: ") +
              lab_only);
  }
  // And the mirror: a served key name inside a [winn3] section is equally
  // unrecognised, so neither spelling leaks into the other.
  for (const char* served_only : {"inner_router_v4 = 10.10.0.1",
                                  "static_private = ERERERERERERERERERERERER"
                                  "ERERERERERERERERERERERE=",
                                  "carrier_classes = udp,tcp,tls"}) {
    const std::string mixed = std::string(kGoodConfig) + served_only + "\n";
    Check(!ParseWinn3Section(mixed, &config, &error),
          std::string("a served key name inside a [winn3] section is "
                      "unrecognised: ") +
              served_only);
  }
}

void TestBothProtocolsAtOnceIsRefused() {
  const std::string both =
      std::string(kGoodConfig) + "\n[winn]\nenabled = true\n";
  Winn3HostConfig config;
  std::string error;
  Check(!ParseWinn3Section(both, &config, &error),
        "a config selecting winn/1 AND winn/3 is refused");
  Check(error.find("cleartext") != std::string::npos,
        "and the refusal says what would go wrong");
}

void TestUnknownKeyIsARefusal() {
  const std::string extra = std::string(kGoodConfig) + "mtu = 1223\n";
  Winn3HostConfig config;
  std::string error;
  Check(!ParseWinn3Section(extra, &config, &error),
        "an unrecognised [winn3] key is refused, not dropped");
  Check(error.find("mtu") != std::string::npos,
        "and the refusal names the key");
}

void TestEndpointMustBeAnIpLiteral() {
  struct Case {
    const char* endpoint;
    bool accepted;
    const char* why;
  };
  const Case cases[] = {
      {"198.51.100.7:443", true, "an IPv4 literal with a port"},
      {"[2001:db8::1]:443", true, "a bracketed IPv6 literal with a port"},
      {"gateway.example.org:443", false,
       "a hostname would be a DNS lookup on the censored path"},
      {"198.51.100.7", false, "no port"},
      {"198.51.100.7:0", false, "port zero"},
      {"198.51.100.7:99999", false, "a port above 65535"},
      {"2001:db8::1:443", false, "unbracketed IPv6 is ambiguous"},
      {":443", false, "no host"},
      {"", false, "empty"},
  };
  for (const Case& c : cases) {
    std::string raw = kGoodConfig;
    const std::string needle = "endpoint = 198.51.100.7:443\n";
    raw.replace(raw.find(needle), needle.size(),
                "endpoint = " + std::string(c.endpoint) + "\n");
    Winn3HostConfig config;
    std::string error;
    Check(ParseWinn3Section(raw, &config, &error) == c.accepted,
          std::string("endpoint acceptance: ") + c.why);
  }
}

void TestEndpointSplitFeedsTheRoutePin() {
  std::string host;
  std::string port;
  Check(SplitWinn3Endpoint("198.51.100.7:443", &host, &port) &&
            host == "198.51.100.7" && port == "443",
        "the endpoint splits into the host the /32 pin is installed for");
  Check(SplitWinn3Endpoint("[2001:db8::1]:443", &host, &port) &&
            host == "2001:db8::1" && port == "443",
        "and the bracketed IPv6 form unwraps");
  Check(!SplitWinn3Endpoint("gateway.example.org:443", &host, &port),
        "a hostname is REFUSED rather than resolved: pinning a /32 to a "
        "resolved address is a DNS lookup on the censored path, and the "
        "address it returns may not be the one the engine dials");
}

void TestThePlanMustCoverTheDialledClass() {
  std::string raw = kGoodConfig;
  const std::string needle = "plan = udp, tcp, tls\n";
  raw.replace(raw.find(needle), needle.size(), "plan = tcp, tls\n");
  Winn3HostConfig config;
  std::string error;
  Check(!ParseWinn3Section(raw, &config, &error),
        "a plan that omits the dialled class is refused: the message floor -- "
        "and therefore the adapter MTU -- was not computed over it");

  std::string empty = kGoodConfig;
  empty.replace(empty.find(needle), needle.size(), "plan = \n");
  Check(!ParseWinn3Section(empty, &config, &error) &&
            error.find("plan is empty") != std::string::npos,
        "an empty plan is refused AS empty. The dialled-class check below "
        "would also refuse it, but 'your plan omits the class you dial' sends "
        "an operator hunting for a class that is not there at all");

  std::string unknown = kGoodConfig;
  unknown.replace(unknown.find(needle), needle.size(), "plan = udp, quic\n");
  Check(!ParseWinn3Section(unknown, &config, &error),
        "a plan naming an unknown class is refused");
}

void TestRequiredFields() {
  struct Case {
    const char* line;
    const char* why;
  };
  const Case cases[] = {
      {"gateway_id = kansas-1\n",
       "gateway_id, without which an initiation replays at another gateway"},
      {"node = lab-alpha\n", "the signed descriptor node identity"},
      {"selected_node = lab-alpha\n", "the selected-node identity"},
      {"inner_v4 = 10.9.0.2\n", "the inner assignment"},
      {"static_key_path = C:\\ProgramData\\WinsVPN\\winn3\\static.key\n",
       "this end's static key path"},
      {"gateway_static_key_path = "
       "C:\\ProgramData\\WinsVPN\\winn3\\gateway.pub\n",
       "the gateway's static key path: there is no anonymous mode"},
      {"admission_path = C:\\ProgramData\\WinsVPN\\winn3\\admission\n",
       "the admission secret's path"},
  };
  for (const Case& c : cases) {
    std::string raw = kGoodConfig;
    raw.erase(raw.find(c.line), std::string(c.line).size());
    Winn3HostConfig config;
    std::string error;
    Check(!ParseWinn3Section(raw, &config, &error),
          std::string("a [winn3] section is refused without ") + c.why);
  }
}

void TestResolversNeedTheInnerDeclaration() {
  std::string raw = std::string(kGoodConfig) + "dns = 10.9.0.53\n";
  Winn3HostConfig config;
  std::string error;
  Check(!ParseWinn3Section(raw, &config, &error),
        "resolvers without dns_are_inner are refused: a resolver reachable "
        "outside the tunnel resolves names over the censored path the moment "
        "the tunnel drops");
  raw += "dns_are_inner = true\n";
  Check(ParseWinn3Section(raw, &config, &error),
        "and accepted once the host declares them inner");
  Check(config.dns_servers.size() == 1 && config.dns_servers[0] == "10.9.0.53",
        "the resolver list is carried through");
}

// --- the profile document ---------------------------------------------------

void TestTheProfileIsTheEnginesDocument() {
  const Winn3HostConfig config = GoodConfig();
  const std::string json =
      BuildWinn3ProfileJson(config, 49152, "physical /32 pin to the gateway");

  // The one field that decides whether the tunnel encrypts.
  Check(json.find("\"kind\":\"loopback-udp\"") != std::string::npos,
        "device.kind is loopback-udp: the seam that carries RAW INNER PACKETS "
        "to the layer that encrypts them");
  Check(json.find("awg") == std::string::npos &&
            json.find("ip-packet") == std::string::npos,
        "and the profile names no winn/1 payload class at all");
  Check(json.find("\"host_port\":49152") != std::string::npos,
        "device.host_port is the port the relay already bound");
  Check(json.find("\"name\":\"\"") != std::string::npos,
        "device.name is empty: loadWinn3Profile refuses a name on a "
        "loopback-udp device");
  Check(json.find("\"version\":\"winn3-host/1\"") != std::string::npos,
        "the profile version is the one this engine accepts");
  Check(json.find("\"role\":\"client\"") != std::string::npos,
        "a desktop host is always the client");
  Check(json.find("\"allow_own_socket\":true") != std::string::npos,
        "the engine owns its outer socket under the desktop model");
  Check(json.find("\"outer_socket_exclusion\":\"physical /32 pin to the "
                  "gateway\"") != std::string::npos,
        "and the exclusion the host installed is written down beside it");
  Check(json.find("\"plan\":[\"udp\",\"tcp\",\"tls\"]") != std::string::npos,
        "the plan is carried in order");
  Check(json.find("\"fast_pq\":false") != std::string::npos,
        "StrictPQ is the default: harvest-now-decrypt-later is live for this "
        "user population");

  // NO KEY MATERIAL, only paths.
  Check(json.find("static.key") != std::string::npos,
        "key files are named by path");
  Check(json.find("PrivateKey") == std::string::npos,
        "and no key material crosses this boundary");
}

void TestWindowsPathsSurviveJsonEncoding() {
  Winn3HostConfig config = GoodConfig();
  config.static_key_path = "C:\\ProgramData\\Win's VPN\\a\"b\\static.key";
  const std::string json = BuildWinn3ProfileJson(config, 1, "x");
  Check(json.find("C:\\\\ProgramData\\\\Win's VPN\\\\a\\\"b\\\\static.key") !=
            std::string::npos,
        "a Windows path's backslashes and an embedded quote are escaped. "
        "Unescaped, \\P and \\W are invalid JSON escapes and Go rejects the "
        "whole profile with a message about the document rather than the path");
  // A tab inside a value must not terminate anything.
  config.gateway_id = "a\tb";
  const std::string tabbed = BuildWinn3ProfileJson(config, 1, "x");
  Check(tabbed.find("\"gateway_id\":\"a\\tb\"") != std::string::npos,
        "a named control character is escaped rather than dropped");
  // And one with no short escape. Emitted raw, a byte below 0x20 is a literal
  // control character inside a JSON string, which encoding/json rejects
  // outright -- so the engine would refuse the whole profile with a message
  // about the document rather than about the field that carried it.
  config.gateway_id = std::string("a\x01") + "b";
  const std::string numeric = BuildWinn3ProfileJson(config, 1, "x");
  Check(numeric.find("\"gateway_id\":\"a\\u0001b\"") != std::string::npos,
        "and one with no short escape is escaped numerically");
  Check(numeric.find('\x01') == std::string::npos,
        "with no raw control byte left anywhere in the document");
}

// --- the two child processes' lines -----------------------------------------

void TestRelayHostPortLine() {
  int port = 0;
  // Copied from windows/winn3_engine/main_windows.go's
  // fmt.Fprintf(out, "host-port %d\n", hostPort).
  Check(ParseRelayHostPort("host-port 49152\n", &port) && port == 49152,
        "the relay's first line is read");
  Check(!ParseRelayHostPort("host-port 0", &port), "port zero is refused");
  Check(!ParseRelayHostPort("host-port 65536", &port),
        "a port above 65535 is refused");
  Check(!ParseRelayHostPort("host-port", &port), "a bare prefix is refused");
  Check(!ParseRelayHostPort("host-port abc", &port),
        "a non-numeric port is refused");
  Check(!ParseRelayHostPort("winn3-relay: host-port 49152", &port),
        "the prefix must be at position zero: a diagnostic that merely "
        "CONTAINS the line is not the line");
  // A note for whoever mutation-tests this next. Replacing the anchored
  // compare in TakeTrailingPort with an unanchored find() SURVIVES this suite,
  // and it is an equivalent mutant rather than a hole. The port is read from a
  // FIXED offset -- substr(prefix.size()) -- so whenever the prefix is found at
  // any position > 0, that offset lands inside or before the prefix itself,
  // whose characters are letters and hyphens; ParseDecimal then refuses. The
  // two spellings can only differ when the prefix is found at 0, where they
  // agree. The anchored form is kept because it states the intent, not because
  // a test can tell them apart.
  Check(!ParseRelayHostPort("ready name=winsvpn3", &port),
        "the readiness line is not a host-port line");
}

void TestEngineSeamPortLine() {
  int port = 0;
  // Copied from winn_protocol_experimental/cmd/winn-datapath/winn3_run.go:324.
  Check(ParseEngineSeamPort(
            "winn-datapath: winn3 loopback seam engine port 51001\n", &port) &&
            port == 51001,
        "the engine's stderr announcement is read");
  Check(!ParseEngineSeamPort("winn-datapath: winn3 loopback seam engine port",
                             &port),
        "a truncated announcement is refused");
  Check(!ParseEngineSeamPort("winn-datapath: some other diagnostic 51001",
                             &port),
        "another diagnostic ending in a number is not the announcement");
  Check(!ParseEngineSeamPort("host-port 51001", &port),
        "the RELAY's line is not the ENGINE's line. They arrive on two "
        "different pipes from two different processes, and confusing them "
        "would point each half of the seam at itself");
}

void TestRelayReadyLine() {
  Winn3RelayReady ready;
  // Copied from main_windows.go's readiness fmt.Fprintf.
  Check(ParseRelayReady(
            "ready name=winsvpn3 luid=1688849860263937 mtu=1139 "
            "floor-mtu=1139 ipv6=false\n",
            &ready),
        "the readiness line parses");
  Check(ready.name == "winsvpn3", "the adapter name is read");
  Check(ready.luid == 1688849860263937ULL, "the LUID is read");
  Check(ready.mtu == 1139 && ready.floor_mtu == 1139, "both MTUs are read");
  Check(!ready.ipv6,
        "and ipv6 is false at the shipping floor, because 1139 < 1280");

  const char* broken[] = {
      "ready name=winsvpn3 luid=1 mtu=1139 floor-mtu=1139",
      "ready name=winsvpn3 luid=1 mtu=1139 ipv6=false",
      "ready luid=1 mtu=1139 floor-mtu=1139 ipv6=false",
      "ready name=winsvpn3 luid=1 mtu=1139 floor-mtu=1139 ipv6=maybe",
      "ready name= luid=1 mtu=1139 floor-mtu=1139 ipv6=false",
      "ready name=winsvpn3 luid=x mtu=1139 floor-mtu=1139 ipv6=false",
      "ready name=winsvpn3 luid=1 mtu=1139 floor-mtu=1139 ipv6=false extra=1",
      "host-port 49152",
      "ready",
  };
  for (const char* line : broken) {
    Check(!ParseRelayReady(line, &ready),
          std::string("a malformed readiness line is refused: ") + line);
  }
}

void TestStartCommandIsByteExact() {
  // This must be exactly what parseStartCommand in
  // windows/winn3_engine/packet.go accepts: `start mtu=<n> engine-port=<n>`,
  // two fields, no third, newline-terminated because the relay reads it with a
  // line scanner and would otherwise hold no adapter forever.
  Check(RenderStartCommand(1139, 51001) == "start mtu=1139 engine-port=51001\n",
        "the start command is byte-exact against the relay's parser");
}

// --- the MTU obligations ----------------------------------------------------

void TestPublishedPlanMtusAreAccepted() {
  std::string error;
  Check(VerifyPublishedInnerMtu(kShippingFloorInnerMTU, &error),
        "1139 is the plan floor and is accepted");
  Check(1364 - 112 - 29 == 1223 &&
            VerifyPublishedInnerMtu(1223, &error),
        "1223 is accepted for its published 1364-byte path plan");
  Check(1470 - 48 - 29 == 1393 &&
            VerifyPublishedInnerMtu(1393, &error),
        "1393 is accepted for its published 1470-byte path plan");
  Check(!VerifyPublishedInnerMtu(0, &error) &&
            error.find("non-positive") != std::string::npos,
        "zero is refused AS non-positive. The message matters: 'the engine "
        "published nothing' and 'the engine published something too small' "
        "are different faults, and the range check below would swallow the "
        "first into the second");
  Check(!VerifyPublishedInnerMtu(-1, &error) &&
            error.find("non-positive") != std::string::npos,
        "a negative MTU is refused the same way");
  Check(!VerifyPublishedInnerMtu(575, &error),
        "below the IPv4 minimum is refused");
  Check(VerifyPublishedInnerMtu(576, &error), "the IPv4 minimum is accepted");
  Check(!VerifyPublishedInnerMtu(65536, &error), "above the maximum is refused");
  // A legitimately wider path is not the trap and must not be refused.
  Check(VerifyPublishedInnerMtu(1400, &error),
        "a wider measured floor is accepted: 1139 is expected, not mandated");
}

void TestTheAppliedMtuMustKeepAgreeing() {
  EngineStatus status = CarryingStatus();
  std::string error;
  Check(VerifyAppliedMtuStillAgrees(kShippingFloorInnerMTU, status, &error),
        "the adapter's MTU and the engine's published one agree");
  status.inner_mtu = kDialledUdpV4InnerMTU;
  Check(!VerifyAppliedMtuStillAgrees(kShippingFloorInnerMTU, status, &error),
        "a live inner_mtu that no longer matches the adapter is refused: a "
        "live adapter cannot be resized and the gap is silently black-holed");
  EngineStatus unparsed;
  Check(!VerifyAppliedMtuStillAgrees(kShippingFloorInnerMTU, unparsed, &error) &&
            error.find("unparsed") != std::string::npos,
        "an unparsed document is refused AS unparsed, not as a mismatch. Its "
        "zero MTU would fail the comparison anyway, and reporting that as 'the "
        "engine now publishes 0' would send an operator looking for a sizing "
        "bug that is really a parse failure");
}

void TestTheAdapterNameIsNotTheWinn1One() {
  // kRelayAdapterName is what StartWindowsWinn3Tunnel compares the relay's
  // reported adapter against before installing any posture on it. If it ever
  // became "winsvpn" -- windows/awg_engine's adapter, which carries AmneziaWG
  // outer datagrams that are ALREADY ENCRYPTED -- this supervisor would install
  // a v3 posture on an interface owned by a different protocol, and point an
  // inner-packet datapath at it.
  Check(std::string(winsvpn::winn3::kRelayAdapterName) == "winsvpn3",
        "the v3 adapter is winsvpn3, exactly as main_windows.go names it");
  Check(std::string(winsvpn::winn3::kRelayAdapterName) != "winsvpn",
        "and is NOT the winn/1 AmneziaWG adapter");
  // The relay reports it, so the two must agree on the wire as well as in the
  // constant.
  Winn3RelayReady ready;
  Check(ParseRelayReady("ready name=winsvpn3 luid=1 mtu=1139 floor-mtu=1139 "
                        "ipv6=false",
                        &ready) &&
            ready.name == std::string(winsvpn::winn3::kRelayAdapterName),
        "and what the relay reports matches the constant the host checks");
}

void TestInnerIPv6IsArithmeticallyPossibleAtTheFloor() {
  Check(InnerIPv6IsArithmeticallyPossible(kShippingFloorInnerMTU),
        "1309 >= 1280, so inner IPv6 CAN be carried at the shipping floor "
        "now (the fleet default path_mtu 1450 raised the floor from 1139 to "
        "1309 on 2026-08-10). That is exactly what makes the fail-closed sink "
        "legal on the default for the first time (winn3_posture.h)");
  Check(!InnerIPv6IsArithmeticallyPossible(1279), "1279 still cannot");
  Check(InnerIPv6IsArithmeticallyPossible(1280),
        "1280 is RFC 8200's minimum link MTU and is the first that can");
}

// --- the promotion decision -------------------------------------------------

void TestPromotionNeedsBothHalves() {
  std::string reason;
  EngineStatus status = CarryingStatus();
  Check(DecideWinn3Promotion(status, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kPromote,
        "carrying with a delivered inner packet promotes");
  Check(reason.empty(), "and says nothing, because nothing is missing");

  // Half one missing: the gate never opened.
  status = CarryingStatus();
  status.promotion_ready = false;
  status.gate_state = "closed";
  status.rx_packets = 0;
  Check(DecideWinn3Promotion(status, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kHold,
        "a closed gate holds the bootstrap posture");
  Check(reason.find("closed") != std::string::npos,
        "and names the gate state, because a gate that never opened is a "
        "handshake problem");

  // Half two missing: the gate is open and nothing has come back.
  status = CarryingStatus();
  status.promotion_ready = false;
  status.rx_packets = 0;
  Check(DecideWinn3Promotion(status, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kHold,
        "a carrying gate with no delivered inner packet still holds");
  Check(reason.find("no inner packet") != std::string::npos,
        "and says so, because an open gate with no delivery is a return-path "
        "problem and not the same fault");
}

void TestADocumentThatDisagreesWithItselfIsRefused() {
  std::string reason;
  EngineStatus status = CarryingStatus();
  status.rx_packets = 0;  // ...while still claiming promotion_ready.
  Check(DecideWinn3Promotion(status, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kRefuse,
        "promotion_ready with zero deliveries is REFUSED, not believed: "
        "trusting the field over the evidence for it is how a gate becomes "
        "decorative");
}

// THE OTHER HALF OF THE SAME SENTENCE, ADDED 2026-08-12.
//
// DecideWinn3Promotion re-derived from the evidence for ONE of the two halves
// of `promotion_ready`. Zero deliveries beside a ready claim refused; a gate
// that may not carry beside a ready claim did not, because the gate comparison
// lived inside `if (!status.promotion_ready)` and was unreachable once the
// field said true. That branch is a DIAGNOSTIC -- it tells a held session which
// half it is waiting on -- and it stays exactly as it is. What was missing is
// the belt-and-braces check beside the rx_packets one.
//
// The verdict is kRefuse and not kHold on purpose, and the distinction is the
// whole point. kHold means "nothing is wrong and nothing is proven yet", which
// is the honest answer for a document that says false. A document that says
// TRUE while naming a gate that may not carry is not unproven -- it is
// internally inconsistent, which is the same fault the zero-deliveries check
// already refuses, and refusing it is what stops the supervisor from acting on
// a document it has already caught contradicting itself.
void TestAReadyClaimBesideAGateThatMayNotCarryIsRefused() {
  std::string reason;
  // Every non-carrying name winn3/tun.State.String() emits, plus the sentinel
  // it returns for a value it does not recognise. Deliveries stay nonzero, so
  // the rx_packets half cannot be what refuses any of these.
  const std::vector<std::string> not_carrying = {
      "closed", "handshaking", "epoch0", "rekeying", "down", "invalid", ""};
  for (const std::string& gate : not_carrying) {
    EngineStatus status = CarryingStatus();
    status.gate_state = gate;  // ...while still claiming promotion_ready.
    Check(status.promotion_ready && status.rx_packets > 0,
          "the fixture claims ready WITH deliveries: gate='" + gate + "'");
    Check(DecideWinn3Promotion(status, kShippingFloorInnerMTU, &reason) ==
              Winn3PromotionVerdict::kRefuse,
          "a ready claim beside a '" + gate +
              "' gate is REFUSED: it disagrees with itself exactly as a ready "
              "claim with zero deliveries does");
    Check(reason.find("gate") != std::string::npos,
          "and the reason names the gate rather than the counters, so the "
          "operator is not sent after the wrong half: " + reason);
  }

  // The positive control: the document the engine really writes is untouched.
  Check(DecideWinn3Promotion(CarryingStatus(), kShippingFloorInnerMTU,
                             &reason) == Winn3PromotionVerdict::kPromote,
        "and an honest carrying document still promotes");

  // And the DIAGNOSTIC branch above it is unchanged: a document that says
  // false still HOLDS and still names which half is missing.
  EngineStatus not_ready = CarryingStatus();
  not_ready.promotion_ready = false;
  not_ready.gate_state = "handshaking";
  not_ready.rx_packets = 0;
  Check(DecideWinn3Promotion(not_ready, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kHold,
        "an honest not-ready document still HOLDS rather than refusing");
  Check(reason.find("handshaking") != std::string::npos,
        "and still names the gate state: " + reason);
}

void TestRefusalAndUnparsedAreDifferentAnswers() {
  std::string reason;
  EngineStatus refused = CarryingStatus();
  refused.refusal = "the carrier was lost";
  Check(DecideWinn3Promotion(refused, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kRefuse,
        "an engine refusal stops the tunnel");
  Check(reason.find("carrier was lost") != std::string::npos,
        "and is passed through, because the field a support ticket needs is "
        "the one that says why");

  EngineStatus unparsed;
  Check(DecideWinn3Promotion(unparsed, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kHold,
        "an unparsed line HOLDS rather than refuses: one malformed line on an "
        "otherwise healthy stream must not tear down a working tunnel, and a "
        "document from a newer engine narrows rather than guesses");

  EngineStatus stale = CarryingStatus();
  stale.inner_mtu = 900;
  Check(DecideWinn3Promotion(stale, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kRefuse,
        "an MTU that stopped agreeing refuses even while promotion_ready is "
        "true: the adapter is already built and cannot be resized");
}

// TestBootstrapPromotesRoutesOnlyAfterTransportObservedBothWays pins the one
// invariant this file exists to hold: while the supervisor is in the BOOTSTRAP
// posture it may install only the narrow next-hop, and the widened routes -- the
// default-route /1 halves and the resolver -- appear in the rendered commands
// ONLY after the engine has proven the datapath. For the winn/3 engine that
// proof is transfer-observed: an inner packet was validated and delivered to the
// host device, the same "transport observed both ways" gate every other host
// promotes its routes on. The supervisor reads it as `promotion_ready`, which
// the engine computes as `gate == carrying && rx_packets > 0` (winn3_status.go).
//
// The NEGATIVE half is what protects the anti-slip this lane exists for:
// `rx_offered` -- a payload ARRIVED on the carrier -- must not widen. Only a
// DELIVERED `rx_packets` can. A supervisor that promoted when the engine said a
// payload arrived but none reached the device would be widening routes over a
// return path it has not proven, which is exactly the deaf half-tunnel the whole
// staged-posture machinery is there to prevent.
void TestBootstrapPromotesRoutesOnlyAfterTransportObservedBothWays() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;

  // While the engine has NOT observed transport both ways, the decision holds
  // and nothing wider than the next hop may be rendered.
  EngineStatus unproven = CarryingStatus();
  unproven.promotion_ready = false;
  unproven.posture = "bootstrap";
  unproven.gate_state = "carrying";
  unproven.rx_packets = 0;
  // A payload arrived on the carrier but none was delivered to the host device:
  // the return path is unproven. This is the exact rx_offered-vs-rx_packets
  // slip -- offered, not delivered -- and it must NOT widen.
  unproven.rx_offered = 12;

  std::string reason;
  Check(DecideWinn3Promotion(unproven, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kHold,
        "while transport is not yet observed both ways (no inner packet "
        "delivered) the supervisor HOLDS the bootstrap posture");
  Check(reason.find("no inner packet") != std::string::npos,
        "and says the return path is unproven, not that the handshake failed");

  const PostureInput input = PostureInputFrom(config, "pin", unproven);
  PosturePlan bootstrap, refused;
  std::string error;
  Check(BuildBootstrapPosture(input, unproven, &bootstrap, &error),
        "the bootstrap posture builds from the unproven document: " + error);
  Check(VerifyBootstrapIsNarrow(bootstrap, &error),
        "and is verified narrow, so no widening exists to apply yet");
  Check(!BuildPromotedPosture(input, unproven, &refused, &error),
        "and the widened posture is REFUSED while the datapath is unproven, so "
        "the default route cannot move before transport is observed both ways");

  bool bootstrap_default_low = false;
  bool bootstrap_resolver = false;
  for (const std::vector<std::string>& command :
       RenderWindowsPostureCommands("winsvpn3", bootstrap)) {
    for (const std::string& token : command) {
      if (token == winsvpn::winn3::detail::kDefaultRouteLowHalf) {
        bootstrap_default_low = true;
      }
      if (token == "10.9.0.53") bootstrap_resolver = true;
    }
  }
  Check(!bootstrap_default_low && !bootstrap_resolver,
        "the rendered bootstrap installs no default-route half and no resolver: "
        "routes are not promoted until transport is observed both ways");

  // The moment the engine proves the transport (an inner packet delivered), the
  // decision promotes and the widened posture installs the default route.
  EngineStatus proven = CarryingStatus();
  proven.promotion_ready = true;
  proven.posture = "promoted";
  proven.gate_state = "carrying";
  proven.rx_packets = 12;
  Check(DecideWinn3Promotion(proven, kShippingFloorInnerMTU, &reason) ==
            Winn3PromotionVerdict::kPromote,
        "and only once transport is observed both ways (a delivered inner "
        "packet) does the supervisor PROMOTE");
  PosturePlan promoted;
  Check(BuildPromotedPosture(input, proven, &promoted, &error),
        "the widened posture builds now that the datapath is proven: " + error);
  Check(promoted.default_route,
        "and installs the default route at promotion");

  const std::vector<std::vector<std::string>> promoted_delta =
      PromotedCommandDelta(
          RenderWindowsPostureCommands("winsvpn3", promoted),
          RenderWindowsPostureCommands("winsvpn3", bootstrap));
  bool promoted_default_low = false;
  bool promoted_default_high = false;
  for (const std::vector<std::string>& command : promoted_delta) {
    for (const std::string& token : command) {
      if (token == winsvpn::winn3::detail::kDefaultRouteLowHalf) {
        promoted_default_low = true;
      }
      if (token == winsvpn::winn3::detail::kDefaultRouteHighHalf) {
        promoted_default_high = true;
      }
    }
  }
  Check(promoted_default_low && promoted_default_high,
        "and the promotion delta carries the default-route /1 halves -- routes "
        "promote only after transport was observed both ways");
}

// --- the posture, end to end ------------------------------------------------

void TestBootstrapIsNarrowFromARealConfig() {
  const Winn3HostConfig config = GoodConfig();
  EngineStatus sizing;
  sizing.valid = true;
  sizing.event = "sizing";
  sizing.posture = "bootstrap";
  sizing.gate_state = "closed";
  sizing.inner_mtu = kShippingFloorInnerMTU;

  const PostureInput input =
      PostureInputFrom(config, "physical /32 pin", sizing);
  PosturePlan plan;
  std::string error;
  Check(BuildBootstrapPosture(input, sizing, &plan, &error),
        "a bootstrap posture builds from the engine's own numbers");
  Check(VerifyBootstrapIsNarrow(plan, &error),
        "and re-checking the built object confirms it is narrow");
  Check(plan.mtu == kShippingFloorInnerMTU, "the MTU is the engine's");
  Check(plan.included_routes.size() == 1 &&
            plan.included_routes[0] == "10.9.0.1/32",
        "exactly one route, and it is the inner next hop");
  Check(!plan.default_route, "no default route");
  Check(!plan.ipv6, "no IPv6");
  Check(plan.dns_servers.empty(), "no resolver");

  // The refusal that matters most: promotion on an unproven datapath.
  PosturePlan promoted;
  Check(!BuildPromotedPosture(input, sizing, &promoted, &error),
        "and promotion is refused while the gate is closed");
}

void TestPostureInputFromCarriesInnerIPv6OnlyWhenTheEngineCanCarryIt() {
  Winn3HostConfig config = GoodConfig();
  config.inner_v6 = "2001:db8::2";
  config.router_v6 = "2001:db8::1";
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;

  // The engine says the plan floor cannot carry inner IPv6: the configured
  // address and router are dropped rather than named, so no posture ever names
  // an address the tunnel cannot carry.
  EngineStatus no6 = CarryingStatus();
  no6.inner_ipv6 = false;
  const PostureInput narrow = PostureInputFrom(config, "pin", no6);
  Check(narrow.inner_v6.empty(),
        "a served inner IPv6 address is DROPPED when the engine says the plan "
        "floor cannot carry inner IPv6: installing it would make the host "
        "prefer the family that black-holes");
  Check(narrow.router_v6.empty(), "and its router is dropped with it");

  // The engine says the plan floor CAN carry inner IPv6: the configured inner
  // address is carried through and the promoted posture installs it.
  EngineStatus yes6 = CarryingStatus();
  yes6.inner_mtu = 1400;
  yes6.inner_ipv6 = true;
  const PostureInput inner = PostureInputFrom(config, "pin", yes6);
  Check(inner.inner_v6 == "2001:db8::2" && inner.router_v6 == "2001:db8::1",
        "and carried through when the engine says the floor can take it");

  PosturePlan plan;
  std::string error;
  Check(BuildPromotedPosture(inner, yes6, &plan, &error) && plan.ipv6 &&
            plan.inner_v6 == "2001:db8::2" && plan.ipv6_sink.empty(),
        "which promotes with the INNER IPv6 address, and no sink");

  // Without an inner IPv6 address at a legal MTU, promotion installs the
  // fail-closed SINK instead -- IPv6 is still drawn onto the tunnel so it
  // cannot reach the physical interface, at the same address Apple and
  // Android use.
  const PostureInput dropped = PostureInputFrom(config, "pin", no6);
  PosturePlan sink;
  Check(BuildPromotedPosture(dropped, no6, &sink, &error) && sink.ipv6 &&
            sink.inner_v6.empty() &&
            sink.ipv6_sink == "fd00:d951:1::2",
        "and with no inner IPv6 it installs the fail-closed SINK, so the host "
        "never leaves host IPv6 on the physical interface beside a promoted "
        "tunnel");
}

void TestPromotedPostureRendersRealNetshCommands() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;

  const EngineStatus status = CarryingStatus();
  const PostureInput input = PostureInputFrom(config, "pin", status);
  PosturePlan plan;
  std::string error;
  Check(BuildPromotedPosture(input, status, &plan, &error),
        "the promoted posture builds once the datapath is proven");

  // THIS IS THE CALL RenderWindowsPostureCommands NEVER HAD.
  const std::vector<std::vector<std::string>> commands =
      RenderWindowsPostureCommands("winsvpn3", plan);
  Check(!commands.empty(), "and renders netsh argument vectors");

  bool set_address = false;
  bool set_mtu = false;
  bool default_low = false;
  bool default_high = false;
  bool resolver = false;
  // The fail-closed IPv6 sink: the three commands that make a v6 packet
  // egress the tun instead of the physical NIC. This posture carries no inner
  // IPv6 (CarryingStatus sets inner_ipv6=false), so promotion must install the
  // sink address on the tun and point the v6 default at it in the two /1
  // halves. Asserting these is the whole point: a renderer that silently
  // dropped the sink would leave host IPv6 on the physical interface beside a
  // promoted v4 tunnel -- the exact leak this lane exists to close -- and
  // without these checks the suite would still pass.
  bool sink_address = false;
  bool v6_default_low = false;
  bool v6_default_high = false;
  for (const std::vector<std::string>& command : commands) {
    const std::string line = RenderWin32CommandLine(command);
    if (line.find("set address") != std::string::npos &&
        line.find("address=10.9.0.2/32") != std::string::npos) {
      set_address = true;
    }
    if (line.find("set subinterface") != std::string::npos &&
        line.find("mtu=" + std::to_string(kShippingFloorInnerMTU)) !=
            std::string::npos) {
      set_mtu = true;
    }
    if (line.find("0.0.0.0/1") != std::string::npos) default_low = true;
    if (line.find("128.0.0.0/1") != std::string::npos) default_high = true;
    if (line.find("dnsservers") != std::string::npos) resolver = true;
    // IPv6 sink shape: `netsh interface ipv6 set address interface=winsvpn3
    // address=fd00:d951:1::2/128` plus the two v6 default halves.
    if (line.find("ipv6") != std::string::npos &&
        line.find("set address") != std::string::npos &&
        line.find(kIPv6SinkAddress) != std::string::npos) {
      sink_address = true;
    }
    // The v6 halves are asserted as EXACT argv tokens, not substrings of the
    // joined command line: `8000::/1` contains `::/1` as a substring, so a
    // `find("::/1")` on the line would keep the low-half assertion green even
    // with the low half dropped. Exact-token match is what makes each half
    // individually load-bearing.
    for (const std::string& token : command) {
      if (token == winsvpn::winn3::detail::kIPv6DefaultRouteLowHalf) {
        v6_default_low = true;
      }
      if (token == winsvpn::winn3::detail::kIPv6DefaultRouteHighHalf) {
        v6_default_high = true;
      }
    }
    Check(command.size() >= 2 && command[0] == "netsh",
          "every rendered command is a netsh argument vector");
  }
  Check(set_address, "the inner address is set as a /32");
  Check(set_mtu, "the MTU is set to the engine's inner_mtu");
  Check(default_low && default_high,
        "the default route is two /1s, which beat an existing default on "
        "specificity without deleting it -- so a failed teardown leaves the "
        "host's own default intact rather than none at all");
  Check(resolver, "and the inner resolver is installed at promotion");
  Check(sink_address,
        "and the PROMOTED posture installs the fail-closed IPv6 sink address "
        "on the tun, because this session carries no inner IPv6 -- without it "
        "host IPv6 stays on the physical interface beside a promoted v4 "
        "tunnel");
  Check(v6_default_low && v6_default_high,
        "and points the v6 default at the tun in the two /1 halves, so a "
        "global-scope v6 destination is drawn into the tunnel where the "
        "winn3/tun layer blackholes it rather than egressing the physical "
        "NIC in the clear");
}

// Every rendered `add route` argv carries store=active.
//
// netsh's default store for `add route` is persistent. A persistent record
// outlives the Wintun adapter teardown the stop path relies on (active routes
// die with the interface; the store copy does not), and the leftover a next
// boot or a next session re-materializes is a stale next-hop /32 or /1 that
// outranks whatever the new session installs. Measured live on winpc
// 2026-08-23 after a clean stop: `route print -4`'s persistent section still
// listed the finished session's three routes. Pinned here so the renderer can
// never drift back to the implicit persistent store.
void TestRenderedRouteCommandsAreActiveStoreOnly() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;
  const EngineStatus status = CarryingStatus();
  const PostureInput input = PostureInputFrom(config, "pin", status);
  PosturePlan promoted;
  std::string error;
  Check(BuildPromotedPosture(input, status, &promoted, &error),
        "the store=active check needs a promoted posture to render: " + error);
  const std::vector<std::vector<std::string>> commands =
      RenderWindowsPostureCommands("winsvpn3", promoted);
  bool saw_add_route = false;
  for (const std::vector<std::string>& command : commands) {
    const bool is_add_route =
        command.size() >= 3 && command[0] == "netsh" && command[1] == "interface" &&
        (command[2] == "ipv4" || command[2] == "ipv6") &&
        std::find(command.begin(), command.end(), "add") != command.end() &&
        std::find(command.begin(), command.end(), "route") != command.end();
    if (is_add_route) {
      saw_add_route = true;
      Check(command.back() == "store=active",
            "every rendered `add route` command ends in store=active: an "
            "implicit persistent store is exactly the route record that "
            "survived a clean stop on winpc 2026-08-23");
    }
  }
  Check(saw_add_route,
        "the promoted posture really contains route commands for this check "
        "to have checked anything");
}

// --- joining an argument vector for CreateProcess ---------------------------

// TestPromotedCommandDeltaIsIdempotentAcrossRepeatApply pins the Windows
// applier's repeat-apply guarantee: the command set promotion actually executes
// is the promoted-vs-bootstrap DELTA, never the whole promoted render, so a
// repeated application cannot re-issue a command an interface already holds.
//
// WHY REPEAT-APPLY MATTERS, and the concrete winpc observation behind it
// (winn3_posture.h:1148): re-running the RAW renderer
// `RenderWindowsPostureCommands(interface, promoted)` a second time re-emits
// the bootstrap's `netsh ... add route <next-hop>` (and its `set address`,
// `set subinterface`). The second `add route` answers "The object already
// exists." with a non-zero exit, the Windows applier stops on the FIRST failing
// command, and promotion fails before the IPv6 sink or any default route moved.
// The delta is the answer to that: it drops every command the bootstrap already
// applied, and once the WIDENINGS have themselves been applied, a further
// repeat-apply must run nothing at all.
void TestPromotedCommandDeltaIsIdempotentAcrossRepeatApply() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;
  const EngineStatus status = CarryingStatus();
  const PostureInput input = PostureInputFrom(config, "pin", status);
  PosturePlan bootstrap, promoted;
  std::string error;
  Check(BuildBootstrapPosture(input, status, &bootstrap, &error),
        "bootstrap builds for the delta test: " + error);
  Check(BuildPromotedPosture(input, status, &promoted, &error),
        "promoted builds for the delta test: " + error);

  const std::vector<std::vector<std::string>> bootstrap_argv =
      RenderWindowsPostureCommands("winsvpn3", bootstrap);
  const std::vector<std::vector<std::string>> promoted_argv =
      RenderWindowsPostureCommands("winsvpn3", promoted);
  const std::vector<std::vector<std::string>> delta =
      PromotedCommandDelta(promoted_argv, bootstrap_argv);

  // FIRST application. The delta must not re-issue the bootstrap's next-hop
  // `add route 10.9.0.1/32` -- the exact command whose second issue answered
  // "The object already exists" on winpc.
  bool delta_has_next_hop = false;
  for (const std::vector<std::string>& argv : delta) {
    for (const std::string& token : argv) {
      if (token == "10.9.0.1/32") delta_has_next_hop = true;
    }
  }
  Check(!delta_has_next_hop,
        "the promoted delta omits the bootstrap next-hop route");
  std::string capture_error;
  Check(VerifyPromotedCommandsCapture(delta, &capture_error),
        "and the delta itself captures traffic, so promotion applies a real "
        "widening: " + capture_error);

  // REPEAT application. After the delta is run the interface holds the
  // bootstrap set PLUS the delta -- i.e. the whole promoted set. A second
  // promotion computed against the genuinely-applied set must render an EMPTY
  // delta: no netsh command runs again, so `add route` (and a multi-resolver
  // `add dnsservers index=2`) cannot fail "already exists", and promotion
  // cannot stall on its first command.
  std::vector<std::vector<std::string>> applied = bootstrap_argv;
  for (const std::vector<std::string>& command : delta) {
    applied.push_back(command);
  }
  const std::vector<std::vector<std::string>> reapply =
      PromotedCommandDelta(promoted_argv, applied);
  Check(reapply.empty(),
        "repeat-apply of an already-applied promoted posture renders an EMPTY "
        "delta: nothing is re-run, so no route add can fail with 'already "
        "exists'");
  Check(!VerifyPromotedCommandsCapture(reapply, &capture_error),
        "and an empty re-promotion is correctly refused by the capture guard, "
        "never falsely reported as a widening");
}

// TestWindowsWinn3StartIsTwoPhase pins that a real start is TWO ordered
// phases and that the second phase is only the widening -- so a start can never
// begin wide, and promotion can never re-issue the bootstrap's own commands.
//
// Phase one renders the BOOTSTRAP posture: narrow, one /32 next hop, the
// engine's MTU, no default route, no IPv6 sink, no resolver. Phase two is the
// DELTA to the promoted posture: the default-route /1 halves and the fail-closed
// IPv6 sink, and NOT the next-hop add-route the bootstrap already issued. The
// promoted set is byte-for-byte bootstrap UNION delta; a start that replaced the
// bootstrap render with the promoted render wholesale would re-issue the
// `add route` and fail "The object already exists." on winpc.
void TestWindowsWinn3StartIsTwoPhase() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;
  const EngineStatus status = CarryingStatus();
  const PostureInput input = PostureInputFrom(config, "pin", status);
  PosturePlan bootstrap, promoted;
  std::string error;
  Check(BuildBootstrapPosture(input, status, &bootstrap, &error) &&
            VerifyBootstrapIsNarrow(bootstrap, &error),
        "phase ONE -- bootstrap -- builds narrow from a real config: " + error);
  Check(BuildPromotedPosture(input, status, &promoted, &error),
        "phase TWO -- promotion -- builds once the datapath is proven: " +
            error);

  const std::vector<std::vector<std::string>> phase_one =
      RenderWindowsPostureCommands("winsvpn3", bootstrap);
  const std::vector<std::vector<std::string>> phase_two =
      RenderWindowsPostureCommands("winsvpn3", promoted);

  // Phase one, at the rendered-argv level (the commands a start actually
  // executes first), is narrow: no default-route half and no IPv6 sink. The
  // plans are verified narrow above, but the argv is what moves routes.
  bool phase_one_default_low = false;
  bool phase_one_sink = false;
  for (const std::vector<std::string>& command : phase_one) {
    for (const std::string& token : command) {
      if (token == winsvpn::winn3::detail::kDefaultRouteLowHalf) {
        phase_one_default_low = true;
      }
      if (token == kIPv6SinkAddress) phase_one_sink = true;
    }
  }
  Check(!phase_one_default_low,
        "phase one installs no default route: a start never begins wide");
  Check(!phase_one_sink,
        "phase one installs no IPv6 sink: fail-closed v6 belongs to the "
        "widening, not to the base");

  // Phase two is the widening, and it is a real, non-empty widening.
  const std::vector<std::vector<std::string>> delta =
      PromotedCommandDelta(phase_two, phase_one);
  Check(!delta.empty(),
        "phase two is a real widening: the delta to promotion is not empty");
  std::string capture_error;
  Check(VerifyPromotedCommandsCapture(delta, &capture_error),
        "and phase two captures traffic: " + capture_error);

  bool delta_default_low = false;
  bool delta_default_high = false;
  bool delta_next_hop = false;
  for (const std::vector<std::string>& command : delta) {
    for (const std::string& token : command) {
      if (token == winsvpn::winn3::detail::kDefaultRouteLowHalf) {
        delta_default_low = true;
      }
      if (token == winsvpn::winn3::detail::kDefaultRouteHighHalf) {
        delta_default_high = true;
      }
      if (token == "10.9.0.1/32") delta_next_hop = true;
    }
  }
  Check(delta_default_low && delta_default_high,
        "the second phase carries the default-route /1 halves: widening, not "
        "a new base");
  Check(!delta_next_hop,
        "the second phase does NOT re-issue the bootstrap's next-hop add "
        "route -- the exact command whose second issue fails 'already exists' "
        "on winpc");
}

// TestIdempotentClose pins that "closing" a promoted tunnel is idempotent: a
// repeated close runs no command that could fail, whether the tunnel is up or
// already down.
//
// The Windows renderers only ever ADD (set address, set subinterface, add
// route). There is no `delete route` here, so a promoted tunnel is CLOSED by
// tearing the interface down -- exactly what StopWindowsWinn3Tunnel does, a
// kill-on-job-close -- never by running netsh in reverse. The decidable
// invariant that keeps a repeated close from re-issuing a command that answers
// "The object already exists." / "The system cannot find the file specified"
// on winpc is that the command set is a fixed point:
//
//   - re-applying an already-applied promoted set is an EMPTY delta, and
//   - closing an already-closed (nothing-applied) set is an EMPTY delta.
//
// So a supervisor whose close re-runs these commands is provably a no-op on the
// second pass rather than a command that fails. The mutation that would break
// this is dropping the "already done" filter in PromotedCommandDelta so it
// always returns the whole promoted set -- that makes both EMPTY-delta
// assertions go red.
void TestIdempotentClose() {
  Winn3HostConfig config = GoodConfig();
  config.full_routes = {"0.0.0.0/0"};
  config.dns_servers = {"10.9.0.53"};
  config.dns_servers_are_inner = true;
  const EngineStatus status = CarryingStatus();
  const PostureInput input = PostureInputFrom(config, "pin", status);
  PosturePlan bootstrap, promoted;
  std::string error;
  Check(BuildBootstrapPosture(input, status, &bootstrap, &error) &&
            BuildPromotedPosture(input, status, &promoted, &error),
        "both postures build for the close test: " + error);

  const std::vector<std::vector<std::string>> narrow =
      RenderWindowsPostureCommands("winsvpn3", bootstrap);
  const std::vector<std::vector<std::string>> wide =
      RenderWindowsPostureCommands("winsvpn3", promoted);

  // A full start applies narrow, then the widening: the applied SET is exactly
  // the promoted render. Order-insensitive: phase one runs first, then the
  // delta, so the next-hop that phase one already holds lands ahead of the
  // sink command the renderer would emit -- same commands, different order.
  std::vector<std::vector<std::string>> applied = narrow;
  for (const std::vector<std::string>& command : PromotedCommandDelta(wide, narrow)) {
    applied.push_back(command);
  }
  bool all_wide_applied = true;
  for (const std::vector<std::string>& command : wide) {
    bool found = false;
    for (const std::vector<std::string>& got : applied) {
      if (got == command) {
        found = true;
        break;
      }
    }
    if (!found) all_wide_applied = false;
  }
  Check(applied.size() == wide.size() && all_wide_applied,
        "after a full start the applied SET is exactly the promoted render "
        "(phase one, then the widening)");

  // Closing an interface that still holds the promoted set must not re-run any
  // of it: the "already applied" filter makes a repeat close an empty no-op.
  Check(PromotedCommandDelta(applied, applied).empty(),
        "re-closing an already-applied promoted set runs nothing");
  // And closing an already-closed set (nothing applied) is an empty no-op too.
  const std::vector<std::vector<std::string>> none;
  Check(PromotedCommandDelta(none, none).empty(),
        "closing an already-closed set runs nothing");

  // There is no delete/remove in the rendered vocabulary, so close cannot be
  // a netsh reversal: every command this renderer emits is an add/set, which a
  // torn-down interface cannot satisfy. The supervisor's close therefore has to
  // be the adapter teardown, and a repeat of it must issue nothing.
  for (const std::vector<std::string>& command : narrow) {
    Check(command.size() >= 2 && command[0] == "netsh",
          "every rendered command is a netsh argument vector");
  }
  for (const std::vector<std::string>& command : wide) {
    for (const std::string& token : command) {
      Check(token != "delete" && token != "remove",
            "no rendered command is a delete/remove: close is teardown, never "
            "a netsh reversal");
    }
  }
}

void TestWin32Quoting() {
  Check(QuoteWin32Argument("netsh") == "netsh",
        "an ordinary token is passed through unchanged");
  Check(QuoteWin32Argument("name=Local Area Connection") ==
            "\"name=Local Area Connection\"",
        "whitespace is quoted");
  Check(QuoteWin32Argument("") == "\"\"", "an empty argument is quoted");
  Check(QuoteWin32Argument("a\"b") == "\"a\\\"b\"", "an interior quote escapes");
  Check(QuoteWin32Argument("C:\\a b\\") == "\"C:\\a b\\\\\"",
        "a trailing backslash is doubled so it does not escape the closing "
        "quote and swallow the next argument");
  Check(QuoteWin32Argument("C:\\path\\file") == "C:\\path\\file",
        "backslashes with no whitespace need no quoting at all");
  Check(RenderWin32CommandLine({"netsh", "interface", "ipv4", "set",
                                "subinterface", "winsvpn3", "mtu=1139",
                                "store=active"}) ==
            "netsh interface ipv4 set subinterface winsvpn3 mtu=1139 "
            "store=active",
        "the common case is byte-identical to what an operator would type");
}

// --- the cross-language conformance check -----------------------------------

void TestARealEngineDocumentParses() {
  // A verbatim status line as encoding/json emits winn3Status: no spaces, keys
  // in struct order, every field present. If the engine's schema drifts, this
  // is the check that fails on a development machine rather than in Myanmar.
  const std::string line =
      "{\"event\":\"posture\",\"posture\":\"bootstrap\","
      "\"promotion_ready\":false,\"gate_state\":\"closed\",\"rx_packets\":0,"
      "\"rx_offered\":0,\"tx_packets\":0,\"tx_dropped_closed\":0,"
      "\"rx_dropped_closed\":0,\"tx_dropped_invalid\":0,\"messages_sent\":0,"
      "\"messages_received\":0,\"send_failed\":0,\"recv_failed\":0,"
      "\"migrations\":0,\"inner_mtu\":1139,\"message_size\":1168,"
      "\"inner_ipv6\":false,\"plan\":[\"udp\",\"tcp\",\"tls\"],"
      "\"outer_socket_exclusion\":\"physical /32 pin\"}";
  EngineStatus status;
  Check(ParseWinn3StatusLine(line, &status), "a real status document parses");
  Check(status.inner_mtu == 1139 && status.message_size == 1168,
        "and carries the floor's arithmetic: 1168 - 29 = 1139");
  Check(!status.promotion_ready && status.gate_state == "closed",
        "and refuses to promote");
  std::string reason;
  Check(DecideWinn3Promotion(status, 1139, &reason) ==
            Winn3PromotionVerdict::kHold,
        "which the supervisor reads as hold");

  // tx_dropped_invalid must not be read as tx_dropped_closed. They are
  // different claims -- "the gate refused while shut" versus "the gate was OPEN
  // and the packet was refused anyway, most importantly for a source address
  // this session was never assigned" -- and one number would conflate them.
  const std::string distinct =
      "{\"event\":\"posture\",\"promotion_ready\":false,"
      "\"tx_dropped_invalid\":7,\"tx_dropped_closed\":3,\"inner_mtu\":1139}";
  EngineStatus counters;
  Check(ParseWinn3StatusLine(distinct, &counters) &&
            counters.tx_dropped_closed == 3,
        "tx_dropped_closed is read as itself and not as tx_dropped_invalid");
}

// --- the two conformance modes ----------------------------------------------
//
// These exist so that the SAME code the service compiles can be pointed at a
// REAL winn-datapath binary, in both directions, by
// tools/verify_winn3_windows_supervisor.sh:
//
//   -emit-profile <host_port>   [winn3] section on stdin -> profile on stdout
//   -parse                      status documents on stdin -> the verdict
//
// A parser tested only against literals a human typed is a parser tested
// against what that human believed the other side emits. This is the check
// that reads what it actually emits.

int EmitProfile(int host_port) {
  std::string raw;
  std::string line;
  while (std::getline(std::cin, line)) {
    raw += line;
    raw += "\n";
  }
  Winn3HostConfig config;
  std::string error;
  if (!ParseWinn3Section(raw, &config, &error)) {
    std::fprintf(stderr, "refused: %s\n", error.c_str());
    return 1;
  }
  std::printf("%s\n", BuildWinn3ProfileJson(
                          config, host_port,
                          "pinned /32 host route on the physical interface")
                          .c_str());
  return 0;
}

int ParseDocuments() {
  std::string line;
  int parsed = 0;
  while (std::getline(std::cin, line)) {
    EngineStatus status;
    if (!ParseWinn3StatusLine(line, &status)) {
      continue;
    }
    ++parsed;
    std::printf(
        "parsed event=%s posture=%s promotion_ready=%s gate=%s rx_packets=%llu "
        "inner_mtu=%d message_size=%d inner_ipv6=%s\n",
        status.event.c_str(), status.posture.c_str(),
        status.promotion_ready ? "true" : "false", status.gate_state.c_str(),
        static_cast<unsigned long long>(status.rx_packets), status.inner_mtu,
        status.message_size, status.inner_ipv6 ? "true" : "false");

    std::string mtu_error;
    std::printf("published inner MTU accepted: %s\n",
                VerifyPublishedInnerMtu(status.inner_mtu, &mtu_error)
                    ? "yes"
                    : mtu_error.c_str());
    std::printf("start command the relay would receive: %s",
                RenderStartCommand(status.inner_mtu, 51001).c_str());

    std::string reason;
    switch (DecideWinn3Promotion(status, status.inner_mtu, &reason)) {
      case Winn3PromotionVerdict::kPromote:
        std::printf("verdict: PROMOTE\n");
        break;
      case Winn3PromotionVerdict::kHold:
        std::printf("verdict: HOLD -- %s\n", reason.c_str());
        break;
      case Winn3PromotionVerdict::kRefuse:
        std::printf("verdict: REFUSE -- %s\n", reason.c_str());
        break;
    }

    Winn3HostConfig config = GoodConfig();
    const PostureInput input = PostureInputFrom(config, "pin", status);
    PosturePlan plan;
    std::string error;
    if (BuildBootstrapPosture(input, status, &plan, &error) &&
        VerifyBootstrapIsNarrow(plan, &error)) {
      std::printf("bootstrap from the engine's own numbers: mtu=%d routes=%zu "
                  "default=%s ipv6=%s dns=%zu\n",
                  plan.mtu, plan.included_routes.size(),
                  plan.default_route ? "yes" : "no", plan.ipv6 ? "yes" : "no",
                  plan.dns_servers.size());
      for (const std::vector<std::string>& command :
           RenderWindowsPostureCommands("winsvpn3", plan)) {
        std::printf("  would run: %s\n",
                    RenderWin32CommandLine(command).c_str());
      }
    } else {
      std::printf("bootstrap refused: %s\n", error.c_str());
    }
  }
  if (parsed == 0) {
    std::fprintf(stderr, "no status document was parsed from stdin\n");
    return 1;
  }
  return 0;
}

void TestWindowsWinn3LivenessNeverFallsThroughToV1() {
  Check(std::string(winsvpn::winn3::kRelayAdapterName) == "winsvpn3",
        "the v3 adapter is winsvpn3");
  Check(winsvpn::winn3::WindowsTunnelRunningConsideringV3(true, true, true,
                                                          false),
        "promoted v3 with both children is live");
  Check(!winsvpn::winn3::WindowsTunnelRunningConsideringV3(true, true, false,
                                                           true),
        "v3 active but not promoted must not fall through to v1");
  Check(!winsvpn::winn3::WindowsTunnelRunningConsideringV3(true, false, true,
                                                           true),
        "v3 active with a dead datapath must not fall through to v1");
  Check(!winsvpn::winn3::WindowsTunnelRunningConsideringV3(true, false, false,
                                                           true),
        "a v3 session is never reported live via the v1 path");
  Check(winsvpn::winn3::WindowsTunnelRunningConsideringV3(false, false, false,
                                                           true),
        "with no v3 session, the v1 running answer is used");
}

void TestWindowsWinn3ProofOutcomesAndFallbackAuthorization() {
  using winsvpn::winn3::ClassifyWinn3ProofDiagnostic;
  using winsvpn::winn3::ClassifyWinn3StartFailure;
  using winsvpn::winn3::MakeConnectedWinn3StartProof;
  using winsvpn::winn3::Winn3ProofOutcome;
  using winsvpn::winn3::Winn3ProofOutcomeName;
  using winsvpn::winn3::Winn3StartProofAuthorizesOrdinaryFallback;

  Check(std::string(Winn3ProofOutcomeName(Winn3ProofOutcome::kConnected)) ==
            "connected",
        "connected wire name");
  Check(std::string(Winn3ProofOutcomeName(
            Winn3ProofOutcome::kOrdinaryConnectivity)) ==
            "ordinary_connectivity",
        "ordinary_connectivity wire name");
  Check(std::string(Winn3ProofOutcomeName(
            Winn3ProofOutcome::kTerminalSecurity)) == "terminal_security",
        "terminal_security wire name");
  Check(std::string(Winn3ProofOutcomeName(
            Winn3ProofOutcome::kUnknownTerminal)) == "unknown_terminal",
        "unknown_terminal wire name");

  Check(ClassifyWinn3ProofDiagnostic("Network is unreachable") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "diagnostic strings never authorize ordinary connectivity");
  Check(ClassifyWinn3ProofDiagnostic("WSAENETUNREACH") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "WSA name text is not a structured OS error");
  Check(ClassifyWinn3ProofDiagnostic("No route to host") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "EHOSTUNREACH prose is not a structured OS error");
  Check(ClassifyWinn3ProofDiagnostic("connection refused") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "connection refused never authorizes cover");
  Check(ClassifyWinn3ProofDiagnostic("stderr: Network is unreachable", 10051) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "WSAENETUNREACH 10051 is ordinary only as a structured OS error");
  Check(ClassifyWinn3ProofDiagnostic("timeout", 10051, true) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "timeout overrides an ordinary OS error");
  Check(ClassifyWinn3ProofDiagnostic("", 10050) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "WSAENETDOWN 10050 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 10064) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "WSAEHOSTDOWN 10064 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 10065) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "WSAEHOSTUNREACH 10065 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 10061) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "WSAECONNREFUSED is not ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 51) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "Darwin ENETUNREACH is not a Windows ordinary code");

  Check(ClassifyWinn3ProofDiagnostic("admission rejected") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "admission refusal is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "handshake messages arrived and none of them could be opened") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "unopenable handshake is a credential fault");
  Check(ClassifyWinn3ProofDiagnostic("replay window refused the initiation") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "replay is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "the status document disagrees with itself") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "proof integrity disagreement is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "The Winn Protocol v3 relay reported an unexpected adapter name") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "wrong adapter name is proof integrity");
  Check(ClassifyWinn3ProofDiagnostic(
            "[winn] signed descriptor node and selected node must both "
            "be a strict ASCII node identity and match; a missing "
            "identity, Unicode homoglyph, alias conflict, or "
            "cross-node replay is refused before credential files "
            "or session start") == Winn3ProofOutcome::kTerminalSecurity,
        "descriptor-to-selected-node refusal is terminal security");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(
            ClassifyWinn3StartFailure(
                21, false,
                "[winn3] signed descriptor node and selected node must both "
                "be a strict ASCII node identity and match"),
            21),
        "a node-binding security refusal must not authorize v1 fallback");

  Check(ClassifyWinn3ProofDiagnostic(
            "the Winn Protocol v3 datapath was never proven") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "proof timeout without network evidence is unknown");
  Check(ClassifyWinn3ProofDiagnostic(
            "the datapath stopped before it carried anything") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "engine death without network evidence is unknown");
  Check(ClassifyWinn3ProofDiagnostic("") == Winn3ProofOutcome::kUnknownTerminal,
        "an empty diagnostic cannot authorize fallback");

  const auto ordinary = ClassifyWinn3StartFailure(
      21, false, "bind failed", 10051, 99, "0123456789abcdef", "node-a");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 21, 99),
        "matching generation plus WSA OS error and token authorizes fallback");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 22, 99),
        "a stale generation cannot authorize fallback");
  Check(ordinary.start_token == 99, "ordinary proof echoes the start token");
  Check(winsvpn::winn3::Winn3AuthorizationToken(ordinary) == 99,
        "authorization token exists only for ordinary verdict");
  const auto unknown = ClassifyWinn3StartFailure(
      21, false, "the Winn Protocol v3 datapath was never proven");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(unknown, 21),
        "unknown_terminal fails closed");
  const auto security =
      ClassifyWinn3StartFailure(21, false, "admission rejected");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(security, 21),
        "terminal_security fails closed");
  const auto canceled = ClassifyWinn3StartFailure(
      21, false, "Tunnel start was canceled before the transport launched.");
  Check(canceled.canceled, "cancel wording is detected from the diagnostic");
  Check(canceled.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "cancel is unknown_terminal");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(canceled, 21),
        "stop/cancel does not authorize fallback");
  const auto connected = MakeConnectedWinn3StartProof(21);
  Check(connected.outcome == Winn3ProofOutcome::kConnected,
        "a successful start is connected");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(connected, 21),
        "connected does not authorize fallback");
}

void TestWindowsWinn3CapturedOsErrorPropagatesToCover() {
  using winsvpn::winn3::ArmWinn3AwgXrayGrant;
  using winsvpn::winn3::ClassifyCapturedWinn3StartFailure;
  using winsvpn::winn3::ClassifyWinn3StartFailure;
  using winsvpn::winn3::ConsumeWinn3AwgXrayGrant;
  using winsvpn::winn3::kWindowsWsaEnetunreach;
  using winsvpn::winn3::PeekWindowsWinn3OsError;
  using winsvpn::winn3::RememberWindowsWinn3OsError;
  using winsvpn::winn3::TakeWindowsWinn3OsError;
  using winsvpn::winn3::Winn3AwgXrayGrant;
  using winsvpn::winn3::Winn3CoverLeg;
  using winsvpn::winn3::Winn3GrantConsumeResult;
  using winsvpn::winn3::Winn3ProofOutcome;
  using winsvpn::winn3::Winn3StartProofAuthorizesOrdinaryFallback;

  RememberWindowsWinn3OsError(0);
  Check(TakeWindowsWinn3OsError() == 0, "empty capture slot is zero");

  const std::string prose = "Network is unreachable";
  Check(ClassifyWinn3StartFailure(21, false, prose, 0, 99, "0123456789abcdef",
                                  "node-a")
                .outcome == Winn3ProofOutcome::kUnknownTerminal,
        "production os_error=0 never authorizes from prose");

  RememberWindowsWinn3OsError(kWindowsWsaEnetunreach);
  Check(PeekWindowsWinn3OsError() == kWindowsWsaEnetunreach,
        "remember stores the exact WSA integer");
  const auto ordinary = ClassifyCapturedWinn3StartFailure(
      21, false, prose, 99, "0123456789abcdef", "node-a");
  Check(ordinary.os_error == kWindowsWsaEnetunreach,
        "captured WSAENETUNREACH is stored on the proof");
  Check(ordinary.outcome == Winn3ProofOutcome::kOrdinaryConnectivity,
        "WSAENETUNREACH authorizes ordinary_connectivity");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 21, 99),
        "captured WSAENETUNREACH authorizes generation-bound cover");
  Check(PeekWindowsWinn3OsError() == 0, "classify consumes the captured error");

  Winn3AwgXrayGrant grant;
  Check(ArmWinn3AwgXrayGrant(99, 21, "0123456789abcdef", "node-a", 1000, &grant),
        "ordinary captured start arms the one-use grant");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 99, 21, "0123456789abcdef", "node-a",
                                 "v1-cover", Winn3CoverLeg::kAwg, 1001) ==
            Winn3GrantConsumeResult::kOk,
        "first cover consume is AWG");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 99, 21, "0123456789abcdef", "node-a",
                                 "v1-cover", Winn3CoverLeg::kXray, 1002) ==
            Winn3GrantConsumeResult::kOk,
        "optional Xray consume follows AWG");

  RememberWindowsWinn3OsError(10061);
  const auto refused = ClassifyCapturedWinn3StartFailure(
      21, false, prose, 99, "0123456789abcdef", "node-a");
  Check(refused.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "WSAECONNREFUSED is not ordinary");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(refused, 21, 99),
        "WSAECONNREFUSED never authorizes cover");

  RememberWindowsWinn3OsError(51);
  const auto darwin = ClassifyCapturedWinn3StartFailure(
      21, false, prose, 99, "0123456789abcdef", "node-a");
  Check(darwin.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "Darwin ENETUNREACH is not a Windows ordinary code");

  RememberWindowsWinn3OsError(kWindowsWsaEnetunreach);
  const auto security = ClassifyCapturedWinn3StartFailure(
      21, false, "admission rejected", 99, "0123456789abcdef", "node-a");
  Check(security.outcome == Winn3ProofOutcome::kTerminalSecurity,
        "terminal security wins over WSAENETUNREACH");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(security, 21, 99),
        "security plus WSAENETUNREACH does not authorize cover");

  RememberWindowsWinn3OsError(kWindowsWsaEnetunreach);
  const auto timed_out = ClassifyCapturedWinn3StartFailure(
      21, false, prose, 99, "0123456789abcdef", "node-a", true);
  Check(timed_out.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "timeout wins over WSAENETUNREACH");

  RememberWindowsWinn3OsError(kWindowsWsaEnetunreach);
  const auto canceled = ClassifyCapturedWinn3StartFailure(
      21, true, prose, 99, "0123456789abcdef", "node-a");
  Check(canceled.canceled, "cancel flag is preserved");
  Check(canceled.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "cancel wins over WSAENETUNREACH");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(canceled, 21, 99),
        "cancel never authorizes cover");
}

void TestWindowsWinn3StartReadinessStop() {
  using winsvpn::winn3::ClassifyWinn3StartFailure;
  using winsvpn::winn3::MakeConnectedWinn3StartProof;
  using winsvpn::winn3::WindowsTunnelRunningConsideringV3;
  using winsvpn::winn3::Winn3StartProof;
  using winsvpn::winn3::Winn3StartProofAuthorizesOrdinaryFallback;

  Winn3StartProof proof = MakeConnectedWinn3StartProof(33);
  bool v3_active = true;
  Check(WindowsTunnelRunningConsideringV3(v3_active, true, true, true),
        "start then readiness: promoted v3 is live");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(proof, 33),
        "a connected start does not authorize fallback");

  v3_active = false;
  proof = Winn3StartProof();
  Check(!WindowsTunnelRunningConsideringV3(v3_active, true, true, false),
        "stop clears v3_active so leftover children are not the user tunnel");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(proof, 33),
        "a stopped session does not keep a fallback authorization");

  proof = ClassifyWinn3StartFailure(34, false, "route failed", 10065, 77,
                                    "0123456789abcdef", "node-a");
  v3_active = false;
  Check(!WindowsTunnelRunningConsideringV3(v3_active, false, false, false),
        "a failed start is not live");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(proof, 34, 77),
        "ordinary connectivity after start-readiness-stop may fallback");
}

void TestWindowsWinn3GrantTtlOrderAndProbeAlias() {
  using winsvpn::winn3::ArmWinn3AwgXrayGrant;
  using winsvpn::winn3::ClassifyWindowsTunnelProbeAlias;
  using winsvpn::winn3::ConsumeWinn3AwgXrayGrant;
  using winsvpn::winn3::WindowsTunnelProbeAlias;
  using winsvpn::winn3::WindowsTunnelProbeAliasName;
  using winsvpn::winn3::Winn3AwgXrayGrant;
  using winsvpn::winn3::Winn3CoverLeg;
  using winsvpn::winn3::Winn3GrantConsumeResult;
  using winsvpn::winn3::kRelayAdapterName;
  using winsvpn::winn3::kWinn1AdapterName;

  Winn3AwgXrayGrant grant;
  Check(ArmWinn3AwgXrayGrant(9, 3, "0123456789abcdef", "v3-node", 1000, &grant),
        "ordinary identities arm a one-use grant");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kXray, 1001) ==
            Winn3GrantConsumeResult::kWrongLeg,
        "Xray cannot consume before AWG");
  Check(grant.start_token == 0, "wrong-leg consume clears the grant");
  Check(ArmWinn3AwgXrayGrant(9, 3, "0123456789abcdef", "v3-node", 1000, &grant),
        "re-arm after wrong-leg clear");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 1001) ==
            Winn3GrantConsumeResult::kOk,
        "first consume is AWG and binds the exact v1 target");
  Check(grant.next_leg == Winn3CoverLeg::kXray, "next cover leg is Xray");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "other-node", Winn3CoverLeg::kXray, 1002) ==
            Winn3GrantConsumeResult::kMismatch,
        "Xray against a different returned node is refused");
  Check(ArmWinn3AwgXrayGrant(9, 3, "0123456789abcdef", "v3-node", 1000, &grant),
        "re-arm for TTL");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 1000) ==
            Winn3GrantConsumeResult::kOk,
        "AWG consume inside TTL");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kXray,
                                 1000 + 60001) ==
            Winn3GrantConsumeResult::kExpired,
        "grant expires at 60s monotonic");
  Check(ArmWinn3AwgXrayGrant(9, 3, "0123456789abcdef", "v3-node", 1000, &grant),
        "re-arm for AWG then Xray success");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 1010) ==
            Winn3GrantConsumeResult::kOk,
        "AWG consume");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 9, 3, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kXray, 1011) ==
            Winn3GrantConsumeResult::kOk,
        "optional Xray consume clears the grant");
  Check(grant.start_token == 0, "Xray completion clears the one-use grant");

  Check(ClassifyWindowsTunnelProbeAlias(true, true, true, false) ==
            WindowsTunnelProbeAlias::kWinn3,
        "live v3 uses winsvpn3");
  Check(std::string(WindowsTunnelProbeAliasName(
            WindowsTunnelProbeAlias::kWinn3)) == kRelayAdapterName,
        "v3 probe alias is winsvpn3");
  Check(ClassifyWindowsTunnelProbeAlias(false, false, false, true) ==
            WindowsTunnelProbeAlias::kWinn1,
        "live v1 uses winsvpn");
  Check(std::string(WindowsTunnelProbeAliasName(
            WindowsTunnelProbeAlias::kWinn1)) == kWinn1AdapterName,
        "v1 probe alias is winsvpn");
  Check(ClassifyWindowsTunnelProbeAlias(true, true, false, false) ==
            WindowsTunnelProbeAlias::kRefuse,
        "stale v3 session refuses a probe alias");
  Check(ClassifyWindowsTunnelProbeAlias(true, true, true, true) ==
            WindowsTunnelProbeAlias::kRefuse,
        "ambiguous v3+v1 live session refuses a probe alias");
}

void TestWindowsWinn3ConcurrentSnapshot() {
  using winsvpn::winn3::Winn3HostSessionGuard;
  using winsvpn::winn3::Winn3HostSessionSnapshot;
  Winn3HostSessionGuard guard;
  std::atomic<int> mismatches{0};
  std::thread writer([&]() {
    for (int i = 1; i <= 4000; ++i) {
      Winn3HostSessionSnapshot snapshot;
      snapshot.proof.generation = i;
      snapshot.proof.start_token = i;
      snapshot.v3_active = (i % 2) == 0;
      snapshot.v3_running = snapshot.v3_active;
      snapshot.v3_promoted = snapshot.v3_active;
      guard.Store(snapshot);
    }
  });
  std::thread reader([&]() {
    for (int i = 0; i < 4000; ++i) {
      const Winn3HostSessionSnapshot snapshot = guard.Load();
      if (snapshot.proof.generation != snapshot.proof.start_token) {
        mismatches.fetch_add(1, std::memory_order_relaxed);
      }
    }
  });
  writer.join();
  reader.join();
  Check(mismatches.load() == 0,
        "one mutex snapshot never tears generation from token");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2 && std::string(argv[1]) == "-parse") {
    return ParseDocuments();
  }
  if (argc >= 3 && std::string(argv[1]) == "-emit-profile") {
    return EmitProfile(std::atoi(argv[2]));
  }
  TestSelectionIsItsOwnSection();
  TestTheServedSectionSelectsV3AndNotWinn1();
  TestTheServedSectionParsesIntoTheSameSession();
  TestTheServedSectionBindsTheSelectedNode();
  TestNativeStartBindsTheIndependentPickerNode();
  TestBothSpellingsRequireTheSameStrictAsciiNodeIdentity();
  TestTheServedKeyMaterialBecomesFilesAndNeverEntersTheProfile();
  TestTheServedDualAuthPairIsConsumedAndBound();
  TestTheServedDualAuthPairRefusesMismatchMissingAndStale();
  TestTheServedSectionRefusesTheEncodingMistakesThatAreSilent();
  TestBothProtocolsAtOnceIsRefused();
  TestUnknownKeyIsARefusal();
  TestEndpointMustBeAnIpLiteral();
  TestEndpointSplitFeedsTheRoutePin();
  TestThePlanMustCoverTheDialledClass();
  TestRequiredFields();
  TestResolversNeedTheInnerDeclaration();
  TestTheProfileIsTheEnginesDocument();
  TestWindowsPathsSurviveJsonEncoding();
  TestRelayHostPortLine();
  TestEngineSeamPortLine();
  TestRelayReadyLine();
  TestStartCommandIsByteExact();
  TestPublishedPlanMtusAreAccepted();
  TestTheAppliedMtuMustKeepAgreeing();
  TestTheAdapterNameIsNotTheWinn1One();
  TestInnerIPv6IsArithmeticallyPossibleAtTheFloor();
  TestPromotionNeedsBothHalves();
  TestADocumentThatDisagreesWithItselfIsRefused();
  TestAReadyClaimBesideAGateThatMayNotCarryIsRefused();
  TestRefusalAndUnparsedAreDifferentAnswers();
  TestBootstrapPromotesRoutesOnlyAfterTransportObservedBothWays();
  TestBootstrapIsNarrowFromARealConfig();
  TestPostureInputFromCarriesInnerIPv6OnlyWhenTheEngineCanCarryIt();
  TestPromotedPostureRendersRealNetshCommands();
  TestPromotedCommandDeltaIsIdempotentAcrossRepeatApply();
  TestRenderedRouteCommandsAreActiveStoreOnly();
  TestWindowsWinn3StartIsTwoPhase();
  TestIdempotentClose();
  TestWin32Quoting();
  TestARealEngineDocumentParses();
  TestWindowsWinn3LivenessNeverFallsThroughToV1();
  TestWindowsWinn3ProofOutcomesAndFallbackAuthorization();
  TestWindowsWinn3CapturedOsErrorPropagatesToCover();
  TestWindowsWinn3StartReadinessStop();
  TestWindowsWinn3GrantTtlOrderAndProbeAlias();
  TestWindowsWinn3ConcurrentSnapshot();
  if (failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("winn3_supervisor_test: all checks passed\n");
  return 0;
}
