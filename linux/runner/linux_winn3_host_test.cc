// Tests for the Linux Winn Protocol v3 host.
//
// WHY THIS FILE EXISTS. Before 2026-08-09 linux/runner contained ZERO
// occurrences of `winn3` outside a test: linux_winn_host.cc passed only
// `-transport` and `-carrier-profile`, CMakeLists.txt compiled no v3 source,
// and windows/runner/winn3_posture.h -- the policy that decides when a user's
// default route, IPv6 and resolvers move onto a tunnel -- had no caller on this
// platform at all. Meanwhile the protocol itself was proven on Linux: a v3
// session carried 4,194,304 bytes of TCP through two real /dev/net/tun devices
// across two network namespaces, digest byte-identical, reproduced twice. The
// protocol was never the question. The host wiring was.
//
// The three things this file is really guarding:
//
//  1. THE PLAN FLOOR. sizing:: is a C++ mirror of winn3/carrier/sizing.go, and
//     a drift in it is the 84-byte black hole: every full-size flow dies at the
//     first migration while the tunnel still reads up, small packets keep
//     working, and the report comes from a country where nobody can attach a
//     debugger. TestSizingAgreesWithGo pins the same seven worked examples
//     Android's WinnV3Sizing.assertsAgreeWithGo() does.
//
//  2. THE PAYLOAD CLASS. `ip-packet` against `awg-datagram`. Getting it wrong
//     in the winn/1 direction hands inner IP packets to an engine with no
//     WireGuard implementation, which forwards them to the gateway in
//     CLEARTEXT.
//
//  3. THE PROMOTION SHAPE. The winn/1 gate on Linux runs AFTER awg-quick has
//     claimed the host's routing, so it decides keep-vs-teardown. A standalone
//     v3 session has no awg-quick, and its proof -- RxPackets > 0 -- is
//     defined over a host device that must therefore already exist. So Linux v3
//     is neither the Linux v1 shape nor the Windows one, and
//     TestTheV1ShapeWouldHaveWidenedWhereV3Refuses is the load-bearing test:
//     it replays a v1-shaped decision beside the v3 one over the same status
//     documents and shows the v1 shape widening where v3 refuses.
//
// It is deliberately free of glib/gio and of <windows.h> -- like
// winn3_posture_test.cc, linux_winn_gate_test.cc and
// linux_winn_carrier_profile_test.cc, and for the same stated reason -- so it
// builds and RUNS on the development host as well as on the target. A test that
// only Linux can execute is a test that does not get run.
//
// Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -o /tmp/linux_winn3_host_test
//       linux/runner/linux_winn3_host_test.cc linux/runner/linux_winn3_host.cc
//   /tmp/linux_winn3_host_test
//
// It is registered as the linux_winn3_host_test ctest target in
// linux/runner/CMakeLists.txt, with linux_winn_gate_test and
// winn3_posture_test. It can also be built as a standalone program with its
// own main so it still runs on the development host without a full Flutter
// Linux configure. linux_winn_carrier_profile_test.cc remains standalone-only.

#include "linux_winn3_host.h"

#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
// std::strlen. libc++ pulls it in transitively so clang on the development
// host never noticed; libstdc++ does not, so `g++ -Werror` on the TARGET
// platform could not build this file at all.
#include <cstring>
#include <sstream>
#include <string>
#include <utility>
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

using winsvpn::winn3::EngineStatus;
using winsvpn::winn3::ParseWinn3StatusLine;
using winsvpn::winn3::Posture;
using winsvpn::winn3::PosturePlan;
using winsvpn::winn3host::DecideLinuxWinn3Promotion;
using winsvpn::winn3host::LinuxWinn3Keys;
using winsvpn::winn3host::LinuxWinn3Params;
using winsvpn::winn3host::LinuxWinn3Promotion;
using winsvpn::winn3host::LinuxConfigSelectsWinn3;
using winsvpn::winn3host::LinuxWinn3ServedKeyMaterial;
using winsvpn::winn3host::NormalizeLinuxWinn3NodeIdentity;
using winsvpn::winn3host::ParseLinuxWinn3Section;
using winsvpn::winn3host::ValidateLinuxWinn3IndependentSelectedNode;
using winsvpn::winn3host::WriteLinuxWinn3KeyFiles;

using Mechanism = winsvpn::winn3host::LinuxWinn3ResolverMechanism;
using Outcome = winsvpn::winn3host::LinuxWinn3PostureOutcome;

using Commands = std::vector<std::vector<std::string>>;

std::string Join(const std::vector<std::string>& argv) {
  std::string out;
  for (const std::string& token : argv) {
    if (!out.empty()) out.push_back(' ');
    out += token;
  }
  return out;
}

bool Contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

bool HasCommand(const Commands& commands, const std::string& joined) {
  for (const std::vector<std::string>& argv : commands) {
    if (Join(argv) == joined) return true;
  }
  return false;
}

int IndexOfCommand(const Commands& commands, const std::string& joined) {
  for (size_t i = 0; i < commands.size(); ++i) {
    if (Join(commands[i]) == joined) return static_cast<int>(i);
  }
  return -1;
}

// A status document of the exact shape cmd/winn-datapath emits, built from
// winn3_status.go's own field list so that a field added there shows up here as
// a compile-free but visible omission rather than as a silently different test.
std::string StatusLine(bool ready, const std::string& gate, uint64_t rx_packets,
                       uint64_t rx_offered, int inner_mtu, bool inner_ipv6,
                       const std::string& refusal = std::string()) {
  std::ostringstream line;
  line << "{\"event\":\"posture\",\"posture\":\""
       << (ready ? "promoted" : "bootstrap") << "\",\"promotion_ready\":"
       << (ready ? "true" : "false") << ",\"gate_state\":\"" << gate << "\""
       << ",\"rx_packets\":" << rx_packets << ",\"rx_offered\":" << rx_offered
       << ",\"tx_packets\":0,\"tx_dropped_closed\":0,\"rx_dropped_closed\":0"
       << ",\"tx_dropped_invalid\":0"
       << ",\"messages_sent\":4,\"messages_received\":4,\"send_failed\":0"
       << ",\"recv_failed\":0,\"migrations\":0"
       << ",\"inner_mtu\":" << inner_mtu << ",\"message_size\":"
       << (inner_mtu + winsvpn::winn3host::sizing::kOverhead)
       << ",\"inner_ipv6\":" << (inner_ipv6 ? "true" : "false")
       << ",\"plan\":[\"udp\",\"tcp\",\"tls\"]"
       << ",\"outer_socket_exclusion\":\"host route 203.0.113.9/32\"";
  if (!refusal.empty()) line << ",\"refusal\":\"" << refusal << "\"";
  line << "}";
  return line.str();
}

// The plan floor at a 1500-byte path over [udp,tcp,tls]. Written out rather
// than computed so that a mistake in the mirror cannot make the test agree with
// itself; driver.NewSizing(1500, udp, tcp, tls).InnerMTU is 1359.
constexpr int kFloorInnerMtu1500 = 1359;

LinuxWinn3Params SampleParams() {
  LinuxWinn3Params params;
  params.interface_name = "winsvpn3";
  params.gateway_endpoint = "203.0.113.9:51820";
  params.inner_address = "10.64.0.2";
  params.inner_next_hop = "10.64.0.1";
  params.path_mtu = 1500;
  params.carrier_classes = {"udp", "tcp", "tls"};
  params.session_id = "0123456789abcdef0123456789abcdef";
  params.full_routes = {"0.0.0.0/1", "128.0.0.0/1"};
  params.dns_servers = {"10.64.0.1"};
  params.dns_servers_are_inner = true;
  params.physical_interface = "wlan0";
  params.physical_next_hop = "192.168.1.1";
  params.keys.role = "client";
  params.keys.gateway_id = "kansas-1";
  params.keys.static_path = "/home/u/.local/share/wins_vpn/winn3/static.key";
  params.keys.gateway_static_path =
      "/home/u/.local/share/wins_vpn/winn3/gateway.pub";
  params.keys.admission_path =
      "/home/u/.local/share/wins_vpn/winn3/admission.key";
  params.keys.outer_socket_exclusion =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);
  return params;
}

// The joined `ip -4 route del ...` of SampleParams' own outer-socket exclusion.
//
// Taken from the renderer rather than written out, so the fake kernel below and
// the code under test cannot disagree about which route "ours" is -- which is
// the entire distinction the repair rule turns on.
std::string SampleExclusionDel() {
  const Commands teardown =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionTeardown(SampleParams());
  return teardown.empty() ? std::string() : Join(teardown.front());
}

// The destination-scoped prefix both exclusion forms share: `ip -4 route del
// 203.0.113.9/32` plus whatever the kernel needs to match it. The routed and
// on-link vectors differ only after the destination, and the fake kernel's
// "nothing stranded" answer must not depend on the form.
std::string SampleExclusionDelPrefix() {
  const std::string del = SampleExclusionDel();
  const size_t via = del.find(" via ");
  const size_t dev = del.find(" dev ");
  size_t cut = std::string::npos;
  if (via != std::string::npos) cut = via;
  if (dev != std::string::npos && (cut == std::string::npos || dev < cut)) {
    cut = dev;
  }
  return cut == std::string::npos ? del : del.substr(0, cut);
}

// A privileged runner that records instead of executing. Nothing in
// linux_winn3_host.cc may execute a command itself; this is how that is
// asserted rather than assumed.
struct RecordingRunner {
  Commands ran;
  // EVERY command handed to the runner, including the ones it refused. `ran`
  // holds only what succeeded, which is the right answer for "what is in the
  // kernel" and the wrong one for "what did this host TRY to do to the user's
  // routing table". The blocked-exclusion checks need the second question: the
  // claim being tested is that a route this product did not write is never
  // deleted, and a deletion that was attempted and failed would still be a
  // deletion that was attempted.
  Commands attempted;
  std::string fail_on;  // when non-empty, the joined command that fails
  // Joined commands that fail, by exact match. `fail_on` is kept for the
  // existing single-command cases; this carries a set, which the rollback
  // cases need because they have to fail a posture command AND a reversal.
  std::vector<std::string> fail_all;
  // Joined probe commands that SUCCEED. Everything else answers non-zero,
  // which is what a container with no systemd-resolved and no openresolv
  // actually does -- so the default RecordingRunner detects the mechanism a
  // bare Linux would.
  std::vector<std::string> probes_ok;
  // The standard input each command was handed, joined command -> bytes.
  std::vector<std::pair<std::string, std::string>> stdin_seen;

  // Does the kernel this fake stands for ALREADY hold this session's own
  // outer-socket exclusion when the bootstrap begins?
  //
  // A real machine does not, unless a previous session was killed between the
  // exclusion going in and its teardown running. So the default is false, and
  // the repair `del` that now opens every bootstrap answers "No such process"
  // on it -- the ordinary case rather than an error.
  //
  // It applies to the FIRST route del only, because the repair and the ROLLBACK
  // run the identical vector by construction and the rollback must still be
  // able to succeed. A single `fail_all` entry could not say that, which is
  // exactly why this exists rather than being spelled with one.
  //
  // Scoped to the session's OWN exclusion vector rather than to "the first
  // route del", because the PROMOTED applier's rollback deletes routes too and
  // it runs no repair -- a rule phrased over route deletions in general would
  // have made the first reversal of every promotion fail. Measured: it did.
  //
  // Matched on the destination rather than the whole vector, because the
  // exclusion has TWO forms since 2026-08-21 -- routed (`via <hop> dev
  // <iface>`) and on-link (`dev <iface>`) -- and a real kernel holds neither
  // of them at a bootstrap's open. Both dels must answer "No such process"
  // once, or the fake kernel would pretend to have removed an on-link route
  // it never held.
  bool stale_exclusion_in_kernel = false;
  bool exclusion_del_seen = false;

  bool IsOurExclusionDel(const std::string& joined) const {
    // The teardown of either form starts `ip [-4|-6] route del <host>/32`,
    // and the host part is the destination both forms pin.
    return joined.rfind("ip ", 0) == 0 &&
           joined.find(" route del ") != std::string::npos &&
           joined.rfind(SampleExclusionDelPrefix(), 0) == 0;
  }

  bool IsProbe(const std::string& joined) const {
    return joined.rfind("resolvectl --no-pager status", 0) == 0 ||
           joined.rfind("resolvconf -l", 0) == 0 ||
           joined.rfind("ip link show dev ", 0) == 0 ||
           joined.rfind("test ", 0) == 0;
  }

  static bool IsRouteDel(const std::string& joined) {
    return joined.rfind("ip ", 0) == 0 &&
           joined.find(" route del ") != std::string::npos;
  }

  winsvpn::winn3host::LinuxWinn3PrivilegedRunner Runner() {
    return [this](const std::vector<std::string>& argv,
                  const std::string& stdin_bytes, std::string* error) {
      const std::string joined = Join(argv);
      attempted.push_back(argv);
      if (IsProbe(joined)) {
        for (const std::string& ok : probes_ok) {
          if (ok == joined) return true;
        }
        if (error != nullptr) *error = "the test host does not have that";
        return false;
      }
      if (IsOurExclusionDel(joined) && !exclusion_del_seen) {
        exclusion_del_seen = true;
        if (!stale_exclusion_in_kernel) {
          if (error != nullptr) *error = "RTNETLINK answers: No such process";
          return false;
        }
      }
      if (!fail_on.empty() && joined == fail_on) {
        if (error != nullptr) *error = "refused by the test";
        return false;
      }
      for (const std::string& fail : fail_all) {
        if (fail == joined) {
          if (error != nullptr) *error = "refused by the test";
          return false;
        }
      }
      ran.push_back(argv);
      stdin_seen.push_back({joined, stdin_bytes});
      return true;
    };
  }
};

// The probe answer of a machine whose physical interface really is there. A
// bootstrap only asks when its exclusion has already been refused, to keep a
// mistyped `--phys-if` from being reported as a route that is in the way.
void GivePhysicalInterface(RecordingRunner* runner,
                           const std::string& device) {
  runner->probes_ok.push_back("ip link show dev " + device);
}

// The probe answers of a machine that has systemd-resolved running. Anything
// that does not set this is a machine that has none, which is the environment
// defect 2 of 2026-08-10 is about.
void GiveSystemdResolved(RecordingRunner* runner) {
  runner->probes_ok.push_back("resolvectl --no-pager status");
}
void GiveResolvconf(RecordingRunner* runner) {
  runner->probes_ok.push_back("resolvconf -l");
}
void GivePlainResolvConf(RecordingRunner* runner) {
  runner->probes_ok.push_back("test -f /etc/resolv.conf");
}

const char* OutcomeName(winsvpn::winn3host::LinuxWinn3PostureOutcome value) {
  return winsvpn::winn3host::LinuxWinn3PostureOutcomeName(value);
}

// --- sizing -----------------------------------------------------------------

void TestSizingAgreesWithGo() {
  namespace sizing = winsvpn::winn3host::sizing;
  std::string error;
  Check(sizing::AssertsAgreeWithGo(&error),
        "the sizing mirror agrees with winn3/carrier/sizing.go: " + error);

  // Spelled out separately from AssertsAgreeWithGo so that a mutation which
  // guts that function still fails a test.
  int inner = 0;
  Check(sizing::PlanFloorInnerMtu(1500, {"udp", "tcp", "tls"}, &inner, nullptr) &&
            inner == kFloorInnerMtu1500,
        "the plan floor inner MTU at a 1500-byte path is 1359");
  Check(sizing::PlanFloorInnerMtu(1280, {"udp", "tcp", "tls"}, &inner, nullptr) &&
            inner == 1139,
        "the plan floor inner MTU at a 1280-byte path is 1139");

  // THE 84-BYTE GAP, restated as the thing it prevents: sizing to the DIALLED
  // udp/IPv4 carrier gives 1443, and a tunnel configured at 1443 black-holes
  // every full-size flow the moment it migrates to tls over IPv6.
  Check(sizing::InnerMtuForPath(1500, sizing::kUdpOverIPv4Overhead) == 1443,
        "the dialled udp/IPv4 inner MTU at a 1500-byte path is 1443");
  Check(sizing::InnerMtuForPath(1500, sizing::kUdpOverIPv4Overhead) -
                kFloorInnerMtu1500 ==
            84,
        "the dialled carrier is 84 bytes wider than the plan floor");

  // A single-class plan is NOT the floor over the full plan, and a host that
  // sized to it would be making exactly the mistake the floor exists to stop.
  int udp_only = 0;
  Check(sizing::PlanFloorInnerMtu(1500, {"udp"}, &udp_only, nullptr) &&
            udp_only > kFloorInnerMtu1500,
        "a udp-only plan yields a wider inner MTU than the full plan");
}

void TestSizingRefusesRatherThanDefaults() {
  namespace sizing = winsvpn::winn3host::sizing;
  int out = 0;
  std::string error;
  Check(!sizing::PlanFloorMessageSize(1500, {}, &out, &error),
        "an empty migration plan is refused");
  Check(Contains(error, "escalate to"), "the empty-plan refusal says why");

  error.clear();
  Check(!sizing::PlanFloorMessageSize(1500, {"udp", "quic"}, &out, &error),
        "an unknown carrier class is refused rather than charged a default");
  Check(Contains(error, "quic"), "the unknown-class refusal names the class");

  int overhead = 0;
  Check(!sizing::CarrierOverhead("h3", true, &overhead),
        "CarrierOverhead has no default branch");

  error.clear();
  Check(!sizing::PlanFloorInnerMtu(200, {"udp"}, &out, &error),
        "a path MTU below the IPv4 floor is refused");
  Check(Contains(error, "576"), "the floor refusal names the 576-byte floor");
}

// --- the key document -------------------------------------------------------

void TestTheKeyDocumentNamesFilesAndHoldsNoKeyMaterial() {
  const LinuxWinn3Params params = SampleParams();
  std::string document;
  std::string error;
  Check(winsvpn::winn3host::BuildLinuxWinn3KeysJson(params.keys, &document,
                                                    &error),
        "a complete key document builds: " + error);

  // The engine decodes with DisallowUnknownFields, so the key set is part of
  // the contract rather than an implementation detail: one extra key is a hard
  // refusal at start. Pinning the whole set is what catches an addition here
  // that the Go document has not grown.
  const char* expected[] = {"\"version\":",
                            "\"role\":",
                            "\"gateway_id\":",
                            "\"static_path\":",
                            "\"gateway_static_path\":",
                            "\"admission_path\":",
                            "\"outer_socket_exclusion\":",
                            "\"fast_pq\":",
                            "\"rekey_after_messages\":"};
  size_t keys_present = 0;
  for (const char* key : expected) {
    if (Contains(document, key)) ++keys_present;
  }
  Check(keys_present == 9, "the key document carries exactly the nine fields "
                           "winn3Keys declares");
  size_t colons = 0;
  for (size_t at = document.find("\":"); at != std::string::npos;
       at = document.find("\":", at + 1)) {
    ++colons;
  }
  Check(colons == 9, "the key document carries NO field beyond those nine, "
                     "which DisallowUnknownFields would refuse");

  Check(Contains(document, "\"version\":\"winn3-keys/1\""),
        "the key document pins the version this build speaks");
  Check(Contains(document, "\"role\":\"client\""),
        "the Linux host is always the client");

  // The paths are named. The CONTENTS are not, and this host never opens them.
  Check(Contains(document, params.keys.static_path),
        "static_path is named by path");
  Check(Contains(document, params.keys.gateway_static_path),
        "gateway_static_path is named by path");
  Check(Contains(document, params.keys.admission_path),
        "admission_path is named by path");
}

void TestTheKeyDocumentRefusesRatherThanEmitsSomethingTheEngineWouldReject() {
  const LinuxWinn3Params base = SampleParams();
  std::string document;
  std::string error;

  LinuxWinn3Keys gateway = base.keys;
  gateway.role = "gateway";
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(gateway, &document, &error),
        "the gateway role is refused: it is the lab responder's, and a client "
        "that claimed it would be given an admit-all Accept and no gateway "
        "static key to authenticate against");

  LinuxWinn3Keys no_gateway_id = base.keys;
  no_gateway_id.gateway_id = "  ";
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(no_gateway_id, &document,
                                                     &error),
        "an empty gateway_id is refused");
  Check(Contains(error, "replays"), "the gateway_id refusal names the replay");

  LinuxWinn3Keys relative = base.keys;
  relative.static_path = "static.key";
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(relative, &document,
                                                     &error),
        "a relative static_path is refused");

  LinuxWinn3Keys anonymous = base.keys;
  anonymous.gateway_static_path = "";
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(anonymous, &document,
                                                     &error),
        "a client with no gateway static key is refused: there is no "
        "anonymous mode");

  // THE ONE THAT MATTERS MOST. This host always sets allow_own_socket, because
  // -transport stdio cannot carry a descriptor. winn3_create.go refusal 4
  // rejects that unless the key document declares the exclusion, so an empty
  // one must fail HERE rather than at create time on a user's machine.
  LinuxWinn3Keys unexcluded = base.keys;
  unexcluded.outer_socket_exclusion = "   ";
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(unexcluded, &document,
                                                     &error),
        "a key document with no declared exclusion is refused");
  Check(Contains(error, "tunnel it"),
        "the exclusion refusal explains the loop it prevents");
}

void TestTheKeyDocumentDescriptionLeaksNoPath() {
  const LinuxWinn3Params params = SampleParams();
  const std::string described =
      winsvpn::winn3host::DescribeLinuxWinn3Keys(params.keys);
  Check(!Contains(described, params.keys.static_path),
        "the loggable description carries no static key path");
  Check(!Contains(described, params.keys.admission_path),
        "the loggable description carries no admission path");
  // The version token is "winn3-keys/1" and is the only legitimate slash in the
  // line. With it removed, ANY remaining slash is a path that escaped.
  std::string without_version = described;
  const std::string version_token = "winn3-keys/1";
  const auto version_at = without_version.find(version_token);
  if (version_at != std::string::npos) {
    without_version.erase(version_at, version_token.size());
  }
  Check(!Contains(without_version, "/"),
        "the loggable description carries no path at all");
  Check(Contains(described, "exclusion_declared=true"),
        "the loggable description states whether the exclusion was declared");
}

void TestTheKeyDocumentIsWrittenPrivate() {
  char root_template[] = "/tmp/wins-winn3-host-test.XXXXXX";
  const char* root = mkdtemp(root_template);
  Check(root != nullptr, "a temporary directory could be made");
  if (root == nullptr) return;
  Check(setenv("XDG_DATA_HOME", root, 1) == 0, "XDG_DATA_HOME could be set");
  Check(mkdir((std::string(root) + "/wins_vpn").c_str(), 0700) == 0,
        "the app directory could be made");
  Check(mkdir((std::string(root) + "/wins_vpn/winn3").c_str(), 0700) == 0,
        "the winn3 state directory could be made");

  const LinuxWinn3Params params = SampleParams();
  std::string path;
  std::string error;
  Check(winsvpn::winn3host::WriteLinuxWinn3KeysDocument(params.keys, &path,
                                                        &error),
        "the key document is written: " + error);
  struct stat info {};
  Check(stat(path.c_str(), &info) == 0, "the key document exists");
  Check((info.st_mode & 0777) == 0600,
        "the key document is 0600: it names every key file on this device");
  Check(!Contains(path, "/tmp/wins-winn3-host-test.XXXXXX"),
        "the key document went to the per-user directory");
}

// --- the create document ----------------------------------------------------

void TestTheCreateDocumentIsTheV3One() {
  const LinuxWinn3Params params = SampleParams();
  std::string document;
  std::string error;
  Check(winsvpn::winn3host::BuildLinuxWinn3CreateJson(params, &document, &error),
        "a complete create document builds: " + error);

  Check(Contains(document, "\"payload\":\"ip-packet\""),
        "the create document carries the v3 payload class");
  // The one that puts CLEARTEXT on the wire if it is ever wrong.
  Check(!Contains(document, "awg-datagram"),
        "the create document never names the winn/1 relay payload class");
  Check(Contains(document, "\"owns_tun\":false"),
        "owns_tun is false: THIS host owns the device");
  Check(Contains(document, "\"allow_own_socket\":true"),
        "allow_own_socket is true, which -transport stdio forces and the "
        "exclusion makes honest");
  Check(Contains(document,
                 "\"inner_mtu\":" + std::to_string(kFloorInnerMtu1500)),
        "inner_mtu is the plan floor and nothing else");
  Check(Contains(document, "\"path_mtu\":1500"),
        "path_mtu is echoed so the engine computes the same floor");
  Check(Contains(document, "\"carrier_classes\":[\"udp\",\"tcp\",\"tls\"]"),
        "the full migration plan crosses, not the dialled class");
  Check(Contains(document, "\"gateway_endpoint\":\"203.0.113.9:51820\""),
        "the gateway endpoint crosses verbatim");

  // Not the dialled carrier's MTU. If this ever passes, the create seam will
  // refuse the session and the refusal will be right.
  Check(!Contains(document, "\"inner_mtu\":1443"),
        "inner_mtu is never the dialled udp/IPv4 carrier's 1443");
}

void TestTheCreateDocumentRefusesWhatWouldLeak() {
  LinuxWinn3Params params = SampleParams();
  std::string document;
  std::string error;

  params.gateway_endpoint = "gateway.example.org:51820";
  Check(!winsvpn::winn3host::BuildLinuxWinn3CreateJson(params, &document,
                                                       &error),
        "a hostname gateway endpoint is refused");
  Check(Contains(error, "DNS"),
        "the hostname refusal names the DNS lookup it prevents");

  params = SampleParams();
  params.inner_address = "";
  Check(!winsvpn::winn3host::BuildLinuxWinn3CreateJson(params, &document,
                                                       &error),
        "a session with no inner address is refused");

  params = SampleParams();
  params.carrier_classes.clear();
  Check(!winsvpn::winn3host::BuildLinuxWinn3CreateJson(params, &document,
                                                       &error),
        "a session with no migration plan is refused");

  params = SampleParams();
  params.carrier_classes = {"udp", "h3"};
  Check(!winsvpn::winn3host::BuildLinuxWinn3CreateJson(params, &document,
                                                       &error),
        "an unknown class in the plan is refused rather than dropped");
}

void TestTheEndpointSplitter() {
  std::string host;
  std::string port;
  Check(winsvpn::winn3host::SplitLinuxWinn3Endpoint("203.0.113.9:51820", &host,
                                                    &port) &&
            host == "203.0.113.9" && port == "51820",
        "an IPv4 endpoint splits");
  Check(winsvpn::winn3host::SplitLinuxWinn3Endpoint("[2001:db8::1]:51820",
                                                    &host, &port) &&
            host == "2001:db8::1" && port == "51820",
        "a bracketed IPv6 endpoint splits");
  const char* refused[] = {"gateway.example.org:51820", "203.0.113.9",
                           "203.0.113.9:0",            "203.0.113.9:99999",
                           "2001:db8::1:51820",        ":51820",
                           "203.0.113.9:"};
  for (const char* value : refused) {
    Check(!winsvpn::winn3host::SplitLinuxWinn3Endpoint(value, &host, &port),
          std::string("refused as an endpoint: ") + value);
  }
}

// --- the promotion probe collision guards -----------------------------------

// The two targets the pre-promotion echo must never reach: the carrier
// endpoint (its /32 is pinned to the PHYSICAL interface by the
// destination-scoped exclusion, while the bootstrap routes exactly the inner
// next hop into the tun) and this host's own inner_v4 (an echo addressed to
// this device is not a probe). Windows refuses both pairs in
// winn3_supervisor.cpp SendInnerPromotionProbe; this test proves the Linux
// host's guard agrees, as a pure function the development host can run.
void TestTheInnerPromotionProbeRefusesCollisions() {
  winsvpn::winn3host::LinuxWinn3Params params;
  params.gateway_endpoint = "203.0.113.9:51820";
  params.inner_address = "10.64.0.2";
  params.inner_next_hop = "10.64.0.1";

  Check(winsvpn::winn3host::LinuxWinn3InnerPromotionProbeCollisionRefusal(
            params)
            .empty(),
        "no collision: the echo may proceed when the endpoint, the inner next "
        "hop and the host's own assignment are three different addresses");

  // THE ENDPOINT COLLISION. Addressed there, the echo's route is one the OS
  // may resolve either way: physical pin and tunnel route both describe the
  // same /32.
  winsvpn::winn3host::LinuxWinn3Params endpoint_collision = params;
  endpoint_collision.inner_next_hop = "203.0.113.9";
  const std::string endpoint_refusal =
      winsvpn::winn3host::LinuxWinn3InnerPromotionProbeCollisionRefusal(
          endpoint_collision);
  Check(!endpoint_refusal.empty(),
        "the probe refuses an inner next hop equal to the carrier endpoint");
  Check(endpoint_refusal.find("203.0.113.9") != std::string::npos,
        "the endpoint refusal names the colliding address: " + endpoint_refusal);

  // The same collision under a DIFFERENT SPELLING of the same address is
  // still a collision: equality is decided over the numeric address, not the
  // text, so a leading-zero endpoint spelling cannot slip past the guard.
  winsvpn::winn3host::LinuxWinn3Params leading_zero_collision = params;
  leading_zero_collision.gateway_endpoint = "203.000.113.009:51820";
  leading_zero_collision.inner_next_hop = "203.0.113.9";
  Check(!winsvpn::winn3host::LinuxWinn3InnerPromotionProbeCollisionRefusal(
             leading_zero_collision)
             .empty(),
        "the endpoint collision is decided canonically: a leading-zero "
        "spelling of the endpoint address still refuses");

  // THE SELF COLLISION. An echo addressed to this host's own assignment is
  // not a probe; it could never reach the gateway to be reflected.
  winsvpn::winn3host::LinuxWinn3Params self_collision = params;
  self_collision.inner_next_hop = "10.64.0.2";
  const std::string self_refusal =
      winsvpn::winn3host::LinuxWinn3InnerPromotionProbeCollisionRefusal(
          self_collision);
  Check(!self_refusal.empty(),
        "the probe refuses an inner next hop equal to the host's own inner_v4");
  Check(self_refusal.find("10.64.0.2") != std::string::npos,
        "the self refusal names the host's own assignment: " + self_refusal);

  // An IPv6 carrier endpoint cannot equal an IPv4 inner next hop, exactly as
  // the Windows guard's InetPtonA(AF_INET, ...) skips it: a healthy
  // v6-endpoint session must not be refused.
  winsvpn::winn3host::LinuxWinn3Params v6_endpoint = params;
  v6_endpoint.gateway_endpoint = "[2001:db8::1]:51820";
  Check(winsvpn::winn3host::LinuxWinn3InnerPromotionProbeCollisionRefusal(
            v6_endpoint)
            .empty(),
        "an IPv6 endpoint cannot collide with the IPv4 inner next hop, so the "
        "probe is not refused for it");
}

// --- the argv ---------------------------------------------------------------

void TestTheEngineArgv() {
  const std::vector<std::string> argv =
      winsvpn::winn3host::LinuxWinn3EngineArguments("/opt/winn-datapath",
                                                    "/private/winn3-keys.json");
  Check(Join(argv) ==
            "/opt/winn-datapath -transport stdio -winn3 -winn3-keys "
            "/private/winn3-keys.json",
        "the argv is exactly the frame mode's, with the key document by path");

  // The four ways this argv can be wrong, each asserted rather than assumed.
  Check(std::find(argv.begin(), argv.end(), "-winn3") != argv.end(),
        "-winn3 is present: without it the engine runs the winn/1 relay under "
        "a session the gateway negotiated as v3, which is a silent downgrade");
  Check(std::find(argv.begin(), argv.end(), "-winn3-keys") != argv.end(),
        "-winn3-keys is present: the engine refuses -winn3 without it, because "
        "key material must not cross a channel whose payload is peer-supplied");
  Check(std::find(argv.begin(), argv.end(), "-winn3-tun-fd") == argv.end(),
        "-winn3-tun-fd is absent: it belongs to -winn3-profile, and frame mode "
        "refuses it because THIS host owns the device");
  Check(std::find(argv.begin(), argv.end(), "-carrier-profile") == argv.end(),
        "-carrier-profile is absent: it is a winn/1 carrier and the engine "
        "refuses it beside -winn3");
  // No positional argument: flags.NArg() != 0 is fatal in cmd/winn-datapath.
  for (size_t i = 1; i < argv.size(); ++i) {
    if (argv[i].empty() || argv[i][0] == '-') continue;
    Check(argv[i - 1] == "-transport" || argv[i - 1] == "-winn3-keys",
          "every non-flag token is the value of the flag before it: " + argv[i]);
  }
}

// --- the exclusion ----------------------------------------------------------

void TestTheExclusionIsDestinationScopedRatherThanAFwmark() {
  const LinuxWinn3Params params = SampleParams();
  const Commands install =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionCommands(params);
  Check(install.size() == 1, "the exclusion is exactly one command");
  Check(Join(install[0]) ==
            "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "the exclusion is a /32 host route via the physical next hop, NOT an "
        "awg-quick fwmark rule -- there is no awg-quick in a standalone v3 "
        "session and the engine's own socket carries no SO_MARK");

  const Commands remove =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionTeardown(params);
  Check(remove.size() == 1 &&
            Join(remove[0]) ==
                "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "the teardown is the same route with del, so the two cannot describe "
        "different routes");

  // The exclusion beats the promoted default on specificity, which is the whole
  // reason it needs no mark: /32 against the /1 pair.
  Check(Contains(Join(install[0]), "/32"),
        "the exclusion is a /32, which beats the promoted 0.0.0.0/1 pair");

  const std::string described =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);
  Check(Contains(described, "203.0.113.9/32") &&
            Contains(described, "192.168.1.1") && Contains(described, "wlan0"),
        "the description names the same three facts the command renders");
}

void TestTheExclusionIsOnLinkWithoutANextHopOrRefused() {
  // ON-LINK CONTRACT, added 2026-08-21 (app-level live-test lane). A gateway
  // on the host's own subnet has no next hop -- `ip route get <host>` answers
  // `dev <iface>` with no `via` -- and the old rule ("no next hop means no
  // exclusion") refused every such topology. The exclusion an on-link gateway
  // needs is the direct-device form: the /32 pinned to the physical interface
  // with no via, which still beats the promoted 0.0.0.0/1 pair on specificity
  // and still keeps the engine's outer socket off the tunnel.
  LinuxWinn3Params params = SampleParams();
  params.physical_next_hop = "";
  const Commands on_link =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionCommands(params);
  Check(on_link.size() == 1 &&
            Join(on_link[0]) == "ip -4 route add 203.0.113.9/32 dev wlan0",
        "no next hop means an on-link exclusion: the /32 on the physical "
        "interface, direct-device form, no via");
  Check(!Contains(Join(on_link[0]), "via"),
        "and the rendered vector carries no via, because the kernel never "
        "had one to name");

  const std::string described =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);
  Check(!described.empty() && Contains(described, "203.0.113.9/32") &&
            Contains(described, "dev wlan0") &&
            Contains(described, "(on-link)"),
        "no next hop means an on-link DESCRIPTION too: the host still says "
        "what it installed, and says which form it used");
  Check(!Contains(described, " via "),
        "and the description invents no next hop the kernel did not give");

  const Commands on_link_teardown =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionTeardown(params);
  Check(on_link_teardown.size() == 1 &&
            Join(on_link_teardown[0]) ==
                "ip -4 route del 203.0.113.9/32 dev wlan0",
        "the on-link teardown is the identical vector with del, so the "
        "repair-before-add probe of an on-link session stays exact");

  // The refusals below are the other half of the contract and must STILL
  // fire: on-link changes nothing about what cannot be described at all.
  params = SampleParams();
  params.physical_interface = "";
  Check(winsvpn::winn3host::RenderLinuxWinn3ExclusionCommands(params).empty(),
        "no physical interface means no exclusion command");
  Check(winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params).empty(),
        "no physical interface means no exclusion description");

  params = SampleParams();
  params.gateway_endpoint = "not-an-endpoint";
  Check(winsvpn::winn3host::RenderLinuxWinn3ExclusionCommands(params).empty(),
        "an unparseable gateway endpoint means no exclusion command");
  Check(winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params).empty(),
        "an unparseable gateway endpoint means no exclusion description");
}

// --- the bootstrap posture --------------------------------------------------

void TestTheBootstrapPostureIsNarrowAndPutsTheExclusionFirst() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus status;
  Check(ParseWinn3StatusLine(
            StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
            &status),
        "the CreateAck status parses");

  RecordingRunner runner;
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      params, status, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kApplied,
        "the bootstrap posture applies: " + result.error);
  Check(result.posture == Posture::kBootstrap,
        "and the RESULT says which posture it describes, so a value that has "
        "been logged or stored still knows how its hazard fields are read");
  Check(!result.capturing,
        "a bootstrap that applied captures nothing -- structurally, because "
        "two narrowness checks ran before its first command");
  Check(result.exclusion_installed,
        "and it reports that the outer-socket exclusion IS installed: it is on "
        "the physical interface, it does not go when the tun descriptor does, "
        "and the session now owes a teardown");
  Check(result.rollback_attempted == false && result.rollback_failed.empty(),
        "nothing was reversed on a posture that did not fail");
  Check(result.resolver_mechanism ==
            winsvpn::winn3host::LinuxWinn3ResolverMechanism::kUnknown,
        "and NO resolver mechanism is claimed: the bootstrap installs no "
        "resolver, so reporting one would report a detection it never ran");

  Check(plan.posture == Posture::kBootstrap, "the plan is the bootstrap one");
  Check(!plan.default_route, "the bootstrap posture takes no default route");
  Check(!plan.ipv6, "the bootstrap posture installs no IPv6");
  Check(plan.dns_servers.empty(), "the bootstrap posture installs no resolver");
  Check(plan.included_routes.size() == 1 &&
            plan.included_routes[0] == "10.64.0.1/32",
        "the bootstrap posture installs AT MOST ONE route, the inner next hop");
  Check(plan.prefix_v4 == 32, "the inner address is a /32");
  Check(plan.mtu == kFloorInnerMtu1500,
        "the MTU is the engine's own inner MTU, not a number this host chose");

  // ORDER IS THE CONTRACT. The exclusion is installed from the FIRST posture,
  // before the link exists, because installing it later means installing it
  // after traffic could already have been captured.
  const int exclusion_at = IndexOfCommand(
      runner.ran, "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  const int address_at = IndexOfCommand(
      runner.ran, "ip -4 address add 10.64.0.2/32 dev winsvpn3");
  Check(exclusion_at == 0,
        "the exclusion is the FIRST command that installs anything");
  Check(address_at > exclusion_at,
        "the inner address is installed after the exclusion");

  // The repair runs before it and installs nothing, so it does not disturb the
  // ordering above. On this host it finds nothing, which is the ordinary case.
  Check(Join(runner.attempted.front()) ==
            "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "and the very first thing ATTEMPTED is the exclusion's own del: a "
        "route stranded by a previous process is repaired before the add that "
        "would otherwise meet it with EEXIST");
  Check(!result.stale_exclusion_repaired,
        "on a host with nothing stranded the repair finds nothing, and that is "
        "not an error -- it is every ordinary first run");
  Check(!Contains(DescribeLinuxWinn3PostureResult(result), "STRANDED"),
        "so the one-line description says nothing about a stranded route");

  // Nothing that widens anything is in the rendered set.
  for (const std::vector<std::string>& argv : runner.ran) {
    const std::string joined = Join(argv);
    Check(!Contains(joined, "0.0.0.0/1") && !Contains(joined, "128.0.0.0/1"),
          "no bootstrap command installs the default-route pair: " + joined);
    Check(!Contains(joined, "resolvectl"),
          "no bootstrap command installs a resolver: " + joined);
    Check(!Contains(joined, "-6"),
          "no bootstrap command touches IPv6: " + joined);
  }
  Check(HasCommand(runner.ran, "ip link set dev winsvpn3 mtu 1359 up"),
        "the link is brought up at the plan floor");
}

void TestTheBootstrapPostureRefusesRatherThanWidens() {
  LinuxWinn3Params params = SampleParams();
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);

  // An ON-LINK session -- gateway on the host's own subnet, so no next hop --
  // is NOT a refusal. It applies with the direct-device exclusion as its
  // FIRST command, exactly as a routed session does, because the on-link /32
  // on the physical interface beats the promoted default pair all the same.
  params.physical_next_hop = "";
  RecordingRunner on_link_runner;
  PosturePlan on_link_plan;
  const auto on_link = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      params, status, on_link_runner.Runner(), &on_link_plan);
  Check(on_link.outcome == Outcome::kApplied,
        std::string("an on-link bootstrap applies: empty next hop is the "
                    "same-subnet case, not a missing input; got ") +
            OutcomeName(on_link.outcome) + ": " + on_link.error);
  Check(on_link.exclusion_installed && !on_link_runner.ran.empty() &&
            Join(on_link_runner.ran.front()) ==
                "ip -4 route add 203.0.113.9/32 dev wlan0",
        "and its exclusion is the direct-device /32, still the FIRST command "
        "so the outer socket is off the tunnel before traffic can be "
        "captured");
  Check(Contains(on_link_plan.outer_socket_exclusion, "(on-link)"),
        "the plan carries the on-link description, so the status document "
        "says which form this host installed");

  // No physical interface -> refusal, and NOT a posture without an exclusion.
  params = SampleParams();
  params.physical_interface = "";
  RecordingRunner runner;
  PosturePlan plan;
  const auto no_exclusion =
      winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
          params, status, runner.Runner(), &plan);
  Check(no_exclusion.outcome == Outcome::kNotAttempted,
        "a session that cannot describe its exclusion is refused BEFORE a "
        "command runs, which is the outcome that means a retry is clean");
  Check(Contains(no_exclusion.error, "awg-quick"),
        "the refusal says there is no awg-quick fwmark to fall back on");
  Check(runner.ran.empty(), "a refused bootstrap runs NO command");
  Check(!no_exclusion.exclusion_installed && no_exclusion.applied.empty(),
        "and it leaves nothing behind to outlive the process");

  // No status document -> no inner MTU -> refusal.
  params = SampleParams();
  RecordingRunner second;
  const EngineStatus unparsed;
  const auto no_status = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      params, unparsed, second.Runner(), &plan);
  Check(no_status.outcome == Outcome::kNotAttempted,
        "a bootstrap posture without an engine status is refused: the inner "
        "MTU is unknown and a posture with no MTU is not a posture");
  Check(second.ran.empty(), "that refusal runs NO command either");

  // A failing FIRST command leaves nothing installed, so there is nothing to
  // reverse -- and that is kRolledBack rather than kNotAttempted, because a
  // command DID run. The two are not interchangeable: kNotAttempted promises
  // the executor was never reached.
  //
  // This runner is ALSO a host whose physical interface is not there: nothing
  // answers the `ip link show dev wlan0` probe. That is the reason the exclusion
  // was refused here, and the reason this stays kRolledBack -- correcting the
  // interface makes the retry clean, so the retryable outcome is the honest one.
  RecordingRunner third;
  third.fail_on = "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0";
  const auto first_failed =
      winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
          SampleParams(), status, third.Runner(), &plan);
  Check(first_failed.outcome == Outcome::kRolledBack,
        std::string("a failed exclusion install fails the whole bootstrap with "
                    "nothing left to reverse; got ") +
            OutcomeName(first_failed.outcome));
  Check(third.ran.empty(),
        "and nothing after the failed command is attempted");
  Check(!first_failed.exclusion_installed,
        "the exclusion never went in, so nothing outlives the process");
  Check(Contains(first_failed.error, "wlan0") &&
            Contains(first_failed.error, "does not exist"),
        "and a missing physical interface is NAMED as the cause rather than "
        "reported as a route that is in the way -- a message that blamed a "
        "route for a mistyped interface would claim more than its evidence");
  Check(first_failed.outcome != Outcome::kExclusionBlocked,
        "so a bad session parameter is NOT the blocked-exclusion outcome: that "
        "one promises a retry cannot help, and here a corrected one can");
}

// ---------------------------------------------------------------------------
// REPAIR FIRST, THEN TAKE. Item 3 of the 2026-08-10 return-contract handoff.
//
// The rollback above reverses what THIS call installed. A session SIGKILLed
// after the exclusion goes in never reaches its own rollback at all, and a
// rollback that itself fails returns kPartiallyApplied and leaves the route
// where it is. Either way the next bootstrap's FIRST command is that identical
// `ip route add`, which `ip` answers EEXIST, exit 2 -- so one hard kill refused
// every later session on the machine, permanently.
// ---------------------------------------------------------------------------
void TestAStrandedExclusionIsRepairedBeforeTheNextBootstrap() {
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);

  RecordingRunner runner;
  // A machine a previous session was killed on: OUR exclusion, exactly as we
  // would write it, already in the kernel.
  runner.stale_exclusion_in_kernel = true;
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      SampleParams(), status, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kApplied,
        std::string("a bootstrap on a machine carrying a STRANDED exclusion "
                    "still applies -- which before the repair it could not, "
                    "ever again; got ") +
            OutcomeName(result.outcome) + ": " + result.error);
  Check(result.stale_exclusion_repaired,
        "and the result SAYS a previous process's exclusion was found and "
        "removed: it is the only in-band evidence that the last session was "
        "killed before its teardown ran");
  Check(Join(runner.ran.at(0)) ==
            "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "the repair is the first command to succeed");
  Check(Join(runner.ran.at(1)) ==
            "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "and the exclusion's add follows it immediately, so the destination is "
        "free by the time the add runs");

  // THE REPAIR IS THE TEARDOWN VECTOR, NOT A DELETION OF ITS OWN. A `del` that
  // dropped `via` or `dev` would match ANY route to that destination and would
  // remove one this product never wrote.
  const Commands teardown =
      winsvpn::winn3host::RenderLinuxWinn3ExclusionTeardown(SampleParams());
  Check(teardown.size() == 1 && runner.ran.at(0) == teardown.at(0),
        "and it is byte-for-byte RenderLinuxWinn3ExclusionTeardown's vector -- "
        "one token swapped from the add -- so the repair cannot describe a "
        "different route from the one it is repairing");
  for (const std::vector<std::string>& argv : runner.attempted) {
    const std::string joined = Join(argv);
    if (!RecordingRunner::IsRouteDel(joined)) continue;
    Check(Contains(joined, " via ") && Contains(joined, " dev "),
          "every route deletion this host attempts carries BOTH via and dev, "
          "so the kernel matches on them and a route to the same destination "
          "that somebody else wrote cannot be caught by it: " + joined);
  }
  Check(Contains(DescribeLinuxWinn3PostureResult(result), "STRANDED"),
        "the one-line description says so even on a healthy run: unlike the "
        "exclusion warning this is not about THIS session, and a host that "
        "reports it every start is a host something is killing");
  Check(result.exclusion_installed,
        "and the exclusion is installed at the end, by design, as on any "
        "healthy bootstrap");
}

// The other half of the rule, and the half that must not be a silent delete.
//
// A route to our gateway via a next hop that is NOT ours is the most broken
// state available -- it makes the gateway unreachable whether or not we start.
// It is also the one state we cannot prove is ours: it might be a previous
// session of ours from another network, or a policy route the user needs. We
// keep no copy to put it back from, so it is refused BY NAME and never removed.
void TestARouteWeDidNotWriteIsRefusedRatherThanDeleted() {
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);

  RecordingRunner runner;
  // Nothing of OURS is stranded -- the exact-selector del finds nothing, which
  // is precisely what the kernel answers when the route in the way has a
  // different next hop. The add is then refused, as `ip` refuses a taken
  // destination with EEXIST.
  runner.stale_exclusion_in_kernel = false;
  runner.fail_all.push_back(
      "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  // ...on a host whose physical interface really is there, so the refusal
  // cannot be blamed on a session parameter.
  GivePhysicalInterface(&runner, "wlan0");
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      SampleParams(), status, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kExclusionBlocked,
        std::string("a destination routed by an entry we did not write is its "
                    "OWN outcome; got ") +
            OutcomeName(result.outcome));
  Check(result.outcome != Outcome::kNotAttempted &&
            result.outcome != Outcome::kRolledBack,
        "and it is neither of the two that promise a clean retry: a retry here "
        "fails identically until somebody removes that route, and reporting "
        "either of those would send a caller into a loop that cannot succeed");
  Check(!result.stale_exclusion_repaired,
        "nothing of ours was found, which is the fact the rule turns on: what "
        "is in the way is not this product's leftover");

  // NOTHING WAS DELETED. Not by the repair, which the kernel would not match,
  // and not by any second attempt at it.
  Check(runner.ran.empty(),
        "no command succeeded at all, so nothing was installed AND nothing was "
        "removed");
  int deletions = 0;
  for (const std::vector<std::string>& argv : runner.attempted) {
    const std::string joined = Join(argv);
    if (!RecordingRunner::IsRouteDel(joined)) continue;
    ++deletions;
    Check(joined == "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0",
          "the only deletion ever ATTEMPTED is our own exclusion's exact "
          "vector: no fallback to a destination-only `del` that would remove "
          "the user's route; " + joined);
  }
  Check(deletions == 1,
        "and it is attempted exactly once -- there is no retry that widens the "
        "selector when the narrow one finds nothing");

  Check(!result.exclusion_installed,
        "the blocking route is NOT counted as our residue: a teardown that "
        "believed it was ours would go and delete it later");
  Check(result.applied.empty() && !result.rollback_attempted,
        "nothing was applied and nothing was reversed");
  Check(Contains(result.error, "203.0.113.9") &&
            Contains(result.error, "DIFFERENT"),
        "the refusal NAMES the mismatch -- the destination, and that what is "
        "there has a different next hop or device -- rather than leaving a "
        "silent unreachable state: " + result.error);
  Check(Contains(result.error, "NOT REMOVED") &&
            Contains(result.error, "ip -4 route show"),
        "it says the route was left alone and gives the read-only command that "
        "shows what it is");
  Check(Contains(DescribeLinuxWinn3PostureResult(result),
                 "THIS HOST DID NOT INSTALL"),
        "and the one-line description leads with it");
}

// ---------------------------------------------------------------------------
// THE BOOTSTRAP'S OWN FAIL-OPEN SHAPE, MEASURED 2026-08-10
//
// The exclusion goes in, the next command fails, and the kernel keeps a host
// route on the PHYSICAL interface that this process's death does not remove.
// Nothing about it captures traffic -- that is why it was left alone when the
// promoted applier was fixed -- but it is verbatim the first command of the
// next bootstrap, and `ip` answers a repeated identical route with EEXIST. So
// one half-applied bootstrap refuses every later session on the machine.
// ---------------------------------------------------------------------------
void TestAPartialBootstrapReversesTheExclusion() {
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);

  RecordingRunner runner;
  // The exclusion succeeds; the command straight after it does not.
  runner.fail_all.push_back("ip -4 address add 10.64.0.2/32 dev winsvpn3");
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      SampleParams(), status, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kRolledBack,
        std::string("a bootstrap that got part way and was fully reversed is "
                    "ROLLED BACK, not a bare false; got ") +
            OutcomeName(result.outcome));
  Check(result.applied.size() == 1 &&
            Join(result.applied[0]) ==
                "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev wlan0",
        "the result carries HOW FAR IT GOT, which the boolean could not");
  Check(Join(result.failed) == "ip -4 address add 10.64.0.2/32 dev winsvpn3",
        "and which command stopped it");
  Check(result.rollback_attempted, "the reversal was attempted");
  Check(result.rollback_failed.empty(), "and every reversal succeeded");
  Check(HasCommand(runner.ran,
                   "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0"),
        "THE EXCLUSION WAS REMOVED -- one token swapped from the add, so the "
        "del cannot describe a different route from the thing it undoes");
  Check(!result.exclusion_installed,
        "so nothing this attempt installed outlives the process");
  Check(Contains(result.error, "retry starts clean"),
        "and the caller is told the difference that matters: this failure is "
        "retryable, the other one is not");
}

void TestAFailedExclusionReversalIsItsOwnOutcome() {
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);

  RecordingRunner runner;
  runner.fail_all.push_back("ip -4 address add 10.64.0.2/32 dev winsvpn3");
  // AND the reversal of the exclusion fails. This is the third state the
  // promoted lane enumerated rather than collapsed, and it is the state that
  // wedges every later session on this machine.
  runner.fail_all.push_back(
      "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      SampleParams(), status, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kPartiallyApplied,
        std::string("a reversal that fails is PARTIALLY APPLIED -- a distinct "
                    "value, because collapsing it into rolled-back hides the "
                    "one state that outlives the process; got ") +
            OutcomeName(result.outcome));
  Check(result.rollback_failed.size() == 1, "the failed reversal is counted");
  Check(result.exclusion_installed,
        "AND the result says the exclusion is still in the kernel. This is the "
        "field a bootstrap caller reads where a promotion caller reads "
        "`capturing`");
  Check(!result.capturing,
        "it is still not capturing, and the honest report of a non-capturing "
        "residue is not the same as a report of no residue");
  Check(Contains(result.error, "EEXIST"),
        "and the error names the consequence -- the next bootstrap's first "
        "command fails -- rather than only the fact");
  Check(Contains(DescribeLinuxWinn3PostureResult(result),
                 "THE OUTER-SOCKET EXCLUSION IS STILL INSTALLED"),
        "the one-line description leads with it, the way the promoted one "
        "leads with capturing");
  Check(Contains(DescribeLinuxWinn3PostureResult(result), "bootstrap posture"),
        "and it names the posture rather than calling every result promoted");
}

// A bootstrap that APPLIED also leaves the exclusion behind -- by design. The
// field must say so, because a process killed here strands that route just as
// surely, and a flag that only ever fires on failure would let the caller
// believe a healthy session owes nothing.
void TestAHealthyBootstrapStillReportsTheExclusion() {
  EngineStatus status;
  ParseWinn3StatusLine(
      StatusLine(false, "handshaking", 0, 0, kFloorInnerMtu1500, false),
      &status);
  RecordingRunner runner;
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      SampleParams(), status, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kApplied, "the posture applied");
  Check(result.exclusion_installed,
        "and the exclusion is reported installed on a HEALTHY bootstrap too");
  Check(!Contains(DescribeLinuxWinn3PostureResult(result),
                  "STILL INSTALLED"),
        "but the one-line description does NOT shout about it here: a warning "
        "printed on every healthy run is a warning nobody reads on the run "
        "that matters");
}

// The shared posture header is now COMPILED INTO THIS RUNNER through
// linux_winn3_host.cc, so the guards this host leans on are this host's
// business too. They are asserted here as well as in winn3_posture_test.cc,
// deliberately: the two files are separate binaries, and a change to the header
// that only one of them catches is a change the other's reviewer will not see.
void TestTheGuardsThisHostLeansOn() {
  std::string error;

  PosturePlan wide;
  wide.posture = Posture::kBootstrap;
  wide.inner_v4 = "10.64.0.2";
  wide.prefix_v4 = 32;
  wide.mtu = kFloorInnerMtu1500;
  wide.outer_socket_exclusion = "host route";
  wide.default_route = true;
  Check(!winsvpn::winn3::VerifyBootstrapIsNarrow(wide, &error),
        "a bootstrap plan carrying the default route is refused by the "
        "narrowness re-check");

  PosturePlan with_dns = wide;
  with_dns.default_route = false;
  with_dns.dns_servers = {"10.64.0.1"};
  Check(!winsvpn::winn3::VerifyBootstrapIsNarrow(with_dns, &error),
        "a bootstrap plan carrying a resolver is refused");

  PosturePlan with_v6 = wide;
  with_v6.default_route = false;
  with_v6.ipv6 = true;
  Check(!winsvpn::winn3::VerifyBootstrapIsNarrow(with_v6, &error),
        "a bootstrap plan carrying IPv6 is refused");

  PosturePlan two_routes = wide;
  two_routes.default_route = false;
  two_routes.included_routes = {"10.64.0.1/32", "10.0.0.0/8"};
  Check(!winsvpn::winn3::VerifyBootstrapIsNarrow(two_routes, &error),
        "a bootstrap plan carrying more than one route is refused");

  PosturePlan wide_prefix = wide;
  wide_prefix.default_route = false;
  wide_prefix.prefix_v4 = 24;
  Check(!winsvpn::winn3::VerifyBootstrapIsNarrow(wide_prefix, &error),
        "a bootstrap plan whose inner prefix is wider than /32 is refused: it "
        "lets the host originate from an address the tunnel drops");

  PosturePlan narrow = wide;
  narrow.default_route = false;
  Check(winsvpn::winn3::VerifyBootstrapIsNarrow(narrow, &error),
        "and the narrow plan itself passes: " + error);
}

// The last thing between the policy and the kernel is the argument vector, and
// a renderer that widened on its own would sail past every plan-level check in
// the system. So the rendered set is checked on its own terms.
void TestTheRenderedBootstrapIsCheckedToo() {
  std::string error;
  using Argv = std::vector<std::string>;
  const Commands narrow = {
      Argv{"ip", "-4", "address", "add", "10.64.0.2/32", "dev", "winsvpn3"},
      Argv{"ip", "link", "set", "dev", "winsvpn3", "mtu", "1359", "up"},
      Argv{"ip", "route", "add", "10.64.0.1/32", "dev", "winsvpn3"}};
  Check(winsvpn::winn3host::VerifyLinuxWinn3BootstrapCommandsAreNarrow(narrow,
                                                                       &error),
        "the narrow rendering passes: " + error);

  Commands widened = narrow;
  widened.push_back(Argv{"ip", "route", "add", "0.0.0.0/1", "dev", "winsvpn3"});
  Check(!winsvpn::winn3host::VerifyLinuxWinn3BootstrapCommandsAreNarrow(
            widened, &error),
        "a rendered default-route half is refused even though the PLAN said "
        "it took none");

  Commands literal_default = narrow;
  literal_default.push_back(
      Argv{"ip", "route", "add", "default", "dev", "winsvpn3"});
  Check(!winsvpn::winn3host::VerifyLinuxWinn3BootstrapCommandsAreNarrow(
            literal_default, &error),
        "a literal default route is refused too");

  Commands v6 = narrow;
  v6.push_back(Argv{"ip", "-6", "address", "add", "fd00::2/128", "dev",
                    "winsvpn3"});
  Check(!winsvpn::winn3host::VerifyLinuxWinn3BootstrapCommandsAreNarrow(
            v6, &error),
        "a rendered IPv6 command is refused");

  Commands resolver = narrow;
  resolver.push_back(Argv{"resolvectl", "dns", "winsvpn3", "10.64.0.1"});
  Check(!winsvpn::winn3host::VerifyLinuxWinn3BootstrapCommandsAreNarrow(
            resolver, &error),
        "a rendered resolver is refused");
}

// --- promotion --------------------------------------------------------------

void TestPromotionWidensOnlyOnTheEnginesProof() {
  const LinuxWinn3Params params = SampleParams();
  PosturePlan plan;
  std::string error;

  // Not ready -> refusal, no matter how healthy everything else looks.
  EngineStatus carrying_but_empty;
  ParseWinn3StatusLine(
      StatusLine(false, "carrying", 0, 4096, kFloorInnerMtu1500, false),
      &carrying_but_empty);
  RecordingRunner unproven;
  GiveSystemdResolved(&unproven);
  const auto unproven_result =
      winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
          params, carrying_but_empty, unproven.Runner(), &plan);
  Check(unproven_result.outcome == Outcome::kNotAttempted,
        "a carrying gate with 4096 arrivals and zero DELIVERIES does not "
        "promote: rx_offered is not rx_packets");
  Check(unproven.ran.empty(), "a refused promotion runs no command");
  Check(!unproven_result.capturing,
        "and it reports that nothing is capturing, which is the fact a caller "
        "acts on");

  // Ready -> the widenings, in one call.
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);
  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kApplied,
        "a proven datapath promotes: " + result.error);
  Check(result.capturing,
        "and the result says the kernel is now capturing, which is the whole "
        "point of the widening");
  Check(result.resolver_mechanism == Mechanism::kSystemdResolved,
        "a host whose `resolvectl --no-pager status` answers is driven through "
        "systemd-resolved");
  Check(plan.posture == Posture::kPromoted, "the plan is the promoted one");
  Check(plan.default_route, "the promoted posture takes the default route");
  Check(HasCommand(runner.ran, "ip route add 0.0.0.0/1 dev winsvpn3"),
        "the promoted posture installs 0.0.0.0/1");
  Check(HasCommand(runner.ran, "ip route add 128.0.0.0/1 dev winsvpn3"),
        "the promoted posture installs 128.0.0.0/1 -- the pair beats an "
        "existing default on specificity WITHOUT deleting it, which is what "
        "makes a partial teardown safe");
  Check(HasCommand(runner.ran, "resolvectl dns winsvpn3 10.64.0.1"),
        "the promoted posture installs the resolvers");
  Check(HasCommand(runner.ran, "resolvectl domain winsvpn3 ~."),
        "and makes them authoritative for ALL names, not only the link's own "
        "search domain");

  // The exclusion is NOT re-installed: it is already in place and a second add
  // would fail with EEXIST, turning a correct promotion into an error.
  Check(IndexOfCommand(runner.ran,
                       "ip -4 route add 203.0.113.9/32 via 192.168.1.1 dev "
                       "wlan0") < 0,
        "promotion does not re-install the exclusion");

  // The MTU and the address are the bootstrap's, unchanged: the promoted plan
  // is the narrow one PLUS the widenings, never a second configuration.
  Check(plan.mtu == kFloorInnerMtu1500 && plan.inner_v4 == "10.64.0.2" &&
            plan.prefix_v4 == 32,
        "the promoted plan keeps the bootstrap's address, prefix and MTU");
}

// The case a bare "has anything been delivered?" check gets wrong.
//
// A rekey is a normal, recurring event in a long session, and while it is in
// flight the gate is NOT carrying even though thousands of inner packets have
// already been delivered. So `rx_packets > 0` alone is not the predicate and
// neither is "the gate was carrying once": promotion_ready is the conjunction,
// evaluated NOW, and this is the input that tells the two apart.
void TestPromotionRefusesMidRekeyEvenWithDeliveries() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus rekeying;
  Check(ParseWinn3StatusLine(
            StatusLine(false, "rekeying", 4096, 4096, kFloorInnerMtu1500, false),
            &rekeying),
        "a mid-rekey status parses");
  Check(rekeying.rx_packets == 4096 && !rekeying.promotion_ready,
        "a mid-rekey document reports deliveries AND is not promotion-ready");

  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  PosturePlan plan;
  Check(winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
            params, rekeying, runner.Runner(), &plan)
                .outcome == Outcome::kNotAttempted,
        "a mid-rekey session does not promote, even with 4096 inner packets "
        "already delivered");
  Check(runner.ran.empty(), "and nothing is installed");

  std::string reason;
  Check(DecideLinuxWinn3Promotion(
            true, StatusLine(false, "rekeying", 4096, 4096, 1359, false),
            nullptr, &reason) == LinuxWinn3Promotion::kNotYet,
        "and the gate holds rather than promotes or refuses");
}

void TestPromotionRefusesResolversItCannotJustify() {
  LinuxWinn3Params params = SampleParams();
  params.dns_servers_are_inner = false;
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);
  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kNotAttempted,
        "resolvers the host has not declared inner are refused");
  Check(Contains(result.error, "censored path"),
        "the refusal names what an outside resolver does when the tunnel drops");
  Check(runner.ran.empty(), "and nothing is installed");
}

void TestPromotionRefusesIPv6ThePlanCannotCarry() {
  LinuxWinn3Params params = SampleParams();
  params.inner_address = "fd00::2";
  params.inner_next_hop = "fd00::1";
  params.keys.outer_socket_exclusion =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);
  EngineStatus proven_v4_only;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false),
      &proven_v4_only);
  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven_v4_only, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kNotAttempted,
        "inner IPv6 is refused when the plan floor cannot carry it");
  Check(Contains(result.error, "black-hole"),
        "the refusal names the black hole it prevents");
  Check(runner.ran.empty(), "and nothing is installed");
}

// --- the gate ---------------------------------------------------------------

void TestTheGateIsTriState() {
  EngineStatus parsed;
  std::string reason;

  Check(DecideLinuxWinn3Promotion(false, std::string(), &parsed, &reason) ==
            LinuxWinn3Promotion::kRefuse,
        "a dead engine is refused immediately, not polled");
  Check(Contains(reason, "nothing to wait for"),
        "and the refusal says there is nothing to wait for");

  Check(DecideLinuxWinn3Promotion(true, std::string(), &parsed, &reason) ==
            LinuxWinn3Promotion::kNotYet,
        "no status document yet is kNotYet");

  Check(DecideLinuxWinn3Promotion(true, "{\"event\":\"posture\"}", &parsed,
                                  &reason) == LinuxWinn3Promotion::kNotYet,
        "a document with no promotion_ready is kNotYet, and is NAMED as a "
        "possible version mismatch rather than silently read as false");
  Check(Contains(reason, "drifted") || Contains(reason, "older"),
        "and the wording says a schema mismatch is possible");

  Check(DecideLinuxWinn3Promotion(
            true, StatusLine(false, "handshaking", 0, 0, 1359, false), &parsed,
            &reason) == LinuxWinn3Promotion::kNotYet,
        "a handshaking gate is kNotYet");
  Check(Contains(reason, "handshaking"),
        "and the wording names WHICH half is missing -- a gate that never "
        "opened is a handshake problem");

  Check(DecideLinuxWinn3Promotion(
            true, StatusLine(false, "carrying", 0, 900, 1359, false), &parsed,
            &reason) == LinuxWinn3Promotion::kNotYet,
        "a carrying gate with no delivery is kNotYet");
  Check(Contains(reason, "return path"),
        "and the wording names the other half -- an open gate with no "
        "delivered packet is a return-path problem");

  Check(DecideLinuxWinn3Promotion(
            true, StatusLine(true, "carrying", 1, 1, 1359, false), &parsed,
            &reason) == LinuxWinn3Promotion::kPromote,
        "carrying plus one delivered inner packet promotes");
  Check(reason.empty(), "and says nothing, because nothing is missing");
  Check(parsed.rx_packets == 1 && parsed.inner_mtu == 1359,
        "the parsed document reaches the caller");

  // The document that disagrees with itself.
  Check(DecideLinuxWinn3Promotion(
            true, StatusLine(true, "carrying", 0, 5, 1359, false), &parsed,
            &reason) == LinuxWinn3Promotion::kRefuse,
        "promotion_ready true with zero delivered packets is REFUSED, not "
        "believed: trusting the field over the evidence for it is how a host "
        "promotes on a bug");

  Check(DecideLinuxWinn3Promotion(
            true,
            StatusLine(false, "closed", 0, 0, 1359, false, "carrier is dead"),
            &parsed, &reason) == LinuxWinn3Promotion::kRefuse,
        "an engine-reported refusal is final, not polled");
  Check(Contains(reason, "carrier is dead"),
        "and the engine's own reason reaches the operator");
}

// THE OTHER HALF OF THE SAME BELT AND BRACES, ADDED 2026-08-12.
//
// TestTheGateIsTriState above covers ready-with-zero-deliveries. It did not
// cover ready-beside-a-gate-that-may-not-carry, and nor did the code: the
// gate comparison lives in the wording block BELOW the `promotion_ready`
// branch, where it names which half a held session is waiting on, and that
// block is unreachable once the field says true. So a status document reading
// ready=true, a non-carrying gate and nonzero deliveries returned kPromote and
// the comparison never ran.
//
// `promotion_ready` is a conjunction. Re-deriving one half of it and not the
// other is the defect, and the fix is the missing half placed beside its twin.
void TestAReadyClaimBesideAGateThatMayNotCarryIsRefused() {
  EngineStatus parsed;
  std::string reason;

  // Every non-carrying name winn3/tun.State.String() emits, plus the sentinel
  // it returns for a value it does not recognise. Deliveries are nonzero
  // throughout, so the rx_packets half cannot be what refuses any of these.
  const char* not_carrying[] = {"closed",   "handshaking", "epoch0",
                                "rekeying", "down",        "invalid"};
  for (const char* gate : not_carrying) {
    Check(DecideLinuxWinn3Promotion(
              true, StatusLine(true, gate, 6, 6, kFloorInnerMtu1500, false),
              &parsed, &reason) == LinuxWinn3Promotion::kRefuse,
          std::string("promotion_ready beside a '") + gate +
              "' gate is REFUSED, not believed: a ready claim on a gate that "
              "may not carry disagrees with itself exactly as a ready claim "
              "with zero deliveries does");
    Check(Contains(reason, gate),
          std::string("and the refusal names the gate state it read: ") +
              reason);
  }

  // The half that needs no attacker: gate_state is OPTIONAL to the parser, so
  // an engine that speaks promotion_ready without publishing a gate state
  // parses to an empty one, and empty is not the carrying name.
  Check(DecideLinuxWinn3Promotion(
            true,
            "{\"event\":\"posture\",\"posture\":\"promoted\","
            "\"promotion_ready\":true,\"rx_packets\":9,\"rx_offered\":9,"
            "\"inner_mtu\":1359,\"message_size\":1500,\"inner_ipv6\":false}",
            &parsed, &reason) == LinuxWinn3Promotion::kRefuse,
        "a ready document that never names a gate state does not promote");

  // The positive control. The tightening must refuse the contradiction and
  // must NOT refuse the document the engine really writes.
  Check(DecideLinuxWinn3Promotion(
            true,
            StatusLine(true, "carrying", 3, 3, kFloorInnerMtu1500, false),
            &parsed, &reason) == LinuxWinn3Promotion::kPromote,
        "and the honest document still promotes, unchanged");
  Check(reason.empty(), "and still says nothing, because nothing is missing");
}

void TestTheGateSaysNothingSecret() {
  const std::string endpoint = "203.0.113.9:51820";
  const char* documents[] = {
      "",
      "{\"event\":\"posture\"}",
      "not json",
  };
  for (const char* document : documents) {
    std::string reason;
    DecideLinuxWinn3Promotion(true, document, nullptr, &reason);
    Check(!Contains(reason, endpoint),
          "the gate's reason never carries the gateway endpoint");
    Check(!Contains(reason, document) || std::string(document).empty(),
          "the gate's reason never quotes the status document back");
  }
}

// THE LOAD-BEARING ONE.
//
// The winn/1 gate on Linux runs after awg-quick has already claimed the host's
// routing, so it answers ONE question -- keep or tear down -- and it answers it
// from a single boolean the engine publishes. Replayed over v3 status documents
// that shape widens where the v3 shape refuses, and the gap is exactly the
// difference between "the session says DATA may flow" and "an inner packet was
// validated and reached the host device".
void TestTheV1ShapeWouldHaveWidenedWhereV3Refuses() {
  // The v1-shaped decision, in the terms a v3 document offers it: the gate is
  // open, so the transport has converged, so keep the routing awg-quick
  // already installed. It never asks whether anything was DELIVERED.
  const auto v1_shape_keeps_routing = [](const std::string& document) {
    EngineStatus status;
    if (!ParseWinn3StatusLine(document, &status)) return false;
    return status.gate_state == winsvpn::winn3::kCarryingGate;
  };

  struct Case {
    const char* what;
    std::string document;
  };
  const Case cases[] = {
      {"the gate opened and nothing has come back",
       StatusLine(false, "carrying", 0, 0, 1359, false)},
      {"payloads are arriving and none has been validated",
       StatusLine(false, "carrying", 0, 8192, 1359, false)},
      {"a rekey is in flight",
       StatusLine(false, "rekeying", 0, 12, 1359, false)},
  };

  for (const Case& c : cases) {
    std::string reason;
    const LinuxWinn3Promotion v3 =
        DecideLinuxWinn3Promotion(true, c.document, nullptr, &reason);
    const bool v1 = v1_shape_keeps_routing(c.document);
    Check(v3 != LinuxWinn3Promotion::kPromote,
          std::string("v3 does not widen when ") + c.what);
    if (v1) {
      // Documented, not asserted away: this is the case the two shapes answer
      // differently, and on Linux v1 the answer costs the user their traffic
      // for as long as the session lasts, because awg-quick already moved the
      // default route.
      Check(v3 == LinuxWinn3Promotion::kNotYet,
            std::string("v3 holds the bootstrap posture where the v1 shape "
                        "would have kept a full tunnel: ") +
                c.what);
    }
  }

  // The one case both shapes agree on, which is what makes the disagreement
  // above meaningful rather than a gate that never promotes.
  const std::string proven = StatusLine(true, "carrying", 3, 3, 1359, false);
  Check(v1_shape_keeps_routing(proven), "the v1 shape keeps a proven tunnel");
  Check(DecideLinuxWinn3Promotion(true, proven, nullptr, nullptr) ==
            LinuxWinn3Promotion::kPromote,
        "and v3 promotes it too");
}

// --- teardown ---------------------------------------------------------------

// Flattens the argv out of the command records, so the ordering checks below
// stay written in the terms they were written in.
Commands ArgvOf(
    const std::vector<winsvpn::winn3host::LinuxWinn3Command>& commands) {
  Commands out;
  for (const winsvpn::winn3host::LinuxWinn3Command& command : commands) {
    out.push_back(command.argv);
  }
  return out;
}

void TestTeardownRemovesTheExclusionLast() {
  const LinuxWinn3Params params = SampleParams();
  const Commands commands = ArgvOf(
      winsvpn::winn3host::RenderLinuxWinn3TeardownCommands(
          params, Mechanism::kSystemdResolved));
  const int exclusion_at = IndexOfCommand(
      commands, "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  const int link_at = IndexOfCommand(commands, "ip link delete dev winsvpn3");
  Check(exclusion_at >= 0, "teardown removes the exclusion");
  Check(link_at >= 0, "teardown removes the link");
  Check(exclusion_at == static_cast<int>(commands.size()) - 1,
        "the exclusion is removed LAST: while it stands the gateway is merely "
        "reachable by its own physical path, and removing it first would leave "
        "a window in which tunnel routes still exist and the engine's own "
        "datagrams match them");
  Check(link_at < exclusion_at, "the link goes before the exclusion");
  Check(IndexOfCommand(commands, "resolvectl revert winsvpn3") < link_at,
        "the resolvers are reverted before the link is deleted");

  // The teardown undoes THE MECHANISM THAT WAS USED. A teardown that always
  // ran `resolvectl revert` would leave an openresolv host holding the
  // tunnel's resolvers after the tunnel was gone, and would leave a rewritten
  // /etc/resolv.conf in place for good.
  const Commands by_resolvconf = ArgvOf(
      winsvpn::winn3host::RenderLinuxWinn3TeardownCommands(
          params, Mechanism::kResolvconf));
  Check(HasCommand(by_resolvconf, "resolvconf -d winsvpn3 -f"),
        "an openresolv session is torn down with resolvconf, not resolvectl");
  Check(!HasCommand(by_resolvconf, "resolvectl revert winsvpn3"),
        "and not with resolvectl as well");

  const Commands by_file = ArgvOf(
      winsvpn::winn3host::RenderLinuxWinn3TeardownCommands(
          params, Mechanism::kResolvConfFile));
  const int restore_at = IndexOfCommand(
      by_file, "cp -f /var/lib/winsvpn/winn3-resolv.conf.orig /etc/resolv.conf");
  const int drop_at =
      IndexOfCommand(by_file, "rm -f /var/lib/winsvpn/winn3-resolv.conf.orig");
  Check(restore_at >= 0, "a rewritten /etc/resolv.conf is restored at teardown");
  Check(drop_at > restore_at,
        "and the backup is removed only AFTER the restore -- removing it first "
        "would destroy the only copy of the user's own resolvers");

  const Commands never_promoted = ArgvOf(
      winsvpn::winn3host::RenderLinuxWinn3TeardownCommands(params,
                                                           Mechanism::kUnknown));
  Check(!HasCommand(never_promoted, "resolvectl revert winsvpn3") &&
            !HasCommand(never_promoted, "resolvconf -d winsvpn3 -f") &&
            restore_at != IndexOfCommand(never_promoted, "cp"),
        "a session that never promoted removes no resolver, because it "
        "installed none");
}

// THE TEARDOWN SPEC THE FLEET LANE ASKED FOR, 2026-08-23.
//
// The fleet measured the residue of a stop that ran neither half of the v3
// teardown: the tun, the /1 pair, the /32 and the systemd-resolved settings
// all stayed up. This pins the teardown SPEC itself: it must emit, in order,
// the explicit `ip route del` of both promoted /1 halves (plus the IPv6 pair
// the promotion renders when the plan floor carries the sink), the resolver
// restore, the tun deletion, and the outer-socket /32 removal LAST.
void TestTheTeardownEmitsThePromotedRouteDelsInOrder() {
  const LinuxWinn3Params params = SampleParams();
  const Commands commands = ArgvOf(
      winsvpn::winn3host::RenderLinuxWinn3TeardownCommands(
          params, Mechanism::kSystemdResolved));
  const int low = IndexOfCommand(commands, "ip route del 0.0.0.0/1 dev winsvpn3");
  const int high =
      IndexOfCommand(commands, "ip route del 128.0.0.0/1 dev winsvpn3");
  const int v6_low = IndexOfCommand(commands, "ip -6 route del ::/1 dev winsvpn3");
  const int v6_high =
      IndexOfCommand(commands, "ip -6 route del 8000::/1 dev winsvpn3");
  const int revert = IndexOfCommand(commands, "resolvectl revert winsvpn3");
  const int link_down =
      IndexOfCommand(commands, "ip link set dev winsvpn3 down");
  const int link_del = IndexOfCommand(commands, "ip link delete dev winsvpn3");
  const int exclusion = IndexOfCommand(
      commands, "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  Check(low >= 0 && high >= 0,
        "the teardown removes BOTH halves of the promoted /1 pair explicitly, "
        "rather than relying on the link deletion that the fleet run never "
        "reached");
  Check(v6_low >= 0 && v6_high >= 0,
        "and both IPv6 halves, which the promoted posture renders when the "
        "plan floor carries the sink");
  Check(low < revert && high < revert && v6_low < revert && v6_high < revert,
        "the route dels come FIRST: nothing points at a device that is about "
        "to go away while the resolver is being reverted");
  Check(revert < link_del,
        "the resolver is reverted BEFORE the link is deleted, so a "
        "systemd-resolved revert always finds the interface it names");
  Check(link_down >= 0 && link_down < link_del,
        "the tun is brought down before it is deleted");
  Check(link_del < exclusion,
        "the tun is deleted before the exclusion is removed");
  Check(exclusion == static_cast<int>(commands.size()) - 1,
        "and the outer-socket /32 is removed LAST: while it stands the gateway "
        "is merely reachable by its own physical path, and removing it first "
        "would leave a window in which tunnel routes still exist and the "
        "engine's own datagrams match them");
}

// THE STOP PATH, 2026-08-23: production StopTunnel, the start path's own
// failure exits and the e2e harness all call StopLinuxWinn3Standalone, and
// this pins what that one function does with a real session: it runs the full
// teardown sequence through the privileged runner, and it is idempotent --
// a second stop runs nothing, and a stop with nothing remembered runs nothing
// and succeeds.
void TestTheStandaloneStopRunsTheTeardownAndIsIdempotent() {
  // Nothing was ever registered: a stop runs nothing, needs no runner, and
  // succeeds -- a machine where nothing is up must be able to stop cleanly.
  {
    RecordingRunner idle;
    std::string error;
    Check(winsvpn::winn3host::StopLinuxWinn3Standalone(idle.Runner(), &error) &&
              idle.attempted.empty(),
          "a stop with no standalone session remembered runs NOTHING and "
          "succeeds, so a host with no elevator can still stop cleanly");
  }

  // A full session: remember it, apply the bootstrap (the exclusion goes in),
  // apply the promotion through systemd-resolved (the resolvers go in).
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);
  winsvpn::winn3host::RememberLinuxWinn3Session(params);

  RecordingRunner bootstrap_runner;
  GiveSystemdResolved(&bootstrap_runner);
  PosturePlan narrow;
  const auto bootstrap = winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
      params, proven, bootstrap_runner.Runner(), &narrow);
  Check(bootstrap.outcome == Outcome::kApplied,
        "the bootstrap applied, so the outer-socket exclusion is installed: " +
            bootstrap.error);

  RecordingRunner promoted_runner;
  GiveSystemdResolved(&promoted_runner);
  PosturePlan plan;
  const auto promoted = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, promoted_runner.Runner(), &plan);
  Check(promoted.outcome == Outcome::kApplied,
        "the promotion applied, so the /1 pair and the resolvers are "
        "installed: " +
            promoted.error);

  // The stop. `stale_exclusion_in_kernel` models what the appliers just did:
  // the exclusion IS in the kernel, so its del must succeed.
  RecordingRunner stop_runner;
  stop_runner.stale_exclusion_in_kernel = true;
  std::string error;
  Check(winsvpn::winn3host::StopLinuxWinn3Standalone(stop_runner.Runner(),
                                                     &error),
        "the stop runs the full teardown through the runner: " + error);
  const Commands ran = stop_runner.ran;
  const int low = IndexOfCommand(ran, "ip route del 0.0.0.0/1 dev winsvpn3");
  const int high = IndexOfCommand(ran, "ip route del 128.0.0.0/1 dev winsvpn3");
  const int revert = IndexOfCommand(ran, "resolvectl revert winsvpn3");
  const int link_del = IndexOfCommand(ran, "ip link delete dev winsvpn3");
  const int exclusion = IndexOfCommand(
      ran, "ip -4 route del 203.0.113.9/32 via 192.168.1.1 dev wlan0");
  Check(low >= 0 && high >= 0, "the stop emits the /1 pair dels");
  Check(low < revert && high < revert,
        "in order: the route dels run before the resolver revert");
  Check(revert < link_del,
        "the resolver revert runs before the tun deletion");
  Check(link_del < exclusion,
        "the tun deletion runs before the exclusion removal");
  Check(exclusion == static_cast<int>(ran.size()) - 1,
        "and the exclusion is removed LAST, exactly the order the rendered "
        "spec pins");
  Check(!winsvpn::winn3host::LinuxWinn3StandaloneSessionWasStarted(),
        "a successful stop forgets the session");

  // Idempotent: the second stop runs nothing and succeeds.
  RecordingRunner again;
  std::string again_error;
  Check(winsvpn::winn3host::StopLinuxWinn3Standalone(again.Runner(),
                                                     &again_error) &&
            again.attempted.empty(),
        "a second stop runs NOTHING: the session was already reversed");
}

// --- the resolver mechanism -------------------------------------------------
//
// DEFECT 2 of 2026-08-10: promotion was impossible without systemd-resolved.
// The renderer emitted `resolvectl dns <iface> <ip>` and nothing else, so on a
// container, on Alpine, or on any machine using plain /etc/resolv.conf or
// openresolv the resolver command failed and BuildPromotedPosture's -- correct
// -- refusal to promote without resolvers made promotion unreachable.

void TestTheResolverMechanismIsProbedNotAssumed() {
  const LinuxWinn3Params params = SampleParams();
  std::string detail;

  RecordingRunner systemd;
  GiveSystemdResolved(&systemd);
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            params, systemd.Runner(), &detail) == Mechanism::kSystemdResolved,
        "a host whose resolvectl reaches the bus is systemd-resolved");

  // THE CASE THAT MATTERS: resolvectl exists but its bus does not answer. The
  // probe is `resolvectl --no-pager status` rather than `--version` precisely
  // so this machine is not read as a systemd-resolved one -- which is what the
  // old renderer effectively did, and it is how the 2026-08-10 run ended with
  // two capturing routes installed and a resolver command at exit 127.
  RecordingRunner dead_bus;
  GivePlainResolvConf(&dead_bus);
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            params, dead_bus.Runner(), &detail) == Mechanism::kResolvConfFile,
        "a host with resolvectl installed but no running resolved is NOT "
        "driven through systemd-resolved");

  RecordingRunner openresolv;
  GiveResolvconf(&openresolv);
  GivePlainResolvConf(&openresolv);
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            params, openresolv.Runner(), &detail) == Mechanism::kResolvconf,
        "resolvconf is preferred over rewriting /etc/resolv.conf, because the "
        "system already knows how to undo it");

  // A symlinked /etc/resolv.conf belongs to some other manager. Writing
  // through the link would clobber that manager's file while its manager was
  // merely not answering.
  RecordingRunner symlinked;
  symlinked.probes_ok.push_back("test -h /etc/resolv.conf");
  symlinked.probes_ok.push_back("test -f /etc/resolv.conf");
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            params, symlinked.Runner(), &detail) == Mechanism::kNone,
        "a symlinked /etc/resolv.conf is refused rather than written through");
  Check(Contains(detail, "symbolic link"), "and the refusal says why");

  RecordingRunner nothing;
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            params, nothing.Runner(), &detail) == Mechanism::kNone,
        "a host with no mechanism at all answers none");

  LinuxWinn3Params refuses_rewrite = SampleParams();
  refuses_rewrite.allow_direct_resolv_conf = false;
  RecordingRunner plain;
  GivePlainResolvConf(&plain);
  Check(winsvpn::winn3host::DetectLinuxWinn3ResolverMechanism(
            refuses_rewrite, plain.Runner(), &detail) == Mechanism::kNone,
        "allow_direct_resolv_conf false refuses the rewrite rather than "
        "silently taking it");
}

void TestEveryMechanismInstallsTheResolversItWasGiven() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);

  // openresolv: the body goes in on STANDARD INPUT, because openresolv has no
  // argument form for it.
  {
    RecordingRunner runner;
    GiveResolvconf(&runner);
    PosturePlan plan;
    const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
        params, proven, runner.Runner(), &plan);
    Check(result.outcome == Outcome::kApplied,
          "a machine with openresolv and NO systemd-resolved promotes: " +
              result.error);
    Check(result.resolver_mechanism == Mechanism::kResolvconf,
          "through resolvconf");
    Check(HasCommand(runner.ran, "resolvconf -a winsvpn3 -m 0 -x"),
          "with the exclusive, lowest-metric form wg-quick also uses");
    bool body_seen = false;
    for (const auto& entry : runner.stdin_seen) {
      if (entry.first == "resolvconf -a winsvpn3 -m 0 -x" &&
          entry.second == "nameserver 10.64.0.1\n") {
        body_seen = true;
      }
    }
    Check(body_seen,
          "and the resolv.conf body on standard input -- an argv-only runner "
          "could not have reached openresolv at all");
    Check(HasCommand(runner.ran, "ip route add 0.0.0.0/1 dev winsvpn3") &&
              HasCommand(runner.ran, "ip route add 128.0.0.0/1 dev winsvpn3"),
          "and both halves of the capture still go in");
  }

  // /etc/resolv.conf: repair, then back up, then write.
  {
    RecordingRunner runner;
    GivePlainResolvConf(&runner);
    PosturePlan plan;
    const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
        params, proven, runner.Runner(), &plan);
    Check(result.outcome == Outcome::kApplied,
          "a machine with neither systemd-resolved nor resolvconf promotes: " +
              result.error);
    Check(result.resolver_mechanism == Mechanism::kResolvConfFile,
          "by rewriting /etc/resolv.conf");
    const int repair_at = IndexOfCommand(
        runner.ran,
        "cp -f /var/lib/winsvpn/winn3-resolv.conf.orig /etc/resolv.conf");
    const int backup_at = IndexOfCommand(
        runner.ran,
        "cp -f /etc/resolv.conf /var/lib/winsvpn/winn3-resolv.conf.orig");
    const int write_at = IndexOfCommand(runner.ran, "tee /etc/resolv.conf");
    Check(repair_at >= 0 && backup_at > repair_at && write_at > backup_at,
          "a stale backup is RESTORED before a new one is taken, so a session "
          "killed before its teardown cannot make the next session back up a "
          "dead tunnel's resolvers as if they were the user's own");
    std::string body;
    for (const auto& entry : runner.stdin_seen) {
      if (entry.first == "tee /etc/resolv.conf") body = entry.second;
    }
    Check(Contains(body, "nameserver 10.64.0.1"),
          "the tunnel's resolver is written");
    Check(Contains(body, "/var/lib/winsvpn/winn3-resolv.conf.orig"),
          "and the file names the absolute path of the original, so a user "
          "whose name resolution has stopped reads the cause out of the file "
          "that is causing it");
    Check(Contains(body, "Win's VPN"),
          "and names what wrote it");
  }
}

void TestPromotionRefusesAHostWithNoResolverMechanism() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);
  RecordingRunner runner;  // answers no to every probe
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kNotAttempted,
        "a host that can install no resolver does not promote");
  Check(!result.capturing && runner.ran.empty(),
        "and NOTHING is installed -- the refusal happens before the first "
        "capturing route, not after it, which is the whole difference between "
        "this and the 2026-08-10 run");
  Check(Contains(result.error, "resolver set cannot move"),
        "and the refusal is the route-set-and-resolver-set rule, one layer "
        "down from BuildPromotedPosture's");
}

// --- the partial application ------------------------------------------------
//
// DEFECT 1 of 2026-08-10: the return value disagreed with kernel state.

void TestAPartialPromotionIsRolledBackAndSaysSo() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);

  // The measured shape: the routes go in, the resolver step fails.
  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  runner.fail_on = "resolvectl dns winsvpn3 10.64.0.1";
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kRolledBack,
        std::string("a promotion that fails part way is rolled back, not "
                    "reported as if nothing happened; got ") +
            OutcomeName(result.outcome));
  Check(!result.capturing,
        "and the result says the kernel is NOT capturing, which is the claim "
        "`ip route get 1.1.1.1` has to agree with");
  Check(result.rollback_attempted, "the rollback was attempted");
  Check(result.rollback_failed.empty(), "and every reversal succeeded");
  Check(result.applied.size() >= 5,
        "the sink address and the four /1 routes had been applied before the "
        "resolver step failed (the IPv6 sink widened the promoted delta, so "
        "'two capturing routes' is no longer the whole set)");
  Check(HasCommand(result.applied, "ip -6 address add fd00:d951:1::2/128 dev winsvpn3"),
        "the IPv6 sink address was applied");
  Check(HasCommand(result.applied, "ip route add 0.0.0.0/1 dev winsvpn3") &&
            HasCommand(result.applied, "ip route add 128.0.0.0/1 dev winsvpn3"),
        "and both IPv4 halves were applied");
  Check(HasCommand(result.applied, "ip -6 route add ::/1 dev winsvpn3") &&
            HasCommand(result.applied, "ip -6 route add 8000::/1 dev winsvpn3"),
        "and both IPv6 halves were applied");
  Check(Join(result.failed) == "resolvectl dns winsvpn3 10.64.0.1",
        "and the failing command is named rather than summarised away");

  // The reversals actually ran, in reverse order, and they are `del` forms of
  // the same vectors rather than independently written ones.
  const int high_del =
      IndexOfCommand(runner.ran, "ip route del 128.0.0.0/1 dev winsvpn3");
  const int low_del =
      IndexOfCommand(runner.ran, "ip route del 0.0.0.0/1 dev winsvpn3");
  Check(high_del >= 0 && low_del > high_del,
        "the widest thing installed is the first thing removed");
  Check(!HasCommand(runner.ran, "ip link set dev winsvpn3 mtu 1359 down"),
        "the MTU is not 'reversed' by inventing a command for it: it captures "
        "nothing and there is no unset");
}

void TestARollbackThatFailsIsNamedRatherThanHidden() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);

  // The third state: the resolver step fails AND one reversal fails. This is
  // the state a rollback-only fix would have left unenumerated, and it is why
  // the result type exists rather than only the cleanup.
  RecordingRunner runner;
  GiveSystemdResolved(&runner);
  runner.fail_all.push_back("resolvectl dns winsvpn3 10.64.0.1");
  runner.fail_all.push_back("ip route del 0.0.0.0/1 dev winsvpn3");
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);

  Check(result.outcome == Outcome::kPartiallyApplied,
        std::string("a rollback that fails leaves a PARTIALLY APPLIED posture, "
                    "which is a value the caller receives; got ") +
            OutcomeName(result.outcome));
  Check(result.rollback_failed.size() == 1,
        "and the reversal that failed is counted");
  Check(!result.capturing,
        "0.0.0.0/1 alone does not capture: 128.0.0.0/1 came out, and half the "
        "pair is not a capture -- the same asymmetry "
        "VerifyPromotedCommandsCapture refuses to promote on");
  Check(Contains(result.error, "torn down"),
        "and the caller is told the session must be torn down rather than left "
        "running");

  // Both halves left behind IS a capture, and the result must say so.
  RecordingRunner both;
  GiveSystemdResolved(&both);
  both.fail_all.push_back("resolvectl dns winsvpn3 10.64.0.1");
  both.fail_all.push_back("ip route del 0.0.0.0/1 dev winsvpn3");
  both.fail_all.push_back("ip route del 128.0.0.0/1 dev winsvpn3");
  PosturePlan both_plan;
  const auto both_result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, both.Runner(), &both_plan);
  Check(both_result.outcome == Outcome::kPartiallyApplied,
        "a rollback that removes nothing is partially applied");
  Check(both_result.capturing,
        "AND it reports capturing -- this is the exact 2026-08-10 kernel state "
        "that the old boolean reported as plain `false`");
  Check(Contains(DescribeLinuxWinn3PostureResult(both_result),
                 "THE KERNEL IS CAPTURING"),
        "and the one-line description leads with it");
}

void TestTheResultIsPublishedInTheStatusDocument() {
  const LinuxWinn3Params params = SampleParams();
  EngineStatus proven;
  ParseWinn3StatusLine(
      StatusLine(true, "carrying", 7, 7, kFloorInnerMtu1500, false), &proven);
  RecordingRunner runner;
  GiveResolvconf(&runner);
  PosturePlan plan;
  const auto result = winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
      params, proven, runner.Runner(), &plan);
  Check(result.outcome == Outcome::kApplied, "the promotion applied");
  const std::string status = winsvpn::winn3host::LinuxWinn3ResolverStatusJson();
  Check(Contains(status, "\"resolver_mechanism\":\"resolvconf\""),
        "the mechanism an operator would need is IN the status document, not "
        "only in a local variable: " +
            status);
  Check(Contains(status, "\"promoted_posture\":\"applied\""),
        "and so is the outcome");
  Check(Contains(status, "\"promoted_capturing\":true"),
        "and whether the kernel is capturing");
}

}  // namespace

// ===========================================================================
// THE SERVED `[winn]` SECTION
// ===========================================================================
//
// kServedConfig is BYTE FOR BYTE what winn3/conform's ServedWinnSectionINI
// renders for the reference operator -- the same document Apple, Android and
// Windows are fed, and the same literal windows/runner/winn3_supervisor_test.cc
// carries. TestTheServedFixtureIsTheOneEveryHostParses in
// winn_protocol_experimental/winn3/conform/conform_test.go greps this file for
// it, so it cannot drift from the contract without failing the Go suite.
//
// Until 2026-08-09 Linux had NO reader for this at all. Everything else in this
// file -- the sizing mirror, the key document, the create payload, both
// postures, the promotion predicate -- existed and was tested, and nothing
// could fill a LinuxWinn3Params except a caller writing the struct by hand.
// That is not a divergence from the served contract; it is an absence from it,
// and an absence is quieter: a divergence shows up the first time two hosts are
// compared, and a platform with no parser never enters the comparison.
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

void TestTheServedSectionSelectsAndParses() {
  Check(LinuxConfigSelectsWinn3(kServedConfig),
        "`carrier = winn3` selects the standalone v3 host");
  Check(!LinuxConfigSelectsWinn3(
            "[winn]\nenabled = true\ncarrier = direct-awg\n"),
        "the AmneziaWG-carried winn/1 path is not this host's business");
  Check(!LinuxConfigSelectsWinn3("[winn]\nenabled = true\n"),
        "a section naming no carrier selects nothing here: ParseLinuxWinn"
        "Section owns that configuration and this must never speak for it");

  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;
  Check(ParseLinuxWinn3Section(kServedConfig, &params, &material, &error),
        "the served section parses: " + error);
  Check(params.gateway_endpoint == "203.0.113.7:51820", "endpoint");
  Check(params.inner_address == "10.10.0.9",
        "inner_v4 is the v3 gateway's own inner space and not the AmneziaWG "
        "assignment: the winn/3 tun layer drops every packet whose source does "
        "not match its assignment");
  Check(params.inner_next_hop == "10.10.0.1", "inner_router_v4");
  Check(params.path_mtu == 1500, "the path MTU the section named");
  Check(params.carrier_classes.size() == 3 &&
            params.carrier_classes[0] == "udp" &&
            params.carrier_classes[2] == "tls",
        "the migration plan the floor is computed over");

  // THE ONE DECODE, at the descriptor boundary. The key document carries the
  // operator's gateway NAME, byte for byte what `winn3-gateway -gateway-id`
  // was given, because the admission tag is computed over it and never
  // transmitted.
  Check(params.keys.gateway_id == "winsgw01",
        "gateway_id is decoded exactly once, here");
  Check(params.keys.gateway_id != "d2luc2d3MDE=",
        "the transport base64 does not survive into the key document");

  // The key material, in the two shapes that matter.
  Check(material.static_private.size() == 32, "a 32-byte X25519 private key");
  Check(material.gateway_static.size() == 32, "a 32-byte X25519 public key");
  // 64, NOT 32. keygen writes 64 ASCII hex characters and every consumer keys
  // with THOSE CHARACTERS. Hex-decoding them keys 32 bytes against the
  // gateway's 64, and that failure BUILDS a session and then goes completely
  // silent -- worse than a refusal, because a host watching for "did the
  // gateway see me" sees yes.
  Check(material.admission_secret ==
            "6f39a0c1d24b7e8f5a3c9012b4d6e8f01a2b3c4d5e6f708192a3b4c5d6e7f809",
        "the admission secret is the key file's bytes, opaque and never "
        "decoded again");

  // And the plan floor this host computes from the served numbers is the one
  // every other host computes: 1359, not the dialled UDP/IPv4 1443.
  int inner = 0;
  Check(winsvpn::winn3host::sizing::PlanFloorInnerMtu(
            params.path_mtu, params.carrier_classes, &inner, &error),
        "the served plan sizes: " + error);
  Check(inner == 1359,
        "the plan floor at a 1500-byte path over [udp,tcp,tls] is 1359; 1443 "
        "would be the dialled UDP-over-IPv4 carrier, 84 bytes too wide, and it "
        "black-holes every full-size flow at the first migration while the "
        "tunnel reads up at both ends");
}

void TestTheServedDualAuthPairIsConsumedAndBound() {
  const std::string dual = std::string(kServedConfig) +
                           "auth_ed25519 = " + DualAuthEd25519B64() +
                           "\nauth_mldsa65 = " + DualAuthMldsa65B64() + "\n";
  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;
  Check(ParseLinuxWinn3Section(dual, &params, &material, &error),
        "a served section carrying both dual-auth keys parses: " + error);
  Check(material.auth_ed25519_hex == std::string(64, 'a'),
        "the Ed25519 pub is stored as 64 lowercase hex characters");
  Check(material.auth_mldsa65_hex == std::string(3904, 'b'),
        "the ML-DSA-65 pub is stored as 3904 lowercase hex characters");

  char root_template[] = "/tmp/wins-winn3-dualauth.XXXXXX";
  const char* root = mkdtemp(root_template);
  Check(root != nullptr, "a temporary directory could be made");
  if (root == nullptr) return;
  Check(setenv("XDG_DATA_HOME", root, 1) == 0, "XDG_DATA_HOME could be set");
  Check(mkdir((std::string(root) + "/wins_vpn").c_str(), 0700) == 0,
        "the app directory could be made");
  Check(mkdir((std::string(root) + "/wins_vpn/winn3").c_str(), 0700) == 0,
        "the winn3 state directory could be made");
  Check(WriteLinuxWinn3KeyFiles(material, &params, &error),
        "dual-auth files are written: " + error);
  Check(params.keys.dual_auth_ed25519_pub_path.find("auth_ed25519.pub") !=
            std::string::npos,
        "the key document path names auth_ed25519.pub");
  Check(params.keys.dual_auth_mldsa65_pub_path.find("auth_mldsa65.pub") !=
            std::string::npos,
        "the key document path names auth_mldsa65.pub");
  params.keys.outer_socket_exclusion = "exclusion";
  std::string document;
  Check(winsvpn::winn3host::BuildLinuxWinn3KeysJson(params.keys, &document,
                                                    &error),
        "a dual-auth key document builds: " + error);
  Check(Contains(document, "\"dual_auth_ed25519_pub_path\"") &&
            Contains(document, "\"dual_auth_mldsa65_pub_path\""),
        "the engine document binds both dual-auth paths");
  Check(!Contains(document, material.auth_ed25519_hex) &&
            !Contains(document, DualAuthEd25519B64()),
        "the key document holds no dual-auth key material");
}

void TestTheServedDualAuthPairRefusesMismatchMissingAndStale() {
  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;

  const std::string missing_ml = std::string(kServedConfig) +
                                 "auth_ed25519 = " + DualAuthEd25519B64() +
                                 "\n";
  Check(!ParseLinuxWinn3Section(missing_ml, &params, &material, &error),
        "a missing auth_mldsa65 half is refused");
  Check(Contains(error, "auth_ed25519") && Contains(error, "auth_mldsa65"),
        "the half-provision refusal names both keys: " + error);
  Check(params.inner_address.empty() && material.auth_ed25519_hex.empty(),
        "a refused parse fills no dual-auth material");

  const std::string missing_ed = std::string(kServedConfig) +
                                 "auth_mldsa65 = " + DualAuthMldsa65B64() +
                                 "\n";
  Check(!ParseLinuxWinn3Section(missing_ed, &params, &material, &error),
        "a missing auth_ed25519 half is refused");

  const std::string short_ed =
      std::string(kServedConfig) + "auth_ed25519 = " +
      EncodeStdBase64(std::string(31, '\xAA')) +
      "\nauth_mldsa65 = " + DualAuthMldsa65B64() + "\n";
  Check(!ParseLinuxWinn3Section(short_ed, &params, &material, &error),
        "a 31-byte Ed25519 key is a length mismatch");
  Check(Contains(error, "auth_ed25519"),
        "the mismatch names auth_ed25519: " + error);

  const std::string swapped =
      std::string(kServedConfig) + "auth_ed25519 = " + DualAuthMldsa65B64() +
      "\nauth_mldsa65 = " + DualAuthEd25519B64() + "\n";
  Check(!ParseLinuxWinn3Section(swapped, &params, &material, &error),
        "swapped dual-auth sizes are a mismatch");

  Check(ParseLinuxWinn3Section(kServedConfig, &params, &material, &error),
        "a legacy served section without the pair still parses: " + error);
  Check(material.auth_ed25519_hex.empty() && material.auth_mldsa65_hex.empty(),
        "legacy parse stores no stale dual-auth values");

  LinuxWinn3Keys half = SampleParams().keys;
  half.dual_auth_ed25519_pub_path = "/tmp/auth_ed25519.pub";
  std::string document;
  Check(!winsvpn::winn3host::BuildLinuxWinn3KeysJson(half, &document, &error),
        "a half-set dual-auth path pair is refused at the key document");
  Check(Contains(error, "together"),
        "the document refusal names the both-or-neither rule: " + error);

  char root_template[] = "/tmp/wins-winn3-stale-dualauth.XXXXXX";
  const char* root = mkdtemp(root_template);
  Check(root != nullptr, "a stale-test directory could be made");
  if (root == nullptr) return;
  Check(setenv("XDG_DATA_HOME", root, 1) == 0, "XDG_DATA_HOME could be set");
  Check(mkdir((std::string(root) + "/wins_vpn").c_str(), 0700) == 0,
        "the app directory could be made");
  Check(mkdir((std::string(root) + "/wins_vpn/winn3").c_str(), 0700) == 0,
        "the winn3 state directory could be made");
  const std::string stale_ed =
      std::string(root) + "/wins_vpn/winn3/auth_ed25519.pub";
  const std::string stale_ml =
      std::string(root) + "/wins_vpn/winn3/auth_mldsa65.pub";
  FILE* ed = std::fopen(stale_ed.c_str(), "w");
  FILE* ml = std::fopen(stale_ml.c_str(), "w");
  Check(ed != nullptr && ml != nullptr, "stale dual-auth files could be planted");
  if (ed != nullptr) {
    std::fputs("stale-ed", ed);
    std::fclose(ed);
  }
  if (ml != nullptr) {
    std::fputs("stale-ml", ml);
    std::fclose(ml);
  }
  Check(WriteLinuxWinn3KeyFiles(material, &params, &error),
        "a legacy write succeeds over leftover dual-auth files: " + error);
  Check(params.keys.dual_auth_ed25519_pub_path.empty() &&
            params.keys.dual_auth_mldsa65_pub_path.empty(),
        "a legacy session does not bind leftover dual-auth paths");
  Check(access(stale_ed.c_str(), F_OK) != 0 &&
            access(stale_ml.c_str(), F_OK) != 0,
        "stale dual-auth files are unlinked rather than rebound");
  params.keys.outer_socket_exclusion = "exclusion";
  Check(winsvpn::winn3host::BuildLinuxWinn3KeysJson(params.keys, &document,
                                                    &error),
        "a legacy key document still builds: " + error);
  Check(!Contains(document, "dual_auth_"),
        "a stale dual-auth pair is not rebound into the engine document");
}

void TestTheServedSectionBindsTheSelectedNode() {
  const std::string selected = "selected_node = lab-alpha\n";
  const std::string descriptor = "node = lab-alpha\n";
  std::vector<std::string> refused;
  std::string mismatch = kServedConfig;
  mismatch.replace(mismatch.find(selected), selected.size(),
                   "selected_node = lab-beta\n");
  refused.push_back(mismatch);
  std::string missing = kServedConfig;
  missing.replace(missing.find(descriptor), descriptor.size(), "");
  refused.push_back(missing);
  refused.push_back(std::string(kServedConfig) + descriptor);
  for (const std::string& raw : refused) {
    LinuxWinn3Params params;
    LinuxWinn3ServedKeyMaterial material;
    std::string error;
    Check(!ParseLinuxWinn3Section(raw, &params, &material, &error),
          "a missing, mismatched, or duplicate node binding is refused");
    Check(Contains(error, "node"),
          "the node-binding refusal names the node field: " + error);
  }
}

void TestNativeStartBindsTheIndependentPickerNode() {
  std::string normalized;
  Check(NormalizeLinuxWinn3NodeIdentity(" Lab-Alpha ", &normalized) &&
            normalized == "lab-alpha",
        "Linux folds only ASCII case in the independent picker slug");
  Check(!NormalizeLinuxWinn3NodeIdentity(
            std::string("\xE2\x84\xAA") + "1", &normalized),
        "Linux refuses the Kelvin-sign Unicode fold");

  std::string error;
  Check(ValidateLinuxWinn3IndependentSelectedNode(
            kServedConfig, "Lab-Alpha", &error),
        "the independently selected picker slug binds: " + error);
  for (const std::string& caller : {
           std::string(), std::string("lab-beta"),
           std::string("\xE2\x84\xAA") + "1",
       }) {
    error.clear();
    Check(!ValidateLinuxWinn3IndependentSelectedNode(
              kServedConfig, caller, &error),
          "missing, conflicting, or Unicode picker identity is refused");
    Check(Contains(error, "independently selected node"),
          "the native caller-binding refusal names its independent source: " +
              error);
  }
}

void TestTheServedSectionRefusesWhatWouldBeSilent() {
  struct Case {
    const char* replace;
    const char* with;
    const char* names;
  };
  const Case cases[] = {
      {"inner_v4 = 10.10.0.9", "inner_v4 =", "inner_v4"},
      {"inner_router_v4 = 10.10.0.1", "inner_router_v4 =", "inner_router_v4"},
      {"gateway_id = d2luc2d3MDE=", "gateway_id = not base64!", "gateway_id"},
      // URL-SAFE base64, and embedded whitespace. The signed descriptor emits
      // neither, and a decoder lenient enough to accept them would produce
      // DIFFERENT bytes for two values an operator would call the same --
      // silently, because both would decode.
      {"gateway_id = d2luc2d3MDE=", "gateway_id = d2luc2d3MD_=", "gateway_id"},
      {"gateway_id = d2luc2d3MDE=", "gateway_id = d2lu c2d3MDE=", "gateway_id"},
      {"static_private = ERERERERERERERERERERERERERERERERERERERERERE=",
       "static_private = ERERERERERERERERERERERERERERERERERERERERER-",
       "static_private"},
      {"static_private = ERERERERERERERERERERERERERERERERERERERERERE=",
       "static_private = 1f1f1f1f", "static_private"},
      {"gateway_static = U1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1M=",
       "gateway_static =", "gateway_static"},
      {"carrier_classes = udp,tcp,tls", "carrier_classes =", "carrier_classes"},
      {"carrier_classes = udp,tcp,tls", "carrier_classes = udp,quic",
       "carrier_classes"},
      {"endpoint = 203.0.113.7:51820", "endpoint = gateway.example:51820",
       "endpoint"},
  };
  for (const Case& c : cases) {
    std::string mutated = kServedConfig;
    const auto at = mutated.find(c.replace);
    Check(at != std::string::npos,
          std::string("the fixture still contains ") + c.replace);
    mutated.replace(at, std::strlen(c.replace), c.with);
    LinuxWinn3Params params;
    LinuxWinn3ServedKeyMaterial material;
    std::string error;
    Check(!ParseLinuxWinn3Section(mutated, &params, &material, &error),
          std::string("refused: ") + c.with);
    Check(error.find(c.names) != std::string::npos,
          std::string("and the refusal names ") + c.names + " (got: " + error +
              ")");
  }

  // An unrecognised key is a refusal, not something to drop. A dropped key
  // looks exactly like a key that took effect, and the two that could silently
  // not take effect here are the migration plan and the inner address.
  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;
  Check(!ParseLinuxWinn3Section(std::string(kServedConfig) + "mtu = 1223\n",
                                &params, &material, &error),
        "an unrecognised [winn] key is refused");
  Check(error.find("mtu") != std::string::npos, "and it names the key");

  // Neither output is partially filled on a refusal.
  Check(params.inner_address.empty() && material.admission_secret.empty(),
        "a refused parse fills nothing: a half-built session is one that "
        "starts with a value nobody chose");
}

// THE CARRIER GATE. windows/runner/winn3_supervisor refuses a plan naming an
// unknown class ("a plan naming an unknown class is refused") and so does Apple's
// host. ParseLinuxWinn3Section must mirror that gate: an unsupported carrier is
// a refusal at parse time, NAMED, never a silent drop and never charged a
// default floor -- because a class whose message floor was never computed over
// it black-holes the session at the first escalation while both ends still read
// up. The general refusal table covers this as one row; this test makes the
// gate a named assertion of its own so a regression in the carrier check wins a
// failure that says "carrier".
void TestTheCarrierGateRefusesAnUnsupportedCarrier() {
  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;

  // Control green: the supported plan parses.
  Check(ParseLinuxWinn3Section(kServedConfig, &params, &material, &error),
        "the served [winn] section with the supported plan parses: " + error);

  // A single unsupported carrier is refused and NAMED, so the operator is told
  // which class cannot escalate rather than that the whole plan is bad.
  std::string mutated = kServedConfig;
  const std::string needle = "carrier_classes = udp,tcp,tls\n";
  const auto at = mutated.find(needle);
  Check(at != std::string::npos, "the fixture still carries the plan line");
  mutated.replace(at, needle.size(), "carrier_classes = udp,tcp,quic\n");
  error.clear();
  Check(!ParseLinuxWinn3Section(mutated, &params, &material, &error),
        "a plan naming the unsupported carrier quic is refused at parse time");
  Check(error.find("quic") != std::string::npos,
        "and the refusal names the unsupported carrier (got: " + error + ")");

  // The gate refuses the UNKNOWN CLASS, not merely a differently-ordered plan:
  // plan order is irrelevant, membership is not.
  std::string reordered = kServedConfig;
  reordered.replace(at, needle.size(), "carrier_classes = tls,udp,tcp\n");
  error.clear();
  Check(ParseLinuxWinn3Section(reordered, &params, &material, &error),
        "a differently-ordered plan of supported carriers still parses: " +
            error);

  // And the sizing gate agrees: the same unsupported carrier is refused at the
  // message-floor level, where a silently-recalculated floor is the black hole.
  int out = 0;
  error.clear();
  Check(!winsvpn::winn3host::sizing::PlanFloorMessageSize(
            1500, {"udp", "tcp", "quic"}, &out, &error),
        "the sizing gate refuses the same unsupported carrier");
  Check(error.find("quic") != std::string::npos,
        "and the sizing gate names the unsupported carrier");
}

// THE CARRIER GATE. `carrier` is the discriminator that separates the v3 host
// from the shipping winn/1 AmneziaWG relay, on every platform: Windows refuses
// any carrier but `direct-awg` in its winn/1 parser and selects v3 only for
// `winn3`, Apple reads the same `[winn] carrier = winn3` the control plane
// serves, and this host must refuse any `[winn]` section whose carrier is not
// `winn3` BEFORE it touches a single other key. A section that is really a
// winn/1 session -- or that names a carrier nobody emits -- must never be
// handed to the inner-packet v3 relay, because that mistake either puts
// cleartext on the wire or double-encrypts everything.
void TestTheCarrierDiscriminatorRefusesAnUnsupportedCarrier() {
  // The positive control, so the refusal below is an answer and not the whole
  // gate: exactly the served carrier selects and parses.
  LinuxWinn3Params params;
  LinuxWinn3ServedKeyMaterial material;
  std::string error;
  Check(LinuxConfigSelectsWinn3(kServedConfig),
        "the served `carrier = winn3` selects the v3 host");
  Check(ParseLinuxWinn3Section(kServedConfig, &params, &material, &error),
        "and the served carrier parses: " + error);

  // The negative half: every carrier that is not `winn3` is refused, and the
  // refusal blames the carrier field. Most refusals are the winn/1 AmneziaWG
  // carrier, which must never reach the inner-packet relay.
  const char* refused_carriers[] = {
      "direct-awg",  // the shipping winn/1 AmneziaWG carrier
      "quic",        // a migration class misused as the discriminator
      "winn2",       // a carrier nobody emits
      "",            // an empty carrier value
  };
  for (const char* carrier : refused_carriers) {
    const std::string config =
        std::string("[winn]\nenabled = true\ncarrier = ") + carrier + "\n";
    Check(!LinuxConfigSelectsWinn3(config),
          std::string("a `carrier = ") + carrier +
              "` section does not select the v3 host");
    params = LinuxWinn3Params();
    material = LinuxWinn3ServedKeyMaterial();
    error.clear();
    Check(!ParseLinuxWinn3Section(config, &params, &material, &error),
          std::string("the \"") + carrier +
              "\" carrier is refused by the v3 host, not dropped or guessed");
    Check(Contains(error, "carrier"),
          std::string("and the refusal blames the carrier field, not a key "
                      "that happens to sort nearby: ") +
              error);
    Check(params.inner_address.empty() && material.admission_secret.empty(),
          "a refused carrier fills nothing: a half-built session is one that "
          "starts with a value nobody chose");
  }

  // A section with NO carrier is refused the same way: this host must never
  // speak for a [winn] section that does not declare which protocol it is.
  const std::string no_carrier = "[winn]\nenabled = true\n";
  Check(!LinuxConfigSelectsWinn3(no_carrier),
        "a [winn] section naming no carrier selects nothing here");
  params = LinuxWinn3Params();
  material = LinuxWinn3ServedKeyMaterial();
  error.clear();
  Check(!ParseLinuxWinn3Section(no_carrier, &params, &material, &error),
        "and ParseLinuxWinn3Section refuses a carrier-less section rather "
        "than guessing, matching ParseWindowsWinnSection's by-name refusal");
}

void TestLinuxWinn3LivenessNeverFallsThroughToV1() {
  Check(std::string(winsvpn::winn3host::kLinuxWinn3InterfaceName) == "winsvpn3",
        "the standalone v3 interface is winsvpn3, not the v1 winsvpn name");
  Check(winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            true, true, true, false),
        "a promoted v3 session with winsvpn3 and the v3 engine is live");
  Check(!winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            true, true, false, true),
        "v3 started with a dead v3 engine must not fall through to v1");
  Check(!winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            true, false, true, true),
        "v3 started without winsvpn3 must not fall through to v1");
  Check(!winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            true, false, false, true),
        "a remembered v3 session is never reported live via the v1 path");
  Check(winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            false, false, false, true),
        "with no v3 session, the v1 running answer is used");
  Check(!winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
            false, true, true, false),
        "winsvpn3 leftovers without a remembered session are not a live tunnel");
}

void TestLinuxWinn3ProofOutcomesAndFallbackAuthorization() {
  using winsvpn::winn3host::ClassifyWinn3ProofDiagnostic;
  using winsvpn::winn3host::ClassifyWinn3StartFailure;
  using winsvpn::winn3host::MakeConnectedWinn3StartProof;
  using winsvpn::winn3host::Winn3ProofOutcome;
  using winsvpn::winn3host::Winn3ProofOutcomeName;
  using winsvpn::winn3host::Winn3StartProofAuthorizesOrdinaryFallback;

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
  Check(ClassifyWinn3ProofDiagnostic("No route to host") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "EHOSTUNREACH prose is not a structured OS error");
  Check(ClassifyWinn3ProofDiagnostic("connect: Connection refused") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "connection refused never authorizes cover");
  Check(ClassifyWinn3ProofDiagnostic("Network is unreachable", 101) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "Linux ENETUNREACH 101 is ordinary only as a structured OS error");
  Check(ClassifyWinn3ProofDiagnostic("timeout", 101, true) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "timeout overrides an ordinary OS error");
  Check(ClassifyWinn3ProofDiagnostic("", 100) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "Linux ENETDOWN 100 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 112) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "Linux EHOSTDOWN 112 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 113) ==
            Winn3ProofOutcome::kOrdinaryConnectivity,
        "Linux EHOSTUNREACH 113 is ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 111) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "ECONNREFUSED is not ordinary");
  Check(ClassifyWinn3ProofDiagnostic("", 51) ==
            Winn3ProofOutcome::kUnknownTerminal,
        "Darwin ENETUNREACH is not a Linux ordinary code");

  Check(ClassifyWinn3ProofDiagnostic("admission rejected") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "admission refusal is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "handshake messages arrived and none of them could be opened. "
            "Check the gateway static key") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "unopenable handshake is a credential fault");
  Check(ClassifyWinn3ProofDiagnostic("replay journal persistence failed") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "replay integrity is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "the status document disagrees with itself") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "proof integrity disagreement is terminal security");
  Check(ClassifyWinn3ProofDiagnostic(
            "This server asked for a standalone Winn Protocol v3 session and "
            "the connection details could not be used") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "unusable served credentials are terminal security");

  Check(ClassifyWinn3ProofDiagnostic(
            "The Winn Protocol v3 session never reached the carrying state") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "silence without network evidence is unknown, not ordinary");
  Check(ClassifyWinn3ProofDiagnostic(
            "handshake attempts exhausted; nothing arrived at all") ==
            Winn3ProofOutcome::kUnknownTerminal,
        "credential silence and a UDP drop are indistinguishable");
  Check(ClassifyWinn3ProofDiagnostic("") == Winn3ProofOutcome::kUnknownTerminal,
        "an empty diagnostic cannot authorize fallback");
  Check(ClassifyWinn3ProofDiagnostic(
            "Network is unreachable; admission rejected") ==
            Winn3ProofOutcome::kTerminalSecurity,
        "security evidence wins over a network phrase");

  const auto ordinary = ClassifyWinn3StartFailure(
      7, false, "ip route get failed", 101, 55, "0123456789abcdef", "node-a");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 7, 55),
        "matching generation plus Linux OS error and token authorizes fallback");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 8),
        "a stale generation cannot authorize fallback");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 0),
        "generation 0 cannot authorize fallback");
  const auto unknown =
      ClassifyWinn3StartFailure(7, false, "the datapath was never proven");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(unknown, 7),
        "unknown_terminal fails closed");
  const auto security =
      ClassifyWinn3StartFailure(7, false, "admission rejected");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(security, 7),
        "terminal_security fails closed");
  const auto canceled =
      ClassifyWinn3StartFailure(7, true, "Network is unreachable");
  Check(canceled.canceled, "canceled starts stay canceled");
  Check(canceled.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "cancel is unknown_terminal even with network evidence");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(canceled, 7),
        "stop/cancel does not authorize fallback");
  const auto connected = MakeConnectedWinn3StartProof(7);
  Check(connected.outcome == Winn3ProofOutcome::kConnected,
        "a successful start is connected");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(connected, 7),
        "connected does not authorize fallback");
}

void TestLinuxWinn3CapturedOsErrorPropagatesToCover() {
  using winsvpn::winn3host::ArmWinn3AwgXrayGrant;
  using winsvpn::winn3host::CaptureCurrentLinuxOsError;
  using winsvpn::winn3host::ClassifyCapturedWinn3StartFailure;
  using winsvpn::winn3host::ClassifyWinn3StartFailure;
  using winsvpn::winn3host::ConsumeWinn3AwgXrayGrant;
  using winsvpn::winn3host::kLinuxEnetunreach;
  using winsvpn::winn3host::PeekLinuxWinn3OsError;
  using winsvpn::winn3host::RememberLinuxWinn3OsError;
  using winsvpn::winn3host::TakeLinuxWinn3OsError;
  using winsvpn::winn3host::Winn3AwgXrayGrant;
  using winsvpn::winn3host::Winn3CoverLeg;
  using winsvpn::winn3host::Winn3GrantConsumeResult;
  using winsvpn::winn3host::Winn3ProofOutcome;
  using winsvpn::winn3host::Winn3StartProofAuthorizesOrdinaryFallback;

  RememberLinuxWinn3OsError(0);
  Check(TakeLinuxWinn3OsError() == 0, "empty capture slot is zero");

  const std::string prose = "Network is unreachable";
  Check(ClassifyWinn3StartFailure(7, false, prose, 0, 55, "0123456789abcdef",
                                  "node-a")
                .outcome == Winn3ProofOutcome::kUnknownTerminal,
        "production os_error=0 never authorizes from prose");

  errno = kLinuxEnetunreach;
  Check(CaptureCurrentLinuxOsError() == kLinuxEnetunreach,
        "capture reads the integer errno, not strerror prose");
  RememberLinuxWinn3OsError(CaptureCurrentLinuxOsError());
  errno = 0;
  Check(PeekLinuxWinn3OsError() == kLinuxEnetunreach,
        "remembered errno survives a later errno clobber");
  const auto ordinary = ClassifyCapturedWinn3StartFailure(
      7, false, prose, 55, "0123456789abcdef", "node-a");
  Check(ordinary.os_error == kLinuxEnetunreach,
        "captured ENETUNREACH is stored on the proof");
  Check(ordinary.outcome == Winn3ProofOutcome::kOrdinaryConnectivity,
        "Linux ENETUNREACH authorizes ordinary_connectivity");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(ordinary, 7, 55),
        "captured ENETUNREACH authorizes generation-bound cover");
  Check(PeekLinuxWinn3OsError() == 0, "classify consumes the captured error");

  Winn3AwgXrayGrant grant;
  Check(ArmWinn3AwgXrayGrant(55, 7, "0123456789abcdef", "node-a", 500, &grant),
        "ordinary captured start arms the one-use grant");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 55, 7, "0123456789abcdef", "node-a",
                                 "v1-cover", Winn3CoverLeg::kAwg, 501) ==
            Winn3GrantConsumeResult::kOk,
        "first cover consume is AWG");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 55, 7, "0123456789abcdef", "node-a",
                                 "v1-cover", Winn3CoverLeg::kXray, 502) ==
            Winn3GrantConsumeResult::kOk,
        "optional Xray consume follows AWG");

  RememberLinuxWinn3OsError(111);
  const auto refused = ClassifyCapturedWinn3StartFailure(
      7, false, prose, 55, "0123456789abcdef", "node-a");
  Check(refused.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "ECONNREFUSED is not ordinary");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(refused, 7, 55),
        "ECONNREFUSED never authorizes cover");

  RememberLinuxWinn3OsError(51);
  const auto darwin = ClassifyCapturedWinn3StartFailure(
      7, false, prose, 55, "0123456789abcdef", "node-a");
  Check(darwin.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "Darwin ENETUNREACH is not a Linux ordinary code");

  RememberLinuxWinn3OsError(kLinuxEnetunreach);
  const auto security = ClassifyCapturedWinn3StartFailure(
      7, false, "admission rejected", 55, "0123456789abcdef", "node-a");
  Check(security.outcome == Winn3ProofOutcome::kTerminalSecurity,
        "terminal security wins over ENETUNREACH");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(security, 7, 55),
        "security plus ENETUNREACH does not authorize cover");

  RememberLinuxWinn3OsError(kLinuxEnetunreach);
  const auto timed_out = ClassifyCapturedWinn3StartFailure(
      7, false, prose, 55, "0123456789abcdef", "node-a", true);
  Check(timed_out.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "timeout wins over ENETUNREACH");

  RememberLinuxWinn3OsError(kLinuxEnetunreach);
  const auto canceled = ClassifyCapturedWinn3StartFailure(
      7, true, prose, 55, "0123456789abcdef", "node-a");
  Check(canceled.canceled, "cancel flag is preserved");
  Check(canceled.outcome == Winn3ProofOutcome::kUnknownTerminal,
        "cancel wins over ENETUNREACH");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(canceled, 7, 55),
        "cancel never authorizes cover");
}

void TestLinuxWinn3StartReadinessStop() {
  using winsvpn::winn3host::ClassifyWinn3StartFailure;
  using winsvpn::winn3host::LinuxTunnelRunningConsideringV3;
  using winsvpn::winn3host::MakeConnectedWinn3StartProof;
  using winsvpn::winn3host::Winn3StartProof;
  using winsvpn::winn3host::Winn3StartProofAuthorizesOrdinaryFallback;

  Winn3StartProof proof = MakeConnectedWinn3StartProof(11);
  bool session_started = true;
  Check(LinuxTunnelRunningConsideringV3(session_started, true, true, true),
        "start then readiness: v3 is live");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(proof, 11),
        "a connected start does not authorize fallback");

  session_started = false;
  proof = Winn3StartProof();
  Check(!LinuxTunnelRunningConsideringV3(session_started, true, true, false),
        "stop clears the v3 session so leftover iface/engine are not live");
  Check(!Winn3StartProofAuthorizesOrdinaryFallback(proof, 11),
        "a stopped session does not keep a fallback authorization");

  proof = ClassifyWinn3StartFailure(12, false, "route failed", 113, 44,
                                    "0123456789abcdef", "node-a");
  session_started = false;
  Check(!LinuxTunnelRunningConsideringV3(session_started, false, false, false),
        "a failed start is not live");
  Check(Winn3StartProofAuthorizesOrdinaryFallback(proof, 12, 44),
        "ordinary connectivity after start-readiness-stop may fallback");
}

void TestLinuxWinn3GrantTtlAndOrder() {
  using winsvpn::winn3host::ArmWinn3AwgXrayGrant;
  using winsvpn::winn3host::ConsumeWinn3AwgXrayGrant;
  using winsvpn::winn3host::Winn3AwgXrayGrant;
  using winsvpn::winn3host::Winn3CoverLeg;
  using winsvpn::winn3host::Winn3GrantConsumeResult;

  Winn3AwgXrayGrant grant;
  Check(ArmWinn3AwgXrayGrant(8, 2, "0123456789abcdef", "v3-node", 500, &grant),
        "ordinary identities arm a one-use grant");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kXray, 501) ==
            Winn3GrantConsumeResult::kWrongLeg,
        "Xray cannot consume before AWG");
  Check(ArmWinn3AwgXrayGrant(8, 2, "0123456789abcdef", "v3-node", 500, &grant),
        "re-arm after wrong-leg clear");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 501) ==
            Winn3GrantConsumeResult::kOk,
        "first consume is AWG");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 502) ==
            Winn3GrantConsumeResult::kWrongLeg,
        "second AWG consume is refused");
  Check(ArmWinn3AwgXrayGrant(8, 2, "0123456789abcdef", "v3-node", 500, &grant),
        "re-arm for TTL");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg,
                                 500 + 60001) ==
            Winn3GrantConsumeResult::kExpired,
        "grant expires at 60s monotonic");
  Check(ArmWinn3AwgXrayGrant(8, 2, "0123456789abcdef", "v3-node", 500, &grant),
        "re-arm for AWG then Xray success");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kAwg, 510) ==
            Winn3GrantConsumeResult::kOk,
        "AWG consume");
  Check(ConsumeWinn3AwgXrayGrant(&grant, 8, 2, "0123456789abcdef", "v3-node",
                                 "v1-cover", Winn3CoverLeg::kXray, 511) ==
            Winn3GrantConsumeResult::kOk,
        "optional Xray consume clears the grant");
}

int main() {
  TestTheServedSectionSelectsAndParses();
  TestTheServedDualAuthPairIsConsumedAndBound();
  TestTheServedDualAuthPairRefusesMismatchMissingAndStale();
  TestTheServedSectionBindsTheSelectedNode();
  TestNativeStartBindsTheIndependentPickerNode();
  TestTheServedSectionRefusesWhatWouldBeSilent();
  TestTheCarrierGateRefusesAnUnsupportedCarrier();
  TestTheCarrierDiscriminatorRefusesAnUnsupportedCarrier();
  TestSizingAgreesWithGo();
  TestSizingRefusesRatherThanDefaults();
  TestTheKeyDocumentNamesFilesAndHoldsNoKeyMaterial();
  TestTheKeyDocumentRefusesRatherThanEmitsSomethingTheEngineWouldReject();
  TestTheKeyDocumentDescriptionLeaksNoPath();
  TestTheKeyDocumentIsWrittenPrivate();
  TestTheCreateDocumentIsTheV3One();
  TestTheCreateDocumentRefusesWhatWouldLeak();
  TestTheEndpointSplitter();
  TestTheInnerPromotionProbeRefusesCollisions();
  TestTheEngineArgv();
  TestTheExclusionIsDestinationScopedRatherThanAFwmark();
  TestTheExclusionIsOnLinkWithoutANextHopOrRefused();
  TestTheBootstrapPostureIsNarrowAndPutsTheExclusionFirst();
  TestTheBootstrapPostureRefusesRatherThanWidens();
  TestAPartialBootstrapReversesTheExclusion();
  TestAFailedExclusionReversalIsItsOwnOutcome();
  TestAStrandedExclusionIsRepairedBeforeTheNextBootstrap();
  TestARouteWeDidNotWriteIsRefusedRatherThanDeleted();
  TestAHealthyBootstrapStillReportsTheExclusion();
  TestTheGuardsThisHostLeansOn();
  TestTheRenderedBootstrapIsCheckedToo();
  TestPromotionWidensOnlyOnTheEnginesProof();
  TestPromotionRefusesMidRekeyEvenWithDeliveries();
  TestPromotionRefusesResolversItCannotJustify();
  TestPromotionRefusesIPv6ThePlanCannotCarry();
  TestTheGateIsTriState();
  TestAReadyClaimBesideAGateThatMayNotCarryIsRefused();
  TestTheGateSaysNothingSecret();
  TestTheV1ShapeWouldHaveWidenedWhereV3Refuses();
  TestTeardownRemovesTheExclusionLast();
  TestTheTeardownEmitsThePromotedRouteDelsInOrder();
  TestTheStandaloneStopRunsTheTeardownAndIsIdempotent();
  TestTheResolverMechanismIsProbedNotAssumed();
  TestEveryMechanismInstallsTheResolversItWasGiven();
  TestPromotionRefusesAHostWithNoResolverMechanism();
  TestAPartialPromotionIsRolledBackAndSaysSo();
  TestARollbackThatFailsIsNamedRatherThanHidden();
  TestTheResultIsPublishedInTheStatusDocument();
  TestLinuxWinn3LivenessNeverFallsThroughToV1();
  TestLinuxWinn3ProofOutcomesAndFallbackAuthorization();
  TestLinuxWinn3CapturedOsErrorPropagatesToCover();
  TestLinuxWinn3StartReadinessStop();
  TestLinuxWinn3GrantTtlAndOrder();

  if (failures != 0) {
    std::fprintf(stderr, "\n%d check(s) failed\n", failures);
    return 1;
  }
  std::fprintf(stderr, "linux_winn3_host_test: all checks passed\n");
  return 0;
}
