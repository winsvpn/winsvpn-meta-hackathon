"""Compile the production standalone Winn v3 start with recording fakes.

StartLinuxWinn3StandaloneTunnel is extracted unmodified from
linux_tunnel_backend.cc. Every host, engine and privileged call is a fake that
records what it was asked to do, so no device, route or firewall rule changes.
The property checked: once the unprivileged start has created the persistent
winsvpn3 device, every refusal runs the unified teardown that deletes it.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "linux/runner/linux_tunnel_backend.cc"

PREFIX = r'''
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <initializer_list>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

std::string fail_at;
std::vector<std::string> events;
int stop_calls = 0;
bool g_winn_tunnel_active = false;

unsigned fake_geteuid() { return 1000; }
unsigned fake_getegid() { return 1000; }
#define geteuid fake_geteuid
#define getegid fake_getegid

uint64_t NowMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count());
}
enum class ProcOutput { kCapture, kSuppress };
struct ProcResult { std::string output; };
ProcResult RunShScript(const std::string&, const std::string&,
                       const std::vector<std::string>&, ProcOutput) {
  return {"192.0.2.10 via 10.0.0.1 dev eth0 src 10.0.0.2"};
}
std::string FindWinnDatapathExecutable() { return "/opt/engine"; }
int RunPrivilegedTunnelCommand(const std::string& action,
                               const std::string& = "",
                               const std::string& = "",
                               const std::string& = "") {
  events.push_back("helper " + action);
  return fail_at == "ks" ? 1 : 0;
}
bool RunPrivilegedWinn3Posture(const std::vector<std::string>& argv,
                               const std::string&, std::string*) {
  std::string joined;
  for (const std::string& part : argv) joined += (joined.empty() ? "" : " ") + part;
  events.push_back("posture " + joined);
  return !(fail_at == "tuntap" && argv.size() > 2 && argv[1] == "tuntap" &&
           argv[2] == "add");
}
std::string ExtractJsonCounters(const std::string&,
                                std::initializer_list<const char*>) {
  return "{}";
}

namespace winsvpn {
namespace winn3 {
struct EngineStatus {
  bool valid = false;
  int gate_state = 0;
  uint64_t rx_packets = 0;
};
struct PosturePlan {};
constexpr int kCarryingGate = 7;
}  // namespace winn3
namespace winn3host {
struct Keys { std::string outer_socket_exclusion; };
struct LinuxWinn3Params {
  std::string interface_name;
  std::string gateway_endpoint;
  std::string physical_next_hop;
  std::string physical_interface;
  int path_mtu = 0;
  std::vector<std::string> carrier_classes;
  Keys keys;
};
struct LinuxWinn3ServedKeyMaterial {};
using LinuxWinn3PrivilegedRunner = std::function<bool(
    const std::vector<std::string>&, const std::string&, std::string*)>;
enum class LinuxWinn3PostureOutcome { kNotAttempted, kApplied, kRolledBack };
struct LinuxWinn3PostureResult {
  LinuxWinn3PostureOutcome outcome = LinuxWinn3PostureOutcome::kNotAttempted;
};
enum class LinuxWinn3Promotion { kPromote, kNotYet, kRefuse };
namespace sizing {
constexpr int kDefaultPathMtu = 1500;
template <typename T>
bool PlanFloorInnerMtu(int, const T&, int* floor, std::string*) {
  *floor = 1280;
  return true;
}
}  // namespace sizing
bool ParseLinuxWinn3Section(const std::string&, LinuxWinn3Params* params,
                            LinuxWinn3ServedKeyMaterial*, std::string*) {
  params->interface_name = "winsvpn3";
  params->gateway_endpoint = "192.0.2.10:443";
  return true;
}
bool SplitLinuxWinn3Endpoint(const std::string&, std::string* host,
                             std::string* port) {
  *host = "192.0.2.10";
  *port = "443";
  return true;
}
void RememberLinuxWinn3Session(const LinuxWinn3Params&) {
  events.push_back("remember");
}
bool WriteLinuxWinn3KeyFiles(const LinuxWinn3ServedKeyMaterial&,
                             LinuxWinn3Params*, std::string*) {
  events.push_back("keys");
  return true;
}
std::string DescribeLinuxWinn3Exclusion(const LinuxWinn3Params&) {
  return "exclusion";
}
bool StopLinuxWinn3Standalone(const LinuxWinn3PrivilegedRunner&,
                              std::string*) {
  events.push_back("unified-teardown");
  ++stop_calls;
  return true;
}
int OpenLinuxWinn3Tun(const std::string&, std::string* error) {
  events.push_back("open-tun");
  if (fail_at == "open") {
    *error = "TUNSETIFF refused";
    return -1;
  }
  return 42;
}
bool StartLinuxWinn3Engine(const std::string&, int, const LinuxWinn3Params&,
                           winn3::EngineStatus*, std::string* error) {
  events.push_back("start-engine");
  if (fail_at == "engine") {
    *error = "engine exited before its CreateAck";
    return false;
  }
  return true;
}
bool RemoveLinuxWinn3KeyFiles(std::string*) { return true; }
LinuxWinn3PostureResult ApplyLinuxWinn3BootstrapPosture(
    const LinuxWinn3Params&, const winn3::EngineStatus&,
    const LinuxWinn3PrivilegedRunner&, winn3::PosturePlan*) {
  LinuxWinn3PostureResult result;
  result.outcome = LinuxWinn3PostureOutcome::kRolledBack;
  return result;
}
void SetLinuxWinn3BootstrapStatus(const LinuxWinn3PostureResult&) {}
void SetLinuxWinn3ResolverStatus(const LinuxWinn3PostureResult&) {}
std::string DescribeLinuxWinn3PostureResult(const LinuxWinn3PostureResult&) {
  return "detail";
}
bool LinuxWinn3PostureOutcomeShouldRetry(LinuxWinn3PostureOutcome) {
  return false;
}
const char* LinuxWinn3PostureOutcomeName(LinuxWinn3PostureOutcome) {
  return "rolled-back";
}
LinuxWinn3Promotion LinuxWinn3PromotionState(winn3::EngineStatus*,
                                             std::string*) {
  return LinuxWinn3Promotion::kRefuse;
}
bool LinuxWinn3EngineRunning() { return false; }
bool SendLinuxWinn3InnerPromotionProbe(const LinuxWinn3Params&) {
  return false;
}
LinuxWinn3PostureResult ApplyLinuxWinn3PromotedPosture(
    const LinuxWinn3Params&, const winn3::EngineStatus&,
    const LinuxWinn3PrivilegedRunner&, winn3::PosturePlan*) {
  return LinuxWinn3PostureResult();
}
std::string LinuxWinn3PumpStatsJson() { return "{}"; }
std::string LinuxWinn3EngineStatusJson() { return "{}"; }
}  // namespace winn3host
}  // namespace winsvpn
'''

SUFFIX = r'''
int main(int argc, char** argv) {
  if (argc != 2) return 2;
  fail_at = argv[1];
  std::string error;
  const bool started = StartLinuxWinn3StandaloneTunnel("[winn]\n", &error);
  bool created = false;
  bool torn_down_after_create = false;
  for (const std::string& event : events) {
    if (event.rfind("posture ip tuntap add dev winsvpn3", 0) == 0) created = true;
    if (created && event == "unified-teardown") torn_down_after_create = true;
  }
  std::printf("started=%d created=%d stop_calls=%d torn_down_after_create=%d\n",
              started, created, stop_calls, torn_down_after_create);
  for (const std::string& event : events) std::printf("  %s\n", event.c_str());
  return 0;
}
'''


class Winn3StartFailureTeardownTests(unittest.TestCase):
    binary = None
    work = None

    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("c++")
        if compiler is None:
            raise unittest.SkipTest("c++ is unavailable")
        text = SOURCE.read_text()
        start = text.index(
            "bool StartLinuxWinn3StandaloneTunnel(const std::string& raw_config,")
        body = text[start:text.index("\n}\n", start) + 3]
        cls.work = tempfile.TemporaryDirectory()
        work = pathlib.Path(cls.work.name)
        unit = work / "winn3_start_failure.cc"
        unit.write_text(PREFIX + body + SUFFIX)
        cls.binary = work / "winn3_start_failure"
        built = subprocess.run(
            [compiler, "-std=c++17", str(unit), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if built.returncode != 0:
            cls.work.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        if cls.work is not None:
            cls.work.cleanup()

    def run_start(self, fail_at):
        ran = subprocess.run([str(self.binary), fail_at], capture_output=True,
                             text=True, timeout=20)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        return ran.stdout

    def test_refusals_after_device_creation_delete_it(self):
        for fail_at in ("tuntap", "open", "engine", "bootstrap"):
            with self.subTest(fail_at=fail_at):
                out = self.run_start(fail_at)
                self.assertIn("started=0", out)
                self.assertIn("stop_calls=1", out, out)
                if fail_at != "tuntap":
                    self.assertIn("created=1", out, out)
                    self.assertIn("torn_down_after_create=1", out, out)

    def test_block_refusal_before_device_creation_owes_no_teardown(self):
        out = self.run_start("ks")
        self.assertIn("started=0 created=0 stop_calls=0", out, out)
        self.assertIn("helper winn3-ks-on", out)
        self.assertNotIn("posture ip tuntap", out)


if __name__ == "__main__":
    unittest.main()
