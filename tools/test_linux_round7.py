#!/usr/bin/env python3
"""Compile production Linux cleanup, bypass and redaction with local doubles.

No host service, firewall, cgroup or tunnel is changed by these regressions.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PowerInhibitionTests(unittest.TestCase):
    def test_cleanup_bypass_resolution_and_counter_redaction(self):
        source = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text()
        self.assertNotIn("StartTunnelPowerProtection", source)
        self.assertNotIn('"/usr/bin/sleep"', source)
        self.assertNotIn("PowerInhibitPidFile", source)
        self.assertNotIn("wins_vpn_power_inhibit.pid", source)
        stop = source[source.index("void StopTunnelPowerProtection()"):
                      source.index("// Atomically and safely writes")]
        bypass = source[source.index("bool EnsureLinuxBypassSlice("):
                        source.index("void StopLinuxBypassSlice()")]
        counters_start = source.index("// Copies out just the INTEGER fields")
        counters = source[source.index("std::string ExtractJsonCounters(", counters_start):
                          source.index("bool StopTunnel(", counters_start)]
        diagnostic = source[source.index('  std::fprintf(stderr,\n               "winn3 promotion refusal diagnostics:'):
                            source.index('  std::string residue;', source.index('"winn3 promotion refusal diagnostics:'))]
        prefix = r'''
#include <cassert>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>
enum class ProcOutput { kSuppress, kCapture };
struct ProcResult { int exit_status; std::string output; };
std::vector<std::vector<std::string>> calls;
std::string missing;
bool active = false;
constexpr int F_OK = 0;
int access(const char*, int) { return 0; }
std::string Which(const std::string& name) {
  return name == missing ? "" : "/custom/bin/" + name;
}
bool ProcSucceeded(const ProcResult& result) { return result.exit_status == 0; }
ProcResult RunArgv(const std::vector<std::string>& argv, ProcOutput) {
  calls.push_back(argv);
  if (argv.size() > 2 && argv[2] == "is-active") return {active ? 0 : 3, ""};
  if (argv.size() > 2 && argv[2] == "show") return {0, "/winsvpn-bypass.slice"};
  return {0, ""};
}
namespace winsvpn::winn3host {
std::string LinuxWinn3PumpStatsJson() { return "{\"tx_bytes\":12}"; }
std::string LinuxWinn3EngineStatusJson() {
  return R"({"gateway_endpoint":"PRIVATE-ENDPOINT:5555","session_id":"PRIVATE-SESSION","max_datagram":1200,"queue_depth":8,"queue_length":1,"uptime_ms":42,"tx_datagrams":2,"tx_bytes":12,"tx_rejected":0,"rx_datagrams":3,"rx_bytes":20,"rx_dropped":0,"rx_oversize":0,"rx_foreign_sender":0})";
}
}
'''
        suffix = r'''
int main() {
  missing = "systemctl";
  StopTunnelPowerProtection();
  assert(calls.empty());
  missing.clear();
  StopTunnelPowerProtection();
  StopTunnelPowerProtection();
  assert(calls.size() == 2);
  assert(calls[0] == (std::vector<std::string>{
      "/custom/bin/systemctl", "--user", "stop", "winsvpn-power-inhibit.service"}));
  std::string cgroup, error;
  calls.clear();
  missing = "sleep";
  assert(!EnsureLinuxBypassSlice(&cgroup, &error));
  assert(calls.empty());
  missing.clear();
  assert(EnsureLinuxBypassSlice(&cgroup, &error));
  bool found_sleep = false;
  for (const auto& call : calls) {
    if (call[0] == "/custom/bin/systemd-run") {
      assert(call[5] == "/custom/bin/sleep");
      assert(call[6] == "infinity");
      found_sleep = true;
    }
  }
  assert(found_sleep);
  active = true;
  calls.clear();
  assert(EnsureLinuxBypassSlice(&cgroup, &error));
  for (const auto& call : calls) assert(call[0] != "/custom/bin/systemd-run");
'''
        with tempfile.TemporaryDirectory(prefix="winsvpn-linux-round11-") as directory:
            path = Path(directory)
            (path / "test.cc").write_text(prefix + stop + bypass + counters + suffix + diagnostic + "\n}\n")
            subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-UNDEBUG",
                            str(path / "test.cc"), "-o", str(path / "test")], check=True)
            result = subprocess.run([str(path / "test")], capture_output=True, text=True,
                                    check=True, timeout=10)
            self.assertIn("tx_bytes=12", result.stderr)
            self.assertIn("rx_foreign_sender=0", result.stderr)
            self.assertNotIn("PRIVATE", result.stderr)
            self.assertNotIn("gateway_endpoint", result.stderr)
            self.assertNotIn("session_id", result.stderr)


if __name__ == "__main__":
    unittest.main()
