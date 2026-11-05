#!/usr/bin/env python3
"""Exercise real shutdown functions with GLib and simulated native resources.

Run on Linux with a C++17 compiler and gio-2.0 development files. Privileged
tunnel operations are replaced with recording fakes; no host routes change.
"""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature)
    end = source.index("\n}", start) + 2
    return source[start:end]


PREFIX = r'''
#include <gio/gio.h>
#include <glib-unix.h>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <functional>
#include <set>
#include <string>
#include <vector>
#include <unistd.h>
bool g_linux_split_tunnel_ready = false;
std::set<std::string> g_linux_excluded_apps;
bool g_winn_tunnel_active = false;
bool g_tunnel_session_committed = false;
int g_winn_last_tx_payload = 0, g_winn_last_rx_payload = 0;
int g_winn_unhealthy_streak = 0;
int stop_result = 0, stop_calls = 0, bypass_calls = 0;
int xray_calls = 0, power_calls = 0, standalone_calls = 0;
bool standalone = false, standalone_ok = true;
constexpr int kLinuxUnownedFirewallChainExit = 79;
constexpr char kLinuxUnownedFirewallChainMessage[] = "foreign firewall";
namespace winsvpn {
namespace winn {
std::string LinuxWinnEngineStatusJson() { return "{}"; }
std::string LinuxWinnSeamStatsJson() { return "{}"; }
void StopLinuxWinnEngine() {}
}
namespace winn3host {
enum class Winn3ProofOutcome { kConnected, kUnknown };
struct Winn3StartProof { Winn3ProofOutcome outcome = Winn3ProofOutcome::kUnknown; };
using LinuxWinn3PrivilegedRunner = std::function<bool(
    const std::vector<std::string>&, const std::string&, std::string*)>;
bool LinuxWinn3StandaloneSessionWasStarted() { return standalone; }
bool StopLinuxWinn3Standalone(const LinuxWinn3PrivilegedRunner&, std::string* error) {
  ++standalone_calls;
  if (!standalone_ok) { *error = "cleanup failed"; return false; }
  standalone = false;
  return true;
}
}
}
winsvpn::winn3host::Winn3StartProof g_last_winn3_proof;
std::string ExtractJsonCounters(const std::string&, const std::vector<std::string>&) { return ""; }
bool RunPrivilegedWinn3Posture(const std::vector<std::string>&, const std::string&, std::string*) { return true; }
void StopLinuxBypassSlice() { ++bypass_calls; }
void StopXrayProcess() { ++xray_calls; }
void StopTunnelPowerProtection() { ++power_calls; }
std::vector<std::string> PrivilegedRunner() { return {"test-runner"}; }
int RunPrivilegedTunnelCommand(const std::string& command) {
  assert(command == "stop"); ++stop_calls; return stop_result;
}
std::string DataDirectory() { return ""; }
GApplicationClass parent_class{};
GApplicationClass* my_application_parent_class = &parent_class;
'''

SUFFIX = r'''
void ParentShutdown(GApplication*) {}
void OnShutdown(GApplication* app, gpointer) { my_application_shutdown(app); }
gboolean EndApplication(gpointer data) {
  auto* app = G_APPLICATION(data);
  int signal = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(app), "test-signal"));
  if (signal) kill(getpid(), signal);
  else g_application_quit(app);
  return G_SOURCE_REMOVE;
}
void OnActivate(GApplication* app, gpointer) {
  g_application_hold(app);
  g_timeout_add(10, EndApplication, app);
}
void CheckFailuresAndRetry() {
  std::string error;
  assert(ShutdownLinuxTunnelBackend(&error));
  assert(stop_calls == 0 && standalone_calls == 0);
  g_tunnel_session_committed = true;
  stop_result = 1;
  assert(!ShutdownLinuxTunnelBackend(&error));
  assert(g_tunnel_session_committed && stop_calls == 1);
  stop_result = 0;
  assert(ShutdownLinuxTunnelBackend(&error));
  assert(!g_tunnel_session_committed && stop_calls == 2);
  assert(bypass_calls == 1 && xray_calls == 2 && power_calls == 2);
  assert(ShutdownLinuxTunnelBackend(&error));
  assert(stop_calls == 2);
  standalone = true;
  standalone_ok = false;
  g_tunnel_session_committed = true;
  assert(!ShutdownLinuxTunnelBackend(&error));
  assert(g_tunnel_session_committed && standalone_calls == 1);
  assert(bypass_calls == 2 && power_calls == 3 && xray_calls == 2);
  standalone_ok = true;
  assert(ShutdownLinuxTunnelBackend(&error));
  assert(!g_tunnel_session_committed && standalone_calls == 2);
  assert(bypass_calls == 3 && power_calls == 4 && xray_calls == 2);
  assert(ShutdownLinuxTunnelBackend(&error));
  assert(standalone_calls == 2 && stop_calls == 2);
  assert(bypass_calls == 3 && power_calls == 4 && xray_calls == 2);
}
int main(int argc, char** argv) {
  assert(argc == 2);
  g_log_set_always_fatal(static_cast<GLogLevelFlags>(G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL));
  parent_class.parent_class.g_type_class.g_type = G_TYPE_APPLICATION;
  parent_class.shutdown = ParentShutdown;
  CheckFailuresAndRetry();
  stop_calls = 0;
  g_tunnel_session_committed = true;
  g_autoptr(GApplication) app = g_application_new(
      "org.winsvpn.shutdown.test", G_APPLICATION_NON_UNIQUE);
  const std::string mode = argv[1];
  const int signal = mode == "int" ? SIGINT : mode == "term" ? SIGTERM :
                     mode == "hup" ? SIGHUP : mode == "quit" ? SIGQUIT : 0;
  g_object_set_data(G_OBJECT(app), "test-signal", GINT_TO_POINTER(signal));
  g_signal_connect(app, "activate", G_CALLBACK(OnActivate), nullptr);
  g_signal_connect(app, "shutdown", G_CALLBACK(OnShutdown), nullptr);
'''


class LinuxShutdownTests(unittest.TestCase):
    def test_cleanup_and_glib_exit_paths(self):
        backend = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text()
        application = (ROOT / "linux/runner/my_application.cc").read_text()
        main = (ROOT / "linux/runner/main.cc").read_text()
        start = function(backend, "bool StartTunnel(")
        self.assertEqual(start.count("return true;"), 2)
        self.assertEqual(start.count("g_tunnel_session_committed = true;\n"), 2)
        registrations = main[main.index("  const guint sighup_source ="):main.index("  return status;")]
        registrations = registrations.replace("argc, argv", "1, argv")
        source = "\n".join((
            PREFIX, function(backend, "bool StopTunnel("),
            function(backend, "bool ShutdownLinuxTunnelBackend("),
            function(application, "static void my_application_shutdown("),
            function(main, "gboolean QuitApplicationFromUnixSignal("),
            function(main, "void ForwardQuitToTermination("),
            SUFFIX, registrations,
            "assert(status == 0); assert(stop_calls == 1);",
            "assert(!g_tunnel_session_committed); return 0; }",
        ))
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "gio-2.0"], text=True))
        with tempfile.TemporaryDirectory(prefix="winsvpn-shutdown-test-") as directory:
            path = Path(directory)
            (path / "test.cc").write_text(source)
            subprocess.run(["c++", "-std=c++17", "-Wall", "-Werror", "-UNDEBUG",
                            str(path / "test.cc"), "-o", str(path / "test"), *flags], check=True)
            for mode in ("normal", "int", "term", "hup", "quit"):
                with self.subTest(mode=mode):
                    subprocess.run([str(path / "test"), mode], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
