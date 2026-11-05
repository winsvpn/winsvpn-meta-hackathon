#ifndef RUNNER_WINDOWS_SPLIT_TUNNEL_H_
#define RUNNER_WINDOWS_SPLIT_TUNNEL_H_

#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdint>
#include <string>
#include <vector>

struct WindowsInstalledApp {
  std::wstring name;
  std::wstring executable_path;
};

// Retained ABI shape for the tunnel-service status response. Current Windows
// releases do not ship a per-app split driver, so all counters remain zero.
struct WindowsSplitTunnelDiagnostics {
  bool consumer_running = false;
  uint64_t start_events = 0;
  uint64_t stop_events = 0;
  uint64_t error_events = 0;
  uint64_t malformed_events = 0;
  uint64_t io_errors = 0;
};

std::vector<WindowsInstalledApp> ListWindowsInstalledApps();

bool PrepareWindowsAppExclusions(
    const std::vector<std::wstring>& executable_paths,
    const std::string& raw_config,
    std::string* error);

bool StartWindowsAppExclusions(const std::vector<std::wstring>& executable_paths,
                               const std::string& raw_config,
                               std::string* error);
// Both functions reject non-empty executable_paths. Windows per-app split is
// explicitly unsupported; empty paths preserve destination-based carrier and
// AllowedIPs route preparation.

// Install only a narrow tunnel-bound IPv4 probe route. The physical AWG/Xray
// carrier /32 is already pinned by PrepareWindowsAppExclusions(), so this can
// generate authenticated peer traffic without exposing an owned /0 route.
bool InstallWindowsTunnelConvergenceProbeRoute(
    const std::string& raw_config,
    std::string* probe_address,
    std::string* error);
// Removes every transient convergence probe route this session owns. Failing
// to remove one is not acceptable to hide: a /1 left installed beside the
// promoted /0 outranks it for half the address space for the whole session, so
// deletions are performed against the LIVE route table (the committed row
// shape can differ from the pre-creation shape) and a failed deletion is
// reported through *error rather than swallowed.
bool RemoveWindowsTunnelConvergenceProbeRoute(std::string* error);

// Promote a convergence-proven AWG session to manual default routes on the
// dynamic tunnel interface while preserving every AllowedIPs gap as a
// more-specific physical bypass. This must only be called after a recent
// handshake and nontrivial bidirectional peer transfer have been verified.
bool InstallWindowsTunnelRoutes(const std::string& raw_config,
                                std::string* error);
// The owned physical-bypass and carrier-pin prefixes of the current session.
std::vector<IP_ADDRESS_PREFIX> WindowsPhysicalPermitPrefixes();
void RemoveWindowsTunnelRoutes();
bool WindowsTunnelRouteLedgerEmpty();

void StopWindowsAppExclusions();

WindowsSplitTunnelDiagnostics GetWindowsSplitTunnelDiagnostics();

// Compatibility hook for the uninstaller. Current releases own no per-app
// split-driver service, so this validates its output pointer and succeeds.
bool CleanupWindowsSplitTunnelForUninstall(std::string* error);

#endif  // RUNNER_WINDOWS_SPLIT_TUNNEL_H_
