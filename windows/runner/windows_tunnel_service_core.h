#ifndef RUNNER_WINDOWS_TUNNEL_SERVICE_CORE_H_
#define RUNNER_WINDOWS_TUNNEL_SERVICE_CORE_H_

#include <string>

bool StartPrivilegedWindowsTunnel(const std::string& config,
                                  std::string* error);
bool StopPrivilegedWindowsTunnel(std::string* error);
bool CleanupPrivilegedWindowsTunnel(std::string* error);
bool IsPrivilegedWindowsTunnelRunning();
// Returns only non-secret AWG liveness counters. The response never includes
// peer keys, preshared keys, endpoints, addresses, or obfuscation parameters.
std::string PrivilegedWindowsTunnelRuntimeStatus();
bool RunPrivilegedWindowsTunnelValidationSelfTest(std::string* error);
bool PrivilegedWindowsTunnelConfigRequiresXray(const std::string& config,
                                               bool* requires_xray,
                                               std::string* error);

#endif  // RUNNER_WINDOWS_TUNNEL_SERVICE_CORE_H_
