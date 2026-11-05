#ifndef RUNNER_WINDOWS_KILL_SWITCH_H_
#define RUNNER_WINDOWS_KILL_SWITCH_H_

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <string>
#include <vector>

// Installs, or atomically replaces, block-by-default filters at the four ALE
// authorization layers with exactly these exceptions: loopback, DHCP, the
// tunnel adapter (when tunnel_luid.Value != 0) and each permitted remote
// prefix (owned physical-bypass and carrier-pin routes, or the v3 gateway).
// The session is NOT dynamic: the filters outlive a crashed or terminated
// service on purpose. They do not survive a reboot.
bool EnableWindowsKillSwitch(const NET_LUID& tunnel_luid,
                             const std::vector<IP_ADDRESS_PREFIX>& permitted_remote,
                             std::string* error);

// Removes every filter, the sublayer and the provider. Called only from an
// explicit kStop that succeeded and from CleanupPrivilegedWindowsTunnel.
bool DisableWindowsKillSwitch(std::string* error);

// "a.b.c.d:port" or "[v6]:port" to a /32 or /128 prefix. False otherwise.
bool WindowsPermitPrefixFromEndpoint(const std::string& endpoint,
                                     IP_ADDRESS_PREFIX* out);

#endif  // RUNNER_WINDOWS_KILL_SWITCH_H_
