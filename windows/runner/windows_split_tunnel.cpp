/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
/*
 * Windows destination-routing controller. The withdrawn per-app driver
 * implementation remains below only as non-compiled provenance while the
 * route-only implementation is kept independent of it.
 * See docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md.
 */

#include "windows_split_tunnel.h"
#include "windows_tunnel_service_protocol.h"
#include "windows_winn_engine.h"

// Self-contained instead of dependent on the caller spelling -DNOMINMAX: every
// consumer that embeds this file (the tunnel-service target compiles it with
// the define handed down by CMake, but the route-plan test TU and any other
// embedder would otherwise have windows.h's min/max macros shatter every
// std::min/std::max call below). Defined before <windows.h> is first reached.
#define NOMINMAX 1
#define PSAPI_VERSION 2
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

#if 0  // Withdrawn per-app split-driver implementation. Never shipped.
constexpr wchar_t kDriverDevice[] = L"\\\\.\\MULLVADSPLITTUNNEL";
constexpr wchar_t kDriverFilename[] = L"mullvad-split-tunnel.sys";
constexpr wchar_t kDriverService[] = L"WinsVPNSplitTunnel";
constexpr wchar_t kDriverDiagnosticsPath[] =
    L"C:\\ProgramData\\WinsVPN\\split-driver-diagnostics.json";
constexpr wchar_t kDriverDiagnosticsTempPath[] =
    L"C:\\ProgramData\\WinsVPN\\split-driver-diagnostics.tmp";
constexpr DWORD kServiceWaitMilliseconds =
    winsvpn::tunnel_service::kSplitDriverServiceWaitMilliseconds;
constexpr DWORD kDriverIoTimeoutMilliseconds =
    winsvpn::tunnel_service::kSplitDriverIoTimeoutMilliseconds;

// Driver-owned WFP sublayers. These GUIDs are part of the upstream driver's
// userspace contract and must remain identical.
const GUID kWfpProvider = {0x21e1dab8, 0xb9db, 0x43c0,
                           {0xb3, 0x43, 0xeb, 0x93, 0x65, 0xc7, 0xbd, 0xd2}};
const GUID kBaselineSublayer = {0x21e068a2, 0x2851, 0x43c5,
                                 {0x8a, 0x29, 0x7a, 0xfe, 0x3f, 0x26, 0x03, 0x84}};
const GUID kDnsSublayer = {0xe65841b6, 0x82f6, 0x4d55,
                           {0xbd, 0xe2, 0x61, 0xf8, 0x4d, 0x45, 0x08, 0xd4}};
// These priorities are part of Mullvad's WinFW integration contract. WFP
// sublayer weights are priorities, not exclusive slots: foreign sublayers may
// legitimately use the same numeric value. Moving the redirect callouts down
// to the next unused weights lets a higher hard-permit filter consume
// FWPS_RIGHT_ACTION_WRITE before the split driver can rewrite a socket's
// source address.
constexpr UINT16 kBaselineSublayerWeight = 0xffff;
constexpr UINT16 kDnsSublayerWeight = 0xfffe;
static_assert(kBaselineSublayerWeight > kDnsSublayerWeight,
              "Split baseline must outrank split DNS");

// Fwpm* functions return DWORD even though the facility-specific FWP_E_*
// constants are declared as signed HRESULT values. Normalize the expected
// statuses once so /W4 /WX comparisons stay in the API's DWORD domain.
constexpr DWORD kFwpProviderNotFoundStatus =
    static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
constexpr DWORD kFwpSublayerNotFoundStatus =
    static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND);
constexpr DWORD kFwpInUseStatus = static_cast<DWORD>(FWP_E_IN_USE);

#ifndef CTL_CODE
#define FILE_ANY_ACCESS 0x0000
#define METHOD_BUFFERED 0
#define METHOD_NEITHER 3
#define CTL_CODE(DeviceType, Function, Method, Access) \
  (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define IOCTL_INITIALIZE \
  static_cast<DWORD>(CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_DEQUEUE_EVENT \
  static_cast<DWORD>(CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_REGISTER_PROCESSES \
  static_cast<DWORD>(CTL_CODE(0x8000, 3, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_REGISTER_IP_ADDRESSES \
  static_cast<DWORD>(CTL_CODE(0x8000, 4, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_SET_CONFIGURATION \
  static_cast<DWORD>(CTL_CODE(0x8000, 6, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_CLEAR_CONFIGURATION \
  static_cast<DWORD>(CTL_CODE(0x8000, 8, METHOD_NEITHER, FILE_ANY_ACCESS))
#define IOCTL_GET_STATE \
  static_cast<DWORD>(CTL_CODE(0x8000, 9, METHOD_BUFFERED, FILE_ANY_ACCESS))
#define IOCTL_RESET \
  static_cast<DWORD>(CTL_CODE(0x8000, 11, METHOD_NEITHER, FILE_ANY_ACCESS))

enum DriverState : SIZE_T {
  kStateNone = 0,
  kStateStarted = 1,
  kStateInitialized = 2,
  kStateReady = 3,
  kStateRunning = 4,
};

struct ConfigurationEntry {
  SIZE_T image_name_offset;
  USHORT image_name_length;
};

// Input for the v1.3 driver INITIALIZE request. Supplying the WinFW-owned
// GUIDs lets multiple VPN products coexist without sharing fixed sublayers.
struct SublayerGuids {
  GUID baseline;
  GUID dns;
};
static_assert(sizeof(SublayerGuids) == sizeof(GUID) * 2,
              "Split-driver sublayer GUID framing changed");

struct ConfigurationHeader {
  SIZE_T num_entries;
  SIZE_T total_length;
};

struct IpAddressesConfig {
  IN_ADDR tunnel_ipv4;
  IN_ADDR internet_ipv4;
  IN6_ADDR tunnel_ipv6;
  IN6_ADDR internet_ipv6;
};

struct ProcessDiscoveryHeader {
  SIZE_T num_entries;
  SIZE_T total_length;
};

struct ProcessDiscoveryEntry {
  HANDLE process_id;
  HANDLE parent_process_id;
  SIZE_T image_name_offset;
  USHORT image_name_length;
};

struct ProcessInfo {
  DWORD process_id = 0;
  DWORD parent_process_id = 0;
  std::wstring device_path;
};
#endif

struct OwnedRoute {
  MIB_IPFORWARD_ROW2 row = {};
  bool physical_bypass = false;
  bool convergence_probe = false;
  bool carrier_pin = false;
};

DWORD g_prepared_internet_index = 0;
MIB_IPFORWARD_ROW2 g_prepared_internet_route = {};
bool g_prepared_internet_route_valid = false;
std::string g_prepared_tunnel_address;
std::vector<OwnedRoute> g_tunnel_routes;
std::mutex g_network_state_mutex;
DWORD g_active_tunnel_index = 0;
NET_LUID g_active_tunnel_luid = {};
HANDLE g_network_refresh_signal = nullptr;
HANDLE g_network_refresh_stop = nullptr;
HANDLE g_route_change_notification = nullptr;
HANDLE g_interface_change_notification = nullptr;
HANDLE g_address_change_notification = nullptr;
std::thread g_network_refresh_thread;
#if 0  // Withdrawn per-app split-driver implementation. Never shipped.
HANDLE g_driver = INVALID_HANDLE_VALUE;
IpAddressesConfig g_active_driver_addresses = {};
HANDLE g_driver_event_stop = nullptr;
std::thread g_driver_event_thread;
std::atomic<bool> g_driver_event_consumer_running{false};
std::atomic<bool> g_driver_event_session_started{false};
std::atomic<uint64_t> g_driver_start_events{0};
std::atomic<uint64_t> g_driver_stop_events{0};
std::atomic<uint64_t> g_driver_error_events{0};
std::atomic<uint64_t> g_driver_malformed_events{0};
std::atomic<uint64_t> g_driver_io_errors{0};

constexpr DWORD kDriverEventBufferBytes = 2048;
constexpr DWORD kDriverEventStart = 0;
constexpr DWORD kDriverEventStop = 1;
constexpr DWORD kDriverEventErrorStart = 0x80000001;
constexpr DWORD kDriverEventErrorStop = 0x80000002;
constexpr DWORD kDriverEventErrorMessage = 0x80000003;

void ResetDriverEventCounters() {
  g_driver_start_events = 0;
  g_driver_stop_events = 0;
  g_driver_error_events = 0;
  g_driver_malformed_events = 0;
  g_driver_io_errors = 0;
  DeleteFileW(kDriverDiagnosticsPath);
  DeleteFileW(kDriverDiagnosticsTempPath);
}

void WriteDriverEventDiagnostics() {
  // Persist only aggregate counters after disconnect.  Raw driver events can
  // contain process ids and executable paths and therefore never leave
  // memory.  The already-hardened ProgramData directory limits this file to
  // SYSTEM and administrators.
  std::ostringstream json;
  json << "{\"schema_version\":1,\"secret_material_redacted\":true"
       << ",\"start_events\":" << g_driver_start_events.load()
       << ",\"stop_events\":" << g_driver_stop_events.load()
       << ",\"error_events\":" << g_driver_error_events.load()
       << ",\"malformed_events\":" << g_driver_malformed_events.load()
       << ",\"io_errors\":" << g_driver_io_errors.load() << "}";
  const std::string body = json.str();
  HANDLE file = CreateFileW(kDriverDiagnosticsTempPath, GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  const bool ok = WriteFile(file, body.data(), static_cast<DWORD>(body.size()),
                            &written, nullptr) != FALSE &&
                  written == body.size() && FlushFileBuffers(file) != FALSE;
  CloseHandle(file);
  if (!ok ||
      !MoveFileExW(kDriverDiagnosticsTempPath, kDriverDiagnosticsPath,
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(kDriverDiagnosticsTempPath);
  }
}

void CountDriverEvent(const std::vector<uint8_t>& event, DWORD returned) {
  // EventHeader begins with a 32-bit id.  Do not deserialize or retain the
  // variable process/image payload: operational diagnostics need only prove
  // whether the driver classified arrivals and whether it reported an error.
  if (returned < sizeof(DWORD) || returned > event.size()) {
    ++g_driver_malformed_events;
    return;
  }
  DWORD event_id = 0;
  std::memcpy(&event_id, event.data(), sizeof(event_id));
  switch (event_id) {
    case kDriverEventStart:
      ++g_driver_start_events;
      break;
    case kDriverEventStop:
      ++g_driver_stop_events;
      break;
    case kDriverEventErrorStart:
    case kDriverEventErrorStop:
    case kDriverEventErrorMessage:
      ++g_driver_error_events;
      break;
    default:
      ++g_driver_malformed_events;
      break;
  }
}

void DriverEventConsumer() {
  HANDLE io_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (io_event == nullptr) {
    ++g_driver_io_errors;
    return;
  }
  g_driver_event_consumer_running = true;
  std::vector<uint8_t> event(kDriverEventBufferBytes, 0);
  while (WaitForSingleObject(g_driver_event_stop, 0) != WAIT_OBJECT_0) {
    ResetEvent(io_event);
    OVERLAPPED overlapped = {};
    overlapped.hEvent = io_event;
    DWORD returned = 0;
    const BOOL started = DeviceIoControl(
        g_driver, IOCTL_DEQUEUE_EVENT, nullptr, 0, event.data(),
        static_cast<DWORD>(event.size()), nullptr, &overlapped);
    if (!started && GetLastError() != ERROR_IO_PENDING) {
      ++g_driver_io_errors;
      if (WaitForSingleObject(g_driver_event_stop, 100) == WAIT_OBJECT_0) break;
      continue;
    }

    HANDLE waits[] = {io_event, g_driver_event_stop};
    const DWORD wait = WaitForMultipleObjects(_countof(waits), waits, FALSE,
                                              INFINITE);
    if (wait == WAIT_OBJECT_0 + 1) {
      CancelIoEx(g_driver, &overlapped);
      GetOverlappedResult(g_driver, &overlapped, &returned, TRUE);
      break;
    }
    if (wait != WAIT_OBJECT_0 ||
        !GetOverlappedResult(g_driver, &overlapped, &returned, FALSE)) {
      ++g_driver_io_errors;
      CancelIoEx(g_driver, &overlapped);
      GetOverlappedResult(g_driver, &overlapped, &returned, TRUE);
      if (WaitForSingleObject(g_driver_event_stop, 100) == WAIT_OBJECT_0) break;
      continue;
    }
    CountDriverEvent(event, returned);
  }
  CloseHandle(io_event);
  g_driver_event_consumer_running = false;
}

bool StartDriverEventConsumer(std::string* error) {
  if (g_driver_event_thread.joinable()) return true;
  ResetDriverEventCounters();
  g_driver_event_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (g_driver_event_stop == nullptr) {
    *error = "Unable to create the split-tunnel driver event boundary.";
    return false;
  }
  try {
    g_driver_event_thread = std::thread(DriverEventConsumer);
  } catch (...) {
    CloseHandle(g_driver_event_stop);
    g_driver_event_stop = nullptr;
    *error = "Unable to start the split-tunnel driver event consumer.";
    return false;
  }
  for (int attempt = 0; attempt < 50; ++attempt) {
    if (g_driver_event_consumer_running) {
      g_driver_event_session_started = true;
      return true;
    }
    if (!g_driver_event_thread.joinable()) break;
    Sleep(10);
  }
  SetEvent(g_driver_event_stop);
  if (g_driver_event_thread.joinable()) g_driver_event_thread.join();
  CloseHandle(g_driver_event_stop);
  g_driver_event_stop = nullptr;
  *error = "The split-tunnel driver event consumer did not start.";
  return false;
}

void StopDriverEventConsumer() {
  if (g_driver_event_stop != nullptr) SetEvent(g_driver_event_stop);
  if (g_driver_event_thread.joinable()) g_driver_event_thread.join();
  if (g_driver_event_stop != nullptr) {
    CloseHandle(g_driver_event_stop);
    g_driver_event_stop = nullptr;
  }
  g_driver_event_consumer_running = false;
}

bool DriverIoctl(HANDLE device, DWORD code, void* input, DWORD input_size,
                 void* output, DWORD output_size, DWORD* returned) {
  if (device == INVALID_HANDLE_VALUE) return false;
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (event == nullptr) return false;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = event;
  DWORD transferred = 0;
  BOOL started = DeviceIoControl(device, code, input, input_size, output,
                                 output_size, nullptr, &overlapped);
  if (!started && GetLastError() != ERROR_IO_PENDING) {
    CloseHandle(event);
    return false;
  }
  const DWORD wait = WaitForSingleObject(event, kDriverIoTimeoutMilliseconds);
  if (wait != WAIT_OBJECT_0 ||
      !GetOverlappedResult(device, &overlapped, &transferred, FALSE)) {
    CancelIoEx(device, &overlapped);
    GetOverlappedResult(device, &overlapped, &transferred, TRUE);
    CloseHandle(event);
    return false;
  }
  CloseHandle(event);
  if (returned != nullptr) *returned = transferred;
  return true;
}

std::wstring ModuleDirectory() {
  wchar_t path[MAX_PATH * 4] = {};
  const DWORD size = GetModuleFileNameW(nullptr, path, _countof(path));
  if (size == 0 || size >= _countof(path)) return L".";
  std::wstring full(path, size);
  const size_t slash = full.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"." : full.substr(0, slash);
}

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
  if (left.empty() || left.back() == L'\\' || left.back() == L'/') {
    return left + right;
  }
  return left + L"\\" + right;
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) return "";
  const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr,
                                         0, nullptr, nullptr);
  if (length <= 0) return "";
  std::string out(static_cast<size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), length, nullptr, nullptr);
  return out;
}
#endif

std::string Trim(std::string value) {
  const auto not_space = [](unsigned char c) { return !std::isspace(c); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
              value.end());
  return value;
}

std::string LowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::tolower(c));
                 });
  return value;
}

std::string SectionValue(const std::string& config,
                         const std::string& section,
                         const std::string& key) {
  std::istringstream stream(config);
  std::string line;
  bool in_section = false;
  while (std::getline(stream, line)) {
    line = Trim(line);
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    if (line.front() == '[' && line.back() == ']') {
      std::string current = line.substr(1, line.size() - 2);
      std::transform(current.begin(), current.end(), current.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      std::string expected = section;
      std::transform(expected.begin(), expected.end(), expected.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      in_section = current == expected;
      continue;
    }
    if (!in_section) continue;
    const size_t equals = line.find('=');
    if (equals == std::string::npos) continue;
    std::string current_key = Trim(line.substr(0, equals));
    std::transform(current_key.begin(), current_key.end(), current_key.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string expected_key = key;
    std::transform(expected_key.begin(), expected_key.end(),
                   expected_key.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (current_key == expected_key) return Trim(line.substr(equals + 1));
  }
  return "";
}

// The carrier-host resolution order, extracted into a unit seam so
// PrepareWindowsAppExclusions is not the only copy of the rule and a test can
// pin it. The resolved host is the address whose /32 the protected
// physical route is pinned to, so it MUST be the address the OUTER socket
// actually addresses:
//
//  1. `[Xray] Host`            -- the Xray stealth carrier's edge.
//  2. WindowsWinnCarrierHost() -- `[winn] endpoint` host. On a winn start the
//     AmneziaWG peer endpoint is about to be rewritten to the loopback seam, so
//     it is never a valid pin; the Winn gateway may also differ from the AWG
//     gateway.
//  3. `[Peer] Endpoint`        -- the plain AmneziaWG peer, unchanged.
//
// Returns the HOST portion only (brackets and port stripped), or "" when none
// of the three carriers is present.
std::string WindowsCarrierHostForConfig(const std::string& raw_config) {
  std::string host = SectionValue(raw_config, "Xray", "Host");
  // Every returned value must be a BARE host, because every consumer feeds the
  // result to GetAddrInfoW (via ResolveBestInterface), which requires a host
  // without a port component. Strip the same way the `[Peer] Endpoint` branch
  // below does: brackets for a bracketed IPv6 literal, then any trailing port.
  if (!host.empty()) {
    if (host.front() == '[') {
      const size_t end = host.find(']');
      host = end == std::string::npos ? "" : host.substr(1, end - 1);
    } else {
      const size_t colon = host.rfind(':');
      if (colon != std::string::npos) host = host.substr(0, colon);
    }
  }
  if (host.empty()) {
    host = winsvpn::winn::WindowsWinnCarrierHost(raw_config);
  }
  if (host.empty()) {
    host = SectionValue(raw_config, "Peer", "Endpoint");
    if (!host.empty() && host.front() == '[') {
      const size_t end = host.find(']');
      host = end == std::string::npos ? "" : host.substr(1, end - 1);
    } else {
      const size_t colon = host.rfind(':');
      if (colon != std::string::npos) host = host.substr(0, colon);
    }
  }
  return host;
}

#if 0  // Withdrawn per-app split-driver implementation. Never shipped.
bool IsWinsVpnSplitSublayerName(const wchar_t* name);
bool IsWinsVpnPinnedSublayerName(const GUID& key, const wchar_t* name);

bool IsWinsVpnProviderName(const wchar_t* name) {
  return name != nullptr &&
         wcscmp(name, L"Win's VPN split-tunnel provider") == 0;
}

bool EnsureProvider(HANDLE engine) {
  FWPM_PROVIDER0* existing = nullptr;
  DWORD status = FwpmProviderGetByKey0(engine, &kWfpProvider, &existing);
  if (status == ERROR_SUCCESS) {
    const bool owned = existing != nullptr &&
                       IsWinsVpnProviderName(existing->displayData.name);
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    // The Mullvad provider GUID is shared by clients of this driver. Never
    // attach Win's filters to a foreign provider that happens to reuse it.
    return owned;
  }
  if (status != kFwpProviderNotFoundStatus) return false;

  wchar_t name[] = L"Win's VPN split-tunnel provider";
  wchar_t description[] = L"Mullvad split-tunnel WFP integration for Win's VPN";
  FWPM_PROVIDER0 provider = {};
  provider.providerKey = kWfpProvider;
  provider.displayData.name = name;
  provider.displayData.description = description;
  return FwpmProviderAdd0(engine, &provider, nullptr) == ERROR_SUCCESS;
}

bool EnsureSublayer(HANDLE engine, const GUID& key, wchar_t* name,
                    UINT16 weight) {
  FWPM_SUBLAYER0* existing = nullptr;
  DWORD status = FwpmSubLayerGetByKey0(engine, &key, &existing);
  if (status == ERROR_SUCCESS) {
    const bool compatible = existing != nullptr &&
                            existing->providerKey != nullptr &&
                            IsEqualGUID(*existing->providerKey, kWfpProvider);
    const bool exact =
        compatible &&
        IsWinsVpnPinnedSublayerName(key, existing->displayData.name) &&
        existing->weight == weight;
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    return exact;
  }
  if (status != kFwpSublayerNotFoundStatus) return false;
  FWPM_SUBLAYER0 layer = {};
  layer.subLayerKey = key;
  layer.displayData.name = name;
  layer.displayData.description = name;
  layer.providerKey = const_cast<GUID*>(&kWfpProvider);
  layer.weight = weight;
  return FwpmSubLayerAdd0(engine, &layer, nullptr) == ERROR_SUCCESS;
}

bool IsWinsVpnSplitSublayerName(const wchar_t* name) {
  if (name == nullptr) return false;
  return wcscmp(name, L"WinsVPN Split Tunnel Baseline") == 0 ||
         wcscmp(name, L"WinsVPN Split Tunnel DNS") == 0 ||
         wcscmp(name, L"Win's VPN Split Tunnel Baseline") == 0 ||
         wcscmp(name, L"Win's VPN Split Tunnel DNS") == 0;
}

bool IsWinsVpnPinnedSublayerName(const GUID& key, const wchar_t* name) {
  if (name == nullptr) return false;
  if (IsEqualGUID(key, kBaselineSublayer)) {
    return wcscmp(name, L"WinsVPN Split Tunnel Baseline") == 0 ||
           wcscmp(name, L"Win's VPN Split Tunnel Baseline") == 0;
  }
  if (IsEqualGUID(key, kDnsSublayer)) {
    return wcscmp(name, L"WinsVPN Split Tunnel DNS") == 0 ||
           wcscmp(name, L"Win's VPN Split Tunnel DNS") == 0;
  }
  return false;
}

bool RemoveStaleWinsVpnSplitSublayers(HANDLE engine) {
  HANDLE enumeration = nullptr;
  if (FwpmSubLayerCreateEnumHandle0(engine, nullptr, &enumeration) !=
      ERROR_SUCCESS) {
    return false;
  }
  std::vector<GUID> stale;
  bool complete = true;
  for (;;) {
    FWPM_SUBLAYER0** entries = nullptr;
    UINT32 count = 0;
    const DWORD status =
        FwpmSubLayerEnum0(engine, enumeration, 64, &entries, &count);
    if (status != ERROR_SUCCESS) {
      complete = false;
      if (entries != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
      }
      break;
    }
    for (UINT32 i = 0; i < count; ++i) {
      const FWPM_SUBLAYER0* entry = entries[i];
      if (entry == nullptr || entry->providerKey == nullptr ||
          !IsEqualGUID(*entry->providerKey, kWfpProvider) ||
          IsEqualGUID(entry->subLayerKey, kBaselineSublayer) ||
          IsEqualGUID(entry->subLayerKey, kDnsSublayer) ||
          !IsWinsVpnSplitSublayerName(entry->displayData.name)) {
        continue;
      }
      stale.push_back(entry->subLayerKey);
    }
    if (entries != nullptr) {
      FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
    }
    if (count == 0) break;
  }
  FwpmSubLayerDestroyEnumHandle0(engine, enumeration);
  if (!complete) return false;

  // These names and provider identify only sublayers created by older Win's
  // VPN candidates. A sublayer that still owns filters cannot be deleted and
  // therefore fails closed instead of disturbing another active WFP client.
  for (const GUID& key : stale) {
    const DWORD status = FwpmSubLayerDeleteByKey0(engine, &key);
    if (status != ERROR_SUCCESS && status != kFwpSublayerNotFoundStatus) {
      return false;
    }
  }
  return true;
}

bool ReadOwnedPinnedSublayer(HANDLE engine, const GUID& key, bool* exists,
                             UINT16* weight) {
  *exists = false;
  *weight = 0;
  FWPM_SUBLAYER0* existing = nullptr;
  const DWORD status = FwpmSubLayerGetByKey0(engine, &key, &existing);
  if (status == kFwpSublayerNotFoundStatus) return true;
  if (status != ERROR_SUCCESS || existing == nullptr) return false;
  const bool owned =
      existing->providerKey != nullptr &&
      IsEqualGUID(*existing->providerKey, kWfpProvider) &&
      IsWinsVpnPinnedSublayerName(key, existing->displayData.name);
  if (owned) {
    *exists = true;
    *weight = existing->weight;
  }
  FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
  return owned;
}

bool EnsurePinnedSublayerPair(HANDLE engine) {
  bool baseline_exists = false;
  bool dns_exists = false;
  UINT16 baseline_actual = 0;
  UINT16 dns_actual = 0;
  if (!ReadOwnedPinnedSublayer(engine, kBaselineSublayer, &baseline_exists,
                               &baseline_actual) ||
      !ReadOwnedPinnedSublayer(engine, kDnsSublayer, &dns_exists,
                               &dns_actual)) {
    return false;
  }

  const UINT16 baseline_desired = kBaselineSublayerWeight;
  const UINT16 dns_desired = kDnsSublayerWeight;
  if (baseline_exists && dns_exists && baseline_actual == baseline_desired &&
      dns_actual == dns_desired) {
    return true;
  }

  // Repair the pair atomically. Deletion fails while active filters reference a
  // pinned sublayer; the outer transaction then restores every prior object.
  if ((baseline_exists &&
       FwpmSubLayerDeleteByKey0(engine, &kBaselineSublayer) != ERROR_SUCCESS) ||
      (dns_exists &&
       FwpmSubLayerDeleteByKey0(engine, &kDnsSublayer) != ERROR_SUCCESS)) {
    return false;
  }
  wchar_t baseline_name[] = L"WinsVPN Split Tunnel Baseline";
  wchar_t dns_name[] = L"WinsVPN Split Tunnel DNS";
  if (!EnsureSublayer(engine, kBaselineSublayer, baseline_name,
                      baseline_desired) ||
      !EnsureSublayer(engine, kDnsSublayer, dns_name, dns_desired)) {
    return false;
  }

  bool verified_baseline = false;
  bool verified_dns = false;
  UINT16 verified_baseline_weight = 0;
  UINT16 verified_dns_weight = 0;
  return ReadOwnedPinnedSublayer(engine, kBaselineSublayer, &verified_baseline,
                                 &verified_baseline_weight) &&
         ReadOwnedPinnedSublayer(engine, kDnsSublayer, &verified_dns,
                                 &verified_dns_weight) &&
         verified_baseline && verified_dns &&
         verified_baseline_weight == baseline_desired &&
         verified_dns_weight == dns_desired;
}

bool EnsureDriverSublayers(std::string* error) {
  HANDLE engine = nullptr;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine) !=
      ERROR_SUCCESS) {
    *error = "Unable to open Windows Filtering Platform.";
    return false;
  }
  const bool transaction_started =
      FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS;
  const bool staged = transaction_started && EnsureProvider(engine) &&
                      RemoveStaleWinsVpnSplitSublayers(engine) &&
                      EnsurePinnedSublayerPair(engine);
  bool ok = false;
  if (staged && FwpmTransactionCommit0(engine) == ERROR_SUCCESS) {
    ok = true;
  } else if (transaction_started) {
    FwpmTransactionAbort0(engine);
  }
  FwpmEngineClose0(engine);
  if (!ok) {
    *error = "Unable to initialize split-tunnel filtering sublayers.";
  }
  return ok;
}

bool DeleteVerifiedOwnedPinnedSublayer(HANDLE engine, const GUID& key) {
  FWPM_SUBLAYER0* existing = nullptr;
  const DWORD query = FwpmSubLayerGetByKey0(engine, &key, &existing);
  if (query == kFwpSublayerNotFoundStatus) return true;
  if (query != ERROR_SUCCESS || existing == nullptr) return false;
  const bool owned =
      existing->providerKey != nullptr &&
      IsEqualGUID(*existing->providerKey, kWfpProvider) &&
      IsWinsVpnPinnedSublayerName(key, existing->displayData.name);
  FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
  if (!owned) return false;

  // BFE refuses deletion while filters reference the sublayer. Treat every
  // such result (and every other deletion error) as an active/unknown owner and
  // fail closed; the surrounding transaction restores any earlier deletion.
  return FwpmSubLayerDeleteByKey0(engine, &key) == ERROR_SUCCESS;
}

bool RemoveWinsVpnProviderIfUnused(HANDLE engine) {
  FWPM_PROVIDER0* existing = nullptr;
  const DWORD query = FwpmProviderGetByKey0(engine, &kWfpProvider, &existing);
  if (query == kFwpProviderNotFoundStatus) return true;
  if (query != ERROR_SUCCESS || existing == nullptr) return false;
  const bool owned = IsWinsVpnProviderName(existing->displayData.name);
  FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
  if (!owned) {
    // The provider key is shared by this driver family. A foreign provider is
    // retained even after all verified Win's VPN sublayers have been removed.
    return true;
  }

  const DWORD deleted = FwpmProviderDeleteByKey0(engine, &kWfpProvider);
  // FWP_E_IN_USE proves another object still references this otherwise-owned
  // provider. Retain it without disturbing that object; all other failures are
  // unknown and therefore abort the transaction.
  return deleted == ERROR_SUCCESS || deleted == kFwpProviderNotFoundStatus ||
         deleted == kFwpInUseStatus;
}

bool CleanupOwnedWinsVpnWfpForUninstall(std::string* error) {
  HANDLE engine = nullptr;
  if (FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine) !=
      ERROR_SUCCESS) {
    *error = "Unable to open Windows Filtering Platform for uninstall cleanup.";
    return false;
  }
  const bool transaction_started =
      FwpmTransactionBegin0(engine, 0) == ERROR_SUCCESS;
  const bool staged =
      transaction_started && RemoveStaleWinsVpnSplitSublayers(engine) &&
      DeleteVerifiedOwnedPinnedSublayer(engine, kBaselineSublayer) &&
      DeleteVerifiedOwnedPinnedSublayer(engine, kDnsSublayer) &&
      RemoveWinsVpnProviderIfUnused(engine);
  bool ok = false;
  if (staged && FwpmTransactionCommit0(engine) == ERROR_SUCCESS) {
    ok = true;
  } else if (transaction_started) {
    FwpmTransactionAbort0(engine);
  }
  FwpmEngineClose0(engine);
  if (!ok) {
    *error = "Unable to remove verified inactive Win's VPN filtering objects.";
  }
  return ok;
}

bool ServiceCanOwnSharedDriver(const wchar_t* name) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scm == nullptr) return true;
  SC_HANDLE service = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const DWORD code = GetLastError();
    CloseServiceHandle(scm);
    return code != ERROR_SERVICE_DOES_NOT_EXIST;
  }
  SERVICE_STATUS_PROCESS status = {};
  DWORD bytes_needed = 0;
  const bool query_ok = QueryServiceStatusEx(
      service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status),
      sizeof(status), &bytes_needed) != FALSE;
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  // An installed but fully stopped Mullvad/Amnezia service does not own the
  // singleton device. Starting/active/pending/unknown states remain a hard
  // conflict; a later race also fails safely when this process opens it.
  return !query_ok || status.dwCurrentState != SERVICE_STOPPED;
}

bool WaitForServiceState(SC_HANDLE service, DWORD target_state,
                         DWORD timeout_milliseconds) {
  const ULONGLONG deadline = GetTickCount64() + timeout_milliseconds;
  SERVICE_STATUS_PROCESS status = {};
  DWORD bytes_needed = 0;
  while (GetTickCount64() < deadline) {
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&status),
                              sizeof(status), &bytes_needed)) {
      return false;
    }
    if (status.dwCurrentState == target_state) return true;
    if (target_state == SERVICE_RUNNING &&
        status.dwCurrentState != SERVICE_START_PENDING) {
      return false;
    }
    if (target_state == SERVICE_STOPPED &&
        status.dwCurrentState != SERVICE_STOP_PENDING) {
      return false;
    }
    Sleep(250);
  }
  return false;
}

bool ConflictingSplitTunnelActive() {
  // The kernel driver exposes one global control device. Reusing it while
  // another VPN owns it can corrupt either client's filtering state.
  return ServiceCanOwnSharedDriver(L"MullvadVPN") ||
         ServiceCanOwnSharedDriver(L"mullvad-split-tunnel") ||
         ServiceCanOwnSharedDriver(L"AmneziaVPNSplitTunnel");
}

bool EnsureDriverStarted(std::string* error) {
  if (ConflictingSplitTunnelActive()) {
    *error = "Mullvad VPN or AmneziaVPN is active on the shared split-tunnel driver device.";
    return false;
  }
  const std::wstring driver_path = JoinPath(ModuleDirectory(), kDriverFilename);
  if (GetFileAttributesW(driver_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
    *error = "The signed Windows split-tunnel driver is missing.";
    return false;
  }
  // Kernel-driver ImagePath is not a Win32 command line. SCM converts this
  // absolute DOS path to its native \??\ form. Literal quotes are retained in
  // the driver ImagePath and make I/O manager loading fail with ERROR_INVALID_NAME.
  const std::wstring service_driver_path = driver_path;
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (scm == nullptr) {
    *error = "Administrator access is required to install the split-tunnel driver.";
    return false;
  }
  SC_HANDLE service = OpenServiceW(scm, kDriverService, SERVICE_ALL_ACCESS);
  bool created_driver_service = false;
  if (service == nullptr && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
    service = CreateServiceW(
        scm, kDriverService, L"Win's VPN Split Tunnel", SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        service_driver_path.c_str(), nullptr, nullptr, nullptr, nullptr,
        nullptr);
    created_driver_service = service != nullptr;
  }
  if (service == nullptr) {
    CloseServiceHandle(scm);
    *error = "Unable to register the signed split-tunnel driver.";
    return false;
  }

  SERVICE_STATUS_PROCESS service_status = {};
  DWORD bytes_needed = 0;
  if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<BYTE*>(&service_status),
                            sizeof(service_status), &bytes_needed)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    *error = "Unable to inspect the split-tunnel driver service.";
    return false;
  }
  if (service_status.dwCurrentState == SERVICE_RUNNING) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return true;
  }
  if (service_status.dwCurrentState == SERVICE_START_PENDING) {
    const bool running =
        WaitForServiceState(service, SERVICE_RUNNING, kServiceWaitMilliseconds);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    if (!running) *error = "Timed out waiting for the split-tunnel driver.";
    return running;
  }
  if (service_status.dwCurrentState == SERVICE_STOP_PENDING &&
      !WaitForServiceState(service, SERVICE_STOPPED,
                           kServiceWaitMilliseconds)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    *error = "Timed out waiting for the previous split-tunnel driver instance to stop.";
    return false;
  } else if (service_status.dwCurrentState != SERVICE_STOPPED &&
             service_status.dwCurrentState != SERVICE_STOP_PENDING) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    *error = "The split-tunnel driver service is in an unsafe transitional state.";
    return false;
  }

  if (!created_driver_service) {
    // A failed kernel load can leave a stopped SCM record with a stale driver
    // exit state that cannot be restarted reliably after its ImagePath is
    // corrected. This is our private, stopped service, so recreate only its
    // registration; never delete an active driver instance.
    if (!DeleteService(service)) {
      CloseServiceHandle(service);
      CloseServiceHandle(scm);
      *error = "Unable to refresh the stopped split-tunnel driver registration.";
      return false;
    }
    CloseServiceHandle(service);
    service = nullptr;
    for (int attempt = 0; attempt < 40; ++attempt) {
      SC_HANDLE pending = OpenServiceW(scm, kDriverService, SERVICE_QUERY_STATUS);
      if (pending == nullptr && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
        break;
      }
      if (pending != nullptr) CloseServiceHandle(pending);
      Sleep(50);
    }
    service = CreateServiceW(
        scm, kDriverService, L"Win's VPN Split Tunnel", SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        service_driver_path.c_str(), nullptr, nullptr, nullptr, nullptr,
        nullptr);
    if (service == nullptr) {
      CloseServiceHandle(scm);
      *error = "Unable to recreate the stopped split-tunnel driver registration.";
      return false;
    }
  }

  // Never force-stop a running instance to replace its ImagePath. The
  // upstream driver must first receive IOCTL_RESET or its WFP callbacks may
  // remain registered. At this point the handle is newly created or was
  // recreated from a confirmed stopped private instance.
  if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                             SERVICE_NO_CHANGE, service_driver_path.c_str(),
                             nullptr, nullptr, nullptr, nullptr, nullptr,
                             L"Win's VPN Split Tunnel")) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    *error = "Unable to secure the split-tunnel driver service configuration.";
    return false;
  }
  if (!StartServiceW(service, 0, nullptr)) {
    const DWORD start_error = GetLastError();
    if (start_error == ERROR_SERVICE_ALREADY_RUNNING) {
      // Continue to the bounded running-state confirmation below.
    } else {
      CloseServiceHandle(service);
      CloseServiceHandle(scm);
      *error = "Unable to start the signed split-tunnel driver (Windows error " +
               std::to_string(start_error) + ").";
      return false;
    }
  }
  if (!WaitForServiceState(service, SERVICE_RUNNING,
                           kServiceWaitMilliseconds)) {
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    *error = "Timed out waiting for the signed split-tunnel driver to start.";
    return false;
  }
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return true;
}

DriverState GetDriverState() {
  if (g_driver == INVALID_HANDLE_VALUE) return kStateNone;
  SIZE_T state = 0;
  DWORD returned = 0;
  if (!DriverIoctl(g_driver, IOCTL_GET_STATE, nullptr, 0, &state,
                   static_cast<DWORD>(sizeof(state)), &returned) ||
      returned == 0) {
    return kStateNone;
  }
  return static_cast<DriverState>(state);
}

bool InitializeDriver(std::string* error) {
  for (int attempt = 0; attempt < 20; ++attempt) {
    g_driver = CreateFileW(kDriverDevice, GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                           nullptr);
    if (g_driver != INVALID_HANDLE_VALUE) break;
    Sleep(100);
  }
  if (g_driver == INVALID_HANDLE_VALUE) {
    *error = "The split-tunnel driver did not expose its control device.";
    return false;
  }
  DriverState state = GetDriverState();
  DWORD returned = 0;
  if (state >= kStateInitialized) {
    if (!DriverIoctl(g_driver, IOCTL_RESET, nullptr, 0, nullptr, 0,
                     &returned)) {
      *error = "The split-tunnel driver rejected its pre-initialization reset.";
      return false;
    }
  }
  SublayerGuids sublayer_guids = {kBaselineSublayer, kDnsSublayer};
  if (!DriverIoctl(g_driver, IOCTL_INITIALIZE, &sublayer_guids,
                   static_cast<DWORD>(sizeof(sublayer_guids)), nullptr, 0,
                   &returned)) {
    *error = "The split-tunnel driver rejected initialization.";
    return false;
  }
  return GetDriverState() >= kStateInitialized;
}

std::vector<uint8_t> ProcessSnapshotBlob() {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return {};
  PROCESSENTRY32W entry = {};
  entry.dwSize = sizeof(entry);
  std::map<DWORD, ProcessInfo> processes;
  if (Process32FirstW(snapshot, &entry)) {
    do {
      HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                   entry.th32ProcessID);
      if (process == nullptr) continue;
      wchar_t image[MAX_PATH * 4] = {};
      ProcessInfo info;
      info.process_id = entry.th32ProcessID;
      info.parent_process_id = entry.th32ParentProcessID;
      if (K32GetProcessImageFileNameW(process, image, _countof(image)) > 0) {
        info.device_path = image;
      }
      processes[info.process_id] = info;
      CloseHandle(process);
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  if (processes.empty()) return {};

  size_t string_bytes = 0;
  for (const auto& item : processes) {
    string_bytes += item.second.device_path.size() * sizeof(wchar_t);
  }
  const size_t total = sizeof(ProcessDiscoveryHeader) +
                       processes.size() * sizeof(ProcessDiscoveryEntry) +
                       string_bytes;
  std::vector<uint8_t> blob(total, 0);
  auto* header = reinterpret_cast<ProcessDiscoveryHeader*>(blob.data());
  auto* output = reinterpret_cast<ProcessDiscoveryEntry*>(header + 1);
  auto* strings = reinterpret_cast<uint8_t*>(output + processes.size());
  SIZE_T offset = 0;
  for (const auto& item : processes) {
    const ProcessInfo& process = item.second;
    output->process_id = reinterpret_cast<HANDLE>(
        static_cast<uintptr_t>(process.process_id));
    output->parent_process_id = reinterpret_cast<HANDLE>(
        static_cast<uintptr_t>(process.parent_process_id));
    if (!process.device_path.empty()) {
      const size_t bytes = process.device_path.size() * sizeof(wchar_t);
      output->image_name_offset = offset;
      output->image_name_length = static_cast<USHORT>(bytes);
      std::memcpy(strings + offset, process.device_path.data(), bytes);
      offset += bytes;
    }
    ++output;
  }
  header->num_entries = processes.size();
  header->total_length = total;
  return blob;
}
#endif

std::wstring CanonicalExecutablePath(const std::wstring& raw) {
  if (raw.empty() || raw.size() >= 32768) return L"";
  wchar_t full[32768] = {};
  const DWORD size = GetFullPathNameW(raw.c_str(), _countof(full), full, nullptr);
  if (size == 0 || size >= _countof(full)) return L"";
  const DWORD attrs = GetFileAttributesW(full);
  if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    return L"";
  }
  std::wstring result(full, size);
  std::wstring lower = result;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  if (lower.size() < 4 || lower.substr(lower.size() - 4) != L".exe") return L"";
  return result;
}

#if 0  // Withdrawn per-app split-driver implementation. Never shipped.
std::wstring ToDevicePath(const std::wstring& raw) {
  std::wstring path = CanonicalExecutablePath(raw);
  if (path.size() < 3 || path[1] != L':') return L"";
  wchar_t drive[3] = {path[0], L':', L'\0'};
  wchar_t device[4096] = {};
  if (QueryDosDeviceW(drive, device, _countof(device)) == 0) return L"";
  return std::wstring(device) + path.substr(2);
}

std::vector<uint8_t> AppConfigurationBlob(
    const std::vector<std::wstring>& paths) {
  std::vector<std::wstring> device_paths;
  size_t string_bytes = 0;
  for (const auto& path : paths) {
    std::wstring device = ToDevicePath(path);
    if (device.empty()) continue;
    if (std::find(device_paths.begin(), device_paths.end(), device) !=
        device_paths.end()) {
      continue;
    }
    string_bytes += device.size() * sizeof(wchar_t);
    device_paths.push_back(device);
  }
  if (device_paths.empty()) return {};
  const size_t total = sizeof(ConfigurationHeader) +
                       device_paths.size() * sizeof(ConfigurationEntry) +
                       string_bytes;
  std::vector<uint8_t> blob(total, 0);
  auto* header = reinterpret_cast<ConfigurationHeader*>(blob.data());
  auto* output = reinterpret_cast<ConfigurationEntry*>(header + 1);
  auto* strings = reinterpret_cast<uint8_t*>(output + device_paths.size());
  SIZE_T offset = 0;
  for (const auto& path : device_paths) {
    const size_t bytes = path.size() * sizeof(wchar_t);
    output->image_name_offset = offset;
    output->image_name_length = static_cast<USHORT>(bytes);
    std::memcpy(strings, path.data(), bytes);
    strings += bytes;
    offset += bytes;
    ++output;
  }
  header->num_entries = device_paths.size();
  header->total_length = total;
  return blob;
}
#endif

bool ResolveBestInterface(const std::string& host, DWORD* index,
                          MIB_IPFORWARD_ROW2* route,
                          SOCKADDR_INET* resolved_destination) {
  if (host.empty() || index == nullptr || route == nullptr ||
      resolved_destination == nullptr) {
    return false;
  }
  WSADATA winsock = {};
  if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return false;
  ADDRINFOW hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  std::wstring wide(host.begin(), host.end());
  ADDRINFOW* result = nullptr;
  if (GetAddrInfoW(wide.c_str(), nullptr, &hints, &result) != 0 ||
      result == nullptr) {
    WSACleanup();
    return false;
  }
  SOCKADDR_INET destination = {};
  std::memcpy(&destination, result->ai_addr,
              std::min<size_t>(result->ai_addrlen, sizeof(destination)));
  SOCKADDR_INET source = {};
  const DWORD status =
      GetBestRoute2(nullptr, 0, nullptr, &destination, 0, route, &source);
  if (status == NO_ERROR) {
    *index = route->InterfaceIndex;
    *resolved_destination = destination;
  }
  FreeAddrInfoW(result);
  WSACleanup();
  return status == NO_ERROR;
}

bool AdapterAddresses(DWORD index, IN_ADDR* ipv4, IN6_ADDR* ipv6) {
  ULONG size = 0;
  GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                      GAA_FLAG_SKIP_DNS_SERVER,
                       nullptr, nullptr, &size);
  std::vector<uint8_t> buffer(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  if (GetAdaptersAddresses(AF_UNSPEC,
                           GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                               GAA_FLAG_SKIP_DNS_SERVER,
                           nullptr, adapters, &size) != NO_ERROR) {
    return false;
  }
  std::memset(ipv6, 0, sizeof(*ipv6));
  bool found_v4 = false;
  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    if (adapter->IfIndex != index) continue;
    for (auto* address = adapter->FirstUnicastAddress; address != nullptr;
         address = address->Next) {
      if (address->Address.lpSockaddr->sa_family == AF_INET && !found_v4) {
        *ipv4 = reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr)->sin_addr;
        found_v4 = true;
      } else if (address->Address.lpSockaddr->sa_family == AF_INET6) {
        *ipv6 = reinterpret_cast<SOCKADDR_IN6*>(address->Address.lpSockaddr)->sin6_addr;
      }
    }
    return found_v4;
  }
  return false;
}

bool FindAdapterByIpv4(const std::string& address, DWORD* index) {
  IN_ADDR expected = {};
  if (InetPtonA(AF_INET, address.c_str(), &expected) != 1) return false;
  ULONG size = 0;
  GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                       nullptr, nullptr, &size);
  std::vector<uint8_t> buffer(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  if (GetAdaptersAddresses(AF_INET,
                           GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                           nullptr, adapters, &size) != NO_ERROR) {
    return false;
  }
  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    for (auto* current = adapter->FirstUnicastAddress; current != nullptr;
         current = current->Next) {
      if (current->Address.lpSockaddr->sa_family != AF_INET) continue;
      const IN_ADDR actual =
          reinterpret_cast<SOCKADDR_IN*>(current->Address.lpSockaddr)->sin_addr;
      if (actual.S_un.S_addr == expected.S_un.S_addr) {
        *index = adapter->IfIndex;
        return true;
      }
    }
  }
  return false;
}

bool ParsePrivateTunnelGatewayIpv4(const std::string& value,
                                   const std::string& tunnel_address,
                                   SOCKADDR_INET* gateway) {
  if (gateway == nullptr || value.empty() || tunnel_address.empty()) {
    return false;
  }
  IN_ADDR parsed_gateway = {};
  IN_ADDR parsed_tunnel = {};
  if (InetPtonA(AF_INET, value.c_str(), &parsed_gateway) != 1 ||
      InetPtonA(AF_INET, tunnel_address.c_str(), &parsed_tunnel) != 1 ||
      parsed_gateway.S_un.S_addr == parsed_tunnel.S_un.S_addr) {
    return false;
  }
  const uint32_t host = ntohl(parsed_gateway.S_un.S_addr);
  const uint8_t first = static_cast<uint8_t>(host >> 24);
  const uint8_t second = static_cast<uint8_t>((host >> 16) & 0xff);
  const uint8_t fourth = static_cast<uint8_t>(host & 0xff);
  const bool private_address =
      first == 10 || (first == 172 && second >= 16 && second <= 31) ||
      (first == 192 && second == 168);
  if (!private_address || fourth == 0 || fourth == 255) return false;

  *gateway = {};
  gateway->Ipv4.sin_family = AF_INET;
  gateway->Ipv4.sin_addr = parsed_gateway;
  return true;
}

bool ParseRoutePrefix(const std::string& raw, IP_ADDRESS_PREFIX* prefix) {
  if (prefix == nullptr) return false;
  const std::string value = Trim(raw);
  const size_t slash = value.rfind('/');
  if (slash == std::string::npos || slash == 0 || slash + 1 >= value.size()) {
    return false;
  }
  const std::string address = value.substr(0, slash);
  const std::string prefix_text = value.substr(slash + 1);
  char* end = nullptr;
  const unsigned long length =
      std::strtoul(prefix_text.c_str(), &end, 10);
  if (end == prefix_text.c_str() || *end != '\0') return false;

  *prefix = {};
  if (address.find(':') != std::string::npos) {
    if (length > 128) return false;
    prefix->Prefix.Ipv6.sin6_family = AF_INET6;
    if (InetPtonA(AF_INET6, address.c_str(),
                  &prefix->Prefix.Ipv6.sin6_addr) != 1) {
      return false;
    }
  } else {
    if (length > 32) return false;
    prefix->Prefix.Ipv4.sin_family = AF_INET;
    if (InetPtonA(AF_INET, address.c_str(),
                  &prefix->Prefix.Ipv4.sin_addr) != 1) {
      return false;
    }
  }
  prefix->PrefixLength = static_cast<UINT8>(length);
  return true;
}

bool Ipv4PrefixContains(const IP_ADDRESS_PREFIX& prefix,
                        const IN_ADDR& address) {
  if (prefix.Prefix.si_family != AF_INET || prefix.PrefixLength > 32) {
    return false;
  }
  const uint32_t candidate = ntohl(address.S_un.S_addr);
  const uint32_t network = ntohl(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
  const uint32_t mask = prefix.PrefixLength == 0
                            ? 0
                            : 0xffffffffU << (32 - prefix.PrefixLength);
  return (candidate & mask) == (network & mask);
}

struct Ipv4Range {
  uint64_t start;
  uint64_t end;
};

bool BuildManualRoutePlan(const std::string& allowed,
                          std::vector<IP_ADDRESS_PREFIX>* bypass_ipv4,
                          bool* install_ipv4_default,
                          bool* install_ipv6_default) {
  if (bypass_ipv4 == nullptr || install_ipv4_default == nullptr ||
      install_ipv6_default == nullptr) {
    return false;
  }
  bypass_ipv4->clear();
  *install_ipv4_default = false;
  *install_ipv6_default = false;

  std::vector<Ipv4Range> allowed_ipv4;
  bool ipv6_lower_half = false;
  bool ipv6_upper_half = false;
  std::istringstream routes(allowed);
  std::string item;
  size_t route_count = 0;
  while (std::getline(routes, item, ',')) {
    if (++route_count > 260) return false;
    IP_ADDRESS_PREFIX prefix = {};
    if (!ParseRoutePrefix(item, &prefix)) return false;
    if (prefix.Prefix.si_family == AF_INET) {
      const uint8_t length = prefix.PrefixLength;
      const uint64_t block = uint64_t{1} << (32 - length);
      const uint64_t address = ntohl(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
      const uint64_t start = address & ~(block - 1);
      allowed_ipv4.push_back({start, start + block - 1});
      continue;
    }

    // Windows per-app configs deliberately keep ::/0 out of the AWG file to
    // avoid its implicit kill-switch, but still cover both IPv6 halves.  The
    // manual route can safely collapse only complete IPv6 coverage.
    const IN6_ADDR& address = prefix.Prefix.Ipv6.sin6_addr;
    bool all_zero = true;
    for (uint8_t byte : address.u.Byte) all_zero = all_zero && byte == 0;
    if (prefix.PrefixLength == 0 && all_zero) {
      ipv6_lower_half = true;
      ipv6_upper_half = true;
    } else if (prefix.PrefixLength == 1) {
      bool trailing_zero = true;
      for (size_t i = 1; i < 16; ++i) {
        trailing_zero = trailing_zero && address.u.Byte[i] == 0;
      }
      if (!trailing_zero || (address.u.Byte[0] != 0x00 &&
                             address.u.Byte[0] != 0x80)) {
        return false;
      }
      if (address.u.Byte[0] == 0x00) ipv6_lower_half = true;
      if (address.u.Byte[0] == 0x80) ipv6_upper_half = true;
    } else {
      return false;
    }
  }
  if (allowed_ipv4.empty() || !ipv6_lower_half || !ipv6_upper_half) {
    return false;
  }

  std::sort(allowed_ipv4.begin(), allowed_ipv4.end(),
            [](const Ipv4Range& left, const Ipv4Range& right) {
              return left.start < right.start;
            });
  std::vector<Ipv4Range> merged;
  for (const Ipv4Range& range : allowed_ipv4) {
    if (merged.empty() || range.start > merged.back().end + 1) {
      merged.push_back(range);
    } else {
      merged.back().end = std::max(merged.back().end, range.end);
    }
  }

  std::vector<Ipv4Range> excluded;
  uint64_t cursor = 0;
  for (const Ipv4Range& range : merged) {
    if (cursor < range.start) excluded.push_back({cursor, range.start - 1});
    if (range.end == 0xffffffffULL) {
      cursor = 0x100000000ULL;
      break;
    }
    cursor = std::max(cursor, range.end + 1);
  }
  if (cursor <= 0xffffffffULL) excluded.push_back({cursor, 0xffffffffULL});

  for (const Ipv4Range& range : excluded) {
    uint64_t current = range.start;
    while (current <= range.end) {
      uint64_t block = current == 0 ? 0x100000000ULL
                                    : (current & (~current + 1));
      const uint64_t remaining = range.end - current + 1;
      while (block > remaining) block >>= 1;
      uint8_t prefix_length = 32;
      for (uint64_t size = block; size > 1; size >>= 1) --prefix_length;
      IP_ADDRESS_PREFIX prefix = {};
      prefix.Prefix.Ipv4.sin_family = AF_INET;
      prefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
          htonl(static_cast<uint32_t>(current));
      prefix.PrefixLength = prefix_length;
      bypass_ipv4->push_back(prefix);
      if (block == 0x100000000ULL) break;
      current += block;
    }
  }
  *install_ipv4_default = true;
  *install_ipv6_default = true;
  return bypass_ipv4->size() <= 260;
}

bool SameLuid(const NET_LUID& left, const NET_LUID& right);
bool SameNextHop(const SOCKADDR_INET& left, const SOCKADDR_INET& right);

bool SamePrefix(const IP_ADDRESS_PREFIX& left,
                const IP_ADDRESS_PREFIX& right) {
  if (left.Prefix.si_family != right.Prefix.si_family ||
      left.PrefixLength != right.PrefixLength) {
    return false;
  }
  if (left.Prefix.si_family == AF_INET) {
    return left.Prefix.Ipv4.sin_addr.S_un.S_addr ==
           right.Prefix.Ipv4.sin_addr.S_un.S_addr;
  }
  if (left.Prefix.si_family == AF_INET6) {
    return std::memcmp(&left.Prefix.Ipv6.sin6_addr,
                       &right.Prefix.Ipv6.sin6_addr,
                       sizeof(IN6_ADDR)) == 0;
  }
  return false;
}

bool CreateOwnedRoute(const IP_ADDRESS_PREFIX& prefix,
                      const NET_LUID& interface_luid,
                      const SOCKADDR_INET& next_hop,
                      bool physical_bypass,
                      bool convergence_probe,
                      bool carrier_pin,
                      std::string* error) {
  MIB_IPFORWARD_ROW2 route = {};
  InitializeIpForwardEntry(&route);
  route.DestinationPrefix = prefix;
  route.InterfaceLuid = interface_luid;
  route.NextHop = next_hop;
  route.ValidLifetime = 0xffffffff;
  route.PreferredLifetime = 0xffffffff;
  route.Metric = 0;
  route.Protocol = MIB_IPPROTO_NETMGMT;
  route.Loopback = false;
  route.AutoconfigureAddress = false;
  route.Publish = false;
  route.Immortal = false;
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    const bool already_owned =
        std::any_of(g_tunnel_routes.begin(), g_tunnel_routes.end(),
                    [&](const OwnedRoute& owned) {
                      return SamePrefix(owned.row.DestinationPrefix, prefix) &&
                             SameLuid(owned.row.InterfaceLuid,
                                      interface_luid) &&
                             SameNextHop(owned.row.NextHop, next_hop);
                    });
    if (already_owned) return true;
  }
  const DWORD status = CreateIpForwardEntry2(&route);
  if (status == ERROR_OBJECT_ALREADY_EXISTS) {
    *error =
        "Refusing to trust a matching tunnel route not owned by this session.";
    return false;
  }
  if (status != NO_ERROR) {
    *error = "Windows rejected a protected tunnel route (error " +
             std::to_string(status) + ").";
    return false;
  }
  // Track only rows created by this process. Deleting a pre-existing row on
  // disconnect would corrupt the user's physical routing configuration.
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  g_tunnel_routes.push_back(
      {route, physical_bypass, convergence_probe, carrier_pin});
  return true;
}

bool CreateOwnedRoute(const IP_ADDRESS_PREFIX& prefix,
                      const NET_LUID& interface_luid,
                      const SOCKADDR_INET& next_hop,
                      bool physical_bypass,
                      std::string* error) {
  return CreateOwnedRoute(prefix, interface_luid, next_hop, physical_bypass,
                          false, false, error);
}

bool CreateOwnedCarrierRoute(const IP_ADDRESS_PREFIX& prefix,
                             const NET_LUID& interface_luid,
                             const SOCKADDR_INET& next_hop,
                             std::string* error) {
  return CreateOwnedRoute(prefix, interface_luid, next_hop, true, false, true,
                          error);
}

bool CreateOwnedRoute(const IP_ADDRESS_PREFIX& prefix,
                      const NET_LUID& interface_luid,
                      const SOCKADDR_INET& next_hop,
                      std::string* error) {
  return CreateOwnedRoute(prefix, interface_luid, next_hop, false, false,
                          false, error);
}

bool SameLuid(const NET_LUID& left, const NET_LUID& right) {
  return left.Value == right.Value;
}

bool SameNextHop(const SOCKADDR_INET& left, const SOCKADDR_INET& right) {
  if (left.si_family != right.si_family) return false;
  if (left.si_family == AF_INET) {
    return left.Ipv4.sin_addr.S_un.S_addr ==
           right.Ipv4.sin_addr.S_un.S_addr;
  }
  if (left.si_family == AF_INET6) {
    return std::memcmp(&left.Ipv6.sin6_addr, &right.Ipv6.sin6_addr,
                       sizeof(IN6_ADDR)) == 0 &&
           left.Ipv6.sin6_scope_id == right.Ipv6.sin6_scope_id;
  }
  return false;
}

bool RouteHasUsableGateway(const MIB_IPFORWARD_ROW2& route,
                           ADDRESS_FAMILY family) {
  if (family == AF_INET) {
    return route.NextHop.Ipv4.sin_family == AF_INET &&
           route.NextHop.Ipv4.sin_addr.S_un.S_addr != 0;
  }
  if (family == AF_INET6) {
    return route.NextHop.Ipv6.sin6_family == AF_INET6 &&
           !IN6_IS_ADDR_UNSPECIFIED(&route.NextHop.Ipv6.sin6_addr);
  }
  return false;
}

bool LooksLikeTunnelInterface(const MIB_IF_ROW2& interface_row,
                              const NET_LUID& active_tunnel_luid) {
  if (SameLuid(interface_row.InterfaceLuid, active_tunnel_luid) ||
      interface_row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
      interface_row.Type == IF_TYPE_TUNNEL) {
    return true;
  }
  std::wstring description(interface_row.Description);
  std::transform(description.begin(), description.end(), description.begin(),
                 [](wchar_t value) {
                   return static_cast<wchar_t>(std::towlower(value));
                 });
  for (const wchar_t* marker : {L"amnezia", L"wireguard", L"wintun",
                                L" tunnel", L"tap-windows"}) {
    if (description.find(marker) != std::wstring::npos) return true;
  }
  return false;
}

bool FindBestPhysicalDefaultRoute(ADDRESS_FAMILY family,
                                  const NET_LUID& active_tunnel_luid,
                                  MIB_IPFORWARD_ROW2* best_route) {
  if (best_route == nullptr || (family != AF_INET && family != AF_INET6)) {
    return false;
  }
  PMIB_IPFORWARD_TABLE2 table = nullptr;
  if (GetIpForwardTable2(family, &table) != NO_ERROR || table == nullptr) {
    return false;
  }

  bool found = false;
  uint64_t best_metric = ~uint64_t{0};
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IPFORWARD_ROW2& route = table->Table[i];
    if (route.DestinationPrefix.PrefixLength != 0 || route.Loopback ||
        !RouteHasUsableGateway(route, family)) {
      continue;
    }

    MIB_IF_ROW2 interface_row = {};
    interface_row.InterfaceLuid = route.InterfaceLuid;
    interface_row.InterfaceIndex = route.InterfaceIndex;
    if (GetIfEntry2(&interface_row) != NO_ERROR ||
        interface_row.OperStatus != IfOperStatusUp ||
        LooksLikeTunnelInterface(interface_row, active_tunnel_luid)) {
      continue;
    }

    MIB_IPINTERFACE_ROW ip_interface = {};
    InitializeIpInterfaceEntry(&ip_interface);
    ip_interface.Family = family;
    ip_interface.InterfaceLuid = route.InterfaceLuid;
    ip_interface.InterfaceIndex = route.InterfaceIndex;
    if (GetIpInterfaceEntry(&ip_interface) != NO_ERROR) continue;

    const uint64_t effective_metric =
        static_cast<uint64_t>(route.Metric) + ip_interface.Metric;
    if (!found || effective_metric < best_metric) {
      *best_route = route;
      if (best_route->InterfaceIndex == 0) {
        best_route->InterfaceIndex = interface_row.InterfaceIndex;
      }
      best_metric = effective_metric;
      found = true;
    }
  }
  FreeMibTable(table);
  return found;
}

bool AdapterAddressForFamily(DWORD index, ADDRESS_FAMILY family, void* output) {
  if (index == 0 || output == nullptr ||
      (family != AF_INET && family != AF_INET6)) {
    return false;
  }
  ULONG size = 0;
  GetAdaptersAddresses(family,
                       GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                           GAA_FLAG_SKIP_DNS_SERVER,
                       nullptr, nullptr, &size);
  if (size == 0) return false;
  std::vector<uint8_t> buffer(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  if (GetAdaptersAddresses(family,
                           GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                               GAA_FLAG_SKIP_DNS_SERVER,
                           nullptr, adapters, &size) != NO_ERROR) {
    return false;
  }
  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    if (adapter->IfIndex != index && adapter->Ipv6IfIndex != index) continue;
    for (auto* address = adapter->FirstUnicastAddress; address != nullptr;
         address = address->Next) {
      if (address->Address.lpSockaddr->sa_family != family) continue;
      if (family == AF_INET) {
        const IN_ADDR value =
            reinterpret_cast<SOCKADDR_IN*>(address->Address.lpSockaddr)->sin_addr;
        const uint32_t host = ntohl(value.S_un.S_addr);
        if (host == 0 || (host >> 24) == 127 || (host >> 16) == 0xa9fe) {
          continue;
        }
        *static_cast<IN_ADDR*>(output) = value;
        return true;
      }
      const IN6_ADDR value =
          reinterpret_cast<SOCKADDR_IN6*>(address->Address.lpSockaddr)->sin6_addr;
      if (IN6_IS_ADDR_UNSPECIFIED(&value) || IN6_IS_ADDR_LOOPBACK(&value) ||
          IN6_IS_ADDR_LINKLOCAL(&value) || IN6_IS_ADDR_MULTICAST(&value)) {
        continue;
      }
      *static_cast<IN6_ADDR*>(output) = value;
      return true;
    }
  }
  return false;
}

bool RefreshOwnedPhysicalBypassRoutes(
    const MIB_IPFORWARD_ROW2& physical_default) {
  struct Replacement {
    size_t index = 0;
    MIB_IPFORWARD_ROW2 candidate = {};
    bool candidate_owned = false;
  };
  std::vector<Replacement> replacements;
  std::vector<MIB_IPFORWARD_ROW2> newly_created;

  for (size_t i = 0; i < g_tunnel_routes.size(); ++i) {
    const OwnedRoute& owned = g_tunnel_routes[i];
    if (!owned.physical_bypass ||
        (SameLuid(owned.row.InterfaceLuid, physical_default.InterfaceLuid) &&
         SameNextHop(owned.row.NextHop, physical_default.NextHop))) {
      continue;
    }
    MIB_IPFORWARD_ROW2 candidate = owned.row;
    candidate.InterfaceLuid = physical_default.InterfaceLuid;
    candidate.InterfaceIndex = physical_default.InterfaceIndex;
    candidate.NextHop = physical_default.NextHop;
    const DWORD status = CreateIpForwardEntry2(&candidate);
    if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
      for (auto route = newly_created.rbegin(); route != newly_created.rend();
           ++route) {
        DeleteIpForwardEntry2(&*route);
      }
      return false;
    }
    const bool candidate_owned = status == NO_ERROR;
    if (candidate_owned) newly_created.push_back(candidate);
    replacements.push_back({i, candidate, candidate_owned});
  }
  if (replacements.empty()) return true;

  bool deleted_all_old_rows = true;
  std::vector<OwnedRoute> refreshed;
  refreshed.reserve(g_tunnel_routes.size() + newly_created.size());
  for (size_t i = 0; i < g_tunnel_routes.size(); ++i) {
    const auto replacement =
        std::find_if(replacements.begin(), replacements.end(),
                     [i](const Replacement& item) { return item.index == i; });
    if (replacement == replacements.end()) {
      refreshed.push_back(g_tunnel_routes[i]);
      continue;
    }
    const DWORD deleted = DeleteIpForwardEntry2(&g_tunnel_routes[i].row);
    if (deleted != NO_ERROR && deleted != ERROR_NOT_FOUND &&
        deleted != ERROR_FILE_NOT_FOUND) {
      refreshed.push_back(g_tunnel_routes[i]);
      deleted_all_old_rows = false;
    }
    if (replacement->candidate_owned) {
      refreshed.push_back({replacement->candidate, true});
    }
  }
  g_tunnel_routes = std::move(refreshed);
  return deleted_all_old_rows;
}

bool RefreshPhysicalNetworkState() {
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  if (g_active_tunnel_index == 0) {
    return false;
  }
  IN_ADDR tunnel_ipv4 = {};
  IN6_ADDR tunnel_ipv6 = {};
  if (!AdapterAddresses(g_active_tunnel_index, &tunnel_ipv4, &tunnel_ipv6)) {
    return false;
  }

  MIB_IPFORWARD_ROW2 physical_ipv4 = {};
  const bool has_ipv4_route =
      FindBestPhysicalDefaultRoute(AF_INET, g_active_tunnel_luid,
                                   &physical_ipv4);
  IN_ADDR physical_ipv4_address = {};
  const bool has_ipv4_address =
      has_ipv4_route &&
      AdapterAddressForFamily(physical_ipv4.InterfaceIndex, AF_INET,
                              &physical_ipv4_address);
  // Destination-based split tunneling owns only explicit physical bypass
  // routes. If the physical path disappears, retain the existing fail-closed
  // route state instead of inventing process-based behavior.
  return has_ipv4_address && RefreshOwnedPhysicalBypassRoutes(physical_ipv4);
}

void CALLBACK RouteChangeCallback(void* context, PMIB_IPFORWARD_ROW2,
                                  MIB_NOTIFICATION_TYPE) {
  SetEvent(static_cast<HANDLE>(context));
}

void CALLBACK InterfaceChangeCallback(void* context, PMIB_IPINTERFACE_ROW,
                                      MIB_NOTIFICATION_TYPE) {
  SetEvent(static_cast<HANDLE>(context));
}

void CALLBACK AddressChangeCallback(void* context,
                                    PMIB_UNICASTIPADDRESS_ROW,
                                    MIB_NOTIFICATION_TYPE) {
  SetEvent(static_cast<HANDLE>(context));
}

void PhysicalNetworkRefreshWorker() {
  HANDLE waits[] = {g_network_refresh_stop, g_network_refresh_signal};
  while (true) {
    const DWORD wait = WaitForMultipleObjects(_countof(waits), waits, FALSE,
                                              INFINITE);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) return;
    if (wait != WAIT_OBJECT_0 + 1) continue;

    // Coalesce route, interface, and address bursts. Callbacks only signal the
    // event; all IP Helper queries and route mutation remain serialized on
    // this worker.
    do {
      ResetEvent(g_network_refresh_signal);
      if (WaitForSingleObject(g_network_refresh_stop, 250) == WAIT_OBJECT_0) {
        return;
      }
    } while (WaitForSingleObject(g_network_refresh_signal, 0) ==
             WAIT_OBJECT_0);
    RefreshPhysicalNetworkState();
  }
}

void CancelNetworkNotification(HANDLE* notification) {
  if (notification == nullptr || *notification == nullptr) return;
  CancelMibChangeNotify2(*notification);
  *notification = nullptr;
}

void StopPhysicalNetworkMonitor() {
  // Cancellation guarantees that no callback can signal a handle after it is
  // closed. The worker is joined before owned routes can be reset or removed.
  CancelNetworkNotification(&g_route_change_notification);
  CancelNetworkNotification(&g_interface_change_notification);
  CancelNetworkNotification(&g_address_change_notification);
  if (g_network_refresh_stop != nullptr) SetEvent(g_network_refresh_stop);
  if (g_network_refresh_thread.joinable()) g_network_refresh_thread.join();
  if (g_network_refresh_signal != nullptr) {
    CloseHandle(g_network_refresh_signal);
    g_network_refresh_signal = nullptr;
  }
  if (g_network_refresh_stop != nullptr) {
    CloseHandle(g_network_refresh_stop);
    g_network_refresh_stop = nullptr;
  }
}

bool StartPhysicalNetworkMonitor(std::string* error) {
  StopPhysicalNetworkMonitor();
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    const bool route_only_ready = std::any_of(
        g_tunnel_routes.begin(), g_tunnel_routes.end(),
        [](const OwnedRoute& route) { return route.physical_bypass; });
    if (g_active_tunnel_index == 0 || !route_only_ready) {
      *error =
          "The physical network monitor lacks an active tunnel bypass path.";
      return false;
    }
  }

  g_network_refresh_signal = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  g_network_refresh_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (g_network_refresh_signal == nullptr || g_network_refresh_stop == nullptr) {
    *error = "Unable to create the physical network monitor events.";
    StopPhysicalNetworkMonitor();
    return false;
  }
  DWORD status = NotifyRouteChange2(AF_UNSPEC, RouteChangeCallback,
                                    g_network_refresh_signal, FALSE,
                                    &g_route_change_notification);
  if (status == NO_ERROR) {
    status = NotifyIpInterfaceChange(AF_UNSPEC, InterfaceChangeCallback,
                                     g_network_refresh_signal, FALSE,
                                     &g_interface_change_notification);
  }
  if (status == NO_ERROR) {
    status = NotifyUnicastIpAddressChange(
        AF_UNSPEC, AddressChangeCallback, g_network_refresh_signal, FALSE,
        &g_address_change_notification);
  }
  if (status != NO_ERROR) {
    *error = "Windows rejected physical network change monitoring (error " +
             std::to_string(status) + ").";
    StopPhysicalNetworkMonitor();
    return false;
  }
  try {
    g_network_refresh_thread = std::thread(PhysicalNetworkRefreshWorker);
  } catch (...) {
    *error = "Unable to start the physical network refresh worker.";
    StopPhysicalNetworkMonitor();
    return false;
  }
  SetEvent(g_network_refresh_signal);
  return true;
}

std::wstring RegistryString(HKEY key, const wchar_t* name) {
  DWORD type = 0;
  DWORD size = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || size < sizeof(wchar_t)) {
    return L"";
  }
  std::vector<wchar_t> value(size / sizeof(wchar_t) + 1, L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type,
                       reinterpret_cast<BYTE*>(value.data()), &size) !=
      ERROR_SUCCESS) {
    return L"";
  }
  if (type == REG_EXPAND_SZ) {
    wchar_t expanded[32768] = {};
    if (ExpandEnvironmentStringsW(value.data(), expanded, _countof(expanded)) > 0) {
      return expanded;
    }
  }
  return value.data();
}

std::wstring ExecutableFromDisplayIcon(std::wstring value) {
  value.erase(std::remove(value.begin(), value.end(), L'"'), value.end());
  const size_t comma = value.rfind(L',');
  if (comma != std::wstring::npos) value = value.substr(0, comma);
  while (!value.empty() && iswspace(value.back())) value.pop_back();
  return CanonicalExecutablePath(value);
}

void ReadInstalledAppsRoot(HKEY root, REGSAM view,
                           std::map<std::wstring, WindowsInstalledApp>* apps) {
  HKEY uninstall = nullptr;
  if (RegOpenKeyExW(root,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    0, KEY_READ | view, &uninstall) != ERROR_SUCCESS) {
    return;
  }
  DWORD index = 0;
  wchar_t name[512] = {};
  DWORD name_size = _countof(name);
  while (RegEnumKeyExW(uninstall, index++, name, &name_size, nullptr, nullptr,
                       nullptr, nullptr) == ERROR_SUCCESS) {
    HKEY app_key = nullptr;
    if (RegOpenKeyExW(uninstall, name, 0, KEY_READ | view, &app_key) ==
        ERROR_SUCCESS) {
      const std::wstring display_name = RegistryString(app_key, L"DisplayName");
      const std::wstring path =
          ExecutableFromDisplayIcon(RegistryString(app_key, L"DisplayIcon"));
      if (!display_name.empty() && !path.empty()) {
        std::wstring key = path;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](wchar_t c) {
                         return static_cast<wchar_t>(std::towlower(c));
                       });
        (*apps)[key] = {display_name, path};
      }
      RegCloseKey(app_key);
    }
    name_size = _countof(name);
  }
  RegCloseKey(uninstall);
}

}  // namespace

std::vector<WindowsInstalledApp> ListWindowsInstalledApps() {
  std::map<std::wstring, WindowsInstalledApp> apps;
  ReadInstalledAppsRoot(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, &apps);
  ReadInstalledAppsRoot(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, &apps);
  ReadInstalledAppsRoot(HKEY_CURRENT_USER, KEY_WOW64_64KEY, &apps);
  ReadInstalledAppsRoot(HKEY_CURRENT_USER, KEY_WOW64_32KEY, &apps);
  std::vector<WindowsInstalledApp> result;
  for (const auto& app : apps) result.push_back(app.second);
  std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
    return _wcsicmp(left.name.c_str(), right.name.c_str()) < 0;
  });
  return result;
}

void RemoveWindowsTunnelRoutes() {
  StopPhysicalNetworkMonitor();
  RemoveWindowsTunnelConvergenceProbeRoute(nullptr);
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  for (size_t remaining = g_tunnel_routes.size(); remaining > 0; --remaining) {
    const size_t index = remaining - 1;
    if (g_tunnel_routes[index].convergence_probe) {
      continue;
    }
    const DWORD deleted =
        DeleteIpForwardEntry2(&g_tunnel_routes[index].row);
    if (deleted == NO_ERROR || deleted == ERROR_NOT_FOUND ||
        deleted == ERROR_FILE_NOT_FOUND) {
      g_tunnel_routes.erase(g_tunnel_routes.begin() + index);
    }
  }
}

bool WindowsTunnelRouteLedgerEmpty() {
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  return g_tunnel_routes.empty();
}

std::vector<IP_ADDRESS_PREFIX> WindowsPhysicalPermitPrefixes() {
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  std::vector<IP_ADDRESS_PREFIX> out;
  for (const OwnedRoute& route : g_tunnel_routes) {
    if (route.carrier_pin || route.physical_bypass) {
      out.push_back(route.row.DestinationPrefix);
    }
  }
  return out;
}

bool RemoveWindowsTunnelConvergenceProbeRoute(std::string* error) {
  std::lock_guard<std::mutex> lock(g_network_state_mutex);
  bool all_removed = true;
  for (auto route = g_tunnel_routes.begin(); route != g_tunnel_routes.end();) {
    if (!route->convergence_probe) {
      ++route;
      continue;
    }
    // Delete from the LIVE route table, not from the stored pre-creation row
    // shape. CreateIpForwardEntry2 can commit a different NextHop family or
    // address than it was asked for on a gatewayless Wintun row, and a delete
    // keyed on the stored shape then misses the committed row and fails
    // silently. This enumerates the committed table and deletes the row that
    // actually exists (prefix + interface + the NETMGMT protocol this
    // session creates under), and the delete result is checked: a /1 left
    // installed beside the promoted /0 would keep winning lookups for half the
    // address space for the life of the tunnel.
    bool removed_one = true;
    const ADDRESS_FAMILY families[] = {static_cast<ADDRESS_FAMILY>(AF_INET),
                                       static_cast<ADDRESS_FAMILY>(AF_INET6)};
    for (ADDRESS_FAMILY family : families) {
      PMIB_IPFORWARD_TABLE2 table = nullptr;
      if (GetIpForwardTable2(family, &table) != NO_ERROR || table == nullptr) {
        removed_one = false;
        if (error != nullptr) {
          *error =
              "Windows could not read the route table to remove a convergence "
              "probe route, so the transient /1 may still be installed.";
        }
        continue;
      }
      for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& live = table->Table[i];
        if (!SamePrefix(live.DestinationPrefix,
                        route->row.DestinationPrefix) ||
            !SameLuid(live.InterfaceLuid, route->row.InterfaceLuid) ||
            live.Protocol != MIB_IPPROTO_NETMGMT) {
          continue;
        }
        const DWORD deleted = DeleteIpForwardEntry2(&live);
        if (deleted != NO_ERROR) {
          removed_one = false;
          if (error != nullptr) {
            *error =
                "Windows refused to remove a transient convergence probe route "
                "(error " +
                std::to_string(deleted) + ").";
          }
        }
      }
      FreeMibTable(table);
    }
    if (!removed_one) {
      all_removed = false;
      ++route;
    } else {
      route = g_tunnel_routes.erase(route);
    }
  }
  return all_removed;
}

bool VerifyCommittedWindowsTunnelRoutes(const NET_LUID& tunnel_luid,
                                        std::string* error) {
  // BOUNDED COMMIT POLL, 2026-08-22 (Windows live-test lane). The /0 commit and
  // its verification raced: CreateIpForwardEntry2 returned success with the new
  // /0 already visible in the route table, while GetBestRoute2 in the same
  // instant failed with ERROR_NETWORK_UNREACHABLE (1232); measured on the live
  // host the identical lookup succeeded a few hundred milliseconds later and
  // selected the tunnel /0 (metric 5 vs the Wi-Fi metric 30). Poll each half
  // with a bounded deadline instead of reading once and refusing a route the
  // table had committed.
  constexpr ULONGLONG kCommitPollDeadlineMs = 5000;
  for (const char* address : {"1.1.1.1", "129.6.15.28"}) {
    SOCKADDR_INET destination = {};
    destination.Ipv4.sin_family = AF_INET;
    if (InetPtonA(AF_INET, address, &destination.Ipv4.sin_addr) != 1) {
      *error = "A Windows route-commit verification address is invalid.";
      return false;
    }
    bool committed = false;
    DWORD last_status = NO_ERROR;
    const ULONGLONG deadline = GetTickCount64() + kCommitPollDeadlineMs;
    for (;;) {
      MIB_IPFORWARD_ROW2 selected = {};
      SOCKADDR_INET source = {};
      last_status = GetBestRoute2(nullptr, 0, nullptr, &destination, 0,
                                  &selected, &source);
      if (last_status == NO_ERROR &&
          SameLuid(selected.InterfaceLuid, tunnel_luid) &&
          selected.DestinationPrefix.PrefixLength == 0) {
        committed = true;
        break;
      }
      if (GetTickCount64() >= deadline) break;
      Sleep(10);
    }
    if (!committed) {
      *error =
          "Windows did not commit both public IPv4 route halves to the tunnel "
          "/0 (last lookup error " +
          std::to_string(last_status) + ").";
      return false;
    }
  }

  MIB_IPFORWARD_ROW2 carrier = {};
  bool carrier_found = false;
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    const auto found =
        std::find_if(g_tunnel_routes.begin(), g_tunnel_routes.end(),
                     [](const OwnedRoute& route) { return route.carrier_pin; });
    if (found != g_tunnel_routes.end()) {
      carrier = found->row;
      carrier_found = true;
    }
  }
  if (!carrier_found || carrier.DestinationPrefix.PrefixLength != 32 ||
      carrier.DestinationPrefix.Prefix.si_family != AF_INET) {
    *error = "The exact physical carrier pin was lost before route commit.";
    return false;
  }
  SOCKADDR_INET carrier_destination = {};
  carrier_destination.Ipv4 = carrier.DestinationPrefix.Prefix.Ipv4;
  MIB_IPFORWARD_ROW2 selected_carrier = {};
  SOCKADDR_INET carrier_source = {};
  if (GetBestRoute2(nullptr, 0, nullptr, &carrier_destination, 0,
                    &selected_carrier, &carrier_source) != NO_ERROR ||
      !SameLuid(selected_carrier.InterfaceLuid, carrier.InterfaceLuid) ||
      !SameNextHop(selected_carrier.NextHop, carrier.NextHop) ||
      selected_carrier.DestinationPrefix.PrefixLength != 32) {
    *error = "The AWG/Xray carrier escaped its captured physical /32 route.";
    return false;
  }
  return true;
}

bool InstallWindowsTunnelConvergenceProbeRoute(
    const std::string& raw_config,
    std::string* probe_address,
    std::string* error) {
  if (probe_address == nullptr || error == nullptr) return false;
  probe_address->clear();

  // Every failure path below removes the half-installed probe routes, and a
  // removal failure appends to the error rather than being swallowed: a /1
  // silently left installed would outrank the routes of whatever session comes
  // next.
  const auto cleanup_probe_routes = [](std::string* route_error) {
    std::string cleanup_error;
    if (!RemoveWindowsTunnelConvergenceProbeRoute(&cleanup_error)) {
      if (route_error->empty()) {
        *route_error =
            "Windows could not remove the partial convergence probe route: " +
            cleanup_error;
      } else {
        *route_error +=
            " The partial convergence probe route also could not be removed: " +
            cleanup_error;
      }
    }
  };

  std::string tunnel_address = SectionValue(raw_config, "Interface", "Address");
  const size_t slash = tunnel_address.find('/');
  if (slash != std::string::npos) tunnel_address = tunnel_address.substr(0, slash);
  DWORD tunnel_index = 0;
  for (int attempt = 0; attempt < 50; ++attempt) {
    if (FindAdapterByIpv4(tunnel_address, &tunnel_index)) break;
    Sleep(100);
  }
  NET_LUID tunnel_luid = {};
  if (tunnel_index == 0 ||
      ConvertInterfaceIndexToLuid(tunnel_index, &tunnel_luid) != NO_ERROR) {
    *error = "The Windows tunnel interface is unavailable for convergence proof.";
    return false;
  }

  // Precommit /1s contain all IPv4 and IPv6 traffic without exposing an owned
  // /0. The outer AWG endpoint or Xray carrier remains more-specific on its
  // exact captured physical /32. These routes are removed immediately after
  // final /0 route verification or on any bounded failure.
  const std::array<std::pair<const char*, uint8_t>, 2> ipv4_halves = {{
      {"0.0.0.0", static_cast<uint8_t>(1)},
      {"128.0.0.0", static_cast<uint8_t>(1)},
  }};
  for (const auto& half : ipv4_halves) {
    IP_ADDRESS_PREFIX prefix = {};
    prefix.Prefix.Ipv4.sin_family = AF_INET;
    prefix.PrefixLength = half.second;
    SOCKADDR_INET next_hop = {};
    next_hop.si_family = AF_INET;
    if (InetPtonA(AF_INET, half.first, &prefix.Prefix.Ipv4.sin_addr) != 1 ||
        !CreateOwnedRoute(prefix, tunnel_luid, next_hop, false, true, false,
                          error)) {
      cleanup_probe_routes(error);
      return false;
    }
  }
  const std::array<std::pair<const char*, uint8_t>, 2> ipv6_halves = {{
      {"::", static_cast<uint8_t>(1)},
      {"8000::", static_cast<uint8_t>(1)},
  }};
  for (const auto& half : ipv6_halves) {
    IP_ADDRESS_PREFIX prefix = {};
    prefix.Prefix.Ipv6.sin6_family = AF_INET6;
    prefix.PrefixLength = half.second;
    SOCKADDR_INET next_hop = {};
    next_hop.si_family = AF_INET6;
    if (InetPtonA(AF_INET6, half.first, &prefix.Prefix.Ipv6.sin6_addr) != 1 ||
        !CreateOwnedRoute(prefix, tunnel_luid, next_hop, false, true, false,
                          error)) {
      cleanup_probe_routes(error);
      return false;
    }
  }

  // Quad9 is deliberately numeric: convergence must not depend on pre-tunnel
  // DNS and this address is covered by the lower precommit IPv4 half.
  constexpr char kConvergenceProbeAddress[] = "9.9.9.9";
  IN_ADDR parsed_probe = {};
  if (InetPtonA(AF_INET, kConvergenceProbeAddress, &parsed_probe) != 1) {
    *error = "The Windows convergence probe address is invalid.";
    cleanup_probe_routes(error);
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    g_active_tunnel_index = tunnel_index;
    g_active_tunnel_luid = tunnel_luid;
  }
  *probe_address = kConvergenceProbeAddress;
  return true;
}

bool InstallWindowsTunnelRoutes(const std::string& raw_config,
                                std::string* error) {
  if (error == nullptr) return false;
  // The physical carrier and narrow convergence route are intentionally kept
  // pinned while the proven session is promoted. Start always clears stale
  // owned state before preparation, and every failure path performs full
  // fail-closed cleanup.

  std::string tunnel_address = SectionValue(raw_config, "Interface", "Address");
  const size_t slash = tunnel_address.find('/');
  if (slash != std::string::npos) tunnel_address = tunnel_address.substr(0, slash);
  const std::string allowed = SectionValue(raw_config, "Peer", "AllowedIPs");
  if (tunnel_address.empty() || allowed.empty()) {
    *error = "Manual Windows tunnel routes are missing required configuration.";
    return false;
  }

  DWORD tunnel_index = 0;
  const ULONGLONG adapter_deadline = GetTickCount64() + 5000;
  unsigned attempt = 0;
  for (;;) {
    if (FindAdapterByIpv4(tunnel_address, &tunnel_index)) break;
    const ULONGLONG now = GetTickCount64();
    if (now >= adapter_deadline) break;
    const DWORD interval =
        attempt < 10 ? 5 : (attempt < 20 ? 15 : 25);
    const ULONGLONG remaining = adapter_deadline - now;
    Sleep(static_cast<DWORD>(
        remaining < interval ? remaining : interval));
    ++attempt;
  }
  NET_LUID tunnel_luid = {};
  if (tunnel_index == 0 ||
      ConvertInterfaceIndexToLuid(tunnel_index, &tunnel_luid) != NO_ERROR) {
    *error = "The Windows tunnel interface is unavailable for route installation.";
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    g_active_tunnel_index = tunnel_index;
    g_active_tunnel_luid = tunnel_luid;
  }

  // Manual routing serves two bounded Windows paths: selected user processes
  // redirected by the split driver and the Xray carrier's pinned physical
  // /32. More-specific /1 tunnel routes still win lookup after a process is
  // rebound to the physical address, so collapse complete coverage to manual
  // /0 routes while retaining the /1s only inside the AWG peer configuration
  // (which avoids WireGuard for Windows' implicit /0 kill-switch). Any IPv4
  // gaps in AllowedIPs become more-specific physical routes, preserving the
  // pinned carrier, peer, and user destination exclusions without excluding
  // Xray's loopback UDP traffic from the tunnel process-wide.
  std::vector<IP_ADDRESS_PREFIX> bypass_ipv4;
  bool install_ipv4_default = false;
  bool install_ipv6_default = false;
  if (!g_prepared_internet_route_valid ||
      !BuildManualRoutePlan(allowed, &bypass_ipv4, &install_ipv4_default,
                            &install_ipv6_default)) {
    *error = "The Windows per-app route plan is incomplete or unsafe.";
    return false;
  }
  SOCKADDR_INET tunnel_gateway = {};
  if (install_ipv4_default &&
      !ParsePrivateTunnelGatewayIpv4(
          SectionValue(raw_config, "WinsApp", "TunnelGatewayIPv4"),
          tunnel_address, &tunnel_gateway)) {
    *error = "The Windows per-app tunnel gateway is missing or invalid.";
    RemoveWindowsTunnelRoutes();
    return false;
  }
  // StartWindowsAppExclusions consumes the prepared interface index and
  // tunnel address when it engages the driver, but route installation still
  // needs the physical LUID and gateway captured before any VPN route change.
  // Consume that remaining snapshot exactly once here.
  MIB_IPFORWARD_ROW2 prepared_internet_route = g_prepared_internet_route;
  g_prepared_internet_index = 0;
  g_prepared_internet_route = {};
  g_prepared_internet_route_valid = false;
  g_prepared_tunnel_address.clear();

  for (const IP_ADDRESS_PREFIX& prefix : bypass_ipv4) {
    SOCKADDR_INET destination = {};
    destination.Ipv4 = prefix.Prefix.Ipv4;
    // 0.0.0.0 is not a useful route-query destination. A /0 physical bypass
    // cannot occur for a valid generated config, but using .1 keeps the
    // lookup well-defined before the explicit safety check below.
    if (destination.Ipv4.sin_addr.S_un.S_addr == 0) {
      destination.Ipv4.sin_addr.S_un.S_addr = htonl(1);
    }
    MIB_IPFORWARD_ROW2 best_physical = {};
    SOCKADDR_INET best_source = {};
    const DWORD best_route_status =
        GetBestRoute2(&prepared_internet_route.InterfaceLuid, 0, nullptr,
                      &destination, 0, &best_physical, &best_source);
    if (best_route_status != NO_ERROR) {
      // The tunnel adapter and its owned /0 are already live at this point.
      // During that route transition, GetBestRoute2 can transiently reject an
      // otherwise valid physical-interface-constrained lookup.  The exact
      // physical default was captured before any tunnel mutation, so retain
      // that fail-closed snapshot rather than falling back to an unconstrained
      // lookup that could select the tunnel itself.
      if (!RouteHasUsableGateway(prepared_internet_route, AF_INET)) {
        *error = "Unable to protect a physical per-app bypass route (error " +
                 std::to_string(best_route_status) + ").";
        RemoveWindowsTunnelRoutes();
        return false;
      }
      best_physical = prepared_internet_route;
    }
    if (!CreateOwnedRoute(prefix, prepared_internet_route.InterfaceLuid,
                          best_physical.NextHop, true, error)) {
      RemoveWindowsTunnelRoutes();
      return false;
    }
  }

  if (install_ipv4_default) {
    IP_ADDRESS_PREFIX prefix = {};
    prefix.Prefix.Ipv4.sin_family = AF_INET;
    prefix.PrefixLength = 0;
    // A layer-3 tunnel route is on-link. Using the synthetic tunnel gateway as
    // NextHop makes Windows try to resolve that address through the Wintun
    // interface, so packets reach the adapter but never enter the AWG session.
    SOCKADDR_INET next_hop = {};
    next_hop.si_family = AF_INET;
    if (!CreateOwnedRoute(prefix, tunnel_luid, next_hop, error)) {
      RemoveWindowsTunnelRoutes();
      return false;
    }
  }
  if (install_ipv6_default) {
    IP_ADDRESS_PREFIX prefix = {};
    prefix.Prefix.Ipv6.sin6_family = AF_INET6;
    prefix.PrefixLength = 0;
    SOCKADDR_INET next_hop = {};
    next_hop.si_family = AF_INET6;
    if (!CreateOwnedRoute(prefix, tunnel_luid, next_hop, error)) {
      RemoveWindowsTunnelRoutes();
      return false;
    }
  }
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    if (g_tunnel_routes.empty()) return false;
  }
  {
    // Removing the probe routes is part of the commit and is NOT best-effort:
    // a /1 left beside the owned /0 would keep the more-specific selection for
    // the whole session while the ownership bookkeeping below believes it was
    // removed.
    std::string cleanup_error;
    if (!RemoveWindowsTunnelConvergenceProbeRoute(&cleanup_error)) {
      RemoveWindowsTunnelRoutes();
      *error =
          "Windows could not remove the convergence probe routes before the "
          "final route commit, so the connection was stopped rather than left "
          "with a transient /1 outranking the promoted /0: " +
          cleanup_error;
      return false;
    }
  }
  if (!VerifyCommittedWindowsTunnelRoutes(tunnel_luid, error)) {
    RemoveWindowsTunnelRoutes();
    return false;
  }
  if (!StartPhysicalNetworkMonitor(error)) {
    RemoveWindowsTunnelRoutes();
    return false;
  }
  return true;
}

bool StartWindowsAppExclusions(const std::vector<std::wstring>& executable_paths,
                               const std::string& raw_config,
                               std::string* error) {
  (void)raw_config;
  if (!executable_paths.empty()) {
    if (error != nullptr) {
      *error =
          "Windows per-app split tunneling is unsupported; only "
          "destination-based split routing is available.";
    }
    return false;
  }
  // Route-only sessions consume the carrier pin and manual destination route
  // plan prepared before the tunnel interface changes.
  return true;
}

bool PrepareWindowsAppExclusions(
    const std::vector<std::wstring>& executable_paths,
    const std::string& raw_config,
    std::string* error) {
  StopWindowsAppExclusions();
  if (!executable_paths.empty()) {
    if (error != nullptr) {
      *error =
          "Windows per-app split tunneling is unsupported; only "
          "destination-based split routing is available.";
    }
    return false;
  }
  const bool manual_routes =
      LowerAscii(SectionValue(raw_config, "Interface", "Table")) == "off";
  if (!manual_routes) {
    return true;
  }
  // The address whose /32 has to be pinned on the physical interface is the one
  // the OUTER socket actually addresses, and which socket that is depends on the
  // transport:
  //
  //  - Xray stealth: the Xray carrier host.
  //  - Winn Protocol v3: `[winn] endpoint`, NOT `[Peer] Endpoint`. On a winn/3
  //    start the AmneziaWG peer endpoint is rewritten to 127.0.0.1:<seam>, so
  //    deriving the pin from the peer would pin the loopback address and leave
  //    the engine's real outer socket to be captured by the tunnel's own
  //    default route -- the tunnel would then dead-loop. The Winn gateway may
  //    also legitimately differ from the AmneziaWG gateway. The Apple lane
  //    found this exact hole in its own transport-exclusion route and closed it
  //    the same way.
  //  - Plain AmneziaWG: the peer endpoint, unchanged.
  //
  // Winn and Xray are mutually exclusive outer transports and are refused
  // together both in Dart and in InstallPrivilegedTunnel, so the order between
  // the first two branches cannot decide anything in practice. The order itself
  // lives in WindowsCarrierHostForConfig (see above) as a unit-testable seam.
  std::string remote_host = WindowsCarrierHostForConfig(raw_config);
  std::string tunnel_address = SectionValue(raw_config, "Interface", "Address");
  const size_t slash = tunnel_address.find('/');
  if (slash != std::string::npos) tunnel_address = tunnel_address.substr(0, slash);
  DWORD internet_index = 0;
  MIB_IPFORWARD_ROW2 internet_route = {};
  SOCKADDR_INET resolved_destination = {};
  if (remote_host.empty() || tunnel_address.empty() ||
      !ResolveBestInterface(remote_host, &internet_index, &internet_route,
                            &resolved_destination)) {
    *error = "Unable to resolve the protected physical carrier route.";
    return false;
  }
  std::vector<IP_ADDRESS_PREFIX> bypass_ipv4;
  bool install_ipv4_default = false;
  bool install_ipv6_default = false;
  const std::string allowed = SectionValue(raw_config, "Peer", "AllowedIPs");
  const bool route_plan_valid =
      resolved_destination.si_family == AF_INET &&
      BuildManualRoutePlan(allowed, &bypass_ipv4, &install_ipv4_default,
                           &install_ipv6_default) &&
      install_ipv4_default && install_ipv6_default;
  if (route_plan_valid &&
      !std::any_of(bypass_ipv4.begin(), bypass_ipv4.end(),
                   [&](const IP_ADDRESS_PREFIX& prefix) {
                     return Ipv4PrefixContains(
                         prefix, resolved_destination.Ipv4.sin_addr);
                   })) {
    // `awg setconf` owns only peer selection; it never protects the outer UDP
    // socket from the operating-system default route. Resolve the current
    // direct-AWG endpoint or Xray carrier before route mutation and add an
    // owned physical host route. This is required even when the endpoint is a
    // hostname and therefore cannot be safely hardcoded into Dart AllowedIPs.
    IP_ADDRESS_PREFIX endpoint_bypass = {};
    endpoint_bypass.Prefix.Ipv4 = resolved_destination.Ipv4;
    endpoint_bypass.PrefixLength = 32;
    bypass_ipv4.push_back(endpoint_bypass);
  }
  const bool destination_bypassed =
      route_plan_valid &&
      std::any_of(bypass_ipv4.begin(), bypass_ipv4.end(),
                  [&](const IP_ADDRESS_PREFIX& prefix) {
                    return Ipv4PrefixContains(
                        prefix, resolved_destination.Ipv4.sin_addr);
                  });
  if (!destination_bypassed) {
    *error =
        "The physical carrier address is not excluded from the tunnel routes.";
    return false;
  }
  const auto pin_physical_carrier = [&]() {
    IP_ADDRESS_PREFIX carrier = {};
    carrier.Prefix.Ipv4 = resolved_destination.Ipv4;
    carrier.PrefixLength = 32;
    return CreateOwnedCarrierRoute(carrier, internet_route.InterfaceLuid,
                                   internet_route.NextHop, error);
  };
  g_prepared_internet_index = internet_index;
  g_prepared_internet_route = internet_route;
  g_prepared_internet_route_valid = true;
  g_prepared_tunnel_address = tunnel_address;
  if (!pin_physical_carrier()) {
    StopWindowsAppExclusions();
    RemoveWindowsTunnelRoutes();
    return false;
  }
  return true;
}

void StopWindowsAppExclusions() {
  StopPhysicalNetworkMonitor();
  g_prepared_internet_index = 0;
  g_prepared_internet_route = {};
  g_prepared_internet_route_valid = false;
  g_prepared_tunnel_address.clear();
  {
    std::lock_guard<std::mutex> lock(g_network_state_mutex);
    g_active_tunnel_index = 0;
    g_active_tunnel_luid = {};
  }
}

WindowsSplitTunnelDiagnostics GetWindowsSplitTunnelDiagnostics() {
  return {};
}

bool CleanupWindowsSplitTunnelForUninstall(std::string* error) {
  if (error == nullptr) return false;
  error->clear();
  // Current releases never install or own a per-app split driver. Destination
  // routes are transient IP Helper rows removed by normal tunnel teardown.
  return true;
}
