#if defined(WINS_TUNNEL_SERVICE_CORE)
#include "windows_tunnel_service_core.h"
#include "windows_kill_switch.h"
#else
#include "windows_tunnel_backend.h"
#include "windows_tunnel_service_client.h"
#endif
#include "windows_tunnel_service_protocol.h"
#include "windows_split_tunnel.h"
#include "windows_winn_engine.h"
// The Winn Protocol v3 supervisor. A SEPARATE header from the one above, in a
// separate namespace, compiled from a separate translation unit, deliberately:
// windows_winn_engine.h is the shipping AmneziaWG-carried winn/1 path, whose
// seam relays already-encrypted AWG outer datagrams, and winn3_supervisor.h is
// the standalone v3 path, whose seam relays RAW INNER PACKETS to the layer that
// encrypts them. Neither can call the other's code, and ParseWinn3Section
// refuses a configuration that selects both.
#include "winn3_supervisor.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <netioapi.h>
#include <powrprof.h>
#include <sddl.h>
#include <wincrypt.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <cstdlib>
#include <cstdint>
#include <thread>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#if !defined(WINS_TUNNEL_SERVICE_CORE)
#include <flutter/encodable_value.h>
#include <flutter/method_call.h>
#include <flutter/method_channel.h>
#include <flutter/method_result.h>
#include <flutter/standard_method_codec.h>
#endif

namespace {

constexpr wchar_t kTunnelName[] = L"winsvpn";
constexpr wchar_t kTunnelServiceName[] = L"AmneziaWGTunnel$winsvpn";
constexpr wchar_t kAwgEngineStopEvent[] =
    L"Global\\WinsVPN.AwgEngine.Stop.v1";

#if defined(WINS_TUNNEL_SERVICE_CORE)
// True while the ACTIVE tunnel was started as winn/3. Separate from
// WindowsWinnEngineRunning() on purpose: that answers "is an engine alive",
// this answers "was this tunnel supposed to have one", and the difference is
// what distinguishes a healthy AmneziaWG tunnel from a Winn tunnel whose engine
// has died. Written and read only under the privileged service's own single
// start/stop serialization.
std::atomic<bool> g_winn_tunnel_active{false};
// True while a STANDALONE Winn Protocol v3 tunnel is up. Deliberately a second
// flag rather than a value of the first: the two protocols have different
// adapters, different engines and different liveness questions, and one flag
// with two meanings is one flag that will be read with the wrong meaning.
std::atomic<bool> g_winn3_tunnel_active{false};
#endif

winsvpn::winn3::Winn3StartProof g_last_winn3_proof;

#if !defined(WINS_TUNNEL_SERVICE_CORE)
std::mutex g_winn3_session_mutex;
winsvpn::winn3::Winn3AwgXrayGrant g_awg_xray_grant;
#endif

#if !defined(WINS_TUNNEL_SERVICE_CORE)
std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> g_channel;
PROCESS_INFORMATION g_xray_process = {};
HANDLE g_xray_job = nullptr;
std::recursive_mutex g_xray_mutex;
std::mutex g_power_request_mutex;
std::mutex g_transition_commit_mutex;
HANDLE g_power_request = nullptr;
std::atomic<int64_t> g_canceled_generation_floor{0};
std::atomic<uint64_t> g_committed_generation{0};
std::atomic<bool> g_start_in_flight{false};
std::atomic<bool> g_stop_in_flight{false};
std::mutex g_async_worker_mutex;
std::condition_variable g_async_worker_cv;
bool g_backend_shutting_down = false;
uint32_t g_async_worker_count = 0;

using EncodableMethodResult =
    flutter::MethodResult<flutter::EncodableValue>;

bool BeginAsyncWorker() {
  std::lock_guard<std::mutex> lock(g_async_worker_mutex);
  if (g_backend_shutting_down) return false;
  ++g_async_worker_count;
  return true;
}

void EndAsyncWorker() {
  std::lock_guard<std::mutex> lock(g_async_worker_mutex);
  if (g_async_worker_count > 0) --g_async_worker_count;
  g_async_worker_cv.notify_all();
}

bool IsBackendShuttingDown() {
  std::lock_guard<std::mutex> lock(g_async_worker_mutex);
  return g_backend_shutting_down;
}

template <typename ResultType>
class ScopedAsyncWorker {
 public:
  explicit ScopedAsyncWorker(std::shared_ptr<ResultType>* result)
      : result_(result) {}
  ~ScopedAsyncWorker() {
    // Release the MethodResult (and its retained messenger callback) before
    // publishing worker quiescence to the window-shutdown path.
    if (result_ != nullptr) result_->reset();
    EndAsyncWorker();
  }

 private:
  std::shared_ptr<ResultType>* result_;
};

void CompleteEncodableMethodAsync(
    std::unique_ptr<EncodableMethodResult> result,
    std::function<flutter::EncodableValue()> operation) {
  if (!BeginAsyncWorker()) {
    result->Error("WINDOWS_TUNNEL_SHUTTING_DOWN",
                  "The Windows tunnel bridge is shutting down.");
    return;
  }
  auto async_result =
      std::shared_ptr<EncodableMethodResult>(result.release());
  try {
    // Flutter's Windows messenger wrapper explicitly supports sending the
    // response from any thread and retains the messenger until this result is
    // completed. Native service queries must not occupy the platform/UI thread.
    std::thread([async_result, operation = std::move(operation)]() mutable {
      ScopedAsyncWorker<EncodableMethodResult> worker(&async_result);
      try {
        flutter::EncodableValue value = operation();
        if (!IsBackendShuttingDown()) {
          async_result->Success(value);
        }
      } catch (...) {
        if (!IsBackendShuttingDown()) {
          async_result->Error("WINDOWS_TUNNEL_QUERY_FAILED",
                              "The Windows tunnel query failed unexpectedly.");
        }
      }
    }).detach();
  } catch (...) {
    EndAsyncWorker();
    async_result->Error("WINDOWS_TUNNEL_QUERY_DISPATCH_FAILED",
                        "Unable to dispatch the Windows tunnel query.");
  }
}
#else
PROCESS_INFORMATION g_awg_engine_process = {};
HANDLE g_awg_engine_job = nullptr;
std::atomic<bool> g_tunnel_promoted{false};
#endif

bool IsTransitionGenerationAllowed(int64_t transition_generation,
                                   int64_t canceled_generation_floor) {
  return transition_generation > 0 &&
         transition_generation > canceled_generation_floor;
}

int64_t RaisedCanceledGenerationFloor(int64_t current_floor,
                                      int64_t cancellation_generation) {
  return cancellation_generation > current_floor ? cancellation_generation
                                                  : current_floor;
}

#if !defined(WINS_TUNNEL_SERVICE_CORE)
bool IsWindowsStartGenerationAllowed(int64_t transition_generation) {
  return IsTransitionGenerationAllowed(
      transition_generation,
      g_canceled_generation_floor.load(std::memory_order_acquire));
}

void AdvanceWindowsCanceledGenerationFloor(int64_t cancellation_generation) {
  int64_t current =
      g_canceled_generation_floor.load(std::memory_order_acquire);
  while (cancellation_generation > current &&
         !g_canceled_generation_floor.compare_exchange_weak(
             current, cancellation_generation, std::memory_order_acq_rel,
             std::memory_order_acquire)) {
  }
}
#endif

std::wstring Utf8ToWide(const std::string& value) {
  if (value.empty()) {
    return L"";
  }
  const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                       static_cast<int>(value.size()), nullptr,
                                       0);
  if (size <= 0) {
    return L"";
  }
  std::wstring out(static_cast<size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), size);
  return out;
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return "";
  }
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                       static_cast<int>(value.size()), nullptr,
                                       0, nullptr, nullptr);
  if (size <= 0) {
    return "";
  }
  std::string out(static_cast<size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), size, nullptr, nullptr);
  return out;
}

std::wstring EnvVar(const wchar_t* name) {
  wchar_t buffer[MAX_PATH * 2] = {};
  const DWORD size = GetEnvironmentVariableW(name, buffer,
                                             static_cast<DWORD>(_countof(buffer)));
  if (size == 0 || size >= _countof(buffer)) {
    return L"";
  }
  return buffer;
}

bool FileExists(const std::wstring& path) {
  const DWORD attrs = GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool DirectoryExists(const std::wstring& path) {
  const DWORD attrs = GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
  if (left.empty()) {
    return right;
  }
  if (left.back() == L'\\' || left.back() == L'/') {
    return left + right;
  }
  return left + L"\\" + right;
}

std::wstring ModuleDirectory() {
  wchar_t path[MAX_PATH * 4] = {};
  const DWORD size = GetModuleFileNameW(nullptr, path,
                                        static_cast<DWORD>(_countof(path)));
  if (size == 0 || size >= _countof(path)) {
    return L".";
  }
  std::wstring full(path, size);
  const size_t slash = full.find_last_of(L"\\/");
  if (slash == std::wstring::npos) {
    return L".";
  }
  return full.substr(0, slash);
}

std::wstring ProgramDataDirectory() {
  const std::wstring program_data = EnvVar(L"ProgramData");
  if (!program_data.empty()) {
    return JoinPath(program_data, L"WinsVPN");
  }
  return L"C:\\ProgramData\\WinsVPN";
}

std::wstring UserRuntimeDirectory() {
  const std::wstring local_app_data = EnvVar(L"LOCALAPPDATA");
  if (local_app_data.empty()) {
    return L"";
  }
  return JoinPath(JoinPath(local_app_data, L"WinsVPN"), L"Runtime");
}

bool EnsureDirectory(const std::wstring& path) {
  const DWORD existing = GetFileAttributesW(path.c_str());
  if (existing != INVALID_FILE_ATTRIBUTES) {
    return (existing & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (existing & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
  }
  if (CreateDirectoryW(path.c_str(), nullptr) != 0 || GetLastError() == ERROR_ALREADY_EXISTS) {
    return true;
  }
  return false;
}

std::wstring Quote(const std::wstring& value) {
  return L"\"" + value + L"\"";
}

// N-01: absolute path to a Windows system executable. This translation unit is
// compiled into the WINS_TUNNEL_SERVICE_CORE binary, which runs as LocalSystem,
// and RunCommand below passes lpApplicationName = nullptr. That makes an
// unqualified image name resolve through the CreateProcess search order, which
// consults the module directory and the process current directory before
// System32. Resolving against GetSystemDirectoryW is the same rule RunNetsh in
// winn3_supervisor.cpp already commits to, and the same reason
// FindAwgToolExecutable refuses its Program Files fallback. Returns an empty
// string on failure so the caller can fail closed rather than fall back to a
// name.
std::wstring SystemExecutablePath(const std::wstring& file_name) {
  wchar_t system_directory[MAX_PATH] = {};
  const UINT length = GetSystemDirectoryW(system_directory, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return std::wstring();
  }
  return std::wstring(system_directory, length) + L"\\" + file_name;
}

struct ProcessResult {
  bool started = false;
  DWORD exit_code = 1;
};

struct TunnelServiceStatus {
  bool query_ok = false;
  bool exists = false;
  DWORD state = SERVICE_STOPPED;
};

ProcessResult RunCommand(const std::wstring& command_line,
                         DWORD timeout_ms = 60000) {
  constexpr DWORD kTerminationDrainMilliseconds = 500;
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  const auto remaining = [deadline]() -> DWORD {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) return 0;
    return static_cast<DWORD>(
        std::min<ULONGLONG>(deadline - now, MAXDWORD));
  };
  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process = {};
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');
  ProcessResult result;
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == nullptr ||
      !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &limits, sizeof(limits))) {
    result.exit_code = GetLastError();
    if (job != nullptr) CloseHandle(job);
    return result;
  }
  if (!CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr,
                      &startup, &process)) {
    result.exit_code = GetLastError();
    CloseHandle(job);
    return result;
  }
  result.started = true;
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    result.exit_code = GetLastError();
    // The suspended child is not inside the job when assignment fails.
    // Terminate it directly before releasing the last process handle.
    TerminateProcess(process.hProcess, result.exit_code);
    WaitForSingleObject(
        process.hProcess,
        std::min<DWORD>(remaining(), kTerminationDrainMilliseconds));
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(job);
    return result;
  }
  if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    result.exit_code = GetLastError();
    TerminateJobObject(job, result.exit_code);
    WaitForSingleObject(
        process.hProcess,
        std::min<DWORD>(remaining(), kTerminationDrainMilliseconds));
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    CloseHandle(job);
    return result;
  }
  // Reserve a bounded drain inside the caller's total deadline. Closing the
  // kill-on-close job is the final descendant cleanup boundary; no timeout or
  // WAIT_FAILED path waits forever or leaves an untracked PowerShell/curl.
  const DWORD remaining_before_wait = remaining();
  const DWORD execution_wait =
      remaining_before_wait > kTerminationDrainMilliseconds
          ? remaining_before_wait - kTerminationDrainMilliseconds
          : 0;
  const DWORD wait_result =
      WaitForSingleObject(process.hProcess, execution_wait);
  if (wait_result == WAIT_TIMEOUT) {
    TerminateJobObject(job, 1);
    WaitForSingleObject(
        process.hProcess,
        std::min<DWORD>(remaining(), kTerminationDrainMilliseconds));
    result.exit_code = WAIT_TIMEOUT;
  } else if (wait_result == WAIT_OBJECT_0) {
    DWORD exit_code = 1;
    if (GetExitCodeProcess(process.hProcess, &exit_code)) {
      result.exit_code = exit_code;
    }
  } else {
    result.exit_code = GetLastError();
    TerminateJobObject(job, result.exit_code);
    WaitForSingleObject(
        process.hProcess,
        std::min<DWORD>(remaining(), kTerminationDrainMilliseconds));
  }
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  return result;
}

TunnelServiceStatus QueryTunnelServiceStatus() {
  TunnelServiceStatus result;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return result;
  }
  SC_HANDLE service =
      OpenServiceW(manager, kTunnelServiceName, SERVICE_QUERY_STATUS);
  if (service == nullptr) {
    const DWORD error = GetLastError();
    CloseServiceHandle(manager);
    if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
      result.query_ok = true;
    }
    return result;
  }
  SERVICE_STATUS_PROCESS status = {};
  DWORD bytes_needed = 0;
  const BOOL ok = QueryServiceStatusEx(
      service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
      sizeof(status), &bytes_needed);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (ok == 0) {
    return result;
  }
  result.query_ok = true;
  result.exists = true;
  result.state = status.dwCurrentState;
  return result;
}

bool WaitForTunnelService(bool should_exist, DWORD desired_state,
                          DWORD timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  do {
    const TunnelServiceStatus status = QueryTunnelServiceStatus();
    if (status.query_ok && status.exists == should_exist &&
        (!should_exist || status.state == desired_state)) {
      return true;
    }
    Sleep(250);
  } while (GetTickCount64() < deadline);
  return false;
}

bool RemoveTunnelService(const std::wstring& amneziawg) {
  const TunnelServiceStatus initial_status = QueryTunnelServiceStatus();
  if (initial_status.query_ok && !initial_status.exists) {
    return true;
  }
  const ProcessResult uninstall =
      RunCommand(Quote(amneziawg) + L" /uninstalltunnelservice " +
                     std::wstring(kTunnelName),
                 winsvpn::tunnel_service::
                     kLegacyUninstallCommandTimeoutMilliseconds);
  if (WaitForTunnelService(
          false, SERVICE_STOPPED,
          winsvpn::tunnel_service::kLegacyInitialRemovalWaitMilliseconds)) {
    return true;
  }

  // A failed uninstall must not be ignored: WireGuard-family Windows clients
  // can retain their WFP kill-switch while the stale service remains. Stop the
  // service, retry the vendor cleanup, and require SCM-confirmed removal before
  // attempting another route.
  //
  // sc.exe is resolved to its absolute System32 path, never left unqualified.
  // See SystemExecutablePath above. An unresolvable system directory skips the
  // stop rather than running an unqualified name; the SCM-confirmed removal
  // check below is the authority either way.
  const std::wstring sc_exe = SystemExecutablePath(L"sc.exe");
  if (!sc_exe.empty()) {
    RunCommand(Quote(sc_exe) + L" stop " + Quote(kTunnelServiceName),
               winsvpn::tunnel_service::kLegacyScmStopTimeoutMilliseconds);
  }
  const ProcessResult retry =
      RunCommand(Quote(amneziawg) + L" /uninstalltunnelservice " +
                     std::wstring(kTunnelName),
                 winsvpn::tunnel_service::
                     kLegacyUninstallCommandTimeoutMilliseconds);
  const bool removed = WaitForTunnelService(
      false, SERVICE_STOPPED,
      winsvpn::tunnel_service::kLegacyFinalRemovalWaitMilliseconds);
  return removed &&
         ((uninstall.started && uninstall.exit_code == 0) ||
          (retry.started && retry.exit_code == 0));
}

#if !defined(WINS_TUNNEL_SERVICE_CORE)
void StopXrayProcess() {
  std::lock_guard<std::recursive_mutex> lock(g_xray_mutex);
  if (g_xray_process.hProcess != nullptr) {
    if (g_xray_job != nullptr) {
      TerminateJobObject(g_xray_job, 0);
    } else {
      TerminateProcess(g_xray_process.hProcess, 0);
    }
    WaitForSingleObject(g_xray_process.hProcess, 3000);
    CloseHandle(g_xray_process.hProcess);
    if (g_xray_process.hThread != nullptr) {
      CloseHandle(g_xray_process.hThread);
    }
    g_xray_process = {};
  }
  if (g_xray_job != nullptr) {
    CloseHandle(g_xray_job);
    g_xray_job = nullptr;
  }
  const std::wstring runtime_directory = UserRuntimeDirectory();
  if (!runtime_directory.empty()) {
    DeleteFileW(JoinPath(runtime_directory, L"wins_xray_client.json").c_str());
  }
}

bool IsXrayProcessRunning() {
  std::lock_guard<std::recursive_mutex> lock(g_xray_mutex);
  return g_xray_process.hProcess != nullptr &&
         WaitForSingleObject(g_xray_process.hProcess, 0) == WAIT_TIMEOUT;
}

// CORE-7-T17C-claude: the Windows half of the local account reset, called
// by Dart after its stop-proof and before it deletes the cleanup journal.
//
// The Xray client configuration is written to the per-user runtime directory
// under a unique name (UniqueConfigPath), or under the fixed name by older
// builds, and its atomic writer names its temporary file after it. The stop
// deletes only the fixed name and ignores the result (StopXrayProcess), and a
// crash before ScopedFileDelete runs leaves a unique copy no stop deletes. So
// every entry with that stem is deleted here, and the verdict is a fresh
// listing that finds none.
//
// The service's AmneziaWG configuration lives in ProgramData\WinsVPN, whose
// DACL admits only SYSTEM and Administrators, so this unprivileged process
// can neither list nor delete there. The fixed name the service's stop
// deletes there is checked by name, and only "not found" counts as absent.
enum class AccountRuntimeScan { kNone, kFound, kError };

AccountRuntimeScan ScanAccountRuntimeEntries(
    const std::wstring& directory,
    std::vector<std::wstring>* names) {
  WIN32_FIND_DATAW entry = {};
  const HANDLE find = FindFirstFileExW(
      JoinPath(directory, L"wins_xray_client*").c_str(), FindExInfoBasic,
      &entry, FindExSearchNameMatch, nullptr, 0);
  if (find == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND
               ? AccountRuntimeScan::kNone
               : AccountRuntimeScan::kError;
  }
  do {
    names->push_back(entry.cFileName);
  } while (FindNextFileW(find, &entry));
  const DWORD error = GetLastError();
  FindClose(find);
  if (error != ERROR_NO_MORE_FILES) {
    return AccountRuntimeScan::kError;
  }
  return names->empty() ? AccountRuntimeScan::kNone
                        : AccountRuntimeScan::kFound;
}

bool AccountResetRuntimePathAbsent(const std::wstring& path) {
  if (path.empty()) {
    return false;
  }
  if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  const DWORD error = GetLastError();
  return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool EraseLocalAccountRuntime() {
  if (IsXrayProcessRunning()) {
    return false;
  }
  const std::wstring runtime_directory = UserRuntimeDirectory();
  if (runtime_directory.empty()) {
    return false;
  }
  std::vector<std::wstring> found;
  if (ScanAccountRuntimeEntries(runtime_directory, &found) ==
      AccountRuntimeScan::kError) {
    return false;
  }
  for (const std::wstring& name : found) {
    // A directory or an undeletable file fails here and is caught by the
    // listing below; a symbolic link is removed, never followed.
    DeleteFileW(JoinPath(runtime_directory, name).c_str());
  }
  std::vector<std::wstring> remaining;
  if (ScanAccountRuntimeEntries(runtime_directory, &remaining) !=
      AccountRuntimeScan::kNone) {
    return false;
  }
  return AccountResetRuntimePathAbsent(
      JoinPath(ProgramDataDirectory(), L"winsvpn.conf"));
}

void EnableTunnelPowerProtection() {
  std::lock_guard<std::mutex> lock(g_power_request_mutex);
  if (g_power_request == nullptr) {
    REASON_CONTEXT reason = {};
    reason.Version = POWER_REQUEST_CONTEXT_VERSION;
    reason.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
    reason.Reason.SimpleReasonString =
        const_cast<PWSTR>(L"Win's VPN has an active protected tunnel");
    HANDLE request = PowerCreateRequest(&reason);
    if (request != nullptr && request != INVALID_HANDLE_VALUE &&
        PowerSetRequest(request, PowerRequestSystemRequired)) {
      g_power_request = request;
    } else if (request != nullptr && request != INVALID_HANDLE_VALUE) {
      CloseHandle(request);
    }
  }
  SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
  PROCESS_POWER_THROTTLING_STATE power_state = {};
  power_state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
  power_state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
  power_state.StateMask = 0;
  SetProcessInformation(GetCurrentProcess(), ProcessPowerThrottling,
                        &power_state, sizeof(power_state));
}

void DisableTunnelPowerProtection() {
  std::lock_guard<std::mutex> lock(g_power_request_mutex);
  if (g_power_request != nullptr) {
    PowerClearRequest(g_power_request, PowerRequestSystemRequired);
    CloseHandle(g_power_request);
    g_power_request = nullptr;
  }
  SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
}
#endif

std::string Trim(const std::string& value) {
  size_t start = 0;
  while (start < value.size() &&
         std::isspace(static_cast<unsigned char>(value[start])) != 0) {
    ++start;
  }
  size_t end = value.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
    --end;
  }
  return value.substr(start, end - start);
}

std::string LowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool IsSectionHeader(const std::string& line) {
  return line.size() >= 3 && line.front() == '[' && line.back() == ']';
}

std::map<std::string, std::string> ParseSection(const std::string& config,
                                                const std::string& section_name) {
  std::map<std::string, std::string> out;
  std::istringstream stream(config);
  std::string line;
  bool in_section = false;
  const std::string wanted = LowerAscii(section_name);
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    if (IsSectionHeader(trimmed)) {
      const std::string current =
          LowerAscii(trimmed.substr(1, trimmed.size() - 2));
      in_section = current == wanted;
      continue;
    }
    if (!in_section) {
      continue;
    }
    const size_t equals = trimmed.find('=');
    if (equals == std::string::npos) {
      continue;
    }
    out[LowerAscii(Trim(trimmed.substr(0, equals)))] =
        Trim(trimmed.substr(equals + 1));
  }
  return out;
}

std::string SectionValue(const std::map<std::string, std::string>& section,
                         const std::string& key,
                         const std::string& fallback = "") {
  const auto it = section.find(key);
  if (it == section.end() || it->second.empty()) {
    return fallback;
  }
  return it->second;
}

std::string BuildAwgSetconfConfig(const std::string& raw_config) {
  const auto interface_config = ParseSection(raw_config, "interface");
  const auto peer = ParseSection(raw_config, "peer");
  const std::string private_key =
      SectionValue(interface_config, "privatekey");
  const std::string public_key = SectionValue(peer, "publickey");
  const std::string endpoint = SectionValue(peer, "endpoint");
  const std::string allowed_ips = SectionValue(peer, "allowedips");
  if (private_key.empty() || public_key.empty() || endpoint.empty() ||
      allowed_ips.empty()) {
    return "";
  }
  std::ostringstream out;
  out << "[Interface]\nPrivateKey = " << private_key << "\n";
  for (const auto& field : {
           std::pair<const char*, const char*>{"Jc", "jc"},
           {"Jmin", "jmin"}, {"Jmax", "jmax"}, {"S1", "s1"},
           {"S2", "s2"}, {"S3", "s3"}, {"S4", "s4"},
           {"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"},
           {"H4", "h4"},
       }) {
    const std::string value = SectionValue(interface_config, field.second);
    if (!value.empty()) out << field.first << " = " << value << "\n";
  }
  out << "\n[Peer]\nPublicKey = " << public_key << "\n";
  const std::string preshared_key = SectionValue(peer, "presharedkey");
  if (!preshared_key.empty()) {
    out << "PresharedKey = " << preshared_key << "\n";
  }
  out << "Endpoint = " << endpoint << "\n"
      << "AllowedIPs = " << allowed_ips << "\n";
  const std::string persistent_keepalive =
      SectionValue(peer, "persistentkeepalive");
  if (!persistent_keepalive.empty()) {
    out << "PersistentKeepalive = " << persistent_keepalive << "\n";
  }
  return out.str();
}

bool SectionBool(const std::map<std::string, std::string>& section,
                 const std::string& key) {
  const std::string value = LowerAscii(SectionValue(section, key));
  return value == "1" || value == "true" || value == "yes" || value == "y";
}

int PositiveIntValue(const std::map<std::string, std::string>& section,
                     const std::string& key,
                     int fallback) {
  const std::string value = SectionValue(section, key);
  if (value.empty()) {
    return fallback;
  }
  char* end = nullptr;
  const long parsed = std::strtol(value.c_str(), &end, 10);
  if (end == value.c_str() || *end != '\0' || parsed < 1 || parsed > 65535) {
    return fallback;
  }
  return static_cast<int>(parsed);
}

bool IsValidPortValue(const std::string& value) {
  if (value.empty() || value.size() > 5) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return std::isdigit(c) != 0;
         }) &&
         std::strtol(value.c_str(), nullptr, 10) >= 1 &&
         std::strtol(value.c_str(), nullptr, 10) <= 65535;
}

bool IsValidXrayUuid(const std::string& value) {
  if (value.size() != 36) {
    return false;
  }
  for (size_t i = 0; i < value.size(); ++i) {
    const bool separator = i == 8 || i == 13 || i == 18 || i == 23;
    if (separator ? value[i] != '-'
                  : std::isxdigit(static_cast<unsigned char>(value[i])) == 0) {
      return false;
    }
  }
  return true;
}

bool IsValidXrayHostname(const std::string& value) {
  if (value.empty() || value.size() > 253) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char c) {
    return std::isalnum(c) != 0 || c == '.' || c == '-';
  });
}

bool IsValidXrayPath(const std::string& value) {
  return !value.empty() && value.front() == '/' && value.size() <= 256 &&
         value.find('\r') == std::string::npos &&
         value.find('\n') == std::string::npos;
}

bool ValidateRestrictedTunnelConfig(const std::string& config,
                                    std::string* error) {
  if (error == nullptr) {
    return false;
  }
  error->clear();
  if (config.empty() || config.size() > 512 * 1024 ||
      config.find('\0') != std::string::npos) {
    *error = "Tunnel configuration size or encoding is invalid.";
    return false;
  }
  std::map<std::string, std::set<std::string>> allowed = {
      {"interface",
       {"privatekey", "address", "mtu", "dns", "jc", "jmin", "jmax",
        "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "table"}},
      {"peer",
       {"publickey", "presharedkey", "endpoint", "allowedips",
        "persistentkeepalive"}},
      {"xray",
       {"enabled", "uuid", "host", "port", "servername", "path",
        "security", "localport", "remoteawghost", "remoteawgport"}},
      {"winsdebug", {"clientpublickey"}},
      {"winsapp",
       {"excludedpackages", "excludedpathsb64", "tunnelgatewayipv4"}},
      // Winn Protocol v3. Exactly the keys lib/winn_protocol_dispatch.dart
      // emits, which are in turn exactly the keys WinnEngineConfig.from
      // accepts. Without this section here a `[winn]` config was rejected as
      // "an unknown or duplicate section" BEFORE the start path ever saw it,
      // which is why StartPrivilegedWinnTunnel was unreachable even for a
      // caller that wanted it.
      //
      // The eleven carrier-profile keys are listed even though this host
      // builds direct-awg only. They are here so that an http3-connect-udp
      // config is refused by ParseWindowsWinnSection's carrier gate, which
      // names the carrier as the cause, rather than by this allowlist, which
      // would name whichever profile key happened to come first. Same
      // reasoning, same order, as ParseLinuxWinnSection.
      {"winn",
       {"enabled", "endpoint", "carrier", "max_datagram", "session_id",
        "h1", "h2", "h3", "h4", "s1", "s2", "s3", "s4",
        "masque_template", "public_target", "server_name", "suite",
        "controller_id", "device_id", "device_pq_algorithm",
        "manifest_digest", "sequence_epoch", "max_inner_datagram",
        "privacy_profile"}},
      // Winn Protocol v3, STANDALONE. A different section from `[winn]`
      // because it is a different protocol: its own handshake, its own AEAD,
      // its own rekey and framing, its own Wintun adapter ("winsvpn3"), and a
      // seam that carries raw inner IP packets rather than AmneziaWG outer
      // datagrams. Nothing beneath it is AmneziaWG.
      //
      // It is listed here for exactly the reason the block above records for
      // `[winn]`: without it, a v3 configuration is rejected as "an unknown or
      // duplicate section" BEFORE the start path ever sees it, which is what
      // kept StartPrivilegedWinnTunnel unreachable for a caller that wanted
      // it. Adding a section to this allowlist cannot loosen any check that
      // applies to a configuration which does not carry it.
      //
      // The keys are exactly the fields winn3_profile.go's document declares,
      // plus the two posture lists. ParseWinn3Section refuses an unrecognised
      // one a second time, with a message that names the key rather than the
      // section.
      {"winn3",
       {"enabled", "endpoint", "class", "plan", "path_mtu", "gateway_id",
        "inner_v4", "inner_v6", "router_v4", "router_v6", "static_key_path",
        "gateway_static_key_path", "admission_path", "routes", "dns",
        "dns_are_inner", "fast_pq"}},
  };
  allowed.erase("winn3");
  if (winsvpn::winn3::ConfigSelectsWinn3(config)) {
    allowed["winn"] = {
        "enabled", "endpoint", "carrier", "node", "selected_node",
        "inner_v4", "inner_router_v4", "inner_resolver_v4",
        "static_private", "gateway_static", "gateway_id", "admission_key",
        "auth_ed25519", "auth_mldsa65", "psk", "path_mtu",
        "carrier_classes", "session_id"};
  }
  std::map<std::string, std::set<std::string>> seen_keys;
  std::set<std::string> seen_sections;
  std::string current_section;
  std::istringstream stream(config);
  std::string line;
  size_t line_count = 0;
  while (std::getline(stream, line)) {
    if (++line_count > 512) {
      *error = "Tunnel configuration contains too many directives.";
      return false;
    }
    const std::string trimmed = Trim(line);
    if (trimmed.empty()) {
      continue;
    }
    if (IsSectionHeader(trimmed)) {
      current_section = LowerAscii(trimmed.substr(1, trimmed.size() - 2));
      if (allowed.find(current_section) == allowed.end() ||
          !seen_sections.insert(current_section).second) {
        *error = "Tunnel configuration contains an unknown or duplicate section.";
        return false;
      }
      continue;
    }
    const size_t equals = trimmed.find('=');
    if (current_section.empty() || equals == std::string::npos) {
      *error = "Tunnel configuration contains a malformed directive.";
      return false;
    }
    const std::string key = LowerAscii(Trim(trimmed.substr(0, equals)));
    const std::string value = Trim(trimmed.substr(equals + 1));
    const auto section_it = allowed.find(current_section);
    const bool optional_empty_app_value =
        current_section == "winsapp" &&
        (key == "excludedpackages" || key == "excludedpathsb64");
    if (key.empty() || (!optional_empty_app_value && value.empty()) ||
        value.size() > 64 * 1024 ||
        section_it == allowed.end() ||
        section_it->second.find(key) == section_it->second.end() ||
        !seen_keys[current_section].insert(key).second) {
      *error = "Tunnel configuration contains an unsafe, empty, or duplicate directive.";
      return false;
    }
  }
  const std::string table =
      LowerAscii(SectionValue(ParseSection(config, "interface"), "table"));
  if (!table.empty() && table != "off") {
    *error = "Windows tunnel routing accepts only Table=off.";
    return false;
  }
  if (winsvpn::winn3::ConfigSelectsWinn3(config)) {
    if (seen_sections.count("xray") != 0) {
      *error = "Standalone Winn v3 cannot include an Xray relay section.";
      return false;
    }
    winsvpn::winn3::Winn3HostConfig parsed;
    return winsvpn::winn3::ParseWinn3Section(config, &parsed, error);
  }
  const auto interface_config = ParseSection(config, "interface");
  // AmneziaWG obfuscation bounds. These three numbers are the Windows half of
  // a cross-language contract: they must equal `VpnConfigValidator.awgJunkMax`,
  // `.awgHeaderMin` and `.awgHeaderMax` in `lib/vpn_config_validation.dart`.
  // `test/awg_obfuscation_bounds_parity_test.dart` reads this file and asserts
  // exactly that, because widening one language alone is what produced the
  // 2026-08-07 lockout risk: Dart accepted a full-width header while this
  // validator still refused it -- twice, on digit count and on value -- on the
  // live connect path through InstallTunnel/InstallPrivilegedTunnel.
  //
  // jc/jmin/jmax/s1..s4 are packet and byte counts, so the small ceiling is
  // correct for them and must not inherit the widened one. h1..h4 replace
  // WireGuard's four message-type values in the leading little-endian uint32:
  // anything below 2^24 leaves the top byte zero and preserves the exact shape
  // DPI matches on, so they need the whole uint32. That is the bound
  // `windows_winn_engine.cpp:406` already applies on the winn/3 path; this is
  // the classic-AWG path catching up to it, not a new invention.
  constexpr uint64_t kAwgJunkMax = 1000000ULL;
  constexpr uint64_t kAwgHeaderMin = 5ULL;
  constexpr uint64_t kAwgHeaderMax = 4294967295ULL;
  constexpr size_t kAwgJunkMaxDigits = 7;
  constexpr size_t kAwgHeaderMaxDigits = 10;
  // H1..H4 may be a single value OR an inclusive range "<start>-<end>".
  // AmneziaWG's device/magic-header.go parses both on these four fields and
  // calls Generate() once PER PACKET, so a range makes the header word vary
  // per datagram instead of being fixed for the life of the flow. A scalar is
  // stored as the degenerate range start == end, which is exactly how the
  // engine stores it, and is what keeps the legacy 11/22/33/44 set valid --
  // these parameters are not negotiated, so refusing a spelling the far end
  // uses is a fleet lockout rather than a downgrade.
  struct AwgHeaderSpec {
    uint64_t start;
    uint64_t end;
  };
  // One 10-digit endpoint, a separator, and a second 10-digit endpoint.
  constexpr size_t kAwgHeaderSpecMaxDigits = kAwgHeaderMaxDigits * 2 + 1;
  std::map<std::string, uint64_t> obfuscation;
  std::map<std::string, AwgHeaderSpec> header_specs;
  // strtoull, not strtoul: MSVC is LLP64, so `unsigned long` is 32 bits and
  // strtoul would saturate an over-range 10-digit value to ULONG_MAX -- which
  // is exactly kAwgHeaderMax -- and slip past the ceiling check with a
  // silently rewritten number. `unsigned long long` is 64-bit everywhere.
  const auto parse_bounded = [](const std::string& text, uint64_t min_value,
                                uint64_t max_value, size_t max_digits,
                                uint64_t* out) -> bool {
    if (text.empty() || text.size() > max_digits ||
        !std::all_of(text.begin(), text.end(), [](unsigned char c) {
          return std::isdigit(c) != 0;
        })) {
      return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0' || errno == ERANGE ||
        parsed > max_value || parsed < min_value) {
      return false;
    }
    *out = static_cast<uint64_t>(parsed);
    return true;
  };
  for (const char* key : {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
                          "h1", "h2", "h3", "h4"}) {
    const bool is_header = key[0] == 'h';
    const std::string value = SectionValue(interface_config, key);
    if (!is_header) {
      uint64_t parsed = 0;
      if (!parse_bounded(value, 0ULL, kAwgJunkMax, kAwgJunkMaxDigits,
                         &parsed)) {
        *error = "Windows tunnel configuration has missing or invalid AWG obfuscation values.";
        return false;
      }
      obfuscation.emplace(key, parsed);
      continue;
    }
    if (value.empty() || value.size() > kAwgHeaderSpecMaxDigits) {
      *error = "Windows tunnel configuration has missing or invalid AWG obfuscation values.";
      return false;
    }
    const size_t separator = value.find('-');
    const std::string start_text =
        separator == std::string::npos ? value : value.substr(0, separator);
    const std::string end_text =
        separator == std::string::npos ? value : value.substr(separator + 1);
    // A second separator leaves a non-digit in end_text, so parse_bounded
    // refuses it; an empty side is refused for the same reason. Both endpoints
    // are bounded, so every word the engine could draw is inside the contract.
    AwgHeaderSpec spec{0ULL, 0ULL};
    if (!parse_bounded(start_text, kAwgHeaderMin, kAwgHeaderMax,
                       kAwgHeaderMaxDigits, &spec.start) ||
        !parse_bounded(end_text, kAwgHeaderMin, kAwgHeaderMax,
                       kAwgHeaderMaxDigits, &spec.end) ||
        spec.end < spec.start) {
      *error = "Windows tunnel configuration has out-of-range AWG obfuscation values.";
      return false;
    }
    header_specs.emplace(key, spec);
  }
  if (obfuscation["jmin"] > obfuscation["jmax"]) {
    *error = "Windows tunnel configuration has inconsistent AWG jitter bounds.";
    return false;
  }
  // Two message types that can produce the same word leave the peer unable to
  // tell a handshake from a transport packet, so a collision is a broken
  // config rather than a weak one. kAwgHeaderMin above already excludes
  // WireGuard's reserved 1..4. The legacy 11/22/33/44 set passes both rules,
  // which is required: these parameters are not negotiated, so rejecting them
  // would lock out every peer still configured with them.
  //
  // With ranges the test is INTERSECTION, not equality -- and it is not a
  // stricter local opinion: `mergeWithDevice` in the engine's device/uapi.go
  // refuses a device whose four headers overlap ("headers must not overlap"),
  // so accepting an overlapping set here would hand the tunnel a config it
  // cannot start. For two scalars intersection degrades to equality, which is
  // the rule this block enforced before ranges existed.
  {
    const char* const header_keys[4] = {"h1", "h2", "h3", "h4"};
    for (size_t a = 0; a < 4; ++a) {
      for (size_t b = a + 1; b < 4; ++b) {
        const AwgHeaderSpec& left = header_specs[header_keys[a]];
        const AwgHeaderSpec& right = header_specs[header_keys[b]];
        if (left.start <= right.end && right.start <= left.end) {
          *error = "Windows tunnel configuration has colliding AWG header types.";
          return false;
        }
      }
    }
  }
  for (const auto& requirement : {
           std::pair<std::string, std::string>{"interface", "privatekey"},
           {"interface", "address"},
           {"peer", "publickey"},
           {"peer", "endpoint"},
           {"peer", "allowedips"},
       }) {
    const auto section_it = seen_keys.find(requirement.first);
    if (section_it == seen_keys.end() ||
        section_it->second.find(requirement.second) == section_it->second.end()) {
      *error = "Tunnel configuration is missing a required AWG directive.";
      return false;
    }
  }
  return true;
}

std::vector<std::wstring> WindowsAppExclusionPaths(
    const std::string& raw_config,
    std::string* error) {
  const auto section = ParseSection(raw_config, "winsapp");
  const std::string encoded = SectionValue(section, "excludedpathsb64");
  if (encoded.empty()) {
    return {};
  }
  DWORD decoded_size = 0;
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                            CRYPT_STRING_BASE64, nullptr, &decoded_size,
                            nullptr, nullptr) ||
      decoded_size == 0 || decoded_size > 1024 * 1024) {
    *error = "The Windows app-exclusion payload is invalid.";
    return {};
  }
  std::string decoded(static_cast<size_t>(decoded_size), '\0');
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                            CRYPT_STRING_BASE64,
                            reinterpret_cast<BYTE*>(decoded.data()),
                            &decoded_size, nullptr, nullptr)) {
    *error = "The Windows app-exclusion payload could not be decoded.";
    return {};
  }
  decoded.resize(decoded_size);
  if (decoded.find('\0') != std::string::npos) {
    *error = "The Windows app-exclusion payload contains invalid characters.";
    return {};
  }
  std::vector<std::wstring> paths;
  std::istringstream stream(decoded);
  std::string line;
  while (std::getline(stream, line)) {
    line = Trim(line);
    if (line.empty()) continue;
    const std::wstring path = Utf8ToWide(line);
    if (path.empty()) {
      *error = "A Windows app-exclusion path is not valid UTF-8.";
      return {};
    }
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
      paths.push_back(path);
    }
  }
  return paths;
}

std::string JsonEscape(const std::string& value) {
  std::ostringstream out;
  for (const unsigned char c : value) {
    switch (c) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u";
          constexpr char digits[] = "0123456789abcdef";
          out << '0' << '0' << digits[(c >> 4) & 0x0f] << digits[c & 0x0f];
        } else {
          out << static_cast<char>(c);
        }
        break;
    }
  }
  return out.str();
}

std::wstring FindAmneziaExecutable() {
  const std::wstring module_candidate = JoinPath(ModuleDirectory(), L"amneziawg.exe");
  if (FileExists(module_candidate)) {
    return module_candidate;
  }
  // M-11: the MSI-installed maintenance helper is still upstream's Go 1.24.4
  // binary. Win's VPN packages an independently source-built Go 1.26.5 helper
  // beside this module and Authenticode-signs that exact staged copy. Falling
  // back to Program Files\AmneziaWG would silently undo the runtime refresh
  // whenever the app-owned helper was missing or quarantined; fail closed
  // instead.
  return L"";
}

// N-1: resolved from the module directory ALONE, for the same reason
// FindAmneziaExecutable above refuses its own Program Files fallback. The app
// ships and Authenticode-signs the exact staged awg.exe beside this module, so
// a Program Files candidate can only ever be an unpinned substitute for a
// pinned one. The fallback was additionally unsound on its own terms: it read
// %ProgramFiles%, an inherited environment value, which a 32-bit build resolves
// to "Program Files (x86)" under WOW64 (missing the 64-bit MSI install
// entirely) and which anyone able to shape this process's environment can
// redirect outright. This function runs at SYSTEM authority in the
// WINS_TUNNEL_SERVICE_CORE build, so that redirection would choose which binary
// runs as SYSTEM. Fail closed instead; the caller already reports an incomplete
// payload cleanly.
std::wstring FindAwgToolExecutable() {
  const std::wstring module_candidate = JoinPath(ModuleDirectory(), L"awg.exe");
  if (FileExists(module_candidate)) {
    return module_candidate;
  }
  return L"";
}

std::wstring FindWinsAwgEngineExecutable() {
  const std::wstring candidate =
      JoinPath(ModuleDirectory(), L"winsvpn_awg_engine.exe");
  return FileExists(candidate) ? candidate : L"";
}

// The Winn Protocol v3 datapath engine, built by
// tools/build_winn_protocol_engine.sh datapath-windows-{amd64,arm64}.
//
// Deliberately resolved by this name ALONE. The Go program in
// windows/winn_framing_fixture/ speaks the same framing, and accepting it here
// is exactly how a fixture would come to be mistaken for a transport. It is
// refused a second time at the create acknowledgement, which requires the real
// datapath's `contract` field, and it identifies itself in-band as
// "winn-test-double" on top of that.
//
// It is a WNN3 framing conformance fixture and never a transport; it used to be
// a test double for an engine that had not shipped, and its artifact was once
// named `winsvpn_winn_engine.exe`. Neither refusal above depends on its name or
// path, so neither was affected by that rename.
std::wstring FindWinnDatapathExecutable() {
  const std::wstring candidate =
      JoinPath(ModuleDirectory(), L"winn-datapath.exe");
  return FileExists(candidate) ? candidate : L"";
}

std::wstring FindXrayExecutable() {
  const std::wstring candidate = JoinPath(ModuleDirectory(), L"xray.exe");
  if (FileExists(candidate)) {
    return candidate;
  }
  return L"";
}

void WipeString(std::string* value) {
  if (value != nullptr && !value->empty()) {
    SecureZeroMemory(value->data(), value->size());
    value->clear();
  }
}

class ScopedStringWipe {
 public:
  explicit ScopedStringWipe(std::string* value) : value_(value) {}
  ~ScopedStringWipe() { WipeString(value_); }
  ScopedStringWipe(const ScopedStringWipe&) = delete;
  ScopedStringWipe& operator=(const ScopedStringWipe&) = delete;

 private:
  std::string* value_;
};

constexpr size_t kMaximumSecureTextBytes = 4 * 1024 * 1024;
constexpr wchar_t kSystemAdminDirectorySddl[] =
    L"O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
constexpr wchar_t kSystemAdminFileSddl[] =
    L"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
constexpr uint8_t kDpapiFileMagic[] = {'W', 'V', 'D', 'P', 1, 0, 0, 0};
std::atomic<uint64_t> g_secure_file_nonce{0};

class ScopedFileDelete {
 public:
  explicit ScopedFileDelete(std::wstring path) : path_(std::move(path)) {}
  ~ScopedFileDelete() {
    if (!path_.empty()) DeleteFileW(path_.c_str());
  }
  ScopedFileDelete(const ScopedFileDelete&) = delete;
  ScopedFileDelete& operator=(const ScopedFileDelete&) = delete;

 private:
  std::wstring path_;
};

bool IsValidUtf8Text(const std::string& value) {
  if (value.find('\0') != std::string::npos ||
      value.size() > kMaximumSecureTextBytes) {
    return false;
  }
  if (value.empty()) return true;
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                             static_cast<int>(value.size()), nullptr, 0) > 0;
}

bool CurrentUserSidString(std::wstring* sid_string) {
  if (sid_string == nullptr) return false;
  sid_string->clear();
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  DWORD bytes = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
  std::vector<uint8_t> buffer(bytes);
  DWORD returned = 0;
  const bool token_ok = bytes > 0 &&
                        GetTokenInformation(token, TokenUser, buffer.data(),
                                            bytes, &returned) != FALSE;
  CloseHandle(token);
  if (!token_ok) return false;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR converted = nullptr;
  if (!ConvertSidToStringSidW(user->User.Sid, &converted) ||
      converted == nullptr) {
    return false;
  }
  *sid_string = converted;
  LocalFree(converted);
  return !sid_string->empty();
}

bool CurrentUserSystemDaclSddl(std::wstring* sddl) {
  std::wstring sid;
  if (sddl == nullptr || !CurrentUserSidString(&sid)) return false;
  *sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + sid + L")";
  return true;
}

bool ConvertSddl(const std::wstring& sddl,
                 PSECURITY_DESCRIPTOR* descriptor) {
  return descriptor != nullptr && !sddl.empty() &&
         ConvertStringSecurityDescriptorToSecurityDescriptorW(
             sddl.c_str(), SDDL_REVISION_1, descriptor, nullptr) != FALSE;
}

bool ApplyProtectedDacl(const std::wstring& path,
                        const std::wstring& sddl) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertSddl(sddl, &descriptor)) return false;
  const BOOL ok = SetFileSecurityW(
      path.c_str(),
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      descriptor);
  LocalFree(descriptor);
  return ok != FALSE;
}

bool ApplyProtectedOwnerAndDacl(const std::wstring& path,
                                const std::wstring& sddl) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertSddl(sddl, &descriptor)) return false;
  const BOOL ok = SetFileSecurityW(
      path.c_str(),
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
          PROTECTED_DACL_SECURITY_INFORMATION,
      descriptor);
  LocalFree(descriptor);
  return ok != FALSE;
}

bool EnsureDirectoryWithDacl(const std::wstring& path,
                             const std::wstring& sddl) {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertSddl(sddl, &descriptor)) return false;
  SECURITY_ATTRIBUTES security = {};
  security.nLength = sizeof(security);
  security.lpSecurityDescriptor = descriptor;
  const BOOL created = CreateDirectoryW(path.c_str(), &security);
  const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
  LocalFree(descriptor);
  if (!created && create_error != ERROR_ALREADY_EXISTS) return false;
  const DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES ||
      (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    return false;
  }
  return ApplyProtectedDacl(path, sddl);
}

std::wstring UniqueSiblingPath(const std::wstring& path,
                               const wchar_t* marker) {
  const uint64_t nonce =
      g_secure_file_nonce.fetch_add(1, std::memory_order_relaxed) + 1;
  return path + L"." + marker + L"." + std::to_wstring(GetCurrentProcessId()) +
         L"." + std::to_wstring(GetTickCount64()) + L"." +
         std::to_wstring(nonce);
}

bool WriteBytesSecureAtomic(const std::wstring& path, const uint8_t* bytes,
                            size_t size, const std::wstring& sddl) {
  if ((bytes == nullptr && size != 0) || size > kMaximumSecureTextBytes +
                                                    1024 * 1024) {
    return false;
  }
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertSddl(sddl, &descriptor)) return false;
  SECURITY_ATTRIBUTES security = {};
  security.nLength = sizeof(security);
  security.lpSecurityDescriptor = descriptor;

  HANDLE file = INVALID_HANDLE_VALUE;
  std::wstring temporary;
  for (int attempt = 0; attempt < 32; ++attempt) {
    temporary = UniqueSiblingPath(path, L"tmp");
    file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &security,
                       CREATE_NEW,
                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH,
                       nullptr);
    if (file != INVALID_HANDLE_VALUE || GetLastError() != ERROR_FILE_EXISTS) {
      break;
    }
  }
  LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE) return false;

  DWORD written = 0;
  const BOOL write_ok = size == 0 ||
                        WriteFile(file, bytes, static_cast<DWORD>(size),
                                  &written, nullptr);
  const DWORD expected_size = static_cast<DWORD>(size);
  const BOOL flush_ok = write_ok != FALSE && written == expected_size &&
                         FlushFileBuffers(file) != FALSE;
  CloseHandle(file);
  if (!flush_ok) {
    DeleteFileW(temporary.c_str());
    return false;
  }

  const DWORD existing = GetFileAttributesW(path.c_str());
  if (existing != INVALID_FILE_ATTRIBUTES &&
      ((existing & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
       (existing & FILE_ATTRIBUTE_REPARSE_POINT) != 0)) {
    DeleteFileW(temporary.c_str());
    return false;
  }
  if (!MoveFileExW(temporary.c_str(), path.c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    // Replacement failed. The destination still holds the previous value.
    DeleteFileW(temporary.c_str());
    return false;
  }
  if (!ApplyProtectedDacl(path, sddl)) {
    // Only remove a value that this call successfully installed.
    DeleteFileW(path.c_str());
    return false;
  }
  return true;
}

bool ReadRegularFileBounded(const std::wstring& path, size_t maximum_bytes,
                            std::vector<uint8_t>* output) {
  if (output == nullptr) return false;
  output->clear();
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, 0, nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  FILE_ATTRIBUTE_TAG_INFO tag = {};
  LARGE_INTEGER size = {};
  const bool metadata_ok =
      GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag,
                                   sizeof(tag)) != FALSE &&
      (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
      (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
      GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0 &&
      static_cast<uint64_t>(size.QuadPart) <= maximum_bytes;
  if (!metadata_ok) {
    CloseHandle(file);
    return false;
  }
  output->resize(static_cast<size_t>(size.QuadPart));
  DWORD read = 0;
  const BOOL read_ok = output->empty() ||
                       ReadFile(file, output->data(),
                                static_cast<DWORD>(output->size()), &read,
                                nullptr);
  CloseHandle(file);
  const DWORD expected_size = static_cast<DWORD>(output->size());
  if (!read_ok || read != expected_size) {
    if (!output->empty()) SecureZeroMemory(output->data(), output->size());
    output->clear();
    return false;
  }
  return true;
}

bool WipeAndDeleteRegularFile(const std::wstring& path) {
  HANDLE file = CreateFileW(
      path.c_str(), GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES, 0, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS |
                         FILE_FLAG_WRITE_THROUGH,
      nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
  }
  FILE_ATTRIBUTE_TAG_INFO tag = {};
  LARGE_INTEGER size = {};
  bool ok = GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag,
                                         sizeof(tag)) != FALSE &&
            (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
            (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            GetFileSizeEx(file, &size) != FALSE && size.QuadPart >= 0 &&
            static_cast<uint64_t>(size.QuadPart) <=
                kMaximumSecureTextBytes + 1024 * 1024;
  std::vector<uint8_t> zeros(64 * 1024, 0);
  uint64_t remaining = ok ? static_cast<uint64_t>(size.QuadPart) : 0;
  while (ok && remaining > 0) {
    const DWORD chunk = static_cast<DWORD>(
        std::min<uint64_t>(remaining, zeros.size()));
    DWORD written = 0;
    ok = WriteFile(file, zeros.data(), chunk, &written, nullptr) != FALSE &&
         written == chunk;
    remaining -= ok ? chunk : 0;
  }
  if (ok) {
    LARGE_INTEGER origin = {};
    ok = SetFilePointerEx(file, origin, nullptr, FILE_BEGIN) != FALSE &&
          SetEndOfFile(file) != FALSE && FlushFileBuffers(file) != FALSE;
  }
  if (ok) {
    FILE_DISPOSITION_INFO_EX disposition = {};
    disposition.Flags = FILE_DISPOSITION_FLAG_DELETE |
                        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
                        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
    ok = SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition,
                                    sizeof(disposition)) != FALSE;
    if (!ok) {
      FILE_DISPOSITION_INFO fallback = {};
      fallback.DeleteFile = TRUE;
      ok = SetFileInformationByHandle(file, FileDispositionInfo, &fallback,
                                      sizeof(fallback)) != FALSE;
    }
  }
  CloseHandle(file);
  return ok;
}

std::wstring UniqueConfigPath(const std::wstring& directory,
                              const wchar_t* stem,
                              const wchar_t* extension) {
  for (int attempt = 0; attempt < 32; ++attempt) {
    const uint64_t nonce =
        g_secure_file_nonce.fetch_add(1, std::memory_order_relaxed) + 1;
    const std::wstring candidate =
        JoinPath(directory, std::wstring(stem) + L"." +
                                std::to_wstring(GetCurrentProcessId()) + L"." +
                                std::to_wstring(GetTickCount64()) + L"." +
                                std::to_wstring(nonce) + extension);
    if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) {
      return candidate;
    }
  }
  return L"";
}

#if !defined(WINS_TUNNEL_SERVICE_CORE)
bool IsAllowedSecureTextName(const std::string& name) {
  static const std::set<std::string> allowed = {
      "client_keypair.json", "calc_session.json", "calc_state.json",
      "install_id.txt", "node_cache.json",
      "pending_logout.json",
      "user_pin.txt",       "vpn_config.txt", "vpn_settings.txt",
      "wins_vpn_restart_config.conf",
      "winn3_keypair.json",
      "direct_udp_transport_memory.json",
  };
  return allowed.find(name) != allowed.end();
}

std::wstring SecureStateDirectory() {
  const std::wstring local_app_data = EnvVar(L"LOCALAPPDATA");
  if (local_app_data.empty()) return L"";
  return JoinPath(JoinPath(local_app_data, L"WinsVPN"), L"SecureState");
}

std::wstring LegacySecureTextPath(const std::string& name) {
  const std::wstring app_data = EnvVar(L"APPDATA");
  if (app_data.empty() || !IsAllowedSecureTextName(name)) return L"";
  return JoinPath(JoinPath(app_data, L"wins_vpn"), Utf8ToWide(name));
}

bool EnsureSecureStateDirectory(std::wstring* directory,
                                std::wstring* sddl) {
  if (directory == nullptr || sddl == nullptr ||
      !CurrentUserSystemDaclSddl(sddl)) {
    return false;
  }
  const std::wstring local_app_data = EnvVar(L"LOCALAPPDATA");
  const std::wstring parent = JoinPath(local_app_data, L"WinsVPN");
  *directory = SecureStateDirectory();
  return !local_app_data.empty() && !directory->empty() &&
         EnsureDirectory(parent) && EnsureDirectoryWithDacl(*directory, *sddl);
}

std::vector<uint8_t> DpapiEntropy(const std::string& name) {
  const std::string value = "WinsVPN:WindowsSecureText:v1:" + name;
  return std::vector<uint8_t>(value.begin(), value.end());
}

bool ProtectWindowsText(const std::string& name, const std::string& plaintext,
                        std::vector<uint8_t>* encoded) {
  if (encoded == nullptr || !IsAllowedSecureTextName(name) ||
      !IsValidUtf8Text(plaintext)) {
    return false;
  }
  encoded->clear();
  std::vector<uint8_t> entropy = DpapiEntropy(name);
  DATA_BLOB input = {
      static_cast<DWORD>(plaintext.size()),
      plaintext.empty()
          ? nullptr
          : reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data())),
  };
  DATA_BLOB entropy_blob = {static_cast<DWORD>(entropy.size()), entropy.data()};
  DATA_BLOB output = {};
  const BOOL ok = CryptProtectData(
      &input, L"Win's VPN secure state", &entropy_blob, nullptr, nullptr,
      CRYPTPROTECT_UI_FORBIDDEN, &output);
  if (!entropy.empty()) SecureZeroMemory(entropy.data(), entropy.size());
  if (!ok || output.pbData == nullptr || output.cbData == 0) {
    if (output.pbData != nullptr) LocalFree(output.pbData);
    return false;
  }
  encoded->insert(encoded->end(), std::begin(kDpapiFileMagic),
                  std::end(kDpapiFileMagic));
  encoded->insert(encoded->end(), output.pbData,
                  output.pbData + output.cbData);
  SecureZeroMemory(output.pbData, output.cbData);
  LocalFree(output.pbData);
  return true;
}

bool UnprotectWindowsText(const std::string& name,
                          const std::vector<uint8_t>& encoded,
                          std::string* plaintext) {
  if (plaintext == nullptr || !IsAllowedSecureTextName(name) ||
      encoded.size() <= sizeof(kDpapiFileMagic) ||
      !std::equal(std::begin(kDpapiFileMagic), std::end(kDpapiFileMagic),
                  encoded.begin())) {
    return false;
  }
  plaintext->clear();
  std::vector<uint8_t> entropy = DpapiEntropy(name);
  DATA_BLOB input = {
      static_cast<DWORD>(encoded.size() - sizeof(kDpapiFileMagic)),
      const_cast<BYTE*>(encoded.data() + sizeof(kDpapiFileMagic)),
  };
  DATA_BLOB entropy_blob = {static_cast<DWORD>(entropy.size()), entropy.data()};
  DATA_BLOB output = {};
  const BOOL ok = CryptUnprotectData(&input, nullptr, &entropy_blob, nullptr,
                                     nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                                     &output);
  if (!entropy.empty()) SecureZeroMemory(entropy.data(), entropy.size());
  if (!ok || output.cbData > kMaximumSecureTextBytes ||
      (output.cbData != 0 && output.pbData == nullptr)) {
    if (output.pbData != nullptr) {
      SecureZeroMemory(output.pbData, output.cbData);
      LocalFree(output.pbData);
    }
    return false;
  }
  plaintext->assign(reinterpret_cast<const char*>(output.pbData),
                    output.cbData);
  if (output.pbData != nullptr) {
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
  }
  if (!IsValidUtf8Text(*plaintext)) {
    WipeString(plaintext);
    return false;
  }
  return true;
}

bool WriteEncryptedWindowsTextAtPath(const std::string& name,
                                     const std::string& plaintext,
                                     const std::wstring& path,
                                     const std::wstring& sddl) {
  std::vector<uint8_t> encoded;
  if (!ProtectWindowsText(name, plaintext, &encoded)) return false;
  const bool written = WriteBytesSecureAtomic(path, encoded.data(),
                                              encoded.size(), sddl);
  if (!encoded.empty()) SecureZeroMemory(encoded.data(), encoded.size());
  return written;
}

bool HasStrictCurrentUserSystemDacl(const std::wstring& path);

bool RetireLegacyPlaintextFile(const std::wstring& legacy_path,
                               std::string* plaintext, std::string* error) {
  if (plaintext == nullptr || error == nullptr) return false;
  if (legacy_path.empty()) return true;
  if (WipeAndDeleteRegularFile(legacy_path)) return true;
  WipeString(plaintext);
  *error = "Legacy secure text cleanup failed closed; retry is required.";
  return false;
}

bool WriteWindowsSecureText(const std::string& name,
                            const std::string& plaintext,
                            std::string* error) {
  if (error == nullptr || !IsAllowedSecureTextName(name) ||
      !IsValidUtf8Text(plaintext)) {
    if (error != nullptr) *error = "Secure text name or value is invalid.";
    return false;
  }
  std::wstring directory;
  std::wstring sddl;
  if (!EnsureSecureStateDirectory(&directory, &sddl) ||
      !WriteEncryptedWindowsTextAtPath(
          name, plaintext, JoinPath(directory, Utf8ToWide(name) + L".wvdp"),
          sddl)) {
    *error = "Unable to protect secure text with Windows DPAPI.";
    return false;
  }
  return true;
}

bool ReadWindowsSecureText(const std::string& name, std::string* plaintext,
                           bool* found, std::string* error) {
  if (plaintext == nullptr || found == nullptr || error == nullptr ||
      !IsAllowedSecureTextName(name)) {
    if (error != nullptr) *error = "Secure text name is invalid.";
    return false;
  }
  plaintext->clear();
  *found = false;
  std::wstring directory;
  std::wstring sddl;
  if (!EnsureSecureStateDirectory(&directory, &sddl)) {
    *error = "Unable to secure the Windows secure-text directory.";
    return false;
  }
  const std::wstring secure_path =
      JoinPath(directory, Utf8ToWide(name) + L".wvdp");
  const std::wstring legacy_path = LegacySecureTextPath(name);
  if (!secure_path.empty() && FileExists(secure_path)) {
    if (!HasStrictCurrentUserSystemDacl(secure_path)) {
      *error = "Stored secure text has an invalid access-control policy.";
      return false;
    }
    std::vector<uint8_t> encoded;
    const bool read = ReadRegularFileBounded(
        secure_path, kMaximumSecureTextBytes + 1024 * 1024, &encoded);
    const bool decrypted = read && UnprotectWindowsText(name, encoded, plaintext);
    if (!encoded.empty()) SecureZeroMemory(encoded.data(), encoded.size());
    if (!decrypted) {
      *error = "Stored secure text failed Windows DPAPI validation.";
      return false;
    }
    if (!RetireLegacyPlaintextFile(legacy_path, plaintext, error)) {
      return false;
    }
    *found = true;
    return true;
  }

  if (legacy_path.empty() || !FileExists(legacy_path)) return true;
  std::vector<uint8_t> legacy_bytes;
  if (!ReadRegularFileBounded(legacy_path, kMaximumSecureTextBytes,
                              &legacy_bytes)) {
    *error = "Legacy secure text is not a bounded regular file.";
    return false;
  }
  plaintext->assign(reinterpret_cast<const char*>(legacy_bytes.data()),
                    legacy_bytes.size());
  if (!legacy_bytes.empty()) {
    SecureZeroMemory(legacy_bytes.data(), legacy_bytes.size());
  }
  if (!IsValidUtf8Text(*plaintext) ||
      !WriteWindowsSecureText(name, *plaintext, error)) {
    WipeString(plaintext);
    if (error->empty()) *error = "Legacy secure text migration failed closed.";
    return false;
  }
  if (!RetireLegacyPlaintextFile(legacy_path, plaintext, error)) return false;
  *found = true;
  return true;
}

bool DeleteWindowsSecureText(const std::string& name, std::string* error) {
  if (error == nullptr || !IsAllowedSecureTextName(name)) {
    if (error != nullptr) *error = "Secure text name is invalid.";
    return false;
  }
  std::wstring directory;
  std::wstring sddl;
  if (!EnsureSecureStateDirectory(&directory, &sddl)) {
    *error = "Unable to secure the Windows secure-text directory.";
    return false;
  }
  const std::wstring secure_path =
      JoinPath(directory, Utf8ToWide(name) + L".wvdp");
  if (!secure_path.empty() && FileExists(secure_path) &&
      !WipeAndDeleteRegularFile(secure_path)) {
    *error = "Unable to remove protected secure text.";
    return false;
  }
  const std::wstring legacy_path = LegacySecureTextPath(name);
  if (!legacy_path.empty() && FileExists(legacy_path) &&
      !WipeAndDeleteRegularFile(legacy_path)) {
    *error = "Unable to remove legacy secure text.";
    return false;
  }
  return true;
}

bool HasStrictCurrentUserSystemDacl(const std::wstring& path) {
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  const DWORD status = GetNamedSecurityInfoW(
      const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr,
      &descriptor);
  if (status != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
    if (descriptor != nullptr) LocalFree(descriptor);
    return false;
  }
  SECURITY_DESCRIPTOR_CONTROL control = 0;
  DWORD revision = 0;
  ACL_SIZE_INFORMATION info = {};
  bool valid = GetSecurityDescriptorControl(descriptor, &control,
                                            &revision) != FALSE &&
               (control & SE_DACL_PROTECTED) != 0 &&
               GetAclInformation(dacl, &info, sizeof(info),
                                 AclSizeInformation) != FALSE &&
               info.AceCount == 2;

  HANDLE token = nullptr;
  DWORD user_bytes = 0;
  std::vector<uint8_t> user_buffer;
  if (valid && OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    GetTokenInformation(token, TokenUser, nullptr, 0, &user_bytes);
    user_buffer.resize(user_bytes);
    DWORD returned = 0;
    valid = user_bytes > 0 &&
            GetTokenInformation(token, TokenUser, user_buffer.data(),
                                user_bytes, &returned) != FALSE;
    CloseHandle(token);
  } else {
    valid = false;
  }
  BYTE system_sid_buffer[SECURITY_MAX_SID_SIZE] = {};
  DWORD system_sid_size = sizeof(system_sid_buffer);
  valid = valid &&
           CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid_buffer,
                              &system_sid_size) != FALSE;
  bool found_user = false;
  bool found_system = false;
  for (DWORD index = 0; valid && index < info.AceCount; ++index) {
    void* raw_ace = nullptr;
    valid = GetAce(dacl, index, &raw_ace) != FALSE && raw_ace != nullptr;
    if (!valid) break;
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
    PSID sid = const_cast<DWORD*>(&ace->SidStart);
    const auto* user =
        reinterpret_cast<const TOKEN_USER*>(user_buffer.data());
    const bool is_user = EqualSid(sid, user->User.Sid) != FALSE;
    const bool is_system = EqualSid(sid, system_sid_buffer) != FALSE;
    valid = ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            (ace->Header.AceFlags & INHERITED_ACE) == 0 &&
            ace->Mask == FILE_ALL_ACCESS && (is_user != is_system) &&
            !(is_user && found_user) && !(is_system && found_system);
    found_user = found_user || is_user;
    found_system = found_system || is_system;
  }
  LocalFree(descriptor);
  return valid && found_user && found_system;
}
#endif

bool CompleteOverlappedPipeIo(HANDLE pipe,
                              OVERLAPPED* overlapped,
                              DWORD timeout_ms,
                              DWORD* transferred) {
  if (overlapped == nullptr || overlapped->hEvent == nullptr ||
      transferred == nullptr) {
    return false;
  }
  if (WaitForSingleObject(overlapped->hEvent, timeout_ms) != WAIT_OBJECT_0) {
    CancelIoEx(pipe, overlapped);
    DWORD canceled_bytes = 0;
    GetOverlappedResult(pipe, overlapped, &canceled_bytes, TRUE);
    return false;
  }
  return GetOverlappedResult(pipe, overlapped, transferred, FALSE) != FALSE;
}

bool WritePipeBounded(HANDLE pipe,
                      const char* bytes,
                      DWORD size,
                      DWORD timeout_ms) {
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (overlapped.hEvent == nullptr) return false;
  DWORD written = 0;
  bool ok = WriteFile(pipe, bytes, size, &written, &overlapped) != FALSE;
  if (!ok && GetLastError() == ERROR_IO_PENDING) {
    ok = CompleteOverlappedPipeIo(pipe, &overlapped, timeout_ms, &written);
  }
  CloseHandle(overlapped.hEvent);
  return ok && written == size;
}

bool ReadPipeBounded(HANDLE pipe,
                     char* bytes,
                     DWORD capacity,
                     DWORD timeout_ms,
                     DWORD* read) {
  if (read == nullptr) return false;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (overlapped.hEvent == nullptr) return false;
  *read = 0;
  bool ok = ReadFile(pipe, bytes, capacity, read, &overlapped) != FALSE;
  if (!ok && GetLastError() == ERROR_IO_PENDING) {
    ok = CompleteOverlappedPipeIo(pipe, &overlapped, timeout_ms, read);
  }
  CloseHandle(overlapped.hEvent);
  return ok;
}

bool ReadAwgRuntimeUapi(std::string* response,
                        DWORD readiness_timeout_ms = winsvpn::tunnel_service::
                            kAwgUapiReadinessTimeoutMilliseconds) {
  if (response == nullptr) return false;
  response->clear();
  std::wstring pipe_path =
      LR"(\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\)";
  pipe_path += kTunnelName;
  const ULONGLONG readiness_deadline =
      GetTickCount64() + readiness_timeout_ms;
  HANDLE pipe = INVALID_HANDLE_VALUE;
  for (;;) {
    pipe = CreateFileW(
        pipe_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
        nullptr);
    if (pipe != INVALID_HANDLE_VALUE) break;
    if (GetTickCount64() >= readiness_deadline) return false;
    if (GetLastError() == ERROR_PIPE_BUSY) {
      WaitNamedPipeW(pipe_path.c_str(), 200);
    } else {
      Sleep(100);
    }
  }

  constexpr char request[] = "get=1\n\n";
  if (!WritePipeBounded(pipe, request,
                        static_cast<DWORD>(sizeof(request) - 1),
                        winsvpn::tunnel_service::
                            kAwgUapiWriteTimeoutMilliseconds)) {
    CloseHandle(pipe);
    return false;
  }
  constexpr size_t kMaximumResponse = 64 * 1024;
  const ULONGLONG response_deadline =
      GetTickCount64() +
      winsvpn::tunnel_service::kAwgUapiResponseTimeoutMilliseconds;
  while (response->size() < kMaximumResponse) {
    char buffer[4096] = {};
    DWORD read = 0;
    const ULONGLONG now = GetTickCount64();
    if (now >= response_deadline ||
        !ReadPipeBounded(
            pipe, buffer, static_cast<DWORD>(sizeof(buffer)),
            static_cast<DWORD>(std::min<ULONGLONG>(
                winsvpn::tunnel_service::kAwgUapiWriteTimeoutMilliseconds,
                response_deadline - now)),
            &read) ||
        read == 0) {
      CloseHandle(pipe);
      response->clear();
      return false;
    }
    response->append(buffer, read);
    if (response->size() >= 2 &&
        response->compare(response->size() - 2, 2, "\n\n") == 0) {
      CloseHandle(pipe);
      return true;
    }
  }
  CloseHandle(pipe);
  response->clear();
  return false;
}

#if defined(WINS_TUNNEL_SERVICE_CORE)
void CloseAwgEngineHandles() {
  if (g_awg_engine_process.hThread != nullptr) {
    CloseHandle(g_awg_engine_process.hThread);
  }
  if (g_awg_engine_process.hProcess != nullptr) {
    CloseHandle(g_awg_engine_process.hProcess);
  }
  if (g_awg_engine_job != nullptr) {
    CloseHandle(g_awg_engine_job);
  }
  g_awg_engine_process = {};
  g_awg_engine_job = nullptr;
}

bool IsWinsAwgEngineRunning() {
  return g_awg_engine_process.hProcess != nullptr &&
         WaitForSingleObject(g_awg_engine_process.hProcess, 0) == WAIT_TIMEOUT;
}

bool StopWinsAwgEngine() {
  HANDLE stop_event =
      OpenEventW(EVENT_MODIFY_STATE, FALSE, kAwgEngineStopEvent);
  if (stop_event != nullptr) {
    SetEvent(stop_event);
    CloseHandle(stop_event);
  }

  bool stopped = true;
  if (g_awg_engine_process.hProcess != nullptr) {
    DWORD wait = WaitForSingleObject(
        g_awg_engine_process.hProcess,
        winsvpn::tunnel_service::kAwgEngineStopWaitMilliseconds);
    if (wait == WAIT_TIMEOUT) {
      if (g_awg_engine_job != nullptr) {
        TerminateJobObject(g_awg_engine_job, 1);
      } else {
        TerminateProcess(g_awg_engine_process.hProcess, 1);
      }
      wait = WaitForSingleObject(
          g_awg_engine_process.hProcess,
          winsvpn::tunnel_service::kAwgEngineStopWaitMilliseconds);
    }
    stopped = wait == WAIT_OBJECT_0;
  } else if (stop_event != nullptr) {
    // A manager restart should terminate its kill-on-close job. This bounded
    // wait also cleans up a previously requested graceful shutdown.
    Sleep(500);
  }
  CloseAwgEngineHandles();
  return stopped;
}

bool StartWinsAwgEngine(const std::wstring& config_path,
                        std::string* error) {
  if (!StopWinsAwgEngine()) {
    *error = "Unable to stop the previous Win's VPN AWG engine safely.";
    return false;
  }
  const std::wstring engine = FindWinsAwgEngineExecutable();
  const std::wstring awg_tool = FindAwgToolExecutable();
  const std::wstring runtime_directory = ModuleDirectory();
  if (engine.empty() || awg_tool.empty() || runtime_directory.empty() ||
      !FileExists(JoinPath(runtime_directory, L"wintun.dll"))) {
    *error = "The pinned Win's VPN AWG engine payload is incomplete.";
    return false;
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits = {};
  job_limits.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == nullptr ||
      !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &job_limits, sizeof(job_limits))) {
    if (job != nullptr) CloseHandle(job);
    *error = "Unable to create the AWG engine lifetime boundary.";
    return false;
  }

  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  std::wstring command = Quote(engine);
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  PROCESS_INFORMATION process = {};
  if (!CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                      runtime_directory.c_str(), &startup, &process) ||
      !AssignProcessToJobObject(job, process.hProcess) ||
      ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
    if (process.hProcess != nullptr) {
      TerminateProcess(process.hProcess, 1);
      WaitForSingleObject(process.hProcess, 3000);
      CloseHandle(process.hProcess);
    }
    if (process.hThread != nullptr) CloseHandle(process.hThread);
    CloseHandle(job);
    *error = "Unable to launch the pinned Win's VPN AWG engine.";
    return false;
  }
  CloseHandle(process.hThread);
  process.hThread = nullptr;
  g_awg_engine_process = process;
  g_awg_engine_job = job;

  std::string readiness;
  ScopedStringWipe wipe_readiness(&readiness);
  if (!ReadAwgRuntimeUapi(
          &readiness,
          winsvpn::tunnel_service::kAwgUapiReadinessTimeoutMilliseconds)) {
    StopWinsAwgEngine();
    *error = "The Win's VPN AWG engine did not expose its protected UAPI.";
    return false;
  }
  const ProcessResult configured =
      RunCommand(Quote(awg_tool) + L" setconf " + Quote(kTunnelName) + L" " +
                     Quote(config_path),
                 winsvpn::tunnel_service::kAwgSetconfTimeoutMilliseconds);
  if (!configured.started || configured.exit_code != 0) {
    StopWinsAwgEngine();
    *error = "The Win's VPN AWG engine rejected the tunnel configuration.";
    return false;
  }
  return true;
}

bool ConfigureWinsAwgInterface(const std::string& raw_config,
                               std::string* error) {
  if (error == nullptr) return false;
  const auto interface_config = ParseSection(raw_config, "interface");
  const std::string address_value = SectionValue(interface_config, "address");
  const size_t slash = address_value.find('/');
  if (slash == std::string::npos || slash == 0 ||
      slash + 1 >= address_value.size()) {
    *error = "The Windows tunnel address is invalid.";
    return false;
  }
  const std::string address = address_value.substr(0, slash);
  const std::string prefix_text = address_value.substr(slash + 1);
  char* prefix_end = nullptr;
  const long prefix = std::strtol(prefix_text.c_str(), &prefix_end, 10);
  IN_ADDR parsed_address = {};
  if (prefix_end == prefix_text.c_str() || *prefix_end != '\0' ||
      prefix < 1 || prefix > 32 ||
      InetPtonA(AF_INET, address.c_str(), &parsed_address) != 1) {
    *error = "The Windows tunnel address is not a usable IPv4 prefix.";
    return false;
  }
  const std::string mtu_text = SectionValue(interface_config, "mtu", "1420");
  char* mtu_end = nullptr;
  const long mtu = std::strtol(mtu_text.c_str(), &mtu_end, 10);
  if (mtu_end == mtu_text.c_str() || *mtu_end != '\0' ||
      mtu < 1280 || mtu > 9000) {
    *error = "The Windows tunnel MTU is invalid.";
    return false;
  }
  std::string dns_text = SectionValue(interface_config, "dns");
  std::replace(dns_text.begin(), dns_text.end(), ',', ' ');
  std::istringstream dns_stream(dns_text);
  std::vector<std::string> dns_addresses;
  std::string dns_address;
  while (dns_stream >> dns_address) {
    IN_ADDR parsed_dns = {};
    if (InetPtonA(AF_INET, dns_address.c_str(), &parsed_dns) != 1) {
      *error = "The Windows tunnel DNS list contains a non-IPv4 address.";
      return false;
    }
    dns_addresses.push_back(dns_address);
  }
  if (dns_addresses.empty() || dns_addresses.size() > 4) {
    *error = "The Windows tunnel DNS list is empty or too large.";
    return false;
  }

  NET_LUID interface_luid = {};
  const ULONGLONG deadline =
      GetTickCount64() +
      winsvpn::tunnel_service::kAwgAdapterReadinessTimeoutMilliseconds;
  while (ConvertInterfaceAliasToLuid(kTunnelName, &interface_luid) != NO_ERROR) {
    if (GetTickCount64() >= deadline) {
      *error = "The Windows AWG adapter alias did not become available.";
      return false;
    }
    Sleep(10);
  }

  MIB_UNICASTIPADDRESS_ROW address_row = {};
  InitializeUnicastIpAddressEntry(&address_row);
  address_row.InterfaceLuid = interface_luid;
  address_row.Address.Ipv4.sin_family = AF_INET;
  address_row.Address.Ipv4.sin_addr = parsed_address;
  address_row.OnLinkPrefixLength = static_cast<UINT8>(prefix);
  address_row.PrefixOrigin = IpPrefixOriginManual;
  address_row.SuffixOrigin = IpSuffixOriginManual;
  address_row.ValidLifetime = 0xffffffff;
  address_row.PreferredLifetime = 0xffffffff;
  const DWORD address_result = CreateUnicastIpAddressEntry(&address_row);
  if (address_result != NO_ERROR && address_result != ERROR_OBJECT_ALREADY_EXISTS) {
    *error = "Unable to assign the Windows tunnel IPv4 address.";
    return false;
  }

  MIB_IPINTERFACE_ROW interface_row = {};
  InitializeIpInterfaceEntry(&interface_row);
  interface_row.Family = AF_INET;
  interface_row.InterfaceLuid = interface_luid;
  if (GetIpInterfaceEntry(&interface_row) != NO_ERROR) {
    *error = "Unable to read the Windows tunnel interface settings.";
    return false;
  }
  interface_row.NlMtu = static_cast<ULONG>(mtu);
  interface_row.SitePrefixLength = 0;
  if (SetIpInterfaceEntry(&interface_row) != NO_ERROR) {
    *error = "Unable to apply the Windows tunnel MTU.";
    return false;
  }

  std::wstring name_servers;
  for (const std::string& dns : dns_addresses) {
    if (!name_servers.empty()) name_servers += L",";
    name_servers += Utf8ToWide(dns);
  }
  GUID interface_guid = {};
  if (ConvertInterfaceLuidToGuid(&interface_luid, &interface_guid) != NO_ERROR) {
    *error = "Unable to identify the Windows tunnel DNS interface.";
    return false;
  }
  DNS_INTERFACE_SETTINGS dns_settings = {};
  dns_settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
  dns_settings.Flags = DNS_SETTING_NAMESERVER;
  dns_settings.NameServer = name_servers.data();
  if (SetInterfaceDnsSettings(interface_guid, &dns_settings) != NO_ERROR) {
    *error = "Unable to apply the Windows tunnel DNS servers.";
    return false;
  }
  return true;
}
#endif

bool IsLowerHexKey(const std::string& value) {
  return value.size() == 64 &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}

bool Base64KeyToLowerHex(const std::string& encoded, std::string* hex) {
  if (hex == nullptr || encoded.empty()) return false;
  DWORD decoded_size = 0;
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, nullptr,
                            &decoded_size, nullptr, nullptr) ||
      decoded_size != 32) {
    return false;
  }
  std::vector<BYTE> decoded(decoded_size);
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
                            decoded.data(), &decoded_size, nullptr, nullptr) ||
      decoded_size != 32) {
    SecureZeroMemory(decoded.data(), decoded.size());
    return false;
  }
  constexpr char digits[] = "0123456789abcdef";
  hex->resize(decoded_size * 2);
  for (size_t i = 0; i < decoded_size; ++i) {
    (*hex)[i * 2] = digits[decoded[i] >> 4];
    (*hex)[i * 2 + 1] = digits[decoded[i] & 0x0f];
  }
  SecureZeroMemory(decoded.data(), decoded.size());
  return true;
}

struct AwgRuntimePeer {
  std::string public_key;
  std::string preshared_key;
  std::string endpoint;
  std::vector<std::string> allowed_ips;
  uint64_t last_handshake_time_sec = 0;
  uint64_t rx_bytes = 0;
  uint64_t tx_bytes = 0;
  bool has_last_handshake_time_sec = false;
  bool has_rx_bytes = false;
  bool has_tx_bytes = false;
};

struct AwgRuntimeSnapshot {
  std::string private_key;
  uint64_t listen_port = 0;
  bool has_listen_port = false;
  std::map<std::string, std::string> obfuscation;
  std::vector<AwgRuntimePeer> peers;
  bool errno_zero = false;

  ~AwgRuntimeSnapshot() {
    WipeString(&private_key);
    for (auto& peer : peers) WipeString(&peer.preshared_key);
  }
};

constexpr uint64_t kMinimumConvergenceTransferBytes = 32;
constexpr uint64_t kMaximumConvergenceHandshakeAgeSeconds = 30;

bool HasNontrivialIncrease(uint64_t current,
                           uint64_t baseline,
                           uint64_t minimum_increase) {
  return current >= baseline && current - baseline >= minimum_increase;
}

bool IsAwgPeerConverged(const AwgRuntimePeer& peer,
                        uint64_t baseline_rx,
                        uint64_t baseline_tx,
                        uint64_t earliest_handshake_unix,
                        uint64_t now_unix) {
  const uint64_t earliest_accepted =
      earliest_handshake_unix > 2 ? earliest_handshake_unix - 2 : 0;
  const bool clock_sane =
      peer.last_handshake_time_sec <= now_unix
          ? now_unix - peer.last_handshake_time_sec <=
                kMaximumConvergenceHandshakeAgeSeconds
          : peer.last_handshake_time_sec - now_unix <= 5;
  return peer.has_last_handshake_time_sec && peer.has_rx_bytes &&
         peer.has_tx_bytes && peer.last_handshake_time_sec > 0 &&
         peer.last_handshake_time_sec >= earliest_accepted && clock_sane &&
         HasNontrivialIncrease(peer.rx_bytes, baseline_rx,
                               kMinimumConvergenceTransferBytes) &&
         HasNontrivialIncrease(peer.tx_bytes, baseline_tx,
                               kMinimumConvergenceTransferBytes);
}

bool AssignOnce(std::string* target, const std::string& value) {
  if (target == nullptr || !target->empty() || value.empty()) return false;
  *target = value;
  return true;
}

bool ParseUnsignedDecimalOnce(const std::string& value,
                              uint64_t* target,
                              bool* assigned) {
  if (target == nullptr || assigned == nullptr || *assigned || value.empty()) {
    return false;
  }
  uint64_t parsed = 0;
  for (const unsigned char c : value) {
    if (c < '0' || c > '9') return false;
    const uint64_t digit = static_cast<uint64_t>(c - '0');
    if (parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
      return false;
    }
    parsed = parsed * 10 + digit;
  }
  *target = parsed;
  *assigned = true;
  return true;
}

bool ParseAllowedIpSet(const std::string& raw,
                       std::set<std::string>* parsed) {
  if (parsed == nullptr) return false;
  parsed->clear();
  std::istringstream stream(raw);
  std::string item;
  while (std::getline(stream, item, ',')) {
    const std::string value = LowerAscii(Trim(item));
    if (value.empty() || value.size() > 64) return false;
    const size_t slash = value.rfind('/');
    if (slash == std::string::npos || slash == 0 ||
        slash + 1 >= value.size()) {
      return false;
    }
    const std::string address = value.substr(0, slash);
    const std::string prefix_text = value.substr(slash + 1);
    if (!std::all_of(prefix_text.begin(), prefix_text.end(),
                     [](unsigned char c) { return std::isdigit(c) != 0; })) {
      return false;
    }
    const unsigned long prefix =
        std::strtoul(prefix_text.c_str(), nullptr, 10);
    const bool ipv6 = address.find(':') != std::string::npos;
    if ((ipv6 && prefix > 128) || (!ipv6 && prefix > 32)) return false;
    const bool address_shape_valid = std::all_of(
        address.begin(), address.end(), [ipv6](unsigned char c) {
          return ipv6 ? std::isxdigit(c) != 0 || c == ':'
                      : std::isdigit(c) != 0 || c == '.';
        });
    if (!address_shape_valid ||
        (ipv6 ? address.find(':') == std::string::npos
              : address.find('.') == std::string::npos) ||
        !parsed->insert(value).second) {
      return false;
    }
  }
  return !parsed->empty();
}

bool ParseAwgRuntimeUapi(const std::string& response,
                         AwgRuntimeSnapshot* snapshot) {
  if (snapshot == nullptr || response.size() > 64 * 1024) return false;
  std::istringstream stream(response);
  std::string line;
  AwgRuntimePeer* peer = nullptr;
  bool terminated = false;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) {
      terminated = true;
      break;
    }
    const size_t equals = line.find('=');
    if (equals == std::string::npos || equals == 0 || equals > 64 ||
        line.size() - equals - 1 > 2048) {
      return false;
    }
    const std::string key = line.substr(0, equals);
    const std::string value = line.substr(equals + 1);
    if (key == "errno") {
      if (snapshot->errno_zero || value != "0") return false;
      snapshot->errno_zero = true;
    } else if (key == "private_key" && peer == nullptr) {
      if (!IsLowerHexKey(value) ||
          !AssignOnce(&snapshot->private_key, value)) {
        return false;
      }
    } else if (key == "listen_port" && peer == nullptr) {
      if (!ParseUnsignedDecimalOnce(value, &snapshot->listen_port,
                                    &snapshot->has_listen_port)) {
        return false;
      }
    } else if (key == "public_key") {
      if (!IsLowerHexKey(value)) return false;
      snapshot->peers.push_back({});
      peer = &snapshot->peers.back();
      peer->public_key = value;
    } else if (key == "preshared_key" && peer != nullptr) {
      if (!IsLowerHexKey(value) || !AssignOnce(&peer->preshared_key, value)) {
        return false;
      }
    } else if (key == "endpoint" && peer != nullptr) {
      if (!AssignOnce(&peer->endpoint, value)) return false;
    } else if (key == "allowed_ip" && peer != nullptr) {
      std::set<std::string> parsed;
      if (!ParseAllowedIpSet(value, &parsed) || parsed.size() != 1) {
        return false;
      }
      const std::string normalized = *parsed.begin();
      if (std::find(peer->allowed_ips.begin(), peer->allowed_ips.end(),
                    normalized) != peer->allowed_ips.end()) {
        return false;
      }
      peer->allowed_ips.push_back(normalized);
    } else if (key == "last_handshake_time_sec" && peer != nullptr) {
      if (!ParseUnsignedDecimalOnce(value, &peer->last_handshake_time_sec,
                                    &peer->has_last_handshake_time_sec)) {
        return false;
      }
    } else if (key == "rx_bytes" && peer != nullptr) {
      if (!ParseUnsignedDecimalOnce(value, &peer->rx_bytes,
                                    &peer->has_rx_bytes)) {
        return false;
      }
    } else if (key == "tx_bytes" && peer != nullptr) {
      if (!ParseUnsignedDecimalOnce(value, &peer->tx_bytes,
                                    &peer->has_tx_bytes)) {
        return false;
      }
    } else if (peer == nullptr &&
               (key == "jc" || key == "jmin" || key == "jmax" ||
                key == "s1" || key == "s2" || key == "s3" ||
                key == "s4" || key == "h1" || key == "h2" ||
                key == "h3" || key == "h4")) {
      if (value.empty() || !snapshot->obfuscation.emplace(key, value).second) {
        return false;
      }
    }
  }
  return terminated && snapshot->errno_zero &&
         IsLowerHexKey(snapshot->private_key) && !snapshot->peers.empty();
}

bool ParseEndpoint(const std::string& endpoint,
                   std::string* host,
                   std::string* service) {
  if (host == nullptr || service == nullptr || endpoint.empty()) return false;
  host->clear();
  service->clear();
  if (endpoint.front() == '[') {
    const size_t close = endpoint.find(']');
    if (close == std::string::npos || close <= 1 ||
        close + 2 >= endpoint.size() || endpoint[close + 1] != ':') {
      return false;
    }
    *host = endpoint.substr(1, close - 1);
    *service = endpoint.substr(close + 2);
  } else {
    const size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || colon == 0 ||
        colon + 1 >= endpoint.size()) {
      return false;
    }
    *host = endpoint.substr(0, colon);
    *service = endpoint.substr(colon + 1);
  }
  if (host->empty() || service->empty() || service->size() > 5) return false;
  uint32_t port = 0;
  for (const unsigned char c : *service) {
    if (!std::isdigit(c)) return false;
    port = port * 10 + static_cast<uint32_t>(c - '0');
    if (port > 65535) return false;
  }
  return port > 0;
}

std::set<std::string> ResolveEndpointAddresses(const std::string& host,
                                               const std::string& service) {
  std::set<std::string> addresses;
  addrinfo hints = {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &result) != 0 ||
      result == nullptr) {
    return addresses;
  }
  for (const addrinfo* current = result; current != nullptr;
       current = current->ai_next) {
    char numeric_host[NI_MAXHOST] = {};
    if (getnameinfo(current->ai_addr, static_cast<socklen_t>(current->ai_addrlen),
                    numeric_host, sizeof(numeric_host), nullptr, 0,
                    NI_NUMERICHOST) == 0) {
      addresses.insert(LowerAscii(numeric_host));
    }
  }
  freeaddrinfo(result);
  return addresses;
}

bool EndpointsMatch(const std::string& loaded,
                    const std::string& configured) {
  if (LowerAscii(loaded) == LowerAscii(configured)) return true;
  std::string loaded_host;
  std::string loaded_service;
  std::string configured_host;
  std::string configured_service;
  if (!ParseEndpoint(loaded, &loaded_host, &loaded_service) ||
      !ParseEndpoint(configured, &configured_host, &configured_service) ||
      loaded_service != configured_service) {
    return false;
  }
  WSADATA data = {};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
  const std::set<std::string> loaded_addresses =
      ResolveEndpointAddresses(loaded_host, loaded_service);
  const std::set<std::string> configured_addresses =
      ResolveEndpointAddresses(configured_host, configured_service);
  WSACleanup();
  if (loaded_addresses.empty() || configured_addresses.empty()) return false;
  for (const std::string& address : loaded_addresses) {
    if (configured_addresses.find(address) != configured_addresses.end()) {
      return true;
    }
  }
  return false;
}

// `expected_endpoint_override` is empty on every AmneziaWG start and carries
// the loopback seam ("127.0.0.1:<port>") on a Winn start.
//
// This is not a loosening. It is the proof that the seam took effect: on a
// winn/3 tunnel the running AWG engine MUST have loaded the loopback endpoint,
// because that is where its outer datagrams have to go for Winn to be carrying
// anything. An AWG runtime that loaded the real gateway instead would be
// sending its own outer datagrams straight out of the physical NIC while this
// host believed they were being carried -- a silent downgrade of a winn/3
// negotiation to plain AmneziaWG, which is precisely what must never happen.
bool ValidateLoadedAwgRuntime(const std::string& raw_config,
                              const std::string& expected_endpoint_override,
                              std::string* error) {
  if (error == nullptr) return false;
  const auto interface_config = ParseSection(raw_config, "interface");
  const auto peer_config = ParseSection(raw_config, "peer");
  std::string expected_private;
  ScopedStringWipe wipe_expected_private(&expected_private);
  if (!Base64KeyToLowerHex(SectionValue(interface_config, "privatekey"),
                           &expected_private)) {
    *error = "The Windows tunnel configuration has an invalid client identity.";
    return false;
  }
  std::string expected_peer;
  if (!Base64KeyToLowerHex(SectionValue(peer_config, "publickey"),
                           &expected_peer)) {
    *error = "The Windows tunnel configuration has an invalid server identity.";
    return false;
  }
  std::string expected_psk(64, '0');
  ScopedStringWipe wipe_expected_psk(&expected_psk);
  const std::string configured_psk = SectionValue(peer_config, "presharedkey");
  if (!configured_psk.empty() &&
      !Base64KeyToLowerHex(configured_psk, &expected_psk)) {
    *error = "The Windows tunnel configuration has an invalid preshared key.";
    return false;
  }
  const std::string expected_endpoint =
      expected_endpoint_override.empty()
          ? SectionValue(peer_config, "endpoint")
          : expected_endpoint_override;
  if (expected_endpoint.empty()) {
    *error = "The Windows tunnel configuration has no server endpoint.";
    return false;
  }

  std::string response;
  ScopedStringWipe wipe_response(&response);
  if (!ReadAwgRuntimeUapi(&response)) {
    *error =
        "The protected Windows AWG runtime was not readable after startup.";
    return false;
  }
  AwgRuntimeSnapshot runtime;
  if (!ParseAwgRuntimeUapi(response, &runtime)) {
    *error = "The protected Windows AWG runtime response was invalid.";
    return false;
  }
  if (runtime.private_key != expected_private) {
    *error = "The Windows AWG runtime loaded a different client identity.";
    return false;
  }
  if (runtime.peers.size() != 1 || runtime.peers[0].public_key != expected_peer) {
    *error = "The Windows AWG runtime loaded a different server peer.";
    return false;
  }
  if (runtime.peers[0].preshared_key != expected_psk) {
    *error = "The Windows AWG runtime loaded a different preshared key.";
    return false;
  }
  if (!EndpointsMatch(runtime.peers[0].endpoint, expected_endpoint)) {
    *error = "The Windows AWG runtime loaded a different peer endpoint.";
    return false;
  }
  std::set<std::string> expected_allowed;
  if (!ParseAllowedIpSet(SectionValue(peer_config, "allowedips"),
                         &expected_allowed)) {
    *error = "The Windows tunnel configuration has no usable AllowedIPs.";
    return false;
  }
  std::set<std::string> loaded_allowed(runtime.peers[0].allowed_ips.begin(),
                                       runtime.peers[0].allowed_ips.end());
  if (loaded_allowed.empty()) {
    *error = "The Windows AWG runtime loaded no AllowedIPs for peer lookup.";
    return false;
  }
  if (loaded_allowed != expected_allowed) {
    *error = "The Windows AWG runtime loaded different AllowedIPs.";
    return false;
  }
  for (const std::string& key : {
           "jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
           "h1", "h2", "h3", "h4",
       }) {
    const std::string expected = SectionValue(interface_config, key);
    const auto loaded = runtime.obfuscation.find(key);
    // AmneziaWG's protected UAPI deliberately omits zero-valued numeric
    // fields. The installed config still contains the explicit zero, so use
    // the serializer's documented zero default for an omitted field.
    const std::string loaded_value =
        loaded == runtime.obfuscation.end() ? "0" : loaded->second;
    if (expected.empty() || loaded_value != expected) {
      *error =
          "The Windows AWG runtime loaded different obfuscation parameters.";
      return false;
    }
  }
  return true;
}

// The running AmneziaWG runtime's own UDP port, from its UAPI. It is the only
// loopback source the Winn seam admits, so it is read from the runtime rather
// than learned from whichever local process reaches the seam first.
bool ReadLoadedAwgListenPort(uint16_t* port) {
  if (port == nullptr) return false;
  *port = 0;
  std::string response;
  ScopedStringWipe wipe_response(&response);
  if (!ReadAwgRuntimeUapi(&response)) return false;
  AwgRuntimeSnapshot runtime;
  if (!ParseAwgRuntimeUapi(response, &runtime) || !runtime.has_listen_port ||
      runtime.listen_port == 0 || runtime.listen_port > 65535) {
    return false;
  }
  *port = static_cast<uint16_t>(runtime.listen_port);
  return true;
}

#if defined(WINS_TUNNEL_SERVICE_CORE)
struct AwgTransferSnapshot {
  uint64_t handshake_unix = 0;
  uint64_t rx_bytes = 0;
  uint64_t tx_bytes = 0;
  bool complete = false;
};

bool ReadAwgTransferSnapshot(AwgTransferSnapshot* transfer) {
  if (transfer == nullptr) return false;
  *transfer = {};
  std::string response;
  ScopedStringWipe wipe_response(&response);
  AwgRuntimeSnapshot runtime;
  if (!ReadAwgRuntimeUapi(
          &response,
          winsvpn::tunnel_service::kAwgBaselineReadinessTimeoutMilliseconds) ||
      !ParseAwgRuntimeUapi(response, &runtime) || runtime.peers.size() != 1) {
    return false;
  }
  const AwgRuntimePeer& peer = runtime.peers[0];
  transfer->handshake_unix = peer.last_handshake_time_sec;
  transfer->rx_bytes = peer.rx_bytes;
  transfer->tx_bytes = peer.tx_bytes;
  transfer->complete = peer.has_last_handshake_time_sec && peer.has_rx_bytes &&
                       peer.has_tx_bytes;
  return transfer->complete;
}

bool SendTunnelBoundDnsConvergenceProbe(const std::string& raw_config,
                                        const std::string& probe_address) {
  std::string tunnel_address =
      SectionValue(ParseSection(raw_config, "interface"), "address");
  const size_t slash = tunnel_address.find('/');
  if (slash != std::string::npos) tunnel_address.resize(slash);
  IN_ADDR local_address = {};
  IN_ADDR remote_address = {};
  if (InetPtonA(AF_INET, tunnel_address.c_str(), &local_address) != 1 ||
      InetPtonA(AF_INET, probe_address.c_str(), &remote_address) != 1) {
    return false;
  }

  WSADATA data = {};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
  SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_handle == INVALID_SOCKET) {
    WSACleanup();
    return false;
  }
  const DWORD timeout_ms = 750;
  setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
             reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
  SOCKADDR_IN local = {};
  local.sin_family = AF_INET;
  local.sin_addr = local_address;
  local.sin_port = 0;
  SOCKADDR_IN remote = {};
  remote.sin_family = AF_INET;
  remote.sin_addr = remote_address;
  remote.sin_port = htons(53);

  // A minimal A query for connectivitycheck.gstatic.com. Its transaction ID
  // is local-only and no response content is retained; the sole purpose is to
  // prove authenticated bidirectional peer transfer before route promotion.
  const uint16_t transaction =
      static_cast<uint16_t>(GetTickCount64() & 0xffffu);
  std::vector<uint8_t> query = {
      static_cast<uint8_t>(transaction >> 8),
      static_cast<uint8_t>(transaction & 0xff),
      0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      17, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'v', 'i', 't', 'y',
      'c', 'h', 'e', 'c', 'k',
      7, 'g', 's', 't', 'a', 't', 'i', 'c',
      3, 'c', 'o', 'm', 0,
      0x00, 0x01, 0x00, 0x01,
  };
  const bool bound =
      bind(socket_handle, reinterpret_cast<SOCKADDR*>(&local), sizeof(local)) ==
      0;
  const int sent =
      bound ? sendto(socket_handle, reinterpret_cast<const char*>(query.data()),
                     static_cast<int>(query.size()), 0,
                     reinterpret_cast<SOCKADDR*>(&remote), sizeof(remote))
            : SOCKET_ERROR;
  if (sent == static_cast<int>(query.size())) {
    uint8_t response[512] = {};
    recv(socket_handle, reinterpret_cast<char*>(response), sizeof(response), 0);
    SecureZeroMemory(response, sizeof(response));
  }
  SecureZeroMemory(query.data(), query.size());
  closesocket(socket_handle);
  WSACleanup();
  return sent == static_cast<int>(query.size());
}

bool WaitForAwgConvergence(const std::string& raw_config,
                           const AwgTransferSnapshot& baseline,
                           const std::string& probe_address,
                           uint64_t earliest_handshake_unix,
                           std::string* error) {
  const ULONGLONG deadline =
      GetTickCount64() +
      winsvpn::tunnel_service::kAwgConvergenceDeadlineMilliseconds;
  do {
    if (!IsWinsAwgEngineRunning()) {
      *error = "The Windows AWG engine exited during convergence.";
      return false;
    }
    SendTunnelBoundDnsConvergenceProbe(raw_config, probe_address);
    AwgTransferSnapshot current;
    if (ReadAwgTransferSnapshot(&current)) {
      AwgRuntimePeer peer;
      peer.last_handshake_time_sec = current.handshake_unix;
      peer.rx_bytes = current.rx_bytes;
      peer.tx_bytes = current.tx_bytes;
      peer.has_last_handshake_time_sec = current.complete;
      peer.has_rx_bytes = current.complete;
      peer.has_tx_bytes = current.complete;
      if (IsAwgPeerConverged(
              peer, baseline.rx_bytes, baseline.tx_bytes,
              earliest_handshake_unix,
              static_cast<uint64_t>(std::time(nullptr)))) {
        return true;
      }
    }
    Sleep(250);
  } while (GetTickCount64() < deadline);
  *error =
      "The Windows AWG session did not prove a recent handshake and "
      "bidirectional peer transfer before the fail-closed timeout.";
  return false;
}

// Bounded, and it is the transfer-proven half of the Winn route-promotion gate.
//
// The AmneziaWG half (WaitForAwgConvergence) proves the cryptography succeeded;
// this proves the carrier is actually delivering. datapath/status.go is
// explicit that neither alone is sufficient and that `up` is not a gate at all,
// so this reads transport_observed_both_ways and nothing else.
bool WaitForWinnTransportConvergence(std::string* error) {
  const ULONGLONG deadline =
      GetTickCount64() +
      winsvpn::tunnel_service::kWinnTransportConvergenceDeadlineMilliseconds;
  std::string last_status;
  // Carried out of the loop so the timeout message below can name WHICH
  // unproven state the budget was spent in. It is written by
  // DecideWinnTransportGate and never quotes the status document, which carries
  // the customer's gateway endpoint.
  std::string reason;
  do {
    if (!winsvpn::winn::WindowsWinnEngineRunning()) {
      *error = "The Winn Protocol engine exited during convergence.";
      return false;
    }
    const winsvpn::winn::WinnTransportGate gate =
        winsvpn::winn::WindowsWinnTransportGate(&last_status, &reason);
    if (gate == winsvpn::winn::WinnTransportGate::kObserved) {
      return true;
    }
    // A verdict of "this session can never prove itself" is final on the first
    // read, so spending the remaining budget on it would only delay the same
    // refusal. This is also the answer to the objection the replaced fail-open
    // was written around: closing that hole adds NO stall to the case it was
    // worried about, because that case now leaves the loop immediately instead
    // of polling to the deadline.
    if (gate == winsvpn::winn::WinnTransportGate::kCannotObserve) {
      *error =
          "The Winn Protocol tunnel was refused rather than promoted without "
          "proof: " +
          reason;
      return false;
    }
    Sleep(250);
  } while (GetTickCount64() < deadline);
  *error =
      "The Winn Protocol session did not observe AmneziaWG transport datagrams "
      "in both directions before the fail-closed timeout, so the tunnel was "
      "never promoted.";
  if (!reason.empty()) {
    *error += " Last observation: " + reason;
  }
  return false;
}

void FailClosedPrivilegedTunnel() {
  g_tunnel_promoted.store(false, std::memory_order_release);
  g_winn_tunnel_active.store(false, std::memory_order_release);
  // The standalone v3 tunnel comes down here too, and idempotently. This
  // function is reached from the winn/1 path and from the service's own
  // watchdog, and a v3 relay left holding the "winsvpn3" adapter after a
  // fail-closed is an interface with an address and no datapath beneath it --
  // which is exactly the state everything else here exists to prevent.
  g_winn3_tunnel_active.store(false, std::memory_order_release);
  winsvpn::winn3::StopWindowsWinn3Tunnel();
  if (g_last_winn3_proof.outcome ==
      winsvpn::winn3::Winn3ProofOutcome::kConnected) {
    g_last_winn3_proof = winsvpn::winn3::Winn3StartProof();
  }
  // Before the routes come down, so the engine stops addressing a gateway whose
  // /32 pin is about to be removed. Idempotent when Winn never started.
  winsvpn::winn::StopWindowsWinnEngine();
  StopWindowsAppExclusions();
  RemoveWindowsTunnelRoutes();
  if (!StopWinsAwgEngine()) {
    // Closing this LocalSystem process closes the engine's kill-on-close job.
    // Continuing after both graceful and forced engine termination failed
    // would leave an untracked packet path while reporting a rejected start.
    TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
  }
}
#endif

// True for a dotted-quad IPv4 literal. A pure string test on purpose: its
// whole job is to decide whether a resolver is needed at all, so it must never
// reach one.
bool IsIpv4Literal(const std::string& value) {
  int octets = 0;
  size_t index = 0;
  while (index < value.size()) {
    size_t digits = 0;
    unsigned int accumulator = 0;
    while (index < value.size() && std::isdigit(static_cast<unsigned char>(value[index]))) {
      if (digits == 0 && value[index] == '0' && index + 1 < value.size() &&
          std::isdigit(static_cast<unsigned char>(value[index + 1]))) {
        return false;  // no leading zeros -- "010" is not 10 everywhere
      }
      accumulator = accumulator * 10 + static_cast<unsigned int>(value[index] - '0');
      ++digits;
      ++index;
    }
    if (digits == 0 || digits > 3 || accumulator > 255) return false;
    ++octets;
    if (index == value.size()) break;
    if (value[index] != '.') return false;
    ++index;
    if (index == value.size()) return false;
  }
  return octets == 4;
}

// The same public-IPv4 test Linux applies before it will hand an address to
// Xray (linux_tunnel_backend.cc IsPublicIpv4Address). A carrier that resolves
// into RFC1918, loopback, CGNAT, link-local or a reserved documentation range
// is a hijacked or misconfigured answer, not an edge.
bool IsPublicIpv4Address(const in_addr& address) {
  const uint32_t ip = ntohl(address.s_addr);
  const uint8_t first = static_cast<uint8_t>(ip >> 24);
  const uint8_t second = static_cast<uint8_t>((ip >> 16) & 0xff);
  const uint8_t third = static_cast<uint8_t>((ip >> 8) & 0xff);
  if (first == 0 || first == 10 || first == 127 || first >= 224 ||
      (first == 100 && second >= 64 && second <= 127) ||
      (first == 169 && second == 254) ||
      (first == 172 && second >= 16 && second <= 31) ||
      (first == 192 && second == 168) ||
      (first == 192 && second == 0 && (third == 0 || third == 2)) ||
      (first == 198 && (second == 18 || second == 19)) ||
      (first == 198 && second == 51 && third == 100) ||
      (first == 203 && second == 0 && third == 113)) {
    return false;
  }
  return true;
}

// DNS EGRESS (2026-08-07). Resolves the carrier host to public IPv4 literals
// so the Xray child process never receives a name.
//
// Windows used to hand Xray the hostname and let it resolve. Measured on the
// pinned engine build on the lab host, that is 104 plaintext UDP/53 packets
// naming the carrier in about ten seconds -- 52 A and 52 AAAA, because
// sockopt.domainStrategy=UseIPv4 filters the *result* and does not constrain
// the *query* -- repeating for as long as the dial keeps failing. Resolving
// here is what Linux has always done. It does not remove the query from the
// wire; it turns an unbounded retry loop inside a vendored binary into one
// bounded, A-only, auditable call, and removes the Xray-side query entirely
// (measured: 0).
//
// AF_INET, so no AAAA is asked for a carrier that has no AAAA record -- an
// absence that is itself a distinguishing signal. An address that is already a
// literal short-circuits and asks nothing at all.
std::vector<std::string> ResolvePublicIpv4Addresses(const std::string& hostname) {
  if (IsIpv4Literal(hostname)) {
    in_addr parsed = {};
    if (inet_pton(AF_INET, hostname.c_str(), &parsed) != 1 ||
        !IsPublicIpv4Address(parsed)) {
      return {};
    }
    return {hostname};
  }
  WSADATA data = {};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return {};
  addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0 ||
      result == nullptr) {
    WSACleanup();
    return {};
  }
  std::set<std::string> addresses;
  for (const addrinfo* current = result; current != nullptr;
       current = current->ai_next) {
    if (current->ai_family != AF_INET || current->ai_addr == nullptr) continue;
    const auto* socket_address =
        reinterpret_cast<const sockaddr_in*>(current->ai_addr);
    if (!IsPublicIpv4Address(socket_address->sin_addr)) continue;
    char text[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &socket_address->sin_addr, text, sizeof(text)) !=
        nullptr) {
      addresses.insert(text);
    }
  }
  freeaddrinfo(result);
  WSACleanup();
  return std::vector<std::string>(addresses.begin(), addresses.end());
}

// transport_ipv4s must be the already-resolved, already-validated edge list
// from ResolvePublicIpv4Addresses -- it is taken as a parameter rather than
// re-derived so the JSON actually written can never disagree with what the
// caller checked, and so this function performs no name resolution of its own.
std::string BuildXrayConfig(const std::map<std::string, std::string>& section,
                            const std::vector<std::string>& transport_ipv4s) {
  const std::string uuid = SectionValue(section, "uuid");
  const std::string host = SectionValue(section, "host");
  const int port = PositiveIntValue(section, "port", 80);
  const std::string server_name = SectionValue(section, "servername", host);
  const std::string path = SectionValue(section, "path", "/wins-stealth-tunnel");
  const std::string security =
      LowerAscii(SectionValue(section, "security", "tls"));
  const int local_port = PositiveIntValue(section, "localport", 42110);
  const std::string remote_awg_host =
      SectionValue(section, "remoteawghost", "127.0.0.1");
  const int remote_awg_port = PositiveIntValue(section, "remoteawgport", 9110);

  std::ostringstream json;
  json << "{";
  json << "\"log\":{\"loglevel\":\"warning\"},";
  json << "\"policy\":{\"levels\":{\"0\":{\"handshake\":4,\"connIdle\":300,"
          "\"uplinkOnly\":2,\"downlinkOnly\":5,\"bufferSize\":4096}},"
          "\"system\":{\"statsInboundUplink\":false,\"statsInboundDownlink\":false,"
          "\"statsOutboundUplink\":false,\"statsOutboundDownlink\":false}},";
  json << "\"inbounds\":[{\"tag\":\"awg-local-in\",\"listen\":\"127.0.0.1\",";
  json << "\"port\":" << local_port << ",\"protocol\":\"tunnel\",";
  // Xray 26.9.30 accepts network/address/port for tunnel settings (legacy
  // spelling kept; the renamed fields are rejected by the deployment gate).
  json << "\"settings\":{\"network\":\"udp\",\"address\":\""
       << JsonEscape(remote_awg_host) << "\",\"port\":" << remote_awg_port
       << ",\"followRedirect\":false,\"userLevel\":0},";
  json << "\"streamSettings\":{\"sockopt\":{\"domainStrategy\":\"UseIPv4\","
          "\"tcpNoDelay\":true}}}],";
  // One VLESS outbound per prevalidated IPv4 edge, selected by a roundRobin
  // balancer -- the shape Linux already ships. Not a stylistic choice:
  // upstream at the pinned commit rejects a multi-entry "vnext" outright
  // (infra/conf/vless.go: "Multiple endpoints in \"vnext\" should use multiple
  // VLESS outbounds and routing balancer instead"), so a balancer is the only
  // way to keep the address rotation the hostname path used to get for free
  // from the resolver -- without asking Xray to resolve anything.
  json << "\"outbounds\":[";
  for (std::size_t i = 0; i < transport_ipv4s.size(); ++i) {
    if (i != 0) json << ",";
    json << "{\"tag\":\"vless-ws-edge-" << i << "\",\"protocol\":\"vless\",";
    json << "\"settings\":{\"vnext\":[{\"address\":\""
         << JsonEscape(transport_ipv4s[i]) << "\",\"port\":" << port
         << ",\"users\":[{\"id\":\"" << JsonEscape(uuid)
         << "\",\"encryption\":\"none\",\"level\":0}]}]},";
    // The SNI and the WebSocket Host header stay the carrier's DNS name even
    // though the address above is a literal. That is the whole point: the
    // certificate is issued for the name, and the name is never asked of a
    // resolver by the Xray process.
    //
    // domainStrategy is retained but is NOT a DNS control: it is measured not
    // to keep the outer lookup on IPv4 (it filters the result of a
    // both-families query). With a literal address there is no lookup left for
    // it to affect; it stays because it also selects the IPv4 socket family.
    json << "\"streamSettings\":{\"network\":\"ws\",\"security\":\""
         << JsonEscape(security) << "\",\"wsSettings\":{\"path\":\""
         << JsonEscape(path) << "\",\"headers\":{\"Host\":\""
         << JsonEscape(server_name)
         << "\"}},\"sockopt\":{\"domainStrategy\":\"UseIPv4\","
            "\"tcpFastOpen\":true,\"tcpNoDelay\":true,\"tcpKeepAliveIdle\":30,"
            "\"tcpKeepAliveInterval\":15,\"tcpUserTimeout\":15000,"
            "\"tcpMptcp\":false}";
    if (security == "tls") {
      json << ",\"tlsSettings\":{\"serverName\":\"" << JsonEscape(server_name)
           << "\",\"allowInsecure\":false}";
    }
    json << "},\"mux\":{\"enabled\":false,\"concurrency\":0,"
            "\"xudpConcurrency\":0,\"xudpProxyUDP443\":\"skip\"}}";
  }
  json << "],";
  json << "\"routing\":{\"rules\":[{\"type\":\"field\","
          "\"inboundTag\":[\"awg-local-in\"],"
          "\"balancerTag\":\"vless-ws-balancer\"}],"
          "\"balancers\":[{\"tag\":\"vless-ws-balancer\","
          "\"selector\":[\"vless-ws-edge-\"],"
          "\"strategy\":{\"type\":\"roundRobin\"}}]}}";
  return json.str();
}

#if !defined(WINS_TUNNEL_SERVICE_CORE)
bool IsExpectedCommittedManagerStatus(const std::string& manager_status) {
  const uint64_t expected_generation =
      g_committed_generation.load(std::memory_order_acquire);
  const std::string generation_marker =
      ";generation=" + std::to_string(expected_generation) + ";";
  return expected_generation > 0 && manager_status.rfind("running;", 0) == 0 &&
         manager_status.find(";phase=committed;") != std::string::npos &&
         manager_status.find(";route_committed=1;") != std::string::npos &&
         manager_status.find(generation_marker) != std::string::npos;
}
#endif

bool IsTunnelRunning() {
#if defined(WINS_TUNNEL_SERVICE_CORE)
  // A STANDALONE v3 tunnel has no AmneziaWG engine to ask about, so the
  // conjunction below would answer false for a perfectly healthy one. Its own
  // liveness is the honest pair: both children alive AND the promoted posture
  // installed. A relay alive with a dead engine holds an adapter whose seam has
  // nothing beneath it -- it carries nothing -- and a promoted flag alone would
  // survive the datapath it was granted for.
  if (g_winn3_tunnel_active.load(std::memory_order_acquire)) {
    return winsvpn::winn3::WindowsTunnelRunningConsideringV3(
        true, winsvpn::winn3::WindowsWinn3TunnelRunning(),
        winsvpn::winn3::WindowsWinn3TunnelPromoted(), false);
  }
  // On a winn/3 tunnel the AmneziaWG peer endpoint points at a loopback seam.
  // If the engine behind that seam is gone the adapter is still up, still has
  // routes, and every packet entering it dies silently. Interface presence --
  // and, equally, AWG-engine presence -- is therefore not proof here, which is
  // the same correction the Linux lane had to make to IsTunnelRunning.
  if (g_winn_tunnel_active.load(std::memory_order_acquire) &&
      !winsvpn::winn::WindowsWinnEngineRunning()) {
    return false;
  }
  return g_tunnel_promoted.load(std::memory_order_acquire) &&
         IsWinsAwgEngineRunning();
#else
  std::string manager_status;
  std::string manager_error;
  return QueryWindowsTunnelManager(&manager_status, &manager_error) &&
         IsExpectedCommittedManagerStatus(manager_status);
#endif
}

// Exact WSA code from a non-blocking datagram connect to the already-parsed
// IP-literal gateway. Diagnostic prose is never inspected. Immediate
// WSAEWOULDBLOCK/WSAEINPROGRESS means a route exists and is not ordinary.
int CaptureWindowsWinn3GatewayOsError(const std::string& endpoint) {
  std::string host;
  std::string port_text;
  if (!winsvpn::winn3::SplitWinn3Endpoint(endpoint, &host, &port_text)) {
    return 0;
  }
  char* end = nullptr;
  const unsigned long port = std::strtoul(port_text.c_str(), &end, 10);
  if (end == port_text.c_str() || (end != nullptr && *end != '\0') ||
      port == 0 || port > 65535UL) {
    return 0;
  }
  const bool ipv6 = host.find(':') != std::string::npos;
  const int family = ipv6 ? AF_INET6 : AF_INET;
  SOCKET sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == INVALID_SOCKET) return 0;
  u_long nonblocking = 1;
  if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
    closesocket(sock);
    return 0;
  }
  int rc = SOCKET_ERROR;
  if (ipv6) {
    sockaddr_in6 addr = {};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(static_cast<uint16_t>(port));
    if (InetPtonA(AF_INET6, host.c_str(), &addr.sin6_addr) != 1) {
      closesocket(sock);
      return 0;
    }
    rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  } else {
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (InetPtonA(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
      closesocket(sock);
      return 0;
    }
    rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  }
  if (rc == 0) {
    closesocket(sock);
    return 0;
  }
  const int os_error = WSAGetLastError();
  closesocket(sock);
  if (os_error == WSAEWOULDBLOCK || os_error == WSAEINPROGRESS) {
    return 0;
  }
  return os_error;
}

int CaptureWindowsWinn3GatewayOsErrorFromConfig(const std::string& raw_config) {
  winsvpn::winn3::Winn3HostConfig parsed;
  std::string ignored;
  if (!winsvpn::winn3::ParseWinn3Section(raw_config, &parsed, &ignored)) {
    return 0;
  }
  return CaptureWindowsWinn3GatewayOsError(parsed.endpoint);
}

#if !defined(WINS_TUNNEL_SERVICE_CORE)
flutter::EncodableValue TunnelActivitySnapshotValue() {
  std::string manager_status;
  std::string manager_error;
  const bool manager_known =
      QueryWindowsTunnelManager(&manager_status, &manager_error);
  const bool manager_active =
      manager_known && IsExpectedCommittedManagerStatus(manager_status);
  const bool xray_active = IsXrayProcessRunning();

  flutter::EncodableMap snapshot;
  snapshot[flutter::EncodableValue("known")] =
      flutter::EncodableValue(manager_known || xray_active);
  snapshot[flutter::EncodableValue("active")] =
      flutter::EncodableValue(manager_active || xray_active);
  snapshot[flutter::EncodableValue("manager_known")] =
      flutter::EncodableValue(manager_known);
  snapshot[flutter::EncodableValue("manager_active")] =
      flutter::EncodableValue(manager_active);
  snapshot[flutter::EncodableValue("xray_active")] =
      flutter::EncodableValue(xray_active);
  return flutter::EncodableValue(snapshot);
}

bool ParseTunnelManagerUnsigned(const std::string& status,
                                const std::string& key,
                                uint64_t* value) {
  if (value == nullptr || key.empty()) return false;
  const std::string marker = ";" + key + "=";
  size_t start = status.find(marker);
  if (start == std::string::npos) {
    const std::string prefix = key + "=";
    if (status.rfind(prefix, 0) != 0) return false;
    start = 0;
  } else {
    start += 1;
  }
  start += key.size() + 1;
  const size_t end = status.find(';', start);
  const std::string text = status.substr(start, end - start);
  bool assigned = false;
  return ParseUnsignedDecimalOnce(text, value, &assigned);
}

flutter::EncodableMap Winn3ProofEncodableMap(
    const winsvpn::winn3::Winn3StartProof& proof);

flutter::EncodableValue TunnelReadinessValue() {
  std::string manager_status;
  std::string manager_error;
  uint64_t awg_query = 0;
  uint64_t awg_handshake_unix = 0;
  uint64_t awg_rx_bytes = 0;
  uint64_t awg_tx_bytes = 0;
  const bool manager_status_ok =
      QueryWindowsTunnelManager(&manager_status, &manager_error) &&
      IsExpectedCommittedManagerStatus(manager_status);
  const bool active = manager_status_ok;
  const bool awg_status_ok =
      manager_status_ok &&
      ParseTunnelManagerUnsigned(manager_status, "awg_query", &awg_query) &&
      ParseTunnelManagerUnsigned(manager_status, "awg_handshake_unix",
                                 &awg_handshake_unix) &&
      ParseTunnelManagerUnsigned(manager_status, "awg_rx_bytes",
                                 &awg_rx_bytes) &&
      ParseTunnelManagerUnsigned(manager_status, "awg_tx_bytes",
                                 &awg_tx_bytes) &&
      awg_query == 1;
  const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
  const bool handshake_recent =
      awg_status_ok && awg_handshake_unix > 0 &&
      awg_handshake_unix <= now + 5 && now <= awg_handshake_unix + 180;
  flutter::EncodableMap readiness;
  readiness[flutter::EncodableValue("active")] =
      flutter::EncodableValue(active);
  readiness[flutter::EncodableValue("engine_ready")] =
      flutter::EncodableValue(active);
  readiness[flutter::EncodableValue("engine_ready_ms")] =
      flutter::EncodableValue(static_cast<int64_t>(active ? 1500 : 0));
  readiness[flutter::EncodableValue("underlying_transport")] =
      flutter::EncodableValue("desktop");
  readiness[flutter::EncodableValue("vpn_present")] =
      flutter::EncodableValue(active);
  // Service presence proves only that the native tunnel engine is running.
  // It must never be promoted to internet/validation proof until a probe is
  // explicitly bound to the tunnel interface.
  readiness[flutter::EncodableValue("vpn_internet")] =
      flutter::EncodableValue(false);
  readiness[flutter::EncodableValue("vpn_validated")] =
      flutter::EncodableValue(false);
  readiness[flutter::EncodableValue("awg_runtime_query_ok")] =
      flutter::EncodableValue(awg_status_ok);
  readiness[flutter::EncodableValue("awg_handshake_recent")] =
      flutter::EncodableValue(handshake_recent);
  const int64_t effective_rx = static_cast<int64_t>(std::min<uint64_t>(
      awg_rx_bytes,
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max())));
  const int64_t effective_tx = static_cast<int64_t>(std::min<uint64_t>(
      awg_tx_bytes,
      static_cast<uint64_t>(std::numeric_limits<int64_t>::max())));
  readiness[flutter::EncodableValue("awg_rx_bytes")] =
      flutter::EncodableValue(effective_rx);
  readiness[flutter::EncodableValue("awg_tx_bytes")] =
      flutter::EncodableValue(effective_tx);
  readiness[flutter::EncodableValue("tun_rx_bytes")] =
      flutter::EncodableValue(effective_rx);
  readiness[flutter::EncodableValue("tun_tx_bytes")] =
      flutter::EncodableValue(effective_tx);
  readiness[flutter::EncodableValue("traffic_rx_bytes")] =
      flutter::EncodableValue(effective_rx);
  readiness[flutter::EncodableValue("traffic_tx_bytes")] =
      flutter::EncodableValue(effective_tx);
  readiness[flutter::EncodableValue("uid_rx_bytes")] =
      flutter::EncodableValue(static_cast<int64_t>(0));
  readiness[flutter::EncodableValue("uid_tx_bytes")] =
      flutter::EncodableValue(static_cast<int64_t>(0));
  winsvpn::winn3::Winn3StartProof proof;
  {
    std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
    proof = g_last_winn3_proof;
  }
  const flutter::EncodableMap proof_fields = Winn3ProofEncodableMap(proof);
  for (const auto& field : proof_fields) {
    readiness[field.first] = field.second;
  }
  return flutter::EncodableValue(readiness);
}

flutter::EncodableMap Winn3ProofEncodableMap(
    const winsvpn::winn3::Winn3StartProof& proof) {
  flutter::EncodableMap details;
  details[flutter::EncodableValue("winn3_verdict")] = flutter::EncodableValue(
      std::string(winsvpn::winn3::Winn3ProofOutcomeName(proof.outcome)));
  details[flutter::EncodableValue("winn3_start_generation")] =
      flutter::EncodableValue(proof.generation);
  details[flutter::EncodableValue("winn3_start_token")] =
      flutter::EncodableValue(proof.start_token);
  details[flutter::EncodableValue("winn3_start_canceled")] =
      flutter::EncodableValue(proof.canceled);
  if (!proof.selection_generation.empty()) {
    details[flutter::EncodableValue("winn3_selection_generation")] =
        flutter::EncodableValue(proof.selection_generation);
  }
  if (!proof.failed_node.empty()) {
    details[flutter::EncodableValue("winn3_failed_node")] =
        flutter::EncodableValue(proof.failed_node);
  }
  const int64_t auth = winsvpn::winn3::Winn3AuthorizationToken(proof);
  if (auth > 0) {
    details[flutter::EncodableValue("winn3_awg_xray_authorization_token")] =
        flutter::EncodableValue(auth);
  }
  return details;
}

bool TunnelInterfaceIpv4(IN_ADDR* address, NET_IFINDEX* interface_index) {
  if (address == nullptr || interface_index == nullptr) return false;
  std::string manager_status;
  std::string manager_error;
  const bool manager_known =
      QueryWindowsTunnelManager(&manager_status, &manager_error);
  uint64_t winn3 = 0;
  uint64_t winn3_datapath = 0;
  uint64_t winn3_promoted = 0;
  uint64_t winn = 0;
  const bool family_known =
      manager_known &&
      ParseTunnelManagerUnsigned(manager_status, "winn3", &winn3) &&
      ParseTunnelManagerUnsigned(manager_status, "winn3_datapath",
                                 &winn3_datapath) &&
      ParseTunnelManagerUnsigned(manager_status, "winn3_promoted",
                                 &winn3_promoted) &&
      ParseTunnelManagerUnsigned(manager_status, "winn", &winn);
  const bool ordinary_family =
      winn3 == 0 && winn3_datapath == 0 && winn3_promoted == 0 &&
      winn <= 1;
  const bool standalone_family =
      winn3 == 1 && winn3_datapath == 1 && winn3_promoted == 1 &&
      winn == 0;
  if (!family_known ||
      !IsExpectedCommittedManagerStatus(manager_status) ||
      (!ordinary_family && !standalone_family)) {
    return false;
  }
  const bool v1_running = ordinary_family;
  winsvpn::winn3::WindowsTunnelProbeAlias alias;
  {
    std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
    winsvpn::winn3::Winn3HostSessionSnapshot snapshot;
    snapshot.proof = g_last_winn3_proof;
    snapshot.grant = g_awg_xray_grant;
    snapshot.v3_active = winn3 == 1;
    snapshot.v3_running = winn3_datapath == 1;
    snapshot.v3_promoted = winn3_promoted == 1;
    snapshot.v1_running = v1_running;
    alias = winsvpn::winn3::ClassifyWindowsTunnelProbeAlias(
        snapshot.v3_active, snapshot.v3_running, snapshot.v3_promoted,
        snapshot.v1_running);
  }
  if (alias == winsvpn::winn3::WindowsTunnelProbeAlias::kRefuse) {
    return false;
  }
  const char* alias_utf8 = winsvpn::winn3::WindowsTunnelProbeAliasName(alias);
  if (alias_utf8 == nullptr || alias_utf8[0] == '\0') return false;
  std::wstring alias_wide;
  for (const char* cursor = alias_utf8; *cursor != '\0'; ++cursor) {
    alias_wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*cursor)));
  }
  NET_LUID tunnel_luid = {};
  if (ConvertInterfaceAliasToLuid(alias_wide.c_str(), &tunnel_luid) != NO_ERROR) {
    return false;
  }
  PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
  if (GetUnicastIpAddressTable(AF_INET, &table) != NO_ERROR ||
      table == nullptr) {
    return false;
  }
  bool found = false;
  for (ULONG index = 0; index < table->NumEntries; ++index) {
    const MIB_UNICASTIPADDRESS_ROW& row = table->Table[index];
    if (row.InterfaceLuid.Value != tunnel_luid.Value ||
        row.Address.Ipv4.sin_family != AF_INET ||
        row.DadState != IpDadStatePreferred) {
      continue;
    }
    const IN_ADDR candidate = row.Address.Ipv4.sin_addr;
    const uint32_t host_address = ntohl(candidate.S_un.S_addr);
    if (host_address == 0 || (host_address & 0xff000000u) == 0x7f000000u ||
        (host_address & 0xffff0000u) == 0xa9fe0000u) {
      continue;
    }
    *address = candidate;
    *interface_index = row.InterfaceIndex;
    found = true;
    break;
  }
  FreeMibTable(table);
  return found;
}

bool WaitForSocketReady(SOCKET socket_handle, bool writable,
                        ULONGLONG deadline) {
  const ULONGLONG wait_now = GetTickCount64();
  if (wait_now >= deadline) return false;
  const ULONGLONG remaining_ms = deadline - wait_now;
  timeval timeout = {};
  timeout.tv_sec = static_cast<long>(remaining_ms / 1000);
  timeout.tv_usec = static_cast<long>((remaining_ms % 1000) * 1000);
  fd_set ready;
  fd_set failed;
  FD_ZERO(&ready);
  FD_ZERO(&failed);
  FD_SET(socket_handle, &ready);
  FD_SET(socket_handle, &failed);
  const int selected = writable
                           ? select(0, nullptr, &ready, &failed, &timeout)
                           : select(0, &ready, nullptr, &failed, &timeout);
  return selected > 0 && FD_ISSET(socket_handle, &ready) &&
         !FD_ISSET(socket_handle, &failed);
}

bool ConnectTunnelBoundHttp(const IN_ADDR& local_address,
                            NET_IFINDEX interface_index,
                            const char* remote_address,
                            ULONGLONG overall_deadline) {
  constexpr ULONGLONG kEndpointTimeoutMilliseconds = 3000;
  const ULONGLONG now = GetTickCount64();
  if (remote_address == nullptr || now >= overall_deadline) return false;
  SOCKET socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_handle == INVALID_SOCKET) return false;
  SOCKADDR_IN local = {};
  local.sin_family = AF_INET;
  local.sin_addr = local_address;
  local.sin_port = 0;
  SOCKADDR_IN remote = {};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(80);
  const DWORD network_interface_index = htonl(interface_index);
  const bool addresses_ready =
      bind(socket_handle, reinterpret_cast<SOCKADDR*>(&local), sizeof(local)) ==
          0 &&
      InetPtonA(AF_INET, remote_address, &remote.sin_addr) == 1 &&
      setsockopt(socket_handle, IPPROTO_IP, IP_UNICAST_IF,
                 reinterpret_cast<const char*>(&network_interface_index),
                 sizeof(network_interface_index)) == 0;
  u_long nonblocking = 1;
  if (!addresses_ready ||
      ioctlsocket(socket_handle, FIONBIO, &nonblocking) != 0) {
    closesocket(socket_handle);
    return false;
  }
  int connected = connect(socket_handle,
                          reinterpret_cast<SOCKADDR*>(&remote), sizeof(remote));
  const ULONGLONG endpoint_deadline =
      std::min<ULONGLONG>(overall_deadline,
                          now + kEndpointTimeoutMilliseconds);
  if (connected != 0) {
    const int connect_error = WSAGetLastError();
    if ((connect_error != WSAEWOULDBLOCK &&
         connect_error != WSAEINPROGRESS) ||
        !WaitForSocketReady(socket_handle, true, endpoint_deadline)) {
      closesocket(socket_handle);
      return false;
    }
    int socket_error = WSAETIMEDOUT;
    int socket_error_size = sizeof(socket_error);
    if (getsockopt(socket_handle, SOL_SOCKET, SO_ERROR,
                   reinterpret_cast<char*>(&socket_error),
                   &socket_error_size) != 0 ||
        socket_error != 0) {
      closesocket(socket_handle);
      return false;
    }
  }
  constexpr char kRequest[] =
      "GET /cdn-cgi/trace HTTP/1.1\r\n"
      "Host: cloudflare.com\r\n"
      "Connection: close\r\n"
      "User-Agent: WinsVPN-Connectivity/1\r\n\r\n";
  size_t sent_total = 0;
  while (sent_total < sizeof(kRequest) - 1) {
    const int sent = send(socket_handle, kRequest + sent_total,
                          static_cast<int>(sizeof(kRequest) - 1 - sent_total),
                          0);
    if (sent > 0) {
      sent_total += static_cast<size_t>(sent);
      continue;
    }
    if ((sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) &&
        WaitForSocketReady(socket_handle, true, endpoint_deadline)) {
      continue;
    }
    closesocket(socket_handle);
    return false;
  }
  std::string response;
  response.reserve(4096);
  char buffer[1024] = {};
  bool validated = false;
  while (response.size() < 16 * 1024 &&
         WaitForSocketReady(socket_handle, false, endpoint_deadline)) {
    const int received = recv(socket_handle, buffer, sizeof(buffer), 0);
    if (received > 0) {
      response.append(buffer, static_cast<size_t>(received));
      const std::string lower = LowerAscii(response);
      const bool http_ok =
          lower.rfind("http/1.1 200 ", 0) == 0 ||
          lower.rfind("http/1.0 200 ", 0) == 0;
      validated = http_ok &&
                  lower.find("\r\nserver: cloudflare") != std::string::npos &&
                  lower.find("\nh=cloudflare.com") != std::string::npos;
      if (validated) break;
      continue;
    }
    if (received == 0) break;
    if (WSAGetLastError() != WSAEWOULDBLOCK) break;
  }
  SecureZeroMemory(buffer, sizeof(buffer));
  if (!response.empty()) SecureZeroMemory(response.data(), response.size());
  closesocket(socket_handle);
  return validated;
}

bool ProbeTunnelBoundInternet() {
  constexpr ULONGLONG kProbeBudgetMilliseconds = 7000;
  const ULONGLONG deadline = GetTickCount64() + kProbeBudgetMilliseconds;
  WSADATA data = {};
  if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
  IN_ADDR local_address = {};
  NET_IFINDEX interface_index = 0;
  if (!TunnelInterfaceIpv4(&local_address, &interface_index)) {
    WSACleanup();
    return false;
  }
  bool connected = false;
  // Two independent public HTTPS edges reduce false negatives without DNS or
  // a PowerShell/curl child. The TCP socket is explicitly bound to winsvpn's
  // current IPv4 address, so success is tunnel-path proof.
  for (const char* endpoint : {"1.1.1.1", "1.0.0.1"}) {
    if (ConnectTunnelBoundHttp(local_address, interface_index, endpoint,
                               deadline)) {
      connected = true;
      break;
    }
    if (GetTickCount64() >= deadline) break;
  }
  WSACleanup();
  return connected;
}

flutter::EncodableValue ProbeInternetValue() {
  // The generation is committed only after the protected manager reports a
  // successful route commit. Avoid a second 12-second manager query here: the
  // interface-bound probe itself is the authoritative liveness check and must
  // finish before Dart's 9-second cancellation boundary.
  const bool active =
      g_committed_generation.load(std::memory_order_acquire) > 0 &&
      !g_stop_in_flight.load(std::memory_order_acquire);
  const bool ok = active && ProbeTunnelBoundInternet();
  flutter::EncodableMap response;
  response[flutter::EncodableValue("ok")] = flutter::EncodableValue(ok);
  response[flutter::EncodableValue("bound_to_tunnel")] =
      flutter::EncodableValue(ok);
  response[flutter::EncodableValue("status")] =
      flutter::EncodableValue(static_cast<int64_t>(ok ? 200 : 0));
  response[flutter::EncodableValue("error")] =
      flutter::EncodableValue(
          ok ? "" : active ? "Windows tunnel-bound internet probe failed"
                             : "Windows tunnel is not active");
  return flutter::EncodableValue(response);
}
#endif

#if !defined(WINS_TUNNEL_SERVICE_CORE)
bool StartXrayIfNeeded(const std::string& raw_config, std::string* error) {
  std::lock_guard<std::recursive_mutex> lock(g_xray_mutex);
  const std::map<std::string, std::string> xray = ParseSection(raw_config, "xray");
  if (!SectionBool(xray, "enabled")) {
    StopXrayProcess();
    return true;
  }
  StopXrayProcess();
  const std::string uuid = SectionValue(xray, "uuid");
  const std::string host = SectionValue(xray, "host");
  const std::string server_name = SectionValue(xray, "servername", host);
  const std::string security =
      LowerAscii(SectionValue(xray, "security", "tls"));
  if (!IsValidXrayUuid(uuid) || !IsValidXrayHostname(host) ||
      !IsValidXrayHostname(server_name)) {
    *error = "Xray stealth UUID, host, or TLS server name is invalid.";
    return false;
  }
  if (!IsValidPortValue(SectionValue(xray, "port", "80")) ||
      !IsValidPortValue(SectionValue(xray, "localport", "42110")) ||
      !IsValidPortValue(SectionValue(xray, "remoteawgport", "9110"))) {
    *error = "Xray stealth port is outside 1-65535.";
    return false;
  }
  if (!IsValidXrayPath(
          SectionValue(xray, "path", "/wins-stealth-tunnel"))) {
    *error = "Xray stealth WebSocket path is invalid.";
    return false;
  }
  if (security != "tls") {
    *error = "Windows Xray transport requires TLS.";
    return false;
  }
  // IP-PINNED BOOTSTRAP (2026-08-07). `host` may now be an IPv4 literal. The
  // blocker recorded in NETWORK_OBSERVABLE_DNS_SNI_AUDIT_20260806.md §6.7 was
  // that TLS transports need a DNS name for the certificate. They do -- but
  // that binds the SNI, not the address. Measured on the pinned engine: a
  // literal vnext.address alongside a hostname serverName produces an empty
  // capture. So a literal is allowed, and only `servername` must stay a name.
  if (security == "tls" && IsIpv4Literal(host) && IsIpv4Literal(server_name)) {
    *error =
        "Xray stealth host is an IP literal but no TLS server name was "
        "supplied; a certificate cannot be verified against an address.";
    return false;
  }
  const std::string remote_host =
      LowerAscii(SectionValue(xray, "remoteawghost", "127.0.0.1"));
  if (remote_host != "127.0.0.1" && remote_host != "localhost" &&
      remote_host != "::1") {
    *error = "Xray stealth AWG destination must remain loopback-only.";
    return false;
  }
  const std::wstring xray_exe = FindXrayExecutable();
  if (xray_exe.empty()) {
    *error = "xray.exe is missing from the Win's VPN install directory.";
    return false;
  }
  // Resolve before anything else is committed, and fail closed exactly as
  // Linux does: no public IPv4, no transport. See ResolvePublicIpv4Addresses
  // for why this moved out of the Xray child process.
  const std::vector<std::string> transport_ipv4s =
      ResolvePublicIpv4Addresses(host);
  if (transport_ipv4s.empty()) {
    *error = "Xray stealth host did not resolve to a public IPv4 address.";
    return false;
  }

  const std::wstring directory = UserRuntimeDirectory();
  std::wstring runtime_sddl;
  const size_t directory_separator = directory.find_last_of(L"\\/");
  if (directory.empty() || directory_separator == std::wstring::npos ||
      !CurrentUserSystemDaclSddl(&runtime_sddl) ||
      !EnsureDirectory(directory.substr(0, directory_separator)) ||
      !EnsureDirectoryWithDacl(directory, runtime_sddl)) {
    *error = "Unable to create the private per-user Xray runtime directory.";
    return false;
  }
  const std::wstring config_path =
      UniqueConfigPath(directory, L"wins_xray_client", L".json");
  std::string xray_config = BuildXrayConfig(xray, transport_ipv4s);
  ScopedStringWipe wipe_xray_config(&xray_config);
  if (config_path.empty() ||
      !WriteBytesSecureAtomic(
          config_path, reinterpret_cast<const uint8_t*>(xray_config.data()),
          xray_config.size(), runtime_sddl)) {
    *error = "Unable to write Xray client config.";
    return false;
  }
  ScopedFileDelete delete_xray_config(config_path);

  STARTUPINFOW startup = {};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  std::wstring command =
      Quote(xray_exe) + L" run -c " + Quote(config_path);
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits = {};
  job_limits.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == nullptr ||
      !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &job_limits, sizeof(job_limits))) {
    if (job != nullptr) {
      CloseHandle(job);
    }
    *error = "Unable to create the Xray carrier lifetime boundary.";
    return false;
  }
  if (!CreateProcessW(xray_exe.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup,
                      &g_xray_process)) {
    *error = "Unable to launch bundled Xray transport.";
    CloseHandle(job);
    g_xray_process = {};
    return false;
  }
  if (!AssignProcessToJobObject(job, g_xray_process.hProcess) ||
      ResumeThread(g_xray_process.hThread) == static_cast<DWORD>(-1)) {
    TerminateProcess(g_xray_process.hProcess, 1);
    WaitForSingleObject(g_xray_process.hProcess, 3000);
    CloseHandle(g_xray_process.hProcess);
    CloseHandle(g_xray_process.hThread);
    CloseHandle(job);
    g_xray_process = {};
    *error = "Unable to bind Xray to the app lifetime boundary.";
    return false;
  }
  g_xray_job = job;
  const int inbound_port = PositiveIntValue(xray, "localport", 42110);
  const auto inbound_bound = [](DWORD pid, int port) {
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<uint8_t> buffer(size + 4096);
    size = static_cast<ULONG>(buffer.size());
    if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
      return false;
    }
    const auto* table =
        reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
      if (table->table[i].dwOwningPid == pid &&
          table->table[i].dwLocalAddr == htonl(INADDR_LOOPBACK) &&
          ntohs(static_cast<u_short>(table->table[i].dwLocalPort)) == port) {
        return true;
      }
    }
    return false;
  };
  const ULONGLONG ready_deadline = GetTickCount64() + 3000;
  bool ready = false;
  while (GetTickCount64() < ready_deadline) {
    if (WaitForSingleObject(g_xray_process.hProcess, 20) != WAIT_TIMEOUT) break;
    if (inbound_bound(g_xray_process.dwProcessId, inbound_port)) {
      ready = true;
      break;
    }
  }
  if (!ready) {
    StopXrayProcess();
    *error = "Xray transport did not open its local inbound.";
    return false;
  }
  return true;
}
#endif

#if defined(WINS_TUNNEL_SERVICE_CORE)
// The Winn Protocol v3 start, which shares NOTHING with the one below it.
//
// v3 is a standalone protocol. There is no AmneziaWG under it, so this path
// never looks for awg.exe, never writes an awg-quick configuration, never runs
// setconf, and never waits for an AWG handshake. It starts two children -- the
// v3 tun relay that owns the "winsvpn3" Wintun adapter, and cmd/winn-datapath
// against a `device.kind: loopback-udp` profile -- installs the narrow
// bootstrap posture on the adapter, and widens it only when the engine's own
// status document reports promotion_ready, which is `gate == carrying AND
// rx_packets > 0` computed once, in Go, beside the counters.
//
// Everything it does lives in winn3_supervisor.{h,cpp}. This function is the
// three lines that make it reachable, and it is deliberately not woven into the
// AmneziaWG start path below: a v3 tunnel that shared any step with a v1 tunnel
// would be a v1 step that could run for a v3 config, and the steps that could
// run wrongly are the ones that decide what encrypts what.
bool InstallWinn3StandaloneTunnel(const std::string& raw_config,
                                  std::string* error) {
  // Idempotent. A previous v3 tunnel that was never torn down would hold the
  // one "winsvpn3" adapter, and the relay refuses a second instance with an
  // exit code rather than a sentence.
  winsvpn::winn3::StopWindowsWinn3Tunnel();
  winsvpn::winn3::Winn3HostConfig winn3_config;
  if (!winsvpn::winn3::ParseWinn3Section(raw_config, &winn3_config, error)) {
    winsvpn::winn3::RememberWindowsWinn3OsError(0);
    g_last_winn3_proof = winsvpn::winn3::ClassifyCapturedWinn3StartFailure(
        0, false, error != nullptr ? *error : "");
    return false;
  }
  if (!winsvpn::winn3::StartWindowsWinn3Tunnel(winn3_config, error)) {
    // Fail-closed: the supervisor already unwound, and this is the belt to its
    // braces. Nothing is left holding an adapter or a route.
    winsvpn::winn3::StopWindowsWinn3Tunnel();
    g_winn3_tunnel_active.store(false, std::memory_order_release);
    winsvpn::winn3::RememberWindowsWinn3OsError(
        CaptureWindowsWinn3GatewayOsError(winn3_config.endpoint));
    g_last_winn3_proof = winsvpn::winn3::ClassifyCapturedWinn3StartFailure(
        0, false, error != nullptr ? *error : "");
    return false;
  }
  IP_ADDRESS_PREFIX winn3_gateway = {};
  NET_LUID winn3_luid = {};
  if (!WindowsPermitPrefixFromEndpoint(winn3_config.endpoint, &winn3_gateway) ||
      ConvertInterfaceAliasToLuid(L"winsvpn3", &winn3_luid) != NO_ERROR ||
      !EnableWindowsKillSwitch(winn3_luid, {winn3_gateway}, error)) {
    if (error != nullptr && error->empty()) {
      *error = "The Winn Protocol v3 network policy could not be installed.";
    }
    winsvpn::winn3::StopWindowsWinn3Tunnel();
    g_winn3_tunnel_active.store(false, std::memory_order_release);
    g_last_winn3_proof = winsvpn::winn3::ClassifyCapturedWinn3StartFailure(
        0, false, error != nullptr ? *error : "");
    return false;
  }
  g_winn3_tunnel_active.store(true, std::memory_order_release);
  g_tunnel_promoted.store(true, std::memory_order_release);
  g_last_winn3_proof = winsvpn::winn3::MakeConnectedWinn3StartProof(0);
  return true;
}

bool InstallPrivilegedTunnel(const std::string& raw_config,
                             std::string* error) {
  g_tunnel_promoted.store(false, std::memory_order_release);
  if (!ValidateRestrictedTunnelConfig(raw_config, error)) {
    return false;
  }

  // THE v3 BRANCH, and it is taken before anything AmneziaWG-shaped happens.
  //
  // It has to be first. A standalone v3 configuration has no [Peer], no
  // AllowedIPs and no reason for awg.exe to be installed at all, so every check
  // below this point -- FindAmneziaExecutable, the `Table = off` requirement,
  // RemoveTunnelService -- would refuse a perfectly good v3 config for missing
  // something a different protocol needs.
  //
  // It cannot fire for any configuration that does not carry `[winn3] enabled =
  // true`, which is a section no server serves today and which no existing
  // config in this tree contains. The AmneziaWG path below, including the
  // winn/1 tri-state transport gate a sibling lane closed today, is reached by
  // exactly the same configurations it was reached by before.
  if (winsvpn::winn3::ConfigSelectsWinn3(raw_config)) {
    FailClosedPrivilegedTunnel();
    if (!WindowsTunnelRouteLedgerEmpty()) {
      *error = "A route from the previous session could not be removed, "
               "so a new session was not started.";
      return false;
    }
    return InstallWinn3StandaloneTunnel(raw_config, error);
  }

  const std::wstring amneziawg = FindAmneziaExecutable();
  if (amneziawg.empty()) {
    *error = "AmneziaWG for Windows is not installed.";
    return false;
  }
  FailClosedPrivilegedTunnel();
  if (!WindowsTunnelRouteLedgerEmpty()) {
    *error = "A route from the previous Win's VPN session could not be "
             "removed, so a new session was not started. Restart the "
             "computer, then connect again.";
    return false;
  }
  if (!RemoveTunnelService(amneziawg)) {
    *error = "Unable to remove the previous AmneziaWG tunnel service safely.";
    return false;
  }
  std::vector<std::wstring> excluded_apps =
      WindowsAppExclusionPaths(raw_config, error);
  const bool manual_routes =
      LowerAscii(SectionValue(ParseSection(raw_config, "interface"), "table")) ==
      "off";
  if (!manual_routes) {
    *error = "The Win's VPN product engine requires owned Windows routes.";
    return false;
  }

  // --- Winn Protocol v3 -------------------------------------------------
  //
  // ANTI-DOWNGRADE. From here on there is no path that starts this tunnel
  // without Winn once the configuration selects it. A `[winn] enabled = true`
  // configuration that cannot start the Winn path FAILS; it never becomes a
  // classical AmneziaWG start, because the gateway negotiated winn/3 and a
  // client that quietly speaks winn/1 instead has downgraded it without telling
  // anyone.
  const bool winn_selected =
      winsvpn::winn::WindowsConfigSelectsWinnProtocol(raw_config);
  winsvpn::winn::WindowsWinnParams winn_params;
  std::wstring winn_engine_path;
  uintptr_t winn_seam = winsvpn::winn::kInvalidWinnSeam;
  uint16_t winn_seam_port = 0;
  std::string winn_seam_endpoint;
  const auto fail_winn = [&](const std::string& message) {
    winsvpn::winn::CloseWindowsWinnSeam(winn_seam);
    winn_seam = winsvpn::winn::kInvalidWinnSeam;
    *error = message;
    FailClosedPrivilegedTunnel();
    return false;
  };
  // THE STACKED ARRANGEMENT, told apart from the competing one exactly as the
  // Apple and Android halves tell them apart: by where the Winn engine's own
  // gateway endpoint points. Stacked, it is the Xray inbound on loopback --
  // AmneziaWG -> Winn seam -> Winn engine -> Xray -> edge, two distinct
  // loopback ports and no contention. Competing, it is a real gateway, and then
  // both transports really do want the one AmneziaWG peer-endpoint field.
  //
  // Nothing else on this platform needs to change for it: StartXrayIfNeeded has
  // already run in InstallTunnel, and PrepareWindowsAppExclusions below already
  // prefers `[Xray] Host` over the Winn endpoint when both are present, so the
  // /32 it pins on the physical NIC is Xray's edge -- which is the socket that
  // actually leaves the device here. The Winn engine's socket targets
  // 127.0.0.1 and is never matched by the tunnel's default route.
  const bool winn_stealth_chain =
      winn_selected &&
      SectionBool(ParseSection(raw_config, "xray"), "enabled") &&
      SectionValue(ParseSection(raw_config, "winn"), "endpoint") ==
          "127.0.0.1:" +
              SectionValue(ParseSection(raw_config, "xray"), "localport");
  if (winn_selected) {
    // Winn and the Xray stealth transport are different OUTER transports and
    // cannot both carry one tunnel WHEN THEY COMPETE. Dart refuses that
    // combination earlier; this is the native restatement, so a config that
    // reached here by another route still cannot start two carriers over one
    // adapter. Narrowed, not removed: only the stacked arrangement above is
    // let through, and every other pairing still fails closed here.
    if (SectionBool(ParseSection(raw_config, "xray"), "enabled") &&
        !winn_stealth_chain) {
      return fail_winn(
          "This server asks for Winn Protocol v3 and the stealth transport at "
          "the same time. They are different outer transports and cannot both "
          "carry one tunnel, so this connection was stopped rather than "
          "silently choosing one.");
    }
    std::string winn_error;
    if (!winsvpn::winn::ParseWindowsWinnSection(raw_config, &winn_params,
                                                &winn_error)) {
      return fail_winn(winn_error);
    }
    winn_engine_path = FindWinnDatapathExecutable();
    if (winn_engine_path.empty()) {
      return fail_winn(
          "This server uses Winn Protocol v3, but the Winn datapath engine is "
          "not installed beside this application, so the connection was "
          "stopped rather than started over a different transport.");
    }
    // The seam is bound BEFORE the AmneziaWG configuration is written, for two
    // reasons: its port has to go into that file, and a bound socket means
    // AmneziaWG's first handshake initiations queue in the receive buffer
    // instead of drawing ICMP port-unreachable while the engine is starting.
    winn_seam = winsvpn::winn::BindWindowsWinnSeam(&winn_seam_port,
                                                   &winn_error);
    if (winn_seam == winsvpn::winn::kInvalidWinnSeam) {
      return fail_winn(winn_error);
    }
    winn_seam_endpoint = "127.0.0.1:" + std::to_string(winn_seam_port);
  }

  // STEP 1, and it must be first. PrepareWindowsAppExclusions resolves the
  // carrier address over the *current* physical default route and pins an owned
  // /32 host route to it on the physical interface, before any tunnel default
  // route exists. On a Winn start that address comes from `[winn] endpoint`,
  // because the AmneziaWG peer endpoint is about to become loopback and the
  // Winn gateway may differ from the AmneziaWG gateway anyway. Longest-prefix
  // match then keeps the engine's outer UDP socket on the physical NIC for the
  // whole life of the tunnel.
  if (!error->empty() ||
      !PrepareWindowsAppExclusions(excluded_apps, raw_config, error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }

  // Nothing but loopback, DHCP and the owned carrier and bypass prefixes may
  // leave while the engine comes up. No tunnel adapter is permitted yet.
  if (!EnableWindowsKillSwitch(NET_LUID{}, WindowsPhysicalPermitPrefixes(),
                               error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  const std::wstring directory = ProgramDataDirectory();
  if (!EnsureDirectoryWithDacl(directory, kSystemAdminDirectorySddl) ||
      !ApplyProtectedOwnerAndDacl(directory, kSystemAdminDirectorySddl)) {
    if (winn_selected) {
      return fail_winn("Unable to secure the ProgramData WinsVPN directory.");
    }
    FailClosedPrivilegedTunnel();
    *error = "Unable to secure the ProgramData WinsVPN directory.";
    return false;
  }
  const std::wstring config_path =
      UniqueConfigPath(directory, L"winsvpn", L".conf");
  std::string awg_config = BuildAwgSetconfConfig(raw_config);
  ScopedStringWipe wipe_awg_config(&awg_config);
  // THE SEAM REWRITE. AmneziaWG keeps the tun and keeps doing all of the
  // cryptography; only the destination of its already-encrypted OUTER datagrams
  // changes. RewriteAwgPeerEndpointToSeam refuses anything other than exactly
  // one Endpoint line, because two would mean one of them still pointed at the
  // real gateway.
  if (winn_selected && !awg_config.empty()) {
    std::string seam_config;
    ScopedStringWipe wipe_seam_config(&seam_config);
    if (!winsvpn::winn::RewriteAwgPeerEndpointToSeam(
            awg_config, winn_seam_port, &seam_config)) {
      return fail_winn(
          "Refusing to start Winn Protocol v3: this AmneziaWG configuration "
          "does not have exactly one peer endpoint to redirect to the Winn "
          "loopback seam.");
    }
    awg_config.swap(seam_config);
  }
  if (config_path.empty() || awg_config.empty() ||
      !WriteBytesSecureAtomic(
          config_path, reinterpret_cast<const uint8_t*>(awg_config.data()),
          awg_config.size(), kSystemAdminFileSddl)) {
    if (winn_selected) {
      return fail_winn("Unable to write AmneziaWG tunnel config.");
    }
    FailClosedPrivilegedTunnel();
    *error = "Unable to write AmneziaWG tunnel config.";
    return false;
  }
  ScopedFileDelete delete_awg_config(config_path);
  const uint64_t convergence_start_unix =
      static_cast<uint64_t>(std::time(nullptr));

  if (!StartWinsAwgEngine(config_path, error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  // On a Winn start this is the proof the seam took effect: the running AWG
  // runtime must report the loopback endpoint, not the gateway.
  if (!ValidateLoadedAwgRuntime(raw_config, winn_seam_endpoint, error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  if (!ConfigureWinsAwgInterface(raw_config, error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  NET_LUID policy_tunnel_luid = {};
  if (ConvertInterfaceAliasToLuid(kTunnelName, &policy_tunnel_luid) !=
      NO_ERROR) {
    if (winn_selected) {
      return fail_winn(
          "The Windows tunnel adapter was not found for the network policy.");
    }
    FailClosedPrivilegedTunnel();
    *error = "The Windows tunnel adapter was not found for the network policy.";
    return false;
  }
  if (!EnableWindowsKillSwitch(policy_tunnel_luid,
                               WindowsPhysicalPermitPrefixes(), error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  if (!StartWindowsAppExclusions(excluded_apps, raw_config, error)) {
    if (winn_selected) return fail_winn(*error);
    FailClosedPrivilegedTunnel();
    return false;
  }
  if (winn_selected) {
    std::string winn_error;
    if (!ReadLoadedAwgListenPort(&winn_params.awg_listen_port)) {
      return fail_winn(
          "Refusing to start Winn Protocol v3: the AmneziaWG runtime did not "
          "report its own source port, so the Winn seam could not tell it "
          "from another local sender.");
    }
    // Ownership of the seam passes to this call on both outcomes.
    const bool started = winsvpn::winn::StartWindowsWinnEngine(
        winn_engine_path, winn_seam, winn_params, &winn_error);
    winn_seam = winsvpn::winn::kInvalidWinnSeam;
    if (!started) {
      return fail_winn(winn_error);
    }
    g_winn_tunnel_active.store(true, std::memory_order_release);
  }
  AwgTransferSnapshot baseline;
  if (!ReadAwgTransferSnapshot(&baseline)) {
    *error =
        "The Windows AWG transfer counters were unavailable before convergence.";
    FailClosedPrivilegedTunnel();
    return false;
  }
  std::string convergence_probe_address;
  if (!InstallWindowsTunnelConvergenceProbeRoute(
          raw_config, &convergence_probe_address, error) ||
      !WaitForAwgConvergence(raw_config, baseline,
                             convergence_probe_address,
                             convergence_start_unix, error)) {
    FailClosedPrivilegedTunnel();
    return false;
  }
  // THE SECOND HALF OF THE WINN PROMOTION GATE.
  //
  // This replaced a check for the substring `"up":true` in the engine's create
  // acknowledgement. datapath/status.go says in as many words that `up` is link
  // liveness -- "a socket exists" -- and must not gate route promotion. The
  // conjunction it names as the correct gate is
  // `transport_observed_both_ways AND a recent host AWG handshake`, and both
  // halves are now required: WaitForAwgConvergence above proved the handshake
  // and nontrivial bidirectional peer transfer, and this proves the carrier
  // actually moved AmneziaWG transport datagrams in both directions.
  if (winn_selected && !WaitForWinnTransportConvergence(error)) {
    FailClosedPrivilegedTunnel();
    return false;
  }
  if (!InstallWindowsTunnelRoutes(raw_config, error)) {
    FailClosedPrivilegedTunnel();
    return false;
  }
  if (!EnableWindowsKillSwitch(policy_tunnel_luid,
                               WindowsPhysicalPermitPrefixes(), error)) {
    FailClosedPrivilegedTunnel();
    return false;
  }
  g_tunnel_promoted.store(true, std::memory_order_release);
  return true;
}

bool UninstallPrivilegedTunnel(std::string* error) {
  g_tunnel_promoted.store(false, std::memory_order_release);
  g_winn_tunnel_active.store(false, std::memory_order_release);
  // A standalone v3 tunnel is torn down here and RETURNS here: it shares no
  // step with what follows. Stopping the relay destroys the "winsvpn3" adapter,
  // and the addresses, MTU and interface-scoped routes installed on it cease to
  // exist with the interface -- so the posture teardown is structural rather
  // than a sequence of netsh deletions that could half-fail. The one artefact
  // that outlives the adapter, the physical /32 pin that kept the engine's own
  // outer socket out of the tunnel, is removed by StopWindowsWinn3Tunnel first.
  if (g_winn3_tunnel_active.exchange(false, std::memory_order_acq_rel)) {
    winsvpn::winn3::StopWindowsWinn3Tunnel();
    if (g_last_winn3_proof.outcome ==
        winsvpn::winn3::Winn3ProofOutcome::kConnected) {
      g_last_winn3_proof = winsvpn::winn3::Winn3StartProof();
    }
    return true;
  }
  const std::wstring amneziawg = FindAmneziaExecutable();
  // Stopped before the routes come down, so the engine is not still addressing
  // a gateway whose physical /32 pin is about to be removed. Idempotent when
  // this tunnel was never a winn/3 one.
  winsvpn::winn::StopWindowsWinnEngine();
  StopWindowsAppExclusions();
  RemoveWindowsTunnelRoutes();
  const std::wstring config_path =
      JoinPath(ProgramDataDirectory(), L"winsvpn.conf");
  const bool engine_stopped = StopWinsAwgEngine();
  const TunnelServiceStatus legacy_status = QueryTunnelServiceStatus();
  const bool legacy_removed =
      legacy_status.query_ok && !legacy_status.exists
          ? true
          : !amneziawg.empty() && RemoveTunnelService(amneziawg);
  DeleteFileW(config_path.c_str());
  if (!engine_stopped || !legacy_removed) {
    *error = "The Win's VPN AWG engine did not stop cleanly.";
    return false;
  }
  return true;
}
#endif

#if !defined(WINS_TUNNEL_SERVICE_CORE)
bool InstallTunnel(const std::string& raw_config,
                   int64_t transition_generation, std::string* error) {
  g_committed_generation.store(0, std::memory_order_release);
  if (IsBackendShuttingDown() ||
      !IsWindowsStartGenerationAllowed(transition_generation)) {
    *error = "Tunnel start was canceled before the transport launched.";
    return false;
  }
  if (!ValidateRestrictedTunnelConfig(raw_config, error) ||
      !StartXrayIfNeeded(raw_config, error)) {
    return false;
  }
  if (IsBackendShuttingDown() ||
      !IsWindowsStartGenerationAllowed(transition_generation)) {
    StopXrayProcess();
    *error = "Tunnel start was canceled while the transport launched.";
    return false;
  }
  uint32_t carrier_pid = 0;
  bool commit_allowed = false;
  {
    std::lock_guard<std::recursive_mutex> lock(g_xray_mutex);
    carrier_pid =
        g_xray_process.hProcess == nullptr ? 0 : g_xray_process.dwProcessId;
  }
  if (IsBackendShuttingDown() ||
      !IsWindowsStartGenerationAllowed(transition_generation)) {
    StopXrayProcess();
    *error = "Tunnel start was canceled before its service boundary.";
    return false;
  }
  if (!ArmWindowsTunnelStartCancellation(
          static_cast<uint64_t>(transition_generation), error)) {
    StopXrayProcess();
    return false;
  }
  if (IsBackendShuttingDown() ||
      !IsWindowsStartGenerationAllowed(transition_generation)) {
    SignalWindowsTunnelStartCancellation();
    DisarmWindowsTunnelStartCancellation();
    StopXrayProcess();
    *error = "Tunnel start was canceled while arming its service boundary.";
    return false;
  }
  const bool service_started = StartWindowsTunnelThroughService(
      raw_config, carrier_pid, static_cast<uint64_t>(transition_generation),
      error);
  DisarmWindowsTunnelStartCancellation();
  if (!service_started) {
    StopXrayProcess();
    return false;
  }
  if (!IsWindowsStartGenerationAllowed(transition_generation)) {
    std::string cleanup_error;
    StopWindowsTunnelThroughService(&cleanup_error);
    StopXrayProcess();
    *error = "Tunnel start was canceled before it could be committed.";
    return false;
  }
  {
    // Serialize the final generation check/commit with stop's publication of
    // its cancellation floor. Without this lock, stop could finish teardown
    // between the last check and power protection, allowing a canceled worker
    // to resurrect a committed generation after disconnect completed.
    std::lock_guard<std::mutex> lock(g_transition_commit_mutex);
    commit_allowed =
        IsWindowsStartGenerationAllowed(transition_generation) &&
        !g_stop_in_flight.load(std::memory_order_acquire) &&
        !IsBackendShuttingDown();
    if (commit_allowed) {
      g_committed_generation.store(
          static_cast<uint64_t>(transition_generation),
          std::memory_order_release);
      EnableTunnelPowerProtection();
    }
  }
  if (!commit_allowed) {
    std::string cleanup_error;
    StopWindowsTunnelThroughService(&cleanup_error);
    StopXrayProcess();
    *error = "Tunnel start was canceled at its commit boundary.";
    return false;
  }
  return true;
}

bool UninstallTunnel(std::string* error) {
  g_committed_generation.store(0, std::memory_order_release);
  std::string service_error;
  const bool service_stopped =
      StopWindowsTunnelThroughService(&service_error);
  // Local carrier and power-state cleanup must never depend on the manager
  // replying successfully. A crashed/restarting service is exactly when Xray
  // residue would otherwise strand stop settlement and future fallback.
  StopXrayProcess();
  DisableTunnelPowerProtection();
  if (g_last_winn3_proof.outcome ==
      winsvpn::winn3::Winn3ProofOutcome::kConnected) {
    g_last_winn3_proof = winsvpn::winn3::Winn3StartProof();
  }
  if (!service_stopped) {
    if (error != nullptr) {
      *error = service_error.empty()
                   ? "The protected tunnel manager did not confirm teardown."
                   : service_error;
    }
    return false;
  }
  return true;
}
#endif

#if !defined(WINS_TUNNEL_SERVICE_CORE)
std::string ConfigFromCall(
    const flutter::MethodCall<flutter::EncodableValue>& call) {
  const flutter::EncodableValue* args = call.arguments();
  if (args == nullptr || !std::holds_alternative<flutter::EncodableMap>(*args)) {
    return "";
  }
  const auto& map = std::get<flutter::EncodableMap>(*args);
  const auto it = map.find(flutter::EncodableValue("config"));
  if (it == map.end() || !std::holds_alternative<std::string>(it->second)) {
    return "";
  }
  return std::get<std::string>(it->second);
}

bool TryStringArgFromCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    const std::string& key, std::string* value) {
  if (value == nullptr) return false;
  value->clear();
  const flutter::EncodableValue* args = call.arguments();
  if (args == nullptr || !std::holds_alternative<flutter::EncodableMap>(*args)) {
    return false;
  }
  const auto& map = std::get<flutter::EncodableMap>(*args);
  const auto it = map.find(flutter::EncodableValue(key));
  if (it == map.end() || !std::holds_alternative<std::string>(it->second)) {
    return false;
  }
  *value = std::get<std::string>(it->second);
  return true;
}

std::string StringArgFromCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    const std::string& key) {
  std::string value;
  TryStringArgFromCall(call, key, &value);
  return value;
}

enum class Int64ArgStatus { kMissing, kValid, kInvalid };

Int64ArgStatus Int64ArgFromCall(
    const flutter::MethodCall<flutter::EncodableValue>& call,
    const std::string& key, int64_t* value) {
  if (value == nullptr) {
    return Int64ArgStatus::kInvalid;
  }
  const flutter::EncodableValue* args = call.arguments();
  if (args == nullptr || !std::holds_alternative<flutter::EncodableMap>(*args)) {
    return Int64ArgStatus::kMissing;
  }
  const auto& map = std::get<flutter::EncodableMap>(*args);
  const auto it = map.find(flutter::EncodableValue(key));
  if (it == map.end()) {
    return Int64ArgStatus::kMissing;
  }
  if (std::holds_alternative<int32_t>(it->second)) {
    *value = std::get<int32_t>(it->second);
    return Int64ArgStatus::kValid;
  }
  if (std::holds_alternative<int64_t>(it->second)) {
    *value = std::get<int64_t>(it->second);
    return Int64ArgStatus::kValid;
  }
  return Int64ArgStatus::kInvalid;
}

LRESULT CALLBACK AnnouncementWindowProc(HWND hwnd,
                                        UINT message,
                                        WPARAM wparam,
                                        LPARAM lparam) {
  return DefWindowProcW(hwnd, message, wparam, lparam);
}

std::wstring NotificationText(const std::wstring& value, size_t max_chars) {
  if (value.size() <= max_chars) {
    return value;
  }
  if (max_chars <= 3) {
    return value.substr(0, max_chars);
  }
  return value.substr(0, max_chars - 3) + L"...";
}

bool ShowAnnouncementNotification(const std::string& title,
                                  const std::string& body) {
  if (Trim(body).empty()) {
    return false;
  }
  const std::wstring wide_title =
      NotificationText(Utf8ToWide(title.empty() ? "Win's VPN Announcement"
                                                : title),
                       63);
  const std::wstring wide_body = NotificationText(Utf8ToWide(body), 255);
  std::thread([wide_title, wide_body]() {
    const wchar_t kWindowClass[] = L"WinsVpnAnnouncementNotificationWindow";
    HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSW window_class = {};
    window_class.lpfnWndProc = AnnouncementWindowProc;
    window_class.hInstance = instance;
    window_class.lpszClassName = kWindowClass;
    RegisterClassW(&window_class);

    HWND hwnd = CreateWindowExW(0, kWindowClass, L"", 0, 0, 0, 0, 0,
                                HWND_MESSAGE, nullptr, instance, nullptr);
    if (hwnd == nullptr) {
      return;
    }

    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = hwnd;
    data.uID = 5300;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_INFO;
    data.uCallbackMessage = WM_APP + 5300;
    data.hIcon = LoadIconW(nullptr, IDI_INFORMATION);
    data.dwInfoFlags = NIIF_INFO;
    wcsncpy_s(data.szInfoTitle, wide_title.c_str(), _TRUNCATE);
    wcsncpy_s(data.szInfo, wide_body.c_str(), _TRUNCATE);

    if (Shell_NotifyIconW(NIM_ADD, &data)) {
      Shell_NotifyIconW(NIM_MODIFY, &data);
      Sleep(12000);
      Shell_NotifyIconW(NIM_DELETE, &data);
    }
    DestroyWindow(hwnd);
  }).detach();
  return true;
}
#endif

}  // namespace

#if defined(WINS_TUNNEL_SERVICE_CORE)
bool RunningEmulatedOnArm64() {
  USHORT process_machine = 0;
  USHORT native_machine = 0;
  return IsWow64Process2(GetCurrentProcess(), &process_machine,
                         &native_machine) != FALSE &&
         native_machine == IMAGE_FILE_MACHINE_ARM64 &&
#if defined(_M_ARM64)
         false;
#else
         true;
#endif
}

bool StartPrivilegedWindowsTunnel(const std::string& config,
                                  std::string* error) {
  if (RunningEmulatedOnArm64()) {
    *error = "This x64 build cannot start the VPN on this Arm64 computer. "
             "An independently verified Arm64 build is required.";
    return false;
  }
  return InstallPrivilegedTunnel(config, error);
}

bool StopPrivilegedWindowsTunnel(std::string* error) {
  return UninstallPrivilegedTunnel(error);
}

bool CleanupPrivilegedWindowsTunnel(std::string* error) {
  if (error == nullptr) {
    return false;
  }
  error->clear();
  std::string tunnel_error;
  const bool tunnel_stopped = UninstallPrivilegedTunnel(&tunnel_error);
  std::string split_error;
  const bool split_cleaned = CleanupWindowsSplitTunnelForUninstall(&split_error);
  std::string policy_error;
  const bool policy_removed = DisableWindowsKillSwitch(&policy_error);
  if (!tunnel_stopped) {
    *error = tunnel_error;
  } else if (!split_cleaned) {
    *error = split_error;
  } else if (!policy_removed) {
    *error = policy_error;
  }
  return tunnel_stopped && split_cleaned && policy_removed;
}

bool IsPrivilegedWindowsTunnelRunning() {
  return IsTunnelRunning();
}

// Non-secret liveness only, and it is what the kStatus command returns. The
// Winn fields are booleans about this host's own observations, never the
// engine's status document: that document names the gateway endpoint and the
// local endpoint, and this string crosses a pipe the elevated-admin role may
// read.
static std::string WinnRuntimeStatusFields() {
  // The standalone v3 tunnel reports its own three booleans, appended rather
  // than folded into the winn/1 ones: "the AmneziaWG carrier moved a transport
  // datagram both ways" and "an inner packet reached the host device" are
  // different claims about different protocols, and a reader that saw one under
  // the other's name would draw the wrong conclusion from a true value. The
  // status string is substring-matched by IsExpectedCommittedManagerStatus, so
  // appending fields cannot disturb what already reads it.
  //
  // These are this host's OWN observations and the engine's two booleans -- not
  // the v3 status document. That document is safe to log in full by
  // construction, but this string crosses a pipe the elevated-admin role may
  // read, and the rule on this pipe is booleans only.
  if (g_winn3_tunnel_active.load(std::memory_order_acquire)) {
    const bool running = winsvpn::winn3::WindowsWinn3TunnelRunning();
    const bool promoted = winsvpn::winn3::WindowsWinn3TunnelPromoted();
    return std::string("winn=0;winn_engine=0;winn_transport=0;winn3=1") +
           ";winn3_datapath=" + (running ? "1" : "0") +
           ";winn3_promoted=" + (promoted ? "1" : "0");
  }
  if (!g_winn_tunnel_active.load(std::memory_order_acquire)) {
    return "winn=0;winn_engine=0;winn_transport=0;winn3=0;winn3_datapath=0"
           ";winn3_promoted=0";
  }
  const bool engine_running = winsvpn::winn::WindowsWinnEngineRunning();
  const bool transport =
      engine_running &&
      winsvpn::winn::WindowsWinnTransportObservedBothWays(nullptr);
  // The v3 booleans are emitted as zero rather than omitted, so that the field
  // set is the same in all three branches. A reader that has to tell "this
  // tunnel is not v3" from "this host is too old to say" has been given a
  // second question it cannot answer.
  return std::string("winn=1;winn_engine=") + (engine_running ? "1" : "0") +
         ";winn_transport=" + (transport ? "1" : "0") +
         ";winn3=0;winn3_datapath=0;winn3_promoted=0";
}

std::string PrivilegedWindowsTunnelRuntimeStatus() {
  const std::string winn_fields = ";" + WinnRuntimeStatusFields();
  std::string response;
  ScopedStringWipe wipe_response(&response);
  AwgRuntimeSnapshot runtime;
  if (!IsTunnelRunning() || !ReadAwgRuntimeUapi(&response, 1000) ||
      !ParseAwgRuntimeUapi(response, &runtime) || runtime.peers.size() != 1) {
    return "awg_query=0;awg_peer_count=0;awg_handshake=0;awg_rx=0;awg_tx=0;"
           "awg_handshake_unix=0;awg_rx_bytes=0;awg_tx_bytes=0" +
           winn_fields;
  }
  const AwgRuntimePeer& peer = runtime.peers[0];
  const uint64_t handshake =
      peer.has_last_handshake_time_sec ? peer.last_handshake_time_sec : 0;
  const uint64_t rx = peer.has_rx_bytes ? peer.rx_bytes : 0;
  const uint64_t tx = peer.has_tx_bytes ? peer.tx_bytes : 0;
  return "awg_query=1;awg_peer_count=1;awg_handshake=" +
         std::to_string(handshake > 0 ? 1 : 0) +
         ";awg_rx=" + std::to_string(rx > 0 ? 1 : 0) +
         ";awg_tx=" + std::to_string(tx > 0 ? 1 : 0) +
         ";awg_handshake_unix=" + std::to_string(handshake) +
         ";awg_rx_bytes=" + std::to_string(rx) +
         ";awg_tx_bytes=" + std::to_string(tx) + winn_fields;
}

bool RunPrivilegedWindowsTunnelValidationSelfTest(std::string* error) {
  if (error == nullptr) {
    return false;
  }
  error->clear();
  int64_t canceled_floor = 0;
  if (IsTransitionGenerationAllowed(0, canceled_floor) ||
      !IsTransitionGenerationAllowed(1, canceled_floor)) {
    *error = "Missing or first tunnel transition generation was handled incorrectly.";
    return false;
  }
  canceled_floor = RaisedCanceledGenerationFloor(canceled_floor, 2);
  if (IsTransitionGenerationAllowed(1, canceled_floor) ||
      IsTransitionGenerationAllowed(2, canceled_floor) ||
      !IsTransitionGenerationAllowed(3, canceled_floor)) {
    *error = "Canceled or newer tunnel transition generation was handled incorrectly.";
    return false;
  }
  if (RaisedCanceledGenerationFloor(canceled_floor, 1) != canceled_floor) {
    *error = "Tunnel cancellation generation floor moved backwards.";
    return false;
  }
  std::set<std::string> allowed_ip_self_test;
  if (!ParseAllowedIpSet(
          "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
          &allowed_ip_self_test) ||
      allowed_ip_self_test.size() != 4 ||
      ParseAllowedIpSet("0.0.0.0/33", &allowed_ip_self_test) ||
      ParseAllowedIpSet("not-an-address/24", &allowed_ip_self_test)) {
    *error = "AWG AllowedIPs validation self-test failed.";
    return false;
  }
  if (!EndpointsMatch("127.0.0.1:9110", "127.0.0.1:9110") ||
      !EndpointsMatch("127.0.0.1:9110", "localhost:9110") ||
      EndpointsMatch("127.0.0.1:9110", "localhost:9111") ||
      EndpointsMatch("127.0.0.1:9110", "invalid.invalid:9110")) {
    *error = "AWG endpoint validation self-test failed.";
    return false;
  }
  const std::string uapi_self_test =
      "private_key=" + std::string(64, '1') + "\n" +
      "public_key=" + std::string(64, '2') + "\n" +
      "preshared_key=" + std::string(64, '0') + "\n" +
      "endpoint=127.0.0.1:42110\n"
      "allowed_ip=0.0.0.0/1\n"
      "allowed_ip=128.0.0.0/1\n"
      "allowed_ip=::/1\n"
      "allowed_ip=8000::/1\n"
      "last_handshake_time_sec=1784450000\n"
      "rx_bytes=172\n"
      "tx_bytes=164\n"
      "errno=0\n\n";
  AwgRuntimeSnapshot uapi_snapshot;
  if (!ParseAwgRuntimeUapi(uapi_self_test, &uapi_snapshot) ||
      uapi_snapshot.peers.size() != 1 ||
      uapi_snapshot.peers[0].allowed_ips.size() != 4 ||
      !uapi_snapshot.peers[0].has_last_handshake_time_sec ||
      uapi_snapshot.peers[0].last_handshake_time_sec != 1784450000 ||
      !uapi_snapshot.peers[0].has_rx_bytes ||
      uapi_snapshot.peers[0].rx_bytes != 172 ||
      !uapi_snapshot.peers[0].has_tx_bytes ||
      uapi_snapshot.peers[0].tx_bytes != 164) {
    *error = "AWG protected UAPI AllowedIPs self-test failed.";
    return false;
  }
  const AwgRuntimePeer& converged_peer = uapi_snapshot.peers[0];
  if (!IsAwgPeerConverged(converged_peer, 100, 100, 1784450000,
                          1784450005) ||
      IsAwgPeerConverged(converged_peer, 150, 140, 1784450000,
                         1784450005) ||
      IsAwgPeerConverged(converged_peer, 100, 100, 1784450040,
                         1784450040) ||
      IsAwgPeerConverged(converged_peer, 100, 100, 1784450000,
                         1784450040)) {
    *error = "AWG convergence freshness or transfer threshold self-test failed.";
    return false;
  }
  const std::string safe =
      "[Interface]\n"
      "PrivateKey = test-private-key\n"
      "Address = 10.90.0.2/32\n"
      "DNS = 9.9.9.9\n"
      "Jc = 2\n"
      "Jmin = 10\n"
      "Jmax = 30\n"
      "S1 = 16\n"
      "S2 = 80\n"
      "S3 = 16\n"
      "S4 = 0\n"
      "H1 = 11\n"
      "H2 = 22\n"
      "H3 = 33\n"
      "H4 = 44\n"
      "[Peer]\n"
      "PublicKey = test-public-key\n"
      "Endpoint = 127.0.0.1:9110\n"
      "AllowedIPs = 0.0.0.0/0\n";
  std::string validation_error;
  if (!ValidateRestrictedTunnelConfig(safe, &validation_error)) {
    *error = "A safe tunnel configuration failed validation.";
    return false;
  }
  const char served_winn3[] =
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
  for (const std::string& document : {
           std::string(served_winn3), safe + served_winn3}) {
    if (!ValidateRestrictedTunnelConfig(document, &validation_error)) {
      *error = "A served standalone Winn v3 document failed outer validation.";
      return false;
    }
  }
  const std::string served(served_winn3);
  std::string mismatched = served;
  mismatched.replace(mismatched.find("selected_node = lab-alpha"),
                     std::strlen("selected_node = lab-alpha"),
                     "selected_node = lab-beta");
  std::string malformed = served;
  malformed.replace(malformed.find("static_private = "),
                    malformed.find('\n', malformed.find("static_private = ")) -
                        malformed.find("static_private = "),
                    "static_private = malformed");
  for (const std::string& document : {
           served + "node = lab-alpha\n",
           served + "[winn3]\nKeysFile = C:\\private.key\n",
           served + "[Xray]\nEnabled = true\n",
           mismatched, malformed}) {
    if (ValidateRestrictedTunnelConfig(document, &validation_error)) {
      *error = "An unsafe standalone Winn v3 document passed outer validation.";
      return false;
    }
  }
  const std::string injected_obfuscation =
      safe.substr(0, safe.find("H4 = 44")) +
      "H4 = 44\\nTable = auto\n" +
      safe.substr(safe.find("H4 = 44") + std::strlen("H4 = 44\n"));
  validation_error.clear();
  if (ValidateRestrictedTunnelConfig(injected_obfuscation, &validation_error)) {
    *error = "An injected AWG obfuscation value passed validation.";
    return false;
  }
  // AWG header keyspace self-test. `safe` above already proves the legacy
  // 11/22/33/44 set still validates, which is load-bearing -- these parameters
  // are not negotiated, so rejecting them locks out every existing peer. What
  // follows proves the other half: a full-width uint32 header set is accepted
  // (a value under 2^24 leaves the top header byte zero and preserves the
  // vanilla WireGuard shape, which is the entire point of the widened
  // keyspace), while reserved, colliding and over-range values are still
  // refused. The over-range case is deliberately 4294967296 -- ten digits, so
  // it clears the digit check and can only be caught by the value check, and
  // it is the exact value the previous strtoul would have saturated to
  // ULONG_MAX and let through.
  const auto with_headers = [&safe](const std::string& h1, const std::string& h2,
                                    const std::string& h3,
                                    const std::string& h4) {
    return safe.substr(0, safe.find("H1 = 11")) + "H1 = " + h1 + "\nH2 = " + h2 +
           "\nH3 = " + h3 + "\nH4 = " + h4 + "\n" +
           safe.substr(safe.find("H4 = 44") + std::strlen("H4 = 44\n"));
  };
  validation_error.clear();
  if (!ValidateRestrictedTunnelConfig(
          with_headers("3221225473", "2164260866", "4026531843", "1073741828"),
          &validation_error)) {
    *error = "A full-width AWG header set failed validation.";
    return false;
  }
  std::string setconf_self_test = BuildAwgSetconfConfig(safe);
  ScopedStringWipe wipe_setconf_self_test(&setconf_self_test);
  if (setconf_self_test.find("PrivateKey = test-private-key") ==
          std::string::npos ||
      setconf_self_test.find("AllowedIPs = 0.0.0.0/0") ==
          std::string::npos ||
      setconf_self_test.find("Address =") != std::string::npos ||
      setconf_self_test.find("DNS =") != std::string::npos ||
      setconf_self_test.find("MTU =") != std::string::npos ||
      setconf_self_test.find("Table =") != std::string::npos) {
    *error = "AWG setconf serializer self-test failed.";
    return false;
  }
  const std::string no_exclusions =
      safe + "[WinsApp]\nExcludedPackages =\nExcludedPathsB64 =\n";
  if (!ValidateRestrictedTunnelConfig(no_exclusions, &validation_error)) {
    *error = "Empty optional app exclusions failed validation.";
    return false;
  }
  bool requires_xray = true;
  if (!PrivilegedWindowsTunnelConfigRequiresXray(
          safe, &requires_xray, &validation_error) || requires_xray) {
    *error = "A direct AWG configuration incorrectly required an Xray carrier.";
    return false;
  }
  const std::string xray = safe +
      "[Xray]\nEnabled = true\nUUID = 00000000-0000-0000-0000-000000000000\n"
      "Host = example.invalid\nPort = 80\nServerName = example.invalid\n"
      "Path = /wins-stealth-tunnel\nSecurity = none\nLocalPort = 42110\n"
      "RemoteAwgHost = 127.0.0.1\nRemoteAwgPort = 9110\n";
  requires_xray = false;
  if (!PrivilegedWindowsTunnelConfigRequiresXray(
          xray, &requires_xray, &validation_error) || !requires_xray) {
    *error = "An Xray fallback configuration did not require a carrier process.";
    return false;
  }
  // The edge list is supplied rather than resolved: this self-test must not
  // make a DNS query, and after the 2026-08-07 DNS-egress fix BuildXrayConfig
  // cannot resolve one for it. TEST-NET-3 (RFC 5737) literals, two of them so
  // the balancer shape is exercised rather than assumed.
  const std::string xray_runtime = BuildXrayConfig(
      ParseSection(xray, "xray"), {"203.0.113.10", "203.0.113.11"});
  for (const std::string& required : {
           std::string{"\"protocol\":\"tunnel\""},
           // The carrier address must be a literal and the SNI/Host header
           // must still be the name -- that pairing IS the fix, so assert it
           // rather than leaving it to a code reading.
           std::string{"\"address\":\"203.0.113.10\""},
           std::string{"\"address\":\"203.0.113.11\""},
           std::string{"\"headers\":{\"Host\":\"example.invalid\"}"},
           std::string{"\"tag\":\"vless-ws-edge-0\""},
           std::string{"\"balancerTag\":\"vless-ws-balancer\""},
           std::string{"\"enabled\":false"},
           std::string{"\"xudpConcurrency\":0"},
           std::string{"\"xudpProxyUDP443\":\"skip\""},
       }) {
    if (xray_runtime.find(required) == std::string::npos) {
      *error = "The Windows Xray fallback lost its bounded UDP carrier contract.";
      return false;
    }
  }
  // A hostname must never reach the Xray child again.
  if (xray_runtime.find("\"address\":\"example.invalid\"") != std::string::npos) {
    *error = "The Windows Xray fallback handed the carrier hostname to Xray.";
    return false;
  }

  const std::vector<std::pair<std::string, std::string>> rejected = {
      {safe + "PostUp = powershell.exe -Command whoami\n",
       "script directive"},
      {safe + "[WinsApp]\nExcludedPackages = example\n"
              "ExcludedPackages = duplicate\n",
       "duplicate directive"},
      {safe + "[Unknown]\nValue = unsafe\n", "unknown section"},
      {safe + "[WinsDebug]\nUnknownKey = unsafe\n", "unknown directive"},
      {"[Interface]\nPrivateKey =\nAddress = 10.90.0.2/32\n"
       "[Peer]\nPublicKey = test-public-key\nEndpoint = 127.0.0.1:9110\n"
       "AllowedIPs = 0.0.0.0/0\n",
       "empty required directive"},
      {safe + std::string(513 * 1024, 'x'), "oversized input"},
      {safe + std::string("embedded\0nul", 12), "embedded NUL"},
      {with_headers("4294967296", "22", "33", "44"), "over-range AWG header"},
      {with_headers("99999999999", "22", "33", "44"),
       "over-length AWG header"},
      {with_headers("4", "22", "33", "44"), "reserved AWG header"},
      {with_headers("11", "11", "33", "44"), "colliding AWG header"},
  };
  for (const auto& test : rejected) {
    validation_error.clear();
    if (ValidateRestrictedTunnelConfig(test.first, &validation_error)) {
      *error = "Tunnel validation accepted a rejected " + test.second + ".";
      return false;
    }
  }
  return true;
}

bool PrivilegedWindowsTunnelConfigRequiresXray(const std::string& config,
                                               bool* requires_xray,
                                               std::string* error) {
  if (requires_xray == nullptr || error == nullptr ||
      !ValidateRestrictedTunnelConfig(config, error)) {
    return false;
  }
  *requires_xray = SectionBool(ParseSection(config, "xray"), "enabled");
  return true;
}
#else
bool RunWindowsSecureStorageSelfTest(std::string* error) {
  if (error == nullptr) return false;
  error->clear();
  const std::wstring local_app_data = EnvVar(L"LOCALAPPDATA");
  const std::wstring parent = JoinPath(local_app_data, L"WinsVPN");
  std::wstring sddl;
  if (local_app_data.empty() || !CurrentUserSystemDaclSddl(&sddl) ||
      !EnsureDirectory(parent)) {
    *error = "Secure-storage self-test setup failed.";
    return false;
  }

  const std::wstring directory =
      UniqueSiblingPath(JoinPath(parent, L"SecureStorageSelfTest"), L"dir");
  const std::wstring path = JoinPath(directory, L"probe.wvdp");
  const std::wstring legacy_path = JoinPath(directory, L"legacy.txt");
  const std::wstring tampered_directory =
      JoinPath(directory, L"tampered-directory.wvdp");
  const std::wstring tampered_link = JoinPath(directory, L"tampered-link.wvdp");
  std::string plaintext = "winsvpn-dpapi-self-test";
  std::string decrypted;
  std::string corrupted_plaintext;
  std::string migration_plaintext;
  ScopedStringWipe wipe_plaintext(&plaintext);
  ScopedStringWipe wipe_decrypted(&decrypted);
  ScopedStringWipe wipe_corrupted_plaintext(&corrupted_plaintext);
  ScopedStringWipe wipe_migration_plaintext(&migration_plaintext);
  std::vector<uint8_t> stored;
  std::vector<uint8_t> corrupted;

  bool ok = EnsureDirectoryWithDacl(directory, sddl) &&
            HasStrictCurrentUserSystemDacl(directory) &&
            !IsAllowedSecureTextName("../vpn_config.txt") &&
            !IsAllowedSecureTextName("VPN_CONFIG.TXT") &&
            WriteEncryptedWindowsTextAtPath("vpn_config.txt", plaintext, path,
                                            sddl) &&
            HasStrictCurrentUserSystemDacl(path) &&
            ReadRegularFileBounded(path,
                                   kMaximumSecureTextBytes + 1024 * 1024,
                                   &stored) &&
            UnprotectWindowsText("vpn_config.txt", stored, &decrypted) &&
            decrypted == plaintext;
  if (ok) {
    corrupted = stored;
    corrupted.back() ^= 0x01;
    ok = !UnprotectWindowsText("vpn_config.txt", corrupted,
                               &corrupted_plaintext);
  }
  if (ok) {
    const bool directory_created =
        CreateDirectoryW(tampered_directory.c_str(), nullptr) != FALSE;
    const bool tamper_rejected =
        directory_created && !WipeAndDeleteRegularFile(tampered_directory) &&
        DirectoryExists(tampered_directory);
    const bool tamper_cleaned =
        directory_created && RemoveDirectoryW(tampered_directory.c_str()) != FALSE;
    ok = tamper_rejected && tamper_cleaned;
  }
  if (ok) {
    const bool link_created =
        CreateSymbolicLinkW(tampered_link.c_str(), path.c_str(),
                            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != FALSE;
    if (link_created) {
      ok = !WipeAndDeleteRegularFile(tampered_link) && FileExists(path) &&
           DeleteFileW(tampered_link.c_str()) != FALSE;
    }
  }
  if (ok) {
    ok = WriteBytesSecureAtomic(
        legacy_path, reinterpret_cast<const uint8_t*>(plaintext.data()),
        plaintext.size(), sddl);
  }
  HANDLE legacy_lock = INVALID_HANDLE_VALUE;
  if (ok) {
    legacy_lock = CreateFileW(legacy_path.c_str(), GENERIC_READ, 0, nullptr,
                              OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr);
    migration_plaintext = plaintext;
    std::string migration_error;
    const bool first_cleanup =
        legacy_lock != INVALID_HANDLE_VALUE &&
        RetireLegacyPlaintextFile(legacy_path, &migration_plaintext,
                                  &migration_error);
    ok = !first_cleanup && migration_plaintext.empty() && FileExists(path) &&
         FileExists(legacy_path);
  }
  if (legacy_lock != INVALID_HANDLE_VALUE) CloseHandle(legacy_lock);
  if (ok) {
    migration_plaintext = plaintext;
    std::string migration_error;
    ok = RetireLegacyPlaintextFile(legacy_path, &migration_plaintext,
                                   &migration_error) &&
         FileExists(path) && !FileExists(legacy_path);
  }

  if (!stored.empty()) SecureZeroMemory(stored.data(), stored.size());
  if (!corrupted.empty()) {
    SecureZeroMemory(corrupted.data(), corrupted.size());
  }
  const bool file_cleaned = WipeAndDeleteRegularFile(path);
  const bool legacy_cleaned = WipeAndDeleteRegularFile(legacy_path);
  DeleteFileW(tampered_link.c_str());
  RemoveDirectoryW(tampered_directory.c_str());
  const bool directory_cleaned = RemoveDirectoryW(directory.c_str()) != FALSE;
  if (!ok || !file_cleaned || !legacy_cleaned || !directory_cleaned) {
    *error =
        "Windows DPAPI, DACL, migration retry, tamper, or cleanup self-test failed.";
    return false;
  }
  return true;
}

void RegisterWindowsTunnelBackend(flutter::BinaryMessenger* messenger) {
  {
    std::lock_guard<std::mutex> lock(g_async_worker_mutex);
    g_backend_shutting_down = false;
  }
  g_channel = std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
      messenger, "wins_vpn/tunnel",
      &flutter::StandardMethodCodec::GetInstance());

  g_channel->SetMethodCallHandler(
      [](const flutter::MethodCall<flutter::EncodableValue>& call,
         std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
        if (call.method_name() == "readSecureText") {
          std::string name;
          if (!TryStringArgFromCall(call, "name", &name)) {
            result->Error("BAD_ARGS", "Secure text name is missing.");
            return;
          }
          std::string value;
          ScopedStringWipe wipe_value(&value);
          std::string error;
          bool found = false;
          if (!ReadWindowsSecureText(name, &value, &found, &error)) {
            result->Error("WINDOWS_SECURE_STORAGE_FAILED", error);
            return;
          }
          if (!found) {
            result->Success(flutter::EncodableValue());
            return;
          }
          result->Success(flutter::EncodableValue(value));
          return;
        }
        if (call.method_name() == "writeSecureText") {
          std::string name;
          std::string value;
          ScopedStringWipe wipe_value(&value);
          if (!TryStringArgFromCall(call, "name", &name) ||
              !TryStringArgFromCall(call, "value", &value)) {
            result->Error("BAD_ARGS", "Secure text name or value is missing.");
            return;
          }
          std::string error;
          if (!WriteWindowsSecureText(name, value, &error)) {
            result->Error("WINDOWS_SECURE_STORAGE_FAILED", error);
            return;
          }
          result->Success(flutter::EncodableValue(true));
          return;
        }
        if (call.method_name() == "deleteSecureText") {
          std::string name;
          if (!TryStringArgFromCall(call, "name", &name)) {
            result->Error("BAD_ARGS", "Secure text name is missing.");
            return;
          }
          std::string error;
          if (!DeleteWindowsSecureText(name, &error)) {
            result->Error("WINDOWS_SECURE_STORAGE_FAILED", error);
            return;
          }
          result->Success(flutter::EncodableValue(true));
          return;
        }
        if (call.method_name() == "eraseLocalAccountRuntime") {
          CompleteEncodableMethodAsync(std::move(result), []() {
            return flutter::EncodableValue(EraseLocalAccountRuntime());
          });
          return;
        }
        if (call.method_name() == "getTunnelState") {
          CompleteEncodableMethodAsync(
              std::move(result),
              []() { return flutter::EncodableValue(IsTunnelRunning()); });
          return;
        }
        if (call.method_name() == "resolveCarrierIpv4") {
          // PREFLIGHT DNS EGRESS (2026-08-07). The only caller is
          // lib/main.dart's _resolveXrayCarrierIpv4ForPreflight, so the Xray
          // WebSocket preflight can dial an address literal instead of handing
          // Socket.connect a hostname -- which dart:io resolves with no family
          // hint, an A *and* an AAAA, per probed candidate, before any tunnel
          // exists. Delegated to the same AF_INET ResolvePublicIpv4Addresses
          // that StartXrayIfNeeded uses, so Windows keeps one implementation
          // rather than growing a second beside it. Async because getaddrinfo
          // must not occupy the platform thread.
          std::string host;
          if (!TryStringArgFromCall(call, "host", &host) || host.empty() ||
              host.size() > 253) {
            result->Error("BAD_ARGS", "Carrier host is invalid.");
            return;
          }
          CompleteEncodableMethodAsync(
              std::move(result), [host]() {
                flutter::EncodableList addresses;
                for (const std::string& address :
                     ResolvePublicIpv4Addresses(host)) {
                  addresses.push_back(flutter::EncodableValue(address));
                }
                return flutter::EncodableValue(addresses);
              });
          return;
        }
        if (call.method_name() == "getTunnelActivity") {
          CompleteEncodableMethodAsync(std::move(result), []() {
            return flutter::EncodableValue(IsTunnelRunning() ||
                                           IsXrayProcessRunning());
          });
          return;
        }
        if (call.method_name() == "getTunnelActivitySnapshot") {
          CompleteEncodableMethodAsync(
              std::move(result), []() { return TunnelActivitySnapshotValue(); });
          return;
        }
        if (call.method_name() == "getTunnelReadiness" ||
            call.method_name() == "getTunnelStatus") {
          CompleteEncodableMethodAsync(
              std::move(result), []() { return TunnelReadinessValue(); });
          return;
        }
        if (call.method_name() == "probeVpnInternet") {
          CompleteEncodableMethodAsync(
              std::move(result), []() { return ProbeInternetValue(); });
          return;
        }
        if (call.method_name() == "getInstalledApps") {
          flutter::EncodableList values;
          for (const auto& app : ListWindowsInstalledApps()) {
            flutter::EncodableMap value;
            value[flutter::EncodableValue("name")] =
                flutter::EncodableValue(WideToUtf8(app.name));
            value[flutter::EncodableValue("package_name")] =
                flutter::EncodableValue(WideToUtf8(app.executable_path));
            value[flutter::EncodableValue("is_system")] =
                flutter::EncodableValue(false);
            values.push_back(flutter::EncodableValue(value));
          }
          result->Success(flutter::EncodableValue(values));
          return;
        }
        if (call.method_name() == "stopTunnel") {
          int64_t cancellation_generation = 0;
          const Int64ArgStatus generation_status = Int64ArgFromCall(
              call, "cancellationGeneration", &cancellation_generation);
          const bool valid_generation =
              generation_status == Int64ArgStatus::kValid &&
              cancellation_generation > 0;
          bool expected = false;
          {
            std::lock_guard<std::mutex> lock(g_transition_commit_mutex);
            if (!g_stop_in_flight.compare_exchange_strong(
                    expected, true, std::memory_order_acq_rel)) {
              result->Error("WINDOWS_TUNNEL_STOP_BUSY",
                            "A Windows tunnel stop is already in progress.");
              return;
            }
            // Publish the fence before any teardown. A malformed stop request
            // is latched fail-closed until app restart because it cannot name a
            // generation that would safely bound an in-flight commit.
            AdvanceWindowsCanceledGenerationFloor(
                valid_generation
                    ? cancellation_generation
                    : std::numeric_limits<int64_t>::max());
            // This signal is deliberately issued on the platform thread before
            // dispatching cleanup. If the protected service is still converging
            // a start, its watchdog terminates that fail-closed operation instead
            // of making stop wait behind a 160-second single-instance pipe call.
            SignalWindowsTunnelStartCancellation();
          }
          {
            std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
            g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
          }
          using Result = flutter::MethodResult<flutter::EncodableValue>;
          auto async_result = std::shared_ptr<Result>(result.release());
          if (!BeginAsyncWorker()) {
            g_stop_in_flight.store(false, std::memory_order_release);
            async_result->Error("WINDOWS_TUNNEL_SHUTTING_DOWN",
                                "The Windows tunnel bridge is shutting down.");
            return;
          }
          try {
            std::thread([async_result, valid_generation]() mutable {
              ScopedAsyncWorker<Result> worker(&async_result);
              std::string error;
              const bool stopped = UninstallTunnel(&error);
              g_stop_in_flight.store(false, std::memory_order_release);
              if (IsBackendShuttingDown()) {
                return;
              } else if (!valid_generation) {
                async_result->Error(
                    "WINDOWS_TUNNEL_BAD_CANCELLATION_GENERATION",
                    "Cancellation generation must be a positive integer.");
              } else if (!stopped) {
                async_result->Error("WINDOWS_TUNNEL_STOP_FAILED", error);
              } else {
                async_result->Success(
                    flutter::EncodableValue("Tunnel stopped"));
              }
            }).detach();
          } catch (...) {
            EndAsyncWorker();
            g_stop_in_flight.store(false, std::memory_order_release);
            async_result->Error("WINDOWS_TUNNEL_STOP_DISPATCH_FAILED",
                                "Unable to dispatch Windows tunnel cleanup.");
          }
          return;
        }
        if (call.method_name() == "startTunnel") {
          const std::string config = ConfigFromCall(call);
          if (config.empty()) {
            result->Error("BAD_ARGS", "Configuration payload missing");
            return;
          }
          const bool selects_winn3 =
              winsvpn::winn3::ConfigSelectsWinn3(config);
          std::string independent_selected_node;
          std::string selected_node_error;
          if (selects_winn3 &&
              (!TryStringArgFromCall(call, "selected_node",
                                    &independent_selected_node) ||
               !winsvpn::winn3::ValidateWinn3IndependentSelectedNode(
                   config, independent_selected_node, &selected_node_error))) {
            result->Error(
                "WINDOWS_WINN3_SELECTED_NODE_REQUIRED",
                selected_node_error.empty()
                    ? "Winn Protocol v3 requires an independently selected node."
                    : selected_node_error);
            return;
          }
          int64_t transition_generation = 0;
          const Int64ArgStatus generation_status = Int64ArgFromCall(
              call, "transitionGeneration", &transition_generation);
          if (generation_status != Int64ArgStatus::kValid ||
              transition_generation <= 0) {
            result->Error("WINDOWS_TUNNEL_GENERATION_REQUIRED",
                          "Tunnel start requires a positive transition generation.");
            return;
          }
          int64_t winn3_start_token = 0;
          const Int64ArgStatus token_status =
              Int64ArgFromCall(call, "winn3StartToken", &winn3_start_token);
          int64_t winn3_start_generation = 0;
          const Int64ArgStatus winn3_generation_status = Int64ArgFromCall(
              call, "winn3StartGeneration", &winn3_start_generation);
          std::string selection_generation;
          const bool has_selection = TryStringArgFromCall(
              call, "winn3SelectionGeneration", &selection_generation);
          std::string failed_node;
          const bool has_failed_node =
              TryStringArgFromCall(call, "winn3FailedNode", &failed_node);
          int64_t cover_auth_token = 0;
          const Int64ArgStatus cover_auth_status = Int64ArgFromCall(
              call, "winn3AwgXrayAuthorizationToken", &cover_auth_token);
          std::string cover_target;
          const bool has_cover_target =
              TryStringArgFromCall(call, "winn3CoverExactTarget", &cover_target);
          std::string cover_leg_text;
          const bool has_cover_leg =
              TryStringArgFromCall(call, "winn3CoverLeg", &cover_leg_text);
          if (selects_winn3) {
            if (token_status != Int64ArgStatus::kValid || winn3_start_token <= 0 ||
                winn3_generation_status != Int64ArgStatus::kValid ||
                winn3_start_generation != transition_generation ||
                !has_selection ||
                !winsvpn::winn3::IsWinn3SelectionGeneration(
                    selection_generation) ||
                !has_failed_node ||
                !winsvpn::winn3::IsConcreteWinn3NodeSlug(failed_node)) {
              result->Error(
                  "WINDOWS_WINN3_START_IDENTITY_REQUIRED",
                  "Winn v3 start token, generation, selection, and failed node "
                  "must be exact positive identities.");
              return;
            }
            {
              std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
              g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
            }
          }
          const bool cover_requested =
              cover_auth_status != Int64ArgStatus::kMissing || has_cover_target ||
              has_cover_leg ||
              (!selects_winn3 && token_status != Int64ArgStatus::kMissing);
          if (!selects_winn3 && cover_requested) {
            winsvpn::winn3::Winn3CoverLeg cover_leg =
                winsvpn::winn3::Winn3CoverLeg::kAwg;
            if (cover_auth_status != Int64ArgStatus::kValid ||
                cover_auth_token <= 0 ||
                token_status != Int64ArgStatus::kValid ||
                winn3_start_token != cover_auth_token ||
                winn3_generation_status != Int64ArgStatus::kValid ||
                winn3_start_generation <= 0 ||
                !has_selection || !has_failed_node || !has_cover_target ||
                !has_cover_leg ||
                !winsvpn::winn3::ParseWinn3CoverLeg(cover_leg_text, &cover_leg)) {
              result->Error("WINDOWS_WINN3_COVER_GRANT_INVALID",
                            "Cover AWG/Xray start identities are malformed.");
              return;
            }
            std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
            const auto consume = winsvpn::winn3::ConsumeWinn3AwgXrayGrant(
                &g_awg_xray_grant, winn3_start_token, winn3_start_generation,
                selection_generation, failed_node, cover_target, cover_leg,
                static_cast<int64_t>(GetTickCount64()));
            if (consume != winsvpn::winn3::Winn3GrantConsumeResult::kOk) {
              result->Error("WINDOWS_WINN3_COVER_GRANT_REFUSED",
                            "Cover AWG/Xray grant is missing, expired, or mismatched.");
              return;
            }
          } else if (!selects_winn3) {
            std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
            g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
          }
          if (!IsWindowsStartGenerationAllowed(transition_generation)) {
            result->Error("WINDOWS_TUNNEL_STALE_START",
                          "Tunnel start belongs to a canceled transition.");
            return;
          }
          if (g_stop_in_flight.load(std::memory_order_acquire)) {
            result->Error("WINDOWS_TUNNEL_STOP_BUSY",
                          "Tunnel cleanup is still in progress.");
            return;
          }
          bool expected = false;
          if (!g_start_in_flight.compare_exchange_strong(
                  expected, true, std::memory_order_acq_rel)) {
            result->Error("WINDOWS_TUNNEL_START_BUSY",
                          "A Windows tunnel start is already in progress.");
            return;
          }
          using Result = flutter::MethodResult<flutter::EncodableValue>;
          auto async_result = std::shared_ptr<Result>(result.release());
          if (!BeginAsyncWorker()) {
            g_start_in_flight.store(false, std::memory_order_release);
            async_result->Error("WINDOWS_TUNNEL_SHUTTING_DOWN",
                                "The Windows tunnel bridge is shutting down.");
            return;
          }
          try {
            std::thread([config, transition_generation, winn3_start_token,
                         winn3_start_generation, selection_generation, failed_node,
                         cover_requested, async_result]() mutable {
              ScopedAsyncWorker<Result> worker(&async_result);
              std::string error;
              const bool winn3 = winsvpn::winn3::ConfigSelectsWinn3(config);
              const bool started =
                  InstallTunnel(config, transition_generation, &error);
              g_start_in_flight.store(false, std::memory_order_release);
              if (IsBackendShuttingDown()) {
                return;
              } else if (!started) {
                if (winn3) {
                  winsvpn::winn3::RememberWindowsWinn3OsError(
                      CaptureWindowsWinn3GatewayOsErrorFromConfig(config));
                  winsvpn::winn3::Winn3StartProof proof;
                  {
                    std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
                    proof = winsvpn::winn3::ClassifyCapturedWinn3StartFailure(
                        transition_generation, false, error, winn3_start_token,
                        selection_generation, failed_node);
                    g_last_winn3_proof = proof;
                    if (proof.outcome ==
                        winsvpn::winn3::Winn3ProofOutcome::kOrdinaryConnectivity) {
                      winsvpn::winn3::ArmWinn3AwgXrayGrant(
                          winn3_start_token, winn3_start_generation,
                          selection_generation, failed_node,
                          static_cast<int64_t>(GetTickCount64()),
                          &g_awg_xray_grant);
                    } else {
                      g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
                    }
                  }
                  async_result->Error(
                      winsvpn::winn3::Winn3ProofOutcomeName(proof.outcome),
                      error, flutter::EncodableValue(Winn3ProofEncodableMap(proof)));
                } else {
                  async_result->Error("WINDOWS_TUNNEL_START_FAILED", error);
                }
              } else {
                if (winn3) {
                  std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
                  g_last_winn3_proof =
                      winsvpn::winn3::MakeConnectedWinn3StartProof(
                          transition_generation, winn3_start_token,
                          selection_generation, failed_node);
                  g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
                } else if (cover_requested) {
                  std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
                  g_awg_xray_grant = winsvpn::winn3::Winn3AwgXrayGrant();
                }
                async_result->Success(
                    flutter::EncodableValue("Tunnel Initializing"));
              }
            }).detach();
          } catch (...) {
            EndAsyncWorker();
            g_start_in_flight.store(false, std::memory_order_release);
            async_result->Error("WINDOWS_TUNNEL_START_DISPATCH_FAILED",
                                "Unable to dispatch Windows tunnel startup.");
          }
          return;
        }
        if (call.method_name() == "showAnnouncementNotification") {
          const std::string title = StringArgFromCall(call, "title");
          const std::string body = StringArgFromCall(call, "body");
          result->Success(
              flutter::EncodableValue(ShowAnnouncementNotification(title, body)));
          return;
        }
        result->NotImplemented();
      });
}

void ShutdownWindowsTunnelBackend() {
  bool already_quiesced = false;
  {
    std::lock_guard<std::mutex> lock(g_async_worker_mutex);
    already_quiesced = g_backend_shutting_down && g_async_worker_count == 0;
    g_backend_shutting_down = true;
  }
  if (already_quiesced) {
    g_channel.reset();
    return;
  }
  // Abort an in-progress protected start before destroying the Flutter
  // messenger retained by its asynchronous MethodResult.
  {
    std::lock_guard<std::mutex> transition_lock(g_transition_commit_mutex);
    // This permanent floor closes the pre-arm race: a worker that has not yet
    // created its named cancellation event cannot create or commit a start
    // after window shutdown begins.
    AdvanceWindowsCanceledGenerationFloor(
        std::numeric_limits<int64_t>::max());
    SignalWindowsTunnelStartCancellation();
  }
  std::unique_lock<std::mutex> lock(g_async_worker_mutex);
  const bool quiesced = g_async_worker_cv.wait_for(
      lock, std::chrono::seconds(35), []() { return g_async_worker_count == 0; });
  lock.unlock();
  if (!quiesced) {
    // Returning through CRT static destruction while detached workers still
    // reference process-global mutexes would be a use-after-destruction race.
    // Process termination is safe here because the window is already closing.
    TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
    ExitProcess(ERROR_TIMEOUT);
  }
  g_channel.reset();
}
#endif
