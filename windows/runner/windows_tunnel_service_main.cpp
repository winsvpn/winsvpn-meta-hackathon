#include "windows_tunnel_service_core.h"
#include "windows_tunnel_service_protocol.h"
#include "windows_split_tunnel.h"
#include "windows_kill_switch.h"

#include <windows.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using winsvpn::tunnel_service::Command;
using winsvpn::tunnel_service::RequestHeader;
using winsvpn::tunnel_service::ResponseHeader;
using winsvpn::tunnel_service::Status;

SERVICE_STATUS_HANDLE g_service_status_handle = nullptr;
SERVICE_STATUS g_service_status = {};
HANDLE g_stop_event = nullptr;
HANDLE g_carrier_process = nullptr;
enum class TunnelPhase : uint32_t {
  kIdle = 0,
  kConverging = 1,
  kCommitted = 2,
  kStopping = 3,
};
std::atomic<TunnelPhase> g_tunnel_phase{TunnelPhase::kIdle};
std::atomic<uint64_t> g_tunnel_generation{0};

[[noreturn]] void TerminateServiceFailClosed(DWORD exit_code) {
  TerminateProcess(GetCurrentProcess(), exit_code);
  // Terminating the current process should not return. ExitProcess is the
  // final no-return boundary if a security product or injected hook reports a
  // failed TerminateProcess call.
  ExitProcess(exit_code);
}

const char* TunnelPhaseName(TunnelPhase phase) {
  switch (phase) {
    case TunnelPhase::kConverging:
      return "converging";
    case TunnelPhase::kCommitted:
      return "committed";
    case TunnelPhase::kStopping:
      return "stopping";
    default:
      return "idle";
  }
}

std::wstring ModulePath() {
  std::vector<wchar_t> buffer(32768, L'\0');
  const DWORD size = GetModuleFileNameW(nullptr, buffer.data(),
                                        static_cast<DWORD>(buffer.size()));
  if (size == 0 || size >= buffer.size()) {
    return L"";
  }
  return std::wstring(buffer.data(), size);
}

std::wstring ModuleDirectory() {
  const std::wstring path = ModulePath();
  const size_t slash = path.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"" : path.substr(0, slash);
}

std::wstring JoinPath(const std::wstring& left, const std::wstring& right) {
  if (left.empty()) {
    return right;
  }
  return left + (left.back() == L'\\' ? L"" : L"\\") + right;
}

bool SamePath(const std::wstring& left, const std::wstring& right) {
  return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

std::wstring StartCancellationEventName(DWORD client_pid,
                                        uint64_t transition_generation) {
  return std::wstring(winsvpn::tunnel_service::kStartCancellationEventPrefix) +
         std::to_wstring(client_pid) + L"." +
         std::to_wstring(transition_generation);
}

bool IsCurrentProcessElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }
  TOKEN_ELEVATION elevation = {};
  DWORD returned = 0;
  const bool elevated =
      GetTokenInformation(token, TokenElevation, &elevation,
                          sizeof(elevation), &returned) != FALSE &&
      elevation.TokenIsElevated != 0;
  CloseHandle(token);
  return elevated;
}

void ReportServiceStatus(DWORD state, DWORD error = NO_ERROR,
                         DWORD wait_hint = 0) {
  if (g_service_status_handle == nullptr) {
    return;
  }
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwCurrentState = state;
  g_service_status.dwWin32ExitCode = error;
  g_service_status.dwWaitHint = wait_hint;
  g_service_status.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                               : 0;
  g_service_status.dwCheckPoint =
      state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING
          ? g_service_status.dwCheckPoint + 1
          : 0;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

bool IsStopRequested() {
  return g_stop_event != nullptr &&
         WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0;
}

bool PipeIoBounded(HANDLE pipe, bool write, void* buffer, DWORD bytes,
                   DWORD timeout_ms, DWORD* transferred) {
  *transferred = 0;
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (overlapped.hEvent == nullptr) return false;

  const BOOL immediate =
      write ? WriteFile(pipe, buffer, bytes, nullptr, &overlapped)
            : ReadFile(pipe, buffer, bytes, nullptr, &overlapped);
  DWORD code = immediate ? ERROR_SUCCESS : GetLastError();
  bool timed_out = false;

  if (!immediate && code == ERROR_IO_PENDING) {
    HANDLE waits[] = {overlapped.hEvent, g_stop_event};
    const DWORD count = g_stop_event == nullptr ? 1 : 2;
    const DWORD waited =
        WaitForMultipleObjects(count, waits, FALSE, timeout_ms);
    if (waited != WAIT_OBJECT_0) {
      timed_out = true;
      CancelIoEx(pipe, &overlapped);
      if (WaitForSingleObject(overlapped.hEvent, 1000) != WAIT_OBJECT_0) {
        // [[noreturn]]: the process exits fail-closed; nothing follows.
        TerminateServiceFailClosed(ERROR_TIMEOUT);
      }
    }
  } else if (!immediate && code != ERROR_MORE_DATA) {
    CloseHandle(overlapped.hEvent);
    return false;
  }

  const BOOL completed =
      GetOverlappedResult(pipe, &overlapped, transferred, FALSE);
  code = completed ? ERROR_SUCCESS : GetLastError();
  CloseHandle(overlapped.hEvent);
  return !timed_out &&
         (completed != FALSE || code == ERROR_MORE_DATA);
}

// The client reads its framed response and then closes its handle
// (windows_tunnel_service_client.cpp closes on every path). Waiting for that
// close is the overlapped equivalent of FlushFileBuffers, with the same bound.
void WaitForClientDrain(HANDLE pipe) {
  uint8_t ignored = 0;
  DWORD read = 0;
  (void)PipeIoBounded(pipe, false, &ignored, 1,
                      winsvpn::tunnel_service::kResponseFlushTimeoutMilliseconds,
                      &read);
}

bool ReadPipeExact(HANDLE pipe, void* destination, DWORD bytes,
                   DWORD timeout_ms) {
  auto* output = static_cast<uint8_t*>(destination);
  DWORD total = 0;
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  while (total < bytes) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline || IsStopRequested()) return false;
    DWORD read = 0;
    if (!PipeIoBounded(pipe, false, output + total, bytes - total,
                       static_cast<DWORD>(deadline - now), &read) ||
        read == 0) {
      return false;
    }
    total += read;
  }
  return true;
}

bool GetActiveConsolePipeClient(HANDLE pipe, DWORD* client_pid) {
  if (client_pid == nullptr) {
    return false;
  }
  ULONG native_client_pid = 0;
  if (!GetNamedPipeClientProcessId(pipe, &native_client_pid) ||
      native_client_pid == 0) {
    return false;
  }
  DWORD client_session = 0;
  const DWORD active_session = WTSGetActiveConsoleSessionId();
  if (active_session == 0xFFFFFFFF ||
      !ProcessIdToSessionId(static_cast<DWORD>(native_client_pid),
                            &client_session) ||
      client_session != active_session) {
    return false;
  }
  *client_pid = static_cast<DWORD>(native_client_pid);
  return true;
}

// SHA-256 of the Authenticode signer's leaf certificate of `image`. Empty when
// the image is unsigned, untrusted or unreadable. Offline: no revocation check
// and no URL retrieval.
std::vector<BYTE> AuthenticodeLeafSha256(const std::wstring& image) {
  std::vector<BYTE> leaf;
  WINTRUST_FILE_INFO file = {};
  file.cbStruct = sizeof(file);
  file.pcwszFilePath = image.c_str();
  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  WINTRUST_DATA data = {};
  data.cbStruct = sizeof(data);
  data.dwUIChoice = WTD_UI_NONE;
  data.fdwRevocationChecks = WTD_REVOKE_NONE;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &file;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  HWND no_ui = static_cast<HWND>(INVALID_HANDLE_VALUE);
  if (WinVerifyTrust(no_ui, &action, &data) == ERROR_SUCCESS) {
    CRYPT_PROVIDER_DATA* provider =
        WTHelperProvDataFromStateData(data.hWVTStateData);
    CRYPT_PROVIDER_SGNR* signer =
        provider == nullptr
            ? nullptr
            : WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
    CRYPT_PROVIDER_CERT* cert =
        signer == nullptr ? nullptr : WTHelperGetProvCertFromChain(signer, 0);
    if (cert != nullptr && cert->pCert != nullptr) {
      BYTE digest[32] = {};
      DWORD digest_size = sizeof(digest);
      if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                                cert->pCert->pbCertEncoded,
                                cert->pCert->cbCertEncoded, digest,
                                &digest_size) &&
          digest_size == sizeof(digest)) {
        leaf.assign(digest, digest + sizeof(digest));
      }
    }
  }
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(no_ui, &action, &data);
  return leaf;
}

// Ruling A6 (2026-10-04): the mutating client must carry the same Authenticode
// signer leaf as this service. A release build refuses when either image is
// unsigned. Only a Debug build of an unsigned service falls back to the path
// rule above. The client verdict is cached per image path and last-write time,
// because every status poll passes through here.
bool ClientSignedBySameLeaf(const std::wstring& client_image) {
  static std::mutex mutex;
  static bool service_read = false;
  static std::vector<BYTE> service_leaf;
  static std::wstring cached_client;
  static FILETIME cached_write = {};
  static bool cached_ok = false;
  std::lock_guard<std::mutex> lock(mutex);
  if (!service_read) {
    service_leaf = AuthenticodeLeafSha256(ModulePath());
    service_read = true;
  }
  if (service_leaf.empty()) {
#if defined(WINS_TUNNEL_SERVICE_ALLOW_UNSIGNED_DEV)
    return true;
#else
    return false;
#endif
  }
  WIN32_FILE_ATTRIBUTE_DATA attributes = {};
  if (!GetFileAttributesExW(client_image.c_str(), GetFileExInfoStandard,
                            &attributes)) {
    return false;
  }
  if (cached_client == client_image &&
      CompareFileTime(&cached_write, &attributes.ftLastWriteTime) == 0) {
    return cached_ok;
  }
  const std::vector<BYTE> client_leaf = AuthenticodeLeafSha256(client_image);
  cached_ok = !client_leaf.empty() && client_leaf == service_leaf;
  cached_client = client_image;
  cached_write = attributes.ftLastWriteTime;
  return cached_ok;
}

bool IsAuthorizedAppPipeClient(HANDLE pipe) {
  DWORD client_pid = 0;
  if (!GetActiveConsolePipeClient(pipe, &client_pid)) {
    return false;
  }
  const DWORD active_session = WTSGetActiveConsoleSessionId();
  if (active_session == 0xFFFFFFFF) {
    return false;
  }

  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               client_pid);
  if (process == nullptr) {
    return false;
  }
  ULONG recheck_pid = 0;
  if (!GetNamedPipeClientProcessId(pipe, &recheck_pid) ||
      static_cast<DWORD>(recheck_pid) != client_pid) {
    CloseHandle(process);
    return false;
  }
  DWORD exit_code = 0;
  if (!GetExitCodeProcess(process, &exit_code) || exit_code != STILL_ACTIVE) {
    CloseHandle(process);
    return false;
  }
  std::vector<wchar_t> path(32768, L'\0');
  DWORD path_size = static_cast<DWORD>(path.size());
  const bool path_ok =
      QueryFullProcessImageNameW(process, 0, path.data(), &path_size) != FALSE;
  ULONG final_pid = 0;
  const bool still_same =
      GetNamedPipeClientProcessId(pipe, &final_pid) != FALSE &&
      static_cast<DWORD>(final_pid) == client_pid;
  CloseHandle(process);
  if (!path_ok || !still_same ||
      !SamePath(std::wstring(path.data(), path_size),
                JoinPath(ModuleDirectory(), L"wins_vpn.exe"))) {
    return false;
  }
  if (!ClientSignedBySameLeaf(std::wstring(path.data(), path_size))) {
    return false;
  }

  if (!ImpersonateNamedPipeClient(pipe)) {
    return false;
  }
  HANDLE token = nullptr;
  bool authorized = false;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    DWORD token_session = 0;
    DWORD returned = 0;
    if (GetTokenInformation(token, TokenSessionId, &token_session,
                            sizeof(token_session), &returned) &&
        token_session == active_session) {
      DWORD user_bytes = 0;
      GetTokenInformation(token, TokenUser, nullptr, 0, &user_bytes);
      std::vector<uint8_t> user_buffer(user_bytes);
      if (user_bytes > 0 &&
          GetTokenInformation(token, TokenUser, user_buffer.data(), user_bytes,
                              &returned)) {
        const auto* user =
            reinterpret_cast<const TOKEN_USER*>(user_buffer.data());
        authorized = !IsWellKnownSid(user->User.Sid, WinLocalSystemSid) &&
                     !IsWellKnownSid(user->User.Sid, WinLocalServiceSid) &&
                     !IsWellKnownSid(user->User.Sid, WinNetworkServiceSid);
      }
    }
    CloseHandle(token);
  }
  const bool reverted = RevertToSelf() != FALSE;
  return authorized && reverted;
}

bool IsAuthorizedElevatedAdminStatusClient(HANDLE pipe) {
  DWORD client_pid = 0;
  if (!GetActiveConsolePipeClient(pipe, &client_pid)) {
    return false;
  }
  // Confirm that the process still exists before impersonating the pipe. The
  // PID is never used to grant start/stop authority; this path is status-only.
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               client_pid);
  if (process == nullptr) {
    return false;
  }
  CloseHandle(process);

  if (!ImpersonateNamedPipeClient(pipe)) {
    return false;
  }
  HANDLE token = nullptr;
  bool authorized = false;
  if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
    const DWORD active_session = WTSGetActiveConsoleSessionId();
    DWORD token_session = 0;
    DWORD returned = 0;
    TOKEN_ELEVATION elevation = {};
    DWORD user_bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &user_bytes);
    std::vector<uint8_t> user_buffer(user_bytes);

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID administrators_sid = nullptr;
    const bool administrators_sid_ok =
        AllocateAndInitializeSid(
            &nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
            &administrators_sid) != FALSE;
    BOOL is_administrator = FALSE;
    const bool membership_ok =
        administrators_sid_ok &&
        CheckTokenMembership(token, administrators_sid, &is_administrator) !=
            FALSE;

    if (GetTokenInformation(token, TokenSessionId, &token_session,
                            sizeof(token_session), &returned) &&
        GetTokenInformation(token, TokenElevation, &elevation,
                            sizeof(elevation), &returned) &&
        user_bytes > 0 &&
        GetTokenInformation(token, TokenUser, user_buffer.data(), user_bytes,
                            &returned)) {
      const auto* user =
          reinterpret_cast<const TOKEN_USER*>(user_buffer.data());
      const bool interactive_user =
          !IsWellKnownSid(user->User.Sid, WinLocalSystemSid) &&
          !IsWellKnownSid(user->User.Sid, WinLocalServiceSid) &&
          !IsWellKnownSid(user->User.Sid, WinNetworkServiceSid);
      authorized = active_session != 0xFFFFFFFF &&
                   token_session == active_session && interactive_user &&
                   elevation.TokenIsElevated != 0 && membership_ok &&
                   is_administrator != FALSE;
    }
    if (administrators_sid != nullptr) {
      FreeSid(administrators_sid);
    }
    CloseHandle(token);
  }
  const bool reverted = RevertToSelf() != FALSE;
  return authorized && reverted;
}

void CloseCarrierProcessMonitor() {
  if (g_carrier_process != nullptr) {
    CloseHandle(g_carrier_process);
    g_carrier_process = nullptr;
  }
}

HANDLE OpenVerifiedCarrierProcess(uint32_t carrier_pid) {
  if (carrier_pid == 0) {
    return nullptr;
  }
  DWORD carrier_session = 0;
  const DWORD active_session = WTSGetActiveConsoleSessionId();
  if (active_session == 0xFFFFFFFF ||
      !ProcessIdToSessionId(carrier_pid, &carrier_session) ||
      carrier_session != active_session) {
    return nullptr;
  }
  HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, carrier_pid);
  if (process == nullptr) {
    return nullptr;
  }
  std::vector<wchar_t> path(32768, L'\0');
  DWORD path_size = static_cast<DWORD>(path.size());
  const bool valid =
      QueryFullProcessImageNameW(process, 0, path.data(), &path_size) != FALSE &&
      SamePath(std::wstring(path.data(), path_size),
               JoinPath(ModuleDirectory(), L"xray.exe")) &&
      WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
  if (!valid) {
    CloseHandle(process);
    return nullptr;
  }
  return process;
}

bool StopPrivilegedWindowsTunnelBounded(std::string* error) {
  HANDLE completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (completed == nullptr) {
    if (error != nullptr) {
      *error = "Unable to arm the privileged stop watchdog.";
    }
    TerminateServiceFailClosed(ERROR_TIMEOUT);
  }
  std::thread watchdog([completed]() {
    if (WaitForSingleObject(
            completed,
            winsvpn::tunnel_service::kStopOverallWatchdogMilliseconds) !=
        WAIT_OBJECT_0) {
      TerminateServiceFailClosed(ERROR_TIMEOUT);
    }
  });
  const bool stopped = StopPrivilegedWindowsTunnel(error);
  SetEvent(completed);
  watchdog.join();
  CloseHandle(completed);
  return stopped;
}

void StopTunnelAfterCarrierExit() {
  if (g_carrier_process == nullptr ||
      WaitForSingleObject(g_carrier_process, 0) != WAIT_OBJECT_0) {
    return;
  }
  g_tunnel_phase.store(TunnelPhase::kStopping, std::memory_order_release);
  CloseCarrierProcessMonitor();
  std::string error;
  StopPrivilegedWindowsTunnelBounded(&error);
  g_tunnel_phase.store(TunnelPhase::kIdle, std::memory_order_release);
  g_tunnel_generation.store(0, std::memory_order_release);
}

void WriteResponse(HANDLE pipe, Status status, std::string message) {
  if (message.size() > winsvpn::tunnel_service::kMaxResponseBytes) {
    message.resize(winsvpn::tunnel_service::kMaxResponseBytes);
  }
  ResponseHeader header = {
      winsvpn::tunnel_service::kProtocolMagic,
      winsvpn::tunnel_service::kProtocolVersion,
      static_cast<uint16_t>(status),
      static_cast<uint32_t>(message.size()),
  };
  std::vector<uint8_t> response(sizeof(header) + message.size());
  std::memcpy(response.data(), &header, sizeof(header));
  if (!message.empty()) {
    std::memcpy(response.data() + sizeof(header), message.data(), message.size());
  }

  DWORD written = 0;
  if (!PipeIoBounded(pipe, true, response.data(),
                     static_cast<DWORD>(response.size()),
                     winsvpn::tunnel_service::kResponseWriteTimeoutMilliseconds,
                     &written)) {
    return;  // client gone or timed out; the caller disconnects the instance
  }
  if (written != static_cast<DWORD>(response.size())) {
    TerminateServiceFailClosed(ERROR_WRITE_FAULT);
  }
}

enum class PipeClientRole {
  kRejected,
  kInstalledApp,
  kElevatedAdmin,
};

// Identify the connected pipe client's authority using only cheap, bounded
// PID/session/token/installed-app-path checks, before any framed-request
// read is attempted. Deciding authorization here -- rather than after the
// 5-second header read that used to gate it -- means an unauthorized local
// process can no longer occupy the service's single pipe instance across
// repeated timed waits and block legitimate start, stop, and status
// requests.
PipeClientRole AuthorizePipeClientBeforeRead(HANDLE pipe) {
  // Mutation authority remains bound to the exact installed interactive app.
  if (IsAuthorizedAppPipeClient(pipe)) {
    return PipeClientRole::kInstalledApp;
  }
  // The release harness runs elevated in the active console session and may
  // read only the sanitized kStatus response so that a public-egress canary
  // is cryptographically bound to the same committed transition generation.
  if (IsAuthorizedElevatedAdminStatusClient(pipe)) {
    return PipeClientRole::kElevatedAdmin;
  }
  return PipeClientRole::kRejected;
}

void HandlePipeClient(HANDLE pipe) {
  const PipeClientRole role = AuthorizePipeClientBeforeRead(pipe);
  if (role == PipeClientRole::kRejected) {
    // Reject immediately: no header/payload read and no framed response is
    // written or flushed for an unauthorized client, so it cannot spend the
    // service's single pipe instance on a timed wait before disconnecting.
    return;
  }

  // Only an authorized client may consume the bounded response-drain wait.
  // The guard sits after the rejection above and drains on every authorized
  // return path before RunPipeServer disconnects the pipe.
  struct AuthorizedClientDrain {
    HANDLE pipe;
    ~AuthorizedClientDrain() { WaitForClientDrain(pipe); }
  } drain{pipe};

  RequestHeader header = {};
  if (!ReadPipeExact(pipe, &header, sizeof(header), 5000)) {
    WriteResponse(pipe, Status::kInvalidRequest, "Incomplete tunnel request.");
    return;
  }
  if (header.magic != winsvpn::tunnel_service::kProtocolMagic ||
      header.version != winsvpn::tunnel_service::kProtocolVersion ||
      header.payload_size > winsvpn::tunnel_service::kMaxRequestBytes) {
    WriteResponse(pipe, Status::kInvalidRequest,
                  "Tunnel request protocol validation failed.");
    return;
  }

  const Command command = static_cast<Command>(header.command);
  const bool known_command = command == Command::kStart ||
                             command == Command::kStop ||
                             command == Command::kStatus;
  if (!known_command) {
    WriteResponse(pipe, Status::kInvalidRequest, "Unknown tunnel command.");
    return;
  }
  // The elevated-admin role is authorized for kStatus only; Start/Stop
  // mutation authority still belongs exclusively to the exact installed
  // interactive app (kInstalledApp, checked above). This reproduces the
  // same status-only restriction the previous per-command authorization
  // enforced; it runs here because the command it depends on is only known
  // once the header has been read.
  if (role == PipeClientRole::kElevatedAdmin && command != Command::kStatus) {
    WriteResponse(pipe, Status::kRejected,
                  "Tunnel request failed client identity verification.");
    return;
  }

  std::string payload(header.payload_size, '\0');
  if (header.payload_size > 0 &&
      !ReadPipeExact(pipe, payload.data(), header.payload_size, 5000)) {
    WriteResponse(pipe, Status::kInvalidRequest,
                  "Tunnel request payload was incomplete.");
    return;
  }
  if (payload.find('\0') != std::string::npos) {
    WriteResponse(pipe, Status::kInvalidRequest,
                  "Tunnel request payload contains invalid bytes.");
    return;
  }

  std::string error;
  if (command == Command::kStart) {
    if (payload.empty() || header.transition_generation == 0) {
      WriteResponse(pipe, Status::kInvalidRequest,
                    "Tunnel configuration or transition generation is missing.");
      return;
    }
    bool requires_xray = false;
    if (!PrivilegedWindowsTunnelConfigRequiresXray(
            payload, &requires_xray, &error)) {
      WriteResponse(pipe, Status::kInvalidRequest, error);
      return;
    }
    HANDLE carrier_process = nullptr;
    if (requires_xray) {
      carrier_process = OpenVerifiedCarrierProcess(header.carrier_pid);
      if (carrier_process == nullptr) {
        WriteResponse(pipe, Status::kRejected,
                      "Xray fallback carrier identity verification failed.");
        return;
      }
    } else if (header.carrier_pid != 0) {
      WriteResponse(pipe, Status::kInvalidRequest,
                    "Direct AWG requests must not name a carrier process.");
      return;
    }
    ULONG client_pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &client_pid) || client_pid == 0) {
      if (carrier_process != nullptr) {
        CloseHandle(carrier_process);
      }
      WriteResponse(pipe, Status::kRejected,
                    "Tunnel client process identity is unavailable.");
      return;
    }
    const std::wstring cancellation_event_name =
        StartCancellationEventName(client_pid, header.transition_generation);
    HANDLE cancellation_event =
        OpenEventW(SYNCHRONIZE, FALSE, cancellation_event_name.c_str());
    HANDLE client_process =
        OpenProcess(SYNCHRONIZE, FALSE, client_pid);
    if (cancellation_event == nullptr || client_process == nullptr ||
        WaitForSingleObject(cancellation_event, 0) == WAIT_OBJECT_0 ||
        WaitForSingleObject(client_process, 0) == WAIT_OBJECT_0) {
      if (cancellation_event != nullptr) CloseHandle(cancellation_event);
      if (client_process != nullptr) CloseHandle(client_process);
      if (carrier_process != nullptr) CloseHandle(carrier_process);
      WriteResponse(pipe, Status::kRejected,
                    "Tunnel start was canceled before convergence.");
      return;
    }
    CloseCarrierProcessMonitor();
    g_tunnel_generation.store(header.transition_generation,
                              std::memory_order_release);
    g_tunnel_phase.store(TunnelPhase::kConverging,
                         std::memory_order_release);
    // Start owns the service's single authenticated pipe synchronously. If a
    // kernel, SCM, or vendor operation violates its component bound, terminate
    // this manager fail-closed before the native client can abandon it and
    // leave an unobservable start running. The AWG engine's kill-on-close job
    // is destroyed with this process and SCM applies the recovery policy.
    HANDLE start_completed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (start_completed == nullptr) {
      CloseHandle(cancellation_event);
      CloseHandle(client_process);
      if (carrier_process != nullptr) CloseHandle(carrier_process);
      g_tunnel_phase.store(TunnelPhase::kIdle, std::memory_order_release);
      g_tunnel_generation.store(0, std::memory_order_release);
      WriteResponse(pipe, Status::kOperationFailed,
                    "Unable to arm the tunnel start watchdog.");
      return;
    }
    std::thread start_watchdog([start_completed, cancellation_event,
                                client_process]() {
      HANDLE boundaries[] = {start_completed, cancellation_event,
                             client_process, g_stop_event};
      const DWORD wait = WaitForMultipleObjects(
          static_cast<DWORD>(_countof(boundaries)), boundaries, FALSE,
          winsvpn::tunnel_service::kStartOverallWatchdogMilliseconds);
      if (wait != WAIT_OBJECT_0) {
        // Cancellation, client exit, SCM stop/shutdown, timeout, or a failed
        // wait all abort convergence by terminating the manager. Closing its
        // kill-on-close job also terminates the uncommitted AWG engine.
        TerminateServiceFailClosed(ERROR_TIMEOUT);
      }
    });
    const auto finish_start_watchdog = [&]() {
      SetEvent(start_completed);
      start_watchdog.join();
      CloseHandle(start_completed);
      CloseHandle(cancellation_event);
      CloseHandle(client_process);
    };
    if (!StartPrivilegedWindowsTunnel(payload, &error)) {
      finish_start_watchdog();
      if (carrier_process != nullptr) {
        CloseHandle(carrier_process);
      }
      g_tunnel_phase.store(TunnelPhase::kIdle, std::memory_order_release);
      g_tunnel_generation.store(0, std::memory_order_release);
      WriteResponse(pipe, Status::kOperationFailed, error);
      return;
    }
    finish_start_watchdog();
    g_carrier_process = carrier_process;
    g_tunnel_phase.store(TunnelPhase::kCommitted,
                         std::memory_order_release);
    WriteResponse(pipe, Status::kStartSucceeded, "Tunnel started.");
    return;
  }
  if (command == Command::kStop) {
    if (!payload.empty() || header.carrier_pid != 0 ||
        header.transition_generation != 0) {
      WriteResponse(pipe, Status::kInvalidRequest,
                    "Stop requests must not contain a payload or carrier PID.");
      return;
    }
    g_tunnel_phase.store(TunnelPhase::kStopping, std::memory_order_release);
    CloseCarrierProcessMonitor();
    // Every cleanup primitive is bounded, but a kernel driver, SCM request, or
    // vendor helper can still violate that contract. A wedged LocalSystem
    // manager would otherwise block all later status and fallback requests.
    // Terminating this service is fail-closed: the kill-on-close AWG job is
    // destroyed, SCM restarts the manager, and the next start reclaims owned
    // routes and split-driver state before installing a new transport.
    const bool stopped = StopPrivilegedWindowsTunnelBounded(&error);
    g_tunnel_phase.store(TunnelPhase::kIdle, std::memory_order_release);
    g_tunnel_generation.store(0, std::memory_order_release);
    if (!stopped) {
      WriteResponse(pipe, Status::kOperationFailed, error);
      return;
    }
    std::string policy_error;
    if (!DisableWindowsKillSwitch(&policy_error)) {
      WriteResponse(pipe, Status::kOperationFailed, policy_error);
      return;
    }
    WriteResponse(pipe, Status::kStopSucceeded, "Tunnel stopped.");
    return;
  }
  if (command == Command::kStatus) {
    if (!payload.empty() || header.carrier_pid != 0 ||
        header.transition_generation != 0) {
      WriteResponse(pipe, Status::kInvalidRequest,
                    "Status requests must not contain a payload or carrier PID.");
      return;
    }
    const WindowsSplitTunnelDiagnostics diagnostics =
        GetWindowsSplitTunnelDiagnostics();
    const TunnelPhase phase =
        g_tunnel_phase.load(std::memory_order_acquire);
    const uint64_t generation =
        g_tunnel_generation.load(std::memory_order_acquire);
    const bool tunnel_running = phase == TunnelPhase::kCommitted &&
                                generation > 0 &&
                                IsPrivilegedWindowsTunnelRunning();
    std::string status = tunnel_running ? "running" : "stopped";
    status += ";generation=" + std::to_string(generation) +
              ";phase=" + TunnelPhaseName(phase) +
              ";route_committed=" +
              std::to_string(tunnel_running ? 1 : 0);
    status += ";split_consumer=" +
              std::to_string(diagnostics.consumer_running ? 1 : 0) +
              ";split_start=" + std::to_string(diagnostics.start_events) +
              ";split_stop=" + std::to_string(diagnostics.stop_events) +
              ";split_errors=" + std::to_string(diagnostics.error_events) +
               ";split_malformed=" +
               std::to_string(diagnostics.malformed_events) +
               ";split_io_errors=" + std::to_string(diagnostics.io_errors);
    status += ";" + PrivilegedWindowsTunnelRuntimeStatus();
    WriteResponse(pipe, Status::kOk, status);
    return;
  }
  WriteResponse(pipe, Status::kInvalidRequest, "Unknown tunnel command.");
}

DWORD RunPipeServer() {
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  constexpr wchar_t kPipeSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kPipeSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
    return GetLastError();
  }
  SECURITY_ATTRIBUTES security = {};
  security.nLength = sizeof(security);
  security.lpSecurityDescriptor = descriptor;
  HANDLE pipe = CreateNamedPipeW(
      winsvpn::tunnel_service::kPipeName,
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
          PIPE_REJECT_REMOTE_CLIENTS,
      1,
      static_cast<DWORD>(sizeof(ResponseHeader) +
                         winsvpn::tunnel_service::kMaxResponseBytes),
      winsvpn::tunnel_service::kMaxRequestBytes, 0, &security);
  LocalFree(descriptor);
  if (pipe == INVALID_HANDLE_VALUE) return GetLastError();
  HANDLE connected = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (connected == nullptr) {
    const DWORD error = GetLastError();
    CloseHandle(pipe);
    return error;
  }
  while (!IsStopRequested()) {
    OVERLAPPED overlapped = {};
    overlapped.hEvent = connected;
    ResetEvent(connected);
    BOOL ok = ConnectNamedPipe(pipe, &overlapped);
    DWORD code = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && code == ERROR_IO_PENDING) {
      HANDLE waits[3] = {connected, g_stop_event, g_carrier_process};
      const DWORD count = g_carrier_process != nullptr ? 3 : 2;
      const DWORD wait = WaitForMultipleObjects(count, waits, FALSE, INFINITE);
      if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &overlapped);
        if (WaitForSingleObject(connected, 1000) != WAIT_OBJECT_0) {
          TerminateServiceFailClosed(ERROR_TIMEOUT);
        }
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &overlapped, &ignored, FALSE);
        if (wait == WAIT_OBJECT_0 + 2) StopTunnelAfterCarrierExit();
        continue;
      }
      DWORD ignored = 0;
      code = GetOverlappedResult(pipe, &overlapped, &ignored, FALSE)
                 ? ERROR_SUCCESS
                 : GetLastError();
    }
    if (code == ERROR_SUCCESS || code == ERROR_PIPE_CONNECTED) {
      HandlePipeClient(pipe);
      DisconnectNamedPipe(pipe);
      continue;
    }
    if (code == ERROR_NO_DATA) {
      DisconnectNamedPipe(pipe);
      continue;
    }
    CloseHandle(connected);
    CloseHandle(pipe);
    return code;
  }
  CloseHandle(connected);
  CloseHandle(pipe);
  return ERROR_SUCCESS;
}

void WINAPI ServiceControlHandler(DWORD control) {
  if ((control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) &&
      g_stop_event != nullptr) {
    ReportServiceStatus(
        SERVICE_STOP_PENDING, NO_ERROR,
        winsvpn::tunnel_service::kStopOverallWatchdogMilliseconds + 10000);
    SetEvent(g_stop_event);
  }
}

void WINAPI ServiceMain(DWORD, wchar_t**) {
  g_service_status_handle = RegisterServiceCtrlHandlerW(
      winsvpn::tunnel_service::kServiceName, ServiceControlHandler);
  if (g_service_status_handle == nullptr) {
    return;
  }
  ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 10000);
  g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (g_stop_event == nullptr) {
    ReportServiceStatus(SERVICE_STOPPED, GetLastError());
    return;
  }
  ReportServiceStatus(SERVICE_RUNNING);
  const DWORD server_error = RunPipeServer();
  ReportServiceStatus(
      SERVICE_STOP_PENDING, NO_ERROR,
      winsvpn::tunnel_service::kStopOverallWatchdogMilliseconds + 10000);
  g_tunnel_phase.store(TunnelPhase::kStopping, std::memory_order_release);
  CloseCarrierProcessMonitor();
  std::string error;
  const bool tunnel_stopped = StopPrivilegedWindowsTunnelBounded(&error);
  g_tunnel_phase.store(TunnelPhase::kIdle, std::memory_order_release);
  g_tunnel_generation.store(0, std::memory_order_release);
  CloseHandle(g_stop_event);
  g_stop_event = nullptr;
  ReportServiceStatus(SERVICE_STOPPED,
                      server_error != ERROR_SUCCESS
                          ? server_error
                          : tunnel_stopped ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

bool WaitForServiceState(SC_HANDLE service, DWORD desired, DWORD timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + timeout_ms;
  do {
    SERVICE_STATUS_PROCESS status = {};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&status), sizeof(status),
                              &needed)) {
      return false;
    }
    if (status.dwCurrentState == desired) {
      return true;
    }
    Sleep(100);
  } while (GetTickCount64() < deadline);
  return false;
}

constexpr DWORD kServiceDeletionRetryTimeoutMilliseconds = 30000;
constexpr DWORD kServiceDeletionRetryIntervalMilliseconds = 250;

SC_HANDLE CreateTunnelManagerService(SC_HANDLE manager,
                                     const std::wstring& binary_path,
                                     DWORD* create_error) {
  const ULONGLONG deadline =
      GetTickCount64() + kServiceDeletionRetryTimeoutMilliseconds;
  for (;;) {
    SC_HANDLE service = CreateServiceW(
        manager, winsvpn::tunnel_service::kServiceName,
        winsvpn::tunnel_service::kServiceDisplayName,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START |
            SERVICE_STOP,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_SEVERE,
        binary_path.c_str(), nullptr, nullptr, nullptr, L"LocalSystem", nullptr);
    if (service != nullptr) {
      *create_error = ERROR_SUCCESS;
      return service;
    }

    *create_error = GetLastError();
    if (*create_error != ERROR_SERVICE_MARKED_FOR_DELETE) {
      return nullptr;
    }

    // DeleteService completes only after every process releases its service
    // handle. Services MMC and endpoint-management tools can briefly keep such
    // a handle open across an otherwise successful upgrade uninstall.
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) {
      return nullptr;
    }
    const ULONGLONG remaining = deadline - now;
    Sleep(static_cast<DWORD>(std::min<ULONGLONG>(
        remaining, kServiceDeletionRetryIntervalMilliseconds)));
  }
}

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

int InstallService() {
  if (RunningEmulatedOnArm64()) return ERROR_BAD_EXE_FORMAT;
  const std::wstring module = ModulePath();
  if (module.empty()) {
    return 2;
  }
  std::string cleanup_error;
  if (!CleanupPrivilegedWindowsTunnel(&cleanup_error)) {
    return 8;
  }
  const std::wstring binary_path = L"\"" + module + L"\" --service";
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
  if (manager == nullptr) {
    return 3;
  }
  DWORD create_error = ERROR_SUCCESS;
  SC_HANDLE service =
      CreateTunnelManagerService(manager, binary_path, &create_error);
  if (service == nullptr && create_error == ERROR_SERVICE_EXISTS) {
    service = OpenServiceW(manager, winsvpn::tunnel_service::kServiceName,
                           SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS |
                               SERVICE_START | SERVICE_STOP);
    if (service != nullptr) {
      SERVICE_STATUS status = {};
      if (!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
          GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return 9;
      }
      if (!WaitForServiceState(service, SERVICE_STOPPED, 180000)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return 10;
      }
    }
    if (service != nullptr && !ChangeServiceConfigW(
            service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_ERROR_SEVERE,
            binary_path.c_str(), nullptr, nullptr, nullptr, L"LocalSystem",
            nullptr, winsvpn::tunnel_service::kServiceDisplayName)) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      return 4;
    }
  }
  if (service == nullptr) {
    CloseServiceHandle(manager);
    return 5;
  }

  SERVICE_DESCRIPTIONW description = {
      const_cast<wchar_t*>(
          L"Performs only Win's VPN tunnel and owned route operations.")};
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION,
                             &description)) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 11;
  }
  // The GUI may auto-start immediately after sign-in. Keep the lightweight
  // manager available during that boot window instead of racing a delayed
  // service start and reporting a false repair error.
  SERVICE_DELAYED_AUTO_START_INFO delayed = {FALSE};
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                             &delayed)) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 12;
  }
  SERVICE_SID_INFO sid = {SERVICE_SID_TYPE_UNRESTRICTED};
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_SERVICE_SID_INFO, &sid)) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 13;
  }
  SC_ACTION actions[] = {
      {SC_ACTION_RESTART, 5000},
      {SC_ACTION_RESTART, 15000},
      {SC_ACTION_RESTART, 60000},
  };
  SERVICE_FAILURE_ACTIONSW failures = {};
  failures.dwResetPeriod = 86400;
  failures.cActions = static_cast<DWORD>(_countof(actions));
  failures.lpsaActions = actions;
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS,
                             &failures)) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 14;
  }
  SERVICE_FAILURE_ACTIONS_FLAG failure_policy = {TRUE};
  if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                             &failure_policy)) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 15;
  }

  if (!StartServiceW(service, 0, nullptr) &&
      GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return 6;
  }
  const bool running = WaitForServiceState(service, SERVICE_RUNNING, 15000);
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return running ? 0 : 7;
}

int UninstallService() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    return 2;
  }
  SC_HANDLE service = OpenServiceW(
      manager, winsvpn::tunnel_service::kServiceName,
      SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (service == nullptr && GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) {
    CloseServiceHandle(manager);
    return 6;
  }
  if (service != nullptr) {
    SERVICE_STATUS status = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status) &&
        GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      return 3;
    }
    if (!WaitForServiceState(service, SERVICE_STOPPED, 180000)) {
      CloseServiceHandle(service);
      CloseServiceHandle(manager);
      return 4;
    }
  }

  std::string error;
  const bool cleaned = CleanupPrivilegedWindowsTunnel(&error);
  const bool deleted = service == nullptr || DeleteService(service) != FALSE ||
                       GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE;
  if (service != nullptr) {
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
  return cleaned && deleted ? 0 : 5;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && wcscmp(argv[1], L"--service") == 0) {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<wchar_t*>(winsvpn::tunnel_service::kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    return StartServiceCtrlDispatcherW(table) ? 0 : 1;
  }
  if (argc == 2 && wcscmp(argv[1], L"--install") == 0) {
    return IsCurrentProcessElevated() ? InstallService()
                                      : ERROR_ELEVATION_REQUIRED;
  }
  if (argc == 2 && wcscmp(argv[1], L"--uninstall") == 0) {
    return IsCurrentProcessElevated() ? UninstallService()
                                      : ERROR_ELEVATION_REQUIRED;
  }
  if (argc == 2 && wcscmp(argv[1], L"--protocol-self-test") == 0) {
    std::string error;
    return sizeof(RequestHeader) == 24 && sizeof(ResponseHeader) == 12 &&
                   RunPrivilegedWindowsTunnelValidationSelfTest(&error)
               ? 0
               : 1;
  }
  return 64;
}
