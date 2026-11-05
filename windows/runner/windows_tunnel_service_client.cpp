#include "windows_tunnel_service_client.h"

#include "windows_tunnel_service_protocol.h"

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace {

using winsvpn::tunnel_service::Command;
using winsvpn::tunnel_service::RequestHeader;
using winsvpn::tunnel_service::ResponseHeader;
using winsvpn::tunnel_service::Status;

std::mutex g_start_cancellation_mutex;
HANDLE g_start_cancellation_event = nullptr;

std::wstring StartCancellationEventName(uint64_t transition_generation) {
  return std::wstring(winsvpn::tunnel_service::kStartCancellationEventPrefix) +
         std::to_wstring(GetCurrentProcessId()) + L"." +
         std::to_wstring(transition_generation);
}

DWORD CommandTimeoutMs(Command command) {
  switch (command) {
    case Command::kStart:
      return winsvpn::tunnel_service::kStartCommandTimeoutMilliseconds;
    case Command::kStop:
      return winsvpn::tunnel_service::kStopCommandTimeoutMilliseconds;
    case Command::kStatus:
      return winsvpn::tunnel_service::kStatusCommandTimeoutMilliseconds;
    default:
      return winsvpn::tunnel_service::kStatusCommandTimeoutMilliseconds;
  }
}

// The manager exposes a single pipe instance, so it is fully occupied for
// the whole duration of any in-flight start/stop. Status polling drives the
// Windows failover settlement loop, which already retries on its own
// ~500ms cadence (windowsTunnelStopPollInterval). Waiting the full 5s here
// on every busy poll can burn most of that loop's bounded budget before it
// ever observes a clean quiet window, even after the tunnel is genuinely
// and safely stopped. Fail fast for status and let the caller retry; start
// and stop keep the longer wait since each is a one-shot call, not polled.
DWORD PipeWaitTimeoutMs(Command command) {
  return command == Command::kStatus
             ? winsvpn::tunnel_service::kStatusPipeWaitTimeoutMilliseconds
             : winsvpn::tunnel_service::kMutationPipeWaitTimeoutMilliseconds;
}

DWORD RemainingTimeoutMs(ULONGLONG deadline) {
  const ULONGLONG now = GetTickCount64();
  if (now >= deadline) return 0;
  return static_cast<DWORD>(
      std::min<ULONGLONG>(deadline - now, MAXDWORD));
}

bool CompleteOverlappedPipeIo(HANDLE pipe, OVERLAPPED* overlapped,
                              DWORD timeout_ms, DWORD* transferred,
                              DWORD* completion_error) {
  if (overlapped == nullptr || overlapped->hEvent == nullptr ||
      transferred == nullptr || completion_error == nullptr) {
    return false;
  }
  if (timeout_ms == 0 ||
      WaitForSingleObject(overlapped->hEvent, timeout_ms) != WAIT_OBJECT_0) {
    CancelIoEx(pipe, overlapped);
    // The kernel may still own both the OVERLAPPED structure and its event
    // after CancelIoEx returns. Observe terminal completion before either
    // stack storage or handle is released; a timed wait followed by closing
    // them is a use-after-scope/invalid-handle race.
    DWORD canceled_bytes = 0;
    GetOverlappedResult(pipe, overlapped, &canceled_bytes, TRUE);
    *completion_error = ERROR_TIMEOUT;
    return false;
  }
  if (GetOverlappedResult(pipe, overlapped, transferred, FALSE) != FALSE) {
    *completion_error = ERROR_SUCCESS;
    return true;
  }
  *completion_error = GetLastError();
  return *completion_error == ERROR_MORE_DATA;
}

bool WritePipeBounded(HANDLE pipe, const uint8_t* bytes, DWORD size,
                      ULONGLONG deadline, std::string* error) {
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (overlapped.hEvent == nullptr) {
    *error = "Unable to create the tunnel-manager write event.";
    return false;
  }
  DWORD written = 0;
  DWORD completion_error = ERROR_SUCCESS;
  bool ok = WriteFile(pipe, bytes, size, &written, &overlapped) != FALSE;
  if (!ok) {
    completion_error = GetLastError();
    if (completion_error == ERROR_IO_PENDING) {
      ok = CompleteOverlappedPipeIo(
          pipe, &overlapped, RemainingTimeoutMs(deadline), &written,
          &completion_error);
    }
  }
  CloseHandle(overlapped.hEvent);
  if (!ok || written != size) {
    *error = completion_error == ERROR_TIMEOUT
                 ? "Tunnel manager request timed out."
                 : "Unable to send the tunnel request to the protected service.";
    return false;
  }
  return true;
}

bool ReadPipeChunkBounded(HANDLE pipe, uint8_t* destination, DWORD capacity,
                          ULONGLONG deadline, DWORD* bytes_read,
                          bool* more_data, std::string* error) {
  OVERLAPPED overlapped = {};
  overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (overlapped.hEvent == nullptr) {
    *error = "Unable to create the tunnel-manager read event.";
    return false;
  }
  *bytes_read = 0;
  *more_data = false;
  DWORD completion_error = ERROR_SUCCESS;
  bool ok =
      ReadFile(pipe, destination, capacity, bytes_read, &overlapped) != FALSE;
  if (!ok) {
    completion_error = GetLastError();
    if (completion_error == ERROR_IO_PENDING) {
      ok = CompleteOverlappedPipeIo(
          pipe, &overlapped, RemainingTimeoutMs(deadline), bytes_read,
          &completion_error);
    } else if (completion_error == ERROR_MORE_DATA) {
      ok = true;
    }
  }
  CloseHandle(overlapped.hEvent);
  *more_data = completion_error == ERROR_MORE_DATA;
  if (!ok) {
    *error = completion_error == ERROR_TIMEOUT
                 ? "Tunnel manager response timed out."
                 : "Tunnel manager returned an incomplete response.";
    return false;
  }
  return true;
}

bool ReadPipeExact(HANDLE pipe, void* destination, DWORD bytes,
                   ULONGLONG deadline, std::string* error) {
  auto* output = static_cast<uint8_t*>(destination);
  DWORD total = 0;
  while (total < bytes) {
    DWORD read = 0;
    bool more_data = false;
    if (!ReadPipeChunkBounded(pipe, output + total, bytes - total, deadline,
                              &read, &more_data, error)) {
      return false;
    }
    if (read > 0) {
      total += read;
    }
    // Message-mode named pipes can report ERROR_MORE_DATA (and, when the
    // server closes immediately after its final write, occasionally a closing
    // status) together with the bytes requested by this read. Once the exact
    // frame segment is present, consume it instead of turning a successful
    // privileged operation into a false transport failure.
    if (total == bytes) {
      return true;
    }
    if (read == 0 || !more_data) {
      *error = "Tunnel manager closed the response pipe unexpectedly.";
      return false;
    }
  }
  return true;
}

bool CallTunnelManager(Command command, const std::string& payload,
                       uint32_t carrier_pid, uint64_t transition_generation,
                       std::string* response_text_out,
                       std::string* error) {
  if (error == nullptr) {
    return false;
  }
  error->clear();
  if (response_text_out != nullptr) {
    response_text_out->clear();
  }
  if (payload.size() > winsvpn::tunnel_service::kMaxRequestBytes) {
    *error = "Tunnel configuration exceeds the service request limit.";
    return false;
  }

  if (!WaitNamedPipeW(winsvpn::tunnel_service::kPipeName,
                      PipeWaitTimeoutMs(command))) {
    *error = "Win's VPN Tunnel Manager is unavailable. Repair the installation.";
    return false;
  }
  HANDLE pipe = CreateFileW(
      winsvpn::tunnel_service::kPipeName, GENERIC_READ | GENERIC_WRITE, 0,
      nullptr, OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION |
          SECURITY_EFFECTIVE_ONLY,
      nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    *error = "Unable to open the protected tunnel-manager channel.";
    return false;
  }

  // B2-2 (Claude audit, 2026-08-28): authenticate the SERVER before any
  // payload byte leaves. The client used to open the pipe and immediately
  // write the AWG configuration -- including PrivateKey and PresharedKey --
  // with no idea who was on the other end. During the service-restart
  // window a local attacker can squat the pipe name and harvest exactly
  // that, and answer with a success code the client commits on. The
  // server's process image must now be the INSTALLED tunnel service
  // (wins_vpn_tunnel_service.exe beside this executable) before the
  // request is built. SECURITY_IDENTIFICATION already protected the server
  // FROM the client; this is the mirror image.
  {
    DWORD server_pid = 0;
    if (GetNamedPipeServerProcessId(pipe, &server_pid) == FALSE ||
        server_pid == 0) {
      CloseHandle(pipe);
      *error = "The tunnel-manager channel has no verifiable server.";
      return false;
    }
    HANDLE server_process =
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
    if (server_process == nullptr) {
      CloseHandle(pipe);
      *error = "The tunnel-manager server could not be inspected.";
      return false;
    }
    wchar_t image[MAX_PATH] = {};
    DWORD image_length = MAX_PATH;
    const bool image_ok = QueryFullProcessImageNameW(
                              server_process, 0, image, &image_length) != FALSE;
    CloseHandle(server_process);
    wchar_t self[MAX_PATH] = {};
    DWORD self_length = GetModuleFileNameW(nullptr, self, MAX_PATH);
    bool service_beside_client = false;
    if (image_ok && self_length > 0 && self_length < MAX_PATH) {
      const std::wstring self_path(self, self_length);
      const size_t separator = self_path.find_last_of(L"\\/");
      if (separator != std::wstring::npos) {
        service_beside_client =
            _wcsicmp(std::wstring(image, image_length).c_str(),
                     self_path.substr(0, separator + 1)
                         .append(L"wins_vpn_tunnel_service.exe")
                         .c_str()) == 0;
      }
    }
    if (!service_beside_client) {
      CloseHandle(pipe);
      *error =
          "The tunnel-manager channel is not served by the installed Win's "
          "VPN service. Repair the installation.";
      return false;
    }
  }

  DWORD mode = PIPE_READMODE_MESSAGE;
  if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
    CloseHandle(pipe);
    *error = "Unable to enable the tunnel-manager message protocol.";
    return false;
  }

  RequestHeader header = {
      winsvpn::tunnel_service::kProtocolMagic,
      winsvpn::tunnel_service::kProtocolVersion,
      static_cast<uint16_t>(command),
      static_cast<uint32_t>(payload.size()),
      carrier_pid,
      transition_generation,
  };
  std::vector<uint8_t> request(sizeof(header) + payload.size());
  std::memcpy(request.data(), &header, sizeof(header));
  if (!payload.empty()) {
    std::memcpy(request.data() + sizeof(header), payload.data(), payload.size());
  }
  const ULONGLONG deadline = GetTickCount64() + CommandTimeoutMs(command);
  if (!WritePipeBounded(pipe, request.data(),
                        static_cast<DWORD>(request.size()), deadline, error)) {
    CloseHandle(pipe);
    return false;
  }

  ResponseHeader response = {};
  if (!ReadPipeExact(pipe, &response, sizeof(response), deadline, error)) {
    CloseHandle(pipe);
    return false;
  }
  if (response.magic != winsvpn::tunnel_service::kProtocolMagic ||
      response.version != winsvpn::tunnel_service::kProtocolVersion ||
      response.payload_size > winsvpn::tunnel_service::kMaxResponseBytes) {
    CloseHandle(pipe);
    *error = "Tunnel manager returned an invalid protocol response.";
    return false;
  }
  std::string response_text(response.payload_size, '\0');
  if (response.payload_size > 0 &&
      !ReadPipeExact(pipe, response_text.data(), response.payload_size,
                     deadline, error)) {
    CloseHandle(pipe);
    return false;
  }
  CloseHandle(pipe);

  if (response.status !=
      (command == Command::kStart
           ? static_cast<uint16_t>(Status::kStartSucceeded)
           : command == Command::kStop
                 ? static_cast<uint16_t>(Status::kStopSucceeded)
                 : static_cast<uint16_t>(Status::kOk))) {
    *error = response_text.empty()
                 ? "The protected tunnel manager rejected the request."
                 : response_text;
    return false;
  }
  if (response_text_out != nullptr) {
    *response_text_out = response_text;
  }
  return true;
}

}  // namespace

bool ArmWindowsTunnelStartCancellation(uint64_t transition_generation,
                                       std::string* error) {
  if (error == nullptr || transition_generation == 0) {
    return false;
  }
  std::lock_guard<std::mutex> lock(g_start_cancellation_mutex);
  if (g_start_cancellation_event != nullptr) {
    *error = "A Windows tunnel start is already in progress.";
    return false;
  }
  const std::wstring name = StartCancellationEventName(transition_generation);
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, name.c_str());
  if (event == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
    if (event != nullptr) {
      CloseHandle(event);
    }
    *error = "Unable to establish the tunnel start cancellation boundary.";
    return false;
  }
  g_start_cancellation_event = event;
  return true;
}

void SignalWindowsTunnelStartCancellation() {
  std::lock_guard<std::mutex> lock(g_start_cancellation_mutex);
  if (g_start_cancellation_event != nullptr) {
    SetEvent(g_start_cancellation_event);
  }
}

void DisarmWindowsTunnelStartCancellation() {
  std::lock_guard<std::mutex> lock(g_start_cancellation_mutex);
  if (g_start_cancellation_event != nullptr) {
    CloseHandle(g_start_cancellation_event);
    g_start_cancellation_event = nullptr;
  }
}

bool StartWindowsTunnelThroughService(const std::string& config,
                                      uint32_t carrier_pid,
                                      uint64_t transition_generation,
                                      std::string* error) {
  return CallTunnelManager(Command::kStart, config, carrier_pid,
                           transition_generation, nullptr, error);
}

bool StopWindowsTunnelThroughService(std::string* error) {
  return CallTunnelManager(Command::kStop, "", 0, 0, nullptr, error);
}

bool QueryWindowsTunnelManager(std::string* status, std::string* error) {
  return CallTunnelManager(Command::kStatus, "", 0, 0, status, error);
}
