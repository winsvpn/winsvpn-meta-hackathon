#include "winn3_supervisor.h"

#if defined(WINS_TUNNEL_SERVICE_CORE)

// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <sddl.h>
#include <aclapi.h>
// clang-format on

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "windows_tunnel_service_protocol.h"

// The Windows half of the Winn Protocol v3 supervisor.
//
// Everything that DECIDES is in winn3_supervisor.h, where it is standard C++17
// and is executed by winn3_supervisor_test.cc on a development machine that is
// not Windows. What is left here is the part that genuinely needs the platform:
// two child processes, four pipes, a route pin, and netsh. This file makes no
// decision it could have made in the header, and where it looks like it does --
// the MTU it hands the relay, the moment it promotes -- it is calling a
// function from the header.
//
// # The one lifetime rule
//
// Both children live in a single KILL-ON-JOB-CLOSE job object. That is what
// makes every failure path below correct without each one having to be: if this
// process dies, is terminated, or simply drops the job handle, Windows destroys
// the relay, the relay's Wintun adapter goes with it, and the interface every
// posture command was installed on ceases to exist -- taking the addresses and
// the interface-scoped routes with it. THE POSTURE TEARDOWN IS STRUCTURAL. The
// one thing that does NOT go away by itself is the physical /32 pin, because it
// is installed on the physical interface and that interface survives; it is the
// single thing StopWindowsWinn3Tunnel has to undo by hand, and it is undone
// before anything else.

namespace winsvpn::winn3 {
namespace {

// The bounded components of a v3 start. Each is a wait on a specific event from
// a specific child, not a sleep, so the normal case costs milliseconds.
constexpr DWORD kRelayHostPortTimeoutMs = 5000;
constexpr DWORD kPrintSizingTimeoutMs = 5000;
constexpr DWORD kEngineSeamPortTimeoutMs = 10000;
constexpr DWORD kRelayReadyTimeoutMs = 10000;
constexpr DWORD kFirstStatusTimeoutMs = 10000;
// The promotion wait is the only long one, and it is the honest one: it is
// waiting for a handshake to complete over a censored network AND for an inner
// packet to come back. A shorter budget would fail a link that was going to
// work; an unbounded one would leave a user staring at a spinner. The status
// stream ticks once a second, so this is twenty-five chances to read a counter.
constexpr DWORD kPromotionDeadlineMs = 25000;
constexpr DWORD kNetshTimeoutMs = 15000;
constexpr DWORD kChildStopWaitMs = 5000;
constexpr DWORD kReaderJoinTimeoutMs = 5000;

// One descriptor contract is used for both fresh creation and verification.
// O:SY makes ownership part of the contract; P prevents inherited ACEs; AI
// records the installer's auto-inherited directory form; and the only two ACEs
// grant full control to LocalSystem and Builtin Administrators.
constexpr wchar_t kWinn3DirectorySddl[] =
    L"O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
constexpr wchar_t kWinn3FileSddl[] =
    L"O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";

// The whole v3 start must fit inside the service's own start watchdog, which is
// shared with the winn/1 path and is not this lane's to raise. Asserted rather
// than assumed, because the failure mode of getting it wrong is the service
// terminating itself mid-start -- fail-closed, but indistinguishable from a
// crash in a support ticket.
constexpr DWORD kWinn3CriticalPathBudgetMs =
    kRelayHostPortTimeoutMs + kPrintSizingTimeoutMs + kEngineSeamPortTimeoutMs +
    kRelayReadyTimeoutMs + kFirstStatusTimeoutMs + kPromotionDeadlineMs +
    kNetshTimeoutMs;
static_assert(
    kWinn3CriticalPathBudgetMs <
        winsvpn::tunnel_service::kStartOverallWatchdogMilliseconds,
    "The winn/3 start path must fit inside the service start watchdog.");

// The relay reports this many bytes at most on one line. A child that emits an
// unbounded line is a child that would otherwise grow this process's memory
// without limit, and neither of these children has any reason to.
constexpr size_t kMaxChildLineBytes = 8192;

std::wstring Widen(const std::string& value) {
  if (value.empty()) {
    return std::wstring();
  }
  const int needed = MultiByteToWideChar(
      CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (needed <= 0) {
    return std::wstring();
  }
  std::wstring out(static_cast<size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), needed);
  return out;
}

void CloseHandleIfValid(HANDLE* handle) {
  if (handle != nullptr && *handle != nullptr &&
      *handle != INVALID_HANDLE_VALUE) {
    CloseHandle(*handle);
    *handle = INVALID_HANDLE_VALUE;
  }
}

// PipeLineReader turns a byte pipe into lines.
//
// A blocking ReadFile is used rather than an overlapped one because there is
// exactly one way each of these pipes ends -- the child exits, or this process
// closes its own handle during teardown -- and both produce a read failure that
// unwinds the thread. A timeout on the read itself would only duplicate the
// timeouts the start path already applies to the EVENTS these threads signal.
class PipeLineReader {
 public:
  explicit PipeLineReader(HANDLE pipe) : pipe_(pipe) {}

  bool NextLine(std::string* line) {
    for (;;) {
      const size_t newline = buffer_.find('\n');
      if (newline != std::string::npos) {
        *line = buffer_.substr(0, newline);
        buffer_.erase(0, newline + 1);
        return true;
      }
      if (buffer_.size() > kMaxChildLineBytes) {
        // Refuse rather than grow. Nothing on either of these pipes has a
        // legitimate reason to emit a line this long.
        return false;
      }
      char chunk[1024];
      DWORD read = 0;
      if (ReadFile(pipe_, chunk, sizeof(chunk), &read, nullptr) == FALSE ||
          read == 0) {
        return false;
      }
      buffer_.append(chunk, read);
    }
  }

  // NextLineBefore is the bounded variant, for the ONE reader that is not on a
  // thread of its own.
  //
  // The threaded readers can afford a blocking ReadFile because the only ways
  // their pipes end -- the child exits, or teardown closes this process's
  // handle -- both unwind them, and the start path bounds the EVENTS they
  // signal rather than the reads themselves. The sizing query has no thread and
  // no event, so it bounds the read. PeekNamedPipe is used rather than
  // overlapped I/O because it never blocks and needs no second handle: a
  // pathological child that neither writes nor exits costs one poll interval of
  // latency instead of the service's whole start watchdog.
  bool NextLineBefore(std::string* line, ULONGLONG deadline) {
    for (;;) {
      const size_t newline = buffer_.find('\n');
      if (newline != std::string::npos) {
        *line = buffer_.substr(0, newline);
        buffer_.erase(0, newline + 1);
        return true;
      }
      if (buffer_.size() > kMaxChildLineBytes) {
        return false;
      }
      DWORD available = 0;
      if (PeekNamedPipe(pipe_, nullptr, 0, nullptr, &available, nullptr) ==
          FALSE) {
        return false;  // The write end is gone: EOF, or the child died.
      }
      if (available == 0) {
        if (GetTickCount64() >= deadline) {
          return false;
        }
        Sleep(25);
        continue;
      }
      char chunk[1024];
      const DWORD want =
          available < sizeof(chunk) ? available : sizeof(chunk);
      DWORD read = 0;
      if (ReadFile(pipe_, chunk, want, &read, nullptr) == FALSE || read == 0) {
        return false;
      }
      buffer_.append(chunk, read);
    }
  }

 private:
  HANDLE pipe_;
  std::string buffer_;
};

struct ChildProcess {
  PROCESS_INFORMATION info = {};
  HANDLE stdin_write = INVALID_HANDLE_VALUE;
  HANDLE stdout_read = INVALID_HANDLE_VALUE;
  HANDLE stderr_read = INVALID_HANDLE_VALUE;

  bool Alive() const {
    return info.hProcess != nullptr &&
           WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT;
  }
};

// Supervision is a singleton. Two v3 tunnels would be two Wintun adapters
// fighting over one adapter name, which the relay already refuses with its
// named stop event; refusing here as well means the refusal is legible instead
// of arriving as a child that exited with code 3.
struct SupervisorState {
  std::mutex lifecycle;

  ChildProcess relay;
  ChildProcess engine;
  HANDLE job = nullptr;

  HANDLE relay_host_port_event = nullptr;
  HANDLE relay_ready_event = nullptr;
  HANDLE engine_port_event = nullptr;
  HANDLE status_event = nullptr;

  HANDLE relay_reader = nullptr;
  HANDLE engine_stdout_reader = nullptr;
  HANDLE engine_stderr_reader = nullptr;

  std::atomic<int> relay_host_port{0};
  std::atomic<int> engine_seam_port{0};
  std::atomic<bool> stopping{false};
  std::atomic<bool> promoted{false};

  std::mutex status_mutex;
  std::string last_status_json;
  EngineStatus last_status;
  Winn3RelayReady ready;

  // The physical /32 pin. The ONE thing teardown must undo by hand.
  MIB_IPFORWARD_ROW2 pin = {};
  bool pin_installed = false;
  std::string exclusion_description;

  int applied_mtu = 0;
  std::wstring profile_path;
  std::vector<std::wstring> session_working_paths;
};

std::mutex g_lifecycle_mutex;
SupervisorState* g_state = nullptr;

// --- launching ---------------------------------------------------------------

std::wstring ModuleDirectoryOf() {
  wchar_t path[MAX_PATH] = {};
  const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return std::wstring();
  }
  std::wstring full(path, length);
  const size_t separator = full.find_last_of(L"\\/");
  return separator == std::wstring::npos ? std::wstring()
                                         : full.substr(0, separator);
}

bool FileExistsAt(const std::wstring& path) {
  if (path.empty()) {
    return false;
  }
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES &&
         (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring JoinModulePath(const wchar_t* leaf) {
  const std::wstring directory = ModuleDirectoryOf();
  if (directory.empty()) {
    return std::wstring();
  }
  return directory + L"\\" + leaf;
}

// The v3 relay, resolved by this name ALONE.
//
// It is NOT windows/awg_engine's winsvpn_awg_engine.exe and must never be
// confused with it: that binary IS AmneziaWG, it owns the adapter named
// "winsvpn", and it emits already-encrypted outer datagrams. This one owns
// "winsvpn3" and emits RAW INNER PACKETS. Starting the wrong one here is the
// mistake that puts cleartext on the wire, so the name is exact and there is no
// fallback search path for it.
std::wstring FindWinn3RelayExecutable() {
  const std::wstring candidate = JoinModulePath(L"winsvpn_winn3_engine.exe");
  return FileExistsAt(candidate) ? candidate : std::wstring();
}

std::wstring FindWinn3DatapathExecutable() {
  const std::wstring candidate = JoinModulePath(L"winn-datapath.exe");
  return FileExistsAt(candidate) ? candidate : std::wstring();
}

// LaunchChild starts one child with the requested redirections.
//
// Exactly the redirected handles are inherited, through a
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST, and nothing else. bInheritHandles alone
// would hand the child every inheritable handle this service holds, which for a
// LocalSystem tunnel manager includes handles it has no business seeing.
bool LaunchChild(const std::wstring& image, const std::wstring& arguments,
                 HANDLE job, bool want_stdin, ChildProcess* child,
                 std::string* error) {
  SECURITY_ATTRIBUTES inheritable = {};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;

  HANDLE child_stdin = INVALID_HANDLE_VALUE;
  HANDLE child_stdout = INVALID_HANDLE_VALUE;
  HANDLE child_stderr = INVALID_HANDLE_VALUE;
  HANDLE host_stdin_write = INVALID_HANDLE_VALUE;
  HANDLE host_stdout_read = INVALID_HANDLE_VALUE;
  HANDLE host_stderr_read = INVALID_HANDLE_VALUE;

  const auto abandon = [&](const char* message) {
    CloseHandleIfValid(&child_stdin);
    CloseHandleIfValid(&child_stdout);
    CloseHandleIfValid(&child_stderr);
    CloseHandleIfValid(&host_stdin_write);
    CloseHandleIfValid(&host_stdout_read);
    CloseHandleIfValid(&host_stderr_read);
    *error = message;
    return false;
  };

  if (CreatePipe(&host_stdout_read, &child_stdout, &inheritable, 0) == FALSE ||
      CreatePipe(&host_stderr_read, &child_stderr, &inheritable, 0) == FALSE) {
    return abandon("Unable to create the Winn Protocol v3 child pipes.");
  }
  if (want_stdin &&
      CreatePipe(&child_stdin, &host_stdin_write, &inheritable, 0) == FALSE) {
    return abandon("Unable to create the Winn Protocol v3 control pipe.");
  }
  if (!want_stdin) {
    // A child with no control channel still needs a stdin, and it must be one
    // that reads EOF immediately rather than an inherited console.
    child_stdin =
        CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &inheritable, OPEN_EXISTING, 0, nullptr);
    if (child_stdin == INVALID_HANDLE_VALUE) {
      return abandon("Unable to open the null device for a v3 child.");
    }
  }
  // The host ends must never reach the child, or the child would hold its own
  // read end open and teardown could not rely on a broken pipe.
  if (SetHandleInformation(host_stdout_read, HANDLE_FLAG_INHERIT, 0) == FALSE ||
      SetHandleInformation(host_stderr_read, HANDLE_FLAG_INHERIT, 0) == FALSE ||
      (want_stdin && SetHandleInformation(host_stdin_write, HANDLE_FLAG_INHERIT,
                                          0) == FALSE)) {
    return abandon("Unable to secure the Winn Protocol v3 pipe handles.");
  }

  HANDLE inherited[3] = {child_stdin, child_stdout, child_stderr};
  SIZE_T attribute_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
  std::vector<uint8_t> attribute_storage(attribute_size);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes =
      reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  const bool attributes_ready =
      attribute_size != 0 &&
      InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) !=
          FALSE &&
      UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                inherited, sizeof(inherited), nullptr,
                                nullptr) != FALSE;
  if (!attributes_ready) {
    return abandon("Unable to restrict handle inheritance for a v3 child.");
  }

  STARTUPINFOEXW startup = {};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = child_stdin;
  startup.StartupInfo.hStdOutput = child_stdout;
  startup.StartupInfo.hStdError = child_stderr;
  startup.lpAttributeList = attributes;

  // Quoting the image path keeps a space in the install directory from being
  // parsed as an argument -- and the relay REFUSES to start with any argument
  // at all, so a split path there is a silent exit code 2 rather than a message.
  std::wstring command = L"\"" + image + L"\"";
  if (!arguments.empty()) {
    command += L" " + arguments;
  }
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  const size_t separator = image.find_last_of(L"\\/");
  const std::wstring working_directory =
      separator == std::wstring::npos ? std::wstring()
                                      : image.substr(0, separator);

  PROCESS_INFORMATION process = {};
  bool created =
      CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | CREATE_SUSPENDED |
                         EXTENDED_STARTUPINFO_PRESENT,
                     nullptr,
                     working_directory.empty() ? nullptr
                                               : working_directory.c_str(),
                     &startup.StartupInfo, &process) != FALSE;
  if (created &&
      (AssignProcessToJobObject(job, process.hProcess) == FALSE ||
       ResumeThread(process.hThread) == static_cast<DWORD>(-1))) {
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, kChildStopWaitMs);
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    process = PROCESS_INFORMATION{};
    created = false;
  }
  DeleteProcThreadAttributeList(attributes);

  // The child owns its ends now; the host must drop them so a child exit is
  // observable as a broken pipe rather than as a reader blocked forever.
  CloseHandleIfValid(&child_stdin);
  CloseHandleIfValid(&child_stdout);
  CloseHandleIfValid(&child_stderr);

  if (!created || process.hProcess == nullptr) {
    return abandon("Unable to launch a Winn Protocol v3 child process.");
  }
  CloseHandle(process.hThread);
  process.hThread = nullptr;

  child->info = process;
  child->stdin_write = want_stdin ? host_stdin_write : INVALID_HANDLE_VALUE;
  child->stdout_read = host_stdout_read;
  child->stderr_read = host_stderr_read;
  return true;
}

// --- the reader threads ------------------------------------------------------

DWORD WINAPI RelayReaderThread(LPVOID parameter) {
  SupervisorState* state = static_cast<SupervisorState*>(parameter);
  PipeLineReader reader(state->relay.stdout_read);
  std::string line;
  while (reader.NextLine(&line)) {
    int port = 0;
    if (ParseRelayHostPort(line, &port)) {
      state->relay_host_port.store(port, std::memory_order_release);
      SetEvent(state->relay_host_port_event);
      continue;
    }
    Winn3RelayReady ready;
    if (ParseRelayReady(line, &ready)) {
      {
        std::lock_guard<std::mutex> guard(state->status_mutex);
        state->ready = ready;
      }
      SetEvent(state->relay_ready_event);
      continue;
    }
    // Anything else is drained. A relay that emitted an unrecognised line has
    // not been given permission to do anything by it.
  }
  // EOF: the relay is gone, so the adapter is gone. Waking every waiter is what
  // turns "the child died" into a bounded refusal rather than a timeout.
  SetEvent(state->relay_host_port_event);
  SetEvent(state->relay_ready_event);
  SetEvent(state->status_event);
  return 0;
}

DWORD WINAPI EngineStdoutThread(LPVOID parameter) {
  SupervisorState* state = static_cast<SupervisorState*>(parameter);
  PipeLineReader reader(state->engine.stdout_read);
  std::string line;
  while (reader.NextLine(&line)) {
    EngineStatus parsed;
    const bool ok = ParseWinn3StatusLine(line, &parsed);
    {
      std::lock_guard<std::mutex> guard(state->status_mutex);
      // The RAW line is kept only when it parsed. A line this host could not
      // make sense of is not published as though it were a status document.
      if (ok) {
        state->last_status_json = line;
        state->last_status = parsed;
      }
    }
    if (ok) {
      SetEvent(state->status_event);
    }
  }
  SetEvent(state->status_event);
  return 0;
}

DWORD WINAPI EngineStderrThread(LPVOID parameter) {
  SupervisorState* state = static_cast<SupervisorState*>(parameter);
  PipeLineReader reader(state->engine.stderr_read);
  std::string line;
  while (reader.NextLine(&line)) {
    int port = 0;
    if (ParseEngineSeamPort(line, &port)) {
      state->engine_seam_port.store(port, std::memory_order_release);
      SetEvent(state->engine_port_event);
    }
    // Every other stderr line is drained and DISCARDED rather than logged.
    //
    // The engine's first stderr line is profile.describeForLog(). Checked by
    // running the real binary rather than assumed: it emits shapes and
    // booleans -- `version=winn3-host/1 role=client carrier=udp
    // plan=udp+tcp+tls path_mtu=1280 device=loopback-udp inner_v4=true
    // inner_v6=false allow_own_socket=true exclusion_declared=true
    // fast_pq=false` -- and carries no endpoint and no address. So the reason
    // this drains rather than logs is NOT that the line is sensitive. It is
    // that stderr is an unbounded surface belonging to another process, this
    // one runs as LocalSystem, and the status document on stdout is the
    // diagnostic surface that has a schema.
  }
  SetEvent(state->engine_port_event);
  return 0;
}

// --- the physical /32 pin ----------------------------------------------------

// InstallOuterSocketPin keeps the engine's own outer socket out of the tunnel
// it carries.
//
// The engine opens ONE socket that touches the network, under allow_own_socket.
// Without an exclusion, that socket's datagrams match the tunnel's own default
// route the moment this supervisor promotes, and the carrier loops into itself.
// The Windows exclusion is a PINNED /32 HOST ROUTE to the v3 gateway on the
// PHYSICAL interface with the physical next hop, installed BEFORE any tunnel
// route exists. Longest-prefix match means that /32 always beats the two /1s
// promotion installs on the tunnel.
//
// It follows `[winn3] endpoint` and nothing else. The Apple lane found the hole
// this avoids: deriving the exclusion from a peer endpoint that has been
// rewritten to loopback pins 127.0.0.1 and the tunnel dead-loops.
//
// A LOOPBACK carrier is a legitimate case and is not pinned: a v3 session
// stacked on a local stealth inbound dials 127.0.0.1, which no tunnel route can
// capture, so there is nothing to exclude. It is reported as such rather than
// silently skipped, because "no pin was needed" and "the pin failed" must never
// look the same in a log.
bool InstallOuterSocketPin(const std::string& endpoint, SupervisorState* state,
                           std::string* error) {
  std::string host;
  std::string port;
  if (!SplitWinn3Endpoint(endpoint, &host, &port)) {
    *error =
        "The Winn Protocol v3 carrier endpoint is not an IP literal with a "
        "port, so no outer-socket exclusion could be pinned for it.";
    return false;
  }

  SOCKADDR_INET destination = {};
  const std::wstring wide_host = Widen(host);
  if (InetPtonW(AF_INET, wide_host.c_str(), &destination.Ipv4.sin_addr) == 1) {
    destination.si_family = AF_INET;
    destination.Ipv4.sin_family = AF_INET;
    const uint32_t address = ntohl(destination.Ipv4.sin_addr.s_addr);
    if ((address >> 24) == 127) {
      state->pin_installed = false;
      state->exclusion_description =
          "no physical pin required: the v3 carrier dials a loopback address, "
          "which no tunnel route can capture";
      return true;
    }
  } else if (InetPtonW(AF_INET6, wide_host.c_str(),
                       &destination.Ipv6.sin6_addr) == 1) {
    destination.si_family = AF_INET6;
    destination.Ipv6.sin6_family = AF_INET6;
    if (IN6_IS_ADDR_LOOPBACK(&destination.Ipv6.sin6_addr)) {
      state->pin_installed = false;
      state->exclusion_description =
          "no physical pin required: the v3 carrier dials a loopback address, "
          "which no tunnel route can capture";
      return true;
    }
  } else {
    *error =
        "The Winn Protocol v3 carrier endpoint is not a usable IP address.";
    return false;
  }

  MIB_IPFORWARD_ROW2 best = {};
  SOCKADDR_INET best_source = {};
  if (GetBestRoute2(nullptr, 0, nullptr, &destination, 0, &best,
                    &best_source) != NO_ERROR) {
    *error =
        "Windows has no route to the Winn Protocol v3 gateway, so the "
        "engine's own outer socket could not be excluded from the tunnel it "
        "would carry. The connection was stopped rather than started without "
        "the exclusion.";
    return false;
  }

  MIB_IPFORWARD_ROW2 pin = {};
  InitializeIpForwardEntry(&pin);
  pin.InterfaceLuid = best.InterfaceLuid;
  pin.InterfaceIndex = best.InterfaceIndex;
  pin.DestinationPrefix.Prefix = destination;
  pin.DestinationPrefix.PrefixLength =
      destination.si_family == AF_INET ? 32 : 128;
  pin.NextHop = best.NextHop;
  pin.SitePrefixLength = 0;
  pin.Metric = 1;
  pin.Protocol = MIB_IPPROTO_NETMGMT;
  pin.Loopback = FALSE;
  pin.AutoconfigureAddress = FALSE;
  pin.Publish = FALSE;
  pin.Immortal = FALSE;

  const DWORD created = CreateIpForwardEntry2(&pin);
  if (created != NO_ERROR && created != ERROR_OBJECT_ALREADY_EXISTS) {
    *error =
        "Windows refused the physical host route that keeps the Winn Protocol "
        "v3 engine's own socket out of the tunnel it carries, so the "
        "connection was stopped rather than started without it.";
    return false;
  }
  state->pin = pin;
  // ERROR_OBJECT_ALREADY_EXISTS means somebody else's identical row is already
  // there. It is recorded as OURS anyway, so teardown removes it: leaving a
  // stale /32 to the gateway on the physical interface is a worse outcome than
  // removing a row we may not have created, because it survives the tunnel and
  // silently excludes that address from every future one.
  state->pin_installed = true;
  state->exclusion_description =
      "pinned /32 host route to the winn/3 gateway on the physical interface "
      "with the physical next hop, installed before any tunnel route existed";
  return true;
}

void RemoveOuterSocketPin(SupervisorState* state) {
  if (state->pin_installed) {
    DeleteIpForwardEntry2(&state->pin);
    state->pin_installed = false;
  }
}

// --- executing the posture ---------------------------------------------------

// RunNetsh executes ONE rendered argument vector.
//
// netsh is resolved to its absolute path in the system directory rather than
// found on PATH. This process is LocalSystem; a PATH lookup for a program it
// runs with those privileges is a privilege-escalation surface, and it is one
// that costs nothing to close.
bool RunNetsh(const std::vector<std::string>& argv, std::string* error) {
  if (argv.empty() || argv[0] != "netsh") {
    *error = "A Winn Protocol v3 posture command was not a netsh command.";
    return false;
  }
  wchar_t system_directory[MAX_PATH] = {};
  const UINT length = GetSystemDirectoryW(system_directory, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    *error = "Unable to locate the Windows system directory.";
    return false;
  }
  const std::wstring image =
      std::wstring(system_directory, length) + L"\\netsh.exe";

  std::vector<std::string> tail(argv.begin() + 1, argv.end());
  const std::wstring arguments = Widen(RenderWin32CommandLine(tail));
  std::wstring command = L"\"" + image + L"\"";
  if (!arguments.empty()) {
    command += L" " + arguments;
  }
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');

  SECURITY_ATTRIBUTES inheritable = {};
  inheritable.nLength = sizeof(inheritable);
  inheritable.bInheritHandle = TRUE;
  HANDLE null_device =
      CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  &inheritable, OPEN_EXISTING, 0, nullptr);
  if (null_device == INVALID_HANDLE_VALUE) {
    *error = "Unable to open the null device for a posture command.";
    return false;
  }

  // B-03 (Daybreak audit, 2026-08-28): inherit EXACTLY the null device and
  // nothing else. This process is a multithreaded LocalSystem service, and
  // plain STARTUPINFO + bInheritHandles=TRUE inherits every inheritable
  // handle in the process at create time -- including engine pipe endpoints
  // another thread marked inheritable in its own launch window. An
  // inherited engine writer can delay netsh's teardown past its own exit;
  // an inherited reader hands control-channel bytes to a child that must
  // never see them. The explicit PROC_THREAD_ATTRIBUTE_HANDLE_LIST (the
  // same pattern the engine launch uses) closes the window: the kernel
  // transfers only the listed handles.
  HANDLE inherited[1] = {null_device};
  SIZE_T attribute_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_size);
  std::vector<uint8_t> attribute_storage(attribute_size);
  LPPROC_THREAD_ATTRIBUTE_LIST attributes =
      reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_storage.data());
  const bool attributes_ready =
      attribute_size != 0 &&
      InitializeProcThreadAttributeList(attributes, 1, 0, &attribute_size) !=
          FALSE &&
      UpdateProcThreadAttribute(attributes, 0,
                                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited,
                                sizeof(inherited), nullptr, nullptr) != FALSE;

  STARTUPINFOEXW startup = {};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = nullptr;
  startup.StartupInfo.hStdOutput = null_device;
  // netsh's own output is discarded on purpose. It echoes the arguments, and
  // the arguments carry the user's inner address.
  startup.StartupInfo.hStdError = null_device;
  startup.lpAttributeList = attributes;

  PROCESS_INFORMATION process = {};
  const bool created =
      attributes_ready &&
      CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                     nullptr, &startup.StartupInfo, &process) != FALSE;
  if (attributes_ready) {
    DeleteProcThreadAttributeList(attributes);
  }
  CloseHandle(null_device);
  if (!created) {
    *error = "Unable to run a Winn Protocol v3 posture command.";
    return false;
  }
  const DWORD waited = WaitForSingleObject(process.hProcess, kNetshTimeoutMs);
  DWORD exit_code = 1;
  if (waited != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, 1);
    WaitForSingleObject(process.hProcess, kChildStopWaitMs);
  } else {
    GetExitCodeProcess(process.hProcess, &exit_code);
  }
  CloseHandle(process.hProcess);
  CloseHandle(process.hThread);
  if (waited != WAIT_OBJECT_0 || exit_code != 0) {
    // The command is NOT quoted into the message. It carries the inner address.
    *error =
        "A Winn Protocol v3 posture command failed, so the tunnel was stopped "
        "rather than left in a partly-applied posture.";
    return false;
  }
  return true;
}

// ApplyPosture runs a whole plan.
//
// It stops at the FIRST failure and reports it. A partly-applied posture is the
// one outcome that must not be treated as success: half a bootstrap posture is
// an interface with an address and no MTU, and half a promoted posture is a
// default route with no resolver.
bool ApplyPosture(const std::string& interface_name, const PosturePlan& plan,
                  std::string* error) {
  const std::vector<std::vector<std::string>> commands =
      RenderWindowsPostureCommands(interface_name, plan);
  if (commands.empty()) {
    *error = "The Winn Protocol v3 posture rendered no commands at all.";
    return false;
  }
  for (const std::vector<std::string>& command : commands) {
    if (!RunNetsh(command, error)) {
      return false;
    }
  }
  return true;
}

// ApplyPostureDelta runs a PROMOTED posture as a delta from the bootstrap.
//
// A promoted posture is the bootstrap plus its widenings, so re-rendering it
// whole re-issues the bootstrap's `add route <next-hop>` (and its `set
// address`, `set subinterface`), and the second `add route` against an
// interface that already holds the route answers "The object already exists."
// with a non-zero exit. ApplyPosture stops at the first failing command, so a
// promoted apply would fail on its very first command -- before the IPv6 sink
// or any default route moved -- and the tunnel would report carrying while the
// host never widens, leaving host IPv6 on the physical interface. The Linux
// host already closes this by executing only the delta; this is the same fix
// for the Windows applier.
//
// The delta is also the honest input for the capture check: the terms that
// were already applied at bootstrap are filtered away BEFORE capture is asked,
// so the check is about what will actually run.
bool ApplyPostureDelta(const std::string& interface_name,
                       const PosturePlan& promoted,
                       const PosturePlan& bootstrap, std::string* error) {
  const std::vector<std::vector<std::string>> already =
      RenderWindowsPostureCommands(interface_name, bootstrap);
  const std::vector<std::vector<std::string>> delta = PromotedCommandDelta(
      RenderWindowsPostureCommands(interface_name, promoted), already);
  if (!VerifyPromotedCommandsCapture(delta, error)) {
    return false;
  }
  for (const std::vector<std::string>& command : delta) {
    if (!RunNetsh(command, error)) {
      return false;
    }
  }
  return true;
}

// --- the profile document on disk --------------------------------------------

// WriteProfile writes the -winn3-profile document with a DACL that admits only
// SYSTEM and Administrators.
//
// The document holds NO KEY MATERIAL -- only paths -- but it names the
// gateway, and the paths it names are the paths to the keys. A world-readable
// copy of it is a map.
bool WriteProfile(const std::wstring& path, const std::string& json,
                  std::string* error) {
  SECURITY_ATTRIBUTES attributes = {};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = FALSE;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kWinn3FileSddl, SDDL_REVISION_1, &descriptor, nullptr) == FALSE) {
    *error = "Unable to build the Winn Protocol v3 profile's access control.";
    return false;
  }
  attributes.lpSecurityDescriptor = descriptor;
  // B2-1 (Claude audit, 2026-08-28): delete-then-CREATE_NEW, both reparse
  // aware. The old CREATE_ALWAYS had two holes: on a pre-existing file the
  // supplied SECURITY_ATTRIBUTES are IGNORED (the existing DACL and owner
  // survive -- a standard user who pre-created the name kept a readable
  // copy of the LocalSystem-written static key), and without
  // FILE_FLAG_OPEN_REPARSE_POINT a symlink or junction planted at the name
  // was followed, redirecting the privileged write to a victim path.
  // DeleteFileW removes a reparse point ITSELF (never follows it); a fresh
  // CREATE_NEW with the flag and an explicit SYSTEM/Admin-only DACL then
  // lands a new regular file whose custody nobody but this service shaped.
  DeleteFileW(path.c_str());
  const HANDLE file =
      CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                  nullptr);
  LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE) {
    *error = "Unable to write the Winn Protocol v3 profile.";
    return false;
  }
  DWORD written = 0;
  const bool ok =
      WriteFile(file, json.data(), static_cast<DWORD>(json.size()), &written,
                nullptr) != FALSE &&
      written == json.size() && FlushFileBuffers(file) != FALSE;
  CloseHandle(file);
  if (!ok) {
    DeleteFileW(path.c_str());
    *error = "Unable to write the Winn Protocol v3 profile.";
    return false;
  }
  return true;
}

// B2-1 (Claude audit, 2026-08-28): %ProgramData%\WinsVPN used to be created
// with a NULL security attributes pointer, inheriting ProgramData's default
// ACL -- under which a standard user can pre-create the directory and OWN
// it, then read everything LocalSystem later writes into it (including
// static.key) or plant junctions the writes follow. The directory is now
// created with one explicit owner/DACL, and a pre-existing directory is
// VERIFIED against those exact owner and ACL bytes. Exact equality makes every
// extra ACE type, generic right, WRITE_OWNER grant, malformed ACL, and parsing
// failure a mismatch without maintaining a second access-right interpreter.
bool EnsureWinn3ProtectedDirectory(const std::wstring& directory,
                                   std::string* error) {
  SECURITY_ATTRIBUTES attributes = {};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = FALSE;
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
          kWinn3DirectorySddl, SDDL_REVISION_1, &descriptor, nullptr) ==
      FALSE) {
    *error = "Unable to build the Winn Protocol v3 key directory's access control.";
    return false;
  }
  attributes.lpSecurityDescriptor = descriptor;
  const BOOL created = CreateDirectoryW(directory.c_str(), &attributes);
  const DWORD create_error = created ? ERROR_SUCCESS : GetLastError();
  if (!created && create_error != ERROR_ALREADY_EXISTS) {
    LocalFree(descriptor);
    *error = "Unable to create the Winn Protocol v3 key directory.";
    return false;
  }
  // Verify fresh and pre-existing directories before any key byte is written.
  const HANDLE directory_handle =
      CreateFileW(directory.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING,
                  FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                  nullptr);
  if (directory_handle == INVALID_HANDLE_VALUE) {
    LocalFree(descriptor);
    *error = "The Winn Protocol v3 key directory exists but cannot be inspected.";
    return false;
  }
  std::string failure;
  BY_HANDLE_FILE_INFORMATION info = {};
  if (GetFileInformationByHandle(directory_handle, &info) == FALSE ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    failure = "is a reparse point (junction/symlink), not a real directory";
  }
  if (failure.empty()) {
    PSECURITY_DESCRIPTOR existing = nullptr;
    if (GetSecurityInfo(directory_handle, SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, nullptr, nullptr,
                        &existing) != ERROR_SUCCESS) {
      failure = "cannot be verified (security descriptor unreadable)";
    } else {
      PSID existing_owner = nullptr;
      PSID expected_owner = nullptr;
      BOOL existing_owner_defaulted = FALSE;
      BOOL expected_owner_defaulted = FALSE;
      PACL existing_dacl = nullptr;
      PACL expected_dacl = nullptr;
      BOOL existing_dacl_present = FALSE;
      BOOL expected_dacl_present = FALSE;
      BOOL existing_dacl_defaulted = FALSE;
      BOOL expected_dacl_defaulted = FALSE;
      SECURITY_DESCRIPTOR_CONTROL control = 0;
      DWORD revision = 0;
      ACL_SIZE_INFORMATION existing_acl_info = {};
      ACL_SIZE_INFORMATION expected_acl_info = {};
      const bool exact =
          IsValidSecurityDescriptor(existing) != FALSE &&
          IsValidSecurityDescriptor(descriptor) != FALSE &&
          GetSecurityDescriptorOwner(existing, &existing_owner,
                                     &existing_owner_defaulted) != FALSE &&
          GetSecurityDescriptorOwner(descriptor, &expected_owner,
                                     &expected_owner_defaulted) != FALSE &&
          existing_owner != nullptr && expected_owner != nullptr &&
          EqualSid(existing_owner, expected_owner) != FALSE &&
          GetSecurityDescriptorControl(existing, &control, &revision) != FALSE &&
          (control & SE_DACL_PROTECTED) != 0 &&
          GetSecurityDescriptorDacl(existing, &existing_dacl_present,
                                    &existing_dacl,
                                    &existing_dacl_defaulted) != FALSE &&
          GetSecurityDescriptorDacl(descriptor, &expected_dacl_present,
                                    &expected_dacl,
                                    &expected_dacl_defaulted) != FALSE &&
          existing_dacl_present != FALSE && expected_dacl_present != FALSE &&
          existing_dacl != nullptr && expected_dacl != nullptr &&
          IsValidAcl(existing_dacl) != FALSE &&
          IsValidAcl(expected_dacl) != FALSE &&
          GetAclInformation(existing_dacl, &existing_acl_info,
                            sizeof(existing_acl_info), AclSizeInformation) !=
              FALSE &&
          GetAclInformation(expected_dacl, &expected_acl_info,
                            sizeof(expected_acl_info), AclSizeInformation) !=
              FALSE &&
          existing_acl_info.AclBytesInUse == expected_acl_info.AclBytesInUse &&
          std::memcmp(existing_dacl, expected_dacl,
                      expected_acl_info.AclBytesInUse) == 0;
      if (!exact) {
        failure = "does not match the canonical protected owner and DACL";
      }
      LocalFree(existing);
    }
  }
  CloseHandle(directory_handle);
  LocalFree(descriptor);
  if (!failure.empty()) {
    *error = "The Winn Protocol v3 key directory " + failure +
             ". Delete it (from an elevated shell) and start the tunnel again.";
    return false;
  }
  return true;
}

std::wstring Winn3ProfilePath() {
  wchar_t buffer[MAX_PATH] = {};
  const DWORD length =
      GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return std::wstring();
  }
  const std::wstring directory =
      std::wstring(buffer, length) + L"\\WinsVPN";
  return directory + L"\\winn3-host.json";
}

std::string Winn3KeyDirectoryUtf8() {
  char buffer[MAX_PATH] = {};
  const DWORD length =
      GetEnvironmentVariableA("ProgramData", buffer, MAX_PATH);
  if (length == 0 || length >= MAX_PATH) {
    return std::string();
  }
  return std::string(buffer, length) + "\\WinsVPN";
}

bool WriteServedWinn3KeyFiles(const Winn3HostConfig& config,
                              const std::string& directory,
                              std::vector<std::wstring>* working_paths,
                              std::string* error) {
  if (working_paths == nullptr) {
    *error = "No Winn Protocol v3 working-file ledger was provided.";
    return false;
  }
  std::vector<Winn3KeyFile> files;
  if (!Winn3KeyFilesFor(config, &files, error)) {
    return false;
  }
  // B2-1: custody is verified (or created protected) BEFORE any key byte
  // is written -- a pre-created user-owned directory can no longer receive
  // the LocalSystem-written static key.
  if (!EnsureWinn3ProtectedDirectory(Widen(directory), error)) {
    return false;
  }
  for (const Winn3KeyFile& file : files) {
    const std::wstring path = Widen(directory + "\\" + file.name);
    working_paths->push_back(path);
    if (!WriteProfile(path, file.contents, error)) {
      return false;
    }
  }
  if (supervisor_detail::Trim(config.auth_ed25519_b64).empty() &&
      supervisor_detail::Trim(config.auth_mldsa65_b64).empty()) {
    DeleteFileW(Widen(directory + "\\" + kDualAuthEd25519File).c_str());
    DeleteFileW(Widen(directory + "\\" + kDualAuthMldsa65File).c_str());
  }
  return true;
}

// --- the pre-flight sizing query ---------------------------------------------

// ReadPublishedInnerMtu runs `-winn3-print-sizing` and reads the number.
//
// This is why the adapter is never built from a constant. The mode computes the
// plan floor from the profile and EXITS -- no socket, no key read, no gateway
// contacted -- so the authoritative inner MTU is known before anything touches
// the network, and a profile that would have produced the wrong one is refused
// while the cost of refusing is a retry rather than a broken tunnel.
bool ReadPublishedInnerMtu(const std::wstring& engine,
                           const std::wstring& profile_path,
                           EngineStatus* sizing, std::string* error) {
  ChildProcess child;
  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (job == nullptr ||
      SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                              sizeof(limits)) == FALSE) {
    if (job != nullptr) CloseHandle(job);
    *error = "Unable to bound the Winn Protocol v3 sizing query.";
    return false;
  }
  const std::wstring arguments =
      L"-winn3-profile \"" + profile_path + L"\" -winn3-print-sizing";
  if (!LaunchChild(engine, arguments, job, false, &child, error)) {
    CloseHandle(job);
    return false;
  }

  PipeLineReader reader(child.stdout_read);
  std::string line;
  bool parsed = false;
  const ULONGLONG deadline = GetTickCount64() + kPrintSizingTimeoutMs;
  while (reader.NextLineBefore(&line, deadline)) {
    if (ParseWinn3StatusLine(line, sizing)) {
      parsed = true;
      break;
    }
  }
  // Closing the job kills the child whether it exited or not. The sizing mode
  // exits on its own; the job is what makes "it did not" bounded.
  WaitForSingleObject(child.info.hProcess, kPrintSizingTimeoutMs);
  CloseHandleIfValid(&child.stdin_write);
  CloseHandleIfValid(&child.stdout_read);
  CloseHandleIfValid(&child.stderr_read);
  if (child.info.hProcess != nullptr) CloseHandle(child.info.hProcess);
  CloseHandle(job);

  if (!parsed) {
    *error =
        "The Winn Protocol v3 engine published no usable sizing document, so "
        "the inner MTU the adapter must be built with is unknown. The "
        "connection was stopped rather than started with a guessed MTU.";
    return false;
  }
  return true;
}

// --- teardown ----------------------------------------------------------------

// TeardownLocked stops everything, in the one order that is safe.
//
// The physical /32 pin comes off FIRST, while the engine may still hold its
// socket open. That is deliberate: the pin is the only artefact that outlives
// this process, and a teardown that dies half way should have already removed
// the thing that would otherwise persist. Everything else -- the adapter, its
// address, its MTU and its routes -- goes away structurally when the relay
// dies, because the interface they are installed on ceases to exist.
void TeardownLocked(SupervisorState* state) {
  state->stopping.store(true, std::memory_order_release);
  state->promoted.store(false, std::memory_order_release);

  RemoveOuterSocketPin(state);

  // Closing the relay's stdin is the documented way to ask it to stop: it
  // treats EOF on the control pipe as "the privileged service is gone" and
  // unwinds, because a relay that outlived its supervisor would hold an adapter
  // nobody is configuring and a seam nobody is draining.
  CloseHandleIfValid(&state->relay.stdin_write);

  if (state->job != nullptr) {
    if (state->relay.info.hProcess != nullptr &&
        WaitForSingleObject(state->relay.info.hProcess, kChildStopWaitMs) !=
            WAIT_OBJECT_0) {
      TerminateJobObject(state->job, 1);
    } else {
      TerminateJobObject(state->job, 0);
    }
  }
  if (state->relay.info.hProcess != nullptr) {
    WaitForSingleObject(state->relay.info.hProcess, kChildStopWaitMs);
  }
  if (state->engine.info.hProcess != nullptr) {
    WaitForSingleObject(state->engine.info.hProcess, kChildStopWaitMs);
  }

  // Closing the read ends releases any reader still parked in ReadFile even if
  // a child somehow survived its job.
  CloseHandleIfValid(&state->relay.stdout_read);
  CloseHandleIfValid(&state->relay.stderr_read);
  CloseHandleIfValid(&state->engine.stdout_read);
  CloseHandleIfValid(&state->engine.stderr_read);

  HANDLE readers[3];
  DWORD reader_count = 0;
  if (state->relay_reader != nullptr) readers[reader_count++] = state->relay_reader;
  if (state->engine_stdout_reader != nullptr) {
    readers[reader_count++] = state->engine_stdout_reader;
  }
  if (state->engine_stderr_reader != nullptr) {
    readers[reader_count++] = state->engine_stderr_reader;
  }
  if (reader_count != 0 &&
      WaitForMultipleObjects(reader_count, readers, TRUE,
                             kReaderJoinTimeoutMs) == WAIT_TIMEOUT) {
    // A reader still inside ReadFile means freeing this state would free the
    // buffer it is writing into. There is no safe way to continue in-process,
    // and both children are already dead in their kill-on-close job, so this
    // terminates fail-closed -- the same handling FailClosedPrivilegedTunnel
    // and windows_winn_engine.cpp's TeardownLocked already use for exactly this
    // non-quiescence case.
    TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
    ExitProcess(ERROR_TIMEOUT);
  }
  for (DWORD i = 0; i < reader_count; ++i) {
    CloseHandle(readers[i]);
  }
  state->relay_reader = nullptr;
  state->engine_stdout_reader = nullptr;
  state->engine_stderr_reader = nullptr;

  if (state->relay.info.hProcess != nullptr) {
    CloseHandle(state->relay.info.hProcess);
  }
  if (state->engine.info.hProcess != nullptr) {
    CloseHandle(state->engine.info.hProcess);
  }
  state->relay = ChildProcess{};
  state->engine = ChildProcess{};
  if (state->job != nullptr) {
    CloseHandle(state->job);
    state->job = nullptr;
  }
  CloseHandleIfValid(&state->relay_host_port_event);
  CloseHandleIfValid(&state->relay_ready_event);
  CloseHandleIfValid(&state->engine_port_event);
  CloseHandleIfValid(&state->status_event);
  // All consumers are gone. Remove every served-session working file, not
  // only the private pair, so no stale companion can bind a later session.
  for (const std::wstring& path : state->session_working_paths) {
    if (DeleteFileW(path.c_str()) == FALSE &&
        GetLastError() != ERROR_FILE_NOT_FOUND) {
      // A filter driver can transiently retain a just-closed file. Preserve
      // least retention by asking the OS to remove it at the next boot.
      MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
  }
  state->session_working_paths.clear();
  if (!state->profile_path.empty()) {
    DeleteFileW(state->profile_path.c_str());
    state->profile_path.clear();
  }
}

// THE SELF-STARTING PROMOTION PROBE.
//
// The promotion gate is `gate == carrying AND rx_packets > 0`, computed beside
// the engine's own counters, and rx_packets only advances once an inner packet
// arrives from the gateway. Against a reactive gateway nothing sends the first
// inner packet pre-promotion: application traffic waits for native start, the
// engine emits no inner probe, and a quiet host produces none either -- so the
// gate starves while a healthy session carries, and the promotion window times
// out. (Measured on the 2026-08-22 live-test lanes on Linux, identical shape.)
//
// This is the host's own first inner packet: ONE ICMP echo, sourced from the
// session's inner assignment and addressed to the inner next hop. That pairing
// is what keeps the /32 containment intact: the bootstrap posture routes
// exactly ONE address, the inner next hop's /32, so the echo can only enter
// the tunnel and can never escape onto the physical default route -- and the
// v3 reflector answers IPv4 addressed to its own assignment, which is the
// inner next hop, so the reflected echo satisfies rx_packets > 0 without
// widening anything. The caller bounds it (interval + attempt cap) and treats
// it as advisory: promotion still decides exclusively from the engine's own
// proof, and the window still fails closed when nothing comes back.
bool SendInnerPromotionProbe(const Winn3HostConfig& config, std::string* note) {
  IN_ADDR parsed_source = {};
  IN_ADDR parsed_target = {};
  if (config.inner_v4.empty() ||
      InetPtonA(AF_INET, config.inner_v4.c_str(), &parsed_source) != 1) {
    if (note != nullptr) {
      *note = "no inner IPv4 assignment to source the promotion probe from";
    }
    return false;
  }
  if (config.router_v4.empty() ||
      InetPtonA(AF_INET, config.router_v4.c_str(), &parsed_target) != 1) {
    if (note != nullptr) {
      *note = "no inner IPv4 next hop to address the promotion probe to";
    }
    return false;
  }
  const IPAddr target = parsed_target.S_un.S_addr;
  // THE COLLISION GUARDS.
  //
  // The echo's route is chosen by the OS here (IcmpSendEcho2 takes a
  // destination only), so this host must itself refuse the two targets whose
  // route could leave the machine instead of entering the tunnel:
  //
  //   1. The carrier endpoint. Its /32 is pinned to the PHYSICAL interface by
  //      InstallOuterSocketPin, while the bootstrap posture routes ONLY the
  //      inner next hop's /32 through the relay adapter. A signed descriptor
  //      that ever set inner_router_v4 equal to the endpoint address would make
  //      both pins describe one destination, and whichever the OS chose, up to
  //      four zero-payload echoes could leave the physical NIC on the censored
  //      path. Linux already fails closed on this; this host must too.
  //   2. This host's own inner_v4. Addressed to this device, the echo would
  //      never reach the gateway to be reflected, and nothing about it would
  //      be a probe.
  std::string endpoint_host;
  IN_ADDR parsed_endpoint = {};
  if (SplitWinn3Endpoint(config.endpoint, &endpoint_host, nullptr) &&
      InetPtonA(AF_INET, endpoint_host.c_str(), &parsed_endpoint) == 1 &&
      parsed_endpoint.S_un.S_addr == target) {
    if (note != nullptr) {
      *note = "the promotion probe's inner next hop (" + config.router_v4 +
              ") is the carrier endpoint's own address (" + endpoint_host +
              "); the endpoint's /32 is pinned to the physical interface, so " +
              "the echo could leave the machine on the censored path instead " +
              "of entering the tunnel. Refusing to send.";
    }
    return false;
  }
  if (parsed_source.S_un.S_addr == target) {
    if (note != nullptr) {
      *note = "the promotion probe's inner next hop (" + config.router_v4 +
              ") is this host's own inner_v4 assignment (" + config.inner_v4 +
              "); an echo addressed to this device would not reach the gateway." +
              " Refusing to send.";
    }
    return false;
  }
  const HANDLE icmp = IcmpCreateFile();
  if (icmp == INVALID_HANDLE_VALUE) {
    if (note != nullptr) {
      *note = "IcmpCreateFile failed (error " +
              std::to_string(GetLastError()) + ")";
    }
    return false;
  }
  // The SDK's OneCore IcmpSendEcho2 takes the destination only: the source is
  // chosen by the OS from the route the echo takes, and the bootstrap posture
  // routes exactly the inner next hop's /32 through the relay adapter, whose
  // ONLY IPv4 address is this session's inner assignment. The echo therefore
  // leaves sourced from the inner address the engine's validator requires.
  IP_OPTION_INFORMATION options = {};
  options.Ttl = 64;
  constexpr DWORD kReplyBytes = sizeof(ICMP_ECHO_REPLY) + 8;
  uint8_t reply_buffer[kReplyBytes] = {};
  const DWORD replies =
      IcmpSendEcho2(icmp, nullptr, nullptr, nullptr, target, nullptr, 0,
                    &options, reply_buffer, kReplyBytes, 1000);
  IcmpCloseHandle(icmp);
  if (replies == 0) {
    if (note != nullptr) {
      *note = "the promotion ICMP echo was not sent (error " +
              std::to_string(GetLastError()) + ")";
    }
    return false;
  }
  return true;
}

}  // namespace

// --- the staged start --------------------------------------------------------

bool StartWindowsWinn3Tunnel(const Winn3HostConfig& config,
                             std::string* error) {
  if (error == nullptr) {
    return false;
  }
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  if (g_state != nullptr) {
    *error = "A Winn Protocol v3 tunnel is already running.";
    return false;
  }

  const std::wstring relay_image = FindWinn3RelayExecutable();
  const std::wstring engine_image = FindWinn3DatapathExecutable();
  if (relay_image.empty()) {
    *error =
        "This server uses Winn Protocol v3, but the v3 tun relay is not "
        "installed beside this application, so the connection was stopped "
        "rather than started over a different transport.";
    return false;
  }
  if (engine_image.empty()) {
    *error =
        "This server uses Winn Protocol v3, but the Winn datapath engine is "
        "not installed beside this application, so the connection was stopped "
        "rather than started over a different transport.";
    return false;
  }

  std::unique_ptr<SupervisorState> state(new SupervisorState());
  const auto fail = [&](const std::string& message) {
    *error = message;
    TeardownLocked(state.get());
    return false;
  };

  state->relay_host_port_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  state->relay_ready_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  state->engine_port_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  state->status_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
  state->job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (state->relay_host_port_event == nullptr ||
      state->relay_ready_event == nullptr ||
      state->engine_port_event == nullptr || state->status_event == nullptr ||
      state->job == nullptr ||
      SetInformationJobObject(state->job, JobObjectExtendedLimitInformation,
                              &limits, sizeof(limits)) == FALSE) {
    return fail("Unable to create the Winn Protocol v3 lifetime boundary.");
  }

  // STEP 1. The relay binds 127.0.0.1:0 before anything else exists and prints
  // its port. Binding first means the engine's first inner packets queue in a
  // receive buffer instead of drawing ICMP port-unreachable while the relay is
  // still creating an adapter. It takes NO arguments, ever: windows/awg_engine
  // refuses to start with any, and this one keeps that property so that a
  // confused caller cannot point it somewhere.
  if (!LaunchChild(relay_image, std::wstring(), state->job, true, &state->relay,
                   error)) {
    const std::string message = *error;
    return fail(message);
  }
  state->relay_reader =
      CreateThread(nullptr, 0, RelayReaderThread, state.get(), 0, nullptr);
  if (state->relay_reader == nullptr) {
    return fail("Unable to read from the Winn Protocol v3 relay.");
  }
  if (WaitForSingleObject(state->relay_host_port_event,
                          kRelayHostPortTimeoutMs) != WAIT_OBJECT_0 ||
      state->relay_host_port.load(std::memory_order_acquire) == 0) {
    return fail(
        "The Winn Protocol v3 relay did not report its loopback seam port. It "
        "runs as LocalSystem and refuses a second instance, so a relay that "
        "exits immediately is either not running with those privileges or is "
        "already running for another tunnel.");
  }
  const int host_port = state->relay_host_port.load(std::memory_order_acquire);

  // STEP 2. The exclusion goes in BEFORE the profile that claims it, and before
  // any tunnel route can exist. allow_own_socket without an installed exclusion
  // is a carrier that loops into the tunnel it carries.
  if (!InstallOuterSocketPin(config.endpoint, state.get(), error)) {
    const std::string message = *error;
    return fail(message);
  }
  state->profile_path = Winn3ProfilePath();
  if (state->profile_path.empty()) {
    return fail("Unable to locate the ProgramData directory.");
  }
  Winn3HostConfig session_config = config;
  if (config.section == "winn") {
    const std::string key_directory = Winn3KeyDirectoryUtf8();
    if (key_directory.empty()) {
      return fail("Unable to locate the ProgramData directory.");
    }
    if (!WriteServedWinn3KeyFiles(config, key_directory,
                                  &state->session_working_paths, error)) {
      const std::string message = *error;
      return fail(message);
    }
    session_config = Winn3ConfigWithKeyPaths(config, key_directory);
  }
  const std::string profile_json = BuildWinn3ProfileJson(
      session_config, host_port, state->exclusion_description);
  // B2-1: the profile's parent directory gets the same custody check the
  // key directory does (they are the same directory; this also covers the
  // non-key session shapes, which never call WriteServedWinn3KeyFiles).
  {
    const std::size_t separator = state->profile_path.find_last_of(L"\\/");
    const std::wstring profile_directory =
        separator == std::wstring::npos
            ? std::wstring()
            : state->profile_path.substr(0, separator);
    if (profile_directory.empty() ||
        !EnsureWinn3ProtectedDirectory(profile_directory, error)) {
      const std::string message = *error;
      return fail(message);
    }
  }
  if (!WriteProfile(state->profile_path, profile_json, error)) {
    const std::string message = *error;
    return fail(message);
  }

  // STEP 3. The authoritative inner MTU, with nothing yet touching the network.
  EngineStatus sizing;
  if (!ReadPublishedInnerMtu(engine_image, state->profile_path, &sizing,
                             error)) {
    const std::string message = *error;
    return fail(message);
  }
  if (!VerifyPublishedInnerMtu(sizing.inner_mtu, error)) {
    const std::string message = *error;
    return fail(message);
  }
  state->applied_mtu = sizing.inner_mtu;

  // STEP 4. The engine. It prints its own seam port on stderr, which is where
  // it has to be: the relay needs it before the first status line in order to
  // finish wiring its half of the seam.
  const std::wstring engine_arguments =
      L"-winn3-profile \"" + state->profile_path + L"\"";
  if (!LaunchChild(engine_image, engine_arguments, state->job, false,
                   &state->engine, error)) {
    const std::string message = *error;
    return fail(message);
  }
  state->engine_stdout_reader =
      CreateThread(nullptr, 0, EngineStdoutThread, state.get(), 0, nullptr);
  state->engine_stderr_reader =
      CreateThread(nullptr, 0, EngineStderrThread, state.get(), 0, nullptr);
  if (state->engine_stdout_reader == nullptr ||
      state->engine_stderr_reader == nullptr) {
    return fail("Unable to read from the Winn Protocol v3 engine.");
  }
  if (WaitForSingleObject(state->engine_port_event, kEngineSeamPortTimeoutMs) !=
          WAIT_OBJECT_0 ||
      state->engine_seam_port.load(std::memory_order_acquire) == 0) {
    return fail(
        "The Winn Protocol v3 engine did not report its loopback seam port, "
        "so the relay was never told where to send inner packets and no "
        "adapter was created.");
  }

  // STEP 5. The one control line the relay accepts. Until this arrives THERE IS
  // NO ADAPTER -- which is the property this whole ordering exists for: Windows
  // never has an interface it might route traffic to before the layer that
  // encrypts is reachable.
  const std::string start_command = RenderStartCommand(
      state->applied_mtu,
      state->engine_seam_port.load(std::memory_order_acquire));
  DWORD written = 0;
  if (WriteFile(state->relay.stdin_write, start_command.data(),
                static_cast<DWORD>(start_command.size()), &written,
                nullptr) == FALSE ||
      written != start_command.size()) {
    return fail("Unable to start the Winn Protocol v3 tun relay.");
  }

  // STEP 6. The adapter exists from here.
  if (WaitForSingleObject(state->relay_ready_event, kRelayReadyTimeoutMs) !=
      WAIT_OBJECT_0) {
    return fail(
        "The Winn Protocol v3 relay did not create its Wintun adapter. It "
        "refuses to create one at all until the layer that encrypts is "
        "reachable, so nothing was left half-configured.");
  }
  Winn3RelayReady ready;
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    ready = state->ready;
  }
  if (ready.name.empty()) {
    return fail("The Winn Protocol v3 relay reported no adapter.");
  }
  if (ready.name != kRelayAdapterName) {
    // The winn/1 adapter is "winsvpn" and carries AmneziaWG outer datagrams
    // that are already encrypted. Installing a v3 posture on it would point an
    // inner-packet datapath at an interface owned by a different protocol.
    return fail(
        "The Winn Protocol v3 relay reported an unexpected adapter name, so "
        "the posture was not installed on it.");
  }
  if (ready.mtu != state->applied_mtu) {
    return fail(
        "The Winn Protocol v3 relay built its adapter with an MTU other than "
        "the one the engine published, so the tunnel was stopped rather than "
        "left to black hole every full-size flow.");
  }

  // STEP 7. THE BOOTSTRAP POSTURE. One /32, the inner next hop only, the
  // engine's MTU, no default route, no IPv6, no DNS -- and the exclusion is
  // already in place. Built by winn3_posture.h, re-checked by
  // VerifyBootstrapIsNarrow rather than trusted, and only then executed.
  EngineStatus first_status;
  if (WaitForSingleObject(state->status_event, kFirstStatusTimeoutMs) !=
      WAIT_OBJECT_0) {
    return fail(
        "The Winn Protocol v3 engine published no status document, so the "
        "inner MTU to apply to the adapter could not be confirmed.");
  }
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    first_status = state->last_status;
  }
  if (!VerifyAppliedMtuStillAgrees(state->applied_mtu, first_status, error)) {
    const std::string message = *error;
    return fail(message);
  }

  const PostureInput input =
      PostureInputFrom(config, state->exclusion_description, first_status);
  PosturePlan bootstrap;
  if (!BuildBootstrapPosture(input, first_status, &bootstrap, error) ||
      !VerifyBootstrapIsNarrow(bootstrap, error)) {
    const std::string message = *error;
    return fail(message);
  }
  if (!ApplyPosture(ready.name, bootstrap, error)) {
    const std::string message = *error;
    return fail(message);
  }

  // STEP 8. PROMOTION, and only on the engine's own proof. `promotion_ready` is
  // computed once, in Go, beside the counters: the gate is carrying AND an
  // inner packet has been validated and written to the host device. This host
  // does not recompute it, because two hosts recomputing it would eventually
  // compute it two different ways -- the classic slip being RxOffered for
  // RxPackets, which is "a payload arrived" versus "an inner packet reached the
  // device".
  const ULONGLONG deadline = GetTickCount64() + kPromotionDeadlineMs;
  std::string reason = "the Winn Protocol v3 datapath was never proven.";
  bool proven = false;
  // The self-starting probe, bounded: at most a handful of one-second echoes
  // spaced across the promotion window, and only while the gate carries with
  // nothing delivered. kNotYet with the gate open is the starvation shape; a
  // refusal is checked FIRST, above, so nothing is tickled on a session about
  // to be refused.
  constexpr int kMaxPromotionProbes = 4;
  constexpr ULONGLONG kPromotionProbeIntervalMs = 3000;
  ULONGLONG next_probe_at = 0;
  int probes_sent = 0;
  std::string probe_note;
  for (;;) {
    EngineStatus status;
    {
      std::lock_guard<std::mutex> guard(state->status_mutex);
      status = state->last_status;
    }
    const Winn3PromotionVerdict verdict =
        DecideWinn3Promotion(status, state->applied_mtu, &reason);
    if (verdict == Winn3PromotionVerdict::kPromote) {
      proven = true;
      break;
    }
    if (verdict == Winn3PromotionVerdict::kRefuse) {
      return fail("Winn Protocol v3 could not start: " + reason);
    }
    if (!state->relay.Alive() || !state->engine.Alive()) {
      return fail(
          "Winn Protocol v3 could not start: the datapath stopped before it "
          "carried anything.");
    }
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) {
      break;
    }
    if (probes_sent < kMaxPromotionProbes && status.valid &&
        status.gate_state == kCarryingGate && status.rx_packets == 0 &&
        now >= next_probe_at) {
      (void)SendInnerPromotionProbe(config, &probe_note);
      ++probes_sent;
      next_probe_at = now + kPromotionProbeIntervalMs;
    }
    // Waiting on the status event rather than sleeping means the normal case
    // costs one tick of the engine's own one-second status interval.
    WaitForSingleObject(state->status_event,
                        static_cast<DWORD>(deadline - now));
  }
  if (!proven) {
    return fail("Winn Protocol v3 could not start: " + reason);
  }

  EngineStatus proof;
  {
    std::lock_guard<std::mutex> guard(state->status_mutex);
    proof = state->last_status;
  }
  PosturePlan promoted;
  if (!BuildPromotedPosture(PostureInputFrom(config,
                                             state->exclusion_description,
                                             proof),
                            proof, &promoted, error)) {
    const std::string message = *error;
    return fail(message);
  }
  if (!ApplyPostureDelta(ready.name, promoted, bootstrap, error)) {
    const std::string message = *error;
    return fail(message);
  }
  state->promoted.store(true, std::memory_order_release);
  g_state = state.release();
  return true;
}

void StopWindowsWinn3Tunnel() {
  SupervisorState* state = nullptr;
  {
    std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
    state = g_state;
    g_state = nullptr;
    if (state == nullptr) {
      return;
    }
    TeardownLocked(state);
  }
  delete state;
}

bool WindowsWinn3TunnelRunning() {
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  if (g_state == nullptr) {
    return false;
  }
  // BOTH children, deliberately. A relay alive with a dead engine holds an
  // adapter whose seam has nothing beneath it: it carries nothing, and
  // reporting that as a working tunnel is the exact failure this project has
  // already been bitten by.
  return g_state->relay.Alive() && g_state->engine.Alive();
}

bool WindowsWinn3TunnelPromoted() {
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  return g_state != nullptr &&
         g_state->promoted.load(std::memory_order_acquire);
}

std::string WindowsWinn3StatusJson() {
  std::lock_guard<std::mutex> lifecycle(g_lifecycle_mutex);
  if (g_state == nullptr) {
    return std::string();
  }
  std::lock_guard<std::mutex> guard(g_state->status_mutex);
  return g_state->last_status_json;
}

}  // namespace winsvpn::winn3

#endif  // WINS_TUNNEL_SERVICE_CORE
