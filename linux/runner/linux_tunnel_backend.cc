#include "linux_tunnel_backend.h"
#include "linux_secure_store.h"
#include "linux_secure_store_async.h"
#include "linux_winn_host.h"
// The STANDALONE Winn Protocol v3 host. A separate translation unit from
// linux_winn_host.h on purpose: that one is the shipping winn/1 AmneziaWG
// relay and this one carries inner IP packets under v3's own handshake. The
// two must never be reachable from one configuration, and StartTunnel below
// branches between them on the carrier before either parser sees the document.
#include "linux_winn3_host.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <net/if.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <dirent.h>
#include <fstream>
#include <limits.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// M-10: expected SHA-256 of the first-party, root-executed
// winsvpn-bypass-bpf helper. Unlike the third-party awg/xray binaries, this
// helper is rebuilt for every release, so no stable literal hash can be
// committed here. The release builder should inject the freshly-built value
// via -DWINSVPN_BPF_HELPER_SHA256='"<hex>"'; when it is absent the runtime
// still refuses to execute the helper out of any bundle directory that is
// not root-owned and non-writable (validate_root_owned_path below), which is
// the M-10 local-privilege-escalation threat.
#ifndef WINSVPN_BPF_HELPER_SHA256
#define WINSVPN_BPF_HELPER_SHA256 ""
#endif

// Global-scope declaration so the anonymous namespace below refers to THE
// environ, not a private one. glibc's <unistd.h> also declares it; a redundant
// compatible declaration is legal.
extern char** environ;

namespace {

constexpr char kChannelName[] = "wins_vpn/tunnel";
constexpr char kTunnelName[] = "winsvpn";
constexpr char kBpfHelperExpectedSha256[] = WINSVPN_BPF_HELPER_SHA256;

FlMethodChannel* g_channel = nullptr;
bool g_linux_split_tunnel_ready = false;
winsvpn::winn3host::Winn3StartProof g_last_winn3_proof;
winsvpn::winn3host::Winn3AwgXrayGrant g_awg_xray_grant;
std::mutex g_winn3_session_mutex;
bool g_last_start_was_winn3 = false;
int64_t g_canceled_winn3_generation_floor = 0;

uint64_t NowMs() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

std::set<std::string> g_linux_excluded_apps;
std::string g_xray_config_path;
// True while the ACTIVE tunnel was started as winn/3. Separate from
// LinuxWinnEngineRunning() on purpose: that answers "is an engine alive", this
// answers "was this tunnel supposed to have one", and it is the difference
// between a healthy AmneziaWG tunnel and a Winn tunnel whose engine has died.
bool g_winn_tunnel_active = false;
bool g_tunnel_session_committed = false;
bool IsTunnelRunning();

// WINN DATAPATH PROGRESS, sampled by IsTunnelRunning on winn/3.
// Mirrors Android's winnDatapathIsCarrying (VpnTunnelService.kt).
// -1 means "no sample yet". Added 2026-08-07 with the health fix.
long long g_winn_last_tx_payload = -1;
long long g_winn_last_rx_payload = -1;
int g_winn_unhealthy_streak = 0;
bool WinnDatapathIsCarrying(const std::string& status);

struct LinuxDesktopApp {
  std::string name;
  std::string desktop_file;
  std::vector<std::string> command;
};

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
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) {
                   return static_cast<char>(std::tolower(c));
                 });
  return value;
}

bool IsSectionHeader(const std::string& line) {
  return line.size() >= 3 && line.front() == '[' && line.back() == ']';
}

std::map<std::string, std::string> ParseSection(
    const std::string& config,
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

bool SectionBool(const std::map<std::string, std::string>& section,
                 const std::string& key) {
  const auto it = section.find(LowerAscii(key));
  if (it == section.end()) {
    return false;
  }
  const std::string value = LowerAscii(Trim(it->second));
  return value == "true" || value == "1" || value == "yes" || value == "on";
}

std::string SectionValue(const std::map<std::string, std::string>& section,
                         const std::string& key,
                         const std::string& fallback = "") {
  const auto it = section.find(LowerAscii(key));
  if (it == section.end() || it->second.empty()) {
    return fallback;
  }
  return it->second;
}

bool IsValidPortValue(const std::string& value) {
  if (value.empty() || value.size() > 5) {
    return false;
  }
  unsigned int port = 0;
  for (const unsigned char c : value) {
    if (std::isdigit(c) == 0) {
      return false;
    }
    port = port * 10 + static_cast<unsigned int>(c - '0');
  }
  return port >= 1 && port <= 65535;
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

std::string StripSections(const std::string& config,
                          const std::vector<std::string>& sections) {
  std::vector<std::string> lower_sections;
  for (const std::string& section : sections) {
    lower_sections.push_back(LowerAscii(section));
  }
  std::istringstream stream(config);
  std::ostringstream out;
  std::string line;
  bool skip = false;
  while (std::getline(stream, line)) {
    const std::string trimmed = Trim(line);
    if (IsSectionHeader(trimmed)) {
      const std::string current =
          LowerAscii(trimmed.substr(1, trimmed.size() - 2));
      skip = std::find(lower_sections.begin(), lower_sections.end(), current) !=
             lower_sections.end();
    }
    if (!skip) {
      out << line << '\n';
    }
  }
  return out.str();
}

bool HostIpv6Disabled() {
  for (const char* path : {"/proc/sys/net/ipv6/conf/all/disable_ipv6",
                           "/proc/sys/net/ipv6/conf/default/disable_ipv6"}) {
    std::ifstream file(path);
    std::string value;
    if (file && std::getline(file, value) && Trim(value) == "1") {
      return true;
    }
  }
  return access("/proc/net/if_inet6", F_OK) != 0;
}

std::string RemoveIpv6AllowedIps(const std::string& config) {
  std::istringstream stream(config);
  std::ostringstream out;
  std::string line;
  while (std::getline(stream, line)) {
    const size_t equals = line.find('=');
    if (equals == std::string::npos ||
        LowerAscii(Trim(line.substr(0, equals))) != "allowedips") {
      out << line << '\n';
      continue;
    }
    std::istringstream values(line.substr(equals + 1));
    std::vector<std::string> ipv4_values;
    std::string value;
    while (std::getline(values, value, ',')) {
      value = Trim(value);
      if (!value.empty() && value.find(':') == std::string::npos) {
        ipv4_values.push_back(value);
      }
    }
    if (ipv4_values.empty()) continue;
    out << line.substr(0, equals) << "= ";
    for (size_t index = 0; index < ipv4_values.size(); ++index) {
      if (index > 0) out << ", ";
      out << ipv4_values[index];
    }
    out << '\n';
  }
  return out.str();
}

// ---------------------------------------------------------------------------
// PROCESS EXECUTION (B-APP-004 hardening, 2026-08-28).
//
// Two primitives, one rule: a shell may appear ONLY around a compile-time-
// constant script body, and every dynamic value crosses as a real argv entry.
// Nothing composes a command STRING that a shell later parses, so a quoting
// mistake cannot become code execution in any context -- least of all the
// root contexts below. RunArgv never invokes a shell at all; RunShScript
// allows one only for a literal script (PATH resolution, pipelines) whose
// body is a C++ string constant.
// ---------------------------------------------------------------------------

enum class ProcOutput {
  kInherit,   // the child shares this process's stdout and stderr
  kSuppress,  // both streams go to /dev/null
  kCapture,   // both streams merge into one pipe the caller reads
};

struct ProcResult {
  // -1 spawn/wait failed; 124 timeout; otherwise exit code or 128+signal.
  int exit_status = -1;
  std::string output;  // kCapture only
};

// Executes argv (argv[0] included, absolute path expected) with no shell
// anywhere in the loop: posix_spawn(3) with an explicit argument vector.
//
// F-08/F-10/F-11 (final audit 2026-08-28): read() and waitpid() are retried
// on EINTR (a signal arriving mid-capture used to truncate the output and
// strand an unreaped child with exit 141); the capture pipe is created with
// pipe2(O_CLOEXEC) so no other thread's fork+exec can race a leaked
// descriptor into a grandchild between pipe() and spawn(); and every
// posix_spawn_file_actions_* return code is checked so a failed action setup
// reports a spawn failure instead of spawning with partial plumbing.
ProcResult RunArgv(
    const std::vector<std::string>& argv, ProcOutput mode,
    std::chrono::milliseconds timeout = std::chrono::seconds(15)) {
  ProcResult result;
  if (argv.empty() || argv[0].empty() || timeout.count() <= 0) {
    return result;
  }
  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& argument : argv) {
    raw.push_back(const_cast<char*>(argument.c_str()));
  }
  raw.push_back(nullptr);

  posix_spawn_file_actions_t actions;
  const bool actions_initialized =
      posix_spawn_file_actions_init(&actions) == 0;
  posix_spawnattr_t attributes;
  const bool attributes_initialized = posix_spawnattr_init(&attributes) == 0;
  bool actions_ok = actions_initialized && attributes_initialized;
  if (actions_ok) {
    // Set the group before exec, without a parent/child setpgid race.
    actions_ok =
        posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP) == 0 &&
        posix_spawnattr_setpgroup(&attributes, 0) == 0;
  }
  bool spawned = false;
  bool capture_overflow = false;
  bool timed_out = false;
  constexpr size_t kMaxCapturedBytes = 1024 * 1024;
  int devnull_fd = -1;
  int pipe_fds[2] = {-1, -1};
  if (actions_ok && mode == ProcOutput::kSuppress) {
    devnull_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (devnull_fd >= 0) {
      actions_ok &= posix_spawn_file_actions_adddup2(
                        &actions, devnull_fd, STDOUT_FILENO) == 0;
      actions_ok &= posix_spawn_file_actions_adddup2(
                        &actions, devnull_fd, STDERR_FILENO) == 0;
    } else {
      actions_ok = false;
    }
  } else if (actions_ok && mode == ProcOutput::kCapture) {
#if defined(__linux__) || defined(__APPLE__)
    // F-10: pipe2(O_CLOEXEC) is atomic. A plain pipe() left a window in this
    // multithreaded process where another thread's fork+exec inherited the
    // capture descriptors; close-on-exec closes that window by construction.
    if (pipe2(pipe_fds, O_CLOEXEC) == 0) {
#else
    if (pipe(pipe_fds) == 0) {
#endif
      // Only the reader is nonblocking; helpers retain blocking stdout/stderr.
      const int flags = fcntl(pipe_fds[0], F_GETFL, 0);
      actions_ok = flags >= 0 &&
          fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK) == 0;
      actions_ok &= posix_spawn_file_actions_adddup2(
                        &actions, pipe_fds[1], STDOUT_FILENO) == 0;
      actions_ok &= posix_spawn_file_actions_adddup2(
                        &actions, pipe_fds[1], STDERR_FILENO) == 0;
      actions_ok &=
          posix_spawn_file_actions_addclose(&actions, pipe_fds[0]) == 0;
      actions_ok &=
          posix_spawn_file_actions_addclose(&actions, pipe_fds[1]) == 0;
    } else {
      actions_ok = false;
    }
  }

  pid_t pid = -1;
  auto deadline = std::chrono::steady_clock::now() + timeout;
  if (actions_ok &&
      posix_spawn(&pid, raw[0], &actions, &attributes, raw.data(),
                  environ) == 0) {
    spawned = true;
  }
  // The parent's copies of the plumbing are closed no matter how the spawn
  // went, so a failed spawn leaks nothing.
  if (pipe_fds[1] >= 0) close(pipe_fds[1]);
  if (spawned) {
    std::array<char, 4096> buffer = {};
    std::string captured;
    int status = 0;
    bool waited = false;
    for (;;) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        if (!timed_out) {
          timed_out = true;
          kill(-pid, SIGTERM);
          deadline = now + std::chrono::seconds(2);
        } else {
          // Keep the leader unreaped throughout the grace period so its PID
          // cannot be reused before this final group signal. Descendants may
          // ignore TERM or close stdout while still running.
          kill(-pid, SIGKILL);
          // A group signal can succeed for a descendant but be denied for
          // an elevated leader. Do not block on a child we cannot signal.
          const int wait_options = kill(pid, SIGKILL) == 0 ? 0 : WNOHANG;
          pid_t waited_pid;
          do {
            waited_pid = waitpid(pid, &status, wait_options);
          } while (waited_pid < 0 && errno == EINTR);
          waited = waited_pid == pid;
          break;
        }
      }

      if (pipe_fds[0] >= 0) {
        const ssize_t read_bytes =
            read(pipe_fds[0], buffer.data(), buffer.size());
        if (read_bytes > 0) {
          const size_t chunk_bytes = static_cast<size_t>(read_bytes);
          if (!capture_overflow &&
              chunk_bytes <= kMaxCapturedBytes - captured.size()) {
            captured.append(buffer.data(), chunk_bytes);
          } else {
            capture_overflow = true;
            captured.clear();
          }
          // Check the deadline after every chunk, even after overflow. An
          // endless writer must not trap us in a drain-until-EAGAIN loop.
          continue;
        }
        if (read_bytes < 0 && errno == EINTR) continue;
        if (read_bytes == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
          close(pipe_fds[0]);
          pipe_fds[0] = -1;
        }
      }

      // Defer reaping while descendants can hold the capture pipe open.
      // EOF alone is insufficient: a quiet child may close both streams
      // and hang. Decode only an exact-child wait, never an ECHILD failure.
      if (pipe_fds[0] < 0 && !timed_out) {
        const pid_t waited_pid = waitpid(pid, &status, WNOHANG);
        if (waited_pid == pid) {
          waited = true;
          break;
        }
        if (waited_pid < 0 && errno != EINTR) break;
      }

      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - std::chrono::steady_clock::now()).count();
      const int wait_ms = static_cast<int>(std::max<int64_t>(
          0, std::min<int64_t>(25, remaining)));
      pollfd descriptor = {pipe_fds[0], POLLIN, 0};
      // EINTR returns to the deadline check instead of restarting a full
      // relative wait. A negative descriptor gives a bounded idle wait.
      if (poll(&descriptor, 1, wait_ms) < 0 && errno != EINTR &&
          pipe_fds[0] >= 0) {
        close(pipe_fds[0]);
        pipe_fds[0] = -1;
      }
    }
    result.output = Trim(captured);
    if (waited) {
      if (WIFEXITED(status)) {
        result.exit_status = WEXITSTATUS(status);
      } else if (WIFSIGNALED(status)) {
        result.exit_status = 128 + WTERMSIG(status);
      } else {
        result.exit_status = 1;
      }
    }
    // !waited leaves exit_status at its -1 default: spawn-succeeded-but-
    // unreaped is a failure, and callers already treat nonzero as failure.
  }
  if (pipe_fds[0] >= 0) close(pipe_fds[0]);
  if (devnull_fd >= 0) close(devnull_fd);
  if (actions_initialized) {
    posix_spawn_file_actions_destroy(&actions);
  }
  if (attributes_initialized) {
    posix_spawnattr_destroy(&attributes);
  }
  if (capture_overflow) {
    result.exit_status = 75;
    result.output.clear();
  }
  if (timed_out) result.exit_status = 124;
  return result;
}

// Runs a COMPILE-TIME-CONSTANT shell script body. The body must be a literal
// (it is executed by /bin/sh); every dynamic value is passed as a parameter
// and reaches the script as $1, $2, ... (name is $0). This is the only form
// in which a shell may see this app's data.
ProcResult RunShScript(const std::string& script, const std::string& name,
                       const std::vector<std::string>& params,
                       ProcOutput mode) {
  std::vector<std::string> argv;
  argv.reserve(params.size() + 4);
  argv.push_back("/bin/sh");
  argv.push_back("-c");
  argv.push_back(script);
  argv.push_back(name);
  for (const std::string& parameter : params) {
    argv.push_back(parameter);
  }
  return RunArgv(argv, mode);
}

bool ProcSucceeded(const ProcResult& result) {
  return result.exit_status == 0;
}

// Resolve a tool by name through /bin/sh's own `command -v`, with the name
// itself crossing as an argv entry (the script body is a literal).
std::string Which(const std::string& name) {
  const ProcResult result = RunShScript(
      "command -v \"$1\" 2>/dev/null", "winsvpn-which", {name},
      ProcOutput::kCapture);
  return ProcSucceeded(result) ? result.output : std::string();
}

bool StartsWith(const std::string& value, const std::string& prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

std::string CanonicalPath(const std::string& path) {
  std::array<char, PATH_MAX> resolved = {};
  if (realpath(path.c_str(), resolved.data()) == nullptr) {
    return "";
  }
  return resolved.data();
}

std::vector<std::string> LinuxDesktopDirectories() {
  std::vector<std::string> directories;
  const char* home = std::getenv("HOME");
  if (home != nullptr && *home != '\0') {
    directories.push_back(std::string(home) + "/.local/share/applications");
    directories.push_back(
        std::string(home) + "/.local/share/flatpak/exports/share/applications");
  }
  directories.push_back("/var/lib/flatpak/exports/share/applications");
  directories.push_back("/var/lib/snapd/desktop/applications");
  directories.push_back("/usr/local/share/applications");
  directories.push_back("/usr/share/applications");
  return directories;
}

bool IsAllowedDesktopFile(const std::string& path) {
  const std::string canonical = CanonicalPath(path);
  if (canonical.empty() || !g_str_has_suffix(canonical.c_str(), ".desktop")) {
    return false;
  }
  for (const std::string& directory : LinuxDesktopDirectories()) {
    const std::string allowed = CanonicalPath(directory);
    if (!allowed.empty() &&
        (canonical == allowed || StartsWith(canonical, allowed + "/"))) {
      return true;
    }
  }
  return false;
}

std::vector<std::string> ParseDesktopExec(const std::string& raw_exec,
                                          const std::string& name,
                                          const std::string& desktop_file) {
  gint argc = 0;
  gchar** argv = nullptr;
  g_autoptr(GError) error = nullptr;
  if (!g_shell_parse_argv(raw_exec.c_str(), &argc, &argv, &error) || argc < 1) {
    if (argv != nullptr) g_strfreev(argv);
    return {};
  }
  std::vector<std::string> parsed;
  for (gint index = 0; index < argc; ++index) {
    std::string value = argv[index] == nullptr ? "" : argv[index];
    if (value == "%f" || value == "%F" || value == "%u" ||
        value == "%U" || value == "%d" || value == "%D" ||
        value == "%n" || value == "%N" || value == "%v" ||
        value == "%m" || value == "%i") {
      continue;
    }
    if (value == "%c") value = name;
    if (value == "%k") value = desktop_file;
    size_t percent = 0;
    while ((percent = value.find("%%", percent)) != std::string::npos) {
      value.replace(percent, 2, "%");
      ++percent;
    }
    // Unsupported embedded field codes can change argument meaning. Ignore the
    // desktop entry rather than trying to launch a surprising command.
    if (value.find('%') != std::string::npos) {
      parsed.clear();
      break;
    }
    if (!value.empty()) parsed.push_back(value);
  }
  g_strfreev(argv);
  if (parsed.empty()) return {};

  std::string executable;
  if (!parsed[0].empty() && parsed[0][0] == '/') {
    executable = CanonicalPath(parsed[0]);
  } else {
    gchar* found = g_find_program_in_path(parsed[0].c_str());
    if (found != nullptr) {
      executable = CanonicalPath(found);
      g_free(found);
    }
  }
  if (executable.empty() || access(executable.c_str(), X_OK) != 0) return {};
  parsed[0] = executable;
  return parsed;
}

bool DesktopBool(GKeyFile* key_file, const char* key) {
  g_autoptr(GError) error = nullptr;
  const gboolean value =
      g_key_file_get_boolean(key_file, "Desktop Entry", key, &error);
  return error == nullptr && value;
}

bool LoadLinuxDesktopApp(const std::string& path, LinuxDesktopApp* app) {
  if (!IsAllowedDesktopFile(path)) return false;
  g_autoptr(GKeyFile) key_file = g_key_file_new();
  g_autoptr(GError) error = nullptr;
  if (!g_key_file_load_from_file(key_file, path.c_str(), G_KEY_FILE_NONE,
                                 &error)) {
    return false;
  }
  g_autofree gchar* type =
      g_key_file_get_string(key_file, "Desktop Entry", "Type", nullptr);
  if (type == nullptr || std::string(type) != "Application" ||
      DesktopBool(key_file, "Hidden") || DesktopBool(key_file, "NoDisplay")) {
    return false;
  }
  g_autofree gchar* name =
      g_key_file_get_locale_string(key_file, "Desktop Entry", "Name", nullptr,
                                   nullptr);
  g_autofree gchar* raw_exec =
      g_key_file_get_string(key_file, "Desktop Entry", "Exec", nullptr);
  if (name == nullptr || raw_exec == nullptr || Trim(name).empty()) return false;

  const std::string canonical = CanonicalPath(path);
  const std::vector<std::string> command =
      ParseDesktopExec(raw_exec, Trim(name), canonical);
  if (canonical.empty() || command.empty()) return false;
  app->name = Trim(name);
  app->desktop_file = canonical;
  app->command = command;
  return true;
}

std::vector<LinuxDesktopApp> ListLinuxInstalledApps() {
  std::map<std::string, LinuxDesktopApp> by_desktop_id;
  for (const std::string& directory : LinuxDesktopDirectories()) {
    g_autoptr(GDir) dir = g_dir_open(directory.c_str(), 0, nullptr);
    if (dir == nullptr) continue;
    const gchar* entry = nullptr;
    while ((entry = g_dir_read_name(dir)) != nullptr) {
      if (!g_str_has_suffix(entry, ".desktop")) continue;
      LinuxDesktopApp app;
      if (!LoadLinuxDesktopApp(directory + "/" + entry, &app)) continue;
      // Directory order gives user-local launchers priority over system ones.
      by_desktop_id.emplace(entry, app);
    }
  }
  std::vector<LinuxDesktopApp> apps;
  for (const auto& item : by_desktop_id) apps.push_back(item.second);
  std::sort(apps.begin(), apps.end(), [](const LinuxDesktopApp& left,
                                         const LinuxDesktopApp& right) {
    return LowerAscii(left.name) < LowerAscii(right.name);
  });
  return apps;
}

std::vector<std::string> DecodeBase64Lines(const std::string& encoded) {
  if (encoded.empty() || encoded.size() > 1024 * 1024) return {};
  gsize decoded_size = 0;
  guchar* decoded = g_base64_decode(encoded.c_str(), &decoded_size);
  if (decoded == nullptr || decoded_size > 1024 * 1024) {
    g_free(decoded);
    return {};
  }
  std::istringstream stream(
      std::string(reinterpret_cast<const char*>(decoded), decoded_size));
  g_free(decoded);
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(stream, line)) {
    line = Trim(line);
    if (!line.empty()) lines.push_back(line);
  }
  return lines;
}

std::string ExtractJsonCounters(const std::string& json,
                                const std::vector<std::string>& keys);

bool EnsureLinuxBypassSlice(std::string* cgroup_path, std::string* error) {
  const std::string systemd_run = Which("systemd-run");
  const std::string systemctl = Which("systemctl");
  const std::string sleep = Which("sleep");
  if (systemd_run.empty() || systemctl.empty() || sleep.empty() ||
      !ProcSucceeded(RunArgv({systemctl, "--user", "show-environment"},
                             ProcOutput::kSuppress))) {
    *error = "Linux per-app bypass requires an active systemd user session.";
    return false;
  }
  // Keep one inert process in the slice. A RemainAfterExit oneshot unit looks
  // active after systemd removes its empty cgroup, which makes both xt_cgroup
  // and a fail-safe cgroup BPF link race a nonexistent directory.
  const bool anchor_active = ProcSucceeded(
      RunArgv({systemctl, "--user", "is-active", "--quiet",
               "winsvpn-bypass-anchor-v2.service"},
              ProcOutput::kSuppress));
  if (!anchor_active &&
      !ProcSucceeded(RunArgv({systemd_run, "--user", "--quiet",
                             "--unit=winsvpn-bypass-anchor-v2",
                             "--slice=winsvpn-bypass.slice", sleep,
                             "infinity"},
                            ProcOutput::kSuppress))) {
    *error = "Unable to create the isolated Linux per-app bypass cgroup.";
    return false;
  }
  const ProcResult control_group =
      RunArgv({systemctl, "--user", "show", "--property=ControlGroup",
               "--value", "winsvpn-bypass.slice"},
              ProcOutput::kCapture);
  *cgroup_path = control_group.output;
  if (cgroup_path->empty() || (*cgroup_path)[0] != '/' ||
      cgroup_path->find("..") != std::string::npos) {
    *error = "The Linux per-app bypass cgroup could not be verified.";
    return false;
  }
  if (access(("/sys/fs/cgroup" + *cgroup_path).c_str(), F_OK) != 0) {
    *error = "The Linux per-app bypass cgroup is not active.";
    return false;
  }
  return true;
}

void StopLinuxBypassSlice() {
  const std::string systemctl = Which("systemctl");
  if (systemctl.empty()) return;
  RunArgv({systemctl, "--user", "stop", "winsvpn-bypass-anchor-v2.service"},
          ProcOutput::kSuppress);
}

bool LaunchLinuxBypassApp(const std::string& desktop_file,
                          std::string* error) {
  const std::string systemd_run = Which("systemd-run");
  if (systemd_run.empty()) {
    *error = "systemd-run is required for Linux per-app bypass.";
    return false;
  }
  if (!g_linux_split_tunnel_ready || !IsTunnelRunning()) {
    *error = "Connect Win's VPN before launching an app outside the VPN.";
    return false;
  }
  LinuxDesktopApp app;
  if (!LoadLinuxDesktopApp(desktop_file, &app)) {
    *error = "The selected Linux desktop application is no longer valid.";
    return false;
  }
  if (g_linux_excluded_apps.find(app.desktop_file) ==
      g_linux_excluded_apps.end()) {
    *error = "Select this Linux app for bypass before launching it.";
    return false;
  }
  std::vector<std::string> arguments = {
      systemd_run, "--user", "--scope", "--collect", "--quiet",
      "--slice=winsvpn-bypass.slice"};
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto micros =
      std::chrono::duration_cast<std::chrono::microseconds>(now).count();
  arguments.push_back("--unit=winsvpn-bypass-" + std::to_string(getpid()) +
                      "-" + std::to_string(micros));
  arguments.push_back("--");
  arguments.insert(arguments.end(), app.command.begin(), app.command.end());

  std::vector<gchar*> argv;
  for (std::string& value : arguments) argv.push_back(&value[0]);
  argv.push_back(nullptr);
  g_autoptr(GError) spawn_error = nullptr;
  if (!g_spawn_async(nullptr, argv.data(), nullptr,
                     static_cast<GSpawnFlags>(0), nullptr,
                     nullptr, nullptr, &spawn_error)) {
    *error = "Unable to launch the selected app in the Linux bypass cgroup.";
    return false;
  }
  return true;
}

std::string ExecutableDirectory() {
  std::array<char, 4096> path = {};
  const ssize_t size =
      readlink("/proc/self/exe", path.data(), path.size() - 1);
  if (size <= 0) {
    return ".";
  }
  path[static_cast<size_t>(size)] = '\0';
  std::string full(path.data());
  const size_t slash = full.find_last_of('/');
  if (slash == std::string::npos) {
    return ".";
  }
  return full.substr(0, slash);
}

// Mirrors UserDataDirectory() in linux_secure_store.cc: only an absolute
// XDG_DATA_HOME, or an absolute HOME plus "/.local/share", is a legitimate
// per-user private directory. Never fall back to a shared, world-writable
// location such as /tmp -- callers must fail closed instead (L-4).
std::string PrivateDataBaseDirectory() {
  const char* xdg = std::getenv("XDG_DATA_HOME");
  if (xdg != nullptr && xdg[0] == '/') {
    return xdg;
  }
  const char* home = std::getenv("HOME");
  if (home != nullptr && home[0] == '/') {
    return std::string(home) + "/.local/share";
  }
  return "";
}

// Creates (if needed) and opens a single path component beneath parent_fd
// without ever following a symlink placed at that name. The final component
// is additionally required to end up owned by the current user with no
// group/other access, since it holds VPN/Xray configuration state.
bool OpenOrCreatePrivateDirectoryComponent(int parent_fd,
                                           const std::string& component,
                                           bool is_final,
                                           int* out_fd) {
  if (mkdirat(parent_fd, component.c_str(), is_final ? 0700 : 0755) != 0 &&
      errno != EEXIST) {
    return false;
  }
  const int fd = openat(parent_fd, component.c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  struct stat info = {};
  if (fstat(fd, &info) != 0 || !S_ISDIR(info.st_mode)) {
    close(fd);
    return false;
  }
  if (is_final) {
    if (info.st_uid != geteuid()) {
      close(fd);
      return false;
    }
    // fchmod acts on the descriptor already opened above with O_NOFOLLOW, so
    // tightening a too-permissive preexisting directory here can never
    // follow or affect a symlink.
    if ((info.st_mode & 0077) != 0 && fchmod(fd, 0700) != 0) {
      close(fd);
      return false;
    }
  }
  *out_fd = fd;
  return true;
}

// Walks an absolute path one component at a time with O_NOFOLLOW at every
// level (creating components as needed), so a symlink pre-placed anywhere
// along the path -- including at the final component -- is rejected instead
// of followed. Returns an open descriptor for the final directory.
bool OpenPrivateDirectoryPath(const std::string& absolute_path, int* out_fd) {
  if (out_fd == nullptr || absolute_path.size() < 2 ||
      absolute_path.front() != '/' || absolute_path.back() == '/') {
    return false;
  }
  int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (current < 0) {
    return false;
  }
  size_t offset = 1;
  while (offset < absolute_path.size()) {
    const size_t slash = absolute_path.find('/', offset);
    const bool is_final = slash == std::string::npos;
    const std::string component = absolute_path.substr(
        offset, is_final ? std::string::npos : slash - offset);
    offset = is_final ? absolute_path.size() : slash + 1;
    if (component.empty() || component == "." || component == "..") {
      close(current);
      return false;
    }
    int next = -1;
    if (!OpenOrCreatePrivateDirectoryComponent(current, component, is_final,
                                               &next)) {
      close(current);
      return false;
    }
    close(current);
    current = next;
  }
  *out_fd = current;
  return true;
}

std::string DataDirectory() {
  const std::string base = PrivateDataBaseDirectory();
  if (base.empty()) {
    g_warning(
        "Win's VPN has no private per-user data directory (HOME and "
        "XDG_DATA_HOME are both unset or relative); refusing to fall back "
        "to a shared location such as /tmp.");
    return "";
  }
  const std::string path = base + "/wins_vpn";
  int directory_fd = -1;
  if (!OpenPrivateDirectoryPath(path, &directory_fd)) {
    g_warning(
        "Win's VPN could not safely create or verify its private data "
        "directory (it may be blocked by a symlink, or owned by another "
        "user): %s",
        path.c_str());
    return "";
  }
  close(directory_fd);
  return path;
}

// CORE-7-T17C-claude: the Linux half of the local account reset, called by
// Dart after its stop-proof and before it deletes the cleanup journal. The
// AmneziaWG and Xray configurations live in the private data directory under
// fixed names, and WriteFile's crash leftovers under ".<name>.tmp.<pid>.<us>".
// The stop removes the fixed names only after a successful privileged stop
// and ignores the result (StopXrayProcess, StopTunnel), and it never reads
// the user copy (the privileged stop works on its own root copy). So every
// such entry is unlinked here, and the verdict is a fresh listing that finds
// none.
bool IsLocalAccountRuntimeName(const std::string& name) {
  return name == "winsvpn.conf" || name == "wins_xray_client.json" ||
         name.rfind(".winsvpn.conf.tmp.", 0) == 0 ||
         name.rfind(".wins_xray_client.json.tmp.", 0) == 0;
}

// -1: the directory could not be listed; 0: no entry; 1: entries found.
int ScanLocalAccountRuntime(int directory_fd,
                            std::vector<std::string>* names) {
  const int scan_fd = dup(directory_fd);
  if (scan_fd < 0) {
    return -1;
  }
  DIR* directory = fdopendir(scan_fd);
  if (directory == nullptr) {
    close(scan_fd);
    return -1;
  }
  rewinddir(directory);
  errno = 0;
  while (struct dirent* entry = readdir(directory)) {
    if (IsLocalAccountRuntimeName(entry->d_name)) {
      names->push_back(entry->d_name);
    }
    errno = 0;
  }
  const bool listed = errno == 0;
  closedir(directory);
  if (!listed) {
    return -1;
  }
  return names->empty() ? 0 : 1;
}

bool EraseLocalAccountRuntime() {
  const std::string directory = DataDirectory();
  if (directory.empty()) {
    return false;
  }
  int directory_fd = -1;
  if (!OpenPrivateDirectoryPath(directory, &directory_fd)) {
    return false;
  }
  std::vector<std::string> found;
  bool erased = ScanLocalAccountRuntime(directory_fd, &found) >= 0;
  for (const std::string& name : found) {
    // Unlinks a symbolic link itself; a directory fails with EISDIR and is
    // caught by the listing below.
    if (unlinkat(directory_fd, name.c_str(), 0) != 0 && errno != ENOENT) {
      erased = false;
    }
  }
  if (erased && !found.empty() && fsync(directory_fd) != 0) {
    erased = false;
  }
  std::vector<std::string> remaining;
  if (erased && ScanLocalAccountRuntime(directory_fd, &remaining) != 0) {
    erased = false;
  }
  close(directory_fd);
  return erased;
}

void StopTunnelPowerProtection() {
  const std::string systemctl = Which("systemctl");
  if (systemctl.empty()) return;
  RunArgv({systemctl, "--user", "stop", "winsvpn-power-inhibit.service"},
          ProcOutput::kSuppress);
}

// Atomically and safely writes content to path: the directory component is
// opened with O_NOFOLLOW, the temporary file is created with
// O_CREAT|O_EXCL|O_NOFOLLOW (so a preexisting file or symlink at that exact
// temp name is rejected rather than clobbered/followed), and the final
// rename is atomic. A symlink placed at the final destination name is simply
// replaced atomically by the rename, exactly as a plain rename() would, and
// is never opened or followed (L-4).
bool WriteFile(const std::string& path, const std::string& content) {
  const size_t slash = path.find_last_of('/');
  if (slash == std::string::npos || slash == 0) {
    return false;
  }
  const std::string directory = path.substr(0, slash);
  const std::string filename = path.substr(slash + 1);
  if (filename.empty() || filename == "." || filename == "..") {
    return false;
  }
  const int directory_fd = open(
      directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (directory_fd < 0) {
    return false;
  }
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto micros =
      std::chrono::duration_cast<std::chrono::microseconds>(now).count();
  const std::string temp_name = "." + filename + ".tmp." +
                                std::to_string(getpid()) + "." +
                                std::to_string(micros);
  const int file_fd =
      openat(directory_fd, temp_name.c_str(),
             O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (file_fd < 0) {
    close(directory_fd);
    return false;
  }
  bool ok = true;
  size_t written = 0;
  while (written < content.size()) {
    const ssize_t count = write(file_fd, content.data() + written,
                                content.size() - written);
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      ok = false;
      break;
    }
    written += static_cast<size_t>(count);
  }
  if (ok && fsync(file_fd) != 0) {
    ok = false;
  }
  close(file_fd);
  if (ok && renameat(directory_fd, temp_name.c_str(), directory_fd,
                     filename.c_str()) != 0) {
    ok = false;
  }
  if (!ok) {
    unlinkat(directory_fd, temp_name.c_str(), 0);
  }
  close(directory_fd);
  return ok;
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
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
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
          out << "\\u00";
          const char hex[] = "0123456789abcdef";
          out << hex[(c >> 4) & 0x0f] << hex[c & 0x0f];
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

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

// True for a dotted-quad IPv4 literal. A pure string test on purpose: its
// whole job is to decide whether a resolver is needed at all, so it must never
// reach one. getaddrinfo() happens to short-circuit numeric hosts too, but
// that is a glibc property this code should not be silently relying on when
// the whole point of the caller is that no query is made.
bool IsIpv4Literal(const std::string& value) {
  int octets = 0;
  size_t index = 0;
  while (index < value.size()) {
    size_t digits = 0;
    unsigned int accumulator = 0;
    while (index < value.size() &&
           std::isdigit(static_cast<unsigned char>(value[index]))) {
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

std::vector<std::string> ResolvePublicIpv4Addresses(
    const std::string& hostname) {
  // IP-pinned bootstrap (2026-08-07): a carrier delivered as a literal is
  // never looked up, so nothing about it leaves the device before the tunnel
  // exists. Measured: zero packets.
  if (IsIpv4Literal(hostname)) {
    in_addr parsed = {};
    if (inet_pton(AF_INET, hostname.c_str(), &parsed) != 1 ||
        !IsPublicIpv4Address(parsed)) {
      return {};
    }
    return {hostname};
  }
  addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* result = nullptr;
  if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0 ||
      result == nullptr) {
    return {};
  }
  std::set<std::string> addresses;
  for (addrinfo* current = result; current != nullptr;
       current = current->ai_next) {
    if (current->ai_family != AF_INET || current->ai_addr == nullptr) continue;
    const auto* socket_address =
        reinterpret_cast<const sockaddr_in*>(current->ai_addr);
    if (!IsPublicIpv4Address(socket_address->sin_addr)) continue;
    std::array<char, INET_ADDRSTRLEN> text = {};
    if (inet_ntop(AF_INET, &socket_address->sin_addr, text.data(),
                  text.size()) != nullptr) {
      addresses.insert(text.data());
    }
  }
  freeaddrinfo(result);
  return std::vector<std::string>(addresses.begin(), addresses.end());
}

// security must be the value already validated and logged by the caller
// (StartXrayTransportIfNeeded) -- it is taken as a parameter rather than
// re-derived from section so the JSON actually written can never disagree
// with what was checked against the plaintext-transport compatibility flag.
std::string BuildXrayConfig(const std::map<std::string, std::string>& section,
                            const std::vector<std::string>& transport_ipv4s,
                            const std::string& security) {
  const std::string uuid = SectionValue(section, "uuid");
  const std::string host = SectionValue(section, "host");
  const std::string port = SectionValue(section, "port", "80");
  const std::string server_name = SectionValue(section, "servername", host);
  const std::string path =
      SectionValue(section, "path", "/wins-stealth-tunnel");
  const std::string local_port = SectionValue(section, "localport", "42110");
  const std::string remote_host =
      SectionValue(section, "remoteawghost", "127.0.0.1");
  const std::string remote_port =
      SectionValue(section, "remoteawgport", "9110");

  // Resolve and validate every edge before the kill switch is raised. The
  // locked Xray identity deliberately cannot use the host DNS socket after
  // that point, so give Xray all validated IPv4 alternatives directly rather
  // than pinning one edge or weakening the firewall for runtime DNS.

  std::ostringstream json;
  json << "{\n"
       << "  \"log\": {\"loglevel\": \"warning\"},\n"
       << "  \"policy\": {\n"
       << "    \"levels\": {\"0\": {\"handshake\": 4, \"connIdle\": 300, "
          "\"uplinkOnly\": 2, \"downlinkOnly\": 5, \"bufferSize\": 4096}},\n"
       << "    \"system\": {\"statsInboundUplink\": false, "
          "\"statsInboundDownlink\": false, \"statsOutboundUplink\": false, "
          "\"statsOutboundDownlink\": false}\n"
       << "  },\n"
       << "  \"inbounds\": [{\n"
       << "    \"tag\": \"awg-local-in\",\n"
       << "    \"listen\": \"127.0.0.1\",\n"
       << "    \"port\": " << local_port << ",\n"
       << "    \"protocol\": \"tunnel\",\n"
       << "    \"settings\": {\"network\": \"udp\", \"address\": \""
       << JsonEscape(remote_host) << "\", \"port\": " << remote_port
       << ", \"followRedirect\": false, \"userLevel\": 0},\n"
       << "    \"streamSettings\": {\"sockopt\": {\"domainStrategy\": "
          "\"UseIPv4\", \"tcpNoDelay\": true}}\n"
       << "  }],\n"
       << "  \"outbounds\": [";
  for (std::size_t i = 0; i < transport_ipv4s.size(); ++i) {
    if (i != 0) json << ",";
    json << "{\n"
         << "    \"tag\": \"vless-ws-edge-" << i << "\",\n"
         << "    \"protocol\": \"vless\",\n"
         << "    \"settings\": {\"vnext\": [{\"address\": \""
         << JsonEscape(transport_ipv4s[i]) << "\", \"port\": " << port
         << ", \"users\": [{\"id\": \""
         << JsonEscape(uuid)
         << "\", \"encryption\": \"none\", \"level\": 0}]}]},\n"
         << "    \"streamSettings\": {\"network\": \"ws\", \"security\": \""
         << JsonEscape(security) << "\", \"wsSettings\": {\"path\": \""
         << JsonEscape(path) << "\", \"host\": \""
         << JsonEscape(server_name) << "\", \"headers\": {\"Host\": \""
         << JsonEscape(server_name)
         << "\"}}, \"sockopt\": {\"domainStrategy\": \"UseIPv4\", "
            "\"tcpFastOpen\": true, \"tcpNoDelay\": true, "
            "\"tcpCongestion\": \"bbr\", \"tcpKeepAliveIdle\": 30, "
            "\"tcpKeepAliveInterval\": 15, \"tcpUserTimeout\": 15000, "
            "\"tcpMptcp\": false}";
    if (security == "tls") {
      json << ", \"tlsSettings\": {\"serverName\": \""
           << JsonEscape(server_name) << "\", \"allowInsecure\": false}";
    }
    json << "},\n"
         << "    \"mux\": {\"enabled\": false, \"concurrency\": 0, "
            "\"xudpConcurrency\": 0, \"xudpProxyUDP443\": \"skip\"}\n"
         << "  }";
  }
  json << "],\n"
       << "  \"routing\": {\"rules\": [{\"type\": \"field\", "
          "\"inboundTag\": [\"awg-local-in\"], "
          "\"balancerTag\": \"vless-ws-balancer\"}], "
          "\"balancers\": [{\"tag\": \"vless-ws-balancer\", "
          "\"selector\": [\"vless-ws-edge-\"], "
          "\"strategy\": {\"type\": \"roundRobin\"}}]}\n"
       << "}\n";
  return json.str();
}

std::string FindXrayExecutable() {
  const std::string bundled = ExecutableDirectory() + "/xray";
  if (access(bundled.c_str(), X_OK) == 0) {
    return bundled;
  }
  return Which("xray");
}

// The Winn datapath engine, built by
// tools/build_winn_protocol_engine.sh datapath-linux-{amd64,arm64}.
//
// Bundle-only, and deliberately not `Which()`: this binary is the thing that
// carries every outer datagram, so picking one up off PATH would let anything
// that can write to a PATH directory become the tunnel's transport. It runs as
// the desktop user rather than root, so it is outside the M-10 root-execution
// threat the awg/xray hashes address, but it must still be a real, executable,
// non-symlink file inside the app's own bundle.
std::string FindWinnDatapathExecutable() {
  const std::string bundled = ExecutableDirectory() + "/winn-datapath";
  struct stat info = {};
  if (lstat(bundled.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
    return "";
  }
  return access(bundled.c_str(), X_OK) == 0 ? bundled : "";
}

void StopXrayProcess() {
  if (!g_xray_config_path.empty()) {
    std::remove(g_xray_config_path.c_str());
    g_xray_config_path.clear();
  }
  const std::string directory = DataDirectory();
  if (!directory.empty()) {
    std::remove((directory + "/wins_xray_client.json").c_str());
  }
}

bool StartXrayTransportIfNeeded(const std::string& raw_config,
                                std::string* error) {
  const std::map<std::string, std::string> section =
      ParseSection(raw_config, "xray");
  if (!SectionBool(section, "enabled")) {
    StopXrayProcess();
    return true;
  }
  StopXrayProcess();
  const std::string uuid = SectionValue(section, "uuid");
  const std::string host = SectionValue(section, "host");
  const std::string server_name = SectionValue(section, "servername", host);
  // Ruling 4 (2026-10-04): the outer transport is TLS on every platform.
  // `security = none` is refused whatever else the config carries; the old
  // allowplaintexttransport flag no longer has any effect.
  const std::string security =
      LowerAscii(SectionValue(section, "security", "tls"));
  if (!IsValidXrayUuid(uuid) || !IsValidXrayHostname(host) ||
      !IsValidXrayHostname(server_name)) {
    *error = "Xray stealth UUID, host, or TLS server name is invalid.";
    return false;
  }
  if (!IsValidPortValue(SectionValue(section, "port", "80")) ||
      !IsValidPortValue(SectionValue(section, "localport", "42110")) ||
      !IsValidPortValue(SectionValue(section, "remoteawgport", "9110"))) {
    *error = "Xray stealth port is outside 1-65535.";
    return false;
  }
  if (!IsValidXrayPath(
          SectionValue(section, "path", "/wins-stealth-tunnel"))) {
    *error = "Xray stealth WebSocket path is invalid.";
    return false;
  }
  if (security != "tls") {
    *error = "Xray transport requires TLS.";
    return false;
  }
  // IP-PINNED BOOTSTRAP (2026-08-07). `host` may be an IPv4 literal, in which
  // case ResolvePublicIpv4Addresses makes no query at all. The TLS constraint
  // recorded in NETWORK_OBSERVABLE_DNS_SNI_AUDIT_20260806.md §6.7 binds the
  // SNI, not the address -- but it does still bind the SNI, so a literal host
  // with no explicit servername would present an address as SNI and fail
  // certificate verification. Refuse it here, where the message is useful,
  // rather than in a TLS handshake error.
  if (security == "tls" && IsIpv4Literal(host) && IsIpv4Literal(server_name)) {
    *error =
        "Xray stealth host is an IP literal but no TLS server name was "
        "supplied; a certificate cannot be verified against an address.";
    return false;
  }
  const std::string remote_host =
      LowerAscii(SectionValue(section, "remoteawghost", "127.0.0.1"));
  if (remote_host != "127.0.0.1" && remote_host != "localhost" &&
      remote_host != "::1") {
    *error = "Xray stealth AWG destination must remain loopback-only.";
    return false;
  }
  const std::string xray = FindXrayExecutable();
  if (xray.empty()) {
    *error = "xray is not installed or bundled with this Linux build.";
    return false;
  }
  const std::vector<std::string> transport_ipv4s =
      ResolvePublicIpv4Addresses(host);
  if (transport_ipv4s.empty()) {
    *error = "Xray stealth host did not resolve to a public IPv4 address.";
    return false;
  }

  const std::string directory = DataDirectory();
  if (directory.empty()) {
    *error = "No private Linux data directory is available for the Xray client config.";
    return false;
  }
  const std::string config_path = directory + "/wins_xray_client.json";
  if (!WriteFile(config_path,
                 BuildXrayConfig(section, transport_ipv4s, security))) {
    *error = "Unable to write Xray client config.";
    return false;
  }
  g_xray_config_path = config_path;
  return true;
}

// The privilege-elevation argv prefix: {"sudo", "-n"} or {"/path/pkexec"}.
// Empty for euid 0 (root needs no elevator). Returned as an ARGV VECTOR, not
// a shell-string prefix, so the caller can prepend it to a real argv and no
// shell ever re-parses the result (B-APP-004).
std::vector<std::string> PrivilegedRunner() {
  if (geteuid() == 0) {
    return {};
  }
  const std::string sudo = Which("sudo");
  // A deliberately passwordless sudo policy is already an authorization
  // decision and works in minimal graphical sessions such as WSLg, where
  // PolicyKit may have no authentication agent or controlling terminal.
  // Probe it before pkexec; never fall back after a user dismisses pkexec.
  if (!sudo.empty() &&
      ProcSucceeded(RunArgv({sudo, "-n", "true"}, ProcOutput::kSuppress))) {
    return {sudo, "-n"};
  }
  const std::string pkexec = Which("pkexec");
  if (!pkexec.empty()) {
    return {pkexec};
  }
  return {};
}

// The privileged helper's exit status for "a firewall chain with one of our
// names exists on this host, but its rules are not ours, so it was left
// exactly as found". Distinct from the generic 65 because it is the only
// blocking-chain condition the application deliberately will not resolve
// itself, and therefore the only one a user has to act on.
constexpr int kLinuxUnownedFirewallChainExit = 66;

// Written for someone whose machine currently has no internet and no LAN, who
// cannot open a web page to look anything up, and who may reasonably suspect
// they have been blocked rather than that a firewall chain collided. So it
// names the cause, says plainly that this is a rule on their own computer and
// not a blocked account, and gives the commands verbatim.
//
// Those commands were executed against a real chain before being written here:
// `-F` alone restores connectivity, and `-D` matches only when the comment
// match is repeated in full -- `-D OUTPUT -j WINSVPN_KS` fails with "Bad rule"
// and leaves the user exactly as stuck. An untested recovery instruction is a
// guess, and this one is read by somebody who cannot look up a correction.
// The fuller version ships on disk at share/doc/wins-vpn/RECOVERY.md for the
// same reason: a user in this state cannot be sent to a website.
constexpr char kLinuxUnownedFirewallChainMessage[] =
    "This computer has a firewall chain named WINSVPN_KS that Win's VPN did "
    "not create, so it was left untouched. Your account is fine and nothing "
    "has been blocked remotely -- this is a firewall rule on this computer. "
    "To see what it contains, open a terminal and run:  "
    "sudo iptables -S WINSVPN_KS  "
    "To stop it blocking your connection, run:  sudo iptables -F WINSVPN_KS  "
    "and  sudo ip6tables -F WINSVPN_KS  "
    "To remove it afterwards, run:  sudo iptables -X WINSVPN_KS  and  "
    "sudo ip6tables -X WINSVPN_KS  "
    "Full instructions, including what to do if that is not enough, are stored "
    "on this computer and can be read without internet access at "
    "/opt/wins-vpn/share/doc/wins-vpn/RECOVERY.md";

std::string PrivilegedTunnelScript() {
  return R"WINS(set -eu
umask 077
# M-10: establish a fixed, root-owned system search path before invoking any
# utility. The bundled runtime directory is only ever prepended below, after
# it has been proven root-owned and non-writable by validate_root_owned_path.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
NAME=winsvpn
CONF_DIR=/etc/wins-vpn
CONF_DST="$CONF_DIR/$NAME.conf"
SPLIT_STATE_DIR=/run/wins-vpn
BUNDLE_DIR="${4:-}"
XRAY_CONFIG_SRC="${5:-}"
APP_PID="${6:-}"
WINSVPN_BPF_EXPECTED_SHA256="${7:-}"
# The Winn Protocol v3 gateway endpoint, empty on every winn/1 start. Read into
# a variable up here with the others because $1..$9 inside a shell function are
# the FUNCTION's arguments, not the script's.
WINN_ENDPOINT="${8:-}"
BUNDLE_READY=0
verify_bundle_hash() {
  actual="$(sha256sum "$BUNDLE_DIR/$1" | awk '{print $1}')"
  [ "$actual" = "$2" ] || {
    echo "Win's VPN rejected a modified bundled $1 runtime" >&2
    return 65
  }
}
# M-10: a bundle directory is trusted for privileged (root) execution only if
# it, and every ancestor up to /, is owned by root and not group/other
# writable. This rejects a copied/portable bundle placed under any
# user-writable directory before it can shadow system tools on PATH or supply
# an unhashed root-executed helper.
validate_root_owned_path() {
  vrp_check="$(readlink -f -- "$1" 2>/dev/null || realpath -- "$1" 2>/dev/null || echo "$1")"
  while :; do
    vrp_meta="$(stat -Lc '%u %a' -- "$vrp_check")" || return 65
    vrp_uid="${vrp_meta%% *}"
    vrp_mode="${vrp_meta##* }"
    [ "$vrp_uid" = "0" ] || return 65
    [ $((0$vrp_mode & 0022)) -eq 0 ] || return 65
    [ "$vrp_check" = "/" ] && break
    vrp_check="${vrp_check%/*}"
    [ -n "$vrp_check" ] || vrp_check=/
  done
}
# The bundled AmneziaWG runtime is ARCHITECTURE-SPECIFIC. Empty means "no
# pinned hash exists for this architecture"; every caller treats empty as a
# refusal rather than as a skip.
#
# What each of the three actually is, MEASURED rather than assumed:
#
#   awg-quick     Bourne-Again SHELL SCRIPT. Byte-identical on every
#                 architecture, so its hash is pinned ONCE.
#   awg           ELF, dynamically linked C from amneziawg-tools v3.1.20260812.
#                 x86_64 uses the pinned Ubuntu 22.04 zip. linux-arm64 is a
#                 from-source rebuild of the same tag (tools/build_linux_arm64_awg.sh).
#   amneziawg-go  ELF, statically linked Go from v3.1.20260828. linux-arm64 is
#                 the same pinned source/recipe as amd64 with GOARCH=arm64.
#
# Xray is likewise from-source via tools/build_xray_engine.sh on both
# architectures. A bundle that ships a partial AmneziaWG triple is refused.
select_bundle_arch_hashes() {
  # Empty means "no pinned hash exists for this architecture"; every caller
  # treats empty as a refusal rather than as a skip.
  AWG_SHA256=
  AWG_GO_SHA256=
  XRAY_SHA256=
  # The release producer transforms upstream awg-quick into the reviewed
  # userspace-only script. Verify the exact bundled output on every target.
  AWG_QUICK_SHA256=89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db
  BUNDLE_ARCH="$(uname -m 2>/dev/null || echo unknown)"
  case "$BUNDLE_ARCH" in
    x86_64|amd64)
      AWG_SHA256=23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8
      AWG_GO_SHA256=5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f
      XRAY_SHA256=09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12
      ;;
    aarch64|arm64)
      AWG_SHA256=bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d
      AWG_GO_SHA256=9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a
      XRAY_SHA256=868fcabbf9a08d1e453bc6dc82dd8ca27cfcf8cdb2b3a8ff31b824361966964b
      ;;
    *)
      : # Same: an unpinned architecture is a refusal, not a pass.
      ;;
  esac
}
verify_bundled_tools() {
  [ -n "$BUNDLE_DIR" ] || return 0
  BUNDLE_DIR="$(readlink -f -- "$BUNDLE_DIR")" || {
    echo "Win's VPN could not resolve its bundled runtime directory" >&2
    return 65
  }
  case "$BUNDLE_DIR" in
    /*) ;;
    *) echo "Win's VPN rejected a non-absolute bundled runtime path" >&2; return 65 ;;
  esac
  present=0
  for file in awg awg-quick amneziawg-go; do
    [ ! -e "$BUNDLE_DIR/$file" ] || present=$((present + 1))
  done
  [ "$present" -eq 3 ] || {
    echo "Win's VPN requires all bundled AmneziaWG components when an installed runtime directory is supplied ($present of 3 present)" >&2
    return 65
  }
  command -v sha256sum >/dev/null 2>&1 || {
    echo "sha256sum is required to verify bundled AmneziaWG tools" >&2
    return 127
  }
  for file in awg awg-quick amneziawg-go; do
    [ -f "$BUNDLE_DIR/$file" ] && [ ! -L "$BUNDLE_DIR/$file" ] && \
      [ -x "$BUNDLE_DIR/$file" ] || {
        echo "Win's VPN rejected an unsafe bundled AmneziaWG runtime" >&2
        return 65
      }
  done
  # M-10: only prepend the bundle to root's PATH once the directory and all of
  # its ancestors are proven root-owned and non-writable, so no non-root
  # process can shadow ip/iptables/install/stat/etc. from within it.
  validate_root_owned_path "$BUNDLE_DIR" || {
    echo "Win's VPN refused to trust a bundled runtime directory that is not root-owned or is writable by a non-root user" >&2
    return 65
  }
  select_bundle_arch_hashes
  if [ -z "$AWG_SHA256" ] || [ -z "$AWG_GO_SHA256" ]; then
    echo "Win's VPN has no pinned AmneziaWG runtime for this computer's processor type ($BUNDLE_ARCH), so it will not run the installed bundle" >&2
    return 65
  fi
  verify_bundle_hash awg "$AWG_SHA256"
  verify_bundle_hash awg-quick "$AWG_QUICK_SHA256"
  verify_bundle_hash amneziawg-go "$AWG_GO_SHA256"
  PATH="$BUNDLE_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export PATH
  WG_QUICK_USERSPACE_IMPLEMENTATION="$BUNDLE_DIR/amneziawg-go"
  export WG_QUICK_USERSPACE_IMPLEMENTATION
  BUNDLE_READY=1
}
verify_bundled_tools
find_awg_quick() {
  if [ "$BUNDLE_READY" -eq 1 ]; then printf '%s\n' "$BUNDLE_DIR/awg-quick"; return; fi
  if command -v awg-quick >/dev/null 2>&1; then command -v awg-quick; return; fi
  if command -v amneziawg-quick >/dev/null 2>&1; then command -v amneziawg-quick; return; fi
}
find_awg() {
  if [ "$BUNDLE_READY" -eq 1 ]; then printf '%s\n' "$BUNDLE_DIR/awg"; return; fi
  if command -v awg >/dev/null 2>&1; then command -v awg; return; fi
  if command -v amneziawg >/dev/null 2>&1; then command -v amneziawg; return; fi
}
cleanup_xray_transport() {
  XRAY_STATE_DIR=/run/wins-vpn-xray
  UID_FILE="$SPLIT_STATE_DIR/xray-uid"
  MARK_FILE="$SPLIT_STATE_DIR/xray-mark"
  if [ -s "$XRAY_STATE_DIR/xray.pid" ]; then
    pid="$(cat "$XRAY_STATE_DIR/xray.pid")"
    case "$pid" in ''|*[!0-9]*) pid= ;; esac
    if [ -n "$pid" ] && [ -e "/proc/$pid/exe" ] && \
      [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$BUNDLE_DIR/xray" ]; then
      kill "$pid" >/dev/null 2>&1 || true
      count=0
      while kill -0 "$pid" >/dev/null 2>&1 && [ "$count" -lt 20 ]; do
        sleep 0.1
        count=$((count + 1))
      done
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  fi
  if [ -s "$UID_FILE" ]; then
    xray_uid="$(cat "$UID_FILE")"
    case "$xray_uid" in ''|*[!0-9]*) xray_uid= ;; esac
    if [ -n "$xray_uid" ]; then
      for xray_rule_priority in 1 50 100; do
        while ip -4 rule delete priority "$xray_rule_priority" \
          uidrange "$xray_uid-$xray_uid" lookup main >/dev/null 2>&1; do :; done
      done
    fi
  fi
  xray_mark="$(cat "$MARK_FILE" 2>/dev/null || true)"
  printf '%s\n' "$xray_mark" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || \
    xray_mark=
  if [ -n "${xray_uid:-}" ] && [ -n "$xray_mark" ] && \
      command -v iptables >/dev/null 2>&1; then
    while iptables -w 5 -t mangle -C OUTPUT -m owner \
      --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-connmark \
      -j CONNMARK --save-mark >/dev/null 2>&1; do
      iptables -w 5 -t mangle -D OUTPUT -m owner \
        --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-connmark \
        -j CONNMARK --save-mark
    done
    while iptables -w 5 -t mangle -C OUTPUT -m owner \
      --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-bypass \
      -j MARK --set-mark "$xray_mark" >/dev/null 2>&1; do
      iptables -w 5 -t mangle -D OUTPUT -m owner \
        --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-bypass \
        -j MARK --set-mark "$xray_mark"
    done
    while iptables -w 5 -t mangle -C PREROUTING -m connmark \
      --mark "$xray_mark" -m comment --comment winsvpn-xray-connmark \
      -j CONNMARK --restore-mark >/dev/null 2>&1; do
      iptables -w 5 -t mangle -D PREROUTING -m connmark \
        --mark "$xray_mark" -m comment --comment winsvpn-xray-connmark \
        -j CONNMARK --restore-mark
    done
  fi
  rm -f "$UID_FILE" "$MARK_FILE"
  rm -rf "$XRAY_STATE_DIR"
}
configure_xray_transport() {
  cleanup_xray_transport
  [ -n "$XRAY_CONFIG_SRC" ] || return 0
  [ -f "$XRAY_CONFIG_SRC" ] && [ ! -L "$XRAY_CONFIG_SRC" ] && \
    [ -s "$XRAY_CONFIG_SRC" ] && [ "$(stat -c %s "$XRAY_CONFIG_SRC")" -le 65536 ] || {
      echo "Win's VPN rejected an unsafe Xray client config" >&2
      return 65
    }
  [ -f "$BUNDLE_DIR/xray" ] && [ ! -L "$BUNDLE_DIR/xray" ] && \
    [ -x "$BUNDLE_DIR/xray" ] || {
      echo "Win's VPN bundled Xray runtime is unavailable" >&2
      return 127
    }
  select_bundle_arch_hashes
  if [ -z "$XRAY_SHA256" ]; then
    echo "Win's VPN has no pinned Xray runtime for this computer's processor type ($BUNDLE_ARCH), so it will not run the bundled xray. This is not a problem with your files: no reviewed Xray pin exists for this processor. A bundle that does not carry xray at all is unaffected." >&2
    return 65
  fi
  verify_bundle_hash xray "$XRAY_SHA256"
  command -v setpriv >/dev/null 2>&1 || {
    echo "setpriv is required for isolated Xray transport" >&2
    return 127
  }
  xray_uid="$(id -u winsvpn-xray 2>/dev/null || true)"
  xray_gid="$(id -g winsvpn-xray 2>/dev/null || true)"
  case "$xray_uid:$xray_gid" in
    *[!0-9:]*) echo "The isolated winsvpn-xray service account is unavailable" >&2; return 65 ;;
  esac
  [ -n "$xray_uid" ] && [ -n "$xray_gid" ] || {
    echo "The isolated winsvpn-xray service account is unavailable" >&2
    return 65
  }
  [ "$xray_uid" -gt 0 ] && [ "$xray_uid" -lt 1000 ] || {
    echo "The isolated winsvpn-xray account is not a non-root system account" >&2
    return 65
  }
  xray_home="$(getent passwd winsvpn-xray | awk -F: '{print $6}')"
  xray_shell="$(getent passwd winsvpn-xray | awk -F: '{print $7}')"
  xray_password="$(getent shadow winsvpn-xray 2>/dev/null | awk -F: '{print $2}')"
  [ "$xray_home" = /nonexistent ] || {
    echo "The isolated winsvpn-xray account has an unsafe home directory" >&2
    return 65
  }
  case "$xray_shell" in
    */nologin) ;;
    *) echo "The isolated winsvpn-xray account has an interactive shell" >&2; return 65 ;;
  esac
  case "$xray_password" in
    '!'*|'*'*) ;;
    *) echo "The isolated winsvpn-xray account is not locked" >&2; return 65 ;;
  esac
  XRAY_STATE_DIR=/run/wins-vpn-xray
  install -d -m 0750 -o root -g "$xray_gid" "$XRAY_STATE_DIR"
  install -m 0600 -o "$xray_uid" -g "$xray_gid" \
    "$XRAY_CONFIG_SRC" "$XRAY_STATE_DIR/client.json"
  install -d -m 0700 "$SPLIT_STATE_DIR"
  printf '%s\n' "$xray_uid" > "$SPLIT_STATE_DIR/xray-uid"
  chmod 600 "$SPLIT_STATE_DIR/xray-uid"
}
activate_xray_transport() {
  XRAY_STATE_DIR=/run/wins-vpn-xray
  UID_FILE="$SPLIT_STATE_DIR/xray-uid"
  MARK_FILE="$SPLIT_STATE_DIR/xray-mark"
  [ -s "$XRAY_STATE_DIR/client.json" ] || return 0
  [ -s "$UID_FILE" ] || {
    echo "Win's VPN lost the isolated Xray identity state" >&2
    return 65
  }
  xray_uid="$(cat "$UID_FILE")"
  xray_gid="$(id -g winsvpn-xray 2>/dev/null || true)"
  case "$xray_uid:$xray_gid" in
    *[!0-9:]*) echo "The isolated winsvpn-xray identity changed during startup" >&2; return 65 ;;
  esac
  AWG="$(find_awg || true)"
  [ -n "$AWG" ] || {
    echo "AmneziaWG is unavailable for isolated Xray packet marking" >&2
    return 127
  }
  xray_mark="$($AWG show "$NAME" fwmark 2>/dev/null || true)"
  printf '%s\n' "$xray_mark" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || {
    echo "Win's VPN could not verify the AWG policy mark for Xray" >&2
    return 65
  }
  [ "$xray_mark" != 0 ] || {
    echo "Win's VPN rejected an empty AWG policy mark for Xray" >&2
    return 65
  }
  command -v iptables >/dev/null 2>&1 || {
    echo "iptables is required for isolated Xray packet marking" >&2
    return 127
  }
  iptables -m owner -h >/dev/null 2>&1 && \
    iptables -j MARK -h >/dev/null 2>&1 && \
    iptables -j CONNMARK -h >/dev/null 2>&1 || {
      echo "iptables owner, MARK, and CONNMARK support is required for Xray" >&2
      return 95
    }
  # awg-quick chooses automatic policy priorities relative to rules that
  # already exist. Add the Xray-only exception after awg-quick is up, place it
  # directly after the immutable local-table rule, and verify the actual route
  # before starting any outer transport socket.
  ip -4 rule add priority 1 uidrange "$xray_uid-$xray_uid" lookup main
  printf '%s\n' "$xray_mark" > "$MARK_FILE"
  chmod 600 "$MARK_FILE"
  iptables -w 5 -t mangle -I OUTPUT 1 -m owner \
    --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-bypass \
    -j MARK --set-mark "$xray_mark"
  iptables -w 5 -t mangle -I OUTPUT 2 -m owner \
    --uid-owner "$xray_uid" -m comment --comment winsvpn-xray-connmark \
    -j CONNMARK --save-mark
  iptables -w 5 -t mangle -I PREROUTING 1 -m connmark \
    --mark "$xray_mark" -m comment --comment winsvpn-xray-connmark \
    -j CONNMARK --restore-mark
  if ip -4 route get 1.1.1.1 mark "$xray_mark" uid "$xray_uid" | \
      grep -Eq ' dev winsvpn( |$)'; then
    echo "Win's VPN rejected a recursive Xray transport route" >&2
    cleanup_xray_transport
    return 65
  fi
  : > "$XRAY_STATE_DIR/xray.log"
  chmod 600 "$XRAY_STATE_DIR/xray.log"
  setpriv --reuid="$xray_uid" --regid="$xray_gid" --clear-groups \
    --no-new-privs "$BUNDLE_DIR/xray" run -c "$XRAY_STATE_DIR/client.json" \
    > "$XRAY_STATE_DIR/xray.log" 2>&1 &
  xray_pid=$!
  printf '%s\n' "$xray_pid" > "$XRAY_STATE_DIR/xray.pid"
  chmod 600 "$XRAY_STATE_DIR/xray.pid"
  xray_port="$(sed -n 's/^    "port": \([0-9][0-9]*\),$/\1/p' \
    "$XRAY_STATE_DIR/client.json" | head -n 1)"
  case "$xray_port" in
    ''|*[!0-9]*)
      cleanup_xray_transport
      return 65
      ;;
  esac
  xray_port_hex="$(printf '%04X' "$xray_port")"

  xray_owns_inbound() {
    xray_inodes=" "
    for xray_fd in /proc/"$xray_pid"/fd/*; do
      xray_socket="$(readlink "$xray_fd" 2>/dev/null)" || continue
      case "$xray_socket" in
        socket:\[*\])
          xray_inode="${xray_socket#socket:\[}"
          xray_inode="${xray_inode%\]}"
          case "$xray_inode" in
            ''|*[!0-9]*) continue ;;
          esac
          xray_inodes="$xray_inodes$xray_inode "
          ;;
      esac
    done
    awk -v address="0100007F:$xray_port_hex" -v owned="$xray_inodes" '
      $2 == address && index(owned, " " $10 " ") { found = 1 }
      END { exit !found }
    ' "/proc/$xray_pid/net/udp" 2>/dev/null
  }

  xray_ready=0
  count=0
  while [ "$count" -lt 60 ]; do
    kill -0 "$xray_pid" >/dev/null 2>&1 || break
    if xray_owns_inbound; then
      xray_ready=1
      break
    fi
    sleep 0.05
    count=$((count + 1))
  done
  if [ "$xray_ready" -ne 1 ]; then
    cleanup_xray_transport
    echo "Xray transport did not open its owned local inbound" >&2
    return 1
  fi
  kill -0 "$xray_pid" >/dev/null 2>&1 || {
    tail -n 20 "$XRAY_STATE_DIR/xray.log" >&2 || true
    cleanup_xray_transport
    return 1
  }
}
winn_state_read() {
  # Prints a stored Winn state value only when it still looks like the kind of
  # token it is supposed to be, so a tampered state file can never reach an
  # iptables argument.
  winn_value="$(cat "$SPLIT_STATE_DIR/$1" 2>/dev/null || true)"
  case "$2" in
    mark) printf '%s\n' "$winn_value" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || return 0 ;;
    host) case "$winn_value" in ''|*[!0-9A-Fa-f:.]*) return 0 ;; esac ;;
    port) case "$winn_value" in ''|*[!0-9]*) return 0 ;; esac ;;
    *) return 0 ;;
  esac
  printf '%s\n' "$winn_value"
}
cleanup_winn_transport() {
  winn_mark="$(winn_state_read winn-mark mark)"
  winn_host="$(winn_state_read winn-host host)"
  winn_port="$(winn_state_read winn-port port)"
  winn_table="$(winn_state_read winn-table port)"
  if [ -n "$winn_host" ] && [ -n "$winn_table" ]; then
    case "$winn_host" in
      *:*) winn_ipv=-6; winn_prefix=128 ;;
      *)   winn_ipv=-4; winn_prefix=32 ;;
    esac
    while ip "$winn_ipv" route del "$winn_host/$winn_prefix" \
      table "$winn_table" >/dev/null 2>&1; do :; done
  fi
  if [ -n "$winn_mark" ] && [ -n "$winn_host" ] && [ -n "$winn_port" ]; then
    case "$winn_host" in
      *:*) winn_ipt=ip6tables ;;
      *)   winn_ipt=iptables ;;
    esac
    if command -v "$winn_ipt" >/dev/null 2>&1; then
      while "$winn_ipt" -w 5 -t mangle -C OUTPUT -d "$winn_host" -p udp \
        --dport "$winn_port" -m comment --comment winsvpn-winn-connmark \
        -j CONNMARK --save-mark >/dev/null 2>&1; do
        "$winn_ipt" -w 5 -t mangle -D OUTPUT -d "$winn_host" -p udp \
          --dport "$winn_port" -m comment --comment winsvpn-winn-connmark \
          -j CONNMARK --save-mark || break
      done
      while "$winn_ipt" -w 5 -t mangle -C OUTPUT -d "$winn_host" -p udp \
        --dport "$winn_port" -m comment --comment winsvpn-winn-bypass \
        -j MARK --set-mark "$winn_mark" >/dev/null 2>&1; do
        "$winn_ipt" -w 5 -t mangle -D OUTPUT -d "$winn_host" -p udp \
          --dport "$winn_port" -m comment --comment winsvpn-winn-bypass \
          -j MARK --set-mark "$winn_mark" || break
      done
      while "$winn_ipt" -w 5 -t mangle -C PREROUTING -m connmark \
        --mark "$winn_mark" -m comment --comment winsvpn-winn-connmark \
        -j CONNMARK --restore-mark >/dev/null 2>&1; do
        "$winn_ipt" -w 5 -t mangle -D PREROUTING -m connmark \
          --mark "$winn_mark" -m comment --comment winsvpn-winn-connmark \
          -j CONNMARK --restore-mark || break
      done
    fi
  fi
  rm -f "$SPLIT_STATE_DIR/winn-mark" "$SPLIT_STATE_DIR/winn-host" \
    "$SPLIT_STATE_DIR/winn-port" "$SPLIT_STATE_DIR/winn-table"
}
# Keeps the Winn engine's ONE outer socket out of the tunnel it is carrying.
#
# THIS NEEDS TWO MECHANISMS, NOT ONE, AND THE REASON IS SUBTLE ENOUGH THAT IT
# WAS GOT WRONG HERE FIRST. Both are installed below.
#
# 1. A HOST ROUTE for the gateway in awg-quick's own routing table, via the
#    pre-tunnel default. This is what actually keeps the outer datagrams off the
#    tunnel, and a packet mark cannot replace it.
#
#    AmneziaWG marks its OWN socket, so its very first route lookup is already
#    marked and both the device and the SOURCE ADDRESS come out right. This
#    engine's socket cannot be marked that way -- SO_MARK needs CAP_NET_ADMIN
#    and the app is unprivileged -- so the only mark available is an iptables
#    one, applied in mangle OUTPUT. That is too late for source selection: the
#    kernel picks the source address during the FIRST route lookup, which is
#    unmarked, resolves to `default dev winsvpn`, and yields the TUNNEL address.
#    Re-routing after the mark changes the outgoing device but keeps that
#    already-chosen source, so the datagram leaves the physical interface
#    carrying a tunnel-internal source address. Observed directly: the gateway
#    then records that unroutable address as the peer endpoint and every reply
#    is sent somewhere it can never arrive from. The tunnel handshakes outbound
#    and receives nothing, forever.
#
#    A more-specific route in the tunnel table fixes the first lookup itself,
#    which is why it is the mechanism datapath/carrier.go names for the desktop
#    model: `transportFD < 0` plus ROUTE exclusion.
#
# 2. The fwmark, which is still required -- for the KILL SWITCH rather than for
#    routing. configure_kill_switch's chain RETURNs on `-m mark --mark
#    $ROUTING_MARK` and REJECTs every other non-tunnel destination inside
#    AllowedIPs. With AllowedIPs 0.0.0.0/0 that is everything, so an unmarked
#    outer datagram leaving on the physical interface is rejected by this host's
#    own firewall even once its route is correct.
#
# The engine runs as the desktop user and has no uid of its own to match on, so
# both are keyed by DESTINATION. That is exact rather than approximate: the
# AmneziaWG peer endpoint has already been rewritten to a loopback seam, so the
# Winn engine is the only thing on this host still addressing the gateway.
parse_winn_endpoint() {
  case "$WINN_ENDPOINT" in
    \[*\]:*)
      WINN_HOST="${WINN_ENDPOINT#\[}"
      WINN_HOST="${WINN_HOST%%\]:*}"
      WINN_PORT="${WINN_ENDPOINT##*\]:}"
      WINN_IPT=ip6tables
      WINN_IPV=-6
      WINN_PREFIX=128
      ;;
    *:*:*)
      echo "Win's VPN rejected an ambiguous Winn gateway endpoint" >&2
      return 65
      ;;
    *:*)
      WINN_HOST="${WINN_ENDPOINT%%:*}"
      WINN_PORT="${WINN_ENDPOINT##*:}"
      WINN_IPT=iptables
      WINN_IPV=-4
      WINN_PREFIX=32
      ;;
    *)
      echo "Win's VPN rejected a malformed Winn gateway endpoint" >&2
      return 65
      ;;
  esac
  case "$WINN_HOST" in
    ''|*[!0-9A-Fa-f:.]*)
      echo "Win's VPN rejected a non-literal Winn gateway address" >&2
      return 65
      ;;
  esac
  case "$WINN_PORT" in
    ''|*[!0-9]*)
      echo "Win's VPN rejected a non-numeric Winn gateway port" >&2
      return 65
      ;;
  esac
  if [ "$WINN_PORT" -lt 1 ] || [ "$WINN_PORT" -gt 65535 ]; then
    echo "Win's VPN rejected a Winn gateway port outside 1-65535" >&2
    return 65
  fi
}

activate_winn_transport() {
  [ -n "$WINN_ENDPOINT" ] || return 0
  parse_winn_endpoint || return $?
  AWG="$(find_awg || true)"
  [ -n "$AWG" ] || {
    echo "AmneziaWG is unavailable for the Winn outer-socket exclusion" >&2
    return 127
  }
  winn_mark="$($AWG show "$NAME" fwmark 2>/dev/null || true)"
  printf '%s\n' "$winn_mark" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || {
    echo "Win's VPN could not verify the AWG policy mark for Winn" >&2
    return 65
  }
  if printf '%s\n' "$winn_mark" | grep -Eq '^(0x0+|0+)$'; then
    echo "Win's VPN rejected an empty AWG policy mark for Winn" >&2
    return 65
  fi
  command -v "$WINN_IPT" >/dev/null 2>&1 || {
    echo "$WINN_IPT is required for the Winn outer-socket exclusion" >&2
    return 127
  }
  "$WINN_IPT" -j MARK -h >/dev/null 2>&1 && \
    "$WINN_IPT" -j CONNMARK -h >/dev/null 2>&1 && \
    "$WINN_IPT" -m comment -h >/dev/null 2>&1 || {
      echo "$WINN_IPT MARK, CONNMARK, and comment support is required for Winn" >&2
      return 95
    }
  # awg-quick's routing table, discovered from the rule it installed rather than
  # assumed. wg-quick derives the table number and the fwmark from the same
  # counter, but that is an implementation detail of a tool we do not own, so it
  # is read back instead of inferred.
  winn_mark_dec=$((winn_mark))
  winn_table=
  for winn_rule in $(ip "$WINN_IPV" rule show 2>/dev/null | \
      sed -n 's/.*not from all fwmark \([^ ]*\) lookup \([^ ]*\).*/\1:\2/p'); do
    winn_rule_mark="${winn_rule%%:*}"
    winn_rule_table="${winn_rule##*:}"
    case "$winn_rule_table" in ''|*[!0-9]*) continue ;; esac
    [ "$((winn_rule_mark))" = "$winn_mark_dec" ] || continue
    winn_table="$winn_rule_table"
    break
  done
  [ -n "$winn_table" ] || {
    echo "Win's VPN could not find the AmneziaWG policy routing table" >&2
    return 65
  }
  # The pre-tunnel default, still in the main table: awg-quick puts its own
  # default in the policy table, never in main.
  winn_default="$(ip "$WINN_IPV" route show default table main 2>/dev/null | head -1)"
  winn_via="$(printf '%s\n' "$winn_default" | sed -n 's/.*via \([^ ]*\).*/\1/p')"
  winn_dev="$(printf '%s\n' "$winn_default" | sed -n 's/.*dev \([^ ]*\).*/\1/p')"
  [ -n "$winn_dev" ] || {
    echo "Win's VPN found no physical default route to carry Winn" >&2
    return 65
  }
  [ "$winn_dev" != "$NAME" ] || {
    echo "Win's VPN refused to carry Winn over the tunnel it is building" >&2
    return 65
  }
  case "$winn_dev" in *[!A-Za-z0-9._-]*)
    echo "Win's VPN rejected an unsafe default-route device name" >&2
    return 65 ;;
  esac
  case "$winn_via" in *[!0-9A-Fa-f:.]*)
    echo "Win's VPN rejected an unsafe default-route gateway address" >&2
    return 65 ;;
  esac
  install -d -m 700 "$SPLIT_STATE_DIR"
  printf '%s\n' "$winn_mark" > "$SPLIT_STATE_DIR/winn-mark"
  printf '%s\n' "$WINN_HOST" > "$SPLIT_STATE_DIR/winn-host"
  printf '%s\n' "$WINN_PORT" > "$SPLIT_STATE_DIR/winn-port"
  printf '%s\n' "$winn_table" > "$SPLIT_STATE_DIR/winn-table"
  chmod 600 "$SPLIT_STATE_DIR/winn-mark" "$SPLIT_STATE_DIR/winn-host" \
    "$SPLIT_STATE_DIR/winn-port" "$SPLIT_STATE_DIR/winn-table"
  # THE ROUTE EXCLUSION. More specific than awg-quick's `default dev $NAME`, so
  # it wins the FIRST route lookup and the source address is chosen from the
  # physical interface rather than from the tunnel.
  if [ -n "$winn_via" ]; then
    ip "$WINN_IPV" route replace "$WINN_HOST/$WINN_PREFIX" via "$winn_via" \
      dev "$winn_dev" table "$winn_table"
  else
    ip "$WINN_IPV" route replace "$WINN_HOST/$WINN_PREFIX" \
      dev "$winn_dev" table "$winn_table"
  fi
  "$WINN_IPT" -w 5 -t mangle -I OUTPUT 1 -d "$WINN_HOST" -p udp \
    --dport "$WINN_PORT" -m comment --comment winsvpn-winn-bypass \
    -j MARK --set-mark "$winn_mark"
  "$WINN_IPT" -w 5 -t mangle -I OUTPUT 2 -d "$WINN_HOST" -p udp \
    --dport "$WINN_PORT" -m comment --comment winsvpn-winn-connmark \
    -j CONNMARK --save-mark
  "$WINN_IPT" -w 5 -t mangle -I PREROUTING 1 -m connmark \
    --mark "$winn_mark" -m comment --comment winsvpn-winn-connmark \
    -j CONNMARK --restore-mark
  # THE RECURSION CHECK, run against BOTH lookups.
  #
  # The UNMARKED one is the one that matters and the one that was missing: it is
  # the lookup the kernel performs first, and therefore the lookup that chooses
  # the source address. A tunnel-internal source on a datagram that leaves the
  # physical interface is not a routing loop, so the marked check alone passes
  # while the gateway learns an unroutable peer endpoint and the session is dead
  # in the return direction only -- the hardest possible shape to diagnose.
  #
  # Both are checked before any outer socket exists to loop or to mislead.
  for winn_probe in unmarked marked; do
    if [ "$winn_probe" = marked ]; then
      winn_route="$(ip "$WINN_IPV" route get "$WINN_HOST" mark "$winn_mark" 2>&1)"
    else
      winn_route="$(ip "$WINN_IPV" route get "$WINN_HOST" 2>&1)"
    fi
    if printf '%s\n' "$winn_route" | grep -Eq " dev $NAME( |$)"; then
      echo "Win's VPN rejected a recursive Winn transport route ($winn_probe)" >&2
      cleanup_winn_transport
      return 65
    fi
    # A source address inside the tunnel is the same defect wearing a different
    # hat: the route left by the physical interface but the datagram would still
    # carry an address the gateway cannot reply to.
    winn_src="$(printf '%s\n' "$winn_route" | sed -n 's/.*src \([^ ]*\).*/\1/p')"
    if [ -n "$winn_src" ] && \
        ip "$WINN_IPV" addr show dev "$NAME" 2>/dev/null | \
        grep -Eq "(inet|inet6) ${winn_src}(/| )"; then
      echo "Win's VPN rejected a Winn transport source address inside the tunnel ($winn_probe)" >&2
      cleanup_winn_transport
      return 65
    fi
  done
}
cleanup_split_bpf() {
  BPF_PID_FILE="$SPLIT_STATE_DIR/app-bypass-bpf.pid"
  BPF_LOG_FILE="$SPLIT_STATE_DIR/app-bypass-bpf.log"
  if [ -s "$BPF_PID_FILE" ]; then
    bpf_pid="$(cat "$BPF_PID_FILE")"
    case "$bpf_pid" in ''|*[!0-9]*) bpf_pid= ;; esac
    expected_bpf="$BUNDLE_DIR/winsvpn-bypass-bpf"
    if [ -n "$bpf_pid" ] && [ -e "/proc/$bpf_pid/exe" ] && \
      [ "$(readlink -f "/proc/$bpf_pid/exe" 2>/dev/null || true)" = "$expected_bpf" ]; then
      kill "$bpf_pid" >/dev/null 2>&1 || true
      count=0
      while kill -0 "$bpf_pid" >/dev/null 2>&1 && [ "$count" -lt 20 ]; do
        sleep 0.1
        count=$((count + 1))
      done
      if kill -0 "$bpf_pid" >/dev/null 2>&1 && \
        [ "$(readlink -f "/proc/$bpf_pid/exe" 2>/dev/null || true)" = "$expected_bpf" ]; then
        kill -9 "$bpf_pid" >/dev/null 2>&1 || true
      fi
    fi
  fi
  rm -f "$BPF_PID_FILE" "$BPF_LOG_FILE"
}
# Decides whether a blocking chain belongs to this application, using the
# chain's own contents rather than a marker file.
#
# This replaces an ownership test that keyed on "$SPLIT_STATE_DIR/kill-switch-
# active". That test was wrong in both directions.
#
# It locked users out. SPLIT_STATE_DIR is /run, which is tmpfs, so the marker
# is destroyed by every reboot -- while a host running iptables-persistent
# restores the saved WINSVPN_KS chain at boot. The chain came back and the
# marker did not, so cleanup refused to touch its own blocking chain and BOTH
# start and stop aborted. The host had no internet, no LAN, and no in-app way
# back; the only exit was a root iptables incantation. On this threat model a
# machine that silently loses all connectivity is not read as a lost marker
# file, it is read as having been cut off or detected.
#
# And it never delivered the protection it was written for. The marker only
# ever recorded "this application installed a chain at some point during this
# boot". That is not a statement about the chain currently in the kernel, so
# with the marker present a same-named chain belonging to somebody else was
# flushed and deleted without ever being inspected.
#
# Every rule this script adds to its own chains carries a --comment tag, and
# comments are preserved verbatim by iptables-save/iptables-restore, so the tag
# is durable evidence that outlives the reboot the marker cannot. A chain is
# ours only if EVERY rule in it carries our tag; a single foreign rule leaves
# the whole chain untouched. A chain holding no rules at all encodes no policy,
# and the kernel refuses to delete a chain anything still jumps to, so
# reclaiming an empty one cannot destroy another owner's configuration.
winsvpn_chain_is_ours() {
  CHAIN_IPT="$1"
  CHAIN_NAME="$2"
  CHAIN_TAG="$3"
  CHAIN_RULES="$("$CHAIN_IPT" -w 5 -S "$CHAIN_NAME" 2>/dev/null)" || return 1
  CHAIN_BODY="$(printf '%s\n' "$CHAIN_RULES" | \
    grep -v -x -e "-N $CHAIN_NAME" || true)"
  [ -n "$CHAIN_BODY" ] || return 0
  ! printf '%s\n' "$CHAIN_BODY" | grep -q -v -e "--comment $CHAIN_TAG"
}
cleanup_kill_switch() {
  KS_CHAIN=WINSVPN_KS
  KS_STATE_FILE="$SPLIT_STATE_DIR/kill-switch-active"
  # The marker is advisory from here on: it records that a start completed, and
  # it is never permitted to prevent removal of a chain proven ours above. A
  # marker that is missing (every reboot), truncated, or written by a different
  # version must not be able to strand a user behind this app's own kill
  # switch, so an unusable one is reported and then ignored.
  if [ -L "$KS_STATE_FILE" ] || \
    { [ -e "$KS_STATE_FILE" ] && [ ! -f "$KS_STATE_FILE" ]; }; then
    echo "Win's VPN ignored unsafe Linux kill-switch state" >&2
  fi
  KS_FOREIGN=0
  for IPT in iptables ip6tables; do
    if ! command -v "$IPT" >/dev/null 2>&1; then
      # Nothing can be inspected or removed without the tool. Reporting this
      # and continuing is strictly better than aborting: an abort here removes
      # nothing and additionally prevents the reconnect-guard teardown below.
      echo "$IPT is unavailable to remove the Linux kill switch" >&2
      continue
    fi
    "$IPT" -w 5 -nL "$KS_CHAIN" >/dev/null 2>&1 || continue
    if ! winsvpn_chain_is_ours "$IPT" "$KS_CHAIN" winsvpn-killswitch; then
      echo "Win's VPN refused to modify an unowned Linux firewall chain" >&2
      KS_FOREIGN=1
      continue
    fi
    if [ ! -f "$KS_STATE_FILE" ]; then
      # The chain outlived its marker: a reboot on a host that restores saved
      # firewall rules. Recovering it is the whole point of the content test.
      echo "Win's VPN reclaimed a $IPT kill-switch chain left by an earlier session" >&2
    fi
    while "$IPT" -w 5 -C OUTPUT -m comment \
      --comment winsvpn-killswitch -j "$KS_CHAIN" >/dev/null 2>&1; do
      "$IPT" -w 5 -D OUTPUT -m comment \
        --comment winsvpn-killswitch -j "$KS_CHAIN" || break
    done
    "$IPT" -w 5 -F "$KS_CHAIN"
    "$IPT" -w 5 -X "$KS_CHAIN"
  done
  rm -f "$KS_STATE_FILE" "$SPLIT_STATE_DIR/kill-switch-ipv4" \
    "$SPLIT_STATE_DIR/kill-switch-ipv6"
  [ "$KS_FOREIGN" -eq 0 ] || return 66
}
winn3_ks_chain_state() {
  # $1 iptables or ip6tables. 0: the table lists without WINSVPN_KS3.
  # 1: WINSVPN_KS3 exists. 2: neither could be proven. A failed -nL is not
  # proof of absence (exit 4 is a busy xtables lock); only a table that lists
  # without the chain is.
  "$1" -w 5 -nL WINSVPN_KS3 >/dev/null 2>&1 && return 1
  KS3_TABLE="$("$1" -w 5 -S 2>/dev/null)" || return 2
  printf '%s\n' "$KS3_TABLE" | grep -q -x -e '-N WINSVPN_KS3' && return 1
  return 0
}
cleanup_winn3_kill_switch() {
  KS3_RC=0
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || continue
    winn3_ks_chain_state "$IPT"
    case $? in
      0) continue ;;
      1) ;;
      *) KS3_RC=1; continue ;;
    esac
    if ! winsvpn_chain_is_ours "$IPT" WINSVPN_KS3 winsvpn-killswitch3; then
      echo "Win's VPN refused to modify an unowned Linux firewall chain" >&2
      KS3_RC=66
      continue
    fi
    KS3_DETACHED=1
    while "$IPT" -w 5 -C OUTPUT -m comment --comment winsvpn-killswitch3 \
        -j WINSVPN_KS3 >/dev/null 2>&1; do
      "$IPT" -w 5 -D OUTPUT -m comment --comment winsvpn-killswitch3 \
        -j WINSVPN_KS3 || { KS3_DETACHED=0; break; }
    done
    # A failed -C ends the loop exactly as an absent rule does, so
    # detachment is proven only by an OUTPUT listing that succeeds and holds
    # no jump to the chain. Never flush a chain OUTPUT may still jump to: an
    # empty attached chain would turn the block into a pass-through.
    if [ "$KS3_DETACHED" -eq 1 ]; then
      KS3_OUTPUT="$("$IPT" -w 5 -S OUTPUT 2>/dev/null)" || KS3_DETACHED=0
    fi
    if [ "$KS3_DETACHED" -eq 1 ] && printf '%s\n' "$KS3_OUTPUT" | \
        grep -q -e ' -[jg] WINSVPN_KS3$' -e ' -[jg] WINSVPN_KS3 '; then
      KS3_DETACHED=0
    fi
    if [ "$KS3_DETACHED" -ne 1 ]; then
      KS3_RC=1
      continue
    fi
    "$IPT" -w 5 -F WINSVPN_KS3 || { KS3_RC=1; continue; }
    "$IPT" -w 5 -X WINSVPN_KS3 || KS3_RC=1
  done
  return "$KS3_RC"
}
append_ipv6_link_control() {
  [ "$1" = ip6tables ] || return 0
  # IPv6 carrier routes still need on-link neighbor discovery. Permit only
  # host router solicitations and neighbor solicitation/advertisement, with
  # the hop limit required by Neighbor Discovery. These cannot be forwarded.
  for ND_TYPE in 133 135 136; do
    "$1" -w 5 -A "$2" -p ipv6-icmp --icmpv6-type "$ND_TYPE" \
      -m hl --hl-eq 255 -m comment --comment "$3" -j RETURN || return 1
  done
}
build_winn3_ks_chain() {
  # $1 iptables or ip6tables. Fills the WINSVPN_KS3 that
  # configure_winn3_kill_switch has just created, ending in REJECT, while
  # nothing jumps to it yet.
  "$1" -w 5 -A WINSVPN_KS3 -o lo -m comment \
    --comment winsvpn-killswitch3 -j RETURN || return 1
  "$1" -w 5 -A WINSVPN_KS3 -o winsvpn3 -m comment \
    --comment winsvpn-killswitch3 -j RETURN || return 1
  if [ "$1" = iptables ]; then
    "$1" -w 5 -A WINSVPN_KS3 -p udp --sport 68 --dport 67 -m comment \
      --comment winsvpn-killswitch3 -j RETURN || return 1
  else
    "$1" -w 5 -A WINSVPN_KS3 -p udp --sport 546 --dport 547 -m comment \
      --comment winsvpn-killswitch3 -j RETURN || return 1
  fi
  if [ "$1" = "$WINN_IPT" ]; then
    # Only the configured gateway port, over udp (the class the served engine
    # dials) and tcp (the one it may migrate to on the same port).
    for WINN_PROTO in udp tcp; do
      "$1" -w 5 -A WINSVPN_KS3 -p "$WINN_PROTO" -d "$WINN_HOST" \
        --dport "$WINN_PORT" -m comment --comment winsvpn-killswitch3 \
        -j RETURN || return 1
    done
  fi
  append_ipv6_link_control "$1" WINSVPN_KS3 winsvpn-killswitch3 || return 1
  "$1" -w 5 -A WINSVPN_KS3 -m comment \
    --comment winsvpn-killswitch3 -j REJECT || return 1
}
configure_winn3_kill_switch() {
  parse_winn_endpoint || return $?
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || {
      echo "$IPT is required for the Winn v3 network block" >&2
      return 127
    }
    winn3_ks_chain_state "$IPT"
    case $? in
      0) ;;
      1)
        echo "A previous network block must be explicitly recovered before a new session." >&2
        return 75
        ;;
      *)
        echo "Win's VPN could not read the $IPT filter table" >&2
        return 1
        ;;
    esac
  done
  for IPT in iptables ip6tables; do
    # Only a chain this call created is ever flushed or deleted here. A failed
    # -N (a busy lock, or a chain another session created since the check)
    # touches nothing.
    "$IPT" -w 5 -N WINSVPN_KS3 || return 1
    if ! build_winn3_ks_chain "$IPT"; then
      # Created above and not attached, so removing it cannot open anything.
      # Whatever the other family already attached stays in place.
      "$IPT" -w 5 -F WINSVPN_KS3 >/dev/null 2>&1 || true
      "$IPT" -w 5 -X WINSVPN_KS3 >/dev/null 2>&1 || true
      return 1
    fi
    "$IPT" -w 5 -I OUTPUT 1 -m comment --comment winsvpn-killswitch3 \
      -j WINSVPN_KS3 || return 1
  done
}

kill_switch_restore_preflight() {
  for KS_RESTORE in iptables-restore ip6tables-restore; do
    command -v "$KS_RESTORE" >/dev/null 2>&1 || {
      echo "$KS_RESTORE is required for the Linux kill switch" >&2
      return 127
    }
    printf '*filter\nCOMMIT\n' |
      "$KS_RESTORE" -w 5 --noflush || {
        echo "$KS_RESTORE does not support the required restore invocation" >&2
        return 95
      }
  done
}

configure_kill_switch() {
  kill_switch_restore_preflight || return $?
  CONF="$1"
  AWG="$(find_awg || true)"
  [ -n "$AWG" ] || {
    echo "AmneziaWG is unavailable for the Linux kill switch" >&2
    return 127
  }
  ROUTING_MARK="$($AWG show "$NAME" fwmark 2>/dev/null || true)"
  printf '%s\n' "$ROUTING_MARK" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || {
    echo "Win's VPN could not verify the Linux kill-switch routing mark" >&2
    return 65
  }
  if printf '%s\n' "$ROUTING_MARK" | grep -Eq '^(0x0+|0+)$'; then
    echo "Win's VPN rejected an empty Linux kill-switch routing mark" >&2
    return 65
  fi
  cleanup_kill_switch || return $?
  install -d -m 700 "$SPLIT_STATE_DIR"
  KS_IPV4="$SPLIT_STATE_DIR/kill-switch-ipv4"
  KS_IPV6="$SPLIT_STATE_DIR/kill-switch-ipv6"
  : > "$KS_IPV4"
  : > "$KS_IPV6"
  chmod 600 "$KS_IPV4" "$KS_IPV6"
  awk '
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      section=tolower($0); gsub(/[[:space:]\[\]]/, "", section); next
    }
    section == "peer" {
      equals=index($0, "="); if (equals < 2) next
      key=tolower(trim(substr($0, 1, equals - 1)))
      if (key != "allowedips") next
      count=split(substr($0, equals + 1), values, ",")
      for (item_index=1; item_index <= count; item_index++) {
        value=trim(values[item_index]); if (value != "") print value
      }
    }
  ' "$CONF" | LC_ALL=C sort -u | while IFS= read -r CIDR; do
    case "$CIDR" in
      *:*)
        case "$CIDR" in *[!0-9A-Fa-f:./]*) exit 65 ;; esac
        printf '%s\n' "$CIDR" >> "$KS_IPV6"
        ;;
      *)
        case "$CIDR" in *[!0-9./]*) exit 65 ;; esac
        printf '%s\n' "$CIDR" >> "$KS_IPV4"
        ;;
    esac
  done || {
    echo "Win's VPN rejected unsafe Linux kill-switch routes" >&2
    rm -f "$KS_IPV4" "$KS_IPV6"
    return 65
  }
  [ -s "$KS_IPV4" ] || [ -s "$KS_IPV6" ] || {
    echo "Win's VPN rejected an empty Linux kill-switch route set" >&2
    rm -f "$KS_IPV4" "$KS_IPV6"
    return 65
  }
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || {
      echo "$IPT is required for the Linux kill switch" >&2
      rm -f "$KS_IPV4" "$KS_IPV6"
      return 127
    }
    if ! "$IPT" -m addrtype -h >/dev/null 2>&1 || \
      ! "$IPT" -m mark -h >/dev/null 2>&1 || \
      ! "$IPT" -m comment -h >/dev/null 2>&1; then
        echo "$IPT lacks required Linux kill-switch match support" >&2
        rm -f "$KS_IPV4" "$KS_IPV6"
        return 95
    fi
  done
  printf 'v1\n' > "$SPLIT_STATE_DIR/kill-switch-active"
  chmod 600 "$SPLIT_STATE_DIR/kill-switch-active"
  install_kill_switch_family() {
    IPT="$1"
    CIDR_FILE="$2"
    "$IPT" -w 5 -N WINSVPN_KS || return 1
    "$IPT" -w 5 -A WINSVPN_KS -o "$NAME" -m comment \
      --comment winsvpn-killswitch -j RETURN || return 1
    "$IPT" -w 5 -A WINSVPN_KS -m mark --mark "$ROUTING_MARK" \
      -m comment --comment winsvpn-killswitch -j RETURN || return 1
    append_ipv6_link_control "$IPT" WINSVPN_KS winsvpn-killswitch || return 1
    KS_BATCH="$CIDR_FILE.rules"
    : > "$KS_BATCH"
    chmod 600 "$KS_BATCH"
    printf '*filter\n' >> "$KS_BATCH"
    while IFS= read -r CIDR; do
      [ -n "$CIDR" ] || continue
      printf -- '-A WINSVPN_KS -d %s -m addrtype ! --dst-type LOCAL -m comment --comment winsvpn-killswitch -j REJECT\n' "$CIDR" >> "$KS_BATCH"
    done < "$CIDR_FILE"
    printf 'COMMIT\n' >> "$KS_BATCH"
    "$IPT-restore" -w 5 --noflush < "$KS_BATCH" || { rm -f "$KS_BATCH"; return 1; }
    rm -f "$KS_BATCH"
    if [ ! -s "$CIDR_FILE" ]; then
      # An IPv4-only AWG policy must not leave the physical IPv6 stack as an
      # unprotected escape route (and vice versa). Preserve only local traffic
      # when a family has no tunnel route; reject every non-local destination.
      "$IPT" -w 5 -A WINSVPN_KS -m addrtype ! --dst-type LOCAL \
        -m comment --comment winsvpn-killswitch-empty-family \
        -j REJECT || return 1
    fi
    "$IPT" -w 5 -A WINSVPN_KS -m comment \
      --comment winsvpn-killswitch -j RETURN || return 1
    "$IPT" -w 5 -I OUTPUT 1 -m comment \
      --comment winsvpn-killswitch -j WINSVPN_KS || return 1
  }
  install_kill_switch_family iptables "$KS_IPV4" || {
    cleanup_kill_switch
    return 1
  }
  install_kill_switch_family ip6tables "$KS_IPV6" || {
    cleanup_kill_switch
    return 1
  }
  rm -f "$KS_IPV4" "$KS_IPV6"
}
parse_reconnect_guard_endpoint() {
  awk '
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      section=tolower($0); gsub(/[[:space:]\[\]]/, "", section); next
    }
    section == "peer" {
      equals=index($0, "="); if (equals < 2) next
      key=tolower(trim(substr($0, 1, equals - 1)))
      if (key == "endpoint") { print trim(substr($0, equals + 1)); exit }
    }
  ' "$1"
}
resolve_reconnect_guard_targets() {
  # Prints "<ipv4|ipv6> <address> <port>" for every literal address the new
  # tunnel Endpoint in config $1 resolves to, so the transition guard can
  # allow exactly that handshake through while it is up. Anything absent,
  # ambiguous, or unresolvable prints nothing -- callers must treat silence
  # as "no bypass," which keeps the guard at its most restrictive rather
  # than ever opening it up.
  RG_RAW_ENDPOINT="$(parse_reconnect_guard_endpoint "$1")"
  [ -n "$RG_RAW_ENDPOINT" ] || return 0
  case "$RG_RAW_ENDPOINT" in
    \[*\]:*)
      RG_EP_HOST="${RG_RAW_ENDPOINT#\[}"
      RG_EP_HOST="${RG_EP_HOST%%\]:*}"
      RG_EP_PORT="${RG_RAW_ENDPOINT##*\]:}"
      ;;
    *:*:*)
      # A bare, unbracketed IPv6 literal has no unambiguous host/port split.
      # Win's VPN always brackets IPv6 endpoints when it writes configs; a
      # config that doesn't is treated as unresolvable rather than guessed.
      return 0
      ;;
    *:*)
      RG_EP_HOST="${RG_RAW_ENDPOINT%%:*}"
      RG_EP_PORT="${RG_RAW_ENDPOINT##*:}"
      ;;
    *)
      return 0
      ;;
  esac
  case "$RG_EP_PORT" in ''|*[!0-9]*) return 0 ;; esac
  [ "$RG_EP_PORT" -ge 1 ] && [ "$RG_EP_PORT" -le 65535 ] || return 0
  [ -n "$RG_EP_HOST" ] || return 0
  # getent resolves literal IPv4/IPv6 addresses as well as hostnames via the
  # same NSS path awg-quick itself relies on, so one lookup covers every
  # form the Endpoint can legally take. A failed lookup yields no target
  # (fail closed) instead of guessing at an address.
  getent ahosts "$RG_EP_HOST" 2>/dev/null | awk '{print $1}' | LC_ALL=C sort -u | \
    while IFS= read -r RG_ADDR; do
      [ -n "$RG_ADDR" ] || continue
      case "$RG_ADDR" in
        *[!0-9.]*) ;;
        *) printf 'ipv4 %s %s\n' "$RG_ADDR" "$RG_EP_PORT"; continue ;;
      esac
      case "$RG_ADDR" in
        *[!0-9A-Fa-f:]*) ;;
        *:*) printf 'ipv6 %s %s\n' "$RG_ADDR" "$RG_EP_PORT" ;;
      esac
    done
}
reconnect_guard_slot_chain() {
  case "$1" in
    A) printf '%s\n' WINSVPN_RGA ;;
    B) printf '%s\n' WINSVPN_RGB ;;
  esac
}
# Records that a teardown declined to touch a same-named chain it did not
# recognise. A global rather than a return value because `set -e` is in force
# and begin_reconnect_guard calls this function without checking its status;
# returning non-zero there would abort the whole script.
RG_TEARDOWN_REFUSED=0
reconnect_guard_teardown_slot() {
  RG_CHAIN="$(reconnect_guard_slot_chain "$1")"
  [ -n "$RG_CHAIN" ] || return 0
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || continue
    "$IPT" -w 5 -nL "$RG_CHAIN" >/dev/null 2>&1 || continue
    # The guard chain is as total a block as the kill switch is -- it REJECTs
    # everything that is not loopback, already-established, DHCP or the tunnel
    # endpoint -- and it is restored across a reboot by exactly the same
    # persistent-firewall setups. It gets the same content-based ownership test
    # for the same reason.
    if ! winsvpn_chain_is_ours "$IPT" "$RG_CHAIN" winsvpn-reconnect-guard; then
      echo "Win's VPN refused to modify an unowned Linux firewall chain" >&2
      RG_TEARDOWN_REFUSED=1
      continue
    fi
    while "$IPT" -w 5 -C OUTPUT -m comment \
      --comment winsvpn-reconnect-guard -j "$RG_CHAIN" >/dev/null 2>&1; do
      "$IPT" -w 5 -D OUTPUT -m comment \
        --comment winsvpn-reconnect-guard -j "$RG_CHAIN" || break
    done
    "$IPT" -w 5 -F "$RG_CHAIN" >/dev/null 2>&1 || true
    "$IPT" -w 5 -X "$RG_CHAIN" >/dev/null 2>&1 || true
  done
}
# The reconnect guard is a short-lived, maximally-restrictive ruleset that
# must cover the entire window between tearing down the previous
# tunnel/kill-switch and the new kill-switch being fully installed, so a
# host never has an unprotected instant during reconnect. iptables has no
# atomic "replace chain contents" primitive, so begin_reconnect_guard
# alternates between two fixed chain slots: the unused slot is always built
# fresh and jumped-to from OUTPUT *before* any previously active slot's
# jump is removed, so at least one fully populated guard chain is live at
# all times. On any failure the newly built slot is left jumped-to (fail
# closed) instead of being rolled back; only a caller that reaches full
# kill-switch protection should ever call cleanup_reconnect_guard.
begin_reconnect_guard() {
  CONF="$1"
  RG_STATE_FILE="$SPLIT_STATE_DIR/reconnect-guard-active"
  RG_ACTIVE_SLOT=
  if [ -e "$RG_STATE_FILE" ] || [ -L "$RG_STATE_FILE" ]; then
    if [ ! -f "$RG_STATE_FILE" ] || [ -L "$RG_STATE_FILE" ]; then
      echo "Win's VPN rejected unsafe Linux reconnect-guard state" >&2
      return 65
    fi
    case "$(cat "$RG_STATE_FILE")" in
      v1:A) RG_ACTIVE_SLOT=A ;;
      v1:B) RG_ACTIVE_SLOT=B ;;
      *)
        echo "Win's VPN rejected unknown Linux reconnect-guard state" >&2
        return 65
        ;;
    esac
  fi
  case "$RG_ACTIVE_SLOT" in
    A) RG_TARGET_SLOT=B ;;
    *) RG_TARGET_SLOT=A ;;
  esac
  RG_TARGET_CHAIN="$(reconnect_guard_slot_chain "$RG_TARGET_SLOT")"
  install -d -m 700 "$SPLIT_STATE_DIR"
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || {
      echo "$IPT is required for the Linux reconnect guard" >&2
      return 127
    }
    if ! "$IPT" -m conntrack -h >/dev/null 2>&1 || \
      ! "$IPT" -m comment -h >/dev/null 2>&1; then
        echo "$IPT lacks required Linux reconnect-guard match support" >&2
        return 95
    fi
  done
  # The target slot is, by construction, never the slot OUTPUT currently
  # jumps to, so rebuilding it from scratch cannot remove live protection.
  reconnect_guard_teardown_slot "$RG_TARGET_SLOT"
  for IPT in iptables ip6tables; do
    "$IPT" -w 5 -N "$RG_TARGET_CHAIN" || return 1
    "$IPT" -w 5 -A "$RG_TARGET_CHAIN" -o lo -m comment \
      --comment winsvpn-reconnect-guard -j RETURN || return 1
    "$IPT" -w 5 -A "$RG_TARGET_CHAIN" -o "$NAME" -m comment \
      --comment winsvpn-reconnect-guard -j RETURN || return 1
    if [ "$IPT" = iptables ]; then
      "$IPT" -w 5 -A "$RG_TARGET_CHAIN" -p udp --sport 68 --dport 67 \
        -m comment --comment winsvpn-reconnect-guard-dhcp -j RETURN || return 1
    else
      "$IPT" -w 5 -A "$RG_TARGET_CHAIN" -p udp --sport 546 --dport 547 \
        -m comment --comment winsvpn-reconnect-guard-dhcp -j RETURN || return 1
    fi
  done
  resolve_reconnect_guard_targets "$CONF" | \
    while IFS=' ' read -r RG_FAMILY RG_ADDR RG_PORT; do
      [ -n "$RG_FAMILY" ] && [ -n "$RG_ADDR" ] && [ -n "$RG_PORT" ] || continue
      case "$RG_FAMILY" in
        ipv4) RG_TARGET_IPT=iptables ;;
        ipv6) RG_TARGET_IPT=ip6tables ;;
        *) continue ;;
      esac
      "$RG_TARGET_IPT" -w 5 -A "$RG_TARGET_CHAIN" -d "$RG_ADDR" -p udp \
        --dport "$RG_PORT" -m comment \
        --comment winsvpn-reconnect-guard-endpoint -j RETURN || exit 1
    done || return 1
  for IPT in iptables ip6tables; do
    append_ipv6_link_control "$IPT" "$RG_TARGET_CHAIN" winsvpn-reconnect-guard || return 1
    "$IPT" -w 5 -A "$RG_TARGET_CHAIN" -m comment \
      --comment winsvpn-reconnect-guard -j REJECT || return 1
    "$IPT" -w 5 -I OUTPUT 1 -m comment \
      --comment winsvpn-reconnect-guard -j "$RG_TARGET_CHAIN" || return 1
  done
  printf 'v1:%s\n' "$RG_TARGET_SLOT" > "$RG_STATE_FILE"
  chmod 600 "$RG_STATE_FILE"
  # The new slot's jump is now live, so any other slot left over from a
  # prior crashed/aborted attempt is redundant and safe to remove.
  for RG_OTHER_SLOT in A B; do
    [ "$RG_OTHER_SLOT" != "$RG_TARGET_SLOT" ] || continue
    reconnect_guard_teardown_slot "$RG_OTHER_SLOT"
  done
}
cleanup_reconnect_guard() {
  RG_STATE_FILE="$SPLIT_STATE_DIR/reconnect-guard-active"
  # Advisory only, exactly as in cleanup_kill_switch: an unreadable or
  # unrecognised marker must not be able to keep a REJECT-everything chain
  # installed on a user's host. Ownership is decided per chain, by content.
  if [ -L "$RG_STATE_FILE" ] || \
    { [ -e "$RG_STATE_FILE" ] && [ ! -f "$RG_STATE_FILE" ]; }; then
    echo "Win's VPN ignored unsafe Linux reconnect-guard state" >&2
  fi
  RG_TEARDOWN_REFUSED=0
  reconnect_guard_teardown_slot A
  reconnect_guard_teardown_slot B
  rm -f "$RG_STATE_FILE"
  [ "$RG_TEARDOWN_REFUSED" -eq 0 ] || return 66
}
cleanup_split_rules() {
  cleanup_split_bpf
  CGROUP_FILE="$SPLIT_STATE_DIR/app-bypass-cgroup"
  MARK_FILE="$SPLIT_STATE_DIR/app-bypass-mark"
  if [ ! -s "$CGROUP_FILE" ] || [ ! -s "$MARK_FILE" ]; then
    rm -f "$CGROUP_FILE" "$MARK_FILE"
    return 0
  fi
  CGROUP_PATH="$(cat "$CGROUP_FILE")"
  ROUTING_MARK="$(cat "$MARK_FILE")"
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || continue
    for PROTO in udp tcp; do
      while "$IPT" -w 5 -t mangle -C OUTPUT -m cgroup --path "$CGROUP_PATH" \
        -p "$PROTO" --dport 53 -m comment \
        --comment winsvpn-app-bypass-dns-clear -j MARK --set-mark 0 \
        >/dev/null 2>&1; do
        "$IPT" -w 5 -t mangle -D OUTPUT -m cgroup --path "$CGROUP_PATH" \
          -p "$PROTO" --dport 53 -m comment \
          --comment winsvpn-app-bypass-dns-clear -j MARK --set-mark 0
      done
      while "$IPT" -w 5 -t mangle -C OUTPUT -m cgroup --path "$CGROUP_PATH" \
        -p "$PROTO" --dport 53 -m comment \
        --comment winsvpn-app-bypass-dns-return -j RETURN >/dev/null 2>&1; do
        "$IPT" -w 5 -t mangle -D OUTPUT -m cgroup --path "$CGROUP_PATH" \
          -p "$PROTO" --dport 53 -m comment \
          --comment winsvpn-app-bypass-dns-return -j RETURN
      done
    done
    while "$IPT" -w 5 -t mangle -C OUTPUT -m cgroup --path "$CGROUP_PATH" \
      -m comment --comment winsvpn-app-bypass-connmark \
      -j CONNMARK --save-mark >/dev/null 2>&1; do
      "$IPT" -w 5 -t mangle -D OUTPUT -m cgroup --path "$CGROUP_PATH" \
        -m comment --comment winsvpn-app-bypass-connmark \
        -j CONNMARK --save-mark
    done
    while "$IPT" -w 5 -t mangle -C OUTPUT -m cgroup --path "$CGROUP_PATH" \
      -m comment --comment winsvpn-app-bypass -j MARK --set-mark "$ROUTING_MARK" \
      >/dev/null 2>&1; do
      "$IPT" -w 5 -t mangle -D OUTPUT -m cgroup --path "$CGROUP_PATH" \
        -m comment --comment winsvpn-app-bypass -j MARK --set-mark "$ROUTING_MARK"
    done
    while "$IPT" -w 5 -t mangle -C PREROUTING -m connmark \
      --mark "$ROUTING_MARK" -m comment \
      --comment winsvpn-app-bypass-connmark -j CONNMARK --restore-mark \
      >/dev/null 2>&1; do
      "$IPT" -w 5 -t mangle -D PREROUTING -m connmark \
        --mark "$ROUTING_MARK" -m comment \
        --comment winsvpn-app-bypass-connmark -j CONNMARK --restore-mark
    done
  done
  rm -f "$CGROUP_FILE" "$MARK_FILE"
}
configure_split_rules() {
  CGROUP_PATH="${1#/}"
  MONITOR_PID="${2:-$APP_PID}"
  case "$CGROUP_PATH" in
    ''|*..*|*[!A-Za-z0-9_.@/-]*)
      echo "Win's VPN rejected an unsafe Linux bypass cgroup path" >&2
      return 65
      ;;
  esac
  case "$MONITOR_PID" in
    ''|*[!0-9]*)
      echo "Win's VPN rejected an invalid split-helper monitor PID" >&2
      return 65
      ;;
  esac
  [ "$MONITOR_PID" -gt 1 ] && [ -e "/proc/$MONITOR_PID" ] || {
    echo "The Win's VPN GUI process is unavailable for fail-safe split monitoring" >&2
    return 65
  }
  BPF_HELPER="$BUNDLE_DIR/winsvpn-bypass-bpf"
  BPF_CGROUP="/sys/fs/cgroup/$CGROUP_PATH"
  [ -f "$BPF_HELPER" ] && [ ! -L "$BPF_HELPER" ] && [ -x "$BPF_HELPER" ] || {
    echo "The bundled Linux split-tunnel BPF helper is missing or unsafe" >&2
    return 65
  }
  # M-10: the BPF helper is executed as root by exact path here regardless of
  # BUNDLE_READY, so it needs its own trust check even when no AmneziaWG tools
  # were bundled. Refuse a bundle directory that is not root-owned/non-writable,
  # and enforce a pinned hash when the release build injected one.
  validate_root_owned_path "$BUNDLE_DIR" || {
    echo "Win's VPN refused to run the split-tunnel BPF helper from a non-root-owned or writable bundle directory" >&2
    return 65
  }
  validate_root_owned_path "$BPF_HELPER" || {
    echo "Win's VPN refused a non-root-owned or writable split-tunnel BPF helper" >&2
    return 65
  }
  if [ -n "$WINSVPN_BPF_EXPECTED_SHA256" ]; then
    verify_bundle_hash winsvpn-bypass-bpf "$WINSVPN_BPF_EXPECTED_SHA256" || return 65
  fi
  [ -d "$BPF_CGROUP" ] && [ ! -L "$BPF_CGROUP" ] || {
    echo "The Linux split-tunnel cgroup is not active" >&2
    return 65
  }
  AWG="$(find_awg || true)"
  if [ -z "$AWG" ]; then
    echo "AmneziaWG userspace tool is unavailable for split-tunnel routing" >&2
    return 127
  fi
  ROUTING_MARK="$($AWG show "$NAME" fwmark 2>/dev/null || true)"
  printf '%s\n' "$ROUTING_MARK" | grep -Eq '^(0x[0-9A-Fa-f]+|[0-9]+)$' || {
    echo "Win's VPN could not verify the AmneziaWG routing mark" >&2
    return 65
  }
  [ -n "$ROUTING_MARK" ] && [ "$ROUTING_MARK" != "0" ] || {
    echo "AmneziaWG did not publish a usable routing mark" >&2
    return 65
  }
  for IPT in iptables ip6tables; do
    command -v "$IPT" >/dev/null 2>&1 || {
      echo "$IPT is required for Linux per-app split tunneling" >&2
      return 127
    }
    "$IPT" -m cgroup -h >/dev/null 2>&1 || {
      echo "The kernel xt_cgroup matcher is required for Linux per-app split tunneling" >&2
      return 95
    }
  done
  cleanup_split_rules
  install -d -m 700 "$SPLIT_STATE_DIR"
  printf '%s\n' "$CGROUP_PATH" > "$SPLIT_STATE_DIR/app-bypass-cgroup"
  printf '%s\n' "$ROUTING_MARK" > "$SPLIT_STATE_DIR/app-bypass-mark"
  chmod 600 "$SPLIT_STATE_DIR/app-bypass-cgroup" "$SPLIT_STATE_DIR/app-bypass-mark"
  install_split_rules() {
    IPT="$1"
    "$IPT" -w 5 -t mangle -I OUTPUT 1 -m cgroup --path "$CGROUP_PATH" \
      -m comment --comment winsvpn-app-bypass \
      -j MARK --set-mark "$ROUTING_MARK"
    "$IPT" -w 5 -t mangle -I OUTPUT 2 -m cgroup --path "$CGROUP_PATH" \
      -m comment --comment winsvpn-app-bypass-connmark \
      -j CONNMARK --save-mark
    "$IPT" -w 5 -t mangle -I PREROUTING 1 -m connmark \
      --mark "$ROUTING_MARK" -m comment \
      --comment winsvpn-app-bypass-connmark -j CONNMARK --restore-mark
    # The BPF hook marks sockets before their first route lookup. Clear only
    # resolver packets, then stop traversal before the general cgroup MARK, so
    # system DNS stays protected while every selected-app destination bypasses.
    for PROTO in udp tcp; do
      "$IPT" -w 5 -t mangle -I OUTPUT 1 -m cgroup --path "$CGROUP_PATH" \
        -p "$PROTO" --dport 53 -m comment \
        --comment winsvpn-app-bypass-dns-return -j RETURN
      "$IPT" -w 5 -t mangle -I OUTPUT 1 -m cgroup --path "$CGROUP_PATH" \
        -p "$PROTO" --dport 53 -m comment \
        --comment winsvpn-app-bypass-dns-clear -j MARK --set-mark 0
    done
  }
  install_split_rules iptables || { cleanup_split_rules; return 1; }
  install_split_rules ip6tables || { cleanup_split_rules; return 1; }

  BPF_PID_FILE="$SPLIT_STATE_DIR/app-bypass-bpf.pid"
  BPF_LOG_FILE="$SPLIT_STATE_DIR/app-bypass-bpf.log"
  : > "$BPF_LOG_FILE"
  chmod 600 "$BPF_LOG_FILE"
  "$BPF_HELPER" --cgroup "$BPF_CGROUP" --mark "$ROUTING_MARK" \
    --monitor-pid "$MONITOR_PID" > "$BPF_LOG_FILE" 2>&1 &
  bpf_pid=$!
  printf '%s\n' "$bpf_pid" > "$BPF_PID_FILE"
  chmod 600 "$BPF_PID_FILE"
  count=0
  while ! grep -qx READY "$BPF_LOG_FILE" 2>/dev/null && \
    kill -0 "$bpf_pid" >/dev/null 2>&1 && [ "$count" -lt 20 ]; do
    sleep 0.1
    count=$((count + 1))
  done
  if ! grep -qx READY "$BPF_LOG_FILE" 2>/dev/null || \
    ! kill -0 "$bpf_pid" >/dev/null 2>&1; then
    tail -n 20 "$BPF_LOG_FILE" >&2 || true
    cleanup_split_rules
    echo "Linux could not attach the fail-safe per-app socket-mark BPF link" >&2
    return 95
  fi
}
validate_config() {
  awk '
    function trim(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); return v }
    /^[[:space:]]*($|#|;)/ { next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      section=tolower($0); gsub(/[[:space:]\[\]]/, "", section)
      if (section == "interface") interfaces++
      else if (section == "peer") peers++
      else exit 65
      next
    }
    {
      equals=index($0, "="); if (equals < 2) exit 65
      key=tolower(trim(substr($0, 1, equals - 1)))
      if (section == "interface") {
        if (key !~ /^(privatekey|address|mtu|dns|listenport|jc|jmin|jmax|s1|s2|s3|s4|h1|h2|h3|h4)$/) exit 65
        if (key == "listenport") {
          value=trim(substr($0, equals + 1))
          if (value !~ /^[0-9]+$/ || value + 0 < 1024 || value + 0 > 65535) exit 65
        }
      } else if (section == "peer") {
        if (key !~ /^(publickey|presharedkey|endpoint|allowedips|persistentkeepalive)$/) exit 65
      } else exit 65
    }
    END { if (interfaces != 1 || peers != 1) exit 65 }
  ' "$1"
}
# The winsvpn3 tun is this app's only when DESKTOP-8 created it persistent and
# owned by the requesting user: the tun driver reports that uid in
# /sys/class/net/winsvpn3/owner (-1 when unset; absent on any non-tun
# device). Nothing else named winsvpn3 is ever deleted or taken down here.
winn3_tun_ours() {
  WINN3_REQUESTER="${PKEXEC_UID:-${SUDO_UID:-}}"
  [ -n "$WINN3_REQUESTER" ] || return 1
  WINN3_TUN_HAS="$(cat /sys/class/net/winsvpn3/owner 2>/dev/null)" || return 1
  [ "$WINN3_TUN_HAS" = "$WINN3_REQUESTER" ]
}
# 0 when the link may be changed: no winsvpn3 exists, root itself is the
# caller (a root GUI's engine opens its own non-persistent tun, and no
# requesting uid exists), or the device is ours as above.
winn3_tun_mutable() {
  [ -e /sys/class/net/winsvpn3 ] || return 0
  [ -n "${PKEXEC_UID:-${SUDO_UID:-}}" ] || return 0
  winn3_tun_ours
}

case "${1:-}" in
  start)
    CONF_SRC="${2:-}"
    BYPASS_CGROUP="${3:-}"
    if [ -z "$CONF_SRC" ] || [ ! -s "$CONF_SRC" ]; then
      echo "Win's VPN config missing" >&2; exit 64
    fi
    validate_config "$CONF_SRC" || {
      echo "Win's VPN rejected unsafe or malformed AWG config" >&2; exit 65
    }
    TOOL="$(find_awg_quick || true)"
    if [ -z "$TOOL" ]; then
      echo "AmneziaWG tools are neither bundled nor installed on this Linux host." >&2; exit 127
    fi
    install -d -m 700 "$CONF_DIR"
    install -m 600 "$CONF_SRC" "$CONF_DST"
    validate_config "$CONF_DST" || { rm -f "$CONF_DST"; exit 65; }
    # Refuse an unsupported restore tool before any existing protection or
    # tunnel is torn down (DESKTOP-28).
    kill_switch_restore_preflight || { KS_RC=$?; rm -f "$CONF_DST"; exit "$KS_RC"; }
    # Install the transition guard before touching the previous tunnel or
    # kill switch. It stays fail-closed for the rest of this case on any
    # error below, and is only relaxed once the real kill switch for the
    # new tunnel is confirmed active.
    begin_reconnect_guard "$CONF_DST" || { rm -f "$CONF_DST"; exit 65; }
    cleanup_split_rules
    cleanup_xray_transport
    cleanup_winn_transport
    "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true
    # Propagate the real status. 66 means a same-named chain on this host is
    # not ours, which needs its own message rather than the generic one -- it
    # is the single case the app cannot resolve for the user itself.
    cleanup_kill_switch || { KS_RC=$?; rm -f "$CONF_DST"; exit "$KS_RC"; }
    cleanup_winn3_kill_switch || { KS_RC=$?; rm -f "$CONF_DST"; exit "$KS_RC"; }
    configure_xray_transport || {
      cleanup_xray_transport
      rm -f "$CONF_DST"
      exit 1
    }
    "$TOOL" up "$CONF_DST" || {
      cleanup_xray_transport
      rm -f "$CONF_DST"
      exit 1
    }
    configure_kill_switch "$CONF_DST" || {
      "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true
      cleanup_kill_switch || true
      cleanup_xray_transport
      rm -f "$CONF_DST"
      exit 65
    }
    activate_xray_transport || {
      cleanup_xray_transport
      "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true
      cleanup_kill_switch || true
      rm -f "$CONF_DST"
      exit 65
    }
    # The Winn outer-socket exclusion. It must come after awg-quick is up
    # (there is no fwmark to read before that) and after the kill switch is
    # installed (its mark-RETURN rule is half of what makes the exclusion
    # work). A failure here tears the tunnel down rather than leaving a
    # winn/3 start running with its transport inside its own tunnel.
    activate_winn_transport || {
      cleanup_winn_transport
      cleanup_xray_transport
      "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true
      cleanup_kill_switch || true
      rm -f "$CONF_DST"
      exit 65
    }
    if [ -n "$BYPASS_CGROUP" ]; then
      configure_split_rules "$BYPASS_CGROUP" "$APP_PID" || {
        cleanup_winn_transport
        cleanup_xray_transport
        "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true
        cleanup_kill_switch || true
        rm -f "$CONF_DST"
        exit 65
      }
    fi
    # Every fallible setup step has succeeded, so the persistent kill switch
    # now covers the same protective role and the transition guard can be
    # relaxed. The failure arms above remove the tunnel and its kill switch;
    # keeping the guard until here leaves them fail-closed. Best-effort only:
    # a redundant guard chain would simply remain stacked on top of the kill
    # switch until the next start/stop.
    cleanup_reconnect_guard || true
    ;;
  stop)
    cleanup_split_rules
    cleanup_xray_transport
    cleanup_winn_transport
    TOOL="$(find_awg_quick || true)"
    if [ -n "$TOOL" ]; then "$TOOL" down "$CONF_DST" >/dev/null 2>&1 || true; fi
    # An explicit stop is the user's way back to a working network, so it must
    # remove everything it can and report afterwards. These two teardowns used
    # to be chained with `|| exit $?`, which meant a kill switch this script
    # declined to touch also prevented the reconnect guard from being removed
    # -- and the guard REJECTs everything by itself, so the host stayed fully
    # offline even after the kill switch was cleared by hand. One blocking
    # chain we cannot remove must never stop us removing the other one we can.
    STOP_RC=0
    cleanup_kill_switch || STOP_RC=$?
    cleanup_reconnect_guard || STOP_RC=$?
    cleanup_winn3_kill_switch || STOP_RC=$?
    rm -f "$CONF_DST"
    ip link delete "$NAME" >/dev/null 2>&1 || true
    if [ -r /sys/class/net/winsvpn3/owner ]; then
      WINN3_TUN_OWNER="$(cat /sys/class/net/winsvpn3/owner 2>/dev/null || true)"
      WINN3_REQUESTER="${PKEXEC_UID:-${SUDO_UID:-}}"
      if [ -n "$WINN3_REQUESTER" ] && [ "$WINN3_TUN_OWNER" = "$WINN3_REQUESTER" ]; then
        ip link delete winsvpn3 >/dev/null 2>&1 || true
      fi
    fi
    [ "$STOP_RC" -eq 0 ] || exit "$STOP_RC"
    ;;
  winn3-posture)
    # The Winn Protocol v3 privileged executor: runs ONE allowlisted argument
    # vector as root, feeding $3 to its standard input.
    #
    # NOT a generic run-any-argv-as-root surface, and deliberately shaped so it
    # cannot become one. The host flattens a rendered `ip`/`resolvectl`/
    # `resolvconf`/`mkdir`/`cp`/`tee`/`rm`/`test` vector to a space-joined
    # base64 blob ($2, transport-safe because every element was validated to
    # contain no whitespace before it was encoded) and the stdin payload to a
    # second base64 blob ($3). Here it is decoded, word-split by IFS only, and
    # RE-CHECKED against the same allowlist before one command runs -- so a
    # broken or compromised host cannot make root run anything outside the set,
    # and a shell string is never parsed as shell (compare every other action
    # in this script, which builds whole `sh -c` bodies by hand; the v3 posture
    # exists to remove exactly that string-construction surface).
    WINN3_ARGV_B64="${2:-}"
    WINN3_STDIN_B64="${3:-}"
    [ -n "$WINN3_ARGV_B64" ] || {
      echo "Win's VPN refused an empty Winn Protocol v3 privileged command" >&2
      exit 65
    }
    mkdir -p "$SPLIT_STATE_DIR" 2>/dev/null || true
    WINN3_STDIN_TXT="$SPLIT_STATE_DIR/winn3-posture-stdin.$$"
    if printf '%s' "$WINN3_STDIN_B64" | base64 -d > "$WINN3_STDIN_TXT" 2>/dev/null; then
      :
    else
      rm -f "$WINN3_STDIN_TXT"
      echo "Win's VPN could not decode the Winn Protocol v3 command input" >&2
      exit 65
    fi
    WINN3_DECODED="$(printf '%s' "$WINN3_ARGV_B64" | base64 -d 2>/dev/null || true)"
    WINN3_DECODED="$(printf '%s' "$WINN3_DECODED" | tr -d '\r')"
    if [ -z "$WINN3_DECODED" ]; then
      rm -f "$WINN3_STDIN_TXT"
      echo "Win's VPN could not decode the Winn Protocol v3 command" >&2
      exit 65
    fi
    # Disable globbing so word-splitting cannot also expand `*`/`?`/`[]`.
    set -f
    # shellcheck disable=SC2086
    set -- $WINN3_DECODED
    [ "$#" -ge 1 ] || {
      rm -f "$WINN3_STDIN_TXT"
      echo "Win's VPN refused an empty Winn Protocol v3 command after decode" >&2
      exit 65
    }
    case "$1" in
      ip)
        # The rendered family flag: `ip -4 route add ...` / `ip -6 address add
        # ...` puts the flag at $2, so the subcommand to check is $3 there and
        # $2 in the unflagged `ip route add ...` / `ip link ...` shapes. The
        # C++ Winn3PostureAllowArgv applies the identical rule; a command that
        # passes one of the two and fails the other is a defect, not a feature.
        if [ "${2:-}" = "-4" ] || [ "${2:-}" = "-6" ]; then
          WINN3_IP_SUB="${3:-}"
        else
          WINN3_IP_SUB="${2:-}"
        fi
        case "$WINN3_IP_SUB" in
          route|address) ;;
          link)
            # The two destructive shapes the v3 teardown renders
            # (linux_winn3_host.cc:2380, 2384). A winsvpn3 this app did not
            # create for the requesting user is left alone.
            if { [ "$#" -eq 5 ] && [ "$3" = delete ] && [ "$4" = dev ] && \
                 [ "$5" = winsvpn3 ]; } || \
               { [ "$#" -eq 6 ] && [ "$3" = set ] && [ "$4" = dev ] && \
                 [ "$5" = winsvpn3 ] && [ "$6" = down ]; }; then
              winn3_tun_mutable || {
                echo "Win's VPN refused to change a winsvpn3 device it did not create for this user" >&2
                rm -f "$WINN3_STDIN_TXT"; exit 66
              }
            fi
            ;;
          tuntap)
            WINN3_TUN_OWNER="${PKEXEC_UID:-${SUDO_UID:-}}"
            if [ "$#" -eq 11 ] && [ "$3" = add ] && [ "$4" = dev ] && \
               [ "$5" = winsvpn3 ] && [ "$6" = mode ] && [ "$7" = tun ] && \
               [ "$8" = user ] && [ "${10}" = group ]; then
              case "$9:${11}" in *[!0-9:]*|:*|*:) echo "Win's VPN refused a tuntap owner" >&2
                rm -f "$WINN3_STDIN_TXT"; exit 65 ;; esac
              if [ -z "$WINN3_TUN_OWNER" ] || [ "$9" != "$WINN3_TUN_OWNER" ]; then
                echo "Win's VPN refused a tun owner other than the requesting user" >&2
                rm -f "$WINN3_STDIN_TXT"; exit 65
              fi
            elif [ "$#" -eq 7 ] && [ "$3" = del ] && [ "$4" = dev ] && \
                 [ "$5" = winsvpn3 ] && [ "$6" = mode ] && [ "$7" = tun ]; then
              if [ ! -e /sys/class/net/winsvpn3 ]; then
                rm -f "$WINN3_STDIN_TXT"; exit 0
              fi
              winn3_tun_ours || {
                echo "Win's VPN refused to delete a winsvpn3 device it did not create for this user" >&2
                rm -f "$WINN3_STDIN_TXT"; exit 66
              }
            else
              echo "Win's VPN refused an ip tuntap shape" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            fi
            ;;
          *) echo "Win's VPN refused an ip subcommand outside route/address/link/tuntap" >&2
             rm -f "$WINN3_STDIN_TXT"; exit 65 ;;
        esac
        ;;
      resolvectl)
        # `--no-pager status` is the systemd-resolved mechanism probe, and it
        # runs through this same runner, so it is allowlisted beside the three
        # installing subcommands. A bare `resolvectl` with NO subcommand is
        # refused here too (the host Winn3PostureAllowArgv refuses it): the two
        # sides must accept the same closed vocabulary, and a bare binary name
        # is not part of it.
        if [ "$#" -eq 3 ] && [ "$2" = "--no-pager" ] && [ "$3" = "status" ]; then
          :
        elif [ "$#" -ge 2 ]; then
          case "$2" in
            dns|domain|revert) ;;
            *) echo "Win's VPN refused a resolvectl subcommand outside dns/domain/revert" >&2
               rm -f "$WINN3_STDIN_TXT"; exit 65 ;;
          esac
        else
          echo "Win's VPN refused a resolvectl subcommand outside dns/domain/revert" >&2
          rm -f "$WINN3_STDIN_TXT"; exit 65
        fi
        ;;
      resolvconf)
        # `-l` is the openresolv mechanism probe; `-a`/`-d` install/remove. A
        # bare `resolvconf` with NO flag is refused here for the same reason as
        # a bare `resolvectl` above: both sides must accept the same closed set.
        if [ "$#" -ge 2 ]; then
          case "$2" in
            -a|-d) ;;
            -l) [ "$#" -eq 2 ] || {
                  echo "Win's VPN refused a resolvconf subcommand outside -a/-d" >&2
                  rm -f "$WINN3_STDIN_TXT"; exit 65
                }
                ;;
            *) echo "Win's VPN refused a resolvconf subcommand outside -a/-d" >&2
               rm -f "$WINN3_STDIN_TXT"; exit 65 ;;
          esac
        else
          echo "Win's VPN refused a resolvconf subcommand outside -a/-d" >&2
          rm -f "$WINN3_STDIN_TXT"; exit 65
        fi
        ;;
      mkdir|cp|tee|rm|test)
        # Closed file/copy vocabulary rendered by this component only, and each
        # verb is ALSO shape-checked so none of them can serve as a
        # run-anything root re-entry. Kept identical to Winn3PostureAllowArgv in
        # C++: a vector that passes one and fails the other is a defect.
        case "$1" in
          mkdir)
            [ "$#" -eq 3 ] && [ "$2" = "-p" ] && [ "$3" = "/var/lib/winsvpn" ] || {
              echo "Win's VPN refused a mkdir outside -p /var/lib/winsvpn" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            }
            ;;
          cp)
            # Only the two directions between the backup and /etc/resolv.conf.
            # Any other cp destination would let a broken host write wherever
            # root can -- the exact escalation the path pin removes.
            {
              [ "$#" -eq 4 ] && [ "$2" = "-f" ] && \
                [ "$3" = "/var/lib/winsvpn/winn3-resolv.conf.orig" ] && \
                [ "$4" = "/etc/resolv.conf" ]
            } || {
              [ "$#" -eq 4 ] && [ "$2" = "-f" ] && \
                [ "$3" = "/etc/resolv.conf" ] && \
                [ "$4" = "/var/lib/winsvpn/winn3-resolv.conf.orig" ]
            } || {
              echo "Win's VPN refused a cp outside the resolv.conf backup shapes" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            }
            ;;
          tee)
            [ "$#" -eq 2 ] && [ "$2" = "/etc/resolv.conf" ] || {
              echo "Win's VPN refused a tee outside /etc/resolv.conf" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            }
            ;;
          rm)
            [ "$#" -eq 3 ] && [ "$2" = "-f" ] && \
              [ "$3" = "/var/lib/winsvpn/winn3-resolv.conf.orig" ] || {
              echo "Win's VPN refused an rm outside -f /var/lib/winsvpn/winn3-resolv.conf.orig" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            }
            ;;
          test)
            [ "$#" -eq 3 ] && { [ "$2" = "-h" ] || [ "$2" = "-f" ]; } && \
              [ "$3" = "/etc/resolv.conf" ] || {
              echo "Win's VPN refused a test outside -h|-f /etc/resolv.conf" >&2
              rm -f "$WINN3_STDIN_TXT"; exit 65
            }
            ;;
        esac
        ;;
      *)
        echo "Win's VPN refused a non-allowlisted Winn Protocol v3 privileged command: $1" >&2
        rm -f "$WINN3_STDIN_TXT"
        exit 65
        ;;
    esac
    if [ "$1" = "test" ]; then
      "$@" 2>&1
    else
      "$@" < "$WINN3_STDIN_TXT" 2>&1
    fi
    WINN3_RC=$?
    rm -f "$WINN3_STDIN_TXT"
    exit "$WINN3_RC"
    ;;
  winn3-ks-on)
    configure_winn3_kill_switch || exit $?
    ;;
  winn3-ks-off)
    cleanup_winn3_kill_switch || exit $?
    ;;
  *)
    echo "Usage: winsvpn-helper start <config> [bypass-cgroup]|stop|winn3-posture" >&2
    exit 64
    ;;
esac
)WINS";
}

int RunPrivilegedTunnelCommand(const std::string& action,
                               const std::string& config_path = "",
                               const std::string& cgroup_path = "",
                               const std::string& winn_endpoint = "") {
  // Re-validated here rather than trusted. The Dart dispatch already refuses a
  // non-literal endpoint and ParseLinuxWinnSection refuses it again, but this
  // string is about to cross into a ROOT context, so it is checked once more
  // at the boundary it actually crosses.
  std::string winn_host;
  std::string winn_port;
  const std::string winn_argument =
      winn_endpoint.empty() ||
              !winsvpn::winn::SplitLinuxWinnEndpoint(winn_endpoint, &winn_host,
                                                     &winn_port)
          ? std::string()
          : winn_endpoint;
  const std::vector<std::string> elevator = PrivilegedRunner();
  // B-APP-004: the privileged invocation is an ARGV VECTOR, never a composed
  // command string. The elevator (sudo -n / pkexec) runs /bin/sh with the
  // helper script as ONE argv entry and every parameter as its own argv entry
  // ($0..$8 inside the script), so no value is ever quoted into, or parsed
  // out of, a shell command line -- and the script body itself is a C++
  // literal.
  std::vector<std::string> argv = elevator;
  argv.insert(argv.end(),
              {"/bin/sh", "-c", PrivilegedTunnelScript(), "winnvpn-helper",
               action, config_path, cgroup_path, ExecutableDirectory(),
               g_xray_config_path, std::to_string(getpid()),
               // M-10: pass the release-injected BPF-helper hash (empty
               // unless built with -DWINSVPN_BPF_HELPER_SHA256) so the
               // privileged script can pin it as $7.
               std::string(kBpfHelperExpectedSha256),
               // $8: the Winn gateway endpoint, empty unless this is a
               // winn/3 start. The script installs the fwmark exclusion for
               // exactly this destination.
               winn_argument});
  return RunArgv(argv, ProcOutput::kInherit).exit_status;
}

// ---------------------------------------------------------------------------
// The Winn Protocol v3 privileged executor (the `winn3-posture` runner).
//
// This is the OTHER privileged surface beside winsvpn-helper start/stop, and
// it exists because the two serve different trust shapes. start/stop run one
// large root shell script with a closed set of actions. Winn v3 renders a
// closed set of `ip`/`resolvectl`/`resolvconf`/`mkdir`/`cp`/`tee`/`rm`/`test`
// ARGUMENT VECTORS and runs each one as root, feeding `stdin_bytes` for the
// two resolver mechanisms that have no argument form (openresolv, and the
// direct /etc/resolv.conf rewrite). A rendered vector must never be flattened
// into a shell string by a caller -- a shell string is exactly the quoting bug
// argument vectors exist to remove -- so the vector is transported base64, is
// re-split by IFS inside the ROOT script (never parsed as shell), and the root
// side enforces its own allowlist before one command runs.
//
// The allowlist is therefore enforced TWICE: here, as the last thing the
// unprivileged host does before asking for elevation (a broken renderer fails
// before it ever hands root a vector), and again inside the root script (a
// compromised or miscompiled host cannot make root run anything outside the
// set). Both sides allow the same closed vocabulary; a command that passes one
// and fails the other is a defect, not a feature.
// ---------------------------------------------------------------------------

// True when an element can pass safely through the base64/IFS transport to the
// root script: no whitespace or control byte (the IFS re-split in the root
// script splits on whitespace, so an element containing any would be silently
// divided into two arguments) and no NUL.
bool Winn3ArgvElementIsTransportSafe(const std::string& part) {
  for (const char c : part) {
    const unsigned char uc = static_cast<unsigned char>(c);
    if (uc <= 0x20 || uc == 0x7f) return false;
  }
  return true;
}

bool Winn3PostureAllowArgv(const std::vector<std::string>& argv,
                           std::string* why) {
  if (argv.empty()) {
    if (why != nullptr) *why = "empty command";
    return false;
  }
  for (const std::string& part : argv) {
    if (part.empty()) {
      if (why != nullptr) *why = "an argument is empty";
      return false;
    }
    if (!Winn3ArgvElementIsTransportSafe(part)) {
      if (why != nullptr)
        *why = "an argument contains whitespace or a control character";
      return false;
    }
  }
  const std::string& bin = argv[0];
  // The RENDERED family flag. RenderLinuxWinn3ExclusionCommands and
  // RenderLinuxPostureCommands emit `ip -4 route add ...` / `ip -6 address add
  // ...` with the family flag BEFORE the subcommand, so the subcommand is argv[2]
  // in that shape and argv[1] in the unflagged `ip route add ...` / `ip link ...`
  // shape. Both happen for real; an allowlist that accepts only one of them
  // makes the served path refuse its own posture.
  size_t ip_sub_offset = 1;
  if (bin == "ip" && argv.size() > 1 && (argv[1] == "-4" || argv[1] == "-6")) {
    ip_sub_offset = 2;
  }
  const std::string sub =
      argv.size() > ip_sub_offset ? argv[ip_sub_offset] : std::string();
  if (bin == "ip") {
    const bool tuntap_add =
        argv.size() == 11 && argv[1] == "tuntap" && argv[2] == "add" &&
        argv[3] == "dev" &&
        argv[4] == winsvpn::winn3host::kLinuxWinn3InterfaceName &&
        argv[5] == "mode" && argv[6] == "tun" && argv[7] == "user" &&
        argv[8] == std::to_string(geteuid()) && argv[9] == "group" &&
        argv[10] == std::to_string(getegid());
    const bool tuntap_del =
        argv.size() == 7 && argv[1] == "tuntap" && argv[2] == "del" &&
        argv[3] == "dev" &&
        argv[4] == winsvpn::winn3host::kLinuxWinn3InterfaceName &&
        argv[5] == "mode" && argv[6] == "tun";
    if (!(sub == "route" || sub == "address" || sub == "link" || tuntap_add ||
          tuntap_del)) {
      if (why != nullptr)
        *why = "the ip subcommand must be route, address, link or the exact "
               "winsvpn3 tuntap add/del";
      return false;
    }
  } else if (bin == "resolvectl") {
    // `--no-pager status` is the mechanism PROBE that DetectLinuxWinn3Resolver
    // Mechanism issues to ask whether systemd-resolved answers on this host's
    // bus, and the probe runs through the SAME runner as the posture commands.
    const bool status_probe =
        sub == "--no-pager" && argv.size() == 3 && argv[2] == "status";
    if (!(sub == "dns" || sub == "domain" || sub == "revert" || status_probe)) {
      if (why != nullptr)
        *why = "the resolvectl subcommand must be dns, domain or revert";
      return false;
    }
  } else if (bin == "resolvconf") {
    // `-l` is the mechanism probe that asks whether openresolv manages this
    // host's resolvers, and it too runs through the same runner.
    const bool list_probe =
        sub == "-l" && argv.size() == 2;
    if (!(sub == "-a" || sub == "-d" || list_probe)) {
      if (why != nullptr)
        *why = "the resolvconf subcommand must be -a or -d";
      return false;
    }
  } else if (!(bin == "mkdir" || bin == "cp" || bin == "tee" || bin == "rm" ||
               bin == "test")) {
    if (why != nullptr) *why = "command is not on the allowlisted set: " + bin;
    return false;
  } else if (bin == "mkdir") {
    // `mkdir -p <dir>` — the renderer emits exactly the backup dir.
    if (argv.size() != 3 || argv[1] != "-p" ||
        argv[2] != winsvpn::winn3host::kResolvConfBackupDir) {
      if (why != nullptr)
        *why = "mkdir must be exactly `-p " +
               std::string(winsvpn::winn3host::kResolvConfBackupDir) + "`";
      return false;
    }
  } else if (bin == "cp") {
    // `cp -f <src> <dst>` — the resolv.conf backup/restore renderers emit
    // exactly the two directions between the backup and /etc/resolv.conf. Only
    // the stranding-repair shapes are legitimate; any other `cp` destination
    // would let a broken host write wherever root can, which is what the path
    // pin is here to remove.
    const bool backup_to_conf =
        argv.size() == 4 && argv[1] == "-f" &&
        argv[2] == winsvpn::winn3host::kResolvConfBackup &&
        argv[3] == winsvpn::winn3host::kResolvConfPath;
    const bool conf_to_backup =
        argv.size() == 4 && argv[1] == "-f" &&
        argv[2] == winsvpn::winn3host::kResolvConfPath &&
        argv[3] == winsvpn::winn3host::kResolvConfBackup;
    if (!backup_to_conf && !conf_to_backup) {
      if (why != nullptr)
        *why = "cp must be exactly `-f <backup> <resolv.conf>` or the reverse";
      return false;
    }
  } else if (bin == "tee") {
    // `tee <path>` with the body on stdin — the direct rewrite renders exactly
    // /etc/resolv.conf. Any other `tee` destination would let a broken host
    // overwrite an arbitrary root file.
    if (argv.size() != 2 ||
        argv[1] != winsvpn::winn3host::kResolvConfPath) {
      if (why != nullptr)
        *why = "tee must be exactly `" +
               std::string(winsvpn::winn3host::kResolvConfPath) + "`";
      return false;
    }
  } else if (bin == "rm") {
    // `rm -f <path>` — the backup-drop renderer emits exactly the backup.
    if (argv.size() != 3 || argv[1] != "-f" ||
        argv[2] != winsvpn::winn3host::kResolvConfBackup) {
      if (why != nullptr)
        *why = "rm must be exactly `-f " +
               std::string(winsvpn::winn3host::kResolvConfBackup) + "`";
      return false;
    }
  } else if (bin == "test") {
    // `test -h|-f <path>` — the direct-rewrite eligibility probes emit exactly
    // these two shapes against /etc/resolv.conf. No `test` of any other path,
    // and no `test` of the file's CONTENT is ever rendered.
    const bool h_or_f = argv.size() == 3 && (argv[1] == "-h" || argv[1] == "-f");
    if (!h_or_f || argv[2] != winsvpn::winn3host::kResolvConfPath) {
      if (why != nullptr)
        *why = "test must be exactly `-h|-f " +
               std::string(winsvpn::winn3host::kResolvConfPath) + "`";
      return false;
    }
  }
  return true;
}

// The runner StartLinuxWinn3StandaloneTunnel hands to the posture appliers.
// Returns true when the vector ran and succeeded as root with stdin_bytes on
// its standard input. It is a `LinuxWinn3PrivilegedRunner` -- `bool(argv,
// stdin, std::string*)`.
bool RunPrivilegedWinn3Posture(const std::vector<std::string>& argv,
                               const std::string& stdin_bytes,
                               std::string* error) {
  std::string why;
  if (!Winn3PostureAllowArgv(argv, &why)) {
    if (error != nullptr)
      *error = "A Winn Protocol v3 privileged command was refused: " + why;
    return false;
  }
  // Space-joined (every element already validated to contain no whitespace),
  // then base64 so it survives the shell-quoted transport byte-for-byte.
  std::string joined;
  for (size_t i = 0; i < argv.size(); ++i) {
    if (i != 0) joined += ' ';
    joined += argv[i];
  }
  gchar* argv_b64 = g_base64_encode(
      reinterpret_cast<const guchar*>(joined.data()), joined.size());
  gchar* stdin_b64 = g_base64_encode(
      reinterpret_cast<const guchar*>(stdin_bytes.data()), stdin_bytes.size());
  if (argv_b64 == nullptr || stdin_b64 == nullptr) {
    g_free(argv_b64);
    g_free(stdin_b64);
    if (error != nullptr)
      *error = "A Winn Protocol v3 privileged command could not be encoded";
    return false;
  }
  const std::vector<std::string> elevator = PrivilegedRunner();
  // ROOT RUNS, 2026-08-21 (app-level live-test lane). PrivilegedRunner()
  // returns an empty vector for euid 0 because root needs no elevator, and
  // StopTunnel already treats that shape as runnable (`elevator.empty() &&
  // geteuid() != 0` is its only refusal). This runner used to refuse EVERY
  // empty runner, so a root host -- the lab box this lane runs on -- could
  // never apply the winn3 posture even though the commands are exactly the
  // ones root may run directly. The refusal now fires only for a NON-root
  // process with no elevator, which is the case the message describes.
  if (elevator.empty() && geteuid() != 0) {
    g_free(argv_b64);
    g_free(stdin_b64);
    if (error != nullptr)
      *error =
          "This computer cannot run a Winn Protocol v3 session because no "
          "privileged elevator (sudo or pkexec) is available";
    return false;
  }
  // B-APP-004: argv form, same shape as RunPrivilegedTunnelCommand. The
  // elevator runs /bin/sh with the literal helper script; the two base64
  // blobs cross as argv entries ($2, $3), never as quoted strings. Output is
  // captured (both streams merged) so a refused elevation explains itself.
  std::vector<std::string> command = elevator;
  command.insert(command.end(),
                 {"/bin/sh", "-c", PrivilegedTunnelScript(),
                  "winnvpn-helper", "winn3-posture",
                  std::string(argv_b64), std::string(stdin_b64)});
  g_free(argv_b64);
  g_free(stdin_b64);
  const ProcResult result = RunArgv(command, ProcOutput::kCapture);
  if (result.exit_status == 0) return true;
  if (error != nullptr) {
    // Name the verb only. The arguments carry the inner address, the
    // gateway and the resolvers, and this string reaches the UI.
    *error = "A Winn Protocol v3 privileged command (" + argv[0] +
             (argv.size() > 1 ? " " + argv[1] : std::string()) +
             ") failed with exit " + std::to_string(result.exit_status) + ".";
  }
  return false;
}

bool IsTunnelRunning() {
  // STANDALONE v3 first, and exclusively. The v3 tun is `winsvpn3` and its
  // engine is LinuxWinn3; the v1 path below looks at `winsvpn` and the
  // AmneziaWG/winn/1 engine. Falling through while a v3 session is remembered
  // would report a leftover v1 interface as the user's tunnel, or report a
  // healthy v3 session as down because `winsvpn` is absent.
  if (winsvpn::winn3host::LinuxWinn3StandaloneSessionWasStarted()) {
    const bool winsvpn3_present =
        if_nametoindex(winsvpn::winn3host::kLinuxWinn3InterfaceName) != 0;
    const bool v3_engine = winsvpn::winn3host::LinuxWinn3EngineRunning();
    return winsvpn::winn3host::LinuxTunnelRunningConsideringV3(
        true, winsvpn3_present, v3_engine, false);
  }
  const bool interface_present = if_nametoindex(kTunnelName) != 0;
  if (!interface_present) {
    return false;
  }
  // PROCESS EXISTENCE IS NOT PROOF OF A WORKING TUNNEL, and neither is
  // interface existence. On a winn/3 tunnel the AmneziaWG peer endpoint points
  // at a loopback seam; if the engine behind that seam is gone, the interface
  // is still up and still has routes, and every packet entering it dies
  // silently. Reporting that as "running" is the exact failure mode this
  // project has already been bitten by, so it is refused here.
  if (g_winn_tunnel_active && !winsvpn::winn::LinuxWinnEngineRunning()) {
    return false;
  }
  // HEALTH: freshness alone was the root cause of the 105 s silent blackout
  // Android measured. Linux had the same defect: IsTunnelRunning checked that
  // the engine process existed, not that it was carrying. After the gate
  // converges, a DPI-style silent drop leaves the engine answering STATUS
  // promptly while carrying nothing, and this predicate would stay true
  // forever. Check asymmetric progress here as well; idle stays healthy by
  // construction. Mirrors Android's currentEngineHandleHealthy.
  if (g_winn_tunnel_active) {
    const std::string status = winsvpn::winn::LinuxWinnEngineStatusJson();
    // Empty status with no engine is already handled above; an empty status
    // with a running engine is a failed round trip, not proof of health.
    if (!status.empty()) {
      bool carrying = WinnDatapathIsCarrying(status);
      if (!carrying) {
        g_winn_unhealthy_streak++;
        if (g_winn_unhealthy_streak >= 3) {
          g_warning("Winn datapath health check failed repeatedly; closing stale tunnel");
          return false;
        }
      } else {
        g_winn_unhealthy_streak = 0;
      }
    }
  }
  return true;
}

static bool LinuxSampleTunnelTrafficBytes(int64_t* rx_out, int64_t* tx_out) {
  if (!rx_out || !tx_out) return false;
  *rx_out = 0;
  *tx_out = 0;
  std::ifstream dev_file("/proc/net/dev");
  if (!dev_file.is_open()) return false;
  std::string line;
  bool found = false;
  while (std::getline(dev_file, line)) {
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string ifname = line.substr(0, colon);
    ifname.erase(0, ifname.find_first_not_of(" \t\r\n"));
    if (ifname.rfind("tun", 0) == 0 || ifname.rfind("wins", 0) == 0 ||
        ifname.rfind("awg", 0) == 0 || ifname.rfind("wg", 0) == 0) {
      std::istringstream iss(line.substr(colon + 1));
      int64_t rx_b = 0, rx_p = 0, rx_e = 0, rx_d = 0, rx_f = 0, rx_o = 0, rx_c = 0, rx_m = 0;
      int64_t tx_b = 0;
      if (iss >> rx_b >> rx_p >> rx_e >> rx_d >> rx_f >> rx_o >> rx_c >> rx_m >> tx_b) {
        *rx_out += rx_b;
        *tx_out += tx_b;
        found = true;
      }
    }
  }
  return found;
}

FlValue* TunnelReadinessValue() {
  const bool active = IsTunnelRunning();
  int64_t linux_rx = 0, linux_tx = 0;
  if (active) {
    LinuxSampleTunnelTrafficBytes(&linux_rx, &linux_tx);
  }
  FlValue* readiness = fl_value_new_map();
  fl_value_set_string_take(readiness, "active", fl_value_new_bool(active));
  fl_value_set_string_take(readiness, "engine_ready", fl_value_new_bool(active));
  fl_value_set_string_take(
      readiness, "engine_ready_ms",
      fl_value_new_int(static_cast<int64_t>(active ? 1500 : 0)));
  fl_value_set_string_take(readiness, "underlying_transport",
                           fl_value_new_string("desktop"));
  fl_value_set_string_take(readiness, "vpn_present", fl_value_new_bool(active));
  // Interface presence is not proof that customer traffic can traverse the
  // encrypted path. Only the explicit tunnel-bound probe may establish that.
  fl_value_set_string_take(readiness, "vpn_internet", fl_value_new_bool(false));
  fl_value_set_string_take(readiness, "vpn_validated", fl_value_new_bool(false));
  fl_value_set_string_take(readiness, "tun_rx_bytes", fl_value_new_int(linux_rx));
  fl_value_set_string_take(readiness, "tun_tx_bytes", fl_value_new_int(linux_tx));
  fl_value_set_string_take(readiness, "traffic_rx_bytes", fl_value_new_int(linux_rx));
  fl_value_set_string_take(readiness, "traffic_tx_bytes", fl_value_new_int(linux_tx));
  fl_value_set_string_take(readiness, "uid_rx_bytes", fl_value_new_int(0));
  fl_value_set_string_take(readiness, "uid_tx_bytes", fl_value_new_int(0));
  winsvpn::winn3host::Winn3StartProof proof;
  {
    std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
    proof = g_last_winn3_proof;
  }
  fl_value_set_string_take(
      readiness, "winn3_verdict",
      fl_value_new_string(
          winsvpn::winn3host::Winn3ProofOutcomeName(proof.outcome)));
  fl_value_set_string_take(
      readiness, "winn3_start_generation",
      fl_value_new_int(proof.generation));
  fl_value_set_string_take(
      readiness, "winn3_start_token", fl_value_new_int(proof.start_token));
  fl_value_set_string_take(
      readiness, "winn3_start_canceled",
      fl_value_new_bool(proof.canceled));
  if (!proof.selection_generation.empty()) {
    fl_value_set_string_take(
        readiness, "winn3_selection_generation",
        fl_value_new_string(proof.selection_generation.c_str()));
  }
  if (!proof.failed_node.empty()) {
    fl_value_set_string_take(readiness, "winn3_failed_node",
                             fl_value_new_string(proof.failed_node.c_str()));
  }
  const int64_t auth = winsvpn::winn3host::Winn3AuthorizationToken(proof);
  if (auth > 0) {
    fl_value_set_string_take(readiness, "winn3_awg_xray_authorization_token",
                             fl_value_new_int(auth));
  }
  return readiness;
}

FlValue* ProbeInternetValue() {
  const bool active = IsTunnelRunning();
  const bool v3 =
      winsvpn::winn3host::LinuxWinn3StandaloneSessionWasStarted();
  const char* tun =
      v3 ? winsvpn::winn3host::kLinuxWinn3InterfaceName : kTunnelName;
  const std::string route_pattern =
      v3 ? " dev winsvpn3( |$)" : " dev winsvpn( |$)";
  // Literal script bodies; the interface name crosses as $1 and the route
  // pattern as $1 respectively. No dynamic value is ever parsed as shell.
  const bool route_uses_tunnel =
      active &&
      ProcSucceeded(RunShScript("ip route get 1.1.1.1 2>/dev/null | grep -Eq \"$1\"",
                                "winsvpn-route-check", {route_pattern},
                                ProcOutput::kSuppress));
  const bool ok = route_uses_tunnel &&
                  ProcSucceeded(RunShScript(
                      "curl -fsS --max-time 4 --interface \"$1\" "
                      "https://cloudflare.com/cdn-cgi/trace || "
                      "curl -fsS --max-time 4 --interface \"$1\" "
                      "https://connectivitycheck.gstatic.com/generate_204",
                      "winsvpn-net-check", {tun}, ProcOutput::kSuppress));
  FlValue* response = fl_value_new_map();
  fl_value_set_string_take(response, "ok", fl_value_new_bool(ok));
  fl_value_set_string_take(response, "bound_to_tunnel",
                           fl_value_new_bool(route_uses_tunnel));
  fl_value_set_string_take(response, "status", fl_value_new_int(ok ? 204 : 0));
  const char* error = "";
  if (!active) {
    error = "Linux tunnel is not active";
  } else if (!route_uses_tunnel) {
    error = "Linux default route is not bound to the tunnel";
  } else if (!ok) {
    error = "Linux tunnel-bound internet probe failed";
  }
  fl_value_set_string_take(response, "error", fl_value_new_string(error));
  return response;
}

// WINN HEALTH: asymmetric progress, ported 2026-08-07 from Android's
// winnDatapathIsCarrying (VpnTunnelService.kt).
//
// The freshness-only check IsTunnelRunning had before this was the root cause
// of the 105 s silent blackout Android measured: an engine answering STATUS
// promptly while carrying nothing was "healthy" forever. transport_observed
// latches, so re-reading it after start proves nothing; and requiring traffic
// would tear down an idle tunnel. So a verdict is reached only when this
// device SENT payload datagrams across the interval and NONE came back -- the
// signature of a path that has gone dead outbound-only (the censorship case).
// An idle session advances neither counter and is never judged.
// Returns true (healthy) whenever there is no basis for a verdict, matching
// Android's winnDatapathIsCarrying exactly.
bool WinnDatapathIsCarrying(const std::string& status) {
  if (status.empty()) return true;
  // WINN_FAIL_OPEN_CLOSED 2026-08-09. THE SECOND INSTANCE OF THE SAME DEFECT.
  //
  // This used to substring-match `"awg_classification":"configured-h1h4"` in
  // the ENGINE'S REPLY and, when the substring was absent, `return true` --
  // healthy -- with a g_warning nobody reads. That is the identical fail-open
  // the convergence gate carried, in the identical shape and for the identical
  // stated reason, and it fails for the identical reason: `awg_classification`
  // is a round-trip echo of the `awg_header_types` document this host itself
  // built, so an engine-side rename, a version skew or a pretty-printing
  // encoder switched the ONGOING health check off for the whole session. The
  // 105 s silent blackout this check exists to catch would then run forever.
  //
  // The question "can this session's counters fire at all?" is answered where
  // the answer actually lives: the h1..h4 table THIS HOST latched at
  // StartLinuxWinnEngine. When it classifies -- true for every configuration
  // ParseLinuxWinnSection accepts -- the counter comparison below runs
  // regardless of how the engine spells its classification field, which is
  // strictly more checking than shipped before.
  if (!winsvpn::winn::LinuxWinnEngineHeadersClassify()) {
    // Unreachable for a promoted session: WaitForLinuxWinnTransportConvergence
    // refuses kCannotObserve at start, so g_winn_tunnel_active is never set for
    // a session whose table cannot classify, and a status document this
    // non-empty means the engine is up and the latch is meaningful. Fail closed
    // anyway rather than reporting a tunnel healthy on the strength of a check
    // that is structurally unable to run.
    g_warning(
        "Winn datapath health check cannot run: this session was started "
        "without a complete AmneziaWG h1..h4 classification table, so the "
        "transport counters can never fire. Closing the tunnel rather than "
        "reporting it healthy without proof.");
    return false;
  }
  auto extractLong = [](const std::string& json, const std::string& key, long long def) -> long long {
    const std::string needle = "\"" + key + "\":";
    size_t at = json.find(needle);
    if (at == std::string::npos) return def;
    size_t i = at + needle.size();
    std::string val;
    while (i < json.size() && std::isdigit(static_cast<unsigned char>(json[i]))) {
      val.push_back(json[i]); ++i;
    }
    if (val.empty()) return def;
    try { return std::stoll(val); } catch (...) { return def; }
  };
  long long tx = extractLong(status, "tx_transport_payload_datagrams", -1);
  long long rx = extractLong(status, "rx_transport_payload_datagrams", -1);
  if (tx < 0 || rx < 0) return true;
  long long prevTx = g_winn_last_tx_payload;
  long long prevRx = g_winn_last_rx_payload;
  g_winn_last_tx_payload = tx;
  g_winn_last_rx_payload = rx;
  if (prevTx < 0 || prevRx < 0) return true;
  bool sentThisInterval = tx > prevTx;
  bool receivedThisInterval = rx > prevRx;
  if (sentThisInterval && !receivedThisInterval) {
    g_warning("Winn datapath carried %lld outbound payload datagrams with nothing returning.", tx - prevTx);
    return false;
  }
  return true;
}

// Deadlines for the Winn route-promotion gate below. The 5 s budget is
// deliberately the same number Windows uses at
// kWinnTransportConvergenceDeadlineMilliseconds, and the 250 ms tick the same
// one Apple uses at winnDatapathProofTickMilliseconds, so the three platforms
// fail closed on the same schedule rather than on three invented ones.
constexpr int kWinnTransportConvergenceDeadlineMs = 5000;
constexpr int kWinnTransportConvergenceTickMs = 250;

// Polls the engine's own status document until it reports transport observed in
// BOTH directions, or the deadline expires.
//
// `transport_observed_both_ways` is produced by
// winn_protocol_experimental/datapath/status.go and reaches this process
// verbatim through LinuxWinnEngineStatusJson(). The document is never logged --
// it carries `gateway_endpoint`, the customer's real gateway address -- so the
// verdict is read out of it by LinuxWinnTransportGate and nothing from it is
// ever put in *error.
//
// `up` is deliberately NOT consulted, matching the note in
// windows/runner/windows_winn_engine.cpp: `up` says the carrier is open, which
// is true of a carrier whose datagrams are all being dropped on path.
//
// WINN_FAIL_OPEN_CLOSED 2026-08-09. THE FAIL-OPEN THAT WAS HERE. This loop used
// to `return true` -- promote -- whenever the engine's reply lacked the exact
// substring `"awg_classification":"configured-h1h4"`, on the reasoning that
// h1..h4 are mandatory at parse time so the branch was unreachable. The
// reasoning did not hold, because the branch keyed on the ENGINE'S REPLY rather
// than on this host's own parsed config: `awg_classification` is a round-trip
// echo of the `awg_header_types` document this host itself built
// (status.go:230-233 <- engine.headersConfigured <- engine.go:304 <-
// BuildLinuxWinnConfigJson), so an engine-side field rename, a version skew or
// a pretty-printing encoder read as "gate off" instead of as "something is
// wrong" -- and the gate promoted the user's default route onto an unproven
// carrier, with the only trace a g_warning line.
//
// The decision now lives in LinuxWinnTransportGate over the h1..h4 table THIS
// HOST latched at StartLinuxWinnEngine. The reply is read for exactly one
// field, `transport_observed_both_ways`, and for wording.
bool WaitForLinuxWinnTransportConvergence(std::string* error) {
  const int ticks =
      kWinnTransportConvergenceDeadlineMs / kWinnTransportConvergenceTickMs;
  // Carried out of the loop so the timeout message below can name WHICH
  // unproven state the budget was spent in. It is written by
  // DecideWinnTransportGate and never quotes the status document, which carries
  // the customer's gateway endpoint.
  std::string reason;
  for (int i = 0; i < ticks; ++i) {
    // Checked FIRST, matching WaitForWinnTransportConvergence on Windows. An
    // engine that has exited answers with an empty document forever, and each
    // ask costs up to kStatusTimeoutMs, so there is nothing to buy by asking it
    // twenty more times.
    if (!winsvpn::winn::LinuxWinnEngineRunning()) {
      if (error != nullptr) {
        *error =
            "The Linux Winn Protocol engine exited before the datapath could "
            "be proven to carry traffic, so the tunnel was stopped and the "
            "host's routing restored.";
      }
      return false;
    }
    const winsvpn::winn::WinnTransportGate gate =
        winsvpn::winn::LinuxWinnTransportGate(nullptr, &reason);
    if (gate == winsvpn::winn::WinnTransportGate::kObserved) return true;
    // A verdict of "this session can never prove itself" is final on the first
    // read, so spending the remaining budget on it would only delay the same
    // refusal. This is also the answer to the objection the replaced fail-open
    // was written around -- that refusing would "silently time out": closing
    // the hole adds NO stall to the case it worried about, because that case
    // now leaves the loop immediately instead of polling to the deadline.
    if (gate == winsvpn::winn::WinnTransportGate::kCannotObserve) {
      if (error != nullptr) {
        *error =
            "The Linux Winn Protocol tunnel was refused rather than promoted "
            "without proof: " +
            reason;
      }
      return false;
    }
    usleep(kWinnTransportConvergenceTickMs * 1000);
  }
  if (error != nullptr) {
    *error =
        "Linux Winn Protocol v3 datapath did not carry traffic in both "
        "directions before the deadline. The tunnel was stopped and the "
        "host's routing restored.";
    if (!reason.empty()) *error += " Last observation: " + reason;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The STANDALONE Winn Protocol v3 start.
//
// ===========================================================================
// WHAT THIS IS NOT
// ===========================================================================
//
// It is NOT the relay path above. Everything from WinnDatapathIsCarrying to
// WaitForLinuxWinnTransportConvergence belongs to winn/1: AmneziaWG inside a
// Winn carrier, promoted after awg-quick has already claimed the host's
// routing, gated by a tri-state read of the ENGINE's own latched parse. That is
// the shipping path, a fail-open in it was closed on 2026-08-09, and nothing
// here touches it.
//
// This one carries inner IP packets under v3's own handshake, owns its own tun
// device, and must install a posture BEFORE it can prove anything -- because
// its proof, RxPackets, counts inner packets WRITTEN TO THE HOST DEVICE, and a
// host that installs nothing has no device to deliver into. Deferring the
// device defers the proof forever.
//
// ===========================================================================
// WHY IT EXISTS AS A BRANCH AT ALL
// ===========================================================================
//
// Until 2026-08-09 linux_tunnel_backend.cc reached ParseLinuxWinnSection for
// EVERY `[winn] enabled = true` configuration, including one carrying
// `carrier = winn3`. That parser refuses a carrier it cannot build, so a served
// standalone config failed closed -- but it failed as "this host cannot build
// carrier winn3", which is the winn/1 relay's sentence about a protocol it is
// not being asked to speak. ParseLinuxWinn3Section existed, was tested, and had
// no caller: Linux could PARSE a served config and could not be STARTED by one,
// so it could not appear in a cross-host comparison even in principle.
//
// The branch is placed exactly where windows_tunnel_backend.cpp places its own
// (`if (ConfigSelectsWinn3(raw_config)) return InstallWinn3StandaloneTunnel(…)`)
// -- before either winn/1 predicate is consulted, so the two parsers can never
// both claim one document.
//
// ===========================================================================
// AND WHY IT REFUSES TODAY
// ===========================================================================
//
// The refusal below is the finding, not a placeholder. A served `[winn]`
// section carries no `dns` key -- see lib/winn_protocol_dispatch.dart's closed
// emission list -- and the promoted posture takes the default route
// unconditionally. A session started from one could therefore only ever promote
// into a posture that widens the ROUTES onto the tunnel and leaves NAME
// RESOLUTION pointed at whatever the network handed out. On the connections
// these users have that is the CPE the censor operates, reached over the
// physical link's own connected prefix, which is more specific than the /1 pair
// and so is not captured by it.
//
// That is a leak with a green gate: pages load, the tunnel reports carrying,
// and every hostname the user visits is handed to the network they installed
// this to hide from. winn3_posture.h now refuses to build such a posture. This
// refuses EARLIER, at the only moment where nothing has been installed and
// nothing has to be torn down again -- the same reason the outer-path facts
// below are read before any route exists.
//
// Everything above the refusal is real work on the live path: the served
// document is parsed by the v3 parser, its key material is written 0600, the
// engine is located, and the outer-path facts are read while they can still be
// read honestly. What is missing is a CONTRACT FIELD, and the refusal says so
// by name rather than reporting a failure the operator would read as a bug.

// Exact Linux errno from a non-blocking datagram connect to the already-parsed
// IP-literal gateway. Diagnostic prose is never inspected. EINPROGRESS/EAGAIN
// means a route exists and is not ordinary unreachability.
int CaptureLinuxWinn3GatewayOsError(const std::string& endpoint) {
  std::string host;
  std::string port_text;
  if (!winsvpn::winn3host::SplitLinuxWinn3Endpoint(endpoint, &host,
                                                   &port_text)) {
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
  const int sock = ::socket(family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (sock < 0) return 0;
  int rc = -1;
  if (ipv6) {
    sockaddr_in6 addr = {};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr) != 1) {
      ::close(sock);
      return 0;
    }
    rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  } else {
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
      ::close(sock);
      return 0;
    }
    rc = ::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  }
  if (rc == 0) {
    ::close(sock);
    return 0;
  }
  const int os_error = errno;
  ::close(sock);
  if (os_error == EINPROGRESS || os_error == EAGAIN || os_error == EWOULDBLOCK) {
    return 0;
  }
  return os_error;
}

int CaptureLinuxWinn3GatewayOsErrorFromConfig(const std::string& raw_config) {
  winsvpn::winn3host::LinuxWinn3Params params;
  winsvpn::winn3host::LinuxWinn3ServedKeyMaterial material;
  std::string ignored;
  if (!winsvpn::winn3host::ParseLinuxWinn3Section(raw_config, &params, &material,
                                                  &ignored)) {
    return 0;
  }
  return CaptureLinuxWinn3GatewayOsError(params.gateway_endpoint);
}

// THE STANDALONE START. The comment block above this helper cluster is the
// contract this function implements.
bool StartLinuxWinn3StandaloneTunnel(const std::string& raw_config,
                                     std::string* error) {
  bool owns_key_files = false;
  const auto refuse = [&](const std::string& message) {
    std::string cleanup_error;
    const bool cleaned =
        !owns_key_files ||
        winsvpn::winn3host::RemoveLinuxWinn3KeyFiles(&cleanup_error);
    if (error != nullptr) {
      *error = message;
      if (!cleaned) *error += " " + cleanup_error;
    }
    return false;
  };

  winsvpn::winn3host::LinuxWinn3Params params;
  winsvpn::winn3host::LinuxWinn3ServedKeyMaterial material;
  std::string winn3_error;
  if (!winsvpn::winn3host::ParseLinuxWinn3Section(raw_config, &params,
                                                  &material, &winn3_error)) {
    return refuse("This server asked for a standalone Winn Protocol v3 "
                  "session and the connection details could not be used: " +
                  winn3_error);
  }

  // Resolved BEFORE anything touches the network or the filesystem, so a build
  // without the engine fails while the host is still in its pre-tunnel state.
  const std::string engine_path = FindWinnDatapathExecutable();
  if (engine_path.empty()) {
    return refuse(
        "This server uses a standalone Winn Protocol v3 session, but the Winn "
        "datapath engine is not bundled with this Linux build, so the "
        "connection was stopped rather than started without it.");
  }

  // THE OUTER-PATH FACTS, READ BEFORE ANYTHING IS INSTALLED.
  //
  // This is the only moment they can be read honestly. After a posture is
  // applied the answer to "how do I reach the gateway" is the tunnel, and an
  // exclusion built from that answer sends the engine's own carrier datagrams
  // into the tunnel they carry. A standalone session has no awg-quick fwmark to
  // fall back on, so this read is not an optimisation -- it is the whole
  // exclusion.
  std::string gateway_host;
  std::string gateway_port;
  if (!winsvpn::winn3host::SplitLinuxWinn3Endpoint(params.gateway_endpoint,
                                                   &gateway_host,
                                                   &gateway_port)) {
    return refuse(
        "This server supplied a standalone Winn Protocol v3 gateway address "
        "this computer cannot use, so the connection was stopped.");
  }
  // B-APP-004: gateway_host is SERVED data. It crosses as a real argv entry
  // (no shell, no quoting); the pipeline around it is a literal script body.
  const std::string route_line =
      RunShScript("ip route get \"$1\" 2>/dev/null | head -n 1",
                  "winsvpn-route-read", {gateway_host},
                  ProcOutput::kCapture)
          .output;
  const auto field_after = [&route_line](const std::string& key) {
    std::istringstream stream(route_line);
    std::string token;
    while (stream >> token) {
      if (token == key && (stream >> token)) return token;
    }
    return std::string();
  };
  params.physical_next_hop = field_after("via");
  params.physical_interface = field_after("dev");
  // ON-LINK GATEWAYS, 2026-08-21 (app-level live-test lane): a gateway on the
  // host's own subnet has no next hop -- `ip route get <host>` names `dev`
  // without `via` -- so a missing `via` alone is no longer a refusal. The
  // exclusion for that topology is the direct-device /32 (no `via`) that
  // RenderLinuxWinn3ExclusionCommands emits; a missing PHYSICAL INTERFACE
  // still refuses, because an exclusion with no device cannot keep the
  // engine's outer socket off the tunnel.
  if (params.physical_interface.empty()) {
    return refuse(
        "This computer could not work out how it currently reaches the "
        "server, so the connection was stopped. Starting without that would "
        "send the tunnel's own traffic into the tunnel it carries.");
  }

  // REMEMBERED FROM THIS POINT, so every way out of this function -- and the
  // production StopTunnel, however much later -- can reverse exactly what a
  // standalone session installs. The fields the teardown renderer needs
  // (interface name, gateway endpoint, physical interface and next hop) are
  // all final here. Everything before this line can still fail without having
  // installed a single kernel state, so it owes no teardown.
  winsvpn::winn3host::RememberLinuxWinn3Session(params);
  if (RunPrivilegedTunnelCommand("winn3-ks-on", "", "",
                                 params.gateway_endpoint) != 0) {
    return refuse("This computer could not install the network block that "
                  "keeps traffic inside a Winn Protocol v3 session, so the "
                  "connection was stopped.");
  }

  // The key files. Unprivileged, 0600, written under the per-user private data
  // directory, with the mode set before any byte is written.
  owns_key_files = true;
  if (!winsvpn::winn3host::WriteLinuxWinn3KeyFiles(material, &params,
                                                   &winn3_error)) {
    return refuse("This computer could not store the connection keys for a "
                  "standalone Winn Protocol v3 session: " +
                  winn3_error);
  }
  params.keys.outer_socket_exclusion =
      winsvpn::winn3host::DescribeLinuxWinn3Exclusion(params);
  if (params.keys.outer_socket_exclusion.empty()) {
    return refuse(
        "This computer could not describe the exclusion that keeps a "
        "standalone Winn Protocol v3 session's own traffic out of the tunnel "
        "it carries, so the connection was stopped.");
  }

  // THE SIZING PLAN. 2026-08-10: this used to be the whole story -- the served
  // path built the promoted posture here as a pre-flight and refused before
  // anything ran, because there was no privileged executor to satisfy it. The
  // pre-flight is gone (the session now genuinely drives the sequence below and
  // reaches OpenLinuxWinn3Tun), but the sizing check stays because it is real
  // and cheap: a served document whose MTU/carrier set cannot produce a usable
  // interface must not create a tun it cannot size.
  //
  // The floor is computed from the served path MTU over the served migration
  // plan, using the SAME substitution BuildLinuxWinn3CreateJson and the engine
  // argument builder make -- one place computing the floor at a different path
  // MTU is the shape of defect 3.
  const int path_mtu = params.path_mtu > 0
                           ? params.path_mtu
                           : winsvpn::winn3host::sizing::kDefaultPathMtu;
  int plan_floor = 0;
  if (!winsvpn::winn3host::sizing::PlanFloorInnerMtu(
          path_mtu, params.carrier_classes, &plan_floor, &winn3_error)) {
    return refuse(
        "This server's standalone Winn Protocol v3 settings do not size a "
        "usable connection on this computer, so it was stopped: " +
        winn3_error);
  }
  (void)plan_floor;
  // THE PRIVILEGED RUNNER. The host is unprivileged and the posture appliers
  // above only RENDER argument vectors -- nothing in linux_winn3_host.cc ever
  // executes one. Before this change no Linux build supplied a
  // LinuxWinn3PrivilegedRunner for the served path: RunPrivilegedTunnelCommand
  // knew only `start` and `stop`, so StartLinuxWinn3StandaloneTunnel refused
  // before any privileged execution. Supplying it here (the new
  // winsvpn-helper `winn3-posture` action) is what lets the served path reach
  // OpenLinuxWinn3Tun and run the bootstrap posture for real.
  const winsvpn::winn3host::LinuxWinn3PrivilegedRunner privileged =
      [](const std::vector<std::string>& argv, const std::string& stdin_bytes,
         std::string* err) {
        return RunPrivilegedWinn3Posture(argv, stdin_bytes, err);
      };

  // Open the tun device. IFF_TUN | IFF_NO_PI is set inside OpenLinuxWinn3Tun;
  // IFF_NO_PI matters because a 4-byte PACKET_INFO prefix would be read by the
  // inner-IP validator as a malformed packet and every packet dropped. This is
  // the shipped path reaching OpenLinuxWinn3Tun for the first time; on every
  // Linux release before this it was exercised only by the standalone e2e
  // driver.
  std::string tun_open_error;
  // The GUI is unprivileged: TUNSETIFF may only CREATE a device with
  // CAP_NET_ADMIN, but it may ATTACH to a persistent tun owned by this uid.
  // A root GUI creates its own non-persistent tun in OpenLinuxWinn3Tun and
  // needs neither command.
  if (geteuid() != 0) {
    const std::string uid = std::to_string(static_cast<unsigned>(geteuid()));
    const std::string gid = std::to_string(static_cast<unsigned>(getegid()));
    std::string tuntap_error;
    // Removes only a leftover winsvpn3 that this app created for this user.
    // The root script refuses any other with exit 66; the add below then
    // fails on the existing name and the start is refused.
    (void)RunPrivilegedWinn3Posture(
        {"ip", "tuntap", "del", "dev", params.interface_name, "mode", "tun"},
        std::string(), nullptr);
    if (!RunPrivilegedWinn3Posture(
            {"ip", "tuntap", "add", "dev", params.interface_name, "mode", "tun",
             "user", uid, "group", gid},
            std::string(), &tuntap_error)) {
      (void)winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, nullptr);
      return refuse("This computer could not create the Winn Protocol v3 "
                    "virtual network device: " + tuntap_error);
    }
  }
  const int tun_fd = winsvpn::winn3host::OpenLinuxWinn3Tun(
      params.interface_name, &tun_open_error);
  if (tun_fd < 0) {
    // The unified teardown, as on the tuntap failure above: it deletes the
    // persistent winsvpn3 this start created, which would otherwise outlive
    // the refusal and make winsvpn-recover refuse with exit 65.
    (void)winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, nullptr);
    return refuse(
        "This computer could not open a virtual network device for a "
        "standalone Winn Protocol v3 session: " +
        tun_open_error);
  }
  // OWNERSHIP OF tun_fd PASSES TO StartLinuxWinn3Engine ON EVERY OUTCOME.

  // Start the engine over stdio carrying the tun descriptor. On false nothing
  // is left running and tun_fd ownership has been closed by the call.
  winsvpn::winn3::EngineStatus ack;
  if (!winsvpn::winn3host::StartLinuxWinn3Engine(engine_path, tun_fd, params,
                                                 &ack, &winn3_error)) {
    (void)winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, nullptr);
    return refuse(
        "This computer could not start the Winn Protocol v3 datapath for a "
        "standalone session, so the connection was stopped: " +
        winn3_error);
  }

  // The narrow bootstrap posture: the outer-socket exclusion first, then the
  // link. Executed as root through the privileged runner. The CreateAck status
  // (ack) is where the authoritative inner MTU comes from, which is why this
  // runs after the start and not before it. The bootstrap installs NO resolver,
  // so it does not depend on the served `[winn]` carrying one.
  winsvpn::winn3::PosturePlan bootstrap_plan;
  const winsvpn::winn3host::LinuxWinn3PostureResult bootstrap =
      winsvpn::winn3host::ApplyLinuxWinn3BootstrapPosture(
          params, ack, privileged, &bootstrap_plan);
  const bool bootstrap_ok =
      bootstrap.outcome ==
      winsvpn::winn3host::LinuxWinn3PostureOutcome::kApplied;
  winsvpn::winn3host::SetLinuxWinn3BootstrapStatus(bootstrap);
  if (!bootstrap_ok) {
    const std::string detail =
        winsvpn::winn3host::DescribeLinuxWinn3PostureResult(bootstrap);
    const bool retry = winsvpn::winn3host::LinuxWinn3PostureOutcomeShouldRetry(
        bootstrap.outcome);
    // The unified teardown, not a bare engine stop: a kPartiallyApplied
    // bootstrap can leave the outer-socket exclusion on the physical
    // interface, and the unified stop is what removes it (its exclusion
    // removal runs only when the bootstrap result says one is installed).
    (void)winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, nullptr);
    return refuse(
        "This computer could not install the narrow Winn Protocol v3 "
        "bootstrap posture (" +
        std::string(winsvpn::winn3host::LinuxWinn3PostureOutcomeName(
            bootstrap.outcome)) +
        "), so the connection was stopped. " + detail +
        (retry ? std::string(" This is transient and a retry may succeed.")
               : std::string(
                     " A retry will not change this on this host.")));
  }

  // FROM HERE ON THE EXCLUSION IS INSTALLED AND THE SESSION OWES A TEARDOWN.
  // The bootstrap's outer-socket exclusion is a route on the PHYSICAL
  // interface, so unlike everything on the tun it does NOT go away when the
  // engine is stopped; it is the stale route that makes the next start fail
  // EEXIST. Every way out below goes through StopLinuxWinn3Standalone -- the
  // SAME unified teardown the production StopTunnel and the e2e harness use --
  // which stops the engine (deleting the tun and everything scoped to it),
  // removes the promoted /1 pair, reverts any resolver and removes the
  // exclusion LAST.

  // Poll the gate until the session is carrying (the CreateAck means the
  // engine accepted its configuration, NOT that the handshake completed).
  bool carrying = false;
  const uint64_t carry_deadline = NowMs() + 15000;
  while (NowMs() < carry_deadline) {
    winsvpn::winn3::EngineStatus probe;
    std::string probe_reason;
    (void)winsvpn::winn3host::LinuxWinn3PromotionState(&probe, &probe_reason);
    if (probe.valid && probe.gate_state == winsvpn::winn3::kCarryingGate) {
      carrying = true;
      break;
    }
    if (!winsvpn::winn3host::LinuxWinn3EngineRunning()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  if (!carrying) {
    std::string residue;
    const bool stopped_clean =
        winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, &residue);
    std::string text =
        "The Winn Protocol v3 session never reached the carrying state, so "
        "the connection was stopped.";
    if (!stopped_clean) {
      text += " " + residue;
    }
    return refuse(text);
  }

  // Attempt promotion. The gate decision and the promoted posture are applied
  // through the same privileged runner. A served `[winn]` document currently
  // carries no resolver, and winn3_posture.h refuses a resolverless promotion
  // ('route set and resolver set have to move together'), so this attempts and
  // refuses at the promotion itself rather than before anything ran. On the
  // served contract as it exists today that leaves the session unable to
  // promote, and we refuse and tear down rather than leave the user believing
  // they are protected when the datapath never widened.
  //
  // POLL FOR PROMOTION READINESS, 2026-08-21 (app-level live-test lane). The
  // carry poll above proves the session driver opened its gate. Promotion is
  // the STRONGER predicate -- gate carrying AND at least one inner packet
  // validated and written to the host device -- and that proof comes from the
  // host's own first packet, which on a real device is an application's very
  // first datagram. Reading it ONCE right after the gate opens races that
  // first packet: measured live, the gate opened, one read said
  // rx_packets=0, and the first reflected ping arrived ~1s later while the
  // teardown was already running. [LinuxWinn3Promotion] was built for exactly
  // this shape (kPromote / kNotYet / kRefuse, "keep polling until the
  // caller's deadline"), so poll it with the same bounded budget as the carry
  // poll. kRefuse still fails immediately; the deadline is fail-closed.
  winsvpn::winn3::EngineStatus promote_status;
  std::string promote_reason;
  winsvpn::winn3host::LinuxWinn3Promotion verdict =
      winsvpn::winn3host::LinuxWinn3Promotion::kNotYet;
  const uint64_t promote_deadline = NowMs() + 15000;
  // PROMOTION SELF-START, 2026-08-22 (app-level live-test lane). The gate
  // starves on a quiet host: it needs rx_packets > 0, nothing sends the first
  // inner packet pre-promotion against a reactive gateway, and the harness
  // traffic waits for native start -- so a healthy carrying session ran the
  // whole window out (three live runs, both engine builds). The runner had to
  // inject inner ICMP from outside the app to unblock it. That injection is
  // now the product's own business: one minimal inner echo, addressed to the
  // inner next hop (the ONE /32 the bootstrap routes into the tun, so it can
  // never leak onto the physical default) and sourced from the session's own
  // inner assignment (so the engine's validator accepts it). Bounded and
  // advisory: at most a handful of probes, sent only while the gate carries
  // with nothing delivered, and a refusal still fails immediately while the
  // deadline still fails closed.
  constexpr size_t kMaxPromotionProbes = 4;
  constexpr uint64_t kPromotionProbeIntervalMs = 2500;
  uint64_t next_probe_at = 0;
  size_t probes_sent = 0;
  while (NowMs() < promote_deadline) {
    verdict = winsvpn::winn3host::LinuxWinn3PromotionState(&promote_status,
                                                           &promote_reason);
    if (verdict == winsvpn::winn3host::LinuxWinn3Promotion::kRefuse) break;
    if (verdict == winsvpn::winn3host::LinuxWinn3Promotion::kPromote &&
        promote_status.valid) {
      break;
    }
    if (!winsvpn::winn3host::LinuxWinn3EngineRunning()) break;
    const uint64_t now = NowMs();
    if (probes_sent < kMaxPromotionProbes && now >= next_probe_at &&
        promote_status.valid &&
        promote_status.gate_state == winsvpn::winn3::kCarryingGate &&
        promote_status.rx_packets == 0) {
      (void)winsvpn::winn3host::SendLinuxWinn3InnerPromotionProbe(params);
      ++probes_sent;
      next_probe_at = now + kPromotionProbeIntervalMs;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  if (verdict == winsvpn::winn3host::LinuxWinn3Promotion::kPromote &&
      promote_status.valid) {
    winsvpn::winn3::PosturePlan promoted_plan;
    const winsvpn::winn3host::LinuxWinn3PostureResult promoted =
        winsvpn::winn3host::ApplyLinuxWinn3PromotedPosture(
            params, promote_status, privileged, &promoted_plan);
    winsvpn::winn3host::SetLinuxWinn3ResolverStatus(promoted);
    if (promoted.outcome ==
        winsvpn::winn3host::LinuxWinn3PostureOutcome::kApplied) {
      g_winn_tunnel_active = true;
      return true;
    }
    std::string residue;
    const bool stopped_clean =
        winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, &residue);
    std::string text =
        "The standalone Winn Protocol v3 session could not be promoted, so "
        "the connection was stopped. " +
        winsvpn::winn3host::DescribeLinuxWinn3PostureResult(promoted);
    if (!stopped_clean) {
      text += " " + residue;
    }
    return refuse(text);
  }

  // The gate never said promote. For a served standalone document this is the
  // resolver gap: promotion is refused because the served `[winn]` carries no
  // resolver. Refuse and tear down cleanly rather than leave residue or a
  // false "protected" state.
  //
  // LANE DIAGNOSTIC, 2026-08-21 (app-level live-test lane): dump the host pump
  // counters and the engine's own status document on this refusal path, so a
  // lab transcript can tell "no inner traffic entered the tun" from "the
  // engine dropped the return path". Counters only, never key material.
  std::fprintf(stderr,
               "winn3 promotion refusal diagnostics: pump=%s engine=%s\n",
               winsvpn::winn3host::LinuxWinn3PumpStatsJson().c_str(),
               ExtractJsonCounters(
                   winsvpn::winn3host::LinuxWinn3EngineStatusJson(),
                   {"max_datagram", "queue_depth", "queue_length", "uptime_ms",
                    "tx_datagrams", "tx_bytes", "tx_rejected", "rx_datagrams",
                    "rx_bytes", "rx_dropped", "rx_oversize", "rx_foreign_sender"})
                   .c_str());
  std::string residue;
  const bool stopped_clean =
      winsvpn::winn3host::StopLinuxWinn3Standalone(privileged, &residue);
  std::string text =
      "The standalone Winn Protocol v3 session could not be promoted, so the "
      "connection was stopped. " +
      (promote_reason.empty()
           ? std::string("The gate did not reach the promotion state.")
           : promote_reason) +
      (!stopped_clean ? " " + residue : std::string());
  return refuse(text);
}

bool StartTunnel(const std::string& raw_config, int64_t transition_generation,
                 std::string* error) {
  if (transition_generation <= 0 ||
      transition_generation <= g_canceled_winn3_generation_floor) {
    // A rejected start did not run, so the previous start's outcome flag must
    // not leak into the handler's failure path and restamp the Winn v3 proof
    // or grant from this canceled request.
    g_last_start_was_winn3 = false;
    if (error != nullptr) {
      *error = "Tunnel start was canceled before the transport launched.";
    }
    return false;
  }

  g_linux_split_tunnel_ready = false;
  g_linux_excluded_apps.clear();
  g_last_start_was_winn3 = false;
  {
    std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
    g_last_winn3_proof = winsvpn::winn3host::Winn3StartProof();
    if (winsvpn::winn3host::LinuxConfigSelectsWinn3(raw_config)) {
      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();
    }
  }
  // Any previous Winn session is over before a new tunnel is negotiated.
  winsvpn::winn::StopLinuxWinnEngine();
  g_winn_tunnel_active = false;
  g_winn_last_tx_payload = -1;
  g_winn_last_rx_payload = -1;
  g_winn_unhealthy_streak = 0;
  std::string bypass_cgroup;
  const std::map<std::string, std::string> app_section =
      ParseSection(raw_config, "winsapp");
  const std::string encoded_apps =
      SectionValue(app_section, "excludedpathsb64");
  const std::vector<std::string> excluded_apps =
      DecodeBase64Lines(encoded_apps);
  if (!encoded_apps.empty() && excluded_apps.empty()) {
    *error = "The Linux app-exclusion payload is invalid.";
    return false;
  }
  for (const std::string& desktop_file : excluded_apps) {
    LinuxDesktopApp app;
    if (!LoadLinuxDesktopApp(desktop_file, &app)) {
      // Desktop launchers can disappear after an application is uninstalled
      // or its packaging format changes.  A stale exclusion must not prevent
      // the protected tunnel from starting.  Skipping it is fail-closed: the
      // unavailable application cannot be launched, and any replacement app
      // remains inside the VPN until the user explicitly selects its current
      // launcher.
      g_warning("Skipped a Linux split-tunnel selection that is no longer valid.");
      continue;
    }
    g_linux_excluded_apps.insert(app.desktop_file);
  }
  if (!g_linux_excluded_apps.empty() &&
      !EnsureLinuxBypassSlice(&bypass_cgroup, error)) {
    g_linux_excluded_apps.clear();
    return false;
  }
  // --- STANDALONE Winn Protocol v3 --------------------------------------
  //
  // Branched HERE, before either winn/1 predicate is consulted, exactly as
  // windows_tunnel_backend.cpp branches on ConfigSelectsWinn3 before reaching
  // ParseWinn3Section. The two parsers must never both be able to claim one
  // document: LinuxConfigSelectsWinn3 is true only for `[winn] carrier =
  // winn3`, and ParseLinuxWinnSection refuses every carrier it cannot build,
  // so the split is exhaustive in both directions.
  //
  // Before this, a served standalone configuration reached the winn/1 relay
  // parser and was refused there -- fail-closed, but refused in the relay's
  // words about a protocol it was not being asked to speak, and with
  // ParseLinuxWinn3Section sitting unreached in the same binary.
  //
  // The split-tunnel and Xray state above has already been set up; the v3 start
  // owns neither, and both are cleared on the way out because a refused start
  // must leave the host exactly as it found it.
  if (winsvpn::winn3host::LinuxConfigSelectsWinn3(raw_config)) {
    g_last_start_was_winn3 = true;
    if (transition_generation > 0 &&
        transition_generation <= g_canceled_winn3_generation_floor) {
      g_last_winn3_proof = winsvpn::winn3host::ClassifyWinn3StartFailure(
          transition_generation, true,
          "Tunnel start was canceled before the transport launched.");
      *error = "Tunnel start was canceled before the transport launched.";
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      return false;
    }
    const bool started = StartLinuxWinn3StandaloneTunnel(raw_config, error);
    if (!started) {
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      winsvpn::winn3host::RememberLinuxWinn3OsError(
          CaptureLinuxWinn3GatewayOsErrorFromConfig(raw_config));
      g_last_winn3_proof =
          winsvpn::winn3host::ClassifyCapturedWinn3StartFailure(
              transition_generation, false,
              error != nullptr ? *error : "");
      return false;
    }
    g_last_winn3_proof =
        winsvpn::winn3host::MakeConnectedWinn3StartProof(transition_generation);
    g_tunnel_session_committed = true;
    return true;
  }

  // --- Winn Protocol v3 over the AmneziaWG relay ------------------------
  //
  // ANTI-DOWNGRADE. Once this returns true there is no path below that starts
  // the tunnel without Winn. A `[winn] enabled = true` configuration that
  // cannot start the Winn path FAILS; it never becomes a classical AmneziaWG
  // start, because the gateway negotiated winn/3 and a client that quietly
  // speaks winn/1 instead has downgraded it without telling anyone.
  const bool winn_selected =
      winsvpn::winn::LinuxConfigSelectsWinnProtocol(raw_config);
  winsvpn::winn::LinuxWinnParams winn_params;
  int winn_seam_fd = -1;
  uint16_t winn_seam_port = 0;
  std::string winn_engine_path;
  // THE STACKED ARRANGEMENT, told apart from the competing one exactly as the
  // Apple, Android and Windows halves tell them apart: by where the Winn
  // engine's own gateway endpoint points. Stacked, it is the Xray inbound on
  // loopback -- AmneziaWG -> Winn seam -> Winn engine -> Xray -> edge, two
  // distinct loopback ports and no contention for the one AmneziaWG
  // peer-endpoint field. Competing, it is a real gateway, and then both
  // transports genuinely do want that field.
  const bool winn_stealth_chain =
      winn_selected && SectionBool(ParseSection(raw_config, "xray"), "enabled") &&
      SectionValue(ParseSection(raw_config, "winn"), "endpoint") ==
          "127.0.0.1:" +
              SectionValue(ParseSection(raw_config, "xray"), "localport");
  if (winn_selected) {
    const auto fail_winn = [&](const std::string& message) {
      *error = message;
      if (winn_seam_fd >= 0) close(winn_seam_fd);
      StopXrayProcess();
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      return false;
    };
    // Winn and the Xray stealth transport are different OUTER transports and
    // cannot both carry one tunnel WHEN THEY COMPETE. VpnTunnelService refuses
    // that combination natively on Android; refuse it here rather than silently
    // choosing one. Narrowed, not removed: only the stacked arrangement above
    // is let through, and every other pairing still fails closed here.
    if (SectionBool(ParseSection(raw_config, "xray"), "enabled") &&
        !winn_stealth_chain) {
      return fail_winn(
          "This server asks for Winn Protocol v3 and the stealth transport at "
          "the same time. They are different outer transports and cannot both "
          "carry one tunnel, so this connection was stopped.");
    }
    std::string winn_error;
    if (!winsvpn::winn::ParseLinuxWinnSection(raw_config, &winn_params,
                                              &winn_error)) {
      return fail_winn(winn_error);
    }
    // Resolved BEFORE anything touches the network, so a build without the
    // engine fails while the host is still in its pre-tunnel state.
    winn_engine_path = FindWinnDatapathExecutable();
    if (winn_engine_path.empty()) {
      return fail_winn(
          "This server uses Winn Protocol v3, but the Winn datapath engine is "
          "not bundled with this Linux build, so the connection was stopped "
          "rather than started without it.");
    }
    // The seam is bound FIRST, for two reasons: its port has to be known to
    // write the AmneziaWG configuration, and a bound socket means AmneziaWG's
    // first handshake initiations queue in the receive buffer instead of
    // drawing ICMP port-unreachable while the engine is still starting.
    winn_seam_fd = winsvpn::winn::BindLinuxWinnSeam(&winn_seam_port,
                                                    &winn_error);
    if (winn_seam_fd < 0) {
      return fail_winn(winn_error);
    }
    // AmneziaWG's own source port, chosen here and written into its
    // configuration as ListenPort, so the seam admits exactly that socket from
    // the first datagram instead of whichever local process sends first
    // (ANDROID-59 does the same on Android).
    if (!winsvpn::winn::ReserveLinuxAwgListenPort(&winn_params.awg_listen_port,
                                                   &winn_error)) {
      return fail_winn(winn_error);
    }
  }

  if (!StartXrayTransportIfNeeded(raw_config, error)) {
    if (winn_seam_fd >= 0) close(winn_seam_fd);
    StopLinuxBypassSlice();
    g_linux_excluded_apps.clear();
    return false;
  }
  // "winn" MUST be in this list. validate_config's awk allowlist accepts only
  // [interface] and [peer]; a surviving [winn] section makes it `exit 65` and
  // the start fails with "rejected unsafe or malformed AWG config". Stripping
  // it is also what leaves exactly one `Endpoint` line for the seam rewrite
  // below to find -- the [winn] section carries an `endpoint` key of its own.
  std::string awg_config = StripSections(
      raw_config, {"xray", "winsdebug", "winsapp", "winsboost", "winn"});
  // A disabled IPv6 stack cannot accept awg-quick's ::/0 route. Removing only
  // IPv6 AllowedIPs is safe here because the host has no usable IPv6 path to
  // leak; IPv4 remains protected and must still pass the bound tunnel probe.
  if (HostIpv6Disabled()) {
    awg_config = RemoveIpv6AllowedIps(awg_config);
  }
  // The seam redirect. From here on AmneziaWG's outer datagrams go to a
  // loopback socket this process owns instead of to the gateway, and the ONLY
  // thing that still addresses the gateway is the Winn engine -- which is
  // exactly what makes the destination-matched fwmark exclusion below both
  // sufficient and narrow.
  if (winn_selected) {
    std::string redirected;
    if (!winsvpn::winn::RewriteAwgPeerEndpointToSeam(
            awg_config, winn_seam_port, winn_params.awg_listen_port,
            &redirected)) {
      *error =
          "Refusing to start Winn Protocol v3: this AmneziaWG configuration "
          "does not have exactly one interface and one peer endpoint to "
          "redirect to the Winn outer-datagram seam.";
      close(winn_seam_fd);
      StopXrayProcess();
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      return false;
    }
    awg_config = redirected;
  }
  const std::string data_directory = DataDirectory();
  if (data_directory.empty()) {
    *error = "No private Linux data directory is available for the tunnel config.";
    if (winn_seam_fd >= 0) close(winn_seam_fd);
    StopXrayProcess();
    StopLinuxBypassSlice();
    return false;
  }
  const std::string config_path = data_directory + "/winsvpn.conf";
  if (!WriteFile(config_path, awg_config)) {
    *error = "Unable to write Linux tunnel config.";
    if (winn_seam_fd >= 0) close(winn_seam_fd);
    StopXrayProcess();
    StopLinuxBypassSlice();
    return false;
  }
  const std::vector<std::string> runner = PrivilegedRunner();
  if (runner.empty() && geteuid() != 0) {
    *error =
        "Linux tunnel setup needs pkexec, sudo, or root privileges to create "
        "the VPN interface.";
    if (winn_seam_fd >= 0) close(winn_seam_fd);
    StopXrayProcess();
    StopLinuxBypassSlice();
    return false;
  }
  // The privileged half installs the outer-socket exclusion: awg-quick's own
  // fwmark, applied to datagrams addressed to this endpoint, plus the
  // recursion check that proves the marked route does not resolve back into
  // the tunnel. It can only run once awg-quick has published the mark, which
  // is why it is inside the privileged script rather than here.
  //
  // EMPTY IN THE STACKED ARRANGEMENT, and that is the correct value rather than
  // a skipped step. `activate_winn_transport` installs a route exclusion and an
  // fwmark rule keyed on the Winn gateway's DESTINATION, because on a plain
  // winn/3 tunnel the Winn engine is the only thing on this host still
  // addressing the gateway. Stacked, the Winn engine addresses 127.0.0.1 --
  // never matched by awg-quick's default route, so it needs no exclusion -- and
  // the socket that actually leaves the device is Xray's, which already has the
  // exclusion v1's stealth leg installs for it. Passing 127.0.0.1 here would
  // install a `127.0.0.1/32 via <physical gateway>` route, which is wrong.
  // `activate_winn_transport` returns 0 immediately on an empty value.
  const int exit_code = RunPrivilegedTunnelCommand(
      "start", config_path, bypass_cgroup,
      winn_selected && !winn_stealth_chain ? winn_params.endpoint
                                           : std::string());
  if (exit_code != 0) {
    // 66 is the one start failure the app cannot resolve on the user's behalf:
    // a chain named WINSVPN_KS exists but carries rules this app did not
    // write, so it was deliberately left alone. Every other kill-switch
    // orphan -- including a chain restored across a reboot after its /run
    // marker was wiped -- is now reclaimed automatically by
    // cleanup_kill_switch, so it never reaches the user as an error at all.
    // Give this case its own text, because the generic string sends someone
    // whose machine has no network at all off to check PolicyKit.
    *error =
        exit_code == kLinuxUnownedFirewallChainExit
            ? std::string(kLinuxUnownedFirewallChainMessage)
        : winn_selected
            ? std::string(
                  "Linux Winn Protocol v3 start failed. Verify the bundled "
                  "AmneziaWG runtime, iptables mark and connmark support, and "
                  "PolicyKit/root permission.")
            : std::string(
                  "Linux tunnel start failed. Verify the bundled AmneziaWG "
                  "runtime, required Linux networking tools, and "
                  "PolicyKit/root permission.");
    if (winn_seam_fd >= 0) close(winn_seam_fd);
    StopXrayProcess();
    StopLinuxBypassSlice();
    g_linux_excluded_apps.clear();
    std::remove(config_path.c_str());
    return false;
  }
  if (winn_selected) {
    // Only now: the exclusion is installed and verified, so the engine's own
    // socket has somewhere to go that is not back into this tunnel.
    std::string winn_error;
    if (!winsvpn::winn::StartLinuxWinnEngine(winn_engine_path, winn_seam_fd,
                                             winn_params, &winn_error)) {
      *error = winn_error;
      // StartLinuxWinnEngine owns the seam descriptor on both outcomes.
      winn_seam_fd = -1;
      RunPrivilegedTunnelCommand("stop");
      StopXrayProcess();
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      std::remove(config_path.c_str());
      return false;
    }
    winn_seam_fd = -1;
    // ROUTE-PROMOTION GATE. StartLinuxWinnEngine returning true means the
    // engine PROCESS started; it does not mean one datagram has crossed.
    // Without this poll a gateway whose outer UDP is dropped on path -- the
    // censorship case this protocol exists for -- leaves the host's default
    // route, DNS and IPv6 pointing into a tunnel that carries nothing, while
    // the app reports success and IsTunnelRunning keeps answering true because
    // the engine is alive and healthy. The engine already publishes the
    // answer; Linux was simply never asking for it.
    //
    // Stated precisely so it is not overclaimed later: this is NOT the staged
    // promotion Windows (windows_tunnel_backend.cpp, routes installed only
    // after WaitForWinnTransportConvergence) and Apple
    // (runWinnDatapathProofConvergence, which never widens a narrow bootstrap
    // posture until the proof lands) have. By the time control reaches here
    // awg-quick has ALREADY claimed the host's routing, and narrowing that
    // would mean running the interface Table=off and owning every route by
    // hand -- a much larger change than this one. What this buys is
    // fail-closed behaviour inside a bounded deadline instead of a silent
    // black hole that persists until the user notices nothing loads.
    //
    // The refusal wording comes back in *error and reaches the user through the
    // method channel, which is the only trace a production install has: the
    // g_warning this replaces went to stderr, where nobody sees it. It is
    // written by DecideWinnTransportGate and never carries any part of the
    // status document, whose `gateway_endpoint` is the customer's real gateway
    // address.
    if (!WaitForLinuxWinnTransportConvergence(error)) {
      winsvpn::winn::StopLinuxWinnEngine();
      RunPrivilegedTunnelCommand("stop");
      StopXrayProcess();
      StopLinuxBypassSlice();
      g_linux_excluded_apps.clear();
      std::remove(config_path.c_str());
      return false;
    }
    g_winn_last_tx_payload = -1;
    g_winn_last_rx_payload = -1;
    g_winn_unhealthy_streak = 0;
    g_winn_tunnel_active = true;
  }
  if (!g_xray_config_path.empty()) {
    std::remove(g_xray_config_path.c_str());
    g_xray_config_path.clear();
  }
  std::remove(config_path.c_str());
  g_linux_split_tunnel_ready = !g_linux_excluded_apps.empty();
  g_tunnel_session_committed = true;
  return true;
}

// Copies out just the INTEGER fields named in `keys` from a JSON document.
//
// The engine's status document carries `gateway_endpoint` -- the customer's
// real gateway address -- so the document itself must never be written to a
// log. Its counters are not sensitive and are exactly what is wanted, so they
// are extracted by name and nothing else is emitted.
std::string ExtractJsonCounters(const std::string& json,
                                const std::vector<std::string>& keys) {
  std::string out;
  for (const std::string& key : keys) {
    const std::string needle = "\"" + key + "\":";
    const size_t at = json.find(needle);
    if (at == std::string::npos) continue;
    size_t i = at + needle.size();
    std::string value;
    while (i < json.size() &&
           (std::isdigit(static_cast<unsigned char>(json[i])) != 0)) {
      value.push_back(json[i]);
      ++i;
    }
    if (value.empty()) continue;
    if (!out.empty()) out.push_back(' ');
    out += key + "=" + value;
  }
  return out;
}

bool StopTunnel(std::string* error) {
  g_linux_split_tunnel_ready = false;
  g_linux_excluded_apps.clear();

  // THE STATUS DOCUMENT NOW HAS A CALLER. LinuxWinnEngineStatusJson() had none
  // at all before this: the engine answered StatusRequest frames that nothing
  // in the product ever sent, so its tx_rejected/rx_dropped counters could not
  // reach an operator by any route. Read here, while the engine is still up,
  // because after StopLinuxWinnEngine() there is nothing left to ask.
  //
  // Read the SEAM stats alongside them, and understand which answers what: the
  // engine's counters say what the ENGINE REFUSED, and they were zero
  // throughout a 26.51% loss event because nothing ever reached the engine to
  // be refused. The seam's counters say what the HOST saw. Neither substitutes
  // for the other, which is why both are printed on the same line.
  if (g_winn_tunnel_active) {
    const std::string engine_counters = ExtractJsonCounters(
        winsvpn::winn::LinuxWinnEngineStatusJson(),
        {"tx_datagrams", "tx_rejected", "rx_datagrams", "rx_dropped",
         "rx_oversize", "rx_foreign_sender", "queue_length"});
    const std::string seam_stats = winsvpn::winn::LinuxWinnSeamStatsJson();
    if (!engine_counters.empty()) {
      std::fprintf(stderr, "winn engine at close: %s\n",
                   engine_counters.c_str());
    }
    if (!seam_stats.empty()) {
      // Safe in full: every field is an integer the host counted itself.
      std::fprintf(stderr, "winn seam at close: %s\n", seam_stats.c_str());
    }
  }

  // THE STANDALONE WINN3 TEARDOWN, BEFORE THE RELAY ONE. The fleet measured
  // the residue of a stop that ran only the relay half: the tun, the /1 pair,
  // the /32 exclusion, the systemd-resolved settings and the engine process
  // all stayed up, and the lane had to kill them by hand. That was this call
  // missing. StopLinuxWinn3Standalone is the SAME unified teardown the start
  // path's own failure exits and the tun e2e harness use, and it is
  // idempotent: with no standalone session remembered it runs nothing and
  // succeeds, so the relay path below is untouched.
  //
  // A standalone session never started awg-quick, so its stop does not run
  // awg-quick down either: there is no `winsvpn` interface for it to find,
  // and running it would turn a clean standalone stop into a reported
  // failure -- which is exactly the failure that left the measured residue
  // for a human to clean up. The split-tunnel slice is still owed a stop,
  // because EnsureLinuxBypassSlice ran before the v3 branch in StartTunnel.
  if (winsvpn::winn3host::LinuxWinn3StandaloneSessionWasStarted()) {
    std::string winn3_error;
    const winsvpn::winn3host::LinuxWinn3PrivilegedRunner winn3_runner =
        [](const std::vector<std::string>& argv,
           const std::string& stdin_bytes, std::string* err) {
          return RunPrivilegedWinn3Posture(argv, stdin_bytes, err);
        };
    const bool winn3_ok = winsvpn::winn3host::StopLinuxWinn3Standalone(
        winn3_runner, &winn3_error);
    StopLinuxBypassSlice();
    StopTunnelPowerProtection();
    g_winn_tunnel_active = false;
    g_winn_last_tx_payload = -1;
    g_winn_last_rx_payload = -1;
    g_winn_unhealthy_streak = 0;
    if (g_last_winn3_proof.outcome ==
        winsvpn::winn3host::Winn3ProofOutcome::kConnected) {
      g_last_winn3_proof = winsvpn::winn3host::Winn3StartProof();
    }
    if (!winn3_ok) {
      if (error != nullptr) *error = winn3_error;
      return false;
    }
    const int ks_rc = RunPrivilegedTunnelCommand("winn3-ks-off");
    if (ks_rc != 0) {
      if (error != nullptr) {
        *error = ks_rc == kLinuxUnownedFirewallChainExit
                     ? std::string(kLinuxUnownedFirewallChainMessage)
                     : std::string(
                           "The Winn Protocol v3 network block could not be "
                           "removed. Authorize cleanup and try again.");
      }
      return false;
    }
    g_tunnel_session_committed = false;
    return true;
  }

  // Before awg-quick goes down, so the engine stops draining a seam that is
  // about to have nothing writing into it. Idempotent when Winn never started.
  winsvpn::winn::StopLinuxWinnEngine();
  StopXrayProcess();
  StopTunnelPowerProtection();
  const std::vector<std::string> runner = PrivilegedRunner();
  if (runner.empty() && geteuid() != 0) {
    *error =
        "Linux tunnel stop needs pkexec, sudo, or root privileges to remove "
        "the VPN interface.";
    return false;
  }
  const int exit_code = RunPrivilegedTunnelCommand("stop");
  if (exit_code != 0) {
    *error =
        exit_code == kLinuxUnownedFirewallChainExit
            ? std::string(kLinuxUnownedFirewallChainMessage)
            : std::string(
                  "Linux tunnel stop failed. The protected route may still be "
                  "active; authorize cleanup and try again before starting "
                  "another route.");
    return false;
  }
  StopLinuxBypassSlice();
  g_winn_tunnel_active = false;
  g_winn_last_tx_payload = -1;
  g_winn_last_rx_payload = -1;
  g_winn_unhealthy_streak = 0;
  const std::string data_directory = DataDirectory();
  if (!data_directory.empty()) {
    std::remove((data_directory + "/winsvpn.conf").c_str());
  }
  g_tunnel_session_committed = false;
  return true;
}

std::string ConfigFromCall(FlMethodCall* method_call) {
  FlValue* args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return "";
  }
  FlValue* config = fl_value_lookup_string(args, "config");
  if (config == nullptr || fl_value_get_type(config) != FL_VALUE_TYPE_STRING) {
    return "";
  }
  return fl_value_get_string(config);
}

std::string StringArgFromCall(FlMethodCall* method_call,
                              const char* key) {
  FlValue* args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return "";
  }
  FlValue* value = fl_value_lookup_string(args, key);
  if (value == nullptr || fl_value_get_type(value) != FL_VALUE_TYPE_STRING) {
    return "";
  }
  return fl_value_get_string(value);
}

bool TryStringArgFromCall(FlMethodCall* method_call,
                          const char* key,
                          std::string* output) {
  if (output == nullptr) return false;
  FlValue* args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return false;
  }
  FlValue* value = fl_value_lookup_string(args, key);
  if (value == nullptr || fl_value_get_type(value) != FL_VALUE_TYPE_STRING) {
    return false;
  }
  *output = fl_value_get_string(value);
  return true;
}

bool TryExactInt64ArgFromCall(FlMethodCall* method_call, const char* key,
                              int64_t* output) {
  if (output == nullptr) return false;
  *output = 0;
  FlValue* args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return false;
  }
  FlValue* value = fl_value_lookup_string(args, key);
  if (value == nullptr) return false;
  if (fl_value_get_type(value) != FL_VALUE_TYPE_INT) return false;
  *output = fl_value_get_int(value);
  return true;
}

bool TryInt64ArgFromCall(FlMethodCall* method_call, const char* key,
                         int64_t* output) {
  if (output == nullptr) return false;
  *output = 0;
  FlValue* args = fl_method_call_get_args(method_call);
  if (args == nullptr || fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
    return false;
  }
  FlValue* value = fl_value_lookup_string(args, key);
  if (value == nullptr) return false;
  if (fl_value_get_type(value) == FL_VALUE_TYPE_INT) {
    *output = fl_value_get_int(value);
    return true;
  }
  if (fl_value_get_type(value) == FL_VALUE_TYPE_STRING) {
    const std::string text = fl_value_get_string(value);
    if (text.empty()) return false;
    char* end = nullptr;
    const long long parsed = std::strtoll(text.c_str(), &end, 10);
    if (end == nullptr || *end != '\0') return false;
    *output = static_cast<int64_t>(parsed);
    return true;
  }
  return false;
}

bool ShowAnnouncementNotification(const std::string& title,
                                  const std::string& body) {
  if (Trim(body).empty()) {
    return false;
  }
  const std::string notify_send = Which("notify-send");
  if (notify_send.empty()) {
    return false;
  }
  const std::string resolved_title =
      Trim(title).empty() ? "Win's VPN Announcement" : title;
  // B-APP-004: argv form via g_spawn_async (GLib reaps the child, so the
  // announcement stays off the UI thread exactly as the old `&` did). The
  // hub-served body crosses as one argv entry; nothing is shell-quoted.
  std::vector<std::string> argv = {notify_send, "--app-name=Win's VPN",
                                   resolved_title, body};
  std::vector<char*> raw;
  raw.reserve(argv.size() + 1);
  for (const std::string& argument : argv) {
    raw.push_back(const_cast<char*>(argument.c_str()));
  }
  raw.push_back(nullptr);
  GError* spawn_error = nullptr;
  const gboolean spawned =
      g_spawn_async(nullptr, raw.data(), nullptr,
                    static_cast<GSpawnFlags>(G_SPAWN_STDOUT_TO_DEV_NULL |
                                             G_SPAWN_STDERR_TO_DEV_NULL),
                    nullptr, nullptr, nullptr, &spawn_error);
  if (spawn_error != nullptr) {
    g_warning("Failed to show the Linux announcement notification: %s",
              spawn_error->message);
    g_error_free(spawn_error);
  }
  return spawned == TRUE;
}

void RespondSuccess(FlMethodCall* method_call, FlValue* value) {
  g_autoptr(FlValue) owned_value = value;
  g_autoptr(GError) error = nullptr;
  if (!fl_method_call_respond_success(method_call, owned_value, &error)) {
    g_warning("Failed to send Linux tunnel success response: %s",
              error != nullptr ? error->message : "unknown error");
  }
}

void RespondError(FlMethodCall* method_call,
                  const char* code,
                  const std::string& message,
                  FlValue* details = nullptr) {
  g_autoptr(GError) error = nullptr;
  g_autoptr(FlValue) owned_details = details;
  if (!fl_method_call_respond_error(method_call, code, message.c_str(),
                                    owned_details, &error)) {
    g_warning("Failed to send Linux tunnel error response: %s",
              error != nullptr ? error->message : "unknown error");
  }
}

FlValue* Winn3ProofDetailsValue(
    const winsvpn::winn3host::Winn3StartProof& proof) {
  FlValue* details = fl_value_new_map();
  fl_value_set_string_take(
      details, "winn3_verdict",
      fl_value_new_string(
          winsvpn::winn3host::Winn3ProofOutcomeName(proof.outcome)));
  fl_value_set_string_take(details, "winn3_start_generation",
                           fl_value_new_int(proof.generation));
  fl_value_set_string_take(details, "winn3_start_token",
                           fl_value_new_int(proof.start_token));
  fl_value_set_string_take(details, "winn3_start_canceled",
                           fl_value_new_bool(proof.canceled));
  if (!proof.selection_generation.empty()) {
    fl_value_set_string_take(
        details, "winn3_selection_generation",
        fl_value_new_string(proof.selection_generation.c_str()));
  }
  if (!proof.failed_node.empty()) {
    fl_value_set_string_take(details, "winn3_failed_node",
                             fl_value_new_string(proof.failed_node.c_str()));
  }
  const int64_t auth = winsvpn::winn3host::Winn3AuthorizationToken(proof);
  if (auth > 0) {
    fl_value_set_string_take(details, "winn3_awg_xray_authorization_token",
                             fl_value_new_int(auth));
  }
  return details;
}

struct SecureMethodCallContext {
  FlMethodCall* method_call = nullptr;
};

void DestroySecureMethodCallContext(gpointer data) {
  auto* context = static_cast<SecureMethodCallContext*>(data);
  if (context == nullptr) return;
  if (context->method_call != nullptr) {
    g_object_unref(context->method_call);
  }
  delete context;
}

void CompleteSecureMethodCall(LinuxSecureTextAsyncOperation operation,
                              const LinuxSecureTextAsyncResult& result,
                              gpointer user_data) {
  auto* context = static_cast<SecureMethodCallContext*>(user_data);
  FlMethodCall* method_call = context->method_call;
  if (!result.succeeded) {
    RespondError(method_call, "LINUX_SECURE_STORE_FAILED",
                 result.error.empty() ? "Linux secure-state request failed."
                                      : result.error);
    return;
  }
  if (operation == LinuxSecureTextAsyncOperation::kRead) {
    RespondSuccess(method_call, result.found
                                    ? fl_value_new_string(result.value.c_str())
                                    : fl_value_new_null());
    return;
  }
  RespondSuccess(method_call, fl_value_new_bool(true));
}

SecureMethodCallContext* RetainSecureMethodCall(FlMethodCall* method_call) {
  auto* context = new SecureMethodCallContext;
  context->method_call = static_cast<FlMethodCall*>(g_object_ref(method_call));
  return context;
}

void MethodCallHandler(FlMethodChannel* channel,
                       FlMethodCall* method_call,
                       gpointer user_data) {
  (void)channel;
  (void)user_data;
  const std::string method = fl_method_call_get_name(method_call);
  if (method == "eraseLocalAccountRuntime") {
    RespondSuccess(method_call,
                   fl_value_new_bool(EraseLocalAccountRuntime()));
    return;
  }
  if (method == "getTunnelState") {
    RespondSuccess(method_call, fl_value_new_bool(IsTunnelRunning()));
    return;
  }
  if (method == "getTunnelReadiness" || method == "getTunnelStatus") {
    RespondSuccess(method_call, TunnelReadinessValue());
    return;
  }
  if (method == "probeVpnInternet") {
    RespondSuccess(method_call, ProbeInternetValue());
    return;
  }
  if (method == "readSecureText") {
    const std::string name = StringArgFromCall(method_call, "name");
    if (!IsAllowedLinuxSecureTextName(name)) {
      RespondError(method_call, "BAD_ARGS", "Secure text name is invalid.");
      return;
    }
    RunLinuxSecureTextAsync(
        LinuxSecureTextAsyncOperation::kRead, name, "",
        CompleteSecureMethodCall, RetainSecureMethodCall(method_call),
        DestroySecureMethodCallContext);
    return;
  }
  if (method == "writeSecureText") {
    const std::string name = StringArgFromCall(method_call, "name");
    std::string plaintext;
    if (!IsAllowedLinuxSecureTextName(name) ||
        !TryStringArgFromCall(method_call, "value", &plaintext)) {
      RespondError(method_call, "BAD_ARGS",
                   "Secure text name or value is invalid.");
      return;
    }
    RunLinuxSecureTextAsync(
        LinuxSecureTextAsyncOperation::kWrite, name, std::move(plaintext),
        CompleteSecureMethodCall, RetainSecureMethodCall(method_call),
        DestroySecureMethodCallContext);
    return;
  }
  if (method == "deleteSecureText") {
    const std::string name = StringArgFromCall(method_call, "name");
    if (!IsAllowedLinuxSecureTextName(name)) {
      RespondError(method_call, "BAD_ARGS", "Secure text name is invalid.");
      return;
    }
    RunLinuxSecureTextAsync(
        LinuxSecureTextAsyncOperation::kDelete, name, "",
        CompleteSecureMethodCall, RetainSecureMethodCall(method_call),
        DestroySecureMethodCallContext);
    return;
  }
  if (method == "getInstalledApps") {
    FlValue* values = fl_value_new_list();
    for (const LinuxDesktopApp& app : ListLinuxInstalledApps()) {
      FlValue* value = fl_value_new_map();
      fl_value_set_string_take(value, "name",
                               fl_value_new_string(app.name.c_str()));
      fl_value_set_string_take(
          value, "package_name",
          fl_value_new_string(app.desktop_file.c_str()));
      fl_value_set_string_take(value, "is_system", fl_value_new_bool(false));
      fl_value_append_take(values, value);
    }
    RespondSuccess(method_call, values);
    return;
  }
  if (method == "launchSplitTunnelApp") {
    const std::string desktop_file =
        StringArgFromCall(method_call, "package_name");
    std::string error;
    if (desktop_file.empty() ||
        !LaunchLinuxBypassApp(desktop_file, &error)) {
      RespondError(method_call, "LINUX_SPLIT_APP_LAUNCH_FAILED",
                   error.empty() ? "Linux bypass app is missing." : error);
      return;
    }
    RespondSuccess(method_call,
                   fl_value_new_string("App launched outside the VPN"));
    return;
  }
  if (method == "stopTunnel") {
    int64_t cancellation_generation = 0;
    if (TryInt64ArgFromCall(method_call, "cancellationGeneration",
                            &cancellation_generation) &&
        cancellation_generation > 0 &&
        cancellation_generation > g_canceled_winn3_generation_floor) {
      g_canceled_winn3_generation_floor = cancellation_generation;
    }
    {
      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();
    }
    std::string error;
    if (!StopTunnel(&error)) {
      RespondError(method_call, "LINUX_TUNNEL_STOP_FAILED", error);
      return;
    }
    RespondSuccess(method_call, fl_value_new_string("Tunnel stopped"));
    return;
  }
  if (method == "startTunnel") {
    const std::string config = ConfigFromCall(method_call);
    if (config.empty()) {
      RespondError(method_call, "BAD_ARGS", "Configuration payload missing");
      return;
    }
    if (winsvpn::winn3host::LinuxConfigSelectsWinn3(config)) {
      std::string independent_selected_node;
      std::string selected_node_error;
      if (!TryStringArgFromCall(method_call, "selected_node",
                                &independent_selected_node) ||
          !winsvpn::winn3host::ValidateLinuxWinn3IndependentSelectedNode(
              config, independent_selected_node, &selected_node_error)) {
        RespondError(
            method_call, "LINUX_WINN3_SELECTED_NODE_REQUIRED",
            selected_node_error.empty()
                ? "Winn Protocol v3 requires an independently selected node."
                : selected_node_error);
        return;
      }
    }
    int64_t transition_generation = 0;
    (void)TryInt64ArgFromCall(method_call, "transitionGeneration",
                              &transition_generation);
    int64_t winn3_start_token = 0;
    const bool has_token = TryExactInt64ArgFromCall(
        method_call, "winn3StartToken", &winn3_start_token);
    int64_t winn3_start_generation = 0;
    const bool has_winn3_generation = TryExactInt64ArgFromCall(
        method_call, "winn3StartGeneration", &winn3_start_generation);
    std::string selection_generation;
    const bool has_selection = TryStringArgFromCall(
        method_call, "winn3SelectionGeneration", &selection_generation);
    std::string failed_node;
    const bool has_failed_node =
        TryStringArgFromCall(method_call, "winn3FailedNode", &failed_node);
    int64_t cover_auth_token = 0;
    const bool has_cover_auth = TryExactInt64ArgFromCall(
        method_call, "winn3AwgXrayAuthorizationToken", &cover_auth_token);
    std::string cover_target;
    const bool has_cover_target = TryStringArgFromCall(
        method_call, "winn3CoverExactTarget", &cover_target);
    std::string cover_leg_text;
    const bool has_cover_leg =
        TryStringArgFromCall(method_call, "winn3CoverLeg", &cover_leg_text);
    const bool selects_winn3 =
        winsvpn::winn3host::LinuxConfigSelectsWinn3(config);
    if (selects_winn3) {
      if (!has_token || winn3_start_token <= 0 || !has_winn3_generation ||
          winn3_start_generation != transition_generation || !has_selection ||
          !winsvpn::winn3host::IsWinn3SelectionGeneration(
              selection_generation) ||
          !has_failed_node ||
          !winsvpn::winn3host::IsConcreteWinn3NodeSlug(failed_node)) {
        RespondError(
            method_call, "LINUX_WINN3_START_IDENTITY_REQUIRED",
            "Winn v3 start token, generation, selection, and failed node "
            "must be exact positive identities.");
        return;
      }
    }
    const bool cover_requested =
        has_cover_auth || has_cover_target || has_cover_leg ||
        (!selects_winn3 && has_token);
    if (!selects_winn3 && cover_requested) {
      winsvpn::winn3host::Winn3CoverLeg cover_leg =
          winsvpn::winn3host::Winn3CoverLeg::kAwg;
      if (!has_cover_auth || cover_auth_token <= 0 || !has_token ||
          winn3_start_token != cover_auth_token || !has_winn3_generation ||
          winn3_start_generation <= 0 || !has_selection ||
          !has_failed_node || !has_cover_target || !has_cover_leg ||
          !winsvpn::winn3host::ParseWinn3CoverLeg(cover_leg_text, &cover_leg)) {
        RespondError(method_call, "LINUX_WINN3_COVER_GRANT_INVALID",
                     "Cover AWG/Xray start identities are malformed.");
        return;
      }
      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
      if (winsvpn::winn3host::ConsumeWinn3AwgXrayGrant(
              &g_awg_xray_grant, winn3_start_token, winn3_start_generation,
              selection_generation, failed_node, cover_target, cover_leg,
              static_cast<int64_t>(NowMs())) !=
          winsvpn::winn3host::Winn3GrantConsumeResult::kOk) {
        RespondError(method_call, "LINUX_WINN3_COVER_GRANT_REFUSED",
                     "Cover AWG/Xray grant is missing, expired, or mismatched.");
        return;
      }
    } else if (!selects_winn3) {
      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();
    }
    std::string error;
    if (!StartTunnel(config, transition_generation, &error)) {
      // Surface kExclusionBlocked with a distinct code so a caller that
      // retries on a timer can honour the "will never change" contract. The
      // string check is on the closed-set outcome name and the gated error-code
      // token, not on translated prose, so it works in every locale.
      const bool blocked =
          error.find("LINUX_WINN3_EXCLUSION_BLOCKED") != std::string::npos ||
          error.find("exclusion-blocked") != std::string::npos ||
          error.find("THE GATEWAY'S DESTINATION IS ALREADY ROUTED") !=
              std::string::npos;
      if (g_last_start_was_winn3) {
        std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
        g_last_winn3_proof.start_token = winn3_start_token;
        g_last_winn3_proof.selection_generation = selection_generation;
        g_last_winn3_proof.failed_node = failed_node;
        if (g_last_winn3_proof.outcome ==
            winsvpn::winn3host::Winn3ProofOutcome::kOrdinaryConnectivity) {
          winsvpn::winn3host::ArmWinn3AwgXrayGrant(
              winn3_start_token, winn3_start_generation, selection_generation,
              failed_node, static_cast<int64_t>(NowMs()), &g_awg_xray_grant);
        } else {
          g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();
        }
      }
      if (g_last_start_was_winn3 && !blocked) {
        RespondError(method_call,
                     winsvpn::winn3host::Winn3ProofOutcomeName(
                         g_last_winn3_proof.outcome),
                     error, Winn3ProofDetailsValue(g_last_winn3_proof));
        return;
      }
      RespondError(method_call,
                   blocked ? "LINUX_WINN3_EXCLUSION_BLOCKED"
                           : "LINUX_TUNNEL_START_FAILED",
                   error);
      return;
    }
    if (g_last_start_was_winn3) {
      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
      g_last_winn3_proof.start_token = winn3_start_token;
      g_last_winn3_proof.selection_generation = selection_generation;
      g_last_winn3_proof.failed_node = failed_node;
    }
    if (!selects_winn3 && cover_requested) {
      std::lock_guard<std::mutex> lock(g_winn3_session_mutex);
      g_awg_xray_grant = winsvpn::winn3host::Winn3AwgXrayGrant();
    }
    RespondSuccess(method_call, fl_value_new_string("Tunnel Initializing"));
    return;
  }
  // Winn v3 posture outcomes, for an operator or a status document.
  //
  // All four promoted outcomes (applied, not-attempted, rolled-back,
  // partially-applied) plus kExclusionBlocked surface here. A status document
  // that only carries the promoted posture would hide the bootstrap's wedge, and
  // a caller that retries kExclusionBlocked on a timer spins forever -- the
  // fifth value exists precisely to name the one outcome that must not be
  // retried without operator action. Each map carries its own `should_retry`
  // closed-set boolean so a caller need not re-derive it.
  if (method == "getWinn3BootstrapStatus") {
    const std::string json =
        winsvpn::winn3host::LinuxWinn3BootstrapStatusJson();
    RespondSuccess(method_call, fl_value_new_string(json.c_str()));
    return;
  }
  if (method == "getWinn3ResolverStatus") {
    const std::string json =
        winsvpn::winn3host::LinuxWinn3ResolverStatusJson();
    RespondSuccess(method_call, fl_value_new_string(json.c_str()));
    return;
  }
  if (method == "getWinn3PumpStats") {
    std::string json = winsvpn::winn3host::LinuxWinn3PumpStatsJson();
    if (json.empty()) {
      // Publish at least the posture outcomes even when no session is running:
      // the blocking route outlives the process and an operator needs to see it
      // without starting a second session to trigger it.
      const std::string bootstrap =
          winsvpn::winn3host::LinuxWinn3BootstrapStatusJson();
      const std::string resolver =
          winsvpn::winn3host::LinuxWinn3ResolverStatusJson();
      json = "{\"empty\":true,\"bootstrap\":" + bootstrap +
             ",\"resolver\":" + resolver + "}";
    }
    RespondSuccess(method_call, fl_value_new_string(json.c_str()));
    return;
  }
  if (method == "showAnnouncementNotification") {
    const std::string title = StringArgFromCall(method_call, "title");
    const std::string body = StringArgFromCall(method_call, "body");
    RespondSuccess(method_call,
                   fl_value_new_bool(ShowAnnouncementNotification(title, body)));
    return;
  }
  g_autoptr(GError) error = nullptr;
  if (!fl_method_call_respond_not_implemented(method_call, &error)) {
    g_warning("Failed to send Linux tunnel not-implemented response: %s",
              error != nullptr ? error->message : "unknown error");
  }
}

}  // namespace

bool ShutdownLinuxTunnelBackend(std::string* error) {
  if (!g_tunnel_session_committed) return true;
  return StopTunnel(error);
}

void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger) {
  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_channel = fl_method_channel_new(messenger, kChannelName,
                                    FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(g_channel, MethodCallHandler,
                                            nullptr, nullptr);
}
