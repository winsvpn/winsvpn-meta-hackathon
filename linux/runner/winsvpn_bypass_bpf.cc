#include <fcntl.h>
#include <grp.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

volatile sig_atomic_t g_stop = 0;

void StopHandler(int) {
  g_stop = 1;
}

int Bpf(enum bpf_cmd command, union bpf_attr* attributes) {
  return static_cast<int>(
      syscall(__NR_bpf, command, attributes, sizeof(*attributes)));
}

struct bpf_insn Instruction(uint8_t code,
                            uint8_t destination,
                            uint8_t source,
                            int16_t offset,
                            int32_t immediate) {
  struct bpf_insn instruction = {};
  instruction.code = code;
  instruction.dst_reg = destination;
  instruction.src_reg = source;
  instruction.off = offset;
  instruction.imm = immediate;
  return instruction;
}

// The socket-mark BPF program for the split set, as a pure instruction stream.
// It is separated from the BPF_PROG_LOAD syscall so the test can include this
// file (with main renamed) and assert, on a build host that can never attach a
// cgroup link, that the program the helper would submit is well-formed and that
// its socket-mark route is exactly the routing mark the split set was assigned.
// The emitted program: store the requested mark into the sock's mark field, set
// the return register to 1 (accept the socket), and exit -- three instructions.
std::vector<struct bpf_insn> BuildSocketMarkProgram(uint32_t mark) {
  return {
      Instruction(BPF_ST | BPF_MEM | BPF_W, BPF_REG_1, 0,
                  static_cast<int16_t>(offsetof(struct bpf_sock, mark)),
                  static_cast<int32_t>(mark)),
      Instruction(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1),
      Instruction(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
  };
}

int LoadSocketMarkProgram(uint32_t mark, std::string* error) {
  const std::vector<struct bpf_insn> instructions =
      BuildSocketMarkProgram(mark);
  const char license[] = "GPL";
  std::vector<char> verifier_log(64 * 1024, '\0');
  union bpf_attr attributes = {};
  attributes.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
  attributes.expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
  attributes.insn_cnt = static_cast<uint32_t>(instructions.size());
  attributes.insns = reinterpret_cast<uint64_t>(instructions.data());
  attributes.license = reinterpret_cast<uint64_t>(license);
  attributes.log_buf = reinterpret_cast<uint64_t>(verifier_log.data());
  attributes.log_size = static_cast<uint32_t>(verifier_log.size());
  attributes.log_level = 1;
  const int program_fd = Bpf(BPF_PROG_LOAD, &attributes);
  if (program_fd < 0) {
    *error = "BPF_PROG_LOAD failed: " + std::string(std::strerror(errno));
    if (!verifier_log.empty() && verifier_log.front() != '\0') {
      *error += " (verifier: " + std::string(verifier_log.data()) + ")";
    }
  }
  return program_fd;
}

bool ParseUnsigned(const char* text, uint64_t maximum, uint64_t* value) {
  if (text == nullptr || text[0] == '\0' || text[0] == '-') return false;
  errno = 0;
  char* end = nullptr;
  const unsigned long long parsed = std::strtoull(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || parsed == 0 ||
      parsed > maximum) {
    return false;
  }
  *value = static_cast<uint64_t>(parsed);
  return true;
}

int AttachSocketMarkProgram(int program_fd,
                            int cgroup_fd,
                            std::string* error) {
  union bpf_attr attributes = {};
  attributes.link_create.prog_fd = static_cast<uint32_t>(program_fd);
  attributes.link_create.target_fd = static_cast<uint32_t>(cgroup_fd);
  attributes.link_create.attach_type = BPF_CGROUP_INET_SOCK_CREATE;
  // Cgroup BPF links compose safely with existing inherited programs. Link
  // creation does not accept the legacy BPF_PROG_ATTACH ALLOW_MULTI flag.
  attributes.link_create.flags = 0;
  const int link_fd = Bpf(BPF_LINK_CREATE, &attributes);
  if (link_fd < 0) {
    *error = "BPF_LINK_CREATE failed: " + std::string(std::strerror(errno));
  }
  return link_fd;
}

int OpenVerifiedCgroup(const std::string& supplied_path, std::string* error) {
  char resolved[PATH_MAX] = {};
  if (realpath(supplied_path.c_str(), resolved) == nullptr) {
    *error = "Unable to resolve the bypass cgroup: " +
             std::string(std::strerror(errno));
    return -1;
  }
  const std::string path(resolved);
  const std::string root = "/sys/fs/cgroup/";
  if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0) {
    *error = "The bypass cgroup is outside the unified cgroup hierarchy.";
    return -1;
  }
  struct statfs filesystem = {};
  if (statfs(path.c_str(), &filesystem) != 0 ||
      static_cast<unsigned long>(filesystem.f_type) != CGROUP2_SUPER_MAGIC) {
    *error = "Linux per-app bypass requires the unified cgroup v2 hierarchy.";
    return -1;
  }
  const int cgroup_fd =
      open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (cgroup_fd < 0) {
    *error = "Unable to open the bypass cgroup: " +
             std::string(std::strerror(errno));
  }
  return cgroup_fd;
}

int OpenMonitoredPid(pid_t pid, std::string* error) {
#ifdef __NR_pidfd_open
  const int pid_fd = static_cast<int>(syscall(__NR_pidfd_open, pid, 0));
  if (pid_fd < 0) {
    *error = "pidfd_open failed: " + std::string(std::strerror(errno));
  }
  return pid_fd;
#else
  (void)pid;
  *error = "This Linux libc does not expose pidfd_open.";
  return -1;
#endif
}

bool DropPrivileges(std::string* error) {
  struct passwd* nobody = getpwnam("nobody");
  if (nobody == nullptr || nobody->pw_uid == 0 || nobody->pw_gid == 0) {
    *error = "The locked nobody identity is unavailable.";
    return false;
  }
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
      prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
      setgroups(0, nullptr) != 0 || setgid(nobody->pw_gid) != 0 ||
      setuid(nobody->pw_uid) != 0 || geteuid() == 0 || getegid() == 0) {
    *error = "Unable to drop bypass-helper privileges: " +
             std::string(std::strerror(errno));
    return false;
  }
  return true;
}

void Version() {
  std::cout << "winsvpn-bypass-bpf 1.0.0\n";
}

void Usage() {
  std::cerr << "Usage: winsvpn-bypass-bpf --cgroup PATH --mark MARK "
               "--monitor-pid PID\n";
}

void Help() {
  std::cout
      << "Usage: winsvpn-bypass-bpf --cgroup PATH --mark MARK "
         "--monitor-pid PID\n"
      << "\n"
      << "An isolated helper that attaches a cgroup v2 socket-mark BPF link so\n"
      << "selected applications bypass the VPN's protected route, then drops to\n"
      << "the nobody identity while it holds that fail-safe link open. The link\n"
      << "is closed automatically when the monitored PID exits, on signal, or on\n"
      << "any error, returning the applications to the protected route.\n"
      << "\n"
      << "Options:\n"
      << "  --help, -h       Show this help and exit.\n"
      << "  --version        Print the version and exit.\n"
      << "\n"
      << "This helper requires root. It never loads a program on this machine's\n"
      << "build host; it only compiles the BPF instruction sequence and attaches\n"
      << "it once, at runtime, on a Linux target.\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string cgroup_path;
  uint64_t parsed_mark = 0;
  uint64_t parsed_pid = 0;
  for (int i = 1; i < argc; ++i) {
    const std::string argument(argv[i]);
    if (argument == "--help" || argument == "-h") {
      Help();
      return 0;
    } else if (argument == "--version") {
      Version();
      return 0;
    } else if (argument == "--cgroup" && i + 1 < argc) {
      cgroup_path = argv[++i];
    } else if (argument == "--mark" && i + 1 < argc) {
      if (!ParseUnsigned(argv[++i], std::numeric_limits<uint32_t>::max(),
                         &parsed_mark)) {
        Usage();
        return 64;
      }
    } else if (argument == "--monitor-pid" && i + 1 < argc) {
      if (!ParseUnsigned(argv[++i], std::numeric_limits<int32_t>::max(),
                         &parsed_pid)) {
        Usage();
        return 64;
      }
    } else {
      Usage();
      return 64;
    }
  }
  if (geteuid() != 0 || cgroup_path.empty() || parsed_mark == 0 ||
      parsed_pid <= 1) {
    Usage();
    return 64;
  }

  std::string error;
  const int cgroup_fd = OpenVerifiedCgroup(cgroup_path, &error);
  if (cgroup_fd < 0) {
    std::cerr << error << '\n';
    return 65;
  }
  const int pid_fd = OpenMonitoredPid(static_cast<pid_t>(parsed_pid), &error);
  if (pid_fd < 0) {
    std::cerr << error << '\n';
    close(cgroup_fd);
    return 65;
  }
  const int program_fd =
      LoadSocketMarkProgram(static_cast<uint32_t>(parsed_mark), &error);
  if (program_fd < 0) {
    std::cerr << error << '\n';
    close(pid_fd);
    close(cgroup_fd);
    return 65;
  }
  const int link_fd = AttachSocketMarkProgram(program_fd, cgroup_fd, &error);
  close(program_fd);
  close(cgroup_fd);
  if (link_fd < 0) {
    std::cerr << error << '\n';
    close(pid_fd);
    return 65;
  }
  if (!DropPrivileges(&error)) {
    std::cerr << error << '\n';
    close(link_fd);
    close(pid_fd);
    return 65;
  }

  struct sigaction action = {};
  action.sa_handler = StopHandler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, nullptr);
  sigaction(SIGINT, &action, nullptr);
  sigaction(SIGHUP, &action, nullptr);
  signal(SIGPIPE, SIG_IGN);

  std::cout << "READY" << std::endl;
  struct pollfd monitor = {};
  monitor.fd = pid_fd;
  monitor.events = POLLIN;
  while (!g_stop) {
    monitor.revents = 0;
    const int result = poll(&monitor, 1, 1000);
    if (result > 0 &&
        (monitor.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
      break;
    }
    if (result < 0 && errno != EINTR) break;
  }

  // Closing the BPF link is fail-safe: every selected application immediately
  // returns to the protected route if the GUI exits, cleanup signals us, or
  // this minimal helper fails.
  close(link_fd);
  close(pid_fd);
  return 0;
}
