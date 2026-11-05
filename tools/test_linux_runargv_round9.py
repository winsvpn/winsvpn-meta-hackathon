#!/usr/bin/env python3
"""Compile and run the production RunArgv against harmless Linux child fixtures.

Requires Python 3 and a C++17 compiler. No Flutter, network, VPN, privilege
elevation, or lifecycle operations are used. All generated files are temporary.
The subreaper is test-only, letting us check and reap orphaned grandchildren.
"""

from pathlib import Path
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

PREFIX = r'''
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
extern char** environ;
'''

HARNESS = r'''
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void WriteAll(int fd, const std::string& value) {
  size_t offset = 0;
  while (offset < value.size()) {
    const ssize_t count = write(fd, value.data() + offset, value.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    Require(count > 0, "fixture write failed");
    offset += static_cast<size_t>(count);
  }
}

void Record(const std::string& path, const char* role) {
  const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  Require(fd >= 0, "fixture journal open failed");
  WriteAll(fd, std::to_string(getpid()) + " " + std::to_string(getpgrp()) +
                   " " + role + "\n");
  close(fd);
}

void FinishOnTerm(int) { _exit(0); }
volatile sig_atomic_t interrupts = 0;
volatile sig_atomic_t terms = 0;
void Interrupt(int) { interrupts = 1; }
void ObserveTerm(int) { terms = 1; }

int Fixture(const std::string& kind, const std::string& journal) {
  Record(journal, "child");
  Require(getpid() == getpgrp(), "spawn did not establish a dedicated group");
  Require((fcntl(STDOUT_FILENO, F_GETFL) & O_NONBLOCK) == 0,
          "helper stdout unexpectedly nonblocking");
  if (kind == "quiet") return 0;
  if (kind == "exit") return 37;
  if (kind == "signal") { raise(SIGUSR1); return 99; }
  if (kind == "capture") {
    WriteAll(STDOUT_FILENO, " \tstdout\n");
    WriteAll(STDERR_FILENO, "stderr \t\n");
    return 0;
  }
  if (kind == "cap" || kind == "overflow") {
    const std::string chunk(4096, 'x');
    for (int i = 0; i < 256; ++i) WriteAll(STDOUT_FILENO, chunk);
    if (kind == "overflow") WriteAll(STDERR_FILENO, "x");
    return 0;
  }
  if (kind == "delayed") {
    for (int i = 0; i < 8; ++i) {
      WriteAll(STDOUT_FILENO, "x");
      std::this_thread::sleep_for(20ms);
    }
    return 0;
  }
  if (kind == "resistant" || kind == "endless") signal(SIGTERM, SIG_IGN);
  if (kind == "closed") { close(STDOUT_FILENO); close(STDERR_FILENO); }
  if (kind.rfind("tree-", 0) == 0) {
    signal(SIGTERM, kind == "tree-resistant" ? SIG_IGN : FinishOnTerm);
    int ready[2];
    Require(pipe2(ready, O_CLOEXEC) == 0, "fixture readiness pipe failed");
    const pid_t grandchild = fork();
    Require(grandchild >= 0, "fixture fork failed");
    if (grandchild == 0) {
      close(ready[0]);
      signal(SIGTERM, SIG_IGN);
      if (kind == "tree-closed") {
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
      }
      Record(journal, "grandchild");
      WriteAll(ready[1], "x");
      close(ready[1]);
      if (kind == "tree-noisy") {
        for (;;) WriteAll(STDOUT_FILENO, std::string(4096, 'x'));
      }
      for (;;) pause();
    }
    close(ready[1]);
    char byte;
    Require(read(ready[0], &byte, 1) == 1, "fixture grandchild did not start");
    close(ready[0]);
    if (kind == "tree-held" || kind == "tree-noisy") return 0;
  }
  if (kind == "endless") {
    for (;;) WriteAll(STDOUT_FILENO, std::string(4096, 'x'));
  }
  for (;;) pause();
}

int OpenFdCount() {
  DIR* directory = opendir("/proc/self/fd");
  Require(directory != nullptr, "cannot count descriptors");
  int count = 0;
  while (readdir(directory)) ++count;
  closedir(directory);
  return count;
}

void VerifyReaped(const std::string& journal, bool tree) {
  std::ifstream input(journal);
  pid_t pid, group;
  std::string role;
  int children = 0, grandchildren = 0;
  while (input >> pid >> group >> role) {
    Require(group != getpgrp(), "fixture shares caller process group");
    int status = 0;
    if (role == "child") {
      ++children;
      Require(pid == group, "fixture group leader mismatch");
      Require(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD,
              "RunArgv did not reap its direct child");
    } else {
      ++grandchildren;
      const auto deadline = Clock::now() + 1s;
      pid_t waited;
      do {
        waited = waitpid(pid, &status, WNOHANG);
        if (waited != 0) break;
        std::this_thread::sleep_for(5ms);
      } while (Clock::now() < deadline);
      Require(waited == pid, "grandchild survived group cleanup");
      Require(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
              "TERM-resistant grandchild was not killed by escalation");
    }
    Require(kill(pid, 0) == -1 && errno == ESRCH, "fixture process still exists");
  }
  Require(children == 1, "missing direct-child fixture evidence");
  Require(grandchildren == (tree ? 1 : 0), "missing grandchild fixture evidence");
}

void Timer(bool enabled) {
  itimerval timer{};
  if (enabled) {
    timer.it_value.tv_usec = 1000;
    timer.it_interval.tv_usec = 1000;
  }
  Require(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "timer setup failed");
}

int main(int argc, char** argv) {
  try {
    Require(argc >= 4, "fixture arguments missing");
    if (std::string(argv[1]) == "fixture") return Fixture(argv[2], argv[3]);
    Require(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "subreaper setup failed");
    const std::string kind = argv[1], journal = argv[3];
    const std::string output_mode = argv[2];
    const auto mode = output_mode == "capture" ? ProcOutput::kCapture :
        output_mode == "suppress" ? ProcOutput::kSuppress : ProcOutput::kInherit;
    const int before_fds = OpenFdCount();
    if (kind == "invalid") {
      for (int i = 0; i < 30; ++i) {
        Require(RunArgv({}, mode).exit_status == -1, "empty argv succeeded");
        Require(RunArgv({""}, mode).exit_status == -1, "empty path succeeded");
        Require(RunArgv({argv[0]}, mode, 0ms).exit_status == -1,
                "zero timeout accepted");
        Require(RunArgv({argv[0]}, mode, -1ms).exit_status == -1,
                "negative timeout accepted");
        Require(RunArgv({"/nonexistent-winsvpn-round9-fixture"}, mode).exit_status == -1,
                "failed spawn succeeded");
      }
    } else {
      const bool timed = kind == "hang" || kind == "closed" ||
          kind == "resistant" || kind == "endless" || kind == "default" ||
          kind.rfind("tree-", 0) == 0;
      struct sigaction action{};
      action.sa_handler = Interrupt;
      sigemptyset(&action.sa_mask);
      Require(sigaction(SIGALRM, &action, nullptr) == 0, "interrupt setup failed");
      action.sa_handler = ObserveTerm;
      Require(sigaction(SIGTERM, &action, nullptr) == 0, "TERM setup failed");
      if (kind == "failed-wait") signal(SIGCHLD, SIG_IGN);
      const bool interrupted = kind == "delayed" || kind == "resistant";
      if (interrupted) Timer(true);
      std::thread term_sender;
      if (kind == "resistant") term_sender = std::thread([] {
        std::this_thread::sleep_for(100ms);
        kill(getpid(), SIGTERM);
      });
      const std::vector<std::string> args = {
          argv[0], "fixture", kind == "default" ? "resistant" :
              kind == "failed-wait" ? "quiet" : kind, journal};
      const auto started = Clock::now();
      const auto result = kind == "default" ? RunArgv(args, mode) :
          RunArgv(args, mode, timed ? 300ms : 3s);
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          Clock::now() - started).count();
      Timer(false);
      if (term_sender.joinable()) term_sender.join();
      if (interrupted) Require(interrupts != 0, "EINTR stimulus did not run");
      if (kind == "resistant") Require(terms != 0, "caller TERM was blocked");
      else Require(terms == 0, "group cleanup signaled the caller");
      const int expected = timed ? 124 : kind == "overflow" ? 75 :
          kind == "exit" ? 37 : kind == "signal" ? 128 + SIGUSR1 :
          kind == "failed-wait" ? -1 : 0;
      Require(result.exit_status == expected, "wrong exit status");
      if (timed) {
        const long minimum = kind == "default" ? 17000 : 2300;
        Require(elapsed >= minimum && elapsed < minimum + 1500,
                "timeout or two-second grace deadline violated");
      } else Require(elapsed < 2000, "normal completion was delayed");
      std::string expected_output;
      if (mode == ProcOutput::kCapture) {
        if (kind == "capture") expected_output = "stdout\nstderr";
        if (kind == "cap") expected_output = std::string(1024 * 1024, 'x');
        if (kind == "delayed") expected_output = "xxxxxxxx";
      }
      Require(result.output == expected_output, "captured output changed or exceeded cap");
      VerifyReaped(journal, kind.rfind("tree-", 0) == 0);
      std::cout << kind << " " << output_mode << ": exit=" << result.exit_status
                << " elapsed_ms=" << elapsed << " bytes=" << result.output.size() << "\n";
    }
    Require(OpenFdCount() == before_fds, "RunArgv leaked descriptors");
    int status = 0;
    Require(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD,
            "unexpected owned child remains");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << "\n";
    return 1;
  }
}
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux runtime required")
class RunArgvRound9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("c++")
        if compiler is None:
            raise RuntimeError("a C++17 compiler is required")
        cls.temporary = tempfile.TemporaryDirectory(prefix="winsvpn-runargv-round9-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = (ROOT / "linux/runner/linux_tunnel_backend.cc").read_text()
        trim_start = source.index("std::string Trim(")
        trim_end = source.index("\n}\n", trim_start) + 3
        start = source.index("enum class ProcOutput {")
        end = source.index("// Runs a COMPILE-TIME-CONSTANT shell script body.", start)
        cls.production = source[trim_start:trim_end] + source[start:end]
        cls.compiler = compiler
        code = PREFIX + cls.production + HARNESS
        path = cls.directory / "runargv.cc"
        path.write_text(code, encoding="utf-8", newline="\n")
        cls.binary = cls.directory / "runargv"
        subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                        "-pthread", *shlex.split(os.environ.get("CXXFLAGS", "")),
                        str(path), "-o", str(cls.binary)], check=True, timeout=60)

    def exercise(self, kind, mode="capture", binary=None):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            journal = Path(directory) / "pids"
            try:
                subprocess.run([str(binary or self.binary), kind, mode, str(journal)],
                               check=True, timeout=22 if kind == "default" else 8)
            finally:
                # Only test-owned groups are eligible for emergency cleanup.
                # Normally every recorded PID has already been reaped.
                if journal.exists():
                    for line in journal.read_text().splitlines():
                        pid, group, _ = line.split()
                        try:
                            if os.getpgid(int(pid)) == int(group) != os.getpgrp():
                                os.killpg(int(group), 9)
                        except ProcessLookupError:
                            pass

    def test_normal_output_modes_and_exit_statuses(self):
        for kind in ("quiet", "exit", "signal", "capture", "failed-wait"):
            for mode in ("capture", "suppress", "inherit"):
                with self.subTest(kind=kind, mode=mode):
                    self.exercise(kind, mode)

    def test_capture_limit_and_eintr_preserve_output(self):
        for kind in ("cap", "overflow", "delayed"):
            with self.subTest(kind=kind):
                self.exercise(kind)

    def test_invalid_arguments_and_spawn_failure_do_not_leak(self):
        for mode in ("capture", "suppress", "inherit"):
            with self.subTest(mode=mode):
                self.exercise("invalid", mode)

    def test_quiet_hang_in_every_output_mode_and_closed_streams(self):
        for mode in ("capture", "suppress", "inherit"):
            with self.subTest(mode=mode):
                self.exercise("hang", mode)
        self.exercise("closed")

    def test_endless_writer_cannot_starve_deadline_after_overflow(self):
        self.exercise("endless")

    def test_term_resistant_child_with_eintr_and_caller_sigterm(self):
        self.exercise("resistant")

    def test_grandchildren_outlive_parent_or_close_pipe_or_write_forever(self):
        for kind in ("tree-held", "tree-resistant", "tree-closed", "tree-noisy"):
            with self.subTest(kind=kind):
                self.exercise(kind)

    def test_default_timeout_is_fifteen_seconds_plus_two_second_grace(self):
        self.exercise("default")

    def test_refused_signals_return_timeout_without_blocking_reap(self):
        # Inject only kill(2) permission errors around the unchanged production
        # extraction. The child, capture pipe, deadline and waits remain real.
        denied_kill = r'''
int RefuseKill(pid_t, int) { errno = EPERM; return -1; }
#define kill RefuseKill
'''
        main = r'''
int main(int argc, char** argv) {
  Require(argc == 4, "fixture arguments missing");
  if (std::string(argv[1]) == "fixture") {
    Record(argv[3], "child");
    for (;;) pause();
  }
  const int before_fds = OpenFdCount();
  const auto started = Clock::now();
  const auto result = RunArgv({argv[0], "fixture", "hang", argv[3]},
                              ProcOutput::kCapture, 50ms);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      Clock::now() - started).count();
  std::ifstream journal(argv[3]);
  pid_t pid = -1, group = -1;
  std::string role;
  journal >> pid >> group >> role;
  Require(pid > 1 && pid == group && group != getpgrp(), "fixture PID missing");
  int status = 0;
  const bool alive = waitpid(pid, &status, WNOHANG) == 0;
  // Real signal and reap are test cleanup, outside the injected production.
  Require(kill(-group, SIGKILL) == 0, "fixture cleanup signal failed");
  Require(waitpid(pid, &status, 0) == pid, "fixture cleanup reap failed");
  journal.close();
  Require(alive, "signal denial was not exercised");
  Require(result.exit_status == 124, "signal denial did not report timeout");
  Require(elapsed >= 2050 && elapsed < 3550, "signal denial blocked final reap");
  Require(OpenFdCount() == before_fds, "signal denial leaked descriptors");
  std::cout << "refused signals: exit=124 elapsed_ms=" << elapsed << "\n";
}
'''
        code = (PREFIX + denied_kill + self.production + "\n#undef kill\n" +
                HARNESS[:HARNESS.index("int main(")] + main)
        path = self.directory / "refused.cc"
        binary = self.directory / "refused"
        path.write_text(code, encoding="utf-8", newline="\n")
        subprocess.run([self.compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                        "-pthread", *shlex.split(os.environ.get("CXXFLAGS", "")),
                        str(path), "-o", str(binary)], check=True, timeout=60)
        self.exercise("denied", binary=binary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
