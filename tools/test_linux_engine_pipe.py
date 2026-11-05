#!/usr/bin/env python3
"""Compile the actual engine-pipe writers and exercise hostile pipe states.

Runs on POSIX hosts. This does not replace packaged Linux device acceptance.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

WRITERS

void Require(bool value, const char* message) {
  if (!value) {
    std::cerr << message << std::endl;
    std::exit(1);
  }
}

void Interrupt(int) {}

void Exercise(bool (*writer)(int, const uint8_t*, size_t)) {
  uint8_t byte = 42;
  Require(!writer(-1, &byte, 1), "invalid descriptor accepted");
  int fd[2];
  Require(pipe(fd) == 0, "pipe creation failed");
  Require(!writer(fd[1], nullptr, 1), "null input accepted");
  Require(writer(fd[1], nullptr, 0), "empty write refused");
  std::vector<uint8_t> expected(2 * 1024 * 1024);
  for (size_t i = 0; i < expected.size(); ++i) expected[i] = i % 251;
  std::vector<uint8_t> received;
  std::thread reader([&] {
    uint8_t data[4096];
    ssize_t count;
    while ((count = read(fd[0], data, sizeof(data))) > 0) {
      received.insert(received.end(), data, data + count);
    }
  });
  Require(writer(fd[1], expected.data(), expected.size()), "partial write failed");
  close(fd[1]);
  reader.join();
  close(fd[0]);
  Require(received == expected, "partial writes changed or lost payload");

  Require(pipe(fd) == 0, "closed-reader pipe creation failed");
  close(fd[0]);
  Require(!writer(fd[1], &byte, 1), "closed reader accepted");
  close(fd[1]);

  for (bool interrupted : {false, true}) {
    Require(pipe(fd) == 0, "saturation pipe creation failed");
    Require(fcntl(fd[1], F_SETFL, O_NONBLOCK) == 0, "nonblock failed");
    uint8_t fill[4096] = {};
    while (write(fd[1], fill, sizeof(fill)) > 0) {}
    Require(errno == EAGAIN || errno == EWOULDBLOCK, "pipe not full");
    itimerval timer{};
    if (interrupted) {
      struct sigaction action{};
      action.sa_handler = Interrupt;
      sigemptyset(&action.sa_mask);
      Require(sigaction(SIGALRM, &action, nullptr) == 0, "sigaction failed");
      timer.it_value.tv_usec = 5000;
      timer.it_interval.tv_usec = 5000;
      Require(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "timer failed");
    }
    const auto start = std::chrono::steady_clock::now();
    Require(!writer(fd[1], &byte, 1), "full pipe accepted");
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    timer = {};
    Require(setitimer(ITIMER_REAL, &timer, nullptr) == 0, "timer stop failed");
    Require(elapsed >= 4800 && elapsed < 7000, "write deadline violated");
    close(fd[0]);
    close(fd[1]);
    std::cout << "saturated pipe, interrupted=" << interrupted
              << ", elapsed_ms=" << elapsed << std::endl;
  }
}

int main() {
  IGNORE_SIGPIPE
  Exercise(relay::WriteEnginePipeAll);
  Exercise(standalone::WriteEnginePipeAll);
  std::cout << "both production pipe writers passed" << std::endl;
}
'''


class LinuxEnginePipeTests(unittest.TestCase):
    def test_real_writers_handle_backpressure_eintr_and_closed_readers(self):
        compiler = shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(compiler, "a C++ compiler is required")
        writers = []
        for name, namespace in (("linux_winn_host.cc", "relay"),
                                ("linux_winn3_host.cc", "standalone")):
            source = (ROOT / "linux/runner" / name).read_text()
            start = source.index("constexpr int kEnginePipeWriteTimeoutMilliseconds =")
            end = source.index("\n}\n", start) + 3
            writers.append(f"namespace {namespace} {{\n{source[start:end]}\n}}")
            self.assertNotIn("WriteAll(state->stdin_fd", source)
            self.assertEqual(source.count("WriteEnginePipeAll(state->stdin_fd"), 2)
        main = (ROOT / "linux/runner/main.cc").read_text()
        ignore = "std::signal(SIGPIPE, SIG_IGN);"
        self.assertIn(ignore, main)
        code = HARNESS.replace("WRITERS", "\n".join(writers)).replace("IGNORE_SIGPIPE", ignore)
        with tempfile.TemporaryDirectory(prefix="winsvpn-pipe-test-") as temporary:
            source = pathlib.Path(temporary) / "pipe.cc"
            binary = pathlib.Path(temporary) / "pipe"
            source.write_text(code)
            subprocess.run([compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                            "-pthread", str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=35)


if __name__ == "__main__":
    unittest.main()
