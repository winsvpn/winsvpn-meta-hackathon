// winsvpn_bypass_bpf_test.cc -- test for the Linux split-tunnel socket-mark BPF
// helper (winsvpn_bypass_bpf.cc).
//
// WHY THIS FILE EXISTS. The bypass helper's one job is to attach, to every
// socket created inside the split cgroup, the routing mark that steers that
// socket around the VPN's protected route. A mistake in the instruction stream
// is silent: the socket is either marked with the wrong value (split traffic
// collides with protected, or leaves the kill switch's jurisdiction) or not
// marked at all (the selected application is pinned to the protected route and
// the "bypass" silently does nothing). Both present to the user as "the split
// tunnel is broken" with no error anywhere. The kernel verifier rejects a
// malformed program with a bare errno -- indistinguishable, on the failing
// host, from "no privilege" -- so relying on the verifier alone does not police
// the route value, and a released binary that marks the wrong value is exactly
// the silent-refusal family this project spends its time fighting.
//
// Two claims, both asserted against the REAL implementation:
//   1. The program the helper would submit is loadable-shaped: exactly three
//      instructions; a 32-bit store of the mark into sk->mark at the kernel's
//      own offsetof; a return register set to 1 (accept); an exit.
//   2. Its route matches the split set: the mark the program stores equals the
//      routing mark it was asked for -- asserted for the split routing mark, for
//      a different mark (the route must CHANGE, closing the constant-marker
//      survivor), and for a 32-bit mark that must survive the cast bit-exactly.
//
// When the build host has privilege (root / CAP_BPF / CAP_SYS_ADMIN) the test
// also submits the real program to BPF_PROG_LOAD and demands a valid fd -- the
// strongest form of "the bypass program loads". Without privilege the load
// fails EPERM and is reported as a logged note, not a pass or a fail, so a
// normal unprivileged ctest run stays green without ever claiming the kernel
// accepted a program it did not. The load-path claim is only earned by an
// actual load, or it is never asserted.
//
// The helper is a standalone program with its own main, so this test does NOT
// link winsvpn_bypass_bpf.cc as a second translation unit (that would collide
// the two mains). Instead this file #includes the .cc with its main renamed,
// so the checks drive the real Instruction / BuildSocketMarkProgram /
// ParseUnsigned / LoadSocketMarkProgram and nothing here restates their logic.
//
// Linux-only: it needs <linux/bpf.h>, so it builds where the helper ships, not
// on a developer Mac. Build and run on any Linux host:
//
//   c++ -std=c++17 -Wall -Wextra -o winsvpn_bypass_bpf_test winsvpn_bypass_bpf_test.cc && ./winsvpn_bypass_bpf_test
//
// It is expected to be registered from linux/runner/CMakeLists.txt (owned by
// the Linux-link lane) as a standalone ctest target built from THIS ONE file:
//
//   add_executable(winsvpn_bypass_bpf_test "winsvpn_bypass_bpf_test.cc")
//   add_test(NAME winsvpn_bypass_bpf_test COMMAND winsvpn_bypass_bpf_test)

// The helper's own main is renamed (never called here) so this translation unit
// supplies the only main. Everything else in the anonymous namespace of the .cc
// -- Instruction, BuildSocketMarkProgram, ParseUnsigned, LoadSocketMarkProgram
// -- becomes reachable because the include lands in this same TU.
#define main winsvpn_bypass_bpf_private_main
#include "winsvpn_bypass_bpf.cc"
#undef main

#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* what) {
  if (!condition) {
    ++failures;
    std::fprintf(stderr, "FAIL: %s\n", what);
  }
}

// The routing mark the production wiring hands the helper is the AmneziaWG
// fwmark (linux_tunnel_backend.cc configure_split_rules passes `awg show
// fwmark` straight to --mark). The posture carrier uses fwmark 0x1f4 as its
// worked example; 0x1f4 == 500.
constexpr uint32_t kSplitRoutingMark = 0x1f4u;

void TestProgramIsWellFormed() {
  const std::vector<struct bpf_insn> program =
      BuildSocketMarkProgram(kSplitRoutingMark);
  Check(program.size() == 3, "the socket-mark program is exactly three instructions");
  if (program.size() != 3) return;

  Check(program[0].code ==
            static_cast<uint8_t>(BPF_ST | BPF_MEM | BPF_W),
        "instruction 0 is a 32-bit socket-field store");
  Check(program[0].dst_reg == BPF_REG_1, "instruction 0 stores into R1 (the sock)");
  Check(program[0].off == static_cast<int16_t>(offsetof(struct bpf_sock, mark)),
        "instruction 0 writes at the exact bpf_sock.mark offset");

  Check(program[1].code ==
            static_cast<uint8_t>(BPF_ALU64 | BPF_MOV | BPF_K),
        "instruction 1 loads a constant");
  Check(program[1].dst_reg == BPF_REG_0,
        "instruction 1 targets the return register");
  Check(program[1].imm == 1, "instruction 1 returns 1 (accept the socket)");

  Check(program[2].code == static_cast<uint8_t>(BPF_JMP | BPF_EXIT),
        "instruction 2 is the exit");
}

void TestRouteMatchesSplitRoutingMark() {
  const std::vector<struct bpf_insn> for_split =
      BuildSocketMarkProgram(kSplitRoutingMark);
  Check(for_split.size() == 3, "split-set program built");
  if (for_split.size() != 3) return;
  Check(for_split[0].imm == static_cast<int32_t>(kSplitRoutingMark),
        "the stored mark equals the split-set routing mark (0x1f4)");

  // The negative control: a different requested mark must land in the program.
  // If the builder were replaced by a mark-unaware constant, this catches it.
  const std::vector<struct bpf_insn> for_other =
      BuildSocketMarkProgram(999);
  Check(for_other.size() == 3 && for_other[0].imm == 999,
        "a distinct mark is wired through, not a constant");
  Check(for_other.size() == 3 &&
            for_other[0].imm != static_cast<int32_t>(kSplitRoutingMark),
        "the other program's mark differs from the split routing mark");

  // A large valid 32-bit mark must survive the int32 cast bit-exactly (the
  // kernel store writes the low 32 bits regardless of sign).
  const uint32_t big = 0xF0000001u;
  const std::vector<struct bpf_insn> for_big = BuildSocketMarkProgram(big);
  Check(for_big.size() == 3 &&
            static_cast<uint32_t>(for_big[0].imm) == big,
        "a 32-bit mark round-trips bit-exactly through the instruction");
}

void TestMarkParsing() {
  uint64_t value = 0;
  Check(ParseUnsigned("0x1f4", UINT32_MAX, &value) && value == 0x1f4u,
        "--mark 0x1f4 parses to 500");
  Check(ParseUnsigned("500", UINT32_MAX, &value) && value == 500u,
        "--mark 500 parses");

  Check(!ParseUnsigned("", UINT32_MAX, &value), "empty mark is rejected");
  Check(!ParseUnsigned("-1", UINT32_MAX, &value), "negative mark is rejected");
  Check(!ParseUnsigned("0", UINT32_MAX, &value),
        "zero mark is rejected (fail-closed guard)");
  Check(!ParseUnsigned("0x1f4x", UINT32_MAX, &value), "trailing junk is rejected");
  Check(!ParseUnsigned("99999999999999999999", UINT32_MAX, &value),
        "overflow is rejected");
  Check(!ParseUnsigned("0x1f4", 100, &value), "over-maximum is rejected");
}

void TestPrivilegedLoadIfAvailable() {
  std::string error;
  const int fd = LoadSocketMarkProgram(kSplitRoutingMark, &error);
  const int saved_errno = errno;
  if (fd >= 0) {
    ::close(fd);
    std::printf(
        "info: kernel accepted the socket-mark program (privileged load)\n");
    return;
  }
  if (saved_errno == EPERM || saved_errno == EACCES) {
    std::printf("info: unprivileged host (errno=%s); privileged kernel-load "
                "claim not exercised\n",
                std::strerror(saved_errno));
    return;
  }
  ++failures;
  std::fprintf(stderr,
               "FAIL: kernel refused the socket-mark program for a reason "
               "other than privilege (errno=%s): %s\n",
               std::strerror(saved_errno), error.c_str());
}

}  // namespace

int main() {
  TestProgramIsWellFormed();
  TestRouteMatchesSplitRoutingMark();
  TestMarkParsing();
  TestPrivilegedLoadIfAvailable();
  if (failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  std::printf("winsvpn_bypass_bpf_test: all checks passed\n");
  return 0;
}