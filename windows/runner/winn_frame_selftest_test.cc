// Standalone Winn Protocol v3 framing self-test.
//
// WHY THIS FILE EXISTS. The framing contract in winn_frame.h is the wire layout
// every Winn v3 lane must agree on, and the byte-exact golden vector, the
// byte-at-a-time round trip and the rejection set live in
// winn_frame_selftest.h. That header is invoked from two places today: the
// validation self-test path inside windows_winn_engine.cpp (compiled into the
// shipping service) and tools/verify_winn_framing_conformance.sh (a development
// host-only script). Neither is a ctest test, so a framing regression is not
// caught by `ctest` on the Windows build machine.
//
// This is the third, ctest-shaped entry point: a standalone C++17 program with
// its own main, deliberately free of <windows.h> so it builds and runs both on
// the development host (via tools/verify_native_standalone_tests.sh) and on
// winpc under ctest (windows/runner/CMakeLists.txt), exactly like
// winn3_supervisor_test.cc and windows_winn_gate_test.cc.
//
//   c++ -std=c++17 -Wall -Wextra -Werror -o winn_frame_selftest_test \
//       windows/runner/winn_frame_selftest_test.cc && ./winn_frame_selftest_test

#include "winn_frame_selftest.h"

#include <cstdio>
#include <string>

int main() {
  std::string failure;
  if (!winsvpn::winn::RunWinnFrameSelfTest(&failure)) {
    std::fprintf(stderr, "winn_frame_selftest: %s\n", failure.c_str());
    return 1;
  }
  std::printf("winn_frame_selftest: all checks passed\n");
  return 0;
}
