cmake_minimum_required(VERSION 3.13)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME}
  "main.cc"
  "my_application.cc"
  "linux_secure_store.cc"
  "linux_secure_store_async.cc"
  "linux_tunnel_backend.cc"
  "linux_winn_host.cc"
  "linux_winn3_host.cc"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
)

# Minimal root-started helper that attaches a cgroup socket-mark BPF link and
# immediately drops to nobody while it holds that fail-safe link open.
add_executable(winsvpn-bypass-bpf
  "winsvpn_bypass_bpf.cc"
)

# The privileged real-kernel-TUN end-to-end driver. It links the SAME
# linux_winn3_host.cc that the shipped runner links -- not a reimplementation of
# the Winn v3 datapath -- and drives it through a real /dev/net/tun device, a
# real winn-datapath engine subprocess and a real winn3-gateway far end (see the
# driver's own header). It is deliberately a SEPARATE target from ${BINARY_NAME}
# because it needs net_admin + /dev/net/tun and must never end up in the shipped
# bundle: a 057-byte-tall privileged test binary sitting next to the app is a
# foot-gun. It shares the source of truth but rides inside the build tree only.
#
# It is registered with add_test so `ctest` can run it inside the isolated lab
# container (--cap-add=NET_ADMIN --device /dev/net/tun), where it genuinely
# carries packets and asserts zero loss + byte-exact returns. A build without the
# container will fail to open /dev/net/tun and the test reports that failure --
# it never lies by skipping.
# Built only when the lab harness arguments were supplied at configure time
# (same gate as the add_test below). A normal `flutter build linux` must not
# compile this privileged test driver: it needs net_admin + /dev/net/tun, must
# never ride in the shipped bundle, and its -Werror warnings would otherwise
# break every release build. The lab lane passes -DWINS_TUN_E2E_ARGS=... to
# include both the binary and its ctest registration.
if(DEFINED WINS_TUN_E2E_ARGS AND NOT WINS_TUN_E2E_ARGS STREQUAL "")
  add_executable(winsvpn-linux-winn3-tun-e2e
    "linux_winn3_host_tun_e2e.cc"
    "linux_winn3_host.cc"
  )
  target_compile_features(winsvpn-linux-winn3-tun-e2e PRIVATE cxx_std_17)
  target_link_libraries(winsvpn-linux-winn3-tun-e2e PRIVATE Threads::Threads)
endif()

# The Linux secure store exercised as its own ctest target (read / write /
# overwrite / delete / denied interactions). This is the one test in the
# standalone set that CANNOT run on a developer Mac -- it needs real glib/gio
# and libsecret -- so registering it here is what makes it run anywhere a real
# Secret Service exists. The default command covers the no-service, fail-closed
# and hardening paths (which need no keyring); --positive additionally exercises
# the Secret Service round-trips (write/read/overwrite/delete), which need a
# live keyring such as gnome-keyring on a session bus.
add_executable(linux_secure_store_test
  "linux_secure_store_test.cc"
  "linux_secure_store.cc"
  "linux_secure_store_async.cc"
)
target_compile_features(linux_secure_store_test PRIVATE cxx_std_17)
target_link_libraries(linux_secure_store_test PRIVATE PkgConfig::GTK PkgConfig::LIBSECRET)
# -Wall WITHOUT -Werror, matching tools/verify_native_standalone_tests.sh which
# deliberately avoids -Werror for these files: a warning must never take down the
# shipped Linux app build (or gate this target on one) for a reason unrelated to
# what the test checks.
target_compile_options(linux_secure_store_test PRIVATE -Wall)
# -UNDEBUG because this test is 95 assert() calls and NOTHING ELSE. CMake's
# default CMAKE_CXX_FLAGS_RELEASE is "-O3 -DNDEBUG", so in the Release config
# that `flutter build linux --release` uses, every one of those assertions
# compiles to nothing: the test passed in about a second having verified
# nothing at all, for the component that decides whether a user's credentials
# are written to disk in the clear. CMake emits <DEFINES> before <FLAGS>, so
# this -U undoes the -D. It also makes the 15 unused-variable warnings go away
# on their own, because those variables were only unused while the asserts
# that read them were being compiled away.
target_compile_options(linux_secure_store_test PRIVATE -UNDEBUG)
enable_testing()
add_test(
  NAME linux_secure_store_test
  COMMAND linux_secure_store_test
)
# The positive (Secret Service round-trip) test needs a LIVE keyring -- a
# gnome-keyring on a session bus -- which a plain builder container does not
# have. Registering it unconditionally makes `ctest` red in the default build
# even though the code under test is fine, so it is gated behind an explicit
# option that the keyring-bearing environment enables.
option(WINS_ENABLE_SECSTORE_POSITIVE "Register the linux_secure_store_test_positive Secret Service round-trip ctest (needs a live keyring)" OFF)
if(WINS_ENABLE_SECSTORE_POSITIVE)
  add_test(
    NAME linux_secure_store_test_positive
    COMMAND linux_secure_store_test --positive
  )
endif()

add_executable(winsvpn_bypass_bpf_test "winsvpn_bypass_bpf_test.cc")
target_compile_features(winsvpn_bypass_bpf_test PRIVATE cxx_std_17)
target_compile_options(winsvpn_bypass_bpf_test PRIVATE -Wall)
add_test(
  NAME winsvpn_bypass_bpf_test
  COMMAND winsvpn_bypass_bpf_test
)

# The Winn v3 host contract, registered as ctest targets so the Linux build
# runs them alongside the other standalone programs. Both are standard C++17
# with their own main and no glib/gio or <windows.h>, exactly as their headers
# document, so neither needs GTK or libsecret to build or run.
add_executable(linux_winn3_host_test
  "linux_winn3_host_test.cc"
  "linux_winn3_host.cc"
)
target_compile_features(linux_winn3_host_test PRIVATE cxx_std_17)
target_compile_options(linux_winn3_host_test PRIVATE -Wall)
target_link_libraries(linux_winn3_host_test PRIVATE Threads::Threads)
add_test(
  NAME linux_winn3_host_test
  COMMAND linux_winn3_host_test
)

add_executable(winn3_posture_test "winn3_posture_test.cc")
target_compile_features(winn3_posture_test PRIVATE cxx_std_17)
target_compile_options(winn3_posture_test PRIVATE -Wall)
add_test(
  NAME winn3_posture_test
  COMMAND winn3_posture_test
)

add_executable(linux_winn_gate_test "linux_winn_gate_test.cc")
target_compile_features(linux_winn_gate_test PRIVATE cxx_std_17)
target_compile_options(linux_winn_gate_test PRIVATE -Wall)
add_test(
  NAME linux_winn_gate_test
  COMMAND linux_winn_gate_test
)

add_executable(linux_winn_seam_pin_test "linux_winn_seam_pin_test.cc")
target_compile_features(linux_winn_seam_pin_test PRIVATE cxx_std_17)
target_compile_options(linux_winn_seam_pin_test PRIVATE -Wall)
target_link_libraries(linux_winn_seam_pin_test PRIVATE Threads::Threads)
add_test(
  NAME linux_winn_seam_pin_test
  COMMAND linux_winn_seam_pin_test
)

# The driver requires the isolated lab harness (engine, gateway, keys, a
# physical-interface arg). ctest passes the harness via WINS_TUN_E2E_ARGS so the
# same build tree drives the loopback TUN harness and the full lab unchanged.
# Without the harness a plain build cannot open /dev/net/tun and the driver
# reports a real failure -- which is correct behaviour for the binary but would
# make a default `ctest` red for infrastructure the build does not provide. So
# the e2e is only registered when the harness arguments were supplied at
# configure time; the lab lane passes -DWINS_TUN_E2E_ARGS=... to include it.
if(DEFINED WINS_TUN_E2E_ARGS AND NOT WINS_TUN_E2E_ARGS STREQUAL "")
  add_test(
    NAME winsvpn_linux_winn3_tun_e2e
    COMMAND winsvpn-linux-winn3-tun-e2e ${WINS_TUN_E2E_ARGS}
  )
endif()

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})
apply_standard_settings(winsvpn-bypass-bpf)
if(DEFINED WINS_TUN_E2E_ARGS AND NOT WINS_TUN_E2E_ARGS STREQUAL "")
  apply_standard_settings(winsvpn-linux-winn3-tun-e2e)
endif()
apply_standard_settings(winsvpn_bypass_bpf_test)

# The Winn host shares windows/runner/winn_frame.h, which is the normative
# reference implementation of the WNN3 frame layout and is standard C++17
# (nested namespace definition, no <windows.h>). apply_standard_settings asks
# for cxx_std_14, which is a FLOOR rather than a ceiling, so raising it here
# affects only this target.
#
# winn3_posture.h in THIS directory is the Linux-local copy of the Winn v3
# staged-posture policy, kept byte-identical (parity) with
# windows/runner/winn3_posture.h so the Linux host and the Windows supervisor
# expose the same fail-closed posture contract (the narrow bootstrap, the
# promotion gate, and the per-platform command renderers). It is header-only
# standard C++17 with no platform headers. linux_winn3_host.h includes it as
# "winn3_posture.h"; the drift guard for the two copies is that
# windows/runner/winn3_posture.h is shared through the tests, and any editing
# lane must re-sync the Linux copy rather than let them diverge.
#
# It IS COMPILED INTO THIS RUNNER, through linux_winn3_host.cc, which includes
# it and calls BuildBootstrapPosture, VerifyBootstrapIsNarrow,
# BuildPromotedPosture, ParseWinn3StatusLine and RenderLinuxPostureCommands.
# Until 2026-08-09 it had no caller on this platform at all: the header was
# exercised only by linux/runner/winn3_posture_test.cc, which is a standalone
# program outside this file, so nothing in the shipping binary referenced the
# policy that decides when a user's default route moves. A posture policy that
# the product does not link is a posture policy the product does not have.
#
# The tests are registered as ctest targets above -- linux_winn3_host_test and
# winn3_posture_test each have their own main and need no glib/gio, so they run
# in the plain Linux build with only Threads. They were standalone programs
# until 2026-08-11; the registration exists so `ctest` runs the host contract
# rather than leaving it to whoever remembers the header comment's build line.
#
# linux_winn3_host.cc is the STANDALONE v3 host and is deliberately a separate
# translation unit from linux_winn_host.cc, which is the shipping winn/1
# AmneziaWG relay. The two carry different payloads -- inner IP packets against
# AmneziaWG outer datagrams -- and merging them would give a future edit one
# place to make a v3 decision on a v1 session. The failure mode of that mistake
# is cleartext on the wire.
target_compile_features(${BINARY_NAME} PRIVATE cxx_std_17)

# The Winn seam runs two pump threads: one draining AmneziaWG's outer datagrams
# off the loopback socket into Inbound frames, one delivering Outbound frames
# back to it.
find_package(Threads REQUIRED)
target_link_libraries(${BINARY_NAME} PRIVATE Threads::Threads)

# Keep native DWARF only long enough for the release builder to extract private
# debug companions. Delivery binaries are stripped and linked back with an
# exact .gnu_debuglink/build-id pair by tools/build_linux_release.sh.
foreach(WINS_OWNED_TARGET ${BINARY_NAME} winsvpn-bypass-bpf)
  target_compile_options(${WINS_OWNED_TARGET} PRIVATE "$<$<CONFIG:Release>:-g>")
  target_link_options(${WINS_OWNED_TARGET} PRIVATE "$<$<CONFIG:Release>:-Wl,--build-id=sha1>")
endforeach()

# Add preprocessor definitions for the application ID.
add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

# Add dependency libraries. Add any application-specific dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::GTK)
target_link_libraries(${BINARY_NAME} PRIVATE PkgConfig::LIBSECRET)

target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")
