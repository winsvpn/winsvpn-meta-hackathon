cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME} WIN32
  "flutter_window.cpp"
  "main.cpp"
  "utils.cpp"
  "windows_tunnel_backend.cpp"
  "windows_tunnel_service_client.cpp"
  "windows_split_tunnel.cpp"
  "windows_winn_engine.cpp"
  "win32_window.cpp"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  "Runner.rc"
  "runner.exe.manifest"
)

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})
# The shared tunnel backend intentionally contains privileged-service helpers
# that are compiled out of the UI call graph. Match the service target's
# target-scoped suppression so /W4 /WX does not turn C4505 dead-code notices
# into UI build failures.
target_compile_options(${BINARY_NAME} PRIVATE /wd4505)

# Add preprocessor definitions for the build version.
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

# Disable Windows macros that collide with C++ standard library functions.
target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")
target_link_options(${BINARY_NAME} PRIVATE "/MANIFESTUAC:level='asInvoker' uiAccess='false'")

# Add dependency libraries and include directories. Add any application-specific
# dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter flutter_wrapper_app)
target_link_libraries(${BINARY_NAME} PRIVATE "dwmapi.lib")
target_link_libraries(${BINARY_NAME} PRIVATE "shell32.lib")
target_link_libraries(${BINARY_NAME} PRIVATE "advapi32.lib" "crypt32.lib" "fwpuclnt.lib" "iphlpapi.lib" "powrprof.lib" "ws2_32.lib")
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")

# Run the Flutter tool portions of the build. This must not be removed.
add_dependencies(${BINARY_NAME} flutter_assemble)

# Keep privileged tunnel and signed split-driver operations outside the Flutter
# UI process. The installer registers this narrow LocalSystem service, while the
# ordinary desktop app communicates over an authenticated local named pipe.
#
# winn3_supervisor.cpp is the Winn Protocol v3 supervisor: it starts the v3 tun
# relay (windows/winn3_engine, which owns the "winsvpn3" Wintun adapter),
# starts cmd/winn-datapath against a `device.kind: loopback-udp` profile, tells
# each one the other's loopback port, installs the BOOTSTRAP posture that
# winn3_posture.h renders, and promotes routes only on the engine's own
# promotion_ready proof.
#
# It is in THIS target only, and deliberately not in ${BINARY_NAME}. Everything
# it does is privileged -- two child processes, a physical /32 route pin and
# netsh -- and its Windows half is compiled out entirely without
# WINS_TUNNEL_SERVICE_CORE, exactly as windows_winn_engine.cpp's is. The Flutter
# UI has no business holding any of it.
#
# It is a SEPARATE translation unit from windows_winn_engine.cpp, which is the
# shipping AmneziaWG-carried winn/1 path. The two speak different seam
# contracts -- winn/1 relays already-encrypted AWG outer datagrams, winn/3
# relays raw inner packets to the layer that encrypts them -- and merging them
# would make the difference a runtime branch rather than two files that cannot
# call each other's code.
add_executable(wins_vpn_tunnel_service
  "windows_tunnel_service_main.cpp"
  "windows_kill_switch.cpp"
  "windows_tunnel_backend.cpp"
  "windows_split_tunnel.cpp"
  "windows_winn_engine.cpp"
  "winn3_supervisor.cpp"
)
apply_standard_settings(wins_vpn_tunnel_service)
# winn3_supervisor.h and winn3_posture.h are header-only standard C++17 with
# nested namespace definitions, which cxx_std_14 does not accept.
# apply_standard_settings asks for cxx_std_14, which is a FLOOR rather than a
# ceiling, so raising it here affects only this target -- the same arrangement
# linux/runner/CMakeLists.txt already uses for winn_frame.h.
target_compile_features(wins_vpn_tunnel_service PRIVATE cxx_std_17)
target_compile_definitions(wins_vpn_tunnel_service PRIVATE
  "NOMINMAX"
  "WINS_TUNNEL_SERVICE_CORE=1"
  "$<$<CONFIG:Debug>:WINS_TUNNEL_SERVICE_ALLOW_UNSIGNED_DEV=1>"
)
target_compile_options(wins_vpn_tunnel_service PRIVATE /wd4505)
target_link_libraries(wins_vpn_tunnel_service PRIVATE
  "wintrust.lib"
  "advapi32.lib"
  "crypt32.lib"
  "fwpuclnt.lib"
  "iphlpapi.lib"
  "shell32.lib"
  "ws2_32.lib"
)

add_test(NAME windows_tunnel_service_protocol_self_test COMMAND wins_vpn_tunnel_service --protocol-self-test)

# The elevated-service client wire-contract test. It is a standalone C++17
# program with its own main. Its wire-format assertions build and RUN on the
# development host via tools/verify_native_standalone_tests.sh, while its
# Win32 pipe-squatting integration check is compiled on Windows only. It is
# registered here as a ctest test so the Windows build runs both portions
# through add_test/ctest. It is a
# SEPARATE test-only target and deliberately a source of neither shipped target
# (${BINARY_NAME} nor wins_vpn_tunnel_service), so it can never reach a shipped
# binary; it pins the pipe wire contract in windows_tunnel_service_protocol.h.
add_executable(winsvpn-tunnel-service-client-test
  "windows_tunnel_service_client_test.cc"
  "windows_tunnel_service_client.cpp"
)
apply_standard_settings(winsvpn-tunnel-service-client-test)
# enable_testing() is called at the project root in windows/CMakeLists.txt so
# `ctest` from the build root recurses into this directory's CTestTestfile.cmake.
add_test(
  NAME windows_tunnel_service_client_test
  COMMAND winsvpn-tunnel-service-client-test
)

# Route-promotion gate tests for the Windows Winn Protocol v1 host.
# Standalone C++17, free of <windows.h> so it builds and RUNS on the development
# host as well as on the target (same shape as the client test above).
add_executable(windows_winn_gate_test
  "windows_winn_gate_test.cc"
)
apply_standard_settings(windows_winn_gate_test)
target_compile_features(windows_winn_gate_test PRIVATE cxx_std_17)
add_test(
  NAME windows_winn_gate_test
  COMMAND windows_winn_gate_test
)

# Standalone Winn Protocol v3 supervisor tests (the decidable half).
# Same shape: standard C++17, no <windows.h>, builds and RUNS on the
# development host and on winpc. It pins the contract in
# winn3_supervisor.h / winn3_posture.h -- parsing, MTU, promotion, and the
# PromotedCommandDelta idempotency that keeps a repeat promotion from
# re-issuing "netsh ... add route <next-hop>" and failing "already exists".
add_executable(winn3_supervisor_test
  "winn3_supervisor_test.cc"
)
apply_standard_settings(winn3_supervisor_test)
target_compile_features(winn3_supervisor_test PRIVATE cxx_std_17)
add_test(
  NAME winn3_supervisor_test
  COMMAND winn3_supervisor_test
)

# Standalone Winn Protocol v3 framing self-test (winn_frame_selftest.h).
# Same shape: standard C++17, no <windows.h>, builds and RUNS on the
# development host and on winpc. It pins the byte-exact wire layout in
# winn_frame.h that every Winn v3 lane must agree on -- golden encoding, the
# byte-at-a-time round trip and the rejection set -- as an ordinary ctest test,
# so a framing regression is caught by `ctest` here rather than only by the
# shipping binary's self-test path and the dev-host conformance script.
add_executable(winn_frame_selftest_test
  "winn_frame_selftest_test.cc"
)
apply_standard_settings(winn_frame_selftest_test)
target_compile_features(winn_frame_selftest_test PRIVATE cxx_std_17)
add_test(
  NAME winn_frame_selftest_test
  COMMAND winn_frame_selftest_test
)

# Windows split-tunnel route-plan test. Unlike the sibling *_test.cc targets
# above (which are free of <windows.h> so they build and run on the POSIX
# host), this TU #includes the REAL windows_split_tunnel.cpp -- whose routing
# core lives in an anonymous namespace with internal linkage, so a separate TU
# cannot declare it extern and link it -- which drags in <windows.h> and the
# Windows SDK surface the planner uses. It therefore builds and RUNS only on
# the Windows target with the MSVC toolchain (winpc); it is deliberately NOT in
# tools/verify_native_standalone_tests.sh's windows/runner glob. It pins, against
# the real production planner:
#   1) that a split config produces explicit excluded (physical-bypass) ranges
#      (a dropped bypass would let the tunnel's own /0 -- enforceRoutes-style
#      full capture -- pull that range inside the tunnel), and
#   2) that no bypass prefix overlaps an allowed/tunnel network (an allowed
#      address must not leak out the physical NIC).
# Together those are the complete non-leak guarantee: the IPv4 address space is
# partitioned exactly once into {tunnel(allowed), physical(bypass)}. It compiles
# the same TU windows_split_tunnel.cpp #includes, so it also links
# windows_winn_engine.cpp for WindowsWinnCarrierHost and fwpuclnt for the Fwpm*
# surface the include brings in.
add_executable(winsvpn-split-routeplan-test
  "../test/windows_split_tunnel_routeplan_test.cc"
  "windows_winn_engine.cpp"
)
apply_standard_settings(winsvpn-split-routeplan-test)
target_compile_features(winsvpn-split-routeplan-test PRIVATE cxx_std_17)
target_include_directories(winsvpn-split-routeplan-test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(winsvpn-split-routeplan-test PRIVATE
  "ws2_32.lib"
  "advapi32.lib"
  "iphlpapi.lib"
  "fwpuclnt.lib"
  "user32.lib"
  "shell32.lib"
  "crypt32.lib"
)
add_test(
  NAME windows_split_tunnel_routeplan_test
  COMMAND winsvpn-split-routeplan-test
)

# Carrier-host resolution-order test. Same Windows-only shape as the route-plan
# test above: it #includes the real windows_split_tunnel.cpp (where
# WindowsCarrierHostForConfig lives in the anonymous-namespace routing core) and
# links windows_winn_engine.cpp for WindowsWinnCarrierHost, so it builds and runs
# only on winpc with the MSVC toolchain. It pins the outer-socket carrier order
# ([Xray] Host -> [winn] endpoint -> [Peer] Endpoint) that decides which address
# gets the owned /32 physical route pin.
add_executable(winsvpn-carrierhost-test
  "../test/windows_split_tunnel_carrierhost_test.cc"
  "windows_winn_engine.cpp"
)
apply_standard_settings(winsvpn-carrierhost-test)
target_compile_features(winsvpn-carrierhost-test PRIVATE cxx_std_17)
target_include_directories(winsvpn-carrierhost-test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(winsvpn-carrierhost-test PRIVATE
  "ws2_32.lib"
  "advapi32.lib"
  "iphlpapi.lib"
  "fwpuclnt.lib"
  "user32.lib"
  "shell32.lib"
  "crypt32.lib"
)
add_test(
  NAME windows_split_tunnel_carrierhost_test
  COMMAND winsvpn-carrierhost-test
)

add_executable(winsvpn-carrierpin-test
  "../test/windows_split_tunnel_carrier_pin_test.cc"
  "windows_winn_engine.cpp"
)
apply_standard_settings(winsvpn-carrierpin-test)
target_compile_features(winsvpn-carrierpin-test PRIVATE cxx_std_17)
target_include_directories(winsvpn-carrierpin-test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(winsvpn-carrierpin-test PRIVATE
  "ws2_32.lib"
  "advapi32.lib"
  "iphlpapi.lib"
  "fwpuclnt.lib"
  "user32.lib"
  "shell32.lib"
  "crypt32.lib"
)
add_test(
  NAME windows_split_tunnel_carrier_pin_test
  COMMAND winsvpn-carrierpin-test
)
