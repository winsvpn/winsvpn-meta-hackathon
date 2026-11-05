#!/usr/bin/env bash
# Cross-compiles the REAL wins_vpn_tunnel_service CMake target (the LocalSystem
# tunnel-manager service, including the Winn Protocol v3 integration in
# windows_winn_engine.cpp) for windows/amd64 AND windows/arm64, from a macOS or
# Linux host, using clang-cl + lld-link against a genuine, unmodified copy of
# Microsoft's Windows SDK + MSVC CRT (fetched by `xwin` -- see
# tools/README_WINDOWS_ELEVATED_VERIFY.md for how that toolchain was verified).
#
# WHAT THIS IS FOR: staging genuine, PE32+, correctly-import-tabled arm64
# service binaries ahead of an eventual arm64 Windows bring-up, so that work
# does not also have to start the C++ side from zero. See
# installer/windows/build_installer.ps1's Build-Arm64WinnComponentsBestEffort,
# which calls this script the same optional, never-fails-the-release way
# Build-WinnDatapathEngine already treats the Winn Go engine.
#
# WHAT THIS IS NOT: a way to produce a shippable Windows installer of any
# architecture. The Flutter UI target (${BINARY_NAME}, i.e. wins_vpn.exe) is
# NOT built by this script -- it needs Flutter's own prebuilt Windows engine
# embedding (flutter.lib / flutter_wrapper_app.lib / generated_plugin_registrant.cc),
# which this repository does not vendor and which Flutter itself will not
# cross-build for windows-arm64 from any host
# (packages/flutter_tools/lib/src/commands/build_windows.dart:63-70 in the
# Flutter SDK: BuildWindowsCommand hard-refuses non-Windows hosts, and selects
# windows-arm64 only when the CURRENT host already reports
# HostPlatform.windows_arm64 -- there is no --target-platform flag on this
# command, unlike `flutter build apk`). Only wins_vpn_tunnel_service.exe (the
# native Win32 service binary) is in scope here.
#
# This target was deliberately chosen because it needs none of the above: per
# windows/runner/CMakeLists.txt:57-76 it is four plain C++ files
# (windows_tunnel_service_main.cpp, windows_tunnel_backend.cpp,
# windows_split_tunnel.cpp, windows_winn_engine.cpp) linked only against
# standard Win32 import libraries (advapi32/crypt32/fwpuclnt/iphlpapi/
# shell32/ws2_32) -- windows_tunnel_backend.cpp's Flutter method-channel code
# is compiled out entirely under -DWINS_TUNNEL_SERVICE_CORE=1, the same define
# CMake already passes for this exact target.
#
# An explicit producer invocation is fail closed. Missing clang-cl, lld-link,
# xwin SDK/CRT, or `file` architecture inspection is a build failure, never a
# successful skip. Optional callers may choose not to invoke this producer.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_dir="${repo_root}/windows/runner"
output_dir="${1:-${repo_root}/build/windows-arm64-staging/tunnel-service}"
if [[ "${output_dir}" != /* ]]; then
  output_dir="$(pwd -P)/${output_dir}"
fi

# Toolchain discovery. All three are configurable via environment variables so
# a future CI runner that installs them to different paths does not need this
# script edited -- same escape hatch tools/build_apple_engine_wrappers.sh and
# tools/build_windows_winn_engine.sh already give their own toolchains.
clang_cl="${WINS_CLANG_CL:-/Users/owner/.homebrew/Homebrew/opt/llvm/bin/clang-cl}"
lld_link="${WINS_LLD_LINK:-/Users/owner/.homebrew/Homebrew/opt/lld/bin/lld-link}"
# WINS_XWIN_SDK_DIR and the repo-root cache override the machine-global one.
# The repo ships its own fetch of Win11 SDK 10.0.26100 + MSVC CRT 14.44 at
# <repo-root>/.xwin-cache (the "repo-root cache"); prior to 2026-08-11 this
# script only ever looked at ${HOME}/.xwin-sdk, so a checkout that carried the
# cache still silently rebuilt from the machine-global copy (or skipped when
# that copy was absent). Prefer the env override, then the shipped cache
# (recognised by this script's own layout probe), then the machine-global copy.
xwin_dir="${WINS_XWIN_SDK_DIR:-}"
if [[ -z "${xwin_dir}" ]]; then
  repo_xwin="${repo_root}/../../.xwin-cache"
  if [[ -d "${repo_xwin}/crt/include" && -d "${repo_xwin}/sdk/include/um" ]]; then
    xwin_dir="${repo_xwin}"
  else
    xwin_dir="${HOME}/.xwin-sdk"
  fi
fi

# winn3_supervisor.cpp is the fifth translation unit, added when the Winn
# Protocol v3 supervisor landed. It is the party that starts the v3 tun relay
# and cmd/winn-datapath, installs the bootstrap posture winn3_posture.h renders,
# and promotes routes only on the engine's promotion_ready proof. It needs no
# new import library: it uses iphlpapi (GetBestRoute2/CreateIpForwardEntry2 for
# the outer-socket /32 pin) and advapi32 (the profile's DACL), both already
# linked below.
sources=(windows_tunnel_service_main.cpp windows_tunnel_backend.cpp windows_split_tunnel.cpp windows_winn_engine.cpp winn3_supervisor.cpp)

# Real windows/CMakeLists.txt (cxx_std_17, /W4 /WX /wd4100, /EHsc,
# -D_HAS_EXCEPTIONS=0, -DUNICODE -D_UNICODE) plus the wins_vpn_tunnel_service
# target's own additions (windows/runner/CMakeLists.txt:57-76): -DNOMINMAX
# -DWINS_TUNNEL_SERVICE_CORE=1, /wd4505.
common_defines=(-DUNICODE -D_UNICODE -DNOMINMAX -DWINS_TUNNEL_SERVICE_CORE=1 -D_HAS_EXCEPTIONS=0)
# /wd4505 suppresses MSVC's C4505 ("unreferenced local function removed"),
# which is how real cl.exe flags the WINS_TUNNEL_SERVICE_CORE-guarded UI-only
# static helpers inside windows_tunnel_backend.cpp / windows_split_tunnel.cpp
# (see windows/runner/CMakeLists.txt:26-29's own comment on exactly this).
# clang-cl's /W4 additionally enables its own, differently-numbered
# -Wunused-function / -Wunused-const-variable diagnostics for the identical
# dead-code pattern; /wd4505 does not silence those, because they are not the
# same diagnostic ID in clang's system -- found by a real build failure, not
# assumed. The two -Wno- flags below reproduce the SAME suppression intent as
# the real /wd4505, spelled for clang-cl instead of cl.exe.
common_warn=(/W4 /WX /wd4100 /wd4505 -Wno-unused-function -Wno-unused-const-variable)

log() { printf '[WINN-ARM64-SERVICE] %s\n' "$*"; }

if [[ ! -f "${src_dir}/windows_tunnel_service_main.cpp" ]]; then
  log "Source tree is missing ${src_dir}/windows_tunnel_service_main.cpp -- nothing to build."
  exit 1
fi
if [[ ! -x "${clang_cl}" ]]; then
  log "FAILED: clang-cl not found at ${clang_cl} (set WINS_CLANG_CL to override)."
  exit 1
fi
if [[ ! -x "${lld_link}" ]]; then
  log "FAILED: lld-link not found at ${lld_link} (set WINS_LLD_LINK to override)."
  exit 1
fi
if [[ ! -d "${xwin_dir}/crt/include" || ! -d "${xwin_dir}/sdk/include/um" ]]; then
  log "FAILED: no xwin-fetched Windows SDK/CRT found at ${xwin_dir} (set WINS_XWIN_SDK_DIR to override)."
  exit 1
fi
if ! command -v file >/dev/null 2>&1; then
  log "FAILED: the file architecture inspector is required to validate produced PE machine types."
  exit 1
fi

mkdir -p "${output_dir}"

triple_for() {
  case "$1" in
    amd64) echo "x86_64-pc-windows-msvc" ;;
    arm64) echo "aarch64-pc-windows-msvc" ;;
  esac
}
libdir_for() {
  case "$1" in
    amd64) echo "x86_64" ;;
    arm64) echo "aarch64" ;;
  esac
}
machine_for() {
  case "$1" in
    amd64) echo "X64" ;;
    arm64) echo "ARM64" ;;
  esac
}
file_machine_for() {
  case "$1" in
    amd64) echo "x86-64" ;;
    arm64) echo "Aarch64" ;;
  esac
}

overall_ok=1

for arch in amd64 arm64; do
  triple="$(triple_for "${arch}")"
  libdir="$(libdir_for "${arch}")"
  machine="$(machine_for "${arch}")"
  expect_machine="$(file_machine_for "${arch}")"
  arch_out="${output_dir}/${arch}"
  mkdir -p "${arch_out}"

  log "Compiling wins_vpn_tunnel_service for windows/${arch} (${triple})"
  compile_ok=1
  objs=()
  for src in "${sources[@]}"; do
    base="${src%.cpp}"
    obj="${arch_out}/${base}.obj"
    if ! ( cd "${src_dir}" && "${clang_cl}" --target="${triple}" -fms-compatibility-version=19.44 \
        -imsvc"${xwin_dir}/crt/include" \
        -imsvc"${xwin_dir}/sdk/include/ucrt" \
        -imsvc"${xwin_dir}/sdk/include/um" \
        -imsvc"${xwin_dir}/sdk/include/shared" \
        -I"${src_dir}" \
        /std:c++17 "${common_warn[@]}" /EHsc "${common_defines[@]}" \
        /c "${src}" /Fo:"${obj}" ) \
      > "${arch_out}/${base}.compile.log" 2>&1; then
      log "COMPILE FAILED: windows/${arch} ${src} (see ${arch_out}/${base}.compile.log)"
      tail -n 40 "${arch_out}/${base}.compile.log" | sed 's/^/  /'
      compile_ok=0
      overall_ok=0
    else
      objs+=("${obj}")
    fi
  done

  if [[ ${compile_ok} -ne 1 ]]; then
    log "Skipping link for windows/${arch}: not every translation unit compiled."
    continue
  fi

  exe="${arch_out}/wins_vpn_tunnel_service.exe"
  log "Linking windows/${arch} -> ${exe}"
  if ! "${lld_link}" \
    "/LIBPATH:${xwin_dir}/crt/lib/${libdir}" \
    "/LIBPATH:${xwin_dir}/sdk/lib/um/${libdir}" \
    "/LIBPATH:${xwin_dir}/sdk/lib/ucrt/${libdir}" \
    "/MACHINE:${machine}" \
    /SUBSYSTEM:CONSOLE /NOLOGO \
    "${objs[@]}" \
    advapi32.lib crypt32.lib fwpuclnt.lib iphlpapi.lib shell32.lib ws2_32.lib \
    "/OUT:${exe}" \
    > "${arch_out}/link.log" 2>&1; then
    log "LINK FAILED: windows/${arch} (see ${arch_out}/link.log)"
    tail -n 60 "${arch_out}/link.log" | sed 's/^/  /'
    overall_ok=0
    continue
  fi

  description="$(file -b "${exe}")"
  if [[ "${description}" != *"PE32+"* ]] || [[ "${description}" != *"${expect_machine}"* ]]; then
    log "PRODUCED THE WRONG MACHINE TYPE for windows/${arch}: ${description}"
    overall_ok=0
    continue
  fi
  log "OK windows/${arch}: ${description}"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${exe}" | sed 's/^/  /'
  fi
done

if [[ ${overall_ok} -eq 1 ]]; then
  log "wins_vpn_tunnel_service.exe cross-compiled and linked for windows/amd64 and windows/arm64."
  log "COMPILED AND LINKED, NOT EXECUTED: no Windows hardware of either architecture ran either binary. No privileged runtime behavior (route pinning, service install, AWG interop) was exercised."
  exit 0
fi
log "One or more architectures failed. See the logs above."
exit 1
