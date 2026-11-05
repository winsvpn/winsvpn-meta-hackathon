#!/usr/bin/env bash
#
# verify_winn3_conformance.sh — the winn/3 CROSS-HOST CONFORMANCE SUITE.
#
# ===========================================================================
# WHAT THIS IS FOR
# ===========================================================================
#
# On 2026-08-09 three defects were found in one evening and all three had the
# same shape: a client and a gateway disagreeing about an encoding or a size,
# producing NO SESSION AND NO ERROR ON EITHER SIDE.
#
#   1. gateway_id encoding — cdatapath base64-decoded a field four other call
#      sites took verbatim. `winsgw01` is eight characters of the base64
#      alphabet, so an ordinary operator name was enough to trigger it.
#   2. Android inner MTU — WinnV3EngineConfig emitted the dialled UDP/IPv4
#      number (1443) where the plan floor across udp+tcp+tls is 1359.
#   3. path_mtu is not negotiated at all — a 1280 gateway against a 1500 client
#      gives plan floors of 1232 and 1452. Still unfixed.
#
# A v3 gateway never answers an unauthenticated datagram, so under the Myanmar
# threat model every one of these is indistinguishable from a censor blocking
# the user. None of them can be found by looking at either end alone.
#
# This script feeds ONE operator configuration to every host in the tree and
# asserts they all derive byte-identical admission-tag inputs and identical plan
# floors. It fails loudly and names both values.
#
# ===========================================================================
# HOW IT IS PUT TOGETHER
# ===========================================================================
#
#   Go hosts      covered by adapters inside their own packages, so a
#                 divergence in cmd/winn3-gateway fails cmd/winn3-gateway's own
#                 test run. `go test` here drives all five.
#   Kotlin        the REAL android/app/src/main/kotlin sources, compiled with
#                 kotlinc against android.jar and run on a plain JVM. No Gradle
#                 daemon and no build lock, so a conformance run cannot collide
#                 with another lane's build.
#   Swift         the REAL apple/WinsTunnelCore sources, compiled with swiftc.
#   C++           NOT a deriving host: linux/runner and windows/runner READ
#                 inner_mtu out of the engine's status document rather than
#                 computing it. That is checked as a source-level property
#                 below, because "does not derive" is a claim that can rot.
#
# No harness compares anything. Each one runs its host's real derivation and
# prints JSON; `winn3-conformance -verify` does the comparing, once, in the same
# function the Go hosts are checked with. Three languages with three assertion
# implementations would be three chances to write a comparison that passes when
# it should not.
#
# ===========================================================================
# EXIT CODES
# ===========================================================================
#
#   0  every host that could be reached agreed
#   1  at least one host diverged — read the table
#   2  at least one host could not be reached (toolchain missing) and nothing
#      diverged. NEVER conflated with 0: a green pipeline that skipped a
#      platform looks exactly like one that covered it, and only one of them
#      means anything.
#
# Usage: tools/verify_winn3_conformance.sh [--strict]
#        tools/verify_winn3_conformance.sh --check-kotlin-toolchain
#   --strict  treat an unreachable host as a failure (exit 1). Use in CI on a
#             machine that is supposed to have every toolchain.
#   --check-kotlin-toolchain  resolve and print the exact reviewed Kotlin
#             compiler closure without running the host conformance suite.

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

STRICT=0
CHECK_KOTLIN_TOOLCHAIN=0
for arg in "$@"; do
  case "${arg}" in
    --strict) STRICT=1 ;;
    --check-kotlin-toolchain) CHECK_KOTLIN_TOOLCHAIN=1 ;;
    *) printf 'unknown argument: %s\n' "${arg}" >&2; exit 64 ;;
  esac
done

ENGINE_DIR="${PROJECT_ROOT}/winn_protocol_experimental"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-winn3-conformance.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

REPORTS=()
UNREACHED=()

say() { printf '%s\n' "$*"; }
section() { printf '\n=== %s ===\n' "$*"; }

# Resolve Kotlin from the reviewed repository pin, never from cache ordering.
# The exact support versions are the runtime closure declared by the reviewed
# kotlin-compiler-embeddable 2.4.20 POM plus the Android lockfile's annotation
# dependency. Updating the compiler pin requires reviewing this closure too.
GRADLE_CACHE="${GRADLE_CACHE:-${HOME}/.gradle/caches/modules-2/files-2.1}"
KOTLIN_PIN_FILE="${PROJECT_ROOT}/tools/toolchain-pins.json"
KOTLIN_REFLECT_VERSION="1.6.10"
KOTLIN_COROUTINES_VERSION="1.8.0"
KOTLIN_TROVE_VERSION="1.0.20200330"
KOTLIN_ANNOTATIONS_VERSION="13.0"
ANDROIDX_ANNOTATION_VERSION="1.8.1"

read_kotlin_pin() {
  python3 - "${KOTLIN_PIN_FILE}" <<'PY'
import json
import re
import sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle, object_pairs_hook=reject_duplicates)
    version = document["tools"]["kotlin"]["version"]
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
    print(f"invalid Kotlin pin manifest: {exc}", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    print("Kotlin pin must be an exact stable numeric version", file=sys.stderr)
    raise SystemExit(1)
print(version)
PY
}

find_exact_jar() {
  local group="$1" artifact="$2" version="$3"
  local root="${GRADLE_CACHE}/${group}/${artifact}/${version}"
  local matches=()
  shopt -s nullglob
  matches=("${root}"/*/"${artifact}-${version}.jar")
  shopt -u nullglob
  if [[ ${#matches[@]} -ne 1 ]]; then
    printf 'expected exactly one cached %s:%s:%s jar, found %d under %s\n' \
      "$group" "$artifact" "$version" "${#matches[@]}" "$root" >&2
    return 1
  fi
  if [[ ! -f "${matches[0]}" || -L "${matches[0]}" ]]; then
    printf 'cached Kotlin dependency is not a regular non-symlink file: %s\n' \
      "${matches[0]}" >&2
    return 1
  fi
  printf '%s\n' "${matches[0]}"
}

resolve_kotlin_toolchain() {
  KOTLIN_VERSION="$(read_kotlin_pin)" || return 1
  KOTLINC_JAR="$(find_exact_jar org.jetbrains.kotlin kotlin-compiler-embeddable "${KOTLIN_VERSION}")" || return 1
  STDLIB_JAR="$(find_exact_jar org.jetbrains.kotlin kotlin-stdlib "${KOTLIN_VERSION}")" || return 1
  REFLECT_JAR="$(find_exact_jar org.jetbrains.kotlin kotlin-reflect "${KOTLIN_REFLECT_VERSION}")" || return 1
  DAEMON_JAR="$(find_exact_jar org.jetbrains.kotlin kotlin-daemon-embeddable "${KOTLIN_VERSION}")" || return 1
  COROUTINES_JAR="$(find_exact_jar org.jetbrains.kotlinx kotlinx-coroutines-core-jvm "${KOTLIN_COROUTINES_VERSION}")" || return 1
  TROVE_JAR="$(find_exact_jar org.jetbrains.intellij.deps trove4j "${KOTLIN_TROVE_VERSION}")" || return 1
  ANNOT_JAR="$(find_exact_jar org.jetbrains annotations "${KOTLIN_ANNOTATIONS_VERSION}")" || return 1
  ANDROIDX_JAR="$(find_exact_jar androidx.annotation annotation-jvm "${ANDROIDX_ANNOTATION_VERSION}")" || return 1
}

if [[ ${CHECK_KOTLIN_TOOLCHAIN} -eq 1 ]]; then
  resolve_kotlin_toolchain || exit 2
  printf 'KOTLIN_TOOLCHAIN_OK version=%s compiler=%s\n' \
    "${KOTLIN_VERSION}" "${KOTLINC_JAR}"
  exit 0
fi

# --------------------------------------------------------------------------
# 0. the reference vectors and the task list
# --------------------------------------------------------------------------

section "reference vectors"
command -v go >/dev/null 2>&1 || { say "Go is required to compute the reference vectors."; exit 2; }

VECTORS="${WORK_DIR}/vectors.json"
TASKS="${WORK_DIR}/tasks.txt"
( cd "${ENGINE_DIR}" && go run ./cmd/winn3-conformance -emit "${VECTORS}" -emit-tasks "${TASKS}" )
say "operator configuration:"
grep -E '"gateway_id"|"path_mtu"|"carrier_classes"' "${VECTORS}" | head -5

# --------------------------------------------------------------------------
# 1. the Go hosts
# --------------------------------------------------------------------------
#
# -count=1 because Go's test cache serves stale greens in this module and a
# cached pass on a file another lane just edited is worse than no pass at all.

section "Go hosts (cdatapath, cmd/winn-datapath, cmd/winn3-gateway, cmd/winn3-labrig)"
GO_STATUS=0
( cd "${ENGINE_DIR}" && go test -count=1 \
    ./winn3/conform/ \
    ./cdatapath/ \
    ./cmd/winn-datapath/ \
    ./cmd/winn3-gateway/ \
    ./cmd/winn3-labrig/ \
    -run 'Conform|Conformance|Admission|GatewayID|PlanFloor|PathMTU|Divergence|Demux|EntryPoint|Neither|Labrig|Rigs|CABI|AGatewayBuilt|CreateSeamRefusesTheDialled|Reference|LowerClamp|Overheads|FailureMessage|MustMatch|TwoDefaults|VectorFile' \
    -v 2>&1 | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|ok|FAIL|PASS)' | grep -Ev '^=== RUN' | tail -40 ) || GO_STATUS=1
if [[ ${GO_STATUS} -ne 0 ]]; then
  say ""
  say "the Go conformance adapters FAILED — re-run for the full message:"
  say "  (cd ${ENGINE_DIR} && go test -count=1 ./winn3/conform/ ./cdatapath/ ./cmd/winn-datapath/ ./cmd/winn3-gateway/ ./cmd/winn3-labrig/ -run Conform)"
fi

# --------------------------------------------------------------------------
# 2. Kotlin
# --------------------------------------------------------------------------

section "Kotlin host (android/app/src/main/kotlin — WinnV3Sizing, WinnV3Keys)"
kotlin_report="${WORK_DIR}/kotlin-report.json"
kotlin_ok=0

SDK_DIR=""
if [[ -n "${ANDROID_HOME:-}" ]]; then
  SDK_DIR="${ANDROID_HOME}"
elif [[ -f android/local.properties ]]; then
  SDK_DIR="$(sed -n 's/^sdk\.dir=//p' android/local.properties | head -1)"
fi
ANDROID_JAR=""
if [[ -n "${SDK_DIR}" && -d "${SDK_DIR}/platforms" ]]; then
  # Newest platform present. android.jar is used for COMPILATION only; nothing
  # here calls an Android API at run time.
  ANDROID_JAR="$(ls -d "${SDK_DIR}"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
fi

KOTLIN_TOOLCHAIN_ERROR_FILE="${WORK_DIR}/kotlin-toolchain-error.log"
if ! resolve_kotlin_toolchain 2>"${KOTLIN_TOOLCHAIN_ERROR_FILE}"; then
  KOTLINC_JAR=""
  STDLIB_JAR=""
fi

if ! command -v java >/dev/null 2>&1; then
  UNREACHED+=("kotlin: no java on PATH")
elif [[ -z "${KOTLINC_JAR}" || -z "${STDLIB_JAR}" ]]; then
  cat "${KOTLIN_TOOLCHAIN_ERROR_FILE}"
  UNREACHED+=("kotlin: exact reviewed compiler closure unavailable")
elif [[ -z "${ANDROID_JAR}" ]]; then
  UNREACHED+=("kotlin: no android.jar (set ANDROID_HOME or android/local.properties sdk.dir)")
else
  COMPILER_CP="${KOTLINC_JAR}:${STDLIB_JAR}:${REFLECT_JAR}:${ANNOT_JAR}:${TROVE_JAR}:${DAEMON_JAR}:${COROUTINES_JAR}"
  COMPILE_CP="${STDLIB_JAR}:${ANNOT_JAR}:${ANDROIDX_JAR}:${ANDROID_JAR}"

  # GLOBBED, NOT LISTED, so a new source can never silently drop out of
  # coverage — the same rule tools/verify_apple_winn_seam.sh follows.
  #
  # Two filters, both mechanical rather than by name:
  #
  #   * AppleDouble `._*` files. This tree is full of them, they are not
  #     Kotlin, and kotlinc dies on them with a character-encoding error that
  #     reads like a source bug.
  #   * ANDROID ENTRY POINTS — a file that imports Flutter/Play Services/
  #     libwg-go/org.json, or that declares a class extending an Android
  #     framework component (Activity, BroadcastReceiver, Service,
  #     VpnService, FlutterActivity, WearableListenerService). Those are the UI
  #     and plugin surfaces; none of them derives a size or an admission input,
  #     and pulling their dependency closure in would make a conformance run
  #     depend on a Flutter build. A helper coupled directly to
  #     VpnTunnelService is part of that same entry-point closure and is also
  #     excluded; the two required derivation files are asserted below after
  #     filtering, so this cannot silently drop either conformance boundary.
  #
  # Both filters are STRUCTURAL — an import line and a superclass — not a
  # hand-written list of filenames. So a new UI file is skipped automatically
  # and a new DERIVATION file is picked up automatically, which is the
  # direction this mistake has to fail in: a filter that had to be edited to
  # cover a new file is a filter that silently stops covering things.
  KT_SOURCES=()
  while IFS= read -r f; do
    if grep -qE '^import (io\.flutter|com\.google|org\.json|org\.amnezia|androidx\.core)' "$f"; then
      continue
    fi
    if grep -qE 'class +[A-Za-z0-9_]+ *: *(Activity|BroadcastReceiver|Service|VpnService|FlutterActivity|WearableListenerService|LauncherEntryActivity)\(' "$f"; then
      continue
    fi
    if grep -qE '^[[:space:]]*[A-Za-z_].*VpnTunnelService\.' "$f"; then
      continue
    fi
    KT_SOURCES+=("$f")
  done < <(
    find android/app/src/main/kotlin/org/winsvpn/app -maxdepth 1 -name '*.kt' ! -name '._*' | sort
  )
  # The two files the suite exists to cover must be in the set, whatever the
  # filter did. A filter that silently dropped WinnV3Posture.kt would leave a
  # conformance run that compiles, runs, and proves nothing.
  for required in WinnV3Posture.kt WinnV3Keys.kt; do
    if ! printf '%s\n' "${KT_SOURCES[@]}" | grep -q "/${required}$"; then
      say "the Kotlin source filter dropped ${required}, which is the file under test."
      UNREACHED+=("kotlin: ${required} was filtered out")
      KT_SOURCES=()
      break
    fi
  done
  # BuildConfig is GENERATED by the Android Gradle plugin and is not a source
  # in this tree, so a gradle-free compile has to supply it. Regenerated here
  # from the two fields the sources actually read, discovered by grep rather
  # than assumed — a hand-written stub that fell behind would fail the compile
  # for a reason unrelated to conformance, which is the kind of noise that gets
  # a check switched off.
  BUILDCONFIG_FIELDS="$(grep -rhoE 'BuildConfig\.[A-Za-z_]+' "${KT_SOURCES[@]}" 2>/dev/null |
    sed 's/BuildConfig\.//' | sort -u)"
  {
    printf 'package org.winsvpn.app\n\n'
    printf '// GENERATED by tools/verify_winn3_conformance.sh, standing in for the Android\n'
    printf '// Gradle plugin. Fields discovered by grep over the sources being compiled.\n'
    printf 'internal object BuildConfig {\n'
    for field in ${BUILDCONFIG_FIELDS}; do
      case "${field}" in
        DEBUG) printf '    const val DEBUG = false\n' ;;
        *) printf '    const val %s = ""\n' "${field}" ;;
      esac
    done
    printf '}\n'
  } >"${WORK_DIR}/BuildConfig.kt"
  KT_SOURCES+=("${WORK_DIR}/BuildConfig.kt")

  say "compiling ${#KT_SOURCES[@]} real Kotlin sources + the harness with Kotlin ${KOTLIN_VERSION} against $(basename "$(dirname "${ANDROID_JAR}")")"

  if java -cp "${COMPILER_CP}" org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
        -nowarn -no-reflect -no-stdlib \
        -classpath "${COMPILE_CP}" \
        -d "${WORK_DIR}/kotlin-classes" \
        "${KT_SOURCES[@]}" tools/winn3_conformance_kotlin_harness.kt \
        >"${WORK_DIR}/kotlinc.log" 2>&1; then
    # android.jar is a compile-time stub and is deliberately not runnable on a
    # plain JVM. WinnV3Keys selects its java.nio path at SDK 37, but the JVM
    # verifier must still resolve the ErrnoException catch type on the unused
    # pre-O android.system path before it can load the real production class.
    # Provide only those runtime types, without replacing any product Kotlin
    # class or any derivation that this conformance suite exists to exercise.
    mkdir -p "${WORK_DIR}/android-runtime-stub/android/os" \
      "${WORK_DIR}/android-runtime-stub/android/system"
    cat >"${WORK_DIR}/android-runtime-stub/android/os/Build.java" <<'JAVA'
package android.os;
public final class Build {
  private Build() {}
  public static final class VERSION {
    private VERSION() {}
    // WinnV3Keys reserves zero for its plain-JVM conformance/test host. This
    // selects the real java.nio implementation instead of pretending a JVM
    // process can execute Android's libcore Os descriptor operations.
    public static final int SDK_INT = 0;
  }
  public static final class VERSION_CODES {
    private VERSION_CODES() {}
    public static final int O = 26;
  }
}
JAVA
    cat >"${WORK_DIR}/android-runtime-stub/android/system/ErrnoException.java" <<'JAVA'
package android.system;
public class ErrnoException extends Exception {
  public final int errno;
  public ErrnoException(String functionName, int errno) {
    super(functionName + ": errno=" + errno);
    this.errno = errno;
  }
}
JAVA
    if ! command -v javac >/dev/null 2>&1 || \
       ! javac -d "${WORK_DIR}/kotlin-classes" \
           "${WORK_DIR}/android-runtime-stub/android/os/Build.java" \
           "${WORK_DIR}/android-runtime-stub/android/system/ErrnoException.java"; then
      say "the Kotlin harness Android runtime constant shim FAILED to compile"
      UNREACHED+=("kotlin: Android runtime shim compile failed")
    elif java -cp "${WORK_DIR}/kotlin-classes:${STDLIB_JAR}:${ANNOT_JAR}:${ANDROIDX_JAR}" \
          org.winsvpn.app.Winn3_conformance_kotlin_harnessKt "${TASKS}" "${WORK_DIR}" \
          >"${kotlin_report}" 2>"${WORK_DIR}/kotlin-run.log"; then
      REPORTS+=("${kotlin_report}")
      kotlin_ok=1
      say "kotlin harness reported $(wc -c <"${kotlin_report}" | tr -d ' ') bytes"
    else
      say "the Kotlin harness FAILED to run:"
      tail -20 "${WORK_DIR}/kotlin-run.log"
      UNREACHED+=("kotlin: harness run failed")
    fi
  else
    say "kotlinc FAILED:"
    grep -E 'error:' "${WORK_DIR}/kotlinc.log" | head -15
    UNREACHED+=("kotlin: compile failed")
  fi
fi
[[ ${kotlin_ok} -eq 1 ]] || say "kotlin: NOT COVERED on this run"

# --------------------------------------------------------------------------
# 3. Swift
# --------------------------------------------------------------------------

section "Swift host (apple/WinsTunnelCore — the descriptor boundary)"
swift_report="${WORK_DIR}/swift-report.json"
swift_ok=0

if [[ "$(uname -s)" != "Darwin" ]]; then
  UNREACHED+=("swift: not macOS")
elif ! command -v xcrun >/dev/null 2>&1; then
  UNREACHED+=("swift: no xcrun (full Xcode command line tools are required)")
else
  SWIFTC_BIN="$(xcrun -f swiftc)"
  SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
  TARGET="arm64-apple-macos13.0"
  SWIFT_MODULE_CACHE="${WORK_DIR}/swift-module-cache"
  mkdir -p "${SWIFT_MODULE_CACHE}"

  SWIFT_SOURCES=()
  while IFS= read -r f; do SWIFT_SOURCES+=("$f"); done < <(
    find apple/WinsTunnelCore -maxdepth 1 -name '*.swift' ! -name '._*' | sort
  )
  say "compiling ${#SWIFT_SOURCES[@]} real Swift sources + the harness"

  # Copied in as `main.swift`. Swift permits top-level statements only in a file
  # with that name, and the harness is top-level on purpose: the alternative is
  # an @main type whose lifecycle would sit between the reader and the two
  # derivations this file exists to show.
  cp tools/winn3_conformance_swift_harness.swift "${WORK_DIR}/main.swift"

  # No Go archive is linked. The winn/3 C ABI is reached by dlsym in
  # WinsWinn3Datapath, so nothing here needs it — and not linking it keeps this
  # run fast and independent of a cgo build. The archive-linked contract harness
  # is tools/verify_apple_winn3_host_contract.sh and covers the create refusals;
  # this one covers the derivation.
  if "${SWIFTC_BIN}" -sdk "${SDK_PATH}" -target "${TARGET}" \
        -module-cache-path "${SWIFT_MODULE_CACHE}" \
        "${SWIFT_SOURCES[@]}" "${WORK_DIR}/main.swift" \
        -framework Foundation -framework NetworkExtension -framework Security \
        -lresolv \
        -o "${WORK_DIR}/winn3_conformance_swift" \
        >"${WORK_DIR}/swiftc.log" 2>&1; then
    if "${WORK_DIR}/winn3_conformance_swift" "${TASKS}" \
          >"${swift_report}" 2>"${WORK_DIR}/swift-run.log"; then
      REPORTS+=("${swift_report}")
      swift_ok=1
      say "swift harness reported $(wc -c <"${swift_report}" | tr -d ' ') bytes"
    else
      say "the Swift harness FAILED to run:"
      tail -20 "${WORK_DIR}/swift-run.log"
      UNREACHED+=("swift: harness run failed")
    fi
  else
    say "swiftc FAILED:"
    grep -E 'error:' "${WORK_DIR}/swiftc.log" | head -15
    UNREACHED+=("swift: compile failed")
  fi
fi
[[ ${swift_ok} -eq 1 ]] || say "swift: NOT COVERED on this run"

# --------------------------------------------------------------------------
# 4. the C++ hosts, which must NOT derive
# --------------------------------------------------------------------------
#
# linux/runner and windows/runner read inner_mtu and message_size out of the
# engine's status document rather than computing them. That is the correct
# design — one implementation of the arithmetic, in Go — and it is the reason
# they need no conformance harness.
#
# But "does not derive" is a claim that rots. A future edit that added a local
# MTU computation to a C++ host would reintroduce defect 2 on the two platforms
# with no test to catch it, so the claim is checked here rather than trusted.

section "C++ hosts (must CONSUME the engine's numbers, never derive them)"
cxx_status=0
cxx_without_comments() {
  awk '
    BEGIN { in_block = 0 }
    {
      line = $0
      output = ""
      while (length(line) > 0) {
        if (in_block) {
          block_end = index(line, "*/")
          if (!block_end) { line = ""; break }
          line = substr(line, block_end + 2)
          in_block = 0
          continue
        }
        block_start = index(line, "/*")
        line_comment = index(line, "//")
        if (line_comment && (!block_start || line_comment < block_start)) {
          output = output substr(line, 1, line_comment - 1)
          line = ""
          break
        }
        if (block_start) {
          output = output substr(line, 1, block_start - 1)
          line = substr(line, block_start + 2)
          in_block = 1
          continue
        }
        output = output line
        line = ""
      }
      print output
    }
  ' "$1"
}
for f in linux/runner/linux_winn_host.cc linux/runner/linux_winn_host.h \
         windows/runner/winn3_posture.h windows/runner/windows_winn_engine.cpp; do
  [[ -f "$f" ]] || continue
  # The header constants are the arithmetic's raw material. A C++ host that
  # names one of them is a C++ host doing MTU arithmetic locally.
  if cxx_without_comments "$f" | grep -nE '\b(1443|1359|1423|1203|1139|1388|1168)\b' >/dev/null 2>&1; then
    say "DERIVES?  $f names a plan-floor constant:"
    cxx_without_comments "$f" | grep -nE '\b(1443|1359|1423|1203|1139|1388|1168)\b' | head -5
    cxx_status=1
  fi
  if cxx_without_comments "$f" | grep -nE 'path_mtu[^"]*-[^"]*(28|48|70|90|92|112)\b' >/dev/null 2>&1; then
    say "DERIVES?  $f subtracts a carrier overhead from a path MTU:"
    cxx_without_comments "$f" | grep -nE 'path_mtu[^"]*-[^"]*(28|48|70|90|92|112)\b' | head -5
    cxx_status=1
  fi
done
if [[ ${cxx_status} -eq 0 ]]; then
  say "linux/runner and windows/runner still CONSUME inner_mtu from the status document."
  say "They derive no plan floor, so there is nothing for them to diverge on — which is"
  say "why they are the two hosts that cannot have defect 2."
fi

# --------------------------------------------------------------------------
# 5. the comparison
# --------------------------------------------------------------------------

section "cross-host comparison"
VERIFY_STATUS=0
if [[ ${#REPORTS[@]} -gt 0 ]]; then
  joined="$(IFS=,; printf '%s' "${REPORTS[*]}")"
  ( cd "${ENGINE_DIR}" && go run ./cmd/winn3-conformance -vectors "${VECTORS}" -verify "${joined}" ) \
    || VERIFY_STATUS=$?
else
  say "no non-Go host reported; nothing to compare."
  VERIFY_STATUS=2
fi

# --------------------------------------------------------------------------
# 6. the verdict
# --------------------------------------------------------------------------

section "verdict"
if [[ ${#UNREACHED[@]} -gt 0 ]]; then
  say "NOT COVERED on this run:"
  for u in "${UNREACHED[@]}"; do say "  - ${u}"; done
  say ""
  say "A host that was not reached was not checked. This is reported separately from"
  say "a pass because a green pipeline that skipped a platform looks exactly like one"
  say "that covered it, and only one of them means anything."
fi

if [[ ${GO_STATUS} -ne 0 || ${VERIFY_STATUS} -eq 1 || ${cxx_status} -ne 0 ]]; then
  say ""
  say "FAIL: at least one host diverges. Every divergence here produces no session and"
  say "no error on either side, which under this threat model reads as censorship."
  exit 1
fi
if [[ ${#UNREACHED[@]} -gt 0 || ${VERIFY_STATUS} -eq 2 ]]; then
  if [[ ${STRICT} -eq 1 ]]; then
    say ""
    say "FAIL (--strict): a host could not be reached."
    exit 1
  fi
  say ""
  say "UNPROVEN: nothing diverged, but not every host was reached."
  exit 2
fi
say ""
say "PASS: every host reached derives byte-identical admission-tag inputs and"
say "identical plan floors from the same operator configuration."
exit 0
