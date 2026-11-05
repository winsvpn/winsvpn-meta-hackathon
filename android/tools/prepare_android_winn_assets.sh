#!/usr/bin/env bash
set -Eeuo pipefail

# Stage the Winn Protocol engine into each shipping Android variant's
# android/app/src/<variant>/jniLibs/<abi>/ directory.
#
# This is the exact shape of tools/prepare_android_xray_assets.sh -- it
# delegates the cross-compile to a build script and drops the result under a
# lib*.so name so the package installer extracts it into nativeLibraryDir,
# where VpnTunnelService execs it as a subprocess. It is a second consumer of
# an existing pattern, not a second native-library strategy.
#
# Verified facts this relies on (checked, not assumed):
#   - android/app/src/main/jniLibs/arm64-v8a/libxray.so is an "ELF 64-bit LSB
#     pie executable, ARM aarch64", i.e. the shipping precedent is already a
#     plain Go executable carried under a lib*.so name.
#   - The built manifest carries extractNativeLibs="true" (from
#     packaging.jniLibs.useLegacyPackaging = true in app/build.gradle.kts), so
#     jniLibs entries land in nativeLibraryDir as real files that can be exec'd.
#   - packaging.jniLibs.excludes lists only armeabi-v7a, x86, libam-quick.so
#     and libam.so, and ndk.abiFilters is arm64-v8a + x86_64. libwinnengine.so
#     therefore needs ZERO Gradle change to be packaged.
#
# ---------------------------------------------------------------------------
# FRESHNESS / ABI GATE, and WHAT THE STAGING MODES DO.
#
# Both staging modes take the Winn engine from a Winn release directory
# (tools/winn_release.py, contract winsvpn-winn-release-manifest-v1): two
# independent builds per target that must be byte-identical, a manifest of every
# output's sha256, and for a signed release an Ed25519 signature by the owner's
# release authority key. The engine is ./cmd/winn-datapath, built by the driver
# for targets datapath-android-{arm64,arm,amd64}.
#
# --stage-release DIR  (release): runs ONE verification,
#     /usr/bin/python3 -I tools/winn_release.py verify --release DIR --print-manifest
#   which must exit 0 (signature against the pinned authority key AND every
#   artifact sha256) and prints the exact manifest bytes it verified. Every
#   expected digest comes from those held bytes; manifest.json is never read
#   again. Each ABI's engine is copied, bound to the held manifest, gated, and
#   installed as libwinnengine.so into every shipping variant, and a
#   winn-release.json stamp is written to android/app/src/<variant>/. The
#   stamp carries the signed manifest bytes and their Ed25519 signature, so the
#   release gates (Gradle verifyAndroidReleaseEngineInputs and --release-check,
#   through `winn_release.py verify-android-stamp`) re-verify the signature
#   under the pinned authority key and re-hash the staged bytes against the
#   signed entry. No network, no rebuild; libxray.so is left untouched.
#
# --stage  (debug/dev): builds the Winn engines through the driver
#   (winn_release.py build --set android --out <mktemp>/winn-release
#   --source-commit <git HEAD>), then stages from that UNSIGNED release exactly
#   like --stage-release but verifying with --allow-unsigned. It also rebuilds
#   and re-stages libxray.so (tools/build_xray_engine.sh, android-*) as before,
#   so a winn engine build can never ride an old transport. It writes NO stamp
#   and removes any existing one, so a dev-staged engine can never satisfy the
#   release gate.
#
# Every file is gated for ABI (arm64-v8a=183 / armeabi-v7a=40 / x86_64=62
# e_machine) and 16 KB page alignment before it is installed, and the winn
# datapath additionally carries the freshness + v3 content gates below.
#
# The default mode is --check: it only verifies prerequisites and gates whatever
# is already staged, writing nothing. --verify is the same gate without the
# "would run" listing (the release producers run it). --release-check gates the
# standalone v3 engines and also requires a valid winn-release.json stamp for
# the source set a release build packages. Run
#
#     bash android/tools/prepare_android_winn_assets.sh --stage-release /ABS/release
#
# to stage a signed release, or --stage for a local dev build. --stage needs the
# pinned toolchains (the driver exits 3 with TOOLCHAIN-MISSING when one is
# absent) and network for build_xray_engine.sh. Both validate then install only
# files this run produced. After staging, regenerate the freeze with
# tools/release_dependency_freeze.py.
# ---------------------------------------------------------------------------

usage() {
  echo "Usage: $0 [--check|--release-check|--verify|--stage|--stage-release RELEASE_DIR]" >&2
  exit 2
}

MODE="check"
RELEASE_DIR_ARG=""
max_args=1
case "${1:-}" in
  ""|--check) MODE="check" ;;
  --release-check) MODE="release-check" ;;
  --stage) MODE="stage" ;;
  --stage-release)
    MODE="stage-release"
    RELEASE_DIR_ARG="${2:-}"
    [[ -n "${RELEASE_DIR_ARG}" ]] || usage
    max_args=2
    ;;
  --verify) MODE="verify" ;;
  *) usage ;;
esac
[[ "$#" -le "${max_args}" ]] || usage

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${HERE}/../.." && pwd)"
BUILD_ENGINE="${PROJECT_ROOT}/tools/build_winn_protocol_engine.sh"
# The release driver. Every Winn engine this script installs comes out of a
# release directory it produced and verified.
RELEASE_DRIVER_REL="tools/winn_release.py"
RELEASE_DRIVER="${PROJECT_ROOT}/${RELEASE_DRIVER_REL}"
RELEASE_PYTHON="/usr/bin/python3"
# The NDK the whole Android build pins (android/app/build.gradle.kts ndkVersion,
# tools/build_xray_engine.sh, android/tools/build_winn_tun_bulk.sh). NDK r30 was
# approved by the owner; one value, used everywhere below.
ANDROID_NDK_PIN="30.0.16248370"
# The stamp --stage-release writes next to each variant's jniLibs, and the
# release gates (Gradle verifyAndroidReleaseEngineInputs and --release-check)
# require for the source set a release build packages.
RELEASE_STAMP_NAME="winn-release.json"
RELEASE_STAMP_CONTRACT="winsvpn-winn-release-android-stage-v1"
JNI_ROOT="${PROJECT_ROOT}/android/app/src"
SHIP_VARIANTS=(main debug profile release)
ENGINE_NAME="libwinnengine.so"
# The second native engine this staging pass owns. libwinnengine.so is the
# Winn Protocol v3 datapath; libxray.so is the Xray transport the host rides it
# through (the same libxray.so prepare_android_xray_assets.sh builds for
# src/main/jniLibs). Every winn engine build must re-stage BOTH so the shipping
# variant cannot carry a fresh winn engine bolted onto a transport binary from
# an older build. Built by tools/build_xray_engine.sh (network + pinned Go).
XRAY_ENGINE_NAME="libxray.so"
XRAY_BUILD_ENGINE="${PROJECT_ROOT}/tools/build_xray_engine.sh"

# ---------------------------------------------------------------------------
# THE FRESHNESS GATE (added 2026-08-09)
# ---------------------------------------------------------------------------
#
# This exists because the failure it prevents has already shipped. Android
# carried six libwinnengine.so files dated Aug 8 00:44 containing ZERO winn3
# symbols while the source tree had v3, and nothing anywhere objected. The same
# week Apple was found shipping a dylib older than all 122 of its live winn3
# sources, past a build gate that validated seventeen symbols and happened not
# to list the one v3 entry point.
#
# The cause here was mechanical and is fixed alongside the gate: this script
# used to build target `android-arm64`, which is ./cmd/winn-clientinfo, and that
# package links NO winn3 code at all -- `go list -deps ./cmd/winn-clientinfo`
# returns zero winnprotocol/winn3 packages, against five for the datapath
# engine. So --stage could not have produced a v3-carrying engine no matter how
# fresh the tree was. The artifact that actually carries packets, and the one
# staged under this name today, is ./cmd/winn-datapath.
#
# Two independent checks, because either alone is defeatable:
#
#   FRESHNESS -- the staged .so must be at least as new as every Go file in its
#   own dependency closure, taken from `go list -deps` for the real GOOS/GOARCH
#   rather than from a hand-kept list that drifts.
#
#   CONTENT -- the image must contain the winn3 package paths. A name check is
#   worthless: an artifact with a plausible filename that no build step produced
#   is precisely the hazard (the Windows lane found `winsvpnwinn3engine.exe`
#   sitting next to the real `winsvpn_winn3_engine.exe`, pure litter from a bare
#   `go build` naming its output after the module path). Content is what cannot
#   be faked by a filename.
#
# And staging never validates a file it did not just write: the build goes to a
# mktemp -d, the gate runs on that fresh output, and only then is it installed.

# -P resolves symlinks, so MODULE_DIR is the same string `go list` prints for
# .Dir. Without it a checkout reached through a symlink enumerates sources whose
# paths never match the prefix filter, the list comes back empty, and an empty
# list is indistinguishable from "nothing is newer" unless you fail closed on it,
# which gate_engine does, but matching properly is better than refusing
# properly.
MODULE_DIR="$(cd "${PROJECT_ROOT}/winn_protocol_experimental" 2>/dev/null && pwd -P || echo "${PROJECT_ROOT}/winn_protocol_experimental")"
ENGINE_PKG="./cmd/winn-datapath"

# The five winn3 packages cmd/winn-datapath links. ALL must be present: a
# partial set means the engine was built against a tree where v3 was half wired
# in, which is the state that produced a "winn3 is there" claim from a grep for
# the string "winn3" alone.
V3_REQUIRED_SYMBOLS=(
  "winsvpn.local/winnprotocol/winn3/core"
  "winsvpn.local/winnprotocol/winn3/session"
  "winsvpn.local/winnprotocol/winn3/carrier"
  "winsvpn.local/winnprotocol/winn3/tun"
  "winsvpn.local/winnprotocol/winn3/driver"
)

fail=0
note() { printf '  %s\n' "$*"; }
bad() { printf '  MISSING: %s\n' "$*"; fail=1; }
gate_fail() { printf 'REFUSED: %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# ABI VERIFICATION (added 2026-08-10, engine_stage)
# ---------------------------------------------------------------------------
# A staging pass can re-stage the right bytes into the wrong ABI's directory
# and Gradle never notices: jniLibs/<abi>/ is picked by the abiFilters and
# packaging, not by what the file actually is, so an arm64 image dropped into
# x86_64/ installs for exactly the device class it cannot run on (and vice
# versa). The useLegacyPackaging path extracts these to nativeLibraryDir as
# real exec files, so a wrong-architecture engine is not merely dead at load --
# it is exec'd and SIGSEGVs. AGP strips debug symbols on the way into the APK
# but does not rewrite the ELF e_machine, so this is one of the few properties
# that survives packaging intact (same reasoning as the v3 symbol gate).
#
# elf_machine reads e_machine (2 bytes, little endian, offset 18) straight out
# of the ELF header, independent of `file` or host uname.
elf_machine() {
  local so="$1"
  od -An -tu2 -j18 -N2 "${so}" 2>/dev/null | tr -d ' '
}

# verify_abi refuses a staged file whose ELF machine does not match the goarch
# its jniLibs directory claims. goarch -> e_machine: arm64 = 183 (AArch64),
# arm = 40 (EM_ARM / armeabi-v7a), amd64 = 62 (x86_64).
verify_abi() {
  local so="$1" goarch="$2" label="$3" want got
  case "${goarch}" in
    arm64) want=183 ;;
    arm) want=40 ;;
    amd64) want=62 ;;
    *) gate_fail "${label}: unknown goarch ${goarch} for ABI check."; return 1 ;;
  esac
  got="$(elf_machine "${so}")"
  if [[ -z "${got}" ]]; then
    gate_fail "${label}: ${so} has no readable ELF machine field -- it is not an ELF file at all."
    return 1
  fi
  if [[ "${got}" != "${want}" ]]; then
    gate_fail "${label}: ${so} is ELF e_machine ${got}, expected ${want} (${goarch}). The ${abi_name:-${goarch}} slot is staging the wrong architecture; that build would install for a device class it cannot run on."
    return 1
  fi
  return 0
}

# verify_page_alignment refuses a 64-bit staged executable whose PT_LOAD
# segments are not 16 KB aligned (required on 16 KB page devices, Android 15+).
verify_page_alignment() {
  local so="$1" goarch="$2" label="$3"
  case "${goarch}" in arm64|amd64) ;; *) return 0 ;; esac
  if ! /usr/bin/python3 - "${so}" <<'PY'
import struct
import sys

try:
    data = open(sys.argv[1], "rb").read()
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("invalid ELF header")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phnum == 0:
        raise ValueError("invalid program headers")
    if phoff + phentsize * phnum > len(data):
        raise ValueError("truncated program headers")
    loads = 0
    for index in range(phnum):
        kind, flags, offset, vaddr, paddr, filesz, memsz, align = \
            struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        if kind != 1:
            continue
        loads += 1
        if filesz > memsz or offset + filesz > len(data):
            raise ValueError("invalid load segment")
        if align < 16384 or align & (align - 1):
            raise ValueError("invalid load alignment")
        if (vaddr - offset) % 16384:
            raise ValueError("incongruent load segment")
    if loads == 0:
        raise ValueError("no load segments")
except (OSError, ValueError, struct.error):
    sys.exit(1)
PY
  then
    gate_fail "${label}: ${so} failed ELF page-alignment validation."
    return 1
  fi
}

goarch_for_abi() {
  case "${1:?goarch_for_abi: missing ABI}" in
    arm64-v8a) printf 'arm64\n' ;;
    armeabi-v7a) printf 'arm\n' ;;
    x86_64) printf 'amd64\n' ;;
    *) gate_fail "unknown Android ABI $1"; return 1 ;;
  esac
}


# engine_sources lists every in-module Go file the engine is built from, for one
# GOARCH. Empty output is itself a failure and is treated as one by the caller:
# a source list that cannot be computed must never read as "nothing is newer".
# CGO_ENABLED=1 is required, not incidental: `GOOS=android GOARCH=amd64` refuses
# outright with "requires external (cgo) linking, but cgo is not enabled" and
# then lists nothing. Enumerating zero sources would silently mean "nothing is
# newer than the artifact", i.e. a stale binary passing the gate for the exact
# arch the emulator uses -- so the caller treats an empty list as a REFUSAL, and
# this sets the variable that makes the list correct instead.
engine_sources() {
  local goarch="$1"
  ( cd "${MODULE_DIR}" && CGO_ENABLED=1 GOOS=android GOARCH="${goarch}" go list -deps \
      -f '{{$d:=.Dir}}{{range .GoFiles}}{{$d}}/{{.}}
{{end}}{{$e:=.Dir}}{{range .CgoFiles}}{{$e}}/{{.}}
{{end}}' "${ENGINE_PKG}" 2>/dev/null ) | grep "^${MODULE_DIR}/" || true
}

# Owner ruling 2026-10-27: the engines in the website APK are garbled, which
# hashes every package path, so the v3 names above cannot appear in their
# bytes. Such an engine passes CONTENT only through its signed binding: the
# signed manifest entry for these exact bytes must name ./cmd/winn-datapath,
# the datapath role and garble, and record v3_packages_linked, which the
# builder sets only after `go list -deps` in the sealed build source showed all
# five winn3 packages. The same check over this checkout is kept as well. A plain engine never
# takes this path. GATE_VERIFIED_MANIFEST names manifest bytes that
# `winn_release.py verify` already authenticated (signed --stage-release only).
GATE_VERIFIED_MANIFEST=""

obfuscated_v3_binding() {
  local so="$1" goarch="$2" manifest_kind manifest_path deps sym set_dir
  # The verified manifest also covers the pending destination copies the
  # install step re-gates (.libwinnengine.so.pending.*): each still binds by
  # its own digest below.
  if [[ -n "${GATE_VERIFIED_MANIFEST}" && ( "${so}" == "${STAGE_DIR}/"* \
        || "${so}" == "${JNI_ROOT}/"*"/jniLibs/"*"/.${ENGINE_NAME}.pending."* ) ]]; then
    manifest_kind=manifest
    manifest_path="${GATE_VERIFIED_MANIFEST}"
  elif [[ "${so}" == "${JNI_ROOT}/"*"/jniLibs/"*"/${ENGINE_NAME}" ]]; then
    set_dir="${so%/jniLibs/*}"
    manifest_kind=stamp
    manifest_path="${set_dir}/${RELEASE_STAMP_NAME}"
    [[ -f "${manifest_path}" && ! -L "${manifest_path}" ]] || return 1
    "${RELEASE_PYTHON}" -I -B "${RELEASE_DRIVER}" verify-android-stamp \
      --stamp "${manifest_path}" --artifact "${so}" --target "datapath-android-${goarch}" >/dev/null || return 1
  else
    return 1
  fi
  "${RELEASE_PYTHON}" -I - "${manifest_kind}" "${manifest_path}" "${so}" "datapath-android-${goarch}" <<'PY' || return 1
import base64
import hashlib
import json
import os
import sys

kind, path, engine, target = sys.argv[1:]
with open(path, "rb") as handle:
    document = json.load(handle)
if kind == "stamp":
    document = json.loads(base64.b64decode(document["manifest_b64"]))
rows = [row for row in document.get("artifacts", []) if row.get("target") == target]
if len(rows) != 1:
    raise SystemExit(1)
row = rows[0]
with open(engine, "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
obfuscation = row.get("obfuscation") or {}
if (row.get("sha256") != digest or row.get("size") != os.path.getsize(engine)
        or row.get("package") != "./cmd/winn-datapath" or row.get("role") != "datapath"
        or obfuscation.get("tool") != "mvdan.cc/garble"
        or document.get("obfuscation") != obfuscation
        or row.get("v3_packages_linked") is not True):
    raise SystemExit(1)
PY
  deps="$(cd "${MODULE_DIR}" && CGO_ENABLED=1 GOOS=android GOARCH="${goarch}" go list -deps "${ENGINE_PKG}" 2>/dev/null)" || return 1
  for sym in "${V3_REQUIRED_SYMBOLS[@]}"; do
    grep -qx -F "${sym}" <<<"${deps}" || return 1
  done
  return 0
}

# gate_engine is the whole check for one staged file. It NAMES what is stale
# rather than reporting a bare boolean, because "something is out of date" sends
# the reader back to do the diff by hand.
gate_engine() {
  local so="$1" goarch="$2" label="$3"
  local ok=0

  if [[ ! -f "${so}" ]]; then
    gate_fail "${label}: ${so} does not exist."
    return 1
  fi
  if [[ ! -s "${so}" ]]; then
    gate_fail "${label}: ${so} is empty."
    return 1
  fi

  if ! verify_abi "${so}" "${goarch}" "${label}"; then
    ok=1
  fi
  if ! verify_page_alignment "${so}" "${goarch}" "${label}"; then
    ok=1
  fi

  # --- content -------------------------------------------------------------
  local missing=()
  local sym
  for sym in "${V3_REQUIRED_SYMBOLS[@]}"; do
    if ! LC_ALL=C grep -a -q -F "${sym}" "${so}"; then
      missing+=("${sym}")
    fi
  done
  if [[ "${#missing[@]}" -eq "${#V3_REQUIRED_SYMBOLS[@]}" ]] && obfuscated_v3_binding "${so}" "${goarch}"; then
    note "${label}: garbled engine; v3 content proven by its signed manifest entry and go list -deps"
    missing=()
  fi
  if [[ "${#missing[@]}" -ne 0 ]]; then
    gate_fail "${label}: ${so} contains NO v3 code for ${#missing[@]} of ${#V3_REQUIRED_SYMBOLS[@]} required packages:"
    for sym in "${missing[@]}"; do printf '    absent: %s\n' "${sym}" >&2; done
    printf '  This is the Aug 8 failure exactly: an engine staged under a v3 name with no v3\n' >&2
    printf '  inside it. Restage datapath-android-%s with: bash %s --stage-release <signed release dir>\n' \
      "${goarch}" "${HERE}/prepare_android_winn_assets.sh" >&2
    ok=1
  fi

  # --- freshness -----------------------------------------------------------
  local srcs newer=() f count=0
  srcs="$(engine_sources "${goarch}")"
  if [[ -z "${srcs}" ]]; then
    gate_fail "${label}: could not enumerate the engine's Go sources (go list failed for android/${goarch}). Refusing to call an unverifiable artifact fresh."
    return 1
  fi
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    count=$((count + 1))
    if [[ "${f}" -nt "${so}" ]]; then
      newer+=("${f}")
    fi
  done <<< "${srcs}"

  if [[ "${#newer[@]}" -ne 0 ]]; then
    gate_fail "${label}: ${so} is STALE -- ${#newer[@]} of ${count} Go sources it is built from are newer than it."
    printf '  staged engine mtime: %s\n' "$(date -r "${so}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown)" >&2
    printf '  newer sources (first 10 of %d):\n' "${#newer[@]}" >&2
    for f in "${newer[@]:0:10}"; do
      printf '    %s  %s\n' "$(date -r "${f}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown)" "${f#"${PROJECT_ROOT}"/}" >&2
    done
    ok=1
  fi

  if [[ "${ok}" -eq 0 ]]; then
    note "GATE OK: ${label} (${count} sources checked, all ${#V3_REQUIRED_SYMBOLS[@]} v3 packages present)"
  fi
  return "${ok}"
}

# gate_xray validates a staged libxray.so transport binary: it must exist, be
# non-empty, and carry the ABI its jniLibs directory claims. Xray carries no
# winn3 packages (it is the transport, not the protocol), so the v3 symbol gate
# does not -- and must not -- apply to it; the meaningful checks are presence
# and the correct architecture, which is exactly the thing that has no other
# guard.
gate_xray() {
  local so="$1" goarch="$2" label="$3"
  if [[ ! -f "${so}" ]]; then
    gate_fail "${label}: ${so} does not exist."
    return 1
  fi
  if [[ ! -s "${so}" ]]; then
    gate_fail "${label}: ${so} is empty."
    return 1
  fi
  verify_abi "${so}" "${goarch}" "${label}" || return 1
  verify_page_alignment "${so}" "${goarch}" "${label}" || return 1
  note "GATE OK: ${label}"
  return 0
}

# gate_all_staged runs the gate over every staged engine in every source set.
# main/ is not the only one that ships: the engines actually packaged today live
# in src/debug, src/profile and src/release, and a gate that only looked where
# this script writes would have missed all six of the stale ones. Both native
# engines (winn datapath, xray transport) are gated, each with its own gate.
gate_all_staged() {
  local include_legacy_transport="${1:-1}"
  local rc=0 found=0 set_name abi so name goarch names
  names=("${ENGINE_NAME}")
  [[ "${include_legacy_transport}" == "1" ]] && names+=("${XRAY_ENGINE_NAME}")
  for set_name in main debug profile release; do
    for abi in arm64-v8a armeabi-v7a x86_64; do
      goarch="$(goarch_for_abi "${abi}")" || return 1
      for name in "${names[@]}"; do
        so="${PROJECT_ROOT}/android/app/src/${set_name}/jniLibs/${abi}/${name}"
        if [[ ! -f "${so}" ]]; then
          if [[ "${include_legacy_transport}" == "0" && "${set_name}" != "main" ]]; then
            gate_fail "src/${set_name} ${abi} ${name}: required standalone-v3 staged engine is missing."
            rc=1
          fi
          continue
        fi
        found=$((found + 1))
        if [[ "${name}" == "${ENGINE_NAME}" ]]; then
          gate_engine "${so}" "${goarch}" "src/${set_name} ${abi} ${name}" || rc=1
        else
          gate_xray "${so}" "${goarch}" "src/${set_name} ${abi} ${name}" || rc=1
        fi
      done
    done
  done
  if [[ "${found}" -eq 0 ]]; then
    note "no ${ENGINE_NAME} or ${XRAY_ENGINE_NAME} is staged in any source set; nothing to gate"
  fi
  return "${rc}"
}

# target_for_abi names the release driver target that carries an ABI's engine.
target_for_abi() {
  local goarch
  goarch="$(goarch_for_abi "$1")" || return 1
  printf 'datapath-android-%s\n' "${goarch}"
}

# bind_release_manifest is the byte binding between a release and the engines
# this run copied out of it. It runs on the exact manifest bytes the driver
# verified and printed (never on a second read of manifest.json), against the
# private copies the gates ran on. For every ABI it requires exactly one
# manifest entry for datapath-android-<goarch> at artifacts/<target>/<engine>,
# build_a == build_b == sha256 (the two independent builds agreed), and the
# copy's sha256 and size equal to that entry. In signed mode it also requires
# the signature record to name this exact manifest, and writes the
# winn-release.json stamp carrying the manifest bytes and the signature, which
# the caller then authenticates with `winn_release.py verify-android-stamp`.
bind_release_manifest() {
  "${RELEASE_PYTHON}" -I - "$@" <<'PY'
import base64
import hashlib
import json
import os
import re
import sys

mode, manifest_path, sig_path, stage_dir, engine_name, stamp_path, contract = sys.argv[1:8]
ABIS = (("arm64-v8a", "arm64"), ("armeabi-v7a", "arm"), ("x86_64", "amd64"))
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def fail(message):
    print("REFUSED: " + message, file=sys.stderr)
    sys.exit(1)


def digest(path):
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load(path, label):
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        value = json.loads(raw)
    except ValueError:
        fail(label + " is not valid JSON.")
    if not isinstance(value, dict):
        fail(label + " is not a JSON object.")
    return raw, value


manifest_raw, manifest = load(manifest_path, "manifest.json")
manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
if manifest.get("contract") != "winsvpn-winn-release-manifest-v1":
    fail("manifest.json does not carry contract winsvpn-winn-release-manifest-v1.")
artifacts = manifest.get("artifacts")
if not isinstance(artifacts, list):
    fail("manifest.json has no artifacts list.")

engines = {}
for abi, goarch in ABIS:
    target = "datapath-android-" + goarch
    entries = [e for e in artifacts if isinstance(e, dict) and e.get("target") == target]
    if len(entries) != 1:
        fail("manifest.json lists %d entries for %s, expected exactly 1." % (len(entries), target))
    entry = entries[0]
    want = entry.get("sha256")
    if not isinstance(want, str) or not HEX64.match(want):
        fail("manifest.json %s sha256 is not 64 lowercase hex." % target)
    if entry.get("build_a_sha256") != want or entry.get("build_b_sha256") != want:
        fail("manifest.json %s: build_a/build_b/sha256 disagree; the two builds were not byte-identical." % target)
    if entry.get("path") != "artifacts/%s/%s" % (target, engine_name):
        fail("manifest.json %s path is not artifacts/%s/%s." % (target, target, engine_name))
    copy = os.path.join(stage_dir, abi, engine_name)
    if os.path.islink(copy) or not os.path.isfile(copy):
        fail("the staged copy for %s is missing: %s" % (abi, copy))
    got = digest(copy)
    size = os.path.getsize(copy)
    if got != want:
        fail("%s: the copied engine sha256 %s does not match the manifest %s." % (abi, got, want))
    if type(entry.get("size")) is not int or entry["size"] != size:
        fail("%s: the copied engine is %d bytes; the manifest says %r." % (abi, size, entry.get("size")))
    engines[abi] = {"sha256": got, "size": size, "target": target}

source = manifest.get("source") if isinstance(manifest.get("source"), dict) else {}
commit = source.get("commit") if isinstance(source.get("commit"), str) else None

if mode == "signed":
    _, signature = load(sig_path, "manifest.sig.json")
    if signature.get("contract") != "winsvpn-winn-release-signature-v1":
        fail("manifest.sig.json does not carry contract winsvpn-winn-release-signature-v1.")
    if signature.get("algorithm") != "ed25519":
        fail("manifest.sig.json algorithm is not ed25519.")
    public_key = signature.get("public_key")
    if not isinstance(public_key, str) or not HEX64.match(public_key):
        fail("manifest.sig.json public_key is not 64 lowercase hex.")
    if signature.get("manifest_sha256") != manifest_sha256:
        fail("manifest.sig.json signs a different manifest than the one verified.")
    signature_hex = signature.get("signature")
    if not isinstance(signature_hex, str) or re.fullmatch(r"[0-9a-f]{128}", signature_hex) is None:
        fail("manifest.sig.json signature is not 128 lowercase hex.")
    # The stamp keeps the signed payload itself, so every release gate can
    # re-verify the Ed25519 signature under the pinned key instead of trusting
    # hex-shaped fields.
    stamp = {
        "contract": contract,
        "engines": engines,
        "manifest_b64": base64.b64encode(manifest_raw).decode("ascii"),
        "manifest_signature": signature_hex,
        "release_manifest_sha256": manifest_sha256,
        "signature_public_key": public_key,
        "signed": True,
        "source_commit": commit,
    }
    tmp = stamp_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(stamp, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, stamp_path)
    print("  release manifest sha256 %s, signed by %s" % (manifest_sha256, public_key))
else:
    print("  release manifest sha256 %s (UNSIGNED, dev use only)" % manifest_sha256)
for abi, _ in ABIS:
    print("  %s %s sha256 %s" % (abi, engines[abi]["target"], engines[abi]["sha256"]))
PY
}

# check_release_stamps is the shell twin of the Gradle release gate. For each
# ABI it takes the engine a release build packages (src/release shadows
# src/main, decided without following links) and the winn-release.json stamp
# of that same source set, and asks the release driver to authenticate them:
# the Ed25519 signature over the manifest bytes the stamp carries must verify
# under the pinned authority key, and the engine's sha256 and size must equal
# that signed manifest's reproducible entry for the ABI's target.
check_release_stamps() {
  local abi target source_set engine failed=0
  for abi in arm64-v8a armeabi-v7a x86_64; do
    target="$(target_for_abi "${abi}")" || return 1
    source_set=main
    engine="${JNI_ROOT}/release/jniLibs/${abi}/${ENGINE_NAME}"
    if [[ -e "${engine}" || -L "${engine}" ]]; then
      source_set=release
    fi
    engine="${JNI_ROOT}/${source_set}/jniLibs/${abi}/${ENGINE_NAME}"
    if [[ ! -f "${JNI_ROOT}/${source_set}/${RELEASE_STAMP_NAME}" || -L "${JNI_ROOT}/${source_set}/${RELEASE_STAMP_NAME}" ]]; then
      echo "REFUSED: src/${source_set}/${RELEASE_STAMP_NAME} is missing or not a regular file; stage a signed release with --stage-release." >&2
      failed=1
      continue
    fi
    "${RELEASE_PYTHON}" -I -B "${RELEASE_DRIVER}" verify-android-stamp \
      --stamp "${JNI_ROOT}/${source_set}/${RELEASE_STAMP_NAME}" \
      --artifact "${engine}" --target "${target}" || failed=1
  done
  return "${failed}"
}

printf 'Winn Protocol Android engine staging (%s mode)\n' "${MODE}"
printf 'Prerequisites:\n'

if [[ -f "${RELEASE_DRIVER}" ]]; then
  note "release driver: ${RELEASE_DRIVER}"
elif [[ "${MODE}" == "stage" || "${MODE}" == "stage-release" ]]; then
  bad "release driver ${RELEASE_DRIVER} (owned by the Arbiter)"
else
  note "release driver: ${RELEASE_DRIVER} (absent; needed only to stage)"
fi

if [[ -x "${RELEASE_PYTHON}" ]]; then
  note "python: ${RELEASE_PYTHON}"
else
  bad "${RELEASE_PYTHON}"
fi

if [[ "${MODE}" == "stage-release" ]]; then
  note "xray build script: not used; --stage-release leaves libxray.so untouched"
elif [[ -f "${XRAY_BUILD_ENGINE}" ]]; then
  note "xray build script: ${XRAY_BUILD_ENGINE}"
else
  bad "xray build script ${XRAY_BUILD_ENGINE}"
fi

for variant in "${SHIP_VARIANTS[@]}"; do
  for abi in arm64-v8a armeabi-v7a x86_64; do
    jni_dir="${JNI_ROOT}/${variant}/jniLibs/${abi}"
    if [[ -d "${jni_dir}" ]]; then
      note "jniLibs dir: ${jni_dir}"
    else
      note "jniLibs dir: ${jni_dir} (will be created)"
    fi
    for name in "${ENGINE_NAME}" "${XRAY_ENGINE_NAME}"; do
      if [[ -f "${jni_dir}/${name}" ]]; then
        note "already staged: ${jni_dir}/${name}"
      else
        note "not staged: ${jni_dir}/${name}"
      fi
    done
  done
done

# The freshness gate enumerates the engine's Go sources with `go list`, so Go is
# needed in every mode, including --stage-release (which builds nothing).
if command -v go >/dev/null 2>&1; then
  note "go: $(command -v go)"
else
  bad "go on PATH"
fi

# discover_pinned_ndk prints the pinned NDK under the SDK, or nothing.
discover_pinned_ndk() {
  ls -d "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/.local/android-sdk}}/ndk/${ANDROID_NDK_PIN}" 2>/dev/null || true
}

if [[ "${MODE}" == "stage-release" ]]; then
  note "NDK: not used; --stage-release builds nothing"
elif [[ -n "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
  note "NDK: ${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT}}"
else
  ndk_guess="$(discover_pinned_ndk)"
  if [[ -n "${ndk_guess}" ]]; then
    note "NDK (discovered): ${ndk_guess}"
  else
    bad "Android NDK ${ANDROID_NDK_PIN} (set ANDROID_NDK_HOME)"
  fi
fi

if [[ "${MODE}" == "check" || "${MODE}" == "release-check" || "${MODE}" == "verify" ]]; then
  printf '\nFreshness gate over every staged engine:\n'
  gate_rc=0
  if [[ "${MODE}" == "release-check" ]]; then
    # Standalone v3 release artifacts exclude the legacy Xray transport. Gate
    # every staged Winn datapath without making an excluded developer asset a
    # release prerequisite.
    gate_all_staged 0 || gate_rc=1
    printf '\nSigned release stamp for the source set a release build packages:\n'
    check_release_stamps || gate_rc=1
  else
    gate_all_staged 1 || gate_rc=1
  fi

  if [[ "${MODE}" == "check" ]]; then
    cat <<MSG

Would run, in --stage-release RELEASE_DIR mode (signed, no network, no rebuild):
  ${RELEASE_PYTHON} -I ${RELEASE_DRIVER_REL} verify --release RELEASE_DIR --print-manifest -> <tmp>/release-snapshot/manifest.json (the verified bytes)
  copy RELEASE_DIR/artifacts/datapath-android-{arm64,arm,amd64}/${ENGINE_NAME} -> <tmp>/{arm64-v8a,armeabi-v7a,x86_64}/${ENGINE_NAME}
  <binding to the verified manifest + freshness + v3 + ABI + page-alignment gate on each copy>
  ${RELEASE_PYTHON} -I ${RELEASE_DRIVER_REL} verify-android-stamp on each copy (signature under the pinned key)
  install to ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/<abi>/${ENGINE_NAME}
  write ${JNI_ROOT}/{main,debug,profile,release}/${RELEASE_STAMP_NAME}
  (${XRAY_ENGINE_NAME} is left untouched)

Would run, in --stage mode (unsigned, debug/dev only):
  ${RELEASE_PYTHON} -I ${RELEASE_DRIVER_REL} build --set android --out <tmp>/winn-release --source-commit <git HEAD> --ndk <NDK ${ANDROID_NDK_PIN}>
  ${RELEASE_PYTHON} -I ${RELEASE_DRIVER_REL} verify --release <tmp>/winn-release --allow-unsigned --print-manifest
  bash ${XRAY_BUILD_ENGINE} android-arm64 <tmp>/arm64-v8a/${XRAY_ENGINE_NAME}
  bash ${XRAY_BUILD_ENGINE} android-arm <tmp>/armeabi-v7a/${XRAY_ENGINE_NAME}
  bash ${XRAY_BUILD_ENGINE} android-amd64 <tmp>/x86_64/${XRAY_ENGINE_NAME}
  <freshness + v3 + ABI gate on each fresh file>
  install each gated build to ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/<abi>/{${ENGINE_NAME},${XRAY_ENGINE_NAME}}
  remove every ${RELEASE_STAMP_NAME} (a dev-staged engine must not satisfy the release gate)

Nothing was written. No Gradle change is needed for these files to be
packaged and extracted; see the header of this script for why.
MSG
  fi

  if [[ "${gate_rc}" -ne 0 ]]; then
    printf '\nA staged engine failed the freshness gate. It must not ship.\n' >&2
    exit 1
  fi
  exit "${fail}"
fi

if [[ "${fail}" -ne 0 ]]; then
  echo "Refusing to stage: prerequisites are missing." >&2
  exit 1
fi

RELEASE_DIR=""
if [[ "${MODE}" == "stage-release" ]]; then
  if [[ ! -d "${RELEASE_DIR_ARG}" || -L "${RELEASE_DIR_ARG}" ]]; then
    gate_fail "--stage-release: ${RELEASE_DIR_ARG} is not a directory (symlinks are refused)."
    exit 1
  fi
  RELEASE_DIR="$(cd "${RELEASE_DIR_ARG}" && pwd -P)"
fi

cat >&2 <<'WARN'

WARNING: staging changes the APK/AAB inputs and invalidates the release
dependency freeze for 1.0.14+29, which is in store review. Regenerate it with
tools/release_dependency_freeze.py afterwards.

WARN

# Build into a private directory and install only what passes.
#
# The order is the point. A gate that runs after the artifact is already sitting
# in jniLibs/ has already lost: the Apple lane found exactly that shape, where a
# REJECTED wrapper was left behind in staging by the very run that rejected it,
# so the next build validated yesterday's file and passed. Here the build output
# never touches jniLibs/ until it has been gated, and the gate only ever looks at
# a file this run created -- checked by requiring the file to be newer than a
# marker dropped immediately before the build. That closes the other half of the
# same hole: "the build did not run and yesterday's file is still there" is
# indistinguishable from success unless you demand fresh bytes. Winn engines
# copied out of a release directory are this run's copies by construction, and
# are additionally bound byte for byte to the release manifest.
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/winnengine-stage.XXXXXX")"
MARKER="${STAGE_DIR}/.build-started"
# Pending copies this run created beside their destinations, and where each
# one goes. Only these are ever removed or renamed.
PENDING_PATHS=()
PENDING_DESTINATIONS=()
cleanup() {
  rm -rf "${STAGE_DIR}"
  local pending
  for pending in ${PENDING_PATHS[@]+"${PENDING_PATHS[@]}"}; do
    if [[ -f "${pending}" && ! -L "${pending}" ]]; then
      rm -f -- "${pending}"
    fi
  done
}
trap cleanup EXIT

# exclusive_pending_copy SOURCE DEST_DIR NAME MODE copies SOURCE to a new file
# with an unpredictable name in DEST_DIR, created with O_CREAT|O_EXCL|O_NOFOLLOW
# so an existing or racing path (or a planted symlink) is refused and never
# written through, and prints that path. The copy is read and written through
# descriptors and its sha256 must equal the source's.
exclusive_pending_copy() {
  "${RELEASE_PYTHON}" -I - "$@" <<'WINS_PENDING_EOF'
import hashlib, os, secrets, stat, sys

source, directory, name, mode = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 8)
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
info = os.lstat(directory)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit(f"destination directory is not a real directory: {directory}")
path = os.path.join(directory, f".{name}.pending.{secrets.token_hex(8)}")
src = os.open(source, read_flags)
try:
    if not stat.S_ISREG(os.fstat(src).st_mode):
        raise SystemExit(f"not a regular file: {source}")
    try:
        dst = os.open(path, write_flags, 0o600)
    except FileExistsError:
        raise SystemExit(f"refusing an existing pending path: {path}")
    source_digest, copy_digest = hashlib.sha256(), hashlib.sha256()
    try:
        while True:
            block = os.read(src, 1024 * 1024)
            if not block:
                break
            source_digest.update(block)
            view = memoryview(block)
            while view:
                view = view[os.write(dst, view):]
        os.fchmod(dst, mode)
        os.fsync(dst)
        os.lseek(dst, 0, os.SEEK_SET)
    finally:
        os.close(dst)
finally:
    os.close(src)
check = os.open(path, read_flags)
try:
    while True:
        block = os.read(check, 1024 * 1024)
        if not block:
            break
        copy_digest.update(block)
finally:
    os.close(check)
if copy_digest.digest() != source_digest.digest():
    os.unlink(path)
    raise SystemExit(f"pending copy differs from its source: {path}")
print(path)
WINS_PENDING_EOF
}

# replace_into_place PENDING DESTINATION renames a pending copy over its
# destination with rename(2): atomic, never follows a destination symlink, and
# refused (EISDIR) if something made the destination a directory, where `mv`
# would have moved the engine inside it and reported success.
replace_into_place() {
  "${RELEASE_PYTHON}" -I - "$@" <<'WINS_REPLACE_EOF'
import os, stat, sys

pending, destination = sys.argv[1], sys.argv[2]
info = os.lstat(pending)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit(f"pending copy is no longer a regular file: {pending}")
os.rename(pending, destination)
WINS_REPLACE_EOF
}

# run_release_driver runs the driver from the project root, in isolated mode.
# Exit 3 from the driver means a pinned toolchain is absent (TOOLCHAIN-MISSING);
# it is passed through unchanged so callers can tell it apart from a refusal.
run_release_driver() {
  ( cd "${PROJECT_ROOT}" && "${RELEASE_PYTHON}" -I "${RELEASE_DRIVER_REL}" "$@" )
}

# stage_winn_from_release copies each ABI's engine out of a release directory
# into the private staging dir and gates the copy. SIGNED=1 is release mode:
# the driver must verify the signature against the pinned authority key, and a
# winn-release.json stamp is produced and authenticated. SIGNED=0 is the dev
# path behind --stage: --allow-unsigned, every artifact sha256 still checked,
# no stamp.
#
# The release is verified exactly once. The driver prints the manifest bytes it
# verified; those held bytes are the only manifest this run uses. The copies
# are bound to them byte for byte, so an artifact or manifest replaced after
# verification cannot pass.
stage_winn_from_release() {
  local rel="$1" signed="$2" abi goarch target rc printed
  local -a verify_flags=()
  [[ "${signed}" == "1" ]] || verify_flags=(--allow-unsigned)

  local snap="${STAGE_DIR}/release-snapshot"
  mkdir -p "${snap}" || return 1
  if [[ "${signed}" == "1" ]]; then
    if [[ ! -f "${rel}/manifest.sig.json" || -L "${rel}/manifest.sig.json" ]]; then
      gate_fail "${rel}/manifest.sig.json is missing: --stage-release requires a release signed with winn_release.py sign."
      return 1
    fi
    # Read once, before verification. The stamp built from it is authenticated
    # below against the verified manifest bytes and the pinned key, so a
    # signature record swapped in either direction is refused.
    cp "${rel}/manifest.sig.json" "${snap}/manifest.sig.json" || return 1
  fi

  echo "[+] Verifying ${rel} (one verification; its manifest bytes are held)"
  rc=0
  run_release_driver verify --release "${rel}" ${verify_flags[@]+"${verify_flags[@]}"} \
    --print-manifest >"${snap}/manifest.json" || rc=$?
  if [[ "${rc}" -eq 3 ]]; then
    gate_fail "the release driver reports a missing toolchain (TOOLCHAIN-MISSING, exit 3)."
    return 3
  fi
  if [[ "${rc}" -ne 0 ]]; then
    gate_fail "winn_release.py verify exited ${rc}. Nothing was installed."
    return 1
  fi
  if [[ "${signed}" == "1" ]]; then
    GATE_VERIFIED_MANIFEST="${snap}/manifest.json"
  fi

  for abi in arm64-v8a armeabi-v7a x86_64; do
    goarch="$(goarch_for_abi "${abi}")" || return 1
    target="$(target_for_abi "${abi}")" || return 1
    printed="${rel}/artifacts/${target}/${ENGINE_NAME}"
    if [[ ! -f "${printed}" || -L "${printed}" ]]; then
      gate_fail "${target}: ${printed} is not a regular file."
      return 1
    fi
    mkdir -p "${STAGE_DIR}/${abi}" || return 1
    cp "${printed}" "${STAGE_DIR}/${abi}/${ENGINE_NAME}" || return 1
    chmod 755 "${STAGE_DIR}/${abi}/${ENGINE_NAME}" || return 1
    gate_engine "${STAGE_DIR}/${abi}/${ENGINE_NAME}" "${goarch}" "release ${target} ${abi} ${ENGINE_NAME}" || return 1
  done

  if [[ "${signed}" == "1" ]]; then
    bind_release_manifest signed "${snap}/manifest.json" "${snap}/manifest.sig.json" \
      "${STAGE_DIR}" "${ENGINE_NAME}" "${STAGE_DIR}/${RELEASE_STAMP_NAME}" "${RELEASE_STAMP_CONTRACT}" || return 1
    for abi in arm64-v8a armeabi-v7a x86_64; do
      target="$(target_for_abi "${abi}")" || return 1
      "${RELEASE_PYTHON}" -I -B "${RELEASE_DRIVER}" verify-android-stamp \
        --stamp "${STAGE_DIR}/${RELEASE_STAMP_NAME}" \
        --artifact "${STAGE_DIR}/${abi}/${ENGINE_NAME}" --target "${target}" || {
        gate_fail "${target}: the new winn-release.json stamp does not authenticate. Nothing was installed."
        return 1
      }
    done
  else
    bind_release_manifest unsigned "${snap}/manifest.json" "" \
      "${STAGE_DIR}" "${ENGINE_NAME}" "" "${RELEASE_STAMP_CONTRACT}" || return 1
  fi
  return 0
}

# build_xray_and_gate builds the Xray transport for one ABI into the private
# staging dir via build_xray_engine.sh, refuses a file older than the marker
# dropped before the build, and gates it on ABI and page alignment.
build_xray_and_gate() {
  local abi="$1" goarch="$2" xray_target out
  case "${abi}" in
    arm64-v8a) xray_target="android-arm64" ;;
    armeabi-v7a) xray_target="android-arm" ;;
    x86_64)    xray_target="android-amd64" ;;
    *) gate_fail "${abi}: unknown ABI."; return 1 ;;
  esac
  mkdir -p "${STAGE_DIR}/${abi}"

  : > "${MARKER}"
  sleep 1  # so "newer than the marker" is decidable on one-second-resolution filesystems

  echo "[+] Staging Xray transport (${abi})"
  local xray_build_ok=0
  if bash "${XRAY_BUILD_ENGINE}" "${xray_target}" "${STAGE_DIR}/${abi}/${XRAY_ENGINE_NAME}"; then
    xray_build_ok=1
  fi
  if [[ "${xray_build_ok}" -ne 1 ]]; then
    gate_fail "${abi}: the xray build failed. Nothing was installed, and whatever is already in jniLibs/ was NOT validated by this run."
    return 1
  fi

  # Refuse to validate a file this run did not just write.
  out="${STAGE_DIR}/${abi}/${XRAY_ENGINE_NAME}"
  if [[ ! -f "${out}" ]]; then
    gate_fail "${abi}: the build reported success but produced no ${out}."
    return 1
  fi
  if [[ ! "${out}" -nt "${MARKER}" ]]; then
    gate_fail "${abi}: ${out} is not newer than the marker dropped before the build started, so it is a leftover rather than this run's output. Refusing to validate it."
    return 1
  fi

  gate_xray "${out}" "${goarch}" "freshly built ${abi} ${XRAY_ENGINE_NAME}" || return 1
  return 0
}

INSTALL_NAMES=("${ENGINE_NAME}")
WRITE_STAMP=0

if [[ "${MODE}" == "stage-release" ]]; then
  printf '\nStaging the Winn engines from signed release %s\n' "${RELEASE_DIR}"
  printf '  %s is left untouched in this mode; nothing is rebuilt and no network is used.\n' "${XRAY_ENGINE_NAME}"
  stage_rc=0
  stage_winn_from_release "${RELEASE_DIR}" 1 || stage_rc=$?
  if [[ "${stage_rc}" -ne 0 ]]; then
    echo "Refusing to stage: the signed release did not verify or an engine did not pass the gate." >&2
    exit "$([[ "${stage_rc}" -eq 3 ]] && echo 3 || echo 1)"
  fi
  WRITE_STAMP=1
else
  # The xray build script searches different default SDK locations for the NDK
  # than the driver does. Resolve the pinned NDK once (it may already be set in
  # the caller's env) and hand it to both, so --stage needs no operator
  # environment.
  if [[ -z "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]]; then
    ndk_guess="$(discover_pinned_ndk)"
    if [[ -n "${ndk_guess}" ]]; then
      export ANDROID_NDK_HOME="${ndk_guess}"
      note "ANDROID_NDK_HOME exported for the builds: ${ndk_guess}"
    fi
  fi

  selected_ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  if [[ -z "${selected_ndk}" ]]; then
    gate_fail "No Android NDK was selected."
    exit 1
  fi
  if ! grep -Fqx "Pkg.Revision = ${ANDROID_NDK_PIN}" \
      "${selected_ndk}/source.properties"; then
    gate_fail "Selected NDK does not match the project pin ${ANDROID_NDK_PIN}."
    exit 1
  fi
  export ANDROID_NDK_HOME="${selected_ndk}"
  export ANDROID_NDK_ROOT="${selected_ndk}"

  # The driver seals the source from a commit. WINN_SOURCE_COMMIT names one
  # explicitly; otherwise it is this checkout's HEAD. The driver itself refuses
  # a dirty tree or an unknown commit.
  source_commit="${WINN_SOURCE_COMMIT:-}"
  if [[ -z "${source_commit}" ]]; then
    source_commit="$(git -C "${PROJECT_ROOT}" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
  fi
  if [[ ! "${source_commit}" =~ ^[0-9a-f]{7,64}$ ]]; then
    gate_fail "Cannot resolve the source commit (git HEAD of ${PROJECT_ROOT}, or WINN_SOURCE_COMMIT)."
    exit 1
  fi

  # Optional driver inputs, passed through only when set: the pinned Go archive
  # (same variable the builder's direct mode uses) and a source export for a
  # tree that is not a git checkout. The driver verifies both against the pins
  # and the commit.
  driver_extra=()
  if [[ -n "${WINS_WINN_GO_ARCHIVE:-}" ]]; then
    driver_extra+=(--go-archive "${WINS_WINN_GO_ARCHIVE}")
  fi
  if [[ -n "${WINN_SOURCE_EXPORT:-}" ]]; then
    driver_extra+=(--source-export "${WINN_SOURCE_EXPORT}")
  fi

  dev_release="${STAGE_DIR}/winn-release"
  echo "[+] Building the Winn Protocol Android engines through the release driver (commit ${source_commit})"
  build_rc=0
  run_release_driver build --set android --out "${dev_release}" \
    --source-commit "${source_commit}" --ndk "${selected_ndk}" \
    ${driver_extra[@]+"${driver_extra[@]}"} || build_rc=$?
  if [[ "${build_rc}" -eq 3 ]]; then
    gate_fail "the release driver reports a missing toolchain (TOOLCHAIN-MISSING, exit 3). Nothing was installed."
    exit 3
  fi
  if [[ "${build_rc}" -ne 0 ]]; then
    gate_fail "winn_release.py build exited ${build_rc}. Nothing was installed, and whatever is already in jniLibs/ was NOT validated by this run."
    exit 1
  fi

  stage_rc=0
  stage_winn_from_release "${dev_release}" 0 || stage_rc=$?
  if [[ "${stage_rc}" -eq 0 ]]; then
    build_xray_and_gate arm64-v8a arm64 || stage_rc=1
    build_xray_and_gate armeabi-v7a arm || stage_rc=1
    build_xray_and_gate x86_64 amd64 || stage_rc=1
  fi
  if [[ "${stage_rc}" -ne 0 ]]; then
    echo "Refusing to stage: an engine did not pass the freshness/ABI gate." >&2
    exit "$([[ "${stage_rc}" -eq 3 ]] && echo 3 || echo 1)"
  fi
  INSTALL_NAMES+=("${XRAY_ENGINE_NAME}")
fi

# All ABIs have now passed before any shipping input is changed. Prepare every
# destination as a sibling temporary, gate those exact copied bytes, then rename
# each into place. This prevents a failed second architecture from leaving only
# half of the variants updated.
install_rc=0
for variant in "${SHIP_VARIANTS[@]}"; do
  for abi in arm64-v8a armeabi-v7a x86_64; do
    goarch="$(goarch_for_abi "${abi}")" || exit 1
    for name in "${INSTALL_NAMES[@]}"; do
      source_so="${STAGE_DIR}/${abi}/${name}"
      dest_dir="${JNI_ROOT}/${variant}/jniLibs/${abi}"
      dest_so="${dest_dir}/${name}"
      mkdir -p "${dest_dir}"
      pending_so="$(exclusive_pending_copy "${source_so}" "${dest_dir}" "${name}" 755)" || {
        gate_fail "src/${variant} ${abi} ${name}: the pending copy could not be created exclusively."
        exit 1
      }
      PENDING_PATHS+=("${pending_so}")
      PENDING_DESTINATIONS+=("${dest_so}")
      if [[ "${name}" == "${ENGINE_NAME}" ]]; then
        gate_engine "${pending_so}" "${goarch}" "pending src/${variant} ${abi} ${name}" || install_rc=1
        if ! cmp -s "${source_so}" "${pending_so}"; then
          gate_fail "pending src/${variant} ${abi} ${name} differs from the verified copy."
          install_rc=1
        fi
      else
        gate_xray "${pending_so}" "${goarch}" "pending src/${variant} ${abi} ${name}" || install_rc=1
      fi
    done
  done
  if [[ "${WRITE_STAMP}" -eq 1 ]]; then
    pending_stamp="$(exclusive_pending_copy "${STAGE_DIR}/${RELEASE_STAMP_NAME}" \
      "${JNI_ROOT}/${variant}" "${RELEASE_STAMP_NAME}" 644)" || {
      gate_fail "src/${variant} ${RELEASE_STAMP_NAME}: the pending copy could not be created exclusively."
      exit 1
    }
    PENDING_PATHS+=("${pending_stamp}")
    PENDING_DESTINATIONS+=("${JNI_ROOT}/${variant}/${RELEASE_STAMP_NAME}")
  fi
done
if [[ "${install_rc}" -ne 0 ]]; then
  echo "Refusing to install: one or more destination copies failed the gate." >&2
  exit 1
fi

# A dev build must never keep a signed stamp alive: remove stamps BEFORE the
# unsigned engines land, so an interruption leaves no stamp rather than a stamp
# that names other bytes. A signed stage renames engines first and the stamp
# last; an interruption there leaves an old stamp that no longer matches, which
# the release gates refuse.
if [[ "${WRITE_STAMP}" -eq 0 ]]; then
  for variant in "${SHIP_VARIANTS[@]}"; do
    rm -f "${JNI_ROOT}/${variant}/${RELEASE_STAMP_NAME}"
  done
fi
# Every engine is renamed first and every stamp last.
for stamp_pass in 0 1; do
  for index in "${!PENDING_PATHS[@]}"; do
    is_stamp=0
    [[ "${PENDING_DESTINATIONS[$index]##*/}" != "${RELEASE_STAMP_NAME}" ]] || is_stamp=1
    [[ "${is_stamp}" -eq "${stamp_pass}" ]] || continue
    replace_into_place "${PENDING_PATHS[$index]}" "${PENDING_DESTINATIONS[$index]}" || {
      gate_fail "could not rename ${PENDING_PATHS[$index]} over ${PENDING_DESTINATIONS[$index]}."
      exit 1
    }
  done
done
PENDING_PATHS=()

# Gate all installed files, not merely the private build outputs.
if [[ "${MODE}" == "stage-release" ]]; then
  final_rc=0
  gate_all_staged 0 || final_rc=1
  check_release_stamps || final_rc=1
  if [[ "${final_rc}" -ne 0 ]]; then
    echo "The installed engines failed the post-install gate. They must not ship." >&2
    exit 1
  fi
  cat <<MSG

Winn Protocol Android engines staged from signed release ${RELEASE_DIR}:
  ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/${ENGINE_NAME}
  ${JNI_ROOT}/{main,debug,profile,release}/${RELEASE_STAMP_NAME}
${XRAY_ENGINE_NAME} was left untouched.

Rebuild the APK/AAB, then regenerate the release dependency freeze.
MSG
else
  gate_all_staged || { echo "The installed engines failed the post-install gate." >&2; exit 1; }
  cat <<MSG

Winn Protocol Android engines staged and gated for all shipping variants
from an UNSIGNED dev build (debug/dev use only; the release gate refuses them):
  ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/arm64-v8a/{${ENGINE_NAME},${XRAY_ENGINE_NAME}}
  ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/armeabi-v7a/{${ENGINE_NAME},${XRAY_ENGINE_NAME}}
  ${JNI_ROOT}/{main,debug,profile,release}/jniLibs/x86_64/{${ENGINE_NAME},${XRAY_ENGINE_NAME}}

64-bit ARM phones use arm64-v8a, 32-bit ARM devices use armeabi-v7a, and the
x86_64 copies are for emulators. Rebuild the APK, then regenerate the release
dependency freeze.
MSG
fi
