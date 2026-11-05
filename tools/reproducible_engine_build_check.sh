#!/usr/bin/env bash
# Two-build reproducibility + host-path-leak gate for the app-embedded Winn v3
# engines. This is the check that produced the 2026-08-10 evidence in
# docs/handoff/REPRODUCIBLE_BUILDS_20260810.md: building the shipping engine
# binaries twice, from independent empty Go build caches, must yield
# byte-identical artifacts that carry no build-host path.
#
# Why it exists (read the catalogue before editing it):
#   - "A green you cannot make fail is not evidence." Two empty caches and a
#     byte cmp are the structure that gives the green teeth: if a future change
#     makes the build host-dependent (a timestamp, an absolute path, an
#     unpinned toolchain), cmp goes red naming the engine.
#   - Go embeds the BUILD HOST's home path into a binary whenever a module is
#     `replace`d to a directory OUTSIDE the main module root -- even with
#     -trimpath (verified 2026-08-10; that is the mechanism behind the
#     libWinsAmneziaWGPacketEngine.dylib leak this lane fixed in
#     build_apple_wg_go_bridge.sh). The scan below is the negative control that
#     keeps such paths out of every engine this checker builds.
#   - The flags reviewed in build_winn_protocol_engine.sh are asserted here
#     structurally (-trimpath, -buildvcs=false, -buildid=, CGO_ENABLED=0): a
#     reintroduced bare path or a dropped flag must fail the scan, not pass by
#     omission.
#
# Targets are taken as argv (not constants): targets=<t>[,<t>...], where each
# <t> is a target accepted by tools/winn_release.py (e.g. datapath-linux-amd64,
# linux-amd64, winn3-gateway-linux-amd64). The two independent builds per target
# are the release driver's: tools/winn_release.py build seals two source
# snapshot copies, runs the builder once per copy with a fresh private GOCACHE
# each time, refuses any byte difference, and records build_a_sha256 and
# build_b_sha256 in manifest.json. This checker re-reads that record and adds
# its own host-path and build-settings gates on the shipped bytes.
#
#   ./tools/reproducible_engine_build_check.sh \
#     --targets datapath-linux-amd64,linux-amd64 \
#     --source-commit <sha> \
#     [--source-export <dir>] [--go-archive <go archive>] [--ndk <dir>] \
#     [--developer-dir <dir>] [--module-proxy <url>] \
#     [--out <work-root>]   # optional; defaults to .artifacts/reproducible-engine-build
#
#   ./tools/reproducible_engine_build_check.sh \
#     --targets datapath-linux-arm64 --release <existing release dir>
#                           # check a release the driver already built
#
# GO_BIN (default: go) is used only to read `go version -m` from the outputs.
#
# Exits 0 only if every target is byte-identical across its two builds, carries
# zero host-path bytes, and reproduces the reviewed Go build settings. Exit 3
# means a pinned toolchain is missing (the driver's TOOLCHAIN-MISSING). Any
# other exit means the reproducibility contract is broken.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DRIVER="${ROOT}/tools/winn_release.py"
GO_BIN="${GO_BIN:-go}"

die() { printf 'REPRODUCIBLE ENGINE BUILD CHECK ERROR: %s\n' "$*" >&2; exit 1; }

targets=""
out_root=""
release=""
source_commit=""
build_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --targets)
      targets="$2"; shift 2;;
    --out)
      out_root="$2"; shift 2;;
    --release)
      release="$2"; shift 2;;
    --source-commit)
      source_commit="$2"; shift 2;;
    --source-export|--go-archive|--ndk|--developer-dir|--module-proxy)
      build_args+=("$1" "$2"); shift 2;;
    *)
      die "unknown argument: $1";;
  esac
done
[[ -n "${targets}" ]] || die "--targets <list> is required."
[[ -f "${DRIVER}" ]] || die "release driver not found: ${DRIVER}"
"${GO_BIN}" version >/dev/null 2>&1 || die "GO_BIN is not runnable: ${GO_BIN}"

if [[ -z "${release}" ]]; then
  [[ -n "${source_commit}" ]] || die "--source-commit <sha> is required to build."
  if [[ -z "${out_root}" ]]; then
    out_root="${ROOT}/.artifacts/reproducible-engine-build"
  fi
  mkdir -p "${out_root}"
  run_dir="$(mktemp -d "${out_root}/run.XXXXXX")"
  release="${run_dir}/release"
  build_status=0
  /usr/bin/python3 -I "${DRIVER}" build --out "${release}" --targets "${targets}" \
    --source-commit "${source_commit}" ${build_args[@]+"${build_args[@]}"} \
    >"${run_dir}/build.log" 2>&1 || build_status=$?
  if [[ "${build_status}" -ne 0 ]]; then
    cat "${run_dir}/build.log" >&2
    if [[ "${build_status}" -eq 3 ]]; then
      printf 'REPRODUCIBLE ENGINE BUILD CHECK ERROR: a pinned toolchain is missing\n' >&2
      exit 3
    fi
    die "the two-build release of ${targets} failed (exit ${build_status}); the driver refuses non-identical builds"
  fi
else
  [[ -z "${source_commit}" && "${#build_args[@]}" -eq 0 ]] \
    || die "--release checks an existing release; build options do not apply."
  [[ -d "${release}" && ! -L "${release}" ]] || die "--release is not a directory: ${release}"
  release="$(cd "${release}" && pwd -P)"
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/reproducible-engine-check.XXXXXX")"
trap 'rm -rf -- "${scratch}"' EXIT
fail_count=0
IFS=',' read -r -a target_list <<<"${targets}"
for tgt in "${target_list[@]}"; do
  # The driver re-hashes every artifact and refuses a release whose manifest
  # does not record build_a == build_b. The signature is not this gate's
  # subject, so --allow-unsigned is used here (never in release staging).
  verify_status=0
  # One verification per target; line 1 of its stdout is the exact manifest
  # it verified, line 2 the artifact path. The record below is read from that
  # line, never from a second read of manifest.json.
  /usr/bin/python3 -I "${DRIVER}" verify --release "${release}" --allow-unsigned \
    --print-manifest --print-artifact "${tgt}" >"${scratch}/verify.out" 2>"${scratch}/verify.err" || verify_status=$?
  artifact="$(sed -n 2p "${scratch}/verify.out")"
  if [[ "${verify_status}" -ne 0 || -z "${artifact}" || ! -f "${artifact}" ]]; then
    printf 'FAIL %s: the release holds no verified artifact for this target\n' "${tgt}"
    sed 's/^/  /' "${scratch}/verify.err"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Independent re-read of the two-build record, so a driver regression that
  # stopped comparing would still fail here.
  if ! /usr/bin/python3 -I -c '
import hashlib
import json
import sys

verified_output, target, artifact = sys.argv[1:4]


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate manifest key {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise SystemExit(f"non-finite manifest number {value}")


with open(verified_output, "rb") as handle:
    manifest = json.loads(handle.read().split(b"\n", 1)[0], object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_constant)
entries = [entry for entry in manifest.get("artifacts", []) if entry.get("target") == target]
if len(entries) != 1:
    raise SystemExit(f"{target} is not listed exactly once")
entry = entries[0]
with open(artifact, "rb") as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
if not (entry.get("build_a_sha256") == entry.get("build_b_sha256") == entry.get("sha256") == digest):
    raise SystemExit(f"{target}: build_a, build_b and the shipped bytes are not identical")
' "${scratch}/verify.out" "${tgt}" "${artifact}"; then
    printf 'FAIL %s: two builds are NOT byte-identical\n' "${tgt}"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Negative control: the compiled artifact must carry no build-host path.
  # The binary's own byte stream is scanned, so a needle reused by both builds
  # never masks a leak (both would carry it and still cmp-equal).
  leaked="$(strings -a "${artifact}" | grep -E "/Users/|/Volumes/" | head -n 1 || true)"
  leaked="${leaked:-}"
  if [[ -n "${leaked}" ]]; then
    printf 'FAIL %s: built artifact embeds a host path: %s\n' "${tgt}" "${leaked}"
    fail_count=$((fail_count + 1))
    continue
  fi

  # Structural flags contract, checked so a dropped flag fails rather than
  # slipping through on the byte cmp (which would still pass if both builds
  # dropped the same flag). -trimpath must be set, and with -buildvcs=false a
  # `go version -m` report carries no `vcs` field at all.
  settings="$("${GO_BIN}" version -m "${artifact}" 2>/dev/null || true)"
  if ! printf '%s\n' "${settings}" | grep -Fq -- "-trimpath=true"; then
    printf 'FAIL %s: reviewed build setting -trimpath=true missing\n' "${tgt}"
    fail_count=$((fail_count + 1))
    continue
  fi
  if printf '%s\n' "${settings}" | grep -q -- '^	vcs	'; then
    printf 'FAIL %s: VCS metadata embedded despite -buildvcs=false\n' "${tgt}"
    fail_count=$((fail_count + 1))
    continue
  fi

  printf 'PASS %s: byte-identical two-build, no host path, reviewed flags\n' "${tgt}"
done

if [[ "${fail_count}" -gt 0 ]]; then
  die "${fail_count} target(s) failed the reproducibility gate"
fi
printf 'REPRODUCIBLE ENGINE BUILD CHECK: PASS (%s targets)\n' "${#target_list[@]}"
