#!/usr/bin/env bash
# Stage the Windows Winn Protocol engine and v3 tun relay for BOTH
# architectures the platform plan requires (windows/amd64 and windows/arm64),
# then build and check the WNN3 framing fixture.
#
# Usage:
#   tools/build_windows_winn_engine.sh --release DIR
#       Release mode. DIR is a signed Winn release directory produced by
#       `tools/winn_release.py build` and `sign`. The release is verified
#       exactly once, by `winn_release.py verify --release DIR --print-manifest`,
#       which checks the manifest signature against the pinned release
#       authority and every artifact digest, and prints the manifest bytes it
#       verified. Every expected digest comes from those held bytes; the
#       manifest file is never read again, and each copied image must hash to
#       its authenticated digest.
#
#   tools/build_windows_winn_engine.sh [--source-commit SHA] [-- DRIVER_ARGS...]
#       Dev mode. Builds the `windows` set through the release driver
#       (`winn_release.py build --set windows --out TMP/rel ...`) and stages
#       from that UNSIGNED release with `verify --allow-unsigned`. Dev and
#       debug use only: the output is not release input. SHA defaults to the
#       checkout's HEAD; DRIVER_ARGS are passed to `winn_release.py build`
#       (for example --go-archive PATH, --module-proxy URL, --jobs N).
#
#   Common options:
#     --engine-root DIR   where engines are staged (default build/windows/winn3)
#     --fixture-dir DIR   where fixtures are written (default build/windows/winn)
#
# WHERE THE ENGINE GOES, and why those names.
# windows/runner/windows_tunnel_backend.cpp (FindWinnDatapathExecutable) and
# windows/runner/winn3_supervisor.cpp (FindWinn3DatapathExecutable) both
# resolve exactly `winn-datapath.exe` beside the running module, with no
# fallback. The packaging scripts take it from one directory per architecture:
#   build/windows/winn3/x64/winn-datapath.exe     (windows/amd64)
#   build/windows/winn3/arm64/winn-datapath.exe   (windows/arm64)
# installer/windows/build_zip_installer.ps1, build_winn3_msi.ps1 and
# build_winn3_msi_arm64.ps1 default -EngineDir to those directories, and
# installer/windows/build_installer.ps1 verifies the same release itself.
# windows/runner/winn3_supervisor.cpp (FindWinn3RelayExecutable) resolves the v3
# tun relay the same way, so it is staged beside the engine from the same
# release (targets winn3-relay-windows-{amd64,arm64}):
#   build/windows/winn3/x64/winsvpn_winn3_engine.exe
#   build/windows/winn3/arm64/winsvpn_winn3_engine.exe
# The relay moves raw inner packets and does no cryptography, so the
# compiled-role check below is what keeps it and the datapath apart.
#
# THE FIXTURE IS STILL BUILT, AND IS NOT THE ENGINE.
# windows/winn_framing_fixture/main.go is a second, independent implementation
# of the WNN3 framing in windows/runner/winn_frame.h, which is the only reason
# a framing bug shared by both sides of one implementation could be caught at
# all. It can never be reached at runtime: the host looks for
# `winn-datapath.exe` and not this artifact's name, the create acknowledgement
# requires contract `winn-datapath/1`, which the fixture does not emit, and it
# identifies itself in-band as "winn-test-double". It is written to a separate
# directory so it can never be packaged by an -EngineDir copy.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture_source_dir="${repo_root}/windows/winn_framing_fixture"
release_tool="${repo_root}/tools/winn_release.py"
role_tool="${repo_root}/tools/windows_winn3_artifact_provenance.py"
python_bin="/usr/bin/python3"

die() {
  printf 'WINDOWS WINN ENGINE STAGING ERROR: %s\n' "$*" >&2
  exit 1
}

release_dir=""
source_commit=""
engine_root="${repo_root}/build/windows/winn3"
fixture_dir="${repo_root}/build/windows/winn"
declare -a driver_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --release) [[ $# -ge 2 ]] || die 'missing --release value'; release_dir="$2"; shift 2 ;;
    --source-commit) [[ $# -ge 2 ]] || die 'missing --source-commit value'; source_commit="$2"; shift 2 ;;
    --engine-root) [[ $# -ge 2 ]] || die 'missing --engine-root value'; engine_root="$2"; shift 2 ;;
    --fixture-dir) [[ $# -ge 2 ]] || die 'missing --fixture-dir value'; fixture_dir="$2"; shift 2 ;;
    --) shift; driver_args=("$@"); break ;;
    *) die "unsupported argument: $1 (see the usage in this script's header)" ;;
  esac
done

if [[ -n "${release_dir}" ]]; then
  [[ -z "${source_commit}" && ${#driver_args[@]} -eq 0 ]] \
    || die '--release stages an existing signed release; --source-commit and driver arguments apply only to dev builds'
fi

[[ -x "${python_bin}" ]] || die "${python_bin} is required"
[[ -f "${release_tool}" ]] || die "the release driver is missing at ${release_tool}"
[[ -f "${role_tool}" ]] || die "the compiled-role checker is missing at ${role_tool}"
[[ -f "${fixture_source_dir}/main.go" ]] \
  || die "the framing fixture source is missing at ${fixture_source_dir}/main.go"

# The plan requires both architectures on Windows. Neither is optional, so a
# failure on either one fails the whole staging rather than shipping half a
# matrix.
declare -a architectures=("amd64" "arm64")
declare -a output_architectures=("x64" "arm64")
declare -a expected_machine=("x86-64" "Aarch64")

# Never trust a name or an exit code alone: confirm the artifact is genuinely a
# PE32+ binary for the architecture that was requested. Applied to the real
# engine and the fixture alike: shipping an amd64 binary named arm64 is exactly
# the half-a-matrix failure the "both architectures" rule exists to prevent.
verify_pe() {
  local path="$1" arch="$2" machine="$3" label="$4"
  [[ -f "${path}" && ! -L "${path}" ]] \
    || die "${label} for windows/${arch} produced no regular artifact."
  if command -v file >/dev/null 2>&1; then
    local description; description="$(file -b "${path}")"
    if [[ "${description}" != *"PE32+"* ]] || [[ "${description}" != *"${machine}"* ]]; then
      die "${label} windows/${arch} has the wrong machine type: ${description}"
    fi
    echo "  ${label} windows/${arch}: ${description}"
  fi
  if command -v shasum >/dev/null 2>&1; then
    printf '  '; shasum -a 256 "${path}"
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '  '; sha256sum "${path}"
  fi
}

file_sha256() {
  "${python_bin}" -I -B -c '
import hashlib, sys
digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for chunk in iter(lambda: handle.read(1 << 20), b""):
        digest.update(chunk)
print(digest.hexdigest())
' "$1"
}

# exclusive_pending_copy SOURCE DEST_DIR NAME copies SOURCE to a new file with
# an unpredictable name in DEST_DIR, created with O_CREAT|O_EXCL|O_NOFOLLOW so
# an existing or racing path (or a planted symlink) is refused and never
# written through, and prints that path.
exclusive_pending_copy() {
  "${python_bin}" -I -B - "$@" <<'WINS_PENDING_EOF'
import os, secrets, stat, sys

source, directory, name = sys.argv[1:4]
read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
info = os.lstat(directory)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
    raise SystemExit(f"destination directory is not a real directory: {directory}")
path = os.path.join(directory, f".{name}.{secrets.token_hex(8)}")
src = os.open(source, read_flags)
try:
    if not stat.S_ISREG(os.fstat(src).st_mode):
        raise SystemExit(f"not a regular file: {source}")
    try:
        dst = os.open(path, write_flags, 0o600)
    except FileExistsError:
        raise SystemExit(f"refusing an existing pending path: {path}")
    try:
        while True:
            block = os.read(src, 1024 * 1024)
            if not block:
                break
            view = memoryview(block)
            while view:
                view = view[os.write(dst, view):]
        os.fsync(dst)
    finally:
        os.close(dst)
finally:
    os.close(src)
print(path)
WINS_PENDING_EOF
}

# replace_into_place PENDING DESTINATION: rename(2) the pending copy over its
# destination. Atomic, never follows a destination symlink, and refused if the
# destination became a directory (where `mv -f` would move the image inside it).
replace_into_place() {
  "${python_bin}" -I -B - "$@" <<'WINS_REPLACE_EOF'
import os, stat, sys

pending, destination = sys.argv[1:3]
info = os.lstat(pending)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
    raise SystemExit(f"pending copy is no longer a regular file: {pending}")
os.rename(pending, destination)
WINS_REPLACE_EOF
}

# The authenticated digest for TARGET, taken from the manifest JSON that
# `verify --print-manifest` printed (the exact bytes whose signature it
# checked), never from a second read of the release directory. The entry must
# also name the expected release-relative path.
manifest_sha256() {
  "${python_bin}" -I -B -c '
import json, re, sys
manifest = json.loads(sys.argv[1])
target, filename = sys.argv[2:4]
rows = [
    row for row in manifest.get("artifacts", [])
    if isinstance(row, dict) and row.get("target") == target
]
if len(rows) != 1:
    sys.exit("manifest must contain exactly one entry for " + target)
row = rows[0]
if row.get("path") != "artifacts/" + target + "/" + filename:
    sys.exit("manifest artifact path is unexpected for " + target)
digest = row.get("sha256")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    sys.exit("manifest digest is invalid for " + target)
print(digest)
' "$1" "$2" "$3"
}

tmp_root=""
declare -a pending_stages=()
declare -a pending_destinations=()
cleanup() {
  local status=$?
  trap - EXIT
  local pending
  for pending in ${pending_stages[@]+"${pending_stages[@]}"}; do
    rm -f -- "${pending}"
  done
  if [[ -n "${tmp_root}" && -d "${tmp_root}" ]]; then
    chmod -R u+rwX "${tmp_root}" 2>/dev/null || true
    rm -rf -- "${tmp_root}"
  fi
  exit "${status}"
}
trap cleanup EXIT

declare -a verify_flags=()
if [[ -n "${release_dir}" ]]; then
  [[ -d "${release_dir}" ]] || die "release directory does not exist: ${release_dir}"
  release_dir="$(cd "${release_dir}" && pwd -P)"
  echo "Staging the Windows Winn engine from the signed release ${release_dir}"
else
  if [[ -z "${source_commit}" ]]; then
    command -v git >/dev/null 2>&1 \
      || die 'git is unavailable; pass --source-commit SHA or --release DIR'
    source_commit="$(git -C "${repo_root}" rev-parse --verify 'HEAD^{commit}')" \
      || die 'the checkout HEAD could not be resolved; pass --source-commit SHA or --release DIR'
  fi
  [[ "${source_commit}" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] \
    || die "--source-commit must be a full lowercase commit id: ${source_commit}"
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/winn-windows-release.XXXXXXXX")"
  release_dir="${tmp_root}/rel"
  echo "Building the Windows Winn set through the release driver (UNSIGNED, dev use only)"
  # A failed build fails this script, with the driver's own exit status
  # (3 means a toolchain is missing). There is no fallback and no partial stage.
  "${python_bin}" -I "${release_tool}" build --set windows --out "${release_dir}" \
    --source-commit "${source_commit}" ${driver_args[@]+"${driver_args[@]}"} \
    || { status=$?; printf 'WINDOWS WINN ENGINE STAGING ERROR: release driver build failed (exit %s)\n' "${status}" >&2; exit "${status}"; }
  verify_flags=(--allow-unsigned)
fi

[[ -f "${release_dir}/manifest.json" ]] \
  || die "release directory has no manifest.json: ${release_dir}"

# One verification for all four images. Its stdout is the verified manifest.
verified_manifest_json="$("${python_bin}" -I -B "${release_tool}" verify \
  --release "${release_dir}" ${verify_flags[@]+"${verify_flags[@]}"} \
  --print-manifest)" || die 'release verification failed'

# Copy one verified release artifact to a private temporary name in its
# destination directory. Nothing is published here.
#   stage_artifact TARGET FILENAME ROLE ARCH OUTPUT_ARCH MACHINE LABEL
stage_artifact() {
  local target="$1" filename="$2" role="$3" arch="$4" output_arch="$5"
  local machine="$6" label="$7"
  local printed expected_sha destination_dir destination staged staged_sha
  printed="${release_dir}/artifacts/${target}/${filename}"
  expected_sha="$(manifest_sha256 "${verified_manifest_json}" "${target}" "${filename}")" \
    || die "authenticated manifest digest for ${target} is unavailable"
  [[ -f "${printed}" && ! -L "${printed}" ]] \
    || die "verified artifact is not a regular file: ${printed}"

  # The compiled Go build information must name the expected main package
  # and module, and the PE machine must match, so the datapath and the relay
  # can never be staged under each other's names (the relay has no
  # cryptography). Bound to the authenticated digest, which the copy below
  # must match too, so both checks see the same bytes.
  "${python_bin}" -I -B "${role_tool}" check-role --role "${role}" \
    --architecture "${output_arch}" --expect-sha256 "${expected_sha}" \
    "${printed}" || die "compiled-role check failed for ${target}"

  destination_dir="${engine_root}/${output_arch}"
  mkdir -p "${destination_dir}"
  [[ -d "${destination_dir}" && ! -L "${destination_dir}" ]] \
    || die "engine destination is not a regular directory: ${destination_dir}"
  destination="${destination_dir}/${filename}"
  [[ ! -L "${destination}" ]] || die "engine destination is a symlink: ${destination}"
  staged="$(exclusive_pending_copy "${printed}" "${destination_dir}" "${filename}")" \
    || die "exclusive copy failed for ${target}"
  pending_stages+=("${staged}")
  pending_destinations+=("${destination}")
  [[ -f "${staged}" && ! -L "${staged}" ]] || die "staged ${target} is not a regular file"
  staged_sha="$(file_sha256 "${staged}")"
  [[ "${staged_sha}" == "${expected_sha}" ]] \
    || die "staged ${target} sha256 ${staged_sha} differs from the authenticated manifest ${expected_sha}"
  (verify_pe "${staged}" "${arch}" "${machine}" "${label}") \
    || die "PE machine check failed for ${target}"
  chmod 0644 "${staged}"
  echo "  verified ${target} (sha256 ${expected_sha})"
}

# 1. THE REAL ENGINE AND THE v3 TUN RELAY, from the same release.
echo "Real engine (cmd/winn-datapath) and v3 tun relay (windows/winn3_engine):"
for index in "${!architectures[@]}"; do
  arch="${architectures[$index]}"
  output_arch="${output_architectures[$index]}"
  stage_artifact "datapath-windows-${arch}" 'winn-datapath.exe' core \
    "${arch}" "${output_arch}" "${expected_machine[$index]}" engine
  stage_artifact "winn3-relay-windows-${arch}" 'winsvpn_winn3_engine.exe' relay \
    "${arch}" "${output_arch}" "${expected_machine[$index]}" relay
done

# Publish only after all four passed, so a failure on one never leaves a new
# image beside a stale one, or a datapath beside a relay from another release.
for index in "${!pending_stages[@]}"; do
  replace_into_place "${pending_stages[$index]}" "${pending_destinations[$index]}" \
    || die "could not publish ${pending_destinations[$index]}"
  echo "  staged ${pending_destinations[$index]}"
done
pending_stages=()

# 2. THE FIXTURE. It earns its keep here, not by existing: two independent
# implementations of the WNN3 layout are only worth having if something makes
# them prove they agree, and this is cheap, needs no Windows, and fails loudly.
command -v go >/dev/null 2>&1 \
  || die 'A Go toolchain on PATH is required to build the framing fixture.'
mkdir -p "${fixture_dir}"

echo "WNN3 framing conformance (c++ winn_frame.h vs go fixture):"
bash "${repo_root}/tools/verify_winn_framing_conformance.sh" | sed 's/^/  /'

echo "Framing fixture (windows/winn_framing_fixture, NOT the engine):"
for index in "${!architectures[@]}"; do
  arch="${architectures[$index]}"
  output="${fixture_dir}/winn_framing_fixture_${arch}.exe"
  (
    cd "${fixture_source_dir}"
    CGO_ENABLED=0 \
    GOOS=windows \
    GOARCH="${arch}" \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
        -o "${output}" .
  )
  verify_pe "${output}" "${arch}" "${expected_machine[$index]}" "fixture"
done

if [[ ${#verify_flags[@]} -eq 0 ]]; then
  echo "WINDOWS WINN ENGINE STAGING: PASS (signed release, engine + relay, amd64 + arm64; framing fixture checked)"
else
  echo "WINDOWS WINN ENGINE STAGING: PASS (UNSIGNED dev build, engine + relay, amd64 + arm64; not release input)"
fi
