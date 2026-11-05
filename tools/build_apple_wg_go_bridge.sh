#!/usr/bin/env bash
set -Eeuo pipefail
# Engine bytes depend on the builder's umask (archive member and output modes
# are recorded); the release producer runs under umask 077, so every build
# does, including a direct WP-A1 rebuild (R11a, measured 2026-10-15).
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONHOME PYTHONPATH
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
export PYTHONDONTWRITEBYTECODE=1
hash -r 2>/dev/null || true

SCRIPT_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${PROJECT_ROOT:-}" && "${PROJECT_ROOT}" != "${SCRIPT_PROJECT_ROOT}" ]]; then
  printf 'ERROR: PROJECT_ROOT override is refused for the release producer.\n' >&2
  exit 1
fi
PROJECT_ROOT="${SCRIPT_PROJECT_ROOT}"
AMNEZIAWG_APPLE_REPO="https://github.com/amnezia-vpn/amneziawg-apple.git"
AMNEZIAWG_APPLE_TAG="v3.1.20260814"
AMNEZIAWG_APPLE_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"
AMNEZIAWG_APPLE_TREE="24183de0cc22b957ff9e34ac3494a80f515ac565"
AMNEZIAWG_APPLE_GENERATION="3.1"
# Measured 2026-10-15 from the official tag v3.1.20260814 (lightweight tag,
# commit and tree above) fetched from AMNEZIAWG_APPLE_REPO:
# Sources/WireGuardKitGo/go.mod and go.sum. The prior v3.1.4 values are gone.
AMNEZIAWG_APPLE_GO_MOD_SHA256="790252dad6cad8aa668ccc4dafdfdac4f2fa3d3fbefce16ded750f0a46cabe0d"
AMNEZIAWG_APPLE_GO_SUM_SHA256="1a806e7973118c0ce8832e15d246fea0c44335a31fc4a0abe36a2ed165fada9d"
# Companion Go engine with stability designation unavailable, consumed by WireGuardKitGo/go.mod.
# The Apple wrapper and Go engine use independent upstream version schemes.
AMNEZIAWG_GO_TAG="v3.1.20260828"
AMNEZIAWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
AMNEZIAWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
AMNEZIAWG_GO_MODULE="github.com/amnezia-vpn/amneziawg-go/v3"
AMNEZIAWG_GO_SUM="h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c="
AMNEZIAWG_GO_MOD_SUM="h1:YoPc6qcOZqD7TXZ1xpedD8Sx3aSKsxN05ZqEFmXDNHk="
# The official Apple wrapper tag requires amneziawg-go v3.1.20260814 and no
# wrapper tag consumes the frozen engine tag yet. The pristine checkout is
# verified against the wrapper's own requirement; the reviewed modfile copy
# then raises exactly that requirement to AMNEZIAWG_GO_TAG. The two engine
# versions share a byte-identical go.mod, so AMNEZIAWG_GO_MOD_SUM is common
# and only the module zip sum differs.
AMNEZIAWG_APPLE_UPSTREAM_GO_TAG="v3.1.20260814"
AMNEZIAWG_APPLE_UPSTREAM_GO_SUM="h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0="
# SHA-256 of the module ZIP served by proxy.golang.org for this exact version,
# measured 2026-10-15; its h1: dirhash equals AMNEZIAWG_GO_SUM and the
# sum.golang.org record.
AMNEZIAWG_GO_MODULE_ZIP_SHA256="14f378d365a612a60aa4352e257d06a02a0091023fd47cb0b4fa7a3e27a174dd"
APPLE_WG_GO_SOURCE_DIR="${APPLE_WG_GO_SOURCE_DIR:-}"
APPLE_WG_GO_OUTPUT_DIR="${APPLE_WG_GO_OUTPUT_DIR:-${PROJECT_ROOT}/.artifacts/apple-wg-go}"
APPLE_WG_GO_PROVENANCE_FILE="${APPLE_WG_GO_OUTPUT_DIR}/apple_awg_31_bridge_provenance.json"
APPLE_WG_GO_ARCHS="${APPLE_WG_GO_ARCHS:-}"
APPLE_MACOS_DEPLOYMENT_TARGET="${APPLE_MACOS_DEPLOYMENT_TARGET:-13.0}"
APPLE_IOS_DEPLOYMENT_TARGET="${APPLE_IOS_DEPLOYMENT_TARGET:-13.0}"
APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET="${APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET:-14.0}"
AMNEZIA_LIBXRAY_MODULE="github.com/amnezia-vpn/amnezia-libxray"
AMNEZIA_LIBXRAY_VERSION="v1.0.3"
AMNEZIA_LIBXRAY_COMMIT="e8cc06d7427251fa549093e7cc32c28b0f5fbafa"
AMNEZIA_LIBXRAY_SUM="h1:xaBuYYVwJgwDZEg4zjzpbg2bDlOczXxM7QNV97Z4ZSU="
AMNEZIA_LIBXRAY_GO_MOD_SUM="h1:rhrXlhRYuWZK7Ok3IDM/JxiaPPszmiJxoWFABwAm6Sg="
AMNEZIA_LIBXRAY_ZIP_SHA256="9435bf77b8da780438b4e152a6b75b35991a920bd4ab5b00533613e8d1d54f4f"
# The official Apple wrapper tag pins an older libxray release than the one
# reviewed above, and that older release is the only one its go.mod and go.sum
# bind. The pristine checkout is verified against these upstream values, then
# prepare_hostname_safe_xray_module() raises exactly that one requirement to
# AMNEZIA_LIBXRAY_VERSION in the reviewed modfile copy. The pristine files stay
# byte-identical to the official tag.
AMNEZIA_LIBXRAY_UPSTREAM_VERSION="v1.0.2"
AMNEZIA_LIBXRAY_UPSTREAM_SUM="h1:em3rcsaOztgOXxvpBOEyAw+OKdfX+fUiibEMI3K79/s="
AMNEZIA_LIBXRAY_UPSTREAM_GO_MOD_SUM="h1:jWzoA5Zd3qu6XJ/4Knz7kQyvaOrLZrPXGQQ0NL7mfPQ="
AMNEZIA_XRAY_MODULE="github.com/amnezia-vpn/amnezia-xray-core"
AMNEZIA_XRAY_REPLACED_MODULE="github.com/xtls/xray-core"
AMNEZIA_XRAY_VERSION="v1.260924.0"
AMNEZIA_XRAY_COMMIT="77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3"
AMNEZIA_XRAY_SUM="h1:4PniqnMxVxC54OdTx3e73BOMH/GD6jf85iaRyApAwGQ="
AMNEZIA_XRAY_GO_MOD_SUM="h1:VwJOtL3vj2w+8TWa6MZE1q88NsfrWvOXGJ+5wZ2N2ro="
# Module ZIP SHA-256 values for amnezia-libxray and amnezia-xray-core were
# measured 2026-10-15 from proxy.golang.org; each ZIP's h1: dirhash equals the
# _SUM pin and the sum.golang.org record. The reviewed modfile, sumfile and
# patched vendor closure were measured the same day by this script's own
# go mod tidy / go mod vendor / ECH patch sequence with the pinned Go 1.27.1.
AMNEZIA_XRAY_ZIP_SHA256="7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40"
AMNEZIA_XRAY_REVIEW_MOD_SHA256="b8d76ea5d2b8cc175934df7be21bbd4f2d8c077b1e3d8b89b0e407017b143f83"
AMNEZIA_XRAY_REVIEW_SUM_SHA256="7b3bed540ff49c058d43a3bd778880e0e57e402527a9da8ba7822aa8bdc2329b"
AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256="ce72b7f83277a9011e3ba40d9bb754df4a7d043c5f84c6e5c05a5cfb067f4778"
# Keep the upstream ECH format example aligned with the hostname-only DNS
# contract used by the data planes. This is diagnostic text, not a runtime
# resolver override, but public-IP URIs are forbidden in customer artifacts.
WINS_APPLE_ECH_DOH_EXAMPLE="https://dns.quad9.net/dns-query"
PATCHED_GOFLAGS=""
PATCH_WORK_ROOT=""
PATCH_MODFILE=""
REVIEWED_GO_WORK_ROOT=""
REVIEWED_GO_HOME=""
REVIEWED_GO_GOPATH=""
REVIEWED_GO_GOMODCACHE=""
REVIEWED_GO_GOCACHE=""
REVIEWED_GO_TMPDIR=""
REVIEWED_GO_AR_DIR=""
APPLE_WG_GO_SOURCE_DATE_EPOCH=""
# H-5: release builds must never trust an ambient `go` -- a stale toolchain
# silently reintroduces fixed standard-library CVEs, and a malicious
# executable earlier on a developer's PATH could inject code into every
# signed iOS/macOS native engine. prepare_reviewed_go() takes Go only from
# WINS_RELEASE_GO_ROOT (the root extracted by
# `tools/winn_release.py prepare-go`, which checks the official archive
# SHA-256) and measures it itself: bin/go SHA-256, the normalized install-tree
# SHA-256 and `go version` must equal the pins below. A digest claimed through
# the environment is never trusted. The archive hashes remain provenance for
# both official Darwin distributions.
REVIEWED_GO_VERSION="1.27.1"
REVIEWED_GO_DARWIN_ARM64_SHA256="ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
REVIEWED_GO_DARWIN_AMD64_SHA256="8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"
REVIEWED_GO_DARWIN_ARM64_TREE_SHA256="f8de74060cc6cfa4a52c3768a6999c0eb4119dec0281d75d225d44a35a2975ac"
REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256="132b69336a1f809932a8a20b0201dbbb980e86e3a323ae32e893639d83d71598"
REVIEWED_GO_PROXY="https://proxy.golang.org"
REVIEWED_GO_SUMDB="sum.golang.org"
APPLE_WG_GO_REPRODUCIBLE_GOFLAGS="-mod=readonly -trimpath -buildvcs=false"
# `-s -w` removes the Go symbol table and DWARF from the delivered static
# bridge. `-buildid=` prevents a host-specific Go build ID. The required C
# exports are validated with nm after every slice is linked, so these flags
# cannot silently remove the host/PacketTunnel ABI.
APPLE_WG_GO_REVIEWED_LDFLAGS="-s -w -buildid="

REQUIRED_SYMBOLS=(
  wgTurnOn
  wgTurnOff
  wgSetConfig
  wgGetConfig
  wgVersion
  LibXrayRunXray
  LibXrayStopXray
  LibXraySetSockCallback
)

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# An empty or malformed pin is a missing measurement, not a checksum mismatch.
# It refuses with exit 65 and names every value that has to be recorded.
die_unpinned() {
  local label
  for label in "$@"; do
    printf 'ERROR: unpinned %s: measure it on a networked host and record it in tools/build_apple_wg_go_bridge.sh\n' "${label}" >&2
  done
  exit 65
}

require_sha256() {
  local path="$1"
  local expected="$2"
  local label="$3"
  [[ "${expected}" =~ ^[0-9a-f]{64}$ ]] \
    || die_unpinned "${label} SHA-256"
  [[ -f "${path}" && ! -L "${path}" ]] \
    || die "${label} is missing, non-regular, or symbolic: ${path}"
  printf '%s  %s\n' "${expected}" "${path}" | shasum -a 256 -c - >/dev/null \
    || die "${label} SHA-256 verification failed: ${path}"
}

require_absent_path() {
  local path="$1"
  local label="$2"
  [[ ! -e "${path}" && ! -L "${path}" ]] \
    || die "${label} must not preexist: ${path}"
}

require_release_closure() {
  local missing=() pin name label
  [[ "${AMNEZIAWG_APPLE_TREE}" =~ ^[0-9a-f]{40}$ ]] \
    || missing+=("AMNEZIAWG_APPLE_TREE (${AMNEZIAWG_APPLE_TAG} Git tree SHA-1)")
  [[ "${AMNEZIA_LIBXRAY_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || missing+=("AMNEZIA_LIBXRAY_COMMIT (${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION} commit)")
  [[ "${AMNEZIA_LIBXRAY_SUM}" == h1:* && "${AMNEZIA_LIBXRAY_GO_MOD_SUM}" == h1:* ]] \
    || missing+=("AMNEZIA_LIBXRAY_SUM/AMNEZIA_LIBXRAY_GO_MOD_SUM (${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION} Go sums)")
  [[ "${AMNEZIA_XRAY_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || missing+=("AMNEZIA_XRAY_COMMIT (${AMNEZIA_XRAY_MODULE}@${AMNEZIA_XRAY_VERSION} commit)")
  [[ "${AMNEZIA_XRAY_SUM}" == h1:* && "${AMNEZIA_XRAY_GO_MOD_SUM}" == h1:* ]] \
    || missing+=("AMNEZIA_XRAY_SUM/AMNEZIA_XRAY_GO_MOD_SUM (${AMNEZIA_XRAY_MODULE}@${AMNEZIA_XRAY_VERSION} Go sums)")
  while IFS='|' read -r pin name label; do
    [[ "${pin}" =~ ^[0-9a-f]{64}$ ]] \
      || missing+=("${name} (${label} SHA-256)")
  done <<PINS
${AMNEZIAWG_APPLE_GO_MOD_SHA256}|AMNEZIAWG_APPLE_GO_MOD_SHA256|${AMNEZIAWG_APPLE_TAG} WireGuardKitGo/go.mod
${AMNEZIAWG_APPLE_GO_SUM_SHA256}|AMNEZIAWG_APPLE_GO_SUM_SHA256|${AMNEZIAWG_APPLE_TAG} WireGuardKitGo/go.sum
${AMNEZIAWG_GO_MODULE_ZIP_SHA256}|AMNEZIAWG_GO_MODULE_ZIP_SHA256|${AMNEZIAWG_GO_MODULE}@${AMNEZIAWG_GO_TAG} module ZIP
${AMNEZIA_LIBXRAY_ZIP_SHA256}|AMNEZIA_LIBXRAY_ZIP_SHA256|${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION} module ZIP
${AMNEZIA_XRAY_ZIP_SHA256}|AMNEZIA_XRAY_ZIP_SHA256|${AMNEZIA_XRAY_MODULE}@${AMNEZIA_XRAY_VERSION} module ZIP
${AMNEZIA_XRAY_REVIEW_MOD_SHA256}|AMNEZIA_XRAY_REVIEW_MOD_SHA256|reviewed WireGuardKitGo modfile
${AMNEZIA_XRAY_REVIEW_SUM_SHA256}|AMNEZIA_XRAY_REVIEW_SUM_SHA256|reviewed WireGuardKitGo sumfile
${AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256}|AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256|patched vendor closure
PINS
  # Bash 3.2 treats an empty array as unset under `set -u`, so test the count.
  if [[ "${#missing[@]}" -gt 0 ]]; then
    die_unpinned "${missing[@]}"
  fi
}

reject_hostile_go_environment() {
  local name
  for name in GOFLAGS GOWORK GOPROXY GOSUMDB GOEXPERIMENT; do
    [[ -z "${!name:-}" ]] \
      || die "Ambient ${name} is refused; the release Go environment is constructed by this producer."
  done
  [[ -z "${APPLE_WG_GO_ARCHS}" ]] \
    || die "APPLE_WG_GO_ARCHS is refused; release architecture sets are immutable."
}

apple_wg_go_flags() {
  printf "%s %s '-ldflags=%s'\n" \
    "${APPLE_WG_GO_REPRODUCIBLE_GOFLAGS}" \
    "${PATCHED_GOFLAGS}" \
    "${APPLE_WG_GO_REVIEWED_LDFLAGS}"
}

# Measures the Go root named by WINS_RELEASE_GO_ROOT against the pins in this
# file. Every value is re-measured from disk on each call; nothing claimed by
# the caller's environment is accepted.
verify_reviewed_go_root() {
  local label="$1" measured_tree
  [[ "${GO_BIN:-}" == "${WINS_RELEASE_GO_ROOT:?}/bin/go" ]] \
    || die "Pinned Go executable path drifted from WINS_RELEASE_GO_ROOT."
  [[ -x "${GO_BIN}" && -f "${GO_BIN}" && ! -L "${GO_BIN}" ]] \
    || die "WINS_RELEASE_GO_ROOT has no regular executable bin/go (${label})."
  require_sha256 "${GO_BIN}" "${REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256}" \
    "WINS_RELEASE_GO_ROOT bin/go (${label})"
  measured_tree="$(/usr/bin/python3 -I "${PROJECT_ROOT}/tools/winn_release.py" \
    digest --kind go-tree "${WINS_RELEASE_GO_ROOT}")" \
    || die "WINS_RELEASE_GO_ROOT install tree could not be measured (${label}); it must be the frozen tree from tools/winn_release.py prepare-go."
  [[ "${measured_tree}" == "${REVIEWED_GO_DARWIN_ARM64_TREE_SHA256}" ]] \
    || die "WINS_RELEASE_GO_ROOT install tree ${measured_tree} is not the reviewed Go tree ${REVIEWED_GO_DARWIN_ARM64_TREE_SHA256} (${label})."
}

prepare_reviewed_go() {
  local identity go_root canonical
  [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] \
    || die "Pinned Apple release Go is reviewed only for darwin/arm64 (tools/toolchain-pins.json pins only that install tree)."
  [[ -z "${WINS_RELEASE_GO:-}" ]] \
    || die "WINS_RELEASE_GO executable path export is refused; pass the extracted Go root as WINS_RELEASE_GO_ROOT."
  go_root="${WINS_RELEASE_GO_ROOT:-}"
  [[ "${go_root}" == /* && -d "${go_root}" && ! -L "${go_root}" ]] \
    || die "WINS_RELEASE_GO_ROOT must name the pinned Go ${REVIEWED_GO_VERSION} root extracted by tools/winn_release.py prepare-go."
  canonical="$(cd "${go_root}" && pwd -P)" \
    || die "WINS_RELEASE_GO_ROOT cannot be resolved."
  [[ "${canonical}" == "${go_root}" ]] \
    || die "WINS_RELEASE_GO_ROOT must already be canonical: ${go_root}"
  WINS_RELEASE_GO_ROOT="${go_root}"
  export WINS_RELEASE_GO_ROOT
  GO_BIN="${go_root}/bin/go"
  verify_reviewed_go_root "before build"

  REVIEWED_GO_WORK_ROOT="$(mktemp -d "/private/tmp/wins-apple-reviewed-go.XXXXXX")"
  # Registered here (not just by main()/verify_hostname_patch() after
  # ensure_tools returns) so this temp dir is cleaned up even if a future
  # caller invokes ensure_tools without repeating that trap; re-registering
  # the same handler at the existing call sites afterward is a harmless
  # no-op, not a second independent trap.
  trap cleanup_patch_work_root EXIT
  chmod 700 "${REVIEWED_GO_WORK_ROOT}"
  REVIEWED_GO_HOME="${REVIEWED_GO_WORK_ROOT}/home"
  REVIEWED_GO_GOPATH="${REVIEWED_GO_WORK_ROOT}/gopath"
  REVIEWED_GO_GOMODCACHE="${REVIEWED_GO_WORK_ROOT}/gomodcache"
  REVIEWED_GO_GOCACHE="${REVIEWED_GO_WORK_ROOT}/gocache"
  REVIEWED_GO_TMPDIR="${REVIEWED_GO_WORK_ROOT}/tmp"
  mkdir -p "${REVIEWED_GO_HOME}" "${REVIEWED_GO_GOPATH}" \
    "${REVIEWED_GO_GOMODCACHE}" "${REVIEWED_GO_GOCACHE}" "${REVIEWED_GO_TMPDIR}"
  # GOTELEMETRY is not settable from the environment; the private HOME's mode
  # file turns telemetry off so no detached counter writer outlives cleanup.
  mkdir -p "${REVIEWED_GO_HOME}/Library/Application Support/go/telemetry"
  printf 'off\n' >"${REVIEWED_GO_HOME}/Library/Application Support/go/telemetry/mode"
  identity="$(reviewed_go '' version)" \
    || die "Pinned Go could not report its version."
  [[ "${identity}" == "go version go${REVIEWED_GO_VERSION} darwin/arm64" ]] \
    || die "Reviewed Go toolchain identity mismatch: ${identity}"
  if [[ -z "${APPLE_WG_GO_SOURCE_DIR}" ]]; then
    APPLE_WG_GO_SOURCE_DIR="${REVIEWED_GO_WORK_ROOT}/source/amneziawg-apple"
  fi
  require_absent_path "${APPLE_WG_GO_SOURCE_DIR}" "Apple AWG source checkout"
}

reviewed_go() {
  local goflags="$1"
  shift
  /usr/bin/env -i \
    "HOME=${REVIEWED_GO_HOME:?}" \
    "PATH=${WINS_RELEASE_GO_ROOT:?}/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    "TMPDIR=${REVIEWED_GO_TMPDIR:?}" \
    "GOROOT=${WINS_RELEASE_GO_ROOT:?}" \
    "GOPATH=${REVIEWED_GO_GOPATH:?}" \
    "GOMODCACHE=${REVIEWED_GO_GOMODCACHE:?}" \
    "GOCACHE=${REVIEWED_GO_GOCACHE:?}" \
    "GOENV=off" \
    "GOTOOLCHAIN=local" \
    "GOFLAGS=${goflags}" \
    "GOWORK=off" \
    "GOPROXY=${REVIEWED_GO_PROXY}" \
    "GOSUMDB=${REVIEWED_GO_SUMDB}" \
    "GOEXPERIMENT=" \
    "GOPRIVATE=" \
    "GONOPROXY=" \
    "GONOSUMDB=" \
    "GOAUTH=off" \
    "GOTELEMETRY=off" \
    "LANG=C" \
    "LC_ALL=C" \
    "TZ=UTC" \
    "${GO_BIN:?}" "$@"
}

reviewed_git() {
  /usr/bin/env -i \
    "HOME=${REVIEWED_GO_HOME:?}" \
    "PATH=/usr/bin:/bin:/usr/sbin:/sbin" \
    "TMPDIR=${REVIEWED_GO_TMPDIR:?}" \
    "GIT_CONFIG_NOSYSTEM=1" \
    "GIT_CONFIG_GLOBAL=/dev/null" \
    "GIT_TERMINAL_PROMPT=0" \
    "GIT_ASKPASS=/usr/bin/false" \
    "SSH_ASKPASS=/usr/bin/false" \
    "LANG=C" \
    "LC_ALL=C" \
    "TZ=UTC" \
    /usr/bin/git "$@"
}

ensure_tools() {
  command -v git >/dev/null 2>&1 || die "git is required."
  command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."
  prepare_reviewed_go
  command -v python3 >/dev/null 2>&1 || die "Python 3 is required for deterministic source patching."
  reviewed_go '' version
}

patch_hostname_safe_xray_source() {
  local source_root="$1"
  local source_file="${source_root}/transport/internet/tls/ech.go"
  [[ -f "${source_file}" && ! -L "${source_file}" ]] \
    || die "Pinned Amnezia Xray ECH source is missing or unsafe."
  python3 - "${source_file}" "${WINS_APPLE_ECH_DOH_EXAMPLE}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
replacement_uri = sys.argv[2]
old = b"example.com+https://1.1.1.1/dns-query"
new = ("example.com+" + replacement_uri).encode("ascii")
data = path.read_bytes()
if old not in data or new in data:
    raise SystemExit(
        "Pinned Amnezia Xray ECH source has no reviewed hostname example to patch."
    )
updated = data.replace(old, new)
if old in updated or new not in updated:
    raise SystemExit("Hostname-safe ECH example patch did not replace every unsafe URI.")
path.write_bytes(updated)
PY
}

# A local filesystem replace leaks its absolute path through Go build metadata
# even with -trimpath. The hostname-safe Xray patch must therefore live at the
# exact standard vendor path while the modfile retains the reviewed versioned
# replacement. This keeps binary metadata reproducible and identifies the
# policy-selected v1.260924.0 instead of an owner-specific cache directory.
assert_trimpath_covered_patch_root() {
  local root="$1" module_dir="$2"
  [[ "${root}" == "${module_dir}/vendor/github.com/xtls/xray-core" ]] \
    || die "Pinned Amnezia Xray patch must use the exact WireGuardKitGo vendor path: ${root}"
}

verify_pinned_awg_go_module() {
  local metadata_file metadata source_root module_zip
  metadata_file="${REVIEWED_GO_WORK_ROOT}/amneziawg-go-download.json"
  (
    cd "${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
    reviewed_go '' mod download -json \
      "${AMNEZIAWG_GO_MODULE}@${AMNEZIAWG_GO_TAG}"
  ) >"${metadata_file}"
  metadata="$(python3 - "${metadata_file}" \
    "${AMNEZIAWG_GO_MODULE}" "${AMNEZIAWG_GO_TAG}" \
    "${AMNEZIAWG_GO_SUM}" "${AMNEZIAWG_GO_MOD_SUM}" \
    "${AMNEZIAWG_GO_COMMIT}" <<'PY'
import json
import pathlib
import sys

path, expected_module, expected_version, expected_sum, expected_mod_sum, expected_commit = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected = {
    "Path": expected_module,
    "Version": expected_version,
    "Sum": expected_sum,
    "GoModSum": expected_mod_sum,
}
for key, wanted in expected.items():
    if value.get(key) != wanted:
        raise SystemExit(
            f"Pinned AmneziaWG Go module {key} mismatch: expected {wanted!r}, found {value.get(key)!r}"
        )
origin = value.get("Origin") or {}
if origin.get("VCS") != "git" or origin.get("Hash") != expected_commit:
    raise SystemExit(
        "Pinned AmneziaWG Go module origin mismatch: "
        f"expected git commit {expected_commit}, found {origin!r}"
    )
source = pathlib.Path(value.get("Dir", ""))
archive = pathlib.Path(value.get("Zip", ""))
if not source.is_dir() or source.is_symlink():
    raise SystemExit(f"Pinned AmneziaWG Go module directory is missing or symbolic: {source}")
if not archive.is_file() or archive.is_symlink():
    raise SystemExit(f"Pinned AmneziaWG Go module zip is missing or symbolic: {archive}")
print(source)
print(archive)
PY
)" || die "Pinned AmneziaWG Go module metadata verification failed."
  source_root="$(printf '%s\n' "${metadata}" | sed -n '1p')"
  module_zip="$(printf '%s\n' "${metadata}" | sed -n '2p')"
  [[ -d "${source_root}" && ! -L "${source_root}" ]] \
    || die "Pinned AmneziaWG Go module cache is missing or unsafe."
  [[ -f "${module_zip}" && ! -L "${module_zip}" ]] \
    || die "Pinned AmneziaWG Go module archive is missing or unsafe."
  require_sha256 "${module_zip}" "${AMNEZIAWG_GO_MODULE_ZIP_SHA256}" \
    "Pinned AmneziaWG Go module archive"
  grep -Fqx "module ${AMNEZIAWG_GO_MODULE}" "${source_root}/go.mod" \
    || die "Pinned AmneziaWG Go module declares an unexpected module path."
}

verify_pinned_libxray_module() {
  local metadata_file metadata source_root module_zip
  metadata_file="${REVIEWED_GO_WORK_ROOT}/amnezia-libxray-download.json"
  (
    cd "${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
    reviewed_go '' mod download -json \
      "${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION}"
  ) >"${metadata_file}"
  metadata="$(python3 - "${metadata_file}" \
    "${AMNEZIA_LIBXRAY_MODULE}" "${AMNEZIA_LIBXRAY_VERSION}" \
    "${AMNEZIA_LIBXRAY_SUM}" "${AMNEZIA_LIBXRAY_GO_MOD_SUM}" \
    "${AMNEZIA_LIBXRAY_COMMIT}" <<'PY'
import json
import pathlib
import sys

path, expected_module, expected_version, expected_sum, expected_mod_sum, expected_commit = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected = {
    "Path": expected_module,
    "Version": expected_version,
    "Sum": expected_sum,
    "GoModSum": expected_mod_sum,
}
for key, wanted in expected.items():
    if value.get(key) != wanted:
        raise SystemExit(
            f"Pinned libxray module {key} mismatch: expected {wanted!r}, found {value.get(key)!r}"
        )
origin = value.get("Origin") or {}
if origin.get("VCS") != "git" or origin.get("Hash") != expected_commit:
    raise SystemExit(
        "Pinned libxray module origin mismatch: "
        f"expected git commit {expected_commit}, found {origin!r}"
    )
source = pathlib.Path(value.get("Dir", ""))
archive = pathlib.Path(value.get("Zip", ""))
if not source.is_dir() or source.is_symlink():
    raise SystemExit(f"Pinned libxray module directory is missing or symbolic: {source}")
if not archive.is_file() or archive.is_symlink():
    raise SystemExit(f"Pinned libxray module zip is missing or symbolic: {archive}")
print(source)
print(archive)
PY
)" || die "Pinned amnezia-libxray module metadata verification failed."
  source_root="$(printf '%s\n' "${metadata}" | sed -n '1p')"
  module_zip="$(printf '%s\n' "${metadata}" | sed -n '2p')"
  [[ -d "${source_root}" && ! -L "${source_root}" ]] \
    || die "Pinned amnezia-libxray module cache is missing or unsafe."
  require_sha256 "${module_zip}" "${AMNEZIA_LIBXRAY_ZIP_SHA256}" \
    "Pinned amnezia-libxray module archive"
  grep -Fqx "module ${AMNEZIA_LIBXRAY_MODULE}" "${source_root}/go.mod" \
    || die "Pinned amnezia-libxray module declares an unexpected module path."
}

prepare_hostname_safe_xray_module() {
  local source_root module_zip patched_root module_dir modfile metadata_file metadata
  verify_pinned_awg_go_module
  verify_pinned_libxray_module
  metadata_file="${REVIEWED_GO_WORK_ROOT}/amnezia-xray-download.json"
  (
    cd "${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
    reviewed_go '' mod download -json \
      "${AMNEZIA_XRAY_MODULE}@${AMNEZIA_XRAY_VERSION}"
  ) >"${metadata_file}"
  metadata="$(python3 - "${metadata_file}" \
    "${AMNEZIA_XRAY_MODULE}" "${AMNEZIA_XRAY_VERSION}" \
    "${AMNEZIA_XRAY_SUM}" "${AMNEZIA_XRAY_GO_MOD_SUM}" \
    "${AMNEZIA_XRAY_COMMIT}" <<'PY'
import json
import pathlib
import sys

path, expected_module, expected_version, expected_sum, expected_mod_sum, expected_commit = sys.argv[1:]
value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
expected = {
    "Path": expected_module,
    "Version": expected_version,
    "Sum": expected_sum,
    "GoModSum": expected_mod_sum,
}
for key, wanted in expected.items():
    if value.get(key) != wanted:
        raise SystemExit(
            f"Pinned Xray module {key} mismatch: expected {wanted!r}, found {value.get(key)!r}"
        )
origin = value.get("Origin") or {}
if origin.get("VCS") != "git" or origin.get("Hash") != expected_commit:
    raise SystemExit(
        "Pinned Xray module origin mismatch: "
        f"expected git commit {expected_commit}, found {origin!r}"
    )
source = pathlib.Path(value.get("Dir", ""))
archive = pathlib.Path(value.get("Zip", ""))
if not source.is_dir() or source.is_symlink():
    raise SystemExit(f"Pinned Xray module directory is missing or symbolic: {source}")
if not archive.is_file() or archive.is_symlink():
    raise SystemExit(f"Pinned Xray module zip is missing or symbolic: {archive}")
print(source)
print(archive)
PY
)" || die "Pinned Amnezia Xray module metadata verification failed."
  source_root="$(printf '%s\n' "${metadata}" | sed -n '1p')"
  module_zip="$(printf '%s\n' "${metadata}" | sed -n '2p')"
  [[ -d "${source_root}" && ! -L "${source_root}" ]] \
    || die "Pinned Amnezia Xray module cache is missing or unsafe."
  require_sha256 "${module_zip}" "${AMNEZIA_XRAY_ZIP_SHA256}" \
    "Pinned Amnezia Xray module archive"
  grep -Fqx "module ${AMNEZIA_XRAY_REPLACED_MODULE}" "${source_root}/go.mod" \
    || die "Pinned Amnezia Xray module declares an unexpected module path."

  module_dir="${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
  modfile="${module_dir}/winsvpn-hostname-safe.mod"
  PATCH_WORK_ROOT="${module_dir}/vendor"
  [[ ! -e "${modfile}" && ! -e "${module_dir}/winsvpn-hostname-safe.sum" \
     && ! -e "${PATCH_WORK_ROOT}" ]] \
    || die "Stale hostname-safe Go modfile or vendor tree exists in the pinned source tree."
  cp "${module_dir}/go.mod" "${modfile}"
  cp "${module_dir}/go.sum" "${module_dir}/winsvpn-hostname-safe.sum"
  PATCH_MODFILE="${modfile}"
  # Raise the libxray requirement to the reviewed release in the reviewed copy
  # only. A replace directive inside libxray's own go.mod is ignored (only the
  # main module's replaces apply), so the Xray core replacement below is the
  # one that selects the core.
  (
    cd "${module_dir}"
    reviewed_go '' mod edit -modfile="${modfile}" \
      -require="${AMNEZIA_LIBXRAY_MODULE}@${AMNEZIA_LIBXRAY_VERSION}"
  )
  # Raise the engine requirement to the frozen tag in the reviewed copies only;
  # the pristine go.mod and go.sum stay byte-identical to the official tag.
  (
    cd "${module_dir}"
    reviewed_go '' mod edit -modfile="${modfile}" \
      -require="${AMNEZIAWG_GO_MODULE}@${AMNEZIAWG_GO_TAG}"
  )
  sed -i.bak \
    -e "s#^\(${AMNEZIAWG_GO_MODULE} \)${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG} ${AMNEZIAWG_APPLE_UPSTREAM_GO_SUM}\$#\1${AMNEZIAWG_GO_TAG} ${AMNEZIAWG_GO_SUM}#" \
    -e "s#^\(${AMNEZIAWG_GO_MODULE} \)${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}/go.mod #\1${AMNEZIAWG_GO_TAG}/go.mod #" \
    "${module_dir}/winsvpn-hostname-safe.sum"
  rm -f -- "${module_dir}/winsvpn-hostname-safe.sum.bak"
  grep -Fqx "${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_GO_TAG} ${AMNEZIAWG_GO_SUM}" \
    "${module_dir}/winsvpn-hostname-safe.sum" \
    || die "Reviewed Apple sum file does not bind amneziawg-go ${AMNEZIAWG_GO_TAG}."
  grep -Fqx "${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_GO_TAG}/go.mod ${AMNEZIAWG_GO_MOD_SUM}" \
    "${module_dir}/winsvpn-hostname-safe.sum" \
    || die "Reviewed Apple sum file does not bind the amneziawg-go ${AMNEZIAWG_GO_TAG} go.mod sum."
  # Resolve the exact Xray tag's complete minimal-version-selection graph in
  # the temporary modfile, then freeze the exact result. Weakening the build
  # to -mod=mod would let Go rewrite this graph silently during compilation.
  (
    cd "${module_dir}"
    reviewed_go '' mod edit -modfile="${modfile}" \
      -replace="${AMNEZIA_XRAY_REPLACED_MODULE}=${AMNEZIA_XRAY_MODULE}@${AMNEZIA_XRAY_VERSION}"
    reviewed_go '' mod tidy -modfile="${modfile}"
  )
  require_sha256 "${modfile}" "${AMNEZIA_XRAY_REVIEW_MOD_SHA256}" \
    "Reviewed Apple Xray dependency modfile"
  require_sha256 "${module_dir}/winsvpn-hostname-safe.sum" \
    "${AMNEZIA_XRAY_REVIEW_SUM_SHA256}" \
    "Reviewed Apple Xray dependency sum file"
  (
    cd "${module_dir}"
    reviewed_go '' mod vendor -modfile="${modfile}"
  )
  patched_root="${PATCH_WORK_ROOT}/github.com/xtls/xray-core"
  assert_trimpath_covered_patch_root "${patched_root}" "${module_dir}"
  patch_hostname_safe_xray_source "${patched_root}"
  PATCHED_GOFLAGS="-modfile=${modfile} -mod=vendor"
  verify_reviewed_modfile
}

verify_reviewed_modfile() {
  local sum_file="${PATCH_MODFILE%.mod}.sum"
  local patched_source vendor_closure
  [[ -n "${PATCH_MODFILE}" && -n "${PATCH_WORK_ROOT}" ]] \
    || die "Apple Xray patched modfile is not prepared."
  require_sha256 "${PATCH_MODFILE}" "${AMNEZIA_XRAY_REVIEW_MOD_SHA256}" \
    "Apple Xray dependency modfile"
  require_sha256 "${sum_file}" "${AMNEZIA_XRAY_REVIEW_SUM_SHA256}" \
    "Apple Xray dependency sum file"
  [[ -d "${PATCH_WORK_ROOT}" && ! -L "${PATCH_WORK_ROOT}" ]] \
    || die "Apple Xray vendor tree is missing or symbolic."
  [[ -z "$(find "${PATCH_WORK_ROOT}" -type l -print -quit)" ]] \
    || die "Apple Xray vendor tree contains a symbolic link."
  [[ -z "$(find "${PATCH_WORK_ROOT}" ! -type d ! -type f -print -quit)" ]] \
    || die "Apple Xray vendor tree contains a non-regular entry."
  grep -Fqx "# ${AMNEZIA_XRAY_REPLACED_MODULE} v1.260724.0 => ${AMNEZIA_XRAY_MODULE} ${AMNEZIA_XRAY_VERSION}" \
    "${PATCH_WORK_ROOT}/modules.txt" \
    || die "Apple Xray vendor manifest does not bind the reviewed replacement."
  grep -Fqx "# ${AMNEZIA_LIBXRAY_MODULE} ${AMNEZIA_LIBXRAY_VERSION}" \
    "${PATCH_WORK_ROOT}/modules.txt" \
    || die "Apple Xray vendor manifest does not bind reviewed amnezia-libxray."
  grep -Fqx "# ${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_GO_TAG}" \
    "${PATCH_WORK_ROOT}/modules.txt" \
    || die "Apple Xray vendor manifest does not bind the frozen amneziawg-go engine."
  patched_source="${PATCH_WORK_ROOT}/github.com/xtls/xray-core/transport/internet/tls/ech.go"
  grep -Fq "example.com+${WINS_APPLE_ECH_DOH_EXAMPLE}" "${patched_source}" \
    || die "Apple Xray vendor tree lost the hostname-safe ECH patch."
  ! grep -Fq 'https://1.1.1.1/dns-query' "${patched_source}" \
    || die "Apple Xray vendor tree contains the retired public-IP ECH example."
  vendor_closure="$(
    cd "${PATCH_WORK_ROOT}"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}'
  )"
  [[ "${vendor_closure}" == "${AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256}" ]] \
    || die "Apple Xray patched vendor closure mismatch: ${vendor_closure}"
}

cleanup_patch_work_root() {
  if [[ -n "${PATCH_MODFILE}" ]]; then
    case "${PATCH_MODFILE}" in
      "${APPLE_WG_GO_SOURCE_DIR}"/Sources/WireGuardKitGo/winsvpn-hostname-safe.mod)
        rm -f "${PATCH_MODFILE}" "${PATCH_MODFILE%.mod}.sum"
        ;;
      *)
        die "Refusing to remove an unsafe Apple Xray patch modfile."
        ;;
    esac
  fi
  if [[ -n "${PATCH_WORK_ROOT}" ]]; then
    case "${PATCH_WORK_ROOT}" in
      "${APPLE_WG_GO_SOURCE_DIR}"/Sources/WireGuardKitGo/vendor)
        rm -rf "${PATCH_WORK_ROOT}"
        ;;
      *)
        die "Refusing to remove an unsafe Apple Xray patch work root."
        ;;
    esac
  fi
  if [[ -n "${REVIEWED_GO_WORK_ROOT}" ]]; then
    case "${REVIEWED_GO_WORK_ROOT}" in
      /private/tmp/wins-apple-reviewed-go.*)
        # Go writes its module cache read-only (dirs 0555), so a plain rm -rf
        # fails with EACCES and the EXIT trap turns a finished run into exit 1.
        chmod -R u+w "${REVIEWED_GO_WORK_ROOT}"
        rm -rf "${REVIEWED_GO_WORK_ROOT}"
        ;;
      *)
        die "Refusing to remove an unsafe reviewed-Go work root."
        ;;
    esac
  fi
}

self_test() (
  command -v python3 >/dev/null 2>&1 || die "Python 3 is required for the self-test."
  local root
  root="$(mktemp -d "/private/tmp/wins-apple-xray-patch-test.XXXXXX")"
  trap 'case "${root}" in /private/tmp/wins-apple-xray-patch-test.*) rm -rf "${root}";; esac' EXIT

  # The exact standard vendor path must pass, and any local replace-style path
  # must fail because Go records it in binary module metadata.
  mkdir -p "${root}/module-dir/vendor/github.com/xtls/xray-core"
  assert_trimpath_covered_patch_root \
    "${root}/module-dir/vendor/github.com/xtls/xray-core" \
    "${root}/module-dir"
  if (assert_trimpath_covered_patch_root \
        "${root}/module-dir/.hostname-safe-xray.bad/amnezia-xray-core" \
        "${root}/module-dir" >/dev/null 2>&1); then
    die "Self-test accepted a local replacement path instead of the exact vendor path."
  fi
  printf 'APPLE WG GO TRIMPATH PATCH-ROOT INVARIANT SELF-TEST: PASS\n'

  mkdir -p "${root}/transport/internet/tls"
  cat >"${root}/transport/internet/tls/ech.go" <<'EOF'
// example.com+https://1.1.1.1/dns-query
var message = "example.com+https://1.1.1.1/dns-query"
EOF
  patch_hostname_safe_xray_source "${root}"
  grep -Fq 'example.com+https://dns.quad9.net/dns-query' "${root}/transport/internet/tls/ech.go"
  if grep -Fq 'https://1.1.1.1/dns-query' "${root}/transport/internet/tls/ech.go"; then
    die "Hostname-safe ECH self-test retained the public-IP URI."
  fi

  printf '%s\n' '// example.com+https://9.9.9.9/dns-query' \
    >"${root}/transport/internet/tls/ech.go"
  if (patch_hostname_safe_xray_source "${root}" >/dev/null 2>&1); then
    die "Hostname-safe ECH patch accepted an unexpected upstream source shape."
  fi
  local reviewed_flags
  reviewed_flags="$(apple_wg_go_flags)"
  [[ "${reviewed_flags}" == *"-mod=readonly -trimpath -buildvcs=false"* ]] \
    || die "Apple Go bridge self-test did not enforce reproducible Go flags."
  [[ "${reviewed_flags}" == *"'-ldflags=-s -w -buildid='"* ]] \
    || die "Apple Go bridge self-test did not enforce reviewed Go linker stripping."
  [[ "${AMNEZIAWG_APPLE_TAG}" == "v3.1.20260814" ]]
  [[ "${AMNEZIAWG_APPLE_COMMIT}" == "fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d" ]]
  [[ "${AMNEZIAWG_APPLE_TREE}" == "24183de0cc22b957ff9e34ac3494a80f515ac565" ]]
  [[ "${AMNEZIAWG_APPLE_GENERATION}" == "3.1" ]]
  [[ "${AMNEZIAWG_GO_TAG}" == "v3.1.20260828" ]]
  [[ "${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}" == "v3.1.20260814" ]]
  [[ "${AMNEZIAWG_APPLE_UPSTREAM_GO_SUM}" == "h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0=" ]]
  [[ "${AMNEZIAWG_GO_SUM}" == "h1:D8d8gGvwXcTxUIsE4z6F6vjy4/VZddu95vMNtOygh1c=" ]]
  [[ "${AMNEZIAWG_GO_COMMIT}" == "b5928efb6ca19f0153958460c3d141f04abc5c2e" ]]
  [[ "${AMNEZIAWG_GO_COMMIT}" != "${AMNEZIAWG_APPLE_COMMIT}" ]]
  [[ "${AMNEZIA_LIBXRAY_VERSION}" == "v1.0.3" ]]
  [[ "${AMNEZIA_LIBXRAY_COMMIT}" == "e8cc06d7427251fa549093e7cc32c28b0f5fbafa" ]]
  [[ "${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}" == "v1.0.2" ]]
  [[ "${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}" != "${AMNEZIA_LIBXRAY_VERSION}" ]]
  [[ "${AMNEZIA_LIBXRAY_UPSTREAM_SUM}" == "h1:em3rcsaOztgOXxvpBOEyAw+OKdfX+fUiibEMI3K79/s=" ]]
  [[ "${AMNEZIA_LIBXRAY_UPSTREAM_GO_MOD_SUM}" == "h1:jWzoA5Zd3qu6XJ/4Knz7kQyvaOrLZrPXGQQ0NL7mfPQ=" ]]
  [[ "${AMNEZIAWG_GO_SOURCE_SHA256}" == "10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4" ]]
  [[ "${REVIEWED_GO_VERSION}" == "1.27.1" ]]
  [[ "${AMNEZIA_XRAY_REPLACED_MODULE}" == "github.com/xtls/xray-core" ]]
  [[ "${AMNEZIA_XRAY_VERSION}" == "v1.260924.0" ]]
  [[ "${AMNEZIA_XRAY_COMMIT}" == "77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3" ]]
  local unpinned_status=0
  ( require_sha256 "${root}/transport/internet/tls/ech.go" "" "self-test fixture" ) \
    >/dev/null 2>&1 || unpinned_status=$?
  [[ "${unpinned_status}" -eq 65 ]] \
    || die "Apple Go bridge self-test accepted an unpinned SHA-256."
  printf 'APPLE AWG 3.1 CLOSURE IDENTITY SELF-TEST: PASS\n'
  printf 'APPLE WG GO HOSTNAME-SAFE SOURCE PATCH SELF-TEST: PASS\n'
)

verify_hostname_patch() {
  ensure_tools
  sync_source
  trap cleanup_patch_work_root EXIT
  prepare_hostname_safe_xray_module
  local patched_source module_dir replacement_identity
  patched_source="${PATCH_WORK_ROOT}/github.com/xtls/xray-core/transport/internet/tls/ech.go"
  grep -Fq "example.com+${WINS_APPLE_ECH_DOH_EXAMPLE}" "${patched_source}"
  if grep -Fq 'https://1.1.1.1/dns-query' "${patched_source}"; then
    die "Pinned hostname-safe Xray source retained the public-IP URI."
  fi
  module_dir="${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
  replacement_identity="$(
    cd "${module_dir}"
    reviewed_go "${PATCHED_GOFLAGS}" list -m \
      -f '{{if .Replace}}{{.Replace.Path}} {{.Replace.Version}}{{end}}' \
      "${AMNEZIA_XRAY_REPLACED_MODULE}"
  )"
  [[ "${replacement_identity}" == "${AMNEZIA_XRAY_MODULE} ${AMNEZIA_XRAY_VERSION}" ]] \
    || die "Go did not resolve the reviewed versioned Amnezia Xray replacement."
  printf 'APPLE WG GO PINNED HOSTNAME PATCH VERIFY: PASS\n'
}

sync_source() {
  require_absent_path "${APPLE_WG_GO_SOURCE_DIR}" "Apple AWG source checkout"
  mkdir -p "$(dirname "${APPLE_WG_GO_SOURCE_DIR}")" "${APPLE_WG_GO_SOURCE_DIR}"
  reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" init -q
  reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" remote add origin "${AMNEZIAWG_APPLE_REPO}"
  reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" fetch --depth=1 --force origin \
    "refs/tags/${AMNEZIAWG_APPLE_TAG}"
  local fetched_commit
  fetched_commit="$(reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" rev-parse 'FETCH_HEAD^{commit}')"
  [[ "${fetched_commit}" == "${AMNEZIAWG_APPLE_COMMIT}" ]] \
    || die "Official Apple AWG tag ${AMNEZIAWG_APPLE_TAG} resolved to ${fetched_commit}, expected ${AMNEZIAWG_APPLE_COMMIT}."
  reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" checkout --detach FETCH_HEAD
  verify_upstream_source_contract
  APPLE_WG_GO_SOURCE_DATE_EPOCH="$(reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" show -s --format=%ct HEAD)"
  [[ "${APPLE_WG_GO_SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]] \
    || die "Apple AWG source commit timestamp is invalid."
}

verify_upstream_source_contract() {
  local actual_commit actual_tree status module_dir
  actual_commit="$(reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" rev-parse HEAD)"
  actual_tree="$(reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" rev-parse 'HEAD^{tree}')"
  [[ "${actual_commit}" == "${AMNEZIAWG_APPLE_COMMIT}" ]] \
    || die "Apple AWG checkout commit mismatch: ${actual_commit}"
  [[ "${actual_tree}" == "${AMNEZIAWG_APPLE_TREE}" ]] \
    || die "Apple AWG checkout tree mismatch: ${actual_tree}"
  status="$(reviewed_git -C "${APPLE_WG_GO_SOURCE_DIR}" status --porcelain --untracked-files=all)"
  [[ -z "${status}" ]] \
    || die "Apple AWG checkout is not pristine after selecting ${AMNEZIAWG_APPLE_TAG}."

  module_dir="${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo"
  require_sha256 "${module_dir}/go.mod" "${AMNEZIAWG_APPLE_GO_MOD_SHA256}" \
    "Apple AWG 3.1 go.mod"
  require_sha256 "${module_dir}/go.sum" "${AMNEZIAWG_APPLE_GO_SUM_SHA256}" \
    "Apple AWG 3.1 go.sum"
  grep -Fqx "github.com/amnezia-vpn/amneziawg-go/v3 ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}" \
    < <(sed -n "s/^[[:space:]]*\(github.com\/amnezia-vpn\/amneziawg-go\/v3 ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}\)[[:space:]]*$/\1/p" "${module_dir}/go.mod") \
    || die "Apple AWG source does not pin amneziawg-go/v3 ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}."
  grep -Fqx "${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG} ${AMNEZIAWG_APPLE_UPSTREAM_GO_SUM}" \
    "${module_dir}/go.sum" \
    || die "Apple AWG source does not bind the reviewed AmneziaWG Go module sum."
  grep -Fqx "${AMNEZIAWG_GO_MODULE} ${AMNEZIAWG_APPLE_UPSTREAM_GO_TAG}/go.mod ${AMNEZIAWG_GO_MOD_SUM}" \
    "${module_dir}/go.sum" \
    || die "Apple AWG source does not bind the reviewed AmneziaWG Go go.mod sum."
  grep -Fqx "${AMNEZIA_LIBXRAY_MODULE} ${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}" \
    < <(awk -v module="${AMNEZIA_LIBXRAY_MODULE}" \
      -v version="${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}" \
      '$1 == module && $2 == version && NF == 2 { print $1 " " $2 }' \
      "${module_dir}/go.mod") \
    || die "Apple AWG source does not pin amnezia-libxray ${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}."
  grep -Fqx "${AMNEZIA_LIBXRAY_MODULE} ${AMNEZIA_LIBXRAY_UPSTREAM_VERSION} ${AMNEZIA_LIBXRAY_UPSTREAM_SUM}" \
    "${module_dir}/go.sum" \
    || die "Apple AWG source does not bind the reviewed amnezia-libxray module sum."
  grep -Fqx "${AMNEZIA_LIBXRAY_MODULE} ${AMNEZIA_LIBXRAY_UPSTREAM_VERSION}/go.mod ${AMNEZIA_LIBXRAY_UPSTREAM_GO_MOD_SUM}" \
    "${module_dir}/go.sum" \
    || die "Apple AWG source does not bind the reviewed amnezia-libxray go.mod sum."
  [[ "${AMNEZIAWG_GO_COMMIT}" != "${AMNEZIAWG_APPLE_COMMIT}" ]] \
    || die "Apple wrapper commit must remain distinct from the Go engine commit."
  # The immutable Apple tag and reviewed Xray core use independent upstream
  # version schemes. The go.mod and go.sum hashes above freeze the exact
  # upstream contents, while prepare_hostname_safe_xray_module() reapplies the
  # checksum-pinned core replacement before any build begins.
  grep -Eq '^replace github\.com/xtls/xray-core => github\.com/amnezia-vpn/amnezia-xray-core v[0-9][^[:space:]]*$' \
    "${module_dir}/go.mod" \
    || die "Apple AWG source has an unexpected Xray replacement module."
}

expected_platform() {
  case "$1" in
    macosx) printf 'MACOS\n' ;;
    iphoneos) printf 'IOS\n' ;;
    iphonesimulator) printf 'IOSSIMULATOR\n' ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

platform_archs() {
  case "$1" in
    macosx) printf 'arm64 x86_64\n' ;;
    iphoneos) printf 'arm64\n' ;;
    iphonesimulator) printf 'arm64 x86_64\n' ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

validate_symbols() {
  local archive="$1"
  local symbols
  symbols="$(xcrun nm -gU "${archive}" 2>/dev/null | awk '{ print $NF }' | sed 's/^_//' | sort -u)"
  [[ -n "${symbols}" ]] || die "No exported symbols found in ${archive}."
  local symbol
  for symbol in "${REQUIRED_SYMBOLS[@]}"; do
    grep -qx "${symbol}" <<<"${symbols}" \
      || die "Apple Go bridge archive is missing symbol ${symbol}: ${archive}"
  done
}

validate_archs() {
  local archive="$1"
  local required_archs="$2"
  local actual_archs
  actual_archs="$(xcrun lipo -archs "${archive}" 2>/dev/null || true)"
  [[ -n "${actual_archs// }" ]] || die "No inspectable architectures in ${archive}."

  local actual_normalized required_normalized
  local -a actual_array required_array
  read -r -a actual_array <<<"${actual_archs}"
  read -r -a required_array <<<"${required_archs}"
  actual_normalized="$(printf '%s\n' "${actual_array[@]}" | LC_ALL=C sort -u | paste -sd ' ' -)"
  required_normalized="$(printf '%s\n' "${required_array[@]}" | LC_ALL=C sort -u | paste -sd ' ' -)"
  [[ "${actual_normalized}" == "${required_normalized}" ]] \
    || die "Apple Go bridge archive ${archive} architectures are ${actual_archs}; expected exactly ${required_archs}."
}

validate_platform() {
  local archive="$1"
  local platform="$2"
  local archs="$3"
  local expected
  expected="$(expected_platform "${platform}")"

  local tmp_dir
  tmp_dir="$(mktemp -d "${REVIEWED_GO_TMPDIR:?}/validate.XXXXXX")"

  local arch
  for arch in ${archs}; do
    rm -f "${tmp_dir}/thin.a" "${tmp_dir}/go.o"
    xcrun lipo "${archive}" -thin "${arch}" -output "${tmp_dir}/thin.a"
    (cd "${tmp_dir}" && xcrun ar -x thin.a go.o)
    [[ -f "${tmp_dir}/go.o" ]] || die "Could not extract ${arch} go.o from ${archive}."

    local actual
    actual="$(xcrun vtool -show-build "${tmp_dir}/go.o" 2>/dev/null \
      | awk '/^[[:space:]]*platform[[:space:]]+[A-Z0-9_]+[[:space:]]*$/ { print $2; exit }')"
    [[ "${actual}" == "${expected}" ]] \
      || die "Apple Go bridge archive ${archive} ${arch} slice targets ${actual:-unknown}; expected ${expected}."
  done
  rm -rf "${tmp_dir}"
}

# Go 1.26 exported darwin_arm_init_thread_exception_port and
# darwin_arm_init_mach_exception_handler from !lldb iOS builds, but those
# functions were empty stubs. Go 1.27 replaced the Darwin-specific cgo thread
# implementation with the unified pthread implementation and removed both
# no-op symbols. Gate the load-bearing Go 1.27 cgo thread entry points in every
# simulator slice instead. validate_platform() independently proves these are
# IOSSIMULATOR Mach-O slices, so a macOS archive cannot satisfy this check.
validate_simulator_cgo_helpers() {
  local archive="$1"
  local archs="$2"
  local tmp_dir
  tmp_dir="$(mktemp -d "${REVIEWED_GO_TMPDIR:?}/sim-cgo.XXXXXX")"
  local arch symbols symbol
  local required_helpers=(
    _cgo_sys_thread_start
    x_cgo_getstackbound
    x_cgo_init
    x_cgo_sys_thread_create
    x_cgo_thread_start
  )
  for arch in ${archs}; do
    rm -f "${tmp_dir}/thin.a"
    xcrun lipo "${archive}" -thin "${arch}" -output "${tmp_dir}/thin.a"
    symbols="$(xcrun nm -a "${tmp_dir}/thin.a" 2>/dev/null \
      | awk '$2 == "T" { print $3 }' | sed 's/^_//' | sort -u)"
    for symbol in "${required_helpers[@]}"; do
      grep -qx "${symbol}" <<<"${symbols}" \
        || die "iPhone simulator Go bridge archive ${arch} is missing Go 1.27 cgo helper ${symbol}."
    done
  done
  rm -rf "${tmp_dir}"
}

# Xcode 27.0 cctools archivers (ar -s, ranlib, libtool -static) sometimes
# leave uninitialized bytes in the padding of the __.SYMDEF string table:
# measured 2026-10-15, /usr/bin/ar -q -c -s wrote them in 6 of 60 runs on
# identical inputs with ZERO_AR_DATE=1. cmd/link builds every c-archive with
# `ar -q -c -s`, and cmd/go hashes the whole archive into the Go build ID
# inside go.o, so one stray byte changes go.o, libwg-go.a and every wrapper
# linked from it. This private `ar` runs /usr/bin/ar unchanged and then zeroes
# only the string-table bytes after the last symbol name, which is exactly
# what a clean run writes. A symbol table it cannot parse is refused.
# cmd/link asks the C compiler for its archiver (`clang --print-prog-name=ar`),
# which returns Xcode's own ar, so the directory is handed to clang as
# COMPILER_PATH (clang's environment form of -B, searched before its own tool
# directory; `cc -###` output is unchanged by it, so cgo action IDs are too).
# It is also on PATH after the pinned Go bin directory, which has no `ar`, for
# a linker that falls back to plain `ar`.
install_deterministic_ar() {
  REVIEWED_GO_AR_DIR="${REVIEWED_GO_WORK_ROOT:?}/ar-bin"
  require_absent_path "${REVIEWED_GO_AR_DIR}" "Deterministic ar directory"
  mkdir -m 700 "${REVIEWED_GO_AR_DIR}"
  cat >"${REVIEWED_GO_AR_DIR}/ar" <<'PY'
#!/usr/bin/python3 -I
import struct
import subprocess
import sys


def refuse(message):
    sys.stderr.write(f"deterministic ar: {message}\n")
    raise SystemExit(1)


def normalize(path):
    with open(path, "r+b") as handle:
        data = bytearray(handle.read())
        if data[:8] != b"!<arch>\n" or len(data) < 68:
            refuse(f"{path} is not an ar archive")
        name = bytes(data[8:24]).rstrip(b" ")
        size = int(bytes(data[56:66]).decode("ascii").strip())
        body_start = 68
        if name.startswith(b"#1/"):
            name_length = int(name[3:])
            name = bytes(data[68:68 + name_length]).rstrip(b"\0")
            body_start += name_length
        body_end = 68 + size
        if name in (b"__.SYMDEF", b"__.SYMDEF SORTED"):
            word, entry = "<I", 8
        elif name in (b"__.SYMDEF_64", b"__.SYMDEF_64 SORTED"):
            word, entry = "<Q", 16
        else:
            refuse(f"{path} does not start with a symbol table: {name!r}")
        width = struct.calcsize(word)
        if body_end > len(data) or body_start + 2 * width > body_end:
            refuse(f"{path} symbol table is truncated")
        ranlib_bytes = struct.unpack_from(word, data, body_start)[0]
        entries = body_start + width
        if ranlib_bytes % entry or entries + ranlib_bytes + width > body_end:
            refuse(f"{path} symbol table entries are malformed")
        string_bytes = struct.unpack_from(word, data, entries + ranlib_bytes)[0]
        strings = entries + ranlib_bytes + width
        strings_end = strings + string_bytes
        if strings_end > body_end or any(data[strings_end:body_end]):
            refuse(f"{path} symbol table has unexpected trailing bytes")
        last = strings
        for index in range(ranlib_bytes // entry):
            offset = struct.unpack_from(word, data, entries + index * entry)[0]
            if offset >= string_bytes:
                refuse(f"{path} symbol name offset is out of range")
            terminator = data.find(b"\0", strings + offset, strings_end)
            if terminator < 0:
                refuse(f"{path} symbol name is not terminated")
            last = max(last, terminator + 1)
        data[last:strings_end] = bytes(strings_end - last)
        handle.seek(0)
        handle.write(data)


arguments = sys.argv[1:]
# cmd/link of the pinned Go calls exactly `ar -q -c -s <archive> <members...>`.
# Any other shape means the toolchain changed: refuse here, by name, instead of
# skipping normalization and failing later as "archive is not reproducible".
if (
    arguments[:3] != ["-q", "-c", "-s"]
    or len(arguments) < 5
    or any(argument.startswith("-") for argument in arguments[3:])
):
    refuse(
        "the deterministic ar wrapper accepts only `-q -c -s <archive> <members...>` "
        "from the pinned Go linker; review a changed toolchain before using it"
    )
status = subprocess.run(["/usr/bin/ar", *arguments], check=False).returncode
if status:
    raise SystemExit(status)
normalize(arguments[3])
PY
  chmod 700 "${REVIEWED_GO_AR_DIR}/ar"
}

build_platform_once() {
  local platform="$1"
  local archs="$2"
  local sdk_root="$3"
  local deployment_flag="$4"
  local deployment_env="$5"
  local deployment_value="$6"
  local pass="$7"
  local pass_root="${REVIEWED_GO_WORK_ROOT}/builds/${platform}/${pass}"
  local output_dir="${pass_root}/output"
  local temp_dir="${pass_root}/temp"
  local pass_gocache="${pass_root}/gocache"
  local goroot_seed="${pass_root}/goroot-seed"
  local clang_bin lipo_bin archive
  require_absent_path "${pass_root}" "Apple AWG deterministic build pass"
  mkdir -p "${output_dir}" "${temp_dir}" "${pass_gocache}" "${goroot_seed}"
  # WireGuardKitGo applies its reviewed runtime diff to a per-build GOROOT.
  # The authenticated owner runtime is sealed read-only, so copy its exact
  # bytes into this fresh private pass before upstream Makefile patching.
  /usr/bin/rsync -a --exclude=pkg/obj/go-build \
    "${WINS_RELEASE_GO_ROOT:?}/" "${goroot_seed}/"
  chmod -R u+w "${goroot_seed}"
  require_sha256 "${goroot_seed}/bin/go" \
    "${REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256}" \
    "Deterministic Apple AWG build-pass Go executable"
  clang_bin="$(xcrun --sdk "${platform}" -f clang)"
  lipo_bin="$(xcrun -f lipo)"
  [[ -x "${clang_bin}" && ! -L "${clang_bin}" ]] \
    || die "Xcode did not resolve a safe clang for ${platform}."
  [[ -x "${lipo_bin}" && ! -L "${lipo_bin}" ]] \
    || die "Xcode did not resolve a safe lipo."
  [[ -f "${REVIEWED_GO_AR_DIR:?}/ar" && -x "${REVIEWED_GO_AR_DIR}/ar" && ! -L "${REVIEWED_GO_AR_DIR}/ar" \
     && ! -e "${WINS_RELEASE_GO_ROOT:?}/bin/ar" ]] \
    || die "The deterministic ar is missing or shadowed by the pinned Go bin directory."
  [[ "$(/usr/bin/env -i "PATH=/usr/bin:/bin" "COMPILER_PATH=${REVIEWED_GO_AR_DIR}" \
        "${clang_bin}" --print-prog-name=ar)" == "${REVIEWED_GO_AR_DIR}/ar" ]] \
    || die "Xcode clang does not resolve the deterministic ar through COMPILER_PATH."

  /usr/bin/env -i \
    "HOME=${REVIEWED_GO_HOME:?}" \
    "PATH=${WINS_RELEASE_GO_ROOT:?}/bin:${REVIEWED_GO_AR_DIR:?}:/usr/bin:/bin:/usr/sbin:/sbin" \
    "COMPILER_PATH=${REVIEWED_GO_AR_DIR:?}" \
    "TMPDIR=${REVIEWED_GO_TMPDIR:?}" \
    "GOROOT=${goroot_seed}" \
    "GOPATH=${REVIEWED_GO_GOPATH:?}" \
    "GOMODCACHE=${REVIEWED_GO_GOMODCACHE:?}" \
    "GOCACHE=${pass_gocache}" \
    "GOENV=off" \
    "GOTOOLCHAIN=local" \
    "GOFLAGS=$(apple_wg_go_flags)" \
    "GOWORK=off" \
    "GOPROXY=${REVIEWED_GO_PROXY}" \
    "GOSUMDB=${REVIEWED_GO_SUMDB}" \
    "GOEXPERIMENT=" \
    "GOPRIVATE=" \
    "GONOPROXY=" \
    "GONOSUMDB=" \
    "GOAUTH=off" \
    "GOTELEMETRY=off" \
    "LANG=C" \
    "LC_ALL=C" \
    "TZ=UTC" \
    "SOURCE_DATE_EPOCH=${APPLE_WG_GO_SOURCE_DATE_EPOCH:?}" \
    "ZERO_AR_DATE=1" \
    SDKROOT="${sdk_root}" \
    /usr/bin/make \
      -B \
      PLATFORM_NAME="${platform}" \
      GOOS_iphonesimulator=ios \
      DEPLOYMENT_TARGET_CLANG_FLAG_NAME="${deployment_flag}" \
      DEPLOYMENT_TARGET_CLANG_ENV_NAME="${deployment_env}" \
      "${deployment_env}=${deployment_value}" \
      ARCHS="${archs}" \
      CC="${clang_bin}" \
      LIPO="${lipo_bin}" \
      CONFIGURATION_BUILD_DIR="${output_dir}" \
      CONFIGURATION_TEMP_DIR="${temp_dir}" \
      -C "${APPLE_WG_GO_SOURCE_DIR}/Sources/WireGuardKitGo" \
      build

  archive="${output_dir}/libwg-go.a"
  [[ -f "${archive}" && ! -L "${archive}" ]] \
    || die "Deterministic Apple AWG build pass did not produce a safe archive: ${archive}"
  validate_symbols "${archive}"
  validate_archs "${archive}" "${archs}"
  validate_platform "${archive}" "${platform}" "${archs}"
  if [[ "${platform}" == "iphonesimulator" ]]; then
    validate_simulator_cgo_helpers "${archive}" "${archs}"
  fi
  printf '%s\n' "${archive}"
}

build_platform() {
  local platform="$1"
  local archs sdk_root
  archs="$(platform_archs "${platform}")"
  sdk_root="$(xcrun --sdk "${platform}" --show-sdk-path)"
  [[ -d "${sdk_root}" ]] \
    || die "Xcode did not resolve the ${platform} SDK root."
  local deployment_flag deployment_env deployment_value
  case "${platform}" in
    macosx)
      deployment_flag="mmacosx-version-min"
      deployment_env="MACOSX_DEPLOYMENT_TARGET"
      deployment_value="${APPLE_MACOS_DEPLOYMENT_TARGET}"
      ;;
    iphoneos)
      deployment_flag="miphoneos-version-min"
      deployment_env="IPHONEOS_DEPLOYMENT_TARGET"
      deployment_value="${APPLE_IOS_DEPLOYMENT_TARGET}"
      ;;
    iphonesimulator)
      deployment_flag="mios-simulator-version-min"
      deployment_env="IPHONEOS_DEPLOYMENT_TARGET"
      deployment_value="${APPLE_IOS_SIMULATOR_DEPLOYMENT_TARGET}"
      ;;
    *) die "Unknown Apple platform '${platform}'." ;;
  esac
  verify_reviewed_modfile
  local first second first_sha second_sha output_dir archive
  first="$(build_platform_once "${platform}" "${archs}" "${sdk_root}" \
    "${deployment_flag}" "${deployment_env}" "${deployment_value}" first | tail -n 1)"
  second="$(build_platform_once "${platform}" "${archs}" "${sdk_root}" \
    "${deployment_flag}" "${deployment_env}" "${deployment_value}" second | tail -n 1)"
  first_sha="$(shasum -a 256 "${first}" | awk '{print $1}')"
  second_sha="$(shasum -a 256 "${second}" | awk '{print $1}')"
  [[ "${first_sha}" == "${second_sha}" ]] \
    || die "Apple AWG ${platform} archive is not reproducible: ${first_sha} != ${second_sha}"

  output_dir="${APPLE_WG_GO_OUTPUT_DIR}/${platform}"
  require_absent_path "${output_dir}" "Apple AWG ${platform} output"
  mkdir "${output_dir}"
  archive="${output_dir}/libwg-go.a"
  mv "${first}" "${archive}"
  require_sha256 "${archive}" "${first_sha}" "Published Apple AWG ${platform} archive"
  validate_archs "${archive}" "${archs}"
  printf 'Validated reproducible Apple Go bridge: %s (%s, sha256=%s)\n' \
    "${archive}" "${archs}" "${first_sha}"
}

run_embedded_runtime_gate() {
  # H-5 (Final Recommendations.md): "run the embedded-runtime gate on the
  # finished slices before packaging." This re-derives the Go version
  # actually embedded in the libwg-go.a slices just built above -- a
  # defense-in-depth self-check independent of, and in addition to, whatever
  # prepare_reviewed_go() already enforced at fetch time. It catches a
  # future regression in this script (e.g. someone reintroducing an ambient
  # or unpinned Go) at the moment the slices are produced, before
  # build_apple_engine_wrappers.sh links them into the wrapper dylibs that
  # get staged into the Xcode project. build_apple_release_candidates.sh
  # also calls this same gate (in begin_receipts), but that call happens
  # before this script runs and cannot see the artifacts this run is about
  # to produce, so it does not substitute for checking here.
  python3 "${PROJECT_ROOT}/tools/verify_embedded_engine_runtime_versions.py" \
    || die "Embedded engine runtime version gate failed for the freshly built Apple Go bridge slices."
}

write_bridge_provenance() {
  local output_tmp
  [[ ! -L "${APPLE_WG_GO_PROVENANCE_FILE}" ]] \
    || die "Apple AWG bridge provenance path must not be symbolic."
  output_tmp="$(mktemp "${APPLE_WG_GO_OUTPUT_DIR}/.apple-awg-31-bridge-provenance.XXXXXX")"
  python3 - "${output_tmp}" "${APPLE_WG_GO_OUTPUT_DIR}" \
    "${AMNEZIAWG_APPLE_REPO}" "${AMNEZIAWG_APPLE_TAG}" \
    "${AMNEZIAWG_APPLE_COMMIT}" "${AMNEZIAWG_APPLE_TREE}" \
    "${AMNEZIAWG_APPLE_GENERATION}" \
    "${AMNEZIAWG_APPLE_GO_MOD_SHA256}" "${AMNEZIAWG_APPLE_GO_SUM_SHA256}" \
    "${REVIEWED_GO_VERSION}" "${REVIEWED_GO_DARWIN_ARM64_SHA256}" \
    "${REVIEWED_GO_DARWIN_AMD64_SHA256}" \
    "${AMNEZIA_XRAY_MODULE}" "${AMNEZIA_XRAY_REPLACED_MODULE}" \
    "${AMNEZIA_XRAY_VERSION}" "${AMNEZIA_XRAY_COMMIT}" \
    "${AMNEZIA_XRAY_SUM}" "${AMNEZIA_XRAY_GO_MOD_SUM}" \
    "${AMNEZIA_XRAY_ZIP_SHA256}" \
    "${AMNEZIAWG_GO_MODULE}" "${AMNEZIAWG_GO_TAG}" \
    "${AMNEZIAWG_GO_COMMIT}" "${AMNEZIAWG_GO_SOURCE_SHA256}" \
    "${AMNEZIAWG_GO_SUM}" "${AMNEZIAWG_GO_MOD_SUM}" \
    "${AMNEZIAWG_GO_MODULE_ZIP_SHA256}" \
    "${AMNEZIA_LIBXRAY_MODULE}" "${AMNEZIA_LIBXRAY_VERSION}" \
    "${AMNEZIA_LIBXRAY_COMMIT}" "${AMNEZIA_LIBXRAY_SUM}" \
    "${AMNEZIA_LIBXRAY_GO_MOD_SUM}" "${AMNEZIA_LIBXRAY_ZIP_SHA256}" \
    "${AMNEZIA_XRAY_REVIEW_MOD_SHA256}" \
    "${AMNEZIA_XRAY_REVIEW_SUM_SHA256}" \
    "${AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256}" \
    "${REVIEWED_GO_DARWIN_ARM64_TREE_SHA256}" \
    "${REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256}" \
    "${REVIEWED_GO_PROXY}" "${REVIEWED_GO_SUMDB}" \
    "${APPLE_WG_GO_SOURCE_DATE_EPOCH}" <<'PY'
import hashlib
import json
import pathlib
import sys

(
    output_path,
    output_root,
    repository,
    tag,
    commit,
    tree,
    generation,
    go_mod_sha256,
    go_sum_sha256,
    go_version,
    go_darwin_arm64_sha256,
    go_darwin_amd64_sha256,
    xray_source_module,
    xray_replaced_module,
    xray_version,
    xray_commit,
    xray_sum,
    xray_go_mod_sum,
    xray_zip_sha256,
    awg_go_module,
    awg_go_tag,
    awg_go_commit,
    awg_go_source_sha256,
    awg_go_sum,
    awg_go_mod_sum,
    awg_go_module_zip_sha256,
    libxray_module,
    libxray_version,
    libxray_commit,
    libxray_sum,
    libxray_go_mod_sum,
    libxray_zip_sha256,
    review_mod_sha256,
    review_sum_sha256,
    patched_vendor_closure_sha256,
    go_darwin_arm64_tree_sha256,
    go_darwin_arm64_executable_sha256,
    go_proxy,
    go_sumdb,
    source_date_epoch,
) = sys.argv[1:]
root = pathlib.Path(output_root)


def artifact(relative, architectures):
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"Apple AWG bridge artifact is missing or symbolic: {path}")
    return {
        "architectures": architectures,
        "path": relative,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


manifest = {
    "archives": {
        "iphoneos": artifact("iphoneos/libwg-go.a", ["arm64"]),
        "iphonesimulator": artifact(
            "iphonesimulator/libwg-go.a", ["arm64", "x86_64"]
        ),
        "macosx": artifact("macosx/libwg-go.a", ["arm64", "x86_64"]),
    },
    "component": "amneziawg-apple",
    "generation": generation,
    "build_contract": {
        "architectures": {
            "iphoneos": ["arm64"],
            "iphonesimulator": ["arm64", "x86_64"],
            "macosx": ["arm64", "x86_64"],
        },
        "double_build_verified": True,
        "go_environment": {
            "goenv": "off",
            "goexperiment": "",
            "goproxy": go_proxy,
            "gosumdb": go_sumdb,
            "gotoolchain": "local",
            "gowork": "off",
        },
        "source_date_epoch": int(source_date_epoch),
    },
    "go_engine": {
        "commit": awg_go_commit,
        "go_mod_sum": awg_go_mod_sum,
        "module": awg_go_module,
        "module_sum": awg_go_sum,
        "module_zip_sha256": awg_go_module_zip_sha256,
        "source_archive_sha256": awg_go_source_sha256,
        "tag": awg_go_tag,
    },
    "go_toolchain": {
        "darwin_amd64_archive_sha256": go_darwin_amd64_sha256,
        "darwin_arm64_archive_sha256": go_darwin_arm64_sha256,
        "version": go_version,
    },
    "libxray": {
        "commit": libxray_commit,
        "go_mod_sum": libxray_go_mod_sum,
        "module": libxray_module,
        "module_sum": libxray_sum,
        "version": libxray_version,
        "zip_sha256": libxray_zip_sha256,
    },
    "module_closure": {
        "patched_vendor_sha256": patched_vendor_closure_sha256,
        "reviewed_mod_sha256": review_mod_sha256,
        "reviewed_sum_sha256": review_sum_sha256,
    },
    "pinned_go_root": {
        "darwin_arm64_executable_sha256": go_darwin_arm64_executable_sha256,
        "darwin_arm64_tree_sha256": go_darwin_arm64_tree_sha256,
    },
    "schema_version": 1,
    "source": {
        "commit": commit,
        "go_mod_sha256": go_mod_sha256,
        "go_sum_sha256": go_sum_sha256,
        "repository": repository,
        "tag": tag,
        "tree": tree,
    },
    "xray_replacement": {
        "commit": xray_commit,
        "go_mod_sum": xray_go_mod_sum,
        "module_sum": xray_sum,
        "replaced_module": xray_replaced_module,
        "source_module": xray_source_module,
        "version": xray_version,
        "zip_sha256": xray_zip_sha256,
    },
}
pathlib.Path(output_path).write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
  chmod 0600 "${output_tmp}"
  mv "${output_tmp}" "${APPLE_WG_GO_PROVENANCE_FILE}"
  printf 'Apple AWG 3.1 bridge provenance: %s (sha256=%s)\n' \
    "${APPLE_WG_GO_PROVENANCE_FILE}" \
    "$(shasum -a 256 "${APPLE_WG_GO_PROVENANCE_FILE}" | awk '{print $1}')"
}

main() {
  require_release_closure
  ensure_tools
  require_absent_path "${APPLE_WG_GO_OUTPUT_DIR}" "Apple AWG output root"
  mkdir -p "$(dirname "${APPLE_WG_GO_OUTPUT_DIR}")"
  mkdir "${APPLE_WG_GO_OUTPUT_DIR}"
  sync_source
  trap cleanup_patch_work_root EXIT
  prepare_hostname_safe_xray_module
  [[ ! -L "${APPLE_WG_GO_PROVENANCE_FILE}" ]] \
    || die "Apple AWG bridge provenance path must not be symbolic."
  install_deterministic_ar
  build_platform macosx
  build_platform iphoneos
  build_platform iphonesimulator
  verify_reviewed_go_root "after build"
  run_embedded_runtime_gate
  write_bridge_provenance
  printf 'Apple Go bridge build complete: %s\n' "${APPLE_WG_GO_OUTPUT_DIR}"
}

reject_hostile_go_environment

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
if [[ "${1:-}" == "--verify-hostname-patch" ]]; then
  require_release_closure
  verify_hostname_patch
  exit 0
fi
if [[ "${1:-}" == "--check-release-go" ]]; then
  # Offline check of the pinned Go handed to this producer: the same
  # measurements prepare_reviewed_go() makes before a build, with no source
  # fetch and no module download.
  prepare_reviewed_go
  printf 'APPLE AWG PINNED RELEASE GO: PASS (%s)\n' "${WINS_RELEASE_GO_ROOT}"
  exit 0
fi
if [[ "${1:-}" == "--preflight" ]]; then
  require_release_closure
  printf 'Apple AWG release closure pins verified.\n'
  exit 0
fi

main "$@"
