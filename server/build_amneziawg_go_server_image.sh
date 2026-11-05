#!/usr/bin/env bash
# Build and verify the local AmneziaWG server image from immutable upstream
# source. The deployment scripts deliberately never pull this image name.
set -Eeuo pipefail
umask 077

AWG_GO_REPOSITORY="https://github.com/amnezia-vpn/amneziawg-go"
AWG_GO_TAG="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
AWG_GO_SOURCE_DATE_EPOCH="1787932107"
AWG_GO_BINARY_SHA256_AMD64="21c06c4d72decfe645c4042da78bf28401fb129939087c5f587492de08dc6584"
AWG_GO_BINARY_SHA256_ARM64="5afa5276170d71e46c485fe02717b7ebe57ff6adf00630ceccefb70eb2bd67d1"

AWG_TOOLS_REPOSITORY="https://github.com/amnezia-vpn/amneziawg-tools"
AWG_TOOLS_TAG="v3.1.20260812"
AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
AWG_TOOLS_SOURCE_SHA256="dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
AWG_TOOLS_SOURCE_DATE_EPOCH="1786573489"
AWG_QUICK_SHA256="f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"

GO_VERSION="1.27.1"
GO_ARCHIVE_SHA256_AMD64="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"
GO_ARCHIVE_SHA256_ARM64="3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec"
GO_MODULE_PROXY="https://proxy.golang.org"
GO_MODULE_SUMDB="sum.golang.org"

# Alpine 3.24.2 is frozen by per-platform manifest digest. There is no mutable
# tag in the Dockerfile that the producer emits.
ALPINE_VERSION="3.24.2"
ALPINE_BASE_DIGEST_AMD64="sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395"
ALPINE_BASE_DIGEST_ARM64="sha256:260479a1cfaf304c4c20da7f8405d3ce313513dcd534bb743257bdd2fe0f3e2d"
ALPINE_REPOSITORY="https://dl-cdn.alpinelinux.org/alpine/v3.24/main"
ALPINE_BUILD_BASE_VERSION="0.5-r4"
ALPINE_LINUX_HEADERS_VERSION="7.0.0-r1"
ALPINE_BASH_VERSION="5.3.9-r1"
ALPINE_IPROUTE2_VERSION="7.0.0-r0"
ALPINE_IPTABLES_VERSION="1.8.13-r0"

AWG_SERVER_IMAGE="amneziavpn/amneziawg-go:v3.1.20260828"
AWG_IMAGE_PROVENANCE_DIR="${AWG_IMAGE_PROVENANCE_DIR:-/var/lib/winsvpn/awg-server-image}"
AWG_IMAGE_PROVENANCE_FILE="${AWG_IMAGE_PROVENANCE_DIR}/provenance.json"

log() { printf '[AWG-IMAGE] %s\n' "$*" >&2; }
die() { printf '[AWG-IMAGE][ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: build_amneziawg_go_server_image.sh [--ensure|--build|--verify|--print-pins]

  --ensure      verify the exact local image or rebuild it from pinned source
  --build       always rebuild, verify, and atomically replace provenance
  --verify      verify the local image and its provenance without network use
  --print-pins  print the immutable producer inputs without Docker or network
EOF
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *) die "Only linux/amd64 and linux/arm64 are supported; found $(uname -m)." ;;
  esac
}

require_linux_host() {
  [[ "$(uname -s)" == "Linux" ]] || die "The server image must be built or verified on Linux."
}

go_archive_sha256() {
  case "$1" in
    amd64) printf '%s\n' "${GO_ARCHIVE_SHA256_AMD64}" ;;
    arm64) printf '%s\n' "${GO_ARCHIVE_SHA256_ARM64}" ;;
    *) return 1 ;;
  esac
}

awg_go_binary_sha256() {
  case "$1" in
    amd64) printf '%s\n' "${AWG_GO_BINARY_SHA256_AMD64}" ;;
    arm64) printf '%s\n' "${AWG_GO_BINARY_SHA256_ARM64}" ;;
    *) return 1 ;;
  esac
}

alpine_base_digest() {
  case "$1" in
    amd64) printf '%s\n' "${ALPINE_BASE_DIGEST_AMD64}" ;;
    arm64) printf '%s\n' "${ALPINE_BASE_DIGEST_ARM64}" ;;
    *) return 1 ;;
  esac
}

print_pins() {
  cat <<EOF
AWG_SERVER_IMAGE=${AWG_SERVER_IMAGE}
AWG_GO_REPOSITORY=${AWG_GO_REPOSITORY}
AWG_GO_TAG=${AWG_GO_TAG}
AWG_GO_COMMIT=${AWG_GO_COMMIT}
AWG_GO_SOURCE_SHA256=${AWG_GO_SOURCE_SHA256}
AWG_GO_BINARY_SHA256_AMD64=${AWG_GO_BINARY_SHA256_AMD64}
AWG_GO_BINARY_SHA256_ARM64=${AWG_GO_BINARY_SHA256_ARM64}
AWG_TOOLS_REPOSITORY=${AWG_TOOLS_REPOSITORY}
AWG_TOOLS_TAG=${AWG_TOOLS_TAG}
AWG_TOOLS_COMMIT=${AWG_TOOLS_COMMIT}
AWG_TOOLS_SOURCE_SHA256=${AWG_TOOLS_SOURCE_SHA256}
AWG_QUICK_SHA256=${AWG_QUICK_SHA256}
GO_VERSION=${GO_VERSION}
GO_ARCHIVE_SHA256_AMD64=${GO_ARCHIVE_SHA256_AMD64}
GO_ARCHIVE_SHA256_ARM64=${GO_ARCHIVE_SHA256_ARM64}
GOPROXY=${GO_MODULE_PROXY}
GOSUMDB=${GO_MODULE_SUMDB}
GOPRIVATE=
GONOPROXY=
GONOSUMDB=
ALPINE_VERSION=${ALPINE_VERSION}
ALPINE_BASE_DIGEST_AMD64=${ALPINE_BASE_DIGEST_AMD64}
ALPINE_BASE_DIGEST_ARM64=${ALPINE_BASE_DIGEST_ARM64}
ALPINE_BUILD_BASE_VERSION=${ALPINE_BUILD_BASE_VERSION}
ALPINE_LINUX_HEADERS_VERSION=${ALPINE_LINUX_HEADERS_VERSION}
ALPINE_BASH_VERSION=${ALPINE_BASH_VERSION}
ALPINE_IPROUTE2_VERSION=${ALPINE_IPROUTE2_VERSION}
ALPINE_IPTABLES_VERSION=${ALPINE_IPTABLES_VERSION}
EOF
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "${command_name}" >/dev/null 2>&1 || die "Required command not found: ${command_name}"
  done
}

download_exact() {
  local url="$1" destination="$2" expected_sha256="$3" actual_sha256
  curl --proto '=https' --tlsv1.2 -fsSL --retry 4 --retry-all-errors \
    "${url}" -o "${destination}"
  actual_sha256="$(sha256_file "${destination}")"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] || \
    die "SHA-256 mismatch for ${url}: expected ${expected_sha256}, found ${actual_sha256}."
}

image_label() {
  local key="$1"
  docker image inspect --format "{{ index .Config.Labels \"${key}\" }}" "${AWG_SERVER_IMAGE}"
}

verify_image_labels() {
  local arch="$1" expected_go_binary_sha256="$2" expected_base_digest="$3"
  local image_id image_arch image_os
  image_id="$(docker image inspect --format '{{.Id}}' "${AWG_SERVER_IMAGE}")" || return 1
  image_arch="$(docker image inspect --format '{{.Architecture}}' "${AWG_SERVER_IMAGE}")" || return 1
  image_os="$(docker image inspect --format '{{.Os}}' "${AWG_SERVER_IMAGE}")" || return 1
  [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [[ "${image_arch}" == "${arch}" && "${image_os}" == "linux" ]] || return 1
  [[ "$(image_label org.opencontainers.image.source)" == "${AWG_GO_REPOSITORY}" ]] || return 1
  [[ "$(image_label org.opencontainers.image.version)" == "${AWG_GO_TAG}" ]] || return 1
  [[ "$(image_label org.opencontainers.image.revision)" == "${AWG_GO_COMMIT}" ]] || return 1
  [[ "$(image_label org.opencontainers.image.created)" == "2026-08-28T15:48:27Z" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.source.sha256)" == "${AWG_GO_SOURCE_SHA256}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.binary.sha256)" == "${expected_go_binary_sha256}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.tools.tag)" == "${AWG_TOOLS_TAG}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.tools.commit)" == "${AWG_TOOLS_COMMIT}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.tools.source.sha256)" == "${AWG_TOOLS_SOURCE_SHA256}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.go.version)" == "${GO_VERSION}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.go.archive.sha256)" == "$(go_archive_sha256 "${arch}")" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.go.goproxy)" == "${GO_MODULE_PROXY}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.go.gosumdb)" == "${GO_MODULE_SUMDB}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.base.digest)" == "${expected_base_digest}" ]] || return 1
  [[ "$(image_label com.winsvpn.awg.arch)" == "${arch}" ]] || return 1
}

runtime_hash() {
  local path="$1"
  docker run --rm --pull=never --network none --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only --pids-limit 32 --memory 64m \
    --entrypoint /usr/bin/sha256sum "${AWG_SERVER_IMAGE}" "${path}" | awk '{print $1}'
}

verify_image_runtime() {
  local arch="$1" expected_go_binary_sha256="$2"
  [[ "$(runtime_hash /usr/bin/amneziawg-go)" == "${expected_go_binary_sha256}" ]] || return 1
  [[ "$(runtime_hash /usr/bin/awg-quick)" == "${AWG_QUICK_SHA256}" ]] || return 1
  docker run --rm --pull=never --network none --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only --pids-limit 32 --memory 64m \
    --entrypoint /bin/sh "${AWG_SERVER_IMAGE}" -ec '
      test "$(/usr/bin/amneziawg-go --version | sed -n "1p")" = "amneziawg-go v3.1.20260828"
      test "$(/usr/bin/awg --version)" = "amneziawg-tools v3.1.20260812 - https://amnezia.org"
      test "$(readlink /usr/bin/wg)" = "/usr/bin/awg"
      test "$(readlink /usr/bin/wg-quick)" = "/usr/bin/awg-quick"
      command -v bash ip iptables >/dev/null
    ' || return 1
  [[ "$(image_label com.winsvpn.awg.arch)" == "${arch}" ]] || return 1
}

verify_receipt() {
  local arch="$1" image_id="$2" go_binary_sha256="$3" tools_binary_sha256="$4" base_digest="$5"
  [[ -f "${AWG_IMAGE_PROVENANCE_FILE}" && ! -L "${AWG_IMAGE_PROVENANCE_FILE}" ]] || return 1
  python3 - "${AWG_IMAGE_PROVENANCE_FILE}" "${AWG_SERVER_IMAGE}" "${image_id}" \
    "${arch}" "${go_binary_sha256}" "${tools_binary_sha256}" "${base_digest}" \
    "${AWG_GO_TAG}" "${AWG_GO_COMMIT}" "${AWG_GO_SOURCE_SHA256}" \
    "${AWG_TOOLS_TAG}" "${AWG_TOOLS_COMMIT}" "${AWG_TOOLS_SOURCE_SHA256}" \
    "${GO_VERSION}" "$(go_archive_sha256 "${arch}")" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "schema": 1,
    "image": sys.argv[2],
    "local_image_id": sys.argv[3],
    "architecture": sys.argv[4],
    "amneziawg_go_binary_sha256": sys.argv[5],
    "amneziawg_tools_binary_sha256": sys.argv[6],
    "base_image_digest": sys.argv[7],
    "amneziawg_go_tag": sys.argv[8],
    "amneziawg_go_commit": sys.argv[9],
    "amneziawg_go_source_sha256": sys.argv[10],
    "amneziawg_tools_tag": sys.argv[11],
    "amneziawg_tools_commit": sys.argv[12],
    "amneziawg_tools_source_sha256": sys.argv[13],
    "go_version": sys.argv[14],
    "go_archive_sha256": sys.argv[15],
    "goproxy": "https://proxy.golang.org",
    "gosumdb": "sum.golang.org",
    "goprivate": "",
    "gonoproxy": "",
    "gonosumdb": "",
}
if data != expected:
    raise SystemExit("provenance receipt does not match the verified local image")
PY
}

write_receipt() {
  local arch="$1" image_id="$2" go_binary_sha256="$3" tools_binary_sha256="$4" base_digest="$5"
  local receipt_tmp
  install -d -m 0755 "${AWG_IMAGE_PROVENANCE_DIR}"
  receipt_tmp="$(mktemp "${AWG_IMAGE_PROVENANCE_DIR}/.provenance.XXXXXX")"
  python3 - "${receipt_tmp}" "${AWG_SERVER_IMAGE}" "${image_id}" "${arch}" \
    "${go_binary_sha256}" "${tools_binary_sha256}" "${base_digest}" \
    "${AWG_GO_TAG}" "${AWG_GO_COMMIT}" "${AWG_GO_SOURCE_SHA256}" \
    "${AWG_TOOLS_TAG}" "${AWG_TOOLS_COMMIT}" "${AWG_TOOLS_SOURCE_SHA256}" \
    "${GO_VERSION}" "$(go_archive_sha256 "${arch}")" <<'PY'
import json
import pathlib
import sys

receipt = {
    "schema": 1,
    "image": sys.argv[2],
    "local_image_id": sys.argv[3],
    "architecture": sys.argv[4],
    "amneziawg_go_binary_sha256": sys.argv[5],
    "amneziawg_tools_binary_sha256": sys.argv[6],
    "base_image_digest": sys.argv[7],
    "amneziawg_go_tag": sys.argv[8],
    "amneziawg_go_commit": sys.argv[9],
    "amneziawg_go_source_sha256": sys.argv[10],
    "amneziawg_tools_tag": sys.argv[11],
    "amneziawg_tools_commit": sys.argv[12],
    "amneziawg_tools_source_sha256": sys.argv[13],
    "go_version": sys.argv[14],
    "go_archive_sha256": sys.argv[15],
    "goproxy": "https://proxy.golang.org",
    "gosumdb": "sum.golang.org",
    "goprivate": "",
    "gonoproxy": "",
    "gonosumdb": "",
}
pathlib.Path(sys.argv[1]).write_text(
    json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
  chmod 0644 "${receipt_tmp}"
  mv -f "${receipt_tmp}" "${AWG_IMAGE_PROVENANCE_FILE}"
}

verify_all() (
  local arch go_binary_sha256 base_digest image_id tools_binary_sha256
  require_linux_host
  require_commands docker python3 sha256sum
  arch="$(host_arch)"
  go_binary_sha256="$(awg_go_binary_sha256 "${arch}")"
  base_digest="$(alpine_base_digest "${arch}")"
  verify_image_labels "${arch}" "${go_binary_sha256}" "${base_digest}" || \
    die "Local image labels or architecture do not match the frozen producer."
  verify_image_runtime "${arch}" "${go_binary_sha256}" || \
    die "Local image runtime binaries do not match the frozen producer."
  image_id="$(docker image inspect --format '{{.Id}}' "${AWG_SERVER_IMAGE}")"
  tools_binary_sha256="$(runtime_hash /usr/bin/awg)"
  verify_receipt "${arch}" "${image_id}" "${go_binary_sha256}" \
    "${tools_binary_sha256}" "${base_digest}" || \
    die "Local image provenance receipt is missing or inconsistent."
  printf '%s\n' "${AWG_SERVER_IMAGE}"
)

build_image() (
  local arch go_archive_sha256 go_binary_sha256 base_digest
  local work_root go_archive go_source_archive tools_source_archive source_dir
  local go_binary tools_binary_sha256 image_id
  # stdout carries only the image name; the callers compare it exactly, so
  # every build tool (go mod verify, docker build) writes to stderr instead.
  exec 3>&1 1>&2
  require_linux_host
  require_commands curl docker python3 sed sha256sum tar
  arch="$(host_arch)"
  go_archive_sha256="$(go_archive_sha256 "${arch}")"
  go_binary_sha256="$(awg_go_binary_sha256 "${arch}")"
  base_digest="$(alpine_base_digest "${arch}")"

  work_root="$(mktemp -d "${TMPDIR:-/tmp}/wins-awg-server-image.XXXXXX")"
  # Invoked by the EXIT trap below.
  # shellcheck disable=SC2329
  cleanup_awg_image_build() {
    case "${work_root}" in
      "${TMPDIR:-/tmp}"/wins-awg-server-image.*)
        chmod -R u+w "${work_root}" 2>/dev/null || true
        rm -rf -- "${work_root}"
        ;;
      *) log "Refusing to remove unexpected build root ${work_root}." ;;
    esac
  }
  trap cleanup_awg_image_build EXIT

  go_archive="${work_root}/go${GO_VERSION}.linux-${arch}.tar.gz"
  go_source_archive="${work_root}/amneziawg-go-${AWG_GO_COMMIT}.tar.gz"
  tools_source_archive="${work_root}/amneziawg-tools-${AWG_TOOLS_TAG}.tar.gz"
  download_exact "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
    "${go_archive}" "${go_archive_sha256}"
  download_exact "${AWG_GO_REPOSITORY}/archive/${AWG_GO_COMMIT}.tar.gz" \
    "${go_source_archive}" "${AWG_GO_SOURCE_SHA256}"
  download_exact "${AWG_TOOLS_REPOSITORY}/archive/refs/tags/${AWG_TOOLS_TAG}.tar.gz" \
    "${tools_source_archive}" "${AWG_TOOLS_SOURCE_SHA256}"

  mkdir -p "${work_root}/go-sdk" "${work_root}/source" "${work_root}/tools-check"
  tar -xzf "${go_archive}" -C "${work_root}/go-sdk"
  tar -xzf "${go_source_archive}" -C "${work_root}/source"
  tar -xzf "${tools_source_archive}" -C "${work_root}/tools-check"
  source_dir="${work_root}/source/amneziawg-go-${AWG_GO_COMMIT}"
  [[ -f "${source_dir}/go.mod" && -f "${source_dir}/go.sum" ]] || \
    die "Pinned AmneziaWG Go archive has an unexpected layout."
  grep -Fxq 'module github.com/amnezia-vpn/amneziawg-go/v3' "${source_dir}/go.mod" || \
    die "Pinned AmneziaWG Go module identity changed."
  grep -Fxq 'go 1.25.0' "${source_dir}/go.mod" || \
    die "Pinned AmneziaWG Go language version changed."
  grep -Fxq 'const Version = "0.0.20250522"' "${source_dir}/version.go" || \
    die "Pinned source version constant changed; refusing an unreviewed patch."
  sed -i 's/const Version = "0.0.20250522"/const Version = "v3.1.20260828"/' \
    "${source_dir}/version.go"
  grep -Fxq 'const Version = "v3.1.20260828"' "${source_dir}/version.go" || \
    die "Could not freeze the runtime version to ${AWG_GO_TAG}."
  grep -Fxq '#define WIREGUARD_TOOLS_VERSION "3.1.20260812"' \
    "${work_root}/tools-check/amneziawg-tools-${AWG_TOOLS_TAG#v}/src/version.h" || \
    die "Pinned AmneziaWG tools version changed."
  [[ "$(sha256_file "${work_root}/tools-check/amneziawg-tools-${AWG_TOOLS_TAG#v}/src/wg-quick/linux.bash")" == "${AWG_QUICK_SHA256}" ]] || \
    die "Pinned awg-quick source hash changed."

  [[ "$("${work_root}/go-sdk/go/bin/go" version)" == "go version go${GO_VERSION} linux/${arch}" ]] || \
    die "Pinned Go archive reports an unexpected version or architecture."
  export GOENV=off GOTOOLCHAIN=local
  export GOPROXY="${GO_MODULE_PROXY}" GOSUMDB="${GO_MODULE_SUMDB}"
  export GOPRIVATE="" GONOPROXY="" GONOSUMDB=""
  export GOMODCACHE="${work_root}/go-mod-cache" GOCACHE="${work_root}/go-build-cache"
  export CGO_ENABLED=0 GOOS=linux GOARCH="${arch}"
  export SOURCE_DATE_EPOCH="${AWG_GO_SOURCE_DATE_EPOCH}"
  if [[ "${arch}" == "amd64" ]]; then export GOAMD64=v1; else unset GOAMD64; fi
  (
    cd "${source_dir}"
    "${work_root}/go-sdk/go/bin/go" mod download
    "${work_root}/go-sdk/go/bin/go" mod verify
    "${work_root}/go-sdk/go/bin/go" build -mod=readonly -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' -o "${work_root}/amneziawg-go" .
  )
  go_binary="${work_root}/amneziawg-go"
  [[ "$(sha256_file "${go_binary}")" == "${go_binary_sha256}" ]] || \
    die "Reproducible AmneziaWG Go binary hash mismatch for ${arch}: expected ${go_binary_sha256}, found $(sha256_file "${go_binary}")."
  "${work_root}/go-sdk/go/bin/go" version -m "${go_binary}" | \
    grep -Fxq $'\tpath\tgithub.com/amnezia-vpn/amneziawg-go/v3' || \
    die "Built binary does not contain the expected module identity."

  cp "${tools_source_archive}" "${work_root}/amneziawg-tools.tar.gz"
  cat > "${work_root}/Dockerfile" <<'DOCKERFILE'
ARG ALPINE_BASE=alpine@sha256:260479a1cfaf304c4c20da7f8405d3ce313513dcd534bb743257bdd2fe0f3e2d
FROM ${ALPINE_BASE} AS tools
ARG ALPINE_REPOSITORY
ARG BUILD_BASE_VERSION
ARG LINUX_HEADERS_VERSION
ARG AWG_TOOLS_SOURCE_SHA256
ARG AWG_TOOLS_SOURCE_DATE_EPOCH
RUN printf '%s\n' "${ALPINE_REPOSITORY}" > /etc/apk/repositories && \
    apk add --no-cache \
      "build-base=${BUILD_BASE_VERSION}" \
      "linux-headers=${LINUX_HEADERS_VERSION}"
COPY amneziawg-tools.tar.gz /tmp/amneziawg-tools.tar.gz
RUN printf '%s  %s\n' "${AWG_TOOLS_SOURCE_SHA256}" /tmp/amneziawg-tools.tar.gz | sha256sum -c - && \
    mkdir -p /build/one /build/two /out && \
    tar -xzf /tmp/amneziawg-tools.tar.gz -C /build/one --strip-components=1 && \
    tar -xzf /tmp/amneziawg-tools.tar.gz -C /build/two --strip-components=1 && \
    for pass in one two; do \
      cd "/build/${pass}/src"; \
      export SOURCE_DATE_EPOCH="${AWG_TOOLS_SOURCE_DATE_EPOCH}"; \
      export CFLAGS="-O3 -ffile-prefix-map=/build/${pass}=. -fno-ident -g0 -fPIE"; \
      export LDFLAGS='-pie -Wl,--build-id=none -Wl,-z,relro,-z,now'; \
      make PLATFORM=linux WITH_WGQUICK=no WITH_BASHCOMPLETION=no WITH_SYSTEMDUNITS=no; \
    done && \
    cmp /build/one/src/wg /build/two/src/wg && \
    cmp /build/one/src/wg-quick/linux.bash /build/two/src/wg-quick/linux.bash && \
    install -m 0755 /build/one/src/wg /out/awg && \
    install -m 0755 /build/one/src/wg-quick/linux.bash /out/awg-quick && \
    test "$(/out/awg --version)" = 'amneziawg-tools v3.1.20260812 - https://amnezia.org'

ARG ALPINE_BASE
FROM ${ALPINE_BASE}
ARG ALPINE_REPOSITORY
ARG BASH_VERSION
ARG IPROUTE2_VERSION
ARG IPTABLES_VERSION
ARG AWG_GO_REPOSITORY
ARG AWG_GO_TAG
ARG AWG_GO_COMMIT
ARG AWG_GO_SOURCE_SHA256
ARG AWG_GO_BINARY_SHA256
ARG AWG_TOOLS_TAG
ARG AWG_TOOLS_COMMIT
ARG AWG_TOOLS_SOURCE_SHA256
ARG GO_VERSION
ARG GO_ARCHIVE_SHA256
ARG GO_MODULE_PROXY
ARG GO_MODULE_SUMDB
ARG BASE_DIGEST
ARG TARGET_ARCH
RUN printf '%s\n' "${ALPINE_REPOSITORY}" > /etc/apk/repositories && \
    apk add --no-cache \
      "bash=${BASH_VERSION}" \
      "iproute2=${IPROUTE2_VERSION}" \
      "iptables=${IPTABLES_VERSION}"
COPY amneziawg-go /usr/bin/amneziawg-go
COPY --from=tools /out/awg /usr/bin/awg
COPY --from=tools /out/awg-quick /usr/bin/awg-quick
RUN chmod 0755 /usr/bin/amneziawg-go /usr/bin/awg /usr/bin/awg-quick && \
    ln -s /usr/bin/awg /usr/bin/wg && \
    ln -s /usr/bin/awg-quick /usr/bin/wg-quick && \
    test "$(/usr/bin/amneziawg-go --version | sed -n '1p')" = "amneziawg-go ${AWG_GO_TAG}" && \
    test "$(/usr/bin/awg --version)" = 'amneziawg-tools v3.1.20260812 - https://amnezia.org'
LABEL org.opencontainers.image.source="${AWG_GO_REPOSITORY}" \
      org.opencontainers.image.version="${AWG_GO_TAG}" \
      org.opencontainers.image.revision="${AWG_GO_COMMIT}" \
      org.opencontainers.image.created="2026-08-28T15:48:27Z" \
      com.winsvpn.awg.source.sha256="${AWG_GO_SOURCE_SHA256}" \
      com.winsvpn.awg.binary.sha256="${AWG_GO_BINARY_SHA256}" \
      com.winsvpn.awg.tools.tag="${AWG_TOOLS_TAG}" \
      com.winsvpn.awg.tools.commit="${AWG_TOOLS_COMMIT}" \
      com.winsvpn.awg.tools.source.sha256="${AWG_TOOLS_SOURCE_SHA256}" \
      com.winsvpn.awg.go.version="${GO_VERSION}" \
      com.winsvpn.awg.go.archive.sha256="${GO_ARCHIVE_SHA256}" \
      com.winsvpn.awg.go.goproxy="${GO_MODULE_PROXY}" \
      com.winsvpn.awg.go.gosumdb="${GO_MODULE_SUMDB}" \
      com.winsvpn.awg.base.digest="${BASE_DIGEST}" \
      com.winsvpn.awg.arch="${TARGET_ARCH}"
DOCKERFILE

  log "Building ${AWG_SERVER_IMAGE} for linux/${arch} from verified source."
  docker build --pull=false --no-cache --network default \
    --build-arg "ALPINE_BASE=alpine@${base_digest}" \
    --build-arg "ALPINE_REPOSITORY=${ALPINE_REPOSITORY}" \
    --build-arg "BUILD_BASE_VERSION=${ALPINE_BUILD_BASE_VERSION}" \
    --build-arg "LINUX_HEADERS_VERSION=${ALPINE_LINUX_HEADERS_VERSION}" \
    --build-arg "BASH_VERSION=${ALPINE_BASH_VERSION}" \
    --build-arg "IPROUTE2_VERSION=${ALPINE_IPROUTE2_VERSION}" \
    --build-arg "IPTABLES_VERSION=${ALPINE_IPTABLES_VERSION}" \
    --build-arg "AWG_GO_REPOSITORY=${AWG_GO_REPOSITORY}" \
    --build-arg "AWG_GO_TAG=${AWG_GO_TAG}" \
    --build-arg "AWG_GO_COMMIT=${AWG_GO_COMMIT}" \
    --build-arg "AWG_GO_SOURCE_SHA256=${AWG_GO_SOURCE_SHA256}" \
    --build-arg "AWG_GO_BINARY_SHA256=${go_binary_sha256}" \
    --build-arg "AWG_TOOLS_TAG=${AWG_TOOLS_TAG}" \
    --build-arg "AWG_TOOLS_COMMIT=${AWG_TOOLS_COMMIT}" \
    --build-arg "AWG_TOOLS_SOURCE_SHA256=${AWG_TOOLS_SOURCE_SHA256}" \
    --build-arg "AWG_TOOLS_SOURCE_DATE_EPOCH=${AWG_TOOLS_SOURCE_DATE_EPOCH}" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "GO_ARCHIVE_SHA256=${go_archive_sha256}" \
    --build-arg "GO_MODULE_PROXY=${GO_MODULE_PROXY}" \
    --build-arg "GO_MODULE_SUMDB=${GO_MODULE_SUMDB}" \
    --build-arg "BASE_DIGEST=${base_digest}" \
    --build-arg "TARGET_ARCH=${arch}" \
    --tag "${AWG_SERVER_IMAGE}" \
    --file "${work_root}/Dockerfile" "${work_root}"

  verify_image_labels "${arch}" "${go_binary_sha256}" "${base_digest}" || \
    die "Fresh image labels or architecture failed verification."
  verify_image_runtime "${arch}" "${go_binary_sha256}" || \
    die "Fresh image runtime failed verification."
  image_id="$(docker image inspect --format '{{.Id}}' "${AWG_SERVER_IMAGE}")"
  tools_binary_sha256="$(runtime_hash /usr/bin/awg)"
  write_receipt "${arch}" "${image_id}" "${go_binary_sha256}" \
    "${tools_binary_sha256}" "${base_digest}"
  verify_receipt "${arch}" "${image_id}" "${go_binary_sha256}" \
    "${tools_binary_sha256}" "${base_digest}" || \
    die "Fresh image provenance receipt failed verification."
  log "Verified local image ${image_id}; provenance: ${AWG_IMAGE_PROVENANCE_FILE}"
  printf '%s\n' "${AWG_SERVER_IMAGE}" >&3
)

main() {
  local mode="ensure"
  [[ $# -le 1 ]] || { usage >&2; return 2; }
  case "${1:---ensure}" in
    --ensure) mode="ensure" ;;
    --build) mode="build" ;;
    --verify) mode="verify" ;;
    --print-pins) print_pins; return 0 ;;
    --help|-h) usage; return 0 ;;
    *) usage >&2; return 2 ;;
  esac
  case "${mode}" in
    verify) verify_all ;;
    build) build_image ;;
    ensure)
      if verify_all >/dev/null 2>&1; then
        printf '%s\n' "${AWG_SERVER_IMAGE}"
      else
        log "No verified local image and receipt were found; rebuilding."
        build_image
      fi
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
