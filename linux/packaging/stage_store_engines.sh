#!/usr/bin/env bash
# Stage architecture-bound AWG, Xray, and Winn v3 datapath payloads for Linux
# Snap/Flatpak recipes. Flutter's linux bundle does not produce these files;
# calling this helper is the only store-recipe engine source.
set -Eeuo pipefail

DEST="${1:-}"
ARCH="${2:-}"
[[ -n "${DEST}" && -n "${ARCH}" ]] || {
  echo "Usage: linux/packaging/stage_store_engines.sh <dest-dir> <x64|arm64>" >&2
  exit 64
}
case "${ARCH}" in
  x64|arm64) ;;
  *)
    echo "Usage: linux/packaging/stage_store_engines.sh <dest-dir> <x64|arm64>" >&2
    exit 64
    ;;
esac
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"

refuse_bundle_dest() {
  local candidate="$1"
  case "${candidate}" in
    */build/linux/*/release/bundle|*/build/linux/*/release/bundle/|*/build/linux/*/release/bundle/*)
      echo "refusing to stage store engines into a Flutter linux bundle." >&2
      exit 65
      ;;
  esac
}

if [[ -L "${DEST}" ]]; then
  echo "refusing symlink engine destination: ${DEST}" >&2
  exit 65
fi
refuse_bundle_dest "${DEST}"
if [[ -e "${DEST}" ]]; then
  [[ -d "${DEST}" && ! -L "${DEST}" ]] || {
    echo "refusing symlink engine destination: ${DEST}" >&2
    exit 65
  }
fi
mkdir -p -- "${DEST}"
[[ -d "${DEST}" && ! -L "${DEST}" ]] || {
  echo "refusing symlink engine destination: ${DEST}" >&2
  exit 65
}
DEST_ABS="$(cd -- "${DEST}" && pwd -P)"
refuse_bundle_dest "${DEST_ABS}"
[[ ! -L "${DEST_ABS}" ]] || {
  echo "refusing symlink engine destination: ${DEST_ABS}" >&2
  exit 65
}

exec /bin/bash "${ROOT}/tools/build_linux_release.sh" --stage-engines "${DEST_ABS}" "${ARCH}"
