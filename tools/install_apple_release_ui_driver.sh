#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DRIVER_SOURCE="${ROOT}/tools/apple_release_ui_driver.py"
OBSERVER_SOURCE="${ROOT}/tools/apple_map_semantic_observer.swift"
ROUTE_CONTROLLER_SOURCE="${ROOT}/tools/android_remote_route_control.py"
INSTALL_ROOT="/usr/local/libexec"
DRIVER_TARGET="${INSTALL_ROOT}/winsvpn-apple-release-ui-driver.py"
OBSERVER_TARGET="${INSTALL_ROOT}/winsvpn-apple-map-observer"
ROUTE_CONTROLLER_TARGET="${INSTALL_ROOT}/winsvpn-apple-route-controller.py"
MANIFEST_TARGET="${INSTALL_ROOT}/winsvpn-apple-release-tools.json"

[[ "$(uname -s)" == "Darwin" ]] || { printf 'Apple driver installation requires macOS.\n' >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || { printf 'Apple driver installation must run as root.\n' >&2; exit 1; }
for source in "${DRIVER_SOURCE}" "${OBSERVER_SOURCE}" "${ROUTE_CONTROLLER_SOURCE}"; do
  [[ -f "${source}" && ! -L "${source}" ]] || { printf 'Unsafe/missing Apple driver source: %s\n' "${source}" >&2; exit 1; }
done
command -v xcrun >/dev/null
command -v python3 >/dev/null

umask 077
install -d -o root -g wheel -m 0755 "${INSTALL_ROOT}"
tmpdir="$(mktemp -d /private/tmp/wins-apple-driver.XXXXXX)"
trap 'rm -rf "${tmpdir}"' EXIT
xcrun swiftc -O \
  -framework AppKit -framework Vision -framework NaturalLanguage \
  "${OBSERVER_SOURCE}" -o "${tmpdir}/winsvpn-apple-map-observer"
if "${tmpdir}/winsvpn-apple-map-observer" >/dev/null 2>&1; then
  printf 'Map observer unexpectedly accepted a missing screenshot argument.\n' >&2
  exit 1
fi
python3 "${DRIVER_SOURCE}" self_test
python3 "${ROUTE_CONTROLLER_SOURCE}" self-test

install -o root -g wheel -m 0755 "${DRIVER_SOURCE}" "${DRIVER_TARGET}"
install -o root -g wheel -m 0755 "${tmpdir}/winsvpn-apple-map-observer" "${OBSERVER_TARGET}"
install -o root -g wheel -m 0755 "${ROUTE_CONTROLLER_SOURCE}" "${ROUTE_CONTROLLER_TARGET}"
python3 - "${DRIVER_SOURCE}" "${DRIVER_TARGET}" "${OBSERVER_SOURCE}" "${OBSERVER_TARGET}" "${ROUTE_CONTROLLER_SOURCE}" "${ROUTE_CONTROLLER_TARGET}" "${tmpdir}/manifest.json" <<'PY'
import hashlib, json, pathlib, sys
def digest(value): return hashlib.sha256(pathlib.Path(value).read_bytes()).hexdigest()
payload = {
  "schema_version": 1,
  "contract": "winsvpn-apple-release-tools-v1",
  "driver_source_sha256": digest(sys.argv[1]),
  "driver_installed_sha256": digest(sys.argv[2]),
  "map_observer_source_sha256": digest(sys.argv[3]),
  "map_observer_installed_sha256": digest(sys.argv[4]),
  "route_controller_source_sha256": digest(sys.argv[5]),
  "route_controller_installed_sha256": digest(sys.argv[6]),
  "secret_material_redacted": True,
}
pathlib.Path(sys.argv[7]).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
PY
install -o root -g wheel -m 0600 "${tmpdir}/manifest.json" "${MANIFEST_TARGET}"
"${DRIVER_TARGET}" self_test
"${ROUTE_CONTROLLER_TARGET}" self-test
printf 'Apple release UI driver installed with exact source binding.\n'
