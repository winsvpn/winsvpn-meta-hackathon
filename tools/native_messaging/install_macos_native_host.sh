#!/usr/bin/env bash
# macOS-only native-messaging host install, registration, rollback, and uninstall.
#
# The compiled host is installed OUTSIDE the sandboxed app, at the exact path
# named in the generated Chrome/Edge/Firefox manifests. Mac App Store packaging
# cannot deliver this host: see apple_cross_store_artifact_gate.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HOST_NAME="org.winsvpn.bridge"
LAYOUT="${SCRIPT_DIR}/native_host_layout.py"
GATE="${SCRIPT_DIR}/../apple_cross_store_artifact_gate.py"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
SYSTEM=0
UNINSTALL=0
REMOVE_HOST=0
REQUIRE_SIGNATURE=0
HOST_PATH=""
DEST_DIR=""
FIREFOX_MANIFEST_DIR=""
CHROME_MANIFEST_DIR=""
EDGE_MANIFEST_DIR=""
ROLLBACK_DIR=""
INSTALLED_HOST=""
FIREFOX_TARGET=""
CHROME_TARGET=""
EDGE_TARGET=""
HOME_CANON=""
CHROME_BLOCKED=0
CHROME_BLOCK_REASON=""
EDGE_BLOCKED=0
EDGE_BLOCK_REASON=""
RESTORE_FAILED=0
HOST_PREVIOUS=""

usage() {
  cat >&2 <<'USAGE'
usage: install_macos_native_host.sh [--system] [--host-path PATH] [--dest-dir PATH]
                                    [--firefox-manifest-dir PATH]
                                    [--chrome-manifest-dir PATH]
                                    [--edge-manifest-dir PATH]
                                    [--require-signature] [--uninstall] [--remove-host]

  Installs a universal wins_bridge_host outside the sandboxed app and writes
  native-messaging manifests that name that exact path. Firefox is always
  registered as companion@winsvpn.org. Chrome and Edge use the distinct store
  ids recorded in tools/native_messaging/manifests/store_ids.json. A browser
  whose id is not recorded is skipped (owner-blocked) and its live
  registration is left in place; the others still install. An unsafe or
  invalid record aborts and does not uninstall them. No store id is invented.
USAGE
  exit 2
}

die() {
  printf 'macos native-host: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) SYSTEM=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --remove-host) REMOVE_HOST=1; shift ;;
    --require-signature) REQUIRE_SIGNATURE=1; shift ;;
    --host-path) HOST_PATH="${2:-}"; shift 2 ;;
    --dest-dir) DEST_DIR="${2:-}"; shift 2 ;;
    --firefox-manifest-dir) FIREFOX_MANIFEST_DIR="${2:-}"; shift 2 ;;
    --chrome-manifest-dir) CHROME_MANIFEST_DIR="${2:-}"; shift 2 ;;
    --edge-manifest-dir) EDGE_MANIFEST_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) usage ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die "this helper is macOS-only"
[[ -x "${PYTHON_BIN}" ]] || die "python3 is required at ${PYTHON_BIN}"
[[ -f "${LAYOUT}" && -f "${GATE}" ]] || die "native-host layout or Apple gate is missing"

layout_cmd() {
  "${PYTHON_BIN}" "${LAYOUT}" "$@"
}

gate_cmd() {
  "${PYTHON_BIN}" "${GATE}" native-host "$@"
}

normalize_abs() {
  local value="$1"
  case "${value}" in
    "~") value="${HOME}" ;;
    "~/"*) value="${HOME}/${value#\~/}" ;;
    /*) ;;
    *) value="${PWD}/${value}" ;;
  esac
  printf '%s\n' "${value}"
}

path_has_dotdot() {
  local value="$1"
  local comp
  local IFS="/"
  local -a parts
  IFS="/" read -r -a parts <<< "${value}"
  for comp in "${parts[@]}"; do
    if [[ "${comp}" == ".." ]]; then
      return 0
    fi
  done
  return 1
}

canonicalize_abs() {
  local value="$1"
  local existing suffix="" parent resolved
  value="$(normalize_abs "${value}")"
  [[ "${value}" == /* ]] || die "native-host path must be absolute"
  if path_has_dotdot "${value}"; then
    die "refusing dot-dot native-host path ${value}"
  fi
  existing="${value}"
  while [[ ! -e "${existing}" && ! -L "${existing}" ]]; do
    if [[ "${existing}" == "/" ]]; then
      break
    fi
    suffix="/$(basename "${existing}")${suffix}"
    existing="$(dirname "${existing}")"
  done
  if [[ -L "${existing}" ]]; then
    die "refusing symlink parent ${existing}"
  fi
  if [[ -d "${existing}" ]]; then
    resolved="$(cd "${existing}" && pwd -P)" || die "cannot canonicalize ${existing}"
  else
    parent="$(dirname "${existing}")"
    if [[ -L "${parent}" ]]; then
      die "refusing symlink parent ${parent}"
    fi
    parent="$(cd "${parent}" && pwd -P)" || die "cannot canonicalize ${parent}"
    resolved="${parent}/$(basename "${existing}")"
  fi
  printf '%s%s\n' "${resolved}" "${suffix}"
}

canonical_home() {
  local value="${HOME}"
  value="$(normalize_abs "${value}")"
  [[ -n "${value}" ]] || die "HOME is missing"
  if [[ -d "${value}" ]]; then
    (cd "${value}" && pwd -P) || die "cannot canonicalize HOME"
    return 0
  fi
  printf '%s\n' "${value}"
}

is_protected() {
  local candidate="$1" prefix home_root
  home_root="${HOME_CANON}"
  [[ -n "${home_root}" ]] || home_root="$(canonical_home)"
  while IFS= read -r prefix; do
    [[ -n "${prefix}" ]] || continue
    case "${candidate}" in
      "${prefix}"|"${prefix}"/*) return 0 ;;
    esac
  done <<EOF
${home_root}/Documents
${home_root}/Desktop
${home_root}/Downloads
${home_root}/Library/Mobile Documents
${home_root}/Movies
${home_root}/Music
${home_root}/Pictures
/Volumes
EOF
  return 1
}

is_sandboxed_app_path() {
  local candidate="$1"
  case "${candidate}" in
    *.app|*.app/*|*.appex|*.appex/*) return 0 ;;
  esac
  return 1
}

resolve_dest_dir() {
  if [[ -n "${DEST_DIR}" ]]; then
    DEST_DIR="$(canonicalize_abs "${DEST_DIR}")"
    return 0
  fi
  if [[ "${SYSTEM}" == "1" ]]; then
    DEST_DIR="$(layout_cmd unix-host-dest --uname Darwin --system)"
  else
    DEST_DIR="$(layout_cmd unix-host-dest --uname Darwin --home "${HOME}")"
  fi
  DEST_DIR="$(canonicalize_abs "${DEST_DIR}")"
}

resolve_manifest_dir() {
  local browser="$1"
  local override="$2"
  local resolved
  if [[ -n "${override}" ]]; then
    canonicalize_abs "${override}"
    return 0
  fi
  local args=(unix-dest --browser "${browser}" --uname Darwin --home "${HOME}")
  [[ "${SYSTEM}" == "1" ]] && args+=(--system)
  resolved="$(layout_cmd "${args[@]}")"
  canonicalize_abs "${resolved}"
}

refuse_install_location() {
  local candidate="$1"
  if is_protected "${candidate}"; then
    die "refusing TCC-protected native-host path ${candidate}"
  fi
  if is_sandboxed_app_path "${candidate}"; then
    die "refusing sandboxed-app native-host path ${candidate}"
  fi
}

firefox_manifest_path() {
  printf '%s/%s.json\n' "$(resolve_manifest_dir firefox "${FIREFOX_MANIFEST_DIR}")" "${HOST_NAME}"
}

chrome_manifest_path() {
  printf '%s/%s.json\n' "$(resolve_manifest_dir chrome "${CHROME_MANIFEST_DIR}")" "${HOST_NAME}"
}

edge_manifest_path() {
  printf '%s/%s.json\n' "$(resolve_manifest_dir edge "${EDGE_MANIFEST_DIR}")" "${HOST_NAME}"
}

read_owner_chromium_snapshot() {
  "${PYTHON_BIN}" - "${LAYOUT}" <<'PY'
import sys
from pathlib import Path

layout_path = Path(sys.argv[1])
sys.path.insert(0, str(layout_path.parent))
import native_host_layout as layout
import render_host_manifest as renderer

try:
    ids = renderer.owner_issued_chromium_ids()
except renderer.OwnerIdentityBlocked:
    # A partial record skips only the browser whose id is missing.
    try:
        ids = renderer.recorded_store_ids()
    except (OSError, ValueError) as error:
        print(f"native-host registration refused: {error}", file=sys.stderr)
        raise SystemExit(1)
except (OSError, ValueError) as error:
    print(f"native-host registration refused: {error}", file=sys.stderr)
    raise SystemExit(1)
chrome = ids.get("chrome") or ""
edge = ids.get("edge") or ""
if chrome and chrome == edge:
    print(
        "native-host registration refused: Chrome and Edge store-listing ids "
        "must be distinct",
        file=sys.stderr,
    )
    raise SystemExit(1)
for browser, value in (("chrome", chrome), ("edge", edge)):
    if value:
        print(f"{browser} {value}")
    else:
        print(f"{browser}-missing {renderer.missing_store_id_message(browser)}")
PY
}

apple_gate_supports_edge() {
  "${PYTHON_BIN}" - "${GATE}" <<'PY'
import ast
import sys
from pathlib import Path

gate_path = Path(sys.argv[1])
text = gate_path.read_text(encoding="utf-8")
tree = ast.parse(text)
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name == "verify_macos_native_host_manifests":
        names = {arg.arg for arg in node.args.args}
        names.update(arg.arg for arg in node.args.kwonlyargs)
        if "edge" in names and "owner_edge_id" in names and "--owner-edge-id" in text:
            raise SystemExit(0)
        break
raise SystemExit(1)
PY
}

verify_chromium_manifest() {
  local browser="$1"
  local extension_id="$2"
  local manifest_path="$3"
  "${PYTHON_BIN}" - "${browser}" "${extension_id}" "${INSTALLED_HOST}" "${manifest_path}" <<'PY'
import json
import sys

browser, extension_id, host_path, manifest_path = sys.argv[1:]
payload = open(manifest_path, "rb").read()
try:
    document = json.loads(payload.decode("utf-8"))
except (UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"{browser} native-host manifest is not JSON") from error
expected = {
    "name": "org.winsvpn.bridge",
    "description": "Win's VPN browser bridge",
    "path": host_path,
    "type": "stdio",
    "allowed_origins": [f"chrome-extension://{extension_id}/"],
}
if document != expected:
    raise SystemExit(f"{browser} native-host manifest is not exact")
encoded = json.dumps(document, ensure_ascii=True)
if "placeholder" in encoded.lower():
    raise SystemExit(f"{browser} native-host manifest still contains a placeholder")
PY
}

leaf_nlink() {
  /usr/bin/stat -f %l "$1" 2>/dev/null || /usr/bin/stat -c %h "$1"
}

refuse_live_leaf() {
  local path="$1"
  local nlink
  if [[ -L "${path}" ]]; then
    die "refusing symlink native-host path ${path}"
  fi
  if [[ ! -e "${path}" ]]; then
    return 0
  fi
  if [[ ! -f "${path}" ]]; then
    die "refusing special native-host path ${path}"
  fi
  nlink="$(leaf_nlink "${path}")" || die "cannot stat ${path}"
  if [[ "${nlink}" != "1" ]]; then
    die "refusing hardlinked native-host path ${path}"
  fi
}

backup_if_present() {
  local source="$1"
  local name="$2"
  local nlink
  layout_cmd mkdir-p --dir "${ROLLBACK_DIR}" >/dev/null
  printf 'absent\n' > "${ROLLBACK_DIR}/${name}.backup-state"
  if [[ -L "${source}" ]]; then
    die "refusing symlink native-host path ${source}"
  fi
  [[ -e "${source}" ]] || return 0
  if [[ ! -f "${source}" ]]; then
    die "refusing special native-host path ${source}"
  fi
  nlink="$(leaf_nlink "${source}")" || die "cannot stat ${source}"
  if [[ "${nlink}" != "1" ]]; then
    die "refusing hardlinked native-host path ${source}"
  fi
  cp -p -- "${source}" "${ROLLBACK_DIR}/${name}" || die "rollback copy failed for ${source}"
  if [[ -L "${ROLLBACK_DIR}/${name}" || ! -f "${ROLLBACK_DIR}/${name}" ]]; then
    die "rollback copy failed for ${source}"
  fi
  nlink="$(leaf_nlink "${ROLLBACK_DIR}/${name}")" || die "cannot stat rollback copy ${name}"
  if [[ "${nlink}" != "1" ]]; then
    die "rollback copy failed for ${source}"
  fi
  printf 'present\n' > "${ROLLBACK_DIR}/${name}.backup-state"
}

mark_mutated() {
  local name="$1"
  [[ -n "${ROLLBACK_DIR}" && -d "${ROLLBACK_DIR}" ]] || die "rollback directory is missing"
  printf 'mutated\n' > "${ROLLBACK_DIR}/${name}.mutated"
}

restore_rollback() {
  local dest="$1"
  local name="$2"
  local backup="${ROLLBACK_DIR}/${name}"
  local nlink
  if [[ ! -f "${ROLLBACK_DIR}/${name}.mutated" ]]; then
    return 0
  fi
  if [[ -L "${dest}" || ( -e "${dest}" && ! -f "${dest}" ) ]]; then
    printf 'macos native-host: rollback restore failed for %s\n' "${dest}" >&2
    RESTORE_FAILED=1
    return 1
  fi
  if [[ -f "${backup}" && ! -L "${backup}" ]]; then
    nlink="$(leaf_nlink "${backup}")" || nlink=""
    if [[ "${nlink}" != "1" ]]; then
      printf 'macos native-host: rollback restore failed for %s\n' "${dest}" >&2
      RESTORE_FAILED=1
      return 1
    fi
    if [[ -f "${dest}" ]]; then
      nlink="$(leaf_nlink "${dest}")" || nlink=""
      if [[ "${nlink}" != "1" ]]; then
        printf 'macos native-host: rollback restore failed for %s\n' "${dest}" >&2
        RESTORE_FAILED=1
        return 1
      fi
    fi
    if ! mv -f -- "${backup}" "${dest}"; then
      printf 'macos native-host: rollback restore failed for %s\n' "${dest}" >&2
      RESTORE_FAILED=1
      return 1
    fi
    return 0
  fi
  if [[ -L "${dest}" ]]; then
    printf 'macos native-host: rollback remove failed for %s\n' "${dest}" >&2
    RESTORE_FAILED=1
    return 1
  fi
  if ! rm -f -- "${dest}"; then
    printf 'macos native-host: rollback remove failed for %s\n' "${dest}" >&2
    RESTORE_FAILED=1
    return 1
  fi
}

rollback_install() {
  local status=$?
  trap - EXIT
  [[ -n "${ROLLBACK_DIR}" && -d "${ROLLBACK_DIR}" ]] || exit "${status}"
  RESTORE_FAILED=0
  # Attempt every mutated target even if an earlier restore fails, then
  # surface the aggregate failure. set -e would otherwise abort the trap.
  set +e
  if [[ -n "${INSTALLED_HOST}" ]]; then
    restore_rollback "${INSTALLED_HOST}" host.bin
  fi
  restore_rollback "${FIREFOX_TARGET}" firefox.json
  restore_rollback "${CHROME_TARGET}" chrome.json
  restore_rollback "${EDGE_TARGET}" edge.json
  if [[ -n "${HOST_PREVIOUS}" ]]; then
    layout_cmd uninstall-leaf --output "${HOST_PREVIOUS}" >/dev/null
  fi
  set -e
  if [[ "${RESTORE_FAILED}" == "1" ]]; then
    printf 'macos native-host: rollback could not restore every live file; retained recovery copies at %s\n' "${ROLLBACK_DIR}" >&2
    if [[ "${status}" -eq 0 ]]; then
      status=1
    fi
    exit "${status}"
  fi
  rm -rf -- "${ROLLBACK_DIR}"
  exit "${status}"
}

HOME_CANON="$(canonical_home)"

if [[ "${UNINSTALL}" == "1" ]]; then
  resolve_dest_dir
  FIREFOX_TARGET="$(firefox_manifest_path)"
  CHROME_TARGET="$(chrome_manifest_path)"
  EDGE_TARGET="$(edge_manifest_path)"
  layout_cmd uninstall-manifest --output "${FIREFOX_TARGET}" >/dev/null
  layout_cmd uninstall-manifest --output "${CHROME_TARGET}" >/dev/null
  layout_cmd uninstall-manifest --output "${EDGE_TARGET}" >/dev/null
  if [[ "${REMOVE_HOST}" == "1" ]]; then
    HOST_FILE="${DEST_DIR}/wins_bridge_host"
    layout_cmd uninstall-leaf --output "${HOST_FILE}" >/dev/null
    rmdir -- "${DEST_DIR}" 2>/dev/null || true
    printf 'removed host: %s\n' "${HOST_FILE}"
  fi
  printf 'uninstalled macos native-host manifests\n'
  exit 0
fi

[[ -n "${HOST_PATH}" ]] || HOST_PATH="${SCRIPT_DIR}/host/wins_bridge_host"
[[ ! -L "${HOST_PATH}" && -f "${HOST_PATH}" && -x "${HOST_PATH}" ]] || die "compiled host is missing, symbolic, or not executable: ${HOST_PATH}"
HOST_PATH="$(cd "$(dirname "${HOST_PATH}")" && pwd -P)/$(basename "${HOST_PATH}")"
[[ "$(leaf_nlink "${HOST_PATH}")" == "1" ]] || die "refusing hardlinked native-host source ${HOST_PATH}"

resolve_dest_dir
refuse_install_location "${DEST_DIR}"
if [[ "${SYSTEM}" == "1" && "$(id -u)" != "0" ]]; then
  die "--system writes outside \$HOME and needs root"
fi

FIREFOX_DIR="$(resolve_manifest_dir firefox "${FIREFOX_MANIFEST_DIR}")"
CHROME_DIR="$(resolve_manifest_dir chrome "${CHROME_MANIFEST_DIR}")"
EDGE_DIR="$(resolve_manifest_dir edge "${EDGE_MANIFEST_DIR}")"
FIREFOX_TARGET="${FIREFOX_DIR}/${HOST_NAME}.json"
CHROME_TARGET="${CHROME_DIR}/${HOST_NAME}.json"
EDGE_TARGET="${EDGE_DIR}/${HOST_NAME}.json"
refuse_install_location "${FIREFOX_DIR}"
refuse_install_location "${CHROME_DIR}"
refuse_install_location "${EDGE_DIR}"

CHROME_ID=""
EDGE_ID=""
SNAPSHOT=""
SNAPSHOT_STATUS=0
set +e
SNAPSHOT="$(read_owner_chromium_snapshot)"
SNAPSHOT_STATUS=$?
set -e
if [[ "${SNAPSHOT_STATUS}" -ne 0 ]]; then
  die "owner identity snapshot failed (${SNAPSHOT_STATUS})"
fi
while IFS= read -r line; do
  case "${line}" in
    "chrome "*) CHROME_ID="${line#chrome }" ;;
    "edge "*) EDGE_ID="${line#edge }" ;;
    "chrome-missing "*)
      CHROME_BLOCKED=1
      CHROME_BLOCK_REASON="${line#chrome-missing }"
      ;;
    "edge-missing "*)
      EDGE_BLOCKED=1
      EDGE_BLOCK_REASON="${line#edge-missing }"
      ;;
  esac
done <<< "${SNAPSHOT}"
CHROME_ID="$(printf '%s' "${CHROME_ID}" | tr -d '\r\n')"
EDGE_ID="$(printf '%s' "${EDGE_ID}" | tr -d '\r\n')"
if [[ ( -z "${CHROME_ID}" && "${CHROME_BLOCKED}" == "0" ) || ( -z "${EDGE_ID}" && "${EDGE_BLOCKED}" == "0" ) ]]; then
  die "owner identity snapshot was incomplete"
fi
if [[ -n "${CHROME_ID}" && "${CHROME_ID}" == "${EDGE_ID}" ]]; then
  die "Chrome and Edge store-listing ids must be distinct; refusing to reuse one identity"
fi

INSTALLED_HOST="${DEST_DIR}/wins_bridge_host"
ROLLBACK_DIR="${DEST_DIR}/.winsvpn-native-host-rollback.$$"
HOST_PREVIOUS=""
trap rollback_install EXIT

layout_cmd mkdir-p --dir "${DEST_DIR}" >/dev/null
layout_cmd mkdir-p --dir "${FIREFOX_DIR}" >/dev/null
layout_cmd mkdir-p --dir "${ROLLBACK_DIR}" >/dev/null
chmod 700 "${ROLLBACK_DIR}" 2>/dev/null || true
backup_if_present "${INSTALLED_HOST}" host.bin
backup_if_present "${FIREFOX_TARGET}" firefox.json
backup_if_present "${CHROME_TARGET}" chrome.json
backup_if_present "${EDGE_TARGET}" edge.json

if [[ "${HOST_PATH}" != "${INSTALLED_HOST}" ]]; then
  staged="${INSTALLED_HOST}.new"
  if [[ -L "${staged}" ]]; then
    rm -f -- "${staged}" || die "cannot remove preplanted staging symlink ${staged}"
  fi
  if [[ -e "${staged}" || -L "${staged}" ]]; then
    if [[ -d "${staged}" && ! -L "${staged}" ]]; then
      die "refusing preplanted staging directory ${staged}"
    fi
    rm -f -- "${staged}" || die "cannot clear staging path ${staged}"
  fi
  if [[ -e "${staged}" || -L "${staged}" ]]; then
    die "refusing preplanted staging path ${staged}"
  fi
  refuse_live_leaf "${INSTALLED_HOST}"
  # Journal before replacement. A marker without a completed mutation is safe:
  # rollback restores the snapshot (or exact absence) idempotently.
  mark_mutated host.bin
  HOST_PREVIOUS="$(layout_cmd install-host --source "${HOST_PATH}" --dest "${INSTALLED_HOST}")"
  HOST_PREVIOUS="$(printf '%s' "${HOST_PREVIOUS}" | tr -d '\r\n')"
fi
refuse_install_location "${INSTALLED_HOST}"
refuse_live_leaf "${INSTALLED_HOST}"

GATE_ARGS=(verify-binary --host "${INSTALLED_HOST}")
if [[ "${REQUIRE_SIGNATURE}" == "1" ]]; then
  GATE_ARGS+=(--require-signature --require-notarization)
fi
gate_cmd "${GATE_ARGS[@]}"

gate_cmd handshake --host "${INSTALLED_HOST}"

mark_mutated firefox.json
layout_cmd install-manifest \
  --browser firefox \
  --host-path "${INSTALLED_HOST}" \
  --output "${FIREFOX_TARGET}" >/dev/null
chmod 600 "${FIREFOX_TARGET}" 2>/dev/null || true

if [[ "${CHROME_BLOCKED}" == "0" ]]; then
  layout_cmd mkdir-p --dir "${CHROME_DIR}" >/dev/null
  mark_mutated chrome.json
  layout_cmd install-manifest \
    --browser chrome \
    --host-path "${INSTALLED_HOST}" \
    --extension-id "${CHROME_ID}" \
    --output "${CHROME_TARGET}" >/dev/null
  chmod 600 "${CHROME_TARGET}" 2>/dev/null || true
  verify_chromium_manifest chrome "${CHROME_ID}" "${CHROME_TARGET}"
fi

if [[ "${EDGE_BLOCKED}" == "0" ]]; then
  layout_cmd mkdir-p --dir "${EDGE_DIR}" >/dev/null
  mark_mutated edge.json
  layout_cmd install-manifest \
    --browser edge \
    --host-path "${INSTALLED_HOST}" \
    --extension-id "${EDGE_ID}" \
    --output "${EDGE_TARGET}" >/dev/null
  chmod 600 "${EDGE_TARGET}" 2>/dev/null || true
  verify_chromium_manifest edge "${EDGE_ID}" "${EDGE_TARGET}"
fi

if [[ "${CHROME_BLOCKED}" == "0" && "${EDGE_BLOCKED}" == "0" ]]; then
  if cmp -s "${CHROME_TARGET}" "${EDGE_TARGET}"; then
    die "Chrome and Edge native-host manifests must be distinct"
  fi
fi

MANIFEST_ARGS=(
  verify-manifests
  --host-path "${INSTALLED_HOST}"
  --firefox "${FIREFOX_TARGET}"
)
if [[ "${CHROME_BLOCKED}" == "0" ]]; then
  MANIFEST_ARGS+=(--chrome "${CHROME_TARGET}" --owner-chrome-id "${CHROME_ID}")
fi
EDGE_GATE_SUPPORTED=1
set +e
apple_gate_supports_edge
EDGE_GATE_SUPPORTED=$?
set -e
if [[ "${EDGE_GATE_SUPPORTED}" -eq 0 && "${EDGE_BLOCKED}" == "0" ]]; then
  MANIFEST_ARGS+=(--edge "${EDGE_TARGET}" --owner-edge-id "${EDGE_ID}")
fi
gate_cmd "${MANIFEST_ARGS[@]}"
if [[ "${EDGE_BLOCKED}" == "0" && "${EDGE_GATE_SUPPORTED}" -ne 0 ]]; then
  verify_chromium_manifest edge "${EDGE_ID}" "${EDGE_TARGET}"
fi

if [[ -n "${HOST_PREVIOUS}" ]]; then
  layout_cmd uninstall-leaf --output "${HOST_PREVIOUS}" >/dev/null || true
fi
rm -rf -- "${ROLLBACK_DIR}"
trap - EXIT

printf 'installed macos native-host: %s\n' "${INSTALLED_HOST}"
printf '  firefox manifest: %s\n' "${FIREFOX_TARGET}"
if [[ "${CHROME_BLOCKED}" == "1" ]]; then
  printf '  chrome: owner-blocked (%s)\n' "${CHROME_BLOCK_REASON}"
else
  printf '  chrome manifest: %s\n' "${CHROME_TARGET}"
fi
if [[ "${EDGE_BLOCKED}" == "1" ]]; then
  printf '  edge: owner-blocked (%s)\n' "${EDGE_BLOCK_REASON}"
else
  printf '  edge manifest: %s\n' "${EDGE_TARGET}"
fi
