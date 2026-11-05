#!/usr/bin/env bash
# Fail-closed deployment producer for the aicore Win's VPN Smart Router.
# --preflight is read-only. --deploy is the only mutating mode.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SERVICE_NAME="wins-edge-router.service"
readonly SERVICE_USER="aicore"
readonly SERVICE_GROUP="aicore"
readonly REQUIRED_PYTHON_VERSION="3.14.7"
readonly CANONICAL_UNIT_SHA256="6dbd9f0eae77a800e6a812faabc44bfa0f31549f9f2920d17da28d3c53e39f29"
readonly PRODUCTION_INSTALL_ROOT="/opt/winsvpn-router"
readonly PRODUCTION_ENV_FILE="/etc/winsvpn/router.env"
readonly PRODUCTION_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
readonly PRODUCTION_HELPER_PATH="/usr/local/libexec/winsvpn-router-install"
readonly PRODUCTION_LOCK_PATH="/run/lock/winsvpn-router-deploy.lock"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")"
readonly INSTALLER_NAME="$(basename -- "${BASH_SOURCE[0]}")"
readonly UNIT_SOURCE_NAME="wins-edge-router.service.example"

RUNTIME_FILES=(
  fallback.py
  gemini_client.py
  local_gemma_client.py
  main.py
  provider_common.py
  schemas.py
  security.py
  requirements.lock
  requirements.txt
)
SOURCE_FILES=(
  "${RUNTIME_FILES[@]}"
  "$INSTALLER_NAME"
  "$UNIT_SOURCE_NAME"
)

MODE=""
TARGET_ROOT="/"
ENV_FILE=""
PYTHON_BIN="/usr/bin/python3.14"
SYSTEMCTL_BIN="systemctl"
SS_BIN="ss"
ROLLBACK_DIR=""
NEW_RELEASE_DIR=""
DEPLOY_COMMITTED=0
ROLLBACK_RUNNING=0
UNIT_BACKUP_STATE="unset"
HELPER_BACKUP_STATE="unset"
PREVIOUS_CURRENT_STATE="unset"
PREVIOUS_CURRENT_TARGET=""
PREVIOUS_ACTIVE=0
PREVIOUS_ENABLED=0
UNIT_CHANGED=0
HELPER_CHANGED=0
CURRENT_CHANGED=0
ENABLE_CHANGED=0
RESTART_ATTEMPTED=0
SOURCE_ORIGIN=""
SOURCE_BINDING=""
SOURCE_STAGE_DIR=""
DEPLOY_SOURCE_DIR="$SCRIPT_DIR"
STAGED_EXECUTION=0
HELPER_SHA256=""

usage() {
  cat <<'EOF'
Usage:
  install_aicore_router.sh --preflight [options]
  install_aicore_router.sh --deploy [options]
  install_aicore_router.sh --verify-runtime [options]

Modes:
  --preflight       Read-only source, environment, interpreter, user, and
                    loopback-listener validation. Never writes or restarts.
  --deploy          Run preflight, atomically install and activate the exact
                    source closure, then restart with automatic rollback.
  --verify-runtime  Read-only installed-release check used by systemd.

Options:
  --env-file PATH     Dedicated systemd EnvironmentFile.
  --python PATH       Interpreter, which must be exactly Python 3.14.7.
  --systemctl PATH    systemctl executable, primarily for offline tests.
  --ss PATH           ss executable used to prove port 8002 is loopback-only.
  --target-root PATH  Test-only prefix for absolute deployment paths.
  -h, --help          Show this help.
EOF
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

require_value() {
  local option="$1"
  local value="${2-}"
  [[ -n "$value" && "$value" != -* ]] || fail "${option} requires a value"
}

set_mode() {
  local proposed="$1"
  [[ -z "$MODE" ]] || fail "exactly one execution mode is required"
  MODE="$proposed"
}

while (($#)); do
  case "$1" in
    --preflight) set_mode preflight; shift ;;
    --deploy) set_mode deploy; shift ;;
    --verify-runtime) set_mode verify-runtime; shift ;;
    --env-file)
      require_value "$1" "${2-}"; ENV_FILE="$2"; shift 2 ;;
    --python)
      require_value "$1" "${2-}"; PYTHON_BIN="$2"; shift 2 ;;
    --systemctl)
      require_value "$1" "${2-}"; SYSTEMCTL_BIN="$2"; shift 2 ;;
    --ss)
      require_value "$1" "${2-}"; SS_BIN="$2"; shift 2 ;;
    --target-root)
      require_value "$1" "${2-}"; TARGET_ROOT="$2"; shift 2 ;;
    --internal-source-origin)
      require_value "$1" "${2-}"; SOURCE_ORIGIN="$2"; shift 2 ;;
    --internal-source-binding)
      require_value "$1" "${2-}"; SOURCE_BINDING="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$MODE" ]] || fail "one of --preflight, --deploy, or --verify-runtime is required"
if [[ -n "$SOURCE_ORIGIN" || -n "$SOURCE_BINDING" ]]; then
  [[ "$MODE" == "deploy" && -n "$SOURCE_ORIGIN" && -n "$SOURCE_BINDING" ]] || \
    fail "internal staged-source arguments are incomplete or unavailable for this mode"
  STAGED_EXECUTION=1
fi
[[ "$TARGET_ROOT" = /* && "$TARGET_ROOT" != *$'\n'* ]] || fail "--target-root must be a normalized absolute path"
if [[ "$TARGET_ROOT" != "/" ]]; then
  [[ "${WINSVPN_ROUTER_TESTING:-}" == "1" ]] || \
    fail "non-root --target-root is restricted to the offline test harness"
  TARGET_ROOT="${TARGET_ROOT%/}"
fi
[[ -d "$TARGET_ROOT" && ! -L "$TARGET_ROOT" ]] || fail "target root must be a real directory"
readonly TARGET_ROOT

rooted() {
  local path="$1"
  [[ "$path" = /* ]] || fail "internal deployment path is not absolute"
  if [[ "$TARGET_ROOT" == "/" ]]; then
    printf '%s\n' "$path"
  else
    printf '%s%s\n' "$TARGET_ROOT" "$path"
  fi
}

readonly INSTALL_ROOT="$(rooted "$PRODUCTION_INSTALL_ROOT")"
readonly RELEASES_DIR="${INSTALL_ROOT}/releases"
readonly CURRENT_LINK="${INSTALL_ROOT}/current"
readonly UNIT_PATH="$(rooted "$PRODUCTION_UNIT_PATH")"
readonly HELPER_PATH="$(rooted "$PRODUCTION_HELPER_PATH")"
readonly LOCK_PATH="$(rooted "$PRODUCTION_LOCK_PATH")"
readonly TEMP_ROOT="$(rooted "/var/tmp")"
if [[ -z "$ENV_FILE" ]]; then ENV_FILE="$(rooted "$PRODUCTION_ENV_FILE")"; fi
readonly ENV_FILE

resolve_executable() {
  local requested="$1"
  local resolved
  if [[ "$requested" == */* ]]; then
    resolved="$requested"
  else
    resolved="$(command -v -- "$requested" 2>/dev/null || true)"
  fi
  [[ -n "$resolved" && -x "$resolved" && ! -d "$resolved" ]] || \
    fail "required executable is unavailable: ${requested}"
  printf '%s\n' "$resolved"
}

PYTHON_BIN="$(resolve_executable "$PYTHON_BIN")"
SYSTEMCTL_BIN="$(resolve_executable "$SYSTEMCTL_BIN")"
SS_BIN="$(resolve_executable "$SS_BIN")"
readonly PYTHON_BIN SYSTEMCTL_BIN SS_BIN

if [[ "$TARGET_ROOT" == "/" && "$MODE" == "deploy" ]]; then
  [[ "$PYTHON_BIN" == "/usr/bin/python3.14" ]] || \
    fail "production deployment requires the canonical /usr/bin/python3.14 interpreter"
fi

require_command() {
  command -v -- "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

validate_python() {
  local actual
  actual="$("$PYTHON_BIN" -I -c 'import platform; print(platform.python_version())' 2>/dev/null)" || \
    fail "Python interpreter validation failed"
  [[ "$actual" == "$REQUIRED_PYTHON_VERSION" ]] || fail "Python ${REQUIRED_PYTHON_VERSION} is required"
}

validate_target_root() {
  local physical
  physical="$(cd -- "$TARGET_ROOT" && pwd -P)"
  [[ "$physical" == "$TARGET_ROOT" ]] || fail "target root must be normalized and contain no symlink"
}

validate_path_ancestors() {
  local path="$1"
  local allow_missing="$2"
  "$PYTHON_BIN" -I - "$path" "$allow_missing" <<'PY' >/dev/null || fail "unsafe path ancestry: ${path}"
import os
import stat
import sys
raw, allow_missing = sys.argv[1], sys.argv[2] == "1"
if not raw.startswith("/") or os.path.normpath(raw) != raw or "\x00" in raw:
    raise SystemExit(1)
current = "/"
for part in raw.split("/")[1:-1]:
    current = os.path.join(current, part)
    try:
        info = os.lstat(current)
    except FileNotFoundError:
        if allow_missing:
            break
        raise SystemExit(1)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SystemExit(1)
PY
}

validate_source() {
  local source_root="$1"
  "$PYTHON_BIN" -I - "$source_root" "$INSTALLER_NAME" "$UNIT_SOURCE_NAME" \
    "$CANONICAL_UNIT_SHA256" "${RUNTIME_FILES[@]}" <<'PY' >/dev/null || \
    fail "router source closure validation failed"
import os
from pathlib import Path
import hashlib
import re
import stat
import sys
root = Path(sys.argv[1])
installer_name = sys.argv[2]
unit_name = sys.argv[3]
canonical_unit_sha256 = sys.argv[4]
runtime_names = sys.argv[5:]
script = root / installer_name
expected = set(runtime_names) | {installer_name, unit_name}
if root.is_symlink() or not root.is_dir() or root.resolve() != root:
    raise SystemExit(1)
for name in expected:
    path = root / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit(1)
    if info.st_nlink != 1 or info.st_size <= 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise SystemExit(1)
actual_runtime = {
    path.name for path in root.iterdir()
    if path.is_file() and not path.is_symlink()
    and (path.suffix == ".py" or path.name in {"requirements.lock", "requirements.txt"})
}
if actual_runtime != set(runtime_names) or not os.access(script, os.X_OK):
    raise SystemExit(1)
lock = (root / "requirements.lock").read_text(encoding="utf-8")
if "--only-binary :all:" not in lock or "git+" in lock.lower() or "://" in lock:
    raise SystemExit(1)
blocks = []
lines = lock.splitlines()
index = 0
pin = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+-]+(?:\s*\\)?$")
while index < len(lines):
    line = lines[index]
    if not pin.match(line):
        index += 1
        continue
    block = [line]
    index += 1
    while index < len(lines) and lines[index][:1] in {" ", "\t"}:
        block.append(lines[index])
        index += 1
    blocks.append("\n".join(block))
if not blocks or any(not re.search(r"--hash=sha256:[0-9a-f]{64}\b", block) for block in blocks):
    raise SystemExit(1)
unit_bytes = (root / unit_name).read_bytes()
if hashlib.sha256(unit_bytes).hexdigest() != canonical_unit_sha256:
    raise SystemExit(1)
unit = unit_bytes.decode("utf-8")
required = {
    "Type=exec",
    "User=aicore",
    "Group=aicore",
    "Slice=wins-ai.slice",
    "WorkingDirectory=/opt/winsvpn-router/current",
    "EnvironmentFile=/etc/winsvpn/router.env",
    "ExecStartPre=+/usr/local/libexec/winsvpn-router-install --verify-runtime",
    "ExecStart=/opt/winsvpn-router/current/.venv/bin/python -I -m uvicorn main:app --host 127.0.0.1 --port 8090 --no-access-log",
    "StateDirectory=winsvpn-router",
    "StateDirectoryMode=0700",
    "ProtectSystem=strict",
    "ProtectHome=true",
}
if not required.issubset(set(unit.splitlines())):
    raise SystemExit(1)
PY
}

validate_installed_unit() {
  local expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$UNIT_PATH" "$TARGET_ROOT" "$expected_uid" "$CANONICAL_UNIT_SHA256" <<'PY' >/dev/null || \
    fail "installed Smart Router unit is not canonical"
from pathlib import Path
import hashlib
import os
import stat
import sys

unit_path = Path(sys.argv[1])
target_root = Path(sys.argv[2])
expected_uid = int(sys.argv[3])
canonical_unit_sha256 = sys.argv[4]
info = unit_path.lstat()
if (
    unit_path.is_symlink()
    or not stat.S_ISREG(info.st_mode)
    or info.st_nlink != 1
    or info.st_uid != expected_uid
    or stat.S_IMODE(info.st_mode) != 0o644
):
    raise SystemExit(1)
lines = unit_path.read_text(encoding="utf-8").splitlines()
if hashlib.sha256(unit_path.read_bytes()).hexdigest() != canonical_unit_sha256:
    raise SystemExit(1)
required = {
    "Type=exec",
    "User=aicore",
    "Group=aicore",
    "Slice=wins-ai.slice",
    "WorkingDirectory=/opt/winsvpn-router/current",
    "EnvironmentFile=/etc/winsvpn/router.env",
    "ExecStartPre=+/usr/local/libexec/winsvpn-router-install --verify-runtime",
    "ExecStart=/opt/winsvpn-router/current/.venv/bin/python -I -m uvicorn main:app --host 127.0.0.1 --port 8090 --no-access-log",
    "StateDirectory=winsvpn-router",
    "StateDirectoryMode=0700",
    "ProtectSystem=strict",
    "ProtectHome=true",
}
if not required.issubset(set(lines)):
    raise SystemExit(1)
if [line for line in lines if line.startswith("ExecStart=")] != [
    "ExecStart=/opt/winsvpn-router/current/.venv/bin/python -I -m uvicorn main:app --host 127.0.0.1 --port 8090 --no-access-log"
]:
    raise SystemExit(1)
if [line for line in lines if line.startswith("ExecStartPre=")] != [
    "ExecStartPre=+/usr/local/libexec/winsvpn-router-install --verify-runtime"
]:
    raise SystemExit(1)
if any(line.startswith(("ExecStartPost=", "ExecCondition=")) for line in lines):
    raise SystemExit(1)
if [line for line in lines if line.startswith("EnvironmentFile=")] != [
    "EnvironmentFile=/etc/winsvpn/router.env"
]:
    raise SystemExit(1)

for relative in (
    "etc/systemd/system/wins-edge-router.service.d",
    "run/systemd/system/wins-edge-router.service.d",
    "run/systemd/transient/wins-edge-router.service.d",
    "run/systemd/generator.early/wins-edge-router.service.d",
    "run/systemd/generator/wins-edge-router.service.d",
    "run/systemd/generator.late/wins-edge-router.service.d",
    "usr/local/lib/systemd/system/wins-edge-router.service.d",
    "usr/lib/systemd/system/wins-edge-router.service.d",
    "lib/systemd/system/wins-edge-router.service.d",
):
    dropin = target_root / relative
    try:
        dropin.lstat()
    except FileNotFoundError:
        continue
    raise SystemExit(1)
PY
}

compute_source_manifest() {
  local source_root="$1"
  shift
  "$PYTHON_BIN" -I - "$source_root" "$@" <<'PY'
from pathlib import Path
import hashlib
import sys
root = Path(sys.argv[1])
for name in sys.argv[2:]:
    data = (root / name).read_bytes()
    print(f"{hashlib.sha256(data).hexdigest()}  {name}")
PY
}

sha256_text() {
  "$PYTHON_BIN" -I -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())'
}

validate_environment() {
  local expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$ENV_FILE" "$expected_uid" <<'PY' >/dev/null || \
    fail "router environment validation failed"
from pathlib import Path
from urllib.parse import urlsplit
import os
import re
import stat
import sys
path = Path(sys.argv[1])
expected_uid = int(sys.argv[2])
try:
    info = path.lstat()
except OSError:
    raise SystemExit(1)
if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    raise SystemExit(1)
if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 65536:
    raise SystemExit(1)
if not path.is_absolute() or str(path) != os.path.normpath(path):
    raise SystemExit(1)
allowed = {
    "SMART_ROUTER_HMAC_SECRET", "EDGE_ROUTER_SECRET",
    "SMART_ROUTER_GEMMA_MODEL", "EDGE_ROUTER_GEMMA_MODEL",
    "LOCAL_LLM_MODEL", "LOCAL_MODEL", "GEMMA_MODEL",
    "SMART_ROUTER_GEMMA_MODEL_REVISION",
    "SMART_ROUTER_GEMMA_ARTIFACT_ROOT",
    "SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",
    "SMART_ROUTER_GEMMA_URL", "EDGE_ROUTER_GEMMA_URL", "LOCAL_LLM_URL", "VLLM_URL",
    "SMART_ROUTER_VLLM_API_KEY", "VLLM_API_KEY",
    "GEMINI_API_KEY", "GEMINI_MODEL",
    "SMART_ROUTER_TOTAL_BUDGET_MS", "SMART_ROUTER_LOCAL_TIMEOUT_MS",
    "SMART_ROUTER_GOOGLE_TIMEOUT_MS", "SMART_ROUTER_QUEUE_TIMEOUT_MS",
    "SMART_ROUTER_MAX_CONCURRENT_REQUESTS", "SMART_ROUTER_MAX_BODY_BYTES",
    "SMART_ROUTER_RATE_LIMIT_REQUESTS", "SMART_ROUTER_RATE_WINDOW_SECONDS",
    "SMART_ROUTER_AUTH_WINDOW_SECONDS", "SMART_ROUTER_NONCE_JOURNAL_PATH",
    "SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES", "SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES",
    "SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS", "DECISIONS_FILE",
}
values = {}
for raw in path.read_text(encoding="utf-8").splitlines():
    if not raw or raw.startswith("#"):
        continue
    if raw != raw.strip() or "=" not in raw:
        raise SystemExit(1)
    key, value = raw.split("=", 1)
    if key not in allowed or key in values or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
        raise SystemExit(1)
    if value and not re.fullmatch(r"[A-Za-z0-9._~:/+?&=%@-]+", value):
        raise SystemExit(1)
    values[key] = value
def exactly_one(names, required=True):
    present = [(name, values.get(name, "")) for name in names if values.get(name, "")]
    if len(present) > 1 or (required and len(present) != 1):
        raise SystemExit(1)
    return present[0][1] if present else ""
secret = exactly_one(("SMART_ROUTER_HMAC_SECRET", "EDGE_ROUTER_SECRET"))
if not 32 <= len(secret) <= 4096:
    raise SystemExit(1)
model = exactly_one((
    "SMART_ROUTER_GEMMA_MODEL", "EDGE_ROUTER_GEMMA_MODEL", "LOCAL_LLM_MODEL",
    "LOCAL_MODEL", "GEMMA_MODEL",
))
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model):
    raise SystemExit(1)
revision = exactly_one(("SMART_ROUTER_GEMMA_MODEL_REVISION",))
if not re.fullmatch(r"(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})", revision):
    raise SystemExit(1)
artifact_root = exactly_one(("SMART_ROUTER_GEMMA_ARTIFACT_ROOT",))
if (
    not artifact_root.startswith("/")
    or os.path.normpath(artifact_root) != artifact_root
    or "\x00" in artifact_root
):
    raise SystemExit(1)
inventory = exactly_one(("SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",))
if not re.fullmatch(r"[0-9a-f]{64}", inventory):
    raise SystemExit(1)
url = exactly_one(("SMART_ROUTER_GEMMA_URL", "EDGE_ROUTER_GEMMA_URL", "LOCAL_LLM_URL", "VLLM_URL"))
parsed = urlsplit(url)
if (
    parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
    or parsed.port != 8002 or parsed.username is not None or parsed.password is not None
    or parsed.query or parsed.fragment or parsed.path.rstrip("/") not in {"", "/v1/chat/completions"}
):
    raise SystemExit(1)
exactly_one(("SMART_ROUTER_VLLM_API_KEY", "VLLM_API_KEY"), required=False)
google_key = values.get("GEMINI_API_KEY", "")
google_model = values.get("GEMINI_MODEL", "")
if bool(google_key) != bool(google_model):
    raise SystemExit(1)
if google_model and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", google_model):
    raise SystemExit(1)
if values.get("SMART_ROUTER_NONCE_JOURNAL_PATH") != "/var/lib/winsvpn-router/replay-nonces.sqlite3":
    raise SystemExit(1)
if values.get("DECISIONS_FILE") != "/var/lib/winsvpn-router/router-decisions.jsonl":
    raise SystemExit(1)
ranges = {
    "SMART_ROUTER_TOTAL_BUDGET_MS": (250, 5000),
    "SMART_ROUTER_LOCAL_TIMEOUT_MS": (100, 3000),
    "SMART_ROUTER_GOOGLE_TIMEOUT_MS": (100, 3000),
    "SMART_ROUTER_QUEUE_TIMEOUT_MS": (1, 250),
    "SMART_ROUTER_MAX_CONCURRENT_REQUESTS": (1, 64),
    "SMART_ROUTER_MAX_BODY_BYTES": (4096, 262144),
    "SMART_ROUTER_RATE_LIMIT_REQUESTS": (1, 10000),
    "SMART_ROUTER_RATE_WINDOW_SECONDS": (1, 3600),
    "SMART_ROUTER_AUTH_WINDOW_SECONDS": (5, 300),
    "SMART_ROUTER_NONCE_JOURNAL_MAX_ENTRIES": (256, 10000),
    "SMART_ROUTER_NONCE_JOURNAL_MAX_BYTES": (1048576, 16777216),
    "SMART_ROUTER_NONCE_JOURNAL_LOCK_TIMEOUT_MS": (50, 2000),
}
for name, (minimum, maximum) in ranges.items():
    raw = values.get(name, "")
    if not raw or not raw.isascii() or not raw.isdecimal() or not minimum <= int(raw) <= maximum:
        raise SystemExit(1)
if int(values["SMART_ROUTER_LOCAL_TIMEOUT_MS"]) + int(values["SMART_ROUTER_GOOGLE_TIMEOUT_MS"]) >= int(values["SMART_ROUTER_TOTAL_BUDGET_MS"]):
    raise SystemExit(1)
PY
}

validate_service_user() {
  local uid gid
  uid="$(id -u "$SERVICE_USER" 2>/dev/null)" || fail "service user aicore is missing"
  gid="$(id -g "$SERVICE_GROUP" 2>/dev/null)" || fail "service group aicore is missing"
  [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$uid" -gt 0 && "$gid" -gt 0 ]] || \
    fail "service account IDs are invalid"
}

validate_gemma_artifact() {
  "$PYTHON_BIN" -I - "$ENV_FILE" "$TARGET_ROOT" <<'PY' >/dev/null || \
    fail "reviewed Gemma artifact identity validation failed"
from pathlib import Path
import hashlib
import os
import re
import stat
import sys

env_path, target_root = sys.argv[1:]
values = {}
for raw in Path(env_path).read_text(encoding="utf-8").splitlines():
    if not raw or raw.startswith("#"):
        continue
    key, value = raw.split("=", 1)
    if key in values:
        raise SystemExit(1)
    values[key] = value

def required(name):
    value = values.get(name, "")
    if not value:
        raise SystemExit(1)
    return value

model_names = (
    "SMART_ROUTER_GEMMA_MODEL", "EDGE_ROUTER_GEMMA_MODEL", "LOCAL_LLM_MODEL",
    "LOCAL_MODEL", "GEMMA_MODEL",
)
model_values = [values.get(name, "") for name in model_names if values.get(name, "")]
if len(model_values) != 1:
    raise SystemExit(1)
model = model_values[0]
revision = required("SMART_ROUTER_GEMMA_MODEL_REVISION")
artifact_root_value = required("SMART_ROUTER_GEMMA_ARTIFACT_ROOT")
inventory = required("SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}", model):
    raise SystemExit(1)
if not re.fullmatch(r"(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})", revision):
    raise SystemExit(1)
if not re.fullmatch(r"[0-9a-f]{64}", inventory):
    raise SystemExit(1)
if (
    not artifact_root_value.startswith("/")
    or os.path.normpath(artifact_root_value) != artifact_root_value
    or "\x00" in artifact_root_value
):
    raise SystemExit(1)

prefix = Path(target_root)
root = Path(artifact_root_value) if target_root == "/" else prefix / artifact_root_value.lstrip("/")
try:
    root.relative_to(prefix)
except ValueError:
    raise SystemExit(1)
expected_uid = 0 if target_root == "/" else os.getuid()

def require_directory(path):
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) & 0o222
    ):
        raise SystemExit(1)
    return info

def require_ancestor(path):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != expected_uid:
        raise SystemExit(1)

current = prefix
require_ancestor(current)
for part in root.relative_to(prefix).parts:
    current /= part
    if current == root:
        require_directory(current)
    else:
        require_ancestor(current)
root_info = require_directory(root)

def category(relative):
    name = Path(relative).name.lower()
    if name.endswith((".safetensors", ".bin", ".gguf", ".pt", ".pth")) or "weight" in name:
        return "weights"
    if (
        name.startswith("tokenizer")
        or name in {"added_tokens.json", "special_tokens_map.json"}
        or name.endswith((".model", ".tiktoken"))
    ):
        return "tokenizer"
    if (
        name == "config.json"
        or name.startswith("config.")
        or name in {"generation_config.json", "preprocessor_config.json"}
    ):
        return "config"
    return "other"

entries = [f"D . {stat.S_IMODE(root_info.st_mode):04o}"]
categories = set()
for current_name, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
    current_path = Path(current_name)
    directory_names.sort()
    file_names.sort()
    for name in directory_names:
        path = current_path / name
        relative = path.relative_to(root).as_posix()
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", relative):
            raise SystemExit(1)
        info = require_directory(path)
        entries.append(f"D {relative} {stat.S_IMODE(info.st_mode):04o}")
    for name in file_names:
        path = current_path / name
        relative = path.relative_to(root).as_posix()
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", relative):
            raise SystemExit(1)
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o222
        ):
            raise SystemExit(1)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            raise SystemExit(1)
        try:
            live_info = os.fstat(descriptor)
            if (
                live_info.st_dev != info.st_dev
                or live_info.st_ino != info.st_ino
                or live_info.st_uid != expected_uid
                or live_info.st_nlink != 1
                or stat.S_IMODE(live_info.st_mode) & 0o222
            ):
                raise SystemExit(1)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
        kind = category(relative)
        categories.add(kind)
        entries.append(
            f"F {kind} {relative} {stat.S_IMODE(info.st_mode):04o} {digest.hexdigest()}"
        )

if not {"weights", "tokenizer", "config"}.issubset(categories):
    raise SystemExit(1)
actual = hashlib.sha256(("\n".join(sorted(entries)) + "\n").encode("ascii")).hexdigest()
if actual != inventory:
    raise SystemExit(1)
PY
}

validate_vllm_listener() {
  local requirement="${1:-required}" sockets
  case "$requirement" in
    required|optional) ;;
    *) fail "invalid vLLM listener requirement" ;;
  esac
  sockets="$("$SS_BIN" -H -ltn 2>/dev/null)" || fail "could not inspect listening TCP sockets"
  "$PYTHON_BIN" -I -c '
import sys
listeners = []
for raw in sys.argv[1].splitlines():
    fields = raw.split()
    if len(fields) < 4:
        continue
    local = fields[3]
    if ":" not in local:
        continue
    host, port = local.rsplit(":", 1)
    if port == "8002":
        listeners.append(host.strip("[]"))
if any(host not in {"127.0.0.1", "::1"} for host in listeners):
    raise SystemExit(1)
if sys.argv[2] == "required" and not listeners:
    raise SystemExit(1)
' "$sockets" "$requirement" >/dev/null || fail "vLLM port 8002 is not exclusively loopback-bound"
}

validate_vllm_served_model() {
  "$PYTHON_BIN" -I - "$ENV_FILE" "$TARGET_ROOT" <<'PY' >/dev/null || \
    fail "configured local Gemma model is not served by loopback vLLM"
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

path, target_root = sys.argv[1:]
values = {}
for raw in open(path, encoding="utf-8"):
    line = raw.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    key, value = line.split("=", 1)
    values[key] = value

def exactly_one(names):
    present = [values.get(name, "") for name in names if values.get(name, "")]
    if len(present) != 1:
        raise SystemExit(1)
    return present[0]

model = exactly_one((
    "SMART_ROUTER_GEMMA_MODEL", "EDGE_ROUTER_GEMMA_MODEL", "LOCAL_LLM_MODEL",
    "LOCAL_MODEL", "GEMMA_MODEL",
))
revision = exactly_one(("SMART_ROUTER_GEMMA_MODEL_REVISION",))
artifact_root = exactly_one(("SMART_ROUTER_GEMMA_ARTIFACT_ROOT",))
inventory = exactly_one(("SMART_ROUTER_GEMMA_ARTIFACT_INVENTORY_SHA256",))
base_url = exactly_one((
    "SMART_ROUTER_GEMMA_URL", "EDGE_ROUTER_GEMMA_URL", "LOCAL_LLM_URL", "VLLM_URL",
))
parsed = urllib.parse.urlsplit(base_url)
if (
    parsed.scheme != "http"
    or parsed.hostname not in {"127.0.0.1", "::1"}
    or parsed.port != 8002
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
):
    raise SystemExit(1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result

endpoint = urllib.parse.urlunsplit(("http", parsed.netloc, "/v1/models", "", ""))
test_endpoint = os.environ.get("WINSVPN_ROUTER_TEST_VLLM_MODELS_URL", "")
if test_endpoint:
    if target_root == "/" or os.environ.get("WINSVPN_ROUTER_TESTING") != "1":
        raise SystemExit(1)
    test_parsed = urllib.parse.urlsplit(test_endpoint)
    if (
        test_parsed.scheme != "http"
        or test_parsed.hostname not in {"127.0.0.1", "::1"}
        or test_parsed.port is None
        or test_parsed.username is not None
        or test_parsed.password is not None
        or test_parsed.query
        or test_parsed.fragment
        or test_parsed.path != "/v1/models"
    ):
        raise SystemExit(1)
    endpoint = test_endpoint
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    with opener.open(endpoint, timeout=0.5) as response:
        if response.status != 200:
            raise SystemExit(1)
        raw = response.read(65537)
except (OSError, urllib.error.URLError, urllib.error.HTTPError):
    raise SystemExit(1)
if len(raw) > 65536:
    raise SystemExit(1)
try:
    decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(decoded, dict) or not isinstance(decoded.get("data"), list):
    raise SystemExit(1)
same_alias = [
    item for item in decoded["data"]
    if isinstance(item, dict) and item.get("id") == model
]
# Stock vLLM /v1/models entries (ModelCard) carry id and root (the --model
# path), never this project's revision/inventory extensions. Require the
# served root to be the installer-validated artifact directory, and require
# a revision/inventory field to match only when a server actually sends one.
if (
    len(same_alias) != 1
    or same_alias[0].get("root", artifact_root) != artifact_root
    or same_alias[0].get("model_revision", revision) != revision
    or same_alias[0].get("artifact_inventory_sha256", inventory) != inventory
):
    raise SystemExit(1)
PY
}

cleanup_source_stage() {
  [[ -n "$SOURCE_STAGE_DIR" ]] || return 0
  local parent name expected_uid
  parent="$(dirname -- "$SOURCE_STAGE_DIR")"
  name="$(basename -- "$SOURCE_STAGE_DIR")"
  [[ "$parent" == "$TEMP_ROOT" && "$name" =~ ^winsvpn-router-source\.[A-Za-z0-9]{8}$ ]] || \
    fail "refusing unsafe staged-source cleanup"
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$SOURCE_STAGE_DIR" "$expected_uid" <<'PY' >/dev/null || \
    fail "refusing unsafe staged-source cleanup"
import os
import stat
import sys
path = sys.argv[1]
expected_uid = int(sys.argv[2])
info = os.stat(path, follow_symlinks=False)
if (
    not stat.S_ISDIR(info.st_mode)
    or stat.S_ISLNK(info.st_mode)
    or info.st_uid != expected_uid
    or stat.S_IMODE(info.st_mode) != 0o700
):
    raise SystemExit(1)
PY
  rm -rf -- "$SOURCE_STAGE_DIR"
  SOURCE_STAGE_DIR=""
}

on_stage_exec_exit() {
  local rc=$?
  trap - EXIT
  cleanup_source_stage || rc=1
  exit "$rc"
}

stage_source_closure() {
  [[ -d "$TEMP_ROOT" && ! -L "$TEMP_ROOT" ]] || fail "staged-source parent is unavailable"
  require_command mktemp
  require_command rm
  SOURCE_STAGE_DIR="$(mktemp -d "${TEMP_ROOT}/winsvpn-router-source.XXXXXXXX")"
  chmod 0700 "$SOURCE_STAGE_DIR"
  trap on_stage_exec_exit EXIT
  local expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$SCRIPT_DIR" "$SOURCE_STAGE_DIR" "$expected_uid" \
    "$INSTALLER_NAME" "${SOURCE_FILES[@]}" <<'PY' >/dev/null || \
    fail "router source staging failed"
import hashlib
import json
import os
import stat
import sys

source_path, stage_path = sys.argv[1:3]
expected_stage_uid = int(sys.argv[3])
installer_name = sys.argv[4]
names = sys.argv[5:]

if len(names) != len(set(names)) or installer_name not in names:
    raise SystemExit(1)

def identity(info):
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ]

source_lstat = os.stat(source_path, follow_symlinks=False)
source_fd = os.open(
    source_path,
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
stage_fd = os.open(
    stage_path,
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
)
try:
    source_info = os.fstat(source_fd)
    stage_info = os.fstat(stage_fd)
    if identity(source_info) != identity(source_lstat):
        raise SystemExit(1)
    if (
        not stat.S_ISDIR(source_info.st_mode)
        or not stat.S_ISDIR(stage_info.st_mode)
        or stage_info.st_uid != expected_stage_uid
        or stat.S_IMODE(stage_info.st_mode) != 0o700
    ):
        raise SystemExit(1)
    records = {}
    for name in names:
        if not name or "/" in name or name in {".", "..", ".SOURCE_BINDING.json"}:
            raise SystemExit(1)
        source_file = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=source_fd,
        )
        try:
            before = os.fstat(source_file)
            linked_before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if (
                identity(before) != identity(linked_before)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or stat.S_IMODE(before.st_mode) & 0o022
            ):
                raise SystemExit(1)
            if name == installer_name and not stat.S_IMODE(before.st_mode) & 0o100:
                raise SystemExit(1)
            output_mode = 0o755 if name == installer_name else 0o644
            destination = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                output_mode,
                dir_fd=stage_fd,
            )
            digest = hashlib.sha256()
            try:
                while True:
                    chunk = os.read(source_file, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    offset = 0
                    while offset < len(chunk):
                        written = os.write(destination, chunk[offset:])
                        if written <= 0:
                            raise SystemExit(1)
                        offset += written
                os.fchmod(destination, output_mode)
                os.fsync(destination)
                staged_info = os.fstat(destination)
                if (
                    not stat.S_ISREG(staged_info.st_mode)
                    or staged_info.st_uid != expected_stage_uid
                    or staged_info.st_nlink != 1
                    or stat.S_IMODE(staged_info.st_mode) != output_mode
                    or staged_info.st_size != before.st_size
                ):
                    raise SystemExit(1)
            finally:
                os.close(destination)
            after = os.fstat(source_file)
            linked_after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if identity(before) != identity(after) or identity(after) != identity(linked_after):
                raise SystemExit(1)
            records[name] = {"identity": identity(after), "sha256": digest.hexdigest()}
        finally:
            os.close(source_file)
    source_after = os.fstat(source_fd)
    source_linked = os.stat(source_path, follow_symlinks=False)
    if identity(source_info) != identity(source_after) or identity(source_after) != identity(source_linked):
        raise SystemExit(1)
    binding = json.dumps(
        {"source_root_identity": identity(source_after), "files": records},
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    binding_fd = os.open(
        ".SOURCE_BINDING.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=stage_fd,
    )
    try:
        offset = 0
        while offset < len(binding):
            written = os.write(binding_fd, binding[offset:])
            if written <= 0:
                raise SystemExit(1)
            offset += written
        os.fchmod(binding_fd, 0o600)
        os.fsync(binding_fd)
    finally:
        os.close(binding_fd)
    os.fsync(stage_fd)
finally:
    os.close(stage_fd)
    os.close(source_fd)
PY
}

reexec_staged_deploy() {
  stage_source_closure
  exec "${SOURCE_STAGE_DIR}/${INSTALLER_NAME}" --deploy \
    --target-root "$TARGET_ROOT" --env-file "$ENV_FILE" --python "$PYTHON_BIN" \
    --systemctl "$SYSTEMCTL_BIN" --ss "$SS_BIN" \
    --internal-source-origin "$SCRIPT_DIR" \
    --internal-source-binding "${SOURCE_STAGE_DIR}/.SOURCE_BINDING.json"
  fail "could not execute the descriptor-staged router installer"
}

validate_staged_context() {
  [[ "$SCRIPT_DIR" == "$TEMP_ROOT"/winsvpn-router-source.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9] ]] || \
    fail "internal staged-source directory is invalid"
  [[ "$SOURCE_BINDING" == "${SCRIPT_DIR}/.SOURCE_BINDING.json" ]] || \
    fail "internal staged-source binding path is invalid"
  [[ "$SOURCE_ORIGIN" = /* && "$SOURCE_ORIGIN" != *$'\n'* && "$SOURCE_ORIGIN" != "$SCRIPT_DIR" ]] || \
    fail "internal staged-source origin is invalid"
  SOURCE_STAGE_DIR="$SCRIPT_DIR"
  DEPLOY_SOURCE_DIR="$SCRIPT_DIR"
  local expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$SCRIPT_DIR" "$SOURCE_BINDING" "$expected_uid" <<'PY' >/dev/null || \
    fail "internal staged-source custody validation failed"
import os
import stat
import sys
root, binding = sys.argv[1:3]
expected_uid = int(sys.argv[3])
root_info = os.stat(root, follow_symlinks=False)
binding_info = os.stat(binding, follow_symlinks=False)
if (
    not stat.S_ISDIR(root_info.st_mode)
    or stat.S_ISLNK(root_info.st_mode)
    or root_info.st_uid != expected_uid
    or stat.S_IMODE(root_info.st_mode) != 0o700
    or not stat.S_ISREG(binding_info.st_mode)
    or stat.S_ISLNK(binding_info.st_mode)
    or binding_info.st_uid != expected_uid
    or binding_info.st_nlink != 1
    or stat.S_IMODE(binding_info.st_mode) != 0o600
):
    raise SystemExit(1)
PY
}

verify_source_origin_binding() {
  "$PYTHON_BIN" -I - "$SOURCE_ORIGIN" "$SOURCE_STAGE_DIR" \
    "$(basename -- "$SOURCE_BINDING")" "${SOURCE_FILES[@]}" <<'PY' >/dev/null || \
    fail "router source identity changed after staging"
import hashlib
import json
import os
import stat
import sys

source_path, stage_path, binding_name = sys.argv[1:4]
expected_names = sys.argv[4:]

def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

def identity(info):
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ]

stage_fd = os.open(stage_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    binding_fd = os.open(binding_name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=stage_fd)
    try:
        binding_info = os.fstat(binding_fd)
        if not stat.S_ISREG(binding_info.st_mode) or binding_info.st_nlink != 1:
            raise SystemExit(1)
        raw = bytearray()
        while True:
            chunk = os.read(binding_fd, 65536)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > 1024 * 1024:
                raise SystemExit(1)
    finally:
        os.close(binding_fd)
finally:
    os.close(stage_fd)

try:
    binding = json.loads(bytes(raw).decode("ascii"), object_pairs_hook=strict_pairs)
except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if set(binding) != {"source_root_identity", "files"} or set(binding["files"]) != set(expected_names):
    raise SystemExit(1)

source_fd = os.open(source_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    root_before = os.fstat(source_fd)
    if identity(root_before) != binding["source_root_identity"]:
        raise SystemExit(1)
    for name in expected_names:
        record = binding["files"].get(name)
        if not isinstance(record, dict) or set(record) != {"identity", "sha256"}:
            raise SystemExit(1)
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=source_fd)
        try:
            before = os.fstat(descriptor)
            linked_before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if identity(before) != record["identity"] or identity(before) != identity(linked_before):
                raise SystemExit(1)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(descriptor)
            linked_after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if (
                identity(after) != record["identity"]
                or identity(after) != identity(linked_after)
                or digest.hexdigest() != record["sha256"]
            ):
                raise SystemExit(1)
        finally:
            os.close(descriptor)
    root_after = os.fstat(source_fd)
    root_linked = os.stat(source_path, follow_symlinks=False)
    if identity(root_after) != binding["source_root_identity"] or identity(root_after) != identity(root_linked):
        raise SystemExit(1)
finally:
    os.close(source_fd)
PY
}

preflight_requirements() {
  for command in cmp cp flock install mkdir mktemp mv readlink rm; do require_command "$command"; done
  "$SYSTEMCTL_BIN" --version >/dev/null 2>&1 || fail "systemctl validation failed"
}

run_preflight() {
  validate_python
  validate_target_root
  validate_path_ancestors "$ENV_FILE" 0
  validate_path_ancestors "$INSTALL_ROOT" 1
  validate_path_ancestors "$UNIT_PATH" 1
  validate_path_ancestors "$HELPER_PATH" 1
  validate_path_ancestors "$LOCK_PATH" 1
  preflight_requirements
  validate_service_user
  validate_environment
  validate_source "$DEPLOY_SOURCE_DIR"
  validate_gemma_artifact
  validate_vllm_listener
  validate_vllm_served_model
  SOURCE_MANIFEST="$(compute_source_manifest "$DEPLOY_SOURCE_DIR" "${SOURCE_FILES[@]}")"
  RELEASE_ID="$(printf '%s\n' "$SOURCE_MANIFEST" | sha256_text)"
  HELPER_SHA256="$("$PYTHON_BIN" -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
    "${DEPLOY_SOURCE_DIR}/${INSTALLER_NAME}")"
  readonly SOURCE_MANIFEST RELEASE_ID HELPER_SHA256
  printf 'Smart Router preflight: PASS\nRelease ID: %s\nHelper SHA-256: %s\n' \
    "$RELEASE_ID" "$HELPER_SHA256"
}

atomic_replace_file() {
  local source="$1" destination="$2" mode="$3" parent temp
  parent="$(dirname -- "$destination")"
  temp="$(mktemp "${parent}/.$(basename -- "$destination").tmp.XXXXXXXX")"
  install -m "$mode" -- "$source" "$temp"
  if [[ "$TARGET_ROOT" == "/" ]]; then chown 0:0 "$temp"; fi
  mv -f -- "$temp" "$destination"
}

atomic_replace_text() {
  local destination="$1" mode="$2" content="$3" parent temp
  parent="$(dirname -- "$destination")"
  temp="$(mktemp "${parent}/.$(basename -- "$destination").tmp.XXXXXXXX")"
  printf '%s\n' "$content" >"$temp"
  chmod "$mode" "$temp"
  if [[ "$TARGET_ROOT" == "/" ]]; then chown 0:0 "$temp"; fi
  mv -f -- "$temp" "$destination"
}

verify_installed_helper() {
  local expected_sha256="$1" expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$HELPER_PATH" "$TARGET_ROOT" "$expected_uid" "$expected_sha256" <<'PY' >/dev/null || \
    fail "installed Smart Router helper identity verification failed"
import hashlib
import os
import stat
import sys

path, target_root = sys.argv[1:3]
expected_uid = int(sys.argv[3])
expected_sha256 = sys.argv[4]

normalized = os.path.normpath(path)
if not path.startswith("/") or normalized != path:
    raise SystemExit(1)
root_prefix = target_root.rstrip("/")
relative = path[len(root_prefix):] if root_prefix else path
if not relative.startswith("/"):
    raise SystemExit(1)
current_fd = os.open(target_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    components = relative.split("/")[1:]
    for component in components[:-1]:
        next_fd = os.open(
            component,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current_fd,
        )
        info = os.fstat(next_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            os.close(next_fd)
            raise SystemExit(1)
        os.close(current_fd)
        current_fd = next_fd
    leaf = components[-1]
    descriptor = os.open(leaf, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current_fd)
    try:
        before = os.fstat(descriptor)
        linked_before = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            identity(before) != identity(linked_before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_uid
            or stat.S_IMODE(before.st_mode) != 0o755
        ):
            raise SystemExit(1)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        linked_after = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        if (
            identity(before) != identity(after)
            or identity(after) != identity(linked_after)
            or digest.hexdigest() != expected_sha256
        ):
            raise SystemExit(1)
    finally:
        os.close(descriptor)
finally:
    os.close(current_fd)
PY
}

atomic_symlink() {
  "$PYTHON_BIN" -I - "$1" "$2" <<'PY'
import os
import secrets
import sys
target, link = sys.argv[1:]
temporary = os.path.join(os.path.dirname(link), ".current.tmp." + secrets.token_hex(8))
os.symlink(target, temporary)
try:
    os.replace(temporary, link)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

validate_managed_current() {
  if [[ ! -e "$CURRENT_LINK" && ! -L "$CURRENT_LINK" ]]; then
    PREVIOUS_CURRENT_STATE="absent"
    return
  fi
  [[ -L "$CURRENT_LINK" ]] || fail "managed current path is not a symlink"
  PREVIOUS_CURRENT_TARGET="$(readlink -- "$CURRENT_LINK")"
  [[ "$PREVIOUS_CURRENT_TARGET" =~ ^releases/[0-9a-f]{64}$ ]] || fail "managed current symlink has an invalid target"
  [[ -d "${INSTALL_ROOT}/${PREVIOUS_CURRENT_TARGET}" && ! -L "${INSTALL_ROOT}/${PREVIOUS_CURRENT_TARGET}" ]] || \
    fail "managed current symlink target is unavailable"
  PREVIOUS_CURRENT_STATE="present"
}

venv_inventory() {
  local action="$1" release_dir="$2" expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$action" "$release_dir" "$expected_uid" <<'PY' >/dev/null || \
    fail "installed virtual environment inventory validation failed"
import hashlib
import json
import os
import posixpath
import secrets
import stat
import sys

action, release_dir, owner = sys.argv[1:]
owner = int(owner)
if action not in {"seal", "verify"}:
    raise SystemExit(1)
max_files = 100000
max_bytes = 2 * 1024 * 1024 * 1024
max_manifest = 16 * 1024 * 1024
open_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
open_file = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
entries = []
total_bytes = 0


def stable(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def check(info):
    if info.st_uid != owner or stat.S_IMODE(info.st_mode) & 0o6022:
        raise ValueError("unsafe inventory object custody")


def visit(descriptor, relative):
    global total_bytes
    before = os.fstat(descriptor)
    check(before)
    entries.append(["directory", relative, stat.S_IMODE(before.st_mode)])
    for name in sorted(os.listdir(descriptor)):
        if len(entries) >= max_files:
            raise ValueError("inventory entry limit")
        child = name if relative == "." else relative + "/" + name
        info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            if info.st_uid != owner:
                raise ValueError("unsafe link owner")
            target = os.readlink(name, dir_fd=descriptor)
            normalized = posixpath.normpath(posixpath.join(posixpath.dirname(child), target))
            if posixpath.isabs(target) or normalized == ".." or normalized.startswith("../"):
                raise ValueError("virtual environment link leaves inventory")
            if stable(info) != stable(os.stat(name, dir_fd=descriptor, follow_symlinks=False)):
                raise ValueError("link changed during inventory")
            entries.append(["link", child, target])
            continue
        check(info)
        if stat.S_ISDIR(info.st_mode):
            child_fd = os.open(name, open_dir, dir_fd=descriptor)
            try:
                if stable(info) != stable(os.fstat(child_fd)):
                    raise ValueError("directory changed during inventory")
                visit(child_fd, child)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            file_fd = os.open(name, open_file, dir_fd=descriptor)
            try:
                opened = os.fstat(file_fd)
                if stable(info) != stable(opened):
                    raise ValueError("file changed during inventory")
                digest = hashlib.sha256()
                read_bytes = 0
                while True:
                    data = os.read(file_fd, 1024 * 1024)
                    if not data:
                        break
                    read_bytes += len(data)
                    total_bytes += len(data)
                    if total_bytes > max_bytes:
                        raise ValueError("inventory byte limit")
                    digest.update(data)
                if read_bytes != opened.st_size or stable(opened) != stable(os.fstat(file_fd)):
                    raise ValueError("file changed during inventory")
            finally:
                os.close(file_fd)
            entries.append(["file", child, stat.S_IMODE(info.st_mode), info.st_size, digest.hexdigest()])
        else:
            raise ValueError("unsupported inventory object")
    if stable(before) != stable(os.fstat(descriptor)):
        raise ValueError("directory changed during inventory")


root_fd = os.open(release_dir, open_dir)
try:
    check(os.fstat(root_fd))
    venv_fd = os.open(".venv", open_dir, dir_fd=root_fd)
    try:
        visit(venv_fd, ".")
    finally:
        os.close(venv_fd)
    encoded = (json.dumps({"version": 1, "entries": entries}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if len(encoded) > max_manifest:
        raise ValueError("inventory manifest limit")
    manifest = "VENV_MANIFEST.json"
    if action == "verify":
        manifest_fd = os.open(manifest, open_file, dir_fd=root_fd)
        try:
            info = os.fstat(manifest_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > max_manifest):
                raise ValueError("unsafe inventory manifest")
            chunks = bytearray()
            while len(chunks) <= max_manifest:
                data = os.read(manifest_fd, min(1024 * 1024, max_manifest + 1 - len(chunks)))
                if not data:
                    break
                chunks.extend(data)
            if bytes(chunks) != encoded or stable(info) != stable(os.fstat(manifest_fd)):
                raise ValueError("virtual environment inventory differs")
        finally:
            os.close(manifest_fd)
    else:
        try:
            os.stat(manifest, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("refusing to replace an existing sealed inventory")
        temporary = ".venv-inventory-" + secrets.token_hex(16)
        file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                          | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        try:
            with os.fdopen(file_fd, "wb", closefd=True) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, manifest, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
finally:
    os.close(root_fd)
PY
}

verify_release() {
  local release_dir="$1" expected_id="${2-}"
  local expected_uid
  if [[ "$TARGET_ROOT" == "/" ]]; then expected_uid=0; else expected_uid="$(id -u)"; fi
  "$PYTHON_BIN" -I - "$release_dir" "$expected_id" "$expected_uid" <<'PY' >/dev/null || \
    fail "installed release verification failed"
from pathlib import Path
import hashlib
import os
import re
import stat
import sys
root = Path(sys.argv[1])
expected_id = sys.argv[2]
expected_uid = int(sys.argv[3])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(1)
root_info = root.lstat()
if root_info.st_uid != expected_uid or stat.S_IMODE(root_info.st_mode) != 0o755:
    raise SystemExit(1)
manifest_path = root / "SOURCE_MANIFEST.sha256"
info = manifest_path.lstat()
if (
    not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
    or stat.S_IMODE(info.st_mode) != 0o600
):
    raise SystemExit(1)
manifest = manifest_path.read_text(encoding="ascii")
release_id = hashlib.sha256(manifest.encode("ascii")).hexdigest()
if expected_id and release_id != expected_id:
    raise SystemExit(1)
if root.name != release_id:
    raise SystemExit(1)
seen = set()
for raw in manifest.splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", raw)
    if not match or match.group(2) in seen:
        raise SystemExit(1)
    digest, name = match.groups()
    seen.add(name)
    path = root / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(1)
    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o644:
        raise SystemExit(1)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit(1)
declared = {p.name for p in root.iterdir() if p.is_file() and p.name not in {"SOURCE_MANIFEST.sha256", "VENV_MANIFEST.json"}}
if declared != seen:
    raise SystemExit(1)
venv_python = root / ".venv/bin/python"
if not venv_python.exists() or not os.access(venv_python, os.X_OK):
    raise SystemExit(1)
venv_info = venv_python.stat()
if venv_info.st_uid != expected_uid or stat.S_IMODE(venv_info.st_mode) & 0o022:
    raise SystemExit(1)
PY
  venv_inventory verify "$release_dir"
  local venv_python="${release_dir}/.venv/bin/python" version
  version="$("$venv_python" -I -c 'import platform; print(platform.python_version())' 2>/dev/null)" || \
    fail "installed release Python validation failed"
  [[ "$version" == "$REQUIRED_PYTHON_VERSION" ]] || fail "installed release Python version is invalid"
  "$venv_python" -I - "$release_dir/requirements.lock" <<'PY' >/dev/null || \
    fail "installed dependency closure validation failed"
from importlib import metadata
from pathlib import Path
import re
import sys
def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()
expected = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    match = re.match(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)", line)
    if match:
        expected[normalized(match.group(1))] = match.group(2)
installed = {
    normalized(dist.metadata["Name"]): dist.version
    for dist in metadata.distributions()
    if dist.metadata.get("Name") and normalized(dist.metadata["Name"]) != "pip"
}
if installed != expected:
    raise SystemExit(1)
PY
}

build_release() {
  local release_dir="$1" name
  mkdir -- "$release_dir"
  chmod 0755 "$release_dir"
  NEW_RELEASE_DIR="$release_dir"
  for name in "${SOURCE_FILES[@]}"; do
    atomic_replace_file "${DEPLOY_SOURCE_DIR}/${name}" "${release_dir}/${name}" 0644
  done
  "$PYTHON_BIN" -I -m venv --copies --without-scm-ignore-files "${release_dir}/.venv" \
    >"${ROLLBACK_DIR}/venv.log" 2>&1 || fail "Python virtual environment creation failed"
  env -i HOME=/root PATH=/usr/bin:/bin PIP_CONFIG_FILE=/dev/null \
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 PIP_PROGRESS_BAR=off \
    "${release_dir}/.venv/bin/python" -I -m pip install \
      --no-cache-dir --require-hashes --only-binary=:all: \
      -r "${release_dir}/requirements.lock" \
      >"${ROLLBACK_DIR}/pip.log" 2>&1 || fail "hash-locked dependency installation failed"
  "${release_dir}/.venv/bin/python" -I -m pip check \
    >"${ROLLBACK_DIR}/pip-check.log" 2>&1 || fail "installed dependency consistency check failed"
  "${release_dir}/.venv/bin/python" -I - "$release_dir" <<'PY' \
    >"${ROLLBACK_DIR}/import-check.log" 2>&1 || fail "router import validation failed"
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[1])))
import fallback, gemini_client, local_gemma_client, main, provider_common, schemas, security
assert main.app is not None
PY
  atomic_replace_text "${release_dir}/SOURCE_MANIFEST.sha256" 0600 "$SOURCE_MANIFEST"
  if [[ "$TARGET_ROOT" == "/" ]]; then chown -R 0:0 "$release_dir"; fi
  venv_inventory seal "$release_dir"
  verify_release "$release_dir" "$RELEASE_ID"
}

backup_path() {
  local path="$1" label="$2" state_var="$3"
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    printf -v "$state_var" '%s' absent
    return
  fi
  [[ -f "$path" && ! -L "$path" ]] || fail "refusing to replace unsafe path: ${path}"
  cp -p -- "$path" "${ROLLBACK_DIR}/${label}"
  printf -v "$state_var" '%s' present
}

restore_path() {
  local path="$1" label="$2" state="$3"
  if [[ "$state" == "present" ]]; then
    local mode
    mode="$("$PYTHON_BIN" -I -c 'import os,stat,sys; print(format(stat.S_IMODE(os.stat(sys.argv[1], follow_symlinks=False).st_mode), "04o"))' "${ROLLBACK_DIR}/${label}")"
    atomic_replace_file "${ROLLBACK_DIR}/${label}" "$path" "$mode"
  elif [[ "$state" == "absent" ]]; then
    rm -f -- "$path"
  fi
}

systemctl_quiet() {
  "$SYSTEMCTL_BIN" "$@" >/dev/null 2>&1
}

rollback_deploy() {
  local original_rc="${1:-1}" rollback_failed=0
  [[ "$DEPLOY_COMMITTED" -eq 0 && "$ROLLBACK_RUNNING" -eq 0 ]] || return "$original_rc"
  ROLLBACK_RUNNING=1
  set +e
  if [[ "$CURRENT_CHANGED" -eq 1 ]]; then
    if [[ "$PREVIOUS_CURRENT_STATE" == "present" ]]; then
      atomic_symlink "$PREVIOUS_CURRENT_TARGET" "$CURRENT_LINK" || rollback_failed=1
    else
      rm -f -- "$CURRENT_LINK" || rollback_failed=1
    fi
  fi
  if [[ "$UNIT_CHANGED" -eq 1 ]]; then
    restore_path "$UNIT_PATH" unit.previous "$UNIT_BACKUP_STATE" || rollback_failed=1
  fi
  if [[ "$HELPER_CHANGED" -eq 1 ]]; then
    restore_path "$HELPER_PATH" helper.previous "$HELPER_BACKUP_STATE" || rollback_failed=1
  fi
  if [[ "$UNIT_CHANGED" -eq 1 ]]; then systemctl_quiet daemon-reload || rollback_failed=1; fi
  if [[ "$ENABLE_CHANGED" -eq 1 && "$PREVIOUS_ENABLED" -eq 0 ]]; then
    systemctl_quiet disable "$SERVICE_NAME" || rollback_failed=1
  fi
  if [[ "$RESTART_ATTEMPTED" -eq 1 ]]; then
    if [[ "$PREVIOUS_ACTIVE" -eq 1 ]]; then
      systemctl_quiet restart "$SERVICE_NAME" || rollback_failed=1
    else
      systemctl_quiet stop "$SERVICE_NAME" || rollback_failed=1
    fi
  fi
  if [[ -n "$NEW_RELEASE_DIR" && -d "$NEW_RELEASE_DIR" && ! -L "$NEW_RELEASE_DIR" ]]; then
    case "$NEW_RELEASE_DIR" in
      "$RELEASES_DIR"/*)
        local cleanup_name
        cleanup_name="$(basename -- "$NEW_RELEASE_DIR")"
        if [[ "$cleanup_name" =~ ^[0-9a-f]{64}$ ]]; then
          rm -rf -- "$NEW_RELEASE_DIR" || rollback_failed=1
        else
          rollback_failed=1
        fi
        ;;
      *) rollback_failed=1 ;;
    esac
  fi
  if [[ -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" && ! -L "$ROLLBACK_DIR" ]]; then
    rm -rf -- "$ROLLBACK_DIR" || rollback_failed=1
  fi
  if [[ "$rollback_failed" -eq 0 ]]; then
    printf 'ERROR: deployment failed; previous service state was restored\n' >&2
  else
    printf 'ERROR: deployment and rollback failed; manual recovery is required\n' >&2
  fi
  return "$original_rc"
}

on_deploy_exit() {
  local rc=$?
  trap - EXIT
  if [[ "$rc" -ne 0 && "$MODE" == "deploy" && ( -n "$ROLLBACK_DIR" || "$HELPER_CHANGED" -eq 1 || "$UNIT_CHANGED" -eq 1 || "$CURRENT_CHANGED" -eq 1 ) ]]; then
    rollback_deploy "$rc" || true
  fi
  cleanup_source_stage || rc=1
  exit "$rc"
}

verify_deployed_endpoints() {
  "$1" -I - <<'PY' >/dev/null 2>&1 || fail "deployed /live or /ready endpoint did not become ready"
import json
import time
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
required = (
    "http://127.0.0.1:8090/live",
    "http://127.0.0.1:8090/ready",
)
for _ in range(20):
    try:
        ready = True
        for url in required:
            with opener.open(url, timeout=0.5) as response:
                body = json.loads(response.read(4096))
                if not (
                    response.status == 200
                    and set(body) == {"ok", "version"}
                    and body["ok"] is True
                    and isinstance(body["version"], str)
                    and body["version"]
                ):
                    ready = False
                    break
        if ready:
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(0.25)
raise SystemExit(1)
PY
}

run_deploy() {
  if [[ "$STAGED_EXECUTION" -eq 0 ]]; then
    if [[ "$TARGET_ROOT" == "/" && "$(id -u)" -ne 0 ]]; then fail "--deploy requires root"; fi
    reexec_staged_deploy
  fi
  validate_staged_context
  trap on_deploy_exit EXIT
  run_preflight
  install -d -m 0755 -- "$INSTALL_ROOT" "$RELEASES_DIR" "$(dirname -- "$UNIT_PATH")" \
    "$(dirname -- "$HELPER_PATH")" "$(dirname -- "$LOCK_PATH")" "$TEMP_ROOT"
  validate_path_ancestors "$INSTALL_ROOT" 0
  validate_path_ancestors "$UNIT_PATH" 0
  validate_path_ancestors "$HELPER_PATH" 0
  validate_path_ancestors "$LOCK_PATH" 0
  if [[ ! -e "$LOCK_PATH" ]]; then install -m 0600 /dev/null "$LOCK_PATH"; fi
  "$PYTHON_BIN" -I - "$LOCK_PATH" <<'PY' >/dev/null || fail "deployment lock is unsafe"
import os, stat, sys
info = os.lstat(sys.argv[1])
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit(1)
PY
  exec 9<>"$LOCK_PATH"
  flock -n 9 || fail "another Smart Router deployment is in progress"
  ROLLBACK_DIR="$(mktemp -d "${TEMP_ROOT}/winsvpn-router-deploy.XXXXXXXX")"
  chmod 0700 "$ROLLBACK_DIR"
  validate_managed_current
  if systemctl_quiet is-active --quiet "$SERVICE_NAME"; then PREVIOUS_ACTIVE=1; fi
  if systemctl_quiet is-enabled --quiet "$SERVICE_NAME"; then PREVIOUS_ENABLED=1; fi
  backup_path "$UNIT_PATH" unit.previous UNIT_BACKUP_STATE
  backup_path "$HELPER_PATH" helper.previous HELPER_BACKUP_STATE
  local release_dir="${RELEASES_DIR}/${RELEASE_ID}"
  if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    [[ -d "$release_dir" && ! -L "$release_dir" ]] || fail "release ID path is unsafe"
    verify_release "$release_dir" "$RELEASE_ID"
  else
    build_release "$release_dir"
  fi
  verify_source_origin_binding
  local release_helper="${release_dir}/${INSTALLER_NAME}"
  if [[ ! -f "$HELPER_PATH" ]] || ! cmp -s -- "$release_helper" "$HELPER_PATH"; then
    atomic_replace_file "$release_helper" "$HELPER_PATH" 0755
    HELPER_CHANGED=1
  fi
  verify_installed_helper "$HELPER_SHA256"
  local release_unit="${release_dir}/${UNIT_SOURCE_NAME}"
  if [[ ! -f "$UNIT_PATH" ]] || ! cmp -s -- "$release_unit" "$UNIT_PATH"; then
    atomic_replace_file "$release_unit" "$UNIT_PATH" 0644
    UNIT_CHANGED=1
  fi
  validate_installed_unit
  local desired_target="releases/${RELEASE_ID}"
  if [[ "$PREVIOUS_CURRENT_STATE" != "present" || "$PREVIOUS_CURRENT_TARGET" != "$desired_target" ]]; then
    atomic_symlink "$desired_target" "$CURRENT_LINK"
    CURRENT_CHANGED=1
  fi
  if [[ "$UNIT_CHANGED" -eq 1 ]]; then systemctl_quiet daemon-reload || fail "systemd daemon-reload failed"; fi
  if [[ "$PREVIOUS_ENABLED" -eq 0 ]]; then
    ENABLE_CHANGED=1
    systemctl_quiet enable "$SERVICE_NAME" || fail "systemd enable failed"
  fi
  if [[ "$UNIT_CHANGED" -eq 1 || "$CURRENT_CHANGED" -eq 1 ]]; then
    RESTART_ATTEMPTED=1
    systemctl_quiet restart "$SERVICE_NAME" || fail "Smart Router restart failed"
    systemctl_quiet is-active --quiet "$SERVICE_NAME" || fail "Smart Router is not active after restart"
    verify_deployed_endpoints "${release_dir}/.venv/bin/python"
  elif [[ "$PREVIOUS_ACTIVE" -eq 0 ]]; then
    RESTART_ATTEMPTED=1
    systemctl_quiet start "$SERVICE_NAME" || fail "Smart Router start failed"
    systemctl_quiet is-active --quiet "$SERVICE_NAME" || fail "Smart Router is not active after start"
    verify_deployed_endpoints "${release_dir}/.venv/bin/python"
  fi
  DEPLOY_COMMITTED=1
  if [[ -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" && ! -L "$ROLLBACK_DIR" ]]; then rm -rf -- "$ROLLBACK_DIR"; fi
  ROLLBACK_DIR=""
  NEW_RELEASE_DIR=""
  if [[ "$UNIT_CHANGED" -eq 0 && "$HELPER_CHANGED" -eq 0 && "$CURRENT_CHANGED" -eq 0 && "$ENABLE_CHANGED" -eq 0 && "$RESTART_ATTEMPTED" -eq 0 ]]; then
    printf 'Smart Router deploy: PASS (already current, no restart)\n'
  else
    printf 'Smart Router deploy: PASS\n'
  fi
  printf 'Release ID: %s\n' "$RELEASE_ID"
}

run_verify_runtime() {
  validate_python
  validate_target_root
  validate_path_ancestors "$ENV_FILE" 0
  validate_path_ancestors "$INSTALL_ROOT" 0
  validate_environment
  validate_gemma_artifact
  validate_vllm_listener optional
  [[ -L "$CURRENT_LINK" ]] || fail "installed current release is missing"
  local target
  target="$(readlink -- "$CURRENT_LINK")"
  [[ "$target" =~ ^releases/[0-9a-f]{64}$ ]] || fail "installed current release target is invalid"
  verify_release "${INSTALL_ROOT}/${target}" "${target#releases/}"
  validate_installed_unit
  printf 'Smart Router runtime verification: PASS\n'
}

case "$MODE" in
  preflight) run_preflight ;;
  deploy) run_deploy ;;
  verify-runtime) run_verify_runtime ;;
  *) fail "internal mode dispatch error" ;;
esac
