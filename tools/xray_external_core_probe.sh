#!/usr/bin/env bash
set -euo pipefail

err() { printf '%s\n' "$*" >&2; }

# Newest upstream Xray-core tag reviewed for this tree (owner decision
# 2026-10-06; upstream flags it GitHub pre-release), with the matching
# linux-64 archive digest and extracted executable digest.
wins_require_reviewed_xray_pin() {
  local requested_version="${1:-}"
  local requested_hash="${2:-}"
  local reviewed_version="26.9.30"
  local reviewed_hash="f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e"
  if [[ "${requested_version}" != "${reviewed_version}" ]]; then
    err "Caller env may not select Xray ${requested_version}; release/deployment requires reviewed v${reviewed_version}."
    return 1
  fi
  if [[ "${requested_hash}" != "${reviewed_hash}" ]]; then
    err "Xray archive hash does not match the reviewed v${reviewed_version} digest; refusing mismatched pin."
    return 1
  fi
  return 0
}

wins_lock_deployed_xray_pin() {
  if [[ -n "${WINS_XRAY_PIN_SELFTEST_VERSION:-}" || -n "${WINS_XRAY_PIN_SELFTEST_SHA256:-}" ]]; then
    err "WINS_XRAY_PIN_SELFTEST_* is a non-release fixture and cannot select an Xray pin on a release/deployment path."
    return 1
  fi
  wins_require_reviewed_xray_pin "${1:-}" "${2:-}"
}

wins_self_test_xray_pin() {
  local version hash
  version="${WINS_XRAY_PIN_SELFTEST_VERSION:-${xray_version:-${XRAY_VERSION:-26.9.30}}}"
  hash="${WINS_XRAY_PIN_SELFTEST_SHA256:-${xray_sha256:-${XRAY_LINUX_64_SHA256:-f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e}}}"
  wins_require_reviewed_xray_pin "${version}" "${hash}"
}

wins_xray_file_sha256() {
  local path="${1:-}" digest=""
  if [[ -x /usr/bin/sha256sum ]]; then
    digest="$(/usr/bin/sha256sum "${path}" 2>/dev/null)"
  elif [[ -x /usr/bin/shasum ]]; then
    digest="$(/usr/bin/shasum -a 256 "${path}" 2>/dev/null)"
  else
    err "sha256sum is required to attest the Xray executable."
    return 1
  fi
  digest="${digest%% *}"
  if [[ ! "${digest}" =~ ^[0-9a-f]{64}$ ]]; then
    err "Unable to hash Xray executable ${path}."
    return 1
  fi
  printf '%s\n' "${digest}"
}

wins_xray_file_identity() {
  local path="${1:-}" ident="" nlink=""
  if [[ -L "${path}" ]]; then
    err "Xray executable must not be a symlink (${path})."
    return 1
  fi
  if [[ ! -f "${path}" ]]; then
    err "Reviewed Xray executable is missing (${path})."
    return 1
  fi
  if [[ ! -x /usr/bin/stat ]]; then
    err "stat is required to attest the Xray executable identity."
    return 1
  fi
  ident="$(/usr/bin/stat -c '%d:%i:%h:%s' "${path}" 2>/dev/null || true)"
  if [[ ! "${ident}" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]]; then
    ident="$(/usr/bin/stat -f '%d:%i:%l:%z' "${path}" 2>/dev/null || true)"
  fi
  if [[ ! "${ident}" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+$ ]]; then
    err "Unable to stat Xray executable ${path}."
    return 1
  fi
  nlink="${ident#*:}"
  nlink="${nlink#*:}"
  nlink="${nlink%%:*}"
  if [[ "${nlink}" != "1" ]]; then
    err "Xray executable must be a regular non-hardlinked file (${path})."
    return 1
  fi
  printf '%s\n' "${ident}"
}

wins_reviewed_xray_binary_installed() {
  local path="${1:-/usr/local/bin/xray}"
  local reviewed_hash="96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7"
  local actual="" before="" after=""
  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  before="$(wins_xray_file_identity "${path}" 2>/dev/null)" || return 1
  actual="$(wins_xray_file_sha256 "${path}" 2>/dev/null)" || return 1
  after="$(wins_xray_file_identity "${path}" 2>/dev/null)" || return 1
  [[ "${before}" == "${after}" ]] || return 1
  [[ "${actual}" == "${reviewed_hash}" ]]
}

wins_require_reviewed_xray_binary() {
  local path="${1:-/usr/local/bin/xray}"
  local reviewed_hash="96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7"
  local actual="" before="" after=""
  before="$(wins_xray_file_identity "${path}")" || return 1
  actual="$(wins_xray_file_sha256 "${path}")" || return 1
  after="$(wins_xray_file_identity "${path}")" || return 1
  if [[ "${before}" != "${after}" ]]; then
    err "Xray executable identity changed during attestation (${path})."
    return 1
  fi
  if [[ "${actual}" != "${reviewed_hash}" ]]; then
    err "Installed Xray executable does not match reviewed v26.9.30 linux-64 bytes; refusing ${path}."
    return 1
  fi
  return 0
}

wins_xray_linux_fd_exec() {
  local path="${1:-}"
  shift
  if [[ "$(/usr/bin/uname -s 2>/dev/null || true)" != "Linux" ]]; then
    err "Xray bind-exec requires Linux; refusing path exec of ${path}."
    return 1
  fi
  if [[ ! -d /proc/self/fd ]]; then
    err "Linux /proc/self/fd is required to bind-execute attested Xray; refusing."
    return 1
  fi
  if [[ ! -x /usr/bin/python3 ]]; then
    err "/usr/bin/python3 is required to bind-execute attested Xray; refusing."
    return 1
  fi
  /usr/bin/python3 - "${path}" "$@" <<'PY'
import os
import shutil
import stat
import subprocess
import sys
import tempfile

path = sys.argv[1]
argv = ["xray"] + sys.argv[2:]
reviewed = "96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7"
if os.uname()[0] != "Linux":
    sys.stderr.write("Xray bind-exec requires Linux; refusing.\n")
    raise SystemExit(1)
if not hasattr(os, "O_NOFOLLOW"):
    sys.stderr.write("O_NOFOLLOW is required to open Xray without following links; refusing.\n")
    raise SystemExit(1)
if not os.access("/usr/bin/sha256sum", os.X_OK):
    sys.stderr.write("sha256sum is required to attest the Xray executable.\n")
    raise SystemExit(1)
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
except OSError:
    sys.stderr.write("Unable to open Xray executable without following links.\n")
    raise SystemExit(1)
info = os.fstat(fd)
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    sys.stderr.write("Xray executable must be a regular non-hardlinked file.\n")
    raise SystemExit(1)
proc_path = "/proc/%d/fd/%d" % (os.getpid(), fd)
try:
    hashed = subprocess.check_output(["/usr/bin/sha256sum", proc_path], text=True)
except (OSError, subprocess.CalledProcessError):
    sys.stderr.write("Unable to hash Xray executable descriptor.\n")
    raise SystemExit(1)
digest = hashed.split()[0]
if digest != reviewed:
    sys.stderr.write("Installed Xray executable does not match reviewed v26.9.30 linux-64 bytes; refusing descriptor exec.\n")
    raise SystemExit(1)
info_after = os.fstat(fd)
if (info.st_dev, info.st_ino, info.st_nlink, info.st_size) != (info_after.st_dev, info_after.st_ino, info_after.st_nlink, info_after.st_size):
    sys.stderr.write("Xray executable identity changed during descriptor attestation.\n")
    raise SystemExit(1)
if os.path.isdir("/proc/self/fd"):
    try:
        os.execv("/proc/self/fd/%d" % fd, argv)
    except OSError:
        pass
if os.geteuid() != 0 or not os.path.isdir("/root"):
    sys.stderr.write("Linux descriptor-bound Xray execution is unavailable; refusing path exec.\n")
    raise SystemExit(1)
snap_dir = tempfile.mkdtemp(prefix="wins-xray-exec.", dir="/root")
os.chmod(snap_dir, 0o700)
snap_path = snap_dir + "/xray"
os.lseek(fd, 0, os.SEEK_SET)
out = os.open(snap_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
while True:
    chunk = os.read(fd, 1024 * 1024)
    if not chunk:
        break
    os.write(out, chunk)
os.close(out)
os.close(fd)
snap_fd = os.open(snap_path, os.O_RDONLY | os.O_NOFOLLOW)
snap_info = os.fstat(snap_fd)
if not stat.S_ISREG(snap_info.st_mode) or snap_info.st_nlink != 1 or snap_info.st_uid != 0:
    shutil.rmtree(snap_dir, ignore_errors=True)
    sys.stderr.write("Xray snapshot is not a root-owned regular file; refusing.\n")
    raise SystemExit(1)
snap_proc = "/proc/%d/fd/%d" % (os.getpid(), snap_fd)
try:
    snap_hashed = subprocess.check_output(["/usr/bin/sha256sum", snap_proc], text=True)
except (OSError, subprocess.CalledProcessError):
    shutil.rmtree(snap_dir, ignore_errors=True)
    sys.stderr.write("Unable to hash Xray snapshot descriptor.\n")
    raise SystemExit(1)
if snap_hashed.split()[0] != reviewed:
    shutil.rmtree(snap_dir, ignore_errors=True)
    sys.stderr.write("Xray snapshot does not match reviewed v26.9.30 linux-64 bytes; refusing.\n")
    raise SystemExit(1)
try:
    os.execv("/proc/self/fd/%d" % snap_fd, argv)
except OSError:
    pass
try:
    os.execv(snap_path, argv)
except OSError:
    shutil.rmtree(snap_dir, ignore_errors=True)
    sys.stderr.write("Unable to execute attested Xray snapshot; refusing.\n")
    raise SystemExit(1)
PY
}

wins_exec_reviewed_xray() {
  local path="/usr/local/bin/xray"
  local before="" after="" rc=0
  if [[ "${1:-}" == /* ]]; then
    path="$1"
    shift
  fi
  wins_require_reviewed_xray_binary "${path}" || return 1
  before="$(wins_xray_file_identity "${path}")" || return 1
  wins_xray_linux_fd_exec "${path}" "$@" || rc=$?
  after="$(wins_xray_file_identity "${path}")" || return 1
  if [[ "${before}" != "${after}" ]]; then
    err "Xray executable identity changed during execution (${path})."
    return 1
  fi
  wins_require_reviewed_xray_binary "${path}" || return 1
  return "${rc}"
}

wins_require_linux_amd64_xray_preflight() {
  local kernel machine
  kernel="$(/usr/bin/uname -s 2>/dev/null || true)"
  machine="$(/usr/bin/uname -m 2>/dev/null || true)"
  if [[ "${kernel}" != "Linux" ]]; then
    err "Xray linux-64 archive requires Linux; found ${kernel:-unknown}."
    return 1
  fi
  case "${machine}" in
    x86_64|amd64) return 0 ;;
  esac
  err "Xray linux-64 archive requires amd64; found ${machine:-unknown}."
  return 1
}

wins_xray_pin_self_test_requested() {
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == "--self-test-xray-pin" ]]; then
      return 0
    fi
  done
  return 1
}

wins_dispatch_xray_pin_self_test() {
  if [[ "$#" -ne 1 || "${1:-}" != "--self-test-xray-pin" ]]; then
    err "--self-test-xray-pin must be the sole argument; mixed or surplus arguments are refused before any network or sudo path."
    return 2
  fi
  if wins_self_test_xray_pin; then
    printf 'reviewed_xray_pin=%s\n' "26.9.30"
    return 0
  fi
  return 1
}

if wins_xray_pin_self_test_requested "$@"; then
  wins_dispatch_xray_pin_self_test "$@"
  exit $?
fi
if [[ "$#" -ne 0 ]]; then
  err "Usage: xray_external_core_probe.sh [--self-test-xray-pin]"
  exit 2
fi

xray_version="${XRAY_VERSION:-26.9.30}"
xray_sha256="${XRAY_LINUX_64_SHA256:-f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e}"
xray_bin_sha256="${XRAY_LINUX_64_BIN_SHA256:-96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7}"

wins_lock_deployed_xray_pin "${xray_version}" "${xray_sha256}" || exit 1
xray_version="26.9.30"
xray_sha256="f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e"
xray_bin_sha256="96efb28b8b2086275598dc46e73b5dc340da948b4e1ccc4f1719f83f67b793a7"
wins_require_linux_amd64_xray_preflight || exit 1

database="${WINS_HUB_DATABASE:-/root/vpn_auth/vpn_users.db}"

work_dir="$(mktemp -d)"
xray_pid=""

cleanup() {
  if [[ -n "${xray_pid}" ]]; then
    /usr/bin/pkill -P "${xray_pid}" >/dev/null 2>&1 || true
    kill "${xray_pid}" >/dev/null 2>&1 || true
  fi
  rm -rf "${work_dir}"
}
trap cleanup EXIT

curl -fsSL --retry 4 --retry-all-errors --connect-timeout 10 --max-time 180 \
  -o "${work_dir}/xray.zip" \
  "https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/Xray-linux-64.zip"
printf '%s  %s\n' "${xray_sha256}" "${work_dir}/xray.zip" | /usr/bin/sha256sum -c - >/dev/null
unzip -q "${work_dir}/xray.zip" xray -d "${work_dir}"
chmod 700 "${work_dir}/xray"
wins_require_reviewed_xray_binary "${work_dir}/xray" || exit 1

python3 - "${database}" "${work_dir}/client.json" <<'PY'
import json
import sqlite3
import sys
from urllib.parse import urlsplit

database, destination = sys.argv[1:]
connection = sqlite3.connect(database)
connection.row_factory = sqlite3.Row
row = connection.execute(
    """
    SELECT stealth_endpoint, xray_uuid, xray_path, xray_security
      FROM core_servers
     WHERE status = 'online'
     ORDER BY rowid DESC
     LIMIT 1
    """
).fetchone()
if row is None:
    raise SystemExit("No online Core server is registered")

endpoint = str(row["stealth_endpoint"] or "").strip()
parsed = urlsplit("//" + endpoint)
host = parsed.hostname or ""
port = parsed.port or 80
path = str(row["xray_path"] or "/wins-core-tunnel").strip()
security = str(row["xray_security"] or "none").strip().lower()
uuid = str(row["xray_uuid"] or "").strip()
if not host or not uuid or security not in {"none", "tls"}:
    raise SystemExit("The registered Core Xray transport is incomplete")

stream = {
    "network": "ws",
    "security": security,
    "wsSettings": {"path": path, "headers": {"Host": host}},
    "sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True},
}
if security == "tls":
    stream["tlsSettings"] = {"serverName": host, "allowInsecure": False}

config = {
    "log": {"loglevel": "debug"},
    "inbounds": [{
        "tag": "external-core-probe-in",
        "listen": "127.0.0.1",
        "port": 42113,
        "protocol": "tunnel",
        "settings": {
            "network": "udp",
            "address": "127.0.0.1",
            "port": 9210,
            "followRedirect": False,
            "userLevel": 0,
        },
    }],
    "outbounds": [{
        "tag": "external-core-probe-out",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": host,
            "port": port,
            "users": [{"id": uuid, "encryption": "none", "level": 0}],
        }]},
        "streamSettings": stream,
        "targetStrategy": "UseIPv4",
        "mux": {
            "enabled": False,
            "concurrency": 0,
            "xudpConcurrency": 0,
            "xudpProxyUDP443": "skip",
        },
    }],
    "routing": {"rules": [{
        "type": "field",
        "inboundTag": ["external-core-probe-in"],
        "outboundTag": "external-core-probe-out",
    }]},
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(config, handle)
PY
chmod 600 "${work_dir}/client.json"

wins_exec_reviewed_xray "${work_dir}/xray" run -test -config "${work_dir}/client.json" >/dev/null 2>&1
wins_require_reviewed_xray_binary "${work_dir}/xray" || exit 1
before="$(wins_xray_file_identity "${work_dir}/xray")" || exit 1
wins_xray_linux_fd_exec "${work_dir}/xray" run -config "${work_dir}/client.json" >"${work_dir}/client.log" 2>&1 &
xray_pid=$!
after="$(wins_xray_file_identity "${work_dir}/xray")" || exit 1
if [[ "${before}" != "${after}" ]]; then
  err "Xray executable identity changed during probe execution (${work_dir}/xray)."
  exit 1
fi
wins_require_reviewed_xray_binary "${work_dir}/xray" || exit 1
sleep 1

python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"wins-external-core-probe", ("127.0.0.1", 42113))
sock.close()
PY
sleep 8

if ! kill -0 "${xray_pid}" >/dev/null 2>&1; then
  echo XRAY_EXTERNAL_CORE_PROCESS=EXITED
else
  echo XRAY_EXTERNAL_CORE_PROCESS=ACTIVE
fi
sed -E \
  -e 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<uuid>/g' \
  -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<ipv4>/g' \
  "${work_dir}/client.log" | tail -n 100
