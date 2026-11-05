#!/usr/bin/env bash
set -Eeuo pipefail

STAGE_DIR="${1:-}"
TRANSACTION_PARENT="${2:-/root}"
TARGET=/usr/local/bin/wins-core-sync
TIMER_TARGET=/etc/systemd/system/wins-core-sync.timer
TIMER=wins-core-sync.timer
SERVICE=wins-core-sync.service

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -n "${STAGE_DIR}" ]] || die "usage: $0 STAGE_DIR [TRANSACTION_PARENT]"
STAGE_DIR="$(readlink -f -- "${STAGE_DIR}")"
TRANSACTION_PARENT="$(readlink -f -- "${TRANSACTION_PARENT}")"
[[ -d "${STAGE_DIR}" && -d "${TRANSACTION_PARENT}" ]] || die "stage or transaction parent missing"
[[ -f "${TARGET}" ]] || die "live Core sync agent missing"

python3 - "${STAGE_DIR}" <<'PY'
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

stage = Path(sys.argv[1])
manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
if manifest.get("contract") != "winsvpn-core-sync-staging-v1":
    raise SystemExit("unexpected staging contract")
if manifest.get("readiness_transaction") != "preserve-until-failure":
    raise SystemExit("unexpected readiness transaction")
if manifest.get("secret_material_present") is not False:
    raise SystemExit("staging manifest reports secret material")
if manifest.get("publication_authorized") is not False:
    raise SystemExit("staging manifest must remain non-publication")
files = manifest.get("files")
if not isinstance(files, list) or {item.get("name") for item in files} != {"wins-core-sync", "wins-core-sync.timer"}:
    raise SystemExit("staging manifest file set is not exact")
by_name = {item["name"]: item for item in files}
for name, expected_mode in (("wins-core-sync", "0700"), ("wins-core-sync.timer", "0644")):
    candidate = stage / name
    data = candidate.read_bytes()
    entry = by_name[name]
    if hashlib.sha256(data).hexdigest() != entry.get("sha256") or len(data) != entry.get("size_bytes"):
        raise SystemExit("staged Core sync agent does not match manifest")
    if entry.get("mode") != expected_mode or stat.S_IMODE(candidate.stat().st_mode) & 0o022:
        raise SystemExit("staged Core sync agent mode is unsafe")
candidate = stage / "wins-core-sync"
data = candidate.read_bytes()
text = data.decode("utf-8", errors="strict")
if re.search(r"^\s*register_core false\s*$", text, re.MULTILINE):
    raise SystemExit("transient-unready race is present")
for marker in (
    "register_core false || true",
    "register_core true",
    "trap - EXIT",
    'CORE_SYNC_FAILURE_STAGE="ready-registration"',
):
    if marker not in text:
        raise SystemExit("readiness transaction marker missing")
timer = (stage / "wins-core-sync.timer").read_text(encoding="utf-8", errors="strict")
if ("OnBootSec=3s" not in timer or "OnUnitActiveSec=1s" not in timer
        or "AccuracySec=100ms" not in timer):
    raise SystemExit("bounded Core sync timer marker missing")
PY
bash -n "${STAGE_DIR}/wins-core-sync"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TXN_DIR="${TRANSACTION_PARENT}/winsvpn-core-sync-${STAMP}"
umask 077
mkdir -m 0700 -- "${TXN_DIR}"
cp -a -- "${TARGET}" "${TXN_DIR}/wins-core-sync.preimage"
cp -a -- "${TIMER_TARGET}" "${TXN_DIR}/wins-core-sync.timer.preimage"
PRE_TIMER_ENABLED="$(systemctl is-enabled "${TIMER}" 2>/dev/null || true)"
PRE_TIMER_ACTIVE="$(systemctl is-active "${TIMER}" 2>/dev/null || true)"
ROLLBACK_REQUIRED=1

restore_timer() {
  if [[ "${PRE_TIMER_ENABLED}" == "enabled" ]]; then
    systemctl enable "${TIMER}" >/dev/null 2>&1 || true
  else
    systemctl disable "${TIMER}" >/dev/null 2>&1 || true
  fi
  if [[ "${PRE_TIMER_ACTIVE}" == "active" ]]; then
    systemctl start "${TIMER}" >/dev/null 2>&1 || true
  else
    systemctl stop "${TIMER}" >/dev/null 2>&1 || true
  fi
}

verify_timer_state() {
  local current_enabled current_active
  current_enabled="$(systemctl is-enabled "${TIMER}" 2>/dev/null || true)"
  current_active="$(systemctl is-active "${TIMER}" 2>/dev/null || true)"
  if [[ "${current_enabled}" != "${PRE_TIMER_ENABLED}" ]]; then
    printf 'ERROR: Core sync timer enabled state changed: expected=%s actual=%s\n' \
      "${PRE_TIMER_ENABLED}" "${current_enabled}" >&2
    return 1
  fi
  if [[ "${current_active}" != "${PRE_TIMER_ACTIVE}" ]]; then
    printf 'ERROR: Core sync timer active state changed: expected=%s actual=%s\n' \
      "${PRE_TIMER_ACTIVE}" "${current_active}" >&2
    return 1
  fi
}

rollback() {
  rc=$?
  trap - ERR INT TERM EXIT
  if [[ "${ROLLBACK_REQUIRED}" -eq 1 ]]; then
    systemctl stop "${TIMER}" "${SERVICE}" >/dev/null 2>&1 || true
    install -o root -g root -m "$(stat -c '%a' "${TXN_DIR}/wins-core-sync.preimage")" \
      -- "${TXN_DIR}/wins-core-sync.preimage" "${TARGET}"
    install -o root -g root -m "$(stat -c '%a' "${TXN_DIR}/wins-core-sync.timer.preimage")" \
      -- "${TXN_DIR}/wins-core-sync.timer.preimage" "${TIMER_TARGET}"
    systemctl daemon-reload >/dev/null 2>&1 || true
    restore_timer
  fi
  exit "${rc}"
}
trap rollback ERR INT TERM EXIT

systemctl stop "${TIMER}" "${SERVICE}"
install -o root -g root -m 0700 -- "${STAGE_DIR}/wins-core-sync" "${TARGET}"
install -o root -g root -m 0644 -- "${STAGE_DIR}/wins-core-sync.timer" "${TIMER_TARGET}"
bash -n "${TARGET}"
systemctl daemon-reload
timeout --signal=TERM --kill-after=10s 120s systemctl start "${SERVICE}"
[[ "$(systemctl show "${SERVICE}" -p Result --value)" == "success" ]]
[[ "$(systemctl show "${SERVICE}" -p ExecMainStatus --value)" == "0" ]]
restore_timer
verify_timer_state

python3 - "${TXN_DIR}/commit.json" "${TXN_DIR}" "${STAGE_DIR}/manifest.json" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

destination, transaction, manifest = sys.argv[1:]
payload = {
    "committed_at_utc": datetime.now(timezone.utc).isoformat(),
    "contract": "winsvpn-core-sync-live-transaction-v1",
    "readiness_transaction": "preserve-until-failure",
    "staging_manifest_sha256": hashlib.sha256(Path(manifest).read_bytes()).hexdigest(),
    "transaction_dir": transaction,
}
Path(destination).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 0600 "${TXN_DIR}/commit.json"
ROLLBACK_REQUIRED=0
trap - ERR INT TERM EXIT
printf 'Committed Core sync transaction: %s\n' "${TXN_DIR}"
