#!/usr/bin/env bash
set -Eeuo pipefail

# Apply a staged Win's VPN threat-triage engine to an existing Control Hub.
# The staging directory must be produced by stage_control_triage_engine.py.
# This helper never changes Suricata rules; their hashes are enforced across
# the transaction. A root-only transaction directory retains the preimage for
# operator-directed rollback and audit.

STAGE_DIR="${1:-}"
TRANSACTION_PARENT="${2:-/root}"
DB_PATH="${SECURITY_EVENTS_DB:-/var/lib/wins-security-alerts/security_events.db}"
RULE_FILES=(
  /var/lib/suricata/rules/suricata.rules
  /var/lib/suricata/rules/wins-local.rules
)
TARGET_FILES=(
  /usr/local/lib/wins_threat_triage.py
  /usr/local/bin/wins-threat-triage
  /etc/systemd/system/wins-threat-triage-report.service
  /etc/systemd/system/wins-threat-triage-report.timer
)
STAGED_NAMES=(
  wins_threat_triage.py
  wins-threat-triage
  wins-threat-triage-report.service
  wins-threat-triage-report.timer
)
WATCH_UNITS=(
  wins-security-alert-monitor.timer
  wins-threat-triage-report.timer
)
QUIESCE_UNITS=(
  wins-security-alert-monitor.timer
  wins-threat-triage-report.timer
  wins-security-alert-monitor.service
  wins-threat-triage-report.service
)

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ -n "${STAGE_DIR}" ]] || die "usage: $0 STAGE_DIR [TRANSACTION_PARENT]"
STAGE_DIR="$(readlink -f -- "${STAGE_DIR}")"
TRANSACTION_PARENT="$(readlink -f -- "${TRANSACTION_PARENT}")"
[[ -d "${STAGE_DIR}" ]] || die "staging directory not found"
[[ -d "${TRANSACTION_PARENT}" ]] || die "transaction parent not found"
[[ "${STAGE_DIR}" != "${TRANSACTION_PARENT}" ]] || die "staging and transaction directories must differ"
[[ -f "${DB_PATH}" ]] || die "security-events database not found"
for path in "${RULE_FILES[@]}"; do
  [[ -f "${path}" ]] || die "configured Suricata rule file not found: ${path}"
done

python3 - "${STAGE_DIR}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

stage = Path(sys.argv[1])
manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
if manifest.get("contract") != "winsvpn-control-triage-staging-v1":
    raise SystemExit("unexpected staging contract")
if manifest.get("model_version") != "wins-triage-v3-local-health-context":
    raise SystemExit("unexpected triage model")
if manifest.get("publication_authorized") is not False:
    raise SystemExit("staging manifest must remain non-publication")
if manifest.get("secret_material_present") is not False:
    raise SystemExit("staging manifest reports secret material")

expected = {
    "wins_threat_triage.py": "0600",
    "wins-threat-triage": "0700",
    "wins-threat-triage-report.service": "0644",
    "wins-threat-triage-report.timer": "0644",
}
entries = manifest.get("files")
if not isinstance(entries, list) or {e.get("name") for e in entries} != set(expected):
    raise SystemExit("staging manifest file set is not exact")
for entry in entries:
    name = entry["name"]
    path = stage / name
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
        raise SystemExit(f"staged hash mismatch: {name}")
    if len(data) != entry.get("size_bytes"):
        raise SystemExit(f"staged size mismatch: {name}")
    if entry.get("mode") != expected[name]:
        raise SystemExit(f"unexpected declared mode: {name}")
    if stat.S_IMODE(path.stat().st_mode) & 0o022:
        raise SystemExit(f"staged file is group/world writable: {name}")
PY

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TXN_DIR="${TRANSACTION_PARENT}/winsvpn-triage-v3-${STAMP}"
umask 077
mkdir -m 0700 -- "${TXN_DIR}"
mkdir -m 0700 -- "${TXN_DIR}/preimage"
STATE_FILE="${TXN_DIR}/unit-state.tsv"
RULE_HASHES="${TXN_DIR}/suricata-rules.sha256"
PRE_COUNTS="${TXN_DIR}/pre-counts.json"
POST_COUNTS="${TXN_DIR}/post-counts.json"
RECLASSIFY_RESULT="${TXN_DIR}/reclassify.json"
REPORT_RESULT="${TXN_DIR}/report.json"
COMMIT_FILE="${TXN_DIR}/commit.json"
DB_BACKUP="${TXN_DIR}/security_events.preimage.db"
ROLLBACK_REQUIRED=1

for index in "${!TARGET_FILES[@]}"; do
  target="${TARGET_FILES[index]}"
  name="${STAGED_NAMES[index]}"
  [[ -f "${target}" ]] || die "live target missing: ${target}"
  cp -a -- "${target}" "${TXN_DIR}/preimage/${name}"
done

: > "${STATE_FILE}"
for unit in "${WATCH_UNITS[@]}"; do
  enabled="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  active="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  printf '%s\t%s\t%s\n' "${unit}" "${enabled}" "${active}" >> "${STATE_FILE}"
done
sha256sum -- "${RULE_FILES[@]}" > "${RULE_HASHES}"

db_counts() {
  local destination="$1"
  python3 - "${DB_PATH}" "${destination}" <<'PY'
import json
import sqlite3
import sys

db, destination = sys.argv[1:]
conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
try:
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    events = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    feedback = conn.execute("SELECT COUNT(*) FROM security_feedback").fetchone()[0]
    human = conn.execute(
        "SELECT COUNT(*) FROM security_events "
        "WHERE COALESCE(triage_feedback_state,'') LIKE 'human_confirmed:%'"
    ).fetchone()[0]
finally:
    conn.close()
payload = {
    "integrity": integrity,
    "security_events": events,
    "security_feedback": feedback,
    "human_confirmed": human,
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
    handle.write("\n")
PY
}

restore_unit_state() {
  while IFS=$'\t' read -r unit enabled active; do
    if [[ "${enabled}" == "enabled" ]]; then
      systemctl enable "${unit}" >/dev/null 2>&1 || true
    else
      systemctl disable "${unit}" >/dev/null 2>&1 || true
    fi
    if [[ "${active}" == "active" ]]; then
      systemctl start "${unit}" >/dev/null 2>&1 || true
    else
      systemctl stop "${unit}" >/dev/null 2>&1 || true
    fi
  done < "${STATE_FILE}"
}

rollback() {
  local rc=$?
  trap - ERR INT TERM EXIT
  if [[ "${ROLLBACK_REQUIRED}" -eq 1 ]]; then
    printf 'Transaction failed; restoring preimage from %s\n' "${TXN_DIR}" >&2
    systemctl stop "${QUIESCE_UNITS[@]}" >/dev/null 2>&1 || true
    for index in "${!TARGET_FILES[@]}"; do
      install -o root -g root -m "$(stat -c '%a' "${TXN_DIR}/preimage/${STAGED_NAMES[index]}")" \
        -- "${TXN_DIR}/preimage/${STAGED_NAMES[index]}" "${TARGET_FILES[index]}"
    done
    if [[ -f "${DB_BACKUP}" ]]; then
      db_uid="$(stat -c '%u' "${DB_PATH}")"
      db_gid="$(stat -c '%g' "${DB_PATH}")"
      db_mode="$(stat -c '%a' "${DB_PATH}")"
      rm -f -- "${DB_PATH}-wal" "${DB_PATH}-shm"
      install -o "${db_uid}" -g "${db_gid}" -m "${db_mode}" -- "${DB_BACKUP}" "${DB_PATH}"
    fi
    systemctl daemon-reload || true
    restore_unit_state
  fi
  exit "${rc}"
}
trap rollback ERR INT TERM EXIT

systemctl stop "${QUIESCE_UNITS[@]}"
db_counts "${PRE_COUNTS}"
python3 - "${DB_PATH}" "${DB_BACKUP}" <<'PY'
import sqlite3
import sys

source_path, backup_path = sys.argv[1:]
source = sqlite3.connect(source_path)
backup = sqlite3.connect(backup_path)
try:
    source.execute("PRAGMA wal_checkpoint(FULL)")
    source.backup(backup)
    if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("SQLite backup integrity check failed")
finally:
    backup.close()
    source.close()
PY
chmod 0600 "${DB_BACKUP}"

install -o root -g root -m 0600 -- "${STAGE_DIR}/wins_threat_triage.py" /usr/local/lib/wins_threat_triage.py
install -o root -g root -m 0700 -- "${STAGE_DIR}/wins-threat-triage" /usr/local/bin/wins-threat-triage
install -o root -g root -m 0644 -- "${STAGE_DIR}/wins-threat-triage-report.service" /etc/systemd/system/wins-threat-triage-report.service
install -o root -g root -m 0644 -- "${STAGE_DIR}/wins-threat-triage-report.timer" /etc/systemd/system/wins-threat-triage-report.timer
python3 -m py_compile /usr/local/lib/wins_threat_triage.py /usr/local/bin/wins-threat-triage
systemd-analyze verify /etc/systemd/system/wins-threat-triage-report.service /etc/systemd/system/wins-threat-triage-report.timer
systemctl daemon-reload

/usr/local/bin/wins-threat-triage reclassify --limit 50000 --include-stale > "${RECLASSIFY_RESULT}"
/usr/local/bin/wins-threat-triage report --hours 24 > "${REPORT_RESULT}"
python3 - "${RECLASSIFY_RESULT}" "${REPORT_RESULT}" <<'PY'
import json
import sys

reclassified = json.load(open(sys.argv[1], encoding="utf-8"))
report = json.load(open(sys.argv[2], encoding="utf-8"))
expected = "wins-triage-v3-local-health-context"
if reclassified.get("model_version") != expected:
    raise SystemExit("reclassify model mismatch")
if report.get("model_version") != expected:
    raise SystemExit("report model mismatch")
if not isinstance(report.get("counts"), dict):
    raise SystemExit("report counts missing")
PY

db_counts "${POST_COUNTS}"
python3 - "${PRE_COUNTS}" "${POST_COUNTS}" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
if before.get("integrity") != "ok" or after.get("integrity") != "ok":
    raise SystemExit("database integrity check failed")
for key in ("security_events", "security_feedback", "human_confirmed"):
    if before.get(key) != after.get(key):
        raise SystemExit(f"database invariant changed: {key}")
PY
sha256sum -c --strict "${RULE_HASHES}"
systemctl is-active --quiet suricata.service

restore_unit_state
systemctl start wins-threat-triage-report.service
[[ "$(systemctl show wins-threat-triage-report.service -p Result --value)" == "success" ]]
systemctl is-active --quiet suricata.service
systemctl is-active --quiet wins-security-alert-monitor.timer
systemctl is-active --quiet wins-threat-triage-report.timer
sha256sum -c --strict "${RULE_HASHES}"

python3 - "${COMMIT_FILE}" "${TXN_DIR}" "${STAGE_DIR}/manifest.json" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

destination, transaction_dir, manifest_path = sys.argv[1:]
manifest_bytes = Path(manifest_path).read_bytes()
payload = {
    "committed_at_utc": datetime.now(timezone.utc).isoformat(),
    "contract": "winsvpn-control-triage-live-transaction-v1",
    "model_version": "wins-triage-v3-local-health-context",
    "staging_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "suricata_rules_unchanged": True,
    "transaction_dir": transaction_dir,
}
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
chmod 0600 "${COMMIT_FILE}"
ROLLBACK_REQUIRED=0
trap - ERR INT TERM EXIT
printf 'Committed triage v3 transaction: %s\n' "${TXN_DIR}"
