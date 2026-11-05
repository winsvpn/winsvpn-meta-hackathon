#!/usr/bin/env bash
# Win's VPN Control Hub Automated Daily Backup
# Generates transaction-consistent snapshot, AES-256 encryption, and local retention pruning.

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/winsvpn}"
LOG_FILE="/var/log/wins-hub-backup.log"
DATE_STAMP="$(date -u +'%Y%m%d_%H%M%SZ')"
RETENTION_DAYS=30
RETENTION_MONTHS=12
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/etc/winsvpn/backup_key.bin}"

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "${LOG_FILE}"
}

mkdir -p "${BACKUP_DIR}/daily" "${BACKUP_DIR}/monthly"
chmod 700 "${BACKUP_DIR}"

log "Starting Win's VPN Hub daily automated backup..."

# Ensure encryption key exists
if [[ ! -f "${ENCRYPTION_KEY_FILE}" ]]; then
  log "Generating AES-256 backup encryption key at ${ENCRYPTION_KEY_FILE}"
  mkdir -p "$(dirname "${ENCRYPTION_KEY_FILE}")"
  openssl rand -hex 32 > "${ENCRYPTION_KEY_FILE}"
  chmod 600 "${ENCRYPTION_KEY_FILE}"
fi

RAW_DUMP="/tmp/wins_hub_dump_${DATE_STAMP}.dump"

if command -v pg_dump >/dev/null 2>&1 && [[ -n "${DATABASE_URL:-}" || -n "${PGDATABASE:-}" ]]; then
  log "Executing PostgreSQL transaction-consistent snapshot..."
  pg_dump -Fc --no-owner --no-privileges "${DATABASE_URL:-wins_vpn}" > "${RAW_DUMP}"
  pg_restore --list "${RAW_DUMP}" >/dev/null
  log "PostgreSQL dump integrity verified."
elif [[ -f "/root/vpn_auth/vpn_users.db" ]]; then
  log "Using SQLite backup for /root/vpn_auth/vpn_users.db..."
  sqlite3 /root/vpn_auth/vpn_users.db ".backup '${RAW_DUMP}'"
  log "SQLite dump completed."
else
  log "ERROR: No database source found."
  exit 1
fi

ENC_OUTPUT="${BACKUP_DIR}/daily/wins_hub_backup_${DATE_STAMP}.enc"

log "Encrypting and compressing database backup..."
gzip -c "${RAW_DUMP}" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -pass "file:${ENCRYPTION_KEY_FILE}" \
    -out "${ENC_OUTPUT}"
chmod 600 "${ENC_OUTPUT}"

rm -f "${RAW_DUMP}"

# SHA-256 manifest
sha256sum "${ENC_OUTPUT}" > "${ENC_OUTPUT}.sha256"
log "Backup written to ${ENC_OUTPUT} ($(du -h "${ENC_OUTPUT}" | cut -f1))"

# Copy monthly snapshot on 1st day of month
if [[ "$(date +%d)" == "01" ]]; then
  cp -p "${ENC_OUTPUT}" "${BACKUP_DIR}/monthly/"
  cp -p "${ENC_OUTPUT}.sha256" "${BACKUP_DIR}/monthly/"
  log "Monthly archive snapshot recorded."
fi

# Prune retention
find "${BACKUP_DIR}/daily" -type f -mtime +${RETENTION_DAYS} -delete
find "${BACKUP_DIR}/monthly" -type f -mtime +$((RETENTION_MONTHS * 30)) -delete
log "Retention policy enforced (Daily: ${RETENTION_DAYS}d, Monthly: ${RETENTION_MONTHS}m)."

log "Daily backup completed successfully."
