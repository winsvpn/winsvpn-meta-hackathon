#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Credentials never belong in this script. Configure a root-owned rclone
# remote separately and keep /root/.config/rclone/rclone.conf mode 600.
DESTINATION="${WINS_BACKUP_REMOTE:-GoogleDrive_secured:}"
RCLONE_CONFIG="${RCLONE_CONFIG:-/root/.config/rclone/rclone.conf}"
DB_SOURCE="${WINS_DB_PATH:-/root/vpn_auth/vpn_users.db}"
TIMESTAMP="$(date -u +%Y-%m-%d_%H-%M-%SZ)"
ARCHIVE_NAME="winvpn_$(hostname -s)_hotsite_${TIMESTAMP}.tar.gz"
OUTPUT_DIR="${WINS_BACKUP_OUTPUT_DIR:-/var/backups/winsvpn}"
STAGE_DIR=""
UNCOMPRESSED_TAR=""
ARCHIVE_PATH=""

log() { printf '[wins-backup] %s\n' "$*"; }
die() { printf '[wins-backup] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local exit_code=$?
  [[ -n "${STAGE_DIR}" && -d "${STAGE_DIR}" ]] && rm -rf -- "${STAGE_DIR}"
  [[ -n "${UNCOMPRESSED_TAR}" && -f "${UNCOMPRESSED_TAR}" ]] && rm -f -- "${UNCOMPRESSED_TAR}"
  exit "${exit_code}"
}
trap cleanup EXIT INT TERM

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root so the snapshot can read protected service files."
for command_name in rclone sqlite3 tar pigz hostname; do
  command -v "${command_name}" >/dev/null 2>&1 || die "Missing required command: ${command_name}"
done
[[ -s "${RCLONE_CONFIG}" ]] || die "Missing rclone config: ${RCLONE_CONFIG}"
[[ "${DESTINATION}" == *: ]] || die "WINS_BACKUP_REMOTE must name an rclone remote ending in ':'"

install -d -m 700 "${OUTPUT_DIR}"
STAGE_DIR="$(mktemp -d "${OUTPUT_DIR}/.stage.XXXXXX")"
UNCOMPRESSED_TAR="${STAGE_DIR}/${ARCHIVE_NAME%.gz}"
ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}"

remote_name="${DESTINATION%%:*}"
rclone listremotes --config "${RCLONE_CONFIG}" | grep -qxF "${remote_name}:" || \
  die "rclone remote '${remote_name}:' is not configured"

if [[ -f "${DB_SOURCE}" ]]; then
  log "Creating a consistent SQLite snapshot"
  install -d -m 700 "${STAGE_DIR}/root/vpn_auth"
  sqlite3 "${DB_SOURCE}" ".timeout 10000" ".backup '${STAGE_DIR}/root/vpn_auth/vpn_users.db'"
  chmod 600 "${STAGE_DIR}/root/vpn_auth/vpn_users.db"
fi

log "Archiving /root with live SQLite files excluded"
tar -cf "${UNCOMPRESSED_TAR}" \
  --exclude='root/vpn_auth/vpn_users.db' \
  --exclude='root/vpn_auth/vpn_users.db-journal' \
  --exclude='root/vpn_auth/vpn_users.db-wal' \
  --exclude='root/vpn_auth/vpn_users.db-shm' \
  --exclude='*.tar.gz' \
  --exclude='*.tar' \
  -C / root

if [[ -f "${STAGE_DIR}/root/vpn_auth/vpn_users.db" ]]; then
  tar -rf "${UNCOMPRESSED_TAR}" -C "${STAGE_DIR}" root/vpn_auth/vpn_users.db
fi

log "Compressing snapshot"
pigz -9 "${UNCOMPRESSED_TAR}"
mv -- "${UNCOMPRESSED_TAR}.gz" "${ARCHIVE_PATH}"
chmod 600 "${ARCHIVE_PATH}"

log "Uploading encrypted snapshot through rclone remote ${remote_name}:"
if rclone copyto "${ARCHIVE_PATH}" "${DESTINATION}${ARCHIVE_NAME}" \
    --config "${RCLONE_CONFIG}" --transfers 2 --checkers 4 --retries 3 --low-level-retries 10; then
  rm -f -- "${ARCHIVE_PATH}"
  log "Backup uploaded and local staging archive removed"
else
  die "Upload failed; encrypted staging archive retained at ${ARCHIVE_PATH}"
fi
