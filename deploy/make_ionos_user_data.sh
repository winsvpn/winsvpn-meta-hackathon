#!/usr/bin/env bash
# make_ionos_user_data.sh: builds the text the owner pastes into the IONOS
# Cloud Panel "User data" field (Servers & Cloud, the VPS, Actions, Reinstall
# Image, Advanced Options) for the control hub rebuild (LUKS-FIX round,
# 2026-10-11). The output is a cloud-init user script (first line #!/bin/bash,
# runs once as root on the first boot of the reinstalled host). It embeds
# deploy/fde_boot_chain.sh (xz, base64) together with its sha256, stages it on
# first boot and arms NOTHING: no passphrase, no key, no token is ever in the
# pasted text (docs/FDE_CUSTODY_CLOSURE.md forbids a credential in provider
# user-data, which the provider may retain). The host decodes it with the
# python3 that cloud-init itself needs, so no extra package is assumed.
#
# Usage: deploy/make_ionos_user_data.sh [converter] > ionos_user_data.sh
# The output is deterministic for a given converter, so
# tools/test_fde_early_boot_network.py regenerates and compares it.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONVERTER="${1:-${HERE}/fde_boot_chain.sh}"
[[ -s "${CONVERTER}" ]] || { echo "converter not found: ${CONVERTER}" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "missing tool: python3" >&2; exit 1; }
BLOB_FILE="$(mktemp)"
trap 'rm -f -- "${BLOB_FILE}"' EXIT
SHA="$(python3 - "${CONVERTER}" "${BLOB_FILE}" <<'PY'
import base64, hashlib, lzma, sys
data = open(sys.argv[1], "rb").read()
packed = lzma.compress(data, format=lzma.FORMAT_XZ, preset=9 | lzma.PRESET_EXTREME)
text = base64.b64encode(packed).decode("ascii")
with open(sys.argv[2], "w", encoding="ascii") as out:
    for i in range(0, len(text), 120):
        out.write(text[i:i + 120] + "\n")
print(hashlib.sha256(data).hexdigest())
PY
)"
[[ "${SHA}" =~ ^[0-9a-f]{64}$ ]] || { echo "cannot hash ${CONVERTER}" >&2; exit 1; }
[[ -s "${BLOB_FILE}" ]] || { echo "empty converter blob" >&2; exit 1; }

awk -v sha="${SHA}" -v blobfile="${BLOB_FILE}" '
  $0 == "@CONVERTER_BLOB@" {
    while ((getline line < blobfile) > 0) print line
    close(blobfile)
    next
  }
  { gsub(/@CONVERTER_SHA256@/, sha); print }
' <<'TEMPLATE'
#!/bin/bash
# Win's VPN hub, IONOS User data (Ubuntu 24.04). Generated from
# deploy/fde_boot_chain.sh (sha256 @CONVERTER_SHA256@) by
# deploy/make_ionos_user_data.sh. NO secret inside. Stages the converter and
# /usr/local/sbin/winn-fde-arm on first boot and arms NOTHING; the passphrase
# arrives later over SSH (docs/FDE_CUSTODY_CLOSURE.md). Safe to re-run.
# Log: /var/log/winn-fde-userdata.log.
set -u
umask 077
LOG=/var/log/winn-fde-userdata.log
exec >>"${LOG}" 2>&1
echo "=== winn-fde user data start $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
CONVERTER_SHA256='@CONVERTER_SHA256@'
STAGED=/root/fde_boot_chain.sh
HELPER=/usr/local/sbin/winn-fde-arm
STATE_DIR=/var/lib
note() { echo "[winn-fde-userdata] $*"; echo "winn-fde: $*" > /dev/console 2>/dev/null || true; }
fail() {
  note "FAILED: $*"
  printf 'reason=%s\n' "$*" > "${STATE_DIR}/winn-fde-stage-failed"
  exit 1
}
[ "$(id -u)" = 0 ] || fail "not running as root"
install -d -m 755 "${STATE_DIR}" /usr/local/sbin
# Bind the retained provider payload by digest (custody evidence, no content).
if [ -r "$0" ]; then
  sha256sum "$0" | awk '{print $1}' > "${STATE_DIR}/winn-fde-userdata.sha256"
fi
# Never touch a host that is already encrypted, converted, armed or converting.
root_src="$(findmnt -no SOURCE / 2>/dev/null || true)"
if [ -n "${root_src}" ] && lsblk -no TYPE "${root_src}" 2>/dev/null | grep -qx crypt; then
  note "root is already LUKS-backed; nothing staged"
  exit 0
fi
for marker in "${STATE_DIR}/winn-fde-done" "${STATE_DIR}/winn-fde-custody.receipt" \
              /root/.winn-fde-pass /root/.winn-fde-conversion-key; do
  if [ -e "${marker}" ] || [ -L "${marker}" ]; then
    note "${marker} exists: host is converted or armed; nothing staged"
    exit 0
  fi
done
if [ -e "${STAGED}" ] || [ -L "${STAGED}" ]; then
  if [ -f "${STAGED}" ] && [ ! -L "${STAGED}" ] \
     && [ "$(sha256sum "${STAGED}" | awk '{print $1}')" = "${CONVERTER_SHA256}" ] && [ -x "${HELPER}" ]; then
    note "converter already staged with the expected digest; nothing to do"
    exit 0
  fi
  fail "${STAGED} exists with a different digest or shape; refusing to overwrite it (remove it by hand if the staged copy is wrong)"
fi

tmp="$(mktemp /root/.fde_boot_chain.XXXXXX)" || fail "cannot create a temporary file under /root"
python3 -c 'import base64, lzma, sys; sys.stdout.buffer.write(lzma.decompress(base64.b64decode(sys.stdin.read())))' \
  > "${tmp}" <<'BLOB' || { rm -f "${tmp}"; fail "cannot decode the embedded converter"; }
@CONVERTER_BLOB@
BLOB
actual="$(sha256sum "${tmp}" | awk '{print $1}')"
if [ "${actual}" != "${CONVERTER_SHA256}" ]; then
  rm -f "${tmp}"
  fail "embedded converter sha256 ${actual} differs from ${CONVERTER_SHA256}; stage deploy/fde_boot_chain.sh by scp instead"
fi
bash -n "${tmp}" || { rm -f "${tmp}"; fail "embedded converter does not parse"; }
chmod 700 "${tmp}"
mv -f "${tmp}" "${STAGED}"

cat > "${HELPER}.tmp" <<'HELPER'
#!/bin/bash
# winn-fde-arm: passphrase on stdin, then arm. --check: pre-flight only, writes
# nothing. The pre-flight runs before the passphrase is written. Never an
# argument, never echoed, never logged; the converter removes this helper.
set -Eeuo pipefail
umask 077
CONVERTER=/root/fde_boot_chain.sh
EXPECTED='@CONVERTER_SHA256@'
PASS=/root/.winn-fde-pass
die() { echo "[winn-fde-arm] $*" >&2; exit 1; }
[[ "${EUID}" -eq 0 ]] || die "run as root"
[[ -f "${CONVERTER}" && ! -L "${CONVERTER}" ]] || die "${CONVERTER} is missing; stage it first (scp deploy/fde_boot_chain.sh)"
actual="$(sha256sum "${CONVERTER}" | awk '{print $1}')"
[[ "${actual}" == "${EXPECTED}" ]] || die "converter sha256 ${actual} does not match the staged digest ${EXPECTED}"
if [[ "${1:-}" == "--check" ]]; then
  WINN_FDE_PREFLIGHT_ONLY=1 exec bash "${CONVERTER}"
fi
[[ $# -eq 0 ]] || die "usage: printf '%s' PASSPHRASE | winn-fde-arm    or    winn-fde-arm --check"
[[ ! -t 0 ]] || die "the passphrase is read from stdin, never from the terminal or the command line"
[[ ! -e "${PASS}" && ! -L "${PASS}" ]] || die "${PASS} already exists; shred -u it first if you mean to deliver again"
WINN_FDE_PREFLIGHT_ONLY=1 bash "${CONVERTER}" </dev/null >&2 || die "pre-flight refused; no passphrase was written"
tmp="$(mktemp /root/.winn-fde-pass.XXXXXX)"
trap 'rm -f -- "${tmp}"' EXIT
head -c 4098 > "${tmp}"
# One trailing newline (echo, or an editor) is forgiven: it is not part of
# the passphrase typed at the console. Everything else is checked by the
# converter's validator (32 to 4096 bytes, no newline, no edge whitespace).
if [[ "$(tail -c 1 "${tmp}" | od -An -tu1 | tr -d ' ')" == "10" ]]; then
  truncate -s -1 "${tmp}"
  if [[ "$(tail -c 1 "${tmp}" | od -An -tu1 | tr -d ' ')" == "13" ]]; then
    truncate -s -1 "${tmp}"
  fi
fi
bytes="$(wc -c < "${tmp}")"
(( bytes >= 32 && bytes <= 4096 )) || die "passphrase must be 32 to 4096 bytes without a newline (got ${bytes})"
chmod 600 "${tmp}"
mv -f -- "${tmp}" "${PASS}"
trap - EXIT
echo "[winn-fde-arm] passphrase delivered to ${PASS} (${bytes} bytes); arming the conversion"
exec bash "${CONVERTER}"
HELPER
chmod 700 "${HELPER}.tmp"
mv -f "${HELPER}.tmp" "${HELPER}"

{
  printf 'converter_sha256=%s\n' "${CONVERTER_SHA256}"
  printf 'staged_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'converter=%s\n' "${STAGED}"
  printf 'helper=%s\n' "${HELPER}"
} > "${STATE_DIR}/winn-fde-staged"
rm -f "${STATE_DIR}/winn-fde-stage-failed"
note "converter staged at ${STAGED} (sha256 ${CONVERTER_SHA256}); deliver the passphrase over SSH, then run winn-fde-arm"
echo "=== winn-fde user data end ==="
exit 0
TEMPLATE
