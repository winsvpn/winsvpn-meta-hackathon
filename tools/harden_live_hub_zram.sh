#!/usr/bin/env bash
# Transactionally replace an unencrypted provider /swapfile with RAM-only zram.
# This helper contains no credentials and deliberately does not back up swap
# contents. It is safe to rerun and does not touch network/firewall state.

set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly CONFIG_PATH=/etc/systemd/zram-generator.conf
readonly SWAPFILE=/swapfile
readonly LOCK_PATH=/run/lock/winsvpn-zram-hardening.lock
readonly ZRAM_SIZE_EXPR='min(ram * 50 / 100, 2048)'

die() { printf '[ZRAM-HARDEN][ERR] %s\n' "$*" >&2; exit 1; }
log() { printf '[ZRAM-HARDEN] %s\n' "$*"; }

staging=
rollback_dir=
restore_disk_swap=0
fstab_uid=
fstab_gid=
fstab_mode=

cleanup_staging() {
  if [[ -n ${staging:-} ]]; then
    rm -f -- "${staging}" || true
  fi
}

restore_failed_transaction() {
  local rc=$?
  local rollback_failed=0
  trap - EXIT INT TERM
  if (( rc != 0 && restore_disk_swap == 1 )); then
    log 'Failure detected after disk swap was disabled; restoring the exact pre-transaction state'
    if [[ -z ${rollback_dir:-} || ! -f ${rollback_dir}/fstab.before ]]; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] original fstab backup is unavailable\n' >&2
      rollback_failed=1
    elif ! install -o "${fstab_uid}" -g "${fstab_gid}" -m "${fstab_mode}" \
      "${rollback_dir}/fstab.before" /etc/fstab; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] failed to restore /etc/fstab\n' >&2
      rollback_failed=1
    elif ! cmp -s -- "${rollback_dir}/fstab.before" /etc/fstab; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] restored /etc/fstab does not match its backup\n' >&2
      rollback_failed=1
    fi
    if [[ ! -f ${SWAPFILE} || -L ${SWAPFILE} ]]; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] /swapfile is unavailable or unsafe\n' >&2
      rollback_failed=1
    elif ! swapon "${SWAPFILE}" >/dev/null 2>&1; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] failed to reactivate /swapfile\n' >&2
      rollback_failed=1
    elif ! rollback_swap_names=$(swapon --noheadings --raw --show=NAME 2>/dev/null); then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] failed to query active swap after rollback\n' >&2
      rollback_failed=1
    elif ! grep -Fxq "${SWAPFILE}" <<<"${rollback_swap_names}"; then
      printf '[ZRAM-HARDEN][ROLLBACK-ERR] /swapfile is not active after rollback\n' >&2
      rollback_failed=1
    fi
    if (( rollback_failed == 0 )); then
      log 'Rollback PASS: original fstab and /swapfile are active again'
    else
      rc=70
    fi
  fi
  cleanup_staging
  exit "${rc}"
}

trap restore_failed_transaction EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ ${EUID} -eq 0 ]] || die 'root is required'
[[ -r /etc/os-release ]] || die '/etc/os-release is unavailable'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] ||
  die 'this reviewed helper supports Ubuntu 24.04 only'
[[ -d /run/systemd/system ]] || die 'systemd is required'
install -d -m 0755 /run/lock
exec 9>"${LOCK_PATH}"
flock -n 9 || die 'another zram hardening transaction is active'

root_source=$(findmnt -no SOURCE /)
root_real=$(readlink -f "${root_source}" 2>/dev/null || printf '%s' "${root_source}")
root_block_types=$(lsblk -spno TYPE "${root_real}" 2>/dev/null || true)
if grep -qx crypt <<<"${root_block_types}"; then
  die 'root is already dm-crypt/LUKS backed; use the full installer swap policy instead'
fi

memory_available_kib=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
[[ ${memory_available_kib} =~ ^[0-9]+$ && ${memory_available_kib} -ge 1048576 ]] ||
  die 'at least 1 GiB of currently available RAM is required'

swapfile_active=0
while IFS= read -r source; do
  case "${source}" in
    "${SWAPFILE}") swapfile_active=1 ;;
    /dev/zram*|/dev/ram*) ;;
    *) die "unsupported non-RAM swap is active before mutation: ${source}" ;;
  esac
done < <(swapon --noheadings --raw --show=NAME 2>/dev/null)

if (( swapfile_active == 1 )); then
  [[ -f ${SWAPFILE} && ! -L ${SWAPFILE} ]] || die '/swapfile is not a regular file'
  read -r swap_uid swap_mode < <(stat -c '%u %a' -- "${SWAPFILE}")
  [[ ${swap_uid} == 0 && ${swap_mode} == 600 ]] || die '/swapfile ownership or mode is unsafe'
fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
rollback_dir="/root/winsvpn-zram-hardening-${stamp}"
install -d -m 0700 "${rollback_dir}"
[[ -f /etc/fstab && ! -L /etc/fstab ]] || die '/etc/fstab is unsafe'
read -r fstab_uid fstab_gid fstab_mode < <(stat -c '%u %g %a' -- /etc/fstab)
[[ ${fstab_uid} == 0 && ${fstab_gid} =~ ^[0-9]+$ && ${fstab_mode} =~ ^[0-7]{3,4}$ ]] ||
  die '/etc/fstab ownership or mode is unsafe'
install -m 0600 /etc/fstab "${rollback_dir}/fstab.before"
if [[ -e ${CONFIG_PATH} || -L ${CONFIG_PATH} ]]; then
  [[ -f ${CONFIG_PATH} && ! -L ${CONFIG_PATH} ]] || die 'existing zram config is unsafe'
  install -m 0600 "${CONFIG_PATH}" "${rollback_dir}/zram-generator.conf.before"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
kernel_release=$(uname -r)
[[ ${kernel_release} =~ ^[0-9A-Za-z.+_~-]+$ ]] || die 'running kernel release is malformed'
zram_packages=(systemd-zram-generator)
zram_kernel_releases=("${kernel_release}")
if [[ -e /boot/vmlinuz || -L /boot/vmlinuz ]]; then
  default_kernel_image=$(readlink -f /boot/vmlinuz 2>/dev/null || true)
  default_kernel_release=${default_kernel_image##*/vmlinuz-}
  if [[ ${default_kernel_image##*/} == vmlinuz-* &&
        ${default_kernel_release} =~ ^[0-9A-Za-z.+_~-]+$ &&
        ${default_kernel_release} != "${kernel_release}" ]]; then
    zram_kernel_releases+=("${default_kernel_release}")
  fi
fi
for zram_kernel_release in "${zram_kernel_releases[@]}"; do
  if ! modinfo -k "${zram_kernel_release}" zram >/dev/null 2>&1; then
    zram_kernel_package="linux-modules-extra-${zram_kernel_release}"
    zram_kernel_candidate=$(
      apt-cache policy "${zram_kernel_package}" |
        awk '/^[[:space:]]*Candidate:/ {candidate=$2} END {print candidate}'
    )
    [[ -n ${zram_kernel_candidate} && ${zram_kernel_candidate} != '(none)' ]] ||
      die "Ubuntu package ${zram_kernel_package} is unavailable for kernel ${zram_kernel_release}"
    zram_packages+=("${zram_kernel_package}")
  fi
done
apt-get install -y -qq --no-install-recommends "${zram_packages[@]}"
for zram_kernel_release in "${zram_kernel_releases[@]}"; do
  depmod -a "${zram_kernel_release}"
  modinfo -k "${zram_kernel_release}" zram >/dev/null 2>&1 ||
    die "zram remains unavailable for installed kernel ${zram_kernel_release}"
done
generator=/usr/lib/systemd/system-generators/zram-generator
[[ -x ${generator} && -f ${generator} && ! -L ${generator} ]] ||
  die 'Ubuntu zram generator is unavailable after package installation'
generator_owner=$(stat -c '%u' -- "${generator}")
generator_mode=$(stat -c '%a' -- "${generator}")
[[ ${generator_owner} == 0 && $((8#${generator_mode} & 0022)) -eq 0 ]] ||
  die 'installed zram generator ownership/mode is unsafe'
generator_real=$(readlink -f "${generator}")
generator_package_match=0
while IFS= read -r generator_owned_path; do
  [[ ${generator_owned_path} == /* && -e ${generator_owned_path} ]] || continue
  if [[ $(readlink -f "${generator_owned_path}") == "${generator_real}" ]]; then
    generator_package_match=1
  fi
done < <(dpkg-query -L systemd-zram-generator)
(( generator_package_match == 1 )) ||
  die 'zram generator is not owned by the expected Ubuntu package'
modprobe zram || die 'the verified zram kernel module could not be loaded'
[[ -d /sys/class/zram-control ]] || die 'the kernel did not expose zram-control after module load'
zram_module_path=$(modinfo -n zram)
if [[ ${zram_module_path} == '(builtin)' ]]; then
  grep -Fxq 'CONFIG_ZRAM=y' "/boot/config-${kernel_release}" ||
    die 'zram reports built-in without a matching kernel configuration'
else
  zram_module_real=$(readlink -f "${zram_module_path}")
  zram_module_root=$(readlink -f "/lib/modules/${kernel_release}")
  case "${zram_module_real}" in
    "${zram_module_root}/"*) ;;
    *) die 'zram module escapes the running kernel module tree' ;;
  esac
  [[ -f ${zram_module_real} && ! -L ${zram_module_real} ]] ||
    die 'zram module file is unavailable or unsafe'
  zram_module_package_match=0
  for zram_module_package in \
    "linux-modules-${kernel_release}" \
    "linux-modules-extra-${kernel_release}"; do
    dpkg-query -W -f='${db:Status-Abbrev}' "${zram_module_package}" 2>/dev/null |
      grep -Fxq 'ii ' || continue
    while IFS= read -r zram_owned_path; do
      [[ ${zram_owned_path} == /* && -e ${zram_owned_path} ]] || continue
      if [[ $(readlink -f "${zram_owned_path}") == "${zram_module_real}" ]]; then
        zram_module_package_match=1
      fi
    done < <(dpkg-query -L "${zram_module_package}")
  done
  (( zram_module_package_match == 1 )) ||
    die 'zram module is not owned by the matching Ubuntu kernel package'
fi

[[ ! -L /etc/systemd && ! -L ${CONFIG_PATH} ]] || die 'zram configuration path is unsafe'
staging=$(mktemp /etc/systemd/.wins-zram-generator.XXXXXX)
cat >"${staging}" <<EOF
# Managed by Win's VPN. Compressed RAM only: intentionally no writeback-device.
[zram0]
zram-size = ${ZRAM_SIZE_EXPR}
compression-algorithm = zstd
swap-priority = 100
EOF
chmod 0644 "${staging}"
mv -f -- "${staging}" "${CONFIG_PATH}"
staging=

systemctl daemon-reload
systemctl start dev-zram0.swap
active_swap_names=$(swapon --noheadings --raw --show=NAME)
grep -Fxq /dev/zram0 <<<"${active_swap_names}" ||
  die '/dev/zram0 did not become active'
zram_priority=$(swapon --noheadings --raw --show=NAME,PRIO | awk '$1=="/dev/zram0" {print $2}')
[[ ${zram_priority} == 100 ]] || die 'zram swap priority is not 100'
[[ -r /sys/block/zram0/backing_dev ]] || die 'zram backing-device state is unavailable'
zram_backing=$(tr -d '[:space:]' </sys/block/zram0/backing_dev)
[[ -z ${zram_backing} || ${zram_backing} == none ]] || die 'zram unexpectedly has disk writeback configured'
grep -Eq '\[zstd\]' /sys/block/zram0/comp_algorithm || die 'zram is not using zstd compression'

if (( swapfile_active == 1 )); then
  restore_disk_swap=1
  swapoff "${SWAPFILE}"
fi

python3 - <<'PY'
import os
import pathlib
import stat
import uuid

path = pathlib.Path('/etc/fstab')
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
    raise SystemExit('/etc/fstab is unsafe')
lines = path.read_text(encoding='utf-8').splitlines()
kept = []
for line in lines:
    fields = line.split()
    if fields and not fields[0].startswith('#') and fields[0] == '/swapfile' and 'swap' in fields[1:3]:
        continue
    kept.append(line)
temporary = path.with_name(f'.fstab.wins-zram.{uuid.uuid4().hex}.tmp')
temporary.write_text('\n'.join(kept) + '\n', encoding='utf-8')
os.chmod(temporary, stat.S_IMODE(info.st_mode))
os.chown(temporary, info.st_uid, info.st_gid)
os.replace(temporary, path)
PY

if grep -Eq '^[[:space:]]*/swapfile[[:space:]]+([^[:space:]]+[[:space:]]+)?swap([[:space:]]|$)' /etc/fstab; then
  die '/swapfile remains in /etc/fstab'
fi
while IFS= read -r source; do
  case "${source}" in
    /dev/zram*|/dev/ram*) ;;
    *) die "non-RAM swap remains active: ${source}" ;;
  esac
done < <(swapon --noheadings --raw --show=NAME 2>/dev/null)

restore_disk_swap=0
if [[ -e ${SWAPFILE} ]]; then
  rm -f -- "${SWAPFILE}"
fi
[[ ! -e ${SWAPFILE} ]] || die '/swapfile could not be removed'

{
  printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'fstab_before_sha256=%s\n' "$(sha256sum "${rollback_dir}/fstab.before" | awk '{print $1}')"
  printf 'fstab_after_sha256=%s\n' "$(sha256sum /etc/fstab | awk '{print $1}')"
  printf 'zram_config_sha256=%s\n' "$(sha256sum "${CONFIG_PATH}" | awk '{print $1}')"
  printf 'generator_package_version=%s\n' "$(dpkg-query -W -f='${Version}' systemd-zram-generator)"
  printf 'zram_priority=%s\n' "${zram_priority}"
  printf 'zram_backing=%s\n' "${zram_backing:-none}"
} >"${rollback_dir}/transaction.manifest"
chmod 0600 "${rollback_dir}/transaction.manifest"

trap - EXIT INT TERM
cleanup_staging
log "PASS: RAM-only zram is active; plaintext /swapfile is disabled and removed"
log "Rollback metadata: ${rollback_dir}"
