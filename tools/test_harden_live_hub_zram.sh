#!/usr/bin/env bash
# Isolated regression tests for the live-hub zram transaction. No host swap,
# fstab, package, systemd, or firewall state is touched.

set -Eeuo pipefail
umask 077

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
helper="${repo_root}/tools/harden_live_hub_zram.sh"

bash -n "${helper}"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -x "${helper}"
fi

grep -Fq "readonly ZRAM_SIZE_EXPR='min(ram * 50 / 100, 2048)'" "${helper}"
grep -Fq 'compression-algorithm = zstd' "${helper}"
grep -Fq 'swap-priority = 100' "${helper}"
# The kernel variable must remain literal in the production-source assertion.
# shellcheck disable=SC2016
grep -Fq 'zram_kernel_package="linux-modules-extra-${zram_kernel_release}"' "${helper}"
# shellcheck disable=SC2016
grep -Fq 'default_kernel_image=$(readlink -f /boot/vmlinuz' "${helper}"
# shellcheck disable=SC2016
grep -Fq 'modinfo -k "${zram_kernel_release}" zram' "${helper}"
grep -Fq 'modprobe zram' "${helper}"
grep -Fq 'zram module is not owned by the matching Ubuntu kernel package' "${helper}"
if grep -Eq '^[[:space:]]*writeback-device[[:space:]]*=' "${helper}"; then
  printf 'FAIL: disk writeback must never be configured\n' >&2
  exit 1
fi
if grep -Eq 'swapoff[[:space:]]+(-a|--all)' "${helper}"; then
  printf 'FAIL: broad swapoff is forbidden\n' >&2
  exit 1
fi

preflight_line=$(grep -n -m1 'unsupported non-RAM swap is active before mutation' "${helper}" | cut -d: -f1)
mutation_line=$(grep -n -m1 '^apt-get update' "${helper}" | cut -d: -f1)
[[ ${preflight_line} =~ ^[0-9]+$ && ${mutation_line} =~ ^[0-9]+$ ]]
(( preflight_line < mutation_line )) || {
  printf 'FAIL: unsupported swap rejection is not a preflight check\n' >&2
  exit 1
}

test_root=$(mktemp -d "${TMPDIR:-/tmp}/wins-zram-rollback.XXXXXX")
cleanup() { rm -rf -- "${test_root}"; }
trap cleanup EXIT
mkdir -p "${test_root}/etc" "${test_root}/rollback"
printf 'UUID=root / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n' \
  >"${test_root}/rollback/fstab.before"
printf 'UUID=root / ext4 defaults 0 1\n' >"${test_root}/etc/fstab"
printf 'mock-swap\n' >"${test_root}/swapfile"
chmod 0600 "${test_root}/swapfile"

export TEST_FSTAB="${test_root}/etc/fstab"
export TEST_SWAPFILE="${test_root}/swapfile"
export TEST_ROLLBACK="${test_root}/rollback"
export TEST_MARKER="${test_root}/swapon.called"
export TEST_FIXTURE_UID="$(id -u)"
export TEST_FIXTURE_GID="$(id -g)"

# Execute the exact production rollback functions with their fixed host paths
# redirected to this disposable fixture. Stop before production preflights.
# The two replacement variables intentionally remain literal for the child shell.
# shellcheck disable=SC2016
functions=$(
  awk '{print} /^trap restore_failed_transaction EXIT$/ {exit}' "${helper}" |
    sed \
      -e '/^trap restore_failed_transaction EXIT$/d' \
      -e '/^trap .* INT$/d' \
      -e '/^trap .* TERM$/d' \
      -e 's#readonly SWAPFILE=/swapfile#SWAPFILE="${TEST_SWAPFILE}"#' \
      -e 's#/etc/fstab#${TEST_FSTAB}#g'
)
export functions

set +e
bash -c '
  eval "$functions"
  set +eE
  rollback_dir=$TEST_ROLLBACK
  fstab_uid=$TEST_FIXTURE_UID
  fstab_gid=$TEST_FIXTURE_GID
  fstab_mode=644
  restore_disk_swap=1
  swapon() {
    if [[ ${1:-} == --noheadings ]]; then
      printf "%s\n" "$SWAPFILE"
    else
      : >"$TEST_MARKER"
    fi
  }
  trap restore_failed_transaction EXIT
  die forced-after-swapoff
'
rc=$?
set -e
[[ ${rc} -eq 1 ]] || {
  printf 'FAIL: explicit post-swapoff failure returned %s, expected 1\n' "${rc}" >&2
  exit 1
}
cmp -s "${test_root}/rollback/fstab.before" "${test_root}/etc/fstab"
[[ -f ${test_root}/swapon.called ]]

printf 'changed-again\n' >"${test_root}/etc/fstab"
rm -f "${test_root}/swapon.called"
set +e
bash -c '
  eval "$functions"
  set +eE
  rollback_dir=$TEST_ROLLBACK
  fstab_uid=$TEST_FIXTURE_UID
  fstab_gid=$TEST_FIXTURE_GID
  fstab_mode=644
  restore_disk_swap=1
  swapon() { return 1; }
  trap restore_failed_transaction EXIT
  exit 9
'
rc=$?
set -e
[[ ${rc} -eq 70 ]] || {
  printf 'FAIL: rollback failure returned %s, expected 70\n' "${rc}" >&2
  exit 1
}
cmp -s "${test_root}/rollback/fstab.before" "${test_root}/etc/fstab"

printf 'PASS live-hub zram transaction syntax, invariants, rollback, and rollback-failure signaling\n'
