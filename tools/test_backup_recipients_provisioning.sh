#!/usr/bin/env bash
# Lane L54 / L51 C7: the data-plane installer provisions
# /etc/winsvpn/backup-recipients.age from operator-supplied PUBLIC recipients
# (BACKUP_AGE_RECIPIENTS), the preseed tool carries them from a local file
# (-BackupRecipientsFile), private identities are refused on both sides, and
# the winn/3 gateway backup still fails closed when no recipients exist.
#
# Runs the installer's own functions against a private sandbox path (install,
# chown stubbed; nothing outside a temp dir is touched) and the preseed's own
# Read-BackupRecipients function under pwsh. Test identities are generated
# fresh in the temp dir and deleted on exit.
#
# usage: tools/test_backup_recipients_provisioning.sh [repo_root]
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DP="${ROOT}/server/wins_data_plane_setup_ONETOUCH.sh"
# Slice S6: wins_winn3_gateway_install.sh is a tombstone. Check 7 proves the
# standalone installer's gateway backup, which design v17 2.1 E merges into the
# data plane's backup in slice S4, so it reads the frozen copy of that installer
# (deleted with the tombstone). S4 replaces check 7 with the merged backup.
GW="${ROOT}/server/testdata/winn3_gateway_install_retired/wins_winn3_gateway_install.sh.snapshot"
PRESEED="${ROOT}/tools/wins_deployment_preseed.ps1"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
failures=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failures=$((failures + 1)); }

extract_fn() { # extract_fn <file> <name>: print the function body, or nothing
  awk -v n="$2() {" '$0 == n {on = 1} on {print} on && $0 == "}" {exit}' "$1"
}

# Recipients: real ones when age-keygen exists (so the installer's `age -R`
# check runs for real), otherwise syntactically valid stand-ins with age hidden.
AGE_PATH_DIR=""
if command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1; then
  age-keygen -o "${WORK}/id1.txt" 2>/dev/null; age-keygen -o "${WORK}/id2.txt" 2>/dev/null
  R1="$(age-keygen -y "${WORK}/id1.txt")"
  SECRET="$(grep '^AGE-SECRET-KEY-' "${WORK}/id1.txt")"
else
  R1="age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"
  SECRET="AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS"
  AGE_PATH_DIR="${WORK}/noage"; mkdir -p "${AGE_PATH_DIR}"
fi
ssh-keygen -q -t ed25519 -N '' -C l54-test -f "${WORK}/sshkey" >/dev/null
R2="$(cat "${WORK}/sshkey.pub")"

HARNESS="${WORK}/harness.sh"
{
  echo 'set -uo pipefail'
  echo 'log() { echo "LOG $*"; }; warn() { echo "WARN $*"; }; err() { echo "ERR $*" >&2; }'
  echo 'install() { local -a a=(); while (( $# )); do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done; command install "${a[@]}"; }'
  echo 'chown() { return 0; }'
  echo 'sha256sum() { shasum -a 256 "$@"; }'
  for fn in backup_age_recipient_lines validate_backup_age_recipients write_backup_age_recipients; do
    extract_fn "${DP}" "${fn}"
  done
  echo 'BACKUP_AGE_RECIPIENTS_FILE_DEFAULT="${SANDBOX_TARGET}"'
  echo 'BACKUP_AGE_RECIPIENTS="${BACKUP_AGE_RECIPIENTS:-}"'
  echo '"$@"'
} > "${HARNESS}"

run_installer() { # run_installer <target> <recipients|""> <function>
  local target="$1" recips="$2" fn="$3" path="${PATH}"
  [[ -n "${AGE_PATH_DIR}" ]] && path="$(printf '%s' "${PATH}" | tr ':' '\n' | grep -v -e homebrew -e /usr/local/bin | paste -sd: -)"
  SANDBOX_TARGET="${target}" BACKUP_AGE_RECIPIENTS="${recips}" PATH="${path}" bash "${HARNESS}" "${fn}" > "${WORK}/out" 2>&1
}

mode_of() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

for fn in backup_age_recipient_lines validate_backup_age_recipients write_backup_age_recipients; do
  [[ -n "$(extract_fn "${DP}" "${fn}")" ]] && pass "installer defines ${fn}" || fail "installer lacks ${fn}"
done
grep -q '^  validate_backup_age_recipients || exit 1$' "${DP}" \
  && pass "preflight validates the recipients before any mutation" \
  || fail "preflight does not validate BACKUP_AGE_RECIPIENTS"
awk '/^main\(\) \{/{on=1} on && /^  write_backup_age_recipients$/{found=1} on && /^}$/{exit} END{exit !found}' "${DP}" \
  && pass "main() writes the recipients during deploy" \
  || fail "main() never calls write_backup_age_recipients"

# 1. two valid public recipients -> file written, root-only mode, one per line.
T1="${WORK}/etc1/backup-recipients.age"; mkdir -p "$(dirname "${T1}")"
if run_installer "${T1}" "${R1}; ${R2}" write_backup_age_recipients && [[ -f "${T1}" ]]; then
  if [[ "$(cat "${T1}")" == "$(printf '%s\n%s' "${R1}" "${R2}")" && "$(mode_of "${T1}")" == 600 ]]; then
    pass "valid recipients written one per line with mode 600"
  else
    fail "recipients file content or mode wrong (mode $(mode_of "${T1}"))"
  fi
else
  fail "valid recipients were not written: $(tr '\n' ' ' < "${WORK}/out")"
fi
if command -v age >/dev/null 2>&1 && [[ -z "${AGE_PATH_DIR}" && -f "${T1}" ]]; then
  printf 'secret\n' | age -R "${T1}" -o "${WORK}/probe.age" \
    && [[ "$(age -d -i "${WORK}/id1.txt" "${WORK}/probe.age")" == secret ]] \
    && pass "written file encrypts to the operator identity (age round trip)" \
    || fail "written file does not round-trip through age"
fi

# 2. same recipients again -> unchanged (idempotent reinstall).
before="$(shasum -a 256 "${T1}" 2>/dev/null | cut -c1-64)"
run_installer "${T1}" "${R1};${R2}" write_backup_age_recipients
[[ "$(shasum -a 256 "${T1}" 2>/dev/null | cut -c1-64)" == "${before}" ]] && grep -q 'already match' "${WORK}/out" \
  && pass "reinstall with the same recipients changes nothing" \
  || fail "reinstall with the same recipients rewrote the file"

# 3. a private identity is refused and nothing is written.
T3="${WORK}/etc3/backup-recipients.age"; mkdir -p "$(dirname "${T3}")"
if run_installer "${T3}" "${R1};${SECRET}" write_backup_age_recipients; then
  fail "a private age identity was accepted"
else
  [[ ! -e "${T3}" ]] && grep -q 'PRIVATE identity' "${WORK}/out" && ! grep -q "${SECRET}" "${WORK}/out" \
    && pass "private age identity refused, nothing written, secret not echoed" \
    || fail "private identity refused but a file was written or the secret echoed"
fi
if run_installer "${T3}" "${R1};-----BEGIN OPENSSH PRIVATE KEY-----" validate_backup_age_recipients; then
  fail "an OpenSSH private key marker was accepted"
else
  grep -q 'PRIVATE identity' "${WORK}/out" && pass "OpenSSH private key marker refused at preflight" \
    || fail "OpenSSH private key marker not refused as a private identity"
fi

# 4. a non-recipient entry is refused.
if run_installer "${T3}" "${R1};hello world" write_backup_age_recipients; then
  fail "a non-recipient entry was accepted"
else
  [[ ! -e "${T3}" ]] && grep -q 'not an age or SSH public recipient' "${WORK}/out" \
    && pass "non-recipient entry refused" || fail "non-recipient entry not refused by the validator"
fi

# 5. unset + absent -> warning only (the gateway backup then fails closed).
T5="${WORK}/etc5/backup-recipients.age"; mkdir -p "$(dirname "${T5}")"
if run_installer "${T5}" "" write_backup_age_recipients && [[ ! -e "${T5}" ]] && grep -q 'fail closed' "${WORK}/out"; then
  pass "unset recipients: no file, loud warning that the gateway backup fails closed"
else
  fail "unset recipients path wrong: $(tr '\n' ' ' < "${WORK}/out")"
fi

# 6. unset + existing -> kept byte for byte.
printf '%s\n' "${R1}" > "${T5}"; chmod 600 "${T5}"; keep="$(shasum -a 256 "${T5}" | cut -c1-64)"
run_installer "${T5}" "" write_backup_age_recipients
[[ "$(shasum -a 256 "${T5}" | cut -c1-64)" == "${keep}" ]] && grep -q 'keeping the existing' "${WORK}/out" \
  && pass "unset recipients keep an existing file unchanged" \
  || fail "unset recipients changed an existing file"

# 7. the gateway backup still fails closed without recipients (kept, not weakened).
gw_backup="$(awk '/cat > \/usr\/local\/bin\/wins-gateway-backup <</{on=1; next} on && /^EOF$/{exit} on {print}' "${GW}")"
if grep -q 'REQUIRE_BACKUP_ENCRYPTION=1 but no age recipients are readable' <<< "${gw_backup}" \
    && grep -q "BACKUP_AGE_RECIPIENTS_FILE=\${BACKUP_AGE_RECIPIENTS_FILE}" "${GW}" \
    && grep -q '^BACKUP_AGE_RECIPIENTS_FILE="${BACKUP_AGE_RECIPIENTS_FILE:-/etc/winsvpn/backup-recipients.age}"$' "${GW}"; then
  pass "gateway backup reads /etc/winsvpn/backup-recipients.age and fails closed without it"
else
  fail "gateway backup fail-closed path or recipients path changed"
fi

# 8. preseed: Read-BackupRecipients carries public recipients, refuses secrets,
#    and Deploy appends its line to the staged defaults env for -Role data only.
if command -v pwsh >/dev/null 2>&1; then
  fnfile="${WORK}/read_backup_recipients.ps1"
  awk '/^function Read-BackupRecipients \{/{on=1} on {print} on && /^}$/{exit}' "${PRESEED}" > "${fnfile}"
  if [[ ! -s "${fnfile}" ]]; then
    fail "preseed lacks Read-BackupRecipients"
  else
    printf '# owner recipients\n%s\n\n%s\n' "${R1}" "${R2}" > "${WORK}/recips.txt"
    printf '%s\n%s\n' "${R1}" "${SECRET}" > "${WORK}/bad.txt"
    line="$(pwsh -NoProfile -Command ". '${fnfile}'; Read-BackupRecipients -Path '${WORK}/recips.txt'" 2>/dev/null)"
    [[ "${line}" == "BACKUP_AGE_RECIPIENTS='${R1};${R2}'" ]] \
      && pass "preseed renders the defaults-env line from the local file" \
      || fail "preseed line wrong: ${line:0:80}"
    if pwsh -NoProfile -Command ". '${fnfile}'; try { Read-BackupRecipients -Path '${WORK}/bad.txt' | Out-Null; exit 0 } catch { exit 3 }" >/dev/null 2>&1; then
      fail "preseed accepted a private identity"
    else
      pass "preseed refuses a private identity"
    fi
    # End to end: the preseed line, sourced like /root/winsvpn-defaults.env, drives the installer.
    T8="${WORK}/etc8/backup-recipients.age"; mkdir -p "$(dirname "${T8}")"
    recips="$(bash -c "${line}"'; printf "%s" "${BACKUP_AGE_RECIPIENTS}"')"
    run_installer "${T8}" "${recips}" write_backup_age_recipients
    [[ -f "${T8}" && "$(cat "${T8}")" == "$(printf '%s\n%s' "${R1}" "${R2}")" ]] \
      && pass "preseed file -> defaults env -> installer writes the same recipients" \
      || fail "preseed to installer round trip failed"
  fi
  grep -q 'if (\$null -ne \$backupRecipientsLine) {' "${PRESEED}" \
    && grep -q "throw '-BackupRecipientsFile applies to -Role data only.'" "${PRESEED}" \
    && pass "preseed Deploy stages the line into winsvpn-defaults.env for data only" \
    || fail "preseed Deploy does not carry the recipients"
else
  fail "pwsh not available; preseed path not tested"
fi

if (( failures > 0 )); then
  printf '%d check(s) failed\n' "${failures}"
  exit 1
fi
echo "all checks passed"
