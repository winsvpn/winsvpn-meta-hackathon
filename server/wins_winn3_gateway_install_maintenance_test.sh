#!/usr/bin/env bash
# Prove wins_winn3_gateway_install.sh arms standalone-gateway maintenance:
# weekly timer, encrypted /etc/winn/credentials backup, fail2ban sshd jail.
# Mutates a PRIVATE copy under scratch — never the shared tree.
#
# Controls:
#   no-mutation              (extracted live scripts)     must PASS
#   comment-only             (private copy)               must PASS
#   M1 drop credentials path                              must FAIL
#   M2 REQUIRE_BACKUP_ENCRYPTION=1 without recipients     must FAIL
#   M3 plaintext tar.gz left in /var/backups/winsvpn      must FAIL (scored inverted: live must not leave it)
#
# Usage:
#   bash wins_winn3_gateway_install_maintenance_test.sh
#   bash wins_winn3_gateway_install_maintenance_test.sh /path/to/wins_winn3_gateway_install.sh
set -euo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
WORKDIR="${WINN3_MAINT_TEST_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/gw_maintenance_timers/maint_test}"
rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}"

PASS=0
FAIL=0
BUILD_FAIL=0

fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
build_fail() { BUILD_FAIL=$((BUILD_FAIL + 1)); printf 'BUILD_FAIL: %s\n' "$*"; }

extract_heredoc() {
  local script="$1" needle="$2" terminator="$3"
  awk -v needle="${needle}" -v terminator="${terminator}" '
    index($0, needle) { capture=1; next }
    capture && $0 == terminator { exit }
    capture { print }
  ' "${script}"
}

if [[ ! -f "${INSTALL}" ]]; then
  echo "missing installer: ${INSTALL}" >&2
  exit 2
fi

bash -n "${INSTALL}"
pass "bash -n installer"

# --- static claims on the installer ---------------------------------------
if grep -Fq 'install_gateway_maintenance' "${INSTALL}"; then
  pass "installer defines/calls install_gateway_maintenance"
else
  fail "installer missing install_gateway_maintenance"
fi

if grep -Fq 'preflight_maintenance' "${INSTALL}"; then
  pass "installer defines preflight_maintenance"
else
  fail "installer missing preflight_maintenance"
fi

# --install path calls it; --preflight must not.
python3 - "${INSTALL}" <<'PY'
import sys
from pathlib import Path
src = Path(sys.argv[1]).read_text(encoding="utf-8")

def function_definition(source, signature):
    start = source.index(signature)
    depth = 0
    brace_idx = source.index("{", start)
    for idx in range(brace_idx, len(source)):
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1]
    raise SystemExit("unbalanced " + signature)

def extract_if_fi(source, start):
    depth = 0
    import re
    for match in re.finditer(r"(?m)^[ \t]*(if|fi)\b", source[start:]):
        if match.group(1) == "if":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return source[start : start + match.end()]
    raise SystemExit("unbalanced if/fi")

main = function_definition(src, "main() {")
pre = extract_if_fi(main, main.index('if [[ "${WINN3_GATEWAY_MODE}" == "preflight" ]]; then'))
if "install_gateway_maintenance" in pre:
    print("PREFLIGHT_CALLS_INSTALL")
    sys.exit(1)
if "preflight_maintenance" not in pre:
    print("PREFLIGHT_MISSING_INSPECT")
    sys.exit(1)
if "install_gateway_maintenance" not in main:
    print("MAIN_MISSING_INSTALL_MAINT")
    sys.exit(1)
print("OK")
PY
pass "main --preflight inspects maintenance; --install path is the only writer"

# --- extract generated scripts --------------------------------------------
BACKUP="${WORKDIR}/wins-gateway-backup"
WEEKLY="${WORKDIR}/wins-weekly-maintenance"
RESTORE="${WORKDIR}/wins-gateway-restore-preflight"
JAIL="${WORKDIR}/winsvpn-sshd.conf"

extract_heredoc "${INSTALL}" "cat > /usr/local/bin/wins-gateway-backup <<'EOF'" EOF > "${BACKUP}"
extract_heredoc "${INSTALL}" "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'" EOF > "${WEEKLY}"
extract_heredoc "${INSTALL}" "cat > /usr/local/bin/wins-gateway-restore-preflight <<'EOF'" EOF > "${RESTORE}"
extract_heredoc "${INSTALL}" "cat > /etc/fail2ban/jail.d/winsvpn-sshd.conf <<EOF" EOF > "${JAIL}"

for f in "${BACKUP}" "${WEEKLY}" "${RESTORE}"; do
  if [[ ! -s "${f}" ]]; then
    build_fail "extracted $(basename "${f}") is empty"
    echo "PASS=${PASS} FAIL=${FAIL} BUILD_FAIL=${BUILD_FAIL}"
    exit 1
  fi
  if bash -n "${f}"; then
    pass "bash -n $(basename "${f}")"
  else
    build_fail "bash -n $(basename "${f}") failed"
  fi
  chmod 700 "${f}"
done

# --- weekly: reuse hygiene, omit data-plane-only pieces --------------------
if grep -Fq 'MAINT_ROLE="gateway"' "${WEEKLY}"; then
  pass "weekly MAINT_ROLE=gateway"
else
  fail "weekly missing MAINT_ROLE=gateway"
fi
if grep -Fq 'restart Fail2Ban' "${WEEKLY}"; then
  pass "weekly restarts fail2ban"
else
  fail "weekly does not restart fail2ban"
fi
if grep -Fq 'restore_unattended_upgrades' "${WEEKLY}"; then
  pass "weekly restores unattended-upgrades"
else
  fail "weekly missing restore_unattended_upgrades"
fi
weekly_forbidden=0
for needle in docker xray AdGuardHome wins-node-register nginx amnezia; do
  if grep -Fiq "${needle}" "${WEEKLY}"; then
    fail "weekly contains data-plane piece: ${needle}"
    weekly_forbidden=1
  fi
done
if [[ "${weekly_forbidden}" -eq 0 ]]; then
  pass "weekly omits docker/xray/AdGuard/register/nginx/amnezia"
fi
if grep -Fq 'NOT restarting (would drop every v3 session)' "${WEEKLY}"; then
  pass "weekly refuses to restart an active winn3-gateway"
else
  fail "weekly missing active-gateway restart guard"
fi

# --- backup: credentials mandatory, age encrypt, no data-plane sources -----
if grep -Fq 'etc/winn/credentials' "${BACKUP}"; then
  pass "backup lists etc/winn/credentials"
else
  fail "backup missing etc/winn/credentials"
fi
if grep -Fq 'age -R' "${BACKUP}" && grep -Fq 'shred -u' "${BACKUP}"; then
  pass "backup encrypts with age -R and shreds plaintext"
else
  fail "backup missing age -R / shred -u"
fi
if grep -Fq 'REQUIRE_BACKUP_ENCRYPTION' "${BACKUP}"; then
  pass "backup honors REQUIRE_BACKUP_ENCRYPTION"
else
  fail "backup missing REQUIRE_BACKUP_ENCRYPTION"
fi
backup_forbidden=0
for needle in etc/amnezia usr/local/etc/xray opt/AdGuardHome wins-node-register docker; do
  if grep -Fq "${needle}" "${BACKUP}"; then
    fail "backup contains data-plane source: ${needle}"
    backup_forbidden=1
  fi
done
if [[ "${backup_forbidden}" -eq 0 ]]; then
  pass "backup omits amnezia/xray/AdGuard/register/docker paths"
fi
if grep -Fq 'backup-recipients.age' "${BACKUP}"; then
  pass "backup excludes age recipients from the archive"
else
  fail "backup does not mention excluding backup-recipients.age"
fi

# --- fail2ban jail shape (mirrors data-plane jail.d) -----------------------
if grep -Fq 'enabled = true' "${JAIL}" && grep -Fq 'backend = systemd' "${JAIL}" \
    && grep -Fq 'maxretry = 10' "${JAIL}" && grep -Fq 'bantime = 86400' "${JAIL}"; then
  pass "fail2ban sshd jail matches data-plane shape"
else
  fail "fail2ban jail missing expected sshd settings"
  echo "jail was:" >&2
  cat "${JAIL}" >&2
fi

# --- mock PATH for Linux-only helpers --------------------------------------
MOCK="${WORKDIR}/mock-bin"
mkdir -p "${MOCK}"

cat > "${MOCK}/stat" <<'EOF'
#!/usr/bin/env python3
import os, stat, sys
args = sys.argv[1:]
fmt = None
paths = []
i = 0
while i < len(args):
    if args[i] == "-c" and i + 1 < len(args):
        fmt = args[i + 1]
        i += 2
        continue
    if args[i].startswith("-"):
        i += 1
        continue
    paths.append(args[i])
    i += 1
if not paths:
    sys.exit(1)
path = paths[0]
st = os.stat(path)
mode = stat.S_IMODE(st.st_mode)
uid = 0  # the backup script requires root-owned contract/recipients
out = fmt or "%u %a"
out = out.replace("%u", str(uid)).replace("%a", f"{mode:o}")
sys.stdout.write(out + "\n")
EOF
chmod 700 "${MOCK}/stat"

cat > "${MOCK}/find" <<'EOF'
#!/usr/bin/env python3
"""GNU find -prune -perm /022 used by the backup script's recipients check.

Any other invocation is delegated to /usr/bin/find so the test harness can
still count files in the local backup directory.
"""
import os, stat, sys, subprocess
args = sys.argv[1:]
if "-perm" in args and any(a in ("/022", "-perm") for a in args):
    path = args[0] if args else ""
    if path and os.path.isfile(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o022:
            sys.stdout.write(path + "\n")
    sys.exit(0)
os.execv("/usr/bin/find", ["/usr/bin/find", *args])
EOF
chmod 700 "${MOCK}/find"

cat > "${MOCK}/age" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# age encryption/decryption test double: copy bytes verbatim.
out=""
infile=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -R) shift; shift || true ;;
    -d) shift ;;
    -i) shift; shift || true ;;
    -o) out="${2:-}"; shift 2 ;;
    *) infile="$1"; shift ;;
  esac
done
[[ -n "${out}" && -n "${infile}" ]] || exit 2
cp -a -- "${infile}" "${out}"
if [[ -n "${WINS_TEST_AGE_PLAINTEXT:-}" ]]; then
  cp -a -- "${infile}" "${WINS_TEST_AGE_PLAINTEXT}"
fi
printf 'mock-age-ok\n' >&2
EOF
chmod 700 "${MOCK}/age"

cat > "${MOCK}/shred" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shred -u -- FILE
target=""
for arg in "$@"; do
  case "${arg}" in
    -u|--|--remove) ;;
    *) target="${arg}" ;;
  esac
done
[[ -n "${target}" ]] || exit 2
rm -f -- "${target}"
EOF
chmod 700 "${MOCK}/shred"

cat > "${MOCK}/install" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Minimal GNU/BSD install stand-in: -d -m MODE DIR  or  -m MODE SRC DEST
mode="755"
dirs=0
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) dirs=1; shift ;;
    -m) mode="$2"; shift 2 ;;
    -o|-g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ "${dirs}" -eq 1 ]]; then
  mkdir -p "${args[@]}"
  chmod "${mode}" "${args[@]}"
  exit 0
fi
last_index=$((${#args[@]} - 1))
dest="${args[${last_index}]}"
unset 'args[${last_index}]'
if [[ "${dest}" == */ || -d "${dest}" ]]; then
  mkdir -p "${dest}"
  for src in "${args[@]}"; do
    cp -a "${src}" "${dest}/$(basename "${src}")"
    chmod "${mode}" "${dest}/$(basename "${src}")"
  done
  exit 0
fi
src="${args[0]}"
cp -a "${src}" "${dest}"
chmod "${mode}" "${dest}"
EOF
chmod 700 "${MOCK}/install"

# The generated backup script is GNU tar (Ubuntu). BSD tar rejects
# --hard-dereference. Homebrew gtar is the same dialect the node will run.
if [[ -x $HOME/.homebrew/Homebrew/bin/gtar ]]; then
  ln -sf $HOME/.homebrew/Homebrew/bin/gtar "${MOCK}/tar"
else
  fail "Homebrew gtar is required to exercise the GNU-tar backup script on macOS"
fi

count_files() {
  local dir="$1" pattern="$2"
  local extra="${3:-}"
  if [[ ! -d "${dir}" ]]; then
    printf '0'
    return 0
  fi
  if [[ -n "${extra}" ]]; then
    find "${dir}" -maxdepth 1 -type f -name "${pattern}" ! -name "${extra}" | wc -l | tr -d ' '
  else
    find "${dir}" -maxdepth 1 -type f -name "${pattern}" | wc -l | tr -d ' '
  fi
}

# Prefer our mocks over system binaries that disagree (BSD stat, BSD tar).
export PATH="${MOCK}:${PATH}"

make_fixture() {
  local root="$1"
  rm -rf "${root}"
  mkdir -p \
    "${root}/etc/winn/credentials" \
    "${root}/etc/winsvpn" \
    "${root}/etc/systemd/system" \
    "${root}/var/backups" \
    "${root}/run"
  printf 'STATIC-KEY-MATERIAL-NOT-A-REAL-KEY\n' > "${root}/etc/winn/credentials/winn3-gateway-static.key"
  printf 'ADMISSION-SECRET-NOT-A-REAL-SECRET\n' > "${root}/etc/winn/credentials/winn3-gateway-admission.key"
  chmod 600 "${root}/etc/winn/credentials/"*
  printf '%s\n' \
    'WINS_GATEWAY_RECOVERY_CONTRACT_VERSION=1' \
    'WINS_GATEWAY_INSTALL_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' \
    'WINS_GATEWAY_INSTALL_EPOCH=100' \
    'WINS_GATEWAY_RESTORE_ORDER=fresh-install-then-state' \
    > "${root}/etc/winsvpn/gateway-install-contract.env"
  chmod 600 "${root}/etc/winsvpn/gateway-install-contract.env"
  printf 'age1testrecipientpublickeyonly\n' > "${root}/etc/winsvpn/backup-recipients.age"
  chmod 600 "${root}/etc/winsvpn/backup-recipients.age"
  printf '%s\n' \
    'RCLONE_REMOTE=GoogleDrive_secured' \
    'REQUIRE_REMOTE_BACKUP=0' \
    "BACKUP_AGE_RECIPIENTS_FILE=${root}/etc/winsvpn/backup-recipients.age" \
    'REQUIRE_BACKUP_ENCRYPTION=1' \
    'LOCAL_BACKUP_RETENTION_DAYS=1' \
    'BACKUP_HOST_ID=gateway-test' \
    > "${root}/etc/winsvpn/gateway-backup.env"
  chmod 600 "${root}/etc/winsvpn/gateway-backup.env"
  printf 'WINN3_GATEWAY_ID=test\n' > "${root}/etc/winn/winn3-gateway.env"
}

run_backup() {
  local root="$1"
  local plaintext="$2"
  WINS_BACKUP_SOURCE_ROOT="${root}" \
    WINS_BACKUP_RUNTIME_ROOT="${root}/run" \
    WINS_TEST_AGE_PLAINTEXT="${plaintext}" \
    bash "${BACKUP}"
}

# CONTROL_GREEN
FIXTURE="${WORKDIR}/fixture-green"
PLAIN="${WORKDIR}/age-input.tar.gz"
make_fixture "${FIXTURE}"
mkdir -p "${FIXTURE}/var/backups/winsvpn"
printf 'expired\n' > "${FIXTURE}/var/backups/winsvpn/wins-gateway-backup-expired.tar.gz.age"
touch -t 200001010000 "${FIXTURE}/var/backups/winsvpn/wins-gateway-backup-expired.tar.gz.age"
set +e
run_backup "${FIXTURE}" "${PLAIN}" >"${WORKDIR}/green.out" 2>"${WORKDIR}/green.err"
green_rc=$?
set -e
if [[ "${green_rc}" -eq 0 ]]; then
  pass "CONTROL_GREEN backup exits 0"
else
  fail "CONTROL_GREEN backup exited ${green_rc}"
  cat "${WORKDIR}/green.err" >&2 || true
fi

if [[ -s "${PLAIN}" ]] && tar -tzf "${PLAIN}" | grep -E 'etc/winn/credentials/winn3-gateway-static.key' >/dev/null; then
  pass "CONTROL_GREEN archive contains winn3-gateway-static.key"
else
  fail "CONTROL_GREEN archive missing credentials member (plain=${PLAIN} exists=$([[ -e ${PLAIN} ]] && echo yes || echo no))"
  tar -tzf "${PLAIN}" 2>/dev/null | head >&2 || true
fi

age_count="$(count_files "${FIXTURE}/var/backups/winsvpn" 'wins-gateway-backup-*.tar.gz.age')"
plain_count="$(count_files "${FIXTURE}/var/backups/winsvpn" 'wins-gateway-backup-*.tar.gz' '*.age')"
if [[ "${age_count}" == "1" ]]; then
  pass "CONTROL_GREEN wrote one local .age archive"
else
  fail "CONTROL_GREEN expected one .age in local backups, got ${age_count}"
  ls -la "${FIXTURE}/var/backups/winsvpn" >&2 || true
fi
if [[ "${plain_count}" == "0" ]]; then
  pass "CONTROL_GREEN left no plaintext tar.gz in /var/backups/winsvpn"
else
  fail "CONTROL_GREEN left ${plain_count} plaintext tar.gz in local backups"
fi
if [[ ! -e "${FIXTURE}/var/backups/winsvpn/wins-gateway-backup-expired.tar.gz.age" ]]; then
  pass "CONTROL_GREEN pruned expired local gateway backup"
else
  fail "CONTROL_GREEN retained an expired local gateway backup"
fi

# Restore preflight must distinguish transport integrity from verified content.
AGE_ARCHIVE="$(find "${FIXTURE}/var/backups/winsvpn" -maxdepth 1 -type f -name '*.tar.gz.age' | head -n 1)"
AGE_MANIFEST="${AGE_ARCHIVE}.sha256"
IDENTITY="${WORKDIR}/offline-age-identity.txt"
printf 'AGE-SECRET-KEY-TEST-ONLY\n' > "${IDENTITY}"
set +e
bash "${RESTORE}" "${AGE_ARCHIVE}" "${AGE_MANIFEST}" >"${WORKDIR}/restore-noidentity.out" 2>"${WORKDIR}/restore-noidentity.err"
restore_rc=$?
set -e
if [[ "${restore_rc}" == "3" ]] && grep -Fq 'CONTENT UNVERIFIED' "${WORKDIR}/restore-noidentity.err"; then
  pass "restore encrypted archive without identity is CONTENT UNVERIFIED and nonzero"
else
  fail "restore encrypted archive without identity returned ${restore_rc}"
fi
set +e
bash "${RESTORE}" "${AGE_ARCHIVE}" "${AGE_MANIFEST}" "${IDENTITY}" >"${WORKDIR}/restore-verified.out" 2>"${WORKDIR}/restore-verified.err"
restore_verified_rc=$?
set -e
if [[ "${restore_verified_rc}" == "4" ]] \
    && grep -Fq 'CONTENT VERIFIED; LIVE CREDENTIAL RESTORE FORBIDDEN' "${WORKDIR}/restore-verified.err" \
    && grep -Fq 'higher descriptor seq and admission_gen' "${WORKDIR}/restore-verified.err"; then
  pass "restore verifies decrypted members but forbids replaying archived credentials"
else
  fail "restore verified archive returned ${restore_verified_rc} without the anti-rollback refusal"
  cat "${WORKDIR}/restore-verified.err" >&2 || true
fi

# IA-DP-10: a real gateway always carries /etc/winsvpn/role and
# owned-paths.winn3-gateway, and a co-hosted data-cover node also carries the
# data plane's secrets under /etc/winsvpn. Every archive such a host produces
# must still pass its own restore preflight and carry none of those files.
FIXTURE_CO="${WORKDIR}/fixture-cohosted"
PLAIN_CO="${WORKDIR}/age-input-cohosted.tar.gz"
make_fixture "${FIXTURE_CO}"
mkdir -p "${FIXTURE_CO}/etc/winsvpn/node-origin"
printf 'data-cover\n' > "${FIXTURE_CO}/etc/winsvpn/role"
printf '/etc/winn/winn3-gateway.env\n' > "${FIXTURE_CO}/etc/winsvpn/owned-paths.winn3-gateway"
printf 'ORIGIN-KEY-NOT-A-REAL-KEY\n' > "${FIXTURE_CO}/etc/winsvpn/node-origin/origin.key"
printf 'PUBLIC_VPN_INGRESS_ADMISSION=1\n' > "${FIXTURE_CO}/etc/winsvpn/public-vpn-ingress-admission.env"
printf 'disabled\n' > "${FIXTURE_CO}/etc/winsvpn/local-serving.disabled"
printf 'DATA_PLANE_BACKUP=1\n' > "${FIXTURE_CO}/etc/winsvpn/backup.env"
set +e
run_backup "${FIXTURE_CO}" "${PLAIN_CO}" >"${WORKDIR}/cohosted.out" 2>"${WORKDIR}/cohosted.err"
co_rc=$?
set -e
if [[ "${co_rc}" -eq 0 && -s "${PLAIN_CO}" ]]; then
  pass "IA-DP-10 co-hosted backup exits 0"
else
  fail "IA-DP-10 co-hosted backup exited ${co_rc}"
  cat "${WORKDIR}/cohosted.err" >&2 || true
fi
co_winsvpn="$(tar -tzf "${PLAIN_CO}" 2>/dev/null | grep -E '^\./?etc/winsvpn/.' | sed 's#^\./##' | LC_ALL=C sort | tr '\n' ' ' || true)"
if [[ "${co_winsvpn}" == "etc/winsvpn/gateway-backup-recovery.env etc/winsvpn/gateway-backup.env " ]]; then
  pass "IA-DP-10 archive carries only the two gateway files under etc/winsvpn"
else
  fail "IA-DP-10 archive carries etc/winsvpn members outside the recovery contract: ${co_winsvpn}"
fi
CO_ARCHIVE="$(find "${FIXTURE_CO}/var/backups/winsvpn" -maxdepth 1 -type f -name '*.tar.gz.age' | head -n 1)"
set +e
bash "${RESTORE}" "${CO_ARCHIVE}" "${CO_ARCHIVE}.sha256" "${IDENTITY}" >"${WORKDIR}/restore-cohosted.out" 2>"${WORKDIR}/restore-cohosted.err"
co_restore_rc=$?
set -e
if [[ "${co_restore_rc}" == "4" ]] && grep -Fq 'CONTENT VERIFIED; LIVE CREDENTIAL RESTORE FORBIDDEN' "${WORKDIR}/restore-cohosted.err"; then
  pass "IA-DP-10 co-hosted archive passes its own restore preflight"
else
  fail "IA-DP-10 restore preflight refused the gateway's own archive (rc=${co_restore_rc})"
  cat "${WORKDIR}/restore-cohosted.err" >&2 || true
fi

LEGACY_POLICY_ROOT="${WORKDIR}/legacy-policy-root"
LEGACY_POLICY="${WORKDIR}/legacy-policy.tar.gz"
mkdir -p "${LEGACY_POLICY_ROOT}/etc/winn/credentials" "${LEGACY_POLICY_ROOT}/etc/winsvpn"
printf 'old-consumed-static-key\n' > "${LEGACY_POLICY_ROOT}/etc/winn/credentials/winn3-gateway-static.key"
printf '%s\n' \
  'WINS_GATEWAY_RECOVERY_CONTRACT_VERSION=1' \
  'WINS_GATEWAY_SOURCE_INSTALL_ID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' \
  'WINS_GATEWAY_SOURCE_INSTALL_EPOCH=100' \
  'WINS_GATEWAY_BACKUP_EPOCH=101' \
  'WINS_GATEWAY_RESTORE_ORDER=fresh-install-then-state' \
  > "${LEGACY_POLICY_ROOT}/etc/winsvpn/gateway-backup-recovery.env"
tar -C "${LEGACY_POLICY_ROOT}" -czf "${LEGACY_POLICY}" .
(cd "${WORKDIR}" && sha256sum "$(basename "${LEGACY_POLICY}")" > "$(basename "${LEGACY_POLICY}").sha256")
if bash "${RESTORE}" "${LEGACY_POLICY}" "${LEGACY_POLICY}.sha256" >/dev/null 2>"${WORKDIR}/legacy-policy.err"; then
  fail "restore accepted a legacy archive without anti-rollback policy"
elif grep -Fq 'predates the anti-rollback credential policy' "${WORKDIR}/legacy-policy.err"; then
  pass "restore rejects legacy archive that could resurrect consumed credentials"
else
  fail "restore rejected legacy archive for the wrong reason"
  cat "${WORKDIR}/legacy-policy.err" >&2 || true
fi

MUTATED_POLICY="${WORKDIR}/mutated-policy.tar.gz"
python3 - "${PLAIN}" "${MUTATED_POLICY}" <<'PY'
import io
import tarfile
import sys

source, output = sys.argv[1:]
with tarfile.open(source, "r:gz") as src, tarfile.open(output, "w:gz") as dst:
    for member in src.getmembers():
        data = src.extractfile(member).read() if member.isfile() else None
        if member.name.lstrip("./") == "etc/winsvpn/gateway-backup-recovery.env":
            text = data.decode("utf-8").replace(
                "WINS_GATEWAY_CREDENTIAL_RESTORE_POLICY=regenerate-never-replay",
                "WINS_GATEWAY_CREDENTIAL_RESTORE_POLICY=replay-allowed",
            )
            data = text.encode("utf-8")
            member.size = len(data)
        dst.addfile(member, io.BytesIO(data) if data is not None else None)
PY
(cd "${WORKDIR}" && sha256sum "$(basename "${MUTATED_POLICY}")" > "$(basename "${MUTATED_POLICY}").sha256")
if bash "${RESTORE}" "${MUTATED_POLICY}" "${MUTATED_POLICY}.sha256" >/dev/null 2>"${WORKDIR}/mutated-policy.err"; then
  fail "restore accepted a recovery contract that permits credential replay"
elif grep -Fq 'invalid or permits credential replay' "${WORKDIR}/mutated-policy.err"; then
  pass "restore rejects a mutated credential replay policy"
else
  fail "restore rejected mutated policy for the wrong reason"
  cat "${WORKDIR}/mutated-policy.err" >&2 || true
fi

BADSUM="${WORKDIR}/bad.sha256"
printf '%064d  %s\n' 0 "$(basename "${AGE_ARCHIVE}")" > "${BADSUM}"
if bash "${RESTORE}" "${AGE_ARCHIVE}" "${BADSUM}" "${IDENTITY}" >/dev/null 2>&1; then
  fail "restore accepted a bad checksum"
else
  pass "restore rejects a bad checksum"
fi

GARBAGE="${WORKDIR}/garbage.tar.gz.age"
printf 'not an age payload\n' > "${GARBAGE}"
(cd "${WORKDIR}" && sha256sum "$(basename "${GARBAGE}")" > "$(basename "${GARBAGE}").sha256")
if bash "${RESTORE}" "${GARBAGE}" "${GARBAGE}.sha256" "${IDENTITY}" >/dev/null 2>&1; then
  fail "restore accepted checksum-valid garbage"
else
  pass "restore rejects checksum-valid garbage after decrypt"
fi

NOCRED_ROOT="${WORKDIR}/nocred-root"
NOCRED="${WORKDIR}/nocred.tar.gz"
mkdir -p "${NOCRED_ROOT}/etc/winsvpn"
printf 'WINS_GATEWAY_RESTORE_ORDER=fresh-install-then-state\n' > "${NOCRED_ROOT}/etc/winsvpn/gateway-backup-recovery.env"
tar -C "${NOCRED_ROOT}" -czf "${NOCRED}" .
(cd "${WORKDIR}" && sha256sum "$(basename "${NOCRED}")" > "$(basename "${NOCRED}").sha256")
if bash "${RESTORE}" "${NOCRED}" "${NOCRED}.sha256" >/dev/null 2>&1; then
  fail "restore accepted an archive without credentials"
else
  pass "restore rejects an archive without credentials"
fi

# CONTROL_NEUTRAL: comment-only edit of a private copy
NEUTRAL="${WORKDIR}/backup-neutral.sh"
awk 'NR==2 { print "# comment-only control: credentials path must still be backed up" } { print }' "${BACKUP}" > "${NEUTRAL}"
chmod 700 "${NEUTRAL}"
bash -n "${NEUTRAL}"
FIXTURE_N="${WORKDIR}/fixture-neutral"
PLAIN_N="${WORKDIR}/age-input-neutral.tar.gz"
make_fixture "${FIXTURE_N}"
if WINS_BACKUP_SOURCE_ROOT="${FIXTURE_N}" WINS_BACKUP_RUNTIME_ROOT="${FIXTURE_N}/run" \
    WINS_TEST_AGE_PLAINTEXT="${PLAIN_N}" bash "${NEUTRAL}"; then
  pass "CONTROL_NEUTRAL comment-only backup exits 0"
else
  fail "CONTROL_NEUTRAL comment-only backup exited nonzero"
fi

# M1: drop the credentials path from a private copy
MUT1="${WORKDIR}/backup-m1.sh"
# Replace only the mandatory-path occurrences, not the error-string word if we
# keep one — both the existence check and sources=(...) must move or the
# live check still forces credentials. Rename the path in both sites.
sed 's#etc/winn/credentials#etc/winn/credentials-MUTATED#g' "${BACKUP}" > "${MUT1}"
chmod 700 "${MUT1}"
if bash -n "${MUT1}"; then
  FIXTURE_M1="${WORKDIR}/fixture-m1"
  make_fixture "${FIXTURE_M1}"
  set +e
  WINS_BACKUP_SOURCE_ROOT="${FIXTURE_M1}" WINS_BACKUP_RUNTIME_ROOT="${FIXTURE_M1}/run" \
    WINS_TEST_AGE_PLAINTEXT="${WORKDIR}/age-m1.tar.gz" bash "${MUT1}" >/dev/null 2>"${WORKDIR}/m1.err"
  rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    pass "M1 renamed credentials path: backup exited ${rc} (caught)"
  else
    fail "M1 renamed credentials path: backup exited 0 (survivor — credentials no longer required)"
  fi
else
  build_fail "M1 mutant did not parse"
fi

# M2: no recipients, REQUIRE_BACKUP_ENCRYPTION=1
FIXTURE_M2="${WORKDIR}/fixture-m2"
make_fixture "${FIXTURE_M2}"
rm -f "${FIXTURE_M2}/etc/winsvpn/backup-recipients.age"
# Point env at the missing file (already the default path under fixture).
set +e
WINS_BACKUP_SOURCE_ROOT="${FIXTURE_M2}" WINS_BACKUP_RUNTIME_ROOT="${FIXTURE_M2}/run" \
  WINS_TEST_AGE_PLAINTEXT="${WORKDIR}/age-m2.tar.gz" bash "${BACKUP}" >/dev/null 2>"${WORKDIR}/m2.err"
rc=$?
set -e
if [[ "${rc}" -ne 0 ]]; then
  pass "M2 missing recipients: backup exited ${rc} (caught)"
else
  fail "M2 missing recipients: backup exited 0"
fi
m2_plain="$(count_files "${FIXTURE_M2}/var/backups/winsvpn" '*')"
if [[ "${m2_plain}" == "0" ]]; then
  pass "M2 missing recipients left nothing in /var/backups/winsvpn"
else
  fail "M2 missing recipients left ${m2_plain} file(s) in local backups"
  ls -la "${FIXTURE_M2}/var/backups/winsvpn" >&2 || true
fi
if grep -q 'REQUIRE_BACKUP_ENCRYPTION=1' "${WORKDIR}/m2.err"; then
  pass "M2 error names REQUIRE_BACKUP_ENCRYPTION=1"
else
  fail "M2 error did not name REQUIRE_BACKUP_ENCRYPTION=1"
  cat "${WORKDIR}/m2.err" >&2 || true
fi

# M3 inverted: live green must not leave plaintext. Already asserted above.
# Extra teeth: a mutant that comments out shred and the ARCHIVE=.age reassignment
# must be visible as plaintext in local backups.
MUT3="${WORKDIR}/backup-m3.sh"
python3 - "${BACKUP}" "${MUT3}" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text(encoding="utf-8")
old = '''  shred -u -- "${ARCHIVE}" 2>/dev/null || rm -f -- "${ARCHIVE}"
  ARCHIVE="${ARCHIVE}.age"
  ARCHIVE_NAME="${ARCHIVE_NAME}.age"'''
if src.count(old) != 1:
    raise SystemExit(f"shred block count={src.count(old)}")
src = src.replace(old, "  # shredded skipped by M3\n", 1)
Path(sys.argv[2]).write_text(src, encoding="utf-8")
PY
chmod 700 "${MUT3}"
if bash -n "${MUT3}"; then
  FIXTURE_M3="${WORKDIR}/fixture-m3"
  make_fixture "${FIXTURE_M3}"
  set +e
  WINS_BACKUP_SOURCE_ROOT="${FIXTURE_M3}" WINS_BACKUP_RUNTIME_ROOT="${FIXTURE_M3}/run" \
    WINS_TEST_AGE_PLAINTEXT="${WORKDIR}/age-m3.tar.gz" bash "${MUT3}" >/dev/null 2>"${WORKDIR}/m3.err"
  rc=$?
  set -e
  m3_plain="$(count_files "${FIXTURE_M3}/var/backups/winsvpn" 'wins-gateway-backup-*.tar.gz' '*.age')"
  if [[ "${rc}" -eq 0 && "${m3_plain}" != "0" ]]; then
    pass "M3 skip-shred left plaintext tar.gz (caught inverted: mutant is red vs live green)"
  else
    fail "M3 skip-shred did not leave plaintext (rc=${rc} plain=${m3_plain}); mutation may not have applied"
  fi
else
  build_fail "M3 mutant did not parse"
fi

# --- weekly EXIT restores unattended-upgrades --------------------------------
WEEKLY_FAIL="${WORKDIR}/weekly-failure"
WEEKLY_EVENTS="${WORKDIR}/weekly-events.log"
: > "${WEEKLY_EVENTS}"
sed \
  -e "s#LOG_FILE=\"/var/log/winsvpn/weekly-maintenance.log\"#LOG_FILE=\"${WORKDIR}/weekly-maintenance.log\"#" \
  -e "s#STATUS_FILE=\"/var/log/winsvpn/weekly-maintenance.status\"#STATUS_FILE=\"${WORKDIR}/weekly-maintenance.status\"#" \
  -e "s#mkdir -p /var/log/winsvpn#mkdir -p \"${WORKDIR}\"#" \
  -e '/run_step "apt update"/a\
exit 71
' \
  "${WEEKLY}" > "${WEEKLY_FAIL}"
chmod 700 "${WEEKLY_FAIL}"
FAKE="${WORKDIR}/weekly-fake-bin"
mkdir -p "${FAKE}"
cat > "${FAKE}/systemctl" <<'EOF'
#!/usr/bin/env bash
printf 'systemctl:%s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
cat > "${FAKE}/apt-get" <<'EOF'
#!/usr/bin/env bash
printf 'package-work:apt-get %s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
cat > "${FAKE}/dpkg" <<'EOF'
#!/usr/bin/env bash
printf 'package-work:dpkg %s\n' "$*" >> "${WINS_TEST_EVENT_FILE}"
exit 0
EOF
for command_name in fuser pgrep; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "${FAKE}/${command_name}"
done
chmod 700 "${FAKE}/"*
set +e
PATH="${FAKE}:${PATH}" WINS_TEST_EVENT_FILE="${WEEKLY_EVENTS}" bash "${WEEKLY_FAIL}" >/dev/null 2>&1
weekly_rc=$?
set -e
if [[ "${weekly_rc}" == "71" ]]; then
  pass "weekly injected failure exits 71"
else
  fail "weekly injected failure exited ${weekly_rc}, expected 71"
fi
python3 - "${WEEKLY_EVENTS}" <<'PY'
import sys
events = open(sys.argv[1], encoding="utf-8").read().splitlines()
try:
    stop = events.index("systemctl:stop unattended-upgrades")
    work = next(i for i, e in enumerate(events) if e.startswith("package-work:"))
    restore = events.index("systemctl:enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer")
except (ValueError, StopIteration) as exc:
    print("EVENTS", events)
    raise SystemExit(f"missing event: {exc}")
if not (stop < work < restore):
    print(events)
    raise SystemExit(f"order stop={stop} work={work} restore={restore}")
print("OK")
PY
pass "weekly EXIT restores unattended-upgrades after package work"

# --- installer does not clobber data-plane backup.env / weekly -------------
if grep -Fq 'Do not touch /etc/winsvpn/backup.env' "${INSTALL}"; then
  pass "installer documents not touching data-plane backup.env"
else
  fail "installer missing backup.env non-clobber note"
fi
if grep -Fq 'data_plane_weekly_present' "${INSTALL}"; then
  pass "installer skips data-plane weekly overwrite"
else
  fail "installer missing data_plane_weekly_present"
fi

echo
echo "PASS=${PASS} FAIL=${FAIL} BUILD_FAIL=${BUILD_FAIL}"
if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
