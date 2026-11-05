#!/usr/bin/env bash
# Core installer runtime test: the package-reboot boundary and the fail-closed
# hold (IA-CORE-01, 02, 05, 07, 13).
#
# Drives the real main(), traps, preimage capture, reboot pause, rollback and
# hold from server/wins_core_server_setup_ONETOUCH.sh. Only the host-mutating
# edges are replaced: package installation, swap policy and the iptables
# binaries (through the installer's own CORE_SECURITY_* hooks). One case also
# commits the hold with the real iptables inside a private network namespace.
#
# Needs root on Linux (GNU stat/find/install), like
# tools/test_deployment_runtime_configs.sh. Optional first argument: the core
# installer to test (the mutation driver passes mutated copies).
set -Eeuo pipefail
trap '[[ $- == *e* ]] && echo "FAIL ${BASH_SOURCE[0]##*/}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_SCRIPT="$(realpath -- "${1:-${ROOT_DIR}/server/wins_core_server_setup_ONETOUCH.sh}")"

[[ "$(uname -s)" == Linux && "${EUID}" -eq 0 ]] || {
  echo "This runtime test needs root on Linux." >&2
  exit 1
}
# Nothing here may reach a network: run the whole test in a private one.
if [[ -z "${WINS_CORE_REBOOT_TEST_NETNS:-}" ]]; then
  command -v unshare >/dev/null 2>&1 || { echo "unshare is required." >&2; exit 1; }
  exec env WINS_CORE_REBOOT_TEST_NETNS=1 unshare --net -- bash "$0" "${CORE_SCRIPT}"
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT
chmod 700 "${work_dir}"

# Isolate every configuration path the installer sources at load time.
export WINS_DEFAULTS_FILE=/nonexistent/winsvpn-defaults.env
export WINS_SECRETS_FILE=/nonexistent/winsvpn-secrets.env
export AWG_OBFUSCATION_PROFILE=/nonexistent/awg-obfuscation.env
export CORE_ENV_FILE=/nonexistent/wins_core.env
export HUB_API_BASE=http://192.0.2.1
export INSTALL_CORE_IDS_IPS=1
export CORE_STEALTH_TRANSPORTS='80:none,443:tls'
export CORE_ADMIN_CIDR=192.0.2.0/24
unset SSH_CONNECTION WINSVPN_DEPLOY_SOURCE CORE_BOOTSTRAP_TOKEN CORE_TOKEN || true

# A bare `! cmd` never trips errexit, so negative checks go through this.
refute_grep() {
  if grep "$@"; then
    echo "FAIL unexpected match: grep $*" >&2
    exit 1
  fi
}

HOLD_IN='-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN'
GRANT="$(printf 'g%.0s' {1..40})"

# A case directory: a fake host root, stateful iptables mocks and hook paths.
# The mocks keep the live hold in ${R}/hold-active, log every iptables
# mutation to ${R}/iptables.log and every restore payload to ${R}/restore.log.
new_case() {
  R="${work_dir}/$1"
  mkdir -p "${R}/bin" "${R}/host/etc/iptables"
  cat > "${R}/bin/iptables-save" <<'EOF'
#!/usr/bin/env bash
if [[ -e "${MOCK_ROOT:?}/hold-active" ]]; then
  printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' \
    ':WINVPN-CORE-FAILURE-HOLD-IN - [0:0]' ':WINVPN-CORE-FAILURE-HOLD-FWD - [0:0]' \
    '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' \
    '-A WINVPN-CORE-FAILURE-HOLD-IN -j DROP' '-A WINVPN-CORE-FAILURE-HOLD-FWD -j DROP' COMMIT
elif [[ -e "${MOCK_ROOT}/serving" ]]; then
  printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' \
    '-A WINVPN-CORE-INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0' \
    '-A WINVPN-CORE-INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0' COMMIT
else
  printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':FORWARD ACCEPT [0:0]' COMMIT
fi
EOF
  cat > "${R}/bin/iptables-restore" <<'EOF'
#!/usr/bin/env bash
payload="$(cat)"
if [[ " $* " == *' --test '* ]]; then exit "${MOCK_RESTORE_TEST_RC:-0}"; fi
[[ "${MOCK_RESTORE_COMMIT_RC:-0}" == 0 ]] || exit "${MOCK_RESTORE_COMMIT_RC}"
printf '%s\n--\n' "${payload}" >> "${MOCK_ROOT:?}/restore.log"
if grep -Fxq -- '-A WINVPN-CORE-FAILURE-HOLD-IN -j DROP' <<<"${payload}"; then
  touch "${MOCK_ROOT}/hold-active"
fi
EOF
  cat > "${R}/bin/iptables" <<'EOF'
#!/usr/bin/env bash
held=0; [[ -e "${MOCK_ROOT:?}/hold-active" ]] && held=1
case "$1" in
  -S)
    if [[ "${held}" != 1 ]]; then printf '%s\n' "-P $2 ACCEPT"; exit 0; fi
    case "$2" in
      INPUT) printf '%s\n' '-P INPUT DROP' '-A INPUT -j WINVPN-CORE-FAILURE-HOLD-IN' ;;
      FORWARD) printf '%s\n' '-P FORWARD DROP' '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD' ;;
      *) exit 1 ;;
    esac
    ;;
  -C) [[ "${held}" == 1 ]] ;;
  -D) printf '%s\n' "$*" >> "${MOCK_ROOT}/iptables.log"; rm -f -- "${MOCK_ROOT}/hold-active" ;;
  *) exit 1 ;;
esac
EOF
  chmod 755 "${R}/bin/"*
  printf '%s\n' '11111111-1111-4111-8111-111111111111' > "${R}/boot-id"
  export MOCK_ROOT="${R}"
  export CORE_SECURITY_IPTABLES_SAVE_BIN="${R}/bin/iptables-save"
  export CORE_SECURITY_IPTABLES_RESTORE_BIN="${R}/bin/iptables-restore"
  export CORE_SECURITY_IPTABLES_BIN="${R}/bin/iptables"
  export CORE_SECURITY_IP6TABLES_SAVE_BIN=/nonexistent/ip6tables-save
  export WINS_CORE_SECURITY_ROOT="${R}/host"
  export CORE_PACKAGE_SECURITY_PREIMAGE_ROOT="${R}/preimages"
  export CORE_FAILURE_HOLD_RECEIPT_ROOT="${R}/holds"
  export WINSVPN_REBOOT_REQUIRED_FILE="${R}/reboot-required"
  export WINSVPN_BOOT_ID_FILE="${R}/boot-id"
  export WINSVPN_DEPLOY_STATE_DIR="${R}/state"
  export CORE_SYNC_AGENT_PATH="${R}/wins-core-sync"
  unset CORE_IPTABLES_RULES_V4_PATH MOCK_RESTORE_TEST_RC MOCK_RESTORE_COMMIT_RC || true
}

# The protected-state Suricata files an installed Core carries.
install_protected_suricata_files() {
  install -d -m 755 "${R}/host/etc/suricata" \
    "${R}/host/etc/systemd/system/suricata.service.d" "${R}/host/lib/systemd/system"
  printf '%s\n' 'vars: {}' > "${R}/host/etc/suricata/suricata.yaml"
  printf '%s\n' '[Service]' 'ExecStart=' \
    'ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0 -c /etc/suricata/suricata.yaml' \
    > "${R}/host/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf"
  printf '%s\n' '[Service]' 'ExecStart=/usr/bin/suricata --af-packet' \
    > "${R}/host/lib/systemd/system/suricata.service"
  chmod 644 "${R}/host/etc/suricata/suricata.yaml" \
    "${R}/host/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf" \
    "${R}/host/lib/systemd/system/suricata.service"
}

# Runs the real main() --deploy with only the host-mutating steps replaced.
# apt_install leaves what the Ubuntu package leaves (suricata.yaml and the
# vendor unit, never the Wins -q 0 override) and, when asked, the reboot flag.
# configure_swap_policy is the first step after the reboot boundary.
run_core_deploy() {
  local reboot_required="$1"
  (
    # shellcheck disable=SC1090
    source "${CORE_SCRIPT}"
    unique_preimage_dir
    as_root() { :; }
    wins_lock_deployed_xray_pin() { return 0; }
    preflight_core() { :; }
    verify_disk_encryption_posture() { :; }
    mark_core_role() { :; }
    apt_install() {
      install -d -m 755 "${R}/host/etc/suricata" "${R}/host/lib/systemd/system"
      printf '%s\n' 'vars: {}' > "${R}/host/etc/suricata/suricata.yaml"
      printf '%s\n' '[Service]' > "${R}/host/lib/systemd/system/suricata.service"
      chmod 644 "${R}/host/etc/suricata/suricata.yaml" "${R}/host/lib/systemd/system/suricata.service"
      if [[ "${reboot_required}" == 1 ]]; then touch "${WINSVPN_REBOOT_REQUIRED_FILE}"; fi
    }
    configure_swap_policy() { touch "${R}/resumed-after-boundary"; exit 0; }
    main --deploy
  ) > "${R}/deploy.log" 2>&1
}

# The preimage stamp is second-resolution plus $$, which a ( ) subshell shares
# with this test; give every capture its own directory instead.
unique_preimage_dir() {
  export CORE_PACKAGE_SECURITY_PREIMAGE_DIR="${CORE_PACKAGE_SECURITY_PREIMAGE_ROOT}/capture-${BASHPID}"
}

latest_preimage_state() {
  sed -n 's/^state=//p' "$(cat "${R}/preimages/latest")/contract.env"
}

# --- IA-CORE-01: the package-reboot pause is not a failure ------------------
new_case reboot-pause
set +e
run_core_deploy 1
rc=$?
set -e
[[ "${rc}" == 75 ]] || { cat "${R}/deploy.log" >&2; echo "FAIL reboot pause exited ${rc}, expected 75" >&2; exit 1; }
grep -Fq 'Deployment paused safely' "${R}/deploy.log"
[[ ! -e "${R}/holds/latest.receipt" ]] || { cat "${R}/deploy.log" >&2; echo "FAIL a failure hold was installed for a reboot pause" >&2; exit 1; }
[[ ! -e "${R}/restore.log" && ! -e "${R}/hold-active" ]]
refute_grep -Eq 'CRITICAL|package mutation failed' "${R}/deploy.log"
[[ ! -e "${R}/resumed-after-boundary" ]]
grep -Fxq 'boot_id=11111111-1111-4111-8111-111111111111' "${R}/state/core.reboot-required"
[[ "$(latest_preimage_state)" == fresh ]]
echo "PASS Core package-reboot pause exits 75 with no rollback, no hold and no CRITICAL line"

# The rerun after the reboot: the package's suricata.yaml and vendor unit now
# exist, the Wins override does not. The host is still fresh and resumes.
printf '%s\n' '22222222-2222-4222-8222-222222222222' > "${R}/boot-id"
rm -f -- "${WINSVPN_REBOOT_REQUIRED_FILE}"
set +e
run_core_deploy 0
rc=$?
set -e
[[ "${rc}" == 0 ]] || { cat "${R}/deploy.log" >&2; echo "FAIL post-reboot rerun exited ${rc}, expected 0" >&2; exit 1; }
[[ -e "${R}/resumed-after-boundary" ]]
grep -Fq 'Verified the required package reboot for the core role' "${R}/deploy.log"
[[ "$(latest_preimage_state)" == fresh ]]
[[ ! -e "${R}/state/core.reboot-required" && ! -e "${R}/holds/latest.receipt" ]]
echo "PASS Core rerun after the package reboot classifies the host fresh and resumes past the boundary"

# A dangling symlink in place of the Wins override is not an absent override:
# the host is not fresh, and the preimage capture refuses it.
new_case symlinked-override
install -d -m 755 "${R}/host/etc/suricata" "${R}/host/etc/systemd/system/suricata.service.d" "${R}/host/lib/systemd/system"
printf '%s\n' 'vars: {}' > "${R}/host/etc/suricata/suricata.yaml"
printf '%s\n' '[Service]' > "${R}/host/lib/systemd/system/suricata.service"
chmod 644 "${R}/host/etc/suricata/suricata.yaml" "${R}/host/lib/systemd/system/suricata.service"
ln -s "${R}/nowhere.conf" "${R}/host/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf"
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  if capture_core_package_security_preimage; then exit 0; else exit 1; fi
) > "${R}/capture.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]] || { cat "${R}/capture.out" >&2; echo "FAIL a symlinked override was classified as a fresh host" >&2; exit 1; }
grep -Fq 'is missing or unsafe' "${R}/capture.out"
echo "PASS Core preimage capture refuses a symlinked override instead of treating the host as fresh"

# --- A real failure at the boundary still rolls back and holds (IA-CORE-05/07)
new_case boundary-failure
export WINSVPN_BOOT_ID_FILE="${R}/unreadable-boot-id"
set +e
run_core_deploy 1
rc=$?
set -e
[[ "${rc}" == 1 ]] || { cat "${R}/deploy.log" >&2; echo "FAIL boundary failure exited ${rc}, expected 1" >&2; exit 1; }
grep -Fxq 'reason=fresh-package-mutation-failure' "${R}/holds/latest.receipt"
grep -Fxq 'boot_persisted=1' "${R}/holds/latest.receipt"
grep -Fq 'held closed with a root-only receipt' "${R}/deploy.log"
! grep -Fq 'CRITICAL' "${R}/deploy.log" || { cat "${R}/deploy.log" >&2; echo "FAIL a correctly installed hold was reported as a CRITICAL rollback failure" >&2; exit 1; }
[[ "$(stat -c '%u:%g:%a' "${R}/host/etc/iptables/rules.v4")" == 0:0:600 ]]
grep -Fxq -- "${HOLD_IN}" "${R}/host/etc/iptables/rules.v4"
grep -Fxq "active_rules_sha256=$(sha256sum "${R}/host/etc/iptables/rules.v4" | awk '{print $1}')" "${R}/holds/latest.receipt"
[[ -z "$(find "${R}/host/etc/iptables" -name '.rules.v4.*' -print -quit)" ]]
echo "PASS Core non-75 boundary failure rolls back, persists the hold for boot, and reports it truthfully"

# --- IA-CORE-05: the rollback reports the hold's real outcome ----------------
# Called the way production calls it: in a conditional context, where errexit
# is off, and once from inside the armed ERR trap.
new_case hold-commit-fails
export MOCK_RESTORE_COMMIT_RC=4
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  capture_core_package_security_preimage
  if restore_core_package_security_preimage; then exit 0; else exit 1; fi
) > "${R}/restore.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]] || { cat "${R}/restore.out" >&2; echo "FAIL a failed hold commit was reported as held closed" >&2; exit 1; }
refute_grep -Fq 'held closed with a root-only receipt' "${R}/restore.out"
[[ ! -e "${R}/holds/latest.receipt" ]]
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  trap 'core_deployment_error_handler "$?"' ERR
  trap 'core_deployment_exit_handler "$?"' EXIT
  capture_core_package_security_preimage
  false
) > "${R}/trap.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]]
grep -Fq 'CRITICAL: automatic Core package-security rollback failed' "${R}/trap.out"
echo "PASS Core fresh rollback returns failure when the hold cannot be committed, in and out of the trap"

# --- IA-CORE-07: persistence edges ---------------------------------------------
new_case hold-no-persistent-dir
rmdir "${R}/host/etc/iptables"
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  install_core_failure_hold_firewall unit-test-no-dir
) > "${R}/hold.out" 2>&1
grep -Fxq 'boot_persisted=0' "${R}/holds/latest.receipt"
grep -Fq 'not persisted' "${R}/hold.out"
[[ ! -e "${R}/host/etc/iptables" ]]

new_case hold-persist-fails
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  install() {
    case "${!#}" in */.rules.v4.wins-hold.*) return 1 ;; esac
    command install "$@"
  }
  if install_core_failure_hold_firewall unit-test-persist-fails; then exit 0; else exit 1; fi
) > "${R}/hold.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]]
grep -Fq 'will not survive a reboot' "${R}/hold.out"
grep -Fxq 'boot_persisted=0' "${R}/holds/latest.receipt"
[[ ! -e "${R}/host/etc/iptables/rules.v4" ]]
[[ -z "$(find "${R}/host/etc/iptables" -name '.rules.v4.*' -print -quit)" ]]

new_case hold-receipt-fails
printf 'not a directory\n' > "${R}/holds"
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  if install_core_failure_hold_firewall unit-test-receipt-fails; then exit 0; else exit 1; fi
) > "${R}/hold.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]]
grep -Fq 'receipt could not be written' "${R}/hold.out"
echo "PASS Core hold records a missing persistence directory and fails on unpersisted or unreceipted holds"

# --- IA-CORE-13: a failed re-hold never removes the live hold ----------------
new_case rehold-validation-fails
touch "${R}/hold-active"
export MOCK_RESTORE_TEST_RC=2
set +e
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  if install_core_failure_hold_firewall unit-test-rehold; then exit 0; else exit 1; fi
) > "${R}/hold.out" 2>&1
rc=$?
set -e
[[ "${rc}" == 1 ]]
[[ -e "${R}/hold-active" ]] || { echo "FAIL the live hold was removed before the replacement validated" >&2; exit 1; }
[[ ! -e "${R}/iptables.log" ]]
unset MOCK_RESTORE_TEST_RC
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  install_core_failure_hold_firewall unit-test-rehold
) > "${R}/hold.out" 2>&1
[[ ! -e "${R}/iptables.log" ]]
python3 - "${R}/restore.log" <<'PY'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
assert lines.count("-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN") == 1, lines
assert lines.count("-D FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD") == 1, lines
assert lines.index("-D INPUT -j WINVPN-CORE-FAILURE-HOLD-IN") < lines.index("-I INPUT 1 -j WINVPN-CORE-FAILURE-HOLD-IN"), lines
PY
echo "PASS Core re-hold removes the previous hold jumps only inside its own atomic transaction"

# --- IA-CORE-05: the protected rollback does not report a failed restore -----
new_case protected-restore-fails
install_protected_suricata_files
touch "${R}/serving"
cat > "${R}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$1" in daemon-reload|reset-failed|is-active) exit 0 ;; restart) exit "${MOCK_RESTART_RC:-0}" ;; *) exit 64 ;; esac
EOF
cat > "${R}/bin/suricata" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == --build-info ]] && { echo 'NFQ support: yes'; exit 0; }
[[ "$1" == -T ]]
EOF
printf '%s\n' '#!/usr/bin/env bash' '[[ "$*" == "-c uptime" ]]' > "${R}/bin/suricatasc"
chmod 755 "${R}/bin/systemctl" "${R}/bin/suricata" "${R}/bin/suricatasc"
printf '%s\n' '0 0 0 0 0 0 0 0 0' > "${R}/nfnetlink_queue"
export CORE_SECURITY_SYSTEMCTL_BIN="${R}/bin/systemctl" CORE_SECURITY_SURICATA_BIN="${R}/bin/suricata"
export CORE_SECURITY_SURICATASC_BIN="${R}/bin/suricatasc" CORE_NFQUEUE_PROC_PATH="${R}/nfnetlink_queue"
export CORE_SECURITY_IP6TABLES_RESTORE_BIN=/nonexistent/ip6tables-restore
for failure in firewall-commit suricata-restart; do
  set +e
  (
    # shellcheck disable=SC1090
    source "${CORE_SCRIPT}"
    unique_preimage_dir
    capture_core_package_security_preimage
    [[ "$(sed -n 's/^state=//p' "${CORE_PACKAGE_SECURITY_PREIMAGE_ACTIVE}/contract.env")" == protected ]]
    if [[ "${failure}" == firewall-commit ]]; then export MOCK_RESTORE_COMMIT_RC=4; else export MOCK_RESTART_RC=5; fi
    if restore_core_package_security_preimage; then exit 0; else exit 1; fi
  ) > "${R}/restore-${failure}.out" 2>&1
  rc=$?
  set -e
  [[ "${rc}" == 1 ]] || { cat "${R}/restore-${failure}.out" >&2; echo "FAIL protected rollback reported success after a ${failure} failure" >&2; exit 1; }
  refute_grep -Fq 'Restored and validated' "${R}/restore-${failure}.out"
done
(
  # shellcheck disable=SC1090
  source "${CORE_SCRIPT}"
  unique_preimage_dir
  capture_core_package_security_preimage
  restore_core_package_security_preimage
) > "${R}/restore-ok.out" 2>&1
grep -Fq 'Restored and validated' "${R}/restore-ok.out"
echo "PASS Core protected rollback fails on a failed firewall commit or Suricata restart and passes when both succeed"

# --- IA-CORE-02: a token-less env file from a failed first bootstrap ---------
# CORE_ID and the env file are the only inputs; curl is recorded, never run.
run_withdrawal() {
  (
    # shellcheck disable=SC1090
    source "${CORE_SCRIPT}"
    unique_preimage_dir
    curl() { printf '%s\n' "$*" >> "${R}/curl.log"; printf '{}'; }
    load_existing_core_env_for_preflight
    if begin_core_deployment_withdrawal_before_mutation; then exit 0; else exit 1; fi
  ) > "${R}/withdrawal.out" 2>&1
}
new_case tokenless-env
export CORE_ENV_FILE="${R}/wins_core.env"
printf 'CORE_TOKEN=%q\nCORE_ID=%q\n' "" "test-core" > "${CORE_ENV_FILE}"
chmod 600 "${CORE_ENV_FILE}"
set +e
CORE_BOOTSTRAP_TOKEN="${GRANT}" run_withdrawal; rc_grant=$?
run_withdrawal; rc_nogrant=$?
touch "${CORE_SYNC_AGENT_PATH}"
CORE_BOOTSTRAP_TOKEN="${GRANT}" run_withdrawal; rc_registered=$?
set -e
[[ "${rc_grant}" == 0 ]] || { echo "FAIL a never-registered token-less Core with a fresh grant was refused" >&2; exit 1; }
[[ "${rc_nogrant}" == 1 && "${rc_registered}" == 1 ]]
grep -Fq 'lacks CORE_TOKEN' "${R}/withdrawal.out"
[[ ! -e "${R}/curl.log" && ! -e "${R}/hold-active" ]]
printf 'CORE_TOKEN=%q\nCORE_ID=%q\n' "existing-token-value" "test-core" > "${CORE_ENV_FILE}"
set +e
CORE_BOOTSTRAP_TOKEN="${GRANT}" run_withdrawal; rc_token=$?
set -e
[[ "${rc_token}" == 1 ]]
grep -Fq '/api/v1/core/test-core/deployment/withdraw' "${R}/curl.log"
grep -Fq 'Hub refused the pre-mutation Core deployment withdrawal' "${R}/withdrawal.out"
export CORE_ENV_FILE=/nonexistent/wins_core.env
echo "PASS Core rerun after a failed first bootstrap proceeds only with a grant and no sync agent; a token still goes to the hub"

# --- IA-CORE-07/13 against the real netfilter, in this private namespace -----
if command -v iptables-restore >/dev/null 2>&1 && iptables -S INPUT >/dev/null 2>&1; then
  new_case real-netfilter
  unset CORE_SECURITY_IPTABLES_SAVE_BIN CORE_SECURITY_IPTABLES_RESTORE_BIN CORE_SECURITY_IPTABLES_BIN
  for attempt in 1 2; do
    (
      # shellcheck disable=SC1090
      source "${CORE_SCRIPT}"
      unique_preimage_dir
      install_core_failure_hold_firewall "real-netfilter-${attempt}"
    ) > "${R}/real-${attempt}.out" 2>&1 || { cat "${R}/real-${attempt}.out" >&2; echo "FAIL real hold attempt ${attempt}" >&2; exit 1; }
    [[ "$(iptables -S INPUT | sed -n '2p')" == "${HOLD_IN}" ]]
    [[ "$(iptables -S INPUT | grep -Fxc -- "${HOLD_IN}")" == 1 ]]
    [[ "$(iptables -S FORWARD | grep -Fxc -- '-A FORWARD -j WINVPN-CORE-FAILURE-HOLD-FWD')" == 1 ]]
    grep -Fxq -- "${HOLD_IN}" "${R}/host/etc/iptables/rules.v4"
    grep -Fxq "reason=real-netfilter-${attempt}" "${R}/holds/latest.receipt"
  done
  # The persisted file is a complete ruleset that the real parser accepts.
  iptables-restore --test < "${R}/host/etc/iptables/rules.v4"
  echo "PASS Core hold commits twice with the real iptables ($(iptables --version)) and persists a restorable rules.v4"
else
  echo "SKIP real-netfilter hold case: iptables is unavailable in this namespace"
fi

echo "Core reboot-boundary and fail-closed hold runtime tests passed."
