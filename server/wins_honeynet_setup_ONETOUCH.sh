#!/usr/bin/env bash
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
export DEBIAN_PRIORITY=critical
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1

APT_GET=(apt-get -o DPkg::Lock::Timeout=900 -o Acquire::Retries=3 -o Dpkg::Use-Pty=0 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

TPOT_REPOSITORY="https://github.com/telekom-security/tpotce.git"
TPOT_COMMIT="${TPOT_COMMIT:-84637788c76629c449925f2428387fdb61454f0e}"
TPOT_DIR="${TPOT_DIR:-${HOME}/tpotce}"
TPOT_TYPE="${TPOT_TYPE:-h}"
ROLE_FILE="/etc/winsvpn/role"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# T-Pot's own "incoming, T-Pot Management" ports per upstream's port table
# (README "Ports" section, verified against the pinned commit above):
# 64294 sensor-to-hive data via the NGINX reverse proxy, 64295 SSH, 64297
# the NGINX-fronted WebUI. These are distinct from the many honeypot
# listener ports, which are deliberately left open to the whole internet.
TPOT_ADMIN_PORTS_DEFAULT="64294 64295 64297"
WINS_HONEYNET_ADMIN_NFT_CONF="/etc/wins-honeynet-admin-cidr.nft"
WINS_HONEYNET_ADMIN_NFT_TABLE="wins_honeynet_admin"

# sha256 of install.sh at TPOT_COMMIT above *after* applying this script's own
# apply_password_fd_patch (see write_tpot_install_password_fd_patch). This is
# not an externally-sourced value being trusted blindly: it pins our own
# deterministic patch output against itself, so apply_password_fd_patch can
# detect upstream drift or a corrupted/tampered patch application before this
# script ever hands a real secret to the patched installer.
TPOT_INSTALL_PATCHED_SHA256="97f660c02eb587e55feaf59115262c07ea69afc8f2fa3656181b52ca87dd1df5"

log() { printf '[HONEynet] %s\n' "$*"; }
warn() { printf '[HONEynet] WARN: %s\n' "$*" >&2; }
die() { printf '[HONEynet] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: bash server/wins_honeynet_setup_ONETOUCH.sh --validate|--deploy|--postflight

This role is for a fresh, dedicated, disposable Ubuntu 24.04 host only. It
must not share a VPS, VPC trust zone, credentials, SSH keys, backups, DNS
tokens, or private network routes with any Win's VPN production server.

Required acknowledgements:
  HONEYPOT_ACK_ISOLATED=YES
  HONEYPOT_EGRESS_GUARD_ACK=YES
  HONEYPOT_ADMIN_CIDR=<trusted management CIDR>

TPOT_TYPE=h installs a standalone Hive and additionally requires:
  HONEYPOT_WEB_USER=<3-32 safe characters>
  HONEYPOT_WEB_PASSWORD=<24-128 printable non-space characters>

TPOT_TYPE=s installs a sensor and requires a separately deployed Hive. The
reviewed pinned installer is invoked through its supported unattended mode;
deployment still prints its SSH, firewall, package, and reboot changes.
EOF
}

package_manager_busy() {
  local lock_file
  if command -v fuser >/dev/null 2>&1; then
    for lock_file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
      fuser "${lock_file}" >/dev/null 2>&1 && return 0
    done
  fi
  pgrep -x '(apt|apt-get|dpkg)' >/dev/null 2>&1
}

wait_for_cloud_init_and_apt() {
  local timeout="${HONEYPOT_APT_LOCK_TIMEOUT_SECONDS:-900}" elapsed=0
  local output="" status=0
  if command -v cloud-init >/dev/null 2>&1; then
    output="$(timeout "${timeout}" cloud-init status --wait 2>&1)" || status=$?
    if ((status != 0)) && ! grep -Eq '^status:[[:space:]]*(done|disabled)$' <<<"${output}"; then
      die "cloud-init did not finish within ${timeout}s; inspect cloud-init status --long before retrying."
    fi
  fi
  while package_manager_busy; do
    ((elapsed >= timeout)) && die "Timed out waiting for cloud-init or the package manager after ${timeout}s."
    sleep 5
    ((elapsed += 5))
  done
}

install_prerequisites() {
  command -v sudo >/dev/null 2>&1 || die "A non-root sudo-capable administration user is required."
  sudo -n true >/dev/null 2>&1 || \
    die "Unattended deployment requires noninteractive sudo; provision the decoy admin key/user first."
  wait_for_cloud_init_and_apt
  sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "${APT_GET[@]}" update
  sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    "${APT_GET[@]}" install -y --no-install-recommends \
      ca-certificates git python3 nftables
  command -v git >/dev/null 2>&1 || die "git installation did not complete."
  command -v nft >/dev/null 2>&1 || die "nftables installation did not complete."
}

require_supported_host() {
  local os_id="" os_version="" role="" default_ifaces="" memory_kb disk_kb
  [[ -r /etc/os-release ]] || die "Missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID:-}"
  os_version="${VERSION_ID:-}"
  [[ "${os_id}" == "ubuntu" && "${os_version}" == "24.04" ]] || \
    die "Use a fresh Ubuntu 24.04 server; detected ${os_id:-unknown} ${os_version:-unknown}."
  [[ -d /run/systemd/system ]] || die "A systemd-based host is required."
  [[ "$(uname -m)" == "x86_64" ]] || die "This reviewed profile currently supports x86_64 only."
  command -v python3 >/dev/null 2>&1 || die "Install python3 from Ubuntu's repository before continuing."

  [[ "${HONEYPOT_ACK_ISOLATED:-}" == "YES" ]] || \
    die "Set HONEYPOT_ACK_ISOLATED=YES only after assigning a separate disposable host and trust zone."
  [[ "${HONEYPOT_EGRESS_GUARD_ACK:-}" == "YES" ]] || \
    die "Set HONEYPOT_EGRESS_GUARD_ACK=YES only after configuring provider-level egress containment."
  [[ -n "${HONEYPOT_ADMIN_CIDR:-}" ]] || die "HONEYPOT_ADMIN_CIDR is required."
  python3 - "${HONEYPOT_ADMIN_CIDR}" <<'PY'
import ipaddress
import sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY

  case "${TPOT_TYPE}" in
    h|s) ;;
    *) die "TPOT_TYPE must be h (standalone Hive) or s (distributed sensor)." ;;
  esac
  if [[ "${TPOT_TYPE}" == "h" ]]; then
    [[ "${HONEYPOT_WEB_USER:-}" =~ ^[A-Za-z0-9_.-]{3,32}$ ]] || \
      die "HONEYPOT_WEB_USER must contain 3-32 letters, digits, dot, underscore, or hyphen characters."
    # HONEYPOT_WEB_PASSWORD is deliberately read from the environment here,
    # not passed as an argv token: this script's own process already has it
    # exported (it must, to see "${HONEYPOT_WEB_PASSWORD:-}" itself), and a
    # child process inherits the environment silently, whereas an argv value
    # is visible to any local user via ps/proc for as long as the process runs.
    python3 - "${HONEYPOT_WEB_USER}" <<'PY'
import os
import string
import sys

user = sys.argv[1]
password = os.environ.get("HONEYPOT_WEB_PASSWORD", "")
if not 24 <= len(password) <= 128:
    raise SystemExit("HONEYPOT_WEB_PASSWORD must contain 24-128 characters.")
if any(ch not in string.printable or ch.isspace() for ch in password):
    raise SystemExit("HONEYPOT_WEB_PASSWORD must contain printable non-space characters only.")
if password.casefold() == user.casefold():
    raise SystemExit("HONEYPOT_WEB_PASSWORD must not equal HONEYPOT_WEB_USER.")
classes = (
    any(ch.islower() for ch in password),
    any(ch.isupper() for ch in password),
    any(ch.isdigit() for ch in password),
    any(not ch.isalnum() for ch in password),
)
if sum(classes) < 3:
    raise SystemExit("HONEYPOT_WEB_PASSWORD must use at least three character classes.")
PY
  fi

  if [[ -s "${ROLE_FILE}" ]]; then
    role="$(tr -d '[:space:]' < "${ROLE_FILE}")"
    [[ "${role}" == "honeynet" ]] || die "Host is already assigned to Win's VPN role '${role}'."
  fi
  [[ ! -e /root/vpn_auth && ! -e /root/node.env && ! -e /etc/wins-core ]] || \
    die "Production VPN artifacts were found. Reimage this host; do not convert it in place."

  default_ifaces="$(ip -o route show default | awk '{print $5}' | sort -u | tr '\n' ' ')"
  [[ -n "${default_ifaces// }" && "$(wc -w <<<"${default_ifaces}")" -eq 1 ]] || \
    die "T-Pot's reviewed deployment expects exactly one default-route interface; found: ${default_ifaces:-none}"

  memory_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  disk_kb="$(df -Pk "${HOME}" | awk 'NR==2 {print $2}')"
  if [[ "${TPOT_TYPE}" == "h" ]]; then
    ((memory_kb >= 16777216)) || die "Standalone Hive requires at least 16 GiB RAM."
    ((disk_kb >= 268435456)) || die "Standalone Hive requires at least 256 GiB total storage."
  else
    ((memory_kb >= 8388608)) || die "Sensor requires at least 8 GiB RAM."
    ((disk_kb >= 134217728)) || die "Sensor requires at least 128 GiB total storage."
  fi

  if ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:)(80|443|64294|64295|64297)$'; then
    die "A T-Pot-required TCP port is already in use. Reimage or remove the conflicting service."
  fi
  log "Dedicated-host preflight passed type=${TPOT_TYPE} interface=${default_ifaces} admin_cidr=${HONEYPOT_ADMIN_CIDR}"
}

# Restricts T-Pot's admin ports to HONEYPOT_ADMIN_CIDR using this host's own
# nftables. Previously this CIDR was validated and logged but never actually
# enforced locally; the script relied entirely on the hosting provider's
# firewall/security group, which this script has no way to inspect or
# guarantee. This must run, and be verified by verify_admin_cidr_firewall,
# before T-Pot's installer brings those ports up. Idempotent (delete+
# redefine the table in one atomic `nft -f` transaction, per the nftables
# wiki's documented pattern for tables independently managed alongside
# others, e.g. Docker's), so it is safe to rerun on redeploy, and it is
# reasserted on every boot by wins-honeynet-admin-cidr.service so a later
# reboot (T-Pot requires one) can never silently drop the restriction.
enforce_admin_cidr_firewall() {
  command -v nft >/dev/null 2>&1 || die "nftables (nft) is required to locally enforce HONEYPOT_ADMIN_CIDR."
  local family_token other_family_nfproto
  family_token="$(python3 - "${HONEYPOT_ADMIN_CIDR}" <<'PY'
import ipaddress
import sys
print("ip6" if ipaddress.ip_network(sys.argv[1], strict=False).version == 6 else "ip")
PY
)"
  # HONEYPOT_ADMIN_CIDR only ever names one address family. In an `inet`
  # (dual-stack) table, a family-qualified match (`ip saddr` / `ip6 saddr`)
  # never evaluates the other family's packets at all -- they fall straight
  # through to this chain's own `policy accept`, leaving the admin ports
  # fully open on whichever family the operator didn't configure. Since
  # there is no configured address for that other family, the only
  # correct default is to drop its traffic to these ports outright. A bare
  # `ip6`/`ip` token with no following field is not valid nft syntax on its
  # own (empirically confirmed: "syntax error, unexpected counter"); an
  # unconditional family match needs `meta nfproto ipv4`/`ipv6` instead.
  other_family_nfproto="ipv4"
  [[ "${family_token}" == "ip" ]] && other_family_nfproto="ipv6"
  local admin_ports_nft="${TPOT_ADMIN_PORTS_DEFAULT// /, }"

  # This script runs as a non-root sudo-capable user throughout (see the
  # EUID checks in prepare_pinned_source below), so every write under /etc
  # and every nft/systemctl mutation must go through explicit sudo, the same
  # way the existing ROLE_FILE handling below does via `sudo tee`. A plain
  # shell redirect (`cat >`) would run as the unprivileged invoking user and
  # fail outright against /etc paths.
  cat <<EOF | sudo tee "${WINS_HONEYNET_ADMIN_NFT_CONF}" >/dev/null
# Managed by server/wins_honeynet_setup_ONETOUCH.sh (enforce_admin_cidr_firewall).
# Do not edit by hand; rerun that script's --deploy step to regenerate.
table inet ${WINS_HONEYNET_ADMIN_NFT_TABLE}
delete table inet ${WINS_HONEYNET_ADMIN_NFT_TABLE}

table inet ${WINS_HONEYNET_ADMIN_NFT_TABLE} {
  chain input {
    type filter hook input priority -10; policy accept;
    ip saddr 127.0.0.0/8 accept
    ip6 saddr ::1 accept
    tcp dport { ${admin_ports_nft} } ${family_token} saddr != ${HONEYPOT_ADMIN_CIDR} counter drop
    tcp dport { ${admin_ports_nft} } meta nfproto ${other_family_nfproto} counter drop
  }
}
EOF
  sudo chmod 600 "${WINS_HONEYNET_ADMIN_NFT_CONF}"
  sudo nft -c -f "${WINS_HONEYNET_ADMIN_NFT_CONF}" || \
    die "Generated nftables admin-CIDR ruleset failed validation (nft -c -f)."
  sudo nft -f "${WINS_HONEYNET_ADMIN_NFT_CONF}"

  # Reasserted at every boot, ordered before networking comes up, so there
  # is no post-reboot window with this table absent. nftables rule loading
  # does not require an active network path, so running this early is safe.
  cat <<EOF | sudo tee /etc/systemd/system/wins-honeynet-admin-cidr.service >/dev/null
[Unit]
Description=Wins VPN local nftables enforcement of HONEYPOT_ADMIN_CIDR for T-Pot admin ports
DefaultDependencies=no
Before=sysinit.target network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${WINS_HONEYNET_ADMIN_NFT_CONF}

[Install]
WantedBy=sysinit.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable wins-honeynet-admin-cidr.service
}

# Confirms the effective, currently-installed kernel ruleset (not merely the
# on-disk config file) still restricts every T-Pot admin port to
# HONEYPOT_ADMIN_CIDR, and that enforcement is enabled to persist across
# reboot. Used at both --deploy time and --postflight.
verify_admin_cidr_firewall() {
  command -v nft >/dev/null 2>&1 || { warn "nft is required to verify admin-CIDR enforcement."; return 1; }
  local ruleset admin_ports_nft="${TPOT_ADMIN_PORTS_DEFAULT// /, }"
  local family_token other_family_nfproto
  family_token="$(python3 - "${HONEYPOT_ADMIN_CIDR}" <<'PY'
import ipaddress
import sys
print("ip6" if ipaddress.ip_network(sys.argv[1], strict=False).version == 6 else "ip")
PY
)"
  other_family_nfproto="ipv4"
  [[ "${family_token}" == "ip" ]] && other_family_nfproto="ipv6"
  # Reading netfilter state generally needs the same privilege as writing
  # it, so this uses sudo too (see enforce_admin_cidr_firewall).
  ruleset="$(sudo nft list table inet "${WINS_HONEYNET_ADMIN_NFT_TABLE}" 2>/dev/null)" || {
    warn "Local admin-CIDR enforcement table '${WINS_HONEYNET_ADMIN_NFT_TABLE}' is not loaded in the kernel."
    return 1
  }
  grep -Fq 'hook input priority -10' <<<"${ruleset}" || {
    warn "Local admin-CIDR enforcement chain hook was altered or removed."
    return 1
  }
  grep -Fq "dport { ${admin_ports_nft} }" <<<"${ruleset}" || {
    warn "Local admin-CIDR enforcement no longer covers the expected T-Pot admin ports (${admin_ports_nft})."
    return 1
  }
  grep -Fq "${HONEYPOT_ADMIN_CIDR}" <<<"${ruleset}" || {
    warn "Local admin-CIDR enforcement no longer references the configured HONEYPOT_ADMIN_CIDR."
    return 1
  }
  grep -Fq 'drop' <<<"${ruleset}" || {
    warn "Local admin-CIDR enforcement rule no longer drops non-matching sources."
    return 1
  }
  grep -Fq "dport { ${admin_ports_nft} } meta nfproto ${other_family_nfproto}" <<<"${ruleset}" || {
    warn "Local admin-CIDR enforcement no longer restricts the ${other_family_nfproto} address family; the admin ports are open to the entire ${other_family_nfproto} internet."
    return 1
  }
  systemctl is-enabled --quiet wins-honeynet-admin-cidr.service 2>/dev/null || {
    warn "Local admin-CIDR enforcement is not enabled to persist across reboot."
    return 1
  }
}

# Best-effort, provider-agnostic check. This script targets any Ubuntu
# 24.04 VPS regardless of hosting provider, and this sandboxed environment
# has no credentials for, or documented API contract with, a real cloud
# provider's firewall/security-group console. A genuine implementation
# needs to be written against whichever specific provider this host
# actually runs on (its CLI or REST API), authenticate, list the security
# group/firewall attached to this host, and assert it permits the given
# ports from admin_cidr only. Rather than fabricate an integration this
# environment cannot exercise or verify, this always reports "unverified"
# and tells the operator exactly what to check by hand. This is a
# deliberately separate, non-fatal opinion about the provider's side of
# the fence; enforce_admin_cidr_firewall/verify_admin_cidr_firewall above
# are this host's own real, verified, fail-closed half of the control.
provider_firewall_allows_only() {
  local admin_cidr="$1"; shift
  local ports=("$@")
  warn "Provider-firewall verification for TCP ${ports[*]} is NOT automated here:"
  warn "  this script has no credentials for, and no coded integration with,"
  warn "  whichever hosting provider this host runs on."
  warn "MANUAL ACTION REQUIRED: in that provider's control panel or"
  warn "  security-group/firewall console, confirm inbound TCP ${ports[*]}"
  warn "  is restricted to ${admin_cidr} and nothing wider, on the live host"
  warn "  (not just in this script)."
  return 2
}

tpot_install_sha256() {
  sha256sum "${TPOT_DIR}/install.sh" 2>/dev/null | awk '{print $1}'
}

# Upstream's install.sh only accepts the Hive/sensor-fleet web password via
# `-p <password>`, an argv token any local user/process can read from
# /proc/<pid>/cmdline for as long as the installer runs. Upstream has no
# `--password-fd`, stdin-read, or env-var alternative at the pinned commit
# (checked: only `-p` populates myWEB_PW). This vendors a small, reviewed
# patch adding `-P <fd>`, which reads one line from an already-open file
# descriptor instead, so main() can pipe the secret in via fd 0 and it never
# appears in argv. Kept as a heredoc here (applied to a throwaway file and
# removed immediately) rather than a separate tracked file so it can't drift
# from the sha256 pin checked by apply_password_fd_patch without both being
# reviewed together in the same diff.
write_tpot_install_password_fd_patch() {
  local patch_file="$1"
  cat > "${patch_file}" <<'PATCH_EOF'
--- a/install.sh
+++ b/install.sh
@@ -2,19 +2,24 @@
 
 print_help() {
   cat <<EOF
-Usage: $0 [-s] -t <type> [-u <webuser>] [-p <password>]
+Usage: $0 [-s] -t <type> [-u <webuser>] [-p <password>|-P <fd>]
 
 Options:
   -s                Suppress installation confirmation prompt (sets myQST=y)
   -t <type>         Type of installation (required if -s is used):
-                      h - hive      (requires -u and -p)
+                      h - hive      (requires -u and -p/-P)
                       s - sensor    (no user/pass required)
-                      l - llm       (requires -u and -p)
-                      i - mini      (requires -u and -p)
+                      l - llm       (requires -u and -p/-P)
+                      i - mini      (requires -u and -p/-P)
                       m - mobile    (no user/pass required)
-                      t - tarpit    (requires -u and -p)
+                      t - tarpit    (requires -u and -p/-P)
   -u <webuser>      Web interface username (required for h/l/i/t)
-  -p <password>     Web interface password (required for h/l/i/t)
+  -p <password>     Web interface password (required for h/l/i/t unless -P
+                      is used). Visible in argv/process listings; prefer -P.
+  -P <fd>           Read the web interface password from open file
+                      descriptor <fd> (e.g. -P 0 to read one line from
+                      stdin) instead of argv. Wins VPN Inc. local patch:
+                      keeps the password out of /proc/<pid>/cmdline.
   -h                Show this help message
 EOF
   exit 1
@@ -56,8 +61,9 @@
 myTPOT_TYPE=""
 myWEB_USER=""
 myWEB_PW=""
+myWEB_PW_FD=""
 
-while getopts ":st:u:p:h" opt; do
+while getopts ":st:u:p:P:h" opt; do
   case "$opt" in
     s)
       myQST="y"
@@ -72,6 +78,9 @@
     p)
       export myWEB_PW="${OPTARG}"
       ;;
+    P)
+      myWEB_PW_FD="${OPTARG}"
+      ;;
     h|\?)
       print_help
       ;;
@@ -81,6 +90,16 @@
       ;;
   esac
 done
+
+# Wins VPN Inc. local patch: let -P name an already-open file descriptor to
+# read the web-user password from (one line, e.g. a piped stdin), instead of
+# requiring the plaintext password as an argv token via -p. -p still wins if
+# both are somehow given. This keeps the secret out of /proc/<pid>/cmdline
+# and process listings during unattended (-s) installs.
+if [[ -z "$myWEB_PW" && -n "$myWEB_PW_FD" ]]; then
+  IFS= read -r myWEB_PW <&"${myWEB_PW_FD}"
+  export myWEB_PW
+fi
 
 # -s requires -t
 if [[ "$myQST" == "y" && -z "$myTPOT_TYPE" ]]; then
PATCH_EOF
}

# Applies write_tpot_install_password_fd_patch to the pinned checkout and
# verifies the *result* against TPOT_INSTALL_PATCHED_SHA256 before letting
# deployment continue, so a patch that failed to apply cleanly (upstream
# drift) or landed corrupted cannot silently fall through to installing with
# an unpatched -p-only installer. Idempotent: if a previous run already
# applied it, the pre-check short-circuits.
apply_password_fd_patch() {
  [[ "$(tpot_install_sha256)" != "${TPOT_INSTALL_PATCHED_SHA256}" ]] || return 0
  local patch_file
  patch_file="$(mktemp)"
  # Deliberately not using `trap ... RETURN` for cleanup here: bash RETURN
  # traps are not scoped to the function that set them, they keep firing on
  # every enclosing function's return too. That would re-run this cleanup
  # against prepare_pinned_source's (and main's) return with patch_file no
  # longer in scope, which is a real, previously-confirmed unbound-variable
  # crash under `set -u`. Explicit rm -f on every exit path avoids that.
  write_tpot_install_password_fd_patch "${patch_file}"
  git -C "${TPOT_DIR}" apply --whitespace=nowarn "${patch_file}" || {
    rm -f -- "${patch_file}"
    die "Failed to apply the reviewed password-fd patch to the pinned T-Pot installer; upstream install.sh may have drifted from the reviewed commit."
  }
  rm -f -- "${patch_file}"
  [[ "$(tpot_install_sha256)" == "${TPOT_INSTALL_PATCHED_SHA256}" ]] || \
    die "Patched T-Pot installer does not match the reviewed sha256 pin (${TPOT_INSTALL_PATCHED_SHA256}); refusing to proceed with an unverified installer."
}

prepare_pinned_source() {
  [[ "${EUID:-$(id -u)}" -ne 0 ]] || die "Run T-Pot as a non-root sudo-capable user, per upstream requirements."
  if [[ -e "${TPOT_DIR}" && ! -d "${TPOT_DIR}/.git" ]]; then
    die "${TPOT_DIR} exists but is not a Git checkout; move it aside manually."
  fi
  if [[ ! -d "${TPOT_DIR}/.git" ]]; then
    git clone --no-checkout --filter=blob:none "${TPOT_REPOSITORY}" "${TPOT_DIR}"
  fi
  if [[ -n "$(git -C "${TPOT_DIR}" status --porcelain)" ]]; then
    # The one expected local diff is our own already-applied password-fd
    # patch from a prior run (checked by content, not just presence);
    # anything else is unreviewed drift/tampering and must stop deployment.
    [[ "$(git -C "${TPOT_DIR}" status --porcelain)" == " M install.sh" \
      && "$(tpot_install_sha256)" == "${TPOT_INSTALL_PATCHED_SHA256}" ]] || \
      die "${TPOT_DIR} has local changes; review them before deployment."
  fi
  git -C "${TPOT_DIR}" fetch --depth 1 origin "${TPOT_COMMIT}"
  git -C "${TPOT_DIR}" checkout --detach "${TPOT_COMMIT}"
  [[ "$(git -C "${TPOT_DIR}" rev-parse HEAD)" == "${TPOT_COMMIT}" ]] || die "Pinned T-Pot commit verification failed."
  # checkout --detach above only moves HEAD; it does not revert a
  # working-tree-only edit to a file already at this commit, so reset
  # install.sh to upstream's pristine content before re-checking its
  # contract and reapplying our patch fresh on every run.
  git -C "${TPOT_DIR}" checkout -- install.sh
  grep -Fq 'while getopts ":st:u:p:h"' "${TPOT_DIR}/install.sh" || \
    die "Pinned T-Pot installer no longer exposes the reviewed unattended argument contract."
  apply_password_fd_patch
  sudo install -d -m 700 /etc/winsvpn
  printf 'honeynet\n' | sudo tee "${ROLE_FILE}" >/dev/null
  sudo chmod 600 "${ROLE_FILE}"
}

postflight() {
  # Unlike --validate/--deploy, --postflight does not call
  # require_supported_host, so this variable is not otherwise guaranteed to
  # be set in this invocation; check explicitly for a clear error instead of
  # an "unbound variable" crash from set -u once verify_admin_cidr_firewall
  # below references it.
  [[ -n "${HONEYPOT_ADMIN_CIDR:-}" ]] || die "HONEYPOT_ADMIN_CIDR is required (same value used for --deploy)."
  [[ -s "${ROLE_FILE}" && "$(tr -d '[:space:]' < "${ROLE_FILE}")" == "honeynet" ]] || die "Honeynet role marker missing."
  systemctl is-active --quiet tpot.service || die "tpot.service is not active."
  command -v docker >/dev/null 2>&1 || die "Docker is not installed."
  [[ -n "$(docker ps -q)" ]] || die "No T-Pot containers are running."
  ss -H -lnt | awk '{print $4}' | grep -Eq '(^|:)64295$' || die "T-Pot management SSH port 64295 is not listening."
  ss -H -lnt | awk '{print $4}' | grep -Eq '(^|:)64297$' || die "T-Pot management web port 64297 is not listening."
  verify_admin_cidr_firewall || \
    die "Local HONEYPOT_ADMIN_CIDR enforcement did not verify; admin ports may be reachable beyond ${HONEYPOT_ADMIN_CIDR}."
  # Non-fatal: see provider_firewall_allows_only for why the provider side
  # cannot be verified from inside this host in a provider-agnostic way.
  provider_firewall_allows_only "${HONEYPOT_ADMIN_CIDR}" ${TPOT_ADMIN_PORTS_DEFAULT} || true
  log "Local postflight passed: admin ports are live and locally restricted to ${HONEYPOT_ADMIN_CIDR}, verified against the effective nftables ruleset (not just a reminder)."
}

# --- F-11: crash dumps, journals, swap and hibernation (HANDOFF 3g) --------
# Role-portable emitters: the five one-touch installers do not all define the
# same log/warn/err trio (the honeynet role has `die` and no `err`), and this
# block must be byte-identical in every role so it cannot drift between them.
_f11_log()  { if declare -F log  >/dev/null 2>&1; then log  "$@"; else printf '[INFO] %s\n' "$*"; fi; }
_f11_warn() { if declare -F warn >/dev/null 2>&1; then warn "$@"; else printf '[WARN] %s\n' "$*" >&2; fi; }
_f11_err()  { if declare -F err  >/dev/null 2>&1; then err  "$@"; else printf '[ERR] %s\n'  "$*" >&2; fi; }

# --- F-11 step 5a helpers: no second copy of the journal on disk ------------
# MEASURED 2026-09-24 on seven data-plane nodes (lane L25): Storage=volatile
# held the journal in RAM, but every line was ALSO in /var/log/syslog,
# kern.log and auth.log, kept for four weekly rotations. Two paths put it
# there:
#   * Ubuntu's rsyslog package ships /usr/lib/systemd/journald.conf.d/syslog.conf
#     with ForwardToSyslog=yes. journald.conf(5) sorts drop-ins by FILENAME
#     across all directories, so syslog.conf is read after 99-winsvpn.conf and
#     turns forwarding back on;
#   * rsyslog's imklog reads /proc/kmsg itself, so kernel lines reach kern.log
#     even with forwarding off.
# The zz- drop-in sorts after syslog.conf, and rsyslog.service plus
# syslog.socket are stopped and masked. No role reads the rsyslog files:
# fail2ban runs backend=systemd, for which fail2ban's jail.conf says logpath
# is not valid, and the hub's alert monitor reads journalctl. Files rsyslog
# already wrote are NOT removed here; deleting them is an operator decision.
#
# Every step must succeed and every postcondition is observed; a check that
# cannot run is a failure, not a pass (Round U, OI-U3).
WINS_F11_SYSLOG_STATE=/var/lib/winsvpn/f11-syslog-prior-state
WINS_F11_NO_SYSLOG_DROPIN=/etc/systemd/journald.conf.d/zz-winsvpn-no-syslog.conf
# Exact copy (bytes and mode, cp -p) of a zz drop-in that existed before the
# first containment run, kept beside the state record in the same 0700
# directory. Written only when the drop-in existed.
WINS_F11_ZZ_PRIOR_COPY=/var/lib/winsvpn/f11-zz-winsvpn-no-syslog.conf.prior

# Prints "present" or "absent". rsyslog counts as present when its package is
# installed or its unit is loaded, so a unit left behind by a removed package
# is still contained.
_f11_rsyslog_presence() {
  local pkg load
  pkg="$(dpkg-query -W -f='${db:Status-Abbrev}' rsyslog 2>/dev/null || true)"
  load="$(systemctl show -p LoadState --value rsyslog.service 2>/dev/null || true)"
  if [[ "${pkg}" == "ii "* || "${load}" == "loaded" ]]; then
    printf 'present\n'
  else
    printf 'absent\n'
  fi
}

# Records the prior state once, on the first run that reaches this step, so a
# re-run cannot overwrite the original with the already-contained state.
# Before overwriting an existing zz drop-in, retain its exact contents and mode
# in the protected prior-state record (Round U, OI-U3): the copy is taken, and
# checked byte for byte, before the state file exists, so a state file that
# says "present" always has its copy.
_f11_syslog_record_prior_state() {
  local presence="$1" unit prop value zz_state=absent
  [[ -s "${WINS_F11_SYSLOG_STATE}" ]] && return 0
  install -d -m 700 "${WINS_F11_SYSLOG_STATE%/*}" || return 1
  if [[ -e "${WINS_F11_NO_SYSLOG_DROPIN}" || -L "${WINS_F11_NO_SYSLOG_DROPIN}" ]]; then
    [[ -f "${WINS_F11_NO_SYSLOG_DROPIN}" && ! -L "${WINS_F11_NO_SYSLOG_DROPIN}" ]] || return 1
    cp -p -- "${WINS_F11_NO_SYSLOG_DROPIN}" "${WINS_F11_ZZ_PRIOR_COPY}.tmp" || return 1
    cmp -s -- "${WINS_F11_NO_SYSLOG_DROPIN}" "${WINS_F11_ZZ_PRIOR_COPY}.tmp" || return 1
    mv -f -- "${WINS_F11_ZZ_PRIOR_COPY}.tmp" "${WINS_F11_ZZ_PRIOR_COPY}" || return 1
    zz_state=present
  fi
  {
    printf 'recorded_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'rsyslog=%s\n' "${presence}"
    printf 'zz_dropin=%s\n' "${zz_state}"
    for unit in rsyslog.service syslog.socket; do
      for prop in LoadState ActiveState UnitFileState; do
        value="$(systemctl show -p "${prop}" --value "${unit}" 2>/dev/null || true)"
        printf '%s.%s=%s\n' "${unit}" "${prop}" "${value}"
      done
    done
  } > "${WINS_F11_SYSLOG_STATE}.tmp" || return 1
  chmod 600 "${WINS_F11_SYSLOG_STATE}.tmp" || return 1
  mv -f "${WINS_F11_SYSLOG_STATE}.tmp" "${WINS_F11_SYSLOG_STATE}"
}

# Reads the effective journald ForwardToSyslog. Missing tool, failed command
# or no assignment at all are failures, never an implicit pass.
_f11_effective_forward_to_syslog() {
  local merged value
  if ! command -v systemd-analyze >/dev/null 2>&1; then
    _f11_err "F-11: systemd-analyze is not available; the effective ForwardToSyslog cannot be verified"
    return 1
  fi
  if ! merged="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null)"; then
    _f11_err "F-11: systemd-analyze cat-config systemd/journald.conf failed; the effective ForwardToSyslog cannot be verified"
    return 1
  fi
  value="$(printf '%s\n' "${merged}" \
    | sed -n 's/^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*//p' | tail -n 1)"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -z "${value}" ]]; then
    _f11_err "F-11: the merged journald configuration has no ForwardToSyslog assignment; the drop-ins were not read"
    return 1
  fi
  printf '%s\n' "${value}"
}

_f11_contain_syslog_units() {
  local presence="$1" unit state
  if [[ "${presence}" == "absent" ]]; then
    # Explicit, not assumed: with no rsyslog, nothing may be serving the
    # syslog socket or answering as syslog.service either.
    _f11_log "F-11: rsyslog is not installed; checking that no other syslog daemon is running"
    for unit in syslog.socket syslog.service; do
      if systemctl is-active --quiet "${unit}" 2>/dev/null; then
        _f11_err "F-11: rsyslog is absent but ${unit} is active; an unknown syslog daemon would still copy the journal to disk"
        return 1
      fi
    done
    return 0
  fi
  if ! systemctl stop syslog.socket rsyslog.service; then
    _f11_err "F-11: could not stop rsyslog.service and syslog.socket"
    return 1
  fi
  if ! systemctl mask rsyslog.service syslog.socket; then
    _f11_err "F-11: could not mask rsyslog.service and syslog.socket"
    return 1
  fi
  for unit in rsyslog.service syslog.socket; do
    state="$(systemctl is-active "${unit}" 2>/dev/null || true)"
    if [[ "${state}" != "inactive" && "${state}" != "failed" ]]; then
      _f11_err "F-11: ${unit} is '${state}' after stop; it would keep copying the journal to /var/log"
      return 1
    fi
    state="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
    if [[ "${state}" != "masked" ]]; then
      _f11_err "F-11: ${unit} is '${state}' after mask, not 'masked'"
      return 1
    fi
  done
}

# A fresh entry must reach the journal and must not reach any file rsyslog
# writes. This is the observation that the disk copy is actually closed.
_f11_verify_no_disk_copy() {
  local journal_storage="$1" nonce seen="" f _
  nonce="wins-f11-probe-$(cat /proc/sys/kernel/random/uuid 2>/dev/null || printf '%s-%s' "$(date +%s)" "${RANDOM}${RANDOM}")"
  if ! printf '%s\n' "${nonce}" | systemd-cat -t wins-f11-probe -p info; then
    _f11_err "F-11: could not write a probe entry to the journal"
    return 1
  fi
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    seen="$(journalctl -q --no-pager -t wins-f11-probe -o cat -n 50 2>/dev/null || true)"
    [[ $'\n'"${seen}"$'\n' == *$'\n'"${nonce}"$'\n'* ]] && break
    seen=""
    sleep 0.5
  done
  if [[ -z "${seen}" ]]; then
    _f11_err "F-11: a fresh probe entry never appeared in the journal; journald is not accepting entries"
    return 1
  fi
  sleep 1
  for f in /var/log/syslog /var/log/messages /var/log/user.log /var/log/daemon.log /var/log/kern.log /var/log/auth.log; do
    if [[ -f "${f}" ]] && grep -Fqs -- "${nonce}" "${f}"; then
      _f11_err "F-11: the journal probe entry was also written to ${f}; the disk copy is still open"
      return 1
    fi
  done
  if [[ "${journal_storage}" == "volatile" && -d /var/log/journal ]]; then
    _f11_err "F-11: Storage=volatile but /var/log/journal exists after the journald restart"
    return 1
  fi
  _f11_log "F-11 verified: a fresh journal entry was recorded and no syslog file on disk received it"
}

# Step 5a. Called from harden_crash_artifacts after 99-winsvpn.conf is written.
contain_syslog_disk_copy() {
  local journal_storage="$1" presence forward
  presence="$(_f11_rsyslog_presence)"
  _f11_syslog_record_prior_state "${presence}" || {
    _f11_err "F-11: could not record the prior syslog state in ${WINS_F11_SYSLOG_STATE}; refusing to change it without a rollback record"
    return 1
  }
  cat > "${WINS_F11_NO_SYSLOG_DROPIN}" <<'EOF' || return 1
[Journal]
ForwardToSyslog=no
EOF
  chmod 644 "${WINS_F11_NO_SYSLOG_DROPIN}" || return 1
  _f11_contain_syslog_units "${presence}" || return 1
  if ! systemctl restart systemd-journald; then
    _f11_err "F-11: systemd-journald did not restart; the journal settings are not in effect"
    return 1
  fi
  if ! systemctl is-active --quiet systemd-journald; then
    _f11_err "F-11: systemd-journald is not active after restart"
    return 1
  fi
  forward="$(_f11_effective_forward_to_syslog)" || return 1
  if [[ "${forward}" != "no" ]]; then
    _f11_err "F-11: journald still forwards to syslog (effective ForwardToSyslog=${forward}); a drop-in sorting after zz-winsvpn-no-syslog.conf overrides it"
    return 1
  fi
  _f11_verify_no_disk_copy "${journal_storage}" || return 1
}

# Rollback for step 5a. Not called by the installer. Restores the units'
# recorded prior state; restores a pre-existing zz- drop-in's recorded bytes
# and mode, or removes the drop-in when it was originally absent.
wins_f11_syslog_rollback() {
  local key value unit
  local -A prior=()
  [[ -s "${WINS_F11_SYSLOG_STATE}" ]] || {
    _f11_err "F-11 rollback: no prior-state record at ${WINS_F11_SYSLOG_STATE}"
    return 1
  }
  while IFS='=' read -r key value; do
    [[ -n "${key}" ]] && prior["${key}"]="${value}"
  done < "${WINS_F11_SYSLOG_STATE}"
  case "${prior[zz_dropin]:-}" in
    absent)
      rm -f -- "${WINS_F11_NO_SYSLOG_DROPIN}" || return 1
      ;;
    present)
      # Restore the recorded bytes and mode (cp -p kept both).
      [[ -f "${WINS_F11_ZZ_PRIOR_COPY}" ]] || {
        _f11_err "F-11 rollback: the prior zz drop-in copy ${WINS_F11_ZZ_PRIOR_COPY} is missing"
        return 1
      }
      cp -p -- "${WINS_F11_ZZ_PRIOR_COPY}" "${WINS_F11_NO_SYSLOG_DROPIN}" || return 1
      ;;
    *)
      _f11_err "F-11 rollback: the prior-state record does not say whether the zz drop-in existed"
      return 1
      ;;
  esac
  for unit in rsyslog.service syslog.socket; do
    [[ "${prior[${unit}.LoadState]:-}" == "loaded" ]] || continue
    [[ "${prior[${unit}.UnitFileState]:-}" == "masked" ]] && continue
    systemctl unmask "${unit}" || return 1
  done
  systemctl restart systemd-journald || return 1
  for unit in syslog.socket rsyslog.service; do
    if [[ "${prior[${unit}.ActiveState]:-}" == "active" ]]; then
      systemctl start "${unit}" || return 1
    fi
  done
  _f11_log "F-11 rollback: rsyslog.service and syslog.socket restored to their recorded prior state"
}

harden_crash_artifacts() {
  # F-11 (HANDOFF 3g). A core dump of a secret-bearing process is a verbatim
  # copy of every key, token, session and account record that process held in
  # memory, written to disk outside every retention window this system
  # enforces. Nothing here disabled them before: neither systemd-coredump nor
  # Ubuntu's apport was touched by any role, and journald ran on the distro
  # default `Storage=auto`, which silently becomes PERSISTENT the moment
  # /var/log/journal exists.
  #
  # "Verify with a harmless test process" is the load-bearing part of this
  # function. A configuration that was never observed to work is not a control,
  # and core-dump suppression is exactly the kind of setting that looks applied
  # and is not.
  _f11_log "F-11: disabling core dumps and crash reporting, bounding the journal"

  # --- 1. kernel-level: discard the core before anything can write it -------
  # `|/bin/false` makes the kernel PIPE the core to a process that exits
  # immediately, so no file is produced regardless of any process's RLIMIT_CORE
  # and regardless of whether systemd-coredump is installed. This is the one
  # control that does not depend on a daemon, a login session, or a re-exec,
  # which is why it is first and why it is what the verification below checks.
  # --- 0. quiesce apport FIRST ----------------------------------------------
  # ORDERING IS LOAD-BEARING. DO NOT MOVE THIS BELOW THE SYSCTL APPLY.
  #
  # `systemctl stop apport.service` runs /etc/init.d/apport stop, which invokes
  # stop_apport() in /usr/share/apport/apport (lines 705-709), and that function
  # executes write_to_proc_sys("kernel/core_pattern", "core"). Stopping apport
  # therefore RESETS kernel.core_pattern to the distro default.
  #
  # Until 2026-08-13 this block lived in step 4, AFTER step 1 applied the discard
  # pattern, so stopping apport silently undid it and step 6's verification aborted
  # the entire install with:
  #   F-11 VERIFICATION FAILED: kernel.core_pattern is 'core', not the discard pattern.
  # MEASURED on <NODE_ES_IP>, 2026-08-13.
  #
  # The defect hid itself: this block also MASKS apport, so on any retry the stop is
  # a no-op, core_pattern survives, and the run passes. It therefore only ever bit the
  # FIRST deploy against a host where apport was still active -- which is every fresh
  # node -- and presented as a flake that "fixed itself" on re-run.
  if [[ -d /etc/default ]]; then
    printf 'enabled=0\n' > /etc/default/apport
    chmod 644 /etc/default/apport
  fi
  systemctl stop apport.service >/dev/null 2>&1 || true
  systemctl disable apport.service >/dev/null 2>&1 || true
  systemctl mask apport.service >/dev/null 2>&1 || true

  install -d -m 755 /etc/sysctl.d
  cat > /etc/sysctl.d/99-winsvpn-coredump.conf <<'EOF'
# F-11: no core dumps for any process on this host.
kernel.core_pattern=|/bin/false
# setuid/privileged processes must never become dumpable.
fs.suid_dumpable=0
EOF
  chmod 644 /etc/sysctl.d/99-winsvpn-coredump.conf
  sysctl -q -p /etc/sysctl.d/99-winsvpn-coredump.conf 2>/dev/null || \
    _f11_warn "F-11: could not apply core-dump sysctl immediately; it will apply at next boot"

  # --- 2. resource limits: belt to the kernel's braces ----------------------
  install -d -m 755 /etc/security/limits.d
  cat > /etc/security/limits.d/99-winsvpn-coredump.conf <<'EOF'
# F-11: zero core limit for every user including root.
*     soft  core  0
*     hard  core  0
root  soft  core  0
root  hard  core  0
EOF
  chmod 644 /etc/security/limits.d/99-winsvpn-coredump.conf

  # limits.d only covers PAM logins. Services are started by systemd, which
  # uses its own DefaultLimitCORE and never consults limits.d at all -- the
  # single most common way a "core dumps are disabled" claim turns out to be
  # false for exactly the processes that matter.
  install -d -m 755 /etc/systemd/system.conf.d
  cat > /etc/systemd/system.conf.d/99-winsvpn-coredump.conf <<'EOF'
[Manager]
DefaultLimitCORE=0:0
EOF
  chmod 644 /etc/systemd/system.conf.d/99-winsvpn-coredump.conf
  install -d -m 755 /etc/systemd/user.conf.d
  cat > /etc/systemd/user.conf.d/99-winsvpn-coredump.conf <<'EOF'
[Manager]
DefaultLimitCORE=0:0
EOF
  chmod 644 /etc/systemd/user.conf.d/99-winsvpn-coredump.conf

  # --- 3. systemd-coredump: store nothing, and do not run at all ------------
  install -d -m 755 /etc/systemd/coredump.conf.d
  cat > /etc/systemd/coredump.conf.d/99-winsvpn.conf <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
EOF
  chmod 644 /etc/systemd/coredump.conf.d/99-winsvpn.conf
  # Masking the socket stops the handler being socket-activated even if some
  # later package resets kernel.core_pattern to hand cores to systemd-coredump.
  systemctl mask systemd-coredump.socket >/dev/null 2>&1 || true
  systemctl stop systemd-coredump.socket >/dev/null 2>&1 || true

  # --- 4. crash artifacts already on disk -----------------------------------
  # apport itself is quiesced in step 0, ABOVE the sysctl apply. See the comment
  # there for why that ordering cannot be moved back here.
  # Anything already collected is a crash artifact of a secret-bearing process.
  rm -rf -- /var/crash/* 2>/dev/null || true
  rm -rf -- /var/lib/systemd/coredump/* 2>/dev/null || true

  # --- 5. journald: explicit, bounded, and volatile by default --------------
  # `Storage=auto` is not a decision, it is an accident waiting for someone to
  # create /var/log/journal. State it. Volatile keeps the journal in RAM under
  # a hard cap, which is compatible with operations here: the security alert
  # monitor reads the journal on a short timer within a boot, and durable
  # security records live in the events database, not the journal.
  local journal_storage="${WINS_JOURNAL_STORAGE:-volatile}"
  case "${journal_storage}" in
    volatile|persistent|auto|none) ;;
    *)
      _f11_err "WINS_JOURNAL_STORAGE must be one of volatile, persistent, auto, none (got '${journal_storage}')"
      return 1
      ;;
  esac
  install -d -m 755 /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-winsvpn.conf <<EOF
[Journal]
Storage=${journal_storage}
RuntimeMaxUse=192M
RuntimeKeepFree=64M
SystemMaxUse=192M
MaxRetentionSec=7day
ForwardToSyslog=no
ForwardToWall=no
Compress=yes
Seal=yes
EOF
  chmod 644 /etc/systemd/journald.conf.d/99-winsvpn.conf
  if [[ "${journal_storage}" == "volatile" && -d /var/log/journal ]]; then
    # Leaving an on-disk journal behind while declaring volatile storage keeps
    # the old persistent entries readable forever.
    rm -rf -- /var/log/journal
  fi
  # --- 5a. no second copy on disk; restart journald and verify ------------
  # The restart that applies these settings runs inside
  # contain_syslog_disk_copy, and a failed restart is a failure there, not a
  # warning: settings that "apply at next boot" were never observed working.
  contain_syslog_disk_copy "${journal_storage}" || return 1

  # --- 6. swap and hibernation ---------------------------------------------
  # Swap is already constrained to protected backing by the early preflight in
  # each role. Hibernation is not: it writes the ENTIRE contents of RAM,
  # including every decrypted key, to the swap device as a resume image.
  systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target >/dev/null 2>&1 || true
  if [[ -d /etc/systemd/sleep.conf.d ]] || install -d -m 755 /etc/systemd/sleep.conf.d 2>/dev/null; then
    cat > /etc/systemd/sleep.conf.d/99-winsvpn.conf <<'EOF'
[Sleep]
AllowHibernation=no
AllowSuspendThenHibernate=no
AllowHybridSleep=no
EOF
    chmod 644 /etc/systemd/sleep.conf.d/99-winsvpn.conf
  fi
  if [[ -s /sys/power/resume ]] && [[ "$(cat /sys/power/resume 2>/dev/null)" != "0:0" ]]; then
    _f11_warn "F-11: a hibernation resume device is configured; a resume image may hold decrypted secrets"
  fi

  verify_crash_artifacts_suppressed
}

verify_crash_artifacts_suppressed() {
  # THE VERIFICATION. HANDOFF 3g: "a configuration that was never observed to
  # work is not a control." This runs a harmless process that deliberately
  # aborts and proves no core file is produced anywhere it could land.
  #
  # SIGABRT on a `sleep` is the test: it is a normal unprivileged process, it
  # dies immediately, and it is the standard way a crashing daemon produces a
  # dump. Nothing here touches a real service.
  local work core_found=0 pattern
  pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo '')"
  if [[ "${pattern}" != "|/bin/false" ]]; then
    _f11_err "F-11 VERIFICATION FAILED: kernel.core_pattern is '${pattern}', not the discard pattern."
    _f11_err "A crashing secret-bearing process would still write its memory to disk. Refusing to continue."
    return 1
  fi
  if [[ "$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo 1)" != "0" ]]; then
    _f11_err "F-11 VERIFICATION FAILED: fs.suid_dumpable is not 0."
    return 1
  fi

  work="$(mktemp -d /tmp/wins-coredump-check-XXXXXX)"
  (
    cd "${work}" || exit 0
    # Ask for an unlimited core explicitly: if the suppression is real, the
    # request is irrelevant and no file appears anyway. This is what makes the
    # test meaningful rather than a tautology about our own ulimit.
    ulimit -c unlimited 2>/dev/null || true
    sleep 30 &
    child=$!
    kill -ABRT "${child}" 2>/dev/null || true
    wait "${child}" 2>/dev/null || true
  ) >/dev/null 2>&1 || true
  sleep 1

  # A core could land in the process CWD, or in the systemd-coredump store.
  # Command substitution, never `| grep -q`: under `set -o pipefail` an early
  # -q exit can SIGPIPE the producing find and turn a passing check into 141.
  if [[ -n "$(find "${work}" -maxdepth 1 -type f -name 'core*' -print -quit 2>/dev/null)" ]]; then
    core_found=1
  fi
  if [[ -n "$(find /var/lib/systemd/coredump -maxdepth 1 -type f -newermt '-2 minutes' -print -quit 2>/dev/null)" ]]; then
    core_found=1
  fi
  rm -rf -- "${work}"

  if (( core_found != 0 )); then
    _f11_err "F-11 VERIFICATION FAILED: a deliberately aborted test process produced a core dump."
    _f11_err "Core-dump suppression is NOT in effect. Refusing to continue with an unverified control."
    return 1
  fi
  _f11_log "F-11 verified: an aborted test process produced no core dump, in its CWD or the systemd store"
  return 0
}

main() {
  case "${1:-}" in
    --validate)
      require_supported_host
      log "Validation completed with no changes."
      ;;
    --deploy)
      require_supported_host
      # F-11 (HANDOFF 3g): core dumps, crash reporting, journal and hibernation.
      # Runs before any secret-bearing service starts, so no crash artifact of
      # one can predate the suppression.
      harden_crash_artifacts
      install_prerequisites
      # Local admin-CIDR containment must be live, and verified against the
      # actual kernel ruleset, before T-Pot's installer can bring its admin
      # ports up below — otherwise there would be a window where those ports
      # are reachable from anywhere and this host relies solely on the
      # (unverifiable-from-here) provider firewall.
      enforce_admin_cidr_firewall
      verify_admin_cidr_firewall || \
        die "Local HONEYPOT_ADMIN_CIDR enforcement did not verify immediately after being applied; refusing to start T-Pot."
      # Advisory only here (see provider_firewall_allows_only): this host has
      # no way to verify the provider's side, so deployment does not block on
      # it. postflight re-checks both this and the local rules above once
      # T-Pot is actually up.
      provider_firewall_allows_only "${HONEYPOT_ADMIN_CIDR}" ${TPOT_ADMIN_PORTS_DEFAULT} || true
      prepare_pinned_source
      warn "Upstream will move SSH to 64295, alter DNS/firewall policy, install Docker, and require a reboot."
      log "Starting the pinned unattended T-Pot '${TPOT_TYPE}' installation."
      cd "${TPOT_DIR}"
      if [[ "${TPOT_TYPE}" == "h" ]]; then
        # -P 0 (added to the pinned installer by apply_password_fd_patch)
        # reads the password as one line from stdin instead of accepting it
        # as an argv token, so it never appears in this process's or
        # install.sh's /proc/<pid>/cmdline or in process-listing tools. The
        # trailing newline gives read(1) an unambiguous delimiter; the
        # password itself is already validated non-whitespace above, so it
        # cannot contain one.
        printf '%s\n' "${HONEYPOT_WEB_PASSWORD}" \
          | ./install.sh -s -t "${TPOT_TYPE}" -u "${HONEYPOT_WEB_USER}" -P 0
      else
        ./install.sh -s -t "${TPOT_TYPE}"
      fi
      ;;
    --postflight)
      postflight
      ;;
    --help|-h) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
