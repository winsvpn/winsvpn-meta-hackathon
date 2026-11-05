#!/usr/bin/env bash
set -Eeuo pipefail

# Standalone Cowrie SSH deception listener for a dedicated, non-production
# decoy host. Redirects inbound TCP 22 to an isolated Cowrie instance so
# internet scans against this host's real SSH banner hit deception traffic
# instead, and restricts Cowrie's own outbound traffic to established
# connections only.
#
# This script is intentionally standalone: nothing else in this repository
# invokes it. server/wins_control_plane_setup_ONETOUCH.sh always refuses
# INSTALL_CONTROL_HONEYPOT=1 and will never call this script, because
# running a deception SSH listener on the same host as the real
# control-plane origin would let a compromised decoy pivot straight into
# production. Use this script only on a host that is not, and will never
# be, the control, data, or core role.
#
# For a full multi-honeypot decoy VPS instead of a single Cowrie listener,
# use server/wins_honeynet_setup_ONETOUCH.sh on its own disposable host.

ROLE_FILE="/etc/winsvpn/role"
COWRIE_ROLE_MARKER="cowrie-honeypot"
COWRIE_VERSION_DEFAULT="${COWRIE_VERSION:-3.1.1}"
COWRIE_LISTEN_PORT_DEFAULT="${COWRIE_LISTEN_PORT:-2222}"
HONEYPOT_ADMIN_SSH_CIDRS_DEFAULT="${HONEYPOT_ADMIN_SSH_CIDRS:-}"

log()  { echo -e "\033[1;36m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*"; }

usage() {
  cat <<'EOF'
Usage: sudo bash server/wins_cowrie_honeypot_ONETOUCH.sh [--preflight|--deploy|--postflight|--remove]

Installs an isolated Cowrie SSH honeypot and redirects inbound TCP 22 to it.

This is standalone, optional, deferred tooling. Nothing else in this
repository invokes it. Deploy it only on a dedicated, disposable host that
is not running, and will never run, the control, data, or core roles.

Required acknowledgement:
  HONEYPOT_ACK_STANDALONE=YES   (only after choosing a dedicated decoy host)

Optional:
  HONEYPOT_ADMIN_SSH_CIDRS="203.0.113.4/32 198.51.100.0/24"
    Trusted management CIDRs that bypass the port-22 redirect and reach the
    host's real sshd. Leave unset to redirect every source, including yours;
    confirm you have an alternate management path (console, VPN, etc.)
    before deploying without this set.
  HONEYPOT_DOMAIN=edge.example.com   (used only to derive a decoy hostname)
  COWRIE_LISTEN_PORT=2222   (Cowrie's real listener; default 2222)
  COWRIE_VERSION=3.1.1      (requires a matching COWRIE_REQUIREMENTS_LOCK_B64
                              when overridden)

--remove tears down the redirect, the egress restriction, and the systemd
service, but leaves /opt/wins-cowrie and its logs in place for review.
EOF
}

require_root() {
  [[ "${EUID:-0}" -eq 0 ]] || { err "Run as root"; exit 1; }
}

valid_port() {
  local port="${1:-}"
  [[ "${port}" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
}

require_dedicated_decoy_host() {
  [[ "${HONEYPOT_ACK_STANDALONE:-}" == "YES" ]] || {
    err "Set HONEYPOT_ACK_STANDALONE=YES only after choosing a dedicated, disposable decoy host."
    return 1
  }
  if [[ -s "${ROLE_FILE}" ]]; then
    local role
    role="$(tr -d '[:space:]' < "${ROLE_FILE}")"
    [[ "${role}" == "${COWRIE_ROLE_MARKER}" ]] || {
      err "Host is already assigned to Win's VPN role '${role}'; a Cowrie deception listener must not share it."
      return 1
    }
  fi
  [[ ! -e /root/vpn_auth && ! -e /root/node.env && ! -e /etc/wins-core ]] || {
    err "Production Win's VPN artifacts were found on this host; use a separate dedicated decoy host instead."
    return 1
  }
}

mark_cowrie_honeypot_role() {
  install -d -m 700 /etc/winsvpn
  printf '%s\n' "${COWRIE_ROLE_MARKER}" > "${ROLE_FILE}"
  chmod 600 "${ROLE_FILE}"
}

wait_for_cowrie() {
  local attempt port="${COWRIE_LISTEN_PORT:-$COWRIE_LISTEN_PORT_DEFAULT}"
  for attempt in {1..30}; do
    if systemctl is-active --quiet wins-cowrie.service \
      && ss -ltn | awk -v expected=":${port}" '$4 ~ (expected "$" ) {found=1} END {exit found ? 0 : 1}'; then
      return 0
    fi
    sleep 1
  done
  err "Cowrie did not expose its SSH listener on TCP ${port} within 30 seconds."
  systemctl status wins-cowrie.service --no-pager -l || true
  return 1
}

# iptables and ip6tables are entirely separate rule sets (unlike nftables'
# unified inet table): every rule below must exist in both, or IPv6 traffic
# to port 22 reaches the real sshd completely unredirected and undropped.
# HONEYPOT_ADMIN_SSH_CIDRS can mix IPv4 and IPv6 CIDRs; each must only ever
# be handed to the matching protocol's tool, since iptables rejects an IPv6
# CIDR and vice versa.
split_admin_ssh_cidrs_by_family() {
  local cidr
  for cidr in ${HONEYPOT_ADMIN_SSH_CIDRS:-$HONEYPOT_ADMIN_SSH_CIDRS_DEFAULT}; do
    python3 - "${cidr}" <<'PY' || { err "HONEYPOT_ADMIN_SSH_CIDRS entry is not a valid IPv4/IPv6 CIDR: ${cidr}"; return 1; }
import ipaddress
import sys
net = ipaddress.ip_network(sys.argv[1], strict=False)
print(f"{net.version} {sys.argv[1]}")
PY
  done
}

# Cowrie's own outbound traffic is restricted to already-established
# connections, inbound TCP 22 is redirected to Cowrie's real listener, and
# any direct (non-redirected) traffic to that real listener is dropped.
# Idempotent: safe to rerun without duplicating chains or jump rules.
configure_honeypot_firewall() {
  local port="${COWRIE_LISTEN_PORT:-$COWRIE_LISTEN_PORT_DEFAULT}"
  valid_port "${port}" || { err "COWRIE_LISTEN_PORT is invalid."; return 1; }
  command -v iptables >/dev/null 2>&1 || { err "iptables is required."; return 1; }
  command -v ip6tables >/dev/null 2>&1 || { err "ip6tables is required."; return 1; }

  local family_cidrs
  family_cidrs="$(split_admin_ssh_cidrs_by_family)" || return 1

  local tool
  for tool in iptables ip6tables; do
    "${tool}" -N WINVPN-HONEYPOT-EGRESS 2>/dev/null || true
    "${tool}" -F WINVPN-HONEYPOT-EGRESS
    "${tool}" -t nat -N WINVPN-HONEYPOT 2>/dev/null || true
    "${tool}" -t nat -F WINVPN-HONEYPOT

    "${tool}" -C OUTPUT -m owner --uid-owner cowrie -j WINVPN-HONEYPOT-EGRESS 2>/dev/null \
      || "${tool}" -I OUTPUT 1 -m owner --uid-owner cowrie -j WINVPN-HONEYPOT-EGRESS
    "${tool}" -A WINVPN-HONEYPOT-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    "${tool}" -A WINVPN-HONEYPOT-EGRESS -j REJECT --reject-with icmp-port-unreachable

    "${tool}" -t nat -C PREROUTING -p tcp --dport 22 -j WINVPN-HONEYPOT 2>/dev/null \
      || "${tool}" -t nat -I PREROUTING 1 -p tcp --dport 22 -j WINVPN-HONEYPOT
  done

  local family version trusted_cidr
  for tool in iptables ip6tables; do
    [[ "${tool}" == "iptables" ]] && family=4 || family=6
    while read -r version trusted_cidr; do
      [[ "${version}" == "${family}" ]] || continue
      "${tool}" -t nat -A WINVPN-HONEYPOT -s "${trusted_cidr}" -j RETURN
    done <<<"${family_cidrs}"
    "${tool}" -t nat -A WINVPN-HONEYPOT -p tcp -j REDIRECT --to-ports "${port}"

    # After the NAT redirect, conntrack still reports the pre-NAT destination
    # port (22), so a plain --dport rule on the real Cowrie port would never
    # match. Match the tracked original destination port instead.
    "${tool}" -C INPUT -p tcp --dport "${port}" -m conntrack --ctorigdstport 22 -j ACCEPT 2>/dev/null \
      || "${tool}" -I INPUT 1 -p tcp --dport "${port}" -m conntrack --ctorigdstport 22 -j ACCEPT

    # Only traffic that arrived redirected from the apparent real sshd port
    # (22) may reach Cowrie's actual listener. Without this, a permissive
    # ambient INPUT policy (this script does not itself set INPUT's default
    # policy) would let direct scans of the real port fall through to Cowrie
    # unfiltered, and expose a second, identically-behaved SSH banner that
    # can tip off a careful attacker that this host is a decoy. Inserted at
    # position 2, immediately after the ctorigdstport ACCEPT above, so
    # redirected traffic is accepted first and everything else hits this
    # DROP rather than the ACCEPT.
    "${tool}" -C INPUT -p tcp --dport "${port}" -j DROP 2>/dev/null \
      || "${tool}" -I INPUT 2 -p tcp --dport "${port}" -j DROP
  done
}

# Re-checks every rule configure_honeypot_firewall installs so callers can
# confirm containment is actually in place (not just "the commands ran")
# before Cowrie's listener is allowed to start, and again at postflight.
verify_honeypot_firewall() {
  local port="${COWRIE_LISTEN_PORT:-$COWRIE_LISTEN_PORT_DEFAULT}"
  local failed=0
  local tool
  for tool in iptables ip6tables; do
    "${tool}" -t nat -C PREROUTING -p tcp --dport 22 -j WINVPN-HONEYPOT 2>/dev/null || {
      err "Verification failed: ${tool} NAT redirect of TCP 22 to Cowrie is missing."
      failed=1
    }
    "${tool}" -C INPUT -p tcp --dport "${port}" -m conntrack --ctorigdstport 22 -j ACCEPT 2>/dev/null || {
      err "Verification failed: ${tool} accept-redirected-traffic rule for TCP ${port} is missing."
      failed=1
    }
    "${tool}" -C INPUT -p tcp --dport "${port}" -j DROP 2>/dev/null || {
      err "Verification failed: ${tool} drop-direct-traffic rule for TCP ${port} is missing."
      failed=1
    }
    "${tool}" -C OUTPUT -m owner --uid-owner cowrie -j WINVPN-HONEYPOT-EGRESS 2>/dev/null || {
      err "Verification failed: ${tool} Cowrie egress containment is not attached to OUTPUT."
      failed=1
    }
    "${tool}" -C WINVPN-HONEYPOT-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || {
      err "Verification failed: ${tool} Cowrie egress ESTABLISHED,RELATED allowance is missing."
      failed=1
    }
    "${tool}" -C WINVPN-HONEYPOT-EGRESS -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || {
      err "Verification failed: ${tool} Cowrie egress default-reject rule is missing."
      failed=1
    }
  done
  [[ "${failed}" -eq 0 ]]
}

remove_honeypot_firewall() {
  local port="${COWRIE_LISTEN_PORT:-$COWRIE_LISTEN_PORT_DEFAULT}"
  local tool
  for tool in iptables ip6tables; do
    "${tool}" -t nat -D PREROUTING -p tcp --dport 22 -j WINVPN-HONEYPOT 2>/dev/null || true
    "${tool}" -D OUTPUT -m owner --uid-owner cowrie -j WINVPN-HONEYPOT-EGRESS 2>/dev/null || true
    "${tool}" -D INPUT -p tcp --dport "${port}" -m conntrack --ctorigdstport 22 -j ACCEPT 2>/dev/null || true
    "${tool}" -D INPUT -p tcp --dport "${port}" -j DROP 2>/dev/null || true
    "${tool}" -t nat -F WINVPN-HONEYPOT 2>/dev/null || true
    "${tool}" -t nat -X WINVPN-HONEYPOT 2>/dev/null || true
    "${tool}" -F WINVPN-HONEYPOT-EGRESS 2>/dev/null || true
    "${tool}" -X WINVPN-HONEYPOT-EGRESS 2>/dev/null || true
  done
}

remove_cowrie_service() {
  if systemctl list-unit-files wins-cowrie.service >/dev/null 2>&1; then
    systemctl disable --now wins-cowrie.service >/dev/null 2>&1 || true
    systemctl reset-failed wins-cowrie.service >/dev/null 2>&1 || true
  fi
}

install_cowrie_honeypot() {
  local root_dir="/opt/wins-cowrie" state_dir="/opt/wins-cowrie/state"
  local venv_dir="/opt/wins-cowrie/venv" lock_file="/opt/wins-cowrie/requirements.lock" installed_version=""
  local port="${COWRIE_LISTEN_PORT:-$COWRIE_LISTEN_PORT_DEFAULT}"
  local listen_interface="0.0.0.0" honeypot_hostname
  honeypot_hostname="srv-edge-$(printf '%s' "${HONEYPOT_DOMAIN:-$(hostname -f 2>/dev/null || hostname)}" | sha256sum | cut -c1-12)"
  valid_port "${port}" || { err "COWRIE_LISTEN_PORT is invalid."; return 1; }
  if ! id -u cowrie >/dev/null 2>&1; then
    useradd --system --home-dir "${root_dir}" --shell /usr/sbin/nologin cowrie
  fi
  install -d -o root -g root -m 755 "${root_dir}"
  install -d -o cowrie -g cowrie -m 750 "${state_dir}"
  if [[ -x "${venv_dir}/bin/python" ]]; then
    installed_version="$("${venv_dir}/bin/python" -c 'import importlib.metadata; print(importlib.metadata.version("cowrie"))' 2>/dev/null || true)"
  fi
  if [[ "${installed_version}" != "${COWRIE_VERSION_DEFAULT}" ]]; then
    rm -rf "${venv_dir}"
    python3 -m venv "${venv_dir}"
    if [[ -n "${COWRIE_REQUIREMENTS_LOCK_B64:-}" ]]; then
      printf '%s' "${COWRIE_REQUIREMENTS_LOCK_B64}" | base64 --decode > "${lock_file}" || {
        err "COWRIE_REQUIREMENTS_LOCK_B64 is not valid base64."
        return 1
      }
    else
      [[ "${COWRIE_VERSION_DEFAULT}" == "3.1.1" ]] || {
        err "A non-default Cowrie version requires a complete hashed COWRIE_REQUIREMENTS_LOCK_B64."
        return 1
      }
      cat > "${lock_file}" <<'EOF'
appdirs==1.4.4 --hash=sha256:a841dacd6b99318a741b166adb07e19ee71a274450e68237b4650ca1055ab128
attrs==26.1.0 --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309
automat==25.4.16 --hash=sha256:04e9bce696a8d5671ee698005af6e5a9fa15354140a87f4870744604dcdd3ba1
bcrypt==5.0.0 --hash=sha256:7aeef54b60ceddb6f30ee3db090351ecf0d40ec6e2abf41430997407a46d2254
cffi==2.1.1 --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf
constantly==23.10.4 --hash=sha256:3fd9b4d1c3dc1ec9757f3c52aef7e53ad9323dbe39f51dfd4c43853b68dfa3f9
cowrie==3.1.1 --hash=sha256:3ca9baa375a231daf60783aa6d3f90cee3d8a28189c2d5a7b752d2efb12a8f2c
cryptography==50.0.0 --hash=sha256:06a32a980526a6ab9a4b9bf8f7385800791e2bb960903cb6b530e4817509a3b7
hyperlink==21.0.0 --hash=sha256:e6b14c37ecb73e89c77d78cdb4c2cc8f3fb59a885c5b3f819ff4ed80f25af1b4
idna==3.18 --hash=sha256:7f952cbe720b688055e3f87de14f5c3e5fdaa8bc3928985c4077ca689de849a2
incremental==24.11.0 --hash=sha256:a34450716b1c4341fe6676a0598e88a39e04189f4dce5dc96f656e040baa10b3
lark==1.3.1 --hash=sha256:c629b661023a014c37da873b4ff58a817398d12635d3bbb2c5a03be7fe5d1e12
multipart==2.0.1 --hash=sha256:ac54d6bd0353ee30d2703af75adacd8b2052d4adb634e9e74dc7c5b06e0bcd86
packaging==26.3 --hash=sha256:d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c
pyasn1==0.6.4 --hash=sha256:deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b
pyasn1-modules==0.4.2 --hash=sha256:29253a9207ce32b64c3ac6600edc75368f98473906e8fd1043bd6b5b1de2c14a
pycparser==3.0 --hash=sha256:b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992
pyopenssl==26.4.0 --hash=sha256:f0eb0cb2d581d3ad2b9c489468485e7f2ab6727d08401bcf9d824c3caddf3c1c
service-identity==26.1.0 --hash=sha256:68c32dadbb69135fb951077677e07cd7f6031020f3a8c8f47a28cda8a0742118
treq==26.7.0 --hash=sha256:0a56ac4d970f7b1e27a4df4057d225efd84524b1847e123a725c531039702f98
twisted==26.4.0 --hash=sha256:dc25ea0ebf6511c24f03232ee9f4afa54b291c5d897990e3a39cc4d14a1ef4c0
typing-extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8
zope-interface==8.6 --hash=sha256:9217b1123f6aeec9ddf1789bffd83da3123546d551c164a99f862a5d1f5ac0f8
EOF
    fi
    chmod 600 "${lock_file}"
    "${venv_dir}/bin/pip" install --disable-pip-version-check --only-binary=:all: --require-hashes -r "${lock_file}"
  fi
  # Prebuild Twisted's plugin cache while the pinned virtualenv is writable.
  # At runtime systemd intentionally mounts the virtualenv read-only.
  "${venv_dir}/bin/twistd" --help >/dev/null
  chmod 644 "${venv_dir}"/lib/python*/site-packages/twisted/plugins/dropin.cache
  if [[ ! -f "${state_dir}/etc/cowrie.cfg" ]]; then
    chown -R cowrie:cowrie "${state_dir}"
    runuser -u cowrie -- bash -c "cd '${state_dir}' && '${venv_dir}/bin/cowrie' init"
  fi
  cat > "${state_dir}/etc/cowrie.cfg" <<EOF
[honeypot]
hostname = ${honeypot_hostname}

[ssh]
enabled = true
listen_endpoints = tcp:${port}:interface=${listen_interface}

[telnet]
enabled = false

[output_jsonlog]
enabled = true
EOF
  chown -R cowrie:cowrie "${state_dir}"
  chmod 750 "${state_dir}" "${state_dir}/etc"
  chmod 640 "${state_dir}/etc/cowrie.cfg"

  cat > /etc/systemd/system/wins-cowrie.service <<EOF
[Unit]
Description=Wins VPN isolated Cowrie SSH honeypot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=${state_dir}
# Cowrie 3.x selects Twisted's foreground mode through this environment
# variable. Passing "-n" to the service-manager wrapper is rejected by its
# argument parser before twistd starts.
Environment=COWRIE_STDOUT=yes
# The Cowrie wrapper execs twistd by name, so make the pinned virtualenv's
# console scripts discoverable without relying on a login-shell PATH.
Environment=PATH=${venv_dir}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Even in foreground mode Twisted creates a PID file; keep it in the only
# writable runtime directory instead of the protected state-directory root.
ExecStart=${venv_dir}/bin/cowrie start -- --pidfile=var/run/twistd.pid
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${state_dir}/var
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
# AF_INET6 is intentionally excluded: cowrie.cfg above binds the SSH
# listener to interface=0.0.0.0 (IPv4) only, so Cowrie has no legitimate
# use for an IPv6 socket. Excluding it here blocks any IPv6 socket(2) call
# at the syscall level, regardless of the IPv4-only egress firewall below.
RestrictAddressFamilies=AF_UNIX AF_INET
CapabilityBoundingSet=
AmbientCapabilities=
MemoryHigh=256M
MemoryMax=384M
TasksMax=256

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/logrotate.d/wins-cowrie <<EOF
${state_dir}/var/log/cowrie/*.log ${state_dir}/var/log/cowrie/*.json {
    daily
    rotate 30
    maxsize 50M
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
  systemctl daemon-reload
  # Enabled only, deliberately not started here: the firewall containment
  # (redirect + drop-direct-port + egress restriction) must be installed and
  # verified before Cowrie's listener ever comes up. start_cowrie_service
  # performs the actual start once that is confirmed in place.
  systemctl enable wins-cowrie.service
}

start_cowrie_service() {
  systemctl start wins-cowrie.service
  wait_for_cowrie
}

preflight() {
  require_root
  require_dedicated_decoy_host
  command -v systemctl >/dev/null 2>&1 || { err "A systemd-based host is required."; exit 1; }
  command -v iptables >/dev/null 2>&1 || { err "iptables is required."; exit 1; }
  command -v python3 >/dev/null 2>&1 || { err "python3 is required."; exit 1; }
  [[ -z "${HONEYPOT_ADMIN_SSH_CIDRS:-$HONEYPOT_ADMIN_SSH_CIDRS_DEFAULT}" ]] && \
    warn "HONEYPOT_ADMIN_SSH_CIDRS is unset; every source, including yours, will be redirected to Cowrie on TCP 22."
  log "Preflight passed."
}

deploy() {
  require_root
  require_dedicated_decoy_host
  # Order matters: install (enables but does not start the service), then
  # firewall containment, then verify that containment actually landed, and
  # only then start Cowrie. This closes the window where Cowrie could be
  # reachable before ingress/egress containment is confirmed in place.
  # F-11 (HANDOFF 3g): core dumps, crash reporting, journal and hibernation.
  # Runs before any secret-bearing service starts, so no crash artifact of one
  # can predate the suppression.
  harden_crash_artifacts
  install_cowrie_honeypot
  configure_honeypot_firewall
  verify_honeypot_firewall || {
    err "Refusing to start Cowrie: firewall containment did not verify."
    exit 1
  }
  start_cowrie_service
  mark_cowrie_honeypot_role
  log "Cowrie honeypot deployed and redirecting TCP 22 on this host."
}

postflight() {
  require_root
  [[ -s "${ROLE_FILE}" && "$(tr -d '[:space:]' < "${ROLE_FILE}")" == "${COWRIE_ROLE_MARKER}" ]] || {
    err "Cowrie honeypot role marker missing."
    exit 1
  }
  wait_for_cowrie
  verify_honeypot_firewall || {
    err "Postflight failed: honeypot firewall containment is incomplete."
    exit 1
  }
  log "Postflight passed: Cowrie is active, the real port is unreachable directly, and egress is contained."
}

remove() {
  require_root
  remove_honeypot_firewall
  remove_cowrie_service
  rm -f "${ROLE_FILE}"
  log "Cowrie honeypot redirect and service removed. /opt/wins-cowrie and its logs were left in place for review."
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
  case "${1:---help}" in
    --preflight) preflight ;;
    --deploy) deploy ;;
    --postflight) postflight ;;
    --remove) remove ;;
    --help|-h) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
