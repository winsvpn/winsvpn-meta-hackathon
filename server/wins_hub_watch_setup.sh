#!/usr/bin/env bash
# Win's VPN FLEET2 Q2: the external hub watcher.
#
# Installs, on a host OUTSIDE the hub's data center that the owner controls
# (aicore, on the owner's premises), the same wins-attest-collect and
# wins-fleet-attest programs the hub runs, extracted byte for byte from the
# control-plane installer named by --from, so there is one source. They run
# with --role watcher:
#   * every 2 min: ssh to the hub with a pinned host key and a key the hub
#     accepts only for `wins-fleet-attest --role hub hub-report` (restrict,
#     forced command), compare the hub's report with the baseline kept HERE,
#     and check the hub's alerting pipeline (monitor, attestation, watchdog,
#     last delivered mail, stuck queue);
#   * mail SECURITY_ALERT_EMAIL through THIS host's own SMTP2GO credentials
#     when the hub is unreachable, rebooted, changed, or has gone silent;
#   * a watchdog every 5 min and a daily digest, like the hub's.
# A hub that is powered off, rebooted, wiped, or whose root user stops its
# timers or blocks its mail cannot stop this host from mailing.
#
# Independence (FLEET2 Turn 2): a watcher the hub can log in to is not a
# watcher. A hub-root attacker would use the hub's own SSH key to stop it.
# The hub holds root-capable keys for every node and for the Core host
# (core_ssh_command, user with sudo), so neither a node nor a hub-managed Core
# can be the watcher. --hub-pubkey names the hub's public key
# (/root/.ssh/id_rsa.pub on the hub); setup refuses while that key, or any
# key line that names wins-hub-managed, is authorized for any account here.
#
# Usage: sudo bash wins_hub_watch_setup.sh --from /path/to/wins_control_plane_setup_ONETOUCH.sh \
#          --hub-pubkey /path/to/hub_id_rsa.pub
# Owner inputs, root-owned and mode 0600 (names only here, never values):
#   /etc/winsvpn/hub-watch.env          HUB_WATCH_SSH_HOST HUB_WATCH_SSH_PORT HUB_WATCH_SSH_USER
#                                       SMTP_SERVER SMTP_PORT SMTP_USER SMTP_PASS EMAIL_SENDER
#                                       SECURITY_ALERT_EMAIL (KEY='value' lines)
#   /etc/winsvpn/hub-watch.known_hosts  the hub's pinned host key line(s)
# The watcher key /etc/winsvpn/hub-watch_ed25519 is created when missing; its
# public half is printed for /root/winsvpn-hub-watcher.pub on the hub, then
# the control-plane installer is rerun there (install_hub_watcher_key).
set -Eeuo pipefail
umask 077

ROOT="${WINS_HUB_WATCH_ROOT:-}"
err() { printf '[ERR] %s\n' "$*" >&2; }
log() { printf '[INFO] %s\n' "$*"; }

source_file=""
hub_pubkey=""
while (( $# )); do
  case "$1" in
    --from) source_file="${2:-}"; shift 2 ;;
    --hub-pubkey) hub_pubkey="${2:-}"; shift 2 ;;
    *) err "usage: $0 --from /path/to/wins_control_plane_setup_ONETOUCH.sh --hub-pubkey /path/to/hub_id_rsa.pub"; exit 2 ;;
  esac
done
[[ -n "${source_file}" && -f "${source_file}" ]] || { err "--from must name the control-plane installer."; exit 2; }
[[ -n "${hub_pubkey}" && -f "${hub_pubkey}" ]] || { err "--hub-pubkey must name the hub's public key file."; exit 2; }
[[ -n "${ROOT}" || "$(id -u)" == "0" ]] || { err "Run as root."; exit 1; }
command -v systemctl >/dev/null 2>&1 || { err "systemd is required."; exit 1; }
command -v python3 >/dev/null 2>&1 || { err "python3 is required."; exit 1; }

# One heredoc body of the control-plane installer, by its exact opening line.
extract() {
  local opener="$1" terminator="$2" out="$3"
  awk -v open="${opener}" -v term="${terminator}" '
    $0 == open { inside = 1; found = 1; next }
    inside && $0 == term { inside = 0; done = 1; exit }
    inside { print }
    END { if (!found || !done) exit 3 }' "${source_file}" > "${out}"
}

check_input() {
  local path="$1" mode
  [[ -f "${path}" && ! -L "${path}" ]] || { err "${path} is missing or not a regular file."; return 1; }
  mode="$(stat -c '%u:%a' "${path}")" || { err "Could not stat ${path}."; return 1; }
  [[ "${mode}" == "0:600" || -n "${ROOT}" && "${mode#*:}" == "600" ]] || { err "${path} must be root-owned mode 0600 (is ${mode})."; return 1; }
}

# Refuses while the hub can log in here (see "Independence" above). Every
# account's home from passwd is searched, at authorized_keys and
# authorized_keys2, plus the dropbear initramfs keys.
hub_blob="$(awk 'NF >= 2 && $1 ~ /^(ssh-|ecdsa-|sk-)/ { print $2; exit }' "${hub_pubkey}")"
[[ "${hub_blob}" =~ ^[A-Za-z0-9+/=]{60,}$ ]] || { err "${hub_pubkey} holds no public key line."; exit 1; }
independence_hits=""
while IFS=: read -r _name _pw _uid _gid _gecos home _shell; do
  [[ -n "${home}" ]] || continue
  for keyfile in "${ROOT}${home}/.ssh/authorized_keys" "${ROOT}${home}/.ssh/authorized_keys2"; do
    [[ -f "${keyfile}" ]] || continue
    if grep -Fq -- "${hub_blob}" "${keyfile}" || grep -q 'wins-hub-managed' "${keyfile}"; then
      independence_hits+=" ${keyfile#"${ROOT}"}"
    fi
  done
done < "${ROOT}/etc/passwd"
for keyfile in "${ROOT}/etc/dropbear/initramfs/authorized_keys"; do
  [[ -f "${keyfile}" ]] && grep -Fq -- "${hub_blob}" "${keyfile}" && independence_hits+=" ${keyfile#"${ROOT}"}"
done
if [[ -n "${independence_hits}" ]]; then
  err "The hub can log in to this host (its key is authorized in:${independence_hits}). A hub-root attacker could stop this watcher; use a host the hub cannot reach, or remove those lines by hand first."
  exit 1
fi

etc="${ROOT}/etc/winsvpn"
check_input "${etc}/hub-watch.env"
check_input "${etc}/hub-watch.known_hosts"
for key in HUB_WATCH_SSH_HOST SMTP_USER SMTP_PASS SECURITY_ALERT_EMAIL; do
  grep -Eq "^${key}=.+" "${etc}/hub-watch.env" || { err "${etc}/hub-watch.env has no ${key}."; exit 1; }
done

install -d -m 0755 "${ROOT}/usr/local/lib" "${ROOT}/usr/local/sbin" "${ROOT}/etc/systemd/system"
install -d -m 0700 "${ROOT}/var/lib/wins-hub-watch"
stage="$(mktemp -d)"
trap 'rm -rf -- "${stage}"' EXIT
extract "  install_generated_file 0644 /usr/local/lib/wins-attest-collect.py <<'ATTESTCOLLECTEOF'" \
  ATTESTCOLLECTEOF "${stage}/collect" || { err "The installer carries no wins-attest-collect."; exit 1; }
extract "  install_generated_file 0700 /usr/local/sbin/wins-fleet-attest <<'FLEETATTESTEOF'" \
  FLEETATTESTEOF "${stage}/attest" || { err "The installer carries no wins-fleet-attest."; exit 1; }
python3 -I -c 'import ast, sys
for path in sys.argv[1:]:
    ast.parse(open(path, encoding="utf-8").read(), path)' "${stage}/collect" "${stage}/attest" \
  || { err "The extracted programs do not parse."; exit 1; }
install -m 0644 "${stage}/collect" "${ROOT}/usr/local/lib/wins-attest-collect.py"
install -m 0700 "${stage}/attest" "${ROOT}/usr/local/sbin/wins-fleet-attest"

if [[ ! -e "${etc}/hub-watch_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C wins-hub-watcher -f "${etc}/hub-watch_ed25519"
fi
chmod 0600 "${etc}/hub-watch_ed25519"

unit() { # unit NAME (body on stdin)
  local tmp
  tmp="$(mktemp "${ROOT}/etc/systemd/system/.$1.XXXXXX")"
  cat > "${tmp}"
  chmod 0644 "${tmp}"
  mv -f -- "${tmp}" "${ROOT}/etc/systemd/system/$1"
}
service_body() { # service_body DESCRIPTION COMMAND [OnFailure]
  printf '[Unit]\nDescription=%s\nAfter=network-online.target\nWants=network-online.target\n%s\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/wins-fleet-attest --role watcher %s\nTimeoutStartSec=110\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=/var/lib/wins-hub-watch\nLimitCORE=0\n' \
    "$1" "${3:+OnFailure=wins-hub-watch-watchdog.service
}" "$2"
}
timer_body() { # timer_body DESCRIPTION ONCALENDAR UNIT
  printf '[Unit]\nDescription=%s\n\n[Timer]\nOnCalendar=%s\nAccuracySec=5s\nPersistent=true\nUnit=%s\n\n[Install]\nWantedBy=timers.target\n' "$1" "$2" "$3"
}
service_body "Win's VPN external hub watcher (FLEET2)" run onfailure | unit wins-hub-watch.service
timer_body "Run the Win's VPN external hub watcher every 2 minutes" '*-*-* *:01/2:00' wins-hub-watch.service | unit wins-hub-watch.timer
service_body "Win's VPN hub watcher watchdog (FLEET2)" watchdog | unit wins-hub-watch-watchdog.service
timer_body "Run the Win's VPN hub watcher watchdog every 5 minutes" '*-*-* *:00/5:50' wins-hub-watch-watchdog.service | unit wins-hub-watch-watchdog.timer
service_body "Mail the Win's VPN hub watcher daily digest (FLEET2)" digest onfailure | unit wins-hub-watch-digest.service
timer_body "Mail the Win's VPN hub watcher daily digest" '*-*-* 11:05:00 UTC' wins-hub-watch-digest.service | unit wins-hub-watch-digest.timer

systemctl daemon-reload
for timer in wins-hub-watch.timer wins-hub-watch-watchdog.timer wins-hub-watch-digest.timer; do
  systemctl enable "${timer}" >/dev/null
  systemctl restart "${timer}"
done
log "External hub watcher installed. Authorize this public key on the hub as /root/winsvpn-hub-watcher.pub, then rerun the control-plane installer there:"
cat "${etc}/hub-watch_ed25519.pub"
ssh-keygen -l -f "${etc}/hub-watch_ed25519.pub"
