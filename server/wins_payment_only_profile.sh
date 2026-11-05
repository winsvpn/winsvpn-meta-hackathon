#!/usr/bin/env bash
# Win's VPN TP-S1 (owner, 2026-10-09): payment-only profile for the Spain
# payment server. Spain is ruled not a VPN node (kept dark, plan D3) but the
# data-plane installer leaves inline Suricata (NFQUEUE 0), the AmneziaWG
# container and the Winn v3 gateway running on it. This profile stops those
# three, reversibly, and leaves the payment path alone: the management tunnel,
# the commerce tunnel, nginx on loopback 23000 (BTCPay) and 23001 (the wallet
# RPC), BTCPay (docker), monero-wallet-rpc, the firewall and SSH.
#
# It works only on a host the certified data-plane installer converged. It
# uses that installer's own primitives and no new firewall code:
#   * /etc/winsvpn/public-vpn-ingress-admission.env and
#     /usr/local/bin/wins-edge-hardening. With admission 0 the edge rebuild
#     emits no NFQUEUE rule and no public VPN accept, and it rewrites
#     /etc/iptables/rules.v4 under the shared firewall lock. This is the same
#     bootstrap-closed firewall every node runs during its install, with SSH on
#     the management tunnel. Payments need no public inbound port: both
#     tunnels are outbound cloudflared connections to loopback.
#
# ORDER IS LOAD-BEARING (memory note inline-suricata-cgroup-stall): a queue
# rule must never exist without a bound listener.
#   apply:  admission 0 -> edge rebuild -> prove zero NFQUEUE rules live and in
#           rules.v4 -> only then stop the watchdog, the rule timer and
#           Suricata -> stop the gateway and the AWG container.
#   revert: start Suricata -> wait until queue 0 is bound -> start the gateway
#           and the container -> only then restore admission 1 and rebuild
#           (the edge rebuild itself refuses admission 1 unless Suricata is
#           active and bound).
# A failed admission-0 rebuild restores the previous admission file exactly
# (its value, or its absence) and stops nothing; when that restore fails too,
# the recorded state is kept, so revert or a rerun still knows the previous
# admission. A rebuild that succeeds but
# leaves a queue rule behind stops nothing either; admission stays 0 (VPN
# ingress closed, Suricata still bound to every remaining queue rule) and the
# recorded state is kept, so `revert` restores the previous admission.
# A repeated apply re-proves admission 0 and zero queue rules, and re-installs
# the gates, before it stops anything; a failed firewall read is never a zero.
#
# While the profile is active, a drop-in on suricata.service and
# winn3-gateway.service makes any start a no-op (ConditionPathExists), so
# a package trigger or a hub-driven start cannot bring them back half-way.
# A data-plane installer rerun therefore needs `revert` first; run without it,
# the rerun stops at its own Suricata check, loudly.
#
# Usage: sudo bash wins_payment_only_profile.sh apply|revert|status
set -Eeuo pipefail
umask 077

ROOT="${WINS_PO_ROOT:-}"
STATE_FILE="${ROOT}/etc/winsvpn/payment-only.state"
ACTIVE_MARKER="${ROOT}/etc/winsvpn/payment-only.active"
ADMISSION_FILE="${ROOT}/etc/winsvpn/public-vpn-ingress-admission.env"
EDGE_HARDENING="${ROOT}/usr/local/bin/wins-edge-hardening"
RULES_FILES=("${ROOT}/etc/iptables/rules.v4" "${ROOT}/etc/iptables/rules.v6")
UNIT_DIR="${ROOT}/etc/systemd/system"
NFQ_PROC="${WINS_PO_NFQ_PROC:-/proc/net/netfilter/nfnetlink_queue}"
AWG_CONTAINER="${WINS_PO_AWG_CONTAINER:-amnezia-awg2}"
QUEUE_WAIT_SECONDS="${WINS_PO_QUEUE_WAIT_SECONDS:-90}"
# Stop order: the watchdog first (it edits queue rules), then the rule timer,
# then Suricata itself.
SURICATA_UNITS=(wins-suricata-nfq-watchdog.service wins-suricata-update.timer suricata.service)
GATED_UNITS=(suricata.service winn3-gateway.service)
PAYMENT_UNITS=(nginx.service docker.service monero-wallet-rpc.service wins-node-management-tunnel.service)
OPTIONAL_PAYMENT_UNITS=(wins-commerce-tunnel.service)
DROPIN_NAME="99-winsvpn-payment-only.conf"

log() { printf '[payment-only] %s\n' "$*"; }
err() { printf '[payment-only] ERROR: %s\n' "$*" >&2; }

require_root() {
  [[ "$(id -u)" == "0" ]] || { err "run as root"; exit 1; }
}

require_certified_primitives() {
  [[ -f "${EDGE_HARDENING}" && ! -L "${EDGE_HARDENING}" && -x "${EDGE_HARDENING}" ]] \
    && grep -Fq 'PUBLIC_VPN_INGRESS_ADMISSION_FILE=' "${EDGE_HARDENING}" \
    && grep -Fq 'apply_firewall' "${EDGE_HARDENING}" || {
    err "${EDGE_HARDENING} is not the certified data-plane edge rebuild (no admission-file support). Rerun the certified data-plane installer on this host first."
    exit 1
  }
}

unit_known() { systemctl cat "$1" >/dev/null 2>&1; }
unit_enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }
unit_active() { systemctl is-active "$1" 2>/dev/null || true; }

# Every NFQUEUE rule in the live ruleset (both families) and in the files the
# boot restores. Prints a count ("no match" is 0). FLEET1 Turn 2 (Astra): a
# firewall read that fails, or a saved rules path that is not a readable
# regular file, prints nothing and returns 1; absence is never assumed.
nfqueue_rule_count() {
  local command snapshot n total=0 f
  for command in iptables-save ip6tables-save; do
    snapshot="$("${command}" 2>/dev/null)" || {
      err "Cannot read ${command}; queue absence is unverified"
      return 1
    }
    n="$(printf '%s\n' "${snapshot}" |
      awk '/-j NFQUEUE/ {n++} END {print n + 0}')" || return 1
    total=$((total + n))
  done
  for f in "${RULES_FILES[@]}"; do
    [[ -e "${f}" || -L "${f}" ]] || continue
    [[ -f "${f}" && ! -L "${f}" && -r "${f}" ]] || {
      err "Cannot read regular saved rules ${f}"
      return 1
    }
    n="$(awk '/-j NFQUEUE/ {n++} END {print n + 0}' "${f}")" || return 1
    total=$((total + n))
  done
  printf '%s\n' "${total}"
}

queue_zero_bound() {
  [[ -r "${NFQ_PROC}" ]] && awk '$1 == 0 {found = 1} END {exit(found ? 0 : 1)}' "${NFQ_PROC}"
}

admission_value() {
  [[ -f "${ADMISSION_FILE}" ]] || { printf 'absent\n'; return 0; }
  sed -n 's/^PUBLIC_VPN_INGRESS_ADMISSION=\([01]\)$/\1/p' "${ADMISSION_FILE}" | tail -n 1
}

write_admission() {
  local value="$1" tmp
  [[ "${value}" =~ ^[01]$ ]] || { err "internal: admission value ${value}"; return 1; }
  [[ ! -L "${ADMISSION_FILE}" ]] || { err "${ADMISSION_FILE} is a symlink"; return 1; }
  # FLEET1 Turn 3 (Astra): explicit failure propagation; restore_admission
  # runs this beneath a conditional, where errexit is off.
  install -d -m 0700 "$(dirname -- "${ADMISSION_FILE}")" || return 1
  tmp="$(mktemp "$(dirname -- "${ADMISSION_FILE}")/.public-vpn-ingress-admission.XXXXXX")" || return 1
  if ! {
    printf 'PUBLIC_VPN_INGRESS_ADMISSION=%s\n' "${value}" > "${tmp}" &&
    chmod 0600 "${tmp}" &&
    mv -f -- "${tmp}" "${ADMISSION_FILE}"
  }; then
    rm -f -- "${tmp}"
    return 1
  fi
}

# Put the admission file back exactly as recorded: 0 or 1, or no file at all
# (the data-plane edge rebuild reads an absent file as 0).
restore_admission() {
  case "$1" in
    0|1) write_admission "$1" ;;
    absent)
      [[ ! -L "${ADMISSION_FILE}" ]] || { err "${ADMISSION_FILE} is a symlink"; return 1; }
      rm -f -- "${ADMISSION_FILE}"
      ;;
    *) err "internal: recorded admission ${1:-empty}"; return 1 ;;
  esac
}

container_state() {
  docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "${AWG_CONTAINER}" 2>/dev/null || printf 'absent absent\n'
}

state_value() { sed -n "s/^$1=//p" "${STATE_FILE}" | tail -n 1; }

install_gates() {
  local unit
  for unit in "${GATED_UNITS[@]}"; do
    install -d -m 0755 "${UNIT_DIR}/${unit}.d"
    printf '%s\n' "# Win's VPN TP-S1: no start while the payment-only profile is active." \
      '[Unit]' "ConditionPathExists=!/etc/winsvpn/payment-only.active" > "${UNIT_DIR}/${unit}.d/${DROPIN_NAME}"
    chmod 0644 "${UNIT_DIR}/${unit}.d/${DROPIN_NAME}"
  done
}

remove_gates() {
  local unit
  for unit in "${GATED_UNITS[@]}"; do
    rm -f -- "${UNIT_DIR}/${unit}.d/${DROPIN_NAME}"
  done
}

verify_payment_path() {
  local unit bad=0 code
  # Ubuntu 24.04 may run sshd socket-activated: either unit counts.
  if [[ "$(unit_active ssh.service)" != "active" && "$(unit_active ssh.socket)" != "active" ]]; then
    err "neither ssh.service nor ssh.socket is active"
    bad=1
  fi
  for unit in "${PAYMENT_UNITS[@]}"; do
    [[ "$(unit_active "${unit}")" == "active" ]] || { err "${unit} is not active"; bad=1; }
  done
  for unit in "${OPTIONAL_PAYMENT_UNITS[@]}"; do
    unit_known "${unit}" || continue
    [[ "$(unit_active "${unit}")" == "active" ]] || { err "${unit} is not active"; bad=1; }
  done
  code="$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' http://127.0.0.1:23000/ 2>/dev/null || true)"
  [[ "${code}" =~ ^(200|302)$ ]] || { err "nginx 127.0.0.1:23000 (BTCPay) answered ${code:-nothing}"; bad=1; }
  code="$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -X POST http://127.0.0.1:18083/json_rpc 2>/dev/null || true)"
  [[ "${code}" == "401" ]] || { err "monero-wallet-rpc 127.0.0.1:18083 answered ${code:-nothing}, expected a digest challenge (401)"; bad=1; }
  # FLEET1 Turn 2: the wallet RPC is reachable through nginx only on its own
  # listener (the monero-rpc.winsvpn.org ingress), never through the public
  # BTCPay listener, whatever Host a request carries.
  code="$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' -X POST http://127.0.0.1:23001/json_rpc 2>/dev/null || true)"
  [[ "${code}" == "401" ]] || { err "nginx 127.0.0.1:23001 (wallet RPC) answered ${code:-nothing}, expected the wallet's digest challenge (401)"; bad=1; }
  if wallet_reachable_on_btcpay_listener; then
    err "nginx 127.0.0.1:23000 (public BTCPay listener) reaches the wallet RPC; install the current wins-crypto-payments.conf"
    bad=1
  fi
  return "${bad}"
}

# 0 when any Host on the BTCPay listener draws the wallet's digest challenge.
wallet_reachable_on_btcpay_listener() {
  local host headers
  for host in btcpay.winsvpn.org monero-rpc.winsvpn.org localhost; do
    headers="$(curl -s -o /dev/null -D - --max-time 5 -X POST -H "Host: ${host}" http://127.0.0.1:23000/json_rpc 2>/dev/null || true)"
    grep -qi '^www-authenticate: *digest' <<< "${headers//$'\r'/}" && return 0
  done
  return 1
}

cmd_apply() {
  local prior_admission unit queue_count
  require_root
  require_certified_primitives
  if [[ -e "${ACTIVE_MARKER}" ]]; then
    log "already active; re-verifying"
  else
    if [[ ! -e "${STATE_FILE}" ]]; then
      prior_admission="$(admission_value)"
      install -d -m 0700 "$(dirname -- "${STATE_FILE}")"
      {
        printf 'PRIOR_ADMISSION=%s\n' "${prior_admission:-absent}"
        for unit in "${SURICATA_UNITS[@]}" winn3-gateway.service; do
          printf 'PRIOR_ENABLED_%s=%s\n' "${unit//[^A-Za-z0-9]/_}" "$(unit_enabled "${unit}")"
          printf 'PRIOR_ACTIVE_%s=%s\n' "${unit//[^A-Za-z0-9]/_}" "$(unit_active "${unit}")"
        done
        printf 'PRIOR_CONTAINER=%s\n' "$(container_state | tr ' ' ':')"
      } > "${STATE_FILE}"
      chmod 0600 "${STATE_FILE}"
    fi
    prior_admission="$(state_value PRIOR_ADMISSION)"
    # 1. Close VPN ingress: no queue rule, no public VPN accept.
    write_admission 0
    if ! PUBLIC_VPN_INGRESS_ADMISSION=0 INSTALL_DATA_IDS_IPS=0 "${EDGE_HARDENING}"; then
      # FLEET1 Turn 3 (Astra): the recorded state is the only copy of the
      # previous admission; it goes only once that admission is back.
      if ! restore_admission "${prior_admission}"; then
        err "the admission-0 firewall rebuild failed and the previous admission (${prior_admission}) could not be restored; the recorded state is kept at ${STATE_FILE} for revert or a rerun of apply. Suricata was not touched."
        exit 1
      fi
      rm -f -- "${STATE_FILE}"
      err "the admission-0 firewall rebuild failed; the admission file is restored and Suricata was not touched"
      exit 1
    fi
    # 2. Prove it before any listener goes away.
    queue_count="$(nfqueue_rule_count)" || queue_count="unreadable"
    if [[ "${queue_count}" != "0" ]]; then
      err "NFQUEUE rules remain after the rebuild (${queue_count}, live or in /etc/iptables); Suricata was NOT stopped. Admission stays 0 and the recorded state is kept: inspect iptables-save, then rerun apply, or run revert to restore the previous admission."
      exit 1
    fi
    # 3. Only now: mark the profile active.
    : > "${ACTIVE_MARKER}"
    chmod 0600 "${ACTIVE_MARKER}"
  fi
  # FLEET1 Turn 2 (Astra): every apply, first or repeated, re-proves the closed
  # state and re-installs the gates before any listener goes away.
  [[ -f "${STATE_FILE}" && ! -L "${STATE_FILE}" ]] || {
    err "Payment-only state is missing or invalid; refusing to stop services"
    exit 1
  }
  [[ "$(admission_value)" == "0" ]] || {
    err "VPN admission is not closed; refusing to stop services"
    exit 1
  }
  queue_count="$(nfqueue_rule_count)" || { err "queue absence is unverified; refusing to stop services"; exit 1; }
  [[ "${queue_count}" == "0" ]] || {
    err "NFQUEUE rules remain; refusing to stop services"
    exit 1
  }
  install_gates
  systemctl daemon-reload
  for unit in "${SURICATA_UNITS[@]}" winn3-gateway.service; do
    unit_known "${unit}" || continue
    systemctl disable --now "${unit}" >/dev/null 2>&1 || { err "could not stop ${unit}"; exit 1; }
  done
  if [[ "$(container_state)" != absent* ]]; then
    docker update --restart=no "${AWG_CONTAINER}" >/dev/null
    docker stop "${AWG_CONTAINER}" >/dev/null
  fi
  for unit in suricata.service winn3-gateway.service; do
    [[ "$(unit_active "${unit}")" != "active" ]] || { err "${unit} is still active"; exit 1; }
  done
  [[ "$(container_state)" != true* ]] || { err "${AWG_CONTAINER} is still running"; exit 1; }
  queue_count="$(nfqueue_rule_count)" || queue_count="unreadable"
  [[ "${queue_count}" == "0" ]] || { err "an NFQUEUE rule reappeared (${queue_count})"; exit 1; }
  if verify_payment_path; then
    log "active: Suricata, ${AWG_CONTAINER} and winn3-gateway are stopped; no NFQUEUE rule exists; the payment path answers"
  else
    err "the profile is active but the payment path check above failed; inspect those services (they were not touched)"
    exit 1
  fi
}

cmd_revert() {
  local prior_admission waited unit key policy running
  require_root
  require_certified_primitives
  [[ -f "${STATE_FILE}" ]] || { err "no payment-only state at ${STATE_FILE}; nothing to revert"; exit 1; }
  prior_admission="$(state_value PRIOR_ADMISSION)"
  rm -f -- "${ACTIVE_MARKER}"
  remove_gates
  systemctl daemon-reload
  # 1. Suricata first, and its queue bound, before any queue rule can return.
  for unit in suricata.service wins-suricata-update.timer wins-suricata-nfq-watchdog.service; do
    unit_known "${unit}" || continue
    key="${unit//[^A-Za-z0-9]/_}"
    if [[ "$(state_value "PRIOR_ENABLED_${key}")" == "enabled" ]]; then
      systemctl enable "${unit}" >/dev/null 2>&1 || { err "could not enable ${unit}"; exit 1; }
    fi
    if [[ "$(state_value "PRIOR_ACTIVE_${key}")" == "active" ]]; then
      systemctl start "${unit}" || { err "could not start ${unit}; admission stays 0"; exit 1; }
    fi
    if [[ "${unit}" == suricata.service && "$(state_value "PRIOR_ACTIVE_${key}")" == "active" ]]; then
      waited=0
      until queue_zero_bound; do
        (( waited < QUEUE_WAIT_SECONDS )) || {
          err "Suricata did not bind NFQUEUE 0 within ${QUEUE_WAIT_SECONDS}s; admission stays 0, so no queue rule exists. Fix Suricata, then rerun revert."
          exit 1
        }
        sleep 1
        waited=$(( waited + 1 ))
      done
    fi
  done
  # 2. The gateway and the AWG container, as they were.
  key="winn3_gateway_service"
  if [[ "$(state_value "PRIOR_ENABLED_${key}")" == "enabled" ]]; then
    systemctl enable winn3-gateway.service >/dev/null 2>&1 || { err "could not enable winn3-gateway.service"; exit 1; }
  fi
  if [[ "$(state_value "PRIOR_ACTIVE_${key}")" == "active" ]]; then
    systemctl start winn3-gateway.service || { err "could not start winn3-gateway.service; admission stays 0"; exit 1; }
  fi
  IFS=: read -r running policy <<< "$(state_value PRIOR_CONTAINER)"
  if [[ "${running}" != "absent" && -n "${policy}" ]]; then
    docker update --restart="${policy}" "${AWG_CONTAINER}" >/dev/null
    if [[ "${running}" == "true" ]]; then
      docker start "${AWG_CONTAINER}" >/dev/null
    fi
  fi
  # 3. Only now restore admission; the rebuild refuses 1 unless queue 0 is healthy.
  if [[ "${prior_admission}" == "1" ]]; then
    write_admission 1
    if ! PUBLIC_VPN_INGRESS_ADMISSION=1 "${EDGE_HARDENING}"; then
      write_admission 0
      err "the admission-1 rebuild refused; admission stays 0 (no queue rule). The services are back; fix the edge check and rerun revert."
      exit 1
    fi
  else
    # 0, or no file at all before apply (the edge rebuild reads absence as 0).
    restore_admission "${prior_admission}" || exit 1
  fi
  rm -f -- "${STATE_FILE}"
  log "reverted: services and admission restored to the recorded state"
}

cmd_status() {
  printf 'active=%s\n' "$([[ -e "${ACTIVE_MARKER}" ]] && echo yes || echo no)"
  printf 'admission=%s\n' "$(admission_value)"
  printf 'nfqueue_rules=%s\n' "$(nfqueue_rule_count || printf 'unknown')"
  printf 'queue0_bound=%s\n' "$(queue_zero_bound && echo yes || echo no)"
  printf 'suricata=%s gateway=%s container=%s\n' "$(unit_active suricata.service)" \
    "$(unit_active winn3-gateway.service)" "$(container_state | tr ' ' ':')"
}

case "${1:-}" in
  apply) cmd_apply ;;
  revert) cmd_revert ;;
  status) cmd_status ;;
  *) printf 'Usage: sudo bash %s apply|revert|status\n' "${0##*/}" >&2; exit 2 ;;
esac
