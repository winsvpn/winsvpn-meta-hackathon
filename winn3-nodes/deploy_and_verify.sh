#!/usr/bin/env bash
# deploy_and_verify.sh -- supervisor-run script for the two winn/3 demo
# gateways (gateway-vm-a / gateway-vm-b) and their hub-VM verification.
#
# This script NEVER contacts any host by itself. The supervisor copies it plus
# a staging bundle onto each VM (see `stage-help`) and runs one subcommand
# there:
#
#   deploy_and_verify.sh deploy <role>            ON the gateway VM (root)
#   deploy_and_verify.sh verify-node <role>       ON the gateway VM (root)
#   deploy_and_verify.sh verify-hub <role> [ip]   ON the hub VM (root)
#   deploy_and_verify.sh rollback <role>          ON the gateway VM (root)
#   deploy_and_verify.sh stage-help               anywhere
#
# Semantics mirror server/wins_winn3_gateway_install.sh: unit flags baked at
# install (-forward -accept-transit=true -forward-if -forward-cidr
# -peer-registry, BindPaths/DeviceAllow under PrivateDevices=yes, CAP_NET_ADMIN
# [+ CAP_NET_BIND_SERVICE for TCP/53]), firewall oneshot with WINN3GW-* chains
# and both FORWARD jump directions, sysctls one-way (ip_forward never turned
# back off; rollback leaves sysctls and their drop-ins, per runbook section 10).
#
# Roles: demo-gw-a (gateway-vm-a, 10.10.0.0/24) and demo-gw-b
# (gateway-vm-b, 10.11.0.0/24). Never run against any other host.

set -euo pipefail

FAILURES=0
PASS()  { printf 'PASS  %s\n' "$*"; }
FAIL()  { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES+1)); }
NOTE()  { printf 'NOTE  %s\n' "$*"; }
RECEIPT() { printf 'RECEIPT %s\n' "$*"; }
die()   { printf '[deploy_and_verify][ERR] %s\n' "$*" >&2; exit 1; }

role_facts() {
  case "${1:-}" in
    demo-gw-a)
      ROLE=demo-gw-a; GW_ID=demo-gw-a; ENDPOINT=203.0.113.10
      SUBNET=10.10.0.0/24; INNER_V4=10.10.0.1; CLIENT_V4=10.10.0.2
      VERIFY_HOSTPORT=52711 ;;
    demo-gw-b)
      ROLE=demo-gw-b; GW_ID=demo-gw-b; ENDPOINT=203.0.113.20
      SUBNET=10.11.0.0/24; INNER_V4=10.11.0.1; CLIENT_V4=10.11.0.2
      VERIFY_HOSTPORT=52712 ;;
    *) die "unknown role '${1:-}' (demo-gw-a | demo-gw-b)" ;;
  esac
}

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# stage-help: what the supervisor copies where. Printed, not executed.
# ---------------------------------------------------------------------------
cmd_stage_help() {
  cat <<EOF
Supervisor staging (from the lane workdir /Users/owner/xprize/awg-nodes).
This script never contacts hosts; you push these with your own ssh/scp/rsync.

Gateway VM <role in demo-gw-a demo-gw-b>  ->  /root/winn3-stage/ :
  out/winn3-gateway-linux-amd64 out/winn3-gateway-linux-amd64.sha256
  deploy_and_verify.sh
  nodes/<role>/winn3-gateway.env
  nodes/<role>/winn3-gateway.service
  nodes/<role>/winn3-gateway-firewall
  nodes/<role>/winn3-gateway-firewall.service
  keys/<role>/winn3-gateway-static.key        (SECRET 600)
  keys/<role>/winn3-gateway-admission.key     (SECRET 600)
  keys/<role>/cover/                          (winn-leaf*.pem cover-*.pem ech-server-keys.json)
  keys/<role>/winn3-peers.json

Hub VM (hub-vm)  ->  /root/winn3-hub-stage/ :
  out/winn-datapath-linux-amd64 out/winn-datapath-linux-amd64.sha256
  deploy_and_verify.sh
  keys/demo-gw-a/{client.key,static.pub,winn3-gateway-admission.key}  ->  /root/winn3-hub-stage/demo-gw-a/
  keys/demo-gw-b/{client.key,static.pub,winn3-gateway-admission.key}  ->  /root/winn3-hub-stage/demo-gw-b/

Then ON each gateway VM:  cd /root/winn3-stage && bash deploy_and_verify.sh deploy <role>
Then ON the hub VM:       cd /root/winn3-hub-stage && bash deploy_and_verify.sh verify-hub <role>
Then ON each gateway VM:  bash deploy_and_verify.sh verify-node <role>
Rollback ON a gateway VM: bash deploy_and_verify.sh rollback <role>
EOF
}

# ---------------------------------------------------------------------------
# deploy <role> -- ON the gateway VM, cwd = staging dir, as root.
# ---------------------------------------------------------------------------
cmd_deploy() {
  role_facts "${1:-}"
  [[ $EUID -eq 0 ]] || die "deploy must run as root on the gateway VM"
  command -v systemctl >/dev/null 2>&1 || die "systemd required"
  [[ "$(uname -m)" == "x86_64" ]] || die "binary is linux/amd64; host is $(uname -m)"
  if [[ "${WINN_PROTOCOL_V3_ENABLE:-0}" == "1" ]]; then
    NOTE "WINN_PROTOCOL_V3_ENABLE=1 is set; it changes nothing here (standalone v3 IS this path). Unset it to keep logs honest."
  fi

  STAGE="$(pwd -P)"
  BIN_SRC="winn3-gateway-linux-amd64"
  GW_INSTALL=/usr/local/libexec/winn/winn3-gateway
  ENV_FILE=/etc/winn/winn3-gateway.env
  UNIT=/etc/systemd/system/winn3-gateway.service
  FW_SCRIPT=/usr/local/sbin/winn3-gateway-firewall
  FW_UNIT=/etc/systemd/system/winn3-gateway-firewall.service
  CRED_DIR=/etc/winn/credentials
  PEERS=/etc/winn/winn3-peers.json

  for f in "$BIN_SRC" "$BIN_SRC.sha256" winn3-gateway.env winn3-gateway.service \
           winn3-gateway-firewall winn3-gateway-firewall.service \
           winn3-gateway-static.key winn3-gateway-admission.key winn3-peers.json \
           cover/winn-leaf.pem cover/winn-leaf-key.pem cover/cover-fullchain.pem \
           cover/cover-key.pem cover/ech-server-keys.json; do
    [[ -f "$f" ]] || die "staging incomplete: $f missing in $STAGE"
  done

  # Binary integrity (verify_staged_binary semantics).
  (cd "$STAGE" && sha256sum -c "$BIN_SRC.sha256") || die "gateway binary sha256 mismatch"
  chmod 755 "$BIN_SRC"
  "$BIN_SRC" -h >/dev/null 2>&1 || true # smoke: it parses flags

  # Preflight (runbook 5.3): tun node, ip(8), no pre-existing winn3gw0, default route.
  [[ -c /dev/net/tun ]] || { modprobe tun 2>/dev/null || true; }
  [[ -c /dev/net/tun ]] || die "/dev/net/tun missing; install/load the tun module first"
  command -v ip >/dev/null 2>&1 || die "ip(8) not on PATH"
  if ip link show winn3gw0 >/dev/null 2>&1; then
    die "winn3gw0 already exists; the gateway creates it exclusively (IFF_TUN_EXCL). ip link del winn3gw0 if it is a leftover"
  fi
  WAN_IF="$(source_staged wan_if)"
  [[ -n "$WAN_IF" ]] || die "could not resolve WAN interface"
  NOTE "WAN interface: $WAN_IF (FORWARD/NAT rules key off it)"

  # Service user.
  getent group winn3-gateway >/dev/null 2>&1 || groupadd --system winn3-gateway
  id -u winn3-gateway >/dev/null 2>&1 || useradd --system --gid winn3-gateway \
    --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin winn3-gateway

  # Files.
  install -d -m 755 -o root -g root "$(dirname "$GW_INSTALL")"
  install -m 755 -o root -g root "$BIN_SRC" "$GW_INSTALL"
  install -d -m 755 -o root -g root /etc/winn
  install -d -m 700 -o root -g root "$CRED_DIR"
  install -d -m 700 -o root -g root "$CRED_DIR/winn3-cover"
  install -m 600 -o root -g root winn3-gateway.env "$ENV_FILE"
  install -m 600 -o root -g root winn3-gateway-static.key "$CRED_DIR/winn3-gateway-static.key"
  install -m 600 -o root -g root winn3-gateway-admission.key "$CRED_DIR/winn3-gateway-admission.key"
  for f in winn-leaf.pem winn-leaf-key.pem cover-fullchain.pem cover-key.pem ech-server-keys.json; do
    install -m 600 -o root -g root "cover/$f" "$CRED_DIR/winn3-cover/$f"
  done
  install -m 640 -o root -g winn3-gateway winn3-peers.json "$PEERS"
  install -m 700 -o root -g root winn3-gateway-firewall "$FW_SCRIPT"
  install -m 644 -o root -g root winn3-gateway.service "$UNIT"
  install -m 644 -o root -g root winn3-gateway-firewall.service "$FW_UNIT"

  # Sysctls: one-way, additive drop-ins (ensure_ip_forward / udp buffers /
  # conntrack tiering). Never reverted by rollback, by design.
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  install -d -m 755 -o root -g root /etc/sysctl.d
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/60-winn3-gateway-forward.conf
  chmod 644 /etc/sysctl.d/60-winn3-gateway-forward.conf
  for knob in net.core.rmem_max net.core.wmem_max; do
    cur="$(sysctl -n "$knob" 2>/dev/null || echo 0)"
    (( cur >= 134217728 )) || sysctl -w "$knob=134217728" >/dev/null
  done
  for knob in net.core.rmem_default net.core.wmem_default; do
    cur="$(sysctl -n "$knob" 2>/dev/null || echo 0)"
    (( cur >= 33554432 )) || sysctl -w "$knob=33554432" >/dev/null
  done
  printf 'net.core.rmem_max=134217728\nnet.core.wmem_max=134217728\nnet.core.rmem_default=33554432\nnet.core.wmem_default=33554432\n' \
    > /etc/sysctl.d/60-winn3-gateway-udp-buffers.conf
  chmod 644 /etc/sysctl.d/60-winn3-gateway-udp-buffers.conf
  cat > /etc/sysctl.d/60-winn3-gateway-pps.conf <<'EOF'
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
EOF
  # OI-19 (Round 36 treaty): the qdisc choice is per interface, not node wide.
  # net.core.default_qdisc only affects interfaces created later (docker veth
  # and friends included), and winn3gw0 does not exist at deploy time, so fq is
  # applied to that device alone when the gateway creates it. The udev rule
  # (Round 37 cross-examination) makes it survive gateway restarts and any
  # later device recreation, which the deploy-time waiter alone does not.
  printf 'ACTION=="add", SUBSYSTEM=="net", KERNEL=="winn3gw0", RUN+="/usr/sbin/tc qdisc replace dev winn3gw0 root fq"\n' \
    > /etc/udev/rules.d/99-winn3gw0-qdisc.rules
  chmod 644 /etc/udev/rules.d/99-winn3gw0-qdisc.rules
  (
    for _ in $(seq 1 120); do
      if ip link show winn3gw0 >/dev/null 2>&1; then
        tc qdisc replace dev winn3gw0 root fq 2>/dev/null || true
        break
      fi
      sleep 1
    done
  ) >/dev/null 2>&1 &
  chmod 644 /etc/sysctl.d/60-winn3-gateway-pps.conf
  sysctl -p /etc/sysctl.d/60-winn3-gateway-pps.conf >/dev/null 2>&1 || true
  CT_MAX="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 0)"
  CT_TARGET=262144
  MEM_KB="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  (( MEM_KB >= 7340032 )) && CT_TARGET=1048576
  if (( CT_MAX < CT_TARGET )); then
    sysctl -w "net.netfilter.nf_conntrack_max=${CT_TARGET}" >/dev/null
    printf 'net.netfilter.nf_conntrack_max=%d\n' "$CT_TARGET" \
      >> /etc/sysctl.d/60-winn3-gateway-forward.conf
  fi

  # Units up.
  systemctl daemon-reload
  systemctl enable winn3-gateway-firewall.service >/dev/null 2>&1
  systemctl restart winn3-gateway-firewall.service
  systemctl enable winn3-gateway.service >/dev/null 2>&1
  systemctl restart winn3-gateway.service
  sleep 3

  if systemctl is-active --quiet winn3-gateway.service; then
    PASS "winn3-gateway.service active on $(source_staged listen)"
  else
    FAIL "winn3-gateway.service not active; journal tail:"
    journalctl -u winn3-gateway -n 30 --no-pager -o cat | sed 's/^/    /' || true
    die "deploy failed at service start"
  fi

  # D10 ruleset receipts (runbook 5.3).
  ip link show winn3gw0 >/dev/null 2>&1 \
    && PASS "winn3gw0 exists: $(ip -4 -o addr show dev winn3gw0 | awk '{print $4}')" \
    || NOTE "winn3gw0 not up yet (created on first session path); re-check with verify-node"
  local_jump_receipts

  RECEIPT "deploy ${ROLE}: binary $(sha256sum "$GW_INSTALL" | cut -c1-16)… installed; env+unit+credentials+peers in place; firewall oneshot enabled; ip_forward=1"
  NOTE "next: on the hub VM run  bash deploy_and_verify.sh verify-hub ${ROLE}"
  NOTE "then here:              bash deploy_and_verify.sh verify-node ${ROLE}"

  # OI-15 (Round 36 treaty): the deploy verdict gates the exit code. FAIL
  # receipts from local_jump_receipts increment FAILURES, and without this call
  # the command exited zero through a failed deploy.
  verdict
}

source_staged() {
  # Read a value out of the staged env file (operator scalars, no secrets).
  local value=""
  case "$1" in
    wan_if)
      value="$(awk -F= '/^WINN3_GATEWAY_WAN_IF=/{print $2; exit}' winn3-gateway.env 2>/dev/null || true)"
      if [[ -z "$value" ]]; then
        value="$(ip -o route show default | awk '{print $5; exit}')"
      fi ;;
    listen)
      value="$(awk -F= '/^WINN3_GATEWAY_LISTEN=/{print $2; exit}' winn3-gateway.env 2>/dev/null || true)" ;;
  esac
  printf '%s' "$value"
}

local_jump_receipts() {
  local iface=winn3gw0
  if iptables -S WINN3GW-FORWARD >/dev/null 2>&1; then
    PASS "WINN3GW-FORWARD chain: $(iptables -S WINN3GW-FORWARD | wc -l) rules"
  else
    FAIL "WINN3GW-FORWARD chain missing"
  fi
  local jumps i o
  i="$(iptables -S FORWARD 2>/dev/null | grep -c -- "-i ${iface} -j WINN3GW-FORWARD" || true)"
  o="$(iptables -S FORWARD 2>/dev/null | grep -c -- "-o ${iface} -j WINN3GW-FORWARD" || true)"
  [[ "$i" == "1" && "$o" == "1" ]] \
    && PASS "FORWARD jumps: exactly one per direction (-i=${i}, -o=${o})" \
    || FAIL "FORWARD jumps wrong (-i=${i}, -o=${o}; want 1 and 1)"
  iptables -t nat -S WINN3GW-NAT-POSTROUTING 2>/dev/null | grep -q MASQUERADE \
    && PASS "WINN3GW-NAT-POSTROUTING MASQUERADE present" \
    || FAIL "NAT MASQUERADE rule missing"
}

# ---------------------------------------------------------------------------
# verify-node <role> -- ON the gateway VM.
# ---------------------------------------------------------------------------
cmd_verify_node() {
  role_facts "${1:-}"
  [[ $EUID -eq 0 ]] || die "verify-node runs as root on the gateway VM"
  NOTE "node-local checks only; external UDP/TCP ingress is proven by verify-hub from the hub VM"

  systemctl is-active --quiet winn3-gateway.service \
    && PASS "systemctl is-active winn3-gateway" \
    || FAIL "winn3-gateway is not active"

  ss -lunp 2>/dev/null | grep -q ':9111 ' \
    && PASS "UDP 9111 listening (ss -lunp)" \
    || FAIL "UDP 9111 not listening (ss -lunp)"
  ss -ltnp 2>/dev/null | grep -q ':9111 ' \
    && PASS "TCP 9111 listening (ss -ltnp)" \
    || FAIL "TCP 9111 not listening (ss -ltnp)"

  if ip link show winn3gw0 >/dev/null 2>&1; then
    ip -4 -o addr show dev winn3gw0 | grep -q "${INNER_V4}/" \
      && PASS "winn3gw0 carries ${INNER_V4}" \
      || FAIL "winn3gw0 exists but ${INNER_V4} is missing"
  else
    FAIL "winn3gw0 does not exist"
  fi

  [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "1" ]] \
    && PASS "net.ipv4.ip_forward=1" \
    || FAIL "net.ipv4.ip_forward is not 1"

  systemctl cat winn3-gateway 2>/dev/null | grep -q -- '-accept-transit=true' \
    && PASS "unit bakes -accept-transit=true" \
    || FAIL "unit lost -accept-transit=true"
  systemctl show winn3-gateway -p BindPaths 2>/dev/null | grep -q '/dev/net/tun' \
    && PASS "unit BindPaths=/dev/net/tun" \
    || FAIL "unit lost BindPaths=/dev/net/tun"

  local_jump_receipts

  local posture
  posture="$(journalctl -u winn3-gateway -n 200 --no-pager -o cat 2>/dev/null | grep '"event":"posture"' | tail -1 || true)"
  if [[ -n "$posture" ]]; then
    RECEIPT "last gateway posture: $(printf '%s' "$posture" | tr -d '\n' | cut -c1-400)"
    printf '%s' "$posture" | grep -q '"carriage_proven":true' \
      && PASS "gateway reports carriage_proven=true (forward-mode promotion evidence)" \
      || NOTE "carriage_proven not yet true; it latches after verify-hub drives traffic"
  else
    NOTE "no posture line in the last 200 journal lines yet"
  fi

  # OI-26 (Round 36 treaty): once verify passes, the runtime copies live in
  # /etc/winn/credentials (0700 root), so the staging copies of secret material
  # are shredded and their absence is receipted. A later redeploy requires
  # re-staging, which the staging-incomplete check states plainly.
  # Round 37 cross-examination: the same cleanup must run on FAILED verify and
  # on interruption, not only on the success path, so an EXIT trap carries it.
  cleanup_staged_secrets() {
    local s
    for s in \
        winn3-gateway-static.key \
        winn3-gateway-admission.key \
        cover/winn-leaf-key.pem \
        cover/cover-key.pem \
        cover/ech-server-keys.json; do
      if [[ -f "$s" ]]; then
        shred -u "$s" 2>/dev/null || rm -f "$s"
        NOTE "staged secret removed on exit: $s"
      fi
    done
  }
  trap cleanup_staged_secrets EXIT
  local staged_secret
  for staged_secret in \
      winn3-gateway-static.key \
      winn3-gateway-admission.key \
      cover/winn-leaf-key.pem \
      cover/cover-key.pem \
      cover/ech-server-keys.json; do
    if [[ -f "$staged_secret" ]]; then
      shred -u "$staged_secret" 2>/dev/null || rm -f "$staged_secret"
    fi
    [[ -e "$staged_secret" ]] \
      && FAIL "staged secret survived cleanup: $staged_secret" \
      || PASS "staged secret removed: $staged_secret"
  done

  verdict
}

# ---------------------------------------------------------------------------
# verify-hub <role> [endpoint-ip] -- ON the hub VM, cwd = hub staging dir.
# Uses the linux winn-datapath client + a hand-written -winn3-profile
# (runbook 5.4): handshake, one ICMP echo to the inner router, one ICMP echo
# through the NAT to 1.1.1.1. PASS/FAIL receipts, no secrets printed.
# ---------------------------------------------------------------------------
cmd_verify_hub() {
  role_facts "${1:-}"
  local endpoint="${2:-$ENDPOINT}"
  [[ -x winn-datapath-linux-amd64 ]] || die "winn-datapath-linux-amd64 missing in $(pwd -P)"
  command -v python3 >/dev/null 2>&1 || die "python3 required on the hub VM"
  for f in "$ROLE/client.key" "$ROLE/static.pub" "$ROLE/winn3-gateway-admission.key"; do
    [[ -f "$f" ]] || die "staging incomplete: $f missing (client half for $ROLE)"
  done
  sha256sum -c winn-datapath-linux-amd64.sha256 || die "datapath binary sha256 mismatch"

  STAGE_DIR="$(pwd -P)/$ROLE"
  PROFILE="$STAGE_DIR/verify-profile.json"
  cat > "$PROFILE" <<EOF
{
  "version": "winn3-host/1",
  "role": "client",
  "plan": ["udp"],
  "path_mtu": 1450,
  "gateway_id": "${GW_ID}",
  "carrier": { "class": "udp", "endpoint": "${endpoint}:9111" },
  "inner": { "v4": "${CLIENT_V4}", "router_v4": "${INNER_V4}" },
  "keys": {
    "static_path": "${STAGE_DIR}/client.key",
    "gateway_static_path": "${STAGE_DIR}/static.pub",
    "admission_path": "${STAGE_DIR}/winn3-gateway-admission.key"
  },
  "device": { "kind": "loopback-udp", "host_port": ${VERIFY_HOSTPORT} },
  "allow_own_socket": true,
  "outer_socket_exclusion": "hub-vm verifier: engine outer socket uses the host default route to ${endpoint}:9111; no route is installed over the loopback seam",
  "fast_pq": false
}
EOF
  chmod 600 "$PROFILE"

  python3 - "$ROLE" "$endpoint" "$PROFILE" "$(pwd -P)/winn-datapath-linux-amd64" "$VERIFY_HOSTPORT" "$INNER_V4" "$CLIENT_V4" <<'PYEOF'
import json, os, re, socket, struct, subprocess, sys, threading, time

role, endpoint, profile, binpath, host_port, inner_v4, client_v4 = sys.argv[1:8]
host_port = int(host_port)
LOG = open(f"verify-{role}.status.log", "w")
RECEIPTS = []
fails = 0

def rec(name, ok, detail=""):
    global fails
    line = ("PASS" if ok else "FAIL") + f"  {role} {name}" + (f" :: {detail}" if detail else "")
    print(line); RECEIPTS.append(line)
    if not ok:
        fails += 1

def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def icmp_echo(src, dst, ident, seq, payload=b"winn3-demo-carriage"):
    icmp = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = struct.pack("!BBHHH", 8, 0, csum(icmp), ident, seq) + payload
    total = 20 + len(icmp)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 1, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 1, csum(hdr),
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + icmp

seam = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
seam.bind(("127.0.0.1", host_port))
seam.settimeout(0.5)

proc = subprocess.Popen([binpath, "-winn3-profile", profile],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
engine_port = None
statuses = []
lock = threading.Lock()

def pump_stderr():
    global engine_port
    for raw in proc.stderr:
        line = raw.decode("utf-8", "replace").rstrip()
        print("[stderr] " + line, file=LOG)
        m = re.search(r"loopback seam engine port (\d+)", line)
        if m:
            engine_port = int(m.group(1))

def pump_stdout():
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").strip()
        if not line:
            continue
        print("[status] " + line, file=LOG)
        try:
            with lock:
                statuses.append(json.loads(line))
        except json.JSONDecodeError:
            pass

for t in (threading.Thread(target=pump_stderr, daemon=True),
          threading.Thread(target=pump_stdout, daemon=True)):
    t.start()

def terminate():
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

try:
    # 0. TCP 9111 external-origin probe (cover listener accepts the stream).
    tcp_ok = False
    try:
        with socket.create_connection((endpoint, 9111), timeout=5):
            tcp_ok = True
    except OSError:
        pass
    rec("tcp-9111-connect", tcp_ok, f"TCP connect to {endpoint}:9111 from hub VM")

    # 1. Handshake: wait for gate_state carrying on the status channel.
    deadline = time.time() + 30
    carrying = False
    while time.time() < deadline and proc.poll() is None:
        with lock:
            if any(s.get("gate_state") == "carrying" for s in statuses):
                carrying = True
                break
        time.sleep(0.2)
    last = {}
    with lock:
        if statuses:
            last = statuses[-1]
    rec("handshake-carrying", carrying,
        f"gate_state={last.get('gate_state','?')} rx_packets={last.get('rx_packets')} tx_packets={last.get('tx_packets')}")
    if not carrying:
        terminate()
        for line in RECEIPTS:
            print("RECEIPT " + line)
        print(f"RESULT {role}: FAIL (no handshake; see verify-{role}.status.log)")
        sys.exit(1)

    # 2. Find the engine's loopback seam port from stderr.
    deadline = time.time() + 10
    while engine_port is None and time.time() < deadline:
        time.sleep(0.1)
    if engine_port is None:
        rec("seam-port", False, "engine did not print its loopback seam port")
        terminate()
        sys.exit(1)

    def ping(target, name, tries=6):
        ident = 0x7733
        for seq in range(1, tries + 1):
            seam.sendto(icmp_echo(client_v4, target, ident, seq), ("127.0.0.1", engine_port))
            waited = 0.0
            while waited < 2.0:
                try:
                    data, _ = seam.recvfrom(65535)
                except socket.timeout:
                    waited += 0.5
                    continue
                if len(data) < 28:
                    continue
                ihl = (data[0] & 0x0F) * 4
                if data[9] != 1 or len(data) < ihl + 8:
                    continue
                src = socket.inet_ntoa(data[12:16])
                typ, code, _, rid, rseq = struct.unpack("!BBHHH", data[ihl:ihl+8])
                if typ == 0 and rid == ident and rseq == seq and src == target:
                    rec(name, True, f"icmp echo reply from {src} (seq {seq})")
                    return True
                waited += 0.05
        rec(name, False, f"no icmp echo reply from {target} after {tries} tries")
        return False

    ok_inner = ping(inner_v4, "icmp-inner-router")
    ok_nat = ping("1.1.1.1", "icmp-carriage-nat")

    time.sleep(1.5)
    last = {}
    with lock:
        if statuses:
            last = statuses[-1]
    rec("client-rx-packets>0", last.get("rx_packets", 0) > 0,
        f"final status rx_packets={last.get('rx_packets')} promotion_ready={last.get('promotion_ready')}")

    print(f"RECEIPT {role} endpoint={endpoint}:9111 handshake={int(carrying)} inner={int(ok_inner)} nat={int(ok_nat)}")
    # OI-15 (Round 36 treaty): the verdict counts every recorded failure, not
    # only the three headline checks. tcp-9111-connect, seam-port, and a dead
    # client-rx-packets each record into fails and must fail the result.
    result = "PASS" if fails == 0 else "FAIL"
    print(f"RESULT {role}: {result} (failures={fails} handshake={int(carrying)} icmp-inner={int(ok_inner)} icmp-nat={int(ok_nat)}; log verify-{role}.status.log)")
    sys.exit(0 if result == "PASS" else 1)
finally:
    terminate()
    seam.close()
    LOG.close()
PYEOF
}

# ---------------------------------------------------------------------------
# rollback <role> -- ON the gateway VM. Stop units, mirror the D10 -D loops,
# delete files and secrets. Sysctls and their drop-ins stay (one-way), per
# runbook section 10.
# ---------------------------------------------------------------------------
cmd_rollback() {
  role_facts "${1:-}"
  [[ $EUID -eq 0 ]] || die "rollback runs as root on the gateway VM"

  systemctl stop winn3-gateway.service 2>/dev/null || true
  systemctl disable winn3-gateway.service 2>/dev/null || true
  systemctl stop winn3-gateway-firewall.service 2>/dev/null || true
  systemctl disable winn3-gateway-firewall.service 2>/dev/null || true

  local iface=winn3gw0 cidr="$SUBNET"
  local wan_if
  wan_if="$(awk -F= '/^WINN3_GATEWAY_WAN_IF=/{print $2; exit}' /etc/winn/winn3-gateway.env 2>/dev/null || true)"
  [[ -n "$wan_if" ]] || wan_if="$(ip -o route show default | awk '{print $5; exit}')"

  if [[ -n "$wan_if" ]]; then
    while iptables -w 10 -D FORWARD -i "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    while iptables -w 10 -D FORWARD -o "$iface" -j WINN3GW-FORWARD 2>/dev/null; do :; done
    while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
    while iptables -w 10 -D INPUT -i "$iface" -d "$INNER_V4" -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
  fi
  iptables -w 10 -F WINN3GW-FORWARD 2>/dev/null || true
  iptables -w 10 -X WINN3GW-FORWARD 2>/dev/null || true
  iptables -w 10 -t nat -F WINN3GW-NAT-POSTROUTING 2>/dev/null || true
  iptables -w 10 -t nat -X WINN3GW-NAT-POSTROUTING 2>/dev/null || true
  iptables -w 10 -F WINN3GW-INPUT 2>/dev/null || true
  iptables -w 10 -X WINN3GW-INPUT 2>/dev/null || true
  for protocol in udp tcp; do
    while iptables -w 10 -D INPUT -p "$protocol" --dport 9111 -j ACCEPT 2>/dev/null; do :; done
    while iptables -w 10 -D WINVPN-INPUT -p "$protocol" --dport 9111 -j ACCEPT 2>/dev/null; do :; done
  done

  rm -f /etc/systemd/system/winn3-gateway.service
  rm -f /etc/systemd/system/winn3-gateway-firewall.service
  systemctl daemon-reload
  rm -f /usr/local/libexec/winn/winn3-gateway
  rm -f /usr/local/sbin/winn3-gateway-firewall
  rm -f /etc/winn/winn3-gateway.env
  rm -f /etc/winn/winn3-peers.json
  rm -rf /etc/winn/credentials/winn3-cover
  shred -u /etc/winn/credentials/winn3-gateway-static.key 2>/dev/null || rm -f /etc/winn/credentials/winn3-gateway-static.key
  shred -u /etc/winn/credentials/winn3-gateway-admission.key 2>/dev/null || rm -f /etc/winn/credentials/winn3-gateway-admission.key

  NOTE "sysctls (ip_forward, rmem/wmem, nf_conntrack_max) and /etc/sysctl.d/60-winn3-gateway-*.conf left in place: one-way by design (runbook section 10)"
  NOTE "secrets shredded; units, binary, env, peers and cover material removed"
  RECEIPT "rollback ${ROLE}: stopped, uninstalled, secrets shredded; sysctls retained"
}

verdict() {
  if (( FAILURES == 0 )); then
    printf 'RESULT: PASS (%s)\n' "$ROLE"
  else
    printf 'RESULT: FAIL (%s) -- %d check(s) failed\n' "$ROLE" "$FAILURES"
    exit 1
  fi
}

case "${1:-}" in
  deploy)     shift; cmd_deploy "$@" ;;
  verify-node) shift; cmd_verify_node "$@" ;;
  verify-hub) shift; cmd_verify_hub "$@" ;;
  rollback)   shift; cmd_rollback "$@" ;;
  stage-help|-h|--help|help) cmd_stage_help ;;
  *) usage; die "unknown command '${1:-}'" ;;
esac
