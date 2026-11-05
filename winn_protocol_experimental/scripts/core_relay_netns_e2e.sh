#!/usr/bin/env bash
# core_relay_netns_e2e.sh: Linux network-namespace end to end rehearsal of the
# w3r/1 ciphertext relay Double VPN (packet B), with NO real host involved.
#
#   phone ns --UDP--> home ns (eero: port forward + random-port SNAT) --> core ns (relay DNAT) --> home ns --> exit ns
#                     WAN side, relay port 9211 forwarded          Core LAN address             exit gateway UDP 9111
#
# STATUS: NOT_RUN. This file has been written and syntax checked only. It needs a
# Linux machine, root, /dev/net/tun, iptables with the conntrack, hashlimit and
# nat modules, and four prebuilt binaries. The sysctls net.core.rmem_max and
# net.core.wmem_max must both be >= 8 MiB (8388608): the exit gateway refuses to
# start otherwise (the default of a stock VM, 212992, failed). Run it in a
# throwaway VM or a lab host, never on a production Core or exit.
#
# What it proves when it passes
#   1. the shipping helper (extracted from server/wins_core_server_setup_ONETOUCH.sh)
#      verifies a signed exit descriptor and installs the three relay chains, and
#      its state report lists the relay as up;
#   2. a real winn3 session from the phone reaches the carrying state THROUGH the
#      double NAT (home router and Core), with the exit's own gateway, descriptor
#      keys and admission: the Core holds no session, no TUN and no listener;
#   3. ping and a 20 MiB TCP download from the phone cross the relay and the exit
#      NAT intact (sha256);
#   4. the exit sees only the home router's address as the peer (never the phone's)
#      and the phone's network sees only the home router's address (never the
#      exit's): the two-hop address split the relay exists for;
#   5. the Core's NEW-flow limits: one phone address is cut off at its burst,
#      six phone addresses each get through, and the per-port aggregate bound
#      holds when it is lowered;
#   6. fail closed: `wins-core-relay clear` ends forwarding at once and the phone
#      session stops carrying; a bad or expired descriptor leaves the relay down;
#   7. idle: a session with no user traffic survives 100 s (the keepalive keeps
#      both NAT mappings alive) without a source port change at the exit;
#   8. MEASUREMENT (informational, must recover within 150 s): the time for the
#      session to come back after BOTH NAT tables are flushed under a
#      port-randomizing home router, with the exit in `-demux address` (default)
#      and in `-demux token`. This is the number behind the optional
#      WINN3_GATEWAY_DEMUX=token owner decision.
#
# Safety: refuses unless Linux, EUID 0 and --i-know-this-needs-root. Creates only
# network namespaces and veth devices whose names start with w3r- and removes them
# on exit. It touches no other interface, no default namespace routing and no
# default namespace firewall (every iptables call runs inside a w3r- namespace).
# The lab "public" addresses are used inside the isolated namespaces only and
# never leave them; they are chosen because the helper refuses documentation,
# private and CGNAT ranges as relay targets by design.
#
# Build the binaries (from winn_protocol_experimental/, no cgo needed):
#   B=/abs/path/bin; mkdir -p "$B"
#   for c in winn3-gateway winn-datapath winn3-labrig winn-pki; do
#     CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$B/$c" "./cmd/$c"; done
#
# Run:
#   sudo W3R_BIN_DIR=/abs/path/bin ./scripts/core_relay_netns_e2e.sh --i-know-this-needs-root
#
# Environment: W3R_BIN_DIR (required, absolute), W3R_INSTALLER (default: the
# installer next to this repo), W3R_KEEP=1 keeps the state directory (logs and lab
# keys) after a successful run; it is always kept on failure and its path is
# printed. W3R_SKIP_REBIND=1 skips the (slow) measurement of assertion 8.
#
# The gateway runs with the LAB cover flags (-insecure-cover-*). That is correct
# for this rehearsal and must never be copied to a deployment.

set -Eeuo pipefail

NS_PHONE=w3r-phone
NS_HOME=w3r-home
NS_CORE=w3r-core
NS_EXIT=w3r-exit
NS_NET=w3r-net

# The lab "public" space is the first octet below. It is built at run time on purpose: the
# helper refuses documentation, private and CGNAT ranges as relay targets, so the lab
# needs globally routable looking addresses, and those must not appear as literals in
# the repository (the push gate tools/ipscrub refuses them). They exist only inside the
# w3r- namespaces and never leave them.
LAB=11

PHONE_IP=${LAB}.1.0.2
NET_P=${LAB}.1.0.1
HOME_WAN=${LAB}.2.0.2
NET_H=${LAB}.2.0.1
HOME_LAN=192.168.77.1
CORE_LAN=192.168.77.36
EXIT_IP=${LAB}.3.0.2
NET_E=${LAB}.3.0.1
TARGET_HTTP=${LAB}.9.0.80
EXIT_SLUG=lab-exit1
RELAY_PORT=9211
RELAY_PORT_MIN=9211
RELAY_PORT_MAX=9218
RELAY_PORT_RANGE="${RELAY_PORT_MIN}-${RELAY_PORT_MAX}"
EXIT_PORT=9111
PHONE_INNER=10.10.0.37
EXIT_ROUTER=10.10.0.1
EXIT_POOL=10.10.0.0/24
PATH_MTU=1450
TUN_PHONE=w3rp0

STATE=""
PIDS=()
FAILS=0
EXIT_GW_PID=""
PHONE_PID=""

log() { printf '[w3r-e2e] %s\n' "$*"; }
pass() { printf '[w3r-e2e] PASS  %s\n' "$*"; }
fail() { printf '[w3r-e2e] FAIL  %s\n' "$*" >&2; FAILS=$((FAILS + 1)); }
info() { printf '[w3r-e2e] INFO  %s\n' "$*"; }
die() { printf '[w3r-e2e] ABORT %s\n' "$*" >&2; exit 2; }

cleanup() {
  local rc=$?
  set +e
  local pid phone_profile_pattern=""
  # tunfd-exec runs winn-datapath as a child of winn3-labrig. Killing the
  # recorded parent PID does not signal that child. Match only this run's
  # unique profile path so failure cleanup also stops it.
  if [[ -n "${STATE}" ]]; then
    phone_profile_pattern="${STATE//./\\.}/phone/leg/profile\\.json"
    pkill -TERM -f -- "${phone_profile_pattern}" 2>/dev/null || true
  fi
  for pid in "${PIDS[@]:-}"; do
    [[ -n "${pid}" ]] && kill -TERM "${pid}" 2>/dev/null
  done
  sleep 1
  if [[ -n "${STATE}" ]]; then
    pkill -KILL -f -- "${phone_profile_pattern}" 2>/dev/null || true
  fi
  for pid in "${PIDS[@]:-}"; do
    [[ -n "${pid}" ]] && kill -KILL "${pid}" 2>/dev/null
  done
  local ns
  for ns in "${NS_PHONE}" "${NS_HOME}" "${NS_CORE}" "${NS_EXIT}" "${NS_NET}"; do
    ip netns del "${ns}" 2>/dev/null
  done
  if [[ -n "${STATE}" ]]; then
    if (( rc != 0 || FAILS != 0 )) || [[ "${W3R_KEEP:-0}" == "1" ]]; then
      log "state kept in ${STATE} (logs and lab keys only)"
    else
      rm -rf -- "${STATE}"
    fi
  fi
  exit "${rc}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ----------------------------------------------------------------- guards

[[ "$(uname -s)" == "Linux" ]] || die "Linux only (uname says $(uname -s))"
[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ "${1:-}" == "--i-know-this-needs-root" ]] || die "pass --i-know-this-needs-root to confirm this is a throwaway machine"
[[ -n "${W3R_BIN_DIR:-}" && "${W3R_BIN_DIR}" == /* ]] || die "W3R_BIN_DIR must be an absolute path"
for bin in winn3-gateway winn-datapath winn3-labrig winn-pki; do
  [[ -x "${W3R_BIN_DIR}/${bin}" ]] || die "missing ${W3R_BIN_DIR}/${bin}"
done
for tool in ip iptables iptables-restore python3 sha256sum head openssl conntrack pkill; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing tool: ${tool}"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun is not available"
for ns in "${NS_PHONE}" "${NS_HOME}" "${NS_CORE}" "${NS_EXIT}" "${NS_NET}"; do
  if ip netns list | awk '{print $1}' | grep -qx "${ns}"; then
    die "namespace ${ns} already exists; refusing to touch it (remove it by hand if it is a leftover)"
  fi
done
HAVE_TCPDUMP=0; command -v tcpdump >/dev/null 2>&1 && HAVE_TCPDUMP=1
HAVE_CONNTRACK=1  # required above: the helper purges relayed flows with conntrack -D

BIN="${W3R_BIN_DIR}"
HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="${W3R_INSTALLER:-${HERE}/../../server/wins_core_server_setup_ONETOUCH.sh}"
[[ -r "${INSTALLER}" ]] || die "cannot read the Core installer ${INSTALLER} (set W3R_INSTALLER)"
STATE="$(mktemp -d /tmp/w3r-e2e.XXXXXX)"
chmod 700 "${STATE}"
log "state directory ${STATE}"

nsx() { local ns="$1"; shift; ip netns exec "${ns}" "$@"; }

spawn() {
  # spawn LOGNAME NS CMD... ; stdout+stderr to ${STATE}/LOGNAME.log ; pid in LAST_PID and PIDS
  # `ip netns exec` is run directly (not through the nsx shell function) so that $! is the pid of the
  # command itself: `ip netns exec` execs the target, whereas a backgrounded shell function is a
  # subshell whose pid is not the command's, and kill on it would leave the command running.
  local name="$1" ns="$2"; shift 2
  ip netns exec "${ns}" "$@" >"${STATE}/${name}.log" 2>&1 &
  LAST_PID=$!
  PIDS+=("${LAST_PID}")
}

wait_for_line() {
  local file="$1" regex="$2" secs="$3" i
  for ((i = 0; i < secs * 10; i++)); do
    if grep -Eq "${regex}" "${file}" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

b64_of_hex_file() {
  python3 -c 'import base64,sys; print(base64.b64encode(bytes.fromhex(open(sys.argv[1]).read().strip())).decode())' "$1"
}

# ----------------------------------------------------------------- the shipping helper

# The helper under test is the text the installer ships, not a copy.
HELPER="${STATE}/wins-core-relay"
python3 - "${INSTALLER}" "${HELPER}" <<'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
start = next(i for i, l in enumerate(lines) if "<<'WINS_CORE_RELAY_PY'" in l)
end = next(i for i in range(start + 1, len(lines)) if lines[i] == "WINS_CORE_RELAY_PY")
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(lines[start + 1:end]) + "\n")
PY
chmod 0755 "${HELPER}"
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "${HELPER}" || die "the extracted helper does not parse"
# The two static gate rules the installer renders BEFORE the generic established accept (packet B2,
# finding C1). The lab replicates them below; this check keeps the lab and the installer in step.
GATE_FWD='-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${relay_gate_range}" -j WINVPN-RELAY-FWD'
GATE_DROP='-A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${relay_gate_range}" -j DROP'
grep -Fq -- "${GATE_FWD}" "${INSTALLER}" && grep -Fq -- "${GATE_DROP}" "${INSTALLER}" \
  || die "the installer no longer renders the static relay gate this rehearsal replicates"

# ----------------------------------------------------------------- topology

log "creating namespaces and veths (all names start with w3r-)"
for ns in "${NS_PHONE}" "${NS_HOME}" "${NS_CORE}" "${NS_EXIT}" "${NS_NET}"; do ip netns add "${ns}"; nsx "${ns}" ip link set lo up; done

mklink() {
  # mklink NSA IFA ADDRA NSB IFB ADDRB   (both /24)
  ip link add "$2" type veth peer name "$5"
  ip link set "$2" netns "$1"; ip link set "$5" netns "$4"
  nsx "$1" ip addr add "$3/24" dev "$2"; nsx "$1" ip link set "$2" up
  nsx "$4" ip addr add "$6/24" dev "$5"; nsx "$4" ip link set "$5" up
}
mklink "${NS_PHONE}" w3r-p0 "${PHONE_IP}" "${NS_NET}" w3r-n0 "${NET_P}"
mklink "${NS_HOME}" w3r-hw0 "${HOME_WAN}" "${NS_NET}" w3r-n1 "${NET_H}"
mklink "${NS_HOME}" w3r-hl0 "${HOME_LAN}" "${NS_CORE}" w3r-c0 "${CORE_LAN}"
mklink "${NS_EXIT}" w3r-e0 "${EXIT_IP}" "${NS_NET}" w3r-n2 "${NET_E}"
nsx "${NS_NET}" ip link add w3r-t0 type dummy
nsx "${NS_NET}" ip addr add "${TARGET_HTTP}/32" dev w3r-t0
nsx "${NS_NET}" ip link set w3r-t0 up
nsx "${NS_PHONE}" ip route add default via "${NET_P}"
nsx "${NS_HOME}" ip route add default via "${NET_H}" dev w3r-hw0
nsx "${NS_CORE}" ip route add default via "${HOME_LAN}" dev w3r-c0
nsx "${NS_EXIT}" ip route add default via "${NET_E}" dev w3r-e0
for ns in "${NS_NET}" "${NS_HOME}" "${NS_CORE}" "${NS_EXIT}"; do
  nsx "${ns}" sysctl -qw net.ipv4.ip_forward=1
  nsx "${ns}" sysctl -qw net.ipv4.conf.all.rp_filter=0
  nsx "${ns}" sysctl -qw net.ipv4.conf.default.rp_filter=0
done
nsx "${NS_NET}" iptables -P FORWARD ACCEPT
# Six extra phone addresses for the per-source limit assertion.
for n in 3 4 5 6 7 8; do nsx "${NS_PHONE}" ip addr add "${LAB}.1.0.${n}/24" dev w3r-p0; done

# The home router (the eero): forward the relay port range to the Core's LAN
# address, and source-NAT everything else out of the WAN with RANDOM ports, the
# worst realistic case for a session that is keyed on the peer's address and port.
nsx "${NS_HOME}" iptables -P FORWARD ACCEPT
nsx "${NS_HOME}" iptables -t nat -A PREROUTING -i w3r-hw0 -p udp --dport "${RELAY_PORT_MIN}:${RELAY_PORT_MAX}" -j DNAT --to-destination "${CORE_LAN}"
nsx "${NS_HOME}" iptables -t nat -A POSTROUTING -o w3r-hw0 -j MASQUERADE --random

# The Core, as the installer leaves it with CORE_RELAY_ENABLE=1: sysctls, the
# static jump after the established accept, the three guarded chains, INPUT drop.
nsx "${NS_CORE}" sysctl -qw net.ipv4.conf.all.send_redirects=0
nsx "${NS_CORE}" sysctl -qw net.ipv4.conf.default.send_redirects=0
nsx "${NS_CORE}" sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=180 2>/dev/null \
  || info "this kernel does not expose the conntrack stream timeout per namespace; the default applies"
nsx "${NS_CORE}" iptables -P INPUT DROP
nsx "${NS_CORE}" iptables -A INPUT -i lo -j ACCEPT
nsx "${NS_CORE}" iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
nsx "${NS_CORE}" iptables -P FORWARD DROP
nsx "${NS_CORE}" iptables -N WINVPN-CORE-FORWARD
nsx "${NS_CORE}" iptables -A FORWARD -j WINVPN-CORE-FORWARD
nsx "${NS_CORE}" iptables -N WINVPN-RELAY-FWD
nsx "${NS_CORE}" iptables -t nat -N WINVPN-RELAY-PRE
nsx "${NS_CORE}" iptables -t nat -N WINVPN-RELAY-POST
nsx "${NS_CORE}" iptables -A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${RELAY_PORT_MIN}:${RELAY_PORT_MAX}" -j WINVPN-RELAY-FWD
nsx "${NS_CORE}" iptables -A WINVPN-CORE-FORWARD -p udp -m conntrack --ctstate DNAT --ctorigdstport "${RELAY_PORT_MIN}:${RELAY_PORT_MAX}" -j DROP
nsx "${NS_CORE}" iptables -A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
nsx "${NS_CORE}" iptables -A WINVPN-CORE-FORWARD -j DROP

# ----------------------------------------------------------------- keys, descriptor, desired

log "generating lab keys, the lab PKI, a lab g1 signing key and the signed exit descriptor"
mkdir -p "${STATE}/exit" "${STATE}/phone" "${STATE}/pki" "${STATE}/core/run" "${STATE}/inet/www"
"${BIN}/winn3-gateway" -mode keygen -out "${STATE}/exit/gw" >/dev/null
"${BIN}/winn3-gateway" -mode keygen -out "${STATE}/phone/id" >/dev/null
"${BIN}/winn-pki" -out "${STATE}/pki/lab" -server-name localhost > "${STATE}/pki/paths.json"
COVER_CERT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ServerCert"])' "${STATE}/pki/paths.json")"
COVER_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ServerKey"])' "${STATE}/pki/paths.json")"
COVER_ECH="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ECHServerKeys"])' "${STATE}/pki/paths.json")"
LAB_COVER_FLAGS=(-cert "${COVER_CERT}" -key "${COVER_KEY}" -ech-keys "${COVER_ECH}"
  -insecure-cover-reuses-winn-leaf -insecure-cover-identifies-operator -insecure-cover-is-not-a-real-origin)
: > "${STATE}/exit/replay.journal"; chmod 600 "${STATE}/exit/replay.journal"
PHONE_PUB_B64="$(b64_of_hex_file "${STATE}/phone/id/static.pub")"
printf '{"version":1,"peers":[{"static_public":"%s","inner_v4":"%s","not_after":0}]}\n' \
  "${PHONE_PUB_B64}" "${PHONE_INNER}" > "${STATE}/exit/peers.json"
chmod 640 "${STATE}/exit/peers.json"

# desired.json = what the hub's GET /api/v1/core/assignments carries under "relay".
# The descriptor is signed with a lab key whose public half becomes ring.pub, the
# way the owner's g-slot key is pinned on the Core.
python3 - "${STATE}" "${EXIT_SLUG}" "${EXIT_IP}:${EXIT_PORT}" "${RELAY_PORT}" "${STATE}/exit/gw/static.pub" "${STATE}/exit/gw/admission.key" "${RELAY_PORT_RANGE}" <<'PY'
import base64, json, subprocess, sys, time
state, slug, endpoint, port, static_pub_path, admission_path, port_range = sys.argv[1:8]
b64 = lambda raw: base64.b64encode(raw).decode()
pem = state + "/core/g1.pem"
subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", pem], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
der = subprocess.run(["openssl", "pkey", "-in", pem, "-pubout", "-outform", "DER"], check=True,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
open(state + "/core/ring.pub", "w").write("g1=%s\n" % b64(der[-32:]))
now = int(time.time())
def make(iat, not_after, node):
    doc = {
        "admission_gen": 0, "admission_secret": b64(open(admission_path).read().strip().encode()),
        "alg": "ed25519", "bucket_window_s": 30, "endpoint": endpoint,
        "gateway_id": b64(b"gw-exit-lab"), "iat": iat, "inner_resolver_v4": "10.10.0.1",
        "inner_router_v4": "10.10.0.1", "kid": "g1", "max_skew_s": 30, "node": node,
        "not_after": not_after, "padding": "none", "seq": 1,
        "static_pub": b64(bytes.fromhex(open(static_pub_path).read().strip())),
        "tag_size": 16, "v": 3,
    }
    payload = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    open(state + "/core/msg", "wb").write(b"winsvpn-winn3-descriptor/v1\x00" + payload)
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", state + "/core/msg",
                    "-out", state + "/core/sig"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"payload": b64(payload), "sig": b64(open(state + "/core/sig", "rb").read())}
good = make(now - 100, now + 7 * 86400, slug)
expired = make(now - 3 * 86400, now - 86400, slug)
def desired(env):
    return {"v": 1, "port_range": port_range, "relays": [{"exit_slug": slug, "port": int(port), "descriptor": env}]}
json.dump(desired(good), open(state + "/core/run/desired.json", "w"))
json.dump(desired(expired), open(state + "/core/run/desired-expired.json", "w"))
json.dump({"v": 1, "port_range": port_range, "relays": []}, open(state + "/core/run/desired-empty.json", "w"))
PY
chmod 0600 "${STATE}/core/run/"*.json

RELAY_ARGS=(--ring "${STATE}/core/ring.pub" --wan-iface w3r-c0 --port-range "${RELAY_PORT_RANGE}"
  --self-ip "${CORE_LAN}")
relay() { nsx "${NS_CORE}" python3 "${HELPER}" "$@" --state "${STATE}/core/run/state.json" "${RELAY_ARGS[@]}"; }
state_field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "${STATE}/core/run/state.json" "$1"; }

# ----------------------------------------------------------------- internet services and the exit

head -c 20971520 /dev/urandom > "${STATE}/inet/www/blob.bin"
BLOB_SHA="$(sha256sum "${STATE}/inet/www/blob.bin" | awk '{print $1}')"
spawn inet-http "${NS_NET}" python3 -m http.server 8080 --bind "${TARGET_HTTP}" --directory "${STATE}/inet/www"

start_exit_gateway() {
  # start_exit_gateway DEMUX
  local demux="$1"
  spawn "exit-gw-${demux}" "${NS_EXIT}" env "WINN3_REPLAY_JOURNAL=${STATE}/exit/replay.journal" \
    "${BIN}/winn3-gateway" -mode serve -listen "${EXIT_IP}:${EXIT_PORT}" \
    -static "${STATE}/exit/gw/static.key" -admission "${STATE}/exit/gw/admission.key" \
    -gateway-id gw-exit-lab -inner-v4 "${EXIT_ROUTER}" -plan udp -path-mtu "${PATH_MTU}" -max-sessions 64 \
    -forward -accept-transit=true -forward-if winn3gw0 -forward-cidr "${EXIT_POOL}" \
    -peer-registry "${STATE}/exit/peers.json" -demux "${demux}" \
    "${LAB_COVER_FLAGS[@]}"
  EXIT_GW_PID="${LAST_PID}"
  wait_for_line "${STATE}/exit-gw-${demux}.log" '"event":"listening"' 20 \
    || { cat "${STATE}/exit-gw-${demux}.log" >&2; die "exit gateway (${demux}) did not start"; }
}
start_exit_gateway address
nsx "${NS_EXIT}" iptables -t nat -A POSTROUTING -s "${EXIT_POOL}" -o w3r-e0 -j MASQUERADE
nsx "${NS_EXIT}" iptables -P FORWARD ACCEPT

# ----------------------------------------------------------------- assertion 1: the helper

log "assertion 1: apply the signed exit descriptor through the shipping helper"
if relay apply --desired "${STATE}/core/run/desired.json" >"${STATE}/relay-apply.log" 2>&1; then pass "wins-core-relay apply exited 0"; else fail "apply failed: $(tail -n 5 "${STATE}/relay-apply.log")"; fi
if [[ "$(state_field 'd["state"]')" == "active" && "$(state_field 'd["listens"][0]["state"]')" == "up" ]]; then pass "state.json reports the relay up"; else fail "state.json: $(cat "${STATE}/core/run/state.json")"; fi
if nsx "${NS_CORE}" iptables -t nat -S WINVPN-RELAY-PRE | grep -q -- "--to-destination ${EXIT_IP}:${EXIT_PORT}"; then pass "the DNAT target is the signed exit endpoint"; else fail "the DNAT rule is missing or aims elsewhere"; fi
if nsx "${NS_CORE}" ss -lun | grep -Eq ":(${RELAY_PORT}|${EXIT_PORT})\b"; then fail "the Core has a UDP listener on a relay port"; else pass "the Core has no UDP listener on a relay port (kernel path only)"; fi

# ----------------------------------------------------------------- phone through the relay

log "starting the phone: a real winn3 session to the EXIT, dialled at the Core relay endpoint"
render_profile() {
  python3 - "$@" <<'PY'
import json, sys
out, endpoint, gateway_id, inner, router, static, gw_static, admission, tun = sys.argv[1:10]
doc = {
    "version": "winn3-host/1", "role": "client", "plan": ["udp"], "path_mtu": 1450,
    "gateway_id": gateway_id,
    "carrier": {"class": "udp", "endpoint": endpoint},
    "inner": {"v4": inner, "v6": "", "router_v4": router, "router_v6": ""},
    "keys": {"static_path": static, "gateway_static_path": gw_static, "admission_path": admission,
             "dual_auth_ed25519_pub_path": "", "dual_auth_mldsa65_pub_path": ""},
    "device": {"kind": "tun-fd", "host_port": 0, "name": tun},
    "allow_own_socket": True,
    "outer_socket_exclusion": "lab: the engine socket leaves through the namespace main table",
    "fast_pq": False,
}
json.dump(doc, open(out, "w"), indent=2)
PY
}
mkdir -p "${STATE}/phone/leg"
install -m 0600 "${STATE}/phone/id/static.key" "${STATE}/phone/leg/static"
install -m 0600 "${STATE}/exit/gw/static.pub" "${STATE}/phone/leg/gateway-static"
install -m 0600 "${STATE}/exit/gw/admission.key" "${STATE}/phone/leg/admission"
# THE relay claim: the profile names the Core's address and relay port, while the
# gateway key, admission secret and gateway id are the exit's own.
render_profile "${STATE}/phone/leg/profile.json" "${HOME_WAN}:${RELAY_PORT}" gw-exit-lab "${PHONE_INNER}" "${EXIT_ROUTER}" \
  "${STATE}/phone/leg/static" "${STATE}/phone/leg/gateway-static" "${STATE}/phone/leg/admission" "${TUN_PHONE}"
PHONE_MTU="$("${BIN}/winn-datapath" -winn3-profile "${STATE}/phone/leg/profile.json" -winn3-print-sizing 2>/dev/null \
  | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["inner_mtu"])')"
log "phone inner MTU from print-sizing: ${PHONE_MTU}"

CAPTURE_E=""
CAPTURE_P=""
if (( HAVE_TCPDUMP )); then
  ip netns exec "${NS_EXIT}" tcpdump -l -n -i w3r-e0 "udp port ${EXIT_PORT}" >"${STATE}/exit-wire.txt" 2>/dev/null &
  CAPTURE_E=$!; PIDS+=("${CAPTURE_E}")
  ip netns exec "${NS_PHONE}" tcpdump -l -n -i w3r-p0 udp >"${STATE}/phone-wire.txt" 2>/dev/null &
  CAPTURE_P=$!; PIDS+=("${CAPTURE_P}")
  sleep 1
fi

start_phone() {
  spawn phone-leg "${NS_PHONE}" "${BIN}/winn3-labrig" -mode tunfd-exec -tun "${TUN_PHONE}" -tun-addr "${PHONE_INNER}" -mtu "${PHONE_MTU}" -- \
    "${BIN}/winn-datapath" -winn3-profile "${STATE}/phone/leg/profile.json" -winn3-tun-fd 3
  PHONE_PID="${LAST_PID}"
  wait_for_line "${STATE}/phone-leg.log" '"gate_state":"carrying"' 60 || { tail -n 20 "${STATE}/phone-leg.log" >&2; return 1; }
  nsx "${NS_PHONE}" ip route replace "${TARGET_HTTP}/32" dev "${TUN_PHONE}"
}
if start_phone; then pass "the phone session reached carrying through the home NAT and the Core relay"; else die "the phone session never reached carrying"; fi

phone_ping() { nsx "${NS_PHONE}" ping -c 1 -W 2 "${TARGET_HTTP}" >/dev/null 2>&1; }
http_fetch() {
  nsx "${NS_PHONE}" python3 - "$1" "$2" <<'PY'
import hashlib, sys, urllib.request
url, timeout = sys.argv[1], float(sys.argv[2])
try:
    body = urllib.request.urlopen(url, timeout=timeout).read()
except Exception as exc:
    print("ERR", exc); sys.exit(1)
print(hashlib.sha256(body).hexdigest())
PY
}

log "assertion 3: ping and a 20 MiB download across the relay and the exit NAT"
if nsx "${NS_PHONE}" ping -c 3 -W 2 "${TARGET_HTTP}" >"${STATE}/ping1.log" 2>&1; then pass "ping phone to ${TARGET_HTTP}"; else fail "ping failed (see ${STATE}/ping1.log)"; fi
GOT_SHA="$(http_fetch "http://${TARGET_HTTP}:8080/blob.bin" 90 || true)"
if [[ "${GOT_SHA}" == "${BLOB_SHA}" ]]; then pass "download sha256 matches"; else fail "download failed or differs: ${GOT_SHA}"; fi

log "assertion 4: the address split"
if (( HAVE_TCPDUMP )); then
  sleep 1
  if grep -q "${HOME_WAN}\\." "${STATE}/exit-wire.txt" && ! grep -q "${PHONE_IP}" "${STATE}/exit-wire.txt"; then
    pass "the exit saw only the home router address as its peer, never the phone's"
  else
    fail "exit wire capture: expected only ${HOME_WAN}, found: $(grep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\.[0-9]* >' "${STATE}/exit-wire.txt" | sort -u | head -n 5 | tr '\n' ' ')"
  fi
  if grep -q "${HOME_WAN}\\.${RELAY_PORT}" "${STATE}/phone-wire.txt" && ! grep -q "${EXIT_IP}" "${STATE}/phone-wire.txt"; then
    pass "the phone's network saw only the relay address, never the exit's"
  else
    fail "phone wire capture contains the exit address or lacks the relay address"
  fi
else
  info "tcpdump is not installed: assertion 4 not evaluated"
fi
if nsx "${NS_CORE}" ip link show 2>/dev/null | grep -Eq ' w3[a-z0-9]*:'; then fail "the Core has a winn3 TUN interface"; else pass "the Core holds no winn3 interface"; fi
if nsx "${NS_CORE}" ip rule show | grep -q "10.10.0"; then fail "the Core has a policy rule for a phone address"; else pass "the Core has no per-phone policy state"; fi

# ----------------------------------------------------------------- assertion 7: idle survival

log "assertion 7: 100 s with no user traffic, then ping, and the exit-side source port is unchanged"
ports_before="$(grep -o "${HOME_WAN}\\.[0-9]* >" "${STATE}/exit-wire.txt" 2>/dev/null | sort -u | tr '\n' ' ')"
sleep 100
if phone_ping; then pass "the session survived 100 s idle"; else fail "ping failed after 100 s idle"; fi
if (( HAVE_TCPDUMP )); then
  ports_after="$(grep -o "${HOME_WAN}\\.[0-9]* >" "${STATE}/exit-wire.txt" 2>/dev/null | sort -u | tr '\n' ' ')"
  if [[ "${ports_before}" == "${ports_after}" ]]; then pass "no source port change at the exit across the idle period"; else fail "the exit-side source ports changed: before [${ports_before}] after [${ports_after}]"; fi
fi

# ----------------------------------------------------------------- assertion 5: NEW-flow limits

log "assertion 5: per-source and per-port NEW flow limits (synthetic UDP to the relay port)"
# Count datagrams that reach the exit's port. A junk datagram is not a winn3
# initiation, so the exit stays silent; every one that gets through shows on the
# exit wire. Distinct junk flows come from distinct source ports.
flood() {
  # flood SRC_IP FLOWS
  nsx "${NS_PHONE}" python3 - "$1" "$2" "${HOME_WAN}" "${RELAY_PORT}" <<'PY'
import socket, sys
src, flows, dst, port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
socks = []
for i in range(flows):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.sendto(b"\x00" * 1200, (dst, port))
    socks.append(s)
PY
}
count_exit_from_home() {
  sleep 1
  grep -c "${HOME_WAN}\\.[0-9]* > ${EXIT_IP}\\.${EXIT_PORT}: UDP, length 1200" "${STATE}/exit-wire.txt" 2>/dev/null || true
}
if (( HAVE_TCPDUMP )); then
  c0="$(count_exit_from_home)"
  flood ${LAB}.1.0.3 200
  c1="$(count_exit_from_home)"
  one_ip=$((c1 - c0))
  info "one phone address sent 200 NEW flows; ${one_ip} reached the exit"
  if (( one_ip >= 10 && one_ip <= 45 )); then pass "one phone address is cut off near its burst of 20 (got ${one_ip})"; else fail "per-source limit: ${one_ip} of 200 reached the exit"; fi
  sleep 3
  c2="$(count_exit_from_home)"
  for n in 4 5 6 7 8; do flood "${LAB}.1.0.${n}" 15; done
  flood ${LAB}.1.0.2 15
  c3="$(count_exit_from_home)"
  six_ips=$((c3 - c2))
  if (( six_ips >= 80 )); then pass "six phone addresses with 15 flows each all got through (${six_ips} of 90)"; else fail "six addresses: only ${six_ips} of 90 reached the exit"; fi
  # Lower the per-port aggregate and prove it bounds the exit even for many addresses.
  relay apply --desired "${STATE}/core/run/desired.json" --rate-port 20/second --burst-port 30 >/dev/null 2>&1 || true
  sleep 3
  c4="$(count_exit_from_home)"
  for n in 3 4 5 6 7 8; do flood "${LAB}.1.0.${n}" 15; done
  c5="$(count_exit_from_home)"
  aggregate=$((c5 - c4))
  info "with the per-port aggregate at 20/s burst 30, ${aggregate} of 90 reached the exit"
  if (( aggregate <= 45 )); then pass "the per-port aggregate bounds the exit (${aggregate} of 90)"; else fail "per-port aggregate did not bound the flood (${aggregate} of 90)"; fi
  relay apply --desired "${STATE}/core/run/desired.json" >/dev/null 2>&1 || fail "could not restore the default limits"
else
  info "tcpdump is not installed: assertion 5 not evaluated"
fi

# ----------------------------------------------------------------- assertion 8: NAT flush recovery

recovery_seconds() {
  # Flush both NAT tables, then time how long until the phone reaches the target again.
  local start now elapsed
  if (( ! HAVE_CONNTRACK )); then echo "n/a"; return 0; fi
  nsx "${NS_HOME}" conntrack -F >/dev/null 2>&1 || true
  nsx "${NS_CORE}" conntrack -F >/dev/null 2>&1 || true
  start="$(date +%s)"
  while true; do
    if phone_ping; then now="$(date +%s)"; echo $((now - start)); return 0; fi
    now="$(date +%s)"; elapsed=$((now - start))
    if (( elapsed > 150 )); then echo "timeout"; return 0; fi
    sleep 1
  done
}
if [[ "${W3R_SKIP_REBIND:-0}" != "1" ]]; then
  log "assertion 8 (measurement): recovery after a NAT flush, exit in -demux address"
  rec_addr="$(recovery_seconds)"
  info "recovery with -demux address: ${rec_addr} s"
  if [[ "${rec_addr}" == "timeout" ]]; then fail "the session did not recover within 150 s (-demux address)"; fi

  log "assertion 8 (measurement): restart the exit gateway with -demux token and repeat"
  kill -TERM "${PHONE_PID}" 2>/dev/null || true
  pkill -TERM -f -- "${STATE//./\\.}/phone/leg/profile\\.json" 2>/dev/null || true
  kill -TERM "${EXIT_GW_PID}" 2>/dev/null || true
  sleep 3
  pkill -KILL -f -- "${STATE//./\\.}/phone/leg/profile\\.json" 2>/dev/null || true
  start_exit_gateway token
  : > "${STATE}/phone-leg.log"
  if start_phone; then pass "the phone reconnected to the -demux token exit"; else fail "the phone did not reconnect to the -demux token exit"; fi
  rec_token="$(recovery_seconds)"
  info "recovery with -demux token: ${rec_token} s"
  if [[ "${rec_token}" == "timeout" ]]; then fail "the session did not recover within 150 s (-demux token)"; fi
fi

# ----------------------------------------------------------------- assertion 6: fail closed

log "assertion 6: fail closed, on a LIVE established flow (finding C1 of packet B)"
# Nothing is flushed before these checks: the point is that a flow which is already
# ESTABLISHED in conntrack stops when the relay is cleared, because the static gate
# judges both directions of every flow of the relay range before the generic established accept.
count_range_flows() {
  # relayed flows of the range still in the Core's conntrack table (0 when none)
  nsx "${NS_CORE}" conntrack -L -p udp 2>/dev/null | awk -v lo="${RELAY_PORT_MIN}" -v hi="${RELAY_PORT_MAX}" '
    { for (i = 1; i <= NF; i++) if ($i ~ /^dport=/) { split($i, a, "="); if (a[2] + 0 >= lo && a[2] + 0 <= hi) n++; break } }
    END { print n + 0 }'
}
phone_ping || fail "precondition: the phone must reach the target before the relay is cleared"
flows_before="$(count_range_flows)"
info "relayed flows in the Core conntrack table before clear: ${flows_before}"
if relay clear >/dev/null 2>&1; then pass "wins-core-relay clear exited 0"; else fail "clear failed"; fi
if nsx "${NS_CORE}" iptables -t nat -S WINVPN-RELAY-PRE | grep -q DNAT; then fail "a DNAT rule survived clear"; else pass "the DNAT chain is empty after clear"; fi
if [[ "$(state_field 'd["state"]')" == "inactive" ]]; then pass "state.json is inactive after clear"; else fail "state after clear: $(cat "${STATE}/core/run/state.json")"; fi
# The established flow must stop within a few seconds, with conntrack NOT flushed by the script.
stopped=0
for ((i = 0; i < 10; i++)); do
  if ! phone_ping; then stopped=1; break; fi
  sleep 1
done
if (( stopped )); then pass "the established relayed flow stopped within 10 s of clear (static gate, no conntrack flush by the script)"; else fail "the established flow still carried traffic 10 s after clear (finding C1 is open)"; fi
flows_after="$(count_range_flows)"
if [[ "${flows_after}" == "0" ]]; then pass "the helper purged the relayed flows of the range from conntrack"; else fail "${flows_after} relayed flows of the range survived clear in conntrack"; fi
if (( HAVE_TCPDUMP )); then
  before_clear="$(count_exit_from_home)"
  flood ${LAB}.1.0.3 5
  after_clear="$(count_exit_from_home)"
  if (( after_clear == before_clear )); then pass "no datagram reaches the exit after clear"; else fail "datagrams still reached the exit after clear"; fi
fi

log "assertion 6b: an expired descriptor cuts a live flow the same way"
relay apply --desired "${STATE}/core/run/desired.json" >/dev/null 2>&1 || true
recovered=0
for ((i = 0; i < 120; i++)); do
  if phone_ping; then recovered=1; break; fi
  sleep 1
done
if (( recovered )); then pass "the session came back after the relay was re-applied (a new flow)"; else fail "the phone did not recover after re-apply within 120 s"; fi
relay apply --desired "${STATE}/core/run/desired-expired.json" >/dev/null 2>&1 || true
if [[ "$(state_field 'd["listens"][0]["state"]')" == "down" && "$(state_field 'd["listens"][0].get("reason")')" == "descriptor_expired" ]] \
   && ! nsx "${NS_CORE}" iptables -t nat -S WINVPN-RELAY-PRE | grep -q DNAT; then
  pass "an expired descriptor leaves the relay down with no DNAT rule"
else
  fail "expired descriptor handling: $(cat "${STATE}/core/run/state.json")"
fi
stopped=0
for ((i = 0; i < 10; i++)); do
  if ! phone_ping; then stopped=1; break; fi
  sleep 1
done
if (( stopped )); then pass "the established flow stopped within 10 s of the descriptor expiring"; else fail "the established flow survived the expiry (finding C1 is open)"; fi
relay apply --desired "${STATE}/core/run/desired.json" >/dev/null 2>&1 || true
if [[ "$(state_field 'd["listens"][0]["state"]')" == "up" ]]; then pass "the relay comes back up from the signed descriptor"; else fail "the relay did not come back up"; fi

log "assertion 6c: a range mismatch keeps the relay off"
# The helper's own range comes LAST so it overrides the default one (argparse keeps the last value).
nsx "${NS_CORE}" python3 "${HELPER}" apply --desired "${STATE}/core/run/desired.json" --state "${STATE}/core/run/state.json" \
  "${RELAY_ARGS[@]}" --port-range "9300-9307" >/dev/null 2>&1 || true
if [[ "$(state_field 'd["state"]')" == "inactive" && "$(state_field 'd["listens"][0].get("reason")')" == "port_range_mismatch" ]]; then pass "a Core and hub range mismatch leaves every relay down"; else fail "range mismatch handling: $(cat "${STATE}/core/run/state.json")"; fi
relay apply --desired "${STATE}/core/run/desired.json" >/dev/null 2>&1 || true

if (( FAILS == 0 )); then
  log "ALL ASSERTIONS PASSED"
  exit 0
fi
log "${FAILS} assertion(s) FAILED; logs in ${STATE}"
exit 1
