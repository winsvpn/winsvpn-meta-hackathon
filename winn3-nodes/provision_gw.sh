#!/usr/bin/env bash
# NOT AUTHORITATIVE (design v17 2.8, slice S6). This stages the demo gateways of
# the xprize demo. It is not how a production gateway is installed: that is
# server/wins_data_plane_setup_ONETOUCH.sh alone. The standalone installer this
# file says it mirrors, server/wins_winn3_gateway_install.sh, is a tombstone, so
# every "as the installer writes it" statement below describes retired text.
# provision_gw.sh <role> -- stage everything one winn/3 demo gateway needs.
#
# Lane: xprize demo, nodes (winn3 gateways). Workdir only; no network, no git.
# Supersedes the AWG deliverables that used to live in this directory.
#
# What it does, per role (demo-gw-a | demo-gw-b):
#   1. Generates the gateway static keypair + admission secret + a dedicated
#      verification client pair with module/cmd/winn3-demo-material -mode
#      keygen, which is byte-identical in format to `winn3-gateway -mode
#      keygen` (the method tools/winn3_gateway_provision_keys.sh uses on the
#      node; here the supervisor deploys, so generation happens in the
#      workdir and deploy_and_verify.sh install the secrets on the node).
#      Private material is written 0600 under keys/<role>/ and is NEVER
#      printed; only public fingerprints reach stdout or PUBSUMMARY.md.
#   2. Generates the cover material the gateway REQUIRES before it will
#      start (requireCoverFlags): Winn leaf, cover chain, ECH server keys.
#   3. Writes the peer registry binding the verification client to x.x.0.2.
#   4. Writes nodes/<role>/winn3-gateway.env (WINN3_GATEWAY_* names exactly
#      as wins_winn3_gateway_install.sh emit_env_text writes them).
#   5. Writes nodes/<role>/winn3-gateway.service with the installer's
#      FORWARD=1 + RESOLVER=1 semantics (-accept-transit=true, BindPaths,
#      DeviceAllow, CAP_NET_ADMIN[+CAP_NET_BIND_SERVICE], LoadCredential,
#      SocketBindDeny/Allow, cover flags, memory derivation).
#   6. Writes the firewall oneshot (script + unit) mirroring
#      write_gateway_listen_firewall_unit, with the GCE NIC parametrized.
#   7. Writes the hub-VM verification client profile for -winn3-profile.
#   8. Refreshes keys/PUBSUMMARY.md for every staged role (public material only).
#
# Environment overrides (all optional):
#   NIC            WAN nic the FORWARD/NAT rules use      (default ens4)
#   PATH_MTU       planning path MTU                      (default 1450)
#   LISTEN         gateway listen address                 (default 0.0.0.0:9111)
#   PLAN           comma-separated migration plan        (default udp)
#   MAX_SESSIONS   session ceiling                        (default 64)
#   RESOLVER       1 to answer DNS at INNER_V4:53        (default 1)
#   RESOLVER_UPSTREAM  upstream resolver addr:port        (default 1.1.1.1:53)
#   COVER_DOMAIN   dull public domain for the cover cert (default per role)
#   WINN3_GATEWAY_FORWARD_ASYNC  1 bakes -forward-async-write (rev3.4) into
#                  the unit, as the installer's write_unit() does   (default 0)
#
# The admission secret is opaque file bytes: ASCII hex text, never decoded.

set -euo pipefail

cd "$(dirname "$0")"
WORKDIR="$(pwd -P)"

GO_BIN="${GO_BIN:-/Users/owner/.local/go/bin/go}"
HELPER_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HELPER_ARCH="$(uname -m)"
HELPER="out/winn3-demo-material-${HELPER_OS}-${HELPER_ARCH}"
LINUX_GATEWAY="out/winn3-gateway-linux-amd64"
LINUX_DATAPATH="out/winn-datapath-linux-amd64"

log()  { printf '[provision] %s\n' "$*"; }
err()  { printf '[provision][ERR] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Per-role facts (SPEC.md v2 nodes table). egress IP is printed in receipts;
# this script never contacts it.
# ---------------------------------------------------------------------------
role_facts() {
  case "${1:-}" in
    demo-gw-a)
      ROLE=demo-gw-a; GW_ID=demo-gw-a; ENDPOINT=203.0.113.10
      SUBNET=10.10.0.0/24; INNER_V4=10.10.0.1; CLIENT_V4=10.10.0.2
      VERIFY_HOSTPORT=52711; COVER_DOMAIN_DEFAULT=static-assets-cdn.net ;;
    demo-gw-b)
      ROLE=demo-gw-b; GW_ID=demo-gw-b; ENDPOINT=203.0.113.20
      SUBNET=10.11.0.0/24; INNER_V4=10.11.0.1; CLIENT_V4=10.11.0.2
      VERIFY_HOSTPORT=52712; COVER_DOMAIN_DEFAULT=content-delivery-edge.net ;;
    *) usage; die "unknown role '${1:-}' (demo-gw-a | demo-gw-b)" ;;
  esac
}

usage() {
  cat <<'EOF'
Usage: provision_gw.sh <demo-gw-a|demo-gw-b>

Env overrides: NIC PATH_MTU LISTEN PLAN MAX_SESSIONS RESOLVER RESOLVER_UPSTREAM COVER_DOMAIN
               WINN3_GATEWAY_FORWARD_ASYNC
EOF
}

[[ $# -eq 1 ]] || { usage; exit 1; }
role_facts "$1"

NIC="${NIC:-ens4}"
PATH_MTU="${PATH_MTU:-1450}"
LISTEN="${LISTEN:-0.0.0.0:9111}"
PLAN="${PLAN:-udp}"
MAX_SESSIONS="${MAX_SESSIONS:-64}"
RESOLVER="${RESOLVER:-1}"
RESOLVER_UPSTREAM="${RESOLVER_UPSTREAM:-1.1.1.1:53}"
RESOLVER_TIMEOUT="${RESOLVER_TIMEOUT:-5s}"
FORWARD_IF=winn3gw0
FORWARD=1
# Multicore TUN writes (rev3.4), off by default, same name and values as
# server/wins_winn3_gateway_install.sh. FORWARD is always 1 here.
FORWARD_ASYNC="${WINN3_GATEWAY_FORWARD_ASYNC:-0}"
case "$FORWARD_ASYNC" in
  0) FORWARD_ASYNC_FLAG="" ;;
  1) FORWARD_ASYNC_FLAG=$'\n  -forward-async-write \\' ;;
  *) die "WINN3_GATEWAY_FORWARD_ASYNC='$FORWARD_ASYNC' must be 0 or 1" ;;
esac
COVER_DOMAIN="${COVER_DOMAIN:-$COVER_DOMAIN_DEFAULT}"
WINN_NAME="winn3gw-${ROLE}.lab"

[[ -x "$HELPER" ]] || die "helper $HELPER missing; build it first (see README.md)"
[[ -x "$LINUX_GATEWAY" ]] || die "$LINUX_GATEWAY missing"
[[ -x "$LINUX_DATAPATH" ]] || die "$LINUX_DATAPATH missing"

# ---------------------------------------------------------------------------
# Memory derivation, identical to derive_gateway_memory:
# MemoryMax = 64 MiB + 1.5 MiB * sessions; MemoryHigh = 75%; GOMEMLIMIT = 80%
# of MemoryHigh. systemd M is MiB; Go takes MiB or raw bytes.
# ---------------------------------------------------------------------------
if ! [[ "$MAX_SESSIONS" =~ ^[1-9][0-9]*$ ]]; then
  die "MAX_SESSIONS='$MAX_SESSIONS' is not a positive integer"
fi
MAX_KIB=$((64 * 1024 + 1536 * MAX_SESSIONS))
HIGH_KIB=$((MAX_KIB * 75 / 100))
GOMEM_BYTES=$((HIGH_KIB * 1024 * 80 / 100))
if (( MAX_KIB % 1024 == 0 )); then MEMORY_MAX="$((MAX_KIB / 1024))M"; else MEMORY_MAX="${MAX_KIB}K"; fi
if (( HIGH_KIB % 1024 == 0 )); then MEMORY_HIGH="$((HIGH_KIB / 1024))M"; else MEMORY_HIGH="${HIGH_KIB}K"; fi
if (( GOMEM_BYTES % 1048576 == 0 )); then GOMEMLIMIT="$((GOMEM_BYTES / 1048576))MiB"; else GOMEMLIMIT="${GOMEM_BYTES}"; fi

KEYDIR="keys/${ROLE}"
NODEDIR="nodes/${ROLE}"
rm -rf "$KEYDIR" "$NODEDIR"
mkdir -p "$KEYDIR" "$NODEDIR"
chmod 700 "$KEYDIR"

log "role ${ROLE}: gateway_id=${GW_ID} endpoint=${ENDPOINT} subnet=${SUBNET} inner=${INNER_V4} nic=${NIC}"
log "plan=${PLAN} path_mtu=${PATH_MTU} listen=${LISTEN} max_sessions=${MAX_SESSIONS} resolver=${RESOLVER} upstream=${RESOLVER_UPSTREAM}"
log "memory: MemoryMax=${MEMORY_MAX} MemoryHigh=${MEMORY_HIGH} GOMEMLIMIT=${GOMEMLIMIT}"

# ---------------------------------------------------------------------------
# 1. Key material (keygen method of tools/winn3_gateway_provision_keys.sh,
#    executed by the same-format generator locally).
# ---------------------------------------------------------------------------
KG="$(mktemp -d "${WORKDIR}/${KEYDIR}/.kg.XXXXXX")"
"$HELPER" -mode keygen -out "$KG" >/dev/null
for f in static.key static.pub admission.key client.key client.pub; do
  [[ -s "$KG/$f" ]] || die "keygen did not write $f"
done
mv "$KG/static.key"    "$KEYDIR/winn3-gateway-static.key"
mv "$KG/static.pub"    "$KEYDIR/static.pub"
mv "$KG/admission.key" "$KEYDIR/winn3-gateway-admission.key"
mv "$KG/client.key"    "$KEYDIR/client.key"
mv "$KG/client.pub"    "$KEYDIR/client.pub"
rm -rf "$KG"
chmod 600 "$KEYDIR/winn3-gateway-static.key" "$KEYDIR/winn3-gateway-admission.key" "$KEYDIR/client.key"
chmod 644 "$KEYDIR/static.pub" "$KEYDIR/client.pub"

# 2. Cover material (gateway refuses to start without it).
"$HELPER" -mode cover -out "$KEYDIR/cover" \
  -winn-name "$WINN_NAME" -cover-domain "$COVER_DOMAIN" >/dev/null
chmod 600 "$KEYDIR/cover/winn-leaf-key.pem" "$KEYDIR/cover/cover-key.pem" "$KEYDIR/cover/ech-server-keys.json"

# 3. Peer registry binding the verification client (public material only).
"$HELPER" -mode peers -client-pub "$KEYDIR/client.pub" \
  -inner-v4 "$CLIENT_V4" -out "$KEYDIR/winn3-peers.json" >/dev/null
chmod 644 "$KEYDIR/winn3-peers.json"

# ---------------------------------------------------------------------------
# Fingerprints: public-safe, domain-separated, matching the provision tool's
# admission fingerprint so both ends can compare without any secret leaving
# its directory.
# ---------------------------------------------------------------------------
FP_DOMAIN='winn3-admission-fingerprint-v1'
admission_fp() {
  { printf '%s' "$FP_DOMAIN"; tr -d '\r\n' < "$1"; } | shasum -a 256 | cut -c1-16
}
STATIC_PUB_HEX="$(tr -d '\r\n' < "$KEYDIR/static.pub")"
CLIENT_PUB_HEX="$(tr -d '\r\n' < "$KEYDIR/client.pub")"
ADMISSION_FP="$(admission_fp "$KEYDIR/winn3-gateway-admission.key")"
STATIC_PUB_SHA="$(shasum -a 256 "$KEYDIR/static.pub" | cut -d' ' -f1)"
CLIENT_PUB_SHA="$(shasum -a 256 "$KEYDIR/client.pub" | cut -d' ' -f1)"
COVER_CHAIN_SHA="$(shasum -a 256 "$KEYDIR/cover/cover-fullchain.pem" | cut -d' ' -f1)"

# static_pub in the two encodings consumers use:
#   hex text  -> winn3-gateway -static expects a private key file but the
#                datapath profile gateway_static_path accepts hex or raw
#   base64    -> descriptor --static-pub wants base64 of the RAW 32 bytes
STATIC_PUB_B64="$(printf '%s' "$STATIC_PUB_HEX" | xxd -r -p | base64)"

cat > "$KEYDIR/fingerprints.txt" <<EOF
# public fingerprints for ${ROLE} (${GW_ID}) -- no secret material
gateway_id            ${GW_ID}
endpoint              ${ENDPOINT}:9111
static.pub sha256     ${STATIC_PUB_SHA}
static.pub hex        ${STATIC_PUB_HEX}
static.pub base64     ${STATIC_PUB_B64}
client.pub sha256     ${CLIENT_PUB_SHA}
client.pub hex        ${CLIENT_PUB_HEX}
admission fingerprint ${ADMISSION_FP}
cover chain sha256    ${COVER_CHAIN_SHA}
EOF
chmod 644 "$KEYDIR/fingerprints.txt"

# ---------------------------------------------------------------------------
# 4. Env file (names per emit_env_text; values baked per this role).
#    The firewall oneshot requires root:600 on this file after install.
# ---------------------------------------------------------------------------
cat > "$NODEDIR/winn3-gateway.env" <<EOF
# Winn Protocol v3 gateway -- staged by provision_gw.sh for ${ROLE}
# $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Read by winn3-gateway.service. Values are the operator's decision record;
# the unit bakes the flags at install time (same rule as the installer).

WINN3_GATEWAY_LISTEN=${LISTEN}

# RAW operator-string bytes; the client profile's gateway_id must match
# exactly. Not valid base64 (contains '-'), per runbook section 4.
WINN3_GATEWAY_ID=${GW_ID}

# Nothing negotiates this; client profiles must carry the same value.
WINN3_GATEWAY_PATH_MTU=${PATH_MTU}

# Host address inside FORWARD_CIDR; equals descriptor inner_router_v4.
WINN3_GATEWAY_INNER_V4=${INNER_V4}

WINN3_GATEWAY_PLAN=${PLAN}
WINN3_GATEWAY_MAX_SESSIONS=${MAX_SESSIONS}
GOMEMLIMIT=${GOMEMLIMIT}

# 1 = real forwarding. -forward/-accept-transit/-forward-if/-forward-cidr are
# baked into the unit; editing this value and restarting changes nothing.
WINN3_GATEWAY_FORWARD=${FORWARD}
WINN3_GATEWAY_FORWARD_IF=${FORWARD_IF}
WINN3_GATEWAY_FORWARD_CIDR=${SUBNET}
WINN3_GATEWAY_WAN_IF=${NIC}

# Record only: -forward-async-write is baked into the unit, like -forward.
WINN3_GATEWAY_FORWARD_ASYNC=${FORWARD_ASYNC}

# In-process resolver at INNER_V4:53 (UDP in-process; TCP/53 via the unit's
# CAP_NET_BIND_SERVICE). Required so descriptor inner_resolver_v4 answers.
WINN3_GATEWAY_RESOLVER=${RESOLVER}
WINN3_GATEWAY_RESOLVER_UPSTREAM=${RESOLVER_UPSTREAM}
WINN3_GATEWAY_RESOLVER_TIMEOUT=${RESOLVER_TIMEOUT}
EOF

# ---------------------------------------------------------------------------
# 5. systemd unit (emit_unit_text semantics, FORWARD=1 + RESOLVER=1 branch).
# ---------------------------------------------------------------------------
LISTEN_PORT="${LISTEN##*:}"
CAP_BIND="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"

cat > "$NODEDIR/winn3-gateway.service" <<EOF
[Unit]
Description=Winn Protocol v3 gateway (reachable multi-session responder; real forwarding via ${FORWARD_IF} + resolver at ${INNER_V4}:53 via ${RESOLVER_UPSTREAM})
Documentation=file:///etc/winn/winn3-gateway.env
After=network-online.target winn3-gateway-firewall.service
Wants=network-online.target
Requires=winn3-gateway-firewall.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=winn3-gateway
Group=winn3-gateway
EnvironmentFile=/etc/winn/winn3-gateway.env
Environment=GOMEMLIMIT=${GOMEMLIMIT}
LoadCredential=static.key:/etc/winn/credentials/winn3-gateway-static.key
LoadCredential=admission.key:/etc/winn/credentials/winn3-gateway-admission.key
LoadCredential=winn-leaf.pem:/etc/winn/credentials/winn3-cover/winn-leaf.pem
LoadCredential=winn-leaf-key.pem:/etc/winn/credentials/winn3-cover/winn-leaf-key.pem
LoadCredential=cover.pem:/etc/winn/credentials/winn3-cover/cover-fullchain.pem
LoadCredential=cover-key.pem:/etc/winn/credentials/winn3-cover/cover-key.pem
LoadCredential=ech-keys.json:/etc/winn/credentials/winn3-cover/ech-server-keys.json
RuntimeDirectory=winn3-gateway
RuntimeDirectoryMode=0700
# systemd exposes LoadCredential files 0440; the binary's private-file reader
# refuses any group access, so re-install each at 0400 into /run first. The
# leading + runs this as root outside the sandbox.
ExecStartPre=+/bin/sh -c 'for f in static.key admission.key winn-leaf.pem winn-leaf-key.pem cover.pem cover-key.pem ech-keys.json; do [ -f "\$CREDENTIALS_DIRECTORY/\$f" ] && install -m 0400 -o winn3-gateway -g winn3-gateway "\$CREDENTIALS_DIRECTORY/\$f" /run/winn3-gateway/\$f; done; true'
ExecStart=/usr/local/libexec/winn/winn3-gateway \\
  -mode serve \\
  -listen \${WINN3_GATEWAY_LISTEN} \\
  -static /run/winn3-gateway/static.key \\
  -admission /run/winn3-gateway/admission.key \\
  -gateway-id \${WINN3_GATEWAY_ID} \\
  -inner-v4 \${WINN3_GATEWAY_INNER_V4} \\
  -plan \${WINN3_GATEWAY_PLAN} \\
  -path-mtu \${WINN3_GATEWAY_PATH_MTU} \\
  -max-sessions ${MAX_SESSIONS} \\
  -forward \\
  -accept-transit=true \\
  -forward-if ${FORWARD_IF} \\
  -forward-cidr ${SUBNET} \\
  -peer-registry /etc/winn/winn3-peers.json \\${FORWARD_ASYNC_FLAG}
  -resolver \\
  -resolver-upstream \${WINN3_GATEWAY_RESOLVER_UPSTREAM} \\
  -resolver-timeout \${WINN3_GATEWAY_RESOLVER_TIMEOUT} \\
  -cover-cert /run/winn3-gateway/cover.pem \\
  -cover-key /run/winn3-gateway/cover-key.pem \\
  -ech-keys /run/winn3-gateway/ech-keys.json \\
  -cert /run/winn3-gateway/winn-leaf.pem \\
  -key /run/winn3-gateway/winn-leaf-key.pem
Restart=on-failure
RestartSec=2
TimeoutStopSec=20
KillSignal=SIGTERM
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=${CAP_BIND}
AmbientCapabilities=${CAP_BIND}
DeviceAllow=/dev/net/tun rw
BindPaths=/dev/net/tun
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SocketBindDeny=any
SocketBindAllow=udp:${LISTEN_PORT}
SocketBindAllow=tcp:${LISTEN_PORT}
SocketBindAllow=tcp:53
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
PrivateDevices=yes
PrivateTmp=yes
PrivateMounts=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectProc=invisible
ProtectSystem=strict
# ProcSubset=pid removed 2026-08-29: the bind proof reads
# /proc/sys/kernel/random/boot_id, which subset=pid masks (measured on
# systemd 255; see server/wins_winn3_gateway_install.sh). ProtectProc
# =invisible above still hides all other processes.
RemoveIPC=yes
SystemCallArchitectures=native
LimitNOFILE=8192
TasksMax=256
# Session-derived: MemoryMax = 64M + 1.5 MiB * ${MAX_SESSIONS}; MemoryHigh = 75%; GOMEMLIMIT = 80% of High.
MemoryMax=${MEMORY_MAX}
MemoryHigh=${MEMORY_HIGH}

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# 6. Firewall oneshot (write_gateway_listen_firewall_unit semantics).
# ---------------------------------------------------------------------------
cat > "$NODEDIR/winn3-gateway-firewall" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
env_file="${WINN3_GATEWAY_ENV_FILE:-/etc/winn/winn3-gateway.env}"
[[ -f "${env_file}" && ! -L "${env_file}" \
    && "$(stat -c '%u:%a' "${env_file}")" == "0:600" ]] || {
  echo "winn3 gateway firewall requires a root-owned regular 0600 env file" >&2
  exit 1
}
# shellcheck disable=SC1090
source "${env_file}"
port="${WINN3_GATEWAY_LISTEN##*:}"
[[ "${port}" =~ ^[0-9]+$ && "${port}" -ge 1 && "${port}" -le 65535 ]] || {
  echo "invalid WINN3_GATEWAY_LISTEN in ${env_file}" >&2
  exit 1
}
# This demo helper only manages a standalone host's own INPUT. On a data-plane
# node an unpositioned insert into WINVPN-INPUT lands above its SSH-recovery
# and local-serving guard jumps (OI-G3.3), so it refuses there; the guard-aware
# placement is server/wins_winn3_gateway_install.sh's boot helper.
filter_rules="$(iptables -w 10 -S)" || {
  echo "winn3 gateway firewall: cannot read the filter table; nothing was changed." >&2
  exit 1
}
if grep -Eq -- '^-N WINVPN-INPUT$|^-A INPUT .*-[jg] (WINVPN-INPUT|WINVPN-SSH-RECOVERY|WINVPN-LOCAL-SERVING)( |$)' <<<"${filter_rules}"; then
  echo "winn3 gateway firewall: this is a data-plane host (WINVPN-INPUT or its guards exist); install with server/wins_winn3_gateway_install.sh instead. Nothing was changed." >&2
  exit 1
fi
chain=INPUT
for protocol in udp tcp; do
  iptables -w 10 -C "${chain}" -p "${protocol}" --dport "${port}" -j ACCEPT >/dev/null 2>&1 \
    || iptables -w 10 -I "${chain}" -p "${protocol}" --dport "${port}" -j ACCEPT
  iptables -w 10 -C "${chain}" -p "${protocol}" --dport "${port}" -j ACCEPT
done

if [[ "${WINN3_GATEWAY_FORWARD:-0}" == "1" ]]; then
  iface="${WINN3_GATEWAY_FORWARD_IF:?}"
  cidr="${WINN3_GATEWAY_FORWARD_CIDR:?}"
  wan_if="${WINN3_GATEWAY_WAN_IF:-$(ip -o route show default | awk '{print $5; exit}')}"
  [[ -n "${wan_if}" ]] || { echo "could not resolve Winn3 gateway WAN interface" >&2; exit 1; }

  iptables -w 10 -N WINN3GW-FORWARD 2>/dev/null || true
  iptables -w 10 -F WINN3GW-FORWARD
  iptables -w 10 -A WINN3GW-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -s "${cidr}" -i "${iface}" -o "${wan_if}" -j ACCEPT
  iptables -w 10 -A WINN3GW-FORWARD -j DROP

  iptables -w 10 -t nat -N WINN3GW-NAT-POSTROUTING 2>/dev/null || true
  iptables -w 10 -t nat -F WINN3GW-NAT-POSTROUTING
  iptables -w 10 -t nat -A WINN3GW-NAT-POSTROUTING -s "${cidr}" -o "${wan_if}" -j MASQUERADE

  while iptables -w 10 -D FORWARD -i "${iface}" -j WINN3GW-FORWARD 2>/dev/null; do :; done
  while iptables -w 10 -D FORWARD -o "${iface}" -j WINN3GW-FORWARD 2>/dev/null; do :; done
  while iptables -w 10 -t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING 2>/dev/null; do :; done
  iptables -w 10 -I FORWARD 1 -i "${iface}" -j WINN3GW-FORWARD
  iptables -w 10 -I FORWARD 1 -o "${iface}" -j WINN3GW-FORWARD
  iptables -w 10 -t nat -I POSTROUTING 1 -j WINN3GW-NAT-POSTROUTING

  iptables -w 10 -C FORWARD -i "${iface}" -j WINN3GW-FORWARD
  iptables -w 10 -C FORWARD -o "${iface}" -j WINN3GW-FORWARD
  iptables -w 10 -t nat -C WINN3GW-NAT-POSTROUTING -s "${cidr}" -o "${wan_if}" -j MASQUERADE

  if [[ "${WINN3_GATEWAY_RESOLVER:-0}" == "1" ]]; then
    inner="${WINN3_GATEWAY_INNER_V4:?}"
    iptables -w 10 -N WINN3GW-INPUT 2>/dev/null || true
    iptables -w 10 -F WINN3GW-INPUT
    iptables -w 10 -A WINN3GW-INPUT -i "${iface}" -d "${inner}" -p tcp --dport 53 -j ACCEPT
    iptables -w 10 -A WINN3GW-INPUT -j DROP
    while iptables -w 10 -D INPUT -i "${iface}" -d "${inner}" -p tcp --dport 53 -j WINN3GW-INPUT 2>/dev/null; do :; done
    iptables -w 10 -I INPUT 1 -i "${iface}" -d "${inner}" -p tcp --dport 53 -j WINN3GW-INPUT
    iptables -w 10 -C INPUT -i "${iface}" -d "${inner}" -p tcp --dport 53 -j WINN3GW-INPUT
  fi
fi
EOF

cat > "$NODEDIR/winn3-gateway-firewall.service" <<'EOF'
[Unit]
Description=Winn Protocol v3 gateway UDP/TCP ingress
After=network-online.target
Before=winn3-gateway.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/winn3-gateway-firewall
RemainAfterExit=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------------
# 7. Hub-VM verification client profile (runbook 5.4; device loopback-udp).
#    Key paths are absolute on the hub VM staging directory.
# ---------------------------------------------------------------------------
HUB_STAGE="\${HUB_STAGE_DIR:?set HUB_STAGE_DIR to the hub staging dir}"
cat > "$NODEDIR/client-profile.json" <<EOF
{
  "version": "winn3-host/1",
  "role": "client",
  "plan": ["${PLAN}"],
  "path_mtu": ${PATH_MTU},
  "gateway_id": "${GW_ID}",
  "carrier": {
    "class": "udp",
    "endpoint": "${ENDPOINT}:9111"
  },
  "inner": {
    "v4": "${CLIENT_V4}",
    "router_v4": "${INNER_V4}"
  },
  "keys": {
    "static_path": "${HUB_STAGE}/client.key",
    "gateway_static_path": "${HUB_STAGE}/gateway-static.pub",
    "admission_path": "${HUB_STAGE}/admission.key"
  },
  "device": {
    "kind": "loopback-udp",
    "host_port": ${VERIFY_HOSTPORT}
  },
  "allow_own_socket": true,
  "outer_socket_exclusion": "hub-vm verifier binds no default route over the seam; the engine's outer UDP socket routes via the host default route to ${ENDPOINT}:9111, not via the loopback seam",
  "fast_pq": false
}
EOF

log "staged ${NODEDIR}:"
ls -1 "$NODEDIR" | sed 's/^/  /'
log "staged ${KEYDIR}:"
find "$KEYDIR" -type f | sort | sed 's/^/  /'

# ---------------------------------------------------------------------------
# 8. PUBSUMMARY.md refresh (both roles; public material only).
# ---------------------------------------------------------------------------
write_role_summary() {
  local role="$1" keydir="keys/$1"
  local gw_id endpoint subnet inner cover_domain static_hex static_b64 adm_fp static_sha cover_sha
  case "$role" in
    demo-gw-a) gw_id=demo-gw-a; endpoint=203.0.113.10; subnet=10.10.0.0/24; inner=10.10.0.1; cover_domain=static-assets-cdn.net ;;
    demo-gw-b) gw_id=demo-gw-b; endpoint=203.0.113.20; subnet=10.11.0.0/24; inner=10.11.0.1; cover_domain=content-delivery-edge.net ;;
  esac
  static_hex="$(tr -d '\r\n' < "$keydir/static.pub")"
  static_b64="$(printf '%s' "$static_hex" | xxd -r -p | base64)"
  client_hex="$(tr -d '\r\n' < "$keydir/client.pub")"
  adm_fp="$({ printf '%s' 'winn3-admission-fingerprint-v1'; tr -d '\r\n' < "$keydir/winn3-gateway-admission.key"; } | shasum -a 256 | cut -c1-16)"
  static_sha="$(shasum -a 256 "$keydir/static.pub" | cut -d' ' -f1)"
  cover_sha="$(shasum -a 256 "$keydir/cover/cover-fullchain.pem" | cut -d' ' -f1)"
  cat <<SUMMARY
## ${role} (${gw_id})

| fact | value |
|---|---|
| VM | gateway-vm-a/b per SPEC.md (egress ${endpoint}) |
| endpoint (descriptor + client profile) | \`${endpoint}:9111\` (IP literal, UDP+TCP) |
| inner_router_v4 = inner_resolver_v4 | \`${inner}\` (descriptor requires the two EQUAL) |
| forward subnet | \`${subnet}\` (gateway .1, clients from .2; winn3-peers.json binds the verify client to .2) |
| path MTU | 1450 (gateway, client profile, descriptor must all agree; nothing negotiates it) |
| gateway static PUBLIC (hex, 64 chars) | \`${static_hex}\` |
| gateway static PUBLIC (base64 of raw 32 bytes) | \`${static_b64}\` |
| static.pub sha256 | \`${static_sha}\` |
| client PUBLIC (hex, 64 chars, verify-client) | \`${client_hex}\` |
| admission fingerprint (16 hex, safe to paste) | \`${adm_fp}\` |
| cover chain sha256 | \`${cover_sha}\` (cover domain \`${cover_domain}\`, lab-generated demo material) |

### Where each item goes (per tools/winn3_sign_descriptor.py payload builder)

| signer argument | value source | public/secret |
|---|---|---|
| \`--node\` | slug from SPEC.md (\`demo-route-a\` / \`demo-route-b\`) | public |
| \`--endpoint\` | \`${endpoint}:9111\` | public |
| \`--inner-router-v4\` | \`${inner}\` | public |
| \`--inner-resolver-v4\` | \`${inner}\` (MUST equal inner-router-v4; gateway answers DNS there) | public |
| \`--static-pub\` | base64 above (= \`keys/${role}/static.pub\` decoded to raw 32 bytes) | public |
| \`--gateway-id-text\` | \`${gw_id}\` (raw UTF-8; '-' keeps it out of valid-base64 territory) | public |
| \`--admission-secret-file\` | SECRET, supervisor-held: \`keys/${role}/winn3-gateway-admission.key\` (opaque ASCII-hex file bytes; NEVER hex-decode, never print) | secret |
| \`--admission-gen\` / \`--seq\` / \`--prev-seq\` / \`--kid\` | supervisor ceremony (seq strictly increases; first publication \`--prev-seq none\`) | n/a |

The gateway's PRIVATE halves never leave the node once deployed:
\`keys/${role}/winn3-gateway-static.key\` -> /etc/winn/credentials/winn3-gateway-static.key (0600 root),
\`winn3-gateway-admission.key\` -> /etc/winn/credentials/winn3-gateway-admission.key (0600 root).
The hub-VM verification client uses \`keys/${role}/client.key\` + \`static.pub\` + a copy of the admission file.

SUMMARY
}

{
  cat <<'HDR'
# keys/PUBSUMMARY.md -- winn/3 demo gateways, PUBLIC material only

Generated by provision_gw.sh. No secret is printed here. The only supervisor-held
secret named below is the admission key FILE (symmetric: gateway + every client
hold the same file bytes; descriptor \`admission_secret\` rides the signed payload).

Descriptor envelope shape (hub serves): {"payload": <b64>, "sig": <b64>},
format_version 3 inside, domain winsvpn-winn3-descriptor/v1, Ed25519 over
DOMAIN||0x00||payload-bytes. Signing is the supervisor's offline ceremony.

HDR
  for summary_role in demo-gw-a demo-gw-b; do
    if [[ -d "keys/$summary_role" ]]; then
      write_role_summary "$summary_role"
    fi
  done
} > keys/PUBSUMMARY.md

log "wrote keys/PUBSUMMARY.md"
log "receipts (public only):"
sed 's/^/  /' "$KEYDIR/fingerprints.txt"
log "DONE ${ROLE}. No private material was printed."
