#!/bin/sh
set -eu

# Measures real data throughput through Winn's production direct-AWG
# Candidate/Connection/carrier path. Run aicore_awg_baseline_throughput.sh
# immediately before or after this script against the same gateway to compute
# Phase 1's "direct throughput reaches at least 90% of AWG baseline" gate.
# Reuses the same safe NAT-egress namespace pattern as the acceptance driver.

IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
PING_BIN=${PING_BIN:-/bin/ping}
AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
ACCEPTANCE_BIN=${ACCEPTANCE_BIN:-/opt/winn-lab/bin/winn-acceptance}
IPERF3_BIN=${IPERF3_BIN:-/usr/bin/iperf3}
TIMEOUT_BIN=${TIMEOUT_BIN:-/usr/bin/timeout}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winntpns}
CLIENT_VETH=${CLIENT_VETH:-winntpv0}
ROOT_VETH=${ROOT_VETH:-winntpv1}
CLIENT_VETH_SUBNET=${CLIENT_VETH_SUBNET:-172.31.211.0/30}
CLIENT_VETH_ROOT_IP=${CLIENT_VETH_ROOT_IP:-172.31.211.1}
CLIENT_VETH_NS_IP=${CLIENT_VETH_NS_IP:-172.31.211.2}
TABLE_NAME=${TABLE_NAME:-winnthroughput}
UNDERLAY_MARK=${UNDERLAY_MARK:-9980}
NAT_TABLE=${NAT_TABLE:-winnthroughputnat}
EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE}

GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT:?must set GATEWAY_ENDPOINT}
GATEWAY_PUBKEY=${GATEWAY_PUBKEY:?must set GATEWAY_PUBKEY}
GATEWAY_ID=${GATEWAY_ID:-${GATEWAY_NAME:?must set GATEWAY_ID or GATEWAY_NAME}}
GATEWAY_INNER_IP=${GATEWAY_INNER_IP:-10.203.1.1}
CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}
HOLD_SECONDS=${HOLD_SECONDS:-30}
IPERF_SECONDS=${IPERF_SECONDS:-8}
IPERF_OMIT_SECONDS=${IPERF_OMIT_SECONDS:-3}
IPERF_STREAMS=${IPERF_STREAMS:-4}
IPERF_JSON_OUT=${IPERF_JSON_OUT:-}

for executable in "$IP_BIN" "$NFT_BIN" "$PING_BIN" "$AWG_BIN" "$AWG_ENGINE" "$ACCEPTANCE_BIN" "$IPERF3_BIN" "$TIMEOUT_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
if "$IP_BIN" netns list | awk '{ print $1 }' | grep -Fx "$CLIENT_NAMESPACE" >/dev/null 2>&1; then
	echo "refusing to reuse existing namespace: $CLIENT_NAMESPACE" >&2
	exit 1
fi

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-throughput.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

WINN_PID=""
IP_FORWARD_PREVIOUS=""
NAT_ADDED=0
IPERF_JSON_TEMP=""

cleanup() {
	if [ -n "$WINN_PID" ]; then
		kill "$WINN_PID" >/dev/null 2>&1 || true
		wait "$WINN_PID" >/dev/null 2>&1 || true
	fi
	if [ "$NAT_ADDED" -eq 1 ]; then
		"$NFT_BIN" delete table ip "$NAT_TABLE" >/dev/null 2>&1 || true
	fi
	"$IP_BIN" netns del "$CLIENT_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$ROOT_VETH" >/dev/null 2>&1 || true
	if [ -n "$IP_FORWARD_PREVIOUS" ]; then
		sysctl -w net.ipv4.ip_forward="$IP_FORWARD_PREVIOUS" >/dev/null 2>&1 || true
	fi
	find "$private_directory" -type f -delete >/dev/null 2>&1 || true
	rmdir "$private_directory" >/dev/null 2>&1 || true
	if [ -n "$IPERF_JSON_TEMP" ] && [ -f "$IPERF_JSON_TEMP" ]; then
		unlink "$IPERF_JSON_TEMP" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }

echo "=== SAFETY CHECK: SSH-carrying route before any change ==="
"$IP_BIN" route show default

IP_FORWARD_PREVIOUS=$(sysctl -n net.ipv4.ip_forward)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" link add "$ROOT_VETH" type veth peer name "$CLIENT_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" address add "${CLIENT_VETH_ROOT_IP}/30" dev "$ROOT_VETH"
"$IP_BIN" link set dev "$ROOT_VETH" up
client_exec "$IP_BIN" link set lo up
client_exec "$IP_BIN" address add "${CLIENT_VETH_NS_IP}/30" dev "$CLIENT_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
client_exec "$IP_BIN" route add default via "$CLIENT_VETH_ROOT_IP"
if command -v ethtool >/dev/null 2>&1; then
	ethtool -K "$ROOT_VETH" tx off rx off >/dev/null 2>&1 || true
	client_exec ethtool -K "$CLIENT_VETH" tx off rx off >/dev/null 2>&1 || true
fi
"$NFT_BIN" add table ip "$NAT_TABLE"
"$NFT_BIN" add chain ip "$NAT_TABLE" postrouting \
	'{ type nat hook postrouting priority 100 ; }'
"$NFT_BIN" add rule ip "$NAT_TABLE" postrouting \
	ip saddr "$CLIENT_VETH_SUBNET" oifname "$EGRESS_INTERFACE" masquerade
NAT_ADDED=1
client_exec "$PING_BIN" -n -q -c 1 -W 2 -I "$CLIENT_VETH" "$CLIENT_VETH_ROOT_IP" >/dev/null

echo "=== PHASE 1: throughput through Winn's production candidate path ==="
"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$ACCEPTANCE_BIN" \
	-attempts=1 \
	-warm-batch=1 \
	-gateway-id="$GATEWAY_ID" \
	-client-private-key-file="$CLIENT_PRIVATE_KEY_FILE" \
	-psk-file="$PSK_FILE" \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$(printf '%x' "$UNDERLAY_MARK")" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary=/usr/bin/resolvectl \
	-temp-root="$private_directory" \
	-log-path="$private_directory/throughput-acceptance.jsonl" \
	-log-key-path="$private_directory/throughput-acceptance.key" \
	-online-hold="${HOLD_SECONDS}s" \
	>"$private_directory/winn-acceptance.log" 2>&1 &
WINN_PID=$!

attempt=0
while ! grep -q '^HOLD_ONLINE ' "$private_directory/winn-acceptance.log" 2>/dev/null; do
	if ! kill -0 "$WINN_PID" >/dev/null 2>&1; then
		echo "winn acceptance process exited before committing" >&2
		cat "$private_directory/winn-acceptance.log" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 500 ]; then
		echo "winn production candidate never committed" >&2
		cat "$private_directory/winn-acceptance.log" >&2
		exit 1
	fi
	sleep 0.05
done
echo "winn tunnel committed, running iperf3 through it"

winn_iface=$(client_exec "$IP_BIN" -o link show | grep -oE 'winn[0-9a-f]{10}' | head -1)
if [ -z "$winn_iface" ]; then
	echo "could not find committed winn tunnel interface" >&2
	cat "$private_directory/winn-acceptance.log" >&2
	exit 1
fi
echo "committed tunnel interface: $winn_iface"

client_exec "$TIMEOUT_BIN" "$((IPERF_OMIT_SECONDS + IPERF_SECONDS + 10))s" \
	"$IPERF3_BIN" -c "$GATEWAY_INNER_IP" -p 5201 \
	-O "$IPERF_OMIT_SECONDS" -t "$IPERF_SECONDS" -P "$IPERF_STREAMS" \
	--bind-dev "$winn_iface" -J \
	>"$private_directory/winn-iperf3.json" 2>"$private_directory/winn-iperf3.err" || {
	echo "winn iperf3 run failed" >&2
	cat "$private_directory/winn-iperf3.err" >&2
	exit 1
}
winn_mbps=$(python3 -c "import json; d=json.load(open('$private_directory/winn-iperf3.json')); print(d['end']['sum_sent']['bits_per_second']/1e6)")
echo "WINN_THROUGHPUT_MBPS=$winn_mbps"
if [ -n "$IPERF_JSON_OUT" ]; then
	if [ -e "$IPERF_JSON_OUT" ]; then
		echo "refusing to overwrite IPERF_JSON_OUT: $IPERF_JSON_OUT" >&2
		exit 1
	fi
	output_parent=$(dirname -- "$IPERF_JSON_OUT")
	if [ ! -d "$output_parent" ]; then
		echo "IPERF_JSON_OUT parent does not exist: $output_parent" >&2
		exit 1
	fi
	IPERF_JSON_TEMP="${IPERF_JSON_OUT}.tmp.$$"
	if [ -e "$IPERF_JSON_TEMP" ]; then
		echo "refusing to reuse temporary evidence path: $IPERF_JSON_TEMP" >&2
		exit 1
	fi
	cp "$private_directory/winn-iperf3.json" "$IPERF_JSON_TEMP"
	chmod 0600 "$IPERF_JSON_TEMP"
	mv "$IPERF_JSON_TEMP" "$IPERF_JSON_OUT"
	IPERF_JSON_TEMP=""
	iperf_json_sha256=$(sha256sum "$IPERF_JSON_OUT" | awk '{ print $1 }')
	echo "THROUGHPUT_IPERF_JSON_SHA256=$iperf_json_sha256"
fi
echo "THROUGHPUT_ROLE=winn"
echo "THROUGHPUT_PATH=production-directawg-candidate-v1"
echo "THROUGHPUT_GATEWAY_ENDPOINT=$GATEWAY_ENDPOINT"
echo "THROUGHPUT_GATEWAY_INNER_IP=$GATEWAY_INNER_IP"

if ! wait "$WINN_PID"; then
	echo "winn production candidate failed during hold/teardown" >&2
	cat "$private_directory/winn-acceptance.log" >&2
	exit 1
fi
WINN_PID=""
echo "PASS: winn tunnel throughput measured, clean close"
