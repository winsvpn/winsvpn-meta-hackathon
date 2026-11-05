#!/bin/sh
set -eu

# Runs cmd/winn-acceptance inside a disposable, internet-routed network
# namespace, reusing the exact same safe NAT-egress setup proven in
# scripts/aicore_real_gateway_e2e.sh (see that file's own header for why
# this is namespace-isolated and never touches the root namespace's own
# nftables/SSH path). This variant runs the full multi-attempt driver
# instead of the single-shot E2E binary.

IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
PING_BIN=${PING_BIN:-/bin/ping}
TC_BIN=${TC_BIN:-/usr/sbin/tc}
ACCEPTANCE_BIN=${ACCEPTANCE_BIN:-/opt/winn-lab/bin/winn-acceptance}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winnacns}
CLIENT_VETH=${CLIENT_VETH:-winnacv0}
ROOT_VETH=${ROOT_VETH:-winnacv1}
CLIENT_VETH_SUBNET=${CLIENT_VETH_SUBNET:-172.31.210.0/30}
CLIENT_VETH_ROOT_IP=${CLIENT_VETH_ROOT_IP:-172.31.210.1}
CLIENT_VETH_NS_IP=${CLIENT_VETH_NS_IP:-172.31.210.2}
TABLE_NAME=${TABLE_NAME:-winnacceptance}
UNDERLAY_MARK=${UNDERLAY_MARK:-9979}
NAT_TABLE=${NAT_TABLE:-winnacceptancenat}
EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE}

CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}
ATTEMPTS=${ATTEMPTS:-10}
WARM_BATCH=${WARM_BATCH:-5}
LOG_PATH=${LOG_PATH:?must set LOG_PATH}
LOG_KEY_PATH=${LOG_KEY_PATH:?must set LOG_KEY_PATH}
GATEWAY_LIMIT=${GATEWAY_LIMIT:-0}
NETWORK_PROFILE=${NETWORK_PROFILE:-baseline}
NETWORK_INTERFACE=${NETWORK_INTERFACE:-ethernet}
IP_FAMILY=${IP_FAMILY:-ipv4}
NETWORK_NAT=${NETWORK_NAT:-namespace-masquerade}
CLIENT_REGION=${CLIENT_REGION:-aicore-lab}
ENVIRONMENT_PATH=${ENVIRONMENT_PATH:-"${LOG_PATH}.environment"}

case "$NETWORK_PROFILE" in
baseline)
	NETWORK_IMPAIRMENT=none
	RTT_MS=0
	LOSS_FRACTION=0
	CAPACITY_MBPS=0
	NETEM_ARGS=""
	;;
metro)
	NETWORK_IMPAIRMENT=netem-metro-v1
	RTT_MS=30
	LOSS_FRACTION=0.001
	CAPACITY_MBPS=100
	NETEM_ARGS="delay 15ms 3ms distribution normal loss 0.1% rate 100mbit limit 2000"
	;;
cellular)
	NETWORK_IMPAIRMENT=netem-cellular-v1
	RTT_MS=90
	LOSS_FRACTION=0.005
	CAPACITY_MBPS=25
	NETEM_ARGS="delay 45ms 10ms distribution normal loss 0.5% rate 25mbit limit 2000"
	;;
constrained)
	NETWORK_IMPAIRMENT=netem-constrained-v1
	RTT_MS=200
	LOSS_FRACTION=0.01
	CAPACITY_MBPS=5
	NETEM_ARGS="delay 100ms 20ms distribution normal loss 1% rate 5mbit limit 2000"
	;;
*)
	echo "unknown NETWORK_PROFILE: $NETWORK_PROFILE" >&2
	exit 1
	;;
esac

for executable in "$IP_BIN" "$NFT_BIN" "$PING_BIN" "$TC_BIN" "$ACCEPTANCE_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
if "$IP_BIN" netns list | awk '{ print $1 }' | grep -Fx "$CLIENT_NAMESPACE" >/dev/null 2>&1; then
	echo "refusing to reuse existing namespace: $CLIENT_NAMESPACE" >&2
	exit 1
fi
for interface_name in "$CLIENT_VETH" "$ROOT_VETH"; do
	if "$IP_BIN" link show dev "$interface_name" >/dev/null 2>&1; then
		echo "refusing to reuse existing interface: $interface_name" >&2
		exit 1
	fi
done
if ! "$IP_BIN" link show dev "$EGRESS_INTERFACE" >/dev/null 2>&1; then
	echo "egress interface does not exist: $EGRESS_INTERFACE" >&2
	exit 1
fi

environment_temporary="${ENVIRONMENT_PATH}.tmp.$$"
if [ -e "$ENVIRONMENT_PATH" ] || [ -e "$environment_temporary" ]; then
	echo "refusing to overwrite environment evidence" >&2
	exit 1
fi
private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-acceptance-run.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

DRIVER_PID=""
IP_FORWARD_PREVIOUS=""
NAT_ADDED=0

cleanup() {
	if [ -n "$DRIVER_PID" ]; then
		kill "$DRIVER_PID" >/dev/null 2>&1 || true
		wait "$DRIVER_PID" >/dev/null 2>&1 || true
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
	rm -f "$environment_temporary" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }
publish_environment() {
	if ! ln "$environment_temporary" "$ENVIRONMENT_PATH"; then
		echo "failed to publish environment evidence exclusively" >&2
		return 1
	fi
	rm -f "$environment_temporary"
}

echo "=== SAFETY CHECK: confirming SSH-carrying route is untouched before any change ==="
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
if [ -n "$NETEM_ARGS" ]; then
	# Apply the fixed per-direction profile to both ends of the disposable
	# veth. The listed delay is one half of the declared RTT; applying it only
	# to CLIENT_VETH would understate the round-trip impairment by half.
	# shellcheck disable=SC2086
	client_exec "$TC_BIN" qdisc replace dev "$CLIENT_VETH" root \
		handle 1: netem $NETEM_ARGS
	# NETEM_ARGS is selected only by the fixed case table above.
	# shellcheck disable=SC2086
	"$TC_BIN" qdisc replace dev "$ROOT_VETH" root \
		handle 1: netem $NETEM_ARGS
fi

"$NFT_BIN" add table ip "$NAT_TABLE"
"$NFT_BIN" add chain ip "$NAT_TABLE" postrouting \
	'{ type nat hook postrouting priority 100 ; }'
"$NFT_BIN" add rule ip "$NAT_TABLE" postrouting \
	ip saddr "$CLIENT_VETH_SUBNET" oifname "$EGRESS_INTERFACE" masquerade
NAT_ADDED=1

client_exec "$PING_BIN" -n -q -c 1 -W 2 -I "$CLIENT_VETH" "$CLIENT_VETH_ROOT_IP" >/dev/null
echo "=== veth+NAT path established, testing real internet reachability from namespace ==="
client_exec "$PING_BIN" -n -q -c 2 -W 3 -I "$CLIENT_VETH" 1.1.1.1

{
	echo "schema=winn-network-envelope/v1"
	echo "captured_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "profile=$NETWORK_PROFILE"
	echo "impairment=$NETWORK_IMPAIRMENT"
	echo "declared_rtt_ms=$RTT_MS"
	echo "declared_loss_fraction=$LOSS_FRACTION"
	echo "declared_capacity_mbps=$CAPACITY_MBPS"
	echo "namespace=$CLIENT_NAMESPACE"
	echo "client_interface=$CLIENT_VETH"
	echo "egress_interface=$EGRESS_INTERFACE"
	echo "ip_family=$IP_FAMILY"
	echo "nat=$NETWORK_NAT"
	echo "acceptance_binary_sha256=$(
		sha256sum "$ACCEPTANCE_BIN" | awk '{print $1}'
	)"
	echo "--- ip-address ---"
	client_exec "$IP_BIN" -details address show
	echo "--- ip-route ---"
	client_exec "$IP_BIN" -details route show table all
	echo "--- tc-before ---"
	client_exec "$TC_BIN" -s -details qdisc show dev "$CLIENT_VETH"
	echo "--- tc-root-before ---"
	"$TC_BIN" -s -details qdisc show dev "$ROOT_VETH"
} >"$environment_temporary"

echo "=== RUNNING winn-acceptance: $ATTEMPTS attempts, warm-batch=$WARM_BATCH ==="
set +e
client_exec "$ACCEPTANCE_BIN" \
	-attempts="$ATTEMPTS" \
	-warm-batch="$WARM_BATCH" \
	-client-private-key-file="$CLIENT_PRIVATE_KEY_FILE" \
	-psk-file="$PSK_FILE" \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$(printf '%x' "$UNDERLAY_MARK")" \
	-temp-root="$private_directory" \
	-gateway-limit="$GATEWAY_LIMIT" \
	-network-interface="$NETWORK_INTERFACE" \
	-ip-family="$IP_FAMILY" \
	-nat="$NETWORK_NAT" \
	-impairment="$NETWORK_IMPAIRMENT" \
	-rtt-ms="$RTT_MS" \
	-loss-fraction="$LOSS_FRACTION" \
	-capacity-mbps="$CAPACITY_MBPS" \
	-client-region="$CLIENT_REGION" \
	-log-path="$LOG_PATH" \
	-log-key-path="$LOG_KEY_PATH"
driver_status=$?
set -e

if [ "$driver_status" -ne 0 ]; then
	{
		echo "--- tc-after-failure ---"
		client_exec "$TC_BIN" -s -details qdisc show dev "$CLIENT_VETH"
		echo "--- tc-root-after-failure ---"
		"$TC_BIN" -s -details qdisc show dev "$ROOT_VETH"
		echo "driver_exit_status=$driver_status"
	} >>"$environment_temporary"
	publish_environment
	echo "ACCEPTANCE DRIVER FAILED (exit $driver_status)" >&2
	exit 1
fi
{
	echo "--- tc-after-success ---"
	client_exec "$TC_BIN" -s -details qdisc show dev "$CLIENT_VETH"
	echo "--- tc-root-after-success ---"
	"$TC_BIN" -s -details qdisc show dev "$ROOT_VETH"
	echo "driver_exit_status=0"
} >>"$environment_temporary"
publish_environment
sha256sum "$ENVIRONMENT_PATH"
echo "=== ACCEPTANCE DRIVER COMPLETED ==="

echo "=== SAFETY CHECK: confirming SSH-carrying route still intact after cleanup ==="
cleanup
trap - EXIT HUP INT TERM
"$IP_BIN" route show default
