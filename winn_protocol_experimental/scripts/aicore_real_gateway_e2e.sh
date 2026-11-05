#!/bin/sh
set -eu

# Privileged, namespace-isolated E2E test for the real internal/directawg
# Linux controller + nftables policy factory against a REAL cloud gateway
# over the real internet, rather than a local fake. The disposable client
# namespace gets real egress via a NAT/masquerade rule scoped to its own
# veth subnet in the root namespace — this is the ONLY root-namespace
# change made; the kill-switch nftables table itself is created inside the
# namespace via "ip netns exec", which is a fully separate netfilter
# instance from the root namespace's own rules (confirmed: this is how
# scripts/aicore_directawg_policy_e2e.sh's kill-switch already works
# safely). Nothing here touches the root namespace's existing nftables/ufw
# chains, default route, or SSH path.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
RESOLVECTL_BIN=${RESOLVECTL_BIN:-/usr/bin/resolvectl}
PING_BIN=${PING_BIN:-/bin/ping}
E2E_BIN=${E2E_BIN:-/opt/winn-lab/bin/winn-aicore-directawg-e2e}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winnrgns}
CLIENT_VETH=${CLIENT_VETH:-winnrgv0}
ROOT_VETH=${ROOT_VETH:-winnrgv1}
CLIENT_VETH_SUBNET=${CLIENT_VETH_SUBNET:-172.31.209.0/30}
CLIENT_VETH_ROOT_IP=${CLIENT_VETH_ROOT_IP:-172.31.209.1}
CLIENT_VETH_NS_IP=${CLIENT_VETH_NS_IP:-172.31.209.2}
TABLE_NAME=${TABLE_NAME:-winnrealgw}
UNDERLAY_MARK=${UNDERLAY_MARK:-9978}
NAT_TABLE=${NAT_TABLE:-winnrealgwnat}
EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE (the real internet-facing interface)}

GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT:?must set GATEWAY_ENDPOINT (ip:port)}
GATEWAY_PUBKEY=${GATEWAY_PUBKEY:?must set GATEWAY_PUBKEY}
CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}
# INNER_POOL is the client's own leased-address pool (must not overlap the
# gateway's own /30). TUNNEL_ROUTE is the wider range routed through the
# tunnel and that DNS/canary verification must stay within — it must cover
# both the gateway's own address (where the responders listen) and
# INNER_POOL, since Verify*'s route check validates against this, not
# against INNER_POOL.
INNER_POOL=${INNER_POOL:?must set INNER_POOL, e.g. 10.203.1.16/28}
TUNNEL_ROUTE=${TUNNEL_ROUTE:?must set TUNNEL_ROUTE, e.g. 10.203.1.0/24}
DNS_RESOLVER=${DNS_RESOLVER:?must set DNS_RESOLVER, e.g. 10.203.1.1:53}
CANARY_ENDPOINT=${CANARY_ENDPOINT:?must set CANARY_ENDPOINT, e.g. 10.203.1.1:9999}
EXPECTED_DNS_ANSWER=${EXPECTED_DNS_ANSWER:-203.0.113.99}

for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$NFT_BIN" \
	"$RESOLVECTL_BIN" "$PING_BIN" "$E2E_BIN"; do
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

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-real-gw-e2e.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

CLIENT_PID=""
IP_FORWARD_PREVIOUS=""
NAT_ADDED=0

cleanup() {
	if [ -n "$CLIENT_PID" ]; then
		kill "$CLIENT_PID" >/dev/null 2>&1 || true
		wait "$CLIENT_PID" >/dev/null 2>&1 || true
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
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }

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

# NAT rule scoped ONLY to this run's specific /30 subnet egressing out the
# named real interface — additive, does not touch or replace any existing
# rule, and is fully removed in cleanup(). This is the only root-namespace
# firewall change this script makes.
"$NFT_BIN" add table ip "$NAT_TABLE"
"$NFT_BIN" add chain ip "$NAT_TABLE" postrouting \
	'{ type nat hook postrouting priority 100 ; }'
"$NFT_BIN" add rule ip "$NAT_TABLE" postrouting \
	ip saddr "$CLIENT_VETH_SUBNET" oifname "$EGRESS_INTERFACE" masquerade
NAT_ADDED=1

client_exec "$PING_BIN" -n -q -c 1 -W 2 -I "$CLIENT_VETH" "$CLIENT_VETH_ROOT_IP" >/dev/null
echo "=== veth+NAT path established, testing real internet reachability from namespace ==="
client_exec "$PING_BIN" -n -q -c 2 -W 3 -I "$CLIENT_VETH" 1.1.1.1

client_private_b64=$(tr -d '\r\n' <"$CLIENT_PRIVATE_KEY_FILE")
psk_b64=$(tr -d '\r\n' <"$PSK_FILE")

TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
	"$IP_BIN" netns exec "$CLIENT_NAMESPACE" tcpdump -U -i "$CLIENT_VETH" -n -vv udp port 51820 \
		>"$private_directory/client-veth-tcpdump.log" 2>&1 &
	TCPDUMP_PID=$!
	sleep 1
fi

echo "=== RUNNING CLIENT E2E: real controller + real policy vs REAL gateway $GATEWAY_ENDPOINT ==="
set +e
client_exec "$E2E_BIN" -mode=client \
	-gateway-endpoint="$GATEWAY_ENDPOINT" \
	-gateway-pubkey="$GATEWAY_PUBKEY" \
	-client-private-key="$client_private_b64" \
	-psk="$psk_b64" \
	-inner-pool="$INNER_POOL" \
	-allowed-ip="$TUNNEL_ROUTE" \
	-verification-route="$TUNNEL_ROUTE" \
	-listen-port-min=41020 \
	-listen-port-max=41022 \
	-dns-resolver="$DNS_RESOLVER" \
	-expected-dns-answer="$EXPECTED_DNS_ANSWER" \
	-canary-endpoint="$CANARY_ENDPOINT" \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$UNDERLAY_MARK" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary="$RESOLVECTL_BIN" \
	-temp-root="$private_directory" \
	-hold-seconds=2
client_status=$?
set -e
if [ -n "$TCPDUMP_PID" ]; then
	kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
	wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
fi
echo "=== DIAGNOSTIC: tcpdump on client veth, udp port 51820 ==="
cat "$private_directory/client-veth-tcpdump.log" 2>&1 || echo "(no capture)"

if [ "$client_status" -ne 0 ]; then
	echo "CLIENT E2E FAILED (exit $client_status)" >&2
	client_exec "$NFT_BIN" list ruleset 2>&1 || true
	exit 1
fi
echo "=== CLIENT E2E SUCCEEDED against real cloud gateway ==="

# The table itself is deliberately reused across candidates/attempts --
# only Release() (never called by this single-attempt test) tears it down
# fully. The correct per-attempt check is that THIS interface's own
# elements are gone from tunnel_ifaces, not that the table vanished.
if client_exec "$NFT_BIN" list set inet "$TABLE_NAME" tunnel_ifaces 2>&1 |
	grep -q "winn[0-9a-f]"; then
	echo "TEARDOWN FAILURE: a tunnel interface is still admitted in tunnel_ifaces" >&2
	client_exec "$NFT_BIN" list table inet "$TABLE_NAME" >&2
	exit 1
fi
echo "TEARDOWN_OK: candidate interface removed from tunnel_ifaces after Close"

cleanup
trap - EXIT HUP INT TERM

echo "=== SAFETY CHECK: confirming SSH-carrying route still intact after cleanup ==="
"$IP_BIN" route show default
echo "PASS: real AWG handshake + real nftables kill-switch + real DNS/canary verification, against a real internet cloud gateway, clean teardown"
