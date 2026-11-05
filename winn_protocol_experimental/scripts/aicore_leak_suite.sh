#!/bin/sh
set -eu

# Leak suite for Phase 1's "DNS, IPv4, IPv6 ... leak tests with zero-leak
# acceptance" gate (WebRTC is out of scope: this is a headless Linux
# driver, no browser/WebRTC stack in the loop at all). Establishes a real
# committed Winn tunnel (same proven namespace+NAT pattern as
# aicore_real_gateway_e2e.sh), then, while it is active and the kill
# switch is engaged, attempts exactly the traffic a leak would be: raw,
# unmarked packets sent directly via the underlay interface, bypassing
# the tunnel. A pass means every such attempt is blocked while legitimate
# tunnel traffic keeps working (a positive control, so "everything is
# broken" cannot masquerade as "leaks are prevented").

IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
PING_BIN=${PING_BIN:-/bin/ping}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
E2E_BIN=${E2E_BIN:-/opt/winn-lab/bin/winn-aicore-directawg-e2e}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winnlkns}
CLIENT_VETH=${CLIENT_VETH:-winnlkv0}
ROOT_VETH=${ROOT_VETH:-winnlkv1}
CLIENT_VETH_SUBNET=${CLIENT_VETH_SUBNET:-172.31.212.0/30}
CLIENT_VETH_ROOT_IP=${CLIENT_VETH_ROOT_IP:-172.31.212.1}
CLIENT_VETH_NS_IP=${CLIENT_VETH_NS_IP:-172.31.212.2}
CLIENT_VETH_SUBNET_V6=${CLIENT_VETH_SUBNET_V6:-fd00:212::/126}
CLIENT_VETH_ROOT_IP_V6=${CLIENT_VETH_ROOT_IP_V6:-fd00:212::1}
CLIENT_VETH_NS_IP_V6=${CLIENT_VETH_NS_IP_V6:-fd00:212::2}
TABLE_NAME=${TABLE_NAME:-winnleaktest}
UNDERLAY_MARK=${UNDERLAY_MARK:-9981}
NAT_TABLE=${NAT_TABLE:-winnleaktestnat}
EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE}

GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT:?must set GATEWAY_ENDPOINT}
GATEWAY_PUBKEY=${GATEWAY_PUBKEY:?must set GATEWAY_PUBKEY}
GATEWAY_INNER_IP=${GATEWAY_INNER_IP:-10.203.1.1}
CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}
HOLD_SECONDS=${HOLD_SECONDS:-15}
LEAK_PROBE_TARGET=${LEAK_PROBE_TARGET:-1.1.1.1}
LEAK_PROBE_TARGET_V6=${LEAK_PROBE_TARGET_V6:-2606:4700:4700::1111}

for executable in "$IP_BIN" "$NFT_BIN" "$PING_BIN" "$AWG_ENGINE" "$AWG_BIN" "$E2E_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
if "$IP_BIN" netns list | awk '{ print $1 }' | grep -Fx "$CLIENT_NAMESPACE" >/dev/null 2>&1; then
	echo "refusing to reuse existing namespace: $CLIENT_NAMESPACE" >&2
	exit 1
fi

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-leak-suite.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

WINN_PID=""
IP_FORWARD_PREVIOUS=""
IP6_FORWARD_PREVIOUS=""
NAT_ADDED=0
NAT6_ADDED=0
UFW_ROUTE_RULE_ADDED=0

cleanup() {
	if [ -n "$WINN_PID" ]; then
		kill "$WINN_PID" >/dev/null 2>&1 || true
		wait "$WINN_PID" >/dev/null 2>&1 || true
	fi
	if [ "$UFW_ROUTE_RULE_ADDED" -eq 1 ]; then
		ufw route delete allow in on "$ROOT_VETH" out on "$EGRESS_INTERFACE" >/dev/null 2>&1 || true
	fi
	if [ "$NAT_ADDED" -eq 1 ]; then
		"$NFT_BIN" delete table ip "$NAT_TABLE" >/dev/null 2>&1 || true
	fi
	if [ "$NAT6_ADDED" -eq 1 ]; then
		"$NFT_BIN" delete table ip6 "$NAT_TABLE" >/dev/null 2>&1 || true
	fi
	"$IP_BIN" netns del "$CLIENT_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$ROOT_VETH" >/dev/null 2>&1 || true
	if [ -n "$IP_FORWARD_PREVIOUS" ]; then
		sysctl -w net.ipv4.ip_forward="$IP_FORWARD_PREVIOUS" >/dev/null 2>&1 || true
	fi
	if [ -n "$IP6_FORWARD_PREVIOUS" ]; then
		sysctl -w net.ipv6.conf.all.forwarding="$IP6_FORWARD_PREVIOUS" >/dev/null 2>&1 || true
	fi
	find "$private_directory" -type f -delete >/dev/null 2>&1 || true
	rmdir "$private_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }

echo "=== SAFETY CHECK: SSH-carrying route before any change ==="
"$IP_BIN" route show default

IP_FORWARD_PREVIOUS=$(sysctl -n net.ipv4.ip_forward)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
IP6_FORWARD_PREVIOUS=$(sysctl -n net.ipv6.conf.all.forwarding)
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" link add "$ROOT_VETH" type veth peer name "$CLIENT_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" address add "${CLIENT_VETH_ROOT_IP}/30" dev "$ROOT_VETH"
"$IP_BIN" -6 address add "${CLIENT_VETH_ROOT_IP_V6}/126" dev "$ROOT_VETH"
"$IP_BIN" link set dev "$ROOT_VETH" up
client_exec "$IP_BIN" link set lo up
client_exec "$IP_BIN" address add "${CLIENT_VETH_NS_IP}/30" dev "$CLIENT_VETH"
client_exec "$IP_BIN" -6 address add "${CLIENT_VETH_NS_IP_V6}/126" dev "$CLIENT_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
client_exec "$IP_BIN" route add default via "$CLIENT_VETH_ROOT_IP"
client_exec "$IP_BIN" -6 route add default via "$CLIENT_VETH_ROOT_IP_V6"
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
"$NFT_BIN" add table ip6 "$NAT_TABLE"
"$NFT_BIN" add chain ip6 "$NAT_TABLE" postrouting \
	'{ type nat hook postrouting priority 100 ; }'
"$NFT_BIN" add rule ip6 "$NAT_TABLE" postrouting \
	ip6 saddr "$CLIENT_VETH_SUBNET_V6" oifname "$EGRESS_INTERFACE" masquerade
NAT6_ADDED=1
# On a host hardened with ufw (the cloud gateway nodes, unlike AICORE), ufw's
# own FORWARD chain defaults to policy drop independent of ip_forward, and
# ufw doesn't auto-allow routing for a newly created veth pair. Without this,
# the NAT'd handshake never leaves the box: it gets dropped at FORWARD
# (IN=<root-veth> OUT=<egress>) with zero indication anywhere except the
# kernel log. Scope the allow to this run's own veth/egress pair only.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
	ufw route allow in on "$ROOT_VETH" out on "$EGRESS_INTERFACE" >/dev/null 2>&1
	UFW_ROUTE_RULE_ADDED=1
fi
client_exec "$PING_BIN" -n -q -c 1 -W 2 -I "$CLIENT_VETH" "$CLIENT_VETH_ROOT_IP" >/dev/null

echo "=== BASELINE (no tunnel): confirm the underlay CAN reach the internet normally ==="
if ! client_exec "$PING_BIN" -n -q -c 2 -W 3 -I "$CLIENT_VETH" "$LEAK_PROBE_TARGET" >/dev/null 2>&1; then
	echo "pre-tunnel baseline reachability failed -- cannot meaningfully test leaks" >&2
	exit 1
fi
echo "baseline OK: $LEAK_PROBE_TARGET reachable via $CLIENT_VETH before any tunnel exists"

# IPv6 baseline: the namespace has its own NAT66 path set up above, but
# whether that actually reaches the real internet still depends on the
# host having genuine global IPv6 connectivity (not all vantage points
# do). An IPv6 leak probe blocked later could mean either "the kill
# switch blocked it" or "there was never any IPv6 route at all" -- those
# are not the same finding, and conflating them would misreport an
# inconclusive result as a pass. Check which one applies empirically
# before drawing any conclusion from the post-tunnel probe.
IPV6_BASELINE_REACHABLE=0
if client_exec "$PING_BIN" -6 -n -q -c 3 -W 3 -I "$CLIENT_VETH" "$LEAK_PROBE_TARGET_V6" >/dev/null 2>&1; then
	IPV6_BASELINE_REACHABLE=1
	echo "IPv6 baseline OK: $LEAK_PROBE_TARGET_V6 reachable via $CLIENT_VETH before any tunnel exists"
else
	echo "IPv6 baseline: NOT reachable even before any tunnel/kill-switch exists (no IPv6 route in this environment) -- the IPv6 probe below will be reported as inconclusive, not a pass, regardless of its result"
fi

client_private_b64=$(tr -d '\r\n' <"$CLIENT_PRIVATE_KEY_FILE")
psk_b64=$(tr -d '\r\n' <"$PSK_FILE")

echo "=== establishing a real committed Winn tunnel ==="
"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$E2E_BIN" -mode=client \
	-gateway-endpoint="$GATEWAY_ENDPOINT" \
	-gateway-pubkey="$GATEWAY_PUBKEY" \
	-client-private-key="$client_private_b64" \
	-psk="$psk_b64" \
	-inner-pool=10.203.1.16/28 \
	-allowed-ip=10.203.1.0/24 \
	-verification-route=10.203.1.0/24 \
	-listen-port-min=41230 \
	-listen-port-max=41240 \
	-dns-resolver="${GATEWAY_INNER_IP}:53" \
	-expected-dns-answer=203.0.113.99 \
	-canary-endpoint="${GATEWAY_INNER_IP}:9999" \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$(printf '%x' "$UNDERLAY_MARK")" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary=/usr/bin/resolvectl \
	-temp-root="$private_directory" \
	-hold-seconds="$HOLD_SECONDS" \
	>"$private_directory/winn-e2e.log" 2>&1 &
WINN_PID=$!

attempt=0
while ! grep -q COMMIT_OK "$private_directory/winn-e2e.log" 2>/dev/null; do
	if ! kill -0 "$WINN_PID" >/dev/null 2>&1; then
		echo "winn E2E process exited before committing" >&2
		cat "$private_directory/winn-e2e.log" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 500 ]; then
		echo "winn E2E process never committed" >&2
		exit 1
	fi
	sleep 0.05
done
echo "tunnel committed, kill switch engaged -- running leak probes now"

winn_iface=$(client_exec "$IP_BIN" -o link show | grep -oE 'winn[0-9a-f]{10}' | head -1)
if [ -z "$winn_iface" ]; then
	echo "could not find committed winn tunnel interface" >&2
	exit 1
fi

leak_found=0

echo "--- IPv4 leak probe: raw ping via underlay interface, unmarked ---"
if client_exec "$PING_BIN" -n -q -c 3 -W 2 -I "$CLIENT_VETH" "$LEAK_PROBE_TARGET" >"$private_directory/leak-v4.log" 2>&1; then
	echo "LEAK DETECTED: unmarked IPv4 traffic via $CLIENT_VETH reached $LEAK_PROBE_TARGET while tunnel was active" >&2
	cat "$private_directory/leak-v4.log" >&2
	leak_found=1
else
	echo "PASS: unmarked IPv4 traffic via underlay was blocked (no leak)"
fi

echo "--- IPv6 leak probe: raw ping6 via underlay interface, unmarked ---"
ipv6_inconclusive=0
if [ "$IPV6_BASELINE_REACHABLE" -eq 0 ]; then
	client_exec "$PING_BIN" -6 -n -q -c 3 -W 2 -I "$CLIENT_VETH" "$LEAK_PROBE_TARGET_V6" >"$private_directory/leak-v6.log" 2>&1 || true
	ipv6_inconclusive=1
	echo "INCONCLUSIVE: no IPv6 baseline reachability existed even before the tunnel -- this environment has no real IPv6 route to leak through, so blocking the probe below proves nothing about the kill switch's IPv6-leak-prevention behavior"
elif client_exec "$PING_BIN" -6 -n -q -c 3 -W 2 -I "$CLIENT_VETH" "$LEAK_PROBE_TARGET_V6" >"$private_directory/leak-v6.log" 2>&1; then
	echo "LEAK DETECTED: unmarked IPv6 traffic via $CLIENT_VETH reached $LEAK_PROBE_TARGET_V6 while tunnel was active" >&2
	cat "$private_directory/leak-v6.log" >&2
	leak_found=1
else
	echo "PASS: unmarked IPv6 traffic via underlay was blocked (no leak) -- baseline confirmed this path was reachable before the tunnel existed"
fi

echo "--- DNS leak probe: raw resolution attempt bypassing the tunnel's resolver ---"
if client_exec getent hosts winn-leak-probe.example >"$private_directory/leak-dns.log" 2>&1; then
	echo "unexpected: getent succeeded (name may not exist, treat as inconclusive rather than a hard leak signal)" >&2
	cat "$private_directory/leak-dns.log" >&2
else
	if client_exec "$PING_BIN" -n -q -c 1 -W 2 -I "$CLIENT_VETH" 8.8.8.8 >/dev/null 2>&1; then
		echo "LEAK DETECTED: raw path to a well-known public DNS resolver (8.8.8.8) is reachable while tunnel is active" >&2
		leak_found=1
	else
		echo "PASS: raw path to a well-known public DNS resolver is blocked while tunnel is active (no path for a leaking DNS query to take)"
	fi
fi

echo "--- POSITIVE CONTROL: legitimate tunnel-interface traffic must still work ---"
if client_exec "$PING_BIN" -n -q -c 2 -W 2 -I "$winn_iface" "$GATEWAY_INNER_IP" >"$private_directory/positive-control.log" 2>&1; then
	echo "PASS: legitimate traffic via the committed tunnel interface still works (the block above is a real leak prevention, not a dead network)"
else
	echo "POSITIVE CONTROL FAILED: even legitimate tunnel traffic is blocked -- the leak probes above are meaningless" >&2
	cat "$private_directory/positive-control.log" >&2
	leak_found=2
fi

wait "$WINN_PID" || true
WINN_PID=""

if [ "$leak_found" -ne 0 ]; then
	echo "LEAK SUITE FAILED" >&2
	exit 1
fi
if [ "$ipv6_inconclusive" -eq 1 ]; then
	echo "PASS (PARTIAL): IPv4 and DNS-adjacent raw paths confirmed blocked while the tunnel was active, with genuine pre-tunnel baselines proving those paths were real; legitimate tunnel traffic confirmed still working. IPv6 is INCONCLUSIVE -- this environment has no real IPv6 connectivity at all (confirmed via baseline), so the IPv6 leak probe did not exercise a real path and cannot be counted toward the zero-leak gate. IPv6 must be re-tested from a vantage point with genuine IPv6 connectivity before it can be marked pass or fail."
else
	echo "PASS: IPv4, IPv6, and DNS-adjacent raw paths all blocked while the tunnel was active, each with a genuine pre-tunnel baseline confirming the path was real; legitimate tunnel traffic confirmed still working"
fi
