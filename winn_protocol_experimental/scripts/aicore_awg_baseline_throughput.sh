#!/bin/sh
set -eu

# Raw AmneziaWG baseline throughput (no Winn wrapping, no candidate-isolated
# controller, no kill switch) against the same real gateway, for Phase 1's
# throughput-vs-baseline comparison. Safe in AICORE's root namespace: this
# creates one disposable AWG interface (no route/nftables/DNS changes
# touching the host's own default path) and tears it down completely,
# matching the already-proven pattern from this session's raw sanity
# checks.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IPERF3_BIN=${IPERF3_BIN:-/usr/bin/iperf3}
TIMEOUT_BIN=${TIMEOUT_BIN:-/usr/bin/timeout}
IFACE=${IFACE:-winnbaseline0}
CLIENT_INNER_IP=${CLIENT_INNER_IP:-10.203.1.20}

CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}
GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT:?must set GATEWAY_ENDPOINT}
GATEWAY_PUBKEY=${GATEWAY_PUBKEY:?must set GATEWAY_PUBKEY}
GATEWAY_INNER_IP=${GATEWAY_INNER_IP:-10.203.1.1}
IPERF_SECONDS=${IPERF_SECONDS:-8}
IPERF_OMIT_SECONDS=${IPERF_OMIT_SECONDS:-3}
IPERF_STREAMS=${IPERF_STREAMS:-4}
IPERF_JSON_OUT=${IPERF_JSON_OUT:-}

for executable in "$AWG_BIN" "$AWG_ENGINE" "$IPERF3_BIN" "$TIMEOUT_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
if ip link show dev "$IFACE" >/dev/null 2>&1; then
	echo "refusing to reuse existing interface: $IFACE" >&2
	exit 1
fi

echo "=== SAFETY CHECK: SSH-carrying route before any change ==="
ip route show default

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-awg-baseline.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077
ENGINE_PID=""
IPERF_JSON_TEMP=""

cleanup() {
	if [ -n "$ENGINE_PID" ]; then
		kill "$ENGINE_PID" >/dev/null 2>&1 || true
		wait "$ENGINE_PID" >/dev/null 2>&1 || true
	fi
	ip link del dev "$IFACE" >/dev/null 2>&1 || true
	find "$private_directory" -type f -delete >/dev/null 2>&1 || true
	rmdir "$private_directory" >/dev/null 2>&1 || true
	if [ -n "$IPERF_JSON_TEMP" ] && [ -f "$IPERF_JSON_TEMP" ]; then
		unlink "$IPERF_JSON_TEMP" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT HUP INT TERM

"$AWG_ENGINE" -f "$IFACE" >"$private_directory/daemon.log" 2>&1 &
ENGINE_PID=$!
attempt=0
while ! ip link show dev "$IFACE" >/dev/null 2>&1; do
	if ! kill -0 "$ENGINE_PID" >/dev/null 2>&1; then
		echo "baseline AWG engine exited before its interface appeared" >&2
		cat "$private_directory/daemon.log" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 100 ]; then
		echo "baseline AWG interface never appeared" >&2
		exit 1
	fi
	sleep 0.05
done

"$AWG_BIN" set "$IFACE" \
	private-key "$CLIENT_PRIVATE_KEY_FILE" \
	jc 4 jmin 12 jmax 64 \
	s1 16 s2 80 s3 24 s4 8 \
	h1 111111 h2 222222 h3 333333 h4 444444 \
	peer "$GATEWAY_PUBKEY" \
	preshared-key "$PSK_FILE" \
	allowed-ips "${GATEWAY_INNER_IP}/32" \
	endpoint "$GATEWAY_ENDPOINT" \
	persistent-keepalive 5
ip address add "${CLIENT_INNER_IP}/30" dev "$IFACE"
ip link set dev "$IFACE" mtu 1280 up

sleep 1
if ! ping -c 2 -W 2 -I "$IFACE" "$GATEWAY_INNER_IP" >"$private_directory/ping.log" 2>&1; then
	echo "baseline handshake/ping failed" >&2
	cat "$private_directory/ping.log" >&2
	"$AWG_BIN" show "$IFACE" || true
	exit 1
fi
echo "baseline AWG handshake OK, running iperf3"

if ! "$TIMEOUT_BIN" "$((IPERF_OMIT_SECONDS + IPERF_SECONDS + 10))s" \
	"$IPERF3_BIN" -c "$GATEWAY_INNER_IP" -p 5201 \
	-O "$IPERF_OMIT_SECONDS" -t "$IPERF_SECONDS" -P "$IPERF_STREAMS" \
	--bind-dev "$IFACE" -J \
	>"$private_directory/iperf3.json" 2>"$private_directory/iperf3.err"; then
	echo "baseline iperf3 run failed" >&2
	cat "$private_directory/iperf3.err" >&2
	exit 1
fi
baseline_mbps=$(python3 -c "import json; d=json.load(open('$private_directory/iperf3.json')); print(d['end']['sum_sent']['bits_per_second']/1e6)")
echo "BASELINE_THROUGHPUT_MBPS=$baseline_mbps"
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
	cp "$private_directory/iperf3.json" "$IPERF_JSON_TEMP"
	chmod 0600 "$IPERF_JSON_TEMP"
	mv "$IPERF_JSON_TEMP" "$IPERF_JSON_OUT"
	IPERF_JSON_TEMP=""
	iperf_json_sha256=$(sha256sum "$IPERF_JSON_OUT" | awk '{ print $1 }')
	echo "THROUGHPUT_IPERF_JSON_SHA256=$iperf_json_sha256"
fi
echo "THROUGHPUT_ROLE=baseline"
echo "THROUGHPUT_PATH=raw-awg"
echo "THROUGHPUT_GATEWAY_ENDPOINT=$GATEWAY_ENDPOINT"
echo "THROUGHPUT_GATEWAY_INNER_IP=$GATEWAY_INNER_IP"

cleanup
trap - EXIT HUP INT TERM
echo "=== SAFETY CHECK: SSH-carrying route after cleanup ==="
ip route show default
echo "PASS: raw AWG baseline throughput measured, clean teardown"
