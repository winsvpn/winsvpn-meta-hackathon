#!/bin/sh
set -eu

# Privileged, namespace-isolated E2E test for the real internal/directawg
# Linux controller and nftables policy factory together — not just raw AWG
# (see scripts/aicore_awg_e2e.sh for that), and never against fakes. Every
# nft/ip/resolvectl/awg command this script or the E2E binary issues operates
# inside a disposable network namespace created below; nothing here ever
# targets the host's root namespace or its default route/nftables/SSH path.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
RESOLVECTL_BIN=${RESOLVECTL_BIN:-/usr/bin/resolvectl}
PING_BIN=${PING_BIN:-/bin/ping}
E2E_BIN=${E2E_BIN:-/opt/winn-lab/bin/winn-aicore-directawg-e2e}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winnpcns}
SERVER_NAMESPACE=${SERVER_NAMESPACE:-winnpsns}
CLIENT_VETH=${CLIENT_VETH:-winnpcv0}
SERVER_VETH=${SERVER_VETH:-winnpsv0}
SERVER_AWG_IFACE=${SERVER_AWG_IFACE:-winnps0}
SERVER_AWG_PORT=${SERVER_AWG_PORT:-41003}
TABLE_NAME=${TABLE_NAME:-winnaicoree2e}
UNDERLAY_MARK=${UNDERLAY_MARK:-9977}
INITIAL_CLIENT_BLACKHOLE_MS=${INITIAL_CLIENT_BLACKHOLE_MS:-0}
CLIENT_HOLD_SECONDS=${CLIENT_HOLD_SECONDS:-2}

for numeric_value in "$INITIAL_CLIENT_BLACKHOLE_MS" "$CLIENT_HOLD_SECONDS"; do
	case "$numeric_value" in
	"" | *[!0-9]*)
		echo "blackhole milliseconds and hold seconds must be integers" >&2
		exit 1
		;;
	esac
done
if [ "$INITIAL_CLIENT_BLACKHOLE_MS" -gt 2000 ] ||
	[ "$CLIENT_HOLD_SECONDS" -gt 10 ]; then
	echo "blackhole milliseconds or hold seconds exceed test limits" >&2
	exit 1
fi

for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$NFT_BIN" \
	"$RESOLVECTL_BIN" "$PING_BIN" "$E2E_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
for namespace in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE"; do
	if "$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$namespace" >/dev/null 2>&1; then
		echo "refusing to reuse existing namespace: $namespace" >&2
		exit 1
	fi
done
for interface_name in "$CLIENT_VETH" "$SERVER_VETH"; do
	if "$IP_BIN" link show dev "$interface_name" >/dev/null 2>&1; then
		echo "refusing to reuse existing interface: $interface_name" >&2
		exit 1
	fi
done

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-directawg-policy-e2e.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

SERVER_PID=""
RESPONDER_PID=""
CLIENT_PID=""
TCPDUMP_PID=""
CLIENT_TCPDUMP_PID=""
BLACKHOLE_PID=""

cleanup() {
	for process_id in "$CLIENT_PID" "$RESPONDER_PID" "$SERVER_PID" \
		"$TCPDUMP_PID" "$CLIENT_TCPDUMP_PID" "$BLACKHOLE_PID"; do
		if [ -n "$process_id" ]; then
			kill "$process_id" >/dev/null 2>&1 || true
			wait "$process_id" >/dev/null 2>&1 || true
		fi
	done
	# Defense in depth: even with -f (foreground), explicitly match and kill
	# by this run's exact interface name in case anything still detached.
	pkill -f "amneziawg-go .*${SERVER_AWG_IFACE}\$" >/dev/null 2>&1 || true
	"$IP_BIN" netns del "$CLIENT_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" netns del "$SERVER_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$CLIENT_VETH" >/dev/null 2>&1 || true
	find "$private_directory" -type f -delete >/dev/null 2>&1 || true
	rmdir "$private_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }
server_exec() { "$IP_BIN" netns exec "$SERVER_NAMESPACE" "$@"; }

echo "=== BASELINE (root namespace, before test) ==="
"$NFT_BIN" list ruleset 2>&1 || echo "(empty ruleset)"
"$RESOLVECTL_BIN" status 2>&1 | head -8

"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" netns add "$SERVER_NAMESPACE"
"$IP_BIN" link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
client_exec "$IP_BIN" link set lo up
server_exec "$IP_BIN" link set lo up
client_exec "$IP_BIN" address add 172.31.206.1/30 dev "$CLIENT_VETH"
server_exec "$IP_BIN" address add 172.31.206.2/30 dev "$SERVER_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
server_exec "$IP_BIN" link set dev "$SERVER_VETH" up
# Force full, correct checksum computation instead of relying on veth's
# checksum-offload assumptions: verified separately that packets from a
# marked relay socket sharing a namespace with an active AmneziaWG interface
# arrive with an invalid UDP checksum (tcpdump -vv: "bad udp cksum") and are
# silently dropped by the receiving kernel before userspace ever sees them.
if command -v ethtool >/dev/null 2>&1; then
	client_exec ethtool -K "$CLIENT_VETH" tx off rx off >/dev/null 2>&1 || true
	server_exec ethtool -K "$SERVER_VETH" tx off rx off >/dev/null 2>&1 || true
fi
client_exec "$PING_BIN" -n -q -c 1 -W 1 -I "$CLIENT_VETH" 172.31.206.2 >/dev/null

"$AWG_BIN" genkey >"$private_directory/server-private"
"$AWG_BIN" pubkey <"$private_directory/server-private" \
	>"$private_directory/server-public"
"$AWG_BIN" genkey >"$private_directory/client-private"
"$AWG_BIN" pubkey <"$private_directory/client-private" \
	>"$private_directory/client-public"
"$AWG_BIN" genpsk >"$private_directory/psk"
server_public=$(tr -d '\r\n' <"$private_directory/server-public")
client_public=$(tr -d '\r\n' <"$private_directory/client-public")
client_private_b64=$(tr -d '\r\n' <"$private_directory/client-private")
psk_b64=$(tr -d '\r\n' <"$private_directory/psk")

# -f (foreground) is required: without it, amneziawg-go daemonizes and
# detaches, so killing this tracked PID alone would not actually stop it.
# Backgrounding "$IP_BIN netns exec ..." directly (not via the server_exec
# function) matters too: backgrounding a function call adds a subshell layer,
# so $! captures that wrapper's PID rather than the exec'd target's, and
# killing the wrapper alone leaves the real process running and orphaned.
"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$AWG_ENGINE" -f "$SERVER_AWG_IFACE" \
	>/dev/null &
SERVER_PID=$!
attempt=0
while ! server_exec "$IP_BIN" link show dev "$SERVER_AWG_IFACE" \
	>/dev/null 2>&1; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		echo "server AWG interface did not appear" >&2
		exit 1
	fi
	sleep 0.02
done
# No persistent-keepalive here either: this side must not send anything to
# the client until the client's own verification traffic initiates the
# handshake, so the client's Prepare() zero-baseline check is meaningful.
# jc/jmin/jmax/s1-s4/h1-h4 must match the client's AWGObfuscation values
# (cmd/winn-aicore-directawg-e2e/main.go) exactly: AmneziaWG's obfuscation
# scheme uses h1-h4 as shared magic header values both peers must agree on
# to recognize each other's junk/handshake packets, so a mismatch here — not
# a network problem — is why packets arrived (valid checksum, accepted by
# nftables) but the daemon never processed them as protocol traffic.
server_exec "$AWG_BIN" set "$SERVER_AWG_IFACE" \
	private-key "$private_directory/server-private" \
	listen-port "$SERVER_AWG_PORT" \
	jc 4 jmin 12 jmax 64 \
	s1 16 s2 80 s3 24 s4 8 \
	h1 111111 h2 222222 h3 333333 h4 444444 \
	peer "$client_public" \
	preshared-key "$private_directory/psk" \
	allowed-ips 10.204.1.0/24
server_exec "$IP_BIN" address add 10.204.0.2/24 dev "$SERVER_AWG_IFACE"
server_exec "$IP_BIN" link set dev "$SERVER_AWG_IFACE" mtu 1280 up

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$E2E_BIN" -mode=server \
	-dns-listen=10.204.0.2:5300 \
	-canary-listen=10.204.0.2:5301 \
	-answer-ip=203.0.113.55 \
	>"$private_directory/server-responders.log" 2>&1 &
RESPONDER_PID=$!
attempt=0
while ! grep -q READY "$private_directory/server-responders.log" \
	>/dev/null 2>&1; do
	if ! kill -0 "$RESPONDER_PID" >/dev/null 2>&1; then
		cat "$private_directory/server-responders.log" >&2
		echo "server responders exited before becoming ready" >&2
		exit 1
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		cat "$private_directory/server-responders.log" >&2
		echo "server responders did not become ready" >&2
		exit 1
	fi
	sleep 0.02
done

TCPDUMP_PID=""
CLIENT_TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
	# No protocol filter (catch anything at all, not just udp) and a longer
	# startup wait, to rule out a capture-readiness race rather than assume
	# one. Capturing on both sides of the veth pair narrows down whether a
	# packet ever actually leaves the client at all.
	"$IP_BIN" netns exec "$SERVER_NAMESPACE" tcpdump -i "$SERVER_VETH" -n -vv -c 40 \
		>"$private_directory/server-tcpdump.log" 2>&1 &
	TCPDUMP_PID=$!
	"$IP_BIN" netns exec "$CLIENT_NAMESPACE" tcpdump -i "$CLIENT_VETH" -n -vv -c 40 \
		>"$private_directory/client-tcpdump.log" 2>&1 &
	CLIENT_TCPDUMP_PID=$!
	sleep 2
fi

echo "=== RUNNING CLIENT E2E: real linuxController + real LinuxNftResolvedPolicyFactory ==="
if [ "$INITIAL_CLIENT_BLACKHOLE_MS" -gt 0 ]; then
	client_exec /usr/sbin/tc qdisc replace dev "$CLIENT_VETH" root netem loss 100%
	(
		sleep_seconds=$(
			awk -v delay="$INITIAL_CLIENT_BLACKHOLE_MS" \
				'BEGIN { printf "%.3f", delay / 1000 }'
		)
		sleep "$sleep_seconds"
		client_exec /usr/sbin/tc qdisc del dev "$CLIENT_VETH" root
	) &
	BLACKHOLE_PID=$!
fi
client_started_nanoseconds=$(date +%s%N)
set +e
client_exec "$E2E_BIN" -mode=client \
	-gateway-endpoint="172.31.206.2:$SERVER_AWG_PORT" \
	-gateway-pubkey="$server_public" \
	-client-private-key="$client_private_b64" \
	-psk="$psk_b64" \
	-inner-pool=10.204.1.0/24 \
	-allowed-ip=10.204.0.0/23 \
	-verification-route=10.204.0.0/24 \
	-listen-port-min=41010 \
	-listen-port-max=41012 \
	-dns-resolver=10.204.0.2:5300 \
	-expected-dns-answer=203.0.113.55 \
	-canary-endpoint=10.204.0.2:5301 \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$UNDERLAY_MARK" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary="$RESOLVECTL_BIN" \
	-temp-root="$private_directory" \
	-hold-seconds="$CLIENT_HOLD_SECONDS"
client_status=$?
set -e
client_elapsed_milliseconds=$(
	awk -v start="$client_started_nanoseconds" -v end="$(date +%s%N)" \
		'BEGIN { printf "%.3f", (end - start) / 1000000 }'
)
if [ -n "$BLACKHOLE_PID" ]; then
	wait "$BLACKHOLE_PID"
	BLACKHOLE_PID=""
fi
for pid in "$TCPDUMP_PID" "$CLIENT_TCPDUMP_PID"; do
	if [ -n "$pid" ]; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
	fi
done
TCPDUMP_PID=""
CLIENT_TCPDUMP_PID=""
echo "=== DIAGNOSTIC: tcpdump on client veth (no filter) ==="
cat "$private_directory/client-tcpdump.log" 2>&1 || echo "(no capture)"
echo "=== DIAGNOSTIC: tcpdump on server veth (no filter) ==="
cat "$private_directory/server-tcpdump.log" 2>&1 || echo "(no capture)"
echo "=== DIAGNOSTIC: server-side DNS/canary responder log ==="
cat "$private_directory/server-responders.log" 2>&1 || echo "(no log)"
if [ "$client_status" -ne 0 ]; then
	echo "CLIENT E2E FAILED (exit $client_status)" >&2
	exit 1
fi
if [ "$INITIAL_CLIENT_BLACKHOLE_MS" -gt 0 ] &&
	! awk -v elapsed="$client_elapsed_milliseconds" \
		'BEGIN { exit elapsed <= 3000 ? 0 : 1 }'; then
	echo "CLIENT E2E exceeded 3s after forced handshake loss: ${client_elapsed_milliseconds}ms" >&2
	exit 1
fi
echo "CLIENT_E2E_ELAPSED_MILLISECONDS=$client_elapsed_milliseconds"
echo "=== CLIENT E2E SUCCEEDED ==="

if client_exec "$NFT_BIN" list table inet "$TABLE_NAME" >/dev/null 2>&1; then
	echo "TEARDOWN FAILURE: nft table still exists after Close" >&2
	exit 1
fi
echo "TEARDOWN_OK: nft table removed after Close"
if client_exec "$IP_BIN" -o link show |
	grep -E '^[0-9]+: winn[0-9a-f]{10}[@:]' >/dev/null 2>&1; then
	echo "TEARDOWN FAILURE: an AWG interface is still present after Close" >&2
	client_exec "$IP_BIN" -o link show >&2
	exit 1
fi
echo "TEARDOWN_OK: no AWG interface remains"

cleanup
trap - EXIT HUP INT TERM

for namespace in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE"; do
	if "$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$namespace" >/dev/null 2>&1; then
		echo "namespace teardown failed: $namespace" >&2
		exit 1
	fi
done
echo "=== FINAL (root namespace, after test — compare to baseline) ==="
"$NFT_BIN" list ruleset 2>&1 || echo "(empty ruleset)"
"$RESOLVECTL_BIN" status 2>&1 | head -8
echo "PASS: real AWG handshake, real nftables kill-switch admission (fwmark fix), tunnel-only DNS+canary verification, and clean teardown"
