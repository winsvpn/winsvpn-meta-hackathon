#!/bin/sh
set -eu

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IP_BIN=${IP_BIN:-/usr/sbin/ip}
PING_BIN=${PING_BIN:-/usr/bin/ping}
CLIENT_INTERFACE=${CLIENT_INTERFACE:-winnc0}
SERVER_INTERFACE=${SERVER_INTERFACE:-winns0}
CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winncns}
SERVER_NAMESPACE=${SERVER_NAMESPACE:-winnsns}
CLIENT_VETH=${CLIENT_VETH:-winncv0}
SERVER_VETH=${SERVER_VETH:-winnsv0}
CLIENT_PORT=${CLIENT_PORT:-41001}
SERVER_PORT=${SERVER_PORT:-41002}

for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$PING_BIN"; do
	if [ ! -x "$executable" ]; then
		echo "required executable is missing: $executable" >&2
		exit 1
	fi
done
for identifier in \
	"$CLIENT_INTERFACE" "$SERVER_INTERFACE" \
	"$CLIENT_NAMESPACE" "$SERVER_NAMESPACE" \
	"$CLIENT_VETH" "$SERVER_VETH"; do
	case "$identifier" in
		"" | *[!A-Za-z0-9_.=-]*)
			echo "invalid test network identifier" >&2
			exit 1
			;;
	esac
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

private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-awg-e2e.XXXXXXXX")
chmod 0700 "$private_directory"
CLIENT_ENGINE_PID=""
SERVER_ENGINE_PID=""
cleanup() {
	for process_id in "$CLIENT_ENGINE_PID" "$SERVER_ENGINE_PID"; do
		if [ -n "$process_id" ]; then
			kill "$process_id" >/dev/null 2>&1 || true
			wait "$process_id" >/dev/null 2>&1 || true
		fi
	done
	"$IP_BIN" netns del "$CLIENT_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" netns del "$SERVER_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$CLIENT_VETH" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$SERVER_VETH" >/dev/null 2>&1 || true
	find "$private_directory" -type f -delete
	rmdir "$private_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
umask 077

client_exec() {
	"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"
}
server_exec() {
	"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$@"
}

"$AWG_BIN" genkey >"$private_directory/client-private"
"$AWG_BIN" pubkey \
	<"$private_directory/client-private" \
	>"$private_directory/client-public"
"$AWG_BIN" genkey >"$private_directory/server-private"
"$AWG_BIN" pubkey \
	<"$private_directory/server-private" \
	>"$private_directory/server-public"
"$AWG_BIN" genpsk >"$private_directory/preshared-key"

"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" netns add "$SERVER_NAMESPACE"
"$IP_BIN" link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
client_exec "$IP_BIN" link set lo up
server_exec "$IP_BIN" link set lo up
client_exec "$IP_BIN" address add 172.31.203.1/30 dev "$CLIENT_VETH"
server_exec "$IP_BIN" address add 172.31.203.2/30 dev "$SERVER_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
server_exec "$IP_BIN" link set dev "$SERVER_VETH" up
client_exec "$PING_BIN" -n -q -I "$CLIENT_VETH" -c 1 -W 1 172.31.203.2

# -f (foreground) is required: without it, amneziawg-go daemonizes and
# detaches from this script's process tree entirely, so cleanup's PID-based
# kill (and formerly, relying on namespace deletion alone) cannot actually
# stop it. Backgrounding "$IP_BIN netns exec ..." directly, rather than
# through the client_exec/server_exec function wrappers, matters too:
# backgrounding a function call adds a subshell layer, so $! would capture
# that wrapper's PID rather than the exec'd engine's.
"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$AWG_ENGINE" -f "$CLIENT_INTERFACE" \
	>/dev/null &
CLIENT_ENGINE_PID=$!
"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$AWG_ENGINE" -f "$SERVER_INTERFACE" \
	>/dev/null &
SERVER_ENGINE_PID=$!
for namespace_interface in \
	"$CLIENT_NAMESPACE:$CLIENT_INTERFACE" \
	"$SERVER_NAMESPACE:$SERVER_INTERFACE"; do
	namespace=${namespace_interface%%:*}
	interface_name=${namespace_interface#*:}
	attempt=0
	while ! "$IP_BIN" -n "$namespace" link show dev "$interface_name" \
		>/dev/null 2>&1; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 100 ]; then
			echo "AWG interface did not appear: $interface_name" >&2
			exit 1
		fi
		sleep 0.02
	done
done

client_public=$(tr -d '\r\n' <"$private_directory/client-public")
server_public=$(tr -d '\r\n' <"$private_directory/server-public")
client_exec "$AWG_BIN" set "$CLIENT_INTERFACE" \
	private-key "$private_directory/client-private" \
	listen-port "$CLIENT_PORT" \
	peer "$server_public" \
	preshared-key "$private_directory/preshared-key" \
	allowed-ips 10.203.0.2/32 \
	endpoint "172.31.203.2:$SERVER_PORT" \
	persistent-keepalive 1
server_exec "$AWG_BIN" set "$SERVER_INTERFACE" \
	private-key "$private_directory/server-private" \
	listen-port "$SERVER_PORT" \
	peer "$client_public" \
	preshared-key "$private_directory/preshared-key" \
	allowed-ips 10.203.0.1/32 \
	endpoint "172.31.203.1:$CLIENT_PORT" \
	persistent-keepalive 1

client_exec "$IP_BIN" address add 10.203.0.1/30 dev "$CLIENT_INTERFACE"
server_exec "$IP_BIN" address add 10.203.0.2/30 dev "$SERVER_INTERFACE"
client_exec "$IP_BIN" link set dev "$CLIENT_INTERFACE" mtu 1280 up
server_exec "$IP_BIN" link set dev "$SERVER_INTERFACE" mtu 1280 up

client_exec "$PING_BIN" -n -q -I "$CLIENT_INTERFACE" -c 3 -W 1 10.203.0.2
server_exec "$PING_BIN" -n -q -I "$SERVER_INTERFACE" -c 3 -W 1 10.203.0.1

client_handshake=$(
	client_exec "$AWG_BIN" show "$CLIENT_INTERFACE" latest-handshakes |
		awk -v peer="$server_public" '$1 == peer { print $2 }'
)
server_handshake=$(
	server_exec "$AWG_BIN" show "$SERVER_INTERFACE" latest-handshakes |
		awk -v peer="$client_public" '$1 == peer { print $2 }'
)
client_transfer=$(
	client_exec "$AWG_BIN" show "$CLIENT_INTERFACE" transfer |
		awk -v peer="$server_public" '$1 == peer { print $2 " " $3 }'
)
server_transfer=$(
	server_exec "$AWG_BIN" show "$SERVER_INTERFACE" transfer |
		awk -v peer="$client_public" '$1 == peer { print $2 " " $3 }'
)
case "$client_handshake:$server_handshake:$client_transfer:$server_transfer" in
	0:* | *:0:* | *" 0:"* | *" 0" | *:"0 "*)
		echo "AWG handshake or bidirectional counters did not advance" >&2
		exit 1
		;;
esac

cleanup
trap - EXIT HUP INT TERM
for namespace in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE"; do
	if "$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$namespace" >/dev/null 2>&1; then
		echo "AWG namespace teardown failed: $namespace" >&2
		exit 1
	fi
done
echo "PASS: real AWG handshake, bidirectional tunnel, status, and teardown"
