#!/bin/sh
set -eu

# Privileged AICORE proof for DirectAWG's contextual teardown contract.
# All VPN nftables, rules, routes, interfaces, and processes live inside two
# disposable namespaces. This script never installs a root-namespace kill
# switch, changes the root default route, or adds root NAT.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
RESOLVECTL_BIN=${RESOLVECTL_BIN:-/usr/bin/resolvectl}
PING_BIN=${PING_BIN:-/bin/ping}
E2E_BIN=${E2E_BIN:-/opt/winn-lab/bin/winn-teardown-e2e}

CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-winntcns}
SERVER_NAMESPACE=${SERVER_NAMESPACE:-winntsns}
CLIENT_VETH=${CLIENT_VETH:-winntcv0}
SERVER_VETH=${SERVER_VETH:-winntsv0}
SERVER_AWG_IFACE=${SERVER_AWG_IFACE:-winnts0}
SERVER_AWG_PORT=${SERVER_AWG_PORT:-41303}
TABLE_PREFIX=${TABLE_PREFIX:-winntd}
UNDERLAY_MARK=${UNDERLAY_MARK:-997a}
STOP_TIMEOUT=${STOP_TIMEOUT:-650ms}
ALLOW_KERNEL_PAYLOAD_LIMITATION=${ALLOW_KERNEL_PAYLOAD_LIMITATION:-0}
EXPECTED_SOURCE_DIGEST=${EXPECTED_SOURCE_DIGEST:?set the exact embedded source-tree digest}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/opt/winn-lab/evidence}
RUN_ID=${RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')-$$}
EVIDENCE_DIR=${EVIDENCE_DIR:-"$EVIDENCE_ROOT/teardown-fault-$RUN_ID"}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if [ "$(id -u)" -ne 0 ]; then
	fail "run as root on the disposable AICORE lab host"
fi
case "$EXPECTED_SOURCE_DIGEST" in
	*[!0-9a-f]* | "")
		fail "EXPECTED_SOURCE_DIGEST must be lowercase hexadecimal"
		;;
esac
if [ "${#EXPECTED_SOURCE_DIGEST}" -ne 64 ]; then
	fail "EXPECTED_SOURCE_DIGEST must be exactly 64 hexadecimal characters"
fi
for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$NFT_BIN" \
	"$RESOLVECTL_BIN" "$PING_BIN" "$E2E_BIN"; do
	if [ ! -x "$executable" ]; then
		fail "required executable is missing: $executable"
	fi
done
for identifier in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE" "$CLIENT_VETH" \
	"$SERVER_VETH" "$SERVER_AWG_IFACE" "$TABLE_PREFIX"; do
	case "$identifier" in
	"" | *[!A-Za-z0-9_.-]*)
		fail "invalid scoped identifier: $identifier"
		;;
	esac
done
for namespace in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE"; do
	if "$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$namespace" >/dev/null 2>&1; then
		fail "refusing to reuse existing namespace: $namespace"
	fi
done
for interface_name in "$CLIENT_VETH" "$SERVER_VETH"; do
	if "$IP_BIN" link show dev "$interface_name" >/dev/null 2>&1; then
		fail "refusing to reuse existing root interface: $interface_name"
	fi
done
if "$NFT_BIN" list tables 2>/dev/null |
	awk '{ print $3 }' | grep -E "^${TABLE_PREFIX}[123]$" >/dev/null 2>&1; then
	fail "refusing to run while a scoped test nft table already exists in root"
fi
embedded_digest=$("$E2E_BIN" -print-source-digest)
if [ "$embedded_digest" != "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "binary source digest mismatch: embedded=$embedded_digest expected=$EXPECTED_SOURCE_DIGEST"
fi
if [ -e "$EVIDENCE_DIR" ]; then
	fail "refusing to overwrite evidence directory: $EVIDENCE_DIR"
fi
mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-teardown-fault.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077

SERVER_ENGINE_PID=""
RESPONDER_PID=""

namespace_kill_all() {
	namespace_kill_name=$1
	if ! "$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$namespace_kill_name" >/dev/null 2>&1; then
		return
	fi
	for namespace_kill_pid in $("$IP_BIN" netns pids "$namespace_kill_name" 2>/dev/null || true); do
		kill "$namespace_kill_pid" >/dev/null 2>&1 || true
	done
	for namespace_kill_pid in $("$IP_BIN" netns pids "$namespace_kill_name" 2>/dev/null || true); do
		kill -KILL "$namespace_kill_pid" >/dev/null 2>&1 || true
	done
}

cleanup() {
	for cleanup_pid in "$RESPONDER_PID" "$SERVER_ENGINE_PID"; do
		if [ -n "$cleanup_pid" ]; then
			kill "$cleanup_pid" >/dev/null 2>&1 || true
			wait "$cleanup_pid" >/dev/null 2>&1 || true
		fi
	done
	namespace_kill_all "$CLIENT_NAMESPACE"
	namespace_kill_all "$SERVER_NAMESPACE"
	"$IP_BIN" netns del "$CLIENT_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" netns del "$SERVER_NAMESPACE" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$CLIENT_VETH" >/dev/null 2>&1 || true
	"$IP_BIN" link del dev "$SERVER_VETH" >/dev/null 2>&1 || true
	find "$private_directory" -type f -delete >/dev/null 2>&1 || true
	rmdir "$private_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

client_exec() { "$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"; }
server_exec() { "$IP_BIN" netns exec "$SERVER_NAMESPACE" "$@"; }

capture_root() {
	capture_root_destination=$1
	{
		echo "=== default-route ==="
		"$IP_BIN" route show default
		echo "=== rules-v4 ==="
		"$IP_BIN" -4 rule show
		echo "=== routes-v4 ==="
		"$IP_BIN" -4 route show table all
		echo "=== nftables ==="
		"$NFT_BIN" list ruleset
	} >"$capture_root_destination"
}

capture_root "$EVIDENCE_DIR/root-before.txt"
"$IP_BIN" netns list >"$EVIDENCE_DIR/netns-before.txt"
"$E2E_BIN" -print-source-digest >"$EVIDENCE_DIR/embedded-source-digest.txt"
sha256sum "$E2E_BIN" >"$EVIDENCE_DIR/e2e-binary.sha256"
if [ -n "$SOURCE_MANIFEST" ]; then
	if [ ! -f "$SOURCE_MANIFEST" ]; then
		fail "SOURCE_MANIFEST does not exist: $SOURCE_MANIFEST"
	fi
	cp "$SOURCE_MANIFEST" "$EVIDENCE_DIR/source-manifest.sha256"
fi
{
	echo "schema=winn-teardown-fault-e2e/v1"
	echo "captured_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "hostname=$(hostname)"
	echo "kernel=$(uname -srmo)"
	echo "source_digest=$EXPECTED_SOURCE_DIGEST"
	echo "client_namespace=$CLIENT_NAMESPACE"
	echo "server_namespace=$SERVER_NAMESPACE"
	echo "client_veth=$CLIENT_VETH"
	echo "server_veth=$SERVER_VETH"
	echo "server_awg_interface=$SERVER_AWG_IFACE"
	echo "table_prefix=$TABLE_PREFIX"
	echo "stop_timeout=$STOP_TIMEOUT"
	echo "allow_kernel_payload_limitation=$ALLOW_KERNEL_PAYLOAD_LIMITATION"
	echo "root_kill_switch_mutated=false"
	echo "root_routes_mutated=false"
	echo "root_nat_mutated=false"
	echo "resolvectl_scope=recorded-only"
	echo "resolvectl_limitation=systemd-resolved cannot address a link index in another network namespace"
} >"$EVIDENCE_DIR/environment.txt"

"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" netns add "$SERVER_NAMESPACE"
"$IP_BIN" link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
client_exec "$IP_BIN" link set lo up
server_exec "$IP_BIN" link set lo up
client_exec "$IP_BIN" address add 172.31.216.1/30 dev "$CLIENT_VETH"
server_exec "$IP_BIN" address add 172.31.216.2/30 dev "$SERVER_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
server_exec "$IP_BIN" link set dev "$SERVER_VETH" up
if command -v ethtool >/dev/null 2>&1; then
	client_exec ethtool -K "$CLIENT_VETH" tx off rx off >/dev/null 2>&1 || true
	server_exec ethtool -K "$SERVER_VETH" tx off rx off >/dev/null 2>&1 || true
fi
client_exec "$PING_BIN" -n -q -c 1 -W 1 -I "$CLIENT_VETH" 172.31.216.2

"$AWG_BIN" genkey >"$private_directory/server-private"
"$AWG_BIN" pubkey <"$private_directory/server-private" >"$private_directory/server-public"
"$AWG_BIN" genkey >"$private_directory/client-private"
"$AWG_BIN" pubkey <"$private_directory/client-private" >"$private_directory/client-public"
"$AWG_BIN" genpsk >"$private_directory/psk"
server_public=$(tr -d '\r\n' <"$private_directory/server-public")
client_public=$(tr -d '\r\n' <"$private_directory/client-public")
client_private_b64=$(tr -d '\r\n' <"$private_directory/client-private")
psk_b64=$(tr -d '\r\n' <"$private_directory/psk")

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$AWG_ENGINE" -f "$SERVER_AWG_IFACE" \
	>"$EVIDENCE_DIR/server-engine.log" 2>&1 &
SERVER_ENGINE_PID=$!
attempt=0
while ! server_exec "$IP_BIN" link show dev "$SERVER_AWG_IFACE" >/dev/null 2>&1; do
	if ! kill -0 "$SERVER_ENGINE_PID" >/dev/null 2>&1; then
		fail "server AWG process exited before interface readiness"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		fail "server AWG interface did not appear"
	fi
	sleep 0.02
done
server_exec "$AWG_BIN" set "$SERVER_AWG_IFACE" \
	private-key "$private_directory/server-private" \
	listen-port "$SERVER_AWG_PORT" \
	jc 4 jmin 12 jmax 64 \
	s1 16 s2 80 s3 24 s4 8 \
	h1 111111 h2 222222 h3 333333 h4 444444 \
	peer "$client_public" \
	preshared-key "$private_directory/psk" \
	allowed-ips 10.216.1.0/24
server_exec "$IP_BIN" address add 10.216.0.2/24 dev "$SERVER_AWG_IFACE"
server_exec "$IP_BIN" link set dev "$SERVER_AWG_IFACE" mtu 1280 up

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$E2E_BIN" -mode=server \
	-dns-listen=10.216.0.2:5300 \
	-canary-listen=10.216.0.2:5301 \
	-answer-ip=203.0.113.77 \
	>"$EVIDENCE_DIR/server-responders.log" 2>&1 &
RESPONDER_PID=$!
attempt=0
while ! grep -q '^READY$' "$EVIDENCE_DIR/server-responders.log" 2>/dev/null; do
	if ! kill -0 "$RESPONDER_PID" >/dev/null 2>&1; then
		fail "server responders exited before readiness"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		fail "server responders did not become ready"
	fi
	sleep 0.02
done

payload_limitation_arg=""
if [ "$ALLOW_KERNEL_PAYLOAD_LIMITATION" -eq 1 ]; then
	payload_limitation_arg="-allow-kernel-payload-limitation"
fi
set +e
# payload_limitation_arg is empty or one fixed flag selected above.
# shellcheck disable=SC2086
client_exec "$E2E_BIN" -mode=client $payload_limitation_arg \
	-gateway-endpoint="172.31.216.2:$SERVER_AWG_PORT" \
	-gateway-pubkey="$server_public" \
	-client-private-key="$client_private_b64" \
	-psk="$psk_b64" \
	-inner-pool=10.216.1.0/24 \
	-allowed-ip=10.216.0.0/23 \
	-verification-route=10.216.0.0/24 \
	-dns-resolver=10.216.0.2:5300 \
	-expected-dns-answer=203.0.113.77 \
	-canary-endpoint=10.216.0.2:5301 \
	-table-prefix="$TABLE_PREFIX" \
	-underlay-interface="$CLIENT_VETH" \
	-underlay-mark="$UNDERLAY_MARK" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary="$RESOLVECTL_BIN" \
	-temp-root="$private_directory" \
	-stop-timeout="$STOP_TIMEOUT" \
	>"$EVIDENCE_DIR/client.log" 2>&1
client_status=$?
set -e
cat "$EVIDENCE_DIR/client.log"
if [ "$client_status" -ne 0 ]; then
	fail "client fault matrix failed with status $client_status"
fi
grep -Fq 'PASS fault_matrix=3 real_awg=true real_nft=true real_ip=true exact_residue=true' \
	"$EVIDENCE_DIR/client.log" ||
	fail "client log lacks the complete pass marker"

for table_suffix in 1 2 3; do
	if client_exec "$NFT_BIN" list table inet "${TABLE_PREFIX}${table_suffix}" \
		>/dev/null 2>&1; then
		fail "client namespace nft residue: ${TABLE_PREFIX}${table_suffix}"
	fi
done
if client_exec "$IP_BIN" -o link show |
	grep -E 'winn[0-9a-f]{10}' >/dev/null 2>&1; then
	client_exec "$IP_BIN" -o link show >"$EVIDENCE_DIR/client-link-residue.txt"
	fail "client namespace AWG interface residue"
fi
sed -n 's/.*process_pid=\([0-9][0-9]*\).*/\1/p' \
	"$EVIDENCE_DIR/client.log" >"$private_directory/client-process-pids"
while IFS= read -r process_id; do
	if [ -r "/proc/$process_id/cmdline" ] &&
		tr '\0' ' ' <"/proc/$process_id/cmdline" |
			grep -F "$AWG_ENGINE" >/dev/null 2>&1; then
		fail "client AWG process residue: pid $process_id"
	fi
done <"$private_directory/client-process-pids"
client_exec "$IP_BIN" -4 rule show >"$EVIDENCE_DIR/client-rules-final.txt"
client_exec "$IP_BIN" -4 route show table all >"$EVIDENCE_DIR/client-routes-final.txt"
client_exec "$NFT_BIN" list ruleset >"$EVIDENCE_DIR/client-nft-final.txt"

cleanup
trap - EXIT HUP INT TERM
capture_root "$EVIDENCE_DIR/root-after.txt"
"$IP_BIN" netns list >"$EVIDENCE_DIR/netns-after.txt"
if ! cmp -s "$EVIDENCE_DIR/root-before.txt" "$EVIDENCE_DIR/root-after.txt"; then
	diff -u "$EVIDENCE_DIR/root-before.txt" "$EVIDENCE_DIR/root-after.txt" \
		>"$EVIDENCE_DIR/root-state.diff" || true
	fail "root route/rule/nft state changed"
fi
if ! cmp -s "$EVIDENCE_DIR/netns-before.txt" "$EVIDENCE_DIR/netns-after.txt"; then
	diff -u "$EVIDENCE_DIR/netns-before.txt" "$EVIDENCE_DIR/netns-after.txt" \
		>"$EVIDENCE_DIR/netns-state.diff" || true
	fail "network namespace residue remains"
fi
for interface_name in "$CLIENT_VETH" "$SERVER_VETH"; do
	if "$IP_BIN" link show dev "$interface_name" >/dev/null 2>&1; then
		fail "root veth residue remains: $interface_name"
	fi
done

echo "PASS" >"$EVIDENCE_DIR/result.txt"
manifest_temporary="$(dirname "$EVIDENCE_DIR")/.teardown-evidence-manifest-$RUN_ID.tmp"
(
	cd "$EVIDENCE_DIR"
	find . -type f ! -name evidence-manifest.sha256 -print0 |
		sort -z |
		xargs -0 sha256sum
) >"$manifest_temporary"
mv "$manifest_temporary" "$EVIDENCE_DIR/evidence-manifest.sha256"
archive="${EVIDENCE_DIR}.tar.gz"
tar -C "$(dirname "$EVIDENCE_DIR")" -czf "$archive" "$(basename "$EVIDENCE_DIR")"
sha256sum "$archive" >"${archive}.sha256"
echo "PASS: contextual teardown fault matrix completed in disposable namespaces"
echo "EVIDENCE_DIR=$EVIDENCE_DIR"
echo "EVIDENCE_ARCHIVE=$archive"
echo "EVIDENCE_ARCHIVE_SHA256=$(awk '{ print $1 }' "${archive}.sha256")"
