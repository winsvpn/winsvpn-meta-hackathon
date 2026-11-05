#!/bin/sh
set -eu

# Honesty-first AICORE vertical proof for the production Winn Linux H3
# candidate. The root namespace is only used to create and later delete two
# disposable namespaces. The H3 kill switch, routes, resolver transaction,
# AWG interfaces, carrier listener, and probe responders never enter root.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
# LinuxUnderlayMarkAuthorizer intentionally rejects symlinked executable
# paths. Ubuntu exposes /usr/sbin/ip as a symlink, while /usr/bin/ip is the
# real executable.
IP_BIN=${IP_BIN:-/usr/bin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
RESOLVECTL_BIN=${RESOLVECTL_BIN:-/usr/bin/resolvectl}
PING_BIN=${PING_BIN:-/bin/ping}
HTTP_PROBE_BIN=${HTTP_PROBE_BIN:-/usr/bin/wget}
E2E_BIN=${E2E_BIN:-/opt/winn-lab/bin/winn-h3-e2e}
CARRIER_BIN=${CARRIER_BIN:-/opt/winn-lab/bin/winn-carrier-server}
PKI_BIN=${PKI_BIN:-/opt/winn-lab/bin/winn-pki}
AUDIT_BIN=${AUDIT_BIN:-/opt/winn-lab/bin/winn-audit}
TCPDUMP_BIN=${TCPDUMP_BIN:-/usr/bin/tcpdump}
SYSCTL_BIN=${SYSCTL_BIN:-/usr/sbin/sysctl}

RUN_TOKEN=${RUN_TOKEN:-$$}
CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-wh3cns$RUN_TOKEN}
SERVER_NAMESPACE=${SERVER_NAMESPACE:-wh3sns$RUN_TOKEN}
CLIENT_VETH=${CLIENT_VETH:-wh3cv$RUN_TOKEN}
SERVER_VETH=${SERVER_VETH:-wh3sv$RUN_TOKEN}
SERVER_AWG_IFACE=${SERVER_AWG_IFACE:-wh3awg$RUN_TOKEN}
TABLE_NAME=${TABLE_NAME:-wh3t$RUN_TOKEN}
H3_PORT=${H3_PORT:-41443}
METRICS_PORT=${METRICS_PORT:-41444}
SERVER_AWG_PORT=${SERVER_AWG_PORT:-41403}
DIRECT_UNDERLAY_MARK=${DIRECT_UNDERLAY_MARK:-a311}
H3_UNDERLAY_MARK=${H3_UNDERLAY_MARK:-a312}

OUTER_CLIENT=${OUTER_CLIENT:-172.31.226.1}
OUTER_SERVER=${OUTER_SERVER:-172.31.226.2}
INNER_SERVER=${INNER_SERVER:-10.226.0.2}
INNER_CLIENT_POOL=${INNER_CLIENT_POOL:-10.226.1.0/24}
INNER_ALLOWED=${INNER_ALLOWED:-10.226.0.0/23}
VERIFY_PREFIX=${VERIFY_PREFIX:-10.226.0.0/24}
DNS_PORT=${DNS_PORT:-5300}
CANARY_PORT=${CANARY_PORT:-5301}
EXPECTED_ANSWER=${EXPECTED_ANSWER:-203.0.113.226}
CARRIER_NAME=${CARRIER_NAME:-carrier.winn.test}
PUBLIC_TARGET=${PUBLIC_TARGET:-winn.invalid:443}
CONTROLLER_ID=${CONTROLLER_ID:-aicore-h3-controller}
DEVICE_ID=${DEVICE_ID:-aicore-h3-device}

EXPECTED_SOURCE_DIGEST=${EXPECTED_SOURCE_DIGEST:?set the exact embedded source-tree digest}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/opt/winn-lab/evidence}
RUN_ID=${RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')-$RUN_TOKEN}
EVIDENCE_DIR=${EVIDENCE_DIR:-"$EVIDENCE_ROOT/h3-e2e-$RUN_ID"}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if [ "$(id -u)" -ne 0 ]; then
	fail "run as root on the disposable AICORE lab host"
fi
case "$EXPECTED_SOURCE_DIGEST" in
	"" | *[!0-9a-f]*)
		fail "EXPECTED_SOURCE_DIGEST must be lowercase hexadecimal"
		;;
esac
if [ "${#EXPECTED_SOURCE_DIGEST}" -ne 64 ]; then
	fail "EXPECTED_SOURCE_DIGEST must be 64 hexadecimal characters"
fi
for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$NFT_BIN" \
	"$RESOLVECTL_BIN" "$PING_BIN" "$HTTP_PROBE_BIN" "$E2E_BIN" \
	"$CARRIER_BIN" "$PKI_BIN" "$AUDIT_BIN" "$TCPDUMP_BIN" \
	"$SYSCTL_BIN"; do
	if [ ! -x "$executable" ]; then
		fail "required executable is missing: $executable"
	fi
done
for identifier in "$CLIENT_NAMESPACE" "$SERVER_NAMESPACE" "$CLIENT_VETH" \
	"$SERVER_VETH" "$SERVER_AWG_IFACE" "$TABLE_NAME"; do
	case "$identifier" in
	"" | *[!A-Za-z0-9_.-]*)
		fail "invalid scoped identifier: $identifier"
		;;
	esac
done
for interface_name in "$CLIENT_VETH" "$SERVER_VETH" "$SERVER_AWG_IFACE"; do
	if [ "${#interface_name}" -gt 15 ]; then
		fail "interface name exceeds Linux IFNAMSIZ: $interface_name"
	fi
done
if [ "${#TABLE_NAME}" -gt 15 ]; then
	fail "nft table name is too long for this evidence harness"
fi
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
embedded_digest=$("$E2E_BIN" -print-source-digest)
if [ "$embedded_digest" != "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "binary source digest mismatch: embedded=$embedded_digest expected=$EXPECTED_SOURCE_DIGEST"
fi
if [ -e "$EVIDENCE_DIR" ]; then
	fail "refusing to overwrite evidence directory: $EVIDENCE_DIR"
fi
mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-h3-e2e.XXXXXXXX")
chmod 0700 "$private_directory"
umask 077
PKI_DIR="$private_directory/pki"

SERVER_AWG_PID=""
RESPONDER_PID=""
CARRIER_PID=""
CLIENT_CAPTURE_PID=""
SERVER_CAPTURE_PID=""
FINALIZED=0

client_exec() {
	"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$@"
}

server_exec() {
	"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$@"
}

namespace_exists() {
	"$IP_BIN" netns list | awk '{ print $1 }' |
		grep -Fx "$1" >/dev/null 2>&1
}

namespace_kill_all() {
	cleanup_namespace=$1
	if ! namespace_exists "$cleanup_namespace"; then
		return
	fi
	for cleanup_pid in $("$IP_BIN" netns pids "$cleanup_namespace" 2>/dev/null || true); do
		kill "$cleanup_pid" >/dev/null 2>&1 || true
	done
	for cleanup_pid in $("$IP_BIN" netns pids "$cleanup_namespace" 2>/dev/null || true); do
		kill -KILL "$cleanup_pid" >/dev/null 2>&1 || true
	done
}

capture_root() {
	capture_destination=$1
	{
		echo "=== default-route ==="
		"$IP_BIN" route show default
		echo "=== rules-v4 ==="
		"$IP_BIN" -4 rule show
		echo "=== nftables ==="
		# Do not let unrelated SSH/UFW packet counters create a false root
		# state diff on an existing cloud gateway.
		"$NFT_BIN" --stateless list ruleset
	} >"$capture_destination" 2>&1
}

capture_namespace_diagnostics() {
	capture_namespace=$1
	capture_prefix=$2
	if ! namespace_exists "$capture_namespace"; then
		return
	fi
	"$IP_BIN" netns exec "$capture_namespace" "$IP_BIN" -o link show \
		>"$EVIDENCE_DIR/${capture_prefix}-links.txt" 2>&1 || true
	"$IP_BIN" netns exec "$capture_namespace" "$IP_BIN" -4 rule show \
		>"$EVIDENCE_DIR/${capture_prefix}-rules.txt" 2>&1 || true
	"$IP_BIN" netns exec "$capture_namespace" "$IP_BIN" -4 route show table all \
		>"$EVIDENCE_DIR/${capture_prefix}-routes.txt" 2>&1 || true
	"$IP_BIN" netns exec "$capture_namespace" "$NFT_BIN" list ruleset \
		>"$EVIDENCE_DIR/${capture_prefix}-nft.txt" 2>&1 || true
}

cleanup() {
	for cleanup_pid in "$CLIENT_CAPTURE_PID" "$SERVER_CAPTURE_PID" \
		"$CARRIER_PID" "$RESPONDER_PID" "$SERVER_AWG_PID"; do
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
	find "$private_directory" -depth -type d -empty -delete >/dev/null 2>&1 || true
}

finalize() {
	status=$?
	if [ "$FINALIZED" -eq 1 ]; then
		exit "$status"
	fi
	FINALIZED=1
	trap - EXIT HUP INT TERM
	set +e
	capture_namespace_diagnostics "$CLIENT_NAMESPACE" client-final
	capture_namespace_diagnostics "$SERVER_NAMESPACE" server-final
	cleanup
	capture_root "$EVIDENCE_DIR/root-after.txt"
	"$IP_BIN" netns list >"$EVIDENCE_DIR/netns-after.txt"
	if ! cmp -s "$EVIDENCE_DIR/root-before.txt" "$EVIDENCE_DIR/root-after.txt"; then
		diff -u "$EVIDENCE_DIR/root-before.txt" "$EVIDENCE_DIR/root-after.txt" \
			>"$EVIDENCE_DIR/root-state.diff" 2>&1 || true
		status=1
	fi
	if ! cmp -s "$EVIDENCE_DIR/netns-before.txt" "$EVIDENCE_DIR/netns-after.txt"; then
		diff -u "$EVIDENCE_DIR/netns-before.txt" "$EVIDENCE_DIR/netns-after.txt" \
			>"$EVIDENCE_DIR/netns-state.diff" 2>&1 || true
		status=1
	fi
	for interface_name in "$CLIENT_VETH" "$SERVER_VETH"; do
		if "$IP_BIN" link show dev "$interface_name" >/dev/null 2>&1; then
			echo "root veth residue: $interface_name" \
				>>"$EVIDENCE_DIR/cleanup-errors.txt"
			status=1
		fi
	done
	if [ "$status" -eq 0 ]; then
		echo "PASS" >"$EVIDENCE_DIR/result.txt"
	else
		echo "FAIL status=$status" >"$EVIDENCE_DIR/result.txt"
	fi
	manifest_temporary="$(dirname "$EVIDENCE_DIR")/.h3-manifest-$RUN_ID.tmp"
	(
		cd "$EVIDENCE_DIR" || exit 1
		find . -type f ! -name evidence-manifest.sha256 -print0 |
			sort -z |
			xargs -0 sha256sum
	) >"$manifest_temporary"
	mv "$manifest_temporary" "$EVIDENCE_DIR/evidence-manifest.sha256"
	archive="${EVIDENCE_DIR}.tar.gz"
	tar -C "$(dirname "$EVIDENCE_DIR")" -czf "$archive" \
		"$(basename "$EVIDENCE_DIR")"
	sha256sum "$archive" >"${archive}.sha256"
	echo "EVIDENCE_DIR=$EVIDENCE_DIR"
	echo "EVIDENCE_ARCHIVE=$archive"
	echo "EVIDENCE_ARCHIVE_SHA256=$(awk '{ print $1 }' "${archive}.sha256")"
	exit "$status"
}

trap finalize EXIT
trap 'exit 130' HUP INT TERM

capture_root "$EVIDENCE_DIR/root-before.txt"
"$IP_BIN" netns list >"$EVIDENCE_DIR/netns-before.txt"
"$E2E_BIN" -print-source-digest >"$EVIDENCE_DIR/embedded-source-digest.txt"
sha256sum "$E2E_BIN" "$CARRIER_BIN" "$PKI_BIN" "$AUDIT_BIN" \
	>"$EVIDENCE_DIR/binaries.sha256"
if [ -n "$SOURCE_MANIFEST" ]; then
	if [ ! -f "$SOURCE_MANIFEST" ]; then
		fail "SOURCE_MANIFEST does not exist: $SOURCE_MANIFEST"
	fi
	cp "$SOURCE_MANIFEST" "$EVIDENCE_DIR/source-manifest.sha256"
fi
{
	echo "schema=winn-h3-e2e/v2"
	echo "captured_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "hostname=$(hostname)"
	echo "kernel=$(uname -srmo)"
	echo "protocol_version=winn/3"
	echo "source_digest=$EXPECTED_SOURCE_DIGEST"
	echo "client_namespace=$CLIENT_NAMESPACE"
	echo "server_namespace=$SERVER_NAMESPACE"
	echo "underlay_interface=$CLIENT_VETH"
	echo "nft_table=$TABLE_NAME"
	echo "root_kill_switch_mutated=false"
	echo "root_routes_mutated=false"
	echo "root_nat_mutated=false"
	echo "tls_profile=TLS1.3 X25519+ML-KEM-768"
	echo "ech=required-and-client-acceptance-enforced"
	echo "zero_rtt=false"
	echo "carrier=authenticated RFC9298 CONNECT-UDP"
	echo "preparation=live TLS1.3/QUIC plus authenticated CONNECT-UDP datagram proof"
	echo "click_path=reuses prepared HTTP/3 connection with a distinct authentication request"
	echo "inner_tunnel=real AmneziaWG"
	echo "connect_budget=3s"
	echo "resolvectl_scope=recorded-only"
	echo "resolvectl_limitation=systemd-resolved cannot address a link index in another network namespace"
	echo "protected_dns_probe=real marked socket through inner AWG"
	echo "client_namespace_rp_filter=disabled for pre-commit marked-table replies"
} >"$EVIDENCE_DIR/environment.txt"

"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" netns add "$SERVER_NAMESPACE"
"$IP_BIN" link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
client_exec "$IP_BIN" link set lo up
server_exec "$IP_BIN" link set lo up
# Probe replies arrive on a candidate interface before its transaction is
# committed to the main table. Linux loose reverse-path filtering still drops
# them when its unmarked reverse lookup cannot see the candidate's mark-based
# table. AWG authenticates its peer and enforces allowed-ips, so disable
# rp_filter only inside the disposable client namespace before the candidate
# interface is created. Root and the server namespace retain their policies.
client_exec "$SYSCTL_BIN" -q -w net.ipv4.conf.all.rp_filter=0
client_exec "$SYSCTL_BIN" -q -w net.ipv4.conf.default.rp_filter=0
client_exec "$IP_BIN" address add "$OUTER_CLIENT/30" dev "$CLIENT_VETH"
server_exec "$IP_BIN" address add "$OUTER_SERVER/30" dev "$SERVER_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
server_exec "$IP_BIN" link set dev "$SERVER_VETH" up
if command -v ethtool >/dev/null 2>&1; then
	client_exec ethtool -K "$CLIENT_VETH" tx off rx off >/dev/null 2>&1 || true
	server_exec ethtool -K "$SERVER_VETH" tx off rx off >/dev/null 2>&1 || true
fi
client_exec "$PING_BIN" -n -q -c 1 -W 1 -I "$CLIENT_VETH" "$OUTER_SERVER"

"$PKI_BIN" \
	-out "$PKI_DIR" \
	-server-name "$CARRIER_NAME" \
	-device-id "$DEVICE_ID" \
	>"$EVIDENCE_DIR/pki.log" 2>&1

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

"$IP_BIN" netns exec "$SERVER_NAMESPACE" \
	"$AWG_ENGINE" -f "$SERVER_AWG_IFACE" \
	>"$EVIDENCE_DIR/server-awg.log" 2>&1 &
SERVER_AWG_PID=$!
attempt=0
while ! server_exec "$IP_BIN" link show dev "$SERVER_AWG_IFACE" \
	>/dev/null 2>&1; do
	if ! kill -0 "$SERVER_AWG_PID" >/dev/null 2>&1; then
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
	allowed-ips "$INNER_CLIENT_POOL"
server_exec "$IP_BIN" address add "$INNER_SERVER/24" dev "$SERVER_AWG_IFACE"
server_exec "$IP_BIN" link set dev "$SERVER_AWG_IFACE" mtu 1280 up
# `awg set ... allowed-ips` updates cryptographic peer selection but does not
# install an IP route. The responder namespace needs this explicit scoped
# return route (and reverse-path source reachability) for the client pool.
server_exec "$IP_BIN" route add "$INNER_CLIENT_POOL" dev "$SERVER_AWG_IFACE"

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$E2E_BIN" -mode=server \
	-dns-listen="$INNER_SERVER:$DNS_PORT" \
	-canary-listen="$INNER_SERVER:$CANARY_PORT" \
	-answer-ip="$EXPECTED_ANSWER" \
	>"$EVIDENCE_DIR/responders.log" 2>&1 &
RESPONDER_PID=$!
attempt=0
while ! grep -q '^READY$' "$EVIDENCE_DIR/responders.log" 2>/dev/null; do
	if ! kill -0 "$RESPONDER_PID" >/dev/null 2>&1; then
		fail "DNS/canary responder exited before readiness"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		fail "DNS/canary responder did not become ready"
	fi
	sleep 0.02
done

masque_template="https://$CARRIER_NAME:$H3_PORT/.well-known/masque/udp/{target_host}/{target_port}/"
"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$CARRIER_BIN" \
	-addr "$OUTER_SERVER:$H3_PORT" \
	-metrics-addr "127.0.0.1:$METRICS_PORT" \
	-masque-template "$masque_template" \
	-public-target "$PUBLIC_TARGET" \
	-awg-backend "$OUTER_SERVER:$SERVER_AWG_PORT" \
	-cert "$PKI_DIR/server.pem" \
	-key "$PKI_DIR/server-key.pem" \
	-client-ca "$PKI_DIR/ca.pem" \
	-device-registry "$PKI_DIR/device-pq-registry.json" \
	-controller-pq-seed "$PKI_DIR/controller-mldsa87.seed" \
	-controller-id "$CONTROLLER_ID" \
	-audit-log "$EVIDENCE_DIR/carrier-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	-ech-keys "$PKI_DIR/ech-server-keys.json" \
	-suite x25519-mlkem768 \
	-lab-mode \
	>"$EVIDENCE_DIR/carrier.log" 2>&1 &
CARRIER_PID=$!
attempt=0
until server_exec "$HTTP_PROBE_BIN" -q -O /dev/null \
	"http://127.0.0.1:$METRICS_PORT/readyz" >/dev/null 2>&1; do
	if ! kill -0 "$CARRIER_PID" >/dev/null 2>&1; then
		fail "production carrier exited before readiness"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 200 ]; then
		fail "production carrier readiness timeout"
	fi
	sleep 0.02
done

"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$TCPDUMP_BIN" \
	-i any -n -vv -l -U -s 0 -c 300 \
	>"$EVIDENCE_DIR/client-tcpdump.log" 2>&1 &
CLIENT_CAPTURE_PID=$!
"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$TCPDUMP_BIN" \
	-i any -n -vv -l -U -s 0 -c 300 \
	>"$EVIDENCE_DIR/server-tcpdump.log" 2>&1 &
SERVER_CAPTURE_PID=$!
sleep 0.2

set +e
client_exec "$E2E_BIN" -mode=client \
	-server-name="$CARRIER_NAME" \
	-remote-endpoint="$OUTER_SERVER:$H3_PORT" \
	-masque-template="$masque_template" \
	-public-target="$PUBLIC_TARGET" \
	-device-id="$DEVICE_ID" \
	-controller-id="$CONTROLLER_ID" \
	-device-cert="$PKI_DIR/device.pem" \
	-device-key="$PKI_DIR/device-key.pem" \
	-root-ca="$PKI_DIR/ca.pem" \
	-device-pq-seed="$PKI_DIR/device-mldsa65.seed" \
	-controller-pq-pins="$PKI_DIR/controller-pq-pins.json" \
	-ech-config-list="$PKI_DIR/ech-config-list.bin" \
	-gateway-endpoint="$OUTER_SERVER:$SERVER_AWG_PORT" \
	-gateway-pubkey="$server_public" \
	-client-private-key="$client_private_b64" \
	-psk="$psk_b64" \
	-inner-pool="$INNER_CLIENT_POOL" \
	-allowed-ip="$INNER_ALLOWED" \
	-verification-route="$VERIFY_PREFIX" \
	-listen-port-min=41410 \
	-listen-port-max=41415 \
	-dns-resolver="$INNER_SERVER:$DNS_PORT" \
	-expected-dns-answer="$EXPECTED_ANSWER" \
	-canary-endpoint="$INNER_SERVER:$CANARY_PORT" \
	-client-namespace="$CLIENT_NAMESPACE" \
	-table-name="$TABLE_NAME" \
	-underlay-interface="$CLIENT_VETH" \
	-direct-underlay-mark="$DIRECT_UNDERLAY_MARK" \
	-h3-underlay-mark="$H3_UNDERLAY_MARK" \
	-awg-go-binary="$AWG_ENGINE" \
	-awg-binary="$AWG_BIN" \
	-ip-binary="$IP_BIN" \
	-nft-binary="$NFT_BIN" \
	-resolvectl-binary="$RESOLVECTL_BIN" \
	-temp-root="$private_directory" \
	-hold=250ms \
	>"$EVIDENCE_DIR/client.log" 2>&1
client_status=$?
set -e
cat "$EVIDENCE_DIR/client.log"
for capture_pid in "$CLIENT_CAPTURE_PID" "$SERVER_CAPTURE_PID"; do
	kill "$capture_pid" >/dev/null 2>&1 || true
	wait "$capture_pid" >/dev/null 2>&1 || true
done
CLIENT_CAPTURE_PID=""
SERVER_CAPTURE_PID=""

capture_namespace_diagnostics "$CLIENT_NAMESPACE" client-post-run
capture_namespace_diagnostics "$SERVER_NAMESPACE" server-post-run
server_exec "$AWG_BIN" show "$SERVER_AWG_IFACE" dump \
	>"$EVIDENCE_DIR/server-awg-final.txt" 2>&1 || true
"$AUDIT_BIN" \
	-audit-log "$EVIDENCE_DIR/carrier-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	>"$EVIDENCE_DIR/audit-verify.log" 2>&1

if [ "$client_status" -ne 0 ]; then
	fail "production H3 client failed with status $client_status"
fi
grep -Fq 'LIVE_H3_PREPARED elapsed=' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks live H3 preparation marker"
grep -Fq 'auth_mode=identity authenticated_connect_probe=true preparation_auth_requests=1' \
	"$EVIDENCE_DIR/client.log" ||
	fail "client log lacks exact preparation authentication proof"
grep -Fq 'PREPARED protocol_version=winn/3' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks Winn v3 preparation marker"
grep -Fq 'h3_fixed_ip=true live_h3=true' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks prepared fixed-IP H3 proof"
grep -Fq 'ONLINE elapsed=' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks ONLINE marker"
grep -Fq 'ech_accepted=true' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks accepted-ECH proof"
grep -Fq 'inner_awg_fresh=true' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks fresh inner-AWG proof"
grep -Fq 'protected_dns=true canary=true' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks protected DNS/canary proof"
grep -Fq 'BOUNDED_TEARDOWN_OK' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks bounded teardown proof"
h3_open_count=$(
	grep -c '"event":"carrier_h3_open"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true
)
h3_closed_count=$(
	grep -c '"event":"carrier_h3_closed"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true
)
h3_auth_only_count=$(
	grep -c '"event":"carrier_h3_auth_only"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true
)
if [ "$h3_auth_only_count" -ne 1 ] ||
	[ "$h3_open_count" -ne 1 ] ||
	[ "$h3_closed_count" -ne 1 ]; then
	fail "carrier audit must contain one authentication-only preparation and one data lifecycle"
fi
if client_exec "$NFT_BIN" list table inet "$TABLE_NAME" >/dev/null 2>&1; then
	fail "candidate nft table remains after client teardown"
fi
if client_exec "$IP_BIN" -o link show |
	grep -E 'winn[0-9a-f]{10}' >/dev/null 2>&1; then
	fail "candidate AWG interface remains after client teardown"
fi

echo "PASS: live pre-click fixed-IP protected H3, strict hybrid TLS 1.3, accepted ECH, two distinct ML-DSA CONNECT-UDP requests on one HTTP/3 connection, fresh inner AWG, protected probes, sub-3-second click commit, and bounded teardown"
