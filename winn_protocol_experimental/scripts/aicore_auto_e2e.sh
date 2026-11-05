#!/bin/sh
set -eu

# Privileged AICORE proof for the production Winn v3 Linux Auto join:
# signed ManifestV2 and Linux profile, rollback/transparency pinning, real
# rotation state, encrypted anonymous-token inventory, durable TLS PostgreSQL
# redemption, live DirectAWG probing, prepared anonymous H3, a sub-three-second
# one-click race, protected DNS/canary checks, and bounded cleanup.

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
IP_BIN=${IP_BIN:-/usr/bin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
RESOLVECTL_BIN=${RESOLVECTL_BIN:-/usr/bin/resolvectl}
PING_BIN=${PING_BIN:-/bin/ping}
HTTP_PROBE_BIN=${HTTP_PROBE_BIN:-/usr/bin/wget}
TCPDUMP_BIN=${TCPDUMP_BIN:-/usr/bin/tcpdump}
SYSCTL_BIN=${SYSCTL_BIN:-/usr/sbin/sysctl}
TC_BIN=${TC_BIN:-/usr/sbin/tc}
JQ_BIN=${JQ_BIN:-/usr/bin/jq}
OPENSSL_BIN=${OPENSSL_BIN:-/usr/bin/openssl}
RUNUSER_BIN=${RUNUSER_BIN:-/usr/sbin/runuser}

AUTO_BIN=${AUTO_BIN:-/opt/winn-lab/bin/winn-auto-e2e}
FIXTURE_BIN=${FIXTURE_BIN:-/opt/winn-lab/bin/winn-auto-fixture}
CARRIER_BIN=${CARRIER_BIN:-/opt/winn-lab/bin/winn-carrier-server}
PKI_BIN=${PKI_BIN:-/opt/winn-lab/bin/winn-pki}
TOKEN_ISSUER_BIN=${TOKEN_ISSUER_BIN:-/opt/winn-lab/bin/winn-token-issuer}
TOKEN_BIN=${TOKEN_BIN:-/opt/winn-lab/bin/winn-token}
AUDIT_BIN=${AUDIT_BIN:-/opt/winn-lab/bin/winn-audit}
MEASUREMENT_VERIFY_BIN=${MEASUREMENT_VERIFY_BIN:-/opt/winn-lab/bin/winn-measurement-verify}
RESPONDER_BIN=${RESPONDER_BIN:-/opt/winn-lab/bin/winn-h3-e2e}
POSTGRES_SCHEMA=${POSTGRES_SCHEMA:-/opt/winn-lab/schema/postgres_v1.sql}

PG_BINDIR=${PG_BINDIR:-}
PG_OS_USER=${PG_OS_USER:-postgres}
PG_PORT=${PG_PORT:-45432}
PG_DATABASE=${PG_DATABASE:-winn_auto_e2e}
PG_DATABASE_USER=${PG_DATABASE_USER:-winn_auto_e2e}

RUN_TOKEN=${RUN_TOKEN:-$$}
CLIENT_NAMESPACE=${CLIENT_NAMESPACE:-wacn$RUN_TOKEN}
SERVER_NAMESPACE=${SERVER_NAMESPACE:-wasn$RUN_TOKEN}
CLIENT_VETH=${CLIENT_VETH:-wacv$RUN_TOKEN}
SERVER_VETH=${SERVER_VETH:-wasv$RUN_TOKEN}
SERVER_AWG_IFACE=${SERVER_AWG_IFACE:-wasg$RUN_TOKEN}
TABLE_NAME=${TABLE_NAME:-wat$RUN_TOKEN}

H3_PORT=${H3_PORT:-42443}
METRICS_PORT=${METRICS_PORT:-42444}
TOKEN_PORT=${TOKEN_PORT:-42445}
SERVER_AWG_PORT=${SERVER_AWG_PORT:-42403}
DIRECT_UNDERLAY_MARK=${DIRECT_UNDERLAY_MARK:-a511}
H3_UNDERLAY_MARK=${H3_UNDERLAY_MARK:-a512}

OUTER_CLIENT=${OUTER_CLIENT:-172.31.228.1}
OUTER_SERVER=${OUTER_SERVER:-172.31.228.2}
INNER_SERVER=${INNER_SERVER:-10.228.0.2}
INNER_CLIENT_POOL=${INNER_CLIENT_POOL:-10.228.1.0/24}
INNER_ALLOWED=${INNER_ALLOWED:-10.228.0.0/23}
VERIFY_PREFIX=${VERIFY_PREFIX:-10.228.0.0/24}
DNS_PORT=${DNS_PORT:-5500}
CANARY_PORT=${CANARY_PORT:-5501}
EXPECTED_ANSWER=${EXPECTED_ANSWER:-203.0.113.228}

CARRIER_NAME=${CARRIER_NAME:-carrier.winn.test}
PUBLIC_TARGET=${PUBLIC_TARGET:-winn.invalid:443}
CONTROLLER_ID=${CONTROLLER_ID:-aicore-auto-controller}
DEVICE_ID=${DEVICE_ID:-aicore-auto-device}
NODE_ID=${NODE_ID:-aicore-auto-node}
DIRECT_TRANSPORT_ID=${DIRECT_TRANSPORT_ID:-direct-primary}
H3_TRANSPORT_ID=${H3_TRANSPORT_ID:-h3-primary}
# Restrict preparation to one carrier so a cell can produce targeted
# evidence for HTTP/3, which Auto otherwise almost never selects.
FORCE_CARRIER=${FORCE_CARRIER:-}
ATTEMPTS=${ATTEMPTS:-1}
READINESS=${READINESS:-warm}
TOKEN_COUNT=${TOKEN_COUNT:-$((3 * ATTEMPTS + 8))}
HOLD=${HOLD:-}
DIRECT_INITIAL_OUTER_DROP=${DIRECT_INITIAL_OUTER_DROP:-0s}
DIRECT_CLICK_DELAY=${DIRECT_CLICK_DELAY:-0s}
IMPAIRMENT_ID=${IMPAIRMENT_ID:-baseline}
case "$IMPAIRMENT_ID" in
baseline)
	RTT_MS=0
	ONE_WAY_DELAY_MS=0
	LOSS_FRACTION=0
	PER_LEG_LOSS_PERCENT=0
	CAPACITY_MBPS=0
	;;
nominal-30ms-0.1pct-100mbps)
	RTT_MS=30
	ONE_WAY_DELAY_MS=15
	LOSS_FRACTION=0.001
	PER_LEG_LOSS_PERCENT=0.05001250625390474
	CAPACITY_MBPS=100
	;;
constrained-100ms-1pct-25mbps)
	RTT_MS=100
	ONE_WAY_DELAY_MS=50
	LOSS_FRACTION=0.01
	PER_LEG_LOSS_PERCENT=0.5012562893380035
	CAPACITY_MBPS=25
	;;
envelope-edge-250ms-3pct-10mbps)
	RTT_MS=250
	ONE_WAY_DELAY_MS=125
	LOSS_FRACTION=0.03
	PER_LEG_LOSS_PERCENT=1.5114219820389518
	CAPACITY_MBPS=10
	;;
*)
	echo "FAIL: IMPAIRMENT_ID is not one of the frozen Phase 1 profiles" >&2
	exit 1
	;;
esac
if [ -z "$HOLD" ]; then
	if [ "$ATTEMPTS" -eq 1 ]; then
		HOLD=250ms
	else
		HOLD=0s
	fi
fi

EXPECTED_SOURCE_DIGEST=${EXPECTED_SOURCE_DIGEST:?set the exact embedded source-tree digest}
EXPECTED_AWG_ENGINE_SHA256=${EXPECTED_AWG_ENGINE_SHA256:?set exact Winn AWG engine digest}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-}
EXECUTION_INVENTORY=${EXECUTION_INVENTORY:-}
EXPECTED_EXECUTION_INVENTORY_SHA256=${EXPECTED_EXECUTION_INVENTORY_SHA256:-}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/opt/winn-lab/evidence}
RUN_ID=${RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')-$RUN_TOKEN}
# AUDIT-CLOSE. The terminal checkpoint is deliberately NOT created here.
#
# This harness runs winn-carrier-server as root, and the carrier is the process
# that writes the audit trail. The checkpoint exists to constrain exactly that
# process, so a finalizer seed stored anywhere on this host would constrain
# nothing: a root writer can read any root-owned file whatever its permission
# bits, and can read its own environment. File modes and environment scrubbing
# defend against a different, lesser identity; they are worth nothing when the
# party being constrained already holds the same privilege as the credential.
#
# Finalization therefore happens on the controller, on a different machine, over
# the retrieved evidence directory — see scripts/finalize_audit_checkpoint.sh.
# The seed never exists on this host at all, which is a custody boundary the
# carrier cannot cross no matter what it runs as.
#
# What this harness owes that design is two things: the checkpoint name must
# stay out of every manifest rebuild below, and the absence of finalizer
# material on this host must be checked rather than assumed.
AUDIT_CHECKPOINT_NAME=audit-checkpoint.json
EVIDENCE_DIR=${EVIDENCE_DIR:-"$EVIDENCE_ROOT/auto-e2e-$RUN_ID"}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

if [ "$(id -u)" -ne 0 ]; then
	fail "run as root on the AICORE lab host"
fi
case "$FORCE_CARRIER" in
	"" | http3 | direct-awg) ;;
	*) fail "FORCE_CARRIER must be empty, http3, or direct-awg" ;;
esac
case "$EXPECTED_SOURCE_DIGEST" in
	"" | *[!0-9a-f]*)
		fail "EXPECTED_SOURCE_DIGEST must be lowercase hexadecimal"
		;;
esac
if [ "${#EXPECTED_SOURCE_DIGEST}" -ne 64 ]; then
	fail "EXPECTED_SOURCE_DIGEST must contain 64 hexadecimal characters"
fi
if [ -n "$EXECUTION_INVENTORY" ] ||
	[ -n "$EXPECTED_EXECUTION_INVENTORY_SHA256" ]; then
	if [ ! -f "$EXECUTION_INVENTORY" ]; then
		fail "EXECUTION_INVENTORY does not exist: $EXECUTION_INVENTORY"
	fi
	case "$EXPECTED_EXECUTION_INVENTORY_SHA256" in
	????????????????????????????????????????????????????????????????) ;;
	*) fail "expected execution inventory digest must be 64 characters" ;;
	esac
	case "$EXPECTED_EXECUTION_INVENTORY_SHA256" in
	*[!0-9a-f]*)
		fail "expected execution inventory digest must be lowercase hexadecimal"
		;;
	esac
	actual_execution_inventory_sha256=$(
		sha256sum "$EXECUTION_INVENTORY" | awk '{ print $1 }'
	)
	if [ "$actual_execution_inventory_sha256" != \
		"$EXPECTED_EXECUTION_INVENTORY_SHA256" ]; then
		fail "execution inventory digest mismatch"
	fi
	if ! sha256sum -c "$EXECUTION_INVENTORY" >/dev/null; then
		fail "an executable or frozen input differs from the execution inventory"
	fi
fi
case "$ATTEMPTS" in
	"" | *[!0-9]*)
		fail "ATTEMPTS must be a positive integer"
		;;
esac
if [ "$ATTEMPTS" -lt 1 ] || [ "$ATTEMPTS" -gt 4000 ]; then
	fail "ATTEMPTS must be within [1,4000]"
fi
case "$DIRECT_INITIAL_OUTER_DROP" in
0s)
	;;
*ms)
	drop_millis=${DIRECT_INITIAL_OUTER_DROP%ms}
	case "$drop_millis" in
	"" | *[!0-9]*)
		fail "DIRECT_INITIAL_OUTER_DROP must be 0s or integer milliseconds"
		;;
	esac
	if [ "$drop_millis" -gt 2000 ]; then
		fail "DIRECT_INITIAL_OUTER_DROP cannot exceed 2000ms"
	fi
	;;
*)
	fail "DIRECT_INITIAL_OUTER_DROP must be 0s or integer milliseconds"
	;;
esac
case "$DIRECT_CLICK_DELAY" in
0s)
	;;
*ms)
	click_delay_millis=${DIRECT_CLICK_DELAY%ms}
	case "$click_delay_millis" in
	"" | *[!0-9]*)
		fail "DIRECT_CLICK_DELAY must be 0s or integer milliseconds"
		;;
	esac
	if [ "$click_delay_millis" -gt 2000 ]; then
		fail "DIRECT_CLICK_DELAY cannot exceed 2000ms"
	fi
	;;
*)
	fail "DIRECT_CLICK_DELAY must be 0s or integer milliseconds"
	;;
esac
case "$READINESS" in
warm | cold) ;;
*) fail "READINESS must be warm or cold" ;;
esac
expected_token_count=$((3 * ATTEMPTS + 8))
if [ "$TOKEN_COUNT" -ne "$expected_token_count" ]; then
	fail "TOKEN_COUNT must be 3*ATTEMPTS+8 ($expected_token_count)"
fi
if [ -z "$PG_BINDIR" ]; then
	if command -v pg_config >/dev/null 2>&1; then
		PG_BINDIR=$(pg_config --bindir)
	else
		fail "pg_config is required; install the PostgreSQL server package"
	fi
fi
PG_INITDB=$PG_BINDIR/initdb
PG_CTL=$PG_BINDIR/pg_ctl
PG_CREATEDB=$PG_BINDIR/createdb
PG_PSQL=$PG_BINDIR/psql

for executable in "$AWG_BIN" "$AWG_ENGINE" "$IP_BIN" "$NFT_BIN" \
	"$RESOLVECTL_BIN" "$PING_BIN" "$HTTP_PROBE_BIN" "$TCPDUMP_BIN" \
	"$SYSCTL_BIN" "$TC_BIN" "$JQ_BIN" "$OPENSSL_BIN" "$RUNUSER_BIN" "$AUTO_BIN" \
	"$FIXTURE_BIN" "$CARRIER_BIN" "$PKI_BIN" "$TOKEN_ISSUER_BIN" \
	"$TOKEN_BIN" "$AUDIT_BIN" "$RESPONDER_BIN" "$PG_INITDB" \
	"$MEASUREMENT_VERIFY_BIN" "$PG_CTL" "$PG_CREATEDB" "$PG_PSQL"; do
	if [ ! -x "$executable" ]; then
		fail "required executable is missing: $executable"
	fi
done
if [ ! -f "$POSTGRES_SCHEMA" ]; then
	fail "PostgreSQL schema is missing: $POSTGRES_SCHEMA"
fi
if ! id "$PG_OS_USER" >/dev/null 2>&1; then
	fail "PostgreSQL operating-system account is missing: $PG_OS_USER"
fi
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
	fail "nft table name is too long"
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
embedded_digest=$("$AUTO_BIN" -print-source-digest)
if [ "$embedded_digest" != "$EXPECTED_SOURCE_DIGEST" ]; then
	fail "binary source digest mismatch: embedded=$embedded_digest expected=$EXPECTED_SOURCE_DIGEST"
fi
actual_awg_engine_sha=$(sha256sum "$AWG_ENGINE" | awk '{ print $1 }')
if [ "$actual_awg_engine_sha" != "$EXPECTED_AWG_ENGINE_SHA256" ]; then
	fail "Winn AWG engine digest mismatch"
fi
if [ -e "$EVIDENCE_DIR" ]; then
	fail "refusing to overwrite evidence directory: $EVIDENCE_DIR"
fi

mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
private_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-auto-e2e.XXXXXXXX")
# PostgreSQL runs as its dedicated OS account. Search permission permits it to
# reach only the explicitly owned pgdata subtree; all generated secrets remain
# mode 0600.
chmod 0711 "$private_directory"
umask 077

PKI_DIR=$private_directory/pki
FIXTURE_DIR=$private_directory/fixture
TOKEN_DIR=$private_directory/tokens
PG_DATA_DIR=$private_directory/pgdata
PG_SOCKET_DIR=$private_directory/pgsocket
PG_PASSWORD_FILE=$private_directory/postgres-password
POSTGRES_DSN_FILE=$private_directory/privacy-token-postgres.dsn
CREDENTIAL_VAULT=$private_directory/credential-vault.bin
CREDENTIAL_VAULT_KEY=$private_directory/credential-vault.key
MEASUREMENT_LOG=$EVIDENCE_DIR/attempts.jsonl
MEASUREMENT_KEY=$EVIDENCE_DIR/attempts.key
PG_PASSWORD=winn_auto_e2e_$RUN_TOKEN

SERVER_AWG_PID=""
RESPONDER_PID=""
TOKEN_ISSUER_PID=""
CARRIER_PID=""
CLIENT_CAPTURE_PID=""
SERVER_CAPTURE_PID=""
PG_STARTED=0
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
		"$NFT_BIN" --stateless list ruleset
	} >"$capture_destination" 2>&1
}

capture_namespace_diagnostics() {
	capture_namespace=$1
	capture_prefix=$2
	capture_device=$3
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
	"$IP_BIN" netns exec "$capture_namespace" "$TC_BIN" -s qdisc show \
		>"$EVIDENCE_DIR/${capture_prefix}-qdisc.txt" 2>&1 || true
	"$IP_BIN" netns exec "$capture_namespace" "$TC_BIN" -j -s -d \
		qdisc show dev "$capture_device" \
		>"$EVIDENCE_DIR/${capture_prefix}-qdisc.json" 2>&1 || true
}

validate_qdisc_evidence() {
	qdisc_file=$1
	if [ "$IMPAIRMENT_ID" = baseline ]; then
		"$JQ_BIN" -e '
			type == "array" and length > 0 and
			([.[] | select(.kind == "netem")] | length == 0)
		' "$qdisc_file" >/dev/null ||
			fail "baseline qdisc evidence contains netem or is invalid"
		return
	fi
	expected_delay_seconds=$(
		awk -v delay_ms="$ONE_WAY_DELAY_MS" \
			'BEGIN { printf "%.9f", delay_ms / 1000 }'
	)
	expected_loss_fraction=$(
		awk -v loss_percent="$PER_LEG_LOSS_PERCENT" \
			'BEGIN { printf "%.9f", loss_percent / 100 }'
	)
	expected_rate_bytes=$((CAPACITY_MBPS * 1000000 / 8))
	# $delay/$loss/$rate below are jq variables, not shell expansions.
	# shellcheck disable=SC2016
	"$JQ_BIN" -e \
		--argjson delay "$expected_delay_seconds" \
		--argjson loss "$expected_loss_fraction" \
		--argjson rate "$expected_rate_bytes" '
			[.[] | select(.kind == "netem" and .root == true)] as $netem |
			($netem | length) == 1 and
			$netem[0].packets > 0 and
			$netem[0].options.delay.delay >= ($delay - 0.000001) and
			$netem[0].options.delay.delay <= ($delay + 0.000001) and
			$netem[0].options["loss-random"].loss >= ($loss - 0.000001) and
			$netem[0].options["loss-random"].loss <= ($loss + 0.000001) and
			$netem[0].options.rate.rate == $rate
		' "$qdisc_file" >/dev/null ||
		fail "post-run qdisc evidence differs from the frozen impairment"
}

cleanup() {
	for cleanup_pid in "$CLIENT_CAPTURE_PID" "$SERVER_CAPTURE_PID" \
		"$CARRIER_PID" "$TOKEN_ISSUER_PID" "$RESPONDER_PID" \
		"$SERVER_AWG_PID"; do
		if [ -n "$cleanup_pid" ]; then
			kill "$cleanup_pid" >/dev/null 2>&1 || true
			wait "$cleanup_pid" >/dev/null 2>&1 || true
		fi
	done
	if [ "$PG_STARTED" -eq 1 ] && namespace_exists "$SERVER_NAMESPACE"; then
		server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
			"$PG_CTL" -D "$PG_DATA_DIR" -m fast -w stop \
			>/dev/null 2>&1 || true
		PG_STARTED=0
	fi
	if [ -f "$PG_DATA_DIR/postgres.log" ]; then
		cp "$PG_DATA_DIR/postgres.log" "$EVIDENCE_DIR/postgres.log" \
			>/dev/null 2>&1 || true
	fi
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
	capture_namespace_diagnostics \
		"$CLIENT_NAMESPACE" client-final "$CLIENT_VETH"
	capture_namespace_diagnostics \
		"$SERVER_NAMESPACE" server-final "$SERVER_VETH"
	cleanup
	if [ -n "$EXECUTION_INVENTORY" ] &&
		! sha256sum -c "$EXECUTION_INVENTORY" \
			>"$EVIDENCE_DIR/execution-inventory-postcheck.txt" 2>&1; then
		echo "execution inventory changed during the batch" \
			>>"$EVIDENCE_DIR/cleanup-errors.txt"
		status=1
	fi
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
	# The manifest excludes itself and the audit checkpoint. Excluding the
	# checkpoint is mandatory, not cosmetic: the checkpoint binds this
	# manifest's SHA-256, so a manifest that hashed the checkpoint would be a
	# digest cycle neither could satisfy. finalize() runs on every exit path and
	# rebuilds the manifest from whatever is on disk, so the exclusion has to
	# live here — otherwise a later exit-triggered rebuild would sweep an
	# already-sealed checkpoint into the manifest and retroactively invalidate
	# what that checkpoint attested about the manifest's hash.
	manifest_temporary="$(dirname "$EVIDENCE_DIR")/.auto-manifest-$RUN_ID.tmp"
	(
		cd "$EVIDENCE_DIR" || exit 1
		find . -type f \
			! -name evidence-manifest.sha256 \
			! -name "$AUDIT_CHECKPOINT_NAME" \
			-print0 |
			sort -z |
			xargs -0 sha256sum
	) >"$manifest_temporary"
	mv "$manifest_temporary" "$EVIDENCE_DIR/evidence-manifest.sha256"

	# The evidence leaves this host closed but not yet CLOSED-OFF: the log is
	# final and the manifest is sealed, and the controller adds the signed
	# checkpoint over both once this directory has been retrieved. Nothing here
	# may pre-create one, because a checkpoint produced on the writer's own host
	# would be signed by a credential the writer could have read.
	if [ -e "$EVIDENCE_DIR/$AUDIT_CHECKPOINT_NAME" ]; then
		echo "an audit checkpoint was created on the producing host" \
			>>"$EVIDENCE_DIR/cleanup-errors.txt"
		status=1
	fi

	# AUDIT-CLOSE. Deliberately NOT "${EVIDENCE_DIR}.tar.gz": the verifier looks
	# for that exact name, and an archive under it would be an archive of
	# evidence whose trail has never been closed. The controller writes the
	# ordinary archive after sealing and verifying the checkpoint.
	archive="${EVIDENCE_DIR}.closed-pending.tar.gz"
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
"$AUTO_BIN" -print-source-digest >"$EVIDENCE_DIR/embedded-source-digest.txt"
sha256sum "$AUTO_BIN" "$AWG_ENGINE" "$AWG_BIN" \
	"$FIXTURE_BIN" "$CARRIER_BIN" "$PKI_BIN" \
	"$TOKEN_ISSUER_BIN" "$TOKEN_BIN" "$AUDIT_BIN" "$RESPONDER_BIN" \
	"$MEASUREMENT_VERIFY_BIN" \
	>"$EVIDENCE_DIR/binaries.sha256"
if [ -n "$SOURCE_MANIFEST" ]; then
	if [ ! -f "$SOURCE_MANIFEST" ]; then
		fail "SOURCE_MANIFEST does not exist: $SOURCE_MANIFEST"
	fi
	cp "$SOURCE_MANIFEST" "$EVIDENCE_DIR/source-manifest.sha256"
fi
if [ -n "$EXECUTION_INVENTORY" ]; then
	cp "$EXECUTION_INVENTORY" "$EVIDENCE_DIR/execution-inventory.sha256"
fi
# Deliberately a fixed assignment rather than an overridable default: the same
# value is recorded in environment.txt and passed to the carrier below, and the
# verifier uses the recording to require that every authenticated carrier
# request redeemed a durable token. If this could be set from the surrounding
# environment, an identity-mode run would seal evidence claiming otherwise.
CARRIER_AUTHORIZATION_MODE=anonymous-token
{
	echo "schema=winn-auto-e2e/v1"
	echo "captured_at_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "hostname=$(hostname)"
	echo "kernel=$(uname -srmo)"
	echo "protocol_version=winn/3"
	echo "source_digest=$EXPECTED_SOURCE_DIGEST"
	echo "execution_inventory_sha256=$EXPECTED_EXECUTION_INVENTORY_SHA256"
	echo "manifest=controller-signed-v2"
	echo "transparency=append-only-receipt-plus-rollback-pin"
	echo "linux_profile=controller-signed-and-manifest-bound"
	echo "rotation=real-coordinator-state"
	echo "credential_inventory=AES-256-GCM-vault"
	echo "credential_issuance=blind-split-trust"
	echo "redemption=single-use-TLS-PostgreSQL"
	echo "carrier_authorization_mode=$CARRIER_AUTHORIZATION_MODE"
	echo "direct_preparation=real-isolated-AWG-probe"
	echo "awg_engine_sha256=$EXPECTED_AWG_ENGINE_SHA256"
	echo "awg_handshake_hedge_offsets=700ms,1100ms,1500ms,1900ms"
	echo "direct_initial_outer_drop=$DIRECT_INITIAL_OUTER_DROP"
	echo "direct_click_delay=$DIRECT_CLICK_DELAY"
	echo "force_carrier=$FORCE_CARRIER"
	echo "h3_preparation=live-anonymous-TLS1.3-QUIC-CONNECT-UDP"
	echo "tls_profile=TLS1.3 X25519+ML-KEM-768"
	echo "ech=required-and-client-acceptance-enforced"
	echo "zero_rtt=false"
	echo "click_budget=3s"
	echo "attempts=$ATTEMPTS"
	echo "readiness=$READINESS"
	echo "credential_count=$TOKEN_COUNT"
	echo "impairment_id=$IMPAIRMENT_ID"
	echo "rtt_millis=$RTT_MS"
	echo "loss_fraction=$LOSS_FRACTION"
	echo "capacity_mbps=$CAPACITY_MBPS"
	echo "one_way_delay_millis=$ONE_WAY_DELAY_MS"
	echo "per_leg_loss_percent=$PER_LEG_LOSS_PERCENT"
	echo "root_kill_switch_mutated=false"
	echo "root_routes_mutated=false"
	echo "root_nat_mutated=false"
	echo "resolvectl_scope=recorded-only"
	echo "protected_dns_probe=real-marked-socket-through-inner-AWG"
} >"$EVIDENCE_DIR/environment.txt"

"$IP_BIN" netns add "$CLIENT_NAMESPACE"
"$IP_BIN" netns add "$SERVER_NAMESPACE"
"$IP_BIN" link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
"$IP_BIN" link set "$CLIENT_VETH" netns "$CLIENT_NAMESPACE"
"$IP_BIN" link set "$SERVER_VETH" netns "$SERVER_NAMESPACE"
client_exec "$IP_BIN" link set lo up
server_exec "$IP_BIN" link set lo up
client_exec "$SYSCTL_BIN" -q -w net.ipv4.conf.all.rp_filter=0
client_exec "$SYSCTL_BIN" -q -w net.ipv4.conf.default.rp_filter=0
client_exec "$IP_BIN" address add "$OUTER_CLIENT/30" dev "$CLIENT_VETH"
server_exec "$IP_BIN" address add "$OUTER_SERVER/30" dev "$SERVER_VETH"
client_exec "$IP_BIN" link set dev "$CLIENT_VETH" up
server_exec "$IP_BIN" link set dev "$SERVER_VETH" up
if [ "$IMPAIRMENT_ID" != baseline ]; then
	client_exec "$TC_BIN" qdisc replace dev "$CLIENT_VETH" root netem \
		delay "${ONE_WAY_DELAY_MS}ms" \
		loss "${PER_LEG_LOSS_PERCENT}%" \
		rate "${CAPACITY_MBPS}mbit"
	server_exec "$TC_BIN" qdisc replace dev "$SERVER_VETH" root netem \
		delay "${ONE_WAY_DELAY_MS}ms" \
		loss "${PER_LEG_LOSS_PERCENT}%" \
		rate "${CAPACITY_MBPS}mbit"
fi
client_exec "$TC_BIN" -s qdisc show dev "$CLIENT_VETH" \
	>"$EVIDENCE_DIR/client-qdisc.txt"
server_exec "$TC_BIN" -s qdisc show dev "$SERVER_VETH" \
	>"$EVIDENCE_DIR/server-qdisc.txt"
if command -v ethtool >/dev/null 2>&1; then
	client_exec ethtool -K "$CLIENT_VETH" tx off rx off >/dev/null 2>&1 || true
	server_exec ethtool -K "$SERVER_VETH" tx off rx off >/dev/null 2>&1 || true
fi
client_exec "$PING_BIN" -n -q -c 1 -W 2 \
	-I "$CLIENT_VETH" "$OUTER_SERVER" \
	>"$EVIDENCE_DIR/impairment-warmup-ping.txt" 2>&1 || true
client_exec "$PING_BIN" -n -q -c 10 -i 0.2 -W 2 \
	-I "$CLIENT_VETH" "$OUTER_SERVER" \
	>"$EVIDENCE_DIR/impairment-ping.txt"
cat "$EVIDENCE_DIR/impairment-ping.txt"
MEASURED_RTT_MS=$(
	awk -F= '
		/^rtt / {
			gsub(/ ms/, "", $2)
			split($2, values, "/")
			print values[2]
		}
	' "$EVIDENCE_DIR/impairment-ping.txt"
)
if [ -z "$MEASURED_RTT_MS" ]; then
	fail "could not derive measured RTT from impairment calibration"
fi
if ! awk -v measured="$MEASURED_RTT_MS" -v declared="$RTT_MS" '
	BEGIN {
		if (declared == 0) {
			exit measured <= 5 ? 0 : 1
		}
		exit measured >= declared * 0.80 &&
			measured <= declared * 1.20 ? 0 : 1
	}
'; then
	fail "measured RTT $MEASURED_RTT_MS ms is outside the frozen $RTT_MS ms profile tolerance"
fi
echo "measured_rtt_millis=$MEASURED_RTT_MS" \
	>>"$EVIDENCE_DIR/environment.txt"

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
server_exec "$IP_BIN" route add "$INNER_CLIENT_POOL" dev "$SERVER_AWG_IFACE"

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$RESPONDER_BIN" -mode=server \
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

# Start a disposable private PostgreSQL cluster inside the server namespace.
# It is not a system service and is synchronously stopped and deleted by the
# harness. The carrier connects with sslmode=verify-full.
mkdir -p "$PG_DATA_DIR" "$PG_SOCKET_DIR"
chown "$PG_OS_USER:$PG_OS_USER" "$PG_DATA_DIR" "$PG_SOCKET_DIR"
printf '%s\n' "$PG_PASSWORD" >"$PG_PASSWORD_FILE"
chown "$PG_OS_USER:$PG_OS_USER" "$PG_PASSWORD_FILE"
server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	"$PG_INITDB" \
	-D "$PG_DATA_DIR" \
	--username="$PG_DATABASE_USER" \
	--pwfile="$PG_PASSWORD_FILE" \
	--auth-host=scram-sha-256 \
	--auth-local=trust \
	--no-locale \
	--encoding=UTF8 \
	>"$EVIDENCE_DIR/postgres-init.log" 2>&1
"$OPENSSL_BIN" req -x509 -newkey rsa:2048 -nodes \
	-keyout "$private_directory/postgres-server.key" \
	-out "$private_directory/postgres-server.crt" \
	-days 1 \
	-subj "/CN=winn-auto-e2e-postgres" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,digitalSignature,keyCertSign" \
	-addext "extendedKeyUsage=serverAuth" \
	>"$EVIDENCE_DIR/postgres-openssl.log" 2>&1
install -o "$PG_OS_USER" -g "$PG_OS_USER" -m 0600 \
	"$private_directory/postgres-server.key" "$PG_DATA_DIR/server.key"
install -o "$PG_OS_USER" -g "$PG_OS_USER" -m 0644 \
	"$private_directory/postgres-server.crt" "$PG_DATA_DIR/server.crt"
server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	"$PG_CTL" -D "$PG_DATA_DIR" -w start \
	-l "$PG_DATA_DIR/postgres.log" \
	-o "-c listen_addresses=127.0.0.1 -c port=$PG_PORT -c unix_socket_directories=$PG_SOCKET_DIR -c ssl=on -c ssl_cert_file=$PG_DATA_DIR/server.crt -c ssl_key_file=$PG_DATA_DIR/server.key"
PG_STARTED=1
server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	env PGPASSWORD="$PG_PASSWORD" \
	"$PG_CREATEDB" -h 127.0.0.1 -p "$PG_PORT" \
	-U "$PG_DATABASE_USER" "$PG_DATABASE"
server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	env PGPASSWORD="$PG_PASSWORD" \
	"$PG_PSQL" -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PG_PORT" \
	-U "$PG_DATABASE_USER" -d "$PG_DATABASE" \
	<"$POSTGRES_SCHEMA" >"$EVIDENCE_DIR/postgres-schema.log" 2>&1
server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	env PGPASSWORD="$PG_PASSWORD" PGSSLMODE=verify-full \
	PGSSLROOTCERT="$PG_DATA_DIR/server.crt" \
	"$PG_PSQL" -At -h 127.0.0.1 -p "$PG_PORT" \
	-U "$PG_DATABASE_USER" -d "$PG_DATABASE" \
	-c "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()" \
	>"$EVIDENCE_DIR/postgres-tls.txt"
grep -Fxq t "$EVIDENCE_DIR/postgres-tls.txt" ||
	fail "PostgreSQL verify-full TLS proof failed"
printf '%s\n' \
	"postgres://$PG_DATABASE_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT/$PG_DATABASE?sslmode=verify-full&sslrootcert=$PG_DATA_DIR/server.crt" \
	>"$POSTGRES_DSN_FILE"

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$TOKEN_ISSUER_BIN" \
	-addr "$OUTER_SERVER:$TOKEN_PORT" \
	-cert "$PKI_DIR/server.pem" \
	-key "$PKI_DIR/server-key.pem" \
	-client-ca "$PKI_DIR/ca.pem" \
	-device-registry "$PKI_DIR/device-pq-registry.json" \
	-privacy-token-private-key "$PKI_DIR/privacy-token-issuer-key.pem" \
	-ech-keys "$PKI_DIR/ech-server-keys.json" \
	-audit-log "$EVIDENCE_DIR/issuer-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	-rate-burst="$TOKEN_COUNT" \
	-rate-per-minute="$TOKEN_COUNT" \
	-insecure-cover-reuses-winn-leaf \
	>"$EVIDENCE_DIR/issuer.log" 2>&1 &
TOKEN_ISSUER_PID=$!

issue_tokens() {
	token_attempt=0
	until client_exec "$TOKEN_BIN" \
		-issuer-url "https://$OUTER_SERVER:$TOKEN_PORT/winn/v1/privacy-token" \
		-privacy-token-public-key "$PKI_DIR/privacy-token-issuer-public.pem" \
		-out-dir "$TOKEN_DIR" \
		-count "$TOKEN_COUNT" \
		-cert "$PKI_DIR/device.pem" \
		-key "$PKI_DIR/device-key.pem" \
		-root-ca "$PKI_DIR/ca.pem" \
		-server-name "$CARRIER_NAME" \
		-device-id "$DEVICE_ID" \
		-device-pq-seed "$PKI_DIR/device-mldsa65.seed" \
		-ech-config-list "$PKI_DIR/ech-config-list.bin" \
		>>"$EVIDENCE_DIR/token-client.log" 2>&1; do
		if find "$TOKEN_DIR" -type f -print -quit |
			grep -q .; then
			fail "batch token issuer failed after creating ambiguous bundles"
		fi
		if ! kill -0 "$TOKEN_ISSUER_PID" >/dev/null 2>&1; then
			fail "privacy-token issuer exited before issuance completed"
		fi
		token_attempt=$((token_attempt + 1))
		if [ "$token_attempt" -ge 120 ]; then
			fail "privacy-token issuer readiness timeout"
		fi
		sleep 0.05
	done
}

mkdir -p "$TOKEN_DIR"
issue_tokens
issued_count=$(grep -c '"event":"privacy_token_issued"' \
	"$EVIDENCE_DIR/issuer-audit.jsonl" || true)
if [ "$issued_count" -ne "$TOKEN_COUNT" ]; then
	fail "issuer audit count is $issued_count, want $TOKEN_COUNT"
fi

masque_template="https://$CARRIER_NAME:$H3_PORT/.well-known/masque/udp/{target_host}/{target_port}/"
"$FIXTURE_BIN" \
	-out "$FIXTURE_DIR" \
	-controller-pq-seed "$PKI_DIR/controller-mldsa65.seed" \
	-controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
	-privacy-token-public-key "$PKI_DIR/privacy-token-issuer-public.pem" \
	-ech-config-list "$PKI_DIR/ech-config-list.bin" \
	-psk-file "$private_directory/psk" \
	-controller-id "$CONTROLLER_ID" \
	-device-id "$DEVICE_ID" \
	-node-id "$NODE_ID" \
	-direct-transport-id "$DIRECT_TRANSPORT_ID" \
	-h3-transport-id "$H3_TRANSPORT_ID" \
	-direct-endpoint "$OUTER_SERVER:$SERVER_AWG_PORT" \
	-masque-template "$masque_template" \
	-server-name "$CARRIER_NAME" \
	-ipv4-hint "$OUTER_SERVER" \
	-fixed-backend "$OUTER_SERVER:$SERVER_AWG_PORT" \
	-gateway-public-key "$server_public" \
	-public-target "$PUBLIC_TARGET" \
	-inner-address-pool "$INNER_CLIENT_POOL" \
	-allowed-ips "$INNER_ALLOWED" \
	-verification-routes "$VERIFY_PREFIX" \
	-listen-port-min 61000 \
	-listen-port-max 61100 \
	-dns-resolver "$INNER_SERVER:$DNS_PORT" \
	-expected-dns-answers "$EXPECTED_ANSWER" \
	-canary-endpoint "$INNER_SERVER:$CANARY_PORT" \
	-lifetime 1h \
	>"$EVIDENCE_DIR/fixture.json"

"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$CARRIER_BIN" \
	-addr "$OUTER_SERVER:$H3_PORT" \
	-metrics-addr "127.0.0.1:$METRICS_PORT" \
	-awg-backend "$OUTER_SERVER:$SERVER_AWG_PORT" \
	-cert "$PKI_DIR/server.pem" \
	-key "$PKI_DIR/server-key.pem" \
	-controller-pq-seed "$PKI_DIR/controller-mldsa65.seed" \
	-controller-pq-algorithm mldsa65 \
	-audit-log "$EVIDENCE_DIR/carrier-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	-ech-keys "$PKI_DIR/ech-server-keys.json" \
	-authorization-mode "$CARRIER_AUTHORIZATION_MODE" \
	-privacy-token-postgres-dsn-file "$POSTGRES_DSN_FILE" \
	-manifest-format v2 \
	-gateway-manifest "$FIXTURE_DIR/manifest-v2.json" \
	-node-id "$NODE_ID" \
	-transport-id "$H3_TRANSPORT_ID" \
	-manifest-v2-trust-state "$FIXTURE_DIR/trust-state-v2.json" \
	-controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
	-transparency-log "$FIXTURE_DIR/transparency.jsonl" \
	-insecure-cover-reuses-winn-leaf \
	>"$EVIDENCE_DIR/carrier.log" 2>&1 &
CARRIER_PID=$!
attempt=0
until server_exec "$HTTP_PROBE_BIN" -q -O /dev/null \
	"http://127.0.0.1:$METRICS_PORT/readyz" >/dev/null 2>&1; do
	if ! kill -0 "$CARRIER_PID" >/dev/null 2>&1; then
		fail "production v2 carrier exited before readiness"
	fi
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 240 ]; then
		fail "production v2 carrier readiness timeout"
	fi
	sleep 0.05
done

head -c 32 /dev/urandom >"$CREDENTIAL_VAULT_KEY"
chmod 0600 "$CREDENTIAL_VAULT_KEY"
head -c 32 /dev/urandom >"$MEASUREMENT_KEY"
chmod 0600 "$MEASUREMENT_KEY"

"$IP_BIN" netns exec "$CLIENT_NAMESPACE" "$TCPDUMP_BIN" \
	-i any -n -vv -l -U -s 0 -c 600 \
	>"$EVIDENCE_DIR/client-tcpdump.log" 2>&1 &
CLIENT_CAPTURE_PID=$!
"$IP_BIN" netns exec "$SERVER_NAMESPACE" "$TCPDUMP_BIN" \
	-i any -n -vv -l -U -s 0 -c 600 \
	>"$EVIDENCE_DIR/server-tcpdump.log" 2>&1 &
SERVER_CAPTURE_PID=$!
sleep 0.2

set +e
client_exec "$AUTO_BIN" \
	-manifest-v2 "$FIXTURE_DIR/manifest-v2.json" \
	-node-id "$NODE_ID" \
	-transparency-log "$FIXTURE_DIR/transparency.jsonl" \
	-trust-state-v2 "$FIXTURE_DIR/trust-state-v2.json" \
	-linux-profile "$FIXTURE_DIR/linux-profile.json" \
	-controller-pq-pins "$PKI_DIR/controller-pq-pins.json" \
	-direct-transport-id "$DIRECT_TRANSPORT_ID" \
	-h3-transport-id "$H3_TRANSPORT_ID" \
	-force-carrier "$FORCE_CARRIER" \
	-device-id "$DEVICE_ID" \
	-device-pq-seed "$PKI_DIR/device-mldsa65.seed" \
	-root-ca "$PKI_DIR/ca.pem" \
	-client-private-key-file "$private_directory/client-private" \
	-rotation-state "$FIXTURE_DIR/rotation.state" \
	-applied-psk "$FIXTURE_DIR/current.psk" \
	-credential-vault "$CREDENTIAL_VAULT" \
	-credential-vault-key "$CREDENTIAL_VAULT_KEY" \
	-privacy-token-bundle-dir "$TOKEN_DIR" \
	-client-namespace "$CLIENT_NAMESPACE" \
	-table-name "$TABLE_NAME" \
	-underlay-interface "$CLIENT_VETH" \
	-direct-underlay-mark "$DIRECT_UNDERLAY_MARK" \
	-h3-underlay-mark "$H3_UNDERLAY_MARK" \
	-awg-go-binary "$AWG_ENGINE" \
	-awg-binary "$AWG_BIN" \
	-ip-binary "$IP_BIN" \
	-nft-binary "$NFT_BIN" \
	-resolvectl-binary "$RESOLVECTL_BIN" \
	-temp-root "$private_directory" \
	-direct-initial-outer-drop "$DIRECT_INITIAL_OUTER_DROP" \
	-direct-click-delay "$DIRECT_CLICK_DELAY" \
	-attempts "$ATTEMPTS" \
	-readiness "$READINESS" \
	-measurement-log "$MEASUREMENT_LOG" \
	-measurement-key "$MEASUREMENT_KEY" \
	-network-interface ethernet \
	-ip-family ipv4 \
	-nat none \
	-impairment "$IMPAIRMENT_ID" \
	-rtt-ms "$MEASURED_RTT_MS" \
	-loss-fraction "$LOSS_FRACTION" \
	-capacity-mbps "$CAPACITY_MBPS" \
	-client-region aicore-lab \
	-server-region aicore-lab \
	-server-provider private-lab \
	-hold "$HOLD" \
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

capture_namespace_diagnostics \
	"$CLIENT_NAMESPACE" client-post-run "$CLIENT_VETH"
capture_namespace_diagnostics \
	"$SERVER_NAMESPACE" server-post-run "$SERVER_VETH"
validate_qdisc_evidence "$EVIDENCE_DIR/client-post-run-qdisc.json"
validate_qdisc_evidence "$EVIDENCE_DIR/server-post-run-qdisc.json"
server_exec "$AWG_BIN" show "$SERVER_AWG_IFACE" dump \
	>"$EVIDENCE_DIR/server-awg-final.txt" 2>&1 || true

# Client teardown is synchronous locally, but the remote HTTP/3 handler can
# need one final RTT to observe stream closure and append its authenticated
# close record. Wait outside the measured connection interval before freezing
# and verifying the audit chain. This never converts a missing close into a
# pass: the exact open/close equality gate below remains unchanged.
carrier_audit_wait_started=$(date +%s)
# Quiescence budget for the carrier audit counters, not a correctness bound.
#
# The gate below is exact open/close (and auth_only/authenticated) equality; the
# "unchanged for one second" test is only a proxy for "every event has arrived".
# Lengthening this budget cannot mask a leak: a genuine mismatch never becomes
# equal however long you wait, so a short budget adds only false invalidations.
#
# Five seconds was marginal on the constrained profile (100 ms RTT, 1% loss):
# gate-6 preflight batch constrained-100ms-1pct-25mbps--warm--b001 invalidated a
# run whose 100/100 attempts had all succeeded with bounded teardown, and whose
# final counters reconciled exactly (open=100 closed=100,
# authenticated=292 = auth_only 192 + open 100). Late events kept resetting the
# stability timer until the deadline expired. A formal 80,000-attempt matrix
# would hit this at random across its slower cells.
carrier_audit_wait_deadline=$((carrier_audit_wait_started + 30))
carrier_audit_stable_signature=
carrier_audit_stable_started_ns=0
# The aborted class joins the stability set. A post-authentication abort is a
# terminal event like any other, so a late-arriving one must reset the
# quiescence timer; otherwise the conservation equality below could be
# evaluated against a trail that is still being written.
while :; do
	carrier_audit_wait_open=$(grep -c '"event":"carrier_h3_open"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_closed=$(grep -c '"event":"carrier_h3_closed"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_auth_only=$(grep -c '"event":"carrier_h3_auth_only"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_aborted=$(grep -c '"event":"carrier_h3_aborted"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_authenticated=$(grep -c \
		'"event":"carrier_h3_authenticated"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	# The same carrier process also serves H2 on the same audit log and the
	# same redemption store, so H2 events have to be quiescent too before the
	# combined redemption equality can be evaluated.
	carrier_audit_wait_h2_open=$(grep -c '"event":"carrier_h2_open"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_h2_closed=$(grep -c '"event":"carrier_h2_closed"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_h2_aborted=$(grep -c '"event":"carrier_h2_aborted"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_h2_authenticated=$(grep -c \
		'"event":"carrier_h2_authenticated"' \
		"$EVIDENCE_DIR/carrier-audit.jsonl" || true)
	carrier_audit_wait_total=$((carrier_audit_wait_authenticated +
		carrier_audit_wait_h2_authenticated))
	carrier_audit_wait_terminal=$((carrier_audit_wait_auth_only +
		carrier_audit_wait_open + carrier_audit_wait_aborted +
		carrier_audit_wait_h2_open + carrier_audit_wait_h2_aborted))
	carrier_audit_wait_signature="$carrier_audit_wait_open/$carrier_audit_wait_closed/$carrier_audit_wait_auth_only/$carrier_audit_wait_aborted/$carrier_audit_wait_authenticated/$carrier_audit_wait_h2_open/$carrier_audit_wait_h2_closed/$carrier_audit_wait_h2_aborted/$carrier_audit_wait_h2_authenticated"
	if [ "$carrier_audit_wait_total" -ge "$ATTEMPTS" ] &&
		[ "$carrier_audit_wait_closed" -eq "$carrier_audit_wait_open" ] &&
		[ "$carrier_audit_wait_h2_closed" -eq "$carrier_audit_wait_h2_open" ] &&
		[ "$carrier_audit_wait_terminal" -eq "$carrier_audit_wait_total" ]; then
		carrier_audit_now_ns=$(date +%s%N)
		if [ "$carrier_audit_wait_signature" != "$carrier_audit_stable_signature" ]; then
			carrier_audit_stable_signature=$carrier_audit_wait_signature
			carrier_audit_stable_started_ns=$carrier_audit_now_ns
		elif [ $((carrier_audit_now_ns - carrier_audit_stable_started_ns)) \
			-ge 1000000000 ]; then
			break
		fi
	else
		carrier_audit_stable_signature=
		carrier_audit_stable_started_ns=0
	fi
	if [ "$(date +%s)" -ge "$carrier_audit_wait_deadline" ]; then
		fail "carrier audit counters did not converge on an exact conservation within the 30-second quiescence budget; final counts were h3 open=$carrier_audit_wait_open closed=$carrier_audit_wait_closed auth_only=$carrier_audit_wait_auth_only aborted=$carrier_audit_wait_aborted authenticated=$carrier_audit_wait_authenticated, h2 open=$carrier_audit_wait_h2_open closed=$carrier_audit_wait_h2_closed aborted=$carrier_audit_wait_h2_aborted authenticated=$carrier_audit_wait_h2_authenticated"
	fi
	sleep 0.05
done
carrier_audit_wait_finished=$(date +%s)
printf 'started_unix=%s\nfinished_unix=%s\nauthenticated=%s\nauth_only=%s\nopen=%s\nclosed=%s\naborted=%s\ntotal_authenticated=%s\n' \
	"$carrier_audit_wait_started" \
	"$carrier_audit_wait_finished" \
	"$carrier_audit_wait_authenticated" \
	"$carrier_audit_wait_auth_only" \
	"$carrier_audit_wait_open" \
	"$carrier_audit_wait_closed" \
	"$carrier_audit_wait_aborted" \
	"$carrier_audit_wait_total" \
	>"$EVIDENCE_DIR/carrier-audit-convergence.txt"

"$AUDIT_BIN" \
	-audit-log "$EVIDENCE_DIR/issuer-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	>"$EVIDENCE_DIR/issuer-audit-verify.log" 2>&1
"$AUDIT_BIN" \
	-audit-log "$EVIDENCE_DIR/carrier-audit.jsonl" \
	-audit-key "$PKI_DIR/audit.key" \
	>"$EVIDENCE_DIR/carrier-audit-verify.log" 2>&1
"$MEASUREMENT_VERIFY_BIN" \
	-log "$MEASUREMENT_LOG" \
	-key "$MEASUREMENT_KEY" \
	-expected-count "$ATTEMPTS" \
	>"$EVIDENCE_DIR/measurement-verify.log" 2>&1

if [ "$client_status" -ne 0 ]; then
	fail "production Auto client failed with status $client_status"
fi
grep -Fq 'protocol_version=winn/3' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks Winn v3 protocol marker"
prepared_count=$(grep -c 'AUTO_PREPARED attempt=' \
	"$EVIDENCE_DIR/client.log" || true)
online_count=$(grep -c 'AUTO_ONLINE attempt=' \
	"$EVIDENCE_DIR/client.log" || true)
failed_count=$(grep -c 'AUTO_FAILED attempt=' \
	"$EVIDENCE_DIR/client.log" || true)
outcome_count=$((online_count + failed_count))
teardown_count=$(grep -c 'AUTO_BOUNDED_TEARDOWN_OK attempt=' \
	"$EVIDENCE_DIR/client.log" || true)
if [ "$outcome_count" -ne "$ATTEMPTS" ]; then
	fail "client log has $outcome_count terminal outcomes, want $ATTEMPTS"
fi
if [ "$prepared_count" -gt 0 ]; then
	grep -Fq 'anonymous_vault=true rotation_psk=true live_h3=true' \
		"$EVIDENCE_DIR/client.log" ||
		fail "prepared client log lacks real vault/rotation/H3 proof"
fi
if [ "$online_count" -gt 0 ]; then
	grep -Fq 'fresh_awg=true bidirectional=true protected_dns=true canary=true' \
		"$EVIDENCE_DIR/client.log" ||
		fail "Online client log lacks all four predicates"
fi
if [ "$teardown_count" -ne "$prepared_count" ]; then
	fail "client log has $teardown_count teardown proofs for $prepared_count prepared attempts"
fi
grep -Fq 'AUTO_BATCH_SUMMARY requested=' "$EVIDENCE_DIR/client.log" ||
	fail "client log lacks the authenticated batch summary"
case "$HOLD" in
0 | 0s | 0ms)
	;;
*)
	grep -Fq "AUTO_HEALTH_HOLD_OK attempt=1/1 duration=$HOLD" \
		"$EVIDENCE_DIR/client.log" ||
		fail "client log lacks the requested post-commit health hold proof"
	;;
esac
measurement_count=$(wc -l <"$MEASUREMENT_LOG" | tr -d '[:space:]')
if [ "$measurement_count" -ne "$ATTEMPTS" ]; then
	fail "measurement count is $measurement_count, want $ATTEMPTS"
fi

# Carrier conservation law.
#
# A request that redeems a single-use privacy token creates a durable database
# row before the carrier has produced any HTTP result. It may still fail
# afterwards, but it may not vanish from the sealed audit trail. Every
# authenticated request therefore reaches exactly one mutually exclusive
# terminal class — auth_only, open, or aborted — and the counts reconcile
# exactly:
#
#   durable redemptions == anonymous authenticated events
#   authenticated       == auth_only + open + aborted   (per carrier)
#   open                == closed                       (per carrier)
#
# The bounds that used to stand in for this equality are kept below as
# secondary sanity checks on the *shape* of the run. They are no longer the
# reconciliation: an equality that only holds within a range is not a
# conservation law, and the previous defect was exactly a denominator that
# silently absorbed post-authentication failures.
carrier_event_count() {
	grep -c "\"event\":\"$1\"" "$EVIDENCE_DIR/carrier-audit.jsonl" || true
}
h3_open_count=$(carrier_event_count carrier_h3_open)
h3_closed_count=$(carrier_event_count carrier_h3_closed)
h3_auth_only_count=$(carrier_event_count carrier_h3_auth_only)
h3_aborted_count=$(carrier_event_count carrier_h3_aborted)
h3_authenticated_count=$(carrier_event_count carrier_h3_authenticated)
h2_open_count=$(carrier_event_count carrier_h2_open)
h2_closed_count=$(carrier_event_count carrier_h2_closed)
h2_aborted_count=$(carrier_event_count carrier_h2_aborted)
h2_authenticated_count=$(carrier_event_count carrier_h2_authenticated)
# The H2 carrier has no authenticate-only preparation class; it is counted as
# zero so the same equation shape applies to both carriers.
h2_auth_only_count=0
# Only anonymous-token authentications redeem a durable token. The mode is
# sealed in each authenticated record's detail, so this is read from the trail
# rather than assumed from the harness configuration.
anonymous_authenticated_count=$(grep -c \
	'"event":"carrier_h[23]_authenticated".*mode=anonymous-token ' \
	"$EVIDENCE_DIR/carrier-audit.jsonl" || true)

server_exec "$RUNUSER_BIN" -u "$PG_OS_USER" -- \
	env PGPASSWORD="$PG_PASSWORD" PGSSLMODE=verify-full \
	PGSSLROOTCERT="$PG_DATA_DIR/server.crt" \
	"$PG_PSQL" -At -h 127.0.0.1 -p "$PG_PORT" \
	-U "$PG_DATABASE_USER" -d "$PG_DATABASE" \
	-c "SELECT count(*) FROM winn_privacy_token_redemptions" \
	>"$EVIDENCE_DIR/redemption-count.txt"
redemption_count=$(tr -d '[:space:]' <"$EVIDENCE_DIR/redemption-count.txt")

# Seal the reconciliation the harness actually performed, before asserting on
# it, so a failing run still carries its numbers and so the offline verifier
# can reject any batch whose sealed claim disagrees with its own recount of
# carrier-audit.jsonl. Written before the assertions because finalize() builds
# evidence-manifest.sha256 from whatever is on disk at exit.
printf 'schema=carrier-terminal/v1\nredemptions=%s\nanonymous_authenticated=%s\nh3_authenticated=%s\nh3_auth_only=%s\nh3_open=%s\nh3_closed=%s\nh3_aborted=%s\nh2_authenticated=%s\nh2_auth_only=%s\nh2_open=%s\nh2_closed=%s\nh2_aborted=%s\n' \
	"$redemption_count" \
	"$anonymous_authenticated_count" \
	"$h3_authenticated_count" \
	"$h3_auth_only_count" \
	"$h3_open_count" \
	"$h3_closed_count" \
	"$h3_aborted_count" \
	"$h2_authenticated_count" \
	"$h2_auth_only_count" \
	"$h2_open_count" \
	"$h2_closed_count" \
	"$h2_aborted_count" \
	>"$EVIDENCE_DIR/carrier-conservation.txt"

h3_terminal_count=$((h3_auth_only_count + h3_open_count + h3_aborted_count))
h2_terminal_count=$((h2_auth_only_count + h2_open_count + h2_aborted_count))
if [ "$h3_authenticated_count" -ne "$h3_terminal_count" ] ||
	[ "$h3_closed_count" -ne "$h3_open_count" ]; then
	fail "H3 carrier conservation failed: authenticated=$h3_authenticated_count auth_only=$h3_auth_only_count open=$h3_open_count aborted=$h3_aborted_count closed=$h3_closed_count"
fi
if [ "$h2_authenticated_count" -ne "$h2_terminal_count" ] ||
	[ "$h2_closed_count" -ne "$h2_open_count" ]; then
	fail "H2 carrier conservation failed: authenticated=$h2_authenticated_count open=$h2_open_count aborted=$h2_aborted_count closed=$h2_closed_count"
fi
if [ "$redemption_count" -ne "$anonymous_authenticated_count" ]; then
	fail "durable redemption count $redemption_count differs from anonymous authenticated carrier requests $anonymous_authenticated_count"
fi

# Secondary sanity checks on the shape of the run. These never substitute for
# the equalities above.
#
# A failed cold preparation can authenticate both of its anonymous H3
# preparation requests before another candidate makes the whole assembly fail.
# Those durable redemptions remain valid evidence even though no Attempt object
# was returned, so bound auth-only events by requested—not prepared—attempts.
maximum_auth_only_count=$((2 * ATTEMPTS))
maximum_h3_count=$((maximum_auth_only_count + prepared_count))
if [ "$h3_auth_only_count" -lt "$prepared_count" ] ||
	[ "$h3_auth_only_count" -gt "$maximum_auth_only_count" ] ||
	[ "$h3_open_count" -gt "$prepared_count" ] ||
	[ "$h3_authenticated_count" -gt "$maximum_h3_count" ]; then
	fail "carrier audit has implausible H3 counts: auth_only=$h3_auth_only_count open=$h3_open_count aborted=$h3_aborted_count total=$h3_authenticated_count"
fi
if client_exec "$NFT_BIN" list table inet "$TABLE_NAME" >/dev/null 2>&1; then
	fail "candidate nft table remains after client teardown"
fi
if client_exec "$IP_BIN" -o link show |
	grep -E 'winn[0-9a-f]{10}' >/dev/null 2>&1; then
	fail "candidate AWG interface remains after client teardown"
fi

echo "PASS: signed production Auto preparation, real rotation and encrypted blind-token inventory, TLS PostgreSQL single-use redemption, live DirectAWG plus prepared anonymous H3, verified sub-three-second Online, and bounded residue-free teardown"
