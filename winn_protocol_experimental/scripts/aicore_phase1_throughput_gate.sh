#!/bin/sh
set -eu

# Acceptance-grade Phase-1 throughput gate.
#
# Policy:
#   * Run at least 10 back-to-back raw-AWG/Winn pairs against the exact same
#     gateway.
#   * Use a balanced cryptographically randomized order plan, archived before
#     the first pair starts.
#   * Exercise Winn's production direct-AWG Candidate/Connection path.
#   * Archive stdout, stderr, raw iperf3 JSON, GNU time CPU/RSS data,
#     environment snapshots, exact executable/script hashes, and per-pair JSON.
#   * Fail unless EVERY paired Winn/raw-AWG ratio is at least 90%. This is
#     deliberately stricter and less ambiguous than passing on an average.
#   * Fail closed on a missing marker, mismatched gateway, missing raw JSON,
#     malformed metric, child error, teardown residue, or changed host route/
#     forwarding state.
#
# Child-script evidence contract (required before any paid test begins):
#
# Baseline stdout:
#   THROUGHPUT_ROLE=baseline
#   THROUGHPUT_PATH=raw-awg
# Winn stdout:
#   THROUGHPUT_ROLE=winn
#   THROUGHPUT_PATH=production-directawg-candidate-v1
# Both stdout streams:
#   THROUGHPUT_GATEWAY_ENDPOINT=<exact GATEWAY_ENDPOINT>
#   THROUGHPUT_GATEWAY_INNER_IP=<exact GATEWAY_INNER_IP>
#   THROUGHPUT_IPERF_JSON_SHA256=<sha256 of IPERF_JSON_OUT>
# Each child must honor IPERF_JSON_OUT by atomically copying its successful raw
# iperf3 JSON there before private cleanup. The analyzer cross-checks that JSON
# against the child-reported Mbps value.

SCRIPT_DIR=$(dirname -- "$0")
SCRIPT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR" && pwd)
ORCHESTRATOR_PATH="$SCRIPT_DIR/$(basename -- "$0")"

PYTHON_BIN=${PYTHON_BIN:-/usr/bin/python3}
TIME_BIN=${TIME_BIN:-/usr/bin/time}
SHA256_BIN=${SHA256_BIN:-/usr/bin/sha256sum}
IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
SETSID_BIN=${SETSID_BIN:-/usr/bin/setsid}

ANALYZER=${ANALYZER:-"$SCRIPT_DIR/analyze_phase1_throughput.py"}
BASELINE_SCRIPT=${BASELINE_SCRIPT:-"$SCRIPT_DIR/aicore_awg_baseline_throughput.sh"}
WINN_SCRIPT=${WINN_SCRIPT:-"$SCRIPT_DIR/aicore_throughput_compare.sh"}

PAIRS=${PAIRS:-10}
GATE_PERCENT=${GATE_PERCENT:-90}
PAIR_COOLDOWN_SECONDS=${PAIR_COOLDOWN_SECONDS:-2}
IPERF_SECONDS=${IPERF_SECONDS:-8}
IPERF_OMIT_SECONDS=${IPERF_OMIT_SECONDS:-3}
IPERF_STREAMS=${IPERF_STREAMS:-4}
HOLD_SECONDS=${HOLD_SECONDS:-30}
REQUIRE_RAW_IPERF_JSON=${REQUIRE_RAW_IPERF_JSON:-1}
ARCHIVE_ROOT=${ARCHIVE_ROOT:-/opt/winn-lab/measurements/phase1-throughput}

EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE}
GATEWAY_NAME=${GATEWAY_NAME:?must set GATEWAY_NAME}
GATEWAY_ENDPOINT=${GATEWAY_ENDPOINT:?must set GATEWAY_ENDPOINT}
GATEWAY_PUBKEY=${GATEWAY_PUBKEY:?must set GATEWAY_PUBKEY}
GATEWAY_INNER_IP=${GATEWAY_INNER_IP:-10.203.1.1}
CLIENT_PRIVATE_KEY_FILE=${CLIENT_PRIVATE_KEY_FILE:?must set CLIENT_PRIVATE_KEY_FILE}
PSK_FILE=${PSK_FILE:?must set PSK_FILE}

AWG_BIN=${AWG_BIN:-/opt/winn-lab/bin/awg}
AWG_ENGINE=${AWG_ENGINE:-/opt/winn-lab/bin/amneziawg-go}
ACCEPTANCE_BIN=${ACCEPTANCE_BIN:-/opt/winn-lab/bin/winn-acceptance}
IPERF3_BIN=${IPERF3_BIN:-/usr/bin/iperf3}

umask 077
RUN_DIRECTORY=""
CURRENT_CHILD_PGID=""
COMPLETED=0
LOCK_DIRECTORY=""

write_status() {
	status=$1
	detail=$2
	if [ -n "$RUN_DIRECTORY" ] && [ -d "$RUN_DIRECTORY" ]; then
		{
			echo "status=$status"
			echo "detail=$detail"
			date -u '+updated_at=%Y-%m-%dT%H:%M:%SZ'
		} >"$RUN_DIRECTORY/STATUS"
	fi
}

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$CURRENT_CHILD_PGID" ]; then
		kill -TERM -- "-$CURRENT_CHILD_PGID" >/dev/null 2>&1 || true
		wait "$CURRENT_CHILD_PGID" >/dev/null 2>&1 || true
		CURRENT_CHILD_PGID=""
	fi
	if [ "$COMPLETED" -ne 1 ]; then
		write_status "FAIL" "orchestrator exited before a passing gate"
	fi
	if [ -n "$LOCK_DIRECTORY" ]; then
		rmdir "$LOCK_DIRECTORY" >/dev/null 2>&1 || true
	fi
	exit "$status"
}

on_signal() {
	exit 130
}

trap cleanup EXIT
trap on_signal HUP INT TERM

fail() {
	echo "THROUGHPUT GATE ERROR: $*" >&2
	exit 1
}

case "$PAIRS" in
	''|*[!0-9]*) fail "PAIRS must be an integer" ;;
esac
if [ "$PAIRS" -lt 10 ]; then
	fail "PAIRS must be at least 10"
fi
case "$IPERF_SECONDS" in
	''|*[!0-9]*) fail "IPERF_SECONDS must be a positive integer" ;;
esac
case "$IPERF_OMIT_SECONDS" in
	''|*[!0-9]*) fail "IPERF_OMIT_SECONDS must be a non-negative integer" ;;
esac
case "$IPERF_STREAMS" in
	''|*[!0-9]*) fail "IPERF_STREAMS must be a positive integer" ;;
esac
case "$HOLD_SECONDS" in
	''|*[!0-9]*) fail "HOLD_SECONDS must be a positive integer" ;;
esac
if [ "$IPERF_SECONDS" -lt 1 ]; then
	fail "IPERF_SECONDS must be positive"
fi
if [ "$IPERF_STREAMS" -lt 1 ]; then
	fail "IPERF_STREAMS must be positive"
fi
minimum_hold=$((IPERF_OMIT_SECONDS + IPERF_SECONDS + 10))
if [ "$HOLD_SECONDS" -lt "$minimum_hold" ]; then
	fail "HOLD_SECONDS must be at least IPERF_OMIT_SECONDS + IPERF_SECONDS + 10"
fi
case "$PAIR_COOLDOWN_SECONDS" in
	''|*[!0-9]*) fail "PAIR_COOLDOWN_SECONDS must be a non-negative integer" ;;
esac
case "$REQUIRE_RAW_IPERF_JSON" in
	0|1) ;;
	*) fail "REQUIRE_RAW_IPERF_JSON must be 0 or 1" ;;
esac
if [ "$(id -u)" -ne 0 ]; then
	fail "run as root on the disposable AICORE lab host"
fi

for executable in \
	"$PYTHON_BIN" "$TIME_BIN" "$SHA256_BIN" "$IP_BIN" "$NFT_BIN" \
	"$SETSID_BIN" "$AWG_BIN" "$AWG_ENGINE" \
	"$ACCEPTANCE_BIN" "$IPERF3_BIN" "$BASELINE_SCRIPT" "$WINN_SCRIPT"
do
	if [ ! -x "$executable" ]; then
		fail "required executable is missing: $executable"
	fi
done
if [ ! -r "$ANALYZER" ]; then
	fail "analyzer is missing or unreadable: $ANALYZER"
fi
for credential in "$CLIENT_PRIVATE_KEY_FILE" "$PSK_FILE"; do
	if [ ! -f "$credential" ] || [ ! -r "$credential" ]; then
		fail "required credential file is missing or unreadable"
	fi
done
if ! "$IP_BIN" link show dev "$EGRESS_INTERFACE" >/dev/null 2>&1; then
	fail "egress interface does not exist: $EGRESS_INTERFACE"
fi

# Refuse to spend test time when either child lacks the evidence contract.
require_source_marker() {
	script=$1
	marker=$2
	if ! grep -F "$marker" "$script" >/dev/null 2>&1; then
		fail "$script does not implement required contract marker: $marker"
	fi
}

require_source_marker "$BASELINE_SCRIPT" 'THROUGHPUT_ROLE=baseline'
require_source_marker "$BASELINE_SCRIPT" 'THROUGHPUT_PATH=raw-awg'
require_source_marker "$WINN_SCRIPT" 'THROUGHPUT_ROLE=winn'
require_source_marker "$WINN_SCRIPT" 'THROUGHPUT_PATH=production-directawg-candidate-v1'
require_source_marker "$BASELINE_SCRIPT" 'THROUGHPUT_GATEWAY_ENDPOINT='
require_source_marker "$WINN_SCRIPT" 'THROUGHPUT_GATEWAY_ENDPOINT='
require_source_marker "$BASELINE_SCRIPT" 'THROUGHPUT_GATEWAY_INNER_IP='
require_source_marker "$WINN_SCRIPT" 'THROUGHPUT_GATEWAY_INNER_IP='
if grep -F 'winn-aicore-directawg-e2e' "$WINN_SCRIPT" >/dev/null 2>&1; then
	fail "Winn child still references the non-production E2E relay"
fi
require_source_marker "$WINN_SCRIPT" 'ACCEPTANCE_BIN'
require_source_marker "$WINN_SCRIPT" 'online-hold'
if [ "$REQUIRE_RAW_IPERF_JSON" -eq 1 ]; then
	require_source_marker "$BASELINE_SCRIPT" 'IPERF_JSON_OUT'
	require_source_marker "$WINN_SCRIPT" 'IPERF_JSON_OUT'
	require_source_marker "$BASELINE_SCRIPT" 'THROUGHPUT_IPERF_JSON_SHA256='
	require_source_marker "$WINN_SCRIPT" 'THROUGHPUT_IPERF_JSON_SHA256='
fi

mkdir -p "$ARCHIVE_ROOT"
chmod 0700 "$ARCHIVE_ROOT"
LOCK_DIRECTORY="$ARCHIVE_ROOT/.phase1-throughput.lock"
if ! mkdir -m 0700 "$LOCK_DIRECTORY" 2>/dev/null; then
	fail "another Phase-1 throughput gate appears active: $LOCK_DIRECTORY"
fi

created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
random_suffix=$(
	"$PYTHON_BIN" -c 'import secrets; print(secrets.token_hex(6))'
)
run_timestamp=$(date -u '+%Y%m%dT%H%M%SZ')
run_id="${run_timestamp}-${random_suffix}"
RUN_DIRECTORY="$ARCHIVE_ROOT/$run_id"
if ! mkdir -m 0700 "$RUN_DIRECTORY"; then
	fail "cannot create unique archive directory: $RUN_DIRECTORY"
fi
write_status "RUNNING" "paired measurements have not completed"

snapshot_environment() {
	output=$1
	{
		echo "captured_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "hostname=$(hostname)"
		echo "egress_interface=$EGRESS_INTERFACE"
		echo "gateway_name=$GATEWAY_NAME"
		echo "gateway_endpoint=$GATEWAY_ENDPOINT"
		echo "gateway_inner_ip=$GATEWAY_INNER_IP"
		echo "pairs=$PAIRS"
		echo "gate_percent=$GATE_PERCENT"
		echo "iperf_seconds=$IPERF_SECONDS"
		echo "iperf_omit_seconds=$IPERF_OMIT_SECONDS"
		echo "iperf_streams=$IPERF_STREAMS"
		echo "hold_seconds=$HOLD_SECONDS"
		echo "credential_files_present=true"
		uname -a
		if command -v lscpu >/dev/null 2>&1; then
			lscpu
		fi
		if command -v free >/dev/null 2>&1; then
			free -b
		fi
		"$IPERF3_BIN" --version 2>&1
		"$IP_BIN" -brief link show
		"$IP_BIN" -brief address show dev "$EGRESS_INTERFACE"
		"$IP_BIN" route show default
		"$IP_BIN" -6 route show default
		echo "net.ipv4.ip_forward=$(sysctl -n net.ipv4.ip_forward)"
		echo "net.ipv6.conf.all.forwarding=$(sysctl -n net.ipv6.conf.all.forwarding)"
		"$IP_BIN" netns list
		"$NFT_BIN" list tables
		echo "managed_processes:"
		ps -eo pid=,args= | awk '
			/amneziawg-go/ || /winn-acceptance/ {
				if ($0 !~ /awk/) print
			}
		'
	} >"$output"
}

snapshot_managed_processes() {
	ps -eo pid=,args= | awk '
		/amneziawg-go/ || /winn-acceptance/ {
			if ($0 !~ /awk/) print
		}
	' | sort
}

DEFAULT_ROUTE_BEFORE=$("$IP_BIN" route show default)
DEFAULT_ROUTE6_BEFORE=$("$IP_BIN" -6 route show default)
IP_FORWARD_BEFORE=$(sysctl -n net.ipv4.ip_forward)
IP6_FORWARD_BEFORE=$(sysctl -n net.ipv6.conf.all.forwarding)
snapshot_managed_processes >"$RUN_DIRECTORY/managed-processes.before.txt"
snapshot_environment "$RUN_DIRECTORY/environment.before.txt"

manifest_arguments=""
if [ "$REQUIRE_RAW_IPERF_JSON" -eq 1 ]; then
	manifest_arguments="--require-raw-json"
fi
# shellcheck disable=SC2086
"$PYTHON_BIN" "$ANALYZER" manifest \
	--run-id "$run_id" \
	--created-at "$created_at" \
	--expected-pairs "$PAIRS" \
	--gate-percent "$GATE_PERCENT" \
	--gateway-name "$GATEWAY_NAME" \
	--gateway-endpoint "$GATEWAY_ENDPOINT" \
	--gateway-inner-ip "$GATEWAY_INNER_IP" \
	$manifest_arguments \
	--file "orchestrator=$ORCHESTRATOR_PATH" \
	--file "analyzer=$ANALYZER" \
	--file "baseline_child=$BASELINE_SCRIPT" \
	--file "winn_child=$WINN_SCRIPT" \
	--file "awg=$AWG_BIN" \
	--file "awg_engine=$AWG_ENGINE" \
	--file "acceptance_binary=$ACCEPTANCE_BIN" \
	--file "iperf3=$IPERF3_BIN" \
	--file "environment_before=$RUN_DIRECTORY/environment.before.txt" \
	--output "$RUN_DIRECTORY/manifest.json"

"$PYTHON_BIN" "$ANALYZER" schedule \
	--pairs "$PAIRS" \
	--output "$RUN_DIRECTORY/order-plan.json"

assert_host_restored() {
	pair_label=$1
	baseline_iface=$2
	client_namespace=$3
	root_veth=$4
	nat_table=$5
	before_processes=$6
	after_processes=$7

	if "$IP_BIN" link show dev "$baseline_iface" >/dev/null 2>&1; then
		fail "$pair_label left baseline interface $baseline_iface"
	fi
	if "$IP_BIN" netns list | awk '{ print $1 }' | grep -Fx "$client_namespace" >/dev/null 2>&1; then
		fail "$pair_label left namespace $client_namespace"
	fi
	if "$IP_BIN" link show dev "$root_veth" >/dev/null 2>&1; then
		fail "$pair_label left root veth $root_veth"
	fi
	if "$NFT_BIN" list table ip "$nat_table" >/dev/null 2>&1; then
		fail "$pair_label left NAT table $nat_table"
	fi
	if [ "$("$IP_BIN" route show default)" != "$DEFAULT_ROUTE_BEFORE" ]; then
		fail "$pair_label changed the IPv4 default route"
	fi
	if [ "$("$IP_BIN" -6 route show default)" != "$DEFAULT_ROUTE6_BEFORE" ]; then
		fail "$pair_label changed the IPv6 default route"
	fi
	if [ "$(sysctl -n net.ipv4.ip_forward)" != "$IP_FORWARD_BEFORE" ]; then
		fail "$pair_label did not restore net.ipv4.ip_forward"
	fi
	if [ "$(sysctl -n net.ipv6.conf.all.forwarding)" != "$IP6_FORWARD_BEFORE" ]; then
		fail "$pair_label did not restore IPv6 forwarding"
	fi
	if ! cmp -s "$before_processes" "$after_processes"; then
		diff -u "$before_processes" "$after_processes" \
			>"$pair_label/managed-processes.diff" 2>&1 || true
		fail "$pair_label changed the managed process set"
	fi
}

run_child() {
	role=$1
	script=$2
	pair_directory=$3
	baseline_iface=$4
	client_namespace=$5
	client_veth=$6
	root_veth=$7
	table_name=$8
	nat_table=$9
	underlay_mark=${10}

	stdout_path="$pair_directory/$role.stdout"
	stderr_path="$pair_directory/$role.stderr"
	time_path="$pair_directory/$role.time.txt"
	raw_json_path="$pair_directory/$role.iperf3.json"
	exit_path="$pair_directory/$role.exit"
	started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

	set +e
	"$SETSID_BIN" --wait "$TIME_BIN" -v -o "$time_path" \
		env \
		IP_BIN="$IP_BIN" \
		NFT_BIN="$NFT_BIN" \
		AWG_BIN="$AWG_BIN" \
		AWG_ENGINE="$AWG_ENGINE" \
		ACCEPTANCE_BIN="$ACCEPTANCE_BIN" \
		IPERF3_BIN="$IPERF3_BIN" \
		EGRESS_INTERFACE="$EGRESS_INTERFACE" \
		GATEWAY_NAME="$GATEWAY_NAME" \
		GATEWAY_ENDPOINT="$GATEWAY_ENDPOINT" \
		GATEWAY_PUBKEY="$GATEWAY_PUBKEY" \
		GATEWAY_INNER_IP="$GATEWAY_INNER_IP" \
		CLIENT_PRIVATE_KEY_FILE="$CLIENT_PRIVATE_KEY_FILE" \
		PSK_FILE="$PSK_FILE" \
		IPERF_SECONDS="$IPERF_SECONDS" \
		IPERF_OMIT_SECONDS="$IPERF_OMIT_SECONDS" \
		IPERF_STREAMS="$IPERF_STREAMS" \
		HOLD_SECONDS="$HOLD_SECONDS" \
		IPERF_JSON_OUT="$raw_json_path" \
		IFACE="$baseline_iface" \
		CLIENT_NAMESPACE="$client_namespace" \
		CLIENT_VETH="$client_veth" \
		ROOT_VETH="$root_veth" \
		TABLE_NAME="$table_name" \
		NAT_TABLE="$nat_table" \
		UNDERLAY_MARK="$underlay_mark" \
		"$script" >"$stdout_path" 2>"$stderr_path" &
	CURRENT_CHILD_PGID=$!
	wait "$CURRENT_CHILD_PGID"
	child_status=$?
	CURRENT_CHILD_PGID=""
	set -e

	{
		echo "role=$role"
		echo "started_at=$started_at"
		echo "finished_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "exit_status=$child_status"
	} >"$exit_path"
	if [ "$child_status" -ne 0 ]; then
		fail "$role child failed with status $child_status; see $pair_directory"
	fi
}

pair_index=1
while [ "$pair_index" -le "$PAIRS" ]; do
	pair_number=$(printf '%03d' "$pair_index")
	pair_directory="$RUN_DIRECTORY/pair-$pair_number"
	mkdir -m 0700 "$pair_directory"
	order=$(
		"$PYTHON_BIN" "$ANALYZER" order \
			--schedule "$RUN_DIRECTORY/order-plan.json" \
			--pair-index "$pair_index"
	)
	echo "PAIR $pair_index/$PAIRS order=$order"
	echo "$order" >"$pair_directory/order.txt"

	baseline_iface="wpb$pair_number"
	client_namespace="wpt${pair_number}n"
	client_veth="wpt${pair_number}c"
	root_veth="wpt${pair_number}r"
	table_name="wpt${pair_number}"
	nat_table="wpt${pair_number}nat"
	underlay_mark=$((12000 + pair_index))

	if "$IP_BIN" link show dev "$baseline_iface" >/dev/null 2>&1; then
		fail "pre-existing baseline interface: $baseline_iface"
	fi
	if "$IP_BIN" netns list | awk '{ print $1 }' | grep -Fx "$client_namespace" >/dev/null 2>&1; then
		fail "pre-existing namespace: $client_namespace"
	fi
	snapshot_managed_processes >"$pair_directory/managed-processes.before.txt"

	if [ "$order" = "baseline-first" ]; then
		run_child baseline "$BASELINE_SCRIPT" "$pair_directory" \
			"$baseline_iface" "$client_namespace" "$client_veth" \
			"$root_veth" "$table_name" "$nat_table" "$underlay_mark"
		sleep "$PAIR_COOLDOWN_SECONDS"
		run_child winn "$WINN_SCRIPT" "$pair_directory" \
			"$baseline_iface" "$client_namespace" "$client_veth" \
			"$root_veth" "$table_name" "$nat_table" "$underlay_mark"
	else
		run_child winn "$WINN_SCRIPT" "$pair_directory" \
			"$baseline_iface" "$client_namespace" "$client_veth" \
			"$root_veth" "$table_name" "$nat_table" "$underlay_mark"
		sleep "$PAIR_COOLDOWN_SECONDS"
		run_child baseline "$BASELINE_SCRIPT" "$pair_directory" \
			"$baseline_iface" "$client_namespace" "$client_veth" \
			"$root_veth" "$table_name" "$nat_table" "$underlay_mark"
	fi

	snapshot_managed_processes >"$pair_directory/managed-processes.after.txt"
	assert_host_restored "$pair_directory" "$baseline_iface" \
		"$client_namespace" "$root_veth" "$nat_table" \
		"$pair_directory/managed-processes.before.txt" \
		"$pair_directory/managed-processes.after.txt"

	pair_raw_argument=""
	if [ "$REQUIRE_RAW_IPERF_JSON" -eq 1 ]; then
		pair_raw_argument="--require-raw-json"
	fi
	# shellcheck disable=SC2086
	"$PYTHON_BIN" "$ANALYZER" pair \
		--pair-index "$pair_index" \
		--order "$order" \
		--baseline-stdout "$pair_directory/baseline.stdout" \
		--baseline-stderr "$pair_directory/baseline.stderr" \
		--baseline-time "$pair_directory/baseline.time.txt" \
		--baseline-iperf-json "$pair_directory/baseline.iperf3.json" \
		--winn-stdout "$pair_directory/winn.stdout" \
		--winn-stderr "$pair_directory/winn.stderr" \
		--winn-time "$pair_directory/winn.time.txt" \
		--winn-iperf-json "$pair_directory/winn.iperf3.json" \
		--gateway-name "$GATEWAY_NAME" \
		--gateway-endpoint "$GATEWAY_ENDPOINT" \
		--gateway-inner-ip "$GATEWAY_INNER_IP" \
		$pair_raw_argument \
		--output "$pair_directory/pair.json" \
		| tee "$pair_directory/pair-summary.txt"

	pair_index=$((pair_index + 1))
	if [ "$pair_index" -le "$PAIRS" ]; then
		sleep "$PAIR_COOLDOWN_SECONDS"
	fi
done

summary_status=0
"$PYTHON_BIN" "$ANALYZER" summary \
	--pairs-root "$RUN_DIRECTORY" \
	--expected-pairs "$PAIRS" \
	--gate-percent "$GATE_PERCENT" \
	--output "$RUN_DIRECTORY/summary.json" \
	>"$RUN_DIRECTORY/summary.txt" 2>"$RUN_DIRECTORY/summary.stderr" ||
	summary_status=$?

snapshot_managed_processes >"$RUN_DIRECTORY/managed-processes.after.txt"
snapshot_environment "$RUN_DIRECTORY/environment.after.txt"
if ! cmp -s \
	"$RUN_DIRECTORY/managed-processes.before.txt" \
	"$RUN_DIRECTORY/managed-processes.after.txt"
then
	diff -u \
		"$RUN_DIRECTORY/managed-processes.before.txt" \
		"$RUN_DIRECTORY/managed-processes.after.txt" \
		>"$RUN_DIRECTORY/managed-processes.final.diff" 2>&1 || true
	fail "final managed process set differs from the initial state"
fi
if [ "$summary_status" -ne 0 ]; then
	write_status "FAIL" "one or more paired ratios missed the Phase-1 threshold"
	fail "paired throughput gate failed; see $RUN_DIRECTORY/summary.json"
fi

write_status "PASS" "all paired Winn/raw-AWG ratios met the threshold"
find "$RUN_DIRECTORY" -type f ! -name checksums.sha256 -print0 |
	sort -z |
	xargs -0 "$SHA256_BIN" >"$RUN_DIRECTORY/checksums.sha256"
checksums_digest=$("$SHA256_BIN" "$RUN_DIRECTORY/checksums.sha256" | awk '{ print $1 }')
echo "THROUGHPUT_GATE=PASS"
echo "ARCHIVE_DIRECTORY=$RUN_DIRECTORY"
echo "CHECKSUM_MANIFEST_SHA256=$checksums_digest"
cat "$RUN_DIRECTORY/summary.txt"
COMPLETED=1
