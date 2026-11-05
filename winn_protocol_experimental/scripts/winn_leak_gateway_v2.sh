#!/bin/sh
set -eu

# Acceptance-only gateway lease for the Winn leak-suite v2.
#
# This script is intentionally limited to a dedicated disposable test gateway.
# It does not edit AWG peers, addresses, UFW, cloud firewalls, or persistent
# service configuration. The caller must provision an isolated v4/v6-capable
# AWG profile first. A bounded lease, exact process identities, uniquely named
# nftables tables, before/after forwarding values, pcaps, and counter snapshots
# make every change attributable and recoverable.

ACTION=${1:-}
RUN_ID=${RUN_ID:-}
ACK_VALUE=WINN_LEAK_V2_DEDICATED_DISPOSABLE_GATEWAY
GATEWAY_DISPOSABLE_ACK=${GATEWAY_DISPOSABLE_ACK:-}

IP_BIN=${IP_BIN:-/usr/sbin/ip}
NFT_BIN=${NFT_BIN:-/usr/sbin/nft}
JQ_BIN=${JQ_BIN:-/usr/bin/jq}
TCPDUMP_BIN=${TCPDUMP_BIN:-/usr/bin/tcpdump}
OBSERVER_BIN=${OBSERVER_BIN:-/opt/winn-lab/bin/winn-leak-v2}
SELF_PATH=${SELF_PATH:-$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")}

RUNTIME_ROOT=${RUNTIME_ROOT:-/run/winn-leak-v2}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-/var/lib/winn-leak-v2}

fail() {
	echo "winn leak gateway v2: $*" >&2
	exit 1
}

is_run_id() {
	case "$1" in
		????????????????????????????????)
			printf '%s' "$1" | LC_ALL=C grep -Eq '^[0-9a-f]{32}$'
			;;
		*) return 1 ;;
	esac
}

require_binary() {
	[ -x "$1" ] || fail "required executable is missing: $1"
}

require_run_id() {
	is_run_id "$RUN_ID" || fail "RUN_ID must be lowercase 32-hex"
}

runtime_dir_for() {
	printf '%s/%s\n' "$RUNTIME_ROOT" "$RUN_ID"
}

state_path_for() {
	printf '%s/state.json\n' "$(runtime_dir_for)"
}

process_start_ticks() {
	pid=$1
	[ -r "/proc/$pid/stat" ] || return 1
	# comm is parenthesized and may contain spaces; fields after the final ") "
	# begin with original field 3, so original field 22 is position 20 here.
	sed 's/^.*) //' "/proc/$pid/stat" | awk '{ print $20 }'
}

exact_process_alive() {
	pid=$1
	expected_ticks=$2
	[ -d "/proc/$pid" ] || return 1
	actual_ticks=$(process_start_ticks "$pid") || return 1
	[ "$actual_ticks" = "$expected_ticks" ]
}

stop_exact_process() {
	pid=$1
	expected_ticks=$2
	if ! exact_process_alive "$pid" "$expected_ticks"; then
		return 0
	fi
	kill "$pid"
	remaining=100
	while exact_process_alive "$pid" "$expected_ticks"; do
		remaining=$((remaining - 1))
		if [ "$remaining" -le 0 ]; then
			kill -KILL "$pid"
			break
		fi
		sleep 0.05
	done
}

validate_table_name() {
	printf '%s' "$1" | LC_ALL=C grep -Eq '^[a-z][a-z0-9_]{0,31}$' ||
		fail "derived nftables table name is invalid"
}

require_empty_base_firewall() {
	if command -v ufw >/dev/null 2>&1 &&
		ufw status 2>/dev/null | grep -q '^Status: active'; then
		fail "UFW is active; v2 requires a dedicated gateway instead of modifying a shared firewall"
	fi
	if command -v iptables >/dev/null 2>&1; then
		iptables -S FORWARD 2>/dev/null | grep -Fx -- '-P FORWARD ACCEPT' >/dev/null ||
			fail "IPv4 FORWARD policy is not ACCEPT on the dedicated gateway"
	fi
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -S FORWARD 2>/dev/null | grep -Fx -- '-P FORWARD ACCEPT' >/dev/null ||
			fail "IPv6 FORWARD policy is not ACCEPT on the dedicated gateway"
	fi
}

assert_interface() {
	"$IP_BIN" link show dev "$1" >/dev/null 2>&1 ||
		fail "interface does not exist: $1"
}

assert_listener_ip_on_interface() {
	listen=$1
	interface=$2
	host=${listen%:*}
	case "$listen" in
		\[*\]:*) host=$(printf '%s' "$listen" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p') ;;
	esac
	[ -n "$host" ] || fail "could not parse listener: $listen"
	"$IP_BIN" -o address show dev "$interface" |
		awk '{ print $4 }' |
		cut -d/ -f1 |
		grep -Fx "$host" >/dev/null ||
		fail "DNS listener IP $host is not assigned to $interface"
}

start_lease() {
	require_run_id
	[ "$GATEWAY_DISPOSABLE_ACK" = "$ACK_VALUE" ] ||
		fail "dedicated disposable gateway acknowledgement is required"
	[ "$(id -u)" -eq 0 ] || fail "start requires root"
	for binary in "$IP_BIN" "$NFT_BIN" "$JQ_BIN" "$TCPDUMP_BIN" "$OBSERVER_BIN"; do
		require_binary "$binary"
	done
	require_binary "$SELF_PATH"

	TUNNEL_INTERFACE=${TUNNEL_INTERFACE:?must set TUNNEL_INTERFACE}
	EGRESS_INTERFACE=${EGRESS_INTERFACE:?must set EGRESS_INTERFACE}
	CLIENT_SUBNET_V4=${CLIENT_SUBNET_V4:?must set CLIENT_SUBNET_V4}
	CLIENT_SUBNET_V6=${CLIENT_SUBNET_V6:?must set CLIENT_SUBNET_V6}
	DNS_LISTEN=${DNS_LISTEN:?must set DNS_LISTEN}
	# Normally HTTP/STUN run on an independently routed public observer so
	# their recorded source proves real Internet egress. These optional
	# listeners are retained only for explicitly designed multi-interface labs.
	HTTP_LISTEN=${HTTP_LISTEN:-}
	STUN_LISTEN=${STUN_LISTEN:-}
	ANSWER_V4=${ANSWER_V4:?must set ANSWER_V4}
	ANSWER_V6=${ANSWER_V6:?must set ANSWER_V6}
	NONCE=${NONCE:?must set NONCE}
	DNS_ZONE=${DNS_ZONE:-leak-v2.invalid}
	LEASE_SECONDS=${LEASE_SECONDS:-1800}
	GATEWAY_PROFILE_DIGEST=${GATEWAY_PROFILE_DIGEST:?must set GATEWAY_PROFILE_DIGEST}

	is_run_id "$NONCE" || fail "NONCE must be lowercase 32-hex"
	printf '%s' "$GATEWAY_PROFILE_DIGEST" |
		LC_ALL=C grep -Eq '^[0-9a-f]{64}$' ||
		fail "GATEWAY_PROFILE_DIGEST must be lowercase SHA-256"
	case "$LEASE_SECONDS" in
		*[!0-9]* | '') fail "LEASE_SECONDS must be an integer" ;;
	esac
	[ "$LEASE_SECONDS" -ge 60 ] && [ "$LEASE_SECONDS" -le 7200 ] ||
		fail "LEASE_SECONDS must be between 60 and 7200"

	assert_interface "$TUNNEL_INTERFACE"
	assert_interface "$EGRESS_INTERFACE"
	assert_listener_ip_on_interface "$DNS_LISTEN" "$TUNNEL_INTERFACE"
	require_empty_base_firewall

	run_short=$(printf '%s' "$RUN_ID" | cut -c1-12)
	FILTER_TABLE=wlv2f_$run_short
	NAT4_TABLE=wlv2n4_$run_short
	NAT6_TABLE=wlv2n6_$run_short
	validate_table_name "$FILTER_TABLE"
	validate_table_name "$NAT4_TABLE"
	validate_table_name "$NAT6_TABLE"
	for spec in "inet $FILTER_TABLE" "ip $NAT4_TABLE" "ip6 $NAT6_TABLE"; do
		# shellcheck disable=SC2086
		if "$NFT_BIN" list table $spec >/dev/null 2>&1; then
			fail "refusing to reuse nftables table: $spec"
		fi
	done

	runtime_dir=$(runtime_dir_for)
	evidence_dir=$EVIDENCE_ROOT/$RUN_ID
	[ ! -e "$runtime_dir" ] || fail "runtime directory already exists: $runtime_dir"
	[ ! -e "$evidence_dir" ] || fail "evidence directory already exists: $evidence_dir"
	umask 077
	mkdir -p "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	chmod 0700 "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	mkdir "$runtime_dir" "$evidence_dir"
	chmod 0700 "$runtime_dir" "$evidence_dir"

	ip4_previous=$(sysctl -n net.ipv4.ip_forward)
	ip6_previous=$(sysctl -n net.ipv6.conf.all.forwarding)
	observer_pid=
	observer_ticks=
	tcpdump_pid=
	tcpdump_ticks=
	watchdog_pid=
	watchdog_ticks=
	filter_added=0
	nat4_added=0
	nat6_added=0
	start_succeeded=0

	rollback_start() {
		[ "$start_succeeded" -eq 0 ] || return 0
		[ -z "$watchdog_pid" ] || stop_exact_process "$watchdog_pid" "$watchdog_ticks" || true
		[ -z "$tcpdump_pid" ] || stop_exact_process "$tcpdump_pid" "$tcpdump_ticks" || true
		[ -z "$observer_pid" ] || stop_exact_process "$observer_pid" "$observer_ticks" || true
		[ "$filter_added" -eq 0 ] || "$NFT_BIN" delete table inet "$FILTER_TABLE" || true
		[ "$nat4_added" -eq 0 ] || "$NFT_BIN" delete table ip "$NAT4_TABLE" || true
		[ "$nat6_added" -eq 0 ] || "$NFT_BIN" delete table ip6 "$NAT6_TABLE" || true
		sysctl -w net.ipv4.ip_forward="$ip4_previous" >/dev/null || true
		sysctl -w net.ipv6.conf.all.forwarding="$ip6_previous" >/dev/null || true
	}
	trap rollback_start EXIT HUP INT TERM

	sysctl -w net.ipv4.ip_forward=1 >/dev/null
	sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

	nft_batch=$runtime_dir/gateway.nft
	{
		printf 'table inet %s {\n' "$FILTER_TABLE"
		printf ' chain forward {\n'
		printf '  type filter hook forward priority -50; policy accept;\n'
		printf '  iifname "%s" oifname "%s" ip saddr %s counter accept comment "winn-leak-v2-v4-egress"\n' \
			"$TUNNEL_INTERFACE" "$EGRESS_INTERFACE" "$CLIENT_SUBNET_V4"
		printf '  iifname "%s" oifname "%s" ip daddr %s ct state established,related counter accept comment "winn-leak-v2-v4-return"\n' \
			"$EGRESS_INTERFACE" "$TUNNEL_INTERFACE" "$CLIENT_SUBNET_V4"
		printf '  iifname "%s" oifname "%s" ip6 saddr %s counter accept comment "winn-leak-v2-v6-egress"\n' \
			"$TUNNEL_INTERFACE" "$EGRESS_INTERFACE" "$CLIENT_SUBNET_V6"
		printf '  iifname "%s" oifname "%s" ip6 daddr %s ct state established,related counter accept comment "winn-leak-v2-v6-return"\n' \
			"$EGRESS_INTERFACE" "$TUNNEL_INTERFACE" "$CLIENT_SUBNET_V6"
		printf ' }\n}\n'
		printf 'table ip %s {\n' "$NAT4_TABLE"
		printf ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n'
		printf '  ip saddr %s oifname "%s" counter masquerade comment "winn-leak-v2-v4-nat"\n' \
			"$CLIENT_SUBNET_V4" "$EGRESS_INTERFACE"
		printf ' }\n}\n'
		printf 'table ip6 %s {\n' "$NAT6_TABLE"
		printf ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n'
		printf '  ip6 saddr %s oifname "%s" counter masquerade comment "winn-leak-v2-v6-nat66"\n' \
			"$CLIENT_SUBNET_V6" "$EGRESS_INTERFACE"
		printf ' }\n}\n'
	} >"$nft_batch"
	chmod 0600 "$nft_batch"
	"$NFT_BIN" -f "$nft_batch"
	filter_added=1
	nat4_added=1
	nat6_added=1

	"$OBSERVER_BIN" observer \
		-run-id="$RUN_ID" \
		-nonce="$NONCE" \
		-zone="$DNS_ZONE" \
		-dns-listen="$DNS_LISTEN" \
		-http-listen="$HTTP_LISTEN" \
		-stun-listen="$STUN_LISTEN" \
		-answer-v4="$ANSWER_V4" \
		-answer-v6="$ANSWER_V6" \
		-evidence-log="$evidence_dir/observer.jsonl" \
		-ready-file="$runtime_dir/observer-ready.json" \
		>"$evidence_dir/observer.stdout.log" \
		2>"$evidence_dir/observer.stderr.log" &
	observer_pid=$!
	observer_ticks=$(process_start_ticks "$observer_pid")
	ready_attempt=0
	while [ ! -f "$runtime_dir/observer-ready.json" ]; do
		exact_process_alive "$observer_pid" "$observer_ticks" ||
			fail "observer exited before readiness"
		ready_attempt=$((ready_attempt + 1))
		[ "$ready_attempt" -lt 200 ] || fail "observer readiness timed out"
		sleep 0.05
	done

	"$TCPDUMP_BIN" -U -i any -s 0 -w "$evidence_dir/gateway.pcap" \
		"net $CLIENT_SUBNET_V4 or net $CLIENT_SUBNET_V6 or port 53 or port 3478" \
		>"$evidence_dir/tcpdump.stdout.log" \
		2>"$evidence_dir/tcpdump.stderr.log" &
	tcpdump_pid=$!
	tcpdump_ticks=$(process_start_ticks "$tcpdump_pid")
	sleep 0.2
	exact_process_alive "$tcpdump_pid" "$tcpdump_ticks" ||
		fail "tcpdump exited before the lease became ready"

	state_path=$(state_path_for)
	# shellcheck disable=SC2016 # jq variables are supplied with --arg.
	"$JQ_BIN" -n \
		--arg version "winn-leak-gateway-lease/v2" \
		--arg run_id "$RUN_ID" \
		--arg started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		--arg tunnel_interface "$TUNNEL_INTERFACE" \
		--arg egress_interface "$EGRESS_INTERFACE" \
		--arg client_subnet_v4 "$CLIENT_SUBNET_V4" \
		--arg client_subnet_v6 "$CLIENT_SUBNET_V6" \
		--arg filter_table "$FILTER_TABLE" \
		--arg nat4_table "$NAT4_TABLE" \
		--arg nat6_table "$NAT6_TABLE" \
		--arg ip4_previous "$ip4_previous" \
		--arg ip6_previous "$ip6_previous" \
		--arg evidence_dir "$evidence_dir" \
		--arg gateway_profile_digest "$GATEWAY_PROFILE_DIGEST" \
		--argjson observer_pid "$observer_pid" \
		--arg observer_ticks "$observer_ticks" \
		--argjson tcpdump_pid "$tcpdump_pid" \
		--arg tcpdump_ticks "$tcpdump_ticks" \
		--argjson lease_seconds "$LEASE_SECONDS" \
		'{
			version:$version, run_id:$run_id, started_at:$started_at,
			tunnel_interface:$tunnel_interface, egress_interface:$egress_interface,
			client_subnet_v4:$client_subnet_v4, client_subnet_v6:$client_subnet_v6,
			filter_table:$filter_table, nat4_table:$nat4_table, nat6_table:$nat6_table,
			ip4_previous:$ip4_previous, ip6_previous:$ip6_previous,
			evidence_dir:$evidence_dir, gateway_profile_digest:$gateway_profile_digest,
			observer:{pid:$observer_pid,start_ticks:$observer_ticks},
			tcpdump:{pid:$tcpdump_pid,start_ticks:$tcpdump_ticks},
			lease_seconds:$lease_seconds
		}' >"$state_path"
	chmod 0600 "$state_path"
	sync "$state_path"

	# shellcheck disable=SC2016 # $1..$4 expand in the child sh, not here.
	nohup sh -c '
		sleep "$1"
		RUN_ID=$2 GATEWAY_DISPOSABLE_ACK=$3 SELF_PATH=$4 exec "$4" stop
	' sh "$LEASE_SECONDS" "$RUN_ID" "$ACK_VALUE" "$SELF_PATH" \
		>"$evidence_dir/watchdog.stdout.log" \
		2>"$evidence_dir/watchdog.stderr.log" </dev/null &
	watchdog_pid=$!
	watchdog_ticks=$(process_start_ticks "$watchdog_pid")
	temp_state=$runtime_dir/state.with-watchdog.json
	# shellcheck disable=SC2016 # jq variables are supplied with --arg.
	"$JQ_BIN" \
		--argjson watchdog_pid "$watchdog_pid" \
		--arg watchdog_ticks "$watchdog_ticks" \
		'. + {watchdog:{pid:$watchdog_pid,start_ticks:$watchdog_ticks}}' \
		"$state_path" >"$temp_state"
	chmod 0600 "$temp_state"
	mv "$temp_state" "$state_path"
	sync "$state_path"

	start_succeeded=1
	trap - EXIT HUP INT TERM
	echo "READY run_id=$RUN_ID lease_seconds=$LEASE_SECONDS evidence=$evidence_dir"
}

stop_lease() {
	require_run_id
	[ "$GATEWAY_DISPOSABLE_ACK" = "$ACK_VALUE" ] ||
		fail "dedicated disposable gateway acknowledgement is required"
	[ "$(id -u)" -eq 0 ] || fail "stop requires root"
	for binary in "$IP_BIN" "$NFT_BIN" "$JQ_BIN"; do
		require_binary "$binary"
	done
	state_path=$(state_path_for)
	[ -f "$state_path" ] || fail "lease state does not exist: $state_path"
	[ ! -L "$state_path" ] || fail "lease state must not be a symlink"
	[ "$(stat -c '%a' "$state_path")" = 600 ] || fail "lease state mode is not 0600"
	[ "$("$JQ_BIN" -r '.version' "$state_path")" = winn-leak-gateway-lease/v2 ] ||
		fail "lease state version mismatch"
	[ "$("$JQ_BIN" -r '.run_id' "$state_path")" = "$RUN_ID" ] ||
		fail "lease state run ID mismatch"

	filter_table=$("$JQ_BIN" -r '.filter_table' "$state_path")
	nat4_table=$("$JQ_BIN" -r '.nat4_table' "$state_path")
	nat6_table=$("$JQ_BIN" -r '.nat6_table' "$state_path")
	ip4_previous=$("$JQ_BIN" -r '.ip4_previous' "$state_path")
	ip6_previous=$("$JQ_BIN" -r '.ip6_previous' "$state_path")
	evidence_dir=$("$JQ_BIN" -r '.evidence_dir' "$state_path")
	observer_pid=$("$JQ_BIN" -r '.observer.pid' "$state_path")
	observer_ticks=$("$JQ_BIN" -r '.observer.start_ticks' "$state_path")
	tcpdump_pid=$("$JQ_BIN" -r '.tcpdump.pid' "$state_path")
	tcpdump_ticks=$("$JQ_BIN" -r '.tcpdump.start_ticks' "$state_path")
	watchdog_pid=$("$JQ_BIN" -r '.watchdog.pid // 0' "$state_path")
	watchdog_ticks=$("$JQ_BIN" -r '.watchdog.start_ticks // ""' "$state_path")

	"$NFT_BIN" list table inet "$filter_table" >"$evidence_dir/filter-counters.nft"
	"$NFT_BIN" list table ip "$nat4_table" >"$evidence_dir/nat4-counters.nft"
	"$NFT_BIN" list table ip6 "$nat6_table" >"$evidence_dir/nat6-counters.nft"
	"$IP_BIN" -s link >"$evidence_dir/ip-link-counters.txt"

	stop_exact_process "$tcpdump_pid" "$tcpdump_ticks"
	stop_exact_process "$observer_pid" "$observer_ticks"
	if [ "$watchdog_pid" -ne 0 ] && [ "$watchdog_pid" -ne "$$" ] &&
		[ -n "$watchdog_ticks" ]; then
		stop_exact_process "$watchdog_pid" "$watchdog_ticks"
	fi

	"$NFT_BIN" delete table inet "$filter_table"
	"$NFT_BIN" delete table ip "$nat4_table"
	"$NFT_BIN" delete table ip6 "$nat6_table"
	sysctl -w net.ipv4.ip_forward="$ip4_previous" >/dev/null
	sysctl -w net.ipv6.conf.all.forwarding="$ip6_previous" >/dev/null

	# shellcheck disable=SC2016 # jq variables are supplied with --arg.
	"$JQ_BIN" \
		--arg stopped_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'. + {stopped_at:$stopped_at, state:"stopped"}' \
		"$state_path" >"$evidence_dir/gateway-state-stopped.json"
	chmod 0600 "$evidence_dir/gateway-state-stopped.json"
	sync "$evidence_dir/gateway-state-stopped.json"
	rm -f "$state_path" "$(runtime_dir_for)/observer-ready.json" "$(runtime_dir_for)/gateway.nft"
	rmdir "$(runtime_dir_for)"
	echo "STOPPED run_id=$RUN_ID evidence=$evidence_dir"
}

status_lease() {
	require_run_id
	require_binary "$JQ_BIN"
	state_path=$(state_path_for)
	if [ ! -f "$state_path" ]; then
		echo "ABSENT run_id=$RUN_ID"
		return 1
	fi
	observer_pid=$("$JQ_BIN" -r '.observer.pid' "$state_path")
	observer_ticks=$("$JQ_BIN" -r '.observer.start_ticks' "$state_path")
	tcpdump_pid=$("$JQ_BIN" -r '.tcpdump.pid' "$state_path")
	tcpdump_ticks=$("$JQ_BIN" -r '.tcpdump.start_ticks' "$state_path")
	exact_process_alive "$observer_pid" "$observer_ticks" ||
		fail "observer process identity is not alive"
	exact_process_alive "$tcpdump_pid" "$tcpdump_ticks" ||
		fail "tcpdump process identity is not alive"
	echo "ACTIVE run_id=$RUN_ID state=$state_path"
}

case "$ACTION" in
	start) start_lease ;;
	stop) stop_lease ;;
	status) status_lease ;;
	*) fail "usage: RUN_ID=<32hex> $0 <start|stop|status>" ;;
esac
