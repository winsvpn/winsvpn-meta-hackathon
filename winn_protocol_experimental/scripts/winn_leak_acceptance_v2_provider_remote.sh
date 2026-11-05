#!/bin/sh
set -eu

# Provider-side lifecycle helper for the Winn leak acceptance v2 harness.
# This file is deployed identically to the dedicated UpCloud gateway and the
# independent Vultr observer. A root-owned mode-0600 provider.env selects the
# role and contains paths to secret files, never secret values.

ROLE=${1:-}
ACTION=${2:-}
RUN_ID=${3:-}
FAMILY=${4:-}
SCENARIO=${5:-}

CONFIG_PATH=${WINN_LEAK_PROVIDER_CONFIG:-/etc/winn-leak-v2/provider.env}
RUNTIME_ROOT=/run/winn-leak-provider-v2
EVIDENCE_ROOT=/var/lib/winn-leak-provider-v2

fail() {
	echo "winn leak provider v2: $*" >&2
	exit 1
}

require_binary() {
	[ -x "$1" ] || fail "required executable is missing: $1"
}

validate_token() {
	printf '%s' "$1" | LC_ALL=C grep -Eq '^[a-z0-9][a-z0-9_-]{0,31}$' ||
		fail "invalid token: $1"
}

validate_run_id() {
	printf '%s' "$RUN_ID" | LC_ALL=C grep -Eq '^[0-9a-f]{32}$' ||
		fail "RUN_ID must be lowercase 32-hex"
}

require_private_config() {
	[ -f "$CONFIG_PATH" ] && [ ! -L "$CONFIG_PATH" ] ||
		fail "provider config must be a regular non-symlink file"
	[ "$(stat -c '%a' "$CONFIG_PATH")" = 600 ] ||
		fail "provider config mode must be 0600"
	# shellcheck disable=SC1090 # fixed, root-owned deployment input.
	. "$CONFIG_PATH"
	[ "${CONFIG_VERSION:-}" = winn-leak-provider-config/v2 ] ||
		fail "provider config version mismatch"
	[ "$(hostname)" = "${EXPECTED_HOSTNAME:-}" ] ||
		fail "provider hostname mismatch"
	[ "${PROVIDER_ROLE:-}" = "$ROLE" ] ||
		fail "provider role mismatch"
	RUNTIME_ROOT=${RUNTIME_ROOT_OVERRIDE:-$RUNTIME_ROOT}
	EVIDENCE_ROOT=${EVIDENCE_ROOT_OVERRIDE:-$EVIDENCE_ROOT}
}

runtime_dir() {
	printf '%s/%s-%s-%s-%s\n' \
		"$RUNTIME_ROOT" "$ROLE" "$RUN_ID" "$FAMILY" "$SCENARIO"
}

evidence_dir() {
	printf '%s/%s-%s-%s-%s\n' \
		"$EVIDENCE_ROOT" "$ROLE" "$RUN_ID" "$FAMILY" "$SCENARIO"
}

state_path() {
	printf '%s/state.json\n' "$(runtime_dir)"
}

process_start_ticks() {
	process_pid=$1
	[ -r "/proc/$process_pid/stat" ] || return 1
	sed 's/^.*) //' "/proc/$process_pid/stat" | awk '{print $20}'
}

process_pgid() {
	process_pid=$1
	ps -o pgid= -p "$process_pid" | tr -d ' '
}

exact_process_alive() {
	process_pid=$1
	expected_pgid=$2
	expected_ticks=$3
	[ -d "/proc/$process_pid" ] || return 1
	[ "$(process_start_ticks "$process_pid")" = "$expected_ticks" ] || return 1
	[ "$(process_pgid "$process_pid")" = "$expected_pgid" ] || return 1
	[ "$process_pid" = "$expected_pgid" ]
}

process_group_alive() {
	group_id=$1
	/usr/bin/kill -0 -- "-$group_id" 2>/dev/null
}

stop_exact_process() {
	process_pid=$1
	expected_pgid=$2
	expected_ticks=$3
	if ! exact_process_alive "$process_pid" "$expected_pgid" "$expected_ticks"; then
		if process_group_alive "$expected_pgid"; then
			fail "leader identity changed while process group remains: $expected_pgid"
		fi
		return 0
	fi
	/usr/bin/kill -TERM -- "-$expected_pgid"
	attempt=0
	while process_group_alive "$expected_pgid"; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 100 ]; then
			/usr/bin/kill -KILL -- "-$expected_pgid"
			break
		fi
		sleep 0.05
	done
	attempt=0
	while process_group_alive "$expected_pgid"; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 100 ] ||
			fail "process group survived SIGKILL: $expected_pgid"
		sleep 0.05
	done
}

start_managed() {
	label=$1
	shift
	output_dir=$(evidence_dir)
	stdout_path=$output_dir/$label.stdout.log
	stderr_path=$output_dir/$label.stderr.log
	(umask 077; set -C; : >"$stdout_path"; : >"$stderr_path")
	setsid "$@" </dev/null >"$stdout_path" 2>"$stderr_path" &
	process_pid=$!
	process_ticks=$(process_start_ticks "$process_pid") ||
		fail "$label exited before identity capture"
	process_group=$(process_pgid "$process_pid")
	[ "$process_group" = "$process_pid" ] ||
		fail "$label did not own a dedicated process group"
	sleep 0.1
	exact_process_alive "$process_pid" "$process_group" "$process_ticks" ||
		fail "$label exited before readiness"
	printf '%s:%s:%s\n' "$process_pid" "$process_group" "$process_ticks"
}

identity_field() {
	identity=$1
	field=$2
	printf '%s' "$identity" | cut -d: -f"$field"
}

stop_identity() {
	identity=$1
	[ -n "$identity" ] || return 0
	stop_exact_process \
		"$(identity_field "$identity" 1)" \
		"$(identity_field "$identity" 2)" \
		"$(identity_field "$identity" 3)"
}

service_identity() {
	service_pid=$(systemctl show winn-gateway -p MainPID --value)
	[ "$service_pid" -gt 1 ] || fail "winn-gateway has no live MainPID"
	service_ticks=$(process_start_ticks "$service_pid") ||
		fail "cannot capture winn-gateway identity"
	printf '%s:%s\n' "$service_pid" "$service_ticks"
}

assert_service_identity() {
	expected_pid=$1
	expected_ticks=$2
	[ "$(systemctl is-active winn-gateway)" = active ] ||
		fail "winn-gateway is not active"
	[ "$(systemctl show winn-gateway -p MainPID --value)" = "$expected_pid" ] ||
		fail "winn-gateway MainPID changed"
	[ "$(process_start_ticks "$expected_pid")" = "$expected_ticks" ] ||
		fail "winn-gateway process identity changed"
}

sha256_path() {
	sha256sum "$1" | awk '{print $1}'
}

capture_baseline() {
	destination=$1
	systemctl show winn-gateway \
		-p ActiveState -p MainPID -p ExecMainStartTimestampMonotonic \
		>"$destination/winn-gateway.baseline.txt"
	ufw status numbered >"$destination/ufw.baseline.txt" 2>&1 || true
	nft list tables >"$destination/nft-tables.baseline.txt"
	ip -j address show >"$destination/ip-address.baseline.json"
	ip -j route show table all >"$destination/ip-route4.baseline.json"
	ip -j -6 route show table all >"$destination/ip-route6.baseline.json"
	sysctl -n net.ipv4.ip_forward >"$destination/ip4-forward.baseline.txt"
	sysctl -n net.ipv6.conf.all.forwarding >"$destination/ip6-forward.baseline.txt"
}

capture_final() {
	destination=$1
	systemctl show winn-gateway \
		-p ActiveState -p MainPID -p ExecMainStartTimestampMonotonic \
		>"$destination/winn-gateway.final.txt"
	ufw status numbered >"$destination/ufw.final.txt" 2>&1 || true
	nft list tables >"$destination/nft-tables.final.txt"
	ip -j address show >"$destination/ip-address.final.json"
	ip -j route show table all >"$destination/ip-route4.final.json"
	ip -j -6 route show table all >"$destination/ip-route6.final.json"
	sysctl -n net.ipv4.ip_forward >"$destination/ip4-forward.final.txt"
	sysctl -n net.ipv6.conf.all.forwarding >"$destination/ip6-forward.final.txt"
}

ufw_is_active() {
	ufw status 2>/dev/null | grep -q '^Status: active'
}

delete_ufw_comment() {
	comment=$1
	numbers=$(ufw status numbered 2>/dev/null |
		awk -v marker="$comment" '
			index($0, marker) {
				line=$0
				sub(/^[^[]*\[/, "", line)
				sub(/\].*$/, "", line)
				gsub(/[[:space:]]/, "", line)
				print line
			}' |
		sort -rn)
	for number in $numbers; do
		ufw --force delete "$number" >/dev/null
	done
	ufw status numbered 2>/dev/null | grep -F "$comment" >/dev/null &&
		fail "UFW rule comment remains: $comment"
	return 0
}

wait_interface() {
	interface_name=$1
	attempt=0
	while ! ip link show dev "$interface_name" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 200 ] || fail "interface readiness timed out"
		sleep 0.05
	done
}

wait_ready_file() {
	ready_path=$1
	expected_version=$2
	expected_pid=$3
	attempt=0
	while :; do
		if [ -f "$ready_path" ] &&
			[ "$(jq -r '.version // empty' "$ready_path" 2>/dev/null)" = "$expected_version" ] &&
			[ "$(jq -r '.run_id // empty' "$ready_path" 2>/dev/null)" = "$RUN_ID" ] &&
			[ "$(jq -r '.pid // empty' "$ready_path" 2>/dev/null)" = "$expected_pid" ]; then
			return 0
		fi
		attempt=$((attempt + 1))
		[ "$attempt" -lt 200 ] || fail "managed service readiness timed out"
		sleep 0.05
	done
}

select_gateway_family() {
	case "$FAMILY" in
	v4)
		GATEWAY_INTERFACE_CIDR=$GATEWAY_V4_INTERFACE_CIDR
		GATEWAY_CLIENT_CIDR=$GATEWAY_V4_CLIENT_CIDR
		GATEWAY_EGRESS_INTERFACE=$GATEWAY_V4_EGRESS_INTERFACE
		GATEWAY_LISTEN_PORT=$GATEWAY_V4_LISTEN_PORT
		GATEWAY_PRIVATE_KEY_FILE=$GATEWAY_V4_PRIVATE_KEY_FILE
		GATEWAY_CLIENT_PUBLIC_KEY_FILE=$GATEWAY_V4_CLIENT_PUBLIC_KEY_FILE
		GATEWAY_PSK_FILE=$GATEWAY_V4_PSK_FILE
		GATEWAY_DNS_LISTEN=$GATEWAY_V4_DNS_LISTEN
		GATEWAY_CANARY_LISTEN=$GATEWAY_V4_CANARY_LISTEN
		GATEWAY_NONCE=$GATEWAY_V4_NONCE
		GATEWAY_FAMILY_FLAG=-4
		GATEWAY_NFT_FAMILY=ip
		GATEWAY_SOURCE_KEY='ip saddr'
		GATEWAY_DESTINATION_KEY='ip daddr'
		GATEWAY_FORWARD_SYSCTL=net.ipv4.ip_forward
		;;
	v6)
		GATEWAY_INTERFACE_CIDR=$GATEWAY_V6_INTERFACE_CIDR
		GATEWAY_CLIENT_CIDR=$GATEWAY_V6_CLIENT_CIDR
		GATEWAY_EGRESS_INTERFACE=$GATEWAY_V6_EGRESS_INTERFACE
		GATEWAY_LISTEN_PORT=$GATEWAY_V6_LISTEN_PORT
		GATEWAY_PRIVATE_KEY_FILE=$GATEWAY_V6_PRIVATE_KEY_FILE
		GATEWAY_CLIENT_PUBLIC_KEY_FILE=$GATEWAY_V6_CLIENT_PUBLIC_KEY_FILE
		GATEWAY_PSK_FILE=$GATEWAY_V6_PSK_FILE
		GATEWAY_DNS_LISTEN=$GATEWAY_V6_DNS_LISTEN
		GATEWAY_CANARY_LISTEN=$GATEWAY_V6_CANARY_LISTEN
		GATEWAY_NONCE=$GATEWAY_V6_NONCE
		GATEWAY_FAMILY_FLAG=-6
		GATEWAY_NFT_FAMILY=ip6
		GATEWAY_SOURCE_KEY='ip6 saddr'
		GATEWAY_DESTINATION_KEY='ip6 daddr'
		GATEWAY_FORWARD_SYSCTL=net.ipv6.conf.all.forwarding
		;;
	*) fail "family must be v4 or v6" ;;
	esac
	for secret_path in \
		"$GATEWAY_PRIVATE_KEY_FILE" "$GATEWAY_PSK_FILE"; do
		[ -f "$secret_path" ] && [ ! -L "$secret_path" ] ||
			fail "gateway secret file is missing"
		[ "$(stat -c '%a' "$secret_path")" = 600 ] ||
			fail "gateway secret file mode is not 0600"
	done
	[ -f "$GATEWAY_CLIENT_PUBLIC_KEY_FILE" ] &&
		[ ! -L "$GATEWAY_CLIENT_PUBLIC_KEY_FILE" ] ||
		fail "client public key file is missing"
}

select_observer_family() {
	case "$FAMILY" in
	v4)
		OBSERVER_PUBLIC_IP=$OBSERVER_V4_PUBLIC_IP
		OBSERVER_INTERFACE=$OBSERVER_V4_INTERFACE
		OBSERVER_HTTP_PORT=$OBSERVER_V4_HTTP_PORT
		OBSERVER_STUN_PORT=$OBSERVER_V4_STUN_PORT
		OBSERVER_DNS_PORT=$OBSERVER_V4_DNS_PORT
		OBSERVER_NONCE=$OBSERVER_V4_NONCE
		OBSERVER_EXPECTED_PEER=$OBSERVER_V4_EXPECTED_PEER
		;;
	v6)
		OBSERVER_PUBLIC_IP=$OBSERVER_V6_PUBLIC_IP
		OBSERVER_INTERFACE=$OBSERVER_V6_INTERFACE
		OBSERVER_HTTP_PORT=$OBSERVER_V6_HTTP_PORT
		OBSERVER_STUN_PORT=$OBSERVER_V6_STUN_PORT
		OBSERVER_DNS_PORT=$OBSERVER_V6_DNS_PORT
		OBSERVER_NONCE=$OBSERVER_V6_NONCE
		OBSERVER_EXPECTED_PEER=$OBSERVER_V6_EXPECTED_PEER
		;;
	*) fail "family must be v4 or v6" ;;
	esac
}

write_gateway_state() {
	state_file=$(state_path)
	service_pid=$(identity_field "$service_before" 1)
	service_ticks=$(identity_field "$service_before" 2)
	jq -n \
		--arg version winn-leak-provider-state/v2 \
		--arg role gateway \
		--arg run_id "$RUN_ID" \
		--arg family "$FAMILY" \
		--arg scenario "$SCENARIO" \
		--arg interface "$gateway_interface" \
		--arg peer_mode "$GATEWAY_PEER_MODE" \
		--arg egress_interface "$GATEWAY_EGRESS_INTERFACE" \
		--arg filter_table "$filter_table" \
		--arg nat_table "$nat_table" \
		--arg outage_table "$outage_table" \
		--arg forwarding_sysctl "$GATEWAY_FORWARD_SYSCTL" \
		--arg forwarding_previous "$forwarding_previous" \
		--arg ufw_comment "$ufw_comment" \
		--arg awg "$awg_identity" \
		--arg dns "$dns_identity" \
		--arg canary "$canary_identity" \
		--arg pcap "$pcap_identity" \
		--argjson service_pid "$service_pid" \
		--arg service_ticks "$service_ticks" \
		'{
			version:$version,role:$role,run_id:$run_id,family:$family,
			scenario:$scenario,interface:$interface,peer_mode:$peer_mode,
			egress_interface:$egress_interface,filter_table:$filter_table,
			nat_table:$nat_table,outage_table:$outage_table,
			outage:false,forwarding_sysctl:$forwarding_sysctl,
			forwarding_previous:$forwarding_previous,ufw_comment:$ufw_comment,
			processes:{awg:$awg,dns:$dns,canary:$canary,pcap:$pcap},
			service:{pid:$service_pid,start_ticks:$service_ticks}
		}' >"$state_file"
	chmod 0600 "$state_file"
	sync "$state_file"
}

start_gateway() {
	select_gateway_family
	case "${GATEWAY_PEER_MODE:-}" in
	fixture | acceptance) ;;
	*) fail "gateway peer mode must be fixture or acceptance" ;;
	esac
	require_binary "$AWG_GO_BINARY"
	require_binary "$AWG_BINARY"
	require_binary "$WINN_LEAK_BINARY"
	require_binary "$CANARY_BINARY"
	require_binary "$TCPDUMP_BINARY"
	require_binary "$NFT_BINARY"
	[ "$(id -u)" -eq 0 ] || fail "gateway start requires root"
	run_short=$(printf '%s' "$RUN_ID" | cut -c1-10)
	case "$FAMILY" in
	v4) family_digit=4 ;;
	v6) family_digit=6 ;;
	esac
	gateway_interface=wl${family_digit}${run_short}
	filter_table=wlv2f_${run_short}
	nat_table=wlv2n${family_digit}_${run_short}
	outage_table=wlv2o_${run_short}
	ufw_comment=wlv2g-${RUN_ID}-${FAMILY}
	validate_token "$filter_table"
	validate_token "$nat_table"
	validate_token "$outage_table"
	[ ! -e "$(runtime_dir)" ] || fail "gateway runtime already exists"
	[ ! -e "$(evidence_dir)" ] || fail "gateway evidence already exists"
	ip link show dev "$gateway_interface" >/dev/null 2>&1 &&
		fail "gateway interface already exists"
	nft list table inet "$filter_table" >/dev/null 2>&1 &&
		fail "gateway filter table already exists"
	nft list table "$GATEWAY_NFT_FAMILY" "$nat_table" >/dev/null 2>&1 &&
		fail "gateway NAT table already exists"

	umask 077
	mkdir -p "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	chmod 0700 "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	mkdir "$(runtime_dir)" "$(evidence_dir)"
	chmod 0700 "$(runtime_dir)" "$(evidence_dir)"
	capture_baseline "$(evidence_dir)"
	service_before=$(service_identity)
	forwarding_previous=$(sysctl -n "$GATEWAY_FORWARD_SYSCTL")
	awg_identity=
	dns_identity=
	canary_identity=
	pcap_identity=
	started=0

	rollback_gateway_start() {
		[ "$started" -eq 0 ] || return 0
		stop_identity "$pcap_identity" || true
		stop_identity "$canary_identity" || true
		stop_identity "$dns_identity" || true
		stop_identity "$awg_identity" || true
		nft delete table inet "$filter_table" 2>/dev/null || true
		nft delete table "$GATEWAY_NFT_FAMILY" "$nat_table" 2>/dev/null || true
		ip link del dev "$gateway_interface" 2>/dev/null || true
		sysctl -w "$GATEWAY_FORWARD_SYSCTL=$forwarding_previous" >/dev/null || true
		delete_ufw_comment "$ufw_comment" 2>/dev/null || true
		rm -f "$(state_path)"
		rmdir "$(runtime_dir)" 2>/dev/null || true
		rm -rf "$(evidence_dir)"
	}
	trap rollback_gateway_start EXIT HUP INT TERM

	awg_identity=$(start_managed awg "$AWG_GO_BINARY" -f "$gateway_interface")
	wait_interface "$gateway_interface"
	client_public_key=$(tr -d '\r\n' <"$GATEWAY_CLIENT_PUBLIC_KEY_FILE")
	printf '%s' "$client_public_key" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
		fail "client public key encoding is invalid"
	"$AWG_BINARY" set "$gateway_interface" \
		private-key "$GATEWAY_PRIVATE_KEY_FILE" \
		listen-port "$GATEWAY_LISTEN_PORT" \
		jc 4 jmin 12 jmax 64 \
		s1 16 s2 80 s3 24 s4 8 \
		h1 111111 h2 222222 h3 333333 h4 444444 \
		peer "$client_public_key" \
		preshared-key "$GATEWAY_PSK_FILE" \
		allowed-ips "$GATEWAY_CLIENT_CIDR" \
		persistent-keepalive 25
	ip "$GATEWAY_FAMILY_FLAG" address add \
		"$GATEWAY_INTERFACE_CIDR" dev "$gateway_interface"
	ip link set dev "$gateway_interface" mtu 1280 up
	ip "$GATEWAY_FAMILY_FLAG" route replace \
		"$GATEWAY_CLIENT_CIDR" dev "$gateway_interface"
	sysctl -w "$GATEWAY_FORWARD_SYSCTL=1" >/dev/null

	nft_batch=$(runtime_dir)/gateway.nft
	{
		printf 'table inet %s {\n' "$filter_table"
		printf ' chain forward { type filter hook forward priority -50; policy accept;\n'
		printf '  iifname "%s" oifname "%s" %s %s counter accept comment "winn-leak-v2-egress"\n' \
			"$gateway_interface" "$GATEWAY_EGRESS_INTERFACE" \
			"$GATEWAY_SOURCE_KEY" "$GATEWAY_CLIENT_CIDR"
		printf '  iifname "%s" oifname "%s" %s %s ct state established,related counter accept comment "winn-leak-v2-return"\n' \
			"$GATEWAY_EGRESS_INTERFACE" "$gateway_interface" \
			"$GATEWAY_DESTINATION_KEY" "$GATEWAY_CLIENT_CIDR"
		printf ' }\n}\n'
		printf 'table %s %s {\n' "$GATEWAY_NFT_FAMILY" "$nat_table"
		printf ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n'
		printf '  %s %s oifname "%s" counter masquerade comment "winn-leak-v2-nat"\n' \
			"$GATEWAY_SOURCE_KEY" "$GATEWAY_CLIENT_CIDR" "$GATEWAY_EGRESS_INTERFACE"
		printf ' }\n}\n'
	} >"$nft_batch"
	chmod 0600 "$nft_batch"
	"$NFT_BINARY" -f "$nft_batch"
	if ufw_is_active; then
		ufw allow in on "$GATEWAY_EGRESS_INTERFACE" \
			to any port "$GATEWAY_LISTEN_PORT" proto udp \
			comment "$ufw_comment" >/dev/null
		ufw route allow in on "$gateway_interface" \
			out on "$GATEWAY_EGRESS_INTERFACE" \
			comment "$ufw_comment" >/dev/null
	fi

	dns_identity=$(start_managed dns "$WINN_LEAK_BINARY" observer \
		-run-id="$RUN_ID" \
		-nonce="$GATEWAY_NONCE" \
		-zone="$GATEWAY_DNS_ZONE" \
		-dns-listen="$GATEWAY_DNS_LISTEN" \
		-answer-v4="$GATEWAY_DNS_ANSWER_V4" \
		-answer-v6="$GATEWAY_DNS_ANSWER_V6" \
		-evidence-log="$(evidence_dir)/dns.jsonl" \
		-ready-file="$(runtime_dir)/dns-ready.json")
	wait_ready_file "$(runtime_dir)/dns-ready.json" \
		winn-leak-observer/v2 "$(identity_field "$dns_identity" 1)"
	canary_identity=$(start_managed canary "$CANARY_BINARY" \
		-listen="$GATEWAY_CANARY_LISTEN" \
		-run-id="$RUN_ID" \
		-evidence-log="$(evidence_dir)/canary.jsonl" \
		-ready-file="$(runtime_dir)/canary-ready.json")
	wait_ready_file "$(runtime_dir)/canary-ready.json" \
		winn-leak-canary-ready/v2 "$(identity_field "$canary_identity" 1)"
	pcap_identity=$(start_managed pcap "$TCPDUMP_BINARY" -U -i any -s 0 \
		-w "$(evidence_dir)/gateway.pcap" \
		"net $GATEWAY_CLIENT_CIDR or udp port $GATEWAY_LISTEN_PORT or port 53")

	write_gateway_state
	started=1
	trap - EXIT HUP INT TERM
	echo "READY role=gateway run_id=$RUN_ID family=$FAMILY interface=$gateway_interface"
}

write_observer_state() {
	state_file=$(state_path)
	service_pid=$(identity_field "$service_before" 1)
	service_ticks=$(identity_field "$service_before" 2)
	jq -n \
		--arg version winn-leak-provider-state/v2 \
		--arg role observer \
		--arg run_id "$RUN_ID" \
		--arg family "$FAMILY" \
		--arg scenario "$SCENARIO" \
		--arg expected_peer "$OBSERVER_EXPECTED_PEER" \
		--arg ufw_comment "$ufw_comment" \
		--arg observer "$observer_identity" \
		--arg pcap "$pcap_identity" \
		--argjson service_pid "$service_pid" \
		--arg service_ticks "$service_ticks" \
		'{
			version:$version,role:$role,run_id:$run_id,family:$family,
			scenario:$scenario,expected_peer:$expected_peer,
			checkpoint_count:0,ufw_comment:$ufw_comment,
			processes:{observer:$observer,pcap:$pcap},
			service:{pid:$service_pid,start_ticks:$service_ticks}
		}' >"$state_file"
	chmod 0600 "$state_file"
	sync "$state_file"
}

start_observer() {
	select_observer_family
	require_binary "$WINN_LEAK_BINARY"
	require_binary "$TCPDUMP_BINARY"
	[ "$(id -u)" -eq 0 ] || fail "observer start requires root"
	ufw_comment=wlv2o-${RUN_ID}-${FAMILY}
	[ ! -e "$(runtime_dir)" ] || fail "observer runtime already exists"
	[ ! -e "$(evidence_dir)" ] || fail "observer evidence already exists"
	ss -H -lntu | grep -E "[:.]($OBSERVER_HTTP_PORT|$OBSERVER_STUN_PORT)[[:space:]]" >/dev/null &&
		fail "observer acceptance port is already in use"

	umask 077
	mkdir -p "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	chmod 0700 "$RUNTIME_ROOT" "$EVIDENCE_ROOT"
	mkdir "$(runtime_dir)" "$(evidence_dir)"
	chmod 0700 "$(runtime_dir)" "$(evidence_dir)"
	capture_baseline "$(evidence_dir)"
	service_before=$(service_identity)
	observer_identity=
	pcap_identity=
	started=0

	rollback_observer_start() {
		[ "$started" -eq 0 ] || return 0
		stop_identity "$pcap_identity" || true
		stop_identity "$observer_identity" || true
		delete_ufw_comment "$ufw_comment" 2>/dev/null || true
		rm -f "$(state_path)"
		rmdir "$(runtime_dir)" 2>/dev/null || true
		rm -rf "$(evidence_dir)"
	}
	trap rollback_observer_start EXIT HUP INT TERM

	if ufw_is_active; then
		ufw allow in on "$OBSERVER_INTERFACE" \
			to "$OBSERVER_PUBLIC_IP" port "$OBSERVER_HTTP_PORT" proto tcp \
			comment "$ufw_comment" >/dev/null
		ufw allow in on "$OBSERVER_INTERFACE" \
			to "$OBSERVER_PUBLIC_IP" port "$OBSERVER_STUN_PORT" proto udp \
			comment "$ufw_comment" >/dev/null
	fi
	case "$FAMILY" in
	v4)
		http_listen=$OBSERVER_PUBLIC_IP:$OBSERVER_HTTP_PORT
		stun_listen=$OBSERVER_PUBLIC_IP:$OBSERVER_STUN_PORT
		dns_listen=127.0.0.1:$OBSERVER_DNS_PORT
		;;
	v6)
		http_listen=[$OBSERVER_PUBLIC_IP]:$OBSERVER_HTTP_PORT
		stun_listen=[$OBSERVER_PUBLIC_IP]:$OBSERVER_STUN_PORT
		dns_listen="[::1]:$OBSERVER_DNS_PORT"
		;;
	esac
	observer_identity=$(start_managed observer "$WINN_LEAK_BINARY" observer \
		-run-id="$RUN_ID" \
		-nonce="$OBSERVER_NONCE" \
		-zone="$OBSERVER_DNS_ZONE" \
		-dns-listen="$dns_listen" \
		-http-listen="$http_listen" \
		-stun-listen="$stun_listen" \
		-answer-v4="$OBSERVER_ANSWER_V4" \
		-answer-v6="$OBSERVER_ANSWER_V6" \
		-evidence-log="$(evidence_dir)/observer.jsonl" \
		-ready-file="$(runtime_dir)/observer-ready.json")
	wait_ready_file "$(runtime_dir)/observer-ready.json" \
		winn-leak-observer/v2 "$(identity_field "$observer_identity" 1)"
	pcap_identity=$(start_managed pcap "$TCPDUMP_BINARY" -U \
		-i "$OBSERVER_INTERFACE" -s 0 \
		-w "$(evidence_dir)/observer.pcap" \
		"tcp port $OBSERVER_HTTP_PORT or udp port $OBSERVER_STUN_PORT")
	write_observer_state
	started=1
	trap - EXIT HUP INT TERM
	echo "READY role=observer run_id=$RUN_ID family=$FAMILY"
}

load_state() {
	state_file=$(state_path)
	[ -f "$state_file" ] && [ ! -L "$state_file" ] ||
		fail "provider state is absent"
	[ "$(stat -c '%a' "$state_file")" = 600 ] ||
		fail "provider state mode is not 0600"
	[ "$(jq -r '.version' "$state_file")" = winn-leak-provider-state/v2 ] ||
		fail "provider state version mismatch"
	[ "$(jq -r '.role' "$state_file")" = "$ROLE" ] ||
		fail "provider state role mismatch"
	[ "$(jq -r '.run_id' "$state_file")" = "$RUN_ID" ] ||
		fail "provider state run mismatch"
	[ "$(jq -r '.family' "$state_file")" = "$FAMILY" ] ||
		fail "provider state family mismatch"
	[ "$(jq -r '.scenario' "$state_file")" = "$SCENARIO" ] ||
		fail "provider state scenario mismatch"
}

assert_identity_json() {
	json_path=$1
	identity=$(jq -r "$json_path" "$(state_path)")
	[ "$identity" != null ] && [ -n "$identity" ] ||
		fail "missing process identity at $json_path"
	exact_process_alive \
		"$(identity_field "$identity" 1)" \
		"$(identity_field "$identity" 2)" \
		"$(identity_field "$identity" 3)" ||
		fail "process identity is not alive: $json_path"
}

status_role() {
	load_state
	service_pid=$(jq -r '.service.pid' "$(state_path)")
	service_ticks=$(jq -r '.service.start_ticks' "$(state_path)")
	assert_service_identity "$service_pid" "$service_ticks"
	if [ "$ROLE" = gateway ]; then
		select_gateway_family
		assert_identity_json '.processes.awg'
		assert_identity_json '.processes.dns'
		assert_identity_json '.processes.canary'
		assert_identity_json '.processes.pcap'
		interface_name=$(jq -r '.interface' "$(state_path)")
		ip link show dev "$interface_name" >/dev/null ||
			fail "gateway interface is absent"
		nft list table inet "$(jq -r '.filter_table' "$(state_path)")" >/dev/null ||
			fail "gateway filter table is absent"
		nft list table "$GATEWAY_NFT_FAMILY" \
			"$(jq -r '.nat_table' "$(state_path)")" >/dev/null ||
			fail "gateway NAT table is absent"
		outage_table=$(jq -r '.outage_table' "$(state_path)")
		if [ "$(jq -r '.outage' "$(state_path)")" = true ]; then
			nft list table inet "$outage_table" >/dev/null ||
				fail "gateway outage table is absent"
		else
			nft list table inet "$outage_table" >/dev/null 2>&1 &&
				fail "gateway outage table exists outside an outage"
		fi
	else
		assert_identity_json '.processes.observer'
		assert_identity_json '.processes.pcap'
	fi
	echo "ACTIVE role=$ROLE run_id=$RUN_ID family=$FAMILY"
}

observer_external_count() {
	jq -s \
		--arg peer "$(jq -r '.expected_peer' "$(state_path)")" '
		[
			.[] |
			select(.kind == "http_canary" or .kind == "stun_binding") |
			if .peer_ip != $peer then
				error("unexpected observer peer " + (.peer_ip // ""))
			else .
			end |
			select(.accepted == true)
		] | length
	' "$(evidence_dir)/observer.jsonl"
}

observer_kind_count() {
	kind=$1
	jq -s --arg kind "$kind" --arg peer "$(jq -r '.expected_peer' "$(state_path)")" '
		[
			.[] |
			select(.kind == $kind and .accepted == true and .peer_ip == $peer)
		] | length
	' "$(evidence_dir)/observer.jsonl"
}

observer_assert() {
	load_state
	[ "$ROLE" = observer ] || fail "assertion action requires observer role"
	status_role >/dev/null
	current_count=$(observer_external_count)
	checkpoint=$(jq -r '.checkpoint_count' "$(state_path)")
	case "$ACTION" in
	assert-prepared | assert-verified)
		[ "$current_count" -eq 0 ] ||
			fail "$ACTION observed premature public traffic"
		;;
	assert-committed)
		[ "$(observer_kind_count http_canary)" -ge 1 ] ||
			fail "committed observer evidence omitted HTTP"
		[ "$(observer_kind_count stun_binding)" -ge 1 ] ||
			fail "committed observer evidence omitted STUN"
		;;
	assert-outage-fail-closed | assert-crashed-fail-closed | assert-stopped)
		[ "$current_count" -eq "$checkpoint" ] ||
			fail "$ACTION observed new public traffic"
		;;
	assert-recovered)
		[ "$current_count" -gt "$checkpoint" ] ||
			fail "recovery produced no new public observer event"
		[ "$(observer_kind_count http_canary)" -ge 2 ] ||
			fail "recovery observer evidence omitted fresh HTTP"
		[ "$(observer_kind_count stun_binding)" -ge 2 ] ||
			fail "recovery observer evidence omitted fresh STUN"
		;;
	*) fail "unknown observer assertion: $ACTION" ;;
	esac
	temp_state=$(runtime_dir)/state.next.json
	jq --argjson count "$current_count" \
		'.checkpoint_count=$count' "$(state_path)" >"$temp_state"
	chmod 0600 "$temp_state"
	mv "$temp_state" "$(state_path)"
	sync "$(state_path)"
	echo "PASS role=observer action=$ACTION count=$current_count"
}

gateway_outage() {
	load_state
	[ "$ROLE" = gateway ] || fail "outage requires gateway role"
	[ "$(jq -r '.outage' "$(state_path)")" = false ] ||
		fail "gateway outage is already active"
	interface_name=$(jq -r '.interface' "$(state_path)")
	outage_table=$(jq -r '.outage_table' "$(state_path)")
	{
		printf 'table inet %s {\n' "$outage_table"
		printf ' chain input { type filter hook input priority -300; policy accept;\n'
		printf '  iifname "%s" counter drop comment "winn-leak-v2-outage-local"\n' "$interface_name"
		printf ' }\n'
		printf ' chain forward { type filter hook forward priority -300; policy accept;\n'
		printf '  iifname "%s" counter drop comment "winn-leak-v2-outage-egress"\n' "$interface_name"
		printf '  oifname "%s" counter drop comment "winn-leak-v2-outage-return"\n' "$interface_name"
		printf ' }\n}\n'
	} >"$(runtime_dir)/outage.nft"
	chmod 0600 "$(runtime_dir)/outage.nft"
	nft -f "$(runtime_dir)/outage.nft"
	temp_state=$(runtime_dir)/state.next.json
	jq '.outage=true' "$(state_path)" >"$temp_state"
	chmod 0600 "$temp_state"
	mv "$temp_state" "$(state_path)"
	sync "$(state_path)"
	echo "OUTAGE role=gateway run_id=$RUN_ID family=$FAMILY"
}

gateway_recover() {
	load_state
	[ "$ROLE" = gateway ] || fail "recover requires gateway role"
	outage_table=$(jq -r '.outage_table' "$(state_path)")
	if [ "$(jq -r '.outage' "$(state_path)")" = true ]; then
		nft list table inet "$outage_table" \
			>"$(evidence_dir)/outage-counters.nft"
		nft delete table inet "$outage_table"
	fi
	temp_state=$(runtime_dir)/state.next.json
	jq '.outage=false' "$(state_path)" >"$temp_state"
	chmod 0600 "$temp_state"
	mv "$temp_state" "$(state_path)"
	sync "$(state_path)"
	echo "RECOVERED role=gateway run_id=$RUN_ID family=$FAMILY"
}

stop_role() {
	load_state
	evidence=$(evidence_dir)
	service_pid=$(jq -r '.service.pid' "$(state_path)")
	service_ticks=$(jq -r '.service.start_ticks' "$(state_path)")
	assert_service_identity "$service_pid" "$service_ticks"
	if [ "$ROLE" = gateway ]; then
		select_gateway_family
		if [ "$(jq -r '.outage' "$(state_path)")" = true ]; then
			gateway_recover >/dev/null
			load_state
		fi
		filter_table=$(jq -r '.filter_table' "$(state_path)")
		nat_table=$(jq -r '.nat_table' "$(state_path)")
		nft list table inet "$filter_table" >"$evidence/filter-counters.nft"
		nft list table "$GATEWAY_NFT_FAMILY" "$nat_table" \
			>"$evidence/nat-counters.nft"
		stop_identity "$(jq -r '.processes.pcap' "$(state_path)")"
		stop_identity "$(jq -r '.processes.canary' "$(state_path)")"
		stop_identity "$(jq -r '.processes.dns' "$(state_path)")"
		stop_identity "$(jq -r '.processes.awg' "$(state_path)")"
		nft delete table inet "$filter_table"
		nft delete table "$GATEWAY_NFT_FAMILY" "$nat_table"
		ip link del dev "$(jq -r '.interface' "$(state_path)")" 2>/dev/null || true
		sysctl_name=$(jq -r '.forwarding_sysctl' "$(state_path)")
		sysctl_previous=$(jq -r '.forwarding_previous' "$(state_path)")
		sysctl -w "$sysctl_name=$sysctl_previous" >/dev/null
	else
		stop_identity "$(jq -r '.processes.pcap' "$(state_path)")"
		stop_identity "$(jq -r '.processes.observer' "$(state_path)")"
	fi
	delete_ufw_comment "$(jq -r '.ufw_comment' "$(state_path)")"
	capture_final "$evidence"
	cmp "$evidence/ufw.baseline.txt" "$evidence/ufw.final.txt" ||
		fail "UFW baseline was not restored exactly"
	cmp "$evidence/nft-tables.baseline.txt" "$evidence/nft-tables.final.txt" ||
		fail "nftables table baseline was not restored exactly"
	cmp "$evidence/ip4-forward.baseline.txt" "$evidence/ip4-forward.final.txt" ||
		fail "IPv4 forwarding baseline was not restored exactly"
	cmp "$evidence/ip6-forward.baseline.txt" "$evidence/ip6-forward.final.txt" ||
		fail "IPv6 forwarding baseline was not restored exactly"
	assert_service_identity "$service_pid" "$service_ticks"
	jq -n \
		--arg version winn-leak-provider-stopped/v2 \
		--arg role "$ROLE" \
		--arg run_id "$RUN_ID" \
		--arg family "$FAMILY" \
		--arg scenario "$SCENARIO" \
		--arg stopped_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{version:$version,role:$role,run_id:$run_id,family:$family,
		  scenario:$scenario,stopped_at:$stopped_at}' \
		>"$evidence/stopped.json"
	chmod 0600 "$evidence/stopped.json"
	sync "$evidence/stopped.json"
	rm -f "$(state_path)" "$(runtime_dir)"/*.json "$(runtime_dir)"/*.nft
	rmdir "$(runtime_dir)"
	echo "STOPPED role=$ROLE run_id=$RUN_ID family=$FAMILY"
}

purge_evidence() {
	evidence=$(evidence_dir)
	[ ! -e "$(runtime_dir)" ] || fail "runtime exists; refusing evidence purge"
	[ -f "$evidence/stopped.json" ] ||
		fail "stopped marker is absent; refusing evidence purge"
	[ "$(jq -r '.run_id' "$evidence/stopped.json")" = "$RUN_ID" ] ||
		fail "stopped marker run mismatch"
	rm -rf "$evidence"
	echo "PURGED role=$ROLE run_id=$RUN_ID family=$FAMILY"
}

residue_role() {
	[ ! -e "$(runtime_dir)" ] || fail "provider runtime residue remains"
	run_short=$(printf '%s' "$RUN_ID" | cut -c1-10)
	case "$FAMILY" in
	v4) family_digit=4 ;;
	v6) family_digit=6 ;;
	esac
	interface_name=wl${family_digit}${run_short}
	ip link show dev "$interface_name" >/dev/null 2>&1 &&
		fail "provider interface residue remains"
	for table in wlv2f_${run_short} wlv2o_${run_short}; do
		nft list table inet "$table" >/dev/null 2>&1 &&
			fail "provider inet nftables residue remains: $table"
	done
	nft list table ip "wlv2n4_${run_short}" >/dev/null 2>&1 &&
		fail "provider IPv4 NAT residue remains"
	nft list table ip6 "wlv2n6_${run_short}" >/dev/null 2>&1 &&
		fail "provider IPv6 NAT residue remains"
	ufw status numbered 2>/dev/null |
		grep -F "$RUN_ID" >/dev/null &&
		fail "provider UFW residue remains"
	[ ! -e "$(evidence_dir)" ] || fail "provider evidence was not collected/purged"
	[ "$(systemctl is-active winn-gateway)" = active ] ||
		fail "winn-gateway is not active after acceptance cleanup"
	echo "CLEAN role=$ROLE run_id=$RUN_ID family=$FAMILY"
}

validate_run_id
validate_token "$ROLE"
validate_token "$FAMILY"
validate_token "$SCENARIO"
require_private_config
for binary in /usr/bin/jq /usr/bin/kill /usr/bin/setsid /usr/bin/sha256sum \
	/usr/bin/systemctl /usr/sbin/ip /usr/sbin/nft /usr/sbin/ufw; do
	require_binary "$binary"
done

case "$ACTION" in
start)
	case "$ROLE" in
	gateway) start_gateway ;;
	observer) start_observer ;;
	*) fail "unsupported provider role" ;;
	esac
	;;
status) status_role ;;
outage) gateway_outage ;;
recover) gateway_recover ;;
assert-*) observer_assert ;;
stop) stop_role ;;
evidence-path) evidence_dir ;;
purge) purge_evidence ;;
residue) residue_role ;;
*) fail "unsupported action: $ACTION" ;;
esac
