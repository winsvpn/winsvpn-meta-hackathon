#!/bin/sh

# Shared primitives for the four Winn leak acceptance v2 hook executables.
# The caller must enable `set -eu` before sourcing this file.

WINN_LEAK_HOOK_CONFIG=${WINN_LEAK_HOOK_CONFIG:-/etc/winn-leak-v2/hook.json}

hook_fail() {
	echo "winn leak acceptance v2 hook: $*" >&2
	exit 1
}

hook_validate_token() {
	printf '%s' "$1" | LC_ALL=C grep -Eq '^[a-z0-9][a-z0-9_-]{0,31}$' ||
		hook_fail "invalid token: $1"
}

hook_validate_context() {
	[ "$#" -eq 5 ] ||
		hook_fail "expected ACTION RUN_ID FAMILY SCENARIO EVIDENCE_DIR"
	HOOK_ACTION=$1
	HOOK_RUN_ID=$2
	HOOK_FAMILY=$3
	HOOK_SCENARIO=$4
	HOOK_EVIDENCE_DIR=$5
	hook_validate_token "$HOOK_ACTION"
	printf '%s' "$HOOK_RUN_ID" | LC_ALL=C grep -Eq '^[0-9a-f]{32}$' ||
		hook_fail "RUN_ID must be lowercase 32-hex"
	case "$HOOK_FAMILY" in
	v4 | v6) ;;
	*) hook_fail "family must be v4 or v6" ;;
	esac
	case "$HOOK_SCENARIO" in
	graceful | outage | crash | fixture) ;;
	*) hook_fail "scenario is not recognized" ;;
	esac
	[ "${HOOK_EVIDENCE_DIR#/}" != "$HOOK_EVIDENCE_DIR" ] &&
		[ -d "$HOOK_EVIDENCE_DIR" ] &&
		[ ! -L "$HOOK_EVIDENCE_DIR" ] ||
		hook_fail "scenario evidence directory must be an absolute real directory"
	[ "$(realpath -e "$HOOK_EVIDENCE_DIR")" = "$HOOK_EVIDENCE_DIR" ] ||
		hook_fail "scenario evidence path must be canonical"
	[ $((0$(stat -c '%a' "$HOOK_EVIDENCE_DIR") & 077)) -eq 0 ] ||
		hook_fail "scenario evidence directory must deny group/other access"
}

hook_json_required() {
	value=$(jq -er "$1 | strings | select(length > 0)" "$WINN_LEAK_HOOK_CONFIG") ||
		hook_fail "missing hook config field: $1"
	printf '%s\n' "$value"
}

hook_load_config() {
	[ "$(id -u)" -eq 0 ] || hook_fail "hooks require root on the disposable client"
	[ -f "$WINN_LEAK_HOOK_CONFIG" ] &&
		[ ! -L "$WINN_LEAK_HOOK_CONFIG" ] ||
		hook_fail "hook config must be a regular non-symlink file"
	[ "$(stat -c '%a' "$WINN_LEAK_HOOK_CONFIG")" = 600 ] ||
		hook_fail "hook config mode must be 0600"
	[ "$(stat -c '%u' "$WINN_LEAK_HOOK_CONFIG")" = 0 ] ||
		hook_fail "hook config must be owned by root"
	[ "$(jq -er '.version' "$WINN_LEAK_HOOK_CONFIG")" = winn-leak-hook-config/v2 ] ||
		hook_fail "hook config version mismatch"
	HOOK_CLIENT_MARKER=$(hook_json_required '.client.disposable_marker')
	HOOK_EXPECTED_HOSTNAME=$(hook_json_required '.client.expected_hostname')
	HOOK_NETPROBE=$(hook_json_required '.client.netprobe_binary')
	HOOK_TCPDUMP=$(hook_json_required '.client.tcpdump_binary')
	HOOK_AWG_GO=$(hook_json_required '.client.awg_go_binary')
	HOOK_SSH_IDENTITY=$(hook_json_required '.ssh.identity_file')
	HOOK_SSH_PUBLIC_FINGERPRINT=$(hook_json_required '.ssh.public_fingerprint')
	HOOK_KNOWN_HOSTS=$(hook_json_required '.ssh.known_hosts_file')
	for path in "$HOOK_CLIENT_MARKER" "$HOOK_NETPROBE" "$HOOK_TCPDUMP" "$HOOK_AWG_GO" \
		"$HOOK_SSH_IDENTITY" "$HOOK_KNOWN_HOSTS"; do
		[ "${path#/}" != "$path" ] && [ "$(realpath -e "$path")" = "$path" ] ||
			hook_fail "configured path must be absolute, canonical, and present: $path"
	done
	[ -f "$HOOK_CLIENT_MARKER" ] && [ ! -L "$HOOK_CLIENT_MARKER" ] ||
		hook_fail "disposable-client marker is absent"
	[ "$(hostname)" = "$HOOK_EXPECTED_HOSTNAME" ] ||
		hook_fail "hook refused outside the dedicated disposable client"
	[ -x "$HOOK_NETPROBE" ] && [ -f "$HOOK_NETPROBE" ] &&
		[ ! -L "$HOOK_NETPROBE" ] ||
		hook_fail "netprobe helper is not a regular executable"
	[ -x "$HOOK_TCPDUMP" ] && [ -f "$HOOK_TCPDUMP" ] &&
		[ ! -L "$HOOK_TCPDUMP" ] ||
		hook_fail "tcpdump is not a regular executable"
	[ -x "$HOOK_AWG_GO" ] && [ -f "$HOOK_AWG_GO" ] &&
		[ ! -L "$HOOK_AWG_GO" ] ||
		hook_fail "amneziawg-go is not a regular executable"
	[ -f "$HOOK_SSH_IDENTITY" ] && [ ! -L "$HOOK_SSH_IDENTITY" ] ||
		hook_fail "SSH identity is not a regular file"
	case "$(stat -c '%a' "$HOOK_SSH_IDENTITY")" in
	400 | 600) ;;
	*) hook_fail "SSH identity mode must be 0400 or 0600" ;;
	esac
	[ -f "$HOOK_KNOWN_HOSTS" ] && [ ! -L "$HOOK_KNOWN_HOSTS" ] ||
		hook_fail "known_hosts is not a regular file"
	[ $((0$(stat -c '%a' "$HOOK_KNOWN_HOSTS") & 077)) -eq 0 ] ||
		hook_fail "known_hosts must deny group/other access"
	actual_identity_fingerprint=$(
		ssh-keygen -y -f "$HOOK_SSH_IDENTITY" |
			ssh-keygen -lf /dev/stdin -E sha256 |
			awk 'NR == 1 { print $2 }'
	)
	[ "$actual_identity_fingerprint" = "$HOOK_SSH_PUBLIC_FINGERPRINT" ] ||
		hook_fail "SSH identity fingerprint mismatch"
}

hook_provider_field() {
	role=$1
	field=$2
	hook_json_required ".providers.$role.$field"
}

hook_provider_host() {
	role=$1
	hook_json_required ".providers.$role.hosts.$HOOK_FAMILY"
}

hook_verify_provider() {
	role=$1
	HOOK_PROVIDER_HOST=$(hook_provider_host "$role")
	HOOK_PROVIDER_USER=$(hook_provider_field "$role" user)
	HOOK_PROVIDER_FINGERPRINT=$(hook_provider_field "$role" host_ed25519_fingerprint)
	HOOK_PROVIDER_BINARY=$(hook_provider_field "$role" remote_binary)
	HOOK_PROVIDER_EVIDENCE_ROOT=$(hook_provider_field "$role" remote_evidence_root)
	printf '%s' "$HOOK_PROVIDER_HOST" |
		LC_ALL=C grep -Eq '^[0-9A-Fa-f:.]+$' ||
		hook_fail "provider host must be an IP literal"
	printf '%s' "$HOOK_PROVIDER_USER" |
		LC_ALL=C grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' ||
		hook_fail "provider SSH user is invalid"
	HOOK_PROVIDER_FAMILY_FLAG=$(hook_control_plane_host_family_flag "$HOOK_PROVIDER_HOST")
	HOOK_PROVIDER_DESTINATION=$HOOK_PROVIDER_USER@$HOOK_PROVIDER_HOST
	case "$HOOK_PROVIDER_HOST" in
	*:*) HOOK_PROVIDER_SCP_DESTINATION=$HOOK_PROVIDER_USER@[$HOOK_PROVIDER_HOST] ;;
	*) HOOK_PROVIDER_SCP_DESTINATION=$HOOK_PROVIDER_DESTINATION ;;
	esac
	for path in "$HOOK_PROVIDER_BINARY" "$HOOK_PROVIDER_EVIDENCE_ROOT"; do
		printf '%s' "$path" |
			LC_ALL=C grep -Eq '^/[A-Za-z0-9._/-]+$' ||
			hook_fail "unsafe provider path"
	done
	fingerprints=$(
		ssh-keygen -F "$HOOK_PROVIDER_HOST" -f "$HOOK_KNOWN_HOSTS" 2>/dev/null |
			awk '!/^#/ { print }' |
			ssh-keygen -lf /dev/stdin -E sha256 2>/dev/null |
			awk '$4 == "(ED25519)" { print $2 }'
	)
	[ "$(printf '%s\n' "$fingerprints" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] &&
		[ "$fingerprints" = "$HOOK_PROVIDER_FINGERPRINT" ] ||
		hook_fail "provider ED25519 host-key pin mismatch"
}

hook_ssh() {
	ssh "$HOOK_PROVIDER_FAMILY_FLAG" -F /dev/null \
		-i "$HOOK_SSH_IDENTITY" \
		-o BatchMode=yes \
		-o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$HOOK_KNOWN_HOSTS" \
		-o ConnectTimeout=10 \
		-o ServerAliveInterval=5 \
		-o ServerAliveCountMax=2 \
		"$HOOK_PROVIDER_DESTINATION" "$@"
}

hook_provider_exec() {
	role=$1
	action=$2
	hook_verify_provider "$role"
	hook_ssh "$HOOK_PROVIDER_BINARY" "$role" "$action" \
		"$HOOK_RUN_ID" "$HOOK_FAMILY" "$HOOK_SCENARIO"
}

hook_provider_collect_and_purge() {
	role=$1
	hook_verify_provider "$role"
	remote_path=$(hook_ssh "$HOOK_PROVIDER_BINARY" "$role" evidence-path \
		"$HOOK_RUN_ID" "$HOOK_FAMILY" "$HOOK_SCENARIO")
	expected_path=$HOOK_PROVIDER_EVIDENCE_ROOT/$role-$HOOK_RUN_ID-$HOOK_FAMILY-$HOOK_SCENARIO
	[ "$remote_path" = "$expected_path" ] ||
		hook_fail "provider returned an unexpected evidence path"
	local_path=$HOOK_EVIDENCE_DIR/provider-$role
	[ ! -e "$local_path" ] || hook_fail "local provider evidence already exists"
	umask 077
	scp "$HOOK_PROVIDER_FAMILY_FLAG" -F /dev/null -r \
		-i "$HOOK_SSH_IDENTITY" \
		-o BatchMode=yes \
		-o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=yes \
		-o UserKnownHostsFile="$HOOK_KNOWN_HOSTS" \
		-o ConnectTimeout=10 \
		"$HOOK_PROVIDER_SCP_DESTINATION:$remote_path" \
		"$local_path"
	find "$local_path" -type l -print -quit | grep . >/dev/null &&
		hook_fail "provider evidence contains a symlink"
	find "$local_path" ! -type d ! -type f -print -quit | grep . >/dev/null &&
		hook_fail "provider evidence contains a special file"
	find "$local_path" -type d -exec chmod 0700 {} +
	find "$local_path" -type f -exec chmod 0600 {} +
	[ "$(jq -er '.version' "$local_path/stopped.json")" = winn-leak-provider-stopped/v2 ] &&
		[ "$(jq -er '.run_id' "$local_path/stopped.json")" = "$HOOK_RUN_ID" ] &&
		[ "$(jq -er '.role' "$local_path/stopped.json")" = "$role" ] ||
		hook_fail "collected provider stopped marker is invalid"
	hook_ssh "$HOOK_PROVIDER_BINARY" "$role" purge \
		"$HOOK_RUN_ID" "$HOOK_FAMILY" "$HOOK_SCENARIO"
}

hook_control_plane_table() {
	printf 'wlv2c_%s\n' "$(printf '%s' "$HOOK_RUN_ID" | cut -c1-12)"
}

hook_control_plane_host_family_flag() {
	case "$1" in
	*:*) printf '%s\n' -6 ;;
	*) printf '%s\n' -4 ;;
	esac
}

hook_control_plane_host_prefix() {
	case "$1" in
	*:*) printf '%s/128\n' "$1" ;;
	*) printf '%s/32\n' "$1" ;;
	esac
}

hook_control_plane_priority() {
	case "$1" in
	gateway) printf '%s\n' 1000 ;;
	observer) printf '%s\n' 1001 ;;
	*) hook_fail "unknown control-plane role" ;;
	esac
}

hook_control_plane_priority_count() {
	role=$1
	host=$(hook_provider_host "$role")
	family_flag=$(hook_control_plane_host_family_flag "$host")
	priority=$(hook_control_plane_priority "$role")
	ip -j "$family_flag" rule show |
		jq --argjson priority "$priority" '
			[.[] | select(.priority == $priority)] | length
		'
}

hook_control_plane_exact_rule_count() {
	role=$1
	host=$(hook_provider_host "$role")
	family_flag=$(hook_control_plane_host_family_flag "$host")
	priority=$(hook_control_plane_priority "$role")
	ip -j "$family_flag" rule show |
		jq --argjson priority "$priority" --arg host "$host" '
			[
				.[] |
				select(.priority == $priority) |
				select(.dst == $host) |
				select(.ipproto == "tcp") |
				select(.dport == 22) |
				select((.table | tostring) == "main")
			] | length
		'
}

hook_control_plane_rule() {
	host=$1
	case "$host" in
	*:*) address_key='ip6 daddr' ;;
	*) address_key='ip daddr' ;;
	esac
	printf '  %s %s tcp dport 22 counter comment "winn-leak-v2-pinned-control"\n' \
		"$address_key" "$host"
}

hook_control_plane_policy_comment() {
	case "$1" in
	gateway | observer)
		printf 'winn-leak-v2-pinned-control-%s\n' "$1"
		;;
	*) hook_fail "unknown control-plane role" ;;
	esac
}

hook_control_plane_policy_exact_count() {
	role=$1
	table=$(hook_json_required ".families.$HOOK_FAMILY.nft_table")
	interface=$(hook_json_required ".families.$HOOK_FAMILY.underlay_interface")
	host=$(hook_provider_host "$role")
	comment=$(hook_control_plane_policy_comment "$role")
	case "$host" in
	*:*) protocol=ip6 ;;
	*) protocol=ip ;;
	esac
	nft -j list chain inet "$table" output 2>/dev/null |
		jq \
			--arg table "$table" \
			--arg interface "$interface" \
			--arg host "$host" \
			--arg protocol "$protocol" \
			--arg comment "$comment" '
			[
				.nftables[]?.rule? |
				select(.family == "inet") |
				select(.table == $table and .chain == "output") |
				select(.comment == $comment) |
				select(any(.expr[]?;
					.match?.left?.meta?.key == "oifname" and
					.match.right == $interface
				)) |
				select(any(.expr[]?;
					.match?.left?.payload?.protocol == $protocol and
					.match?.left?.payload?.field == "daddr" and
					.match.right == $host
				)) |
				select(any(.expr[]?;
					.match?.left?.payload?.protocol == "tcp" and
					.match?.left?.payload?.field == "dport" and
					.match.right == 22
				)) |
				select(any(.expr[]?; has("counter"))) |
				select(any(.expr[]?; has("accept")))
			] | length
			'
}

hook_control_plane_policy_comment_count() {
	role=$1
	table=$(hook_json_required ".families.$HOOK_FAMILY.nft_table")
	comment=$(hook_control_plane_policy_comment "$role")
	nft -j list chain inet "$table" output 2>/dev/null |
		jq --arg comment "$comment" '
			[.nftables[]?.rule? | select(.comment == $comment)] | length
			'
}

hook_control_plane_policy_assert() {
	table=$(hook_json_required ".families.$HOOK_FAMILY.nft_table")
	nft list table inet "$table" >/dev/null 2>&1 ||
		hook_fail "client fail-closed policy table is absent"
	for role in gateway observer; do
		[ "$(hook_control_plane_policy_comment_count "$role")" -eq 1 ] &&
			[ "$(hook_control_plane_policy_exact_count "$role")" -eq 1 ] ||
			hook_fail "pinned provider control allow is absent or ambiguous: $role"
	done
}

hook_control_plane_policy_admit() {
	table=$(hook_json_required ".families.$HOOK_FAMILY.nft_table")
	interface=$(hook_json_required ".families.$HOOK_FAMILY.underlay_interface")
	printf '%s' "$interface" |
		LC_ALL=C grep -Eq '^[A-Za-z0-9_.=-]{1,64}$' ||
		hook_fail "control-plane underlay interface is invalid"
	nft list table inet "$table" >/dev/null 2>&1 ||
		hook_fail "client fail-closed policy table is absent"
	for role in gateway observer; do
		[ "$(hook_control_plane_policy_comment_count "$role")" -eq 0 ] ||
			hook_fail "pinned provider control allow already exists: $role"
		host=$(hook_provider_host "$role")
		comment=$(hook_control_plane_policy_comment "$role")
		case "$host" in
		*:*) address_key=ip6 ;;
		*) address_key=ip ;;
		esac
		nft insert rule inet "$table" output \
			oifname "$interface" \
			"$address_key" daddr "$host" \
			tcp dport 22 counter accept comment "$comment"
	done
	hook_control_plane_policy_assert
}

hook_control_plane_start() {
	gateway_host=$(hook_provider_host gateway)
	observer_host=$(hook_provider_host observer)
	for host in "$gateway_host" "$observer_host"; do
		printf '%s' "$host" | LC_ALL=C grep -Eq '^[0-9A-Fa-f:.]+$' ||
			hook_fail "control-plane provider host must be an IP literal"
	done
	[ "$gateway_host" != "$observer_host" ] ||
		hook_fail "control-plane provider hosts must differ"
	for role in gateway observer; do
		host=$(hook_provider_host "$role")
		family_flag=$(hook_control_plane_host_family_flag "$host")
		prefix=$(hook_control_plane_host_prefix "$host")
		priority=$(hook_control_plane_priority "$role")
		[ "$(hook_control_plane_priority_count "$role")" -eq 0 ] ||
			hook_fail "control-plane policy-rule priority is already occupied"
		ip "$family_flag" rule add priority "$priority" \
			ipproto tcp dport 22 to "$prefix" table main
		[ "$(hook_control_plane_exact_rule_count "$role")" -eq 1 ] ||
			hook_fail "control-plane policy rule was not installed exactly once"
	done
	table=$(hook_control_plane_table)
	nft list table inet "$table" >/dev/null 2>&1 &&
		hook_fail "control-plane nftables table already exists"
	{
		printf 'table inet %s {\n' "$table"
		printf ' chain audit_output { type filter hook output priority -160; policy accept;\n'
		hook_control_plane_rule "$gateway_host"
		hook_control_plane_rule "$observer_host"
		printf ' }\n}\n'
	} | nft -f -
	nft -j list table inet "$table" \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-started.json"
	ip -j -4 rule show \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-rule4-started.json"
	ip -j -6 rule show \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-rule6-started.json"
	chmod 0600 "$HOOK_EVIDENCE_DIR/client-control-plane-started.json"
	chmod 0600 "$HOOK_EVIDENCE_DIR"/client-control-plane-rule?-started.json
	sync "$HOOK_EVIDENCE_DIR/client-control-plane-started.json"
	sync "$HOOK_EVIDENCE_DIR"/client-control-plane-rule?-started.json
}

hook_control_plane_stop() {
	for role in gateway observer; do
		[ "$(hook_control_plane_exact_rule_count "$role")" -eq 1 ] ||
			hook_fail "control-plane policy rule is absent or ambiguous"
	done
	table=$(hook_control_plane_table)
	nft -j list table inet "$table" \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-stopped.json"
	ip -j -4 rule show \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-rule4-stopped.json"
	ip -j -6 rule show \
		>"$HOOK_EVIDENCE_DIR/client-control-plane-rule6-stopped.json"
	chmod 0600 "$HOOK_EVIDENCE_DIR/client-control-plane-stopped.json"
	chmod 0600 "$HOOK_EVIDENCE_DIR"/client-control-plane-rule?-stopped.json
	sync "$HOOK_EVIDENCE_DIR/client-control-plane-stopped.json"
	sync "$HOOK_EVIDENCE_DIR"/client-control-plane-rule?-stopped.json
	nft delete table inet "$table"
	for role in gateway observer; do
		host=$(hook_provider_host "$role")
		family_flag=$(hook_control_plane_host_family_flag "$host")
		prefix=$(hook_control_plane_host_prefix "$host")
		priority=$(hook_control_plane_priority "$role")
		ip "$family_flag" rule del priority "$priority" \
			ipproto tcp dport 22 to "$prefix" table main
	done
	nft list table inet "$table" >/dev/null 2>&1 &&
		hook_fail "control-plane nftables table survived deletion"
	for role in gateway observer; do
		[ "$(hook_control_plane_priority_count "$role")" -eq 0 ] ||
			hook_fail "control-plane policy rule survived deletion"
	done
	return 0
}

hook_control_plane_abort() {
	table=$(hook_control_plane_table)
	nft delete table inet "$table" >/dev/null 2>&1 || true
	for role in gateway observer; do
		host=$(hook_provider_host "$role")
		family_flag=$(hook_control_plane_host_family_flag "$host")
		prefix=$(hook_control_plane_host_prefix "$host")
		priority=$(hook_control_plane_priority "$role")
		if [ "$(hook_control_plane_exact_rule_count "$role")" -eq 1 ]; then
			ip "$family_flag" rule del priority "$priority" \
				ipproto tcp dport 22 to "$prefix" table main \
				>/dev/null 2>&1 || true
		fi
	done
}

hook_control_plane_residue() {
	table=$(hook_control_plane_table)
	nft list table inet "$table" >/dev/null 2>&1 &&
		hook_fail "control-plane nftables table residue remains"
	for role in gateway observer; do
		[ "$(hook_control_plane_priority_count "$role")" -eq 0 ] ||
			hook_fail "control-plane policy-rule priority residue remains"
	done
	return 0
}

hook_capture_client_state() {
	label=$1
	destination=$HOOK_EVIDENCE_DIR/client-$label
	[ ! -e "$destination" ] || hook_fail "client evidence phase already exists"
	umask 077
	mkdir "$destination"
	ip -j address show >"$destination/ip-address.json"
	ip -j -4 route show table all >"$destination/ip-route4.json"
	ip -j -6 route show table all >"$destination/ip-route6.json"
	ip -j -4 rule show >"$destination/ip-rule4.json"
	ip -j -6 rule show >"$destination/ip-rule6.json"
	nft -j list ruleset >"$destination/nft-ruleset.json"
	resolvectl status >"$destination/resolvectl-status.txt"
	ss -H -apn >"$destination/sockets.txt"
	sysctl -a 2>/dev/null |
		grep -E '^(net\.ipv4\.conf|net\.ipv6\.conf|net\.ipv4\.ip_forward|net\.ipv6\.conf\.all\.forwarding)' \
		>"$destination/network-sysctls.txt"
	[ -s "$destination/network-sysctls.txt" ] ||
		hook_fail "network sysctl evidence is empty"
	return 0
}

hook_state_path() {
	printf '%s/state.json\n' "$HOOK_EVIDENCE_DIR"
}

hook_load_client_state() {
	client_state=$(hook_state_path)
	[ -f "$client_state" ] && [ ! -L "$client_state" ] ||
		hook_fail "client state is absent"
	[ "$(jq -er '.version' "$client_state")" = winn-leak-client/v2 ] &&
		[ "$(jq -er '.run_id' "$client_state")" = "$HOOK_RUN_ID" ] &&
		[ "$(jq -er '.family' "$client_state")" = "$HOOK_FAMILY" ] ||
		hook_fail "client state binding is invalid"
	HOOK_CLIENT_PID=$(jq -er '.pid' "$client_state")
	HOOK_CLIENT_PHASE=$(jq -er '.phase' "$client_state")
	HOOK_CLIENT_INTERFACE=$(jq -r '.interface_name // empty' "$client_state")
	HOOK_CLIENT_NFT_TABLE=$(jq -er '.nft_table' "$client_state")
	if [ -n "$HOOK_CLIENT_INTERFACE" ]; then
		printf '%s' "$HOOK_CLIENT_INTERFACE" |
			LC_ALL=C grep -Eq '^winn[0-9a-f]{10}$' ||
			hook_fail "client state interface is invalid"
	else
		case "$HOOK_CLIENT_PHASE" in
		starting | failed) ;;
		*) hook_fail "live client state omitted its interface" ;;
		esac
	fi
	printf '%s' "$HOOK_CLIENT_NFT_TABLE" |
		LC_ALL=C grep -Eq '^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$' ||
		hook_fail "client state nftables table is invalid"
	case "$HOOK_CLIENT_PID" in
	'' | *[!0-9]*) hook_fail "client state PID is invalid" ;;
	esac
	[ "$HOOK_CLIENT_PID" -gt 1 ] || hook_fail "client state PID is unsafe"
}

hook_process_ticks() {
	process_pid=$1
	[ -r "/proc/$process_pid/stat" ] || return 1
	sed 's/^.*) //' "/proc/$process_pid/stat" | awk '{print $20}'
}

hook_process_pgid() {
	ps -o pgid= -p "$1" | tr -d ' '
}

hook_exact_process_alive() {
	process_pid=$1
	expected_pgid=$2
	expected_ticks=$3
	[ -d "/proc/$process_pid" ] &&
		[ "$(hook_process_ticks "$process_pid")" = "$expected_ticks" ] &&
		[ "$(hook_process_pgid "$process_pid")" = "$expected_pgid" ] &&
		[ "$process_pid" = "$expected_pgid" ]
}

hook_process_group_alive() {
	/usr/bin/kill -0 -- "-$1" 2>/dev/null
}

hook_stop_exact_process() {
	process_pid=$1
	expected_pgid=$2
	expected_ticks=$3
	if ! hook_exact_process_alive "$process_pid" "$expected_pgid" "$expected_ticks"; then
		if hook_process_group_alive "$expected_pgid"; then
			hook_fail "managed process leader changed while its group remains"
		fi
		return 0
	fi
	/usr/bin/kill -TERM -- "-$expected_pgid"
	attempt=0
	while hook_process_group_alive "$expected_pgid"; do
		attempt=$((attempt + 1))
		if [ "$attempt" -eq 100 ]; then
			/usr/bin/kill -KILL -- "-$expected_pgid"
		fi
		[ "$attempt" -lt 200 ] ||
			hook_fail "managed process group survived SIGKILL"
		sleep 0.05
	done
}

hook_probe_runtime_path() {
	printf '%s/.winn-leak-probe-runtime.json\n' "$HOOK_EVIDENCE_DIR"
}

hook_start_client_pcap() {
	runtime_path=$(hook_probe_runtime_path)
	[ ! -e "$runtime_path" ] || hook_fail "client pcap runtime already exists"
	pcap_path=$HOOK_EVIDENCE_DIR/client.pcap
	[ ! -e "$pcap_path" ] || hook_fail "client pcap evidence already exists"
	umask 077
	/usr/bin/setsid "$HOOK_TCPDUMP" -U -i any -s 0 -w "$pcap_path" \
		>"$HOOK_EVIDENCE_DIR/client-pcap.stdout.log" \
		2>"$HOOK_EVIDENCE_DIR/client-pcap.stderr.log" </dev/null &
	pcap_pid=$!
	pcap_ticks=$(hook_process_ticks "$pcap_pid") ||
		hook_fail "tcpdump exited before identity capture"
	pcap_pgid=$(hook_process_pgid "$pcap_pid")
	[ "$pcap_pid" = "$pcap_pgid" ] ||
		hook_fail "tcpdump did not own an exact process group"
	sleep 0.2
	hook_exact_process_alive "$pcap_pid" "$pcap_pgid" "$pcap_ticks" ||
		hook_fail "tcpdump exited before readiness"
	jq -n \
		--arg version winn-leak-probe-runtime/v2 \
		--arg run_id "$HOOK_RUN_ID" \
		--argjson pid "$pcap_pid" \
		--argjson pgid "$pcap_pgid" \
		--arg start_ticks "$pcap_ticks" \
		'{version:$version,run_id:$run_id,
		  pcap:{pid:$pid,pgid:$pgid,start_ticks:$start_ticks}}' \
		>"$runtime_path"
	chmod 0600 "$runtime_path"
	sync "$runtime_path"
}

hook_stop_client_pcap() {
	runtime_path=$(hook_probe_runtime_path)
	[ -f "$runtime_path" ] || return 0
	[ "$(jq -er '.version' "$runtime_path")" = winn-leak-probe-runtime/v2 ] &&
		[ "$(jq -er '.run_id' "$runtime_path")" = "$HOOK_RUN_ID" ] ||
		hook_fail "client pcap runtime binding is invalid"
	hook_stop_exact_process \
		"$(jq -er '.pcap.pid' "$runtime_path")" \
		"$(jq -er '.pcap.pgid' "$runtime_path")" \
		"$(jq -er '.pcap.start_ticks' "$runtime_path")"
	rm -f "$runtime_path"
}
