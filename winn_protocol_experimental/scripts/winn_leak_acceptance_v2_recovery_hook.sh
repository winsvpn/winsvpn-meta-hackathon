#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=winn_leak_acceptance_v2_common.sh
. "$SCRIPT_DIR/winn_leak_acceptance_v2_common.sh"

hook_validate_context "$@"
hook_load_config

family_field() {
	hook_json_required ".families.$HOOK_FAMILY.$1"
}

CONFIGURED_NFT_TABLE=$(family_field nft_table)

family_flag() {
	case "$HOOK_FAMILY" in
	v4) printf '%s\n' -4 ;;
	v6) printf '%s\n' -6 ;;
	esac
}

group_members() {
	group_id=$1
	for stat_path in /proc/[0-9]*/stat; do
		[ -r "$stat_path" ] || continue
		stat_fields=$(sed 's/^.*) //' "$stat_path")
		process_group=$(printf '%s\n' "$stat_fields" | awk '{print $3}')
		[ "$process_group" = "$group_id" ] || continue
		process_pid=${stat_path#/proc/}
		process_pid=${process_pid%/stat}
		printf '%s\n' "$process_pid"
	done
}

terminate_exact_client_group() {
	group_id=$1
	[ "$group_id" -gt 1 ] || hook_fail "refusing unsafe client process group"
	members=$(group_members "$group_id")
	[ ! -d "/proc/$group_id" ] ||
		hook_fail "client group leader is unexpectedly still alive"
	for member in $members; do
		executable=$(readlink -f "/proc/$member/exe") ||
			hook_fail "cannot identify client process-group member"
		[ "$executable" = "$HOOK_AWG_GO" ] ||
			hook_fail "unexpected executable remains in the client process group: $executable"
	done
	if [ -n "$members" ]; then
		/usr/bin/kill -TERM -- "-$group_id"
		attempt=0
		while hook_process_group_alive "$group_id"; do
			attempt=$((attempt + 1))
			if [ "$attempt" -eq 100 ]; then
				/usr/bin/kill -KILL -- "-$group_id"
			fi
			[ "$attempt" -lt 200 ] ||
				hook_fail "client process group survived recovery"
			sleep 0.05
		done
	fi
}

route_tables_for_interface() {
	interface_name=$1
	ip -j "$(family_flag)" route show table all |
		jq -r --arg interface "$interface_name" '
			.[] |
			select(.dev == $interface) |
			(.table | tostring) |
			select(test("^[0-9]+$"))
		' |
		sort -u
}

delete_rules_for_table() {
	table=$1
	flag=$(family_flag)
	rules=$(ip -j "$flag" rule show |
		jq -r --arg table "$table" '
			.[] |
			select((.table | tostring) == $table) |
			.priority | tostring
		' |
		sort -un)
	for priority in $rules; do
		printf '%s' "$priority" | LC_ALL=C grep -Eq '^[1-9][0-9]{2,9}$' ||
			hook_fail "unsafe recovery rule priority"
		[ "$(ip -j "$flag" rule show |
			jq --argjson priority "$priority" '
				[.[] | select(.priority == $priority)] | length
			')" -eq 1 ] ||
			hook_fail "recovery rule priority is not unique"
		ip "$flag" rule del priority "$priority" lookup "$table"
	done
	[ "$(ip -j "$flag" rule show |
		jq --arg table "$table" '
			[.[] | select((.table | tostring) == $table)] | length
		')" -eq 0 ] ||
		hook_fail "policy rules still reference the Winn route table"
}

remove_secret_directories() {
	temp_root=$HOOK_EVIDENCE_DIR/temp
	[ -d "$temp_root" ] || return 0
	for directory in "$temp_root"/winn-directawg-*; do
		[ -e "$directory" ] || continue
		[ -d "$directory" ] && [ ! -L "$directory" ] ||
			hook_fail "unexpected client secret path type"
		find "$directory" -mindepth 1 -maxdepth 1 \
			! -name private-key ! -name preshared-key -print -quit |
			grep . >/dev/null &&
			hook_fail "unexpected file in client secret directory"
		for secret in "$directory/private-key" "$directory/preshared-key"; do
			if [ -e "$secret" ]; then
				[ -f "$secret" ] && [ ! -L "$secret" ] ||
					hook_fail "unexpected client secret file type"
				rm -f "$secret"
			fi
		done
		rmdir "$directory"
	done
}

recover_objects() {
	if [ -f "$(hook_state_path)" ]; then
		hook_load_client_state
	else
		HOOK_CLIENT_INTERFACE=
		HOOK_CLIENT_NFT_TABLE=$CONFIGURED_NFT_TABLE
		HOOK_CLIENT_PID=
	fi
	if [ -n "$HOOK_CLIENT_PID" ] && hook_process_group_alive "$HOOK_CLIENT_PID"; then
		terminate_exact_client_group "$HOOK_CLIENT_PID"
	fi
	if [ -n "$HOOK_CLIENT_INTERFACE" ]; then
		tables=$(route_tables_for_interface "$HOOK_CLIENT_INTERFACE")
		for table in $tables; do
			printf '%s' "$table" | LC_ALL=C grep -Eq '^[1-9][0-9]{2,9}$' ||
				hook_fail "unsafe Winn route table discovered"
			delete_rules_for_table "$table"
			ip "$(family_flag)" route flush table "$table"
		done
		if ip link show dev "$HOOK_CLIENT_INTERFACE" >/dev/null 2>&1; then
			resolvectl revert "$HOOK_CLIENT_INTERFACE" >/dev/null 2>&1 || true
			ip link delete dev "$HOOK_CLIENT_INTERFACE"
		fi
	fi
	if nft list table inet "$HOOK_CLIENT_NFT_TABLE" >/dev/null 2>&1; then
		nft delete table inet "$HOOK_CLIENT_NFT_TABLE"
	fi
	remove_secret_directories
}

assert_recovery_residue() {
	if [ -f "$(hook_state_path)" ]; then
		hook_load_client_state
	else
		HOOK_CLIENT_INTERFACE=
		HOOK_CLIENT_NFT_TABLE=$CONFIGURED_NFT_TABLE
		HOOK_CLIENT_PID=
	fi
	if [ -n "$HOOK_CLIENT_PID" ]; then
		hook_process_group_alive "$HOOK_CLIENT_PID" &&
			hook_fail "client process-group residue remains"
	fi
	if [ -n "$HOOK_CLIENT_INTERFACE" ]; then
		ip link show dev "$HOOK_CLIENT_INTERFACE" >/dev/null 2>&1 &&
			hook_fail "client interface residue remains after recovery"
		[ -z "$(route_tables_for_interface "$HOOK_CLIENT_INTERFACE")" ] ||
			hook_fail "client route-table residue remains after recovery"
	fi
	nft list table inet "$HOOK_CLIENT_NFT_TABLE" >/dev/null 2>&1 &&
		hook_fail "client nftables residue remains after recovery"
	find "$HOOK_EVIDENCE_DIR/temp" -mindepth 1 -print -quit |
		grep . >/dev/null &&
		hook_fail "client temporary secret residue remains after recovery"
	return 0
}

case "$HOOK_ACTION" in
recover-crash)
	hook_load_client_state
	[ "$(jq -er '.phase' "$(hook_state_path)")" = crashing ] ||
		hook_fail "crash recovery requires the crashing state"
	hook_capture_client_state recovery-before
	terminate_exact_client_group "$HOOK_CLIENT_PID"
	recover_objects
	hook_capture_client_state recovery-after
	assert_recovery_residue
	echo "RECOVERED role=recovery run_id=$HOOK_RUN_ID family=$HOOK_FAMILY"
	;;
cleanup)
	hook_capture_client_state cleanup-before
	recover_objects
	hook_capture_client_state cleanup-after
	assert_recovery_residue
	echo "CLEANED role=recovery run_id=$HOOK_RUN_ID family=$HOOK_FAMILY"
	;;
residue)
	assert_recovery_residue
	echo "CLEAN role=recovery run_id=$HOOK_RUN_ID family=$HOOK_FAMILY"
	;;
*) hook_fail "unsupported recovery action: $HOOK_ACTION" ;;
esac
