#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=winn_leak_acceptance_v2_common.sh
. "$SCRIPT_DIR/winn_leak_acceptance_v2_common.sh"

hook_validate_context "$@"
hook_load_config

case "$HOOK_ACTION" in
start)
	control_started=1
	control_start_cleanup() {
		if [ "$control_started" -eq 1 ]; then
			hook_control_plane_abort
		fi
	}
	trap control_start_cleanup EXIT HUP INT TERM
	hook_control_plane_start
	hook_provider_exec observer start
	control_started=0
	trap - EXIT HUP INT TERM
	;;
status | assert-prepared | assert-verified | assert-committed | \
	assert-outage-fail-closed | assert-recovered | \
	assert-crashed-fail-closed | assert-stopped)
	hook_provider_exec observer "$HOOK_ACTION"
	;;
stop)
	hook_provider_exec observer stop
	hook_provider_collect_and_purge observer
	hook_control_plane_stop
	;;
residue)
	hook_control_plane_residue
	hook_provider_exec observer residue
	;;
*) hook_fail "unsupported observer action: $HOOK_ACTION" ;;
esac
