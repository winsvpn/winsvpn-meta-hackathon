#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=winn_leak_acceptance_v2_common.sh
. "$SCRIPT_DIR/winn_leak_acceptance_v2_common.sh"

hook_validate_context "$@"
hook_load_config

case "$HOOK_ACTION" in
start | status | outage | recover)
	hook_provider_exec gateway "$HOOK_ACTION"
	;;
stop)
	hook_provider_exec gateway stop
	hook_provider_collect_and_purge gateway
	;;
residue)
	hook_provider_exec gateway residue
	;;
*) hook_fail "unsupported gateway action: $HOOK_ACTION" ;;
esac
