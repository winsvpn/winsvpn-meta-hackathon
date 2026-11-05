#!/bin/sh
set -eu

# Fault-injection SSH wrapper for the Phase 1 dual-provider runner. The first
# UpCloud destination call fails before invoking SSH; every later call delegates
# to the real client. Use only with a unique smoke matrix and an explicit
# private sentinel path.

sentinel=${ANCHOR_OUTAGE_SENTINEL:?set ANCHOR_OUTAGE_SENTINEL}
real_ssh=${ANCHOR_REAL_SSH_BIN:-/usr/bin/ssh}
outage_call=${ANCHOR_OUTAGE_PROVIDER_CALL:-1}

case "$outage_call" in
	"" | *[!0-9]*) echo "invalid ANCHOR_OUTAGE_PROVIDER_CALL" >&2; exit 64 ;;
esac
if [ "$outage_call" -lt 1 ]; then
	echo "ANCHOR_OUTAGE_PROVIDER_CALL must be positive" >&2
	exit 64
fi

case " $* " in
*" winn-anchor@<NODE_EXIT_CHI> "*)
	counter_file=$sentinel.counter
	current_call=0
	if [ -f "$counter_file" ]; then
		current_call=$(tr -d '[:space:]' <"$counter_file")
	fi
	case "$current_call" in
		"" | *[!0-9]*) echo "invalid outage counter" >&2; exit 65 ;;
	esac
	current_call=$((current_call + 1))
	(umask 077 && printf '%s\n' "$current_call" >"$counter_file.tmp")
	mv "$counter_file.tmp" "$counter_file"
	if [ "$current_call" -eq "$outage_call" ] &&
		[ ! -e "$sentinel" ]; then
		(umask 077 && : >"$sentinel")
		echo "intentional one-provider outage smoke" >&2
		exit 255
	fi
	;;
esac

exec "$real_ssh" "$@"
