#!/bin/sh
set -eu

# Exact controller-cycle adapter for the Phase-1 Auto matrix.
#
# This adapter does not make the local namespace harness a real four-node
# topology. It only makes one controller invocation map to exactly one matrix
# profile/readiness/attempt with an unambiguous cycle-owned matrix ID.

fail() {
	echo "FAIL: $*" >&2
	exit 64
}

actual_names=$(
	/usr/bin/env |
		/usr/bin/cut -d= -f1 |
		/usr/bin/grep -Ev '^(PWD|SHLVL|_)$' |
		LC_ALL=C /usr/bin/sort
)
expected_names='READINESS
WINN_SOAK_ADAPTER_MODE
WINN_SOAK_CYCLE_SEQUENCE
WINN_SOAK_INSTANCE_NONCE
WINN_SOAK_MATRIX_RELATIVE_PATH
WINN_SOAK_MATRIX_SHA256
WINN_SOAK_PROFILE
WINN_SOAK_RUN_ID'
if [ "$actual_names" != "$expected_names" ]; then
	fail "controller environment names are not the exact eight-name contract"
fi

case "$WINN_SOAK_ADAPTER_MODE" in
preflight | run) ;;
*) fail "WINN_SOAK_ADAPTER_MODE must be preflight or run" ;;
esac
case "$READINESS" in
warm | cold) ;;
*) fail "READINESS must be warm or cold" ;;
esac
case "$WINN_SOAK_RUN_ID" in
"" | *[!A-Za-z0-9_.-]*) fail "WINN_SOAK_RUN_ID is invalid" ;;
esac
if [ "${#WINN_SOAK_RUN_ID}" -gt 64 ]; then
	fail "WINN_SOAK_RUN_ID exceeds 64 bytes"
fi
case "$WINN_SOAK_PROFILE" in
"" | *[!A-Za-z0-9_.-]*) fail "WINN_SOAK_PROFILE is invalid" ;;
esac
if [ "${#WINN_SOAK_PROFILE}" -gt 64 ]; then
	fail "WINN_SOAK_PROFILE exceeds 64 bytes"
fi
case "$WINN_SOAK_CYCLE_SEQUENCE" in
"" | *[!0-9]*) fail "WINN_SOAK_CYCLE_SEQUENCE is invalid" ;;
esac
if [ "$WINN_SOAK_CYCLE_SEQUENCE" -lt 1 ] ||
	[ "$WINN_SOAK_CYCLE_SEQUENCE" -gt 1000000 ] ||
	[ "$WINN_SOAK_CYCLE_SEQUENCE" != \
		"$((WINN_SOAK_CYCLE_SEQUENCE + 0))" ]; then
	fail "WINN_SOAK_CYCLE_SEQUENCE must be canonical decimal within [1,1000000]"
fi
case "$WINN_SOAK_INSTANCE_NONCE" in
????????????????????????????????) ;;
*) fail "WINN_SOAK_INSTANCE_NONCE must be 32 lowercase hex characters" ;;
esac
case "$WINN_SOAK_INSTANCE_NONCE" in
*[!0-9a-f]*) fail "WINN_SOAK_INSTANCE_NONCE must be 32 lowercase hex characters" ;;
esac

if [ "$WINN_SOAK_MATRIX_RELATIVE_PATH" != \
	"scripts/aicore_phase1_auto_matrix.sh" ]; then
	fail "WINN_SOAK_MATRIX_RELATIVE_PATH must be scripts/aicore_phase1_auto_matrix.sh"
fi
case "$WINN_SOAK_MATRIX_SHA256" in
????????????????????????????????????????????????????????????????) ;;
*) fail "WINN_SOAK_MATRIX_SHA256 must be 64 lowercase hex characters" ;;
esac
case "$WINN_SOAK_MATRIX_SHA256" in
*[!0-9a-f]*) fail "WINN_SOAK_MATRIX_SHA256 must be 64 lowercase hex characters" ;;
esac

WORKING_ROOT=$(pwd -P)
case "$WORKING_ROOT" in
/*) ;;
*) fail "controller working directory did not resolve absolutely" ;;
esac
MATRIX_SCRIPT="$WORKING_ROOT/$WINN_SOAK_MATRIX_RELATIVE_PATH"
if [ ! -f "$MATRIX_SCRIPT" ] || [ -L "$MATRIX_SCRIPT" ]; then
	fail "pinned matrix script is absent or symbolic"
fi
if [ -x /usr/bin/sha256sum ]; then
	actual_matrix_sha256=$(
		/usr/bin/sha256sum "$MATRIX_SCRIPT" |
			/usr/bin/awk '{ print $1 }'
	)
elif [ -x /usr/bin/shasum ]; then
	actual_matrix_sha256=$(
		/usr/bin/shasum -a 256 "$MATRIX_SCRIPT" |
			/usr/bin/awk '{ print $1 }'
	)
else
	fail "no system SHA-256 utility is available"
fi
if [ "$actual_matrix_sha256" != "$WINN_SOAK_MATRIX_SHA256" ]; then
	fail "pinned matrix script digest mismatch"
fi

MATRIX_ID="soak-${WINN_SOAK_RUN_ID}-${WINN_SOAK_CYCLE_SEQUENCE}-${WINN_SOAK_INSTANCE_NONCE}"
export MATRIX_ID
export MATRIX_MODE="$WINN_SOAK_ADAPTER_MODE"
export ALLOW_PARTIAL_MATRIX=1
export ATTEMPTS_PER_CLASS=1
export PROFILE_FILTER="$WINN_SOAK_PROFILE"
export READINESS_FILTER="$READINESS"
export ANCHOR_MODE=disabled

exec /bin/sh "$MATRIX_SCRIPT"
