#!/bin/sh
set -eu

TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM
SOURCE_DIR=$(
	CDPATH='' cd -- "$(/usr/bin/dirname -- "$0")" && pwd
)
RUNNER="$TEST_ROOT/accepted-runner"
SNAPSHOT="$TEST_ROOT/snapshot"
mkdir -p "$SNAPSHOT/scripts"
cp "$SOURCE_DIR/aicore_phase1_single_cycle_adapter.sh" "$RUNNER"
chmod 0755 "$RUNNER"

cat >"$SNAPSHOT/scripts/aicore_phase1_auto_matrix.sh" <<'EOF'
#!/bin/sh
set -eu
test "$MATRIX_MODE" = "$WINN_SOAK_ADAPTER_MODE"
test "$ALLOW_PARTIAL_MATRIX" = 1
test "$ATTEMPTS_PER_CLASS" = 1
test "$PROFILE_FILTER" = "$WINN_SOAK_PROFILE"
test "$READINESS_FILTER" = "$READINESS"
test "$ANCHOR_MODE" = disabled
expected="soak-${WINN_SOAK_RUN_ID}-${WINN_SOAK_CYCLE_SEQUENCE}-${WINN_SOAK_INSTANCE_NONCE}"
test "$MATRIX_ID" = "$expected"
printf 'adapter-ok mode=%s matrix=%s readiness=%s profile=%s\n' \
	"$MATRIX_MODE" "$MATRIX_ID" "$READINESS_FILTER" "$PROFILE_FILTER"
EOF
chmod 0755 "$SNAPSHOT/scripts/aicore_phase1_auto_matrix.sh"
MATRIX_SHA256=$(
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$SNAPSHOT/scripts/aicore_phase1_auto_matrix.sh"
	else
		shasum -a 256 "$SNAPSHOT/scripts/aicore_phase1_auto_matrix.sh"
	fi |
		awk '{ print $1 }'
)
case "$(uname -s)" in
Linux)
	FD_RUNNER_COMMAND=/proc/self/fd/3
	FD_RUNNER_ARGUMENT=
	;;
Darwin)
	FD_RUNNER_COMMAND=/bin/sh
	FD_RUNNER_ARGUMENT=/dev/fd/3
	;;
*) echo "FAIL: sealed-FD test requires Linux or Darwin" >&2; exit 1 ;;
esac

run_adapter() {
	(
		cd "$SNAPSHOT"
		exec 3<"$RUNNER"
		if [ -n "$FD_RUNNER_ARGUMENT" ]; then
			env -i \
				READINESS="$1" \
				WINN_SOAK_ADAPTER_MODE="$2" \
				WINN_SOAK_CYCLE_SEQUENCE="$3" \
				WINN_SOAK_INSTANCE_NONCE=0123456789abcdef0123456789abcdef \
				WINN_SOAK_MATRIX_RELATIVE_PATH=scripts/aicore_phase1_auto_matrix.sh \
				WINN_SOAK_MATRIX_SHA256="${TEST_MATRIX_SHA256:-$MATRIX_SHA256}" \
				WINN_SOAK_PROFILE="$4" \
				WINN_SOAK_RUN_ID=single-cycle-test \
				"$FD_RUNNER_COMMAND" "$FD_RUNNER_ARGUMENT"
		else
			env -i \
				READINESS="$1" \
				WINN_SOAK_ADAPTER_MODE="$2" \
				WINN_SOAK_CYCLE_SEQUENCE="$3" \
				WINN_SOAK_INSTANCE_NONCE=0123456789abcdef0123456789abcdef \
				WINN_SOAK_MATRIX_RELATIVE_PATH=scripts/aicore_phase1_auto_matrix.sh \
				WINN_SOAK_MATRIX_SHA256="${TEST_MATRIX_SHA256:-$MATRIX_SHA256}" \
				WINN_SOAK_PROFILE="$4" \
				WINN_SOAK_RUN_ID=single-cycle-test \
				"$FD_RUNNER_COMMAND"
		fi
	)
}

warm=$(run_adapter warm preflight 1 constrained-100ms)
case "$warm" in
"adapter-ok mode=preflight matrix=soak-single-cycle-test-1-0123456789abcdef0123456789abcdef readiness=warm profile=constrained-100ms") ;;
*) echo "FAIL: warm binding mismatch: $warm" >&2; exit 1 ;;
esac

cold=$(run_adapter cold run 42 constrained-1pct)
case "$cold" in
"adapter-ok mode=run matrix=soak-single-cycle-test-42-0123456789abcdef0123456789abcdef readiness=cold profile=constrained-1pct") ;;
*) echo "FAIL: cold binding mismatch: $cold" >&2; exit 1 ;;
esac

if env -i \
	READINESS=warm \
	WINN_SOAK_ADAPTER_MODE=preflight \
	WINN_SOAK_CYCLE_SEQUENCE=01 \
	WINN_SOAK_INSTANCE_NONCE=0123456789abcdef0123456789abcdef \
	WINN_SOAK_MATRIX_RELATIVE_PATH=scripts/aicore_phase1_auto_matrix.sh \
	WINN_SOAK_MATRIX_SHA256="$MATRIX_SHA256" \
	WINN_SOAK_PROFILE=fixture \
	WINN_SOAK_RUN_ID=single-cycle-test \
	"$RUNNER" >/dev/null 2>&1; then
	echo "FAIL: noncanonical sequence was accepted" >&2
	exit 1
fi

if env -i \
	EXTRA=forbidden \
	READINESS=warm \
	WINN_SOAK_ADAPTER_MODE=preflight \
	WINN_SOAK_CYCLE_SEQUENCE=1 \
	WINN_SOAK_INSTANCE_NONCE=0123456789abcdef0123456789abcdef \
	WINN_SOAK_MATRIX_RELATIVE_PATH=scripts/aicore_phase1_auto_matrix.sh \
	WINN_SOAK_MATRIX_SHA256="$MATRIX_SHA256" \
	WINN_SOAK_PROFILE=fixture \
	WINN_SOAK_RUN_ID=single-cycle-test \
	"$RUNNER" >/dev/null 2>&1; then
	echo "FAIL: extra environment variable was accepted" >&2
	exit 1
fi

if TEST_MATRIX_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
	run_adapter warm preflight 1 fixture >/dev/null 2>&1; then
	echo "FAIL: wrong pinned matrix digest was accepted" >&2
	exit 1
fi

echo "PASS: sealed-FD adapter binds exact controller identity, matrix, and readiness"
