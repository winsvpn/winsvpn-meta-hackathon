#!/bin/sh
set -eu

SCRIPT_DIR=$(
	CDPATH='' cd -- "$(dirname -- "$0")" && pwd
)
MATRIX_SCRIPT="$SCRIPT_DIR/aicore_phase1_auto_matrix.sh"
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

mkdir -p "$TEST_ROOT/bin"
FAKE="$TEST_ROOT/bin/fake"
AUTO="$TEST_ROOT/bin/auto"
AUDIT="$TEST_ROOT/bin/audit"
PROFILE="$TEST_ROOT/profile.json"
MANIFEST="$TEST_ROOT/source.sha256"
SCHEMA="$TEST_ROOT/postgres.sql"
MATRIX_ROOT="$TEST_ROOT/matrix-must-stay-absent"
JQ=$(command -v jq) || fail "jq is required"

cat >"$FAKE" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$AUDIT" <<'EOF'
#!/bin/sh
test "$1" = -detect-finalizer-leaks
exit 0
EOF
cat >"$MANIFEST" <<'EOF'
fixture source manifest
EOF
SOURCE_DIGEST=$(sha256sum "$MANIFEST" | awk '{ print $1 }')
cat >"$AUTO" <<EOF
#!/bin/sh
if [ "\${1:-}" = -print-source-digest ]; then
	echo "$SOURCE_DIGEST"
	exit 0
fi
exit 64
EOF
cat >"$PROFILE" <<'EOF'
{
  "schema": "winn-phase1-auto-impairment-profiles/v2",
  "batch_size": 100,
  "schedule_seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "attempts_per_readiness_per_profile": 1,
  "profiles": [{"id": "fixture"}],
  "readiness_classes": ["warm", "cold"]
}
EOF
cat >"$SCHEMA" <<'EOF'
-- fixture
EOF
chmod 0755 "$FAKE" "$AUTO" "$AUDIT"

PROFILE_DIGEST=$(sha256sum "$PROFILE" | awk '{ print $1 }')
AWG_DIGEST=$(sha256sum "$FAKE" | awk '{ print $1 }')

run_preflight() {
	MATRIX_MODE=preflight \
	MATRIX_ID=preflight-test \
	MATRIX_ROOT="$MATRIX_ROOT" \
	ALLOW_PARTIAL_MATRIX="${TEST_ALLOW_PARTIAL_MATRIX:-1}" \
	ANCHOR_MODE=disabled \
	PROFILE_FILTER="${TEST_PROFILE_FILTER:-}" \
	READINESS_FILTER="${TEST_READINESS_FILTER:-}" \
	EXPECTED_SOURCE_DIGEST="$SOURCE_DIGEST" \
	EXPECTED_AWG_ENGINE_SHA256="$AWG_DIGEST" \
	EXPECTED_PROFILE_SHA256="${TEST_EXPECTED_PROFILE_SHA256:-$PROFILE_DIGEST}" \
	HARNESS="$FAKE" \
	AUTO_BIN="$AUTO" \
	AWG_BIN="$FAKE" \
	AWG_ENGINE="$FAKE" \
	FIXTURE_BIN="$FAKE" \
	CARRIER_BIN="$FAKE" \
	PKI_BIN="$FAKE" \
	TOKEN_ISSUER_BIN="$FAKE" \
	TOKEN_BIN="$FAKE" \
	AUDIT_BIN="$AUDIT" \
	MEASUREMENT_VERIFY_BIN="$FAKE" \
	MATRIX_VERIFY_BIN="$FAKE" \
	RESPONDER_BIN="$FAKE" \
	FLOCK_BIN="$FAKE" \
	JQ_BIN="$JQ" \
	TIMEOUT_BIN="$FAKE" \
	POSTGRES_SCHEMA="$SCHEMA" \
	SOURCE_MANIFEST="$MANIFEST" \
	PROFILE_CONFIG="${TEST_PROFILE_CONFIG:-$PROFILE}" \
	sh "$MATRIX_SCRIPT"
}

output=$(run_preflight)
case "$output" in
"MATRIX_PREFLIGHT schema=winn-phase1-auto-matrix-preflight/v1 "*" status=ready profile_filter=all readiness_filter=all mutation=none") ;;
*) fail "unexpected preflight output: $output" ;;
esac
if [ -e "$MATRIX_ROOT" ]; then
	fail "preflight created the matrix root"
fi

bad_partial=$(
	TEST_ALLOW_PARTIAL_MATRIX=banana run_preflight 2>&1
) && fail "preflight accepted a nonnumeric partial-matrix flag"
case "$bad_partial" in
*"ALLOW_PARTIAL_MATRIX must be 0 or 1"*) ;;
*) fail "invalid partial flag produced the wrong error: $bad_partial" ;;
esac

bad_profile=$(
	TEST_PROFILE_FILTER=not-in-frozen-profile run_preflight 2>&1
) && fail "preflight accepted an unknown profile filter"
case "$bad_profile" in
*"PROFILE_FILTER is not in the frozen profile configuration"*) ;;
*) fail "unknown profile produced the wrong error: $bad_profile" ;;
esac

missing_readiness_profile="$TEST_ROOT/profile-warm-only.json"
cat >"$missing_readiness_profile" <<'EOF'
{
  "schema": "winn-phase1-auto-impairment-profiles/v2",
  "batch_size": 100,
  "schedule_seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "attempts_per_readiness_per_profile": 1,
  "profiles": [{"id": "fixture"}],
  "readiness_classes": ["warm"]
}
EOF
missing_readiness_digest=$(
	sha256sum "$missing_readiness_profile" | awk '{ print $1 }'
)
bad_readiness=$(
	TEST_PROFILE_CONFIG="$missing_readiness_profile" \
	TEST_EXPECTED_PROFILE_SHA256="$missing_readiness_digest" \
	TEST_READINESS_FILTER=cold \
	run_preflight 2>&1
) && fail "preflight accepted an absent frozen readiness class"
case "$bad_readiness" in
*"READINESS_FILTER is not in the frozen profile configuration"*) ;;
*) fail "absent readiness produced the wrong error: $bad_readiness" ;;
esac
if [ -e "$MATRIX_ROOT" ]; then
	fail "failed filter validation created the matrix root"
fi

bad_awg=$(
	MATRIX_MODE=preflight \
	MATRIX_ID=preflight-test \
	MATRIX_ROOT="$MATRIX_ROOT" \
	ALLOW_PARTIAL_MATRIX=1 \
	ANCHOR_MODE=disabled \
	EXPECTED_SOURCE_DIGEST="$SOURCE_DIGEST" \
	EXPECTED_AWG_ENGINE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
	EXPECTED_PROFILE_SHA256="$PROFILE_DIGEST" \
	HARNESS="$FAKE" \
	AUTO_BIN="$AUTO" \
	AWG_BIN="$FAKE" \
	AWG_ENGINE="$FAKE" \
	FIXTURE_BIN="$FAKE" \
	CARRIER_BIN="$FAKE" \
	PKI_BIN="$FAKE" \
	TOKEN_ISSUER_BIN="$FAKE" \
	TOKEN_BIN="$FAKE" \
	AUDIT_BIN="$AUDIT" \
	MEASUREMENT_VERIFY_BIN="$FAKE" \
	MATRIX_VERIFY_BIN="$FAKE" \
	RESPONDER_BIN="$FAKE" \
	FLOCK_BIN="$FAKE" \
	JQ_BIN="$JQ" \
	TIMEOUT_BIN="$FAKE" \
	POSTGRES_SCHEMA="$SCHEMA" \
	SOURCE_MANIFEST="$MANIFEST" \
	PROFILE_CONFIG="$PROFILE" \
	sh "$MATRIX_SCRIPT" 2>&1
) && fail "preflight accepted the wrong AWG engine digest"
case "$bad_awg" in
*"Winn AWG engine digest mismatch"*) ;;
*) fail "wrong AWG digest produced the wrong error: $bad_awg" ;;
esac
if [ -e "$MATRIX_ROOT" ]; then
	fail "failed preflight created the matrix root"
fi

bad_mode=$(
	MATRIX_MODE=typo sh "$MATRIX_SCRIPT" 2>&1
) && fail "invalid matrix mode was accepted"
case "$bad_mode" in
*"MATRIX_MODE must be preflight or run"*) ;;
*) fail "invalid mode was not rejected first: $bad_mode" ;;
esac

resume_schema_count=$(
	grep -c 'winn-phase1-auto-matrix-batch-closed-pending/v3' \
		"$MATRIX_SCRIPT"
)
if [ "$resume_schema_count" -ne 2 ]; then
	fail "batch writer and resume reader do not share one exact schema"
fi

echo "PASS: matrix preflight is zero-write and digest-bound"
