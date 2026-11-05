#!/bin/sh
set -eu

# Tests for scripts/aicore_phase1_continuous_soak.sh.
#
# The wrapper is driven against a FAKE controller: a small script that records
# the argument vector it was handed and exits with whatever status the test
# asked for. That is the only way to check what the wrapper passes downstream,
# and it keeps these tests from needing a built binary, a snapshot, or a lab.
#
# Every invocation captures the wrapper's REAL exit status. Nothing here pipes
# the wrapper into grep or head: a pipeline reports its last stage's status, so
# a wrapper that failed behind a pipe would be recorded as having succeeded.
# Output is redirected to files, the status is read from $?, and the files are
# searched afterwards.

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WRAPPER="$ROOT_DIR/scripts/aicore_phase1_continuous_soak.sh"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/winn-soak-wrapper-test.XXXXXX")
cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

failures=0
checks=0

check() {
	description=$1
	shift
	checks=$((checks + 1))
	if "$@"; then
		echo "ok   - $description"
	else
		echo "FAIL - $description" >&2
		failures=$((failures + 1))
	fi
}

equals() {
	if [ "$1" = "$2" ]; then
		return 0
	fi
	echo "      wanted [$2], got [$1]" >&2
	return 1
}

file_contains() {
	if grep -q -- "$2" "$1"; then
		return 0
	fi
	echo "      $1 does not contain [$2]" >&2
	return 1
}

file_lacks() {
	if grep -q -- "$2" "$1"; then
		echo "      $1 unexpectedly contains [$2]" >&2
		return 1
	fi
	return 0
}

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

SNAPSHOT="$WORK/snapshot"
STATE="$WORK/state"
EVIDENCE="$WORK/evidence"
BIN="$WORK/bin"
mkdir -p "$SNAPSHOT/scripts" "$STATE" "$EVIDENCE" "$BIN"

RUNNER="$SNAPSHOT/scripts/aicore_phase1_auto_matrix.sh"
printf '#!/bin/sh\nexit 0\n' >"$RUNNER"
chmod 0755 "$RUNNER"

VERIFIER="$BIN/winn-phase1-matrix-verify"
printf 'verifier bytes\n' >"$VERIFIER"
chmod 0755 "$VERIFIER"

MANIFEST="$BIN/winn-auto-e2e.source.sha256"
printf 'aaaa  cmd/winn-auto-e2e/main_linux.go\n' >"$MANIFEST"

ENV_FILE="$WORK/soak.env"
printf 'MATRIX_ID=phase1-auto-v1\nPATH=/usr/bin:/bin\n' >"$ENV_FILE"
chmod 0600 "$ENV_FILE"

# The fake controller. It writes its argv, one argument per line, and exits
# with FAKE_CONTROLLER_STATUS so a downstream failure can be simulated.
CONTROLLER="$BIN/winn-phase1-soak-controller"
ARGV_LOG="$WORK/argv.txt"
cat >"$CONTROLLER" <<'FAKE'
#!/bin/sh
: >"$FAKE_CONTROLLER_ARGV"
for argument in "$@"; do
	printf '%s\n' "$argument" >>"$FAKE_CONTROLLER_ARGV"
done
echo "fake controller ran"
exit "${FAKE_CONTROLLER_STATUS:-0}"
FAKE
chmod 0755 "$CONTROLLER"

digest_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

RUNNER_DIGEST=$(digest_of "$RUNNER")
VERIFIER_DIGEST=$(digest_of "$VERIFIER")
MANIFEST_DIGEST=$(digest_of "$MANIFEST")

STDOUT="$WORK/stdout.txt"
STDERR="$WORK/stderr.txt"
status=0

# invoke MODE [EXTRA_ENV_ASSIGNMENTS...]
#
# The wrapper is run with a fully explicit environment so nothing from this
# test's own shell leaks into it and changes what is being measured.
invoke() {
	invoke_mode=$1
	shift
	: >"$ARGV_LOG"
	set +e
	env \
		PATH="$PATH" \
		FAKE_CONTROLLER_ARGV="$ARGV_LOG" \
		CONTROLLER_BIN="$CONTROLLER" \
		SNAPSHOT_ROOT="$SNAPSHOT" \
		STATE_ROOT="$STATE" \
		EVIDENCE_ROOT="$EVIDENCE" \
		RUNNER_PATH="$RUNNER" \
		VERIFIER_PATH="$VERIFIER" \
		SOURCE_MANIFEST="$MANIFEST" \
		ENV_FILE="$ENV_FILE" \
		RUN_ID=wrapper-test \
		MODE="$invoke_mode" \
		"$@" \
		"$WRAPPER" >"$STDOUT" 2>"$STDERR"
	status=$?
	set -e
}

# ---------------------------------------------------------------------------
# The default mode is preflight, and the pins reach the controller
# ---------------------------------------------------------------------------

invoke preflight
check "preflight exits zero" equals "$status" 0
check "the controller was invoked" file_contains "$STDOUT" "fake controller ran"
check "preflight mode is passed" file_contains "$ARGV_LOG" '^-preflight$'
check "the runner digest is computed and passed" \
	file_contains "$ARGV_LOG" "^-runner-sha256=$RUNNER_DIGEST\$"
check "the verifier digest is computed and passed" \
	file_contains "$ARGV_LOG" "^-verifier-sha256=$VERIFIER_DIGEST\$"
check "the manifest digest is computed and passed" \
	file_contains "$ARGV_LOG" "^-manifest-sha256=$MANIFEST_DIGEST\$"
check "the source digest defaults to the manifest digest" \
	file_contains "$ARGV_LOG" "^-source-digest=$MANIFEST_DIGEST\$"
check "the default duration is seven days" \
	file_contains "$ARGV_LOG" '^-duration=168h$'
check "the env file is passed" file_contains "$ARGV_LOG" "^-env-file=$ENV_FILE\$"
check "the harness announces it is not promotable" \
	file_contains "$STDOUT" "promotable=false"
check "the harness says it is not the production soak" \
	file_contains "$STDOUT" "not the production Auto soak"

# A wrapper that hardcoded the digests instead of computing them would pass
# every check above. Change the runner and require the pin to follow.
printf '#!/bin/sh\nexit 1\n' >"$RUNNER"
CHANGED_RUNNER_DIGEST=$(digest_of "$RUNNER")
invoke preflight
check "a changed runner produces a different pin" \
	file_contains "$ARGV_LOG" "^-runner-sha256=$CHANGED_RUNNER_DIGEST\$"
check "the old runner pin is gone" \
	file_lacks "$ARGV_LOG" "^-runner-sha256=$RUNNER_DIGEST\$"
printf '#!/bin/sh\nexit 0\n' >"$RUNNER"

# ---------------------------------------------------------------------------
# The controller's real exit status is the wrapper's exit status
# ---------------------------------------------------------------------------

invoke preflight FAKE_CONTROLLER_STATUS=65
check "a controller refusal propagates as 65" equals "$status" 65
invoke preflight FAKE_CONTROLLER_STATUS=66
check "a stopped soak propagates as 66" equals "$status" 66
invoke preflight FAKE_CONTROLLER_STATUS=0
check "success still propagates as 0" equals "$status" 0

# ---------------------------------------------------------------------------
# Mode handling
# ---------------------------------------------------------------------------

invoke dry-run
check "dry-run is accepted" equals "$status" 0
check "dry-run mode is passed" file_contains "$ARGV_LOG" '^-dry-run$'

invoke print-systemd-command
check "print-systemd-command is accepted" equals "$status" 0
check "print-systemd-command mode is passed" \
	file_contains "$ARGV_LOG" '^-print-systemd-command$'

invoke nonsense
check "an unknown mode is refused" equals "$status" 1
check "the refusal names MODE" file_contains "$STDERR" "MODE must be"

# The refusal must be about the MODE even when something else is also wrong,
# so an operator who mistyped the mode is not sent to fix a path.
: >"$ARGV_LOG"
set +e
env PATH="$PATH" FAKE_CONTROLLER_ARGV="$ARGV_LOG" MODE=typo \
	"$WRAPPER" >"$STDOUT" 2>"$STDERR"
status=$?
set -e
check "an unknown mode is refused before any path is checked" equals "$status" 1
check "the refusal is about MODE, not a missing variable" \
	file_contains "$STDERR" "MODE must be"

# ---------------------------------------------------------------------------
# A seven-day run needs an explicit confirmation
# ---------------------------------------------------------------------------

invoke run
check "MODE=run without confirmation is refused" equals "$status" 1
check "the refusal explains what run would start" \
	file_contains "$STDERR" "CONFIRM_SEVEN_DAY_RUN=1"
check "no controller was invoked for an unconfirmed run" \
	file_lacks "$STDOUT" "fake controller ran"

invoke run CONFIRM_SEVEN_DAY_RUN=1
check "MODE=run with confirmation reaches the controller" equals "$status" 0
check "run mode is passed" file_contains "$ARGV_LOG" '^-run$'

# ---------------------------------------------------------------------------
# Custody separation
# ---------------------------------------------------------------------------

# Control first: the tree is clean, so the refusal below is attributable to the
# seed rather than to anything else about the fixture.
invoke preflight
check "the clean fixture passes the custody scan" equals "$status" 0

printf 'not-a-real-seed-0011223344\n' >"$STATE/finalizer.seed"
invoke preflight
check "a finalizer seed on the producing host is refused" equals "$status" 1
check "the refusal names custody" file_contains "$STDERR" "CUSTODY"
check "the refusal does not echo the seed" \
	file_lacks "$STDERR" "0011223344"
check "no controller was invoked once custody failed" \
	file_lacks "$STDOUT" "fake controller ran"
rm -f "$STATE/finalizer.seed"

printf 'x\n' >"$EVIDENCE/signing.key"
invoke preflight
check "a signing key in the evidence root is refused" equals "$status" 1
rm -f "$EVIDENCE/signing.key"

invoke preflight
check "removing the material restores the clean result" equals "$status" 0

# ---------------------------------------------------------------------------
# Required inputs
# ---------------------------------------------------------------------------

invoke preflight ENV_FILE=
check "a missing ENV_FILE is refused" equals "$status" 1
check "the refusal names ENV_FILE" file_contains "$STDERR" "set ENV_FILE"

invoke preflight ENV_FILE=relative/path
check "a relative ENV_FILE is refused" equals "$status" 1
check "the refusal names the absolute-path requirement" \
	file_contains "$STDERR" "must be an absolute path"

invoke preflight ENV_FILE="$WORK/absent.env"
check "an ENV_FILE that does not exist is refused" equals "$status" 1
check "the refusal names the missing input" \
	file_contains "$STDERR" "required frozen input is missing"

invoke preflight RUN_ID=../escape
check "a RUN_ID with a path separator is refused" equals "$status" 1
check "the refusal names RUN_ID" file_contains "$STDERR" "RUN_ID is invalid"

invoke preflight CONTROLLER_BIN="$WORK/absent-controller"
check "a missing controller is refused" equals "$status" 1
check "the refusal names the controller" \
	file_contains "$STDERR" "controller is missing"

# ---------------------------------------------------------------------------
# An explicit source digest must agree with the manifest
# ---------------------------------------------------------------------------

invoke preflight EXPECTED_SOURCE_DIGEST="$MANIFEST_DIGEST"
check "an agreeing explicit source digest is accepted" equals "$status" 0

invoke preflight EXPECTED_SOURCE_DIGEST=0000000000000000000000000000000000000000000000000000000000000000
check "a disagreeing explicit source digest is refused" equals "$status" 1
check "the refusal explains the required relationship" \
	file_contains "$STDERR" "same value"

# ---------------------------------------------------------------------------
# The wrapper never starts a systemd unit
# ---------------------------------------------------------------------------

# The wrapper's own comments explain that it never starts a unit, so they name
# systemctl and systemd-run. A plain text search therefore reports the comment
# and says nothing about behaviour -- the first version of this check did
# exactly that and failed. What matters is whether either name appears in
# COMMAND position on an executable line, so comment lines are stripped first.
executable_lines() {
	grep -v '^[[:space:]]*#' "$1" >"$WORK/executable.sh" || true
	printf '%s' "$WORK/executable.sh"
}

WRAPPER_CODE=$(executable_lines "$WRAPPER")
check "the wrapper never invokes systemctl" \
	file_lacks "$WRAPPER_CODE" 'systemctl'
check "the wrapper never invokes systemd-run" \
	file_lacks "$WRAPPER_CODE" 'systemd-run'
# Without this, a stripping bug that produced an empty file would make both
# checks above pass on nothing at all.
check "stripping comments did not empty the file" \
	file_contains "$WRAPPER_CODE" 'exec '

# A search is only meaningful if it WOULD find what it claims to exclude. Both
# predicates are run against a file that genuinely invokes systemd, on an
# executable line, and must report it.
PROBE="$WORK/probe.sh"
printf '#!/bin/sh\n# a comment mentioning systemctl\nsystemctl start x\n' >"$PROBE"
PROBE_CODE=$(executable_lines "$PROBE")
if grep -q -- 'systemctl' "$PROBE_CODE"; then
	echo "ok   - the systemctl search finds a real invocation"
	checks=$((checks + 1))
else
	echo "FAIL - the systemctl search cannot find a real invocation, so the" >&2
	echo "       checks above prove nothing" >&2
	checks=$((checks + 1))
	failures=$((failures + 1))
fi
# And it is not merely matching the comment: a file whose ONLY mention is a
# comment must come back clean.
printf '#!/bin/sh\n# systemctl is never called here\ntrue\n' >"$PROBE"
PROBE_CODE=$(executable_lines "$PROBE")
if grep -q -- 'systemctl' "$PROBE_CODE"; then
	echo "FAIL - the search matches a comment, so it cannot distinguish an" >&2
	echo "       explanation from an invocation" >&2
	checks=$((checks + 1))
	failures=$((failures + 1))
else
	echo "ok   - the search ignores a comment-only mention"
	checks=$((checks + 1))
fi

# ---------------------------------------------------------------------------

echo "---"
echo "$checks checks, $failures failures"
if [ "$failures" -ne 0 ]; then
	exit 1
fi
echo "PASS: aicore_phase1_continuous_soak.sh pins its inputs, asserts custody \
separation, propagates real exit statuses, and starts nothing"
