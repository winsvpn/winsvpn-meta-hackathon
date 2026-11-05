#!/bin/sh
set -eu

# Operator front end for cmd/winn-phase1-soak-controller.
#
# NOT THE PRODUCTION AUTO SOAK. This wrapper and the controller behind it are a
# harness. The production Phase 1 Auto soak requires the real multi-gateway
# topology, a real seven-day execution on it, and a controller-side
# finalization performed off the producing host. None of that exists yet, and
# nothing this script produces may be cited as a passed gate.
#
# What it does: computes the SHA-256 pins of the runner, the verifier and the
# source manifest, asserts the custody separation this project depends on, and
# hands the whole lot to the controller. Every pin is computed HERE and passed
# explicitly, so the controller is never the thing that decides what it is
# allowed to run.
#
# What it deliberately does not do: start anything. MODE defaults to preflight,
# a real seven-day run needs a second explicit confirmation, and neither this
# script nor the controller ever invokes systemctl or systemd-run.
#
# Usage:
#   MODE=preflight ./scripts/aicore_phase1_continuous_soak.sh
#   MODE=dry-run   ./scripts/aicore_phase1_continuous_soak.sh
#   MODE=print-systemd-command ./scripts/aicore_phase1_continuous_soak.sh
#   MODE=run CONFIRM_SEVEN_DAY_RUN=1 ./scripts/aicore_phase1_continuous_soak.sh

CONTROLLER_BIN=${CONTROLLER_BIN:-/opt/winn-lab/bin/winn-phase1-soak-controller}
SNAPSHOT_ROOT=${SNAPSHOT_ROOT:-}
STATE_ROOT=${STATE_ROOT:-}
EVIDENCE_ROOT=${EVIDENCE_ROOT:-}
RUNNER_PATH=${RUNNER_PATH:-}
VERIFIER_PATH=${VERIFIER_PATH:-/opt/winn-lab/bin/winn-phase1-matrix-verify}
SOURCE_MANIFEST=${SOURCE_MANIFEST:-/opt/winn-lab/bin/winn-auto-e2e.source.sha256}
EXPECTED_SOURCE_DIGEST=${EXPECTED_SOURCE_DIGEST:-}
ENV_FILE=${ENV_FILE:-}
RUN_ID=${RUN_ID:-phase1-soak-v1}
DURATION=${DURATION:-168h}
CADENCE=${CADENCE:-1m}
CYCLE_TIMEOUT=${CYCLE_TIMEOUT:-30m}
COLD_EVERY=${COLD_EVERY:-4}
COLD_SETTLE=${COLD_SETTLE:-2m}
MIN_FREE_BYTES=${MIN_FREE_BYTES:-8589934592}
MAX_LOG_BYTES=${MAX_LOG_BYTES:-67108864}
MAX_LOG_FILES=${MAX_LOG_FILES:-8}
MAX_CYCLE_OUTPUT_BYTES=${MAX_CYCLE_OUTPUT_BYTES:-1048576}
MAX_CONTROLLER_OUTPUT_BYTES=${MAX_CONTROLLER_OUTPUT_BYTES:-16777216}
MAX_RSS_BYTES=${MAX_RSS_BYTES:-4294967296}
MAX_THREADS=${MAX_THREADS:-4096}
MAX_OPEN_FILES=${MAX_OPEN_FILES:-4096}
KILL_GRACE=${KILL_GRACE:-30s}
SAMPLE_INTERVAL=${SAMPLE_INTERVAL:-5s}
PROC_ROOT=${PROC_ROOT:-/proc}
ALLOW_WRITABLE_SNAPSHOT=${ALLOW_WRITABLE_SNAPSHOT:-0}
UNIT_NAME=${UNIT_NAME:-winn-phase1-soak}
MODE=${MODE:-preflight}
CONFIRM_SEVEN_DAY_RUN=${CONFIRM_SEVEN_DAY_RUN:-0}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# MODE is validated FIRST, before any path is examined.
#
# A misspelled mode reported as "SNAPSHOT_ROOT is unset" sends an operator to
# fix the wrong thing, and on a script whose only dangerous mode is `run` the
# one message that must never be ambiguous is which mode was selected.
case "$MODE" in
	preflight | dry-run | run | print-systemd-command) ;;
	*)
		fail "MODE must be preflight, dry-run, run, or print-systemd-command"
		;;
esac

# A seven-day run is not something anyone should start by mistyping a variable.
if [ "$MODE" = run ] && [ "$CONFIRM_SEVEN_DAY_RUN" != 1 ]; then
	fail "MODE=run needs CONFIRM_SEVEN_DAY_RUN=1; this starts a $DURATION \
soak that holds the state directory for its whole duration"
fi

case "$RUN_ID" in
	"" | *[!A-Za-z0-9_.-]*) fail "RUN_ID is invalid" ;;
esac
case "$UNIT_NAME" in
	"" | *[!A-Za-z0-9_.-]*) fail "UNIT_NAME is invalid" ;;
esac
case "$ALLOW_WRITABLE_SNAPSHOT" in
	0 | 1) ;;
	*) fail "ALLOW_WRITABLE_SNAPSHOT must be 0 or 1" ;;
esac

for required in SNAPSHOT_ROOT STATE_ROOT EVIDENCE_ROOT RUNNER_PATH ENV_FILE
do
	eval "value=\${$required}"
	if [ -z "$value" ]; then
		fail "set $required"
	fi
	case "$value" in
		/*) ;;
		*) fail "$required must be an absolute path" ;;
	esac
done

if [ ! -x "$CONTROLLER_BIN" ]; then
	fail "controller is missing or not executable: $CONTROLLER_BIN"
fi
if [ ! -d "$SNAPSHOT_ROOT" ]; then
	fail "snapshot root is not a directory: $SNAPSHOT_ROOT"
fi
for input in "$RUNNER_PATH" "$VERIFIER_PATH" "$SOURCE_MANIFEST" "$ENV_FILE"; do
	if [ ! -f "$input" ]; then
		fail "required frozen input is missing: $input"
	fi
	if [ -L "$input" ]; then
		fail "required frozen input is a symbolic link: $input"
	fi
done

# CUSTODY SEPARATION. No finalizer seed and no evidence-signing key may exist
# on the producing host: the checkpoint and the anchors exist to constrain the
# party that writes the evidence, and a key that party can read constrains
# nobody. The separation itself comes from never provisioning the seed here at
# all; the scan below only catches the obvious ways that discipline gets
# broken, and a clean result is NOT proof of absence. The controller repeats
# this check over its own environment, which is a different surface again.
for custody_directory in "$STATE_ROOT" "$EVIDENCE_ROOT" "$SNAPSHOT_ROOT" \
	"$(dirname "$CONTROLLER_BIN")" "$(dirname "$VERIFIER_PATH")"; do
	[ -d "$custody_directory" ] || continue
	for custody_file in finalizer.seed finalizer.key finalizer-secret.key \
		audit-finalizer.seed signing.key slhdsa.secret \
		release-signing.key; do
		if [ -e "$custody_directory/$custody_file" ]; then
			fail "CUSTODY: $custody_directory/$custody_file exists on the \
producing host; no finalizer or signing secret may live where the evidence \
writer can read it"
		fi
	done
done

digest_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	else
		shasum -a 256 "$1" | awk '{ print $1 }'
	fi
}

runner_digest=$(digest_of "$RUNNER_PATH")
verifier_digest=$(digest_of "$VERIFIER_PATH")
manifest_digest=$(digest_of "$SOURCE_MANIFEST")

# The source digest defaults to the manifest's own digest, which is the
# relationship scripts/aicore_phase1_auto_matrix.sh already enforces: it
# requires the manifest digest and the Auto binary's embedded source digest to
# be the same value. Setting EXPECTED_SOURCE_DIGEST explicitly overrides it,
# and a mismatch with the manifest is refused rather than silently preferred.
if [ -z "$EXPECTED_SOURCE_DIGEST" ]; then
	EXPECTED_SOURCE_DIGEST=$manifest_digest
elif [ "$EXPECTED_SOURCE_DIGEST" != "$manifest_digest" ]; then
	fail "EXPECTED_SOURCE_DIGEST does not match the source manifest digest; \
the accepted runner requires these to be the same value"
fi

set -- \
	"-$MODE" \
	"-run-id=$RUN_ID" \
	"-state-root=$STATE_ROOT" \
	"-snapshot-root=$SNAPSHOT_ROOT" \
	"-evidence-root=$EVIDENCE_ROOT" \
	"-runner=$RUNNER_PATH" \
	"-runner-sha256=$runner_digest" \
	"-verifier=$VERIFIER_PATH" \
	"-verifier-sha256=$verifier_digest" \
	"-manifest=$SOURCE_MANIFEST" \
	"-manifest-sha256=$manifest_digest" \
	"-source-digest=$EXPECTED_SOURCE_DIGEST" \
	"-env-file=$ENV_FILE" \
	"-duration=$DURATION" \
	"-cadence=$CADENCE" \
	"-cycle-timeout=$CYCLE_TIMEOUT" \
	"-cold-every=$COLD_EVERY" \
	"-cold-settle=$COLD_SETTLE" \
	"-min-free-bytes=$MIN_FREE_BYTES" \
	"-max-log-bytes=$MAX_LOG_BYTES" \
	"-max-log-files=$MAX_LOG_FILES" \
	"-max-cycle-output-bytes=$MAX_CYCLE_OUTPUT_BYTES" \
	"-max-controller-output-bytes=$MAX_CONTROLLER_OUTPUT_BYTES" \
	"-max-rss-bytes=$MAX_RSS_BYTES" \
	"-max-threads=$MAX_THREADS" \
	"-max-open-files=$MAX_OPEN_FILES" \
	"-kill-grace=$KILL_GRACE" \
	"-sample-interval=$SAMPLE_INTERVAL" \
	"-proc-root=$PROC_ROOT" \
	"-unit-name=$UNIT_NAME" \
	"-controller-path=$CONTROLLER_BIN"

if [ "$ALLOW_WRITABLE_SNAPSHOT" = 1 ]; then
	set -- "$@" -allow-writable-snapshot
fi

echo "SOAK_HARNESS mode=$MODE run_id=$RUN_ID duration=$DURATION \
runner_sha256=$runner_digest promotable=false"
echo "SOAK_HARNESS this is a harness, not the production Auto soak; no result \
here is a passed gate"

# exec, so the controller's REAL exit status is this script's exit status.
#
# Not a pipeline and not a subshell whose status is discarded: a runner behind
# a pipe reports the status of the last stage, which is how a failing seven-day
# soak comes to look like a successful one.
exec "$CONTROLLER_BIN" "$@"
