#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=scripts/postgres_container_cleanup.sh
. "$SCRIPT_DIR/postgres_container_cleanup.sh"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-postgres-cleanup-test.XXXXXX")
cleanup() {
  rm -r "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

FAKE_DOCKER="$SCRIPT_DIR/testdata/fake_docker_cleanup.sh"
SIGNAL_HARNESS="$SCRIPT_DIR/testdata/postgres_cleanup_signal_harness.sh"
TRAP_LIBRARY="$SCRIPT_DIR/postgres_cleanup_traps.sh"
POSTGRES_TEST="$SCRIPT_DIR/postgres_test.sh"
CONTAINER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# The source line must retain the literal runtime ROOT_DIR reference.
# shellcheck disable=SC2016
if ! grep -Fqx '. "$ROOT_DIR/scripts/postgres_cleanup_traps.sh"' \
  "$POSTGRES_TEST"; then
  echo "PostgreSQL test does not source the status-bearing cleanup traps" >&2
  exit 1
fi
if [ "$(grep -Fxc \
  'winn_postgres_install_cleanup_traps postgres_cleanup_resources' \
  "$POSTGRES_TEST")" -ne 1 ]; then
  echo "PostgreSQL test does not install the cleanup callback exactly once" >&2
  exit 1
fi
if grep -Eq '^trap +[^ ]+ +EXIT +HUP +INT +TERM$' "$POSTGRES_TEST"; then
  echo "PostgreSQL test still shares one status-implicit signal trap" >&2
  exit 1
fi

# The pattern deliberately matches literal shell variable references.
# shellcheck disable=SC2016
if grep -Eq '"\\$DOCKER_BIN" (exec|logs|port|stop|inspect) "\\$CONTAINER_NAME"' \
  "$POSTGRES_TEST"; then
  echo "PostgreSQL test still performs a mutable-name Docker operation" >&2
  exit 1
fi
explicit_cleanup_line=$(
  awk '/if ! winn_postgres_stop_remove_container/ { line=NR } END { print line+0 }' \
    "$POSTGRES_TEST"
)
pass_line=$(
  awk '/^echo "PASS: PostgreSQL schema/ { print NR; exit }' "$POSTGRES_TEST"
)
if [ "$explicit_cleanup_line" -eq 0 ] || [ -z "$pass_line" ] ||
  [ "$explicit_cleanup_line" -ge "$pass_line" ]; then
  echo "PostgreSQL PASS is not gated by explicit proven container cleanup" >&2
  exit 1
fi

run_case() {
  name=$1
  stop_status=$2
  ps_status=$3
  ps_output=$4
  log="$WORK_DIR/$name.log"
  : >"$log"
  WINN_FAKE_DOCKER_LOG="$log" \
    WINN_FAKE_DOCKER_STOP_STATUS="$stop_status" \
    WINN_FAKE_DOCKER_PS_STATUS="$ps_status" \
    WINN_FAKE_DOCKER_PS_OUTPUT="$ps_output" \
    WINN_POSTGRES_CLEANUP_INSPECT_ATTEMPTS=1 \
    winn_postgres_stop_remove_container "$FAKE_DOCKER" "$CONTAINER_ID"
}

run_case stop_and_remove 0 0 ""
if ! grep -qx "stop $CONTAINER_ID" "$WORK_DIR/stop_and_remove.log"; then
  echo "cleanup did not stop the exact container ID" >&2
  exit 1
fi
if ! grep -qx "ps -aq --no-trunc --filter id=$CONTAINER_ID" \
  "$WORK_DIR/stop_and_remove.log"; then
  echo "cleanup did not verify exact container removal" >&2
  exit 1
fi

run_case already_removed 1 0 ""

if run_case stop_failed_still_present 1 0 "$CONTAINER_ID" \
  2>"$WORK_DIR/stop_failed_still_present.stderr"; then
  echo "cleanup accepted a failed stop while the container still existed" >&2
  exit 1
fi
if [ ! -s "$WORK_DIR/stop_failed_still_present.stderr" ]; then
  echo "failed container stop lacked a diagnostic" >&2
  exit 1
fi

if run_case stop_succeeded_still_present 0 0 "$CONTAINER_ID" \
  2>"$WORK_DIR/stop_succeeded_still_present.stderr"; then
  echo "cleanup accepted a container that remained after stop" >&2
  exit 1
fi
if [ ! -s "$WORK_DIR/stop_succeeded_still_present.stderr" ]; then
  echo "remaining container lacked a diagnostic" >&2
  exit 1
fi

if run_case state_query_failed 0 2 "" \
  2>"$WORK_DIR/state_query_failed.stderr"; then
  echo "cleanup accepted a failed Docker state query as removal" >&2
  exit 1
fi
if [ ! -s "$WORK_DIR/state_query_failed.stderr" ]; then
  echo "failed Docker state query lacked a diagnostic" >&2
  exit 1
fi

invalid_log="$WORK_DIR/invalid.log"
: >"$invalid_log"
if WINN_FAKE_DOCKER_LOG="$invalid_log" \
  winn_postgres_stop_remove_container "$FAKE_DOCKER" "reused-name" \
  2>"$WORK_DIR/invalid.stderr"; then
  echo "cleanup accepted a mutable container name" >&2
  exit 1
fi
if [ ! -s "$WORK_DIR/invalid.stderr" ]; then
  echo "invalid container identifier lacked a diagnostic" >&2
  exit 1
fi
if [ -s "$invalid_log" ]; then
  echo "cleanup called Docker before rejecting an invalid container ID" >&2
  exit 1
fi

run_trap_case() {
  event=$1
  expected_status=$2
  cleanup_status=$3
  name=$(printf '%s-%s' "$event" "$cleanup_status" | tr '[:upper:]' '[:lower:]')
  case_root="$WORK_DIR/$name"
  mkdir "$case_root"
  set +e
  output=$(
    /bin/sh "$SIGNAL_HARNESS" \
      "$TRAP_LIBRARY" "$case_root" "$event" "$cleanup_status" 2>&1
  )
  status=$?
  set -e
  if [ "$status" -ne "$expected_status" ]; then
    echo "$event cleanup=$cleanup_status exited $status, want $expected_status" >&2
    echo "$output" >&2
    exit 1
  fi
  if [ "$(cat "$case_root/cleanup.log")" != "cleanup" ]; then
    echo "$event cleanup=$cleanup_status did not run cleanup exactly once" >&2
    exit 1
  fi
  case "$output" in
    *PASS*)
      echo "$event cleanup=$cleanup_status emitted PASS after trap dispatch" >&2
      exit 1
      ;;
  esac
  case "$output" in
    *READY*)
      ;;
    *)
      echo "$event cleanup=$cleanup_status did not reach the trap boundary" >&2
      exit 1
      ;;
  esac
}

run_trap_case HUP 129 0
run_trap_case HUP 129 1
run_trap_case INT 130 0
run_trap_case INT 130 1
run_trap_case TERM 143 0
run_trap_case TERM 143 1
run_trap_case EXIT0 0 0
run_trap_case EXIT0 1 1
run_trap_case EXIT7 7 0
run_trap_case EXIT7 7 1

echo "PASS: disposable PostgreSQL cleanup is exact-ID-bound and fail-closed"
