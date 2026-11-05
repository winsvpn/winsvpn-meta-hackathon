#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: postgres_cleanup_signal_harness.sh TRAP_LIBRARY CASE_ROOT EVENT CLEANUP_STATUS" >&2
  exit 64
fi

TRAP_LIBRARY=$1
CASE_ROOT=$2
EVENT=$3
CLEANUP_STATUS=$4

# shellcheck disable=SC1090
. "$TRAP_LIBRARY"

postgres_signal_test_cleanup() {
  printf '%s\n' cleanup >>"$CASE_ROOT/cleanup.log"
  return "$CLEANUP_STATUS"
}

: >"$CASE_ROOT/cleanup.log"
winn_postgres_install_cleanup_traps postgres_signal_test_cleanup
printf '%s\n' READY
case "$EVENT" in
  HUP)
    kill -HUP "$$"
    ;;
  INT)
    kill -INT "$$"
    ;;
  TERM)
    kill -TERM "$$"
    ;;
  EXIT0)
    exit 0
    ;;
  EXIT7)
    exit 7
    ;;
  *)
    echo "unsupported test event: $EVENT" >&2
    exit 64
    ;;
esac

echo "PASS: trap event unexpectedly returned"
