#!/bin/sh

# Install status-bearing cleanup handlers for the disposable PostgreSQL gate.
# The caller supplies a no-argument cleanup function. Signal handlers carry an
# explicit nonzero disposition because $? at signal-delivery time is merely
# the status of the previously completed command and can be zero.
winn_postgres_cleanup_dispatch() {
  status=$1
  cleanup_function=$2
  trap - EXIT HUP INT TERM

  if "$cleanup_function"; then
    cleanup_status=0
  else
    cleanup_status=$?
  fi
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=1
  fi
  exit "$status"
}

winn_postgres_cleanup_on_exit() {
  status=$?
  winn_postgres_cleanup_dispatch "$status" "$WINN_POSTGRES_CLEANUP_FUNCTION"
}

winn_postgres_cleanup_on_hup() {
  winn_postgres_cleanup_dispatch 129 "$WINN_POSTGRES_CLEANUP_FUNCTION"
}

winn_postgres_cleanup_on_int() {
  winn_postgres_cleanup_dispatch 130 "$WINN_POSTGRES_CLEANUP_FUNCTION"
}

winn_postgres_cleanup_on_term() {
  winn_postgres_cleanup_dispatch 143 "$WINN_POSTGRES_CLEANUP_FUNCTION"
}

winn_postgres_install_cleanup_traps() {
  if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "PostgreSQL cleanup function is required" >&2
    return 1
  fi
  WINN_POSTGRES_CLEANUP_FUNCTION=$1
  trap winn_postgres_cleanup_on_exit EXIT
  trap winn_postgres_cleanup_on_hup HUP
  trap winn_postgres_cleanup_on_int INT
  trap winn_postgres_cleanup_on_term TERM
}
