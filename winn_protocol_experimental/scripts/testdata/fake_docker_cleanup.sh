#!/bin/sh
set -eu

printf '%s\n' "$*" >>"$WINN_FAKE_DOCKER_LOG"

case "$1" in
  stop)
    exit "${WINN_FAKE_DOCKER_STOP_STATUS:-0}"
    ;;
  ps)
    if [ -n "${WINN_FAKE_DOCKER_PS_OUTPUT:-}" ]; then
      printf '%s\n' "$WINN_FAKE_DOCKER_PS_OUTPUT"
    fi
    exit "${WINN_FAKE_DOCKER_PS_STATUS:-0}"
    ;;
  *)
    echo "unexpected fake Docker command: $*" >&2
    exit 64
    ;;
esac
