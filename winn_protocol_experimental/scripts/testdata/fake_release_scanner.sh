#!/bin/sh
set -eu

scanner=${0##*/}
target="${GOOS:-unset}/${GOARCH:-unset}"
printf '%s|%s|cgo=%s|args=%s\n' \
  "$scanner" "$target" "${CGO_ENABLED:-unset}" "$*" \
  >>"$WINN_FAKE_SCANNER_LOG"

if [ "${WINN_FAKE_SCANNER_FAIL:-}" = "$scanner:$target" ]; then
  exit 42
fi
