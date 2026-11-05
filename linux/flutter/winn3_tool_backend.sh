#!/usr/bin/env bash
# Append the reviewed Winn3 ring onto DART_DEFINES, then run Flutter's
# tool_backend.sh. Invoked from linux/flutter/CMakeLists.txt via cmake -E env.
set -euo pipefail

if [[ -z "${FLUTTER_ROOT:-}" ]]; then
  printf 'winn3_tool_backend: FLUTTER_ROOT is unset\n' >&2
  exit 1
fi
if [[ -z "${WINN3_RING_DART_DEFINES:-}" ]]; then
  printf 'winn3_tool_backend: WINN3_RING_DART_DEFINES is empty\n' >&2
  exit 1
fi

if [[ -n "${DART_DEFINES:-}" ]]; then
  export DART_DEFINES="${DART_DEFINES},${WINN3_RING_DART_DEFINES}"
else
  export DART_DEFINES="${WINN3_RING_DART_DEFINES}"
fi

exec "${FLUTTER_ROOT}/packages/flutter_tools/bin/tool_backend.sh" "$@"
