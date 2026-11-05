#!/bin/bash
# Sourceable wrapper for authenticated Node.js release archive custody.

_WINS_RN_ACTIVE_TOOL=""
_WINS_RN_ACTIVE_TOOL_SOURCE=""
_WINS_RN_ACTIVE_RUNTIME=""
_WINS_RN_ACTIVE_RUNTIME_ID=""
_WINS_RN_ACTIVE_ROOT=""
_WINS_RN_ACTIVE_TREE_SHA256=""
_WINS_RN_ACTIVE_BINARY=""
_WINS_RN_ACTIVE_BINARY_SHA256=""

_wins_rn_error() {
  printf 'release-node custody: %s\n' "$*" >&2
  return 1
}

_wins_rn_python() {
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rn_error 'authenticated release Python custody is required' || return 1
  [[ -n "${_WINS_RN_ACTIVE_TOOL_SOURCE:-}" ]] ||
    _wins_rn_error 'Node custody controller snapshot is not bound' || return 1
  wins_release_python_run - "$@" <<<"${_WINS_RN_ACTIVE_TOOL_SOURCE}"
}

wins_release_node_cleanup() {
  if [[ -z "${_WINS_RN_ACTIVE_RUNTIME:-}" ]]; then
    return 0
  fi
  _wins_rn_python cleanup \
    "$_WINS_RN_ACTIVE_RUNTIME" "$_WINS_RN_ACTIVE_RUNTIME_ID" || return 1
  _WINS_RN_ACTIVE_TOOL=""
  _WINS_RN_ACTIVE_TOOL_SOURCE=""
  _WINS_RN_ACTIVE_RUNTIME=""
  _WINS_RN_ACTIVE_RUNTIME_ID=""
  _WINS_RN_ACTIVE_ROOT=""
  _WINS_RN_ACTIVE_TREE_SHA256=""
  _WINS_RN_ACTIVE_BINARY=""
  _WINS_RN_ACTIVE_BINARY_SHA256=""
  unset WINS_RELEASE_NODE_RUNTIME WINS_RELEASE_NODE_RUNTIME_ID
  unset WINS_RELEASE_NODE_ROOT WINS_RELEASE_NODE_TREE_SHA256
  unset WINS_RELEASE_NODE WINS_RELEASE_NODE_SHA256 WINS_NODE_CUSTODY_TOOL
}

wins_release_node_prepare() {
  [[ $# -eq 2 ]] ||
    _wins_rn_error 'usage: wins_release_node_prepare ABSOLUTE_TOOL ABSOLUTE_MANIFEST' || return 1
  [[ -z "${_WINS_RN_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rn_error 'Node custody is already active' || return 1
  WINS_NODE_CUSTODY_TOOL="$1"
  [[ "$WINS_NODE_CUSTODY_TOOL" == /* && -f "$WINS_NODE_CUSTODY_TOOL" &&
    ! -L "$WINS_NODE_CUSTODY_TOOL" ]] ||
    _wins_rn_error 'Node custody tool must be one absolute regular file' || return 1
  local tool_source
  tool_source="$(wins_release_python_run -c '
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit("unsafe Node custody controller")
    data = bytearray()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        data.extend(block)
    after = os.fstat(fd)
finally:
    os.close(fd)
latest = path.lstat()
identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
if identity(before) != identity(after) or identity(after) != identity(latest):
    raise SystemExit("Node custody controller changed while snapshotted")
if b"\0" in data or not data:
    raise SystemExit("invalid Node custody controller source")
sys.stdout.buffer.write(data)
' "$WINS_NODE_CUSTODY_TOOL")" || return 1
  [[ -n "$tool_source" ]] ||
    _wins_rn_error 'Node custody controller snapshot is empty' || return 1
  _WINS_RN_ACTIVE_TOOL="$WINS_NODE_CUSTODY_TOOL"
  _WINS_RN_ACTIVE_TOOL_SOURCE="$tool_source"
  local result key value runtime="" runtime_id="" root="" tree_sha="" binary="" binary_sha=""
  result="$(_wins_rn_python prepare "$2")" || {
    _WINS_RN_ACTIVE_TOOL=""
    _WINS_RN_ACTIVE_TOOL_SOURCE=""
    return 1
  }
  while IFS='|' read -r key value; do
    case "$key" in
      RUNTIME) runtime="$value" ;;
      RUNTIME_ID) runtime_id="$value" ;;
      ROOT) root="$value" ;;
      TREE_SHA256) tree_sha="$value" ;;
      BINARY) binary="$value" ;;
      BINARY_SHA256) binary_sha="$value" ;;
      *)
        if [[ -n "$runtime" && -n "$runtime_id" ]]; then
          _wins_rn_python cleanup "$runtime" "$runtime_id" >/dev/null 2>&1 || true
        fi
        _WINS_RN_ACTIVE_TOOL=""
        _WINS_RN_ACTIVE_TOOL_SOURCE=""
        _wins_rn_error 'unexpected Node custody result field'
        return 1
        ;;
    esac
  done <<<"$result"
  [[ -n "$runtime" && -n "$runtime_id" && -n "$root" && "$tree_sha" =~ ^[0-9a-f]{64}$ &&
     -n "$binary" && "$binary_sha" =~ ^[0-9a-f]{64}$ ]] || {
    if [[ -n "$runtime" && -n "$runtime_id" ]]; then
      _wins_rn_python cleanup "$runtime" "$runtime_id" >/dev/null 2>&1 || true
    fi
    _WINS_RN_ACTIVE_TOOL=""
    _WINS_RN_ACTIVE_TOOL_SOURCE=""
    _wins_rn_error 'incomplete Node custody result rejected'
    return 1
  }
  _WINS_RN_ACTIVE_RUNTIME="$runtime"
  _WINS_RN_ACTIVE_RUNTIME_ID="$runtime_id"
  _WINS_RN_ACTIVE_ROOT="$root"
  _WINS_RN_ACTIVE_TREE_SHA256="$tree_sha"
  _WINS_RN_ACTIVE_BINARY="$binary"
  _WINS_RN_ACTIVE_BINARY_SHA256="$binary_sha"
  WINS_RELEASE_NODE_RUNTIME="$runtime"
  WINS_RELEASE_NODE_RUNTIME_ID="$runtime_id"
  WINS_RELEASE_NODE_ROOT="$root"
  WINS_RELEASE_NODE_TREE_SHA256="$tree_sha"
  WINS_RELEASE_NODE="$binary"
  WINS_RELEASE_NODE_SHA256="$binary_sha"
  export WINS_RELEASE_NODE_RUNTIME WINS_RELEASE_NODE_RUNTIME_ID
  export WINS_RELEASE_NODE_ROOT WINS_RELEASE_NODE_TREE_SHA256
  export WINS_RELEASE_NODE WINS_RELEASE_NODE_SHA256
}

wins_release_node_verify() {
  [[ $# -eq 0 ]] || _wins_rn_error 'usage: wins_release_node_verify' || return 1
  _wins_rn_python verify \
    "$_WINS_RN_ACTIVE_RUNTIME" "$_WINS_RN_ACTIVE_RUNTIME_ID" \
    "$_WINS_RN_ACTIVE_ROOT" "$_WINS_RN_ACTIVE_TREE_SHA256" \
    "$_WINS_RN_ACTIVE_BINARY" "$_WINS_RN_ACTIVE_BINARY_SHA256"
}

wins_release_node_run() {
  [[ -n "${_WINS_RN_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rn_error 'Node custody is not prepared' || return 1
  _wins_rn_python run \
    "$_WINS_RN_ACTIVE_RUNTIME" "$_WINS_RN_ACTIVE_RUNTIME_ID" \
    "$_WINS_RN_ACTIVE_ROOT" "$_WINS_RN_ACTIVE_TREE_SHA256" \
    "$_WINS_RN_ACTIVE_BINARY" "$_WINS_RN_ACTIVE_BINARY_SHA256" -- "$@"
}
