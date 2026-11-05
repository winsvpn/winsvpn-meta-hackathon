#!/bin/bash
# Sourceable OpenSSL release-archive custody. Callers cannot self-author a
# locally built archive plus matching pins: only the in-repo controller and
# exact pin manifest may prepare the frozen OpenSSL 4.0.2 CLI, and only after
# an externally authenticated source-to-binary receipt binds official source,
# flags, compiler/toolchain identity, build transaction, output hashes, and
# current controller bytes. Candidate self-auth remains owner-blocked. Live
# toolchain-pins.json freezes the identity-proven 4.0.2 hashes, while prepare
# remains fail-closed until the owner supplies the external build receipt.

_wins_ro_error() {
  printf 'release-openssl custody: %s\n' "$*" >&2
  return 1
}

_wins_ro_helper_dir() {
  local src="${BASH_SOURCE[0]}"
  local dir
  [[ -n "$src" ]] || return 1
  dir="$(cd "$(/usr/bin/dirname "$src")" && pwd)" || return 1
  printf '%s\n' "$dir"
}

_wins_ro_bind_exact_inputs() {
  local tool manifest tools_dir
  [[ $# -eq 2 ]] ||
    _wins_ro_error 'usage: wins_release_openssl_prepare ABSOLUTE_TOOL ABSOLUTE_MANIFEST' || return 1
  tool="$1"
  manifest="$2"
  tools_dir="$(_wins_ro_helper_dir)" ||
    _wins_ro_error 'OpenSSL custody wrapper path could not be resolved' || return 1
  [[ "$tool" == "$tools_dir/release_openssl_archive_custody.py" &&
     -f "$tool" && ! -L "$tool" ]] ||
    _wins_ro_error 'malicious or substituted OpenSSL custody controller rejected' || return 1
  [[ "$manifest" == "$tools_dir/toolchain-pins.json" &&
     -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_ro_error 'replacement OpenSSL pin manifest cannot self-authorize' || return 1
}

_wins_ro_python() {
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_ro_error 'authenticated release Python custody is required' || return 1
  wins_release_python_run "${WINS_OPENSSL_CUSTODY_TOOL:?}" "$@"
}

wins_release_openssl_cleanup() {
  if [[ -z "${WINS_RELEASE_OPENSSL_RUNTIME:-}" ]]; then
    return 0
  fi
  _wins_ro_python cleanup \
    "$WINS_RELEASE_OPENSSL_RUNTIME" "$WINS_RELEASE_OPENSSL_RUNTIME_ID" || return 1
  unset WINS_RELEASE_OPENSSL_RUNTIME WINS_RELEASE_OPENSSL_RUNTIME_ID
  unset WINS_RELEASE_OPENSSL_ROOT WINS_RELEASE_OPENSSL_TREE_SHA256
  unset WINS_RELEASE_OPENSSL WINS_RELEASE_OPENSSL_SHA256
}

wins_release_openssl_prepare() {
  _wins_ro_bind_exact_inputs "$@" || return 1
  [[ -z "${WINS_RELEASE_OPENSSL_RUNTIME:-}" ]] ||
    _wins_ro_error 'OpenSSL custody is already active' || return 1
  WINS_OPENSSL_CUSTODY_TOOL="$1"
  local result key value
  result="$(_wins_ro_python prepare "$2")" || return 1
  while IFS='|' read -r key value; do
    case "$key" in
      RUNTIME) WINS_RELEASE_OPENSSL_RUNTIME="$value" ;;
      RUNTIME_ID) WINS_RELEASE_OPENSSL_RUNTIME_ID="$value" ;;
      ROOT) WINS_RELEASE_OPENSSL_ROOT="$value" ;;
      TREE_SHA256) WINS_RELEASE_OPENSSL_TREE_SHA256="$value" ;;
      BINARY) WINS_RELEASE_OPENSSL="$value" ;;
      BINARY_SHA256) WINS_RELEASE_OPENSSL_SHA256="$value" ;;
      *) _wins_ro_error 'unexpected OpenSSL custody result field'; return 1 ;;
    esac
  done <<<"$result"
  [[ -n "${WINS_RELEASE_OPENSSL_RUNTIME:-}" && -n "${WINS_RELEASE_OPENSSL_RUNTIME_ID:-}" &&
     -n "${WINS_RELEASE_OPENSSL_ROOT:-}" && "${WINS_RELEASE_OPENSSL_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ &&
     -n "${WINS_RELEASE_OPENSSL:-}" && "${WINS_RELEASE_OPENSSL_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
    wins_release_openssl_cleanup >/dev/null 2>&1 || true
    _wins_ro_error 'incomplete OpenSSL custody result rejected'
    return 1
  }
  export WINS_RELEASE_OPENSSL_RUNTIME WINS_RELEASE_OPENSSL_RUNTIME_ID
  export WINS_RELEASE_OPENSSL_ROOT WINS_RELEASE_OPENSSL_TREE_SHA256
  export WINS_RELEASE_OPENSSL WINS_RELEASE_OPENSSL_SHA256
}

wins_release_openssl_verify() {
  [[ $# -eq 0 ]] || _wins_ro_error 'usage: wins_release_openssl_verify' || return 1
  _wins_ro_python verify \
    "$WINS_RELEASE_OPENSSL_RUNTIME" "$WINS_RELEASE_OPENSSL_RUNTIME_ID" \
    "$WINS_RELEASE_OPENSSL_ROOT" "$WINS_RELEASE_OPENSSL_TREE_SHA256" \
    "$WINS_RELEASE_OPENSSL" "$WINS_RELEASE_OPENSSL_SHA256"
}

wins_release_openssl_run() {
  wins_release_openssl_verify || return 1
  local status=0
  /usr/bin/env -i \
    HOME="${WINS_RELEASE_OPENSSL_RUNTIME}/state/home" \
    TMPDIR="${WINS_RELEASE_OPENSSL_RUNTIME}/state/tmp" \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C LC_ALL=C OPENSSL_CONF=/dev/null \
    "$WINS_RELEASE_OPENSSL" "$@" || status=$?
  wins_release_openssl_verify || return 1
  return "$status"
}
