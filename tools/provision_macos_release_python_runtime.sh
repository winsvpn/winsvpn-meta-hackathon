#!/bin/bash
# Non-mutating macOS ReleasePython owner-boundary diagnostic.
#
# Repository code never elevates privilege, installs a runtime, publishes a
# receipt, changes immutable flags, reads a password, or executes mutable
# Python or shell as root. All owner provisioning is external to the repository
# at one fixed root-owned SF_IMMUTABLE boundary.
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
hash -r 2>/dev/null || true

readonly _WINS_PR_ID=/usr/bin/id
readonly _WINS_PR_STAT=/usr/bin/stat
readonly _WINS_PR_PLUTIL=/usr/bin/plutil
readonly _WINS_PR_SHASUM=/usr/bin/shasum
readonly _WINS_PR_DIRNAME=/usr/bin/dirname
readonly _WINS_PR_UNAME=/usr/bin/uname
readonly _WINS_PR_SYSTEM_PYTHON=/usr/bin/python3
readonly _WINS_PR_RUNTIME=/Library/WinsVPN/ReleasePython/3.14.7
readonly _WINS_PR_RECEIPT=/Library/WinsVPN/ReleasePython/3.14.7.receipt.json
readonly _WINS_PR_OWNER_BOUNDARY=/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision
readonly _WINS_PR_REVIEWED_WRAPPER_SHA256=f7acf8ccf7f2228ff03f1c352777fcce68ea6f14cd179fed419f6ef3abe96003
readonly _WINS_PR_EXECUTION_BLOCKER='owner/environment blocker: this host cannot make the Python tree immutable against same-user path replacement through execution'

_wins_pr_error() {
  printf 'release-python provision: %s\n' "$*" >&2
  return 1
}

_wins_pr_note() {
  printf 'release-python provision: %s\n' "$*" >&2
}

_wins_pr_sha256() {
  "$_WINS_PR_SHASUM" -a 256 "$1" | while IFS=' ' read -r digest _rest; do
    printf '%s\n' "$digest"
  done
}

_wins_pr_owner_action() {
  printf 'owner action: use the fixed ReleasePython owner-provisioning boundary at %s from a visible macOS Terminal\n' "$_WINS_PR_OWNER_BOUNDARY"
}

_WINS_PR_SELF="${BASH_SOURCE[0]:-}"
[[ -n "$_WINS_PR_SELF" && ! -L "$_WINS_PR_SELF" ]] ||
  _wins_pr_error "provision diagnostic must be one regular file" || exit 1
_WINS_PR_DIR="$(cd "$("$_WINS_PR_DIRNAME" "$_WINS_PR_SELF")" && pwd -P)" || exit 1
_WINS_PR_SELF="$_WINS_PR_DIR/provision_macos_release_python_runtime.sh"
readonly _WINS_PR_CUSTODY="$_WINS_PR_DIR/macos_release_python_runtime.custody.json"

if [[ "$("$_WINS_PR_ID" -u)" == 0 ]]; then
  _wins_pr_error "OWNER-BLOCKED: repository provision diagnostics refuse root execution"
  _wins_pr_note "$(_wins_pr_owner_action)"
  exit 1
fi

# shellcheck source=release_python_archive_custody.sh
exec 8<"$_WINS_PR_DIR/release_python_archive_custody.sh" || exit 1
_WINS_PR_HELD_WRAPPER_SHA="$(_wins_pr_sha256 /dev/fd/8)" || exit 1
_WINS_PR_EXPECTED_WRAPPER_SHA="$("$_WINS_PR_PLUTIL" -extract wrapper_sha256 raw -o - "$_WINS_PR_CUSTODY" 2>/dev/null)" || exit 1
[[ "$_WINS_PR_HELD_WRAPPER_SHA" == "$_WINS_PR_EXPECTED_WRAPPER_SHA" &&
   "$_WINS_PR_HELD_WRAPPER_SHA" == "$_WINS_PR_REVIEWED_WRAPPER_SHA256" ]] ||
  _wins_pr_error "held ReleasePython wrapper digest mismatch" || exit 1
"$_WINS_PR_SYSTEM_PYTHON" -I -S -c 'import os; os.lseek(8, 0, os.SEEK_SET)' || exit 1
_WINS_RP_HELD_HELPER_DIR="$_WINS_PR_DIR"
source /dev/fd/8 || exit 1
unset _WINS_RP_HELD_HELPER_DIR
exec 8<&-

_wins_pr_metadata_value() {
  "$_WINS_PR_PLUTIL" -extract "$1" raw -o - "$_WINS_PR_CUSTODY" 2>/dev/null
}

_wins_pr_verify_custody_metadata() {
  local contract schema key path expected actual
  [[ -f "$_WINS_PR_CUSTODY" && ! -L "$_WINS_PR_CUSTODY" ]] ||
    _wins_pr_error "Python runtime custody metadata is missing or symbolic" || return 1
  contract="$(_wins_pr_metadata_value contract)" ||
    _wins_pr_error "Python runtime custody metadata is unreadable" || return 1
  schema="$(_wins_pr_metadata_value schema_version)" || return 1
  [[ "$contract" == winsvpn-macos-release-python-runtime-v2 && "$schema" == 3 ]] ||
    _wins_pr_error "Python runtime custody metadata contract mismatch" || return 1
  for key in \
    wrapper provisioner custody_controller receipt_test provision_test \
    archive_test fin_g00_test fin_release_gate android_custody \
    openssl_custody node_custody browser_custody go_custody \
    gcp_proof_collector gcp_proof_live_probe pin_manifest; do
    path="$(_wins_pr_metadata_value "$key")" ||
      _wins_pr_error "missing custody path pin: $key" || return 1
    [[ "$path" == tools/* && "$path" != *../* && "$path" != */.. ]] ||
      _wins_pr_error "unsafe custody path pin: $key" || return 1
    path="$_WINS_PR_DIR/${path#tools/}"
    [[ -f "$path" && ! -L "$path" ]] ||
      _wins_pr_error "custody closure file is missing or symbolic: $key" || return 1
    expected="$(_wins_pr_metadata_value "${key}_sha256")" ||
      _wins_pr_error "missing custody digest pin: ${key}_sha256" || return 1
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] ||
      _wins_pr_error "invalid custody digest pin: ${key}_sha256" || return 1
    actual="$(_wins_pr_sha256 "$path")" || return 1
    [[ "$actual" == "$expected" ]] ||
      _wins_pr_error "stale Python runtime custody digest: ${path#"$_WINS_PR_DIR/"}" || return 1
  done
  [[ "$(_wins_pr_metadata_value runtime_path)" == "$_WINS_PR_RUNTIME" &&
     "$(_wins_pr_metadata_value receipt_path)" == "$_WINS_PR_RECEIPT" &&
     "$(_wins_pr_metadata_value owner_provision_boundary)" == "$_WINS_PR_OWNER_BOUNDARY" ]] ||
    _wins_pr_error "Python runtime custody fixed-path mismatch" || return 1
}

_wins_pr_boundary_state() {
  local owner group mode flags kind links
  [[ -e "$_WINS_PR_OWNER_BOUNDARY" && ! -L "$_WINS_PR_OWNER_BOUNDARY" ]] || return 1
  owner="$($_WINS_PR_STAT -f '%u' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  group="$($_WINS_PR_STAT -f '%g' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  mode="$($_WINS_PR_STAT -f '%Lp' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  flags="$($_WINS_PR_STAT -f '%Sf' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  kind="$($_WINS_PR_STAT -f '%HT' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  links="$($_WINS_PR_STAT -f '%l' "$_WINS_PR_OWNER_BOUNDARY")" || return 1
  [[ "$owner" == 0 && "$group" == 0 && "$mode" == 555 && "$kind" == "Regular File" &&
     "$links" == 1 && ",$flags," == *,schg,* ]]
}

_wins_pr_repo_from_manifest() {
  local manifest="$1" dir
  dir="$("$_WINS_PR_DIRNAME" "$manifest")" || return 1
  (cd "$dir/.." && pwd -P)
}

wins_release_python_provision_owner_runtime() {
  local manifest="${1:-}" repo state rc=0
  [[ $# -eq 1 ]] ||
    _wins_pr_error "usage: provision_macos_release_python_runtime.sh ABSOLUTE_PIN_MANIFEST" || return 1
  [[ "$("$_WINS_PR_UNAME" -s)" == Darwin && "$("$_WINS_PR_UNAME" -m)" == arm64 ]] ||
    _wins_pr_error "macOS arm64 is required" || return 1
  [[ "$manifest" == /* && -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_pr_error "regular absolute pin manifest required" || return 1
  [[ -z "${WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT:-}" ]] ||
    _wins_pr_error "owner-blocked: Python runtime receipt override is refused" || return 1
  _wins_pr_verify_custody_metadata || return 1
  repo="$(_wins_pr_repo_from_manifest "$manifest")" || return 1
  state="$(_wins_rp_receipt_py inspect-existing "$repo" "$manifest")" || rc=$?
  if [[ "$rc" == 0 && "$state" == MATCH ]]; then
    _wins_pr_note "installed runtime diagnosis: authenticated MATCH"
    _wins_pr_note "diagnostic-only: repository provision code cannot authorize or publish owner state"
  fi
  if [[ "$rc" == 0 && "$state" == MISMATCH:* ]]; then
    _wins_pr_note "installed runtime diagnosis: ${state#MISMATCH:}"
  elif [[ "$rc" != 0 ]]; then
    _wins_pr_note "installed runtime diagnosis failed closed (inspect-existing exit ${rc})"
  else
    _wins_pr_note "installed runtime diagnosis: ${state}"
  fi
  if ! _wins_pr_boundary_state; then
    _wins_pr_note "fixed owner-provisioning boundary is absent or fails root/SF_IMMUTABLE custody"
  fi
  _wins_pr_note "${_WINS_PR_EXECUTION_BLOCKER}; owner-provisioned root-owned Python 3.14.7 runtime is unavailable"
  _wins_pr_note "$(_wins_pr_owner_action)"
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  wins_release_python_provision_owner_runtime "$@"
fi
