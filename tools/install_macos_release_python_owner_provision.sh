#!/bin/bash
# Non-privileged preflight for the reviewed native owner-boundary bootstrap.
#
# Root must never interpret this repository-owned shell file. Installation is
# performed only by an already installed, reviewed, root-owned native bootstrap
# that opens and retains exact source descriptors before changing /Library.
# Its only accepted argv is the exact handoff printed below:
#   install ABSOLUTE_CONTROLLER CONTROLLER_SHA256 ABSOLUTE_LAUNCHER LAUNCHER_SHA256

set -euo pipefail

readonly SOURCE_NAME=macos_release_python_owner_provision.py
readonly CONTROLLER_DESTINATION=/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision
readonly LAUNCHER_DESTINATION=/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher
readonly NATIVE_BOOTSTRAP=/Library/WinsVPN/ReleasePythonAuthority/v2/owner-installer-bootstrap
readonly SHASUM=/usr/bin/shasum
readonly STAT=/usr/bin/stat
readonly ID=/usr/bin/id
readonly DIRNAME=/usr/bin/dirname
readonly FILE=/usr/bin/file

fail() {
  printf 'ReleasePython owner-boundary installer: %s\n' "$*" >&2
  exit 1
}

sha256() {
  "$SHASUM" -a 256 "$1" | while IFS=' ' read -r digest _rest; do
    printf '%s\n' "$digest"
  done
}

require_native_bootstrap_custody() {
  local path="$1" expected="$2" owner group mode kind links flags actual description
  [[ -f "$path" && ! -L "$path" ]] || return 1
  owner="$($STAT -f '%u' "$path")" || return 1
  group="$($STAT -f '%g' "$path")" || return 1
  mode="$($STAT -f '%Lp' "$path")" || return 1
  kind="$($STAT -f '%HT' "$path")" || return 1
  links="$($STAT -f '%l' "$path")" || return 1
  flags="$($STAT -f '%Sf' "$path")" || return 1
  actual="$(sha256 "$path")" || return 1
  description="$($FILE -b "$path")" || return 1
  [[ "$owner" == 0 && "$group" == 0 && "$mode" == 555 &&
     "$kind" == 'Regular File' && "$links" == 1 &&
     ",$flags," == *,schg,* && "$actual" == "$expected" &&
     "$description" == 'Mach-O 64-bit executable arm64'* ]]
}

main() {
  [[ $# -eq 4 ]] || fail "usage: $0 REVIEWED_NATIVE_BOOTSTRAP_SHA256 REVIEWED_CONTROLLER_SHA256 ABSOLUTE_LAUNCHER REVIEWED_LAUNCHER_SHA256"
  local bootstrap_expected="$1" controller_expected="$2" launcher_source="$3" launcher_expected="$4"
  local script_dir source source_before launcher_before
  [[ "$($ID -u)" != 0 ]] || fail 'root must invoke only the fixed native bootstrap, never this shell file'
  [[ "$bootstrap_expected" =~ ^[0-9a-f]{64}$ && "$bootstrap_expected" != "$(printf '0%.0s' {1..64})" ]] ||
    fail 'reviewed native bootstrap SHA-256 must be exact and nonzero'
  [[ "$controller_expected" =~ ^[0-9a-f]{64}$ && "$controller_expected" != "$(printf '0%.0s' {1..64})" ]] ||
    fail 'reviewed controller SHA-256 must be exact and nonzero'
  [[ "$launcher_expected" =~ ^[0-9a-f]{64}$ && "$launcher_expected" != "$(printf '0%.0s' {1..64})" ]] ||
    fail 'reviewed launcher SHA-256 must be exact and nonzero'
  [[ "$launcher_source" == /* && "$launcher_source" != / ]] ||
    fail 'reviewed launcher path must be an absolute file path'
  require_native_bootstrap_custody "$NATIVE_BOOTSTRAP" "$bootstrap_expected" ||
    fail 'fixed root-owned immutable native installer bootstrap is absent or invalid'
  script_dir="$(cd "$($DIRNAME "${BASH_SOURCE[0]}")" && pwd -P)" || fail 'cannot bind installer directory'
  source="$script_dir/$SOURCE_NAME"
  [[ -f "$source" && ! -L "$source" ]] || fail 'reviewed source is absent or symbolic'
  [[ -f "$launcher_source" && ! -L "$launcher_source" ]] || fail 'reviewed native launcher is absent or symbolic'
  [[ "$($STAT -f '%l' "$source")" == 1 ]] || fail 'reviewed source must be single-link'
  [[ "$($STAT -f '%l' "$launcher_source")" == 1 ]] || fail 'reviewed launcher must be single-link'
  source_before="$($STAT -f '%d:%i:%u:%g:%p:%l:%z:%m:%c' "$source")" || fail 'cannot bind source identity'
  launcher_before="$($STAT -f '%d:%i:%u:%g:%p:%l:%z:%m:%c' "$launcher_source")" || fail 'cannot bind launcher identity'
  [[ "$(sha256 "$source")" == "$controller_expected" ]] || fail 'reviewed controller SHA-256 mismatch'
  [[ "$(sha256 "$launcher_source")" == "$launcher_expected" ]] || fail 'reviewed launcher SHA-256 mismatch'
  [[ "$source_before" == "$($STAT -f '%d:%i:%u:%g:%p:%l:%z:%m:%c' "$source")" &&
     "$(sha256 "$source")" == "$controller_expected" &&
     "$launcher_before" == "$($STAT -f '%d:%i:%u:%g:%p:%l:%z:%m:%c' "$launcher_source")" &&
     "$(sha256 "$launcher_source")" == "$launcher_expected" ]] ||
    fail 'reviewed controller or launcher changed during non-privileged preflight'
  printf 'OWNER-BLOCKED: invoke only %s from a visible owner-controlled root shell.\n' "$NATIVE_BOOTSTRAP"
  printf 'Bootstrap inputs: install %s %s %s %s\n' \
    "$source" "$controller_expected" "$launcher_source" "$launcher_expected"
  printf 'Destinations: %s %s\n' "$CONTROLLER_DESTINATION" "$LAUNCHER_DESTINATION"
  return 1
}

main "$@"
