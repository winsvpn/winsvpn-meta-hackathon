[CmdletBinding()]
param(
    [ValidateSet('Check', 'Run', 'Codex', 'CodexResume', 'BuildIOS', 'BuildMacOS', 'Simulators', 'VerifyApple')]
    [string]$Action = 'Check',

    [string]$Command,

    [string]$Prompt,

    [string]$SessionId,

    [string]$MacHost = $(if ($env:WINS_MAC_HOST) { $env:WINS_MAC_HOST } else { 'macbook' }),

    [string]$MacHostKeyAlias = 'build-mac.local'
)

$ErrorActionPreference = 'Stop'

$RemoteProject = '/Users/winsvpn/Downloads/wins_vpn'
$RemoteCodex = '/Applications/ChatGPT.app/Contents/Resources/codex'
$RemoteFlutterLock = @'
REMOTE_FLUTTER_LOCK_DIR="${PWD}/.dart_tool/winsvpn-release-build.lock"
REMOTE_FLUTTER_LOCK_OWNER="${REMOTE_FLUTTER_LOCK_DIR}/owner.txt"
REMOTE_FLUTTER_LOCK_TOKEN=''
REMOTE_FLUTTER_LOCK_TEMP=''
REMOTE_FLUTTER_LOCK_ACQUIRED=0

release_remote_flutter_lock() {
  local recorded_token=''
  [[ "${REMOTE_FLUTTER_LOCK_ACQUIRED}" == '1' ]] || return 0
  if [[ ! -f "${REMOTE_FLUTTER_LOCK_OWNER}" ]]; then
    if [[ -n "${REMOTE_FLUTTER_LOCK_TEMP}" ]]; then
      /bin/rm -f -- "${REMOTE_FLUTTER_LOCK_TEMP}" || return 74
    fi
    /bin/rmdir -- "${REMOTE_FLUTTER_LOCK_DIR}" || return 74
    REMOTE_FLUTTER_LOCK_ACQUIRED=0
    return 0
  fi
  recorded_token="$(/usr/bin/sed -n 's/^token=//p' "${REMOTE_FLUTTER_LOCK_OWNER}")"
  if [[ -z "${recorded_token}" || "${recorded_token}" != "${REMOTE_FLUTTER_LOCK_TOKEN}" ]]; then
    printf 'REMOTE MAC ERROR: refusing to remove a release lock no longer owned by this process.\n' >&2
    return 74
  fi
  /bin/rm -f -- "${REMOTE_FLUTTER_LOCK_OWNER}" || return 74
  /bin/rmdir -- "${REMOTE_FLUTTER_LOCK_DIR}" || return 74
  REMOTE_FLUTTER_LOCK_ACQUIRED=0
}

remote_flutter_lock_on_exit() {
  local command_status=$?
  local release_status=0
  trap - EXIT
  if release_remote_flutter_lock; then
    :
  else
    release_status=$?
    if [[ "${command_status}" == '0' ]]; then
      command_status="${release_status}"
    fi
  fi
  exit "${command_status}"
}

acquire_remote_flutter_lock() {
  local action="$1"
  local started_utc=''
  case "${action}" in
    ios|macos|apple-verify) ;;
    *)
      printf 'REMOTE MAC ERROR: invalid remote Flutter lock action.\n' >&2
      return 64
      ;;
  esac
  started_utc="$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')"
  REMOTE_FLUTTER_LOCK_TOKEN="apple-remote:${action}:$$:${started_utc}:${RANDOM}"
  /bin/mkdir -p -- "${PWD}/.dart_tool"
  if ! /bin/mkdir -- "${REMOTE_FLUTTER_LOCK_DIR}" 2>/dev/null; then
    printf 'REMOTE MAC ERROR: another platform build owns %s; no Flutter command was started.\n' \
      "${REMOTE_FLUTTER_LOCK_DIR}" >&2
    return 73
  fi
  REMOTE_FLUTTER_LOCK_ACQUIRED=1
  REMOTE_FLUTTER_LOCK_TEMP="${REMOTE_FLUTTER_LOCK_DIR}/.owner-${REMOTE_FLUTTER_LOCK_TOKEN}"
  if ! (umask 077; printf 'platform=apple-remote\naction=%s\npid=%s\nstarted_utc=%s\ntoken=%s\n' \
      "${action}" "$$" "${started_utc}" "${REMOTE_FLUTTER_LOCK_TOKEN}" \
      >"${REMOTE_FLUTTER_LOCK_TEMP}") \
      || ! /bin/mv -f -- "${REMOTE_FLUTTER_LOCK_TEMP}" "${REMOTE_FLUTTER_LOCK_OWNER}"; then
    release_remote_flutter_lock || true
    printf 'REMOTE MAC ERROR: unable to write release lock owner metadata.\n' >&2
    return 74
  fi
  REMOTE_FLUTTER_LOCK_TEMP=''
}
'@
$RemoteFlutterResolver = @'
resolve_reviewed_flutter() {
  local required_version required_revision
  local managed_flutter=''
  local candidate=''
  local identity=''
  local flutter_version=''
  local flutter_revision=''
  local pin_file="${PWD}/tools/toolchain-pins.json"

  # The reviewed version and revision come from tools/toolchain-pins.json at
  # run time, never from literals. A literal that agrees today is still a
  # defect: the next pin bump silently desynchronises the remote Mac build
  # from every other build.
  if [[ ! -f "${pin_file}" ]]; then
    printf 'REMOTE MAC ERROR: %s is missing; cannot resolve the reviewed Flutter pin.\n' "${pin_file}" >&2
    return 65
  fi
  required_version="$(/usr/bin/python3 - "${pin_file}" tools.flutter.version <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
)"
  required_revision="$(/usr/bin/python3 - "${pin_file}" tools.flutter.revision <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
)"
  managed_flutter="${HOME}/Library/Application Support/WinsVPN/toolchains/flutter-${required_version}-extract/flutter/bin/flutter"

  if [[ -x "${managed_flutter}" ]]; then
    candidate="${managed_flutter}"
  else
    candidate="$(command -v flutter 2>/dev/null || true)"
  fi

  if [[ -z "${candidate}" || "${candidate}" != /* || ! -x "${candidate}" ]]; then
    printf 'REMOTE MAC ERROR: reviewed Flutter %s is unavailable. Expected %s or one absolute executable on PATH.\n' \
      "${required_version}" "${managed_flutter}" >&2
    return 65
  fi
  command -v /usr/bin/python3 >/dev/null 2>&1 || {
    printf 'REMOTE MAC ERROR: /usr/bin/python3 is required to verify Flutter identity.\n' >&2
    return 65
  }

  identity="$("${candidate}" --version --machine | /usr/bin/python3 -c '
import json
import sys

raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit("Flutter version JSON was not found")
value = json.loads(raw[start : end + 1])
print(value.get("frameworkVersion", ""), value.get("frameworkRevision", ""))
')" || {
    printf 'REMOTE MAC ERROR: unable to read Flutter identity from %s.\n' "${candidate}" >&2
    return 65
  }
  read -r flutter_version flutter_revision <<<"${identity}"
  if [[ "${flutter_version}" != "${required_version}" \
     || "${flutter_revision}" != "${required_revision}" ]]; then
    printf 'REMOTE MAC ERROR: Flutter %s (%s) is required; found %s (%s) at %s.\n' \
      "${required_version}" "${required_revision}" \
      "${flutter_version:-unknown}" "${flutter_revision:-unknown}" "${candidate}" >&2
    return 65
  fi

  REVIEWED_FLUTTER="${candidate}"
  export REVIEWED_FLUTTER
  export FLUTTER_BIN="${candidate}"
}
resolve_reviewed_flutter
'@
$MacSshTarget = $MacHost
$MacSshArgs = @()
if ($MacHost -ne 'macbook') {
    if ($MacHostKeyAlias -notmatch '^[A-Za-z0-9.-]+$') {
        throw '-MacHostKeyAlias must be a safe pinned SSH hostname.'
    }
    $MacSshTarget = "winsvpn@$MacHost"
    $MacSshArgs = @(
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "HostKeyAlias=$MacHostKeyAlias",
        '-i', (Join-Path $HOME '.ssh\id_ed25519_codex_lan')
    )
}

function Invoke-MacScript {
    param([Parameter(Mandatory)][string]$Script)

    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Script))
    & ssh @MacSshArgs $MacSshTarget "printf '%s' '$encoded' | base64 -D | zsh"
    if ($LASTEXITCODE -ne 0) {
        throw "Mac command failed with exit code $LASTEXITCODE."
    }
}

switch ($Action) {
    'Check' {
        Invoke-MacScript @"
set -e
printf 'host='; hostname
printf 'user='; whoami
printf 'macos='; sw_vers -productVersion
printf 'arch='; uname -m
xcodebuild -version
swift --version
printf 'project='; git -C '$RemoteProject' rev-parse --show-toplevel
printf 'branch='; git -C '$RemoteProject' branch --show-current
'$RemoteCodex' --version
"@
    }

    'Run' {
        if ([string]::IsNullOrWhiteSpace($Command)) {
            throw '-Command is required for the Run action.'
        }
        Invoke-MacScript "set -e`ncd '$RemoteProject'`n$Command"
    }

    'Codex' {
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw '-Prompt is required for the Codex action.'
        }
        $promptEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Prompt))
        Invoke-MacScript "set -e`nprintf '%s' '$promptEncoded' | base64 -D | '$RemoteCodex' exec --sandbox workspace-write -C '$RemoteProject' -"
    }

    'CodexResume' {
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw '-Prompt is required for the CodexResume action.'
        }
        if (-not [string]::IsNullOrWhiteSpace($SessionId) -and $SessionId -notmatch '^[0-9a-fA-F-]{36}$') {
            throw '-SessionId must be a Codex UUID. Omit it to resume the most recent Mac session.'
        }
        $promptEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Prompt))
        $resumeTarget = if ([string]::IsNullOrWhiteSpace($SessionId)) { '--last' } else { $SessionId }
        Invoke-MacScript "set -e`nprintf '%s' '$promptEncoded' | base64 -D | '$RemoteCodex' exec resume $resumeTarget -"
    }

    'BuildIOS' {
        Invoke-MacScript @"
set -e
cd '$RemoteProject'
$RemoteFlutterLock
trap remote_flutter_lock_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
acquire_remote_flutter_lock ios
$RemoteFlutterResolver
"`$REVIEWED_FLUTTER" pub get
"`$REVIEWED_FLUTTER" build ios --simulator --debug --config-only
xcodebuild -workspace ios/Runner.xcworkspace -scheme Runner -sdk iphonesimulator -configuration Debug build CODE_SIGNING_ALLOWED=NO
"@
    }

    'BuildMacOS' {
        Invoke-MacScript @"
set -e
cd '$RemoteProject'
$RemoteFlutterLock
trap remote_flutter_lock_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
acquire_remote_flutter_lock macos
$RemoteFlutterResolver
"`$REVIEWED_FLUTTER" pub get
"`$REVIEWED_FLUTTER" build macos --debug --config-only
xcodebuild -workspace macos/Runner.xcworkspace -scheme Runner -configuration Debug build CODE_SIGNING_ALLOWED=NO
"@
    }

    'Simulators' {
        Invoke-MacScript "xcrun simctl list devices available"
    }

    'VerifyApple' {
        Invoke-MacScript @"
set -e
cd '$RemoteProject'
$RemoteFlutterLock
trap remote_flutter_lock_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
acquire_remote_flutter_lock apple-verify
$RemoteFlutterResolver
bash tools/verify_apple_readiness.sh
"@
    }
}
