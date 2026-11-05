#!/usr/bin/env bash
# Install the Win's VPN native-messaging host for a browser.
#
#   ./install_native_host.sh [--system] [--host-path PATH] \
#                            <chrome|edge|firefox> <extension-id> [host-path]
#
# TWO THINGS ARE INSTALLED, AND UNTIL 2026-08-07 THIS SCRIPT ONLY INSTALLED ONE.
#
#   1. The MANIFEST, in a per-browser directory (or, on Windows, a registry key).
#   2. The HOST BINARY itself, which the manifest names by absolute path.
#
# It used to write the manifest and leave the binary wherever it already was --
# which, for anyone running this from a checkout, is inside the repository. On
# macOS that is very often `~/Documents`, and that is not a cosmetic detail:
#
# ---------------------------------------------------------------------------
# WHY WHERE THE BINARY SITS DECIDES WHETHER ANY OF THIS WORKS
# ---------------------------------------------------------------------------
#
# macOS TCC gates `~/Documents`, `~/Desktop` and `~/Downloads` per application.
# A browser without that permission cannot read those folders -- and a
# native-messaging host is a file the BROWSER opens and executes, so the
# browser's permission is the one that decides, not the user's.
#
# What that failure looks like was measured on 2026-08-07 on this project's own
# machine, with the real compiled host, on Chrome 151, Edge 151 and Firefox 153
# (`extension/tools/probe_host_location.py`, and the run is in
# `docs/handoff/BROWSER_EXTENSION_HOST_LOCATION_AND_SILENT_LAUNCH_20260807.md`):
#
#   * the browser spawns the process successfully -- it is in `ps`;
#   * the process then blocks FOREVER inside dyld, in `open(2)` on its own
#     executable, because the folder is not readable to it;
#   * nothing is ever written to the pipe, so the browser never sees an error,
#     never fires `onDisconnect`, and reports NOTHING;
#   * 9 of 9 browser/location pairs failed this way from the three protected
#     folders, and 9 of 9 worked from the three unprotected ones.
#
# It is the worst shape a failure can take: no error, no log line, no exit code,
# and a browser extension that can only observe it as a silence. So this script
# now COPIES the binary somewhere every browser can read, REFUSES to point a
# manifest into a protected folder, and CHECKS the installed copy answers.
#
# The browsers also differ in two ways that both have to be right:
#
#   1. WHERE the manifest goes (a different directory per browser per OS, and on
#      Windows a registry key rather than a directory at all).
#   2. HOW the calling extension is identified:
#        Chrome / Edge -> "allowed_origins": ["chrome-extension://<id>/"]
#                         32 lowercase letters; the TRAILING SLASH is required.
#        Firefox       -> "allowed_extensions": ["<addon-id>"]
#                         an email-shaped id from browser_specific_settings.

set -euo pipefail

HOST_NAME="org.winsvpn.bridge"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SYSTEM=0
UNINSTALL=0
REMOVE_HOST=0
BROWSER=""
EXTENSION_ID=""
HOST_PATH=""
DEST_DIR=""
MANIFEST_DIR=""
REQUIRE_INSTALLED_PATH=""
LAYOUT="$SCRIPT_DIR/native_host_layout.py"
RENDERER="$SCRIPT_DIR/render_host_manifest.py"
JSONC_PY="$PACKAGE_ROOT/extension/tools/jsonc.py"
FIREFOX_FRAGMENT="$PACKAGE_ROOT/extension/manifest/firefox.jsonc"
STORE_IDS="$SCRIPT_DIR/manifests/store_ids.json"

usage() {
  cat >&2 <<'USAGE'
usage: install_native_host.sh [--system] [--host-path PATH] [--dest-dir PATH]
                              [--manifest-dir PATH] [--require-installed-path PATH]
                              [--uninstall] [--remove-host]
                              <chrome|edge|firefox> [extension-id] [host-path]

  --system       install for every user on this machine. Needs root, and says
                 so rather than failing halfway through.
  --host-path    the compiled host to install. Default: ./host/wins_bridge_host
  --dest-dir     where to install the binary. Defaults per OS; a packager
                 building an app bundle wants Contents/Resources. A folder the
                 browser cannot read is REFUSED.
  --manifest-dir where to write the native-messaging JSON. Defaults to the
                 per-browser directory the OS actually consults. Tests pass a
                 temporary directory so a real browser profile is not touched.
  --require-installed-path
                 refuse unless the installed host path is exactly this path.
                 Linux package delivery uses this so live manifests cannot
                 name a different binary than the packaged registration.
  --uninstall    remove the per-browser manifest (and, with --remove-host, the
                 copied binary). Idempotent if the manifest is already gone.
  --remove-host  with --uninstall, also delete the installed host binary.

  chrome/edge extension-id: 32 lowercase letters. Omit to use the id
                 recorded in manifests/store_ids.json; never invented.
  firefox extension-id:     companion@winsvpn.org (pinned; may be omitted)
USAGE
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --system) SYSTEM=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --remove-host) REMOVE_HOST=1; shift ;;
    --host-path) HOST_PATH="${2:-}"; shift 2 ;;
    --dest-dir) DEST_DIR="${2:-}"; shift 2 ;;
    --manifest-dir) MANIFEST_DIR="${2:-}"; shift 2 ;;
    --require-installed-path) REQUIRE_INSTALLED_PATH="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    -*) echo "error: unknown option $1" >&2; usage ;;
    *)
      if [ -z "$BROWSER" ]; then BROWSER="$1"
      elif [ -z "$EXTENSION_ID" ]; then EXTENSION_ID="$1"
      elif [ -z "$HOST_PATH" ]; then HOST_PATH="$1"
      else echo "error: too many arguments" >&2; usage
      fi
      shift ;;
  esac
done

[ -n "$BROWSER" ] || usage
case "$BROWSER" in
  chrome|edge|firefox) ;;
  *) usage ;;
esac

require_store_identity_inputs() {
  if [ ! -f "$JSONC_PY" ]; then
    echo "error: refusing native-host registration without extension/tools/jsonc.py" >&2
    exit 1
  fi
  case "$BROWSER" in
    firefox)
      if [ ! -f "$FIREFOX_FRAGMENT" ]; then
        echo "error: refusing Firefox registration without extension/manifest/firefox.jsonc" >&2
        exit 1
      fi
      ;;
  esac
}

require_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to render or remove a native-host manifest" >&2
    exit 1
  fi
  if [ ! -f "$LAYOUT" ] || [ ! -f "$RENDERER" ]; then
    echo "error: native-host renderer/layout is missing beside this script" >&2
    exit 1
  fi
}

layout_manifest_dir() {
  require_python3
  local args=(unix-dest --browser "$BROWSER" --uname "$UNAME" --home "$HOME")
  [ "$SYSTEM" = "1" ] && args+=(--system)
  [ -n "$MANIFEST_DIR" ] && args+=(--manifest-dir "$MANIFEST_DIR")
  python3 "$LAYOUT" "${args[@]}"
}

UNAME="$(uname -s)"

if [ "$UNINSTALL" = "1" ]; then
  DEST="$(layout_manifest_dir)"
  TARGET="$DEST/${HOST_NAME}.json"
  python3 "$LAYOUT" uninstall-manifest --output "$TARGET"
  if [ "$REMOVE_HOST" = "1" ]; then
    if [ -z "$DEST_DIR" ]; then
      DEST_DIR="$(python3 "$LAYOUT" unix-host-dest --uname "$UNAME" $([ "$SYSTEM" = "1" ] && printf '%s' '--system'))"
    fi
    HOST_FILE="$DEST_DIR/wins_bridge_host"
    python3 "$LAYOUT" uninstall-leaf --output "$HOST_FILE"
    echo "removed host: $HOST_FILE"
  fi
  echo "uninstalled: $TARGET"
  exit 0
fi

require_store_identity_inputs

if [ -z "$EXTENSION_ID" ]; then
  require_python3
  status=0
  EXTENSION_ID="$(python3 "$LAYOUT" recorded-id --browser "$BROWSER")" || status=$?
  if [ "$status" -ne 0 ]; then
    if [ "$status" -eq 78 ]; then
      echo "error: $BROWSER store-listing id is missing from" >&2
      echo "       tools/native_messaging/manifests/store_ids.json. Record it there" >&2
      echo "       or pass the 32-letter store id. Refusing to invent one." >&2
      exit 78
    fi
    echo "error: could not resolve the $BROWSER extension id" >&2
    exit 1
  fi
  EXTENSION_ID="$(printf '%s' "$EXTENSION_ID" | tr -d '\r\n')"
fi
[ -n "$EXTENSION_ID" ] || usage

# ---------------------------------------------------------------------------
# Refuse a placeholder extension id before anything is copied or written
# ---------------------------------------------------------------------------
#
# The manifest templates under manifests/ ship with PLACEHOLDER_*_EXTENSION_ID
# in allowed_origins. A real install substitutes the STORE-LISTING id here, and
# this is the one place that substitution happens, so it is the one place that
# can prove the id that reaches the browser is not still a placeholder.
#
#   chrome/edge: the store-listing id is the 32 lowercase letters of the
#                [a-p] alphabet shown on chrome://extensions for the packaged
#                listing; it is stable per listing and is what the store shows.
#   firefox:     companion@winsvpn.org, the add-on id from
#                extension/manifest/firefox.jsonc's browser_specific_settings.
#                That id is the add-on's identity on addons.mozilla.org, so the
#                store-listing value is known and is pinned here.
#
# check_host_manifests.py enforces the same values on the templates at build
# time, from the same canonical source (the Firefox manifest fragment, plus
# WINSVPN_CHROME_STORE_ID / WINSVPN_EDGE_STORE_ID once the stores issue them).
case "$EXTENSION_ID" in
  *PLACEHOLDER*|*placeholder*)
    echo "error: refusing to install a manifest naming a PLACEHOLDER extension id" >&2
    echo "       (got '$EXTENSION_ID'). Substitute the store-listing extension id:" >&2
    echo "       for Chrome/Edge the 32-letter id on chrome://extensions of the" >&2
    echo "       packaged listing; for Firefox companion@winsvpn.org." >&2
    exit 1
    ;;
esac
case "$BROWSER" in
  chrome|edge)
    case "$EXTENSION_ID" in
      [a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p]) ;;
      *)
        echo "error: a Chrome/Edge extension id is 32 lowercase [a-p] letters;" >&2
        echo "       got '$EXTENSION_ID'. That id is the store-listing id shown" >&2
        echo "       on chrome://extensions for the packaged listing." >&2
        exit 1
        ;;
    esac
    ;;
  firefox)
    # The store-listing id IS known for Firefox: the gecko id the add-on ships
    # with, which addons.mozilla.org keys the listing on. Any other value names
    # a different add-on, and the host would answer an add-on that is not ours.
    if [ "$EXTENSION_ID" != "companion@winsvpn.org" ]; then
      echo "error: the Firefox store-listing add-on id is companion@winsvpn.org;" >&2
      echo "       got '$EXTENSION_ID'. Refusing to allow-list anything else." >&2
      exit 1
    fi
    ;;
esac

if [ -z "$HOST_PATH" ]; then
  HOST_PATH="$SCRIPT_DIR/host/wins_bridge_host"
fi

if [ ! -x "$HOST_PATH" ]; then
  # The default host lives in this repository (it is NOT tracked: the compiled
  # binary is gitignored). When it is absent, build it from source here rather
  # than telling the operator to. The recipe is pinned to this exact package:
  # `dart pub get` resolves only the two pure-Dart crypto packages the shared
  # winn_protocol_dispatch.dart needs (see host/pubspec.yaml), and
  # `dart compile exe` emits the single self-contained binary the manifest
  # names. An explicitly supplied --host-path that is missing is a caller
  # error, not a build request, and keeps the original refusal below.
  if [ "$HOST_PATH" = "$SCRIPT_DIR/host/wins_bridge_host" ]; then
    if ! command -v dart >/dev/null 2>&1; then
      echo "error: host executable not found at $HOST_PATH and dart is not" >&2
      echo "       on PATH to build it. Install the Dart SDK or run:" >&2
      echo "  cd $SCRIPT_DIR/host && dart pub get && \\" >&2
      echo "    dart compile exe bin/wins_bridge_host.dart -o wins_bridge_host" >&2
      exit 1
    fi
    echo "host binary not found; building it from source:" >&2
    echo "  cd $SCRIPT_DIR/host && dart pub get && \\" >&2
    echo "    dart compile exe bin/wins_bridge_host.dart -o wins_bridge_host" >&2
    if ! (cd "$SCRIPT_DIR/host" && dart pub get && \
          dart compile exe bin/wins_bridge_host.dart -o wins_bridge_host); then
      echo "error: building the host from source failed; no manifest was written" >&2
      exit 1
    fi
    if [ ! -x "$HOST_PATH" ]; then
      echo "error: the host build reported success but produced no executable at $HOST_PATH" >&2
      exit 1
    fi
  else
    echo "error: host executable not found or not executable: $HOST_PATH" >&2
    echo "build it with:" >&2
    echo "  cd $SCRIPT_DIR/host && dart pub get && \\" >&2
    echo "    dart compile exe bin/wins_bridge_host.dart -o wins_bridge_host" >&2
    echo "then re-run with --host-path pointing at the compiled host." >&2
    exit 1
  fi
fi

# The browser requires an absolute path in the manifest; a relative one is
# accepted by the JSON parser and then fails to launch.
HOST_PATH="$(cd "$(dirname "$HOST_PATH")" && pwd)/$(basename "$HOST_PATH")"

# ---------------------------------------------------------------------------
# The folders a browser cannot read, and the test for being inside one
# ---------------------------------------------------------------------------
#
# This is deliberately a LIST OF PREFIXES rather than a call to some API that
# reports TCC state. There is no such API for another process's permission, the
# answer differs per browser and per machine, and a wrong "yes" here would put
# the binary somewhere that produces the silent failure above. A prefix test
# over the folders macOS actually gates is checkable by anyone reading it.
#
# iCloud Drive is on the list for the same reason as the other three: it is
# gated, and `~/Documents` is often redirected into it.
protected_prefixes() {
  case "$UNAME" in
    Darwin)
      printf '%s\n' \
        "$HOME/Documents" \
        "$HOME/Desktop" \
        "$HOME/Downloads" \
        "$HOME/Library/Mobile Documents" \
        "$HOME/Movies" \
        "$HOME/Music" \
        "$HOME/Pictures" \
        "/Volumes"
      ;;
    *) : ;;   # Linux has no equivalent gate; the list is empty on purpose.
  esac
}

is_protected() {
  local candidate="$1" prefix
  while IFS= read -r prefix; do
    [ -n "$prefix" ] || continue
    case "$candidate" in
      "$prefix"|"$prefix"/*) return 0 ;;
    esac
  done < <(protected_prefixes)
  return 1
}

# ---------------------------------------------------------------------------
# Where the binary is installed to
# ---------------------------------------------------------------------------
#
# Not a scratch directory and not the checkout: a place that survives a reboot,
# is readable by every browser, and belongs to this application.

case "$UNAME" in
  Darwin)
    if [ "$SYSTEM" = "1" ]; then
      HOST_INSTALL_DIR="/Library/Application Support/Win's VPN/NativeMessagingHost"
    else
      HOST_INSTALL_DIR="$HOME/Library/Application Support/Win's VPN/NativeMessagingHost"
    fi
    ;;
  Linux)
    if [ "$SYSTEM" = "1" ]; then
      HOST_INSTALL_DIR="/usr/lib/wins-vpn"
    else
      HOST_INSTALL_DIR="$HOME/.local/lib/wins-vpn"
    fi
    ;;
  *)
    echo "error: unsupported OS $UNAME (on Windows use the registry, see below)" >&2
    exit 1
    ;;
esac

if [ -n "$DEST_DIR" ]; then
  HOST_INSTALL_DIR="$DEST_DIR"
fi

# NORMALISE BEFORE TESTING, because the test is a prefix test and a prefix test
# on a path that is not absolute is a test that passes everything. `--dest-dir
# Documents/host` run from $HOME, or a literal unexpanded `~/Documents`, would
# both have walked straight past the refusal below.
case "$HOST_INSTALL_DIR" in
  "~") HOST_INSTALL_DIR="$HOME" ;;
  "~/"*) HOST_INSTALL_DIR="$HOME/${HOST_INSTALL_DIR#\~/}" ;;
  /*) : ;;
  *) HOST_INSTALL_DIR="$PWD/$HOST_INSTALL_DIR" ;;
esac

# THE REFUSAL, AND IT IS CHECKED BEFORE ANYTHING IS WRITTEN.
#
# Reachable three ways, all real: `--dest-dir` pointed somewhere gated, a home
# directory that lives on an external volume (`/Volumes/...` is gated too), and
# a future edit to the defaults above. Checked here rather than after the copy
# so that a refusal leaves nothing behind.
if is_protected "$HOST_INSTALL_DIR"; then
  echo "error: refusing to install the host into $HOST_INSTALL_DIR" >&2
  echo "       That folder is TCC-protected on macOS, and a native-messaging" >&2
  echo "       host is a file the BROWSER opens. Measured on 2026-08-07 on" >&2
  echo "       Chrome 151, Edge 151 and Firefox 153 with the real host: the" >&2
  echo "       browser spawns the process, the process blocks forever in" >&2
  echo "       open(2) on its own executable, nothing is ever written to the" >&2
  echo "       pipe, and NO BROWSER REPORTS ANYTHING AT ALL. 9 of 9" >&2
  echo "       browser/folder pairs failed this way; 9 of 9 worked outside." >&2
  echo "       Install it outside Documents, Desktop, Downloads, iCloud Drive," >&2
  echo "       Movies, Music, Pictures and removable volumes." >&2
  echo "       Re-run with --dest-dir pointing somewhere else." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Where the manifest goes
# ---------------------------------------------------------------------------
#
# Destinations live in native_host_layout.py so the installer, the Windows
# registry plan, and the tests cannot drift. --manifest-dir overrides for
# packagers and for tests that must not touch a real browser profile.

DEST="$(layout_manifest_dir)"
if [ "$BROWSER" = "firefox" ]; then
  KEY="allowed_extensions"
  VALUE="${EXTENSION_ID}"
else
  KEY="allowed_origins"
  VALUE="chrome-extension://${EXTENSION_ID}/"
fi

# A system-wide install writes outside $HOME. Say so before doing half of it.
if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
  echo "error: --system writes to $HOST_INSTALL_DIR and $DEST, which need root." >&2
  echo "       re-run it as:  sudo $0 --system $BROWSER $EXTENSION_ID" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Install the binary, then the manifest that names it
# ---------------------------------------------------------------------------

INSTALLED_HOST="$HOST_INSTALL_DIR/$(basename "$HOST_PATH")"
if [ -n "$REQUIRE_INSTALLED_PATH" ] && [ "$INSTALLED_HOST" != "$REQUIRE_INSTALLED_PATH" ]; then
  echo "error: refusing to install the host at $INSTALLED_HOST" >&2
  echo "       required installed path is $REQUIRE_INSTALLED_PATH" >&2
  exit 1
fi

HOST_COPIED=0
HOST_HAD_PREVIOUS=0
HOST_PREVIOUS=""

install_host_exclusive() {
  local source="$1" dest="$2"
  HOST_PREVIOUS="$(python3 "$LAYOUT" install-host --source "$source" --dest "$dest")"
}

rollback_installed_host() {
  if [ "$HOST_COPIED" != 1 ]; then
    return 0
  fi
  if ! python3 "$LAYOUT" rollback-host --dest "$INSTALLED_HOST" --backup "$HOST_PREVIOUS"; then
    echo "error: native-host copy rollback failed closed: $INSTALLED_HOST" >&2
    return 1
  fi
  HOST_COPIED=0
  return 0
}

fail_closed_after_copy() {
  if ! rollback_installed_host; then
    echo "error: native-host install rolled back unsuccessfully; no manifest was written" >&2
  fi
  exit 1
}

if [ "$HOST_PATH" = "$INSTALLED_HOST" ]; then
  echo "host already installed at $INSTALLED_HOST"
else
  # Exclusive O_NOFOLLOW temp in the dest directory, then rename into place, so
  # a preplanted .new symlink or special file cannot be written through and a
  # browser that launches the host mid-upgrade gets either the old file or the
  # new one. Previous-host backup is the same exclusive helper, never cp.
  install_host_exclusive "$HOST_PATH" "$INSTALLED_HOST"
  HOST_COPIED=1
  if [ -n "$HOST_PREVIOUS" ]; then
    HOST_HAD_PREVIOUS=1
  fi
  echo "host installed: $INSTALLED_HOST"
  echo "  copied from:  $HOST_PATH"
fi

trap 'status=$?; trap - EXIT; if [ "$status" -ne 0 ]; then rollback_installed_host; fi; exit "$status"' EXIT

if [ "$SYSTEM" = "1" ]; then
  chmod 755 "$HOST_INSTALL_DIR"
fi

# The same test again, on the path the manifest is ABOUT TO NAME rather than on
# the directory that was asked for. Not redundant: `--dest-dir` could name a
# symlink out of an allowed folder and into a gated one, and the only path that
# decides anything is the one that ends up in the JSON.
RESOLVED_HOST="$(cd "$(dirname "$INSTALLED_HOST")" && pwd -P)/$(basename "$INSTALLED_HOST")"
if is_protected "$RESOLVED_HOST"; then
  echo "error: refusing to write a manifest naming $RESOLVED_HOST" >&2
  echo "       $INSTALLED_HOST resolves into a TCC-protected folder. A browser" >&2
  echo "       launching a host from there gets a process that blocks forever" >&2
  echo "       and never answers, with no error reported anywhere." >&2
  fail_closed_after_copy
fi

# ---------------------------------------------------------------------------
# Check the thing that was just installed, rather than reporting the intention
# ---------------------------------------------------------------------------
#
# WHAT THIS PROVES AND WHAT IT DOES NOT. It drives the installed binary over the
# same length-prefixed stdio protocol a browser uses and requires a reply. That
# rules out a truncated copy, a wrong architecture, a missing execute bit, and a
# host that dies on startup.
#
# It does NOT prove the BROWSER can launch it, and must not be read as if it
# did: TCC is a property of the process doing the opening, and this shell is not
# the browser. The prefix refusal above is what covers that, and
# `extension/tools/probe_host_location.py` is what measures it end to end in a
# real browser. Two different claims, kept apart on purpose -- a check that
# reports success while verifying something adjacent is the failure mode this
# whole project keeps finding.

if command -v python3 >/dev/null 2>&1; then
  if python3 - "$INSTALLED_HOST" <<'PY'
import json, struct, subprocess, sys

host = sys.argv[1]
frame = json.dumps({"v": 1, "id": "install-check", "type": "hello"}).encode()
try:
    p = subprocess.Popen([host], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
except OSError as e:
    print(f"  CHECK FAILED: could not start it: {e}")
    sys.exit(1)
try:
    out, _ = p.communicate(struct.pack("<I", len(frame)) + frame, timeout=8)
except subprocess.TimeoutExpired:
    p.kill()
    print("  CHECK FAILED: it started and did not answer within 8s.")
    print("  A host that starts and never answers is the signature of a binary")
    print("  the launching process is not permitted to read.")
    sys.exit(1)
if len(out) < 4:
    print(f"  CHECK FAILED: it answered with {len(out)} byte(s), not a framed reply.")
    sys.exit(1)
(n,) = struct.unpack("<I", out[:4])
try:
    reply = json.loads(out[4:4 + n].decode())
except (ValueError, UnicodeDecodeError) as e:
    print(f"  CHECK FAILED: its reply did not parse: {e}")
    sys.exit(1)
if reply.get("type") != "hello":
    print(f"  CHECK FAILED: it answered {reply.get('type')!r}, not 'hello'.")
    sys.exit(1)
print(f"  check: it answers the handshake -- protocol v{reply.get('protocolVersion')}, "
      f"platform {reply.get('platform')!r}, status {reply.get('status')!r}")
PY
  then
    echo "  (that is this shell launching it. Whether the BROWSER can is a"
    echo "   different question: run extension/tools/probe_host_location.py)"
  else
    echo "error: the installed host does not answer the handshake, so NO MANIFEST" >&2
    echo "       WAS WRITTEN. Nothing now points a browser at a bridge that would" >&2
    echo "       not have worked, which is the whole reason this check runs before" >&2
    echo "       the manifest rather than after it." >&2
    fail_closed_after_copy
  fi
else
  echo "error: python3 is required to drive the installed host before a manifest is written." >&2
  fail_closed_after_copy
fi

# Firefox requires the manifest FILENAME to equal the "name" field. Chrome
# tolerates a mismatch; writing both the same way keeps one rule to remember.
# The renderer is the only writer: it JSON-encodes the path and refuses a
# placeholder id, so a here-doc cannot ship a broken or invented allow-list.
TARGET="$DEST/${HOST_NAME}.json"
require_python3
if ! python3 "$LAYOUT" install-manifest \
  --browser "$BROWSER" \
  --extension-id "$EXTENSION_ID" \
  --host-path "$INSTALLED_HOST" \
  --output "$TARGET"
then
  echo "error: native-host manifest was not written; host copy was rolled back." >&2
  fail_closed_after_copy
fi

# 600 for a per-user install: the browser runs as this user. 644 for a
# system-wide one, where it does not -- a root-owned 600 manifest is a manifest
# no browser can read, which would be this defect again in a new place.
if [ "$SYSTEM" = "1" ]; then chmod 644 "$TARGET"; else chmod 600 "$TARGET"; fi

# ---------------------------------------------------------------------------
# THE FINAL-MANIFEST ASSERTION
# ---------------------------------------------------------------------------
#
# The manifest was just generated, so a placeholder cannot normally appear in
# it -- but the point of this project's build gates is that a guard must prove
# itself, not assume itself. The id is checked in the WRITTEN file: a grep
# refusal that needs no interpreter, plus (when python3 is present) a parse of
# the exact JSON the browser will read, asserting the allow-list entry equals
# the id this script was given and is not a placeholder. Both run before the
# "installed:" line, so a successful run always means the file on disk names
# the store-listing id that was requested.

if grep -q "PLACEHOLDER" "$TARGET"; then
  echo "error: the written manifest still contains a PLACEHOLDER:" >&2
  cat "$TARGET" >&2
  echo "error: no install was reported. This is a bug in the installer." >&2
  python3 "$LAYOUT" uninstall-leaf --output "$TARGET" >/dev/null || true
  fail_closed_after_copy
fi

if ! python3 - "$TARGET" "$KEY" "$VALUE" "$INSTALLED_HOST" <<'PY'
import json, sys

target, key, wanted, host_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(target, "r", encoding="utf-8") as fh:
    manifest = json.load(fh)
entries = manifest.get(key)
if entries != [wanted]:
    print(f"error: written manifest {key} is {entries!r}, expected [{wanted!r}]")
    sys.exit(1)
if manifest.get("path") != host_path:
    print(f"error: written manifest path is {manifest.get('path')!r}, expected {host_path!r}")
    sys.exit(1)
if "PLACEHOLDER" in json.dumps(manifest):
    print("error: written manifest still contains PLACEHOLDER")
    sys.exit(1)
PY
then
  echo "error: the written manifest does not name the installed host and extension id." >&2
  echo "error: no install was reported. The file was left at $TARGET" >&2
  python3 "$LAYOUT" uninstall-leaf --output "$TARGET" >/dev/null || true
  fail_closed_after_copy
fi
echo "  asserted: the written manifest's ${KEY} is exactly [${VALUE}]"
echo "  asserted: the written manifest path is exactly ${INSTALLED_HOST}"

if [ "$HOST_HAD_PREVIOUS" = 1 ]; then
  python3 "$LAYOUT" uninstall-leaf --output "$HOST_PREVIOUS" >/dev/null
fi
HOST_COPIED=0
trap - EXIT

echo "installed: $TARGET"
echo "  host:      $INSTALLED_HOST"
echo "  ${KEY}: ${VALUE}"
if [ "$SYSTEM" != "1" ]; then
  echo "  note: this is a per-user registration. Authenticated browser routing"
  echo "        also needs the root-installed identity receipt, which only the"
  echo "        system install provisions; without it the extension reports the"
  echo "        desktop app as not running."
fi


echo
echo "On Windows use tools/native_messaging/register_native_host.ps1 (HKCU local)"
echo "or the Inno installer (HKLM machine-wide). Both consume the same renderer"
echo "and the same registry subkeys in native_host_layout.py. Chrome/Edge use"
echo "the store ids recorded in tools/native_messaging/manifests/store_ids.json."
echo "Windows has no TCC, but it does have Controlled Folder Access, which gates"
echo "the same three folders when it is switched on. Install under Program Files"
echo "or LocalAppData rather than under Documents, Desktop or Downloads."
