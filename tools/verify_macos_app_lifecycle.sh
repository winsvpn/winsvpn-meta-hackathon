#!/usr/bin/env bash
# Fails if AppDelegate.applicationDidFinishLaunching stops running on macOS.
#
# WHY THIS EXISTS
# ---------------
# `applicationDidFinishLaunching` is the only thing that calls
# `ensureMainWindowVisible()`. If NSApplication stops calling the delegate --
# a second delegate assigned late, a broken nib outlet, a plugin taking the
# outlet -- the app still launches and still shows a window, so nothing looks
# wrong and everything hanging off that method quietly stops happening. This
# repo has already lost months to exactly that, in both directions: the method
# was recorded as dead when it was alive.
#
# WHY IT DOES NOT USE NSLog
# -------------------------
# Foundation gives the unified log the composed `NSLog` message as a dynamic
# argument, so every NSLog from this app is recorded as
#     Df  Win's VPN[...] (Foundation) <private>
# Measured 20260809: 13 NSLog calls -> 13 `<private>` entries, zero readable.
# Grepping `log show` for NSLog text reports "never ran" for code that ran.
# The app logs launch-path lines through `os_log` with `%{public}@`
# (`WinsAppLifecycle` in macos/Runner/AppDelegate.swift), which is not redacted.
#
# USAGE
#   tools/verify_macos_app_lifecycle.sh [/path/to/Win's VPN.app]
# Exit 0 = the delegate ran. Any other exit = it did not, or could not be shown
# to have run, which is the same thing for our purposes.

set -Eeuo pipefail

# The product name contains an apostrophe, and an apostrophe inside a "${...}"
# or "$(...)" expansion opens a single-quoted run that swallows the rest of the
# file. Keep it in a plain double-quoted assignment, never in an expansion.
APP="${1:-}"
if [ -z "$APP" ]; then
  APP="/Applications/Win's VPN.app"
fi
MARKER="WINSLIFECYCLE"
DID_FINISH_LINE="applicationDidFinishLaunching ENTER"
WINDOW_LINE="MainFlutterWindow.awakeFromNib ENTER"
SETTLE_SECONDS="${WINS_LIFECYCLE_SETTLE_SECONDS:-14}"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

printf 'verify_macos_app_lifecycle: %s\n' "$APP"

[ -d "$APP" ] || fail "no app bundle at $APP. Nothing installs a build to /Applications automatically; install one first."

# Note for editors: the product name contains an apostrophe. Keep it in a
# variable and out of nested quoting -- an apostrophe inside "$( ... )" inside a
# double-quoted string opens a single-quoted run and breaks the whole file.
EXEC_NAME="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist" 2>/dev/null || true)"
[ -n "$EXEC_NAME" ] || EXEC_NAME="$(basename "$APP" .app)"
BIN="$APP/Contents/MacOS/$EXEC_NAME"
[ -x "$BIN" ] || fail "no executable at $BIN"

# Trap guard: a .bak_* copy of an .app in /Applications is a live extension
# provider, and it makes every measurement here ambiguous.
STRAYS="$(find /Applications -maxdepth 1 -name '*.bak_*' -print 2>/dev/null || true)"
if [ -n "$STRAYS" ]; then
  fail "bundle backups present in /Applications, which are live providers and will confuse this measurement:
$STRAYS
Move them to .artifacts/ and re-run."
fi

# Guard the stale-install trap: prove the bundle we are about to launch is one
# that even contains the instrumentation before concluding anything from its
# absence in the log.
# `grep -q` exits on first match, which SIGPIPEs `strings`; under `pipefail`
# that makes the pipeline non-zero even on a match. Count instead -- `grep -c`
# drains its input, so the pipeline status means what it looks like it means.
MARKER_HITS="$(strings -a "$BIN" | grep -c "$MARKER" || true)"
if [ "${MARKER_HITS:-0}" -eq 0 ]; then
  fail "installed binary contains no $MARKER string. It predates the lifecycle
instrumentation, so its silence proves nothing. Rebuild Release with
  xcodebuild -workspace macos/Runner.xcworkspace -scheme Runner
    -configuration Release -destination platform=macOS
    -derivedDataPath <dd> DEVELOPMENT_TEAM=5YT8H4U72M -allowProvisioningUpdates build
then rm -rf the installed bundle and ditto the built one over it.
See docs/handoff/MACOS_APPDELEGATE_LIFECYCLE_20260809.md"
fi
note "installed binary carries the $MARKER instrumentation"

APP_NAME="$(basename "$APP" .app)"
pkill -x "$APP_NAME" 2>/dev/null || true
sleep 2

START="$(date '+%Y-%m-%d %H:%M:%S')"
open -a "$APP" || fail "could not launch $APP"
note "launched at $START, settling ${SETTLE_SECONDS}s"
sleep "$SETTLE_SECONDS"

CAPTURE="$(mktemp -t winslifecycle)"
# The owner's predicate, verbatim.
log show --style compact --start "$START" \
  --predicate 'processImagePath CONTAINS "Win'\''s VPN"' > "$CAPTURE" 2>&1
LOG_RC=$?
pkill -x "$APP_NAME" 2>/dev/null || true
[ "$LOG_RC" -eq 0 ] || fail "log show exited $LOG_RC"

if grep -q "$MARKER FAULT" "$CAPTURE"; then
  printf 'FAIL: the app itself reported a launch-path fault:\n' >&2
  grep "$MARKER FAULT" "$CAPTURE" >&2
  rm -f "$CAPTURE"
  exit 1
fi

if ! grep -q "$WINDOW_LINE" "$CAPTURE"; then
  cp "$CAPTURE" "${CAPTURE}.kept"
  fail "the app did not reach MainFlutterWindow.awakeFromNib. It did not launch
far enough to say anything about the delegate. Capture: ${CAPTURE}.kept"
fi
note "control line present: $WINDOW_LINE"

if ! grep -q "$DID_FINISH_LINE" "$CAPTURE"; then
  cp "$CAPTURE" "${CAPTURE}.kept"
  fail "AppDelegate.applicationDidFinishLaunching DID NOT RUN.
The window came up, so the nib loaded and the process is fine -- NSApplication
is not calling this delegate. ensureMainWindowVisible() and everything else
reachable only from that method is dead in this build.
Check, in this order: a second NSApp.delegate assigned after nib load; the
MainMenu.xib delegate outlet on File's Owner; a plugin claiming the outlet.
Capture: ${CAPTURE}.kept"
fi

printf 'PASS: applicationDidFinishLaunching ran.\n'
grep "$MARKER" "$CAPTURE" | sed 's/^/  /'
rm -f "$CAPTURE"
