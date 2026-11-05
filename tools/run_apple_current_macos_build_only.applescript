set projectDirectory to system attribute "WINS_APPLE_GUI_PROJECT_DIR"
if projectDirectory is "" then set projectDirectory to "/Users/winsvpn/Downloads/wins_vpn"
set runtimeScript to system attribute "WINS_APPLE_GUI_RUNTIME_SCRIPT"
if runtimeScript is "" then set runtimeScript to projectDirectory & "/tools/apple_runtime_smoke.sh"
set forceXray to system attribute "WINS_APPLE_FORCE_XRAY"
if forceXray is "" then set forceXray to "0"

set shellScript to "cd " & quoted form of projectDirectory & linefeed & ¬
    "runtime_tmp=\"$(mktemp -d /tmp/wins-apple-current-macos-build-only.XXXXXX)\" || exit 1" & linefeed & ¬
    "chmod 700 \"$runtime_tmp\"" & linefeed & ¬
    "run_log=\"$runtime_tmp/run.log\"" & linefeed & ¬
    "run_status_file=\"$runtime_tmp/status\"" & linefeed & ¬
    "macos_xcconfig=\"$runtime_tmp/macos_development.xcconfig\"" & linefeed & ¬
    "printf 'Run artifacts directory: %s\\n' \"$runtime_tmp\"" & linefeed & ¬
    "printf \"\\nWin's VPN signed macOS development build verification\\n\"" & linefeed & ¬
    "printf 'This builds and strictly verifies the signed macOS development app without running a VPN tunnel or uploading anything.\n'" & linefeed & ¬
    "if [ ! -s \"$macos_xcconfig\" ]; then (cd / && /usr/bin/python3 " & quoted form of (projectDirectory & "/tools/apple_profile_manager.py") & " --require-macos --write-macos-development-xcconfig \"$macos_xcconfig\"); fi" & linefeed & ¬
    "set +e" & linefeed & ¬
    "/usr/bin/env WINS_PROJECT_ROOT=" & quoted form of projectDirectory & " WINS_PRE_RELEASE_SOURCE_SMOKE=1 WINS_SIGNED_MACOS_BUILD=1 WINS_MACOS_DEVELOPMENT_XCCONFIG=\"$macos_xcconfig\" WINS_REQUIRE_APPLE_ENGINE=1 WINS_APPLE_LIVE_TUNNEL_SMOKE=0 WINS_APPLE_FORCE_XRAY=" & quoted form of forceXray & " WINS_IOS_INSTALL=0 WINS_IOS_SIGNED_BUILD=0 WINS_IOS_LIVE_TUNNEL_SMOKE=0 WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS=120 WINS_RELEASE_SHELL_SMOKE=0 WINS_IOS_SIMULATOR_SMOKE=0 WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE=0 WINS_MACOS_LAUNCH_SMOKE=0 /bin/bash " & quoted form of runtimeScript & " 2>&1 | /usr/bin/tee \"$run_log\"" & linefeed & ¬
    "run_status=${pipestatus[1]}" & linefeed & ¬
    "/bin/rm -f -- \"$macos_xcconfig\"" & linefeed & ¬
    "printf '%s\n' \"$run_status\" > \"$run_status_file\"" & linefeed & ¬
    "if [ $run_status -eq 0 ]; then printf '\nSigned macOS development build verification passed. You can return to Codex.\n'; else printf '\nSigned macOS development build verification failed with exit %s. Leave this window open and return to Codex.\n' \"$run_status\"; fi" & linefeed & ¬
    "exit $run_status"

tell application "Terminal"
    activate
    do script "/bin/zsh -lc " & quoted form of shellScript
end tell
