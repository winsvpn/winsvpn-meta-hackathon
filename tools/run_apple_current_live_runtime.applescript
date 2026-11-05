set projectDirectory to system attribute "WINS_APPLE_GUI_PROJECT_DIR"
if projectDirectory is "" then set projectDirectory to "/Users/winsvpn/Downloads/wins_vpn"
set externalLeakAuditUrls to system attribute "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS"
if externalLeakAuditUrls is "" then error "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS must contain at least two approved HTTPS hostname canaries."
set forceXray to system attribute "WINS_APPLE_FORCE_XRAY"
if forceXray is not "1" then set forceXray to "0"

set shellScript to "cd " & quoted form of projectDirectory & linefeed & ¬
    "runtime_tmp=\"$(mktemp -d /tmp/wins-apple-current-live-runtime.XXXXXX)\" || exit 1" & linefeed & ¬
    "chmod 700 \"$runtime_tmp\"" & linefeed & ¬
    "run_log=\"$runtime_tmp/run.log\"" & linefeed & ¬
    "run_status_file=\"$runtime_tmp/status\"" & linefeed & ¬
    "macos_xcconfig=\"$runtime_tmp/macos_development.xcconfig\"" & linefeed & ¬
    "printf 'Run artifacts directory: %s\\n' \"$runtime_tmp\"" & linefeed & ¬
    "printf '\\nWin\\047s VPN current Apple live runtime verification\\n'" & linefeed & ¬
    "printf 'This builds signed development apps, installs the iPhone app, and runs macOS plus iPhone connect/probe/leak/disconnect checks. It does not upload or publish anything.\\n'" & linefeed & ¬
    "printf 'If macOS asks for private-key access, enter the Mac login password and choose Always Allow.\\n\\n'" & linefeed & ¬
    "if [ ! -s \"$macos_xcconfig\" ]; then (cd / && /usr/bin/python3 " & quoted form of (projectDirectory & "/tools/apple_profile_manager.py") & " --require-macos --write-macos-development-xcconfig \"$macos_xcconfig\"); fi" & linefeed & ¬
    "set +e" & linefeed & ¬
    "/usr/bin/caffeinate -dimsu /usr/bin/env WINS_PRE_RELEASE_SOURCE_SMOKE=1 WINS_APPLE_RUNTIME_EVIDENCE_REFRESH=1 WINS_IOS_INSTALL=1 WINS_IOS_LIVE_TUNNEL_SMOKE=1 WINS_IOS_APPROVE_VPN_PERMISSION=1 WINS_SIGNED_MACOS_BUILD=1 WINS_MACOS_DEVELOPMENT_XCCONFIG=\"$macos_xcconfig\" WINS_REQUIRE_APPLE_ENGINE=1 WINS_APPLE_LIVE_TUNNEL_SMOKE=1 WINS_APPLE_FORCE_XRAY=" & quoted form of forceXray & " WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS=120 WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS=180 WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=" & quoted form of externalLeakAuditUrls & " WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS=2 WINS_RELEASE_SHELL_SMOKE=0 WINS_IOS_SIMULATOR_SMOKE=0 WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE=0 WINS_MACOS_LAUNCH_SMOKE=0 /bin/bash tools/apple_runtime_smoke.sh 2>&1 | /usr/bin/tee \"$run_log\"" & linefeed & ¬
    "run_status=${pipestatus[1]}" & linefeed & ¬
    "/bin/rm -f -- \"$macos_xcconfig\"" & linefeed & ¬
    "printf '%s\\n' \"$run_status\" > \"$run_status_file\"" & linefeed & ¬
    "if [ $run_status -eq 0 ]; then printf '\\nCurrent Apple live runtime verification passed. You can return to Codex.\\n'; else printf '\\nCurrent Apple live runtime verification failed with exit %s. Leave this window open and return to Codex.\\n' \"$run_status\"; fi" & linefeed & ¬
    "exit $run_status"

tell application "Terminal"
    activate
    do script "/bin/zsh -lc " & quoted form of shellScript
end tell
