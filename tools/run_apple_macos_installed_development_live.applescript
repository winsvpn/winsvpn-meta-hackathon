set projectDirectory to system attribute "WINS_APPLE_GUI_PROJECT_DIR"
if projectDirectory is "" then set projectDirectory to "/Users/winsvpn/Downloads/wins_vpn"
set liveAppPath to system attribute "WINS_MACOS_LIVE_TUNNEL_APP_PATH"
if liveAppPath is "" then set liveAppPath to "/Applications/Win's VPN.app"
set externalLeakAuditUrls to system attribute "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS"
if externalLeakAuditUrls is "" then error "WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS must contain at least two approved HTTPS hostname canaries."
set forceXray to system attribute "WINS_APPLE_FORCE_XRAY"
if forceXray is not "1" then set forceXray to "0"
set expectDoubleVpn to system attribute "WINS_APPLE_EXPECT_DOUBLE_VPN"
if expectDoubleVpn is not "1" then set expectDoubleVpn to "0"
set expectedTransportMode to "automatic"
if forceXray is "1" then set expectedTransportMode to "xray_vless_ws_amneziawg"

set shellScript to "cd " & quoted form of projectDirectory & linefeed & ¬
    "runtime_tmp=\"$(mktemp -d /tmp/wins-apple-macos-installed-development-live.XXXXXX)\" || exit 1" & linefeed & ¬
    "chmod 700 \"$runtime_tmp\"" & linefeed & ¬
    "run_log=\"$runtime_tmp/run.log\"" & linefeed & ¬
    "run_status_file=\"$runtime_tmp/status\"" & linefeed & ¬
    "printf 'Run artifacts directory: %s\\n' \"$runtime_tmp\"" & linefeed & ¬
    "printf '\\nWin\\047s VPN installed-development macOS live verification\\n'" & linefeed & ¬
    "set +e" & linefeed & ¬
    "/usr/bin/caffeinate -dimsu /usr/bin/env WINS_PRE_RELEASE_SOURCE_SMOKE=1 WINS_SKIP_APPLE_DEBUG_BUILDS=1 WINS_MACOS_LIVE_TUNNEL_APP_PATH=" & quoted form of liveAppPath & " WINS_REQUIRE_APPLE_ENGINE=1 WINS_APPLE_SIGNING_KEYCHAIN_PROBE=1 WINS_APPLE_FORCE_XRAY=" & quoted form of forceXray & " WINS_APPLE_EXPECTED_TRANSPORT_MODE=" & quoted form of expectedTransportMode & " WINS_APPLE_EXPECT_DOUBLE_VPN=" & quoted form of expectDoubleVpn & " WINS_APPLE_SIGNING_KEYCHAIN_PROBE_TIMEOUT_SECONDS=120 WINS_APPLE_LIVE_TUNNEL_SMOKE=1 WINS_APPLE_LIVE_TUNNEL_SMOKE_TIMEOUT_SECONDS=180 WINS_APPLE_EXTERNAL_LEAK_AUDIT=1 WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS=" & quoted form of externalLeakAuditUrls & " WINS_APPLE_EXTERNAL_LEAK_AUDIT_MINIMUM_ENDPOINTS=2 WINS_RELEASE_SHELL_SMOKE=0 WINS_IOS_SIMULATOR_SMOKE=0 WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE=0 WINS_MACOS_LAUNCH_SMOKE=0 /bin/bash tools/apple_runtime_smoke.sh 2>&1 | /usr/bin/tee \"$run_log\"" & linefeed & ¬
    "run_status=${pipestatus[1]}" & linefeed & ¬
    "printf '%s\\n' \"$run_status\" > \"$run_status_file\"" & linefeed & ¬
    "if [ $run_status -eq 0 ]; then printf '\\nInstalled-development macOS live verification passed. You can return to Codex.\\n'; else printf '\\nInstalled-development macOS live verification failed with exit %s. Leave this window open and return to Codex.\\n' \"$run_status\"; fi" & linefeed & ¬
    "exit $run_status"

tell application "Terminal"
    activate
    do script "/bin/zsh -lc " & quoted form of shellScript
end tell
