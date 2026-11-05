set releaseInputIndex to system attribute "WINS_RELEASE_INPUT_INDEX"
if releaseInputIndex is "" then error "WINS_RELEASE_INPUT_INDEX must name the current immutable RELEASE_INPUT_INDEX.json."
set receiptDirectory to system attribute "WINS_APPLE_BUILD_RECEIPT_DIR"

set shellScript to "cd /Users/winsvpn/Downloads/wins_vpn" & linefeed & ¬
    "runtime_tmp=\"$(mktemp -d /tmp/wins-apple-release-candidate-rebuild.XXXXXX)\" || exit 1" & linefeed & ¬
    "chmod 700 \"$runtime_tmp\"" & linefeed & ¬
    "run_log=\"$runtime_tmp/run.log\"" & linefeed & ¬
    "run_status_file=\"$runtime_tmp/status\"" & linefeed & ¬
    "printf 'Run artifacts directory: %s\\n' \"$runtime_tmp\"" & linefeed & ¬
    "printf '\\nWin\\047s VPN paired Apple release-candidate rebuild\\n'" & linefeed & ¬
    "printf 'This rebuilds, verifies, and receipt-binds local App Store iOS and macOS artifacts. It does not upload them.\\n'" & linefeed & ¬
    "printf 'If macOS asks for private-key access, enter the Mac login password and choose Always Allow.\\n\\n'" & linefeed & ¬
    "set +e" & linefeed & ¬
    "/usr/bin/env WINS_RELEASE_INPUT_INDEX=" & quoted form of releaseInputIndex & " WINS_APPLE_BUILD_RECEIPT_DIR=" & quoted form of receiptDirectory & " /usr/bin/caffeinate -dimsu /bin/bash tools/build_apple_release_candidates.sh 2>&1 | /usr/bin/tee \"$run_log\"" & linefeed & ¬
    "run_status=${pipestatus[1]}" & linefeed & ¬
    "printf '%s\\n' \"$run_status\" > \"$run_status_file\"" & linefeed & ¬
    "if [ $run_status -eq 0 ]; then printf '\\nPaired Apple release-candidate rebuild passed. You can return to Codex.\\n'; else printf '\\nPaired Apple release-candidate rebuild failed with exit %s. Leave this window open and return to Codex.\\n' \"$run_status\"; fi" & linefeed & ¬
    "exit $run_status"

tell application "Terminal"
    activate
    do script "/bin/zsh -lc " & quoted form of shellScript
end tell
