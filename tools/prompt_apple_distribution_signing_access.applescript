set shellScript to "set -e" & linefeed & ¬
    "printf '\\nWin\\047s VPN Apple Distribution private-key probe\\n'" & linefeed & ¬
    "printf 'If macOS asks to access the Apple Distribution private key, enter the Mac login password and choose Always Allow.\\n'" & linefeed & ¬
    "printf 'The password stays inside macOS Keychain and is not sent to Codex.\\n\\n'" & linefeed & ¬
    "identity=$(/usr/bin/security find-identity -v -p codesigning | /usr/bin/awk '/\"Apple Distribution:/{print $2; exit}')" & linefeed & ¬
    "if ! printf '%s' \"$identity\" | /usr/bin/grep -Eq '^[0-9A-F]{40}$'; then printf 'Apple Distribution identity not found.\\n'; exit 2; fi" & linefeed & ¬
    "tmp=$(/usr/bin/mktemp -d \"${TMPDIR:-/tmp}/wins-distribution-visible-probe.XXXXXX\")" & linefeed & ¬
    "trap '/bin/rm -rf -- \"$tmp\"' EXIT" & linefeed & ¬
    "/bin/cp /usr/bin/true \"$tmp/probe\"" & linefeed & ¬
    "set +e" & linefeed & ¬
    "/usr/bin/codesign --force --sign \"$identity\" --timestamp=none \"$tmp/probe\"" & linefeed & ¬
    "sign_status=$?" & linefeed & ¬
    "set -e" & linefeed & ¬
    "if [ $sign_status -eq 0 ] && /usr/bin/codesign --verify --strict --verbose=2 \"$tmp/probe\"; then printf '\\nApple Distribution private-key probe passed. You can return to Codex.\\n'; else printf '\\nApple Distribution private-key probe failed. Leave this window open and return to Codex.\\n'; exit ${sign_status:-1}; fi"

tell application "Terminal"
    activate
    do script "/bin/zsh -lc " & quoted form of shellScript
end tell
