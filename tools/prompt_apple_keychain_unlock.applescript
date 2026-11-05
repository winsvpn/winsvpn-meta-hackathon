tell application "Terminal"
    activate
    do script "printf '\\nWin\\047s VPN Apple signing unlock\\nEnter the Mac login password at the security prompt below.\\nThe password stays inside macOS Keychain and is not sent to Codex.\\n\\n'; security unlock-keychain \"$HOME/Library/Keychains/login.keychain-db\"; unlock_status=$?; if [ $unlock_status -eq 0 ]; then printf '\\nKeychain unlocked. You can return to Codex.\\n'; else printf '\\nKeychain unlock failed. Check the password and try the command again.\\n'; fi"
end tell
