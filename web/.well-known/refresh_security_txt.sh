#!/usr/bin/env bash
# Roll security.txt's Expires field forward one year.
#
# RFC 9116 treats an expired security.txt as invalid, so a stale file silently
# turns your disclosure programme off. This is the whole maintenance burden of
# that file; automate it or it will lapse.
#
# Run monthly. It only rewrites when Expires is under 90 days away, so it is safe
# to run often and produces no churn the rest of the year.
#   0 6 1 * *  /path/to/refresh_security_txt.sh /path/to/web/.well-known/security.txt
set -euo pipefail

FILE="${1:-$(dirname "$0")/security.txt}"
[[ -f "$FILE" ]] || { echo "security.txt not found at $FILE" >&2; exit 1; }

current="$(grep -i '^Expires:' "$FILE" | head -1 | sed 's/^[Ee][Xx][Pp][Ii][Rr][Ee][Ss]:[[:space:]]*//')"
[[ -n "$current" ]] || { echo "no Expires field in $FILE" >&2; exit 1; }

# GNU date and BSD/macOS date disagree on parsing; try both.
if current_epoch=$(date -u -d "$current" +%s 2>/dev/null); then
  new_date=$(date -u -d "+1 year" +%Y-%m-%dT00:00:00.000Z)
  threshold=$(date -u -d "+90 days" +%s)
else
  current_epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "${current%.*Z}" +%s 2>/dev/null) \
    || { echo "could not parse Expires: $current" >&2; exit 1; }
  new_date=$(date -u -v+1y +%Y-%m-%dT00:00:00.000Z)
  threshold=$(date -u -v+90d +%s)
fi

if (( current_epoch > threshold )); then
  echo "security.txt Expires=$current is more than 90 days out; nothing to do."
  exit 0
fi

tmp="$(mktemp)"
sed "s|^[Ee][Xx][Pp][Ii][Rr][Ee][Ss]:.*|Expires: $new_date|" "$FILE" > "$tmp"
mv "$tmp" "$FILE"
echo "security.txt Expires rolled forward: $current -> $new_date"
echo "REMEMBER: this only refreshes the file. Redeploy the site for it to take effect."
