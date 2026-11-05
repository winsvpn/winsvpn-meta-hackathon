#!/usr/bin/env bash
set -Eeuo pipefail

for tool in cc objcopy readelf strip; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Linux split-debug fixture requires $tool." >&2
    exit 127
  }
done

fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
printf 'int main(void) { return 0; }\n' >"$fixture/main.c"
cc -g -Wl,--build-id=sha1 "$fixture/main.c" -o "$fixture/app"
objcopy --only-keep-debug "$fixture/app" "$fixture/app.debug"
strip --strip-unneeded "$fixture/app"
(
  cd "$fixture"
  objcopy --add-gnu-debuglink=app.debug "$fixture/app"
)

delivery_sections="$(readelf -SW "$fixture/app")"
debug_sections="$(readelf -SW "$fixture/app.debug" 2>/dev/null)"
grep -q '[.]gnu_debuglink' <<<"$delivery_sections"
grep -q '[.]note[.]gnu[.]build-id' <<<"$delivery_sections"
if grep -Eq '[.]symtab|[.]debug_' <<<"$delivery_sections"; then
  echo "Split-debug fixture delivery binary retained private symbols." >&2
  exit 1
fi
grep -q '[.]symtab' <<<"$debug_sections"
grep -q '[.]debug_info' <<<"$debug_sections"
delivery_build_id="$(readelf -n "$fixture/app" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')"
debug_build_id="$(readelf -n "$fixture/app.debug" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')"
[[ -n "$delivery_build_id" && "$delivery_build_id" == "$debug_build_id" ]]

printf 'LINUX SPLIT-DEBUG FIXTURE: PASS\n'
