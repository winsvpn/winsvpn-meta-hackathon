#!/bin/sh
set -eu

REAL_SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
PRIVATE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/winn-verify-gate.XXXXXX")
PRIVATE_ROOT=$(CDPATH='' cd -- "$PRIVATE_ROOT" && pwd -P)
cleanup() {
  rm -r "$PRIVATE_ROOT"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$PRIVATE_ROOT/scripts" "$PRIVATE_ROOT/driver" \
  "$PRIVATE_ROOT/goroot/bin" "$PRIVATE_ROOT/path" "$PRIVATE_ROOT/trace"

tuple() {
  leaf=$1
  if stat -f '%d %i %z' "$leaf" >/dev/null 2>&1; then
    identity=$(stat -f '%d %i %z' "$leaf")
  else
    identity=$(stat -c '%d %i %s' "$leaf")
  fi
  digest=$(shasum -a 256 "$leaf" | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$leaf" "$identity" "$digest"
}

HOST_GO=$(command -v go || true)
HOST_GOROOT=""
if [ -n "$HOST_GO" ]; then
  HOST_GOROOT=$("$HOST_GO" env GOROOT)
fi
{
  tuple "$REAL_SCRIPT_DIR/verify.sh"
  for sibling in smoke carrier_smoke advanced_carrier_smoke reproducible_build_test postgres_test; do
    tuple "$REAL_SCRIPT_DIR/$sibling.sh"
  done
  if [ -n "$HOST_GO" ]; then
    tuple "$HOST_GO"
    tuple "$HOST_GOROOT/bin/go"
    tuple "$HOST_GOROOT/bin/gofmt"
  fi
} >"$PRIVATE_ROOT/trace/real-before"

cp "$REAL_SCRIPT_DIR/verify.sh" "$PRIVATE_ROOT/scripts/verify.sh"

for sibling in smoke carrier_smoke advanced_carrier_smoke reproducible_build_test postgres_test; do
  printf '#!/bin/sh\nset -eu\nprintf \"%s\\\\n\" >\"%s/trace/%s\"\n' \
    "$sibling" "$PRIVATE_ROOT" "$sibling" >"$PRIVATE_ROOT/scripts/$sibling.sh"
  chmod 0700 "$PRIVATE_ROOT/scripts/$sibling.sh"
done

cat >"$PRIVATE_ROOT/driver/go" <<EOF
#!/bin/sh
set -eu
if [ "\$#" -eq 2 ] && [ "\$1" = env ] && [ "\$2" = GOROOT ]; then
  printf '%s\\n' "$PRIVATE_ROOT/goroot"
  exit 0
fi
printf 'driver-go\\n' >"$PRIVATE_ROOT/trace/driver-go"
exit 0
EOF
cat >"$PRIVATE_ROOT/goroot/bin/go" <<EOF
#!/bin/sh
set -eu
printf 'toolchain-go\\n' >"$PRIVATE_ROOT/trace/toolchain-go"
exit 0
EOF
cat >"$PRIVATE_ROOT/goroot/bin/gofmt" <<EOF
#!/bin/sh
set -eu
printf 'toolchain-gofmt\\n' >"$PRIVATE_ROOT/trace/toolchain-gofmt"
exit 0
EOF
for command in docker openssl; do
  cat >"$PRIVATE_ROOT/path/$command" <<EOF
#!/bin/sh
set -eu
printf '$command\\n' >"$PRIVATE_ROOT/trace/$command"
exit 0
EOF
done
chmod 0700 "$PRIVATE_ROOT/driver/go" "$PRIVATE_ROOT/goroot/bin/go" \
  "$PRIVATE_ROOT/goroot/bin/gofmt" "$PRIVATE_ROOT/path/docker" \
  "$PRIVATE_ROOT/path/openssl" "$PRIVATE_ROOT/scripts/verify.sh"

for leaf in "$PRIVATE_ROOT/driver/go" "$PRIVATE_ROOT/goroot/bin/go" \
  "$PRIVATE_ROOT/goroot/bin/gofmt" \
  "$PRIVATE_ROOT/scripts/smoke.sh" "$PRIVATE_ROOT/scripts/carrier_smoke.sh" \
  "$PRIVATE_ROOT/scripts/advanced_carrier_smoke.sh" \
  "$PRIVATE_ROOT/scripts/reproducible_build_test.sh" \
  "$PRIVATE_ROOT/scripts/postgres_test.sh"; do
  [ -f "$leaf" ] && [ ! -L "$leaf" ] || exit 1
  case "$(CDPATH='' cd -- "$(dirname -- "$leaf")" && pwd -P)/$(basename -- "$leaf")" in
    "$PRIVATE_ROOT"/*) ;;
    *) exit 1 ;;
  esac
done

GO_BIN="$PRIVATE_ROOT/driver/go" \
PATH="$PRIVATE_ROOT/path:/bin:/usr/bin" \
  "$PRIVATE_ROOT/scripts/verify.sh" >/dev/null

{
  tuple "$REAL_SCRIPT_DIR/verify.sh"
  for sibling in smoke carrier_smoke advanced_carrier_smoke reproducible_build_test postgres_test; do
    tuple "$REAL_SCRIPT_DIR/$sibling.sh"
  done
  if [ -n "$HOST_GO" ]; then
    tuple "$HOST_GO"
    tuple "$HOST_GOROOT/bin/go"
    tuple "$HOST_GOROOT/bin/gofmt"
  fi
} >"$PRIVATE_ROOT/trace/real-after"
cmp "$PRIVATE_ROOT/trace/real-before" "$PRIVATE_ROOT/trace/real-after"

for token in driver-go toolchain-go toolchain-gofmt smoke carrier_smoke \
  advanced_carrier_smoke reproducible_build_test postgres_test docker; do
  [ -f "$PRIVATE_ROOT/trace/$token" ] || {
    echo "missing private trace token: $token" >&2
    exit 1
  }
done

echo "PASS: private verify driver, absolute toolchain, and five sibling scripts"
