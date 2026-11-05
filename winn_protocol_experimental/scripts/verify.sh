#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
GO_BIN=${GO_BIN:-go}
export WINN_RELEASE_GATE=1
cd "$ROOT_DIR"
TOOLCHAIN_GO=$("$GO_BIN" env GOROOT)/bin/go
TOOLCHAIN_GOFMT=$(dirname "$TOOLCHAIN_GO")/gofmt

"$GO_BIN" mod verify
unformatted=$("$TOOLCHAIN_GOFMT" -l .)
if [ -n "$unformatted" ]; then
  echo "gofmt required:" >&2
  echo "$unformatted" >&2
  exit 1
fi
for script in "$SCRIPT_DIR"/*.sh; do
  # Syntax-check with the interpreter the shebang names: on Ubuntu /bin/sh
  # is dash, which cannot parse the bash scripts (e.g. obtain_cover_cert.sh
  # uses <<<), so a blanket `sh -n` aborts the gate there while passing on
  # macOS where /bin/sh is bash.
  IFS= read -r shebang < "$script" || shebang=""
  case "$shebang" in
  *bash*) bash -n "$script" ;;
  *) sh -n "$script" ;;
  esac
done
"$GO_BIN" vet ./...
sh "$SCRIPT_DIR/test_scanner_matrix.sh"
GO_BIN="$GO_BIN" "$SCRIPT_DIR/scanner_matrix.sh"
"$GO_BIN" test -race ./...
"$GO_BIN" test ./internal/protocol -run '^$' -fuzz '^FuzzValidatePeerPublicKey$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/protocol -run '^$' -fuzz '^FuzzValidateRequest$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/protocol -run '^$' -fuzz '^FuzzValidateResponse$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/pqauth -run '^$' -fuzz '^FuzzVerifyMLDSASignatureEncoding$' -fuzztime 5s -parallel 1
"$GO_BIN" test ./internal/carrierauth -run '^$' -fuzz '^FuzzSignatureHeader$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/carrier -run '^$' -fuzz '^FuzzReadFrame$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/carrier -run '^$' -fuzz '^FuzzDecodeEnvelope$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/privacytoken -run '^$' -fuzz '^FuzzDecodeTokenHeader$' -fuzztime 10s -parallel 4
"$GO_BIN" test ./internal/wcf3 -run '^$' -fuzz '^FuzzDecode$' -fuzztime 5s -parallel 1
GO_BIN="$GO_BIN" "$SCRIPT_DIR/smoke.sh"
GO_BIN="$GO_BIN" "$SCRIPT_DIR/carrier_smoke.sh"
GO_BIN="$GO_BIN" "$SCRIPT_DIR/advanced_carrier_smoke.sh"
GO_BIN="$GO_BIN" "$SCRIPT_DIR/reproducible_build_test.sh"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "release gate requires a healthy Docker daemon" >&2
  exit 1
fi
GO_BIN="$GO_BIN" "$SCRIPT_DIR/postgres_test.sh"

echo "PASS: modules, formatting, shell syntax, vet, staticcheck, gosec, govulncheck, race, fuzz, interoperability, ECH, transparent manifests, anonymous carrier authorization, path migration, recovery, E2E, reproducibility, and PostgreSQL"
