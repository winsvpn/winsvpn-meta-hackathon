#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
ROOT_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd -P)
GO_BIN=${GO_BIN:-go}
TOOLCHAIN_GO=$("$GO_BIN" env GOROOT)/bin/go
HOST_OS=$("$TOOLCHAIN_GO" env GOHOSTOS)
HOST_ARCH=$("$TOOLCHAIN_GO" env GOHOSTARCH)
TOOLS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-release-scanners.XXXXXX")

cleanup() {
  rm -r "$TOOLS_DIR"
}
trap cleanup EXIT HUP INT TERM

# shellcheck source=scripts/scanner_matrix_runner.sh
. "$SCRIPT_DIR/scanner_matrix_runner.sh"

install_tool() {
  package=$1
  requested_version=$2
  binary_name=$3
  expected_module=$4
  expected_version=$5
  expected_sum=$6

  GOOS="$HOST_OS" GOARCH="$HOST_ARCH" CGO_ENABLED=0 \
    GOTOOLCHAIN=local GOBIN="$TOOLS_DIR" "$TOOLCHAIN_GO" install \
    "$package@$requested_version"
  binary="$TOOLS_DIR/$binary_name"
  if [ ! -x "$binary" ]; then
    echo "pinned scanner install did not produce $binary_name" >&2
    return 1
  fi
  buildinfo=$("$TOOLCHAIN_GO" version -m "$binary")
  if ! printf '%s\n' "$buildinfo" | awk \
    -v path="$package" \
    -v module="$expected_module" \
    -v version="$expected_version" \
    -v sum="$expected_sum" '
      $1 == "path" && $2 == path { found_path=1 }
      $1 == "mod" && $2 == module && $3 == version && $4 == sum {
        found_module=1
      }
      END { exit !(found_path && found_module) }
    '; then
    echo "pinned scanner build identity mismatch for $binary_name" >&2
    return 1
  fi
}

cd "$ROOT_DIR"
install_tool \
  honnef.co/go/tools/cmd/staticcheck 2026.1 staticcheck \
  honnef.co/go/tools v0.7.0 \
  'h1:<REDACTED_WG_KEY>'
install_tool \
  github.com/securego/gosec/v2/cmd/gosec v2.25.0 gosec \
  github.com/securego/gosec/v2 v2.25.0 \
  'h1:<REDACTED_WG_KEY>'
install_tool \
  golang.org/x/vuln/cmd/govulncheck v1.6.0 govulncheck \
  golang.org/x/vuln v1.6.0 \
  'h1:<REDACTED_WG_KEY>'

winn_run_scanner_matrix \
  "$TOOLS_DIR/staticcheck" "$TOOLS_DIR/gosec" "$TOOLS_DIR/govulncheck"
