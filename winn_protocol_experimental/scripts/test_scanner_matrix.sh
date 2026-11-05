#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=scripts/scanner_matrix_runner.sh
. "$SCRIPT_DIR/scanner_matrix_runner.sh"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/winn-scanner-matrix-test.XXXXXX")
cleanup() {
  rm -r "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

for scanner in staticcheck gosec govulncheck; do
  ln -s "$SCRIPT_DIR/testdata/fake_release_scanner.sh" "$WORK_DIR/$scanner"
done

success_log="$WORK_DIR/success.log"
success_output="$WORK_DIR/success.out"
: >"$success_log"
WINN_FAKE_SCANNER_LOG="$success_log" \
  winn_run_scanner_matrix \
  "$WORK_DIR/staticcheck" "$WORK_DIR/gosec" "$WORK_DIR/govulncheck" \
  >"$success_output"

if [ "$(wc -l <"$success_log" | tr -d ' ')" -ne 15 ]; then
  echo "scanner matrix did not execute all 15 scanner/target pairs" >&2
  exit 1
fi
for target in darwin/arm64 linux/amd64 linux/arm64 windows/amd64 android/arm64; do
  for scanner in staticcheck gosec govulncheck; do
    if ! grep -Fq "$scanner|$target|cgo=0|" "$success_log"; then
      echo "scanner matrix omitted $scanner on $target" >&2
      exit 1
    fi
  done
done
if ! grep -q '^PASS: pinned release scanners passed every shipping' \
  "$success_output"; then
  echo "all-pass scanner matrix lacked terminal PASS" >&2
  exit 1
fi

failure_log="$WORK_DIR/failure.log"
failure_output="$WORK_DIR/failure.out"
failure_error="$WORK_DIR/failure.err"
: >"$failure_log"
if WINN_FAKE_SCANNER_LOG="$failure_log" \
  WINN_FAKE_SCANNER_FAIL="gosec:linux/amd64" \
  winn_run_scanner_matrix \
  "$WORK_DIR/staticcheck" "$WORK_DIR/gosec" "$WORK_DIR/govulncheck" \
  >"$failure_output" 2>"$failure_error"; then
  echo "scanner matrix accepted a failing Linux gosec run" >&2
  exit 1
fi
if grep -q '^PASS:' "$failure_output"; then
  echo "failing scanner matrix emitted terminal PASS" >&2
  exit 1
fi
if ! grep -q '^SCANNER_FAIL name=gosec target=linux/amd64$' \
  "$failure_error"; then
  echo "failing scanner tuple lacked an exact terminal diagnostic" >&2
  exit 1
fi
if grep -Fq 'govulncheck|linux/amd64' "$failure_log"; then
  echo "scanner matrix continued after a failed tuple" >&2
  exit 1
fi

missing="$WORK_DIR/missing"
if WINN_FAKE_SCANNER_LOG="$WORK_DIR/missing.log" \
  winn_run_scanner_matrix \
  "$missing" "$WORK_DIR/gosec" "$WORK_DIR/govulncheck" \
  >"$WORK_DIR/missing.out" 2>"$WORK_DIR/missing.err"; then
  echo "scanner matrix accepted a missing scanner executable" >&2
  exit 1
fi
if grep -q '^PASS:' "$WORK_DIR/missing.out"; then
  echo "missing-scanner matrix emitted terminal PASS" >&2
  exit 1
fi

echo "PASS: release scanner matrix is complete and fail-closed"
