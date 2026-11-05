#!/usr/bin/env bash
# Offline Smart Router initiation and distress-routing contract receipt.
# Local pytest only. Does not call Google Cloud, Gemini, aicore, GitHub, or stores.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
OUT="$(dirname "$0")/prod_sanity.txt"
{
  echo "=== Smart Router contract receipt $(date -u +%FT%TZ) ==="
  echo "mode: offline local pytest"
  echo "remote_calls: none"
  echo "contract: deterministic authenticated winn/3 first; local Gemma on distress; Google only when provisioned; immediate deterministic fallback"
  python3 -m pytest -q \
    "$ROOT/tests/test_router.py" \
    "$ROOT/tests/test_protocol_selection.py" \
    "$ROOT/tests/test_hostile_timeout_contract.py"
  echo "=== done ==="
} >"$OUT"
cat "$OUT"
