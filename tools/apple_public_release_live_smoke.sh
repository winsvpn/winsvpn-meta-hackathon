#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "--self-test" ]]; then
  python3 "${ROOT}/tools/test_apple_final_evidence_collector.py"
  python3 "${ROOT}/tools/test_apple_release_ui_driver.py"
  python3 "${ROOT}/tools/apple_release_ui_driver.py" self_test
  python3 "${ROOT}/tools/linux_apple_release_matrix_evidence.py" --self-test
  python3 "${ROOT}/tools/public_release_live_smoke_common.py" \
    --platform ios \
    --producer tools/apple_public_release_live_smoke.sh \
    --self-test
  exec python3 "${ROOT}/tools/public_release_live_smoke_common.py" \
    --platform macos \
    --producer tools/apple_public_release_live_smoke.sh \
    --self-test
fi

PLATFORM="${1:-}"
ARTIFACT="${2:-}"
MACHINE_EVIDENCE="${3:-}"
MAP_SCREENSHOT="${4:-}"
RELEASE_INPUT_INDEX="${5:-}"
BUILD_RECEIPT="${6:-}"
NATIVE_TRANSCRIPT="${7:-}"
OUTPUT_ROOT="${8:-.artifacts/release-evidence}"
if [[ "${PLATFORM}" != "ios" && "${PLATFORM}" != "macos" ]]; then
  printf 'Usage: %s {ios|macos} ARTIFACT MACHINE_EVIDENCE MAP_SCREENSHOT RELEASE_INPUT_INDEX BUILD_RECEIPT [NATIVE_TRANSCRIPT] [OUTPUT_ROOT]\n' "$0" >&2
  exit 2
fi
if [[ -z "${ARTIFACT}" || -z "${MACHINE_EVIDENCE}" || -z "${MAP_SCREENSHOT}" || -z "${RELEASE_INPUT_INDEX}" || -z "${BUILD_RECEIPT}" ]]; then
  printf 'Artifact, machine evidence, map screenshot, RELEASE_INPUT_INDEX, and BUILD_RECEIPT are required.\n' >&2
  exit 2
fi

machine_absolute="$(python3 - "${MACHINE_EVIDENCE}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
artifacts_absolute="$(python3 - "${ROOT}/.artifacts" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
case "${machine_absolute}" in
  "${artifacts_absolute}"/*) ;;
  *)
    printf 'Apple machine evidence must stay under the repository .artifacts directory.\n' >&2
    exit 2
    ;;
esac
[[ -f "${machine_absolute}" ]] || {
  printf 'Apple machine evidence does not exist: %s\n' "${machine_absolute}" >&2
  exit 2
}
[[ ! -L "${MACHINE_EVIDENCE}" ]] || {
  printf 'Apple machine evidence must not be a symlink.\n' >&2
  exit 2
}
mapfile -t collector_bundle < <(python3 - "${ROOT}" "${PLATFORM}" "${MACHINE_EVIDENCE}" "${MAP_SCREENSHOT}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
platform = sys.argv[2]
sys.path.insert(0, str(root / "tools"))
from apple_final_evidence_collector import (
    CollectorError,
    reject_link_components,
    validate_owner_only_bundle,
)

try:
    machine_input = reject_link_components(
        pathlib.Path(sys.argv[3]), "Apple machine evidence", must_exist=True
    )
    map_input = reject_link_components(
        pathlib.Path(sys.argv[4]), "Apple map screenshot", must_exist=True
    )
    expected_machine, expected_map, index_sha256 = validate_owner_only_bundle(
        machine_input.parent,
        platform=platform,
        repo=root,
        expected_uid=0,
    )
except CollectorError as exc:
    raise SystemExit(str(exc)) from exc
if machine_input != expected_machine:
    raise SystemExit("Apple machine evidence is not the exact collector-owned platform file")
if map_input != expected_map:
    raise SystemExit("Apple map screenshot is not the exact collector-owned map file")
print(expected_machine)
print(expected_map)
print(index_sha256)
PY
)
if [[ "${#collector_bundle[@]}" -ne 3 ]]; then
  printf 'Apple collector bundle validation did not return exact bindings.\n' >&2
  exit 2
fi
machine_absolute="${collector_bundle[0]}"
MAP_SCREENSHOT="${collector_bundle[1]}"
evidence_bundle_index_sha256="${collector_bundle[2]}"
if [[ -z "${NATIVE_TRANSCRIPT}" ]]; then
  NATIVE_TRANSCRIPT="${ROOT}/.artifacts/native-transcripts/${PLATFORM}-${evidence_bundle_index_sha256}.json"
fi
native_absolute="$(python3 - "${NATIVE_TRANSCRIPT}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
)"
case "${native_absolute}" in
  "${artifacts_absolute}"/*) ;;
  *)
    printf 'Generated Apple native transcript must stay under the repository .artifacts directory.\n' >&2
    exit 2
    ;;
esac
[[ ! -e "${native_absolute}" ]] || {
  printf 'Refusing to overwrite an existing Apple native transcript: %s\n' "${native_absolute}" >&2
  exit 2
}
python3 "${ROOT}/tools/linux_apple_release_matrix_evidence.py" \
  --machine-evidence "${machine_absolute}" \
  --artifact "${ARTIFACT}" \
  --map-screenshot "${MAP_SCREENSHOT}" \
  --release-input-index "${RELEASE_INPUT_INDEX}" \
  --build-receipt "${BUILD_RECEIPT}" \
  --evidence-bundle-index-sha256 "${evidence_bundle_index_sha256}" \
  --output "${native_absolute}"

exec python3 "${ROOT}/tools/public_release_live_smoke_common.py" \
  --platform "${PLATFORM}" \
  --producer tools/apple_public_release_live_smoke.sh \
  --artifact "${ARTIFACT}" \
  --native-transcript "${native_absolute}" \
  --map-screenshot "${MAP_SCREENSHOT}" \
  --release-input-index "${RELEASE_INPUT_INDEX}" \
  --build-receipt "${BUILD_RECEIPT}" \
  --output-root "${OUTPUT_ROOT}"
