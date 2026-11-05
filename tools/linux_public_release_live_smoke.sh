#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for retired in WINS_LINUX_SIGNER_IDENTITY WINS_LINUX_SIGNER_OIDC_ISSUER; do
  [[ -z "${!retired:-}" ]] || {
    printf '%s is retired; Linux live smoke uses only the local /etc trust anchor.\n' "${retired}" >&2
    exit 2
  }
done
ARGS=(
  "${ROOT}/tools/public_release_live_smoke_common.py"
  --platform linux
  --producer tools/linux_public_release_live_smoke.sh
)

if [[ "${1:-}" == "--self-test" ]]; then
  python3 "${ROOT}/tools/linux_release_ui_driver.py" --self-test
  python3 "${ROOT}/tools/linux_final_evidence_collector.py" --self-test
  python3 "${ROOT}/tools/linux_installed_artifact_manifest.py" --self-test
  python3 "${ROOT}/tools/linux_apple_release_matrix_evidence.py" --self-test
  ARGS+=(--self-test)
else
  ARTIFACT="${1:-${ROOT}/web/downloads/wins-vpn-linux-x64.tar.gz}"
  MACHINE_EVIDENCE="${2:-}"
  MAP_SCREENSHOT="${3:-}"
  if [[ -z "${MACHINE_EVIDENCE}" || -z "${MAP_SCREENSHOT}" ]]; then
    printf 'Usage: %s ARTIFACT MACHINE_EVIDENCE MAP_SCREENSHOT RELEASE_INPUT_INDEX BUILD_RECEIPT [NATIVE_TRANSCRIPT] [OUTPUT_ROOT]\n' "$0" >&2
    exit 2
  fi
  RELEASE_INPUT_INDEX="${4:-}"
  if [[ -z "${RELEASE_INPUT_INDEX}" ]]; then
    printf 'RELEASE_INPUT_INDEX is required.\n' >&2
    exit 2
  fi
  BUILD_RECEIPT="${5:-}"
  if [[ -z "${BUILD_RECEIPT}" ]]; then
    printf 'BUILD_RECEIPT is required.\n' >&2
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
      printf 'Linux machine evidence must stay under the repository .artifacts directory.\n' >&2
      exit 2
      ;;
  esac
  [[ -f "${machine_absolute}" ]] || {
    printf 'Linux machine evidence does not exist: %s\n' "${machine_absolute}" >&2
    exit 2
  }
  mapfile -t collector_bundle < <(python3 - "${ROOT}" "${MACHINE_EVIDENCE}" "${MAP_SCREENSHOT}" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "tools"))
from linux_final_evidence_collector import (
    CollectorError,
    reject_reparse_components,
    validate_owner_only_linux_bundle,
)

try:
    machine_input = reject_reparse_components(
        pathlib.Path(sys.argv[2]), "Linux machine evidence", must_exist=True
    )
    map_input = reject_reparse_components(
        pathlib.Path(sys.argv[3]), "Linux map screenshot", must_exist=True
    )
    machine, screenshot, index_sha256 = validate_owner_only_linux_bundle(
        machine_input.parent, repo=root, expected_uid=0
    )
except CollectorError as exc:
    raise SystemExit(str(exc)) from exc
if machine_input != machine:
    raise SystemExit("Linux machine evidence is not the exact collector-owned file")
if map_input != screenshot:
    raise SystemExit("Linux map screenshot is not the exact collector-owned file")
print(machine)
print(screenshot)
print(index_sha256)
PY
  )
  if [[ "${#collector_bundle[@]}" -ne 3 ]]; then
    printf 'Linux collector bundle validation did not return exact bindings.\n' >&2
    exit 2
  fi
  machine_absolute="${collector_bundle[0]}"
  MAP_SCREENSHOT="${collector_bundle[1]}"
  evidence_bundle_index_sha256="${collector_bundle[2]}"
  NATIVE_TRANSCRIPT="${6:-${ROOT}/.artifacts/native-transcripts/linux-${evidence_bundle_index_sha256}.json}"
  native_absolute="$(python3 - "${NATIVE_TRANSCRIPT}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).expanduser().resolve())
PY
  )"
  case "${native_absolute}" in
    "${artifacts_absolute}"/*) ;;
    *)
      printf 'Generated Linux native transcript must stay under the repository .artifacts directory.\n' >&2
      exit 2
      ;;
  esac
  [[ ! -e "${native_absolute}" ]] || {
    printf 'Refusing to overwrite an existing Linux native transcript: %s\n' "${native_absolute}" >&2
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
  OUTPUT_ROOT="${7:-.artifacts/release-evidence}"
  ARGS+=(
    --artifact "${ARTIFACT}"
    --native-transcript "${native_absolute}"
    --map-screenshot "${MAP_SCREENSHOT}"
    --release-input-index "${RELEASE_INPUT_INDEX}"
    --build-receipt "${BUILD_RECEIPT}"
    --output-root "${OUTPUT_ROOT}"
    --linux-bundle "${WINS_LINUX_COSIGN_BUNDLE:-${ARTIFACT}.sigstore.json}"
  )
fi

exec python3 "${ARGS[@]}"
