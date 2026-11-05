#!/usr/bin/env bash
# shellcheck disable=SC2034  # globals are read by the other files of the bundle
# Entry point inside the namespaces: fx_main.sh [--profile quick|full] SCENARIO...
# Started by tier_a.py as: sudo -n unshare -m -n -p -f --mount-proc bash fx_main.sh ...
set +u
FX_BUNDLE="$(cd "$(dirname "$0")" && pwd)"
export FX_BUNDLE
FX_PROFILE=quick
if [[ "${1:-}" == --profile ]]; then FX_PROFILE="$2"; shift 2; fi
export FX_PROFILE
# shellcheck disable=SC1091
source "${FX_BUNDLE}/fx_lib.sh"
for f in "${FX_BUNDLE}"/sc_*.sh; do
  # shellcheck disable=SC1090
  source "${f}"
done
fx_init
for scenario in "$@"; do
  fx_run_scenario "${scenario}"
done
fx_reset
echo "S7 note main done failed=${FX_FAILED}"
