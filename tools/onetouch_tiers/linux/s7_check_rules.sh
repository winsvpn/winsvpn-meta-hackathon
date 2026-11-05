#!/usr/bin/env bash
# s7_check_rules.sh FILE [all|structure]   (Tier B, root)
# Loads an iptables-save file into a throwaway network namespace and runs the installer's own dominance
# predicate (latch_predicate.py, extracted from the installer under test) there. Prints `S1,S2,L1 pass`
# (or `S1,S2 pass` for structure) or the predicate's refusal, and exits with the predicate's status.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
mode="${2:-all}"
out="$(unshare -n bash -c '/usr/sbin/iptables-restore --wait 10 < "$1" || exit 99; python3 "$2/latch_predicate.py" /usr/sbin/iptables "$3"' _ "$1" "${here}" "${mode}" 2>&1)"
rc=$?
if [[ ${rc} == 0 ]]; then
  [[ "${mode}" == all ]] && echo "S1,S2,L1 pass" || echo "S1,S2 pass"
else
  echo "FAIL rc=${rc}: ${out}"
fi
exit ${rc}
