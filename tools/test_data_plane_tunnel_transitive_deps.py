#!/usr/bin/env python3
"""Follow-up ADV-LOADED-DEPS (Fable ruling 2026-10-01, optional item):
data_tunnel_unit_drop_ssh_requires walks one level further. A unit the
management tunnel connector Requires= (or Requisite=, BindsTo=, PartOf=) that
itself carries such a dependency on ssh refuses the carried rerun before apt,
and a failed read of a dependency's own properties refuses too.

Uses the production function through the TunnelHarness of
tools/test_data_plane_ia_dp_high.py (so WINS_IA_DP_HIGH_DATA points this suite
at another installer copy). systemctl is re-stubbed per unit for `show`; the
stub refuses a unit name that starts with '-' unless it follows `--`, the way
systemctl's option parser does.

Usage: python3 tools/test_data_plane_tunnel_transitive_deps.py [-v]
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_data_plane_ia_dp_high as dph  # noqa: E402

PER_UNIT_SHOW = r'''
eval "orig_$(declare -f systemctl)"
systemctl() {
  if [[ "$1" == show && "$*" == *"-p Requires"* ]]; then
    printf 'systemctl %s\n' "$*" >> "${EVENTS}"
    local unit="${!#}" prev="" arg
    for arg in "$@"; do [[ "${arg}" == "${unit}" ]] && break; prev="${arg}"; done
    if [[ "${unit}" == -* && "${prev}" != -- ]]; then
      echo "systemctl: unrecognized option '${unit}'" >&2
      return 1
    fi
    if [[ "${unit}" == wins-node-management-tunnel.service ]]; then
      [[ ! -e "${STATE}/show_deps_fail" ]] || return 1
      if [[ -e "${STATE}/loaded_deps" ]]; then cat "${STATE}/loaded_deps"; else printf '\n\n\n\n'; fi
      return 0
    fi
    [[ ! -e "${STATE}/fail.${unit}" ]] || return 1
    if [[ -e "${STATE}/deps.${unit}" ]]; then cat "${STATE}/deps.${unit}"; else printf '\n\n\n\n'; fi
    return 0
  fi
  orig_systemctl "$@"
}
'''

CALL = PER_UNIT_SHOW + "data_tunnel_unit_drop_ssh_requires\necho APT-REACHED"


class TransitiveSshDependencyTests(unittest.TestCase):
    def harness(self, tunnel_deps: str, **units: str) -> dph.TunnelHarness:
        h = dph.TunnelHarness(self)
        h.unit_file.write_text("[Unit]\nWants=ssh.service\n", encoding="utf-8")
        (h.state / "loaded_deps").write_text(tunnel_deps, encoding="utf-8")
        for name, deps in units.items():
            (h.state / f"deps.{name}").write_text(deps, encoding="utf-8")
        return h

    def test_an_intermediate_unit_that_requires_ssh_is_refused(self) -> None:
        for prop in ("ssh.service\n\n\n\n", "\n\nsshd.service\n\n", "\n\n\nssh.socket\n", "\nsshd.socket\n\n\n"):
            h = self.harness("bridge.service system.slice\n\n\n\n", **{"bridge.service": prop})
            result = h.run(CALL, dph.LOOPBACK)
            self.assertNotEqual(0, result.returncode, f"{prop!r}: {result.stdout}")
            self.assertNotIn("APT-REACHED", result.stdout, repr(prop))
            self.assertIn("depends on bridge.service", result.stdout)

    def test_a_failed_read_of_a_dependency_refuses(self) -> None:
        h = self.harness("bridge.service\n\n\n\n")
        (h.state / "fail.bridge.service").write_text("", encoding="utf-8")
        result = h.run(CALL, dph.LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertNotIn("APT-REACHED", result.stdout)
        self.assertIn("Could not read the loaded dependencies of bridge.service", result.stdout)

    def test_ordinary_dependencies_including_the_root_mount_continue(self) -> None:
        h = self.harness(
            "system.slice -.mount sysinit.target\n\n\n\n",
            **{"sysinit.target": "\n\n\n\n", "-.mount": "system.slice\n\n\n\n"},
        )
        result = h.run(CALL, dph.LOOPBACK)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("APT-REACHED", result.stdout)

    def test_a_direct_dependency_is_still_refused_first(self) -> None:
        h = self.harness("ssh.service\n\n\n\n")
        result = h.run(CALL, dph.LOOPBACK)
        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertIn("still Requires=", result.stdout)

    def test_an_uncarried_run_reads_nothing(self) -> None:
        h = self.harness("bridge.service\n\n\n\n", **{"bridge.service": "ssh.service\n\n\n\n"})
        result = h.run(CALL, dph.DIRECT)
        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("APT-REACHED", result.stdout)
        self.assertNotIn("-p Requires", h.events_text())


if __name__ == "__main__":
    unittest.main()
