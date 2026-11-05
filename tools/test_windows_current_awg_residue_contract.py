#!/usr/bin/env python3
"""Current Windows gates must fail closed on native AWG-engine residue."""

from __future__ import annotations

import pathlib
import unittest


TOOLS = pathlib.Path(__file__).resolve().parent


class WindowsCurrentAwgResidueContractTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (TOOLS / name).read_text(encoding="utf-8")

    def test_rollback_smoke_requires_positive_clean_state_proofs(self) -> None:
        text = self.read("windows_rollback_reinstall_smoke.ps1")
        for marker in (
            "schema = 'winsvpn.windows.rollback-reinstall-smoke.v2'",
            "$adapterAbsentOrDown = $tunnelAdapters.Count -eq 0",
            "$routesAbsent = $tunnelRoutes.Count -eq 0",
            "$awgEngineAbsent = $awgEngines.Count -eq 0",
            "$xrayAbsent = $xrayProcesses.Count -eq 0",
            "-not $adapterAbsentOrDown -or -not $routesAbsent",
            "-not $awgEngineAbsent -or -not $xrayAbsent",
            "$result = if ($testError) { 'fail' } else { 'pass' }",
            "tunnel_adapter_absent_or_down = $adapterAbsentOrDown",
            "tunnel_routes_absent = $routesAbsent",
        ):
            self.assertIn(marker, text)
        self.assertNotIn("tunnel_adapter_up =", text)
        self.assertNotIn("tunnel_route_present =", text)
        self.assertLess(
            text.index("-not $adapterAbsentOrDown -or -not $routesAbsent"),
            text.index("$result = if ($testError)"),
        )

    def test_rollback_recovery_validates_the_complete_installed_payload(self) -> None:
        text = self.read("windows_rollback_reinstall_smoke.ps1")
        for marker in (
            "InstalledPayload = @($installedPayload)",
            "foreach ($payload in @($Candidate.InstalledPayload))",
            "installed payload does not match its manifest",
            "installed_payload_file_count = @($Candidate.InstalledPayload).Count",
            "Assert-InstalledCandidate -Candidate $current -Stage 'Recovery check'",
        ):
            self.assertIn(marker, text)
        self.assertNotIn("$installedGui = Join-Path", text)
        recovery_check = text.index(
            "Assert-InstalledCandidate -Candidate $current -Stage 'Recovery check'"
        )
        reinstall = text.index("if (-not $currentPresent)", recovery_check)
        self.assertLess(recovery_check, reinstall)

    def test_prefreeze_watchdog_counts_awg_engine_in_zero_residue(self) -> None:
        text = self.read("windows_prefreeze_exact_watchdog.ps1")
        self.assertIn("Get-Process winsvpn_awg_engine", text)
        self.assertIn("awg_engine_process_count = $awgEngine.Count", text)
        self.assertIn("$awgEngine.Count -eq 0 -and", text)
        self.assertIn("awg_engine_absence_is_expected_zero = $true", text)
        self.assertIn("final_awg_engine_process_count", text)

    def test_prefreeze_case_and_binding_count_awg_engine(self) -> None:
        case = self.read("windows_prefreeze_exact_matrix_case.ps1")
        binding = self.read("windows_prefreeze_bind_exact_case.ps1")
        self.assertIn("Get-Process winsvpn_awg_engine", case)
        self.assertIn("awg_engine_process_count = $awgEngine.Count", case)
        self.assertIn("$awgEngine.Count -eq 0 -and", case)
        self.assertIn("final_awg_engine_process_count", case)
        self.assertIn(
            "@(Get-Process winsvpn_awg_engine -ErrorAction SilentlyContinue).Count +",
            binding,
        )

    def test_system_recovery_proof_counts_awg_engine(self) -> None:
        text = self.read("windows_prefreeze_system_recovery_proof.ps1")
        self.assertIn("Get-Process winsvpn_awg_engine", text)
        self.assertIn("$awgEngine.Count -eq 0", text)
        self.assertIn("awg_engine_process_count = $awgEngine.Count", text)


if __name__ == "__main__":
    unittest.main()
