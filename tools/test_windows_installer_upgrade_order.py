import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INNO = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")
SERVICE = (ROOT / "windows/runner/windows_tunnel_service_main.cpp").read_text(
    encoding="utf-8"
)


def section(start: str, end: str) -> str:
    begin = INNO.index(start)
    return INNO[begin : INNO.index(end, begin)]


def source_section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin)]


class WindowsInstallerUpgradeOrderTests(unittest.TestCase):
    def test_service_deletion_retry_is_bounded_and_only_retries_1072(self) -> None:
        timeout_match = re.search(
            r"kServiceDeletionRetryTimeoutMilliseconds\s*=\s*(\d+);", SERVICE
        )
        interval_match = re.search(
            r"kServiceDeletionRetryIntervalMilliseconds\s*=\s*(\d+);", SERVICE
        )
        self.assertIsNotNone(timeout_match)
        self.assertIsNotNone(interval_match)
        timeout_ms = int(timeout_match.group(1))
        interval_ms = int(interval_match.group(1))
        self.assertGreaterEqual(timeout_ms, 5_000)
        self.assertLessEqual(timeout_ms, 60_000)
        self.assertGreater(interval_ms, 0)
        self.assertLessEqual(interval_ms, 1_000)
        self.assertGreater(timeout_ms, interval_ms)

        helper = source_section(
            SERVICE, "SC_HANDLE CreateTunnelManagerService", "int InstallService()"
        )
        self.assertIn("*create_error = GetLastError();", helper)
        self.assertIn(
            "if (*create_error != ERROR_SERVICE_MARKED_FOR_DELETE)", helper
        )
        self.assertIn("const ULONGLONG deadline =", helper)
        self.assertIn("if (now >= deadline)", helper)
        self.assertIn("std::min<ULONGLONG>", helper)
        self.assertEqual(helper.count("CreateServiceW("), 1)

    def test_retry_preserves_existing_install_exit_and_rollback_contract(self) -> None:
        install = source_section(
            SERVICE, "int InstallService()", "int UninstallService()"
        )
        self.assertIn(
            "CreateTunnelManagerService(manager, binary_path, &create_error)", install
        )
        self.assertIn(
            "if (service == nullptr && create_error == ERROR_SERVICE_EXISTS)",
            install,
        )
        exhausted = (
            "if (service == nullptr) {\n"
            "    CloseServiceHandle(manager);\n"
            "    return 5;\n"
            "  }"
        )
        self.assertIn(exhausted, install)
        self.assertNotIn("return ERROR_SERVICE_MARKED_FOR_DELETE", install)

        uninstall = SERVICE[SERVICE.index("int UninstallService()") :]
        self.assertLess(
            uninstall.index("DeleteService(service)"),
            uninstall.index("ERROR_SERVICE_MARKED_FOR_DELETE"),
        )
        restore = section(
            "function RestorePreviousTunnelManager",
            "function RemovePreviousTunnelManagerForUpgrade",
        )
        postinstall = section(
            "procedure CurStepChanged(CurStep: TSetupStep);",
            "procedure CurUninstallStepChanged",
        )
        self.assertIn("'--install'", restore)
        self.assertIn("'--install'", postinstall)

    def test_staged_service_is_embedded_for_pretransition_readiness(self) -> None:
        files = section("[Files]", "[Icons]")
        staged = (
            'Source: "{#SourceDir}\\{#TunnelServiceExeName}"; '
            "Flags: dontcopy noencryption"
        )
        self.assertIn(staged, files)
        self.assertLess(files.index(staged), files.index('Source: "{#SourceDir}\\*"'))

    def test_prerequisites_and_new_payload_are_proven_before_old_service_removal(
        self,
    ) -> None:
        prepare = section(
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        ordered = (
            "ExtractVerifiedEmbeddedPrerequisite(",
            "VerifyEmbeddedPrerequisiteIdentity(",
            "Installing Microsoft Visual C++ Runtime",
            "Installing AmneziaWG Windows tunnel engine",
            "AmneziaWgRuntimeInstalled",
            "Validating the new protected tunnel manager",
            "ValidateStagedTunnelManager(Result)",
            "RemovePreviousTunnelManagerForUpgrade(Result)",
        )
        positions = [prepare.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("'--uninstall'", prepare)

    def test_exact_shared_runtime_skips_msi_but_still_verifies(self) -> None:
        prepare = section(
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        gate = prepare.index("if not AmneziaWgRuntimeInstalled then")
        msi_exec = prepare.index("'/i \"' + AmneziaMsiPath +")
        postcheck = prepare.index("if not AmneziaWgRuntimeInstalled then", gate + 1)
        self.assertLess(gate, msi_exec)
        self.assertLess(msi_exec, postcheck)
        self.assertIn("if ResultCode = 3010 then", prepare[gate:postcheck])
        self.assertLess(
            postcheck,
            prepare.index("ValidateStagedTunnelManager(Result)"),
        )

    def test_active_packet_engine_blocks_prerequisite_mutation(self) -> None:
        probe = section(
            "function WinsVpnPacketEngineIsRunning: Boolean;",
            "function ExtractFreshEmbeddedFile",
        )
        self.assertIn("winsvpn_awg_engine.exe", probe)
        self.assertIn("except\n    Result := True;", probe)
        prepare = section(
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        engine_check = prepare.index("if WinsVpnPacketEngineIsRunning then")
        vc_mutation = prepare.index("Installing Microsoft Visual C++ Runtime")
        awg_mutation = prepare.index("Installing AmneziaWG Windows tunnel engine")
        self.assertLess(engine_check, vc_mutation)
        self.assertLess(engine_check, awg_mutation)

    def test_previous_service_transition_has_exact_recoverable_backup(self) -> None:
        remove = section(
            "function RemovePreviousTunnelManagerForUpgrade",
            "function PrepareToInstall",
        )
        for marker in (
            "PreviousTunnelManagerSha256 := GetSHA256OfFile(ExistingService)",
            "FileCopy(ExistingService, PreviousTunnelManagerBackup, False)",
            "PreviousTunnelManagerNeedsRestore := True",
            "RestorePreviousTunnelManager",
        ):
            self.assertIn(marker, remove)
        self.assertLess(
            remove.index("FileCopy(ExistingService, PreviousTunnelManagerBackup"),
            remove.index("'--uninstall'"),
        )

    def test_all_posttransition_failures_restore_the_previous_manager(self) -> None:
        restore = section(
            "function RestorePreviousTunnelManager",
            "function RemovePreviousTunnelManagerForUpgrade",
        )
        self.assertIn("FileCopy(PreviousTunnelManagerBackup, ExistingService, False)", restore)
        self.assertIn("'--install'", restore)
        postinstall = section(
            "procedure CurStepChanged(CurStep: TSetupStep);",
            "procedure CurUninstallStepChanged",
        )
        self.assertIn("if RestorePreviousTunnelManager then", postinstall)
        self.assertIn("StagedTunnelManagerSha256", postinstall)
        self.assertIn("GetSHA256OfFile(ExpandConstant('{app}\\{#TunnelServiceExeName}'))", postinstall)
        self.assertIn("PreviousTunnelManagerNeedsRestore := False", postinstall)
        deinitialize = section(
            "procedure DeinitializeSetup;", "procedure CurUninstallStepChanged"
        )
        self.assertIn("PreviousTunnelManagerNeedsRestore", deinitialize)
        self.assertIn("not RestorePreviousTunnelManager", deinitialize)

    def test_silent_rollback_failure_never_opens_a_raw_modal_dialog(self) -> None:
        deinitialize = section(
            "procedure DeinitializeSetup;", "procedure CurUninstallStepChanged"
        )
        self.assertIn("SuppressibleMsgBox(", deinitialize)
        self.assertNotIn("\n    MsgBox(", deinitialize)
        self.assertIn("FatalPostInstallFailure := True;", deinitialize)

    def test_postinstall_failure_forces_deterministic_nonzero_exit(self) -> None:
        self.assertIn("FatalPostInstallExitCode = 1603;", INNO)
        helper = section(
            "procedure RaiseFatalPostInstallException",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        self.assertIn("FatalPostInstallFailure := True;", helper)
        self.assertIn("RaiseException(MessageText);", helper)
        postinstall = section(
            "procedure CurStepChanged(CurStep: TSetupStep);",
            "function GetCustomSetupExitCode: Integer;",
        )
        self.assertLess(
            postinstall.index("FatalPostInstallFailure := True;"),
            postinstall.index("ResultCode := -1;"),
        )
        self.assertEqual(postinstall.count("RaiseFatalPostInstallException("), 6)
        self.assertNotIn("RaiseException(", postinstall)
        self.assertLess(
            postinstall.index("PreviousTunnelManagerNeedsRestore := False;"),
            postinstall.rindex("FatalPostInstallFailure := False;"),
        )
        self.assertLess(
            postinstall.index("not DeleteFile(PreviousTunnelManagerBackup)"),
            postinstall.rindex("FatalPostInstallFailure := False;"),
        )
        custom_exit = section(
            "function GetCustomSetupExitCode: Integer;",
            "procedure DeinitializeSetup;",
        )
        self.assertIn("if FatalPostInstallFailure then", custom_exit)
        self.assertIn("Result := FatalPostInstallExitCode", custom_exit)
        self.assertIn("else\n    Result := 0;", custom_exit)

    def test_prerequisite_restart_is_committed_only_after_upgrade_preparation(self) -> None:
        prepare = section(
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "procedure CurStepChanged(CurStep: TSetupStep);",
        )
        self.assertIn("RestartPending := False;", prepare)
        self.assertEqual(prepare.count("RestartPending := True;"), 2)
        self.assertEqual(prepare.count("NeedsRestart := RestartPending;"), 1)
        self.assertLess(
            prepare.index("RemovePreviousTunnelManagerForUpgrade(Result)"),
            prepare.index("NeedsRestart := RestartPending;"),
        )

    def test_installed_amnezia_runtime_is_exactly_hash_bound(self) -> None:
        runtime = section(
            "function AmneziaWgRuntimeInstalled: Boolean;",
            "function ExtractFreshEmbeddedFile",
        )
        for name in (
            "UpstreamAmneziaWgExeSha256",
            "AwgToolExeSha256",
            "WintunDllSha256",
        ):
            self.assertIn(name, runtime)
        post_install = section(
            "procedure CurStepChanged(CurStep: TSetupStep);",
            "procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);",
        )
        self.assertIn("'{#AmneziaWgExeSha256}'", post_install)
        self.assertIn(
            "Go 1.27.1, Authenticode-signed payload",
            post_install,
        )

    def test_embedded_prerequisite_retry_rejects_stale_or_invalid_temp_files(self) -> None:
        extract = section("function ExtractFreshEmbeddedFile", "function ValidateStagedTunnelManager")
        self.assertLess(extract.index("DeleteFile(ExtractedPath)"), extract.index("ExtractTemporaryFile"))
        self.assertIn("GetSHA256OfFile(ExtractedPath)", extract)
        self.assertIn("Length(ExtractedSha256) <> 64", extract)
        self.assertIn("DeleteFile(ExtractedPath);", extract)
        self.assertIn("CompareText(ExtractedSha256, ExpectedSha256)", extract)
        self.assertIn("FileSize(ExtractedPath, ExtractedBytes) or (ExtractedBytes <> ExpectedBytes)", extract)
        self.assertLess(
            INNO.index("CompareText(ExtractedSha256, ExpectedSha256)"),
            INNO.index("function VerifyEmbeddedPrerequisiteIdentity("),
        )

    def test_uninstall_retains_nonexclusive_shared_prerequisites(self) -> None:
        uninstall = INNO[INNO.index("procedure CurUninstallStepChanged") :]
        self.assertIn(
            "Retaining shared prerequisites: Microsoft VC runtime and AmneziaWG MSI.",
            uninstall,
        )
        self.assertIn("does not claim exclusive ownership", uninstall)
        self.assertNotIn("/x ", uninstall.lower())


if __name__ == "__main__":
    unittest.main()
