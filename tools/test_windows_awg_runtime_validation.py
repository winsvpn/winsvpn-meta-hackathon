import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "windows" / "runner" / "windows_tunnel_backend.cpp").read_text(
    encoding="utf-8"
)
MAIN_SOURCE = (ROOT / "windows" / "runner" / "main.cpp").read_text(
    encoding="utf-8"
)
SPLIT_SOURCE = (
    ROOT / "windows" / "runner" / "windows_split_tunnel.cpp"
).read_text(encoding="utf-8")
FLUTTER_SOURCE = (ROOT / "lib" / "main.dart").read_text(encoding="utf-8")
HANDSHAKE_MATRIX = (
    ROOT / "tools" / "windows_xray_awg_handshake_matrix.ps1"
).read_text(encoding="utf-8")
LOCAL_AWG_DIAGNOSTIC = (
    ROOT / "tools" / "windows_local_awg_diagnostic.ps1"
).read_text(encoding="utf-8")
CARRIER_PROBE = (
    ROOT / "tools" / "windows_xray_udp_carrier_probe.ps1"
).read_text(encoding="utf-8")
SERVICE_MAIN = (
    ROOT / "windows" / "runner" / "windows_tunnel_service_main.cpp"
).read_text(encoding="utf-8")
SERVICE_CORE = (
    ROOT / "windows" / "runner" / "windows_tunnel_service_core.h"
).read_text(encoding="utf-8")
SERVICE_CLIENT = (
    ROOT / "windows" / "runner" / "windows_tunnel_service_client.cpp"
).read_text(encoding="utf-8")
NON_ELEVATED_PROBE = (
    ROOT / "tools" / "windows_non_elevated_uapi_probe.ps1"
).read_text(encoding="utf-8")
ENGINE_SOURCE = (ROOT / "windows" / "awg_engine" / "main.go").read_text(
    encoding="utf-8"
)
ENGINE_BUILDER = (ROOT / "tools" / "build_windows_awg_engine.ps1").read_text(
    encoding="utf-8"
)
ENGINE_MODULE = (ROOT / "windows" / "awg_engine" / "go.mod").read_text(
    encoding="utf-8"
)
CLIENT_HELPER_BUILDER = (
    ROOT / "tools" / "build_windows_amneziawg_client.ps1"
).read_text(encoding="utf-8")
INSTALLER_BUILD = (
    ROOT / "installer" / "windows" / "build_installer.ps1"
).read_text(encoding="utf-8")
INNO_INSTALLER = (
    ROOT / "installer" / "windows" / "winsvpn.iss"
).read_text(encoding="utf-8")


class WindowsAwgRuntimeValidationTests(unittest.TestCase):
    def test_awg_builder_returns_without_terminating_installer_runspace(self) -> None:
        self.assertIn("& $AwgEngineBuilder", INSTALLER_BUILD)
        self.assertNotRegex(ENGINE_BUILDER, r"(?m)^\s*exit\s+0\s*$")
        self.assertIn("$global:LASTEXITCODE = 0", ENGINE_BUILDER)
        self.assertTrue(ENGINE_BUILDER.rstrip().endswith("return"))

    def test_windows_secure_text_bridge_is_dpapi_backed_and_allowlisted(self) -> None:
        for fragment in (
            'call.method_name() == "readSecureText"',
            'call.method_name() == "writeSecureText"',
            'call.method_name() == "deleteSecureText"',
            "CryptProtectData(",
            "CryptUnprotectData(",
            "CRYPTPROTECT_UI_FORBIDDEN",
            "IsAllowedSecureTextName(name)",
            '"client_keypair.json"',
            '"pending_logout.json"',
            '"user_pin.txt"',
            '"vpn_config.txt"',
            '"vpn_settings.txt"',
            '"wins_vpn_restart_config.conf"',
            'Utf8ToWide(name) + L".wvdp"',
        ):
            self.assertIn(fragment, SOURCE)
        self.assertIn("!IsAllowedSecureTextName(\"../vpn_config.txt\")", SOURCE)
        self.assertIn("!IsAllowedSecureTextName(\"VPN_CONFIG.TXT\")", SOURCE)

    def test_windows_secure_text_files_are_atomic_non_reparse_and_private(self) -> None:
        for fragment in (
            "CREATE_NEW",
            "MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH",
            "FILE_FLAG_OPEN_REPARSE_POINT",
            "FILE_FLAG_BACKUP_SEMANTICS",
            "GetFileInformationByHandleEx(file, FileAttributeTagInfo",
            "FILE_DISPOSITION_INFO_EX disposition",
            "SetFileInformationByHandle(file, FileDispositionInfoEx",
            "SetFileInformationByHandle(file, FileDispositionInfo",
            "PROTECTED_DACL_SECURITY_INFORMATION",
            "CurrentUserSystemDaclSddl",
            "HasStrictCurrentUserSystemDacl",
            "WipeAndDeleteRegularFile(legacy_path)",
            "Legacy secure text migration failed closed.",
        ):
            self.assertIn(fragment, SOURCE)
        self.assertNotIn("CREATE_ALWAYS", SOURCE)
        self.assertNotIn("WriteUtf8File", SOURCE)

    def test_verified_dpapi_reads_retire_legacy_plaintext_and_preserve_retry(self) -> None:
        reader = re.search(
            r"bool ReadWindowsSecureText\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(reader)
        body = reader.group(0)
        secure_branch = body[body.index("if (!secure_path.empty()") :]
        self.assertIn(
            "RetireLegacyPlaintextFile(legacy_path, plaintext, error)",
            secure_branch,
        )
        self.assertNotIn("DeleteFileW(secure_path.c_str())", body)
        self.assertIn(
            '"Legacy secure text cleanup failed closed; retry is required."',
            SOURCE,
        )

    def test_windows_secure_storage_has_executable_native_self_test(self) -> None:
        for fragment in (
            "RunWindowsSecureStorageSelfTest",
            "SecureStorageSelfTest",
            "corrupted.back() ^= 0x01",
            "legacy_lock",
            "!first_cleanup && migration_plaintext.empty()",
            "FileExists(path) &&",
            "FileExists(legacy_path)",
            "CreateSymbolicLinkW(tampered_link.c_str(), path.c_str()",
            "RemoveDirectoryW(directory.c_str())",
        ):
            self.assertIn(fragment, SOURCE)
        self.assertIn('"--secure-storage-self-test"', MAIN_SOURCE)

    def test_awg_and_xray_configs_are_unique_acl_protected_and_deleted(self) -> None:
        xray = re.search(
            r"bool StartXrayIfNeeded\(.*?\n\}", SOURCE, re.DOTALL
        )
        awg = re.search(
            r"bool InstallPrivilegedTunnel\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(xray)
        self.assertIsNotNone(awg)
        xray_body = xray.group(0)
        awg_body = awg.group(0)
        for fragment in (
            'UniqueConfigPath(directory, L"wins_xray_client", L".json")',
            "WriteBytesSecureAtomic(",
            "ScopedFileDelete delete_xray_config(config_path)",
            "EnsureDirectoryWithDacl(directory, runtime_sddl)",
            "CreateProcessW(xray_exe.c_str()",
        ):
            self.assertIn(fragment, xray_body)
        for fragment in (
            'UniqueConfigPath(directory, L"winsvpn", L".conf")',
            "WriteBytesSecureAtomic(",
            "EnsureDirectoryWithDacl(directory, kSystemAdminDirectorySddl)",
            "ApplyProtectedOwnerAndDacl(directory, kSystemAdminDirectorySddl)",
            "awg_config.size(), kSystemAdminFileSddl)",
            "ScopedFileDelete delete_awg_config(config_path)",
        ):
            self.assertIn(fragment, awg_body)
        self.assertNotIn('JoinPath(directory, L"winsvpn.conf")', awg_body)
        self.assertNotIn("HardenConfigDirectory", SOURCE)
        for name, expected in (
            ("kSystemAdminDirectorySddl", "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            ("kSystemAdminFileSddl", "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"),
        ):
            with self.subTest(sddl=name):
                declaration = re.search(
                    rf'constexpr wchar_t {name}\[\]\s*=\s*L"([^"]+)";', SOURCE
                )
                self.assertIsNotNone(declaration)
                self.assertEqual(declaration.group(1), expected)

    def test_runtime_query_uses_bounded_protected_uapi(self) -> None:
        self.assertIn("ReadAwgRuntimeUapi", SOURCE)
        self.assertIn(
            r"\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG", SOURCE
        )
        self.assertIn("GetTickCount64() + readiness_timeout_ms", SOURCE)
        self.assertIn(
            "kAwgUapiResponseTimeoutMilliseconds", SOURCE
        )
        self.assertIn("CancelIoEx(pipe, overlapped)", SOURCE)
        self.assertNotIn("FindAwgCliExecutable", SOURCE)
        self.assertNotIn("RunCommandCapture", SOURCE)

    def test_runtime_identity_peer_and_endpoint_are_strict(self) -> None:
        for fragment in (
            "runtime.private_key != expected_private",
            "runtime.peers[0].public_key != expected_peer",
            "runtime.peers[0].preshared_key != expected_psk",
            "!EndpointsMatch(runtime.peers[0].endpoint, expected_endpoint)",
            "loaded_service != configured_service",
            "loaded_addresses.empty() || configured_addresses.empty()",
        ):
            self.assertIn(fragment, SOURCE)

    def test_runtime_allowed_ips_are_parsed_and_exact(self) -> None:
        for fragment in (
            'key == "allowed_ip" && peer != nullptr',
            'ParseAllowedIpSet(SectionValue(peer_config, "allowedips")',
            "The Windows AWG runtime loaded no AllowedIPs for peer lookup.",
            "The Windows AWG runtime loaded different AllowedIPs.",
            "loaded_allowed != expected_allowed",
        ):
            self.assertIn(fragment, SOURCE)
        validation = re.search(
            r"bool ValidateLoadedAwgRuntime\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(validation)
        body = validation.group(0)
        self.assertIn("expected_allowed", body)
        self.assertIn("loaded_allowed.empty()", body)
        self.assertNotIn("+ loaded_allowed", body)
        self.assertNotIn("+ expected_allowed", body)
        self.assertIn("AWG AllowedIPs validation self-test failed.", SOURCE)
        self.assertIn("AWG protected UAPI AllowedIPs self-test failed.", SOURCE)

    def test_setconf_payload_excludes_wg_quick_only_fields(self) -> None:
        for fragment in (
            "BuildAwgSetconfConfig(raw_config)",
            'out << "[Interface]\\nPrivateKey = "',
            'out << "Endpoint = "',
            '<< "AllowedIPs = "',
            'setconf_self_test.find("Address =") != std::string::npos',
            'setconf_self_test.find("DNS =") != std::string::npos',
            'setconf_self_test.find("MTU =") != std::string::npos',
            'setconf_self_test.find("Table =") != std::string::npos',
        ):
            self.assertIn(fragment, SOURCE)

    def test_product_engine_interface_is_configured_before_routes(self) -> None:
        for fragment in (
            "ConfigureWinsAwgInterface(raw_config, error)",
            "ConvertInterfaceAliasToLuid(kTunnelName, &interface_luid)",
            "CreateUnicastIpAddressEntry(&address_row)",
            "SetIpInterfaceEntry(&interface_row)",
            "SetInterfaceDnsSettings(interface_guid, &dns_settings)",
        ):
            self.assertIn(fragment, SOURCE)
        configure = SOURCE.index("ConfigureWinsAwgInterface(raw_config, error)")
        routes = SOURCE.index("InstallWindowsTunnelRoutes(raw_config, error)")
        self.assertLess(configure, routes)

    def test_product_engine_always_owns_windows_routes(self) -> None:
        self.assertIn(
            'if (!manual_routes) {\n    *error = "The Win\'s VPN product engine '
            'requires owned Windows routes.";',
            SOURCE,
        )
        self.assertIn(
            "if (!InstallWindowsTunnelRoutes(raw_config, error))", SOURCE
        )
        self.assertNotIn(
            "if (manual_routes && !InstallWindowsTunnelRoutes", SOURCE
        )

    def test_direct_and_xray_endpoints_receive_dynamic_physical_routes(self) -> None:
        for fragment in (
            "const bool route_plan_valid =",
            "endpoint_bypass.Prefix.Ipv4 = resolved_destination.Ipv4;",
            "endpoint_bypass.PrefixLength = 32;",
            "best_physical = prepared_internet_route;",
            "RouteHasUsableGateway(prepared_internet_route, AF_INET)",
            "bypass_ipv4.push_back(endpoint_bypass);",
            "ResolveBestInterface(remote_host, &internet_index",
        ):
            self.assertIn(fragment, SPLIT_SOURCE)
        self.assertIn(
            "it never protects the outer UDP", SPLIT_SOURCE
        )

    def test_wfp_hresult_constants_are_normalized_to_dword_statuses(self) -> None:
        for fragment in (
            "constexpr DWORD kFwpProviderNotFoundStatus =",
            "static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND)",
            "constexpr DWORD kFwpSublayerNotFoundStatus =",
            "static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)",
            "constexpr DWORD kFwpInUseStatus = static_cast<DWORD>(FWP_E_IN_USE)",
            "deleted == kFwpInUseStatus",
        ):
            self.assertIn(fragment, SPLIT_SOURCE)
        self.assertNotRegex(SPLIT_SOURCE, r"(?:==|!=)\s*FWP_E_")

    def test_runtime_secret_material_is_wiped(self) -> None:
        self.assertIn("SecureZeroMemory(value->data(), value->size())", SOURCE)
        self.assertIn("ScopedStringWipe wipe_expected_private", SOURCE)
        self.assertIn("ScopedStringWipe wipe_expected_psk", SOURCE)
        self.assertIn("ScopedStringWipe wipe_response", SOURCE)

    def test_runtime_liveness_counters_are_strictly_parsed_and_relayed(self) -> None:
        for fragment in (
            'key == "last_handshake_time_sec" && peer != nullptr',
            'key == "rx_bytes" && peer != nullptr',
            'key == "tx_bytes" && peer != nullptr',
            "ParseUnsignedDecimalOnce",
            "std::numeric_limits<uint64_t>::max()",
            "PrivilegedWindowsTunnelRuntimeStatus",
            '"awg_query=1;awg_peer_count=1;awg_handshake="',
            '";awg_rx="',
            '";awg_tx="',
            '"awg_runtime_query_ok"',
            '"awg_handshake_recent"',
            '"awg_rx_bytes"',
            '"awg_tx_bytes"',
        ):
            self.assertIn(fragment, SOURCE)
        self.assertIn("PrivilegedWindowsTunnelRuntimeStatus", SERVICE_CORE)
        self.assertIn(
            'status += ";" + PrivilegedWindowsTunnelRuntimeStatus();',
            SERVICE_MAIN,
        )
        self.assertIn("*response_text_out = response_text", SERVICE_CLIENT)

    def test_runtime_status_relay_does_not_serialize_secrets(self) -> None:
        status_function = re.search(
            r"std::string PrivilegedWindowsTunnelRuntimeStatus\(\).*?\n\}",
            SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(status_function)
        body = status_function.group(0)
        for forbidden in (
            "private_key",
            "public_key",
            "preshared_key",
            "endpoint",
            "allowed_ips",
            "obfuscation",
        ):
            self.assertNotIn(forbidden, body)

    def test_all_awg_obfuscation_fields_are_checked(self) -> None:
        validation = re.search(
            r"bool ValidateLoadedAwgRuntime\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(validation)
        body = validation.group(0)
        for key in (
            "jc",
            "jmin",
            "jmax",
            "s1",
            "s2",
            "s3",
            "s4",
            "h1",
            "h2",
            "h3",
            "h4",
        ):
            self.assertRegex(body, rf'"{key}"')
        self.assertIn(
            'loaded == runtime.obfuscation.end() ? "0" : loaded->second', body
        )
        self.assertIn("loaded_value != expected", body)

    def test_failed_runtime_validation_removes_tunnel(self) -> None:
        validation_failure = re.search(
            r"if \(!ValidateLoadedAwgRuntime\(raw_config, winn_seam_endpoint, error\)\) "
            r"\{(?P<body>.*?)\n  \}",
            SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(validation_failure)
        validation_failure_body = validation_failure.group("body")
        self.assertIn(
            "if (winn_selected) return fail_winn(*error);",
            validation_failure_body,
        )
        self.assertRegex(
            validation_failure_body,
            r"FailClosedPrivilegedTunnel\(\);\s*return false;",
        )

        fail_winn_match = re.search(
            r"const auto fail_winn = .*?\{(?P<body>.*?)\n  \};",
            SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(fail_winn_match)
        fail_winn = fail_winn_match.group("body")
        self.assertIn("CloseWindowsWinnSeam(winn_seam)", fail_winn)
        self.assertLess(
            fail_winn.index("FailClosedPrivilegedTunnel()"),
            fail_winn.index("return false"),
        )

        cleanup_match = re.search(
            r"void FailClosedPrivilegedTunnel\(\) \{(?P<body>.*?)\n\}",
            SOURCE,
            re.DOTALL,
        )
        self.assertIsNotNone(cleanup_match)
        cleanup = cleanup_match.group("body")
        for required in (
            "g_tunnel_promoted.store(false",
            "RemoveWindowsTunnelRoutes()",
            "StopWindowsAppExclusions()",
            "StopWinsAwgEngine()",
        ):
            self.assertIn(required, cleanup)
        self.assertLess(
            cleanup.index("g_tunnel_promoted.store(false"),
            cleanup.index("StopWindowsAppExclusions()"),
        )
        self.assertLess(
            cleanup.index("StopWindowsAppExclusions()"),
            cleanup.index("RemoveWindowsTunnelRoutes()"),
        )
        self.assertLess(
            cleanup.index("RemoveWindowsTunnelRoutes()"),
            cleanup.index("StopWinsAwgEngine()"),
        )

    def test_product_engine_is_system_only_and_has_bounded_lifecycle(self) -> None:
        for fragment in (
            'windows.StringToSid("S-1-5-18")',
            "user.User.Sid.Equals(systemSID)",
            "len(os.Args) != 1 || !runningAsLocalSystem()",
            'stopEventName = `Global\\WinsVPN.AwgEngine.Stop.v1`',
            "SecurityDescriptorFromString(",
            "(A;;GA;;;SY)(A;;GA;;;BA)",
            'tun.WintunTunnelType = "WinsVPN"',
            "tun.CreateTUN(interfaceName, 1420)",
            "device.LogLevelSilent",
            "ipc.UAPIListen(interfaceName)",
            "awgDevice.Close()",
        ):
            self.assertIn(fragment, ENGINE_SOURCE)
        self.assertNotIn("fmt.", ENGINE_SOURCE)
        self.assertNotIn("flag.", ENGINE_SOURCE)

    def test_product_engine_is_exactly_pinned_and_reproducibly_built(self) -> None:
        for fragment in (
            "$engineVersion = 'v3.1.20260828'",
            "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'",
            "e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4",
            "fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719",
            "$goVersion = '1.27.1'",
            "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
            "checkout --detach --force $engineCommit",
            "rev-list -n 1 $engineVersion",
            "Get-PreparedEngineEntrypoint",
            "entrypoint_module_migration",
            "-trimpath -buildvcs=false '-ldflags=-s -w -buildid='",
            "non_system_exit_code = 2",
        ):
            self.assertIn(fragment, ENGINE_BUILDER)
        # H-5-class remediation: the pinned Go archive must be SHA-256
        # verified before its extracted go.exe is ever assigned to $portable
        # and trusted -- and neither $env:WINS_GO_EXE nor an ambient PATH
        # go.exe (the old spoofable-by-self-reported-version-string
        # shortcuts) may be trusted at all. See
        # test_windows_awg_go_toolchain_is_never_trusted_ambiently in
        # test_release_supply_chain_hardening.py for the dedicated,
        # more exhaustive regression coverage of this property.
        self.assertLess(
            ENGINE_BUILDER.index(
                "Test-Sha256 -Path $archive -Expected $goArchiveSha256"
            ),
            ENGINE_BUILDER.index(
                "$portable = Join-Path $toolchainRoot 'go\\bin\\go.exe'"
            ),
        )
        self.assertNotIn("Get-Command go.exe", ENGINE_BUILDER)
        self.assertNotIn("WINS_GO_EXE", ENGINE_BUILDER)
        self.assertIn(
            "Remove-Item -LiteralPath $portableRoot -Recurse -Force",
            ENGINE_BUILDER,
        )
        self.assertIn(
            "verified Go archive did not produce the pinned", ENGINE_BUILDER
        )
        for fragment in (
            "go 1.27.1",
            "toolchain go1.27.1",
            "github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828",
            "b5928efb6ca19f0153958460c3d141f04abc5c2e",
        ):
            self.assertIn(fragment, ENGINE_MODULE)

    def test_manager_owns_engine_and_uses_protected_uapi(self) -> None:
        for fragment in (
            "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
            "CREATE_NO_WINDOW | CREATE_SUSPENDED",
            "AssignProcessToJobObject(job, process.hProcess)",
            "OpenEventW(EVENT_MODIFY_STATE, FALSE, kAwgEngineStopEvent)",
            "TerminateJobObject(g_awg_engine_job, 1)",
            'L"winsvpn_awg_engine.exe"',
            'L"wintun.dll"',
            'L" setconf " + Quote(kTunnelName)',
            "kAwgUapiReadinessTimeoutMilliseconds",
            "StartWinsAwgEngine(config_path, error)",
        ):
            self.assertIn(fragment, SOURCE)
        install = re.search(
            r"bool InstallPrivilegedTunnel\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(install)
        self.assertNotIn("/installtunnelservice", install.group(0))

    def test_installer_packages_verified_engine_runtime(self) -> None:
        for fragment in (
            "$AwgEngineBuilder -Output $AwgEngineArtifact",
            "$awgEngineEvidence.engine_version -cne",
            "$AmneziaWgEngineVersion",
            "github.com/amnezia-vpn/amneziawg-go/v3",
            "$awgEngineEvidence.non_system_exit_code -ne 2",
            "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
            "ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a",
            "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
            "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
            "Assert-RebuiltAmneziaWgHelper",
            "unsigned_artifact_sha256",
            "Invoke-ProductSigning -Path $stagedAmneziaWg",
            '"/DAmneziaWgExeSha256=$stagedAmneziaWgSha256"',
        ):
            self.assertIn(fragment, INSTALLER_BUILD)
        for macro, payload in (
            ("AmneziaWgHelperFile", "amneziawg.exe"),
            ("AwgToolFile", "awg.exe"),
            ("WintunFile", "wintun.dll"),
        ):
            self.assertIn(f'#define {macro} "{payload}"', INNO_INSTALLER)
            self.assertIn(
                f'Source: "{{#DependenciesDir}}\\{{#{macro}}}"; DestDir: "{{app}}"',
                INNO_INSTALLER,
            )
        self.assertNotIn(
            'L"AmneziaWG\\\\amneziawg.exe"',
            SOURCE,
        )

    def test_maintenance_helper_builder_is_source_and_toolchain_pinned(self) -> None:
        for fragment in (
            "$sourceVersion = '3.1.0'",
            "$sourceCommit = 'ca5dd3b983bd19c335ab095ccd21fc2f804ec968'",
            "'ad578b6a2107ae4c1bab214c8057e89608ac516d6e381675c3d9441ccc4da70a'",
            "'268286d6183ec93c39e5295e73e660d9920481c66ecff8331ab64fa082230723'",
            "'c501fd947d08a4bfdb29f65a9f06ced004779be7a90a125f703c1c5a5130350b'",
            "'79bd946166bc6e87d4ff1602889557590703fc8a64737fbfe7f0b64ebda431d7'",
            "'a5ad25797aadc29f0e7aa0bf91e6197ce57c48cb845194a18ae7c2dbbebadcbd'",
            "$windowsLibraryVersion = 'v3.1.20260814'",
            "$windowsLibraryCommit = 'e90531d15802cb976773f3b63443bc281f738ca3'",
            "$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'",
            "$engineVersion = 'v3.1.20260828'",
            "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$goVersion = '1.27.1'",
            "'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'",
            "GOTOOLCHAIN = 'local'",
            "GOENV = 'off'",
            "GOWORK = 'off'",
            "GOFLAGS = '-mod=readonly -buildvcs=false'",
            "GOSUMDB = 'sum.golang.org'",
            "GOMODCACHE = $goModuleCache",
            "GOTMPDIR = $goTemporary",
            "GOAMD64 = 'v1'",
            "CGO_CFLAGS = ''",
            "SigningProvider = ''",
            "Assert-TargetPe -Path $builtExe",
            "pending_release_signing",
            "release_signing_required = $true",
            "$upstreamMsiVersion = '3.1.0'",
            "a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b",
            "272badace73caeb26dc42656f318b3eb7f10028c2f76faad1f52d6fe1e0ced12",
            "ba446f6e1a4093e43a65d6ff45f4b8c7b6485dc419327eedaa1a218549740e3a",
            "Get-OfficialAwg31PayloadCandidates",
            "Publish-AwgGenerationTransaction",
            "canonical_unsigned_product_maintenance_helper",
            "official_upstream_signed_gui_helper_not_published",
        ):
            self.assertIn(fragment, CLIENT_HELPER_BUILDER)
        self.assertNotIn("(Get-Command go.exe", CLIENT_HELPER_BUILDER)

    def test_runtime_errors_do_not_embed_key_material(self) -> None:
        validation = re.search(
            r"bool ValidateLoadedAwgRuntime\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(validation)
        body = validation.group(0)
        self.assertNotIn("+ runtime", body)
        self.assertNotIn("+ expected_", body)

    def test_xray_fallback_keeps_native_udp_over_tcp_contract(self) -> None:
        builder = re.search(
            r"std::string BuildXrayConfig\(.*?\n\}", SOURCE, re.DOTALL
        )
        self.assertIsNotNone(builder)
        body = builder.group(0)
        for fragment in (
            r'\"protocol\":\"tunnel\"',
            r'\"enabled\":false',
            r'\"concurrency\":0',
            r'\"xudpConcurrency\":0',
            r'\"xudpProxyUDP443\":\"skip\"',
        ):
            self.assertIn(fragment, body)
        self.assertIn('<< "\\\",\\\"headers\\\":{\\\"Host\\\":\\\""', body)
        self.assertNotIn(r'\"heartbeatPeriod\":15', body)
        self.assertNotIn(r'\"domainStrategy\":\"IPIfNonMatch\"', body)

    def test_xray_uses_pinned_physical_routes_not_process_exclusion(self) -> None:
        self.assertNotIn("excluded_apps.push_back(xray_exe)", SOURCE)
        self.assertIn(
            "..['windows_transport_bypass_ipv4'] = boundedAddresses",
            FLUTTER_SOURCE,
        )
        self.assertIn("..['host'] = boundedAddresses.first", FLUTTER_SOURCE)
        self.assertIn("Ipv4PrefixContains(", SPLIT_SOURCE)
        self.assertIn(
            "The physical carrier address is not excluded from the tunnel routes.",
            SPLIT_SOURCE,
        )
        self.assertIn(
            "Destination-based split tunneling owns only explicit physical bypass",
            SPLIT_SOURCE,
        )
        self.assertIn("Windows per-app split tunneling is unsupported", SPLIT_SOURCE)
        self.assertIn("route.physical_bypass", SPLIT_SOURCE)

    def test_bounded_xray_awg_handshake_matrix_is_nonpublishable_and_cleans_up(
        self,
    ) -> None:
        for marker in (
            "[ValidateSet('Single', 'Double')]",
            "$seen.Contains('80/none')",
            "$seen.Contains('443/tls')",
            "name = \"$($target.name)-tcp$($route.port)-$($route.security)\"",
            "production_parity_mux_disabled = $true",
            "direct_udp_unavailable_by_construction = $true",
            "local_awg_packet_engine_required = $true",
        ):
            self.assertIn(marker, HANDSHAKE_MATRIX)
        self.assertIn("AllowedIPs = 192.0.2.1/32", HANDSHAKE_MATRIX)
        self.assertIn("secret_material_redacted = $true", HANDSHAKE_MATRIX)
        self.assertIn("publication_authorized = $false", HANDSHAKE_MATRIX)
        self.assertIn("public_release_gate_eligible = $false", HANDSHAKE_MATRIX)
        self.assertIn("/uninstalltunnelservice", HANDSHAKE_MATRIX)
        self.assertIn("Remove-Item -LiteralPath $resolvedPrivate", HANDSHAKE_MATRIX)
        self.assertNotIn("client_private_key =", HANDSHAKE_MATRIX)
        self.assertNotIn("preshared_key =", HANDSHAKE_MATRIX)

    def test_local_xray_fallback_diagnostic_is_exact_ephemeral_and_redacted(
        self,
    ) -> None:
        for fragment in (
            "[switch]$ForceXrayFallback",
            "Get-DirectEndpointAddress",
            "-PolicyStore ActiveStore",
            "-Protocol UDP -RemoteAddress $directEndpointAddress",
            "-RemotePort 9110",
            "forcing_rule_removed = $forcingRuleRemoved",
            "xray_handshake_current",
            "direct_handshake_current",
            "secret_material_redacted = $true",
            "publication_authorized = $false",
            "public_release_gate_eligible = $false",
        ):
            self.assertIn(fragment, LOCAL_AWG_DIAGNOSTIC)
        self.assertNotIn("direct_endpoint_address =", LOCAL_AWG_DIAGNOSTIC)
        self.assertNotIn("server_endpoint =", LOCAL_AWG_DIAGNOSTIC)

    def test_xray_udp_echo_binds_explicit_loopback_digest(self) -> None:
        self.assertIn("WINS_PROBE_ECHO_BIND", CARRIER_PROBE)
        self.assertIn("'loopback'", CARRIER_PROBE)
        self.assertIn("WINS_PROBE_GATEWAY_DIGEST", CARRIER_PROBE)
        self.assertIn("Get-StringSha256 '127.0.0.1'", CARRIER_PROBE)
        self.assertIn(
            "payload_forwarded_to_production_awg_listener", CARRIER_PROBE
        )
        self.assertIn(
            "round_trip_echo_supported_by_production_redirect = $false",
            CARRIER_PROBE,
        )
        self.assertIn(
            "xray_redirects_all_vless_udp_to_awg9110", CARRIER_PROBE
        )

    def test_non_elevated_probe_is_redacted_nonpublishable_and_cleans_up(self) -> None:
        for fragment in (
            "ProtectedPrefix\\Administrators\\AmneziaWG\\winsvpn",
            "secret_material_redacted = $true",
            "publication_authorized = $false",
            "pipe_failure_types",
            "on_link_default_route_samples",
            "maximum_adapter_received_bytes",
            "maximum_adapter_sent_bytes",
            "direct_service_samples",
            "xray_service_samples",
            "maximum_direct_adapter_sent_bytes",
            "maximum_xray_adapter_sent_bytes",
            "cleanup_attempted",
            "cleanup_invoked",
            "-Action $action",
        ):
            self.assertIn(fragment, NON_ELEVATED_PROBE)
        for forbidden in (
            "private_key =",
            "public_key =",
            "preshared_key =",
            "endpoint =",
            "allowed_ip =",
            "$raw = $result",
        ):
            self.assertNotIn(forbidden, NON_ELEVATED_PROBE)


if __name__ == "__main__":
    unittest.main()
