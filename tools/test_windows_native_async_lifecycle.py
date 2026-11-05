import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "windows" / "runner"
BACKEND = (RUNNER / "windows_tunnel_backend.cpp").read_text(encoding="utf-8")
CLIENT = (RUNNER / "windows_tunnel_service_client.cpp").read_text(encoding="utf-8")
SERVICE = (RUNNER / "windows_tunnel_service_main.cpp").read_text(encoding="utf-8")
PROTOCOL = (RUNNER / "windows_tunnel_service_protocol.h").read_text(encoding="utf-8")
CMAKE = (RUNNER / "CMakeLists.txt").read_text(encoding="utf-8")


def handler(method: str, next_method: str) -> str:
    start = BACKEND.index(f'if (call.method_name() == "{method}"')
    end = BACKEND.index(f'if (call.method_name() == "{next_method}"', start)
    return BACKEND[start:end]


class WindowsNativeAsyncLifecycleTest(unittest.TestCase):
    def test_start_and_stop_never_run_on_flutter_platform_thread(self) -> None:
        start = handler("startTunnel", "showAnnouncementNotification")
        stop = handler("stopTunnel", "startTunnel")
        self.assertIn("std::thread([config, transition_generation", start)
        self.assertIn("InstallTunnel(config, transition_generation", start)
        self.assertIn("std::thread([async_result, valid_generation]", stop)
        self.assertIn("UninstallTunnel(&error)", stop)
        self.assertIn("g_start_in_flight.compare_exchange_strong", start)
        self.assertIn("g_stop_in_flight.compare_exchange_strong", stop)

    def test_blocking_status_and_probe_calls_are_async(self) -> None:
        self.assertIn("void CompleteEncodableMethodAsync(", BACKEND)
        for method, next_method in (
            ("getTunnelState", "getTunnelActivity"),
            ("getTunnelActivity", "getTunnelActivitySnapshot"),
            ("getTunnelActivitySnapshot", "getTunnelReadiness"),
            ("probeVpnInternet", "getInstalledApps"),
        ):
            self.assertIn(
                "CompleteEncodableMethodAsync", handler(method, next_method), method
            )

    def test_stop_can_cancel_an_inflight_privileged_start(self) -> None:
        self.assertIn("ArmWindowsTunnelStartCancellation(", CLIENT)
        self.assertIn("SignalWindowsTunnelStartCancellation()", CLIENT)
        self.assertIn("DisarmWindowsTunnelStartCancellation()", CLIENT)
        stop = handler("stopTunnel", "startTunnel")
        self.assertLess(
            stop.index("SignalWindowsTunnelStartCancellation();"),
            stop.index("std::thread([async_result, valid_generation]"),
        )
        self.assertIn("OpenEventW(SYNCHRONIZE", SERVICE)
        self.assertIn("WaitForMultipleObjects(", SERVICE)
        self.assertIn("client_process", SERVICE)
        self.assertIn("kStartCancellationEventPrefix", PROTOCOL)
        self.assertIn("std::mutex g_transition_commit_mutex", BACKEND)
        install_start = BACKEND.index("bool InstallTunnel(")
        install_end = BACKEND.index("bool UninstallTunnel(", install_start)
        install = BACKEND[install_start:install_end]
        self.assertIn("std::lock_guard<std::mutex> lock(g_transition_commit_mutex)", install)
        self.assertIn("!g_stop_in_flight.load", install)
        self.assertIn("std::numeric_limits<int64_t>::max()", BACKEND)

    def test_every_service_stop_origin_uses_one_hard_watchdog(self) -> None:
        self.assertIn("kStopOverallWatchdogMilliseconds = 20000", PROTOCOL)
        self.assertIn("bool StopPrivilegedWindowsTunnelBounded(", SERVICE)
        self.assertGreaterEqual(
            SERVICE.count("StopPrivilegedWindowsTunnelBounded("), 4
        )
        self.assertIn("FlushPipeBounded(pipe);", SERVICE)
        self.assertIn("CancelSynchronousIo(thread);", SERVICE)
        self.assertIn("kResponseFlushCancelDrainMilliseconds", SERVICE)
        flush_start = SERVICE.index("void FlushPipeBounded(")
        flush_end = SERVICE.index("void StopTunnelAfterCarrierExit(", flush_start)
        flush = SERVICE[flush_start:flush_end]
        self.assertNotIn("INFINITE", flush)
        self.assertIn("TerminateServiceFailClosed(", flush)

    def test_scm_stop_interrupts_inflight_start(self) -> None:
        start = SERVICE.index("std::thread start_watchdog(")
        end = SERVICE.index("const auto finish_start_watchdog", start)
        watchdog = SERVICE[start:end]
        self.assertIn("client_process, g_stop_event", watchdog)
        self.assertIn("WaitForMultipleObjects(", watchdog)
        self.assertIn("TerminateServiceFailClosed(ERROR_TIMEOUT)", watchdog)

    def test_readiness_and_probe_obey_one_native_deadline(self) -> None:
        readiness_start = BACKEND.index("flutter::EncodableValue TunnelReadinessValue()")
        probe_start = BACKEND.index("flutter::EncodableValue ProbeInternetValue()")
        readiness = BACKEND[readiness_start:probe_start]
        readiness_body_end = BACKEND.index(
            "flutter::EncodableMap Winn3ProofEncodableMap(", readiness_start
        )
        readiness_body = BACKEND[readiness_start:readiness_body_end]
        probe_end = BACKEND.index("#endif", probe_start)
        probe = BACKEND[probe_start:probe_end]
        self.assertEqual(readiness_body.count("QueryWindowsTunnelManager("), 1)
        self.assertNotIn("IsTunnelRunning()", readiness)
        self.assertIn("ProbeTunnelBoundInternet()", probe)
        self.assertNotIn("IsTunnelRunning()", probe)
        self.assertIn("g_committed_generation.load", probe)
        native_probe_start = BACKEND.index("bool TunnelInterfaceIpv4(")
        native_probe = BACKEND[native_probe_start:probe_start]
        self.assertIn("ClassifyWindowsTunnelProbeAlias(", native_probe)
        self.assertIn("WindowsTunnelProbeAliasName(alias)", native_probe)
        self.assertIn("ConvertInterfaceAliasToLuid(alias_wide.c_str()", native_probe)
        self.assertNotIn('ConvertInterfaceAliasToLuid(L"winsvpn"', native_probe)
        self.assertIn("bind(socket_handle", native_probe)
        self.assertIn("IP_UNICAST_IF", native_probe)
        self.assertIn("select(0, nullptr", native_probe)
        self.assertIn("kProbeBudgetMilliseconds = 7000", native_probe)
        self.assertIn("GET /cdn-cgi/trace HTTP/1.1", native_probe)
        self.assertIn('lower.rfind("http/1.1 200 ", 0)', native_probe)
        self.assertIn('lower.find("\\nh=cloudflare.com")', native_probe)
        self.assertIn('{"1.1.1.1", "1.0.0.1"}', native_probe)
        self.assertNotIn("RunCommand(", native_probe)
        run_start = BACKEND.index("ProcessResult RunCommand(")
        run_end = BACKEND.index(
            "TunnelServiceStatus QueryTunnelServiceStatus", run_start
        )
        run_command = BACKEND[run_start:run_end]
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", run_command)
        self.assertIn("TerminateJobObject(job", run_command)
        self.assertIn("TerminateProcess(process.hProcess", run_command)
        self.assertNotIn("INFINITE", run_command)

    def test_window_shutdown_quiesces_detached_native_workers(self) -> None:
        flutter_window = (RUNNER / "flutter_window.cpp").read_text(encoding="utf-8")
        self.assertIn("void ShutdownWindowsTunnelBackend()", BACKEND)
        self.assertIn("g_async_worker_cv.wait_for(", BACKEND)
        self.assertIn("SignalWindowsTunnelStartCancellation();", BACKEND)
        self.assertIn("AdvanceWindowsCanceledGenerationFloor(", BACKEND)
        self.assertIn("std::numeric_limits<int64_t>::max()", BACKEND)
        self.assertIn("ScopedAsyncWorker<Result>", BACKEND)
        self.assertIn("ShutdownWindowsTunnelBackend();", flutter_window)

    def test_power_request_survives_worker_thread_exit(self) -> None:
        self.assertIn("PowerCreateRequest(&reason)", BACKEND)
        self.assertIn("PowerSetRequest(request, PowerRequestSystemRequired)", BACKEND)
        self.assertIn("PowerClearRequest(g_power_request", BACKEND)
        self.assertNotIn("SetThreadExecutionState(", BACKEND)
        self.assertIn('"powrprof.lib"', CMAKE)

    def test_shared_backend_dead_code_warning_is_target_scoped(self) -> None:
        self.assertIn(
            "target_compile_options(${BINARY_NAME} PRIVATE /wd4505)", CMAKE
        )
        self.assertIn(
            "target_compile_options(wins_vpn_tunnel_service PRIVATE /wd4505)",
            CMAKE,
        )
        self.assertEqual(CMAKE.count("PRIVATE /wd4505"), 2)
        self.assertNotIn("/wd4018", CMAKE)

    def test_scm_recovery_configuration_fails_closed(self) -> None:
        for setting in (
            "SERVICE_CONFIG_DESCRIPTION",
            "SERVICE_CONFIG_DELAYED_AUTO_START_INFO",
            "SERVICE_CONFIG_SERVICE_SID_INFO",
            "SERVICE_CONFIG_FAILURE_ACTIONS",
            "SERVICE_CONFIG_FAILURE_ACTIONS_FLAG",
        ):
            self.assertIn(f"ChangeServiceConfig2W(service, {setting}", SERVICE)
        self.assertIn("SERVICE_FAILURE_ACTIONS_FLAG failure_policy = {TRUE}", SERVICE)
        self.assertGreaterEqual(SERVICE.count("if (!ChangeServiceConfig2W("), 5)

    def test_privileged_fail_closed_escalates_engine_stop_failure(self) -> None:
        start = BACKEND.index("void FailClosedPrivilegedTunnel()")
        end = BACKEND.index("#endif", start)
        body = BACKEND[start:end]
        self.assertIn("if (!StopWinsAwgEngine())", body)
        self.assertIn("TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT)", body)


if __name__ == "__main__":
    unittest.main()
