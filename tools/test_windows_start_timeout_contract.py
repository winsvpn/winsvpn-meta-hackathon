from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent


def integer_constant(source: str, name: str) -> int:
    match = re.search(rf"\b{name}\s*=\s*(\d+)\s*;", source)
    if match is None:
        raise AssertionError(f"missing integer constant: {name}")
    return int(match.group(1))


def evaluated_constant(source: str, name: str, values: dict[str, int]) -> int:
    match = re.search(rf"\b{name}\s*=\s*([^;]+);", source)
    if match is None:
        raise AssertionError(f"missing expression constant: {name}")
    total = 0
    for term in match.group(1).replace("\n", " ").split("+"):
        token = term.strip()
        if token.isdigit():
            total += int(token)
        elif token in values:
            total += values[token]
        else:
            raise AssertionError(f"unsupported term in {name}: {token}")
    return total


class WindowsStartTimeoutContractTest(unittest.TestCase):
    def test_dart_outlasts_complete_native_start_rpc_bound(self) -> None:
        protocol = (ROOT / "windows/runner/windows_tunnel_service_protocol.h").read_text(
            encoding="utf-8"
        )
        dart = (ROOT / "lib/tunnel_stop_settlement.dart").read_text(
            encoding="utf-8"
        )
        client = (ROOT / "windows/runner/windows_tunnel_service_client.cpp").read_text(
            encoding="utf-8"
        )
        backend = (ROOT / "windows/runner/windows_tunnel_backend.cpp").read_text(
            encoding="utf-8"
        )

        actual_names = (
            "kLegacyUninstallCommandTimeoutMilliseconds",
            "kLegacyInitialRemovalWaitMilliseconds",
            "kLegacyScmStopTimeoutMilliseconds",
            "kLegacyFinalRemovalWaitMilliseconds",
            "kAwgEngineStopWaitMilliseconds",
            "kAwgUapiReadinessTimeoutMilliseconds",
            "kAwgUapiWriteTimeoutMilliseconds",
            "kAwgUapiResponseTimeoutMilliseconds",
            "kAwgBaselineReadinessTimeoutMilliseconds",
            "kAwgSetconfTimeoutMilliseconds",
            "kAwgAdapterReadinessTimeoutMilliseconds",
            "kAwgConvergenceDeadlineMilliseconds",
            "kRouteCommitMarginMilliseconds",
        )
        actual = {name: integer_constant(protocol, name) for name in actual_names}
        normal_ms = evaluated_constant(
            protocol, "kNormalAwgCriticalPathBudgetMilliseconds", actual
        )
        watchdog_ms = integer_constant(protocol, "kStartOverallWatchdogMilliseconds")
        response_ms = integer_constant(protocol, "kStartCommandTimeoutMilliseconds")
        pipe_wait_ms = integer_constant(
            protocol, "kMutationPipeWaitTimeoutMilliseconds"
        )
        dart_match = re.search(
            r"windowsTunnelNativeStartTimeout\s*=\s*Duration\(seconds:\s*(\d+)\)",
            dart,
        )
        self.assertIsNotNone(dart_match)
        dart_ms = int(dart_match.group(1)) * 1000

        # The normal successful AWG path must include every sequential bound:
        # engine stop (10), startup UAPI (18), setconf (15), validation UAPI
        # (18), adapter (10), baseline UAPI (9), convergence plus one final
        # baseline query (34), and route margin (15), all in seconds.
        full_uapi_ms = (
            actual["kAwgUapiReadinessTimeoutMilliseconds"]
            + actual["kAwgUapiWriteTimeoutMilliseconds"]
            + actual["kAwgUapiResponseTimeoutMilliseconds"]
        )
        baseline_uapi_ms = (
            actual["kAwgBaselineReadinessTimeoutMilliseconds"]
            + actual["kAwgUapiWriteTimeoutMilliseconds"]
            + actual["kAwgUapiResponseTimeoutMilliseconds"]
        )
        convergence_with_final_query_ms = (
            actual["kAwgConvergenceDeadlineMilliseconds"] + baseline_uapi_ms
        )
        expected_normal_ms = (
            (2 * actual["kAwgEngineStopWaitMilliseconds"])
            + full_uapi_ms
            + actual["kAwgSetconfTimeoutMilliseconds"]
            + full_uapi_ms
            + actual["kAwgAdapterReadinessTimeoutMilliseconds"]
            + baseline_uapi_ms
            + convergence_with_final_query_ms
            + actual["kRouteCommitMarginMilliseconds"]
        )
        self.assertEqual(full_uapi_ms, 18000)
        self.assertEqual(baseline_uapi_ms, 9000)
        self.assertEqual(convergence_with_final_query_ms, 34000)
        self.assertEqual(normal_ms, expected_normal_ms)
        self.assertEqual(normal_ms, 129000)
        self.assertGreaterEqual(watchdog_ms, normal_ms + 20000)
        self.assertGreaterEqual(response_ms, watchdog_ms + 10000)
        self.assertGreaterEqual(dart_ms, pipe_wait_ms + response_ms + 5000)

        # Stale SCM component ceilings are intentionally longer than the
        # overall cap. The watchdog, not the native client, ends these hung
        # paths first and destroys the kill-on-close AWG job fail-closed.
        legacy_full_ms = (
            (2 * actual["kLegacyUninstallCommandTimeoutMilliseconds"])
            + actual["kLegacyInitialRemovalWaitMilliseconds"]
            + actual["kLegacyScmStopTimeoutMilliseconds"]
            + actual["kLegacyFinalRemovalWaitMilliseconds"]
        )
        self.assertGreater(
            legacy_full_ms + (2 * actual["kAwgEngineStopWaitMilliseconds"]),
            watchdog_ms,
        )

        # Source must consume the centralized actual deadlines rather than
        # regressing to unrelated literals.
        for required in (
            "kLegacyUninstallCommandTimeoutMilliseconds",
            "kLegacyInitialRemovalWaitMilliseconds",
            "kLegacyScmStopTimeoutMilliseconds",
            "kLegacyFinalRemovalWaitMilliseconds",
            "kAwgEngineStopWaitMilliseconds",
            "kAwgUapiReadinessTimeoutMilliseconds",
            "kAwgUapiWriteTimeoutMilliseconds",
            "kAwgUapiResponseTimeoutMilliseconds",
            "kAwgBaselineReadinessTimeoutMilliseconds",
            "kAwgSetconfTimeoutMilliseconds",
            "kAwgAdapterReadinessTimeoutMilliseconds",
            "kAwgConvergenceDeadlineMilliseconds",
        ):
            self.assertIn(required, backend)
        self.assertIn(
            "winsvpn::tunnel_service::kStartCommandTimeoutMilliseconds", client
        )
        self.assertIn(
            "winsvpn::tunnel_service::kMutationPipeWaitTimeoutMilliseconds", client
        )
        service = (ROOT / "windows/runner/windows_tunnel_service_main.cpp").read_text(
            encoding="utf-8"
        )
        start = service[
            service.index("if (command == Command::kStart)") : service.index(
                "if (command == Command::kStop)"
            )
        ]
        self.assertLess(
            start.index("kStartOverallWatchdogMilliseconds"),
            start.index("StartPrivilegedWindowsTunnel("),
        )
        self.assertIn("TerminateServiceFailClosed(ERROR_TIMEOUT)", start)

    def test_dart_outlasts_stop_and_status_native_bounds(self) -> None:
        protocol = (ROOT / "windows/runner/windows_tunnel_service_protocol.h").read_text(
            encoding="utf-8"
        )
        dart = (ROOT / "lib/tunnel_stop_settlement.dart").read_text(
            encoding="utf-8"
        )
        stop_ms = integer_constant(protocol, "kStopCommandTimeoutMilliseconds")
        mutation_wait_ms = integer_constant(
            protocol, "kMutationPipeWaitTimeoutMilliseconds"
        )
        status_ms = integer_constant(protocol, "kStatusCommandTimeoutMilliseconds")
        status_wait_ms = integer_constant(
            protocol, "kStatusPipeWaitTimeoutMilliseconds"
        )
        stop_match = re.search(
            r"windowsTunnelNativeStopTimeout\s*=\s*Duration\(seconds:\s*(\d+)\)",
            dart,
        )
        status_match = re.search(
            r"windowsTunnelActivitySnapshotTimeout\s*=\s*Duration\(seconds:\s*(\d+)\)",
            dart,
        )
        self.assertIsNotNone(stop_match)
        self.assertIsNotNone(status_match)
        dart_stop_ms = int(stop_match.group(1)) * 1000
        dart_status_ms = int(status_match.group(1)) * 1000
        self.assertGreater(dart_stop_ms, mutation_wait_ms + stop_ms)
        self.assertGreater(dart_status_ms, status_wait_ms + status_ms)

        baseline_status_ms = (
            integer_constant(protocol, "kAwgBaselineReadinessTimeoutMilliseconds")
            + integer_constant(protocol, "kAwgUapiWriteTimeoutMilliseconds")
            + integer_constant(protocol, "kAwgUapiResponseTimeoutMilliseconds")
        )
        self.assertGreater(status_ms, baseline_status_ms)

    def test_timeout_does_not_reorder_cancellation_or_fail_closed_cleanup(self) -> None:
        dart = (ROOT / "lib/main.dart").read_text(encoding="utf-8")
        native = (ROOT / "windows/runner/windows_tunnel_backend.cpp").read_text(
            encoding="utf-8"
        )

        candidate_start = dart.index("Future<bool> _startTunnelCandidate(")
        candidate_end = dart.index(
            "Future<bool> _loadPowerProtectionPromptSeen(", candidate_start
        )
        candidate = dart[candidate_start:candidate_end]
        invocation = candidate.index("'startTunnel'")
        timeout = candidate.index(".timeout(nativeStartTimeout)", invocation)
        cancellation = candidate.index(
            "if (shouldCancel?.call() == true)", timeout
        )
        self.assertLess(invocation, timeout)
        self.assertLess(timeout, cancellation)

        install_start = native.index("bool InstallTunnel(")
        install_end = native.index("bool UninstallTunnel(", install_start)
        install = native[install_start:install_end]
        rpc = install.index("StartWindowsTunnelThroughService(")
        rpc_failure_cleanup = install.index("StopXrayProcess();", rpc)
        commit = install.index("g_committed_generation.store", rpc)
        self.assertLess(rpc, rpc_failure_cleanup)
        self.assertLess(rpc_failure_cleanup, commit)


if __name__ == "__main__":
    unittest.main()
