#!/usr/bin/env python3
"""Static regression checks for the Windows AWG precommit contract."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND = (ROOT / "windows/runner/windows_tunnel_backend.cpp").read_text(
    encoding="utf-8"
)
SPLIT = (ROOT / "windows/runner/windows_split_tunnel.cpp").read_text(
    encoding="utf-8"
)
SERVICE = (ROOT / "windows/runner/windows_tunnel_service_main.cpp").read_text(
    encoding="utf-8"
)
PROTOCOL = (ROOT / "windows/runner/windows_tunnel_service_protocol.h").read_text(
    encoding="utf-8"
)
HARNESS = (ROOT / "tools/windows_interactive_live_cycle.ps1").read_text(
    encoding="utf-8"
)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class WindowsAwgConvergenceGateTests(unittest.TestCase):
    def test_privileged_start_orders_proof_before_route_commit(self) -> None:
        body = function_body(BACKEND, "bool InstallPrivilegedTunnel(")
        ordered = [
            "PrepareWindowsAppExclusions",
            "StartWinsAwgEngine",
            "ConfigureWinsAwgInterface",
            "StartWindowsAppExclusions",
            "InstallWindowsTunnelConvergenceProbeRoute",
            "WaitForAwgConvergence",
            "InstallWindowsTunnelRoutes",
            "g_tunnel_promoted.store(true",
        ]
        positions = [body.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertGreaterEqual(body.count("FailClosedPrivilegedTunnel()"), 8)

    def test_precommit_uses_no_default_route(self) -> None:
        body = function_body(
            SPLIT, "bool InstallWindowsTunnelConvergenceProbeRoute("
        )
        for prefix in ("0.0.0.0", "128.0.0.0", "::", "8000::"):
            self.assertIn(
                f'{{"{prefix}", static_cast<uint8_t>(1)}}', body
            )
        self.assertNotIn("PrefixLength = 0", body)
        self.assertIn("convergence_probe", SPLIT)

    def test_commit_verifies_both_halves_and_physical_carrier(self) -> None:
        body = function_body(SPLIT, "bool VerifyCommittedWindowsTunnelRoutes(")
        self.assertIn('"1.1.1.1"', body)
        self.assertIn('"129.6.15.28"', body)
        self.assertIn("selected.DestinationPrefix.PrefixLength == 0", body)
        self.assertIn("kCommitPollDeadlineMs", body)
        self.assertNotIn("selected.DestinationPrefix.PrefixLength != 0", body)
        self.assertIn("route.carrier_pin", body)
        self.assertIn("SameNextHop(selected_carrier.NextHop, carrier.NextHop)", body)

    def test_unowned_route_collision_is_rejected(self) -> None:
        create = function_body(SPLIT, "bool CreateOwnedRoute(")
        self.assertIn("if (already_owned) return true", create)
        self.assertIn("status == ERROR_OBJECT_ALREADY_EXISTS", create)
        self.assertIn("Refusing to trust", create)

    def test_transfer_gate_requires_fresh_bidirectional_growth(self) -> None:
        predicate = function_body(BACKEND, "bool IsAwgPeerConverged(")
        self.assertIn("kMinimumConvergenceTransferBytes", predicate)
        self.assertIn("peer.rx_bytes", predicate)
        self.assertIn("peer.tx_bytes", predicate)
        self.assertIn("earliest_accepted", predicate)
        waiter = function_body(BACKEND, "bool WaitForAwgConvergence(")
        self.assertIn("kAwgConvergenceDeadlineMilliseconds", waiter)
        self.assertIn("Fail-closed", waiter.replace("fail-closed", "Fail-closed"))

    def test_generation_scoped_phase_and_commit_status(self) -> None:
        self.assertIn("kProtocolVersion = 4", PROTOCOL)
        self.assertIn("kStartSucceeded = 4", PROTOCOL)
        self.assertIn("kStopSucceeded = 5", PROTOCOL)
        self.assertIn("uint64_t transition_generation", PROTOCOL)
        self.assertIn("sizeof(RequestHeader) == 24", SERVICE)
        self.assertIn("TunnelPhase::kConverging", SERVICE)
        self.assertIn("TunnelPhase::kCommitted", SERVICE)
        self.assertIn('";route_committed="', SERVICE)
        self.assertIn('";generation="', SERVICE)
        self.assertIn("g_tunnel_phase.store(TunnelPhase::kStopping", SERVICE)
        self.assertIn("IsExpectedCommittedManagerStatus", BACKEND)

    def test_status_observability_does_not_weaken_mutation_authority(self) -> None:
        handler = function_body(SERVICE, "void HandlePipeClient(HANDLE pipe)")
        # M-12: client authorization now runs in AuthorizePipeClientBeforeRead
        # BEFORE any framed read (so an unauthorized client cannot occupy the
        # single pipe instance across timed waits); HandlePipeClient acts on the
        # returned role. Mutation authority is unchanged -- an unauthorized
        # client is rejected outright, and the elevated-admin (status) role may
        # only issue kStatus, never a kStart/kStop mutation.
        self.assertIn("AuthorizePipeClientBeforeRead(pipe)", handler)
        self.assertIn("PipeClientRole::kRejected", handler)
        self.assertIn("command == Command::kStatus", handler)
        self.assertIn(
            "role == PipeClientRole::kElevatedAdmin && command != Command::kStatus",
            handler,
        )
        authorizer = function_body(
            SERVICE, "PipeClientRole AuthorizePipeClientBeforeRead(HANDLE pipe)"
        )
        self.assertIn("IsAuthorizedAppPipeClient(pipe)", authorizer)
        self.assertIn("IsAuthorizedElevatedAdminStatusClient(pipe)", authorizer)
        self.assertIn("PipeClientRole::kInstalledApp", authorizer)
        self.assertIn("PipeClientRole::kElevatedAdmin", authorizer)
        admin = function_body(
            SERVICE, "bool IsAuthorizedElevatedAdminStatusClient(HANDLE pipe)"
        )
        self.assertIn("WTSGetActiveConsoleSessionId", admin)
        self.assertIn("TokenElevation", admin)
        self.assertIn("DOMAIN_ALIAS_RID_ADMINS", admin)
        self.assertIn("CheckTokenMembership", admin)
        self.assertIn("WinLocalSystemSid", admin)
        app = function_body(SERVICE, "bool IsAuthorizedAppPipeClient(HANDLE pipe)")
        self.assertIn('JoinPath(ModuleDirectory(), L"wins_vpn.exe")', app)

    def test_rejected_client_never_enters_response_drain(self) -> None:
        handler = function_body(SERVICE, "void HandlePipeClient(HANDLE pipe)")
        rejection = function_body(handler, "if (role == PipeClientRole::kRejected)")
        self.assertIn("return;", rejection)
        self.assertNotIn("WaitForClientDrain", rejection)
        guard = handler.index("} drain{pipe};")
        self.assertLess(handler.index(rejection) + len(rejection), guard)
        self.assertLess(guard, handler.index("RequestHeader header"))
        self.assertIn("~AuthorizedClientDrain() { WaitForClientDrain(pipe); }", handler)
        server = function_body(SERVICE, "DWORD RunPipeServer()")
        self.assertNotIn("WaitForClientDrain", server)

    def test_harness_binds_canary_to_same_committed_generation(self) -> None:
        self.assertIn("function Get-TunnelManagerCommitState", HARNESS)
        self.assertIn("[uint16]4", HARNESS)
        self.assertIn("[uint16]3", HARNESS)
        self.assertNotIn(".ReadTimeout =", HARNESS)
        self.assertNotIn(".WriteTimeout =", HARNESS)
        self.assertIn("pre_generation", HARNESS)
        self.assertIn("post_generation", HARNESS)
        self.assertIn("generation_stable_across_canary", HARNESS)
        self.assertIn("$postTunnel.generation -eq $tunnel.generation", HARNESS)
        self.assertIn("$attempt.egress_disposition = 'state_changed'", HARNESS)
        mismatch = HARNESS.index("$connectedEgressMismatchObserved = $true")
        stable = HARNESS.rfind(
            "$attempt.generation_stable_across_canary", 0, mismatch
        )
        self.assertGreater(stable, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
