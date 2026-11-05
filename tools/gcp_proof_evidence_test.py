#!/usr/bin/env python3
"""Focused fail-closed tests for GCP proof evidence custody."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import tools.gcp_proof_evidence as evidence
import tools.gcp_proof_live_probe as probe


PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"TEST_FAKE_PRIVATE_KEY_MATERIAL\n"
    b"-----END PRIVATE KEY-----\n"
)


def _assert_no_secret(message: str) -> None:
    assert "BEGIN" not in message
    assert "PRIVATE KEY" not in message
    assert "TEST_FAKE_PRIVATE_KEY_MATERIAL" not in message


def test_plaintext_secret_evidence_is_refused() -> None:
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught:
        evidence.capture_stream(PEM, "stdout")
    _assert_no_secret(str(caught.value))


def test_base64_secret_evidence_is_refused() -> None:
    encoded = base64.b64encode(PEM)
    assert b"PRIVATE KEY" not in encoded
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught:
        evidence.capture_stream(encoded, "stderr")
    _assert_no_secret(str(caught.value))


def test_urlsafe_base64_and_hex_secret_evidence_are_refused() -> None:
    urlsafe = base64.urlsafe_b64encode(PEM)
    hexed = PEM.hex().encode("ascii")
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught_url:
        evidence.capture_stream(urlsafe, "stdout")
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught_hex:
        evidence.capture_stream(hexed, "stderr")
    _assert_no_secret(str(caught_url.value))
    _assert_no_secret(str(caught_hex.value))


def test_json_wrapped_base64_secret_evidence_is_refused() -> None:
    payload = json.dumps(
        {"blob": base64.b64encode(PEM).decode("ascii")},
        sort_keys=True,
    ).encode("ascii")
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught:
        evidence.capture_stream(payload, "stdout")
    _assert_no_secret(str(caught.value))


def test_double_encoded_base64_secret_evidence_is_refused() -> None:
    double = base64.b64encode(base64.b64encode(PEM))
    with pytest.raises(evidence.fleet.FleetRefused, match="secret material") as caught:
        evidence.capture_stream(double, "stdout")
    _assert_no_secret(str(caught.value))


def test_ordinary_json_and_binary_captures_are_kept() -> None:
    capture = evidence.capture_stream(b'{"Google Cloud SDK":"582.0.0"}\n', "stdout")
    assert capture["encoding"] == "base64"
    assert base64.b64decode(capture["data"]) == b'{"Google Cloud SDK":"582.0.0"}\n'
    binary = evidence.capture_stream(b"\x00\xffstderr", "stderr")
    assert base64.b64decode(binary["data"]) == b"\x00\xffstderr"


def test_subprocess_runner_preserves_bounded_streams_and_exit_code() -> None:
    result = evidence.SubprocessRunner().run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'out'); "
            "sys.stderr.buffer.write(b'err'); raise SystemExit(7)",
        ],
        timeout_seconds=10,
    )
    assert result == evidence.RunResult(stdout=b"out", stderr=b"err", exit_code=7)


def test_retained_probe_child_chain_defeats_ancestor_swap_restore_and_env_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    active = tmp_path / "active"
    saved = tmp_path / "saved"
    replacement = tmp_path / "replacement"
    active.mkdir()
    replacement.mkdir()
    probe_path = active / "probe.py"
    replacement_probe = replacement / "probe.py"
    genuine_marker = tmp_path / "genuine-marker"
    exfil_marker = tmp_path / "substitute-exfil"
    runtime_marker = tmp_path / "runtime-marker"
    credential_path = tmp_path / "credential.json"
    credential_path.write_text("not-a-real-credential\n", encoding="ascii")
    probe_path.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import sys\n"
        "active, saved, replacement, genuine, runtime = map(Path, sys.argv[1:6])\n"
        "active.rename(saved)\n"
        "replacement.rename(active)\n"
        "active.rename(replacement)\n"
        "saved.rename(active)\n"
        "genuine.write_text(os.environ.get('WINS_GCP_PROOF_CREDENTIAL_PATH', ''))\n"
        "runtime.write_text(sys.executable)\n"
        "print('GENUINE')\n",
        encoding="ascii",
    )
    replacement_probe.write_text(
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(exfil_marker)!r}).write_text("
        "os.environ.get('WINS_GCP_PROOF_CREDENTIAL_PATH', 'missing'))\n"
        "print('SUBSTITUTED')\n",
        encoding="ascii",
    )
    runtime_path = Path(sys.executable).resolve(strict=True)
    collector_path = Path(evidence.__file__).resolve(strict=True)
    collector_hold = evidence.hold_path(
        collector_path,
        expected_sha256=hashlib.sha256(collector_path.read_bytes()).hexdigest(),
        label="test collector",
    )
    probe_hold = evidence.hold_path(
        probe_path,
        expected_sha256=hashlib.sha256(probe_path.read_bytes()).hexdigest(),
        label="test probe",
    )
    runtime_hold = evidence.hold_path(
        runtime_path,
        expected_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
        label="test runtime",
        executable=True,
    )
    closure = evidence.AuthenticatedRuntimeClosure(
        collector=collector_hold,
        probe=probe_hold,
        runtime=runtime_hold,
    )
    runner = evidence.SubprocessRunner()
    runner.bind_authenticated_probe(closure)
    monkeypatch.setattr(evidence, "PROBE_SOURCE", probe_path)
    monkeypatch.setenv(probe.CREDENTIAL_PATH_ENV, str(credential_path))
    try:
        with pytest.raises(
            evidence.fleet.FleetRefused, match="execution ancestor changed"
        ):
            runner.run(
                [
                    str(probe_path),
                    str(active),
                    str(saved),
                    str(replacement),
                    str(genuine_marker),
                    str(runtime_marker),
                ],
                timeout_seconds=10,
            )
    finally:
        closure.close()
    assert genuine_marker.read_text(encoding="ascii") == str(credential_path)
    assert runtime_marker.read_text(encoding="ascii") == str(runtime_path)
    assert not exfil_marker.exists()


def test_owner_writable_interpreter_chain_is_refused_before_execution(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "python3.14"
    marker = tmp_path / "ran"
    runtime.write_text(
        "#!/bin/sh\nprintf unsafe > " + str(marker) + "\n",
        encoding="ascii",
    )
    runtime.chmod(0o700)
    with pytest.raises(
        evidence.fleet.FleetRefused, match="owner-writable execution ancestor|safe retained file"
    ):
        evidence.hold_path(
            runtime,
            expected_sha256=hashlib.sha256(runtime.read_bytes()).hexdigest(),
            label="hostile interpreter",
            executable=True,
            reject_effective_write=True,
        )
    assert not marker.exists()


@pytest.mark.parametrize("stream_fd", [1, 2])
def test_subprocess_runner_kills_streaming_output_before_child_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stream_fd: int
) -> None:
    monkeypatch.setattr(evidence.fleet, "MAX_CAPTURE_BYTES", 64 * 1024)
    marker = tmp_path / "child-continued"
    writer = tmp_path / "writer.py"
    writer.write_text(
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        "fd = int(sys.argv[1])\n"
        "for _ in range(1024):\n"
        "    os.write(fd, b'X' * 65536)\n"
        "pathlib.Path(sys.argv[2]).write_bytes(b'unsafe')\n",
        encoding="ascii",
    )
    with pytest.raises(evidence.fleet.FleetRefused, match="exceeds the size limit"):
        evidence.SubprocessRunner().run(
            [sys.executable, str(writer), str(stream_fd), str(marker)],
            timeout_seconds=10,
        )
    assert not marker.exists()


def test_collector_environment_keeps_proof_custody_and_drops_ambient_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "adc.json"))
    monkeypatch.setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", str(tmp_path / "adc.json"))
    monkeypatch.setenv(probe.CREDENTIAL_PATH_ENV, str(tmp_path / "bound.json"))
    monkeypatch.setenv(probe.CREDENTIAL_KIND_ENV, "service_account")
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker"))
    monkeypatch.setenv("KUBECONFIG", str(tmp_path / "kube"))
    monkeypatch.setenv("NETRC", str(tmp_path / "netrc"))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "ssh"))
    environment = evidence.sanitized_collector_environment()
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in environment
    assert "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE" not in environment
    assert "DOCKER_CONFIG" not in environment
    assert "KUBECONFIG" not in environment
    assert "NETRC" not in environment
    assert "SSH_AUTH_SOCK" not in environment
    assert environment[probe.CREDENTIAL_PATH_ENV].endswith("bound.json")
    assert environment[probe.CREDENTIAL_KIND_ENV] == "service_account"


def test_live_collection_fails_closed_without_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(probe.CREDENTIAL_KIND_ENV, raising=False)
    monkeypatch.delenv(probe.CREDENTIAL_PATH_ENV, raising=False)
    monkeypatch.delenv(probe.CREDENTIAL_ACCOUNT_ENV, raising=False)
    monkeypatch.delenv(probe.CREDENTIAL_PROJECT_ENV, raising=False)
    with pytest.raises(evidence.fleet.FleetRefused, match="owner blocker:.*credential") as caught:
        evidence.require_live_collection_custody()
    _assert_no_secret(str(caught.value))
    code = evidence.main(
        [
            "--plan",
            str(tmp_path / "plan.json"),
            "--apply",
            str(tmp_path / "apply.json"),
            "--probe-driver",
            str(tmp_path / "driver"),
            "--output",
            str(tmp_path / "evidence.json"),
            "--run-id",
            "run-1",
            "--session-id",
            "session-1",
            "--correlation-id",
            "correlation-1",
            "--confirm-live-collection",
        ]
    )
    assert code == evidence.fleet.REFUSAL_EXIT


def test_naive_and_offset_clocks_are_refused() -> None:
    with pytest.raises(evidence.fleet.FleetRefused, match="timezone-aware UTC"):
        evidence.require_utc_clock(datetime(2026, 8, 23, 12, 0, 0), "collector clock")
    offset = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone(timedelta(hours=-4)))
    with pytest.raises(evidence.fleet.FleetRefused, match="timezone-aware UTC"):
        evidence.require_utc_clock(offset, "collector clock")
    aware = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    assert evidence.require_utc_clock(aware, "collector clock") is aware


def test_marker_only_observation_is_not_proof() -> None:
    marker = {
        "kind": evidence.fleet.KIND_MARKER,
        "candidate_id": "c" * 64,
        "role": "control",
    }
    assert evidence._marker_only_observation(marker) is True
    assert evidence._marker_only_observation({"markers": {"control": marker}}) is True
    assert (
        evidence._marker_only_observation(
            {
                "roles": [
                    {
                        "role": "control",
                        "instance": "proof-control-a1",
                        "marker": marker,
                    }
                ]
            }
        )
        is True
    )
    bindings = {
        "fleet_id": "fleet",
        "run_id": "run-1",
        "session_id": "session-1",
        "correlation_id": "correlation-1",
        "client_artifact": {"path": "/tmp/client", "sha256": "a" * 64, "bytes": 1},
        "client_build_identity": "linux:1.0.15+30:" + "e" * 64,
        "client_release_binding": {"contract": "test"},
    }
    payload = evidence.fleet.observation_envelope("deployment", bindings, marker)
    stdout = evidence.fleet.canonical_bytes(payload)
    with pytest.raises(
        evidence.fleet.FleetRefused, match="marker-only collector observation"
    ):
        evidence.decode_collector_observation(
            action="deployment", stdout=stdout, bindings=bindings
        )


def test_duplicate_execution_receipt_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    execution = state / evidence.fleet.EXECUTION_NAME
    extra = state / "deployment-execution-old.json"
    payload = {"kind": evidence.fleet.KIND_EXECUTION, "candidate_id": "c" * 64}
    for path in (execution, extra):
        path.write_text(json.dumps(payload), encoding="ascii")
    with pytest.raises(evidence.fleet.FleetRefused, match="duplicate or mixed"):
        evidence.require_unique_proof_receipts(
            state,
            execution_path=execution,
            output=state / "evidence.json",
        )


def test_mixed_acceptance_receipt_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    execution = state / evidence.fleet.EXECUTION_NAME
    execution.write_text(
        json.dumps({"kind": evidence.fleet.KIND_EXECUTION}), encoding="ascii"
    )
    receipt = state / evidence.fleet.RECEIPT_NAME
    receipt.write_text(
        json.dumps({"kind": evidence.fleet.KIND_RECEIPT, "verdict": "pass"}),
        encoding="ascii",
    )
    with pytest.raises(evidence.fleet.FleetRefused, match="acceptance receipt"):
        evidence.require_unique_proof_receipts(
            state,
            execution_path=execution,
            output=state / "evidence.json",
        )


def test_empty_restore_stdout_fails_cleanup_postcondition() -> None:
    spec = evidence.fleet.build_spec(
        project="winsvpn-proof-lab",
        control_name="proof-control-a1",
        winn3_data_name="proof-winn3-a1",
        cover_data_name="proof-cover-a1",
        control_zone="us-east1-b",
        winn3_data_zone="us-east1-b",
        cover_data_zone="us-east1-b",
        control_machine="e2-standard-2",
        winn3_data_machine="e2-medium",
        cover_data_machine="e2-medium",
        admin_source_cidr="203.0.113.0/24",
        dataplane_source_cidr="198.51.100.0/24",
        image_family=evidence.fleet.DEFAULT_IMAGE_FAMILY,
        image_project=evidence.fleet.DEFAULT_IMAGE_PROJECT,
        gcloud_bin="gcloud",
    )
    bindings = {
        "fleet_id": "fleet",
        "run_id": "run-1",
        "session_id": "session-1",
        "correlation_id": "correlation-1",
        "client_artifact": {"path": "/tmp/client", "sha256": "a" * 64, "bytes": 1},
        "client_build_identity": "linux:1.0.15+30:" + "e" * 64,
        "client_release_binding": {"contract": "test"},
    }
    error = evidence.cleanup_postcondition_error(
        action="restore-awg",
        result=evidence.RunResult(stdout=b"", stderr=b"", exit_code=0),
        bindings=bindings,
        spec=spec,
    )
    assert error is not None
    assert "restore-awg" in error
    assert "canonical ASCII JSON" in error


def test_three_vm_binding_refuses_missing_cover_role() -> None:
    spec = evidence.fleet.build_spec(
        project="winsvpn-proof-lab",
        control_name="proof-control-a1",
        winn3_data_name="proof-winn3-a1",
        cover_data_name="proof-cover-a1",
        control_zone="us-east1-b",
        winn3_data_zone="us-east1-b",
        cover_data_zone="us-east1-b",
        control_machine="e2-standard-2",
        winn3_data_machine="e2-medium",
        cover_data_machine="e2-medium",
        admin_source_cidr="203.0.113.0/24",
        dataplane_source_cidr="198.51.100.0/24",
        image_family=evidence.fleet.DEFAULT_IMAGE_FAMILY,
        image_project=evidence.fleet.DEFAULT_IMAGE_PROJECT,
        gcloud_bin="gcloud",
    )
    execution = {
        "ended_utc": "2026-08-23T12:00:00Z",
        "preflight": {
            "instances": {
                "control": {
                    "name": "proof-control-a1",
                    "zone": "us-east1-b",
                    "machine_type": "e2-standard-2",
                    "project": "winsvpn-proof-lab",
                    "role": "control",
                    "creation_transaction": {
                        "creation_timestamp": "2026-08-23T11:50:00Z",
                        "id": "1001",
                    },
                },
                "data-winn3": {
                    "name": "proof-winn3-a1",
                    "zone": "us-east1-b",
                    "machine_type": "e2-medium",
                    "project": "winsvpn-proof-lab",
                    "role": "data-winn3",
                    "creation_transaction": {
                        "creation_timestamp": "2026-08-23T11:50:00Z",
                        "id": "1002",
                    },
                },
            }
        },
    }
    with pytest.raises(evidence.fleet.FleetRefused, match="exact three proof VMs"):
        evidence.require_fresh_three_vm_binding(spec, execution)


def test_candidate_identity_mismatch_is_refused() -> None:
    plan = {"deployment_inputs": {"candidate_id": "c" * 64}}
    execution = {
        "candidate_id": "d" * 64,
        "markers": {
            "control": {"candidate_id": "d" * 64},
            "data-winn3": {"candidate_id": "d" * 64},
            "data-cover": {"candidate_id": "d" * 64},
        },
    }
    deploy_refs = {"deployment_candidate_id": "d" * 64}
    with pytest.raises(
        evidence.fleet.FleetRefused, match="candidate identity mismatch"
    ):
        evidence.require_candidate_identity(execution, deploy_refs, plan)
