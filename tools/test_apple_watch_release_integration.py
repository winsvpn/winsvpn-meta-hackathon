#!/usr/bin/env python3
"""Adversarial checks for Watch verifier integration in Apple release paths."""

from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import apple_cross_store_artifact_gate as gate
import apple_final_evidence_collector as collector
import apple_upload_exact_release_candidates as uploader


ROOT = pathlib.Path(__file__).resolve().parents[1]


def verifier_result(
    ipa: pathlib.Path, *, architectures: list[str] | None = None
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "bundle_id": gate.WATCH_BUNDLE_ID,
        "companion_bundle_id": gate.HOST_BUNDLE_ID,
        "version": gate.CANONICAL_MARKETING_VERSION,
        "build_number": gate.CANONICAL_BUNDLE_VERSION,
        "parent_version": gate.CANONICAL_MARKETING_VERSION,
        "parent_build_number": gate.CANONICAL_BUNDLE_VERSION,
        "ipa_sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(),
        "ipa_bytes": ipa.stat().st_size,
        "executable": gate.WATCH_EXECUTABLE,
        "executable_sha256": hashlib.sha256(b"watch").hexdigest(),
        "architectures": architectures or ["arm64", "arm64_32"],
        "watch_connectivity_dependency": "/System/Library/Frameworks/WatchConnectivity.framework/WatchConnectivity",
        "wc_session_import": "_OBJC_CLASS_$_WCSession",
        "required_selectors": ["activationState", "isReachable", "receivedApplicationContext", "sendMessage:replyHandler:errorHandler:", "session:activationDidCompleteWithState:error:", "session:didReceiveApplicationContext:", "session:didReceiveMessage:", "sessionReachabilityDidChange:"],
        "privacy_manifest_sha256": hashlib.sha256(b"watch-privacy").hexdigest(),
        "debug_sections": False,
    }


class WatchReleaseIntegrationTests(unittest.TestCase):
    def test_gate_expects_exactly_the_selectors_the_verifier_reports(self) -> None:
        # The verifier reports sorted(REQUIRED_SELECTORS); the gate compares that list
        # exactly, so the two must not drift (they disagreed from ee48a2f until r39).
        import apple_watch_artifact_verifier as verifier

        self.assertEqual(
            gate.WATCH_REQUIRED_SELECTORS, tuple(sorted(verifier.REQUIRED_SELECTORS))
        )

    def test_uploader_rejects_watch_privacy_manifest_hash_drift(self) -> None:
        result = verifier_result(pathlib.Path(__file__))
        manifest = {
            "executable_sha256": result["executable_sha256"],
            "privacy_info_sha256": "f" * 64,
        }
        with self.assertRaisesRegex(
            uploader.UploadGateError, "privacy manifest"
        ):
            uploader._verify_watch_manifest_binding(result, manifest)

    @staticmethod
    def _namespace(result: object) -> dict[str, object]:
        namespace = {"RESULT": result}
        exec(
            "class WatchArtifactError(RuntimeError):\n"
            "    pass\n"
            "def verify_ipa(_path):\n"
            "    return RESULT\n",
            namespace,
        )
        return namespace

    @staticmethod
    def _rejecting_namespace(message: str) -> dict[str, object]:
        namespace = {"MESSAGE": message}
        exec(
            "class WatchArtifactError(RuntimeError):\n"
            "    pass\n"
            "def verify_ipa(_path):\n"
            "    raise WatchArtifactError(MESSAGE)\n",
            namespace,
        )
        return namespace

    def test_held_ipa_binds_verifier_identity_and_canonical_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "candidate.ipa"
            ipa.write_bytes(b"signed-ipa-bytes")
            digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
            expected = gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                "apple_watch_artifact_verifier.py"
            ]
            with gate.held_reviewed_watch_verifier_source(
                expected_sha256=expected
            ) as verifier_source, mock.patch.object(
                gate,
                "_isolated_reviewed_source_namespace",
                return_value=self._namespace(verifier_result(ipa)),
            ):
                self.assertEqual(hashlib.sha256(verifier_source).hexdigest(), expected)
                evidence = gate.verify_watch_artifact_snapshot(
                    ipa,
                    artifact_sha256=digest,
                    artifact_size=ipa.stat().st_size,
                    verifier_source=verifier_source,
                    expected_verifier_sha256=expected,
                )
            self.assertEqual(evidence["artifact_sha256"], digest)
            self.assertEqual(
                evidence["verifier"]["path"], gate.WATCH_ARTIFACT_VERIFIER_RELATIVE
            )
            self.assertEqual(
                evidence["verifier"]["sha256"],
                hashlib.sha256(
                    (ROOT / gate.WATCH_ARTIFACT_VERIFIER_RELATIVE).read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                evidence["result_sha256"],
                gate._canonical_json_sha256(evidence["result"]),
            )

    def test_unsupported_watch_architecture_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "candidate.ipa"
            ipa.write_bytes(b"signed-ipa-bytes")
            expected = gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                "apple_watch_artifact_verifier.py"
            ]
            source = (ROOT / gate.WATCH_ARTIFACT_VERIFIER_RELATIVE).read_bytes()
            with mock.patch.object(
                gate,
                "_isolated_reviewed_source_namespace",
                return_value=self._namespace(
                    verifier_result(ipa, architectures=["x86_64"])
                ),
            ):
                with self.assertRaisesRegex(
                    gate.AppleArtifactGateError, "unsupported or incomplete"
                ):
                    gate.verify_watch_artifact_snapshot(
                        ipa,
                        artifact_sha256=hashlib.sha256(ipa.read_bytes()).hexdigest(),
                        artifact_size=ipa.stat().st_size,
                        verifier_source=source,
                        expected_verifier_sha256=expected,
                    )

    def test_missing_and_malformed_verifier_output_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "candidate.ipa"
            ipa.write_bytes(b"signed-ipa-bytes")
            digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
            expected = gate.HELD_ARTIFACT_REVIEW_SOURCE_SHA256[
                "apple_watch_artifact_verifier.py"
            ]
            source = (ROOT / gate.WATCH_ARTIFACT_VERIFIER_RELATIVE).read_bytes()
            for namespace, message in (
                (self._rejecting_namespace("rejected"), "rejected"),
                (self._namespace("not-json"), "exact JSON"),
            ):
                with self.subTest(message=message), mock.patch.object(
                    gate,
                    "_isolated_reviewed_source_namespace",
                    return_value=namespace,
                ):
                    with self.assertRaisesRegex(gate.AppleArtifactGateError, message):
                        gate.verify_watch_artifact_snapshot(
                            ipa,
                            artifact_sha256=digest,
                            artifact_size=ipa.stat().st_size,
                            verifier_source=source,
                            expected_verifier_sha256=expected,
                        )

    def test_both_production_callers_pass_the_exact_held_source_contract(self) -> None:
        source = (ROOT / gate.WATCH_ARTIFACT_VERIFIER_RELATIVE).read_bytes()
        expected = hashlib.sha256(source).hexdigest()
        self.assertEqual(expected, uploader.WATCH_ARTIFACT_VERIFIER_SHA256)
        self.assertEqual(expected, collector.WATCH_ARTIFACT_VERIFIER_SHA256)
        with tempfile.TemporaryDirectory() as temporary:
            ipa = pathlib.Path(temporary) / "candidate.ipa"
            ipa.write_bytes(b"held-candidate")
            digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
            size = ipa.stat().st_size
            result = {
                "result": {"executable_sha256": hashlib.sha256(b"watch").hexdigest()}
            }
            with mock.patch.object(
                uploader, "verify_watch_artifact_snapshot", return_value=result
            ) as upload_verify:
                self.assertIs(
                    uploader.verify_embedded_watch_candidate(
                        ipa, artifact_sha256=digest, artifact_size=size
                    ),
                    result,
                )
            with mock.patch.object(
                collector, "verify_watch_artifact_snapshot", return_value=result
            ) as collector_verify:
                self.assertIs(
                    collector._verify_watch_release_snapshot(
                        ipa, artifact_sha256=digest, artifact_size=size
                    ),
                    result,
                )
            for production_call in (upload_verify, collector_verify):
                production_call.assert_called_once()
                args, kwargs = production_call.call_args
                self.assertEqual(args, (ipa,))
                self.assertEqual(kwargs["artifact_sha256"], digest)
                self.assertEqual(kwargs["artifact_size"], size)
                self.assertEqual(
                    hashlib.sha256(kwargs["verifier_source"]).hexdigest(), expected
                )
                self.assertEqual(kwargs["expected_verifier_sha256"], expected)

    def test_uploader_holds_exact_candidate_and_refuses_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source.ipa"
            source.write_bytes(b"exact-signed-ipa")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            held = uploader.hold_candidate(
                source,
                root / "held.ipa",
                expected_sha256=digest,
                expected_size=source.stat().st_size,
            )
            self.assertEqual(held.read_bytes(), b"exact-signed-ipa")
            self.assertEqual(os.stat(held).st_nlink, 1)
            with self.assertRaisesRegex(uploader.UploadGateError, "stale or substituted"):
                uploader.hold_candidate(
                    source,
                    root / "wrong.ipa",
                    expected_sha256="0" * 64,
                    expected_size=source.stat().st_size,
                )
            held.close()

    def test_uploader_rejects_substitution_before_upload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source.ipa"
            source.write_bytes(b"exact-signed-ipa")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            custody = uploader.hold_candidate(
                source,
                root / "held.ipa",
                expected_sha256=digest,
                expected_size=source.stat().st_size,
            )
            authentic = root / "authentic.ipa"
            custody.path.rename(authentic)
            custody.path.write_bytes(b"same-uid-substitute")
            try:
                with self.assertRaisesRegex(
                    uploader.UploadGateError, "changed while retained|substituted"
                ):
                    custody.verify(rehash=True)
            finally:
                custody.close(verify=False)

    def test_upload_ignores_fake_path_and_uses_retained_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "candidate.ipa"
            source.write_bytes(b"exact-upload-candidate")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            candidate_custody = uploader.hold_candidate(
                source,
                root / "held.ipa",
                expected_sha256=digest,
                expected_size=source.stat().st_size,
            )
            tool = root / "altoolShim"
            tool.write_bytes(b"authenticated-tool")
            tool.chmod(0o500)
            tool_descriptor = os.open(tool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            tool_custody = uploader.HeldCandidate(
                tool,
                tool_descriptor,
                expected_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
                expected_size=tool.stat().st_size,
            )
            key_dir = root / "keys"
            key_dir.mkdir(mode=0o700)
            key = key_dir / "AuthKey_TESTKEY123.p8"
            key.write_bytes(b"private-key-fixture")
            key.chmod(0o600)
            candidate = uploader.Candidate(
                platform="ios",
                artifact_type="ipa",
                path=candidate_custody.path,
                relative_path="candidate.ipa",
                size_bytes=candidate_custody.expected_size,
                sha256=digest,
                app_version="1.0.16",
                build_number="33",
                custody=candidate_custody,
            )

            @contextlib.contextmanager
            def authenticated_tool():
                yield tool_custody

            calls: list[tuple[list[str], dict[str, str], tuple[int, ...]]] = []

            def completed(command, **kwargs):
                calls.append((list(command), dict(kwargs["env"]), kwargs["pass_fds"]))
                return subprocess.CompletedProcess(
                    command, 0, b'{"product-errors":[]}', b""
                )

            with mock.patch.dict(os.environ, {"PATH": str(root / "attacker")}), mock.patch.object(
                uploader, "_authenticated_altool", authenticated_tool
            ), mock.patch.object(uploader, "_bounded_process", side_effect=completed):
                receipt = uploader.upload_candidate(
                    candidate, key, "TESTKEY123", "11111111-2222-3333-4444-555555555555"
                )
            self.assertEqual(receipt["candidate_sha256"], digest)
            self.assertEqual(receipt["candidate_size_bytes"], source.stat().st_size)
            self.assertEqual(receipt["app_version"], "1.0.16")
            self.assertEqual(receipt["build_number"], "33")
            self.assertEqual(
                receipt["processing_status"],
                "unverified_pending_app_store_connect",
            )
            self.assertEqual(len(calls), 1)
            command, env, pass_fds = calls[0]
            self.assertEqual(pathlib.Path(command[0]).parent.as_posix(), "/dev/fd")
            self.assertEqual(pathlib.Path(command[3]).parent.as_posix(), "/dev/fd")
            self.assertEqual(env["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
            self.assertNotIn(str(root / "attacker"), env.values())
            self.assertNotEqual(env["API_PRIVATE_KEYS_DIR"], str(key_dir))
            isolated = pathlib.Path(env["API_PRIVATE_KEYS_DIR"])
            self.assertEqual(isolated.parent, pathlib.Path(tempfile.gettempdir()))
            self.assertEqual(set(pass_fds), {tool_custody.descriptor, candidate_custody.descriptor})

            def empty_response(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, b"{}", b"")

            with mock.patch.object(
                uploader, "_authenticated_altool", authenticated_tool
            ), mock.patch.object(
                uploader, "_bounded_process", side_effect=empty_response
            ), self.assertRaisesRegex(
                uploader.UploadGateError, "clean transfer"
            ):
                uploader.upload_candidate(
                    candidate, key, "TESTKEY123", "11111111-2222-3333-4444-555555555555"
                )
            candidate_custody.close()
            tool_custody.close()

    def test_bounded_process_kills_noisy_and_hung_children(self) -> None:
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(uploader.UploadGateError, "output bound"):
                uploader._bounded_process(
                    [sys.executable, "-c", "import os;os.write(1,b'x'*8192)"],
                    label="noisy Apple fixture",
                    cwd=root,
                    env=environment,
                    timeout=5,
                    output_limit=1024,
                )
            with self.assertRaisesRegex(uploader.UploadGateError, "time bound"):
                uploader._bounded_process(
                    [sys.executable, "-c", "import time;time.sleep(30)"],
                    label="hung Apple fixture",
                    cwd=root,
                    env=environment,
                    timeout=1,
                    output_limit=1024,
                )
            pid_file = root / "descendant.pid"
            uploader._bounded_process(
                [
                    "/bin/sh",
                    "-c",
                    'sleep 30 </dev/null >/dev/null 2>&1 & echo "$!" > "$1"',
                    "apple-descendant",
                    str(pid_file),
                ],
                label="zero-exit Apple leader fixture",
                cwd=root,
                env=environment,
                timeout=5,
                output_limit=1024,
            )
            child_pid = int(pid_file.read_text(encoding="ascii").strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    @unittest.skipUnless(sys.platform == "darwin", "SIGALRM is macOS-only")
    def test_upload_process_start_is_deadline_bounded(self) -> None:
        def blocked_popen(*_args, **_kwargs):
            time.sleep(5)
            raise AssertionError("uploader did not interrupt blocked Popen")

        started = time.monotonic()
        with mock.patch.object(
            uploader.subprocess, "Popen", side_effect=blocked_popen
        ), self.assertRaisesRegex(
            uploader.UploadGateError, "process-start time bound"
        ):
            uploader._bounded_process(
                ["/usr/bin/true"],
                label="blocked uploader Popen",
                cwd=ROOT,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                timeout=1,
            )
        self.assertLess(time.monotonic() - started, 2.0)

    def test_release_validator_does_not_receive_private_key_environment(self) -> None:
        captured: dict[str, object] = {}

        def completed(command, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.dict(
            os.environ,
            {
                "WINS_APPLE_AUTHENTICATION_KEY_PATH": "/private/keys/AuthKey_SECRET.p8",
                "WINS_APPLE_AUTHENTICATION_KEY_ID": "SECRET",
                "WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID": "SECRET-ISSUER",
            },
        ), mock.patch.object(
            uploader, "_bounded_process", side_effect=completed
        ), mock.patch.object(
            uploader,
            "validate_owner_signoff",
            side_effect=RuntimeError("stop after validator"),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after validator"):
                uploader.run_release_gates({})
        self.assertEqual(
            captured["env"],
            {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )

    def test_producer_runs_watch_gate_before_finishing_ios_receipt(self) -> None:
        source = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        watch = source.index('watch-evidence "${IOS_ARTIFACT_REL}"')
        finish = source.index('finish_receipt ios "${IOS_BEGIN}"')
        freeze = source.index('tools/freeze_apple_release_candidates.py')
        self.assertLess(watch, finish)
        self.assertLess(watch, freeze)
        self.assertIn('/usr/bin/tee -a "${VERIFICATION_LOG}"', source[watch:finish])


if __name__ == "__main__":
    unittest.main()
