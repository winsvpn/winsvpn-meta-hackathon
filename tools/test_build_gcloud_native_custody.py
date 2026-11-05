#!/usr/bin/env python3
"""Hostile tests for the native GCP release builders."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
HELPER_BUILDER = TOOLS / "build_gcloud_immutable_helper.sh"
PROVISIONER_BUILDER = TOOLS / "build_gcloud_runtime_provisioner.sh"
GO_CUSTODY_WRAPPER = TOOLS / "release_go_archive_custody.sh"
GO_CUSTODY_CONTROLLER = TOOLS / "release_go_archive_custody.py"
PIN_MANIFEST = TOOLS / "toolchain-pins.json"
STATIC_LINUX_AMD64 = TOOLS / "winn_conformance_build_out" / "winn-clientinfo-linux-amd64"

CONTROL_FILES = (
    "release_python_archive_custody.sh",
    "macos_release_python_runtime_receipt.py",
    "release_go_archive_custody.sh",
    "release_go_archive_custody.py",
    "release_go_archive_custody.trust.json",
    "provision_macos_release_go_runtime.sh",
    "release_source_freeze.py",
    "toolchain-pins.json",
)

BUILDERS = {
    "helper": {
        "path": HELPER_BUILDER,
        "inputs": (
            "gcloud_immutable_helper.go",
            "gcloud_immutable_helper_test.go",
        ),
        "labels": (
            "tools/gcloud_immutable_helper.go",
            "tools/gcloud_immutable_helper_test.go",
        ),
        "kinds": ("source", "test"),
        "outputs": (
            "build/gcloud_immutable_helper/gcloud_immutable_helper_linux_amd64",
        ),
        "receipt": "build/gcloud_immutable_helper/gcloud_immutable_helper_linux_amd64.receipt.json",
        "sidecar": "build/gcloud_immutable_helper/gcloud_immutable_helper_linux_amd64.receipt.json.sha256",
        "producer": "tools/build_gcloud_immutable_helper.sh",
        "host_test_count": 1,
        "build_count": 2,
    },
    "provisioner": {
        "path": PROVISIONER_BUILDER,
        "inputs": (
            "gcloud_runtime_provisioner.go",
            "gcloud_runtime_provisioner_test.go",
            "gcloud_immutable_helper.go",
            "gcloud_immutable_helper_test.go",
        ),
        "labels": (
            "tools/gcloud_runtime_provisioner.go",
            "tools/gcloud_runtime_provisioner_test.go",
            "tools/gcloud_immutable_helper.go",
            "tools/gcloud_immutable_helper_test.go",
        ),
        "kinds": ("source", "test", "source", "test"),
        "outputs": (
            "build/gcloud_runtime_provisioner/gcloud_immutable_helper_linux_amd64",
            "build/gcloud_runtime_provisioner/gcloud_runtime_provisioner_linux_amd64",
        ),
        "receipt": "build/gcloud_runtime_provisioner/gcloud_runtime_provisioner_linux_amd64.receipt.json",
        "sidecar": "build/gcloud_runtime_provisioner/gcloud_runtime_provisioner_linux_amd64.receipt.json.sha256",
        "producer": "tools/build_gcloud_runtime_provisioner.sh",
        "host_test_count": 2,
        "build_count": 4,
    },
}

PYTHON_WRAPPER_SHA256 = (
    "a83405a84f140c3fa8bdfc804bbb48fbe03ebcfcefd0e871a366dd74a7b76066"
)
GO_WRAPPER_SHA256 = (
    "29feac49552e79bdb77c90584e1cae0e2fe60708fd1333d002d28ae9237465e3"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def strict_json(data: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    text = data.decode("ascii")
    value = json.loads(text, object_pairs_hook=reject_duplicates)
    if canonical_json(value) != data:
        raise ValueError("JSON is not compact canonical ASCII with one LF")
    return value


def quoted_array(source: str, name: str) -> tuple[str, ...]:
    match = re.search(
        rf"(?ms)^{re.escape(name)}=\(\n(?P<body>.*?)^\)",
        source,
    )
    if match is None:
        raise AssertionError(f"missing shell array {name}")
    return tuple(re.findall(r'^\s+"([^"]+)"\s*$', match.group("body"), re.MULTILINE))


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class NativeGcloudBuilderCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pin = json.loads(PIN_MANIFEST.read_text(encoding="utf-8"))["tools"]["go"]
        if not STATIC_LINUX_AMD64.is_file():
            raise AssertionError(f"missing static Linux fixture: {STATIC_LINUX_AMD64}")

    def _copy_fixture(self, case: Path, key: str) -> Path:
        repo = case / "repo"
        tools = repo / "tools"
        tools.mkdir(parents=True)
        builder = BUILDERS[key]
        shutil.copyfile(builder["path"], tools / Path(builder["path"]).name)
        (tools / Path(builder["path"]).name).chmod(0o755)
        for name in builder["inputs"]:
            shutil.copyfile(TOOLS / name, tools / name)
        for name in CONTROL_FILES:
            shutil.copyfile(TOOLS / name, tools / name)
        return repo

    def _output_paths(self, repo: Path, key: str) -> tuple[Path, ...]:
        return tuple(repo / relative for relative in BUILDERS[key]["outputs"])

    def _receipt_paths(self, repo: Path, key: str) -> tuple[Path, Path]:
        builder = BUILDERS[key]
        return repo / builder["receipt"], repo / builder["sidecar"]

    def _publication_paths(self, repo: Path, key: str) -> tuple[Path, ...]:
        receipt, sidecar = self._receipt_paths(repo, key)
        return (*self._output_paths(repo, key), receipt, sidecar)

    def _assert_no_artifacts(self, repo: Path, key: str) -> None:
        for output in self._publication_paths(repo, key):
            self.assertFalse(output.exists() or output.is_symlink(), str(output))

    def _assert_no_attestation(self, repo: Path, key: str) -> None:
        receipt, sidecar = self._receipt_paths(repo, key)
        self.assertFalse(receipt.exists() or receipt.is_symlink(), str(receipt))
        self.assertFalse(sidecar.exists() or sidecar.is_symlink(), str(sidecar))

    def _ambient_go_traps(
        self,
        case: Path,
        repo: Path,
        key: str,
    ) -> tuple[Path, Path, Path, Path]:
        home = case / "ambient-home"
        path_bin = case / "ambient-path-bin"
        home_marker = case / "ambient-home-go-invoked"
        path_marker = case / "ambient-path-go-invoked"
        first_output = self._output_paths(repo, key)[0]
        trap_template = (
            "#!/bin/sh\n"
            "/bin/mkdir -p {parent}\n"
            "printf 'attacker artifact\\n' >{output}\n"
            "printf 'invoked\\n' >{marker}\n"
            "exit 0\n"
        )
        write_executable(
            home / ".local" / "toolchains" / "go1.27.1" / "bin" / "go",
            trap_template.format(
                parent=shlex.quote(str(first_output.parent)),
                output=shlex.quote(str(first_output)),
                marker=shlex.quote(str(home_marker)),
            ),
        )
        write_executable(
            path_bin / "go",
            trap_template.format(
                parent=shlex.quote(str(first_output.parent)),
                output=shlex.quote(str(first_output)),
                marker=shlex.quote(str(path_marker)),
            ),
        )
        return home, path_bin, home_marker, path_marker

    def _environment(self, case: Path, home: Path, path_bin: Path) -> dict[str, str]:
        work_tmp = case / "tmp"
        work_tmp.mkdir(exist_ok=True)
        return {
            "HOME": str(home),
            "PATH": f"{path_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(work_tmp),
            "LANG": "C",
            "LC_ALL": "C",
        }

    def _run(
        self,
        repo: Path,
        key: str,
        env: dict[str, str],
        arguments: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        script = repo / "tools" / Path(BUILDERS[key]["path"]).name
        return subprocess.run(
            ["/bin/bash", str(script), *arguments],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def _install_instrumented_custody(self, repo: Path) -> None:
        tools = repo / "tools"
        python_wrapper = tools / "release_python_archive_custody.sh"
        go_wrapper = tools / "release_go_archive_custody.sh"
        python_wrapper.write_text(
            textwrap.dedent(
                """\
                wins_release_python_prepare() { return 0; }
                wins_release_python_run() { /usr/bin/python3 -I -S "$@"; }
                wins_release_python_cleanup() { return 0; }
                """
            ),
            encoding="utf-8",
        )
        go_wrapper.write_text(
            textwrap.dedent(
                """\
                wins_release_go_prepare() {
                  WINS_RELEASE_GO_RUNTIME="${WINS_TEST_RUNTIME:?}"
                  WINS_RELEASE_GO_RUNTIME_ID=fixture-runtime-id
                  WINS_RELEASE_GO_ROOT="/Library/WinsVPN/ReleaseGo/${WINS_TEST_GO_VERSION:?}/extracted/go"
                  WINS_RELEASE_GO_TREE_SHA256="${WINS_TEST_GO_TREE_SHA256:?}"
                  WINS_RELEASE_GO_SHA256="${WINS_TEST_GO_EXECUTABLE_SHA256:?}"
                  export WINS_RELEASE_GO_RUNTIME WINS_RELEASE_GO_RUNTIME_ID
                  export WINS_RELEASE_GO_ROOT WINS_RELEASE_GO_TREE_SHA256
                  export WINS_RELEASE_GO_SHA256
                }
                wins_release_go_verify() {
                  if [[ -n "${WINS_TEST_FAIL_VERIFY_MARKER:-}" && -e "${WINS_TEST_FAIL_VERIFY_MARKER}" ]]; then
                    return 88
                  fi
                  return 0
                }
                wins_release_go_run() {
                  {
                    printf 'CALL:%s\\n' "$*"
                    /usr/bin/env | /usr/bin/sort
                    printf 'END\\n'
                  } >>"${WINS_TEST_GO_LOG:?}"
                  case "${1:-}" in
                    version)
                      printf 'go version go%s darwin/arm64\\n' "${WINS_TEST_GO_VERSION:?}"
                      return 0
                      ;;
                    test)
                      if [[ -n "${WINS_TEST_DRIFT_PATH:-}" ]]; then
                        printf '\\n// hostile source drift\\n' >>"${WINS_TEST_DRIFT_PATH}"
                        return 0
                      fi
                      if [[ -n "${WINS_TEST_SCRIPT_DRIFT_PATH:-}" ]]; then
                        printf '\\n# hostile producer drift\\n' >>"${WINS_TEST_SCRIPT_DRIFT_PATH}"
                      fi
                      if [[ -n "${WINS_TEST_CONTROL_DRIFT_PATH:-}" ]]; then
                        printf '\\n ' >>"${WINS_TEST_CONTROL_DRIFT_PATH}"
                      fi
                      [[ "${WINS_TEST_SUCCESSFUL_BUILD:-}" == 1 ]] || return 73
                      return 0
                      ;;
                    build)
                      [[ "${WINS_TEST_SUCCESSFUL_BUILD:-}" == 1 ]] || return 74
                      : "${WINS_TEST_BUILD_COUNTER:?}"
                      : "${WINS_TEST_ARTIFACT_TEMPLATE:?}"
                      local output="" previous="" count
                      for argument in "$@"; do
                        if [[ "${previous}" == -o ]]; then
                          output="${argument}"
                          break
                        fi
                        previous="${argument}"
                      done
                      [[ -n "${output}" ]] || return 76
                      count=0
                      if [[ -e "${WINS_TEST_BUILD_COUNTER}" ]]; then
                        IFS= read -r count <"${WINS_TEST_BUILD_COUNTER}" || return 77
                      fi
                      [[ "${count}" =~ ^[0-9]+$ ]] || return 78
                      count=$((count + 1))
                      printf '%s\n' "${count}" >"${WINS_TEST_BUILD_COUNTER}"
                      if [[ "${WINS_TEST_ONE_BUILD_ONLY_AT:-}" == "${count}" ]]; then
                        return 0
                      fi
                      /bin/cp "${WINS_TEST_ARTIFACT_TEMPLATE}" "${output}" || return 79
                      /bin/chmod 0755 "${output}" || return 80
                      if [[ "${WINS_TEST_SECOND_BUILD_DRIFT_AT:-}" == "${count}" ]]; then
                        printf X >>"${output}" || return 81
                      fi
                      if [[ "${WINS_TEST_PARTIAL_STAGE_AT:-}" == "${count}" ]]; then
                        : >"$(/usr/bin/dirname "${output}")/.native-receipt.stage" || return 82
                      fi
                      if [[ "${WINS_TEST_OVERWRITE_AT:-}" == "${count}" ]]; then
                        : "${WINS_TEST_OVERWRITE_TARGET:?}"
                        /bin/mkdir -p "$(/usr/bin/dirname "${WINS_TEST_OVERWRITE_TARGET}")" || return 83
                        printf 'attacker sentinel\n' >"${WINS_TEST_OVERWRITE_TARGET}" || return 84
                      fi
                      if [[ "${WINS_TEST_VERIFY_DRIFT_AT:-}" == "${count}" ]]; then
                        : "${WINS_TEST_FAIL_VERIFY_MARKER:?}"
                        : >"${WINS_TEST_FAIL_VERIFY_MARKER}" || return 85
                      fi
                      return 0
                      ;;
                    *) return 75 ;;
                  esac
                }
                wins_release_go_cleanup() { return 0; }
                """
            ),
            encoding="utf-8",
        )

        builder_paths = (
            tools / HELPER_BUILDER.name,
            tools / PROVISIONER_BUILDER.name,
        )
        for builder in builder_paths:
            if not builder.exists():
                continue
            source = builder.read_text(encoding="utf-8")
            self.assertIn(PYTHON_WRAPPER_SHA256, source)
            self.assertIn(GO_WRAPPER_SHA256, source)
            source = source.replace(PYTHON_WRAPPER_SHA256, sha256(python_wrapper), 1)
            source = source.replace(GO_WRAPPER_SHA256, sha256(go_wrapper), 1)
            builder.write_text(source, encoding="utf-8")
            builder.chmod(0o755)

    def _instrumented_environment(
        self,
        case: Path,
        home: Path,
        path_bin: Path,
    ) -> tuple[dict[str, str], Path, Path]:
        env = self._environment(case, home, path_bin)
        private_parent = Path("/private/tmp")
        if not private_parent.is_dir():
            private_parent = Path("/tmp")
        runtime = Path(tempfile.mkdtemp(prefix="wins-release-go.", dir=private_parent))
        self.addCleanup(shutil.rmtree, runtime, True)
        log = case / "go-custody.log"
        build_counter = case / "build-counter"
        verify_marker = case / "verify-drift"
        issuance = case / "owner-issuance.json"
        issuance.write_text("{}\n", encoding="ascii")
        env.update(
            {
                "WINS_GO_CUSTODY_ISSUANCE": str(issuance),
                "WINS_TEST_RUNTIME": str(runtime),
                "WINS_TEST_GO_VERSION": self.pin["version"],
                "WINS_TEST_GO_TREE_SHA256": self.pin["install_tree_sha256"][
                    "darwin_arm64"
                ],
                "WINS_TEST_GO_EXECUTABLE_SHA256": self.pin["executable_sha256"],
                "WINS_TEST_GO_LOG": str(log),
                "WINS_TEST_ARTIFACT_TEMPLATE": str(STATIC_LINUX_AMD64),
                "WINS_TEST_BUILD_COUNTER": str(build_counter),
                "WINS_TEST_FAIL_VERIFY_MARKER": str(verify_marker),
            }
        )
        return env, runtime, log

    def _successful_fixture(
        self,
        case: Path,
        key: str,
    ) -> tuple[Path, dict[str, str]]:
        repo = self._copy_fixture(case, key)
        self._install_instrumented_custody(repo)
        env, _runtime, _log = self._instrumented_environment(
            case,
            case / "home",
            case / "path",
        )
        env["WINS_TEST_SUCCESSFUL_BUILD"] = "1"
        return repo, env

    def _assert_receipt_bundle(self, repo: Path, key: str) -> bytes:
        builder = BUILDERS[key]
        receipt, sidecar = self._receipt_paths(repo, key)
        outputs = self._output_paths(repo, key)
        self.assertTrue(receipt.is_file() and not receipt.is_symlink())
        self.assertTrue(sidecar.is_file() and not sidecar.is_symlink())
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(sidecar.stat().st_mode), 0o444)
        receipt_bytes = receipt.read_bytes()
        self.assertTrue(receipt_bytes.endswith(b"\n"))
        self.assertTrue(receipt_bytes.isascii())
        self.assertNotIn(b".native-build.", receipt_bytes)
        self.assertNotIn(b"/tmp/", receipt_bytes)
        self.assertNotIn(b"WINS_", receipt_bytes)
        payload = strict_json(receipt_bytes)
        self.assertIsInstance(payload, dict)
        assert isinstance(payload, dict)
        self.assertEqual(
            set(payload),
            {
                "artifacts",
                "build_identity",
                "build_policy",
                "contract",
                "custody_controls",
                "producer",
                "schema_version",
                "source_tests",
                "target",
                "toolchain",
            },
        )
        self.assertEqual(payload["contract"], "winsvpn-gcloud-native-double-build-receipt-v1")
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(
            payload["target"],
            {
                "cgo_enabled": "0",
                "goamd64": "v1",
                "goarch": "amd64",
                "goos": "linux",
            },
        )
        identity_preimage = dict(payload)
        build_identity = identity_preimage.pop("build_identity")
        self.assertIsInstance(build_identity, str)
        self.assertEqual(
            build_identity,
            hashlib.sha256(canonical_json(identity_preimage)[:-1]).hexdigest(),
        )
        expected_sources = []
        for path, kind in zip(builder["labels"], builder["kinds"]):
            material = repo / path
            expected_sources.append(
                {
                    "bytes": material.stat().st_size,
                    "kind": kind,
                    "mode": f"{stat.S_IMODE(material.stat().st_mode):04o}",
                    "path": path,
                    "sha256": sha256(material),
                }
            )
        self.assertEqual(payload["source_tests"], expected_sources)
        expected_controls = []
        for name in CONTROL_FILES:
            material = repo / "tools" / name
            expected_controls.append(
                {
                    "bytes": material.stat().st_size,
                    "mode": f"{stat.S_IMODE(material.stat().st_mode):04o}",
                    "path": f"tools/{name}",
                    "sha256": sha256(material),
                }
            )
        self.assertEqual(payload["custody_controls"], expected_controls)
        producer = repo / builder["producer"]
        self.assertEqual(
            payload["producer"],
            {
                "bytes": producer.stat().st_size,
                "mode": f"{stat.S_IMODE(producer.stat().st_mode):04o}",
                "path": builder["producer"],
                "sha256": sha256(producer),
            },
        )
        self.assertEqual(
            payload["toolchain"],
            {
                "archive_platform": "darwin_arm64",
                "archive_sha256": self.pin["archive_sha256"]["darwin_arm64"],
                "custody_wrapper": "tools/release_go_archive_custody.sh",
                "executable": "bin/go",
                "executable_sha256": self.pin["executable_sha256"],
                "install_tree_sha256": self.pin["install_tree_sha256"]["darwin_arm64"],
                "root": f"/Library/WinsVPN/ReleaseGo/{self.pin['version']}/extracted/go",
                "version": self.pin["version"],
            },
        )
        self.assertIsInstance(payload["artifacts"], list)
        assert isinstance(payload["artifacts"], list)
        self.assertEqual(len(payload["artifacts"]), len(outputs))
        for output, record in zip(outputs, payload["artifacts"]):
            self.assertTrue(output.is_file() and not output.is_symlink())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o500)
            self.assertIsInstance(record, dict)
            assert isinstance(record, dict)
            digest = sha256(output)
            self.assertEqual(
                record,
                {
                    "bytes": output.stat().st_size,
                    "double_build": {
                        "first": {"bytes": output.stat().st_size, "sha256": digest},
                        "second": {"bytes": output.stat().st_size, "sha256": digest},
                    },
                    "mode": "0500",
                    "name": output.name,
                    "path": output.relative_to(repo).as_posix(),
                    "sha256": digest,
                },
            )
        self.assertIsInstance(payload["build_policy"], dict)
        assert isinstance(payload["build_policy"], dict)
        policy = payload["build_policy"]
        self.assertEqual(set(policy), {"host_tests", "linux_builds"})
        self.assertEqual(len(policy["host_tests"]), builder["host_test_count"])
        self.assertEqual(len(policy["linux_builds"]), builder["build_count"])
        for build in policy["linux_builds"]:
            self.assertEqual(build["environment"]["GOOS"], "linux")
            self.assertEqual(build["environment"]["GOARCH"], "amd64")
            self.assertEqual(build["environment"]["GOAMD64"], "v1")
            self.assertEqual(build["environment"]["CGO_ENABLED"], "0")
            self.assertTrue(build["environment"]["GOCACHE"].startswith("WORK/"))
            self.assertTrue(build["argv"][-2].startswith("WORK/"))
        self.assertEqual(
            sidecar.read_bytes(),
            f"{hashlib.sha256(receipt_bytes).hexdigest()}  {receipt.name}\n".encode("ascii"),
        )
        self.assertEqual(
            {entry.name for entry in receipt.parent.iterdir()},
            {*(path.name for path in outputs), receipt.name, sidecar.name},
        )
        return receipt_bytes

    def test_fake_custody_publishes_exact_canonical_double_build_receipts(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo, env = self._successful_fixture(case, key)
                completed = self._run(repo, key, env)
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr
                    + Path(env["WINS_TEST_GO_LOG"]).read_text(encoding="utf-8"),
                )
                first_receipt = self._assert_receipt_bundle(repo, key)
                first_snapshot = {
                    path: (sha256(path), stat.S_IMODE(path.stat().st_mode), path.stat().st_ino)
                    for path in self._publication_paths(repo, key)
                }
                Path(env["WINS_TEST_BUILD_COUNTER"]).unlink()
                repeated = self._run(repo, key, env)
                self.assertEqual(repeated.returncode, 0, repeated.stderr)
                self.assertEqual(self._assert_receipt_bundle(repo, key), first_receipt)
                self.assertEqual(
                    {
                        path: (
                            sha256(path),
                            stat.S_IMODE(path.stat().st_mode),
                            path.stat().st_ino,
                        )
                        for path in self._publication_paths(repo, key)
                    },
                    first_snapshot,
                )

    def test_receipts_have_no_workspace_or_timestamp_nondeterminism(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
                first_repo, first_env = self._successful_fixture(Path(first_name), key)
                second_repo, second_env = self._successful_fixture(Path(second_name), key)
                first = self._run(first_repo, key, first_env)
                second = self._run(second_repo, key, second_env)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(
                    self._assert_receipt_bundle(first_repo, key),
                    self._assert_receipt_bundle(second_repo, key),
                )

    def test_caller_authored_build_or_receipt_fields_are_refused(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                completed = self._run(
                    repo,
                    key,
                    self._environment(case, case / "home", case / "path"),
                    ("--receipt=caller-authored.json",),
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "caller-supplied build or receipt fields are refused",
                    completed.stderr,
                )
                self._assert_no_artifacts(repo, key)

    def test_omitted_source_test_or_custody_control_cannot_publish(self) -> None:
        for key, builder in BUILDERS.items():
            omitted = (
                ("source", builder["inputs"][0]),
                (
                    "test",
                    builder["inputs"][builder["kinds"].index("test")],
                ),
                ("custody-control", "toolchain-pins.json"),
            )
            for attack, name in omitted:
                with self.subTest(builder=key, attack=attack), tempfile.TemporaryDirectory() as temporary:
                    case = Path(temporary)
                    repo = self._copy_fixture(case, key)
                    (repo / "tools" / name).unlink()
                    completed = self._run(
                        repo,
                        key,
                        self._environment(case, case / "home", case / "path"),
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    expected = (
                        "reviewed source/test input is missing or symbolic"
                        if attack in {"source", "test"}
                        else "required custody input is missing or symbolic"
                    )
                    self.assertIn(expected, completed.stderr)
                    self._assert_no_artifacts(repo, key)

    def test_one_build_second_hash_script_and_toolchain_drift_leave_no_bundle(self) -> None:
        for key, builder in BUILDERS.items():
            attacks = (
                ("one-build-only", "WINS_TEST_ONE_BUILD_ONLY_AT", str(builder["build_count"])),
                ("altered-second-hash", "WINS_TEST_SECOND_BUILD_DRIFT_AT", "2"),
                (
                    "producer-script-drift",
                    "WINS_TEST_SCRIPT_DRIFT_PATH",
                    str(Path(builder["producer"])),
                ),
                (
                    "toolchain-pin-drift",
                    "WINS_TEST_CONTROL_DRIFT_PATH",
                    "tools/toolchain-pins.json",
                ),
            )
            for attack, variable, value in attacks:
                with self.subTest(builder=key, attack=attack), tempfile.TemporaryDirectory() as temporary:
                    case = Path(temporary)
                    repo, env = self._successful_fixture(case, key)
                    path_value = repo / value if value.startswith("tools/") else value
                    env[variable] = str(path_value)
                    completed = self._run(repo, key, env)
                    self.assertNotEqual(completed.returncode, 0, completed.stderr)
                    self._assert_no_artifacts(repo, key)

    def test_partial_publication_and_overwrite_race_leave_no_attestation(self) -> None:
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key, attack="partial-publication"), tempfile.TemporaryDirectory() as temporary:
                case = Path(temporary)
                repo, env = self._successful_fixture(case, key)
                env["WINS_TEST_PARTIAL_STAGE_AT"] = str(builder["build_count"])
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0, completed.stderr)
                self._assert_no_artifacts(repo, key)

            with self.subTest(builder=key, attack="overwrite-race"), tempfile.TemporaryDirectory() as temporary:
                case = Path(temporary)
                repo, env = self._successful_fixture(case, key)
                sentinel = self._output_paths(repo, key)[0]
                env["WINS_TEST_OVERWRITE_AT"] = str(builder["build_count"])
                env["WINS_TEST_OVERWRITE_TARGET"] = str(sentinel)
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(sentinel.read_bytes(), b"attacker sentinel\n")
                for output in self._output_paths(repo, key)[1:]:
                    self.assertFalse(output.exists() or output.is_symlink(), str(output))
                self._assert_no_attestation(repo, key)

    def test_missing_or_substituted_preexisting_receipt_bundle_is_never_republished(self) -> None:
        for key in BUILDERS:
            for attack in (
                "missing-receipt",
                "forged-receipt-and-sidecar",
                "sidecar-substitution",
                "artifact-drift",
            ):
                with self.subTest(builder=key, attack=attack), tempfile.TemporaryDirectory() as temporary:
                    case = Path(temporary)
                    repo, env = self._successful_fixture(case, key)
                    created = self._run(repo, key, env)
                    self.assertEqual(created.returncode, 0, created.stderr)
                    receipt, sidecar = self._receipt_paths(repo, key)
                    output = self._output_paths(repo, key)[0]
                    original_sidecar = sidecar.read_bytes()
                    original_receipt = receipt.read_bytes()

                    if attack == "missing-receipt":
                        receipt.unlink()
                    elif attack == "forged-receipt-and-sidecar":
                        forged = canonical_json({"forged": True})
                        receipt.chmod(0o644)
                        receipt.write_bytes(forged)
                        receipt.chmod(0o444)
                        sidecar.chmod(0o644)
                        sidecar.write_bytes(
                            f"{hashlib.sha256(forged).hexdigest()}  {receipt.name}\n".encode(
                                "ascii"
                            )
                        )
                        sidecar.chmod(0o444)
                    elif attack == "sidecar-substitution":
                        sidecar.chmod(0o644)
                        sidecar.write_bytes(
                            f"{'0' * 64}  {receipt.name}\n".encode("ascii")
                        )
                        sidecar.chmod(0o444)
                    else:
                        output.chmod(0o700)
                        output.write_bytes(output.read_bytes() + b"X")
                        output.chmod(0o500)

                    repeated = self._run(repo, key, env)
                    self.assertNotEqual(repeated.returncode, 0, repeated.stderr)
                    if attack == "missing-receipt":
                        self.assertFalse(receipt.exists() or receipt.is_symlink())
                        self.assertEqual(sidecar.read_bytes(), original_sidecar)
                    elif attack == "forged-receipt-and-sidecar":
                        self.assertEqual(receipt.read_bytes(), canonical_json({"forged": True}))
                        self.assertEqual(
                            sidecar.read_bytes(),
                            f"{hashlib.sha256(receipt.read_bytes()).hexdigest()}  {receipt.name}\n".encode(
                                "ascii"
                            ),
                        )
                    elif attack == "sidecar-substitution":
                        self.assertEqual(receipt.read_bytes(), original_receipt)
                        self.assertEqual(
                            sidecar.read_bytes(),
                            f"{'0' * 64}  {receipt.name}\n".encode("ascii"),
                        )
                    else:
                        self.assertTrue(output.read_bytes().endswith(b"X"))
                        self.assertEqual(receipt.read_bytes(), original_receipt)
                        self.assertEqual(sidecar.read_bytes(), original_sidecar)

    def test_shell_syntax_and_executable_modes(self) -> None:
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key):
                completed = subprocess.run(
                    ["/bin/bash", "-n", str(builder["path"])],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertTrue(builder["path"].stat().st_mode & stat.S_IXUSR)

    def test_exact_owner_go_pin_and_fd_bound_custody_are_required(self) -> None:
        self.assertEqual(self.pin["version"], "1.27.1")
        wrapper = GO_CUSTODY_WRAPPER.read_text(encoding="utf-8")
        controller = GO_CUSTODY_CONTROLLER.read_text(encoding="utf-8")
        self.assertIn("wins_release_go_run()", wrapper)
        self.assertIn("_wins_rg_python run", wrapper)
        self.assertIn('path = f"/dev/fd/{executable_fd}"', controller)
        self.assertIn("pass_fds=(image.executable_fd,)", controller)
        self.assertIn('"GOENV": "off"', controller)
        self.assertIn('"GOTOOLCHAIN": "local"', controller)
        self.assertIn('"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"', controller)
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key):
                source = builder["path"].read_text(encoding="utf-8")
                self.assertIn('source "${GO_CUSTODY_WRAPPER}"', source)
                self.assertIn("wins_release_go_prepare", source)
                self.assertIn("wins_release_go_verify", source)
                self.assertIn("wins_release_go_run version", source)
                self.assertIn(
                    'EXPECTED_GO_ROOT="/Library/WinsVPN/ReleaseGo/${REVIEWED_GO_VERSION}/extracted/go"',
                    source,
                )
                self.assertIn("WINS_GO_CUSTODY_ISSUANCE", source)

    def test_all_source_test_and_custody_control_digests_are_explicit(self) -> None:
        control_digests = tuple(sha256(TOOLS / name) for name in CONTROL_FILES)
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key):
                source = builder["path"].read_text(encoding="utf-8")
                self.assertEqual(
                    quoted_array(source, "INPUT_LABELS"),
                    builder["labels"],
                )
                self.assertEqual(
                    quoted_array(source, "INPUT_KINDS"),
                    builder["kinds"],
                )
                self.assertEqual(
                    quoted_array(source, "INPUT_EXPECTED_SHA256"),
                    tuple(sha256(TOOLS / name) for name in builder["inputs"]),
                )
                self.assertEqual(
                    quoted_array(source, "CUSTODY_CONTROL_SHA256"),
                    control_digests,
                )
                self.assertIn("reviewed source/test digest mismatch", source)
                self.assertIn("source/test input drift", source)
                self.assertIn("archive_sha256", source)
                self.assertIn("winsvpn-gcloud-native-double-build-receipt-v1", source)
                self.assertNotIn("find ${ROOT}/tools", source)

    def test_no_ambient_or_direct_go_execution_surface(self) -> None:
        direct_go = re.compile(
            r"(?m)^[ \t]*(?:(?:command|env)[ \t]+)?go[ \t]+(?:build|test|version|env)\b"
        )
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key):
                source = builder["path"].read_text(encoding="utf-8")
                self.assertIsNone(direct_go.search(source))
                self.assertNotIn("GO_BIN", source)
                self.assertNotIn(".local/toolchains", source)
                self.assertNotIn("command -v go", source)
                self.assertNotIn('"${HOME}"', source)
                self.assertIn("unset -f go", source)
                self.assertIn(
                    "WINS_RELEASE_GO executable path export is refused",
                    source,
                )

    def test_double_build_static_stripped_linux_amd64_contract(self) -> None:
        for key, builder in BUILDERS.items():
            with self.subTest(builder=key):
                source = builder["path"].read_text(encoding="utf-8")
                self.assertEqual(
                    source.count("build -a -buildmode=exe -pgo=off"),
                    builder["build_count"],
                )
                self.assertGreaterEqual(source.count("-trimpath"), builder["build_count"])
                self.assertGreaterEqual(source.count("-buildvcs=false"), builder["build_count"])
                self.assertEqual(
                    len(re.findall(r"-ldflags=(?:['\"])", source)),
                    builder["build_count"],
                )
                self.assertGreaterEqual(source.count("-s -w -buildid="), 2)
                self.assertIn("export CGO_ENABLED=0", source)
                self.assertIn('export GOOS="${target_os}" GOARCH="${target_arch}"', source)
                self.assertIn("export GOAMD64=v1", source)
                self.assertIn("ELF 64-bit LSB executable", source)
                self.assertIn("statically linked", source)
                self.assertIn('fail(label + " is not stripped")', source)
                self.assertIn("/usr/bin/cmp -s", source)
                self.assertIn("gocache", source)
                self.assertNotIn("/bin/mv -f", source)
                self.assertNotIn("/bin/ln --", source)
                self.assertIn("src_dir_fd=work_directory", source)
                self.assertIn("dst_dir_fd=artifact_directory", source)
                self.assertIn("os.O_EXCL", source)
                self.assertIn('getattr(os, "O_NOFOLLOW", 0)', source)
                self.assertIn("os.fsync(artifact_directory)", source)
                self.assertIn("partial or substituted publication bundle already exists", source)
                self.assertIn("rollback_created", source)

    def test_missing_owner_issuance_cannot_use_ambient_home_or_path_go(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                home, path_bin, home_marker, path_marker = self._ambient_go_traps(
                    case, repo, key
                )
                completed = self._run(
                    repo,
                    key,
                    self._environment(case, home, path_bin),
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("owner-blocked", completed.stderr)
                self.assertIn("issuance", completed.stderr)
                self.assertFalse(home_marker.exists())
                self.assertFalse(path_marker.exists())
                self._assert_no_artifacts(repo, key)

    def test_release_go_path_export_and_missing_custody_fail_closed(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                home, path_bin, home_marker, path_marker = self._ambient_go_traps(
                    case, repo, key
                )
                env = self._environment(case, home, path_bin)
                issuance = case / "issuance.json"
                issuance.write_text("{}\n", encoding="ascii")
                env["WINS_GO_CUSTODY_ISSUANCE"] = str(issuance)
                env["WINS_RELEASE_GO"] = str(path_bin / "go")
                exported = self._run(repo, key, env)
                self.assertNotEqual(exported.returncode, 0)
                self.assertIn("WINS_RELEASE_GO executable path export is refused", exported.stderr)
                self.assertFalse(home_marker.exists())
                self.assertFalse(path_marker.exists())
                self._assert_no_artifacts(repo, key)

                env.pop("WINS_RELEASE_GO")
                (repo / "tools" / "release_go_archive_custody.sh").unlink()
                missing = self._run(repo, key, env)
                self.assertNotEqual(missing.returncode, 0)
                self.assertIn("required custody input is missing", missing.stderr)
                self._assert_no_artifacts(repo, key)

    def test_regular_custody_replacement_and_source_symlink_are_rejected(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                marker = case / "replacement-wrapper-ran"
                replacement = repo / "tools" / "release_go_archive_custody.sh"
                replacement.write_text(
                    f"printf replacement >{shlex.quote(str(marker))}\n",
                    encoding="utf-8",
                )
                env = self._environment(case, case / "home", case / "path")
                env["WINS_GO_CUSTODY_ISSUANCE"] = str(case / "issuance.json")
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("custody control digest mismatch", completed.stderr)
                self.assertFalse(marker.exists())
                self._assert_no_artifacts(repo, key)

            with self.subTest(builder=key, attack="source-symlink"), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                source = repo / "tools" / BUILDERS[key]["inputs"][0]
                outside = case / "attacker.go"
                outside.write_text("package main\n", encoding="utf-8")
                source.unlink()
                source.symlink_to(outside)
                env = self._environment(case, case / "home", case / "path")
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("source/test input is missing or symbolic", completed.stderr)
                self._assert_no_artifacts(repo, key)

    def test_source_drift_after_snapshot_cannot_publish(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                self._install_instrumented_custody(repo)
                home, path_bin, home_marker, path_marker = self._ambient_go_traps(
                    case, repo, key
                )
                env, _runtime, _log = self._instrumented_environment(
                    case, home, path_bin
                )
                drift = repo / "tools" / BUILDERS[key]["inputs"][0]
                env["WINS_TEST_DRIFT_PATH"] = str(drift)
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("source/test input drift", completed.stderr)
                self.assertIn("hostile source drift", drift.read_text(encoding="utf-8"))
                self.assertFalse(home_marker.exists())
                self.assertFalse(path_marker.exists())
                self._assert_no_artifacts(repo, key)

    def test_hostile_go_environment_and_bash_function_are_sanitized(self) -> None:
        for key in BUILDERS:
            with self.subTest(builder=key), tempfile.TemporaryDirectory() as name:
                case = Path(name)
                repo = self._copy_fixture(case, key)
                self._install_instrumented_custody(repo)
                home, path_bin, home_marker, path_marker = self._ambient_go_traps(
                    case, repo, key
                )
                env, _runtime, log = self._instrumented_environment(
                    case, home, path_bin
                )
                bash_marker = case / "ambient-bash-go-invoked"
                bash_env = case / "bash-env"
                bash_env.write_text(
                    "go() { printf invoked >"
                    + shlex.quote(str(bash_marker))
                    + "; return 0; }\nexport -f go\n",
                    encoding="utf-8",
                )
                env.update(
                    {
                        "BASH_ENV": str(bash_env),
                        "GOROOT": str(case / "attacker-goroot"),
                        "GOPATH": str(case / "attacker-gopath"),
                        "GOENV": str(case / "attacker-goenv"),
                        "GOTOOLCHAIN": "auto",
                        "GOFLAGS": "-toolexec=attacker",
                        "GOWORK": str(case / "attacker.work"),
                        "GOCACHE": str(case / "attacker-cache"),
                        "CGO_ENABLED": "1",
                        "CC": str(case / "attacker-cc"),
                        "GOEXPERIMENT": "attacker",
                    }
                )
                completed = self._run(repo, key, env)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn("fd-bound reviewed Go command failed", completed.stderr)
                self.assertFalse(home_marker.exists())
                self.assertFalse(path_marker.exists())
                self.assertFalse(bash_marker.exists())
                self._assert_no_artifacts(repo, key)

                blocks = re.findall(r"(?ms)^CALL:(.*?)\n(.*?)^END$", log.read_text())
                test_environment = next(body for call, body in blocks if call.startswith("test "))
                for hostile in (
                    "GOROOT=",
                    "GOPATH=",
                    "GOFLAGS=",
                    "GOEXPERIMENT=",
                    "CC=",
                ):
                    self.assertNotIn(hostile, test_environment)
                self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin", test_environment)
                self.assertIn("CGO_ENABLED=0", test_environment)
                self.assertIn("GOPROXY=off", test_environment)
                self.assertIn("GOSUMDB=off", test_environment)
                self.assertIn("GOWORK=off", test_environment)
                self.assertIn("GOTELEMETRY=off", test_environment)
                self.assertIn("GOENV=off", test_environment)
                self.assertIn("GOTOOLCHAIN=local", test_environment)
                self.assertRegex(test_environment, r"(?m)^GOCACHE=.*\.native-build\.")
                self.assertRegex(test_environment, r"(?m)^GOMODCACHE=.*\.native-build\.")
                self.assertNotIn(str(home), test_environment)
                self.assertNotIn(str(path_bin), test_environment)


if __name__ == "__main__":
    unittest.main()
