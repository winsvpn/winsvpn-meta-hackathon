#!/usr/bin/env python3
"""Hostile fail-closed tests for website CSP regeneration and deploy preflight.

Exercises web/update_style_csp.py and web/verify_inline_csp.py against isolated
fixtures only. Never writes repository web/_headers, web/_worker.js, or
web/index.html, and never contacts the live site.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
UPDATER_PATH = ROOT / "web" / "update_style_csp.py"
VERIFIER_PATH = ROOT / "web" / "verify_inline_csp.py"
REPO_WEB = ROOT / "web"
REPO_WEB_FILES = ("index.html", "_headers", "_worker.js")

STYLE = "body{color:red}"
SCRIPT = 'console.log("ok");'
LDJSON = '{"@context":"https://schema.org"}'
NONHASH = "https://www.paypal.com"
REDACTED = "sha256-<REDACTED_WG_KEY>"
EXTRA_HASH = "sha256-" + ("A" * 43) + "="


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UPDATER = _load("update_style_csp", UPDATER_PATH)
VERIFIER = _load("verify_inline_csp", VERIFIER_PATH)


def sha(body: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")


def file_sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def html_doc(style: str = STYLE, script: str = SCRIPT,
             ldjson: str = LDJSON) -> str:
    return (
        "<!doctype html><html><head><style>%s</style></head>"
        "<body><script>%s</script>"
        "<script type=\"application/ld+json\">%s</script>"
        "</body></html>"
    ) % (style, script, ldjson)


def expected_pins(html: str) -> tuple[str, list[str]]:
    styles, scripts = VERIFIER.inline_blocks(html)
    return sha(styles[0]), sorted(sha(body) for _, body in scripts)


def policy_text(style_hashes: list[str], script_hashes: list[str],
                extra_script_src: str = NONHASH) -> str:
    style_part = " ".join("'%s'" % h for h in style_hashes)
    script_part = " ".join("'%s'" % h for h in script_hashes)
    extra = (" " + extra_script_src) if extra_script_src else ""
    return (
        "default-src 'self'; "
        "style-src 'self' %s; "
        "script-src 'self' %s%s;"
    ) % (style_part, script_part, extra)


def headers_file(policy: str) -> str:
    return "/*\n  Content-Security-Policy: %s\n" % policy


def worker_file(policy: str) -> str:
    return (
        "// script-src/style-src hashes below must exactly match\n"
        "const CONTENT_SECURITY_POLICY =\n"
        "  \"%s\";\n"
    ) % policy


def joined_errors(errors: list[str]) -> str:
    return "\n".join(errors)


class WebsiteCspDeployGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.repo_before = {
            name: file_sha(REPO_WEB / name) for name in REPO_WEB_FILES
        }

    def tearDown(self) -> None:
        after = {name: file_sha(REPO_WEB / name) for name in REPO_WEB_FILES}
        self.assertEqual(
            self.repo_before, after,
            "repository web/_headers, web/_worker.js, or web/index.html changed")

    def make_web(
            self,
            *,
            html: str | None = None,
            style_pins: list[str] | None = None,
            script_pins: list[str] | None = None,
            worker_style_pins: list[str] | None = None,
            worker_script_pins: list[str] | None = None,
            extra_script_src: str = NONHASH,
            worker_extra_script_src: str | None = None,
            name: str = "site") -> pathlib.Path:
        html = html_doc() if html is None else html
        style_hash, script_hashes = expected_pins(html)
        if style_pins is None:
            style_pins = [style_hash]
        if script_pins is None:
            script_pins = list(script_hashes)
        if worker_style_pins is None:
            worker_style_pins = list(style_pins)
        if worker_script_pins is None:
            worker_script_pins = list(script_pins)
        if worker_extra_script_src is None:
            worker_extra_script_src = extra_script_src
        web = self.root / name
        web.mkdir()
        (web / "index.html").write_text(html, encoding="utf-8")
        (web / "_headers").write_text(
            headers_file(policy_text(
                style_pins, script_pins, extra_script_src)),
            encoding="utf-8")
        (web / "_worker.js").write_text(
            worker_file(policy_text(
                worker_style_pins, worker_script_pins,
                worker_extra_script_src)),
            encoding="utf-8")
        return web

    def assert_fail_preflight(self, web: pathlib.Path, *needles: str) -> str:
        errors = VERIFIER.check(web)
        blob = joined_errors(errors)
        self.assertTrue(errors, "preflight unexpectedly passed")
        for needle in needles:
            self.assertIn(needle, blob)
        return blob

    def assert_pass_preflight(self, web: pathlib.Path) -> None:
        errors = VERIFIER.check(web)
        self.assertEqual(errors, [], joined_errors(errors))
        self.assertEqual(VERIFIER.main([str(web)]), 0)

    def assert_exact_pins(self, web: pathlib.Path) -> None:
        html = (web / "index.html").read_text(encoding="utf-8")
        style_hash, script_hashes = expected_pins(html)
        for host in (web / "_headers", web / "_worker.js"):
            text = host.read_text(encoding="utf-8")
            self.assertNotIn("REDACTED", text)
            self.assertNotIn(EXTRA_HASH, text)
            self.assertEqual(
                VERIFIER.pinned_hashes(text, "style-src"), {style_hash})
            self.assertEqual(
                VERIFIER.pinned_hashes(text, "script-src"), set(script_hashes))
            self.assertIn(NONHASH, text)
        headers_policy = VERIFIER.policy_texts(
            (web / "_headers").read_text(encoding="utf-8"))[0]
        worker_policy = VERIFIER.policy_texts(
            (web / "_worker.js").read_text(encoding="utf-8"))[0]
        self.assertEqual(headers_policy, worker_policy)

    def test_import_does_not_write_repository_web(self) -> None:
        before = dict(self.repo_before)
        _load("update_style_csp_reload", UPDATER_PATH)
        _load("verify_inline_csp_reload", VERIFIER_PATH)
        after = {name: file_sha(REPO_WEB / name) for name in REPO_WEB_FILES}
        self.assertEqual(before, after)

    def test_repository_web_preflight_currently_passes(self) -> None:
        self.assert_pass_preflight(REPO_WEB)
        for host in (REPO_WEB / "_headers", REPO_WEB / "_worker.js"):
            text = host.read_text(encoding="utf-8")
            self.assertNotIn("REDACTED", text)
            self.assertNotIn("sha256-<", text)
            for pin in (VERIFIER.pinned_hashes(text, "style-src")
                        | VERIFIER.pinned_hashes(text, "script-src")):
                self.assertRegex(pin, r"^sha256-[A-Za-z0-9+/]{43}=$")

    def test_redacted_placeholder_is_rejected_then_replaced(self) -> None:
        web = self.make_web(
            style_pins=[REDACTED],
            script_pins=[REDACTED, REDACTED],
        )
        self.assert_fail_preflight(web, "placeholder", REDACTED)
        UPDATER.sync_web_dir(web)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)

    def test_secret_scrubber_package_cannot_pass_preflight(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[REDACTED],
            script_pins=[REDACTED, EXTRA_HASH],
        )
        self.assert_fail_preflight(
            web, "placeholder", "redacted", EXTRA_HASH)
        self.assertNotEqual(
            VERIFIER.pinned_hashes(
                (web / "_headers").read_text(encoding="utf-8"), "style-src"),
            {style_hash})
        proc = subprocess.run(
            [sys.executable, str(VERIFIER_PATH), str(web)],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("placeholder", proc.stderr)
        UPDATER.sync_web_dir(web)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)
        self.assertEqual(
            VERIFIER.pinned_hashes(
                (web / "_headers").read_text(encoding="utf-8"), "script-src"),
            set(script_hashes))

    def test_duplicate_hashes_fail_closed_then_collapse(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[style_hash, style_hash],
            script_pins=script_hashes + script_hashes,
        )
        self.assert_fail_preflight(web, "duplicate")
        UPDATER.sync_web_dir(web)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)
        headers = (web / "_headers").read_text(encoding="utf-8")
        self.assertEqual(
            headers.count("'%s'" % style_hash), 1)

    def test_extra_hashes_fail_closed_and_are_stripped(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[style_hash, EXTRA_HASH],
            script_pins=script_hashes + [EXTRA_HASH],
        )
        self.assert_fail_preflight(web, EXTRA_HASH, "no current inline")
        UPDATER.sync_web_dir(web)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)

    def test_worker_static_divergence_fails_preflight(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[style_hash],
            script_pins=script_hashes,
            worker_style_pins=[REDACTED],
            worker_script_pins=[EXTRA_HASH],
        )
        self.assert_fail_preflight(
            web, "diverge", "placeholder", EXTRA_HASH)
        UPDATER.sync_web_dir(web)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)

    def test_nonhash_policy_divergence_is_rejected_not_rewritten(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[REDACTED],
            script_pins=[REDACTED],
            extra_script_src=NONHASH,
            worker_extra_script_src="https://example.invalid",
        )
        before_headers = (web / "_headers").read_bytes()
        before_worker = (web / "_worker.js").read_bytes()
        self.assert_fail_preflight(web, "diverge")
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(web)
        self.assertIn("unapproved fallback", str(ctx.exception))
        self.assertEqual((web / "_headers").read_bytes(), before_headers)
        self.assertEqual((web / "_worker.js").read_bytes(), before_worker)

    def test_unapproved_fallback_origins_fail_closed(self) -> None:
        unsafe = (
            "*", "http:", "https:", "data:", "blob:",
            "http://attacker.invalid", "https://attacker.invalid",
            "'unsafe-inline'", "'unsafe-eval'",
        )
        for number, source in enumerate(unsafe):
            with self.subTest(source=source):
                web = self.make_web(
                    extra_script_src=source, name="unsafe-%d" % number)
                before = {
                    name: (web / name).read_bytes()
                    for name in ("_headers", "_worker.js")
                }
                self.assert_fail_preflight(web, "unapproved fallback", source)
                with self.assertRaises(UPDATER.CspUpdateError) as ctx:
                    UPDATER.sync_web_dir(web)
                self.assertIn("unapproved fallback", str(ctx.exception))
                self.assertEqual(
                    {name: (web / name).read_bytes() for name in before}, before)

    def test_duplicate_nonfinite_and_malformed_policy_fail_closed(self) -> None:
        cases = (
            ("duplicate", "%s script-src 'self';"),
            ("non-finite", "%s connect-src 'self' Infinity;"),
            ("non-finite", "%s connect-src 'self' 1e400;"),
            ("malformed", "%s Script-Src 'self';"),
        )
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        original_policy = policy_text([style_hash], script_hashes)
        for number, (needle, template) in enumerate(cases):
            with self.subTest(case=needle):
                web = self.make_web(html=html, name="malformed-%d" % number)
                bad_policy = template % original_policy
                (web / "_headers").write_text(
                    headers_file(bad_policy), encoding="utf-8")
                (web / "_worker.js").write_text(
                    worker_file(bad_policy), encoding="utf-8")
                self.assert_fail_preflight(web, needle)
                before = {
                    name: (web / name).read_bytes()
                    for name in ("_headers", "_worker.js")
                }
                with self.assertRaises(UPDATER.CspUpdateError):
                    UPDATER.sync_web_dir(web)
                self.assertEqual(
                    {name: (web / name).read_bytes() for name in before}, before)

    def test_external_script_src_is_case_and_space_insensitive(self) -> None:
        external = (
            '<script SRC = "https://attacker.invalid/external.js">'
            '</script>')
        html = html_doc() + external
        styles, scripts = VERIFIER.inline_blocks(html)
        self.assertEqual(len(styles), 1)
        self.assertEqual(len(scripts), 2)
        web = self.make_web(html=html)
        self.assert_pass_preflight(web)

    def test_invalid_utf8_config_fails_without_traceback(self) -> None:
        web = self.make_web()
        (web / "_headers").write_bytes(b"\xff\xfe\x00")
        self.assert_fail_preflight(web, "not valid UTF-8")
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(web)
        self.assertIn("not valid UTF-8", str(ctx.exception))

    def test_partial_rewrite_rolls_back(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        original_headers = (web / "_headers").read_bytes()
        original_worker = (web / "_worker.js").read_bytes()
        real = UPDATER.os.replace

        def boom(src, dst, *args, **kwargs):
            if os.path.basename(str(dst)) == "_worker.js":
                raise OSError("injected replace failure")
            return real(src, dst, *args, **kwargs)

        with mock.patch.object(UPDATER.os, "replace", boom):
            with self.assertRaises(UPDATER.CspUpdateError) as ctx:
                UPDATER.sync_web_dir(web)
        self.assertIn("partial rewrite", str(ctx.exception))
        self.assertIn("original bytes restored", str(ctx.exception))
        self.assertEqual((web / "_headers").read_bytes(), original_headers)
        self.assertEqual((web / "_worker.js").read_bytes(), original_worker)
        self.assert_fail_preflight(web, "placeholder")

    def test_symlink_substitution_is_rejected(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        outside = self.root / "outside_headers"
        payload = b"OUTSIDE-NOT-A-POLICY\n"
        outside.write_bytes(payload)
        headers = web / "_headers"
        headers.unlink()
        try:
            headers.symlink_to(outside)
        except OSError as exc:
            self.skipTest("symlinks unavailable: %s" % exc)
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(web)
        self.assertIn("symbolic link", str(ctx.exception))
        self.assertEqual(outside.read_bytes(), payload)
        self.assert_fail_preflight(web, "symbolic link")
        self.assertTrue(headers.is_symlink())
        self.assertEqual(outside.read_bytes(), payload)

    def test_hardlink_substitution_is_rejected(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        outside = self.root / "outside_hardlink"
        headers = web / "_headers"
        original = headers.read_bytes()
        outside.write_bytes(original)
        headers.unlink()
        try:
            os.link(outside, headers)
        except OSError as exc:
            self.skipTest("hardlinks unavailable: %s" % exc)
        marker = original + b"#MUTATED"
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(web)
        self.assertIn("hard link", str(ctx.exception))
        self.assert_fail_preflight(web, "hard link")
        self.assertEqual(outside.read_bytes(), original)
        headers.write_bytes(marker)
        self.assertEqual(outside.read_bytes(), marker)

    def test_relative_path_substitution_is_rejected(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        outside_dir = self.root / "escape"
        outside_dir.mkdir()
        target = outside_dir / "_headers"
        marker = b"ESCAPED-TARGET\n"
        target.write_bytes(marker)
        headers = web / "_headers"
        headers.unlink()
        rel = pathlib.Path(os.path.relpath(target, headers.parent))
        try:
            headers.symlink_to(rel)
        except OSError as exc:
            self.skipTest("symlinks unavailable: %s" % exc)
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(web)
        self.assertIn("symbolic link", str(ctx.exception))
        self.assertEqual(target.read_bytes(), marker)
        self.assert_fail_preflight(web, "symbolic link")
        self.assertEqual(target.read_bytes(), marker)
        self.assertEqual(
            {name: file_sha(REPO_WEB / name) for name in REPO_WEB_FILES},
            self.repo_before)

    def test_symlinked_web_dir_is_rejected(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        alias = self.root / "alias_web"
        try:
            alias.symlink_to(web, target_is_directory=True)
        except OSError as exc:
            self.skipTest("directory symlinks unavailable: %s" % exc)
        before_headers = (web / "_headers").read_bytes()
        with self.assertRaises(UPDATER.CspUpdateError) as ctx:
            UPDATER.sync_web_dir(alias)
        self.assertIn("real directory", str(ctx.exception))
        self.assertEqual((web / "_headers").read_bytes(), before_headers)
        errors = VERIFIER.check(alias)
        self.assertTrue(any("real directory" in item for item in errors), errors)

    def test_source_mutation_during_preflight_fails_closed(self) -> None:
        html = html_doc()
        style_hash, script_hashes = expected_pins(html)
        web = self.make_web(
            html=html,
            style_pins=[style_hash],
            script_pins=script_hashes,
        )
        index = web / "index.html"
        original = index.read_bytes()
        real = VERIFIER._read_regular
        state = {"n": 0}

        def wrapped(path, web_dir):
            data = real(path, web_dir)
            if path.name == "index.html":
                state["n"] += 1
                if state["n"] == 1:
                    index.write_bytes(original + b" ")
            return data

        with mock.patch.object(VERIFIER, "_read_regular", wrapped):
            errors = VERIFIER.check(web)
        self.assertTrue(
            any("mutated during preflight" in item for item in errors),
            errors)

    def test_updater_source_mutation_before_commit_fails_closed(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[REDACTED])
        original_headers = (web / "_headers").read_bytes()
        original_worker = (web / "_worker.js").read_bytes()
        index = web / "index.html"
        real = UPDATER._read_regular
        state = {"n": 0}

        def wrapped(path, web_dir):
            data = real(path, web_dir)
            if path.name == "index.html":
                state["n"] += 1
                if state["n"] == 1:
                    html = index.read_text(encoding="utf-8")
                    index.write_text(
                        html.replace(STYLE, STYLE + "x"), encoding="utf-8")
            return data

        with mock.patch.object(UPDATER, "_read_regular", wrapped):
            with self.assertRaises(UPDATER.CspUpdateError) as ctx:
                UPDATER.sync_web_dir(web)
        self.assertIn("mutated", str(ctx.exception))
        self.assertEqual((web / "_headers").read_bytes(), original_headers)
        self.assertEqual((web / "_worker.js").read_bytes(), original_worker)

    def test_cli_updater_rewrites_fixture_not_repository(self) -> None:
        web = self.make_web(style_pins=[REDACTED], script_pins=[EXTRA_HASH])
        proc = subprocess.run(
            [sys.executable, str(UPDATER_PATH), str(web)],
            capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assert_pass_preflight(web)
        self.assert_exact_pins(web)
        self.assertEqual(
            {name: file_sha(REPO_WEB / name) for name in REPO_WEB_FILES},
            self.repo_before)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
