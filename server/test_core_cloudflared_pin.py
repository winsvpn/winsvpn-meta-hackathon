from __future__ import annotations

import hashlib
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "server/wins_core_server_setup_ONETOUCH.sh"
PATCH = ROOT / "server/vendor/cloudflared-2026.10.0-security.patch"
REVIEW = ROOT / "server/vendor/cloudflared-2026.10.0-security-review.md"
EXPECTED_PATCH_SHA256 = "8ec5ecde3a9ded36d10800b9cc0457264a7aee7e083e5eaf7e4cba76dcf8493d"
EXPECTED_REVIEW_SHA256 = "4cd9ddd0cb26a8d3e9a2e6e1d601e9b9973fb7989794b059a498946fd0c376d6"


def source() -> str:
    return CORE.read_text(encoding="utf-8")


def constant(name: str) -> str:
    match = re.search(rf'^{name}="\$\{{{name}:-([^}}]+)\}}"$', source(), re.MULTILINE)
    assert match is not None, name
    return match.group(1)


def install_body() -> str:
    text = source()
    start = text.index("install_cloudflared_package() {")
    end = text.index("\npersist_core_token() {", start)
    return text[start:end]


def test_both_architectures_have_distinct_toolchain_and_output_pins() -> None:
    expected = {
        "CLOUDFLARED_GO_AMD64_SHA256": "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
        "CLOUDFLARED_GO_ARM64_SHA256": "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec",
        "CLOUDFLARED_SOURCE_SHA256": "303c531b416b986bfcc2157c0a90556c94c519ec4d71e64d32abbe5c451f59ec",
        "CLOUDFLARED_AMD64_SHA256": "6205d546fbca7fe372db923580daf8217a0b7107d371b602d20e4311879e1a27",
        "CLOUDFLARED_ARM64_SHA256": "94ec9925148b1e13ac07a664549d5d052f09857e91db0ba570fbd6322afa1c0d",
    }
    assert constant("CLOUDFLARED_GO_VERSION") == "1.27.1"
    assert constant("CLOUDFLARED_SOURCE_COMMIT") == "18cdfe0a6fc7b72a0702d255a1f984e776ce0498"
    for name, digest in expected.items():
        assert constant(name) == digest
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_tampered_security_patch_cannot_match_the_reviewed_pin() -> None:
    patch = PATCH.read_bytes()
    assert hashlib.sha256(patch).hexdigest() == EXPECTED_PATCH_SHA256
    assert hashlib.sha256(patch + b"\n# hostile mutation\n").hexdigest() != EXPECTED_PATCH_SHA256
    assert constant("CLOUDFLARED_PATCH_SHA256") == EXPECTED_PATCH_SHA256
    review = REVIEW.read_bytes()
    assert hashlib.sha256(review).hexdigest() == EXPECTED_REVIEW_SHA256
    assert constant("CLOUDFLARED_REVIEW_SHA256") == EXPECTED_REVIEW_SHA256


def test_dependency_patch_is_data_only_and_updates_every_reviewed_module() -> None:
    patch = PATCH.read_text(encoding="utf-8")
    assert "diff --git a/go.mod b/go.mod" in patch
    assert "diff --git a/go.sum b/go.sum" in patch
    # 2026.10.0 already carries x/net, x/sys, x/term and x/text at fixed
    # versions, so the patch is reduced to the two modules upstream still lags on.
    for fixed in (
        "github.com/klauspost/compress v1.18.7",
        "golang.org/x/crypto v0.56.0",
    ):
        assert f"+\t{fixed}" in patch
    assert "+go 1.26.0" in patch
    for superseded in ("golang.org/x/net", "golang.org/x/sys", "golang.org/x/term", "golang.org/x/text"):
        assert f"+\t{superseded} " not in patch, superseded


def test_source_patch_toolchain_module_and_output_checks_precede_publication() -> None:
    body = install_body()
    ordered = (
        '"${CLOUDFLARED_PATCH_SHA256}" "${patch_file}"',
        '"${CLOUDFLARED_REVIEW_SHA256}" "${review_file}"',
        '"${CLOUDFLARED_SOURCE_SHA256}" "${source_archive}"',
        '"${CLOUDFLARED_PATCHED_GOMOD_SHA256}" "${work_dir}/source/go.mod"',
        '"${CLOUDFLARED_RESOLVED_GOSUM_SHA256}" "${work_dir}/source/go.sum"',
        '"${go_sha}" "${go_archive}"',
        '"${CLOUDFLARED_RESOLVED_GOSUM_SHA256}" go.sum',
        '"${work_dir}/go/bin/go" build',
        '"${output_sha}" "${build_output}"',
        'mv -f -- "${install_tmp}" "${install_path}"',
    )
    positions = [body.index(item) for item in ordered]
    assert positions == sorted(positions)
    assert "export GOFLAGS=-mod=readonly" in body
    assert '"${work_dir}/go/bin/go" mod verify' in body
    assert "export GOPRIVATE=" in body
    assert "export GONOSUMDB=" in body
    assert "export GONOPROXY=" in body
    assert "export GOENV=off" in body
    assert "export GOEXPERIMENT=" in body
    assert "export GOFIPS140=off" in body


def test_distro_package_is_removed_even_when_reviewed_bytes_already_exist() -> None:
    body = install_body()
    package_removal = body.index("apt_retry \"${APT_GET[@]}\" remove -y cloudflared")
    fast_path = body.index('if [[ -f "${install_path}"')
    assert package_removal < fast_path


def test_scan_disposition_is_bound_to_the_exact_module_set() -> None:
    review = REVIEW.read_text(encoding="utf-8")
    for advisory in ("GO-2026-5932", "GO-2026-6354", "GO-2026-6355", "GO-2026-5841"):
        assert advisory in review
    assert "golang.org/x/crypto` v0.55.0 to v0.56.0" in review
    assert "Review-by: 2026-10-13 UTC" in review
    assert constant("CLOUDFLARED_SOURCE_COMMIT") in review
    assert constant("CLOUDFLARED_PATCHED_GOMOD_SHA256") in review
    assert constant("CLOUDFLARED_RESOLVED_GOSUM_SHA256") in review
    assert constant("CLOUDFLARED_GO_AMD64_SHA256") in review
    assert constant("CLOUDFLARED_GO_ARM64_SHA256") in review
    assert EXPECTED_PATCH_SHA256 in review
    # The review states what was NOT verified; dropping that section would turn
    # a partial disposition into an apparent full one.
    assert "## Not yet verified" in review


def test_core_cannot_fall_back_to_the_known_flagged_package_bytes() -> None:
    text = source()
    body = install_body()
    assert "pkg.cloudflare.com/cloudflared/pool/" not in body
    assert 'dpkg -i "${package_file}"' not in body
    assert "c805c7c8102190c04dfc16e3b4cc4acc9007d5b19b3afbcd608ea6fed7645a43" not in text
    assert "096739c69f62cace40b144f0e6c81e61333f3d320ce07a265c7b17b5e925731c" not in text
    assert "ExecStart=/usr/local/bin/cloudflared --no-autoupdate tunnel run" in text
    assert "ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run" not in text
