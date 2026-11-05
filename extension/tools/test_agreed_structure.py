"""EXT-27/29/32: adversarial manifest, HTML and leakscan controls."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checks
import leakscan


@pytest.mark.parametrize("markup", ['<script data-src="x.js"></script>', '<script title="src=x.js"></script>', '<script src=""></script>', '<script src="x.js" src="y.js"></script>', '<script src=" "></script>'])
def test_invalid_script_attribute_refused(markup):
    parser = checks.ScriptSourceCheck()
    parser.feed(markup)
    parser.close()
    assert parser.invalid_scripts == 1


def test_external_script_and_exact_csp():
    parser = checks.ScriptSourceCheck()
    parser.feed('<script type="module" src="x.js"></script>')
    parser.close()
    assert parser.invalid_scripts == 0
    assert checks.parse_csp_directives("script-src 'self'; script-src 'self'") is None
    assert checks.parse_csp_directives("script-src 'self' https://example.test") != checks.REVIEWED_EXTENSION_PAGES_CSP


def test_normalized_scan_is_deduplicated(tmp_path):
    path = tmp_path / "fixture.js"
    path.write_text('const f = globalThis.fetch; const u = "https:" + "//example.net/";')
    findings = leakscan.scan_file(path, tmp_path)
    keys = [(finding.path, finding.kind, finding.detail) for finding in findings]
    assert len(keys) == len(set(keys))
    assert any(finding.kind == "remote URL" for finding in findings)
    assert any("fetch" in finding.detail for finding in findings)

