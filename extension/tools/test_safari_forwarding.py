"""Offline executable tests for the standalone Safari native transport."""
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
APPLE = ROOT / 'apple/SafariProxy'


def compile_run(tmp_path, name, sources, extra=(), arguments=()):
    swift = shutil.which('swiftc')
    if not swift:
        pytest.fail('Safari native tests require the installed Swift compiler')
    binary = tmp_path / name
    command = [swift, '-swift-version', '5', '-module-cache-path', str(tmp_path / 'modules'),
               '-o', str(binary), *[str(APPLE / p) for p in sources], *extra]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([str(binary), *arguments], capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stderr
    expected = {'runtime': 'PASS: real Swift/C stack',
                'broker': 'Safari DNS broker wire and loopback checks passed',
                'session': 'Safari session offline tests passed: 77 assertions'}[name]
    assert expected in result.stdout, result.stdout


def test_real_stack_swift_abi_and_dns(tmp_path):
    archive = APPLE / 'Artifacts/Engine/libSafariWinn-macos-arm64.a'
    assert archive.is_file(), 'Build the pinned offline combined engine first'
    compile_run(tmp_path, 'runtime', [
        'Shared/SafariForwardError.swift', 'Shared/WinnPacketABI.swift',
        'Shared/SafariPacketRuntime.swift', 'Shared/SafariDNSWire.swift', 'Tests/SafariRuntimeTests.swift',
    ], ['-Xlinker', '-force_load', '-Xlinker', str(archive), '-Xlinker', '-export_dynamic',
        '-lresolv', '-framework', 'Security', '-framework', 'CoreFoundation'])


def test_authenticated_dns_loopback(tmp_path):
    compile_run(tmp_path, 'broker', ['Shared/SafariDNSBroker.swift', 'Tests/SafariDNSBrokerTests.swift'])


def test_hub_session_contract_offline(tmp_path):
    legal = plistlib.loads((APPLE / 'Resources/Legal.plist').read_bytes())
    body = tmp_path / 'legal.txt'
    body.write_text(legal['body'])
    compile_run(tmp_path, 'session', ['Shared/SafariHubTrustAnchors.swift', 'Shared/SafariHubSession.swift',
        'Shared/SafariPinnedHubTransport.swift', 'Tests/SafariHubSessionTests.swift'], arguments=[str(body)])


def test_session_lifecycle_regressions(tmp_path):
    result = subprocess.run([sys.executable, '-B', str(APPLE / 'Tools/verify_session_lifecycle.py'),
        '--source-root', str(ROOT), '--output-dir', str(tmp_path)],
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS repeated Disconnect is coalesced' in result.stdout
    assert 'PASS foreign DNS and transparent managers untouched' in result.stdout


def test_provider_lifecycle_regressions(tmp_path):
    result = subprocess.run([sys.executable, '-B', str(APPLE / 'Tools/verify_provider_lifecycle.py'),
        '--source-root', str(ROOT), '--output-dir', str(tmp_path)],
        capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS coordinated DNS and transparent startup' in (tmp_path / 'providers-run.log').read_text()
    assert 'AAAA-only and IPv4-only resolution' in (tmp_path / 'dns-wire-run.log').read_text()
