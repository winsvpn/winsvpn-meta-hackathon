#!/usr/bin/env python3
"""Run requested local checks, retaining each exit code and normalized log."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
RESULTS = []
MUTEX = threading.Lock()


def run(command, name, cwd=ROOT, mandatory=True, timeout=900):
    start = time.monotonic()
    stamp = datetime.now(timezone.utc).isoformat()
    try:
        result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        code, output = result.returncode, result.stdout
    except subprocess.TimeoutExpired as exc:
        code, output = 124, (exc.stdout or b'') + b'\nCHECK TIMEOUT\n'
    output = output.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    log = OUT / (name + '.log')
    log.write_bytes(output)
    item = dict(command=command, display=shlex.join(command), cwd=str(cwd),
                started_at=stamp, seconds=round(time.monotonic() - start, 2),
                exit_code=code, mandatory=mandatory, log=str(log.relative_to(ROOT)))
    with MUTEX:
        RESULTS.append(item)
        temporary = OUT / 'check-results.tmp'
        temporary.write_text(json.dumps(RESULTS, indent=2) + '\n')
        temporary.replace(OUT / 'check-results.json')
        print(name, 'PASS' if code == 0 else f'FAIL({code})', flush=True)


def flutter():
    lock = ROOT / '.dart_tool/winsvpn-release-build.lock'
    lock.mkdir()
    owner = lock / 'owner.txt'
    owner.write_text(f'Round 12 local verification PID={os.getpid()}\n')
    try:
        run(['flutter', 'analyze', '--no-pub'], 'flutter-analyze')
        run(['flutter', 'test', '--no-pub'], 'flutter-test')
    finally:
        owner.unlink()
        lock.rmdir()


def server():
    names = ['test_control_plane_deepseek_round2']
    names += [f'test_control_plane_round{n}' for n in range(4, 12)]
    names += ['test_winn3_descriptor_hub', 'test_account_deletion_hub', 'test_donor_acknowledgment_hub']
    for name in names:
        run(['python3', f'server/{name}.py'], name)


def platform():
    for name in ['website_security_audit', 'verify_apple_method_channel_contract',
                 'test_apple_standalone_v3_wiring', 'test_windows_awg_runtime_validation']:
        run(['python3', f'tools/{name}.py'], name)
    run(['sh', 'tools/verify_rulings.sh'], 'verify-rulings')
    run(['python3', 'tools/native_messaging/test_native_host_registration.py'], 'native-registration', mandatory=False)
    run(['python3', 'tools/test_linux_native_host_delivery.py'], 'linux-native-delivery', mandatory=False)


def go():
    run(['go', 'test', './...'], 'go-test', cwd=ROOT / 'winn_protocol_experimental')
    run(['go', 'test', '-race', './cmd/winn3-gateway'], 'go-race', cwd=ROOT / 'winn_protocol_experimental', mandatory=False)
    run(['go', 'test', './cmd/winn3-gateway', '-run', 'TestGatewayAuthorityExpiresWithoutFileChange', '-count=10'],
        'go-expiry-repeat', cwd=ROOT / 'winn_protocol_experimental', mandatory=False)


if __name__ == '__main__':
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(group) for group in (flutter, server, platform, go)]
        for job in jobs:
            job.result()
    raise SystemExit(int(any(item['exit_code'] for item in RESULTS)))
