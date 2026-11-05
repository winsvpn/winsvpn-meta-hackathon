"""H3 offline behavior and executable mutants, design v17 3.11 and section 5.

The extracted hub and shared root runner use real ephemeral H1 signatures and
in-memory SQLite. Probe subprocesses and registry transport are boundary fakes.
"""
import ast
import base64
import fcntl
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import math
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time as real_time
import types

import pytest
import test_hub_h2_auto_provision as h2

ROOT = Path(__file__).resolve().parent
SOURCE = (ROOT / 'wins_control_plane_setup_ONETOUCH.sh').read_text()
APP = SOURCE.split('cat > "${APP_DIR}/main.py" <<\'PYEOF\'\n', 1)[1].split('\nPYEOF\n', 1)[0]
TREE = ast.parse(APP)


def restore(mod, name, old=None, new=None):
    node = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)
    source = ast.get_source_segment(APP, node)
    if old is not None:
        assert old in source
        source = source.replace(old, new)
    exec(compile(source, '<h3-extracted>', 'exec'), mod.__dict__)


class Canary(h2.Lane):
    def __init__(self, tmp, monkeypatch):
        super().__init__(tmp, monkeypatch)
        for name in ('winn3_pre_sign_canary', 'winn3_served_profile_canary'):
            restore(self.mod, name)
        self.mod.WINN3_CANARY_KEY_ROOT = tmp / 'canary-keys'
        self.mod.WINN3_CANARY_REQUEST_DIR = tmp / 'requests'
        self.mod.WINN3_CANARY_REQUEST_DIR.mkdir(mode=0o700)
        self.calls = []
        self.failure = None
        self.callback = None
        # Preserve OpenSSL operations, including the actual H1 signer.
        actual_run = subprocess.run
        def probe(argv, **kwargs):
            if Path(argv[0]).name != 'winn3-probe':
                return actual_run(argv, **kwargs)
            directory = Path(argv[argv.index('-dir') + 1])
            files = {p.name: p.read_bytes() for p in directory.iterdir()}
            assert all(p.stat().st_mode & 0o777 == 0o600 for p in directory.iterdir())
            kind = 'dns' if '-dns' in argv else 'icmp'
            self.calls.append((list(argv), files, self.row()['protocol_version']))
            self.trace.append(kind)
            if self.callback:
                self.callback(kind)
            self.clock[0] += 0.001
            return types.SimpleNamespace(returncode=1 if self.failure == kind else 0,
                                         stdout=b'v3probe: HANDSHAKE ok state=carrying\n', stderr=b'')
        monkeypatch.setattr(subprocess, 'run', probe)
        route_probes(self.mod)
        monkeypatch.delenv('WINN3_CANARY_NODES', raising=False)
        monkeypatch.delenv('WINN3_CANARY_NODE_SLUG', raising=False)
        monkeypatch.delenv('WINN3_CANARY_BIN', raising=False)
        self.published = []
        def publish(conn, ip, slug, **kwargs):
            document, meta = self.mod.winn3_peer_registry_publication(conn, slug)
            self.published.append((document, meta))
            self.trace.append('registry')
            assert document['peers'][0]['static_public'] == kwargs['expect_static_public']
            return True
        self.mod.sync_winn3_registry_to_node = publish

    def binding(self):
        return self.mod.winn3_canary_binding_for(self.slug)

    def result(self, **overrides):
        data = dict(self.mod.winn3_result_binding(self.row()), slug=self.slug, status='ok', detail='',
                    checked_at=self.mod.utcnow().replace(tzinfo=timezone.utc).isoformat())
        data.update(overrides)
        return data

    def runtime(self, tmp, path=None):
        spec = importlib.util.spec_from_file_location('h3_runtime', path or ROOT / 'wins_winn3_canary_runtime.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.utcnow = self.mod.utcnow
        def sleep(seconds):
            self.clock[0] += seconds
        # A held request is waited for on the same fake clock as the limit.
        mod.time = types.SimpleNamespace(time=lambda: self.clock[0], monotonic=lambda: self.clock[0], sleep=sleep)
        route_probes(mod)
        for name in ('CANARY_RESULT_DIR', 'CANARY_REQUEST_DIR', 'CANARY_STATE_DIR'):
            path = tmp / name
            path.mkdir(mode=0o700)
            setattr(mod, name, path)
        return mod


def route_probes(mod):
    """The probe runner is a process boundary: winn3-probe calls go through
    subprocess.run, which the tests fake, and any other binary goes through
    the real process-group runner."""
    real = getattr(mod, 'winn3_run_canary_probe', None)
    def run_probe(argv, timeout):
        if real is not None and Path(argv[0]).name != 'winn3-probe':
            return real(argv, timeout)
        return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    mod.winn3_run_canary_probe = run_probe


@pytest.fixture
def canary(tmp_path, monkeypatch):
    lane = Canary(tmp_path, monkeypatch)
    yield lane
    lane.database.close()


def test_fresh_pipeline_order_keys_registry_and_default_reservations(canary):
    assert canary.run()['ok']
    assert canary.trace == ['cleanup', 'pull', 'host-signature-and-consistency', 'registry', 'icmp', 'dns',
                            'status', 'sign', 'store', 'icmp', 'dns', 'candidate-gate']
    assert [call[2] for call in canary.calls] == ['winn/1'] * 4
    binding = canary.binding()
    assert binding['inner_v4'] == '10.10.0.254'
    directory = Path(binding['key_dir'])
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / 'client.key').stat().st_mode & 0o777 == 0o600
    assert binding['inner_v4'] in canary.mod.winn3_inner_addresses_in_use(canary.database)
    assert binding['static_public'] in canary.mod.winn3_canary_reserved_publics()
    assert canary.mod.winn3_static_public_in_use(canary.database, binding['static_public'], own_device_ids=set())
    peers, metadata = canary.published[0]
    assert [entry['kind'] for entry in metadata] == ['canary']
    assert len(peers['peers']) == 1
    assert not canary.mod.winn3_canary_is_fresh(canary.row())
    assert json.loads((canary.mod.WINN3_CANARY_REQUEST_DIR / (canary.slug + '.json')).read_text()) == {'slug': canary.slug}


def test_pulled_then_exact_stored_dns_and_dual_auth(canary):
    assert canary.run()['ok']
    envelope = json.loads(canary.row()['winn3_descriptor_json'])
    descriptor = json.loads(base64.b64decode(envelope['payload']))
    for argv, files, _ in canary.calls:
        assert argv[argv.index('-gw') + 1] == descriptor['endpoint']
        assert argv[argv.index('-path-mtu') + 1] == '1450'
        assert argv[argv.index('-dual-ed-pub') + 1] == canary.identity['auth_ed25519_hex']
        assert argv[argv.index('-dual-ml-pub') + 1] == canary.identity['auth_mldsa65_hex']
        assert files['admission.key'] == base64.b64decode(descriptor['admission_secret'])
        if '-dns' in argv:
            assert argv[argv.index('-dns-server') + 1] == descriptor['inner_resolver_v4']
    profile = canary.mod.winn3_render_canary_profile(canary.row())
    # A deliberately contradictory pull cannot influence the served hook.
    contradictory = dict(canary.identity, inner_resolver_v4='10.10.0.99', endpoint='203.0.113.99:9111')
    proof = canary.mod.winn3_served_profile_canary(canary.row(), contradictory, descriptor, 0)
    assert proof['status'] == 'ok' and proof['seq'] == profile['seq']
    assert canary.calls[-1][0][-1] == descriptor['inner_resolver_v4']


@pytest.mark.parametrize('failure', ['icmp', 'dns'])
def test_failed_pre_sign_never_signs_or_flips(canary, failure):
    canary.failure = failure
    assert not canary.run()['ok']
    assert 'sign' not in canary.trace
    assert canary.row()['protocol_version'] == 'winn/1'


def test_served_dns_failure_keeps_signed_descriptor_on_v1(canary):
    def fail_after_store(kind):
        if 'store' in canary.trace:
            canary.failure = 'dns'
    canary.callback = fail_after_store
    assert not canary.run()['ok']
    assert 'sign' in canary.trace
    assert canary.row()['winn3_descriptor_json']
    assert canary.row()['protocol_version'] == 'winn/1'


def test_key_is_stable_and_corrupt_private_never_republished(canary):
    assert canary.run()['ok']
    key = Path(canary.binding()['key_dir']) / 'client.key'
    before = key.read_bytes()
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])
    canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert key.read_bytes() == before
    key.write_text('12' * 32)
    publications = len(canary.published)
    with pytest.raises(ValueError, match='private-public-mismatch'):
        canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert len(canary.published) == publications


def test_manual_override_stays_authoritative(canary, monkeypatch):
    assert canary.run()['ok']
    binding = canary.binding()
    entry = '|'.join((canary.slug, binding['static_public'], binding['inner_v4'], binding['key_dir'],
                      binding['gateway_endpoint'], binding['gateway_id']))
    monkeypatch.setenv('WINN3_CANARY_NODES', entry)
    assert canary.binding() == binding
    monkeypatch.setenv('WINN3_CANARY_NODES', 'malformed')
    assert canary.binding() is None


@pytest.mark.parametrize('field', ['handshake', 'carried', 'dns'])
@pytest.mark.parametrize('seq', [None, 7])
def test_both_hooks_require_every_boolean(canary, field, seq):
    proof = canary.proof(dict(canary.identity, admission_secret=canary.pulled['admission_secret']), 0, seq)
    proof[field] = False
    with pytest.raises(ValueError, match='incomplete'):
        canary.mod.winn3_check_canary(proof, proof['identity_sha256'], 0,
                                     (canary.mod.utcnow() - timedelta(seconds=1)).isoformat(), seq)


@pytest.mark.parametrize('changes', [dict(status='unknown'), dict(identity_sha256='f'*64), dict(seq=999),
                                     dict(generation=1), dict(slug='unknown'), dict(detail='x'*301),
                                     dict(extra='forbidden'), dict(seq=True), dict(generation=True)])
def test_fixed_result_interface_rejects_wrong_bindings(canary, changes):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert not canary.mod.ingest_winn3_canary_result(canary.database, canary.result(**changes), canary.slug)
    assert canary.row()['winn3_canary_status'] == 'unknown'


def test_post_flip_result_is_committed_by_app_and_only_canary_columns(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    before = dict(canary.row())
    assert runtime.run_canary_slug(canary.database, canary.slug)
    result = json.loads((runtime.CANARY_RESULT_DIR / (canary.slug + '.json')).read_text())
    assert set(result) == {'slug', 'status', 'detail', 'identity_sha256', 'seq', 'generation', 'checked_at'}
    assert dict(canary.row()) == before
    assert [call[2] for call in canary.calls[-2:]] == ['winn/3'] * 2
    assert canary.mod.ingest_winn3_canary_result(canary.database, result, canary.slug)
    canary.database.commit()
    after = dict(canary.row())
    assert all(before[key] == after[key] for key in before if not key.startswith('winn3_canary_'))
    assert canary.mod.winn3_canary_is_fresh(canary.row())
    assert not canary.mod.ingest_winn3_canary_result(canary.database, result, canary.slug)


def test_inflight_generation_change_rejects_postflip_result(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    canary.callback = lambda kind: canary.update(deployment_generation=1) if kind == 'dns' else None
    assert runtime.run_canary_slug(canary.database, canary.slug)
    result = json.loads((runtime.CANARY_RESULT_DIR / (canary.slug + '.json')).read_text())
    assert result['generation'] == 0
    assert not canary.mod.ingest_winn3_canary_result(canary.database, result, canary.slug)


@pytest.mark.parametrize('changes', [dict(winn3_canary_seq=999), dict(winn3_canary_generation=1),
                                     dict(winn3_canary_identity_sha256='f'*64), dict(winn3_canary_status='fail'),
                                     dict(winn3_canary_ok_at='2099-01-01T00:00:00'),
                                     dict(winn3_canary_ok_at='2000-01-01T00:00:00')])
def test_go_live_refuses_wrong_or_stale_live_proof(canary, changes):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    assert canary.mod.winn3_canary_is_fresh(canary.row())
    canary.update(**changes)
    assert not canary.mod.winn3_canary_is_fresh(canary.row())


def test_completion_requires_another_live_proof(canary):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    canary.update(deployment_completed_at=canary.mod.utcnow().isoformat())
    assert not canary.mod.winn3_canary_is_fresh(canary.row())
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    assert canary.mod.winn3_canary_is_fresh(canary.row())


def test_readonly_connection_mode_and_sql_write_denial(canary, tmp_path, monkeypatch):
    runtime = canary.runtime(tmp_path)
    observed = []
    real_connect = sqlite3.connect
    def connect(database_uri, **kwargs):
        observed.append((database_uri, kwargs))
        return real_connect(':memory:')
    monkeypatch.setattr(runtime.sqlite3, 'connect', connect)
    conn = runtime.open_canary_database(tmp_path / 'app.db')
    assert observed[0][0].endswith('?mode=ro') and observed[0][1]['uri'] is True
    with pytest.raises(sqlite3.OperationalError, match='readonly'):
        conn.execute('CREATE TABLE forbidden (value TEXT)')
    conn.close()


def test_on_demand_unknown_retired_malformed_and_once_per_minute(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    request = runtime.CANARY_REQUEST_DIR / (canary.slug + '.json')
    calls = len(canary.calls)
    for value in ({'slug': canary.slug, 'exec': 'touch forbidden'}, {'slug': 'unknown'}, 'malformed'):
        request.write_text(json.dumps(value))
        runtime.dispatch_canary_requests(canary.database)
        assert len(canary.calls) == calls
        assert not request.exists()
    unknown = runtime.CANARY_REQUEST_DIR / 'unknown.json'
    unknown.write_text('{"slug":"unknown"}')
    runtime.dispatch_canary_requests(canary.database)
    assert not unknown.exists() and len(canary.calls) == calls
    request.write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 2
    first = float((runtime.CANARY_STATE_DIR / (canary.slug + '.last')).read_text())
    # P2-SEAM-H3: a second request inside the 60 s limit is held, not
    # dropped, and runs once when the limit ends, never inside it.
    request.write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 4 and not request.exists()
    assert float((runtime.CANARY_STATE_DIR / (canary.slug + '.last')).read_text()) - first >= 60
    canary.update(retired_at=canary.mod.utcnow().isoformat())
    request.write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 4 and not request.exists()


def test_on_demand_symlink_never_reads_target(canary, tmp_path):
    runtime = canary.runtime(tmp_path)
    target = tmp_path / 'untouched'
    target.write_text('private local test data')
    (runtime.CANARY_REQUEST_DIR / 'lab-alpha.json').symlink_to(target)
    runtime.dispatch_canary_requests(canary.database)
    assert target.read_text() == 'private local test data'
    assert not list(runtime.CANARY_REQUEST_DIR.iterdir())
    assert not canary.calls


def test_pinned_artifacts_and_deterministic_root_runtime():
    import build_h3_canary_runtime as builder
    assert builder.build(SOURCE, (ROOT / 'h3_canary_cli.py.inc').read_text()) == (ROOT / 'wins_winn3_canary_runtime.py').read_text()
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        data = (ROOT / ('winn3-probe-linux-' + arch)).read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01'
        assert int.from_bytes(data[18:20], 'little') == machine
        assert hashlib.sha256(data).hexdigest() in SOURCE
    assert hashlib.sha256((ROOT / 'wins_winn3_canary_runtime.py').read_bytes()).hexdigest() in SOURCE
    assert 'PathChanged=/var/lib/wins-canary-requests' in SOURCE
    assert 'ReadOnlyPaths=/root/vpn_auth' in SOURCE


@pytest.mark.parametrize('mutant', ['served-booleans-optional', 'served-uses-pulled-identity',
                                   'live-generation-optional', 'result-enum-open',
                                   'result-sequence-optional', 'live-completion-optional',
                                   'readwrite-database', 'request-rate-limit-removed'])
def test_executable_mutants_are_killed(canary, tmp_path, monkeypatch, mutant):
    # Each mutant changes executed code; its associated behavior assertion must
    # fail. The unmodified behavior is exercised independently above.
    with pytest.raises(AssertionError):
        if mutant == 'served-booleans-optional':
            restore(canary.mod, 'winn3_check_canary', 'if any(result.get(name)', 'if seq is None and any(result.get(name)')
            proof = canary.proof(dict(canary.identity, admission_secret=canary.pulled['admission_secret']), 0, 7)
            proof['dns'] = False
            try:
                canary.mod.winn3_check_canary(proof, proof['identity_sha256'], 0,
                                             (canary.mod.utcnow()-timedelta(seconds=1)).isoformat(), 7)
            except ValueError:
                return
            assert False
        elif mutant == 'served-uses-pulled-identity':
            assert canary.run()['ok']
            restore(canary.mod, 'winn3_served_profile_canary', 'profile = winn3_render_canary_profile(node)',
                    'profile = dict(winn3_identity_descriptor(identity, identity["admission_secret"]), path_mtu=1450, seq=descriptor["seq"])')
            identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'], inner_resolver_v4='10.10.0.99')
            descriptor = canary.mod.winn3_stored_descriptor(canary.row())
            canary.mod.winn3_served_profile_canary(canary.row(), identity, descriptor, 0)
            assert canary.calls[-1][0][-1] == canary.identity['inner_resolver_v4']
        elif mutant in ('result-enum-open', 'result-sequence-optional'):
            assert canary.run()['ok']
            if mutant == 'result-enum-open':
                restore(canary.mod, 'ingest_winn3_canary_result', 'result["status"] not in ("ok", "fail")', 'False')
                result = canary.result(status='unexpected')
            else:
                restore(canary.mod, 'ingest_winn3_canary_result', 'if any(result[key] != value for key, value in binding.items()):',
                        'if any(result[key] != value for key, value in binding.items() if key != "seq"):')
                result = canary.result(seq=999)
            assert not canary.mod.ingest_winn3_canary_result(canary.database, result, canary.slug)
        elif mutant in ('live-generation-optional', 'live-completion-optional'):
            assert canary.run()['ok']
            canary.clock[0] += 1
            assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
            canary.database.commit()
            if mutant == 'live-generation-optional':
                restore(canary.mod, 'winn3_canary_is_fresh', 'for key, value in binding.items()', 'for key, value in binding.items() if key != "generation"')
                canary.update(winn3_canary_generation=999)
            else:
                restore(canary.mod, 'winn3_canary_is_fresh', 'if boundary is not None and checked <= boundary:', 'if False:')
                canary.update(deployment_completed_at=canary.mod.utcnow().isoformat())
            assert not canary.mod.winn3_canary_is_fresh(canary.row())
        else:
            runtime = canary.runtime(tmp_path)
            text = (ROOT / 'h3_canary_cli.py.inc').read_text()
            name = 'open_canary_database' if mutant == 'readwrite-database' else 'claim_canary_slug'
            node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name)
            function = ast.get_source_segment(text, node)
            if mutant == 'readwrite-database':
                function = function.replace('?mode=ro', '?mode=rw').replace("connection.execute('PRAGMA query_only=ON')", 'pass')
                real_connect = sqlite3.connect
                monkeypatch.setattr(runtime.sqlite3, 'connect', lambda *a, **kw: real_connect(':memory:'))
                exec(function, runtime.__dict__)
                conn = runtime.open_canary_database(tmp_path / 'data')
                try:
                    conn.execute('CREATE TABLE forbidden (value TEXT)')
                except sqlite3.OperationalError:
                    return
                assert False
            else:
                exec(function.replace('if canary_limit_remaining(slug) > 0:', 'if False:'), runtime.__dict__)
                assert runtime.claim_canary_slug(canary.slug)
                assert not runtime.claim_canary_slug(canary.slug)


def run_embedded(source, marker, canary, monkeypatch, capsys):
    import sys
    code = source.split(marker + '\n', 1)[1].split('\nPYEOF\n', 1)[0]
    monkeypatch.setattr(sqlite3, 'connect', lambda *args, **kwargs: canary.database)
    monkeypatch.setattr(sys, 'argv', ['coverage', 'memory-placeholder', ''])
    exec(compile(code, '<h3-embedded-reader>', 'exec'), {'__name__': 'h3_reader'})
    return capsys.readouterr().out


def test_owned_binding_visible_to_runner(canary, monkeypatch, capsys):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    # Keep the node open only for this coverage-reader test. Promotion itself
    # remains governed by H7 and is never performed by the canary job.
    canary.update(operator_enabled=1)
    marker = '  python3 -I - "${DATABASE_PATH:-${DATABASEPATH:-/root/vpn_auth/vpn_users.db}}" <<\'PYEOF\''
    assert run_embedded(SOURCE, marker, canary, monkeypatch, capsys).strip() == canary.slug


def test_key_crash_recovery_preserves_public_and_private(canary):
    assert canary.run()['ok']
    binding = canary.binding()
    private = (Path(binding['key_dir']) / 'client.key').read_bytes()
    canary.database.execute('DELETE FROM winn3_canary_bindings WHERE slug=?', (canary.slug,))
    canary.database.commit()
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])
    restored = canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert restored['static_public'] == binding['static_public']
    assert (Path(binding['key_dir']) / 'client.key').read_bytes() == private


def test_runner_refuses_invalid_current_envelope(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    canary.update(winn3_descriptor_json='{}')
    calls = len(canary.calls)
    with pytest.raises(ValueError, match='descriptor-invalid'):
        runtime.run_canary_slug(canary.database, canary.slug)
    assert len(canary.calls) == calls


def test_result_ingestion_accepts_aware_application_clock(canary):
    assert canary.run()['ok']
    canary.clock[0] += 1
    actual_clock = canary.mod.utcnow
    canary.mod.utcnow = lambda: actual_clock().replace(tzinfo=timezone.utc)
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)


def test_on_demand_and_periodic_share_rate_limit(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    assert runtime.run_canary_slug(canary.database, canary.slug)
    periodic = float((runtime.CANARY_STATE_DIR / (canary.slug + '.last')).read_text())
    calls = len(canary.calls)
    request = runtime.CANARY_REQUEST_DIR / (canary.slug + '.json')
    request.write_text(json.dumps({'slug': canary.slug}))
    ran = []
    canary.callback = lambda kind: ran.append(canary.clock[0])
    runtime.dispatch_canary_requests(canary.database)
    # The periodic run's claim holds the request until its limit ends.
    assert len(canary.calls) == calls + 2 and ran[0] - periodic >= 60


def test_completion_and_retirement_wire_requests_and_cleanup():
    complete = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'complete_node_deployment')
    retire = next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == 'admin_retire_node')
    # P2-SEAM-H3 (integration): the completion reaches this writer through
    # P2's app-side gate (60 s limit, deferral, retirement cancel), and the
    # retirement removes this file through P2's helper.
    def function(name):
        return ast.get_source_segment(APP, next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name))
    assert 'trigger_winn3_golive_after_release(node_slug)' in ast.get_source_segment(APP, complete)
    assert 'request_winn3_canary_proof(slug, "completion")' in function('trigger_winn3_golive_after_release')
    assert 'winn3_request_canary(clean)' in function('request_winn3_canary_proof')
    assert 'remove_winn3_canary_request(node_slug)' in ast.get_source_segment(APP, retire)
    assert 'WINN3_CANARY_REQUEST_DIR / (name + ".json")' in function('remove_winn3_canary_request')


def test_two_signed_slugs_keep_probes_and_results_separate(canary, tmp_path):
    assert canary.run()['ok']
    slug = 'lab-beta'
    canary.clock[0] = int(canary.clock[0]) + 1
    reply = canary.keys.sign(canary.signer, slug, generation=0, endpoint_ip='203.0.113.11', static=b'\x44'*32)
    assert reply['ok'], reply
    descriptor = json.loads(base64.b64decode(reply['payload']))
    row = dict(canary.row())
    params = json.loads(row['protocol_params_json'])
    params['gateway_endpoint'] = descriptor['endpoint']
    report = json.loads(row['winn3_gateway_report_json'])
    report['gateway_id'] = 'lab-beta-gw1'
    row.update(slug=slug, name='Lab Beta', endpoint='203.0.113.11:9110',
               protocol_params_json=json.dumps(params), winn3_gateway_report_json=json.dumps(report),
               winn3_descriptor_json=json.dumps({'payload': reply['payload'], 'sig': reply['sig']}),
               winn3_identity_sha256=canary.mod.winn3_identity_digest(descriptor))
    # H7-QUESTIONS Q1: the row carries winn3_signer_ticket_json as a SELECT
    # alias over winn3_signer_tickets (WINN3_JOB_ROW_SQL), not a nodes column.
    row.pop('winn3_signer_ticket_json', None)
    columns = list(row)
    canary.database.execute('INSERT INTO nodes (' + ','.join(columns) + ') VALUES (' +
                            ','.join('?' for _ in columns) + ')', tuple(row.values()))
    private, public = canary.mod.generate_winn3_static_material()
    directory = canary.mod.WINN3_CANARY_KEY_ROOT / slug
    directory.mkdir(mode=0o700)
    canary.mod.winn3_write_canary_file(directory, 'client.key', base64.b64decode(private).hex().encode())
    canary.database.execute('INSERT INTO winn3_canary_bindings VALUES (?,?,?,?,?,?)',
                            (slug, public, '10.10.0.253', str(directory), descriptor['endpoint'], 'lab-beta-gw1'))
    canary.database.commit()
    runtime = canary.runtime(tmp_path)
    assert runtime.run_canary_slug(canary.database, canary.slug)
    canary.failure = 'icmp'
    assert not runtime.run_canary_slug(canary.database, slug)
    results = {p.stem: json.loads(p.read_text()) for p in runtime.CANARY_RESULT_DIR.glob('*.json')}
    assert results[canary.slug]['status'] == 'ok' and results[slug]['status'] == 'fail'
    assert results[canary.slug]['identity_sha256'] != results[slug]['identity_sha256']
    assert {call[0][call[0].index('-inner')+1] for call in canary.calls[-3:]} == {'10.10.0.254', '10.10.0.253'}


def test_previous_carrier_cannot_consume_new_deployments_request_budget(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    canary.clock[0] += 10
    canary.update(deployment_generation=1, deployment_released_at=canary.mod.utcnow().isoformat())
    before = len(canary.calls)
    assert not runtime.run_canary_slug(canary.database, canary.slug)
    assert len(canary.calls) == before
    assert not list(runtime.CANARY_STATE_DIR.iterdir())
    canary.clock[0] += 1
    canary.update(winn3_carrier_flipped_at=canary.mod.utcnow().isoformat())
    assert runtime.run_canary_slug(canary.database, canary.slug)
    assert len(canary.calls) == before + 2


@pytest.mark.parametrize('arch', ['amd64', 'arm64'])
@pytest.mark.parametrize('mutant', [None, 'probe-pin', 'runtime-pin'])
def test_installer_executes_pins_before_installation(arch, mutant, monkeypatch):
    import sys
    marker = '  python3 -I - "${SCRIPT_DIR}" "${arch}" <<\'PYEOF\'\n'
    code = SOURCE.split(marker, 1)[1].split('\nimport os\nimport tempfile\nparent =', 1)[0]
    if mutant == 'probe-pin':
        digest = hashlib.sha256((ROOT / ('winn3-probe-linux-' + arch)).read_bytes()).hexdigest()
        assert digest in code
        code = code.replace(digest, '0'*64)
    elif mutant == 'runtime-pin':
        digest = hashlib.sha256((ROOT / 'wins_winn3_canary_runtime.py').read_bytes()).hexdigest()
        assert digest in code
        code = code.replace(digest, '0'*64)
    monkeypatch.setattr(sys, 'argv', ['pins', str(ROOT), arch])
    if mutant:
        with pytest.raises(SystemExit, match='mismatch'):
            exec(compile(code, '<h3-artifact-pins>', 'exec'), {})
    else:
        exec(compile(code, '<h3-artifact-pins>', 'exec'), {})


def keepalive_report(canary, monkeypatch, capsys, **changes):
    """Run the embedded keepalive reader on a row whose clocks are real, never the fake one."""
    import sys
    from datetime import datetime
    marker = '  python3 - "${db}" "${root}" ${kv[@]+"${kv[@]}"} <<\'WINS_KEEPALIVE_CANARY_PY\' || printf \'ERROR coverage check failed to run\\n\''
    code = SOURCE.split(marker + '\n', 1)[1].split('\nWINS_KEEPALIVE_CANARY_PY\n', 1)[0]
    real = datetime.now(timezone.utc)
    binding = canary.mod.winn3_result_binding(canary.row())
    values = dict(operator_enabled=1, winn3_canary_status='ok',
                  winn3_canary_ok_at=real.replace(tzinfo=None).isoformat(),
                  winn3_canary_identity_sha256=binding['identity_sha256'],
                  winn3_canary_seq=binding['seq'], winn3_canary_generation=binding['generation'],
                  deployment_completed_at=(real - timedelta(minutes=10)).isoformat(),
                  deployment_released_at=(real - timedelta(minutes=10)).isoformat(),
                  winn3_carrier_flipped_at=(real - timedelta(minutes=5)).isoformat())
    values.update(changes)
    canary.update(**values)
    canary.database.commit()
    with monkeypatch.context() as patch:
        actual_isfile, actual_access = os.path.isfile, os.access
        patch.setattr(os.path, 'isfile', lambda p: True if p == '/usr/local/bin/winn3-probe' else actual_isfile(p))
        patch.setattr(os, 'access', lambda p, m: True if p == '/usr/local/bin/winn3-probe' else actual_access(p, m))
        patch.setattr(subprocess, 'run', lambda *a, **kw: types.SimpleNamespace(returncode=0))
        patch.setattr(sqlite3, 'connect', lambda *a, **kw: canary.database)
        patch.setattr(sys, 'argv', ['coverage', 'memory-placeholder', ''])
        exec(compile(code, '<h3-keepalive>', 'exec'), {'__name__': 'h3_coverage'})
    return capsys.readouterr().out


def test_keepalive_covers_only_a_fully_bound_live_proof_after_flip(canary, monkeypatch, capsys):
    assert canary.run()['ok']
    future = (canary.mod.utcnow() + timedelta(minutes=5)).isoformat()
    assert keepalive_report(canary, monkeypatch, capsys).splitlines()[0] == 'COVERED ' + canary.slug
    # keepalive_report places the release 10 minutes ago; a flip before it is no flip after the release.
    before_release = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
    for changes in (dict(winn3_canary_generation=99), dict(winn3_canary_identity_sha256='f' * 64),
                    dict(winn3_canary_seq=999), dict(deployment_completed_at=future),
                    dict(winn3_carrier_flipped_at=None), dict(winn3_carrier_flipped_at=''),
                    dict(winn3_carrier_flipped_at='not-a-timestamp'), dict(winn3_carrier_flipped_at=before_release),
                    dict(deployment_released_at='not-a-timestamp'), dict(deployment_completed_at='not-a-timestamp'),
                    dict(winn3_canary_ok_at=future.replace('+00:00', '')),
                    dict(deployment_released_at=future), dict(winn3_carrier_flipped_at=future)):
        out = keepalive_report(canary, monkeypatch, capsys, **changes)
        assert out.startswith('UNCOVERED ' + canary.slug), (changes, out)


def test_live_result_carries_the_current_nonzero_generation(canary, tmp_path):
    assert canary.run()['ok']
    canary.update(deployment_generation=3)
    runtime = canary.runtime(tmp_path)
    canary.clock[0] += 1
    assert runtime.run_canary_slug(canary.database, canary.slug)
    result = json.loads((runtime.CANARY_RESULT_DIR / (canary.slug + '.json')).read_text())
    assert result['generation'] == 3
    assert canary.mod.ingest_winn3_canary_result(canary.database, result, canary.slug)


@pytest.mark.parametrize('changes', [dict(winn3_identity_sha256='f' * 64), dict(deployment_withdrawal_id='a' * 32),
                                     dict(deployment_released_at=None), dict(winn3_carrier_flipped_at=None)])
def test_runner_refuses_an_unbound_or_withdrawn_row_before_any_probe(canary, tmp_path, changes):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    canary.update(**changes)
    try:
        assert not runtime.run_canary_slug(canary.database, canary.slug)
    except ValueError:
        pass
    assert len(canary.calls) == calls and not list(runtime.CANARY_RESULT_DIR.iterdir())


def test_flip_boundary_requires_a_proof_after_the_flip(canary):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    assert canary.mod.winn3_canary_is_fresh(canary.row())
    canary.update(winn3_carrier_flipped_at=canary.mod.utcnow().isoformat())
    assert not canary.mod.winn3_canary_is_fresh(canary.row())


def test_prepare_refuses_a_moved_generation_and_serving_refuses_a_moved_descriptor(canary):
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])
    with pytest.raises(ValueError, match='generation-moved'):
        canary.mod.winn3_prepare_canary(canary.row(), identity, 5)
    assert canary.binding() is None
    assert canary.run()['ok']
    row = canary.row()
    stored = canary.mod.winn3_stored_descriptor(row)
    calls = len(canary.calls)
    with pytest.raises(ValueError, match='descriptor-moved'):
        canary.mod.winn3_served_profile_canary(row, {}, dict(stored, seq=stored['seq'] + 1), 0)
    params = json.loads(row['protocol_params_json'])
    params['gateway_endpoint'] = '203.0.113.99:9111'
    with pytest.raises(ValueError, match='endpoint-mismatch'):
        canary.mod.winn3_render_canary_profile(dict(row, protocol_params_json=json.dumps(params)))
    assert len(canary.calls) == calls


def test_probe_exit_zero_without_a_carrying_handshake_fails(canary, monkeypatch):
    original = subprocess.run
    def silent(argv, **kwargs):
        result = original(argv, **kwargs)
        if Path(argv[0]).name == 'winn3-probe':
            return types.SimpleNamespace(returncode=0, stdout=b'v3probe: HANDSHAKE absent\n', stderr=b'')
        return result
    monkeypatch.setattr(subprocess, 'run', silent)
    assert not canary.run()['ok']
    assert 'sign' not in canary.trace and canary.row()['protocol_version'] == 'winn/1'


@pytest.mark.parametrize('field', ['handshake', 'carried', 'dns'])
def test_settled_cycle_requires_every_proof_boolean(canary, field):
    assert canary.run()['ok']
    row = dict(canary.row())
    assert canary.mod.winn3_cycle_settled(row)
    result = json.loads(row['winn3_served_profile_result_json'])
    result.pop(field)
    row['winn3_served_profile_result_json'] = json.dumps(result)
    assert not canary.mod.winn3_cycle_settled(row)


@pytest.mark.parametrize('bad_flip', [None, '', 'not-a-timestamp', 'before-release'])
def test_live_and_settled_require_current_flip_marker(canary, bad_flip):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    assert canary.mod.winn3_canary_is_fresh(canary.row())
    assert canary.mod.winn3_cycle_settled(canary.row())
    if bad_flip == 'before-release':
        released = datetime.fromisoformat(canary.row()['deployment_released_at'])
        bad_flip = (released - timedelta(seconds=1)).isoformat()
    canary.update(winn3_carrier_flipped_at=bad_flip)
    assert not canary.mod.winn3_canary_is_fresh(canary.row())
    assert not canary.mod.winn3_cycle_settled(canary.row())


# ---- fix round T2: Q5 cleanup, H3-PERF items and their tests

@pytest.mark.parametrize('column,value', [('winn3_carrier_flipped_at', None), ('winn3_carrier_flipped_at', ''),
                                          ('winn3_carrier_flipped_at', 'not-a-timestamp'),
                                          ('deployment_released_at', 'not-a-timestamp')])
def test_runner_refuses_a_missing_or_malformed_marker_cleanly(canary, tmp_path, column, value):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    canary.update(**{column: value})
    # A clean refusal, not a traceback: the periodic path has no handler for ValueError.
    assert runtime.run_canary_slug(canary.database, canary.slug) is False
    assert len(canary.calls) == calls and not list(runtime.CANARY_RESULT_DIR.iterdir())


def request_file(runtime, slug):
    return runtime.CANARY_REQUEST_DIR / (slug + '.json')


def test_perf_dispatcher_sees_a_request_that_lands_during_its_run(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    landed = []
    def land(kind):
        if kind == 'icmp' and not landed:
            landed.append(True)
            canary.clock[0] += 61
            request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    canary.callback = land
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert landed and len(canary.calls) == calls + 4
    assert not request_file(runtime, canary.slug).exists()


def test_perf_dispatcher_rereads_a_bounded_number_of_times(canary, tmp_path):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    rewrites = []
    def keep_landing(kind):
        if kind == 'icmp' and len(rewrites) < 10:
            rewrites.append(True)
            canary.clock[0] += 61
            request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    canary.callback = keep_landing
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert runtime.CANARY_DISPATCH_PASSES == 3
    # Three passes of two probes each; the fourth request is left for the path unit.
    assert len(canary.calls) == calls + 6 and request_file(runtime, canary.slug).exists()


def test_perf_parallel_probes_are_bounded_and_own_their_connections(canary, tmp_path, monkeypatch):
    import threading
    import time as real_time
    runtime = canary.runtime(tmp_path)
    slugs = ['slug-%d' % index for index in range(6)]
    lock, state = threading.Lock(), dict(active=0, peak=0, connections=[])
    barrier = threading.Barrier(2)
    def fake_run(connection, slug):
        with lock:
            state['active'] += 1
            state['peak'] = max(state['peak'], state['active'])
            state['connections'].append(connection)
        barrier.wait(timeout=10) if slug in slugs[:2] else None
        real_time.sleep(0.05)
        with lock:
            state['active'] -= 1
    opened = []
    def fake_open(path):
        connection = sqlite3.connect(':memory:')
        opened.append((path, connection))
        return connection
    monkeypatch.setattr(runtime, 'run_canary_slug', fake_run)
    monkeypatch.setattr(runtime, 'open_canary_database', fake_open)
    runtime.run_dispatched_slugs(canary.database, 'app.db', slugs)
    assert 2 <= state['peak'] <= runtime.CANARY_DISPATCH_WORKERS == 4
    assert len(opened) == 6 and all(path == 'app.db' for path, _ in opened)
    assert canary.database not in state['connections'] and len(set(map(id, state['connections']))) == 6
    # Without a database path, or with one slug, nothing is threaded.
    state.update(peak=0, connections=[])
    runtime.run_dispatched_slugs(canary.database, None, slugs[2:4])
    assert state['peak'] == 1 and state['connections'] == [canary.database] * 2


def test_perf_parallel_workers_keep_their_own_thread_local_connection(canary, tmp_path):
    import threading
    runtime = canary.runtime(tmp_path)
    barrier, seen = threading.Barrier(2), []
    def work(name):
        mine = object()
        runtime._canary_local.connection = mine
        barrier.wait(timeout=10)
        with runtime.get_db() as current:
            seen.append(current is mine)
    threads = [threading.Thread(target=work, args=(name,)) for name in 'ab']
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert seen == [True, True]


def test_perf_one_openssl_derivation_per_key(canary, monkeypatch):
    derivations = []
    real_run = subprocess.run
    def counting(argv, **kwargs):
        if Path(argv[0]).name == 'openssl' and '-pubout' in argv:
            derivations.append(argv)
        return real_run(argv, **kwargs)
    monkeypatch.setattr(subprocess, 'run', counting)
    first, second = b'11' * 32, b'22' * 32
    public = canary.mod.winn3_canary_public_for(first)
    assert canary.mod.winn3_canary_public_for(first) == public and len(derivations) == 1
    other = canary.mod.winn3_canary_public_for(second)
    assert other != public and len(derivations) == 2
    assert canary.mod.winn3_canary_public_for(first) == public and len(derivations) == 2
    # The cache holds a digest of the key, never the key.
    assert first.decode() not in repr(canary.mod._WINN3_CANARY_PUBLIC_CACHE)


def test_perf_a_whole_pre_sign_pass_derives_the_public_key_once(canary, monkeypatch):
    derivations = []
    real_run = subprocess.run
    def counting(argv, **kwargs):
        if Path(argv[0]).name == 'openssl' and 'DER' in argv and '-pubout' in argv and '-in' in argv:
            derivations.append(argv)
        return real_run(argv, **kwargs)
    monkeypatch.setattr(subprocess, 'run', counting)
    assert canary.run()['ok']
    key_derivations = [argv for argv in derivations if Path(argv[argv.index('-in') + 1]).name == 'client.der']
    assert len(key_derivations) == 1


def test_perf_unchanged_binding_is_not_republished_within_the_window(canary, monkeypatch):
    assert canary.run()['ok']
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])
    published = len(canary.published)
    def prepare(generation, changed=identity):
        canary.mod.winn3_prepare_canary(canary.row(), changed, generation)
        return len(canary.published) - published
    assert prepare(0) == 0
    # Each input is moved alone against the cached entry, and each one publishes.
    assert prepare(0, dict(identity, static_pub_hex='ab' * 32)) == 1
    assert prepare(0) == 2
    canary.update(deployment_generation=1)
    assert prepare(1) == 3
    assert prepare(1) == 3
    with canary.database:
        canary.database.execute('UPDATE winn3_canary_bindings SET inner_v4=? WHERE slug=?', ('10.10.0.253', canary.slug))
    assert prepare(1) == 4
    assert prepare(1) == 4
    later = canary.mod.time.monotonic() + canary.mod.WINN3_CANARY_PUBLICATION_TTL_SECONDS + 1
    monkeypatch.setattr(canary.mod.time, 'monotonic', lambda: later)
    assert prepare(1) == 5
    assert canary.slug in canary.mod._WINN3_CANARY_PUBLISHED
    canary.mod.sync_winn3_registry_to_node = lambda *a, **kw: False
    with pytest.raises(ValueError, match='registry-publication-failed'):
        canary.mod.winn3_prepare_canary(canary.row(), dict(identity, static_pub_hex='cd' * 32), 1)
    assert canary.slug not in canary.mod._WINN3_CANARY_PUBLISHED


def test_build_receipt_and_binaries_describe_the_real_sources():
    """D1: the receipt and the pins were once derived from a masked copy of the sources."""
    receipt = json.loads((ROOT / 'winn3-probe.build.json').read_text())
    sources = ROOT.parent / 'winn_protocol_experimental'
    actual = {}
    for directory, _, names in os.walk(sources):
        for name in names:
            path = Path(directory) / name
            if name.endswith('.go') or (path.parent == sources and name in ('go.mod', 'go.sum')):
                actual[str(path.relative_to(sources))] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert receipt['source_files'] == dict(sorted(actual.items()))
    for arch in ('amd64', 'arm64'):
        data = (ROOT / ('winn3-probe-linux-' + arch)).read_bytes()
        assert receipt['artifacts'][arch]['sha256'] == hashlib.sha256(data).hexdigest()
        assert receipt['artifacts'][arch]['bytes'] == len(data)
        assert (data[:6], int(data[18]) | int(data[19]) << 8) == (b'\x7fELF\x02\x01', {'amd64': 62, 'arm64': 183}[arch])
        # A masked module path inside the binary would mean it was built from masked source.
        assert b'winsvpn.local/winnprotocol' in data and b'Product.local' not in data


@pytest.mark.parametrize('column', ['deployment_completed_at', 'deployment_released_at', 'winn3_carrier_flipped_at'])
def test_freshness_refuses_a_malformed_boundary_timestamp(canary, column):
    assert canary.run()['ok']
    canary.clock[0] += 1
    assert canary.mod.ingest_winn3_canary_result(canary.database, canary.result(), canary.slug)
    canary.database.commit()
    assert canary.mod.winn3_canary_is_fresh(canary.row())
    canary.update(**{column: 'not-a-timestamp'})
    assert not canary.mod.winn3_canary_is_fresh(canary.row())


# ---- fix round T3: Astra H3-T2 (manual-binding publication key, runner marker parsing)

def outcome_of(call, *args):
    """The return value, or the escaped exception as a value, so a crash fails an assertion."""
    try:
        return call(*args)
    except Exception as exc:
        return exc


@pytest.mark.parametrize('shape', ['list', 'legacy'])
def test_prepare_publishes_under_each_manual_override_shape(canary, monkeypatch, shape):
    assert canary.run()['ok']
    owned = canary.binding()
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])

    def manual(**changes):
        binding = dict(owned, **changes)
        fields = (canary.slug, binding['static_public'], binding['inner_v4'], binding['key_dir'],
                  binding['gateway_endpoint'], binding['gateway_id'])
        if shape == 'list':
            monkeypatch.setenv('WINN3_CANARY_NODES', '|'.join(fields))
        else:
            for name, value in zip(('NODE_SLUG', 'STATIC_PUBLIC', 'INNER_V4', 'KEY_DIR', 'GATEWAY_ENDPOINT',
                                    'GATEWAY_ID'), fields):
                monkeypatch.setenv('WINN3_CANARY_' + name, value)

    def prepare():
        before = len(canary.published)
        outcome = outcome_of(canary.mod.winn3_prepare_canary, canary.row(), identity, 0)
        assert isinstance(outcome, dict), repr(outcome)
        assert outcome['static_public'] == owned['static_public']
        return len(canary.published) - before

    manual()
    # A manual binding has no "slug" field; the publication key must still build.
    assert 'slug' not in canary.binding()
    canary.mod._WINN3_CANARY_PUBLISHED.clear()
    assert prepare() == 1
    assert prepare() == 0
    manual(gateway_id=owned['gateway_id'] + '-moved')
    assert prepare() == 1
    assert prepare() == 0
    assert canary.mod._WINN3_CANARY_PUBLISHED[canary.slug][0][2][0] == canary.slug


def shifted(text, wall, hours):
    """The same wall clock as naive UTC text plus `wall`, written with a UTC offset of `hours`."""
    base = datetime.fromisoformat(text)
    return (base + wall).replace(tzinfo=timezone(timedelta(hours=hours))).isoformat()


# Each case writes one marker with an offset whose wall clock alone would order
# it the other way round. Flipped is compared with released after conversion.
@pytest.mark.parametrize('column,wall,hours,probes', [
    ('winn3_carrier_flipped_at', timedelta(hours=1), 2, False),       # 1 h before release in UTC
    ('winn3_carrier_flipped_at', timedelta(minutes=-30), -1, True),   # 30 min after release in UTC
    ('deployment_released_at', timedelta(hours=1), 2, True),          # release 1 h before the flip in UTC
    ('deployment_released_at', timedelta(hours=-1), -2, False),       # release 1 h after the flip in UTC
])
def test_runner_converts_offset_markers_before_ordering_them(canary, tmp_path, column, wall, hours, probes):
    assert canary.run()['ok']
    row = canary.row()
    anchor = row['deployment_released_at'] if column == 'winn3_carrier_flipped_at' else row['winn3_carrier_flipped_at']
    value = shifted(anchor, wall, hours)
    released = canary.mod.parse_iso_datetime(value if column == 'deployment_released_at' else row['deployment_released_at'])
    flipped = canary.mod.parse_iso_datetime(value if column == 'winn3_carrier_flipped_at' else row['winn3_carrier_flipped_at'])
    assert (flipped >= released) is probes
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    canary.update(**{column: value})
    canary.clock[0] += 1
    assert outcome_of(runtime.run_canary_slug, canary.database, canary.slug) is probes
    assert (len(canary.calls) > calls) is probes
    assert bool(list(runtime.CANARY_RESULT_DIR.iterdir())) is probes


@pytest.mark.parametrize('column', ['winn3_carrier_flipped_at', 'deployment_released_at'])
def test_runner_refuses_a_blob_marker_cleanly(canary, tmp_path, column):
    assert canary.run()['ok']
    runtime = canary.runtime(tmp_path)
    calls = len(canary.calls)
    canary.update(**{column: canary.row()[column].encode()})
    assert isinstance(canary.row()[column], bytes)
    assert outcome_of(runtime.run_canary_slug, canary.database, canary.slug) is False
    assert len(canary.calls) == calls and not list(runtime.CANARY_RESULT_DIR.iterdir())


# P2-SEAM-H3 (impl review 2026-10-08): H3's consumer takes over the P2
# dispatcher's properties. Each seam_* body takes the runtime under test, so
# test_seam_mutants_are_killed can run it against a mutated build.

SLUG_PATTERN = r'[a-z0-9][a-z0-9_-]{0,62}'


def clocked_sleeps(canary, runtime, limit=200):
    """Record every hold sleep, and stop a hold that never ends."""
    sleeps = []
    def sleep(seconds):
        sleeps.append((canary.clock[0], seconds))
        assert sum(s for _, s in sleeps) <= limit, 'the hold is not bounded'
        canary.clock[0] += seconds
    runtime.time.sleep = sleep
    return sleeps


def seam_held_request_runs_when_the_limit_ends(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    assert runtime.run_canary_slug(canary.database, canary.slug)
    stamp = float((runtime.CANARY_STATE_DIR / (canary.slug + '.last')).read_text())
    calls = len(canary.calls)
    request = request_file(runtime, canary.slug)
    request.write_text(json.dumps({'slug': canary.slug}))
    inode = request.stat().st_ino
    seen = []
    sleeps = clocked_sleeps(canary, runtime)
    original = runtime.time.sleep
    def watching(seconds):
        seen.append(request.exists() and request.stat().st_ino == inode)
        original(seconds)
    runtime.time.sleep = watching
    ran = []
    canary.callback = lambda kind: ran.append(canary.clock[0])
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 2, 'held, not dropped: it runs when the limit ends'
    assert ran[0] - stamp >= 60, 'never inside the limit'
    assert ran[0] - stamp <= 60 + 0.2 + 0.01, 'and when the limit ends, not a poll later'
    assert sleeps and all(seen), 'the held request stays in the spool, never unlinked and rewritten'
    assert not request.exists()


def seam_claim_race_is_written_back_and_held(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    calls = len(canary.calls)
    real_claim = runtime.claim_canary_slug
    raced = []
    def claim(slug):
        # The periodic canary claims the slug after the request was consumed.
        if not raced:
            raced.append(canary.clock[0])
            runtime.winn3_write_canary_file(runtime.CANARY_STATE_DIR, slug + '.last', str(canary.clock[0]).encode())
        return real_claim(slug)
    runtime.claim_canary_slug = claim
    clocked_sleeps(canary, runtime)
    ran = []
    canary.callback = lambda kind: ran.append(canary.clock[0])
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert raced, 'anti-vacuity: the race happened'
    assert len(canary.calls) == calls + 2, 'a request refused only by the limit is never lost'
    assert ran[0] - raced[0] >= 60
    assert not request_file(runtime, canary.slug).exists()


def seam_hold_is_bounded(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    calls = len(canary.calls)
    # A limit that never ends (the slug is claimed again at every poll): the
    # run still ends after one interval plus one poll, and the request is left
    # in the spool, not dropped. A whole-second clock keeps the steps exact.
    canary.clock[0] = float(int(canary.clock[0]) + 1)
    stamp = lambda: runtime.winn3_write_canary_file(runtime.CANARY_STATE_DIR, canary.slug + '.last',
                                                    str(canary.clock[0]).encode())
    stamp()
    sleeps = clocked_sleeps(canary, runtime)
    advance = runtime.time.sleep
    def reclaimed(seconds):
        advance(seconds)
        stamp()
    runtime.time.sleep = reclaimed
    request = request_file(runtime, canary.slug)
    request.write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert request.exists() and json.loads(request.read_text()) == {'slug': canary.slug}, 'left for the next run, not dropped'
    assert len(canary.calls) == calls
    waited = sum(seconds for _, seconds in sleeps)
    assert 60 <= waited <= 60 + 5 + 0.2, waited
    assert all(seconds <= 5 for _, seconds in sleeps), 'the spool is listed again at least every poll'


def seam_non_empty_directories_cannot_starve_a_request(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    calls = len(canary.calls)
    spool = runtime.CANARY_REQUEST_DIR
    (spool / 'c-empty.json').mkdir()
    for index in range(64):
        blocked = spool / ('d%02d.json' % index)
        blocked.mkdir()
        (blocked / 'inner').write_text('x')
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 2, 'the valid request runs in the same start'
    assert [name for name in os.listdir(spool) if name.endswith('.json')] == [], 'nothing is left in the request names'
    rejected = [name for name in os.listdir(spool) if not name.endswith('.json')]
    assert len(rejected) == 1 and not re.fullmatch(SLUG_PATTERN + r'\.json', rejected[0])
    assert len(os.listdir(spool / rejected[0])) == 64, 'moved aside unwalked; the empty one is removed'
    # The store stays out of every later listing.
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    canary.clock[0] += 61
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 4 and len(os.listdir(spool / rejected[0])) == 64


def seam_future_stamp_is_reset(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    calls = len(canary.calls)
    stamp = runtime.CANARY_STATE_DIR / (canary.slug + '.last')
    stamp.write_text(str(canary.clock[0] + 3600))
    clocked_sleeps(canary, runtime, limit=3700)
    ran = []
    canary.callback = lambda kind: ran.append(canary.clock[0])
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    started = canary.clock[0]
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 2, 'a clock moved back holds the request, never drops it'
    assert 60 <= ran[0] - started <= 61, 'held one interval, not opened at once and not for the jump'
    # The periodic (--slug) claim gets the same rule.
    stamp.write_text(str(canary.clock[0] + 3600))
    assert not runtime.claim_canary_slug(canary.slug)
    assert float(stamp.read_text()) <= canary.clock[0], 'the future stamp is reset to now'
    canary.clock[0] += 60
    assert runtime.claim_canary_slug(canary.slug)


def seam_probe_timeout_kills_the_process_group(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    pids = tmp_path / 'pids'
    probe = tmp_path / 'hanging-probe'
    probe.write_text('#!/bin/sh\n/bin/sleep 120 </dev/null >/dev/null 2>&1 &\n'
                     'echo $! > %s\necho $$ >> %s\nexec /bin/sleep 120\n' % (pids, pids))
    probe.chmod(0o755)
    monkeypatch.setenv('WINN3_CANARY_BIN', str(probe))
    runtime.WINN3_CANARY_PROBE_TIMEOUT_SECONDS = 1
    def stop_leftovers():
        for pid in (pids.read_text().split() if pids.exists() else []):
            try:
                os.kill(int(pid), 9)
            except (ProcessLookupError, ValueError):
                pass
    try:
        assert runtime.run_canary_slug(canary.database, canary.slug) is False
        result = json.loads((runtime.CANARY_RESULT_DIR / (canary.slug + '.json')).read_text())
        assert result['status'] == 'fail'
        grandchild = int(pids.read_text().split()[0])
        deadline = real_time.time() + 5
        alive = True
        while alive and real_time.time() < deadline:
            try:
                os.kill(grandchild, 0)
                real_time.sleep(0.05)
            except ProcessLookupError:
                alive = False
        assert not alive, 'a process the probe started outlived its timeout'
    finally:
        stop_leftovers()


def seam_fixed_state_names_cannot_be_slugs(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    claimed = []
    def claim_dispatch(kind):
        # A node slugged "dispatch" claims its limit while the dispatcher
        # holds its own lock: the two must be different files.
        if kind == 'icmp' and not claimed:
            claimed.append(runtime.claim_canary_slug('dispatch'))
    canary.callback = claim_dispatch
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert claimed == [True], 'the slug "dispatch" is not blocked by the dispatcher lock'
    for name in (runtime.CANARY_DISPATCH_LOCK, runtime.CANARY_REJECTED_DIR):
        assert not re.fullmatch(SLUG_PATTERN + r'(\.json|\.lock|\.last)?', name), name


def seam_busy_slug_lock_is_written_back_and_held(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    calls = len(canary.calls)
    real_claim = runtime.claim_canary_slug
    busy = []
    def claim(slug):
        # The periodic canary holds the slug's claim lock at that instant.
        if busy:
            return real_claim(slug)
        lock = os.open(runtime.CANARY_STATE_DIR / (slug + '.lock'), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            busy.append(slug)
            return real_claim(slug)
        finally:
            os.close(lock)
    runtime.claim_canary_slug = claim
    clocked_sleeps(canary, runtime)
    request_file(runtime, canary.slug).write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert busy == [canary.slug], 'anti-vacuity: the claim met a busy lock'
    assert len(canary.calls) == calls + 2, 'a claim refused by a busy slug lock is held, not dropped'
    assert not request_file(runtime, canary.slug).exists()


def seam_request_held_again_after_its_run_has_its_own_bound(canary, tmp_path, monkeypatch, runtime):
    assert canary.run()['ok']
    assert runtime.run_canary_slug(canary.database, canary.slug)
    calls = len(canary.calls)
    canary.clock[0] += 30
    clocked_sleeps(canary, runtime)
    request = request_file(runtime, canary.slug)
    request.write_text(json.dumps({'slug': canary.slug}))
    ran = []
    def again(kind):
        ran.append(canary.clock[0])
        if len(ran) == 1:
            # A new request for the same slug lands while its held one runs.
            request.write_text(json.dumps({'slug': canary.slug}))
    canary.callback = again
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls + 4, 'a request held again after its slug ran gets a bound of its own'
    assert ran[2] - ran[0] >= 60
    assert not request.exists()


def seam_non_finite_stamp_is_reset(canary, tmp_path, monkeypatch, runtime):
    # Integration follow-up (P2-T4 Claude seat note 2): nan and -inf parse as
    # numbers and gave 0 s remaining; a stamp that is not a number had no test.
    assert canary.run()['ok']
    stamp = runtime.CANARY_STATE_DIR / (canary.slug + '.last')
    for text in ('nan', '-inf', 'not-a-number'):
        stamp.write_text(text)
        assert runtime.canary_limit_remaining(canary.slug) == runtime.CANARY_MIN_INTERVAL_SECONDS, text
        reset = float(stamp.read_text())
        assert math.isfinite(reset) and reset <= canary.clock[0], f'{text}: the stamp is reset to now'
        stamp.write_text(text)
        assert not runtime.claim_canary_slug(canary.slug), f'{text}: the periodic claim is held too'


def seam_unreadable_stamp_holds_the_request(canary, tmp_path, monkeypatch, runtime):
    # Integration follow-up (P2-T4 Claude seat note 2): a stamp that cannot be
    # read discarded the request; it is now held, and nothing runs.
    assert canary.run()['ok']
    calls = len(canary.calls)
    stamp = runtime.CANARY_STATE_DIR / (canary.slug + '.last')
    if os.path.lexists(stamp):
        stamp.unlink()
    stamp.mkdir()
    clocked_sleeps(canary, runtime)
    request = request_file(runtime, canary.slug)
    request.write_text(json.dumps({'slug': canary.slug}))
    runtime.dispatch_canary_requests(canary.database)
    assert len(canary.calls) == calls, 'nothing runs while the stamp cannot be read'
    assert request.exists() and json.loads(request.read_text()) == {'slug': canary.slug}, 'held, not discarded'
    assert not runtime.claim_canary_slug(canary.slug), 'the periodic claim is held too'


SEAM_CASES = [seam_held_request_runs_when_the_limit_ends, seam_claim_race_is_written_back_and_held,
              seam_hold_is_bounded, seam_non_empty_directories_cannot_starve_a_request,
              seam_future_stamp_is_reset, seam_probe_timeout_kills_the_process_group,
              seam_fixed_state_names_cannot_be_slugs, seam_busy_slug_lock_is_written_back_and_held,
              seam_request_held_again_after_its_run_has_its_own_bound,
              seam_non_finite_stamp_is_reset, seam_unreadable_stamp_holds_the_request]


@pytest.mark.parametrize('case', SEAM_CASES, ids=[case.__name__ for case in SEAM_CASES])
def test_seam_h3_consumer_takes_over_p2_dispatcher_properties(canary, tmp_path, monkeypatch, case):
    case(canary, tmp_path, monkeypatch, canary.runtime(tmp_path))


SEAM_MUTANTS = {
    # name: (file, old, new, the case that must fail)
    'hold-peek-removed': ('cli', "            if remaining > 0:\n                held.append((slug, remaining))",
                          "            if False:\n                held.append((slug, remaining))",
                          seam_held_request_runs_when_the_limit_ends),
    'held-request-dropped': ('cli', "                held.append((slug, remaining))\n                return None",
                             "                os.unlink(name, dir_fd=directory)\n                return None",
                             seam_held_request_runs_when_the_limit_ends),
    'limit-refusal-after-consume-dropped': ('cli', "    if not getattr(_canary_local, 'limited', False):\n        return None",
                                            "    if True:\n        return None", seam_claim_race_is_written_back_and_held),
    'hold-unbounded': ('cli', "if now - first_held.setdefault(slug, now) < CANARY_MIN_INTERVAL_SECONDS + CANARY_HOLD_POLL_SECONDS:",
                       "if first_held.setdefault(slug, now) is not None:", seam_hold_is_bounded),
    'hold-without-poll': ('cli', "min(min(waits) + 0.2, CANARY_HOLD_POLL_SECONDS)", "min(waits) + 0.2", seam_hold_is_bounded),
    'non-empty-directory-stays': ('cli', "    try:\n        os.mkdir(CANARY_REJECTED_DIR",
                                  "    return\n    try:\n        os.mkdir(CANARY_REJECTED_DIR",
                                  seam_non_empty_directories_cannot_starve_a_request),
    'rejected-store-is-a-request-name': ('cli', "CANARY_REJECTED_DIR = '.rejected'", "CANARY_REJECTED_DIR = 'rejected.json'",
                                         seam_non_empty_directories_cannot_starve_a_request),
    'future-stamp-fails-open': ('cli', "    if last is None or not math.isfinite(last) or last > now:\n        winn3_write_canary_file(CANARY_STATE_DIR, slug + '.last', str(now).encode())\n"
                                "        return float(CANARY_MIN_INTERVAL_SECONDS)",
                                "    if last is None or not math.isfinite(last) or last > now:\n        return 0.0", seam_future_stamp_is_reset),
    'future-stamp-holds-for-the-jump': ('cli', "    if last is None or not math.isfinite(last) or last > now:", "    if last is None or not math.isfinite(last):",
                                        seam_future_stamp_is_reset),
    'probe-timeout-kills-only-the-leader': ('cp', "                os.killpg(proc.pid, signal.SIGKILL)",
                                            "                proc.kill()", seam_probe_timeout_kills_the_process_group),
    'probe-in-the-callers-group': ('cp', "stderr=subprocess.PIPE, start_new_session=True)", "stderr=subprocess.PIPE)",
                                   seam_probe_timeout_kills_the_process_group),
    'dispatch-lock-named-like-a-slug': ('cli', "CANARY_DISPATCH_LOCK = '.dispatch.lock'", "CANARY_DISPATCH_LOCK = 'dispatch.lock'",
                                        seam_fixed_state_names_cannot_be_slugs),
    'busy-slug-lock-dropped': ('cli', "        except BlockingIOError:\n            return False\n        if canary_limit_remaining",
                               "        except BlockingIOError:\n            raise OSError('busy')\n        if canary_limit_remaining",
                               seam_busy_slug_lock_is_written_back_and_held),
    'first-held-never-cleared': ('cli', "            for slug in slugs:\n                first_held.pop(slug, None)\n", "",
                                 seam_request_held_again_after_its_run_has_its_own_bound),
    'non-finite-stamp-fails-open': ('cli', "if last is None or not math.isfinite(last) or last > now:",
                                    "if last is None or last > now:", seam_non_finite_stamp_is_reset),
    'unreadable-stamp-discards': ('cli', "    except OSError:\n        logger.warning('Canary stamp for %s cannot be read; the slug is held', slug)\n        return float(CANARY_MIN_INTERVAL_SECONDS)\n",
                                  "", seam_unreadable_stamp_holds_the_request),
}


@pytest.mark.parametrize('mutant', sorted(SEAM_MUTANTS))
def test_seam_mutants_are_killed(canary, tmp_path, monkeypatch, mutant):
    import build_h3_canary_runtime as builder
    where, old, new, case = SEAM_MUTANTS[mutant]
    source, cli = SOURCE, (ROOT / 'h3_canary_cli.py.inc').read_text()
    if where == 'cli':
        assert cli.count(old) == 1, mutant
        cli = cli.replace(old, new)
    else:
        assert source.count(old) == 1, mutant
        source = source.replace(old, new)
    path = tmp_path / 'mutated_runtime.py'
    path.write_text(builder.build(source, cli))
    with pytest.raises(AssertionError):
        case(canary, tmp_path, monkeypatch, canary.runtime(tmp_path, path))


# ---- HL-F1 (hub-lite FINDINGS, 705bedd): the pre-sign publication takes the management path

def hidden_origin(canary, monkeypatch, tmp_path):
    """The shipped default: HIDE_CONTROL_ORIGIN=1 with Cloudflare Access, so
    node_ssh_command refuses every IP literal and accepts only a pinned name."""
    for name, value in (('HIDE_CONTROL_ORIGIN', True), ('REQUIRE_CLOUDFLARE_ACCESS', True),
                        ('TUNNEL_SERVICE_TOKEN_ID', 'h3-test.access'), ('TUNNEL_SERVICE_TOKEN_SECRET', 's' * 32),
                        ('HUB_MANAGEMENT_SSH_CONTROL_DIR', str(tmp_path / 'ssh-cm'))):
        monkeypatch.setattr(canary.mod, name, value)
    targets = []
    recorded = canary.mod.sync_winn3_registry_to_node

    def publish(conn, host, slug, **kwargs):
        # The real publisher builds its argv with node_ssh_command and turns
        # any exception into a failed publication; so does this boundary.
        targets.append(host)
        try:
            argv = canary.mod.node_ssh_command(host, 'true', connect_timeout=3)
        except ValueError:
            return False
        assert argv[-2] == 'root@' + host
        return recorded(conn, host, slug, **kwargs)
    canary.mod.sync_winn3_registry_to_node = publish
    return targets


def test_hl_f1_prepare_publishes_over_the_pinned_management_host_under_the_shipped_default(canary, monkeypatch,
                                                                                          tmp_path):
    targets = hidden_origin(canary, monkeypatch, tmp_path)
    out = canary.run()
    assert out['ok'], out
    assert targets == ['node.example.test'], 'the node row\'s pinned ssh_host, as winn3_pull_identity uses'
    assert canary.row()['protocol_version'] == 'winn/3'
    # Anti-vacuity: the same transport refuses the endpoint IP under this
    # default, even with a pin written for it (hub-lite's HL-D1 workaround).
    endpoint_ip = canary.mod.extract_node_host(canary.row()['endpoint'])
    with pytest.raises(ValueError, match='Managed SSH host key is unavailable'):
        canary.mod.node_ssh_command(endpoint_ip, 'true')
    canary.pin.write_text(canary.pin.read_text() + endpoint_ip + ' ' + canary.identity['ssh_host_ed25519_key'] + '\n')
    with pytest.raises(ValueError, match='Direct-IP node management is disabled'):
        canary.mod.node_ssh_command(endpoint_ip, 'true')


def test_hl_f1_prepare_follows_the_management_host_and_falls_back_like_the_pull(canary, monkeypatch, tmp_path):
    assert canary.run()['ok']
    identity = dict(canary.identity, admission_secret=canary.pulled['admission_secret'])
    targets = hidden_origin(canary, monkeypatch, tmp_path)
    # A moved management host is a new publication target: the cached entry
    # for the old one does not stand in for it.
    with canary.database:
        canary.database.execute('UPDATE nodes SET ssh_host=? WHERE slug=?', ('node2.example.test', canary.slug))
    canary.pin.write_text(canary.pin.read_text() + 'node2.example.test '
                          + canary.identity['ssh_host_ed25519_key'] + '\n')
    canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert targets == ['node2.example.test']
    canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert targets == ['node2.example.test'], 'an unchanged target inside the window is not republished'
    # No ssh_host: the endpoint host, exactly as winn3_pull_identity falls
    # back; under the hidden origin that is refused and the canary holds.
    with canary.database:
        canary.database.execute('UPDATE nodes SET ssh_host=NULL WHERE slug=?', (canary.slug,))
    with pytest.raises(ValueError, match='canary-registry-publication-failed'):
        canary.mod.winn3_prepare_canary(canary.row(), identity, 0)
    assert targets[-1] == '203.0.113.10'
    assert canary.slug not in canary.mod._WINN3_CANARY_PUBLISHED


HL_F1_MUTANTS = {
    # name: (old, new, the test that must fail)
    'publishes-to-the-endpoint-ip': (
        'management_host = str(_node_field(node, "ssh_host") or extract_node_host(node["endpoint"]))',
        'management_host = extract_node_host(node["endpoint"])',
        test_hl_f1_prepare_publishes_over_the_pinned_management_host_under_the_shipped_default),
    'publication-key-ignores-the-management-host': (
        'published = (generation, management_host,',
        'published = (generation, extract_node_host(node["endpoint"]),',
        test_hl_f1_prepare_follows_the_management_host_and_falls_back_like_the_pull),
}


@pytest.mark.parametrize('mutant', sorted(HL_F1_MUTANTS))
def test_hl_f1_mutants_are_killed(canary, monkeypatch, tmp_path, mutant):
    old, new, case = HL_F1_MUTANTS[mutant]
    assert APP.count(old) == 1, mutant
    restore(canary.mod, 'winn3_prepare_canary', old, new)
    with pytest.raises(AssertionError):
        try:
            case(canary, monkeypatch, tmp_path)
        except ValueError as exc:
            raise AssertionError(repr(exc)) from None
