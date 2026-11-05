"""Offline regressions for the H0 implementation-review findings."""
import urllib.parse
import ast
import base64
import hashlib
import fcntl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import tempfile
import threading
import types
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('H0_REVIEW_SOURCE', ROOT / 'server/wins_control_plane_setup_ONETOUCH.sh')).read_text()
CORE = Path(os.environ.get('H0_CORE_SOURCE', ROOT / 'server/wins_core_server_setup_ONETOUCH.sh')).read_text()
TIER = Path(os.environ.get('H0_TIER_SOURCE', ROOT / 'server/test_hub_h0_sandbox_tier_a.sh')).read_text()


def body(name, source=SOURCE):
    lines = source.splitlines(keepends=True)
    start = lines.index(name + '() {\n')
    tag = None
    for end in range(start + 1, len(lines)):
        line = lines[end].rstrip('\n')
        if tag:
            if line == tag: tag = None
        elif line == '}':
            return ''.join(lines[start:end + 1])
        else:
            match = re.search(r"<<'?([A-Z0-9_]+)'?$", line)
            if match: tag = match[1]
    raise AssertionError(name)


def heredoc(header, source=SOURCE):
    # The body starts on the line after the header. The rest of the header's
    # line is shell, not heredoc text: `python3 -I - <<'ABSTRACTEOF' || rc=$?`.
    after = source.index(header) + len(header)
    end = source.index('\n', after)
    assert '<<' not in source[after:end], source[after:end]
    start = end + 1
    tag = re.search(r"<<'?([A-Z0-9_]+)'?$", header)[1]
    return source[start:source.index('\n' + tag + '\n', start)]


APP = heredoc('cat > "${APP_DIR}/main.py" <<\'PYEOF\'')
CANARY = heredoc("cat > /usr/local/bin/wins-gateway-canary <<'EOF'")


def app_functions(*names, **values):
    tree = ast.parse(APP)
    selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    assert {node.name for node in selected} == set(names)
    namespace = dict(ipaddress=ipaddress, socket=socket, sqlite3=sqlite3, json=json,
                     base64=base64, re=re, os=os, datetime=datetime, timezone=timezone,
                     timedelta=timedelta, Path=Path, Any=object, Optional=object)
    namespace.update(values)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<real-hub-functions>', 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


def bash(script, **env):
    return subprocess.run(['bash', '-c', script], env=dict(os.environ, **env),
                          text=True, capture_output=True, timeout=20)


@pytest.mark.parametrize('rc,value,expected', [(1, '', 1), (0, 'cap_net_admin', 1), (0, '', 0)])
def test_capability_inspection_fails_closed(rc, value, expected):
    section = body('postflight_control')
    start = section.index('  # H0 (D4):')
    end = section.index('  [[ "$(stat', start)
    code = section[start:end]
    # The H0 gates (and the stock-unit masking before them) are tested on their own.
    code = '\n'.join(line for line in code.splitlines() if 'refuse_hub_' not in line and 'ReadOnlyPaths' not in line
                     and 'hub_mask_stock_abstract_services' not in line)
    result = bash(f'err() {{ :; }}; systemctl() {{ printf "%s" "{value}"; return {rc}; }}\nf() {{\n{code}\n}}\nf')
    assert result.returncode == expected, result.stderr


@pytest.mark.parametrize('host', ['127.1', '127.0.1', '2130706433', '0x7f.0.0.1', '0.0', '3405803786'])
def test_numeric_aliases_are_refused(host):
    app = app_functions('node_host_names_this_hub', IONOS_HUB_IP='203.0.113.10')
    assert app.node_host_names_this_hub(host)


def test_venv_is_immutable_and_install_inputs_are_root_only():
    unit = heredoc('cat > "${SERVICE_FILE}" <<EOF')
    assert 'ReadOnlyPaths=${VENV_DIR}' in unit
    setup = body('setup_python')
    assert 'require_root_owned_venv' in setup
    assert 'mktemp /root/.wins-control-plane-requirements.XXXXXX' in setup
    assert '-r "${requirements_lock}"' in setup
    assert '-r "${APP_DIR}/' not in setup
    assert 'trap ' in setup and 'requirements_lock' in setup.split('trap ', 1)[1]
    assert '${VENV_DIR}/bin/python" -m py_compile' not in SOURCE
    assert '-I -S -c' in setup


def test_venv_permission_gate_checks_descendants_and_link_targets():
    code = body('require_root_owned_venv')
    assert 'os.walk' in code and 'st_uid' in code and 'st_gid' in code
    assert '0o022' in code and 'realpath' in code
    assert 'app_dir' in code and 'islink' in code


@pytest.mark.parametrize('attack', ['none', 'writable-pth', 'foreign-owner', 'app-link'])
def test_venv_permission_gate_rejects_dependency_escape(tmp_path, attack):
    app_dir = tmp_path / 'app'; venv = app_dir / 'venv'
    venv.mkdir(parents=True); dependency = venv / 'dependency.pth'; dependency.write_text('fixture\n')
    if attack == 'app-link':
        target = app_dir / 'mutable.py'; target.write_text('fixture\n'); dependency.unlink(); dependency.symlink_to(target)
    script = heredoc("python3 -I - \"${VENV_DIR}\" \"${APP_DIR}\" <<'VENVEOF'", body('require_root_owned_venv'))
    real_lstat = os.lstat
    def fixture_stat(path, **kwargs):
        info = list(real_lstat(path, **kwargs)); info[4] = 0; info[5] = 0
        if str(path) == str(dependency):
            if attack == 'writable-pth': info[0] |= 0o022
            if attack == 'foreign-owner': info[4] = 501
        return os.stat_result(info)
    with patch.object(os, 'lstat', side_effect=fixture_stat), patch.object(__import__('sys'), 'argv', ['gate', str(venv), str(app_dir)]):
        if attack == 'none': exec(compile(script, '<real-venv-gate>', 'exec'), {})
        else:
            with pytest.raises(SystemExit): exec(compile(script, '<real-venv-gate>', 'exec'), {})


def test_all_app_writable_roots_are_denied_as_dependency_targets():
    for root in ['/var/lib/wins-hub-ssh', '/var/lib/wins-site-ai-tunnel', '/var/lib/wins-security-alerts', '/var/log/winsvpn']:
        assert root in body('require_root_owned_venv')
        assert root in body('require_root_canary_executable', CANARY)


def key_gate(tmp_path, effective, *, inspection_rc=0, private=True):
    keys = tmp_path / 'keys'; keys.mkdir(exist_ok=True)
    if private:
        (keys / 'id_rsa').write_text('-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n')
        (keys / 'id_rsa.pub').write_text('ssh-rsa AAAAHUBKEY fixture\n')
    bin_dir = tmp_path / 'bin'; bin_dir.mkdir(exist_ok=True)
    (bin_dir / 'sshd').write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_EFFECTIVE"\nexit "$TEST_INSPECTION_RC"\n')
    (bin_dir / 'ssh-keygen').write_text('#!/bin/sh\nprintf "ssh-rsa AAAAHUBKEY\\n"\n')
    for path in bin_dir.iterdir(): path.chmod(0o755)
    result = bash('err() { printf "%s\\n" "$*" >&2; };\n' + body('refuse_hub_keys_authorized_for_root_here') + '\nrefuse_hub_keys_authorized_for_root_here',
                  PATH=str(bin_dir) + ':' + os.environ['PATH'], WINS_ROOT_SSH_DIR=str(keys),
                  TEST_EFFECTIVE=effective, TEST_INSPECTION_RC=str(inspection_rc), IONOS_HUB_IP='203.0.113.10')
    return keys, result


def test_root_key_gate_is_in_preflight_and_postflight():
    for name in ['preflight_control', 'postflight_control']:
        assert 'refuse_hub_keys_authorized_for_root_here' in body(name)


def test_root_key_gate_checks_effective_alternate_file(tmp_path):
    alternate = tmp_path / 'alternate'; alternate.write_text('restrict ssh-rsa AAAAHUBKEY fixture\n')
    keys, result = key_gate(tmp_path, f'authorizedkeysfile {alternate}\nauthorizedkeyscommand none\ntrustedusercakeys none')
    assert result.returncode != 0
    assert alternate.read_text() == 'restrict ssh-rsa AAAAHUBKEY fixture\n'
    assert keys.joinpath('id_rsa').exists()
    alternate.write_text('ssh-ed25519 AAAAOPERATOR fixture\n')
    _, result = key_gate(tmp_path, f'authorizedkeysfile {alternate}\nauthorizedkeyscommand none\ntrustedusercakeys none')
    assert result.returncode == 0, result.stderr


def test_root_key_gate_derives_a_private_key_without_a_public_file(tmp_path):
    keys, result = key_gate(tmp_path, 'authorizedkeysfile %h/keys/authorized_keys\nauthorizedkeyscommand none\ntrustedusercakeys none')
    assert result.returncode == 0, result.stderr
    (keys / 'id_rsa.pub').unlink()
    (keys / 'authorized_keys').write_text('ssh-rsa AAAAHUBKEY fixture\n')
    _, result = key_gate(tmp_path, 'authorizedkeysfile %h/keys/authorized_keys\nauthorizedkeyscommand none\ntrustedusercakeys none', private=False)
    assert result.returncode != 0


@pytest.mark.parametrize('config,rc', [('authorizedkeysfile none', 1),
                                     ('authorizedkeysfile none\nauthorizedkeyscommand /bin/auth', 0),
                                     ('authorizedkeysfile none\ntrustedusercakeys /etc/ca.pub', 0)])
def test_root_key_gate_refuses_uninspectable_authorization(tmp_path, config, rc):
    _, result = key_gate(tmp_path, config, inspection_rc=rc)
    assert result.returncode != 0


def test_canary_has_no_database_writer_or_app_write_grant():
    unit = heredoc("cat > /etc/systemd/system/wins-gateway-canary.service <<'EOF'")
    # Audit L03 F-4 (Muse): the canary log moved out of the app-writable
    # /var/log/winsvpn, which is no longer in the canary's writable set.
    assert 'ReadWritePaths=/var/lib/wins-canary-results /var/lib/wins-canary-dispatch' in unit
    assert '/var/log/winsvpn' not in unit
    assert 'StateDirectory=wins-canary-results' in unit
    assert 'ReadOnlyPaths=/root/vpn_auth' in unit
    assert not re.search(r'\b(ALTER\s+TABLE|UPDATE\s+nodes|INSERT\s+INTO|DELETE\s+FROM)\b', CANARY, re.I)
    assert 'sqlite3.connect(path, timeout=30)' not in CANARY
    assert 'ReadOnlyPaths=/var/lib/wins-canary-results' in heredoc('cat > "${SERVICE_FILE}" <<EOF')


def test_result_binding_is_captured_before_probe():
    runner = body('run_external_winn3_canary_one', CANARY)
    assert 'wins-winn3-canary-runtime.py' in runner and '--slug "${slug}"' in runner
    runtime = (Path(__file__).parent / 'wins_winn3_canary_runtime.py').read_text()
    tree = ast.parse(runtime)
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_canary_slug')
    code = ast.get_source_segment(runtime, function)
    assert code.index("generation = row['deployment_generation']") < code.index('proof = winn3_probe_canary')
    assert 'connection.rollback()' in code
    assert 'winn3_write_canary_file' in code and '0o644' in code
    assert 'os.replace' in runtime and '?mode=ro' in runtime


def result_fixture():
    conn = sqlite3.connect(':memory:'); conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE nodes (slug TEXT, retired_at TEXT, winn3_identity_sha256 TEXT, deployment_generation INTEGER, winn3_descriptor_json TEXT, winn3_canary_status TEXT, winn3_canary_checked_at TEXT, winn3_canary_ok_at TEXT, winn3_canary_error TEXT, winn3_canary_identity_sha256 TEXT, winn3_canary_seq INTEGER, winn3_canary_generation INTEGER)')
    envelope = json.dumps({'payload': base64.b64encode(json.dumps({'seq': 7}).encode()).decode()})
    conn.execute('INSERT INTO nodes (slug, winn3_identity_sha256, deployment_generation, winn3_descriptor_json) VALUES (?, ?, ?, ?)', ('node-a', 'a' * 64, 3, envelope))
    conn.commit()
    app = app_functions('winn3_result_binding', 'ingest_winn3_canary_result',
                        WINN3_CANARY_HARD_STALE_MINUTES=30, utcnow=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    result = dict(slug='node-a', status='ok', detail='', identity_sha256='a' * 64, seq=7, generation=3,
                  checked_at=datetime.now(timezone.utc).isoformat())
    return app, conn, result


def test_result_ingest_updates_only_canary_columns_and_rejects_replay():
    app, conn, result = result_fixture()
    assert app.ingest_winn3_canary_result(conn, result, 'node-a')
    row = dict(conn.execute('SELECT * FROM nodes').fetchone())
    assert row['winn3_canary_status'] == 'ok'
    assert row['winn3_canary_identity_sha256'] == 'a' * 64
    assert row['winn3_canary_seq'] == 7 and row['winn3_canary_generation'] == 3
    assert row['deployment_generation'] == 3
    assert not app.ingest_winn3_canary_result(conn, result, 'node-a')


def test_freshness_cannot_reuse_proof_from_another_generation():
    app, conn, result = result_fixture()
    assert app.ingest_winn3_canary_result(conn, result, 'node-a')
    current = dict(conn.execute('SELECT * FROM nodes').fetchone())
    boundary = (datetime.fromisoformat(result['checked_at']) - timedelta(seconds=1)).isoformat()
    current.update(deployment_released_at=boundary, winn3_carrier_flipped_at=boundary)
    check = app_functions('parse_iso_datetime', 'winn3_result_binding', 'winn3_canary_is_fresh',
                          _node_field=lambda node, key: node.get(key),
                          WINN3_CANARY_HARD_STALE_MINUTES=30,
                          utcnow=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    assert check.winn3_canary_is_fresh(current)
    current['deployment_generation'] += 1
    assert not check.winn3_canary_is_fresh(current)


def freshness_check():
    return app_functions('parse_iso_datetime', 'winn3_result_binding', 'winn3_canary_is_fresh',
                         _node_field=lambda node, key: node.get(key),
                         WINN3_CANARY_HARD_STALE_MINUTES=30,
                         utcnow=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


def test_a_row_without_an_identity_binds_as_empty_until_h2_stores_one():
    app, conn, result = result_fixture()
    conn.execute('UPDATE nodes SET winn3_identity_sha256=NULL')
    assert not app.ingest_winn3_canary_result(conn, dict(result), 'node-a')  # claims an identity the row lacks
    result['identity_sha256'] = ''
    assert app.ingest_winn3_canary_result(conn, result, 'node-a')
    row = dict(conn.execute('SELECT * FROM nodes').fetchone())
    assert row['winn3_canary_identity_sha256'] == '' and row['winn3_canary_seq'] == 7
    check = freshness_check()
    assert not check.winn3_canary_is_fresh(row)  # H3 requires a tested identity
    row['winn3_identity_sha256'] = 'a' * 64  # H2 stores an identity: the earlier proof is stale
    assert not check.winn3_canary_is_fresh(row)


def test_a_row_without_a_descriptor_binds_seq_zero():
    app, conn, result = result_fixture()
    conn.execute('UPDATE nodes SET winn3_descriptor_json=NULL')
    assert not app.ingest_winn3_canary_result(conn, dict(result), 'node-a')  # claims seq 7
    result['seq'] = 0
    assert app.ingest_winn3_canary_result(conn, result, 'node-a')


def test_a_pre_h0_unbound_verdict_cannot_satisfy_h3_freshness():
    app, conn, result = result_fixture()
    row = dict(conn.execute('SELECT * FROM nodes').fetchone())
    row.update(winn3_canary_status='ok',
               winn3_canary_ok_at=datetime.now(timezone.utc).replace(tzinfo=None).isoformat())
    check = freshness_check()
    assert not check.winn3_canary_is_fresh(row)  # H3 requires the descriptor and generation binding
    row.update(winn3_canary_identity_sha256='a' * 64, winn3_canary_seq=6, winn3_canary_generation=3)
    assert not check.winn3_canary_is_fresh(row)  # a bound verdict for another descriptor


def test_result_fail_is_ingested_and_retired_or_unknown_slug_is_refused():
    app, conn, result = result_fixture(); result['status'] = 'fail'; result['detail'] = 'probe failed'
    assert app.ingest_winn3_canary_result(conn, result, 'node-a')
    assert conn.execute('SELECT winn3_canary_status FROM nodes').fetchone()[0] == 'fail'
    app, conn, result = result_fixture(); conn.execute("UPDATE nodes SET retired_at='retired'")
    assert not app.ingest_winn3_canary_result(conn, result, 'node-a')
    result['slug'] = 'unknown'
    assert not app.ingest_winn3_canary_result(conn, result, 'unknown')


@pytest.mark.parametrize('field,value', [('identity_sha256', 'b' * 64), ('seq', 8), ('generation', 4),
                                       ('slug', '../node-a'), ('status', 'probe_error'), ('detail', 'x' * 301),
                                       ('seq', True), ('generation', -1), ('extra', 'field'),
                                       ('checked_at', '2000-01-01T00:00:00+00:00'),
                                       ('checked_at', '2999-01-01T00:00:00+00:00')])
def test_result_ingest_refuses_bad_or_stale_bindings(field, value):
    app, conn, result = result_fixture(); result[field] = value
    assert not app.ingest_winn3_canary_result(conn, result, 'node-a')
    assert conn.execute('SELECT winn3_canary_status FROM nodes').fetchone()[0] is None

NODES_SCHEMA = ('CREATE TABLE nodes (slug TEXT, retired_at TEXT, winn3_identity_sha256 TEXT, deployment_generation INTEGER, '
                'winn3_descriptor_json TEXT, winn3_canary_status TEXT, winn3_canary_checked_at TEXT, winn3_canary_ok_at TEXT, '
                'winn3_canary_error TEXT, winn3_canary_identity_sha256 TEXT, winn3_canary_seq INTEGER, winn3_canary_generation INTEGER)')


def sweep_fixture(tmp_path, slugs, get_db=None):
    # The real sweep over real result files, with an fstat that reports root
    # ownership so the test runs unprivileged.
    db = tmp_path / 'hub.db'
    results = tmp_path / 'results'
    results.mkdir()
    with sqlite3.connect(db) as conn:
        conn.execute(NODES_SCHEMA)
        conn.executemany('INSERT INTO nodes (slug, deployment_generation) VALUES (?, 0)', [(slug,) for slug in slugs])
    conn.close()

    def fstat(fd):
        info = os.fstat(fd)
        fields = [info[index] for index in range(10)]
        fields[4] = 0
        return os.stat_result(fields, {name: getattr(info, name) for name in ('st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')})

    fake_os = types.ModuleType('os')
    fake_os.__dict__.update(os.__dict__)
    fake_os.fstat = fstat
    import logging
    import time
    from contextlib import ExitStack
    app = app_functions('get_db', 'winn3_result_binding', 'ingest_winn3_canary_result', 'ingest_winn3_canary_results_once',
                        os=fake_os, stat=stat, time=time, contextmanager=contextmanager, ExitStack=ExitStack,
                        DB_PATH=str(db), logger=logging.getLogger('h0-review'), WINN3_CANARY_RESULT_DIR=results,
                        WINN3_CANARY_RESULTS_SEEN={}, _WINN3_CANARY_RESULT_CURSOR='',
                        _WINN3_CANARY_RESULT_CURSOR_LOCK=threading.Lock(), WINN3_CANARY_HARD_STALE_MINUTES=30,
                        utcnow=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    if get_db is not None:
        app.ingest_winn3_canary_results_once.__globals__['get_db'] = get_db(app.get_db)
    return app, db, results


def write_result(results, slug, status='ok', checked_at=None):
    (results / (slug + '.json')).write_text(json.dumps(dict(
        slug=slug, status=status, detail='', identity_sha256='', seq=0, generation=0,
        checked_at=(checked_at or datetime.now(timezone.utc)).isoformat())))


def canary_status(db):
    with closing_connection(db) as conn:
        return dict(conn.execute('SELECT slug, winn3_canary_status FROM nodes').fetchall())


@contextmanager
def closing_connection(db):
    conn = sqlite3.connect(db)
    try:
        yield conn
    finally:
        conn.close()


def test_result_sweep_reaches_every_slug_past_64_and_skips_unchanged_files(tmp_path):
    # More than 64 results and orphaned canary temporary files must not starve
    # a slug (Sol-H0-T3-2), an unchanged committed file must not reopen the
    # database, and a locked database must be retried.
    slugs = ['node-%03d' % index for index in range(70)]
    opens, locked = [0], [1]

    def counting(real_get_db):
        @contextmanager
        def get_db():
            opens[0] += 1
            if locked[0]:
                locked[0] -= 1
                raise sqlite3.OperationalError('database is locked')
            with real_get_db() as conn:
                yield conn
        return get_db

    app, db, results = sweep_fixture(tmp_path, slugs, counting)
    for index in range(8):
        (results / ('.node-%03d.%032x' % (index, index))).write_text('{}')
    (results / 'notes.txt').write_text('unrelated')
    for slug in slugs:
        write_result(results, slug)
    accepted = [app.ingest_winn3_canary_results_once() for _ in range(3)]
    assert accepted == [63, 7, 0]  # the first attempt met the locked database
    assert set(canary_status(db).values()) == {'ok'}
    opens[0] = 0
    for _ in range(4):
        app.ingest_winn3_canary_results_once()
    assert opens[0] == 0
    (results / 'node-069.json').unlink()
    app.ingest_winn3_canary_results_once()
    assert 'node-069.json' not in app.WINN3_CANARY_RESULTS_SEEN and len(app.WINN3_CANARY_RESULTS_SEEN) == 69


def test_result_sweep_retries_a_newer_verdict_that_lost_its_conditional_update(tmp_path):
    # A competing older verdict commits between the newer result's read and its
    # conditional UPDATE (Sol-H0-T4-1). The refused newer result must stay
    # retryable, and win on the next sweep.
    now = datetime.now(timezone.utc)
    race = [1]

    def racing(real_get_db):
        class Racing:
            def __init__(self, conn):
                self.conn = conn

            def __getattr__(self, name):
                return getattr(self.conn, name)

            def execute(self, sql, *args):
                if sql.startswith('UPDATE nodes SET winn3_canary_status') and race and race.pop():
                    with closing_connection(db) as other:
                        other.execute("UPDATE nodes SET winn3_canary_status='fail', winn3_canary_checked_at=? "
                                      "WHERE slug='node-a'", ((now - timedelta(seconds=10)).replace(tzinfo=None).isoformat(),))
                        other.commit()
                return self.conn.execute(sql, *args)

        @contextmanager
        def get_db():
            with real_get_db() as conn:
                yield Racing(conn)
        return get_db

    app, db, results = sweep_fixture(tmp_path, ['node-a'], racing)
    write_result(results, 'node-a', 'ok', now)
    assert app.ingest_winn3_canary_results_once() == 0
    assert canary_status(db) == {'node-a': 'fail'}
    assert 'node-a.json' not in app.WINN3_CANARY_RESULTS_SEEN
    assert app.ingest_winn3_canary_results_once() == 1
    assert canary_status(db) == {'node-a': 'ok'}
    assert app.ingest_winn3_canary_results_once() == 0 and 'node-a.json' in app.WINN3_CANARY_RESULTS_SEEN
    # A result refused for a time 90 s ahead becomes admissible once the clock
    # catches up, without the canary rewriting the file.
    write_result(results, 'node-a', 'fail', datetime.now(timezone.utc) + timedelta(seconds=90))
    assert app.ingest_winn3_canary_results_once() == 0
    app.ingest_winn3_canary_result.__globals__['utcnow'] = (
        lambda: (datetime.now(timezone.utc) + timedelta(seconds=60)).replace(tzinfo=None))
    assert app.ingest_winn3_canary_results_once() == 1
    assert canary_status(db) == {'node-a': 'fail'}


def test_result_sweep_opens_one_connection_and_commits_each_result_alone(tmp_path):
    # Sol-H0-T3-PERF-1: one connection per sweep, opened only when a result
    # reaches the database. A failed commit rolls back that result only, keeps
    # it retryable, and never undoes a result committed before it.
    opens, fail_commit = [0], ['node-c']

    def failing(real_get_db):
        class Failing:
            def __init__(self, conn):
                self.conn, self.slug = conn, None

            def __getattr__(self, name):
                return getattr(self.conn, name)

            def execute(self, sql, *args):
                if sql.startswith('UPDATE nodes SET winn3_canary_status'):
                    self.slug = args[0][8]
                return self.conn.execute(sql, *args)

            def commit(self):
                if self.slug in fail_commit:
                    fail_commit.remove(self.slug)
                    raise sqlite3.OperationalError('database is locked')
                self.conn.commit()

        @contextmanager
        def get_db():
            opens[0] += 1
            with real_get_db() as conn:
                yield Failing(conn)
        return get_db

    app, db, results = sweep_fixture(tmp_path, ['node-a', 'node-b', 'node-c'], failing)
    for slug in ('node-a', 'node-b', 'node-c'):
        write_result(results, slug)
    assert app.ingest_winn3_canary_results_once() == 2
    assert opens[0] == 1
    assert canary_status(db) == {'node-a': 'ok', 'node-b': 'ok', 'node-c': None}
    assert app.ingest_winn3_canary_results_once() == 1
    assert opens[0] == 2
    assert canary_status(db) == {'node-a': 'ok', 'node-b': 'ok', 'node-c': 'ok'}
    assert app.ingest_winn3_canary_results_once() == 0
    assert opens[0] == 2  # everything is committed and cached: no connection at all


def test_result_sweep_aborts_when_a_rollback_fails_and_commits_nothing_after_it(tmp_path):
    # Sol-H0-T5-1: the middle result's commit and then its rollback fail, so
    # its UPDATE may still be pending on the shared connection. The sweep must
    # abort without committing it or any later result, keep the result
    # committed before it, and retry the rest on the next sweep.
    opens, fail = [0], ['node-b']

    def failing(real_get_db):
        class Failing:
            def __init__(self, conn):
                self.conn, self.slug = conn, None

            def __getattr__(self, name):
                return getattr(self.conn, name)

            def execute(self, sql, *args):
                if sql.startswith('UPDATE nodes SET winn3_canary_status'):
                    self.slug = args[0][8]
                return self.conn.execute(sql, *args)

            def commit(self):
                if self.slug in fail:
                    raise sqlite3.OperationalError('disk I/O error')
                self.conn.commit()

            def rollback(self):
                if self.slug in fail:
                    fail.remove(self.slug)
                    raise sqlite3.OperationalError('disk I/O error')
                self.conn.rollback()

        @contextmanager
        def get_db():
            opens[0] += 1
            with real_get_db() as conn:
                yield Failing(conn)
        return get_db

    app, db, results = sweep_fixture(tmp_path, ['node-a', 'node-b', 'node-c'], failing)
    for slug in ('node-a', 'node-b', 'node-c'):
        write_result(results, slug)
    with pytest.raises(RuntimeError) as aborted:
        app.ingest_winn3_canary_results_once()
    assert isinstance(aborted.value.__cause__, sqlite3.OperationalError)
    assert opens[0] == 1
    assert canary_status(db) == {'node-a': 'ok', 'node-b': None, 'node-c': None}
    assert set(app.WINN3_CANARY_RESULTS_SEEN) == {'node-a.json'}
    assert app.ingest_winn3_canary_results_once() == 2
    assert opens[0] == 2
    assert canary_status(db) == {'node-a': 'ok', 'node-b': 'ok', 'node-c': 'ok'}
    assert app.ingest_winn3_canary_results_once() == 0
    assert opens[0] == 2



def test_canary_entrypoints_always_use_the_sandbox_and_propagate_failure():
    code = body('run_prepublication_gateway_canary')
    assert '[[ "${canary_bin}" == "/usr/local/bin/wins-gateway-canary" ]]' in code
    assert 'if systemctl start wins-gateway-canary-prepublication.service; then' in code
    assert 'run_step "gateway fallback canary" systemctl start wins-gateway-canary.service' in SOURCE
    assert 'wins-gateway-canary-prepublication.service' in body('write_gateway_canary')
    for rc in [0, 1]:
        prelude = 'err() { :; }; log() { :; }; warn() { :; }; systemctl() { printf "called\\n"; return ' + str(rc) + '; };\n'
        result = bash(prelude + code + '\nrun_prepublication_gateway_canary\nrun_prepublication_gateway_canary',
                      PUBLIC_CANARY_ATTEMPTS='1', PUBLIC_CANARY_INTERVAL_SECONDS='0')
        assert result.returncode == rc
        assert result.stdout.count('called') == 2


@pytest.mark.parametrize('response,expected', [({'ssh_user': 'wins-site-ai'}, 'wins-site-ai'), ({}, 'root'),
                                            ({'ssh_user': 'root'}, 'root'), ({'ssh_user': 'other'}, None),
                                            ({'ssh_user': 'root; true'}, None)])
def test_core_uses_validated_registration_user(tmp_path, response, expected):
    start = CORE.index('registered_ssh_user="$(')
    end = CORE.index(': > "${registration_dir}/known-hosts"', start)
    code = CORE[start:end]
    (tmp_path / 'response').write_text(json.dumps(response))
    result = bash('set -e; CORE_AI_HUB_SSH_USER=root;\n' + code + '\nprintf "%s" "$CORE_AI_HUB_SSH_USER"', registration_dir=str(tmp_path))
    if expected is None: assert result.returncode == 65
    else: assert result.returncode == 0 and result.stdout == expected


def test_fresh_core_registration_and_autossh_use_the_non_root_account(tmp_path):
    keys = tmp_path / 'site-ai' / 'authorized_keys'
    hostkeys = tmp_path / 'hostkeys'; hostkeys.mkdir()
    (hostkeys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAHOST fixture\n')
    real_path = Path
    def paths(*parts):
        return hostkeys if parts and str(parts[0]) == '/etc/ssh' else real_path(*parts)
    @contextmanager
    def database(): yield object()
    names = ('register_site_ai_tunnel_key', '_site_ai_authorized_keys_path', '_site_ai_ownership_path',
             '_site_ai_ownership_flock', '_site_ai_owned_lines', '_site_ai_save_owned_lines',
             '_site_ai_key_blob_valid', '_authorized_key_line_blob', '_is_site_ai_tunnel_line')
    api = app_functions(*names, Path=paths, fcntl=fcntl, contextmanager=contextmanager,
                        app=types.SimpleNamespace(post=lambda *a, **k: lambda f: f),
                        Header=lambda *a, **k: None, SiteAiTunnelKeyRequest=object, Request=object,
                        DOUBLE_VPN_CORE_ID='test-core', SITE_AI_TUNNEL_SSH_USER='wins-site-ai',
                        get_db=database, ensure_schema=lambda conn: None, require_core_token=lambda *a: None,
                        _SITE_AI_TUNNEL_LOCK=threading.Lock(),
                        _SITE_AI_TUNNEL_PREFIX='restrict,port-forwarding,permitlisten="127.0.0.1:',
                        _SSH_KEY_TYPES_FOR_BLOB=('ssh-ed25519', 'ssh-rsa'),
                        # main.py imports urllib at module top; the handler binds the
                        # tunnel to the port of SITE_AI_LOCAL_ENDPOINT (audit hub-b F-3).
                        urllib=urllib, SITE_AI_LOCAL_ENDPOINT='http://127.0.0.1:11435')
    blob = base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + bytes(32)).decode()
    payload = types.SimpleNamespace(core_id='test-core', public_key='ssh-ed25519 ' + blob,
                                    listen_port=11435, label='fresh-core')
    with patch.dict(os.environ, SITE_AI_TUNNEL_AUTHORIZED_KEYS_FILE=str(keys),
                    SITE_AI_TUNNEL_OWNERSHIP_FILE=str(tmp_path / 'owned.json')):
        response = api.register_site_ai_tunnel_key(payload, object(), 'fixture-core-token')
    assert response['ssh_user'] == 'wins-site-ai'
    assert blob in keys.read_text()
    assert not (tmp_path / 'root' / '.ssh' / 'authorized_keys').exists()
    (tmp_path / 'response').write_text(json.dumps(response))
    start = CORE.index('registered_ssh_user="$(')
    end = CORE.index(': > "${registration_dir}/known-hosts"', start)
    tunnel = CORE[CORE.index('exec autossh -M 0 -N', end):].split('\nEOF\n', 1)[0]
    bin_dir = tmp_path / 'bin'; bin_dir.mkdir()
    (bin_dir / 'autossh').write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    (bin_dir / 'autossh').chmod(0o755)
    result = bash('set -e; CORE_AI_HUB_SSH_USER=root;\n' + CORE[start:end] + tunnel,
                  PATH=str(bin_dir) + ':' + os.environ['PATH'], registration_dir=str(tmp_path),
                  CORE_AI_HUB_SSH_HOST='hub.example.test', CORE_AI_TUNNEL_KNOWN_HOSTS=str(tmp_path / 'known-hosts'),
                  CORE_AI_TUNNEL_KEY=str(tmp_path / 'fresh-key'), CORE_AI_HUB_TUNNEL_PORT='11435', CORE_AI_PORT='11434')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == 'wins-site-ai@hub.example.test'


def test_socket_inventory_and_adversarial_checks_cover_abstract_and_submounts():
    assert 'find /run -xdev' not in TIER
    assert '/proc/net/unix' in TIER and 'SOCK_DGRAM' in TIER
    assert 'SOCK_SEQPACKET' in TIER
    assert 'refuse_hub_abstract_brokers' in body('preflight_control')
    assert 'refuse_hub_abstract_brokers' in body('postflight_control')
    assert 'root@127.0.0.1' in TIER and 'IdentityAgent=none' in TIER and 'IdentitiesOnly=yes' in TIER
    assert '/venv/bin/.h0-tier-a' in TIER


def test_root_key_gate_reads_a_free_text_comment_and_quoted_options(tmp_path):
    config = 'authorizedkeysfile %h/keys/authorized_keys\nauthorizedkeyscommand none\ntrustedusercakeys none'
    keys, _ = key_gate(tmp_path, config)
    (keys / 'authorized_keys').write_text("ssh-ed25519 AAAAOPERATOR Win's MacBook\n")
    _, result = key_gate(tmp_path, config)
    assert result.returncode == 0, result.stderr
    (keys / 'authorized_keys').write_text('command="echo a, b",from="127.0.0.1" ssh-rsa AAAAHUBKEY Win\'s hub\n')
    _, result = key_gate(tmp_path, config)
    assert result.returncode != 0 and 'authorized for root' in result.stderr
    (keys / 'authorized_keys').write_text('command="echo a b",cert-authority ssh-ed25519 AAAACA ca\n')
    _, result = key_gate(tmp_path, config)
    assert result.returncode != 0 and 'certificate authority' in result.stderr


UNIX_HEADER = 'Num       RefCount Protocol Flags    Type St Inode Path\n'
UNIX_ROWS = {
    'listening stream': '0000000000000000: 00000002 00000000 00010000 0001 01 23456 @/org/kernel/linux/storage/multipathd\n',
    'connected client': '0000000000000000: 00000003 00000000 00000000 0001 03 34567 @0003a\n',
    'connected datagram': '0000000000000000: 00000002 00000000 00000000 0002 03 45678 @0003b\n',
    'bound datagram': '0000000000000000: 00000002 00000000 00000000 0002 01 45679 @ISCSIADM_ABSTRACT_NAMESPACE\n',
    'pathname listener': '0000000000000000: 00000002 00000000 00010000 0001 01 56789 /run/systemd/private\n',
}


@pytest.mark.parametrize('rows,refused', [
    (('connected client', 'pathname listener'), ()),
    (('connected client', 'connected datagram', 'pathname listener'), ('@0003b',)),
    (('listening stream', 'connected client'), ('@/org/kernel/linux/storage/multipathd',)),
    (('bound datagram', 'connected datagram'), ('@ISCSIADM_ABSTRACT_NAMESPACE', '@0003b')),
])
def test_abstract_gate_names_every_reachable_endpoint_and_only_those(tmp_path, rows, refused):
    table = tmp_path / 'unix'
    table.write_text(UNIX_HEADER + ''.join(UNIX_ROWS[row] for row in rows))
    result = bash(body('refuse_hub_abstract_brokers').replace('/proc/net/unix', str(table))
                  + '\nrefuse_hub_abstract_brokers')
    assert (result.returncode != 0) == bool(refused), result.stderr
    for name in refused:
        assert name in result.stderr
    assert '@0003a' not in result.stderr


def abstract_gate_code():
    """The gate's Python, extracted as the Linux-only test below runs it."""
    return heredoc("python3 -I - <<'ABSTRACTEOF'", body('refuse_hub_abstract_brokers'))


def test_abstract_gate_extraction_compiles_and_runs_the_gate_on_any_host():
    """FINAL4 F4-MPATH (Astra, Turn 2): the heredoc line now ends in
    `|| rc=$?`, and the extraction took that shell text as Python, so the
    Linux-only test raised SyntaxError. This runs the same extraction where
    /proc/net/unix is absent, with the table read patched as there."""
    code = abstract_gate_code()
    assert code.startswith('import os\n') and 'ABSTRACTEOF' not in code and 'rc=$?' not in code
    gate = compile(code, '<abstract-gate>', 'exec')
    with patch.dict(os.environ, WINS_HUB_ABSTRACT_GATE_MODE='strict'):
        with patch.object(Path, 'read_text', return_value=UNIX_HEADER + UNIX_ROWS['connected client']):
            exec(gate, {})
        with patch.object(Path, 'read_text', return_value=UNIX_HEADER + UNIX_ROWS['bound datagram']), \
                pytest.raises(SystemExit, match=re.escape('@ISCSIADM_ABSTRACT_NAMESPACE (datagram, inode 45679)')):
            exec(gate, {})
    with patch.dict(os.environ, WINS_HUB_ABSTRACT_GATE_MODE='preflight'), \
            patch.object(Path, 'read_text', return_value=UNIX_HEADER + UNIX_ROWS['listening stream']), \
            pytest.raises(SystemExit) as stock:
        exec(gate, {})
    assert stock.value.code == 10


def test_abstract_datagram_server_stays_reachable_after_a_client_connects():
    proc = Path('/proc/net/unix')
    if not proc.is_file():
        pytest.skip('Linux /proc/net/unix is required')
    name = '\0h0-review-' + os.urandom(16).hex()
    shown = '@' + name[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server, \
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as first, \
            socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as second:
        server.settimeout(1)
        server.bind(name)
        first.connect(name)
        row = next(
            line for line in proc.read_text().splitlines()[1:]
            if line.split(None, 7)[-1] == shown
        )
        fields = row.split(None, 7)
        assert fields[4:6] == ['0002', '03']
        second.sendto(b'probe', name)
        assert server.recv(16) == b'probe'
        code = abstract_gate_code()
        with patch.object(Path, 'read_text', return_value=UNIX_HEADER + row + '\n'), \
                pytest.raises(SystemExit, match=re.escape(shown)):
            exec(compile(code, '<abstract-gate>', 'exec'), {})


# The stock Ubuntu 24.04 server image's storage daemons (multipath-tools and
# open-iscsi) listen on two abstract names. --preflight may report exactly
# those listeners on a host that does not use them; a deploy masks their units
# and then runs the gate strictly. Everything else is still refused.
STOCK_ROWS = {
    'multipathd': '0000000000000000: 00000002 00000000 00010000 0001 01 61001 @/org/kernel/linux/storage/multipathd\n',
    'iscsid': '0000000000000000: 00000002 00000000 00010000 0001 01 61002 @ISCSIADM_ABSTRACT_NAMESPACE\n',
    'multipathd seqpacket': '0000000000000000: 00000002 00000000 00010000 0005 01 61003 @/org/kernel/linux/storage/multipathd\n',
    'iscsid datagram': UNIX_ROWS['bound datagram'],
    'other listener': '0000000000000000: 00000002 00000000 00010000 0001 01 61004 @/tmp/.X11-unix/X0\n',
    'connected datagram': UNIX_ROWS['connected datagram'],
    'connected client': UNIX_ROWS['connected client'],
}
STOCK_UNITS = ['multipathd.socket', 'multipathd.service', 'iscsid.socket', 'iscsid.service', 'open-iscsi.service']
SYSTEMCTL_STUB = r'''#!/bin/bash
echo "$*" >> "${SYSTEMCTL_LOG}"
case "$1" in
  list-unit-files) [[ " ${PRESENT_UNITS:-} " == *" $3 "* ]] && echo "$3 enabled enabled"; exit 0 ;;
  disable)
    if [[ "${STOPS:-1}" == "1" ]]; then
      case "$3" in
        multipathd.service) grep -v 'storage/multipathd' "${UNIX_TABLE}" > "${UNIX_TABLE}.new"; mv "${UNIX_TABLE}.new" "${UNIX_TABLE}" ;;
        iscsid.service) grep -v 'ISCSIADM_ABSTRACT_NAMESPACE' "${UNIX_TABLE}" > "${UNIX_TABLE}.new"; mv "${UNIX_TABLE}.new" "${UNIX_TABLE}" ;;
      esac
    fi
    exit 0 ;;
  mask) exit "${MASK_RC:-0}" ;;
esac
exit 0
'''
MULTIPATH_STUB = '#!/bin/bash\necho "$*" >> "${MULTIPATH_LOG}"\nprintf "%s" "${MPATH_OUT:-}"\n'
# Logs its arguments, then runs the command past `-k GRACE` and the duration.
TIMEOUT_STUB = ('#!/bin/bash\necho "$*" >> "${TIMEOUT_LOG}"\n[[ -n "${TIMEOUT_RC:-}" ]] && exit "${TIMEOUT_RC}"\n'
                '[[ "$1" == -k ]] && shift 2\nshift\nexec "$@"\n')


def link(path, target):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(os.path.relpath(target, path.parent))


def storage_host(tmp_path, *, mpath=False, session=False, root_on=None, root_dev='253:0', mountinfo_missing=False):
    """A sysfs tree like the live hub: virtio disk, LUKS root, ext4 /boot, vfat ESP."""
    sys_root = tmp_path / 'sys'
    disk = sys_root / 'devices/pci0000:00/0000:00:04.0/virtio1/block/vda'
    if root_on == 'iscsi':
        disk = sys_root / 'devices/platform/host3/session1/target3:0:0/3:0:0:0/block/sdb'
    for number in (1, 2, 3):
        (disk / f'{disk.name}{number}').mkdir(parents=True)
        (disk / f'{disk.name}{number}/partition').write_text(f'{number}\n')
    crypt = sys_root / 'devices/virtual/block/dm-0'
    (crypt / 'dm').mkdir(parents=True)
    (crypt / 'dm/uuid').write_text('CRYPT-LUKS2-0123456789abcdef-dm_crypt-0\n')
    if root_on == 'mpath':
        # Reachable only through the root's slaves, so the stack walk is what finds it.
        hidden = sys_root / 'devices/virtual/block/dm-2'
        (hidden / 'dm').mkdir(parents=True)
        (hidden / 'dm/uuid').write_text('part1-mpath-3600a098038303053743f4a6f4d6b6e6f\n')
        link(crypt / 'slaves/dm-2', hidden)
    else:
        link(crypt / f'slaves/{disk.name}3', disk / f'{disk.name}3')
    link(sys_root / f'block/{disk.name}', disk)
    link(sys_root / 'block/dm-0', crypt)
    link(sys_root / 'dev/block/253:0', crypt)
    link(sys_root / 'dev/block/252:1', disk / f'{disk.name}1')
    link(sys_root / 'dev/block/252:2', disk / f'{disk.name}2')
    if mpath:
        unused = sys_root / 'devices/virtual/block/dm-1'
        (unused / 'dm').mkdir(parents=True)
        (unused / 'dm/uuid').write_text('mpath-3600a098038303053743f4a6f4d6b6e6f\n')
        link(sys_root / 'block/dm-1', unused)
    if session:
        (sys_root / 'class/iscsi_session/session1').mkdir(parents=True)
    mountinfo = tmp_path / 'mountinfo'
    if mountinfo_missing:
        return sys_root, mountinfo
    mountinfo.write_text(f'25 1 {root_dev} / / rw,relatime shared:1 - ext4 /dev/mapper/dm_crypt-0 rw\n'
                         '30 25 252:2 / /boot rw,relatime shared:2 - ext4 /dev/vda2 rw\n'
                         '31 30 252:1 / /boot/efi rw,relatime shared:3 - vfat /dev/vda1 rw\n'
                         '40 25 0:25 / /proc rw,nosuid shared:4 - proc proc rw\n')
    return sys_root, mountinfo


def storage_gate(tmp_path, rows, call, *, source=SOURCE, sys_root=None, mountinfo=None, **env):
    if sys_root is None:
        sys_root, mountinfo = storage_host(tmp_path)
    table = tmp_path / 'unix'
    table.write_text(UNIX_HEADER + ''.join(STOCK_ROWS[row] for row in rows))
    stubs = tmp_path / 'stubs'
    stubs.mkdir(exist_ok=True)
    for name, text in [('systemctl', SYSTEMCTL_STUB), ('multipath', MULTIPATH_STUB), ('timeout', TIMEOUT_STUB)]:
        (stubs / name).write_text(text)
        (stubs / name).chmod(0o755)
    functions = ''.join(body(name, source) for name in [
        'refuse_hub_abstract_brokers', 'hub_stock_abstract_units',
        'refuse_hub_storage_brokers_in_use', 'hub_mask_stock_abstract_services'])
    functions = (functions.replace('/proc/net/unix', str(table))
                 .replace("SYS = '/sys'", f"SYS = '{sys_root}'")
                 .replace("MOUNTINFO = '/proc/self/mountinfo'", f"MOUNTINFO = '{mountinfo}'"))
    script = 'log() { echo "LOG $*"; }\nerr() { echo "ERR $*"; }\n' + functions + '\n' + call
    values = dict(PATH=f"{stubs}:{os.environ['PATH']}", UNIX_TABLE=str(table),
                  SYSTEMCTL_LOG=str(tmp_path / 'systemctl.log'), MULTIPATH_LOG=str(tmp_path / 'multipath.log'),
                  TIMEOUT_LOG=str(tmp_path / 'timeout.log'))
    values.update(env)
    result = bash(script, **values)
    calls = (tmp_path / 'systemctl.log').read_text().splitlines() if (tmp_path / 'systemctl.log').exists() else []
    return result, calls


def test_fresh_image_preflight_reports_only_the_stock_listeners_and_changes_nothing(tmp_path):
    result, calls = storage_gate(tmp_path, ('multipathd', 'iscsid', 'connected client'),
                                 'refuse_hub_abstract_brokers preflight')
    assert result.returncode == 0, result.stdout + result.stderr
    assert '@/org/kernel/linux/storage/multipathd (stream' in result.stdout
    assert '@ISCSIADM_ABSTRACT_NAMESPACE (stream' in result.stdout
    assert 'Nothing was changed' in result.stdout
    assert calls == []
    assert (tmp_path / 'multipath.log').read_text().split() == ['-ll']
    # FINAL4 (Claude seat, Turn 2 note 3): a listing that ignores SIGTERM is
    # killed after a grace, so it cannot hold --preflight or --deploy.
    assert (tmp_path / 'timeout.log').read_text().splitlines() == ['-k 5 60 multipath -ll']


@pytest.mark.parametrize('mode', ['preflight', 'strict', ''])
@pytest.mark.parametrize('rows,named', [
    (('multipathd', 'iscsid', 'other listener'), '@/tmp/.X11-unix/X0'),
    (('multipathd', 'connected datagram'), '@0003b'),
    (('iscsid datagram',), '@ISCSIADM_ABSTRACT_NAMESPACE (datagram'),
    (('multipathd seqpacket',), '@/org/kernel/linux/storage/multipathd (seqpacket'),
    (('other listener',), '@/tmp/.X11-unix/X0'),
])
def test_every_endpoint_outside_the_stock_pair_is_refused_in_every_mode(tmp_path, mode, rows, named):
    result, calls = storage_gate(tmp_path, rows, f'refuse_hub_abstract_brokers {mode}')
    assert result.returncode != 0
    assert named in result.stderr
    assert calls == []


@pytest.mark.parametrize('mode', ['strict', ''])
def test_strict_gate_still_refuses_the_stock_listeners(tmp_path, mode):
    result, _ = storage_gate(tmp_path, ('multipathd', 'iscsid'), f'refuse_hub_abstract_brokers {mode}',
                             WINS_HUB_ABSTRACT_GATE_MODE='preflight')
    assert result.returncode != 0
    assert '@/org/kernel/linux/storage/multipathd' in result.stderr
    assert '@ISCSIADM_ABSTRACT_NAMESPACE' in result.stderr


def test_an_unknown_gate_mode_is_refused(tmp_path):
    result, _ = storage_gate(tmp_path, ('multipathd',), 'refuse_hub_abstract_brokers lenient')
    assert result.returncode != 0 and 'Unknown abstract-broker gate mode' in result.stdout


IN_USE = {
    'multipath map': (dict(mpath=True), {}, 'dm-multipath map dm-1'),
    'iscsi session': (dict(session=True), {}, 'iSCSI session session1'),
    'root on multipath': (dict(root_on='mpath'), {}, '/ is on dm-multipath device dm-2'),
    'root on iscsi': (dict(root_on='iscsi'), {}, '/ is on iSCSI device sdb3'),
    'multipath -ll lists a map': ({}, dict(MPATH_OUT='mpatha (3600a0980) dm-1 NETAPP,LUN\n'), 'multipath -ll lists a map'),
    'multipath -ll hangs': ({}, dict(TIMEOUT_RC='124'), 'did not finish'),
    'multipath -ll is killed': ({}, dict(TIMEOUT_RC='137'), 'did not finish'),
    'root device unresolvable': (dict(root_dev='253:9'), {}, 'Cannot resolve the block device under /'),
    'mount table unreadable': (dict(mountinfo_missing=True), {}, 'Cannot establish whether this host uses'),
}


@pytest.mark.parametrize('case', sorted(IN_USE))
def test_preflight_refuses_the_stock_listeners_on_a_host_that_uses_them(tmp_path, case):
    host, env, message = IN_USE[case]
    sys_root, mountinfo = storage_host(tmp_path, **host)
    result, calls = storage_gate(tmp_path, ('multipathd', 'iscsid'), 'refuse_hub_abstract_brokers preflight',
                                 sys_root=sys_root, mountinfo=mountinfo, **env)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert 'Nothing was changed' not in result.stdout
    assert calls == []


@pytest.mark.parametrize('case', sorted(IN_USE))
def test_deploy_masks_nothing_on_a_host_that_uses_multipath_or_iscsi(tmp_path, case):
    host, env, message = IN_USE[case]
    sys_root, mountinfo = storage_host(tmp_path, **host)
    result, calls = storage_gate(tmp_path, ('multipathd', 'iscsid'),
                                 'hub_mask_stock_abstract_services || exit 1\nrefuse_hub_abstract_brokers',
                                 sys_root=sys_root, mountinfo=mountinfo, PRESENT_UNITS=' '.join(STOCK_UNITS), **env)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert [call for call in calls if not call.startswith('list-unit-files')] == []


def test_fresh_image_deploy_masks_the_stock_units_and_then_passes_the_strict_gate(tmp_path):
    result, calls = storage_gate(tmp_path, ('multipathd', 'iscsid', 'connected client'),
                                 'hub_mask_stock_abstract_services || exit 1\nrefuse_hub_abstract_brokers',
                                 PRESENT_UNITS=' '.join(STOCK_UNITS))
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == ([f'list-unit-files --no-legend {unit}' for unit in STOCK_UNITS]
                     + [call for unit in STOCK_UNITS for call in (f'disable --now {unit}', f'mask {unit}')])
    assert 'Masked the stock storage units' in result.stdout and 'systemctl unmask' in result.stdout


def test_deploy_masks_only_installed_units_and_the_strict_gate_judges_the_rest(tmp_path):
    (tmp_path / 'partial').mkdir()
    (tmp_path / 'none').mkdir()
    result, calls = storage_gate(tmp_path / 'partial', ('multipathd', 'iscsid'),
                                 'hub_mask_stock_abstract_services || exit 1\nrefuse_hub_abstract_brokers',
                                 PRESENT_UNITS='multipathd.socket multipathd.service')
    assert result.returncode != 0
    assert '@ISCSIADM_ABSTRACT_NAMESPACE' in result.stderr and 'storage/multipathd' not in result.stderr
    assert not any('iscsi' in call for call in calls if not call.startswith('list-unit-files'))
    result, calls = storage_gate(tmp_path / 'none', (), 'hub_mask_stock_abstract_services || exit 1\nrefuse_hub_abstract_brokers')
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(call.startswith('list-unit-files') for call in calls)


def test_deploy_fails_when_a_unit_cannot_be_masked_or_stopped(tmp_path):
    deploy = 'hub_mask_stock_abstract_services || exit 1\nrefuse_hub_abstract_brokers'
    (tmp_path / 'mask').mkdir()
    (tmp_path / 'stop').mkdir()
    result, _ = storage_gate(tmp_path / 'mask', ('multipathd', 'iscsid'), deploy,
                             PRESENT_UNITS=' '.join(STOCK_UNITS), MASK_RC='1')
    assert result.returncode != 0 and 'Could not mask multipathd.socket' in result.stdout
    result, _ = storage_gate(tmp_path / 'stop', ('multipathd', 'iscsid'), deploy,
                             PRESENT_UNITS=' '.join(STOCK_UNITS), STOPS='0')
    assert result.returncode != 0 and '@/org/kernel/linux/storage/multipathd' in result.stderr


def test_only_a_deploy_masks_and_only_after_the_read_only_preflight_checks():
    preflight = body('preflight_control')
    read_only, deploy = preflight.split('  if [[ "${preflight_mode}" == "read-only" ]]; then\n', 1)[1].split('  else\n', 1)
    deploy = deploy.split('  fi\n', 1)[0]
    assert read_only.strip() == 'refuse_hub_abstract_brokers preflight || exit 1'
    assert 'hub_mask_stock_abstract_services' not in read_only
    assert [line.strip() for line in deploy.strip().splitlines()[-2:]] == ['hub_mask_stock_abstract_services || exit 1',
                                                'refuse_hub_abstract_brokers || exit 1']
    masked = preflight.index('hub_mask_stock_abstract_services')
    for check in ('require_supported_production_os', 'role_file}" && "$(tr', 'validate_external_secret_contract',
                  'refuse_hub_keys_authorized_for_root_here'):
        assert preflight.index(check) < masked, check
    assert 'preflight_mode="${1:-deploy}"' in preflight
    main = body('main')
    preview, deploy_path = main.split('    --repair-recovery-contract)', 1)[0], main.split('\n  esac\n', 1)[1]
    assert '      preflight_control read-only\n' in preview
    assert '\n  preflight_control\n' in deploy_path and 'read-only' not in deploy_path
    postflight = body('postflight_control')
    assert postflight.index('hub_mask_stock_abstract_services || return 1') \
        < postflight.index('refuse_hub_abstract_brokers || return 1')
    assert 'refuse_hub_abstract_brokers preflight' not in postflight


def test_spa_helper_prepares_a_boot_persistent_xtables_lock():
    assert 'prepare_wins_xtables_lock' in body('write_hub_spa_window_helper')
    assert 'f /run/xtables.lock 0600 root root -' in body('prepare_wins_xtables_lock')
    unit = heredoc("cat > /etc/systemd/system/wins-hub-spa-window.service <<'EOF'")
    assert 'ReadWritePaths=/run/wins-hub-spa-window /run/xtables.lock' in unit
    assert 'After=systemd-tmpfiles-setup.service' in unit


def test_inventory_covers_every_rendered_privileged_entrypoint():
    inventory = json.loads((ROOT / 'server/h0_privileged_jobs.json').read_text())
    assert inventory['source_sha256'] == hashlib.sha256(SOURCE.encode()).hexdigest()
    # R22 Y1 F3: the digest alone proved nothing once. A pin tool kept it
    # current while every line pointer past main.py was 15 low and one call
    # was missing. Regenerating from the same source must give the stored file.
    spec = importlib.util.spec_from_file_location('h0_privileged_job_inventory',
                                                  ROOT / 'server/h0_privileged_job_inventory.py')
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    assert generator.inventory(SOURCE) == inventory, (
        'server/h0_privileged_jobs.json is stale: run python3 -B server/h0_privileged_job_inventory.py')
    entries = inventory['units']
    for name in ['wins-paypal-sync.service', 'wins-monero-poll.service', 'wins-redemption-outbox.service',
                 'wins-donor-ack-outbox.service', 'wins-hoppy-agent-outbox.service',
                 'wins-security-alert-monitor.service', 'wins-weekly-maintenance.service',
                 'wins-suricata-update.service', 'wins-gateway-canary.service']:
        assert any(name in item['target'] for item in entries), name
    assert all('exec' in item and 'data_consumers' in item and 'sandbox' in item for item in entries)
    assert any(item['target'] == 'installer:setup_python' for item in inventory['other_entrypoints'])


def test_resolver_rebind_and_real_canary_write_denial_are_in_tier_a():
    assert 'resolver replacement' in TIER and 'wins-h0-canary-write-' in TIER
    assert 'sqlite3.connect' in TIER and 'UPDATE nodes' in TIER
