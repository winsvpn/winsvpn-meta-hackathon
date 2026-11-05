"""Offline regressions for Sol-H0-T2-1: the root weekly maintenance helper must
never write inside a directory the sandboxed hub app can write, so a symlink the
app plants there cannot redirect a root write onto a privileged file."""
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('H0_REVIEW_SOURCE', ROOT / 'server/wins_control_plane_setup_ONETOUCH.sh')).read_text()
HELPER_HEADER = "cat > /usr/local/bin/wins-weekly-maintenance <<'EOF'"
WEEKLY_DIR = '/var/log/wins-weekly-maintenance'
APP_LOG_DIR = '/var/log/winsvpn'
ROOT_DIR_LINE = 'install -d -m 0700 -o root -g root /var/log/wins-weekly-maintenance'
BASH = shutil.which('bash')
REAL_INSTALL = shutil.which('install')


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
    start = source.index(header) + len(header) + 1
    tag = re.search(r"<<'?([A-Z0-9_]+)'?$", header)[1]
    return source[start:source.index('\n' + tag + '\n', start)]


def under(path, root):
    return path == root or path.startswith(root.rstrip('/') + '/')


# --- static write-target scan ----------------------------------------------
# Every command that can create, truncate, rename or re-mode a path, and every
# output redirection, is collected and its target expanded against the
# helper's own top-level assignments. A target that cannot be expanded is a
# finding: the scan has to prove where each root write lands.

WRITERS = {'mv', 'cp', 'tee', 'touch', 'install', 'chmod', 'chown', 'ln', 'rm', 'truncate', 'mkdir', 'sed', 'dd'}
PREFIXES = {'if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', 'time', 'exec', '{', '}'}
REDIRECT = re.compile(r'\d*(?:&>>?|>>|>\||>&|<>|>|<<<|<<-?|<&|<)')


def strip_comments(text):
    kept = []
    for line in text.splitlines():
        quote = None
        for i, c in enumerate(line):
            if quote:
                if c == quote and not (quote == '"' and line[i - 1] == '\\'): quote = None
            elif c in '\'"': quote = c
            elif c == '#' and (i == 0 or line[i - 1] in ' \t;'):
                line = line[:i]
                break
        kept.append(line)
    return '\n'.join(kept)


def lift(text, segments):
    """Replace $(...), <(...) and >(...) with placeholders; queue their bodies."""
    out, i = '', 0
    while (m := re.compile(r'[$<>]\(').search(text, i)):
        j, depth, k, quote = m.start(), 1, m.end(), None
        while depth:
            c = text[k]
            if quote:
                if c == quote: quote = None
            elif c in '\'"': quote = c
            elif c == '(': depth += 1
            elif c == ')': depth -= 1
            k += 1
        inner = lift(text[m.end():k - 1], segments)
        dirname = re.fullmatch(r'\s*dirname\s+(\S+)\s*', inner)
        if text[j] == '$' and dirname:
            out += text[i:j] + '@DIRNAME[' + dirname[1].strip('"\'') + ']@'
        else:
            out += text[i:j] + ('' if text[j] == '$' else text[j] + ' ') + '@CMDSUB@'
            segments.append(inner)
        i = k
    return out + text[i:]


def simple_commands(text):
    out, cmd, word, quote, pending, i = [], [], '', None, None, 0

    def flush_word():
        nonlocal word, pending
        if word:
            cmd.append((pending, word) if pending else word)
            pending = None
        word = ''

    def flush_cmd():
        nonlocal cmd
        flush_word()
        if cmd: out.append(cmd)
        cmd = []

    while i < len(text):
        c = text[i]
        if quote:
            word += c
            if c == quote and not (quote == '"' and text[i - 1] == '\\'): quote = None
            i += 1
        elif c in '\'"':
            quote = c; word += c; i += 1
        elif c == '\\' and i + 1 < len(text):
            word += text[i:i + 2]; i += 2
        elif c in ' \t':
            flush_word(); i += 1
        elif (c in '<>' or text.startswith('&>', i)
              or (c.isdigit() and not word and re.match(r'\d+[<>]', text[i:]))):
            flush_word()
            m = REDIRECT.match(text, i)
            pending, i = m[0], m.end()
            while i < len(text) and text[i] in ' \t': i += 1
        elif text.startswith(('&&', '||', ';;'), i):
            flush_cmd(); i += 2
        elif c in ';|&()\n':
            flush_cmd(); i += 1
        else:
            word += c; i += 1
    flush_cmd()
    return out


def write_targets(script):
    """(target word, command) for every write redirection and writer operand."""
    text = strip_comments(script).replace('\\\n', ' ')
    text = re.sub(r'\$?\(\((?:[^()]|\([^()]*\))*\)\)', '0', text)
    segments = []
    pieces = [lift(text, segments)] + segments
    found = []
    for piece in pieces:
        piece = re.sub(r'\[\[.*?\]\]', '[[ ]]', piece)
        for cmd in simple_commands(piece):
            shown = ' '.join(t if isinstance(t, str) else t[0] + t[1] for t in cmd)
            for tok in cmd:
                if isinstance(tok, tuple) and '>' in tok[0] and not re.fullmatch(r'\d+|-', tok[1]):
                    found.append((tok[1], shown))
            words = [t for t in cmd if isinstance(t, str)]
            while words and (words[0] in PREFIXES or re.match(r'[A-Za-z_]\w*=', words[0])):
                words = words[1:]
            if words[:1] == ['run_step']: words = words[2:]
            if not words or words[0] not in WRITERS: continue
            name, operands, args, options_done = words[0], [], iter(words[1:]), False
            for arg in args:
                if not options_done and arg == '--': options_done = True
                elif not options_done and arg.startswith('-') and arg != '-':
                    if name == 'install' and arg in ('-m', '-o', '-g'): next(args, None)
                else: operands.append(arg)
            if name == 'dd': operands = [a[3:] for a in operands if a.startswith('of=')]
            if name == 'chmod' or (name == 'sed' and '-e' not in words): operands = operands[1:]
            if name == 'sed' and not any(w == '-i' or w.startswith('-i') for w in words): operands = []
            found += [(operand, shown) for operand in operands]
    return found


class Unresolved(Exception):
    pass


def expand(word, env):
    text = word.replace('"', '').replace("'", '')
    text = re.sub(r'@DIRNAME\[(.*?)\]@', lambda m: posixpath.dirname(expand(m[1], env)), text)

    def var(m):
        name = m['name'] or m['bare']
        if name in env: return env[name]
        if m['default'] is not None: return expand(m['default'], env)
        raise Unresolved(name)

    text = re.sub(r'\$\{(?P<name>\w+)(?::-(?P<default>[^}]*))?\}|\$(?P<bare>[A-Za-z_]\w*)', var, text)
    if '$' in text or '@CMDSUB@' in text: raise Unresolved(text)
    return text


def helper_env(helper):
    env = {}
    for name, raw in re.findall(r'^([A-Z_][A-Z0-9_]*)="(.*)"$', helper, re.M):
        try: env[name] = expand(raw, env)
        except Unresolved: pass
    # A `while read -r VAR ... done < <(find DIR ...)` loop names files in DIR.
    for name, directory in re.findall(r'read -r (\w+)[^\n]*\n(?:(?!\bdone\b)[\s\S])*?done < <\(find (\S+)', helper):
        try: env[name] = expand(directory, env) + '/*.log'
        except Unresolved: pass
    return env


def app_writable_roots(source):
    app_dir = re.search(r'^APP_DIR="([^"]+)"$', source, re.M)[1]
    unit = heredoc('cat > "${SERVICE_FILE}" <<EOF', source)
    roots = []
    for line in re.findall(r'^ReadWritePaths=(.*)$', unit, re.M):
        roots += [w.lstrip('-+').replace('${APP_DIR}', app_dir) for w in line.split()]
    return roots


def resolved_targets(source):
    helper = heredoc(HELPER_HEADER, source)
    env = helper_env(helper)
    resolved, problems = [], []
    for target, shown in write_targets(helper):
        try: resolved.append((expand(target, env), shown))
        except Unresolved: problems.append(f'unresolved write target {target!r} in: {shown}')
    return env, resolved, problems


def app_dir_write_violations(source):
    roots = app_writable_roots(source)
    _, resolved, problems = resolved_targets(source)
    for path, shown in resolved:
        problems += [f'root write to {path} under app-writable {root}: {shown}' for root in roots if under(path, root)]
    return problems


def placement_violations(source):
    env, resolved, problems = resolved_targets(source)
    for name in ('LOG_FILE', 'STATUS_FILE'):
        if not under(env.get(name, ''), WEEKLY_DIR): problems.append(f'{name}={env.get(name)} is outside {WEEKLY_DIR}')
    for path, shown in resolved:
        if path != '/dev/null' and not under(path, WEEKLY_DIR):
            problems.append(f'write target {path} is outside {WEEKLY_DIR}: {shown}')
    helper = heredoc(HELPER_HEADER, source)
    outer = body('write_weekly_maintenance', source).split(HELPER_HEADER)[0]
    if ROOT_DIR_LINE not in outer: problems.append('installer does not create the maintenance dir root 0700')
    first_write = min(helper.find('touch "${LOG_FILE}"'), helper.find('\nlog "'))
    if ROOT_DIR_LINE not in helper[:first_write]: problems.append('helper does not create its dir root 0700 before logging')
    for line in source.splitlines():
        if WEEKLY_DIR in line and re.search(r'\b(chmod|chown|install|mkdir)\b', line) and line.strip() != ROOT_DIR_LINE:
            problems.append(f'unexpected mode or owner change on {WEEKLY_DIR}: {line.strip()}')
    for line in re.findall(r'^ReadWritePaths=(.*)$', source, re.M):
        for path in line.split():
            if under(WEEKLY_DIR, path.lstrip('-+')): problems.append(f'a unit can write {WEEKLY_DIR} via {path}')
    return problems


# --- behavioural run in a fake root ----------------------------------------

STUBS = {'systemctl': 0, 'logrotate': 0, 'apt-get': 0, 'dpkg': 0, 'curl': 0, 'nginx': 0, 'journalctl': 0,
         'sqlite3': 0, 'findmnt': 1, 'lsblk': 1, 'fuser': 1, 'pgrep': 1}
SENTINEL = b'root:privileged-sentinel\n'
PLANTED = ['master.log.tmp', 'weekly-maintenance.log', 'weekly-maintenance.log.tmp', 'weekly-maintenance.status.tmp']


def snapshot(directory):
    return {p.name: ('link', os.readlink(p)) if p.is_symlink() else ('file', p.read_bytes()) for p in directory.iterdir()}


def run_helper(source, tmp_path):
    fake, bin_dir, sentinel = tmp_path / 'root', tmp_path / 'bin', tmp_path / 'sentinel'
    app_logs = fake / APP_LOG_DIR.lstrip('/')
    app_logs.mkdir(parents=True)
    (fake / 'etc').mkdir()
    (fake / 'etc/logrotate.conf').write_text('# fixture\n')
    bin_dir.mkdir()
    sentinel.write_bytes(SENTINEL)
    (app_logs / 'master.log').write_text(''.join(f'app line {n}\n' for n in range(50)))
    for name in PLANTED:
        (app_logs / name).symlink_to(sentinel)
    stub_log = tmp_path / 'stub-calls.log'
    for name, rc in STUBS.items():
        (bin_dir / name).write_text(f'#!/bin/sh\nprintf \'%s\\n\' "{name} $*" >> "$STUB_LOG"\nexit {rc}\n')
    (bin_dir / 'install').write_text(
        '#!' + BASH + '\nargs=()\nwhile (($#)); do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done\n'
        'printf \'%s\\n\' "install $*" >> "$STUB_LOG"\nexec ' + REAL_INSTALL + ' "${args[@]}"\n')
    for stub in bin_dir.iterdir(): stub.chmod(0o755)
    swaps = tmp_path / 'swaps'
    swaps.write_text('Filename Type Size Used Priority\n')
    helper = re.sub(r'(?<![\w}/.])/(?=(?:var|root|etc|run|usr/local/bin)/)', str(fake) + '/', heredoc(HELPER_HEADER, source))
    script = tmp_path / 'wins-weekly-maintenance'
    script.write_text(helper)
    before_sentinel, before_logs = (sentinel.read_bytes(), sentinel.stat().st_mtime_ns), snapshot(app_logs)
    result = subprocess.run([BASH, str(script)], text=True, capture_output=True, timeout=120,
                            env={'PATH': f'{bin_dir}:{os.environ["PATH"]}', 'HOME': str(tmp_path), 'LANG': 'C',
                                 'STUB_LOG': str(stub_log), 'WINS_MAINTENANCE_SWAPS_FILE': str(swaps)})
    problems = []
    if result.returncode: problems.append(f'helper exited {result.returncode}: {result.stderr[-2000:]}')
    if (sentinel.read_bytes(), sentinel.stat().st_mtime_ns) != before_sentinel:
        problems.append(f'sentinel changed through a planted symlink: {sentinel.read_bytes()[:200]!r}')
    if snapshot(app_logs) != before_logs:
        problems.append(f'{APP_LOG_DIR} contents changed: {sorted(snapshot(app_logs))}')
    weekly = fake / WEEKLY_DIR.lstrip('/')
    if not weekly.is_dir() or stat.S_IMODE(weekly.stat().st_mode) != 0o700:
        problems.append(f'{WEEKLY_DIR} missing or not 0700')
    status = weekly / 'weekly-maintenance.status'
    if not status.is_file() or not re.search(r'^outcome=(ok|completed-with-warnings)$', status.read_text(), re.M):
        problems.append('status file was not written in the maintenance dir')
    calls = stub_log.read_text() if stub_log.exists() else ''
    if 'systemctl start wins-hub-logrotate.service' not in calls:
        problems.append('application-log rotation was not delegated to wins-hub-logrotate.service')
    if f'logrotate {fake}/etc/logrotate.conf' not in calls:
        problems.append('log-pruning step did not run')
    return problems


# --- in-memory mutants ------------------------------------------------------

OLD_PRUNE = '''MAINT_LOG_DIR="${WINS_MAINTENANCE_LOG_DIR:-/var/log/winsvpn}"
prune_winsvpn_logs() {
  local log_path
  if command -v logrotate >/dev/null 2>&1 && [[ -f /etc/logrotate.conf ]]; then
    run_step "run logrotate" logrotate /etc/logrotate.conf
  fi
  while IFS= read -r log_path; do
    [[ -f "${log_path}" && ! -L "${log_path}" ]] || continue
    [[ "${log_path}" == "${LOG_FILE}" ]] && continue
    if tail -n 5000 "${log_path}" > "${log_path}.tmp" 2>/dev/null; then
      chmod 600 "${log_path}.tmp" 2>/dev/null || true
      mv -f "${log_path}.tmp" "${log_path}"
    else
      rm -f -- "${log_path}.tmp"
    fi
  done < <(find "${MAINT_LOG_DIR}" -maxdepth 1 -type f -name '*.log' 2>/dev/null)
  log "INFO capped ${MAINT_LOG_DIR} logs at the newest 5000 lines each"
}
'''


def replace_once(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def mutant_truncation_loop(source):
    return replace_once(source, body('prune_winsvpn_logs', source), OLD_PRUNE)


def mutant_status_back(source):
    return replace_once(source, f'STATUS_FILE="{WEEKLY_DIR}/', f'STATUS_FILE="{APP_LOG_DIR}/')


def mutant_log_back(source):
    return replace_once(source, f'LOG_FILE="{WEEKLY_DIR}/', f'LOG_FILE="{APP_LOG_DIR}/')


def mutant_loose_dir_mode(source):
    return source.replace(ROOT_DIR_LINE, ROOT_DIR_LINE.replace('0700', '0755'))


def pre_repair(source):
    reverted = mutant_log_back(mutant_status_back(mutant_truncation_loop(source)))
    return replace_once(reverted, '\n' + ROOT_DIR_LINE + '\n', '\n')


MUTANTS = [mutant_truncation_loop, mutant_status_back, mutant_log_back, pre_repair]


# --- tests ------------------------------------------------------------------

def test_scan_sees_the_helpers_real_writes():
    env, resolved, problems = resolved_targets(SOURCE)
    assert problems == []
    paths = {path for path, _ in resolved}
    log_file, status_file = env['LOG_FILE'], env['STATUS_FILE']
    assert {log_file, log_file + '.tmp', status_file, status_file + '.tmp', WEEKLY_DIR} <= paths, paths
    assert APP_LOG_DIR in app_writable_roots(SOURCE)


def test_helper_never_writes_under_app_writable_dirs():
    assert app_dir_write_violations(SOURCE) == []


def test_helper_files_live_in_root_only_maintenance_dir():
    assert placement_violations(SOURCE) == []


def test_old_truncation_loop_and_own_app_dir_files_are_gone():
    helper = heredoc(HELPER_HEADER, SOURCE)
    assert '5000' not in helper and 'find "${MAINT_LOG_DIR}"' not in helper
    assert APP_LOG_DIR + '/' not in helper
    assert 'run_step "rotate hub application logs" systemctl start wins-hub-logrotate.service' in body('prune_winsvpn_logs', SOURCE)


def test_planted_symlinks_cannot_redirect_root_writes(tmp_path):
    assert run_helper(SOURCE, tmp_path) == []


@pytest.mark.parametrize('mutant', MUTANTS, ids=lambda m: m.__name__)
def test_scan_and_run_catch_the_regression(mutant, tmp_path):
    source = mutant(SOURCE)
    assert app_dir_write_violations(source)
    assert placement_violations(source)
    assert any('sentinel changed' in p for p in run_helper(source, tmp_path))


def test_placement_catches_a_loosened_directory_mode():
    assert any('0700' in p or 'mode or owner' in p for p in placement_violations(mutant_loose_dir_mode(SOURCE)))
