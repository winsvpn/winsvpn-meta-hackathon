"""Generate a local D5 inventory from the shipped hub installer.

This is a source inventory, not a certification of the deployed host. It
includes every rendered execution directive, generated helper, and installer
entrypoint that can consume app-controlled data. No host state is inspected.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys


def inventory(source):
    helpers = []
    units = []
    # `install_generated_file MODE TARGET <<DELIM` is the installer's atomic
    # form of `cat > TARGET <<DELIM` (FLEET1 Turn 5): same target, same body.
    opening = re.compile(r"^\s*(?:cat >|install_generated_file [0-7]{3,4}) ([^\n]+?) <<-?(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2\n", re.M)
    for match in opening.finditer(source):
        end = source.find('\n' + match[3] + '\n', match.end())
        if end < 0:
            raise ValueError('Unclosed generated artifact')
        body = source[match.end():end]
        target = match[1].strip('"')
        line = source.count('\n', 0, match.start()) + 1
        if '[Service]' in body and ('ExecStart=' in body or 'ExecStop=' in body):
            properties = {}
            for entry in body.splitlines():
                if '=' in entry and not entry.startswith('#'):
                    key, value = entry.split('=', 1)
                    properties.setdefault(key, []).append(value)
            units.append(dict(target=target, line=line,
                              exec={key: value for key, value in properties.items() if key.startswith('Exec')},
                              sandbox={key: value for key, value in properties.items() if key.startswith(('Protect', 'Private', 'ReadOnly', 'ReadWrite', 'Capability', 'NoNew', 'Restrict', 'Bind', 'TemporaryFile'))},
                              data_consumers=[], linked_helpers=[]))
        elif body.startswith(('#!', 'import ', 'from ')) and target.startswith(('/usr/', '${APP_DIR}')):
            imports = []
            calls = []
            file_operations = []
            language = 'shell' if 'bash' in body.splitlines()[0] else 'python'
            if language == 'python':
                try:
                    tree = ast.parse(body)
                except SyntaxError:
                    tree = None
                if tree:
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import): imports.extend(item.name for item in node.names)
                        elif isinstance(node, ast.ImportFrom): imports.append(node.module or '')
                        elif isinstance(node, ast.Call):
                            name = ast.unparse(node.func)
                            if any(word in name for word in ('subprocess.', 'os.system', 'exec', 'eval')): calls.append(name)
                            if any(word in name for word in ('open', 'read', 'write', 'unlink', 'replace', 'mkdir', 'sqlite3.connect')): file_operations.append(name)
            else:
                imports = sorted(set(re.findall(r'^import ([a-zA-Z0-9_., ]+)', body, re.M)))
                calls = sorted(set(re.findall(r'\b(python3|curl|ssh|systemctl|systemd-run|iptables|logrotate|tar|rclone|sqlite3|apt-get|suricata-update)\b', body)))
                file_operations = sorted(set(re.findall(r'\b(source|touch|chmod|chown|install|mkdir|mv|rm|cp|find|readlink|sqlite3\.connect)\b', body)))
            data = []
            for token, label in [('/root/vpn_auth', 'app database, source or state'),
                                 ('DATABASE', 'database path supplied as data'), ('/var/log', 'logs including app-controlled messages'),
                                 ('/var/lib/wins-security-alerts', 'app-controlled security event state'),
                                 ('/root/vpn_auth.env', 'root-owned environment, executable shell input'),
                                 ('/var/lib/wins-canary-results', 'bounded canary results'),
                                 ('127.0.0.1:8000', 'hub API data'), ('localhost:8000', 'hub API data')]:
                if token in body: data.append(label)
            helpers.append(dict(target=target, line=line, language=language,
                                interpreter=body.splitlines()[0] if body.startswith('#!') else 'embedded system Python',
                                imports=sorted(set(imports)), subprocesses=sorted(set(calls)),
                                file_operations=sorted(set(file_operations)), data_consumers=sorted(set(data)),
                                unresolved='Runtime ownership, dependency closure and sandbox behavior require Tier A verification'))
    # H3 ships a pinned generated runtime instead of importing app-writable
    # code. Keep its dependency and data closure in the D5 source inventory.
    staged = Path(__file__).with_name('wins_winn3_canary_runtime.py')
    if 'install_h3_canary_artifacts()' in source:
        body = staged.read_text()
        tree = ast.parse(body)
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        imports += [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        helpers.append(dict(target='/usr/local/bin/wins-winn3-canary-runtime.py',
                            source_artifact=staged.name, source_sha256=hashlib.sha256(body.encode()).hexdigest(),
                            line=1, language='python', interpreter='/usr/bin/python3 -I',
                            imports=sorted(set(imports)), subprocesses=['subprocess.run: pinned winn3-probe'],
                            file_operations=['sqlite3.connect: mode=ro and query_only', 'atomic result publication',
                                             'slug-only request consume', 'per-slug rate-limit state'],
                            data_consumers=['app database and canary bindings as data', 'root-owned environment',
                                            'signed stored descriptor', 'private canary client key', 'slug-only requests'],
                            unresolved='Runtime ownership and mount namespace require Tier A verification'))
    for unit in units:
        commands = '\n'.join(value for values in unit['exec'].values() for value in values)
        linked = [helper for helper in helpers if helper['target'] in commands or (helper['target'] == '/usr/local/bin/wins-winn3-canary-runtime.py' and any(name in commands for name in ('/usr/local/bin/wins-gateway-canary', '/usr/local/bin/wins-winn3-canary-requests')))]
        unit['linked_helpers'] = [helper['target'] for helper in linked]
        unit['data_consumers'] = sorted({item for helper in linked for item in helper['data_consumers']})
        if not linked:
            unit['data_consumers'] = ['external executable or dynamic path; inspect runtime dependency and data closure']
        unit['status'] = 'source profile present' if unit['sandbox'].get('ProtectSystem') == ['strict'] else 'profile incomplete or host-dependent; H1 prerequisite remains unverified'
    return dict(source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                scope='all generated service execution directives and helpers, plus installer and dynamic jobs',
                units=units, helpers=helpers, other_entrypoints=[
                    dict(target='installer:setup_python', inputs=['root-only requirements lock', 'read-only venv'],
                         handling='root ownership and link-target checks; no-write syntax validation'),
                    dict(target='installer:postflight_control', inputs=['app source as data'],
                         handling='system Python -I -S compile without writing bytecode'),
                    dict(target='installer:run_prepublication_gateway_canary', inputs=['hub API and app database'],
                         handling='synchronous sandboxed prepublication unit'),
                    dict(target='maintenance:gateway-canary', inputs=['hub API and app database'],
                         handling='synchronous sandboxed regular canary unit'),
                    dict(target='dynamic:SPA-expiry', inputs=['canonical IPv4 and bounded lease identifier'],
                         handling='fixed iptables deletion argv; systemd timer custody; CAP_NET_ADMIN helper'),
                    dict(target='dynamic:SSH-recovery-expiry', inputs=['installer-owned account and expiry'],
                         handling='root-owned expiry helper; runtime sshd policy still requires verification'),
                    dict(target='host:distribution-jobs', inputs=['logrotate, backup/restore tools, apt, Fail2Ban and Suricata'],
                         handling='distribution logrotate app entry removed; remaining host jobs and plugins must be inspected in Tier A; no host contact in this lane'),
                ])


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    data = inventory((root / 'wins_control_plane_setup_ONETOUCH.sh').read_text())
    (root / 'h0_privileged_jobs.json').write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    print(f"Inventoried {len(data['units'])} rendered execution profiles, {len(data['helpers'])} generated helpers and {len(data['other_entrypoints'])} other entrypoints")
