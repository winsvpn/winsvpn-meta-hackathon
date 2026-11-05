#!/usr/bin/env python3
"""Offline model: a disabled latch must block throughout a chain replacement."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = Path(os.environ.get('WINS_LATCH_INSTALLER',
    str(ROOT / 'server/wins_data_plane_setup_ONETOUCH.sh')))
CHAIN = 'WINVPN-LOCAL-SERVING'
RULES = [
    ['-i', 'lo', '-j', 'RETURN'],
    ['-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '--ctdir', 'REPLY', '-j', 'RETURN'],
    ['-j', 'DROP'],
]
MODEL = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
path = pathlib.Path(os.environ['MODEL_STATE'])
data = json.loads(path.read_text())
args = sys.argv[1:]
chain = 'WINVPN-LOCAL-SERVING'
if args and args[0] in ('-w', '--wait'):
    args = args[2:]
def commit(rules, operation):
    data['rules'] = rules
    # Probe: inbound original-direction WAN TCP/443, allowed by the later
    # ordinary VPN ingress policy. Neither the loopback nor REPLY exception
    # matches it. An empty user chain returns to that later ACCEPT.
    verdict = 'DROP' if ['-j', 'DROP'] in rules else 'ACCEPT'
    data['trace'].append([operation, verdict])
    path.write_text(json.dumps(data))
if pathlib.Path(sys.argv[0]).name == 'iptables-restore':
    body = sys.stdin.read().splitlines()
    assert args == ['--noflush'], args
    assert body[0] == '*filter' and body[-1] == 'COMMIT'
    assert ':' + chain + ' - [0:0]' in body
    rules = [line.split()[2:] for line in body if line.startswith('-A ' + chain + ' ')]
    if os.environ.get('MODEL_RESTORE_FAIL') == '1':
        raise SystemExit(4)
    commit(rules, 'COMMIT')
elif args == ['-n', '-L', chain]:
    pass
elif args == ['-S', 'INPUT']:
    print('-P INPUT DROP\n-A INPUT -j WINVPN-INPUT')
elif args[:3] == ['-I', 'INPUT', '1']:
    pass
elif 'WINVPN-SSH-RECOVERY' in args:
    pass
elif args == ['-S', chain]:
    print('-N ' + chain)
    for rule in data['rules']:
        print('-A ' + chain + ' ' + ' '.join(rule))
elif args == ['-F', chain]:
    commit([], 'flush')
elif args[:2] == ['-A', chain]:
    commit(data['rules'] + [args[2:]], 'append')
else:
    raise AssertionError(args)
'''


def function(source, name):
    start = source.index(name + '() {')
    end = source.index('\n}', start) + 2
    return source[start:end]


class LatchReapplyTests(unittest.TestCase):
    def run_apply(self, fail=False, late=False):
        source = INSTALLER.read_text()
        guard = source.split("<<'WINS_NODE_LOCAL_SERVING_GUARD'\n", 1)[1].split(
            '\nWINS_NODE_LOCAL_SERVING_GUARD', 1)[0]
        body = 'set -euo pipefail\nCHAIN=WINVPN-LOCAL-SERVING\n'
        body += '\n'.join(function(guard, name) for name in (
            'ensure_chain_exists', 'verify_disabled_chain', 'apply_disabled_chain'))
        body += '\npersist_firewall() { return 0; }\nip6_model() { return 0; }\n'
        body += 'IP6TABLES_BIN=ip6_model\n'
        if late:
            body += function(source, 'winn3_late_repair_live')
            body += '\nwinn3_late_command() { "$@" || WINN3_LATE_REPAIR=failed; }\n'
            body += 'winn3_recovery_source() { return 0; }\n'
            body += 'WINN3_LATE_ERRORS=\nwinn3_late_repair_live resume\n'
        else:
            body += 'apply_disabled_chain\n'
        with tempfile.TemporaryDirectory(prefix='latch-atomic-') as tmp:
            directory = Path(tmp)
            state = directory / 'state.json'
            state.write_text(json.dumps({'rules': RULES, 'trace': []}))
            for name in ('iptables', 'iptables-restore'):
                script = directory / name
                script.write_text(MODEL)
                script.chmod(0o700)
            env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ['PATH'],
                MODEL_STATE=str(state),
                IPTABLES_BIN=str(directory / 'iptables'),
                IPTABLES_RESTORE_BIN=str(directory / 'iptables-restore'),
                MODEL_RESTORE_FAIL='1' if fail else '0')
            result = subprocess.run(['bash', '-c', body], env=env,
                capture_output=True, text=True, timeout=10, check=False)
            return result, json.loads(state.read_text())

    def test_disabled_reapply_never_admits_customer_ingress(self):
        result, state = self.run_apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state['rules'], RULES)
        self.assertTrue(state['trace'], 'the model must observe a mutation')
        self.assertTrue(all(verdict == 'DROP' for _, verdict in state['trace']), state['trace'])

    def test_late_repair_never_admits_customer_ingress(self):
        result, state = self.run_apply(late=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state['rules'], RULES)
        self.assertTrue(state['trace'])
        self.assertTrue(all(verdict == 'DROP' for _, verdict in state['trace']), state['trace'])

    def test_failed_late_repair_preserves_disabled_chain(self):
        result, state = self.run_apply(fail=True, late=True)
        self.assertEqual(state['rules'], RULES)
        self.assertEqual(state['trace'], [])

    def test_failed_replacement_preserves_disabled_chain(self):
        result, state = self.run_apply(fail=True)
        self.assertNotEqual(result.returncode, 0, 'restore failure was ignored')
        self.assertEqual(state['rules'], RULES)
        self.assertEqual(state['trace'], [])


if __name__ == '__main__':
    unittest.main()
