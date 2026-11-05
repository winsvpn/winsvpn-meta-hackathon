"""Offline adverse-transition tests. All firewall commands are shell mocks."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'linux/runner/linux_tunnel_backend.cc'


def function(name):
    text = SOURCE.read_text()
    start = text.index(name + '() {\n')
    return text[start:text.index('\n}\n', start) + 3]


MOCKS = r'''
winsvpn_chain_is_ours() { [ "$owned" = 1 ]; }
iptables() { mock_iptables "$@"; }
ip6tables() { mock_iptables "$@"; }
mock_iptables() {
  [ "$1" = -w ] && shift 2
  printf 'CALL %s\n' "$*" >&2
  case "$1" in
    -nL) [ "$fail_list" = 1 ] && return 4; [ "$present" = 1 ] ;;
    -S)
      [ "$fail_table" = 1 ] && return 4
      if [ "${2:-}" = OUTPUT ]; then
        [ "$attached" = 1 ] && printf '%s\n' '-A OUTPUT -j WINSVPN_KS3'
      elif [ "$present" = 1 ]; then
        printf '%s\n' '-N WINSVPN_KS3'
      fi
      return 0 ;;
    -N) [ "$fail_create" = 1 ] && return 4; present=1 ;;
    -C) [ "$attached" = 1 ] ;;
    -D) [ "$fail_detach" = 1 ] && return 4; attached=0 ;;
    -F) flushed=$((flushed + 1)) ;;
    -X) present=0 ;;
    -I) attached=1 ;;
    -A) return 0 ;;
    *) return 99 ;;
  esac
}
'''


class Winn3KillSwitchOfflineTests(unittest.TestCase):
    def check_case(self, setup, action, rc, assertion):
        script = ('present=0 attached=0 owned=1 fail_list=0 fail_table=0 '
                  'fail_create=0 fail_detach=0 flushed=0\n' + MOCKS +
                  function('parse_winn_endpoint') +
                  function('append_ipv6_link_control') +
                  function('winn3_ks_chain_state') +
                  function('cleanup_winn3_kill_switch') +
                  function('build_winn3_ks_chain') +
                  function('configure_winn3_kill_switch') +
                  '\nWINN_ENDPOINT=192.0.2.10:51820\n' + setup + '\n' +
                  action + '\nresult=$?\n' +
                  f'[ "$result" = {rc} ] && {assertion}\n')
        result = subprocess.run(['/bin/sh', '-c', script], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stderr

    def test_busy_presence_probe_preserves_existing_block(self):
        log = self.check_case('present=1 attached=1 fail_list=1',
                              'configure_winn3_kill_switch', 75,
                              '[ "$flushed" = 0 ] && [ "$attached" = 1 ]')
        self.assertNotIn('CALL -N ', log)

    def test_unreadable_table_refuses_without_mutation(self):
        log = self.check_case('present=1 attached=1 fail_list=1 fail_table=1',
                              'configure_winn3_kill_switch', 1,
                              '[ "$flushed" = 0 ] && [ "$attached" = 1 ]')
        self.assertNotIn('CALL -N ', log)

    def test_failed_creation_never_flushes(self):
        self.check_case('fail_create=1', 'configure_winn3_kill_switch', 1,
                        '[ "$flushed" = 0 ]')

    def test_failed_detach_preserves_attached_reject(self):
        self.check_case('present=1 attached=1 fail_detach=1',
                        'cleanup_winn3_kill_switch', 1,
                        '[ "$flushed" = 0 ] && [ "$attached" = 1 ]')

    def test_unowned_chain_is_untouched(self):
        self.check_case('present=1 attached=1 owned=0',
                        'cleanup_winn3_kill_switch', 66,
                        '[ "$flushed" = 0 ] && [ "$attached" = 1 ]')

    def test_output_listing_proves_detachment_before_flush(self):
        self.check_case('present=1 attached=1', 'cleanup_winn3_kill_switch', 0,
                        '[ "$flushed" = 1 ] && [ "$present" = 0 ]')

    def test_failed_output_listing_does_not_flush(self):
        self.check_case('present=1 attached=1 fail_table=1',
                        'cleanup_winn3_kill_switch', 1,
                        '[ "$flushed" = 0 ]')
