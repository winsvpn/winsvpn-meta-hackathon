import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

String _functionBody(String source, String signature, String nextSignature) {
  final start = source.indexOf(signature);
  final end = source.indexOf(nextSignature, start + signature.length);
  expect(start, greaterThanOrEqualTo(0), reason: 'missing $signature');
  expect(end, greaterThan(start), reason: 'missing $nextSignature');
  return source.substring(start, end);
}

void main() {
  final sourceRoot = Platform.environment['WINS_SOURCE_ROOT'] ?? '.';
  final supervisor = File('$sourceRoot/windows/runner/winn3_supervisor.cpp')
      .readAsStringSync();
  final backend = File('$sourceRoot/windows/runner/windows_tunnel_backend.cpp')
      .readAsStringSync();

  test('APP-03 uses one canonical protected owner and DACL contract', () {
    const directorySddl = r'O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)';
    const fileSddl = r'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)';
    expect(supervisor, contains(directorySddl));
    expect(supervisor, contains(fileSddl));
    expect(backend, contains(directorySddl));
    expect(backend, contains(fileSddl));

    final verifier = _functionBody(
      supervisor,
      'bool EnsureWinn3ProtectedDirectory(',
      'std::wstring Winn3ProfilePath()',
    );
    expect(verifier, contains('EqualSid(existing_owner, expected_owner)'));
    expect(verifier, contains('(control & SE_DACL_PROTECTED) != 0'));
    expect(
        verifier, contains('AclBytesInUse == expected_acl_info.AclBytesInUse'));
    expect(verifier, contains('std::memcmp(existing_dacl, expected_dacl'));
    expect(verifier, isNot(contains('GetAce(')));
    expect(verifier, isNot(contains('ACCESS_ALLOWED_ACE_TYPE')));
    expect(verifier, isNot(contains('WRITE_DAC')));
  });

  test('APP-03 key files are created with the explicit protected descriptor',
      () {
    final writer = _functionBody(
      supervisor,
      'bool WriteProfile(',
      'bool EnsureWinn3ProtectedDirectory(',
    );
    expect(writer, contains('kWinn3FileSddl'));
    expect(writer, contains('CREATE_NEW'));
    expect(writer, contains('FILE_FLAG_OPEN_REPARSE_POINT'));

    final pathBuilder = _functionBody(
      supervisor,
      'std::wstring Winn3ProfilePath()',
      'std::string Winn3KeyDirectoryUtf8()',
    );
    expect(pathBuilder, isNot(contains('CreateDirectoryW')),
        reason:
            'must not pre-create the protected directory with a default ACL');
  });

  test('APP-13 rollback and stop remove every served working copy', () {
    final writer = _functionBody(
      supervisor,
      'bool WriteServedWinn3KeyFiles(',
      '// --- the pre-flight sizing query',
    );
    expect(writer, contains('working_paths->push_back(path)'));

    final teardown = _functionBody(
      supervisor,
      'void TeardownLocked(',
      '// THE SELF-STARTING PROMOTION PROBE.',
    );
    expect(teardown, contains('state->session_working_paths'));
    expect(teardown, contains('DeleteFileW(path.c_str())'));
    expect(teardown, contains('MOVEFILE_DELAY_UNTIL_REBOOT'));
    expect(
      teardown.indexOf('WaitForMultipleObjects'),
      lessThan(teardown.indexOf('for (const std::wstring& path')),
      reason: 'children and readers must release key paths before deletion',
    );

    final start = _functionBody(
      supervisor,
      'bool StartWindowsWinn3Tunnel(',
      'void StopWindowsWinn3Tunnel()',
    );
    expect(start, contains('&state->session_working_paths'));
    expect(start, contains('TeardownLocked(state.get())'));
  });
}
