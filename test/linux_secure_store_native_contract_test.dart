import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Linux sensitive state uses a fail-closed libsecret store', () {
    final store = File('linux/runner/linux_secure_store.cc').readAsStringSync();
    final asyncStore =
        File('linux/runner/linux_secure_store_async.cc').readAsStringSync();
    final backend =
        File('linux/runner/linux_tunnel_backend.cc').readAsStringSync();
    final project = File('linux/CMakeLists.txt').readAsStringSync();
    final runner = File('linux/runner/CMakeLists.txt').readAsStringSync();
    final installer = File('linux/packaging/install.sh').readAsStringSync();

    for (final name in <String>[
      'client_keypair.json',
      'calc_session.json',
      'calc_state.json',
      'install_id.txt',
      'node_cache.json',
      'pending_logout.json',
      'user_pin.txt',
      'vpn_config.txt',
      'vpn_settings.txt',
      'wins_vpn_restart_config.conf',
      'winn3_keypair.json',
    ]) {
      expect(store, contains('"$name"'));
    }
    expect(store, contains('secret_password_store_sync'));
    expect(store, contains('secret_password_lookup_sync'));
    expect(store, contains('secret_password_clear_sync'));
    expect(store, contains('StoreSecretVerified'));
    expect(store, contains('WipeAndDeleteLegacyFile'));
    expect(store, contains('O_NOFOLLOW'));
    expect(store, contains('AT_SYMLINK_NOFOLLOW'));
    expect(store, contains('st_uid != geteuid()'));
    expect(store, contains('(directory_metadata.st_mode & 0077) != 0'));
    expect(store, contains('(legacy->metadata.st_mode & 0077) != 0'));
    expect(store, contains('legacy->metadata.st_nlink != 1'));
    expect(store, contains('g_utf8_validate'));
    expect(store, contains('fsync(legacy->file_fd)'));
    expect(store, contains('ftruncate(legacy->file_fd, 0)'));
    expect(store, contains('unlinkat(legacy->directory_fd'));
    final verified = store.indexOf('StoreSecretVerified(name, *plaintext');
    final plaintextDelete =
        store.indexOf('WipeAndDeleteLegacyFile(name, &legacy', verified);
    expect(verified, greaterThanOrEqualTo(0));
    expect(plaintextDelete, greaterThan(verified));
    expect(
      store.substring(
          plaintextDelete, store.indexOf('*found = true', verified)),
      isNot(contains('ClearSecret(')),
      reason: 'A partial plaintext wipe must not destroy the verified copy.',
    );

    for (final method in <String>[
      'readSecureText',
      'writeSecureText',
      'deleteSecureText',
    ]) {
      expect(backend, contains('method == "$method"'));
    }
    expect(backend, contains('LINUX_SECURE_STORE_FAILED'));
    expect(backend, contains('fl_value_new_null()'));
    expect(backend, contains('RunLinuxSecureTextAsync('));
    expect(backend, contains('RetainSecureMethodCall(method_call)'));
    expect(backend, contains('g_object_ref(method_call)'));
    expect(backend, contains('g_object_unref(context->method_call)'));
    expect(backend, isNot(contains('ReadLinuxSecureText(name')));
    expect(backend, isNot(contains('WriteLinuxSecureText(name')));
    expect(backend, isNot(contains('DeleteLinuxSecureText(name')));
    expect(asyncStore, contains('g_task_run_in_thread'));
    expect(asyncStore, contains('g_task_new('));
    expect(asyncStore, contains('g_timeout_source_new('));
    expect(asyncStore, contains('g_main_context_ref_thread_default()'));
    expect(asyncStore, contains('g_source_attach('));
    expect(asyncStore, contains('g_cancellable_cancel'));
    expect(asyncStore, contains('std::lock_guard<std::mutex>'));
    expect(asyncStore,
        contains('kSecureStoreTimeoutMilliseconds = 3000'));
    expect(asyncStore, contains('Linux secret service timed out.'));
    expect(project,
        contains('pkg_check_modules(LIBSECRET REQUIRED IMPORTED_TARGET'));
    expect(runner, contains('"linux_secure_store.cc"'));
    expect(runner, contains('"linux_secure_store_async.cc"'));
    expect(
        runner,
        contains(
            'target_link_libraries(\${BINARY_NAME} PRIVATE PkgConfig::LIBSECRET)'));
    final aptBlock = installer.substring(
      installer.indexOf('if command -v apt-get'),
      installer.indexOf('elif command -v dnf'),
    );
    final dnfBlock = installer.substring(
      installer.indexOf('elif command -v dnf'),
      installer.indexOf('elif command -v pacman'),
    );
    final pacmanStart = installer.indexOf('elif command -v pacman');
    final pacmanBlock = installer.substring(
      pacmanStart,
      installer.indexOf('\nelse', pacmanStart),
    );
    expect(aptBlock, contains('libsecret-1-0'));
    expect(dnfBlock, contains(RegExp(r'\blibsecret\b')));
    expect(pacmanBlock, contains(RegExp(r'\blibsecret\b')));
    expect(
      RegExp(r'gnome-keyring').allMatches(installer).length,
      4,
      reason: 'One mention per package manager (apt/dnf/pacman) plus the '
          'M-2 comment explaining gnome-keyring/libsecret are the app\'s '
          'own Secret Service dependency, not installer verification.',
    );
    expect(
      File('README_FINAL_DEPLOYMENT.md').readAsStringSync(),
      contains('standard per-user Secret Service'),
    );
  });
}
