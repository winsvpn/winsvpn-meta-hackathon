#ifndef RUNNER_LINUX_SECURE_STORE_ASYNC_H_
#define RUNNER_LINUX_SECURE_STORE_ASYNC_H_

#include <glib.h>

#include <string>

enum class LinuxSecureTextAsyncOperation { kRead, kWrite, kDelete };

struct LinuxSecureTextAsyncResult {
  bool succeeded = false;
  bool found = false;
  std::string value;
  std::string error;
};

using LinuxSecureTextAsyncCompletion = void (*)(
    LinuxSecureTextAsyncOperation operation,
    const LinuxSecureTextAsyncResult& result,
    gpointer user_data);

// Runs the potentially blocking Secret Service request on a GLib worker and
// invokes completion on the thread-default main context captured by this call.
// user_data_destroy runs after completion, or when the task is destroyed.
void RunLinuxSecureTextAsync(LinuxSecureTextAsyncOperation operation,
                             std::string name,
                             std::string value,
                             LinuxSecureTextAsyncCompletion completion,
                             gpointer user_data,
                             GDestroyNotify user_data_destroy);

// Primes the secure store behind the async layer. The runner calls this from
// the Linux entrypoint (main.cc) before the engine runs so that the first
// secret-service interaction -- a migration read or a later persist -- is
// issued on the GLib worker thread through linux_secure_store_async.cc rather
// than ever blocking the UI thread. The read result is discarded; its only job
// is to establish the async path with the thread-default main context captured
// by RunLinuxSecureTextAsync.
void InitializeLinuxSecureStoreAsync(void);

#endif  // RUNNER_LINUX_SECURE_STORE_ASYNC_H_
