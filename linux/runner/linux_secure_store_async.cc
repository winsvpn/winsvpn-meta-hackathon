#include "linux_secure_store_async.h"

#include "linux_secure_store.h"

#include <gio/gio.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <mutex>
#include <string>
#include <utility>

namespace {

constexpr guint kSecureStoreTimeoutMilliseconds = 3000;

struct SecureTextTask {
  LinuxSecureTextAsyncOperation operation;
  std::string name;
  std::string value;
  LinuxSecureTextAsyncResult result;
  LinuxSecureTextAsyncCompletion completion = nullptr;
  gpointer user_data = nullptr;
  GDestroyNotify user_data_destroy = nullptr;
  GSource* timeout_source = nullptr;
};

std::mutex g_secure_store_mutex;

void WipeString(std::string* value) {
  if (value == nullptr || value->empty()) return;
  volatile char* bytes = &(*value)[0];
  for (size_t index = 0; index < value->size(); ++index) bytes[index] = 0;
  value->clear();
}

void DestroySecureTextTask(gpointer data) {
  auto* task = static_cast<SecureTextTask*>(data);
  if (task == nullptr) return;
  WipeString(&task->value);
  WipeString(&task->result.value);
  if (task->timeout_source != nullptr) {
    g_source_destroy(task->timeout_source);
    g_source_unref(task->timeout_source);
  }
  if (task->user_data_destroy != nullptr) {
    task->user_data_destroy(task->user_data);
  }
  delete task;
}

guint ConfiguredTimeoutMilliseconds() {
#ifdef WINSVPN_SECURE_STORE_TESTING
  const char* configured =
      std::getenv("WINSVPN_SECURE_STORE_TEST_TIMEOUT_MS");
  if (configured != nullptr && *configured != '\0') {
    char* end = nullptr;
    errno = 0;
    const unsigned long parsed = std::strtoul(configured, &end, 10);
    if (errno == 0 && end != configured && *end == '\0' && parsed > 0 &&
        parsed <= kSecureStoreTimeoutMilliseconds) {
      return static_cast<guint>(parsed);
    }
  }
#endif
  return kSecureStoreTimeoutMilliseconds;
}

gboolean CancelSecureTextTask(gpointer data) {
  g_cancellable_cancel(G_CANCELLABLE(data));
  return G_SOURCE_REMOVE;
}

#ifdef WINSVPN_SECURE_STORE_TESTING
void ApplyTestDelay(GCancellable* cancellable) {
  const char* configured = std::getenv("WINSVPN_SECURE_STORE_TEST_DELAY_MS");
  if (configured == nullptr || *configured == '\0') return;
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(configured, &end, 10);
  if (errno != 0 || end == configured || *end != '\0' || parsed > 10000) {
    return;
  }
  guint remaining = static_cast<guint>(parsed);
  while (remaining > 0 && !g_cancellable_is_cancelled(cancellable)) {
    const guint slice = std::min<guint>(remaining, 10);
    g_usleep(static_cast<gulong>(slice) * 1000);
    remaining -= slice;
  }
}
#endif

void SecureTextTaskWorker(GTask* task,
                          gpointer source_object,
                          gpointer task_data,
                          GCancellable* cancellable) {
  (void)source_object;
  auto* request = static_cast<SecureTextTask*>(task_data);
#ifdef WINSVPN_SECURE_STORE_TESTING
  ApplyTestDelay(cancellable);
#endif
  if (g_cancellable_is_cancelled(cancellable)) {
    request->result.error = "Linux secret service timed out.";
    g_task_return_boolean(task, TRUE);
    return;
  }

  // Serializing protects the one-time plaintext migration from overlapping
  // reads, writes, or deletes for the same process.
  std::lock_guard<std::mutex> lock(g_secure_store_mutex);
  switch (request->operation) {
    case LinuxSecureTextAsyncOperation::kRead:
      request->result.succeeded = ReadLinuxSecureText(
          request->name, &request->result.value, &request->result.found,
          &request->result.error, cancellable);
      break;
    case LinuxSecureTextAsyncOperation::kWrite:
      request->result.succeeded = WriteLinuxSecureText(
          request->name, request->value, &request->result.error, cancellable);
      WipeString(&request->value);
      break;
    case LinuxSecureTextAsyncOperation::kDelete:
      request->result.succeeded = DeleteLinuxSecureText(
          request->name, &request->result.error, cancellable);
      break;
  }
  if (!request->result.succeeded &&
      g_cancellable_is_cancelled(cancellable)) {
    request->result.error = "Linux secret service timed out.";
  }
  g_task_return_boolean(task, TRUE);
}

void SecureTextTaskCompleted(GObject* source_object,
                             GAsyncResult* async_result,
                             gpointer user_data) {
  (void)source_object;
  (void)user_data;
  GTask* task = G_TASK(async_result);
  auto* request =
      static_cast<SecureTextTask*>(g_task_get_task_data(task));
  if (request->timeout_source != nullptr) {
    g_source_destroy(request->timeout_source);
  }
  g_autoptr(GError) task_error = nullptr;
  if (!g_task_propagate_boolean(task, &task_error)) {
    request->result.succeeded = false;
    request->result.error = "Linux secure-state worker failed.";
  }
  request->completion(request->operation, request->result,
                      request->user_data);
}

}  // namespace

void RunLinuxSecureTextAsync(LinuxSecureTextAsyncOperation operation,
                             std::string name,
                             std::string value,
                             LinuxSecureTextAsyncCompletion completion,
                             gpointer user_data,
                             GDestroyNotify user_data_destroy) {
  auto* request = new SecureTextTask;
  request->operation = operation;
  request->name = std::move(name);
  request->value = std::move(value);
  request->completion = completion;
  request->user_data = user_data;
  request->user_data_destroy = user_data_destroy;

  g_autoptr(GCancellable) cancellable = g_cancellable_new();
  g_autoptr(GTask) task = g_task_new(
      nullptr, cancellable, SecureTextTaskCompleted, nullptr);
  // Cancellation is converted into the stable, non-sensitive timeout result
  // by the worker instead of becoming a GLib error in the reply callback.
  g_task_set_check_cancellable(task, FALSE);
  g_task_set_task_data(task, request, DestroySecureTextTask);
  request->timeout_source =
      g_timeout_source_new(ConfiguredTimeoutMilliseconds());
  g_source_set_priority(request->timeout_source, G_PRIORITY_DEFAULT);
  g_source_set_callback(request->timeout_source, CancelSecureTextTask,
                        g_object_ref(cancellable), g_object_unref);
  g_autoptr(GMainContext) response_context =
      g_main_context_ref_thread_default();
  g_source_attach(request->timeout_source, response_context);
  g_task_run_in_thread(task, SecureTextTaskWorker);
}

namespace {

void IgnoreSecureTextResult(LinuxSecureTextAsyncOperation operation,
                            const LinuxSecureTextAsyncResult& result,
                            gpointer user_data) {
  (void)operation;
  (void)user_data;
  // The prime is a fire-and-forget read: the store connection and its
  // thread-default main context are wrestled into the async layer by the call
  // itself, not by anything the result says. The result carries no key
  // material the caller asked for (an empty name read fails closed), so it is
  // discarded without ever being exposed.
  (void)result;
}

}  // namespace

void InitializeLinuxSecureStoreAsync() {
  // The runner's first persist must go through linux_secure_store_async.cc.
  // Issuing a background read named for the one-time migration key primes the
  // Secret Service store on the GLib worker, so a later read or write (and any
  // legacy-file migration) never blocks the UI thread and is serialized with
  // all subsequent operations by the secure-store worker mutex.
  RunLinuxSecureTextAsync(LinuxSecureTextAsyncOperation::kRead,
                          "pending_logout.json", "", IgnoreSecureTextResult,
                          nullptr, nullptr);
}
