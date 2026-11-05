#include "linux_secure_store.h"
#include "linux_secure_store_async.h"

#include <fcntl.h>
#include <gio/gio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

std::string TemporaryDataDirectory() {
  std::array<char, 64> root_template = {};
  const std::string prefix = "/tmp/winsvpn-secure-store-test.XXXXXX";
  std::copy(prefix.begin(), prefix.end(), root_template.begin());
  char* root = mkdtemp(root_template.data());
  assert(root != nullptr);
  const std::string data = std::string(root) + "/data";
  const std::string app = data + "/wins_vpn";
  assert(mkdir(data.c_str(), 0700) == 0);
  assert(mkdir(app.c_str(), 0700) == 0);
  assert(setenv("XDG_DATA_HOME", data.c_str(), 1) == 0);
  return data;
}

void RemoveTemporaryDataDirectory(const std::string& data) {
  assert(rmdir((data + "/wins_vpn").c_str()) == 0);
  assert(rmdir(data.c_str()) == 0);
  const size_t slash = data.find_last_of('/');
  assert(slash != std::string::npos);
  assert(rmdir(data.substr(0, slash).c_str()) == 0);
}

void TestUnavailableServiceFailsClosed() {
  const std::string data = TemporaryDataDirectory();
  const std::string app = data + "/wins_vpn";
  const std::string legacy = app + "/pending_logout.json";
  {
    std::ofstream output(legacy, std::ios::binary | std::ios::trunc);
    output << "{\"pending\":true}";
    assert(output.good());
  }
  assert(chmod(legacy.c_str(), 0600) == 0);
  assert(setenv("DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/winsvpn-secret-service-does-not-exist", 1) ==
         0);
  std::string plaintext;
  std::string error;
  bool found = false;
  assert(!ReadLinuxSecureText("pending_logout.json", &plaintext, &found,
                              &error));
  assert(!found);
  assert(plaintext.empty());
  assert(!error.empty());
  struct stat metadata = {};
  assert(lstat(legacy.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
  std::ifstream preserved(legacy, std::ios::binary);
  std::string preserved_value((std::istreambuf_iterator<char>(preserved)),
                              std::istreambuf_iterator<char>());
  assert(preserved_value == "{\"pending\":true}");
  assert(unlink(legacy.c_str()) == 0);
  RemoveTemporaryDataDirectory(data);
}

void TestOverwriteValue() {
  const std::string data = TemporaryDataDirectory();
  (void)data;
  const std::string first = "first-value";
  const std::string second = "second-value";
  std::string plaintext;
  std::string error;
  bool found = false;

  assert(WriteLinuxSecureText("user_pin.txt", first, &error));
  error.clear();
  found = false;
  assert(WriteLinuxSecureText("user_pin.txt", second, &error));
  assert(ReadLinuxSecureText("user_pin.txt", &plaintext, &found, &error));
  assert(found && plaintext == second);
  found = false;
  plaintext.clear();
  assert(WriteLinuxSecureText("user_pin.txt", first, &error));
  assert(ReadLinuxSecureText("user_pin.txt", &plaintext, &found, &error));
  assert(found && plaintext == first);
  assert(DeleteLinuxSecureText("user_pin.txt", &error));
  RemoveTemporaryDataDirectory(data);
}

void TestDeniedInteractions() {
  const std::string data = TemporaryDataDirectory();
  const std::string app = data + "/wins_vpn";
  std::string plaintext;
  std::string error;
  bool found = false;

  // Names outside the allow-list are refused on every operation, before any
  // secret-service or filesystem interaction.
  for (const char* bad : {"../user_pin.txt", "install_id.txt", "vpn_config.txt.bak"}) {
    error.clear();
    assert(!WriteLinuxSecureText(bad, "value", &error));
    assert(!error.empty());
    error.clear();
    assert(!ReadLinuxSecureText(bad, &plaintext, &found, &error));
    assert(!error.empty());
    error.clear();
    assert(!DeleteLinuxSecureText(bad, &error));
    assert(!error.empty());
  }

  // An absent secret service must fail closed on write and delete as well as
  // read: nothing may be left behind and nothing may be reported as stored.
  const std::string legacy = app + "/user_pin.txt";
  {
    std::ofstream output(legacy, std::ios::binary | std::ios::trunc);
    output << "{\"pending\":true}";
    assert(output.good());
  }
  assert(chmod(legacy.c_str(), 0600) == 0);
  assert(setenv("DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/winsvpn-secret-service-does-not-exist", 1) ==
         0);
  error.clear();
  assert(!WriteLinuxSecureText("user_pin.txt", "value", &error));
  assert(!error.empty());
  error.clear();
  assert(!DeleteLinuxSecureText("user_pin.txt", &error));
  assert(!error.empty());
  struct stat metadata = {};
  assert(lstat(legacy.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
  assert(unsetenv("DBUS_SESSION_BUS_ADDRESS") == 0);
  assert(unlink(legacy.c_str()) == 0);
  RemoveTemporaryDataDirectory(data);
}

void TestPositiveRoundTripAndMigration() {
  const std::string data = TemporaryDataDirectory();
  const std::string app = data + "/wins_vpn";
  std::string plaintext;
  std::string error;
  bool found = false;

  assert(WriteLinuxSecureText("user_pin.txt", "8642", &error));
  assert(ReadLinuxSecureText("user_pin.txt", &plaintext, &found, &error));
  assert(found && plaintext == "8642");
  assert(DeleteLinuxSecureText("user_pin.txt", &error));
  plaintext.clear();
  found = true;
  assert(ReadLinuxSecureText("user_pin.txt", &plaintext, &found, &error));
  assert(!found && plaintext.empty());
  // libsecret reports "nothing matched" as FALSE without an error; deleting
  // an absent name must still succeed.
  assert(DeleteLinuxSecureText("user_pin.txt", &error));

  const std::string legacy = app + "/vpn_settings.txt";
  const std::string legacy_value = "{\"launcher_unlocked\":true}";
  {
    std::ofstream output(legacy, std::ios::binary | std::ios::trunc);
    output << legacy_value;
    assert(output.good());
  }
  assert(chmod(legacy.c_str(), 0600) == 0);
  plaintext.clear();
  found = false;
  assert(ReadLinuxSecureText("vpn_settings.txt", &plaintext, &found, &error));
  assert(found && plaintext == legacy_value);
  assert(access(legacy.c_str(), F_OK) != 0 && errno == ENOENT);
  plaintext.clear();
  found = false;
  assert(ReadLinuxSecureText("vpn_settings.txt", &plaintext, &found, &error));
  assert(found && plaintext == legacy_value);
  assert(DeleteLinuxSecureText("vpn_settings.txt", &error));
  RemoveTemporaryDataDirectory(data);
}

struct AsyncUnavailableProbe {
  GMainLoop* loop = nullptr;
  GThread* main_thread = nullptr;
  guint heartbeats = 0;
  bool completed = false;
  bool watchdog_fired = false;
};

gboolean CountMainLoopHeartbeat(gpointer data) {
  auto* probe = static_cast<AsyncUnavailableProbe*>(data);
  ++probe->heartbeats;
  return probe->completed ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
}

gboolean StopAsyncProbeOnWatchdog(gpointer data) {
  auto* probe = static_cast<AsyncUnavailableProbe*>(data);
  probe->watchdog_fired = true;
  g_main_loop_quit(probe->loop);
  return G_SOURCE_REMOVE;
}

void CompleteAsyncUnavailableProbe(LinuxSecureTextAsyncOperation operation,
                                   const LinuxSecureTextAsyncResult& result,
                                   gpointer data) {
  auto* probe = static_cast<AsyncUnavailableProbe*>(data);
  assert(g_thread_self() == probe->main_thread);
  assert(operation == LinuxSecureTextAsyncOperation::kRead);
  assert(!result.succeeded);
  assert(!result.found);
  assert(result.value.empty());
  assert(result.error == "Linux secret service timed out.");
  probe->completed = true;
  g_main_loop_quit(probe->loop);
}

void TestAsyncUnavailableServiceDoesNotBlockMainLoop() {
  const std::string data = TemporaryDataDirectory();
  const std::string app = data + "/wins_vpn";
  const std::string legacy = app + "/pending_logout.json";
  {
    std::ofstream output(legacy, std::ios::binary | std::ios::trunc);
    output << "{\"pending\":true}";
    assert(output.good());
  }
  assert(chmod(legacy.c_str(), 0600) == 0);
  assert(setenv("DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/winsvpn-secret-service-does-not-exist", 1) ==
         0);
  assert(setenv("WINSVPN_SECURE_STORE_TEST_TIMEOUT_MS", "150", 1) == 0);
  assert(setenv("WINSVPN_SECURE_STORE_TEST_DELAY_MS", "600", 1) == 0);

  AsyncUnavailableProbe probe;
  probe.loop = g_main_loop_new(nullptr, FALSE);
  probe.main_thread = g_thread_self();
  const auto dispatch_started = std::chrono::steady_clock::now();
  RunLinuxSecureTextAsync(
      LinuxSecureTextAsyncOperation::kRead, "pending_logout.json", "",
      CompleteAsyncUnavailableProbe, &probe, nullptr);
  const auto dispatch_elapsed = std::chrono::duration_cast<
      std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                 dispatch_started);
  assert(dispatch_elapsed.count() < 100);
  const guint heartbeat_source =
      g_timeout_add(10, CountMainLoopHeartbeat, &probe);
  const guint watchdog_source =
      g_timeout_add(2000, StopAsyncProbeOnWatchdog, &probe);
  g_main_loop_run(probe.loop);
  if (g_main_context_find_source_by_id(nullptr, heartbeat_source) != nullptr) {
    g_source_remove(heartbeat_source);
  }
  if (g_main_context_find_source_by_id(nullptr, watchdog_source) != nullptr) {
    g_source_remove(watchdog_source);
  }
  g_main_loop_unref(probe.loop);
  assert(probe.completed);
  assert(!probe.watchdog_fired);
  assert(probe.heartbeats >= 5);

  struct stat metadata = {};
  assert(lstat(legacy.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
  std::ifstream preserved(legacy, std::ios::binary);
  std::string preserved_value((std::istreambuf_iterator<char>(preserved)),
                              std::istreambuf_iterator<char>());
  assert(preserved_value == "{\"pending\":true}");
  assert(unlink(legacy.c_str()) == 0);
  unsetenv("WINSVPN_SECURE_STORE_TEST_TIMEOUT_MS");
  unsetenv("WINSVPN_SECURE_STORE_TEST_DELAY_MS");
  RemoveTemporaryDataDirectory(data);
}

void TestHardenLegacyStateDirectory() {
  const std::string data = TemporaryDataDirectory();
  const std::string app = data + "/wins_vpn";

  // Permissive umask: a correct 0600/0700 result has to come from the
  // hardening, not from the process umask.
  const mode_t original_umask = umask(0);

  const char* kHardenable[] = {
      "client_keypair.json", "calc_session.json", "calc_state.json",
      "install_id.txt", "pending_logout.json", "user_pin.txt",
      "vpn_config.txt", "vpn_settings.txt", "wins_vpn_restart_config.conf",
      "winn3_keypair.json", "direct_udp_transport_memory.json",
      "wins_xray.log",
  };
  std::vector<std::string> created;
  for (const char* file : kHardenable) {
    const std::string path = app + "/" + file;
    {
      std::ofstream output(path, std::ios::binary | std::ios::trunc);
      output << "secret";
      assert(output.good());
    }
    created.push_back(path);
  }

  // A listed name that is really a symlink: the hardening must neither chase
  // it nor replace it.
  const std::string link = app + "/node_cache.json";
  assert(symlink("client_keypair.json", link.c_str()) == 0);

  // A name the hardening does not know: must be left at its current mode.
  const std::string foreign = app + "/random_plugin_cache.bin";
  {
    std::ofstream output(foreign, std::ios::binary | std::ios::trunc);
    output << "cache";
    assert(output.good());
  }
  assert(chmod(foreign.c_str(), 0644) == 0);

  assert(chmod(app.c_str(), 0755) == 0);

  HardenLegacyStateDirectory(app);

  struct stat metadata = {};
  assert(lstat(app.c_str(), &metadata) == 0 && S_ISDIR(metadata.st_mode));
  assert((metadata.st_mode & 0777) == 0700);
  for (const std::string& path : created) {
    assert(lstat(path.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
    assert((metadata.st_mode & 0777) == 0600);
  }
  // The symlinked listed name is still a symlink, and its target was hardened.
  assert(lstat(link.c_str(), &metadata) == 0 && S_ISLNK(metadata.st_mode));
  const std::string target = app + "/client_keypair.json";
  assert(lstat(target.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
  assert((metadata.st_mode & 0777) == 0600);
  std::ifstream read_target(target, std::ios::binary);
  const std::string kept((std::istreambuf_iterator<char>(read_target)),
                         std::istreambuf_iterator<char>());
  assert(kept == "secret");
  // The unknown file was untouched.
  assert(lstat(foreign.c_str(), &metadata) == 0 && S_ISREG(metadata.st_mode));
  assert((metadata.st_mode & 0777) == 0644);

  // Missing and non-directory targets must be safe no-ops.
  HardenLegacyStateDirectory(app + "/does-not-exist");
  HardenLegacyStateDirectory(foreign);

  umask(original_umask);

  for (const std::string& path : created) assert(unlink(path.c_str()) == 0);
  assert(unlink(link.c_str()) == 0);
  assert(unlink(foreign.c_str()) == 0);
  RemoveTemporaryDataDirectory(data);
}

int main(int argc, char** argv) {
  const std::array<const char*, 7> allowed = {
      "client_keypair.json", "install_id.txt",   "pending_logout.json",
      "user_pin.txt",        "vpn_config.txt",   "vpn_settings.txt",
      "wins_vpn_restart_config.conf",
  };
  for (const char* name : allowed) {
    assert(IsAllowedLinuxSecureTextName(name));
  }
  for (const char* name : {"", "../user_pin.txt",
                           "/tmp/user_pin.txt", "USER_PIN.TXT",
                           "vpn_config.txt.bak"}) {
    assert(!IsAllowedLinuxSecureTextName(name));
  }
  if (argc == 2 && std::string(argv[1]) == "--positive") {
    TestPositiveRoundTripAndMigration();
    TestOverwriteValue();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--async-unavailable") {
    TestAsyncUnavailableServiceDoesNotBlockMainLoop();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--hardening") {
    TestHardenLegacyStateDirectory();
    return 0;
  }
  assert(argc == 1);
  TestUnavailableServiceFailsClosed();
  TestHardenLegacyStateDirectory();
  TestDeniedInteractions();
  return 0;
}
