#include "linux_secure_store.h"
#include "linux_secure_store_async.h"
#include "my_application.h"

#include <glib-unix.h>
#include <sys/stat.h>

#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <string>

namespace {

gboolean QuitApplicationFromUnixSignal(gpointer user_data) {
  g_application_quit(G_APPLICATION(user_data));
  return G_SOURCE_CONTINUE;
}

void ForwardQuitToTermination(int) {
  const int saved_errno = errno;
  kill(getpid(), SIGTERM);
  errno = saved_errno;
}

void HardenLegacyStateFiles() {
  const char* xdg = std::getenv("XDG_DATA_HOME");
  const char* home = std::getenv("HOME");
  const std::string base =
      xdg != nullptr && *xdg != '\0'
          ? xdg
          : (home != nullptr && *home != '\0' ? std::string(home) + "/.local/share"
                                               : "");
  if (base.empty()) return;
  HardenLegacyStateDirectory(base + "/wins_vpn");
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);
  // Flutter's file APIs honor the process umask. Default to owner-only state
  // before the engine or plugins can persist VPN keys, activation data, or PINs.
  umask(0077);
  HardenLegacyStateFiles();
  // Prime the secure store on the GLib worker before the engine runs so the
  // first persist routes through linux_secure_store_async.cc and is never
  // issued synchronously (blocking) on the UI thread.
  InitializeLinuxSecureStoreAsync();
  g_autoptr(MyApplication) app = my_application_new();
  if (app == nullptr) return EXIT_FAILURE;
  // GLib supports HUP, INT and TERM. Forward QUIT using only signal-safe
  // operations so the application shutdown callback still runs on GLib.
  const guint sighup_source =
      g_unix_signal_add(SIGHUP, QuitApplicationFromUnixSignal, app);
  const guint sigint_source =
      g_unix_signal_add(SIGINT, QuitApplicationFromUnixSignal, app);
  const guint sigterm_source =
      g_unix_signal_add(SIGTERM, QuitApplicationFromUnixSignal, app);
  struct sigaction quit_action = {};
  struct sigaction previous_quit_action = {};
  quit_action.sa_handler = ForwardQuitToTermination;
  sigemptyset(&quit_action.sa_mask);
  quit_action.sa_flags = SA_RESTART;
  if (sigaction(SIGQUIT, &quit_action, &previous_quit_action) != 0) {
    g_warning("Could not install the Linux quit signal handler: %s",
              g_strerror(errno));
    g_source_remove(sigterm_source);
    g_source_remove(sigint_source);
    g_source_remove(sighup_source);
    return EXIT_FAILURE;
  }
  const int status = g_application_run(G_APPLICATION(app), argc, argv);
  sigaction(SIGQUIT, &previous_quit_action, nullptr);
  g_source_remove(sigterm_source);
  g_source_remove(sigint_source);
  g_source_remove(sighup_source);
  return status;
}
