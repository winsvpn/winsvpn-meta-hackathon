// Launch-path wiring test for the Linux Flutter runner.
//
// WHY THIS FILE EXISTS. The one thing an app-launch registration bug looks
// like at runtime is total silence: the VPN backend never answers a method
// call, which to a user in Myanmar is indistinguishable from a censor blocking
// the path. This test is the name-side twin of the "prose outruns evidence"
// rule -- it does not assert what the launch path *should* do, it asserts what
// the launch path textually, provably DOES, on the exact files that go into
// the released runner binary:
//
//   * my_application_activate is wired to GApplication::activate, i.e. it IS
//     the code that runs at app launch;
//   * that handler calls RegisterLinuxTunnelBackend with the real engine
//     binary messenger -- not a stub, not a constant, not a dead include;
//   * linux_tunnel_backend.cc actually defines that function and registers the
//     "wins_vpn/tunnel" method channel with a handler;
//   * the runner CMake target compiles BOTH my_application.cc and
//     linux_tunnel_backend.cc into the same binary, so the registration is
//     linked, not merely declared.
//
// It is deliberately free of glib/gio and of <flutter_linux.h>, exactly like
// winn3_posture_test.cc and linux_winn_carrier_profile_test.cc, so it builds
// and RUNS on the development host as well as on any target -- it only reads
// bytes and reasons about text. Build and run it anywhere:
//
//   c++ -std=c++17 -Wall -Wextra -o /tmp/my_application_launch_wiring_test \
//       linux/runner/my_application_launch_wiring_test.cc \
//       && /tmp/my_application_launch_wiring_test
//
// It is not in linux/runner/CMakeLists.txt, the same standalone-program
// arrangement as the other runner tests that ship their own main.
//
// MUTATION CONTROLS. A wiring test that cannot fail is not evidence, so this
// binary is written to be run three ways against mutated copies (never the
// shared tree):
//   * CONTROL_GREEN -- unchanged sources; every check must pass.
//   * CONTROL_NEUTRAL -- a comment-only edit; every check must still pass.
//   * a deliberate break (drop the RegisterLinuxTunnelBackend call, or feed it
//     a constant messenger, or remove the CMake wiring); THAT check must fail.
// Each check prints CHECK:NAME PASS/FAIL and the exit status is 0 only when no
// required check fails.
//
// Mutate a PRIVATE COPY, never the shared working tree, per the repo mutation
// harness rule. Point this binary at the copy with --my-application,
// --backend and --cmake paths.

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct Source {
  std::string my_application;
  std::string backend;
  std::string cmake;
  std::string main_src;
  std::string store_async_hdr;
  std::string store_async;
  bool loaded = false;
};

bool ReadFile(const std::string& path, std::string* out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  *out = ss.str();
  return true;
}

// Collapse all runs of whitespace to single spaces, trimming the ends, so
// that multi-line calls and differing indentation cannot mask the identity of
// the actual registration statement.
std::string Normalize(const std::string& in) {
  std::string out;
  bool pending_space = false;
  for (char c : in) {
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      pending_space = true;
      continue;
    }
    if (pending_space && !out.empty()) out.push_back(' ');
    pending_space = false;
    out.push_back(c);
  }
  return out;
}

// True when needle occurs in haystack as an exact normalized substring.
bool ContainsNormalized(const std::string& haystack, const std::string& needle) {
  return Normalize(haystack).find(Normalize(needle)) != std::string::npos;
}

int failures = 0;

void Check(bool ok, const std::string& name) {
  std::cout << "CHECK:" << name << " " << (ok ? "PASS" : "FAIL") << "\n";
  if (!ok) ++failures;
}

// The launch handler is the GApplication activate vfunc. Prove the wiring:
// activate = my_application_activate, and the register call sits inside that
// handler's body (a bounded span, so a stray mention elsewhere cannot pass).
bool LaunchHandlerIsActivate(const std::string& src) {
  const std::string marker =
      "G_APPLICATION_CLASS(klass)->activate = my_application_activate;";
  return ContainsNormalized(src, marker);
}

bool LaunchRegistersWithRealMessenger(const std::string& src) {
  const std::string signature = "static void my_application_activate(";
  const std::string next_fn = "static gboolean my_application_local_command_line(";
  size_t start = Normalize(src).find(Normalize(signature));
  size_t end = Normalize(src).find(Normalize(next_fn));
  if (start == std::string::npos || end == std::string::npos || end < start) {
    return false;
  }
  const std::string body = Normalize(src).substr(start, end - start);
  // The registration statement must appear in the handler, and must pass the
  // real engine binary messenger (fl_view_get_engine -> fl_engine_get_...), not
  // a literal/constant/pointer-to-nothing. If someone stubs the messenger the
  // exact expression below stops matching and this check fails.
  return body.find("RegisterLinuxTunnelBackend(") != std::string::npos &&
         body.find(
             "fl_engine_get_binary_messenger(fl_view_get_engine(view))") !=
             std::string::npos;
}

bool IncludeWired(const std::string& src) {
  return ContainsNormalized(src, "#include \"linux_tunnel_backend.h\"");
}

bool BackendDefinesRegister(const std::string& src) {
  return ContainsNormalized(
      src, "void RegisterLinuxTunnelBackend(FlBinaryMessenger* messenger)");
}

bool BackendRegistersChannelWithHandler(const std::string& src) {
  return ContainsNormalized(src, "wins_vpn/tunnel") &&
         ContainsNormalized(src, "fl_method_channel_new(messenger,") &&
         ContainsNormalized(src, "fl_method_channel_set_method_call_handler(");
}

bool CmakeLinksBothIntoRunner(const std::string& src) {
  const std::string target_marker = "add_executable(${BINARY_NAME}";
  const std::string norm = Normalize(src);
  size_t start = norm.find(target_marker);
  if (start == std::string::npos) return false;
  size_t end = norm.find(')', start);
  if (end == std::string::npos || end < start) return false;
  const std::string add = norm.substr(start, end - start);
  return add.find("my_application.cc") != std::string::npos &&
         add.find("linux_tunnel_backend.cc") != std::string::npos;
}

// --- Secure-store launch wiring -------------------------------------------
//
// The runner's first persist must go through linux_secure_store_async.cc. The
// Linux entrypoint (main.cc) reaches it by including the async header and
// calling InitializeLinuxSecureStoreAsync() before the engine runs; the async
// translation unit both declares and defines that symbol, and the runner
// CMake target compiles linux_secure_store_async.cc into the same binary.

bool MainIncludesAsyncStore(const std::string& src) {
  return ContainsNormalized(src, "#include \"linux_secure_store_async.h\"");
}

bool MainCallsSecureStoreInit(const std::string& src) {
  const std::string signature = "int main(int argc, char** argv) {";
  const size_t start = Normalize(src).find(Normalize(signature));
  if (start == std::string::npos) return false;
  // main() is the last function in the file, so the normalized remainder after
  // its opening brace is its body. A stray mention elsewhere (a comment, a
  // dead declaration) cannot satisfy a call appearing inside main().
  const std::string body = Normalize(src).substr(start);
  return body.find("InitializeLinuxSecureStoreAsync()") != std::string::npos;
}

bool AsyncHeaderDeclaresInit(const std::string& src) {
  return ContainsNormalized(
      src, "void InitializeLinuxSecureStoreAsync(void);");
}

bool AsyncSourceDefinesInit(const std::string& src) {
  // Deliberately matches the definition WITHOUT the trailing `;` so a bare
  // forward-declaration copy cannot pass as an implementation.
  return ContainsNormalized(src, "void InitializeLinuxSecureStoreAsync()") &&
         !ContainsNormalized(src, "void InitializeLinuxSecureStoreAsync();");
}

bool CmakeLinksAsyncStore(const std::string& src) {
  const std::string target_marker = "add_executable(${BINARY_NAME}";
  const std::string norm = Normalize(src);
  size_t start = norm.find(target_marker);
  if (start == std::string::npos) return false;
  size_t end = norm.find(')', start);
  if (end == std::string::npos || end < start) return false;
  const std::string add = norm.substr(start, end - start);
  return add.find("linux_secure_store_async.cc") != std::string::npos;
}

int Run(const std::string& my_app_path, const std::string& backend_path,
        const std::string& cmake_path, const std::string& main_path,
        const std::string& async_hdr_path, const std::string& async_src_path) {
  Source s;
  s.loaded = ReadFile(my_app_path, &s.my_application) &&
             ReadFile(backend_path, &s.backend) && ReadFile(cmake_path, &s.cmake) &&
             ReadFile(main_path, &s.main_src) &&
             ReadFile(async_hdr_path, &s.store_async_hdr) &&
             ReadFile(async_src_path, &s.store_async);
  if (!s.loaded) {
    std::cout << "CHECK:files_readable FAIL\n";
    return 1;
  }
  Check(ReadFile(my_app_path, &s.my_application), "my_application_readable");
  Check(ReadFile(backend_path, &s.backend), "backend_readable");
  Check(ReadFile(cmake_path, &s.cmake), "cmake_readable");
  Check(ReadFile(main_path, &s.main_src), "main_readable");
  Check(ReadFile(async_hdr_path, &s.store_async_hdr), "async_store_header_readable");
  Check(ReadFile(async_src_path, &s.store_async), "async_store_source_readable");

  Check(!ContainsNormalized(s.my_application, "G_APPLICATION_NON_UNIQUE") &&
            ContainsNormalized(s.my_application,
                               "static_cast<GApplicationFlags>(0)"),
        "application_has_single_instance_registration");
  Check(ContainsNormalized(s.my_application,
                           "gtk_window_present(GTK_WINDOW(windows->data));") &&
            ContainsNormalized(s.my_application, "if (windows != nullptr)"),
        "activation_presents_existing_window");
  Check(LaunchHandlerIsActivate(s.my_application),
        "activate_vfunc_is_my_application_activate");
  Check(LaunchRegistersWithRealMessenger(s.my_application),
        "launch_handler_calls_register_with_engine_messenger");
  Check(IncludeWired(s.my_application), "my_application_includes_backend_header");
  Check(BackendDefinesRegister(s.backend), "backend_defines_register_function");
  Check(BackendRegistersChannelWithHandler(s.backend),
        "backend_registers_tunnel_channel_with_handler");
  Check(CmakeLinksBothIntoRunner(s.cmake),
        "cmake_links_backend_into_runner_target");

  Check(MainIncludesAsyncStore(s.main_src),
        "main_includes_async_store_header");
  Check(MainCallsSecureStoreInit(s.main_src),
        "main_calls_initialize_async_secure_store");
  Check(AsyncHeaderDeclaresInit(s.store_async_hdr),
        "async_header_declares_initialize_secure_store");
  Check(AsyncSourceDefinesInit(s.store_async),
        "async_source_defines_initialize_secure_store");
  Check(CmakeLinksAsyncStore(s.cmake),
        "cmake_links_async_secure_store_into_runner_target");

  std::cout << (failures == 0 ? "RESULT: PASS\n" : "RESULT: FAIL\n");
  return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  std::string my_app = "linux/runner/my_application.cc";
  std::string backend = "linux/runner/linux_tunnel_backend.cc";
  std::string cmake = "linux/runner/CMakeLists.txt";
  std::string main_src = "linux/runner/main.cc";
  std::string async_hdr = "linux/runner/linux_secure_store_async.h";
  std::string async_src = "linux/runner/linux_secure_store_async.cc";
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string key = argv[i];
    std::string val = argv[i + 1];
    if (key == "--my-application") my_app = val;
    else if (key == "--backend") backend = val;
    else if (key == "--cmake") cmake = val;
    else if (key == "--main") main_src = val;
    else if (key == "--async-hdr") async_hdr = val;
    else if (key == "--async-src") async_src = val;
  }
  return Run(my_app, backend, cmake, main_src, async_hdr, async_src);
}
