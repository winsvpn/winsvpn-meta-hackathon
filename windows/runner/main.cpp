#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <windows.h>

#include "flutter_window.h"
#include "utils.h"
#include "windows_tunnel_backend.h"

namespace {

constexpr wchar_t kSingleInstanceMutexName[] =
    L"Local\\WinsVPN.App.SingleInstance.v1";
constexpr wchar_t kFlutterWindowClassName[] =
    L"FLUTTER_RUNNER_WIN32_WINDOW";

void ActivateExistingInstance() {
  HWND existing = ::FindWindowW(kFlutterWindowClassName, L"Win's VPN");
  if (existing == nullptr) {
    return;
  }
  if (::IsIconic(existing)) {
    ::ShowWindow(existing, SW_RESTORE);
  } else {
    ::ShowWindow(existing, SW_SHOW);
  }
  ::SetForegroundWindow(existing);
}

void ConfigureWindowsPerformanceMode() {
  // Keep the desktop shell responsive for future Windows tunnel integration.
  // Windows uses all available CPU cores by default when affinity is unrestricted.
  ::SetPriorityClass(::GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
  ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#if defined(PROCESS_POWER_THROTTLING_CURRENT_VERSION) && \
    defined(PROCESS_POWER_THROTTLING_EXECUTION_SPEED)
  PROCESS_POWER_THROTTLING_STATE power_throttling = {};
  power_throttling.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;
  power_throttling.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
  power_throttling.StateMask = 0;
  ::SetProcessInformation(::GetCurrentProcess(), ProcessPowerThrottling,
                          &power_throttling, sizeof(power_throttling));
#endif
}

}  // namespace

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();
  if (command_line_arguments.size() == 1 &&
      command_line_arguments.front() == "--secure-storage-self-test") {
    std::string error;
    return RunWindowsSecureStorageSelfTest(&error) ? EXIT_SUCCESS : EXIT_FAILURE;
  }
  // Only one interactive app may own a transition generation and the local
  // Xray carrier in a Windows logon session. A second process would reset its
  // generation counter to one and could otherwise race the first process's
  // stop fence. Keep non-interactive signed-binary self-tests outside this
  // guard so the producer can validate an installed image independently.
  HANDLE single_instance =
      ::CreateMutexW(nullptr, FALSE, kSingleInstanceMutexName);
  if (single_instance == nullptr) {
    return EXIT_FAILURE;
  }
  if (::GetLastError() == ERROR_ALREADY_EXISTS) {
    ActivateExistingInstance();
    ::CloseHandle(single_instance);
    return EXIT_SUCCESS;
  }
  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  const HRESULT com_result =
      ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(com_result)) {
    ::CloseHandle(single_instance);
    return EXIT_FAILURE;
  }

  ConfigureWindowsPerformanceMode();

  flutter::DartProject project(L"data");

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);
  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);
  if (!window.Create(L"Win's VPN", origin, size)) {
    ::CoUninitialize();
    ::CloseHandle(single_instance);
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  BOOL message_result = FALSE;
  while ((message_result = ::GetMessage(&msg, nullptr, 0, 0)) > 0) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  ::CloseHandle(single_instance);
  return message_result == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}
