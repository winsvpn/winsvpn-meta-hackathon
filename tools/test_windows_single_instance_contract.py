import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MAIN = (ROOT / "windows" / "runner" / "main.cpp").read_text(encoding="utf-8")


class WindowsSingleInstanceContractTest(unittest.TestCase):
    def test_interactive_app_is_single_instance_per_logon_session(self) -> None:
        self.assertIn('L"Local\\\\WinsVPN.App.SingleInstance.v1"', MAIN)
        self.assertIn("::CreateMutexW(nullptr, FALSE, kSingleInstanceMutexName)", MAIN)
        self.assertIn("::GetLastError() == ERROR_ALREADY_EXISTS", MAIN)
        self.assertIn("ActivateExistingInstance();", MAIN)

    def test_secure_storage_producer_self_test_precedes_instance_guard(self) -> None:
        self.assertLess(
            MAIN.index('command_line_arguments.front() == "--secure-storage-self-test"'),
            MAIN.index("::CreateMutexW(nullptr, FALSE, kSingleInstanceMutexName)"),
        )

    def test_mutex_handle_is_closed_on_all_post_acquisition_exits(self) -> None:
        acquired = MAIN.index("::CreateMutexW(nullptr, FALSE, kSingleInstanceMutexName)")
        tail = MAIN[acquired:]
        self.assertGreaterEqual(tail.count("::CloseHandle(single_instance);"), 3)
        self.assertIn("::FindWindowW(kFlutterWindowClassName, L\"Win's VPN\")", MAIN)
        self.assertIn("::SetForegroundWindow(existing);", MAIN)

    def test_com_and_message_loop_failures_release_owned_resources(self) -> None:
        self.assertIn("if (FAILED(com_result))", MAIN)
        self.assertIn("while ((message_result = ::GetMessage", MAIN)
        self.assertIn("return message_result == -1 ? EXIT_FAILURE : EXIT_SUCCESS", MAIN)
        create_failure = MAIN[MAIN.index('if (!window.Create(L"Win\'s VPN"'):]
        self.assertLess(
            create_failure.index("::CoUninitialize();"),
            create_failure.index("::CloseHandle(single_instance);"),
        )


if __name__ == "__main__":
    unittest.main()
