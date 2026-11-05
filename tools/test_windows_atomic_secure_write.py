"""Run the actual atomic-write control flow with injected Win32 failures."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

SHIM = r'''
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
using DWORD = unsigned long;
using BOOL = int;
using HANDLE = int;
using PSECURITY_DESCRIPTOR = void*;
struct SECURITY_ATTRIBUTES {
  unsigned long nLength;
  PSECURITY_DESCRIPTOR lpSecurityDescriptor;
};
constexpr HANDLE INVALID_HANDLE_VALUE = -1;
constexpr DWORD INVALID_FILE_ATTRIBUTES = 0xffffffff;
constexpr int FALSE = 0;
constexpr int GENERIC_WRITE = 1, CREATE_NEW = 2;
constexpr int FILE_ATTRIBUTE_TEMPORARY = 4, FILE_FLAG_WRITE_THROUGH = 8;
constexpr int FILE_ATTRIBUTE_DIRECTORY = 16, FILE_ATTRIBUTE_REPARSE_POINT = 32;
constexpr int MOVEFILE_REPLACE_EXISTING = 64, MOVEFILE_WRITE_THROUGH = 128;
constexpr int ERROR_FILE_EXISTS = 80;
constexpr size_t kMaximumSecureTextBytes = 4 * 1024 * 1024;
static std::map<std::wstring, std::string> files;
static std::wstring opened;
static bool move_ok = true, acl_ok = true;
bool ConvertSddl(const std::wstring&, PSECURITY_DESCRIPTOR*) { return true; }
std::wstring UniqueSiblingPath(const std::wstring& p, const wchar_t*) {
  return p + L".tmp";
}
HANDLE CreateFileW(const wchar_t* p, int, int, SECURITY_ATTRIBUTES*, int, int,
                   void*) {
  opened = p;
  files[opened] = "";
  return 1;
}
DWORD GetLastError() { return 0; }
void LocalFree(void*) {}
BOOL WriteFile(HANDLE, const uint8_t* p, DWORD n, DWORD* written, void*) {
  files[opened] = std::string(reinterpret_cast<const char*>(p), n);
  *written = n;
  return 1;
}
BOOL FlushFileBuffers(HANDLE) { return 1; }
void CloseHandle(HANDLE) {}
BOOL DeleteFileW(const wchar_t* p) { return files.erase(p) != 0; }
DWORD GetFileAttributesW(const wchar_t* p) {
  return files.count(p) ? 0 : INVALID_FILE_ATTRIBUTES;
}
BOOL MoveFileExW(const wchar_t* from, const wchar_t* to, int) {
  if (!move_ok) return 0;
  files[to] = files.at(from);
  files.erase(from);
  return 1;
}
bool ApplyProtectedDacl(const std::wstring&, const std::wstring&) {
  return acl_ok;
}
'''

MAIN = r'''
int main() {
  const std::wstring path = L"state.wvdp";
  const uint8_t replacement[] = {'n', 'e', 'w'};
  files[path] = "old";
  move_ok = false;
  bool ok = WriteBytesSecureAtomic(path, replacement, sizeof(replacement), L"acl");
  const bool preserved = !ok && files.count(path) && files.at(path) == "old";
  std::cout << "failed_move_preserves_old=" << preserved << '\n';
  if (!preserved || files.count(path + L".tmp")) return 1;
  move_ok = true;
  acl_ok = false;
  ok = WriteBytesSecureAtomic(path, replacement, sizeof(replacement), L"acl");
  if (ok || files.count(path)) return 2;
  acl_ok = true;
  ok = WriteBytesSecureAtomic(path, replacement, sizeof(replacement), L"acl");
  if (!ok || files.at(path) != "new") return 3;
  std::cout << "acl_failure_and_success_controls=PASS\n";
  return 0;
}
'''


class AtomicWriteFailureTests(unittest.TestCase):
    def test_previous_value_survives_failed_replacement(self):
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("c++ is unavailable")
        source = (ROOT / "windows/runner/windows_tunnel_backend.cpp").read_text()
        start = source.index("bool WriteBytesSecureAtomic(")
        end = source.index("\nbool ReadRegularFileBounded(", start)
        with tempfile.TemporaryDirectory() as raw:
            work = Path(raw)
            cpp = work / "atomic.cc"
            binary = work / "atomic"
            cpp.write_text(SHIM + source[start:end] + MAIN)
            built = subprocess.run(
                [compiler, "-std=c++17", str(cpp), "-o", str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True,
                                 text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn("failed_move_preserves_old=1", ran.stdout)
            self.assertIn("acl_failure_and_success_controls=PASS", ran.stdout)


if __name__ == "__main__":
    unittest.main()
