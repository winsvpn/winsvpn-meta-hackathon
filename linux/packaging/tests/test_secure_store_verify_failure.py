"""Compile the production verified-store routine with deterministic faults.

No Secret Service is used: libsecret calls are replaced by in-process stubs so
the control flow after a successful store and a failed readback is exercised.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "linux/runner/linux_secure_store.cc"

PREFIX = r'''
#include <cstdio>
#include <string>
struct GError {};
struct GCancellable {};
using gboolean = bool;
int kSecureTextSchema = 0;
const char* SECRET_COLLECTION_DEFAULT = "default";
const char* kApplicationAttribute = "fixture";
enum class LookupStatus { kFound, kNotFound, kError };
LookupStatus next_lookup = LookupStatus::kError;
bool retained = false;
int clear_calls = 0;
void g_error_free(GError*) {}
void WipeString(std::string* value) { value->clear(); }
gboolean secret_password_store_sync(int*, const char*, const char*,
    const char*, GCancellable*, GError**, ...) {
  retained = true;
  return true;
}
LookupStatus LookupSecret(const std::string&, std::string* value,
                          std::string* error, GCancellable*) {
  if (next_lookup == LookupStatus::kError) *error = "readback unavailable";
  if (next_lookup == LookupStatus::kFound) *value = "fixture-value";
  return next_lookup;
}
bool ClearSecret(const std::string&, std::string*, GCancellable*) {
  ++clear_calls;
  retained = false;
  return true;
}
'''

SUFFIX = r'''
int main() {
  std::string error;
  bool ok = StoreSecretVerified("client_keypair.json", "fixture-value", &error,
                                nullptr);
  std::printf("write_result=%d retained=%d clear_calls=%d\n", ok, retained,
              clear_calls);
  if (ok || !retained || clear_calls != 0 || error.empty()) return 1;
  next_lookup = LookupStatus::kFound;
  error.clear();
  if (!StoreSecretVerified("client_keypair.json", "fixture-value", &error,
                           nullptr)) {
    return 2;
  }
  next_lookup = LookupStatus::kNotFound;
  error.clear();
  if (StoreSecretVerified("client_keypair.json", "fixture-value", &error,
                          nullptr)) {
    return 3;
  }
  if (retained || clear_calls != 1) return 4;
  return 0;
}
'''


class SecureStoreVerifyFailureTests(unittest.TestCase):
    def test_readback_error_keeps_committed_value(self):
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("c++ is unavailable")
        text = SOURCE.read_text()
        start = text.index("bool StoreSecretVerified(")
        body = text[start:text.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as raw:
            work = pathlib.Path(raw)
            unit = work / "store_commit_test.cc"
            binary = work / "store_commit_test"
            unit.write_text(PREFIX + body + SUFFIX)
            built = subprocess.run(
                [compiler, "-std=c++17", str(unit), "-o", str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary)], capture_output=True,
                                 text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn("write_result=0 retained=1 clear_calls=0", ran.stdout)


if __name__ == "__main__":
    unittest.main()
