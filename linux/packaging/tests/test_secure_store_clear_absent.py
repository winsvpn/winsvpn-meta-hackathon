"""Compile the production Linux secure store against an in-process keyring.

No Secret Service is used. libsecret and GLib are replaced by minimal fakes
that follow the libsecret contract for secret_password_clear_sync: TRUE when
an item was removed, FALSE with no error when nothing matched, FALSE with an
error when the service failed. The legacy plaintext directory is a real
temporary directory, so the delete path's file wipe is exercised as shipped.
"""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "linux/runner/linux_secure_store.cc"

GIO_H = r'''
#pragma once
#include <cstddef>
typedef int gboolean;
typedef char gchar;
typedef long gssize;
typedef int gint;
typedef void* gpointer;
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
struct GError { int code; };
struct GCancellable { int unused; };
inline void g_error_free(GError* error) { delete error; }
inline gboolean g_utf8_validate(const char*, gssize, const gchar**) {
  return TRUE;
}
'''

SECRET_H = r'''
#pragma once
#include <gio/gio.h>
typedef enum { SECRET_SCHEMA_NONE = 0 } SecretSchemaFlags;
typedef enum { SECRET_SCHEMA_ATTRIBUTE_STRING = 0 } SecretSchemaAttributeType;
typedef struct {
  const gchar* name;
  SecretSchemaAttributeType type;
} SecretSchemaAttribute;
typedef struct {
  const gchar* name;
  SecretSchemaFlags flags;
  SecretSchemaAttribute attributes[32];
  gint reserved;
  gpointer reserved1, reserved2, reserved3, reserved4, reserved5, reserved6,
      reserved7;
} SecretSchema;
#define SECRET_COLLECTION_DEFAULT "default"
gchar* secret_password_lookup_sync(const SecretSchema*, GCancellable*,
                                   GError**, ...);
void secret_password_free(gchar*);
gboolean secret_password_clear_sync(const SecretSchema*, GCancellable*,
                                    GError**, ...);
gboolean secret_password_store_sync(const SecretSchema*, const gchar*,
                                    const gchar*, const gchar*, GCancellable*,
                                    GError**, ...);
'''

HARNESS = r'''
#include "linux_secure_store.h"
#include <libsecret/secret.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
std::map<std::string, std::string> keyring;
bool service_fails = false;   // every call sets an error
bool clear_is_inert = false;  // clear finds nothing to remove (locked item)

std::string NameAttribute(va_list args) {
  std::string name;
  for (;;) {
    const char* key = va_arg(args, const char*);
    if (key == nullptr) break;
    const char* value = va_arg(args, const char*);
    if (std::strcmp(key, "name") == 0) name = value;
  }
  return name;
}

void SetError(GError** error) { *error = new GError{1}; }
}  // namespace

gchar* secret_password_lookup_sync(const SecretSchema*, GCancellable*,
                                   GError** error, ...) {
  va_list args;
  va_start(args, error);
  const std::string name = NameAttribute(args);
  va_end(args);
  if (service_fails) { SetError(error); return nullptr; }
  const auto found = keyring.find(name);
  return found == keyring.end() ? nullptr : strdup(found->second.c_str());
}

void secret_password_free(gchar* value) { std::free(value); }

gboolean secret_password_clear_sync(const SecretSchema*, GCancellable*,
                                    GError** error, ...) {
  va_list args;
  va_start(args, error);
  const std::string name = NameAttribute(args);
  va_end(args);
  if (service_fails) { SetError(error); return FALSE; }
  if (clear_is_inert) return FALSE;
  return keyring.erase(name) > 0 ? TRUE : FALSE;
}

gboolean secret_password_store_sync(const SecretSchema*, const gchar*,
                                    const gchar*, const gchar* password,
                                    GCancellable*, GError** error, ...) {
  va_list args;
  va_start(args, error);
  const std::string name = NameAttribute(args);
  va_end(args);
  if (service_fails) { SetError(error); return FALSE; }
  keyring[name] = password;
  return TRUE;
}

static int failures = 0;
static void Expect(bool condition, const char* label) {
  std::printf("%s %s\n", condition ? "PASS" : "FAIL", label);
  if (!condition) ++failures;
}

static void Reset() {
  keyring.clear();
  service_fails = false;
  clear_is_inert = false;
}

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  const std::string app = std::string(argv[1]) + "/wins_vpn";
  if (mkdir(app.c_str(), 0700) != 0) return 2;
  if (setenv("XDG_DATA_HOME", argv[1], 1) != 0) return 2;
  const std::string legacy = app + "/user_pin.txt";
  const auto plant_legacy = [&legacy]() {
    std::ofstream output(legacy, std::ios::binary | std::ios::trunc);
    output << "legacy-secret";
    output.close();
    chmod(legacy.c_str(), 0600);
  };
  const auto legacy_present = [&legacy]() {
    struct stat info = {};
    return lstat(legacy.c_str(), &info) == 0;
  };
  std::string error;

  Reset();
  error.clear();
  Expect(DeleteLinuxSecureText("wins_vpn_restart_config.conf", &error) &&
             error.empty(),
         "deleting a never-stored name succeeds");

  Reset();
  plant_legacy();
  error.clear();
  Expect(DeleteLinuxSecureText("user_pin.txt", &error),
         "delete with only an unmigrated legacy file succeeds");
  Expect(!legacy_present(), "the unmigrated legacy plaintext is removed");

  Reset();
  keyring["user_pin.txt"] = "stored";
  error.clear();
  Expect(DeleteLinuxSecureText("user_pin.txt", &error) &&
             keyring.count("user_pin.txt") == 0,
         "deleting a stored item removes it");

  Reset();
  service_fails = true;
  plant_legacy();
  error.clear();
  Expect(!DeleteLinuxSecureText("user_pin.txt", &error) && !error.empty(),
         "an unavailable service still fails the delete");
  Expect(legacy_present(), "an unavailable service keeps the legacy copy");
  unlink(legacy.c_str());

  Reset();
  keyring["vpn_config.txt"] = "locked";
  clear_is_inert = true;
  error.clear();
  Expect(!DeleteLinuxSecureText("vpn_config.txt", &error) && !error.empty(),
         "an item the clear could not remove still fails the delete");

  rmdir(app.c_str());
  return failures == 0 ? 0 : 1;
}
'''


class SecureStoreClearAbsentTests(unittest.TestCase):
    def test_absent_secret_is_deleted_and_failures_stay_closed(self):
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("c++ is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            # Resolved: the store refuses every symlinked path component,
            # and some temporary roots (macOS /var) are links.
            work = pathlib.Path(raw).resolve()
            (work / "include/gio").mkdir(parents=True)
            (work / "include/libsecret").mkdir(parents=True)
            (work / "include/gio/gio.h").write_text(GIO_H)
            (work / "include/libsecret/secret.h").write_text(SECRET_H)
            (work / "harness.cc").write_text(HARNESS)
            data = work / "data"
            data.mkdir(mode=0o700)
            binary = work / "secure_store_clear_test"
            built = subprocess.run(
                [compiler, "-std=c++17", "-I", str(work / "include"),
                 "-I", str(SOURCE.parent), str(SOURCE),
                 str(work / "harness.cc"), "-o", str(binary)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(binary), str(data)],
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertNotIn("FAIL", ran.stdout)


if __name__ == "__main__":
    unittest.main()
