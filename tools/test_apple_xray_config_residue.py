#!/usr/bin/env python3
"""The Apple Xray wrapper must not leave its VLESS config file on failures.

Compiles the production wrapper with stub LibXray symbols, an injected fsync
failure and a temporary directory redirected into the test's own directory.
No network, product build, signing or upload.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m"

HARNESS = r'''
#import <Foundation/Foundation.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef void (*libxray_sockcallback)(uintptr_t fd, void *ctx);
extern int wins_xray_vless_ws_transport_configure(const char *launch_json);
extern int wins_xray_vless_ws_transport_start(void);
extern void wins_xray_test_set_ifindex_override(int ifindex);

static int g_fsync_fail;

NSString *wins_test_temporary_directory(void) {
  return [NSString stringWithUTF8String:getenv("WINS_XRAY_TEST_TMP")];
}
static int g_run_fail;
static int g_stop_fail;

int wins_test_fsync(int fd) {
  if (g_fsync_fail) {
    errno = EIO;
    return -1;
  }
  return fsync(fd);
}

char *LibXraySetSockCallback(libxray_sockcallback cb, void *ctx) {
  (void)cb;
  (void)ctx;
  return NULL;
}

char *LibXrayRunXray(const char *dat_dir, const char *config_path,
                     int64_t max_memory) {
  (void)dat_dir;
  (void)config_path;
  (void)max_memory;
  return g_run_fail ? strdup("run failed") : NULL;
}

char *LibXrayStopXray(void) {
  return g_stop_fail ? strdup("stop failed") : NULL;
}

static const char *kLaunchJson =
    "{\"xray\":{"
    "\"uuid\":\"123e4567-e89b-12d3-a456-426614174000\","
    "\"host\":\"example.invalid\","
    "\"port\":\"443\","
    "\"servername\":\"example.invalid\","
    "\"path\":\"/vless\","
    "\"security\":\"tls\","
    "\"localport\":\"51820\","
    "\"remoteawghost\":\"127.0.0.1\","
    "\"remoteawgport\":\"51821\""
    "}}";

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  const char *config = argv[1];

  g_fsync_fail = 1;
  int configured = wins_xray_vless_ws_transport_configure(kLaunchJson);
  int residue = access(config, F_OK) == 0;
  printf("fsync_failure configured=%d residue=%d\n", configured, residue);
  g_fsync_fail = 0;

  pid_t child = fork();
  if (child < 0) return 3;
  if (child == 0) {
    wins_xray_test_set_ifindex_override(1);
    if (wins_xray_vless_ws_transport_configure(kLaunchJson) != 1) _exit(4);
    if (access(config, F_OK) != 0) _exit(5);
    g_run_fail = 1;
    g_stop_fail = 1;
    (void)wins_xray_vless_ws_transport_start();
    _exit(6);
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child) return 7;
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  int stop_residue = access(config, F_OK) == 0;
  printf("stop_failure exit=%d residue=%d\n", code, stop_residue);
  return 0;
}
'''


def clang_prefix() -> list[str]:
    xcrun = shutil.which("xcrun")
    if xcrun:
        return [xcrun, "clang"]
    clang = shutil.which("clang")
    if clang:
        return [clang]
    raise unittest.SkipTest("clang/xcrun is required for Apple wrapper harness tests")


class AppleXrayConfigResidueTests(unittest.TestCase):
    def test_failed_configure_and_failed_stop_leave_no_config_file(self) -> None:
        compiler = clang_prefix()
        with tempfile.TemporaryDirectory(prefix="wins-apple-xray-residue-") as raw:
            work = pathlib.Path(raw).resolve()
            tmp = work / "tmp"
            tmp.mkdir(mode=0o700)
            harness = work / "harness.m"
            harness.write_text(HARNESS, encoding="utf-8")
            wrapper_obj = work / "wrapper.o"
            harness_obj = work / "harness.o"
            binary = work / "residue"
            steps = (
                compiler + ["-c", "-fobjc-arc", "-DWINS_XRAY_TRANSPORT_TESTING=1",
                            "-Dfsync=wins_test_fsync",
                            "-DNSTemporaryDirectory=wins_test_temporary_directory",
                            "-o", str(wrapper_obj),
                            str(WRAPPER)],
                compiler + ["-c", "-fobjc-arc", "-o", str(harness_obj),
                            str(harness)],
                compiler + ["-framework", "Foundation", "-o", str(binary),
                            str(wrapper_obj), str(harness_obj)],
            )
            for cmd in steps:
                built = subprocess.run(cmd, cwd=work, capture_output=True,
                                       text=True, timeout=120)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            env = dict(os.environ)
            env["WINS_XRAY_TEST_TMP"] = str(tmp)
            config = tmp / "winsvpn-xray" / "wins_xray_client.json"
            ran = subprocess.run([str(binary), str(config)], cwd=work, env=env,
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn("fsync_failure configured=0 residue=0", ran.stdout)
            self.assertIn("stop_failure exit=70 residue=0", ran.stdout)


if __name__ == "__main__":
    unittest.main()
