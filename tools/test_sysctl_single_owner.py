#!/usr/bin/env python3
"""Lane L54 / L51 C5: one owner per sysctl key on every host role.

systemd-sysctl applies /etc/sysctl.d/*.conf in lexical order and the last file
wins, so two installer files that set one key to different values leave the
effective value to file naming and turn the loser into dead config. Chicago
carried nf_conntrack_max=262144 in 60-winn3-gateway-forward.conf while
99-winsvpn-edge.conf (1048576, the certified live value) overrode it.

Host roles and the installers that write their sysctl.d files:
  data plane  wins_data_plane_setup_ONETOUCH.sh (it carries the gateway block)
  core        wins_core_server_setup_ONETOUCH.sh
  hub         wins_control_plane_setup_ONETOUCH.sh

The three node installers' sysctl heredocs are parsed statically.

Slice S6 (design v17 2.8) retired the standalone gateway installer, the second
writer on a data plane. Its sysctl functions are no longer run here: the file
is a tombstone. What this suite holds now is that the data plane is the only
writer: the tombstone writes no sysctl.d file, the data plane defines none of
the retired installer's sysctl functions and writes none of its two files, and
every key keeps one value and the certified nf_conntrack_max.

Design 10.2 P-1 (slice P1): the data plane takes the larger value of the two
sources for each UDP buffer key. No merged key is below either source (the
gateway installer's former 134217728 target, or a higher value kept in an
edited copy of its file), and merge_udp_buffer_floor, run in a sandbox,
raises, keeps or refuses exactly as that rule says.

usage: tools/test_sysctl_single_owner.py [server_dir]
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = sys.argv[1] if __name__ == "__main__" and len(sys.argv) > 1 else os.path.join(ROOT, "server")
CERTIFIED_CONNTRACK_MAX = "1048576"
FAILURES = []


def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILURES.append(label)


def sysctl_heredocs(path):
    """{file name: {key: value}} for every `cat > <sysctl target> <<TAG` body."""
    lines = open(path, encoding="utf-8").read().split("\n")
    out = {}
    i = 0
    head = re.compile(r"""^\s*cat > (.+?) <<'?([A-Za-z_]+)'?\s*$""")
    while i < len(lines):
        m = head.match(lines[i])
        if not m or "sysctl" not in m.group(1):
            i += 1
            continue
        target, tag = m.group(1), m.group(2)
        name = re.search(r"([0-9A-Za-z_.-]+\.conf)", target)
        if name:
            name = name.group(1)
        elif "memory_sysctl_path" in target:
            default = re.search(r"memory_sysctl_path=\"\$\{WINS_MEMORY_SYSCTL_PATH:-([^}]+)\}\"",
                                "\n".join(lines[max(0, i - 80):i]))
            name = os.path.basename(default.group(1)) if default else "memory-sysctl.conf"
        else:
            name = target
        body = {}
        i += 1
        while i < len(lines) and lines[i] != tag:
            line = lines[i].strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                body[key.strip()] = " ".join(value.split())
            i += 1
        out.setdefault(name, {}).update(body)
        i += 1
    return out


def read_conf(path):
    body = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            body[key.strip()] = " ".join(value.split())
    return body


def conflicts(files):
    """[(key, {file: value})] for keys set to different values in two files."""
    seen = {}
    for name, body in files.items():
        for key, value in body.items():
            seen.setdefault(key, {})[name] = value
    return [(k, v) for k, v in sorted(seen.items()) if len(set(v.values())) > 1]


def effective(files, key):
    value = None
    for name in sorted(files):
        if key in files[name]:
            value = files[name][key]
    return value


# The retired standalone installer's sysctl writers: the items design v17 2.2
# marks "merged" in tools/winn3_gateway_block.py. The data plane is the single
# owner, so none of them may be defined again.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import winn3_gateway_block as block  # noqa: E402

RETIRED_GATEWAY_FUNCS = [name for name, why in block.NOT_MOVED.items()
                         if why.startswith(block.MERGED) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                         and name != name.upper()]
RETIRED_GATEWAY_CONFS = ("60-winn3-gateway-forward.conf", "60-winn3-gateway-udp-buffers.conf")


def defined_functions(path):
    text = open(path, encoding="utf-8").read().split("\n")
    return {line[:-4] for line in text if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\(\) \{", line)}


MERGE_SCRIPT = r'''
set -uo pipefail
err() { echo "ERR $*" >&2; }
__FUNCTION__
merge_udp_buffer_floor "${SANDBOX}"
'''


def merge_function(installer):
    text = open(installer, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(text) if l == "merge_udp_buffer_floor() {")
    end = next(i for i in range(start + 1, len(text)) if text[i] == "}")
    return "\n".join(text[start:end + 1])


SETUP_SCRIPT = r'''
set -uo pipefail
err() { echo "ERR $*" >&2; }
remove_stale_winn3_gateway_sysctls() { :; }
# macOS mktemp ignores TMPDIR; keep the saved copy inside the sandbox so a leftover is seen.
mktemp() { command mktemp "${SANDBOX}/tmp/prior.XXXXXX"; }
__STUBS__
__MERGE__
__SETUP__
setup_sysctl
'''


def setup_prefix(installer):
    """setup_sysctl up to and including the merge and its clean-up: the part that
    writes 99-winsvpn-node.conf and merges, without the host-changing tail."""
    text = open(installer, encoding="utf-8").read()
    start = text.index("\nsetup_sysctl() {") + 1
    merge_at = re.compile(r"^  merge_udp_buffer_floor[^\n]*\|\| \{$", re.M).search(text, start).start()
    end = text.index("\n  }\n", merge_at) + len("\n  }\n")
    tail = '  rm -f "${prior_node_conf}"\n'
    if text.startswith(tail, end):
        end += len(tail)
    return text[start:end].replace("/etc/sysctl.d", "${SANDBOX}") + "}\n"


def run_setup(installer, previous=None, former=None, stubs=""):
    """Run setup_sysctl's write-and-merge against a sandbox that already holds a
    previous 99-winsvpn-node.conf. STUBS is shell that runs after the helper
    stubs, to make a command inside setup_sysctl fail. Returns rc, stderr,
    {key: int}, leftovers."""
    sandbox = tempfile.mkdtemp(prefix="p1_setup_")
    try:
        target = os.path.join(sandbox, "99-winsvpn-node.conf")
        if previous is not None:
            with open(target, "w") as fh:
                fh.write(previous)
        if former is not None:
            with open(os.path.join(sandbox, "60-winn3-gateway-udp-buffers.conf"), "w") as fh:
                fh.write(former)
        script = SETUP_SCRIPT.replace("__MERGE__", merge_function(installer).replace("/etc/sysctl.d", "${SANDBOX}")).replace("__SETUP__", setup_prefix(installer)).replace("__STUBS__", stubs)
        tmpdir = os.path.join(sandbox, "tmp")
        os.makedirs(tmpdir)
        # cwd is the sandbox: a command that misbehaves (the failure cases above
        # make cp and mktemp fail) cannot drop a file into the working tree.
        proc = subprocess.run(["bash", "-c", script], env=dict(os.environ, SANDBOX=sandbox, TMPDIR=tmpdir),
                              capture_output=True, text=True, timeout=60, cwd=sandbox)
        values = {}
        if os.path.isfile(target):
            values = {k: int(v) for k, v in read_conf(target).items() if v.isdigit()}
        return proc.returncode, proc.stderr.strip(), values, os.listdir(tmpdir)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def run_merge(installer, files, symlink_former=None):
    """Run merge_udp_buffer_floor against a sandbox sysctl.d. Returns rc, stderr, {name: {key: int}}."""
    sandbox = tempfile.mkdtemp(prefix="p1_merge_")
    try:
        for name, text in files.items():
            with open(os.path.join(sandbox, name), "w") as fh:
                fh.write(text)
        if symlink_former is not None:
            with open(os.path.join(sandbox, "elsewhere.conf"), "w") as fh:
                fh.write(symlink_former)
            os.symlink(os.path.join(sandbox, "elsewhere.conf"),
                       os.path.join(sandbox, "60-winn3-gateway-udp-buffers.conf"))
        script = MERGE_SCRIPT.replace("__FUNCTION__", merge_function(installer))
        proc = subprocess.run(["bash", "-c", script], env=dict(os.environ, SANDBOX=sandbox),
                              capture_output=True, text=True, timeout=60)
        out = {}
        for name in ("99-winsvpn-node.conf", "60-winn3-gateway-udp-buffers.conf"):
            path = os.path.join(sandbox, name)
            if os.path.isfile(path) and not os.path.islink(path):
                out[name] = {k: int(v) for k, v in read_conf(path).items() if v.isdigit()}
        return proc.returncode, proc.stderr.strip(), out
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def gateway_udp_target(gateway):
    text = open(gateway, encoding="utf-8").read()
    body = text[text.index("ensure_udp_socket_buffers() {"):]
    return int(re.search(r"local target=([0-9]+)", body).group(1))


def check_merge_floor(gateway, dp):
    dp_path = os.path.join(SERVER, "wins_data_plane_setup_ONETOUCH.sh")
    target = gateway_udp_target(gateway)
    for key in ("net.core.rmem_max", "net.core.wmem_max"):
        merged = int(dp["99-winsvpn-node.conf"][key])
        check(merged >= target, f"P-1: the data plane's {key}={merged} is not below the gateway installer's former target {target}")
    base = "net.core.rmem_max=134217728\nnet.core.wmem_max=134217728\n"
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": base})
    check(rc == 0 and out["99-winsvpn-node.conf"] == {"net.core.rmem_max": 134217728, "net.core.wmem_max": 134217728},
          f"P-1 merge: equal sources leave both keys at 134217728 (rc={rc} {err[:120]})")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": base,
                                       "60-winn3-gateway-udp-buffers.conf": "net.core.rmem_max = 268435456\nnet.core.wmem_max = 134217728\n"})
    merged = out.get("99-winsvpn-node.conf", {})
    check(rc == 0 and merged.get("net.core.rmem_max") == 268435456 and merged.get("net.core.wmem_max") == 134217728,
          f"P-1 merge: a higher value kept in the former gateway file is kept, per key ({merged})")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": "net.core.rmem_max=268435456\nnet.core.wmem_max=134217728\n",
                                       "60-winn3-gateway-udp-buffers.conf": "net.core.rmem_max = 134217728\n"})
    check(rc == 0 and out["99-winsvpn-node.conf"]["net.core.rmem_max"] == 268435456,
          "P-1 merge: the data plane's own higher value is never lowered")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": "net.core.rmem_max=67108864\nnet.core.wmem_max=33554432\n"})
    merged = out.get("99-winsvpn-node.conf", {})
    check(rc == 0 and merged == {"net.core.rmem_max": 134217728, "net.core.wmem_max": 134217728},
          f"P-1 merge: a value below the 128 MiB floor is raised to it ({merged})")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": base}, symlink_former="net.core.rmem_max = 999999999\n")
    check(rc == 0 and out["99-winsvpn-node.conf"]["net.core.rmem_max"] == 134217728,
          "P-1 merge: a symlinked former file is not trusted")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": base,
                                       "60-winn3-gateway-udp-buffers.conf": "# net.core.rmem_max = 999999999\nnet.core.rmem_max = bogus\n"})
    check(rc == 0 and out["99-winsvpn-node.conf"]["net.core.rmem_max"] == 134217728,
          "P-1 merge: a comment or a non-number in the former file is ignored")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": "net.core.rmem_max=134217728\n"})
    check(rc != 0, f"P-1 merge: a missing key refuses (rc={rc})")
    rc, err, out = run_merge(dp_path, {"99-winsvpn-node.conf": base + "net.core.rmem_max=1\n"})
    check(rc != 0, f"P-1 merge: a duplicated key refuses (rc={rc})")
    rc, err, out = run_merge(dp_path, {})
    check(rc != 0, f"P-1 merge: a missing data-plane file refuses (rc={rc})")
    text = open(dp_path, encoding="utf-8").read()
    body = text[text.index("\nsetup_sysctl() {"):text.index("\ninstall_awg_kmod_nodebug_guard()")]
    check(body.index("remove_stale_winn3_gateway_sysctls") < body.index("merge_udp_buffer_floor")
          < body.index("sysctl --system"),
          "P-1: setup_sysctl merges after the stale-file removal and before sysctl --system applies it")
    check(re.search(r"merge_udp_buffer_floor [^\n]*\|\| \{", body) and "return 1" in body[body.index("merge_udp_buffer_floor"):][:400],
          "P-1: a failed merge stops setup_sysctl")
    check_setup_keeps_a_higher_value(dp_path)


def check_setup_keeps_a_higher_value(dp_path):
    """setup_sysctl rewrites the node file before it merges: a value higher than
    the floor in the PREVIOUS copy must survive the real call, not only a direct
    call of the helper on an untouched file."""
    old = "net.core.rmem_max=268435456\nnet.core.wmem_max=134217728\nnet.ipv4.ip_forward=1\n"
    rc, err, merged, left = run_setup(dp_path, previous=old)
    check(rc == 0 and merged.get("net.core.rmem_max") == 268435456 and merged.get("net.core.wmem_max") == 134217728,
          f"P-1 setup_sysctl: a higher rmem_max kept in the previous node file survives the rewrite ({merged}, rc={rc} {err[:120]})")
    check(left == [], f"P-1 setup_sysctl: the saved copy of the previous file is removed ({left})")
    rc, err, merged, left = run_setup(dp_path, previous="net.core.rmem_max=67108864\nnet.core.wmem_max=268435456\n")
    check(rc == 0 and merged.get("net.core.rmem_max") == 134217728 and merged.get("net.core.wmem_max") == 268435456,
          f"P-1 setup_sysctl: the floor and a higher value are applied per key ({merged})")
    rc, err, merged, left = run_setup(dp_path)
    check(rc == 0 and merged.get("net.core.rmem_max") == 134217728 and merged.get("net.core.wmem_max") == 134217728 and left == [],
          f"P-1 setup_sysctl: a first install (no previous file) writes the floor ({merged}, left={left})")
    rc, err, merged, left = run_setup(dp_path, previous=old, former="net.core.rmem_max = 536870912\n")
    check(rc == 0 and merged.get("net.core.rmem_max") == 536870912,
          f"P-1 setup_sysctl: the former gateway file still counts beside the previous node file ({merged})")
    # A previous file that cannot be preserved must stop setup_sysctl before the
    # heredoc overwrites it: the higher value would otherwise be lost for good.
    kept = {"net.core.rmem_max": 268435456, "net.core.wmem_max": 134217728, "net.ipv4.ip_forward": 1}
    cases = (
        ("cp fails", "cp() { return 1; }", "Cannot preserve the previous sysctl values"),
        ("mktemp fails", "mktemp() { return 1; }", "Cannot allocate the previous sysctl copy"),
        ("mktemp prints no name", "mktemp() { return 0; }", "has no filename"),
    )
    for label, stub, message in cases:
        rc, err, merged, left = run_setup(dp_path, previous=old, stubs=stub)
        check(rc != 0 and merged == kept and left == [] and message in err,
              f"P-1 setup_sysctl: {label}, the previous node file is left untouched, no copy is left behind and the call fails (rmem_max {merged.get('net.core.rmem_max')}, rc={rc}, left={left}, {err[:120]})")


def main():
    dp = sysctl_heredocs(os.path.join(SERVER, "wins_data_plane_setup_ONETOUCH.sh"))
    core = sysctl_heredocs(os.path.join(SERVER, "wins_core_server_setup_ONETOUCH.sh"))
    hub = sysctl_heredocs(os.path.join(SERVER, "wins_control_plane_setup_ONETOUCH.sh"))
    gateway = os.path.join(SERVER, "wins_winn3_gateway_install.sh")
    check("99-winsvpn-edge.conf" in dp and "99-winsvpn-node.conf" in dp,
          f"data-plane sysctl files parsed: {', '.join(sorted(dp))}")
    check(dp.get("99-winsvpn-edge.conf", {}).get("net.netfilter.nf_conntrack_max") == CERTIFIED_CONNTRACK_MAX,
          f"99-winsvpn-edge.conf owns nf_conntrack_max={CERTIFIED_CONNTRACK_MAX} (certified live value)")
    for key, value in (("net.core.rmem_max", "134217728"),
                       ("net.core.wmem_max", "134217728"),
                       ("net.ipv4.ip_forward", "1")):
        check(effective(dp, key) == value, f"data plane owns {key}={value}")
    for role, files in (("data plane (installer files only)", dp), ("core", core), ("hub", hub)):
        found = conflicts(files)
        check(not found, f"{role}: no key set to two values"
              + ("" if not found else ": " + "; ".join(f"{k} {v}" for k, v in found)))

    # P-1 (slice P1) compares the data plane with the gateway installer's former
    # target. Since slice S6 that installer is a tombstone, and its former text
    # lives only in the frozen snapshot S3 and S6 prove the move against.
    check_merge_floor(os.path.join(SERVER, "testdata", "winn3_gateway_install_retired",
                                   "wins_winn3_gateway_install.sh.snapshot"), dp)

    # Slice S6: the data plane is the single owner on every data plane.
    check(sysctl_heredocs(gateway) == {},
          "the retired standalone installer (tombstone) writes no sysctl.d file")
    dp_functions = defined_functions(os.path.join(SERVER, "wins_data_plane_setup_ONETOUCH.sh"))
    for name in RETIRED_GATEWAY_FUNCS:
        check(name not in dp_functions, f"the data plane defines no second sysctl writer ({name})")
    check("remove_stale_winn3_gateway_sysctls" in dp_functions,
          "the data plane removes the retired installer's two exact former sysctl files (S3)")
    for name in RETIRED_GATEWAY_CONFS:
        check(name not in dp, f"the data plane writes no {name}, which only the retired installer wrote")
    check(defined_functions(gateway) == set(),
          "the retired standalone installer defines no function")

    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


def test_single_owner():
    FAILURES.clear()
    assert main() == 0, FAILURES


if __name__ == "__main__":
    sys.exit(main())
