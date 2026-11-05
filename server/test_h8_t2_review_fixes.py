"""Offline regressions for the H8 Turn 2 review objections (Sol and Gemini)
and the Turn 3 objections (Sol and Claude) fixed in the same file.

Each test fails on the H8-T2 candidate and passes on the fix. Nothing here
contacts a host, the network or a real key: the mint tool runs with its SSH
read and its signing subprocess replaced, and every runbook command that is
executed runs against temporary files with the installer call replaced.

Set H8_FIX_ROOT to run these checks against another tree.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import textwrap
import types

import pytest

ROOT = Path(os.environ.get("H8_FIX_ROOT", Path(__file__).resolve().parents[1]))
CP = (ROOT / "server/wins_control_plane_setup_ONETOUCH.sh").read_text()
RUNBOOK = (ROOT / "docs/runbooks/HUB_COMPROMISE_G3_RECOVERY.md").read_text()
MINT = ROOT / "tools/mint_and_register_winn3_descriptors.py"
SIGN = ROOT / "tools/winn3_sign_descriptor.py"
BASH = "bash"


def comment_text(source):
    """Every '#' comment line joined into one whitespace-normalised string."""
    words = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            words.append(stripped.lstrip("#").strip())
    return re.sub(r"\s+", " ", " ".join(words))


def section(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


def sh_blocks(text):
    """Fenced ```sh blocks, dedented by their fence's own indentation."""
    blocks = []
    for match in re.finditer(r"^( *)```sh\n(.*?)^\1```$", text, re.M | re.S):
        indent = len(match.group(1))
        lines = [line[indent:] if line[:indent].strip() == "" else line
                 for line in match.group(2).splitlines()]
        blocks.append("\n".join(lines) + "\n")
    return blocks


def heredoc_body(block, tag):
    start = block.index(f"<<'{tag}'\n") + len(f"<<'{tag}'\n")
    return block[start:block.index(f"\n{tag}\n", start) + 1]


# ------------------------------------------------------------ mint tool ----

def load_mint():
    spec = importlib.util.spec_from_file_location("h8_mint_under_test", MINT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SECRET = ("ab" * 32).encode("ascii")


def fingerprint(secret):
    return hashlib.sha256(b"winn3-admission-fingerprint-v1" + secret).hexdigest()[:16]


def s4_identity(**overrides):
    """The field set S4's make_identity publishes (impl/S4 tree, line 17553)."""
    identity = {
        "slug": "node-a", "gateway_id": "winsgw-a", "endpoint": "203.0.113.5:9111",
        "inner_router_v4": "10.77.0.1", "inner_resolver_v4": "10.77.0.1",
        "path_mtu": 1380, "plan": "udp",
        "static_pub_hex": "11" * 32, "auth_ed25519_hex": "22" * 32,
        "auth_mldsa65_hex": "33" * 1952,
        "admission_fingerprint": fingerprint(SECRET),
        "credential_record_sha256": "44" * 32,
        "ssh_host_ed25519_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample",
    }
    identity.update(overrides)
    return identity


def run_mint(tmp_path, monkeypatch, identity, secret_bytes, out=None):
    module = load_mint()
    calls = []
    files = {module.IDENTITY_PATH: json.dumps(identity).encode(),
             module.ADMISSION_KEY_PATH: secret_bytes}
    monkeypatch.setattr(module, "ssh_cat", lambda host, path: files[path])

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(
            returncode=0, stderr="",
            stdout=json.dumps({"seq": 5, "previous_seq": 4, "admission_gen": 2}))

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    key = tmp_path / "g1.pem"
    key.write_text("placeholder, never read by the patched signer\n")
    out = out or tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", [
        "mint", "--key", str(key), "--host", "node-a.invalid", "--seq", "5",
        "--prev-seq", "4", "--admission-gen", "2", "--out", str(out)])
    return module, calls, out


def flag(cmd, name):
    return cmd[cmd.index(name) + 1]


def test_require_text_field_refuses_edge_whitespace_instead_of_trimming():
    module = load_mint()
    for value in ("winsgw-a ", " winsgw-a", "winsgw-a\n"):
        with pytest.raises(SystemExit) as exc:
            module.require_text_field({"gateway_id": value}, "gateway_id")
        assert exc.value.code == 2
    assert module.require_text_field({"gateway_id": "winsgw-a"}, "gateway_id") == "winsgw-a"


def test_mint_accepts_the_identity_s4_publishes(tmp_path, monkeypatch):
    module, calls, out = run_mint(tmp_path, monkeypatch, s4_identity(), SECRET + b"\n")
    assert module.main() == 0
    (cmd,) = calls
    assert flag(cmd, "--static-pub") == base64.b64encode(bytes.fromhex("11" * 32)).decode()
    assert flag(cmd, "--auth-ed25519") == base64.b64encode(bytes.fromhex("22" * 32)).decode()
    assert flag(cmd, "--auth-mldsa65") == base64.b64encode(bytes.fromhex("33" * 1952)).decode()
    assert flag(cmd, "--gateway-id-text") == "winsgw-a"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text()) == {"node-a": {"seq": 5, "previous_seq": 4, "admission_gen": 2}}


def test_mint_refuses_a_whitespace_gateway_id_before_signing(tmp_path, monkeypatch, capsys):
    module, calls, _ = run_mint(
        tmp_path, monkeypatch, s4_identity(gateway_id="winsgw-a "), SECRET + b"\n")
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    assert "gateway_id has edge whitespace" in capsys.readouterr().err
    assert calls == []


def test_mint_strips_one_trailing_line_ending_and_nothing_else(tmp_path, monkeypatch, capsys):
    # An embedded LF used to be deleted, turning 65 bytes into a valid secret.
    split = SECRET[:32] + b"\n" + SECRET[32:] + b"\n"
    module, calls, _ = run_mint(tmp_path, monkeypatch, s4_identity(), split)
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "winn3-gateway-admission.key" in err and "exactly 64" in err
    assert calls == []
    # Exactly one CRLF is the one trim the signing primitive also performs.
    module, calls, _ = run_mint(tmp_path, monkeypatch, s4_identity(), SECRET + b"\r\n",
                                out=tmp_path / "crlf.json")
    assert module.main() == 0 and len(calls) == 1


def test_mint_refuses_an_existing_output_path(tmp_path, monkeypatch, capsys):
    existing = tmp_path / "old.json"
    existing.write_text("previous result\n")
    os.chmod(existing, 0o644)
    module, calls, _ = run_mint(tmp_path, monkeypatch, s4_identity(), SECRET, out=existing)
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    assert "--out already exists" in capsys.readouterr().err
    assert existing.read_text() == "previous result\n"
    assert stat.S_IMODE(existing.stat().st_mode) == 0o644


def test_mint_refuses_a_planted_symlink_output(tmp_path, monkeypatch, capsys):
    target = tmp_path / "target.txt"
    target.write_text("untouched\n")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    module, _, _ = run_mint(tmp_path, monkeypatch, s4_identity(), SECRET, out=link)
    with pytest.raises(SystemExit):
        module.main()
    assert "--out already exists" in capsys.readouterr().err
    assert target.read_text() == "untouched\n"


def test_mint_refuses_an_existing_output_before_it_signs(tmp_path, monkeypatch, capsys):
    """The offline signature is made only for an output path that can be used."""
    existing = tmp_path / "old.json"
    existing.write_text("previous result\n")
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "nowhere.json")
    for out in (existing, dangling):
        module, calls, _ = run_mint(tmp_path, monkeypatch, s4_identity(), SECRET, out=out)
        with pytest.raises(SystemExit) as exc:
            module.main()
        assert exc.value.code == 2 and calls == []
        assert "--out already exists" in capsys.readouterr().err
    assert existing.read_text() == "previous result\n"


# ------------------------------------------------- installer comments -----

def test_installer_comments_describe_the_h1_signer_policy():
    text = comment_text(CP)
    for stale in (
        "never a descriptor of its own making",
        "every issuance is rate-limited",
        "All three private keys live offline",
        "serves winn/1 -- the same behaviour as a node with no descriptor at all",
        "Each node needs a new issuance (a t1-ticketed sign or rekey",
    ):
        assert stale not in text, stale
    assert text.count("Normal fleet quotas apply unless a ticketed identity issuance "
                      "spends an operator-granted recovery allowance") == 2
    assert "Normal fleet quotas apply except for ticketed recovery-allowance issuances" in text
    assert "Renewal limits, normal fleet quotas and any operator-granted recovery allowance apply" in text
    assert ("An app attacker with root on the ticketed node can choose the keys that node "
            "signs while its ticket remains unused") in text
    assert "The serve path does not implicitly rewrite it to winn/1" in text
    assert ("The active descriptor-slot private key lives in the separate signer service; "
            "the hub app holds public halves and cannot read the descriptor signing key") in text
    assert "ordinary renewal does not perform that migration" in text


def test_offline_signing_tool_no_longer_claims_a_keyless_hub():
    source = SIGN.read_text()
    assert "The hub holds \"\n            \"no signing key by design" not in source
    assert "every issuance\nis rate-limited" not in source
    spec = importlib.util.spec_from_file_location("h8_sign_under_test", SIGN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    description = module.build_parser().description
    assert description.startswith(
        "Sign a winn/3 standalone gateway descriptor offline. The hub app cannot read "
        "the descriptor key held by the separate signer service. This tool provides "
        "the offline ceremony path. ")
    doc = re.sub(r"\s+", " ", module.__doc__)
    assert ("Normal fleet quotas apply except for ticketed issuances spending an "
            "operator-granted recovery allowance.") in doc


# ------------------------------------------------------------- runbook ----

def test_every_runbook_shell_block_parses():
    blocks = sh_blocks(RUNBOOK)
    assert len(blocks) >= 15
    for block in blocks:
        done = subprocess.run([BASH, "-n"], input=block, text=True, capture_output=True)
        assert done.returncode == 0, (block, done.stderr)


SUDO_SHIM = "#!/bin/sh\nexec \"$@\"\n"
TOKEN_STANDIN = r"""#!/bin/bash
printf 'secrets=%s defaults=%s\n' "${WINS_SECRETS_FILE-}" "${WINS_DEFAULTS_FILE-}" > "$STANDIN_REPORT"
"""


def test_service_token_rotation_block_stops_as_a_whole_on_refusal(tmp_path):
    """The refusal must stop the runtime-file edit and the installer too: the
    block is one root shell, so nothing after the check can run."""
    case1 = section(RUNBOOK, "## Case 1", "## Case 2")
    assert "sudo grep -hs '^TUNNEL_SERVICE_TOKEN_'" not in case1
    (block,) = [b for b in sh_blocks(case1) if "TUNNEL_SERVICE_TOKEN_" in b]
    runtime_list = "/root/vpn_auth.env /root/vpn_auth/.env"
    installer = "bash server/wins_control_plane_setup_ONETOUCH.sh --deploy"
    # Refuse to execute anything unless both host paths were substituted.
    assert block.count(runtime_list) == 1 and block.count(installer) == 1
    assert block.startswith("sudo bash -s -- ")
    canonical, legacy = tmp_path / "vpn_auth.env", tmp_path / "legacy.env"
    standin, report = tmp_path / "installer.sh", tmp_path / "report.txt"
    standin.write_text(TOKEN_STANDIN)
    block = block.replace(runtime_list, f"{canonical} {legacy}").replace(
        installer, f"bash {standin}")
    shim = tmp_path / "bin"
    shim.mkdir()
    for name, text in (("sed", SED_SHIM), ("sudo", SUDO_SHIM)):
        (shim / name).write_text(text)
        (shim / name).chmod(0o755)
    secrets, defaults = tmp_path / "secrets.env", tmp_path / "defaults.env"
    stored = ("A=1\nTUNNEL_SERVICE_TOKEN_ID=runtime-id\n"
              "TUNNEL_SERVICE_TOKEN_SECRET=runtime-secret\nB=2\n")
    env = {"PATH": f"{shim}:{os.environ['PATH']}", "STANDIN_REPORT": str(report),
           "WINS_SECRETS_FILE": str(secrets), "WINS_DEFAULTS_FILE": str(defaults)}

    def run(secrets_text, defaults_text, path_prefix=None):
        secrets.write_text(secrets_text)
        defaults.write_text(defaults_text)
        canonical.write_text(stored)
        legacy.write_text(stored)
        report.unlink(missing_ok=True)
        run_env = dict(env)
        if path_prefix:
            run_env["PATH"] = f"{path_prefix}:{env['PATH']}"
        return subprocess.run([BASH, "-c", block], env=run_env, text=True,
                              capture_output=True)

    for where, args in (("secrets", ("TUNNEL_SERVICE_TOKEN_SECRET=s3cr3t-value-123\n", "OTHER=1\n")),
                        ("defaults", ("OTHER=2\n", "TUNNEL_SERVICE_TOKEN_ID=s3cr3t-value-123\n"))):
        done = run(*args)
        assert done.returncode == 1, where
        assert "s3cr3t-value-123" not in done.stdout + done.stderr, where
        assert not report.exists(), where
        assert canonical.read_text() == stored and legacy.read_text() == stored, where

    for name in (
        "TUNNEL_SERVICE_TOKEN_ID",
        "TUNNEL_SERVICE_TOKEN_SECRET",
    ):
        for template in (
            "export {name}=placeholder\n",
            "  {name}=placeholder\n",
            "declare -x {name}=placeholder\n",
            "export OTHER=1 {name}=placeholder\n",
        ):
            configured = template.format(name=name)
            for args in (
                (configured, "OTHER=1\n"),
                ("OTHER=1\n", configured),
            ):
                done = run(*args)
                assert done.returncode == 1
                assert not report.exists()
                assert canonical.read_text() == stored
                assert legacy.read_text() == stored

    # A grep that fails for any reason other than "no match" also stops it.
    failing = tmp_path / "failing-grep"
    failing.mkdir()
    (failing / "grep").write_text("#!/bin/sh\nexit 2\n")
    (failing / "grep").chmod(0o755)
    done = run("OTHER=3\n", "OTHER=4\n", failing)
    assert done.returncode == 2
    assert not report.exists()
    assert canonical.read_text() == stored and legacy.read_text() == stored

    done = run("OTHER=5\n", "OTHER=6\n")
    assert done.returncode == 0, done.stderr
    assert report.read_text() == f"secrets={secrets} defaults={defaults}\n"
    assert canonical.read_text() == "A=1\nB=2\n" and legacy.read_text() == "A=1\nB=2\n"


def test_case1_recovery_starts_with_an_executable_stop():
    case1 = section(RUNBOOK, "## Case 1", "## Case 2")
    first = sh_blocks(case1)[0]
    done = subprocess.run([BASH, "-c", first], text=True, capture_output=True)
    assert done.returncode == 1
    assert "Recovery blocked" in done.stderr
    assert RUNBOOK.index(first.strip().splitlines()[0]) < RUNBOOK.index("Recovery, in order:")
    assert case1.index(first.strip().splitlines()[0]) < case1.index("sudo rm -f /root/.ssh/id_rsa")


def test_case2_rebuild_starts_with_an_executable_stop():
    step2 = section(RUNBOOK, "### Step 2.", "### Step 3.")
    first = sh_blocks(step2)[0]
    done = subprocess.run([BASH, "-c", first], text=True, capture_output=True)
    assert done.returncode == 1
    assert "Recovery blocked" in done.stderr
    assert RUNBOOK.index(first.strip().splitlines()[0]) < RUNBOOK.index(
        'WINS_SECRETS_FILE="$input/secrets.env"')


def rebuild_root_shell():
    (block,) = [b for b in sh_blocks(RUNBOOK) if 'WINS_SECRETS_FILE="$input/secrets.env"' in b]
    body = block[block.index("bash -c '\n") + len("bash -c '\n"):block.rindex("\n'")]
    assert "'" not in body
    return block, body


def test_rebuild_root_shell_sets_t1_and_the_ring_before_key_injection(tmp_path):
    block, body = rebuild_root_shell()
    t1 = body.index('export WINN3_SIGNER_TICKET_PUBKEY_T1="$T1_PUBLIC_B64"')
    ring = body.index("python3 -B tools/winn3_descriptor_ring_defines.py env")
    inject = body.index('printf "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=')
    assert t1 < ring < inject
    assert 'sudo env T1_PUBLIC_B64="$T1_PUBLIC_B64" bash -c' in block
    exports = body[t1:body.index("\n", ring)] + "\nenv\n"
    done = subprocess.run([BASH, "-c", exports], cwd=ROOT, text=True, capture_output=True,
                          env={"PATH": os.environ["PATH"], "T1_PUBLIC_B64": "dDEtcHVibGlj"})
    assert done.returncode == 0, done.stderr
    seen = dict(line.split("=", 1) for line in done.stdout.splitlines() if "=" in line)
    defines = subprocess.run([sys.executable, "-B", "tools/winn3_descriptor_ring_defines.py", "env"],
                             cwd=ROOT, text=True, capture_output=True, check=True).stdout
    expected = dict(line.split("=", 1) for line in defines.splitlines())
    assert seen["WINN3_SIGNER_TICKET_PUBKEY_T1"] == "dDEtcHVibGlj"
    for slot in ("G1", "G2", "G3"):
        assert seen[f"WINN3_DESCRIPTOR_PUBKEY_{slot}"] == expected[f"WINS_WINN3_DESCRIPTOR_PUBKEY_{slot}"]


INSTALLER_STANDIN = r"""#!/bin/bash
# Records what the installer would see, then exits with STANDIN_RC.
{
  printf 'env_key=%s\n' "${WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64-absent}"
  printf 'secrets_file=%s\n' "${WINS_SECRETS_FILE-}"
  printf 'mode=%s\n' "$(stat -f %Lp "$WINS_SECRETS_FILE" 2>/dev/null || stat -c %a "$WINS_SECRETS_FILE")"
  printf 'slot=%s recovery=%s\n' "${WINN3_DESCRIPTOR_SIGNER_ACTIVE_SLOT-}" "${WINN3_RECOVERY_MODE-}"
  cat "$WINS_SECRETS_FILE"
} > "$STANDIN_REPORT"
exit "$STANDIN_RC"
"""


def test_rebuild_key_reaches_the_installer_only_through_the_input_secrets_file(tmp_path):
    """H1 accepts the signer key only from a root 0600 secrets file under
    /etc/wins-descriptor-signer-input, run as WINS_SECRETS_FILE, never from the
    process environment (H1 fix CP:40876)."""
    _, body = rebuild_root_shell()
    assert "export WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64" not in body
    h1 = os.environ.get("H8_H1_TREE")
    if h1:
        h1_cp = (Path(h1) / "server/wins_control_plane_setup_ONETOUCH.sh").read_text()
        assert 'DESCRIPTOR_SIGNER_INPUT_DIR="/etc/wins-descriptor-signer-input"' in h1_cp
        assert '[[ "${secrets}" == "${DESCRIPTOR_SIGNER_INPUT_DIR}/"* ]] || return 1' in h1_cp
    input_dir, commerce, pem = tmp_path / "input", tmp_path / "commerce.env", tmp_path / "g3.pem"
    standin, report = tmp_path / "installer.sh", tmp_path / "report.txt"
    standin.write_text(INSTALLER_STANDIN)
    replacements = {
        "/etc/wins-descriptor-signer-input": (1, str(input_dir)),
        "install -d -m 0700 -o root -g root": (1, "install -d -m 0700"),
        "/root/winsvpn-secrets.env": (2, str(commerce)),
        "/root/wins-recovery/g3.pem": (2, str(pem)),
        "bash server/wins_control_plane_setup_ONETOUCH.sh --deploy": (1, f"bash {standin}"),
    }
    # Refuse to execute anything unless every host path was substituted.
    for old, (count, new) in replacements.items():
        assert body.count(old) == count, old
        body = body.replace(old, new)
    pem_text = "placeholder PEM bytes, not a key\n"
    expected = base64.b64encode(pem_text.encode()).decode()
    for rc in (0, 7):
        commerce.write_text("PAYPAL_CLIENT_SECRET=commerce-value\n"
                            "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64=stale\n")
        pem.write_text(pem_text)
        env = {"PATH": os.environ["PATH"], "T1_PUBLIC_B64": "dDEtcHVibGlj",
               "STANDIN_REPORT": str(report), "STANDIN_RC": str(rc),
               "WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64": "from-the-environment"}
        done = subprocess.run([BASH, "-c", body], cwd=ROOT, env=env, text=True,
                              capture_output=True)
        assert done.returncode == rc, done.stderr
        lines = report.read_text().splitlines()
        assert lines[0] == "env_key=from-the-environment"  # not set by the runbook
        assert lines[1] == f"secrets_file={input_dir}/secrets.env"
        assert lines[2] == "mode=600"
        assert lines[3] == "slot=g3 recovery=1"
        assert lines[4:] == ["PAYPAL_CLIENT_SECRET=commerce-value",
                             f"WINN3_DESCRIPTOR_SIGNER_KEY_PEM_B64={expected}"]
        assert not (input_dir / "secrets.env").exists()
        assert not pem.exists()
        assert expected not in done.stdout + done.stderr


def prepare_rebuild(tmp_path):
    """The rebuild root shell with every host path and the installer replaced."""
    _, body = rebuild_root_shell()
    paths = types.SimpleNamespace(
        input_dir=tmp_path / "input", commerce=tmp_path / "commerce.env",
        pem=tmp_path / "g3.pem", standin=tmp_path / "installer.sh",
        report=tmp_path / "report.txt")
    paths.standin.write_text(INSTALLER_STANDIN)
    for old, new in (("/etc/wins-descriptor-signer-input", str(paths.input_dir)),
                     ("install -d -m 0700 -o root -g root", "install -d -m 0700"),
                     ("/root/winsvpn-secrets.env", str(paths.commerce)),
                     ("/root/wins-recovery/g3.pem", str(paths.pem)),
                     ("bash server/wins_control_plane_setup_ONETOUCH.sh --deploy",
                      f"bash {paths.standin}")):
        assert old in body, old
        body = body.replace(old, new)
    paths.commerce.write_text("PAYPAL_CLIENT_SECRET=commerce-value\n")
    return body, paths


def test_rebuild_stops_before_the_installer_when_an_input_fails(tmp_path):
    """A failed or empty g3 read, a failed commerce copy, an empty t1 key or a
    failed ring read must stop the root shell before the installer runs. A
    command substitution inside printf's arguments would hide the failure
    from set -e. The exit trap must then remove the input file and g3.pem."""
    body, paths = prepare_rebuild(tmp_path)

    def failing(name, status):
        directory = tmp_path / f"failing-{name}"
        directory.mkdir()
        (directory / name).write_text(f"#!/bin/sh\nexit {status}\n")
        (directory / name).chmod(0o755)
        return f"{directory}:{os.environ['PATH']}"

    no_ring = tmp_path / "no-ring"
    no_ring.mkdir()
    base = {"PATH": os.environ["PATH"], "STANDIN_REPORT": str(paths.report),
            "STANDIN_RC": "0", "T1_PUBLIC_B64": "dDEtcHVibGlj"}
    pem_text = "placeholder PEM bytes, not a key\n"
    # (case, g3.pem text or None, environment, cwd, expected status or None
    # for any nonzero, whether the exit trap is installed before the refusal)
    cases = (
        ("missing g3.pem", None, base, ROOT, None, True),
        ("empty g3.pem", "", base, ROOT, 1, True),
        ("conversion fails", pem_text, dict(base, PATH=failing("openssl", 7)), ROOT, 7, True),
        ("commerce copy fails", pem_text, dict(base, PATH=failing("grep", 2)), ROOT, None, True),
        ("empty t1", pem_text, dict(base, T1_PUBLIC_B64=""), ROOT, 1, False),
        ("no ring defines", pem_text, base, no_ring, 1, False),
    )
    for case, text, env, cwd, status, trapped in cases:
        paths.pem.unlink(missing_ok=True)
        if text is not None:
            paths.pem.write_text(text)
        paths.report.unlink(missing_ok=True)
        done = subprocess.run([BASH, "-c", body], cwd=cwd, env=env, text=True,
                              capture_output=True)
        assert done.returncode != 0, case
        if status is not None:
            assert done.returncode == status, (case, done.stderr)
        assert not paths.report.exists(), case  # the installer never ran
        assert not (paths.input_dir / "secrets.env").exists(), case
        if trapped:
            assert not paths.pem.exists(), case
        else:
            assert paths.pem.exists(), case  # still staged for the retry


def test_updated_hub_history_is_fetched_before_step3_stages_it():
    step2 = section(RUNBOOK, "### Step 2.", "### Step 3.")
    append = step2.index("Case 1 step 1 append command")
    fetch = step2.index("ssh \"$HUB_SSH\" 'sudo cat /etc/winsvpn/hub-key-history'")
    switch = step2.index('HUB_KEY_HISTORY="$WORK/hub-key-history.updated"')
    assert append < fetch < switch
    assert 'h=/etc/winsvpn/hub-key-history' in RUNBOOK


def test_hub_key_history_writer_text_matches_the_installer():
    step2 = section(RUNBOOK, "### Step 2.", "### Step 3.")
    assert "generation fallback" not in step2
    assert "The pubkey route does not generate a missing key." in re.sub(r"\s+", " ", step2)
    route = section(CP, '@app.get("/api/v1/pubkey")', '@app.post("/admin/announce")')
    assert "ssh-keygen" not in route and "subprocess" not in route
    assert "hub-key-history" not in CP.split('ensure_hub_ssh_key() {', 1)[1].split("\n}\n", 1)[0]


def cp_floor_helper():
    start = CP.index("def winn3_admission_sequence_floor(")
    source = CP[start:CP.index("\n\n\ndef ", start)]
    namespace = {}
    exec(source, namespace)
    return namespace["winn3_admission_sequence_floor"]


def test_retained_floor_query_matches_the_installer_helper(tmp_path):
    step4 = section(RUNBOOK, "### Step 4.", "### Step 5.")
    (block,) = [b for b in sh_blocks(step4) if "<<'PY'" in b]
    script = heredoc_body(block, "PY")
    db = tmp_path / "vpn_users.db"
    original = "file:/root/vpn_auth/vpn_users.db?mode=ro"
    assert script.count(original) == 1
    script = script.replace(original, f"file:{db}?mode=ro")
    helper = cp_floor_helper()
    ledgers = {
        "text-floor": {"sequence_floor": "99", "current": {"seq": 40}, "previous": {"seq": 41}},
        "bool-seq": {"sequence_floor": 7, "current": {"seq": True}},
        "bool-only": {"current": {"seq": True}},
        "empty": {},
        "negative": {"sequence_floor": -5, "previous": {"seq": 3}},
        "huge": {"sequence_floor": 2 ** 53},
    }
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE nodes (slug TEXT, winn3_descriptor_json TEXT, "
                     "winn3_admission_json TEXT)")
        for slug, ledger in ledgers.items():
            conn.execute("INSERT INTO nodes VALUES (?, NULL, ?)", (slug, json.dumps(ledger)))
        conn.execute("INSERT INTO nodes VALUES ('null-ledger', NULL, NULL)")
        conn.execute("INSERT INTO nodes VALUES ('live', '{\"payload\": \"x\"}', '{}')")

    def run(slug):
        return subprocess.run([sys.executable, "-I", "-", slug], input=script,
                              text=True, capture_output=True)

    for slug, ledger in ledgers.items():
        done = run(slug)
        if helper({}, ledger) > 2 ** 53 - 1 - 2 ** 32:
            assert done.returncode == 1 and "A-4 floor reset required" in done.stderr
            continue
        assert done.returncode == 0, done.stderr
        assert int(done.stdout) == helper({}, ledger), slug
    assert run("text-floor").stdout.strip() == "41"
    assert run("null-ledger").stdout.strip() == "-1"
    live = run("live")
    assert live.returncode == 1 and "withheld" in live.stderr
    missing = run("absent")
    assert missing.returncode == 1 and "Node not found" in missing.stderr


def test_ticket_preparation_names_host_keys_and_the_recovery_action():
    step4 = section(RUNBOOK, "### Step 4.", "### Step 5.")
    (block,) = [b for b in sh_blocks(step4) if "wins_operator_prepare_subject.sh" in b]
    invocations = block.split("tools/wins_operator_prepare_subject.sh")[1:]
    assert len(invocations) == 2
    for command in invocations:
        assert '--host-keys-file "$HOST_KEYS_FILE"' in command
        assert "--action rekey" not in command
    assert '--action "$RECOVERY_ACTION"' in invocations[1]
    guard = block[block.index("case "):block.index("esac") + len("esac")]
    for action, code in (("reset", 0), ("rekey", 0), ("rebuild", 1), ("", 1)):
        done = subprocess.run([BASH, "-c", guard], text=True, capture_output=True,
                              env={"PATH": os.environ["PATH"], "RECOVERY_ACTION": action})
        assert done.returncode == code, action
    assert "| `$HOST_KEYS_FILE` |" in RUNBOOK and "| `$RECOVERY_ACTION` |" in RUNBOOK


def jq_ok(expression, document):
    return subprocess.run(["jq", "-e", expression], input=json.dumps(document),
                          text=True, capture_output=True).returncode == 0


def test_hold_clearing_step_checks_the_hold_reply_and_claims_no_flip():
    step5 = section(RUNBOOK, "### Step 5.", "### Step 6.")
    flat = re.sub(r"\s+", " ", step5)
    assert "Then the carrier flips." not in flat
    assert "Hold clearance alone is not evidence that the node serves v3." in flat
    (block,) = sh_blocks(step5)
    assert "protocol_params_json" not in block and "-H \"x-admin-token" not in block
    expression = block[block.index("jq -e '") + len("jq -e '"):block.rindex("'")]
    # The hold-clearing reply shape of the H2 route.
    assert jq_ok(expression, {"ok": True, "slug": "node-a", "operator_hold": False,
                              "protocol_version": "winn/1", "hold_cleared": True})
    assert not jq_ok(expression, {"ok": True, "slug": "node-a", "protocol_version": "winn/3"})


SED_SHIM = r'''#!/usr/bin/env python3
"""GNU `sed -i --follow-symlinks -e '/^RE/d' ... FILE`, delete commands only."""
import os, re, sys
args = sys.argv[1:]
assert args[:2] == ["-i", "--follow-symlinks"], args
patterns, rest = [], args[2:]
while rest and rest[0] == "-e":
    expr = rest[1]
    assert expr.startswith("/") and expr.endswith("/d"), expr
    patterns.append(re.compile(expr[1:-2]))
    rest = rest[2:]
(path,) = rest
path = os.path.realpath(path)
with open(path) as handle:
    kept = [line for line in handle if not any(p.search(line) for p in patterns)]
with open(path, "w") as handle:
    handle.writelines(kept)
'''


def test_g2_retirement_cleans_both_runtime_copies_and_refuses_configured_g2(tmp_path):
    step6 = section(RUNBOOK, "### Step 6.", "### Step 7.")
    blocks = sh_blocks(step6)
    (block,) = [b for b in blocks if "<<'SH'" in b]
    body = heredoc_body(block, "SH")
    assert 'ENV_FILE="/root/vpn_auth.env"' in CP
    assert 'APP_DIR="/root/vpn_auth"' in CP and 'LEGACY_ENV_FILE="${APP_DIR}/.env"' in CP
    runtime_list = "/root/vpn_auth.env /root/vpn_auth/.env"
    installer = "bash server/wins_control_plane_setup_ONETOUCH.sh --deploy"
    # Refuse to execute anything unless both host paths were substituted.
    assert body.count(runtime_list) == 1 and body.count(installer) == 1
    canonical, legacy = tmp_path / "vpn_auth.env", tmp_path / "legacy.env"
    # The stand-in runs as the child of env -u, so it sees what the installer
    # would see.
    body = body.replace(runtime_list, f"{canonical} {legacy}").replace(
        installer, "bash -c 'printf \"DEPLOY G2=%s G2F=%s DF=%s SF=%s\\n\" "
                   "\"${WINN3_DESCRIPTOR_PUBKEY_G2-unset}\" "
                   "\"${WINN3_DESCRIPTOR_PUBKEY_G2_FILE-unset}\" "
                   "\"${WINS_DEFAULTS_FILE-unset}\" \"${WINS_SECRETS_FILE-unset}\"'")
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "sed").write_text(SED_SHIM)
    (shim / "sed").chmod(0o755)
    env = {"PATH": f"{shim}:{os.environ['PATH']}", "WINN3_DESCRIPTOR_PUBKEY_G2": "g2pub"}
    defaults, secrets = tmp_path / "defaults.env", tmp_path / "secrets.env"
    stored = "A=1\nWINN3_DESCRIPTOR_PUBKEY_G2=g2pub\nWINN3_DESCRIPTOR_PUBKEY_G2_FILE=/x\nB=2\n"
    canonical.write_text(stored)
    legacy.write_text(stored)

    defaults.write_text("WINN3_DESCRIPTOR_PUBKEY_G2_FILE=/etc/g2.pub\n")
    secrets.write_text("C=3\n")
    done = subprocess.run([BASH, "-s", "--", str(defaults), str(secrets)], input=body,
                          text=True, capture_output=True, env=env)
    assert done.returncode == 1 and "DEPLOY" not in done.stdout
    assert canonical.read_text() == stored and legacy.read_text() == stored

    for name in (
        "WINN3_DESCRIPTOR_PUBKEY_G2",
        "WINN3_DESCRIPTOR_PUBKEY_G2_FILE",
    ):
        for template in (
            "export {name}=placeholder\n",
            "  {name}=placeholder\n",
            "declare -x {name}=placeholder\n",
            "export OTHER=1 {name}=placeholder\n",
        ):
            for target in (defaults, secrets):
                defaults.write_text("D=4\n")
                secrets.write_text("C=3\n")
                target.write_text(template.format(name=name))
                done = subprocess.run(
                    [BASH, "-s", "--", str(defaults), str(secrets)],
                    input=body,
                    text=True,
                    capture_output=True,
                    env=env,
                )
                assert done.returncode == 1
                assert "DEPLOY" not in done.stdout
                assert canonical.read_text() == stored
                assert legacy.read_text() == stored
    secrets.write_text("C=3\n")

    defaults.write_text("D=4\n")
    failing_bin = tmp_path / "grep-error"
    failing_bin.mkdir()
    failing_grep = failing_bin / "grep"
    failing_grep.write_text("#!/bin/sh\nexit 2\n")
    failing_grep.chmod(0o755)
    failing_env = dict(env, PATH=f"{failing_bin}:{env['PATH']}")
    done = subprocess.run(
        [BASH, "-s", "--", str(defaults), str(secrets)],
        input=body,
        text=True,
        capture_output=True,
        env=failing_env,
    )
    assert done.returncode == 2
    assert "DEPLOY" not in done.stdout
    assert canonical.read_text() == stored
    assert legacy.read_text() == stored
    done = subprocess.run([BASH, "-s", "--", str(defaults), str(secrets)], input=body,
                          text=True, capture_output=True, env=env)
    assert done.returncode == 0, done.stderr
    assert canonical.read_text() == "A=1\nB=2\n" and legacy.read_text() == "A=1\nB=2\n"
    assert "DEPLOY G2=unset G2F=unset" in done.stdout
    # The installer reads the same defaults and secrets files the block checked.
    assert f"DF={defaults} SF={secrets}" in done.stdout

    (check,) = [b for b in blocks if "verification_key_slots" in b]
    expression = check[check.index("jq -e '") + len("jq -e '"):check.rindex("'")]
    assert jq_ok(expression, {"ok": True, "verification_key_slots": ["g1", "g3"]})
    assert not jq_ok(expression, {"ok": True, "verification_key_slots": ["g1", "g2", "g3"]})
    assert not jq_ok(expression, {"ok": True, "verification_key_slots": ["g1"]})
