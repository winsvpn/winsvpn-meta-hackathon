#!/usr/bin/env python3
"""End-to-end proof that tools/winn3_sign_descriptor.py signs what the hub accepts.

THE ONLY QUESTION THIS FILE ANSWERS. A signing tool that produces a signature
the hub rejects is worse than no tool, because it burns a ceremony and the
operator has no way to tell a bad signature from a bad payload. So this suite
does not check the tool against its own idea of a signature: it generates a
THROWAWAY Ed25519 keypair with `openssl genpkey`, signs with the real tool as a
SUBPROCESS, stages the tool's own public output into the hub's environment, and
then pushes the envelope through the REAL `/admin/nodes/winn3/descriptor`
handler extracted from wins_control_plane_setup_ONETOUCH.sh. Same approach, and
the same reason, as test_winn3_descriptor_hub.py: a suite that signed with
anything else would be testing its own arithmetic.

NO REAL KEY IS EVER INVOLVED. Every key here is generated in a temporary
directory at run time and shredded at exit. The tool is never pointed at an
owner key by this file, and nothing here contacts a node, a hub, or the network.

Run:  python3 server/test_winn3_sign_descriptor_tool.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_winn3_descriptor_hub as descriptor_tests  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402

harness = descriptor_tests.harness

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(REPO_ROOT, "tools", "winn3_sign_descriptor.py")
HUB_SOURCE = os.path.join(
    REPO_ROOT, "server", "wins_control_plane_setup_ONETOUCH.sh")
ADMIN = descriptor_tests.ADMIN

# Documentation-range literals only (RFC 5737). No project address appears here.
GATEWAY_ENDPOINT = descriptor_tests.GATEWAY_ENDPOINT
NODE_ENDPOINT = descriptor_tests.NODE_ENDPOINT
INNER_ROUTER_V4 = descriptor_tests.INNER_ROUTER_V4
INNER_RESOLVER_V4 = descriptor_tests.INNER_RESOLVER_V4

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


# ======================= throwaway key material ===========================
#
# Generated here, used here, shredded at exit. `openssl genpkey` is the same
# generator the hub test suite uses and the same one the runbook tells the
# operator to type.

_KEYDIR = tempfile.mkdtemp(prefix="winn3-signtool-throwaway-")


def _generate_throwaway(name):
    key_path = os.path.join(_KEYDIR, f"{name}.pem")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", key_path],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.chmod(key_path, 0o600)
    return key_path


def _shred(directory):
    """Overwrite every byte before unlinking. Throwaway or not, a private key
    file is not left on disk for the filesystem to reclaim at its leisure."""
    for root, _dirs, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            try:
                size = os.path.getsize(path)
                with open(path, "r+b") as handle:
                    handle.write(os.urandom(size))
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                pass
    shutil.rmtree(directory, ignore_errors=True)


THROWAWAY_KEY = _generate_throwaway("g1")
OTHER_KEY = _generate_throwaway("g1-impostor")

# The admission secret in the shape keygen actually writes: 64 ASCII hex
# characters plus the trailing newline every consumer strips.
ADMISSION_FILE = os.path.join(_KEYDIR, "admission.key")
with open(ADMISSION_FILE, "w") as _handle:
    _handle.write("a1b2c3d4" * 8 + "\n")

STATIC_PUB_B64 = base64.b64encode(b"S" * 32).decode()


# ============================ tool invocation =============================
def run_tool(*argv, expect_ok=True):
    interpreter = getattr(sys, "_base_executable", None) or sys.executable
    completed = subprocess.run(
        [interpreter, TOOL, *argv],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    if expect_ok and completed.returncode != 0:
        raise AssertionError(
            f"tool exited {completed.returncode}\nSTDERR:\n{completed.stderr}")
    return completed


def sign_with_tool(*, key=None, node="lab-alpha", seq=1, prev_seq="none",
                   gen=1, ttl=86400, kid="g1", extra=()):
    completed = run_tool(
        "sign",
        "--key", key or THROWAWAY_KEY,
        "--node", node,
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", str(gen),
        "--seq", str(seq),
        "--prev-seq", str(prev_seq),
        "--kid", kid,
        "--ttl", str(ttl),
        "--json",
        *extra)
    return json.loads(completed.stdout)


def tool_public_key(key_path=None):
    completed = run_tool("pubkey", "--key", key_path or THROWAWAY_KEY, "--bare")
    return completed.stdout.strip()


# ============================== hub driving ===============================
def load_hub_with_tool_key(public_b64, **env):
    """A hub whose g1 slot holds the key the TOOL derived, and nothing else.

    g2 and g3 are actively cleared: os.environ is process-wide and a key left
    over from test_winn3_descriptor_hub's import-time fixtures would make a
    later assertion pass for the wrong reason.
    """
    for slot in ("g1", "g2", "g3"):
        os.environ.pop(f"WINN3_DESCRIPTOR_PUBKEY_{slot.upper()}", None)
    settings = {"WINN3_DESCRIPTOR_PUBKEY_G1": public_b64}
    settings.update({k: str(v) for k, v in env.items()})
    return harness.load_hub(**settings)


def post_descriptor(mod, **kwargs):
    kwargs.setdefault("x_admin_token", ADMIN)
    kwargs.setdefault(
        "request", FakeRequest(path="/admin/nodes/winn3/descriptor"))
    return mod.admin_set_node_winn3_descriptor(**kwargs)


def publish(mod, signed, slug="lab-alpha"):
    return post_descriptor(
        mod, slug=slug, enabled=True,
        descriptor_payload_b64=signed["descriptor_payload_b64"],
        descriptor_sig_b64=signed["descriptor_sig_b64"])


# ================================= tests ==================================
def test_tool_exists_and_is_executable():
    assert os.path.exists(TOOL), TOOL
    assert os.access(TOOL, os.X_OK), f"{TOOL} is not executable"


def test_pubkey_matches_openssl():
    """The tool's public half must equal what openssl says, byte for byte."""
    der = subprocess.run(
        ["openssl", "pkey", "-in", THROWAWAY_KEY, "-pubout", "-outform", "DER"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    expected = base64.b64encode(der[-32:]).decode()
    assert tool_public_key() == expected, "tool public half disagrees with openssl"
    assert len(base64.b64decode(expected, validate=True)) == 32


def test_pubkey_names_both_environment_variables():
    """The hub and the client read the SAME value under DIFFERENT names.

    Hub: WINN3_DESCRIPTOR_PUBKEY_G1. Client: WINS_WINN3_DESCRIPTOR_PUBKEY_G1.
    Staging one under the other's name is a silent no-op at both ends, so the
    tool must print both, correctly spelled.
    """
    out = run_tool("pubkey", "--key", THROWAWAY_KEY).stdout
    assert "WINN3_DESCRIPTOR_PUBKEY_G1=" in out
    assert "WINS_WINN3_DESCRIPTOR_PUBKEY_G1=" in out
    encoded = tool_public_key()
    assert out.count(encoded) == 2, "both lines must carry the same value"


def test_hub_accepts_a_descriptor_the_tool_signed():
    """THE LEAD QUESTION. Real tool, real openssl, the hub's real handler."""
    public_b64 = tool_public_key()
    signed = sign_with_tool(seq=1, prev_seq="none")
    mod = load_hub_with_tool_key(public_b64)
    descriptor_tests.seed_node(mod, slug="lab-alpha", endpoint=NODE_ENDPOINT)
    result = publish(mod, signed)
    assert result["ok"] is True, result
    assert result["accepted_key_slot"] == "g1", result
    assert result["descriptor"]["node"] == "lab-alpha", result
    assert result["descriptor"]["seq"] == 1, result
    assert result["requires_gateway_side_key_install"] is True, result
    # And the secret never came back as a value.
    assert "admission_secret" not in result["descriptor"], result
    assert result["descriptor"]["admission_secret_bytes"] == 64, result


def test_hub_verification_function_accepts_the_signature_directly():
    """The verification primitive itself, not just the endpoint around it."""
    public_b64 = tool_public_key()
    signed = sign_with_tool(seq=1, prev_seq="none")
    mod = load_hub_with_tool_key(public_b64)
    payload = base64.b64decode(signed["descriptor_payload_b64"], validate=True)
    signature = base64.b64decode(signed["descriptor_sig_b64"], validate=True)
    assert mod.winn3_verify_descriptor_signature(payload, signature, "g1") == "g1"


def test_hub_validates_the_payload_the_tool_builds():
    """Every field rule, run by the hub's own validator on the tool's bytes."""
    mod = load_hub_with_tool_key(tool_public_key())
    signed = sign_with_tool(seq=7, prev_seq=6)
    payload = json.loads(
        base64.b64decode(signed["descriptor_payload_b64"]).decode("utf-8"))
    normalized = mod.validate_winn3_descriptor_payload(payload, slug="lab-alpha")
    assert normalized["seq"] == 7
    assert normalized["v"] == mod.WINN3_DESCRIPTOR_FORMAT_VERSION
    assert set(payload) == set(mod.WINN3_DESCRIPTOR_REQUIRED_FIELDS)


def test_a_signature_from_a_different_key_is_refused():
    """A positive control proves the grep works; this proves the check works.

    Without it, every assertion above would still pass against a hub that
    accepted anything.
    """
    mod = load_hub_with_tool_key(tool_public_key())
    descriptor_tests.seed_node(mod, slug="lab-alpha", endpoint=NODE_ENDPOINT)
    impostor = sign_with_tool(key=OTHER_KEY, seq=1, prev_seq="none")
    try:
        publish(mod, impostor)
    except HTTPException as exc:
        assert exc.status_code == 400, exc.status_code
        assert "signature" in str(exc.detail).lower(), exc.detail
        return
    raise AssertionError("hub accepted a descriptor signed by the wrong key")


def test_tampering_with_one_payload_byte_breaks_the_signature():
    mod = load_hub_with_tool_key(tool_public_key())
    descriptor_tests.seed_node(mod, slug="lab-alpha", endpoint=NODE_ENDPOINT)
    signed = sign_with_tool(seq=1, prev_seq="none")
    payload = json.loads(
        base64.b64decode(signed["descriptor_payload_b64"]).decode("utf-8"))
    payload["seq"] = 99          # the field a replay would want to change
    tampered = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")
    try:
        post_descriptor(
            mod, slug="lab-alpha", enabled=True,
            descriptor_payload_b64=base64.b64encode(tampered).decode(),
            descriptor_sig_b64=signed["descriptor_sig_b64"])
    except HTTPException as exc:
        assert exc.status_code == 400, exc.status_code
        return
    raise AssertionError("hub accepted a payload that was edited after signing")


def test_domain_separation_is_the_hub_domain():
    """Re-derive the signed message independently and confirm the tool's bytes.

    The signature must verify over DOMAIN || 0x00 || payload and over nothing
    else -- a signature that also verified over the bare payload would mean the
    domain separator was not actually in the message.
    """
    public_raw = base64.b64decode(tool_public_key(), validate=True)
    signed = sign_with_tool(seq=1, prev_seq="none")
    payload = base64.b64decode(signed["descriptor_payload_b64"], validate=True)
    signature = base64.b64decode(signed["descriptor_sig_b64"], validate=True)

    def verify(message):
        with tempfile.TemporaryDirectory() as work:
            key_path = os.path.join(work, "k.der")
            msg_path = os.path.join(work, "m.bin")
            sig_path = os.path.join(work, "s.sig")
            with open(key_path, "wb") as handle:
                handle.write(bytes.fromhex("302a300506032b6570032100") + public_raw)
            with open(msg_path, "wb") as handle:
                handle.write(message)
            with open(sig_path, "wb") as handle:
                handle.write(signature)
            return subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                 "-inkey", key_path, "-keyform", "DER",
                 "-sigfile", sig_path, "-in", msg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    assert verify(b"winsvpn-winn3-descriptor/v1" + b"\x00" + payload)
    assert not verify(payload), "no domain separator in the signed message"
    assert not verify(b"winsvpn-announcement/v1" + b"\x00" + payload)


def test_client_and_hub_agree_on_the_domain_string():
    """Byte-for-byte, read out of both sources rather than asserted."""
    with open(HUB_SOURCE, "r", errors="replace") as handle:
        hub_src = handle.read()
    dart_path = os.path.join(REPO_ROOT, "lib", "winn_protocol_dispatch.dart")
    with open(dart_path, "r", errors="replace") as handle:
        dart_src = handle.read()
    assert 'WINN3_DESCRIPTOR_DOMAIN = b"winsvpn-winn3-descriptor/v1"' in hub_src
    assert "kWinn3DescriptorDomain = 'winsvpn-winn3-descriptor/v1'" in dart_src
    with open(TOOL, "r") as handle:
        tool_src = handle.read()
    assert 'DOMAIN = b"winsvpn-winn3-descriptor/v1"' in tool_src


def test_seq_must_strictly_increase_and_the_tool_refuses_first():
    """The rollback defence, checked in the tool BEFORE a signature exists.

    The hub enforces it too (409). The tool enforcing it as well is what stops a
    signature over a rollback-shaped payload from ever being produced -- once it
    exists, anyone who captures it can try it against any hub.
    """
    for seq, prev in ((3, 3), (2, 5), (0, 0)):
        completed = run_tool(
            "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
            "--endpoint", GATEWAY_ENDPOINT,
            "--inner-router-v4", INNER_ROUTER_V4,
            "--inner-resolver-v4", INNER_RESOLVER_V4,
            "--static-pub", STATIC_PUB_B64,
            "--gateway-id-text", "winsgw-fresh-01",
            "--admission-secret-file", ADMISSION_FILE,
            "--admission-gen", "1", "--seq", str(seq), "--prev-seq", str(prev),
            expect_ok=False)
        assert completed.returncode == 2, (seq, prev, completed.returncode)
        assert "strictly increase" in completed.stderr.lower(), completed.stderr
        assert "nothing was signed" in completed.stderr.lower(), completed.stderr
        assert not completed.stdout.strip(), "a refusal must emit no envelope"


def test_prev_seq_has_no_default():
    """Omitting --prev-seq must be an error, not a defaulted 0.

    A defaulted 0 would silently accept a re-upload against a node that already
    has a descriptor -- exactly the replay the field exists to stop.
    """
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1",
        expect_ok=False)
    assert completed.returncode != 0
    assert "prev-seq" in completed.stderr


def test_hub_rejects_a_non_increasing_seq_the_tool_was_lied_to_about():
    """Belt and braces: sign two envelopes honestly, replay the older one."""
    mod = load_hub_with_tool_key(tool_public_key())
    descriptor_tests.seed_node(mod, slug="lab-alpha", endpoint=NODE_ENDPOINT)
    first = sign_with_tool(seq=1, prev_seq="none")
    second = sign_with_tool(seq=2, prev_seq=1)
    assert publish(mod, first)["ok"] is True
    assert publish(mod, second)["ok"] is True
    try:
        publish(mod, first)          # the replay
    except HTTPException as exc:
        assert exc.status_code == 409, exc.status_code
        assert "strictly increase" in str(exc.detail)
        assert "No node record was changed" in str(exc.detail)
        return
    raise AssertionError("hub accepted a replayed earlier envelope")


def test_signing_is_deterministic():
    """Identical inputs must reproduce identical bytes.

    Ed25519 is deterministic and the payload serialisation is sorted and
    compact, so a re-run during an incident produces the same envelope rather
    than a second, differently-encoded one that also has to be reasoned about.
    """
    a = sign_with_tool(seq=4, prev_seq=3, extra=("--iat", "1786000000"))
    b = sign_with_tool(seq=4, prev_seq=3, extra=("--iat", "1786000000"))
    assert a["descriptor_payload_b64"] == b["descriptor_payload_b64"]
    assert a["descriptor_sig_b64"] == b["descriptor_sig_b64"]


def test_no_private_key_material_is_ever_emitted():
    """The root of trust must not appear in stdout, stderr, or any output file.

    Checked against the key's actual bytes in three encodings, not against a
    pattern that a reformat could slip past.
    """
    with open(THROWAWAY_KEY, "rb") as handle:
        pem = handle.read()
    body = b"".join(
        line for line in pem.splitlines() if not line.startswith(b"-----"))
    raw_der = base64.b64decode(body, validate=True)
    seed = raw_der[-32:]                       # the Ed25519 private seed
    needles = [
        pem.decode(),
        body.decode(),
        base64.b64encode(seed).decode(),
        seed.hex(),
    ]
    out_dir = os.path.join(_KEYDIR, "emitted")
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        "--out-dir", out_dir)
    blobs = [completed.stdout, completed.stderr]
    for name in sorted(os.listdir(out_dir)):
        path = os.path.join(out_dir, name)
        assert oct(os.stat(path).st_mode)[-3:] == "600", f"{name} is not 0600"
        with open(path, "r") as handle:
            blobs.append(handle.read())
    for blob in blobs:
        for needle in needles:
            assert needle not in blob, "private key material was emitted"


def test_no_temp_file_outlives_the_run():
    """The message handed to openssl carries the admission secret.

    It must live only inside a temporary directory that is gone when the
    process exits. Asserted by counting what the tool leaves behind in TMPDIR.
    """
    with tempfile.TemporaryDirectory(prefix="winn3-tmpwatch-") as watch:
        env = dict(os.environ, TMPDIR=watch)
        interpreter = getattr(sys, "_base_executable", None) or sys.executable
        completed = subprocess.run(
            [interpreter, TOOL, "sign",
             "--key", THROWAWAY_KEY, "--node", "lab-alpha",
             "--endpoint", GATEWAY_ENDPOINT,
             "--inner-router-v4", INNER_ROUTER_V4,
             "--inner-resolver-v4", INNER_RESOLVER_V4,
             "--static-pub", STATIC_PUB_B64,
             "--gateway-id-text", "winsgw-fresh-01",
             "--admission-secret-file", ADMISSION_FILE,
             "--admission-gen", "1", "--seq", "1", "--prev-seq", "none"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120)
        assert completed.returncode == 0, completed.stderr
        leftovers = os.listdir(watch)
        assert leftovers == [], f"tool left {leftovers} behind in TMPDIR"


def test_a_non_ed25519_key_is_refused_before_signing():
    """An RSA key would sign happily and produce something nothing can verify."""
    rsa_key = os.path.join(_KEYDIR, "rsa.pem")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
         "rsa_keygen_bits:2048", "-out", rsa_key],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    completed = run_tool(
        "pubkey", "--key", rsa_key, "--bare", expect_ok=False)
    assert completed.returncode == 2, completed.returncode
    assert "not Ed25519" in completed.stderr, completed.stderr


def test_gateway_id_double_encoding_must_be_stated_not_guessed():
    """Both forms at once, or neither, must be refused.

    The gateway id is an authenticated input to the admission tag and is never
    transmitted, so a double-encode is invisible to both ends. A tool that
    guessed which form it was handed would be re-creating that defect.
    """
    base = ["sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
            "--endpoint", GATEWAY_ENDPOINT,
            "--inner-router-v4", INNER_ROUTER_V4,
            "--inner-resolver-v4", INNER_RESOLVER_V4,
            "--static-pub", STATIC_PUB_B64,
            "--admission-secret-file", ADMISSION_FILE,
            "--admission-gen", "1", "--seq", "1", "--prev-seq", "none"]
    both = run_tool(*base, "--gateway-id-text", "winsgw-fresh-01",
                    "--gateway-id-b64", base64.b64encode(b"x").decode(),
                    expect_ok=False)
    assert both.returncode == 2, both.returncode
    neither = run_tool(*base, expect_ok=False)
    assert neither.returncode == 2, neither.returncode


def test_edge_whitespace_in_the_gateway_id_is_refused():
    """Trap 3: one trailing space keys 9 bytes on iOS and 8 on Android."""
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01 ",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        expect_ok=False)
    assert completed.returncode == 2
    assert "edge-whitespace" in completed.stderr, completed.stderr


def test_admission_secret_file_bytes_are_used_verbatim():
    """Trap 2: the secret is OPAQUE BYTES and nothing may hex-decode it.

    keygen writes 64 hex characters; the descriptor field must be base64 of
    those 64 ASCII bytes, not of the 32 bytes they spell.
    """
    signed = sign_with_tool(seq=1, prev_seq="none")
    payload = json.loads(
        base64.b64decode(signed["descriptor_payload_b64"]).decode("utf-8"))
    raw = base64.b64decode(payload["admission_secret"], validate=True)
    assert len(raw) == 64, f"expected the 64 ASCII hex bytes, got {len(raw)}"
    assert raw == b"a1b2c3d4" * 8
    assert raw != bytes.fromhex("a1b2c3d4" * 8), "the secret was hex-decoded"


def test_a_32_byte_admission_secret_is_refused():
    """A hex-decoded shipping secret cannot be signed into a descriptor."""
    thirty_two = os.path.join(_KEYDIR, "admission32.key")
    with open(thirty_two, "wb") as handle:
        handle.write(bytes(range(32)))
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", thirty_two,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        expect_ok=False)
    assert completed.returncode != 0
    assert "admission-secret-noncanonical" in completed.stderr, completed.stderr


def test_hub_refuses_a_node_mismatch_the_tool_signed_honestly():
    """`node` is inside the signed bytes. A descriptor for A must not install
    on B, or every client of B seals initiations only A can open -- silently."""
    mod = load_hub_with_tool_key(tool_public_key())
    descriptor_tests.seed_node(mod, slug="lab-alpha", endpoint=NODE_ENDPOINT)
    signed = sign_with_tool(node="lab-beta", seq=1, prev_seq="none")
    try:
        publish(mod, signed, slug="lab-alpha")
    except HTTPException as exc:
        assert exc.status_code == 400, exc.status_code
        assert "node-mismatch" in str(exc.detail), exc.detail
        return
    raise AssertionError("hub accepted a descriptor naming another node")


def test_constants_do_not_drift_from_the_hub():
    """A hand-maintained second copy that silently disagrees with the
    implementation is a failure this project has already had. Every constant the
    tool enforces is read back out of the hub source and compared."""
    mod = load_hub_with_tool_key(tool_public_key())
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    import winn3_sign_descriptor as tool  # noqa: E402

    pairs = [
        ("DOMAIN", tool.DOMAIN, mod.WINN3_DESCRIPTOR_DOMAIN),
        ("FORMAT_VERSION", tool.FORMAT_VERSION,
         mod.WINN3_DESCRIPTOR_FORMAT_VERSION),
        ("KEY_SLOTS", tool.KEY_SLOTS, mod.WINN3_DESCRIPTOR_KEY_SLOTS),
        ("SUPPORTED_ALGS", tool.SUPPORTED_ALGS,
         mod.WINN3_DESCRIPTOR_SUPPORTED_ALGS),
        ("SPKI_PREFIX", tool.ED25519_SPKI_PREFIX, mod.WINN3_ED25519_SPKI_PREFIX),
        ("PUBLIC_KEY_BYTES", tool.ED25519_PUBLIC_KEY_BYTES,
         mod.WINN3_ED25519_PUBLIC_KEY_BYTES),
        ("SIGNATURE_BYTES", tool.ED25519_SIGNATURE_BYTES,
         mod.WINN3_ED25519_SIGNATURE_BYTES),
        ("REQUIRED_FIELDS", tool.REQUIRED_FIELDS,
         mod.WINN3_DESCRIPTOR_REQUIRED_FIELDS),
        ("PLAIN_IPV4_FIELDS", tool.PLAIN_IPV4_FIELDS,
         mod.WINN3_DESCRIPTOR_PLAIN_IPV4_FIELDS),
        ("SECRET_FIELDS", tool.SECRET_FIELDS, mod.WINN3_DESCRIPTOR_SECRET_FIELDS),
        ("MIN_TAG_SIZE", tool.MIN_TAG_SIZE, mod.WINN3_MIN_TAG_SIZE),
        ("MAX_TAG_SIZE", tool.MAX_TAG_SIZE, mod.WINN3_MAX_TAG_SIZE),
        ("MIN_ADMISSION_SECRET_BYTES", tool.MIN_ADMISSION_SECRET_BYTES,
         mod.WINN3_MIN_ADMISSION_SECRET_BYTES),
        ("STATIC_PUBLIC_KEY_BYTES", tool.STATIC_PUBLIC_KEY_BYTES,
         mod.WINN3_STATIC_PUBLIC_KEY_BYTES),
        ("MIN_GATEWAY_ID_BYTES", tool.MIN_GATEWAY_ID_BYTES,
         mod.WINN3_MIN_GATEWAY_ID_BYTES),
        ("MAX_GATEWAY_ID_BYTES", tool.MAX_GATEWAY_ID_BYTES,
         mod.WINN3_MAX_GATEWAY_ID_BYTES),
        ("PADDING_POLICIES", tool.PADDING_POLICIES, mod.WINN3_PADDING_POLICIES),
        ("MAX_LIVE_ADMISSION_KEYS", tool.MAX_LIVE_ADMISSION_KEYS,
         mod.WINN3_MAX_LIVE_ADMISSION_KEYS),
        ("MAX_ADMISSION_HMAC_BUDGET", tool.MAX_ADMISSION_HMAC_BUDGET,
         mod.WINN3_MAX_ADMISSION_HMAC_BUDGET),
        ("MIN_DESCRIPTOR_TTL_SECONDS", tool.MIN_DESCRIPTOR_TTL_SECONDS,
         mod.WINN3_MIN_DESCRIPTOR_TTL_SECONDS),
        ("MAX_DESCRIPTOR_TTL_SECONDS", tool.MAX_DESCRIPTOR_TTL_SECONDS,
         mod.WINN3_MAX_DESCRIPTOR_TTL_SECONDS),
        ("MAX_DESCRIPTOR_BYTES", tool.MAX_DESCRIPTOR_BYTES,
         mod.WINN3_MAX_DESCRIPTOR_BYTES),
        ("MAX_BUCKET_CANDIDATES", tool.MAX_BUCKET_CANDIDATES,
         mod.WINN3_MAX_BUCKET_CANDIDATES),
    ]
    drifted = []
    for name, mine, theirs in pairs:
        if isinstance(mine, (tuple, list)):
            same = tuple(mine) == tuple(theirs)
        else:
            same = mine == theirs
        if not same:
            drifted.append(name)
    assert len(pairs) == 23, f"expected 23 pinned constants, pinned {len(pairs)}"
    assert not drifted, f"tool constants drifted from the hub: {drifted}"


def test_edge_whitespace_matches_the_hub_byte_for_byte():
    """The tool must be neither looser NOR stricter than the hub here.

    `bytes.isspace()` is ASCII-only; `str.strip()` also eats \\x1c-\\x1f and a
    pile of Unicode separators. A tool built on the str form refuses gateway ids
    the hub accepts, which on a deadline reads as a broken tool.
    """
    mod = load_hub_with_tool_key(tool_public_key())
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    import winn3_sign_descriptor as tool  # noqa: E402
    probes = [
        b"", b"winsgw-fresh-01", b" winsgw", b"winsgw ", b"\twinsgw",
        b"winsgw\n", b"winsgw\r", b"winsgw\x0b", b"winsgw\x0c",
        b"\x1fwinsgw", b"winsgw\x1f", b"\x00winsgw", b"winsgw\x00",
        bytes(range(32)), b"\xc2\xa0winsgw", b"winsgw\xc2\xa0",
        b"\xff\xfe", b"win sgw",
    ]
    disagreements = [
        probe for probe in probes
        if tool.operator_text_has_edge_whitespace(probe)
        != mod.winn3_operator_text_has_edge_whitespace(probe)
    ]
    assert not disagreements, (
        f"{len(disagreements)} probes where the tool and the hub disagree")


def test_freshness_geometry_matches_the_hub():
    mod = load_hub_with_tool_key(tool_public_key())
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    import winn3_sign_descriptor as tool  # noqa: E402
    for window, skew in ((10, 60), (10, 10), (5, 30), (30, 300), (1, 1)):
        assert tool.freshness_geometry(window, skew) == \
            mod.winn3_freshness_geometry(window, skew), (window, skew)


def test_rotation_budget_refusal_matches_the_hub():
    """A window/skew product over budget must be refused locally too."""
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        "--bucket-window-s", "10", "--max-skew-s", "3600",
        expect_ok=False)
    assert completed.returncode == 2
    assert "rotation-budget" in completed.stderr, completed.stderr


def test_ttl_bounds_are_enforced_locally():
    for ttl, needle in ((60, "ttl-too-short"), (40 * 24 * 3600, "ttl-too-long")):
        completed = run_tool(
            "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
            "--endpoint", GATEWAY_ENDPOINT,
            "--inner-router-v4", INNER_ROUTER_V4,
            "--inner-resolver-v4", INNER_RESOLVER_V4,
            "--static-pub", STATIC_PUB_B64,
            "--gateway-id-text", "winsgw-fresh-01",
            "--admission-secret-file", ADMISSION_FILE,
            "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
            "--ttl", str(ttl), expect_ok=False)
        assert completed.returncode == 2, ttl
        assert needle in completed.stderr, completed.stderr


def test_hostname_endpoint_is_refused():
    """A hostname would be resolved outside the tunnel. Refused locally, as the
    hub and both clients refuse it."""
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", "gateway.example.test:51820",
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", INNER_RESOLVER_V4,
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        expect_ok=False)
    assert completed.returncode == 2
    assert "endpoint-not-ip-literal" in completed.stderr, completed.stderr


def test_distinct_resolver_address_is_refused_locally():
    completed = run_tool(
        "sign", "--key", THROWAWAY_KEY, "--node", "lab-alpha",
        "--endpoint", GATEWAY_ENDPOINT,
        "--inner-router-v4", INNER_ROUTER_V4,
        "--inner-resolver-v4", "10.10.0.2",
        "--static-pub", STATIC_PUB_B64,
        "--gateway-id-text", "winsgw-fresh-01",
        "--admission-secret-file", ADMISSION_FILE,
        "--admission-gen", "1", "--seq", "1", "--prev-seq", "none",
        expect_ok=False,
    )
    assert completed.returncode == 2
    assert "resolver-does-not-match-gateway-bind" in completed.stderr


def test_the_shipped_dart_client_pins_the_same_format_version_as_the_hub():
    """Drift check: the Dart constant and the hub constant must be the same int.

    `v` is a field-set name, not a cosmetic tag. The hub validates against
    WINN3_DESCRIPTOR_FORMAT_VERSION and the client against
    kWinn3DescriptorFormatVersion; if they disagree, every descriptor the hub
    accepts is refused by the client (or the reverse). Parsing the integer out
    of the Dart source and comparing it to the loaded hub module catches drift
    in either direction, including a future bump that touches only one side.
    """
    dart_path = os.path.join(REPO_ROOT, "lib", "winn_protocol_dispatch.dart")
    with open(dart_path, "r", errors="replace") as handle:
        dart_src = handle.read()
    matches = re.findall(
        r"^const int kWinn3DescriptorFormatVersion = (\d+);$",
        dart_src,
        re.M,
    )
    assert len(matches) == 1, (
        "expected exactly one Dart format-version constant, got %r" % (matches,)
    )
    client_v = int(matches[0])
    mod = load_hub_with_tool_key(tool_public_key())
    assert client_v == mod.WINN3_DESCRIPTOR_FORMAT_VERSION, (
        "Dart kWinn3DescriptorFormatVersion=%s drifted from hub "
        "WINN3_DESCRIPTOR_FORMAT_VERSION=%s"
        % (client_v, mod.WINN3_DESCRIPTOR_FORMAT_VERSION)
    )


def main():
    print("winn/3 descriptor signing tool -- end-to-end against the real hub")
    print(f"  tool: {TOOL}")
    print(f"  throwaway keys in {_KEYDIR} (shredded at exit)")
    print()
    tests = [
        ("tool_exists_and_is_executable", test_tool_exists_and_is_executable),
        ("pubkey_matches_openssl", test_pubkey_matches_openssl),
        ("pubkey_names_both_environment_variables",
         test_pubkey_names_both_environment_variables),
        ("HUB_ACCEPTS_A_DESCRIPTOR_THE_TOOL_SIGNED",
         test_hub_accepts_a_descriptor_the_tool_signed),
        ("hub_verification_function_accepts_the_signature_directly",
         test_hub_verification_function_accepts_the_signature_directly),
        ("hub_validates_the_payload_the_tool_builds",
         test_hub_validates_the_payload_the_tool_builds),
        ("a_signature_from_a_different_key_is_refused",
         test_a_signature_from_a_different_key_is_refused),
        ("tampering_with_one_payload_byte_breaks_the_signature",
         test_tampering_with_one_payload_byte_breaks_the_signature),
        ("domain_separation_is_the_hub_domain",
         test_domain_separation_is_the_hub_domain),
        ("client_and_hub_agree_on_the_domain_string",
         test_client_and_hub_agree_on_the_domain_string),
        ("seq_must_strictly_increase_and_the_tool_refuses_first",
         test_seq_must_strictly_increase_and_the_tool_refuses_first),
        ("prev_seq_has_no_default", test_prev_seq_has_no_default),
        ("hub_rejects_a_non_increasing_seq",
         test_hub_rejects_a_non_increasing_seq_the_tool_was_lied_to_about),
        ("signing_is_deterministic", test_signing_is_deterministic),
        ("no_private_key_material_is_ever_emitted",
         test_no_private_key_material_is_ever_emitted),
        ("no_temp_file_outlives_the_run", test_no_temp_file_outlives_the_run),
        ("a_non_ed25519_key_is_refused_before_signing",
         test_a_non_ed25519_key_is_refused_before_signing),
        ("gateway_id_double_encoding_must_be_stated_not_guessed",
         test_gateway_id_double_encoding_must_be_stated_not_guessed),
        ("edge_whitespace_in_the_gateway_id_is_refused",
         test_edge_whitespace_in_the_gateway_id_is_refused),
        ("admission_secret_file_bytes_are_used_verbatim",
         test_admission_secret_file_bytes_are_used_verbatim),
        ("a_32_byte_admission_secret_is_refused",
         test_a_32_byte_admission_secret_is_refused),
        ("hub_refuses_a_node_mismatch",
         test_hub_refuses_a_node_mismatch_the_tool_signed_honestly),
        ("constants_do_not_drift_from_the_hub",
         test_constants_do_not_drift_from_the_hub),
        ("edge_whitespace_matches_the_hub_byte_for_byte",
         test_edge_whitespace_matches_the_hub_byte_for_byte),
        ("freshness_geometry_matches_the_hub",
         test_freshness_geometry_matches_the_hub),
        ("rotation_budget_refusal_matches_the_hub",
         test_rotation_budget_refusal_matches_the_hub),
        ("ttl_bounds_are_enforced_locally", test_ttl_bounds_are_enforced_locally),
        ("hostname_endpoint_is_refused", test_hostname_endpoint_is_refused),
        ("distinct_resolver_address_is_refused_locally",
         test_distinct_resolver_address_is_refused_locally),
        ("dart_client_pins_the_same_format_version_as_the_hub",
         test_the_shipped_dart_client_pins_the_same_format_version_as_the_hub),
    ]
    for name, fn in tests:
        check(name, fn)

    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, detail in FAILURES:
        print(f"\n--- {name} ---\n{detail}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    try:
        code = main()
    finally:
        _shred(_KEYDIR)
        print(f"throwaway keys shredded: {not os.path.exists(_KEYDIR)}")
    sys.exit(code)
