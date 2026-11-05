#!/usr/bin/env python3
"""Static release gate for the Win's VPN one-touch deployment scripts."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from winn3_gateway_block import tombstone_problems  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "control": ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh",
    "data": ROOT / "server" / "wins_data_plane_setup_ONETOUCH.sh",
    "core": ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh",
}
DEFAULTS_TEMPLATE = ROOT / ".env.example"
GATEWAY_SCRIPT = ROOT / "server" / "wins_winn3_gateway_install.sh"
AWG_SERVER_IMAGE_BUILDER = ROOT / "server" / "build_amneziawg_go_server_image.sh"
AWG_SERVER_IMAGE_INSTALLERS = {
    "core": SCRIPTS["core"],
    "data": SCRIPTS["data"],
}
CLOUDFLARED_SECURITY_PATCH = ROOT / "server/vendor/cloudflared-2026.10.0-security.patch"
CLOUDFLARED_SECURITY_PATCH_SHA256 = (
    "8ec5ecde3a9ded36d10800b9cc0457264a7aee7e083e5eaf7e4cba76dcf8493d"
)
CLOUDFLARED_SECURITY_REVIEW = ROOT / "server/vendor/cloudflared-2026.10.0-security-review.md"
CLOUDFLARED_SECURITY_REVIEW_SHA256 = (
    "4cd9ddd0cb26a8d3e9a2e6e1d601e9b9973fb7989794b059a498946fd0c376d6"
)
HONEYNET_SCRIPT = ROOT / "server" / "wins_honeynet_setup_ONETOUCH.sh"
COWRIE_HONEYPOT_SCRIPT = ROOT / "server" / "wins_cowrie_honeypot_ONETOUCH.sh"
RECOVERY_SCRIPTS = {
    "home Core": ROOT / "tools" / "recover_home_core_ssh.sh",
    "IONOS hub": ROOT / "tools" / "recover_ionos_hub_ssh.sh",
}
CLIENT_XRAY_SOURCES = {
    "android": ROOT / "android" / "app" / "src" / "main" / "kotlin" / "org" / "winsvpn" / "app" / "VpnTunnelService.kt",
    "apple": ROOT / "apple" / "EngineWrappers" / "WinsXrayVlessWsTransport.m",
    "windows": ROOT / "windows" / "runner" / "windows_tunnel_backend.cpp",
    "linux": ROOT / "linux" / "runner" / "linux_tunnel_backend.cc",
}

FORBIDDEN_STATIC_DEPLOYMENT_VALUE_SHA256 = (
    "25bd41a0002745cd80aab7c3491c0f790dc452c777051af50d9384f62cc50944",
    "afddc2f010acc36090f59f662782757f92d86637babf8408f0edbb54cb2fa6df",
    "23831fc53e6e055ef78162b50397fa9b489d53531cc693efa47860b130065897",
    "93e4e143ac997ca0580327e1c12d490468871ff08ff5c6e0fb03efe417b36439",
    "d74645e2f8d02c0a47a354ac68ec45a84ef77127e4af863f1797f1e278077daa",
    "5076e240220369979102f4b86e4bcf405b3ed92756ed7a4a594fb1fa27b20f1d",
    "a60e8d3d59358fe3d72735e912936d0829848d4f1d8fd082ac2daebad37866ab",
    "772d8aa629f3a9537db6d500f14ac42838f2eef9b5a40c075e013fa89d15bbfe",
    "57b69c0cc6d698393b2c758f44c4a5f8c0bd1f382bf9575d31f5e0a379f57150",
    "3058b98508b6b03c621fdac601919ac7bef6df154861ad6800a7b81f418e9471",
    "0fe49feeb5e3fcae4b9c9e04d62c5e8b84aa7e1e76702b3baff451794bd22926",
    "4990dc5c489a25f1917282b881fd197e6a6d06f27935dac8e7caa143f3ad47e3",
    "0e538368ac6a1ee2f8ed563824766e323c3676196d8841f8f8c5acb5e1b8e395",
    "155cb10649ed867dcd222b3b5452657e1ad07f35c4dc8ae945fe15d38cab42d5",
    "7bf1edfdde055cdd62710aedb80b4a722aed872b5a56a04e0f947be89c785876",
)
FORBIDDEN_RECOVERY_ADDRESS_SHA256 = {
    "retired_samsung_host": "4955ccdd662df16bb41006fbdae11a18c0860f5cde162535caa73c802901b8a0",
    "retired_admin_address": "155cb10649ed867dcd222b3b5452657e1ad07f35c4dc8ae945fe15d38cab42d5",
    "operator_address_1": "0e538368ac6a1ee2f8ed563824766e323c3676196d8841f8f8c5acb5e1b8e395",
    "operator_address_2": "7bf1edfdde055cdd62710aedb80b4a722aed872b5a56a04e0f947be89c785876",
}
DEPLOYMENT_VALUE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@%-]{7,}")
IPV4_TOKEN_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


@dataclass(frozen=True)
class Heredoc:
    line: int
    header: str
    body: str


def fail(message: str) -> None:
    raise SystemExit(f"deployment validation failed: {message}")


def token_sha256s(source: str, pattern: re.Pattern[str]) -> set[str]:
    """Hash complete source tokens so retired private values stay out of Git."""
    return {
        hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()
        for match in pattern.finditer(source)
    }


def parse_heredocs(path: Path) -> list[Heredoc]:
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[Heredoc] = []
    index = 0
    while index < len(lines):
        match = re.search(
            r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", lines[index]
        )
        if not match:
            index += 1
            continue
        tag = match.group(1)
        end = index + 1
        while end < len(lines) and lines[end].lstrip("\t") != tag:
            end += 1
        if end >= len(lines):
            fail(f"{path.name}:{index + 1} has an unterminated {tag} heredoc")
        blocks.append(
            Heredoc(
                line=index + 1,
                header=lines[index],
                body="\n".join(lines[index + 1 : end]) + "\n",
            )
        )
        index = end + 1
    return blocks


def validate_embedded_programs(path: Path, blocks: list[Heredoc]) -> None:
    for block in blocks:
        label = f"{path.name}:{block.line}"
        first = block.body.splitlines()[0].strip() if block.body else ""
        if "python3" in block.header or first.startswith("#!/usr/bin/env python"):
            try:
                compile(block.body, label, "exec")
            except SyntaxError as exc:
                fail(f"{label} embedded Python does not compile: {exc}")
            tree = ast.parse(block.body, filename=label)
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in {"execute", "executemany"}
                    and len(node.args) >= 2
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and isinstance(node.args[1], ast.Tuple)
                ):
                    continue
                placeholders = node.args[0].value.count("?")
                arguments = len(node.args[1].elts)
                if placeholders != arguments:
                    fail(
                        f"{label}:{node.lineno} static SQL has {placeholders} "
                        f"placeholders but {arguments} tuple arguments"
                    )
        if first in {"#!/usr/bin/env bash", "#!/bin/bash"}:
            result = subprocess.run(
                ["bash", "-n"],
                input=block.body.encode("utf-8"),
                capture_output=True,
                check=False,
            )
            if result.returncode:
                stderr = result.stderr.decode("utf-8", errors="replace").strip()
                fail(f"{label} embedded Bash does not parse: {stderr}")
        if "config.json" in block.header:
            representative = re.sub(r"\$\{[^}]+}", "10085", block.body)
            try:
                json.loads(representative)
            except json.JSONDecodeError as exc:
                fail(f"{label} generated JSON is malformed: {exc}")
        if "/etc/systemd/system/" in block.header:
            is_drop_in = ".service.d/" in block.header
            is_service = ".service " in block.header or ".service <<" in block.header
            is_timer = ".timer " in block.header or ".timer <<" in block.header
            if not is_drop_in and "[Unit]" not in block.body:
                fail(f"{label} generated systemd unit has no [Unit] section")
            if is_service and (
                "[Service]" not in block.body or "ExecStart=" not in block.body
            ):
                fail(f"{label} generated service lacks [Service]/ExecStart")
            if is_timer and "[Timer]" not in block.body:
                fail(f"{label} generated timer lacks [Timer]")
            if is_drop_in and "[Service]" not in block.body:
                fail(f"{label} generated service drop-in lacks [Service]")
        if "sites-available/" in block.header:
            if block.body.count("{") != block.body.count("}"):
                fail(f"{label} generated Nginx braces are unbalanced")
            has_listener = "listen " in block.body or "${listen_" in block.body
            if "server {" not in block.body or not has_listener:
                fail(f"{label} generated Nginx server is incomplete")


def function_body(source: str, name: str) -> str:
    declarations = list(
        re.finditer(rf"^{re.escape(name)}\(\) \{{\s*$", source, re.MULTILINE)
    )
    if not declarations:
        fail(f"missing function {name}")
    declaration = declarations[-1]
    body_start = declaration.end()
    next_function = re.search(
        r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{\s*$",
        source[body_start:],
        re.MULTILINE,
    )
    body_end = body_start + next_function.start() if next_function else len(source)
    return source[body_start:body_end]


def function_bodies(source: str, name: str) -> list[str]:
    """Return every shell function body, including generated helper copies."""
    declarations = list(
        re.finditer(rf"^{re.escape(name)}\(\) \{{\s*$", source, re.MULTILINE)
    )
    if not declarations:
        fail(f"missing function {name}")
    bodies: list[str] = []
    for declaration in declarations:
        body_start = declaration.end()
        next_function = re.search(
            r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{\s*$",
            source[body_start:],
            re.MULTILINE,
        )
        body_end = body_start + next_function.start() if next_function else len(source)
        bodies.append(source[body_start:body_end])
    return bodies


def shell_assignment_values(source: str, name: str) -> list[str]:
    """Read quoted shell assignments without evaluating deployment code."""
    matches = re.findall(
        rf'^{re.escape(name)}="([^"\n]*)"\s*$', source, re.MULTILINE
    )
    if not matches:
        fail(f"missing quoted assignment {name}")
    return matches


def require_shell_assignment(
    source: str, name: str, expected: str, label: str
) -> None:
    values = shell_assignment_values(source, name)
    if any(value != expected for value in values):
        fail(f"{label} {name} must be {expected!r}")


def validate_awg_31_server_image_contract(
    builder: str | None = None,
    installers: dict[str, str] | None = None,
) -> None:
    """Keep AWG 3.1 deployment tied to the verified local image producer.

    A tag is normally mutable registry state. Here it is only a local image
    name: every installer verifies the staged producer by SHA-256, and that
    producer verifies local labels, runtime hashes, and an exact provenance
    receipt before returning the name. Do not replace this with docker pull.
    """
    builder = (
        AWG_SERVER_IMAGE_BUILDER.read_text(encoding="utf-8")
        if builder is None
        else builder
    )
    installers = (
        {
            name: path.read_text(encoding="utf-8")
            for name, path in AWG_SERVER_IMAGE_INSTALLERS.items()
        }
        if installers is None
        else installers
    )
    if set(installers) != {"core", "data"}:
        fail("AWG server image validation requires exactly the core and data installers")

    pins = {
        "AWG_GO_REPOSITORY": "https://github.com/amnezia-vpn/amneziawg-go",
        "AWG_TOOLS_REPOSITORY": "https://github.com/amnezia-vpn/amneziawg-tools",
        "GO_MODULE_PROXY": "https://proxy.golang.org",
        "GO_MODULE_SUMDB": "sum.golang.org",
    }
    for name, expected in pins.items():
        require_shell_assignment(builder, name, expected, "AWG image builder")

    tag = shell_assignment_values(builder, "AWG_GO_TAG")
    if len(set(tag)) != 1 or not re.fullmatch(r"v3\.1\.\d{8}", tag[0]):
        fail("AWG image builder must pin one AWG 3.1 release tag")
    tools_tag = shell_assignment_values(builder, "AWG_TOOLS_TAG")
    if len(set(tools_tag)) != 1 or not re.fullmatch(r"v3\.1\.\d{8}", tools_tag[0]):
        fail("AWG image builder must pin one AWG tools 3.1 release tag")
    image = shell_assignment_values(builder, "AWG_SERVER_IMAGE")
    expected_image = f"amneziavpn/amneziawg-go:{tag[0]}"
    if image != [expected_image]:
        fail("AWG image builder local image name must match the pinned AWG tag")

    for name in (
        "AWG_GO_COMMIT",
        "AWG_GO_SOURCE_SHA256",
        "AWG_GO_BINARY_SHA256_AMD64",
        "AWG_GO_BINARY_SHA256_ARM64",
        "AWG_TOOLS_COMMIT",
        "AWG_TOOLS_SOURCE_SHA256",
        "AWG_QUICK_SHA256",
        "GO_ARCHIVE_SHA256_AMD64",
        "GO_ARCHIVE_SHA256_ARM64",
    ):
        value = shell_assignment_values(builder, name)
        if len(value) != 1 or not re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{40}", value[0]):
            fail(f"AWG image builder {name} must be one immutable hexadecimal pin")
    for name in ("AWG_GO_COMMIT", "AWG_TOOLS_COMMIT"):
        if len(shell_assignment_values(builder, name)[0]) != 40:
            fail(f"AWG image builder {name} must be a full commit hash")

    for forbidden in ("docker pull", "docker push", "docker login"):
        if forbidden in builder:
            fail(f"AWG image builder must not use {forbidden}")
    for guard in (
        "download_exact() {",
        "sha256_file",
        'docker build --pull=false --no-cache --network default',
        "verify_image_labels",
        "verify_image_runtime",
        "verify_receipt",
        "write_receipt",
        "--pull=never --network none",
        "org.opencontainers.image.source",
        "org.opencontainers.image.version",
        "org.opencontainers.image.revision",
        "com.winsvpn.awg.source.sha256",
        "com.winsvpn.awg.tools.commit",
        "com.winsvpn.awg.go.archive.sha256",
        '[[ -f "${AWG_IMAGE_PROVENANCE_FILE}" && ! -L "${AWG_IMAGE_PROVENANCE_FILE}" ]]',
        "if data != expected:",
        'die "Local image provenance receipt is missing or inconsistent."',
        "verify) verify_all ;;",
        "if verify_all >/dev/null 2>&1; then",
    ):
        if guard not in builder:
            fail(f"AWG image builder lost fail-closed guard: {guard.strip()}")

    producer_sha = hashlib.sha256(builder.encode("utf-8")).hexdigest()
    installer_specs = {
        "core": ("AWG_DOCKER_IMAGE", ("--ensure", "--verify")),
        "data": ("AWG_DOCKER_IMAGE_DEFAULT", ("--ensure",)),
    }
    for name, source in installers.items():
        image_variable, expected_modes = installer_specs[name]
        require_shell_assignment(source, image_variable, expected_image, f"{name} installer")
        require_shell_assignment(
            source,
            "AWG_SERVER_IMAGE_PRODUCER_SHA256",
            producer_sha,
            f"{name} installer",
        )
        if "AWG_DOCKER_IMAGES" in source:
            fail(f"{name} installer must not retain an overridable AWG image list")

        selectors = function_bodies(source, "select_awg_image")
        modes: list[str] = []
        for selector in selectors:
            mode_match = re.search(
                r'image="\$\(bash "\$\{(?:producer|AWG_SERVER_IMAGE_PRODUCER)\}" (--ensure|--verify)\)"',
                selector,
            )
            if not mode_match:
                fail(f"{name} AWG selector must invoke the pinned producer")
            mode = mode_match.group(1)
            for guard in (f'[[ "${{image}}" == "${{{image_variable}}}" ]]',):
                if guard not in selector:
                    fail(f"{name} AWG selector lost fail-closed guard: {guard}")
            if mode == "--ensure":
                for guard in (
                    '[[ -f "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" && ! -L "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" ]]',
                    'source_sha="$(sha256sum "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" | awk \'{print $1}\')"',
                    '[[ "${source_sha}" == "${AWG_SERVER_IMAGE_PRODUCER_SHA256}" ]]',
                    'install -D -m 0755 "${AWG_SERVER_IMAGE_PRODUCER_SOURCE}" "${producer}"',
                ):
                    if guard not in selector:
                        fail(
                            f"{name} AWG source-staging guard is missing: {guard}"
                        )
                installed_file = '[[ -f "${producer}" && ! -L "${producer}" ]]'
                installed_hash = 'installed_sha="$(sha256sum "${producer}" | awk \'{print $1}\')"'
            else:
                installed_file = '[[ -f "${AWG_SERVER_IMAGE_PRODUCER}" && ! -L "${AWG_SERVER_IMAGE_PRODUCER}" ]]'
                installed_hash = 'producer_sha="$(sha256sum "${AWG_SERVER_IMAGE_PRODUCER}" | awk \'{print $1}\')"'
            for guard in (
                installed_file,
                installed_hash,
                '[[ "${producer_sha}" == "${AWG_SERVER_IMAGE_PRODUCER_SHA256}" ]]'
                if mode == "--verify"
                else '[[ "${installed_sha}" == "${AWG_SERVER_IMAGE_PRODUCER_SHA256}" ]]',
            ):
                if guard not in selector:
                    fail(f"{name} AWG installed-producer guard is missing: {guard}")
            if "docker pull" in selector or "docker push" in selector:
                fail(f"{name} AWG selector must not mutate or pull from a registry")
            modes.append(mode)
        if tuple(modes) != expected_modes:
            fail(f"{name} AWG selectors must use producer modes {expected_modes}")


OS_GATE_NAMED_26 = (
    "Ubuntu 26.04 is not a supported production host. The control-plane "
    "pip-compile lock was generated with Python 3.12 and pins C-extension "
    "per-CPython wheels"
)
OS_GATE_GENERIC = "Supported production host is Ubuntu 24.04; detected"
OS_GATE_ACCEPT_24 = 'os_id}" == "ubuntu" && "${os_version}" == "24.04"'
OS_GATE_REFUSE_26 = 'os_id}" == "ubuntu" && "${os_version}" == "26.04"'
OS_GATE_OLD_COMBINED = (
    'ALLOW_UNSUPPORTED_OS:-0}" != "1" && ( "${os_id}" != "ubuntu" '
    '|| "${os_version}" != "24.04" )'
)
OS_GATE_PREFLIGHT = {
    "control": "preflight_control",
    "data": "preflight_data_plane",
    "core": "preflight_core",
}


def validate_require_supported_production_os(label: str, source: str, caller: str) -> None:
    """Lock the shared Ubuntu 24.04 / named-26.04 OS gate. Do not widen."""
    gate = function_body(source, "require_supported_production_os")
    for required in (
        OS_GATE_NAMED_26,
        OS_GATE_GENERIC,
        OS_GATE_ACCEPT_24,
        OS_GATE_REFUSE_26,
        'ALLOW_UNSUPPORTED_OS:-0}" == "1"',
        "exit 1",
    ):
        if required not in gate:
            fail(f"{label} OS gate lost required contract: {required}")
    if OS_GATE_OLD_COMBINED in gate:
        fail(
            f"{label} OS gate reverted to the undifferentiated 24.04 one-liner; "
            "Ubuntu 26.04 must be refused by name citing the pip-compile lock"
        )
    if gate.count("return 0") != 2:
        fail(
            f"{label} OS gate must return 0 only for ALLOW_UNSUPPORTED_OS=1 "
            f"and exact Ubuntu 24.04 (found {gate.count('return 0')} return 0)"
        )
    if re.search(r'os_version" == "26\.04"[\s\S]{0,200}return 0', gate):
        fail(f"{label} OS gate silently accepts Ubuntu 26.04")
    if '|| "${os_version}" == "26.04"' in gate:
        fail(f"{label} OS gate widened the 24.04 accept to include 26.04")
    caller_body = function_body(source, caller)
    if "require_supported_production_os" not in caller_body:
        fail(f"{label} {caller} no longer invokes require_supported_production_os")


def validate_gateway_tombstone(source: str | None = None) -> None:
    """Design v17 2.8, slice S6: the standalone gateway installer is a pointer
    to the data-plane installer and `exit 2`. It had its own OS gate, listen
    firewall and flag warning; none of that may come back."""
    if source is None:
        source = GATEWAY_SCRIPT.read_text(encoding="utf-8")
    problems = tombstone_problems(source)
    if problems:
        fail("the standalone gateway installer is not the tombstone: " + "; ".join(problems))


GATEWAY_HELPER_HEREDOC = "cat <<'EOF' # the boot helper: /usr/local/sbin/winn3-gateway-firewall\n"
PROVISION_GW_SCRIPT = ROOT / "winn3-nodes" / "provision_gw.sh"
PROVISION_GW_HELPER_HEREDOC = "cat > \"$NODEDIR/winn3-gateway-firewall\" <<'EOF'\n"
# `iptables -I WINVPN-INPUT` (or into a chain variable) followed straight by an
# option has no position, so it lands at position 1, above both guard jumps.
UNPOSITIONED_WINVPN_INSERT_RE = re.compile(r'-I[ \t]+(?:WINVPN-INPUT|"\$\{chain\}")[ \t]+-')
EDGE_CHECK_MODE_LINE = 'if [[ "${1:-}" == "--check-winn3-udp-policy" ]]; then'


def heredoc_text(source: str, start: str) -> str | None:
    at = source.find(start)
    if at < 0:
        return None
    body_start = at + len(start)
    end = source.find("\nEOF\n", body_start)
    return source[body_start:end] if end >= 0 else None


def gateway_listen_placement_problem(gateway: str, data: str) -> str | None:
    """Why the gateway's listen-port rules could land above the WINVPN-INPUT
    guard jumps (Round G follow-up OI-G3.3), or None. `gateway` is the text
    that carries the boot helper heredoc: the data-plane installer."""
    helper = heredoc_text(gateway, GATEWAY_HELPER_HEREDOC)
    if helper is None:
        return "the winn3-gateway-firewall boot helper heredoc is missing"
    if UNPOSITIONED_WINVPN_INSERT_RE.search(helper):
        return "the boot helper inserts into WINVPN-INPUT without a position (position 1, above the guards)"
    udp_insert = 'iptables -w 10 -I WINVPN-INPUT "$((lead + head + 1))" -p udp --dport "${port}" -j ACCEPT \\\n      || { partial '
    tcp_insert = 'iptables -w 10 -I WINVPN-INPUT "${tcp_at}" -p tcp --dport "${port}" -j ACCEPT \\\n      || { partial '
    verify_before_delete = '  problem="$(winvpn_layout_problem "${lead}")"\n  for ((i = 0; i < lead; i++)); do'
    delete_above = 'iptables -w 10 -D WINVPN-INPUT -p "${protocol}" --dport "${port}" -j ACCEPT \\\n      || { partial '
    for needle in (
        "local recovery='-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY'",
        "local serving='-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING'",
        "local loopback='-A WINVPN-INPUT -i lo -j ACCEPT'",
        # Round SU (lane L76): the data plane's probe jump is accepted only
        # in its exact kernel form and only between the guards and loopback.
        "local nfq_probe='-A WINVPN-INPUT -i lo -p tcp -m tcp --dport 9199 -j WINVPN-NFQ-PROBE'",
        '  if [[ "${winvpn_rules[base + 2]:-}" == "${loopback}" ]]; then\n    echo 3\n',
        '  elif [[ "${winvpn_rules[base + 2]:-}" == "${nfq_probe}" && "${winvpn_rules[base + 3]:-}" == "${loopback}" ]]; then\n    echo 4\n',
        # --check-layout returns after the plan's layout test, before any write.
        '  if (( check_layout )); then\n',
        udp_insert,
        tcp_insert,
        verify_before_delete,
        delete_above,
        '    echo "WINVPN-INPUT does not end with -j DROP"\n    return 0\n',
        'echo "a TCP ${port} NFQUEUE sits after the TCP ACCEPT (inspection bypass): ${winvpn_rules[i]}"',
        'echo "a rule ahead of the TCP ${port} ACCEPT can stop or divert it: ${winvpn_rules[i]}"',
        'if [[ "${effect}" != none && "${effect}" != queue && "${effect}" != log && "${effect}" != stop ]]; then',
        "if ($0 ~ /[\"\\047\\\\]/ || $1 != \"-A\" || NF < 4) { verdict(\"unsupported\"); exit }",
        '  problem="$(winvpn_layout_problem 0)"\n',
        "if grep -Fxq -- '-N WINVPN-INPUT' <<<\"${filter_rules}\"; then\n  place_winvpn_input_listen || exit 1\n",
        f"grep -Fq -- '{EDGE_CHECK_MODE_LINE}' \"${{edge}}\"",
        '"${edge}" --check-winn3-udp-policy || {',
    ):
        if helper.count(needle) != 1:
            return f"the boot helper lost its guard-aware placement step: {needle}"
    # Both copies behind the guards exist, and are re-verified, before either
    # copy above is deleted; the result is held to the same layout test.
    if not (helper.find(udp_insert) < helper.find(tcp_insert) < helper.find(verify_before_delete)
            < helper.find(delete_above) < helper.find('  problem="$(winvpn_layout_problem 0)"\n')):
        return "the boot helper deletes an above-guard ACCEPT before its replacement behind the guards exists"
    plan_check = '  problem="$(winvpn_layout_problem "${lead}")"\n  if [[ -n "${problem}" ]]; then\n'
    if not (0 <= helper.find(plan_check) < helper.find('  if (( check_layout )); then\n') < helper.find(udp_insert)):
        return "the boot helper's --check-layout mode does not stop after the plan's layout test and before the first insert"
    # Slice S6: the standalone main() and apply_listen_firewall are not moved
    # (tools/winn3_gateway_block.py NOT_MOVED), so the lane L75/L76 checks of
    # their order are gone with them. The data plane's own main() orders its
    # layout check and forwarding preflight before the first write in slice S4.
    # The probe must match the edge script's real check-mode line, or the
    # Round G check silently never runs.
    # The data plane also carries the moved gateway block (design v17 2.2),
    # whose boot helper greps for this line; count the edge script's copy only.
    begin, end = "# --- begin winn3 gateway block ---\n", "# --- end winn3 gateway block ---\n"
    if begin in data and end in data:
        data = data[:data.index(begin)] + data[data.index(end) + len(end):]
    if data.count(EDGE_CHECK_MODE_LINE) != 1:
        return "the data-plane edge script's --check-winn3-udp-policy line no longer matches the boot helper's probe"
    return None


def validate_gateway_listen_firewall_placement(
    gateway: str | None = None,
    data: str | None = None,
    provision: str | None = None,
) -> None:
    if data is None:
        data = SCRIPTS["data"].read_text(encoding="utf-8")
    if gateway is None:
        # Slice S6: the boot helper is written by the gateway block the data
        # plane carries (design v17 2.2), not by the standalone installer.
        gateway = data
    if provision is None:
        provision = PROVISION_GW_SCRIPT.read_text(encoding="utf-8")
    problem = gateway_listen_placement_problem(gateway, data)
    if problem:
        fail(f"gateway listen firewall: {problem}")
    # Anti-vacuity: the pre-fix position-1 insert and a delete-first repair
    # must both be rejected.
    helper = heredoc_text(gateway, GATEWAY_HELPER_HEREDOC) or ""
    old_insert = 'iptables -w 10 -I "${chain}" -p "${protocol}" --dport "${port}" -j ACCEPT'
    tcp_insert = 'iptables -w 10 -I WINVPN-INPUT "${tcp_at}" -p tcp --dport "${port}" -j ACCEPT \\\n      || { partial '
    mutants = (
        gateway.replace(helper, helper + "\n" + old_insert + "\n"),
        gateway.replace(tcp_insert, "true || { partial "),
    )
    if any(gateway_listen_placement_problem(mutant, data) is None for mutant in mutants):
        fail("gateway listen firewall check accepted a position-1 insert or a missing TCP placement")
    demo = heredoc_text(provision, PROVISION_GW_HELPER_HEREDOC)
    if demo is None:
        fail("winn3-nodes/provision_gw.sh lost its gateway firewall heredoc")
    if UNPOSITIONED_WINVPN_INSERT_RE.search(demo.replace('iptables -w 10 -I "${chain}"', "")) \
            or "chain=WINVPN-INPUT" in demo or "^-N WINVPN-INPUT$" not in demo:
        fail("winn3-nodes/provision_gw.sh must refuse a data-plane host instead of inserting into WINVPN-INPUT")


def data_nfq_postflight_problem(data: str) -> str | None:
    """Why the data-plane postflight does not prove Suricata's running NFQ
    repeat mode (Round H follow-up OI-H4.5), or None."""
    if data.count("\nverify_data_suricata_nfq_runtime() {\n") != 1:
        return "verify_data_suricata_nfq_runtime must be defined exactly once"
    body = function_body(data, "verify_data_suricata_nfq_runtime")
    for needle in (
        'dump="$(suricata --dump-config -c "${cfg}" 2>/dev/null)"',
        "grep -Fxq 'nfq.mode = repeat'",
        "grep -Fxq 'nfq.repeat-mark = 1073741824'",
        "grep -Fxq 'nfq.repeat-mask = 1073741824'",
        "grep -Eq '^nfq\\.[0-9]+( |\\.)'",
        '&& "${mpid}" =~ ^[1-9][0-9]*$ && "${empid}" == "${mpid}"',
        "-p ExecMainStartTimestampMonotonic -p InactiveExitTimestampMonotonic",
        "(( start_us + 1000000 >= imono && start_us <= emono + 2000000 )) || return 1",
        "prev == \"-c\" && $0 == cfg { c = 1 } prev == \"-q\" && $0 == \"0\" { q = 1 }",
        "socket.SO_PEERCRED",
        "if peer != main_pid:",
        '"_SYSTEMD_INVOCATION_ID=${invocation}"',
        "(( banner_epoch >= since ))",
        '[[ "${follows}" == 1 ]]',
        "'NFQ running in REPEAT mode with mark 1073741824/1073741824'",
    ):
        if needle not in body:
            return f"verify_data_suricata_nfq_runtime lost a check: {needle}"
    if body.count("  nfq_unchanged || return 1\n") < 4:
        return "verify_data_suricata_nfq_runtime no longer re-checks the service identity after every step"
    postflight = function_body(data, "postflight_data_plane")
    ids_at = postflight.find('if [[ "${INSTALL_DATA_IDS_IPS:-$INSTALL_DATA_IDS_IPS_DEFAULT}" == "1" ]]; then')
    wait_at = postflight.find("\n    wait_for_suricata\n", ids_at)
    call_at = postflight.find("\n    verify_data_suricata_nfq_runtime /etc/suricata/suricata.yaml || return 1\n", ids_at)
    if ids_at < 0 or not 0 <= wait_at < call_at:
        return "postflight_data_plane must run verify_data_suricata_nfq_runtime after wait_for_suricata in its IDS block"
    return None


def validate_data_nfq_postflight(data: str) -> None:
    problem = data_nfq_postflight_problem(data)
    if problem:
        fail(f"data-plane NFQ postflight: {problem}")
    call = "\n    verify_data_suricata_nfq_runtime /etc/suricata/suricata.yaml || return 1\n"
    for mutant in (
        data.replace(call, "\n"),
        data.replace("'NFQ running in REPEAT mode with mark 1073741824/1073741824'", "'NFQ running in'"),
    ):
        if data_nfq_postflight_problem(mutant) is None:
            fail("data-plane NFQ postflight check accepted a mutant without the runtime check")


def assert_order(body: str, label: str, steps: list[str]) -> None:
    positions: list[int] = []
    for step in steps:
        match = re.search(rf"^[ \t]*{re.escape(step)}(?:[ \t]|$)", body, re.MULTILINE)
        if not match:
            fail(f"{label} is missing required step {step}")
        positions.append(match.start())
    if positions != sorted(positions):
        fail(f"{label} order is unsafe: {' -> '.join(steps)}")


NFQ_REPEAT_MARK = 0x40000000


def nfq_repeat_config_problem(body: str) -> str | None:
    """Why an installer's Suricata Python block does not configure NFQ repeat
    mode, or None. Suricata reads the scalar nfq.mode/nfq.repeat-mark keys, so
    data["nfq"] must be a mapping: a list renders as nfq.0.mode, which Suricata
    8 ignores, and it then runs in standard ACCEPT/DROP mode (lane L9)."""
    tree = ast.parse(body)
    constants: dict[str, object] = {}
    values: list[ast.expr] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
            constants[target.id] = node.value.value
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "data"
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == "nfq"
        ):
            values.append(node.value)
    if len(values) != 1:
        return f"expected exactly one data['nfq'] assignment, found {len(values)}"
    value = values[0]
    if not isinstance(value, ast.Dict):
        return f"data['nfq'] must be a dict literal, not {type(value).__name__}"
    resolved: dict[object, object] = {}
    for key, item in zip(value.keys, value.values):
        if not isinstance(key, ast.Constant):
            return "data['nfq'] has a non-literal key"
        if isinstance(item, ast.Constant):
            resolved[key.value] = item.value
        elif isinstance(item, ast.Name) and item.id in constants:
            resolved[key.value] = constants[item.id]
        else:
            return f"data['nfq'][{key.value!r}] is not a literal"
    if resolved.get("mode") != "repeat":
        return f"nfq mode is {resolved.get('mode')!r}, not 'repeat'"
    if resolved.get("repeat-mark") != NFQ_REPEAT_MARK or resolved.get("repeat-mask") != NFQ_REPEAT_MARK:
        return "nfq repeat-mark/repeat-mask differ from the 0x40000000 queue-rule mark guard"
    return None


def validate_nfq_repeat_mode(name: str, source: str, blocks: list[Heredoc]) -> None:
    mark_guard = "local -a nfqueue_target=(-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0)"
    if mark_guard not in source:
        fail(f"{name} NFQUEUE rules lost the 0x40000000 repeat-mark guard")
    nfq_blocks = [block for block in blocks if "python3" in block.header and 'data["nfq"]' in block.body]
    if len(nfq_blocks) != 1:
        fail(f"{name} must configure Suricata nfq in exactly one Python block, found {len(nfq_blocks)}")
    body = nfq_blocks[0].body
    problem = nfq_repeat_config_problem(body)
    if problem:
        fail(f"{name} Suricata NFQ repeat mode is not in effect: {problem}")
    # Anti-vacuity: the same block with nfq wrapped in a list, or in accept
    # mode, must be rejected.
    tree = ast.parse(body)
    nfq_value = next(
        node.value for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Subscript)
        and isinstance(node.targets[0].slice, ast.Constant) and node.targets[0].slice.value == "nfq"
    )
    segment = ast.get_source_segment(body, nfq_value)
    if not segment:
        fail(f"{name} nfq literal could not be located for the anti-vacuity mutants")
    for mutant in (
        body.replace(segment, "[" + segment + "]", 1),
        body.replace(segment, segment.replace('"repeat"', '"accept"', 1), 1),
    ):
        if nfq_repeat_config_problem(mutant) is None:
            fail(f"{name} nfq repeat-mode check accepted a list or accept-mode mutant")


PREPUBLICATION_CANARY_BIN = "/usr/local/bin/wins-gateway-canary"
PREPUBLICATION_CANARY_PIN = (
    '[[ "${canary_bin}" == "' + PREPUBLICATION_CANARY_BIN + '" ]] || {'
)
PREPUBLICATION_CANARY_START = (
    "if systemctl start wins-gateway-canary-prepublication.service; then"
)
PREPUBLICATION_CANARY_ERR = (
    'err "Public gateway canary failed. The active-gateway pointer was not published."'
)
PREPUBLICATION_UNIT_DERIVATION = (
    "  sed '/^\\[Service\\]$/a\\\n"
    "Environment=WINS_CANARY_WINN3_ADVISORY=1\\\n"
    "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1' \\\n"
    "    /etc/systemd/system/wins-gateway-canary.service \\\n"
    "    > /etc/systemd/system/wins-gateway-canary-prepublication.service\n"
)
PREPUBLICATION_SCHEDULED_UNIT_HEAD = (
    "[Service]\nType=oneshot\nExecStart=" + PREPUBLICATION_CANARY_BIN + "\n"
)
PREPUBLICATION_SKIP_TEST = 'if [[ "${WINS_CANARY_SKIP_GATEWAY_RECORD:-0}" != "1" ]]; then'
PREPUBLICATION_SKIP_ELSE = (
    'else\n  log "SKIP active-gateway record during prepublication canary"\nfi\n'
)


def prepublication_canary_problem(source: str) -> str | None:
    """Why the control installer no longer proves the prepublication canary
    contract, or None.

    H0 (62a802b) moved the prepublication canary out of the root shell into the
    sandboxed unit wins-gateway-canary-prepublication.service, which
    write_gateway_canary derives from the scheduled wins-gateway-canary.service.
    The safety property did not change: the prepublication canary runs only the
    reviewed canary with the active-gateway record skipped, and a failure leaves
    the active-gateway pointer unpublished. It is held in four parts: the runner,
    the scheduled unit and its timer (which keep checking the record), the
    derivation of the prepublication unit, and the canary script that honors the
    skip variable."""
    runner = function_body(source, "run_prepublication_gateway_canary")
    for needle in (
        'local canary_bin="${WINS_GATEWAY_CANARY_BIN:-' + PREPUBLICATION_CANARY_BIN + '}"',
        PREPUBLICATION_CANARY_PIN,
        PREPUBLICATION_CANARY_START,
        PREPUBLICATION_CANARY_ERR,
    ):
        if needle not in runner:
            return f"run_prepublication_gateway_canary lost: {needle}"
    steps = [
        runner.index(PREPUBLICATION_CANARY_PIN),
        runner.index(PREPUBLICATION_CANARY_START),
        runner.index(PREPUBLICATION_CANARY_ERR),
    ]
    if steps != sorted(steps):
        return "run_prepublication_gateway_canary must pin the reviewed path, start the unit, then report the unpublished pointer, in that order"
    if not re.search(re.escape(PREPUBLICATION_CANARY_ERR) + r"\n[ \t]*return 1\n", runner):
        return "run_prepublication_gateway_canary must return 1 right after the unpublished-pointer error"
    if re.search(
        r'^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=[^ \t]*[ \t]+)*"\$\{canary_bin\}"',
        runner,
        re.MULTILINE,
    ):
        return "run_prepublication_gateway_canary runs the canary itself, outside its sandboxed unit"
    # canary_bin is only the reviewed-path pin: any other use of it (an inline
    # run, exec, env or timeout wrapper) would run a canary outside its unit.
    if len(re.findall(r"\$\{?canary_bin\b", runner)) != 1:
        return "run_prepublication_gateway_canary uses canary_bin outside its reviewed-path pin"
    script = heredoc_text(source, "cat > /usr/local/bin/wins-gateway-canary <<'EOF'\n")
    unit = heredoc_text(source, "cat > /etc/systemd/system/wins-gateway-canary.service <<'EOF'\n")
    timer = heredoc_text(source, "cat > /etc/systemd/system/wins-gateway-canary.timer <<'EOF'\n")
    if script is None or unit is None or timer is None:
        return "the gateway canary script, scheduled unit or timer heredoc is missing"
    unit_lines = unit.split("\n")
    if unit_lines.count("[Service]") != 1:
        return "the scheduled canary unit must contain exactly one [Service] section"
    if unit_lines.count("Type=oneshot") != 1:
        return "the scheduled canary unit must be Type=oneshot, so systemctl start waits for the canary and returns its status"
    if [line for line in unit_lines if line.startswith("ExecStart=")] != [
        "ExecStart=" + PREPUBLICATION_CANARY_BIN
    ]:
        return "the scheduled canary unit no longer runs only the reviewed canary binary"
    if any(
        line.startswith(("RemainAfterExit=", "ExecStartPre=", "ExecStartPost=", "ExecCondition="))
        for line in unit_lines
    ):
        return "the scheduled canary unit must run its canary on every start (no RemainAfterExit or extra Exec hooks)"
    if "WINS_CANARY_" in unit:
        return "the scheduled canary unit must not set prepublication variables"
    # `systemctl start` waits for a Type=oneshot run and fails when it fails,
    # which is what makes the runner's retry loop and return 1 meaningful. The
    # unit runs one program, the reviewed canary, and carries nothing that turns
    # a failed or skipped run into a successful start or lets a retry reuse an
    # earlier success. The derived unit inherits all of this, because the sed
    # only inserts two Environment lines.
    service_directives = [
        line.split("=", 1)[0].strip()
        for line in unit.split("[Service]\n", 1)[1].splitlines()
        if "=" in line and not line.lstrip().startswith(("#", ";"))
    ]
    if service_directives.count("Type") != 1:
        return "the scheduled canary unit must set Type exactly once, to oneshot"
    if [
        directive for directive in service_directives
        if directive in {
            "ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost",
            "ExecReload", "ExecStop", "ExecStopPost",
        }
    ] != ["ExecStart"]:
        return "the scheduled canary unit must run exactly one program, the reviewed canary, with no other Exec directive"
    for success_masking in ("RemainAfterExit", "SuccessExitStatus"):
        if success_masking in service_directives:
            return f"the scheduled canary unit must not set {success_masking}"
    # The sandbox the prepublication unit inherits.
    for sandbox_line in (
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
    ):
        if unit_lines.count(sandbox_line) != 1:
            return f"the scheduled canary unit lost its sandbox line: {sandbox_line}"
    if re.search(r"^(?:CapabilityBoundingSet|AmbientCapabilities)=.+", unit, re.MULTILINE):
        return "the scheduled canary unit must hold no capability"
    timer_lines = timer.split("\n")
    if re.findall(r"^Unit=.*$", timer, re.MULTILINE) != ["Unit=wins-gateway-canary.service"] or any(
        "prepublication" in line for line in timer_lines
    ):
        return "the canary timer must run the scheduled unit that checks the active-gateway record"
    # Nothing schedules or enables the record-skipping unit: only the runner
    # starts it, once per prepublication attempt.
    if re.search(
        r"Unit=wins-gateway-canary-prepublication\.service|enable[^\n]*wins-gateway-canary-prepublication",
        source,
    ):
        return "the prepublication canary unit must only be started by the prepublication runner"
    if PREPUBLICATION_UNIT_DERIVATION not in source:
        return "the prepublication unit is no longer derived from the scheduled canary unit with the record skipped"
    # Apply the derivation the installer's sed performs and inspect the result,
    # so the proof covers the generated unit and not only the text of the sed.
    derived = unit.replace(
        "[Service]\n",
        "[Service]\n"
        "Environment=WINS_CANARY_WINN3_ADVISORY=1\n"
        "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1\n",
        1,
    ).split("\n")
    for line in (
        "Environment=WINS_CANARY_WINN3_ADVISORY=1",
        "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1",
        "ExecStart=" + PREPUBLICATION_CANARY_BIN,
        "Type=oneshot",
    ):
        if derived.count(line) != 1:
            return f"the derived prepublication unit lost: {line}"
    skip_branch = re.search(
        r'^if \[\[ "\$\{WINS_CANARY_SKIP_GATEWAY_RECORD:-0\}" != "1" \]\]; then\n'
        r"(?P<checked>.*?)^else\n"
        r'[ \t]*log "SKIP active-gateway record during prepublication canary"\n'
        r"^fi\n",
        script,
        re.MULTILINE | re.DOTALL,
    )
    if not skip_branch or "check_gateway_record" not in skip_branch.group("checked"):
        return "the gateway canary no longer skips the active-gateway record when WINS_CANARY_SKIP_GATEWAY_RECORD=1"
    if len(re.findall(r"^[ \t]*check_gateway_record[ \t\\]", script, re.MULTILINE)) != 1:
        return "the gateway canary must reach the active-gateway record check only through the skip branch"
    return None


# Each mutant is exact installer text with one property broken. The guard above
# must reject every one, or it proves nothing; each anchor must occur once.
PREPUBLICATION_CANARY_MUTANTS = (
    (
        "the runner accepts any canary path",
        PREPUBLICATION_CANARY_PIN,
        '[[ -n "${canary_bin}" ]] || {',
    ),
    (
        "the runner executes the canary inline",
        PREPUBLICATION_CANARY_START,
        'if WINS_CANARY_SKIP_GATEWAY_RECORD=1 "${canary_bin}"; then',
    ),
    (
        "the runner also runs the canary under a wrapper",
        PREPUBLICATION_CANARY_START,
        'timeout 60 "${canary_bin}" || true\n    ' + PREPUBLICATION_CANARY_START,
    ),
    (
        "the runner starts the unit without waiting",
        PREPUBLICATION_CANARY_START,
        "if systemctl start --no-block wins-gateway-canary-prepublication.service; then",
    ),
    (
        "the runner returns success after every attempt failed",
        PREPUBLICATION_CANARY_ERR + "\n  return 1\n",
        PREPUBLICATION_CANARY_ERR + "\n  return 0\n",
    ),
    (
        "the derivation no longer skips the active-gateway record",
        "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=1' \\\n",
        "Environment=WINS_CANARY_SKIP_GATEWAY_RECORD=0' \\\n",
    ),
    (
        "the scheduled unit skips the active-gateway record",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        "[Service]\nType=oneshot\nEnvironment=WINS_CANARY_SKIP_GATEWAY_RECORD=1\n"
        "ExecStart=" + PREPUBLICATION_CANARY_BIN + "\n",
    ),
    (
        "the scheduled unit runs another binary",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        "[Service]\nType=oneshot\nExecStart=/usr/local/bin/wins-gateway-canary-unreviewed\n",
    ),
    (
        "the scheduled unit returns before the canary finishes",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        "[Service]\nType=simple\nExecStart=" + PREPUBLICATION_CANARY_BIN + "\n",
    ),
    (
        "the scheduled unit stays active after one run",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        PREPUBLICATION_SCHEDULED_UNIT_HEAD + "RemainAfterExit=yes\n",
    ),
    (
        "a failed canary run counts as success",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        PREPUBLICATION_SCHEDULED_UNIT_HEAD + "SuccessExitStatus=1\n",
    ),
    (
        "the scheduled unit has a condition that can skip the canary",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        "[Service]\nType=oneshot\nExecCondition=/bin/false\nExecStart=" + PREPUBLICATION_CANARY_BIN + "\n",
    ),
    (
        "the scheduled unit runs a second program",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        PREPUBLICATION_SCHEDULED_UNIT_HEAD + "ExecStart=/bin/true\n",
    ),
    (
        "the scheduled unit runs a hook before the canary",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        "[Service]\nType=oneshot\nExecStartPre=/bin/true\nExecStart=" + PREPUBLICATION_CANARY_BIN + "\n",
    ),
    (
        "the scheduled unit runs a stop hook",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        PREPUBLICATION_SCHEDULED_UNIT_HEAD + "ExecStopPost=/bin/true\n",
    ),
    (
        "the scheduled unit sets Type twice",
        PREPUBLICATION_SCHEDULED_UNIT_HEAD,
        PREPUBLICATION_SCHEDULED_UNIT_HEAD + "Type=simple\n",
    ),
    (
        "the scheduled unit loses NoNewPrivileges",
        "privileged job.\nNoNewPrivileges=true\nPrivateTmp=true\n",
        "privileged job.\nPrivateTmp=true\n",
    ),
    (
        "the scheduled unit holds a capability",
        "\nCapabilityBoundingSet=\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nEOF\n\n  sed '/",
        "\nCapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=\nSystemCallArchitectures=native\nLockPersonality=true\nEOF\n\n  sed '/",
    ),
    (
        "the timer runs the record-skipping unit",
        "Persistent=false\nUnit=wins-gateway-canary.service\n",
        "Persistent=false\nUnit=wins-gateway-canary-prepublication.service\n",
    ),
    (
        "the timer also runs the record-skipping unit",
        "Persistent=false\nUnit=wins-gateway-canary.service\n",
        "Persistent=false\nUnit=wins-gateway-canary.service\nUnit=wins-gateway-canary-prepublication.service\n",
    ),
    (
        "the record-skipping unit is enabled",
        "  wins_enable_monotonic_timer wins-gateway-canary.timer\n}\n\nrun_prepublication_gateway_canary() {\n",
        "  wins_enable_monotonic_timer wins-gateway-canary.timer\n"
        "  systemctl enable wins-gateway-canary-prepublication.service\n}\n\nrun_prepublication_gateway_canary() {\n",
    ),
    (
        "the canary script skips the record check when it should run it",
        PREPUBLICATION_SKIP_TEST,
        'if [[ "${WINS_CANARY_SKIP_GATEWAY_RECORD:-0}" == "1" ]]; then',
    ),
    (
        "the canary script checks the record on the skip path too",
        PREPUBLICATION_SKIP_ELSE,
        "else\n  check_gateway_record\n  log \"SKIP active-gateway record during prepublication canary\"\nfi\n",
    ),
    (
        "the canary script checks the record outside the skip branch",
        'exit "${failed}"\nEOF\n  chmod +x ' + PREPUBLICATION_CANARY_BIN + "\n",
        'check_gateway_record "late"\nexit "${failed}"\nEOF\n  chmod +x ' + PREPUBLICATION_CANARY_BIN + "\n",
    ),
)


def validate_prepublication_canary(source: str) -> None:
    problem = prepublication_canary_problem(source)
    if problem:
        fail(f"control prepublication public canary: {problem}")
    for label, old, new in PREPUBLICATION_CANARY_MUTANTS:
        if source.count(old) != 1:
            fail(f"control prepublication canary mutant anchor is not unique: {label}")
        if prepublication_canary_problem(source.replace(old, new, 1)) is None:
            fail(f"control prepublication canary guard accepted a mutant: {label}")


def validate_order_and_contract(name: str, source: str) -> None:
    patch_prefixed_function = re.search(
        r"^\+([A-Za-z_][A-Za-z0-9_]*)\(\) \{\s*$", source, re.MULTILINE
    )
    if patch_prefixed_function:
        fail(
            f"{name} script contains a patch-prefixed function declaration: "
            f"{patch_prefixed_function.group(1)}"
        )
    if "rm -f /var/lib/apt/lists/lock" in source:
        fail(f"{name} script must never delete live APT/dpkg lock files")
    if re.search(
        r'(?:-H|--header)[ \t]+["\'](?:Authorization:[ \t]+Bearer|[xX]-admin-token):?[^\n]*\$\{',
        source,
    ):
        fail(f"{name} script exposes a bearer/admin token in curl process arguments")
    if re.search(r'-u[ \t]+["\'][^\n]*\$\{(?:PAYPAL|CLOUDFLARE)', source):
        fail(f"{name} script exposes an API client secret in curl process arguments")
    for secret_curl_guard in (
        "curl_bearer() {",
        'curl --config <(printf \'header = "Authorization: Bearer %s"\\n\'',
    ):
        if secret_curl_guard not in source:
            fail(f"{name} secret-safe curl transport changed: {secret_curl_guard}")
    for required_package_step in (
        "wait_for_cloud_init",
        "wait_for_fail2ban",
        "wait_for_package_manager",
        "repair_package_state",
        "apt_retry",
    ):
        if f"{required_package_step}() {{" not in source:
            fail(f"{name} script lacks package reliability helper {required_package_step}")
    for required_literal in (
        "DEBIAN_FRONTEND=noninteractive",
        "DPkg::Lock::Timeout=300",
        "Acquire::Retries=3",
        "Dpkg::Use-Pty=0",
        "--force-confdef",
        "--force-confold",
        '"${APT_GET[@]}" upgrade -y --with-new-pkgs',
        'ALLOW_UNSUPPORTED_OS:-0',
        "install -d -m 755 /run/sshd",
    ):
        if required_literal not in source:
            fail(f"{name} script lacks required unattended-upgrade guard: {required_literal}")
    validate_require_supported_production_os(name, source, OS_GATE_PREFLIGHT[name])
    unattended_exports = (
        "export DEBIAN_FRONTEND=noninteractive",
        "export DEBIAN_PRIORITY=critical",
        "export APT_LISTCHANGES_FRONTEND=none",
        "export NEEDRESTART_MODE=a",
        "export UCF_FORCE_CONFFOLD=1",
    )
    prologue = "\n".join(source.splitlines()[:12])
    for required_export in unattended_exports:
        if required_export not in prologue:
            fail(f"{name} package prologue lacks unattended guard: {required_export}")
        minimum_count = 2 if name in {"control", "data"} else 1
        if source.count(required_export) < minimum_count:
            fail(
                f"{name} generated maintenance path lacks unattended guard: "
                f"{required_export}"
            )
    if re.search(r"^[ \t]*apt-get[ \t]+", source, re.MULTILINE):
        fail(f"{name} script bypasses the package retry and lock-wait wrapper")
    early_exit_grep = re.search(
        r"(?<!\|)\|(?!\|)[^\n]*\bgrep[ \t]+-[A-Za-z]*q[A-Za-z]*(?:[ \t]|$)",
        source,
    )
    if early_exit_grep:
        fail(
            f"{name} uses grep -q in a pipeline under pipefail; the producer can "
            "receive SIGPIPE and turn a successful check into exit 141"
        )
    if 'run_step "apt full-upgrade all apt-managed programs"' in source:
        fail(f"{name} weekly maintenance must not perform unattended package removals")
    if name in {"control", "data"}:
        cloudflared_install = function_body(source, "install_cloudflared_package")
        for cloudflared_guard in (
            'CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.10.0}"',
            'CLOUDFLARED_AMD64_SHA256="${CLOUDFLARED_AMD64_SHA256:-9721287c28f78cb623e77c7b95a63feea87e909054d75666a0ec9eff20e5d548}"',
            'CLOUDFLARED_ARM64_SHA256="${CLOUDFLARED_ARM64_SHA256:-7e0d76de3858b6396bd234ae26182bee222133398667d2647b90381d00c00e98}"',
            'cloudflared_${CLOUDFLARED_VERSION}_${package_arch}.deb',
            'printf \'%s  %s\\n\' "${package_sha}" "${package_file}" | sha256sum -c -',
            'apt-mark hold cloudflared',
        ):
            if cloudflared_guard not in source:
                fail(f"{name} cloudflared immutable package gate changed: {cloudflared_guard}")
        if 'apt_retry "${APT_GET[@]}" install -y --allow-downgrades "cloudflared=${CLOUDFLARED_VERSION}"' in cloudflared_install:
            fail(f"{name} cloudflared install regressed to the rotating apt index")
    elif name == "core":
        cloudflared_install = function_body(source, "install_cloudflared_package")
        for cloudflared_constant in (
            'CLOUDFLARED_UPSTREAM_VERSION="${CLOUDFLARED_UPSTREAM_VERSION:-2026.10.0}"',
            'CLOUDFLARED_BUILD_VERSION="${CLOUDFLARED_BUILD_VERSION:-2026.10.0-security1}"',
            'CLOUDFLARED_SOURCE_COMMIT="${CLOUDFLARED_SOURCE_COMMIT:-18cdfe0a6fc7b72a0702d255a1f984e776ce0498}"',
            'CLOUDFLARED_SOURCE_SHA256="${CLOUDFLARED_SOURCE_SHA256:-303c531b416b986bfcc2157c0a90556c94c519ec4d71e64d32abbe5c451f59ec}"',
            'CLOUDFLARED_PATCH_SHA256="${CLOUDFLARED_PATCH_SHA256:-8ec5ecde3a9ded36d10800b9cc0457264a7aee7e083e5eaf7e4cba76dcf8493d}"',
            'CLOUDFLARED_REVIEW_SHA256="${CLOUDFLARED_REVIEW_SHA256:-4cd9ddd0cb26a8d3e9a2e6e1d601e9b9973fb7989794b059a498946fd0c376d6}"',
            'CLOUDFLARED_PATCHED_GOMOD_SHA256="${CLOUDFLARED_PATCHED_GOMOD_SHA256:-2f00aef341c813be5385dfe3ecd5be3c12f79fe04066f47ab28874a945f5d947}"',
            'CLOUDFLARED_RESOLVED_GOSUM_SHA256="${CLOUDFLARED_RESOLVED_GOSUM_SHA256:-2235fabd50493ee2291a5470931268a62e783ce572c67e56c6562b989b773a6a}"',
            'CLOUDFLARED_GO_VERSION="${CLOUDFLARED_GO_VERSION:-1.27.1}"',
            'CLOUDFLARED_GO_AMD64_SHA256="${CLOUDFLARED_GO_AMD64_SHA256:-63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445}"',
            'CLOUDFLARED_GO_ARM64_SHA256="${CLOUDFLARED_GO_ARM64_SHA256:-3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec}"',
            'CLOUDFLARED_AMD64_SHA256="${CLOUDFLARED_AMD64_SHA256:-6205d546fbca7fe372db923580daf8217a0b7107d371b602d20e4311879e1a27}"',
            'CLOUDFLARED_ARM64_SHA256="${CLOUDFLARED_ARM64_SHA256:-94ec9925148b1e13ac07a664549d5d052f09857e91db0ba570fbd6322afa1c0d}"',
        ):
            if cloudflared_constant not in source:
                fail(f"core cloudflared reviewed constant changed: {cloudflared_constant}")
        for cloudflared_guard in (
            'vendor/cloudflared-2026.10.0-security.patch',
            'vendor/cloudflared-2026.10.0-security-review.md',
            'https://codeload.github.com/cloudflare/cloudflared/tar.gz/${CLOUDFLARED_SOURCE_COMMIT}',
            'https://go.dev/dl/go${CLOUDFLARED_GO_VERSION}.linux-${go_arch}.tar.gz',
            'GOTOOLCHAIN=local',
            'GOSUMDB=sum.golang.org',
            'GOFLAGS=-mod=readonly',
            'GOEXPERIMENT=',
            'GOFIPS140=off',
            '"${CLOUDFLARED_PATCHED_GOMOD_SHA256}" go.mod | sha256sum -c -',
            '"${CLOUDFLARED_RESOLVED_GOSUM_SHA256}" go.sum | sha256sum -c -',
            'CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" "${go_arch_feature}"',
            'mv -f -- "${install_tmp}" "${install_path}"',
            'Caller environment may not select alternate cloudflared source, toolchain, dependency, review, or output pins.',
        ):
            if cloudflared_guard not in cloudflared_install:
                fail(f"core cloudflared reviewed-source gate changed: {cloudflared_guard}")
        if 'ExecStart=/usr/local/bin/cloudflared --no-autoupdate tunnel run' not in source:
            fail("core cloudflared service no longer uses the reviewed /usr/local bytes")
        for forbidden in (
            "pkg.cloudflare.com/cloudflared/pool/",
            'dpkg -i "${package_file}"',
            'ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run',
        ):
            if forbidden in cloudflared_install or forbidden in source:
                fail(f"core cloudflared regressed to known-flagged package bytes: {forbidden}")
    if name in {"control", "data", "core"}:
        for suricata_package_guard in (
            'SURICATA_MIN_VERSION_DEFAULT="${SURICATA_MIN_VERSION:-8.0.7}"',
            "ppa:oisf/suricata-stable",
            "--simulate remove suricata-update",
            "Unexpected Suricata migration removal plan; refusing package changes.",
            "dpkg-query -S /usr/bin/suricata-update",
            "verify_suricata_package",
        ):
            if suricata_package_guard not in source:
                fail(f"{name} stable Suricata package guard changed: {suricata_package_guard}")
        apt_body = function_body(source, "apt_install")
        assert_order(
            apt_body,
            f"{name} apt Suricata order",
            [
                'apt_retry "${APT_GET[@]}" update -y',
                "ensure_suricata_stable_repository",
                'apt_retry "${APT_GET[@]}" upgrade -y --with-new-pkgs',
                "verify_suricata_package",
            ],
        )
        if re.search(r"\bsuricata[ \t\\\n]+suricata-update\b", apt_body):
            fail(f"{name} must not request Ubuntu's conflicting standalone suricata-update package")
        repair_body = function_body(source, "repair_package_state")
        assert_order(
            repair_body,
            f"{name} interrupted package repair",
            [
                "remove_conflicting_suricata_update_package",
                "if ! dpkg --force-confdef --force-confold --configure -a; then",
            ],
        )
        # The control script's update heredoc now defines inner functions at column 0 (reload_suricata and
        # friends), which ends function_body early; slice to the next top-level write_* function instead.
        _decl = list(re.finditer(r"^write_suricata_update_timer\(\) \{\s*$", source, re.MULTILINE))[-1]
        _next = re.search(r"^write_[A-Za-z0-9_]+\(\) \{\s*$", source[_decl.end():], re.MULTILINE)
        suricata_update_body = source[_decl.end():_decl.end() + _next.start()] if _next else source[_decl.end():]
        # CP-6: the control updater script is written by write_suricata_update_script,
        # shared with the deploy path (install_control_ids_ips); its body counts too.
        _shared = re.search(r"^write_suricata_update_script\(\) \{\s*$", source, re.MULTILINE)
        if _shared:
            _shared_next = re.search(r"^write_[A-Za-z0-9_]+\(\) \{\s*$", source[_shared.end():], re.MULTILINE)
            suricata_update_body = (
                source[_shared.end():_shared.end() + _shared_next.start()] if _shared_next else source[_shared.end():]
            ) + suricata_update_body
            if "  write_suricata_update_script\n" not in suricata_update_body:
                fail(f"{name} write_suricata_update_timer no longer writes the shared updater script")
        for daily_update_guard in (
            "systemctl disable --now wins-suricata-update.timer",
            "rm -f /usr/local/bin/wins-suricata-update",
            "exec 9>/run/lock/wins-suricata-update.lock",
            "flock -n 9",
            "suricata-update --disable-conf /etc/suricata/disable.conf --modify-conf /etc/suricata/modify.conf",
            "--no-test",
            "Imported Suricata rules still contain a blocking or bypass action",
            "suricata -T -c /etc/suricata/suricata.yaml",
            "suricatasc -c reload-rules",
            "systemctl kill --kill-who=main --signal=USR2 suricata.service",
            "OnCalendar=*-*-* 03:20:00",
            "RandomizedDelaySec=45min",
            "Persistent=true",
            "ProtectSystem=full",
            "UMask=0077",
        ):
            if daily_update_guard not in suricata_update_body:
                fail(f"{name} daily Suricata update guard changed: {daily_update_guard}")
        modify_blocks = [
            block.body for block in parse_heredocs(SCRIPTS[name])
            if "/etc/suricata/modify.conf" in block.header
        ]
        if not modify_blocks or not all(
            're:. "^(drop|reject|rejectsrc|rejectdst|rejectboth|pass)[ \\t]+" "alert "'
            in body for body in modify_blocks
        ):
            fail(f"{name} must convert every imported Suricata blocking/bypass action to alert")
        if name == "control":
            # CP-6: the install applies the alert-only policy through the same
            # staged updater as the daily refresh, never straight to the active file.
            ids_body = function_body(source, "install_control_ids_ips")
            assert_order(
                ids_body,
                f"{name} install-time Suricata update goes through the staged updater",
                [
                    "chmod 700 /usr/local/bin/wins-suricata-action-policy",
                    "write_suricata_update_script",
                    "WINS_SURICATA_UPDATE_NO_RELOAD=1 /usr/local/bin/wins-suricata-update",
                    "if ! /usr/local/bin/wins-suricata-action-policy; then",
                    "if ! suricata -T -c \"${cfg}\" -v; then",
                ],
            )
            # CP-6: a rejected set never stays active: every refusal between the
            # snapshot and the restart puts the last-good config and rules back.
            if ids_body.count('suricata_deploy_restore "${ids_snapshot}" "${ids_files[@]}"') < 4:
                fail(f"{name} install path can leave a rejected Suricata config or ruleset active")
            if "suricata-update --disable-conf" in ids_body:
                fail(f"{name} install path writes suricata-update output straight over the active rules")
            if source.count("--modify-conf /etc/suricata/modify.conf") < 1:
                fail(f"{name} must apply the Suricata alert-only policy during install and daily refresh")
        elif source.count("--modify-conf /etc/suricata/modify.conf") < 2:
            fail(f"{name} must apply the Suricata alert-only policy during install and daily refresh")
        if "Imported Suricata rules still contain a blocking or bypass action" not in source:
            fail(f"{name} must reject an imported Suricata action-policy violation")
        expected_sid_prefix = {
            "control": "990000",
            "data": "991000",
            "core": "992000",
        }[name]
        expected_actions = "\\n".join(
            f"drop:{expected_sid_prefix}{suffix}" for suffix in range(1, 6)
        )
        if f"expected=$'{expected_actions}'" not in source:
            fail(f"{name} exact five-rule Suricata IPS allowlist changed")
        if source.count("/usr/local/bin/wins-suricata-action-policy") < 5:
            fail(f"{name} must enforce the exact IPS action allowlist at install, refresh, and postflight")
        if name in {"data", "core"}:
            # L25 privacy review: every eve alert carries the remote src_ip.
            # Keep three rotated files, rotating daily or sooner at 100M.
            # This is a file-count bound, not a three-day age limit.
            # The timer must be active (one node had a 2.7 GB eve.json
            # with logrotate.timer inactive).
            rotate_blocks = [
                block.body for block in parse_heredocs(SCRIPTS[name])
                if "/etc/logrotate.d/wins-suricata" in block.header
            ]
            if len(rotate_blocks) != 1:
                fail(f"{name} must write exactly one /etc/logrotate.d/wins-suricata policy")
            rotate_lines = [
                line.split() for line in rotate_blocks[0].splitlines()
                if line.split()[:1] == ["rotate"]
            ]
            if rotate_lines != [["rotate", "3"]]:
                fail(f"{name} Suricata eve/fast retention must be exactly 'rotate 3', got {rotate_lines}")
            if "systemctl enable --now logrotate.timer" not in source:
                fail(f"{name} must enable logrotate.timer so the Suricata retention bound is enforced")
            # Round U OI-U3: the rotation path is repaired and verified, and a
            # failure stops the install instead of warning.
            if "  wins_ensure_suricata_rotation || return 1\n" not in source:
                fail(f"{name} must verify the Suricata rotation path and fail the install when it cannot")
            if 'logrotate dry-run for wins-suricata reported issues' in source:
                fail(f"{name} still downgrades a failed Suricata logrotate dry run to a warning")
    if name == "data":
        awg_run = function_body(source, "install_awg")
        for awg_log_bound in (
            "--log-driver json-file",
            "--log-opt max-size=1m",
            "--log-opt max-file=2",
        ):
            if awg_log_bound not in awg_run:
                fail(f"data AWG container log must stay bounded: {awg_log_bound}")
    main = function_body(source, "main")
    early_swap_guard = function_body(source, "wins_early_plaintext_swap_guard")
    for early_guard in (
        'case "${arg}" in',
        "--preflight|--validate) validate_only=1",
        'swapoff "${swap_src}"',
        "deployment stopped before loading credentials",
        "Unprotected swap remains active",
    ):
        if early_guard not in early_swap_guard:
            fail(f"{name} early pre-secret plaintext-swap guard changed: {early_guard}")
    protected_source_guard = function_body(source, "wins_early_swap_source_is_protected")
    for protected_guard in (
        "/dev/zram*|/dev/ram*",
        '[[ "${fs_type}" =~ ^(tmpfs|ramfs)$ ]]',
        'lsblk -spno TYPE "${backing_real}"',
        "grep -x crypt",
    ):
        if protected_guard not in protected_source_guard:
            fail(f"{name} encrypted/RAM-backed swap classification changed: {protected_guard}")
    early_call = 'wins_early_plaintext_swap_guard "$@"'
    first_state_load = "NODE_ENV_FILE=" if name == "data" else "WINS_DEFAULTS_FILE="
    if source.find(early_call) < 0 or source.find(early_call) > source.find(first_state_load):
        fail(f"{name} must run the plaintext-swap guard before loading defaults, node state, or secrets")
    if name == "control":
        assert_order(
            main,
            "control main",
            [
                "require_root",
                "preflight_control",
                "install_hub_ssh_public_key",
                "mark_control_role",
                "apt_install",
                "configure_luks_root_policy",
                "configure_swap_policy",
                "configure_partial_vault",
                "configure_performance_mode",
                "configure_dmcrypt_performance",
                "setup_control_sysctl",
                "write_env",
                "validate_external_secret_contract",
                "ensure_cloudflare_access_service_token",
                "ensure_hub_ssh_key",
                "backup_existing_db",
                "write_app",
                "setup_python",
                "write_sqlite_bootstrap",
                "write_systemd",
                "harden_control_sshd",
                "write_nginx",
                "configure_control_origin_tunnel",
                "configure_rclone_credentials",
                "install_control_ids_ips",
                "write_threat_triage_engine",
                "write_security_alert_monitor",
                "write_security_events_cli",
                "write_paypal_sync_timer",
                "write_backup_script",
                "write_backup_timer",
                "write_backup_helper",
                "write_embedded_rclone_config",
                "write_admin_cli",
                "write_suricata_update_timer",
                "write_cloudflare_access_refresh",
                "write_weekly_maintenance",
                "write_gateway_canary",
                "write_hub_recovery_contract",
                "postflight_control",
                "run_initial_backup",
                "verify_external_integrations",
                "write_cloudflare_hub_dns",
                "run_prepublication_gateway_canary",
                "publish_active_gateway_record",
            ],
        )
        # write_iptables legitimately runs three times (an early fail-closed
        # bootstrap pass right after the runtime environment loads, then a
        # pre-/post-Suricata pair later), so it cannot be a single entry in
        # the strictly-increasing assert_order list above. Check its actual
        # invariant directly instead: the first call must precede every
        # network-facing service start, and the config-load boundary must
        # precede the first call. Matches are restricted to bare call
        # statements (like assert_order above) so mentioning these names in
        # a comment can never satisfy or defeat this check.

        def call_positions(name: str) -> list[int]:
            return [
                found.start()
                for found in re.finditer(
                    rf"^[ \t]*{re.escape(name)}(?:[ \t]|$)", main, re.MULTILINE
                )
            ]

        iptables_calls = call_positions("write_iptables")
        if not iptables_calls:
            fail("control main is missing required step write_iptables")
        first_iptables, last_iptables = iptables_calls[0], iptables_calls[-1]
        secret_contract_calls = call_positions("validate_external_secret_contract")
        if not secret_contract_calls or secret_contract_calls[0] > first_iptables:
            fail(
                "control main must load and validate the runtime environment "
                "before the first fail-closed firewall bootstrap"
            )
        for listener_step in (
            "write_systemd",
            "write_nginx",
            "configure_control_origin_tunnel",
        ):
            listener_calls = call_positions(listener_step)
            if not listener_calls or listener_calls[0] < first_iptables:
                fail(
                    "control main firewall bootstrap order is unsafe: "
                    f"{listener_step} starts before the first write_iptables call"
                )
        ids_ips_calls = call_positions("install_control_ids_ips")
        if not ids_ips_calls or ids_ips_calls[0] > last_iptables:
            fail(
                "control main must apply the final Suricata-aware firewall "
                "pass after install_control_ids_ips"
            )
        if "net.ipv4.ip_forward=0" not in source:
            fail("control hub must remain a non-routing control plane")
        if 'HUB_SSH_PASSWORD_AUTH_DEFAULT="${HUB_SSH_PASSWORD_AUTH:-0}"' not in source:
            fail("control hub SSH must default to key-only authentication")
        if 'HUB_ALLOW_GLOBAL_SSH:-0' not in source:
            fail("control hub SSH must default to trusted source CIDRs only")
        if "WINS_SECRETS_FILE" not in source or "STRICT_ONE_TOUCH_SECRETS" not in source:
            fail("control deployment must load a root-only external secret contract")
        # A honeypot on the control hub would let a compromised decoy pivot
        # straight into the real, protected origin. The Cowrie deception
        # listener now lives only in the standalone, never-invoked
        # server/wins_cowrie_honeypot_ONETOUCH.sh; main() below checks that
        # every production ONETOUCH script, including this one, carries zero
        # trace of it rather than a gated-off, always-refusing code path.
        swap_policy = function_body(source, "configure_swap_policy")
        for swap_guard in (
            'warn "Disabling unencrypted swap before control-plane deployment continues: ${plaintext_swap}"',
            'swapoff "${swap_src}"',
            "Unable to disable unencrypted swap ${swap_src}; control-plane deployment stopped.",
            "Unencrypted swap remains active after hardening",
            "compressed RAM swap remains available.",
            "configure_zram_swap",
        ):
            if swap_guard not in swap_policy:
                fail(f"control plaintext-swap remediation changed: {swap_guard}")
        zram_policy = function_body(source, "configure_zram_swap")
        for zram_guard in (
            "systemd/zram-generator.conf",
            "zram-size = min(ram * ${percent} / 100, ${max_mb})",
            "compression-algorithm = zstd",
            "swap-priority = 100",
            "modprobe zram",
            "zram module is not owned by the matching Ubuntu kernel package",
            "systemctl start dev-zram0.swap",
            "swapon --noheadings --raw --show=NAME",
            "no disk writeback",
        ):
            if zram_guard not in zram_policy:
                fail(f"control zram pressure-relief policy changed: {zram_guard}")
        if "writeback-device =" in zram_policy:
            fail("control zram must not write compressed pages back to plaintext disk")
        if "systemd-zram-generator" not in function_body(source, "apt_install"):
            fail("control package installation must include Ubuntu systemd-zram-generator")
        for module_guard in (
            'zram_kernel_package="linux-modules-extra-${zram_kernel_release}"',
            "default_kernel_image",
            "modinfo -k",
            "apt-cache policy",
            "modinfo zram",
        ):
            if module_guard not in function_body(source, "apt_install"):
                fail(f"control zram kernel-module installation changed: {module_guard}")
        initial_backup = function_body(source, "run_initial_backup")
        if '[[ "${REQUIRE_REMOTE_BACKUP:-1}" == "1" ]]' not in initial_backup or "Public cutover was not performed" not in initial_backup:
            fail("control required initial backup must fail closed before public cutover")
        control_postflight = function_body(source, "postflight_control")
        for recovery_guard in (
            "/etc/winsvpn/hub-install-contract.env",
            "/usr/local/bin/wins-hub-restore-preflight",
            "bash -n /usr/local/bin/wins-hub-restore-preflight",
        ):
            if recovery_guard not in control_postflight:
                fail(f"control postflight recovery contract changed: {recovery_guard}")
        repair_steps = function_body(
            source, "run_hub_recovery_contract_repair_steps"
        )
        for repair_step_guard in (
            "write_hub_recovery_contract || return 1",
            "WINS_SKIP_TRANSIENT_BACKUP_CLEANUP=1 write_backup_script || return 1",
            "write_backup_timer || return 1",
            "bash -n /usr/local/bin/wins-hub-restore-preflight || return 1",
            "bash -n /usr/local/bin/wins-hub-backup || return 1",
            "bash -n /usr/local/bin/wins-hub-db-snapshot || return 1",
            "/etc/systemd/system/wins-hub-db-snapshot.service",
            "systemd-analyze verify",
            "systemctl is-enabled --quiet wins-hub-backup.timer || return 1",
            "systemctl is-active --quiet wins-hub-backup.timer || return 1",
            "systemctl is-active --quiet wins-hub.service || return 1",
        ):
            if repair_step_guard not in repair_steps:
                fail(
                    "control recovery-only transaction no longer propagates "
                    f"failure explicitly: {repair_step_guard}"
                )
        if "harden_sensitive_artifacts" in repair_steps:
            fail(
                "control recovery-only transaction must not mutate unrelated "
                "keys, databases, or application artifacts"
            )
        backup_writer = function_body(source, "write_backup_script")
        backup_writer_steps = [
            "WINS_SKIP_TRANSIENT_BACKUP_CLEANUP",
            "find /tmp -maxdepth 1",
            "cat > /usr/local/bin/wins-hub-backup",
        ]
        backup_writer_positions = [
            backup_writer.find(step) for step in backup_writer_steps
        ]
        if any(position < 0 for position in backup_writer_positions) or \
                backup_writer_positions != sorted(backup_writer_positions):
            fail(
                "control transient-backup cleanup repair override is missing "
                "or ordered unsafely"
            )
        assert_order(
            repair_steps,
            "control recovery-only write/verify order",
            [
                "write_hub_recovery_contract || return 1",
                "WINS_SKIP_TRANSIENT_BACKUP_CLEANUP=1 write_backup_script || return 1",
                "write_backup_timer || return 1",
                "bash -n /usr/local/bin/wins-hub-restore-preflight || return 1",
                "systemd-analyze verify",
                "systemctl is-active --quiet wins-hub.service || return 1",
            ],
        )
        recovery_repair = function_body(source, "repair_hub_recovery_contract")
        for recovery_repair_guard in (
            "winsvpn-recovery-contract-repair-${stamp}",
            "/usr/local/bin/wins-hub-db-snapshot",
            "/etc/systemd/system/wins-hub-db-snapshot.service",
            'printf \'present\\n\' > "${state}"',
            'cp -a -- "${path}" "${backup_dir}/${index}.item"',
            "if ! run_hub_recovery_contract_repair_steps; then",
            'rm -f -- "${path}"',
            'cp -a -- "${backup_dir}/${index}.item" "${path}"',
            "systemctl daemon-reload",
            'previous_timer_enabled}" == "enabled"',
            'previous_timer_active}" == "active"',
            'sha256sum "${managed_paths[@]}"',
        ):
            if recovery_repair_guard not in recovery_repair:
                fail(
                    "control recovery-only rollback/evidence contract changed: "
                    f"{recovery_repair_guard}"
                )
        assert_order(
            recovery_repair,
            "control recovery-only snapshot/commit boundary",
            [
                'cp -a -- "${path}" "${backup_dir}/${index}.item"',
                "if ! run_hub_recovery_contract_repair_steps; then",
                'rm -f -- "${path}"',
                "systemctl daemon-reload",
                'sha256sum "${managed_paths[@]}"',
            ],
        )
        validate_prepublication_canary(source)
        nginx = function_body(source, "write_nginx")
        for nginx_capacity_guard in (
            'local nginx_worker_connections="${NGINX_WORKER_CONNECTIONS:-8192}"',
            'local nginx_nofile_limit="${NGINX_WORKER_NOFILE_LIMIT:-65535}"',
            "worker_processes auto;",
            "worker_connections {connections};",
            "worker_rlimit_nofile {nofile};",
            "LimitNOFILE=${nginx_nofile_limit}",
        ):
            if nginx_capacity_guard not in nginx:
                fail(f"control Nginx connection-capacity tuning changed: {nginx_capacity_guard}")
        for escaped_env_guard in (
            # Must stay unquoted: a double-quoted assignment here leaves
            # escaping backslashes in the *result* instead of consuming them
            # (tools/test_deployment_env_kv_quoting.py proves this).
            "value=${value//\\'/\\'\\\"\\'\\\"\\'}",
            'env_kv_buffer+="${key}=\'${value}\'"$\'\\n\'',
            "Runtime environment value for ${key} contains a forbidden newline.",
            'write_env_kv SMTP_PASS "${smtp_pass}"',
            'write_env_kv PAYPAL_CLIENT_SECRET',
            'write_env_kv ADMIN_TOKEN "${admin_token}"',
            'atomic_replace_file "${ENV_FILE}" "${env_kv_buffer}" 600',
            'atomic_replace_file "${LEGACY_ENV_FILE}" "${env_kv_buffer}" 600',
        ):
            if escaped_env_guard not in source:
                fail(f"control runtime environment escaping changed: {escaped_env_guard}")
        atomic_replace_file = function_body(source, "atomic_replace_file")
        for atomic_replace_guard in (
            'tmp="$(mktemp "${real_target}.XXXXXX")"',
            'printf \'%s\' "${content}" > "${tmp}"',
            'chmod "${mode}" "${tmp}"',
            'mv -f "${tmp}" "${real_target}"',
        ):
            if atomic_replace_guard not in atomic_replace_file:
                fail(f"control atomic env-file replace changed: {atomic_replace_guard}")
        if 'python3 - "${ENV_FILE}" "${LEGACY_ENV_FILE}"' in source:
            fail("control runtime environment must not double-quote Bash-escaped values")
        if "SECURITY_TRIAGE_ABSENT_PRODUCTS" not in function_body(source, "load_existing_envs") or "s/\\\\+([[:space:],()])/\\1/g" not in function_body(source, "load_existing_envs"):
            fail("control runtime environment must migrate legacy escaping in known non-secret list fields")
        control_sshd = function_body(source, "harden_control_sshd")
        if "ssh-keygen -A" not in control_sshd or "sshd -t" not in control_sshd:
            fail("fresh control hosts must generate missing SSH host keys before validation")
        for control_security_guard in (
            'if HIDE_CONTROL_ORIGIN:\n        logger.info("Hidden-origin mode: legacy direct SPA listener is disabled")',
            'bind_host="127.0.0.1"',
            'ExecStart=${VENV_DIR}/bin/python -m uvicorn main:app --host ${bind_host} --port 8000 --no-access-log',
            'restore_bin="${IPTABLES_RESTORE_BIN:-iptables-restore}"',
            '"${restore_bin}" --wait 10 --test --noflush',
            '"${restore_bin}" --wait 10 < "${snapshot}"',
            "ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0",
            'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-0}"',
            "local -a nfqueue_target=(-j NFQUEUE --queue-num 0)",
            "nfqueue_target+=(--queue-bypass)",
            'data["runmode"] = "autofp"',
            'threading["detect-thread-ratio"] = round(min(1.0, 4.0 / cpu_count), 3)',
            "suricata_max_mb=$((mem_total_mb * 50 / 100))",
            "wait_for_suricata",
            "check_security_headers",
            "advertises-double-vpn-with-zero-exits",
            "Content-Security-Policy \"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\" always",
            'Cache-Control "no-store" always',
            "os.chmod(SECURITY_EVENTS_DB, 0o600)",
            "os.chmod(EVENTS_DB, 0o600)",
            'chmod 600 "${DB_PATH}"',
        ):
            if control_security_guard not in source:
                fail(f"control IDS/IPS guard changed: {control_security_guard}")
        if "-j NFQUEUE --queue-num 0 --queue-bypass" in source:
            fail("control NFQUEUE must fail closed unless the explicit recovery override is enabled")
        for queue_activation_guard in (
            "systemctl is-active --quiet suricata.service",
            "systemctl show suricata.service -p ExecStart --value",
            "-q[[:space:]]+0",
        ):
            if queue_activation_guard not in function_body(source, "write_iptables"):
                fail(
                    "control firewall must not activate NFQUEUE before the "
                    f"reviewed inline Suricata service is ready: {queue_activation_guard}"
                )
        control_firewall_calls = list(
            re.finditer(r"^[ \t]*write_iptables(?:[ \t]|$)", main, re.MULTILINE)
        )
        control_dns_call = re.search(
            r"^[ \t]*write_cloudflare_hub_dns(?:[ \t]|$)", main, re.MULTILINE
        )
        # Three calls: an early fail-closed bootstrap pass (before any
        # network-facing service starts), then the pre-/post-Suricata pair.
        # Public DNS must only be published after the final, inline-IPS pass.
        if len(control_firewall_calls) != 3 or control_dns_call is None \
                or control_dns_call.start() < control_firewall_calls[-1].start():
            fail(
                "control public DNS must be published only after the final, "
                "inline-IPS firewall activation"
            )
        for backup_guard in (
            'mktemp -d "${RUNTIME_ROOT}/wins-hub-backup.XXXXXX"',
            "trap cleanup EXIT HUP INT TERM",
            "cat > /usr/local/bin/wins-hub-db-snapshot",
            'sqlite3 "${DB_SOURCE}" ".timeout 30000" ".backup',
            'PREPARED_DB_SNAPSHOT="${WINS_HUB_DB_SNAPSHOT_PATH:-/run/wins-hub-db-snapshot/vpn_users.db}"',
            'install -m 600 "${PREPARED_DB_SNAPSHOT}" "${DB_SNAPSHOT}"',
            "PRAGMA quick_check;",
            'rclone cryptcheck "${UPLOAD_DIR}" "${REMOTE}" --one-way',
            "tar --dereference --hard-dereference",
            'ARCHIVE_TAR="${WORK_DIR}/wins-hub-backup.tar"',
            "--transform='s#^#./#'",
            '-C "${SOURCE_ROOT}" -cf "${ARCHIVE_TAR}" "${present_sources[@]}"',
            'tar --hard-dereference -C "${PAYLOAD_DIR}" -rf "${ARCHIVE_TAR}"',
            'gzip -n -c -- "${ARCHIVE_TAR}" > "${ARCHIVE}"',
            "Refusing to upload sensitive backup through a non-crypt rclone remote",
            "WINS_HUB_RESTORE_ORDER=fresh-install-then-state",
            "wins-hub-restore-preflight",
            "the target must be a distinct fresh install created after this backup",
            "duplicate normalized archive path",
            "unsafe archive member type",
            "manifest is invalid or names a different artifact",
            "UMask=0077",
            "Requires=wins-hub-db-snapshot.service",
            "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any",
            "ReadWritePaths=/root/vpn_auth /run/wins-hub-db-snapshot",
        ):
            if backup_guard not in source:
                fail(f"control secure backup contract changed: {backup_guard}")
        for hardened_service_writer in (
            "write_systemd",
            "write_threat_triage_engine",
            "write_security_alert_monitor",
        ):
            if "UMask=0077" not in function_body(source, hardened_service_writer):
                fail(f"{hardened_service_writer} must create runtime state with a private umask")
        if re.search(r"TOKEN\s*=.*\bor\s*['\"][0-9a-f]{64}['\"]", source):
            fail("control admin helper must not contain a hard-coded token fallback")
        for admin_auth_guard in (
            "def admin_secret_matches(candidate: Optional[str]) -> bool:",
            "hmac.compare_digest(",
            "if not admin_secret_matches(token):",
            # H-2: node/core registration bootstrap no longer accepts the
            # fleet-wide admin token directly -- it accepts a one-time,
            # single-use grant (minted by /admin/bootstrap-grant against the
            # admin token) exchanged through consume_bootstrap_grant, which
            # must still run the supplied token through a constant-time
            # comparison (hmac.compare_digest) rather than a SQL/string
            # equality on the secret itself. The per-node/per-core routine
            # paths (node_token_matches / core_token_matches) are unchanged.
            # None of these may be replaced by a plain equality check.
            "def consume_bootstrap_grant(",
            "hmac.compare_digest(supplied_digest, row[\"token_hash\"])",
            "consume_bootstrap_grant(conn, payload.bootstrap_token, \"node\", slug)",
            "consume_bootstrap_grant(conn, payload.bootstrap_token, \"core\", core_id)",
            "node_token_matches(",
            "def core_token_matches(stored_hash: Optional[str], supplied: Optional[str]) -> bool:",
            "def require_core_token(conn: sqlite3.Connection, core_id: str, supplied: Optional[str],",
        ):
            if admin_auth_guard not in source:
                fail(f"control constant-time administrator authentication changed: {admin_auth_guard}")
        verify_management_marker = '@app.post("/admin/core/verify-management")'
        verify_management_start = source.find(verify_management_marker)
        if verify_management_start == -1:
            fail("control /admin/core/verify-management endpoint is missing")
        else:
            next_decorator = re.search(
                r"^@app\.",
                source[verify_management_start + len(verify_management_marker):],
                re.MULTILINE,
            )
            verify_management_end = (
                verify_management_start + len(verify_management_marker) + next_decorator.start()
                if next_decorator
                else len(source)
            )
            verify_management_body = source[verify_management_start:verify_management_end]
            # H-2: this routine core-scoped endpoint must be core-token-only.
            # Its only real callers -- probe_hub_core_management's redeploy
            # reuse-check and the deployed wins-core-sync timer agent's
            # verify_management_runtime -- always already hold their own
            # CORE_TOKEN before either can reach it, so an ADMIN_TOKEN
            # fallback here would make the fleet-wide admin token a routine
            # credential again, exactly what H-2 eliminated.
            if "x_admin_token" in verify_management_body:
                fail("control /admin/core/verify-management must not accept x_admin_token")
            if "x_core_token: str = Header(...)" not in verify_management_body:
                fail("control /admin/core/verify-management must require x_core_token")
            if (
                'require_core_token(conn, core_id, x_core_token, request, "verify Core management tunnel")'
                not in verify_management_body
            ):
                fail("control /admin/core/verify-management must call require_core_token")
        if "payload.secret_token != ADMIN_SECRET_TOKEN" in source or "token != ADMIN_SECRET_TOKEN" in source:
            fail("control administrator secrets must not use ordinary string equality")
        if "/usr/local/bin/wins-suricata-prune-rules \"${rules_dir}/suricata.rules\"" in source:
            fail("control deployment must not prune forensic IDS evidence")
        disable_blocks = [
            block.body for block in parse_heredocs(SCRIPTS["control"])
            if "/etc/suricata/disable.conf" in block.header
        ]
        if not disable_blocks or any("ET EXPLOIT" in body or "ET WEB_SERVER" in body for body in disable_blocks):
            fail("Suricata disable.conf must not discard exploit-probe evidence")
        for contract_literal in (
            '"client_ip": config_client_ip',
            '"tunnel_gateway_ipv4": config_tunnel_gateway_ipv4',
            '"client_private_key": device_cfg["client_private_key"]',
            '"client_public_key": device_cfg["client_public_key"]',
            '"server_public_key": config_server_public_key',
            '"server_endpoint": config_server_endpoint',
            '"stealth_gateway_endpoint": config_stealth_endpoint',
            '"stealth_active": login.stealth_mode',
            '"double_vpn_active": bool(double_vpn_requested)',
            '"mtu": 1280',
            '"dns": config_dns',
            '"local_port": 42110',
            '"remote_awg_host": "127.0.0.1"',
            '"xray": xray_config',
            '"dynamic_node_config": True',
            '"client_key_generation_required": True',
        ):
            if contract_literal not in source:
                fail(f"control/client VPN contract changed: {contract_literal}")
        for tunnel_gateway_guard in (
            "def normalize_private_tunnel_gateway_ipv4(",
            'tunnel_gateway_ipv4=COALESCE(NULLIF(excluded.tunnel_gateway_ipv4, \'\'), nodes.tunnel_gateway_ipv4)',
            'tunnel_gateway_ipv4=COALESCE(NULLIF(excluded.tunnel_gateway_ipv4, \'\'), core_servers.tunnel_gateway_ipv4)',
            'core["tunnel_gateway_ipv4"]',
            "AND tunnel_gateway_ipv4 IS NOT NULL AND tunnel_gateway_ipv4 != ''",
            'detail="Double VPN core is missing a valid tunnel gateway registration."',
            'detail="Selected VPN route is missing a valid tunnel gateway registration."',
            '"tunnelgatewayipv4": vpn_config["tunnel_gateway_ipv4"]',
        ):
            if tunnel_gateway_guard not in source:
                fail(f"control dynamic tunnel-gateway contract changed: {tunnel_gateway_guard}")
        if "core.get(" in source:
            fail("control Double VPN config must use sqlite3.Row indexing, not dict.get")
        for platform_alias in ('"iphone": "ios"', '"ipad": "ios"', '"win32": "windows"', '"darwin": "macos"'):
            if platform_alias not in source:
                fail(f"control platform normalization changed: {platform_alias}")
        for split_platform_guard in (
            'consumer_per_app = normalized in {"android", "windows", "linux"}',
            '"launcher_cgroup"',
            '"per_app_split_tunnel_requires_launcher": normalized == "linux"',
            '"per_app_split_tunnel_mdm_only": apple',
        ):
            if split_platform_guard not in source:
                fail(f"control split-tunnel capability truth changed: {split_platform_guard}")
        for control_transport_guard in (
            'strict: bool = False',
            'seen_ports: dict[int, str] = {}',
            'port {port} cannot be both TLS and plaintext',
            'the first ordered transport must match the primary port/security',
            'Invalid Xray transports: {exc}',
            'Invalid core Xray transports: {exc}',
        ):
            if control_transport_guard not in source:
                fail(f"control dynamic Xray registration guard changed: {control_transport_guard}")
        if source.count("strict=True,") < 2:
            fail("control node and core registration must both strictly validate ordered Xray transports")
        for capacity_guard in (
            'MAX_NODE_MAX_PEERS = 60000',
            'conn.execute("BEGIN IMMEDIATE")',
            'def node_capacity_snapshot(',
            'def node_accepts_new_peer(',
            'consumes_new_slot and not node_accepts_new_peer(conn, node)',
            'runtime_limit = customer_limit + NODE_RUNTIME_PEER_RESERVE',
            'serialize_peer_mutation=True',
            'flock -w 10 9',
            "Data-plane peer admission lock timed out",
            "Data-plane peer ceiling reached",
            'for x in range(1, VPN_CLIENT_POOL_THIRD_OCTET_MAX + 1):',
            'candidate = f"10.8.255.{y}"',
            'max_peers=excluded.max_peers',
        ):
            if capacity_guard not in source:
                fail(f"control fail-closed node capacity guard changed: {capacity_guard}")
        awg_remote_start = source.find("def remote_awg_exec_command(")
        awg_remote_end = source.find("\ndef normalized_management_ssh_host_keys", awg_remote_start)
        if awg_remote_start < 0 or awg_remote_end < 0:
            fail("control host-side AWG command builder is missing")
        awg_remote_body = source[awg_remote_start:awg_remote_end]
        lock_pos = awg_remote_body.find("flock -w 10 9")
        docker_exec_pos = awg_remote_body.find("docker exec -i")
        if lock_pos < 0 or docker_exec_pos < 0:
            fail("control host-side AWG peer admission lock is incomplete")
        if lock_pos > docker_exec_pos:
            fail("control host-side AWG peer admission lock must precede docker exec")
        remove_peer_start = source.find("def remove_peer_from_node(")
        remove_peer_end = source.find("\ndef ", remove_peer_start + 1)
        if remove_peer_start < 0 or remove_peer_end < 0:
            fail("control AWG peer removal helper is missing")
        remove_peer_body = source[remove_peer_start:remove_peer_end]
        if "serialize_peer_mutation=True" not in remove_peer_body:
            fail("control AWG peer removal must share the peer admission lock")
        if source.find('for x in range(1, VPN_CLIENT_POOL_THIRD_OCTET_MAX + 1):') > source.find('candidate = f"10.8.255.{y}"'):
            fail("ordinary VPN allocation and Double VPN exit pools are no longer explicitly separated")
    elif name == "data":
        data_packages = function_body(source, "apt_install")
        # Round EX2 OI-EX2-4: one provider image shipped without logrotate, so
        # /etc/logrotate.d/wins-suricata never ran. It must be a named package
        # of the main install command, not only a fallback elsewhere.
        package_command = re.search(
            r'^[ \t]*apt_retry "\$\{APT_GET\[@\]\}" install -y \\\n((?:.*\\\n)*.*)$',
            data_packages,
            re.MULTILINE,
        )
        if not package_command:
            fail("data package installation lost its main apt install command")
        elif "logrotate" not in package_command.group(1).replace("\\", " ").split():
            fail("data package installation must install logrotate so Suricata logs rotate")
        if "util-linux" not in data_packages:
            fail("data package installation must explicitly provide flock through util-linux")
        if "conntrack" not in data_packages:
            fail("data package installation must provide conntrack for fail-safe release route guards")
        assert_order(
            main,
            "data main",
            [
                "require_root",
                "preflight_data_plane",
                "check_not_hub",
                "mark_data_role",
                "apt_install",
                "configure_docker_dns",
                "configure_luks_root_policy",
                "configure_swap_policy",
                "configure_partial_vault",
                "configure_performance_mode",
                "configure_dmcrypt_performance",
                "configure_rclone_credentials",
                "collect_inputs",
                "bootstrap_node_token",
                "fetch_hub_pubkey",
                "configure_node_management_tunnel",
                "setup_sysctl",
                "install_awg",
                "install_xray",
                "install_adguard",
                "write_nginx",
                "install_data_ids_ips",
                "remove_legacy_smart_boost",
                "write_register_script",
                "write_firewall",
                "harden_sshd",
                "publish_stealth_dns",
                "write_diagnose_script",
                "write_canary_script",
                "write_backup_script",
                "write_backup_timer",
                "write_embedded_rclone_config",
                "write_suricata_update_timer",
                "write_weekly_maintenance",
                "postflight_data_plane",
                "mark_data_deployment_ready",
                "run_initial_backup",
            ],
        )
        swap_policy = function_body(source, "configure_swap_policy")
        for swap_guard in (
            'local fstab_path="${WINS_FSTAB_PATH:-/etc/fstab}"',
            'swapoff "${swap_src}"',
            "Unable to disable unencrypted swap",
            "remove persisted swap entries",
            "Unencrypted swap remains active after data-plane hardening",
        ):
            if swap_guard not in swap_policy:
                fail(f"data plaintext-swap remediation changed: {swap_guard}")
        management_calls = list(
            re.finditer(
                r"^[ \t]*verify_hub_node_management(?:[ \t]|$)",
                main,
                re.MULTILINE,
            )
        )
        if len(management_calls) != 2:
            fail("data main must verify the outbound management path exactly twice")
        ordered_calls = {
            step: re.search(
                rf"^[ \t]*{re.escape(step)}(?:[ \t]|$)",
                main,
                re.MULTILINE,
            )
            for step in (
                "configure_node_management_tunnel",
                "write_register_script",
                "write_firewall",
                "harden_sshd",
                "publish_stealth_dns",
                "write_diagnose_script",
            )
        }
        if any(match is None for match in ordered_calls.values()):
            fail("data main lacks a required management-path ordering step")
        if not (
            ordered_calls["configure_node_management_tunnel"].start()
            < ordered_calls["write_register_script"].start()
            < management_calls[0].start()
            < ordered_calls["write_firewall"].start()
            < ordered_calls["harden_sshd"].start()
            < management_calls[1].start()
            < ordered_calls["publish_stealth_dns"].start()
            < ordered_calls["write_diagnose_script"].start()
        ):
            fail(
                "data main must verify management before closing direct SSH and "
                "again after firewall/sshd hardening"
            )
        for required in (
            # The data-plane installer may use the persisted per-node random
            # assignment, but must retain 9110 as the final fallback.
            # MTU 1280 is the 2026-09-20 owner decision: cellular-path
            # compatibility outranks the 1440 packet-rate optimization.
            r'WG_PORT_DEFAULT="\${WG_PORT_DEFAULT:-\${WINS_ASSIGNED_WG_PORT:-9110}}"',
            r'AWG_MTU_DEFAULT="\${AWG_MTU:-1280}"',
            r'STEALTH_ORIGIN_PORT_DEFAULT="\${STEALTH_ORIGIN_PORT_DEFAULT:-80}"',
            r'STEALTH_PUBLIC_PORT_DEFAULT="\${STEALTH_PUBLIC_PORT_DEFAULT:-80}"',
            r'XRAY_SECURITY_DEFAULT="\${XRAY_SECURITY_DEFAULT:-none}"',
            r'VPN_UDP_RATE_LIMIT="\${VPN_UDP_RATE_LIMIT:-0}"',
            r'NODE_MAX_PEERS_DEFAULT="\${NODE_MAX_PEERS:-auto}"',
        ):
            if not re.search(required, source):
                fail(f"data-plane transport contract changed: {required}")
        if "SmartBoostEngine" in source or "cat > /usr/local/sbin/wins-boostd" in source:
            fail("parked Smart Boost code returned to the stable data-plane path")
        if "--privileged" in source:
            fail("data-plane AWG container must not run with Docker --privileged")
        if "PostUp = sysctl -w net.ipv4.ip_forward=1" in source:
            fail("data-plane AWG config must not mutate host sysctls from its container")
        # H-3: the AWG container never needs the kernel module path (awg-quick
        # falls back to userspace amneziawg-go whenever the module isn't
        # loaded, which it never is in this container), so SYS_MODULE and the
        # host /lib/modules mount must stay gone; --cap-drop=ALL, --read-only,
        # and read-only config mounts must stay present.
        if re.search(r"--cap-add[= \t]+SYS_MODULE", source):
            fail("data-plane AWG container must not hold CAP_SYS_MODULE")
        if "/lib/modules:/lib/modules" in source:
            fail("data-plane AWG container must not mount the host kernel module tree")
        awg_run_body = function_body(source, "install_awg")
        for awg_hardening_guard in (
            "--cap-drop=ALL",
            "--cap-add=NET_ADMIN",
            "--read-only",
            "--tmpfs /run:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m",
            # Audit improvement 2026-10-14: the CPU quota is sized from the host
            # (all cores but one, minimum 2) instead of a fixed 2.
            '--pids-limit 256 --memory 1g --cpus "$(( $(nproc) > 2 ? $(nproc) - 1 : 2 ))"',
            "-v /etc/amnezia/amneziawg:/etc/wireguard:ro",
        ):
            if awg_hardening_guard not in awg_run_body:
                fail(f"data-plane AWG container hardening changed: {awg_hardening_guard}")
        if "chmod 600 /etc/amnezia/amneziawg/awg0.conf" not in source:
            fail("data-plane AWG private-key config must be mode 600")
        if "sed -n 's/^XRAY_UUID=" not in source or '"${NODE_ENV_FILE}" | tail -n 1' not in source:
            fail("data-plane reruns must preserve the existing Xray UUID")
        if "ADGUARD_DNS_BIND_DEFAULT=\"${ADGUARD_DNS_BIND:-10.8.1.1}\"" not in source:
            fail("data-plane AdGuard DNS must default to the private VPN gateway")
        adguard_config = function_body(source, "write_adguard_config")
        adguard_install = function_body(source, "install_adguard")
        if "    - 0.0.0.0" in adguard_config:
            fail("data-plane AdGuard DNS must not listen on every public interface")
        if "systemctl is-active --quiet AdGuardHome.service" not in adguard_install:
            fail("data-plane AdGuard install must verify service readiness")
        for dns_policy_guard in (
            'ADGUARD_PRIMARY_DOH_DEFAULT="${ADGUARD_PRIMARY_DOH:-https://dns.quad9.net/dns-query}"',
            'ADGUARD_OPENDNS_FALLBACK_DOH_DEFAULT="${ADGUARD_OPENDNS_FALLBACK_DOH:-https://dns.opendns.com/dns-query}"',
            'ADGUARD_RATE_LIMIT_QPS_DEFAULT="${ADGUARD_RATE_LIMIT_QPS:-100}"',
            'ADGUARD_HOME_VERSION_DEFAULT="${ADGUARD_HOME_VERSION:-0.107.79}"',
            'ADGUARD_HOME_LINUX_AMD64_SHA256_DEFAULT="${ADGUARD_HOME_LINUX_AMD64_SHA256:-c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f}"',
            'DNS4EU_COMMERCIAL_DOH_URL_DEFAULT="${DNS4EU_COMMERCIAL_DOH_URL:-}"',
            "validate_adguard_dns_policy || return 1",
            "schema_version: 34",
            "upstream_mode: load_balance",
            "enable_dnssec: true",
            "ratelimit: ${ADGUARD_RATE_LIMIT_QPS_DEFAULT}",
            "ratelimit_subnet_len_ipv4: 32",
            "ratelimit_subnet_len_ipv6: 128",
            "refuse_any: true",
            "protection_enabled: true",
            "filtering_enabled: true",
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "AdGuardHome_linux_amd64.tar.gz",
            "Pinned AdGuard Home v${ADGUARD_HOME_VERSION_DEFAULT} archive checksum mismatch.",
            "ExecStart=/opt/AdGuardHome/AdGuardHome -s run",
            "ProtectSystem=full",
            # IA-DP-03: rendered into a temporary file and renamed over the
            # path, never written through it (the service user owns it).
            "chmod 600 \"${config_tmp}\"",
            "mv -f -T -- \"${config_tmp}\" \"${config_path}\"",
            ".rules_count > 0",
        ):
            if dns_policy_guard not in source:
                fail(f"data-plane deterministic DNS policy changed: {dns_policy_guard}")
        for forbidden_dns_policy in (
            "86.54.11.13",
            "upstream_mode: parallel",
            "94.140.14.14",
            "94.140.15.15",
            "https://dns.adguard-dns.com/dns-query",
        ):
            if forbidden_dns_policy in source:
                fail(f"data-plane contains forbidden DNS policy value: {forbidden_dns_policy}")
        if "write_adguard_config /opt/AdGuardHome/AdGuardHome.yaml" not in adguard_install:
            fail("data-plane install must render the reviewed AdGuard policy")
        for capacity_guard in (
            "calculate_node_max_peers() {",
            "NODE_MAX_PEERS_HARD_LIMIT=60000",
            'write_env_kv NODE_MAX_PEERS "${NODE_MAX_PEERS}"',
            '--argjson max_peers "${NODE_MAX_PEERS}"',
            'max_peers: $max_peers',
            "node_status_from_pressure() {",
            "MemAvailable:",
            "memory_floor_kb=$((mem_total_kb / 10))",
        ):
            if capacity_guard not in source:
                fail(f"data-plane dynamic capacity contract changed: {capacity_guard}")
        for tunnel_gateway_guard in (
            'tunnel_gateway_ipv4="$(awk -F=',
            '--arg tunnel_gateway_ipv4 "${tunnel_gateway_ipv4}"',
            'tunnel_gateway_ipv4: $tunnel_gateway_ipv4',
        ):
            if tunnel_gateway_guard not in source:
                fail(f"data-plane dynamic tunnel-gateway contract changed: {tunnel_gateway_guard}")
        data_nginx_capacity = function_body(source, "configure_nginx_capacity")
        data_nginx_runtime = function_body(source, "verify_nginx_capacity_runtime")
        data_preflight = function_body(source, "preflight_data_plane")
        for nginx_capacity_guard in (
            'DATA_NGINX_WORKER_CONNECTIONS="${DATA_NGINX_WORKER_CONNECTIONS:-${NGINX_WORKER_CONNECTIONS:-32768}}"',
            'DATA_NGINX_WORKER_NOFILE_LIMIT="${DATA_NGINX_WORKER_NOFILE_LIMIT:-${NGINX_WORKER_NOFILE_LIMIT:-65535}}"',
            'DATA_NGINX_PROXY_HEADROOM_PERCENT="${DATA_NGINX_PROXY_HEADROOM_PERCENT:-${NGINX_PROXY_HEADROOM_PERCENT:-20}}"',
            'NGINX_WORKER_CONNECTIONS="${DATA_NGINX_WORKER_CONNECTIONS}"',
            'write_env_kv DATA_NGINX_WORKER_CONNECTIONS "${DATA_NGINX_WORKER_CONNECTIONS}"',
            "nginx_effective_proxy_capacity() {",
            "Each reverse-proxied WebSocket consumes a client and an upstream socket.",
            'xray_capacity="$(nginx_effective_proxy_capacity)"',
            "exceeds effective Nginx Xray/WebSocket capacity",
            'write_env_kv NGINX_WORKER_CONNECTIONS "${NGINX_WORKER_CONNECTIONS}"',
            'limit_conn wins_xray_total ${NODE_MAX_PEERS};',
            "limit_conn_status 503;",
        ):
            if nginx_capacity_guard not in source:
                fail(f"data-plane Nginx admission-capacity contract changed: {nginx_capacity_guard}")
        for nginx_capacity_guard in (
            "worker_processes auto;",
            "worker_connections {connections};",
            "worker_rlimit_nofile {nofile};",
            'limit_conn_zone $server_name zone=wins_xray_total:1m;',
            "LimitNOFILE=${NGINX_WORKER_NOFILE_LIMIT}",
            "systemctl daemon-reload",
        ):
            if nginx_capacity_guard not in data_nginx_capacity:
                fail(f"data-plane Nginx runtime tuning changed: {nginx_capacity_guard}")
        for nginx_runtime_guard in (
            'systemctl show nginx.service -p LimitNOFILE --value',
            'grep -Fxq \'limit_conn_zone $server_name zone=wins_xray_total:1m;\'',
        ):
            if nginx_runtime_guard not in data_nginx_runtime:
                fail(f"data-plane Nginx postflight capacity proof changed: {nginx_runtime_guard}")
        for nginx_preflight_guard in (
            'validate_nginx_capacity_inputs "${NGINX_WORKER_CONNECTIONS}"',
            'calculate_node_max_peers "${NODE_MAX_PEERS_DEFAULT}" >/dev/null',
        ):
            if nginx_preflight_guard not in data_preflight:
                fail(f"data-plane Nginx pre-mutation capacity validation changed: {nginx_preflight_guard}")
        for readiness_guard in (
            'rm -f "${NODE_DEPLOYMENT_READY_FILE_DEFAULT}"',
            'NODE_STATUS="maintenance"',
            "publish_stealth_dns() {",
            "mark_data_deployment_ready() {",
            "Final online node registration failed; the node remains in maintenance.",
        ):
            if readiness_guard not in source:
                fail(f"data-plane fail-closed publication gate changed: {readiness_guard}")
        for peer_runtime_resync_guard in (
            "container_started_at=\"$(docker inspect --format '{{.State.StartedAt}}'",
            'peer_runtime_marker="${peer_runtime_dir}/node-peer-runtime"',
            'runtime_identity="${active_awg_container}:${container_started_at:-${boot_id}}"',
            ".ok == true and (.failed // 0) == 0",
        ):
            if peer_runtime_resync_guard not in source:
                fail(
                    "data-plane boot/container peer resync contract changed: "
                    f"{peer_runtime_resync_guard}"
                )
        for adguard_boot_guard in (
            "ExecStartPre=/usr/local/sbin/wins-wait-vpn-dns-address",
            "Wants=docker.service",
        ):
            if adguard_boot_guard not in adguard_install:
                fail(f"data-plane AdGuard boot guard changed: {adguard_boot_guard}")
        if "http:\n  address: 127.0.0.1:3000" not in adguard_config:
            fail("data-plane AdGuard admin UI must remain loopback-only")
        if 'HUB_API_BASE="http://' in source or 'http://${IONOS_HUB_IP}/api/v1/' in source:
            fail("data-plane admin-token traffic must not default or fall back to plaintext HTTP")
        for edge_ips_guard in (
            "INSTALL_DATA_IDS_IPS_DEFAULT",
            "ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0",
            # Owner ruling, incident CS2 (2026-09-25): data planes fail open.
            'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-1}"',
            "local -a nfqueue_target=(-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0)",
            "nfqueue_target+=(--queue-bypass)",
            'data["runmode"] = "autofp"',
            'threading["detect-thread-ratio"] = round(min(1.0, 4.0 / cpu_count), 3)',
            # Lane L43: one constant ceiling, no memory.high throttle, refusal
            # below 3584 MiB, nfq fail-open, and the queue stall watchdog.
            "WINS_SURICATA_MEMORY_MAX_MB=1536",
            "WINS_SURICATA_MIN_HOST_MEMTOTAL_MB=3584",
            "printf 'infinity %sM\\n' \"${WINS_SURICATA_MEMORY_MAX_MB}\"",
            "Restart=on-failure",
            'data["nfq"]["fail-open"] = fail_open',
            "write_suricata_nfq_watchdog",
            "systemctl is-active --quiet wins-suricata-nfq-watchdog.service",
            # Round SU: memory gate before config changes, shared firewall
            # lock, record-aware persistence, probe path, inline postflight.
            "wins_suricata_memory_gate || return 1",
            'wins_fw_lock || { err "The shared firewall lock is unavailable; active rules were not changed."; return 1; }',
            'wins_fw_persistable_save iptables-save > "${firewall_tmp}"',
            'wins_fw_persistable_save "${IPTABLES_SAVE_BIN}" > "${tmp}"',
            'ipt -A WINVPN-INPUT -i lo -p tcp --dport "${WINS_NFQ_PROBE_PORT}" -j WINVPN-NFQ-PROBE',
            'ipt -A WINVPN-NFQ-PROBE -m mark --mark 0x40000000/0x40000000 -j ACCEPT',
            "wins_postflight_inline_ips || return 1",
            # Round SU turn 2: a failed watchdog hand-off undoes the rebuild and
            # persists nothing; the re-removal keeps the record until it succeeds.
            "Queue watchdog hand-off failed while fail-open was in force; restoring the pre-rebuild ruleset and persisting nothing.",
            "locked do_remove rebuilt",
            "wait_for_suricata",
            'PUBLIC_VPN_INGRESS_ADMISSION="${PUBLIC_VPN_INGRESS_ADMISSION:-0}"',
            'DATA_NFQUEUE_PROC_PATH:-/proc/net/netfilter/nfnetlink_queue',
            "Data-plane public VPN ingress remains closed because inline Suricata queue 0 is not healthy.",
            'ipt -A WINVPN-INPUT -p udp --dport "${WG_PORT}" -j ACCEPT',
            'EnvironmentFile=-/etc/winsvpn/public-vpn-ingress-admission.env',
            "set_public_vpn_ingress_admission 0",
            "set_public_vpn_ingress_admission 1",
            "Could not persist final public admission; the bootstrap-closed firewall was restored.",
            "Final public VPN ingress admission was not committed.",
        ):
            if edge_ips_guard not in source:
                fail(f"data-plane inline IDS/IPS guard changed: {edge_ips_guard}")
        # Owner ruling CS2: the installer's top-level default (written to
        # node.env) and the generated wins-edge-hardening's own default are
        # separate copies; a whole-file match is satisfied by either alone.
        if source.count('SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-1}"') != 2 \
                or "SURICATA_NFQUEUE_FAIL_OPEN:-0}" in source:
            fail("data-plane installer and wins-edge-hardening must both default SURICATA_NFQUEUE_FAIL_OPEN to 1 (owner ruling CS2)")
        # Known issue 1: the WAN fq qdisc does not survive a reboot, so
        # wins-edge-queues.service must be enabled and wanted at boot, and the
        # calibrated flow_limit must stay 32768 (the runtime suite reads it
        # back from the kernel; 131072 / 32768 is the limits in the supplied Canada
        # measurement records, tunnel-speed round 2, Turn 14).
        queues_unit = re.search(
            r"cat > /etc/systemd/system/wins-edge-queues\.service <<'EOF_QUEUES'\n(.*?)\nEOF_QUEUES\n",
            source,
            re.S,
        )
        queues_install = re.search(r"^\[Install\]\n(.*?)(?=^\[|\Z)", queues_unit.group(1) if queues_unit else "", re.M | re.S)
        if (
            queues_unit is None
            or "ExecStart=/usr/local/bin/wins-edge-hardening --queues-only" not in queues_unit.group(1).splitlines()
            or queues_install is None
            or "WantedBy=multi-user.target" not in queues_install.group(1).splitlines()
            or "\n  systemctl enable wins-edge-queues.service\n" not in source
            or 'local fq_flow="32768"' not in function_body(source, "apply_wan_qdisc")
            or 'local fq_lim="131072"' not in function_body(source, "apply_wan_qdisc")
        ):
            fail("data-plane boot-time queue reapply (wins-edge-queues.service, WAN fq limit 131072 flow_limit 32768) changed")
        if "-j NFQUEUE --queue-num 0 --queue-bypass" in source:
            fail("data-plane NFQUEUE must fail closed unless the explicit recovery override is enabled")
        assert_order(
            source,
            "data-plane public stealth queue-before-accept ordering",
            [
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"',
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" -j ACCEPT',
            ],
        )
        # Round SU: a kernel fail-open accept ends INPUT traversal, so the
        # Cloudflare-only restriction must be staged ahead of the queue rules
        # and the watchdog probe path ahead of the loopback ACCEPT.
        assert_order(
            source,
            "data-plane Cloudflare-only restriction before NFQUEUE",
            [
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" -j WINVPN-CF-STEALTH',
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"',
            ],
        )
        # Round EX2: TCP 443 is accepted directly above the queue rules, behind
        # the Cloudflare-only restriction; its NFQUEUE rule stays below.
        early_443 = "ipt -A WINVPN-INPUT -p tcp --dport 443 -j ACCEPT"
        if len(re.findall(rf"^[ \t]*{re.escape(early_443)}$", source, re.MULTILINE)) != 1:
            fail("data-plane must emit exactly one early TCP 443 ACCEPT")
        # The postflight's 443 expectation comes from the build's own predicate.
        for ex2_guard in (
            "    if ex2_443_bypass_expected; then\n      " + early_443 + "\n",
            'if [[ "${1:-}" == "--expects-443-bypass" ]]; then',
            'expect443="$(/usr/local/bin/wins-edge-hardening --expects-443-bypass)" || {',
            '"$(wins_inline_route_counters "${route_port}")" "${expect443}" || return 1',
        ):
            if ex2_guard not in source:
                fail(f"data-plane Round EX2 443 bypass contract changed: {ex2_guard.strip()}")
        assert_order(
            source,
            "data-plane TCP 443 accept between the Cloudflare-only restriction and NFQUEUE",
            [
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" -j WINVPN-CF-STEALTH',
                early_443,
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"',
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" -j ACCEPT',
            ],
        )
        assert_order(
            source,
            "data-plane queue watchdog probe before the loopback ACCEPT",
            [
                'ipt -A WINVPN-INPUT -i lo -p tcp --dport "${WINS_NFQ_PROBE_PORT}" -j WINVPN-NFQ-PROBE',
                "ipt -A WINVPN-INPUT -i lo -j ACCEPT",
            ],
        )
        for backup_guard in (
            'mktemp -d "${RUNTIME_ROOT}/wins-node-backup.XXXXXX"',
            "trap cleanup EXIT HUP INT TERM",
            'rclone cryptcheck "${UPLOAD_DIR}" "${REMOTE}" --one-way',
            "Refusing to upload sensitive backup through a non-crypt rclone remote",
            "UMask=0077",
        ):
            if backup_guard not in source:
                fail(f"data-plane secure backup contract changed: {backup_guard}")
        for deterministic_xray_guard in (
            'XRAY_VERSION_DEFAULT="${XRAY_VERSION:-26.9.30}"',
            'Xray-linux-64.zip',
            'Pinned Xray v${XRAY_VERSION_DEFAULT} archive checksum mismatch',
            '[[ "${installed_xray_version}" == "${XRAY_VERSION_DEFAULT}" ]]',
        ):
            if deterministic_xray_guard not in source:
                fail(f"data-plane Xray supply-chain guard changed: {deterministic_xray_guard}")
        data_xray_dropins = [
            block.body for block in parse_heredocs(SCRIPTS["data"])
            if "xray.service.d/20-winsvpn-user.conf" in block.header
        ]
        if len(data_xray_dropins) != 1:
            fail("data-plane must generate exactly one reviewed Xray hardening drop-in")
        for xray_hardening_guard in (
            "User=xray",
            "Group=xray",
            "StateDirectory=xray",
            "LogsDirectory=xray",
            "UMask=0077",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ReadWritePaths=/var/log/xray /var/lib/xray",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectControlGroups=true",
            "ProtectClock=true",
            "ProtectHostname=true",
            "RestrictSUIDSGID=true",
            "RestrictNamespaces=true",
            "LockPersonality=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ):
            if xray_hardening_guard not in data_xray_dropins[0]:
                fail(
                    "data-plane Xray least-privilege sandbox changed: "
                    f"{xray_hardening_guard}"
                )
        for dynamic_transport_guard in (
            'STEALTH_TRANSPORTS_DEFAULT="${STEALTH_TRANSPORTS:-${STEALTH_PUBLIC_PORT_DEFAULT}:${XRAY_SECURITY_DEFAULT},443:tls}"',
            'Transport port ${port} cannot be both TLS and plaintext.',
            'done < <(tr \',\' \'\\n\' <<<"${STEALTH_TRANSPORTS}")',
            'local route="${STEALTH_TRANSPORTS:-${STEALTH_PUBLIC_PORT:-80}:${XRAY_SECURITY:-none}}"',
            'public_health_url "127.0.0.1" "${port}" "${security}"',
            'stealth_transports: $stealth_transports',
            'edge_hub_call POST origin-certificate',
            'data_refuse_node_fleet_credentials || exit 1',
            'data_require_subject_credential || exit 1',
            'node_origin_cert_valid',
            'Cloudflare Origin CA cannot issue an IP-address certificate',
        ):
            if dynamic_transport_guard not in source:
                fail(f"data-plane dynamic transport contract changed: {dynamic_transport_guard}")
        if re.search(r'XRAY_SECURITY[^\n]*==\s*"tls"[^\n]*\|\|[^\n]*\$\{?port\}?[^\n]*==\s*"443"', source):
            fail("data-plane health checks must not infer TLS from TCP port 443")
        for collected_value_guard in (
            'valid_port "${WG_PORT}" || { err "WG_PORT is invalid."; exit 1; }',
            'valid_port "${STEALTH_PUBLIC_PORT}" || { err "STEALTH_PUBLIC_PORT is invalid."; exit 1; }',
            'valid_port "${XRAY_INBOUND_PORT}" || { err "XRAY_INBOUND_PORT is invalid."; exit 1; }',
            'XRAY_SECURITY must be none or tls.',
        ):
            if collected_value_guard not in source:
                fail(f"data-plane collected transport validation changed: {collected_value_guard}")
        for awg_identity_guard in (
            'AWG_CONTAINER_NAME_DEFAULT="${AWG_CONTAINER_NAME:-amnezia-awg2}"',
            '/etc/amnezia/amneziawg/awg0.conf',
            'awg show awg0 public-key',
        ):
            if awg_identity_guard not in source:
                fail(f"data-plane AmneziaWG identity changed: {awg_identity_guard}")
        nginx = function_body(source, "write_nginx")
        for nginx_security_guard in (
            "server_tokens off;",
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            "add_header Content-Security-Policy \"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\" always;",
            'add_header Cache-Control "no-store" always;',
            "default_type text/plain;",
        ):
            if nginx_security_guard not in nginx:
                fail(f"data-plane Nginx security-header contract changed: {nginx_security_guard}")
        if "add_header Content-Type text/plain" in nginx:
            fail("data-plane health location must not suppress inherited security headers")
        # Winn v3 gateway UDP is accepted behind both guards and ahead of every
        # NFQUEUE rule, and never queued; only its TLS-only TCP cover is queued
        # (lane L8, 2026-09-23). One resolver reads the listener file, and
        # postflight runs the edge script's own check after its final rebuild.
        if 'ipt -A WINVPN-INPUT -p udp --dport "${WINN3_GATEWAY_LISTEN_PORT}" "${nfqueue_target[@]}"' in source:
            fail("data-plane firewall must never queue Winn v3 gateway UDP to NFQUEUE")
        assert_order(
            source,
            "data-plane Winn v3 UDP accept-before-NFQUEUE ordering",
            [
                "ipt -A WINVPN-INPUT -j WINVPN-SSH-RECOVERY",
                "ipt -A WINVPN-INPUT -j WINVPN-LOCAL-SERVING",
                'ipt -A WINVPN-INPUT -p udp --dport "${WINN3_GATEWAY_LISTEN_PORT}" -j ACCEPT',
                'ipt -A WINVPN-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"',
            ],
        )
        assert_order(
            source,
            "data-plane Winn v3 TCP cover queue-before-accept ordering",
            [
                'ipt -A WINVPN-INPUT -p tcp --dport "${WINN3_GATEWAY_LISTEN_PORT}" "${nfqueue_target[@]}"',
                'ipt -A WINVPN-INPUT -p tcp --dport "${WINN3_GATEWAY_LISTEN_PORT}" -j ACCEPT',
            ],
        )
        if source.count("winn3_gateway_resolve() {") != 1 or source.count('source "${WINN3_GATEWAY_ENV_FILE}"') != 1 \
                or 'listen="$(source "${WINN3_GATEWAY_ENV_FILE}" >&2' not in source:
            fail("data-plane Winn v3 gateway listener must be read by one resolver, sourced only in its subshell")
        if source.count("winn3_udp_policy_check() {") != 1 or "--check-winn3-udp-policy" not in source:
            fail("data-plane edge script lost its Winn v3 UDP policy check")
        postflight_start = source.find("\npostflight_data_plane() {\n")
        postflight = source[postflight_start:source.find("\n}\n", postflight_start)]
        rebuild_at = postflight.find("\n  /usr/local/bin/wins-edge-hardening\n")
        check_at = postflight.find("\n  /usr/local/bin/wins-edge-hardening --check-winn3-udp-policy || {\n")
        register_at = postflight.find("\n  /usr/local/bin/wins-node-register\n")
        if postflight_start < 0 or not (0 <= rebuild_at < check_at < register_at):
            fail("data-plane postflight must run the Winn v3 UDP policy check right after its final rebuild")
    elif name == "core":
        assert_order(
            main,
            "core main",
            [
                "as_root",
                "preflight_core",
                "verify_disk_encryption_posture",
                "mark_core_role",
                "apt_install",
                "configure_swap_policy",
                "configure_docker_dns",
                "configure_performance_mode",
                "configure_dmcrypt_performance",
                "setup_sysctl",
                "load_or_create_env",
                "fetch_hub_management_pubkey",
                "prepare_core_ssh_authorized_keys",
                "configure_core_management_tunnel",
                "verify_hub_core_management",
                "install_awg_ingress",
                "install_awg_exit_if_configured",
                "install_xray",
                "write_nginx",
                "install_core_ids_ips",
                "write_firewall",
                "harden_sshd",
                "cloudflare_upsert_core_stealth_record",
                "write_core_sync_agent",
                "install_local_ai_support",
                "write_diagnose",
                "write_suricata_update_timer",
                "postflight_core",
            ],
        )
        swap_policy = function_body(source, "configure_swap_policy")
        for swap_guard in (
            'local fstab_path="${WINS_FSTAB_PATH:-/etc/fstab}"',
            'swapoff "${swap_src}"',
            "Unable to disable unencrypted Core swap",
            "remove persisted swap entries",
            "Unencrypted swap remains active after Core hardening",
            "refuse_disk_swap_request || return 1",
        ):
            if swap_guard not in swap_policy:
                fail(f"Core plaintext-swap remediation changed: {swap_guard}")
        # H-3: Core's three AmneziaWG containers (static ingress, static exit,
        # and the sync agent's dynamic per-assignment exit) were already
        # cap-drop/read-only hardened; only their config bind mounts were
        # still read-write. Lock that in so it can't silently regress.
        for awg_core_fn, awg_core_mount in (
            ("install_awg_ingress", "-v /etc/amnezia/wins-core:/etc/wireguard:ro"),
            ("install_awg_exit_if_configured", "-v /etc/amnezia/wins-core:/etc/wireguard:ro"),
            ("ensure_exit_iface", '-v "${CORE_SYNC_STATE_DIR}:/etc/wireguard:ro"'),
        ):
            awg_core_body = function_body(source, awg_core_fn)
            for awg_core_guard in (
                "--cap-drop ALL",
                "--cap-add NET_ADMIN",
                "--read-only",
                awg_core_mount,
            ):
                if awg_core_guard not in awg_core_body:
                    fail(f"Core {awg_core_fn} AWG container hardening changed: {awg_core_guard}")
        core_xray_units = [
            block.body for block in parse_heredocs(SCRIPTS["core"])
            if (
                "/etc/systemd/system/xray.service <<" in block.header
                or "wins-core-xray-exit@.service <<" in block.header
            )
        ]
        if len(core_xray_units) != 2:
            fail("Core must generate reviewed primary and fallback Xray units")
        for xray_hardening_guard in (
            "User=xray",
            "Group=xray",
            "StateDirectory=xray",
            "LogsDirectory=xray",
            "UMask=0077",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ReadWritePaths=/var/log/xray /var/lib/xray",
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectKernelLogs=true",
            "ProtectControlGroups=true",
            "ProtectClock=true",
            "ProtectHostname=true",
            "RestrictSUIDSGID=true",
            "RestrictNamespaces=true",
            "LockPersonality=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ):
            if not all(xray_hardening_guard in unit for unit in core_xray_units):
                fail(
                    "Core Xray least-privilege sandbox changed: "
                    f"{xray_hardening_guard}"
                )
        core_management_calls = list(
            re.finditer(
                r"^[ \t]*verify_hub_core_management(?:[ \t]|$)",
                main,
                re.MULTILINE,
            )
        )
        if len(core_management_calls) != 2:
            fail("core main must verify the outbound management path exactly twice")
        core_ordered_calls = {
            step: re.search(
                rf"^[ \t]*{re.escape(step)}(?:[ \t]|$)",
                main,
                re.MULTILINE,
            )
            for step in (
                "configure_core_management_tunnel",
                "write_firewall",
                "harden_sshd",
                "cloudflare_upsert_core_stealth_record",
                "write_core_sync_agent",
            )
        }
        if any(match is None for match in core_ordered_calls.values()):
            fail("core main lacks a required management-path ordering step")
        if not (
            core_ordered_calls["configure_core_management_tunnel"].start()
            < core_management_calls[0].start()
            < core_ordered_calls["write_firewall"].start()
            < core_ordered_calls["harden_sshd"].start()
            < core_management_calls[1].start()
            < core_ordered_calls["cloudflare_upsert_core_stealth_record"].start()
            < core_ordered_calls["write_core_sync_agent"].start()
        ):
            fail(
                "core main must verify management before closing direct SSH and "
                "again after firewall/sshd hardening"
            )
        for required in (
            r'CORE_OPEN_PUBLIC_INGRESS="\${CORE_OPEN_PUBLIC_INGRESS:-1}"',
            r'CORE_STEALTH_ORIGIN_PORT="\${CORE_STEALTH_ORIGIN_PORT:-80}"',
            r'CORE_STEALTH_TRANSPORTS="\${CORE_STEALTH_TRANSPORTS:-\${CORE_STEALTH_ORIGIN_PORT}:\${CORE_XRAY_SECURITY},443:tls}"',
            r"printf 'CORE_STEALTH_ORIGIN_PORT=%q",
            r"printf 'CORE_STEALTH_TRANSPORTS=%q",
            r'CORE_UDP_RATE_LIMIT="\${CORE_UDP_RATE_LIMIT:-0}"',
            r'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="\${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-90}"',
            r'CORE_EXIT_HANDSHAKE_MAX_AGE_SECONDS="\${CORE_EXIT_HANDSHAKE_MAX_AGE_SECONDS:-150}"',
            r'CORE_EXIT_RECOVERY_COOLDOWN_SECONDS="\${CORE_EXIT_RECOVERY_COOLDOWN_SECONDS:-300}"',
            r'CORE_AI_ENABLED="\${CORE_AI_ENABLED:-0}"',
            r'CORE_MANAGEMENT_TUNNEL_ENABLED_DEFAULT="\${CORE_MANAGEMENT_TUNNEL_ENABLED:-1}"',
        ):
            if not re.search(required, source):
                fail(f"core transport contract changed: {required}")
        if 'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS="${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS:-45}"' in source:
            fail("core transport contract regressed to the undersized 45-second handshake timeout")
        core_validation = function_body(source, "preflight_core")
        for timeout_guard in (
            '"${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS}" -ge 5',
            '"${CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS}" -le 120',
            'CORE_EXIT_HANDSHAKE_TIMEOUT_SECONDS must be between 5 and 120.',
        ):
            if timeout_guard not in core_validation:
                fail(f"core handshake-timeout validation bounds changed: {timeout_guard}")
        for dynamic_core_guard in (
            'Core transport port ${port} cannot be both TLS and plaintext.',
            '--argjson stealth_transports "${stealth_transports_json}"',
            'stealth_transports:$stealth_transports',
            'done < <(tr \',\' \'\\n\' <<<"${CORE_STEALTH_TRANSPORTS}")',
            'core_edge_hub_call POST origin-certificate',
            'core_refuse_node_fleet_credentials || exit 1',
            'core_require_subject_credential || exit 1',
            'core_origin_cert_valid',
            'request_acme_core_dns_certificate',
            'winsvpn-core-origin',
            'Hub-brokered Core Origin CA request failed',
            'Cloudflare Origin CA cannot issue an IP-address certificate',
            'load_existing_core_env_for_preflight',
            'default_core_stealth_host',
            'cloudflare_upsert_core_stealth_record',
            'core_edge_hub_call POST dns',
            'wins-core-management-tunnel.service',
            'CORE_MANAGEMENT_TUNNEL_BOOTSTRAP_URL',
            'CORE_MANAGEMENT_VERIFY_URL',
            'verify_management_runtime',
            'AllowTcpForwarding no',
            'DisableForwarding yes',
            "printf 'restrict %s\\n'",
            '"${install_path}" tunnel run --help 2>&1 | grep -F -- \'--token-file\' >/dev/null',
            'CORE_AI_HUB_SSH_HOST="${CORE_AI_HUB_SSH_HOST:-}"',
            'CORE_AI_TUNNEL_KNOWN_HOSTS="${CORE_AI_TUNNEL_KNOWN_HOSTS:-/root/.ssh/wins_ai_hub_known_hosts}"',
            "CORE_AI_ENABLED requires an explicit protected DNS CORE_AI_HUB_SSH_HOST",
            'printf \'x-core-token: %s\\n\' "${CORE_TOKEN}" > "${registration_dir}/core-header"',
            '-H @"${registration_dir}/core-header"',
            'StrictHostKeyChecking=yes',
            'UserKnownHostsFile="${CORE_AI_TUNNEL_KNOWN_HOSTS}"',
            'GlobalKnownHostsFile=/dev/null',
            'UpdateHostKeys=no',
            'ProtectSystem=strict',
            'hub_curl() {',
            'curl --config <(printf \'header = "x-core-token: %s"\\n\' "${CORE_TOKEN}") "$@"',
            'tunnel_gateway_ipv4="${CORE_INGRESS_ADDR%%/*}"',
            '--arg tunnel_gateway_ipv4 "${tunnel_gateway_ipv4}"',
            'tunnel_gateway_ipv4:$tunnel_gateway_ipv4',
            'recover_stale_exit_handshake() {',
            'recovering stale stealth handshake (Xray first, AWG second)',
            'systemctl restart "wins-core-xray-exit@${iface}.service"',
            'docker restart "${container}"',
            'Core handshake recovery failed class=exit_handshake_recovery_non_stealth',
            'Core handshake recovery failed class=exit_handshake_recovery_cooldown',
            'Core handshake recovery failed class=exit_handshake_recovery_stamp_create_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_stamp_write_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_stamp_permissions_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_stamp_install_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_xray_restart_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_xray_inactive',
            'Core handshake recovery failed class=exit_handshake_recovery_container_restart_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_interface_missing_after_restart',
            'Core handshake recovery failed class=exit_handshake_recovery_route_metadata_invalid',
            'Core handshake recovery failed class=exit_handshake_recovery_route_restore_failed',
            'Core handshake recovery failed class=exit_handshake_recovery_timeout',
            'recover_stale_exit_handshake "${iface}" "${container}" "${state_mode}" || {',
            'Core runtime validation failed class=exit_handshake_recovery_failed',
        ):
            if dynamic_core_guard not in source:
                fail(f"core dynamic transport contract changed: {dynamic_core_guard}")
        core_ai = function_body(source, "install_local_ai_support")
        if "StrictHostKeyChecking=accept-new" in core_ai:
            fail("Core AI tunnel must not trust an unverified first-seen SSH host key")
        if '-H "x-admin-token: ${ADMIN_TOKEN}"' in core_ai:
            fail("Core AI tunnel must not expose its admin token in curl process arguments")
        if '-H "x-admin-token: ${ADMIN_TOKEN}"' in source:
            fail("Core deployment must not expose its admin token in curl process arguments")
        nginx = function_body(source, "write_nginx")
        for nginx_security_guard in (
            "server_tokens off;",
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            "add_header Content-Security-Policy \"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\" always;",
            'add_header Cache-Control "no-store" always;',
            "default_type text/plain;",
        ):
            if nginx_security_guard not in nginx:
                fail(f"core Nginx security-header contract changed: {nginx_security_guard}")
        if "add_header Content-Type text/plain" in nginx:
            fail("core health location must not suppress inherited security headers")
        core_nginx_capacity = function_body(source, "configure_nginx_capacity")
        core_nginx_runtime = function_body(source, "verify_nginx_capacity_runtime")
        core_preflight = function_body(source, "preflight_core")
        for nginx_capacity_guard in (
            'CORE_NGINX_WORKER_CONNECTIONS="${CORE_NGINX_WORKER_CONNECTIONS:-${NGINX_WORKER_CONNECTIONS:-32768}}"',
            'CORE_NGINX_WORKER_NOFILE_LIMIT="${CORE_NGINX_WORKER_NOFILE_LIMIT:-${NGINX_WORKER_NOFILE_LIMIT:-65535}}"',
            'CORE_NGINX_PROXY_HEADROOM_PERCENT="${CORE_NGINX_PROXY_HEADROOM_PERCENT:-${NGINX_PROXY_HEADROOM_PERCENT:-20}}"',
            'NGINX_WORKER_CONNECTIONS="${CORE_NGINX_WORKER_CONNECTIONS}"',
            'CORE_MAX_XRAY_CONNECTIONS="${CORE_MAX_XRAY_CONNECTIONS:-auto}"',
            "resolve_core_xray_connection_limit() {",
            "Each reverse-proxied WebSocket consumes a client and an upstream socket.",
            "printf 'CORE_MAX_XRAY_CONNECTIONS=%q\\n'",
            "printf 'CORE_NGINX_WORKER_CONNECTIONS=%q\\n'",
            'limit_conn wins_xray_total ${CORE_MAX_XRAY_CONNECTIONS};',
            "limit_conn_status 503;",
        ):
            if nginx_capacity_guard not in source:
                fail(f"core Nginx admission-capacity contract changed: {nginx_capacity_guard}")
        for nginx_capacity_guard in (
            "worker_processes auto;",
            "worker_connections {connections};",
            "worker_rlimit_nofile {nofile};",
            'limit_conn_zone $server_name zone=wins_xray_total:1m;',
            "LimitNOFILE=${NGINX_WORKER_NOFILE_LIMIT}",
            "systemctl daemon-reload",
        ):
            if nginx_capacity_guard not in core_nginx_capacity:
                fail(f"core Nginx runtime tuning changed: {nginx_capacity_guard}")
        for nginx_runtime_guard in (
            'systemctl show nginx.service -p LimitNOFILE --value',
            'grep -Fxq \'limit_conn_zone $server_name zone=wins_xray_total:1m;\'',
        ):
            if nginx_runtime_guard not in core_nginx_runtime:
                fail(f"core Nginx postflight capacity proof changed: {nginx_runtime_guard}")
        for nginx_preflight_guard in (
            'validate_nginx_capacity_inputs "${NGINX_WORKER_CONNECTIONS}"',
            'resolve_core_xray_connection_limit "${CORE_MAX_XRAY_CONNECTIONS}" >/dev/null',
        ):
            if nginx_preflight_guard not in core_preflight:
                fail(f"core Nginx pre-mutation capacity validation changed: {nginx_preflight_guard}")
        firewall = function_body(source, "write_firewall")
        core_ips = function_body(source, "install_core_ids_ips")
        core_ips_runtime = function_body(source, "verify_core_suricata_runtime")
        for core_ips_guard in (
            'INSTALL_CORE_IDS_IPS_DEFAULT="${INSTALL_CORE_IDS_IPS:-1}"',
            'SURICATA_NFQUEUE_FAIL_OPEN_DEFAULT="${SURICATA_NFQUEUE_FAIL_OPEN:-0}"',
            'ExecStartPre=/bin/rm -f /var/run/suricata/suricata-command.socket',
            'ExecStart=/usr/bin/suricata -D --pidfile /run/suricata.pid -q 0',
            'data["unix-command"] = {"enabled": True, "filename": "/var/run/suricata/suricata-command.socket"}',
            '"eve-log"',
            'suricata_max_mb=$((mem_total_mb * 50 / 100))',
            'expected=$\'drop:9920001\\ndrop:9920002\\ndrop:9920003\\ndrop:9920004\\ndrop:9920005\'',
        ):
            if core_ips_guard not in source:
                fail(f"Core inline IDS/IPS contract changed: {core_ips_guard}")
        for queue_guard in (
            'local -a nfqueue_target=(-m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 0)',
            'systemctl is-active --quiet suricata.service',
            'suricatasc -c uptime',
            'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT',
            'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -p tcp --dport "${stealth_port}" "${nfqueue_target[@]}"',
            'local public_vpn_ingress_admission="${2:-${PUBLIC_VPN_INGRESS_ADMISSION:-0}}"',
            '&& "${public_vpn_ingress_admission}" == "1"',
            "Core public VPN ingress cannot be admitted without inline Suricata IDS/IPS.",
        ):
            if queue_guard not in firewall:
                fail(f"Core NFQUEUE ownership/readiness contract changed: {queue_guard}")
        # NFQUEUE must never appear in WINVPN-CORE-FORWARD. core0/coreexit0
        # are themselves AmneziaWG tunnel interfaces, so traffic crossing this
        # chain is the DECRYPTED inner payload of a "Double VPN" relay hop --
        # queuing it to Suricata would let a signature match log the
        # customer's real, decrypted second-hop destination, a privacy
        # regression versus the single-hop data-plane node's own precedent
        # (NFQUEUE there sits only on WINVPN-INPUT, pre-decryption). An
        # earlier revision queued this chain's traffic scoped by CIDR/exit
        # interface to work around NFQUEUE's ACCEPT verdict being terminal
        # for the hook (empirically confirmed with an isolated
        # network-namespace relay and a real NFQUEUE consumer, against both
        # the nft- and legacy-backed iptables: a queued, ACCEPTed packet
        # never re-enters this chain's remaining rules) -- that shape is
        # gone entirely now, not just reordered, so guard against either
        # form of it reappearing.
        forward_body = re.search(
            r'core_restore_rule "\$\{filter_body\}" -A WINVPN-CORE-FORWARD -s "\$\{CORE_INGRESS_CIDR\}".*?'
            r'core_restore_rule "\$\{filter_body\}" -A WINVPN-CORE-FORWARD -j DROP',
            firewall,
            re.DOTALL,
        )
        if not forward_body:
            fail("Core WINVPN-CORE-FORWARD rule block not found in the expected shape")
        if "NFQUEUE" in forward_body.group(0) or "nfqueue_target" in forward_body.group(0):
            fail("Core WINVPN-CORE-FORWARD must never queue relayed (decrypted) traffic to Suricata/NFQUEUE")
        assert_order(
            firewall,
            "Core inline ingress and service ordering",
            [
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-INPUT -s "${CORE_ADMIN_CIDR}" -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT',
            ],
        )
        assert_order(
            firewall,
            "Core inline relay and established-flow ordering",
            [
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -s "${CORE_INGRESS_CIDR}" -d "${CORE_INGRESS_CIDR}" -j REJECT --reject-with icmp-port-unreachable',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -p tcp --dport 25 -j DROP',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -p udp -s "${CORE_INGRESS_CIDR}" -m hashlimit --hashlimit-above "${CORE_UDP_RATE_LIMIT}" --hashlimit-burst "${CORE_UDP_RATE_BURST}" --hashlimit-mode srcip --hashlimit-name wins_core_udp -j DROP',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE}" -s "${CORE_INGRESS_CIDR}" -j ACCEPT',
            ],
        )
        assert_order(
            firewall,
            "Core client relay, NAT, and MSS ordering",
            [
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE}" -s "${CORE_INGRESS_CIDR}" -j ACCEPT',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE_PREFIX}+" -s "${CORE_INGRESS_CIDR}" -j ACCEPT',
                'core_restore_rule "${filter_body}" -A WINVPN-CORE-FORWARD -j DROP',
                'iptables -t nat -C POSTROUTING -j WINVPN-CORE-NAT 2>/dev/null || core_restore_rule "${nat_body}" -I POSTROUTING 1 -j WINVPN-CORE-NAT',
                'core_restore_rule "${nat_body}" -A WINVPN-CORE-NAT -s "${CORE_INGRESS_CIDR}" -o "${CORE_EXIT_IFACE}" -j MASQUERADE',
                'core_restore_rule "${nat_body}" -A WINVPN-CORE-NAT -s "${CORE_INGRESS_CIDR}" -o "${CORE_EXIT_IFACE_PREFIX}+" -j MASQUERADE',
                'core_tcp_mss="$(core_tcp_mss_for_mtu "${CORE_AWG_MTU}")"',
                'core_restore_rule "${mangle_body}" -A WINVPN-CORE-MANGLE -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((core_tcp_mss + 1)):65535" -j TCPMSS --set-mss "${core_tcp_mss}"',
            ],
        )
        if "-j NFQUEUE --queue-num 0 --queue-bypass" in source:
            fail("Core NFQUEUE must fail closed unless the explicit recovery override is enabled")
        for runtime_guard in (
            "systemctl is-enabled --quiet wins-suricata-update.timer",
            "/usr/local/bin/wins-suricata-action-policy",
            "suricata -T -c /etc/suricata/suricata.yaml",
            "MemoryMax is missing or outside the reviewed 768-1536 MiB bound",
            'iptables -C WINVPN-CORE-INPUT -p udp --dport "${CORE_INGRESS_PORT}" -j ACCEPT',
            'Decrypted Core relay traffic must never enter NFQUEUE.',
            "Core NFQUEUE unexpectedly permits fail-open bypass",
        ):
            if runtime_guard not in core_ips_runtime:
                fail(f"Core Suricata runtime verifier changed: {runtime_guard}")
        block_position = firewall.find("--dport 25 -j DROP")
        fast_path_position = firewall.find('-A WINVPN-CORE-FORWARD -i "${CORE_INGRESS_IFACE}" -o "${CORE_EXIT_IFACE}"')
        if block_position < 0 or fast_path_position < 0 or block_position > fast_path_position:
            fail("core abuse blocks must precede broad core-to-exit forwarding")
        if "-i docker0 -j ACCEPT" in source or "-o docker0 -j ACCEPT" in source:
            fail("core firewall must not permit unrestricted docker0 forwarding")
        if 'http://hub.winsvpn.org' in source:
            fail("core admin-token traffic must not default to plaintext HTTP")

    if name in {"data", "core"}:
        if "amneziavpn/amneziawg-go:latest" in source or "metaligh/amneziawg:latest" in source:
            fail(f"{name} AmneziaWG image must not use a mutable upstream tag")
        if "raw.githubusercontent.com/XTLS/Xray-install/main/" in source:
            fail(f"{name} script uses an unpinned Xray installer branch")
        if name == "core":
            for guard in (
                'XRAY_VERSION="${XRAY_VERSION:-26.9.30}"',
                "Xray-linux-64.zip",
                "Pinned Xray v${XRAY_VERSION} archive checksum mismatch",
                'ALLOW_RAW_HUB_ORIGIN="${ALLOW_RAW_HUB_ORIGIN:-0}"',
                "hub_api_uses_raw_origin() {",
                "Refusing to send the Core token to a raw control-hub IP",
            ):
                if guard not in source:
                    fail(f"core Xray supply-chain guard changed: {guard}")


def validate_defaults_template() -> None:
    source = DEFAULTS_TEMPLATE.read_text(encoding="utf-8")
    for variable in (
        "IONOS_HUB_IP",
        "ADMIN_TOKEN",
        "SMTP_USER",
        "SMTP_PASS",
        "PAYPAL_CLIENT_SECRET",
        "CLOUDFLARE_APPCLOUD_API_TOKEN",
        "CLOUDFLARE_WINS_API_TOKEN",
        "CLOUDFLARE_TUNNEL_API_TOKEN",
        "CLOUDFLARE_ACCESS_API_TOKEN",
        "REQUIRE_CLOUDFLARE_ACCESS",
        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID",
        "TUNNEL_SERVICE_TOKEN_ID",
        "TUNNEL_SERVICE_TOKEN_SECRET",
        "WG_PORT_DEFAULT",
        "SURICATA_MIN_VERSION",
        "STEALTH_ORIGIN_PORT_DEFAULT",
        "CORE_INGRESS_PORT",
        "CORE_MANAGEMENT_VERIFY_ATTEMPTS",
        "CORE_MANAGEMENT_VERIFY_INTERVAL_SECONDS",
        "CORE_MANAGEMENT_REUSE_PROBE_ATTEMPTS",
        "APT_ALLOW_REMOVALS",
        "ALLOW_INSECURE_HUB_HTTP",
        "ALLOW_RAW_HUB_ORIGIN",
        "ALLOW_UNENCRYPTED_SWAPFILE",
        "ENABLE_ZRAM_SWAP",
        "ZRAM_SWAP_PERCENT",
        "ZRAM_SWAP_MAX_MB",
        "HUB_SSH_PASSWORD_AUTH",
        "HUB_ALLOW_GLOBAL_SSH",
        "AWG_DOCKER_IMAGES",
        "ADGUARD_DNS_BIND",
        "ADGUARD_PRIMARY_DOH",
        "ADGUARD_OPENDNS_FALLBACK_DOH",
        "ADGUARD_HOME_VERSION",
        "ADGUARD_HOME_LINUX_AMD64_SHA256",
        "DNS4EU_COMMERCIAL_DOH_URL",
        "STRICT_ONE_TOUCH_SECRETS",
        "REQUIRE_REMOTE_BACKUP",
        "RCLONE_REMOTE",
        "NGINX_WORKER_CONNECTIONS",
        "NGINX_WORKER_NOFILE_LIMIT",
        "DATA_NGINX_WORKER_CONNECTIONS",
        "DATA_NGINX_WORKER_NOFILE_LIMIT",
        "DATA_NGINX_PROXY_HEADROOM_PERCENT",
        "CORE_NGINX_WORKER_CONNECTIONS",
        "CORE_NGINX_WORKER_NOFILE_LIMIT",
        "CORE_NGINX_PROXY_HEADROOM_PERCENT",
        "CORE_MAX_XRAY_CONNECTIONS",
        "PUBLIC_CANARY_ATTEMPTS",
        "PUBLIC_CANARY_INTERVAL_SECONDS",
    ):
        if not re.search(rf"^{re.escape(variable)}=", source, re.MULTILINE):
            fail(f".env.example is missing current deployment variable {variable}")
    # L41: data planes and Cores hold no Cloudflare credential; the hub edge
    # broker is the only holder of the app-zone token.
    for stale in ("SMTP_USERNAME=", "SMTP_PASSWORD=", "ADMIN_SECRET_TOKEN=",
                  "CLOUDFLARE_API_TOKEN=", "CLOUDFLARE_ZONE_ID=", "CLOUDFLARE_ACCOUNT_ID="):
        if stale in source:
            fail(f".env.example contains stale deployment variable {stale[:-1]}")
    for hardened_default in (
        "RUN_YABS=0",
        "APT_ALLOW_REMOVALS=0",
        "ALLOW_INSECURE_HUB_HTTP=0",
        "ALLOW_RAW_HUB_ORIGIN=0",
        "ALLOW_UNENCRYPTED_SWAPFILE=0",
        "ENABLE_ZRAM_SWAP=1",
        "ZRAM_SWAP_PERCENT=50",
        "ZRAM_SWAP_MAX_MB=2048",
        "HUB_SSH_PASSWORD_AUTH=0",
        "HUB_ALLOW_GLOBAL_SSH=0",
        "NGINX_WORKER_CONNECTIONS=8192",
        "NGINX_WORKER_NOFILE_LIMIT=65535",
        "DATA_NGINX_WORKER_CONNECTIONS=32768",
        "DATA_NGINX_WORKER_NOFILE_LIMIT=65535",
        "DATA_NGINX_PROXY_HEADROOM_PERCENT=20",
        "CORE_NGINX_WORKER_CONNECTIONS=32768",
        "CORE_NGINX_WORKER_NOFILE_LIMIT=65535",
        "CORE_NGINX_PROXY_HEADROOM_PERCENT=20",
        "CORE_MAX_XRAY_CONNECTIONS=auto",
        "PUBLIC_CANARY_ATTEMPTS=6",
        "PUBLIC_CANARY_INTERVAL_SECONDS=10",
        "STEALTH_ORIGIN_PORT_DEFAULT=80",
        "STEALTH_PUBLIC_PORT_DEFAULT=80",
        "XRAY_SECURITY_DEFAULT=none",
        "CORE_AI_ENABLED=0",
        "ADGUARD_DNS_BIND=10.8.1.1",
        "ADGUARD_PRIMARY_DOH=https://dns.quad9.net/dns-query",
        "ADGUARD_OPENDNS_FALLBACK_DOH=https://dns.opendns.com/dns-query",
        "ADGUARD_HOME_VERSION=0.107.79",
        "ADGUARD_HOME_LINUX_AMD64_SHA256=c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f",
    ):
        if hardened_default not in source:
            fail(f".env.example is missing hardened default {hardened_default}")

    preseed_source = (ROOT / "tools" / "wins_deployment_preseed.ps1").read_text(encoding="utf-8")
    for data_preseed_guard in (
        "'DNS4EU_COMMERCIAL_DOH_URL'",
        "'RCLONE_CONFIG_B64', 'REQUIRE_REMOTE_BACKUP'",
        "required backup credentials",
    ):
        if data_preseed_guard not in preseed_source:
            fail(f"data-plane one-touch preseed backup contract changed: {data_preseed_guard}")
    # L41: no role file for a data plane or Core may carry a Cloudflare
    # credential; the hub edge broker performs every node edge operation.
    for node_credential in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ACCOUNT_ID"):
        if f"-Name '{node_credential}'" in preseed_source:
            fail(f"one-touch preseed still writes {node_credential} into a data/core role file")
    refresh_source = (ROOT / "tools" / "refresh_live_role_secrets.ps1").read_text(encoding="utf-8")
    if "CLOUDFLARE_API_TOKEN" in refresh_source or "CLOUDFLARE_APPCLOUD_API_TOKEN" in refresh_source:
        fail("live role secret refresh still pushes a Cloudflare credential to a data plane or Core")
    # L41 Round CF: no data or core role file carries the fleet ADMIN_TOKEN.
    if "ADMIN_TOKEN = [string]$values.ADMIN_TOKEN" in refresh_source:
        fail("live role secret refresh still pushes the fleet ADMIN_TOKEN to a data plane or Core")
    if "fleet_credential_in_role_content" not in refresh_source:
        fail("live role secret refresh lost its remote refusal of fleet credentials")
    for role_guard in (
        "throw \"$selectedRole preseed must not carry ADMIN_TOKEN.\"",
        "function Read-SubjectSecretFragment",
    ):
        if role_guard not in preseed_source:
            fail(f"one-touch preseed fleet-credential role contract changed: {role_guard}")
    if "'StrictHostKeyChecking=yes'" not in preseed_source:
        fail("one-touch deployment must require a pre-verified SSH host key")
    if "StrictHostKeyChecking=accept-new" in preseed_source:
        fail("one-touch deployment must not trust an unverified first-seen SSH host key")
    for pretransfer_swap_guard in (
        "before SCP transfers the role-scoped",
        "$SUDO swapoff -a",
        "Active swap remains; refusing to transfer deployment credentials.",
        "Invoke-ExternalChecked -FilePath 'scp'",
    ):
        if pretransfer_swap_guard not in preseed_source:
            fail(f"one-touch pre-secret remote swap guard changed: {pretransfer_swap_guard}")
    if preseed_source.find("$SUDO swapoff -a") > preseed_source.find("Invoke-ExternalChecked -FilePath 'scp'"):
        fail("one-touch deployment must disable remote swap before SCP transfers secrets")
    for cloudflare_preseed_guard in (
        "'SetCloudflareAppCloudToken'",
        "'RepairCloudflareAppCloudFallback'",
        "function Read-DeploymentSecret",
        "Read-Host -Prompt $Prompt -AsSecureString",
        "ZeroFreeBSTR",
        "Clipboard input requires explicit -SecretFromClipboard",
        "zones?name=app-cloud-sync.net&status=active",
        'expression = "(not ssl and not ((http.host in {$hostSet}) and '
        '(http.request.uri.path in {$pathSet})))"',
        "refusing to create a zone-wide path-only exception",
    ):
        if cloudflare_preseed_guard not in preseed_source:
            fail(
                "app-cloud-sync.net credential/redirect preseed contract changed: "
                f"{cloudflare_preseed_guard}"
            )

    tunnel_import_start = preseed_source.find("function Set-CloudflareTunnelToken {")
    tunnel_import_end = preseed_source.find("function Set-CloudflareAccessToken {")
    if tunnel_import_start < 0 or tunnel_import_end <= tunnel_import_start:
        fail("Cloudflare Tunnel token importer is missing")
    tunnel_import = preseed_source[tunnel_import_start:tunnel_import_end]
    for tunnel_import_guard in (
        "Read-DeploymentSecret",
        "WINS_CLOUDFLARE_TUNNEL_API_TOKEN",
        "$probeJson.PSObject.Properties['result']",
        "$probeStatus -notin 400, 422",
        "Stored a verified Cloudflare Tunnel Edit token in the DPAPI preseed without printing it.",
    ):
        if tunnel_import_guard not in tunnel_import:
            fail(
                "Cloudflare Tunnel credential import contract changed: "
                f"{tunnel_import_guard}"
            )

    for environment_name in (
        "WINS_CLOUDFLARE_TUNNEL_API_TOKEN",
        "WINS_CLOUDFLARE_ACCESS_API_TOKEN",
        "WINS_CLOUDFLARE_APPCLOUD_API_TOKEN",
    ):
        if preseed_source.count(environment_name) != 1:
            fail(
                "each Cloudflare secret action must use exactly one explicit "
                f"unattended environment input: {environment_name}"
            )
    helper_start = preseed_source.find("function Read-DeploymentSecret {")
    helper_end = preseed_source.find("function New-CryptographicHexSecret {")
    if helper_start < 0 or helper_end <= helper_start:
        fail("protected deployment-secret input helper is missing")
    secret_helper = preseed_source[helper_start:helper_end]
    for helper_guard in (
        "if ($SecretFromStdin -and $SecretFromClipboard)",
        "[EnvironmentVariableTarget]::Process",
        "[Environment]::SetEnvironmentVariable(",
        "if ($SecretFromClipboard)",
        "Get-Clipboard -Raw",
        "Clear-ClipboardSecret",
        "Read-Host -Prompt $Prompt -AsSecureString",
        "ZeroFreeBSTR",
    ):
        if helper_guard not in secret_helper:
            fail(f"deployment secret input hardening changed: {helper_guard}")

    data_source = SCRIPTS["data"].read_text(encoding="utf-8")
    control_source = SCRIPTS["control"].read_text(encoding="utf-8")
    # L41 Round CF: the hub edge broker renders exact (hostname, path) pairs,
    # never independent host and path sets whose product widens exceptions.
    for pair_guard in (
        """clauses = " or ".join(f'(http.host eq "{host}" and http.request.uri.path eq "{path}")' for host, path in unique)""",
        'expression = f"(not ssl and not ({clauses}))"',
        "edge_verify_recorded_state(current, auh, live)",
        "edge_lease_fence(lease)",
        "def require_edge_admin_token(",
        "edge_require_inventory(conn)",
        # Round CF Turn 2: every Cloudflare call re-checks lease and assignment.
        "class EdgeGuard:",
        "def edge_cf_guarded(",
        "guard = EdgeGuard(lease, kind, subject, hosts)",
        # Round CF Turn 3: exception pairs pin their hostname; commit rechecks.
        "pins = edge_exceptions_naming(conn, host)",
        "def edge_remove_exceptions_locked(",
        "a hostname in this transaction is no longer assigned to this subject".capitalize(),
        # Round CF Turn 4: commit judges the transaction's original opened set.
        '"SELECT hostname, state FROM edge_plaintext_exceptions WHERE transaction_id = ?",',
        'if any(pair["state"] != "armed" for pair in opened):',
        # Round CF Turn 5: a repeat request opens no zero-pair transaction, and
        # a zero-pair transaction left by older code settles on commit.
        'return {"ok": True, "transaction_id": None, "state": "committed", "added": 0, "hostnames": hosts, "path": path}',
        'return {"ok": True, "state": "committed", "settled_empty": True}',
        # Round CF Turn 6: an open transaction is handed back only on an exact match.
        "and txn_pairs == wanted):",
        # Round CF Turn 7: the subject's open transactions come from the
        # transaction table, before the all-committed no-op reply.
        "WHERE subject_kind = ? AND subject_id = ? AND state = 'armed' ORDER BY transaction_id\",",
    ):
        if pair_guard not in control_source:
            fail(f"hub edge broker pair/transaction contract changed: {pair_guard}")
    if "SELECT hostname FROM edge_plaintext_exceptions WHERE transaction_id = ? AND state = 'armed'" in control_source:
        fail("hub edge broker commit rechecks only the still-armed pairs; it must recheck every pair the transaction opened")
    if 'edge_close_transaction(transaction_id, "armed")\n' in control_source:
        fail("hub edge broker opens a zero-pair transaction for a repeat exception request; it must be idempotent")
    if "(http.host in {" in control_source.split("# --- Hub-brokered edge operations", 1)[-1]:
        fail("hub edge broker renders a host set; exceptions must be exact pairs")
    for redirect_source_label, redirect_source in (("data-plane", data_source), ("hub edge broker", control_source)):
        if "http.request.scheme" in redirect_source:
            fail(f"{redirect_source_label} Cloudflare redirect uses unsupported http.request.scheme field")
    for data_edge_guard in (
        "edge_hub_call POST plaintext-exemption",
        'plaintext-exemption/${CLOUDFLARE_REDIRECT_TXN_ID}/rollback',
        'plaintext-exemption/${CLOUDFLARE_REDIRECT_TXN_ID}/commit',
        "edge_txn_reconcile || return 1",
        'edge_txn_record commit-pending "${CLOUDFLARE_REDIRECT_TXN_ID}"',
        'jq -e \'.state == "committed" and .added == 0\' "${response_file}"',
    ):
        if data_edge_guard not in data_source:
            fail(f"data-plane hub-brokered redirect transaction contract changed: {data_edge_guard}")
    for node_role in ("data", "core"):
        node_source = SCRIPTS[node_role].read_text(encoding="utf-8")
        if "api.cloudflare.com" in node_source:
            fail(f"{node_role} installer must not call the Cloudflare API; the hub edge broker does")
        # Round CF Turn 2: tokens go only to https://<fronted hub hostname>.
        for https_guard in (
            'edge_valid_hub_base "${HUB_API_BASE:-}" ||',
            "--proto '=https' --proto-redir '=https'",
            "curl --config - --proto =https --proto-redir =https",
            "HUB_API_BASE must be https://<fronted hub hostname>; refusing to send the token anywhere else",
        ):
            if https_guard not in node_source:
                fail(f"{node_role} installer edge/hook HTTPS-only contract changed: {https_guard}")
    publish = function_body(data_source, "publish_stealth_dns")
    if not (
        0 <= publish.find("cloudflare_configure_plaintext_stealth_routes")
        < publish.find("hub_upsert_stealth_records")
    ):
        fail("data-plane plaintext redirect must verify before stealth DNS publication")
    main = function_body(data_source, "main")
    # S4: main()'s second EXIT trap is the ordered winn3_installer_exit wrapper,
    # whose last step is the Cloudflare handler (design 2.7 trap bodies).
    exit_wrapper = function_body(data_source, "winn3_installer_exit")
    if 'trap \'winn3_installer_exit "$?" 1\' EXIT' not in main:
        fail("data-plane main must install the ordered winn3_installer_exit trap with the Cloudflare step")
    if "cloudflare_redirect_transaction_on_exit" not in exit_wrapper:
        fail(
            "data-plane Cloudflare redirect transaction guard changed: "
            "cloudflare_redirect_transaction_on_exit"
        )
    if "cloudflare_redirect_transaction_commit" not in main:
        fail(
            "data-plane Cloudflare redirect transaction guard changed: "
            "cloudflare_redirect_transaction_commit"
        )
    redirect_trap = main.find('trap \'winn3_installer_exit "$?" 1\' EXIT')
    dns_publish = main.find("publish_stealth_dns")
    postflight = main.find("postflight_data_plane")
    redirect_commit = main.find("cloudflare_redirect_transaction_commit")
    if not (redirect_trap < dns_publish < postflight < redirect_commit):
        fail("data-plane Cloudflare redirect must remain reversible from publication through postflight")


def validate_xray_tunnel_contracts() -> None:
    for platform, path in CLIENT_XRAY_SOURCES.items():
        source = path.read_text(encoding="utf-8")
        if "dokodemo-door" in source:
            fail(f"{platform} still generates the legacy dokodemo-door inbound")
        for field in (
            "tunnel",
            "network",
            "address",
            "port",
            "followRedirect",
            "userLevel",
        ):
            if field not in source:
                fail(f"{platform} Xray tunnel contract omits {field}")
        for incompatible_field in ("allowedNetwork", "rewriteAddress", "rewritePort"):
            if incompatible_field in source:
                fail(
                    f"{platform} uses Xray prerelease tunnel field "
                    f"{incompatible_field} with the pinned 26.9.30 binary"
                )

    core = SCRIPTS["core"].read_text(encoding="utf-8")
    for guard in (
        'protocol:"tunnel"',
        'settings:{network:"udp",address:"127.0.0.1",port:$remote_awg_port,followRedirect:false,userLevel:0}',
        'mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}',
        'xray -test -config "${tmp}"',
        'existing_stealth_transport_is_healthy',
        'Core exit setup transition class=healthy_stealth_preserved',
        'Core exit setup transition class=direct_fallback_persisted',
    ):
        if guard not in core:
            fail(f"Core Xray native UDP-over-TCP bridge contract changed: {guard}")
    if 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}' in core:
        fail("Core Xray fallback re-enabled incompatible XUDP aggregation")
    if "dokodemo-door" in core:
        fail("Core still generates the legacy dokodemo-door inbound")
    for incompatible_field in ("allowedNetwork", "rewriteAddress", "rewritePort"):
        if incompatible_field in core:
            fail(
                f"Core uses Xray prerelease tunnel field {incompatible_field} "
                "with the pinned 26.9.30 binary"
            )


_REDIRECTED_WINN_PREFLIGHT = re.compile(
    r"preflight_credentials[^\n]*>/dev/null 2>&1[^\n]*\n?[^\n]*then"
)
_WINN_V3_DEFAULT_OFF = 'WINN_PROTOCOL_V3_ENABLE_DEFAULT="${WINN_PROTOCOL_V3_ENABLE:-0}"'
_WINN_V3_REFUSE_FN = "refuse_retired_winn_protocol_v3_enable"
_DATA_MAIN_REFUSE_BEFORE_ROOT = (
    "  refuse_retired_winn_protocol_v3_enable\n"
    "  require_root\n"
    "  preflight_data_plane"
)
_CONTROL_DEPLOY_REFUSE_BEFORE_ROOT = (
    "  refuse_retired_winn_protocol_v3_enable\n"
    "  require_root\n"
    "  preflight_control"
)
_CONTROL_PREFLIGHT_REFUSE_BEFORE_ROOT = (
    "      refuse_retired_winn_protocol_v3_enable\n"
    "      require_root"
)
_CONTROL_REPAIR_REFUSE = (
    "      refuse_retired_winn_protocol_v3_enable\n"
    "      repair_hub_recovery_contract"
)


def _winn_v3_legacy_install_integrity(label: str, body: str, staged_bin: str) -> None:
    """If a function still contains an install path, the 2026-08-04
    fail-closed checksum / credential / unredirected-preflight gates still
    apply. A tombstone that only refuses does not need them.
    """
    if _REDIRECTED_WINN_PREFLIGHT.search(body):
        fail(
            f"{label} redirects its credential preflight output away from "
            "the operator in the branch that decides whether to start the service -- this "
            "is the exact bug fixed 2026-08-04. Check unredirected, branch on a captured "
            "result instead."
        )
    has_install = "sha256sum -c" in body or f"systemctl enable {staged_bin}" in body
    if not has_install:
        return
    if "winn_v3_missing_credential" not in body:
        fail(f"{label} lost its fail-closed missing-credential path")
    if "sha256sum -c" not in body:
        fail(f"{label} no longer verifies the staged binary's checksum before installing it")
    if staged_bin not in body:
        fail(f"{label} no longer references {staged_bin}")


def _winn_v3_flag1_path_refuses(label: str, body: str) -> None:
    """The first command after the flag!=1 skip must be the loud refuse, not
    a silent return 0 / fall-through install.
    """
    after_skip = re.search(
        r'WINN_PROTOCOL_V3_ENABLE_DEFAULT\}" != "1"[\s\S]*?\n\s*fi\n([^\n]*)',
        body,
    )
    if after_skip is None or _WINN_V3_REFUSE_FN not in after_skip.group(1):
        fail(
            f"{label} flag=1 path does not call {_WINN_V3_REFUSE_FN} immediately "
            "after the opt-in skip — that is a silent split-deploy"
        )


def validate_winn_protocol_v3_contract(
    control: str | None = None,
    data: str | None = None,
    gateway: str | None = None,
) -> None:
    """Static regression gate for Winn Protocol v3 provisioning in the
    ONETOUCH installers; the standalone gateway installer is the tombstone.

    Kept from 2026-08-04: the flag default stays off; Winn must not replace
    Xray/AmneziaWG; the data-plane carrier must not default onto :443; a
    live install path (if one still exists as dead code) must not redirect
    credential preflight to /dev/null.

    Added 2026-08-12: WINN_PROTOCOL_V3_ENABLE=1 is retired. Fleet-wide it
    used to produce a silent SPLIT deploy — control plane staged winn-server
    (a legacy AmneziaWG PSK rotator that cannot start there; no local AWG
    peer) while data-plane install_winn_carrier_server was a tombstone
    unreachable from main(), so the same flag was ignored with no warning.
    Both ONETOUCH installers must refuse that flag from main() before
    require_root. The standalone installer is
    server/wins_winn3_gateway_install.sh; it used to WARN (not refuse) so the
    correct path stayed usable, and since slice S6 it is the tombstone (see
    validate_gateway_tombstone). See
    docs/handoff/WINN3_SPLIT_DEPLOY_LOUD_20260812_deploy_split_deploy_loud.md.
    """
    if control is None:
        control = SCRIPTS["control"].read_text(encoding="utf-8")
    if data is None:
        data = SCRIPTS["data"].read_text(encoding="utf-8")
    if gateway is None:
        gateway = GATEWAY_SCRIPT.read_text(encoding="utf-8")

    for label, source, install_fn, staged_bin in (
        ("control-plane", control, "install_winn_protocol_server", "winn-server"),
        ("data-plane", data, "install_winn_carrier_server", "winn-carrier-server"),
    ):
        if f"{install_fn}() {{" not in source:
            fail(f"{label} script is missing {install_fn}")
        if _WINN_V3_DEFAULT_OFF not in source:
            fail(f"{label} script's Winn Protocol v3 default changed from off -- must stay opt-in")
        if f"{_WINN_V3_REFUSE_FN}() {{" not in source:
            fail(f"{label} script is missing {_WINN_V3_REFUSE_FN}")
        refuse = function_body(source, _WINN_V3_REFUSE_FN)
        for needle in (
            'WINN_PROTOCOL_V3_ENABLE_DEFAULT}" != "1"',
            "SPLIT deploy",
            "wins_winn3_gateway_install.sh",
            "return 1",
        ):
            if needle not in refuse:
                fail(f"{label} {_WINN_V3_REFUSE_FN} lost {needle!r}")
        if refuse.count("return 0") != 1:
            fail(
                f"{label} {_WINN_V3_REFUSE_FN} must return 0 only when the flag is not 1"
            )
        body = function_body(source, install_fn)
        if '"${WINN_PROTOCOL_V3_ENABLE_DEFAULT}" != "1"' not in body:
            fail(f"{label} {install_fn} no longer checks the opt-in flag first")
        _winn_v3_flag1_path_refuses(f"{label} {install_fn}", body)
        _winn_v3_legacy_install_integrity(f"{label} {install_fn}", body, staged_bin)

    control_install = function_body(control, "install_winn_protocol_server")
    refuse_at = control_install.find(_WINN_V3_REFUSE_FN)
    enable_at = control_install.find("systemctl enable winn-server")
    if refuse_at < 0:
        fail("control-plane install_winn_protocol_server no longer calls the retired-flag refuse")
    if enable_at >= 0 and refuse_at > enable_at:
        fail(
            "control-plane install_winn_protocol_server enables winn-server before "
            "refusing WINN_PROTOCOL_V3_ENABLE=1 — that is the silent rotator half of a split deploy"
        )

    data_install = function_body(data, "install_winn_carrier_server")
    if "systemctl enable winn-carrier-server" in data_install:
        fail(
            "data-plane install_winn_carrier_server reinstated the retired AWG-relay unit; "
            "the live function must stay a refuse tombstone"
        )

    if "_winn_carrier_retired_dead_code() {" in data:
        _winn_v3_legacy_install_integrity(
            "data-plane _winn_carrier_retired_dead_code",
            function_body(data, "_winn_carrier_retired_dead_code"),
            "winn-carrier-server",
        )

    for required in ("install_xray() {", "install_awg() {", "harden_xray_service_user() {"):
        if required not in data:
            fail(f"data-plane script lost {required} -- Winn Protocol v3 must be additive, never a replacement for Xray or AmneziaWG")

    data_main = function_body(data, "main")
    if _DATA_MAIN_REFUSE_BEFORE_ROOT not in data_main:
        fail(
            "data-plane main() must call refuse_retired_winn_protocol_v3_enable "
            "before require_root — otherwise WINN_PROTOCOL_V3_ENABLE=1 is a silent success"
        )
    if "install_winn_protocol_server" not in function_body(control, "main"):
        fail("control-plane main() no longer calls install_winn_protocol_server")
    control_main = function_body(control, "main")
    if control_main.count(_WINN_V3_REFUSE_FN) < 3:
        fail(
            "control-plane main() must refuse WINN_PROTOCOL_V3_ENABLE=1 on "
            "--preflight, --repair-recovery-contract, and --deploy"
        )
    if _CONTROL_DEPLOY_REFUSE_BEFORE_ROOT not in control_main:
        fail(
            "control-plane --deploy path must refuse WINN_PROTOCOL_V3_ENABLE=1 "
            "before require_root — refusing only inside install_winn_protocol_server "
            "mutates the hub first"
        )
    if _CONTROL_PREFLIGHT_REFUSE_BEFORE_ROOT not in control_main:
        fail("control-plane --preflight/--validate must refuse WINN_PROTOCOL_V3_ENABLE=1 before require_root")
    if _CONTROL_REPAIR_REFUSE not in control_main:
        fail("control-plane --repair-recovery-contract must refuse WINN_PROTOCOL_V3_ENABLE=1")

    # The public 443 listener belongs to nginx/Xray on the data-plane role
    # (write_nginx) and must keep working byte-for-byte; Winn's carrier must
    # not default onto it and silently create a port conflict.
    if 'WINN_CARRIER_LISTEN_PORT_DEFAULT="${WINN_CARRIER_LISTEN_PORT:-443}"' in data:
        fail("data-plane Winn carrier defaults onto :443, which nginx/Xray already own on this role")

    # Slice S6: the standalone installer no longer warns about the flag. It is
    # the tombstone, which ignores its arguments and environment and exits 2.
    validate_gateway_tombstone(gateway)


def validate_home_and_recovery_helpers() -> None:
    split_claim_guards = (
        "Android provides ordinary native per-app exclusions while Windows provides destination exclusions",
        "Linux provides launcher-scoped per-app bypass",
        "MDM",
        "destination-based exclusions",
    )
    for label in ("control", "core"):
        source = SCRIPTS[label].read_text(encoding="utf-8")
        for guard in split_claim_guards:
            if guard not in source:
                fail(f"{label} Hoppy split-tunnel truthfulness contract changed: {guard}")

    control_source = SCRIPTS["control"].read_text(encoding="utf-8")
    for guard in ('"ssh_host_keys": ssh_host_keys', 'Path("/etc/ssh").glob("ssh_host_*_key.pub")'):
        if guard not in control_source:
            fail(f"control-hub authenticated SSH host-key response contract changed: {guard}")

    for label, path in RECOVERY_SCRIPTS.items():
        source = path.read_text(encoding="utf-8")
        address_digests = token_sha256s(source, IPV4_TOKEN_RE)
        for category, forbidden_digest in FORBIDDEN_RECOVERY_ADDRESS_SHA256.items():
            if forbidden_digest in address_digests:
                fail(
                    f"{label} recovery helper hard-codes a stale administrator "
                    f"address category: {category}"
                )
        for guard in (
            'RECOVERY_ADMIN_CIDRS="${RECOVERY_ADMIN_CIDRS:-}"',
            'RECOVERY_ENABLE_PASSWORD_AUTH="${RECOVERY_ENABLE_PASSWORD_AUTH:-0}"',
            "SSH_CONNECTION%% *",
            "normalize_cidr",
            "PasswordAuthentication ${password_auth}",
            "PermitRootLogin prohibit-password",
            "systemctl reload ssh",
            "iptables -C INPUT",
        ):
            if guard not in source:
                fail(f"{label} dynamic/key-first recovery contract changed: {guard}")
        if "PermitRootLogin yes" in source or "PasswordAuthentication yes" in source:
            fail(f"{label} recovery helper enables password/root SSH unconditionally")
        if "systemctl restart ssh" in source:
            fail(f"{label} recovery helper must reload validated sshd config without dropping the recovery session")


def main() -> int:
    if not CLOUDFLARED_SECURITY_PATCH.is_file() or CLOUDFLARED_SECURITY_PATCH.is_symlink():
        fail("reviewed cloudflared security patch is missing or is a symlink")
    if hashlib.sha256(CLOUDFLARED_SECURITY_PATCH.read_bytes()).hexdigest() != (
        CLOUDFLARED_SECURITY_PATCH_SHA256
    ):
        fail("reviewed cloudflared security patch bytes changed")
    if not CLOUDFLARED_SECURITY_REVIEW.is_file() or CLOUDFLARED_SECURITY_REVIEW.is_symlink():
        fail("reviewed cloudflared security disposition is missing or is a symlink")
    if hashlib.sha256(CLOUDFLARED_SECURITY_REVIEW.read_bytes()).hexdigest() != (
        CLOUDFLARED_SECURITY_REVIEW_SHA256
    ):
        fail("reviewed cloudflared security disposition bytes changed")
    validate_defaults_template()
    validate_awg_31_server_image_contract()
    validate_xray_tunnel_contracts()
    validate_winn_protocol_v3_contract()
    validate_home_and_recovery_helpers()
    deployment_sources = "\n".join(
        path.read_text(encoding="utf-8") for path in (*SCRIPTS.values(), DEFAULTS_TEMPLATE)
    )
    deployment_value_digests = token_sha256s(deployment_sources, DEPLOYMENT_VALUE_TOKEN_RE)
    for index, forbidden_digest in enumerate(FORBIDDEN_STATIC_DEPLOYMENT_VALUE_SHA256, start=1):
        if forbidden_digest in deployment_value_digests:
            fail(
                "static infrastructure/account value must be injected dynamically "
                f"(retired-value category {index:02d})"
            )
    validate_gateway_tombstone()
    validate_gateway_listen_firewall_placement()
    validate_data_nfq_postflight(SCRIPTS["data"].read_text(encoding="utf-8"))
    honeynet = HONEYNET_SCRIPT.read_text(encoding="utf-8")
    for required in (
        'TPOT_COMMIT="${TPOT_COMMIT:-84637788c76629c449925f2428387fdb61454f0e}"',
        'HONEYPOT_ACK_ISOLATED',
        'HONEYPOT_EGRESS_GUARD_ACK',
        'HONEYPOT_ADMIN_CIDR',
        'role}" == "honeynet"',
        'git -C "${TPOT_DIR}" checkout --detach "${TPOT_COMMIT}"',
        'APT_GET=(apt-get -o DPkg::Lock::Timeout=900',
        'wait_for_cloud_init_and_apt',
        '"${APT_GET[@]}" install -y --no-install-recommends',
        'while getopts ":st:u:p:h"',
        # The Hive/sensor-fleet web password is piped to install.sh's stdin
        # ("-P 0") rather than passed as a "-p" argv token, so it never
        # appears in this process' or install.sh's /proc/<pid>/cmdline.
        '| ./install.sh -s -t "${TPOT_TYPE}" -u "${HONEYPOT_WEB_USER}" -P 0',
        './install.sh -s -t "${TPOT_TYPE}"',
    ):
        if required not in honeynet:
            fail(f"honeynet isolation/pinning contract changed: {required}")
    if '-p "${HONEYPOT_WEB_PASSWORD}"' in honeynet:
        fail("honeynet installer must not pass the Hive web password as a process argument")
    # The same argv-exposure class also applied to the earlier password-strength
    # check: it used to pass HONEYPOT_WEB_PASSWORD as a second argv token to a
    # `python3 -` validator, visible via ps/proc for that process' lifetime.
    if '"${HONEYPOT_WEB_USER}" "${HONEYPOT_WEB_PASSWORD:-}"' in honeynet:
        fail("honeynet password-strength check must not pass the Hive web password as an argv token")
    if 'os.environ.get("HONEYPOT_WEB_PASSWORD", "")' not in honeynet:
        fail("honeynet password-strength check no longer reads the Hive web password from the environment")
    if re.search(r"(?:curl|wget)[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh)", honeynet):
        fail("honeynet installer must not pipe remote content into a shell")
    # HONEYPOT_ADMIN_CIDR only ever names one address family. A bare
    # family-qualified nft match (`ip saddr` / `ip6 saddr`) in an `inet`
    # table never evaluates the other family's packets, leaving the T-Pot
    # admin ports fully open on whichever family wasn't configured --
    # empirically reproduced and fixed via an isolated network-namespace
    # test (a non-matching IPv4 source was dropped; the identical excluded
    # source connected over IPv6 with the same rule loaded). The fix
    # requires an unconditional `meta nfproto` drop for the other family,
    # since a bare `ip`/`ip6` token with no following field is not valid
    # nft syntax on its own.
    enforce_admin_cidr = function_body(honeynet, "enforce_admin_cidr_firewall")
    for required in (
        'other_family_nfproto="ipv4"',
        '[[ "${family_token}" == "ip" ]] && other_family_nfproto="ipv6"',
        "tcp dport { ${admin_ports_nft} } meta nfproto ${other_family_nfproto} counter drop",
    ):
        if required not in enforce_admin_cidr:
            fail(f"honeynet admin-CIDR dual-family enforcement changed: {required}")
    verify_admin_cidr = function_body(honeynet, "verify_admin_cidr_firewall")
    if (
        "dport { ${admin_ports_nft} } meta nfproto ${other_family_nfproto}"
        not in verify_admin_cidr
    ):
        fail(
            "honeynet admin-CIDR verification no longer proves the other "
            "address family is also restricted"
        )
    cowrie_honeypot = COWRIE_HONEYPOT_SCRIPT.read_text(encoding="utf-8")
    for required in (
        'HONEYPOT_ACK_STANDALONE',
        'role}" == "${COWRIE_ROLE_MARKER}"',
        '/root/vpn_auth && ! -e /root/node.env && ! -e /etc/wins-core',
        '--require-hashes -r "${lock_file}"',
        'cowrie==3.1.1 --hash=sha256:3ca9baa375a231daf60783aa6d3f90cee3d8a28189c2d5a7b752d2efb12a8f2c',
        'WINVPN-HONEYPOT-EGRESS',
        '--ctorigdstport 22',
    ):
        if required not in cowrie_honeypot:
            fail(f"standalone Cowrie honeypot contract changed: {required}")
    # iptables and ip6tables are entirely separate rule sets. Every
    # containment rule (egress restriction, port-22 redirect, direct-access
    # drop) used to exist only via `iptables`, leaving the real sshd fully
    # reachable, unredirected and undropped, over IPv6 on any dual-stack
    # host -- the same family-blind-spot bug already fixed in the honeynet
    # admin-CIDR firewall above, but for a different toolset (ip6tables has
    # no unified inet-table equivalent the way nftables does).
    cowrie_firewall_fn = function_body(cowrie_honeypot, "configure_honeypot_firewall")
    for required in (
        "command -v ip6tables",
        'for tool in iptables ip6tables; do',
        "split_admin_ssh_cidrs_by_family",
    ):
        if required not in cowrie_firewall_fn:
            fail(f"Cowrie honeypot firewall dual-family enforcement changed: {required}")
    cowrie_verify_fn = function_body(cowrie_honeypot, "verify_honeypot_firewall")
    if "for tool in iptables ip6tables" not in cowrie_verify_fn:
        fail("Cowrie honeypot firewall verification no longer checks both address families")
    # security_events used to retain the raw source IP indefinitely (the
    # retention window governs row lifetime, not which columns get
    # populated). The fix keeps only a keyed HMAC bucket for CIDR/rate
    # matching across all three services that share this schema -- the main
    # app, its admin CLI, the threat-triage backfill, and the alert monitor
    # -- so a writer fixed in isolation can't leave a reader silently
    # expecting the raw value.
    control_plane_source = SCRIPTS["control"].read_text(encoding="utf-8")
    write_app_fn = function_body(control_plane_source, "write_app")
    if "idx_security_events_source ON security_events(source_ip_bucket)" not in write_app_fn:
        fail("control-plane app security_events index no longer targets the hashed IP bucket")
    if not re.search(r'None,\s*\n\s*security_event_hash\(source_ip or "unknown"\),', write_app_fn):
        fail("control-plane app record_security_event() no longer withholds the plaintext source IP")
    # Switching a fresh (not-yet-WAL) SQLite file into WAL mode needs a
    # brief exclusive lock that busy_timeout doesn't reliably cover, so
    # several uvicorn workers opening their first-ever connection to a
    # shared, brand-new DB_PATH at the same instant (a normal multi-worker
    # boot) can race and raise "database is locked" here. get_db() must
    # retry that one PRAGMA instead of issuing it once and propagating the
    # OperationalError into the startup event / request handler.
    get_db_match = re.search(r"def get_db\(\):.*?(?=\ndef )", write_app_fn, re.DOTALL)
    if not get_db_match:
        fail("control-plane app get_db() definition not found")
    get_db_fn = get_db_match.group(0)
    for required in ("for attempt in range(5):", "except sqlite3.OperationalError:", "time.sleep("):
        if required not in get_db_fn:
            fail(f"control-plane app get_db() lost its WAL-switch retry on startup lock contention: {required}")
    security_events_cli_fn = function_body(control_plane_source, "write_security_events_cli")
    for required in (
        "source_ip_bucket IN (?, ?)",
        "RATE_LIMIT_SECRET is not available; cannot compute the source-IP hash bucket to search by.",
        # The bucket derivations diverged once (the monitor JSON-encoded and kept
        # 24 chars, the hub and this CLI str()-encoded and kept 16), so every row
        # the monitor wrote was unfindable by --source-ip AND the failure looked
        # exactly like a genuine "no such events". Both halves are contracts now:
        # search both forms, and never return an unexplained empty result.
        "def legacy_monitor_bucket(",
        "def emit_empty_source_ip_diagnostic(",
    ):
        if required not in security_events_cli_fn:
            fail(f"wins-security-events admin CLI hash-lookup contract changed: {required}")
    if "emit_empty_source_ip_diagnostic(args, census)" not in security_events_cli_fn:
        fail("wins-security-events no longer explains an empty --source-ip result")
    threat_triage_fn = function_body(control_plane_source, "write_threat_triage_engine")
    if "source_in_admin_ssh_network() fails closed" not in threat_triage_fn:
        fail("wins_threat_triage.py reclassify_events() lost its source_ip-retention tradeoff note")
    alert_monitor_fn = function_body(control_plane_source, "write_security_alert_monitor")
    if "idx_security_events_source ON security_events(source_ip_bucket)" not in alert_monitor_fn:
        fail("wins-security-alert-monitor security_events index no longer targets the hashed IP bucket")
    if not re.search(r'None,\s*\n\s*source_ip_bucket_value\(source_ip or "unknown"\),', alert_monitor_fn):
        fail("wins-security-alert-monitor record_event() no longer withholds the plaintext source IP")
    # Every security_events column that TWO producers write must be derived the
    # same way by both, and the monitor is the one that moved. There are two such
    # columns -- source_ip_bucket and details_hash -- and one implementation of
    # the canonical form, canonical_event_hash(). Lock the implementation, then
    # lock each column to it:
    if not re.search(
        r'def canonical_event_hash\(value\) -> str:.*?'
        r'hmac\.new\(RATE_LIMIT_SECRET\.encode\(\), str\(value or ""\)\.encode\(\), '
        r'hashlib\.sha256\)\.hexdigest\(\)\[:16\]',
        alert_monitor_fn,
        re.DOTALL,
    ):
        fail("wins-security-alert-monitor canonical_event_hash() no longer matches the hub's canonical 16-char form")
    if not re.search(
        r'def source_ip_bucket_value\(value\) -> str:(?:(?!\ndef ).)*?'
        r'return canonical_event_hash\(value\)',
        alert_monitor_fn,
        re.DOTALL,
    ):
        fail("wins-security-alert-monitor source_ip_bucket_value() no longer routes through canonical_event_hash()")
    if re.search(r"(?<![A-Za-z_])event_hash\(source_ip", alert_monitor_fn):
        fail("wins-security-alert-monitor bucketed a source IP with event_hash() again; use source_ip_bucket_value()")
    # details_hash: same two-producer problem as the bucket, fixed 2026-08-07
    # (second pass). main.py's record_security_event() writes this column with
    # security_event_hash() -- str()-encoded, 16 chars -- so the monitor must
    # match. event_hash() JSON-encodes an already-str detail_text (adding the
    # surrounding quotes) and keeps 24, so the two forms can never agree.
    if not re.search(r'canonical_event_hash\(detail_text\),\s*\n\s*detail_text,', alert_monitor_fn):
        fail("wins-security-alert-monitor record_event() no longer derives details_hash with canonical_event_hash()")
    if re.search(r"(?<![A-Za-z_])event_hash\(detail_text", alert_monitor_fn):
        fail("wins-security-alert-monitor hashed details with event_hash() again; use canonical_event_hash()")
    if not re.search(r'security_event_hash\(detail_text\),\s*\n\s*detail_text,', write_app_fn):
        fail("hub record_security_event() no longer derives details_hash with the canonical security_event_hash()")
    # ...while event_hash() itself must keep its JSON encoding: throttle_ok()
    # hashes throttle_identity()'s dict into a state FILENAME, and a dict has no
    # stable str() form. Unifying the two functions would silently reset every
    # monitor-*.last throttle file and re-open the alert floodgates.
    if not re.search(
        r'def event_hash\(value\) -> str:.*?json\.dumps\(value, sort_keys=True, default=str\).*?\[:24\]',
        alert_monitor_fn,
        re.DOTALL,
    ):
        fail("wins-security-alert-monitor event_hash() lost the JSON encoding its throttle-state filenames depend on")
    if "key = event_hash(throttle_identity(" not in alert_monitor_fn:
        fail("wins-security-alert-monitor throttle key no longer derives from event_hash(throttle_identity(...))")
    for control_script_path in SCRIPTS.values():
        # No production ONETOUCH deployment script may call into, or embed,
        # the standalone honeypot. Its whole purpose is to run only on a
        # dedicated, disposable host that a human operator invokes directly.
        control_source = control_script_path.read_text(encoding="utf-8")
        for leftover in ("honeypot", "HONEYPOT", "cowrie", "Cowrie", "COWRIE"):
            if leftover in control_source:
                fail(
                    f"{control_script_path.name} must not reference the "
                    f"standalone honeypot: found leftover token {leftover}"
                )
    counts = {"heredocs": 0, "python": 0, "bash": 0, "systemd": 0}
    for name, path in SCRIPTS.items():
        source = path.read_text(encoding="utf-8")
        if "datetime.utcnow()" in source:
            fail(f"{path.name} embeds deprecated datetime.utcnow(); use the timezone-aware UTC helper")
        blocks = parse_heredocs(path)
        validate_embedded_programs(path, blocks)
        validate_order_and_contract(name, source)
        if name in {"data", "core"}:
            validate_nfq_repeat_mode(name, source, blocks)
        counts["heredocs"] += len(blocks)
        counts["python"] += sum(
            "python3" in block.header
            or block.body.startswith("#!/usr/bin/env python")
            for block in blocks
        )
        counts["bash"] += sum(
            block.body.startswith(("#!/usr/bin/env bash", "#!/bin/bash"))
            for block in blocks
        )
        counts["systemd"] += sum(
            "/etc/systemd/system/" in block.header for block in blocks
        )
    for label, regression in (
        ("data-plane dark-start promotion latch", "../server/test_data_plane_dark_start_latch.py"),
        ("OpenSSH drop-in precedence", "test_sshd_dropin_precedence.py"),
        ("package reboot/resume", "test_deployment_reboot_resume.py"),
        ("data-plane management rollback guard", "test_data_plane_management_rollback_guard.py"),
        ("conditional failure propagation", "test_deployment_failure_semantics.py"),
        ("Ubuntu 26.04 OS gate", "test_require_supported_production_os.py"),
        ("Winn Protocol v3 split-deploy refuse", "test_winn_protocol_v3_split_deploy.py"),
    ):
        regression_test = subprocess.run(
            [sys.executable, str(ROOT / "tools" / regression)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if regression_test.returncode != 0:
            fail(f"{label} regression test failed: " + regression_test.stdout.strip())
    print(
        "Deployment scripts validated: "
        f"{len(SCRIPTS)} roles, {counts['heredocs']} heredocs, "
        f"{counts['python']} Python blocks, {counts['bash']} Bash helpers, "
        f"{counts['systemd']} systemd units."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
