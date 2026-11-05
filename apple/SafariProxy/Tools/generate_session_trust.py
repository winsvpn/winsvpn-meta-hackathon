"""Copy only the existing public CA anchors into the standalone Swift target."""
import argparse
import base64
import hashlib
from pathlib import Path
import re


def generate(source: Path) -> str:
    text = source.read_text()
    pem = text.split("const String kControlPlanePinnedCertificatePem = '''", 1)[1].split("'''", 1)[0]
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
    der = [base64.b64decode("".join(block.split()), validate=True) for block in blocks]
    pins = re.findall(r"cert sha256 ([0-9a-f]{64})", text)
    if len(der) != 12 or [hashlib.sha256(item).hexdigest() for item in der] != pins:
        raise ValueError("Public root certificate set differs from source digest inventory")
    result = "// Generated from lib/control_plane_pinning.dart. Public CA certificates only.\nimport Foundation\n\nenum SafariHubTrustAnchors {\n    static let derBase64 = [\n"
    result += "".join('        "' + base64.b64encode(item).decode() + '",\n' for item in der)
    result += "    ]\n    static let sha256 = [\n" + "".join('        "' + pin + '",\n' for pin in pins) + "    ]\n}\n"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = generate(args.source)
    if args.check:
        if args.output.read_text() != output:
            raise SystemExit("Generated public trust anchors differ")
        print("12 public anchors match source certificates and digest inventory")
    else:
        args.output.write_text(output)
