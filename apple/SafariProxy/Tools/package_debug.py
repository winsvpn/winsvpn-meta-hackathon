#!/usr/bin/env python3
"""Package already-built, unsigned development apps and verify web resource parity."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import plistlib
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive_app(app):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(app.rglob('*')):
            if path.is_symlink():
                raise ValueError('Symlinks are not expected in these development app targets')
            if not path.is_file():
                continue
            if path.name.startswith('._') or path.name == '.DS_Store':
                raise ValueError('Filesystem metadata is not a package input')
            info = zipfile.ZipInfo(path.relative_to(app.parent).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--macos-app', type=Path, required=True)
    parser.add_argument('--ios-app', type=Path, required=True)
    parser.add_argument('--source-zip', type=Path, required=True)
    args = parser.parse_args()
    with zipfile.ZipFile(args.source_zip) as source:
        members = source.namelist()
        if len(members) != len(set(members)):
            raise ValueError('Duplicate web resource')
        web = {name: source.read(name) for name in members}
    mac = args.macos_app.resolve()
    ios = args.ios_app.resolve()
    mac_extension = mac / 'Contents/PlugIns/SafariWebMac.appex/Contents'
    ios_extension = ios / 'PlugIns/SafariWebiOS.appex'
    for extension, resource_folder, binary in (
        (mac_extension, mac_extension / 'Resources', mac_extension / 'MacOS/SafariWebMac'),
        (ios_extension, ios_extension, ios_extension / 'SafariWebiOS'),
    ):
        assert binary.is_file(), 'Missing Safari extension executable'
        for name, payload in web.items():
            assert (resource_folder / name).read_bytes() == payload, 'Web resources differ from the source ZIP'
        info = plistlib.loads((extension / 'Info.plist').read_bytes())
        assert info['NSExtension']['NSExtensionPointIdentifier'] == 'com.apple.Safari.web-extension'
    network = mac / 'Contents/Library/SystemExtensions/org.winsvpn.safariproxy.network.systemextension/Contents'
    assert (network / 'MacOS/org.winsvpn.safariproxy.network').is_file(), 'System extension executable was not embedded'
    info = plistlib.loads((network / 'Info.plist').read_bytes())
    assert set(info['NetworkExtension']['NEProviderClasses']) == {
        'com.apple.networkextension.app-proxy', 'com.apple.networkextension.dns-proxy'}
    output = ROOT / 'Artifacts'
    output.mkdir(exist_ok=True)
    rows = []
    for platform, app in (('macos', mac), ('ios', ios)):
        payload = archive_app(app)
        assert payload == archive_app(app), 'Packaging changed the same input bytes'
        path = output / f'safari-proxy-{platform}-debug-unsigned.zip'
        path.write_bytes(payload)
        local_paths = sum(1 for p in app.rglob('*') if p.is_file() and b'/Users/' in p.read_bytes())
        rows.append(dict(file=path.name, sha256=digest(payload), bytes=len(payload),
            kind='unsigned-debug-development-app', routing=False,
            compiled_binary_reproducibility='unverified', files_containing_local_debug_paths=local_paths))
    source_path = output / 'wins-vpn-proxy-safari.zip'
    source_payload = args.source_zip.read_bytes()
    source_path.write_bytes(source_payload)
    rows.append(dict(file=source_path.name, sha256=digest(source_payload), bytes=len(source_payload),
        kind='webextension-package-unsigned', routing=False))
    receipt = dict(schema=1, distribution_ready=False, installed=False,
        source_members=len(web), embedded_web_resources_match=True, artifacts=rows)
    (output / 'artifacts.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
