#!/usr/bin/env python3
"""Build, Developer ID sign, notarize and verify the standalone Safari proxy for macOS.

The release is one drag-install disk image holding SafariProxyMac.app, which
embeds the Safari web extension (Contents/PlugIns) and the NETransparentProxy
plus DNS proxy system extension (Contents/Library/SystemExtensions).

Steps (run in order, or pick some with --steps):
  engine    clean private Go module cache from verified module ZIPs, then
            build_engine.py (bridge tests + c-archive) into build/Engine
  web       extension/build.py safari -> extension/dist/safari
  project   generate_project.py, refusing any drift from the committed tree
  archive   xcodebuild archive, Release, signed to run locally (ad hoc); the
            export step replaces every signature
  export    xcodebuild -exportArchive, method developer-id, automatic
            signing through the App Store Connect API key: registers the App
            IDs, capabilities and app group and creates Developer ID profiles
  inspect   codesign/entitlement/profile/layout checks on the exported app
  notarize  notarize the app (ZIP), staple it, build the DMG, sign it,
            notarize the DMG, staple it
  verify    codesign --verify --deep --strict, spctl, stapler validate
  publish   copy the DMG, SHA256SUMS and a release receipt to --publish-dir
  clean     delete the intermediates this script created (keeps build/Release)

Secrets: the issuer id is read from the env file into the child environment
only; it is never printed or written. The key id is the AuthKey_<ID>.p8 name.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

APPLE = Path(__file__).resolve().parents[1]
REPO = APPLE.parents[1]
BUILD = APPLE / 'build'
TEAM = '5YT8H4U72M'
APPLICATION_IDENTITY = "Developer ID Application: Win's VPN Inc (" + TEAM + ")"
SCHEME = 'SafariProxyMac'
APP_NAME = 'SafariProxyMac.app'
VOLUME_NAME = "Win's VPN Safari Proxy"
ISSUER_VARIABLE = 'WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID'
STEPS = ('engine', 'web', 'project', 'profiles', 'archive', 'export', 'inspect', 'notarize', 'verify', 'publish', 'clean')
GENERATED = ('apple/SafariProxy/Config', 'apple/SafariProxy/SafariProxy.xcodeproj', 'apple/SafariProxy/Resources')
PROFILE_PREFIX = 'Wins VPN Safari Proxy Developer ID '
BUNDLES = {
    'org.winsvpn.safariproxy': ('NETWORK_EXTENSIONS', 'SYSTEM_EXTENSION_INSTALL'),
    'org.winsvpn.safariproxy.web': ('NETWORK_EXTENSIONS',),
    'org.winsvpn.safariproxy.network': ('NETWORK_EXTENSIONS',),
}
NE_VALUES = {'app-proxy-provider-systemextension', 'dns-proxy-systemextension'}


class ReleaseError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def run(argv, *, log: Path | None = None, env=None, cwd=None, timeout=3600, capture=False):
    """Run a command; never echo the environment. Logs hold argv and output only."""
    print('+ ' + ' '.join(str(a) for a in argv), flush=True)
    result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(' '.join(str(a) for a in argv) + '\n\n' + result.stdout)
    if result.returncode:
        tail = '\n'.join(result.stdout.splitlines()[-40:])
        raise ReleaseError(f'{argv[0]} exited {result.returncode}' + (f'; log {log}' if log else '') + '\n' + tail)
    return result.stdout if capture else None


class Release:
    def __init__(self, args):
        self.args = args
        self.receipt_path = BUILD / 'release-receipt.json'
        self.receipt = json.loads(self.receipt_path.read_text()) if self.receipt_path.is_file() else {}
        self.receipt.setdefault('schema', 1)
        self.logs = BUILD / 'logs'
        self.derived = BUILD / 'DerivedData'
        self.archive = BUILD / 'SafariProxyMac.xcarchive'
        self.exported = BUILD / 'Export'
        self.stage = BUILD / 'Release'
        self.engine = BUILD / 'Engine'
        self.web = REPO / 'extension/dist/safari'

    # ----------------------------------------------------------- credentials
    def api_key(self) -> tuple[Path, str]:
        key = self.args.api_key.expanduser().resolve()
        match = re.fullmatch(r'AuthKey_([A-Z0-9]{10})\.p8', key.name)
        if not key.is_file() or not match:
            raise ReleaseError('App Store Connect key must be an existing AuthKey_<KEYID>.p8 file')
        return key, match[1]

    def issuer_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if ISSUER_VARIABLE not in env:
            text = self.args.env_file.expanduser().read_text()
            found = re.findall(r'^\s*(?:export\s+)?' + ISSUER_VARIABLE + r'\s*=\s*["\']?([^"\'\s#]+)', text, re.M)
            if len(found) != 1:
                raise ReleaseError(ISSUER_VARIABLE + ' is not defined exactly once in the env file')
            env[ISSUER_VARIABLE] = found[0]
        if not re.fullmatch(r'[0-9a-f-]{36}', env[ISSUER_VARIABLE]):
            raise ReleaseError(ISSUER_VARIABLE + ' is not a UUID')
        return env

    def xcode_auth(self, env) -> list[str]:
        key, key_id = self.api_key()
        return ['-allowProvisioningUpdates', '-authenticationKeyPath', str(key),
                '-authenticationKeyID', key_id, '-authenticationKeyIssuerID', env[ISSUER_VARIABLE]]

    def notary_auth(self, env) -> list[str]:
        key, key_id = self.api_key()
        return ['--key', str(key), '--key-id', key_id, '--issuer', env[ISSUER_VARIABLE]]

    def redacted_run(self, argv, env, log, timeout=3600, capture=False):
        """Run with the issuer id in argv but never print or log it."""
        secret = env[ISSUER_VARIABLE]
        shown = ['<issuer>' if a == secret else str(a) for a in argv]
        print('+ ' + ' '.join(shown), flush=True)
        result = subprocess.run([str(a) for a in argv], env=env, timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output = result.stdout.replace(secret, '<issuer>')
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(' '.join(shown) + '\n\n' + output)
        if result.returncode:
            tail = '\n'.join(output.splitlines()[-40:])
            raise ReleaseError(f'{shown[0]} {shown[1]} exited {result.returncode}; log {log}\n{tail}')
        return output if capture else None

    # ------------------------------------------------- App Store Connect API
    def asc_token(self, env) -> str:
        key, key_id = self.api_key()

        def b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
        now = int(time.time())
        signing_input = (b64(json.dumps({'alg': 'ES256', 'kid': key_id, 'typ': 'JWT'}).encode()) + '.' +
                         b64(json.dumps({'iss': env[ISSUER_VARIABLE], 'iat': now, 'exp': now + 900,
                                         'aud': 'appstoreconnect-v1'}).encode()))
        # The system LibreSSL reads the key file itself; key bytes never pass through this process.
        der = subprocess.run(['/usr/bin/openssl', 'dgst', '-sha256', '-sign', str(key)],
                             input=signing_input.encode(), capture_output=True, check=True, timeout=30).stdout
        return signing_input + '.' + b64(der_to_raw(der))

    def asc(self, env, method: str, path: str, body: dict | None = None) -> dict:
        if not hasattr(self, '_token') or time.time() - self._token[1] > 600:
            self._token = (self.asc_token(env), time.time())
        request = urllib.request.Request('https://api.appstoreconnect.apple.com' + path, method=method,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={'Authorization': 'Bearer ' + self._token[0],
                                                  'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors='replace')[:2000]
            raise ReleaseError(f'App Store Connect {method} {path.split("?")[0]} -> {error.code}: {detail}') from None
        return json.loads(raw) if raw else {}

    def step_profiles(self):
        """Register the three bundle IDs and their capabilities, then fetch or
        create one Developer ID (MAC_APP_DIRECT) profile per bundle ID."""
        env = self.issuer_env()
        serial = keychain_certificate_serial(APPLICATION_IDENTITY)
        certificates = [c for c in self.asc(env, 'GET', '/v1/certificates?limit=200&filter[certificateType]='
                                            'DEVELOPER_ID_APPLICATION,DEVELOPER_ID_APPLICATION_G2')['data']
                        if c['attributes']['serialNumber'].lstrip('0').upper() == serial]
        if len(certificates) != 1:
            raise ReleaseError('the keychain Developer ID Application certificate is not on the team')
        certificate = certificates[0]['id']
        installed = Path('~/Library/Developer/Xcode/UserData/Provisioning Profiles').expanduser()
        installed.mkdir(parents=True, exist_ok=True)
        profiles = {}
        for identifier, capabilities in BUNDLES.items():
            found = self.asc(env, 'GET', '/v1/bundleIds?limit=20&filter[identifier]=' + identifier)['data']
            found = [b for b in found if b['attributes']['identifier'] == identifier]
            if not found:
                found = [self.asc(env, 'POST', '/v1/bundleIds', {'data': {'type': 'bundleIds', 'attributes': {
                    'identifier': identifier, 'name': 'Wins VPN Safari Proxy ' + identifier.replace('.', ' '),
                    'platform': 'MAC_OS'}}})['data']]
            bundle = found[0]['id']
            enabled = {c['attributes']['capabilityType'] for c in self.asc(
                env, 'GET', f'/v1/bundleIds/{bundle}/bundleIdCapabilities')['data']}
            added = sorted(set(capabilities) - enabled)
            for capability in added:
                self.asc(env, 'POST', '/v1/bundleIdCapabilities', {'data': {
                    'type': 'bundleIdCapabilities', 'attributes': {'capabilityType': capability},
                    'relationships': {'bundleId': {'data': {'type': 'bundleIds', 'id': bundle}}}}})
            name = PROFILE_PREFIX + identifier
            existing = self.asc(env, 'GET', '/v1/profiles?limit=50&include=certificates&filter[profileType]='
                                'MAC_APP_DIRECT&filter[name]=' + urllib.parse.quote(name))
            usable = [p for p in existing['data'] if p['attributes']['name'] == name and
                      p['attributes']['profileState'] == 'ACTIVE' and
                      certificate in [c['id'] for c in p['relationships']['certificates'].get('data', [])]]
            if usable and not added:
                profile = usable[0]
            else:
                # Names are the build's lookup key, so replace a stale profile of
                # this lane's own name rather than creating a second one.
                for stale in existing['data']:
                    if stale['attributes']['name'] == name:
                        self.asc(env, 'DELETE', '/v1/profiles/' + stale['id'])
                profile = self.asc(env, 'POST', '/v1/profiles', {'data': {
                    'type': 'profiles', 'attributes': {'name': name, 'profileType': 'MAC_APP_DIRECT'},
                    'relationships': {'bundleId': {'data': {'type': 'bundleIds', 'id': bundle}},
                                      'certificates': {'data': [{'type': 'certificates', 'id': certificate}]}}}})['data']
            content = base64.b64decode(profile['attributes']['profileContent'])
            decoded = plistlib.loads(subprocess.run(['security', 'cms', '-D'], input=content,
                                                    capture_output=True, check=True).stdout)
            (installed / (decoded['UUID'] + '.provisionprofile')).write_bytes(content)
            if not decoded.get('ProvisionsAllDevices') or decoded['Name'] != name:
                raise ReleaseError('App Store Connect returned an unexpected profile for ' + identifier)
            profiles[identifier] = {'name': decoded['Name'], 'uuid': decoded['UUID'],
                                    'expires': decoded['ExpirationDate'].isoformat(),
                                    'capabilities_added': added}
        self.receipt['profiles'] = profiles

    def save(self):
        BUILD.mkdir(parents=True, exist_ok=True)
        self.receipt_path.write_text(json.dumps(self.receipt, sort_keys=True, indent=2) + '\n')

    # ---------------------------------------------------------------- steps
    def step_engine(self):
        """Stage a private module cache from the shared cache's verified ZIPs.

        Some extracted trees in the shared cache carry symlinks out of the
        cache, which build_engine.py refuses. Each ZIP is checked against the
        pinned go.sum h1 by build_engine.py before it is used.
        """
        sys.path.insert(0, str(APPLE / 'Tools'))
        import build_engine  # noqa: E402  (local helper, same directory)
        source = self.args.module_cache.expanduser().resolve()
        engine_mod = (REPO / 'winn_protocol_experimental/go.mod').read_text()
        carry_mod = (REPO / 'tools/awg_carry_client/go.mod').read_text()
        engine_pins = build_engine.requirements(engine_mod)
        carry_pins = build_engine.requirements(carry_mod)
        pins = {**{n: carry_pins[n] for n in build_engine.EXTRA_MODULES if n not in engine_pins}, **engine_pins}
        private = BUILD / 'gomodcache'
        if private.exists():
            remove_tree(private)
        go = self.args.go.expanduser().resolve()
        fetched = []
        for name, version in sorted(pins.items()):
            escaped = ''.join('!' + c.lower() if c.isupper() else c for c in name)
            if not (source / 'cache/download' / escaped / '@v' / (version + '.zip')).is_file():
                # Not in the shared cache: fetch from the Go module proxy. The
                # go.sum h1 pins are still enforced by build_engine.py.
                empty = BUILD / 'go-fetch'
                empty.mkdir(parents=True, exist_ok=True)
                env = os.environ.copy()
                env.update({'GOMODCACHE': str(private), 'GOFLAGS': '-modcacherw', 'GOTOOLCHAIN': 'local',
                            'GOWORK': 'off', 'GO111MODULE': 'on', 'GOPATH': str(BUILD / 'go-fetch/gopath')})
                run([go, 'mod', 'download', '-x', name + '@' + version], cwd=empty, env=env,
                    log=self.logs / ('fetch-' + escaped.replace('/', '_') + '.log'), timeout=900)
                remove_tree(empty)
                fetched.append(name + '@' + version)
                continue
            escaped = ''.join('!' + c.lower() if c.isupper() else c for c in name)
            metadata = source / 'cache/download' / escaped / '@v'
            destination = private / 'cache/download' / escaped / '@v'
            destination.mkdir(parents=True)
            for suffix in ('.mod', '.info', '.zip', '.ziphash'):
                path = metadata / (version + suffix)
                if path.is_symlink():
                    raise ReleaseError('module metadata symlink refused: ' + name)
                if path.is_file():
                    shutil.copyfile(path, destination / path.name)
            archive = destination / (version + '.zip')
            if not archive.is_file():
                raise ReleaseError('module ZIP missing from the shared cache: ' + name + '@' + version)
            prefix = name + '@' + version + '/'
            target = private / (escaped + '@' + version)
            with zipfile.ZipFile(archive) as z:
                for member in z.infolist():
                    if not member.filename.startswith(prefix) or '..' in Path(member.filename).parts:
                        raise ReleaseError('unexpected module ZIP entry in ' + name)
                    if member.is_dir():
                        continue
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ReleaseError('module ZIP symlink refused: ' + name)
                    out = target / member.filename[len(prefix):]
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(z.read(member))
        run([sys.executable, '-B', APPLE / 'Tools/build_engine.py', '--go', go, '--module-cache', private,
             '--output', self.engine, '--platform', 'macos'], log=self.logs / 'engine.log', timeout=1800)
        build = json.loads((self.engine / 'build-receipt.json').read_text())
        if build.get('status') != 'passed':
            raise ReleaseError('engine build receipt did not pass')
        self.receipt['engine'] = {'input_sha256': build['input_sha256'], 'artifacts': build['artifacts'],
                                  'bridge_tests': build['tests'], 'go': go.parent.parent.name,
                                  'modules': len(pins), 'fetched_from_proxy': fetched}

    def step_web(self):
        run([sys.executable, '-B', REPO / 'extension/build.py', 'safari'], log=self.logs / 'web.log', cwd=REPO / 'extension')
        if not (self.web / 'manifest.json').is_file() or not (self.web / 'src').is_dir():
            raise ReleaseError('extension/build.py did not produce dist/safari')
        package = REPO / 'extension/dist/wins-vpn-proxy-safari.zip'
        self.receipt['web'] = {'zip': package.name, 'sha256': digest(package)}

    def step_project(self):
        def snapshot():
            return {str(p.relative_to(REPO)): digest(p) for g in GENERATED for p in sorted((REPO / g).rglob('*'))
                    if p.is_file()}
        before = snapshot()
        run([sys.executable, '-B', APPLE / 'Tools/generate_project.py'], log=self.logs / 'project.log')
        after = snapshot()
        drift = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if drift:
            raise ReleaseError('generate_project.py output differs from the tree; review and commit it:\n' +
                               '\n'.join(drift))
        head = run(['git', '-C', REPO, 'rev-parse', 'HEAD'], capture=True).strip()
        dirty = run(['git', '-C', REPO, 'status', '--porcelain', '--untracked-files=no', '--', 'apple/SafariProxy',
                     'extension', 'winn_protocol_experimental'], capture=True).strip()
        if dirty and not self.args.allow_dirty:
            raise ReleaseError('release inputs differ from HEAD (use --allow-dirty only for rehearsal):\n' + dirty)
        self.receipt['source'] = {'git_head': head, 'dirty_inputs': bool(dirty)}

    def build_settings(self) -> list[str]:
        engine = self.engine / 'libSafariWinn-macos-arm64.a'
        if not engine.is_file():
            raise ReleaseError('run the engine step first')
        # Every target signs with Developer ID and its own MAC_APP_DIRECT
        # profile, selected by name through the per-target bundle identifier.
        return ['SAFARI_ENGINE_ARCHIVE=' + str(engine), 'DEVELOPMENT_TEAM=' + TEAM, 'ARCHS=arm64',
                'ONLY_ACTIVE_ARCH=NO', 'CODE_SIGN_STYLE=Manual', 'CODE_SIGN_IDENTITY=Developer ID Application',
                'PROVISIONING_PROFILE_SPECIFIER=' + PROFILE_PREFIX + '$(PRODUCT_BUNDLE_IDENTIFIER)',
                'OTHER_CODE_SIGN_FLAGS=--timestamp', 'COMPILER_INDEX_STORE_ENABLE=NO']

    def step_archive(self):
        if self.archive.exists():
            remove_tree(self.archive)
        run(['xcodebuild', 'archive', '-project', APPLE / 'SafariProxy.xcodeproj', '-scheme', SCHEME,
             '-configuration', 'Release', '-destination', 'generic/platform=macOS',
             '-archivePath', self.archive, '-derivedDataPath', self.derived, *self.build_settings()],
            log=self.logs / 'archive.log', timeout=3600)
        app = self.archive / 'Products/Applications' / APP_NAME
        if not app.is_dir():
            raise ReleaseError('archive has no ' + APP_NAME)

    def step_export(self):
        env = self.issuer_env()
        options = BUILD / 'ExportOptions.plist'
        options.write_bytes(plistlib.dumps({'method': 'developer-id', 'teamID': TEAM, 'signingStyle': 'manual',
                                            'signingCertificate': 'Developer ID Application',
                                            'provisioningProfiles': {b: PROFILE_PREFIX + b for b in BUNDLES},
                                            'destination': 'export'}))
        if self.exported.exists():
            remove_tree(self.exported)
        self.redacted_run(['xcodebuild', '-exportArchive', '-archivePath', self.archive, '-exportPath', self.exported,
                           '-exportOptionsPlist', options, *self.xcode_auth(env)], env, self.logs / 'export.log')
        if not (self.exported / APP_NAME).is_dir():
            raise ReleaseError('export produced no app')

    def components(self, app: Path) -> dict[str, Path]:
        return {'app': app,
                'web': app / 'Contents/PlugIns/SafariWebMac.appex',
                'network': app / 'Contents/Library/SystemExtensions/org.winsvpn.safariproxy.network.systemextension'}

    def app_path(self) -> Path:
        stapled = self.stage / APP_NAME
        return stapled if stapled.is_dir() else self.exported / APP_NAME

    def step_inspect(self):
        app = self.app_path()
        comp = self.components(app)
        system_extensions = sorted((app / 'Contents/Library/SystemExtensions').glob('*.systemextension'))
        if len(system_extensions) != 1:
            raise ReleaseError('expected exactly one embedded system extension, found ' + str(system_extensions))
        comp['network'] = system_extensions[0]
        report = {}
        for role, path in comp.items():
            info = plistlib.loads((path / 'Contents/Info.plist').read_bytes())
            details = run(['codesign', '-dvvv', path], capture=True)
            entitlements = plistlib.loads(subprocess.run(['codesign', '-d', '--entitlements', '-', '--xml', str(path)],
                                                         capture_output=True, check=True).stdout or plistlib.dumps({}))
            authority = re.findall(r'^Authority=(.*)$', details, re.M)
            flags = re.search(r'flags=0x[0-9a-f]+\(([^)]*)\)', details)
            if not authority or authority[0] != APPLICATION_IDENTITY:
                raise ReleaseError(role + ' is not signed by ' + APPLICATION_IDENTITY)
            if not flags or 'runtime' not in flags[1].split(','):
                raise ReleaseError(role + ' lacks the hardened runtime')
            if not re.search(r'^Timestamp=', details, re.M):
                raise ReleaseError(role + ' has no secure timestamp')
            if 'com.apple.security.get-task-allow' in entitlements:
                raise ReleaseError(role + ' carries get-task-allow')
            if set(entitlements.get('com.apple.developer.networking.networkextension', [])) - NE_VALUES:
                raise ReleaseError(role + ' has a non Developer ID network extension value')
            profile = path / 'Contents/embedded.provisionprofile'
            profile_info = {}
            if profile.is_file():
                decoded = plistlib.loads(subprocess.run(['security', 'cms', '-D', '-i', str(profile)],
                                                        capture_output=True, check=True).stdout)
                profile_info = {'name': decoded['Name'], 'uuid': decoded['UUID'],
                                'expires': decoded['ExpirationDate'].isoformat(),
                                'provisions_all_devices': decoded.get('ProvisionsAllDevices', False)}
                allowed = decoded['Entitlements']
                for key, value in entitlements.items():
                    if key.startswith('com.apple.developer.') and key not in allowed:
                        raise ReleaseError(role + ' entitlement not in its profile: ' + key)
                if not decoded.get('ProvisionsAllDevices'):
                    raise ReleaseError(role + ' profile is not a Developer ID (all devices) profile')
            elif any(k.startswith('com.apple.developer.') for k in entitlements):
                raise ReleaseError(role + ' uses restricted entitlements without an embedded profile')
            report[role] = {'bundle_id': info['CFBundleIdentifier'], 'version': info['CFBundleShortVersionString'],
                            'build': info['CFBundleVersion'], 'entitlements': entitlements, 'profile': profile_info,
                            'cdhash': re.search(r'^CDHash=(\w+)$', details, re.M)[1]}
        network_info = plistlib.loads((comp['network'] / 'Contents/Info.plist').read_bytes())
        if set(network_info['NetworkExtension']['NEProviderClasses']) != {
                'com.apple.networkextension.app-proxy', 'com.apple.networkextension.dns-proxy'}:
            raise ReleaseError('system extension provider classes changed')
        app_info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        if app_info['SafariProxySystemExtensionIdentifier'] != network_info['CFBundleIdentifier']:
            raise ReleaseError('app activates a different system extension identifier than it embeds')
        resources = comp['web'] / 'Contents/Resources'
        with zipfile.ZipFile(REPO / 'extension/dist/wins-vpn-proxy-safari.zip') as source:
            for name in source.namelist():
                if not name.endswith('/') and (resources / name).read_bytes() != source.read(name):
                    raise ReleaseError('embedded web resource differs from the Safari package: ' + name)
        run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', app])
        self.receipt['components'] = report

    def notarize(self, path: Path, env, label: str) -> dict:
        output = self.redacted_run(['xcrun', 'notarytool', 'submit', path, *self.notary_auth(env), '--wait',
                                    '--timeout', '2h', '--output-format', 'json'], env,
                                   self.logs / ('notary-' + label + '.log'), timeout=7500, capture=True)
        result = json.loads(output.strip().splitlines()[-1])
        submission = result.get('id')
        log_path = self.logs / ('notary-' + label + '-log.json')
        if submission:
            self.redacted_run(['xcrun', 'notarytool', 'log', submission, *self.notary_auth(env), log_path], env,
                              self.logs / ('notary-' + label + '-log.txt'))
        if result.get('status') != 'Accepted':
            raise ReleaseError(label + ' notarization status ' + str(result.get('status')) + '; see ' + str(log_path))
        issues = json.loads(log_path.read_text()).get('issues') if log_path.is_file() else None
        return {'submission_id': submission, 'status': result['status'], 'issues': issues or []}

    def step_notarize(self):
        env = self.issuer_env()
        if self.stage.exists():
            remove_tree(self.stage)
        self.stage.mkdir(parents=True)
        app = self.stage / APP_NAME
        run(['ditto', self.exported / APP_NAME, app])
        upload = BUILD / 'SafariProxyMac-notary.zip'
        run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', app, upload])
        self.receipt['notary_app'] = self.notarize(upload, env, 'app')
        upload.unlink()
        run(['xcrun', 'stapler', 'staple', '-v', app], log=self.logs / 'staple-app.log')
        version = self.receipt.get('components', {}).get('app', {}).get('version') or \
            plistlib.loads((app / 'Contents/Info.plist').read_bytes())['CFBundleShortVersionString']
        build = plistlib.loads((app / 'Contents/Info.plist').read_bytes())['CFBundleVersion']
        dmg_root = BUILD / 'dmg-root'
        if dmg_root.exists():
            remove_tree(dmg_root)
        dmg_root.mkdir()
        run(['ditto', app, dmg_root / APP_NAME])
        (dmg_root / 'Applications').symlink_to('/Applications')
        dmg = self.stage / f'WinsVPN-Safari-Proxy-{version}-{build}-macOS.dmg'
        run(['hdiutil', 'create', '-volname', VOLUME_NAME, '-srcfolder', dmg_root, '-fs', 'APFS',
             '-format', 'ULFO', '-ov', dmg], log=self.logs / 'hdiutil.log')
        remove_tree(dmg_root)
        run(['codesign', '--sign', APPLICATION_IDENTITY, '--timestamp', '--identifier',
             'org.winsvpn.safariproxy.dmg', dmg], log=self.logs / 'codesign-dmg.log')
        self.receipt['notary_dmg'] = self.notarize(dmg, env, 'dmg')
        run(['xcrun', 'stapler', 'staple', '-v', dmg], log=self.logs / 'staple-dmg.log')
        self.receipt['dmg'] = dmg.name

    def step_verify(self):
        app = self.stage / APP_NAME
        dmg = self.stage / self.receipt['dmg']
        checks = {}
        for name, argv in (
                ('codesign_app', ['codesign', '--verify', '--deep', '--strict', '--verbose=2', app]),
                ('codesign_dmg', ['codesign', '--verify', '--strict', '--verbose=2', dmg]),
                ('spctl_app', ['spctl', '-a', '-vvv', '-t', 'exec', app]),
                ('spctl_dmg', ['spctl', '-a', '-vvv', '-t', 'open', '--context', 'context:primary-signature', dmg]),
                ('stapler_app', ['xcrun', 'stapler', 'validate', '-v', app]),
                ('stapler_dmg', ['xcrun', 'stapler', 'validate', '-v', dmg])):
            output = run(argv, capture=True, log=self.logs / ('verify-' + name + '.log'))
            checks[name] = 'passed'
            if name.startswith('spctl') and 'source=Notarized Developer ID' not in output:
                raise ReleaseError(name + ' did not report a notarized Developer ID source')
        # Mount read-only and check the shipped bytes, not only the staging copy.
        mount = BUILD / 'mnt'
        mount.mkdir(exist_ok=True)
        run(['hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, dmg], log=self.logs / 'attach.log')
        try:
            shipped = mount / APP_NAME
            run(['codesign', '--verify', '--deep', '--strict', shipped])
            run(['xcrun', 'stapler', 'validate', shipped])
            for role, path in self.components(app).items():
                inner = shipped / path.relative_to(app)
                if signature_identity(inner) != signature_identity(path):
                    raise ReleaseError('the DMG ' + role + ' differs from the verified staging copy')
            checks['dmg_contents'] = 'passed'
        finally:
            run(['hdiutil', 'detach', mount])
        self.receipt['verification'] = checks

    def step_publish(self):
        target = self.args.publish_dir.expanduser()
        target.mkdir(parents=True, exist_ok=True)
        dmg = self.stage / self.receipt['dmg']
        shutil.copyfile(dmg, target / dmg.name)
        if digest(target / dmg.name) != digest(dmg):
            raise ReleaseError('published DMG differs from the verified DMG')
        self.receipt['dmg_sha256'] = digest(dmg)
        self.receipt['dmg_bytes'] = dmg.stat().st_size
        (target / 'SHA256SUMS').write_text(self.receipt['dmg_sha256'] + '  ' + dmg.name + '\n')
        self.receipt['published_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.save()
        shutil.copyfile(self.receipt_path, target / 'release-receipt.json')

    def step_clean(self):
        for path in (self.derived, self.archive, self.exported, BUILD / 'gomodcache', BUILD / 'mnt',
                     BUILD / 'dmg-root', BUILD / 'SafariProxyMac-notary.zip'):
            if path.exists() or path.is_symlink():
                remove_tree(path) if path.is_dir() and not path.is_symlink() else path.unlink()
        for work in self.engine.glob('engine-*'):
            remove_tree(work)


def der_to_raw(der: bytes) -> bytes:
    """ECDSA DER SEQUENCE(r, s) -> the 64-byte R||S form JWS ES256 requires."""
    if der[0] != 0x30:
        raise ReleaseError('unexpected ECDSA signature encoding')
    offset = 2 if der[1] < 0x80 else 2 + (der[1] & 0x7f)
    parts = []
    for _ in range(2):
        if der[offset] != 0x02:
            raise ReleaseError('unexpected ECDSA integer encoding')
        length = der[offset + 1]
        value = der[offset + 2:offset + 2 + length].lstrip(b'\x00')
        if len(value) > 32:
            raise ReleaseError('ECDSA integer too long')
        parts.append(value.rjust(32, b'\x00'))
        offset += 2 + length
    return parts[0] + parts[1]


def keychain_certificate_serial(identity: str) -> str:
    pem = subprocess.run(['security', 'find-certificate', '-c', identity, '-p'],
                         capture_output=True, check=True, text=True).stdout
    if pem.count('BEGIN CERTIFICATE') != 1:
        raise ReleaseError('expected exactly one keychain certificate named ' + identity)
    text = subprocess.run(['/usr/bin/openssl', 'x509', '-noout', '-serial'], input=pem,
                          capture_output=True, check=True, text=True).stdout
    return text.strip().split('=', 1)[1].lstrip('0').upper()


def signature_identity(path: Path) -> list[str]:
    details = run(['codesign', '-dvvv', path], capture=True)
    return re.findall(r'^(?:Identifier|CDHash|Authority|TeamIdentifier|Timestamp)=.*$', details, re.M)


def remove_tree(path: Path):
    for root, dirs, _ in os.walk(path):
        for name in dirs:
            if not os.path.islink(os.path.join(root, name)):  # never chmod a link target
                os.chmod(os.path.join(root, name), 0o755)
    os.chmod(path, 0o755)
    shutil.rmtree(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--steps', default=','.join(STEPS), help='comma list from: ' + ', '.join(STEPS))
    go_pin = json.loads((REPO / 'tools/toolchain-pins.json').read_text())['tools']['go']['version']
    parser.add_argument('--go', type=Path, default=Path('~/.local/toolchains/go' + go_pin + '/bin/go'),
                        help='Go executable matching tools/toolchain-pins.json and the engine go.mod')
    parser.add_argument('--module-cache', type=Path, default=Path('~/.local/gopath/pkg/mod'))
    parser.add_argument('--api-key', type=Path, required=True, help='App Store Connect AuthKey_<KEYID>.p8')
    parser.add_argument('--env-file', type=Path, default=Path('~/.winsvpn/apple_appstoreconnect.env'),
                        help='file defining ' + ISSUER_VARIABLE + ' (or set it in the environment)')
    parser.add_argument('--publish-dir', type=Path, default=Path("~/Desktop/WinsVPN Safari Proxy release"))
    parser.add_argument('--allow-dirty', action='store_true', help='rehearsal only: build uncommitted inputs')
    args = parser.parse_args()
    steps = [s.strip() for s in args.steps.split(',') if s.strip()]
    unknown = set(steps) - set(STEPS)
    if unknown:
        parser.error('unknown steps: ' + ', '.join(sorted(unknown)))
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ReleaseError('build on a macOS arm64 host')
    release = Release(args)
    for step in STEPS:
        if step in steps:
            print(f'== {step}', flush=True)
            getattr(release, 'step_' + step)()
            release.receipt.setdefault('steps', {})[step] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            release.save()
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, subprocess.SubprocessError, KeyError, ValueError) as error:
        print('build_release: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
