#!/usr/bin/env python3
"""Generate the standalone project without package resolution or third-party tools."""
from pathlib import Path
import hashlib
import json
import plistlib
import re

ROOT = Path(__file__).resolve().parents[1]
OBJECTS = {}
BASE_ID = 'org.winsvpn.safariproxy'


def ident(name):
    return hashlib.sha256(name.encode()).hexdigest()[:24].upper()


def obj(object_name, isa, **fields):
    key = ident(object_name)
    OBJECTS[key] = {'isa': isa, **fields}
    return key


def plist(name, values):
    (ROOT / 'Config' / name).write_bytes(plistlib.dumps(values, sort_keys=True))


def main():
    version = re.findall(r"^version: ([0-9]+\.[0-9]+\.[0-9]+)\+([0-9]+)$",
        (ROOT.parents[1] / "pubspec.yaml").read_text(), re.MULTILINE)
    if len(version) != 1:
        raise ValueError("The repository pubspec must provide one numeric version and build")
    marketing, build_number = version[0]
    # Preserve the exact bundled consent documents and versions from the app.
    dart = (ROOT.parents[1] / 'lib/main.dart').read_text()
    def body(name):
        match = re.search(r'static const String ' + name + r'\s*=\s*("(?:[^"\\]|\\.)*")\s*;', dart)
        if not match:
            raise ValueError('Missing bundled consent source: ' + name)
        return json.loads(match[1])
    def constant(name):
        return re.search(r"static const String " + name + r"\s*=\s*'([^']+)';", dart)[1]
    resources = ROOT / 'Resources'
    resources.mkdir(exist_ok=True)
    privacy_url = re.search(r"'WINS_PRIVACY_POLICY_URL',\s*defaultValue: '([^']+)'", dart)[1]
    (resources / 'Legal.plist').write_bytes(plistlib.dumps(dict(
        body=body('_legalFallbackBody'), privacy=body('_privacyPolicyBody'),
        version=constant('_legalDocumentVersion'), privacyVersion=constant('_privacyPolicyVersion'),
        privacyURL=privacy_url), sort_keys=True))
    common = {
        'CFBundleDevelopmentRegion': 'en', 'CFBundleExecutable': '$(EXECUTABLE_NAME)',
        'CFBundleIdentifier': '$(PRODUCT_BUNDLE_IDENTIFIER)',
        'CFBundleInfoDictionaryVersion': '6.0', 'CFBundleName': '$(PRODUCT_NAME)',
        'CFBundleShortVersionString': '$(MARKETING_VERSION)', 'CFBundleVersion': '$(CURRENT_PROJECT_VERSION)',
        'SafariProxySystemExtensionIdentifier': '$(SAFARI_PROXY_BASE_ID).network',
        'SafariProxyKeychainAccessGroup': '$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).control',
        'SafariProxySessionAccessGroup': '$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).session',
        # Team-prefixed: a Developer ID build needs no portal-registered group and
        # macOS 15+ grants the container without a provisioning-profile check.
        'SafariProxyAppGroup': '$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID)',
    }
    plist('MacApp-Info.plist', dict(common, CFBundlePackageType='APPL',
        LSMinimumSystemVersion='$(MACOSX_DEPLOYMENT_TARGET)', NSPrincipalClass='NSApplication'))
    plist('iOSApp-Info.plist', dict(common, CFBundlePackageType='APPL',
        LSRequiresIPhoneOS=True, UILaunchScreen={},
        UIApplicationSceneManifest={'UIApplicationSupportsMultipleScenes': False},
        UISupportedInterfaceOrientations=['UIInterfaceOrientationPortrait', 'UIInterfaceOrientationPortraitUpsideDown',
            'UIInterfaceOrientationLandscapeLeft', 'UIInterfaceOrientationLandscapeRight']))
    web = dict(common, CFBundlePackageType='XPC!', NSExtension={
        'NSExtensionPointIdentifier': 'com.apple.Safari.web-extension',
        'NSExtensionPrincipalClass': '$(PRODUCT_MODULE_NAME).SafariWebExtensionHandler'})
    plist('Web-Info.plist', web)
    plist('Network-Info.plist', dict(common, CFBundlePackageType='SYSX', LSBackgroundOnly=True,
        NSSystemExtensionUsageDescription='The Safari proxy needs a native provider to route browser traffic.',
        NetworkExtension={
            'NEMachServiceName': '$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).network',
            'NEProviderClasses': {
                'com.apple.networkextension.app-proxy': '$(PRODUCT_MODULE_NAME).TransparentProxyProvider',
                'com.apple.networkextension.dns-proxy': '$(PRODUCT_MODULE_NAME).DNSProxyProvider',
            },
        }))
    keychain = {'keychain-access-groups': ['$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).control']}
    session_keychain = {'keychain-access-groups': keychain['keychain-access-groups'] +
        ['$(AppIdentifierPrefix)$(SAFARI_PROXY_BASE_ID).session']}
    plist('MacApp.entitlements', dict(session_keychain, **{
        'com.apple.security.app-sandbox': True,
        'com.apple.security.network.client': True,
        'com.apple.security.application-groups': ['$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID)'],
        'com.apple.developer.system-extension.install': True,
        'com.apple.developer.networking.networkextension': ['app-proxy-provider-systemextension', 'dns-proxy-systemextension'],
    }))
    plist('MacWeb.entitlements', dict(keychain, **{
        'com.apple.security.app-sandbox': True,
        'com.apple.developer.networking.networkextension': ['app-proxy-provider-systemextension'],
    }))
    plist('Network.entitlements', dict(session_keychain, **{
        'com.apple.security.app-sandbox': True,
        'com.apple.security.network.client': True,
        'com.apple.security.network.server': True,
        'com.apple.security.application-groups': ['$(TeamIdentifierPrefix)$(SAFARI_PROXY_BASE_ID)'],
        'com.apple.developer.networking.networkextension': ['app-proxy-provider-systemextension', 'dns-proxy-systemextension'],
    }))
    # No routing or shared-control privilege on iOS until its native design exists.
    plist('iOSApp.entitlements', {})
    plist('iOSWeb.entitlements', {})
    (ROOT / 'Config' / 'Common.xcconfig').write_text(
        '// Development identities. Supply the approved identity and team when signing.\n'
        f'SAFARI_PROXY_BASE_ID = {BASE_ID}\n'
        'DEVELOPMENT_TEAM =\n'
        f'MARKETING_VERSION = {marketing}\n'
        f'CURRENT_PROJECT_VERSION = {build_number}\n'
        'ENABLE_DEBUG_DYLIB = NO\n'
        'SAFARI_WEB_PACKAGE = $(SRCROOT)/../../extension/dist/safari\n'
        'SAFARI_ENGINE_ARCHIVE = $(SRCROOT)/Artifacts/Engine/libSafariWinn-macos-$(CURRENT_ARCH).a\n'
        'SWIFT_VERSION = 5.0\n'
        'MACOSX_DEPLOYMENT_TARGET = 14.0\n'
        'IPHONEOS_DEPLOYMENT_TARGET = 18.0\n'
        'CODE_SIGN_STYLE = Manual\n'
        'ENABLE_USER_SCRIPT_SANDBOXING = YES\n'
        'CLANG_ENABLE_MODULES = YES\n'
        'SWIFT_EMIT_LOC_STRINGS = NO\n'
        'ENABLE_HARDENED_RUNTIME = YES\n'
    )
    config_ref = obj('config-file', 'PBXFileReference', lastKnownFileType='text.xcconfig', path='Config/Common.xcconfig', sourceTree='<group>')
    files = [config_ref]
    products = []
    targets = []
    project_id = ident('project')

    def file_ref(path, file_type='sourcecode.swift', source_tree='SOURCE_ROOT'):
        key = ident('file:' + path)
        if key not in OBJECTS:
            obj('file:' + path, 'PBXFileReference', lastKnownFileType=file_type, path=path, sourceTree=source_tree)
            files.append(key)
        return key

    shared = ['Shared/ControlProtocol.swift', 'Shared/ControlKeychain.swift', 'Shared/ControlClient.swift']
    specs = [
        ('SafariProxyNetwork', 'macosx', 'com.apple.product-type.system-extension', '.systemextension',
         ['Provider/main.swift', 'Provider/TransparentProxyProvider.swift', 'Provider/DNSProxyProvider.swift',
          'Provider/SafariAppFlow.swift', 'Shared/SafariForwardError.swift', 'Shared/SafariPacketRuntime.swift',
          'Shared/SafariDNSWire.swift', 'Shared/SafariDNSBroker.swift', 'Shared/SafariSessionStore.swift',
          'Shared/ControlProtocol.swift', 'Shared/ControlKeychain.swift', 'Shared/WinnPacketABI.swift'], 'Network', '.network'),
        ('SafariWebMac', 'macosx', 'com.apple.product-type.app-extension', '.appex',
         shared + ['../../extension/safari/SafariWebExtensionHandler.swift'], 'MacWeb', '.web'),
        ('SafariProxyMac', 'macosx', 'com.apple.product-type.application', '.app',
         shared + ['App/SafariProxyApp.swift', 'App/SafariConnection.swift',
          'Shared/SafariForwardError.swift', 'Shared/SafariSessionStore.swift', 'Shared/SafariHubSession.swift',
          'Shared/SafariPinnedHubTransport.swift', 'Shared/SafariHubTrustAnchors.swift',
          '../../extension/safari/native/SafariProxyActivation.swift'], 'MacApp', ''),
        ('SafariWebiOS', 'iphoneos', 'com.apple.product-type.app-extension', '.appex',
         shared + ['../../extension/safari/SafariWebExtensionHandler.swift'], 'iOSWeb', '.ios.web'),
        ('SafariProxyiOS', 'iphoneos', 'com.apple.product-type.application', '.app',
         ['App/SafariProxyApp.swift'], 'iOSApp', '.ios'),
    ]
    for name, sdk, kind, suffix, sources, config, bundle_suffix in specs:
        # sysextd finds a system extension only by <CFBundleIdentifier>.systemextension.
        product_name = BASE_ID + bundle_suffix if suffix == '.systemextension' else name
        product = obj('product:' + name, 'PBXFileReference', explicitFileType=(
            'wrapper.application' if suffix == '.app' else 'wrapper.app-extension' if suffix == '.appex' else 'wrapper.system-extension'
        ), path=product_name + suffix, sourceTree='BUILT_PRODUCTS_DIR', includeInIndex=0)
        products.append(product)
        source_builds = [obj(name + ':' + p, 'PBXBuildFile', fileRef=file_ref(p)) for p in sources]
        phases = [obj(name + ':sources', 'PBXSourcesBuildPhase', buildActionMask=2147483647, files=source_builds, runOnlyForDeploymentPostprocessing=0)]
        if name == 'SafariProxyMac':
            legal = obj(name + ':legal', 'PBXBuildFile', fileRef=file_ref('Resources/Legal.plist', 'text.plist.xml'))
            phases.append(obj(name + ':legal-phase', 'PBXResourcesBuildPhase', buildActionMask=2147483647,
                files=[legal], runOnlyForDeploymentPostprocessing=0))
        if suffix == '.appex':
            resources = [
                obj(name + ':manifest', 'PBXBuildFile', fileRef=file_ref('manifest.json', 'text.json', 'SAFARI_WEB_PACKAGE')),
                obj(name + ':resources', 'PBXBuildFile', fileRef=file_ref('src', 'folder', 'SAFARI_WEB_PACKAGE')),
            ]
            phases.append(obj(name + ':resources-phase', 'PBXResourcesBuildPhase', buildActionMask=2147483647, files=resources, runOnlyForDeploymentPostprocessing=0))
        dependencies = []
        if suffix == '.app':
            embedded = ['SafariWebMac', 'SafariProxyNetwork'] if sdk == 'macosx' else ['SafariWebiOS']
            for child in embedded:
                proxy = obj(name + ':proxy:' + child, 'PBXContainerItemProxy', containerPortal=project_id, proxyType=1, remoteGlobalIDString=ident('target:' + child), remoteInfo=child)
                dependencies.append(obj(name + ':dependency:' + child, 'PBXTargetDependency', target=ident('target:' + child), targetProxy=proxy))
                build = obj(name + ':embed:' + child, 'PBXBuildFile', fileRef=ident('product:' + child), settings={'ATTRIBUTES': ['RemoveHeadersOnCopy']})
                phases.append(obj(name + ':copy:' + child, 'PBXCopyFilesBuildPhase', buildActionMask=2147483647,
                    dstPath='$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions' if child == 'SafariProxyNetwork' else '',
                    dstSubfolderSpec=16 if child == 'SafariProxyNetwork' else 13, files=[build], runOnlyForDeploymentPostprocessing=0))
        configs = []
        for mode in ('Debug', 'Release'):
            settings = dict(
                SDKROOT=sdk, PRODUCT_NAME='$(TARGET_NAME)',
                PRODUCT_BUNDLE_IDENTIFIER='$(SAFARI_PROXY_BASE_ID)' + bundle_suffix,
                INFOPLIST_FILE='Config/' + ('Web' if suffix == '.appex' else config) + '-Info.plist',
                CODE_SIGN_ENTITLEMENTS='Config/' + config + '.entitlements',
                GENERATE_INFOPLIST_FILE='NO',
                SWIFT_OPTIMIZATION_LEVEL='-Onone' if mode == 'Debug' else '-O',
                SWIFT_ACTIVE_COMPILATION_CONDITIONS='DEBUG' if mode == 'Debug' else '',
                SKIP_INSTALL='NO' if suffix == '.app' else 'YES',
                APPLICATION_EXTENSION_API_ONLY='YES' if suffix != '.app' else 'NO',
                LD_RUNPATH_SEARCH_PATHS=['$(inherited)', '@executable_path/../Frameworks', '@executable_path/Frameworks'],
            )
            if sdk == 'iphoneos':
                settings.update(TARGETED_DEVICE_FAMILY='1,2', SUPPORTED_PLATFORMS='iphoneos iphonesimulator', SUPPORTS_MACCATALYST='NO')
            if name == 'SafariProxyNetwork':
                settings.update(OTHER_LDFLAGS=['$(inherited)', '-Wl,-force_load,$(SAFARI_ENGINE_ARCHIVE)',
                    '-lresolv', '-framework', 'Security'], DEAD_CODE_STRIPPING='NO',
                    PRODUCT_NAME='$(PRODUCT_BUNDLE_IDENTIFIER)', PRODUCT_MODULE_NAME=name)
            configs.append(obj(name + ':' + mode, 'XCBuildConfiguration', name=mode, baseConfigurationReference=config_ref, buildSettings=settings))
        config_list = obj(name + ':configs', 'XCConfigurationList', buildConfigurations=configs, defaultConfigurationIsVisible=0, defaultConfigurationName='Debug')
        targets.append(obj('target:' + name, 'PBXNativeTarget', name=name, productName=name, productReference=product, productType=kind,
            buildConfigurationList=config_list, buildPhases=phases, buildRules=[], dependencies=dependencies))

    product_group = obj('products', 'PBXGroup', children=products, name='Products', sourceTree='<group>')
    main_group = obj('main-group', 'PBXGroup', children=files + [product_group], sourceTree='<group>')
    configs = [obj('project:' + m, 'XCBuildConfiguration', name=m, buildSettings={}) for m in ('Debug', 'Release')]
    config_list = obj('project-configs', 'XCConfigurationList', buildConfigurations=configs, defaultConfigurationIsVisible=0, defaultConfigurationName='Debug')
    obj('project', 'PBXProject', attributes={'LastUpgradeCheck': '2700'}, buildConfigurationList=config_list,
        compatibilityVersion='Xcode 14.0', developmentRegion='en', hasScannedForEncodings=0,
        knownRegions=['en', 'Base'], mainGroup=main_group, productRefGroup=product_group,
        projectDirPath='', projectRoot='', targets=targets)

    def render(value, level=0):
        if isinstance(value, dict):
            return '{\n' + ''.join('\t' * (level + 1) + json.dumps(str(k)) + ' = ' + render(v, level + 1) + ';\n' for k, v in value.items()) + '\t' * level + '}'
        if isinstance(value, list):
            return '(' + ', '.join(render(v, level) for v in value) + ')'
        return str(value) if isinstance(value, int) else json.dumps(value)

    project = ROOT / 'SafariProxy.xcodeproj'
    project.mkdir(exist_ok=True)
    (project / 'project.pbxproj').write_text('// !$*UTF8*$!\n' + render(dict(archiveVersion=1, classes={}, objectVersion=56, objects=OBJECTS, rootObject=project_id)) + '\n')
    schemes = project / 'xcshareddata' / 'xcschemes'
    schemes.mkdir(parents=True, exist_ok=True)
    for name in ('SafariProxyMac', 'SafariProxyiOS'):
        (schemes / (name + '.xcscheme')).write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
 <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
  <BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
   <BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident('target:' + name)}" BuildableName="{name}.app" BlueprintName="{name}" ReferencedContainer="container:SafariProxy.xcodeproj"/>
  </BuildActionEntry></BuildActionEntries>
 </BuildAction>
 <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="NO">
  <BuildableProductRunnable runnableDebuggingMode="0"><BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ident('target:' + name)}" BuildableName="{name}.app" BlueprintName="{name}" ReferencedContainer="container:SafariProxy.xcodeproj"/></BuildableProductRunnable>
 </LaunchAction>
 <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')


if __name__ == '__main__':
    main()
