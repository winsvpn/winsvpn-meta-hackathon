// Focused proof that same-UID browser-app impersonation cannot authenticate
// by public HMAC derivation, ad-hoc/wrong-team bundle id, a Program Files
// lookalike, or a Linux broad-prefix executable.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' show Hmac, sha256;
import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/browser_bridge_app_ipc.dart';
import 'package:wins_vpn/browser_bridge_protocol.dart';

const String _kReviewedWindowsSubjectForMatcherProof =
    'CN=Reviewed-WinsVPN-Test';

const String _kMacosValidRequirement =
    'designated => identifier "org.winsvpn.app" and anchor apple generic '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and '
    'certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and '
    'certificate leaf[subject.OU] = "5YT8H4U72M"';

BrowserBridgeAppIpcMacosCodeSignature _macosSignature({
  String identifier = kBrowserBridgeAppIpcMacosBundleId,
  String teamIdentifier = kBrowserBridgeAppIpcMacosTeamIdentifier,
  String designatedRequirement = _kMacosValidRequirement,
  bool currentSignatureValid = true,
  bool adHoc = false,
}) {
  return BrowserBridgeAppIpcMacosCodeSignature(
    identifier: identifier,
    teamIdentifier: teamIdentifier,
    designatedRequirement: designatedRequirement,
    currentSignatureValid: currentSignatureValid,
    adHoc: adHoc,
  );
}

List<BrowserBridgeAppIpcPosixNode> _linuxExactChain({
  String path = kBrowserBridgeAppIpcLinuxInstalledExecutable,
  int leafUid = 0,
  int leafMode = 0x1ED,
  int parentUid = 0,
  int parentMode = 0x1ED,
  bool leafLink = false,
  bool parentLink = false,
  bool isRegularFile = true,
}) {
  return <BrowserBridgeAppIpcPosixNode>[
    BrowserBridgeAppIpcPosixNode(
      path: path,
      uid: leafUid,
      mode: leafMode,
      isLink: leafLink,
      isRegularFile: isRegularFile,
    ),
    BrowserBridgeAppIpcPosixNode(
      path: '/opt/wins-vpn',
      uid: parentUid,
      mode: parentMode,
      isLink: parentLink,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/opt',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
  ];
}

List<BrowserBridgeAppIpcPosixNode> _receiptChain({
  String path = '/usr/local/lib/wins-vpn/browser_bridge.identity',
  int leafUid = 0,
  int leafMode = 0x124,
  int parentUid = 0,
  int parentMode = 0x1ED,
}) {
  return <BrowserBridgeAppIpcPosixNode>[
    BrowserBridgeAppIpcPosixNode(
      path: path,
      uid: leafUid,
      mode: leafMode,
      isLink: false,
      isRegularFile: true,
    ),
    BrowserBridgeAppIpcPosixNode(
      path: '/usr/local/lib/wins-vpn',
      uid: parentUid,
      mode: parentMode,
      isLink: false,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/usr/local/lib',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/usr/local',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/usr',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
    const BrowserBridgeAppIpcPosixNode(
      path: '/',
      uid: 0,
      mode: 0x1ED,
      isLink: false,
    ),
  ];
}

void main() {
  test('public identity cannot derive an IPC MAC key', () {
    final identity = BrowserBridgeAppIpcProcessIdentity.productionFor('macos');
    final publicSecret =
        Hmac(sha256, utf8.encode(kBrowserBridgeAppIpcMacDomain))
            .convert(utf8.encode('${identity.kind}\n${identity.value}'))
            .toString();
    expect(isBrowserBridgeAppIpcTokenShape(publicSecret), isTrue);
    expect(
      () => BrowserBridgeAppIpcTrust.platform(operatingSystem: 'macos'),
      throwsA(
        isA<BrowserBridgeAppIpcException>().having(
          (e) => e.code,
          'code',
          BrowserBridgeAppIpcError.unauthenticatedIdentity,
        ),
      ),
    );
    final owner = BrowserBridgeAppIpcTrust.authenticated(
      secretHex: generateBrowserBridgeAppIpcToken(),
      expectedIdentity: BrowserBridgeAppIpcProcessIdentity.currentProcess(),
    );
    final writtenAt =
        (DateTime.now().toUtc().millisecondsSinceEpoch / 1000).floor();
    final token = generateBrowserBridgeAppIpcToken();
    final ownerMac = browserBridgeAppIpcDiscoveryMac(
      trust: owner,
      host: kBrowserBridgeAppIpcLoopbackHost,
      port: 41234,
      token: token,
      pid: pid,
      writtenAt: writtenAt,
    );
    final publicMac = Hmac(sha256, _hexToBytes(publicSecret))
        .convert(
          utf8.encode(
            '$kBrowserBridgeAppIpcMacDomain\n'
            'host=$kBrowserBridgeAppIpcLoopbackHost\n'
            'port=41234\n'
            'token=$token\n'
            'pid=$pid\n'
            'written_at=$writtenAt\n',
          ),
        )
        .toString();
    expect(ownerMac, isNot(publicMac));
    final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
    expect(source, isNot(contains('_platformSecretHex')));
    expect(
      source,
      isNot(
          contains('Hmac(sha256, utf8.encode(kBrowserBridgeAppIpcMacDomain))')),
    );
  });

  test('macOS same bundle id with wrong team or ad-hoc is refused', () {
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(_macosSignature()),
      isTrue,
    );
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        _macosSignature(teamIdentifier: 'ABCD123456'),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        _macosSignature(
          designatedRequirement:
              'designated => identifier "org.winsvpn.app" and '
              'certificate leaf[subject.OU] = "ABCD123456"',
        ),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        _macosSignature(
          teamIdentifier: 'not set',
          adHoc: true,
          designatedRequirement:
              'designated => identifier "org.winsvpn.app" and anchor adhoc',
        ),
      ),
      isFalse,
    );
    final parsedAdHoc = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\n'
          'TeamIdentifier=not set\n'
          'CodeDirectory v=20400 size=1 flags=0x2(adhoc)\n',
      designatedRequirementText:
          'designated => identifier "org.winsvpn.app" and anchor adhoc',
      verifySucceeded: true,
    );
    expect(parsedAdHoc, isNotNull);
    expect(parsedAdHoc!.adHoc, isTrue);
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(parsedAdHoc),
      isFalse,
    );
    final parsedWrongTeam = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\nTeamIdentifier=ABCD123456\n',
      designatedRequirementText:
          'designated => identifier "org.winsvpn.app" and '
          'certificate leaf[subject.OU] = "ABCD123456"',
      verifySucceeded: true,
    );
    expect(parsedWrongTeam, isNotNull);
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(parsedWrongTeam!),
      isFalse,
    );
  });

  test('Mac App Store re-signed app with Apple\'s MAS DR authenticates', () {
    // Apple re-signs App Store copies ("Apple Mac OS Application Signing");
    // their designated requirement is Apple's two-branch MAS form, which
    // still names the bundle id and the team OU in its Developer ID branch.
    const masRequirement = 'designated => identifier "org.winsvpn.app" and '
        'anchor apple generic and certificate '
        'leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple '
        'generic and certificate 1[field.1.2.840.113635.100.6.2.6] '
        '/* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] '
        '/* exists */ and certificate leaf[subject.OU] = "5YT8H4U72M"';
    final parsed = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\n'
          'Format=app bundle with Mach-O thin (arm64)\n'
          'Authority=Apple Mac OS Application Signing\n'
          'TeamIdentifier=5YT8H4U72M\n'
          'CodeDirectory v=20500 size=1 flags=0x10000(runtime)\n',
      designatedRequirementText: masRequirement,
      verifySucceeded: true,
    );
    expect(parsed, isNotNull);
    expect(browserBridgeAppIpcMacosCodeSignatureAuthenticates(parsed!), isTrue);
    // The same MAS shape for another team or bundle id is refused.
    final otherTeam = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\nTeamIdentifier=ABCD123456\n',
      designatedRequirementText:
          masRequirement.replaceAll('5YT8H4U72M', 'ABCD123456'),
      verifySucceeded: true,
    );
    expect(browserBridgeAppIpcMacosCodeSignatureAuthenticates(otherTeam!),
        isFalse);
    // csreq prints a digit-leading OU quoted and a letter-leading OU bare
    // (measured on four real MAS apps). Only the exact team, in either
    // spelling, is accepted.
    BrowserBridgeAppIpcMacosCodeSignature? withOu(String ou,
        {String team = '5YT8H4U72M'}) {
      return parseBrowserBridgeAppIpcMacosCodeSignature(
        displayText: 'Identifier=org.winsvpn.app\nTeamIdentifier=$team\n',
        designatedRequirementText:
            masRequirement.replaceAll('"5YT8H4U72M"', ou),
        verifySucceeded: true,
      );
    }

    expect(browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        withOu('5YT8H4U72M')!), isTrue);
    expect(browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        withOu('"5YT8H4U72M"')!), isTrue);
    for (final wrong in <String>[
      '5YT8H4U72MX',
      '"5YT8H4U72MX"',
      'X5YT8H4U72M',
      '"5YT8H4U72M',
      '5YT8H4U72M"',
      '"ABCD123456"',
    ]) {
      expect(
          browserBridgeAppIpcMacosCodeSignatureAuthenticates(withOu(wrong)!),
          isFalse,
          reason: wrong);
    }
    // The TeamIdentifier line is the MAS team pin: a DR naming the right
    // team with another CodeDirectory team is refused.
    expect(
        browserBridgeAppIpcMacosCodeSignatureAuthenticates(
            withOu('"5YT8H4U72M"', team: 'ABCD123456')!),
        isFalse);
    final failedVerify = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\nTeamIdentifier=5YT8H4U72M\n',
      designatedRequirementText: masRequirement,
      verifySucceeded: false,
    );
    expect(
      failedVerify == null ||
          !browserBridgeAppIpcMacosCodeSignatureAuthenticates(failedVerify),
      isTrue,
    );
    // The live codesign requirement accepts the MAS leaf marker or a
    // Developer ID chain pinned to this team, never a bare apple anchor.
    final source = File('lib/browser_bridge_app_ipc.dart').readAsStringSync();
    expect(source, contains('leaf[field.1.2.840.113635.100.6.1.9]'));
    expect(source, contains('1[field.1.2.840.113635.100.6.2.6]'));
    expect(source, contains('leaf[field.1.2.840.113635.100.6.1.13]'));
    expect(source, contains("'\"\$kBrowserBridgeAppIpcMacosBundleId\" and '"));
  });

  test('macOS exact bundle id, team, DR, and current signature authenticates',
      () {
    final parsed = parseBrowserBridgeAppIpcMacosCodeSignature(
      displayText: 'Identifier=org.winsvpn.app\n'
          'Format=app bundle\n'
          'TeamIdentifier=5YT8H4U72M\n'
          'CodeDirectory v=20400 size=1 flags=0x0(none)\n',
      designatedRequirementText: _kMacosValidRequirement,
      verifySucceeded: true,
    );
    expect(parsed, isNotNull);
    expect(browserBridgeAppIpcMacosCodeSignatureAuthenticates(parsed!), isTrue);
    expect(
      browserBridgeAppIpcMacosCodeSignatureAuthenticates(
        _macosSignature(currentSignatureValid: false),
      ),
      isFalse,
    );
  });

  test('Windows Program Files lookalike, unsigned, and wrong signer fail', () {
    const exact = r'C:\Program Files\WinsVPN\wins_vpn.exe';
    const programFiles = r'C:\Program Files';
    final valid = const BrowserBridgeAppIpcWindowsAuthenticode(
      status: 'Valid',
      subject: _kReviewedWindowsSubjectForMatcherProof,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: r'C:\Users\wins\Program Files\WinsVPN\wins_vpn.exe',
        programFiles: programFiles,
        authenticode: valid,
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: r'C:\Program Files\WinsVPN\..\..\Users\wins\wins_vpn.exe',
        programFiles: programFiles,
        authenticode: valid,
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: r'C:\Program Files (x86)\WinsVPN\wins_vpn.exe',
        programFiles: programFiles,
        authenticode: valid,
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: exact,
        programFiles: programFiles,
        authenticode: const BrowserBridgeAppIpcWindowsAuthenticode(
          status: 'NotSigned',
          subject: '',
        ),
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: exact,
        programFiles: programFiles,
        authenticode: const BrowserBridgeAppIpcWindowsAuthenticode(
          status: 'Valid',
          subject: 'CN=Wrong Signer',
        ),
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: exact,
        programFiles: programFiles,
        authenticode: valid,
        reviewedSubject: kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject,
      ),
      isFalse,
    );
  });

  test('Windows exact installed path plus reviewed Authenticode authenticates',
      () {
    expect(
      kBrowserBridgeAppIpcWindowsReviewedAuthenticodeSubject,
      isNull,
    );
    expect(
      browserBridgeAppIpcWindowsInstalledExecutableAuthenticates(
        observedPath: r'C:\Program Files\WinsVPN\wins_vpn.exe',
        programFiles: r'C:\Program Files',
        authenticode: const BrowserBridgeAppIpcWindowsAuthenticode(
          status: 'Valid',
          subject: _kReviewedWindowsSubjectForMatcherProof,
        ),
        reviewedSubject: _kReviewedWindowsSubjectForMatcherProof,
      ),
      isTrue,
    );
  });

  test('Linux broad-prefix lookalikes are not the installed executable', () {
    const selfUid = 1000;
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: '/usr/bin/wins-vpn',
        selfUid: selfUid,
        fileThenAncestors: _linuxExactChain(path: '/usr/bin/wins-vpn'),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: '/usr/local/lib/wins-vpn/wins_vpn',
        selfUid: selfUid,
        fileThenAncestors:
            _linuxExactChain(path: '/usr/local/lib/wins-vpn/wins_vpn'),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: '/opt/wins-vpn/extra/wins_vpn',
        selfUid: selfUid,
        fileThenAncestors:
            _linuxExactChain(path: '/opt/wins-vpn/extra/wins_vpn'),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: '/opt/wins-vpn/../tmp/wins_vpn',
        selfUid: selfUid,
        fileThenAncestors: _linuxExactChain(),
      ),
      isFalse,
    );
  });

  test('Linux exact root-owned non-writable installed path authenticates', () {
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: kBrowserBridgeAppIpcLinuxInstalledExecutable,
        selfUid: 1000,
        fileThenAncestors: _linuxExactChain(),
      ),
      isTrue,
    );
  });

  test('writable receipt or ancestry is not owner issuance', () {
    const selfUid = 1000;
    expect(
      browserBridgeAppIpcPosixOwnerReceiptSafe(
        selfUid: selfUid,
        fileThenAncestors: _receiptChain(leafMode: 0x1B6),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcPosixOwnerReceiptSafe(
        selfUid: selfUid,
        fileThenAncestors: _receiptChain(parentMode: 0x1FF),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcPosixOwnerReceiptSafe(
        selfUid: selfUid,
        fileThenAncestors: _receiptChain(parentUid: selfUid),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcLinuxInstalledExecutableAuthenticates(
        observedPath: kBrowserBridgeAppIpcLinuxInstalledExecutable,
        selfUid: selfUid,
        fileThenAncestors: _linuxExactChain(parentMode: 0x1FF),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcPosixOwnerReceiptSafe(
        selfUid: selfUid,
        fileThenAncestors: _receiptChain(),
      ),
      isTrue,
    );
  });

  test(
      'CONNECTED admission still requires authenticated identity and proxyReady',
      () {
    final connected = BridgeStatus(
      status: BridgeTunnelStatus.connected,
      detail: BridgeDetailCode.none,
      winn: BridgeWinnState.unavailableOnThisPlatform,
      selectedSlug: 'japan',
      nodes: <BridgeNode>[
        BridgeNode(slug: 'japan', name: 'Japan', flag: 'JP'),
      ],
      canRequestConnect: false,
      proxyPort: 1,
      proxyReady: true,
    );
    expect(
      browserBridgeAppIpcAdmitStatus(
        connected,
        authenticatedAppIdentity: false,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      ).status,
      BridgeTunnelStatus.appNotRunning,
    );
    expect(
      browserBridgeAppIpcMayIssueProxyCredential(
        browserBridgeAppIpcAdmitStatus(
          connected,
          authenticatedAppIdentity: false,
          winn: BridgeWinnState.unavailableOnThisPlatform,
        ),
      ),
      isFalse,
    );
    expect(
      browserBridgeAppIpcAdmitStatus(
        connected,
        authenticatedAppIdentity: true,
        winn: BridgeWinnState.unavailableOnThisPlatform,
      ).status,
      BridgeTunnelStatus.connected,
    );
    expect(browserBridgeAppIpcMayIssueProxyCredential(connected), isTrue);
  });
}

Uint8List _hexToBytes(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
