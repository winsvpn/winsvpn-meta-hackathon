/// TLS certificate pinning for the control plane.
///
/// The gateway/nodes/announcement control-plane requests (activation, account
/// status, node discovery, legal fetch, logout, account deletion, double-VPN
/// assignment, free-access status) were made through the stock `package:http`
/// client, which trusts whatever the operating system trusts. On a censored
/// network the realistic adversary already sits inside the CA trust boundary
/// (a state CA installed by the operator, an employer profile, a coerced
/// store), so plain Web PKI gives no assurance at all about WHO answered a
/// `/nodes` or `/account/status` call. Anchoring this client to a small
/// compiled root set removes the device trust store from that decision
/// entirely.
///
/// ## How verification works
///
/// [createPinnedControlPlaneClient] builds an `HttpClient` on a
/// `SecurityContext(withTrustedRoots: false)` whose ONLY trust anchors are
/// the CA roots embedded in [kControlPlanePinnedCertificatePem]: the roots of
/// the four certificate authorities Cloudflare documents for its edge
/// certificates and their automatic backups (Google Trust Services, Let's
/// Encrypt, SSL.com, Sectigo), 12 certificates, each in both the Mozilla and
/// Apple root programs. The device trust store is never consulted, so a
/// state, employer or coerced CA installed on the device cannot validate a
/// connection, and neither can any of the other public roots an operating
/// system ships.
///
/// The platform validates chain, hostname (subjectAltName) and validity
/// dates against exactly those anchors, with no `onBadCertificate` override:
/// any failure is a [HandshakeException] before a request exists.
///
/// The leaf key itself is NOT pinned. Cloudflare generates a new key at each
/// routine renewal (all eight control-plane hosts rotated on 2026-10-02 and
/// 2026-10-03), and activates a backup certificate with a different key from
/// a different one of those CAs on revocation or key compromise. A leaf-SPKI
/// pin therefore fails closed for every installed app at the next renewal;
/// the anchor set is the pin instead.
///
/// ## Exact-connection pre-send gate (WVP-001)
///
/// The pinned client supplies [HttpClient.connectionFactory] with a factory
/// that completes TLS itself. Before the factory resolves the socket future,
/// it reads [SecureSocket.peerCertificate] from that exact connection and
/// checks it with [controlPlaneValidatedLeafAcceptable] for the requested
/// host. A failure destroys the socket and throws [HandshakeException].
/// `HttpClient.openUrl` cannot expose a writable request until the socket
/// future resolves, so no HTTP header or body byte can leave on a connection
/// that did not pass both the platform chain gate and this gate. Pooled
/// connections were checked before entering the pool; every new connection
/// passes through the factory again.
///
/// Automatic redirects are disabled on every hop. Eligible redirects are
/// followed manually. Each target is checked for HTTPS, a non-empty hostname
/// in the compiled host set or admitted by an unexpired signed-discovery
/// lease ([signedDiscoveryRequestAuthorized]), a valid TCP port, and no
/// userinfo or IP-literal host before any redirected request byte is
/// written; the exact TLS
/// connection is then verified the same way. HTTP downgrades and malformed
/// Location values fail closed. Redirects are capped. Cross-origin redirects
/// carry only a small allowlist of public negotiation headers by default and
/// never forward Authorization or X-Wins-Activation. Any other header
/// requires an explicit [ControlPlaneRedirectHeaderPolicy] decision for the
/// exact source origin, target origin and header name; transport and
/// content-framing headers can never be authorized.
///
/// [PinnedOriginLedger] remains as an in-memory observation/API-compatibility
/// surface. It is never consulted to authorize a request, so its TTL cannot
/// create a leaf-swap window.
///
/// ## What this does not protect against
///
/// A certificate mis-issued for a control-plane hostname by one of the 12
/// anchored roots, including one obtained through a registrar or DNS
/// takeover, validates. Its holder can read every request sent on that
/// connection, including bearer tokens and the activation secret, and can
/// forge every hub reply except the two that carry offline Ed25519
/// signatures: announcements and Winn3 gateway descriptors. Certificate
/// Transparency monitoring of the three zones can reveal such a
/// certificate only after issuance and only if it was logged; this client
/// does not check SCTs itself.
///
/// ## Provenance of the anchors
///
/// Extracted 2026-10-04 from the macOS SystemRootCertificates keychain and
/// cross-checked byte for byte against the certifi (Mozilla) bundle. The
/// certificate SHA-256 of each anchor is recorded beside its SPKI pin in
/// [kControlPlaneAnchorSpkiPins]. All eight control-plane chains captured on
/// 2026-10-04 (leaf, WE1, GTS Root R4 cross-signed by GlobalSign Root CA)
/// validate to the anchored GTS Root R4 (`openssl verify -CAfile`).
///
/// ## Escaping this layer
///
/// `WINS_CONTROL_PLANE_PINNING_DISABLED=true` (a dart-define) turns the pin
/// check off for LOCAL development against a trusted MITM proxy. It is
/// compile-time and it is asserted away from release builds: the gate in
/// [controlPlanePinningEnforced] returns true for a release build regardless
/// of the define, and [createPinnedControlPlaneClient] carries an assert
/// that fails any non-release compile which sets the flag, so the flag can
/// never ride along into a shipped artifact unnoticed.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' show sha256;
import 'package:flutter/foundation.dart'
    show kReleaseMode, visibleForTesting;
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import 'signed_discovery_admission.dart';

/// Hosts the pinned client may connect to. The mirror fleet
/// (`<label>.app-cloud-sync.net`) is matched by zone suffix in
/// [controlPlaneSpkiPinsForHost].
const Set<String> kControlPlaneHosts = <String>{
  'sync.winsvpn.org',
  'hub.winsvpn.org',
  'winsvpn.org',
  'www.winsvpn.org',
  'sync.winsvpn.com',
  'www.winsvpn.com',
};

const String _kAppCloudSyncZone = 'app-cloud-sync.net';

/// SHA-256 (base64) of the DER SubjectPublicKeyInfo of every trust anchor in
/// [kControlPlanePinnedCertificatePem], in the same order. A chain the
/// platform accepts must end at one of these keys.
/// `test/control_plane_pinning_test.dart` decodes the PEM block and asserts
/// this list equals the anchors' SPKIs exactly, so neither side can drift.
const List<String> kControlPlaneAnchorSpkiPins = <String>[
  // Google Trust Services: GTS Root R1 (RSA)
  //   cert sha256 d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf
  'hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=',
  // Google Trust Services: GTS Root R4 (ECDSA P-384), anchors today's WE1 chains
  //   cert sha256 349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d
  'mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=',
  // Let's Encrypt: ISRG Root X1 (RSA)
  //   cert sha256 96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6
  'C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=',
  // Let's Encrypt: ISRG Root X2 (ECDSA)
  //   cert sha256 69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470
  'diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=',
  // SSL.com Root Certification Authority RSA
  //   cert sha256 85666a562ee0be5ce925c1d8890a6f76a87ec16d4d7d5f29ea7419cf20123b69
  '0cRTd+vc1hjNFlHcLgLCHXUeWqn80bNDH/bs9qMTSPo=',
  // SSL.com Root Certification Authority ECC
  //   cert sha256 3417bb06cc6007da1b961c920b8ab4ce3fad820e4aa30b9acbc4a74ebdcebc65
  'oyD01TTXvpfBro3QSZc1vIlcMjrdLTiL/M9mLCPX+Zo=',
  // SSL.com TLS RSA Root CA 2022
  //   cert sha256 8faf7d2e2cb4709bb8e0b33666bf75a5dd45b5de480f8ea8d4bfe6bebc17f2ed
  'K89VOmb1cJAN3TK6bf4ezAbJGC1mLcG2Dh97dnwr3VQ=',
  // SSL.com TLS ECC Root CA 2022
  //   cert sha256 c32ffd9f46f936d16c3673990959434b9ad60aafbb9e7cf33654f144cc1ba143
  'G/ANXI8TwJTdF+AFBM8IiIUPEv0Gf6H5LA/b9guG4yE=',
  // Sectigo: USERTrust RSA Certification Authority
  //   cert sha256 e793c9b02fd8aa13e21c31228accb08119643b749c898964b1746d46c3d4cbd2
  'x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=',
  // Sectigo: USERTrust ECC Certification Authority
  //   cert sha256 4ff460d54b9c86dabfbcfc5712e0400d2bed3fbc4d4fbdaa86e06adcd2a9ad7a
  'ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=',
  // Sectigo Public Server Authentication Root R46
  //   cert sha256 7bb647a62aeeac88bf257aa522d01ffea395e0ab45c73f93f65654ec38f25a06
  'Douxi77vs4G+Ib/BogbTFymEYq0QSFXwSgVCaZcI09Q=',
  // Sectigo Public Server Authentication Root E46
  //   cert sha256 c90f26f0fb1b4018b22227519b5ca2b53e2ca5b3be5cf18efe1bef47380c5383
  'sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=',
];

/// The anchor SPKI pins that apply to [host] (the same list for every
/// control-plane host), or null when the host is not a control-plane host.
/// The pinned client refuses anything this returns null for, so callers must
/// only route control-plane URLs through it.
List<String>? controlPlaneSpkiPinsForHost(String host) {
  final normalized = host.trim().toLowerCase();
  if (normalized.isEmpty) return null;
  if (kControlPlaneHosts.contains(normalized) ||
      normalized.endsWith('.$_kAppCloudSyncZone')) {
    return kControlPlaneAnchorSpkiPins;
  }
  return null;
}

/// The trust anchors of the pinned client, in [kControlPlaneAnchorSpkiPins]
/// order. Self-signed roots only: no leaf and no intermediate is anchored, so
/// neither a renewal nor an intermediate rotation inside these CAs can strand
/// an install.
const String kControlPlanePinnedCertificatePem = '''
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYD
VQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIG
A1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAw
WjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2Vz
IExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyi
QHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvR
HYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D
9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8
p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF3TCCA8WgAwIBAgIIeyyb0xaAMpkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
BhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQK
DA9TU0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eSBSU0EwHhcNMTYwMjEyMTczOTM5WhcNNDEwMjEyMTcz
OTM5WjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hv
dXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNv
bSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAPkP3aMrfcvQKv7sZ4Wm5y4bunfh4/WvpOz6Sl2R
xFdHaxh3a3by/ZPkPQ/CFp4LZsNWlJ4Xg4XOVu/yFv0AYvUiCVToZRdOQbngT0aX
qhvIuG5iXmmxX9sqAn78bMrzQdjt0Oj8P2FI7bADFB0QDksZ4LtO7IZl/zbzXmcC
C52GVWH9ejjt/uIZALdvoVBidXQ8oPrIJZK0bnoix/geoeOy3ZExqysdBP+lSgQ3
6YWkMyv94tZVNHwZpEpox7Ko07fKoZOI68GXvIz5HdkihCR0xwQ9aqkpk8zruFvh
/l8lqjRYyMEjVJ0bmBHDOJx+PYZspQ9AhnwC9FwCTyjLrnGfDzrIM/4RJTXq/LrF
YD3ZfBjVsqnTdXgDciLKOsMf7yzlLqn6niy2UUb9rwPW6mBo6oUWNmuF6R7As93E
JNyAKoFBbZQ+yODJgUEAnl6/f8UImKIYLEJAs/lvOCdLToD0PYFH4Ih86hzOtXVc
US4cK38acijnALXRdMbX5J+tB5O2UzU1/Dfkw/ZdFr4hc96SCvigY2q8lpJqPvi8
ZVWb3vUNiSYE/CUapiVpy8JtynziWV+XrOvvLsi81xtZPCvM8hnIk2snYxnP/Okm
+Mpxm3+T/jRnhE6Z6/yzeAkzcLpmpnbtG3PrGqUNxCITIJRWCk4sbE6x/c+cCbqi
M+2HAgMBAAGjYzBhMB0GA1UdDgQWBBTdBAkHovV6fVJTEpKV7jiAJQ2mWTAPBgNV
HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFN0ECQei9Xp9UlMSkpXuOIAlDaZZMA4G
A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAIBgRlCn7Jp0cHh5wYfGV
cpNxJK1ok1iOMq8bs3AD/CUrdIWQPXhq9LmLpZc7tRiRux6n+UBbkflVma8eEdBc
Hadm47GUBwwyOabqG7B52B2ccETjit3E+ZUfijhDPwGFpUenPUayvOUiaPd7nNgs
PgohyC0zrL/FgZkxdMF1ccW+sfAjRfSda/wZY52jvATGGAslu1OJD7OAUN5F7kR/
q5R4ZJjT9ijdh9hwZXT7DrkT66cPYakylszeu+1jTBi7qUD3oFRuIIhxdRjqerQ0
cuAjJ3dctpDqhiVAq+8zD8ufgr6iIPv2tS0a5sKFsXQP+8hlAqRSAUfdSSLBv9jr
a6x+3uxjMxW3IwiPxg+NQVrdjsW5j+VFP3jbutIbQLH+cU0/4IGiul607BXgk90I
H37hVZkLId6Tngr75qNJvTYw/ud3sqB1l7UtgYgXZSD32pAAn8lSzDLKNXz1PQ/Y
K9f1JmzJBjSWFupwWRoyeXkLtoh/D1JIPb9s2KJELtFOt3JY04kTlf5Eq/jXixtu
nLwsoFvVagCvXzfh1foQC5ichucmj87w7G6KVwuA406ywKBjYZC6VWg3dGq2ktuf
oYYitmUnDuy2n0Jg5GfCtdpBC8TTi2EbvPofkSvXRAdeuims2cXp71NIWuuA8ShY
Ic2wBlX7Jz9TkHCpBB5XJ7k=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMC
VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T
U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0
aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYwMjEyMTgxNDAzWhcNNDEwMjEyMTgxNDAz
WjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBS
b290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABEVuqVDEpiM2nl8ojRfLliJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI
7Z4INcgn64mMU1jrYor+8FsPazFSY0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPg
CemB+vNH06NjMGEwHQYDVR0OBBYEFILRhXMw5zUE044CkvvlpNHEIejNMA8GA1Ud
EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgtGFczDnNQTTjgKS++Wk0cQh6M0wDgYD
VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2cAMGQCMG/n61kRpGDPYbCWe+0F+S8T
kdzt5fxQaxFGRrMcIQBiu77D5+jNB5n5DQtdcj7EqgIwH7y6C+IwJPt8bYBVCpk+
gA0z5Wajs6O7pdWLjwkspl1+4vAHCGht0nxpbl/f5Wpl
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFiTCCA3GgAwIBAgIQb77arXO9CEDii02+1PdbkTANBgkqhkiG9w0BAQsFADBO
MQswCQYDVQQGEwJVUzEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMSUwIwYDVQQD
DBxTU0wuY29tIFRMUyBSU0EgUm9vdCBDQSAyMDIyMB4XDTIyMDgyNTE2MzQyMloX
DTQ2MDgxOTE2MzQyMVowTjELMAkGA1UEBhMCVVMxGDAWBgNVBAoMD1NTTCBDb3Jw
b3JhdGlvbjElMCMGA1UEAwwcU1NMLmNvbSBUTFMgUlNBIFJvb3QgQ0EgMjAyMjCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANCkCXJPQIgSYT41I57u9nTP
L3tYPc48DRAokC+X94xI2KDYJbFMsBFMF3NQ0CJKY7uB0ylu1bUJPiYYf7ISf5OY
t6/wNr/y7hienDtSxUcZXXTzZGbVXcdotL8bHAajvI9AI7YexoS9UcQbOcGV0ins
S657Lb85/bRi3pZ7QcacoOAGcvvwB5cJOYF0r/c0WRFXCsJbwST0MXMwgsadugL3
PnxEX4MN8/HdIGkWCVDi1FW24IBydm5MR7d1VVm0U3TZlMZBrViKMWYPHqIbKUBO
L9975hYsLfy/7PO0+r4Y9ptJ1O4Fbtk085zx7AGL0SDGD6C1vBdOSHtRwvzpXGk3
R2azaPgVKPC506QVzFpPulJwoxJF3ca6TvvC0PeoUidtbnm1jPx7jMEWTO6Af77w
dr5BUxIzrlo4QqvXDz5BjXYHMtWrifZOZ9mxQnUjbvPNQrL8VfVThxc7wDNY8VLS
+YCk8OjwO4s4zKTGkH8PnP2L0aPP2oOnaclQNtVcBdIKQXTbYxE3waWglksejBYS
d66UNHsef8JmAOSqg+qKkK3ONkRN0VHpvB/zagX9wHQfJRlAUW7qglFA35u5CCoG
AtUjHBPW6dvbxrB6y3snm/vg1UYk7RBLY0ulBY+6uB0rpvqR4pJSvezrZ5dtmi2f
gTIFZzL7SAg/2SW4BCUvAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
BBgwFoAU+y437uOEeicuzRk1sTN8/9REQrkwHQYDVR0OBBYEFPsuN+7jhHonLs0Z
NbEzfP/UREK5MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAjYlt
hEUY8U+zoO9opMAdrDC8Z2awms22qyIZZtM7QbUQnRC6cm4pJCAcAZli05bg4vsM
QtfhWsSWTVTNj8pDU/0quOr4ZcoBwq1gaAafORpR2eCNJvkLTqVTJXojpBzOCBvf
R4iyrT7gJ4eLSYwfqUdYe5byiB0YrrPRpgqU+tvT5TgKa3kSM/tKWTcWQA673vWJ
DPFs0/dRa1419dvAJuoSc06pkZCmF8NsLzjUo3KUQyxi4U5cMj29TH0ZR6LDSeeW
P4+a0zvkEdiLA9z2tmBVGKaBUfPhqBVq6+AL8BQx1rmMRTqoENjwuSfr98t67wVy
lrXEj5ZzxOhWc5y8aVFjvO9nHEMaX3cZHxj4HCUp+UmZKbaSPaKDN7EgkaibMOlq
bLQjk2UEqxHzDh1TJElTHaE/nUiSEeJ9DU/1172iWD54nR4fK/4huxoTtrEoZP2w
AgDHbICivRZQIA9ygV/MlP+7mea6kMvq+cYMwq7FGc4zoWtcu358NFcXrfA/rs3q
r5nsLFR+jM4uElZI7xc7P0peYNLcdDa8pUNjyw9bowJWCZ4kLOGGgYz+qxcs+sji
Mho6/4UIyYOf8kpIEFR3N+2ivEC+5BB09+Rbu7nzifmPQdjH5FCQNYA+HLhNkNPU
98OwoX6EyneSMSy4kLGCenROmxMmtNVQZlR4rmA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICOjCCAcCgAwIBAgIQFAP1q/s3ixdAW+JDsqXRxDAKBggqhkjOPQQDAzBOMQsw
CQYDVQQGEwJVUzEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMSUwIwYDVQQDDBxT
U0wuY29tIFRMUyBFQ0MgUm9vdCBDQSAyMDIyMB4XDTIyMDgyNTE2MzM0OFoXDTQ2
MDgxOTE2MzM0N1owTjELMAkGA1UEBhMCVVMxGDAWBgNVBAoMD1NTTCBDb3Jwb3Jh
dGlvbjElMCMGA1UEAwwcU1NMLmNvbSBUTFMgRUNDIFJvb3QgQ0EgMjAyMjB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABEUpNXP6wrgjzhR9qLFNoFs27iosU8NgCTWyJGYm
acCzldZdkkAZDsalE3D07xJRKF3nzL35PIXBz5SQySvOkkJYWWf9lCcQZIxPBLFN
SeR7T5v15wj4A4j3p8OSSxlUgaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
GDAWgBSJjy+j6CugFFR781a4Jl9nOAuc0DAdBgNVHQ4EFgQUiY8vo+groBRUe/NW
uCZfZzgLnNAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2gAMGUCMFXjIlbp
15IkWE8elDIPDAI2wv2sdDJO4fscgIijzPvX6yv/N33w7deedWo1dlJF4AIxAMeN
b0Igj762TVntd00pxCAgRWSGOlDGxK0tk/UYfXLtqc/ErFc2KAhl3zx5Zn6g6g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw
MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B
3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY
tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/
Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2
VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT
79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6
c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT
Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l
c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee
UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE
Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G
A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF
Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO
VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3
ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs
8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR
iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze
Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ
XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/
qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB
VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB
L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG
jjxDah2nGN59PRbxYvnKkKj9
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjzCCAhWgAwIBAgIQXIuZxVqUxdJxVt7NiYDMJjAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMjAx
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
Ck5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUg
VVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBFQ0MgQ2VydGlm
aWNhdGlvbiBBdXRob3JpdHkwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQarFRaqflo
I+d61SRvU8Za2EurxtW20eZzca7dnNYMYf3boIkDuAUU7FfO7l0/4iGzzvfUinng
o4N+LZfQYcTxmdwlkWOrfzCjtHDix6EznPO/LlxTsV+zfTJ/ijTjeXmjQjBAMB0G
A1UdDgQWBBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjA2Z6EWCNzklwBBHU6+4WMB
zzuqQhFkoJ2UOQIReVx7Hfpkue4WQrO/isIJxOzksU0CMQDpKmFHjFJKS04YcPbW
RNZu9YO6bVi9JNlWSOrvxKJGgYhqOkbRqZtNyWHa0V1Xahg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFijCCA3KgAwIBAgIQdY39i658BwD6qSWn4cetFDANBgkqhkiG9w0BAQwFADBf
MQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQD
Ey1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYw
HhcNMjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEY
MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1Ymxp
YyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCTvtU2UnXYASOgHEdCSe5jtrch/cSV1UgrJnwUUxDa
ef0rty2k1Cz66jLdScK5vQ9IPXtamFSvnl0xdE8H/FAh3aTPaE8bEmNtJZlMKpnz
SDBh+oF8HqcIStw+KxwfGExxqjWMrfhu6DtK2eWUAtaJhBOqbchPM8xQljeSM9xf
iOefVNlI8JhD1mb9nxc4Q8UBUQvX4yMPFF1bFOdLvt30yNoDN9HWOaEhUTCDsG3X
ME6WW5HwcCSrv0WBZEMNvSE6Lzzpng3LILVCJ8zab5vuZDCQOc2TZYEhMbUjUDM3
IuM47fgxMMxF/mL50V0yeUKH32rMVhlATc6qu/m1dkmU8Sf4kaWD5QazYw6A3OAS
VYCmO2a0OYctyPDQ0RTp5A1NDvZdV3LFOxxHVp3i1fuBYYzMTYCQNFu31xR13NgE
SJ/AwSiItOkcyqex8Va3e0lMWeUgFaiEAin6OJRpmkkGj80feRQXEgyDet4fsZfu
+Zd4KKTIRJLpfSYFplhym3kT2BFfrsU4YjRosoYwjviQYZ4ybPUHNs2iTG7sijbt
8uaZFURww3y8nDnAtOFr94MlI1fZEoDlSfB1D++N6xybVCi0ITz8fAr/73trdf+L
HaAZBav6+CuBQug4urv7qv094PPK306Xlynt8xhW6aWWrL3DkJiy4Pmi1KZHQ3xt
zwIDAQABo0IwQDAdBgNVHQ4EFgQUVnNYZJX5khqwEioEYnmhQBWIIUkwDgYDVR0P
AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAC9c
mTz8Bl6MlC5w6tIyMY208FHVvArzZJ8HXtXBc2hkeqK5Duj5XYUtqDdFqij0lgVQ
YKlJfp/imTYpE0RHap1VIDzYm/EDMrraQKFz6oOht0SmDpkBm+S8f74TlH7Kph52
gDY9hAaLMyZlbcp+nv4fjFg4exqDsQ+8FxG75gbMY/qB8oFM2gsQa6H61SilzwZA
Fv97fRheORKkU55+MkIQpiGRqRxOF3yEvJ+M0ejf5lG5Nkc/kLnHvALcWxxPDkjB
JYOcCj+esQMzEhonrPcibCTRAUH4WAP+JWgiH5paPHxsnnVI84HxZmduTILA7rpX
DhjvLpr3Etiga+kFpaHpaPi8TD8SHkXoUsCjvxInebnMMTzD9joiFgOgyY9mpFui
TdaBJQbpdqQACj7LzTWb4OE4y2BThihCQRxEV+ioratF4yUQvNs+ZUH7G6aXD+u5
dHn5HrwdVw1Hr8Mvn4dGp+smWg9WY7ViYG4A++MnESLn/pmPNPW56MORcr3Ywx65
LvKRRFHQV80MNNVIIb/bE/FmJUNS0nAiNs2fxBx1IK1jcmMGDw4nztJqDby1ORrp
0XZ60Vzk50lJLVU3aPAaOpg+VBeHVOmmJ1CJeyAvP/+/oYtKR5j/K3tJPsMpRmAY
QqszKbrAKbkTidOIijlBO8n9pu0f9GBj39ItVQGL
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICOjCCAcGgAwIBAgIQQvLM2htpN0RfFf51KBC49DAKBggqhkjOPQQDAzBfMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN
MjEwMzIyMDAwMDAwWhcNNDYwMzIxMjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYG
A1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBT
ZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAR2+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccC
WvkEN/U0NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+
6xnOQ6OjQjBAMB0GA1UdDgQWBBTRItpMWfFLXyY4qp3W7usNw/upYTAOBgNVHQ8B
Af8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAn7qRa
qCG76UeXlImldCBteU/IvZNeWBj7LRoAasm4PdCkT0RHlAFWovgzJQxC36oCMB3q
4S6ILuH5px0CMk7yn2xVdOOurvulGu7t0vzCAxHrRVxgED1cf5kDW21USAGKcw==
-----END CERTIFICATE-----
''';

/// Minimal definite-length DER element reader. Handles short and long length
/// forms up to 4 length bytes, which covers every X.509 certificate the Web
/// PKI produces. High-tag-number (0x1F) encodings are not parsed; a lookup
/// for 0x30/0xA0 then simply fails, which is the fail-closed direction.
class _DerElement {
  const _DerElement(this.tag, this.start, this.contentStart, this.contentLength);

  final int tag;

  /// Offset of the tag byte: the beginning of the element's encoding.
  final int start;
  final int contentStart;
  final int contentLength;

  int get end => contentStart + contentLength;
}

_DerElement? _derElement(List<int> bytes, int offset) {
  if (offset < 0 || offset >= bytes.length) return null;
  final int tag = bytes[offset];
  var cursor = offset + 1;
  if (cursor >= bytes.length) return null;
  final int first = bytes[cursor];
  int length;
  if ((first & 0x80) == 0) {
    length = first;
    cursor += 1;
  } else {
    final int count = first & 0x7F;
    if (count == 0 || count > 4) return null;
    cursor += 1;
    if (cursor + count > bytes.length) return null;
    length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | bytes[cursor + i];
    }
    cursor += count;
  }
  if (length < 0 || cursor + length > bytes.length) return null;
  return _DerElement(tag, offset, cursor, length);
}

/// The DER encoding of a certificate's SubjectPublicKeyInfo, extracted from
/// the full certificate DER, or null when the DER is not shaped like an
/// X.509 certificate.
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
/// signatureValue }` and `tbsCertificate ::= SEQUENCE { version [0] DEFAULT
/// v1, serialNumber, signature, issuer, validity, subject,
/// subjectPublicKeyInfo, ... }`. This walks exactly that structure: outer
/// SEQUENCE, first element (tbs), optional version [0], then five fixed
/// elements, and the NEXT element is the SPKI. The returned bytes (tag,
/// length and content) are byte-for-byte what
/// `openssl x509 -pubkey | openssl pkey -pubin -outform DER` produces, which
/// is what the pin pipeline hashes.
List<int>? subjectPublicKeyInfoDerOfCertificate(List<int> certificateDer) {
  final _DerElement? top = _derElement(certificateDer, 0);
  if (top == null || top.tag != 0x30) return null;
  final _DerElement? tbs = _derElement(certificateDer, top.contentStart);
  if (tbs == null || tbs.tag != 0x30) return null;

  var cursor = tbs.contentStart;
  final int tbsEnd = tbs.end;
  if (cursor < tbsEnd && certificateDer[cursor] == 0xA0) {
    final _DerElement? version = _derElement(certificateDer, cursor);
    if (version == null) return null;
    cursor = version.end;
  }
  // serialNumber, signature, issuer, validity, subject.
  var skipped = 0;
  while (skipped < 5 && cursor < tbsEnd) {
    final _DerElement? element = _derElement(certificateDer, cursor);
    if (element == null) return null;
    cursor = element.end;
    skipped += 1;
  }
  if (skipped != 5 || cursor >= tbsEnd) return null;
  final _DerElement? spki = _derElement(certificateDer, cursor);
  if (spki == null || spki.tag != 0x30) return null;
  return certificateDer.sublist(spki.start, spki.end);
}

/// SHA-256 of the certificate's DER SubjectPublicKeyInfo, base64-encoded --
/// the exact value format stored in the pin map. Null when [certificateDer]
/// is not a parseable X.509 certificate.
String? spkiSha256Base64OfCertificate(List<int> certificateDer) {
  final List<int>? spki = subjectPublicKeyInfoDerOfCertificate(certificateDer);
  if (spki == null) return null;
  return base64Encode(sha256.convert(spki).bytes);
}

/// Whether pinning is enforced for a build, as a pure function of two facts
/// so the rule itself is testable.
///
/// A RELEASE build always enforces, even if the escape-hatch define was left
/// set by mistake: the release code path cannot be disabled this way. Debug
/// and profile builds honour the define.
bool controlPlanePinningEnforced({
  required bool isReleaseBuild,
  required bool disabledDefine,
}) {
  if (isReleaseBuild) return true;
  return !disabledDefine;
}

/// The escape hatch define. Compile-time, default off. See the library docs.
const bool kControlPlanePinningDisabled = bool.fromEnvironment(
  'WINS_CONTROL_PLANE_PINNING_DISABLED',
  defaultValue: false,
);

/// Decodes a single-certificate PEM (with or without trailing data) to its
/// DER encoding. Returns null for anything that is not shaped like one
/// PEM block with decodable base64.
List<int>? _pemCertificateToDer(String pem) {
  final blocks = pem.split('-----BEGIN CERTIFICATE-----');
  if (blocks.length < 2) return null;
  final body = blocks[1].split('-----END CERTIFICATE-----').first;
  final b64 = body.replaceAll(RegExp(r'\s'), '');
  if (b64.isEmpty) return null;
  try {
    final der = base64.decode(b64);
    return der.isEmpty ? null : der;
  } on FormatException {
    return null;
  }
}

/// The pre-send leaf gate in its pure, testable form, for a connection whose
/// chain, hostname and validity dates the PLATFORM HAS ALREADY VALIDATED
/// against the compiled anchors.
///
/// True only when [host] is a compiled control-plane host or an unexpired
/// signed-discovery host ([signedDiscoveryHostAuthorized]) and [leafDer]
/// parses as an X.509 certificate with a SubjectPublicKeyInfo. The leaf key
/// is deliberately not pinned (see the library docs). This must never be
/// used where the chain was not validated, for example as a
/// `badCertificateCallback`: on its own it accepts any parseable
/// certificate for a listed host.
bool controlPlaneValidatedLeafAcceptable({
  required String host,
  required List<int> leafDer,
}) {
  if (controlPlaneSpkiPinsForHost(host) == null &&
      !signedDiscoveryHostAuthorized(host)) {
    return false;
  }
  return subjectPublicKeyInfoDerOfCertificate(leafDer) != null;
}

/// PEM block for one DER certificate. The platform's
/// `setTrustedCertificatesBytes` accepts PEM or PKCS12 on every supported
/// backend, but not a bare DER blob (BoringSSL fails such a blob with
/// BAD_PKCS12_DATA), so DER anchors are re-wrapped here.
String _pemCertificateFromDer(List<int> der) {
  final body = base64Encode(der)
      .replaceAllMapped(RegExp(r'.{1,64}'), (m) => '${m.group(0)}\n');
  return '-----BEGIN CERTIFICATE-----\n$body-----END CERTIFICATE-----\n';
}

/// [controlPlaneValidatedLeafAcceptable] over a dart:io [X509Certificate].
/// The certificate's `.pem` is converted back to DER (dart:io does not hand
/// the DER out directly through this surface on every platform).
bool controlPlaneX509LeafAcceptable({
  required String host,
  required X509Certificate certificate,
}) {
  final der = _pemCertificateToDer(certificate.pem);
  if (der == null) return false;
  return controlPlaneValidatedLeafAcceptable(host: host, leafDer: der);
}

/// Explicit authorization for forwarding one non-public header across an
/// origin-changing redirect. The client still requires an HTTPS target in the
/// compiled pin map and an exact-connection leaf match before sending it.
/// Credential-bearing headers (Authorization, Cookie, Proxy-Authorization,
/// X-Wins-Activation, API/token/csrf keys) can never cross an origin change,
/// even when this policy returns true.
typedef ControlPlaneRedirectHeaderPolicy =
    bool Function(Uri sourceOrigin, Uri targetOrigin, String headerName);

/// Test seam for synthetic TLS fixtures. Production callers must leave this
/// null so [controlPlaneX509LeafAcceptable] remains the leaf verifier.
@visibleForTesting
typedef ControlPlaneConnectionLeafVerifier =
    bool Function(Uri uri, X509Certificate certificate);

/// Opens the raw TCP connection for one control-plane request. Production
/// uses [Socket.startConnect] on the URI hostname. Tests map a compiled
/// hostname to a local synthetic server; TLS, chain and hostname validation
/// and the pre-send leaf gate all stay on the production code path.
@visibleForTesting
typedef ControlPlaneTcpConnector =
    Future<ConnectionTask<Socket>> Function(String host, int port);

/// Hard ceiling on manually followed control-plane redirects. Callers may
/// request fewer hops via [http.BaseRequest.maxRedirects]; they cannot raise
/// this cap.
const int kControlPlaneMaxRedirects = 5;

/// Whether [uri] is an allowed control-plane request or redirect target.
///
/// The gate is scheme, host, port and compiled host-set membership. IP
/// literals are refused so a DNS-rebound or Location-rewritten address cannot
/// skip hostname validation. The chain and leaf checks run separately on the
/// exact TLS connection before any request byte is written.
bool controlPlaneRequestTargetAllowed(Uri uri) {
  if (uri.scheme.toLowerCase() != 'https') return false;
  if (uri.userInfo.isNotEmpty) return false;
  final String host = uri.host.trim();
  if (host.isEmpty) return false;
  if (InternetAddress.tryParse(host) != null) return false;
  if (controlPlaneSpkiPinsForHost(host) == null &&
      !signedDiscoveryRequestAuthorized(uri)) {
    return false;
  }
  final int port = uri.hasPort ? uri.port : 443;
  if (port < 1 || port > 65535) return false;
  return true;
}

/// Canonical in-memory cache key for a verified origin: lowercased
/// `scheme://host[:port]`. The port distinguishes synthetic test origins
/// from production and a scheme change from the same name; the host is the
/// unit the pin map is keyed on, so a verified `sync.winsvpn.org` at
/// another port is a different origin needing its own probe.
String controlPlaneOriginKey(Uri uri) {
  final String host = uri.host.trim().toLowerCase();
  final String scheme = uri.scheme.toLowerCase();
  final int defaultPort = scheme == 'https'
      ? 443
      : (scheme == 'http' ? 80 : -1);
  final String port = uri.hasPort && uri.port != defaultPort
      ? ':${uri.port}'
      : '';
  return '$scheme://$host$port';
}

/// In-memory observation ledger of origins whose connection leaf passed the
/// pin gate on this client.
///
/// This class is retained for API compatibility and diagnostics. It is never
/// an authorization cache: every newly-created TLS connection is checked even
/// while an origin is inside [ttl].
class PinnedOriginLedger {
  PinnedOriginLedger({
    this.ttl = kControlPlanePinVerifiedOriginTtl,
    DateTime Function()? clock,
  }) : _clock = clock ?? DateTime.now;

  /// How long a successful observation remains visible to callers.
  final Duration ttl;
  final DateTime Function() _clock;
  final Map<String, DateTime> _verifiedAt = <String, DateTime>{};

  /// Whether [uri]'s origin passed the pin gate within [ttl]. Expired
  /// entries are evicted on read, so the map stays small.
  bool isVerified(Uri uri) {
    final String key = controlPlaneOriginKey(uri);
    final DateTime? at = _verifiedAt[key];
    if (at == null) return false;
    if (_clock().difference(at) > ttl) {
      _verifiedAt.remove(key);
      return false;
    }
    return true;
  }

  /// Records that one connection to [uri]'s origin passed the pin gate.
  void markVerified(Uri uri) {
    _verifiedAt[controlPlaneOriginKey(uri)] = _clock();
  }

  /// Drops the entry for [uri]'s origin after a failed connection check.
  void invalidate(Uri uri) {
    _verifiedAt.remove(controlPlaneOriginKey(uri));
  }
}

/// Compatibility TTL for the observation ledger. It never permits sending on
/// a new connection without checking that connection's leaf.
const Duration kControlPlanePinVerifiedOriginTtl = Duration(minutes: 10);

/// Legacy probe path retained for source compatibility. Exact-connection
/// verification no longer sends a separate HTTP probe.
@visibleForTesting
const String kControlPlanePinProbePath = '/healthz';

/// Legacy probe timeout retained for source compatibility.
const Duration kControlPlanePinProbeTimeout = Duration(seconds: 10);

/// End-to-end ceiling for creating the socket, completing TLS, and checking
/// the exact connection leaf. Timeout cancels the underlying connection task
/// and destroys any socket obtained before the timer fires.
const Duration kControlPlanePinConnectionTimeout = Duration(seconds: 10);

/// Largest control-plane response body the pinned client delivers. Request
/// timers bound time, not bytes, and the caller buffers the whole body, so a
/// longer stream fails here, before it is buffered, and the read is cancelled.
const int kMaxControlPlaneResponseBytes = 2 * 1024 * 1024;

/// The response body passed [kMaxControlPlaneResponseBytes]. A transport
/// failure like any other: the caller moves on to the next front.
class ControlPlaneResponseTooLargeException extends http.ClientException {
  ControlPlaneResponseTooLargeException(Uri uri)
      : super(
          'Control-plane response exceeds $kMaxControlPlaneResponseBytes bytes',
          uri,
        );
}

/// [http.Client] whose direct HTTPS connection factory verifies the exact
/// [SecureSocket.peerCertificate] before `openUrl` yields a writable request.
/// Redirects are disabled in dart:io and followed here one verified hop at a
/// time with strict cross-origin header filtering.
class _PinnedControlPlaneClient extends http.BaseClient {
  _PinnedControlPlaneClient(
    this._context, {
    required PinnedOriginLedger ledger,
    Future<ConnectionTask<Socket>> Function(
      Uri url,
      String? proxyHost,
      int? proxyPort,
    )?
    connectionFactory,
    ControlPlaneRedirectHeaderPolicy? redirectHeaderPolicy,
    ControlPlaneConnectionLeafVerifier? connectionLeafVerifier,
    ControlPlaneTcpConnector? tcpConnector,
    Duration connectionVerificationTimeout = kControlPlanePinConnectionTimeout,
  }) : _observationLedger = ledger,
       _providedConnectionFactory = connectionFactory,
       _redirectHeaderPolicy = redirectHeaderPolicy,
       _tcpConnector = tcpConnector,
       _connectionVerificationTimeout = connectionVerificationTimeout,
       _connectionLeafVerifier =
           connectionLeafVerifier ??
           ((Uri uri, X509Certificate certificate) =>
               controlPlaneX509LeafAcceptable(
                 host: uri.host,
                 certificate: certificate,
               )) {
    _inner = (HttpClient(context: _context))
      // A proxy CONNECT path lets dart:io perform TLS internally after the
      // custom socket factory returns, which would hide the peer leaf until
      // after request bytes. Direct TLS is therefore a security invariant.
      ..findProxy = ((Uri _) => 'DIRECT')
      ..connectionFactory = _openPinnedConnection;
  }

  final SecurityContext _context;
  final PinnedOriginLedger _observationLedger;
  final Future<ConnectionTask<Socket>> Function(
    Uri url,
    String? proxyHost,
    int? proxyPort,
  )?
  _providedConnectionFactory;
  final ControlPlaneRedirectHeaderPolicy? _redirectHeaderPolicy;
  final ControlPlaneConnectionLeafVerifier _connectionLeafVerifier;
  final ControlPlaneTcpConnector? _tcpConnector;
  final Duration _connectionVerificationTimeout;

  HttpClient? _inner;

  Future<ConnectionTask<Socket>> _openPinnedConnection(
    Uri uri,
    String? proxyHost,
    int? proxyPort,
  ) {
    if (!controlPlaneRequestTargetAllowed(uri)) {
      return Future<ConnectionTask<Socket>>.error(
        HandshakeException(
          'control-plane connection refused: HTTPS, a valid host and port, '
          'and a compiled pin are required for ${uri.host}',
        ),
      );
    }
    if (proxyHost != null || proxyPort != null) {
      return Future<ConnectionTask<Socket>>.error(
        const HandshakeException(
          'control-plane proxy connections are disabled because their target '
          'TLS leaf cannot be checked before request bytes',
        ),
      );
    }
    if (_connectionVerificationTimeout <= Duration.zero) {
      return Future<ConnectionTask<Socket>>.error(
        ArgumentError.value(
          _connectionVerificationTimeout,
          'connectionVerificationTimeout',
          'must be positive',
        ),
      );
    }

    final Completer<Socket> checkedSocket = Completer<Socket>();
    ConnectionTask<Socket>? task;
    var cancelled = false;
    Socket? connectedSocket;
    late final Timer timeoutTimer;

    void fail(Object error, [StackTrace? stackTrace]) {
      connectedSocket?.destroy();
      task?.cancel();
      _observationLedger.invalidate(uri);
      if (!checkedSocket.isCompleted) {
        if (stackTrace == null) {
          checkedSocket.completeError(error);
        } else {
          checkedSocket.completeError(error, stackTrace);
        }
      }
    }

    timeoutTimer = Timer(_connectionVerificationTimeout, () {
      cancelled = true;
      fail(
        SocketException(
          'control-plane TLS connection and leaf verification timed out '
          'after $_connectionVerificationTimeout',
        ),
      );
    });

    unawaited(
      Future<void>(() async {
        try {
          if (_providedConnectionFactory != null) {
            task = await _providedConnectionFactory(uri, null, null);
          } else {
            // Connect by URI hostname, never by a resolved IP, and validate
            // the chain for that hostname, so DNS rebinding cannot change
            // which name the platform checks.
            final ControlPlaneTcpConnector connect =
                _tcpConnector ?? Socket.startConnect;
            final ConnectionTask<Socket> tcpTask =
                await connect(uri.host, uri.port);
            Socket? rawSocket;
            task = ConnectionTask.fromSocket<Socket>(
              tcpTask.socket.then<Socket>((Socket raw) {
                rawSocket = raw;
                return SecureSocket.secure(
                  raw,
                  host: uri.host,
                  context: _context,
                  supportedProtocols: const <String>['http/1.1'],
                );
              }),
              () {
                tcpTask.cancel();
                rawSocket?.destroy();
              },
            );
          }
          if (cancelled) {
            task?.cancel();
            return;
          }
          final Socket socket = await task!.socket;
          connectedSocket = socket;
          if (cancelled) {
            socket.destroy();
            return;
          }
          if (socket is! SecureSocket) {
            throw const HandshakeException(
              'control-plane connection factory returned a non-TLS socket',
            );
          }
          final X509Certificate? leaf = socket.peerCertificate;
          if (leaf == null || !_connectionLeafVerifier(uri, leaf)) {
            throw const HandshakeException(
              'control-plane exact connection rejected the leaf certificate; '
              'no request bytes were sent',
            );
          }
          _observationLedger.markVerified(uri);
          timeoutTimer.cancel();
          if (!checkedSocket.isCompleted) checkedSocket.complete(socket);
        } catch (error, stackTrace) {
          timeoutTimer.cancel();
          fail(error, stackTrace);
        }
      }),
    );

    final ConnectionTask<Socket> outerTask = ConnectionTask.fromSocket<Socket>(
      checkedSocket.future,
      () {
        cancelled = true;
        timeoutTimer.cancel();
        connectedSocket?.destroy();
        task?.cancel();
        _observationLedger.invalidate(uri);
        if (!checkedSocket.isCompleted) {
          checkedSocket.completeError(
            const SocketException(
              'control-plane connection cancelled before verification',
            ),
          );
        }
      },
    );
    return Future<ConnectionTask<Socket>>.value(outerTask);
  }

  static const Set<String> _publicCrossOriginHeaders = <String>{
    'accept',
    'accept-encoding',
    'accept-language',
    'cache-control',
    'pragma',
    'user-agent',
  };

  static const Set<String> _neverRedirectHeaders = <String>{
    'connection',
    'content-length',
    'host',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  };

  static const Set<String> _neverCrossOriginCredentialHeaders = <String>{
    // Every credential or session bearer the control plane could ever carry.
    // None of these may follow an origin change, even when the redirect
    // header policy returns true, so a policy bug cannot exfiltrate a session
    // to a sibling control-plane host. Same-origin redirects still forward
    // them; only the cross-origin case drops them.
    'authorization',
    'cookie',
    'proxy-authorization',
    'x-wins-activation',
    'x-api-key',
    'x-auth-token',
    'x-csrf-token',
    'x-device-auth-token',
    'x-session-id',
  };

  static int _redirectBudget(int requested) {
    if (requested <= 0) return 0;
    if (requested < kControlPlaneMaxRedirects) return requested;
    return kControlPlaneMaxRedirects;
  }

  Map<String, String> _headersForInitialRequest(Map<String, String> original) {
    final Map<String, String> headers = <String, String>{};
    original.forEach((String name, String value) {
      final String lower = name.toLowerCase();
      if (_neverRedirectHeaders.contains(lower) || lower.startsWith('proxy-')) {
        return;
      }
      headers[name] = value;
    });
    return headers;
  }

  Uri _originOf(Uri uri) => Uri(
    scheme: uri.scheme.toLowerCase(),
    host: uri.host.toLowerCase(),
    port: uri.port,
  );

  Map<String, String> _headersForRedirect(
    Map<String, String> current,
    Uri source,
    Uri target, {
    required bool methodChanged,
  }) {
    final bool sameOrigin =
        controlPlaneOriginKey(source) == controlPlaneOriginKey(target);
    final bool bothPinnedHttps =
        controlPlaneRequestTargetAllowed(source) &&
        controlPlaneRequestTargetAllowed(target);
    final bool sameOriginHttps = sameOrigin && bothPinnedHttps;
    final headers = <String, String>{};
    current.forEach((String name, String value) {
      final String lower = name.toLowerCase();
      if (_neverRedirectHeaders.contains(lower) ||
          lower.startsWith('proxy-') ||
          (methodChanged &&
              const <String>{
                'content-encoding',
                'content-language',
                'content-location',
                'content-range',
                'content-type',
              }.contains(lower))) {
        return;
      }
      if (_neverCrossOriginCredentialHeaders.contains(lower)) {
        if (sameOriginHttps) {
          headers[name] = value;
        }
        return;
      }
      if (sameOriginHttps || _publicCrossOriginHeaders.contains(lower)) {
        headers[name] = value;
        return;
      }
      if (bothPinnedHttps &&
          _redirectHeaderPolicy?.call(
                _originOf(source),
                _originOf(target),
                lower,
              ) ==
              true) {
        headers[name] = value;
      }
    });
    return headers;
  }

  Future<void> _destroyResponse(HttpClientResponse response) async {
    try {
      final Socket socket = await response.detachSocket();
      socket.destroy();
    } catch (_) {
      await response.drain<void>().catchError((_) {});
    }
  }

  http.StreamedResponse _streamResponse(
    http.BaseRequest request,
    HttpClientResponse response,
    bool Function() isAborted,
    Future<void>? abortTrigger,
  ) {
    StreamSubscription<List<int>>? ioResponseSubscription;
    late final StreamController<List<int>> responseController;
    responseController = StreamController<List<int>>(
      onListen: () {
        if (isAborted()) {
          responseController
            ..addError(http.RequestAbortedException(request.url))
            ..close();
          return;
        }
        if (abortTrigger != null) {
          abortTrigger.whenComplete(() {
            if (!responseController.isClosed) {
              responseController
                ..addError(http.RequestAbortedException(request.url))
                ..close();
            }
            ioResponseSubscription?.cancel();
          });
        }
        var received = 0;
        ioResponseSubscription = response.listen(
          (List<int> chunk) {
            if (responseController.isClosed) return;
            received += chunk.length;
            if (received > kMaxControlPlaneResponseBytes) {
              final reading = ioResponseSubscription;
              ioResponseSubscription = null;
              unawaited(reading?.cancel());
              responseController
                ..addError(ControlPlaneResponseTooLargeException(request.url))
                ..close();
              return;
            }
            responseController.add(chunk);
          },
          onDone: () {
            ioResponseSubscription = null;
            unawaited(responseController.close());
          },
          onError: (Object error, StackTrace stackTrace) {
            if (error is HttpException) {
              responseController.addError(
                http.ClientException(error.message, error.uri),
                stackTrace,
              );
            } else {
              responseController.addError(error, stackTrace);
            }
          },
        );
      },
      onPause: () => ioResponseSubscription?.pause(),
      onResume: () => ioResponseSubscription?.resume(),
      onCancel: () => ioResponseSubscription?.cancel(),
      sync: true,
    );

    final headers = <String, String>{};
    response.headers.forEach((String key, List<String> values) {
      headers[key] = values.map((String value) => value.trimRight()).join(',');
    });
    return http.StreamedResponse(
      responseController.stream,
      response.statusCode,
      contentLength: response.contentLength == -1
          ? null
          : response.contentLength,
      request: request,
      headers: headers,
      isRedirect: response.isRedirect,
      persistentConnection: response.persistentConnection,
      reasonPhrase: response.reasonPhrase,
    );
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final HttpClient? inner = _inner;
    if (inner == null) {
      throw http.ClientException(
          'HTTP request failed. Client is already closed.', request.url);
    }

    var isAborted = false;
    Future<void>? abortTrigger;
    if (request case http.Abortable(abortTrigger: final requestAbortTrigger?)) {
      abortTrigger = requestAbortTrigger;
      unawaited(
        requestAbortTrigger.whenComplete(() {
          isAborted = true;
        }),
      );
    }
    final stream = request.finalize();
    Uri currentUri = request.url;
    String currentMethod = request.method;
    bool currentRequestHasBody =
        request.contentLength == null || (request.contentLength ?? 0) > 0;
    Map<String, String> currentHeaders = _headersForInitialRequest(
      request.headers,
    );
    final Set<String> visited = <String>{
      '${currentMethod.toUpperCase()} '
          '${currentUri.replace(fragment: '')}',
    };
    int redirects = 0;
    bool firstHop = true;
    HttpClientRequest? activeRequest;

    if (abortTrigger != null) {
      unawaited(
        abortTrigger.whenComplete(() {
          activeRequest?.abort(http.RequestAbortedException(request.url));
        }),
      );
    }

    try {
      while (true) {
        if (isAborted) {
          throw http.RequestAbortedException(request.url);
        }
        if (!controlPlaneRequestTargetAllowed(currentUri)) {
          throw HandshakeException(
            'control-plane request refused: HTTPS, a valid host and port, '
            'and a compiled pin are required for ${currentUri.host}',
          );
        }
        final HttpClientRequest ioRequest = await inner.openUrl(
          currentMethod,
          currentUri,
        );
        activeRequest = ioRequest;
        if (!controlPlaneRequestTargetAllowed(currentUri)) {
          const error = HandshakeException(
            'control-plane discovery authorization expired before request',
          );
          ioRequest.abort(error);
          throw error;
        }
        if (isAborted) {
          ioRequest.abort(http.RequestAbortedException(request.url));
          throw http.RequestAbortedException(request.url);
        }
        ioRequest
          ..followRedirects = false
          ..maxRedirects = 0
          ..contentLength = firstHop ? (request.contentLength ?? -1) : 0
          ..persistentConnection = request.persistentConnection;
        currentHeaders.forEach(ioRequest.headers.set);

        final HttpClientResponse response;
        if (firstHop) {
          response = await stream.pipe(ioRequest) as HttpClientResponse;
          firstHop = false;
        } else {
          response = await ioRequest.close();
        }
        activeRequest = null;

        final bool hasRedirectStatus = const <int>{
          HttpStatus.movedPermanently,
          HttpStatus.found,
          HttpStatus.seeOther,
          HttpStatus.temporaryRedirect,
          HttpStatus.permanentRedirect,
        }.contains(response.statusCode);
        if (!request.followRedirects || !hasRedirectStatus) {
          return _streamResponse(
            request,
            response,
            () => isAborted,
            abortTrigger,
          );
        }
        if (redirects >= _redirectBudget(request.maxRedirects)) {
          await _destroyResponse(response);
          throw const RedirectException(
            'Redirect limit exceeded',
            <RedirectInfo>[],
          );
        }
        final List<String>? locations =
            response.headers[HttpHeaders.locationHeader];
        if (locations == null ||
            locations.length != 1 ||
            locations.single.trim().isEmpty) {
          await _destroyResponse(response);
          throw const RedirectException(
            'Server response must have exactly one Location header for redirect',
            <RedirectInfo>[],
          );
        }
        final String location = locations.single.trim();
        if (location.contains('\r') ||
            location.contains('\n') ||
            location.contains('\u0000')) {
          await _destroyResponse(response);
          throw const RedirectException(
            'Malformed Location header',
            <RedirectInfo>[],
          );
        }
        Uri? parsedNext;
        try {
          parsedNext = currentUri.resolve(location).replace(fragment: '');
        } on FormatException {
          parsedNext = null;
        }
        if (parsedNext == null || parsedNext.host.trim().isEmpty) {
          await _destroyResponse(response);
          throw const RedirectException(
            'Malformed Location header',
            <RedirectInfo>[],
          );
        }
        final Uri nextUri = parsedNext;
        if (nextUri.scheme.toLowerCase() != 'https') {
          await _destroyResponse(response);
          throw HandshakeException(
            'control-plane redirect refused before forwarding: HTTP '
            'downgrade or non-HTTPS target (${nextUri.scheme})',
          );
        }
        if (!controlPlaneRequestTargetAllowed(nextUri)) {
          await _destroyResponse(response);
          throw HandshakeException(
            'control-plane redirect refused before forwarding: target must '
            'be HTTPS with a valid host and port compiled in the pin map '
            '(${nextUri.host})',
          );
        }
        final String upperMethod = currentMethod.toUpperCase();
        String? nextMethod;
        String? redirectRefusal;
        switch (response.statusCode) {
          case HttpStatus.movedPermanently:
          case HttpStatus.found:
            if ((upperMethod == 'GET' || upperMethod == 'HEAD') &&
                !currentRequestHasBody) {
              nextMethod = upperMethod;
            } else if (upperMethod == 'POST') {
              // Match established user-agent semantics without pretending to
              // replay the consumed POST body.
              nextMethod = 'GET';
            } else {
              redirectRefusal =
                  '301/302 redirect for $upperMethod requires unsupported '
                  'request-body replay';
            }
            break;
          case HttpStatus.seeOther:
            // RFC 9110: 303 instructs the client to retrieve the target as
            // GET, except that HEAD remains HEAD.
            nextMethod = upperMethod == 'HEAD' ? 'HEAD' : 'GET';
            break;
          case HttpStatus.temporaryRedirect:
          case HttpStatus.permanentRedirect:
            if ((upperMethod == 'GET' || upperMethod == 'HEAD') &&
                !currentRequestHasBody) {
              nextMethod = upperMethod;
            } else {
              redirectRefusal =
                  '307/308 body-preserving redirect refused because the '
                  'request body is not replayed';
            }
            break;
        }
        if (redirectRefusal != null || nextMethod == null) {
          await _destroyResponse(response);
          throw RedirectException(
            redirectRefusal ?? 'Unsupported redirect semantics',
            const <RedirectInfo>[],
          );
        }
        final String visitKey = '${nextMethod.toUpperCase()} $nextUri';
        if (!visited.add(visitKey)) {
          await _destroyResponse(response);
          throw const RedirectException(
            'Redirect loop detected',
            <RedirectInfo>[],
          );
        }
        currentHeaders = _headersForRedirect(
          currentHeaders,
          currentUri,
          nextUri,
          methodChanged:
              nextMethod.toUpperCase() != currentMethod.toUpperCase(),
        );
        await _destroyResponse(response);
        currentUri = nextUri;
        currentMethod = nextMethod;
        currentRequestHasBody = false;
        redirects++;
      }
    } on HttpException catch (error) {
      throw http.ClientException(error.message, error.uri);
    } on HandshakeException {
      _observationLedger.invalidate(currentUri);
      rethrow;
    }
  }

  @override
  void close() {
    final HttpClient? inner = _inner;
    if (inner != null) {
      inner.close(force: true);
      _inner = null;
    }
  }
}

SecurityContext _controlPlaneAnchorContext() {
  final blocks = RegExp(
    r'-----BEGIN CERTIFICATE-----\s*'
    r'[A-Za-z0-9+/=\s]+?'
    r'\s*-----END CERTIFICATE-----',
  ).allMatches(kControlPlanePinnedCertificatePem).toList(growable: false);

  if (blocks.length != 12 ||
      kControlPlaneAnchorSpkiPins.length != 12 ||
      kControlPlaneAnchorSpkiPins.toSet().length != 12) {
    throw StateError('Twelve distinct control-plane anchors are required');
  }

  final context = SecurityContext(withTrustedRoots: false);
  for (var index = 0; index < blocks.length; index++) {
    final pem = blocks[index].group(0)!;
    final der = _pemCertificateToDer(pem);
    if (der == null ||
        spkiSha256Base64OfCertificate(der) !=
            kControlPlaneAnchorSpkiPins[index]) {
      throw StateError('Control-plane anchor certificate and SPKI disagree');
    }
    // PEM on every platform, iOS included: dart:io trusts certificates through
    // BoringSSL everywhere, which reads PEM or PKCS12 and fails a bare DER blob
    // with BAD_PKCS12_DATA ("Failure trusting builtin roots"). The iOS note in
    // the SecurityContext docs that asks for DER is stale.
    context.setTrustedCertificatesBytes(utf8.encode(pem));
  }
  return context;
}

/// The control-plane HTTP client with pinning enforced.
///
/// Every gateway/nodes/announcement request goes through this client. The
/// `SecurityContext(withTrustedRoots: false)` carries only the pinned
/// CA roots ([kControlPlanePinnedCertificatePem]) as trust anchors, so the
/// platform validates every handshake against exactly those anchors (chain,
/// hostname, dates). On top of that, the client enforces the pre-send gate
/// documented in the library header on the exact TLS socket before dart:io
/// can expose a writable HTTP request.
///
/// [extraTrustAnchorsDer] appends DER-encoded certificates to the anchor
/// set in debug and profile builds only. A release build refuses to construct
/// the client when it, [connectionFactory], [connectionLeafVerifier] or
/// [tcpConnector] is supplied, because an added anchor confers full trust for
/// every compiled host and the other seams can skip the exact-connection
/// gate. Production call sites never pass them; they exist so tests can stand
/// up synthetic CAs.
///
/// [pinProbeLedger] replaces the compatibility observation ledger. It never
/// authorizes sending and cannot bypass exact-connection verification.
///
/// [connectionFactory] replaces the platform connect path for tests that
/// point pinned-host URLs at a local synthetic TLS server; production call
/// sites never pass it.
///
/// [redirectHeaderPolicy] is the only way a non-public, non-credential header
/// can cross exact origins. Credential headers (Authorization, Cookie,
/// Proxy-Authorization, X-Wins-Activation, API/token/csrf keys) never follow
/// an origin change. HTTPS, compiled target pins, a valid TCP port and
/// exact-connection verification are still mandatory.
/// [connectionLeafVerifier] is a synthetic-certificate test seam; production
/// call sites must leave it null.
/// [tcpConnector] replaces only the TCP connect (tests map a compiled
/// hostname to a local server); production call sites must leave it null.
/// [connectionVerificationTimeout] bounds connection creation, TLS and leaf
/// verification as one operation and defaults to 10 seconds.
///
/// Under the development escape hatch (debug/profile builds compiled with
/// `WINS_CONTROL_PLANE_PINNING_DISABLED=true`) this returns a plain
/// system-trust client instead, for local work against a trusted MITM proxy.
http.Client createPinnedControlPlaneClient({
  List<List<int>> extraTrustAnchorsDer = const [],
  PinnedOriginLedger? pinProbeLedger,
  Future<ConnectionTask<Socket>> Function(
    Uri url,
    String? proxyHost,
    int? proxyPort,
  )?
  connectionFactory,
  ControlPlaneRedirectHeaderPolicy? redirectHeaderPolicy,
  @visibleForTesting ControlPlaneConnectionLeafVerifier? connectionLeafVerifier,
  @visibleForTesting ControlPlaneTcpConnector? tcpConnector,
  Duration connectionVerificationTimeout = kControlPlanePinConnectionTimeout,
}) {
  assert(
    !(kReleaseMode && kControlPlanePinningDisabled),
    'WINS_CONTROL_PLANE_PINNING_DISABLED is a development-only escape hatch '
    'and must never be compiled into a release build',
  );
  final bool enforced = controlPlanePinningEnforced(
    isReleaseBuild: kReleaseMode,
    disabledDefine: kControlPlanePinningDisabled,
  );
  if (!enforced) {
    return IOClient(HttpClient());
  }
  // Every test seam below can widen trust or skip the exact-connection gate
  // (an added anchor confers full trust for every compiled host now that the
  // anchor set is the pin), so a release build refuses to construct with any
  // of them rather than silently dropping it.
  if (kReleaseMode &&
      (extraTrustAnchorsDer.isNotEmpty ||
          connectionFactory != null ||
          connectionLeafVerifier != null ||
          tcpConnector != null)) {
    throw StateError('control-plane test seams are forbidden in release');
  }
  final SecurityContext context = _controlPlaneAnchorContext();
  // Defense in depth behind the release refusal above.
  if (!kReleaseMode) {
    for (final der in extraTrustAnchorsDer) {
      if (der.isNotEmpty) {
        context.setTrustedCertificatesBytes(
          utf8.encode(_pemCertificateFromDer(der)),
        );
      }
    }
  }
  return _PinnedControlPlaneClient(
    context,
    ledger: pinProbeLedger ?? PinnedOriginLedger(),
    connectionFactory: connectionFactory,
    redirectHeaderPolicy: redirectHeaderPolicy,
    connectionLeafVerifier: connectionLeafVerifier,
    tcpConnector: tcpConnector,
    connectionVerificationTimeout: connectionVerificationTimeout,
  );
}
