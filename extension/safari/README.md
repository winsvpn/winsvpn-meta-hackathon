# Standalone Safari development package

`apple/SafariProxy/SafariProxy.xcodeproj` builds a standalone macOS app with a
Safari Web Extension and a system extension containing transparent and DNS
proxy providers. It does not depend on the Flutter VPN app. The iOS target
contains the Safari Web Extension only and does not route traffic.

The macOS implementation translates intercepted TCP/UDP flows into IP packets
with the repository-pinned gVisor stack. One Go archive contains both that
bridge and the unchanged v3 packet engine. Swift uses the same
`WinnTunnelCreateWinn3`, `WinnTunnelWriteInbound`, `WinnTunnelReadOutbound`,
status and close ABI as the existing Apple packet-tunnel wrapper. There is no
application stream mode in that ABI. Carrier HTTP streams are outer transports,
not an application proxy API.

The transparent provider owns the single v3 session. A separate DNS provider
sends UDP and length-framed TCP DNS to an authenticated loopback broker, which
uses that session's stack and signed inner resolver. It never uses an external
DNS socket. DNS affects system lookups while enabled; the app discloses this
scope and replacement of another active DNS proxy. Safari capture starts only
after a DNS query has returned through the engine and the DNS provider renews
its readiness lease. Unhealthy delivered Safari flows are closed. System
behavior after provider crashes or OS removal is not proven by these tests.

Connect displays the exact bundled legal/privacy text and obtains free access
from the existing `/free/verify` contract. Independent locally generated client
and v3 keys stay in the session Keychain group. The client verifies the shipped
TLS roots, hostname, Ed25519 descriptor, selected node, client-key binding,
expiry, carrier plan and protected resolver before starting the engine. The
browser extension can read the separate control credential, not the session
keys. Browser messages contain only authenticated readiness, never engine
configuration. The current helper performs one bounded hub request; it has no
background renewal or gateway race. Expired sessions require a new Connect.

## Offline build

The installed Go executable must match `winn_protocol_experimental/go.mod`.
Supply its path and an existing module cache; the builder verifies the cached
source, module ZIP and metadata against pinned checksums and downloads nothing:

```sh
python3 -B apple/SafariProxy/Tools/build_engine.py \
  --go "$SAFARI_GO_EXECUTABLE" --module-cache "$SAFARI_GO_MODULE_CACHE" \
  --output apple/SafariProxy/Artifacts/Engine
python3 -B apple/SafariProxy/Tools/generate_project.py
python3 -B extension/build.py safari
```

`SAFARI_GO_EXECUTABLE` and `SAFARI_GO_MODULE_CACHE` are operator-supplied local
paths, not credentials. The engine helper records exact inputs, module overlay,
commands and hashes. It changes neither the original engine nor its manifests.
Both arm64 macOS and arm64 iOS engine archives are built; only macOS currently
links the archive into a provider.

`extension/build.py safari` runs every web package gate. Its native-host
identity gate does not apply to Safari, whose native messaging reaches its own
containing app. The shared Safari UI refreshes native status while keeping
browser routing controls disabled, and it never enables the external native
host.

The build requires a current locally compiled native contract host and the
pinned esbuild archive in `WINS_EXTENSION_ESBUILD_CACHE`;
`WINS_EXTENSION_ESBUILD_FETCH=0` prevents esbuild downloads. Copy the built
`extension/dist/safari` to a read-only location and set `SAFARI_WEB_PACKAGE`
below to its absolute path. Both builds must read that same immutable package:

```sh
xcodebuild -project apple/SafariProxy/SafariProxy.xcodeproj \
  -scheme SafariProxyMac -configuration Debug \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath extension/safari/.turn2/derived-macos \
  -disableAutomaticPackageResolution -skipPackageUpdates \
  CODE_SIGNING_ALLOWED=NO ARCHS=arm64 ONLY_ACTIVE_ARCH=YES \
  SAFARI_WEB_PACKAGE="$SAFARI_WEB_PACKAGE" build
xcodebuild -project apple/SafariProxy/SafariProxy.xcodeproj \
  -scheme SafariProxyiOS -configuration Debug \
  -destination 'generic/platform=iOS' \
  -derivedDataPath extension/safari/.turn2/derived-ios \
  -disableAutomaticPackageResolution -skipPackageUpdates \
  CODE_SIGNING_ALLOWED=NO ARCHS=arm64 \
  SAFARI_WEB_PACKAGE="$SAFARI_WEB_PACKAGE" build
python3 -B -m pytest -q -p no:cacheprovider \
  extension/tools/test_safari_forwarding.py \
  extension/tools/test_safari_target.py extension/tools/test_safari_standalone.py \
  extension/tools/test_safari_candidate.py apple/SafariProxy/Tools/test_build_engine.py
```

`Tools/generate_project.py` owns the project, configurations and bundled legal
resource. `Tools/generate_session_trust.py` owns the public TLS-root source.
`SAFARI_PROXY_BASE_ID` is a development identity; signing must supply approved
identifiers and `DEVELOPMENT_TEAM`. No team identifier or private key is bundled.

## Platform and live acceptance boundary

The installed SDK makes `NETransparentProxyProvider` unavailable on iOS. A
standalone v3 implementation there needs a lightweight containing app embedding
`NEPacketTunnelProvider` and a user-approved VPN configuration. The full Flutter
app is unnecessary, but the current iOS target is not that packet tunnel. A
system HTTP/2 or HTTP/3 relay using `NERelayManager` is a different protocol and
scope, not a way to insert this v3 packet engine into a Safari Web Extension.

Unsigned builds do not prove Keychain/app-group access, entitlement issuance,
system-extension activation, Safari/WebKit attribution, hub interoperability,
DNS leak prevention or routing on a device. The signed acceptance run must
exercise normal/private Safari, IPv4/IPv6, HTTP/HTTPS/QUIC, UDP/TCP DNS, outages,
sleep/wake, expiry, reconnect, repeated controls and provider termination with
packet capture and the full VPN app absent. Exact Safari signing identifiers
must be observed before claiming every Safari flow is covered. No automatic
renewal, IPv6 inner assignment or Intel engine archive is supplied here.

See `../../../REPORT_safari2.md` in the parent EXT directory for artifact hashes,
executed commands, the exact shared patch, signing requirements and live checks.
Debug ZIPs contain local debug paths. They are not signed, provisioned,
notarized, installed or ready for distribution.
