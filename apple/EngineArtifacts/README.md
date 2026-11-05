# Apple Engine Artifacts

Place signed, App-Store-reviewable Apple packet-engine artifacts here only on local build machines.
Do not commit the binaries.

Expected source layouts:

- `apple/EngineArtifacts/ios/iphoneos/`
- `apple/EngineArtifacts/ios/iphonesimulator/`
- `apple/EngineArtifacts/macos/`

Required components:

- `amneziawg_packet_engine`
- `xray_vless_ws_transport`
- `winn_packet_engine` - required for release candidates and any
  `WINS_REQUIRE_APPLE_ENGINE=1` gate. Unsigned dry-run builds leave this
  optional so a machine without staged Winn artifacts can still compile.

Optional components on unsigned dry-run only (`WINS_REQUIRE_APPLE_ENGINE=0`
and `WINS_APPLE_WINN3_RELEASE=0`):

- `winn_packet_engine` - when the artifact *is* present it is validated
  exactly as strictly as a required one.

Accepted artifact names include `WinsAmneziaWGPacketEngine.framework`,
`libWinsAmneziaWGPacketEngine.dylib`, `WinsXrayVlessWsTransport.framework`,
`libWinsXrayVlessWsTransport.dylib`, `WinsWinnPacketEngine.framework`, and
`libWinsWinnPacketEngine.dylib`.

The containing app Xcode targets run `tools/stage_apple_engine_artifacts.sh`
after embedding PacketTunnel. The script normalizes both source components into
signed framework bundles under the top-level app `Frameworks` directory; iOS
app extensions never contain standalone dynamic libraries or nested frameworks.
By default it removes stale copied engine artifacts and skips missing components
so unsigned simulator/macOS smoke builds still work. Set
`WINS_REQUIRE_APPLE_ENGINE=1` (or `WINS_APPLE_WINN3_RELEASE=1`) for production
gates to fail when any required component, including Winn, is missing.

Use `tools/build_apple_wg_go_bridge.sh` to build the pinned upstream
AmneziaWG Apple Go bridge archives for `macosx`, `iphoneos`, and
`iphonesimulator`. That helper validates the AWG/Xray symbols, Mach-O platform
metadata, and the iPhone simulator Go/cgo helper symbols needed for arm64
simulator linking. By default it builds macOS and iPhoneSimulator as universal
`arm64 x86_64`, and iPhoneOS as `arm64`. Its output is a static `libwg-go.a`
bridge archive.

The repository latest-tag policy parses numeric version components and selects
the maximum tuple. Under that policy, `v3.1.20260814` is newer than `v3.1.4`.
The official refs reviewed on 2026-08-26 are:

- Repository: `https://github.com/amnezia-vpn/amneziawg-apple.git`
- Tag: `v3.1.20260814`
- Commit: `fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d`
- Git tree: `24183de0cc22b957ff9e34ac3494a80f515ac565`
- Lower policy tag retained as comparison evidence: `v3.1.4`, commit
  `811f5c8213e6b257e9520fff713ec4d22086e9ac`.
- Apple companion Go source: `amneziawg-go` `v3.1.20260828`, commit
  `b5928efb6ca19f0153958460c3d141f04abc5c2e`.
- Cross-platform tools source, not linked into the Apple bridge:
  `amneziawg-tools` `v3.1.20260812`, commit
  `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`.
- Reviewed Go toolchain: `1.27.1`; Darwin arm64 archive SHA-256
  `ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12`
  and Darwin amd64 archive SHA-256
  `8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4`

Status: pinned 2026-10-15 (previously unpinned, and before that labelled owner-blocked: not an upstream-equivalent stable match). The prior bridge producer mixed this policy-selected
Apple tag with `go.mod`, `go.sum`, `amnezia-libxray v1.0.3`, and
`amnezia-xray-core v1.260728.0` closure values introduced by `v3.1.4`. Those
values are not valid evidence for `v3.1.20260814`. The scoped producer now
declares the owner-directed 2026-10-06 pair, `amnezia-libxray v1.0.3`
(commit `e8cc06d7427251fa549093e7cc32c28b0f5fbafa`) and
`amnezia-xray-core v1.260924.0` (commit `77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3`), with the commits taken from the
GitHub tags API and the Go module sums from sum.golang.org. That pair is newer
than the source-level pair the Apple tag itself pins (`amnezia-libxray v1.0.2`
and `amnezia-xray-core v1.260724.0`), so the builder still needs a go.mod
override step before it can run.

Eight SHA-256 pins in `tools/build_apple_wg_go_bridge.sh` need network access
to measure. They were measured on 2026-10-15 from the official tag and
proxy.golang.org, each module ZIP's h1: hash checked against sum.golang.org:

- `AMNEZIAWG_APPLE_GO_MOD_SHA256` and `AMNEZIAWG_APPLE_GO_SUM_SHA256`:
  `v3.1.20260814` `WireGuardKitGo/go.mod` and `go.sum`.
- `AMNEZIAWG_GO_MODULE_ZIP_SHA256`: `amneziawg-go v3.1.20260828` module ZIP.
- `AMNEZIA_LIBXRAY_ZIP_SHA256` and `AMNEZIA_XRAY_ZIP_SHA256`: module ZIPs for
  `amnezia-libxray v1.0.3` and `amnezia-xray-core v1.260924.0` (their commits
  and Go sums are recorded in the bridge).
- `AMNEZIA_XRAY_REVIEW_MOD_SHA256`, `AMNEZIA_XRAY_REVIEW_SUM_SHA256`, and
  `AMNEZIA_XRAY_PATCHED_VENDOR_CLOSURE_SHA256`: the deterministic reviewed
  modfile, sumfile, and patched vendor closure.

If any of them is empty or malformed, `--preflight` and every build refuse
with exit 65 before source fetch,
output-directory creation, or build, printing one `unpinned <name>` line per
missing value. Measure each value on a networked host and record it in
`tools/build_apple_wg_go_bridge.sh`. The bridge does not pin the bytes of the
wrapper or staging producers, and it does not grep them for schema strings.
Each producer checks its own reviewed source pins: after measuring, confirm
that `APPLE_AWG_EXPECTED_GO_MOD_SHA256`, `APPLE_AWG_EXPECTED_GO_SUM_SHA256`,
and `APPLE_AWG_EXPECTED_XRAY_ZIP_SHA256` in
`tools/build_apple_engine_wrappers.sh` and
`tools/stage_apple_engine_artifacts.sh` equal the recorded bridge values, and
update them if they do not.

A rebuild also needs the pinned Go 1.27.1 extracted by
`tools/winn_release.py prepare-go` and passed as `WINS_RELEASE_GO_ROOT`; the
bridge re-measures bin/go and the install tree before and after the build.
Every Go call runs under a scrubbed `env -i` environment with
`GOTOOLCHAIN=local`, and module downloads go only through
`https://proxy.golang.org` with `sum.golang.org` checking. Source,
bridge-output, wrapper-output, and staging transaction roots must be fresh and absent. Existing engine artifacts
and `apple_awg_31_engine_provenance.json` must not be reused, edited,
relabeled, or staged; only a real rebuild issues new bridge, wrapper, and
package provenance.

The producer verifies the remote tag resolution, commit, Git tree, pristine
checkout, module files, Go archives, Xray module identity, Go module sums, and
Xray module ZIP before compilation. A successful bridge build writes
`.artifacts/apple-wg-go/apple_awg_31_bridge_provenance.json`. The wrapper build
then verifies every bridge hash and writes
`apple/EngineArtifacts/apple_awg_31_engine_provenance.json`, binding each AWG
and Xray wrapper to its bridge inputs. The same rebuild also writes
`apple/EngineArtifacts/apple_xray_vless_ws_engine_provenance.json`, binding
every delivered iOS, macOS, and simulator `libWinsXrayVlessWsTransport.dylib`
to the SHA-256 of `apple/EngineWrappers/WinsXrayVlessWsTransport.m` and to the
required production imports `LibXraySetSockCallback`, `dup2`, `getifaddrs`, and
`setsockopt`. Compiling that wrapper source in a test harness is not evidence
that a provenance-bound or embedded dylib was built from it. Mutating the
wrapper source after artifact creation fails closed. Release candidate
production and engine staging fail closed when AWG or Xray provenance is
absent, symbolic, malformed, stale, or inconsistent with the exact wrapper
bytes. The staging producer copies the verified engine provenance into the
containing app resources and records the exact AWG, Xray, and Winn provenance
SHA-256 values in `apple_engine_artifacts_manifest.json`. Winn provenance schema
4 requires the exact platform architecture closure and retains the per-slice
role symbols, minimum OS, platform, install name, UUID, and dependencies.

Use `tools/build_apple_engine_wrappers.sh` after the bridge build to generate
the local `libWinsAmneziaWGPacketEngine.dylib` and
`libWinsXrayVlessWsTransport.dylib` files. The wrapper builder compiles one
Mach-O slice per required architecture and merges multi-arch macOS outputs with
`lipo`. The AWG wrapper links the upstream Go archive once and exports the
Win's VPN C ABI plus the upstream AWG/Xray bridge symbols. The Xray wrapper
depends on
`@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine`, builds the VLESS-WebSocket
client config from the validated launch JSON, and calls the upstream
`LibXrayRunXray` / `LibXrayStopXray` / `LibXraySetSockCallback` API.

`LibXraySetSockCallback` is registered once with a stable C function before
`LibXrayRunXray`. Every outbound Xray socket fd (IPv4, IPv6, Happy Eyeballs
parallel dials, TLS/ECH DNS, reconnects) is bound to the physical non-utun
interface with `IP_BOUND_IF` / `IPV6_BOUND_IF` before connect. That is the
PacketTunnel/NetworkExtension per-fd route-protection path; a single
`excludedRoutes` /32 cannot cover those extra sockets. Start fails closed if
callback registration or a physical interface is unavailable. Stop disarms
protection and does not pass a NULL callback (xray-core appends controllers
and rejects NULL). Before registration, the wrapper retains a nonblocking,
close-on-exec pipe read descriptor. The still-registered callback atomically
dup2(2)s that non-socket descriptor over every later engine-owned socket, so
connect(2), including 127.0.0.1 / localhost / ::1, fails with ENOTSOCK even at
RLIMIT_NOFILE/EMFILE. If descriptor replacement or partial-instance cleanup
fails, the Network Extension terminates fail closed. Engine-owned descriptor
numbers are never closed by the callback.

`LibXrayRunXray` is given a bounded Go `maxMemory` of 16 MiB
(`WINS_XRAY_LIBXRAY_MAX_MEMORY_BYTES`), not 0. Zero disables
`debug.SetMemoryLimit` in amnezia-libxray. AWG and Xray share one Go runtime
in `libwg-go.a`; Winn3 is a separate Go runtime. 16 MiB is a soft heap goal
for the shared AWG+Xray runtime so Xray cannot starve AWG or crowd Winn3
and the Network Extension jetsam budget.

Hostname-safe Xray replacement (do not silently bump or roll back):

- `github.com/amnezia-vpn/amnezia-xray-core` `v1.260924.0` (commit `77e5d55a796bafe17c1b5f2a9d9c590fd2a9f5f3`); the
  module ZIP SHA-256 (`AMNEZIA_XRAY_ZIP_SHA256`) is
  `7df5ebc400da6cc4ab13f5578e2fd19b855f98807f1ef1d86a30afc2cd213c40`.
- One reviewed patch to MPL-covered `transport/internet/tls/ech.go` replaces
  the diagnostic ECH example URI with `https://dns.quad9.net/dns-query`.
- C API wrapper is `amnezia-libxray v1.0.3` (commit
  `e8cc06d7427251fa549093e7cc32c28b0f5fbafa`; amneziawg-apple `v3.1.20260814`
  itself pins v1.0.2); the module ZIP SHA-256 (`AMNEZIA_LIBXRAY_ZIP_SHA256`) is
  `9435bf77b8da780438b4e152a6b75b35991a920bd4ab5b00533613e8d1d54f4f`.
- Non-Apple Windows/Android/Linux Xray remains XTLS/Xray-core `v26.9.30`
  and is a separate pin.

Direct socket-protection tests live in
`apple/EngineWrappers/wins_xray_sock_protect_harness.c` and
`tools/test_apple_xray_runtime_hardening.py`. The harness is compiled with
`-DWINS_XRAY_TRANSPORT_TESTING=1` only. Production wrapper builds must not
define that macro or link the harness.

The artifacts must be Win's VPN-compatible wrapper binaries, not arbitrary
upstream binaries renamed to the accepted filenames. The staging gate checks the
Mach-O platform, architecture, framework-linkage contract, safe framework
symlinks, and exported C ABI symbols before copying anything into the
containing app bundle.

Required `amneziawg_packet_engine` symbols:

- `wins_amneziawg_packet_engine_contract_version`
- `wins_amneziawg_packet_engine_create`
- `wins_amneziawg_packet_engine_start`
- `wins_amneziawg_packet_engine_listen_port`
- `wins_amneziawg_packet_engine_stop`
- `wins_amneziawg_packet_engine_destroy`

Required `xray_vless_ws_transport` symbols:

- `wins_xray_vless_ws_transport_contract_version`
- `wins_xray_vless_ws_transport_configure`
- `wins_xray_vless_ws_transport_start`
- `wins_xray_vless_ws_transport_stop`

Delivered Xray dylibs must also import `LibXraySetSockCallback`, `dup2`,
`getifaddrs`, and `setsockopt`. Those production imports are recorded in
`apple_xray_vless_ws_engine_provenance.json` and checked on every slice.

Required `winn_packet_engine` symbols (required on release/engine gates; also
checked whenever the artifact exists):

- `wins_winn_packet_engine_contract_version`
- `wins_winn_packet_engine_create`
- `wins_winn_packet_engine_start`
- `wins_winn_packet_engine_stop`
- `wins_winn_packet_engine_destroy`
- `wins_winn_packet_engine_awg_seam_port`
- `wins_winn_packet_engine_expect_awg_port`
- `wins_winn_packet_engine_seam_stats`
- `wins_winn_packet_engine_status_json`
- `WinnTunnelCreateWinn3`

The pinned AWG archive must export `wgGetConfig`. Verify it locally with
`nm -gU <pinned-libwg-go.a>` before linking the listen-port reader.

Current v1 adapter signatures:

- `int wins_amneziawg_packet_engine_contract_version(void)`
- `void *wins_amneziawg_packet_engine_create(const char *launch_json, const void *packet_flow)`
- `int wins_amneziawg_packet_engine_start(void *engine)`
- `void wins_amneziawg_packet_engine_stop(void *engine)`
- `void wins_amneziawg_packet_engine_destroy(void *engine)`
- `int wins_xray_vless_ws_transport_contract_version(void)`
- `int wins_xray_vless_ws_transport_configure(const char *launch_json)`
- `int wins_xray_vless_ws_transport_start(void)`
- `void wins_xray_vless_ws_transport_stop(void)`
- `int wins_winn_packet_engine_contract_version(void)`
- `void *wins_winn_packet_engine_create(const char *launch_json, const void *packet_flow)`
- `int wins_winn_packet_engine_start(void *engine)`
- `void wins_winn_packet_engine_stop(void *engine)`
- `void wins_winn_packet_engine_destroy(void *engine)`

## Winn Protocol packet engine

`winn_packet_engine` is built from `apple/EngineWrappers/WinsWinnPacketEngine.m`
plus the `datapath` lane's Go `-buildmode=c-archive` (`libwinn-go.a`), exactly
the way the AmneziaWG wrapper is built from its wrapper plus `libwg-go.a`. iOS
forbids subprocesses, so the c-archive route is forced; macOS shares it rather
than growing a second mechanism.

The current C contract is declared in `apple/EngineWrappers/WinnTunnel.h`.
See the header comment in `apple/EngineWrappers/WinsWinnPacketEngine.m` for
the current AWG outer-datagram seam and packet-flow ownership. The test-only
`apple/EngineWrappers/WinnTunnelTestDouble.c` must never be linked into a
shipping artifact.

`launch_json` contains the validated runtime sections needed by the native
wrapper. It is secret-bearing process-local data and must never be logged. The
`packet_flow` value is the opaque `NEPacketTunnelFlow` object pointer; native
wrappers that need to retain it must do so using platform-appropriate
Objective-C/Swift bridging.
