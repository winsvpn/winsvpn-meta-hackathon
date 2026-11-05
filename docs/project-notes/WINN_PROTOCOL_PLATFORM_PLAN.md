# Winn Protocol — Platform Tunnel Providers

Single source of truth for making Winn Protocol carry real traffic on Windows,
macOS, Linux, Android and iOS, on both x86_64 and ARM.

Owner: admin@winsvpn.org · Started 2026-08-03 · Status: **IN PROGRESS**

> **Live progress is at the bottom of this file.** It is regenerated from
> `.winn_platform_progress/*.json` by `tools/sync_winn_platform_progress.py`.
> Do not hand-edit the LIVE PROGRESS section — edits there are overwritten.
> Each lane agent writes only its own JSON file, so parallel lanes never
> collide on this document.

---

## 1. Ground truth (verified 2026-08-03, not assumed)

Two earlier briefs in this project asserted repo paths that do not exist and
sent an agent down a wrong path. Everything below was verified by direct
search before this plan was written. **Verify again before you rely on it.**

### What already exists

The app ships a working VPN on all four platforms today. The tunnel providers
are real, substantial, and carry AmneziaWG:

| Platform | Provider | Lines |
|---|---|---|
| Android | `android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt` (`VpnService`) | 1382 |
| iOS | `ios/PacketTunnel/PacketTunnelProvider.swift` (`NEPacketTunnelProvider`) | 954 |
| macOS | `macos/PacketTunnel/PacketTunnelProvider.swift` (`NEPacketTunnelProvider`) | 954 |
| Windows | `windows/runner/windows_tunnel_backend.cpp` (WinTun) | 3988 |
| Apple engine wrapper | `apple/EngineWrappers/WinsAmneziaWGPacketEngine.m` (utun) | 191 |
| Windows engine | `windows/awg_engine/main.go` | 124 |

So this work is **extending existing providers to carry a second protocol**,
not writing four tunnel providers from scratch.

### The actual blocker

Winn Protocol v3 compiles for all nine targets, but its only production carrier
assemblies are Linux-only and drive **external binaries** (`nft`, `ip`, `awg`)
as subprocesses:

- `internal/directawg/linux_constructor_unsupported.go` → `ErrLinuxControllerUnsupported` on `!linux`
- `internal/preparation/linux_underlay_runner_unsupported.go` → same
- reference wiring is ~1722 lines gated `//go:build linux` in `cmd/winn-auto-e2e/main_linux.go`

Android, iOS, macOS and Windows cannot shell out to `nft`. **That**, not
portability, is why there is no tunnel. The fix is an in-process datapath.

### Existing native patterns to follow (do not invent a fifth)

- **Apple**: Go → `-buildmode=c-archive` (`libwg-go.a`) → ObjC wrapper → `.dylib`
  → re-wrapped into `.framework` by `tools/stage_apple_engine_artifacts.sh`,
  loaded from Swift with `dlopen`/`dlsym`.
- **Android**: Go cross-compiled by `tools/build_xray_engine.sh` → binary named
  `libxray.so` placed in `jniLibs/<abi>/` → executed as a **subprocess** from
  `nativeLibraryDir`.
- **Windows**: Go → standalone `winsvpn_awg_engine.exe`.
- **Dart ↔ native** is two MethodChannels (`lib/main.dart:93`,
  `lib/watch_bridge.dart:52`). There is **no `dart:ffi` anywhere** — do not add it.

### Already built (previous session, additive, nothing wired)

- `winn_protocol_experimental/clientbinding/binding.go` (+ `binding_test.go`)
- `winn_protocol_experimental/cshared/winn_clientbinding.go`
- `winn_protocol_experimental/cmd/winn-clientinfo/main.go`
- `tools/build_winn_protocol_engine.sh` — builds all nine targets, verified

---

## 2. The contract every lane builds against

Defined up front so all lanes work in parallel without waiting on each other.
**If you need to change this contract, update this section and say so loudly in
your progress file — every other lane depends on it.**

### The shape: the host owns the tunnel device, Go owns the protocol

This is exactly how `libwg-go.a` already works on Apple in this repo, and it is
the only shape that works on all five platforms. Go must **never** create an OS
network interface, edit routes, or shell out to `nft`/`ip`/`awg`.

```
WinnTunnelCreate(configJson, udpFd) -> handle | error
WinnTunnelWriteInbound(handle, buf, len)      // host tun -> protocol
WinnTunnelReadOutbound(handle, buf, cap) -> n // protocol -> host tun
WinnTunnelStatusJSON(handle) -> json
WinnTunnelClose(handle)
```

### Per-platform transport of that contract

| Platform | Transport | Why |
|---|---|---|
| iOS | c-archive static lib + C header | iOS forbids subprocesses. Forced. |
| macOS | c-archive (same as iOS) | Shares the Apple wrapper + framework staging. |
| Android | subprocess + duplex pipe/socketpair | Matches `libxray.so` precedent exactly. |
| Windows | subprocess + duplex pipe | Matches `winsvpn_awg_engine.exe` precedent. |
| Linux | either | Already has the exec carrier; lowest priority. |

### Normative wire framing for the subprocess transports

**Arbitrated 2026-08-03.** The original section 2 fixed the five calls and the
per-platform transport but not the byte layout, so the `android` and `windows`
lanes each invented their own and the `datapath` lane would have had to ship two
framed entry points. Both lanes flagged it rather than diverging silently.

**The Windows layout wins and is now normative for every subprocess host**
(Android, Windows, Linux, and macOS when it uses the subprocess path). It was
chosen over the Android variant because a magic number catches a desynced or
wrong-pipe stream immediately, an explicit version field lets the framing evolve
without guesswork, and its self-test is portable C++17 that runs on any host. The
cost is a 16-byte header instead of 4, which on a ~1420-byte packet is under 1%.

Reference implementation and golden-byte self-test: `windows/runner/winn_frame.h`.

```
  offset  size  field
  0       4     magic     u32 LE = 0x334E4E57  ("WNN3")
  4       2     version   u16 LE = 1
  6       2     opcode    u16 LE
  8       4     length    u32 LE, payload byte count
  12      4     reserved  u32 LE, must be zero
  16      len   payload
```

Opcodes: `Create 0x0001`, `CreateAck 0x0002`, `Inbound 0x0010`,
`Outbound 0x0011`, `StatusRequest 0x0020`, `StatusResponse 0x0021`,
`Close 0x0030`, `CloseAck 0x0031`, `Error 0x00F0`. Everything is little-endian:
both Windows targets and all Android ABIs in use are little-endian, and Go's
`encoding/binary.LittleEndian` maps to it with no conversion. Direction is
enforced per side. `reserved` gives one free extension slot without a version
bump.

Android's `WinnProtocolFraming.kt` converges on this. Its `HELLO`/`READY`
handshake maps onto `Create`/`CreateAck`, and its `SHUTDOWN` onto `Close`.

### The UDP socket rule — get this wrong and Android loops forever

The outer UDP socket **must not** be routed back into the tunnel.

- **Android**: the host must open the socket and call `VpnService.protect(fd)`,
  then pass the protected fd to Go. Go must not open its own socket.
- **Apple**: `NEPacketTunnelProvider` excludes its own traffic; Go may open the
  socket, but it must bind through the provider's interface.
- **Windows**: exclude by route or by the existing split-tunnel logic in
  `windows_split_tunnel.cpp`.

---

## 3. Lanes

Each lane is an independent agent. Lane 1 is the critical path; the platform
lanes build their native side against the contract above and do **not** wait.

| # | Lane | Owns | Model |
|---|---|---|---|
| 1 | `datapath` | Go in-process datapath + the C/subprocess API | Opus 5 |
| 2 | `android` | `VpnTunnelService.kt`, jniLibs packaging, protected fd | Opus 5 |
| 3 | `apple` | iOS + macOS `PacketTunnelProvider.swift`, framework staging | Opus 5 |
| 4 | `windows` | `windows_tunnel_backend.cpp`, engine exe, split tunnel | Opus 5 |
| 5 | `conformance` | Cross-platform build + a test that fails if anyone lies | Sonnet 5 |

---

## 4. Rules that are not negotiable

1. **Additive only.** AmneziaWG is what ships today and must keep working
   byte-for-byte. Winn support is added *alongside*, never replacing.
2. **No on-switch.** Do not flip the `winn/3` refusal at `lib/main.dart:8184-8225`.
   A client that advertises post-quantum support it cannot honour is worse than
   one that refuses. Enabling in production is a governance decision, not an
   engineering one.
3. **Never enters `com.winsvpn.security`.** Winn Protocol must not appear in the
   Win For All repo. Absolute.
4. **Do not change** app version (`1.0.14+29`, in review at three stores),
   application id, signing config, or manifest permissions. If a platform
   genuinely requires a new permission or entitlement, write it in your progress
   file as a **blocked** item and stop — do not add it.
5. **No key material** in prompts, logs, source, or handoff files. If you find
   any, record only `material present at <file>:<line>`.
6. **Do not modify** `winn_protocol_experimental/evidence/` (sealed), the
   append-only logs, or `docs/handoff/*.md`.
7. **Governance gates stand.** The E8 sealed-rehearsal receipt is explicitly
   **non-authorizing**, and the R15 chain still needs a **family-distinct**
   reviewer — Fable 5 is Claude-family and cannot close it.
8. **Anti-fabrication.** This project has a documented history of scripts
   reporting success they never achieved, and of exit codes that lie. Report
   only real command output. Mark anything you could not run `UNVERIFIED`.
   "BLOCKED at X" is a good outcome; a false success is not.

### Baselines that must not regress

- `flutter analyze` → `No issues found!`
- `flutter test` → **341 passing** (was 336 when this plan was written; the
  `conformance` lane added `test/winn_protocol_refusal_guard_test.dart`, +5.
  Measured 2026-08-03, `All tests passed!`. Do NOT "fix" the count by deleting
  that guard file — it is the test that stops anyone advertising Winn support
  that does not exist.)
- `go test ./clientbinding/` → ok

### Known side effect

Any change under `android/`, `ios/`, `macos/`, `windows/` or `lib/` invalidates
the release-input freeze (currently **r18**,
`.artifacts/release-dependency-freeze/1.0.14+29/sr-tiktok-social-button-20260803T110116Z-r18`).
That is expected. Do not hand-edit a freeze; regenerate with
`tools/release_dependency_freeze.py` when a build is actually needed.

---

## LIVE PROGRESS

<!-- BEGIN:LIVE_PROGRESS -->
_Synced 2026-08-04 11:09:24Z. Regenerated by `tools/sync_winn_platform_progress.py` -- do not hand-edit._

| Lane | Status | Done | Summary |
|---|---|---|---|
| `datapath` | &#10003; done | 9/9 | in-process datapath moves real packets on all nine targets via c-archive and WNN3 subprocess; CONTRACT CLARIFICATION: payloads are AWG outer datagrams, not r... |
| `android` | &#10003; done | 8/8 | Android host side of the section-2 contract implemented additively in VpnTunnelService; 34 new JVM tests green against a local framing double; AmneziaWG path... |
| `apple` | &#9679; in progress | 10/12 | iOS+macOS Winn host is COMPLETE IN SOURCE and exercised end to end against the real Go c-archive: AmneziaWG keeps the tun, the Winn seam carries its outer da... |
| `windows` | source-complete-not-executed | 11/13 | The Windows Winn host was rebuilt into the same shape Android, Apple and Linux already ship: the second WinTun adapter is GONE, a 127.0.0.1 seam sits beside ... |
| `conformance` | &#10003; done | 7/7 | Harness + guard test built, both baselines-clean (341 passing, analyze clean, go test ok, 5 runs, 0 flakes). Found a REAL regression: the shared tools/build_... |
| `linux` | &#10003; done | 8/8 | Linux Winn host integration built and PROVEN BY EXECUTION: a real winn/3 session completes end to end through the shipping dispatch path (Dart winnSectionFor... |

### datapath
- [x] Read WINN_PROTOCOL_PLATFORM_PLAN.md in full -- section 2 followed; one payload-semantics clarification raised loudly, see notes
- [x] Map the real datapath on Linux -- Go NEVER touches an IP packet today. amneziawg-go (external binary) owns the tun and the crypto; `awg set <if> peer ... endpoint 127.0.0.1:<port>` points it at a loopback UDP socket; carrier.RelayLocalUDP moves AWG OUTER DATAGRAMS between that socket and the carrier. internal/carrier is already fully portable, no build tags.
- [x] Portable in-process datapath package -- winn_protocol_experimental/datapath. Open(configJSON,udpFD)/WriteInbound/ReadOutbound(+Timeout)/StatusJSON/Close. Adopts a caller-supplied descriptor and takes ownership; refuses to open its own socket unless allow_own_socket. Compiles CGO_ENABLED=0 for all nine target pairs.
- [x] c-archive surface + C header -- cdatapath/ exports 9 WinnTunnel* symbols; curated header cdatapath/winn_datapath.h carries status codes, ownership rules and the route-promotion guidance the cgo-generated header cannot. Linked into a C program and run: real datagrams both ways.
- [x] Subprocess entry point on the NORMATIVE WNN3 framing -- cmd/winn-datapath + datapath/duplex, rewritten to the coordinator's mandated 16-byte little-endian WNN3 header. Byte-identical to windows/runner/winn_frame.h, enforced by a test that compiles that header and diffs 9 vectors. Reader latches on any invalid frame so a stream cannot resynchronise.
- [x] Status fields for a transfer-proven route-promotion gate -- transport_observed_both_ways is the gate field. NO handshake-completed flag: this layer cannot honestly observe one. See notes.
- [x] Real Go tests -- 69 passing. Loopback both directions in-process, over the framed pipe, and through the compiled subprocess; descriptor adoption incl. SCM_RIGHTS; no-subprocess and no-own-socket guards; C++ cross-language conformance.
- [x] Extend tools/build_winn_protocol_engine.sh -- datapath-<nine targets> plus datapath-archive-darwin-{arm64,amd64}. All nine built with real recorded output, exit 0.
- [x] Fix the two build-script regressions conformance found -- ios-arm64 was building a c-archive from ./cmd/winn-clientinfo (a main package). Fixed with select_clientinfo_archive -> ./cshared, plus require_archive_selection so the class of bug cannot recur silently. Stale `trap ... RETURN` replaced with explicit cleanup. Both archive paths now exit 0.

**Verified by real command output:**
- go test -count=1 ./datapath/... ./cmd/winn-datapath/ -> ok x3 packages, 69 passing tests
- go test -count=1 ./clientbinding/ -> ok (pre-existing baseline held)
- go build ./... over the whole module -> exit 0
- CGO_ENABLED=0 go build ./datapath/... for linux/{amd64,arm64} darwin/{amd64,arm64} windows/{amd64,arm64} android/{amd64,arm64} ios/arm64 -> all OK
- build_winn_protocol_engine.sh datapath-<all nine> -> exit 0 each; file(1): ELF x86-64 / ELF aarch64 / Mach-O x86_64 / Mach-O arm64 / PE32+ x86-64 / PE32+ Aarch64 / ELF pie aarch64 (android) / ELF pie x86-64 (android) / ar archive (ios)
- build_winn_protocol_engine.sh ios-arm64 -> 'Validated Apple c-archive (arm64, IOS, package ./cshared, C ABI present)', exit=0 -- this pre-existing target was BROKEN by an earlier revision of my edit and is now fixed
- build_winn_protocol_engine.sh datapath-ios-arm64 / datapath-archive-darwin-{arm64,amd64} -> arm64/IOS, arm64/MACOS, x86_64/MACOS validated, exit=0
- xcrun nm -gU on the datapath archive lists all 9 _WinnTunnel* symbols
- clang++ -std=c++17 against windows/runner/winn_frame.h prints kFrameMagic=0x334e4e57 kFrameVersion=1 kFrameHeaderBytes=16 kMaxFramePayloadBytes=65535 and 9 golden frames byte-identical to this package's encoder
- C program linked against libwinn_datapath.a (darwin-arm64) via cdatapath/winn_datapath.h: contract=winn-datapath/1 protocol=winn/3 max_datagram=1500, host->gateway 200 bytes OK, gateway->host 300 bytes OK, transport_observed_both_ways=true, ALL C ABI CHECKS PASSED, exit=0

## CONTRACT CLARIFICATION - read this, four lanes depend on it

Section 2 says `WinnTunnelWriteInbound` carries `host tun -> protocol`, and
windows/runner/winn_frame.h says an Inbound frame is "exactly one IP packet".
**For this engine they are not IP packets.** They are AmneziaWG OUTER
DATAGRAMS - what the host's own AWG engine would otherwise have sent to and
received from the gateway's UDP endpoint. The framing is payload-agnostic, so
no wire change is needed; what changes is what a host must put in the frame.

The reason is not a shortcut. This Go module contains no WireGuard or
AmneziaWG implementation: nothing in go.mod, nothing in go.sum, nothing in the
local module cache. On Linux the encryption is done by `amneziawg-go`, an
external binary the controller starts as a subprocess, which owns the tun
device; Go's only datapath job is `carrier.RelayLocalUDP`, moving
already-encapsulated datagrams between a loopback UDP socket and the carrier.

So the boundary is drawn BELOW AmneziaWG, not above it:

    host tun -> host's existing AWG engine -> WINN DATAPATH -> network

Every platform already has that AWG engine (libwg-go.a on Apple, the AmneziaWG
GoBackend on Android, windows/awg_engine on Windows), so nothing is missing -
the seam just sits one layer lower than section 2 implies.
`payload:"ip-packet"` is REFUSED at create time rather than silently
forwarding cleartext to the gateway.

## For the windows lane: the route-promotion gate

`"up"` means the engine is open and the carrier socket has not failed. That is
link liveness, true for a socket that has never carried a byte. Do not promote
default routes on it.

Gate on **`transport_observed_both_ways`**, backed by the monotonic counters
`rx_transport_payload_datagrams` and `tx_transport_payload_datagrams`. Those
move only for datagrams carrying the AmneziaWG transport-data header type,
larger than a bare 32-byte keepalive, and inbound only from the configured
gateway endpoint. A peer cannot produce transport-data messages without having
completed the handshake and derived transport keys. `rx_foreign_sender` counts
what was rejected, and a test proves an off-path sender cannot move the gate.

**There is deliberately no `handshake_completed` boolean.** This layer holds no
keys and verifies no authentication tag; every field is a header-type
comparison on bytes it cannot decrypt. An on-path replay from the gateway's
address would move the same counters. The authoritative handshake signal is the
host's own AWG engine (`awg show latest-handshakes`, which
internal/directawg/status_cli.go already consumes on Linux). The correct gate
is the conjunction:

    winn.transport_observed_both_ways AND hostAWG.latestHandshake is recent

Classification needs the signed `h1..h4` values passed as
`awg_header_types`. Without them the engine falls back to plain WireGuard 1..4
and reports `awg_classification:"wireguard-default-1234"`, under which
obfuscated traffic classifies as nothing. That string with zero transport
counters is a configuration gap, not a dead tunnel.

`handshake_response_observed` is also exposed but is strictly weaker: it means
the gateway sent something shaped like a handshake response, not that the
response verified.

## For the android lane

Confirmed and implemented. The engine never opens its own socket when given a
descriptor (asserted by a test that fails if the socket-creation seam is
reached at all), and `allow_own_socket` defaults to false so a missing
protected descriptor fails loudly instead of looping. The engine TAKES
OWNERSHIP of the descriptor and closes it in Close; the host must not close it
again. `-transport unix -receive-fd` reads exactly one SCM_RIGHTS descriptor
and refuses two rather than picking one and leaking the rest.

## Not built, stated plainly

- SUPERSEDED 2026-08-03: the http2 and http3/masque dialers now DO accept a
  caller-supplied socket. `internal/carrier/supplied_socket.go` adds
  `UseSuppliedSocket` on both, single-use and fail-closed, and
  `datapath.OpenWithCarrier` adopts a descriptor and installs it. Note
  http3 and masque are ONE dialer here: `H3Dialer` performs RFC 9298
  CONNECT-UDP through `internal/masque`, so "three carriers" is two.
  Proven with four mutation checks and real datagrams over real QUIC and
  TLS 1.3 x25519-mlkem768. Still NOT wired host-side: nothing calls
  `OpenWithCarrier` from Kotlin, Swift or the WNN3 subprocess, and the C
  ABI cannot reach it because it needs a Go dialer. Android therefore
  still gets direct-awg in practice.
- `CloseAck` carries no payload, per the normative framing, so final counters
  must be fetched with `StatusRequest` BEFORE `Close`.
- Nothing here changes the winn/3 refusal in lib/main.dart. This lane touched
  only winn_protocol_experimental/** and tools/build_winn_protocol_engine.sh.


### android
- [x] Read WINN_PROTOCOL_PLATFORM_PLAN.md in full -- Contract in section 2 accepted unchanged. NO contract change proposed by this lane.
- [x] Map VpnTunnelService.kt before changing anything -- Builder: setSession/addAddress(clientIp,32)/addDnsServer/setMtu, one addRoute per VpnRouteParser.allowedIpv4Routes, allowFamily(AF_INET), fd00:d951:1::1/128 + ::/0 IPv6 sink, addDisallowedApplication only for stealth-xray, user split-tunnel, setUnderlyingNetworks, establish(). tun fd: ParcelFileDescriptor.dup(vpnInterface.fileDescriptor).detachFd() -> raw int -> GoBackend.awgTurnOn. Sockets: awgGetSocketV4/V6 then protect() AFTER the fact (only works because AWG is in-process). MainActivity only passes CONFIG_PAYLOAD + ACTION_CONNECT and reads static status; it needed no change.
- [x] Map the libxray.so packaging pattern -- build_xray_engine.sh cross-compiles Go with NDK clang; prepare_android_xray_assets.sh drops the result at jniLibs/<abi>/libxray.so; service execs it from applicationInfo.nativeLibraryDir. VERIFIED: libxray.so is 'ELF 64-bit LSB pie executable, ARM aarch64' (a Go executable under a lib*.so name), the built manifest carries extractNativeLibs="true", and app-debug.apk contains lib/arm64-v8a/libxray.so + lib/x86_64/libxray.so. Same mechanism carries libwinnengine.so with ZERO Gradle change.
- [x] Implement the Android side of the contract -- 5 new main-source files + additive wiring in VpnTunnelService. Engine is a subprocess reached over one abstract-namespace AF_UNIX stream socket carrying the framing below. Host keeps the tun and the outer UDP socket.
- [x] Protected-UDP-socket rule enforced and tested -- Host opens DatagramSocket -> VpnService.protect() -> hands the descriptor to the engine via SCM_RIGHTS, strictly BEFORE the subprocess is spawned. Bridge refuses to start on an unprotected socket. Two mutation tests confirmed the guards are real (see notes).
- [x] Local test double speaking the same framing -- WinnEngineDouble + LoopbackWinnTransport + FakeTunDevice in the JVM test source set. 17 bridge tests drive handshake, packet path, status round trip, failure and shutdown with no Go engine, no device, no Android framework.
- [x] Packaging step prepared, artifact deliberately not staged -- android/tools/prepare_android_winn_assets.sh. Default --check mode writes nothing; --stage is the one line that would build and drop the binary. Not run: 1.0.14+29 is in store review.
- [x] Verify baselines -- flutter analyze: No issues found! flutter test: 341 passed (336 pre-existing + 5 added by the conformance lane's winn_protocol_refusal_guard_test.dart; this lane added zero Dart tests). Gradle :app:testDebugUnitTest 40/40, :app:assembleDebug BUILD SUCCESSFUL. Release variant compile is UNVERIFIED - blocked by the repo's own signing guard, not by this change.

**Verified by real command output:**
- flutter analyze -> No issues found! (5.2s)
- flutter test -> 341 passed, 0 failed
- gradlew :app:testDebugUnitTest -> BUILD SUCCESSFUL, 40 tests, 0 failures, 0 errors (6 pre-existing + 34 new)
- gradlew :app:compileDebugKotlin -> BUILD SUCCESSFUL, no new warnings
- gradlew :app:assembleDebug -> BUILD SUCCESSFUL; APK contains libxray.so for both ABIs and no libwinnengine.so
- mutation check 1: disabling the protectedBeforeHandoff guard -> 1 test fails (anUnprotectedSocketIsRefusedAndTheEngineIsNeverSpawned)
- mutation check 2: spawning the engine before protecting the socket -> 4 tests fail, including theOuterUdpSocketIsOpenedAndProtectedBeforeTheEngineProcessExists
- android/tools/prepare_android_winn_assets.sh --check -> exit 0, wrote nothing; jniLibs still contains only libxray.so
- AndroidManifest.xml, app/build.gradle.kts and MainActivity.kt are untouched by this lane (git diff of each contains zero 'winn' matches)

## What changed

New, all under `android/**`:
- `app/src/main/kotlin/org/winsvpn/app/WinnProtocolFraming.kt` - the wire format (normative)
- `.../WinnEngineConfig.kt` - `[winn]` INI section -> `configJson`
- `.../WinnEngineTransport.kt` - transport/underlay/process/host interfaces
- `.../WinnTunnelBridge.kt` - the contract's five calls, Android-free, JVM-testable
- `.../WinnAndroidEngineHost.kt` - LocalSocket + SCM_RIGHTS + subprocess spawn
- `app/src/test/kotlin/.../WinnProtocolFramingTest.kt` (9), `WinnEngineConfigTest.kt` (8), `WinnEngineDouble.kt` (the double), `WinnTunnelBridgeTest.kt` (17)
- `android/tools/prepare_android_winn_assets.sh`

Modified: `VpnTunnelService.kt` only. NOT modified: manifest (zero new permissions), `app/build.gradle.kts` (no version/appid/signing/packaging change), `MainActivity.kt`, `lib/main.dart` (the `winn/3` refusal stands).

## FOR THE `datapath` LANE - the Android wire format

The engine binary is `libwinnengine.so` in `jniLibs/<abi>/`, exec'd from `nativeLibraryDir` as `libwinnengine.so tunnel`, with env `WINN_ENGINE_CHANNEL=<name>`. Dial it with `net.Dial("unix", "@"+name)` (Linux abstract namespace). Then, per message:

```
byte  0     type
bytes 1..3  payload length, big-endian uint24 (max 65535)
bytes 4..n  payload
```

| type | name | dir | payload |
|---|---|---|---|
| 0x01 | HELLO | host->engine | config JSON; **SCM_RIGHTS: exactly one fd, the protected UDP socket** |
| 0x02 | READY | engine->host | status JSON |
| 0x03 | INBOUND | host->engine | one IP packet from tun |
| 0x04 | OUTBOUND | engine->host | one IP packet for tun |
| 0x05 | STATUS_REQUEST | host->engine | empty |
| 0x06 | STATUS | engine->host | status JSON |
| 0x07 | SHUTDOWN | host->engine | empty |
| 0x08 | ERROR | engine->host | UTF-8 reason |

HELLO is sent as ONE `sendmsg` (header+payload fused) with the descriptor attached, so your first `recvmsg` yields both. The engine has 10s to answer READY. Answer STATUS_REQUEST promptly: the host's watchdog treats a status reply older than 45s as a dead tunnel regardless of process liveness.

`configJson` shape: `{winn_framing_version, role, endpoint, mtu, tunnel_address, dns[], udp_socket{provided_by_host,protected,transport,engine_may_open_sockets}, params{...}}`. Everything in the app's `[winn]` config section except `enabled` is forwarded verbatim under `params`, so **the schema of `params` is yours** - this lane does not guess at it.

`tools/build_winn_protocol_engine.sh` today builds `winn-clientinfo`, which does NOT speak this framing. Staging it would install a binary that never answers HELLO. The Android side is ready whenever your framed duplex entry point lands.

## The UDP socket rule - why the order is what it is

`VpnService.protect()` marks the kernel socket (netd sets the bypass-VPN `SO_MARK` on the `struct sock`), not the descriptor number. Route lookups for that socket then skip the VPN routing rules and leave over the physical underlay. `dup()` and SCM_RIGHTS both create a new descriptor onto the *same* open file description and the same `struct sock`, so the mark travels into the subprocess - that is what makes the handoff sound.

A socket the engine opened for itself carries no mark. Its datagrams to the server would match the routes this service just installed (`AllowedIPs` plus the `::/0` sink), be written back into our own tun, be handed to the engine as INBOUND, be encapsulated again, and re-emitted forever, with nothing leaving the device.

AmneziaWG gets away with the reverse order (Go opens, Kotlin protects afterwards via `awgGetSocketV4/V6`) only because it is in-process; a raw fd int is meaningless across processes, so a subprocess cannot be protected after the fact. Hence: **open, protect, then spawn, then hand over.** `WinnTunnelBridge.start()` opens and protects before `startEngineProcess()` is ever called, and refuses outright if `protectedBeforeHandoff` is false. Both properties are covered by tests that were confirmed to fail when the code is mutated.

Consequence worth noting: because the socket is individually protected, Winn mode does **not** need the coarse `addDisallowedApplication(packageName)` that stealth-xray is forced into. The app's own UID stays inside the tunnel and `speedTestMeasuresPhysicalRoute` stays false.

## Integrated against the real engine vs. the double

Against the **double** (no real engine exists yet): framing, handshake ordering, HELLO carrying exactly one descriptor, packet pumping and boundary preservation, status round trips, mid-session ERROR, channel drop, shutdown, idempotent close, resource release on every failure path.

**UNVERIFIED, needs a device or emulator:** actual SCM_RIGHTS transfer over `android.net.LocalSocket`; `VpnService.protect()` returning true and the mark surviving the transfer; the subprocess actually spawning from `nativeLibraryDir`; the abstract-socket accept and peer-uid check; end-to-end traffic. The double runs over loopback TCP and only records which descriptor was handed over.

**UNVERIFIED:** release-variant Kotlin compilation. `:app:compileReleaseKotlin` pulls `packageReleaseResources` into the task graph, which trips the repo's pre-existing signing guard in `app/build.gradle.kts`. Supplying signing input was out of scope; debug compile, unit tests and `assembleDebug` all pass.

## Additive-only evidence

The AmneziaWG run loop was moved verbatim into `startAwgEngineThread()` and is called on the `else` branch with `tunPfd.detachFd()`, reproducing the previous `ParcelFileDescriptor.dup(...).detachFd()` exactly. With no `[winn]` section present, `WinnEngineConfig.isEnabled` is false, the added `stripConfigSection(config, "winn")` is a no-op (the inner call already trims), `mode` still resolves to `stealth-xray`/`direct-awg`, and no Winn code executes. A config that enables both `[xray]` and `[winn]` is refused rather than silently resolved.

## Not blocked, nothing requested

No new manifest permission is needed: the channel is an app-private AF_UNIX socket, the subprocess is our own binary, and `INTERNET` already covers the UDP socket. No new Gradle configuration is needed. Nothing here advertises `winn/3`.

## CROSS-LANE FLAG: two subprocess framings now exist

Plan section 2 fixes the five-call API surface but does not fix a byte-level framing. Android and Windows are both "subprocess + duplex pipe" hosts, and both lanes filled that gap independently:

- Android (this lane): `HELLO / READY / INBOUND / OUTBOUND / STATUS_REQUEST / STATUS / SHUTDOWN / ERROR`, 4-byte header (type + uint24 length), HELLO carrying an SCM_RIGHTS descriptor.
- Windows (per its progress file): `create / createAck / inbound / outbound / status / close / closeAck`, over a named pipe, with no descriptor passing.

Semantically the same exchange, but the vocabularies differ, so as written the `datapath` lane would have to ship two framed duplex entry points instead of one. This lane is NOT proposing a contract change and has not altered section 2 - flagging it so whoever owns the plan can decide whether to unify the two or accept one framed entry point per host. The Android side is small and isolated (`WinnProtocolFraming.kt` plus one transport implementation), so converging onto a single agreed format later is a contained change.

Note also that the Android and Windows UDP-socket strategies legitimately differ, per the plan's own per-platform rule: Android passes a `protect()`ed descriptor, Windows pins a /32 host route to the endpoint and lets the engine open its own socket. That difference is by design and is not the divergence being flagged.

### apple
- [x] Read WINN_PROTOCOL_PLATFORM_PLAN.md in full -- contract in section 2 accepted as-is; NO contract change proposed
- [x] Map provider start / network settings / packetFlow / dlopen engine load / framework staging -- the providers are protocol-agnostic and still needed ZERO edits; both remain byte-identical (md5 20a34f265b018090311f0541b398b1b0)
- [x] Add Winn C header + ObjC engine wrapper alongside the AmneziaWG wrapper -- apple/EngineWrappers/WinnTunnel.h + WinsWinnPacketEngine.m
- [x] CORRECTION: move the wrapper to the right side of the AmneziaWG engine -- an earlier revision pumped utun straight into WinnTunnelWriteInbound, which is cleartext IP where the contract is AWG OUTER datagrams. Now a loopback seam below AWG, with an additive sixth symbol wins_winn_packet_engine_awg_seam_port reporting the ephemeral port
- [x] Swift host: start the seam first, read its port, repoint the AmneziaWG UAPI endpoint, then start AmneziaWG -- WinsPacketTunnelEngine.swift. Fails closed at every step; AmneziaWG is never created if the seam does not come up
- [x] CORRECTION: packetCarrierComponent no longer selects Winn INSTEAD of AmneziaWG -- Winn needs BOTH. requiredEngineComponents is now [amneziawg_packet_engine, winn_packet_engine]; WinsPacketCarrier.all no longer contains winn, so a plan naming Winn alone resolves to no tun owner and fails
- [x] CORRECTION: transportIPv4ExclusionRoute now follows [winn] endpoint -- it fell back to the AmneziaWG peer host. The Winn gateway can differ from the AWG gateway (protocol_params.gateway_endpoint), and the peer is repointed to loopback at start, so the /32 keeping the engine's outer socket off the tunnel would have vanished and the tunnel dead-looped
- [x] validate(): the Winn analogue of the Xray loopback-peer rule -- codes 1501-1506. Refuses a missing/hostname/loopback Winn gateway, a full-tunnel config with no /32, an already-loopback AWG peer, Winn+Xray together, and any carrier this ABI cannot build
- [x] NEW GAP FOUND AND CLOSED: the carrier downgrade -- the carrier lane now emits `carrier = <value>` into [winn] on every winn/3 config. The wrapper hardcoded "carrier":"direct-awg" and ignored the key, so an http3-connect-udp config would have STARTED and silently run plain UDP -- a downgrade of the outer transport that no winn/3 version gate watches. Both layers now refuse: WINS_WINN_SUPPORTED_CARRIER in the wrapper, WinsTunnelConfig.supportedWinnCarrier + code 1506 in Swift
- [x] Runtime verification against the REAL Go archive -- tools/verify_apple_winn_seam.sh, 75 checks, committed so it is reproducible -- the previous lane's harness was not kept and had to be rebuilt from scratch
- [ ] Stage a Winn artifact into the PacketTunnel appex -- NOT DONE. winn_packet_engine is an OPTIONAL component and apple/EngineArtifacts/{ios,macos}/ carry no libWinsWinnPacketEngine.dylib. Until one is staged a winn/3 start fails closed at component load
- [ ] Turn iOS/macOS on in kWinnHostCapabilities -- NOT DONE, deliberately. That table is the first anti-downgrade gate and the governance surface; flipping it needs the artifact above plus an owner decision, and it would require editing six guard-rail tests

**BLOCKED:** owner: (1) whether to stage a Winn engine artifact into the shipping appex, (2) whether to flip kWinnHostCapabilities ios/macos to present. Also: the checked-in datapath archives are stale (see notes) and iphonesimulator has no archive at all.

**Verified by real command output:**
- tools/verify_apple_winn_seam.sh: 75/75 checks. Links the REAL apple/WinsTunnelCore Swift host + the REAL apple/EngineWrappers/WinsWinnPacketEngine.m + a FRESH libwinn-datapath-darwin-arm64.a built from the Go source in this tree, and drives WinsNativePacketTunnelEngine.start(). Only AmneziaWG is stubbed (wgTurnOn needs a utun that does not exist outside an appex); the stub captures the launch descriptor it was handed
- REAL DATAGRAMS THROUGH THE REAL GO ENGINE: a datagram sent to the seam reaches a fake gateway byte-identically; the gateway's reply comes back out of the seam port; 32 sequential datagrams arrive in order and unmodified; an unpinned second local sender never reaches the gateway
- ORDERING PROVEN, NOT ASSERTED: the AmneziaWG stub was handed endpoint=127.0.0.1:<seam port>, a string that cannot exist unless the seam was created, started and asked for its ephemeral port first. The real gateway 203.0.113.10 appears nowhere in the repointed UAPI, and every other UAPI line is byte-identical
- FAIL-CLOSED PROVEN 5 WAYS: max_datagram above the archive ceiling, pairwise-equal h1..h4, a gateway hostname, a portless endpoint, and an http3-connect-udp carrier each fail the WHOLE start -- and in every case the AmneziaWG stub records zero create calls and zero start calls, so there is no silent downgrade path
- teardown: stop() is idempotent, AmneziaWG is stopped and destroyed, and the seam port rebinds cleanly afterwards
- tools/verify_winn_abi_conformance.sh: passes, 5 slices, 2 real archives
- tools/verify_apple_tunnel_config.swift (run by tools/verify_apple_readiness.sh): passes, extended with 8 new Winn cases covering carrier selection, the /32, the UAPI repoint and validation codes 1502-1506
- swiftc -typecheck of WinsTunnelCore + ios/PacketTunnel/PacketTunnelProvider.swift: exit 0
- swiftc -typecheck of WinsTunnelCore + macos/PacketTunnel/PacketTunnelProvider.swift: exit 0
- clang -Wall -Wextra -Werror: WinsWinnPacketEngine.m compiles clean on all 5 slices with the cgo-generated header force-included (this is what verify_winn_abi_conformance.sh does)
- tools/build_apple_engine_wrappers.sh winn: produces libWinsWinnPacketEngine.dylib for macosx/arm64 and iphoneos/arm64, passing its own require_symbols gate including wins_winn_packet_engine_awg_seam_port. iphonesimulator produces nothing -- the datapath lane ships no simulator archive
- flutter analyze: No issues found!
- flutter test: 431 passing (baseline at session start was 419; the +12 is other lanes' new tests, not this one)
- both PacketTunnelProvider.swift files still byte-identical: md5 20a34f265b018090311f0541b398b1b0, unmodified

## What runs against the real Go archive, and what does not

**Against the REAL archive, on this machine, for real:** the whole Apple path from `WinsTunnelConfig` parsing through `WinsNativePacketTunnelEngine.start()`, the ObjC wrapper, the loopback seam, and the Go datapath relaying actual datagrams to and from a gateway socket. That is `tools/verify_apple_winn_seam.sh`, 75 checks, macOS/arm64.

**Compiled only, never executed:** every iOS slice, and the x86_64 and simulator slices of macOS. The wrapper compiles clean for all five and the ABI is proven to match, but no iOS binary has been run. iOS and macOS share `apple/WinsTunnelCore/` and `WinsWinnPacketEngine.m` in full, and the only `#if TARGET_OS_*` in the engine path is in the AmneziaWG wrapper (roaming), so the risk is small -- but it is not zero and it is not tested.

**Stubbed:** `wgTurnOn`. The AmneziaWG engine needs a utun device that only exists inside a NetworkExtension. What the harness proves is everything above that call, which is where all of this session's changes live.

**Can an iOS or macOS winn/3 session complete against a gateway today? NO, and for two reasons that are both outside this source:**

 1. `kWinnHostCapabilities` in `lib/winn_protocol_dispatch.dart` still marks ios and macos absent, so `resolveWinnProtocolStart` refuses and `winnSectionForTunnelConfig` throws. No Apple config ever carries a `[winn]` section. Every change in this session is therefore INERT for shipping builds.
 2. No Winn engine artifact is staged into the appex, so even with (1) flipped the component load would fail -- closed, with a clear message, but fail.

## THE CHECKED-IN DATAPATH ARCHIVES ARE STALE, AND ABI CONFORMANCE CANNOT SEE IT

`tools/winn_conformance_build_out/libwinn-datapath-{darwin,ios}-arm64.a` were built 2026-08-03T07:39, before `s1..s4` were added to `datapath.AWGHeaderTypes` (classify.go, 13:56). Their cgo-generated header is BYTE-IDENTICAL to a current one -- the C ABI genuinely did not change -- so `tools/verify_winn_abi_conformance.sh` passes against them while `WinnTunnelCreate` refuses every configuration the wrapper actually produces, with `json: unknown field "s1"`. Reproduced directly.

This is a whole class of failure that signature checking cannot catch, because `datapath.Config` decodes with `DisallowUnknownFields`. It cost this session an hour of chasing a phantom wrapper bug. Two consequences:

- Any Winn wrapper dylib built today from `tools/build_apple_engine_wrappers.sh` is linked against a stale archive and would refuse every real config. The archives must be rebuilt before anything is staged.
- `tools/verify_apple_winn_seam.sh` therefore builds its own archive from the Go source in the tree on every run, into a temp dir. A stale artifact cannot produce a false pass, and no other lane's build output is touched.

## The three anti-downgrade gates, on Apple

1. **Dart dispatch seam / capability table** -- untouched. ios and macos remain `absent`. Their `missing` strings WERE factually wrong after this session (they named `packetCarrierComponent` selecting Winn instead of AmneziaWG, which is exactly what was fixed) and have been corrected to name what actually remains: the unstaged artifact.
2. **`winnSectionForTunnelConfig`** -- untouched.
3. **The native gate** -- this is the one this session built on Apple. `WinsPacketTunnelEngine` throws on every seam failure and AmneziaWG is never created; `WinsPacketCarrier.all` no longer contains Winn so a Winn-only plan resolves to no tun owner; `validate()` refuses six config shapes; and the wrapper refuses any carrier other than `direct-awg`.

## The carrier gate is new and is not optional

This was not in the brief and was found by reading what the carrier lane landed mid-session. `lib/winn_protocol_dispatch.dart` now emits `carrier = <value>` into `[winn]` on EVERY winn/3 config. The Apple ABI can build `direct-awg` only -- `WinnTunnelCreate` takes a C string and every other carrier needs an authenticated profile that reaches Go through a separate document with no C export. Without the gate, an `http3-connect-udp` config would have started successfully and carried traffic over plain UDP, replacing a post-quantum authenticated outer transport with nothing. That is a downgrade of the TRANSPORT rather than of the protocol version, so none of the three version gates would have seen it.

The clean shape when Apple takes carriers is `WinnTunnelCreateWithCarrierProfile(configJSON, profilePath, udpFD, errorOut)`. It was deliberately NOT built. When it lands, `WINS_WINN_SUPPORTED_CARRIER` in the wrapper and `WinsTunnelConfig.supportedWinnCarrier` change together, and `tools/verify_apple_readiness.sh` has an anchor on each.

## Additive-only evidence

- Both `PacketTunnelProvider.swift` files unmodified and still byte-identical.
- No `.pbxproj`, entitlement, provisioning, or App Group change.
- No app version (`1.0.14+29`), application id, or signing change.
- An AmneziaWG-only config is bit-for-bit unaffected: `requiredEngineComponents` is still `[amneziawg_packet_engine]`, `transportEndpointHost` still falls back to the peer endpoint, `transportMode` is still `amneziawg`. Asserted in both harnesses.
- No key material generated or committed.

## What is still unproven

- No iOS or macOS device run, no simulator run, no `xcodebuild` of the PacketTunnel target (needs signing).
- No session against a real Winn gateway. The harness gateway is a UDP socket on loopback.
- The AmneziaWG engine has never actually been pointed at the seam in a real appex -- the stub proves it was HANDED the right UAPI, not that `wgTurnOn` accepts a loopback endpoint and roams correctly. On macOS `wgDisableSomeRoamingForBrokenMobileSemantics` is iOS-only, so macOS AWG can roam; the seam always replies from the pinned seam port so the endpoint should never move, but that is reasoning, not a measurement.
- `iphonesimulator` has no Winn archive, so there is no way to test any of this in a simulator today.


### windows
- [x] Drop the second WinTun adapter -- The old host loaded wintun.dll, created its OWN adapter (pool WinsVPNWinn, fixed GUID), assigned it an address/MTU/DNS, and TunToEngineThread framed raw IP packets off it as kInbound. That is the cleartext bug: the contract is AWG OUTER datagrams and datapath refuses payload:"ip-packet" precisely because forwarding tun packets would put cleartext on the wire. Every line of that is gone -- wintun.dll is no longer loaded by the Winn path at all. AmneziaWG (windows/awg_engine, which calls tun.CreateTUN itself) keeps the one and only adapter and keeps doing all of the cryptography.
- [x] The AWG-datagram seam -- BindWindowsWinnSeam opens a UDP socket bound to 127.0.0.1 (never the wildcard) with WSA_FLAG_NO_HANDLE_INHERIT -- the Windows spelling of the FD_CLOEXEC linux_winn_host.cc sets, and it matters because this service spawns helpers. RewriteAwgPeerEndpointToSeam rewrites the AmneziaWG peer Endpoint to it and refuses anything other than exactly one Endpoint line. Bound BEFORE the awg config is written: the port has to go into that file, and a bound socket queues AmneziaWG's first handshake initiations instead of drawing ICMP port-unreachable while the engine starts. Needs no protection - a loopback-bound socket has no route off the device.
- [x] Adopt the [winn] enabled schema -- The selector was `[winn] protocol = winn/3`. Case was never the issue; the KEY SET was. Windows read only `protocol` while Dart emits enabled/endpoint/carrier/max_datagram/session_id/h1..h4/s1..s4 and no `protocol` at all, so the two schemas shared ZERO keys and a real served config could never have selected the Winn path. WindowsConfigSelectsWinnProtocol now reads `[winn] enabled`, exactly as Android, Apple and Linux do. ParseWindowsWinnSection mirrors ParseLinuxWinnSection field for field, including the carrier gate FIRST and unknown-key-is-a-refusal.
- [x] A real datapath.Config, and the PrivateKey handoff removed -- The old create document was {"protocol","mtu","config"} with the ENTIRE INI -- PrivateKey included -- stuffed into "config". Only the test double could parse it; datapath.ParseConfig would have rejected it on the first unknown field. BuildWindowsWinnConfigJson now emits the real thing: contract/payload/carrier/gateway_endpoint/max_datagram/session_id/allow_own_socket/awg_header_types, in the same key order as WinnEngineConfig.toConfigJson and BuildLinuxWinnConfigJson so the four platforms' Create payloads can be diffed in review. There is no key-material-shaped field left for a key to cross in, and the harness asserts that.
- [x] winn added to the section allowlist -- ValidateRestrictedTunnelConfig rejected a [winn] section as 'an unknown or duplicate section' BEFORE the start path, which is why StartPrivilegedWinnTunnel was unreachable even for a caller that wanted it. The section now carries exactly the keys lib/winn_protocol_dispatch.dart emits, INCLUDING the eleven carrier-profile keys -- not because Windows can build a carrier, but so an http3-connect-udp config is refused by the carrier gate, which names the carrier, rather than by the allowlist, which would name whichever profile key came first. Same reasoning and same order as ParseLinuxWinnSection.
- [x] The elevated dispatch, treated as the security boundary it is -- DELIBERATE DEVIATION, and it needs a reviewer's eyes. No fourth opcode was added. The dispatch still carries exactly kStart/kStop/kStatus, and the Winn path is reached by InstallPrivilegedTunnel branching on `[winn] enabled` inside the EXISTING kStart, the way [xray] and [winsapp] are already handled. A new command would have been a new privileged entry point with its own role check, its own watchdog arming and its own phase transitions to get right; the branch inherits all three unchanged, including the kInstalledApp-only mutation rule and the elevated-admin status-only restriction. What did widen is what the boundary DOES and REPORTS: kStart can now start an engine subprocess, and kStatus gained winn=/winn_engine=/winn_transport= -- three booleans about this host's own observations, never the engine's status document, which names endpoints and crosses a pipe the elevated-admin role may read. The start watchdog budget gained kNormalWinnCriticalPathBudgetMilliseconds and a second static_assert so a winn/3 start cannot silently outlive the watchdog that is supposed to bound it.
- [x] Route promotion tightened -- Was: find the substring "up":true in the create acknowledgement. datapath/status.go says in as many words that Up is link liveness -- 'a socket exists' -- and that a host promoting on it is promoting on the strength of an open socket. It also names the correct gate: transport_observed_both_ways AND a recent host-AWG handshake, neither sufficient alone. Both halves are now required. WaitForAwgConvergence (unchanged, and already the stronger AWG gate) supplies the handshake plus nontrivial bidirectional transfer; WaitForWinnTransportConvergence supplies the engine's own transfer-proven signal, bounded at 5s because it runs AFTER the AWG gate has already passed and is a confirmation rather than a second convergence loop.
- [x] The /32 pin follows [winn] endpoint, not [Peer] Endpoint -- This is the Apple lane's hole, found on Windows before it could bite. PrepareWindowsAppExclusions resolved the carrier from [Xray] Host and then fell back to [Peer] Endpoint. On a winn/3 start the peer endpoint is 127.0.0.1:<seam>, so the pin would have been a loopback /32 and the engine's real outer socket would have been captured by the tunnel's own default route -- a dead loop. WindowsWinnCarrierHost is now consulted between the two. The Winn gateway may also legitimately differ from the AmneziaWG gateway, which is the second reason.
- [x] The carrier-seam collision resolved -- windows_winn_engine.cpp launched a bare image path with the comment 'The engine accepts no arguments.' That was true of the test double and false of cmd/winn-datapath, which already takes -transport, -udp-fd, -receive-fd and -carrier-profile, and which another lane had just given -carrier-profile PATH. The launch now passes `-transport stdio` -- the engine's own default, so nothing changes at runtime. It exists so the argv is a real argv and so adding `-carrier-profile <path>` is one token rather than a redesign, and the comment now says which flag would be added and what would have to be written first.
- [x] The create acknowledgement is checked, not assumed -- New, and not in the brief. StartWindowsWinnEngine refuses a CreateAck whose contract is not winn-datapath/1, whose payload is not awg-datagram, or whose carrier is not direct-awg. Three things fall out: an engine that silently opened a different payload mode or carrier is refused instead of carrying a session nobody negotiated; the host can never claim awg-datagram while something else is on the wire; and the TEST DOUBLE at windows/winn_engine/ is structurally rejected, because it emits no `contract` field at all. The engine is also located as winn-datapath.exe and NOT as winsvpn_winn_engine.exe, so the double cannot be reached by name either.
- [x] IsTunnelRunning no longer accepts AWG presence as proof -- Copied from the Linux lane's correction. On a winn/3 tunnel the AmneziaWG peer endpoint points at a loopback seam; if the engine behind it is gone the adapter is still up, still has routes, and every packet entering it dies silently. IsTunnelRunning returns false when g_winn_tunnel_active and the engine channel is down. WindowsWinnEngineRunning is channel liveness AND process liveness, never process existence alone.
- [ ] Windows arm64 C++ build -- STILL BLOCKED AT THE TOOLCHAIN, independently of every line above, and re-verified rather than inherited. VS 18 Community 14.51.36231 on the build box has bin\Hostx64\{x64,x86} and bin\HostArm64\arm64 -- there is no Hostx64\arm64 cross compiler. `vcvarsall x64_arm64` REPORTS SUCCESS and then resolves cl.exe to Hostx64\x64\cl.exe, which prints 'Version 19.51.36248 for x64'. Installing 'MSVC v14.x - VS 2026 C++ ARM64/ARM64EC build tools' fixes that half. The second half is unchanged: Flutter exposes no windows-arm64 target-platform for `flutter build windows`, so the app has no arm64 build path regardless of the compiler. The Go engine side of arm64 is fine; tools/build_winn_protocol_engine.sh datapath-windows-arm64 builds it today.
- [ ] kWinnHostCapabilities windows flipped to present -- DELIBERATELY NOT DONE. Both fields would have to name something real AND EXECUTED, and no winn/3 session has been carried on a real Windows machine. The seam, the engine subprocess and the framed exchange have been run there; the pinned /32, the peer rewrite reaching a live AWG runtime, and the promotion gate have not. The `missing` text was rewritten because leaving the old one would have been the same class of lie in the other direction -- it named three blockers that are now closed and would have sent the next lane to fix work that is already done. Two new tests pin that: one requires the entry to name execution as the gap and forbids the four retired claims by substring, one restates that a source-complete platform still may not fill in awgDatagramSeam or outerSocketExclusion.

**BLOCKED:** Two things, and they are different in kind. (1) EXECUTION of a full winn/3 tunnel, which needs a Windows box with administrator rights, the AmneziaWG payload (amneziawg.exe, awg.exe, winsvpn_awg_engine.exe, wintun.dll), the LocalSystem tunnel service installed, and a real AmneziaWG gateway. The SSH session on winpc lands in Session 0 as a non-elevated user, so none of the privileged path was reachable from here. That is the only thing standing between this lane and flipping windows on in kWinnHostCapabilities. (2) WINDOWS ARM64, blocked at the MSVC toolset and again at Flutter's target list; unrelated to Winn and not worked around.

**Verified by real command output:**
- REAL WINDOWS, REAL ENGINE, 46/46 CHECKS. tools/verify_windows_winn_seam.cpp built with MSVC 14.51.36231 under /W4 /WX and run on winpc (Windows 10.0.26200.8894, AMD64) against the REAL cmd/winn-datapath cross-compiled by tools/build_winn_protocol_engine.sh datapath-windows-amd64. It drives the SHIPPING host entry points in the order InstallPrivilegedTunnel calls them.
- The live half: 64 AmneziaWG-shaped transport datagrams sent into the seam by a stand-in AWG socket, 64/64 reached the stand-in gateway THROUGH the engine, 64/64 replies came back out of the seam. Engine status from the shipping WindowsWinnEngineStatusJson: transport_observed_both_ways=true, awg_classification=configured-h1h4, awg_prefix_padding_s1=16 s2=80 s3=16 s4=0, tx_transport_payload_datagrams=64, rx_transport_payload_datagrams=64, tx_rejected=0, rx_dropped=0, rx_oversize=0, rx_foreign_sender=0, socket_owned_by_engine=true, goos=windows goarch=amd64.
- PEER PINNING PROVEN NEGATIVELY: a second local UDP socket sending a well-formed transport datagram to the seam produced NO increase at the gateway. Only the pinned AmneziaWG socket can inject into the tunnel.
- The [winn] section under test was produced by the SHIPPING Dart gate resolveWinnProtocolStart executed on the real library, not hand-written.
- The Create document built on Windows by the shipping BuildWindowsWinnConfigJson: {"contract":"winn-datapath/1","payload":"awg-datagram","carrier":"direct-awg","gateway_endpoint":...,"max_datagram":1400,"session_id":...,"allow_own_socket":true,"awg_header_types":{h1..h4,s1..s4}}. Asserted to contain no PrivateKey and no "config" field.
- Refusals executed on Windows: http3-connect-udp carrier refused BY NAME with 'downgrade' in the message; unknown [winn] key refused; hostname gateway endpoint refused; partial h1..h4 refused; duplicate header types refused; a config with zero Endpoint lines refused rather than appended to; a config with two Endpoint lines refused.
- Teardown executed: StopWindowsWinnEngine joins both pumps and reaps the engine, WindowsWinnEngineRunning goes false, the status document goes empty, and the promotion gate answers FALSE rather than stale-true. The engine's kill-on-close job was also observed doing its job -- killing the harness left no winn-datapath.exe behind.
- winn_frame.h self-test PASSES natively on Windows (golden bytes, byte-at-a-time reassembly, 8 rejection cases).
- SERVICE TARGET compiles and links on MSVC 14.51.36231 under the project's exact /W4 /WX /EHsc /std:c++17 /D_HAS_EXCEPTIONS=0 flags: 4 TUs -> wins_vpn_tunnel_service.exe, 716,288 bytes, sha256 a64a275ac35e363836a3076dd47834bd85da46e0187e457e0b8dcb58402adbf5. Zero warnings.
- UI (non-WINS_TUNNEL_SERVICE_CORE) configuration of windows_winn_engine.cpp and windows_split_tunnel.cpp compiles clean under the same flags.
- The portable half of windows_winn_engine.cpp -- the whole INI/parse/JSON layer, with no winsock -- also compiles under clang++ -std=c++17 -Wall -Wextra -Werror -fno-exceptions on macOS, which is what makes it reviewable off a Windows machine.
- ARM64 BLOCK RE-VERIFIED BY EXECUTION, not inherited: `vcvarsall x64_arm64` exits 0 and then `where cl` returns bin\Hostx64\x64\cl.exe, which prints 'for x64'. bin\Hostx64 contains only x64 and x86.
- flutter analyze: No issues found. flutter test: 433 passing (baseline 431; this lane added 2). Go side: go vet ./... exit 0, go build ./... exit 0 in winn_protocol_experimental.
- App version untouched at 1.0.14+29; application id and signing config untouched. No credential, key or token was written to any file in this repository.

## What is proven by EXECUTION versus by COMPILATION, stated plainly

PROVEN BY EXECUTION, on the real Windows box: the loopback seam bind, the seam's peer pinning, the engine subprocess launch with its argv, the Create/CreateAck exchange against the REAL winn-datapath, the create-acknowledgement anti-downgrade checks, both datagram pumps moving AmneziaWG-shaped traffic in both directions, the engine's classification against the configured h1..h4/s1..s4 table, transport_observed_both_ways going true, the framing codec, and the full teardown including the kill-on-close job.

PROVEN BY COMPILATION ONLY: everything that needs administrator rights. The pinned /32 on the physical LUID (PrepareWindowsAppExclusions with WindowsWinnCarrierHost), the AmneziaWG config rewrite reaching a live AWG runtime and being caught by ValidateLoadedAwgRuntime's endpoint check, InstallWindowsTunnelRoutes promotion after the two-part gate, the kStatus winn fields crossing the manager pipe, and IsTunnelRunning's new engine-liveness requirement. All of it compiles and links; none of it has been run. It is UNVERIFIED, not "working".

NOT TESTED AT ALL, and worth naming: no AmneziaWG engine was involved anywhere. The harness stands in for it with a plain loopback UDP socket speaking AmneziaWG-SHAPED datagrams -- real header words at the real offsets, no Noise handshake and no encryption. That is legitimate for testing a seam whose entire job is to carry opaque outer datagrams, and it is NOT a substitute for watching a real awg.exe handshake through a rewritten peer endpoint.

## The dispatch decision a reviewer should look at first

The brief said to widen the elevated dispatch and to treat it as a security boundary. What was done was to widen what the boundary DOES without adding a fourth opcode: the Winn path rides the existing kStart, reached by a branch on `[winn] enabled` inside InstallPrivilegedTunnel, exactly as [xray] and [winsapp] already ride it. The argument is that a new command is a new privileged entry point that has to re-derive the caller-identity check (mutation is kInstalledApp-only), the elevated-admin status-only restriction, the cancellation-event handshake, the start watchdog and the phase machine -- five things the branch inherits correctly for free, and five places a new opcode could get one of them subtly wrong. If the reviewer disagrees, the change is contained: the branch is one `if` in InstallPrivilegedTunnel and the opcode enum is untouched.

What DID have to move for the boundary to stay honest is the watchdog budget. kNormalWinnCriticalPathBudgetMilliseconds is the AWG budget plus the engine CreateAck bound plus the transport-observed bound, and a second static_assert now requires the 150s start watchdog to fit the LONGER of the two paths rather than whichever one was written first. The margin is about 6 seconds, which is thin; that is why the transport gate is 5s and not 10s, and it is the first thing to look at if any component bound is ever raised.

## A Windows shutdown trap, found the hard way, and why the shipped pump avoids it

The first two versions of the harness's stand-in gateway hung on exit, every run, with all 46 checks passing and StopWindowsWinnEngine returning cleanly. Version one used SO_RCVTIMEO plus a polled stop flag; version two called closesocket() from the stopping thread to release the blocked recvfrom. Neither released the thread and the process sat in tasklist forever. Winsock does not promise that closesocket releases a blocking call pending on that socket, and a receive timeout is a timeout rather than a wakeup.

This is worth recording because the SHIPPED inbound pump does not have the problem: it waits on WSAEventSelect(FD_READ) plus an explicit quit event, and it joined on every single run including the ones where the harness hung beside it. The harness now uses the same mechanism, and the comment in it says why. Any future code in this tree that needs to stop a thread blocked on a socket should copy that pattern rather than reaching for closesocket.

## The test double is now unreachable, and its build script is stale

windows/winn_engine/main.go and tools/build_windows_winn_engine.sh build a TEST DOUBLE named winsvpn_winn_engine.exe. The host no longer looks for that name -- it looks for winn-datapath.exe -- and it would refuse the double anyway, because the double emits no `contract` field and the create-acknowledgement check requires winn-datapath/1. That is the correct outcome and it is deliberate. But it leaves a build script producing an artifact nothing consumes, and a reader could reasonably think it is still the engine. Deleting another lane's artifact was out of scope here; the double is still the second independent implementation of the WNN3 framing, which has real review value, so the decision is whether to keep it as a conformance fixture or retire it with its script.

**DECIDED (2026-08-04): kept as a framing conformance fixture, and it now earns
that.** Retiring it was clean on paper -- nothing outside documentation
referenced `winsvpn_winn_engine.exe`, no installer and no CI -- but it would have
thrown away the only independent implementation of the WNN3 layout. That matters
for a specific reason: a framing bug shared by the encoder and decoder of ONE
implementation is invisible to that implementation's own round-trip test. It
encodes wrongly, decodes its own wrong bytes back, and passes. Only a second
implementation written from the layout can catch it.

What changed so it is not mistakable for an engine:

- `windows/winn_engine/` is now `windows/winn_framing_fixture/`, module
  `winsvpn.local/winnframingfixture`. The artifact is
  `winn_framing_fixture_<arch>.exe`, never `winsvpn_winn_engine.exe`. The header
  says it is a fixture and not shippable, in the first sentence.
- `tools/build_windows_winn_engine.sh` builds the REAL engine for both arches via
  `tools/build_winn_protocol_engine.sh datapath-windows-{amd64,arm64}`, verifies
  PE machine type for the engine and not only the fixture, and labels the fixture
  "NOT the engine" in its own output.
- **New: `tools/verify_winn_framing_conformance.sh`.** It compiles
  `windows/runner/winn_frame_selftest.h` with `clang++ -std=c++17 -Wall -Wextra
  -Werror`, runs the fixture's `-selftest`, and diffs the vectors each side
  actually produces. It compares BYTES THEY EMIT, not each side's assertion that
  it matches a constant -- two implementations that each assert their own
  hardcoded vector still drift together when someone updates both. The build
  script runs it.
- It runs on a Mac. Both halves are deliberately platform-free, so this is the
  one layer of the Windows Winn lane that does not need real hardware.

**The host's two refusals were NOT touched.** `FindWinnDatapathExecutable`
resolves `winn-datapath.exe` alone; `StartWindowsWinnEngine` still requires
`"contract":"winn-datapath/1"`, which the fixture does not emit. Neither depends
on the fixture's name or path, so neither was affected by the rename. The in-band
`"engine":"winn-test-double"` identity is also deliberately unchanged.

**Verified:** conformance PASS in both directions; a deliberate one-byte version
perturbation makes it FAIL with exit 1 and a precise message, so the check can
actually fail; all four build artifacts pass machine-type checks;
`flutter analyze` clean; Dart suite 433.

**Also worth recording precisely: windows/arm64 is NOT uniformly blocked.** The
Go datapath engine cross-compiles to windows/arm64 today, verified above. What is
blocked is the MSVC C++ toolchain for the service and UI -- `vcvarsall x64_arm64`
exits 0 and then silently resolves `cl.exe` to `Hostx64\x64\cl.exe`, with no
`Hostx64\arm64` toolset present -- and Flutter, which has no windows-arm64
target. Stating it as "windows/arm64 is blocked" overstates it and would hide
the fact that one of the three components is already there.

## What the next lane actually has to do

One thing, and it is not code: run a winn/3 tunnel on a real Windows machine with administrator rights and a real AmneziaWG gateway, and watch four things. (1) That PrepareWindowsAppExclusions pins the /32 for the [winn] endpoint on the PHYSICAL LUID and that GetBestRoute2 still resolves to it after InstallWindowsTunnelRoutes promotes the /0s -- windows_split_tunnel.cpp already re-checks this at commit and refuses with 'The AWG/Xray carrier escaped its captured physical /32 route'. (2) That the running AWG runtime reports 127.0.0.1:<seam> as its peer endpoint, which ValidateLoadedAwgRuntime now demands and which is the proof the rewrite took effect. (3) That WaitForAwgConvergence and WaitForWinnTransportConvergence both pass, in that order, before any /0 exists. (4) That killing winn-datapath.exe mid-session makes IsTunnelRunning go false rather than leaving a tunnel that looks up and carries nothing. Only after that is flipping windows to WinnHostCapability.present honest, and the guard tests in test/winn_platform_dispatch will need the evidence map extended with the Windows file names.

## Lab material

tools/verify_windows_winn_seam.cpp and tools/verify_windows_winn_seam.ps1 are COMMITTED, unlike the previous Windows lane's harness, which was not kept and had to be rebuilt from scratch by two later lanes. The .conf the harness reads is generated rather than committed and carries no key material; the [winn] half of it must come from the shipping Dart gate. Build artifacts and the run logs live on winpc under C:\WinsVPNBuild\winnhost\ and nothing was written into the repository.

### conformance
- [x] Read WINN_PROTOCOL_PLATFORM_PLAN.md in full -- contract in section 2 and 8 non-negotiable rules read
- [x] Map existing artifact/claim surfaces (build_winn_protocol_engine.sh, cshared exports, lib/main.dart:8184-8225, other lanes' progress JSON) -- confirmed plan section-1 ground truth table accurate (6/6 files, exact line counts); confirmed apple lane's md5 claim accurate
- [x] Build conformance harness: artifact existence/size/filetype + 9-target Go build matrix + c-archive symbol export gate -- tools/winn_conformance_verify.py, 9 subcommands (build-matrix, ios-archive-gates, native-runtime-claims, symbols, ground-truth, scan-claims, apk-contents, baselines, diff-baselines, all). Iterated twice on scan-claims false positives (see notes) and added apk-contents after a real need for it surfaced.
- [x] Write guard test for the winn/3 refusal (TestTunnelIsNotAdvertised precedent) -- test/winn_protocol_refusal_guard_test.dart, source-anchor style matching test/smart_protocol_transport_policy_test.dart precedent (Dart privacy makes _startTunnelCandidate uncallable from test/); logic sanity-checked against 2 simulated flip scenarios offline before trusting it -- both correctly caught
- [x] Verify baselines: flutter analyze, flutter test (336), go test ./clientbinding/ -- run 5 times total across the session (336 pre-guard-test, 341 every time after); flutter analyze clean every time; go test clientbinding ok every time; zero flakes observed, so the isolation-rerun procedure for the known-flaky concurrency test was never triggered
- [x] Cross-check other lanes' progress claims against real repo state -- scan-claims mines all 5 lanes' JSON for path-like claims; every genuine claim resolved to a real file. Also independently compiled+ran the windows lane's portable framing code and inspected the real debug APK's contents (see notes) -- both went beyond text-matching into actually executing/opening the real artifacts.
- [x] Re-verify baselines at the end (concurrent edits from 4 lanes) -- Re-ran the full build-matrix + baselines after noticing tools/build_winn_protocol_engine.sh had changed size mid-session (6375 -> 11903 bytes, the datapath lane extending it). That re-run is what caught the ios-arm64 regression documented below -- direct vindication of why this step exists.

**Verified by real command output:**
- plan section 1 ground-truth file table re-verified independently: all 6 files exist with exact matching line counts (VpnTunnelService.kt=1382, both PacketTunnelProvider.swift=954, windows_tunnel_backend.cpp=3988, WinsAmneziaWGPacketEngine.m=191, windows/awg_engine/main.go=124), re-checked again at end (VpnTunnelService.kt grew additively to 1563, everything else unchanged -- consistent with rule 1)
- apple lane's md5 claim re-verified with a fresh `md5` run: ios and macos PacketTunnelProvider.swift both really are 20a34f265b018090311f0541b398b1b0
- FIRST full build-matrix pass (pre-datapath-script-edit): all 9 targets (windows-amd64/arm64, darwin-amd64/arm64, linux-amd64/arm64, android-arm64/amd64, ios-arm64) built via real `bash tools/build_winn_protocol_engine.sh` invocations, real exit 0, real non-zero-size artifacts, real `file`(1) type match per target; iOS c-archive independently passed lipo/nm(18 symbols, dynamically parsed from source)/vtool; native darwin-arm64 binary actually executed and its JSON claims verified true
- FINAL re-run of the build matrix (post-datapath-script-edit, see notes for the regression this caught): 8/9 targets still pass identically; ios-arm64 NOW FAILS for a real, reproduced reason -- see notes
- flutter analyze: 'No issues found!' -- 4 separate runs across the session, all clean
- flutter test: 336/336 before adding the guard test; 341/341 (336+5 new, 0 failing) in 4 subsequent runs including the final one -- no regression, no flake
- go test ./clientbinding/... in winn_protocol_experimental: ok, all 6 tests pass, checked twice (start and end)
- windows lane's portable framing code (winn_frame.h / winn_frame_selftest.h / the non-WINS_TUNNEL_SERVICE_CORE half of windows_winn_engine.cpp) independently compiled with `clang++ -std=c++17 -Wall -Wextra` on this Mac -- against their real, unmodified source via -I, nothing reimplemented -- and its own self-test plus 4 adversarial config-matching checks I added all PASS
- android lane's packaging claim independently re-verified by opening the real build/app/outputs/apk/debug/app-debug.apk (built 07:31, after the android lane's own 'done' report) with `unzip -l`: lib/arm64-v8a/libxray.so and lib/x86_64/libxray.so are really there; libwinnengine.so is really NOT there, exactly as android.json claims (it says staging was deliberately skipped)

## Harness (tools/winn_conformance_verify.py)

Subcommands: build-matrix, ios-archive-gates, native-runtime-claims, symbols, ground-truth, scan-claims, apk-contents, baselines, diff-baselines, all. Every check runs a real subprocess or a real filesystem/archive read -- see the module docstring for the anti-fabrication rationale. Build outputs: tools/winn_conformance_build_out/. Baseline snapshots: tools/winn_conformance_results/ (baseline_first_pass.json, baseline_final_pass.json, baseline_final_pass2.json).

## THE HEADLINE FINDING: a real regression in tools/build_winn_protocol_engine.sh, found by re-verifying at the end

This file is not mine to fix (only `tools/winn_conformance_*` is my file-ownership lane), so this is reported, not patched. Mid-session the script grew from 6375 to 11903 bytes -- the datapath lane adding real datapath-* targets (see below). Re-running my harness afterward (exactly the re-verify-at-the-end step) surfaced two real, reproduced problems:

**Bug 1 -- ios-arm64 (one of the plan's required nine targets) now builds the wrong package and silently ships zero C symbols.** Before the edit, `build_ios_archive()` built `./cshared` (the package with all 18 `//export`s). After the edit it builds `"${PACKAGE}"`, a variable whose top-level default is `PACKAGE="./cmd/winn-clientinfo"` -- a plain CLI tool with no `//export` directives at all. The script's own comment directly above that default reads: 'The clientinfo default preserves the original behaviour of every pre-existing target byte for byte' -- true for the 8 executable targets (which always used `./cmd/winn-clientinfo`), false for `build_ios_archive`, which used to hardcode `./cshared` and was refactored to inherit `${PACKAGE}` without anyone re-pointing it. Reproduced repeatedly, most recently seconds before writing this note:
```
$ bash tools/build_winn_protocol_engine.sh ios-arm64 <abs-path>.a
Missing exported symbols in <abs-path>.a: _WinnFacadeVersion _WinnProtocolVersion _WinnTunnelSupported _WinnTunnelBackendJSON _WinnFreeString
(exit 1)
```
All 5 required symbols missing, not some. The archive still links (valid Mach-O, arm64, IOS platform -- lipo/vtool pass), so a check that stopped at 'did it compile' would miss this; the nm-based export check is what catches it, exactly the gate the task specification named as load-bearing.

**Bug 2 -- the two new Apple datapath-archive targets (datapath-ios-arm64, datapath-archive-darwin-arm64) actually SUCCEED and then the script crashes anyway, exit 1.** Real output:
```
$ bash tools/build_winn_protocol_engine.sh datapath-ios-arm64 <abs-path>.a
Validated Apple c-archive: <abs-path>.a (arm64, IOS, C ABI present, header <abs-path>.h)
tools/build_winn_protocol_engine.sh: line 127: tmp: unbound variable
(exit 1)
```
The archive genuinely built correctly -- I independently confirmed with my own nm/lipo/vtool calls (not the script's echo): lipo -archs contains arm64, all 9 of the //export'd datapath symbols are present (_WinnTunnelCreate, _WinnTunnelWriteInbound, _WinnTunnelReadOutbound, _WinnTunnelStatusJSON, _WinnTunnelClose, _WinnTunnelContractVersion, _WinnTunnelProtocolVersion, _WinnTunnelMaxDatagram, _WinnTunnelFreeString), vtool reports platform IOS. Root cause: `validate_apple_archive()` sets `trap 'rm -rf "${tmp}"' RETURN` referencing its own `local tmp`; that trap is not function-scoped in bash, so it also re-fires when the CALLING function (build_ios_archive / build_macos_archive) itself returns, by which point `tmp` no longer exists -- `set -u` turns that into a hard error. Net effect: a caller checking only the exit code would wrongly conclude these two builds failed, when the artifact is actually correct. (My own probe with a RELATIVE output path also produced a misleading 'no output' error first, from `mkdir -p` + `cd "${MODULE_DIR}"` resolving a relative OUTPUT against the wrong directory after the internal cd -- that one is a caller-side mistake, not a script bug, and disappeared once I passed absolute paths the way this harness always does; noted here only so a future run doesn't rediscover the same false lead.)

Both bugs are almost certainly incidental side effects of extending the script to support the new datapath targets, not deliberate. Datapath's own progress file (see below) has not caught up to reflect any of this yet.

## datapath.json is very stale relative to real, substantial progress

As of this report, `.winn_platform_progress/datapath.json` still reads step 2/7 ('mapping in progress', nothing else started) and was never updated during this entire session. The actual filesystem tells a very different story: `winn_protocol_experimental/datapath/` (engine.go, config.go, socket.go, status.go + 4 test files), `winn_protocol_experimental/cdatapath/` (the C ABI surface, 9 //export'd symbols matching the plan's exact contract names WinnTunnelCreate/WriteInbound/ReadOutbound/StatusJSON/Close), `winn_protocol_experimental/cmd/winn-datapath/` (the subprocess entry point, with tests), and the build-script extension covering all of it, all exist and are substantial. This is the opposite failure mode from fabrication -- real work understated rather than fake work overstated -- but it has a real cost: apple.json's own WinnTunnel.h explicitly says it is 'PROVISIONAL... When _cgo_export.h lands, diff it against this file', and android.json says 'The Android side is ready whenever your framed duplex entry point lands' -- both are waiting on a handoff that datapath.json gives no sign has happened. Recording this precisely rather than acting on it, per this lane's brief.

Separately, and likely why nobody has caught the two bugs above yet: `cmd/winn-datapath/main.go` itself does not currently build for any target (`undefined: duplex.Hello`, cmd/winn-datapath/main.go:168) -- a real, independent, reproduced compile error in the subprocess entry point, on top of the two shared-script bugs above. Real output:
```
$ bash tools/build_winn_protocol_engine.sh datapath-darwin-arm64 <abs-path>
# winsvpn.local/winnprotocol/cmd/winn-datapath
cmd/winn-datapath/main.go:168:37: undefined: duplex.Hello
(exit 1)
```
Reproduced identically for datapath-windows-amd64 and datapath-android-arm64 as well, so this is not target-specific.

## scan-claims: iterated twice on false positives, final state fully explained

First run flagged Swift/Go dotted symbol names (`PacketTunnelProvider.startTunnel`, `com.apple.net.utun_control`, `tun.CreateTUN`) as if they were file paths -- fixed by requiring a real extension allowlist. Second issue: bare filenames cited without their directory (`windows_tunnel_backend.cpp` instead of `windows/runner/windows_tunnel_backend.cpp`) read as missing -- fixed with a basename fallback search (excludes .git/build/.artifacts/worktrees/etc). Third: a literal '...' elision in prose (`app/src/test/kotlin/.../Foo.kt`) matched the path character class -- fixed with an ellipsis guard. After all three fixes, the only remaining FAILs (6, stable across the last two runs) are all legitimate non-issues, each individually confirmed by hand: `libwg-go.a` / `libwinn-go.a` / `apple_engine_artifacts_manifest.json` are real build-OUTPUT filenames from tools/build_apple_engine_wrappers.sh and tools/stage_apple_engine_artifacts.sh mentioned in prose describing the existing/forthcoming mechanism, not claims that they exist in a clean checkout (grep-confirmed against the scripts that write them); `lib/x86_64/libxray.so` and `lib/arm64-v8a/libxray.so` (android.json) are paths INSIDE the built APK zip, not repo paths -- independently confirmed true via `unzip -l` on the real APK (see verified[]); `libwinnengine.so` (android.json) is explicitly described by android.json itself as NOT staged yet, on purpose -- also independently confirmed absent from the real APK. None of these are lanes claiming something untrue.

## Progress-file staleness pattern (informational)

Android and windows both showed a period mid-session where git diff showed substantial real file changes (VpnTunnelService.kt, windows/runner/CMakeLists.txt + new windows_winn_engine.{h,cpp}/winn_frame*.h) while their own progress.json still read 'no files modified yet'. Both later caught up and finished ('done' / 8-9 done respectively) with thorough, well-evidenced final reports. Spot-checked the new files in both cases while notes were stale (grep for TODO/FIXME/placeholder: none; content was real and substantial, not stubs) -- noting the lag as a characteristic of async checkpointing under this plan's structure, not a violation.

## Cross-lane note already flagged by android, worth relaying

android.json flags that Android's subprocess framing (HELLO/READY/INBOUND/OUTBOUND/STATUS_REQUEST/STATUS/SHUTDOWN/ERROR, 4-byte header) and Windows's (create/createAck/inbound/outbound/status/close/closeAck, per windows.json) are two independently-invented, semantically-equivalent but wire-incompatible framings, since plan section 2 fixes the API surface but not the byte layout. Android did not propose a contract change and this lane is not proposing one either -- relaying because whoever reconciles it against the datapath lane's actual delivered framing (winn_protocol_experimental/cdatapath, WinnTunnelCreate/WriteInbound/ReadOutbound/StatusJSON/Close) needs to know both exist.

## Scope discipline

No file outside this lane's ownership was edited. tools/build_winn_protocol_engine.sh's bugs were reproduced, diagnosed and reported, never patched. Files touched by this lane: tools/winn_conformance_verify.py (created), tools/winn_conformance_build_out/* (build outputs, created), tools/winn_conformance_results/*.json (baseline snapshots, created), test/winn_protocol_refusal_guard_test.dart (created), and this progress file.

### linux
- [x] StripSections must include winn -- linux/runner/linux_tunnel_backend.cc now strips {xray, winsdebug, winsapp, winsboost, winn}. Without it the [winn] section reaches validate_config's awk allowlist, which accepts only [interface] and [peer], and the start dies with exit 65. Stripping it is also what leaves exactly ONE Endpoint line for the seam rewrite to find, because the [winn] section carries an endpoint key of its own.
- [x] The AWG-datagram seam -- BindLinuxWinnSeam opens a UDP socket bound to 127.0.0.1 (never the wildcard) and RewriteAwgPeerEndpointToSeam rewrites the AmneziaWG peer Endpoint to it, refusing anything other than exactly one Endpoint line. Bound BEFORE the awg-quick config is written: the port has to go into that file, and a bound socket queues AmneziaWG's first handshake initiations instead of drawing ICMP port-unreachable while the engine starts. Needs no protection - a loopback-bound socket has no route off the device.
- [x] The outer-socket exclusion needs TWO mechanisms, not one -- CORRECTION TO THE PRIOR LANE'S BRIEF, found by execution. The brief said the exclusion is awg-quick's fwmark. A packet mark alone is NOT sufficient and the failure is silent in one direction only. AmneziaWG marks its OWN socket, so its first route lookup is already marked; this engine's socket cannot be (SO_MARK needs CAP_NET_ADMIN, the app is unprivileged), so the only available mark is an iptables one in mangle OUTPUT - which is too late. The kernel picks the SOURCE ADDRESS during the first, unmarked lookup, which resolves to `default dev winsvpn` and yields the TUNNEL address; re-routing after the mark changes the device but keeps that source. Observed directly: the gateway recorded 10.99.0.2:39724 (a tunnel-internal address) as the peer endpoint and every reply went somewhere it could never arrive from. The tunnel handshaked outbound and received nothing, forever. Fix: a host route for the gateway in awg-quick's own policy table via the pre-tunnel default, which corrects the first lookup itself - the ROUTE exclusion datapath/carrier.go:71-75 already names for the desktop model. The fwmark rules are still installed and still required, but for the KILL SWITCH, whose chain RETURNs on `-m mark --mark $ROUTING_MARK` and would otherwise REJECT the engine's own outer datagrams.
- [x] The recursion check, copied and then extended -- Copied from the Xray path at :1347-1352 as instructed, then extended after the source-address defect above. It now probes BOTH the unmarked and the marked lookup, and additionally refuses a source address that belongs to the tunnel interface. The unmarked probe is the one that matters and the one the original check lacked.
- [x] Native anti-downgrade gate -- A [winn] enabled=true config that cannot start the Winn path FAILS the start; there is no path in StartTunnel that proceeds without Winn once LinuxConfigSelectsWinnProtocol returns true. Missing engine binary, unbindable seam, un-rewritable Endpoint, failed privileged exclusion, and a rejected Create frame are all fail-closed. ParseLinuxWinnSection refuses an unknown [winn] key and refuses any carrier other than direct-awg, checked BEFORE the unknown-key sweep so a carrier config is refused by its real cause rather than by the first profile key.
- [x] IsTunnelRunning no longer accepts interface presence as proof -- On a winn/3 tunnel the AmneziaWG peer endpoint points at a loopback seam; if the engine behind it is gone the interface is still up, still has routes, and every packet entering it dies silently. IsTunnelRunning returns false when g_winn_tunnel_active and the engine channel is down. LinuxWinnEngineRunning is channel liveness, not process existence.
- [x] kWinnHostCapabilities linux flipped to present -- Only after both fields name something real and executed. Two new tests pin the claims: one requires every supported platform to name a real file for each claim, one pins the Linux claims to 127.0.0.1 / Endpoint / fwmark / allow_own_socket / ip route get. flutter test 431 passing (baseline 419), flutter analyze clean.
- [x] Frame codec shared, not forked -- linux_winn_host.cc includes windows/runner/winn_frame.h rather than reimplementing WNN3. That header is the normative reference the Go duplex package names in its own doc and pins byte-for-byte in TestGoldenFrameBytes; a second copy would be a second thing to drift. It is standard C++17 with no <windows.h>, which is why this is possible.

**Verified by real command output:**
- REAL END-TO-END winn/3 SESSION. Two containers plus a router, gateway one hop away so it is reachable only via the default route. ICMP 15/15 both ways, 0% loss. 4 MiB each way, SHA-256 digests IDENTICAL in both directions (client->gateway db06b15d70... == received db06b15d70...; gateway->client 5887667ed2... == received 5887667ed2...). Evidence: ~/.winn-e2e-lab/linuxhost/out/20260804T100013Z/
- Engine status from the shipping LinuxWinnEngineStatusJson: transport_observed_both_ways=true, handshake_response_observed=true, tx_handshake_initiations=1, rx_handshake_responses=1 (ONE handshake, completed), awg_classification=configured-h1h4, awg_prefix_padding_s1=32 s2=48, tx_rejected=0, rx_dropped=0, rx_oversize=0, rx_foreign_sender=0.
- Counters conserve across the boundary: engine tx_bytes 4625420 vs gateway rx 4625156 (delta 264 bytes, ~one datagram of sampling skew); engine tx_datagrams 4615, rx_datagrams 4326. Client AmneziaWG reports 'latest handshake: 19 seconds ago', 4.38 MiB received / 4.41 MiB sent, peer endpoint 127.0.0.1:36054 (the seam).
- SOURCE-ADDRESS CORRECTNESS PROVEN, not assumed: the gateway learned the peer's outer endpoint as 10.88.1.11:36623 - the client's PHYSICAL address - matching the engine's own local_endpoint port exactly. Before the route exclusion was added it learned 10.99.0.2:<port>, a tunnel-internal address.
- The recursion is REAL in this topology and demonstrated before it is fixed: `ip route get 10.88.2.10` returns `dev winsvpn table 51820 src 10.99.0.2`. After activate_winn_transport it returns `via 10.88.1.2 dev eth0 src 10.88.1.11`. After cleanup_winn_transport it reverts to `dev winsvpn`, proving the exclusion was the thing doing the work.
- The exclusion and its cleanup were executed from the SHIPPED SCRIPT TEXT, extracted verbatim from PrivilegedTunnelScript() by awk rather than retyped, so drift between what was tested and what ships is impossible by construction. activate_winn_transport exit 0; cleanup leaves zero winn iptables rules, zero state files, and no host route.
- The [winn] section was produced by the SHIPPING Dart gate winnSectionForTunnelConfig(operatingSystem: 'linux') executed on the real library, not hand-written: [winn] enabled/endpoint/carrier=direct-awg/max_datagram=1400/session_id/h1..h4/s1..s4.
- The host was compiled from linux/runner/linux_winn_host.cc unmodified, in-container, and drives the real winn-datapath built by tools/build_winn_protocol_engine.sh datapath-linux-arm64.
- linux_tunnel_backend.cc and linux_winn_host.cc both compile clean on Linux/arm64 with -Wall -Wextra against the real flutter_linux headers plus gtk+-3.0 and libsecret-1. Only pre-existing warning is the unique_ptr<FILE> attribute note at :279, untouched by this lane.
- flutter analyze: No issues found. flutter test: 431 passing (baseline before this lane: 419). go vet ./... exit 0, go test ./... no failures.
- App version untouched at 1.0.14+29; application id and signing config untouched; no Winn code in com.winsvpn.security; no key material generated outside ephemeral containers or written anywhere in the repo.

## What is proven by EXECUTION versus by COMPILATION

Proven by execution, on Linux/arm64 containers: the seam bind, the Endpoint rewrite, the Create/CreateAck exchange, both datagram pumps, the AmneziaWG handshake completing through the seam, 4 MiB of payload crossing in each direction with matching digests, the engine's classification and counters, the route exclusion, the recursion check, the mark rules, and the full cleanup. Also proven by execution: the shipping Dart gate emitting the [winn] section for linux.

Proven by COMPILATION only: the Flutter method-channel plumbing in linux_tunnel_backend.cc (StartTunnel's Winn block, RunPrivilegedTunnelCommand's $8 argument, StopTunnel, IsTunnelRunning) was compiled but not run inside a live Flutter app, because there is no Linux Flutter runtime on this host. The end-to-end driver calls the same linux_winn_host.cc entry points in the same order the backend calls them, so the host logic is exercised; what is untested by execution is the GTK-side wiring around it.

NOT tested at all, and worth naming: awg-quick itself was never invoked. The harness reproduces awg-quick's policy routing by hand (`ip route add default dev winsvpn table <T>`, `ip rule add not fwmark <M> table <T>`, `ip rule add table main suppress_prefixlength 0`) because awg-quick is not bundled in the lab. The exclusion discovers the table from the rule rather than assuming it, which is the part that had to be right, but a real awg-quick run on a real desktop is still owed. The kill switch was also not installed during the run; its interaction with the mark is argued from configure_kill_switch's own text (the `-m mark --mark $ROUTING_MARK -j RETURN` rule at the top of WINSVPN_KS), not observed.

PROCESS EXISTENCE IS NOT PROOF OF A WORKING TUNNEL. That is why LinuxWinnEngineRunning reports channel liveness rather than waitpid, why IsTunnelRunning refuses to call a winn/3 tunnel active when its engine channel is down, and why the evidence above leads with digests and transport_observed_both_ways rather than with 'the engine started'.

## Unbounded amplification when the exclusion is removed under a live engine

Observed accidentally and worth recording. An early harness ordering removed the exclusion while the engine was still running. The engine's outer datagrams immediately re-entered the tunnel, were re-encrypted, came back through the seam, and were sent again: 1,741,228 tx_datagrams and 1.03 GB in 30 seconds, against 4.59 MB actually reaching the gateway. There is no runtime rate limit on this loop and nothing detects it after start. The pre-start recursion check is the ONLY thing standing between a misconfigured start and that loop, which raises its importance considerably. A runtime guard - for instance refusing to forward when tx_datagrams outruns rx_datagrams by orders of magnitude - does not exist and is not proposed here, only flagged.

## Cross-lane interaction with the carrier work landing in lib/

While this lane ran, another lane added HTTP/3 carrier support to lib/winn_protocol_dispatch.dart: kWinnSupportedCarriers is now {direct-awg, http3-connect-udp}, and a carrier session emits eleven carrier-profile keys into the [winn] section. Because linux is now a supported platform, a winn/3 config naming http3-connect-udp will pass the Dart gate on Linux and then be refused NATIVELY by ParseLinuxWinnSection, which builds direct-awg only. That is fail-closed and never a downgrade, and the refusal message names the carrier as the cause rather than the first unrecognised profile key. But the refusal happens later and less gracefully than it would if the Dart layer knew Linux is direct-awg-only. Whoever owns the carrier lane should decide whether kWinnSupportedCarriers wants to become per-platform; this lane did not edit that lane's in-flight code.

## The include of windows/runner/winn_frame.h from linux/

Deliberate and commented in both files, but it is an odd-looking dependency and a reviewer should know why it exists rather than assume it is an accident. The header is the normative WNN3 reference implementation, named as such by the Go duplex package's own doc, standard C++17 with no <windows.h>, and byte-pinned against Go by TestGoldenFrameBytes. Sharing it means Linux cannot drift from the wire format; copying it would have created a second codec to keep in sync. If it is ever moved to a neutral directory, both includes and linux/runner/CMakeLists.txt's cxx_std_17 requirement move with it.

## Lab material

All lab keys were generated inside ephemeral containers and never written into the repository. The harness, the driver and the evidence live in ~/.winn-e2e-lab/linuxhost/ (run_linux_winn_e2e.sh, winn_linux_host_e2e.cc, emit_winn_config.dart, out/<timestamp>/). amneziawg-go and the awg CLI were built for linux/arm64 from the pinned upstream repositories because the lab's existing binaries are amd64-only and, under amd64 emulation on this host, FIB-rule netlink returns EOPNOTSUPP - `ip rule` does not work at all, so awg-quick's entire `not fwmark` mechanism cannot be exercised there. The run is native arm64 for that reason.
<!-- END:LIVE_PROGRESS -->

---

## DECIDED 2026-08-04: staged Winn engine binaries are NOT tracked in git

**Decision: ignore them.** `.gitignore` now carries
`/android/app/src/debug/jniLibs/**/libwinnengine.so`, covering the arm64-v8a
(9.1 MB) and x86_64 (9.9 MB) artifacts staged by
`android/tools/prepare_android_winn_assets.sh --stage`.

### The precedent looked mixed and is not

`libxray.so` is tracked at 36 MB and 38 MB, which reads as a precedent for
committing a large native binary here. It is not the same case.

**Xray's source is not in this repository.** The only Xray trees on disk are
build scratch under `.artifacts/`, which is itself ignored. So the committed
binary is the *only* copy, and tracking it is what makes the build reproducible
from a clean checkout. It is a **vendored dependency**.

`libwinnengine.so` is built from `winn_protocol_experimental/`, which **is** in
this repository -- `tools/build_winn_protocol_engine.sh` sets
`MODULE_DIR="${PROJECT_ROOT}/winn_protocol_experimental"`. It is a **derived
artifact** of source sitting beside it, rebuildable in about a minute given Go
and the NDK (auto-discovered at `~/.local/android-sdk/ndk`).

Vendored dependency: track it. Derived artifact of in-repo source: do not.

### The failure mode is not hypothetical -- it fired today

Committing a build output of in-repo source creates a staleness trap where the
binary and the source silently disagree. On **2026-08-04** exactly that happened
with the checked-in Apple archives:

`tools/winn_conformance_build_out/libwinn-datapath-{darwin,ios}-arm64.a` were
built at **07:39**. `s1..s4` were added to `datapath.AWGHeaderTypes` at **13:56**.
The cgo header was **byte-identical**, because the C ABI genuinely did not
change -- so `verify_winn_abi_conformance.sh` **passed**, while `WinnTunnelCreate`
refused every config the wrapper produced with `json: unknown field "s1"`.

**Signature checking structurally cannot catch this**, because `datapath.Config`
decodes with `DisallowUnknownFields`: the ABI is stable while the accepted
document changes underneath it. A tracked binary that silently disagrees with
the source beside it is worse than no binary, because it passes the check that
was supposed to protect you.

### Secondary reason

Every rebuild is a new ~19 MB blob in history permanently. This repository was
**1.5 GB** and required a `git filter-repo` rewrite to remove 190 MB of images;
adding a routinely-regenerated 19 MB artifact runs the same problem again on
purpose.

### What this does not change

- **`libxray.so` stays tracked.** Verified after the rule landed: still 2 files
  under `android/app/src/main/jniLibs/`, and `git check-ignore` does not match
  them.
- **The binaries stay in the DEBUG source set.** Item D2 defers the release
  variant while `1.0.14+29` is in store review. They were not moved to
  `src/main`, and `prepare_android_winn_assets.sh` warns if a copy appears there.
- **Nothing was committed.** The rule and this record are working-tree changes.

### Consequence for anyone building

A clean checkout has no engine binary and a `winn/3` start **fails closed** at
`resolveEngineExecutable()` -- which is correct behaviour, not a regression. Run:

```
bash android/tools/prepare_android_winn_assets.sh --stage
```

`--check` is the default and writes nothing.
