# Linux final evidence collector

`tools/linux_final_evidence_collector.py` is release-test tooling. It does not
build or publish an application. Run it only after the Linux artifact and its
dependency-scoped build receipt are frozen.

## Safety boundary

The collector must run as root on the Linux test host. Its desktop driver must
be a regular executable, root-owned, executable, and not group/world writable.
Production collection additionally rejects every symlink/reparse component and
requires the installed driver and split canary to be byte-identical to the
repository sources. A copied script with different bytes is not accepted.
The collector passes arguments as an argv array; it never invokes a shell command
string. The driver may control the installed app and desktop, but it may not
create receipts. All receipt JSON and hashes are created by the collector from
Linux observations. Installed payload verification requires every archive
object to match in path, type, mode, bytes, and root UID/GID; byte-identical
but user-writable executables are rejected.

The driver remains root only for installation, firewall, interface, and
rollback work. It activates the real desktop user's AT-SPI bus and executes all
accessibility discovery/actions in a privilege-dropped helper with that user's
UID/GID and a minimal allowlisted session environment. Privileged release
tokens, SSH-agent paths, payment secrets, and unrelated root variables are not
forwarded into the app or tested installer. Root does not impersonate an
accessibility client on another user's bus. Before cleanup signals the
user-written split-canary PID, it verifies the file owner/mode, process UID,
installed canary command line, and exact cgroup claim.

Use a dedicated test host or console-accessible VM. The network-change action
can interrupt remote management. The driver must target only the named test
interface and must restore it before returning.

## Driver argv and JSON contract

Every successful response is exactly one JSON object with this common envelope:

```json
{
  "schema_version": 1,
  "contract": "winsvpn-linux-final-evidence-collector-v1",
  "action": "routes",
  "passed": true,
  "secret_material_redacted": true
}
```

The executable receives `--action ACTION` plus the arguments below. It must
return only the listed additional fields. Endpoint IPs, tokens, keys, account
identifiers, and raw Core/exit identifiers must never be logged.

| Action | Arguments | Additional result fields |
| --- | --- | --- |
| `routes` | none | `advertised_xray_routes`, each exactly `protocol=tcp`, integer `port`, and `security=none|tls` |
| `clean_install` | `--artifact PATH`, `--app-version`, `--build-number` | exact artifact SHA-256, app version/build, `clean_remove_passed`, `install_passed` |
| `connect` | `--kind`, `--port`, `--security` | echoed route, `forced_route`, `double_vpn_active`, SHA-256 digests of the observed Double VPN Core and exit identities |
| `disconnect` | none | no additional fields |
| `select_split` | none | `selection_applied` |
| `launch_split` | none | `launched`; the installed UI must launch the selected canary in the bypass cgroup |
| `network_change_begin` | `--interface NAME` | `change_triggered_by_harness`; return only after the named interface has materially changed |
| `network_change_restore` | `--interface NAME` | `restored` |
| `rollback_inject` | none | `failure_injected_by_harness` |
| `rollback_restore` | none | `restored` |
| `capture_map` | `--output PATH` | capture method/hash, 50-mile semantic result, distinct surrounding city labels, target-marker result, local-viewport result |
| `finalize` | none | `restored`; disconnects and restores the named interface, rollback bytes, user settings, canary launcher, and prior app-running state |

During the rollback test, the collector invokes `connect` after
`rollback_inject` and requires a nonzero process exit. A success response is a
hard failure. It then invokes `rollback_restore`, compares the full sanitized
network/control-state hash to the pre-injection hash, and requires a working
recovery connection.

For the network-change test, the collector hashes the named interface's kernel
link/address state before and after `network_change_begin` and requires the two
hashes to differ. It invokes `network_change_restore` and then independently
waits for a protected tunnel, DNS, egress, and leak state. A driver response by
itself is not accepted as proof of a real transition.

For a Double VPN connection, the driver reads non-empty Core and exit identity
from the active owner-only app configuration but returns only their SHA-256
digests. Raw identities never cross the driver protocol. Non-Double lanes must
return SHA-256 of the empty byte string. Linux qualification requires one
Double VPN direct-AWG lane and one Double VPN Xray lane for every advertised
port/security route; omitting any Double VPN backup route is a hard failure.
The compiler also requires direct, Xray, and Double lanes to report the same
privacy-preserving protected-egress digest, proving they retained the selected
exit rather than terminating at the Core hop or another route.

For `capture_map`, the driver must capture the actual Win's VPN window as PNG
and derive semantics from the same live window/accessibility tree. The collector
stores the screenshot and only the count of distinct city labels; city names are
not placed in the release receipt.

## Post-freeze invocation

Use a dedicated Xorg/X11 graphical test session. Install the exact in-repository
driver and its dependencies first:

```bash
sudo bash tools/install_linux_release_ui_driver.sh
```

The installer uses noninteractive package-manager settings that preserve the
current system configuration when an update asks whether to replace it. It
installs byte-identical root-owned mode-0755 copies at
`/usr/local/libexec/winsvpn-release-ui-driver.py` and
`/usr/local/libexec/winsvpn-release-split-canary.sh`, then runs the driver
self-test.

```bash
sudo python3 tools/linux_final_evidence_collector.py \
  --driver /usr/local/libexec/winsvpn-release-ui-driver.py \
  --artifact web/downloads/wins-vpn-linux-x64.tar.gz \
  --app-version 1.0.15 \
  --build-number 30 \
  --release-input-index .artifacts/release-inputs/RELEASE_INPUT_INDEX.json \
  --build-receipt .artifacts/build-receipts/linux.json \
  --network-interface eth0 \
  --output-dir .artifacts/linux-final/$(date -u +%Y%m%dT%H%M%SZ)
```

Run the same collector independently on an ARM64 Linux host using
`web/downloads/wins-vpn-linux-arm64.tar.gz`. An x64 receipt, synthetic ELF
fixture, cross-store source check, or emulated run is not ARM64 release
qualification.

The output directory must not already exist and must be under the repository
`.artifacts/` directory. The machine bundle records the exact current public
producer-contract SHA-256, which covers the collector, driver, installer,
canary, compiler, Linux assertion helpers, privacy/obfuscation validators, and
dependency-freeze verifier. Any change in that closure invalidates the raw
machine bundle before it can be recompiled. Then compile and consume it without
editing:

```bash
bash tools/linux_public_release_live_smoke.sh \
  web/downloads/wins-vpn-linux-x64.tar.gz \
  .artifacts/linux-final/RUN/linux-machine-evidence.json \
  .artifacts/linux-final/RUN/linux-map.png \
  .artifacts/release-inputs/RELEASE_INPUT_INDEX.json \
  .artifacts/build-receipts/linux.json
```

Any failed lane leaves publication locked. Do not repair a JSON receipt by hand;
restore the test host, start a new output directory, and rerun the full collector.

## Artifact, engine, custody, and signing preconditions

The collector is not a substitute for package production. Run it only against
an already-frozen candidate that the Linux producers and gates have already
refused or accepted:

- Native matching-architecture tarballs only:
  `web/downloads/wins-vpn-linux-x64.tar.gz` on an x86_64 Linux host and
  `web/downloads/wins-vpn-linux-arm64.tar.gz` on an ARM64 Linux host. Flutter
  3.47.6 still refuses Linux x64-host to ARM64-target builds. An x64 receipt,
  synthetic ELF fixture, WSL-emulated run, or cross-store source check is not
  ARM64 qualification.
- The candidate must contain the Winn Protocol v3 datapath (`winn-datapath`)
  as the primary engine plus the complete Winn v1 AWG/Xray fallback set
  (`awg`, `awg-quick`, `amneziawg-go`, `xray`), the privileged helper, and the
  browser native host. Every packaged ELF64 object, including
  `lib/libapp.so` and `lib/libflutter_linux_gtk.so`, must target that host's
  ELF machine. A mixed-architecture bundle is a hard refusal. Winn v1 over
  AWG then Xray is a required release capability only when the trusted served
  configuration selects that cover path; a failed Winn v3 security check is a
  connection refusal, not an implicit fallback. Snap and Flathub store recipes
  must install `winn3-descriptor-ring-attestation.json` from that same complete
  bundle; a recipe that omits it is incomplete local evidence.
- Obfuscation and private-symbol custody must already exist beside the
  candidate under
  `.artifacts/private-release-symbols/linux/{x64,arm64}/<version>+<build>/`
  with a verified `manifest.json` and `custody-manifest.json`. The collector
  does not create those files.
- Local-key signing preconditions are owner-held and outside this collector:
  Cosign 3.1.3 at `/usr/local/bin/cosign`,
  `WINS_LINUX_COSIGN_KEY`, `WINS_LINUX_COSIGN_PUBKEY`, and
  `WINS_LINUX_COSIGN_TRUST_ANCHOR=/etc/winsvpn/release-signing/cosign.pub`.
  The installer verifies only that root-owned trust-anchor route. This
  collector never signs, never uploads, and never treats an unsigned rehearsal
  archive as a publication receipt.
- Fail-closed receipts remain immutable owner-only files under `.artifacts/`.
  A missing, stale, unsigned, or architecture-mismatched build receipt,
  obfuscation receipt, or cross-store target receipt leaves publication
  locked. Do not hand-edit JSON to clear a red gate.

## Deliberate fail-closed platform limits

- Deterministic capture is supported only in an Xorg/X11 session. Generic
  Wayland capture requires compositor-specific portal authorization and cannot
  be guaranteed by a root CLI without an interactive desktop grant, so the
  driver stops instead of substituting a screenshot supplied by the caller.
  An Ubuntu 24.04 WSLg rehearsal confirmed the boundary: installed-app route
  discovery reported the expected `80:none` and `443:tls` matrix, but WSLg's
  AT-SPI desktop exposed zero applications, so the map action stopped and the
  finalizer restored state. That WSL run is tooling evidence, not Linux release
  qualification.
- Kernel port isolation can force an advertised TCP port, but cannot
  distinguish two security modes advertised on the same destination port. Such
  an ambiguous route set stops the run instead of claiming the requested mode.
- The Linux artifact embeds the semantic application version in AppStream
  metadata but has no separate embedded Flutter build-number field. Build
  number is therefore transitively bound by the immutable build receipt and
  artifact SHA-256; the driver does not pretend to discover it independently.
- Standard raster map tiles do not expose a machine-readable city feature
  layer. The driver requires the actual app accessibility marker/radius plus
  OCR-observed geographic labels from the captured window. Exact classification
  of every raster label as a city would require a release-app semantic layer or
  a separately frozen gazetteer, so this tooling does not make that stronger
  claim.
