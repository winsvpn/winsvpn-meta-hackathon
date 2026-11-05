# Flathub Submission Decision

Status: OWNER APPROVED 2026-08-31; COUNSEL REVIEW PENDING. This marking does not state or imply that counsel reviewed this decision.

Decision only. No Flathub submission, repository pull request, upload, or publication is authorized.

## Application ID

Adopt `org.winsvpn.WinsVPN` as the Flathub application ID. The former planned ID, `org.winsvpn.app`, is rejected because its final component is generic. As of 2026-08-31 the repository still emits the old ID: `linux/CMakeLists.txt` sets `APPLICATION_ID` to `org.winsvpn.app`, the committed packaging files are `linux/packaging/org.winsvpn.app.desktop` and `linux/packaging/org.winsvpn.app.metainfo.xml`, and `linux/packaging/flathub/manifest_artifact.py` still sets `APP_ID = "org.winsvpn.app"` with canonical artifact name `org.winsvpn.app.json`. `org.winsvpn.WinsVPN` is a decided target, not the current build identity.

Before packaging, update those files plus the Flatpak manifest, AppStream metainfo ID, desktop-file name, icon names, D-Bus names, Flutter Linux application ID, and persisted paths derived from the ID. Update every non-test producer that pins the old identity fail-closed: `tools/linux_cross_store_artifact_gate.py`, `linux/packaging/store_manifest_contract.py`, `tools/validate_release_artifact_privacy.py`, `tools/build_linux_release.sh`, `tools/build_linux_deb.sh`, and `tools/linux_release_ui_driver.py`. Update the manifest contract tests that pin the old artifact name.

Preserve an explicit migration from old local paths. Two pins of `org.winsvpn.app` are outside this rename: `kApplicationAttribute` in `linux/runner/linux_secure_store.cc` is a stored-credential attribute, so it requires a read-old-then-write-new migration before it can change; `package_identity` in `web/releases/download-custody.json` is a cross-platform custody field covering Windows, Android, Linux, macOS, and iOS. Do not rename Apple or Android bundle IDs as part of this decision.

## Privilege Boundary

Adopt a two-process boundary:

- `org.winsvpn.WinsVPN` is an unprivileged, sandboxed GUI. It receives only desktop display, audio if actually needed, network client access, and portal-mediated file or secret access. The Flatpak manifest generated today by `linux/packaging/flathub/manifest_artifact.py` requests `--socket=pulseaudio` and `--device=dri` unconditionally, so each must be dropped or justified before packaging, since this decision permits audio only if the final build actually needs it.
- A separately installed host service owns VPN interface, route, DNS, and firewall changes. It runs with the narrow privileges needed for those operations and is controlled through polkit.
- The service API is a closed, typed operation set for connect, disconnect, status, and cleanup. It accepts validated protocol fields and bounded values. It must not accept arbitrary shell commands, executable paths, filesystem paths, environment variables, or raw firewall scripts.
- The service authenticates the local caller, rejects unknown message versions and fields, uses a protected local IPC endpoint, and restores routes, DNS, firewall, and interfaces after failure.
- The Flatpak does not request host filesystem access, device-all, a full session or system bus, host command execution, or a sandbox escape.

The existing direct root-helper/native-tunnel packaging is not declared Flathub-ready. Packaging remains blocked until this service and its polkit policy are implemented and independently tested.

## Flathub AI Policy

Decision: **NO application for the mature-project AI-policy exception.**

Flathub's published requirements were live-verified on 2026-08-31 at `https://docs.flathub.org/docs/for-app-authors/requirements`. The current policy covers AI-assisted app code, content, and submission materials and permits only case-by-case mature-project exceptions. Because the owner chose not to request that exception, this repository must not submit Win's VPN to Flathub under the current policy. Recheck and record the published policy before any future Flathub path is opened. The application ID and privilege design remain prepared for a later policy-compliant path, but the submission status is **INELIGIBLE / HELD**, not ready.

## Reviewer Declaration for a Future Eligible Submission

> Win's VPN uses an unprivileged Flatpak GUI and a separately installed, polkit-controlled host service for VPN interface, route, DNS, and firewall operations. The IPC contract exposes only typed VPN lifecycle operations and does not accept arbitrary commands or paths. The Flatpak requests no host filesystem, device-all, full-bus, or host-command permission. `org.winsvpn.WinsVPN` is the final application ID. A submission must not proceed unless the host service, cleanup behavior, permission manifest, and Flathub AI-policy eligibility have been verified for the exact release.
