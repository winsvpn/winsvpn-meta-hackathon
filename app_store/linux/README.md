# Win's VPN Linux x64 package / Flathub / Snap

Last reviewed: 2026-08-31

Status: OWNER APPROVED; COUNSEL REVIEW PENDING. This does not state or imply
that counsel reviewed the Linux store decisions. No store action was taken.

This folder is Linux x64 store and distribution metadata for release
`1.0.17+34` (AppStream `1.0.17`, Debian `1.0.17-34`). It contains no
credentials, cosign keys, Sigstore tokens, account numbers, or node
addresses.

The production website/manual route is the native tarball, not a DEB
upload. Required website kinds are `wins-vpn-linux-x64.tar.gz` and
`wins-vpn-linux-arm64.tar.gz`. The Debian package
`wins-vpn_1.0.17-34_amd64.deb` is derived from the matching native
tarball and is not a separate cross-store upload target. AppImage identity
`wins-vpn-1.0.17-x86_64.AppImage` stays fail-closed and is not a
`1.0.17+34` upload target. The decided Flathub ID is
`org.winsvpn.WinsVPN`, but the in-tree build identity and generator remain
`org.winsvpn.app`; the typed host service is not implemented, and no AI-policy
exception will be requested. The decided Snap design uses strict confinement
with an authenticated root daemon, but the current generator still emits a
classic recipe. Both store paths remain held. This folder holds x64 listing copy. Native ARM64
tarball evidence remains `pending-owner-evidence` and is not satisfied by
an x64 tarball or amd64 deb.

Current owner state is `OWNER-BLOCKED: ABSENT` for the current signed x64
tarball and for Flathub and Snap listing copy, privacy, review, and
screenshots. The Linux release cosign key is owner-held; its public trust
anchor is committed at `linux/packaging/release-signing/cosign.pub` and
pinned by `tools/linux_cross_store_artifact_gate.py`. There is no current
signed `1.0.17+34` candidate. Flathub and Snap exact release
declarations stay `OWNER-BLOCKED: ABSENT`. Producer output paths are not
candidate bytes.

Authoritative Linux producers:

- `tools/build_linux_release.sh`
- `tools/build_linux_deb.sh`
- `tools/linux_cross_store_artifact_gate.py`
- `linux/packaging/flathub/manifest_artifact.py`
- `linux/packaging/snap/manifest_artifact.py`

Native Winn v3 is primary. Winn v1 AWG then Xray fallback is the ordered
compatibility path after a served Winn v3 attempt. Those engines and the
browser native messaging host must ship in the x64 tarball and the
derived amd64 deb.

Private Flutter split-debug symbols stay under
`.artifacts/private-release-symbols/linux/x64/1.0.17+34` with distinct
per-surface obfuscation receipts and are not uploaded.
`submission_approved` and `upload_authorized` stay false until the owner
supplies a current signed x64 receipt. This package never uploads.
