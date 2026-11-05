# Public download custody

GitHub is backup storage, not website publication authority for any platform.
Available downloads may be exposed only through an approved app store or a
locally verified direct artifact accepted by `tools/website_security_audit.py`,
`tools/website_download_custody.py`, and the final
`tools/verify_website_public_download_gate.py` publication-source gate.

The public download surface stays fail-closed for release `v1.0.16+33`
(`1.0.16+33`). The manifest schema is `winsvpn-download-manifest-v2` with one
entry per architecture (owner ruling 2026-10-25): `windows-x64`,
`windows-arm64`, `android`, `linux-x64`, `linux-arm64`, `macos`, `ios`.
Direct entries stay `verification_pending` and the App Store entries stay
`store_pending`, each with null URL, filename, hash, and byte count, until an
available entry binds all of the following:

- exact current release identity `1.0.16+33` and version `1.0.16`
- production package identity `org.winsvpn.app` (never `com.example.wins_vpn`)
- platform architecture inventory (`x64`/`arm64` for Windows and Linux
  installers, the current Android ABI set, and the current Apple sets)
- canonical target filename, byte count, and SHA-256
- reviewed signature identity (Android production upload certificate, Linux
  Cosign Sigstore bundle, or Windows WinVerifyTrust signer), or, for Windows
  only, the owner waiver below
- Winn v3 primary and Winn v1 AWG-then-Xray fallback provenance
- privacy receipt (`<artifact>.privacy.json`)
- release receipt (`<artifact>.release.json`)
- Winn provenance receipt (`<artifact>.winn.json`)
- publication receipt (`<artifact>.publication.json`)
- Windows WinVerifyTrust receipt (`<installer>.authenticode.json`) bound as
  `artifact.windows_verification`, or the unsigned owner waiver below

Each hosted receipt also carries one evidence object copied from the real
build records by `tools/website_download_publication.py`: the release-host or
real-inventory privacy scan (`scan`), the `BUILD_RECEIPT.json` identity
(`build`), and the signed Winn engine release (`engine_release`, measured inside
Linux tarballs, bound to the producer log line for Windows).

## Unsigned Windows owner waiver (1.0.16+33 only)

For this release only, the Windows x64 and ARM64 installers ship without
Authenticode under a recorded, release-scoped waiver. Such an entry uses the producer's
own unsigned filename (`WinsVPN-UNSIGNED-LOCAL-Setup.exe`,
`WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe`; never a signed-release name), sets
`signature.kind` to `unsigned_owner_waiver`, and carries
`unsigned_waiver: {label: "Unsigned", waiver_filename, waiver_sha256}` bound to
`download-unsigned-waiver.json`. That waiver is release-scoped and quotes the
recorded owner ruling with the ruling record's SHA-256. The Download button
reads "Windows x64 (Unsigned)" and explains the SmartScreen unknown-publisher
warning. Custody refuses the label if the PE carries a certificate table.

## Pinned GitHub release hosting (1.0.16+33)

Owner update 2026-10-25 (Workers Free plan): available desktop entries may use
delivery kind `github_release` with the exact URL
`https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/<filename>`.
Every receipt is still required and still hosted here, the local bytes are
still measured by custody, and the post-deploy live gate fetches each asset and
checks its size and SHA-256. Any other GitHub URL remains backup-only.

## Large-file hosting

Pages caps one asset at 25 MiB, so available direct artifacts are uploaded to
the private R2 bucket `winsvpn-website-downloads` under
`downloads/sha256/<sha256>` and the Worker serves `/downloads/<filename>` from
the `DOWNLOADS_BUCKET` binding only for entries the deployed manifest marks
available, after checking size and streaming the bytes through a SHA-256
check that withholds the last chunk on mismatch. Receipts and sidecars stay in
the Pages deployment. See `docs/runbooks/WEBSITE_DOWNLOAD_R2_PUBLICATION.md`.

GitHub release URLs, relative `/downloads/` paths, `/releases/latest/` routes,
date-stamped substitute filenames, unlabeled architecture artifacts, and
placeholder 302s are not publication authority for this release. Direct
binaries are published only at
`https://winsvpn.org/downloads/<canonical-filename>` after local gates accept
the exact bytes and hosted receipts. The Worker keeps `downloadRedirects`
empty and 404s `/downloads` until those same-origin bytes exist.

The previously published v1.0.0 Android digest
`89e8ba316dd2a041bde8d019fd407aebf6250a1840a73c98f053e0b6b4621d0f` is a
debug-signed `com.example.wins_vpn` APK. The v1.0.0 Windows digest
`25cfc27fabf67a937c52704fc3a288f105aa74d99cdd7a23e850389ef83261d3` is unsigned
installer evidence. Neither hash may be advertised.

A Windows PE certificate table proves only that a `WIN_CERTIFICATE` record is
present. It does not prove that the PKCS#7 is valid, that the file digest is
intact, that the signer is approved, or that the timestamp is trusted. A direct
Windows artifact therefore requires a Windows-generated receipt named
`<installer>.authenticode.json`. The exact receipt SHA-256 and approved signer
subject and certificate SHA-256 must be bound in the download manifest under
`artifact.windows_verification`. The receipt must report successful
WinVerifyTrust, a valid Authenticode status, the exact artifact filename, byte
count and SHA-256, the approved signer identity, and a verified trusted
timestamp. Cross-platform PE inspection alone always remains insufficient for
publication.

For direct binary links, the page fetches and verifies the complete byte count
and SHA-256 before starting a download. Missing WebCrypto, CSP or CORS blocking,
network errors, response errors, stream failures, size mismatches, and digest
mismatches all stop the download. There is no unverified fallback path.
Missing 1.0.16+33 identity, architecture, signature, Winn provenance, privacy,
release, publication, or WinVerifyTrust receipts keep every download option
unavailable. Browser fetches of direct artifacts use `redirect: "error"` so a
placeholder 302 cannot start an unverified download. CSP and the other
security headers in `web/_headers` and `web/_worker.js` must pin the current
inline script/style hashes with no redacted placeholder tokens.

## Final local publication gate

Run:

```sh
python3 -m unittest tools.test_verify_website_public_download_gate
python3 tools/verify_website_public_download_gate.py
```

The final gate checks the exact manifest and custody result together with all
deployable website and Netlify support sources. It rejects manifest-unbound
files, active download or store anchors not exactly authorized by the manifest,
hard-coded platform availability, GitHub or mutable-release placeholders,
download redirects, and route controls that expose pending bytes.

Exit `0` means `READY` and is possible only after exact current artifact
custody passes for every available entry; other entries may stay pending
(per-platform launch, owner ruling 2026-10-25). Exit `78` means `BLOCKED`: the website is
fail-closed, but owner-signed artifacts, accepted store URLs, or owner
publication evidence are absent. Exit `1` means `FAILED`; publication must stop.

After an owner-authorized website deployment, run
`python3 tools/public_website_download_live_gate.py --published-manifest
<gate-passed downloads.json>`. The canonical origin and
every mirror advertised by `web/index.html` must serve the current release
manifest and must not expose an artifact or store link that the manifest does
not authorize. A locally clean source tree does not override stale live bytes.
