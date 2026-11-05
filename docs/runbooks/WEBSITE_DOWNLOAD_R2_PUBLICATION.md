# Website desktop download publication (R2 behind the manifest gate)

Owner ruling 2026-10-25 "Build it properly": large desktop artifacts are hosted
in Cloudflare R2 and served only through the Worker's manifest gate, one
manifest entry per architecture, Windows ships under a recorded owner waiver
labelled "Unsigned", Apple stays `store_pending`, and a producer writes the
receipts the gates demand. This runbook is for the deploy lane after the GPT-6
Sol and Gemini 4 Argon reviews clear. It needs Cloudflare access that this
repository never stores; no step below reads or writes credentials into files.

## What ships for 1.0.16+33

| Entry | Published name | SHA-256 | Bytes | R2 object key |
|---|---|---|---|---|
| windows-x64 (Unsigned) | `WinsVPN-UNSIGNED-LOCAL-Setup.exe` | `5331fbbfa293db2bab752baab6b8feeebddbbdaaf6f948b88e8b505f1c701b70` | 69474102 | `downloads/sha256/5331fbbfa293db2bab752baab6b8feeebddbbdaaf6f948b88e8b505f1c701b70` |
| windows-arm64 (Unsigned) | `WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe` | `a1c76d0384eec22aad9122164dfef39d1a8df63dbbca26ab241f8c4a3253fc32` | 53622614 | `downloads/sha256/a1c76d0384eec22aad9122164dfef39d1a8df63dbbca26ab241f8c4a3253fc32` |
| linux-x64 | `wins-vpn-linux-x64.tar.gz` | `fb99581f11a937ea4dfdb2bf0471016ed59ecb7dafa9bf0ea898f8ee2c1a5077` | 47232916 | `downloads/sha256/fb99581f11a937ea4dfdb2bf0471016ed59ecb7dafa9bf0ea898f8ee2c1a5077` |
| linux-arm64 | `wins-vpn-linux-arm64.tar.gz` | `5ee1bb936d9becef2024e1a1ac8e0fc7b878ecafeb224c035c47bfb4958e557a` | 44550864 | `downloads/sha256/5ee1bb936d9becef2024e1a1ac8e0fc7b878ecafeb224c035c47bfb4958e557a` |

Android stays `verification_pending` (no direct APK). macOS and iOS stay
`store_pending`. The keys come from the manifest SHA-256, so a new build gets a
new key and an old object can never answer for a new manifest entry.

Evidence directories (landing cbb83b7, P5 desktop lane):

```text
E=/Users/owner/.podium/lanes/desktop21/evidence/final-cbb83b7
$E/p5bcbb83b7/windows-x64
$E/p5cbb83b7/windows-arm64
$E/p5cbb83b7/linux-x64
$E/p5cbb83b7/linux-arm64
```

Signed Winn engine releases (source b556f47, tree f3d67b96):
`/Users/owner/.podium/lanes/engines21/winn/winn-release-windows` (manifest
`f12b93c7...`) and `/Users/owner/.podium/lanes/engines21/winn/winn-release-linux`
(manifest `21ef4f81...`). Owner rulings record:
`/Users/owner/xprize/winsvpnv3/.agent/debates/_decisions/owner_rulings_release_targets_20261021.md`.

## 0. Delivery mode for this release: pinned GitHub release (Workers Free)

Owner update 2026-10-25: the Cloudflare account is on the Workers Free plan
(10 ms CPU per request), so the R2 streaming path in sections 1 and 4 cannot
launch now; it stays in the code for a later release. For 1.0.16+33 the four
desktop binaries are assets of one pinned public GitHub release and the
manifest entries use delivery kind `github_release`:

```text
https://github.com/winsvpn/winsvpn-downloads/releases/download/v1.0.16-33/<filename>
```

- Tag `v1.0.16-33`, not `v1.0.16+33`: git accepts `+` in a tag
  (`git check-ref-format refs/tags/v1.0.16+33` exits 0), but `+` in a URL path
  is decoded as a space by some handlers and GitHub links then need `%2B`. The
  hyphen form has one unambiguous URL. Every gate pins this exact
  owner/repo/tag/filename; any other GitHub URL (v1.0.0, `latest`, `+33`,
  another repo or host) stays refused as backup-only.
- The buttons link straight to the pinned asset URL. The Worker does not
  redirect: `/downloads/<binary>` stays 404, so there is no redirect surface.
  The browser cannot fetch and hash a cross-origin GitHub asset (CSP
  `connect-src 'self'`, no CORS), so a click shows the expected SHA-256 and the
  `/downloads/<file>.sha256` link instead of verifying in the page; the live
  gate below fetches and verifies every GitHub asset.
- Receipts, `.sha256` sidecars, the waiver and the Cosign bundles stay on Pages.
- Prerequisite (met 2026-10-25): the rulings record holds the "Desktop
  download hosting" line naming `winsvpn/winsvpn-downloads`.
  `prepare --delivery github` refuses without it, and custody refuses GitHub
  entries whose (private, never uploaded) owner evidence does not quote it.

### GitHub release steps (replace sections 1, 4 and the R2 parts of 2, 3, 6)

1. Section 2 uses `--delivery github` in `prepare` (the rulings record
   now holds the "Desktop download hosting" line naming the repo).
2. Section 3 `stage` (from a clean Git checkout, output outside it). It refuses
   any untracked public file, copies, then runs the one-use final gate, which
   must print READY, and compares every staged byte with the gated source.
   With GitHub entries it writes `<stage dir>/github/` (the four binaries,
   `SHA256SUMS`, the two Linux `.sigstore.json` bundles),
   `<stage dir>/github-release-notes.md`, and the exact, shell-quoted
   `gh release create` command under `github_release.create` in
   `r2-upload-plan.json`. Inspect `<stage dir>/pages/releases/download-unsigned-waiver.json`:
   it carries only the label, notice and an opaque release-scoped reference,
   never ruling text or private record metadata. `releases/README.md` is also
   excluded from the Pages stage. Pages companion files are checked by the
   Worker with at most 64 KiB of SHA-256 each, well inside the Free plan CPU
   limit; no binary passes through the Worker in this mode.
3. Before creating the release, the coordinator enables release immutability
   in the public `winsvpn/winsvpn-downloads` repository (Settings > Releases;
   owner-approved 2026-10-25). It applies only to releases published after it
   is on, so check it and stop on anything else:

   ```sh
   set -e
   gh api repos/winsvpn/winsvpn-downloads/immutable-releases --jq '.enabled' | grep -qx true \
     || { echo "STOP: immutable releases are not enabled"; exit 1; }
   if gh release view v1.0.16-33 --repo winsvpn/winsvpn-downloads >/dev/null 2>&1 \
      || gh api repos/winsvpn/winsvpn-downloads/git/ref/tags/v1.0.16-33 >/dev/null 2>&1; then
     echo "STOP: release or tag v1.0.16-33 already exists"; exit 1
   fi
   ```

   (`GET /repos/{owner}/{repo}/immutable-releases` answers 200 with
   `"enabled": true` when on and 404 when off, so `gh api` fails closed.)
   Never replace assets or move the tag. Create the release (approval
   required; this lane did not run it):

   ```sh
   cd '<stage dir>/github'
   gh release create v1.0.16-33 --repo winsvpn/winsvpn-downloads \
     --title "Win's VPN 1.0.16+33 desktop" --notes-file ../github-release-notes.md \
     WinsVPN-UNSIGNED-LOCAL-Setup.exe WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe \
     wins-vpn-linux-x64.tar.gz wins-vpn-linux-arm64.tar.gz SHA256SUMS \
     wins-vpn-linux-x64.tar.gz.sigstore.json wins-vpn-linux-arm64.tar.gz.sigstore.json
   ```

   `gh` creates the tag on the default branch head if it is absent. Its
   automatic Latest choice is separate from these exact tag URLs. Asset names
   are plain ASCII, so GitHub does not rename them.
4. Verify before the Pages deploy:

   ```sh
   set -e
   GITHUB_STAGE_SUMS="$(pwd -P)/SHA256SUMS"  # current directory: <stage dir>/github
   gh release view v1.0.16-33 --repo winsvpn/winsvpn-downloads \
     --json isDraft,isImmutable,tagName,assets > release-check.json
   jq -e '.isDraft == false and .isImmutable == true and
     .tagName == "v1.0.16-33" and
     ([.assets[].name] | sort) == (["WinsVPN-UNSIGNED-LOCAL-Setup.exe",
       "WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe", "wins-vpn-linux-x64.tar.gz",
       "wins-vpn-linux-arm64.tar.gz", "SHA256SUMS",
       "wins-vpn-linux-x64.tar.gz.sigstore.json",
       "wins-vpn-linux-arm64.tar.gz.sigstore.json"] | sort)' release-check.json
   jq -r '.assets[] | [.name, .size] | @tsv' release-check.json  # sizes = table
   GHCHECK=$(mktemp -d) && cd "$GHCHECK"
   gh release download v1.0.16-33 --repo winsvpn/winsvpn-downloads
   printf '%s\n' \
     '5331fbbfa293db2bab752baab6b8feeebddbbdaaf6f948b88e8b505f1c701b70  WinsVPN-UNSIGNED-LOCAL-Setup.exe' \
     'a1c76d0384eec22aad9122164dfef39d1a8df63dbbca26ab241f8c4a3253fc32  WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe' \
     'fb99581f11a937ea4dfdb2bf0471016ed59ecb7dafa9bf0ea898f8ee2c1a5077  wins-vpn-linux-x64.tar.gz' \
     '5ee1bb936d9becef2024e1a1ac8e0fc7b878ecafeb224c035c47bfb4958e557a  wins-vpn-linux-arm64.tar.gz' \
     | shasum -a 256 -c -  # four OK lines against the reviewed hashes above
   cmp SHA256SUMS "$GITHUB_STAGE_SUMS"
   cosign verify-blob wins-vpn-linux-x64.tar.gz --key <repo>/linux/packaging/release-signing/cosign.pub \
     --bundle wins-vpn-linux-x64.tar.gz.sigstore.json --insecure-ignore-tlog
   cosign verify-blob wins-vpn-linux-arm64.tar.gz --key <repo>/linux/packaging/release-signing/cosign.pub \
     --bundle wins-vpn-linux-arm64.tar.gz.sigstore.json --insecure-ignore-tlog
   ```

5. Section 5 Pages deploy (no R2 binding or upload is needed).
6. After the deploy (the live gate also reads
   `api.github.com/repos/winsvpn/winsvpn-downloads/releases/tags/v1.0.16-33` and
   requires `immutable: true`, `draft: false`, exactly the seven asset names,
   and GitHub's asset digests and sizes equal to the four reviewed constants in
   `tools/public_website_download_live_gate.py`):

   ```sh
   python3 tools/public_website_download_live_gate.py --published-manifest '<stage dir>/pages/releases/downloads.json'
   ```

   It fetches `/`, `/releases/downloads.json` and each pinned asset (one
   redirect, only to `release-assets.githubusercontent.com` or
   `objects.githubusercontent.com`) and checks every byte count and SHA-256.
   PASS prints one "verified GitHub asset" line per binary.

### GitHub rollback

1. Pages first: roll back to the previous deployment (or deploy a stage of the
   committed pending tree). Every entry is pending again and the buttons are
   disabled.
2. Keep the immutable release and its tag for audit. Its assets cannot be
   replaced or removed after publication. If public access to the release
   itself must be revoked, obtain a separate destructive-action approval for
   deleting the release. Never reuse `v1.0.16-33` for different bytes.
3. Committed state: `web/releases/downloads.json` entries back to
   `verification_pending` (and `store_pending` for Apple) with null metadata,
   which is what the repository already holds.

## 1. One-time Cloudflare setup (R2 mode, later release; needs approval)

1. Confirm the Pages project `winsvpn` compatibility date is 2022-11-30 or
   later (Workers & Pages > winsvpn > Settings > Runtime). The Worker builds a
   `ReadableStream` and uses `crypto.DigestStream`; on an older date the R2 route
   answers 404 `r2-unverifiable` (fail closed), not unverified bytes.
2. Confirm the account runs Pages Functions on the Workers Paid plan (default
   30 s CPU per request). The Worker hashes every artifact while streaming it
   (about 70 MB of SHA-256 per Windows download). On Workers Free (10 ms CPU)
   each artifact GET would be cut off with error 1102: a failed download, never
   unverified bytes, but the launch would not work. Record the effective plan
   and CPU limit before uploading or deploying. If either cannot be confirmed,
   stop publication. A pages.dev GET after deploy is a validation check, not a
   substitute for this predeploy gate.
3. Create the private bucket:

   ```sh
   npx wrangler r2 bucket create winsvpn-website-downloads
   ```

   Do not enable the r2.dev public URL and do not attach a custom domain. The
   only reader is the Pages Worker binding.
4. Bind it to Pages (the live project does not read `web/wrangler.jsonc`):
   Workers & Pages > winsvpn > Settings > Bindings > Add > R2 bucket, variable
   name `DOWNLOADS_BUCKET`, bucket `winsvpn-website-downloads`, Production
   environment. Leave Preview unbound: previews then 404 every download. The
   binding takes effect on the next deployment (section 5).

## 2. Produce and gate (fresh clone, within 24 hours of deploy)

Receipts, owner evidence and the challenge must be younger than 24 hours when
the gate runs, and a PASS consumes the one-use challenge. Use a fresh clone of
the reviewed landing commit; rerunning the gate on the same tree refuses with
"already consumed" by design.

```sh
cd <fresh clone>
PY=python3.14
E=/Users/owner/.podium/lanes/desktop21/evidence/final-cbb83b7
$PY tools/website_download_publication.py challenge
$PY tools/website_download_publication.py prepare --delivery github \
  --evidence windows-x64=$E/p5bcbb83b7/windows-x64 \
  --evidence windows-arm64=$E/p5cbb83b7/windows-arm64 \
  --evidence linux-x64=$E/p5cbb83b7/linux-x64 \
  --evidence linux-arm64=$E/p5cbb83b7/linux-arm64 \
  --winn-release-windows /Users/owner/.podium/lanes/engines21/winn/winn-release-windows \
  --winn-release-linux /Users/owner/.podium/lanes/engines21/winn/winn-release-linux \
  --rulings /Users/owner/xprize/winsvpnv3/.agent/debates/_decisions/owner_rulings_release_targets_20261021.md
$PY tools/website_security_audit.py
```

Required: the audit prints `verdict PASS`. The stage command below runs the
one-use final gate after copying. It must print `READY` and report "available
windows-x64, windows-arm64, linux-x64, linux-arm64; not published
android=verification_pending, macos=store_pending, ios=store_pending".
Any other result stops the deploy.

## 3. Stage

```sh
# macOS only: set WINS_RELEASE_COSIGN to the digest-pinned Cosign 3.1.3 binary.
WINS_RELEASE_COSIGN=/Users/owner/.local/toolchains/cosign-v3.1.3/cosign-darwin-arm64 \
  $PY tools/website_download_publication.py stage --out <stage dir>
```

On Linux, run the stage command without the macOS environment assignment.
This checks the final gate once, refuses untracked public files, re-hashes each
available artifact, and writes it to
`<stage dir>/r2/downloads/sha256/<sha256>`, writes the Pages upload directory
`<stage dir>/pages` without the binaries, build tools, owner evidence,
challenge or replay journal, refuses any Pages file over 25 MiB, and writes
`<stage dir>/r2-upload-plan.json` with the exact commands below.

## 4. Upload the R2 objects (R2 mode only, before the Pages deploy)

Upload first, so the new manifest never points at a missing object (a missing
object is a 404, never other bytes). One command per object, from the plan:

```sh
npx wrangler r2 object put winsvpn-website-downloads/downloads/sha256/<sha256> \
  --remote --file '<stage dir>/r2/downloads/sha256/<sha256>' \
  --content-type application/octet-stream
```

Optional stronger upload: the S3-compatible API can store a SHA-256 checksum
(`aws s3api put-object --checksum-sha256 <base64>`); the Worker then also
refuses an object whose stored checksum disagrees before streaming. Verify each
upload by reading it back:

```sh
npx wrangler r2 object get winsvpn-website-downloads/downloads/sha256/<sha256> --remote --file /tmp/check.bin
shasum -a 256 /tmp/check.bin   # must print <sha256>
```

## 5. Deploy Pages

```sh
npx wrangler pages deploy '<stage dir>/pages' --project-name winsvpn --branch main
```

## 6. Verify live (canonical origin and the pages.dev mirror)

```sh
set -e
set -o pipefail
python3 tools/public_website_download_live_gate.py --published-manifest '<stage dir>/pages/releases/downloads.json'
for origin in https://winsvpn.org https://winsvpn.pages.dev; do
  for name in WinsVPN-UNSIGNED-LOCAL-Setup.exe WinsVPN-UNSIGNED-LOCAL-Setup-arm64.exe \
              wins-vpn-linux-x64.tar.gz wins-vpn-linux-arm64.tar.gz; do
    curl -fsSI "$origin/downloads/$name" | grep -iE '^(HTTP|content-length|x-wins-download-route|x-wins-download-sha256)'
    curl -fsS "$origin/downloads/$name" | shasum -a 256
  done
  curl -s -o /dev/null -w '%{http_code}\n' "$origin/downloads/WinsVPN-Setup.exe"            # 404
  curl -s -o /dev/null -w '%{http_code}\n' "$origin/downloads/wins-vpn-android.apk"         # 404
  curl -s -o /dev/null -w '%{http_code}\n' "$origin/downloads/wins-vpn-linux-x64.tar.gz.release.json"  # 200
done
```

Expected: HEAD `200`, `content-length` equal to the table, route
`r2-verified`, the table's SHA-256 in `x-wins-download-sha256` and from
`shasum`; the signed-name and APK paths 404. In a browser, the Download menu
shows "Windows x64 (Unsigned)", "Windows ARM64 (Unsigned)", "Linux x64",
"Linux ARM64", Android disabled, and the Apple entries "App Store release
pending". Then the browser extension submissions may proceed (owner ruling
"Wait for downloads").

## Rollback

1. Pages: Deployments > the previous production deployment > Rollback (or
   deploy a stage of the committed pending tree). The previous manifest marks
   nothing available, so the Worker 404s every `/downloads/*` path at once.
2. Faster kill switch without a deploy: remove the `DOWNLOADS_BUCKET` binding
   and redeploy; every artifact path answers 404 `r2-unavailable` while the
   receipts stay readable.
3. R2 objects may stay: without an available manifest entry no request can
   reach them. Delete them only on an explicit owner instruction.

## Durable release ledger

Every gate PASS first appends its challenge nonce, issuance ID, owner evidence
digest, per-entry nonces and artifact digests to
`/Users/owner/.winsvpn-release-ledger/download-custody-consumed.jsonl`
(directory 0700, file 0600, created on first use, outside every git work tree,
locked across check and fsync'd append). `prepare`, the gate and `stage`
refuse a challenge, issuance or nonce already in it, in any clone, and refuse
the ledger itself on any parse error, symlink, wrong mode or git work tree.
Keep the ledger: never edit or delete it. `WINS_RELEASE_LEDGER` overrides the
path for tests only; the deploy lane must not set it.

## Residual risks the deploy lane must keep in view

- The release ledger protects one machine and one account. A challenge copied
  to another machine is not covered; stage only on this Mac.

- The owner evidence and the waiver are procedural records produced from the
  ruling marker and the record's SHA-256; there is no owner signing key in
  this flow. The waiver's fixed public marker is public by design; the owner
  evidence and the source ruling lines are not uploaded.
- Windows ARM64 architecture is not measured from the installer bytes: the
  outer loader is x64 for both installers (Inno Setup 7.1.0 has no ARM64
  loader). It is bound to the build receipt's `windows-arm64-inno-unsigned`
  target and the producer's own payload PE-machine gate. The Windows Winn
  engines are bound to the producer log line, which is remote self-reported.
- Downloads are full-object only (no Range/resume), so an interrupted 69 MB
  download restarts. The browser path also verifies the SHA-256 before saving.
