# Win's VPN Wear OS Play package

Last reviewed: 2026-08-25

This folder is Wear OS store metadata for the Google Play form factor of
`org.winsvpn.app` version `1.0.16+33` (watch `versionCode` 3301). It contains
no credentials, keystores, upload tokens, account numbers, or node addresses.

Phone and TV Play declarations remain in
`docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`. Do not copy the phone Data safety
matrix onto this Wear package. Do not treat this folder as Play Console
graphics approval.

Wear OS is a non-standalone companion. The watch does not request `INTERNET`,
does not host a `VpnService`, and does not carry account numbers or keys. Pairing
uses the Wearable Data Layer only. Native Winn v3 (primary) and Winn v1 AWG then
Xray fallback execute on the paired phone form factor of the same application
ID. A Wear AAB that packages those engines is not upload-ready.

Authoritative Wear producers:

- `wear_os/tools/prepare_release.sh`
- `wear_os/tools/create_signed_aab_receipt.py`
- `wear_os/tools/signed_aab_receipt.py`
- `wear_os/tools/assert_release_aab.py`

Play what's-new copy is `metadata/en-US/whats_new.txt`. Screenshots and other
listing graphics remain owner-blocked.

`submission_approved` and `upload_authorized` stay false until the owner
approves a current signed Wear AAB receipt. This package never uploads.
