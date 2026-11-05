# Win's VPN Google Play phone/tablet package

Last reviewed: 2026-08-25

This folder is phone/tablet store metadata for the Google Play form factor of
`org.winsvpn.app` version `1.0.16+33` (phone `versionCode` 33). It contains
no credentials, keystores, upload tokens, account numbers, or node addresses.

TV Play metadata lives in `app_store/android/tv/`. Wear OS is a separate
package under `app_store/android/wear/` and must not inherit these receipts.
Play Console copy for Data safety, `VpnService`, foreground-service, and
`QUERY_ALL_PACKAGES` remains in `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`.
Do not treat this folder as Play Console graphics approval.

Authoritative phone/TV producers:

- `tools/verify_android_aab_signers.py`
- `tools/build_android_release_macos.sh`

The production Play upload is the phone/tablet AAB
(`android-phone-tablet-aab`). The phone APK is sidecar-only and is not the
production upload. Native Winn v3 is primary. Winn v1 AWG fallback is the
compatibility path after a served Winn v3 attempt. Those two engines
(`libwinnengine.so` and `libam-go.so`) must ship in this form factor.
Android refuses Xray mode, so `libxray.so` is excluded from packaging and must
not ship.

The installed application label stays `Calculator`. The Play listing name is
`Win's VPN`. Play what's-new copy is `metadata/en-US/whats_new.txt`.
Screenshots and other listing graphics remain owner-blocked.

`submission_approved` and `upload_authorized` stay false until the owner
approves a current signed phone AAB receipt. `QUERY_ALL_PACKAGES` stays
`PENDING` until Play Console shows `Approved`. This package never uploads.
