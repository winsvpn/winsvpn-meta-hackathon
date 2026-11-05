# Win's VPN Google Play Android TV package

Last reviewed: 2026-08-25

This folder is Android TV store metadata for the Google Play form factor of
`org.winsvpn.app` version `1.0.16+33` (TV `versionCode` 3302). It contains
no credentials, keystores, upload tokens, account numbers, or node addresses.

Phone Play metadata lives in `app_store/android/phone/`. Wear OS is a separate
package under `app_store/android/wear/` and must not inherit these receipts.
A phone/tablet AAB or a TV APK is not TV AAB evidence. Play Console copy for
Data safety, `VpnService`, foreground-service, and `QUERY_ALL_PACKAGES`
remains in `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`. Do not treat this
folder as Play Console graphics approval.

Authoritative phone/TV producers:

- `tools/verify_android_aab_signers.py`
- `tools/build_android_release_macos.sh`

TV is a Gradle product flavor of the same application ID (`LEANBACK_LAUNCHER`).
The required Play upload target is `android-tv-aab`. Native Winn v3 is
primary. Winn v1 AWG fallback is the compatibility path after a served Winn
v3 attempt. Those two engines (`libwinnengine.so` and `libam-go.so`) must ship
in this form factor. Android refuses Xray mode, so `libxray.so` is excluded
from packaging and must not ship.

The TV application label is `Win's VPN`. Calculator camouflage is disabled.
The TV overlay does not remove `QUERY_ALL_PACKAGES`. The TV UI exposes the
same per-app picker named `Exclude Apps From VPN (Split Tunneling)`. Play
what's-new copy is `metadata/en-US/whats_new.txt`. Screenshots and other
listing graphics remain owner-blocked.

`submission_approved` and `upload_authorized` stay false until the owner
approves a current signed TV AAB receipt. `QUERY_ALL_PACKAGES` stays
`PENDING` until Play Console shows `Approved`. This package never uploads.
