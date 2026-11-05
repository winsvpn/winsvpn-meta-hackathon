# Phone/tablet Data safety

Package: `org.winsvpn.app`
Release: `1.0.16+33`
Phone versionCode: `30`
Privacy policy: https://www.winsvpn.org/privacy/

Play Console answers are in `docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md`.
Do not copy the Wear "no collection" answers onto this phone package.

Collected after privacy acceptance, for app functionality only:

- Device or other IDs (random per-install identifier, not ANDROID_ID)
- User IDs (account or free-access identity)
- Email address when provided for an account or support
- Approximate location (coarse public-IP scene; not device GPS)
- Purchase history metadata when an external purchase provisions the account
- App info (platform, version, model, locale, capability flags)
- Diagnostics only if the final Play SDK report proves collection

Not collected:

- Browsing history, DNS query history, traffic content, raw VPN traffic,
  destination activity

`QUERY_ALL_PACKAGES` is used only for the on-device split-tunnel picker.
Approval status remains `PENDING` until Play Console shows `Approved`.

Native Winn v3 primary and Winn v1 AWG fallback run on this
phone/tablet form factor.
