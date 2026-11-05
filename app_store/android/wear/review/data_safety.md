# Wear OS Data safety

Package: `org.winsvpn.app`
Release: `1.0.16+33`
Watch versionCode: `3001`
Privacy policy: https://www.winsvpn.org/privacy/

Do not copy the phone Data safety matrix onto the Wear form factor.

Wear OS answers:

- Data collected: no
- Data shared: no
- Off-device collection: no
- Account number or keys on the watch: no
- VPN traffic, DNS history, browsing history, or destination activity: not collected
- Approximate location: not collected by the watch
- Installed apps: not accessed
- Diagnostics: not collected by the watch

The watch exchanges connect/disconnect intent and opaque country labels with the
paired phone over the Wearable Data Layer. That path does not require INTERNET
and does not leave the watch/phone pair as a third-party collection.

Native Winn v3 primary and Winn v1 AWG then Xray fallback run on the paired
phone. Those engines are not packaged in the Wear AAB.
