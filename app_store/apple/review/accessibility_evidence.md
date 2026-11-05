# Apple Accessibility Evidence

Last reviewed: 2026-07-11

## Current App Store Connect State

- The signed-in App Accessibility page shows `Get Started` and no published
  accessibility declarations.
- The App Store Connect API returns zero accessibility declaration resources
  for Apple ID `6789417002`.
- Do not publish an accessibility nutrition-label claim solely from this file.
  A claim should describe the complete common workflow on both submitted
  platforms, not one passing widget or screen.

## Evidence In The Exact Candidate Source

- The activation screen renders without overlap at Flutter text scale `3.2`
  (320%) on an iPhone-sized viewport.
- `Activate Device`, `Try Free Server (100 Mbps upload and download)`, and the Apple-safe
  premium-access action expose semantic names.
- Both activation input controls expose text-field and focusable semantics.
- Empty activation provides written account-number and PIN guidance in
  addition to highlighted borders, so the error is not communicated by color
  alone.
- The offline map's approximate-region marker has a semantic label, and map
  open/close actions have visible tooltips.
- Native controls use standard Flutter buttons, text fields, checkboxes, radio
  controls, and list tiles where those controls appear.

Evidence command:

```bash
flutter test test/widget_test.dart
```

Relevant passing tests:

- `activation controls remain bounded at accessibility text sizes`
- `activation workflow exposes semantic names and control roles`
- `activation validation provides text guidance beyond color`

## Claims Not Yet Proven For Publication

- **VoiceOver:** The activation workflow has useful semantics, but the complete
  logged-in, connect, permission, settings, support, and disconnect workflows
  have not passed a manual VoiceOver audit on both iPhone and Mac.
- **Voice Control:** Standard controls have names, but the complete workflow has
  not passed physical voice-command testing.
- **Larger Text:** The activation screen passes at 320%, but every logged-in
  dashboard and modal state has not been verified at 200% or more.
- **Dark Interface:** The app uses a dark outer theme but intentionally renders
  light translucent operating surfaces; no adaptive dark-interface claim is
  made.
- **Differentiate Without Color Alone:** Activation errors pass this criterion,
  but every connection, server-health, and settings state has not been audited.
- **Sufficient Contrast:** No complete WCAG contrast measurement exists for all
  text/icon/background combinations and opacity states.
- **Reduced Motion:** Several transitions have fixed animation durations and do
  not yet have exact-candidate proof that Reduce Motion is honored everywhere.
- **Captions / Audio Descriptions:** The app has no customer-facing dialogue or
  video content in the current workflow, so these are not claimed.

## Release Rule

Leave all App Accessibility claims unpublished for build `34`. Adding missing
semantics, complete reduced-motion behavior, or other app-code changes requires
a new paired IPA/PKG build, new hashes, fresh runtime tests, screenshots where
visible behavior changes, Apple validation, and owner re-approval.
