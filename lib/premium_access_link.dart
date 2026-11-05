/// Owner ruling 2026-10-24 ("Home page everywhere"): in every build (Google
/// Play, App Store, direct Android APK, Windows, Linux, macOS, iOS) the
/// premium access button opens the website's home page in the external
/// browser. No anchor, no payment route, no build-specific target.
///
/// Pure Dart with no imports, so the target and label are testable on their
/// own and contain no payment or redemption wording (release gate S14A scans
/// Google Play bundles for that wording).
library;

/// The one target of the premium access button. Launched through the app's
/// HTTPS validator and native allowlist like every other external link.
const String kPremiumAccessHomePageUrl = 'https://www.winsvpn.org';

/// The button label in every build. The button opens an information page,
/// so it must not say "Buy" (it starts no purchase in the app).
const String kPremiumAccessActionLabel = 'Premium Access Info';

/// Shown when the browser could not be opened (no browser, as on some TV
/// devices, or the platform refused the launch).
const String kPremiumAccessOpenFailedMessage =
    "Could not open the Win's VPN website.";
