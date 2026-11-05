const Duration androidBatteryExemptionPromptCooldown = Duration(days: 7);

bool shouldEvaluateAndroidBatteryExemption({
  required String operatingSystem,
  required bool privacyConsentGranted,
  required bool tunnelCommitted,
  required bool requestedThisSession,
}) {
  return operatingSystem == 'android' &&
      privacyConsentGranted &&
      tunnelCommitted &&
      !requestedThisSession;
}

bool isAndroidBatteryExemptionPromptOnCooldown({
  required DateTime now,
  required DateTime promptedAt,
  Duration cooldown = androidBatteryExemptionPromptCooldown,
}) {
  // A future timestamp is treated as still cooling down. This fails closed if
  // the device clock moves backwards instead of showing repeated system UI.
  return now.toUtc().difference(promptedAt.toUtc()) < cooldown;
}

/// Precedence between Android Always-on VPN and the battery-optimisation
/// exemption prompt.
///
/// Android's Always-on VPN holds the tunnel's service connection itself and
/// re-establishes it after a drop inside the system VPN service, so the tunnel
/// does not depend on the app process staying awake in the background. A
/// battery-optimisation exemption (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`) is
/// a separate, one-time system prompt that stops Doze restricting the app's
/// background work.
///
/// When Always-on is already armed its own mechanism already covers tunnel
/// liveness, so it takes precedence: the intrusive exemption prompt is
/// redundant and must be suppressed. The exemption is only still warranted
/// (returns true) when Always-on is NOT armed.
bool shouldRequestBatteryExemptionGivenAlwaysOn({required bool alwaysOnArmed}) {
  return !alwaysOnArmed;
}

/// Round-trips the exemption decision against the real device record.
///
/// Android's `dumpsys deviceidle whitelist` lists a user-granted battery
/// optimisation exemption as a comma line `user,<package>,<uid>`, distinct
/// from the `system,` and `system-excidle,` entries it also emits. This
/// reports whether [packageName] is actually present as such a user entry, so
/// a policy decision ("grant the exemption") can be confirmed to have landed
/// rather than assumed.
bool isAndroidPackageBatteryExempt({
  required String packageName,
  required String deviceIdleWhitelistOutput,
}) {
  for (final line in deviceIdleWhitelistOutput.split('\n')) {
    final fields = line.split(',');
    if (fields.length >= 2 &&
        fields.first == 'user' &&
        fields[1] == packageName) {
      return true;
    }
  }
  return false;
}
