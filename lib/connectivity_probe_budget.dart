int tunnelConnectivityAttempts({
  required String platform,
  required bool isApplePlatform,
  required bool stealthActive,
}) {
  if (isApplePlatform) return 8;
  if (platform == 'android') return 3;
  if (platform == 'linux') return stealthActive ? 6 : 4;
  if (platform == 'windows') return stealthActive ? 3 : 2;
  return stealthActive ? 12 : 10;
}
