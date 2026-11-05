// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appName => 'Win\'s VPN';

  @override
  String get appNameAnnouncement => 'Win\'s VPN Announcement';

  @override
  String get welcomeMessage =>
      'Welcome to Win\'s VPN! Thank you for helping yourself by using our services!!';

  @override
  String get secureConnectionEstablished => 'Secure Connection Established.';

  @override
  String get startingProtocol => 'Starting Winn Protocol®...';

  @override
  String get securingRoute => 'Securing VPN route...';

  @override
  String get finalizingRoute => 'Finalizing secure route...';

  @override
  String get trafficSecured => 'Traffic Secured & Obfuscated';

  @override
  String get disconnected => 'Disconnected';

  @override
  String get secured => 'SECURED';

  @override
  String get unprotected => 'UNPROTECTED';

  @override
  String get selectedProtocol => 'Selected Protocol:';

  @override
  String get status => 'Status:';

  @override
  String get referral => 'Referral';

  @override
  String get shareApp => 'Share Win\'s VPN';

  @override
  String get gate => 'Gate:';

  @override
  String get traffic => 'Traffic:';

  @override
  String get notConnected => 'Not connected';

  @override
  String get connecting => 'Connecting...';

  @override
  String get establishingRoute => 'Establishing secure route...';

  @override
  String get carryingTraffic => 'Carrying traffic';

  @override
  String get connectedNoLiveProbe => 'Connected, no live probe on this device';

  @override
  String get flowing => 'Flowing';

  @override
  String get idle => 'Idle';

  @override
  String get notAvailable => 'Not available';

  @override
  String get received => 'Received';

  @override
  String get sent => 'Sent';

  @override
  String get session => 'Session:';

  @override
  String get version1 => 'Version 1';

  @override
  String get version3 => 'Version 3';

  @override
  String get versionNotRecognised => 'Version not recognised by this app';

  @override
  String get directTransport => 'direct transport';

  @override
  String get stealthTransport => 'stealth transport';

  @override
  String get openSourceLicences => 'Open source licences';

  @override
  String get thirdPartyNotices =>
      'Notices for the software this app is built on';

  @override
  String get serverUnreachable => 'Server unreachable right now';

  @override
  String get notReachableFromDevice =>
      'Not reachable from this device right now';

  @override
  String get somethingWentWrong => 'Something went wrong';

  @override
  String get actionFailed =>
      'The app could not complete that action. Please try again later.';

  @override
  String get ok => 'OK';

  @override
  String get cancel => 'Cancel';

  @override
  String get close => 'Close';

  @override
  String get continueButton => 'Continue';

  @override
  String get goBack => 'Go Back';

  @override
  String get notNow => 'Not now';

  @override
  String get allow => 'Allow';

  @override
  String get deny => 'Deny';

  @override
  String get save => 'Save';

  @override
  String get refreshStatus => 'Refresh status';

  @override
  String get allowBackgroundVpn => 'Allow background VPN protection?';

  @override
  String get allowBackgroundVpnDetail =>
      'To keep Win\'s VPN connected when the screen is off or when your network changes, allow the app to run without battery optimization.';

  @override
  String get deleteAccount => 'Delete Account';

  @override
  String get deactivateDevice => 'Deactivate Device';

  @override
  String get cancelDeletion => 'Cancel Deletion';

  @override
  String get privacyPolicyAndLegalConsent => 'Privacy Policy and Legal Consent';

  @override
  String get openingShareOptions => 'Opening share options...';

  @override
  String get websiteLinkCopied => 'Win\'s VPN website link copied.';

  @override
  String get referralLinkCopied => 'Referral link copied.';

  @override
  String get planOneMonth => '1 Month Subscription';

  @override
  String get planOneYear => '1 Year Subscription';

  @override
  String get planOneTimeTenYears => 'One-Time Payment (10 Years)';

  @override
  String get planLifetimeTechSupport => 'Lifetime Access + Tech Support';

  @override
  String get planLifetimeNoTechSupport => 'Lifetime Access (No Tech Support)';

  @override
  String get generalDonation => 'Make a General Donation';

  @override
  String get premiumAutoRenews => 'Premium Auto-renews';

  @override
  String get standardAutoRenews => 'Standard Auto-renews';

  @override
  String get transportAutomatic => 'Automatic';

  @override
  String get transportDirectUdp => 'Direct (UDP) only';

  @override
  String get transportTcp => 'TCP only';

  @override
  String get featureDoubleVpn => 'Double VPN';

  @override
  String get featureSplitTunneling => 'Split Tunneling';

  @override
  String get installedAppAccess => 'Installed app access';

  @override
  String get referralInvite =>
      'Invite a friend and both accounts receive 20% extra VPN time after activation.';

  @override
  String get referralShareDetail =>
      'Share Win\'s VPN with friends. Paid referral bonuses are available after upgrading.';

  @override
  String get openWin => 'Open Win';

  @override
  String duressSmsWithLocation(String link) {
    return 'Safety alert: someone who listed you as an emergency contact may need help. Approx. location: $link';
  }

  @override
  String get duressSmsWithoutLocation =>
      'Safety alert: someone who listed you as an emergency contact may need help. Location not available.';

  @override
  String duressHumanMessageWithLocation(
      String lat, String lng, String link, String time) {
    return 'Automated safety alert: your contact may need help and asked you to be notified. Last known location: $lat, $lng ($link). Sent $time.';
  }

  @override
  String duressHumanMessageWithoutLocation(String time) {
    return 'Automated safety alert: your contact may need help and asked you to be notified. Last known location is unavailable. Sent $time.';
  }

  @override
  String get accept => 'Accept';

  @override
  String get acceptPrivacyPolicy => 'Accept Privacy Policy';

  @override
  String get agree => 'Agree';

  @override
  String get activateDevice => 'Activate Device';

  @override
  String get buyPremiumAccess => 'Buy Premium Access';

  @override
  String get confirmOnThisDevice => 'Confirm On This Device';

  @override
  String get yesDeleteMyAccount => 'Yes, Delete My Account';

  @override
  String get yesConfirmDeletionOnThisDevice =>
      'Yes, Confirm Deletion On This Device';

  @override
  String get thisCannotBeUndone => 'This Cannot Be Undone';

  @override
  String get permanentlyEraseAccount =>
      'Permanently erase this account, its devices, and its data';

  @override
  String get premiumAccessInfo => 'Premium Access Info';

  @override
  String get premiumAccessOptions => 'Premium Access Options';

  @override
  String get openWebsite => 'Open Win\'s VPN Website';

  @override
  String get exploreMap => 'Explore map';

  @override
  String get closeMap => 'Close map';

  @override
  String get download => 'Download';

  @override
  String get upload => 'Upload';

  @override
  String get launchOutsideVpn => 'Launch outside VPN';

  @override
  String get connectVpnToLaunchOutside => 'Connect VPN to launch outside';

  @override
  String get useLaunchButtonOutside =>
      'Use the launch button to open outside the VPN';

  @override
  String get selectAppForBypassFirst => 'Select app for bypass first';

  @override
  String get iHaveSavedIt => 'I have saved it';

  @override
  String get wipeOnly => 'Wipe only';

  @override
  String get setUpEmergencyAlert => 'Set up emergency alert';

  @override
  String get setUpEmergencyAlertLong => 'Set up an emergency alert';

  @override
  String get createRecoveryCode => 'Create a recovery code';

  @override
  String get saveThisRecoveryCode => 'Save this recovery code';

  @override
  String get chooseNewUnlockCode => 'Choose a new unlock code';

  @override
  String get confirmEmergencyCode => 'Confirm emergency code';

  @override
  String get emergencyCode => 'Emergency code';

  @override
  String get emergencyAlert => 'Set Up An Emergency Alert';

  @override
  String get reviewPrivacyPolicyToContinue =>
      'Review Privacy Policy to continue';

  @override
  String get reviewAndAcceptPrivacyPolicy =>
      'Review and accept bundled Privacy Policy';

  @override
  String get viewBundledPrivacyPolicy => 'View bundled Privacy Policy';

  @override
  String get bundledOfflinePrivacyPolicy => 'Bundled offline Privacy Policy';

  @override
  String get tryFreeServer => 'Try Free Server';

  @override
  String get tryFreeServerLimited =>
      'Try Free Server (100 Mbps upload and download)';

  @override
  String get freeServerLimited => 'Free Plan: 100 Mbps upload and download';

  @override
  String get freeServer => 'Free Server';

  @override
  String get smartProtocol => 'Smart Protocol';

  @override
  String get applyingVpnRouteSettings => 'Applying VPN route settings...';

  @override
  String get connectBeforeSensitive =>
      'Connect before you open or fetch anything sensitive. Until the ';

  @override
  String get connectingOverTcpOnly => 'Connecting over TCP only...';

  @override
  String get directRouteUnavailableTryingTcp =>
      'Direct route unavailable. Trying TCP...';

  @override
  String get fetching => 'Fetching...';

  @override
  String get loading => 'Loading...';

  @override
  String get ready => 'Ready';

  @override
  String get searching => 'Searching...';

  @override
  String get syncingFreeServerList => 'Syncing free server list...';

  @override
  String get syncingSecurityUpdates => 'Syncing latest security updates...';

  @override
  String get testing => 'Testing';

  @override
  String get testingTcpFallback => 'Testing TCP fallback...';

  @override
  String get testingUpload => 'Testing upload...';

  @override
  String get tryingTcpFallback => 'Trying TCP fallback...';

  @override
  String get usingTcpFallback => 'Using TCP fallback...';

  @override
  String get disconnecting => 'Disconnecting...';

  @override
  String get maintenanceInProgress => 'Maintenance in progress. Please wait.';

  @override
  String get maintenanceUnderway =>
      'Maintenance underway: Some servers may be offline.';

  @override
  String get coreServerOfflineMaintenance =>
      'Our core server is currently offline for maintenance.';

  @override
  String get applyOnAndroidDevice => 'in Settings to let the app try it. ';

  @override
  String get allTrafficUsesVpn => 'All traffic currently uses the VPN.';

  @override
  String get allIpv4UseVpn => 'All IPv4 destinations will use the VPN.';

  @override
  String connectingTo(String serverName) {
    return 'Connecting to $serverName...';
  }

  @override
  String get switchingServer => 'Switching VPN server...';

  @override
  String get freeServerChanged => 'Free server changed.';

  @override
  String get freeServerChangedConfigSync =>
      'Free server changed. Config will sync when you connect.';

  @override
  String get freeServerIsReady => 'Free server is ready.';

  @override
  String get deviceSuccessfullyActivated => 'Device Successfully Activated!';

  @override
  String freeCount(int count) {
    return '$count free servers available';
  }

  @override
  String get oneFreeServer => '1 free server available';

  @override
  String get alwaysConnectOverTcp => 'Always connect over TCP';

  @override
  String get alwaysOnVpn => 'Always-on VPN';

  @override
  String get allowTextAlert => 'Allow text alert';

  @override
  String get contactEmailOptional => 'Contact email (optional)';

  @override
  String get trustedContactPhoneNumber => 'Trusted contact phone number';

  @override
  String get optional => 'Optional';

  @override
  String get requiredForTextAlert => 'Required for the text alert';

  @override
  String get diagnostics => 'Diagnostics';

  @override
  String get protocol => 'Protocol';

  @override
  String get additionalPermissions => 'Additional permissions';

  @override
  String get autoSelected => 'Auto Selected';

  @override
  String get doubleVpnCoreOffline =>
      'Double VPN core is offline for maintenance. Connecting with standard VPN instead...';

  @override
  String get applyBypassDestinations => 'Apply bypass destinations';

  @override
  String get clearSearch => 'Clear search';

  @override
  String get destinationsOutsideVpn =>
      'Destinations outside VPN (all operating systems)';

  @override
  String get enterIpv4OrCidr =>
      'Enter IPv4 addresses or CIDR networks. These destinations use your normal connection; everything else stays in the VPN.';

  @override
  String get exampleCidr => 'Example: 192.168.0.0/16, 203.0.113.9';

  @override
  String excludeAllApps(String platform) {
    return 'Exclude all $platform';
  }

  @override
  String searchToExclude(String platform) {
    return 'Search $platform to exclude';
  }

  @override
  String get noAppsMatchSearch => 'No apps match your search.';

  @override
  String get appListNotReady => 'App list is not ready yet.';

  @override
  String get selectThisAppForBypass =>
      'Select this app for bypass before launching it.';

  @override
  String get linuxBypassLauncherScoped =>
      'Linux bypass is launcher-scoped: connect, select an app, then use its launch button here. Apps opened normally remain protected by the VPN.';

  @override
  String get linuxAppLaunchedOutside => 'Linux app launched outside the VPN.';

  @override
  String get linuxAppCouldNotLaunch => 'The Linux app could not be launched.';

  @override
  String get connectFirstThenLaunchLinux =>
      'Connect Win\'s VPN first, then launch the selected Linux app outside the VPN.';

  @override
  String get useNoMoreThan64Destinations =>
      'Use no more than 64 destination networks.';

  @override
  String get tooManyRoutes =>
      'Split tunneling produced too many routes. Use broader destination ranges.';

  @override
  String get cannotExcludeAllIpv4 =>
      'Split tunneling cannot exclude the entire IPv4 space.';

  @override
  String get zeroCannotBeExcluded =>
      '0.0.0.0/0 cannot be excluded because it would block the VPN.';

  @override
  String get exclusionsTooManyRoutes =>
      'Those exclusions produce too many routes; combine nearby networks.';

  @override
  String onlyYourIpv4(String routes) {
    return 'Only your selected IPv4 destinations: $routes';
  }

  @override
  String get androidApps => 'Android apps';

  @override
  String get linuxApps => 'Linux apps';

  @override
  String get windowsApps => 'Windows apps';

  @override
  String get perAppExplanation =>
      'To show Exclude Apps From VPN, Win\'s VPN needs to access the list of installed apps on this device. The list is used only on your device to build the split-tunneling picker. The full list is not uploaded, shared, sold, or used for ads or analytics. Only package names you select for exclusion are stored locally and passed to Android VpnService. You can choose Not now and continue using the VPN without per-app exclusions.';

  @override
  String get diagnosticsExplanation =>
      'Records redacted connection-diagnostic information to help ';

  @override
  String get diagnosticsOffNoFile =>
      'support. When off, no diagnostic file is written.';

  @override
  String get keepUpdated => 'Keep this app and your operating system updated.';

  @override
  String get thisAppResistsCensorship =>
      'This app works to resist censorship, but it does not make you ';

  @override
  String get reachableInEverySituation => 'reachable in every situation.';

  @override
  String get showsWhatAppContacts =>
      'tunnel is up, your network can see what the app contacts.';

  @override
  String get cannotVerifyAgainstAddress =>
      'cannot be verified against an address.';

  @override
  String get resolveToPublicIpv4 => 'resolve to a public IPv4 address.';

  @override
  String get anyDirectServerAddress =>
      'anything directly to a server\'s own address. This is ';

  @override
  String get directlyToServer => 'directly to a server';

  @override
  String get normallyUsed => 'normally used';

  @override
  String get atAllInsteadOfFallback => 'at all instead of falling back.';

  @override
  String get removesTheFallbackRoute => 'removes the fallback route.';

  @override
  String get routeWhenDirectUnavailable =>
      'route when the direct route is unavailable.';

  @override
  String get willNotConnectAtAll => 'will not connect at all.';

  @override
  String get keepsVpnRunningAndBlocks =>
      'Keeps the VPN running and blocks traffic if the tunnel drops.';

  @override
  String get triesDirectThenTcp =>
      'Tries the direct route first, then falls back to the TCP ';

  @override
  String get usesOnlyTcpRoute =>
      'Uses only the TCP route and will never send anything ';

  @override
  String get usesOnlyDirectNoFallback =>
      'Uses only the direct route and will not fall back. On a ';

  @override
  String get appWillOnlyUseTcpRoute =>
      'The app will only use the TCP route, and will never send ';

  @override
  String get onNoFallbackLeft =>
      'On: there is no fallback left. If TCP does not work on ';

  @override
  String get networkWhereTcpFails =>
      'network where TCP does not work, the app will not connect ';

  @override
  String get networkWhereDirectFails =>
      'network where the direct route does not work, the app ';

  @override
  String get isOnSoFasterNotTried =>
      'is on, so the faster direct route was not tried. Turn that setting off ';

  @override
  String get onlyIsOnSoTcpNotTried =>
      'only\" is on, so the TCP route was not tried. Turn that setting off in ';

  @override
  String get overTcpIsOn =>
      'over TCP\" is on, so the direct route was not tried. Choose a ';

  @override
  String get differentServerOrTurnOff =>
      'different server, or turn that setting off in Settings.';

  @override
  String get clearsDeviceShowsError =>
      'shows an error; it does not send any message.';

  @override
  String get errorItWillNotSendMessage =>
      'error: it just will not send a message.';

  @override
  String get onThisDeviceCannotSend =>
      'error. On this device it CANNOT send any ';

  @override
  String get messageNotPossibleHere =>
      'message (that is not possible here) so no ';

  @override
  String get textedIfYouUseTheCode => 'texted if you use the code.';

  @override
  String get thisAppCanQuietlyText =>
      'this app can quietly text your trusted contact ';

  @override
  String get notifiesTrustedContact =>
      'notifies a trusted contact if you are ever forced to unlock ';

  @override
  String get youAreForcedToUnlock => 'you are forced to unlock this device.';

  @override
  String get theCodeStillClears =>
      'the code still clears this device and shows the ';

  @override
  String get beforeYouStart =>
      'Before you start - what this protects, and what it cannot';

  @override
  String get iHaveReadAndAgree =>
      'I have read and agree to the Privacy Policy and understand the data handling described above.';

  @override
  String get iUnderstandVpnService =>
      'I understand and agree to the Android VpnService disclosure.';

  @override
  String get iAgreeHoldHarmless => 'I agree to the Hold Harmless Agreement.';

  @override
  String get iAgreeLimitationOfLiability =>
      'I agree to the Limitation of Liability.';

  @override
  String get iAgreeTermsOfService => 'I agree to the Terms of Service.';

  @override
  String get iAgreeElectronicRecords =>
      'I consent to receive service records electronically.';

  @override
  String get iAgreeAllTerms =>
      'I agree to the Privacy Policy, Terms of Service, Hold Harmless Agreement, Limitation of Liability, and Electronic Records consent.';

  @override
  String get privacyPolicyAndLegalRequired =>
      'Privacy Policy and Legal Acceptance Required';

  @override
  String privacyPolicyVersion(String version) {
    return 'Version $version';
  }

  @override
  String get copyrightNotice => '© 2026 Win\'s VPN Inc.';

  @override
  String get planLifetime => 'Lifetime Access';

  @override
  String get doesNotCreateOrRenewVpn => 'Does not create or renew VPN access';

  @override
  String get accessPurchasesEmail =>
      'Access purchases are instantly provisioned and emailed to you.';

  @override
  String get premiumAccessDescription =>
      'Premium access opens the official Win\'s VPN purchase section. Store-specific billing options may be added later where required.';

  @override
  String get appleStoreBillingNote =>
      'For the Apple App Store build, use an existing Win\'s VPN account number or Try Free Server. Apple subscription options may be added through App Store billing after review.';

  @override
  String get googlePlayBillingNote =>
      'For this Google Play build, use an existing Win\'s VPN account number or Try Free Server. Premium purchase options may be added through supported store billing where required.';

  @override
  String accessExpires(String date) {
    return 'Access: $date';
  }

  @override
  String planExpires(String date) {
    return 'Plan Expires: $date';
  }

  @override
  String get referralInviteBenefit =>
      'Invite a friend and both accounts receive 20% extra VPN time after activation.';

  @override
  String get likeShareSubscribe =>
      'Like, share, subscribe, donate. Win for the People!';

  @override
  String get enterSecureAccountNumber => 'Enter Secure Account Number';

  @override
  String get type12DigitAccountNumber =>
      'Type the 12-digit Account Number here.';

  @override
  String get setupKeyHint => 'Setup Key (new/reinstalled devices only)';

  @override
  String get accountNumberHint => 'XXXX-XXXX-XXXX';

  @override
  String get accountNumberOrSetupKeyIncorrect =>
      'Account number or setup key is incorrect. Check your welcome email and try again.';

  @override
  String get newOrReinstalledDevice =>
      'New or reinstalled device: enter the setup key from your welcome email, then click \"Activate Device\" again.';

  @override
  String get fromYourWelcomeEmail =>
      'From your welcome email. Not needed once this device is activated.';

  @override
  String pleaseType12DigitAndPin(int length) {
    return 'Please type your 12-digit Account Number and set a $length-digit PIN before clicking \"Activate Device\".';
  }

  @override
  String get pleaseType12Digit =>
      'Please type your 12-digit Account Number before clicking \"Activate Device\".';

  @override
  String setPinBeforeActivating(int length) {
    return 'Please set a $length-digit PIN by typing it in the PIN box before activating.';
  }

  @override
  String get setPinHereBeforeFree =>
      'Please set the PIN by typing it here and click the \"Try Free Server\" button again.';

  @override
  String setYourPinHere(int length) {
    return 'Set your $length-digit PIN here.';
  }

  @override
  String createPinHint(int length) {
    return 'Create $length-Digit PIN';
  }

  @override
  String pinDigitsHint(int length) {
    return '$length digits';
  }

  @override
  String get freeAccessDisabled => 'Free access is currently disabled.';

  @override
  String get freeAccessTempUnavailable =>
      'Free access is temporarily unavailable. Check your connection, or contact support if this keeps happening.';

  @override
  String get freeServerNotReachable =>
      'Free server is not reachable through the protected gateway network. Please try again soon.';

  @override
  String get freeServerSetupFailed =>
      'Free server setup could not be completed. Check your connection and try again, or contact support if it keeps failing.';

  @override
  String get noFreeServerOnline =>
      'No free server is online right now. Please try again soon.';

  @override
  String get noFreeServersOnlineYet => 'No free servers are online yet.';

  @override
  String get freeDeviceIdentityConflict =>
      'Free-device identity conflict. Please reinstall or contact support.';

  @override
  String get freeActivationRejected =>
      'The free activation request was rejected. Please reinstall or contact support.';

  @override
  String get freeServiceMaintenance =>
      'The free service is undergoing maintenance. Please try again soon.';

  @override
  String get tooManyFreeActivationAttempts =>
      'Too many free activation attempts. Please wait a minute and try again.';

  @override
  String get legalAcceptanceRequired =>
      'Legal acceptance is required before activation.';

  @override
  String get activationFailed =>
      'Activation could not be completed. Check your connection, then try again, or contact support.';

  @override
  String get serverAtCapacity =>
      'Selected server is at capacity. Please choose a different server.';

  @override
  String get vpnConfigMissing =>
      'VPN config missing. Deactivate and activate again.';

  @override
  String get authenticatedIncompleteConfig =>
      'Authenticated, but server returned an incomplete VPN config. Check node registration/public key.';

  @override
  String get invalidNumber => 'Invalid number';

  @override
  String get actionFailedRetry =>
      'The app could not complete that action. Please try again later.';

  @override
  String get nothingWasChanged =>
      'Nothing was changed. Check your connection and try again.';

  @override
  String get couldNotReachAccountService =>
      'Could not reach the account service. ';

  @override
  String get couldNotRefreshVpnConfig =>
      'Could not refresh VPN config. Check hub connection and try again.';

  @override
  String get couldNotOpenPaymentLink => 'Could not open payment link.';

  @override
  String get couldNotOpenSocialLink => 'Could not open social link.';

  @override
  String get couldNotOpenUpdatePage =>
      'Could not open the update page. Visit our website to update.';

  @override
  String get couldNotReachHub =>
      'Could not reach Wins Hub through the protected gateway network. Please try again or contact support.';

  @override
  String get couldNotCheckDeletionStatus =>
      'Could not reach the account service to check deletion status. Check your connection and try again.';

  @override
  String get couldNotSafelyQueueCleanup =>
      'Could not safely queue server cleanup. Try again before deactivating.';

  @override
  String get accountDeleted => 'Your account and its data have been deleted.';

  @override
  String get deviceRemovedKeysNotCleared =>
      'Device removed, but some VPN keys stored on this device could not be fully cleared.';

  @override
  String get deviceRemovedLocally =>
      'Device was removed locally. Server cleanup will retry when the hub is reachable.';

  @override
  String get freeFeatureForPaid => 'This feature is for paid users only.';

  @override
  String get requiredUpdate =>
      'A required update is available. Please update to the latest version to continue.';

  @override
  String get smartProtocolUnavailable =>
      'This server has no TCP route registered yet, and \"Always connect ';

  @override
  String get tcpFallbackNotRegistered =>
      'TCP fallback is not registered for this server yet.';

  @override
  String get couldNotConnectOverTcp =>
      'Could not connect over TCP on this network. \"Always connect over TCP\" ';

  @override
  String get couldNotConnectOverUdp =>
      'Could not connect over direct UDP on this network, and \"Direct (UDP) ';

  @override
  String get setUpEmergencyAlertDescription =>
      'Set up an emergency alert. Choose a second code that quietly ';

  @override
  String get emergencyAlertSetup =>
      'Emergency alert is set up. Your trusted contact will be ';

  @override
  String get emergencyCodeSetup =>
      'Emergency code is set up. Using it clears this device and ';

  @override
  String get chooseSecondCode =>
      'Choose a second code. If you ever enter it on ';

  @override
  String get theLockScreenInstead =>
      'the lock screen instead of your normal code, ';

  @override
  String get theLockScreenOrPin =>
      'your approximate location, then clear itself, ';

  @override
  String get thisDevice => 'this device.';

  @override
  String get contactWillBeNotified => 'contact will be notified.';

  @override
  String get enterConnectionCode => 'Enter connection code';

  @override
  String get currentUnlockCode => 'Current unlock code';

  @override
  String get enterValidPhoneNumber =>
      'Enter a valid phone number for your contact.';

  @override
  String get validPhoneRequired =>
      'A valid phone number is required for the SMS alert';

  @override
  String get sendingTextNeedsSmsPermission =>
      'Sending a text needs SMS permission, which you ';

  @override
  String get willBeAskedFor =>
      'will be asked for. If you choose not to allow it, ';

  @override
  String get itWillNotSendMessage => 'it will just not send a message.';

  @override
  String get twoEmergencyCodesDoNotMatch =>
      'The two emergency codes do not match.';

  @override
  String get unlockCodeUpdated => 'Unlock code updated.';

  @override
  String get thatUnlockCodeIncorrect => 'That unlock code is not correct.';

  @override
  String get theEmergencyCodeCouldNotStore =>
      'The emergency code could not be stored on this device. Nothing was changed.';

  @override
  String get theNewCodeCouldNotStore =>
      'The new code could not be stored on this device. Nothing was changed.';

  @override
  String get theRecoveryCodeCouldNotStore =>
      'The recovery code could not be stored on this device. You can try ';

  @override
  String get againFromHomeScreen => 'again from the home screen.';

  @override
  String get ifYouForgetUnlockCode =>
      'If you forget your unlock code, this is the only way back ';

  @override
  String get useCodeFromSupport =>
      'Use a code from support if the app cannot connect';

  @override
  String get setLongerUnlockCode => 'Set a longer unlock code';

  @override
  String get useLongerCode => 'Use a longer code';

  @override
  String aLongerCodeHarderToGuess(int length) {
    return 'A $length-digit code is much harder to guess.';
  }

  @override
  String get youHaveNoRecoveryCode =>
      'You have no recovery code. Without one, forgetting your ';

  @override
  String get unlockCodeMeansLosingAccess =>
      'unlock code means losing access to this app.';

  @override
  String get youOpenedWithRecoveryCode =>
      'You opened the app with your recovery code, so ';

  @override
  String get unlockCodeNow => 'unlock code now.';

  @override
  String get writeItDown =>
      'Write it down, or put it in a password manager. Keep it ';

  @override
  String get somewhereSeparate => 'somewhere separate from this device.';

  @override
  String yourUnlockCodeIs(int length) {
    return 'Your unlock code is $length digits. ';
  }

  @override
  String pleaseSetNewPin(int length) {
    return 'please set a new $length-digit ';
  }

  @override
  String get unlockCodeNowPrompt => 'unlock code now.';

  @override
  String pleaseDisconnectFirst(String action) {
    return 'Please disconnect the VPN first before $action. Split Tunneling was not changed.';
  }

  @override
  String get pleaseDisconnectDestinations =>
      'Please disconnect the VPN first before changing bypass destinations. Split Tunneling was not changed.';

  @override
  String get pleaseDisconnectApps =>
      'Please disconnect the VPN first before changing excluded apps. Split Tunneling was not changed.';

  @override
  String get pleaseDisconnectDoubleVpn =>
      'Please disconnect the VPN first. Double VPN cannot be changed while the VPN is connected, so nothing was changed.';

  @override
  String get pleaseDisconnectTcpOnly =>
      'Please disconnect the VPN first. The TCP-only setting cannot be changed while the VPN is connected, so nothing was changed.';

  @override
  String get pleaseDisconnectProtocol =>
      'Please disconnect the VPN first. The protocol setting cannot be ';

  @override
  String get changedWhileConnected =>
      'changed while the VPN is connected, so nothing was changed.';

  @override
  String get doubleVpnCouldNotSave =>
      'Double VPN could not be saved because the app could not write its settings. Nothing was changed.';

  @override
  String get settingCouldNotSave =>
      'That setting could not be saved because the app could not write its settings. Nothing was changed.';

  @override
  String get stillDisconnectingSwitch =>
      'Still disconnecting. Please try switching again in a moment.';

  @override
  String get stillDisconnecting =>
      'Still disconnecting. Try again in a moment.';

  @override
  String get vpnDisconnectStillFinishing =>
      'VPN disconnect is still finishing. Please wait a moment before reconnecting.';

  @override
  String get alwaysOnVpnIsOn => 'Always-on VPN is on. Win';

  @override
  String get alwaysOnVpnTurnedOff => 'Always-on VPN turned off.';

  @override
  String get alwaysOnCouldNotEnable =>
      'Always-on could not be enabled by the system on this device. It may ';

  @override
  String get alwaysOnOnlyAndroid =>
      'Always-on is only available on Android. The setting is saved and will ';

  @override
  String get needToBeEnabled =>
      'need to be enabled in your system VPN settings.';

  @override
  String get willAskAgainNextTime =>
      'will ask again next time. Nothing else was affected.';

  @override
  String get failedRouteCouldNotRemove =>
      'The failed VPN route could not be removed safely. Restart the app before retrying.';

  @override
  String get previousRouteCouldNotRemove =>
      'The previous VPN route could not be removed safely. Restart the app before retrying.';

  @override
  String get confirmationsReceived => 'Confirmations received: ';

  @override
  String get disguiseStillShowsVpn =>
      'Your device will still show that a VPN is active. The disguise ';

  @override
  String get hidesWhichAppRunning =>
      'hides which app is running, not the fact of a VPN connection.';

  @override
  String savedAddresses(int count) {
    return 'Saved addresses: $count';
  }

  @override
  String get speedTestUnavailable => 'Speed test unavailable';

  @override
  String get confirmVpn => 'Connect';

  @override
  String get serverListStillSyncing => 'Server list is still syncing.';

  @override
  String lastSpeedTest(String label) {
    return 'Last $label test: ';
  }

  @override
  String get mbps => 'Mbps';

  @override
  String downloadMbps(String download) {
    return '$download Mbps';
  }

  @override
  String uploadMbps(String upload) {
    return '$upload Mbps';
  }

  @override
  String routeCount(int count, String plural) {
    return '$count destination network$plural';
  }

  @override
  String appCount(int count) {
    return '$count apps';
  }

  @override
  String networkCount(int count) {
    return '$count destinations';
  }

  @override
  String get perAppBypassWillBypass => ' will bypass the VPN.';

  @override
  String get inThisBuild => 'in this build';

  @override
  String get unsupportedInThisBuild =>
      'unsupported in this build; routing to update-required, ';

  @override
  String get selectToEnableLauncherScoped =>
      'Select to enable launcher-scoped bypass';

  @override
  String get systemApp => ' (system app)';

  @override
  String get shareWin => 'Share Win';

  @override
  String serverLoadPercent(int percent) {
    return 'Server load $percent%';
  }

  @override
  String get connectVpnAction => 'Connect VPN';

  @override
  String get disconnectVpnAction => 'Disconnect VPN';

  @override
  String get cancelVpnConnectionAction => 'Cancel VPN connection';

  @override
  String get vpnConnectionInProgress => 'VPN connection in progress';

  @override
  String get cancelConnectionAction => 'Cancel connection';

  @override
  String get serverLoadUnknown => 'Server load unknown';
}
