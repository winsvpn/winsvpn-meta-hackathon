import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_my.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
      : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
    delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
  ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('my')
  ];

  /// No description provided for @appName.
  ///
  /// In en, this message translates to:
  /// **'Win\'s VPN'**
  String get appName;

  /// No description provided for @appNameAnnouncement.
  ///
  /// In en, this message translates to:
  /// **'Win\'s VPN Announcement'**
  String get appNameAnnouncement;

  /// No description provided for @welcomeMessage.
  ///
  /// In en, this message translates to:
  /// **'Welcome to Win\'s VPN! Thank you for helping yourself by using our services!!'**
  String get welcomeMessage;

  /// No description provided for @secureConnectionEstablished.
  ///
  /// In en, this message translates to:
  /// **'Secure Connection Established.'**
  String get secureConnectionEstablished;

  /// No description provided for @startingProtocol.
  ///
  /// In en, this message translates to:
  /// **'Starting Winn Protocol®...'**
  String get startingProtocol;

  /// No description provided for @securingRoute.
  ///
  /// In en, this message translates to:
  /// **'Securing VPN route...'**
  String get securingRoute;

  /// No description provided for @finalizingRoute.
  ///
  /// In en, this message translates to:
  /// **'Finalizing secure route...'**
  String get finalizingRoute;

  /// No description provided for @trafficSecured.
  ///
  /// In en, this message translates to:
  /// **'Traffic Secured & Obfuscated'**
  String get trafficSecured;

  /// No description provided for @disconnected.
  ///
  /// In en, this message translates to:
  /// **'Disconnected'**
  String get disconnected;

  /// No description provided for @secured.
  ///
  /// In en, this message translates to:
  /// **'SECURED'**
  String get secured;

  /// No description provided for @unprotected.
  ///
  /// In en, this message translates to:
  /// **'UNPROTECTED'**
  String get unprotected;

  /// No description provided for @selectedProtocol.
  ///
  /// In en, this message translates to:
  /// **'Selected Protocol:'**
  String get selectedProtocol;

  /// No description provided for @status.
  ///
  /// In en, this message translates to:
  /// **'Status:'**
  String get status;

  /// No description provided for @referral.
  ///
  /// In en, this message translates to:
  /// **'Referral'**
  String get referral;

  /// No description provided for @shareApp.
  ///
  /// In en, this message translates to:
  /// **'Share Win\'s VPN'**
  String get shareApp;

  /// No description provided for @gate.
  ///
  /// In en, this message translates to:
  /// **'Gate:'**
  String get gate;

  /// No description provided for @traffic.
  ///
  /// In en, this message translates to:
  /// **'Traffic:'**
  String get traffic;

  /// No description provided for @notConnected.
  ///
  /// In en, this message translates to:
  /// **'Not connected'**
  String get notConnected;

  /// No description provided for @connecting.
  ///
  /// In en, this message translates to:
  /// **'Connecting...'**
  String get connecting;

  /// No description provided for @establishingRoute.
  ///
  /// In en, this message translates to:
  /// **'Establishing secure route...'**
  String get establishingRoute;

  /// No description provided for @carryingTraffic.
  ///
  /// In en, this message translates to:
  /// **'Carrying traffic'**
  String get carryingTraffic;

  /// No description provided for @connectedNoLiveProbe.
  ///
  /// In en, this message translates to:
  /// **'Connected, no live probe on this device'**
  String get connectedNoLiveProbe;

  /// No description provided for @flowing.
  ///
  /// In en, this message translates to:
  /// **'Flowing'**
  String get flowing;

  /// No description provided for @idle.
  ///
  /// In en, this message translates to:
  /// **'Idle'**
  String get idle;

  /// No description provided for @notAvailable.
  ///
  /// In en, this message translates to:
  /// **'Not available'**
  String get notAvailable;

  /// No description provided for @received.
  ///
  /// In en, this message translates to:
  /// **'Received'**
  String get received;

  /// No description provided for @sent.
  ///
  /// In en, this message translates to:
  /// **'Sent'**
  String get sent;

  /// No description provided for @session.
  ///
  /// In en, this message translates to:
  /// **'Session:'**
  String get session;

  /// No description provided for @version1.
  ///
  /// In en, this message translates to:
  /// **'Version 1'**
  String get version1;

  /// No description provided for @version3.
  ///
  /// In en, this message translates to:
  /// **'Version 3'**
  String get version3;

  /// No description provided for @versionNotRecognised.
  ///
  /// In en, this message translates to:
  /// **'Version not recognised by this app'**
  String get versionNotRecognised;

  /// No description provided for @directTransport.
  ///
  /// In en, this message translates to:
  /// **'direct transport'**
  String get directTransport;

  /// No description provided for @stealthTransport.
  ///
  /// In en, this message translates to:
  /// **'stealth transport'**
  String get stealthTransport;

  /// No description provided for @openSourceLicences.
  ///
  /// In en, this message translates to:
  /// **'Open source licences'**
  String get openSourceLicences;

  /// No description provided for @thirdPartyNotices.
  ///
  /// In en, this message translates to:
  /// **'Notices for the software this app is built on'**
  String get thirdPartyNotices;

  /// No description provided for @serverUnreachable.
  ///
  /// In en, this message translates to:
  /// **'Server unreachable right now'**
  String get serverUnreachable;

  /// No description provided for @notReachableFromDevice.
  ///
  /// In en, this message translates to:
  /// **'Not reachable from this device right now'**
  String get notReachableFromDevice;

  /// No description provided for @somethingWentWrong.
  ///
  /// In en, this message translates to:
  /// **'Something went wrong'**
  String get somethingWentWrong;

  /// No description provided for @actionFailed.
  ///
  /// In en, this message translates to:
  /// **'The app could not complete that action. Please try again later.'**
  String get actionFailed;

  /// No description provided for @ok.
  ///
  /// In en, this message translates to:
  /// **'OK'**
  String get ok;

  /// No description provided for @cancel.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// No description provided for @close.
  ///
  /// In en, this message translates to:
  /// **'Close'**
  String get close;

  /// No description provided for @continueButton.
  ///
  /// In en, this message translates to:
  /// **'Continue'**
  String get continueButton;

  /// No description provided for @goBack.
  ///
  /// In en, this message translates to:
  /// **'Go Back'**
  String get goBack;

  /// No description provided for @notNow.
  ///
  /// In en, this message translates to:
  /// **'Not now'**
  String get notNow;

  /// No description provided for @allow.
  ///
  /// In en, this message translates to:
  /// **'Allow'**
  String get allow;

  /// No description provided for @deny.
  ///
  /// In en, this message translates to:
  /// **'Deny'**
  String get deny;

  /// No description provided for @save.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// No description provided for @refreshStatus.
  ///
  /// In en, this message translates to:
  /// **'Refresh status'**
  String get refreshStatus;

  /// No description provided for @allowBackgroundVpn.
  ///
  /// In en, this message translates to:
  /// **'Allow background VPN protection?'**
  String get allowBackgroundVpn;

  /// No description provided for @allowBackgroundVpnDetail.
  ///
  /// In en, this message translates to:
  /// **'To keep Win\'s VPN connected when the screen is off or when your network changes, allow the app to run without battery optimization.'**
  String get allowBackgroundVpnDetail;

  /// No description provided for @deleteAccount.
  ///
  /// In en, this message translates to:
  /// **'Delete Account'**
  String get deleteAccount;

  /// No description provided for @deactivateDevice.
  ///
  /// In en, this message translates to:
  /// **'Deactivate Device'**
  String get deactivateDevice;

  /// No description provided for @cancelDeletion.
  ///
  /// In en, this message translates to:
  /// **'Cancel Deletion'**
  String get cancelDeletion;

  /// No description provided for @privacyPolicyAndLegalConsent.
  ///
  /// In en, this message translates to:
  /// **'Privacy Policy and Legal Consent'**
  String get privacyPolicyAndLegalConsent;

  /// No description provided for @openingShareOptions.
  ///
  /// In en, this message translates to:
  /// **'Opening share options...'**
  String get openingShareOptions;

  /// No description provided for @websiteLinkCopied.
  ///
  /// In en, this message translates to:
  /// **'Win\'s VPN website link copied.'**
  String get websiteLinkCopied;

  /// No description provided for @referralLinkCopied.
  ///
  /// In en, this message translates to:
  /// **'Referral link copied.'**
  String get referralLinkCopied;

  /// No description provided for @planOneMonth.
  ///
  /// In en, this message translates to:
  /// **'1 Month Subscription'**
  String get planOneMonth;

  /// No description provided for @planOneYear.
  ///
  /// In en, this message translates to:
  /// **'1 Year Subscription'**
  String get planOneYear;

  /// No description provided for @planOneTimeTenYears.
  ///
  /// In en, this message translates to:
  /// **'One-Time Payment (10 Years)'**
  String get planOneTimeTenYears;

  /// No description provided for @planLifetimeTechSupport.
  ///
  /// In en, this message translates to:
  /// **'Lifetime Access + Tech Support'**
  String get planLifetimeTechSupport;

  /// No description provided for @planLifetimeNoTechSupport.
  ///
  /// In en, this message translates to:
  /// **'Lifetime Access (No Tech Support)'**
  String get planLifetimeNoTechSupport;

  /// No description provided for @generalDonation.
  ///
  /// In en, this message translates to:
  /// **'Make a General Donation'**
  String get generalDonation;

  /// No description provided for @premiumAutoRenews.
  ///
  /// In en, this message translates to:
  /// **'Premium Auto-renews'**
  String get premiumAutoRenews;

  /// No description provided for @standardAutoRenews.
  ///
  /// In en, this message translates to:
  /// **'Standard Auto-renews'**
  String get standardAutoRenews;

  /// No description provided for @transportAutomatic.
  ///
  /// In en, this message translates to:
  /// **'Automatic'**
  String get transportAutomatic;

  /// No description provided for @transportDirectUdp.
  ///
  /// In en, this message translates to:
  /// **'Direct (UDP) only'**
  String get transportDirectUdp;

  /// No description provided for @transportTcp.
  ///
  /// In en, this message translates to:
  /// **'TCP only'**
  String get transportTcp;

  /// No description provided for @featureDoubleVpn.
  ///
  /// In en, this message translates to:
  /// **'Double VPN'**
  String get featureDoubleVpn;

  /// No description provided for @featureSplitTunneling.
  ///
  /// In en, this message translates to:
  /// **'Split Tunneling'**
  String get featureSplitTunneling;

  /// No description provided for @installedAppAccess.
  ///
  /// In en, this message translates to:
  /// **'Installed app access'**
  String get installedAppAccess;

  /// No description provided for @referralInvite.
  ///
  /// In en, this message translates to:
  /// **'Invite a friend and both accounts receive 20% extra VPN time after activation.'**
  String get referralInvite;

  /// No description provided for @referralShareDetail.
  ///
  /// In en, this message translates to:
  /// **'Share Win\'s VPN with friends. Paid referral bonuses are available after upgrading.'**
  String get referralShareDetail;

  /// No description provided for @openWin.
  ///
  /// In en, this message translates to:
  /// **'Open Win'**
  String get openWin;

  /// Recipient-facing SMS body sent from the handset when coarse coordinates exist. Deliberately neutral: must never name the app, a VPN, censorship, duress or a panic feature. The whole body must fit one GSM-7 SMS part; the maps link is the coordinates payload.
  ///
  /// In en, this message translates to:
  /// **'Safety alert: someone who listed you as an emergency contact may need help. Approx. location: {link}'**
  String duressSmsWithLocation(String link);

  /// Recipient-facing SMS body sent from the handset when no coordinates are available. Neutral, no app-identifying wording.
  ///
  /// In en, this message translates to:
  /// **'Safety alert: someone who listed you as an emergency contact may need help. Location not available.'**
  String get duressSmsWithoutLocation;

  /// Human-readable alert forwarded to a trusted contact when coordinates exist. Neutral, no app-identifying wording.
  ///
  /// In en, this message translates to:
  /// **'Automated safety alert: your contact may need help and asked you to be notified. Last known location: {lat}, {lng} ({link}). Sent {time}.'**
  String duressHumanMessageWithLocation(
      String lat, String lng, String link, String time);

  /// Human-readable alert forwarded to a trusted contact when no coordinates are available. Neutral, no app-identifying wording.
  ///
  /// In en, this message translates to:
  /// **'Automated safety alert: your contact may need help and asked you to be notified. Last known location is unavailable. Sent {time}.'**
  String duressHumanMessageWithoutLocation(String time);

  /// No description provided for @accept.
  ///
  /// In en, this message translates to:
  /// **'Accept'**
  String get accept;

  /// No description provided for @acceptPrivacyPolicy.
  ///
  /// In en, this message translates to:
  /// **'Accept Privacy Policy'**
  String get acceptPrivacyPolicy;

  /// No description provided for @agree.
  ///
  /// In en, this message translates to:
  /// **'Agree'**
  String get agree;

  /// No description provided for @activateDevice.
  ///
  /// In en, this message translates to:
  /// **'Activate Device'**
  String get activateDevice;

  /// No description provided for @buyPremiumAccess.
  ///
  /// In en, this message translates to:
  /// **'Buy Premium Access'**
  String get buyPremiumAccess;

  /// No description provided for @confirmOnThisDevice.
  ///
  /// In en, this message translates to:
  /// **'Confirm On This Device'**
  String get confirmOnThisDevice;

  /// No description provided for @yesDeleteMyAccount.
  ///
  /// In en, this message translates to:
  /// **'Yes, Delete My Account'**
  String get yesDeleteMyAccount;

  /// No description provided for @yesConfirmDeletionOnThisDevice.
  ///
  /// In en, this message translates to:
  /// **'Yes, Confirm Deletion On This Device'**
  String get yesConfirmDeletionOnThisDevice;

  /// No description provided for @thisCannotBeUndone.
  ///
  /// In en, this message translates to:
  /// **'This Cannot Be Undone'**
  String get thisCannotBeUndone;

  /// No description provided for @permanentlyEraseAccount.
  ///
  /// In en, this message translates to:
  /// **'Permanently erase this account, its devices, and its data'**
  String get permanentlyEraseAccount;

  /// No description provided for @premiumAccessInfo.
  ///
  /// In en, this message translates to:
  /// **'Premium Access Info'**
  String get premiumAccessInfo;

  /// No description provided for @premiumAccessOptions.
  ///
  /// In en, this message translates to:
  /// **'Premium Access Options'**
  String get premiumAccessOptions;

  /// No description provided for @openWebsite.
  ///
  /// In en, this message translates to:
  /// **'Open Win\'s VPN Website'**
  String get openWebsite;

  /// No description provided for @exploreMap.
  ///
  /// In en, this message translates to:
  /// **'Explore map'**
  String get exploreMap;

  /// No description provided for @closeMap.
  ///
  /// In en, this message translates to:
  /// **'Close map'**
  String get closeMap;

  /// No description provided for @download.
  ///
  /// In en, this message translates to:
  /// **'Download'**
  String get download;

  /// No description provided for @upload.
  ///
  /// In en, this message translates to:
  /// **'Upload'**
  String get upload;

  /// No description provided for @launchOutsideVpn.
  ///
  /// In en, this message translates to:
  /// **'Launch outside VPN'**
  String get launchOutsideVpn;

  /// No description provided for @connectVpnToLaunchOutside.
  ///
  /// In en, this message translates to:
  /// **'Connect VPN to launch outside'**
  String get connectVpnToLaunchOutside;

  /// No description provided for @useLaunchButtonOutside.
  ///
  /// In en, this message translates to:
  /// **'Use the launch button to open outside the VPN'**
  String get useLaunchButtonOutside;

  /// No description provided for @selectAppForBypassFirst.
  ///
  /// In en, this message translates to:
  /// **'Select app for bypass first'**
  String get selectAppForBypassFirst;

  /// No description provided for @iHaveSavedIt.
  ///
  /// In en, this message translates to:
  /// **'I have saved it'**
  String get iHaveSavedIt;

  /// No description provided for @wipeOnly.
  ///
  /// In en, this message translates to:
  /// **'Wipe only'**
  String get wipeOnly;

  /// No description provided for @setUpEmergencyAlert.
  ///
  /// In en, this message translates to:
  /// **'Set up emergency alert'**
  String get setUpEmergencyAlert;

  /// No description provided for @setUpEmergencyAlertLong.
  ///
  /// In en, this message translates to:
  /// **'Set up an emergency alert'**
  String get setUpEmergencyAlertLong;

  /// No description provided for @createRecoveryCode.
  ///
  /// In en, this message translates to:
  /// **'Create a recovery code'**
  String get createRecoveryCode;

  /// No description provided for @saveThisRecoveryCode.
  ///
  /// In en, this message translates to:
  /// **'Save this recovery code'**
  String get saveThisRecoveryCode;

  /// No description provided for @chooseNewUnlockCode.
  ///
  /// In en, this message translates to:
  /// **'Choose a new unlock code'**
  String get chooseNewUnlockCode;

  /// No description provided for @confirmEmergencyCode.
  ///
  /// In en, this message translates to:
  /// **'Confirm emergency code'**
  String get confirmEmergencyCode;

  /// No description provided for @emergencyCode.
  ///
  /// In en, this message translates to:
  /// **'Emergency code'**
  String get emergencyCode;

  /// No description provided for @emergencyAlert.
  ///
  /// In en, this message translates to:
  /// **'Set Up An Emergency Alert'**
  String get emergencyAlert;

  /// No description provided for @reviewPrivacyPolicyToContinue.
  ///
  /// In en, this message translates to:
  /// **'Review Privacy Policy to continue'**
  String get reviewPrivacyPolicyToContinue;

  /// No description provided for @reviewAndAcceptPrivacyPolicy.
  ///
  /// In en, this message translates to:
  /// **'Review and accept bundled Privacy Policy'**
  String get reviewAndAcceptPrivacyPolicy;

  /// No description provided for @viewBundledPrivacyPolicy.
  ///
  /// In en, this message translates to:
  /// **'View bundled Privacy Policy'**
  String get viewBundledPrivacyPolicy;

  /// No description provided for @bundledOfflinePrivacyPolicy.
  ///
  /// In en, this message translates to:
  /// **'Bundled offline Privacy Policy'**
  String get bundledOfflinePrivacyPolicy;

  /// No description provided for @tryFreeServer.
  ///
  /// In en, this message translates to:
  /// **'Try Free Server'**
  String get tryFreeServer;

  /// No description provided for @tryFreeServerLimited.
  ///
  /// In en, this message translates to:
  /// **'Try Free Server (100 Mbps upload and download)'**
  String get tryFreeServerLimited;

  /// No description provided for @freeServerLimited.
  ///
  /// In en, this message translates to:
  /// **'Free Plan: 100 Mbps upload and download'**
  String get freeServerLimited;

  /// No description provided for @freeServer.
  ///
  /// In en, this message translates to:
  /// **'Free Server'**
  String get freeServer;

  /// No description provided for @smartProtocol.
  ///
  /// In en, this message translates to:
  /// **'Smart Protocol'**
  String get smartProtocol;

  /// No description provided for @applyingVpnRouteSettings.
  ///
  /// In en, this message translates to:
  /// **'Applying VPN route settings...'**
  String get applyingVpnRouteSettings;

  /// No description provided for @connectBeforeSensitive.
  ///
  /// In en, this message translates to:
  /// **'Connect before you open or fetch anything sensitive. Until the '**
  String get connectBeforeSensitive;

  /// No description provided for @connectingOverTcpOnly.
  ///
  /// In en, this message translates to:
  /// **'Connecting over TCP only...'**
  String get connectingOverTcpOnly;

  /// No description provided for @directRouteUnavailableTryingTcp.
  ///
  /// In en, this message translates to:
  /// **'Direct route unavailable. Trying TCP...'**
  String get directRouteUnavailableTryingTcp;

  /// No description provided for @fetching.
  ///
  /// In en, this message translates to:
  /// **'Fetching...'**
  String get fetching;

  /// No description provided for @loading.
  ///
  /// In en, this message translates to:
  /// **'Loading...'**
  String get loading;

  /// No description provided for @ready.
  ///
  /// In en, this message translates to:
  /// **'Ready'**
  String get ready;

  /// No description provided for @searching.
  ///
  /// In en, this message translates to:
  /// **'Searching...'**
  String get searching;

  /// No description provided for @syncingFreeServerList.
  ///
  /// In en, this message translates to:
  /// **'Syncing free server list...'**
  String get syncingFreeServerList;

  /// No description provided for @syncingSecurityUpdates.
  ///
  /// In en, this message translates to:
  /// **'Syncing latest security updates...'**
  String get syncingSecurityUpdates;

  /// No description provided for @testing.
  ///
  /// In en, this message translates to:
  /// **'Testing'**
  String get testing;

  /// No description provided for @testingTcpFallback.
  ///
  /// In en, this message translates to:
  /// **'Testing TCP fallback...'**
  String get testingTcpFallback;

  /// No description provided for @testingUpload.
  ///
  /// In en, this message translates to:
  /// **'Testing upload...'**
  String get testingUpload;

  /// No description provided for @tryingTcpFallback.
  ///
  /// In en, this message translates to:
  /// **'Trying TCP fallback...'**
  String get tryingTcpFallback;

  /// No description provided for @usingTcpFallback.
  ///
  /// In en, this message translates to:
  /// **'Using TCP fallback...'**
  String get usingTcpFallback;

  /// No description provided for @disconnecting.
  ///
  /// In en, this message translates to:
  /// **'Disconnecting...'**
  String get disconnecting;

  /// No description provided for @maintenanceInProgress.
  ///
  /// In en, this message translates to:
  /// **'Maintenance in progress. Please wait.'**
  String get maintenanceInProgress;

  /// No description provided for @maintenanceUnderway.
  ///
  /// In en, this message translates to:
  /// **'Maintenance underway: Some servers may be offline.'**
  String get maintenanceUnderway;

  /// No description provided for @coreServerOfflineMaintenance.
  ///
  /// In en, this message translates to:
  /// **'Our core server is currently offline for maintenance.'**
  String get coreServerOfflineMaintenance;

  /// No description provided for @applyOnAndroidDevice.
  ///
  /// In en, this message translates to:
  /// **'in Settings to let the app try it. '**
  String get applyOnAndroidDevice;

  /// No description provided for @allTrafficUsesVpn.
  ///
  /// In en, this message translates to:
  /// **'All traffic currently uses the VPN.'**
  String get allTrafficUsesVpn;

  /// No description provided for @allIpv4UseVpn.
  ///
  /// In en, this message translates to:
  /// **'All IPv4 destinations will use the VPN.'**
  String get allIpv4UseVpn;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Connecting to {serverName}...'**
  String connectingTo(String serverName);

  /// No description provided for @switchingServer.
  ///
  /// In en, this message translates to:
  /// **'Switching VPN server...'**
  String get switchingServer;

  /// No description provided for @freeServerChanged.
  ///
  /// In en, this message translates to:
  /// **'Free server changed.'**
  String get freeServerChanged;

  /// No description provided for @freeServerChangedConfigSync.
  ///
  /// In en, this message translates to:
  /// **'Free server changed. Config will sync when you connect.'**
  String get freeServerChangedConfigSync;

  /// No description provided for @freeServerIsReady.
  ///
  /// In en, this message translates to:
  /// **'Free server is ready.'**
  String get freeServerIsReady;

  /// No description provided for @deviceSuccessfullyActivated.
  ///
  /// In en, this message translates to:
  /// **'Device Successfully Activated!'**
  String get deviceSuccessfullyActivated;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{count} free servers available'**
  String freeCount(int count);

  /// No description provided for @oneFreeServer.
  ///
  /// In en, this message translates to:
  /// **'1 free server available'**
  String get oneFreeServer;

  /// No description provided for @alwaysConnectOverTcp.
  ///
  /// In en, this message translates to:
  /// **'Always connect over TCP'**
  String get alwaysConnectOverTcp;

  /// No description provided for @alwaysOnVpn.
  ///
  /// In en, this message translates to:
  /// **'Always-on VPN'**
  String get alwaysOnVpn;

  /// No description provided for @allowTextAlert.
  ///
  /// In en, this message translates to:
  /// **'Allow text alert'**
  String get allowTextAlert;

  /// No description provided for @contactEmailOptional.
  ///
  /// In en, this message translates to:
  /// **'Contact email (optional)'**
  String get contactEmailOptional;

  /// No description provided for @trustedContactPhoneNumber.
  ///
  /// In en, this message translates to:
  /// **'Trusted contact phone number'**
  String get trustedContactPhoneNumber;

  /// No description provided for @optional.
  ///
  /// In en, this message translates to:
  /// **'Optional'**
  String get optional;

  /// No description provided for @requiredForTextAlert.
  ///
  /// In en, this message translates to:
  /// **'Required for the text alert'**
  String get requiredForTextAlert;

  /// No description provided for @diagnostics.
  ///
  /// In en, this message translates to:
  /// **'Diagnostics'**
  String get diagnostics;

  /// No description provided for @protocol.
  ///
  /// In en, this message translates to:
  /// **'Protocol'**
  String get protocol;

  /// No description provided for @additionalPermissions.
  ///
  /// In en, this message translates to:
  /// **'Additional permissions'**
  String get additionalPermissions;

  /// No description provided for @autoSelected.
  ///
  /// In en, this message translates to:
  /// **'Auto Selected'**
  String get autoSelected;

  /// No description provided for @doubleVpnCoreOffline.
  ///
  /// In en, this message translates to:
  /// **'Double VPN core is offline for maintenance. Connecting with standard VPN instead...'**
  String get doubleVpnCoreOffline;

  /// No description provided for @applyBypassDestinations.
  ///
  /// In en, this message translates to:
  /// **'Apply bypass destinations'**
  String get applyBypassDestinations;

  /// No description provided for @clearSearch.
  ///
  /// In en, this message translates to:
  /// **'Clear search'**
  String get clearSearch;

  /// No description provided for @destinationsOutsideVpn.
  ///
  /// In en, this message translates to:
  /// **'Destinations outside VPN (all operating systems)'**
  String get destinationsOutsideVpn;

  /// No description provided for @enterIpv4OrCidr.
  ///
  /// In en, this message translates to:
  /// **'Enter IPv4 addresses or CIDR networks. These destinations use your normal connection; everything else stays in the VPN.'**
  String get enterIpv4OrCidr;

  /// No description provided for @exampleCidr.
  ///
  /// In en, this message translates to:
  /// **'Example: 192.168.0.0/16, 203.0.113.9'**
  String get exampleCidr;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Exclude all {platform}'**
  String excludeAllApps(String platform);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Search {platform} to exclude'**
  String searchToExclude(String platform);

  /// No description provided for @noAppsMatchSearch.
  ///
  /// In en, this message translates to:
  /// **'No apps match your search.'**
  String get noAppsMatchSearch;

  /// No description provided for @appListNotReady.
  ///
  /// In en, this message translates to:
  /// **'App list is not ready yet.'**
  String get appListNotReady;

  /// No description provided for @selectThisAppForBypass.
  ///
  /// In en, this message translates to:
  /// **'Select this app for bypass before launching it.'**
  String get selectThisAppForBypass;

  /// No description provided for @linuxBypassLauncherScoped.
  ///
  /// In en, this message translates to:
  /// **'Linux bypass is launcher-scoped: connect, select an app, then use its launch button here. Apps opened normally remain protected by the VPN.'**
  String get linuxBypassLauncherScoped;

  /// No description provided for @linuxAppLaunchedOutside.
  ///
  /// In en, this message translates to:
  /// **'Linux app launched outside the VPN.'**
  String get linuxAppLaunchedOutside;

  /// No description provided for @linuxAppCouldNotLaunch.
  ///
  /// In en, this message translates to:
  /// **'The Linux app could not be launched.'**
  String get linuxAppCouldNotLaunch;

  /// No description provided for @connectFirstThenLaunchLinux.
  ///
  /// In en, this message translates to:
  /// **'Connect Win\'s VPN first, then launch the selected Linux app outside the VPN.'**
  String get connectFirstThenLaunchLinux;

  /// No description provided for @useNoMoreThan64Destinations.
  ///
  /// In en, this message translates to:
  /// **'Use no more than 64 destination networks.'**
  String get useNoMoreThan64Destinations;

  /// No description provided for @tooManyRoutes.
  ///
  /// In en, this message translates to:
  /// **'Split tunneling produced too many routes. Use broader destination ranges.'**
  String get tooManyRoutes;

  /// No description provided for @cannotExcludeAllIpv4.
  ///
  /// In en, this message translates to:
  /// **'Split tunneling cannot exclude the entire IPv4 space.'**
  String get cannotExcludeAllIpv4;

  /// No description provided for @zeroCannotBeExcluded.
  ///
  /// In en, this message translates to:
  /// **'0.0.0.0/0 cannot be excluded because it would block the VPN.'**
  String get zeroCannotBeExcluded;

  /// No description provided for @exclusionsTooManyRoutes.
  ///
  /// In en, this message translates to:
  /// **'Those exclusions produce too many routes; combine nearby networks.'**
  String get exclusionsTooManyRoutes;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Only your selected IPv4 destinations: {routes}'**
  String onlyYourIpv4(String routes);

  /// No description provided for @androidApps.
  ///
  /// In en, this message translates to:
  /// **'Android apps'**
  String get androidApps;

  /// No description provided for @linuxApps.
  ///
  /// In en, this message translates to:
  /// **'Linux apps'**
  String get linuxApps;

  /// No description provided for @windowsApps.
  ///
  /// In en, this message translates to:
  /// **'Windows apps'**
  String get windowsApps;

  /// No description provided for @perAppExplanation.
  ///
  /// In en, this message translates to:
  /// **'To show Exclude Apps From VPN, Win\'s VPN needs to access the list of installed apps on this device. The list is used only on your device to build the split-tunneling picker. The full list is not uploaded, shared, sold, or used for ads or analytics. Only package names you select for exclusion are stored locally and passed to Android VpnService. You can choose Not now and continue using the VPN without per-app exclusions.'**
  String get perAppExplanation;

  /// No description provided for @diagnosticsExplanation.
  ///
  /// In en, this message translates to:
  /// **'Records redacted connection-diagnostic information to help '**
  String get diagnosticsExplanation;

  /// No description provided for @diagnosticsOffNoFile.
  ///
  /// In en, this message translates to:
  /// **'support. When off, no diagnostic file is written.'**
  String get diagnosticsOffNoFile;

  /// No description provided for @keepUpdated.
  ///
  /// In en, this message translates to:
  /// **'Keep this app and your operating system updated.'**
  String get keepUpdated;

  /// No description provided for @thisAppResistsCensorship.
  ///
  /// In en, this message translates to:
  /// **'This app works to resist censorship, but it does not make you '**
  String get thisAppResistsCensorship;

  /// No description provided for @reachableInEverySituation.
  ///
  /// In en, this message translates to:
  /// **'reachable in every situation.'**
  String get reachableInEverySituation;

  /// No description provided for @showsWhatAppContacts.
  ///
  /// In en, this message translates to:
  /// **'tunnel is up, your network can see what the app contacts.'**
  String get showsWhatAppContacts;

  /// No description provided for @cannotVerifyAgainstAddress.
  ///
  /// In en, this message translates to:
  /// **'cannot be verified against an address.'**
  String get cannotVerifyAgainstAddress;

  /// No description provided for @resolveToPublicIpv4.
  ///
  /// In en, this message translates to:
  /// **'resolve to a public IPv4 address.'**
  String get resolveToPublicIpv4;

  /// No description provided for @anyDirectServerAddress.
  ///
  /// In en, this message translates to:
  /// **'anything directly to a server\'s own address. This is '**
  String get anyDirectServerAddress;

  /// No description provided for @directlyToServer.
  ///
  /// In en, this message translates to:
  /// **'directly to a server'**
  String get directlyToServer;

  /// No description provided for @normallyUsed.
  ///
  /// In en, this message translates to:
  /// **'normally used'**
  String get normallyUsed;

  /// No description provided for @atAllInsteadOfFallback.
  ///
  /// In en, this message translates to:
  /// **'at all instead of falling back.'**
  String get atAllInsteadOfFallback;

  /// No description provided for @removesTheFallbackRoute.
  ///
  /// In en, this message translates to:
  /// **'removes the fallback route.'**
  String get removesTheFallbackRoute;

  /// No description provided for @routeWhenDirectUnavailable.
  ///
  /// In en, this message translates to:
  /// **'route when the direct route is unavailable.'**
  String get routeWhenDirectUnavailable;

  /// No description provided for @willNotConnectAtAll.
  ///
  /// In en, this message translates to:
  /// **'will not connect at all.'**
  String get willNotConnectAtAll;

  /// No description provided for @keepsVpnRunningAndBlocks.
  ///
  /// In en, this message translates to:
  /// **'Keeps the VPN running and blocks traffic if the tunnel drops.'**
  String get keepsVpnRunningAndBlocks;

  /// No description provided for @triesDirectThenTcp.
  ///
  /// In en, this message translates to:
  /// **'Tries the direct route first, then falls back to the TCP '**
  String get triesDirectThenTcp;

  /// No description provided for @usesOnlyTcpRoute.
  ///
  /// In en, this message translates to:
  /// **'Uses only the TCP route and will never send anything '**
  String get usesOnlyTcpRoute;

  /// No description provided for @usesOnlyDirectNoFallback.
  ///
  /// In en, this message translates to:
  /// **'Uses only the direct route and will not fall back. On a '**
  String get usesOnlyDirectNoFallback;

  /// No description provided for @appWillOnlyUseTcpRoute.
  ///
  /// In en, this message translates to:
  /// **'The app will only use the TCP route, and will never send '**
  String get appWillOnlyUseTcpRoute;

  /// No description provided for @onNoFallbackLeft.
  ///
  /// In en, this message translates to:
  /// **'On: there is no fallback left. If TCP does not work on '**
  String get onNoFallbackLeft;

  /// No description provided for @networkWhereTcpFails.
  ///
  /// In en, this message translates to:
  /// **'network where TCP does not work, the app will not connect '**
  String get networkWhereTcpFails;

  /// No description provided for @networkWhereDirectFails.
  ///
  /// In en, this message translates to:
  /// **'network where the direct route does not work, the app '**
  String get networkWhereDirectFails;

  /// No description provided for @isOnSoFasterNotTried.
  ///
  /// In en, this message translates to:
  /// **'is on, so the faster direct route was not tried. Turn that setting off '**
  String get isOnSoFasterNotTried;

  /// No description provided for @onlyIsOnSoTcpNotTried.
  ///
  /// In en, this message translates to:
  /// **'only\" is on, so the TCP route was not tried. Turn that setting off in '**
  String get onlyIsOnSoTcpNotTried;

  /// No description provided for @overTcpIsOn.
  ///
  /// In en, this message translates to:
  /// **'over TCP\" is on, so the direct route was not tried. Choose a '**
  String get overTcpIsOn;

  /// No description provided for @differentServerOrTurnOff.
  ///
  /// In en, this message translates to:
  /// **'different server, or turn that setting off in Settings.'**
  String get differentServerOrTurnOff;

  /// No description provided for @clearsDeviceShowsError.
  ///
  /// In en, this message translates to:
  /// **'shows an error; it does not send any message.'**
  String get clearsDeviceShowsError;

  /// No description provided for @errorItWillNotSendMessage.
  ///
  /// In en, this message translates to:
  /// **'error: it just will not send a message.'**
  String get errorItWillNotSendMessage;

  /// No description provided for @onThisDeviceCannotSend.
  ///
  /// In en, this message translates to:
  /// **'error. On this device it CANNOT send any '**
  String get onThisDeviceCannotSend;

  /// No description provided for @messageNotPossibleHere.
  ///
  /// In en, this message translates to:
  /// **'message (that is not possible here) so no '**
  String get messageNotPossibleHere;

  /// No description provided for @textedIfYouUseTheCode.
  ///
  /// In en, this message translates to:
  /// **'texted if you use the code.'**
  String get textedIfYouUseTheCode;

  /// No description provided for @thisAppCanQuietlyText.
  ///
  /// In en, this message translates to:
  /// **'this app can quietly text your trusted contact '**
  String get thisAppCanQuietlyText;

  /// No description provided for @notifiesTrustedContact.
  ///
  /// In en, this message translates to:
  /// **'notifies a trusted contact if you are ever forced to unlock '**
  String get notifiesTrustedContact;

  /// No description provided for @youAreForcedToUnlock.
  ///
  /// In en, this message translates to:
  /// **'you are forced to unlock this device.'**
  String get youAreForcedToUnlock;

  /// No description provided for @theCodeStillClears.
  ///
  /// In en, this message translates to:
  /// **'the code still clears this device and shows the '**
  String get theCodeStillClears;

  /// No description provided for @beforeYouStart.
  ///
  /// In en, this message translates to:
  /// **'Before you start - what this protects, and what it cannot'**
  String get beforeYouStart;

  /// No description provided for @iHaveReadAndAgree.
  ///
  /// In en, this message translates to:
  /// **'I have read and agree to the Privacy Policy and understand the data handling described above.'**
  String get iHaveReadAndAgree;

  /// No description provided for @iUnderstandVpnService.
  ///
  /// In en, this message translates to:
  /// **'I understand and agree to the Android VpnService disclosure.'**
  String get iUnderstandVpnService;

  /// No description provided for @iAgreeHoldHarmless.
  ///
  /// In en, this message translates to:
  /// **'I agree to the Hold Harmless Agreement.'**
  String get iAgreeHoldHarmless;

  /// No description provided for @iAgreeLimitationOfLiability.
  ///
  /// In en, this message translates to:
  /// **'I agree to the Limitation of Liability.'**
  String get iAgreeLimitationOfLiability;

  /// No description provided for @iAgreeTermsOfService.
  ///
  /// In en, this message translates to:
  /// **'I agree to the Terms of Service.'**
  String get iAgreeTermsOfService;

  /// No description provided for @iAgreeElectronicRecords.
  ///
  /// In en, this message translates to:
  /// **'I consent to receive service records electronically.'**
  String get iAgreeElectronicRecords;

  /// No description provided for @iAgreeAllTerms.
  ///
  /// In en, this message translates to:
  /// **'I agree to the Privacy Policy, Terms of Service, Hold Harmless Agreement, Limitation of Liability, and Electronic Records consent.'**
  String get iAgreeAllTerms;

  /// No description provided for @privacyPolicyAndLegalRequired.
  ///
  /// In en, this message translates to:
  /// **'Privacy Policy and Legal Acceptance Required'**
  String get privacyPolicyAndLegalRequired;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Version {version}'**
  String privacyPolicyVersion(String version);

  /// No description provided for @copyrightNotice.
  ///
  /// In en, this message translates to:
  /// **'© 2026 Win\'s VPN Inc.'**
  String get copyrightNotice;

  /// No description provided for @planLifetime.
  ///
  /// In en, this message translates to:
  /// **'Lifetime Access'**
  String get planLifetime;

  /// No description provided for @doesNotCreateOrRenewVpn.
  ///
  /// In en, this message translates to:
  /// **'Does not create or renew VPN access'**
  String get doesNotCreateOrRenewVpn;

  /// No description provided for @accessPurchasesEmail.
  ///
  /// In en, this message translates to:
  /// **'Access purchases are instantly provisioned and emailed to you.'**
  String get accessPurchasesEmail;

  /// No description provided for @premiumAccessDescription.
  ///
  /// In en, this message translates to:
  /// **'Premium access opens the official Win\'s VPN purchase section. Store-specific billing options may be added later where required.'**
  String get premiumAccessDescription;

  /// No description provided for @appleStoreBillingNote.
  ///
  /// In en, this message translates to:
  /// **'For the Apple App Store build, use an existing Win\'s VPN account number or Try Free Server. Apple subscription options may be added through App Store billing after review.'**
  String get appleStoreBillingNote;

  /// No description provided for @googlePlayBillingNote.
  ///
  /// In en, this message translates to:
  /// **'For this Google Play build, use an existing Win\'s VPN account number or Try Free Server. Premium purchase options may be added through supported store billing where required.'**
  String get googlePlayBillingNote;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Access: {date}'**
  String accessExpires(String date);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Plan Expires: {date}'**
  String planExpires(String date);

  /// No description provided for @referralInviteBenefit.
  ///
  /// In en, this message translates to:
  /// **'Invite a friend and both accounts receive 20% extra VPN time after activation.'**
  String get referralInviteBenefit;

  /// No description provided for @likeShareSubscribe.
  ///
  /// In en, this message translates to:
  /// **'Like, share, subscribe, donate. Win for the People!'**
  String get likeShareSubscribe;

  /// No description provided for @enterSecureAccountNumber.
  ///
  /// In en, this message translates to:
  /// **'Enter Secure Account Number'**
  String get enterSecureAccountNumber;

  /// No description provided for @type12DigitAccountNumber.
  ///
  /// In en, this message translates to:
  /// **'Type the 12-digit Account Number here.'**
  String get type12DigitAccountNumber;

  /// No description provided for @setupKeyHint.
  ///
  /// In en, this message translates to:
  /// **'Setup Key (new/reinstalled devices only)'**
  String get setupKeyHint;

  /// No description provided for @accountNumberHint.
  ///
  /// In en, this message translates to:
  /// **'XXXX-XXXX-XXXX'**
  String get accountNumberHint;

  /// No description provided for @accountNumberOrSetupKeyIncorrect.
  ///
  /// In en, this message translates to:
  /// **'Account number or setup key is incorrect. Check your welcome email and try again.'**
  String get accountNumberOrSetupKeyIncorrect;

  /// No description provided for @newOrReinstalledDevice.
  ///
  /// In en, this message translates to:
  /// **'New or reinstalled device: enter the setup key from your welcome email, then click \"Activate Device\" again.'**
  String get newOrReinstalledDevice;

  /// No description provided for @fromYourWelcomeEmail.
  ///
  /// In en, this message translates to:
  /// **'From your welcome email. Not needed once this device is activated.'**
  String get fromYourWelcomeEmail;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Please type your 12-digit Account Number and set a {length}-digit PIN before clicking \"Activate Device\".'**
  String pleaseType12DigitAndPin(int length);

  /// No description provided for @pleaseType12Digit.
  ///
  /// In en, this message translates to:
  /// **'Please type your 12-digit Account Number before clicking \"Activate Device\".'**
  String get pleaseType12Digit;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Please set a {length}-digit PIN by typing it in the PIN box before activating.'**
  String setPinBeforeActivating(int length);

  /// No description provided for @setPinHereBeforeFree.
  ///
  /// In en, this message translates to:
  /// **'Please set the PIN by typing it here and click the \"Try Free Server\" button again.'**
  String get setPinHereBeforeFree;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Set your {length}-digit PIN here.'**
  String setYourPinHere(int length);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Create {length}-Digit PIN'**
  String createPinHint(int length);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{length} digits'**
  String pinDigitsHint(int length);

  /// No description provided for @freeAccessDisabled.
  ///
  /// In en, this message translates to:
  /// **'Free access is currently disabled.'**
  String get freeAccessDisabled;

  /// No description provided for @freeAccessTempUnavailable.
  ///
  /// In en, this message translates to:
  /// **'Free access is temporarily unavailable. Check your connection, or contact support if this keeps happening.'**
  String get freeAccessTempUnavailable;

  /// No description provided for @freeServerNotReachable.
  ///
  /// In en, this message translates to:
  /// **'Free server is not reachable through the protected gateway network. Please try again soon.'**
  String get freeServerNotReachable;

  /// No description provided for @freeServerSetupFailed.
  ///
  /// In en, this message translates to:
  /// **'Free server setup could not be completed. Check your connection and try again, or contact support if it keeps failing.'**
  String get freeServerSetupFailed;

  /// No description provided for @noFreeServerOnline.
  ///
  /// In en, this message translates to:
  /// **'No free server is online right now. Please try again soon.'**
  String get noFreeServerOnline;

  /// No description provided for @noFreeServersOnlineYet.
  ///
  /// In en, this message translates to:
  /// **'No free servers are online yet.'**
  String get noFreeServersOnlineYet;

  /// No description provided for @freeDeviceIdentityConflict.
  ///
  /// In en, this message translates to:
  /// **'Free-device identity conflict. Please reinstall or contact support.'**
  String get freeDeviceIdentityConflict;

  /// No description provided for @freeActivationRejected.
  ///
  /// In en, this message translates to:
  /// **'The free activation request was rejected. Please reinstall or contact support.'**
  String get freeActivationRejected;

  /// No description provided for @freeServiceMaintenance.
  ///
  /// In en, this message translates to:
  /// **'The free service is undergoing maintenance. Please try again soon.'**
  String get freeServiceMaintenance;

  /// No description provided for @tooManyFreeActivationAttempts.
  ///
  /// In en, this message translates to:
  /// **'Too many free activation attempts. Please wait a minute and try again.'**
  String get tooManyFreeActivationAttempts;

  /// No description provided for @legalAcceptanceRequired.
  ///
  /// In en, this message translates to:
  /// **'Legal acceptance is required before activation.'**
  String get legalAcceptanceRequired;

  /// No description provided for @activationFailed.
  ///
  /// In en, this message translates to:
  /// **'Activation could not be completed. Check your connection, then try again, or contact support.'**
  String get activationFailed;

  /// No description provided for @serverAtCapacity.
  ///
  /// In en, this message translates to:
  /// **'Selected server is at capacity. Please choose a different server.'**
  String get serverAtCapacity;

  /// No description provided for @vpnConfigMissing.
  ///
  /// In en, this message translates to:
  /// **'VPN config missing. Deactivate and activate again.'**
  String get vpnConfigMissing;

  /// No description provided for @authenticatedIncompleteConfig.
  ///
  /// In en, this message translates to:
  /// **'Authenticated, but server returned an incomplete VPN config. Check node registration/public key.'**
  String get authenticatedIncompleteConfig;

  /// No description provided for @invalidNumber.
  ///
  /// In en, this message translates to:
  /// **'Invalid number'**
  String get invalidNumber;

  /// No description provided for @actionFailedRetry.
  ///
  /// In en, this message translates to:
  /// **'The app could not complete that action. Please try again later.'**
  String get actionFailedRetry;

  /// No description provided for @nothingWasChanged.
  ///
  /// In en, this message translates to:
  /// **'Nothing was changed. Check your connection and try again.'**
  String get nothingWasChanged;

  /// No description provided for @couldNotReachAccountService.
  ///
  /// In en, this message translates to:
  /// **'Could not reach the account service. '**
  String get couldNotReachAccountService;

  /// No description provided for @couldNotRefreshVpnConfig.
  ///
  /// In en, this message translates to:
  /// **'Could not refresh VPN config. Check hub connection and try again.'**
  String get couldNotRefreshVpnConfig;

  /// No description provided for @couldNotOpenPaymentLink.
  ///
  /// In en, this message translates to:
  /// **'Could not open payment link.'**
  String get couldNotOpenPaymentLink;

  /// No description provided for @couldNotOpenSocialLink.
  ///
  /// In en, this message translates to:
  /// **'Could not open social link.'**
  String get couldNotOpenSocialLink;

  /// No description provided for @couldNotOpenUpdatePage.
  ///
  /// In en, this message translates to:
  /// **'Could not open the update page. Visit our website to update.'**
  String get couldNotOpenUpdatePage;

  /// No description provided for @couldNotReachHub.
  ///
  /// In en, this message translates to:
  /// **'Could not reach Wins Hub through the protected gateway network. Please try again or contact support.'**
  String get couldNotReachHub;

  /// No description provided for @couldNotCheckDeletionStatus.
  ///
  /// In en, this message translates to:
  /// **'Could not reach the account service to check deletion status. Check your connection and try again.'**
  String get couldNotCheckDeletionStatus;

  /// No description provided for @couldNotSafelyQueueCleanup.
  ///
  /// In en, this message translates to:
  /// **'Could not safely queue server cleanup. Try again before deactivating.'**
  String get couldNotSafelyQueueCleanup;

  /// No description provided for @accountDeleted.
  ///
  /// In en, this message translates to:
  /// **'Your account and its data have been deleted.'**
  String get accountDeleted;

  /// No description provided for @deviceRemovedKeysNotCleared.
  ///
  /// In en, this message translates to:
  /// **'Device removed, but some VPN keys stored on this device could not be fully cleared.'**
  String get deviceRemovedKeysNotCleared;

  /// No description provided for @deviceRemovedLocally.
  ///
  /// In en, this message translates to:
  /// **'Device was removed locally. Server cleanup will retry when the hub is reachable.'**
  String get deviceRemovedLocally;

  /// No description provided for @freeFeatureForPaid.
  ///
  /// In en, this message translates to:
  /// **'This feature is for paid users only.'**
  String get freeFeatureForPaid;

  /// No description provided for @requiredUpdate.
  ///
  /// In en, this message translates to:
  /// **'A required update is available. Please update to the latest version to continue.'**
  String get requiredUpdate;

  /// No description provided for @smartProtocolUnavailable.
  ///
  /// In en, this message translates to:
  /// **'This server has no TCP route registered yet, and \"Always connect '**
  String get smartProtocolUnavailable;

  /// No description provided for @tcpFallbackNotRegistered.
  ///
  /// In en, this message translates to:
  /// **'TCP fallback is not registered for this server yet.'**
  String get tcpFallbackNotRegistered;

  /// No description provided for @couldNotConnectOverTcp.
  ///
  /// In en, this message translates to:
  /// **'Could not connect over TCP on this network. \"Always connect over TCP\" '**
  String get couldNotConnectOverTcp;

  /// No description provided for @couldNotConnectOverUdp.
  ///
  /// In en, this message translates to:
  /// **'Could not connect over direct UDP on this network, and \"Direct (UDP) '**
  String get couldNotConnectOverUdp;

  /// No description provided for @setUpEmergencyAlertDescription.
  ///
  /// In en, this message translates to:
  /// **'Set up an emergency alert. Choose a second code that quietly '**
  String get setUpEmergencyAlertDescription;

  /// No description provided for @emergencyAlertSetup.
  ///
  /// In en, this message translates to:
  /// **'Emergency alert is set up. Your trusted contact will be '**
  String get emergencyAlertSetup;

  /// No description provided for @emergencyCodeSetup.
  ///
  /// In en, this message translates to:
  /// **'Emergency code is set up. Using it clears this device and '**
  String get emergencyCodeSetup;

  /// No description provided for @chooseSecondCode.
  ///
  /// In en, this message translates to:
  /// **'Choose a second code. If you ever enter it on '**
  String get chooseSecondCode;

  /// No description provided for @theLockScreenInstead.
  ///
  /// In en, this message translates to:
  /// **'the lock screen instead of your normal code, '**
  String get theLockScreenInstead;

  /// No description provided for @theLockScreenOrPin.
  ///
  /// In en, this message translates to:
  /// **'your approximate location, then clear itself, '**
  String get theLockScreenOrPin;

  /// No description provided for @thisDevice.
  ///
  /// In en, this message translates to:
  /// **'this device.'**
  String get thisDevice;

  /// No description provided for @contactWillBeNotified.
  ///
  /// In en, this message translates to:
  /// **'contact will be notified.'**
  String get contactWillBeNotified;

  /// No description provided for @enterConnectionCode.
  ///
  /// In en, this message translates to:
  /// **'Enter connection code'**
  String get enterConnectionCode;

  /// No description provided for @currentUnlockCode.
  ///
  /// In en, this message translates to:
  /// **'Current unlock code'**
  String get currentUnlockCode;

  /// No description provided for @enterValidPhoneNumber.
  ///
  /// In en, this message translates to:
  /// **'Enter a valid phone number for your contact.'**
  String get enterValidPhoneNumber;

  /// No description provided for @validPhoneRequired.
  ///
  /// In en, this message translates to:
  /// **'A valid phone number is required for the SMS alert'**
  String get validPhoneRequired;

  /// No description provided for @sendingTextNeedsSmsPermission.
  ///
  /// In en, this message translates to:
  /// **'Sending a text needs SMS permission, which you '**
  String get sendingTextNeedsSmsPermission;

  /// No description provided for @willBeAskedFor.
  ///
  /// In en, this message translates to:
  /// **'will be asked for. If you choose not to allow it, '**
  String get willBeAskedFor;

  /// No description provided for @itWillNotSendMessage.
  ///
  /// In en, this message translates to:
  /// **'it will just not send a message.'**
  String get itWillNotSendMessage;

  /// No description provided for @twoEmergencyCodesDoNotMatch.
  ///
  /// In en, this message translates to:
  /// **'The two emergency codes do not match.'**
  String get twoEmergencyCodesDoNotMatch;

  /// No description provided for @unlockCodeUpdated.
  ///
  /// In en, this message translates to:
  /// **'Unlock code updated.'**
  String get unlockCodeUpdated;

  /// No description provided for @thatUnlockCodeIncorrect.
  ///
  /// In en, this message translates to:
  /// **'That unlock code is not correct.'**
  String get thatUnlockCodeIncorrect;

  /// No description provided for @theEmergencyCodeCouldNotStore.
  ///
  /// In en, this message translates to:
  /// **'The emergency code could not be stored on this device. Nothing was changed.'**
  String get theEmergencyCodeCouldNotStore;

  /// No description provided for @theNewCodeCouldNotStore.
  ///
  /// In en, this message translates to:
  /// **'The new code could not be stored on this device. Nothing was changed.'**
  String get theNewCodeCouldNotStore;

  /// No description provided for @theRecoveryCodeCouldNotStore.
  ///
  /// In en, this message translates to:
  /// **'The recovery code could not be stored on this device. You can try '**
  String get theRecoveryCodeCouldNotStore;

  /// No description provided for @againFromHomeScreen.
  ///
  /// In en, this message translates to:
  /// **'again from the home screen.'**
  String get againFromHomeScreen;

  /// No description provided for @ifYouForgetUnlockCode.
  ///
  /// In en, this message translates to:
  /// **'If you forget your unlock code, this is the only way back '**
  String get ifYouForgetUnlockCode;

  /// No description provided for @useCodeFromSupport.
  ///
  /// In en, this message translates to:
  /// **'Use a code from support if the app cannot connect'**
  String get useCodeFromSupport;

  /// No description provided for @setLongerUnlockCode.
  ///
  /// In en, this message translates to:
  /// **'Set a longer unlock code'**
  String get setLongerUnlockCode;

  /// No description provided for @useLongerCode.
  ///
  /// In en, this message translates to:
  /// **'Use a longer code'**
  String get useLongerCode;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'A {length}-digit code is much harder to guess.'**
  String aLongerCodeHarderToGuess(int length);

  /// No description provided for @youHaveNoRecoveryCode.
  ///
  /// In en, this message translates to:
  /// **'You have no recovery code. Without one, forgetting your '**
  String get youHaveNoRecoveryCode;

  /// No description provided for @unlockCodeMeansLosingAccess.
  ///
  /// In en, this message translates to:
  /// **'unlock code means losing access to this app.'**
  String get unlockCodeMeansLosingAccess;

  /// No description provided for @youOpenedWithRecoveryCode.
  ///
  /// In en, this message translates to:
  /// **'You opened the app with your recovery code, so '**
  String get youOpenedWithRecoveryCode;

  /// No description provided for @unlockCodeNow.
  ///
  /// In en, this message translates to:
  /// **'unlock code now.'**
  String get unlockCodeNow;

  /// No description provided for @writeItDown.
  ///
  /// In en, this message translates to:
  /// **'Write it down, or put it in a password manager. Keep it '**
  String get writeItDown;

  /// No description provided for @somewhereSeparate.
  ///
  /// In en, this message translates to:
  /// **'somewhere separate from this device.'**
  String get somewhereSeparate;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Your unlock code is {length} digits. '**
  String yourUnlockCodeIs(int length);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'please set a new {length}-digit '**
  String pleaseSetNewPin(int length);

  /// No description provided for @unlockCodeNowPrompt.
  ///
  /// In en, this message translates to:
  /// **'unlock code now.'**
  String get unlockCodeNowPrompt;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first before {action}. Split Tunneling was not changed.'**
  String pleaseDisconnectFirst(String action);

  /// No description provided for @pleaseDisconnectDestinations.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first before changing bypass destinations. Split Tunneling was not changed.'**
  String get pleaseDisconnectDestinations;

  /// No description provided for @pleaseDisconnectApps.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first before changing excluded apps. Split Tunneling was not changed.'**
  String get pleaseDisconnectApps;

  /// No description provided for @pleaseDisconnectDoubleVpn.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first. Double VPN cannot be changed while the VPN is connected, so nothing was changed.'**
  String get pleaseDisconnectDoubleVpn;

  /// No description provided for @pleaseDisconnectTcpOnly.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first. The TCP-only setting cannot be changed while the VPN is connected, so nothing was changed.'**
  String get pleaseDisconnectTcpOnly;

  /// No description provided for @pleaseDisconnectProtocol.
  ///
  /// In en, this message translates to:
  /// **'Please disconnect the VPN first. The protocol setting cannot be '**
  String get pleaseDisconnectProtocol;

  /// No description provided for @changedWhileConnected.
  ///
  /// In en, this message translates to:
  /// **'changed while the VPN is connected, so nothing was changed.'**
  String get changedWhileConnected;

  /// No description provided for @doubleVpnCouldNotSave.
  ///
  /// In en, this message translates to:
  /// **'Double VPN could not be saved because the app could not write its settings. Nothing was changed.'**
  String get doubleVpnCouldNotSave;

  /// No description provided for @settingCouldNotSave.
  ///
  /// In en, this message translates to:
  /// **'That setting could not be saved because the app could not write its settings. Nothing was changed.'**
  String get settingCouldNotSave;

  /// No description provided for @stillDisconnectingSwitch.
  ///
  /// In en, this message translates to:
  /// **'Still disconnecting. Please try switching again in a moment.'**
  String get stillDisconnectingSwitch;

  /// No description provided for @stillDisconnecting.
  ///
  /// In en, this message translates to:
  /// **'Still disconnecting. Try again in a moment.'**
  String get stillDisconnecting;

  /// No description provided for @vpnDisconnectStillFinishing.
  ///
  /// In en, this message translates to:
  /// **'VPN disconnect is still finishing. Please wait a moment before reconnecting.'**
  String get vpnDisconnectStillFinishing;

  /// No description provided for @alwaysOnVpnIsOn.
  ///
  /// In en, this message translates to:
  /// **'Always-on VPN is on. Win'**
  String get alwaysOnVpnIsOn;

  /// No description provided for @alwaysOnVpnTurnedOff.
  ///
  /// In en, this message translates to:
  /// **'Always-on VPN turned off.'**
  String get alwaysOnVpnTurnedOff;

  /// No description provided for @alwaysOnCouldNotEnable.
  ///
  /// In en, this message translates to:
  /// **'Always-on could not be enabled by the system on this device. It may '**
  String get alwaysOnCouldNotEnable;

  /// No description provided for @alwaysOnOnlyAndroid.
  ///
  /// In en, this message translates to:
  /// **'Always-on is only available on Android. The setting is saved and will '**
  String get alwaysOnOnlyAndroid;

  /// No description provided for @needToBeEnabled.
  ///
  /// In en, this message translates to:
  /// **'need to be enabled in your system VPN settings.'**
  String get needToBeEnabled;

  /// No description provided for @willAskAgainNextTime.
  ///
  /// In en, this message translates to:
  /// **'will ask again next time. Nothing else was affected.'**
  String get willAskAgainNextTime;

  /// No description provided for @failedRouteCouldNotRemove.
  ///
  /// In en, this message translates to:
  /// **'The failed VPN route could not be removed safely. Restart the app before retrying.'**
  String get failedRouteCouldNotRemove;

  /// No description provided for @previousRouteCouldNotRemove.
  ///
  /// In en, this message translates to:
  /// **'The previous VPN route could not be removed safely. Restart the app before retrying.'**
  String get previousRouteCouldNotRemove;

  /// No description provided for @confirmationsReceived.
  ///
  /// In en, this message translates to:
  /// **'Confirmations received: '**
  String get confirmationsReceived;

  /// No description provided for @disguiseStillShowsVpn.
  ///
  /// In en, this message translates to:
  /// **'Your device will still show that a VPN is active. The disguise '**
  String get disguiseStillShowsVpn;

  /// No description provided for @hidesWhichAppRunning.
  ///
  /// In en, this message translates to:
  /// **'hides which app is running, not the fact of a VPN connection.'**
  String get hidesWhichAppRunning;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Saved addresses: {count}'**
  String savedAddresses(int count);

  /// No description provided for @speedTestUnavailable.
  ///
  /// In en, this message translates to:
  /// **'Speed test unavailable'**
  String get speedTestUnavailable;

  /// No description provided for @confirmVpn.
  ///
  /// In en, this message translates to:
  /// **'Connect'**
  String get confirmVpn;

  /// No description provided for @serverListStillSyncing.
  ///
  /// In en, this message translates to:
  /// **'Server list is still syncing.'**
  String get serverListStillSyncing;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'Last {label} test: '**
  String lastSpeedTest(String label);

  /// No description provided for @mbps.
  ///
  /// In en, this message translates to:
  /// **'Mbps'**
  String get mbps;

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{download} Mbps'**
  String downloadMbps(String download);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{upload} Mbps'**
  String uploadMbps(String upload);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{count} destination network{plural}'**
  String routeCount(int count, String plural);

  /// Count of installed apps eligible for bypass.
  ///
  /// In en, this message translates to:
  /// **'{count} apps'**
  String appCount(int count);

  /// User-visible string extracted from lib/main.dart.
  ///
  /// In en, this message translates to:
  /// **'{count} destinations'**
  String networkCount(int count);

  /// No description provided for @perAppBypassWillBypass.
  ///
  /// In en, this message translates to:
  /// **' will bypass the VPN.'**
  String get perAppBypassWillBypass;

  /// No description provided for @inThisBuild.
  ///
  /// In en, this message translates to:
  /// **'in this build'**
  String get inThisBuild;

  /// No description provided for @unsupportedInThisBuild.
  ///
  /// In en, this message translates to:
  /// **'unsupported in this build; routing to update-required, '**
  String get unsupportedInThisBuild;

  /// No description provided for @selectToEnableLauncherScoped.
  ///
  /// In en, this message translates to:
  /// **'Select to enable launcher-scoped bypass'**
  String get selectToEnableLauncherScoped;

  /// No description provided for @systemApp.
  ///
  /// In en, this message translates to:
  /// **' (system app)'**
  String get systemApp;

  /// No description provided for @shareWin.
  ///
  /// In en, this message translates to:
  /// **'Share Win'**
  String get shareWin;

  /// Accessibility label and tooltip for the per-server load bar in the server list. percent is a whole number from 0 to 100 in steps of 5, reported by the hub.
  ///
  /// In en, this message translates to:
  /// **'Server load {percent}%'**
  String serverLoadPercent(int percent);

  /// No description provided for @connectVpnAction.
  ///
  /// In en, this message translates to:
  /// **'Connect VPN'**
  String get connectVpnAction;

  /// No description provided for @disconnectVpnAction.
  ///
  /// In en, this message translates to:
  /// **'Disconnect VPN'**
  String get disconnectVpnAction;

  /// No description provided for @cancelVpnConnectionAction.
  ///
  /// In en, this message translates to:
  /// **'Cancel VPN connection'**
  String get cancelVpnConnectionAction;

  /// No description provided for @vpnConnectionInProgress.
  ///
  /// In en, this message translates to:
  /// **'VPN connection in progress'**
  String get vpnConnectionInProgress;

  /// No description provided for @cancelConnectionAction.
  ///
  /// In en, this message translates to:
  /// **'Cancel connection'**
  String get cancelConnectionAction;

  /// Accessibility label and tooltip for the per-server load bar when the hub did not report a usable load value (older hub, stale data, or a malformed value).
  ///
  /// In en, this message translates to:
  /// **'Server load unknown'**
  String get serverLoadUnknown;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'my'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'my':
      return AppLocalizationsMy();
  }

  throw FlutterError(
      'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
      'an issue with the localizations generation tool. Please file an issue '
      'on GitHub with a reproducible sample app and the gen-l10n configuration '
      'that was used.');
}
