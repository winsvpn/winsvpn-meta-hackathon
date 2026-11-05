#define MyAppName "Win's VPN"
#define MyAppPublisher "Win's VPN"
#define MyAppURL "https://winsvpn.org"
#define MyAppExeName "wins_vpn.exe"
#define TunnelServiceExeName "wins_vpn_tunnel_service.exe"
#ifndef SourceDir
  #define SourceDir "..\..\build\windows\x64\runner\Release"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\build\windows-installer"
#endif
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef ReleaseProductVersion
  #error "ReleaseProductVersion is required. Use build_installer.ps1 so it is derived from pubspec.yaml."
#endif
#ifndef ReleaseFileVersion
  #error "ReleaseFileVersion is required. Use build_installer.ps1 so it is derived from pubspec.yaml."
#endif
#ifndef DependenciesDir
  #define DependenciesDir "dependencies"
#endif
#ifdef Arm64Build
  #define SetupArchitecture "arm64"
  #define ArchitectureLabel "arm64"
  #define OutputArchitectureSuffix "-arm64"
  #define VcRedistFile "VC_redist.arm64.exe"
  #define VcRuntimeRegistryArchitecture "arm64"
  #define VcRuntimeDisplayArchitecture "Arm64"
  #define AmneziaWgMsiFile "amneziawg-arm64.msi"
  #define AmneziaWgHelperFile "amneziawg.exe"
  #define AwgToolFile "awg.exe"
  #define WintunFile "wintun.dll"
  #define XrayFile "xray.exe"
#else
  #define SetupArchitecture "x64os"
  #define ArchitectureLabel "x64"
  #define OutputArchitectureSuffix ""
  #define VcRedistFile "VC_redist.x64.exe"
  #define VcRuntimeRegistryArchitecture "x64"
  #define VcRuntimeDisplayArchitecture "x64"
  #define AmneziaWgMsiFile "amneziawg-amd64.msi"
  #define AmneziaWgHelperFile "amneziawg.exe"
  #define AwgToolFile "awg.exe"
  #define WintunFile "wintun.dll"
  #define XrayFile "xray.exe"
#endif

; Refuse direct ISCC compilation. The signed-by-default PowerShell producer
; defines EnableSigning after its freeze, architecture, and receipt gates. An
; explicitly unsigned local build defines AllowUnsignedLocal and receives a
; visibly non-public filename below.
#ifndef EnableSigning
  #ifndef AllowUnsignedLocal
    #error "Direct ISCC invocation is forbidden. Use build_installer.ps1; unsigned local builds require -AllowUnsigned."
  #endif
#endif
; Third-party licence texts. Deliberately NOT under DependenciesDir: the
; producer passes /DDependenciesDir=<payload-stage>, a directory it wipes and
; repopulates with provenance-bound, hash-verified binaries. These texts are
; repository content, not fetched payload, so they always come from the tree
; beside this script.
#ifndef LicensesDir
  #define LicensesDir "licenses"
#endif
#ifndef VcRuntimeMajor
  #define VcRuntimeMajor 14
#endif
#ifndef VcRuntimeMinor
  #define VcRuntimeMinor 44
#endif
#ifndef VcRuntimeBuild
  #define VcRuntimeBuild 35211
#endif
#ifndef VcRuntimeRevision
  #define VcRuntimeRevision 0
#endif
#ifndef AmneziaWgExeSha256
  #define AmneziaWgExeSha256 ""
#endif
#ifndef UpstreamAmneziaWgExeSha256
  #define UpstreamAmneziaWgExeSha256 ""
#endif
#ifndef AwgToolExeSha256
  #define AwgToolExeSha256 ""
#endif
#ifndef WintunDllSha256
  #define WintunDllSha256 ""
#endif

#ifndef VcRedistExpectedSha256
  #error "VcRedistExpectedSha256 is required. Use build_installer.ps1 so embedded VC_redist bytes are provenance-bound."
#endif
#ifndef VcRedistExpectedBytes
  #error "VcRedistExpectedBytes is required. Use build_installer.ps1 so embedded VC_redist bytes are provenance-bound."
#endif
#ifndef VcRedistExpectedPublisher
  #error "VcRedistExpectedPublisher is required. Use build_installer.ps1 so embedded VC_redist bytes are provenance-bound."
#endif
#ifndef VcRedistExpectedVersion
  #error "VcRedistExpectedVersion is required. Use build_installer.ps1 so embedded VC_redist bytes are provenance-bound."
#endif
#ifndef VcRedistExpectedArchitecture
  #error "VcRedistExpectedArchitecture is required. Use build_installer.ps1 so embedded VC_redist bytes are provenance-bound."
#endif
#ifndef StandaloneWinn3Release
#ifndef AmneziaWgMsiExpectedSha256
  #error "AmneziaWgMsiExpectedSha256 is required. Use build_installer.ps1 so embedded AmneziaWG MSI bytes are provenance-bound."
#endif
#ifndef AmneziaWgMsiExpectedBytes
  #error "AmneziaWgMsiExpectedBytes is required. Use build_installer.ps1 so embedded AmneziaWG MSI bytes are provenance-bound."
#endif
#ifndef AmneziaWgMsiExpectedPublisher
  #error "AmneziaWgMsiExpectedPublisher is required. Use build_installer.ps1 so embedded AmneziaWG MSI bytes are provenance-bound."
#endif
#ifndef AmneziaWgMsiExpectedVersion
  #error "AmneziaWgMsiExpectedVersion is required. Use build_installer.ps1 so embedded AmneziaWG MSI bytes are provenance-bound."
#endif
#ifndef AmneziaWgMsiExpectedArchitecture
  #error "AmneziaWgMsiExpectedArchitecture is required. Use build_installer.ps1 so embedded AmneziaWG MSI bytes are provenance-bound."
#endif
#endif

; SHA-256 of each third-party licence text this installer conveys, mirroring
; the licence-file pins tools/build_linux_release.sh applies to the Linux
; bundle (XRAY_LICENSE_SHA256, AWG_TOOLS_COPYING_SHA256).
;
; These are hardcoded rather than /D-supplied on purpose. The binary hashes
; above default to "" so the producer can inject what it downloaded and
; verified; a licence text is frozen repository content with no download step,
; so an overridable pin would only add a way to silence the check. Verified
; after install by VerifyInstalledLicences: a licence that has gone missing,
; been truncated, or been replaced fails the install rather than shipping
; unnoticed, which is the failure this whole directory exists to prevent.
#define LicensesIndexSha256 "f0126bc0bf77b08c27612fee8b3e05b64990acd86c40faea07408a9cec43a288"
#define StandaloneLicensesIndexSha256 "74970f78a35fc7b13ef358b2b624f1ea0a77e1437f280acc8e75f2ae50f194ef"
#define AwgToolsGpl2LicenceSha256 "2234a66e7f25489d8682d10d6bbb2558bb2a15e83dc4fc49048f985c85bd3cfc"
#define AmneziaWgMitLicenceSha256 "5d5a9f48d4c307fbe53b1b026da713cb5c87f63d4dfeb7a5f91edfc07927d097"
#define XrayMpl2LicenceSha256 "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
#define WintunLicenceSha256 "d9dd00871d2303b9d9172c879aeb08c3ff36e7f4e1e9ceb46b8e36c2fcddfffb"

; Exact retired payload stem used only by [InstallDelete]. Keep it composed in
; the entries below so source-policy checks can distinguish deletion of files
; left by an older release from accidentally packaging those files again.
#define WithdrawnMullvadSplitTunnelStem "mullvad-split-tunnel"

[Setup]
AppId={{B22F86C8-468C-4F61-8F77-D41E35553CF5}
AppName={#MyAppName}
AppVersion={#AppVersion}
VersionInfoProductVersion={#ReleaseProductVersion}
VersionInfoVersion={#ReleaseFileVersion}
VersionInfoProductTextVersion={#ReleaseProductVersion}
VersionInfoTextVersion={#ReleaseFileVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\WinsVPN
DefaultGroupName=Win's VPN
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
#ifdef EnableSigning
  #ifdef PartnerCenterCandidate
OutputBaseFilename=WinsVPN-PartnerCenter{#OutputArchitectureSuffix}
VersionInfoDescription=Win's VPN {#ArchitectureLabel} Partner Center Win32 installer
VersionInfoOriginalFileName=WinsVPN-PartnerCenter{#OutputArchitectureSuffix}.exe
  #else
OutputBaseFilename=WinsVPN-Setup{#OutputArchitectureSuffix}
VersionInfoDescription=Win's VPN {#ArchitectureLabel} website installer
VersionInfoOriginalFileName=WinsVPN-Setup{#OutputArchitectureSuffix}.exe
  #endif
#else
  #ifdef PartnerCenterCandidate
OutputBaseFilename=WinsVPN-UNSIGNED-LOCAL-PartnerCenter{#OutputArchitectureSuffix}
  #else
OutputBaseFilename=WinsVPN-UNSIGNED-LOCAL-Setup{#OutputArchitectureSuffix}
  #endif
#endif
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\windows\runner\resources\app_icon.ico
ArchitecturesAllowed={#SetupArchitecture}
ArchitecturesInstallIn64BitMode={#SetupArchitecture}
; Inno Setup 7.1.0 ships x86 and x64 setup loaders only (no ARM64 loader). Without this directive ISCC embeds the
; 32-bit loader, which the release freeze refuses (it requires a PE32+ x64 installer image).
SetupArchitecture=x64
#ifdef Arm64Build
; The ARM64 installer is this x64 loader around the ARM64 payload, so it needs Windows 11, the first ARM64 Windows that runs
; x64 code. Windows 10 on ARM refuses the loader itself before any Setup code runs; MinVersion makes Setup refuse with its own
; message on every ARM64 host that can start it.
MinVersion=10.0.22000
#endif
PrivilegesRequired=admin
SetupLogging=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no
#ifdef EnableSigning
SignTool=winsvpn
SignedUninstaller=yes
SignedUninstallerDir={#DependenciesDir}\signed-uninstaller-cache
#else
SignedUninstaller=no
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Older Inno releases installed these exact files under {app}; the supported
; ZIP route used the canonical Program Files\WinsVPN directory without an
; Inno AppId. Delete only these six leaf names from those two product-owned
; roots. No wildcard or directory deletion is permitted. [InstallDelete] runs
; after PrepareToInstall has safely stopped the previous privileged manager
; and before the replacement files are copied, so a locked file stops setup
; instead of being silently retained by an otherwise successful upgrade.
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}.sys"
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}.cat"
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}.inf"
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}-arm64.sys"
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}-arm64.cat"
Type: files; Name: "{app}\{#WithdrawnMullvadSplitTunnelStem}-arm64.inf"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}.sys"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}.cat"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}.inf"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}-arm64.sys"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}-arm64.cat"
Type: files; Name: "{autopf}\WinsVPN\{#WithdrawnMullvadSplitTunnelStem}-arm64.inf"

[Files]
Source: "{#DependenciesDir}\{#VcRedistFile}"; Flags: dontcopy noencryption
Source: "{#SourceDir}\{#TunnelServiceExeName}"; Flags: dontcopy noencryption
; NativeMessagingHost\ is staged into SourceDir by Build-BrowserNativeHost and
; arrives through this recursive copy. Registry keys below point at the
; generated JSON only; placeholder templates are never copied here.
; Recursive copy of the Flutter Release tree. PDB/ILK companions stay in
; private symbol custody and must never be installed. The architecture-specific
; setup declaration and producer PE gate reject mixed x64/ARM64 payloads. The producer
; fail-closes on withdrawn kernel split-tunnel SYS/CAT/INF bytes, including
; renamed or nested copies, with reviewed hashes and safe traversal before
; this wildcard is compiled.
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb,*.ilk,*.iobj,*.ipdb,*.map,*.sym,*.dbg,*.debug,*-test.exe,*_test.exe"
Source: "{#DependenciesDir}\{#WintunFile}"; DestDir: "{app}"; DestName: "wintun.dll"; Flags: ignoreversion
#ifndef StandaloneWinn3Release
Source: "{#DependenciesDir}\{#AmneziaWgMsiFile}"; Flags: dontcopy noencryption
Source: "{#DependenciesDir}\{#AmneziaWgHelperFile}"; DestDir: "{app}"; DestName: "amneziawg.exe"; Flags: ignoreversion
Source: "{#DependenciesDir}\{#AwgToolFile}"; DestDir: "{app}"; DestName: "awg.exe"; Flags: ignoreversion
Source: "{#DependenciesDir}\{#XrayFile}"; DestDir: "{app}"; DestName: "xray.exe"; Flags: ignoreversion
#endif

; Third-party licence texts for every binary installed above.
;
; Until now this installer shipped five third-party binaries and not one
; licence file. GPL-2.0 section 1 requires the notice be published on each
; copy, MPL-2.0 section 3.2 requires the licence accompany the Executable
; Form, MIT requires the copyright and permission notice be included in all
; copies, and the Wintun Prebuilt Binaries License clause 3(c) forbids
; removing its proprietary notices. Every one of those is a condition on
; distribution, so it binds the installer, not only the app UI.
;
; This mirrors tools/build_linux_release.sh, which already installs each
; licence into share/doc/wins-vpn/licenses/ under a SHA-256 pin. The Windows
; equivalent is {app}\licenses. THIRD_PARTY_NOTICES.md is the same tracked
; inventory document that build installs, under the same destination name.
; Keep this #ifdef-first branch polarity: standalone and full indexes install
; under the same name, and the standalone index must never name absent runtimes.
#ifdef StandaloneWinn3Release
Source: "{#LicensesDir}\README-STANDALONE-WINN3.txt"; DestDir: "{app}\licenses"; DestName: "README.txt"; Flags: ignoreversion
#else
Source: "{#LicensesDir}\README.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
#endif
Source: "{#LicensesDir}\Wintun-Prebuilt-Binaries-License.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
#ifndef StandaloneWinn3Release
Source: "{#LicensesDir}\amneziawg-tools-GPL-2.0.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#LicensesDir}\amneziawg-MIT.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#LicensesDir}\Xray-core-MPL-2.0.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
#endif
Source: "..\..\docs\THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md"; DestDir: "{app}\licenses"; DestName: "THIRD_PARTY_NOTICES.md"; Flags: ignoreversion

[Icons]
Name: "{group}\Win's VPN"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Win's VPN"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Native-messaging manifests are final generated JSON, never the checked-in
; placeholder templates. Subkeys match tools/native_messaging/native_host_layout.py.
; Register both registry views so a 32-bit or 64-bit browser finds the same
; signed host. uninsdeletekey removes the values on uninstall. Chrome and Edge
; keys exist only when the producer received a store-issued id; they are never
; registered against a placeholder.
Root: HKLM32; Subkey: "Software\Mozilla\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.firefox.json"; Flags: uninsdeletekey
Root: HKLM64; Subkey: "Software\Mozilla\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.firefox.json"; Flags: uninsdeletekey
#ifdef EnableChromeNativeHost
Root: HKLM32; Subkey: "Software\Google\Chrome\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.chrome.json"; Flags: uninsdeletekey
Root: HKLM64; Subkey: "Software\Google\Chrome\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.chrome.json"; Flags: uninsdeletekey
#endif
#ifdef EnableEdgeNativeHost
Root: HKLM32; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.edge.json"; Flags: uninsdeletekey
Root: HKLM64; Subkey: "Software\Microsoft\Edge\NativeMessagingHosts\org.winsvpn.bridge"; ValueType: string; ValueName: ""; ValueData: "{app}\NativeMessagingHost\org.winsvpn.bridge.edge.json"; Flags: uninsdeletekey
#endif

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,Win's VPN}"; Flags: nowait postinstall skipifsilent

[Code]
const
  VcRuntimeRequiredMajor = {#VcRuntimeMajor};
  VcRuntimeRequiredMinor = {#VcRuntimeMinor};
  VcRuntimeRequiredBuild = {#VcRuntimeBuild};
  VcRuntimeRequiredRevision = {#VcRuntimeRevision};
  FatalPostInstallExitCode = 1603;

var
  PreviousTunnelManagerNeedsRestore: Boolean;
  PreviousTunnelManagerBackup: String;
  PreviousTunnelManagerSha256: String;
  StagedTunnelManagerSha256: String;
  FatalPostInstallFailure: Boolean;

function VersionAtLeast(
  Major, Minor, Build, Revision,
  RequiredMajor, RequiredMinor, RequiredBuild, RequiredRevision: Cardinal
): Boolean;
begin
  Result :=
    (Major > RequiredMajor) or
    ((Major = RequiredMajor) and (Minor > RequiredMinor)) or
    ((Major = RequiredMajor) and (Minor = RequiredMinor) and
      (Build > RequiredBuild)) or
    ((Major = RequiredMajor) and (Minor = RequiredMinor) and
      (Build = RequiredBuild) and (Revision >= RequiredRevision));
end;

function VcRuntimeRegistryVersionAtLeast(RootKey: Integer): Boolean;
var
  Installed, Major, Minor, Build, Revision: Cardinal;
begin
  Result :=
    RegQueryDWordValue(
      RootKey,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{#VcRuntimeRegistryArchitecture}',
      'Installed',
      Installed
    ) and (Installed = 1) and
    RegQueryDWordValue(
      RootKey,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{#VcRuntimeRegistryArchitecture}',
      'Major',
      Major
    ) and
    RegQueryDWordValue(
      RootKey,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{#VcRuntimeRegistryArchitecture}',
      'Minor',
      Minor
    ) and
    RegQueryDWordValue(
      RootKey,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{#VcRuntimeRegistryArchitecture}',
      'Bld',
      Build
    ) and
    RegQueryDWordValue(
      RootKey,
      'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\{#VcRuntimeRegistryArchitecture}',
      'Rbld',
      Revision
    ) and
    VersionAtLeast(
      Major,
      Minor,
      Build,
      Revision,
      VcRuntimeRequiredMajor,
      VcRuntimeRequiredMinor,
      VcRuntimeRequiredBuild,
      VcRuntimeRequiredRevision
    );
end;

function VcRuntimeInstalledAtLeastRequired: Boolean;
begin
  Result :=
    VcRuntimeRegistryVersionAtLeast(HKLM64) or
    VcRuntimeRegistryVersionAtLeast(HKLM32);
end;

function AmneziaWgRuntimeInstalled: Boolean;
var
  RuntimeRoot: String;
begin
  RuntimeRoot := ExpandConstant('{autopf}\AmneziaWG');
  Result :=
    FileExists(RuntimeRoot + '\amneziawg.exe') and
    FileExists(RuntimeRoot + '\awg.exe') and
    FileExists(RuntimeRoot + '\wintun.dll') and
    (CompareText(
      GetSHA256OfFile(RuntimeRoot + '\amneziawg.exe'),
      '{#UpstreamAmneziaWgExeSha256}'
    ) = 0) and
    (CompareText(
      GetSHA256OfFile(RuntimeRoot + '\awg.exe'),
      '{#AwgToolExeSha256}'
    ) = 0) and
    (CompareText(
      GetSHA256OfFile(RuntimeRoot + '\wintun.dll'),
      '{#WintunDllSha256}'
    ) = 0);
end;

function WinsVpnPacketEngineIsRunning: Boolean;
var
  Locator, Services, Processes: Variant;
begin
  { PrepareToInstall runs before Inno's normal close-applications phase. Never
    mutate the shared AmneziaWG runtime while the protected packet engine is
    serving an active direct or Xray-carried tunnel. WMI failure is ambiguous
    and therefore fails closed. }
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Services := Locator.ConnectServer('.', 'root\cimv2');
    Processes := Services.ExecQuery(
      'SELECT ProcessId FROM Win32_Process ' +
      'WHERE Name = ''winsvpn_awg_engine.exe'''
    );
    Result := Processes.Count > 0;
  except
    Result := True;
  end;
end;

function ExtractFreshEmbeddedFile(
  const FileName: String;
  var ErrorText: String
): Boolean;
var
  ExtractedPath, ExtractedSha256: String;
begin
  Result := False;
  ExtractedPath := ExpandConstant('{tmp}\') + FileName;
  DeleteFile(ExtractedPath);
  try
    ExtractTemporaryFile(FileName);
    if not FileExists(ExtractedPath) then
    begin
      ErrorText := 'The embedded prerequisite was not extracted: ' + FileName;
      exit;
    end;
    ExtractedSha256 := GetSHA256OfFile(ExtractedPath);
    if Length(ExtractedSha256) <> 64 then
    begin
      DeleteFile(ExtractedPath);
      ErrorText := 'The embedded prerequisite failed SHA-256 validation: ' +
        FileName;
      exit;
    end;
    Result := True;
  except
    DeleteFile(ExtractedPath);
    ErrorText := 'Setup could not securely extract the embedded package: ' +
      FileName + '. ' + GetExceptionMessage;
  end;
end;

function ExtractVerifiedEmbeddedPrerequisite(
  const FileName, ExpectedSha256: String;
  ExpectedBytes: Integer;
  var ErrorText: String
): Boolean;
var
  ExtractedPath, ExtractedSha256: String;
  ExtractedBytes: Integer;
begin
  Result := False;
  if not ExtractFreshEmbeddedFile(FileName, ErrorText) then
    exit;
  ExtractedPath := ExpandConstant('{tmp}\') + FileName;
  if not FileSize(ExtractedPath, ExtractedBytes) or (ExtractedBytes <> ExpectedBytes) then
  begin
    DeleteFile(ExtractedPath);
    ErrorText := 'The embedded prerequisite has the wrong size: ' + FileName;
    exit;
  end;
  ExtractedSha256 := GetSHA256OfFile(ExtractedPath);
  if (Length(ExtractedSha256) <> 64) or
    (CompareText(ExtractedSha256, ExpectedSha256) <> 0) then
  begin
    DeleteFile(ExtractedPath);
    ErrorText := 'The embedded prerequisite failed SHA-256 validation: ' +
      FileName;
    exit;
  end;
  Result := True;
end;

function EmbeddedPrerequisiteMatchesExpected(
  const FilePath, ExpectedSha256: String;
  ExpectedBytes: Integer
): Boolean;
var
  ActualBytes: Integer;
begin
  Result := False;
  if not FileExists(FilePath) then
    exit;
  if not FileSize(FilePath, ActualBytes) or (ActualBytes <> ExpectedBytes) then
    exit;
  Result :=
    (Length(GetSHA256OfFile(FilePath)) = 64) and
    (CompareText(GetSHA256OfFile(FilePath), ExpectedSha256) = 0);
end;

(* Where an elevated PowerShell script is written before it runs. Never {tmp}:
  that is the installing user's own %TEMP%, which the same user's
  non-elevated processes can rewrite between the write and the elevated
  Exec. {app} is under Program Files and inherits its administrator-only
  DACL; it is created here when PrepareToInstall runs before the first file
  copy. Returns '' when it cannot be prepared, so callers fail as for any
  other staging error. Parenthesis-star delimiters on purpose: a brace
  comment would end at the first closing brace, inside {tmp}. *)
function ElevatedScriptPath(const Name: String): String;
var
  AppDir: String;
begin
  Result := '';
  AppDir := ExpandConstant('{app}');
  if not ForceDirectories(AppDir) then
    exit;
  Result := AddBackslash(AppDir) + Name;
end;

{ Browser-bridge owner receipt (R20 A1). The app's browser IPC and the
  native host both refuse to run without an owner-installed secret that an
  ordinary user cannot write: ProgramData\wins_vpn\browser_bridge.identity
  with a protected DACL (SYSTEM and Administrators full, Users read). Same
  exact format and acceptance rules as linux/packaging/install.sh and
  lib/browser_bridge_app_ipc.dart. A valid receipt is kept byte for byte; the
  secret is generated from the OS CSPRNG and never printed or logged. }
function WriteBrowserBridgeIdentityScript(const ScriptPath: String): Boolean;
begin
  Result := SaveStringToFile(ScriptPath,
    '$ErrorActionPreference=''Stop''' + #13#10 +
    'try {' + #13#10 +
    '  $root = [Environment]::GetFolderPath(''CommonApplicationData'')' + #13#10 +
    '  if ([string]::IsNullOrWhiteSpace($root)) { exit 31 }' + #13#10 +
    '  $dir = Join-Path $root ''wins_vpn''' + #13#10 +
    '  $file = Join-Path $dir ''browser_bridge.identity''' + #13#10 +
    '  $system = New-Object Security.Principal.SecurityIdentifier(''S-1-5-18'')' + #13#10 +
    '  $admins = New-Object Security.Principal.SecurityIdentifier(''S-1-5-32-544'')' + #13#10 +
    '  $users = New-Object Security.Principal.SecurityIdentifier(''S-1-5-32-545'')' + #13#10 +
    '  if (Test-Path -LiteralPath $dir) {' + #13#10 +
    '    $item = Get-Item -LiteralPath $dir -Force' + #13#10 +
    '    if (-not $item.PSIsContainer) { exit 32 }' + #13#10 +
    '    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 32 }' + #13#10 +
    '  } else {' + #13#10 +
    '    [void](New-Item -ItemType Directory -Path $dir)' + #13#10 +
    '  }' + #13#10 +
    '  $inherit = [Security.AccessControl.InheritanceFlags]''ContainerInherit,ObjectInherit''' + #13#10 +
    '  $none = [Security.AccessControl.PropagationFlags]::None' + #13#10 +
    '  $allow = [Security.AccessControl.AccessControlType]::Allow' + #13#10 +
    '  $dacl = New-Object Security.AccessControl.DirectorySecurity' + #13#10 +
    '  $dacl.SetOwner($admins)' + #13#10 +
    '  $dacl.SetAccessRuleProtection($true, $false)' + #13#10 +
    '  $dacl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, ''FullControl'', $inherit, $none, $allow)))' + #13#10 +
    '  $dacl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins, ''FullControl'', $inherit, $none, $allow)))' + #13#10 +
    '  $dacl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, ''ReadAndExecute'', $inherit, $none, $allow)))' + #13#10 +
    '  Set-Acl -LiteralPath $dir -AclObject $dacl' + #13#10 +
    '  $valid = $false' + #13#10 +
    '  if (Test-Path -LiteralPath $file) {' + #13#10 +
    '    $leaf = Get-Item -LiteralPath $file -Force' + #13#10 +
    '    if ($leaf.PSIsContainer) { exit 33 }' + #13#10 +
    '    if (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 33 }' + #13#10 +
    '    try {' + #13#10 +
    '      $raw = [IO.File]::ReadAllText($file)' + #13#10 +
    '      if ($raw -cmatch ''^\{"v":1,"secret":"[0-9a-f]{64}"\}$'') { $valid = $true }' + #13#10 +
    '    } catch { $valid = $false }' + #13#10 +
    '  }' + #13#10 +
    '  if (-not $valid) {' + #13#10 +
    '    $bytes = New-Object byte[] 32' + #13#10 +
    '    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()' + #13#10 +
    '    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }' + #13#10 +
    '    $hex = -join ($bytes | ForEach-Object { $_.ToString(''x2'') })' + #13#10 +
    '    $tmp = $file + ''.tmp''' + #13#10 +
    '    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }' + #13#10 +
    '    [IO.File]::WriteAllText($tmp, ''{"v":1,"secret":"'' + $hex + ''"}'', (New-Object Text.UTF8Encoding($false)))' + #13#10 +
    '    Move-Item -LiteralPath $tmp -Destination $file -Force' + #13#10 +
    '    $hex = $null' + #13#10 +
    '  }' + #13#10 +
    '  $facl = New-Object Security.AccessControl.FileSecurity' + #13#10 +
    '  $facl.SetOwner($admins)' + #13#10 +
    '  $facl.SetAccessRuleProtection($true, $false)' + #13#10 +
    '  $facl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, ''FullControl'', $allow)))' + #13#10 +
    '  $facl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($admins, ''FullControl'', $allow)))' + #13#10 +
    '  $facl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, ''Read'', $allow)))' + #13#10 +
    '  Set-Acl -LiteralPath $file -AclObject $facl' + #13#10 +
    '  exit 0' + #13#10 +
    '} catch { exit 30 }' + #13#10,
    False);
end;

{ Not fatal: without the receipt the VPN works and the browser bridge stays
  closed (status app_not_running), which is the fail-closed direction. }
procedure InstallBrowserBridgeIdentity;
var
  ResultCode: Integer;
  ScriptPath: String;
  Tool: String;
begin
  Tool := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  ScriptPath := ElevatedScriptPath('winsvpn-browser-bridge-identity.ps1');
  if ScriptPath <> '' then
    DeleteFile(ScriptPath);
  if (ScriptPath = '') or (not FileExists(Tool)) or
    (not WriteBrowserBridgeIdentityScript(ScriptPath)) then
  begin
    Log('Browser bridge owner receipt: tooling unavailable; bridge stays closed.');
    exit;
  end;
  ResultCode := -1;
  if (not Exec(
    Tool,
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
      ScriptPath + '"',
    ExpandConstant('{tmp}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  )) or (ResultCode <> 0) then
    Log('Browser bridge owner receipt was not issued (exit ' +
      IntToStr(ResultCode) + '); the browser bridge stays closed.')
  else
    Log('Browser bridge owner receipt is in place.');
  DeleteFile(ScriptPath);
end;

function WritePrerequisiteVerifierScript(const ScriptPath: String): Boolean;
begin
  Result := SaveStringToFile(ScriptPath,
    'param([Parameter(Mandatory=$true)][string]$Path,' + #13#10 +
    '[Parameter(Mandatory=$true)][string]$Publisher,' + #13#10 +
    '[Parameter(Mandatory=$true)][string]$Version,' + #13#10 +
    '[Parameter(Mandatory=$true)][string]$Architecture,' + #13#10 +
    '[Parameter(Mandatory=$true)][string]$Kind)' + #13#10 +
    '$ErrorActionPreference=''Stop''' + #13#10 +
    'try {' + #13#10 +
    '  $item = Get-Item -LiteralPath $Path -Force' + #13#10 +
    '  if ($item.PSIsContainer) { exit 21 }' + #13#10 +
    '  if ($item.LinkType) { exit 21 }' + #13#10 +
    '  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 21 }' + #13#10 +
    '  $sig = Get-AuthenticodeSignature -LiteralPath $Path' + #13#10 +
    '  if ($sig.Status -ne ''Valid'' -or -not $sig.SignerCertificate) { exit 22 }' + #13#10 +
    '  if ([string]$sig.SignerCertificate.Subject -cne $Publisher) { exit 23 }' + #13#10 +
    '  if ($Kind -eq ''vc_redist'') {' + #13#10 +
    '    $vi = $item.VersionInfo' + #13#10 +
    '    if ([string]$vi.FileVersion -cne $Version) { exit 24 }' + #13#10 +
    '    if ([string]$vi.ProductVersion -cne $Version) { exit 24 }' + #13#10 +
    '    if ($Architecture -eq ''arm64'') {' + #13#10 +
    '      if ([string]$vi.OriginalFilename -cne ''VC_redist.arm64.exe'') { exit 25 }' + #13#10 +
    '    } else {' + #13#10 +
    '      if ([string]$vi.OriginalFilename -cne ''VC_redist.x64.exe'') { exit 25 }' + #13#10 +
    '    }' + #13#10 +
    '  } elseif ($Kind -eq ''amneziawg_msi'') {' + #13#10 +
    '    $installer = New-Object -ComObject WindowsInstaller.Installer' + #13#10 +
    '    $database = $installer.GetType().InvokeMember(''OpenDatabase'',' +
    ' [Reflection.BindingFlags]::InvokeMethod, $null, $installer, @($Path, 0))' + #13#10 +
    '    $view = $database.GetType().InvokeMember(''OpenView'',' +
    ' [Reflection.BindingFlags]::InvokeMethod, $null, $database,' +
    ' @(''SELECT `Value` FROM `Property` WHERE `Property`=''''ProductVersion''''''))' + #13#10 +
    '    [void]$view.GetType().InvokeMember(''Execute'',' +
    ' [Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)' + #13#10 +
    '    $record = $view.GetType().InvokeMember(''Fetch'',' +
    ' [Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)' + #13#10 +
    '    if ($null -eq $record) { exit 24 }' + #13#10 +
    '    $productVersion = [string]$record.GetType().InvokeMember(''StringData'',' +
    ' [Reflection.BindingFlags]::GetProperty, $null, $record, @(1))' + #13#10 +
    '    if ($productVersion -cne $Version) { exit 24 }' + #13#10 +
    '    $summary = $database.GetType().InvokeMember(''SummaryInformation'',' +
    ' [Reflection.BindingFlags]::GetProperty, $null, $database, $null)' + #13#10 +
    '    $template = [string]$summary.GetType().InvokeMember(''Property'',' +
    ' [Reflection.BindingFlags]::GetProperty, $null, $summary, @(7))' + #13#10 +
    '    $isArm = $template -match ''(?i)Arm64''' + #13#10 +
    '    $isX64 = $template -match ''(?i)(x64|Intel64|AMD64)''' + #13#10 +
    '    if ($Architecture -eq ''arm64'') { if (-not $isArm -or $isX64) { exit 25 } }' + #13#10 +
    '    elseif ($Architecture -eq ''x64'') { if (-not $isX64 -or $isArm) { exit 25 } }' + #13#10 +
    '    else { exit 25 }' + #13#10 +
    '  } else { exit 26 }' + #13#10 +
    '  exit 0' + #13#10 +
    '} catch { exit 27 }' + #13#10,
    False);
end;

function VerifyEmbeddedPrerequisiteIdentity(
  const FilePath, ExpectedSha256, ExpectedPublisher, ExpectedVersion,
    ExpectedArchitecture, Kind: String;
  ExpectedBytes: Integer;
  var ErrorText: String
): Boolean;
var
  Tool, ScriptPath, Args: String;
  ResultCode: Integer;
begin
  Result := False;
  if not EmbeddedPrerequisiteMatchesExpected(FilePath, ExpectedSha256, ExpectedBytes) then
  begin
    ErrorText := 'The embedded prerequisite differs from the reviewed identity: ' +
      ExtractFileName(FilePath);
    exit;
  end;
  Tool := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  if not FileExists(Tool) then
  begin
    ErrorText := 'Prerequisite verification tooling is missing.';
    exit;
  end;
  ScriptPath := ElevatedScriptPath('winsvpn-prereq-verify.ps1');
  if ScriptPath <> '' then
    DeleteFile(ScriptPath);
  if (ScriptPath = '') or (not WritePrerequisiteVerifierScript(ScriptPath)) then
  begin
    ErrorText := 'Prerequisite verification tooling could not be staged.';
    exit;
  end;
  Args :=
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    ScriptPath + '" -Path "' + FilePath + '" -Publisher "' +
    ExpectedPublisher + '" -Version "' + ExpectedVersion +
    '" -Architecture "' + ExpectedArchitecture + '" -Kind "' + Kind + '"';
  ResultCode := -1;
  if not Exec(
    Tool,
    Args,
    ExpandConstant('{tmp}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
  begin
    DeleteFile(ScriptPath);
    ErrorText := 'Prerequisite verification tooling failed to start.';
    exit;
  end;
  DeleteFile(ScriptPath);
  if ResultCode <> 0 then
  begin
    ErrorText :=
      'The embedded prerequisite has the wrong Authenticode signer, version, ' +
      'or architecture, or verification tooling failed. Exit code: ' +
      IntToStr(ResultCode);
    exit;
  end;
  if not EmbeddedPrerequisiteMatchesExpected(FilePath, ExpectedSha256, ExpectedBytes) then
  begin
    ErrorText := 'The embedded prerequisite changed during identity verification: ' +
      ExtractFileName(FilePath);
    exit;
  end;
  Result := True;
end;

function ValidateStagedTunnelManager(var ErrorText: String): Boolean;
var
  ResultCode: Integer;
  StagedService: String;
begin
  Result := False;
  if not ExtractFreshEmbeddedFile('{#TunnelServiceExeName}', ErrorText) then
    exit;
  StagedService := ExpandConstant('{tmp}\{#TunnelServiceExeName}');
  StagedTunnelManagerSha256 := GetSHA256OfFile(StagedService);
  if Length(StagedTunnelManagerSha256) <> 64 then
  begin
    ErrorText := 'The staged tunnel-manager payload lacks exact SHA-256 identity.';
    exit;
  end;
  ResultCode := -1;
  if not Exec(
    StagedService,
    '--protocol-self-test',
    ExpandConstant('{tmp}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) or (ResultCode <> 0) then
  begin
    ErrorText :=
      'The new protected tunnel-manager payload failed its readiness test. ' +
      'Exit code: ' + IntToStr(ResultCode);
    exit;
  end;
  Result := True;
end;

function RestorePreviousTunnelManager: Boolean;
var
  ExistingService: String;
  ResultCode: Integer;
begin
  Result := not PreviousTunnelManagerNeedsRestore;
  if Result then
    exit;

  ExistingService := ExpandConstant('{app}\{#TunnelServiceExeName}');
  ResultCode := -1;
  if (not FileExists(PreviousTunnelManagerBackup)) or
    (CompareText(
      GetSHA256OfFile(PreviousTunnelManagerBackup),
      PreviousTunnelManagerSha256
    ) <> 0) then
  begin
    Log('Previous tunnel-manager restoration rejected an invalid backup.');
    exit;
  end;
  if FileExists(ExistingService) and (not DeleteFile(ExistingService)) then
  begin
    Log('Previous tunnel-manager restoration could not replace the service binary.');
    exit;
  end;
  if (not FileCopy(PreviousTunnelManagerBackup, ExistingService, False)) or
    (CompareText(GetSHA256OfFile(ExistingService),
      PreviousTunnelManagerSha256) <> 0) then
  begin
    Log('Previous tunnel-manager restoration failed exact binary recovery.');
    exit;
  end;
  Result := Exec(
    ExistingService,
    '--install',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) and (ResultCode = 0);
  if Result then
  begin
    PreviousTunnelManagerNeedsRestore := False;
    DeleteFile(PreviousTunnelManagerBackup);
    Log('Previous tunnel manager was restored after an interrupted upgrade.');
  end
  else
    Log('Previous tunnel-manager service registration could not be restored.');
end;

function RemovePreviousTunnelManagerForUpgrade(var ErrorText: String): Boolean;
var
  ExistingService: String;
  ResultCode: Integer;
begin
  Result := False;
  ExistingService := ExpandConstant('{app}\{#TunnelServiceExeName}');
  if not FileExists(ExistingService) then
  begin
    Result := True;
    exit;
  end;

  PreviousTunnelManagerBackup :=
    ExpandConstant('{tmp}\winsvpn-previous-tunnel-manager.exe');
  DeleteFile(PreviousTunnelManagerBackup);
  PreviousTunnelManagerSha256 := GetSHA256OfFile(ExistingService);
  if (Length(PreviousTunnelManagerSha256) <> 64) or
    (not FileCopy(ExistingService, PreviousTunnelManagerBackup, False)) or
    (CompareText(
      GetSHA256OfFile(PreviousTunnelManagerBackup),
      PreviousTunnelManagerSha256
    ) <> 0) then
  begin
    DeleteFile(PreviousTunnelManagerBackup);
    ErrorText :=
      'Setup could not create an exact rollback copy of the previous tunnel manager.';
    exit;
  end;

  PreviousTunnelManagerNeedsRestore := True;
  WizardForm.StatusLabel.Caption :=
    'Stopping the previous Win''s VPN tunnel manager...';
  ResultCode := -1;
  if not Exec(
    ExistingService,
    '--uninstall',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) or (ResultCode <> 0) then
  begin
    if RestorePreviousTunnelManager then
      ErrorText :=
        'The previous tunnel manager could not be stopped safely and was restored.'
    else
      ErrorText :=
        'The previous tunnel manager could not be stopped or restored safely. ' +
        'Setup will not replace privileged files.';
    exit;
  end;
  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  RestartPending: Boolean;
  VcRedistPath, AmneziaMsiPath: String;
begin
  Result := '';
  ResultCode := -1;
  RestartPending := False;
  VcRedistPath := ExpandConstant('{tmp}\{#VcRedistFile}');
  if not ExtractVerifiedEmbeddedPrerequisite(
    '{#VcRedistFile}', '{#VcRedistExpectedSha256}', {#VcRedistExpectedBytes}, Result
  ) then
    exit;
#ifndef StandaloneWinn3Release
  AmneziaMsiPath := ExpandConstant('{tmp}\{#AmneziaWgMsiFile}');
  if not ExtractVerifiedEmbeddedPrerequisite(
    '{#AmneziaWgMsiFile}', '{#AmneziaWgMsiExpectedSha256}',
    {#AmneziaWgMsiExpectedBytes}, Result
  ) then
    exit;
#endif
  if not VerifyEmbeddedPrerequisiteIdentity(
    VcRedistPath,
    '{#VcRedistExpectedSha256}',
    '{#VcRedistExpectedPublisher}',
    '{#VcRedistExpectedVersion}',
    '{#VcRedistExpectedArchitecture}',
    'vc_redist',
    {#VcRedistExpectedBytes},
    Result
  ) then
    exit;
#ifndef StandaloneWinn3Release
  if not VerifyEmbeddedPrerequisiteIdentity(
    AmneziaMsiPath,
    '{#AmneziaWgMsiExpectedSha256}',
    '{#AmneziaWgMsiExpectedPublisher}',
    '{#AmneziaWgMsiExpectedVersion}',
    '{#AmneziaWgMsiExpectedArchitecture}',
    'amneziawg_msi',
    {#AmneziaWgMsiExpectedBytes},
    Result
  ) then
    exit;

  if WinsVpnPacketEngineIsRunning then
  begin
    Result :=
      'An active Win''s VPN tunnel is still using the packet engine. ' +
      'Disconnect the VPN and rerun setup; no prerequisite or privileged ' +
      'payload was changed.';
    exit;
  end;
#endif

  if not VcRuntimeInstalledAtLeastRequired then
  begin
    if not EmbeddedPrerequisiteMatchesExpected(
      VcRedistPath, '{#VcRedistExpectedSha256}', {#VcRedistExpectedBytes}
    ) then
    begin
      Result := 'The embedded VC runtime prerequisite changed before execution.';
      exit;
    end;
    WizardForm.StatusLabel.Caption :=
      'Installing Microsoft Visual C++ Runtime...';
    ResultCode := -1;
    if not Exec(
      VcRedistPath,
      '/install /quiet /norestart',
      ExpandConstant('{tmp}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) then
    begin
      Result :=
        'The required Microsoft Visual C++ Runtime could not be started.';
      exit;
    end;
    if ResultCode = 3010 then
      RestartPending := True;
    if not ((ResultCode = 0) or (ResultCode = 3010) or
      ((ResultCode = 1638) and VcRuntimeInstalledAtLeastRequired)) then
    begin
      Result :=
        'The required Microsoft Visual C++ Runtime installation failed. ' +
        'Exit code: ' + IntToStr(ResultCode);
      exit;
    end;
    if not VcRuntimeInstalledAtLeastRequired then
    begin
      Result :=
        'Microsoft Visual C++ Runtime did not register the required {#VcRuntimeDisplayArchitecture} version.';
      exit;
    end;
  end;

#ifndef StandaloneWinn3Release
  if not EmbeddedPrerequisiteMatchesExpected(
    AmneziaMsiPath, '{#AmneziaWgMsiExpectedSha256}', {#AmneziaWgMsiExpectedBytes}
  ) then
  begin
    Result := 'The embedded AmneziaWG MSI prerequisite changed before execution.';
    exit;
  end;
  WizardForm.StatusLabel.Caption :=
    'Installing AmneziaWG Windows tunnel engine...';
  { Keep a verified shared runtime untouched on reinstall, as the ZIP
    installer does. A silent MSI can wait indefinitely when another
    application has the AmneziaWG service or files open. }
  if not AmneziaWgRuntimeInstalled then
  begin
    ResultCode := -1;
    if not Exec(
      ExpandConstant('{sys}\msiexec.exe'),
      '/i "' + AmneziaMsiPath +
        '" /qn /norestart DO_NOT_LAUNCH=1',
      ExpandConstant('{tmp}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) or not ((ResultCode = 0) or (ResultCode = 3010)) then
    begin
      Result :=
        'The pinned AmneziaWG tunnel-engine installation failed. ' +
        'Exit code: ' + IntToStr(ResultCode);
      exit;
    end;
    if ResultCode = 3010 then
      RestartPending := True;
  end;
  if not AmneziaWgRuntimeInstalled then
  begin
    Result :=
      'AmneziaWG setup completed without registering the required {#VcRuntimeDisplayArchitecture} runtime.';
    exit;
  end;
#endif

  WizardForm.StatusLabel.Caption :=
    'Validating the new protected tunnel manager...';
  if not ValidateStagedTunnelManager(Result) then
    exit;

  { Destructive upgrade work is deliberately last. All shared prerequisites
    and the exact staged replacement have already passed readiness checks. }
  if not RemovePreviousTunnelManagerForUpgrade(Result) then
    exit;
  { Publish the reboot outcome only after the complete preparation and
    recoverable upgrade transition succeeded. A later fatal error must not be
    reported to automation as a successful reboot-required installation. }
  NeedsRestart := RestartPending;
end;

procedure RaiseFatalPostInstallException(const MessageText: String);
begin
  FatalPostInstallFailure := True;
  Log('Fail-closed post-install error: ' + MessageText);
  RaiseException(MessageText);
end;

procedure VerifyInstalledLicence(const FileName, ExpectedSha256: String);
var
  FullPath: String;
begin
  FullPath := ExpandConstant('{app}\licenses\') + FileName;
  if not FileExists(FullPath) then
    RaiseFatalPostInstallException(
      'A third-party licence this release is required to convey is missing ' +
      'from the installation: licenses\' + FileName + '.'
    );
  if CompareText(GetSHA256OfFile(FullPath), ExpectedSha256) <> 0 then
    RaiseFatalPostInstallException(
      'A third-party licence in this installation does not match the exact ' +
      'text this release was built to convey: licenses\' + FileName + '.'
    );
end;

procedure VerifyInstalledLicences;
begin
  { Fail-closed for the same reason tools/build_linux_release.sh exits 65 on a
    licence hash mismatch. Distribution of these binaries is conditioned on
    conveying these notices, so an installation that silently lost one is not
    a lesser install, it is an unlicensed one. The texts are compiled into
    Setup and decompressed under Inno's own integrity checking, so a mismatch
    here means a tampered or truncated install rather than a field fault. }
#ifdef StandaloneWinn3Release
  VerifyInstalledLicence(
    'README.txt', '{#StandaloneLicensesIndexSha256}');
#else
  VerifyInstalledLicence('README.txt', '{#LicensesIndexSha256}');
#endif
  VerifyInstalledLicence(
    'Wintun-Prebuilt-Binaries-License.txt', '{#WintunLicenceSha256}');
#ifndef StandaloneWinn3Release
  VerifyInstalledLicence(
    'amneziawg-tools-GPL-2.0.txt', '{#AwgToolsGpl2LicenceSha256}');
  VerifyInstalledLicence(
    'amneziawg-MIT.txt', '{#AmneziaWgMitLicenceSha256}');
  VerifyInstalledLicence(
    'Xray-core-MPL-2.0.txt', '{#XrayMpl2LicenceSha256}');
#endif

  { Presence only, deliberately. THIRD_PARTY_NOTICES.md is this project's own
    generated component inventory, not an upstream licence text: it changes
    legitimately whenever any component version does, so pinning its hash here
    would turn an ordinary inventory edit into a broken installer. The five
    selected index and licence files above are pinned; README.txt is this
    project's variant-specific index and the other files carry third-party
    licence terms. }
  if not FileExists(ExpandConstant('{app}\licenses\THIRD_PARTY_NOTICES.md')) then
    RaiseFatalPostInstallException(
      'The third-party component inventory is missing from the ' +
      'installation: licenses\THIRD_PARTY_NOTICES.md.'
    );
end;

procedure VerifyInstalledWintunRuntime;
begin
  if (not FileExists(ExpandConstant('{app}\wintun.dll'))) or
    (CompareText(
      GetSHA256OfFile(ExpandConstant('{app}\wintun.dll')),
      '{#WintunDllSha256}'
    ) <> 0) then
    RaiseFatalPostInstallException(
      'The installed Wintun runtime differs from the exact signed payload ' +
      'selected by this release.'
    );
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    exit;

  { Arm before any post-install work so an unexpected exception is also
    reported to automation as a deterministic fatal setup failure. }
  FatalPostInstallFailure := True;
  ResultCode := -1;

  { First, and before any privileged service work: the licences that permit
    this installation to have placed those binaries on disk at all. }
  WizardForm.StatusLabel.Caption :=
    'Verifying third-party licence notices...';
  VerifyInstalledLicences;
  VerifyInstalledWintunRuntime;

#ifndef StandaloneWinn3Release
  if (not FileExists(ExpandConstant('{app}\amneziawg.exe'))) or
    (CompareText(
      GetSHA256OfFile(ExpandConstant('{app}\amneziawg.exe')),
      '{#AmneziaWgExeSha256}'
    ) <> 0) then
    RaiseFatalPostInstallException(
      'The installed AmneziaWG maintenance helper differs from the exact ' +
      'Go 1.27.1, Authenticode-signed payload selected by this release.'
    );
#endif

  WizardForm.StatusLabel.Caption :=
    'Installing the protected Win''s VPN tunnel manager...';
  if (not FileExists(ExpandConstant('{app}\{#TunnelServiceExeName}'))) or
    (CompareText(
      GetSHA256OfFile(ExpandConstant('{app}\{#TunnelServiceExeName}')),
      StagedTunnelManagerSha256
  ) <> 0) then
  begin
    if RestorePreviousTunnelManager then
      RaiseFatalPostInstallException(
        'The installed tunnel-manager payload differs from the tested staged ' +
        'payload. The previous tunnel manager was restored.'
      )
    else
      RaiseFatalPostInstallException(
        'The installed tunnel-manager payload differs from the tested staged ' +
        'payload and the previous manager could not be restored.'
      );
  end;
  if not Exec(
    ExpandConstant('{app}\{#TunnelServiceExeName}'),
    '--install',
    ExpandConstant('{app}'),
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) or (ResultCode <> 0) then
  begin
    { A failed start must not leave a partially registered privileged service. }
    Exec(
      ExpandConstant('{app}\{#TunnelServiceExeName}'),
      '--uninstall',
      ExpandConstant('{app}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    );
    if RestorePreviousTunnelManager then
      RaiseFatalPostInstallException(
        'The new protected tunnel manager failed to install or start. ' +
        'The previous tunnel manager was restored.'
      )
    else
      RaiseFatalPostInstallException(
        'The new protected tunnel manager failed and the previous tunnel ' +
        'manager could not be restored. Setup stopped before launching the app.'
      );
  end;
  PreviousTunnelManagerNeedsRestore := False;
  if (PreviousTunnelManagerBackup <> '') and
    FileExists(PreviousTunnelManagerBackup) and
    (not DeleteFile(PreviousTunnelManagerBackup)) then
    RaiseFatalPostInstallException(
      'The previous tunnel-manager rollback backup could not be removed safely.'
    );
  WizardForm.StatusLabel.Caption :=
    'Preparing the browser extension bridge...';
  InstallBrowserBridgeIdentity;
  { Clear last, only after the service is installed, rollback ownership has
    been committed, and any previous-manager backup has been removed. }
  FatalPostInstallFailure := False;
end;

function GetCustomSetupExitCode: Integer;
begin
  if FatalPostInstallFailure then
    Result := FatalPostInstallExitCode
  else
    Result := 0;
end;

procedure DeinitializeSetup;
begin
  if PreviousTunnelManagerNeedsRestore and
    (not RestorePreviousTunnelManager) then
  begin
    FatalPostInstallFailure := True;
    SuppressibleMsgBox(
      'Setup was interrupted after stopping the previous tunnel manager, and ' +
      'automatic restoration failed. Re-run the last known-good installer ' +
      'before using Win''s VPN.',
      mbCriticalError,
      MB_OK,
      IDOK
    );
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if not Exec(
      ExpandConstant('{app}\{#TunnelServiceExeName}'),
      '--uninstall',
      ExpandConstant('{app}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode
    ) or (ResultCode <> 0) then
      RaiseException(
        'Win''s VPN could not safely stop its tunnel manager and remove the ' +
        'tunnel service. The uninstall was stopped before deleting the ' +
        'privileged service payload.'
      );
    { The Microsoft VC runtime and AmneziaWG MSI are shared machine
      prerequisites. Win's VPN does not claim exclusive ownership and never
      removes or downgrades them during uninstall. }
    Log(
      'Retaining shared prerequisites: Microsoft VC runtime and AmneziaWG MSI.'
    );
  end;
end;
