================================================================================
Win's VPN for Windows -- third-party component notice
third-party licences -- index
================================================================================

Win's VPN for Windows ships the third-party components listed below. Each is
covered by the licence file named beside it. Those files preserve the required
upstream licence text and may also include Win's VPN explanatory headers.

  awg.exe                       amneziawg-tools-GPL-2.0.txt
  amneziawg.exe                 amneziawg-MIT.txt
  xray.exe                      Xray-core-MPL-2.0.txt
  wintun.dll                    architecture-specific x64 or ARM64 binary;
                                Wintun-Prebuilt-Binaries-License.txt

  THIRD_PARTY_NOTICES.md        the full component inventory: exact pinned
                                versions, commits and SHA-256 hashes for every
                                component above, plus the notices for the
                                application's own package dependencies.

Wintun is the one component here that is NOT open source. It is proprietary
software licensed by WireGuard LLC, redistributed unmodified and used only
through its documented API, as its licence requires. Read
Wintun-Prebuilt-Binaries-License.txt for the terms that bind you as a
recipient.

SOURCE CODE. Two of these components carry source-availability obligations.
The accompanying notices specify how source may be obtained:

  * amneziawg-tools is under GPL-2.0. A written offer valid for three years
    from the date you received these binaries is set out in
    amneziawg-tools-GPL-2.0.txt. Request source from support@winsvpn.org.

  * Xray-core is under MPL-2.0. Its Source Code Form is available at
    https://github.com/XTLS/Xray-core/tree/v26.9.30 and on request to
    support@winsvpn.org.

The application also shows these notices on screen, together with the notices
for its Dart and Flutter package dependencies, at
Settings -> Open source licences.

INTEGRITY. Every licence file in this folder is verified against a SHA-256
pinned in the installer script and is checked again after installation. A
licence that has gone missing, been truncated, or been replaced fails the
install rather than passing unnoticed.
