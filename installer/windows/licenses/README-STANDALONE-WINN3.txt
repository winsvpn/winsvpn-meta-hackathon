================================================================================
Win's VPN standalone Winn Protocol v3 engine payload for Windows
third-party licence navigation index
================================================================================

This index applies only to the standalone Winn Protocol v3 engine payload. It
does not describe the full Win's VPN installer.

The payload redistributes this third-party binary as a separate file:

  wintun.dll                    architecture-specific x64 or ARM64 binary;
                                Wintun-Prebuilt-Binaries-License.txt

Wintun is proprietary software licensed by WireGuard LLC. It is redistributed
unmodified and used through its documented API. Read
Wintun-Prebuilt-Binaries-License.txt for the terms that accompany the binary.

The payload also contains the first-party winn-datapath.exe and
winsvpn_winn3_engine.exe programs. Those programs contain statically linked
third-party Go modules. This navigation index does not claim that Wintun is the
only third-party code in those executables.

The standalone payload's complete notices and source-offer bundle is not yet
staged and verified. Do not distribute this package as a release artifact until
that legal bundle is complete and bound to the exact executable bytes.

This variant intentionally does not install amneziawg.exe, awg.exe, xray.exe,
or their separate licence files. Their presence in the full product's index is
not evidence that they are present in this standalone payload.
