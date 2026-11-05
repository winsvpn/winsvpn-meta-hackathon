# Supervisor bundle: pre-verified fix for the 5 red Windows/release tests (pass 4)
# Discovered 2026-08-17. All fixes are SCRATCH-PROVEN (not applied to the tree).
# With all five applied, the 18-file Windows/release Python set is 18/18 PASS and the
# gate prints "RELEASE VERSION CONTRACT: PASS 1.0.16+34". Evidence: receipts/09.
# Freeze impact: ONLY tools/verify_release_version_contract.py is pinned by the
# WINDOWS_INPUTS.json producer_inputs fingerprint; the 4 test files are NOT pinned.

## FIX A (BLOCKER - REQUIRED BEFORE STEP 3) tools/verify_release_version_contract.py:117
#  Old:        "installer/windows/build_installer.ps1": "$ReleaseDir =",
#  New:        "installer/windows/build_installer.ps1": "'begin-build'",
#  sha256: 8f2e3349251c0d24e538013945f7a43bf5be5ef8224b0021364461e4399d60d7
#       -> e19a4a6e00d7b8ab70d3be0d3a67ecb1bc614b2cc1a560ddb1232034a09972a5
#  WHY: The gate's producer_order check requires gate_index <= first_build_index.
#  build_installer.ps1 assigns $ReleaseDir at line 4 while the gate string first
#  appears at line 19, so NO spelling of "$ReleaseDir" can satisfy it (spaced =
#  ValueError, unspaced = "gate too late"). The first real build action in the
#  producer is the freeze 'begin-build' receipt at line 79 (after the gate at :19,
#  actual invoke at :72), which exactly matches the intent used for the other four
#  producers. Verified: gate PASS + its 6-test suite green.

## FIX B tools/test_windows_installer_toolchain_index.py (test_inno_payload_is_exact_standalone)
#  Replace the legacy-name absence loop with a section-scoped assertion (legacy
#  names confined to the repair's [InstallDelete] purge section, absent everywhere
#  else in winsvpn.iss):
#    for x in ('xray','amnezia','mullvad','split-tunnel'):self.assertNotIn(x,INNO.lower())
#  becomes:
#    low=INNO.lower();delete=low[low.index('[installdelete]'):low.index('[files]')]
#    rest=low[:low.index('[installdelete]')]+low[low.index('[files]'):]
#    for x in ('xray','amnezia','mullvad','split-tunnel'):self.assertIn(x,delete);self.assertNotIn(x,rest)

## FIX C tools/test_windows_semantic_watchdog.py (test_live_probe_is_exact_standalone_winn3)
#  The probe now contains the fail-closed $ForbiddenLegacyPayload scan. Replace:
#    for x in ('awg.exe','direct_awg','xray route','windows_transport_diagnostic_helpers'):self.assertNotIn(x,s.lower())
#  with:
#    low=s.lower()
#    for x in ('direct_awg','xray route','windows_transport_diagnostic_helpers'):self.assertNotIn(x,low)
#    fb=low.index('$forbiddenlegacypayload');scan_end=low.index('function assert-legacypayloadabsent')
#    for x in ('awg.exe','xray.exe','amneziawg.exe','mullvad-split-tunnel.sys','winsvpn_awg_engine.exe'):self.assertIn(x,low[fb:scan_end])

## FIX D tools/test_windows_standalone_v3_packaging.py (test_no_legacy_source_or_mode_switch)
#  Legacy names appear only in the [InstallDelete] purge; 'xray' additionally appears
#  in build_installer.ps1 as the manifest contract field staged_xray_product_signed.
#  Replace the body of the test with:
#    build_low=BUILD.casefold();inno_low=INNO.casefold()
#    delete=inno_low[inno_low.index('[installdelete]'):inno_low.index('[files]')]
#    rest=inno_low[:inno_low.index('[installdelete]')]+inno_low[inno_low.index('[files]'):]
#    for marker in ('amnezia','mullvad','direct-awg','awg-datagram','winsvpn_awg_engine'):self.assertNotIn(marker,build_low)
#    self.assertEqual(build_low.count('xray'),build_low.count('staged_xray_product_signed'))
#    for marker in FORBIDDEN:self.assertNotIn(marker,rest)
#    for marker in ('amnezia','xray','mullvad','winsvpn_awg_engine'):self.assertIn(marker,delete)
#    for marker in ('StandaloneWinn3Release','AllowMissingWinn3Carrier','#ifndef Standalone'):self.assertNotIn(marker,BUILD+'\n'+INNO)

## FIX E tools/test_windows_native_async_lifecycle.py (test_historical_cleanup_mutations_break_the_contract)
#  The repair re-signed the cleanup entrypoint to DeleteOwnedService(SC_HANDLE manager,.
#  Change the marker and the mutation needle from "DeleteOwnedService(manager" to
#  "DeleteOwnedService(" in both the mutations tuple and the required tuple
#  (line ~208 and ~215). Verified: mutated count 2 < original 3 -> passes.

## AFTER APPLYING (supervisor steps)
#  1. Review + apply Fixes A-E to the reviewed tree; re-run:
#       python3 tools/verify_release_version_contract.py --root .
#       python3 tools/test_release_version_contract.py
#       python3 tools/run_test_suite.py  (or at least the 5 files above)
#  2. Because Fix A changes the gate hash, re-run the release-freeze ceremony for
#     1.0.16+34 (tools/release_dependency_freeze.py freeze-shared + snapshot-platform
#     + create-index + verify-index) so WINDOWS_INPUTS.json producer_inputs
#     fingerprint and RELEASE_INPUT_INDEX.json.sha256 pin e19a4a6e....
#  3. Copy the fresh index to winpc (replace the current one).
#  4. Then complete the other step-3 preconditions (descriptor keys, prebuilt Release
#     payload) and run the step-3 command block per step3_build_installer_supervisor.md.
