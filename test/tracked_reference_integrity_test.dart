// A tracked file must never depend on a file git does not track.
//
// PORTED from wins_security's
// `platform/flutter/test/tracked_reference_integrity_test.dart` (2026-08-07),
// where this defect was found seven times in a row. Its two hardening lessons
// are carried over verbatim, because both were learned the expensive way:
//
//   * READ FROM THE HEAD TREE, NOT `git ls-files`. `ls-files` reads the INDEX.
//     An index carrying staged deletions answers a different question, and
//     that error once turned "103 of 103" into a plausible "5 of 103". Every
//     absolute check here takes a treeish and reads content from it.
//   * A RATCHET ENTRY IS STALE ONLY WHERE THE CHECKOUT CAN OBSERVE IT. The
//     sibling's first version read its whole baseline as stale in a clone,
//     which would have made the suite red on arrival everywhere - and a red
//     guard gets skipped, which converts a real protection into a muted one.
//
// WHY THIS REPOSITORY IS DIFFERENT, AND WHY THE BAR IS HIGHER.
//
// wins_security is a scanner. wins_vpn is the SHIPPING VPN app, release-frozen
// at 1.0.14+29, installed on phones in Myanmar. A file that is missing from a
// clone here is not an inconvenience; it is a build that does not carry a
// safety feature, and nothing about it looks wrong. The armed set below
// currently includes the duress dispatch, the announcement-signing verifier,
// the discovery/paste-in control-plane intake and the transport-preference
// memory. Every one of those is a file whose absence produces an app that
// launches, connects, and quietly does less than the user believes.
//
// THE SHAPES THIS CHECKS. The naive "does an import resolve" check finds only
// the first one. All of these have actually occurred:
//
//   1. A tracked file resolves an import to an untracked target.       (Dart)
//   2. A SAME-PACKAGE symbol reference with NO IMPORT LINE to grep for.
//      Kotlin, Swift, Java and Go all have this: two files in one
//      package/module see each other's top-level names with nothing written
//      down. There is no path in the source to follow.       (Kotlin/Swift/Go)
//   3. An `android:name` class reference in a manifest - A STRING NO COMPILER
//      CHECKS. It compiles, links, installs, launches, and throws
//      ActivityNotFoundException when the user taps the button.       (XML)
//   4. An ENTIRELY UNTRACKED BUILD SURFACE with nothing tracked pointing into
//      it. You cannot follow a reference that was never written; the only
//      signal is peer asymmetry - a directory holding a build-system marker,
//      untracked, while its siblings are tracked.              (directories)
//   4b. The same defect one file down: a build-system marker (`go.mod`,
//      `.entitlements`) untracked INSIDE an otherwise-tracked directory. The
//      directory-keyed query in (4) is structurally blind to this, and this
//      repository has it right now.                                  (files)
//   4c. A file a BUILD OR RELEASE SCRIPT HARD-REQUIRES, untracked, inside a
//      directory git already tracks - and NOT a build-system marker, so
//      neither (4) nor (4b) can see it. (4) keys on DIRECTORIES and
//      `linux/packaging/` already holds tracked files; (4b) keys on a
//      deliberately narrow list of marker FILENAMES and `RECOVERY.md` is not
//      one. The script runs under `set -Eeuo pipefail` and `install`s the
//      file, so a clone with the script and not the file FAILS THE RELEASE
//      BUILD. The requirement is not a marker and not an import: it is an
//      argument to a command inside a shell script, and the only way to see
//      it is to read the scripts and resolve what they name.       (scripts)
//   5. Assets declared in `pubspec.yaml` but not tracked - and the Apple
//      equivalents nobody thinks of as assets: an `.xcassets` `Contents.json`
//      naming an image file, and a `project.pbxproj` naming an entitlements
//      file by string.                                         (YAML/JSON/pbx)
//   6. UNTRACKED TEST FILES. This is how half a suite goes missing without a
//      single failure: the clone runs fewer tests and reports green.
//
// WHAT THIS FILE CANNOT DETECT, STATED PLAINLY:
//
//   7. A test that passes only against the UNCOMMITTED CONTENT of a TRACKED
//      file. The file is tracked. Its imports are tracked. Nothing is missing.
//      The test is still red in a clone, because the behaviour it asserts
//      lives in a `+88 -2` diff nobody committed. No tracked-vs-untracked
//      check can see this, and no amount of import-closure analysis can
//      either - the dependency is not on a FILE, it is on CONTENT.
//      THE ONLY RELIABLE DETECTOR IS RUNNING THE SUITE IN A FRESH CLONE.
//      This file does not pretend to cover it.
//
// Five tests, deliberately different in strictness:
//
//   * `HEAD tree ...` is the half that TRAVELS. It asserts the committed tree
//     is self-consistent - the property "a fresh clone builds" depends on. Its
//     exemption list, `_knownHeadViolations`, is EMPTY as of 2026-08-07: it
//     held the two landed instances this repository had, both were fixed by
//     tracking the files, and the test is back in its no-exemptions form. It
//     is a STRICT ratchet: a HEAD violation is observable in every checkout,
//     so a stale entry always fails. Keep the list empty.
//   * `working tree ...`, `no build surface ...`, `no test file ...` and
//     `no build or release script ...` are MACHINE-LOCAL ratchets. They catch
//     the defect BEFORE it is committed, which is where every instance has
//     been catchable. They cannot travel, because in a clone the untracked
//     file simply is not there to notice.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Violations that are ALREADY IN `HEAD`.
///
/// EMPTY as of 2026-08-07, and it should stay that way. It held two entries -
/// the macOS `AppIcon` 16pt and 32pt PNGs, named by a tracked `Contents.json`
/// and never tracked themselves - and both were closed by tracking the files.
/// The absolute test is now back in the sibling's no-exemptions form.
///
/// Measured before the fix, in a clone built from `HEAD` with nothing taken
/// from any working tree: `actool` did NOT fail. It exited 0 and emitted
/// `Missing Content` warnings naming both files, then wrote an `AppIcon.icns`
/// and an `Assets.car` with holes where the 16pt and 32pt representations
/// should be. That is the worse of the two branches - a hard failure would at
/// least have stopped somebody.
///
/// Unlike the two working-tree ratchets below, this one is STRICT: a `HEAD`
/// violation is observable in every checkout, in CI, and in a clone, so there
/// is no "unobservable" case to forgive. Fix the defect, delete the line.
const Map<String, String> _knownHeadViolations = <String, String>{};

/// Untracked files that a tracked file already references, as of 2026-08-07.
///
/// Every entry is a live landmine, not an accepted state. Each belongs to a
/// lane that has not committed it yet. NONE of these references exists at
/// `HEAD` - all were armed in the working tree - so the shipping 1.0.14+29
/// build is not currently missing any of them. Committing the tracked PARENT
/// without its child is what detonates it.
///
/// TO REMOVE AN ENTRY: `git add` the file, or delete the reference to it from
/// the tracked parent. Then delete the line here - a stale entry fails this
/// test on purpose, so the list cannot outlive the problem it records.
///
/// TO ADD AN ENTRY: don't. A new entry means a new landmine was armed. Track
/// the file, or stop referencing it from tracked code.
const Map<String, String> _knownArmedReferences = <String, String>{
  // --- Referenced by tracked lib/main.dart, which is MODIFIED. -------------
  //
  // RESOLVED 2026-08-07, six entries removed per the ratchet. All six -
  // duress_dispatch, announcement_signature, discovery_intake,
  // discovery_paste_in, recovery_beacon_gate and direct_udp_transport_memory
  // - are tracked, and they were tracked BEFORE lib/main.dart was, which is
  // the whole point: main.dart imports all six and none of the imports
  // existed at HEAD, so committing it first would have produced a tree that
  // does not compile, and committing it with only some of them would have
  // shipped a client whose duress path and announcement-signature
  // verification were silently absent. The libraries landed with their tests
  // in one commit; main.dart landed in the next one.
  // --- Referenced by tracked lib/winn_protocol_dev_session_main.dart. ------
  //
  // RESOLVED 2026-08-07, entry removed per the ratchet:
  // `lib/winn_protocol_dev_session_traffic.dart` is tracked, in the same
  // commit as the `lib/winn_protocol_dev_session_main.dart:93` import that
  // armed it. Worth keeping the shape of this one on the record: it was the
  // SEVENTH armed reference and the only one not reachable from
  // `lib/main.dart`, so every audit that enumerated main.dart's imports -
  // and several did - counted six and missed it. The import does not exist
  // at HEAD, so nothing in the shipped 1.0.14+29 build was missing it; a
  // commit of the dev-session parent alone is what would have detonated it,
  // in a dev-only file nobody was watching.
  // --- Referenced by tracked ios/Runner.xcodeproj/project.pbxproj, which is
  // --- MODIFIED. Neither reference exists at HEAD. -------------------------
  // CODE_SIGN_ENTITLEMENTS is a string. Nothing checks it until the code-sign
  // step, and only the Debug configuration uses these two - Release and
  // Profile still name the tracked Runner.entitlements / PacketTunnel
  // .entitlements, so the shipping build is unaffected. What breaks is every
  // developer's ability to build and test the VPN on a device from a clone,
  // because both files carry com.apple.developer.networking.networkextension
  // and without it the packet tunnel provider cannot load.
  //
  // 2026-08-08: these two entries went stale for about two hours and this test
  // failed asking for them to be DELETED. Deleting them would have been the
  // wrong fix, and it is worth knowing why before anyone obeys that message
  // here again. The references had not been removed on purpose - a
  // `git reset --hard` at 16:44-16:48 reverted the tracked pbxproj to a HEAD
  // that has never carried the Debug/production bundle-id split, while leaving
  // both untracked *Debug.entitlements files orphaned on disk. The stale
  // baseline was therefore the ratchet correctly reporting collateral damage,
  // not a resolved landmine. The fix was to restore the four pbxproj lines, at
  // which point these entries became true again on their own. See
  // docs/handoff/IOS_DEBUG_SPLIT_RESTORED_20260808.md.
  //
  // The distinction generalises: a stale entry means EITHER the landmine was
  // defused (file tracked / reference removed on purpose - delete the line) OR
  // the tracked parent lost the reference by accident (restore it). Check which
  // before shrinking the ratchet, because the second case looks exactly like
  // the first from inside this test. These two stayed armed until the pbxproj
  // change and both entitlements files were committed together, which landed
  // in c462ee4 -- so they are gone from this baseline, in the shrink-only
  // direction the ratchet exists to enforce.
  //
  // Worth keeping the distinction that episode taught, because the failure
  // message reads the same in both cases and the right response is opposite.
  // A stale entry means EITHER the file became tracked (resolved -- delete the
  // line) OR the reference that armed it was destroyed (a loss -- restore the
  // reference, delete nothing). Earlier the same day these two entries went
  // stale the second way, when `git reset --hard` rewrote the tracked pbxproj
  // to a HEAD that had never carried the Debug split while the untracked
  // entitlements survived as orphans. Deleting them then would have gone green
  // while cementing the loss.
};

/// Build surfaces git has never been told about, as of 2026-08-07.
///
/// This is a DIFFERENT shape from the map above and the reference check is
/// structurally blind to it. There is no dangling import into `extension/` -
/// there is nothing pointing at it at all, from anywhere. A browser extension
/// is found by directory convention, not by reference. Git does not know it
/// exists: it is neither tracked nor ignored, which is the state in which a
/// directory is invisible to everyone except the machine it lives on.
///
/// Two keys appear here: directories (peer asymmetry - a sibling is tracked
/// and this one is not) and individual build-system MARKER FILES that are
/// untracked inside a directory that git otherwise tracks. The second kind is
/// the one a directory-keyed check cannot see, and this repository has four.
///
/// TO REMOVE AN ENTRY: `git add` it, or gitignore it if it really is scratch -
/// "neither" is the state that hides it. Then delete the line.
const Map<String, String> _knownInvisibleBuildSurfaces = <String, String>{
  // --- whole directories --------------------------------------------------
  //
  // RESOLVED 2026-08-07, entry removed per the ratchet: `extension/` is now
  // tracked - 34 source files, with `dist/` correctly ignored by the
  // `extension/.gitignore` a sibling lane added at 02:20. This is the entry
  // this guard was watched to catch, lose sight of, and catch again: the
  // built `dist/*/manifest.json` were its only markers until that ignore rule
  // landed, which is why `build.py` is in `_buildSurfaceMarker`.
  //
  // RESOLVED 2026-08-07, entry removed per the ratchet: `tools/native_messaging`
  // is now tracked - 15 source files (its own pubspec and lock, the host
  // entry point and its harness, five host libraries, two probes, the
  // installer and the three browser manifests). The compiled
  // `host/wins_bridge_host` is deliberately NOT tracked: it is a 6.0 MB
  // Mach-O arm64 build output of `bin/wins_bridge_host.dart`, and
  // `install_native_host.sh` prints the one-line `dart compile exe` recipe
  // when it is absent. That is the same rule `.gitignore` already applies to
  // `build/` and `.dart_tool/`, and the reason the count here is 15 and not
  // 16.
  //
  // The same commit tracked `lib/browser_bridge_{framing,protocol,proxy}.dart`
  // and their three tests, which were the last two of the four places this
  // feature was hiding: nothing tracked references those three libraries, so
  // they were invisible to the reference check AND to the surface check and
  // showed up only in `_knownUntrackedTests`.
  // --- marker files inside tracked directories ----------------------------
  //
  // RESOLVED 2026-08-07, entries removed per the ratchet:
  // `windows/awg_engine/go.{mod,sum}` are tracked. The failure mode in a clone
  // was worse than "go.mod file not found": with no module file of its own,
  // `windows/awg_engine` fell into the repository-root Go module
  // (`winn.local/e8r7promoterr2`, an unrelated promotion tool), so the
  // AmneziaWG datapath was compiled as part of the wrong module and `go build`
  // exited 1 unable to resolve any `github.com/amnezia-vpn/amneziawg-go/*`
  // import. Measured in a clone, then measured again after tracking the two
  // files, when it builds.
  // The two ios `*Debug.entitlements` files were listed here as invisible
  // build surfaces; both are tracked as of c462ee4 and so are removed, which
  // is the resolution this baseline was shrinking toward.
};

/// Test files that exist on this machine and in no clone, as of 2026-08-07.
///
/// This is how a suite loses half of itself without a single red line: the
/// clone runs fewer files and reports green. In the sibling repository a clone
/// ran 1,024 tests where the working tree ran 2,170, and nobody noticed until
/// somebody counted.
///
/// Measured on 2026-08-07, after the camouflage parcel landed in four commits:
/// a fresh depth-1 clone runs **876** tests, up from 593. The eleven tests
/// this file used to list as blocked on an untracked library are tracked, with
/// the seven libraries they need, and so is `lib/main.dart` - which imports
/// six of those seven and could not have been committed before them without
/// producing a tree that does not compile.
///
/// Every count in this file is a clone count. Nothing here was established by
/// reading imports: the twelve tests once called "self-contained, landable
/// today" on import evidence turned out to be exactly ONE, and the same method
/// failed again inside this parcel - two tests whose imports all resolved
/// after their library landed were still red until `lib/main.dart` landed too,
/// because what they depend on is its TEXT.
///
/// Updated 2026-08-08: no Dart test remains in this map. c462ee4 tracked the
/// last eight, and every one of their lines has been deleted below in the
/// shrink-only direction, after `git ls-files` confirmed each is tracked -
/// which is the FIRST of the two ways an entry goes stale and the only one
/// that licenses a deletion. The duress CAMOUFLAGE CONTRACT now runs in every
/// clone, which the paragraph this replaces could not yet say; getting there
/// meant restoring the Android sources it pins, not relaxing what it asserts.
///
/// What is left is four Kotlin/wear unit tests, blocked on native source held
/// open by another lane, in the shape this file calls #2: a Kotlin test writes
/// no import line for a same-package symbol, so there is nothing to resolve
/// and nothing to fail.
///
/// Detection is peer asymmetry, same idea as the surfaces above: a test file
/// is flagged only when it sits in a directory git ALREADY tracks other test
/// files in. That keeps dated backup trees and scratch out of it.
const Map<String, String> _knownUntrackedTests = <String, String>{
  // -- blocked: import a library that is itself in _knownArmedReferences ----
  //
  // RESOLVED 2026-08-07, three entries removed per the ratchet:
  // `test/{duress_dispatch,discovery_record_client,recovery_beacon_gate}
  // _test.dart` are tracked, in the same commit as the libraries they import.
  //
  // One below imports a now-tracked library and STILL cannot land. That was
  // measured, not read: it was run in a clone holding the seven libraries and
  // NOT yet holding lib/main.dart, was red there on BOTH of its groups, and
  // is still red with main.dart landed - because `hub contract` reads
  // server/wins_control_plane_setup_ONETOUCH.sh as text and that installer
  // carries another lane's uncommitted work. This is the seventh shape again:
  // the dependency is on CONTENT, not on a file, so a resolved import is
  // never evidence that a test can land.
  //
  // test/direct_udp_transport_memory_test.dart was in this same position and
  // is RESOLVED: red without lib/main.dart (4 failures, all reading it as
  // text), green with it, tracked in the commit after main.dart rather than
  // in the commit that carried the library it imports.
  // RESOLVED 2026-08-08, entry removed per the ratchet:
  // `test/announcement_signature_test.dart` is tracked as of c462ee4. See the
  // consolidated note below for how all eight of that commit's test files were
  // checked before any line here was deleted.
  //
  // RESOLVED 2026-08-07, two entries removed per the ratchet:
  // `test/browser_bridge_{framing,address_containment}_test.dart` are tracked,
  // in the same commit as the three libraries they import. The containment
  // test is the one worth naming - it asserts that node addresses never reach
  // the browser, and until that commit no clone ran it.
  // `test/browser_bridge_proxy_test.dart` followed one commit later, with
  // lib/camouflage_policy.dart: it asserts the TLS certificate subject and the
  // NSS nickname carry none of kCamouflageLatchForbiddenTokens, and that
  // symbol does not exist at HEAD. Splitting it out of the bridge commit is
  // the whole reason that commit is green.
  //
  // -- every import resolves, and they STILL cannot land -------------------
  //
  // These were recorded on 2026-08-07 as "self-contained: importable today,
  // owner just has not committed". Import resolution said so: every `package:`
  // URI and every file path each one touches is tracked at HEAD.
  //
  // Then they were RUN, one at a time, in a clone built from HEAD with nothing
  // taken from the working tree. Eight of the nine are red there. Import
  // resolution was answering the wrong question: the dependency is not on a
  // FILE, it is on CONTENT, and the content lives in the uncommitted diffs to
  // lib/main.dart (+3499), lib/local_security.dart (+382),
  // lib/pre_vpn_geo.dart (+163), lib/camouflage_policy.dart (+409) and the
  // native/server sources several of them read as text. This is exactly the
  // seventh shape named at the top of this file, and it is the reason that
  // paragraph says the only reliable detector is running the suite in a fresh
  // clone. Do not re-promote any of these to "self-contained" from a static
  // read; re-run it in a clone and see.
  //
  // RESOLVED 2026-08-07: test/node_reachability_listing_test.dart was the one
  // of the nine that is genuinely landable - measured green in the clone, 6
  // tests - and it is tracked now, so its line is gone from this map.
  //
  // RESOLVED 2026-08-07, four entries removed per the ratchet, all in the
  // commit after lib/main.dart, lib/local_security.dart and
  // lib/pre_vpn_geo.dart landed: duress_pin_policy_test,
  // stealth_transport_only_preference_test, map_tile_host_pin_test and
  // legal_acceptance_staleness_test. Each was re-RUN in a clone, not
  // re-reasoned about.
  //
  // RESOLVED 2026-08-08, four more entries removed per the ratchet:
  // `test/{duress_camouflage_contract,announcement_delivery,
  // speed_test_host_allowlist_contract,apple_secure_state_store_native_contract}
  // _test.dart` are all tracked as of c462ee4.
  //
  // ===== THE EIGHT c462ee4 TESTS, AND WHICH DIRECTION THEY WENT STALE ======
  //
  // c462ee4 staged `test/` with `git add -A`, which tracked all eight of the
  // test/*.dart files the COMMIT_SETS_READY_20260808.md staging list had held
  // back with a `:(exclude)` pathspec. That makes their lines here stale, and
  // this ratchet asked for them to be deleted.
  //
  // BEFORE DELETING, THE DIRECTION WAS CHECKED - the same check the
  // *Debug.entitlements note at the top of this file exists to force. A stale
  // entry means EITHER the file became tracked (resolved: delete the line) OR
  // the reference that armed it was destroyed (a loss: restore the reference,
  // delete nothing), and the failure message reads identically either way.
  // `git ls-files --error-unmatch` returns each of the eight, and
  // `git ls-files --others` returns none of them: they are tracked, on disk,
  // and no longer violations. FIRST DIRECTION. The lines are deleted.
  //
  // The second direction still bit, one level down, and is recorded because
  // deleting these lines is exactly the moment it would have been buried. Two
  // of the eight were RED in a clone of c462ee4 - not because they are stale
  // tests, but because the SAME 16:44-16:48 `git reset --hard` named above
  // rewound the Android sources they pin to a HEAD that never carried the
  // 2026-08-06 hardening, while the untracked tests survived as orphans:
  //
  //   * duress_camouflage_contract_test - the logical->on-disk name map and
  //     migrateLegacyLayout in SecureFileStore.kt, "sendDuressSms" /
  //     requestDuressSmsPermission in MainActivity.kt, and SEND_SMS in
  //     AndroidManifest.xml. lib/main.dart:3336 was already invoking the
  //     'sendDuressSms' MethodChannel against a handler that no longer
  //     existed, so the device-native duress alert could only ever return
  //     false on Android - a live safety defect, not a stale assertion.
  //   * speed_test_host_allowlist_contract_test - speedTestAllowedHosts and
  //     the exact-host form of validatedSpeedTestUrl in MainActivity.kt. HEAD
  //     still carried the leading-dot suffix wildcards, including the bare
  //     `.sonic.net` corporate zone.
  //
  // All of it was restored from snapshot/overnight-lanes-20260806 (4ffc1c9),
  // which preserves the pre-reset working tree, and both files are green. The
  // tests were NOT weakened to match the rewound code. See
  // docs/handoff/RED_CONTRACT_TESTS_RESOLVED_20260808.md.
  //
  // The Apple half of the duress contract and the camouflage surface work
  // (app label, launcher aliases, notification disguise, VpnTunnelService
  // DISGUISED_DISPLAY_NAME) were deliberately NOT restored here: they belong
  // to the Apple and camouflage lanes and are still a parcel decision.
  // =========================================================================
  //
  // -- Kotlin unit tests, in source sets that already hold tracked tests ----
  //
  // RESOLVED 2026-08-21, three entries removed per the ratchet. FIRST
  // direction, not read: `git ls-files` returns
  // `android/app/src/test/kotlin/org/winsvpn/app/CamouflageLatchedSurfaceTest.kt`,
  // `.../CamouflageSessionNameTest.kt` and
  // `wear_os/app/src/test/kotlin/org/winsvpn/app/wear/WatchAppNameCamouflageTest.kt`,
  // and `git ls-files --others` returns none of them. The symbols the pair
  // pins (latchedSurfaceIsDisguised / vpnSessionNameFor / DISGUISED_DISPLAY_NAME)
  // are in the tracked VpnTunnelService.kt at HEAD, and the tracked
  // wear strings.xml carries the disguised app_name, so all three compile in
  // a clone of HEAD. The old claim "blocked on shape #2" no longer holds.
  // -- recorded 2026-08-07 by the untracked-build-input audit lane -----------
  //
  // Four entries, every one MEASURED in a depth-1 clone built from a probe
  // tree with nothing taken from the working tree. None is a new landmine:
  // three were already untracked and unrecorded, and the fourth was invisible
  // to this very query because it was sitting in the INDEX (see below). The
  // libraries these tests need are staged; the tests themselves are not,
  // because each is red in a clone for the seventh reason at the top of this
  // file -- it depends on the TEXT of a file another lane has not committed.
  // RESOLVED 2026-08-08, two entries removed per the ratchet:
  // `test/{winn_session_descriptor,android_ipv6_fail_closed_guard}_test.dart`
  // are tracked as of c462ee4, verified with `git ls-files` in the FIRST
  // direction (see the consolidated note above). Both are green: the
  // lib/main.dart content the descriptor test wanted landed in 1b4c2ce, and
  // `mayEstablishTunnel` is in the tracked VpnTunnelService.kt now.
  // RESOLVED 2026-08-21, the Kotlin half of the ipv6 pair is removed too per
  // the ratchet, so this audit lane's four entries are all cleared. FIRST
  // direction: `git ls-files` returns
  // `android/app/src/test/kotlin/org/winsvpn/app/Ipv6FailClosedGateTest.kt`,
  // `git ls-files --others` does not, and `mayEstablishTunnel(address, route)`
  // is in the tracked VpnTunnelService.kt at HEAD, so it compiles in a clone.
  // RESOLVED 2026-08-08, the eighth and last entry removed per the ratchet:
  // `test/awg_obfuscation_bounds_parity_test.dart` is tracked as of c462ee4,
  // verified with `git ls-files` in the FIRST direction. It was the entry that
  // had been HIDDEN FROM THIS QUERY BY BEING STAGED - `untracked` is
  // `git ls-files --others`, so an `A` entry in the index is neither
  // tracked-at-HEAD nor untracked - and the blind spot it names is still real
  // for any future entry, which is why the sentence survives here even though
  // its subject does not.
};

/// Files a tracked BUILD OR RELEASE SCRIPT requires, that git does not track,
/// as of 2026-08-07.
///
/// Shape 4c, and the reason it needed its own checker: BOTH of the queries
/// above are structurally blind to it.
///
///  * `no build surface is invisible to git` keys on DIRECTORIES. It asks
///    which directory boundary has no tracked file above it. `linux/packaging`
///    already holds tracked files, so the directory is "covered" and the
///    untracked file inside it is never looked at.
///  * The shape-4b half of that same query keys on a deliberately narrow list
///    of build-system marker FILENAMES (`_buildSurfaceMarker`). It is narrow on
///    purpose - a wider one drowns in this tree's scratch - and `RECOVERY.md`
///    is not a `go.mod`, an `.entitlements` or a `Podfile`. Widening the list
///    to "any Markdown file" would mute the check within a week.
///
/// So the requirement is derived FROM THE SCRIPTS THEMSELVES rather than from
/// a filename convention or a hand-maintained inventory: a hand list rots, and
/// the whole subject of this file is lists that outlive the truth. See
/// `_Repo.scriptRequirements`.
///
/// TO REMOVE AN ENTRY: `git add` the file (it must land in the same commit as
/// the script change that needs it), or stop requiring it. Then delete the
/// line - a stale entry fails this test on purpose.
const Map<String, String> _knownUntrackedScriptRequirements = <String, String>{
  // RESOLVED 2026-08-07, one entry removed per the ratchet:
  // `linux/packaging/RECOVERY.md` is staged. It was the only entry, and the
  // ratchet reported it stale within a minute of the `git add`, which is the
  // behaviour this map is for.
  //
  // Worth recording precisely, because the entry overstated the tense: the
  // `install -D -m 0644 "$LINUX_PACKAGING_DIR/RECOVERY.md"` line is in the
  // UNCOMMITTED diff to tools/build_linux_release.sh, not at HEAD. Measured in
  // a clone: HEAD's build_linux_release.sh does not name RECOVERY.md at all,
  // so no release build is failing today. It was ARMED, not detonated -- the
  // Linux release breaks the moment that script is committed without the
  // document. Staging the document first is what disarms it, and is the same
  // ordering the camouflage parcel used for lib/main.dart's six imports.
};

/// Filenames that mean "a build reads this directory".
///
/// Deliberately narrow. This tree carries a great deal of legitimately
/// untracked scratch - dated `.bak_*` and `.bak.*` families, `build/`,
/// `output/`, side experiments - and trying to classify all of it is a losing
/// game that ends in a muted test. Anchoring on build-system entry points
/// keeps it precise: every one of these is something a compiler, packager,
/// linker or store submission actually needs.
/// `build.py` and `package.json` are here for a reason worth writing down: at
/// 02:20 on 2026-08-07, twenty minutes after this guard was committed, another
/// lane added `extension/.gitignore` with a `dist/` rule. That was the right
/// thing to do - built output should not be tracked - but it ignored the three
/// `dist/*/manifest.json` files that were the ONLY markers this query could see
/// in `extension/`, and the ratchet immediately reported the entry as stale.
///
/// The underlying defect had not moved an inch: `extension/` still holds 34
/// untracked source files and ZERO tracked ones. Deleting the entry, as the
/// ratchet asked, would have made a real finding disappear because somebody
/// gitignored the evidence for it - which is a more sophisticated version of
/// exactly the failure this file exists to prevent. So the query was taught to
/// see the source-side entry point instead. `build.py` occurs once in this
/// repository, untracked, and it is that entry point; `package.json` occurs
/// zero times and is here so the next JS surface is visible on arrival.
final RegExp _buildSurfaceMarker = RegExp(
  r'^(Podfile|Package\.swift|CMakeLists\.txt|pubspec\.yaml|AndroidManifest\.xml'
  r'|Info\.plist|PrivacyInfo\.xcprivacy|project\.pbxproj|.+\.entitlements'
  r'|.+\.xcconfig|.+\.podspec|build\.gradle(\.kts)?|settings\.gradle(\.kts)?'
  r'|go\.mod|go\.sum|Cargo\.toml|manifest\.json|package\.json|build\.py)$',
);

/// A file whose name says it is a backup, in EITHER naming family this
/// repository uses. `*.bak_<label>` and `*.bak.<label>.<stamp>` both exist and
/// a rule covering only one of them looks like complete coverage while missing
/// half - which is the same shape as the bug this whole file is about.
final RegExp _backupName = RegExp(r'\.bak[._]');

/// Paths a tracked file may reference without them being tracked, because the
/// build regenerates them before anything compiles.
///
/// Nothing may be added here that is not both gitignored AND produced by a
/// build step a clone runs unprompted. "Someone will generate it" is not a
/// build step.
const List<String> _derivedOutputPrefixes = <String>[];

/// Trees the absolute check runs against. Always `HEAD`; anything named in
/// `TRACKED_REFERENCE_INTEGRITY_EXTRA_TREEISH` (comma-separated) as well.
///
/// The hook can only ADD trees, never replace `HEAD`, so it cannot be used to
/// weaken this test - the one property that matters about an escape hatch in a
/// guard whose entire subject is protections that quietly stop protecting.
///
/// What it is for: pre-flighting a commit that has not been made yet. The
/// commit discipline in this repository builds a tree in a temporary
/// `GIT_INDEX_FILE`, so a lane can check that tree BEFORE it becomes history:
///
/// ```sh
/// export GIT_INDEX_FILE=/tmp/probe.index
/// git read-tree HEAD && git update-index --add -- <paths>
/// TREE=$(git write-tree); unset GIT_INDEX_FILE
/// TRACKED_REFERENCE_INTEGRITY_EXTRA_TREEISH=$TREE \
///   flutter test test/tracked_reference_integrity_test.dart
/// ```
List<String> _absoluteTreeishes() {
  const name = 'TRACKED_REFERENCE_INTEGRITY_EXTRA_TREEISH';
  final extra = (Platform.environment[name] ?? '')
      .split(',')
      .map((String s) => s.trim())
      .where((String s) => s.isNotEmpty);
  return <String>['HEAD', ...extra];
}

/// A tracked file referencing something git does not have.
class _Violation {
  _Violation(this.target, this.source, this.detail);

  /// Repo-relative path of the file that is not in the tree.
  final String target;

  /// Repo-relative path of the tracked file that depends on it.
  final String source;

  /// How the dependency is expressed, for the failure message.
  final String detail;

  @override
  String toString() => '$target\n      <- $source  ($detail)';
}

void main() {
  late final String repoRoot;
  late final _Repo repo;
  var gitAvailable = false;

  setUpAll(() {
    final root = _repoRoot();
    if (root == null) return;
    repoRoot = root;
    repo = _Repo(repoRoot);
    gitAvailable = true;
  });

  test('HEAD tree references no file that HEAD does not contain', () {
    if (!gitAvailable) {
      markTestSkipped('not a git checkout: reference integrity unverifiable');
      return;
    }

    for (final treeish in _absoluteTreeishes()) {
      final inTree = repo.pathsAt(treeish);
      final violations = <_Violation>[
        ...repo.dartImportViolations(treeish: treeish, inTree: inTree),
        ...repo.pubspecAssetViolations(treeish: treeish, inTree: inTree),
        // The two shapes with nothing for a compiler to check: a same-package
        // symbol writes no import line, and an `android:name` is a string.
        ...repo.symbolViolations(treeish: treeish, inTree: inTree),
        ...repo.androidManifestViolations(treeish: treeish, inTree: inTree),
        // Apple names files by string in two more places nobody audits.
        ...repo.appleResourceViolations(treeish: treeish, inTree: inTree),
        // C/C++ and Go, which this repository has and the sibling did not.
        ...repo.cIncludeViolations(treeish: treeish, inTree: inTree),
        ...repo.goImportViolations(treeish: treeish, inTree: inTree),
      ];

      final baseline = _knownHeadViolations.keys.toSet();
      final unexpected =
          violations.where((v) => !baseline.contains(v.target)).toList();
      final stale =
          baseline.difference(violations.map((v) => v.target).toSet());

      expect(
        unexpected,
        isEmpty,
        reason: 'The tree $treeish is NOT self-consistent: a fresh clone is '
            'missing files that committed files reference. A commit that '
            'should not have landed, landed.\n\n'
            '${unexpected.map((v) => '  $v').join('\n')}',
      );

      // Only meaningful for HEAD: an extra treeish is a candidate commit that
      // may legitimately have fixed one of these, and failing it for being
      // BETTER than HEAD would punish exactly the person doing the right
      // thing. For HEAD itself the ratchet is strict.
      if (treeish == 'HEAD') {
        expect(
          stale,
          isEmpty,
          reason: 'These _knownHeadViolations entries are fixed - the files '
              'are tracked now, or the references are gone. Delete each line '
              'from _knownHeadViolations. It is a ratchet; it may only '
              'shrink.\n\n'
              '${stale.map((String t) => '  $t').join('\n')}',
        );
      }
    }
  });

  test('working tree arms no new tracked -> untracked reference', () {
    if (!gitAvailable) {
      markTestSkipped('not a git checkout: reference integrity unverifiable');
      return;
    }

    final violations = <_Violation>[
      ...repo.dartImportViolations(treeish: null, inTree: repo.tracked),
      ...repo.pubspecAssetViolations(treeish: null, inTree: repo.tracked),
      ...repo.symbolViolations(treeish: null, inTree: repo.tracked),
      ...repo.androidManifestViolations(treeish: null, inTree: repo.tracked),
      ...repo.appleResourceViolations(treeish: null, inTree: repo.tracked),
      ...repo.cIncludeViolations(treeish: null, inTree: repo.tracked),
      ...repo.goImportViolations(treeish: null, inTree: repo.tracked),
    ];

    final found = violations.map((v) => v.target).toSet();
    final baseline = <String>{
      ..._knownArmedReferences.keys,
      // A defect already in HEAD is also, necessarily, a working-tree defect.
      // Listing it in one place and having it fail in the other would be a
      // guard that contradicts itself.
      ..._knownHeadViolations.keys,
    };

    final unexpected = violations.where((v) => !baseline.contains(v.target));

    expect(
      unexpected,
      isEmpty,
      reason: 'A tracked file now depends on a file git does not track. '
          'Committing that tracked file without this one breaks every clone '
          '- loudly if the reference is a path a compiler resolves, silently '
          'if it is a string (android:name, CODE_SIGN_ENTITLEMENTS, an '
          'xcassets filename) or a same-package symbol.\n'
          'Fix it: `git add` the target, or remove the reference. Do NOT add '
          'it to _knownArmedReferences - that list only records landmines '
          'that predate this test.\n\n'
          '${unexpected.map((v) => '  $v').join('\n')}',
    );

    expect(
      _staleAgainstDisk(repo, baseline, found),
      isEmpty,
      reason: 'These baseline entries are no longer violations - the files '
          'were tracked, or the references were removed. Delete each line '
          'from _knownArmedReferences (or _knownHeadViolations) in this file. '
          'The baseline is a ratchet; it is only allowed to shrink.\n\n'
          '${_staleAgainstDisk(repo, baseline, found).map((t) => '  $t').join('\n')}',
    );
  });

  test('no build surface is invisible to git', () {
    if (!gitAvailable) {
      markTestSkipped('not a git checkout: reference integrity unverifiable');
      return;
    }

    final surfaces = repo.invisibleBuildSurfaces();
    final baseline = _knownInvisibleBuildSurfaces.keys.toSet();

    final unexpected = surfaces.keys.where((String d) => !baseline.contains(d));

    expect(
      unexpected,
      isEmpty,
      reason: 'Something a build reads is neither tracked nor ignored, so git '
          'does not know it exists and a clone will not have it. Nothing '
          'points at it, so no import check can find this - it is only '
          'visible as an absence.\n'
          'Fix it: `git add` it if the build needs it, or add a .gitignore '
          'rule if it is scratch. Leaving it in neither state is what makes '
          'it invisible.\n\n'
          '${unexpected.map((String d) => '  $d  '
              '(${repo.describeSurface(d, surfaces[d]!)})').join('\n')}',
    );

    expect(
      _staleAgainstDisk(repo, baseline, surfaces.keys.toSet()),
      isEmpty,
      reason: 'These _knownInvisibleBuildSurfaces entries are resolved - now '
          'tracked, or ignored, or gone. Delete each line.\n\n'
          '${_staleAgainstDisk(repo, baseline, surfaces.keys.toSet()).map((String d) => '  $d').join('\n')}',
    );
  });

  test('no test file is missing from the tree', () {
    if (!gitAvailable) {
      markTestSkipped('not a git checkout: reference integrity unverifiable');
      return;
    }

    final found = repo.untrackedTestFiles();
    final baseline = _knownUntrackedTests.keys.toSet();

    final unexpected = found.where((String p) => !baseline.contains(p));

    expect(
      unexpected,
      isEmpty,
      reason: 'A test file sits in a directory git already tracks other test '
          'files in, and is not tracked itself. Nothing fails: the clone '
          'simply runs a smaller suite and reports green, which is how half '
          'a suite goes missing.\n'
          'Fix it: `git add` the test, together with whatever it imports.\n\n'
          '${unexpected.map((String p) => '  $p').join('\n')}',
    );

    expect(
      _staleAgainstDisk(repo, baseline, found),
      isEmpty,
      reason: 'These _knownUntrackedTests entries are resolved - the test is '
          'tracked now, or gone. Delete each line.\n\n'
          '${_staleAgainstDisk(repo, baseline, found).map((String p) => '  $p').join('\n')}',
    );
  });

  test('no build or release script requires a file git does not track', () {
    if (!gitAvailable) {
      markTestSkipped('not a git checkout: reference integrity unverifiable');
      return;
    }

    final requirements = repo.scriptRequirements;

    // A NULL RESULT FROM A CHECKER NEVER SEEN TO PRODUCE A NON-NULL ONE IS NOT
    // EVIDENCE. The port of this file lost an entire `project.pbxproj` scan to
    // a missing `re.M` and reported a confident zero. This scan resolves 56
    // tracked in-repo paths across the release scripts today; if a regex is broken, or
    // the scripts move, or `install`/`cp` stop being how this tree stages a
    // bundle, the count collapses and the green below would mean nothing. Fail
    // loudly instead, so the next person fixes the checker rather than
    // inheriting a muted one.
    final satisfied =
        requirements.keys.where(repo.tracked.contains).toList(growable: false);
    expect(
      satisfied.length,
      greaterThanOrEqualTo(30),
      reason: 'The build-script scan resolved only ${satisfied.length} tracked '
          'requirements across ${repo.tracked.where((String p) => p.endsWith('.sh')).length} '
          'scripts. It resolved 56 when written. This check is no longer '
          'looking at anything - repair it before trusting the result.',
    );

    // `untracked` is `git ls-files --others --exclude-standard`: on disk, not
    // tracked, NOT gitignored. A gitignored path is a deliberate declaration
    // and a build step may legitimately produce it; "neither tracked nor
    // ignored" is the state that hides a file from everyone but this machine.
    final found = requirements.keys.where(repo.untracked.contains).toSet();
    final baseline = _knownUntrackedScriptRequirements.keys.toSet();
    final unexpected = found
        .where((String p) => !baseline.contains(p))
        .map((String p) => requirements[p]!);

    expect(
      unexpected,
      isEmpty,
      reason: 'A build or release script requires a file git does not track. '
          'These scripts run under `set -Eeuo pipefail`: the build does not '
          'skip the missing file, it STOPS. A clone that takes the script '
          'change without the file cannot produce a release at all, and '
          'nothing else in this suite can see it - the directory-keyed '
          'surface check considers the directory covered, and there is no '
          'import to follow.\n'
          'Fix it: `git add` the file IN THE SAME COMMIT as the script that '
          'requires it, or make the script tolerate its absence.\n\n'
          '${unexpected.map((_Violation v) => '  $v').join('\n')}',
    );

    expect(
      _staleAgainstDisk(repo, baseline, found),
      isEmpty,
      reason: 'These _knownUntrackedScriptRequirements entries are resolved - '
          'the file is tracked now, or no script requires it any more. Delete '
          'each line. The baseline is a ratchet; it may only shrink.\n\n'
          '${_staleAgainstDisk(repo, baseline, found).map((String p) => '  $p').join('\n')}',
    );
  });
}

// ---------------------------------------------------------------------------

/// Baseline entries that are no longer violations AND that this checkout can
/// actually SEE.
///
/// This predicate is the whole reason the guard can be committed. In a fresh
/// clone none of the untracked files exist, so `baseline - found` is the
/// ENTIRE baseline and every ratchet reports every line as stale. The sibling
/// repository hit exactly that: tracking its guard unchanged would have made
/// the suite red on arrival in every clone and every CI job, and its own
/// header says what happens next - a red test gets skipped, and a real
/// protection becomes a muted one.
///
/// An entry is stale only where the file or directory is present on disk to be
/// judged. Nothing is relaxed where it IS present: an entry whose target
/// exists and is no longer a violation still fails. The consequence, stated
/// honestly: THE TWO WORKING-TREE RATCHETS ARE MACHINE-LOCAL BY NATURE. The
/// `HEAD` test is the half that travels.
Set<String> _staleAgainstDisk(
  _Repo repo,
  Set<String> baseline,
  Set<String> found,
) =>
    baseline.difference(found).where((String path) {
      final full = '${repo.root}/$path';
      return File(full).existsSync() || Directory(full).existsSync();
    }).toSet();

String? _repoRoot() {
  try {
    final result = Process.runSync(
      'git',
      <String>['rev-parse', '--show-toplevel'],
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    if (result.exitCode != 0) return null;
    final root = (result.stdout as String).trim();
    return root.isEmpty ? null : root;
  } on ProcessException {
    return null;
  }
}

class _Repo {
  _Repo(this.root);

  final String root;

  late final Set<String> tracked = _lines(<String>['ls-files']).toSet();

  late final Set<String> untracked =
      _lines(<String>['ls-files', '--others', '--exclude-standard']).toSet();

  final Map<String, Set<String>> _treeCache = <String, Set<String>>{};

  /// Paths present in `treeish`.
  ///
  /// `ls-tree`, NOT `ls-files`. `ls-files` reads the INDEX, and an index
  /// carrying staged deletions or staged additions answers a different
  /// question than "what is in this commit". In the sibling repository that
  /// exact substitution turned a real "103 of 103" result into a plausible
  /// "5 of 103", and the wrong number was believed. This repository's index
  /// happens to be clean today; that is not something to depend on.
  Set<String> pathsAt(String treeish) => _treeCache.putIfAbsent(
        treeish,
        () => _lines(<String>['ls-tree', '-r', '--name-only', treeish]).toSet(),
      );

  List<String> _lines(List<String> args) {
    final result = Process.runSync(
      'git',
      args,
      workingDirectory: root,
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    if (result.exitCode != 0) {
      throw StateError('git ${args.join(' ')} failed: ${result.stderr}');
    }
    return (result.stdout as String)
        .split('\n')
        .where((String line) => line.isNotEmpty)
        .toList();
  }

  /// `git grep`, returning (path, line) pairs. `treeish` null searches the
  /// tracked working-tree files, which is what a commit would capture.
  List<({String path, String text})> _grep(
    String pattern,
    List<String> pathspecs, {
    String? treeish,
    bool includeUntracked = false,
  }) {
    final args = <String>[
      'grep',
      '-I',
      '--no-color',
      '-E',
      if (includeUntracked) '--untracked',
      '-e',
      pattern,
      if (treeish != null) treeish,
      '--',
      ...pathspecs,
    ];
    final result = Process.runSync(
      'git',
      args,
      workingDirectory: root,
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );
    // git grep exits 1 when there are no matches; anything above that is real.
    if (result.exitCode > 1) {
      throw StateError('git ${args.join(' ')} failed: ${result.stderr}');
    }
    final prefix = treeish == null ? '' : '$treeish:';
    final out = <({String path, String text})>[];
    for (final line in (result.stdout as String).split('\n')) {
      if (line.isEmpty) continue;
      var rest = line;
      if (prefix.isNotEmpty) {
        if (!rest.startsWith(prefix)) continue;
        rest = rest.substring(prefix.length);
      }
      final split = rest.indexOf(':');
      if (split < 0) continue;
      out.add((path: rest.substring(0, split), text: rest.substring(split + 1)));
    }
    return out;
  }

  bool _isDerived(String path) =>
      _derivedOutputPrefixes.any((String p) => path.startsWith(p));

  /// The full text of every file in `treeish` matching `pathspecs`.
  ///
  /// One `git grep` for all of them rather than one `git show` each. `-e '^'`
  /// matches every line of every text file, blank lines included, and prints
  /// `treeish:path:line`, so joining the lines back in order reproduces the
  /// blob.
  ///
  /// Reading these from the tree rather than from disk is the point: the
  /// absolute check must ask what the COMMITTED file says. The working copy of
  /// `lib/main.dart` and of `ios/Runner.xcodeproj/project.pbxproj` both differ
  /// from HEAD's right now, and it is precisely those differences that arm the
  /// landmines in `_knownArmedReferences`.
  Map<String, String> _treeContents(String treeish, List<String> pathspecs) {
    final buffers = <String, StringBuffer>{};
    for (final match in _grep('^', pathspecs, treeish: treeish)) {
      (buffers[match.path] ??= StringBuffer()).writeln(match.text);
    }
    return buffers.map(
      (String path, StringBuffer text) => MapEntry(path, text.toString()),
    );
  }

  final Map<String, Map<String, String>> _sourceCache =
      <String, Map<String, String>>{};

  /// Every file of `extension` this check can see, keyed by path: the ones
  /// inside `treeish` read FROM THE TREE, and the ones on this machine that
  /// the tree does NOT contain read from disk.
  ///
  /// That second set is what makes the symbol check possible at all. A
  /// same-package reference names no path, so the only way to say "this
  /// committed file depends on something that was not committed" is to find
  /// the file that DOES declare the symbol - and it exists only on the machine
  /// that made the commit. In a fresh clone that set is empty and the check is
  /// vacuously green, which is correct: in a clone, the tree IS the disk.
  ///
  /// SHORT-CIRCUIT, and it is exact rather than a relaxation: if no file of
  /// this extension is outside the tree, no violation of this shape can exist,
  /// so nothing needs to be read. That is what keeps 637 tracked `.go` files
  /// from being streamed through `git grep` on every run of the suite.
  Map<String, String> _sourcesFor(
    String extension, {
    required String? treeish,
    required Set<String> inTree,
  }) {
    final key = '${treeish ?? ''}|$extension';
    final cached = _sourceCache[key];
    if (cached != null) return cached;

    final outOfTree = <String>[
      for (final path in <String>{...tracked, ...untracked})
        if (path.endsWith(extension) &&
            !inTree.contains(path) &&
            !_backupName.hasMatch(path))
          path,
    ];
    final sources = <String, String>{};
    if (outOfTree.isEmpty) return _sourceCache[key] = sources;

    if (treeish != null) {
      for (final entry
          in _treeContents(treeish, <String>['*$extension']).entries) {
        sources[entry.key] = _strip(entry.value);
      }
    } else {
      for (final path in tracked) {
        if (!path.endsWith(extension)) continue;
        final file = File('$root/$path');
        if (!file.existsSync()) continue;
        sources[path] = _strip(file.readAsStringSync());
      }
    }
    for (final path in outOfTree) {
      final file = File('$root/$path');
      if (!file.existsSync()) continue;
      sources[path] = _strip(file.readAsStringSync());
    }
    return _sourceCache[key] = sources;
  }

  // ------------------------------------------------------------------ Dart --

  static final RegExp _dartDirective =
      RegExp(r'''^\s*(?:import|export|part)\s+(['"])([^'"]+)\1''');

  /// name -> package root, read from the same tree being checked.
  final Map<String, Map<String, String>> _packageCache =
      <String, Map<String, String>>{};

  Map<String, String> _dartPackages(String? treeish) =>
      _packageCache.putIfAbsent(treeish ?? '', () {
        final packages = <String, String>{};
        for (final match in _grep(
          r'^name:[[:space:]]',
          <String>['*pubspec.yaml'],
          treeish: treeish,
          includeUntracked: treeish == null,
        )) {
          final name = RegExp(r'^name:\s*(\S+)').firstMatch(match.text);
          if (name == null) continue;
          packages.putIfAbsent(name.group(1)!, () => _dirname(match.path));
        }
        return packages;
      });

  List<_Violation> dartImportViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    final packages = _dartPackages(treeish);
    final matches = _grep(
      r'''^[[:space:]]*(import|export|part)[[:space:]]+['"]''',
      <String>['*.dart'],
      treeish: treeish,
    );
    for (final match in matches) {
      if (!inTree.contains(match.path)) continue;
      if (_backupName.hasMatch(match.path)) continue;
      final directive = _dartDirective.firstMatch(match.text);
      if (directive == null) continue;
      final uri = directive.group(2)!;
      // Only looks like a directive: a line of a program a test writes at run
      // time. A directive URI cannot interpolate (`$name`), and `@@NAME@@` is
      // a template slot the test fills before writing the file.
      if (uri.contains(r'$') || RegExp(r'^@@\w+@@$').hasMatch(uri)) continue;
      final target = _resolveDartUri(uri, from: match.path, packages: packages);
      if (target == null) continue; // dart:, or an external pub package
      if (inTree.contains(target)) continue;
      if (_isDerived(target)) continue;
      violations.add(_Violation(target, match.path, uri));
    }
    return violations;
  }

  String? _resolveDartUri(
    String uri, {
    required String from,
    required Map<String, String> packages,
  }) {
    if (uri.startsWith('dart:')) return null;
    if (uri.startsWith('package:')) {
      final rest = uri.substring('package:'.length);
      final slash = rest.indexOf('/');
      if (slash < 0) return null;
      final name = rest.substring(0, slash);
      final home = packages[name];
      if (home == null) return null; // a pub.dev dependency, not ours
      return _normalize('$home/lib/${rest.substring(slash + 1)}');
    }
    if (RegExp(r'^[a-zA-Z][a-zA-Z0-9+.\-]*:').hasMatch(uri)) return null;
    return _normalize('${_dirname(from)}/$uri');
  }

  // --------------------------------------------------------------- pubspec --

  /// `assets:` and `- asset:` entries in tracked pubspecs. In the sibling this
  /// shape shipped a font family with no font files.
  List<_Violation> pubspecAssetViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    final matches = _grep(
      r'^[[:space:]]+-[[:space:]]+(asset:[[:space:]]*)?[A-Za-z0-9_./+-]+$',
      <String>['*pubspec.yaml'],
      treeish: treeish,
    );
    for (final match in matches) {
      if (!inTree.contains(match.path)) continue;
      final entry = RegExp(r'^\s+-\s+(?:asset:\s*)?([A-Za-z0-9_./+-]+)$')
          .firstMatch(match.text);
      if (entry == null) continue;
      final value = entry.group(1)!;
      // Only path-shaped values; `- flutter` style list items are not paths.
      if (!value.contains('/') && !value.contains('.')) continue;
      final target = _normalize('${_dirname(match.path)}/$value');
      if (value.endsWith('/')) {
        // A directory asset ships everything under it.
        final stripped = target.endsWith('/')
            ? target.substring(0, target.length - 1)
            : target;
        final present = inTree.where((String p) => p.startsWith('$stripped/'));
        if (present.isEmpty) {
          violations.add(
            _Violation(
                stripped, match.path, 'asset directory has no tracked file'),
          );
        }
        for (final candidate in untracked) {
          if (candidate.startsWith('$stripped/') &&
              !_backupName.hasMatch(candidate)) {
            violations.add(
              _Violation(candidate, match.path, 'under asset dir $value'),
            );
          }
        }
        continue;
      }
      if (inTree.contains(target)) continue;
      if (_isDerived(target)) continue;
      violations.add(_Violation(target, match.path, 'pubspec asset $value'));
    }
    return violations;
  }

  // ------------------------------------------------ Kotlin/Swift/Java/Go ----

  /// Top-level declarations. `private` at file top level is file-scoped in
  /// both Kotlin and Swift, so such a name can never be another file's
  /// dependency; including it produces a false positive on every repeated
  /// helper name.
  static final RegExp _kotlinDecl = RegExp(
    r'^(?<mods>(?:(?:public|internal|private|protected|abstract|open|sealed|'
    r'final|data|enum|annotation|value|inline|external|expect|actual|suspend|'
    r'const|lateinit)[ \t]+)*)'
    r'(?:fun[ \t]+interface|class|interface|object|fun|val|var|typealias)[ \t]+'
    r'(?:<[^>]*>[ \t]*)?'
    r'(?:[A-Za-z_][\w.]*(?:<[^>]*>)?\??\.)?'
    r'(?<name>[A-Za-z_][A-Za-z0-9_]*)',
  );

  static final RegExp _swiftDecl = RegExp(
    r'^(?<mods>(?:(?:public|internal|private|fileprivate|open|final|indirect|'
    r'static)[ \t]+)*)'
    r'(?:class|struct|enum|protocol|typealias|func|let|var|actor)[ \t]+'
    r'(?<name>[A-Za-z_][A-Za-z0-9_]*)',
  );

  static final RegExp _javaDecl = RegExp(
    r'^(?<mods>(?:(?:public|protected|private|abstract|final|static|'
    r'strictfp)[ \t]+)*)'
    r'(?:class|interface|enum|record)[ \t]+'
    r'(?<name>[A-Za-z_][A-Za-z0-9_]*)',
  );

  /// Go has no `private` keyword and no per-file visibility at all: every
  /// top-level name in a directory is visible to every other file in that
  /// directory, exported or not. That makes Go the purest example of shape 2 -
  /// there is never an import line to grep for within a package. `mods` is
  /// captured empty so the shared [_declarations] filter is a no-op here.
  static final RegExp _goDecl = RegExp(
    r'^(?<mods>)(?:func[ \t]+|(?:type|var|const)[ \t]+)'
    r'(?<name>[A-Za-z_][A-Za-z0-9_]*)',
  );

  /// The compilation unit a file belongs to. Two files only see each other's
  /// unqualified top-level names when they are in the same one.
  static String _unitOf(String path, String extension) {
    // A Go package IS a directory. Nothing else about Go's layout matters.
    if (extension == '.go') return _dirname(path);
    final src = path.indexOf('/src/');
    if (src >= 0) {
      // Gradle module AND source set: src/main and src/test do not see each
      // other's top-level names in the direction that matters here.
      final rest = path.substring(src + 5);
      final slash = rest.indexOf('/');
      final set = slash < 0 ? rest : rest.substring(0, slash);
      return '${path.substring(0, src)}#$set';
    }
    final parts = path.split('/');
    return parts.length >= 3 ? parts.take(3).join('/') : _dirname(path);
  }

  static String _packageOf(String source, String path) {
    if (path.endsWith('.swift')) return '';
    if (path.endsWith('.go')) {
      final match =
          RegExp(r'^\s*package\s+(\w+)', multiLine: true).firstMatch(source);
      return match?.group(1) ?? '';
    }
    final match =
        RegExp(r'^\s*package\s+([\w.]+)', multiLine: true).firstMatch(source);
    return match?.group(1) ?? '';
  }

  static String _strip(String source) => source
      .replaceAll(RegExp(r'/\*.*?\*/', dotAll: true), ' ')
      .replaceAll(RegExp(r'^\s*//.*$', multiLine: true), '');

  Set<String> _declarations(String source, RegExp pattern) {
    final names = <String>{};
    for (final match in pattern.allMatches(source)) {
      if ((match.namedGroup('mods') ?? '').contains('private')) continue;
      final name = match.namedGroup('name')!;
      if (name.length >= 4) names.add(name);
    }
    return names;
  }

  /// A file inside the tree using a top-level symbol that only a file OUTSIDE
  /// the tree, in the same compilation unit, declares.
  ///
  /// This is shape 2, and it is the one no compiler and no grep-for-imports
  /// can help with. In Kotlin, Swift and Go a same-unit reference writes
  /// NOTHING down - no path, no import, nothing to search for. The build
  /// simply fails on every machine that does not have the second file, which
  /// is every machine except the one that wrote it.
  ///
  /// `treeish: null` asks the question of the working tree (the ratchet); a
  /// treeish asks it of a committed tree (the absolute check).
  List<_Violation> symbolViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    for (final entry in <(String, RegExp)>[
      ('.kt', _kotlinDecl),
      ('.swift', _swiftDecl),
      ('.java', _javaDecl),
      ('.go', _goDecl),
    ]) {
      final (extension, pattern) = entry;
      final sources = _sourcesFor(extension, treeish: treeish, inTree: inTree);
      if (sources.isEmpty) continue;
      final declarations = <String, Set<String>>{};
      final packages = <String, String>{};
      for (final path in sources.keys) {
        packages[path] = _packageOf(sources[path]!, path);
        declarations[path] = _declarations(
          sources[path]!,
          RegExp(pattern.pattern, multiLine: true),
        );
      }

      for (final path in sources.keys) {
        if (!inTree.contains(path)) continue;
        final unit = _unitOf(path, extension);
        final package = packages[path];
        final peers = sources.keys.where((String other) =>
            other != path &&
            _unitOf(other, extension) == unit &&
            packages[other] == package);
        final namesInTree = <String>{
          for (final peer in peers)
            if (inTree.contains(peer)) ...declarations[peer]!,
          ...declarations[path]!,
        };
        for (final peer in peers) {
          if (inTree.contains(peer)) continue;
          for (final name in declarations[peer]!) {
            if (namesInTree.contains(name)) continue;
            if (!RegExp('\\b$name\\b').hasMatch(sources[path]!)) continue;
            violations.add(_Violation(peer, path, 'uses $name'));
          }
        }
      }

      // Cross-module use goes through an explicit import, which is exact.
      if (extension == '.go') continue; // handled by goImportViolations
      final byFqn = <String, List<String>>{};
      for (final path in declarations.keys) {
        final package = packages[path];
        if (package == null || package.isEmpty) continue;
        for (final name in declarations[path]!) {
          byFqn.putIfAbsent('$package.$name', () => <String>[]).add(path);
        }
      }
      for (final path in sources.keys) {
        if (!inTree.contains(path)) continue;
        for (final match in RegExp(r'^\s*import\s+([\w.]+)', multiLine: true)
            .allMatches(sources[path]!)) {
          final owners = byFqn[match.group(1)!];
          if (owners == null) continue;
          if (owners.any(inTree.contains)) continue;
          for (final owner in owners) {
            violations.add(_Violation(owner, path, 'imports ${match.group(1)}'));
          }
        }
      }
    }
    return violations;
  }

  // ------------------------------------------------------------------- Go ---

  /// A tracked `.go` file importing a package inside one of this repository's
  /// own modules, where that package directory holds no file the tree has.
  ///
  /// Unlike the symbol check this one DOES have a string to follow, but the
  /// string is a module path rather than a file path, so it has to be resolved
  /// through every `go.mod`'s `module` line first.
  List<_Violation> goImportViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    final modules = <String, String>{};
    for (final match in _grep(
      r'^module[[:space:]]+',
      <String>['*go.mod'],
      treeish: treeish,
      includeUntracked: treeish == null,
    )) {
      final name = RegExp(r'^module\s+(\S+)').firstMatch(match.text);
      if (name == null) continue;
      modules.putIfAbsent(name.group(1)!, () => _dirname(match.path));
    }
    if (modules.isEmpty) return violations;

    for (final match in _grep(
      r'^[[:space:]]*([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?"[^"]+"[[:space:]]*$',
      <String>['*.go'],
      treeish: treeish,
    )) {
      if (!inTree.contains(match.path)) continue;
      final quoted = RegExp(r'"([^"]+)"').firstMatch(match.text);
      if (quoted == null) continue;
      final imported = quoted.group(1)!;
      for (final module in modules.keys) {
        if (imported != module && !imported.startsWith('$module/')) continue;
        final relative = imported.substring(module.length).replaceAll(
              RegExp(r'^/'),
              '',
            );
        final home = modules[module]!;
        final directory =
            relative.isEmpty ? home : _normalize('$home/$relative');
        bool inDirectory(String p) =>
            p.startsWith('$directory/') &&
            p.endsWith('.go') &&
            !p.substring(directory.length + 1).contains('/');
        if (inTree.any(inDirectory)) break;
        for (final candidate in untracked.where(inDirectory)) {
          violations.add(
            _Violation(candidate, match.path, 'import "$imported"'),
          );
        }
        break;
      }
    }
    return violations;
  }

  // ------------------------------------------------------------ C and C++ ---

  /// `#include "..."` from a tracked C/C++ file onto an untracked header.
  ///
  /// Only quoted includes: an angle-bracket include is a toolchain or SDK
  /// header and resolving those would mean modelling the include path, which
  /// invents false positives. A candidate is reported only when it is actually
  /// an untracked file on this disk - never when it is merely absent, because
  /// absent means "generated, or provided by the toolchain".
  List<_Violation> cIncludeViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    final headers = <String>[
      for (final p in untracked)
        if (RegExp(r'\.(h|hpp|hh|hxx|inc)$').hasMatch(p) &&
            !_backupName.hasMatch(p))
          p,
    ];
    if (headers.isEmpty) return violations; // exact short-circuit
    for (final match in _grep(
      r'^[[:space:]]*#[[:space:]]*include[[:space:]]+"',
      <String>['*.c', '*.cc', '*.cpp', '*.cxx', '*.h', '*.hpp'],
      treeish: treeish,
    )) {
      if (!inTree.contains(match.path)) continue;
      final quoted = RegExp(r'"([^"]+)"').firstMatch(match.text);
      if (quoted == null) continue;
      final include = quoted.group(1)!;
      final candidates = <String>{
        _normalize('${_dirname(match.path)}/$include'),
        _normalize(include),
        // The two desktop hosts compile with their own directory and their
        // runner/ subdirectory on the include path.
        for (final rootDir in <String>['windows', 'linux', 'macos'])
          if (match.path.startsWith('$rootDir/'))
            ..._normalizeAll(<String>[
              '$rootDir/$include',
              '$rootDir/runner/$include',
            ]),
      };
      if (candidates.any(inTree.contains)) continue;
      for (final candidate in candidates) {
        if (!headers.contains(candidate)) continue;
        violations.add(
          _Violation(candidate, match.path, '#include "$include"'),
        );
      }
    }
    return violations;
  }

  static Iterable<String> _normalizeAll(List<String> paths) =>
      paths.map(_normalize);

  // -------------------------------------------------------------- Apple -----

  /// Two more places Apple names a file by string and nothing checks it until
  /// far too late.
  ///
  /// * An `.xcassets` `Contents.json` lists image filenames. `actool` reads
  ///   the JSON, not the directory. This repository HAD that defect at HEAD -
  ///   the macOS AppIcon 16pt and 32pt PNGs - and it was fixed on 2026-08-07
  ///   by tracking them. Measured while it was live: `actool` took the worse
  ///   of the two branches. It exited 0, warned `Missing Content` naming both
  ///   files, and produced an icon set with holes. Nothing in a normal build
  ///   log stops on that, which is why this checker exists.
  /// * A `project.pbxproj` names entitlements, Info.plist and bridging headers
  ///   in build settings. `CODE_SIGN_ENTITLEMENTS` is the dangerous one: for
  ///   this app the entitlement it points at carries
  ///   `com.apple.developer.networking.networkextension`, without which the
  ///   packet tunnel provider does not load at all.
  List<_Violation> appleResourceViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];

    for (final match in _grep(
      r'"filename"[[:space:]]*:',
      <String>['*Contents.json'],
      treeish: treeish,
    )) {
      if (!inTree.contains(match.path)) continue;
      if (!match.path.contains('.xcassets/')) continue;
      final value =
          RegExp(r'"filename"\s*:\s*"([^"]+)"').firstMatch(match.text);
      if (value == null) continue;
      final target = _normalize('${_dirname(match.path)}/${value.group(1)!}');
      if (inTree.contains(target)) continue;
      violations.add(
        _Violation(target, match.path, 'xcassets filename ${value.group(1)}'),
      );
    }

    for (final match in _grep(
      r'^[[:space:]]*(CODE_SIGN_ENTITLEMENTS|INFOPLIST_FILE|'
      r'SWIFT_OBJC_BRIDGING_HEADER|MODULEMAP_FILE|EXPORTED_SYMBOLS_FILE)'
      r'[[:space:]]*=',
      <String>['*project.pbxproj'],
      treeish: treeish,
    )) {
      if (!inTree.contains(match.path)) continue;
      final setting = RegExp(
        r'^\s*(\w+)\s*=\s*"?([^";]+?)"?\s*;',
      ).firstMatch(match.text);
      if (setting == null) continue;
      final value = setting.group(2)!.trim();
      if (value.isEmpty || value.contains(r'$')) continue;
      // ios/Runner.xcodeproj/project.pbxproj -> paths are relative to ios/.
      final projectDir = _dirname(_dirname(match.path));
      final target = _normalize('$projectDir/$value');
      if (inTree.contains(target)) continue;
      // Only accuse when the file really is here and merely untracked. If it
      // is absent entirely, that is a broken project, not this defect.
      if (!untracked.contains(target)) continue;
      violations.add(
        _Violation(target, match.path, '${setting.group(1)} = $value'),
      );
    }

    return violations;
  }

  // ---------------------------------------------------- Android manifest ----

  /// `android:name` in a manifest inside the tree naming a class that only a
  /// file outside the tree declares.
  ///
  /// The manifest is the one place an Android class is named by string, so
  /// nothing checks it: the app compiles, links, installs, launches, and then
  /// throws `ActivityNotFoundException` the moment the user taps the button.
  /// Worse than a build failure, because it SHIPS.
  ///
  /// The accusation is only made when an out-of-tree file actually declares
  /// the class. That is deliberate: this repository's manifests carry
  /// `<activity-alias android:name=".LauncherReal">` and `.LauncherDecoy`
  /// (the decoy-launcher camouflage), plus meta-data names like
  /// `io.flutter.embedding.android.NormalTheme`. None of those is a class and
  /// none has a declaring file anywhere; a check that flagged "no declaration
  /// found" would report all ten of them forever and be muted within a week.
  List<_Violation> androidManifestViolations({
    required String? treeish,
    required Set<String> inTree,
  }) {
    final violations = <_Violation>[];
    final outOfTreeDeclarations = <String, List<String>>{};
    final inTreeDeclarations = <String>{};
    for (final extension in <String>['.kt', '.java']) {
      final sources = _sourcesFor(extension, treeish: treeish, inTree: inTree);
      for (final path in sources.keys) {
        final names = _declarations(
          sources[path]!,
          RegExp(
            extension == '.kt' ? _kotlinDecl.pattern : _javaDecl.pattern,
            multiLine: true,
          ),
        );
        if (inTree.contains(path)) {
          inTreeDeclarations.addAll(names);
        } else {
          for (final name in names) {
            outOfTreeDeclarations.putIfAbsent(name, () => <String>[]).add(path);
          }
        }
      }
    }
    if (outOfTreeDeclarations.isEmpty) return violations;

    for (final match in _grep(
      r'android:name="\.?[A-Za-z_][A-Za-z0-9_.]*"',
      <String>['*AndroidManifest.xml'],
      treeish: treeish,
    )) {
      if (!inTree.contains(match.path)) continue;
      for (final attribute
          in RegExp(r'android:name="(\.?[A-Za-z_][\w.]*)"')
              .allMatches(match.text)) {
        final value = attribute.group(1)!;
        // Only our own classes: a leading dot, or a package-qualified name.
        if (!value.startsWith('.') && !value.contains('.')) continue;
        final simple = value.split('.').last;
        if (inTreeDeclarations.contains(simple)) continue;
        final owners = outOfTreeDeclarations[simple];
        if (owners == null) continue;
        for (final owner in owners) {
          violations.add(
            _Violation(owner, match.path, 'android:name="$value"'),
          );
        }
      }
    }
    return violations;
  }

  // -------------------------------------------------------- build surfaces --

  /// Every directory prefix that contains at least one tracked file.
  late final Set<String> _trackedDirs = () {
    final dirs = <String>{''};
    for (final path in tracked) {
      final parts = path.split('/');
      for (var i = 1; i < parts.length; i += 1) {
        dirs.add(parts.take(i).join('/'));
      }
    }
    return dirs;
  }();

  /// Directories, or single marker files, that git neither tracks nor ignores
  /// but that a build reads.
  ///
  /// Two queries, because one shape hides from the other:
  ///
  /// * A DIRECTORY with no tracked file in it whose parent DOES have tracked
  ///   files. That boundary is the asymmetry: `tools/` is tracked and
  ///   `tools/native_messaging` is not, so the subdirectory is the unit worth
  ///   naming rather than each of its files.
  /// * A MARKER FILE untracked inside a directory that git otherwise tracks.
  ///   The directory query cannot see this one at all, and it is the shape
  ///   this repository has at HEAD: `windows/awg_engine/main.go` is tracked
  ///   while the `go.mod` that makes it a module is not, so a clone cannot
  ///   build that engine at all.
  ///
  /// `untracked` is `git ls-files --others --exclude-standard`, so an
  /// explicitly gitignored scratch tree never reaches this check. "Neither
  /// tracked nor ignored" is the whole point.
  Map<String, Set<String>> invisibleBuildSurfaces() {
    final surfaces = <String, Set<String>>{};
    for (final path in untracked) {
      final parts = path.split('/');
      if (!_buildSurfaceMarker.hasMatch(parts.last)) continue;
      if (_backupName.hasMatch(path)) continue;
      var reported = false;
      for (var i = 1; i < parts.length; i += 1) {
        final prefix = parts.take(i).join('/');
        if (_trackedDirs.contains(prefix)) continue;
        surfaces.putIfAbsent(prefix, () => <String>{}).add(path);
        reported = true;
        break;
      }
      // Every directory above it is tracked, so no directory is the unit -
      // the marker file itself is.
      if (!reported) surfaces.putIfAbsent(path, () => <String>{path});
    }
    return surfaces;
  }

  String describeSurface(String key, Set<String> markers) {
    // A single marker file that IS the key: the surrounding directory is
    // tracked, so say how many tracked peers it is hiding among.
    if (markers.length == 1 && markers.first == key) {
      final directory = _dirname(key);
      final peers = tracked.where((String p) => _dirname(p) == directory).length;
      return 'untracked build marker in $directory, which holds $peers '
          'tracked files';
    }
    final count = untracked
        .where((String p) =>
            p.startsWith('$key/') &&
            !p.contains('/Pods/') &&
            !p.contains('/.symlinks/') &&
            !p.contains('/ephemeral/'))
        .length;
    return '$count untracked files, incl. '
        '${markers.map((String f) => f.split('/').last).take(4).join(', ')}';
  }

  // --------------------------------------------------------------- tests ----

  /// Test files present on this machine and in no clone.
  ///
  /// Peer asymmetry again, and for the same reason the marker list is narrow:
  /// a repository this size holds plenty of scratch that merely looks like a
  /// test. A file counts only when it sits in a directory git ALREADY tracks
  /// other test files in - so `test/` and the Gradle `src/test/` source sets
  /// are in scope, while a dated backup tree full of copied tests is not.
  Set<String> untrackedTestFiles() {
    bool isTest(String path) {
      final base = path.split('/').last;
      return base.endsWith('_test.dart') ||
          base.endsWith('_test.go') ||
          base.endsWith('Test.kt') ||
          base.endsWith('Test.java') ||
          base.endsWith('Test.swift') ||
          base.endsWith('Tests.swift');
    }

    final trackedTestDirs = <String>{
      for (final path in tracked)
        if (isTest(path)) _dirname(path),
    };
    return <String>{
      for (final path in untracked)
        if (isTest(path) &&
            !_backupName.hasMatch(path) &&
            trackedTestDirs.contains(_dirname(path)))
          path,
    };
  }

  // --------------------------------------------- build-script requirements --

  /// One argument of a shell command: double-quoted, single-quoted, or bare.
  static const String _shellArgument =
      r'''(?:"([^"\n]+)"|'([^'\n]+)'|([^\s"';|&<>()]+))''';

  /// The ways a script in this tree says "this file must ALREADY be here".
  ///
  /// Derived by reading the scripts, not by inventing shapes: every one of the
  /// six occurs in a tracked `*.sh` in this repository, and between them they
  /// resolve every in-repo path the release scripts name. The first capture in
  /// each is the path that must exist BEFORE the line runs - the SOURCE of a
  /// copy, never its destination.
  ///
  ///  * `install`  - `tools/build_linux_release.sh` stages the bundle with it;
  ///                 this is the shape `RECOVERY.md` hides in.
  ///  * `cp`       - the same act, spelled the other way.
  ///  * `source`   - a script pulling in a sibling; absence is a hard failure
  ///                 under `set -u` and a silent one without it.
  ///  * `-f test`  - the explicit precondition, e.g.
  ///                 `[[ -f "$X" ]] || { echo ...; exit 65; }`.
  ///  * interpreter - `python3 tools/x.py`, `bash tools/y.sh`: the argument is
  ///                 a file the run needs.
  ///  * checksum   - `sha256sum "$f"`: pinning the digest of a file presumes
  ///                 the file.
  ///
  /// HEREDOCS AND OTHER WRITES ARE THE OPPOSITE and are handled by
  /// `_scriptCreationShapes`: a path the script itself writes is produced, not
  /// required, and demanding that git track it would be wrong.
  /// `<before><one argument><after>`, so no call site has to spell the
  /// argument alternation out again.
  static RegExp _shellShape(
    String before, {
    String after = '',
    bool multiLine = false,
  }) =>
      RegExp('$before$_shellArgument$after', multiLine: multiLine);

  static final List<(String, RegExp)> _scriptRequirementShapes =
      <(String, RegExp)>[
    (
      'install',
      _shellShape(
          r'\binstall\b(?:\s+(?:-m\s*[0-7]+|-o\s+\S+|-g\s+\S+|-[A-Za-z]+|--))*\s+')
    ),
    ('cp', _shellShape(r'\bcp\b(?:\s+(?:-[A-Za-z-]+|--))*\s+')),
    (
      'source',
      _shellShape(r'(?:^|;|\bthen\b|&&)\s*(?:\.|source)\s+', multiLine: true)
    ),
    ('-f test', _shellShape(r'\[\[?\s+-[fersx]\s+', after: r'\s*\]\]?')),
    (
      'interpreter',
      _shellShape(r'\b(?:bash|sh|python3|python|dart|node|ruby|perl)\s+')
    ),
    ('checksum', _shellShape(r'\b(?:sha256sum|shasum\s+-a\s+256)\s+')),
  ];

  /// Paths a script PRODUCES. Anything here is removed from that script's
  /// requirement set: a heredoc or a redirect writes the file, so it neither
  /// can nor should be tracked on that account.
  static final List<RegExp> _scriptCreationShapes = <RegExp>[
    _shellShape(r'>>?\s*'),
    _shellShape(r'\bmkdir\b(?:\s+-[A-Za-z]+)*\s+'),
    _shellShape(r'\btouch\b\s+'),
  ];

  static final RegExp _shellAssignment = RegExp(
    r'^[ \t]*(?:export[ \t]+|readonly[ \t]+|local[ \t]+)?'
    r'([A-Za-z_][A-Za-z0-9_]*)=(\S.*?)[ \t]*$',
    multiLine: true,
  );

  /// `ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"` and its
  /// `$0` variant - the idiom every build script in this tree opens with.
  static final RegExp _shellSelfDir = RegExp(
    r'''cd\s+"?\$\(\s*dirname\s+"?\$\{?(?:BASH_SOURCE\[0\]|0)\}?"?\s*\)"?'''
    r'''(/[^"\s&|]*)?''',
  );

  static final RegExp _shellTopLevel =
      RegExp(r'git\s+rev-parse\s+--show-toplevel');

  static final RegExp _shellVarRef =
      RegExp(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)');

  /// Blank out `#` comments, then join `\`-continued lines.
  ///
  /// Both halves were found by measuring rather than by reasoning.
  ///
  /// Without comment stripping the bare-word branch of `_shellArgument`
  /// matched ordinary English inside comment blocks and the scan produced
  /// dozens of nonsense paths.
  ///
  /// Without continuation joining the scan MISSED three real requirements of
  /// the Linux release build - the `.desktop` file, the metainfo XML and
  /// `web/icons/Icon-512.png` - because they are written as
  /// `install -D -m 0644 \` with the path on the next line. It found
  /// `RECOVERY.md` and looked complete while being blind to its neighbours,
  /// which is precisely the failure mode this whole file exists to catch.
  static String _stripShellComments(String text) {
    final out = StringBuffer();
    for (final line in text.split('\n')) {
      if (line.trimLeft().startsWith('#')) {
        out.writeln();
        continue;
      }
      String? quote;
      var cut = -1;
      for (var i = 0; i < line.length; i += 1) {
        final c = line[i];
        if (quote != null) {
          if (c == quote) {
            quote = null;
          } else if (c == r'\' && quote == '"') {
            i += 1;
          }
        } else if (c == '"' || c == "'") {
          quote = c;
        } else if (c == '#' && i > 0 && (line[i - 1] == ' ' || line[i - 1] == '\t')) {
          cut = i;
          break;
        }
      }
      out.writeln(cut < 0 ? line : line.substring(0, cut));
    }
    var joined = out.toString();
    while (joined.contains('\\\n')) {
      joined = joined.replaceAll('\\\n', ' ');
    }
    return joined;
  }

  static String _unquote(String value) {
    if (value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'")))) {
      return value.substring(1, value.length - 1);
    }
    return value;
  }

  /// Substitute the variables this scan understands. Returns null the moment
  /// anything is left unresolved - a command substitution, an unknown name, a
  /// glob, a positional parameter. Refusing to guess is what keeps the result
  /// precise enough to be worth failing a suite over.
  static String? _resolveShellWord(String value, Map<String, String> env) {
    if (value.contains(r'$(') || value.contains('`')) return null;
    final out = StringBuffer();
    var i = 0;
    while (i < value.length) {
      final match = _shellVarRef.matchAsPrefix(value, i);
      if (match != null) {
        final name = match.group(1) ?? match.group(2)!;
        final resolved = env[name];
        if (resolved == null) return null;
        out.write(resolved);
        i = match.end;
      } else {
        out.write(value[i]);
        i += 1;
      }
    }
    final text = out.toString();
    for (final bad in const <String>[r'$', '*', '?', '{', '}', '[', ']']) {
      if (text.contains(bad)) return null;
    }
    return text;
  }

  /// Variable -> absolute path, for the variables that resolve inside the repo.
  Map<String, String> _shellEnvironment(String scriptPath, String text) {
    final scriptDir = '$root/${_dirname(scriptPath)}';
    final env = <String, String>{};
    for (final match in _shellAssignment.allMatches(text)) {
      final name = match.group(1)!;
      final raw = match.group(2)!;
      if (raw.contains('pwd')) {
        final selfDir = _shellSelfDir.firstMatch(raw);
        if (selfDir != null) {
          env[name] = '/${_normalize('$scriptDir${selfDir.group(1) ?? ''}')}';
          continue;
        }
      }
      if (_shellTopLevel.hasMatch(raw)) {
        env[name] = root;
        continue;
      }
      final resolved = _resolveShellWord(_unquote(raw.trim()), env);
      if (resolved != null && resolved.startsWith('/')) {
        env[name] = '/${_normalize(resolved)}';
      }
    }
    return env;
  }

  /// Repo-relative paths a script argument could name, keeping only the ones
  /// that exist on disk.
  ///
  /// A relative path is tried against BOTH the repo root and the script's own
  /// directory, because scripts here do both and which one applies depends on
  /// a `cd` that may be several conditionals away. Ambiguity is safe in this
  /// direction: a candidate is only ever reported when it is a real file that
  /// git does not track, so a wrong guess resolves to nothing and disappears.
  List<String> _scriptCandidates(
    String raw,
    Map<String, String> env,
    String scriptPath,
  ) {
    final resolved = _resolveShellWord(raw, env);
    if (resolved == null) return const <String>[];
    final bases = resolved.startsWith('/')
        ? <String>[resolved]
        : <String>['$root/$resolved', '$root/${_dirname(scriptPath)}/$resolved'];
    final out = <String>[];
    for (final candidate in bases) {
      final normalized = '/${_normalize(candidate)}';
      if (!normalized.startsWith('$root/')) continue;
      final relative = normalized.substring(root.length + 1);
      if (relative.isEmpty || _backupName.hasMatch(relative)) continue;
      if (!File(normalized).existsSync()) continue;
      if (!out.contains(relative)) out.add(relative);
    }
    return out;
  }

  /// Every in-repo file a tracked build or release script REQUIRES, mapped to
  /// the reference that requires it.
  ///
  /// Only TRACKED scripts are read. An untracked script is not in a clone at
  /// all, so nothing it requires can break one - the defect this answers is
  /// specifically "the clone has the script and not the file".
  late final Map<String, _Violation> scriptRequirements = () {
    final found = <String, _Violation>{};
    for (final script in tracked.where((String p) => p.endsWith('.sh'))) {
      if (_backupName.hasMatch(script)) continue;
      final String text;
      try {
        text = _stripShellComments(File('$root/$script').readAsStringSync());
      } on FileSystemException {
        continue;
      }
      final env = _shellEnvironment(script, text);
      final produced = <String>{};
      for (final shape in _scriptCreationShapes) {
        for (final match in shape.allMatches(text)) {
          final raw = match.group(1) ?? match.group(2) ?? match.group(3)!;
          produced.addAll(_scriptCandidates(raw, env, script));
        }
      }
      for (final (name, shape) in _scriptRequirementShapes) {
        for (final match in shape.allMatches(text)) {
          final raw = match.group(1) ?? match.group(2) ?? match.group(3)!;
          if (raw.startsWith('-')) continue;
          // A bare word with neither a slash nor an extension is prose or a
          // flag value, not a path.
          if (!raw.contains('/') && !RegExp(r'\.[A-Za-z0-9_]{1,12}$').hasMatch(raw)) {
            continue;
          }
          for (final relative in _scriptCandidates(raw, env, script)) {
            if (produced.contains(relative)) continue;
            found.putIfAbsent(
              relative,
              () => _Violation(relative, script, '$name: $raw'),
            );
          }
        }
      }
    }
    return found;
  }();
}

String _dirname(String path) {
  final index = path.lastIndexOf('/');
  return index <= 0 ? '' : path.substring(0, index);
}

String _normalize(String path) {
  final out = <String>[];
  for (final part in path.split('/')) {
    if (part.isEmpty || part == '.') continue;
    if (part == '..') {
      if (out.isNotEmpty && out.last != '..') {
        out.removeLast();
        continue;
      }
    }
    out.add(part);
  }
  return out.join('/');
}
