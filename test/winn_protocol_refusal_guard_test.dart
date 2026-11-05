import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// GUARD TEST, not a behavioral unit test -- read this before touching it.
//
// WHAT THIS FILE USED TO GUARD, AND WHY THAT CHANGED.
//
// This file previously asserted that `winn/3` was refused outright, per
// WINN_PROTOCOL_PLATFORM_PLAN.md rule 2 ("No on-switch ... Enabling in
// production is a governance decision, not an engineering one"). That
// governance decision has since been taken: the owner decided the app ships
// with Winn Protocol v3, and `winn/3` is now dispatched to the Android Winn
// path. So the blanket refusal is gone.
//
// THE PROPERTY UNDERNEATH IT DID NOT CHANGE, and this file now guards that
// instead: a `winn/3` config must never end up starting the classical
// `winn/1` AmneziaWG path. The gateway negotiated a post-quantum-generation
// session; a client that quietly speaks the classical protocol instead has
// silently downgraded it. Rule 2's actual concern -- "a client that advertises
// post-quantum support it cannot honour is worse than one that refuses" -- is
// therefore preserved in a stronger form than a blanket refusal gave: where
// Winn cannot start, the connection FAILS rather than falling back.
//
// There are two independent places that must honour that, and this file
// guards both:
//
//   1. the dispatch seam in `_startTunnelCandidate`, which must `return false`
//      rather than `break` when Winn cannot start; and
//   2. `_buildRawAmneziaConfig`, the only function that turns a served config
//      into the string the native tunnel starts from, which must THROW for a
//      `winn/3` config it cannot build a `[winn]` section for. That second gate
//      is what makes the property survive the seam being removed, reordered or
//      bypassed by a new call site.
//
// Why this reads source text instead of calling the code: both live inside
// private (leading-underscore) methods on a State class in lib/main.dart. Dart
// privacy is per-*library* (per file), so a leading underscore makes a member
// inaccessible from every other file -- including this one -- no matter what it
// imports. test/smart_protocol_transport_policy_test.dart establishes the
// precedent for this situation elsewhere in the same file: read the source,
// slice out a function body between two anchor strings, and assert on the text.
//
// The BEHAVIOURAL half of this contract -- what actually counts as "can start
// Winn" -- is a pure library and is tested normally, in
// test/winn_protocol_dispatch_test.dart.
//
// The anchors below are comments and code lines, not line numbers, so
// unrelated edits elsewhere in this 8000+ line file cannot make this test
// drift out of sync the way a hard-coded line range would.
void main() {
  late String source;
  late String seam;
  late String configBuilder;

  // Assertions below are about CODE, so full-line comments are removed first.
  // Without this, a comment that names a symbol in order to say the code must
  // NOT call it -- "NOT _promptAppUpdateRequired(): an update cannot give an
  // iPhone an Android tunnel" -- would satisfy a `contains` check and defeat
  // the very assertion it was explaining. Only whole comment lines are
  // dropped, so no string literal in the code can be damaged.
  String withoutComments(String code) => code
      .split('\n')
      .where((line) => !line.trimLeft().startsWith('//'))
      .join('\n');

  String slice(String from, String to, String what) {
    final start = source.indexOf(from);
    expect(
      start,
      greaterThanOrEqualTo(0),
      reason: 'The $what start anchor is gone from lib/main.dart. Either it '
          'was reworded (update the anchor string in this test to match) or '
          'the code itself was removed -- both need a human before this test '
          'can be trusted again.',
    );
    final end = source.indexOf(to, start);
    expect(
      end,
      greaterThan(start),
      reason: 'Could not find the $what end anchor after its start. Update '
          'this test if the code immediately following it legitimately '
          'changed.',
    );
    return source.substring(start, end);
  }

  setUpAll(() {
    source = File('lib/main.dart').readAsStringSync();
    seam = withoutComments(slice(
      '// --- Winn Protocol dispatch seam ---',
      "final stealthActive = _boolValue(config['stealth_active']);",
      'Winn Protocol dispatch seam',
    ));
    // The signature gained an optional `winn3Descriptor` on 2026-08-09 -- the
    // verified gateway descriptor a STANDALONE session needs, passed in rather
    // than derived here because verification is asynchronous and this builder
    // is not. The anchor is the function NAME plus its opening paren so the
    // slice survives a parameter list changing again; the shape it guards is
    // the throw below, not the arguments.
    configBuilder = withoutComments(slice(
      'String _buildRawAmneziaConfig(',
      "final obfs = config['obfuscation'] is Map",
      'AmneziaWG config builder Winn gate',
    ));
  });

  test('the dispatch seam still switches on winn/1 and winn/3', () {
    expect(seam, contains('case kWinnProtocolV1:'));
    expect(seam, contains('case kWinnProtocolV3:'));
  });

  test('winn/3 has its own case body and no longer shares default\'s', () {
    // The previous shape was `case 'winn/3': default:` -- grouped fallthrough
    // into a single refusal. winn/3 is now dispatched, so it must have a body.
    expect(
      RegExp(r'case kWinnProtocolV3:\s*default:').hasMatch(seam),
      isFalse,
      reason: 'winn/3 is no longer refused outright; it must not share the '
          'default: refusal body.',
    );
  });

  test('THE ANTI-DOWNGRADE GUARD: a winn/3 config that cannot start Winn '
      'returns false and never breaks into the AmneziaWG path', () {
    // This is the single most important assertion in this file. If someone
    // later "fixes" a Winn start failure by falling through to AmneziaWG --
    // by turning this `return false` into a `break`, or by deleting the
    // unsupported branch entirely -- this test is what fails.
    final winn3Start = seam.indexOf('case kWinnProtocolV3:');
    final defaultStart = seam.indexOf('default:', winn3Start);
    expect(winn3Start, greaterThanOrEqualTo(0));
    expect(
      defaultStart,
      greaterThan(winn3Start),
      reason: 'The default: branch must still follow winn/3.',
    );
    final winn3Body = seam.substring(winn3Start, defaultStart);

    expect(
      winn3Body,
      contains('resolveWinnProtocolStart('),
      reason: 'winn/3 must ask whether the Winn path can actually start on '
          'this platform with this config. Starting it unconditionally would '
          'be the mirror-image bug: claiming Winn where there is none.',
    );

    final guard = winn3Body.indexOf('if (!winnDecision.supported)');
    expect(
      guard,
      greaterThanOrEqualTo(0),
      reason: 'winn/3 must branch on whether the Winn path can start. With no '
          'such branch it would fall through to the AmneziaWG code below on '
          'every platform that has no Winn engine -- a silent downgrade on '
          'iOS, macOS, Windows and Linux.',
    );

    // Everything between the guard and the end of the case must refuse. The
    // refusal must be a `return`, because a `break` here leaves the switch and
    // runs the shared AmneziaWG start logic below it.
    final refusalBranch = winn3Body.substring(guard);
    final returnFalse = refusalBranch.indexOf('return false;');
    expect(
      returnFalse,
      greaterThanOrEqualTo(0),
      reason: 'An unstartable winn/3 config must `return false` -- fail the '
          'connection -- not continue.',
    );
    expect(
      refusalBranch.substring(0, returnFalse),
      isNot(contains('break;')),
      reason: 'A `break;` on the unsupported path would fall out of the switch '
          'into the shared AmneziaWG start logic below, silently downgrading a '
          'Winn Protocol v3 negotiation to classical AmneziaWG. That is the '
          'exact failure this seam exists to prevent.',
    );
  });

  test('a winn/3 refusal tells the user, and is not disguised as an app '
      'update', () {
    final winn3Start = seam.indexOf('case kWinnProtocolV3:');
    final defaultStart = seam.indexOf('default:', winn3Start);
    final winn3Body = seam.substring(winn3Start, defaultStart);
    expect(
      winn3Body,
      contains('_showFeedback('),
      reason: 'A connection that stops because Winn cannot start must say so. '
          'A silent `return false` is indistinguishable from a hang.',
    );
    expect(
      winn3Body,
      contains('_persistTunnelFailureDiagnostic('),
      reason: 'The refusal reason must reach the failure diagnostic, or a '
          'field report of "it just will not connect" has nothing behind it.',
    );
    expect(
      winn3Body,
      isNot(contains('_promptAppUpdateRequired')),
      reason: 'Updating the app cannot give an iPhone an Android tunnel and '
          'cannot make a malformed config valid. Sending the user to the '
          'store here would be a false explanation.',
    );
  });

  test('an unknown or future protocol_version still refuses outright', () {
    final defaultStart = seam.indexOf('default:');
    expect(defaultStart, greaterThanOrEqualTo(0));
    final defaultBody = seam.substring(defaultStart);
    final prompt = defaultBody.indexOf('_promptAppUpdateRequired()');
    final returnFalse = defaultBody.indexOf('return false;');
    expect(
      prompt,
      greaterThanOrEqualTo(0),
      reason: 'An unknown protocol_version must still route to the '
          'force-update prompt. Only the KNOWN value winn/3 became supported.',
    );
    expect(
      returnFalse,
      greaterThan(prompt),
      reason: 'The default branch must return false AFTER prompting, so an '
          'unknown protocol never proceeds to start.',
    );
    expect(
      defaultBody.substring(prompt, returnFalse),
      isNot(contains('break;')),
      reason: 'A `break;` here would fall through past the switch into the '
          'shared AmneziaWG start logic -- a silent downgrade of whatever '
          'future protocol the gateway just named.',
    );
  });

  test('winn/1 (the shipping protocol) is never routed to a refusal', () {
    final winn1Start = seam.indexOf('case kWinnProtocolV1:');
    final winn3Start = seam.indexOf('case kWinnProtocolV3:');
    expect(winn1Start, greaterThanOrEqualTo(0));
    expect(winn3Start, greaterThan(winn1Start));
    final winn1Body = seam.substring(winn1Start, winn3Start);
    expect(
      winn1Body,
      contains('break;'),
      reason: 'winn/1 must fall through to the shared AmneziaWG path below '
          'the switch, unchanged (rule 1: additive only).',
    );
    expect(
      winn1Body,
      isNot(contains('_promptAppUpdateRequired')),
      reason: 'winn/1 is the protocol AmneziaWG ships today; it must never be '
          'routed to the update-required refusal.',
    );
    expect(
      winn1Body,
      isNot(contains('resolveWinnProtocolStart')),
      reason: 'winn/1 must not consult the Winn policy at all. Doing so would '
          'let a Winn-side change break the shipping protocol.',
    );
  });

  test('the dispatch seam never returns true for any branch', () {
    // The seam only ever does one of two things: `break` to fall through to
    // the shared AmneziaWG path below it, or `return false` to refuse. It must
    // never itself report success -- success here would mean "a tunnel
    // started" before the shared setup code even runs.
    expect(seam, isNot(contains('return true')));
  });

  test('there is exactly one winn/3 dispatch point in the client', () {
    // Guards against a second, more permissive switch/if-chain being added
    // elsewhere in this file that special-cases winn/3 outside this seam.
    final occurrences = 'case kWinnProtocolV3:'.allMatches(source).length;
    expect(
      occurrences,
      1,
      reason: 'Found $occurrences occurrences of "case kWinnProtocolV3:" in '
          'lib/main.dart; expected exactly 1. A second dispatch point for '
          'winn/3 needs the same scrutiny as this one.',
    );
  });

  test('THE SECOND ANTI-DOWNGRADE GATE: the config builder resolves its [winn] '
      'section through the throwing gate', () {
    // _buildRawAmneziaConfig is the only function that turns a served config
    // into the string handed to startTunnel. Routing it through
    // winnSectionForTunnelConfig is what keeps the anti-downgrade property
    // alive if the dispatch seam above is ever removed, reordered, or bypassed
    // by a new call site that forgets it.
    //
    // What that gate DOES on a winn/3 config it cannot start -- throw, rather
    // than return an empty section -- is proven behaviourally in
    // test/winn_protocol_dispatch_test.dart. This test only guards that the
    // builder still goes through it.
    expect(
      configBuilder,
      contains('winnSectionForTunnelConfig('),
      reason: 'The config builder must resolve its [winn] section through the '
          'gate that throws for an unstartable winn/3 config. Building the '
          'section inline, or defaulting it to \'\', reintroduces the silent '
          'downgrade: an AmneziaWG config with no [winn] section is exactly '
          'what VpnTunnelService starts as plain AmneziaWG.',
    );
    expect(
      configBuilder,
      isNot(contains('catch')),
      reason: 'Catching the gate\'s StateError here would turn a refusal back '
          'into a plain AmneziaWG start.',
    );
    expect(
      configBuilder,
      isNot(contains('?? \'\'')),
      reason: 'Defaulting the section to the empty string would defeat the '
          'gate.',
    );
  });

  test('the config builder actually emits the [winn] section it resolved', () {
    // A builder that resolved the section and then dropped it would produce a
    // config with no [winn] section -- which VpnTunnelService reads as "not
    // enabled" and starts as plain AmneziaWG. That is a silent downgrade
    // produced by the builder rather than by the switch, so it is guarded
    // separately from the throw above.
    // Anchored on the function NAME, not on its parameter list -- see the
    // note in setUpAll. What this test guards is that the resolved section is
    // interpolated into the returned document, which no signature change can
    // make true or false.
    final builderBody = withoutComments(slice(
      'String _buildRawAmneziaConfig(',
      'String _currentSelectedSlug()',
      'AmneziaWG config builder body',
    ));
    expect(
      builderBody,
      contains(r'$winnSection'),
      reason: 'The resolved [winn] section must be interpolated into the '
          'returned configuration. Without it the native host sees no [winn] '
          'section and starts the classical AmneziaWG path for a winn/3 '
          'config.',
    );
  });
}
