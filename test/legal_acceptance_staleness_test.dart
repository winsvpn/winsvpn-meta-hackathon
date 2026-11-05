import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/main.dart';

/// Regression tests for the legal-acceptance prompt.
///
/// THE BUG THESE EXIST FOR. `_bundledLegalDocument()` sets its `hash` to the
/// empty string deliberately, so the hub records its own canonical hash when
/// `/legal/current` is unreachable. The acceptance check then compared the
/// stored hash against that empty string as though it were a document
/// identifier. The result: a user who accepted while the live document loaded
/// stored the server's hash, and the very next launch that fell back to the
/// bundled copy -- a 4 second fetch budget makes that ordinary, not exotic --
/// compared `<server hash> != ''`, decided the document had changed, and
/// re-prompted. Accepting offline and then coming online failed the same way in
/// reverse.
///
/// So acceptance could never survive a change in network reachability, which is
/// exactly what the owner reported: "it won't recognize the Acceptance of
/// Privacy Policy properly."
///
/// It shipped because the decision lived inside a State method no test could
/// reach. It is now a pure top-level function, and these pin it.
void main() {
  const version = '2026-07-21.v1';
  const serverHash = 'a3f1c0de5b7290aa11ff00998877665544332211aabbccddeeff0011';

  group('legalAcceptanceIsStale', () {
    test('nothing accepted yet is stale', () {
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: '',
          acceptedHash: '',
          currentVersion: version,
          currentHash: serverHash,
        ),
        isTrue,
      );
    });

    test('a whitespace-only accepted version is stale, not silently accepted',
        () {
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: '   ',
          acceptedHash: serverHash,
          currentVersion: version,
          currentHash: serverHash,
        ),
        isTrue,
      );
    });

    test('THE BUG: accepted online, then the bundled copy loads offline', () {
      // Stored the server's hash. Now the fetch timed out and the bundled
      // document -- whose hash is deliberately empty -- is what we have.
      // Before the fix this returned true and re-prompted a user who had
      // already agreed to this exact version.
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: serverHash,
          currentVersion: version,
          currentHash: '',
        ),
        isFalse,
      );
    });

    test('THE BUG IN REVERSE: accepted offline, then the live copy loads', () {
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: '',
          currentVersion: version,
          currentHash: serverHash,
        ),
        isFalse,
      );
    });

    test('a new document version always re-prompts', () {
      // The version is the identity of what was agreed to. This must keep
      // working, or the fix above would have quietly disabled the prompt.
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: serverHash,
          currentVersion: '2026-09-01.v2',
          currentHash: serverHash,
        ),
        isTrue,
      );
    });

    test('two hashes that are both present and different re-prompt', () {
      // Same version, but the document genuinely changed underneath it. That is
      // a real integrity signal and must NOT be swallowed by the fix.
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: serverHash,
          currentVersion: version,
          currentHash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        ),
        isTrue,
      );
    });

    test('an unchanged document does not re-prompt', () {
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: serverHash,
          currentVersion: version,
          currentHash: serverHash,
        ),
        isFalse,
      );
    });

    test('both hashes absent is not stale when the version matches', () {
      // Two consecutive offline launches. Nothing asserts a hash either time,
      // so there is no evidence the document changed.
      expect(
        legalAcceptanceIsStale(
          acceptedVersion: version,
          acceptedHash: '',
          currentVersion: version,
          currentHash: '',
        ),
        isFalse,
      );
    });

    test('reachability can flip repeatedly without ever re-prompting', () {
      // The user-visible symptom was that this sequence prompted every time.
      final sequence = <String>['', serverHash, '', serverHash, ''];
      var accepted = serverHash;
      for (final current in sequence) {
        expect(
          legalAcceptanceIsStale(
            acceptedVersion: version,
            acceptedHash: accepted,
            currentVersion: version,
            currentHash: current,
          ),
          isFalse,
          reason: 'flipping reachability must not re-prompt (current=$current)',
        );
        if (current.isNotEmpty) accepted = current;
      }
    });
  });
}
