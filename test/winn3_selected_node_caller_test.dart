import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wins_vpn/winn_protocol_dispatch.dart';

/// Flutter startTunnel must send the independently selected node slug to
/// Android and Apple. Deriving that identity only from served INI is the
/// self-claim native hosts already refuse to treat as the caller's choice.
void main() {
  group('resolveWinn3StartTunnelCallerIdentity', () {
    test('sends the exact independently selected slug, not an ASCII fold', () {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'Lab-Alpha',
        servedConfig: <String, dynamic>{'node_slug': 'lab-alpha'},
      );
      expect(caller.isPresent, isTrue);
      expect(caller.exactSlug, 'Lab-Alpha');
      expect(
        caller.startArguments[Winn3StartTunnelCallerIdentity.startArgumentKey],
        'Lab-Alpha',
      );
      expect(caller.startArguments.containsKey('node_slug'), isFalse);
    });

    test('does not substitute a served INI identity when the caller is missing',
        () {
      for (final missing in <String>['', '  ', 'auto', 'AUTO', ' auto ']) {
        final caller = resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: missing,
          servedConfig: <String, dynamic>{'node_slug': 'lab-alpha'},
        );
        expect(
          caller.isPresent,
          isFalse,
          reason:
              'independent slug "$missing" must not fall back to served INI',
        );
        expect(caller.startArguments, isEmpty, reason: missing);
      }
    });

    test('Unicode, dotted, and non-string caller slugs are missing', () {
      expect(
        resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: '\u212A1',
        ).isPresent,
        isFalse,
      );
      expect(
        resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: 'id.1',
        ).isPresent,
        isFalse,
      );
    });

    test('conflicting served aliases refuse even when one matches the caller',
        () {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'lab-alpha',
        servedConfig: <String, dynamic>{
          'node_slug': 'lab-alpha',
          'location_slug': 'lab-beta',
        },
      );
      expect(caller.isPresent, isFalse);
      expect(caller.startArguments, isEmpty);
    });

    test('a served identity that disagrees with the caller is a mismatch', () {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'lab-alpha',
        servedConfig: <String, dynamic>{'selected_node': 'lab-beta'},
      );
      expect(caller.isPresent, isFalse);
    });

    test('each served alias alone still agrees with the independent slug', () {
      for (final key in kWinn3SelectedNodeIdentityKeys) {
        final caller = resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: 'LAB-ALPHA',
          servedConfig: <String, dynamic>{key: 'lab-alpha'},
        );
        expect(caller.isPresent, isTrue, reason: key);
        expect(caller.exactSlug, 'LAB-ALPHA', reason: key);
      }
    });

    test('nested selected_node slug agrees; a map without a slug refuses', () {
      expect(
        resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: 'lab-alpha',
          servedConfig: <String, dynamic>{
            'selected_node': <String, dynamic>{
              'slug': 'Lab-Alpha',
              'name': 'Lab Alpha',
            },
          },
        ).isPresent,
        isTrue,
      );
      expect(
        resolveWinn3StartTunnelCallerIdentity(
          independentlySelectedSlug: 'lab-alpha',
          servedConfig: <String, dynamic>{
            'selected_node': <String, dynamic>{'name': 'Lab Alpha'},
          },
        ).isPresent,
        isFalse,
      );
    });

    test('nested selected_node slug conflict is a mismatch', () {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'lab-alpha',
        servedConfig: <String, dynamic>{
          'selected_node': <String, dynamic>{
            'slug': 'lab-alpha',
            'node_slug': 'lab-beta',
          },
        },
      );
      expect(caller.isPresent, isFalse);
    });

    test('a present independent slug is enough when served aliases are absent',
        () {
      final caller = resolveWinn3StartTunnelCallerIdentity(
        independentlySelectedSlug: 'user-node',
        servedConfig: const <String, dynamic>{},
      );
      expect(caller.isPresent, isTrue);
      expect(
        caller.startArguments[Winn3StartTunnelCallerIdentity.startArgumentKey],
        'user-node',
      );
    });
  });

  group('copyWinn3SelectedNodeIdentities', () {
    test('preserves conflicting aliases instead of first-wins collapse', () {
      final copied = copyWinn3SelectedNodeIdentities(
        dest: <String, dynamic>{'node_slug': 'lab-alpha'},
        raw: <String, dynamic>{
          'node_slug': 'lab-alpha',
          'location_slug': 'lab-beta',
        },
      );
      expect(copied['node_slug'], 'lab-alpha');
      expect(copied['location_slug'], 'lab-beta');
      expect(winn3SelectedNodeIdentity(copied), isEmpty);
    });

    test('keeps a selected_node map instead of toString-coercing it', () {
      final copied = copyWinn3SelectedNodeIdentities(
        dest: <String, dynamic>{'node_slug': ''},
        raw: <String, dynamic>{
          'selected_node': <String, dynamic>{
            'slug': 'lab-alpha',
            'name': 'Lab Alpha',
          },
        },
      );
      expect(copied['selected_node'], isA<Map>());
      expect(winn3SelectedNodeIdentity(copied), 'lab-alpha');
    });
  });

  group('Flutter startTunnel caller wiring', () {
    late String source;
    late String candidate;

    String withoutComments(String code) => code
        .split('\n')
        .where((line) => !line.trimLeft().startsWith('//'))
        .join('\n');

    setUpAll(() {
      source = File('lib/main.dart').readAsStringSync();
      final start = source.indexOf('Future<bool> _startTunnelCandidate(');
      final end = source.indexOf(
        'Future<bool> _loadPowerProtectionPromptSeen(',
        start,
      );
      expect(start, greaterThanOrEqualTo(0));
      expect(end, greaterThan(start));
      candidate = withoutComments(source.substring(start, end));
    });

    test('every native host receives the independently selected slug', () {
      expect(
        candidate,
        contains('resolveWinn3StartTunnelCallerIdentity('),
      );
      expect(
        candidate,
        contains('independentlySelectedSlug: _currentSelectedSlug()'),
      );
      expect(
        candidate,
        contains('startArguments.addAll(selectedNodeCaller.startArguments)'),
      );
      expect(
        candidate,
        isNot(contains('(Platform.isAndroid || _isApplePlatform) &&\n'
            '          selectedNodeCaller.isPresent')),
      );
      expect(
        candidate,
        isNot(contains("startArguments['selected_node'] = "
            'winn3SelectedNodeIdentity(')),
        reason: 'caller identity must not be derived only from served INI',
      );
    });

    test('Winn v3 refuses a missing or conflicting caller before startTunnel',
        () {
      final refuse = candidate.indexOf(
        'protocolVersion == kWinnProtocolV3 && !selectedNodeCaller.isPresent',
      );
      expect(refuse, greaterThanOrEqualTo(0));
      final invoke =
          candidate.indexOf(".invokeMethod(\n            'startTunnel'");
      expect(invoke, greaterThan(refuse));
      expect(
        candidate.substring(refuse, invoke),
        contains('return false;'),
      );
      expect(
        candidate.substring(refuse, invoke),
        contains('_lastTunnelCandidateWasSecurityRefusal = true;'),
      );
      expect(
        candidate.substring(refuse, invoke),
        contains('Winn3NativeVerdict.terminalSecurity'),
      );
      expect(
        candidate.substring(refuse, invoke),
        contains('winn3DescriptorNodeMismatch'),
      );
    });

    test('Winn v1 still reaches startTunnel without the v3 identity refusal',
        () {
      final v1 = candidate.indexOf('case kWinnProtocolV1:');
      final v3 = candidate.indexOf('case kWinnProtocolV3:');
      expect(v1, greaterThanOrEqualTo(0));
      expect(v3, greaterThan(v1));
      expect(
        candidate.substring(v1, v3),
        contains('break;'),
      );
      expect(
        candidate.substring(v1, v3),
        isNot(contains('!selectedNodeCaller.isPresent')),
      );
      expect(candidate, contains(".invokeMethod(\n            'startTunnel'"));
    });

    test('normalization keeps selected-node aliases for the startTunnel caller',
        () {
      final start = source.indexOf(
        'Map<String, dynamic> _normalizeVpnConfig(',
      );
      final end = source.indexOf(
        'bool _hasUsableVpnConfig(',
        start,
      );
      final normalize = withoutComments(source.substring(start, end));
      expect(normalize, contains('copyWinn3SelectedNodeIdentities('));
      expect(normalize, contains('applyWinn3ServedFields('));
    });

    test('Windows and Linux native bridges require the independent method arg',
        () {
      final windows =
          File('windows/runner/windows_tunnel_backend.cpp').readAsStringSync();
      expect(windows, contains('TryStringArgFromCall(call, "selected_node"'));
      expect(windows, contains('ValidateWinn3IndependentSelectedNode('));
      expect(windows, contains('WINDOWS_WINN3_SELECTED_NODE_REQUIRED'));

      final linux =
          File('linux/runner/linux_tunnel_backend.cc').readAsStringSync();
      expect(
        linux,
        contains('TryStringArgFromCall(method_call, "selected_node"'),
      );
      expect(
        linux,
        contains('ValidateLinuxWinn3IndependentSelectedNode('),
      );
      expect(linux, contains('LINUX_WINN3_SELECTED_NODE_REQUIRED'));
    });
  });
}
