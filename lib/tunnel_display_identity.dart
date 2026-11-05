/// Which node the dashboard card names, and for how long that name is valid.
///
/// The card used to render the picker position (`_selectedLocationIndex`)
/// even while a tunnel was secured, so a Winn v3 session running on uk-gb1
/// could read "Canada / Status: online". The picker position is routing
/// intent and the cover-fallback failed-node anchor; it must not be moved to
/// fix the display. This file keeps a separate display record instead.
///
/// The record is written only where a tunnel COMMITS in this process, with the
/// node that tunnel was started for. It belongs to one account epoch and one
/// display-session generation. Any change of the connected flag that carries
/// no verified identity (confirmed cutover, disconnect, native death, native
/// adoption after a restart) ends that generation, so the card falls back to
/// an explicit unknown node instead of guessing.
///
/// Deliberately not consulted: the cached or persisted VPN config. It is
/// preparation state as well as persistence state, so it can name a prepared
/// replacement that never committed, and a failed best-effort write can leave
/// it naming the previous node. Native tunnel status reports no node identity
/// either.
///
/// Round UN: an adopted tunnel (a killed and relaunched app, a destroyed
/// Flutter engine, a native reading that flapped) may be named again from a
/// [PersistedTunnelDisplayRecord], which only a commit writes. It is restored
/// only for the same account scope and the same native tunnel session the
/// platform names now ([nativeTunnelSession]); otherwise the tunnel stays an
/// unknown node.
///
/// Round UN-2: a reading that only flips the connected flag (a relock, a
/// network handover, a native reading that flapped) ends the display session
/// but not what its commit started. The ledger keeps that commit and the
/// native session it started, and names the node again only when the platform
/// names that same session now ([TunnelDisplayLedger.resume]). The stored
/// record is no longer the only way back for a process that kept running.
///
/// Pure Dart with no imports: the connected-server switch harness executes
/// the production switch method against this exact ledger.
library;

/// Identity of the node a committed tunnel session was started for.
///
/// Carries identity metadata only (slug, name, flag). Health (status,
/// latency) is never snapshotted: it is read from the current listing row, or
/// reported as `unknown` when no such row exists.
class CommittedTunnelNode {
  const CommittedTunnelNode({
    required this.slug,
    required this.name,
    required this.flag,
    required this.accountEpoch,
    required this.sessionGeneration,
  });

  final String slug;
  final String? name;
  final Object? flag;
  final int accountEpoch;
  final int sessionGeneration;
}

/// The node slug a committing tunnel is bound to.
///
/// The served config's identity is what the tunnel dials. For Winn v3 it
/// already equals the caller slug native bound to the signed descriptor; for
/// a v1 cover successor it differs from the failed picker node and must be
/// the one named. The caller slug is used only outside cover fallback, where
/// the caller is the picker node itself; during cover fallback the caller is
/// the FAILED node, so an absent served identity stays unknown.
String committedTunnelNodeSlug({
  required String servedIdentity,
  required String callerIdentity,
  required bool coverFallbackInProgress,
}) {
  final served = _usableSlug(servedIdentity);
  if (served.isNotEmpty) return served;
  if (coverFallbackInProgress) return '';
  return _usableSlug(callerIdentity);
}

/// Owns the dashboard's committed-node record and its session generation.
class TunnelDisplayLedger {
  int _generation = 0;
  CommittedTunnelNode? _record;

  // The last commit and the native session it started, kept after its display
  // session ends so the same native session can be named again ([resume]).
  // Only a commit sets it. An explicit end, an app-initiated stop ([forget])
  // and the next commit clear it; a connected-flag flip does not.
  CommittedTunnelNode? _remembered;
  String? _rememberedSession;

  /// Current display-session generation. Capture it before an asynchronous
  /// step and pass it back as `observedGeneration`, so an obsolete completion
  /// cannot end a session that was replaced while it waited.
  int get generation => _generation;

  /// A tunnel committed in this process. Starts a new display session and
  /// records the node it was started for, with identity metadata from the
  /// current listing row when one exists. An unusable slug records nothing,
  /// which renders as an unknown node.
  ///
  /// [nativeSession] is the native session this commit's own start names
  /// ([startedNativeTunnelSession]), or null when the platform names none yet.
  /// With it, the commit is remembered for [resume].
  CommittedTunnelNode? commit({
    required String servedIdentity,
    required String callerIdentity,
    required bool coverFallbackInProgress,
    required int accountEpoch,
    List<Map<String, dynamic>> locations = const <Map<String, dynamic>>[],
    String? nativeSession,
  }) {
    _generation++;
    _remembered = null;
    _rememberedSession = null;
    final slug = committedTunnelNodeSlug(
      servedIdentity: servedIdentity,
      callerIdentity: callerIdentity,
      coverFallbackInProgress: coverFallbackInProgress,
    );
    if (slug.isEmpty) {
      _record = null;
      return null;
    }
    final row = tunnelListingRowForSlug(locations, slug);
    final name = (row?['name'] ?? '').toString().trim();
    final flag = row?['flag'];
    _record = CommittedTunnelNode(
      slug: slug,
      name: name.isEmpty ? null : name,
      flag: flag is String && flag.trim().isEmpty ? null : flag,
      accountEpoch: accountEpoch,
      sessionGeneration: _generation,
    );
    final remembered = nativeSession?.trim() ?? '';
    if (remembered.isNotEmpty) {
      _remembered = _record;
      _rememberedSession = remembered;
    }
    return _record;
  }

  /// The display session ended, was replaced, or was adopted without a
  /// verified identity. With [observedGeneration], this is a no-op (returning
  /// false) when that generation is no longer current: something newer
  /// already ended or replaced it, and that newer record must survive.
  /// An explicit end also forgets what the commit remembered ([forget]).
  bool endSession({int? observedGeneration}) {
    if (!_end(observedGeneration)) return false;
    forget();
    return true;
  }

  bool _end(int? observedGeneration) {
    if (observedGeneration != null && observedGeneration != _generation) {
      return false;
    }
    _generation++;
    _record = null;
    return true;
  }

  /// Applies a change of the connected flag that carries no verified node
  /// identity. Connected to disconnected ends the session; disconnected to
  /// connected is native adoption, which must render unknown. No change keeps
  /// the retained session, for example after a failed switch preparation.
  /// Neither flip forgets what the commit remembered: a flipped flag does not
  /// say the native session ended ([resume] asks the platform).
  bool settle({
    required bool wasConnected,
    required bool isConnected,
    int? observedGeneration,
  }) {
    if (wasConnected == isConnected) return false;
    return _end(observedGeneration);
  }

  /// Drops what the last commit remembered. For an app-initiated stop, which
  /// ends the native session whatever the stop's own result.
  void forget() {
    _remembered = null;
    _rememberedSession = null;
  }

  /// Whether a commit of [accountEpoch] is remembered, so a native session
  /// reading could name it again.
  bool remembers({required int accountEpoch}) =>
      _remembered?.accountEpoch == accountEpoch;

  /// Names the current display session, one that ended on a flipped flag and
  /// was adopted again, from what the last commit remembered. It needs the
  /// platform to name [nativeSession] now, the exact session that commit
  /// started: another start, a restarted service or no reading names a
  /// different session or none, and the tunnel stays an unknown node. The
  /// session gains an identity; it is not replaced, so the generation stays.
  /// A no-op (returning null) when [observedGeneration] is no longer current,
  /// when [accountEpoch] is not the commit's, or when the session already has
  /// a record: a commit in this process outranks a resume.
  CommittedTunnelNode? resume({
    required String? nativeSession,
    required int accountEpoch,
    required int observedGeneration,
  }) {
    final remembered = _remembered;
    if (remembered == null || nativeSession == null) return null;
    if (_rememberedSession != nativeSession) return null;
    if (remembered.accountEpoch != accountEpoch) return null;
    if (observedGeneration != _generation) return null;
    if (recordFor(accountEpoch: accountEpoch) != null) return null;
    _record = CommittedTunnelNode(
      slug: remembered.slug,
      name: remembered.name,
      flag: remembered.flag,
      accountEpoch: accountEpoch,
      sessionGeneration: _generation,
    );
    return _record;
  }

  /// Names the current display session, an adopted tunnel, from a persisted
  /// record the caller verified with [restorableTunnelDisplayRecord]. The
  /// session gains an identity; it is not replaced, so the generation stays.
  /// A no-op (returning null) when [observedGeneration] is no longer current,
  /// or when the session already has a record for [accountEpoch]: a commit in
  /// this process always outranks a restore.
  CommittedTunnelNode? restore({
    required PersistedTunnelDisplayRecord record,
    required int accountEpoch,
    required int observedGeneration,
  }) {
    if (observedGeneration != _generation) return null;
    if (recordFor(accountEpoch: accountEpoch) != null) return null;
    _record = CommittedTunnelNode(
      slug: record.slug,
      name: record.name,
      flag: record.flag,
      accountEpoch: accountEpoch,
      sessionGeneration: _generation,
    );
    return _record;
  }

  /// The record, only while it still belongs to [accountEpoch] and to the
  /// current display session.
  CommittedTunnelNode? recordFor({required int accountEpoch}) {
    final record = _record;
    if (record == null ||
        record.accountEpoch != accountEpoch ||
        record.sessionGeneration != _generation) {
      return null;
    }
    return record;
  }
}

enum DashboardNodeSource {
  /// Not rendering a secured tunnel: the picker position, as before.
  picker,

  /// The node the committed tunnel was started for.
  committedTunnel,

  /// A secured tunnel whose node identity is not known.
  unknownTunnel,
}

class DashboardNodeDisplay {
  const DashboardNodeDisplay(this.source, this.node);

  final DashboardNodeSource source;

  /// The row the card renders; null for [DashboardNodeSource.unknownTunnel]
  /// and for an empty picker listing.
  final Map<String, dynamic>? node;
}

/// The node the dashboard card names.
///
/// While [rendersConnected], the card names the committed tunnel's node from
/// [ledger], never the picker position; when no current record exists for
/// [accountEpoch], it is an explicit unknown node. Otherwise it is the picker
/// position with the existing clamp. A committed node that has no current
/// listing row is shown by identity only, with status `unknown` and no
/// latency.
///
/// [unlistedSelection] is a manual choice the listing does not carry (see
/// node_selection_rebind.dart). While not secured and [selectedIndex] is
/// negative, the card names it by identity instead of clamping to row 0, with
/// the record's own `status` when it carries one (the caller knows whether a
/// fresh listing omits it), else `unavailable`, or `unknown` before any
/// listing has loaded.
DashboardNodeDisplay dashboardNodeForDisplay({
  required List<Map<String, dynamic>> locations,
  required int selectedIndex,
  required bool rendersConnected,
  required TunnelDisplayLedger ledger,
  required int accountEpoch,
  Map<String, dynamic>? unlistedSelection,
}) {
  if (rendersConnected) {
    final record = ledger.recordFor(accountEpoch: accountEpoch);
    if (record == null) {
      return const DashboardNodeDisplay(
          DashboardNodeSource.unknownTunnel, null);
    }
    final listed = tunnelListingRowForSlug(locations, record.slug);
    if (listed != null) {
      return DashboardNodeDisplay(DashboardNodeSource.committedTunnel, listed);
    }
    return DashboardNodeDisplay(
      DashboardNodeSource.committedTunnel,
      <String, dynamic>{
        'slug': record.slug,
        'name': record.name ?? record.slug,
        'status': 'unknown',
        if (record.flag != null) 'flag': record.flag,
      },
    );
  }
  if (selectedIndex < 0 && unlistedSelection != null) {
    return DashboardNodeDisplay(DashboardNodeSource.picker, <String, dynamic>{
      ...unlistedSelection,
      'status': unlistedSelection['status'] ??
          (locations.isEmpty ? 'unknown' : 'unavailable'),
    });
  }
  if (locations.isEmpty) {
    return const DashboardNodeDisplay(DashboardNodeSource.picker, null);
  }
  final safeIndex = selectedIndex >= 0 && selectedIndex < locations.length
      ? selectedIndex
      : 0;
  return DashboardNodeDisplay(DashboardNodeSource.picker, locations[safeIndex]);
}

/// Current listing row for [slug], compared as trimmed ASCII-lowercase so a
/// normalized served identity still finds its row. Null for an empty or
/// `auto` slug, or when the listing has no such row.
Map<String, dynamic>? tunnelListingRowForSlug(
  List<Map<String, dynamic>> locations,
  String slug,
) {
  final wanted = _usableSlug(slug).toLowerCase();
  if (wanted.isEmpty) return null;
  for (final node in locations) {
    if ((node['slug'] ?? '').toString().trim().toLowerCase() == wanted) {
      return node;
    }
  }
  return null;
}

/// The committed node as persisted for an adopted tunnel (Round UN).
///
/// Written only after a commit in this process, and only when the platform
/// names the native session that commit started
/// ([committedNativeTunnelSession]). The caller keeps it inside the
/// encrypted runtime settings record, which logout, account deletion and the
/// duress wipe already delete, and removes it on every app-initiated stop.
/// Identity metadata only, like [CommittedTunnelNode]: never health.
class PersistedTunnelDisplayRecord {
  const PersistedTunnelDisplayRecord({
    required this.slug,
    required this.name,
    required this.flag,
    required this.accountScope,
    required this.nativeSession,
  });

  static const int schema = 1;

  final String slug;
  final String? name;
  final String? flag;

  /// The account scope token of the account whose tunnel committed.
  final String accountScope;

  /// [nativeTunnelSession] of the committed start.
  final String nativeSession;

  Map<String, Object> toJson() => <String, Object>{
        'schema': schema,
        'slug': slug,
        if (name != null) 'name': name!,
        if (flag != null) 'flag': flag!,
        'account_scope': accountScope,
        'native_session': nativeSession,
      };

  /// Strict: any other shape, schema or type is no record at all.
  static PersistedTunnelDisplayRecord? fromJson(Object? raw) {
    if (raw is! Map || raw['schema'] != schema) return null;
    final slug = raw['slug'];
    final name = raw['name'];
    final flag = raw['flag'];
    final accountScope = raw['account_scope'];
    final nativeSession = raw['native_session'];
    if (slug is! String || _usableSlug(slug).isEmpty) return null;
    if (name != null && name is! String) return null;
    if (flag != null && flag is! String) return null;
    if (accountScope is! String || accountScope.trim().isEmpty) return null;
    if (nativeSession is! String || nativeSession.trim().isEmpty) return null;
    final trimmedName = (name as String?)?.trim() ?? '';
    final trimmedFlag = (flag as String?)?.trim() ?? '';
    return PersistedTunnelDisplayRecord(
      slug: _usableSlug(slug),
      name: trimmedName.isEmpty ? null : trimmedName,
      flag: trimmedFlag.isEmpty ? null : trimmedFlag,
      accountScope: accountScope,
      nativeSession: nativeSession,
    );
  }
}

/// The native tunnel session running now, as the platform names it, or null
/// when it names none. Neither platform reports which node a session dials
/// (Android readiness carries only `winn3_failed_node`, Apple only
/// `winn3_selected_node_present`), so this names the session, never the node.
///
/// iOS and macOS: the per-start `status_generation` UUID the host saved in
/// the VPN profile, echoed as `provider_status_generation` only while the
/// provider's status document is current for that profile. It outlives the
/// app process. Only a provider the app started with transient start options
/// names it (Round UN, OI-UN-1): a restart without options (a Settings or
/// menu toggle) keeps the saved generation but runs the App Group shared
/// config, which the host rewrites before it saves the profile, so after a
/// failed save that config can be a newer node's under the older generation.
///
/// Android: the Dart-minted `winn3_start_token` of the last v3 start, only
/// while a v3 engine lifecycle is live (`winn3_lifecycle`). The service never
/// resets the token, so without that key it can describe an earlier session
/// than a v1 tunnel running now. It lives in the service process: it survives
/// a destroyed Flutter engine, not a process death.
///
/// Any other platform (desktop hosts echo no session) is null.
String? nativeTunnelSession(
  Map<dynamic, dynamic>? readiness, {
  required String operatingSystem,
}) {
  if (readiness == null) return null;
  switch (operatingSystem) {
    case 'ios':
    case 'macos':
      if (readiness['provider_status_available'] != true) return null;
      if (readiness['provider_config_source'] != 'transient_start_options') {
        return null;
      }
      final generation = readiness['provider_status_generation'];
      if (generation is! String ||
          !_appleStatusGenerationPattern.hasMatch(generation)) {
        return null;
      }
      return 'apple-status:$generation';
    case 'android':
      final lifecycle = readiness['winn3_lifecycle'];
      final token = readiness['winn3_start_token'];
      if (lifecycle is! String || lifecycle.trim().isEmpty) return null;
      if (token is! int || token <= 0) return null;
      return _androidWinn3Session(token);
  }
  return null;
}

/// The native session a commit in this process started, or null when the
/// platform does not name it. Android must echo the start token this commit's
/// own start minted ([dartStartToken]; a v1 or cover start mints none), so an
/// earlier v3 session can never be bound to it. Apple names the profile
/// generation of the start that just proved ready.
String? committedNativeTunnelSession(
  Map<dynamic, dynamic>? readiness, {
  required String operatingSystem,
  required int? dartStartToken,
}) {
  final session =
      nativeTunnelSession(readiness, operatingSystem: operatingSystem);
  if (session == null || operatingSystem != 'android') return session;
  if (dartStartToken == null || dartStartToken <= 0) return null;
  return session == _androidWinn3Session(dartStartToken) ? session : null;
}

/// The native session a commit's own start names before the platform is
/// asked, or null when it names none (Round UN-2). Android only: the start
/// token this commit's own v3 start minted ([dartStartToken]; a v1 or cover
/// start mints none) is the session [nativeTunnelSession] reports while that
/// start's engine lifecycle is live, and the connect already proved the
/// platform echoed it. Apple's session exists only in a provider reading, so
/// it is not named here and an Apple commit is not remembered.
String? startedNativeTunnelSession({
  required String operatingSystem,
  required int? dartStartToken,
}) {
  if (operatingSystem != 'android') return null;
  if (dartStartToken == null || dartStartToken <= 0) return null;
  return _androidWinn3Session(dartStartToken);
}

/// Whether a commit's session may still be named by a later reading (Round
/// UN, OI-UN-6): Android echoes the token this commit's own v3 start minted
/// ([dartStartToken]) but no engine lifecycle yet. The engine publishes its
/// lifecycle about a second after promotion, and the connected claim does not
/// wait for it. False on every other platform, for a v1 or cover start (no
/// token of its own), and once the token names another start.
bool committedNativeTunnelSessionPending(
  Map<dynamic, dynamic>? readiness, {
  required String operatingSystem,
  required int? dartStartToken,
}) {
  if (readiness == null || operatingSystem != 'android') return false;
  if (dartStartToken == null || dartStartToken <= 0) return false;
  if (readiness['winn3_start_token'] != dartStartToken) return false;
  final lifecycle = readiness['winn3_lifecycle'];
  return lifecycle is! String || lifecycle.trim().isEmpty;
}

/// The persisted record an adopted tunnel may be named by: the same account
/// scope and the same native session as now. Null (an unknown node) when any
/// of them is missing or differs.
PersistedTunnelDisplayRecord? restorableTunnelDisplayRecord({
  required PersistedTunnelDisplayRecord? persisted,
  required String accountScope,
  required String? nativeSession,
}) {
  if (persisted == null || nativeSession == null) return null;
  if (accountScope.isEmpty || persisted.accountScope != accountScope) {
    return null;
  }
  if (persisted.nativeSession != nativeSession) return null;
  return persisted;
}

/// Whether [persisted] can never be restored again, so it should be removed:
/// it belongs to another account, or the platform names a different live
/// session. A missing reading proves nothing and keeps it.
bool persistedTunnelDisplayRecordIsStale({
  required PersistedTunnelDisplayRecord? persisted,
  required String accountScope,
  required String? nativeSession,
}) {
  if (persisted == null) return false;
  if (accountScope.isNotEmpty && persisted.accountScope != accountScope) {
    return true;
  }
  return nativeSession != null && persisted.nativeSession != nativeSession;
}

final RegExp _appleStatusGenerationPattern = RegExp(r'^[A-Za-z0-9._-]{8,64}$');

String _androidWinn3Session(int token) => 'android-winn3:$token';

String _usableSlug(String raw) {
  final slug = raw.trim();
  if (slug.isEmpty || slug.toLowerCase() == 'auto') return '';
  return slug;
}
