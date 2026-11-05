import Foundation
import os

// RouteAudit -- self-contained, auditable route-leak log for the macOS runner.
//
// WHY THIS EXISTS. The running tunnel's routing posture (`enforceRoutes` and
// `excludedRoutes`) is applied inside sources this lane does not own, and none
// of those applications leaves a readable, greppable trace of what was set or
// even that it was set. A route leak that is never recorded is a leak that
// cannot be audited after the fact.
//
// This file is a small, self-contained assertion layer: render one line
// whenever a posture is recorded, write it to os_log, and return it so both
// callers and unit tests can assert on it without depending on the unified-log
// transport.
//
// CHANNEL DELIBERATELY CHOSEN. Per the false-green catalogue, `NSLog` bodies
// render as `<private>` in the unified log while an `os_log` format string and
// a `%{public}@` argument are fully public. If this record is to be *readable*
// in `log show`, it must use `os_log` with `%{public}@` -- so it does. The
// markers `enforce` and `exclude` are intentionally fixed literals, present in
// every rendered line in both postures, so a grep of the unified log for either
// marker finds the audit whether the posture was enforced or not.
//
// Wire-in is intentionally left to the caller: the runner sources that apply
// the posture are not edited here. Whichever site owns `enforceRoutes` /
// `excludedRoutes` calls `RouteAudit.log(enforceRoutes:excludedRoutes:)` at the
// point of application.
struct RouteAudit {
    static let subsystem = "org.winsvpn.app.routeaudit"
    static let category = "route-posture"

    /// Markers that MUST appear verbatim in every rendered line.
    static let enforceMarker = "enforce"
    static let excludeMarker = "exclude"

    /// Renders an excluded route the way the audit line carries it
    /// (`destination/prefix`, e.g. `192.168.50.226/32`). Used by the connect
    /// path (`MainFlutterWindow.startTunnel`) to annotate the
    /// `transportIPv4ExclusionRoute` /32 carve-out with the SAME shape the
    /// unit tests assert on, so a wiring change that renames a field cannot
    /// silently change the audit output without a test seeing it.
    static func excludedRouteString(_ route: WinsIPv4Route) -> String {
        "\(route.destinationAddress)/\(route.prefixLength)"
    }

    private static let log = OSLog(subsystem: subsystem, category: category)

    /// Pure renderer: produces the one-line audit record for a routing posture
    /// with NO side effects. It never writes to os_log -- the unified log stays
    /// at the call site (`log(enforceRoutes:excludedRoutes:)`). Keeping the
    /// rendering pure lets tests assert exactly what a posture renders, without
    /// embedding the renderer in the logging transport. The returned line always
    /// contains both `enforce` and `exclude` markers verbatim, with the applied
    /// values annotated, so a test that asserts on the markers cannot be
    /// satisfied by an empty or hardcoded emission.
    static func render(
        enforceRoutes: Bool,
        excludedRoutes: [String]
    ) -> String {
        let enforce = enforceRoutes
            ? "\(enforceMarker)=on"
            : "\(enforceMarker)=off"
        let exclude = excludedRoutes.isEmpty
            ? "\(excludeMarker)=none"
            : "\(excludeMarker)=\(excludedRoutes.joined(separator: ","))"
        return "route-audit \(enforce) \(exclude)"
    }

    /// Renders one audit line via `render(enforceRoutes:excludedRoutes:)`,
    /// writes it to os_log, and returns it. The os_log write is intentionally
    /// confined to this call site so `render` stays a pure function.
    @discardableResult
    static func log(
        enforceRoutes: Bool,
        excludedRoutes: [String]
    ) -> String {
        let line = render(
            enforceRoutes: enforceRoutes,
            excludedRoutes: excludedRoutes
        )
        #if DEBUG
        os_log("%{public}@", log: log, type: .default, line)
        #endif
        return line
    }
}

// The macOS shipping `enforceRoutes` posture, kept in ONE place so the value
// the connect path applies and the value the audit records cannot drift apart.
//
// RULED `true`, 2026-08-10, reinstated 2026-08-11 (delegated authority; see
// docs/handoff/MACOS_ENFORCEROUTES_TRUE_RULING_20260810.md and
// docs/rulings/RULINGS.lock). This line is a RULED INVARIANT: it must not be
// changed by any lane without a new dated ruling document. The 2026-08-09
// zero-carriage measurement under `true`
// (WINN3_MACOS_ENFORCEROUTES_NECP_20260809.md) is real but was taken with the
// carrier destination on the Mac's own link, the one shape whose `/32`
// carve-out is a locally-defined route that enforcement suppresses
// (WINN3_MACOS_ENFORCEROUTES_SELFSTRANGULATION_20260810_fin_mac_routes.md,
// section 5). Production's carrier endpoint is remote and off-link, a shape
// that measurement does not cover. Carriage under `true` with a remote
// endpoint is the release-gating experiment (owner-scheduled, never on this
// host); until it runs, `true` fails closed while `false` fails open against
// the route-injection decloak the flag was bought to close.
// `MainFlutterWindow.startTunnel` sets `tunnelProtocol.enforceRoutes` from this
// so the applied value and the RouteAudit line always agree; the audit is a
// record of the posture, never a claim that it carries.
enum WinsMacRoutePosture {
  static let enforceRoutes = true
}
