import SwiftUI

/// How the toggle should look and behave right now.
///
/// Derived in one place so the label, the colour and whether the button does
/// anything can never disagree -- the failure mode that makes a watch remote
/// feel broken.
private struct ToggleAppearance {
  let label: String
  let enabled: Bool
  let showSpinner: Bool
  let tint: Color

  init(_ snapshot: PhoneSnapshot, link: PhoneLinkState, sending: Bool) {
    switch (link, sending, snapshot.status) {
    case (.connecting, _, _) where snapshot.updatedAt == 0:
      self.init(label: "…", enabled: false, showSpinner: true, tint: .accentColor)
    case (.unreachable, _, _):
      self.init(label: "Phone", enabled: false, showSpinner: false, tint: .red)
    case (_, true, _):
      self.init(label: "…", enabled: false, showSpinner: true, tint: .accentColor)
    case (_, _, .connecting):
      // Tapping again cancels, exactly as the phone's own power button does
      // while a connect is in flight.
      self.init(label: "Cancel", enabled: true, showSpinner: true, tint: .accentColor)
    case (_, _, .disconnecting):
      self.init(label: "…", enabled: false, showSpinner: true, tint: .accentColor)
    case (_, _, .connected):
      self.init(label: "On", enabled: true, showSpinner: false, tint: .green)
    case (_, _, .permissionRequired):
      // A watch cannot approve a VPN configuration and must not try.
      self.init(label: "Off", enabled: false, showSpinner: false, tint: .red)
    case (_, _, .failed):
      self.init(label: "Retry", enabled: snapshot.canConnect, showSpinner: false, tint: .red)
    case (_, _, .disconnected):
      self.init(label: "Off", enabled: snapshot.canConnect, showSpinner: false, tint: .secondary)
    case (_, _, .unknown):
      self.init(label: "?", enabled: false, showSpinner: false, tint: .secondary)
    }
  }

  private init(label: String, enabled: Bool, showSpinner: Bool, tint: Color) {
    self.label = label
    self.enabled = enabled
    self.showSpinner = showSpinner
    self.tint = tint
  }
}

/// The one line of prose on the screen. Every branch is a state that would
/// otherwise render as an unexplained dead button.
private func statusLine(_ snapshot: PhoneSnapshot, link: PhoneLinkState) -> String {
  if link == .connecting && snapshot.updatedAt == 0 { return "Reaching phone…" }
  if link == .unreachable { return "Phone not reachable" }
  switch snapshot.status {
  case .permissionRequired: return "Approve VPN on iPhone"
  case .connecting: return "Connecting…"
  case .disconnecting: return "Disconnecting…"
  case .failed: return snapshot.detail.isEmpty ? "Connection failed" : snapshot.detail
  case .connected: return "Connected"
  case .disconnected, .unknown:
    if !snapshot.canConnect { return "Open Win's VPN on iPhone" }
    return snapshot.detail.isEmpty ? "Not connected" : snapshot.detail
  }
}

struct ContentView: View {
  @ObservedObject var phone: PhoneLink
  @State private var showingCountries = false

  var body: some View {
    #if os(watchOS)
    // The watch slice renders the remote toggle against PhoneLink. Guarding the
    // whole body keeps any PhoneLink entry point that is tied to the iOS SDK out
    // of the watchOS compile, so ContentView never drags an iOS caller path into
    // the watch build.
    NavigationStack {
      HomeView(phone: phone, showingCountries: $showingCountries)
        .navigationDestination(isPresented: $showingCountries) {
          CountryListView(phone: phone, showingCountries: $showingCountries)
        }
    }
    .onAppear { phone.start() }
    .onOpenURL { url in
      guard url.scheme == "winsvpn" else { return }
      showingCountries = false
      phone.refresh()
    }
    #else
    // Non-watchOS platforms render their own content; this file is the watch
    // slice and must still typecheck if it is ever added to a shared target.
    Color.clear
    #endif
  }
}

private struct HomeView: View {
  @ObservedObject var phone: PhoneLink
  @Binding var showingCountries: Bool

  var body: some View {
    let appearance = ToggleAppearance(phone.snapshot, link: phone.link, sending: phone.sending)

    VStack(spacing: 8) {
      ZStack {
        if appearance.showSpinner {
          ProgressView()
            .progressViewStyle(.circular)
            .tint(appearance.tint)
            .scaleEffect(1.9)
        }
        Button(action: phone.toggleConnection) {
          Text(appearance.label)
            .font(.headline)
            .minimumScaleFactor(0.6)
            .lineLimit(1)
        }
        .buttonStyle(.borderedProminent)
        .tint(appearance.tint)
        .disabled(!appearance.enabled)
        .frame(width: 76, height: 76)
        .clipShape(Circle())
        .accessibilityLabel(
          phone.snapshot.status.isOnOrGoingOn ? "Disconnect VPN" : "Connect VPN"
        )
      }

      Text(statusLine(phone.snapshot, link: phone.link))
        .font(.caption2)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .lineLimit(2)

      Button {
        showingCountries = true
      } label: {
        HStack(spacing: 6) {
          Text(countryLabel)
            .lineLimit(1)
          if let selected = phone.snapshot.selectedCountry {
            ServerLoadBar(country: selected, snapshot: phone.snapshot)
          }
        }
        .frame(maxWidth: .infinity)
      }
      .buttonStyle(.bordered)
      .disabled(phone.snapshot.countries.isEmpty)
    }
    .padding(.horizontal, 6)
    .navigationTitle("Win's VPN")
  }

  private var countryLabel: String {
    if let selected = phone.snapshot.selectedCountry { return selected.display }
    return phone.snapshot.countries.isEmpty ? "No servers yet" : "Choose country"
  }
}

private struct CountryListView: View {
  @ObservedObject var phone: PhoneLink
  @Binding var showingCountries: Bool

  var body: some View {
    List {
      ForEach(phone.snapshot.countries) { country in
        Button {
          phone.selectCountry(country.slug)
          showingCountries = false
        } label: {
          HStack {
            Text(country.display)
              .lineLimit(1)
            Spacer()
            ServerLoadBar(country: country, snapshot: phone.snapshot)
            if country.slug == phone.snapshot.selectedSlug {
              Image(systemName: "checkmark")
                .foregroundStyle(.green)
            }
          }
        }
        // Changing country routes through the phone app's own picker logic, so
        // it is unavailable for the same reason connecting is.
        .disabled(!phone.snapshot.canConnect && country.slug != phone.snapshot.selectedSlug)
      }

      if phone.snapshot.countries.isEmpty {
        Text("Open Win's VPN on your iPhone to load servers.")
          .font(.caption2)
          .foregroundStyle(.secondary)
      }
    }
    .navigationTitle("Country")
  }
}

/// A thin horizontal load bar. Unknown renders as the empty outlined track,
/// the same choice every other target makes. Fills and track are the dark set
/// the phone app uses (lib/server_load_bar.dart ServerLoadPalette.dark). The
/// outline is 0xDADCE0, as on Wear OS: the phone's 0x64748B falls below 3:1 on
/// a dark row. Unlike Wear OS, no watchOS surface puts the bar on a light
/// background: this app never highlights the selected row (it shows a
/// checkmark) and watchOS is dark-only, so one light outline suffices. It is
/// tested against a bracket of dark row and button backgrounds (#000000 to
/// #636366), because the exact watchOS platter colours are not published.
/// watchOS has no tooltip; VoiceOver reads the label, which is
/// derived from the FRESH figure only, so a stale value is never announced.
///
/// Expiry: `LoadFreshness` re-judges the figure on every render, and the
/// TimelineView schedules one extra render at the moment it expires, so the
/// bar turns grey without any other state change.
///
/// Strings are English literals like every other string in this watch target,
/// which has no localisation catalogue today.
struct ServerLoadBar: View {
  let country: WatchCountry
  let snapshot: PhoneSnapshot

  private static let low = Color(red: 0x00 / 255, green: 0xC8 / 255, blue: 0x53 / 255)
  private static let elevated = Color(red: 0xFF / 255, green: 0xAB / 255, blue: 0x40 / 255)
  private static let high = Color(red: 0xFF / 255, green: 0x33 / 255, blue: 0x4B / 255)
  private static let track = Color(red: 0x1E / 255, green: 0x29 / 255, blue: 0x3B / 255)
  /// The outline as 0xRRGGBB, exposed so the contrast harness tests the
  /// shipped value rather than a copy.
  static let outlineRGB: UInt32 = 0xDADCE0
  private static let outline = Color(
    red: Double((outlineRGB >> 16) & 0xFF) / 255,
    green: Double((outlineRGB >> 8) & 0xFF) / 255,
    blue: Double(outlineRGB & 0xFF) / 255)

  /// Same thresholds as the phone: green below 60, amber 60 to under 85, red 85+.
  static func fill(for pct: Int?) -> Color? {
    guard let pct, (0...100).contains(pct) else { return nil }
    if pct >= 85 { return high }
    if pct >= 60 { return elevated }
    return low
  }

  /// A known value always shows a small nub, so a known 0% differs from unknown.
  static func fraction(for pct: Int?) -> CGFloat {
    guard let pct else { return 0 }
    return min(1, max(0.06, CGFloat(pct) / 100))
  }

  static func label(for pct: Int?) -> String {
    guard let pct else { return "Server load unknown" }
    return "Server load \(pct)%"
  }

  var body: some View {
    let expiry = LoadFreshness.secondsUntilExpiry(country, in: snapshot)
      .map { [Date().addingTimeInterval($0)] } ?? []
    TimelineView(.explicit(expiry)) { _ in
      bar(for: LoadFreshness.visibleLoadPct(country, in: snapshot))
    }
  }

  private func bar(for loadPct: Int?) -> some View {
    let width: CGFloat = 28
    let shape = Capsule()
    return ZStack(alignment: .leading) {
      shape.fill(Self.track)
      if let fill = Self.fill(for: loadPct) {
        Rectangle()
          .fill(fill)
          .frame(width: width * Self.fraction(for: loadPct))
      }
    }
    .frame(width: width, height: 6)
    .clipShape(shape)
    .overlay(shape.stroke(Self.outline, lineWidth: 1))
    .accessibilityElement(children: .ignore)
    .accessibilityLabel(Self.label(for: loadPct))
  }
}
