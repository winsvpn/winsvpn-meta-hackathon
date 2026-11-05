import Foundation
import WatchConnectivity

// BEGIN PHONE_LINK_REQUEST_GENERATION
/// Linearizes asynchronous reply, error, and timeout completion by send.
///
/// This type deliberately depends only on Foundation so the exact production
/// implementation can also be executed by the focused host-side Swift race
/// test without mocking WatchConnectivity.
struct PhoneLinkRequestGeneration {
  private var current: UUID?

  mutating func begin() -> UUID {
    let requestID = UUID()
    current = requestID
    return requestID
  }

  mutating func complete(_ requestID: UUID) -> Bool {
    guard current == requestID else { return false }
    current = nil
    return true
  }

  mutating func cancel() {
    current = nil
  }
}
// END PHONE_LINK_REQUEST_GENERATION

/// Everything the watch app knows about how to reach the phone, plus the state
/// the two screens render.
///
/// `sendMessage` is used for commands because it reports delivery failure
/// immediately -- that failure is exactly the "phone unreachable" signal the UI
/// needs. The phone additionally pushes an application context, so re-opening
/// the app shows last-known state instead of an empty list.
final class PhoneLink: NSObject, ObservableObject {

  @Published private(set) var link: PhoneLinkState = .connecting
  @Published private(set) var snapshot: PhoneSnapshot = .empty

  /// A command has been handed to WatchConnectivity and not yet answered.
  @Published private(set) var sending: Bool = false

  /// The toggle spins whenever the phone is mid-transition or the watch is
  /// still waiting for an acknowledgement, so a slow link never looks like a
  /// dead button.
  var busy: Bool { sending || snapshot.status.isBusy }

  /// Identity of the newest interactive WatchConnectivity request.
  ///
  /// `sendMessage` completion handlers and our local deadline are all
  /// asynchronous. A previous request may finish after a newer request has
  /// started, so shared `sending` state is not enough to decide which request
  /// may complete the UI. Only the holder of this identity may do so.
  private var requestGeneration = PhoneLinkRequestGeneration()

  private var session: WCSession? {
    WCSession.isSupported() ? WCSession.default : nil
  }

  func start() {
    guard let session else {
      link = .unreachable
      return
    }
    session.delegate = self
    if session.activationState != .activated {
      session.activate()
    }
    // Whatever the phone last pushed, before asking for anything fresh. Not
    // stamped as a live arrival: the OS retains this context across launches,
    // so its load figures render unknown until a live snapshot arrives.
    apply(PhoneSnapshot(payload: session.receivedApplicationContext))
    refresh()
  }

  // MARK: - Commands

  /// Maps onto the phone's own single connect/disconnect entry point.
  func toggleConnection() {
    send(snapshot.status.isOnOrGoingOn ? .disconnect : .connect)
  }

  func selectCountry(_ slug: String) {
    guard !slug.isEmpty, slug != snapshot.selectedSlug else { return }
    send(.selectCountry, slug: slug)
  }

  func refresh() {
    send(.requestState, silent: true)
  }

  private func send(_ command: WatchLink.Command, slug: String? = nil, silent: Bool = false) {
    guard let session, session.activationState == .activated else {
      requestGeneration.cancel()
      link = .unreachable
      sending = false
      return
    }
    let payload = WatchLink.message(command, slug: slug)
    // Reachable → immediate interactive message with reply so the toggle can
    // reflect the phone's answer without waiting for an application-context
    // push. Unreachable → nothing is sent or queued, and the UI shows
    // "iPhone unreachable" now, never a stale state as current.
    if session.isReachable {
      let requestID = requestGeneration.begin()
      sending = !silent
      session.sendMessage(
        payload,
        replyHandler: { [weak self] reply in
          // Live arrival: stamp it so its load figures can be shown.
          let parsed = PhoneSnapshot(payload: reply)?.arrivedLive()
          DispatchQueue.main.async {
            guard let self, self.complete(requestID: requestID) else { return }
            self.apply(parsed)
          }
        },
        errorHandler: { [weak self] _ in
          DispatchQueue.main.async {
            guard let self, self.complete(requestID: requestID) else { return }
            self.link = .unreachable
          }
        }
      )
      // Hard timeout: a stalled sendMessage must not leave the UI awaiting
      // forever. If neither handler fires within 4 seconds, treat the phone
      // as unreachable and clear the spinner. The reply/error handlers clear
      // `sending` on success, so this is a no-op when they fire in time.
      // DispatchQueue.asyncAfter 4s timeout -> .unreachable
      DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in // DispatchQueue.asyncAfter
        guard let self, self.complete(requestID: requestID) else { return }
        if !silent {
          self.link = .unreachable
        } else if self.link == .connecting {
          // Covers the silent `requestState` at startup: `sending` stays
          // false but `link` is still `.connecting` with no snapshot. A
          // stalled refresh must also flip to `.unreachable` within 4s.
          self.link = .unreachable
        }
      }
    } else {
      requestGeneration.cancel()
      link = .unreachable
      sending = false
      // Connect, disconnect and country changes are never queued: a queued
      // command is delivered whenever the link returns, possibly hours later,
      // and would act on a tunnel state the user can no longer see.
      return
    }
  }

  /// Completes exactly one generation of `sendMessage` work.
  ///
  /// Returning false means that this callback or timeout belongs to a request
  /// superseded by a newer send. It must not clear the newer spinner, apply an
  /// older reply, or mark the current phone link unreachable.
  @discardableResult
  private func complete(requestID: UUID) -> Bool {
    guard requestGeneration.complete(requestID) else { return false }
    sending = false
    return true
  }

  // MARK: - State

  private func apply(_ incoming: PhoneSnapshot?) {
    guard let incoming else { return }
    // Out-of-order delivery is normal across two transports; never let an older
    // snapshot overwrite a newer one and flip the toggle back.
    guard incoming.updatedAt >= snapshot.updatedAt else { return }
    snapshot = incoming
    link = .linked
  }
}

extension PhoneLink: WCSessionDelegate {

  func session(
    _ session: WCSession,
    activationDidCompleteWith activationState: WCSessionActivationState,
    error: Error?
  ) {
    let reachable = error == nil && activationState == .activated
    let pending = PhoneSnapshot(payload: session.receivedApplicationContext)
    DispatchQueue.main.async { [weak self] in
      guard let self else { return }
      if reachable {
        self.apply(pending)
        self.refresh()
      } else {
        self.link = .unreachable
      }
    }
  }

  func sessionReachabilityDidChange(_ session: WCSession) {
    let reachable = session.isReachable
    DispatchQueue.main.async { [weak self] in
      guard let self else { return }
      if reachable {
        self.refresh()
      } else {
        self.link = .unreachable
      }
    }
  }

  func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
    let parsed = PhoneSnapshot(payload: applicationContext)?.arrivedLive()
    DispatchQueue.main.async { [weak self] in
      self?.apply(parsed)
    }
  }

  func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
    let parsed = PhoneSnapshot(payload: message)?.arrivedLive()
    DispatchQueue.main.async { [weak self] in
      self?.apply(parsed)
    }
  }

  // Required on iOS but marked unavailable on watchOS, so a watchOS-only
  // typecheck never surfaces their absence. Without them the conformance is
  // incomplete when the same source builds against the iPhoneOS SDK; guarded
  // so the watchOS build still typechecks.
  #if os(iOS)
  func sessionDidBecomeInactive(_ session: WCSession) {
  }

  func sessionDidDeactivate(_ session: WCSession) {
    // Apple's prescribed pattern: re-activate so the session resumes after
    // the current one deactivates.
    session.activate()
  }
  #endif
}
