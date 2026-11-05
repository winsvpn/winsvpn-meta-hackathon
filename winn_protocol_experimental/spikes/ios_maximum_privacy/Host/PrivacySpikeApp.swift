import SwiftUI

@main
struct PrivacySpikeApp: App {
    @StateObject private var vpn = VPNController()

    var body: some Scene {
        WindowGroup {
            RunView()
                .environmentObject(vpn)
                .task { await vpn.refresh() }
        }
    }
}

