// SPDX-License-Identifier: Apache-2.0

import ExpoModulesCore
import Foundation

public final class TacuaLaunchURLAppDelegateSubscriber: ExpoAppDelegateSubscriber {
#if os(iOS) || os(tvOS)
  public func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    if let url = launchOptions?[.url] as? URL {
      capture(url)
    }
    // Preserve Expo and React Native's existing launch handling.
    return false
  }

  public func application(
    _ application: UIApplication,
    open url: URL,
    options: [UIApplication.OpenURLOptionsKey: Any] = [:]
  ) -> Bool {
    capture(url)
    // This subscriber mirrors a valid link; it never claims the application callback.
    return false
  }

  private func capture(_ url: URL) {
    guard let configuration = try? TacuaLaunchLinkConfiguration.fromBuildConfiguration(),
      TacuaLaunchURLInbox.shared.capture(
        rawURL: url.absoluteString,
        configuration: configuration
      )
    else { return }

    // The notification is deliberately content-free. The URL stays inside the volatile inbox.
    NotificationCenter.default.post(name: .tacuaPendingBackendLaunchURL, object: nil)
  }
#endif
}
