// SPDX-License-Identifier: Apache-2.0

import Foundation

extension Notification.Name {
  static let tacuaPendingBackendLaunchURL = Notification.Name(
    "TacuaPendingBackendLaunchURL"
  )
}

/// A bounded, process-local handoff between UIApplicationDelegate and the Expo module.
///
/// Only URLs that pass the exact build-pinned Tacua parser enter this inbox. Values are never
/// logged or persisted and are removed atomically when the JavaScript lifecycle adapter drains
/// them into its existing serialized, fingerprint-deduplicated delivery queue.
final class TacuaLaunchURLInbox {
  static let shared = TacuaLaunchURLInbox()

  private let lock = NSLock()
  private let maximumPendingURLs: Int
  private var pendingURLs: [String] = []

  init(maximumPendingURLs: Int = 32) {
    precondition(maximumPendingURLs > 0)
    self.maximumPendingURLs = maximumPendingURLs
  }

  @discardableResult
  func capture(
    rawURL: String,
    configuration: TacuaLaunchLinkConfiguration
  ) -> Bool {
    guard (try? TacuaLaunchLinkParser.parse(rawURL, configuration: configuration)) != nil
    else { return false }

    lock.lock()
    defer { lock.unlock() }
    guard pendingURLs.count < maximumPendingURLs else { return false }
    pendingURLs.append(rawURL)
    return true
  }

  func drain() -> [String] {
    lock.lock()
    defer { lock.unlock() }
    let drained = pendingURLs
    pendingURLs.removeAll(keepingCapacity: true)
    return drained
  }
}
