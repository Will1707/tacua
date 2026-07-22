// SPDX-License-Identifier: Apache-2.0

#if TACUA_CAPTURE_FAULT_INJECTION
import Foundation

/// A closed set of QA-only faults. Raw values intentionally match the launch
/// environment contract so malformed or combined values fail closed.
enum TacuaCaptureFaultPlan: String, CaseIterable, Equatable, Sendable {
  case lowStorageStart = "low_storage_start"
  case lowStorageWriter1 = "low_storage_writer_1"
  case writerFinishFailure1 = "writer_finish_failure_1"
  case writerFinishTimeout1 = "writer_finish_timeout_1"
  case stopFailureOnce = "stop_failure_once"
  case stopTimeoutOnce = "stop_timeout_once"
  case stopTimeoutTwice = "stop_timeout_twice"

  init?(environmentValue: String?) {
    guard let environmentValue else { return nil }
    self.init(rawValue: environmentValue)
  }
}

enum TacuaCaptureInjectedFinishBehavior: Equatable, Sendable {
  case none
  case failure
  case timeout
}

enum TacuaCaptureInjectedStopBehavior: Equatable, Sendable {
  case none
  case failure
  case timeout
}

/// An immutable, single-session view of an injected fault. Integrations should
/// use these exact matchers rather than deriving broader behavior from names.
struct TacuaCaptureFaultLease: Equatable, Sendable {
  let plan: TacuaCaptureFaultPlan

  fileprivate init(plan: TacuaCaptureFaultPlan) {
    self.plan = plan
  }

  var shouldFailPreparationStorageCheck: Bool {
    plan == .lowStorageStart
  }

  func shouldFailWriterStorageCheck(segmentIndex: Int) -> Bool {
    segmentIndex == 1 && plan == .lowStorageWriter1
  }

  func finishBehavior(segmentIndex: Int) -> TacuaCaptureInjectedFinishBehavior {
    guard segmentIndex == 1 else { return .none }
    switch plan {
    case .writerFinishFailure1:
      return .failure
    case .writerFinishTimeout1:
      return .timeout
    default:
      return .none
    }
  }

  func shouldRequestStop(afterCommittedSegmentIndex segmentIndex: Int) -> Bool {
    guard segmentIndex == 0 else { return false }
    return plan == .writerFinishFailure1 || plan == .writerFinishTimeout1
  }

  /// Stop invocations are one-based across the entire leased session. Keeping
  /// this ordinal separate from each request's retry counter guarantees that a
  /// later cleanup stop is live after the planned faults have been consumed.
  func stopBehavior(attempt: Int) -> TacuaCaptureInjectedStopBehavior {
    guard attempt > 0 else { return .none }
    switch plan {
    case .stopFailureOnce where attempt == 1:
      return .failure
    case .stopTimeoutOnce where attempt == 1:
      return .timeout
    case .stopTimeoutTwice where attempt == 1 || attempt == 2:
      return .timeout
    default:
      return .none
    }
  }
}

/// Thread-safe lease source. Only the process singleton is used by production
/// code; separate instances make the one-claim rule deterministic to test.
final class TacuaCaptureFaultLeaseSource: @unchecked Sendable {
  static let process = TacuaCaptureFaultLeaseSource()

  private let lock = NSLock()
  private var didClaimLease = false

  var hasClaimedLease: Bool {
    lock.lock()
    defer { lock.unlock() }
    return didClaimLease
  }

  func claim(
    bundleIdentifier: String?,
    faultInjectionEnabled: Bool,
    environmentValue: String?
  ) -> TacuaCaptureFaultLease? {
    guard bundleIdentifier == TacuaCaptureFaultRuntime.requiredBundleIdentifier,
      faultInjectionEnabled,
      let plan = TacuaCaptureFaultPlan(environmentValue: environmentValue)
    else { return nil }

    lock.lock()
    defer { lock.unlock() }
    guard !didClaimLease else { return nil }
    didClaimLease = true
    return TacuaCaptureFaultLease(plan: plan)
  }
}

enum TacuaCaptureFaultRuntime {
  static let requiredBundleIdentifier = "com.tacua.capturelab.acceptance"
  static let enablementInfoKey = "TacuaCaptureFaultInjectionEnabled"
  static let environmentKey = "TACUA_CAPTURE_TEST_FAULT"

  static func configuredProcessPlan(
    bundle: Bundle = .main,
    processInfo: ProcessInfo = .processInfo
  ) -> TacuaCaptureFaultPlan? {
    guard bundle.bundleIdentifier == requiredBundleIdentifier,
      bundle.object(forInfoDictionaryKey: enablementInfoKey) as? Bool == true
    else { return nil }
    return TacuaCaptureFaultPlan(environmentValue: processInfo.environment[environmentKey])
  }

  static func claimProcessLease(
    bundle: Bundle = .main,
    processInfo: ProcessInfo = .processInfo
  ) -> TacuaCaptureFaultLease? {
    TacuaCaptureFaultLeaseSource.process.claim(
      bundleIdentifier: bundle.bundleIdentifier,
      faultInjectionEnabled: bundle.object(forInfoDictionaryKey: enablementInfoKey) as? Bool == true,
      environmentValue: processInfo.environment[environmentKey]
    )
  }

  static var processLeaseWasClaimed: Bool {
    TacuaCaptureFaultLeaseSource.process.hasClaimedLease
  }
}
#endif
