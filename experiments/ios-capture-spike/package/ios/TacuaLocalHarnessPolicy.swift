// SPDX-License-Identifier: Apache-2.0

import CoreFoundation
import Foundation

enum TacuaLocalHarnessRetentionDecision: Equatable {
  case backendEnforced
  case localHarness(rawMediaStopHostUptimeSeconds: Double)

  var bypassesBackendRetention: Bool {
    if case .localHarness = self { return true }
    return false
  }
}

/// A compile-time and build-metadata boundary for the repository's local physical-iPhone harness.
/// Normal SDK hosts must always obtain retention authority from the backend START lifecycle.
enum TacuaLocalHarnessPolicy {
#if DEBUG
  static let requiredBundleIdentifier = "com.tacua.capturelab.acceptance"
  static let retentionBypassInfoKey = "TacuaLocalHarnessRetentionBypassEnabled"
  private static let captureEnabledInfoKey = "TacuaCaptureEnabled"
  private static let buildVariantInfoKey = "TacuaCaptureBuildVariant"
  private static let distributionInfoKey = "TacuaCaptureDistribution"
#endif

  static func retentionDecision(
    bundleIdentifier: String?,
    retentionBypassInfoValue: Any?,
    captureEnabledInfoValue: Any?,
    buildVariant: String?,
    distribution: String?,
    currentUptimeSeconds: Double
  ) -> TacuaLocalHarnessRetentionDecision {
#if DEBUG
    guard bundleIdentifier == requiredBundleIdentifier,
      let flag = retentionBypassInfoValue as? NSNumber,
      CFGetTypeID(flag) == CFBooleanGetTypeID(),
      flag.boolValue,
      let captureEnabled = captureEnabledInfoValue as? NSNumber,
      CFGetTypeID(captureEnabled) == CFBooleanGetTypeID(),
      captureEnabled.boolValue,
      buildVariant == "development",
      distribution == "local",
      currentUptimeSeconds.isFinite,
      currentUptimeSeconds >= 0
    else { return .backendEnforced }

    // ReplayKit start has its own 60-second watchdog. This horizon leaves that full envelope plus
    // one second of dispatch tolerance before the ordinary 30-minute capture limit takes over.
    let stopUptimeSeconds = currentUptimeSeconds
      + TacuaCapturePolicy.maximumDurationSeconds
      + TacuaCapturePolicy.startWatchdogSeconds
      + 1
    guard stopUptimeSeconds.isFinite, stopUptimeSeconds > currentUptimeSeconds else {
      return .backendEnforced
    }
    return .localHarness(rawMediaStopHostUptimeSeconds: stopUptimeSeconds)
#else
    return .backendEnforced
#endif
  }

  static func retentionDecision(
    bundle: Bundle = .main,
    processInfo: ProcessInfo = .processInfo
  ) -> TacuaLocalHarnessRetentionDecision {
#if DEBUG
    return retentionDecision(
      bundleIdentifier: bundle.bundleIdentifier,
      retentionBypassInfoValue: bundle.object(forInfoDictionaryKey: retentionBypassInfoKey),
      captureEnabledInfoValue: bundle.object(forInfoDictionaryKey: captureEnabledInfoKey),
      buildVariant: bundle.object(forInfoDictionaryKey: buildVariantInfoKey) as? String,
      distribution: bundle.object(forInfoDictionaryKey: distributionInfoKey) as? String,
      currentUptimeSeconds: processInfo.systemUptime
    )
#else
    return .backendEnforced
#endif
  }
}
