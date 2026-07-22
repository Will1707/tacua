// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum LocalHarnessPolicyTestFailure: Error { case assertion(String) }

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw LocalHarnessPolicyTestFailure.assertion(message) }
}

@main
enum LocalHarnessPolicyTests {
  static func main() throws {
#if DEBUG
    try debugRequiresEveryExactGate()
#else
    try releaseAlwaysEnforcesBackendRetention()
#endif
    print("Tacua local harness policy tests passed")
  }

#if DEBUG
  private static func debugRequiresEveryExactGate() throws {
    let expectedStop = 100
      + TacuaCapturePolicy.maximumDurationSeconds
      + TacuaCapturePolicy.startWatchdogSeconds
      + 1
    try require(
      TacuaLocalHarnessPolicy.retentionDecision(
        bundleIdentifier: "com.tacua.capturelab.acceptance",
        retentionBypassInfoValue: true,
        captureEnabledInfoValue: true,
        buildVariant: "development",
        distribution: "local",
        currentUptimeSeconds: 100
      ) == .localHarness(rawMediaStopHostUptimeSeconds: expectedStop),
      "The exact debug harness gates should authorize the bounded local policy"
    )

    for bundleIdentifier in [nil, "", "com.tacua.capturelab", "com.example.capturelab"] {
      try require(
        TacuaLocalHarnessPolicy.retentionDecision(
          bundleIdentifier: bundleIdentifier,
          retentionBypassInfoValue: true,
          captureEnabledInfoValue: true,
          buildVariant: "development",
          distribution: "local",
          currentUptimeSeconds: 100
        ) == .backendEnforced,
        "Any non-acceptance bundle must retain backend enforcement"
      )
    }
    for value: Any? in [nil, false, 1, "true"] {
      try require(
        TacuaLocalHarnessPolicy.retentionDecision(
          bundleIdentifier: "com.tacua.capturelab.acceptance",
          retentionBypassInfoValue: value,
          captureEnabledInfoValue: true,
          buildVariant: "development",
          distribution: "local",
          currentUptimeSeconds: 100
        ) == .backendEnforced,
        "The Info.plist gate must be the exact Boolean true value"
      )
    }
    for (captureEnabled, buildVariant, distribution) in [
      (false, "development", "local"),
      (1, "development", "local"),
      (true, "preview", "local"),
      (true, "development", "internal"),
    ] as [(Any?, String?, String?)] {
      try require(
        TacuaLocalHarnessPolicy.retentionDecision(
          bundleIdentifier: "com.tacua.capturelab.acceptance",
          retentionBypassInfoValue: true,
          captureEnabledInfoValue: captureEnabled,
          buildVariant: buildVariant,
          distribution: distribution,
          currentUptimeSeconds: 100
        ) == .backendEnforced,
        "The existing local-development QA gates must also match"
      )
    }
    for uptime in [-1, .infinity, .nan] as [Double] {
      try require(
        TacuaLocalHarnessPolicy.retentionDecision(
          bundleIdentifier: "com.tacua.capturelab.acceptance",
          retentionBypassInfoValue: true,
          captureEnabledInfoValue: true,
          buildVariant: "development",
          distribution: "local",
          currentUptimeSeconds: uptime
        ) == .backendEnforced,
        "An invalid monotonic clock must fail closed"
      )
    }
  }
#else
  private static func releaseAlwaysEnforcesBackendRetention() throws {
    try require(
      TacuaLocalHarnessPolicy.retentionDecision(
        bundleIdentifier: "com.tacua.capturelab.acceptance",
        retentionBypassInfoValue: true,
        captureEnabledInfoValue: true,
        buildVariant: "development",
        distribution: "local",
        currentUptimeSeconds: 100
      ) == .backendEnforced,
      "A non-debug build must never bypass backend retention"
    )
  }
#endif
}
