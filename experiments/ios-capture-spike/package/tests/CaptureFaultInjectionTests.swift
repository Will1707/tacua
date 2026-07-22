// SPDX-License-Identifier: Apache-2.0

#if TACUA_CAPTURE_FAULT_INJECTION
import Foundation

private enum FaultTestFailure: Error {
  case assertion(String)
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw FaultTestFailure.assertion(message) }
}

private func lease(_ plan: TacuaCaptureFaultPlan) throws -> TacuaCaptureFaultLease {
  let source = TacuaCaptureFaultLeaseSource()
  guard let lease = source.claim(
    bundleIdentifier: TacuaCaptureFaultRuntime.requiredBundleIdentifier,
    faultInjectionEnabled: true,
    environmentValue: plan.rawValue
  ) else {
    throw FaultTestFailure.assertion("Expected a lease for \(plan.rawValue)")
  }
  return lease
}

@main
enum CaptureFaultInjectionTests {
  static func main() throws {
    try exactParserContract()
    try storageMatchers()
    try finishMatchers()
    try stopMatchers()
    try runtimeGatesAndOneClaim()
    print("Tacua capture fault-injection tests passed")
  }

  private static func exactParserContract() throws {
    let expected: [(String, TacuaCaptureFaultPlan)] = [
      ("low_storage_start", .lowStorageStart),
      ("low_storage_writer_1", .lowStorageWriter1),
      ("writer_finish_failure_1", .writerFinishFailure1),
      ("writer_finish_timeout_1", .writerFinishTimeout1),
      ("stop_failure_once", .stopFailureOnce),
      ("stop_timeout_once", .stopTimeoutOnce),
      ("stop_timeout_twice", .stopTimeoutTwice),
    ]
    try expect(TacuaCaptureFaultPlan.allCases.count == expected.count, "Every plan must be tested")
    for (rawValue, plan) in expected {
      try expect(
        TacuaCaptureFaultPlan(environmentValue: rawValue) == plan,
        "Expected exact parser match for \(rawValue)"
      )
    }

    for invalid in [nil, "", " low_storage_start", "low_storage_start ", "LOW_STORAGE_START",
                    "low_storage_start,stop_timeout_once"] as [String?] {
      try expect(
        TacuaCaptureFaultPlan(environmentValue: invalid) == nil,
        "Malformed fault values must fail closed"
      )
    }
  }

  private static func storageMatchers() throws {
    let preparation = try lease(.lowStorageStart)
    try expect(preparation.shouldFailPreparationStorageCheck, "Start fault must match preparation")
    try expect(
      !preparation.shouldFailWriterStorageCheck(segmentIndex: 1),
      "Start fault must not leak into writer checks"
    )

    let writer = try lease(.lowStorageWriter1)
    try expect(!writer.shouldFailPreparationStorageCheck, "Writer fault must not fail preparation")
    try expect(writer.shouldFailWriterStorageCheck(segmentIndex: 1), "Writer 1 must match")
    for index in [-1, 0, 2, Int.max] {
      try expect(
        !writer.shouldFailWriterStorageCheck(segmentIndex: index),
        "Writer storage fault must match only index 1"
      )
    }
  }

  private static func finishMatchers() throws {
    let failure = try lease(.writerFinishFailure1)
    let timeout = try lease(.writerFinishTimeout1)
    try expect(failure.finishBehavior(segmentIndex: 1) == .failure, "Writer 1 must fail")
    try expect(timeout.finishBehavior(segmentIndex: 1) == .timeout, "Writer 1 must time out")
    try expect(
      failure.shouldRequestStop(afterCommittedSegmentIndex: 0),
      "Writer failure must request one stop after segment 0 commits"
    )
    try expect(
      timeout.shouldRequestStop(afterCommittedSegmentIndex: 0),
      "Writer timeout must request one stop after segment 0 commits"
    )
    for index in [-1, 0, 2, Int.max] {
      try expect(failure.finishBehavior(segmentIndex: index) == .none, "Failure must stay scoped")
      try expect(timeout.finishBehavior(segmentIndex: index) == .none, "Timeout must stay scoped")
    }
    for index in [-1, 1, 2, Int.max] {
      try expect(
        !failure.shouldRequestStop(afterCommittedSegmentIndex: index),
        "Writer failure auto-stop must match only committed segment 0"
      )
      try expect(
        !timeout.shouldRequestStop(afterCommittedSegmentIndex: index),
        "Writer timeout auto-stop must match only committed segment 0"
      )
    }
    let unrelated = try lease(.lowStorageStart)
    try expect(
      unrelated.finishBehavior(segmentIndex: 1) == .none,
      "Unrelated plans must not alter finalization"
    )
    try expect(
      !unrelated.shouldRequestStop(afterCommittedSegmentIndex: 0),
      "Unrelated plans must not request the writer auto-stop"
    )
  }

  private static func stopMatchers() throws {
    let failure = try lease(.stopFailureOnce)
    let timeoutOnce = try lease(.stopTimeoutOnce)
    let timeoutTwice = try lease(.stopTimeoutTwice)

    try expect(failure.stopBehavior(attempt: 1) == .failure, "First stop must fail")
    try expect(failure.stopBehavior(attempt: 2) == .none, "Failure-once must be consumed by attempt 1")
    try expect(timeoutOnce.stopBehavior(attempt: 1) == .timeout, "First stop must time out")
    try expect(timeoutOnce.stopBehavior(attempt: 2) == .none, "Timeout-once must affect one attempt")
    try expect(timeoutTwice.stopBehavior(attempt: 1) == .timeout, "Attempt 1 must time out")
    try expect(timeoutTwice.stopBehavior(attempt: 2) == .timeout, "Attempt 2 must time out")
    for attempt in [Int.min, -1, 0, 3, Int.max] {
      try expect(failure.stopBehavior(attempt: attempt) == .none, "Failure attempt must be exact")
      try expect(timeoutOnce.stopBehavior(attempt: attempt) == .none, "Single timeout must be exact")
      try expect(timeoutTwice.stopBehavior(attempt: attempt) == .none, "Double timeout must be exact")
    }
  }

  private static func runtimeGatesAndOneClaim() throws {
    for bundleIdentifier in ["com.tacua.capturelab", "com.example.capturelab"] {
      let wrongBundle = TacuaCaptureFaultLeaseSource()
      try expect(
        wrongBundle.claim(
          bundleIdentifier: bundleIdentifier,
          faultInjectionEnabled: true,
          environmentValue: TacuaCaptureFaultPlan.lowStorageStart.rawValue
        ) == nil,
        "A non-acceptance bundle must not receive a lease"
      )
    }

    let disabled = TacuaCaptureFaultLeaseSource()
    try expect(
      disabled.claim(
        bundleIdentifier: TacuaCaptureFaultRuntime.requiredBundleIdentifier,
        faultInjectionEnabled: false,
        environmentValue: TacuaCaptureFaultPlan.lowStorageStart.rawValue
      ) == nil,
      "The Info.plist gate must be enabled"
    )

    let source = TacuaCaptureFaultLeaseSource()
    try expect(!source.hasClaimedLease, "A fresh process lease source must report unconsumed")
    try expect(
      source.claim(
        bundleIdentifier: TacuaCaptureFaultRuntime.requiredBundleIdentifier,
        faultInjectionEnabled: true,
        environmentValue: "unknown_fault"
      ) == nil,
      "An invalid value must not create a lease"
    )
    let first = source.claim(
      bundleIdentifier: TacuaCaptureFaultRuntime.requiredBundleIdentifier,
      faultInjectionEnabled: true,
      environmentValue: TacuaCaptureFaultPlan.stopTimeoutOnce.rawValue
    )
    try expect(first?.plan == .stopTimeoutOnce, "A fully gated claim must succeed")
    try expect(source.hasClaimedLease, "A successful claim must remain observable after JS remount")
    let second = source.claim(
      bundleIdentifier: TacuaCaptureFaultRuntime.requiredBundleIdentifier,
      faultInjectionEnabled: true,
      environmentValue: TacuaCaptureFaultPlan.lowStorageStart.rawValue
    )
    try expect(second == nil, "A process lease source must grant at most one lease")
  }
}
#endif
