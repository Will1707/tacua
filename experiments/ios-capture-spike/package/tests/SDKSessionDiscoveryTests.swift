// SPDX-License-Identifier: Apache-2.0

import Foundation

private enum SDKSessionDiscoveryTestFailure: Error {
  case assertion(String)
  case forcedFailure
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
  if !condition() { throw SDKSessionDiscoveryTestFailure.assertion(message) }
}

private final class QueueListing: TacuaSDKQueueSessionListing {
  var values: [String]
  var shouldFail = false

  init(_ values: [String]) { self.values = values }

  func listLocalSessionIDs() throws -> [String] {
    if shouldFail { throw SDKSessionDiscoveryTestFailure.forcedFailure }
    return values
  }
}

private final class JournalListing: TacuaSDKStartJournalSessionListing {
  var snapshots: [[String]]
  var callCount = 0

  init(_ snapshots: [[String]]) { self.snapshots = snapshots }

  func listLocalSessionIDs() throws -> [String] {
    defer { callCount += 1 }
    return snapshots[min(callCount, snapshots.count - 1)]
  }
}

@main
enum SDKSessionDiscoveryTests {
  static func main() throws {
    try unionsAndSortsQueueAndRecoveryRecords()
    try closesTheJournalToQueueTransitionWindow()
    try closesTheLateJournalPublicationWindow()
    try failsClosedWhenAStoreCannotBeScanned()
    print("Tacua SDK session-discovery tests passed")
  }

  private static func unionsAndSortsQueueAndRecoveryRecords() throws {
    let queue = QueueListing(["local_queue_002", "local_both_001"])
    let journals = JournalListing([
      ["local_recovery_003", "local_both_001"],
      ["local_recovery_003", "local_both_001"],
    ])
    let records = try TacuaSDKBackendSessionDiscoveryCoordinator(
      queueStore: queue,
      startJournalStore: journals
    ).list()
    try require(
      records.map(\.localSessionID) == [
        "local_both_001", "local_queue_002", "local_recovery_003",
      ],
      "Discovery did not return a deterministic union"
    )
    try require(
      records[0].hasCommittedQueue && records[0].hasStartRecovery,
      "Coexisting queue and recovery journal were not reported"
    )
    try require(
      records[1].hasCommittedQueue && !records[1].hasStartRecovery,
      "Queue-only discovery flags are wrong"
    )
    try require(
      !records[2].hasCommittedQueue && records[2].hasStartRecovery,
      "Recovery-only discovery flags are wrong"
    )
  }

  private static func closesTheJournalToQueueTransitionWindow() throws {
    // The journal disappeared after the first scan because its queue was published. Reading the
    // queue between the two journal passes must retain the identifier.
    let records = try TacuaSDKBackendSessionDiscoveryCoordinator(
      queueStore: QueueListing(["local_transition_001"]),
      startJournalStore: JournalListing([["local_transition_001"], []])
    ).list()
    try require(
      records == [TacuaSDKBackendSessionDiscoveryRecord(
        localSessionID: "local_transition_001",
        hasCommittedQueue: true,
        hasStartRecovery: true
      )],
      "Journal-to-queue transition disappeared from discovery"
    )
  }

  private static func closesTheLateJournalPublicationWindow() throws {
    // START published its first durable journal after the initial scan and has not published a
    // queue yet. The stabilizing second journal pass must expose it.
    let records = try TacuaSDKBackendSessionDiscoveryCoordinator(
      queueStore: QueueListing([]),
      startJournalStore: JournalListing([[], ["local_late_001"]])
    ).list()
    try require(
      records == [TacuaSDKBackendSessionDiscoveryRecord(
        localSessionID: "local_late_001",
        hasCommittedQueue: false,
        hasStartRecovery: true
      )],
      "Late START journal publication disappeared from discovery"
    )
  }

  private static func failsClosedWhenAStoreCannotBeScanned() throws {
    let queue = QueueListing([])
    queue.shouldFail = true
    do {
      _ = try TacuaSDKBackendSessionDiscoveryCoordinator(
        queueStore: queue,
        startJournalStore: JournalListing([[]])
      ).list()
      throw SDKSessionDiscoveryTestFailure.assertion("Discovery hid a queue-store failure")
    } catch SDKSessionDiscoveryTestFailure.forcedFailure {}
  }
}
