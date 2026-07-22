// SPDX-License-Identifier: Apache-2.0

import Foundation

struct TacuaSDKBackendSessionDiscoveryRecord: Equatable {
  let localSessionID: String
  let hasCommittedQueue: Bool
  let hasStartRecovery: Bool
}

protocol TacuaSDKQueueSessionListing: AnyObject {
  func listLocalSessionIDs() throws -> [String]
}

extension TacuaTransportQueueFileStore: TacuaSDKQueueSessionListing {}

protocol TacuaSDKStartJournalSessionListing: AnyObject {
  func listLocalSessionIDs() throws -> [String]
}

extension TacuaSDKStartJournalFileStore: TacuaSDKStartJournalSessionListing {}

/// Discovers native-generated START identifiers after process death. START publishes its journal
/// before network I/O and publishes the queue before removing that journal. Reading journals,
/// queues, then journals again avoids the transition window in which a single pass could miss both.
/// Presence flags remain advisory; the selected queue/recovery state is always reloaded under the
/// normal per-session lifecycle lease before any action.
final class TacuaSDKBackendSessionDiscoveryCoordinator {
  private let queueStore: TacuaSDKQueueSessionListing
  private let startJournalStore: TacuaSDKStartJournalSessionListing

  init(
    queueStore: TacuaSDKQueueSessionListing,
    startJournalStore: TacuaSDKStartJournalSessionListing
  ) {
    self.queueStore = queueStore
    self.startJournalStore = startJournalStore
  }

  func list() throws -> [TacuaSDKBackendSessionDiscoveryRecord] {
    let firstJournalIDs = Set(try startJournalStore.listLocalSessionIDs())
    let queueIDs = Set(try queueStore.listLocalSessionIDs())
    let secondJournalIDs = Set(try startJournalStore.listLocalSessionIDs())
    let journalIDs = firstJournalIDs.union(secondJournalIDs)
    return queueIDs.union(journalIDs).sorted().map { localSessionID in
      TacuaSDKBackendSessionDiscoveryRecord(
        localSessionID: localSessionID,
        hasCommittedQueue: queueIDs.contains(localSessionID),
        hasStartRecovery: journalIDs.contains(localSessionID)
      )
    }
  }
}
