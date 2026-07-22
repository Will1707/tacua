// SPDX-License-Identifier: Apache-2.0

import Darwin
import Foundation

enum TacuaSDKLocalRetentionOutcome: Equatable {
  case active(rawMediaExpiresAt: String, stopUptimeMilliseconds: Int64)
  case unmanaged
  case retired
}

/// Wall time is injected so expiry tests and hosts with a stronger trusted-time source do not
/// depend on process uptime or a caller-supplied request timestamp. The boundary is half-open:
/// local raw data is usable only while `now < raw_media_expires_at`.
protocol TacuaAuthoritativeWallClock {
  func nowMilliseconds() throws -> Int64
}

struct TacuaSystemAuthoritativeWallClock: TacuaAuthoritativeWallClock {
  func nowMilliseconds() throws -> Int64 {
    let seconds = Date().timeIntervalSince1970
    guard seconds.isFinite,
      seconds >= 0,
      seconds <= Double(Int64.max) / 1_000
    else { throw TacuaSDKLocalRetentionError.invalidClock }
    return Int64((seconds * 1_000).rounded(.down))
  }
}

/// Enforces the immutable START raw-media deadline over the whole repo-owned local footprint.
///
/// The durable queue is intentionally removed last. Until that final unlink is fsynced it remains
/// both the immutable deadline authority and the crash journal for retries after session-tree,
/// Keychain, START-journal, or RESUME-journal cleanup partially succeeds. An unreadable queue or a
/// queue without START authority is not allowed to retain raw data indefinitely: its exact local
/// footprint is retired immediately and every lifecycle caller fails closed.
final class TacuaSDKLocalRetentionCoordinator: TacuaSDKLocalRetentionChecking {
  private static let maximumCaptureEntries = 4_096

  private let captureRootDirectory: URL
  private let queueStore: TacuaTransportQueueFileStore
  private let startJournalStore: TacuaSDKStartJournalFileStore
  private let resumeJournalStore: TacuaSDKResumeJournalFileStore
  private let credentialStore: TacuaCredentialStoring
  private let wallClock: TacuaAuthoritativeWallClock
  private let monotonicClock: TacuaMonotonicClock
  private let fileManager: FileManager
  private let retirerFactory: (URL) throws -> TacuaLocalSessionRetiring

  init(
    captureRootDirectory: URL,
    queueStore: TacuaTransportQueueFileStore,
    startJournalStore: TacuaSDKStartJournalFileStore,
    resumeJournalStore: TacuaSDKResumeJournalFileStore,
    credentialStore: TacuaCredentialStoring,
    wallClock: TacuaAuthoritativeWallClock = TacuaSystemAuthoritativeWallClock(),
    monotonicClock: TacuaMonotonicClock = TacuaSystemMonotonicClock(),
    fileManager: FileManager = .default,
    retirerFactory: @escaping (URL) throws -> TacuaLocalSessionRetiring = {
      try TacuaScopedSessionRetirer(sessionDirectory: $0)
    }
  ) {
    self.captureRootDirectory = captureRootDirectory.standardizedFileURL
    self.queueStore = queueStore
    self.startJournalStore = startJournalStore
    self.resumeJournalStore = resumeJournalStore
    self.credentialStore = credentialStore
    self.wallClock = wallClock
    self.monotonicClock = monotonicClock
    self.fileManager = fileManager
    self.retirerFactory = retirerFactory
  }

  /// Enforces one session under the same lifecycle lease used by START, RESUME, admission,
  /// upload, deletion, and status recovery. A successful retirement is still reported as expired
  /// so the initiating operation cannot continue against a newly absent queue.
  func requireActive(localSessionID: String) throws {
    switch try enforce(localSessionID: localSessionID) {
    case .active, .unmanaged: return
    case .retired: throw TacuaSDKLocalRetentionError.expired
    }
  }

  @discardableResult
  func enforce(localSessionID: String) throws -> TacuaSDKLocalRetentionOutcome {
    guard Self.validIdentifier(localSessionID) else {
      throw TacuaSDKLocalRetentionError.invalidSessionID
    }
    let lease: TacuaSDKStartLifecycleLease
    do { lease = try startJournalStore.acquireLifecycleLease(localSessionID: localSessionID) }
    catch { throw TacuaSDKLocalRetentionError.cleanupIncomplete }
    defer { lease.release() }

    return try enforceHoldingLifecycleLease(localSessionID: localSessionID)
  }

  /// Internal lifecycle entry point. The caller must already hold the exact per-session START
  /// lease. This intentionally does not reacquire it; flock is process-scoped and a nested
  /// acquisition can silently release or deadlock the outer critical section.
  func requireActiveHoldingLifecycleLease(localSessionID: String) throws {
    switch try enforceHoldingLifecycleLease(localSessionID: localSessionID) {
    case .active, .unmanaged: return
    case .retired: throw TacuaSDKLocalRetentionError.expired
    }
  }

  func activeStopUptimeMillisecondsHoldingLifecycleLease(
    localSessionID: String
  ) throws -> Int64 {
    guard case .active(_, let stopUptimeMilliseconds) = try enforceHoldingLifecycleLease(
      localSessionID: localSessionID
    ) else { throw TacuaSDKLocalRetentionError.expired }
    return stopUptimeMilliseconds
  }

  @discardableResult
  private func enforceHoldingLifecycleLease(
    localSessionID: String
  ) throws -> TacuaSDKLocalRetentionOutcome {
    guard Self.validIdentifier(localSessionID) else {
      throw TacuaSDKLocalRetentionError.invalidSessionID
    }

    let queue: TacuaTransportQueueV3?
    let queueUnreadable: Bool
    do {
      queue = try queueStore.load(localSessionID: localSessionID)
      queueUnreadable = false
    } catch {
      queue = nil
      queueUnreadable = true
    }

    let liveOrRetiringCaptureExists: Bool
    do { liveOrRetiringCaptureExists = try hasCaptureFootprint(localSessionID) }
    catch { throw TacuaSDKLocalRetentionError.cleanupIncomplete }

    var startJournal: TacuaSDKStartJournal?
    var startJournalUnreadable = false
    do { startJournal = try startJournalStore.load(localSessionID: localSessionID) }
    catch { startJournalUnreadable = true }

    var resumeJournalExists = false
    var resumeJournalUnreadable = false
    do {
      resumeJournalExists = try resumeJournalStore.load(localSessionID: localSessionID) != nil
    } catch {
      resumeJournalUnreadable = true
    }

    let queueAuthority = queue?.sessionRetentionAuthority
    let journalAuthority = startJournal?.validatedReceipt?.sessionRetentionAuthority
    if let queueAuthority, let journalAuthority, queueAuthority != journalAuthority {
      return try retire(
        localSessionID: localSessionID,
        queue: queue,
        startJournal: startJournal,
        startJournalUnreadable: startJournalUnreadable
      )
    }
    if let authority = queueAuthority ?? journalAuthority {
      let deadline: Int64
      let now: Int64
      let stopUptimeMilliseconds: Int64?
      do {
        try authority.validate()
        guard let parsed = TacuaProtocolTimestamp.parseMilliseconds(
          authority.rawMediaExpiresAt
        ) else { throw TacuaSDKLocalRetentionError.invalidClock }
        deadline = parsed
        guard let anchor = queue?.timeAnchor ?? startJournal?.validatedReceipt?.timeAnchor else {
          // A server deadline without its persisted server/uptime anchor cannot be evaluated from
          // mutable device wall time. Treat that state as untrusted local authority and retire it.
          return try retire(
            localSessionID: localSessionID,
            queue: queue,
            startJournal: startJournal,
            startJournalUnreadable: startJournalUnreadable
          )
        }
        let wallNow = try wallClock.nowMilliseconds()
        guard wallNow >= 0 else { throw TacuaSDKLocalRetentionError.invalidClock }
        guard let issuedEpoch = TacuaProtocolTimestamp.parseMilliseconds(anchor.issuedAt),
          anchor.issuedEpochMilliseconds == issuedEpoch,
          anchor.uptimeMillisecondsAtIssue >= 0,
          !anchor.bootSessionID.isEmpty,
          anchor.bootSessionID.utf8.count <= 255,
          anchor.minimumEpochMilliseconds >= issuedEpoch
        else {
          return try retire(
            localSessionID: localSessionID,
            queue: queue,
            startJournal: startJournal,
            startJournalUnreadable: startJournalUnreadable
          )
        }
        let currentBootSessionID = monotonicClock.bootSessionID
        let currentUptimeMilliseconds = monotonicClock.uptimeMilliseconds
        if currentBootSessionID == anchor.bootSessionID {
          guard currentUptimeMilliseconds >= anchor.uptimeMillisecondsAtIssue else {
            return try retire(
              localSessionID: localSessionID,
              queue: queue,
              startJournal: startJournal,
              startJournalUnreadable: startJournalUnreadable
            )
          }
          let elapsed = currentUptimeMilliseconds - anchor.uptimeMillisecondsAtIssue
          let (projected, projectedOverflow) = issuedEpoch.addingReportingOverflow(elapsed)
          guard !projectedOverflow else {
            return try retire(
              localSessionID: localSessionID,
              queue: queue,
              startJournal: startJournal,
              startJournalUnreadable: startJournalUnreadable
            )
          }
          let anchoredNow = max(anchor.minimumEpochMilliseconds, projected)
          // The server/monotonic projection is a persisted nondecreasing floor. Device wall-clock
          // rollback can therefore never move retention backwards while the boot anchor is valid.
          now = max(anchoredNow, wallNow)
          if now < deadline {
            let (stop, stopOverflow) = currentUptimeMilliseconds.addingReportingOverflow(
              deadline - now
            )
            guard !stopOverflow else {
              return try retire(
                localSessionID: localSessionID,
                queue: queue,
                startJournal: startJournal,
                startJournalUnreadable: startJournalUnreadable
              )
            }
            stopUptimeMilliseconds = stop
          } else {
            stopUptimeMilliseconds = nil
          }
        } else {
          // Across a reboot, an ordinary wall observation at/after the immutable deadline is
          // sufficient for deletion (never for continued access). A pre-deadline observation
          // cannot prove that the user did not roll time backwards, so it requires a fresh server
          // exchange. An observation below the persisted server floor is an explicit rollback.
          if wallNow >= deadline {
            now = wallNow
            stopUptimeMilliseconds = nil
          } else if wallNow < anchor.minimumEpochMilliseconds {
            throw TacuaSDKLocalRetentionError.clockRollbackDetected
          } else {
            throw TacuaSDKLocalRetentionError.authoritativeTimeUnavailable
          }
        }
      } catch let error as TacuaSDKLocalRetentionError {
        throw error
      } catch {
        return try retire(
          localSessionID: localSessionID,
          queue: queue,
          startJournal: startJournal,
          startJournalUnreadable: startJournalUnreadable
        )
      }
      if !queueUnreadable, now < deadline {
        guard let stopUptimeMilliseconds else {
          throw TacuaSDKLocalRetentionError.authoritativeTimeUnavailable
        }
        return .active(
          rawMediaExpiresAt: authority.rawMediaExpiresAt,
          stopUptimeMilliseconds: stopUptimeMilliseconds
        )
      }
      return try retire(
        localSessionID: localSessionID,
        queue: queue,
        startJournal: startJournal,
        startJournalUnreadable: startJournalUnreadable
      )
    }

    // A pre-receipt START journal has never authorized ReplayKit and has no server deadline yet.
    // Preserve that recovery state only while no raw capture footprint or committed queue exists.
    if !queueUnreadable, queue == nil, startJournal != nil,
      !startJournalUnreadable, !resumeJournalExists, !resumeJournalUnreadable,
      !liveOrRetiringCaptureExists
    {
      return .unmanaged
    }
    if !queueUnreadable, queue == nil, startJournal == nil,
      !startJournalUnreadable, !resumeJournalExists, !resumeJournalUnreadable,
      !liveOrRetiringCaptureExists
    {
      return .unmanaged
    }
    return try retire(
      localSessionID: localSessionID,
      queue: queue,
      startJournal: startJournal,
      startJournalUnreadable: startJournalUnreadable
    )
  }

  /// Relaunch sweep. Hidden `.tacua-retiring-*` trees are included so a crash after the atomic
  /// rename cannot make expired bytes disappear from discovery without actually deleting them.
  @discardableResult
  func sweep() throws -> [String] {
    var identifiers = Set(try queueStore.listLocalSessionIDs())
    identifiers.formUnion(try startJournalStore.listLocalSessionIDs())
    identifiers.formUnion(try resumeJournalStore.listLocalSessionIDs())
    identifiers.formUnion(try captureSessionIDs())
    var retired: [String] = []
    var cleanupFailed = false
    for localSessionID in identifiers.sorted() {
      do {
        if try enforce(localSessionID: localSessionID) == .retired {
          retired.append(localSessionID)
        }
      } catch TacuaSDKLocalRetentionError.authoritativeTimeUnavailable,
        TacuaSDKLocalRetentionError.clockRollbackDetected
      {
        // Discovery metadata remains available so the host can request a fresh reviewer RESUME.
        // Raw capture and transport lifecycle entry points remain blocked by `requireActive`.
        continue
      } catch TacuaSDKLocalRetentionError.cleanupIncomplete {
        // One temporarily unavailable session must not starve cleanup of every later session.
        // Its queue remains the durable retry journal and the aggregate failure tells the caller
        // to schedule another sweep after all currently actionable identifiers were attempted.
        cleanupFailed = true
      }
    }
    if cleanupFailed { throw TacuaSDKLocalRetentionError.cleanupIncomplete }
    return retired
  }

  private func retire(
    localSessionID: String,
    queue: TacuaTransportQueueV3?,
    startJournal: TacuaSDKStartJournal?,
    startJournalUnreadable: Bool
  ) throws -> TacuaSDKLocalRetentionOutcome {
    do {
      let sessionDirectory = captureRootDirectory.appendingPathComponent(
        localSessionID,
        isDirectory: true
      ).standardizedFileURL
      guard sessionDirectory.deletingLastPathComponent() == captureRootDirectory else {
        throw TacuaSDKLocalRetentionError.invalidSessionID
      }
      try retirerFactory(sessionDirectory).retireSession()

      var resumeJournal: TacuaSDKResumeJournal?
      var resumeJournalUnreadable = false
      do { resumeJournal = try resumeJournalStore.load(localSessionID: localSessionID) }
      catch { resumeJournalUnreadable = true }

      // Queue authority owns every credential recorded in its bounded ledger. Removal is
      // idempotent, including a Keychain item that a prior cleanup attempt already deleted.
      if let queue {
        var credentialIDs = Set(queue.credentialExpiryLedger?.keys.map { $0 } ?? [])
        credentialIDs.formUnion(queue.pendingRevokedCredentialRemovals)
        if let current = queue.currentCredentialID { credentialIDs.insert(current) }
        for credentialID in credentialIDs.sorted() {
          try credentialStore.remove(credentialID: credentialID)
        }
      }
      if let resumeJournal {
        try credentialStore.remove(credentialID: resumeJournal.previousCredentialID)
        _ = try TacuaCredentialFactory(store: credentialStore).removeIfOwned(
          credentialID: resumeJournal.newCredentialID,
          ownershipDigest: resumeJournal.newCredentialOwnershipDigest
        )
      }
      if let startJournal {
        _ = try TacuaCredentialFactory(store: credentialStore).removeIfOwned(
          credentialID: startJournal.credentialID,
          ownershipDigest: startJournal.credentialOwnershipDigest
        )
      }

      if resumeJournal != nil || resumeJournalUnreadable {
        try resumeJournalStore.retire(localSessionID: localSessionID)
      }
      if startJournal != nil || startJournalUnreadable {
        try startJournalStore.retire(localSessionID: localSessionID)
      }
      // Last durable mutation: until this exact-name unlink is fsynced the queue retains the
      // immutable deadline and all known credential identifiers for another idempotent retry.
      try queueStore.remove(localSessionID: localSessionID)
      return .retired
    } catch let error as TacuaSDKLocalRetentionError {
      throw error
    } catch {
      throw TacuaSDKLocalRetentionError.cleanupIncomplete
    }
  }

  private func captureSessionIDs() throws -> Set<String> {
    var rootMetadata = stat()
    if lstat(captureRootDirectory.path, &rootMetadata) != 0 {
      if errno == ENOENT { return [] }
      throw TacuaSDKLocalRetentionError.cleanupIncomplete
    }
    guard (rootMetadata.st_mode & S_IFMT) == S_IFDIR else {
      throw TacuaSDKLocalRetentionError.cleanupIncomplete
    }
    let entries = try fileManager.contentsOfDirectory(
      at: captureRootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants]
    )
    guard entries.count <= Self.maximumCaptureEntries else {
      throw TacuaSDKLocalRetentionError.cleanupIncomplete
    }
    var result = Set<String>()
    for entry in entries {
      let name = entry.lastPathComponent
      let identifier: String
      if name.hasPrefix(".tacua-retiring-") {
        identifier = String(name.dropFirst(".tacua-retiring-".count))
      } else {
        identifier = name
      }
      if Self.validIdentifier(identifier) { result.insert(identifier) }
    }
    return result
  }

  private func hasCaptureFootprint(_ localSessionID: String) throws -> Bool {
    try captureSessionIDs().contains(localSessionID)
  }

  private static func validIdentifier(_ value: String) -> Bool {
    value.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil
  }
}
