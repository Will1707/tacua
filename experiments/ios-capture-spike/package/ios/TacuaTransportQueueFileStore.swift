// SPDX-License-Identifier: Apache-2.0

import Darwin
import CryptoKit
import Foundation

enum TacuaTransportQueueFileStoreError: Error, Equatable {
  case invalidSessionID
  case stateConflict
  case unsafePayloadPath
  case payloadIsDirectory
  case payloadDigestMismatch
  case payloadChangedDuringRemoval
}

struct TacuaDeletionFinalizationMarker: Codable, Equatable {
  static let schemaVersion = 1
  static let maximumEncodedBytes = 1_024

  let schemaVersion: Int
  let localSessionID: String
  let deletionID: String
  let tombstoneDigest: String

  init(localSessionID: String, deletionID: String, tombstoneDigest: String) throws {
    schemaVersion = Self.schemaVersion
    self.localSessionID = localSessionID
    self.deletionID = deletionID
    self.tombstoneDigest = tombstoneDigest
    try validate()
  }

  func encoded() throws -> Data {
    try validate()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(self)
    guard !data.isEmpty, data.count <= Self.maximumEncodedBytes else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    return data
  }

  static func decode(_ data: Data) throws -> TacuaDeletionFinalizationMarker {
    guard !data.isEmpty, data.count <= maximumEncodedBytes else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    let marker = try JSONDecoder().decode(Self.self, from: data)
    try marker.validate()
    guard try marker.encoded() == data else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    return marker
  }

  private func validate() throws {
    guard schemaVersion == Self.schemaVersion,
      localSessionID.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil,
      deletionID.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil,
      tombstoneDigest.range(of: "^sha256:[a-f0-9]{64}$", options: .regularExpression) != nil
    else { throw TacuaTransportQueueFileStoreError.stateConflict }
  }
}

final class TacuaTransportQueueFileStore: TacuaTransportQueuePersisting {
  private let rootDirectory: URL
  private let fileManager: FileManager
  private let lock = NSLock()

  init(rootDirectory: URL, fileManager: FileManager = .default) throws {
    guard rootDirectory.isFileURL else {
      throw TacuaTransportQueueFileStoreError.invalidSessionID
    }
    self.rootDirectory = rootDirectory.standardizedFileURL
    self.fileManager = fileManager
    try prepareRootDirectory()
  }

  static func applicationSupportStore(fileManager: FileManager = .default) throws
    -> TacuaTransportQueueFileStore
  {
    guard let applicationSupport = fileManager.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    ).first else {
      throw TacuaTransportQueueError.invalidQueue
    }
    return try TacuaTransportQueueFileStore(
      rootDirectory: applicationSupport
        .appendingPathComponent("TacuaTransport", isDirectory: true)
        .appendingPathComponent("queues", isDirectory: true),
      fileManager: fileManager
    )
  }

  func load(localSessionID: String) throws -> TacuaTransportQueueV3? {
    let url = try queueURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    return try withSessionFileLock(localSessionID: localSessionID) {
      try loadLocked(localSessionID: localSessionID, url: url)
    }
  }

  /// Returns only identifiers backed by a no-follow, single-link regular queue file. This is a
  /// discovery snapshot, not queue authority; callers must load the selected queue under its
  /// normal lifecycle lease before acting on it.
  func listLocalSessionIDs() throws -> [String] {
    lock.lock()
    defer { lock.unlock() }
    let suffix = ".queue-v2.json"
    var enumerationError: Error?
    guard let enumerator = fileManager.enumerator(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants],
      errorHandler: { _, error in
        enumerationError = error
        return false
      }
    ) else { throw TacuaTransportQueueFileStoreError.stateConflict }
    var scannedEntryCount = 0
    var localSessionIDs: [String] = []
    while let value = enumerator.nextObject() {
      guard let entry = value as? URL else {
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      scannedEntryCount += 1
      guard scannedEntryCount <= 4_096 else {
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      let name = entry.lastPathComponent
      guard name.hasSuffix(suffix) else { continue }
      let localSessionID = String(name.dropLast(suffix.count))
      guard localSessionID.range(
        of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression
      ) != nil else { continue }
      var metadata = stat()
      guard lstat(entry.path, &metadata) == 0 else {
        if errno == ENOENT { continue }
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      guard
        (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_nlink == 1
      else { throw TacuaTransportQueueFileStoreError.stateConflict }
      localSessionIDs.append(localSessionID)
    }
    if enumerationError != nil { throw TacuaTransportQueueFileStoreError.stateConflict }
    return localSessionIDs.sorted()
  }

  private func loadLocked(localSessionID: String, url: URL) throws
    -> TacuaTransportQueueV3?
  {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW)
    if descriptor < 0 {
      if errno == ENOENT { return nil }
      throw TacuaTransportQueueError.invalidQueue
    }
    defer { close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_size > 0,
      metadata.st_size <= TacuaTransportQueueV3.maximumEncodedBytes
    else { throw TacuaTransportQueueError.invalidQueue }
    try hardenFile(descriptor: descriptor, at: url)
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let original = try handle.readToEnd() ?? Data()
    guard original.count == metadata.st_size else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let queue = try TacuaTransportQueueV3.decodeOrMigrate(original)
    let migrated = try queue.encoded()
    if migrated != original {
      try persistLocked(migrated, to: url, localSessionID: localSessionID)
    }
    return queue
  }

  func persist(_ queue: TacuaTransportQueueV3) throws {
    let url = try queueURL(localSessionID: queue.localSessionID)
    let data = try queue.encoded()
    lock.lock()
    defer { lock.unlock() }
    try withSessionFileLock(localSessionID: queue.localSessionID) {
      try persistLocked(data, to: url, localSessionID: queue.localSessionID)
    }
  }

  /// Replaces an existing snapshot only when it is still exactly the state the
  /// caller inspected. All future transport read-modify-write paths must use
  /// this primitive (or a store-owned locked mutation), never `load` +
  /// unconditional `persist`.
  func compareAndSwap(
    expected: TacuaTransportQueueV3,
    replacement: TacuaTransportQueueV3
  ) throws {
    guard expected.localSessionID == replacement.localSessionID else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    let url = try queueURL(localSessionID: expected.localSessionID)
    let data = try replacement.encoded()
    lock.lock()
    defer { lock.unlock() }
    try withSessionFileLock(localSessionID: expected.localSessionID) {
      let current = try loadLocked(
        localSessionID: expected.localSessionID,
        url: url
      )
      // Retrying after rename succeeded but the parent fsync reported an error must be able to
      // confirm this caller's exact installed replacement. Only a third state is a real conflict.
      guard current == expected || current == replacement else {
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      try persistLocked(data, to: url, localSessionID: expected.localSessionID)
    }
  }

  /// Installs the first durable queue without ever replacing another START.
  /// Repeating the exact queue is a durability confirmation after an
  /// install-then-fsync error; any different existing queue is a conflict.
  func persistInitial(_ queue: TacuaTransportQueueV3) throws {
    let url = try queueURL(localSessionID: queue.localSessionID)
    let data = try queue.encoded()
    lock.lock()
    defer { lock.unlock() }
    try withSessionFileLock(localSessionID: queue.localSessionID) {
      if let existing = try loadLocked(
        localSessionID: queue.localSessionID,
        url: url
      ), existing != queue {
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      try persistLocked(data, to: url, localSessionID: queue.localSessionID)
    }
  }

  func remove(localSessionID: String) throws {
    let url = try queueURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    try withSessionFileLock(localSessionID: localSessionID) {
      if fileManager.fileExists(atPath: url.path) {
        try fileManager.removeItem(at: url)
      }
      // A retry after unlink-then-fsync failure must still prove that the
      // already-absent name is durably absent before reporting success.
      try syncDirectory()
    }
  }

  /// Returns proof of completed local deletion only after the sensitive queue name is durably
  /// absent. A marker installed before a crash while the queue still exists is intentionally not
  /// reported as final; `finalizeDeletion` resumes that last transition under the same file lock.
  func deletionFinalization(localSessionID: String) throws
    -> TacuaDeletionFinalizationMarker?
  {
    let queueURL = try queueURL(localSessionID: localSessionID)
    let markerURL = try deletionMarkerURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    return try withSessionFileLock(localSessionID: localSessionID) {
      guard try loadLocked(localSessionID: localSessionID, url: queueURL) == nil else {
        return nil
      }
      let marker = try loadDeletionMarkerLocked(markerURL)
      if marker != nil { try syncDirectory() }
      return marker
    }
  }

  /// Installs a minimal non-secret local finalization proof, then unlinks the sensitive queue and
  /// fsyncs the queue root. The marker makes an unlink/fsync ambiguity retryable without treating a
  /// never-existing queue as a successful deletion.
  func finalizeDeletion(localSessionID: String) throws -> TacuaDeletionFinalizationMarker {
    let queueURL = try queueURL(localSessionID: localSessionID)
    let markerURL = try deletionMarkerURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    return try withSessionFileLock(localSessionID: localSessionID) {
      let current = try loadLocked(localSessionID: localSessionID, url: queueURL)
      let existingMarker = try loadDeletionMarkerLocked(markerURL)
      guard let current else {
        guard let existingMarker else {
          throw TacuaTransportQueueFileStoreError.stateConflict
        }
        try syncDirectory()
        return existingMarker
      }
      try current.validate()
      guard let authority = current.deletionCleanupAuthority,
        current.payloadCleanupState == .payloadsRemoved,
        current.credentialCleanupState == .credentialRemoved,
        current.currentCredentialID == nil,
        current.pendingRevokedCredentialRemovals.isEmpty,
        let operation = current.operations.first(where: {
          $0.kind == .deletion && $0.operationID == authority.deletionID
        }),
        operation.state == .responseStored,
        operation.responseArtifactDigest == authority.tombstoneDigest
      else { throw TacuaTransportQueueFileStoreError.stateConflict }
      let marker = try TacuaDeletionFinalizationMarker(
        localSessionID: localSessionID,
        deletionID: authority.deletionID,
        tombstoneDigest: authority.tombstoneDigest
      )
      if let existingMarker {
        guard existingMarker == marker else {
          throw TacuaTransportQueueFileStoreError.stateConflict
        }
      } else {
        try persistDeletionMarkerLocked(marker, to: markerURL)
      }
      let result = unlink(queueURL.path)
      guard result == 0 || errno == ENOENT else {
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      try syncDirectory()
      return marker
    }
  }

  /// Runs the idempotent Keychain cleanup journal when the host explicitly opens this queue during
  /// startup/status recovery. Queue state is persisted before and after each destructive mutation,
  /// so a crash simply replays the same sweep.
  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV3? {
    let url = try queueURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    return try withSessionFileLock(localSessionID: localSessionID) {
      guard var queue = try loadLocked(localSessionID: localSessionID, url: url) else {
        return nil
      }
      // Keep the same process-wide flock across every snapshot and Keychain
      // side effect. A stale cleanup reader can therefore never overwrite an
      // uploader/resume mutation committed by another process.
      let persistence = TacuaLockedQueuePersistence { candidate in
        guard candidate.localSessionID == localSessionID else {
          throw TacuaTransportQueueFileStoreError.stateConflict
        }
        try self.persistLocked(
          candidate.encoded(), to: url, localSessionID: localSessionID
        )
      }
      try TacuaTransportCleanup.removePendingRevokedCredentials(
        queue: &queue, persistence: persistence, credentialStore: credentialStore
      )
      if queue.deletionCleanupAuthority != nil,
        queue.credentialCleanupState != .credentialRemoved
      {
        try TacuaTransportCleanup.removeAuthorizedCredential(
          queue: &queue, persistence: persistence, credentialStore: credentialStore
        )
      }
      return queue
    }
  }

  /// Completes receipt-authorized local payload cleanup while retaining the queue's process-wide
  /// file lock across both journal snapshots and every unlink. The caller must additionally hold
  /// the shared SDK lifecycle lease so START, RESUME, admission, and transport all use one lock
  /// order: lifecycle lease, then queue lock.
  func recoverPayloadCleanup(
    localSessionID: String,
    sessionDirectory: URL
  ) throws -> TacuaTransportQueueV3? {
    let url = try queueURL(localSessionID: localSessionID)
    guard sessionDirectory.standardizedFileURL.lastPathComponent == localSessionID else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    let retirer = try TacuaScopedSessionRetirer(sessionDirectory: sessionDirectory)
    lock.lock()
    defer { lock.unlock() }
    return try withSessionFileLock(localSessionID: localSessionID) {
      guard var queue = try loadLocked(localSessionID: localSessionID, url: url) else {
        return nil
      }
      let persistence = TacuaLockedQueuePersistence { candidate in
        guard candidate.localSessionID == localSessionID else {
          throw TacuaTransportQueueFileStoreError.stateConflict
        }
        try self.persistLocked(
          candidate.encoded(), to: url, localSessionID: localSessionID
        )
      }
      // No network operation can be active while the caller holds the lifecycle lease. The exact
      // session directory is renamed and retired as one receipt-authorized unit, covering manifest,
      // admission, raw diagnostic journal, upload staging, marker labels, and unexpected partials.
      try TacuaTransportCleanup.retireAuthorizedSession(
        queue: &queue,
        persistence: persistence,
        retirer: retirer
      )
      return queue
    }
  }

  func queueURL(localSessionID: String) throws -> URL {
    guard localSessionID.range(
      of: "^[a-z][a-z0-9_-]{2,63}$",
      options: .regularExpression
    ) != nil else { throw TacuaTransportQueueFileStoreError.invalidSessionID }
    let url = rootDirectory.appendingPathComponent("\(localSessionID).queue-v2.json")
      .standardizedFileURL
    guard url.deletingLastPathComponent() == rootDirectory else {
      throw TacuaTransportQueueFileStoreError.invalidSessionID
    }
    return url
  }

  private func deletionMarkerURL(localSessionID: String) throws -> URL {
    _ = try queueURL(localSessionID: localSessionID)
    let url = rootDirectory.appendingPathComponent(
      ".\(localSessionID).deletion-finalized-v1.json"
    ).standardizedFileURL
    guard url.deletingLastPathComponent() == rootDirectory else {
      throw TacuaTransportQueueFileStoreError.invalidSessionID
    }
    return url
  }

  private func loadDeletionMarkerLocked(_ url: URL) throws
    -> TacuaDeletionFinalizationMarker?
  {
    let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    if descriptor < 0 {
      if errno == ENOENT { return nil }
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    defer { close(descriptor) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFREG,
      metadata.st_nlink == 1,
      metadata.st_size > 0,
      metadata.st_size <= TacuaDeletionFinalizationMarker.maximumEncodedBytes
    else { throw TacuaTransportQueueFileStoreError.stateConflict }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let data = try handle.readToEnd() ?? Data()
    guard data.count == metadata.st_size else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    return try TacuaDeletionFinalizationMarker.decode(data)
  }

  private func persistDeletionMarkerLocked(
    _ marker: TacuaDeletionFinalizationMarker,
    to url: URL
  ) throws {
    let data = try marker.encoded()
    let suffix = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    let temporary = rootDirectory.appendingPathComponent(
      ".\(marker.localSessionID).deletion-finalized-v1.\(suffix).tmp"
    ).standardizedFileURL
    guard temporary.deletingLastPathComponent() == rootDirectory else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    let descriptor = open(
      temporary.path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaTransportQueueFileStoreError.stateConflict }
    defer {
      close(descriptor)
      _ = unlink(temporary.path)
    }
    try write(data, descriptor: descriptor)
    guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0,
      fsync(descriptor) == 0
    else { throw TacuaTransportQueueFileStoreError.stateConflict }
    // The final proof is immutable. Even a same-sandbox writer racing between the preceding
    // absence check and publication must not be overwritten with unverified bytes.
    let renameResult = temporary.path.withCString { temporaryPath in
      url.path.withCString { finalPath in
        renameatx_np(AT_FDCWD, temporaryPath, AT_FDCWD, finalPath, UInt32(RENAME_EXCL))
      }
    }
    guard renameResult == 0 else {
      throw TacuaTransportQueueFileStoreError.stateConflict
    }
    try syncDirectory()
  }

  private func prepareRootDirectory() throws {
    var missing: [URL] = []
    var cursor = rootDirectory
    while !fileManager.fileExists(atPath: cursor.path) {
      missing.append(cursor)
      let parent = cursor.deletingLastPathComponent()
      guard parent != cursor else {
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      cursor = parent
    }
    for created in missing.reversed() {
      if mkdir(created.path, S_IRWXU) != 0, errno != EEXIST {
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      var createdMetadata = stat()
      guard lstat(created.path, &createdMetadata) == 0,
        (createdMetadata.st_mode & S_IFMT) == S_IFDIR
      else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
      try hardenDirectory(created)
      try syncDirectory(at: created)
      try syncDirectory(at: created.deletingLastPathComponent())
    }
    var metadata = stat()
    guard lstat(rootDirectory.path, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFDIR
    else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
    // Repair roots created by older builds or by a concurrent initializer.
    try hardenDirectory(rootDirectory)
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var directory = rootDirectory
    try directory.setResourceValues(values)
    try syncDirectory()
    try syncDirectory(at: rootDirectory.deletingLastPathComponent())
  }

  private func withSessionFileLock<T>(
    localSessionID: String,
    _ body: () throws -> T
  ) throws -> T {
    _ = try queueURL(localSessionID: localSessionID)
    let lockURL = rootDirectory.appendingPathComponent(".\(localSessionID).lock")
      .standardizedFileURL
    guard lockURL.deletingLastPathComponent() == rootDirectory else {
      throw TacuaTransportQueueFileStoreError.invalidSessionID
    }
    let descriptor = open(
      lockURL.path,
      O_RDWR | O_CREAT | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaTransportQueueError.invalidQueue }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw TacuaTransportQueueError.invalidQueue
    }
    defer { flock(descriptor, LOCK_UN) }
    try hardenFile(descriptor: descriptor, at: lockURL)
    try syncDirectory()
    try scavengeQueueTemps(localSessionID: localSessionID)
    try scavengeDeletionMarkerTemps(localSessionID: localSessionID)
    return try body()
  }

  private func persistLocked(
    _ data: Data,
    to url: URL,
    localSessionID: String
  ) throws {
    let suffix = UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: "")
    let temporary = rootDirectory.appendingPathComponent(
      ".\(localSessionID).queue-v3.\(suffix).tmp"
    ).standardizedFileURL
    guard temporary.deletingLastPathComponent() == rootDirectory else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let descriptor = open(
      temporary.path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
      S_IRUSR | S_IWUSR
    )
    guard descriptor >= 0 else { throw TacuaTransportQueueError.invalidQueue }
    defer {
      close(descriptor)
      _ = unlink(temporary.path)
    }
    try write(data, descriptor: descriptor)
    try hardenFile(descriptor: descriptor, at: temporary)
    guard rename(temporary.path, url.path) == 0 else {
      throw TacuaTransportQueueError.invalidQueue
    }
    try syncDirectory()
  }

  private func scavengeQueueTemps(localSessionID: String) throws {
    let prefix = ".\(localSessionID).queue-v3."
    let entries = try fileManager.contentsOfDirectory(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants]
    )
    var removed = false
    for entry in entries {
      let name = entry.lastPathComponent
      guard name.hasPrefix(prefix), name.hasSuffix(".tmp"),
        name.utf8.count == prefix.utf8.count + 32 + 4
      else { continue }
      let start = name.index(name.startIndex, offsetBy: prefix.count)
      let end = name.index(name.endIndex, offsetBy: -4)
      let token = String(name[start..<end])
      guard token.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
        continue
      }
      var metadata = stat()
      guard lstat(entry.path, &metadata) == 0 else {
        if errno == ENOENT { continue }
        throw TacuaTransportQueueError.invalidQueue
      }
      guard (metadata.st_mode & S_IFMT) == S_IFREG else {
        throw TacuaTransportQueueError.invalidQueue
      }
      guard unlink(entry.path) == 0 || errno == ENOENT else {
        throw TacuaTransportQueueError.invalidQueue
      }
      removed = true
    }
    if removed { try syncDirectory() }
  }

  private func scavengeDeletionMarkerTemps(localSessionID: String) throws {
    let prefix = ".\(localSessionID).deletion-finalized-v1."
    let entries = try fileManager.contentsOfDirectory(
      at: rootDirectory,
      includingPropertiesForKeys: nil,
      options: [.skipsSubdirectoryDescendants]
    )
    var removed = false
    for entry in entries {
      let name = entry.lastPathComponent
      guard name.hasPrefix(prefix), name.hasSuffix(".tmp"),
        name.utf8.count == prefix.utf8.count + 32 + 4
      else { continue }
      let start = name.index(name.startIndex, offsetBy: prefix.count)
      let end = name.index(name.endIndex, offsetBy: -4)
      let token = String(name[start..<end])
      guard token.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else {
        continue
      }
      var metadata = stat()
      guard lstat(entry.path, &metadata) == 0 else {
        if errno == ENOENT { continue }
        throw TacuaTransportQueueFileStoreError.stateConflict
      }
      guard (metadata.st_mode & S_IFMT) == S_IFREG,
        unlink(entry.path) == 0 || errno == ENOENT
      else { throw TacuaTransportQueueFileStoreError.stateConflict }
      removed = true
    }
    if removed { try syncDirectory() }
  }

  private func hardenDirectory(_ directory: URL) throws {
    try fileManager.setAttributes(
      [
        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        .posixPermissions: 0o700,
      ],
      ofItemAtPath: directory.path
    )
  }

  private func hardenFile(descriptor: Int32, at url: URL) throws {
    guard fchmod(descriptor, S_IRUSR | S_IWUSR) == 0 else {
      throw TacuaTransportQueueError.invalidQueue
    }
    try fileManager.setAttributes(
      [
        .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        .posixPermissions: 0o600,
      ],
      ofItemAtPath: url.path
    )
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
  }

  private func write(_ data: Data, descriptor: Int32) throws {
    try data.withUnsafeBytes { buffer in
      guard let base = buffer.baseAddress else {
        throw TacuaTransportQueueError.invalidQueue
      }
      var offset = 0
      while offset < data.count {
        let count = Darwin.write(
          descriptor,
          base.advanced(by: offset),
          data.count - offset
        )
        guard count > 0 else { throw POSIXError(.EIO) }
        offset += count
      }
    }
  }

  private func syncDirectory() throws {
    try syncDirectory(at: rootDirectory)
  }

  private func syncDirectory(at directory: URL) throws {
    let descriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
  }
}

private struct TacuaLockedQueuePersistence: TacuaTransportQueuePersisting {
  let persistSnapshot: (TacuaTransportQueueV3) throws -> Void

  func persist(_ queue: TacuaTransportQueueV3) throws {
    try persistSnapshot(queue)
  }
}

final class TacuaScopedPayloadRemover: TacuaLocalPayloadRemoving {
  private let sessionDirectory: URL
  private let directorySynchronizer: (Int32) -> Bool
  private let identityLock = NSLock()
  private var removedIdentities = Set<TacuaFileIdentity>()

  init(
    sessionDirectory: URL,
    fileManager: FileManager = .default,
    directorySynchronizer: @escaping (Int32) -> Bool = { fsync($0) == 0 }
  ) throws {
    guard sessionDirectory.isFileURL else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    self.sessionDirectory = sessionDirectory.standardizedFileURL
    self.directorySynchronizer = directorySynchronizer
    _ = fileManager
  }

  func removePayload(_ binding: TacuaLocalPayloadBinding) throws {
    let path = binding.relativePath
    guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("\0"),
      !path.contains("\\")
    else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
    let components = path.split(separator: "/", omittingEmptySubsequences: false)
      .map(String.init)
    guard !components.isEmpty,
      components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }

    let rootDescriptor = open(sessionDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard rootDescriptor >= 0 else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    var parentDescriptor = rootDescriptor
    defer {
      if parentDescriptor != rootDescriptor { close(parentDescriptor) }
      close(rootDescriptor)
    }
    for component in components.dropLast() {
      let childDescriptor = component.withCString {
        openat(parentDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
      }
      if childDescriptor < 0 {
        if errno == ENOENT {
          guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
          return
        }
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      if parentDescriptor != rootDescriptor { close(parentDescriptor) }
      parentDescriptor = childDescriptor
    }
    let leaf = components.last!
    let payloadDescriptor = leaf.withCString {
      openat(parentDescriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
    }
    if payloadDescriptor < 0 {
      if errno == ENOENT {
        guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
        return
      }
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    defer { close(payloadDescriptor) }
    var openedStat = stat()
    guard fstat(payloadDescriptor, &openedStat) == 0,
      (openedStat.st_mode & S_IFMT) == S_IFREG,
      openedStat.st_nlink == 1
    else { throw TacuaTransportQueueFileStoreError.payloadIsDirectory }
    let identity = TacuaFileIdentity(device: openedStat.st_dev, inode: openedStat.st_ino)
    identityLock.lock()
    let firstIdentityUse = removedIdentities.insert(identity).inserted
    identityLock.unlock()
    guard firstIdentityUse else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    let actualDigest = try digest(descriptor: payloadDescriptor)
    guard actualDigest == binding.contentDigest else {
      throw TacuaTransportQueueFileStoreError.payloadDigestMismatch
    }
    var pathStat = stat()
    let statResult = leaf.withCString {
      fstatat(parentDescriptor, $0, &pathStat, AT_SYMLINK_NOFOLLOW)
    }
    guard statResult == 0,
      pathStat.st_dev == openedStat.st_dev,
      pathStat.st_ino == openedStat.st_ino,
      pathStat.st_size == openedStat.st_size,
      pathStat.st_mtimespec.tv_sec == openedStat.st_mtimespec.tv_sec,
      pathStat.st_mtimespec.tv_nsec == openedStat.st_mtimespec.tv_nsec,
      pathStat.st_ctimespec.tv_sec == openedStat.st_ctimespec.tv_sec,
      pathStat.st_ctimespec.tv_nsec == openedStat.st_ctimespec.tv_nsec,
      (pathStat.st_mode & S_IFMT) == S_IFREG
    else { throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval }
    let unlinkResult = leaf.withCString { unlinkat(parentDescriptor, $0, 0) }
    guard unlinkResult == 0 else {
      if errno == ENOENT {
        guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
        return
      }
      throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
    }
    guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
  }

  func removeAbandonedUploadSnapshots() throws {
    let rootDescriptor = open(
      sessionDirectory.path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard rootDescriptor >= 0 else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    defer { close(rootDescriptor) }
    let stagingDescriptor = ".tacua-upload-staging".withCString {
      openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    if stagingDescriptor < 0 {
      if errno == ENOENT {
        guard directorySynchronizer(rootDescriptor) else { throw POSIXError(.EIO) }
        return
      }
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    var stagingDescriptorIsOpen = true
    defer {
      if stagingDescriptorIsOpen { close(stagingDescriptor) }
    }
    let duplicate = dup(stagingDescriptor)
    guard duplicate >= 0, let directory = fdopendir(duplicate) else {
      if duplicate >= 0 { close(duplicate) }
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    var directoryIsOpen = true
    defer {
      if directoryIsOpen { closedir(directory) }
    }
    var names: [String] = []
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
          String(cString: $0)
        }
      }
      if name == "." || name == ".." { continue }
      guard names.count < 128,
        name.range(
          of: "^upload-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\\.snapshot$",
          options: .regularExpression
        ) != nil
      else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
      var metadata = stat()
      let status = name.withCString {
        fstatat(stagingDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
      }
      guard status == 0, (metadata.st_mode & S_IFMT) == S_IFREG,
        metadata.st_nlink == 1,
        metadata.st_size >= 0,
        metadata.st_size <= TacuaSDKBackendProtocol.maximumUploadBytes
      else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
      names.append(name)
    }
    for name in names {
      let result = name.withCString { unlinkat(stagingDescriptor, $0, 0) }
      guard result == 0 || errno == ENOENT else {
        throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
      }
    }
    guard directorySynchronizer(stagingDescriptor) else { throw POSIXError(.EIO) }
    closedir(directory)
    directoryIsOpen = false
    close(stagingDescriptor)
    stagingDescriptorIsOpen = false
    let removal = ".tacua-upload-staging".withCString {
      unlinkat(rootDescriptor, $0, AT_REMOVEDIR)
    }
    guard removal == 0 || errno == ENOENT else {
      throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
    }
    guard directorySynchronizer(rootDescriptor) else { throw POSIXError(.EIO) }
  }

  private func digest(descriptor: Int32) throws -> String {
    guard lseek(descriptor, 0, SEEK_SET) >= 0 else { throw POSIXError(.EIO) }
    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: 256 * 1_024)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      guard count >= 0 else { throw POSIXError(.EIO) }
      if count == 0 { break }
      hasher.update(data: Data(buffer[0..<count]))
    }
    return "sha256:" + hasher.finalize().map { String(format: "%02x", $0) }.joined()
  }
}

/// Receipt-authorized, crash-recoverable retirement of one exact capture-session directory.
///
/// The live directory is first atomically renamed to a deterministic hidden name in its existing
/// parent and that parent is fsynced. Recursive removal then operates only through no-follow,
/// descriptor-relative syscalls. A crash before the final parent fsync is recovered by recognizing
/// and draining that one hidden name; an already absent live and hidden name is an idempotent
/// success only after the parent directory has been fsynced again.
final class TacuaScopedSessionRetirer: TacuaLocalSessionRetiring {
  private static let maximumDepth = 64
  private static let maximumEntries = 65_536
  private static let maximumRescansPerDirectory = 8

  private let parentDirectory: URL
  private let liveName: String
  private let retiringName: String
  private let directorySynchronizer: (Int32) -> Bool

  init(
    sessionDirectory: URL,
    directorySynchronizer: @escaping (Int32) -> Bool = { fsync($0) == 0 }
  ) throws {
    guard sessionDirectory.isFileURL else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    let standardized = sessionDirectory.standardizedFileURL
    let name = standardized.lastPathComponent
    guard name.range(of: "^[a-z][a-z0-9_-]{2,63}$", options: .regularExpression) != nil,
      standardized.deletingLastPathComponent() != standardized
    else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
    // Resolve only the configured capture root, never the session leaf. The canonicalized root is
    // subsequently reopened component-by-component with O_NOFOLLOW so a raced ancestor fails
    // closed instead of redirecting retirement.
    parentDirectory = try Self.canonicalExistingDirectory(
      standardized.deletingLastPathComponent()
    )
    liveName = name
    retiringName = ".tacua-retiring-\(name)"
    self.directorySynchronizer = directorySynchronizer
  }

  func retireSession() throws {
    let parentDescriptor = try Self.openAbsoluteDirectoryNoFollow(parentDirectory)
    defer { close(parentDescriptor) }

    for _ in 0..<4 {
      let live = try metadata(name: liveName, parentDescriptor: parentDescriptor)
      let retiring = try metadata(name: retiringName, parentDescriptor: parentDescriptor)
      guard live == nil || retiring == nil else {
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }

      if let live {
        guard (live.st_mode & S_IFMT) == S_IFDIR else {
          throw TacuaTransportQueueFileStoreError.unsafePayloadPath
        }
        let result = liveName.withCString { livePointer in
          retiringName.withCString { retiringPointer in
            renameat(parentDescriptor, livePointer, parentDescriptor, retiringPointer)
          }
        }
        if result != 0 {
          if errno == ENOENT || errno == EEXIST { continue }
          throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
        }
        guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
        continue
      }

      guard let retiring else {
        guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
        return
      }
      guard (retiring.st_mode & S_IFMT) == S_IFDIR else {
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      let descriptor = retiringName.withCString {
        openat(parentDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      }
      guard descriptor >= 0 else {
        if errno == ENOENT { continue }
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      var opened = stat()
      guard fstat(descriptor, &opened) == 0,
        opened.st_dev == retiring.st_dev,
        opened.st_ino == retiring.st_ino,
        (opened.st_mode & S_IFMT) == S_IFDIR
      else {
        close(descriptor)
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      var remainingEntries = Self.maximumEntries
      do {
        try drainDirectory(
          descriptor,
          rootDevice: opened.st_dev,
          depth: 0,
          remainingEntries: &remainingEntries
        )
      } catch {
        close(descriptor)
        throw error
      }
      close(descriptor)
      let removal = retiringName.withCString {
        unlinkat(parentDescriptor, $0, AT_REMOVEDIR)
      }
      if removal != 0 {
        if errno == ENOENT || errno == ENOTEMPTY { continue }
        throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
      }
      guard directorySynchronizer(parentDescriptor) else { throw POSIXError(.EIO) }
      return
    }
    throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
  }

  private func drainDirectory(
    _ descriptor: Int32,
    rootDevice: dev_t,
    depth: Int,
    remainingEntries: inout Int
  ) throws {
    guard depth <= Self.maximumDepth else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    for _ in 0..<Self.maximumRescansPerDirectory {
      let names = try entryNames(descriptor)
      if names.isEmpty {
        guard directorySynchronizer(descriptor) else { throw POSIXError(.EIO) }
        return
      }
      for name in names {
        guard remainingEntries > 0 else {
          throw TacuaTransportQueueFileStoreError.unsafePayloadPath
        }
        remainingEntries -= 1
        guard let child = try metadata(name: name, parentDescriptor: descriptor) else { continue }
        if (child.st_mode & S_IFMT) == S_IFDIR {
          guard child.st_dev == rootDevice else {
            throw TacuaTransportQueueFileStoreError.unsafePayloadPath
          }
          let childDescriptor = name.withCString {
            openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
          }
          guard childDescriptor >= 0 else {
            if errno == ENOENT { continue }
            throw TacuaTransportQueueFileStoreError.unsafePayloadPath
          }
          var opened = stat()
          guard fstat(childDescriptor, &opened) == 0,
            opened.st_dev == child.st_dev,
            opened.st_ino == child.st_ino,
            (opened.st_mode & S_IFMT) == S_IFDIR
          else {
            close(childDescriptor)
            throw TacuaTransportQueueFileStoreError.unsafePayloadPath
          }
          do {
            try drainDirectory(
              childDescriptor,
              rootDevice: rootDevice,
              depth: depth + 1,
              remainingEntries: &remainingEntries
            )
          } catch {
            close(childDescriptor)
            throw error
          }
          close(childDescriptor)
          let result = name.withCString { unlinkat(descriptor, $0, AT_REMOVEDIR) }
          if result != 0, errno != ENOENT, errno != ENOTEMPTY {
            throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
          }
        } else {
          // unlinkat without AT_REMOVEDIR removes a symlink or other leaf itself; it never follows
          // that leaf to an out-of-scope target. A raced replacement with a directory fails closed.
          let result = name.withCString { unlinkat(descriptor, $0, 0) }
          if result != 0, errno != ENOENT {
            throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
          }
        }
      }
      guard directorySynchronizer(descriptor) else { throw POSIXError(.EIO) }
    }
    throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
  }

  private func entryNames(_ descriptor: Int32) throws -> [String] {
    guard lseek(descriptor, 0, SEEK_SET) >= 0 else { throw POSIXError(.EIO) }
    let duplicate = dup(descriptor)
    guard duplicate >= 0, let directory = fdopendir(duplicate) else {
      if duplicate >= 0 { close(duplicate) }
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    defer { closedir(directory) }
    var names: [String] = []
    while let entry = readdir(directory) {
      let name = withUnsafePointer(to: &entry.pointee.d_name) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
          String(cString: $0)
        }
      }
      if name == "." || name == ".." { continue }
      guard !name.isEmpty, !name.contains("/"), names.count < Self.maximumEntries else {
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      names.append(name)
    }
    return names
  }

  private func metadata(name: String, parentDescriptor: Int32) throws -> stat? {
    var value = stat()
    let result = name.withCString {
      fstatat(parentDescriptor, $0, &value, AT_SYMLINK_NOFOLLOW)
    }
    if result == 0 { return value }
    if errno == ENOENT { return nil }
    throw TacuaTransportQueueFileStoreError.unsafePayloadPath
  }

  private static func openAbsoluteDirectoryNoFollow(_ directory: URL) throws -> Int32 {
    let plan = try directoryTraversalPlan(for: directory)
    var descriptor = plan.anchorPath.withCString {
      open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
    for component in plan.relativeComponents {
      let child = component.withCString {
        openat(descriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      }
      if child < 0 {
        close(descriptor)
        throw TacuaTransportQueueFileStoreError.unsafePayloadPath
      }
      close(descriptor)
      descriptor = child
    }
    return descriptor
  }

  static func directoryTraversalPlan(
    for directory: URL,
    homeDirectory: URL = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
  ) throws -> (anchorPath: String, relativeComponents: [String]) {
    guard directory.isFileURL, directory.path.hasPrefix("/") else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    let directoryComponents = directory.path.split(separator: "/").map(String.init)
    guard directoryComponents.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }

    if let canonicalHome = try? canonicalExistingDirectory(homeDirectory.standardizedFileURL) {
      let homeComponents = canonicalHome.path.split(separator: "/").map(String.init)
      if directoryComponents.starts(with: homeComponents) {
        let relativeComponents = Array(directoryComponents.dropFirst(homeComponents.count))
        guard relativeComponents.allSatisfy({
          !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("/")
        }) else {
          throw TacuaTransportQueueFileStoreError.unsafePayloadPath
        }
        // iOS may deny opening global `/`, while permitting direct access to the app container.
        // Platform-owned ancestors are trusted here; every mutable descendant is still reopened
        // component-by-component with O_NOFOLLOW.
        return (canonicalHome.path, relativeComponents)
      }
    }

    return ("/", directoryComponents)
  }

  private static func canonicalExistingDirectory(_ directory: URL) throws -> URL {
    let resolved: String? = directory.path.withCString { path in
      var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
      guard realpath(path, &buffer) != nil else { return nil }
      return String(cString: buffer)
    }
    guard let resolved else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    return URL(fileURLWithPath: resolved, isDirectory: true)
  }
}

private struct TacuaFileIdentity: Hashable {
  let device: dev_t
  let inode: ino_t
}
