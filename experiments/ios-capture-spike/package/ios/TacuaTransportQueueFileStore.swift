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
      if queue.credentialCleanupState == .tombstoneWritten {
        try TacuaTransportCleanup.removeAuthorizedCredential(
          queue: &queue, persistence: persistence, credentialStore: credentialStore
        )
      }
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
  private let identityLock = NSLock()
  private var removedIdentities = Set<TacuaFileIdentity>()

  init(sessionDirectory: URL, fileManager: FileManager = .default) throws {
    guard sessionDirectory.isFileURL else {
      throw TacuaTransportQueueFileStoreError.unsafePayloadPath
    }
    self.sessionDirectory = sessionDirectory.standardizedFileURL
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
        if errno == ENOENT { return }
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
      if errno == ENOENT { return }
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
      if errno == ENOENT { return }
      throw TacuaTransportQueueFileStoreError.payloadChangedDuringRemoval
    }
    guard fsync(parentDescriptor) == 0 else { throw POSIXError(.EIO) }
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

private struct TacuaFileIdentity: Hashable {
  let device: dev_t
  let inode: ino_t
}
