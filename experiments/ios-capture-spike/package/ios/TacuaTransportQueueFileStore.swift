// SPDX-License-Identifier: Apache-2.0

import Darwin
import CryptoKit
import Foundation

enum TacuaTransportQueueFileStoreError: Error, Equatable {
  case invalidSessionID
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

  func load(localSessionID: String) throws -> TacuaTransportQueueV2? {
    let url = try queueURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
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
      metadata.st_size <= TacuaTransportQueueV2.maximumEncodedBytes
    else { throw TacuaTransportQueueError.invalidQueue }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
    let original = try handle.readToEnd() ?? Data()
    guard original.count == metadata.st_size else {
      throw TacuaTransportQueueError.invalidQueue
    }
    let queue = try TacuaTransportQueueV2.decodeOrMigrate(original)
    let migrated = try queue.encoded()
    if migrated != original { try persistLocked(migrated, to: url) }
    return queue
  }

  func persist(_ queue: TacuaTransportQueueV2) throws {
    let url = try queueURL(localSessionID: queue.localSessionID)
    let data = try queue.encoded()
    lock.lock()
    defer { lock.unlock() }
    try persistLocked(data, to: url)
  }

  func remove(localSessionID: String) throws {
    let url = try queueURL(localSessionID: localSessionID)
    lock.lock()
    defer { lock.unlock() }
    if fileManager.fileExists(atPath: url.path) {
      try fileManager.removeItem(at: url)
      try syncDirectory()
    }
  }

  /// Runs the idempotent Keychain cleanup journal on app startup. Queue state is persisted before
  /// and after each destructive mutation, so a crash simply replays the same sweep.
  func recoverCredentialCleanup(
    localSessionID: String,
    credentialStore: TacuaCredentialStoring
  ) throws -> TacuaTransportQueueV2? {
    guard var queue = try load(localSessionID: localSessionID) else { return nil }
    try TacuaTransportCleanup.removePendingRevokedCredentials(
      queue: &queue, persistence: self, credentialStore: credentialStore
    )
    if queue.credentialCleanupState == .tombstoneWritten {
      try TacuaTransportCleanup.removeAuthorizedCredential(
        queue: &queue, persistence: self, credentialStore: credentialStore
      )
    }
    return queue
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
    try fileManager.createDirectory(
      at: rootDirectory,
      withIntermediateDirectories: true,
      attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
    )
    var metadata = stat()
    guard lstat(rootDirectory.path, &metadata) == 0,
      (metadata.st_mode & S_IFMT) == S_IFDIR
    else { throw TacuaTransportQueueFileStoreError.unsafePayloadPath }
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var directory = rootDirectory
    try directory.setResourceValues(values)
  }

  private func persistLocked(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: [.atomic])
    try fileManager.setAttributes(
      [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
      ofItemAtPath: url.path
    )
    let handle = try FileHandle(forWritingTo: url)
    try handle.synchronize()
    try handle.close()
    try syncDirectory()
  }

  private func syncDirectory() throws {
    let descriptor = open(rootDirectory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard descriptor >= 0 else { throw POSIXError(.EIO) }
    defer { close(descriptor) }
    guard fsync(descriptor) == 0 else { throw POSIXError(.EIO) }
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
