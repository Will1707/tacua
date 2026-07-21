// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Darwin
import Foundation

enum TacuaSDKBackendClientError: Error, Equatable {
  case invalidRequest
  case invalidResponse
  case responseTooLarge
  case unexpectedStatus(Int)
  case unexpectedContentType
  case localPayloadMissing
  case localPayloadMismatch
  case unsafeLocalPayload
  case localPayloadTooLarge
  case transportFailure
}

protocol TacuaBoundedHTTPTransporting {
  func data(for request: URLRequest, uploadFile: URL?) async throws
    -> (Data, HTTPURLResponse)
}

final class TacuaBoundedURLSessionTransport: NSObject, TacuaBoundedHTTPTransporting,
  URLSessionDataDelegate, URLSessionTaskDelegate
{
  private final class TaskState {
    var data = Data()
    var response: HTTPURLResponse?
    var terminalError: Error?
    let continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>

    init(continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>) {
      self.continuation = continuation
    }
  }

  private let maximumResponseBytes: Int
  private let sessionConfiguration: URLSessionConfiguration
  private let stateLock = NSLock()
  private var states: [Int: TaskState] = [:]
  private lazy var session = URLSession(
    configuration: sessionConfiguration,
    delegate: self,
    delegateQueue: nil
  )

  init(
    configuration: URLSessionConfiguration = TacuaBoundedURLSessionTransport.secureConfiguration(),
    maximumResponseBytes: Int = TacuaSDKBackendProtocol.maximumResponseBytes
  ) {
    self.sessionConfiguration = configuration
    self.maximumResponseBytes = maximumResponseBytes
    super.init()
  }

  static func secureConfiguration() -> URLSessionConfiguration {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.urlCache = nil
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.httpCookieAcceptPolicy = .never
    configuration.timeoutIntervalForRequest = 60
    configuration.timeoutIntervalForResource = 30 * 60
    return configuration
  }

  func data(for request: URLRequest, uploadFile: URL? = nil) async throws
    -> (Data, HTTPURLResponse)
  {
    try await withCheckedThrowingContinuation { continuation in
      let task: URLSessionTask
      if let uploadFile {
        task = session.uploadTask(with: request, fromFile: uploadFile)
      } else {
        task = session.dataTask(with: request)
      }
      stateLock.lock()
      states[task.taskIdentifier] = TaskState(continuation: continuation)
      stateLock.unlock()
      task.resume()
    }
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    stateLock.lock()
    guard let state = states[dataTask.taskIdentifier] else {
      stateLock.unlock()
      completionHandler(.cancel)
      return
    }
    guard let response = response as? HTTPURLResponse else {
      state.terminalError = TacuaSDKBackendClientError.invalidResponse
      stateLock.unlock()
      completionHandler(.cancel)
      return
    }
    state.response = response
    if response.expectedContentLength > Int64(maximumResponseBytes) {
      state.terminalError = TacuaSDKBackendClientError.responseTooLarge
      stateLock.unlock()
      completionHandler(.cancel)
      return
    }
    stateLock.unlock()
    completionHandler(.allow)
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive data: Data
  ) {
    stateLock.lock()
    guard let state = states[dataTask.taskIdentifier], state.terminalError == nil else {
      stateLock.unlock()
      return
    }
    guard state.data.count <= maximumResponseBytes - data.count else {
      state.terminalError = TacuaSDKBackendClientError.responseTooLarge
      stateLock.unlock()
      dataTask.cancel()
      return
    }
    state.data.append(data)
    stateLock.unlock()
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    stateLock.lock()
    let state = states.removeValue(forKey: task.taskIdentifier)
    stateLock.unlock()
    guard let state else { return }
    if let terminalError = state.terminalError {
      state.continuation.resume(throwing: terminalError)
    } else if let error {
      state.continuation.resume(throwing: error)
    } else if let response = state.response {
      state.continuation.resume(returning: (state.data, response))
    } else {
      state.continuation.resume(throwing: TacuaSDKBackendClientError.invalidResponse)
    }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    willCacheResponse proposedResponse: CachedURLResponse,
    completionHandler: @escaping (CachedURLResponse?) -> Void
  ) {
    completionHandler(nil)
  }
}

final class TacuaSDKBackendClient {
  private let configuration: TacuaBackendConfiguration
  private let credentialStore: TacuaCredentialStoring
  private let transport: TacuaBoundedHTTPTransporting

  init(
    configuration: TacuaBackendConfiguration,
    credentialStore: TacuaCredentialStoring = TacuaKeychainCredentialStore(),
    transport: TacuaBoundedHTTPTransporting? = nil
  ) {
    self.configuration = configuration
    self.credentialStore = credentialStore
    self.transport = transport ?? TacuaBoundedURLSessionTransport()
  }

  func exchange(_ request: TacuaTransientLaunchRequest) async throws
    -> TacuaValidatedBackendReceipt
  {
    _ = try TacuaSDKBackendProtocol.validateRequest(
      request.canonicalData,
      expectedTransportConfigurationDigest: configuration.configurationDigest
    )
    var urlRequest = try makeRequest(
      method: "POST",
      route: ["v1", "sdk", "launch-exchanges"],
      canonicalJSON: request.canonicalData,
      idempotencyKey: request.exchangeID,
      transportCredentialID: nil
    )
    // Launch codes and new secrets exist only in this transient request body.
    urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
    return try await execute(urlRequest, requestData: request.canonicalData, uploadFile: nil)
  }

  func send(
    _ request: TacuaPreparedBackendRequest,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    guard request.kind != .segment else { throw TacuaSDKBackendClientError.invalidRequest }
    let validatedKind = try TacuaSDKBackendProtocol.validateRequest(request.canonicalData)
    guard validatedKind.rawValue == request.kind.rawValue else {
      throw TacuaSDKBackendClientError.invalidRequest
    }
    let root = try requestObject(request.canonicalData)
    let sessionID = try requiredString(root, "session_id")
    let route: [String]
    switch request.kind {
    case .diagnostic:
      route = ["v1", "sdk", "sessions", sessionID, "diagnostics", request.operationID]
    case .completion:
      route = ["v1", "sdk", "sessions", sessionID, "completions", request.operationID]
    case .deletion:
      route = ["v1", "sdk", "sessions", sessionID, "deletions", request.operationID]
    case .segment:
      throw TacuaSDKBackendClientError.invalidRequest
    }
    let urlRequest = try makeRequest(
      method: "PUT",
      route: route,
      canonicalJSON: request.canonicalData,
      idempotencyKey: request.operationID,
      transportCredentialID: transportCredentialID
    )
    return try await execute(urlRequest, requestData: request.canonicalData, uploadFile: nil)
  }

  func uploadSegment(
    _ request: TacuaPreparedBackendRequest,
    fileURL: URL,
    sessionDirectory: URL,
    transportCredentialID: String
  ) async throws -> TacuaValidatedBackendReceipt {
    guard request.kind == .segment else { throw TacuaSDKBackendClientError.invalidRequest }
    guard try TacuaSDKBackendProtocol.validateRequest(request.canonicalData) == .segment else {
      throw TacuaSDKBackendClientError.invalidRequest
    }
    let intent = try requestObject(request.canonicalData)
    let transportObject = try requiredObject(intent, "transport")
    let expectedSize = try requiredInteger(transportObject, "size_bytes")
    let expectedDigest = try requiredString(transportObject, "content_digest")
    let uploadSnapshot = try prepareUploadSnapshot(
      sourceURL: fileURL,
      sessionDirectory: sessionDirectory,
      expectedSize: expectedSize,
      expectedDigest: expectedDigest
    )
    defer { try? FileManager.default.removeItem(at: uploadSnapshot) }
    let sessionID = try requiredString(intent, "session_id")
    let segmentID = try requiredString(intent, "segment_id")
    let sequence = try requiredInteger(intent, "sequence")
    let route = [
      "v1", "sdk", "sessions", sessionID, "segments", String(sequence), segmentID,
    ]
    var urlRequest = URLRequest(url: try configuration.endpoint(pathSegments: route))
    urlRequest.httpMethod = "PUT"
    try applyAuthorization(to: &urlRequest, credentialID: transportCredentialID)
    urlRequest.setValue(TacuaSDKBackendProtocol.version, forHTTPHeaderField: "Tacua-Protocol-Version")
    urlRequest.setValue(try requiredString(intent, "upload_id"), forHTTPHeaderField: "Idempotency-Key")
    urlRequest.setValue(try requiredString(intent, "scope_digest"), forHTTPHeaderField: "Tacua-Scope-Digest")
    // This header is immutable request truth and may differ from Authorization after rotation.
    urlRequest.setValue(try requiredString(intent, "credential_id"), forHTTPHeaderField: "Tacua-Credential-ID")
    urlRequest.setValue(try requiredString(intent, "sidecar_digest"), forHTTPHeaderField: "Tacua-Sidecar-Digest")
    urlRequest.setValue(try requiredString(intent, "intent_digest"), forHTTPHeaderField: "Tacua-Intent-Digest")
    urlRequest.setValue(try requiredString(intent, "requested_at"), forHTTPHeaderField: "Tacua-Requested-At")
    urlRequest.setValue(try requiredString(transportObject, "content_type"), forHTTPHeaderField: "Content-Type")
    urlRequest.setValue(String(expectedSize), forHTTPHeaderField: "Content-Length")
    urlRequest.setValue(expectedDigest, forHTTPHeaderField: "Tacua-Content-Digest")
    urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
    urlRequest.setValue("no-store", forHTTPHeaderField: "Cache-Control")
    return try await execute(
      urlRequest,
      requestData: request.canonicalData,
      uploadFile: uploadSnapshot
    )
  }

  private func makeRequest(
    method: String,
    route: [String],
    canonicalJSON: Data,
    idempotencyKey: String,
    transportCredentialID: String?
  ) throws -> URLRequest {
    var request = URLRequest(url: try configuration.endpoint(pathSegments: route))
    request.httpMethod = method
    request.httpBody = canonicalJSON
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.setValue(TacuaSDKBackendProtocol.version, forHTTPHeaderField: "Tacua-Protocol-Version")
    request.setValue(idempotencyKey, forHTTPHeaderField: "Idempotency-Key")
    request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
    if let transportCredentialID {
      try applyAuthorization(to: &request, credentialID: transportCredentialID)
    }
    return request
  }

  private func applyAuthorization(to request: inout URLRequest, credentialID: String) throws {
    let secret = try credentialStore.read(credentialID: credentialID)
    guard secret.count == TacuaKeychainCredentialStore.secretLength else {
      throw TacuaCredentialStoreError.invalidSecretLength
    }
    request.setValue("Bearer \(base64URL(secret))", forHTTPHeaderField: "Authorization")
  }

  private func execute(
    _ request: URLRequest,
    requestData: Data,
    uploadFile: URL?
  ) async throws -> TacuaValidatedBackendReceipt {
    let (data, response) = try await transport.data(for: request, uploadFile: uploadFile)
    guard response.statusCode == 200 || response.statusCode == 201 else {
      throw TacuaSDKBackendClientError.unexpectedStatus(response.statusCode)
    }
    guard Self.isJSON(response.value(forHTTPHeaderField: "Content-Type")) else {
      throw TacuaSDKBackendClientError.unexpectedContentType
    }
    return try TacuaSDKBackendProtocol.validateResponse(data, forCanonicalRequest: requestData)
  }

  private func requestObject(_ data: Data) throws -> [String: TacuaJSONValue] {
    guard case .object(let object) = try TacuaCanonicalJSON.parse(data),
      try TacuaCanonicalJSON.data(.object(object)) == data
    else { throw TacuaSDKBackendClientError.invalidRequest }
    return object
  }

  private func requiredObject(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> [String: TacuaJSONValue] {
    guard case .object(let value)? = object[field] else {
      throw TacuaSDKBackendClientError.invalidRequest
    }
    return value
  }

  private func requiredString(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> String {
    guard case .string(let value)? = object[field] else {
      throw TacuaSDKBackendClientError.invalidRequest
    }
    return value
  }

  private func requiredInteger(
    _ object: [String: TacuaJSONValue], _ field: String
  ) throws -> Int64 {
    guard case .integer(let value)? = object[field] else {
      throw TacuaSDKBackendClientError.invalidRequest
    }
    return value
  }

  private func prepareUploadSnapshot(
    sourceURL: URL,
    sessionDirectory: URL,
    expectedSize: Int64,
    expectedDigest: String
  ) throws -> URL {
    guard sourceURL.isFileURL, sessionDirectory.isFileURL,
      expectedSize > 0, expectedSize <= TacuaSDKBackendProtocol.maximumUploadBytes
    else { throw TacuaSDKBackendClientError.unsafeLocalPayload }
    let root = sessionDirectory.standardizedFileURL
    let source = sourceURL.standardizedFileURL
    let rootPrefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
    guard source.path.hasPrefix(rootPrefix) else {
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    let relative = String(source.path.dropFirst(rootPrefix.count))
    let components = relative.split(separator: "/", omittingEmptySubsequences: false)
      .map(String.init)
    guard !components.isEmpty,
      components.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." })
    else { throw TacuaSDKBackendClientError.unsafeLocalPayload }

    let rootDescriptor = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    guard rootDescriptor >= 0 else { throw TacuaSDKBackendClientError.unsafeLocalPayload }
    defer { close(rootDescriptor) }
    var parentDescriptor = rootDescriptor
    defer { if parentDescriptor != rootDescriptor { close(parentDescriptor) } }
    for component in components.dropLast() {
      let child = component.withCString {
        openat(parentDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
      }
      guard child >= 0 else { throw TacuaSDKBackendClientError.unsafeLocalPayload }
      if parentDescriptor != rootDescriptor { close(parentDescriptor) }
      parentDescriptor = child
    }
    let sourceDescriptor = components.last!.withCString {
      openat(parentDescriptor, $0, O_RDONLY | O_NONBLOCK | O_NOFOLLOW)
    }
    guard sourceDescriptor >= 0 else {
      if errno == ENOENT { throw TacuaSDKBackendClientError.localPayloadMissing }
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    defer { close(sourceDescriptor) }
    var initialStat = stat()
    guard fstat(sourceDescriptor, &initialStat) == 0,
      (initialStat.st_mode & S_IFMT) == S_IFREG,
      initialStat.st_nlink == 1
    else { throw TacuaSDKBackendClientError.unsafeLocalPayload }
    guard initialStat.st_size <= TacuaSDKBackendProtocol.maximumUploadBytes else {
      throw TacuaSDKBackendClientError.localPayloadTooLarge
    }
    guard initialStat.st_size == expectedSize else {
      throw TacuaSDKBackendClientError.localPayloadMismatch
    }

    let stagingName = ".tacua-upload-staging"
    let mkdirResult = stagingName.withCString { mkdirat(rootDescriptor, $0, 0o700) }
    guard mkdirResult == 0 || errno == EEXIST else {
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    let stagingDescriptor = stagingName.withCString {
      openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
    }
    guard stagingDescriptor >= 0 else {
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    defer { close(stagingDescriptor) }
    guard fchmod(stagingDescriptor, 0o700) == 0 else {
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    let fileName = "upload-\(UUID().uuidString.lowercased()).snapshot"
    let outputDescriptor = fileName.withCString {
      openat(stagingDescriptor, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    }
    guard outputDescriptor >= 0 else {
      throw TacuaSDKBackendClientError.unsafeLocalPayload
    }
    let stagingURL = root.appendingPathComponent(stagingName, isDirectory: true)
      .appendingPathComponent(fileName)
    var keepSnapshot = false
    defer {
      close(outputDescriptor)
      if !keepSnapshot { _ = fileName.withCString { unlinkat(stagingDescriptor, $0, 0) } }
    }

    guard lseek(sourceDescriptor, 0, SEEK_SET) >= 0 else {
      throw TacuaSDKBackendClientError.localPayloadMismatch
    }
    var hasher = SHA256()
    var total: Int64 = 0
    var buffer = [UInt8](repeating: 0, count: 256 * 1_024)
    while total < expectedSize {
      let limit = min(buffer.count, Int(expectedSize - total))
      let count = Darwin.read(sourceDescriptor, &buffer, limit)
      guard count > 0 else { throw TacuaSDKBackendClientError.localPayloadMismatch }
      total += Int64(count)
      guard total <= TacuaSDKBackendProtocol.maximumUploadBytes else {
        throw TacuaSDKBackendClientError.localPayloadTooLarge
      }
      hasher.update(data: Data(buffer[0..<count]))
      try writeAll(descriptor: outputDescriptor, bytes: buffer, count: count)
    }
    let extraCount = Darwin.read(sourceDescriptor, &buffer, 1)
    guard extraCount == 0 else { throw TacuaSDKBackendClientError.localPayloadMismatch }
    var finalStat = stat()
    guard fstat(sourceDescriptor, &finalStat) == 0,
      finalStat.st_dev == initialStat.st_dev,
      finalStat.st_ino == initialStat.st_ino,
      finalStat.st_size == initialStat.st_size,
      finalStat.st_mtimespec.tv_sec == initialStat.st_mtimespec.tv_sec,
      finalStat.st_mtimespec.tv_nsec == initialStat.st_mtimespec.tv_nsec,
      finalStat.st_ctimespec.tv_sec == initialStat.st_ctimespec.tv_sec,
      finalStat.st_ctimespec.tv_nsec == initialStat.st_ctimespec.tv_nsec
    else { throw TacuaSDKBackendClientError.localPayloadMismatch }
    let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
    guard "sha256:\(digest)" == expectedDigest else {
      throw TacuaSDKBackendClientError.localPayloadMismatch
    }
    guard fsync(outputDescriptor) == 0, fchmod(outputDescriptor, 0o400) == 0,
      fsync(stagingDescriptor) == 0
    else { throw TacuaSDKBackendClientError.transportFailure }
    try FileManager.default.setAttributes(
      [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
      ofItemAtPath: stagingURL.path
    )
    var values = URLResourceValues()
    values.isExcludedFromBackup = true
    var stagingDirectoryURL = stagingURL.deletingLastPathComponent()
    try? stagingDirectoryURL.setResourceValues(values)
    keepSnapshot = true
    return stagingURL
  }

  private func writeAll(descriptor: Int32, bytes: [UInt8], count: Int) throws {
    var written = 0
    while written < count {
      let result = bytes.withUnsafeBytes { rawBuffer -> Int in
        guard let base = rawBuffer.baseAddress else { return -1 }
        return Darwin.write(descriptor, base.advanced(by: written), count - written)
      }
      guard result > 0 else { throw TacuaSDKBackendClientError.transportFailure }
      written += result
    }
  }

  private static func isJSON(_ contentType: String?) -> Bool {
    guard let contentType else { return false }
    let mediaType = contentType.split(separator: ";", maxSplits: 1)[0]
      .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    return mediaType == "application/json"
      || (mediaType.hasPrefix("application/vnd.tacua.") && mediaType.hasSuffix("+json"))
  }

  private func base64URL(_ value: Data) -> String {
    value.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
}
