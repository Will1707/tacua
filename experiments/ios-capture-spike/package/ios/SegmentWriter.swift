// SPDX-License-Identifier: Apache-2.0

import AVFoundation
import CoreMedia
import CryptoKit
import Foundation
import ReplayKit

enum TacuaSegmentAppendResult: Equatable {
  case appended
  /// The sample was rejected and its stream-specific dropped count was updated exactly once.
  case recordedDrop
  /// The writer could not bind this rejection to durable accounting; callers must fail closed.
  case fatalUnaccounted

  var wasAppended: Bool { self == .appended }
}

final class SegmentWriter {
  private typealias FinishCompletion = (Result<CaptureSegment, Error>) -> Void

  private enum FinishState {
    case notStarted
    case awaitingWriterCallback
    case committing
    case terminal
  }

  private enum WriterCallbackDecision {
    case commit
    case timeout(FinishCompletion)
    case ignore
  }

  let index: Int
  let startedAtPTS: CMTime

  private let partialURL: URL
  private let finalURL: URL
  private let sidecarURL: URL
  private let stagedSidecarURL: URL
  private let writer: AVAssetWriter
  private let videoInput: AVAssetWriterInput
  private let appAudioInput: AVAssetWriterInput
  private let microphoneInput: AVAssetWriterInput
  private let firstHostUptimeSeconds: Double
  private let videoDimensions: CMVideoDimensions
  private let appAudioAppendAttemptStartIndex: Int
  private let maximumTrackedAppAudioDrops: Int

  private var lastPTS: CMTime
  private var lastHostUptimeSeconds: Double
  private var lastVideoPTS: CMTime
  private var lastVideoSample: CMSampleBuffer?
  private var videoSamples = 0
  private var heldVideoSamples = 0
  private var appAudioSamples = 0
  private var microphoneSamples = 0
  private var droppedVideoSamples = 0
  private var droppedAppAudioSamples = 0
  private var droppedMicrophoneSamples = 0
  private var appAudioAppendAttempts = 0
  private var appAudioAppendDrops: [TacuaAppAudioAppendDrop] = []
  private var finished = false
  private(set) var fatalError: Error?
  private let finishLock = NSLock()
  private var finishState = FinishState.notStarted
  private var finishDeadlineUptimeSeconds: Double?
  private var finishCompletion: FinishCompletion?
  private var finishWatchdog: DispatchWorkItem?
#if TACUA_CAPTURE_FAULT_INJECTION
  private var injectedFinishBehavior = TacuaCaptureInjectedFinishBehavior.none
#endif

  init(
    index: Int,
    directory: URL,
    firstVideoSample: CMSampleBuffer,
    hostUptimeSeconds: Double,
    appAudioAppendAttemptStartIndex: Int,
    maximumTrackedAppAudioDrops: Int
  ) throws {
    guard let formatDescription = CMSampleBufferGetFormatDescription(firstVideoSample) else {
      throw TacuaCaptureSpikeError.writerCreation("The first video sample has no format description.")
    }

    let dimensions = CMVideoFormatDescriptionGetDimensions(formatDescription)
    guard dimensions.width > 0, dimensions.height > 0 else {
      throw TacuaCaptureSpikeError.writerCreation("The first video sample has invalid dimensions.")
    }

    self.index = index
    self.startedAtPTS = CMSampleBufferGetPresentationTimeStamp(firstVideoSample)
    self.lastPTS = startedAtPTS
    self.lastVideoPTS = startedAtPTS
    self.firstHostUptimeSeconds = hostUptimeSeconds
    self.lastHostUptimeSeconds = hostUptimeSeconds
    self.videoDimensions = dimensions
    self.appAudioAppendAttemptStartIndex = appAudioAppendAttemptStartIndex
    self.maximumTrackedAppAudioDrops = maximumTrackedAppAudioDrops

    let stem = String(format: "segment-%06d", index)
    partialURL = directory.appendingPathComponent("\(stem).partial.mov")
    finalURL = directory.appendingPathComponent("\(stem).mov")
    sidecarURL = finalURL
      .deletingPathExtension()
      .appendingPathExtension("segment.json")
    stagedSidecarURL = directory.appendingPathComponent("\(stem).segment.json.partial")

    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: partialURL.path) {
      try fileManager.removeItem(at: partialURL)
    }
    if fileManager.fileExists(atPath: finalURL.path) {
      throw TacuaCaptureSpikeError.writerCreation("A finalized segment already exists at index \(index).")
    }
    if fileManager.fileExists(atPath: sidecarURL.path) {
      throw TacuaCaptureSpikeError.writerCreation("A finalized segment sidecar already exists at index \(index).")
    }
    if fileManager.fileExists(atPath: stagedSidecarURL.path) {
      try fileManager.removeItem(at: stagedSidecarURL)
    }

    writer = try AVAssetWriter(outputURL: partialURL, fileType: .mov)

    let compression: [String: Any] = [
      AVVideoAverageBitRateKey: 4_000_000,
      AVVideoExpectedSourceFrameRateKey: 30,
      AVVideoMaxKeyFrameIntervalKey: 30,
      AVVideoAllowFrameReorderingKey: false,
    ]
    let videoSettings: [String: Any] = [
      AVVideoCodecKey: AVVideoCodecType.h264,
      AVVideoWidthKey: Int(dimensions.width),
      AVVideoHeightKey: Int(dimensions.height),
      AVVideoCompressionPropertiesKey: compression,
    ]
    videoInput = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
    videoInput.expectsMediaDataInRealTime = true

    appAudioInput = SegmentWriter.makeAudioInput(channelCount: 2, bitRate: 128_000)
    microphoneInput = SegmentWriter.makeAudioInput(channelCount: 1, bitRate: 64_000)

    guard writer.canAdd(videoInput) else {
      throw TacuaCaptureSpikeError.writerCreation("AVAssetWriter rejected the ReplayKit video track.")
    }
    writer.add(videoInput)

    guard writer.canAdd(appAudioInput) else {
      throw TacuaCaptureSpikeError.writerCreation("AVAssetWriter rejected the ReplayKit app-audio track.")
    }
    writer.add(appAudioInput)

    guard writer.canAdd(microphoneInput) else {
      throw TacuaCaptureSpikeError.writerCreation("AVAssetWriter rejected the ReplayKit microphone track.")
    }
    writer.add(microphoneInput)

    guard writer.startWriting() else {
      let code = writer.error?.tacuaStableCode ?? "unknown"
      throw TacuaCaptureSpikeError.writerCreation("AVAssetWriter could not start (\(code)).")
    }
    writer.startSession(atSourceTime: startedAtPTS)
  }

  var durationSeconds: Double {
    max(0, CMTimeGetSeconds(CMTimeSubtract(lastPTS, startedAtPTS)))
  }

  var latestPTS: CMTime { lastPTS }

#if TACUA_CAPTURE_FAULT_INJECTION
  func configureFaultInjection(_ behavior: TacuaCaptureInjectedFinishBehavior) {
    precondition(!finished, "Writer fault injection must be configured before finalization.")
    injectedFinishBehavior = behavior
  }
#endif

  func makeHeldVideoSample(at presentationTimeStamp: CMTime) throws -> CMSampleBuffer {
    guard presentationTimeStamp.isValid,
      CMTimeCompare(presentationTimeStamp, lastVideoPTS) > 0,
      let lastVideoSample
    else {
      throw TacuaCaptureSpikeError.writerFailed(
        "Segment \(index) could not create a monotonic held video frame."
      )
    }
    var timing = CMSampleTimingInfo(
      duration: CMTime(value: 1, timescale: 30),
      presentationTimeStamp: presentationTimeStamp,
      decodeTimeStamp: .invalid
    )
    var copy: CMSampleBuffer?
    let status = CMSampleBufferCreateCopyWithNewTiming(
      allocator: kCFAllocatorDefault,
      sampleBuffer: lastVideoSample,
      sampleTimingEntryCount: 1,
      sampleTimingArray: &timing,
      sampleBufferOut: &copy
    )
    guard status == noErr, let copy else {
      throw TacuaCaptureSpikeError.writerFailed(
        "Segment \(index) could not retime its last video frame (CoreMedia:\(status))."
      )
    }
    return copy
  }

  @discardableResult
  func appendHeldVideoFrame(
    _ sampleBuffer: CMSampleBuffer,
    hostUptimeSeconds: Double
  ) -> Bool {
    let result = append(
      sampleBuffer,
      type: .video,
      hostUptimeSeconds: hostUptimeSeconds
    )
    if result.wasAppended { heldVideoSamples += 1 }
    return result.wasAppended
  }

  func extendVideoToLatestPTS(hostUptimeSeconds: Double) throws {
    guard CMTimeCompare(lastPTS, lastVideoPTS) > 0 else { return }
    let heldFrame = try makeHeldVideoSample(at: lastPTS)
    guard appendHeldVideoFrame(heldFrame, hostUptimeSeconds: hostUptimeSeconds) else {
      throw fatalError ?? TacuaCaptureSpikeError.writerFailed(
        "Segment \(index) rejected its closing held video frame."
      )
    }
  }

  func isCompatible(withVideoSample sampleBuffer: CMSampleBuffer) -> Bool {
    guard let description = CMSampleBufferGetFormatDescription(sampleBuffer) else { return false }
    let candidate = CMVideoFormatDescriptionGetDimensions(description)
    return candidate.width == videoDimensions.width && candidate.height == videoDimensions.height
  }

  @discardableResult
  func append(
    _ sampleBuffer: CMSampleBuffer,
    type: RPSampleBufferType,
    hostUptimeSeconds: Double,
    appAudioAttemptIndex: Int? = nil
  ) -> TacuaSegmentAppendResult {
    if type == .audioApp {
      let expectedIndex = appAudioAppendAttemptStartIndex + appAudioAppendAttempts
      guard appAudioAttemptIndex == expectedIndex else {
        fatalError = TacuaCaptureSpikeError.writerFailed(
          "Segment \(index) received non-contiguous app-audio append accounting."
        )
        return .fatalUnaccounted
      }
      appAudioAppendAttempts += 1
    } else if appAudioAttemptIndex != nil {
      fatalError = TacuaCaptureSpikeError.writerFailed(
        "Segment \(index) received app-audio accounting for another media stream."
      )
      return .fatalUnaccounted
    }

    guard !finished else {
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .writerFinished
      ) ? .recordedDrop : .fatalUnaccounted
    }
    guard CMSampleBufferDataIsReady(sampleBuffer) else {
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .sampleDataNotReady
      ) ? .recordedDrop : .fatalUnaccounted
    }

    guard writer.status == .writing else {
      let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
      fatalError = TacuaCaptureSpikeError.writerFailed("Segment \(index) stopped accepting media (\(code)).")
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .writerNotWriting
      ) ? .recordedDrop : .fatalUnaccounted
    }

    let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
    guard pts.isValid, CMTimeCompare(pts, startedAtPTS) >= 0 else {
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .timestampInvalid
      ) ? .recordedDrop : .fatalUnaccounted
    }

    let input: AVAssetWriterInput
    switch type {
    case .video:
      input = videoInput
    case .audioApp:
      input = appAudioInput
    case .audioMic:
      input = microphoneInput
    @unknown default:
      incrementNonAppAudioDrop(type)
      return .fatalUnaccounted
    }

    guard input.isReadyForMoreMediaData else {
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .inputBackpressure
      ) ? .recordedDrop : .fatalUnaccounted
    }
    guard input.append(sampleBuffer) else {
      if writer.status == .failed || writer.status == .cancelled {
        let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
        fatalError = TacuaCaptureSpikeError.writerFailed("Segment \(index) failed while appending media (\(code)).")
      }
      return recordDrop(
        type,
        appAudioAttemptIndex: appAudioAttemptIndex,
        cause: .appendRejected
      ) ? .recordedDrop : .fatalUnaccounted
    }

    if CMTimeCompare(pts, lastPTS) > 0 {
      lastPTS = pts
      lastHostUptimeSeconds = hostUptimeSeconds
    }
    switch type {
    case .video:
      videoSamples += 1
      lastVideoPTS = pts
      var copy: CMSampleBuffer?
      if CMSampleBufferCreateCopy(
        allocator: kCFAllocatorDefault,
        sampleBuffer: sampleBuffer,
        sampleBufferOut: &copy
      ) == noErr {
        lastVideoSample = copy
      }
    case .audioApp: appAudioSamples += 1
    case .audioMic: microphoneSamples += 1
    @unknown default: break
    }
    return .appended
  }

  func finish(completion: @escaping (Result<CaptureSegment, Error>) -> Void) {
    let watchdog = DispatchWorkItem { [self] in
      timeoutFinalization()
    }

    finishLock.lock()
    guard case .notStarted = finishState else {
      finishLock.unlock()
      completion(.failure(TacuaCaptureSpikeError.writerFailed("Segment \(index) was finalized twice.")))
      return
    }
    finished = true
    finishState = .awaitingWriterCallback
    finishDeadlineUptimeSeconds = ProcessInfo.processInfo.systemUptime
      + TacuaCapturePolicy.writerFinalizationWatchdogSeconds
    finishCompletion = completion
    finishWatchdog = watchdog
    finishLock.unlock()

    videoInput.markAsFinished()
    appAudioInput.markAsFinished()
    microphoneInput.markAsFinished()

    DispatchQueue.global(qos: .utility).asyncAfter(
      deadline: .now() + TacuaCapturePolicy.writerFinalizationWatchdogSeconds,
      execute: watchdog
    )

#if TACUA_CAPTURE_FAULT_INJECTION
    switch injectedFinishBehavior {
    case .failure:
      failFinalization(
        TacuaCaptureSpikeError.writerFailed(
          "The QA harness injected a bounded writer-finalization failure for segment \(index)."
        )
      )
      return
    case .timeout:
      // Let AVAssetWriter finish for real, but delay delivery of its callback
      // until after the production deadline. The watchdog must win, and the
      // actual late callback must be unable to publish media or a sidecar.
      let delayedCallbackDeadline = DispatchTime.now()
        + TacuaCapturePolicy.writerFinalizationWatchdogSeconds + 1
      writer.finishWriting { [self] in
        DispatchQueue.global(qos: .utility).asyncAfter(
          deadline: delayedCallbackDeadline
        ) { [self] in
          handleWriterCompletion()
        }
      }
      return
    case .none:
      break
    }
#endif

    writer.finishWriting { [self] in
      handleWriterCompletion()
    }
  }

  private func handleWriterCompletion() {
    switch claimWriterCallback() {
    case .ignore:
      return
    case .timeout(let completion):
      cancelWriterIfActive()
      cleanupFailedCommitArtifacts()
      completion(.failure(TacuaCaptureSpikeError.writerTimeout))
      return
    case .commit:
      break
    }

    guard writer.status == .completed else {
      let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
      failFinalization(
        TacuaCaptureSpikeError.writerFailed("Segment \(index) failed to finalize (\(code)).")
      )
      return
    }

    DispatchQueue.global(qos: .utility).async { [self] in
      do {
        let fileManager = FileManager.default
        let attributes = try fileManager.attributesOfItem(atPath: partialURL.path)
        let byteLength = (attributes[.size] as? NSNumber)?.int64Value ?? 0
        let sha256 = try SegmentWriter.sha256(url: partialURL)
        let segment = CaptureSegment(
          index: index,
          fileName: finalURL.lastPathComponent,
          sha256: sha256,
          byteLength: byteLength,
          firstMediaPTSSeconds: CMTimeGetSeconds(startedAtPTS),
          lastMediaPTSSeconds: CMTimeGetSeconds(lastPTS),
          firstHostUptimeSeconds: firstHostUptimeSeconds,
          lastHostUptimeSeconds: lastHostUptimeSeconds,
          durationSeconds: durationSeconds,
          videoSamples: videoSamples,
          heldVideoSamples: heldVideoSamples,
          appAudioSamples: appAudioSamples,
          microphoneSamples: microphoneSamples,
          droppedVideoSamples: droppedVideoSamples,
          droppedAppAudioSamples: droppedAppAudioSamples,
          droppedMicrophoneSamples: droppedMicrophoneSamples,
          appAudioAppendAttemptStartIndex: appAudioAppendAttemptStartIndex,
          appAudioAppendAttempts: appAudioAppendAttempts,
          appAudioAppendDrops: appAudioAppendDrops
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let sidecar = try encoder.encode(segment)
        try sidecar.write(
          to: stagedSidecarURL,
          options: [.atomic, .completeFileProtectionUnlessOpen]
        )
        try fileManager.setAttributes(
          [.protectionKey: FileProtectionType.completeUnlessOpen],
          ofItemAtPath: partialURL.path
        )

        publishPreparedSegment(segment)
      } catch {
        failFinalization(
          TacuaCaptureSpikeError.writerFailed(
            "Segment \(index) could not commit its verified media and sidecar."
          )
        )
      }
    }
  }

  private func claimWriterCallback() -> WriterCallbackDecision {
    finishLock.lock()
    defer { finishLock.unlock() }

    guard case .awaitingWriterCallback = finishState else { return .ignore }
    guard !finishDeadlineHasElapsedLocked() else {
      guard let completion = takeTerminalCompletionLocked() else { return .ignore }
      return .timeout(completion)
    }
    finishState = .committing
    return .commit
  }

  /// Publishes the verified pair under the same lock used by the watchdog.
  /// The sidecar is the recovery commit marker, so it is moved first and the
  /// old sidecar-plus-partial crash window remains recoverable. If filesystem
  /// operations cross the monotonic deadline, both trusted names are removed
  /// before the timeout is delivered.
  private func publishPreparedSegment(_ segment: CaptureSegment) {
    var completion: FinishCompletion?
    var result: Result<CaptureSegment, Error>?
    var shouldCancelWriter = false

    finishLock.lock()
    guard case .committing = finishState else {
      finishLock.unlock()
      cleanupFailedCommitArtifacts()
      return
    }

    if finishDeadlineHasElapsedLocked() {
      completion = takeTerminalCompletionLocked()
      result = .failure(TacuaCaptureSpikeError.writerTimeout)
      shouldCancelWriter = true
    } else {
      do {
        let fileManager = FileManager.default
        try fileManager.moveItem(at: stagedSidecarURL, to: sidecarURL)
        try fileManager.moveItem(at: partialURL, to: finalURL)

        if finishDeadlineHasElapsedLocked() {
          cleanupFailedCommitArtifacts()
          completion = takeTerminalCompletionLocked()
          result = .failure(TacuaCaptureSpikeError.writerTimeout)
          shouldCancelWriter = true
        } else {
          completion = takeTerminalCompletionLocked()
          result = .success(segment)
        }
      } catch {
        cleanupFailedCommitArtifacts()
        completion = takeTerminalCompletionLocked()
        if finishDeadlineHasElapsedLocked() {
          result = .failure(TacuaCaptureSpikeError.writerTimeout)
          shouldCancelWriter = true
        } else {
          result = .failure(
            TacuaCaptureSpikeError.writerFailed(
              "Segment \(index) could not publish its verified media and sidecar."
            )
          )
        }
      }
    }
    finishLock.unlock()

    guard let completion, let result else {
      cleanupFailedCommitArtifacts()
      return
    }
    if shouldCancelWriter {
      cancelWriterIfActive()
      cleanupFailedCommitArtifacts()
    }
    completion(result)
  }

  private func timeoutFinalization() {
    finishLock.lock()
    let completion = takeTerminalCompletionLocked()
    finishLock.unlock()

    guard let completion else { return }
    cancelWriterIfActive()
    cleanupFailedCommitArtifacts()
    completion(.failure(TacuaCaptureSpikeError.writerTimeout))
  }

  private func failFinalization(_ error: Error) {
    var terminalError = error
    finishLock.lock()
    if finishDeadlineHasElapsedLocked() {
      terminalError = TacuaCaptureSpikeError.writerTimeout
    }
    let completion = takeTerminalCompletionLocked()
    finishLock.unlock()

    guard let completion else {
      cleanupFailedCommitArtifacts()
      return
    }
    cancelWriterIfActive()
    cleanupFailedCommitArtifacts()
    completion(.failure(terminalError))
  }

  /// Must be called with `finishLock` held.
  private func takeTerminalCompletionLocked() -> FinishCompletion? {
    switch finishState {
    case .awaitingWriterCallback, .committing:
      finishState = .terminal
    case .notStarted, .terminal:
      return nil
    }
    finishWatchdog?.cancel()
    finishWatchdog = nil
    let completion = finishCompletion
    finishCompletion = nil
    return completion
  }

  /// Must be called with `finishLock` held.
  private func finishDeadlineHasElapsedLocked() -> Bool {
    guard let finishDeadlineUptimeSeconds else { return true }
    return ProcessInfo.processInfo.systemUptime >= finishDeadlineUptimeSeconds
  }

  private func cancelWriterIfActive() {
    if writer.status == .unknown || writer.status == .writing {
      writer.cancelWriting()
    }
  }

  /// Removes every filename that recovery could interpret as a trusted
  /// segment. The AVAssetWriter partial remains available for explicit partial
  /// accounting, but a timed-out or failed commit can never leave its sidecar.
  private func cleanupFailedCommitArtifacts() {
    let fileManager = FileManager.default
    try? fileManager.removeItem(at: sidecarURL)
    try? fileManager.removeItem(at: stagedSidecarURL)
    if fileManager.fileExists(atPath: finalURL.path) {
      if !fileManager.fileExists(atPath: partialURL.path) {
        try? fileManager.moveItem(at: finalURL, to: partialURL)
      }
      if fileManager.fileExists(atPath: finalURL.path) {
        try? fileManager.removeItem(at: finalURL)
      }
    }
  }

  private static func makeAudioInput(channelCount: Int, bitRate: Int) -> AVAssetWriterInput {
    let settings: [String: Any] = [
      AVFormatIDKey: kAudioFormatMPEG4AAC,
      AVSampleRateKey: 44_100,
      AVNumberOfChannelsKey: channelCount,
      AVEncoderBitRateKey: bitRate,
    ]
    let input = AVAssetWriterInput(mediaType: .audio, outputSettings: settings)
    input.expectsMediaDataInRealTime = true
    return input
  }

  @discardableResult
  private func recordDrop(
    _ type: RPSampleBufferType,
    appAudioAttemptIndex: Int?,
    cause: TacuaAppAudioAppendDropCause
  ) -> Bool {
    switch type {
    case .video:
      droppedVideoSamples += 1
      return true
    case .audioApp:
      guard let appAudioAttemptIndex else {
        fatalError = TacuaCaptureSpikeError.writerFailed(
          "Segment \(index) could not bind an app-audio drop to its append attempt."
        )
        return false
      }
      guard appAudioAppendDrops.count < maximumTrackedAppAudioDrops else {
        fatalError = TacuaCaptureSpikeError.appAudioAccountingLimitExceeded
        return false
      }
      droppedAppAudioSamples += 1
      appAudioAppendDrops.append(TacuaAppAudioAppendDrop(
        attemptIndex: appAudioAttemptIndex,
        cause: cause
      ))
      return true
    case .audioMic:
      droppedMicrophoneSamples += 1
      return true
    @unknown default:
      return false
    }
  }

  private func incrementNonAppAudioDrop(_ type: RPSampleBufferType) {
    switch type {
    case .video: droppedVideoSamples += 1
    case .audioMic: droppedMicrophoneSamples += 1
    case .audioApp:
      fatalError = TacuaCaptureSpikeError.writerFailed(
        "Segment \(index) reached an unknown app-audio sample type."
      )
    @unknown default: break
    }
  }

  private static func sha256(url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hasher = SHA256()
    while true {
      let data = try handle.read(upToCount: 1_048_576) ?? Data()
      if data.isEmpty { break }
      hasher.update(data: data)
    }
    return hasher.finalize().map { String(format: "%02x", $0) }.joined()
  }
}
