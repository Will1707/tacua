// SPDX-License-Identifier: Apache-2.0

import AVFoundation
import CoreMedia
import CryptoKit
import Foundation
import ReplayKit

final class SegmentWriter {
  let index: Int
  let startedAtPTS: CMTime

  private let partialURL: URL
  private let finalURL: URL
  private let writer: AVAssetWriter
  private let videoInput: AVAssetWriterInput
  private let appAudioInput: AVAssetWriterInput
  private let microphoneInput: AVAssetWriterInput
  private let firstHostUptimeSeconds: Double
  private let videoDimensions: CMVideoDimensions

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
  private var finished = false
  private(set) var fatalError: Error?
  private let finishLock = NSLock()
  private var finishCompletionDelivered = false
  private var finishCompletion: ((Result<CaptureSegment, Error>) -> Void)?
  private var finishWatchdog: DispatchWorkItem?

  init(
    index: Int,
    directory: URL,
    firstVideoSample: CMSampleBuffer,
    hostUptimeSeconds: Double
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

    let stem = String(format: "segment-%06d", index)
    partialURL = directory.appendingPathComponent("\(stem).partial.mov")
    finalURL = directory.appendingPathComponent("\(stem).mov")

    let fileManager = FileManager.default
    if fileManager.fileExists(atPath: partialURL.path) {
      try fileManager.removeItem(at: partialURL)
    }
    if fileManager.fileExists(atPath: finalURL.path) {
      throw TacuaCaptureSpikeError.writerCreation("A finalized segment already exists at index \(index).")
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
    let appended = append(
      sampleBuffer,
      type: .video,
      hostUptimeSeconds: hostUptimeSeconds
    )
    if appended { heldVideoSamples += 1 }
    return appended
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
    hostUptimeSeconds: Double
  ) -> Bool {
    guard !finished, CMSampleBufferDataIsReady(sampleBuffer) else {
      incrementDropped(type)
      return false
    }

    guard writer.status == .writing else {
      let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
      fatalError = TacuaCaptureSpikeError.writerFailed("Segment \(index) stopped accepting media (\(code)).")
      incrementDropped(type)
      return false
    }

    let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
    guard pts.isValid, CMTimeCompare(pts, startedAtPTS) >= 0 else {
      incrementDropped(type)
      return false
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
      incrementDropped(type)
      return false
    }

    guard input.isReadyForMoreMediaData, input.append(sampleBuffer) else {
      if writer.status == .failed || writer.status == .cancelled {
        let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
        fatalError = TacuaCaptureSpikeError.writerFailed("Segment \(index) failed while appending media (\(code)).")
      }
      incrementDropped(type)
      return false
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
    return true
  }

  func finish(completion: @escaping (Result<CaptureSegment, Error>) -> Void) {
    guard !finished else {
      completion(.failure(TacuaCaptureSpikeError.writerFailed("Segment \(index) was finalized twice.")))
      return
    }
    finished = true
    finishCompletion = completion

    videoInput.markAsFinished()
    appAudioInput.markAsFinished()
    microphoneInput.markAsFinished()

    let watchdog = DispatchWorkItem { [self] in
      writer.cancelWriting()
      deliverFinish(.failure(TacuaCaptureSpikeError.writerTimeout))
    }
    finishWatchdog = watchdog
    DispatchQueue.global(qos: .utility).asyncAfter(
      deadline: .now() + TacuaCapturePolicy.writerFinalizationWatchdogSeconds,
      execute: watchdog
    )

    writer.finishWriting { [self] in
      guard writer.status == .completed else {
        let code = writer.error?.tacuaStableCode ?? "AVAssetWriter:\(writer.status.rawValue)"
        deliverFinish(
          .failure(TacuaCaptureSpikeError.writerFailed("Segment \(index) failed to finalize (\(code))."))
        )
        return
      }

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
          droppedMicrophoneSamples: droppedMicrophoneSamples
        )

        let sidecarURL = finalURL
          .deletingPathExtension()
          .appendingPathExtension("segment.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let sidecar = try encoder.encode(segment)
        try sidecar.write(to: sidecarURL, options: [.atomic, .completeFileProtectionUnlessOpen])

        try fileManager.moveItem(at: partialURL, to: finalURL)
        try fileManager.setAttributes(
          [.protectionKey: FileProtectionType.completeUnlessOpen],
          ofItemAtPath: finalURL.path
        )

        deliverFinish(.success(segment))
      } catch {
        deliverFinish(
          .failure(
            TacuaCaptureSpikeError.writerFailed(
              "Segment \(index) could not commit its verified media and sidecar."
            )
          )
        )
      }
    }
  }

  private func deliverFinish(_ result: Result<CaptureSegment, Error>) {
    let completion: ((Result<CaptureSegment, Error>) -> Void)?
    finishLock.lock()
    if finishCompletionDelivered {
      completion = nil
    } else {
      finishCompletionDelivered = true
      finishWatchdog?.cancel()
      finishWatchdog = nil
      completion = finishCompletion
      finishCompletion = nil
    }
    finishLock.unlock()
    completion?(result)
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

  private func incrementDropped(_ type: RPSampleBufferType) {
    switch type {
    case .video: droppedVideoSamples += 1
    case .audioApp: droppedAppAudioSamples += 1
    case .audioMic: droppedMicrophoneSamples += 1
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
