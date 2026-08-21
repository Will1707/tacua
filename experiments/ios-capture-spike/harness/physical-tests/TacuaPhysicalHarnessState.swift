// SPDX-License-Identifier: Apache-2.0

import Foundation

enum TacuaPhysicalInteractionMode {
  case platformDefault
  case requireSkipPreAndPostEventQuiescence
}

enum TacuaQuiescenceContract {
  static let interactionOptionsGetter = "currentInteractionOptions"
  static let interactionOptionsSetter = "setCurrentInteractionOptions:"
  static let interactionOptionsGetterSignature = "I16@0:8"
  static let interactionOptionsSetterSignature = "v20@0:8I16"
  static let skipPreAndPostEventQuiescenceMask: UInt32 = 3

  static func acceptsSignatures(getter: String, setter: String) -> Bool {
    getter == interactionOptionsGetterSignature
      && setter == interactionOptionsSetterSignature
  }

  static func acceptsReadback(_ value: UInt32) -> Bool {
    value == skipPreAndPostEventQuiescenceMask
  }
}

/// Makes the required pre-transition bind, transition, and post-transition
/// bind ordering executable in a host test without XCUIAutomation.
enum TacuaQuiescenceTransitionGate {
  static func perform(
    bind: () -> Bool,
    transition: () -> Void
  ) -> Bool {
    guard bind() else { return false }
    transition()
    return bind()
  }
}

enum TacuaMonotonicTime {
  static func isFinitePositive(_ value: TimeInterval) -> Bool {
    value.isFinite && value > 0
  }

  static func deadline(
    now: TimeInterval,
    after duration: TimeInterval
  ) -> TimeInterval? {
    guard now.isFinite, now >= 0, isFinitePositive(duration) else {
      return nil
    }
    let result = now + duration
    guard result.isFinite, result > now else { return nil }
    return result
  }

  static func isBeforeDeadline(
    now: TimeInterval,
    deadline: TimeInterval
  ) -> Bool {
    now.isFinite && now >= 0 && deadline.isFinite && deadline >= 0
      && now < deadline
  }
}

enum TacuaLaunchPromptPolicyError: Error, Equatable {
  case emptyAppDisplayName
  case emptyButtonLabel
  case duplicateButtonLabel
  case emptyPromptAllowlist
  case promptDoesNotNameApp
  case duplicatePrompt
}

enum TacuaLaunchPromptDisposition: Equatable {
  case none
  case expected
  case unexpected
}

enum TacuaDirectHandoffDecision: Equatable {
  case keepWaiting
  case handleExpectedPrompt
  case acceptForeground
  case failUnexpectedPrompt
}

/// Gives prompt classification priority over foreground acceptance so a
/// foreground target can never hide an unexpected alert or sheet.
enum TacuaDirectHandoffDecisionPolicy {
  static func decide(
    prompt: TacuaLaunchPromptDisposition,
    targetIsForeground: Bool,
    expectedPromptWasHandled: Bool
  ) -> TacuaDirectHandoffDecision {
    switch prompt {
    case .unexpected:
      return .failUnexpectedPrompt
    case .expected where !expectedPromptWasHandled:
      return .handleExpectedPrompt
    case .expected:
      return .keepWaiting
    case .none:
      return targetIsForeground ? .acceptForeground : .keepWaiting
    }
  }
}

/// One snapshot is one alert or sheet. Labels from separate containers must
/// never be combined to synthesize an allowlisted prompt.
struct TacuaLaunchPromptSnapshot: Equatable {
  let staticTextLabels: [String]
  let buttonLabels: [String]
}

struct TacuaLaunchConfirmationPolicy: Equatable {
  let appDisplayName: String
  let exactPromptLabels: Set<String>
  let openButtonLabel: String
  let cancelButtonLabel: String

  init(
    appDisplayName: String,
    exactPromptLabels: [String],
    openButtonLabel: String,
    cancelButtonLabel: String
  ) throws {
    guard !appDisplayName.isEmpty else {
      throw TacuaLaunchPromptPolicyError.emptyAppDisplayName
    }
    guard !openButtonLabel.isEmpty, !cancelButtonLabel.isEmpty else {
      throw TacuaLaunchPromptPolicyError.emptyButtonLabel
    }
    guard openButtonLabel != cancelButtonLabel else {
      throw TacuaLaunchPromptPolicyError.duplicateButtonLabel
    }
    guard !exactPromptLabels.isEmpty else {
      throw TacuaLaunchPromptPolicyError.emptyPromptAllowlist
    }
    guard Set(exactPromptLabels).count == exactPromptLabels.count else {
      throw TacuaLaunchPromptPolicyError.duplicatePrompt
    }
    guard exactPromptLabels.allSatisfy({ $0.contains(appDisplayName) }) else {
      throw TacuaLaunchPromptPolicyError.promptDoesNotNameApp
    }

    self.appDisplayName = appDisplayName
    self.exactPromptLabels = Set(exactPromptLabels)
    self.openButtonLabel = openButtonLabel
    self.cancelButtonLabel = cancelButtonLabel
  }

  func classify(
    _ promptSnapshots: [TacuaLaunchPromptSnapshot]
  ) -> TacuaLaunchPromptDisposition {
    guard !promptSnapshots.isEmpty else { return .none }
    guard promptSnapshots.count == 1, let snapshot = promptSnapshots.first else {
      return .unexpected
    }

    let matchingPromptLabels = snapshot.staticTextLabels.filter(
      exactPromptLabels.contains
    )
    let openButtonCount = snapshot.buttonLabels.filter {
      $0 == openButtonLabel
    }.count
    let cancelButtonCount = snapshot.buttonLabels.filter {
      $0 == cancelButtonLabel
    }.count
    if matchingPromptLabels.count == 1,
      snapshot.buttonLabels.count == 2,
      openButtonCount == 1,
      cancelButtonCount == 1
    {
      return .expected
    }
    return .unexpected
  }
}

struct TacuaPostHandoffObservation: Equatable {
  let targetIsForeground: Bool
  let hasUnexpectedSystemPrompt: Bool
  let hasConsent: Bool
  let hasGenericFailure: Bool
  let hasBuildBindingCheck: Bool
  let hasBuildBindingFailure: Bool
  let hasRecovery: Bool
  let hasNeedsAttention: Bool
  let hasStableBaseline: Bool
}

enum TacuaPostHandoffOutcome: String, Equatable {
  case consent
  case genericFailure = "generic-failure"
  case buildBindingChecking = "build-binding-checking"
  case buildBindingFailure = "build-binding-failure"
  case recovery
  case needsAttention = "needs-attention"
  case unexpectedSystemPrompt = "unexpected-system-prompt"
  case targetLeftForeground = "target-left-foreground"
  case stableBaselineOnly = "stable-baseline-only"
  case unknown
}

/// Only explicit failures are returned during polling. Consent and every
/// diagnostic non-failure are classified at the final observation boundary.
struct TacuaPostHandoffClassifier {
  static func classify(
    _ observation: TacuaPostHandoffObservation,
    bindingCheckIsStable: Bool,
    finalSnapshot: Bool
  ) -> TacuaPostHandoffOutcome? {
    if observation.hasUnexpectedSystemPrompt {
      return .unexpectedSystemPrompt
    }
    if !observation.targetIsForeground {
      return .targetLeftForeground
    }
    if observation.hasGenericFailure {
      return .genericFailure
    }
    if observation.hasBuildBindingFailure {
      return .buildBindingFailure
    }
    if observation.hasRecovery {
      return .recovery
    }
    if observation.hasNeedsAttention {
      return .needsAttention
    }
    guard finalSnapshot else { return nil }
    if observation.hasConsent {
      return .consent
    }
    if observation.hasBuildBindingCheck {
      return bindingCheckIsStable ? .buildBindingChecking : .unknown
    }
    if observation.hasStableBaseline {
      return .stableBaselineOnly
    }
    return .unknown
  }
}

enum TacuaAppAudioPlanError: Error, Equatable {
  case invalidDuration
}

enum TacuaAppAudioPhase: Equatable {
  case readyToTap
  case awaitingPlaybackActive
  case awaitingPlaybackReady
  case observingPostSampleRecording
  case complete
}

/// Pure proof of the required control sequence. A ready control cannot move
/// directly to post-sample observation: the exact active state must first be
/// observed, then disappear while the exact control is ready again.
struct TacuaAppAudioTransitionProof: Equatable {
  private(set) var phase: TacuaAppAudioPhase = .readyToTap

  mutating func didTapPlayback() -> Bool {
    guard phase == .readyToTap else { return false }
    phase = .awaitingPlaybackActive
    return true
  }

  mutating func observe(
    playbackIsActive: Bool,
    controlIsReady: Bool
  ) -> Bool {
    switch phase {
    case .awaitingPlaybackActive where playbackIsActive:
      phase = .awaitingPlaybackReady
      return true
    case .awaitingPlaybackReady where !playbackIsActive && controlIsReady:
      phase = .observingPostSampleRecording
      return true
    default:
      return false
    }
  }

  mutating func didObservePostSampleRecording(
    for duration: TimeInterval
  ) -> Bool {
    guard
      phase == .observingPostSampleRecording,
      TacuaMonotonicTime.isFinitePositive(duration)
    else {
      return false
    }
    phase = .complete
    return true
  }
}

struct TacuaAppAudioPlan: Equatable {
  let playbackStartTimeout: TimeInterval
  let playbackCompletionTimeout: TimeInterval
  let postSampleRecordingWait: TimeInterval
  let pollInterval: TimeInterval

  init(
    playbackStartTimeout: TimeInterval,
    playbackCompletionTimeout: TimeInterval,
    postSampleRecordingWait: TimeInterval,
    pollInterval: TimeInterval = 0.25
  ) throws {
    let durations = [
      playbackStartTimeout,
      playbackCompletionTimeout,
      postSampleRecordingWait,
      pollInterval,
    ]
    guard
      durations.allSatisfy(TacuaMonotonicTime.isFinitePositive),
      pollInterval <= 0.5
    else {
      throw TacuaAppAudioPlanError.invalidDuration
    }
    self.playbackStartTimeout = playbackStartTimeout
    self.playbackCompletionTimeout = playbackCompletionTimeout
    self.postSampleRecordingWait = postSampleRecordingWait
    self.pollInterval = pollInterval
  }
}
