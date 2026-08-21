// SPDX-License-Identifier: Apache-2.0

import Foundation
import ObjectiveC.runtime
import XCTest

/// Binds every XCUIApplication owner before it is queried or interacted with.
/// Call `launch` or `activate` through this controller so a required private
/// interaction policy is also checked after the process transition.
@MainActor
final class TacuaPhysicalApplicationController {
  let mode: TacuaPhysicalInteractionMode

  init(mode: TacuaPhysicalInteractionMode = .platformDefault) {
    self.mode = mode
  }

  @discardableResult
  func bind(_ application: XCUIApplication) -> Bool {
    guard mode == .requireSkipPreAndPostEventQuiescence else { return true }

    let getter = NSSelectorFromString(TacuaQuiescenceContract.interactionOptionsGetter)
    let setter = NSSelectorFromString(TacuaQuiescenceContract.interactionOptionsSetter)
    guard
      application.responds(to: getter),
      application.responds(to: setter),
      let getterMethod = class_getInstanceMethod(type(of: application), getter),
      let setterMethod = class_getInstanceMethod(type(of: application), setter),
      let getterEncoding = method_getTypeEncoding(getterMethod),
      let setterEncoding = method_getTypeEncoding(setterMethod),
      TacuaQuiescenceContract.acceptsSignatures(
        getter: String(cString: getterEncoding),
        setter: String(cString: setterEncoding)
      )
    else {
      XCTFail(
        "The reviewed XCUIApplication interaction-options API is unavailable; no UI interaction was attempted"
      )
      return false
    }

    application.setValue(
      NSNumber(value: TacuaQuiescenceContract.skipPreAndPostEventQuiescenceMask),
      forKey: TacuaQuiescenceContract.interactionOptionsGetter
    )
    guard
      let configured = application.value(
        forKey: TacuaQuiescenceContract.interactionOptionsGetter
      ) as? NSNumber,
      TacuaQuiescenceContract.acceptsReadback(configured.uint32Value)
    else {
      XCTFail(
        "The reviewed XCUIApplication interaction policy was not retained; no UI interaction was attempted"
      )
      return false
    }
    return true
  }

  @discardableResult
  func activate(_ application: XCUIApplication) -> Bool {
    TacuaQuiescenceTransitionGate.perform(
      bind: { self.bind(application) },
      transition: { application.activate() }
    )
  }

  @discardableResult
  func launch(_ application: XCUIApplication) -> Bool {
    TacuaQuiescenceTransitionGate.perform(
      bind: { self.bind(application) },
      transition: { application.launch() }
    )
  }
}

/// Waits only for LaunchServices to foreground the target app. It never calls
/// `launch()` or `activate()` on the target as a fallback.
@MainActor
enum TacuaDirectLaunchHandoff {
  static func waitForForegroundDelivery(
    to target: XCUIApplication,
    from promptOwners: [XCUIApplication],
    policy: TacuaLaunchConfirmationPolicy,
    applications: TacuaPhysicalApplicationController,
    timeout: TimeInterval,
    pollInterval: TimeInterval = 0.25
  ) -> Bool {
    let now = ProcessInfo.processInfo.systemUptime
    guard
      !promptOwners.isEmpty,
      TacuaMonotonicTime.isFinitePositive(pollInterval),
      pollInterval <= 0.5,
      let deadline = TacuaMonotonicTime.deadline(now: now, after: timeout)
    else {
      XCTFail("The direct-launch observation window is invalid")
      return false
    }
    guard applications.bind(target) else { return false }
    for owner in promptOwners where !applications.bind(owner) {
      return false
    }

    var handledConfirmation = false
    while true {
      let promptContainers = allPromptContainers(in: promptOwners)
      let promptSnapshots = snapshots(for: promptContainers)

      let promptDisposition = policy.classify(promptSnapshots)
      switch TacuaDirectHandoffDecisionPolicy.decide(
        prompt: promptDisposition,
        targetIsForeground: target.state == .runningForeground,
        expectedPromptWasHandled: handledConfirmation
      ) {
      case .failUnexpectedPrompt:
        XCTFail("An unexpected LaunchServices prompt appeared; no action was attempted")
        return false
      case .handleExpectedPrompt:
        // Rebuild the global view immediately before binding an action. A
        // second alert or sheet may have appeared after the first snapshot.
        let freshPromptContainers = allPromptContainers(in: promptOwners)
        let freshPromptSnapshots = snapshots(for: freshPromptContainers)
        guard
          freshPromptContainers.count == 1,
          policy.classify(freshPromptSnapshots) == .expected,
          let prompt = freshPromptContainers.first
        else {
          XCTFail("The exact sole LaunchServices prompt could not be rebound")
          return false
        }
        let currentPromptLabels = prompt.staticTexts.allElementsBoundByIndex.map(\.label)
        let currentButtons = prompt.buttons.allElementsBoundByIndex
        let openButtons = currentButtons.filter { $0.label == policy.openButtonLabel }
        let cancelButtons = currentButtons.filter { $0.label == policy.cancelButtonLabel }
        guard
          currentPromptLabels.filter(policy.exactPromptLabels.contains).count == 1,
          currentButtons.count == 2,
          openButtons.count == 1,
          cancelButtons.count == 1,
          let open = openButtons.first,
          open.exists,
          open.isEnabled,
          open.isHittable,
          let cancel = cancelButtons.first,
          cancel.exists,
          cancel.isEnabled,
          cancel.isHittable
        else {
          XCTFail("The exact LaunchServices Open and Cancel actions were not actionable")
          return false
        }
        open.tap()
        handledConfirmation = true
      case .acceptForeground:
        // Prompt classification has already completed for this snapshot.
        return applications.bind(target)
      case .keepWaiting:
        break
      }

      let current = ProcessInfo.processInfo.systemUptime
      guard
        TacuaMonotonicTime.isBeforeDeadline(
          now: current,
          deadline: deadline
        )
      else {
        return false
      }
      RunLoop.current.run(
        until: Date().addingTimeInterval(
          min(pollInterval, max(0.001, deadline - current))
        )
      )
    }
  }

  private static func allPromptContainers(
    in owners: [XCUIApplication]
  ) -> [XCUIElement] {
    owners.flatMap { owner in
      owner.alerts.allElementsBoundByIndex
        + owner.sheets.allElementsBoundByIndex
    }
  }

  private static func snapshots(
    for promptContainers: [XCUIElement]
  ) -> [TacuaLaunchPromptSnapshot] {
    promptContainers.map { prompt in
      TacuaLaunchPromptSnapshot(
        staticTextLabels: prompt.staticTexts.allElementsBoundByIndex.map(\.label),
        buttonLabels: prompt.buttons.allElementsBoundByIndex.map(\.label)
      )
    }
  }
}

/// Runs the full observation window, then takes one priority-ordered final
/// snapshot. Failure, recovery, attention, and unexpected-prompt outcomes are
/// returned immediately; baseline-only is never an early success.
@MainActor
enum TacuaPostHandoffWaiter {
  static func requireConsent(
    timeout: TimeInterval,
    bindingStabilityWindow: TimeInterval,
    pollInterval: TimeInterval = 0.25,
    observe: () -> TacuaPostHandoffObservation
  ) -> Bool {
    let outcome = wait(
      timeout: timeout,
      bindingStabilityWindow: bindingStabilityWindow,
      pollInterval: pollInterval,
      observe: observe
    )
    guard outcome == .consent else {
      XCTFail(
        "The post-handoff observation ended in the allowlisted \(outcome.rawValue) state"
      )
      return false
    }
    return true
  }

  static func wait(
    timeout: TimeInterval,
    bindingStabilityWindow: TimeInterval,
    pollInterval: TimeInterval = 0.25,
    observe: () -> TacuaPostHandoffObservation
  ) -> TacuaPostHandoffOutcome {
    let startedAt = ProcessInfo.processInfo.systemUptime
    guard
      TacuaMonotonicTime.isFinitePositive(bindingStabilityWindow),
      TacuaMonotonicTime.isFinitePositive(pollInterval),
      pollInterval <= 0.5,
      let deadline = TacuaMonotonicTime.deadline(
        now: startedAt,
        after: timeout
      )
    else {
      return .unknown
    }

    var bindingCheckFirstSeenAt: TimeInterval?
    while TacuaMonotonicTime.isBeforeDeadline(
      now: ProcessInfo.processInfo.systemUptime,
      deadline: deadline
    ) {
      let observation = observe()
      let now = ProcessInfo.processInfo.systemUptime
      if observation.hasBuildBindingCheck {
        bindingCheckFirstSeenAt = bindingCheckFirstSeenAt ?? now
      } else {
        bindingCheckFirstSeenAt = nil
      }
      let bindingIsStable =
        bindingCheckFirstSeenAt.map {
          now - $0 >= bindingStabilityWindow
        } ?? false
      if let outcome = TacuaPostHandoffClassifier.classify(
        observation,
        bindingCheckIsStable: bindingIsStable,
        finalSnapshot: false
      ) {
        return outcome
      }
      RunLoop.current.run(
        until: Date().addingTimeInterval(
          min(pollInterval, max(0.001, deadline - now))
        )
      )
    }

    let finalObservation = observe()
    let finalNow = ProcessInfo.processInfo.systemUptime
    if finalObservation.hasBuildBindingCheck {
      bindingCheckFirstSeenAt = bindingCheckFirstSeenAt ?? finalNow
    } else {
      bindingCheckFirstSeenAt = nil
    }
    let bindingIsStable =
      bindingCheckFirstSeenAt.map {
        finalNow - $0 >= bindingStabilityWindow
      } ?? false
    return TacuaPostHandoffClassifier.classify(
      finalObservation,
      bindingCheckIsStable: bindingIsStable,
      finalSnapshot: true
    ) ?? .unknown
  }
}

/// Exact-control app-audio sequence. The caller supplies only reviewed fixed
/// elements; this helper observes recording through playback, readiness, and
/// the configured post-sample recording window.
@MainActor
enum TacuaAppAudioSequencer {
  static func run(
    targetApplication: XCUIApplication,
    control: XCUIElement,
    playbackActiveIndicator: XCUIElement,
    recordingIndicator: XCUIElement,
    failureIndicators: [XCUIElement],
    promptOwner: XCUIApplication,
    applications: TacuaPhysicalApplicationController,
    plan: TacuaAppAudioPlan
  ) -> Bool {
    guard applications.bind(targetApplication) else { return false }
    guard applications.bind(promptOwner) else { return false }
    guard
      noPromptOrFailure(
        recordingIndicator: recordingIndicator,
        failureIndicators: failureIndicators,
        promptOwner: promptOwner
      )
    else { return false }
    guard control.exists, control.isEnabled, control.isHittable else {
      XCTFail("The exact app-audio control was not actionable")
      return false
    }
    guard !playbackActiveIndicator.exists else {
      XCTFail("The exact app-audio active state was already present before playback")
      return false
    }
    var transitionProof = TacuaAppAudioTransitionProof()
    control.tap()
    guard transitionProof.didTapPlayback() else {
      XCTFail("The app-audio transition proof could not start")
      return false
    }

    guard
      waitForPlaybackStart(
        playbackActiveIndicator: playbackActiveIndicator,
        timeout: plan.playbackStartTimeout,
        recordingIndicator: recordingIndicator,
        failureIndicators: failureIndicators,
        promptOwner: promptOwner,
        pollInterval: plan.pollInterval,
        transitionProof: &transitionProof
      )
    else { return false }

    guard
      waitForPlaybackCompletion(
        control: control,
        playbackActiveIndicator: playbackActiveIndicator,
        timeout: plan.playbackCompletionTimeout,
        recordingIndicator: recordingIndicator,
        failureIndicators: failureIndicators,
        promptOwner: promptOwner,
        pollInterval: plan.pollInterval,
        transitionProof: &transitionProof
      )
    else { return false }

    guard
      waitWhileRecording(
        duration: plan.postSampleRecordingWait,
        recordingIndicator: recordingIndicator,
        failureIndicators: failureIndicators,
        promptOwner: promptOwner,
        pollInterval: plan.pollInterval
      ),
      transitionProof.didObservePostSampleRecording(
        for: plan.postSampleRecordingWait
      ),
      transitionProof.phase == .complete
    else {
      XCTFail("The exact app-audio sequence did not complete")
      return false
    }
    return true
  }

  private static func waitForPlaybackStart(
    playbackActiveIndicator: XCUIElement,
    timeout: TimeInterval,
    recordingIndicator: XCUIElement,
    failureIndicators: [XCUIElement],
    promptOwner: XCUIApplication,
    pollInterval: TimeInterval,
    transitionProof: inout TacuaAppAudioTransitionProof
  ) -> Bool {
    let now = ProcessInfo.processInfo.systemUptime
    guard let deadline = TacuaMonotonicTime.deadline(now: now, after: timeout) else {
      XCTFail("The app-audio start observation window is invalid")
      return false
    }
    while TacuaMonotonicTime.isBeforeDeadline(
      now: ProcessInfo.processInfo.systemUptime,
      deadline: deadline
    ) {
      guard
        noPromptOrFailure(
          recordingIndicator: recordingIndicator,
          failureIndicators: failureIndicators,
          promptOwner: promptOwner
        )
      else { return false }
      if playbackActiveIndicator.exists {
        guard
          transitionProof.observe(
            playbackIsActive: true,
            controlIsReady: false
          )
        else {
          XCTFail("The exact app-audio active transition was out of order")
          return false
        }
        return true
      }
      poll(until: deadline, interval: pollInterval)
    }
    XCTFail("The exact app-audio active state did not appear")
    return false
  }

  private static func waitForPlaybackCompletion(
    control: XCUIElement,
    playbackActiveIndicator: XCUIElement,
    timeout: TimeInterval,
    recordingIndicator: XCUIElement,
    failureIndicators: [XCUIElement],
    promptOwner: XCUIApplication,
    pollInterval: TimeInterval,
    transitionProof: inout TacuaAppAudioTransitionProof
  ) -> Bool {
    let now = ProcessInfo.processInfo.systemUptime
    guard let deadline = TacuaMonotonicTime.deadline(now: now, after: timeout) else {
      XCTFail("The app-audio completion observation window is invalid")
      return false
    }
    while TacuaMonotonicTime.isBeforeDeadline(
      now: ProcessInfo.processInfo.systemUptime,
      deadline: deadline
    ) {
      guard
        noPromptOrFailure(
          recordingIndicator: recordingIndicator,
          failureIndicators: failureIndicators,
          promptOwner: promptOwner
        )
      else { return false }
      if !playbackActiveIndicator.exists,
        control.exists,
        control.isEnabled,
        control.isHittable
      {
        guard
          transitionProof.observe(
            playbackIsActive: false,
            controlIsReady: true
          )
        else {
          XCTFail("The exact app-audio ready transition was out of order")
          return false
        }
        return true
      }
      poll(until: deadline, interval: pollInterval)
    }
    XCTFail("The exact app-audio active state did not return to ready")
    return false
  }

  private static func waitWhileRecording(
    duration: TimeInterval,
    recordingIndicator: XCUIElement,
    failureIndicators: [XCUIElement],
    promptOwner: XCUIApplication,
    pollInterval: TimeInterval
  ) -> Bool {
    let now = ProcessInfo.processInfo.systemUptime
    guard let deadline = TacuaMonotonicTime.deadline(now: now, after: duration) else {
      XCTFail("The post-sample recording observation window is invalid")
      return false
    }
    while TacuaMonotonicTime.isBeforeDeadline(
      now: ProcessInfo.processInfo.systemUptime,
      deadline: deadline
    ) {
      guard
        noPromptOrFailure(
          recordingIndicator: recordingIndicator,
          failureIndicators: failureIndicators,
          promptOwner: promptOwner
        )
      else { return false }
      poll(until: deadline, interval: pollInterval)
    }
    return noPromptOrFailure(
      recordingIndicator: recordingIndicator,
      failureIndicators: failureIndicators,
      promptOwner: promptOwner
    )
  }

  private static func noPromptOrFailure(
    recordingIndicator: XCUIElement,
    failureIndicators: [XCUIElement],
    promptOwner: XCUIApplication
  ) -> Bool {
    guard recordingIndicator.exists else {
      XCTFail("Recording stopped during the bounded app-audio sequence")
      return false
    }
    guard !failureIndicators.contains(where: { $0.exists }) else {
      XCTFail("An allowlisted app-audio failure state appeared")
      return false
    }
    guard
      !promptOwner.alerts.firstMatch.exists,
      !promptOwner.sheets.firstMatch.exists
    else {
      XCTFail("An unexpected system prompt appeared during the app-audio sequence")
      return false
    }
    return true
  }

  private static func poll(
    until deadline: TimeInterval,
    interval: TimeInterval
  ) {
    let now = ProcessInfo.processInfo.systemUptime
    let delay = min(interval, max(0.001, deadline - now))
    RunLoop.current.run(until: Date().addingTimeInterval(delay))
  }
}
