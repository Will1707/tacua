// SPDX-License-Identifier: Apache-2.0

import Foundation

private struct Assertions {
  private(set) var failures = 0

  mutating func expect(
    _ condition: @autoclosure () -> Bool,
    _ message: String
  ) {
    guard !condition() else { return }
    failures += 1
    FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
  }

  mutating func expectEqual<Value: Equatable>(
    _ actual: @autoclosure () -> Value,
    _ expected: Value,
    _ message: String
  ) {
    expect(actual() == expected, message)
  }
}

@main
private enum TacuaPhysicalHarnessStateTests {
  static func main() {
    var assertions = Assertions()
    testQuiescenceContract(&assertions)
    testQuiescenceTransitionOrdering(&assertions)
    testExactPromptPolicy(&assertions)
    testFinalBoundaryClassification(&assertions)
    testExplicitFailureClassification(&assertions)
    testMonotonicBounds(&assertions)
    testAudioPlanAndTransitions(&assertions)

    guard assertions.failures == 0 else {
      fatalError("\(assertions.failures) physical-harness state assertion(s) failed")
    }
    print("physical-harness-state-tests=passed")
  }

  private static func testQuiescenceContract(_ assertions: inout Assertions) {
    assertions.expectEqual(
      TacuaQuiescenceContract.interactionOptionsGetter,
      "currentInteractionOptions",
      "quiescence getter must remain exact"
    )
    assertions.expectEqual(
      TacuaQuiescenceContract.interactionOptionsSetter,
      "setCurrentInteractionOptions:",
      "quiescence setter must remain exact"
    )
    assertions.expectEqual(
      TacuaQuiescenceContract.interactionOptionsGetterSignature,
      "I16@0:8",
      "quiescence getter signature must remain exact"
    )
    assertions.expectEqual(
      TacuaQuiescenceContract.interactionOptionsSetterSignature,
      "v20@0:8I16",
      "quiescence setter signature must remain exact"
    )
    assertions.expectEqual(
      TacuaQuiescenceContract.skipPreAndPostEventQuiescenceMask,
      UInt32(3),
      "quiescence mask must remain UInt32 3"
    )
    assertions.expect(
      TacuaQuiescenceContract.acceptsSignatures(
        getter: "I16@0:8",
        setter: "v20@0:8I16"
      ),
      "reviewed quiescence signatures must be accepted"
    )
    assertions.expect(
      !TacuaQuiescenceContract.acceptsSignatures(
        getter: "Q16@0:8",
        setter: "v24@0:8Q16"
      ),
      "unreviewed quiescence signatures must be rejected"
    )
    assertions.expect(
      TacuaQuiescenceContract.acceptsReadback(UInt32(3)),
      "exact quiescence readback must be accepted"
    )
    assertions.expect(
      !TacuaQuiescenceContract.acceptsReadback(UInt32(1)),
      "partial quiescence readback must be rejected"
    )
  }

  private static func testQuiescenceTransitionOrdering(
    _ assertions: inout Assertions
  ) {
    var events: [String] = []
    var bindCount = 0
    let succeeded = TacuaQuiescenceTransitionGate.perform(
      bind: {
        bindCount += 1
        events.append("bind-\(bindCount)")
        return true
      },
      transition: { events.append("transition") }
    )
    assertions.expect(succeeded, "pre/post quiescence binding should succeed")
    assertions.expectEqual(
      events,
      ["bind-1", "transition", "bind-2"],
      "quiescence must bind before and after every transition"
    )

    events = []
    let rejectedBefore = TacuaQuiescenceTransitionGate.perform(
      bind: {
        events.append("bind")
        return false
      },
      transition: { events.append("transition") }
    )
    assertions.expect(!rejectedBefore, "failed pre-bind must fail closed")
    assertions.expectEqual(
      events,
      ["bind"],
      "failed pre-bind must prevent the transition"
    )

    events = []
    bindCount = 0
    let rejectedAfter = TacuaQuiescenceTransitionGate.perform(
      bind: {
        bindCount += 1
        events.append("bind-\(bindCount)")
        return bindCount == 1
      },
      transition: { events.append("transition") }
    )
    assertions.expect(!rejectedAfter, "failed post-bind must fail closed")
    assertions.expectEqual(
      events,
      ["bind-1", "transition", "bind-2"],
      "post-transition binding must always be attempted"
    )
  }

  private static func testExactPromptPolicy(_ assertions: inout Assertions) {
    let appName = "Example · QA"
    let promptLabel = "Open this page in “\(appName)”?”"
    guard
      let policy = try? TacuaLaunchConfirmationPolicy(
        appDisplayName: appName,
        exactPromptLabels: [promptLabel],
        openButtonLabel: "Open",
        cancelButtonLabel: "Cancel"
      )
    else {
      assertions.expect(false, "valid exact prompt policy must initialize")
      return
    }
    let exact = TacuaLaunchPromptSnapshot(
      staticTextLabels: [promptLabel],
      buttonLabels: ["Open", "Cancel"]
    )
    assertions.expectEqual(
      policy.classify([exact]),
      .expected,
      "one prompt container with every exact component must match"
    )
    assertions.expectEqual(
      policy.classify([]),
      .none,
      "absence of alerts and sheets must be distinguished"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel],
          buttonLabels: ["Open"]
        ),
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [],
          buttonLabels: ["Cancel"]
        ),
      ]),
      .unexpected,
      "components split across alert and sheet must never be combined"
    )
    assertions.expectEqual(
      policy.classify([
        exact,
        TacuaLaunchPromptSnapshot(
          staticTextLabels: ["A second system prompt arrived"],
          buttonLabels: ["Dismiss"]
        ),
      ]),
      .unexpected,
      "a second container arriving before tap must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel],
          buttonLabels: ["Open"]
        )
      ]),
      .unexpected,
      "an incomplete exact prompt must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel],
          buttonLabels: ["Open", "Cancel", "Unknown"]
        )
      ]),
      .unexpected,
      "an unexpected third action must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel, promptLabel],
          buttonLabels: ["Open", "Cancel"]
        )
      ]),
      .unexpected,
      "duplicate exact prompt labels must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel],
          buttonLabels: ["Open", "Open", "Cancel"]
        )
      ]),
      .unexpected,
      "duplicate exact Open controls must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: [promptLabel],
          buttonLabels: ["Open", "Cancel", "Cancel"]
        )
      ]),
      .unexpected,
      "duplicate exact Cancel controls must fail closed"
    )
    assertions.expectEqual(
      policy.classify([
        TacuaLaunchPromptSnapshot(
          staticTextLabels: ["Open a different application?"],
          buttonLabels: ["Open", "Cancel"]
        )
      ]),
      .unexpected,
      "a prompt that does not name the configured app must fail closed"
    )
    assertions.expectEqual(
      TacuaDirectHandoffDecisionPolicy.decide(
        prompt: .unexpected,
        targetIsForeground: true,
        expectedPromptWasHandled: false
      ),
      .failUnexpectedPrompt,
      "prompt classification must outrank foreground acceptance"
    )
    assertions.expectEqual(
      TacuaDirectHandoffDecisionPolicy.decide(
        prompt: .expected,
        targetIsForeground: true,
        expectedPromptWasHandled: false
      ),
      .handleExpectedPrompt,
      "an expected prompt must be handled before foreground acceptance"
    )
    assertions.expectEqual(
      TacuaDirectHandoffDecisionPolicy.decide(
        prompt: .expected,
        targetIsForeground: true,
        expectedPromptWasHandled: true
      ),
      .keepWaiting,
      "a handled prompt must disappear before foreground acceptance"
    )
    assertions.expectEqual(
      TacuaDirectHandoffDecisionPolicy.decide(
        prompt: .none,
        targetIsForeground: true,
        expectedPromptWasHandled: true
      ),
      .acceptForeground,
      "foreground may be accepted only after the prompt scan is empty"
    )
  }

  private static func observation(
    foreground: Bool = true,
    unexpectedPrompt: Bool = false,
    consent: Bool = false,
    genericFailure: Bool = false,
    bindingCheck: Bool = false,
    bindingFailure: Bool = false,
    recovery: Bool = false,
    attention: Bool = false,
    baseline: Bool = false
  ) -> TacuaPostHandoffObservation {
    TacuaPostHandoffObservation(
      targetIsForeground: foreground,
      hasUnexpectedSystemPrompt: unexpectedPrompt,
      hasConsent: consent,
      hasGenericFailure: genericFailure,
      hasBuildBindingCheck: bindingCheck,
      hasBuildBindingFailure: bindingFailure,
      hasRecovery: recovery,
      hasNeedsAttention: attention,
      hasStableBaseline: baseline
    )
  }

  private static func testFinalBoundaryClassification(
    _ assertions: inout Assertions
  ) {
    let consent = observation(consent: true)
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        consent,
        bindingCheckIsStable: false,
        finalSnapshot: false
      ),
      nil,
      "consent must not succeed before the final boundary"
    )
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        consent,
        bindingCheckIsStable: false,
        finalSnapshot: true
      ),
      .consent,
      "consent may succeed only at the final boundary"
    )

    let baseline = observation(baseline: true)
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        baseline,
        bindingCheckIsStable: false,
        finalSnapshot: false
      ),
      nil,
      "a seeded dashboard must not end observation early"
    )
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        baseline,
        bindingCheckIsStable: false,
        finalSnapshot: true
      ),
      .stableBaselineOnly,
      "a seeded dashboard is only a final diagnostic"
    )

    let bindingCheck = observation(bindingCheck: true, baseline: true)
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        bindingCheck,
        bindingCheckIsStable: true,
        finalSnapshot: false
      ),
      nil,
      "even a stable binding check must not end observation early"
    )
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        bindingCheck,
        bindingCheckIsStable: true,
        finalSnapshot: true
      ),
      .buildBindingChecking,
      "a stable binding check is a final diagnostic"
    )
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        bindingCheck,
        bindingCheckIsStable: false,
        finalSnapshot: true
      ),
      .unknown,
      "an unstable final binding check must not be promoted"
    )
  }

  private static func testExplicitFailureClassification(
    _ assertions: inout Assertions
  ) {
    let cases: [(TacuaPostHandoffObservation, TacuaPostHandoffOutcome)] = [
      (observation(unexpectedPrompt: true), .unexpectedSystemPrompt),
      (observation(foreground: false), .targetLeftForeground),
      (observation(genericFailure: true), .genericFailure),
      (observation(bindingFailure: true), .buildBindingFailure),
      (observation(recovery: true), .recovery),
      (observation(attention: true), .needsAttention),
    ]
    for (value, expected) in cases {
      assertions.expectEqual(
        TacuaPostHandoffClassifier.classify(
          value,
          bindingCheckIsStable: false,
          finalSnapshot: false
        ),
        expected,
        "explicit \(expected.rawValue) failure must fail fast"
      )
    }
    assertions.expectEqual(
      TacuaPostHandoffClassifier.classify(
        observation(consent: true, genericFailure: true, baseline: true),
        bindingCheckIsStable: false,
        finalSnapshot: true
      ),
      .genericFailure,
      "explicit failure must outrank final success and baseline"
    )
  }

  private static func testMonotonicBounds(_ assertions: inout Assertions) {
    for invalid in [0.0, -1.0, .nan, .infinity, -.infinity] {
      assertions.expect(
        !TacuaMonotonicTime.isFinitePositive(invalid),
        "non-finite or non-positive duration must be rejected"
      )
    }
    assertions.expectEqual(
      TacuaMonotonicTime.deadline(now: 10, after: 2),
      12,
      "valid monotonic deadline must be calculated"
    )
    assertions.expectEqual(
      TacuaMonotonicTime.deadline(now: 10, after: .infinity),
      nil,
      "infinite monotonic bound must be rejected"
    )
    assertions.expectEqual(
      TacuaMonotonicTime.deadline(
        now: Double.greatestFiniteMagnitude,
        after: Double.greatestFiniteMagnitude
      ),
      nil,
      "overflowing monotonic deadline must be rejected"
    )
    assertions.expect(
      !TacuaMonotonicTime.isBeforeDeadline(now: -1, deadline: 1),
      "negative monotonic observations must be rejected"
    )
  }

  private static func testAudioPlanAndTransitions(
    _ assertions: inout Assertions
  ) {
    guard
      let plan = try? TacuaAppAudioPlan(
        playbackStartTimeout: 2,
        playbackCompletionTimeout: 10,
        postSampleRecordingWait: 1.5,
        pollInterval: 0.25
      )
    else {
      assertions.expect(false, "valid app-audio plan must initialize")
      return
    }
    assertions.expect(
      plan.postSampleRecordingWait > 0,
      "post-sample recording observation must be positive"
    )
    let invalidPlans: [(TimeInterval, TimeInterval, TimeInterval, TimeInterval)] = [
      (0, 10, 1, 0.25),
      (2, -1, 1, 0.25),
      (2, 10, 0, 0.25),
      (2, 10, 1, .nan),
      (2, 10, 1, 0.75),
      (.infinity, 10, 1, 0.25),
    ]
    for value in invalidPlans {
      assertions.expect(
        (try? TacuaAppAudioPlan(
          playbackStartTimeout: value.0,
          playbackCompletionTimeout: value.1,
          postSampleRecordingWait: value.2,
          pollInterval: value.3
        )) == nil,
        "invalid app-audio bounds must fail closed"
      )
    }

    var proof = TacuaAppAudioTransitionProof()
    assertions.expect(proof.didTapPlayback(), "playback tap must start proof")
    assertions.expect(
      !proof.observe(playbackIsActive: false, controlIsReady: true),
      "ready must not be accepted before exact active playback"
    )
    assertions.expect(
      !proof.didObservePostSampleRecording(for: 1),
      "post-sample wait must not skip playback transitions"
    )
    assertions.expect(
      proof.observe(playbackIsActive: true, controlIsReady: false),
      "exact active playback must be observed"
    )
    assertions.expect(
      proof.observe(playbackIsActive: false, controlIsReady: true),
      "exact control ready state must follow active playback"
    )
    assertions.expect(
      !proof.didObservePostSampleRecording(for: 0),
      "zero post-sample observation must be rejected"
    )
    assertions.expect(
      proof.didObservePostSampleRecording(for: plan.postSampleRecordingWait),
      "positive post-sample recording observation must complete proof"
    )
    assertions.expectEqual(
      proof.phase,
      .complete,
      "audio proof must finish only after every ordered transition"
    )
  }
}
