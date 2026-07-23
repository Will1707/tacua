// SPDX-License-Identifier: Apache-2.0

import XCTest

/// Narrow physical-device controls for the repository acceptance bundle.
///
/// The allowlist deliberately omits screen-only and denial choices. An
/// unrecognized system prompt fails closed instead of tapping an arbitrary
/// button. Start and Stop are separate tests so XCTest does not remain active
/// throughout the SDK's native 30-minute limit.
final class TacuaCaptureLabUITests: XCTestCase {
  private let appBundleIdentifier = "com.tacua.capturelab.acceptance"

  override func setUpWithError() throws {
    continueAfterFailure = false
  }

  func testGrantPendingPermissions() throws {
    executionTimeAllowance = 60
    let app = XCUIApplication(bundleIdentifier: appBundleIdentifier)
    app.activate()
    XCTAssertTrue(
      app.staticTexts["Tacua Capture Lab"].waitForExistence(timeout: 20),
      "Tacua Capture Lab is not loaded"
    )

    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    let deadline = Date().addingTimeInterval(10)
    var quietSince: Date?
    while Date() < deadline {
      if tapExpectedAffirmativeButton(in: springboard) {
        quietSince = nil
      } else if let quietSince {
        if Date().timeIntervalSince(quietSince) >= 2 {
          break
        }
      } else {
        quietSince = Date()
      }
      RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    }

    let stop = app.buttons["Stop and verify"]
    if stop.waitForExistence(timeout: 10) {
      stop.tap()
      XCTAssertTrue(
        app.buttons["Start local recording"].waitForExistence(timeout: 30),
        "Permission-bootstrap capture did not return to idle"
      )
    } else {
      XCTAssertTrue(
        app.buttons["Start local recording"].waitForExistence(timeout: 10),
        "Capture Lab did not return to a known idle or recording state"
      )
    }
  }

  func testStartRecordingAndExit() throws {
    executionTimeAllowance = 90
    let app = try prepareCaptureLab()
    let start = app.buttons["Start local recording"]
    XCTAssertTrue(waitUntilEnabled(start, timeout: 20), "Start did not become enabled")
    start.tap()

    let mark = app.buttons["Mark spoken issue"]
    XCTAssertTrue(
      waitForCaptureToStart(app: app, marker: mark, timeout: 30),
      "Capture did not start after handling the expected system prompts"
    )
    Thread.sleep(forTimeInterval: 5)
    mark.tap()
  }

  func testStopActiveRecording() throws {
    executionTimeAllowance = 60
    let app = XCUIApplication(bundleIdentifier: appBundleIdentifier)
    app.activate()
    XCTAssertTrue(
      app.staticTexts["Tacua Capture Lab"].waitForExistence(timeout: 20),
      "Tacua Capture Lab is not loaded"
    )
    let stop = app.buttons["Stop and verify"]
    XCTAssertTrue(stop.waitForExistence(timeout: 10), "No active capture is available to stop")
    stop.tap()
    XCTAssertTrue(
      app.buttons["Start local recording"].waitForExistence(timeout: 30),
      "Capture did not return to idle"
    )
    XCTAssertTrue(
      app.staticTexts.matching(NSPredicate(format: "label == %@", "State: completed"))
        .firstMatch.waitForExistence(timeout: 10),
      "Capture did not complete"
    )
    XCTAssertTrue(
      app.staticTexts.matching(NSPredicate(format: "label == %@", "Errors: none"))
        .firstMatch.exists,
      "Capture reported a stable error"
    )
  }

  private func prepareCaptureLab() throws -> XCUIApplication {
    let app = XCUIApplication(bundleIdentifier: appBundleIdentifier)
    app.activate()
    XCTAssertTrue(
      app.staticTexts["Tacua Capture Lab"].waitForExistence(timeout: 20),
      "Tacua Capture Lab is not loaded from the development server"
    )
    XCTAssertFalse(
      app.staticTexts.matching(
        NSPredicate(format: "label CONTAINS %@", "Local harness gate inactive")
      ).firstMatch.exists,
      "The exact local acceptance gate is inactive"
    )

    let consent = app.switches.firstMatch
    XCTAssertTrue(consent.waitForExistence(timeout: 5), "Consent switch is unavailable")
    let consentValue = (consent.value as? String)?.lowercased()
    if consentValue != "1" && consentValue != "true" && consentValue != "on" {
      consent.tap()
    }
    return app
  }

  private func waitForCaptureToStart(
    app: XCUIApplication,
    marker: XCUIElement,
    timeout: TimeInterval
  ) -> Bool {
    let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
      if marker.exists && marker.isHittable {
        return true
      }
      _ = tapExpectedAffirmativeButton(in: springboard)
      RunLoop.current.run(until: Date().addingTimeInterval(0.25))
    }
    return marker.exists && marker.isHittable
  }

  @discardableResult
  private func tapExpectedAffirmativeButton(in springboard: XCUIApplication) -> Bool {
    let replayKitLabels = [
      "Record Screen & Microphone",
      "Grabar pantalla y micrófono",
    ]
    for alert in springboard.alerts.allElementsBoundByIndex where alert.exists {
      for label in replayKitLabels {
        let button = alert.buttons[label]
        if button.exists && button.isHittable {
          button.tap()
          return true
        }
      }

      let prompt = alert.staticTexts.allElementsBoundByIndex
        .map(\.label)
        .joined(separator: " ")
      let isCaptureLabMicrophonePrompt =
        prompt.localizedCaseInsensitiveContains("Tacua Capture Lab") &&
        (
          prompt.localizedCaseInsensitiveContains("microphone") ||
            prompt.localizedCaseInsensitiveContains("micrófono")
        )
      guard isCaptureLabMicrophonePrompt else { continue }
      for label in ["Allow", "Permitir"] {
        let button = alert.buttons[label]
        if button.exists && button.isHittable {
          button.tap()
          return true
        }
      }
    }
    return false
  }

  private func waitUntilEnabled(_ element: XCUIElement, timeout: TimeInterval) -> Bool {
    guard element.waitForExistence(timeout: timeout) else { return false }
    let expectation = XCTNSPredicateExpectation(
      predicate: NSPredicate(format: "enabled == true"),
      object: element
    )
    return XCTWaiter.wait(for: [expectation], timeout: timeout) == .completed
  }
}
