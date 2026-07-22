# Tacua physical-iPhone capture harness

This is a removable Expo development client for `EXP-001`. It links the local
`@tacua/mobile-sdk` package and provides a deliberately small UI for
consent, ReplayKit start/mark/stop, recovery discovery, and local deletion.

The harness is not a production reviewer app and does not upload anything.
Use only synthetic or explicitly approved QA content. Never commit recordings,
device identifiers, signing material, or raw test evidence.

Local capture and recovery use a deliberately narrow native exception: the SDK
must be compiled as Debug, the bundle identifier must be exactly
`com.tacua.capturelab.acceptance`, the ordinary capture configuration must be a
local development build, and `TacuaLocalHarnessRetentionBypassEnabled` must be
the exact Boolean `true` in `Info.plist`. Release builds and every other bundle
continue to require backend retention authority. The prior
`com.tacua.capturelab` install has a different app container; this harness never
scans, resumes, or deletes sessions in that older container.
The local exception uses a bounded monotonic capture horizon and deliberately
does not interpret the manifest's raw-media timestamp as backend authority; the
timestamp is returned only so Resume can match the exact stored session value.
Never use the `.acceptance` bundle for backend-managed capture sessions.

## Local verification

Use Node 22 and an Xcode environment configured for physical-device signing:

```sh
npm install
npm run typecheck
npx expo prebuild --clean --platform ios --no-install
cd ios && pod install && cd ..
npx expo run:ios --device
```

The clean prebuild is mandatory for this bundle migration. Do not launch the
previous generated `com.tacua.capturelab` target with new JavaScript. The UI
also refuses to scan recovery data unless native code reports that every exact
acceptance-harness gate is active.

### Narrow physical UI driver

The generated iOS project may install the tracked
`TacuaCaptureLabAutomation` UI-test scheme after `pod install`:

```sh
./scripts/add_physical_ui_test_target.sh
```

The driver only targets `com.tacua.capturelab.acceptance`. Its system-prompt
allowlist contains exact English and Spanish microphone-preserving choices; it
never selects a screen-only or denial choice and fails closed in an unsupported
locale. Run the permission bootstrap first if an earlier attempt left a system
sheet pending. Then use the split Start and Stop tests rather than keeping
XCTest active for a long recording:

```sh
xcodebuild test \
  -workspace ios/TacuaCaptureLab.xcworkspace \
  -scheme TacuaCaptureLabAutomation \
  -configuration Debug \
  -destination "platform=iOS,id=${TACUA_TEST_DEVICE_ID}" \
  -only-testing:TacuaCaptureLabUITests/TacuaCaptureLabUITests/testGrantPendingPermissions \
  -parallel-testing-enabled NO \
  -collect-test-diagnostics never \
  -allowProvisioningUpdates

xcodebuild test \
  -workspace ios/TacuaCaptureLab.xcworkspace \
  -scheme TacuaCaptureLabAutomation \
  -configuration Debug \
  -destination "platform=iOS,id=${TACUA_TEST_DEVICE_ID}" \
  -only-testing:TacuaCaptureLabUITests/TacuaCaptureLabUITests/testStartRecordingAndExit \
  -parallel-testing-enabled NO \
  -collect-test-diagnostics never \
  -allowProvisioningUpdates
```

`testStartRecordingAndExit` starts capture, waits for ReplayKit, adds one issue
marker, and exits while the app remains in the foreground. For a short smoke
run, invoke `testStopActiveRecording` separately. For the 30-minute gate, leave
the app untouched and let the SDK's native monotonic limit stop it. Narration
played by automation must be labeled synthetic; it does not substitute for a
human manual-QA result.

Start with a short recording. Confirm microphone narration and at least one
verified segment before running interruption, recovery, or 30-minute tests.
The driver handles only its exact allowlisted iOS prompts; an unexpected prompt
or locale remains an operator decision. Physical lock/background actions also
remain manual. Delete local sessions after evidence has been minimized and
recorded.

Sanitized experiment observations live in
[`../PHYSICAL-DEVICE-RESULTS.md`](../PHYSICAL-DEVICE-RESULTS.md). Raw media and
stable device identifiers must never be added to that file or committed.

The deterministic low-storage, writer-finalization, and ReplayKit-stop campaign
uses a separate compile-time QA variant. Follow
[`../FAULT-INJECTION-RUNBOOK.md`](../FAULT-INJECTION-RUNBOOK.md); never simulate
low storage by filling the phone, and never leave the double-stop-timeout plan
without performing its required live cleanup stop. A Start attempt consumes the
process's one-shot lease and disables further starts until relaunch. For the two
writer-finalization plans, the harness calls Stop once automatically after
segment 0 commits.
