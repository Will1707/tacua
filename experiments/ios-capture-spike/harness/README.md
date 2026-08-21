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

### Reusable handoff safety support

The UI-test target also compiles the pure
[`TacuaPhysicalHarnessState.swift`](physical-tests/TacuaPhysicalHarnessState.swift)
contracts and their
[`TacuaPhysicalHarnessSupport.swift`](physical-tests/TacuaPhysicalHarnessSupport.swift)
XCUIAutomation adapter.
It is generic test infrastructure, not a product journey or evidence fixture.
An adopting maintainer must supply exact, reviewed accessibility labels for the
app and OS locale. In particular:

- a Safari-to-app handoff accepts only one alert or sheet containing a complete
  allowlisted prompt label that names the configured app, exactly one
  configured Open action, exactly one configured Cancel action, and no other
  buttons; duplicate elements and components from separate containers are
  rejected, the full prompt-owner set is freshly revalidated before a tap, and
  prompts are scanned before foreground success;
- the handoff waiter never calls `launch()` or `activate()` on the target after
  Safari, so foreground success cannot be manufactured by a fallback;
- the post-handoff classifier observes the full bounded window and permits
  success only at its final priority-ordered snapshot; a stable pre-existing
  dashboard is only a final diagnostic, never early success;
- generic failure, build-binding failure, recovery, attention, foreground loss,
  and unexpected system prompts are the explicit terminal fail-fast outcomes;
- every timeout, stability window, poll interval, and post-sample wait must be
  finite and positive and is evaluated against monotonic uptime; and
- the app-audio helper proves the exact playback state was initially absent,
  became active after the tap, then disappeared while the exact control became
  ready, before completing a positive configurable post-sample recording wait.

The optional quiescence override is XCTest-only and must be selected only for a
reviewed Xcode/XCUIAutomation build. It resolves the runtime getter and setter,
requires their exact Objective-C signatures, sets the exact `UInt32` mask `3`,
reads the value back, and fails closed. Use the application controller for
every target, Safari, and SpringBoard owner, including before and after each
launch or activation. The platform-default mode does not call the private API.
The host-executable support assertions freeze the state-machine, exact runtime
signatures and readback, and pre/post transition-binding contracts. Run
`./scripts/test_physical_harness_state.sh`; it does not contact a simulator or
device. CI separately compiles the XCUIAutomation adapter for
`generic/platform=iOS` without executing it.

### Maintainer-only private runner

[`run_private_physical_ui_test.sh`](scripts/run_private_physical_ui_test.sh) is
an opt-in wrapper for one already-built, exact UI test. Invoking it contacts the
configured physical device, so it is never a CI command and requires the
explicit `--confirm-physical-device` flag. Device identifiers and forbidden
runtime values are read from owner-private files. One-time forbidden values are
never accepted as command-line values. The device identifier is the narrow
exception: after it is read locally, `xcodebuild` necessarily receives it in
the child process's `-destination` argument. It is never printed or logged, and
the exact identifier is added to the forbidden-value scan before any result can
be retained. The runner starts `xcodebuild` in a tracked process group, forwards
`INT`, `HUP`, and `TERM`, and verifies that the entire group—not only its
leader—has exited. Surviving descendants receive `SIGKILL` after a finite grace
period. Once shutdown starts, repeated termination signals are ignored until
the group is gone and the unsealed result has been deleted. Raw stdout and
stderr go directly to `/dev/null`; no persistent raw log is created.

Before a result is retained, [`xcresult_safety.py`](scripts/xcresult_safety.py)
walks every hidden and nested entry without following links. It accepts only
owner-controlled regular files and directories, rejects symlinks, special
files, hard links, traversal, mutation races, read failures, forbidden values
in names or contents, and empty results, then applies `0700`/`0600` permissions
and rescans. Its dedicated statuses are `40` for a leak, `41` for clean/sealed,
and `42` when cleanliness cannot be proved, including every non-help command
line parse failure (`--help` alone remains status `0`). The runner destroys an
unsealed result on any scan, permission, process, interrupt, hangup, or
termination failure. It retains even a failed XCTest result only when that
result completed the safety seal.

Prepare a mode-`0600`, newline-delimited forbidden-values file containing every
exact one-time URL, code, private origin, or other runtime value that must not
be retained. The device identifier file is scanned as an additional exact
forbidden-value source, so a result that embeds it is destroyed. Keep the result
root owner-only and outside the repository. A generic invocation shape is:

```sh
./scripts/run_private_physical_ui_test.sh \
  --xctestrun /private/owner/build/PhysicalTests.xctestrun \
  --only-testing PhysicalTests/ExactUITests/testExactJourney \
  --device-id-file /private/owner/runtime/device-id \
  --result-root /private/owner/results \
  --forbidden-values-file /private/owner/runtime/forbidden-values \
  --confirm-physical-device
```

Never place result bundles, the private value file, device identifiers, launch
URLs, private origins, or raw evidence in the repository. The scanner operates
directly on files and deliberately does not invoke `xcresulttool`.

Sanitized experiment observations live in
[`../PHYSICAL-DEVICE-RESULTS.md`](../PHYSICAL-DEVICE-RESULTS.md). Raw media and
stable device identifiers must never be added to that file or committed.

### Host-side diagnostics retention

Xcode, device tooling, and automation wrappers can produce private host-side
diagnostics even when the app under test retains no media. Store those outputs
only in an owner-private managed operation and enforce their independent
seven-day deadline with the repository-owned
[`manage_pilot_diagnostics.py`](../PILOT-DIAGNOSTICS-RETENTION.md) workflow.
Its daily scoped scavenger replaces cleanup that runs only when another pilot
starts, and its explicit migration mode can harden legacy diagnostics without
silently deleting them. This host policy does not replace SDK or backend
retention and does not authorize committing raw evidence.

The deterministic low-storage, writer-finalization, and ReplayKit-stop campaign
uses a separate compile-time QA variant. Follow
[`../FAULT-INJECTION-RUNBOOK.md`](../FAULT-INJECTION-RUNBOOK.md); never simulate
low storage by filling the phone, and never leave the double-stop-timeout plan
without performing its required live cleanup stop. A Start attempt consumes the
process's one-shot lease and disables further starts until relaunch. For the two
writer-finalization plans, the harness calls Stop once automatically after
segment 0 commits.
