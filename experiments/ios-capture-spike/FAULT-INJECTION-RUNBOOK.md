# EXP-001 fault-injection runbook

This campaign exercises Tacua's real ReplayKit, AVAssetWriter, watchdog,
manifest, and recovery paths on a physical iPhone while replacing only the
specific failure boundary named by each plan. It is QA evidence for the spike,
not a production SDK feature.

## Safety boundary

Fault injection exists only when all four gates agree:

1. Swift is compiled with `TACUA_CAPTURE_FAULT_INJECTION`.
2. The bundle identifier is exactly `com.tacua.capturelab.acceptance`.
3. `TacuaCaptureFaultInjectionEnabled` is `true` in the harness Info.plist.
4. `TACUA_CAPTURE_TEST_FAULT` contains one exact supported value.

The native implementation is enclosed by the compile condition. Ordinary
builds contain none of its plan names or environment key. A process grants at
most one fault lease; terminate and relaunch the harness for every scenario.

Never create real disk pressure on a personal phone. The low-storage plans
override only Tacua's capacity decision, so they prove fail-closed orchestration
but do not claim to reproduce an operating-system `ENOSPC` failure.

## Build and launch

Regenerate the ignored iOS project and CocoaPods metadata after adding a native
source file. A fresh checkout has no tracked `ios/Podfile.lock`, so create its
local lockfile with an ordinary install rather than deployment mode:

```sh
npm ci
npx expo prebuild --platform ios --no-install
cd ios && pod install && cd ..
```

Build the dedicated QA variant with the compilation condition applied to the
app and pod targets. Normal local signing settings still apply:

```sh
xcodebuild \
  -workspace ios/TacuaCaptureLab.xcworkspace \
  -scheme TacuaCaptureLab \
  -configuration Debug \
  -destination 'generic/platform=iOS' \
  SWIFT_ACTIVE_COMPILATION_CONDITIONS='DEBUG TACUA_CAPTURE_FAULT_INJECTION' \
  build
```

This Debug development client intentionally has no embedded JavaScript bundle.
Start Metro from the harness directory in one terminal and keep it running:

```sh
npm run start
```

Install the app, then launch one plan in a fresh process from another terminal.
Pass the development-client URL printed by Expo so a cold launch loads this
project rather than depending on a previous Metro session. Use a local device
name or private identifier; never paste a stable identifier or the concrete
development URL into public evidence.

```sh
xcrun devicectl device process launch \
  --device '<device>' \
  --terminate-existing \
  --environment-variables '{"TACUA_CAPTURE_TEST_FAULT":"low_storage_start"}' \
  --payload-url '<development-client URL printed by Expo>' \
  com.tacua.capturelab.acceptance
```

The Recorder card must display the armed plan before the operator starts. The
harness uses two-second segments for storage and stop plans. The two writer
finalization plans use 30-second segments, longer than the 15-second writer
watchdog. After segment 0 commits, the native fault harness requests Stop
exactly once so index 1 is finalized deterministically before its next
boundary, even if JavaScript remounts. Do not tap Stop first for those two
plans.

Tapping Start consumes the process's one-shot fault lease even if preparation
rejects before creating a session, as `low_storage_start` should. The Recorder
card then shows `lease consumed · relaunch required` and disables Start. Finish
any required stop cleanup, terminate the process, and relaunch it for every new
scenario. Recovery Resume is also disabled in a fault-injection process so a
consumed lease cannot silently produce an uninjected follow-up capture; Keep
partial and Delete remain available.

## Plans and acceptance

| Plan | Expected physical result |
| --- | --- |
| `low_storage_start` | Start rejects `ERR_TACUA_CAPTURE_STORAGE_LOW`; ReplayKit remains idle; no session directory is created. |
| `low_storage_writer_1` | Segment 0 remains checksum-valid; index 1 is not claimed; terminal state is `partial` with `ERR_TACUA_CAPTURE_STORAGE_LOW` and `segment_rotation_failed`; ReplayKit stops. |
| `writer_finish_failure_1` | After segment 0, the harness automatically calls Stop once; finalization fails for index 1; segment 0 remains valid; terminal is `partial` with `ERR_TACUA_CAPTURE_WRITER_FINISH`; no index-1 sidecar is trusted. |
| `writer_finish_timeout_1` | After segment 0, the harness automatically calls Stop once. AVAssetWriter finishes index 1 for real, but the harness delays delivery of its callback until one second after the real 15-second writer watchdog. Keep the process alive for two seconds after the timeout result. Segment 0 survives; terminal is `partial` with `ERR_TACUA_CAPTURE_WRITER_TIMEOUT`; no index-1 media or sidecar is trusted, and the actual late callback cannot publish either one. |
| `stop_failure_once` | Attempt 1 reports a callback failure and attempt 2 invokes real ReplayKit stop; terminal is `partial` with `ERR_TACUA_CAPTURE_STOP_FAILED`; recorder is inactive. |
| `stop_timeout_once` | Attempt 1 omits its callback and the real 15-second watchdog retries; attempt 2 invokes real stop; terminal is `partial` with `ERR_TACUA_CAPTURE_STOP_TIMEOUT`; recorder is inactive. |
| `stop_timeout_twice` | The first stop rejects after two watchdog windows in `stop_failed_capture_active` while the real recorder remains active. A mandatory second Stop uses the now-exhausted plan and must end with the recorder inactive. |

For every plan that creates media, verify every manifest-listed segment's size
and SHA-256 against its MOV, and verify that no unlisted partial is promoted
without a valid sidecar. Treat a missing callback, a hung test, or a recorder
left active as a failure, not as partial success.

## Evidence and cleanup

Public evidence may contain the commit SHA, device model class and iOS version,
plan name, rounded watchdog elapsed time, terminal state, stable codes, gap and
segment counts, and `N/N checksums matched`. Do not publish session IDs, local
paths, media hashes, narration, raw manifests, device identifiers, signing
material, or tokens.

Copy media only to a private temporary directory for inspection, delete that
copy immediately, and delete only the campaign sessions through the harness's
scoped confirmation UI. The `stop_timeout_twice` cleanup stop is mandatory
before proceeding to another plan.
