# Tacua iOS capture spike module

This package is a removable, experiment-only Expo Modules API boundary for Tacua `EXP-001` and `EXP-005`. It targets iOS 17+, compiles against Expo Modules Core, and uses Apple's ReplayKit directly. There is no third-party recorder dependency.

`@tacua/ios-capture-spike` is private, unpublished experiment metadata. It does not claim ownership or availability of the public `@tacua` package-registry scope.

It is a candidate implementation, not the production Tacua SDK contract. Its schema and JavaScript API may change. It must only be linked into a permitted QA build with truthful screen and microphone consent copy; do not include it in an ordinary production/App Store target.

## Candidate behavior

- Captures the host app's ReplayKit video, app-audio, and microphone sample buffers.
- Requires microphone permission and at least one microphone sample. A video-only session cannot be classified as complete.
- Writes independently finalized MOV segments. Continuous audio timestamps drive rotation even when ReplayKit suppresses unchanged video frames. Tacua retimes the last observed video frame only at a segment boundary or tail, and records `heldVideoSamples` so downstream consumers can distinguish those explicit static-frame holds from observed UI changes. Before each partial-to-final rename, it atomically writes a sidecar containing size, SHA-256, timing, and sample counts.
- Reconciles a finalized segment, or a sidecar-verified partial segment, after interruption. It never invents a segment from an unverified file.
- Records host-clock/media-clock calibration, markers, dual-clock continuity gaps, stable public error codes, and truthful nullable status values. A long interval between ReplayKit video samples is not itself a gap when media time and host uptime advance together.
- Applies bounded start, stop, microphone-startup, and writer-finalization watchdogs. A timed-out stop is retried once. If ReplayKit still reports that it is recording, the session remains installed in the nonterminal `stop_failed_capture_active` state and `stop()` rejects; it is never reported as stopped.
- Uses iOS complete-unless-open file protection and excludes capture storage from device backup.

The native design-point limit is 30 minutes. A persisted monotonic deadline and an in-process timer both trigger stop; incoming sample buffers also recheck the deadline. iOS may suspend the host process in the background, so this is not a claim of wall-clock enforcement while suspended. Background, lock-screen, interruption, process-death, and 30-minute behavior remain physical-device test requirements.

## Candidate handoff contract

`start` and `resume` require:

```ts
type CaptureStartOptions = {
  sessionId: string;
  segmentDurationSeconds: number; // 2...60
  organizationId: string;
  projectId: string;
  buildId: string;
  handoffId: string;
  handoffTokenIdentifier?: string;
  expiresAt: string; // ISO-8601
  consentVersion: 'tacua-local-capture-consent-v1';
  expectedApplicationId: string;
  expectedBuildNumber: string;
};
```

The module validates safe identifier syntax, expiry, the current bundle identifier, the current `CFBundleVersion`, and the supported consent version before creating or resuming local capture data. It persists the identity fields in the manifest and checks them again for recovery. `handoffTokenIdentifier` is an opaque identifier only: never pass or persist a raw bearer token.

This validation is deliberately **structural only**. The candidate module does not authenticate a handoff, verify a signature, contact a backend, perform authorization, upload media, or prove consent. Production must replace this local boundary with a cryptographically authenticated backend-issued handoff.

## Fixed recovery choices

After interruption, the host UI can offer exactly three local actions:

1. `resume(options)` reconciles verified segments, creates an explicit `process_resume` gap, and records into new segment indexes. Its remaining budget is 30 minutes minus the durations of already verified segments. Resume requires a fresh, unexpired handoff for the original stored identity and the currently installed app build.
2. `markPartialReadyForUpload(options)` reconciles verified media and changes only the local manifest state to `partial_ready_for_upload`. It requires at least one verified segment and a fresh matching handoff. It does **not** upload, enqueue, transmit, or delete anything.
3. `deleteSession(options)` removes the local session directory. Erasure remains available after handoff expiry, consent-contract changes, and app upgrades. It validates the safe session ID, stored organization/project/handoff identity, and current application identifier, but intentionally does not require the original build number to equal the currently installed build.

`listRecoverableSessions()` returns metadata only and does not expose handoff identifiers. If a manifest is unreadable it reports `manifest_unreadable`; this candidate refuses identity-blind deletion of such a directory. A production privacy design needs an authenticated, user-visible fallback for corrupt local data (for example, a scoped local-data reset).

## Example

```ts
import * as TacuaCapture from '@tacua/ios-capture-spike';

const options = {
  sessionId: 'qa_20260720_001',
  segmentDurationSeconds: 10,
  organizationId: 'org_local',
  projectId: 'sample-mobile-app',
  buildId: 'ios-31',
  handoffId: 'handoff-001',
  handoffTokenIdentifier: 'opaque-token-id-001',
  expiresAt: '2026-07-20T18:00:00Z',
  consentVersion: 'tacua-local-capture-consent-v1' as const,
  expectedApplicationId: 'com.example.samplemobileapp.tacuaqa',
  expectedBuildNumber: '31',
};

await TacuaCapture.start(options);
await TacuaCapture.mark('wrong-copy');
const terminal = await TacuaCapture.stop();
```

## Verification

Run the platform-independent policy tests from this directory:

```sh
npm run test:core
```

The tests cover terminal classification, deadline behavior, media-clock segment boundaries, dual-clock microphone stall detection, crash-window source selection, structural handoff validation, expiry/build-independent deletion authorization, and fail-closed stop-timeout decisions.

Source type-checking against the target Expo/Xcode toolchain is also required. Before promotion beyond the spike, test a development build on a physical iPhone for ReplayKit consent and callbacks, microphone/app-audio formats and continuity, background/foreground and lock transitions, interruption and process kill, 30-minute resource usage, low storage, writer and stop fault injection, protected-file behavior, and recovery of verified partial segments. Simulator-only results are insufficient.
