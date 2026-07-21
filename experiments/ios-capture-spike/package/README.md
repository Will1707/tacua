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
- Finalizes the active segment when the host app backgrounds or the phone locks, records one explicit lifecycle gap, and starts a new segment only after foreground video returns. Audio callbacks received while the writer is intentionally closed are counted separately in `droppedDuringBackground`; Tacua does not synthesize media across the lifecycle gap.
- Applies bounded start, stop, microphone-startup, and writer-finalization watchdogs. The writer deadline spans AVAssetWriter's callback, checksum calculation, sidecar staging, and publication; if timeout wins, no recovery sidecar remains and a late callback cannot publish the segment. A stop attempt that did not issue a live ReplayKit call may retry once. If a live call crosses its watchdog, Tacua bounds the caller but retains exclusive process ownership until that callback resolves, so it never overlaps `stopCapture` calls or reports an unconfirmed stop. If two synthetic timeout attempts leave ReplayKit recording, the session remains installed in the nonterminal `stop_failed_capture_active` state and `stop()` rejects.
- Temporarily disables the iOS idle timer while capture is active and restores the host app's prior setting on terminal stop or start failure. This prevents an unattended foreground QA run from auto-locking the device without overriding an app that had already disabled auto-lock.
- Uses iOS complete-unless-open file protection and excludes capture storage from device backup.

`CaptureTransportPolicy.swift` now defines and tests the next SDK boundary for
scoped upload queues, authenticated receipt matching, idempotent retries,
bounded backoff, deletion gating, and shape-bound sanitized diagnostic events.
It deliberately performs no network I/O and persists no bearer credential; the
backend exchange, secure credential storage, HTTP transport, and capture-session
integration remain implementation work.

The native design-point limit is 30 minutes. A persisted monotonic deadline and an in-process timer both trigger stop; incoming sample buffers also recheck the deadline. iOS may suspend the host process in the background, so this is not a claim of wall-clock enforcement while suspended. `EXP-001` exercised foreground capture, lock recovery, process interruption, the 30-minute limit, and deterministic storage/writer/stop faults on one physical iPhone using synthetic QA data. Those results close the physical candidate gates for the spike; they do not establish a supported-device matrix or production readiness. See the [physical-device results](../PHYSICAL-DEVICE-RESULTS.md) for the exact scope and measurements.

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

They also cover fail-closed storage thresholds, lifecycle sample admission,
multi-boundary catch-up, and the exact QA fault-plan parser/matchers. The test
runner syntax-parses every native source both with and without the dedicated
fault condition, compiles and runs the platform-independent policy and fault
tests, and verifies that plan names do not appear in a non-fault binary. A full
local Xcode build is still required to compile the complete module in each
configuration.

Physical fault injection is available only in the Capture Lab build and is
excluded at compile time from ordinary builds. Its four independent gates,
supported plans, acceptance criteria, evidence boundary, and mandatory cleanup
are defined in
[`../FAULT-INJECTION-RUNBOOK.md`](../FAULT-INJECTION-RUNBOOK.md).

Source type-checking against the target Expo/Xcode toolchain is also required.

## Production SDK promotion checklist

The physical campaign promotes `EXP-001` from simulator-only evidence to a
physical capture candidate. It does not promote this package to the production
SDK. Promotion requires all remaining gates below to close:

- [x] Exercise foreground narration and app audio, static-screen segmentation,
  lock recovery, process interruption, fixed recovery choices, scoped deletion,
  the 30-minute foreground limit, and deterministic storage/writer/stop faults
  on a physical iPhone with synthetic QA data.
- [x] Verify the byte length and SHA-256 of every media segment accepted as
  physical fault-campaign evidence.
- [ ] Eliminate boundary-ordering app-audio drops or define and enforce a
  measured threshold. The 30-minute candidate run dropped 121 of 77,523 app-audio
  append attempts (about 0.156%).
- [ ] Replace structural handoff fields with a cryptographically authenticated,
  backend-issued handoff scoped to the organization, project, build, and current
  consent contract.
- [ ] Implement resumable, integrity-checked upload and an authenticated backend
  receipt. This candidate only marks local data `partial_ready_for_upload`.
- [ ] Verify protected-file behavior in the production integration and provide an
  authenticated, user-visible, scoped local-data reset for an unreadable
  manifest.
- [ ] Enforce runtime retention and deletion, default-deny external egress, and
  explicit authorization before any model or connector receives evidence.
- [ ] Re-run physical compatibility and resource measurements after the
  production transport and security boundaries replace this spike.

Until those gates close, use this package only for explicitly approved, local
QA experiments. It performs no external model egress.
