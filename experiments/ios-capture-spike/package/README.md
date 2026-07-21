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

The package now also contains the native foundation for
`tacua.sdk-backend@1.0.0`: canonical request builders, exhaustive local request
and response validation, a build-pinned backend origin, a redirect-rejecting and
response-bounded `URLSession` client, Keychain-backed credentials, immutable
request replay, and a crash-safe queue. A native START-only lifecycle coordinator
now consumes an approved launch exactly once, creates a device-only credential,
validates and sends the frozen launch exchange, and commits the validated
receiving-session binding to that queue. It does not start ReplayKit, enqueue or
upload media, complete a session, or delete backend data. Automatic
capture-manifest-to-protocol conversion and the upload/completion/deletion
lifecycle are still implementation work; `stop()` does not upload by itself.

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

This validation is deliberately **structural only**. The local capture `start`
and `resume` APIs do not authenticate a handoff, verify a signature, contact a
backend, perform authorization, upload media, or prove consent. Production must
replace this local capture boundary with a cryptographically authenticated,
backend-issued handoff. This statement does not apply to the separate backend
launch API below: `startBackendSession` performs a network exchange with the
build-pinned Tacua backend after affirmative launch consent.

## Backend launch and transport foundation

The host QA target must pin these values in its built `Info.plist`:

- `TacuaBackendOrigin`: an HTTPS origin with no path, query, fragment, or
  userinfo. A debug build may explicitly opt into loopback HTTP with
  `TacuaAllowInsecureLoopback`; a launch link can never override the origin.
- `TacuaLaunchScheme`: the lowercase URL scheme registered by that target.

The only accepted launch URL is:

```text
<TacuaLaunchScheme>://tacua/start?launch_code=<percent-encoded opaque code>
```

`prepareBackendLaunch(url)` rejects duplicate or additional query items,
userinfo, ports, fragments, and any other authority or path. It keeps the
decoded launch code only in volatile native memory and returns a consent request
ID. After the host has presented truthful capture consent,
`confirmBackendLaunchConsent(id, true)` returns a one-shot approved handle. The
launch request builder accepts only that handle, so request construction and
exchange cannot happen before affirmative consent. Decline and cancel discard
the transient value.

```ts
const pending = TacuaCapture.prepareBackendLaunch(incomingURL);
// Present the consent UI named by pending.requiredConsentVersion.
const approved = TacuaCapture.confirmBackendLaunchConsent(
  pending.consentRequestId,
  true,
);
const receiving = await TacuaCapture.startBackendSession({
  approvedLaunchId: approved.approvedLaunchId,
  localSessionId: 'local_qa_001',
  buildIdentity, // exact tacua.sdk-backend@1.0.0 build_identity object
  scope, // exact tacua.sdk-backend@1.0.0 capture_scope object
  requestedAt: '2026-07-21T09:57:00Z',
});
// receiving.captureStarted/uploadsConnected/completionConnected are all false.
```

The host QA app, not the SDK, supplies the complete typed `buildIdentity` and
`scope`. Native code parses them with bounded strict JSON, reconstructs the
canonical request, verifies their own digests and cross-bindings, and requires
the build identity's `transport_configuration_digest` to equal the built-in
backend configuration. The SDK does not invent source, consent, retention, or
build trust.

START uses a separate, canonical, secret-free crash journal. It writes the
exchange and credential identifiers plus a SHA-256 ownership verifier before
the Keychain mutation, marks
`exchange_outcome_unknown` before network I/O, and records a validated receipt
plus the exact monotonic server-time anchor before committing the queue. No
launch code, plaintext secret, Authorization value, or transient launch request
is written to the journal or queue. Recovery deletes a Keychain item only when
its bytes match that verifier, so a crashed duplicate-ID attempt cannot delete a
pre-existing item. A recovered receipt keeps its original
uptime/boot anchor; a reboot therefore requires a fresh resume exchange instead
of extending credential time.

`getBackendStartRecoveryStatus(localSessionId)` makes interrupted state visible.
`credential_prepared` is known not to have reached the network and can be reset
without the unknown-outcome acknowledgement, but a process restart has lost the
volatile launch code, so a later START still needs a fresh reviewer launch.
When its `canRecoverWithoutLaunch` field is true,
`receipt_validated_queue_commit_pending` can be repaired with
`recoverBackendStart(localSessionId)` without another launch. Queue recovery is
structural: it remains available after a build transport change or missing
Keychain item, and the returned `resumeRequired` flag then remains true. The
public resume exchange that repairs that transport authority is a later slice;
until it exists, retain the queue and keep uploads blocked. A new START cannot
replace that committed queue, so do not request or consume another launch code
for the same local session yet. An
`exchange_outcome_unknown` state is deliberately **not** called remotely
recoverable: the backend may have accepted the request, but the process lacks a
validated remote session ID. It retains the Keychain credential and requires a
fresh reviewer launch plus an explicit
`abandonBackendStart(localSessionId, true)` acknowledgement before local reset;
backend retention or operator cleanup must handle any abandoned remote session.
If credential removal or journal cleanup fails after reset ownership is durable,
the status becomes `credential_prepared_reset_pending` or
`exchange_outcome_unknown_reset_pending`. Retry
`abandonBackendStart(localSessionId, false)` to finish that local cleanup. The
unknown-outcome acknowledgement was already recorded before the latter state was
entered, so the retry does not ask the user to acknowledge it a second time.
A crash/failure after receipt validation but before the receipt journal itself
is durable remains conservatively indistinguishable from this unknown-outcome
state. These APIs never claim that capture, uploads, or completion occurred.

`credentialCapability` records the backend authority last established; it is
not, by itself, a transport-usability signal. Even `active` is unsendable while
`resumeRequired` is true (for example after expiry, reboot, build change, or
Keychain loss). `requires_transport_rebind` is always blocked until the future
resume API binds the current build. `completion_replay_or_delete_only` permits
only exact completion replay and deletion work, while `deletion_replay_only`
permits only exact deletion replay and receipt-authorized local cleanup. A
deletion-only queue therefore reports `resumeRequired: false` because it is
terminal, not because uploads are allowed. New media uploads require all of
`credentialCapability: "active"`, `resumeRequired: false`, and
`credentialAvailability: "available"`. A locked device can report
`temporarily_unavailable`; retry after unlock instead of requesting a launch.
Other Keychain failures report `unavailable` and require local diagnosis, not
an assumed credential rotation.

Credentials are 32 random bytes stored as
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; secrets, bearer headers, and
launch codes are prohibited from the durable queue. Rotation records A's
revocation before removing A from Keychain. The host must call
`getBackendQueueStatus(localSessionId)` for each known queue during startup; that
explicit status read idempotently drains pending credential cleanup. Queue
status and cleanup hold the same cross-process per-session lease as START and
refuse to expose a queue while its receipt journal still requires recovery.
Credential
validity is the half-open interval ending at
`expires_at`; an expired credential or a reboot-invalidated monotonic clock
requires a fresh resume exchange. Exact historical request bytes remain bound to
their original credential ID while the current credential authenticates replay.

Segment uploads are copied through no-follow file descriptors into a bounded,
private immutable snapshot before `URLSession` opens them. Completion cleanup
can remove only local files whose path and digest were bound to the exact set of
validated segment and diagnostic receipts. A completion receipt is the sole
payload-cleanup authority; a deletion tombstone is the sole credential-cleanup
authority.

The capture-to-protocol adapter must derive each manifest segment `time_range`
from the verified sidecar's first and last host uptime relative to the persisted
session start. It must never derive ranges from wall-clock timestamps or array
position. Sidecars, including held/dropped sample counters, remain local until
completion-authorized cleanup. The frozen wire protocol transmits only
`sidecar_digest`, not the sidecar bytes, so the backend does not receive that
richer sidecar evidence in V1.

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

They also exercise canonical JSON and the frozen SDK/backend fixtures, strict
nested diagnostic and completion-manifest validation, launch-link and consent
gating, Keychain abstraction, build-pinned origin handling, half-open credential
expiry, rotation recovery, exact replay across multiple credentials, bounded
HTTP responses, redirect rejection, private upload snapshots, and
receipt-to-local-file cleanup binding. Adversarial local files include paths
outside the session, symlinks, directories, FIFOs, digest mismatches, and sparse
files larger than 1 GiB.

The core suite also drives the START lifecycle through success, preflight and
one-shot-consent rejection, ambiguous transport failure, acknowledged local
reset, validated-receipt queue recovery, delayed recovery, reboot recovery, and
queue/journal mismatch. It asserts journal-before-Keychain ordering and scans
every durable START artifact for prohibited launch-code and secret material. It
also covers missing-Keychain and changed-build receipt recovery, durable journal
removal confirmation, duplicate-ID crash recovery, lifecycle-serialized queue
status, stale queue CAS rejection, and private storage modes.

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
- [x] Implement and fixture-test the canonical V1 backend requests, exhaustive
  receipt validation, Keychain credential abstraction, durable replay queue,
  bounded HTTP client, and integrity-checked segment upload snapshot.
- [ ] Connect a stopped capture to the START-established queue. The START-only
  lifecycle coordinator is implemented, but this candidate still only marks
  capture data `partial_ready_for_upload`; `stop()` does not enqueue or upload
  it, and completion/deletion are not orchestrated.
- [ ] Verify protected-file behavior in the production integration and provide an
  authenticated, user-visible, scoped local-data reset for an unreadable
  manifest.
- [ ] Enforce runtime retention and deletion, default-deny external egress, and
  explicit authorization before any model or connector receives evidence.
- [ ] Re-run physical compatibility and resource measurements after the
  production transport and security boundaries replace this spike.

Until those gates close, use this package only for explicitly approved QA
experiments. The transport client can send evidence only to the build-pinned
Tacua backend origin; this package performs no direct external-model egress.
