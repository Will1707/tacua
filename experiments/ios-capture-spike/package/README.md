# Tacua mobile SDK for iOS

`@tacua/mobile-sdk` is Tacua's removable, pre-release Expo Modules API
boundary for iOS QA builds. It targets iOS 17+, compiles against Expo Modules
Core, and uses Apple's ReplayKit directly. There is no third-party recorder
dependency.

The current pre-release package boundary is certified only against Expo SDK 56
and React Native 0.85 (the clean release harness currently resolves Expo
56.0.16 and React Native 0.85.3). The peer dependency ranges deliberately fail
closed outside those minors; expanding them requires another native build and
device-compatibility review.

The source is Apache-2.0 open source. The npm manifest remains marked `private`
only to fail closed on accidental registry publication; Tacua does not claim
ownership or availability of the public `@tacua` registry scope.

This is a pre-1.0 candidate, so its JavaScript API may change. It must only be
linked into a permitted QA build with truthful screen and microphone consent
copy; do not include it in an ordinary production/App Store target.

## Installation

Tacua distributes this pre-release SDK as a versioned GitHub Release tarball,
not through the npm registry. After the `mobile-sdk-v0.1.0` release exists, an
Expo QA app can pin it directly:

```json
{
  "dependencies": {
    "@tacua/mobile-sdk": "https://github.com/Will1707/tacua/releases/download/mobile-sdk-v0.1.0/tacua-mobile-sdk-0.1.0.tgz"
  }
}
```

Run `npm install` and commit the resulting lockfile so npm records the tarball
integrity. For source-tree development, use `"file:../package"` as the harness
does. Configure the Expo plugin and backend-generated sealed SDK profile before
building a new native QA client; an over-the-air JavaScript update cannot add
this native module. Release maintainers must follow the repository's
[mobile SDK release runbook](https://github.com/Will1707/tacua/blob/main/docs/maintainers/MOBILE_SDK_RELEASE.md).

## Candidate behavior

- Captures the host app's ReplayKit video, app-audio, and microphone sample buffers.
- Requires microphone permission and at least one microphone sample. A video-only session cannot be classified as complete.
- Writes independently finalized MOV segments. Continuous audio timestamps drive rotation even when ReplayKit suppresses unchanged video frames. Tacua retimes the last observed video frame only at a segment boundary or tail, and records `heldVideoSamples` so downstream consumers can distinguish those explicit static-frame holds from observed UI changes. Before each partial-to-final rename, it atomically writes a sidecar containing size, SHA-256, timing, and sample counts.
- Gives every AVAssetWriter app-audio append decision a stable, one-based index across segment rotations. Schema-4 sidecars persist each known attempt range and every dropped index with a closed, privacy-safe cause. Before issuing an index, the SDK fsyncs a bounded 4,096-index reservation; process recovery reconstructs every leading, internal, and tail hole around surviving sidecars as an explicit `process_recovery_reservation` unknown range and resumes strictly after the reserved high-watermark, so an issued identity is never silently reused. Exactly 2,048 recorded drops remain valid; the next unrecordable drop fails the capture closed. Any recovered/unknown range permanently makes the run ineligible for physical acceptance.
- Reconciles a finalized segment, or a sidecar-verified partial segment, after interruption. It never invents a segment from an unverified file.
- Records host-clock/media-clock calibration, markers, dual-clock continuity gaps, stable public error codes, and truthful nullable status values. A long interval between ReplayKit video samples is not itself a gap when media time and host uptime advance together.
- Keeps a first-party, append-only native diagnostic journal beside the capture. Route templates, semantic interaction targets, sanitized runtime failures, network completion metadata, lifecycle changes, digest-only custom state, issue marks, and capture gaps receive native monotonic time, dense sequence, deterministic identifiers, a SHA-256 hash chain, and an fsync before success. Tacua does not require OpenTelemetry for this V1 path.
- Finalizes the active segment when the host app backgrounds or the phone locks, records one explicit lifecycle gap, and starts a new segment only after foreground video returns. Audio callbacks received while the writer is intentionally closed are counted separately in `droppedDuringBackground`; Tacua does not synthesize media across the lifecycle gap.
- Applies bounded start, stop, microphone-startup, and writer-finalization watchdogs. The writer deadline spans AVAssetWriter's callback, checksum calculation, sidecar staging, and publication; if timeout wins, no recovery sidecar remains and a late callback cannot publish the segment. A stop attempt that did not issue a live ReplayKit call may retry once. If a live call crosses its watchdog, Tacua bounds the caller but retains exclusive process ownership until that callback resolves, so it never overlaps `stopCapture` calls or reports an unconfirmed stop. If two synthetic timeout attempts leave ReplayKit recording, the session remains installed in the nonterminal `stop_failed_capture_active` state and `stop()` rejects.
- Temporarily disables the iOS idle timer while capture is active and restores the host app's prior setting on terminal stop or start failure. This prevents an unattended foreground QA run from auto-locking the device without overriding an app that had already disabled auto-lock.
- Uses iOS complete-unless-open file protection and excludes capture storage from device backup.

The package now also contains the native foundation for
`tacua.sdk-backend@1.0.0`: canonical request builders, exhaustive local request
and response validation, a build-pinned backend origin, a redirect-rejecting and
response-bounded `URLSession` client, Keychain-backed credentials, immutable
request replay, and a crash-safe queue. Native START and RESUME lifecycle
coordinators consume approved launches exactly once, create device-only
credentials, validate and send the frozen exchanges, and commit validated
receiving or completion-replay authority to that queue. They do not start
ReplayKit. An explicit finalized-capture admission API verifies stopped local
media and atomically adds immutable segment intents plus one sanitized SDK
diagnostic to the queue. A separate async processor now uploads the admitted
artifacts, completes the backend session, and retires the entire local capture
only after the validated completion receipt is durable. Authenticated backend
deletion is also implemented as a fixed, exactly replayable `user_requested`
operation. `stop()` remains intentionally local and never enqueues or transmits
evidence by itself.

The native design-point limit is 30 minutes, further capped by the immutable
backend START raw-media deadline. Native retention evaluation converts that
deadline to an absolute current-boot uptime; ReplayKit startup, the in-process
timer, and incoming sample buffers all use that same non-extendable stop point.
iOS may suspend the host process in the background, so this is not a claim of
wall-clock execution while suspended; relaunch performs the crash-safe sweep
described below. `EXP-001` exercised foreground capture, lock recovery, process
interruption, the 30-minute limit, and deterministic storage/writer/stop faults
on one physical iPhone using synthetic QA data. Those results close the physical
candidate gates for the spike; they do not establish a supported-device matrix
or production readiness. See the [physical-device results](https://github.com/Will1707/tacua/blob/main/experiments/ios-capture-spike/PHYSICAL-DEVICE-RESULTS.md) for the exact scope and measurements.

## Capture-plan contract

Normal host code never constructs the following object. A successful native
`createCaptureSessionPlan` or `resumeCaptureSessionPlan` returns it as
`captureOptions`, after the corresponding backend receipt is committed:

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
  rawMediaExpiresAt: string; // immutable backend START deadline
  consentVersion: 'tacua-local-capture-consent-v1';
  expectedApplicationId: string;
  expectedBuildNumber: string;
};
```

The plan derives organization, project, build, app identifier, native build,
remote handoff ID, credential identifier, credential expiry, and raw-media
expiry from the sealed native profile plus the committed backend receipt. The
only capture tuning value the
host supplies is a finite segment duration from 2 through 60 seconds. Retain
`plan.localSessionId` before calling `start(plan.captureOptions)`: ReplayKit has
not started yet, so that identifier remains available for recovery or backend
deletion if ReplayKit startup later fails.

The lower-level `start(options)` and `resume(options)` functions still validate
safe syntax, expiry, bundle/build identity, and consent before touching local
capture data. They perform no network I/O themselves. The returned plan is the
authenticated bridge between those local functions and the backend lifecycle;
hand-writing its fields is unsupported.

The repository's physical acceptance harness is the sole exception. A native
policy permits its local-only legacy start, resume, discovery, keep, and delete
flow without backend retention authority only when a Debug build, the exact
`com.tacua.capturelab.acceptance` bundle, the local-development QA settings, and
the separate `TacuaLocalHarnessRetentionBypassEnabled` Boolean all agree.
Release builds and every other bundle retain the backend-enforced behavior.

## Backend launch and transport foundation

The host QA target must pin these values in its built `Info.plist`:

- `TacuaSDKProfileJSON` and `TacuaSDKProfileDigest`: the exact canonical,
  backend-compiled public SDK profile and its SHA-256 seal. Install these with
  the package config plugin; do not construct them in JavaScript.
- `TacuaBackendOrigin`: an HTTPS origin with no path, query, fragment, or
  userinfo. A debug build may explicitly opt into loopback HTTP with
  `TacuaAllowInsecureLoopback`; a launch link can never override the origin.
- `TacuaLaunchScheme`: a dedicated lowercase 2–64 character URL scheme registered
  by that target. Browser, OS-service, and Tacua reviewer schemes are rejected.

The accepted START launch URL is:

```text
<TacuaLaunchScheme>://tacua/start?launch_code=<percent-encoded opaque code>
```

The reviewer adds the exact remote-session binding for RESUME:

```text
<TacuaLaunchScheme>://tacua/start?launch_code=<percent-encoded opaque code>&session_id=<remote session id>
```

`prepareBackendLaunch(url)` rejects duplicate or unknown query items,
userinfo, ports, fragments, and any other authority or path. It keeps the
decoded launch code only in volatile native memory and returns a consent request
ID plus `expectedSessionId` (`null` for START and the exact remote session for
RESUME). Before approving RESUME, discover the local queues and select exactly
one whose `getBackendQueueStatus(localSessionId).remoteSessionId` equals that
value; fail closed if none or more than one match. After the host has presented truthful capture consent,
`confirmBackendLaunchConsent(id, true)` returns a one-shot approved handle. The
launch request builder accepts only that handle, so request construction and
exchange cannot happen before affirmative consent. Native code also binds a
RESUME handle to its expected remote session and checks the chosen queue before
clearing the handle, so selecting the wrong queue cannot burn the recovery code.
Decline and cancel discard the transient value.

```ts
const pending = TacuaCapture.prepareBackendLaunch(incomingURL);
// Present the consent UI named by pending.requiredConsentVersion.
const approved = TacuaCapture.confirmBackendLaunchConsent(
  pending.consentRequestId,
  true,
);
const plan = await TacuaCapture.createCaptureSessionPlan({
  approvedLaunchId: approved.approvedLaunchId,
  segmentDurationSeconds: 10,
});
// START is committed; ReplayKit is still stopped.
const receiving = plan.backendSession;
const recording = await TacuaCapture.start(plan.captureOptions);
// After the reviewer stops a complete capture:
await TacuaCapture.stop();
await TacuaCapture.admitFinalizedCapture(plan.localSessionId);
const processed = await TacuaCapture.processAdmittedCapture({
  localSessionId: plan.localSessionId,
});
```

### Backend-managed host controller

`createBackendManagedHostController()` is the dependency-light orchestration
foundation for an Expo QA host. It is intentionally not a React hook and does
not create a second app. A future host screen can subscribe to its immutable
snapshot and render the finite `phase`, `mutation`, and `actions` unions without
reimplementing lifecycle ordering:

```ts
import * as TacuaCapture from '@tacua/mobile-sdk';

const controller = TacuaCapture.createBackendManagedHostController({
  segmentDurationSeconds: 10,
});

const unsubscribe = controller.subscribe((snapshot) => {
  // Render snapshot.phase and snapshot.actions. While mutation is non-null,
  // actions is empty so a UI cannot start an overlapping native mutation.
  renderCaptureState(snapshot);
});

// Forward an incoming link immediately. The controller does not retain the URL,
// launch code, consent-request ID, or approved-launch ID in its public snapshot.
await controller.prepareLaunch(incomingURL);

// Present the exact consent contract named by the awaiting_launch_consent phase.
await controller.respondToLaunchConsent(true);
await controller.exchangeApprovedLaunch();

const next = controller.getSnapshot().phase;
if (next.kind === 'plan_ready' && next.nextAction === 'start_capture') {
  await controller.startPlannedCapture();
} else if (
  next.kind === 'plan_ready' &&
  next.nextAction === 'resume_capture'
) {
  await controller.resumePlannedCapture();
}

// The host still decides when the person stops. Admission remains an explicit
// stopped-capture boundary; transport then runs entirely through native code.
await controller.stopCapture();
await controller.admitAndDrain();

// Call only on a real inactive/background -> active transition. It retries an
// already admitted exact native request, or discovers admitted work after relaunch.
await controller.notifyForeground();

unsubscribe();
controller.dispose();
```

Every mutating method is serialized. Discovery is capped (64 sessions by
default, configurable only from 1 through 128), segment duration stays inside
the SDK's integer 2...60-second bound, and a RESUME link must match exactly one
fresh native queue before consent can be approved. Unknown START/RESUME outcomes
remain operator-reconciliation actions; the controller never guesses whether a
remote exchange succeeded. Subscriber exceptions cannot interrupt lifecycle
work, and public errors expose only a closed controller category plus an
allowlisted, bounded native error code—not native error text.

The fixed interrupted-capture choices are projected as typed actions. With a
current recovered or freshly resumed plan, the host can call
`resumePlannedCapture()` or `keepVerifiedPartial()`. The destructive choice is
the backend-managed `requestAuthenticatedReset()` followed by a separate
`confirmAuthenticatedReset()`; the controller deliberately uses
`deleteBackendSession`, not identity fields or a JS HTTP client. Admission and
upload also call only native SDK primitives, so JavaScript never receives a
bearer secret, constructs backend request bytes, or selects a backend origin,
remote session, deletion reason, build identity, scope, or retention deadline.
The existing native plan bridge does return its validated `CaptureStartOptions`
projection to private controller state because the low-level `start()` and
`resume()` APIs require it. Those plan fields are never included in a public
snapshot, but they do exist in JavaScript memory until the lifecycle no longer
needs them; replacing that pair with an opaque native plan handle is a future
hardening step.

There is one deliberate current API constraint: after process relaunch, an
ordinary committed queue does not expose enough authority to reconstruct
`CaptureStartOptions` in JavaScript. Resume or “keep verified partial” therefore
requires a fresh matching reviewer RESUME launch unless a validated START or
RESUME receipt journal is recoverable. Discovery exposes
`request_resume_launch` for that state. Authenticated reset and replay of already
admitted work remain available without reconstructing those options. Adding a
native queue-to-capture-plan recovery API would remove this extra reviewer-link
step without weakening the secret boundary.

Native code loads the build-time `TacuaSDKProfileJSON`, validates its exact
canonical bytes and digest against the installed app bundle, generates the
local session ID and consent/request timestamp, materializes the dynamic scope,
and calls START. JavaScript cannot supply or override build identity, scope,
retention, timestamp, local session ID, or handoff fields. The two public,
self-digesting artifacts are canonicalized into the crash journal and committed
queue; the one-time launch code and credential secret are never persisted.

At app startup, call `listBackendSessions()` before relying on JavaScript state.
It returns every native-generated identifier currently represented by a START
journal or committed queue, including a START that committed just before the
process died or before its promise resolved. Its presence flags are advisory:
reload `getBackendStartRecoveryStatus(localSessionId)` and
`getBackendQueueStatus(localSessionId)` for each result before presenting a
recovery, resume, upload, or deletion action. Discovery scans START journals,
then queues, then START journals again so the journal-to-queue commit transition
cannot create a false-empty result.

START uses a separate, canonical, secret-free crash journal. It writes the
exchange and credential identifiers, the two bounded canonical public
artifacts, plus a SHA-256 ownership verifier before
the Keychain mutation, marks
`exchange_outcome_unknown` before network I/O, and records a validated receipt
plus the exact monotonic server-time anchor before committing the queue. No
launch code, plaintext secret, Authorization value, or transient launch request
is written to the journal or queue. A validated-receipt recovery can therefore
commit a fully bound queue after process relaunch without JavaScript recreating
historical START input. Recovery deletes a Keychain item only when
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
`recoverStartedCaptureSessionPlan({ localSessionId, segmentDurationSeconds })`
without another launch; this also returns the exact capture options. The
lower-level `recoverBackendStart(localSessionId)` is retained for advanced
diagnostics. Queue recovery is
structural: it remains available after a build transport change or missing
Keychain item. A new START cannot replace that committed queue. Use
`getBackendQueueStatus(localSessionId).resumeRequirement` before requesting a
reviewer launch: only `kind: "resume_session"` may consume a RESUME launch. A
non-null transport configuration change is `blocked`, because frozen session
authority remains pinned to the build that created it. An
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

RESUME derives the remote session ID, previous credential ID, expected session
state, and completion ID exclusively from the committed queue; JavaScript
cannot choose or override them:

```ts
const resumedPlan = await TacuaCapture.resumeCaptureSessionPlan({
  approvedLaunchId: approved.approvedLaunchId,
  localSessionId: plan.localSessionId,
  segmentDurationSeconds: 10,
});
// Credential rotation only: capture/upload/completion flags remain false.
const resumed = resumedPlan.backendSession;
```

For a receiving session, `resumedPlan.captureOptions` carries the rotated
credential and expiry. For a completed session it is `null`: completion-replay
or deletion authority can never be used to restart ReplayKit.

Before launch consumption or network I/O, native code validates the scope/build
binding, queue requirement, monotonic clock, credential history bounds, and
resulting encoded queue capacity. An existing durable artifact pair must match
exact canonical values. A queue migrated with nil/nil artifacts may accept both
validated host artifacts, but installs them only with a successful RESUME; its
receipt journal retains them so crash recovery reproduces the same result queue.
RESUME publishes a secret-free credential
journal before Keychain mutation and `exchange_outcome_unknown` before network
I/O. A validated receipt records exact base/result queue digests and its
original server-time anchor. Recovery accepts only those exact snapshots and
never rewinds the prior authoritative time floor.

Use `getBackendResumeRecoveryStatus(localSessionId)` after startup. A
pre-network `credential_prepared` state can be cleared with
`resetPreparedBackendResume(localSessionId)`. A validated
`receipt_validated_queue_commit_pending` state can be completed without a new
launch via
`recoverResumedCaptureSessionPlan({ localSessionId, segmentDurationSeconds })`,
which returns updated capture options. The lower-level
`recoverBackendResume(localSessionId)` remains an advanced diagnostics API. An
`exchange_outcome_unknown` state cannot be locally reset: the backend may have
revoked credential A and installed B, so deleting B could destroy the only
current authority. It quarantines the queue and reports
`requiresReconciliation: true`; a third queue snapshot reports
`queue_conflict_requires_reconciliation`. Backend-fenced reconciliation is
future work, and neither state is released to uploads. A completed-session
RESUME returns only `completion_replay_or_delete_only` with the exact stored
completion ID and can never restore upload authority. Deleted sessions cannot
resume.

`credentialCapability` records the backend authority last established; it is
not, by itself, a transport-usability signal. Gate transport on the richer
`resumeRequirement`: expiry, a reboot-invalid clock, a missing Keychain item,
or a legacy nil binding returns `kind: "resume_session"`; a changed non-null
binding returns `kind: "blocked"`. `requires_transport_rebind` stays blocked
until RESUME binds the current build. `completion_replay_or_delete_only` permits
only exact completion replay and deletion work, while `deletion_replay_only`
permits only exact deletion replay and receipt-authorized local cleanup. A
deletion-only queue therefore reports `resumeRequired: false` because it is
terminal, not because uploads are allowed. New media uploads require all of
`credentialCapability: "active"`, `resumeRequirement.kind: "none"` with
`reason: "ready"`, and
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
RESUME and refuse to expose a queue while either receipt journal still requires
recovery.
Credential
validity is the half-open interval ending at
`expires_at`; an expired credential or a reboot-invalidated monotonic clock
requires a fresh resume exchange. Exact historical request bytes remain bound to
their original credential ID while the current credential authenticates replay.
If that exact replay finds no durable upload or completion after rotation, the client exposes
`TacuaSDKBackendClientError.backend` only for the backend's canonical, vendor-
typed, at-most-4-KiB reconciliation envelope. The envelope must bind the exact
session, operation kind, operation ID, request digest, historical body credential,
and current transport credential. Unknown codes, extra fields, altered
bindings, wrong content type/status, non-canonical JSON, and oversized bodies
all remain the generic `unexpectedStatus`; error text alone never drives queue
state. A validated historical-miss proof permits one fail-closed rebuild under
the same stable operation ID: only `credential_id`, `requested_at`, and the
derived root digest may change, while every semantic field and payload binding
must remain exact.

Segment uploads are copied through no-follow file descriptors into a bounded,
private immutable snapshot before `URLSession` opens them. Snapshot publication
fsyncs the newly created staging directory and parent, makes the file read-only
before its final fsync, and reopens the path with `O_NOFOLLOW` to prove that file
protection was applied to the descriptor-created inode. Failed snapshots are
unlinked and directory-synced before the attempt returns.

The transport deliberately uses an ephemeral in-process `URLSession`, not a
durable iOS background session. Locking, process suspension, termination, or
loss of connectivity can therefore interrupt a request. The durable queue marks
an operation outcome-unknown before network I/O and retries its exact canonical
bytes after relaunch; V1 does not claim that an upload continues while the host
process is suspended or dead.

A completion receipt is the sole payload-cleanup authority. Native validation
first proves that its cleanup manifest binds the exact admitted segment,
sidecar, sanitized diagnostic, and private source-journal digests. Cleanup then
atomically hides and retires the whole local session directory rather than
deleting only the expected files, so corrupt manifests, partial files, upload
snapshots, and other session remnants cannot survive success. The no-follow,
descriptor-relative traversal never follows a symlink and preserves any target
outside the session. A deletion tombstone scoped to `session_all_data` is the
sole credential-cleanup authority and intentionally does not depend on a
readable local manifest.

`admitFinalizedCapture(localSessionId)` is the normal explicit
local boundary between capture and transport. It holds the same cross-process
lease as START/RESUME, refuses either recovery journal, verifies every manifest,
MOV, and sidecar through no-follow descriptors, and materializes an immutable
secret-free admission artifact. It derives dense wire sequences and segment
`time_range` values from verified sidecar host uptime relative to the persisted
session start—never from wall-clock timestamps or array position. Stable IDs are
`segment_000000`/`upload_segment_000000` and
`envelope_capture_000001`/`upload_diagnostic_000001`.

Admission derives build identity and scope from the committed queue.
`advancedAdmitFinalizedCapture({ localSessionId, buildIdentity, scope })`
remains available only as a migration path: if the queue already has
artifacts, supplied values must be their exact canonical match; a legacy nil/nil
queue requires both until a successful RESUME backfills them. One missing field,
a substituted valid artifact, an invalid digest/schema, or a queue binding
mismatch fails before any admission file is materialized. Inspect
`getBackendQueueStatus(localSessionId).sessionArtifactsAvailable` to distinguish
the legacy case.

Admission projects the private journal into one SDK-owned diagnostic envelope,
merges sanitized manifest marks/gaps that were not already journaled, and always
appends a terminal `custom_state` event from provider `capture_summary`. The
summary hash contains only allowlisted counts and availability booleans. Native
journal sequence and uptime are the chronology source; the envelope reassigns a
dense sequence after deterministic merging and maps uptime to the same-boot
server-time anchor. A torn final journal append is truncated and represented as
an unavailable `custom_state` event plus an explicit
`diagnostic_collection_paused` collection gap; it never invents a capture gap.
Every diagnostic `capture_gap` instead uses the exact sanitized identifier of a
real capture-manifest gap. New journals stop at 9,998 events, reserving the
terminal summary and a content-free `diagnostic_projection_overflow` signal.
Admission preserves manifest marks/gaps before routine diagnostics, reports the
exact omitted count and time range, and deterministically constrains the final
canonical envelope to four MiB. It can still recover a torn legacy 9,999-event
journal into the runtime's 10,000th hard slot before bounded projection.
Capture manifests accept at most 2,048 manual markers and 2,048 gaps; the final
gap slot coalesces additional interruptions into an explicit overflow sentinel.
Interior corruption, reordering, deletion, an unsafe path, or a different boot
fails closed.

The diagnostic upload operation binds the immutable envelope first and, when a
journal exists, the exact private source journal second at
`diagnostics/<localSessionId>.diagnostics-v1.jsonl`. Transport uploads only the
sanitized envelope; the source binding exists so receipt-authorized cleanup can
retire both local artifacts. Marker labels, error strings, raw request/response
bodies, query strings, headers, UI values, handoff fields, launch codes,
credentials, narration text, and raw custom-state values are not copied into
the journal, diagnostic, or admission artifact. Exact validated build/scope values, START
retention deadlines, and the server-time anchor are persisted so later dispatch
and completion can restart without asking JavaScript to recreate authority.
Admission performs one queue compare-and-swap and no network I/O. Exact retries,
including retries after credential rotation, are idempotent; partial or different
stable-ID occupancy is a conflict. Queues created before durable START retention
authority fail closed. Admission also requires a schema-3 or schema-4 capture whose persisted
boot identity matches both the queue time anchor and the current boot; legacy
schema-2 captures have no provable host-uptime chronology and fail closed.
Schema-3 remains uploadable for legacy debugging, but admission labels its
count-only app-audio accounting incomplete and projects a full-run `unknown`
app-audio gap. Schema-4 interrupted evidence is admitted only when its durable
unknown index ranges are internally consistent; admission projects an explicit
`process_terminated` app-audio gap rather than claiming complete accounting.

Sidecar bytes, including non-allowlisted metrics, remain local until
completion-authorized cleanup; segment upload still transmits only their
`sidecar_digest`. For schema 4, admission copies the verified, privacy-safe
app-audio accounting subset into the sealed completion manifest as
`app_audio_accounting`: ordered runtime-segment bindings, attempt ranges, exact
drop indexes and closed causes, reservation high-watermark, and ordered unknown
ranges. The backend persists that manifest and supplies it as
`capture.manifest` to the asynchronous processor after local sidecar cleanup.
Schema 3 projects `null`. The reviewer UI currently exposes only the processor's
derived candidate, evidence, and SDK timeline; it does not render this raw
accounting object directly.

## SDK-local raw-media retention

The START receipt fixes `raw_media_expires_at`; RESUME rotates transport
credentials and advances the server-time anchor but cannot replace or extend
that deadline. Local raw data is usable only on the half-open interval before
the deadline. On the same boot, the SDK evaluates `max(server/monotonic floor,
system wall observation)` and passes ReplayKit an absolute monotonic stop uptime,
so rolling the device clock backwards cannot extend recording or transport.
Admission checks retention before and after materialization, and upload checks
it while holding the existing lifecycle lease before every durable drive step
and again after terminal completion.

At relaunch, a bounded sweep discovers durable queues, START and RESUME journals
(including corrupt exact-name journals), live capture directories, and hidden
`.tacua-retiring-*` directories left by a crash. A current system-wall
observation at or after the immutable deadline is sufficient only to retire
data. Before the deadline after a reboot, raw capture and transport remain
blocked until authenticated RESUME supplies a current-boot server anchor. An
observation below the persisted server floor is treated as rollback. No offline
mobile SDK can prove correct time against arbitrary device-clock tampering, so
this is deliberately not a claim that a pre-deadline relaunch can derive trusted
time without the backend.

Expiry atomically renames and drains the exact capture tree (segments,
sidecars, diagnostics, admission artifacts, and queued upload snapshots), then
removes known Keychain credentials and exact START/RESUME journals. The durable
queue is fsynced and unlinked last, remaining as the immutable authority and
retry journal if protected storage or another cleanup step is unavailable.
Retries and relaunch recovery are idempotent. Missing, corrupt, or conflicting
retention authority fails closed rather than selecting a later deadline.

## Async processing and authenticated deletion

`processAdmittedCapture({ localSessionId })` drives the durable queue until all
segment and diagnostic receipts, one completion receipt, and receipt-authorized
local retirement are committed. It holds capture/lifecycle leases for the whole
drive. Before every request it durably transitions the operation from
`prepared` to `outcome_unknown`; cancellation or transport failure never rewinds
that state. A later call replays the exact canonical request and local payload
binding. Every in-flight send races the same absolute monotonic retention stop;
the concrete URLSession task is cancelled at the boundary, late receipts cannot
commit, and cleanup failure is reported separately while `outcome_unknown`
remains available for retry. The function resolves only after the session directory has been
retired, and an already-completed retry performs no network I/O.

```ts
const processed = await TacuaCapture.processAdmittedCapture({
  localSessionId: 'local_qa_001',
});
// processed.payloadCleanupState === 'payloads_removed'
```

`deleteBackendSession({ localSessionId })` is the authenticated V1 privacy
reset. JavaScript cannot select a remote session, credential, operation ID,
reason, or timestamp: native code derives them from the validated queue and
always uses `deletion_user_requested_000001` with reason `user_requested`. It
accepts active or completed-session deletion authority, gates unresolved START
and RESUME recovery, and persists exact request bytes before transport.

After independently validating the returned tombstone, native code retires the
entire local capture directory, removes pending and current Keychain
credentials, writes a minimal non-sensitive finalization proof, and only then
unlinks the sensitive transport queue. The call resolves after all of those
steps are durable. A retry after finalization uses the proof and performs no
network I/O; an unknown first-attempt outcome remains an exact replay and is
never guessed or rewritten. Because the tombstone covers `session_all_data`,
this path can retire a corrupt or unreadable local manifest without trusting
that manifest.

```ts
const deleted = await TacuaCapture.deleteBackendSession({
  localSessionId: 'local_qa_001',
});
// All three are literal `true` only after durable finalization.
deleted.remoteDataDeleted;
deleted.localSessionRetired;
deleted.credentialRemoved;
```

## Fixed recovery choices

After interruption, the host UI can offer exactly three local actions:

1. `resume(options)` reconciles verified segments, creates an explicit `process_resume` gap, and records into new segment indexes. Its remaining budget is 30 minutes minus the durations of already verified segments. Resume requires a schema-3 or schema-4 manifest from the current boot plus a fresh, unexpired handoff for the original stored identity and the currently installed app build. A resumed schema-4 capture first seals any unused durable reservation as an explicit unknown range, continues strictly after that range, and permanently sets `appAudioAppendAccountingComplete` to `false`; recovery never reuses or invents the prior writer tail. Legacy schema-2 and cross-boot sessions remain listable/finalizable/deletable but cannot restart ReplayKit.
2. `markPartialReadyForUpload(options)` reconciles verified media and changes only the local manifest state to `partial_ready_for_upload`. It requires at least one verified segment and a fresh matching handoff. It does **not** upload, enqueue, transmit, or delete anything.
3. `deleteSession(options)` removes the local session directory. Erasure remains available after handoff expiry, consent-contract changes, and app upgrades. It validates the safe session ID, stored organization/project/handoff identity, and current application identifier, but intentionally does not require the original build number to equal the currently installed build.

`listRecoverableSessions()` returns metadata, including the immutable raw-media
deadline required for exact Resume, but does not expose handoff identifiers. If
a manifest is unreadable it reports `manifest_unreadable`; the
local-only `deleteSession(options)` path still refuses identity-blind deletion.
When a committed backend queue and usable credential exist,
`deleteBackendSession` is the authenticated scoped fallback and does not trust
the manifest. The host product must still present that destructive action to
the user explicitly.

Raw `partial` state is never backend-admissible. A person must first choose
`markPartialReadyForUpload(options)`; only `completed` and the resulting explicit
`partial_ready_for_upload` state cross the admission boundary.

## App-audio acceptance artifact

After a stopped, accounting-complete physical run, copy only its private
`manifest.json` into an operator-controlled temporary directory. Generate the
closed ADR-018 artifact offline; the command validates the derived object before
publishing it atomically:

```sh
python3 ../scripts/generate_app_audio_acceptance.py \
  /private/path/to/manifest.json \
  --run-id physical-audio-001 \
  --evidence-class physical_device \
  --output /private/path/to/app-audio-acceptance.json

python3 ../scripts/validate_app_audio_acceptance.py \
  /private/path/to/app-audio-acceptance.json \
  --source-manifest /private/path/to/manifest.json
```

The generator accepts only schema 4 with complete accounting, no process resume,
the gap-free `completed` state, no stable errors, contiguous segment ranges,
exact totals, and every dropped attempt recorded once. It refuses schema-3 history,
`partial` or recovered runs, missing or
duplicate indexes, and inconsistent sidecars instead of inferring data. The
result is canonical compact JSON for
`tacua.app-audio-acceptance@1.0.0` and binds the exact source-manifest bytes plus
application, build, build-number, session, and schema identity. The
validator requires those artifact bytes to be canonical UTF-8 JSON with one
trailing newline; alternate encodings and merely equivalent pretty JSON fail.
`physical_device` class is an explicit operator claim, not hardware attestation;
the signed-device run record must independently support it. The physical
validator requires the same source manifest and rejects byte or identity
substitution.
The manifest and artifact may expose capture measurements; keep them private
until the aggregate evidence has been reviewed.

## Example

```ts
import * as TacuaCapture from '@tacua/mobile-sdk';

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

const digest = 'a'.repeat(64); // SHA-256 hex from the host's allowlisted snapshot provider
await TacuaCapture.start(options);
await TacuaCapture.recordRouteTransition({
  fromRoute: '/projects/{project_id}',
  toRoute: '/projects/{project_id}/review',
  trigger: 'user',
});
await TacuaCapture.recordUserInteraction({
  action: 'tap',
  target: 'review_submit', // stable semantic ID, never rendered/user-entered text
});
await TacuaCapture.recordNetworkRequestCompleted({
  method: 'POST',
  host: 'api.example.test',
  pathTemplate: '/reviews/{review_id}', // never a raw URL or query string
  statusCode: 503,
  durationMilliseconds: 250,
});
await TacuaCapture.recordCustomState({
  providerId: 'navigation_snapshot',
  collectionStatus: 'available',
  snapshotDigest: `sha256:${digest}`, // digest only; no raw snapshot API exists
});
await TacuaCapture.mark('wrong-copy');
const terminal = await TacuaCapture.stop();
```

## Verification

Run the platform-independent policy tests from this directory:

```sh
sh tests/run-core-tests.sh
```

The tests cover terminal classification, deadline behavior, media-clock segment boundaries, dual-clock microphone stall detection, crash-window source selection, structural handoff validation, expiry/build-independent deletion authorization, and fail-closed stop-timeout decisions.

They also exercise canonical JSON and the frozen SDK/backend fixtures, the
privacy-bounded hash-chained diagnostic journal, torn-tail recovery, deterministic
journal/manifest projection, source-journal binding, strict
nested diagnostic and completion-manifest validation, launch-link and consent
gating, Keychain abstraction, build-pinned origin handling, half-open credential
expiry, rotation recovery, exact replay across multiple credentials, bounded
HTTP responses, redirect rejection, private upload snapshots, and
receipt-to-local-file cleanup binding. Upload orchestration coverage includes
exact cancellation replay, completion construction, terminal idempotency, and
whole-session retirement, with retention rechecked between network operations.
Local-retention coverage includes before/at/after boundaries, server/monotonic
rollback resistance, cross-boot reconciliation, conflicting authority,
relaunch discovery of hidden and corrupt-journal state, partial cleanup,
protected-storage retry, exact credential/journal/payload drainage, and
held-lifecycle-lease operation without nested reacquisition. Authenticated
deletion coverage includes fixed
request identity, independent tombstone validation, corrupt manifests,
Keychain ordering, queue finalization, cancellation, CAS ambiguity, and replay
after crashes. Adversarial local files include paths outside the session,
symlinks, directories, FIFOs, digest mismatches, sparse files larger than 1 GiB,
and protected or unexpected files inside a retired session. External symlink
targets must survive.

The core suite also drives the START lifecycle through success, preflight and
one-shot-consent rejection, ambiguous transport failure, acknowledged local
reset, validated-receipt queue recovery, delayed recovery, reboot recovery, and
queue/journal mismatch. It asserts journal-before-Keychain ordering and scans
every durable START artifact for prohibited launch-code and secret material. It
also covers canonical build/scope retention, headless artifact recovery,
schema-1 nil-artifact migration, artifact substitution/corruption, missing-Keychain
and changed-build receipt recovery, durable journal
removal confirmation, duplicate-ID crash recovery, lifecycle-serialized queue
status, stale queue CAS rejection, and private storage modes. RESUME coverage
includes receiving and completed authority, V2 transport binding,
deterministic pre-network rejection, non-abandonable unknown outcomes, exact
base/result CAS recovery, server-time non-regression, credential cleanup,
START/RESUME cross-gating, exact-match-or-backfill artifact behavior, and secure
canonical journal storage. Admission tests cover hostless current queues,
explicit legacy input, rejection before materialization on host substitution,
the exact 9,998-event boundary with late manifest signals, deterministic overflow,
legacy 9,999-event torn-tail recovery, bounded repeated recovery gaps, and the
runtime relation that every diagnostic capture-gap ID exists in the capture manifest.

They also cover fail-closed storage thresholds, lifecycle sample admission,
multi-boundary catch-up, and the exact QA fault-plan parser/matchers. The test
runner syntax-parses every native source both with and without the dedicated
fault condition, compiles and runs the platform-independent policy and fault
tests, and verifies that plan names do not appear in a non-fault binary. A full
Xcode build of a generated Expo app remains a release gate; the repository
verification and tag-release workflows compile that native integration.

Physical fault injection is available only in the Capture Lab build and is
excluded at compile time from ordinary builds. Its four independent gates,
supported plans, acceptance criteria, evidence boundary, and mandatory cleanup
are defined in the
[fault-injection runbook](https://github.com/Will1707/tacua/blob/main/experiments/ios-capture-spike/FAULT-INJECTION-RUNBOOK.md).

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
- [ ] Pass the accepted V1 app-audio gate: no more than 0.2% of append attempts
  may drop, and every drop must appear exactly once in an explicit
  `app_audio_append_drop` gap. The historical 30-minute run's 121/77,523 rate
  (about 0.156%) is numerically below the ceiling, but it did not record those
  drops as gaps and therefore fails the machine-checkable acceptance artifact.
- [ ] Replace structural handoff fields with a cryptographically authenticated,
  backend-issued handoff scoped to the organization, project, build, and current
  consent contract.
- [x] Implement and fixture-test the canonical V1 backend requests, exhaustive
  receipt validation, Keychain credential abstraction, durable replay queue,
  bounded HTTP client, and integrity-checked segment upload snapshot.
- [x] Connect an explicitly admitted stopped capture to the
  START/RESUME-established queue in one local atomic boundary, drive exact
  segment/diagnostic upload and completion, retire the full local session after
  receipt validation, and implement exact authenticated backend deletion.
  `stop()` itself still does not enqueue or upload.
- [x] Implement authenticated, manifest-independent deletion that can retire a
  corrupt or unreadable capture manifest only after a validated backend
  `session_all_data` tombstone.
- [ ] Expose that reset through a deliberate, user-visible destructive-action
  UI in the tested QA app and verify protected-file behavior in the production
  integration.
- [x] Enforce the immutable backend raw-media deadline over SDK-owned capture,
  queue, lifecycle-journal, and credential state, including relaunch and partial
  cleanup recovery.
- [x] Keep the checked-in backend and optional local processor default-deny for
  external egress, with no model, connector, provider credential, or automatic
  processor configured.
- [ ] Define and verify explicit destination, credential, evidence-scope, and
  retention authorization for every real processor or connector selected later.
- [ ] Re-run physical compatibility and resource measurements after the
  production transport and security boundaries replace this spike.

Until those gates close, use this package only for explicitly approved QA
experiments. The transport client can send evidence only to the build-pinned
Tacua backend origin; this package performs no direct external-model egress.
