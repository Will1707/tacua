# ADR-012: V1 reviewer app, embedded SDK, and backend boundary

- Status: accepted
- Date: 2026-07-21
- Scope: Tacua V1 architecture

## Context

Tacua must let a reviewer begin a narrated QA session, collect evidence from the
app under test, process that evidence asynchronously, and approve candidate
tickets. On iOS, ReplayKit app-only capture belongs to the host application and
the resulting files live inside that application's sandbox. A separate Tacua
application cannot record another app through the selected V1 API or read the
other app's local capture directory.

The first pilot may expose temporary capture controls inside the QA build, but
that expedient must not collapse the product into an SDK-only bug reporter.

## Decision

Tacua V1 has three first-party runtime components with explicit ownership:

1. **Tacua iOS reviewer app** owns project/build selection, review launch,
   processing status, recovery guidance, candidate editing, split/merge/reject,
   approval, and handoff export.
2. **Tacua development-build SDK** is embedded in the app under test. It owns
   consent enforcement, ReplayKit capture, narration, SDK diagnostic events,
   segmented local recovery, the offline queue, integrity-checked upload, and
   deletion of local media after an authenticated receipt.
3. **Tacua self-hosted backend** owns authenticated session grants, durable
   media and structured state, asynchronous transcription/alignment/research,
   candidate tickets, audit state, retention/deletion, and approved handoffs.

The normal launch flow is:

1. The reviewer selects an authorized project and build in Tacua.
2. The backend creates a short-lived, single-use launch code bound to the
   organization, project, tested application/build, and consent contract.
3. Tacua deep-links to the QA build with the opaque launch code. The code is not
   a reusable upload bearer and must not contain evidence or credentials.
4. The embedded SDK verifies that it is an authorized QA build, presents the
   exact capture and upload consent policy, and records the explicit grant
   before sending the launch exchange. It creates and securely persists its
   client credential before that exchange.
5. The SDK exchanges the code only with its build-pinned backend origin. The
   backend validates the code, build/configuration binding and consent contract;
   the SDK then validates the returned scope against the installed app/build
   before starting capture.
6. The SDK uploads verified media segments and diagnostic envelopes directly to
   the backend. The reviewer app observes backend state; it never reads the
   tested app's sandbox.
7. The reviewer returns to Tacua to review and approve generated candidates.

Raw upload credentials must not be persisted in capture manifests, emitted to
logs, or embedded in exported tickets. Offline retries may retain only the
minimum scoped credential material in platform secure storage, with expiry and
revocation enforced by the backend.

The pilot may start and stop capture from a QA-only screen inside the app under
test before the deep-link launcher is complete. That screen is transitional;
it uses the same SDK-owned storage, recovery, upload, and backend contracts as
the final flow.

## Consequences

- Tacua is not an SDK-only product. The SDK remains a removable collection and
  transport component; ticket processing and approval stay outside the tested
  application.
- Recovery actions that require local files must execute in the tested app. The
  reviewer app can explain the state and deep-link back to the appropriate
  recovery action.
- The SDK, rather than the reviewer app, must implement resumable and idempotent
  upload with server receipts before local deletion.
- A target-app crash does not grant the reviewer app access to its files;
  verified segments remain recoverable when that target app relaunches.
- Whole-device and cross-application recording remain outside V1. Supporting
  them later would require a separate platform decision and threat model.
- Production/App Store targets must exclude the capture SDK and its recording
  permissions or entitlements; only explicitly authorized QA/development builds
  may link it.

## Rejected alternatives

- **SDK-only product:** would duplicate project, processing, and approval UI in
  every tested app and would not provide a durable cross-project review system.
- **Reviewer app records the tested app:** is incompatible with the selected
  app-only ReplayKit and iOS sandbox boundary.
- **Reviewer app imports raw local files:** requires unsafe cross-application
  sharing and weakens recovery, authorization, and deletion guarantees.
- **Whole-device broadcast capture for V1:** materially expands consent,
  extension, privacy, and App Review risk without being required for the first
  in-app QA workflow.
