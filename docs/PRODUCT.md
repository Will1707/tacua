# Tacua V1 product boundary

This document is the sanitized public product contract for Tacua. It records the
decisions that are stable enough to guide experiments and contributions without
publishing private interviews, pilot repositories, recordings, or environment
evidence. Everything described here is planned unless the repository explicitly
labels an implementation or experiment as complete.

The separate [release-readiness assessment](RELEASE-READINESS.md) records which
foundations are implemented, what each verification level proves, and which
owner, device, integration, and production gates remain open.

## Purpose

Tacua reduces the reviewer's active time between noticing a mobile-app problem
and handing a reproducible, evidence-backed ticket to a coding agent. It is for
developers and product managers reviewing React Native applications whose
implementation work may have been performed substantially by AI agents.

The primary outcome is not faster model processing. It is less human time spent
capturing screenshots, reconstructing steps, collecting debugging context,
writing several tickets, and answering avoidable follow-up questions.

## Planned V1 workflow

1. The reviewer chooses a project and development build in the Tacua iOS app.
2. Tacua opens the app under test, whose QA build contains the removable Tacua SDK.
3. After explicit consent, the reviewer records the tested app for up to 30
   minutes and narrates issues while walking through it.
4. The SDK preserves segmented app-only media and aligned diagnostic events. It
   records explicit gaps rather than claiming continuity across an interruption.
5. Completed segments remain recoverable offline and later upload to the
   self-hosted backend. After a crash or force-quit, the reviewer can resume,
   submit the verified partial session, or delete it.
6. Asynchronous workers transcribe, align, research, and create zero, one, or
   several evidence-linked candidate tickets. Processing may use local models or
   explicitly configured model APIs.
7. The reviewer edits, splits, merges, rejects, or approves each candidate in
   Tacua. Approval is the point at which a candidate becomes an agent handoff; AI
   generation alone never grants execution authority.
8. V1 exports an approved ticket as canonical Markdown and JSON. Tracker sync,
   including Linear, is deferred.

The split/merge boundary is fixed by accepted
[ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md): one atomic
replacement supersedes the exact source heads without rewriting their history,
and a merge uses the canonical lossless union of source evidence. The portable
contract, backend transaction, and reviewer controls are implemented; a complete
physical reviewer workflow remains an external gate.

## Product shape

Tacua has three planned first-party parts:

- an iOS reviewer app for capture launch, progress, recovery, candidate review,
  and approval;
- a development-build SDK embedded in the app being tested; and
- a provider-neutral Docker deployment containing the API, durable processing,
  structured state, and media storage interfaces.

The ownership and launch boundary between those components is fixed in
[ADR-012](decisions/ADR-012-v1-component-boundary.md). The embedded SDK owns
capture, local recovery, and upload because app-only ReplayKit media remains in
the tested application's sandbox; the reviewer app orchestrates sessions and
reviews backend-owned candidates.

The SDK is essential: screen recording alone does not give a coding agent enough
context to distinguish a visual symptom from navigation, application state,
network, console, or backend behavior. The exact event set and storage topology
remain subject to measured experiments. The public SDK candidate implements the
local capture/recovery boundary, a sealed native START/RESUME bridge, explicit
stopped-capture admission, retry-safe upload and completion, receipt-authorized
local retirement, and authenticated deletion. These operations are connected
as explicit host calls rather than hidden inside `stop()`, so consent and
failure recovery remain visible.

## Fixed V1 boundaries

- iOS is required for the first release; Android follows later.
- Capture is limited to the app under test, not the whole device display.
- The SDK is enabled only in explicitly authorized QA/development builds.
- One self-hosted deployment represents one organization. Multiple projects and
  members are allowed, but cross-customer multi-tenancy is not.
- Raw video and audio default to 30-day retention. Operators may shorten or
  explicitly configure policy; deletion must cover derived data and caches.
- Source repositories and debugging/analytics connectors are read-only.
- External egress is default-deny and must be visible, scoped, and authorized.
- Accessibility includes VoiceOver, large Dynamic Type, reduced motion,
  contrast, and non-audio alternatives for important information.
- Apache-2.0 applies uniformly to first-party source in this repository.

## Evidence and observability

Tacua will own a small, versioned evidence envelope so core capture and handoff do
not require a particular telemetry vendor. Optional adapters may ingest or emit
OpenTelemetry when that improves interoperability. A mandatory OpenTelemetry
runtime dependency is not accepted until a concrete integration requires it.

Evidence may include media timing, reviewer issue marks, navigation and
interaction breadcrumbs, build identity, sanitized console/runtime failures,
network request metadata, and references returned by authorized read-only
connectors. Raw credentials, authorization headers, stable personal identifiers,
and unrestricted payload capture are outside the allowed contract.

## Human approval

“Human approval” means the reviewer confirms the exact ticket version and its
evidence before it can be handed to an implementation agent. It does not mean
the reviewer must supervise transcription or research. The long-running work is
asynchronous; Tacua may ask concise, choice-oriented clarifying questions when an
answer is likely to prevent incorrect implementation.

Approval does not by itself authenticate an execution request. The candidate
handoff contract separates structural validity from short-lived external
authorization, repository scope, and current build/evidence scope.

## Explicitly deferred

- production or App Store builds containing active capture;
- whole-device or cross-application recording;
- autonomous ticket execution without approval;
- a hosted Tacua control plane or required Tacua cloud service;
- cross-customer multi-tenancy;
- Android release support;
- tracker synchronization; and
- a promise of a specific database, object store, queue, identity provider,
  model provider, or observability vendor before the relevant experiments pass.

## Current proof level

The repository contains candidate contracts, risk-reduction experiments, and a
non-production reviewer/backend/SDK foundation, not a deployable V1. Local
synthetic contract and integration suites pass. `EXP-001` also completed
its physical candidate gates on one iPhone using synthetic QA data: foreground
narration and app audio, static-screen segmentation, the 30-minute limit, lock
recovery, process interruption, the fixed recovery choices, scoped deletion,
and deterministic storage/writer/stop fault handling. Every segment accepted as
evidence matched its manifest byte length and SHA-256 value; the detailed scope
and measurements are recorded in the
[physical-device results](../experiments/ios-capture-spike/PHYSICAL-DEVICE-RESULTS.md).

That result proves a local capture candidate, not a production SDK. Since the
physical campaign, the repository has added a backend-issued launch exchange,
authenticated retry-safe upload protocol, tested runtime retention/deletion,
immutable evidence-linked candidate review, atomic structural handoff export,
atomic split/merge replacement, an opt-in offline isolated processor boundary,
and separate short-lived Codex execution assertions. The SDK and backend pieces
are now connected in code and simulator builds, but not yet in a physical
capture-to-reviewed-ticket run. They do not authorize external model egress,
and structural approval alone does not authorize agent execution. The accepted
app-audio ceiling is 0.2% only when every drop is an explicit gap. A later
schema-4 physical run with clearly labeled synthetic narration recorded and
accounted for all 21 drops across 77,521 attempts (about 0.027%) and passed
against its private exact manifest. That closes the narrow ADR-018 machine
gate, not human manual QA or the complete physical capture-to-ticket release
gate. The SDK implements
authenticated, manifest-independent deletion, but the tested QA app still needs
to expose that reset as an explicit destructive action. Protected-file behavior
and that host UI both require production-integration verification.

An operator-selected transcription/research implementation and any authorized
read-only repository or telemetry connectors, automatic foreground upload
draining in a host app, real external execution keys plus nonce-consuming Codex
launch integration, a pilot-to-agent outcome, the physical end-to-end rerun,
and an operator-validated Internet-facing deployment remain release blockers.
