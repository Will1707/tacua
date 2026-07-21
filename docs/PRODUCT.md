# Tacua V1 product boundary

This document is the sanitized public product contract for Tacua. It records the
decisions that are stable enough to guide experiments and contributions without
publishing private interviews, pilot repositories, recordings, or environment
evidence. Everything described here is planned unless the repository explicitly
labels an implementation or experiment as complete.

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

## Product shape

Tacua has three planned first-party parts:

- an iOS reviewer app for capture launch, progress, recovery, candidate review,
  and approval;
- a development-build SDK embedded in the app being tested; and
- a provider-neutral Docker deployment containing the API, durable processing,
  structured state, and media storage interfaces.

The SDK is essential: screen recording alone does not give a coding agent enough
context to distinguish a visual symptom from navigation, application state,
network, console, or backend behavior. The exact event set and storage topology
remain subject to measured experiments. The public SDK candidate intentionally
implements only the local capture and recovery boundary today.

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

The repository contains candidate contracts and risk-reduction experiments, not
a deployable V1. Local synthetic contract suites pass, and the capture SDK has
compiled and linked inside an isolated arm64 iOS Simulator host. Physical-device
ReplayKit behavior, 30-minute resource limits, upload/processing, runtime
security, real-agent outcomes, and an operator-ready Docker topology are still
release blockers.
