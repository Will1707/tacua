<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua release readiness

Tacua is a pre-release, self-hosted foundation. It is not yet an
Internet-facing production service or a generally released mobile SDK. This
document separates code and deterministic test coverage from the external
evidence still needed for an authorized pilot and production promotion.

The presence of a test or workflow is not itself a passing result. A release
candidate is repository-verified only when the complete `Verify` workflow is
green for the exact immutable commit being promoted. Synthetic fixtures,
simulator builds, and one-component device experiments are useful evidence, but
none substitutes for the physical capture-to-approved-ticket workflow.

The implemented V1 architecture's repository-owned source/design threat review
is complete in the [security model](SECURITY-MODEL.md). That static review does
not close the production gate: the exact mobile integration, processor,
connectors, agent runtime, credentials, host, network, storage, and operations
still require the model's deployment-specific overlays and live validation.

## Current implementation boundary

| Area | Implemented foundation | Proof boundary |
| --- | --- | --- |
| iOS capture | App-only ReplayKit capture, narration and app audio, bounded segmentation, issue marks and gaps, a 30-minute design limit, interruption recovery, and scoped local deletion. | The capture candidate passed its documented synthetic-data campaign on one physical iPhone. That campaign predates the complete SDK-to-backend path and is not a supported-device matrix. |
| Mobile SDK lifecycle | A QA-build-only gate; sealed build, backend, consent, scope, and retention profile; consent-gated START and RESUME exchange; crash journals; native session discovery independent of prior JavaScript state; exact replay; stopped-capture admission; diagnostic projection; upload, completion, local retirement, server-anchored local expiry sweeping, and backend deletion. | Swift, TypeScript, config-plugin, and generated Expo/iOS build checks cover the implementation. The full lifecycle has not yet passed on a physical QA build. Upload uses an in-process foreground session: suspension or termination can stop progress, and the host must drain the durable queue again after relaunch. Expiry is checked when discovery or another lifecycle boundary runs. A reboot before the raw deadline blocks raw-data use until authenticated RESUME establishes a current-boot server-time anchor; this is deliberate fail-closed behavior, not continuous background enforcement. |
| Self-hosted backend | A single-organization, single-process Python/SQLite service whose current pilot configuration pins exactly one project, application, tested build, reviewer identity, and administrator credential per deployment; exact SDK receipts; integrity-checked storage; retention and deletion; immutable job and candidate histories; atomic candidate publication and handoff export; sealed configuration; health, preflight, backup, restore, and smoke tooling; hardened Docker definitions. Backup manifest v2 binds and recomputes the earliest retained raw/derived session-evidence deadline and refuses verification plus dry-run or applied restore at expiry. This singular deployment scope is an implementation limit, not a narrowing of the product's future multi-project/member boundary. | Unit and contract suites plus the checked-in Docker CI job exercise these boundaries. Expiry refusal does not destroy off-host bytes, and this is not evidence that a real host, TLS proxy, firewall, storage device, backup destination, destruction lifecycle, or upgrade procedure has been operated successfully. |
| Processing | Durable processing jobs; an opt-in, provider-neutral, shell-free command adapter; and the accepted [ADR-016](decisions/ADR-016-local-processor-isolation.md) host runner/Compose profile for an operator-selected private-pilot processor. Normal backend startup is inert and default-deny for egress. | No transcription model, LLM, repository connector, telemetry connector, API provider, image, model, or command is selected. The isolated profile is separately identified, offline, read-only and resource-bounded, but the exclusive worker still runs only while the HTTP service is stopped and is not an unattended production worker. |
| Reviewer app | Secure self-hosted configuration; display of the single registered build projection and launch-code orchestration; recovery guidance; session, evidence, preview, and job views; candidate editing and clarification; atomic split/merge replacement; exact-version approval; integrity-checked canonical Markdown/JSON sharing. | [ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md) is accepted and its backend/reviewer replacement controls are implemented with deterministic tests pending the complete repository verification run. A physical reviewer-to-QA-app-to-review run remains outstanding. |
| Handoff | Immutable candidate versions, evidence binding, exact approval, canonical Markdown/JSON export, and the accepted local/private-pilot Codex execution policy in [ADR-017](decisions/ADR-017-codex-execution-trust.md). | Structural fixtures do not authorize an agent. The repository gate requires current registry trust plus a 15-minute, exact-scope, unrevoked `codex exec` assertion; all checked-in keys are synthetic. A trusted real consumer trial and any remotely distributed production key design remain external gates under [ADR-011](decisions/ADR-011-approved-handoff.md). |
| SDK distribution | A pre-release `@tacua/mobile-sdk` tarball boundary, checksum validator, and tag-triggered GitHub prerelease workflow. Registry publication remains disabled; this does not make the Apache-2.0 source private. | No SDK release exists until the protected, signed release tag is pushed from a verification-green default-branch commit and the release workflow succeeds. See the [maintainer runbook](maintainers/MOBILE_SDK_RELEASE.md). |

## Accepted V1 operational decisions

- [ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md) accepts atomic
  replacement, exact source consumption, and lossless evidence-union semantics
  for split and merge; backend/reviewer implementation is present pending the
  complete repository verification run.
- [ADR-016](decisions/ADR-016-local-processor-isolation.md) accepts the offline,
  separate-UID/container, bounded private-pilot processor gate without choosing
  or downloading a processor or model.
- [ADR-017](decisions/ADR-017-codex-execution-trust.md) accepts OpenAI Codex as
  the V1 execution consumer only through a current, exact-scope, short-lived,
  unrevoked local assertion and the fixed non-interactive ephemeral
  `workspace-write`, network-off, structured-output profile. Approval alone is
  non-executable.
- [ADR-018](decisions/ADR-018-v1-app-audio-acceptance.md) accepts a maximum 0.2%
  app-audio append-drop rate only when every drop is recorded exactly once as a
  gap. The decision is closed; new passing physical evidence is still required.

## Product-owner decisions still open

The remaining product input cannot be inferred from the implementation:

1. **Real processor selection.** Choose the actual digest-pinned local processor image, executable and model that will run inside the accepted ADR-016 boundary, then define and approve its transcription/research behavior and evidence access. Choosing an external provider instead remains a new credential, destination, retention and egress design.

## Operator inputs and credentials still required

A real deployment or pilot must supply its own values; none should be committed:

- an immutable QA build identity and sealed SDK profile;
- Apple signing and TestFlight or other authorized QA-distribution access;
- the self-hosted HTTPS origin, DNS, trusted certificate, reverse proxy, host
  and provider firewall rules, and a digest-pinned backend image;
- a high-entropy administrator secret, durable local storage, and encrypted,
  access-controlled off-host backup storage;
- least-privilege, read-only repository and observability credentials for each
  connector that is actually selected; and
- model/API credentials only if an explicitly authorized external processing
  design is selected.

Follow the backend [configuration](../services/backend/CONFIGURATION.md),
[operations](../services/backend/OPERATIONS.md), and
[processing-adapter](../services/backend/PROCESSING_ADAPTER.md) runbooks. Their
preflight checks do not configure or prove DNS, TLS ownership, firewalls,
off-host backup transfer or destruction, provider authorization, or host monitoring.

## Required evidence before an authorized private pilot

- The exact commit passes every repository job, including contracts, backend,
  reviewer, SDK, generated iOS compilation, Docker build/smoke, single-writer
  exclusion, backup, and restore.
- The SDK prerelease tarball and checksum are generated from that commit and
  integrated only into the authorized QA target; the ordinary production/App
  Store target proves that the SDK and recording permissions are absent.
- On a physical iPhone, the reviewer app launches the QA app, the tested app
  obtains truthful consent, capture records narration and issues, lifecycle
  interruptions are represented as gaps, relaunch discovers pending work, and
  foreground queue draining completes without losing exact evidence.
- A new 30-minute physical run passes the ADR-018 machine gate: app-audio drops
  are no more than 0.2% of all append attempts and every dropped attempt index
  appears exactly once in an `app_audio_append_drop` gap. The artifact must be
  labeled `physical_device`, validate against the exact digest- and
  identity-bound schema-4 source manifest, contain no recovery reservation
  ranges, stay within the 1,799,000–1,831,000 ms envelope, and respect the SDK's
  10,000,000-attempt/2,048-drop caps. The label is operator evidence
  classification, not hardware attestation. The historical
  121/77,523 run does not satisfy this accounting requirement.
- The selected real processor produces zero, one, and several grounded
  candidates from authorized test data. Screenshots, diagnostic context,
  clarification, edits, approval, canonical export, and rejection all work
  without exposing credentials or unrelated evidence.
- Completion and explicit deletion retire the intended local and backend data;
  retention expiry is observed end to end. Locked-device protected-file
  behavior and an authenticated, user-visible recovery/reset path for corrupt
  local state are verified. The SDK's lifecycle and relaunch boundaries sweep
  expired local capture, journals, credentials, and queue state crash-safely;
  verify that behavior, including pre-deadline reboot reconciliation through
  authenticated RESUME, on the signed physical QA build.
- Backup manifest v2 recomputes and matches the copied database's earliest
  raw/derived evidence deadline, then refuses verification and both restore
  modes at that boundary; the selected off-host system also proves that every
  bundle and replica is physically destroyed by that deadline.
- A real non-interactive `codex exec --ephemeral --sandbox workspace-write`
  invocation, with network off and a required `--output-schema`, consumes one
  approved handoff under the exact ADR-017 trust artifacts. Authentication is
  scoped to only that invocation and is not exposed beside repository-controlled
  code. Controlled Codex state/configuration disables web search and unapproved
  MCP/apps/hooks, proves effective command networking is off, and exposes only
  assertion-bound repository revisions. An authenticated current lookup or
  trusted monotonic store rejects registry/revocation revision rollback. The
  trial completes without treating the assertion as a sandbox, approval, merge,
  or deploy bypass.

Use synthetic or explicitly approved QA data for these gates. Do not publish
recordings, credentials, private source, production telemetry, personal data,
or stable device identifiers as evidence.

## Additional gates before Internet-facing production

- Operate the digest-pinned image behind the intended TLS proxy and firewalls;
  run preflight and exact-origin smoke checks from a representative QA-device
  network.
- Exercise backup, integrity verification, non-destructive restore, applied
  restore, upgrade, rollback, retention alerts, storage exhaustion, and host
  restart on the selected infrastructure. Exercise candidate-image startup
  against an isolated restored copy as a separate compatibility gate; the
  backend intentionally has no migration for schema 1 or the earlier
  unconstrained schema-v2 credential table.
- Apply the security model's [deployment overlay](SECURITY-MODEL.md#deployment-overlay)
  to the exact environment and selected integrations. Validate abuse and
  request-size limits, secret recovery/rotation, processor isolation, dependency
  and image provenance, log redaction, incident response, and data-erasure
  evidence in operation; remediate or explicitly accept the resulting findings.
- Resolve or explicitly gate fail-closed recovery states that currently need
  operator intervention, including indeterminate RESUME exchange reconciliation
  and corrupt local-session recovery.
- Run a supported-device and supported-iOS compatibility/resource campaign on
  the production integration rather than relying on the original capture spike.

Android, whole-device capture, tracker synchronization, cross-customer
multi-tenancy, a hosted Tacua control plane, and autonomous execution without
human approval remain explicitly deferred. They are not hidden V1 release
gates.
