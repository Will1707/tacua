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
| iOS capture | App-only ReplayKit capture, narration and app audio, bounded segmentation, issue marks and gaps, a 30-minute design limit, interruption recovery, and scoped local deletion. | The capture candidate passed its documented synthetic-data campaign on one physical iPhone. A later 30-minute schema-4 run with clearly labeled synthetic narration passed the narrow ADR-018 app-audio machine gate and exact private-manifest validation. Neither run exercises the complete SDK-to-backend-to-ticket path, human manual QA, or a supported-device matrix. |
| Mobile SDK lifecycle | A QA-build-only gate; sealed build, backend, consent, scope, and retention profile; consent-gated START and RESUME exchange; crash journals; native session discovery independent of prior JavaScript state; exact replay; stopped-capture admission; diagnostic projection; upload, completion, local retirement, server-anchored local expiry sweeping, and backend deletion. | Swift, TypeScript, config-plugin, and generated Expo/iOS build checks cover the implementation. The full lifecycle has not yet passed on a physical QA build. Upload uses an in-process foreground session: suspension or termination can stop progress, and the host must drain the durable queue again after relaunch. Expiry is checked when discovery or another lifecycle boundary runs. A reboot before the raw deadline blocks raw-data use until authenticated RESUME establishes a current-boot server-time anchor; this is deliberate fail-closed behavior, not continuous background enforcement. |
| Self-hosted backend | A single-organization, single-process Python/SQLite service whose current pilot configuration pins exactly one project, application, tested build, reviewer identity, and administrator credential per deployment; exact SDK receipts; integrity-checked storage; retention and deletion; immutable job and candidate histories; atomic candidate publication and handoff export; sealed configuration; health, preflight, backup, restore, and smoke tooling; hardened backend and authority-free reviewer images; a digest-pinned HAProxy ingress that exposes both on one origin while keeping the application containers on an egress-denied network; and a fail-closed [tailnet-only single-owner test profile](../services/backend/TAILNET_PRIVATE_PILOT.md). Backup manifest v2 binds and recomputes the earliest retained raw/derived session-evidence deadline and refuses verification plus dry-run or applied restore at expiry. This singular deployment scope is an implementation limit, not a narrowing of the product's future multi-project/member boundary. | Unit and contract suites plus the checked-in Docker CI job exercise these boundaries on the hosted daemon, and the private mini-PC pilot operates the backend topology on one rootless daemon; that is not a general rootless portability matrix. The tailnet profile validates private HTTPS-to-loopback topology, same-origin routing, and the reviewer authority boundary, but neither the limited ingress nor Tailscale Serve proves the production HTTP proxy's overload controls. The ingress sees plaintext authenticated bytes and has a publish-network route but no mounted Tacua secret/state/config. Expiry refusal does not destroy off-host bytes, and this is not evidence that a production TLS proxy, firewall, storage device, backup destination, destruction lifecycle, or upgrade procedure has been operated successfully. |
| Processing | Durable processing jobs; immutable, retention-bound transcript artifacts; an opt-in, provider-neutral, shell-free command adapter; and canonical synthetic adapter-1.0/1.1 plus isolated-wrapper conformance fixtures. The dormant adapter 1.1 path can pass an exact lease-bound transcript from `transcribe` to `align`, records successful consumption atomically, and then pauses before the undesigned `correlate` stage. [ADR-016](decisions/ADR-016-local-processor-isolation.md) defines the host runner/Compose profile, while [ADR-020](decisions/ADR-020-compose-state-processing-bridge.md) defines the crash-safe, descriptor-only bridge from the stopped Compose state worker to that host gate. An optional Apache-2.0 offline processor candidate pins its base image and `whisper.cpp` source, takes a separately supplied digest-verified model, extracts issue screenshots and bounded narration, and emits conservative draft candidates. Normal backend startup remains inert and default-deny for egress. | Contract, bridge, and processor unit coverage plus the container verifiers use synthetic data; they do not prove the complete rootless named-volume interruption campaign or a real-model terminal run. Production completion still creates only legacy pipeline 1.0 jobs. Pipeline 1.1 remains dormant unless an operator supplies the separate outer local-command 1.1 selection. No LLM, repository connector, telemetry connector, or API provider is implemented. The exact retained processor image and model still require promotion and deployment selection. The exclusive worker runs only while the HTTP service is stopped and is not an unattended production worker. |
| Reviewer app | Secure native self-hosted configuration plus a same-origin browser build with tab-scoped configuration; display of the single registered build projection and launch-code orchestration; recovery guidance; session, evidence, preview, and job views; candidate editing and clarification; atomic split/merge replacement; exact-version approval; integrity-checked canonical Markdown/JSON sharing or download. | [ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md) is accepted and its backend/reviewer replacement controls are implemented with deterministic tests. Static-export validation and container smoke tests cover the authority-free browser image and same-origin routing. Browser storage cannot match native Keychain protection, and a physical reviewer-to-QA-app-to-review run remains outstanding. |
| Handoff | Immutable candidate versions, evidence binding, exact approval, canonical Markdown/JSON export, and the accepted local/private-pilot Codex execution policy in [ADR-017](decisions/ADR-017-codex-execution-trust.md). | Structural fixtures do not authorize an agent. The repository gate requires current registry trust plus a 15-minute, exact-scope, unrevoked `codex exec` assertion; all checked-in keys are synthetic. A trusted real consumer trial and any remotely distributed production key design remain external gates under [ADR-011](decisions/ADR-011-approved-handoff.md). |
| SDK distribution | A pre-release `@tacua/mobile-sdk` tarball boundary, checksum validator, and tag-triggered GitHub prerelease workflow. Registry publication remains disabled; this does not make the Apache-2.0 source private. | No SDK release exists until the protected, signed release tag is pushed from a verification-green default-branch commit and the release workflow succeeds. See the [maintainer runbook](maintainers/MOBILE_SDK_RELEASE.md). |

## Accepted V1 operational decisions

- [ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md) accepts atomic
  replacement, exact source consumption, and lossless evidence-union semantics
  for split and merge; backend/reviewer implementation is present pending the
  complete repository verification run.
- [ADR-016](decisions/ADR-016-local-processor-isolation.md) accepts the offline,
  separate-UID/container, bounded private-pilot processor gate. The optional
  checked-in processor candidate does not activate that gate or authorize a
  particular retained image or model by itself.
- [ADR-017](decisions/ADR-017-codex-execution-trust.md) accepts OpenAI Codex as
  the V1 execution consumer only through a current, exact-scope, short-lived,
  unrevoked local assertion and the fixed non-interactive ephemeral
  `workspace-write`, network-off, structured-output profile. Approval alone is
  non-executable.
- [ADR-018](decisions/ADR-018-v1-app-audio-acceptance.md) accepts a maximum 0.2%
  app-audio append-drop rate only when every drop is recorded exactly once as a
  gap. The checked-in 2026-07-23 physical artifact records 21/77,521 drops
  (about 0.027%) and passed against its privately retained exact schema-4
  source manifest, closing this narrow machine gate.
- [ADR-019](decisions/ADR-019-processing-artifact-consumption.md) keeps the
  existing adapter 1.0 wire exact while accepting a separate, dormant 1.1
  transcript-to-alignment handoff with an append-only consumption receipt and
  an explicit pause before later processing stages.
- [ADR-020](decisions/ADR-020-compose-state-processing-bridge.md) accepts an
  exclusive, operator-triggered bridge from the stopped Compose state owner to
  the trusted host isolation gate. Exact host/image provenance, a durable
  sealed operation journal, conservative signal handling, and explicit
  idempotent recovery are required; no Docker socket enters a Tacua container.

## Product-owner decisions still open

The remaining product input cannot be inferred from the implementation:

1. **Processor promotion and evidence scope.** Approve the exact verifier-retained processor image after publication under its registry repository digest, plus the separately verified model path, ID, and digest that will run inside the ADR-016 boundary. Define and approve any repository or observability research behavior and evidence access; those connectors are not implemented by the offline candidate. Choosing an external provider remains a new credential, destination, retention, and egress design.

## Operator inputs and credentials still required

A real deployment or pilot must supply its own values; none should be committed:

- an immutable QA build identity and sealed SDK profile;
- Apple signing and TestFlight or other authorized QA-distribution access;
- the self-hosted HTTPS origin and host; either the bounded production DNS,
  certificate, reverse proxy, firewall, and digest-pinned image boundary, or
  the explicitly test-only tailnet profile and its owner-device access policy;
- a high-entropy administrator secret, durable local storage, and encrypted,
  access-controlled off-host backup storage;
- least-privilege, read-only repository and observability credentials for each
  connector that is actually selected;
- the verifier-retained processor image published under an immutable registry
  repository digest, plus the selected local model's exact path, ID, and
  SHA-256 digest; and
- model/API credentials only if an explicitly authorized external processing
  design is selected.

Follow the backend [configuration](../services/backend/CONFIGURATION.md),
[tailnet private-pilot](../services/backend/TAILNET_PRIVATE_PILOT.md),
[operations](../services/backend/OPERATIONS.md), and
[processing-adapter](../services/backend/PROCESSING_ADAPTER.md) runbooks. Their
preflight checks do not configure or prove DNS, TLS ownership, firewalls,
off-host backup transfer or destruction, provider authorization, or host monitoring.

## Required evidence before an authorized private pilot

- The exact commit passes every repository job, including contracts, backend,
  processor, reviewer, SDK, generated iOS compilation, Docker build/smoke,
  single-writer exclusion, backup, and restore.
- From a clean checkout of that exact commit, the processor verifier succeeds
  with a unique test ID and `TACUA_KEEP_VERIFIED_IMAGES=true`. Record its
  printed local image ID, tag and push that retained object without rebuilding,
  record the registry repository digest, and configure the isolated runner with
  the resulting `registry/repository@sha256:...` reference.
- The SDK prerelease tarball and checksum are generated from that commit and
  integrated only into the authorized QA target; the ordinary production/App
  Store target proves that the SDK and recording permissions are absent.
- On a physical iPhone, the reviewer app launches the QA app, the tested app
  obtains truthful consent, capture records narration and issues, lifecycle
  interruptions are represented as gaps, relaunch discovers pending work, and
  foreground queue draining completes without losing exact evidence.
- Repeat the 30-minute capture in the complete signed pilot workflow with human
  narration and across the selected supported-device matrix. The separate
  ADR-018 machine gate is already closed by the 2026-07-23 `physical_device`
  artifact: it stayed within the duration and accounting bounds, contained no
  recovery reservation ranges, and validated against the exact digest- and
  identity-bound private source manifest. The evidence label is an operator
  classification, not hardware attestation.
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
