<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua V1 security model

## Review status and scope

This document is the completed **repository-owned source and design threat
review** for the implemented V1 architecture in this source tree. It covers the
reviewer app, QA-build mobile SDK, self-hosted backend, local processing
adapter, recovery tooling, and approved-handoff boundary. It records the
controls that exist, the assumptions on which they depend, and risks the
repository does not close.

This is not the threat review for a real deployment. Production promotion still
requires the [deployment overlay](#deployment-overlay) against the exact
immutable release, mobile integration, host, reverse proxy, storage, processor,
connectors, agent runtime, credentials, and operating procedures. That review
must verify configuration and behavior in the selected environment and resolve
or accept its findings. Repository tests and this document are not a penetration
test or an independent security audit.

The architectural source of truth is [ADR-012](decisions/ADR-012-v1-component-boundary.md):
the reviewer app owns launch, review, approval, and export; the removable SDK in
the tested QA app owns consent, app-only capture, local recovery, upload, and
local deletion; the backend owns grants, durable state, processing jobs,
retention, review state, and handoffs. The exact SDK transport is
[ADR-013](decisions/ADR-013-sdk-backend-v1-protocol.md). Product and proof limits
remain in [V1 traceability](V1-TRACEABILITY.md) and
[release readiness](RELEASE-READINESS.md).

## Security objectives and data classes

Tacua prioritizes confidentiality of QA evidence and credentials, integrity and
scope binding of every authorization and artifact, availability of the only
recoverable copy until durable acknowledgement, and timely, observable erasure.
Availability does not mean high availability: V1 is intentionally single-node
and single-process.

| Data class or asset | Examples and locations | Required properties |
| --- | --- | --- |
| Authorization secrets and capabilities | Backend administrator secret; SDK bearer secret; transient launch codes and consent handles; future provider, connector, registry, or agent credentials. | Secret values remain confidential, narrowly scoped, revocable or expiring where the contract defines that lifecycle, and absent from recordings, journals, diagnostics, tickets, logs, and public config. Loss of the administrator secret is an operator recovery event. |
| Public identity and policy | Organization/project/application/build IDs, native build identity, backend origin, consent contract, retention policy, contract versions, digests, repository references, and sealed SDK profile. | Public but integrity-critical. Every consumer rejects unknown shape/version and cross-scope or build substitution. A digest proves consistency, not who authorized the value. |
| Raw capture evidence | ReplayKit video, app audio, microphone narration, segment sidecars, screenshots/keyframes, partial segments, upload snapshots, and any copies in backend state or recovery bundles. | Confidential and project-scoped; byte integrity and provenance are preserved; recoverable data is not retired before validated authority; retention and explicit deletion remain visible and fail closed. |
| Structured diagnostics | Sanitized lifecycle, route-template, interaction-target, network-result, issue-marker, gap, and digest-only custom-state events. | Treated as sensitive evidence despite the bounded schema. It must not contain arbitrary headers, bodies, credential values, or raw private state; order and integrity are preserved. |
| Derived processing data | Transcripts, alignments, research or connector results, model output, keyframes, evidence manifests, and processing workspaces. | Same project/evidence scope as the raw source, bounded and provenance-linked. No real transcription/model/connector implementation is bundled, so any selected implementation needs an overlay below. |
| Review and handoff data | Immutable candidate versions, edits, clarifications, approval state, audit metadata, approved Markdown/JSON, evidence locators and digests. | Exact-version integrity, explicit human approval, deterministic export, and separation of structural validity from execution authority. Ticket text and external content remain untrusted input to consumers. |
| Durable protocol and operational state | Launch/operation verifiers, canonical requests and receipts, credential history, jobs and leases, deletion tombstones, content-free audit rows, health state, SQLite/WAL, object files, config, and logs. | Integrity, bounded replay, crash recovery, minimum necessary disclosure, and single-writer consistency. Identifiers and digests are still sensitive operational metadata. |
| Recovery copies | Mobile crash journals and queues; backend backup bundles containing state, config, and administrator secret; restored staging directories and off-host replicas. | At least as protected as their source. Backup refusal at evidence expiry is not physical deletion; encryption, replica inventory, and destruction are deployment responsibilities. |

## Actors and trust assumptions

| Actor | Authority and trust boundary |
| --- | --- |
| Authorized reviewer | May request a launch, inspect evidence, edit/reject/approve an exact candidate, and export a handoff. Consent in the tested app and candidate approval are separate human decisions. Mistake, coercion, or compromise of the reviewer/device is not solved by schema validation. |
| Reviewer app | An administrator client configured with one backend origin and bearer secret. It does not record another app or read the tested app's sandbox. Anyone holding that shared administrator secret can exercise its backend authority; V1 has no per-human MFA or RBAC. |
| Embedded mobile SDK | Trusted only when linked into the sealed, authorized QA build. It owns the local capture namespace and SDK credential. Host JavaScript, launch URLs, server bodies, local files, and clocks are validated rather than assumed authoritative. |
| Self-hosted backend | The main V1 trusted computing base for authorization and durable state. It trusts its exact config, mounted administrator secret, system clock, Python/SQLite runtime, kernel, filesystem semantics, and exclusive state-volume lock. |
| Deployment operator | Has effective control of image, host, config, administrator secret, state, backups, processing command, network, and upgrades. A malicious or compromised root/operator is outside the in-process protection boundary. |
| Local processor | Trusted operator-selected code only. The adapter narrows inherited data and validates output, but its child runs as the backend UID and is not a hostile-code sandbox. |
| External provider, connector, or coding agent | Untrusted and unauthorized by default. None is installed or granted network/credential authority by this repository. Structural handoff approval is not agent execution authority. |
| Adversary and untrusted content | Includes network attackers, stolen bearer holders, malicious deep links, malformed/oversized requests, tampered local or stored files, hostile model/connector/ticket text, and denial-of-service attempts. A host-root or same-UID compromise can exceed repository controls. |

The design additionally assumes that Apple sandboxing, Keychain, protected-file
semantics, secure randomness, ReplayKit, TLS verification, SHA-256/HMAC, POSIX
no-follow/open/rename/fsync behavior, and the selected container runtime behave
as specified. The backend does not terminate TLS; the deployment must provide a
correct HTTPS reverse proxy. Server authorization uses server time, while the
SDK's post-launch chronology uses a server-derived monotonic anchor. V1 assumes
one mutually trusted organization and exactly one configured project,
application, build, reviewer identity, and administrator credential per
deployment; it is not a hostile multi-tenant boundary.

## Data flows and trust boundaries

| Flow | Boundary and data | Implemented enforcement |
| --- | --- | --- |
| 1. Operator seals the deployment | Operator/build system to public backend config and SDK profile; administrator secret remains a separate mount. | The [configuration compiler](../services/backend/CONFIGURATION.md) derives cross-artifact digests, rejects secret fields and inconsistent pins, and feeds the same parser used at startup. The [Expo plugin](../experiments/ios-capture-spike/package/CONFIG_PLUGIN.md) accepts only bounded canonical profiles for development/preview builds. |
| 2. Reviewer uses administrator API | Reviewer app through the deployment TLS boundary to backend admin routes. | The reviewer stores origin and secret atomically in device-only, when-unlocked secure storage, omits cookies, rejects redirects, checks the response origin, and bounds responses ([reviewer README](../apps/reviewer/README.md)). The backend authenticates before reading protected request bodies and exposes bounded routes ([HTTP adapter](../services/backend/src/tacua_backend/http_api.py)). TLS, firewalling, rate limiting, and public exposure are deployment controls. |
| 3. Reviewer launches the tested app | Backend to reviewer app to a custom URL scheme in the QA app. Only an opaque, short-lived, one-use launch code crosses the deep-link boundary. | The code carries no evidence or reusable upload credential. The SDK rejects alternate authorities, paths, fields, and backend overrides; consent must produce a one-shot native handle before exchange ([launch parser](../experiments/ios-capture-spike/package/ios/TacuaLaunchLink.swift), [start lifecycle](../experiments/ios-capture-spike/package/ios/TacuaSDKStartLifecycle.swift)). |
| 4. SDK captures and persists locally | ReplayKit and host app into the tested app's sandbox, protected capture directory, crash journals, upload queue, and Keychain. | The SDK is app-only, uses protected files excluded from device backup, stores the bearer secret in this-device-only Keychain, seals media/sidecars and append-only diagnostics, snapshots uploads with no-follow descriptors, and records outcome-unknown before network I/O. A server/monotonic time anchor guards the immutable raw-media deadline; lifecycle and relaunch checks retire the scoped local footprint crash-safely at expiry and block use when a pre-deadline reboot needs authenticated RESUME reconciliation ([SDK README](../experiments/ios-capture-spike/package/README.md)). |
| 5. SDK uploads to backend | QA app through TLS to its build-pinned origin, then backend authentication, SQLite, and object storage. | HTTPS is required outside debug loopback; redirects are rejected. Scope, current capability, canonical request digest, body size, object size/digest, exact replay, credential history, and commit-time session/build state are checked under the frozen [protocol](../contracts/sdk-backend-protocol/README.md) and backend [service](../services/backend/src/tacua_backend/service.py). |
| 6. Backend persists and processes | SQLite metadata plus filesystem objects; optional offline child receives a canonical descriptor and inherited read-only evidence descriptors. | One state lock excludes HTTP, operator, and worker processes. Evidence publication is journaled and candidate visibility is atomic under [ADR-014](decisions/ADR-014-atomic-processing-result-publication.md). Normal startup has no processor or egress; the opt-in [adapter](../services/backend/PROCESSING_ADAPTER.md) is bounded and shell-free but trusts the same-UID child. |
| 7. Reviewer approves and exports | Backend evidence/candidate routes to reviewer, then native share sheet to a receiving app or agent. | Preview bytes and exact candidate/evidence versions are verified before approval; exports are bounded canonical JSON and deterministic Markdown. The [handoff contract](../contracts/approved-handoff/README.md) omits evidence payloads and secrets and explicitly requires separate, current execution trust. The share receiver is outside Tacua's trust boundary. |
| 8. Operator backs up or restores | Stopped state volume to a private offline bundle, then optional encrypted off-host storage or a new restore root. | The [operator tool](../services/backend/src/tacua_backend/operator_tool.py) checks ownership/modes, SQLite and deployment pins, exact files/digests, recomputes the sealed earliest raw/derived evidence deadline from the copied database, and refuses verification or either restore mode at expiry. Applied restore re-verifies staging before atomic publication and the published destination afterward. The [runbook](../services/backend/OPERATIONS.md) assigns encryption, transfer, replica destruction, and recovery access control to the operator. |

## Abuse-case review

The control identifiers refer to the evidence table in the next section.

| Threat | Representative abuse case | Current response and residual exposure |
| --- | --- | --- |
| Spoofing | A different app/build, forged deep link, replayed launch code, stolen SDK bearer, or unauthenticated client attempts to create or use a session. | C1–C3 bind the honest SDK to its installed build and validate declared build, origin, consent, session scope, credential verifier, capability, and one-use grant. The server has no Apple app/device attestation, and iOS custom schemes are not globally exclusive; an intercepted launch code can be raced by an impersonator that knows the public build profile. A stolen live bearer retains its exact scoped authority until expiry/revocation. |
| Spoofing | A caller impersonates the configured reviewer or operator. | C2 and C8 require the administrator bearer for admin routes. The shared secret authenticates possession, not a named human, and supplies no MFA, per-action signing, or non-repudiation. |
| Tampering and replay | An attacker changes request bytes, media, sidecars, receipts, stored evidence, candidate history, previews, or a handoff; or repeats an operation under the same ID with different content. | C2–C6 and C8 use closed schemas, canonical bytes, digests, cross-artifact bindings, exact idempotent replay, immutable versions, read-time revalidation, and atomic publication. Unkeyed digests alone do not authenticate a coherently rewritten artifact, and host/root compromise remains outside the boundary. |
| Repudiation | A participant disputes consent, upload, deletion, edit, approval, or export. | Server acceptance times, exact durable receipts, immutable candidate versions, transition actors, deletion tombstones, and bounded audit metadata provide operational traceability (C2, C5, C6, C8). V1 does not provide cryptographic human signatures or legal non-repudiation. |
| Information disclosure | Credentials or private evidence leak through redirects, diagnostics, errors, logs, processor environment, tickets, signed URLs, share cache, or cross-project reads. | C1–C8 reject redirects and cross-scope bindings, omit secrets from public artifacts/journals, bound diagnostic and error schemas, inherit minimal processor state, verify evidence references, scan obvious export secrets, and age the reviewer share cache. Pattern-based secret scanning is defense in depth, infrastructure logs are operator-controlled, and a selected processor/connector may add new disclosure paths. |
| Denial of service | Oversized bodies/files/JSON, request floods, SQLite contention, decompression/media work, processor hangs/output floods, disk exhaustion, or deletion backlog exhaust a single node. | C3, C5, C7, and C9 bound protocol bodies, collections, pagination, processor files/pipes/time/process groups, container PIDs, and health/retention signals. No repository-owned WAF, global rate limiter, resource quota, high-availability replica, or automatic capacity system exists. |
| Elevation of privilege | A launch code becomes an upload bearer; a completed credential uploads new evidence; approval becomes repository execution; a processor gains provider or repository credentials. | C1, C2, C7, and C8 keep grant, receiving, completion/delete, human approval, and execution capabilities distinct. Provider/connector credentials are not inherited or bundled. A same-UID processor or compromised administrator/operator can exceed these logical controls. |
| Scope confusion | Valid data from another organization, project, session, application, build, credential history, evidence manifest, or repository is substituted. | C1, C2, C5, and C8 cross-bind every implemented scope and fail closed. The current single-scope deployment reduces but does not replace these checks; it does not establish cross-customer isolation. |
| Malicious processing or connector content | Hostile transcript, source text, model output, preview, or prompt attempts path traversal, schema escape, secret exfiltration, false grounding, or instruction injection. | C7 and C8 constrain adapter argv, descriptors, paths, output shape/files, authoritative validators, evidence grounding, and human approval. No model or connector is trusted by default. Semantic truth, prompt-injection resistance, and an untrusted-code sandbox require the selected overlays. |
| Destructive or retention-evading action | A caller deletes the wrong session, races evidence reads, restores expired evidence, silently extends retention, or leaves undeleted replicas. | C2 and C4–C6 scope deletion, exclude concurrent reads/publication, use recoverable deletion state, enforce local and backend expiry, and refuse expired recovery bundles. They cannot destroy an operator/provider copy they cannot reach or prove physical erasure on selected storage. |
| Supply-chain or rollback substitution | A floating image, altered SDK tarball/profile, stale schema, old database, or injected runtime source is promoted. | C1, C9, and C10 pin or validate build inputs, exact versions, container inputs, schema compatibility, and release artifacts. The operator still must review dependency/base-image changes, protect CI/releases, verify the immutable candidate, and exercise restore/rollback. |

## Implemented controls and exact repository evidence

| ID | Control | Implementation evidence | Deterministic evidence |
| --- | --- | --- | --- |
| C1 | QA-only build, origin, scope, and consent gate | [Config plugin](../experiments/ios-capture-spike/package/plugin/withTacua.js), [native build-profile validator](../experiments/ios-capture-spike/package/ios/TacuaSDKBuildProfile.swift), [launch parser](../experiments/ios-capture-spike/package/ios/TacuaLaunchLink.swift), and [backend config](../services/backend/src/tacua_backend/config.py). | [Plugin tests](../experiments/ios-capture-spike/package/tests/config-plugin.test.mjs), [build-profile tests](../experiments/ios-capture-spike/package/tests/SDKBuildProfileTests.swift), [launch-link tests](../experiments/ios-capture-spike/package/tests/LaunchLinkTests.swift), and [config tests](../services/backend/tests/test_config_tool.py). |
| C2 | One-use launch grants; keyed server verifiers; scoped, expiring capability states; exact replay and rotation | [Credential store](../experiments/ios-capture-spike/package/ios/TacuaCredentialStore.swift), [start](../experiments/ios-capture-spike/package/ios/TacuaSDKStartLifecycle.swift) and [resume](../experiments/ios-capture-spike/package/ios/TacuaSDKResumeLifecycle.swift) journals, [protocol validator](../contracts/sdk-backend-protocol/src/protocol_contract.py), and backend [service](../services/backend/src/tacua_backend/service.py). | [Protocol tests](../contracts/sdk-backend-protocol/tests/test_protocol_contract.py), [SDK client tests](../experiments/ios-capture-spike/package/tests/SDKBackendClientTests.swift), and backend [protocol/HTTP tests](../services/backend/tests/test_backend.py). |
| C3 | Strict, bounded network and serialization boundary | SDK [redirect-rejecting client](../experiments/ios-capture-spike/package/ios/TacuaSDKBackendClient.swift), reviewer [client](../apps/reviewer/src/api/client.ts), backend [HTTP adapter](../services/backend/src/tacua_backend/http_api.py), and closed [runtime](../contracts/runtime/src/runtime_contract.py) and [ticket](../contracts/ticket-candidate/src/ticket_candidate_contract.py) validators. | SDK [protocol tests](../experiments/ios-capture-spike/package/tests/SDKBackendProtocolTests.swift), reviewer [response-limit tests](../apps/reviewer/src/api/response-limits.test.mjs), backend [HTTP tests](../services/backend/tests/test_backend.py), and contract suites under [`contracts`](../contracts). |
| C4 | Crash-safe mobile evidence, diagnostics, queue replay, deadline enforcement, and receipt-authorized retirement | [Capture session](../experiments/ios-capture-spike/package/ios/TacuaCaptureSession.swift), [admission/snapshot boundary](../experiments/ios-capture-spike/package/ios/TacuaCaptureAdmission.swift), [diagnostic journal](../experiments/ios-capture-spike/package/ios/TacuaDiagnosticJournal.swift), [queue file store](../experiments/ios-capture-spike/package/ios/TacuaTransportQueueFileStore.swift), [local retention coordinator](../experiments/ios-capture-spike/package/ios/TacuaSDKLocalRetention.swift), and [deletion coordinator](../experiments/ios-capture-spike/package/ios/TacuaCaptureDeletionCoordinator.swift). | The package [core test runner](../experiments/ios-capture-spike/package/tests/run-core-tests.sh), dedicated [local retention tests](../experiments/ios-capture-spike/package/tests/LocalRetentionTests.swift), [fault campaign](../experiments/ios-capture-spike/FAULT-INJECTION-RUNBOOK.md), and bounded [physical-device results](../experiments/ios-capture-spike/PHYSICAL-DEVICE-RESULTS.md). |
| C5 | Single-writer, integrity-checked backend persistence and atomic review visibility | [Instance lock](../services/backend/src/tacua_backend/instance_lock.py), [evidence store](../services/backend/src/tacua_backend/evidence_domain.py), [job store](../services/backend/src/tacua_backend/processing_jobs.py), [candidate store](../services/backend/src/tacua_backend/candidate_store.py), and [handoff store](../services/backend/src/tacua_backend/handoff_store.py). | Backend tests for [release regressions](../services/backend/tests/test_backend_release_regressions.py), [evidence](../services/backend/tests/test_evidence_domain.py), [processing publication](../services/backend/tests/test_processing_publication.py), [candidates](../services/backend/tests/test_candidate_store.py), and [handoffs](../services/backend/tests/test_handoff_store.py). |
| C6 | Backend retention, scoped deletion, recovery, and backup deadline binding | Backend [service](../services/backend/src/tacua_backend/service.py), [evidence deletion](../services/backend/src/tacua_backend/evidence_domain.py), and [operator backup/restore tool](../services/backend/src/tacua_backend/operator_tool.py), with the operational boundary stated in the [runbook](../services/backend/OPERATIONS.md). | Backend [lifecycle/regression tests](../services/backend/tests/test_backend_release_regressions.py), [evidence deletion tests](../services/backend/tests/test_evidence_domain.py), and [operator tests](../services/backend/tests/test_operator_tool.py). Device-side status and remaining physical proof are kept current in [release readiness](RELEASE-READINESS.md). |
| C7 | Default-deny, opt-in processing with bounded data inheritance and output | Checked-in [internal Compose network](../services/backend/compose.yaml), [processing adapter](../services/backend/src/tacua_backend/processing_adapter.py), [worker](../services/backend/src/tacua_backend/processing_worker.py), and [adapter runbook](../services/backend/PROCESSING_ADAPTER.md). No command, model, connector, provider key, or automatic runner is configured. | [Adapter tests](../services/backend/tests/test_processing_adapter.py), [job tests](../services/backend/tests/test_processing_jobs.py), and [publication tests](../services/backend/tests/test_processing_publication.py). |
| C8 | Exact candidate/evidence approval and non-executable structural export | Authoritative [candidate contract](../contracts/ticket-candidate/README.md), backend [handoff export](../services/backend/src/tacua_backend/handoff_export.py), reviewer [candidate route](../apps/reviewer/src/app/candidates/[candidate-id].tsx), [preview verifier](../apps/reviewer/src/api/evidence-preview-integrity.ts), and [handoff contract](../contracts/approved-handoff/README.md). | Candidate [contract tests](../contracts/ticket-candidate/tests/test_ticket_candidate_contract.py), approved-handoff [tests](../contracts/approved-handoff/tests/test_contract.py), reviewer [preview tests](../apps/reviewer/src/api/evidence-preview-integrity.test.mjs), rendered [candidate-route regression](../apps/reviewer/src/components/candidate-route.render.test.cjs), and backend [handoff tests](../services/backend/tests/test_handoff_store.py). |
| C9 | Hardened single-node packaging and fail-closed operator preflight | Non-root digest-pinned [Dockerfile](../services/backend/Dockerfile), read-only/capability-dropped/default-deny [Compose model](../services/backend/compose.yaml), immutable-image [production override](../services/backend/compose.production.yaml), and [operator preflight](../services/backend/src/tacua_backend/operator_tool.py). | [Operator tests](../services/backend/tests/test_operator_tool.py), backend-image input [validator](../.github/scripts/validate-backend-image-inputs.mjs) and [adversarial tests](../.github/scripts/validate-backend-image-inputs.test.mjs), plus the repository [verification workflow](../.github/workflows/verify.yml). |
| C10 | Security-policy and contract regression evidence, kept distinct from runtime proof | The synthetic [security harness](../experiments/security-harness/README.md), canonical contracts, ADRs, and this model make default-deny and non-claim boundaries explicit. | The harness [tests](../experiments/security-harness/test/harness.test.mjs) exercise policy/authorization/deletion shapes only; the harness explicitly does not verify runtime security. Repository-local links are checked by the [Markdown checker](../.github/scripts/check-markdown-links.mjs). |

## Residual risks in the implemented source

- The shared administrator bearer is a single deployment credential. There is
  no per-human account, MFA, role separation, signed approval, or cryptographic
  non-repudiation.
- The backend authenticates declared build/scope values but has no Apple App
  Attest or other server-verifiable app/device attestation. A dedicated custom
  URL scheme reduces accidental routing but does not prove exclusive ownership;
  short lifetime and single use limit, but do not eliminate, launch-code theft
  or interception.
- The backend depends on external TLS termination, firewalling, rate limiting,
  durable storage, monitoring, and incident response. Its bounds reduce but do
  not eliminate denial-of-service risk on a single node. Build-pinned origin
  validation is not certificate pinning; clients rely on the platform trust
  store and the deployment's certificate lifecycle.
- Backend state and recovery bundles are not encrypted by repository code. A
  host root/operator or code running with the service UID can read evidence and
  can potentially rewrite state coherently; internal SHA-256 bindings are not a
  substitute for a trusted host or authenticated external ledger.
- The local processor boundary is for trusted code. Same-UID execution is not
  isolation from malicious native code, filesystem discovery, disk exhaustion,
  or kernel/runtime compromise.
- Pattern-based secret rejection and bounded diagnostic schemas are not a
  complete DLP system. Ticket, model, connector, and source text can contain
  sensitive or adversarial semantics even when structurally valid, and Tacua
  does not redact sensitive pixels or speech from an authorized raw capture.
- [ADR-011](decisions/ADR-011-approved-handoff.md) remains proposed. No accepted
  production assertion key lifecycle or real least-privilege agent consumer is
  present.
- A real transcription/research processor, provider, repository connector, and
  observability connector are absent. Their privacy, credential, egress,
  injection, vendor-retention, and erasure risks are therefore unmitigated
  until reviewed as overlays.
- The QA SDK's exclusion from an ordinary production target, truthful consent
  presentation, Apple distribution, locked-device behavior, supported-device
  range, and full physical workflow remain release evidence rather than source
  conclusions.
- V1 is single-node, single-process, and one configured scope. It provides no
  cross-customer multi-tenancy boundary, high availability, disaster-recovery
  objective, or zero-downtime processing.
- Backup expiry refusal does not erase bytes, and deletion receipts cannot
  prove destruction by storage or provider systems outside Tacua's authority.

## Required overlays for a candidate deployment

### Mobile integration overlay

Prove that the exact signed QA build contains the sealed profile and truthful
screen/microphone consent, that only authorized testers can install it, and that
the ordinary production/App Store dependency graph and entitlements exclude
Tacua. Review the chosen custom URL scheme, device-management/loss policy,
Keychain/protected-file behavior, crash recovery, local evidence lifecycle, and
the supported iOS/device resource envelope. Assess malicious scheme collision
and launch-code interception on managed test devices; if the risk is not
acceptable, an app-attested or associated-domain link is a new protocol design,
not a deployment toggle.

### Processor overlay

Choose whether the processor is trusted same-UID code or untrusted code needing
a separate UID/container/sandbox. Inventory every raw and derived input, output,
temporary copy, log, and retention deadline. Set CPU/memory/disk/time/file
limits; mount only read-only scoped evidence; default network to none; isolate
provider credentials from Tacua credentials; allow-list any destinations; treat
media/decoder input and model output as hostile; preserve authoritative output
validation; and prove cleanup, provider-copy deletion, monitoring, and failure
recovery.

### Connector overlay

No connector is implemented. For each selected repository, issue tracker, or
observability source, define exact read operations and data fields, project and
repository allow-lists, credential storage/rotation/revocation, destination
allow-lists, cache and provider-copy retention, query/result bounds, and audit
events. Use least-privilege read-only authority for V1. Treat source text,
issues, logs, traces, and connector responses as untrusted prompt-injection and
data-exfiltration input; a connector must never inherit administrator, SDK, or
agent-write credentials.

### Coding-agent overlay

Resolve [ADR-011](decisions/ADR-011-approved-handoff.md) with a production
issuer/key distribution and revocation design. Require a current assertion for
the exact handoff, repositories, build, evidence, and expiry; isolate the agent
runtime; give it only task-scoped repository authority; retain branch
protection and human merge/deploy gates; treat ticket and evidence text as
untrusted instructions; prevent credential and unrelated-file reads; and audit
tool use, changes, review, rollback, and acceptance. Human candidate approval
alone must never enable execution.

### Deployment overlay

For the exact immutable release candidate and environment:

1. Map the real DNS, certificate, TLS proxy, device-to-host path, firewall/WAF,
   ingress limits, egress routes, admin access, host/container/kernel, state and
   temporary storage, logs, metrics, backups, restore hosts, and every third
   party. Confirm the intended trust boundaries with live configuration.
2. Threat-model credential provisioning, least privilege, offline recovery,
   rotation, revocation, compromise, and loss for administrator, signing,
   registry, processor, connector, CI/release, host, and agent secrets.
3. Select encryption at rest and backup encryption; inventory every replica;
   prove access control, deadline-driven physical destruction, restore,
   rollback, schema compatibility, and incident preservation without silently
   extending evidence retention.
4. Add and test environment-appropriate rate limits, concurrency/resource and
   disk quotas, alerting, log redaction/access/retention, time synchronization,
   vulnerability/image/dependency review, patching, availability objectives,
   incident response, and user-visible erasure evidence.
5. Apply the processor, connector, agent, and mobile overlays actually selected;
   perform adversarial and penetration testing from representative networks;
   remediate or explicitly accept findings; then rerun the full physical
   capture-to-approved-handoff and recovery/deletion gates.

The [operations runbook](../services/backend/OPERATIONS.md),
[release-readiness checklist](RELEASE-READINESS.md), and repository
[security-reporting policy](../SECURITY.md) are inputs to this overlay, not
evidence that it has been completed.

## Explicit non-claims

- This review does not claim that Tacua is production-ready, vulnerability-free,
  compliant with a legal/privacy/security standard, independently audited, or
  safe for sensitive or public-Internet data.
- Passing schemas, digests, tests, synthetic harnesses, simulator builds, or one
  device experiment does not prove a deployed control or authenticate the
  human/operator who supplied an artifact.
- The repository supplies no real transcription model, LLM, external provider,
  repository/telemetry/tracker connector, production assertion authority, or
  autonomous coding-agent execution path.
- A valid approved handoff is not permission to read a repository, change code,
  merge, deploy, or retrieve evidence. External authentication and policy remain
  mandatory.
- The checked-in container model does not provide TLS termination, host
  hardening, encryption at rest, WAF/rate limiting, high availability, or
  physical backup/provider erasure.
- V1 does not claim whole-device or cross-application capture, Android support,
  cross-customer isolation, or protection after compromise of the trusted
  device OS, host root, operator, service UID, processor, CI/release authority,
  or cryptographic primitives.

## Review maintenance and gate closure

The repository-owned source/design portion of the production threat-review gate
is complete when this model and its evidence links describe the exact candidate
tree and the full verification workflow is green. Re-open it for any change to
actors or trust boundaries; collected data; permissions, credentials, consent,
or auth flows; schemas or public routes; persistence, retention, deletion, or
backup; processor/connector/agent behavior; mobile distribution; container or
network topology; or a previously explicit non-claim.

The production gate itself remains open until the deployment overlay is
completed for the actual environment and selected integrations. That external
review cannot be replaced by repository fixtures or documentation.
