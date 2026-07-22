<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua V1 requirements traceability

This document maps the fixed V1 requirements to the repository evidence that
exists today. It is an audit aid, not a release claim. The terms below are used
deliberately:

- **Implemented foundation** means code and deterministic tests exist in this
  repository.
- **Device-evidenced candidate** means a bounded experiment passed on the
  documented device and data, not that the complete V1 passed.
- **External gate** means a real device, credential, deployment, integration,
  or owner decision is still required.

The implemented architecture's completed repository-owned source/design threat
review is the [V1 security model](SECURITY-MODEL.md). Its deployment and
integration overlays remain external gates and must not be represented by
synthetic fixtures.

The original research attachment is background, not the product contract. In
particular, its recommendation to begin on Android was superseded by the fixed
iOS-first V1 decision. Its suggested tools and vendors are not selected
dependencies or integrations merely because they appeared in that research.

## Fixed-requirement matrix

| Fixed V1 requirement | Repository trace | Truthful current boundary |
| --- | --- | --- |
| Open-source Apache-2.0, self-hosted Docker backend | The repository [license](../LICENSE), first-party SPDX headers, backend [Dockerfile](../services/backend/Dockerfile), [Compose model](../services/backend/compose.yaml), and [operations runbook](../services/backend/OPERATIONS.md). Backend and operator tests live in [`services/backend/tests`](../services/backend/tests). | The first-party source and package metadata use Apache-2.0 and a hardened single-node image definition is implemented. This is not a legal opinion about every optional third-party processor an operator might later choose, and no real Internet-facing host has passed the production gates. |
| iOS-first Expo/React Native development-build SDK | The Expo module candidate, config plugin, native Swift code, and tests are under [`experiments/ios-capture-spike/package`](../experiments/ios-capture-spike/package). The [plugin contract](../experiments/ios-capture-spike/package/CONFIG_PLUGIN.md) accepts only development/preview profiles and requires the host to exclude the package from its production dependency graph. | This is a pre-release SDK candidate, not a published or production-qualified SDK. Generated Expo/iOS builds and deterministic tests cover the boundary; the complete released package has not passed a physical pilot integration, and the private pilot must prove the ordinary production target contains neither the module nor recording permissions. |
| App-only ReplayKit narrated manual QA, at most 30 minutes | [`TacuaCaptureSession.swift`](../experiments/ios-capture-spike/package/ios/TacuaCaptureSession.swift), [`CapturePolicy.swift`](../experiments/ios-capture-spike/package/ios/CapturePolicy.swift), their Swift tests, and the bounded [physical-device results](../experiments/ios-capture-spike/PHYSICAL-DEVICE-RESULTS.md). | ReplayKit video, app audio, required microphone narration, segmentation, gaps, and a 30-minute active-capture design limit are implemented. The physical candidate campaign used one iPhone and synthetic QA data. The persisted monotonic deadline is not a claim of uninterrupted wall-clock enforcement while iOS suspends the process, nor is it a supported-device matrix. |
| Upload followed by asynchronous processing | The native SDK queue/client and lifecycle tests are in the iOS package; durable job state is in [`processing_jobs.py`](../services/backend/src/tacua_backend/processing_jobs.py); the opt-in boundary is documented in the [processing-adapter runbook](../services/backend/PROCESSING_ADAPTER.md). | Retry-safe upload/completion and durable asynchronous job state are implemented. Upload is currently foreground and process-bound, so relaunch must drain the durable queue again. The checked-in worker is an exclusive offline operator command, not an unattended worker, and no real transcription, research, or ticket-generation processor is selected or bundled. |
| Reviewer UI shows a ticket with screenshot and SDK evidence | The candidate route, [evidence panel](../apps/reviewer/src/components/candidate-evidence-panel.tsx), digest-checked preview client, and candidate edit controls are under [`apps/reviewer`](../apps/reviewer). Reviewer tests cover response validation, evidence-reference binding, preview integrity, gallery inspection state, handoff integrity, the cicada palette, and a rendered candidate-route regression. | The source and rendered regression cover one review surface containing ticket content, referenced screenshot previews, and a bounded SDK diagnostic timeline, while TypeScript and iOS export cover their respective boundaries. This is deterministic renderer evidence, not physical end-to-end proof. Approval stays locked when referenced available screenshots have not passed integrity checks and been decoded. |
| Human approval before handoff | Candidate state rules and tests are in [`contracts/ticket-candidate`](../contracts/ticket-candidate) and the backend candidate store; approved export is in [`contracts/approved-handoff`](../contracts/approved-handoff) and the backend handoff store. The reviewer route approves an exact candidate/evidence version before enabling share. | Exact-version human approval is enforced before canonical Markdown/JSON handoff publication. Approval is structural authority to create the handoff; it is not authenticated authority for an agent to modify a repository. The real execution-trust design and consumer trial remain external gates under [ADR-011](decisions/ADR-011-approved-handoff.md). |
| One organization per deployment; current pilot pins one project, application, build, and reviewer | [`PilotConfig`](../services/backend/src/tacua_backend/config.py), the [configuration compiler](../services/backend/src/tacua_backend/config_tool.py), example profile, and configuration/backend tests enforce the deployment projection. | The current implementation is stricter than the future product boundary: one deployment has one organization and exactly one pilot project, application, tested build, reviewer identity, and administrator credential. Multiple projects or reviewers are not implemented in this pilot backend and must not be claimed from the future-facing product language. |
| 30-day retention and recovery | The sealed profile defaults raw and derived evidence to 30 days; backend retention/deletion tests cover exact boundaries and crash recovery; the SDK has segmented local recovery, exact resume/partial-submit/delete choices, and server-anchored local deadline enforcement; backend backup/restore tooling is in the operator tool and runbook. | Live backend expiry, crash-safe local expiry retirement, and local capture recovery have deterministic coverage, but end-to-end expiry on a physical workflow is still required. Backup manifest v2 seals the earliest raw/derived deadline from every retained session, recomputes it from the copied database, and refuses verification plus dry-run or applied restore at expiry; physical destruction of off-host copies remains an operator gate. The SDK sweeps expired capture, journal, credential, and queue state when relaunch discovery or another lifecycle boundary runs. After a reboot before the deadline, raw-data operations fail closed until authenticated RESUME refreshes the server-time anchor; this is not a claim of a continuously running background timer. |
| No Linear synchronization in V1; generic future connectors | The deferral is explicit in [the product boundary](PRODUCT.md). Processing is provider-neutral and external egress is default-deny. | There is no Linear sync and no repository, telemetry, or tracker connector implementation in V1. Future connector wording describes a vendor-neutral, read-only extension boundary, not a working integration or permission grant. Selecting a connector requires a separate scope, credentials, tests, and authorization. |
| Cicada-inspired palette | The non-bundled visual reference and roles are documented in the [visual-direction guide](design/visual-direction.md); tokens and contrast tests are in [`apps/reviewer/src/theme`](../apps/reviewer/src/theme). | Adaptive light/dark cicada-derived tokens and automated contrast checks exist. The source image is intentionally not redistributed because its rights are unverified. Device visual review, VoiceOver, Dynamic Type, and reduced-motion verification remain release evidence, not conclusions from the palette unit test. |

## Repository evidence versus external gates

The deterministic repository suites cover file-backed foreground-upload
interruption and exact relaunch replay, crash-safe local and backend retention
deletion, and atomic candidate publication using only synthetic data. Those
checks establish the implemented persistence boundaries; they do not replace
the physical and operational evidence below.

The following are genuine owner, device, credential, or deployment gates and
must not be replaced with fixtures presented as real evidence:

- accept or replace the split/merge semantics proposed by
  [ADR-015](decisions/ADR-015-candidate-split-merge-semantics.md);
- select and authorize a real local or external transcription/research
  processor, including its data-access and egress policy;
- choose execution-trust issuance/revocation and run a least-privilege real
  coding-agent consumer trial;
- decide and enforce the acceptable app-audio boundary-drop threshold, then
  repeat the full capture-to-approved-ticket flow on supported physical
  devices;
- provide Apple signing/distribution access and prove SDK absence from the
  ordinary production target; and
- provide and operate the actual HTTPS origin, DNS, TLS proxy, firewalls,
  durable storage, encrypted off-host backup lifecycle, monitoring, and
  required secrets.

The current release assessment and complete gate list remain in
[release readiness](RELEASE-READINESS.md).
