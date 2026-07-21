<!-- SPDX-License-Identifier: Apache-2.0 -->
# Tacua approved ticket

- Contract: `tacua.approved-handoff@1.1.0`
- Handoff digest: `sha256:0c0db4a908a371bb925440d5a3d8680ca9c8f544b93743cc416dc5a8786b1e21`
- Ticket/version: `ticket-synthetic-001` / `4`
- Approved content digest: `sha256:bdbfb5ffb6153847b5a111d577309a70b3f86c8772ba238db332eca62758fc7f`
- Build identity digest: `sha256:f64af91f8587624ef1f7be29e7651a44b82e86f922ee4bc15c3105f9d467550b`
- Evidence manifest digest: `sha256:43483eaf0a5a55a120c9cfee704ebfbafd3db95dd89d8e6ff5ff8ca320d38f0f`
- Supersession: `current`

## Exact approved source candidate

- Candidate/version: `ticket-synthetic-001` / `4`
- Candidate digest: `sha256:e30833bc2cc5cdac3cf5baa9b19d0b49badce6a1a11152562a3d4910b44084c7`
- Candidate content digest: `sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f`

The JSON below is the exact canonical approved ticket-candidate source, without an artifact trailing newline.

<pre data-tacua-field="source_candidate.canonical_json">{"approval":{"actor_id":"member-approver-001","actor_type":"human","approval_id":"approval-synthetic-001","approved_at":"2026-07-20T10:16:00Z","approved_candidate_version":4,"authorized_evidence_ids":["evidence-backend-001","evidence-keyframe-001","evidence-repository-001","evidence-route-001","evidence-sentry-001","evidence-tap-001"],"candidate_content_digest":"sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f","evidence_manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","immutable":true,"reviewed_candidate_digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999","reviewed_candidate_version":3},"build_id":"build-ios-synthetic-031","build_identity_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","candidate_content_digest":"sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f","candidate_created_at":"2026-07-20T10:10:00Z","candidate_digest":"sha256:e30833bc2cc5cdac3cf5baa9b19d0b49badce6a1a11152562a3d4910b44084c7","candidate_id":"ticket-synthetic-001","candidate_version":4,"content":{"acceptance_criteria":[{"claim_refs":["claim-expected-behavior"],"criterion":"The enabled action label is Save profile in the tested locale.","criterion_id":"criterion-copy","evidence_refs":["evidence-backend-001","evidence-repository-001"],"verification":"Run the focused component test and inspect the iOS profile-form state."},{"claim_refs":["claim-observed-submit"],"criterion":"One enabled tap produces one profile update without a second tap.","criterion_id":"criterion-single-submit","evidence_refs":["evidence-backend-001","evidence-tap-001"],"verification":"Run the focused interaction test with the request adapter stub."}],"actual_behavior":{"claim_refs":["claim-observed-label","claim-observed-submit"],"evidence_refs":["evidence-backend-001","evidence-keyframe-001","evidence-route-001","evidence-tap-001"],"text":"The label is incorrect and the first tap does not submit the update."},"claims":[{"claim_id":"claim-observed-label","confidence":"high","evidence_refs":["evidence-keyframe-001","evidence-route-001"],"kind":"observed","statement":"The visible button label is Save draft, but the approved copy is Save profile.","support":"direct"},{"claim_id":"claim-observed-submit","confidence":"high","evidence_refs":["evidence-tap-001","evidence-backend-001"],"kind":"observed","statement":"The first tap emits the SDK interaction event without a matching backend request; the second tap reaches the deployment.","support":"direct"},{"claim_id":"claim-diagnosis-copy","confidence":"high","evidence_refs":["evidence-repository-001"],"kind":"diagnosis","statement":"The tested mobile revision contains the stale label in the profile-form component snapshot.","support":"direct"},{"claim_id":"claim-constraint-sentry","confidence":"medium","evidence_refs":["evidence-sentry-001"],"kind":"constraint","statement":"Sentry correlation was unavailable because the synthetic connector was intentionally revoked.","support":"inferred"},{"claim_id":"claim-expected-behavior","confidence":"high","evidence_refs":["evidence-repository-001","evidence-backend-001"],"kind":"expected","statement":"The approved behavior is Save profile copy and exactly one update on the first enabled tap.","support":"inferred"}],"clarifications":[{"choices":[{"choice_id":"choice-keep-current","consequence":"No copy correction would be requested.","description":"Keep the copy observed in the tested build.","evidence_refs":["evidence-keyframe-001"],"label":"Keep current copy","presentation":{"evidence_ref":null,"kind":"text","value":"Save draft"},"requires_note":false},{"choice_id":"choice-use-approved","consequence":"The ticket requests the approved label.","description":"Use the reviewer-approved V1 copy.","evidence_refs":["evidence-repository-001"],"label":"Use approved copy","presentation":{"evidence_ref":null,"kind":"text","value":"Save profile"},"requires_note":false}],"clarification_id":"clarification-copy-source","impact":"blocking","question":"Which copy is authoritative?","resolution_note":"Save profile is the approved English copy for V1.","selected_choice_id":"choice-use-approved","status":"resolved","target":"expected_behavior"}],"expected_behavior":{"claim_refs":["claim-expected-behavior"],"evidence_refs":["evidence-backend-001","evidence-repository-001"],"text":"The label reads Save profile and the first tap submits exactly one update."},"priority":"P1","reproduction":{"attempts":2,"preconditions":[{"claim_refs":[],"evidence_refs":[],"precondition_id":"precondition-1","text":"Use the synthetic QA account with an editable profile."},{"claim_refs":[],"evidence_refs":[],"precondition_id":"precondition-2","text":"Open the iOS build identified by this handoff."}],"reproductions":2,"steps":[{"action":"Open Settings, then select Edit profile.","actual_result":null,"claim_refs":["claim-observed-label"],"confidence":"high","evidence_refs":["evidence-route-001"],"expected_result":null,"step_id":"step-open-profile"},{"action":"Change the display name to Synthetic Reviewer.","actual_result":null,"claim_refs":["claim-observed-label"],"confidence":"high","evidence_refs":["evidence-keyframe-001"],"expected_result":null,"step_id":"step-change-name"},{"action":"Tap the visible Save draft button once and wait two seconds.","actual_result":null,"claim_refs":["claim-observed-submit"],"confidence":"high","evidence_refs":["evidence-tap-001","evidence-backend-001"],"expected_result":null,"step_id":"step-tap-save"}]},"scope":{"in_scope":["Correct the profile-form button copy.","Make a single enabled tap submit exactly once.","Add focused regression coverage."],"out_of_scope":["Do not change profile API semantics.","Do not deploy or merge from this handoff."]},"summary":{"claim_refs":["claim-observed-label","claim-observed-submit"],"evidence_refs":["evidence-backend-001","evidence-keyframe-001","evidence-route-001","evidence-tap-001"],"text":"The new profile form displays the wrong button label and submits only after a second tap."},"title":"Save button shows literal ](javascript:synthetic) copy","uncertainty":{"items":[{"evidence_refs":["evidence-sentry-001"],"impact":"non_blocking","statement":"The unavailable Sentry correlation remains an explicit non-blocking limitation.","uncertainty_id":"uncertainty-sentry-correlation"}],"overall_confidence":"medium"}},"contract_version":"tacua.ticket-candidate@1.0.0","evidence_manifest":{"evidence_ids":["evidence-backend-001","evidence-keyframe-001","evidence-repository-001","evidence-route-001","evidence-sentry-001","evidence-tap-001"],"manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_id":"manifest-synthetic-001"},"lineage":{"operation":"approved","parents":[{"candidate_digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999","candidate_id":"ticket-synthetic-001","candidate_version":3}]},"media_type":"application/vnd.tacua.ticket-candidate+json;version=1.0.0","organization_id":"org-synthetic","previous_candidate_digest":"sha256:9999999999999999999999999999999999999999999999999999999999999999","project_id":"project-sample-mobile-app-synthetic","rejection":null,"review":{"last_human_actor_id":"member-approver-001","last_reviewed_at":"2026-07-20T10:15:30Z","notes":["Synthetic fixture review only."],"reviewer_action_required":false,"status":"reviewed"},"session_id":"session-synthetic-001","state":"approved","transition":{"actor":{"actor_id":"member-approver-001","actor_type":"human"},"from_state":"ready_for_review","occurred_at":"2026-07-20T10:16:00Z","reason":"Synthetic owner approved the exact reviewed candidate.","to_state":"approved"},"version_created_at":"2026-07-20T10:16:00Z"}</pre>

## Title

<pre data-tacua-field="ticket.title">Save button shows literal ](javascript:synthetic) copy</pre>

## Summary

<pre data-tacua-field="ticket.summary">The new profile form displays the wrong button label and submits only after a second tap.</pre>

Claims: `claim-observed-label`, `claim-observed-submit`

## Claims

### `claim-observed-label` — `observed` / `direct` / `high`

<pre data-tacua-field="claim.claim-observed-label">The visible button label is Save draft, but the approved copy is Save profile.</pre>

Evidence: `evidence-keyframe-001`, `evidence-route-001`

### `claim-observed-submit` — `observed` / `direct` / `high`

<pre data-tacua-field="claim.claim-observed-submit">The first tap emits the SDK interaction event without a matching backend request; the second tap reaches the deployment.</pre>

Evidence: `evidence-tap-001`, `evidence-backend-001`

### `claim-diagnosis-copy` — `diagnosis` / `direct` / `high`

<pre data-tacua-field="claim.claim-diagnosis-copy">The tested mobile revision contains the stale label in the profile-form component snapshot.</pre>

Evidence: `evidence-repository-001`

### `claim-constraint-sentry` — `constraint` / `inferred` / `medium`

<pre data-tacua-field="claim.claim-constraint-sentry">Sentry correlation was unavailable because the synthetic connector was intentionally revoked.</pre>

Evidence: `evidence-sentry-001`

### `claim-expected-behavior` — `expected` / `inferred` / `high`

<pre data-tacua-field="claim.claim-expected-behavior">The approved behavior is Save profile copy and exactly one update on the first enabled tap.</pre>

Evidence: `evidence-repository-001`, `evidence-backend-001`

## Reproduction

### Preconditions

<pre data-tacua-field="reproduction.precondition">Use the synthetic QA account with an editable profile.</pre>

<pre data-tacua-field="reproduction.precondition">Open the iOS build identified by this handoff.</pre>

### Steps

1. `step-open-profile` (claims: `claim-observed-label`; evidence: `evidence-route-001`)

<pre data-tacua-field="reproduction.step-open-profile">Open Settings, then select Edit profile.</pre>

2. `step-change-name` (claims: `claim-observed-label`; evidence: `evidence-keyframe-001`)

<pre data-tacua-field="reproduction.step-change-name">Change the display name to Synthetic Reviewer.</pre>

3. `step-tap-save` (claims: `claim-observed-submit`; evidence: `evidence-tap-001`, `evidence-backend-001`)

<pre data-tacua-field="reproduction.step-tap-save">Tap the visible Save draft button once and wait two seconds.</pre>

### Observed result

<pre data-tacua-field="reproduction.observed_result">The label is incorrect and the first tap does not submit the update.</pre>

Claims: `claim-observed-label`, `claim-observed-submit`

### Expected result

<pre data-tacua-field="reproduction.expected_result">The label reads Save profile and the first tap submits exactly one update.</pre>

Claims: `claim-expected-behavior`

Attempts/reproductions: `2` / `2`

## Scope

### In scope

<pre data-tacua-field="scope.in_scope">Correct the profile-form button copy.</pre>

<pre data-tacua-field="scope.in_scope">Make a single enabled tap submit exactly once.</pre>

<pre data-tacua-field="scope.in_scope">Add focused regression coverage.</pre>

### Out of scope

<pre data-tacua-field="scope.out_of_scope">Do not change profile API semantics.</pre>

<pre data-tacua-field="scope.out_of_scope">Do not deploy or merge from this handoff.</pre>

## Acceptance criteria

### `criterion-copy`

<pre data-tacua-field="acceptance.criterion-copy.criterion">The enabled action label is Save profile in the tested locale.</pre>

Verification:

<pre data-tacua-field="acceptance.criterion-copy.verification">Run the focused component test and inspect the iOS profile-form state.</pre>

### `criterion-single-submit`

<pre data-tacua-field="acceptance.criterion-single-submit.criterion">One enabled tap produces one profile update without a second tap.</pre>

Verification:

<pre data-tacua-field="acceptance.criterion-single-submit.verification">Run the focused interaction test with the request adapter stub.</pre>

## Clarifications and open questions

### `clarification-copy-source` — `blocking` / `resolved`

<pre data-tacua-field="clarification.clarification-copy-source.question">Which copy is authoritative?</pre>

<pre data-tacua-field="clarification.clarification-copy-source.resolution">Save profile is the approved English copy for V1.</pre>

## Build snapshots

- Mobile: `ios` / `com.example.samplemobileapp.tacua.synthetic` / `1.7.0 (31)`
- Mobile source: `repo-sample-mobile-app@0123456789abcdef0123456789abcdef01234567`
- Backend: `deploy-synthetic-042` / `sha256:2222222222222222222222222222222222222222222222222222222222222222`
- Backend source: `repo-sample-backend@89abcdef0123456789abcdef0123456789abcdef`

## Authorized evidence references

### `evidence-route-001` — `sdk.route_transition` / `available`

<pre data-tacua-field="evidence.evidence-route-001.description">SDK route transition into the profile editor.</pre>

- Revision: `revision-route-001`
- Content: `application/vnd.tacua.sdk-event+json` / `912` bytes / `sha256:4444444444444444444444444444444444444444444444444444444444444444`
- Authorization: `decision-route-001` / `tacua.egress@1.0.0`

### `evidence-keyframe-001` — `media.keyframe` / `available`

<pre data-tacua-field="evidence.evidence-keyframe-001.description">Authorized keyframe showing the incorrect button label; pixels remain reference-only.</pre>

- Revision: `revision-keyframe-001`
- Content: `image/png` / `48123` bytes / `sha256:5555555555555555555555555555555555555555555555555555555555555555`
- Authorization: `decision-keyframe-001` / `tacua.egress@1.0.0`

### `evidence-tap-001` — `sdk.user_interaction` / `available`

<pre data-tacua-field="evidence.evidence-tap-001.description">SDK metadata for the first enabled save-button interaction.</pre>

- Revision: `revision-tap-001`
- Content: `application/vnd.tacua.sdk-event+json` / `608` bytes / `sha256:6666666666666666666666666666666666666666666666666666666666666666`
- Authorization: `decision-tap-001` / `tacua.egress@1.0.0`

### `evidence-repository-001` — `repository.commit_snapshot` / `available`

<pre data-tacua-field="evidence.evidence-repository-001.description">Commit-scoped, read-only repository search snapshot for the profile-form label.</pre>

- Revision: `revision-repository-001`
- Content: `application/vnd.tacua.connector-snapshot+json` / `2048` bytes / `sha256:7777777777777777777777777777777777777777777777777777777777777777`
- Authorization: `decision-repository-001` / `tacua.egress@1.0.0`

### `evidence-backend-001` — `backend.deployment_snapshot` / `available`

<pre data-tacua-field="evidence.evidence-backend-001.description">Immutable backend deployment and request-count snapshot for the session window.</pre>

- Revision: `revision-backend-001`
- Content: `application/vnd.tacua.connector-snapshot+json` / `1344` bytes / `sha256:8888888888888888888888888888888888888888888888888888888888888888`
- Authorization: `decision-backend-001` / `tacua.egress@1.0.0`

### `evidence-sentry-001` — `observability.sentry_snapshot` / `unavailable`

<pre data-tacua-field="evidence.evidence-sentry-001.description">Sentry correlation status for this synthetic session.</pre>

- Unavailable reason: `connector_revoked`

<pre data-tacua-field="evidence.evidence-sentry-001.unavailable">The synthetic connector was revoked before the bounded read. No Sentry payload was copied.</pre>

## Structural scope — not execution authority

- This file is not execution authorization. Before acting, obtain and verify a current trusted registry assertion for this exact handoff digest.
- Only after that independent authorization, the requested scope permits reading the authorized evidence references, modifying code in the listed repositories, and running tests.
- This structural scope never permits external writes, merge, or deploy.
- Repositories: `repo-sample-mobile-app`, `repo-sample-backend`

## Canonical JSON

The escaped canonical JSON below is the complete machine-equivalent representation.

<pre><code class="language-json">{"approval":{"actor_id":"member-approver-001","approval_id":"approval-synthetic-001","approved_at":"2026-07-20T10:16:00Z","immutable":true,"organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","state":"approved","ticket_content_digest":"sha256:bdbfb5ffb6153847b5a111d577309a70b3f86c8772ba238db332eca62758fc7f","ticket_id":"ticket-synthetic-001","ticket_version":4},"authority":{"allowed_repositories":["repo-sample-mobile-app","repo-sample-backend"],"deploy":false,"external_writes":false,"merge":false,"modify_code":true,"purpose":"implement_approved_ticket","read_authorized_evidence":true,"run_tests":true},"build_identity":{"backend":{"availability":"available","deployed_at":"2026-07-20T09:55:00Z","deployment_id":"deploy-synthetic-042","environment":"synthetic-qa","image_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","sources":[{"dirty":false,"repository_id":"repo-sample-backend","revision":"89abcdef0123456789abcdef0123456789abcdef"}],"unavailable_reason":null},"build_id":"build-ios-synthetic-031","build_identity_digest":"sha256:f64af91f8587624ef1f7be29e7651a44b82e86f922ee4bc15c3105f9d467550b","contract_version":"tacua.build-identity@1.0.0","media_type":"application/vnd.tacua.build-identity+json;version=1.0.0","mobile":{"app_version":"1.7.0","application_id":"com.example.samplemobileapp.tacua.synthetic","build_number":"31","distribution":"testflight","native_binary_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","platform":"ios","source":{"dirty":false,"repository_id":"repo-sample-mobile-app","revision":"0123456789abcdef0123456789abcdef01234567"}},"organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","sdk":{"capture_schema_version":"tacua.sdk-evidence@1.0.0","configuration_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","package_name":"@tacua/mobile-sdk","package_version":"0.1.0","source_revision":"fedcba9876543210fedcba9876543210fedcba98"}},"contract_version":"tacua.approved-handoff@1.1.0","evidence_manifest":{"contract_version":"tacua.evidence-manifest@1.0.0","evidence_manifest_digest":"sha256:43483eaf0a5a55a120c9cfee704ebfbafd3db95dd89d8e6ff5ff8ca320d38f0f","items":[{"authorization":{"actor_id":"member-approver-001","approved_at":"2026-07-20T10:15:00Z","authorized_for_handoff":true,"decision_id":"decision-route-001","evidence_id":"evidence-route-001","immutable":true,"organization_id":"org-synthetic","policy_version":"tacua.egress@1.0.0","project_id":"project-sample-mobile-app-synthetic"},"availability":"available","contract_version":"tacua.evidence-item@1.0.0","description":"SDK route transition into the profile editor.","evidence_id":"evidence-route-001","evidence_item_digest":"sha256:e6b5eba909829a62c973a0e32d9f1a56340eeb2a5281bce40ee3dde1e31d3680","evidence_type":"sdk.route_transition","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":{"content_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","content_type":"application/vnd.tacua.sdk-event+json","locator":{"evidence_id":"evidence-route-001","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","revision_id":"revision-route-001","scheme":"tacua-evidence"},"size_bytes":912},"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:00:01Z","component":"mobile_sdk","snapshot_revision":"sdk-event-0007","source_id":"sdk-session-001"},"time_range":{"clock":"session_monotonic","end_ms":1260,"start_ms":1200},"unavailable":null},{"authorization":{"actor_id":"member-approver-001","approved_at":"2026-07-20T10:15:00Z","authorized_for_handoff":true,"decision_id":"decision-keyframe-001","evidence_id":"evidence-keyframe-001","immutable":true,"organization_id":"org-synthetic","policy_version":"tacua.egress@1.0.0","project_id":"project-sample-mobile-app-synthetic"},"availability":"available","contract_version":"tacua.evidence-item@1.0.0","description":"Authorized keyframe showing the incorrect button label; pixels remain reference-only.","evidence_id":"evidence-keyframe-001","evidence_item_digest":"sha256:f4e4427f4ef61ed33700b9f5874be68e5df6452f42e585ff719fffe5fc5be843","evidence_type":"media.keyframe","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":{"content_digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","content_type":"image/png","locator":{"evidence_id":"evidence-keyframe-001","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","revision_id":"revision-keyframe-001","scheme":"tacua-evidence"},"size_bytes":48123},"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:00:04Z","component":"mobile_sdk","snapshot_revision":"keyframe-001","source_id":"sdk-session-001"},"time_range":{"clock":"session_monotonic","end_ms":3900,"start_ms":3900},"unavailable":null},{"authorization":{"actor_id":"member-approver-001","approved_at":"2026-07-20T10:15:00Z","authorized_for_handoff":true,"decision_id":"decision-tap-001","evidence_id":"evidence-tap-001","immutable":true,"organization_id":"org-synthetic","policy_version":"tacua.egress@1.0.0","project_id":"project-sample-mobile-app-synthetic"},"availability":"available","contract_version":"tacua.evidence-item@1.0.0","description":"SDK metadata for the first enabled save-button interaction.","evidence_id":"evidence-tap-001","evidence_item_digest":"sha256:56991e60d9660e2be5fc340bfba1f4f5b81c75fd6a19e938f2a4785cfc9ce55e","evidence_type":"sdk.user_interaction","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":{"content_digest":"sha256:6666666666666666666666666666666666666666666666666666666666666666","content_type":"application/vnd.tacua.sdk-event+json","locator":{"evidence_id":"evidence-tap-001","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","revision_id":"revision-tap-001","scheme":"tacua-evidence"},"size_bytes":608},"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:00:04Z","component":"mobile_sdk","snapshot_revision":"sdk-event-0012","source_id":"sdk-session-001"},"time_range":{"clock":"session_monotonic","end_ms":4240,"start_ms":4200},"unavailable":null},{"authorization":{"actor_id":"member-approver-001","approved_at":"2026-07-20T10:15:00Z","authorized_for_handoff":true,"decision_id":"decision-repository-001","evidence_id":"evidence-repository-001","immutable":true,"organization_id":"org-synthetic","policy_version":"tacua.egress@1.0.0","project_id":"project-sample-mobile-app-synthetic"},"availability":"available","contract_version":"tacua.evidence-item@1.0.0","description":"Commit-scoped, read-only repository search snapshot for the profile-form label.","evidence_id":"evidence-repository-001","evidence_item_digest":"sha256:147956c3559a97a6b6dba078b41bb06e85cd4d917b0fe8ce2733c2df4709f231","evidence_type":"repository.commit_snapshot","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":{"content_digest":"sha256:7777777777777777777777777777777777777777777777777777777777777777","content_type":"application/vnd.tacua.connector-snapshot+json","locator":{"evidence_id":"evidence-repository-001","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","revision_id":"revision-repository-001","scheme":"tacua-evidence"},"size_bytes":2048},"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:07:00Z","component":"repository","snapshot_revision":"0123456789abcdef0123456789abcdef01234567","source_id":"repo-sample-mobile-app"},"time_range":null,"unavailable":null},{"authorization":{"actor_id":"member-approver-001","approved_at":"2026-07-20T10:15:00Z","authorized_for_handoff":true,"decision_id":"decision-backend-001","evidence_id":"evidence-backend-001","immutable":true,"organization_id":"org-synthetic","policy_version":"tacua.egress@1.0.0","project_id":"project-sample-mobile-app-synthetic"},"availability":"available","contract_version":"tacua.evidence-item@1.0.0","description":"Immutable backend deployment and request-count snapshot for the session window.","evidence_id":"evidence-backend-001","evidence_item_digest":"sha256:b703d8bcc07247e8f3c98ae64a0a04b344538b934e210d4c579def4a45ae285b","evidence_type":"backend.deployment_snapshot","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":{"content_digest":"sha256:8888888888888888888888888888888888888888888888888888888888888888","content_type":"application/vnd.tacua.connector-snapshot+json","locator":{"evidence_id":"evidence-backend-001","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","revision_id":"revision-backend-001","scheme":"tacua-evidence"},"size_bytes":1344},"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:08:00Z","component":"backend","snapshot_revision":"backend-snapshot-001","source_id":"deploy-synthetic-042"},"time_range":{"clock":"session_monotonic","end_ms":9000,"start_ms":4000},"unavailable":null},{"authorization":null,"availability":"unavailable","contract_version":"tacua.evidence-item@1.0.0","description":"Sentry correlation status for this synthetic session.","evidence_id":"evidence-sentry-001","evidence_item_digest":"sha256:c120f94f1ccdf7ea5aad97205d9fc5abc2cb9d8a30f39a8eff0ddd5a4b78042b","evidence_type":"observability.sentry_snapshot","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","reference":null,"session_id":"session-synthetic-001","source":{"captured_at":"2026-07-20T10:09:00Z","component":"sentry","snapshot_revision":"unavailable-001","source_id":"sentry-project-synthetic"},"time_range":{"clock":"session_monotonic","end_ms":9000,"start_ms":0},"unavailable":{"detail":"The synthetic connector was revoked before the bounded read. No Sentry payload was copied.","reason":"connector_revoked"}}],"manifest_id":"manifest-synthetic-001","media_type":"application/vnd.tacua.evidence-manifest+json;version=1.0.0","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","session_id":"session-synthetic-001"},"handoff_digest":"sha256:0c0db4a908a371bb925440d5a3d8680ca9c8f544b93743cc416dc5a8786b1e21","media_type":"application/vnd.tacua.approved-handoff+json;version=1.1.0","organization_id":"org-synthetic","project_id":"project-sample-mobile-app-synthetic","source_candidate":{"candidate_content_digest":"sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f","candidate_digest":"sha256:e30833bc2cc5cdac3cf5baa9b19d0b49badce6a1a11152562a3d4910b44084c7","candidate_id":"ticket-synthetic-001","candidate_version":4,"canonical_json":"{\"approval\":{\"actor_id\":\"member-approver-001\",\"actor_type\":\"human\",\"approval_id\":\"approval-synthetic-001\",\"approved_at\":\"2026-07-20T10:16:00Z\",\"approved_candidate_version\":4,\"authorized_evidence_ids\":[\"evidence-backend-001\",\"evidence-keyframe-001\",\"evidence-repository-001\",\"evidence-route-001\",\"evidence-sentry-001\",\"evidence-tap-001\"],\"candidate_content_digest\":\"sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f\",\"evidence_manifest_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"immutable\":true,\"reviewed_candidate_digest\":\"sha256:9999999999999999999999999999999999999999999999999999999999999999\",\"reviewed_candidate_version\":3},\"build_id\":\"build-ios-synthetic-031\",\"build_identity_digest\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"candidate_content_digest\":\"sha256:b745427ba3a05ec4366c1fea950b52e7e883117e9251160b5886d6fae09b8c2f\",\"candidate_created_at\":\"2026-07-20T10:10:00Z\",\"candidate_digest\":\"sha256:e30833bc2cc5cdac3cf5baa9b19d0b49badce6a1a11152562a3d4910b44084c7\",\"candidate_id\":\"ticket-synthetic-001\",\"candidate_version\":4,\"content\":{\"acceptance_criteria\":[{\"claim_refs\":[\"claim-expected-behavior\"],\"criterion\":\"The enabled action label is Save profile in the tested locale.\",\"criterion_id\":\"criterion-copy\",\"evidence_refs\":[\"evidence-backend-001\",\"evidence-repository-001\"],\"verification\":\"Run the focused component test and inspect the iOS profile-form state.\"},{\"claim_refs\":[\"claim-observed-submit\"],\"criterion\":\"One enabled tap produces one profile update without a second tap.\",\"criterion_id\":\"criterion-single-submit\",\"evidence_refs\":[\"evidence-backend-001\",\"evidence-tap-001\"],\"verification\":\"Run the focused interaction test with the request adapter stub.\"}],\"actual_behavior\":{\"claim_refs\":[\"claim-observed-label\",\"claim-observed-submit\"],\"evidence_refs\":[\"evidence-backend-001\",\"evidence-keyframe-001\",\"evidence-route-001\",\"evidence-tap-001\"],\"text\":\"The label is incorrect and the first tap does not submit the update.\"},\"claims\":[{\"claim_id\":\"claim-observed-label\",\"confidence\":\"high\",\"evidence_refs\":[\"evidence-keyframe-001\",\"evidence-route-001\"],\"kind\":\"observed\",\"statement\":\"The visible button label is Save draft, but the approved copy is Save profile.\",\"support\":\"direct\"},{\"claim_id\":\"claim-observed-submit\",\"confidence\":\"high\",\"evidence_refs\":[\"evidence-tap-001\",\"evidence-backend-001\"],\"kind\":\"observed\",\"statement\":\"The first tap emits the SDK interaction event without a matching backend request; the second tap reaches the deployment.\",\"support\":\"direct\"},{\"claim_id\":\"claim-diagnosis-copy\",\"confidence\":\"high\",\"evidence_refs\":[\"evidence-repository-001\"],\"kind\":\"diagnosis\",\"statement\":\"The tested mobile revision contains the stale label in the profile-form component snapshot.\",\"support\":\"direct\"},{\"claim_id\":\"claim-constraint-sentry\",\"confidence\":\"medium\",\"evidence_refs\":[\"evidence-sentry-001\"],\"kind\":\"constraint\",\"statement\":\"Sentry correlation was unavailable because the synthetic connector was intentionally revoked.\",\"support\":\"inferred\"},{\"claim_id\":\"claim-expected-behavior\",\"confidence\":\"high\",\"evidence_refs\":[\"evidence-repository-001\",\"evidence-backend-001\"],\"kind\":\"expected\",\"statement\":\"The approved behavior is Save profile copy and exactly one update on the first enabled tap.\",\"support\":\"inferred\"}],\"clarifications\":[{\"choices\":[{\"choice_id\":\"choice-keep-current\",\"consequence\":\"No copy correction would be requested.\",\"description\":\"Keep the copy observed in the tested build.\",\"evidence_refs\":[\"evidence-keyframe-001\"],\"label\":\"Keep current copy\",\"presentation\":{\"evidence_ref\":null,\"kind\":\"text\",\"value\":\"Save draft\"},\"requires_note\":false},{\"choice_id\":\"choice-use-approved\",\"consequence\":\"The ticket requests the approved label.\",\"description\":\"Use the reviewer-approved V1 copy.\",\"evidence_refs\":[\"evidence-repository-001\"],\"label\":\"Use approved copy\",\"presentation\":{\"evidence_ref\":null,\"kind\":\"text\",\"value\":\"Save profile\"},\"requires_note\":false}],\"clarification_id\":\"clarification-copy-source\",\"impact\":\"blocking\",\"question\":\"Which copy is authoritative?\",\"resolution_note\":\"Save profile is the approved English copy for V1.\",\"selected_choice_id\":\"choice-use-approved\",\"status\":\"resolved\",\"target\":\"expected_behavior\"}],\"expected_behavior\":{\"claim_refs\":[\"claim-expected-behavior\"],\"evidence_refs\":[\"evidence-backend-001\",\"evidence-repository-001\"],\"text\":\"The label reads Save profile and the first tap submits exactly one update.\"},\"priority\":\"P1\",\"reproduction\":{\"attempts\":2,\"preconditions\":[{\"claim_refs\":[],\"evidence_refs\":[],\"precondition_id\":\"precondition-1\",\"text\":\"Use the synthetic QA account with an editable profile.\"},{\"claim_refs\":[],\"evidence_refs\":[],\"precondition_id\":\"precondition-2\",\"text\":\"Open the iOS build identified by this handoff.\"}],\"reproductions\":2,\"steps\":[{\"action\":\"Open Settings, then select Edit profile.\",\"actual_result\":null,\"claim_refs\":[\"claim-observed-label\"],\"confidence\":\"high\",\"evidence_refs\":[\"evidence-route-001\"],\"expected_result\":null,\"step_id\":\"step-open-profile\"},{\"action\":\"Change the display name to Synthetic Reviewer.\",\"actual_result\":null,\"claim_refs\":[\"claim-observed-label\"],\"confidence\":\"high\",\"evidence_refs\":[\"evidence-keyframe-001\"],\"expected_result\":null,\"step_id\":\"step-change-name\"},{\"action\":\"Tap the visible Save draft button once and wait two seconds.\",\"actual_result\":null,\"claim_refs\":[\"claim-observed-submit\"],\"confidence\":\"high\",\"evidence_refs\":[\"evidence-tap-001\",\"evidence-backend-001\"],\"expected_result\":null,\"step_id\":\"step-tap-save\"}]},\"scope\":{\"in_scope\":[\"Correct the profile-form button copy.\",\"Make a single enabled tap submit exactly once.\",\"Add focused regression coverage.\"],\"out_of_scope\":[\"Do not change profile API semantics.\",\"Do not deploy or merge from this handoff.\"]},\"summary\":{\"claim_refs\":[\"claim-observed-label\",\"claim-observed-submit\"],\"evidence_refs\":[\"evidence-backend-001\",\"evidence-keyframe-001\",\"evidence-route-001\",\"evidence-tap-001\"],\"text\":\"The new profile form displays the wrong button label and submits only after a second tap.\"},\"title\":\"Save button shows literal ](javascript:synthetic) copy\",\"uncertainty\":{\"items\":[{\"evidence_refs\":[\"evidence-sentry-001\"],\"impact\":\"non_blocking\",\"statement\":\"The unavailable Sentry correlation remains an explicit non-blocking limitation.\",\"uncertainty_id\":\"uncertainty-sentry-correlation\"}],\"overall_confidence\":\"medium\"}},\"contract_version\":\"tacua.ticket-candidate@1.0.0\",\"evidence_manifest\":{\"evidence_ids\":[\"evidence-backend-001\",\"evidence-keyframe-001\",\"evidence-repository-001\",\"evidence-route-001\",\"evidence-sentry-001\",\"evidence-tap-001\"],\"manifest_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"manifest_id\":\"manifest-synthetic-001\"},\"lineage\":{\"operation\":\"approved\",\"parents\":[{\"candidate_digest\":\"sha256:9999999999999999999999999999999999999999999999999999999999999999\",\"candidate_id\":\"ticket-synthetic-001\",\"candidate_version\":3}]},\"media_type\":\"application/vnd.tacua.ticket-candidate+json;version=1.0.0\",\"organization_id\":\"org-synthetic\",\"previous_candidate_digest\":\"sha256:9999999999999999999999999999999999999999999999999999999999999999\",\"project_id\":\"project-sample-mobile-app-synthetic\",\"rejection\":null,\"review\":{\"last_human_actor_id\":\"member-approver-001\",\"last_reviewed_at\":\"2026-07-20T10:15:30Z\",\"notes\":[\"Synthetic fixture review only.\"],\"reviewer_action_required\":false,\"status\":\"reviewed\"},\"session_id\":\"session-synthetic-001\",\"state\":\"approved\",\"transition\":{\"actor\":{\"actor_id\":\"member-approver-001\",\"actor_type\":\"human\"},\"from_state\":\"ready_for_review\",\"occurred_at\":\"2026-07-20T10:16:00Z\",\"reason\":\"Synthetic owner approved the exact reviewed candidate.\",\"to_state\":\"approved\"},\"version_created_at\":\"2026-07-20T10:16:00Z\"}","contract_version":"tacua.ticket-candidate@1.0.0"},"supersession":{"checked_at":"2026-07-20T10:16:00Z","registry_revision":"registry-revision-001","status":"current","superseded_by_handoff_digest":null,"supersedes_handoff_digest":null},"ticket":{"acceptance_criteria":[{"criterion":"The enabled action label is Save profile in the tested locale.","criterion_id":"criterion-copy","verification":"Run the focused component test and inspect the iOS profile-form state."},{"criterion":"One enabled tap produces one profile update without a second tap.","criterion_id":"criterion-single-submit","verification":"Run the focused interaction test with the request adapter stub."}],"claims":[{"claim_id":"claim-observed-label","confidence":"high","evidence_refs":["evidence-keyframe-001","evidence-route-001"],"kind":"observed","statement":"The visible button label is Save draft, but the approved copy is Save profile.","support":"direct"},{"claim_id":"claim-observed-submit","confidence":"high","evidence_refs":["evidence-tap-001","evidence-backend-001"],"kind":"observed","statement":"The first tap emits the SDK interaction event without a matching backend request; the second tap reaches the deployment.","support":"direct"},{"claim_id":"claim-diagnosis-copy","confidence":"high","evidence_refs":["evidence-repository-001"],"kind":"diagnosis","statement":"The tested mobile revision contains the stale label in the profile-form component snapshot.","support":"direct"},{"claim_id":"claim-constraint-sentry","confidence":"medium","evidence_refs":["evidence-sentry-001"],"kind":"constraint","statement":"Sentry correlation was unavailable because the synthetic connector was intentionally revoked.","support":"inferred"},{"claim_id":"claim-expected-behavior","confidence":"high","evidence_refs":["evidence-repository-001","evidence-backend-001"],"kind":"expected","statement":"The approved behavior is Save profile copy and exactly one update on the first enabled tap.","support":"inferred"}],"clarifications":[{"clarification_id":"clarification-copy-source","impact":"blocking","question":"Which copy is authoritative?","resolution":"Save profile is the approved English copy for V1.","status":"resolved"}],"priority":"P1","reproduction":{"attempts":2,"expected_claim_refs":["claim-expected-behavior"],"expected_result":"The label reads Save profile and the first tap submits exactly one update.","observed_claim_refs":["claim-observed-label","claim-observed-submit"],"observed_result":"The label is incorrect and the first tap does not submit the update.","preconditions":["Use the synthetic QA account with an editable profile.","Open the iOS build identified by this handoff."],"reproductions":2,"steps":[{"action":"Open Settings, then select Edit profile.","claim_refs":["claim-observed-label"],"evidence_refs":["evidence-route-001"],"step_id":"step-open-profile"},{"action":"Change the display name to Synthetic Reviewer.","claim_refs":["claim-observed-label"],"evidence_refs":["evidence-keyframe-001"],"step_id":"step-change-name"},{"action":"Tap the visible Save draft button once and wait two seconds.","claim_refs":["claim-observed-submit"],"evidence_refs":["evidence-tap-001","evidence-backend-001"],"step_id":"step-tap-save"}]},"scope":{"in_scope":["Correct the profile-form button copy.","Make a single enabled tap submit exactly once.","Add focused regression coverage."],"out_of_scope":["Do not change profile API semantics.","Do not deploy or merge from this handoff."]},"state":"approved","summary":"The new profile form displays the wrong button label and submits only after a second tap.","summary_claim_refs":["claim-observed-label","claim-observed-submit"],"ticket_content_digest":"sha256:bdbfb5ffb6153847b5a111d577309a70b3f86c8772ba238db332eca62758fc7f","ticket_id":"ticket-synthetic-001","ticket_version":4,"title":"Save button shows literal ](javascript:synthetic) copy"}}</code></pre>
