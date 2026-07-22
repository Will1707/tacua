<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-015: reviewer candidate split and merge semantics

- Status: proposed — product decision required
- Date: 2026-07-22
- Scope: Tacua V1 candidate review

## Context

The accepted product boundary says that the reviewer can split and merge ticket
candidates. The frozen `tacua.ticket-candidate@1.0.0` contract already permits a
new version-one candidate to record one `split` parent or two through sixteen
`merged` parents. It deliberately does not decide what happens to the source
heads, how evidence from several parents is combined, or what one atomic API and
reviewer interaction must do.

Those choices affect approval safety. Leaving source candidates actionable can
produce duplicate handoffs. Reusing only one merge parent's evidence can discard
the grounding for another parent. Encoding replacement as `rejected` would
misstate the reviewer's decision, while adding a `superseded` candidate state
would require a new contract version and changes to every validator and handoff
consumer.

The standalone contract can validate the shape of parent references, but only
the backend can prove that they identify exact, current, same-scope stored
versions.

## Fixed preparation

Regardless of the final operation semantics:

- `split` and `merged` creation is a human review action; a system or model actor
  is rejected by both authoritative candidate validators;
- every result starts as an unapproved version-one `draft` with a new candidate
  ID and immutable parent references;
- approval remains a later transition from the exact reviewed result version;
- source and result bindings must remain in one organization, project, session,
  tested build, and build-identity digest; and
- all parent counts, identifiers, versions, digests, request sizes, canonical
  JSON, idempotency, and stale-head preconditions fail closed.

These rules do not decide the source disposition or evidence-union behavior.

## Recommended decision

Accept **atomic replacement with an external supersession projection** for V1:

1. A split binds one exact current non-terminal source head and creates two
   through sixteen new draft candidates. Each result reuses the source's exact
   immutable evidence manifest. Each supplied content document must differ from
   the source and from every sibling result.
2. A merge binds two through sixteen distinct exact current non-terminal heads
   from the same capture/build and creates one new draft candidate. The backend
   creates an immutable evidence manifest containing the canonical deduplicated
   union of every source manifest item. The supplied merged content may refer
   only to that closed union.
3. One transaction validates every source head and manifest, creates all result
   manifests/bindings/heads, writes a durable operation record, and marks all
   sources superseded. Any conflict or failure writes none of those effects.
4. Supersession does not mutate or append a misleading rejection to a source
   candidate chain. A separate immutable relationship records the operation,
   human actor, time, exact source versions/digests, and exact result
   versions/digests.
5. Superseded sources remain available in history and evidence views, but are
   excluded from the active review queue and cannot be edited, approved,
   rejected, split, merged, or exported. The backend returns one stable
   `CANDIDATE_SUPERSEDED` conflict with the replacement references.
6. The operation request binds every source version, candidate digest, content
   digest, and evidence-manifest digest, plus the full contract-valid result
   content. One idempotency key covers the complete operation and exact response.
7. The reviewer UI seeds two editable copies for split and one combined draft
   for merge, keeps evidence selection within the permitted manifest, and shows
   a single confirmation summarizing which source tickets will leave the active
   queue. Suggestions may reduce typing, but the human confirms the exact
   resulting content and operation before it is submitted.
8. Supersession is not approval and grants no tracker, repository, model-egress,
   or agent-execution authority. Only the existing exact-version approval and
   handoff guards can grant a structural handoff.

## Smallest remaining product decision

Accept or reject the recommended atomic-replacement semantics above. If it is
rejected, the decision must instead state exactly one source disposition
(`remain active`, `auto-reject`, a new candidate `superseded` state, or another
named behavior) and one merge evidence rule (`exact union`, `same-manifest only`,
or another lossless rule). Backend endpoints and reviewer controls must remain
absent until both are fixed.

## Alternatives considered

- **Leave sources active:** preserves every existing contract state, but permits
  accidental duplicate approval and forces additional reviewer cleanup.
- **Auto-reject sources:** uses existing transitions, but falsely represents
  replacement as a finding that the reviewer judged invalid.
- **Add a terminal `superseded` state:** gives each source a self-contained
  history, but changes the frozen contract and all downstream validators.
- **Require identical manifests for merge:** avoids manifest construction, but
  prevents the common case where generated issues cite different evidence.
- **Keep only one source manifest:** is rejected because it can silently discard
  grounding from the other merged candidates.
