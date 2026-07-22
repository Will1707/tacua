<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua production draft ticket-candidate contract

This dependency-free candidate package defines the mutable-review boundary
between asynchronous issue generation and Tacua's immutable
`approved-handoff` export. It is a production-shaped runtime contract, not an
evaluation corpus format and not execution authority.

Contract version:
`tacua.ticket-candidate@1.0.0` / `application/vnd.tacua.ticket-candidate+json;version=1.0.0`.

## Exact identity owner

This package is the sole schema and validator owner for that exact contract
version and media type. Consumers must dispatch on both exact values and must
not choose a schema by inspecting payload fields.

The incompatible prototype formerly found in `contracts/runtime` now uses the
distinct `tacua.runtime-ticket-candidate@1.0.0` /
`application/vnd.tacua.runtime-ticket-candidate+json;version=1.0.0` identity.
It exists only as a recovery boundary for the original runtime bundle and is
not accepted here. The runtime package provides an explicit, shape-validating
migration for old prototype artifacts that carried this package's identity;
normal validation never treats the two contracts as aliases.

## Boundary

Each artifact is one immutable candidate-version snapshot. It binds:

- one organization, project, tested build and capture session;
- the tested build-identity digest;
- one evidence-manifest ID, digest and closed evidence-ID inventory;
- one candidate ID and monotonically increasing version;
- the exact preceding candidate digest and typed lineage operation;
- grounded ticket content, uncertainty and bounded visual clarification
  choices;
- the state transition and human-review status; and
- an optional immutable human approval or rejection.

The ticket content includes actual and expected behavior, typed claims,
preconditions, reproduction steps, acceptance criteria, scope, uncertainty and
clarifications. Direct and inferred claims must cite evidence. Every content
evidence reference must exist in the bound evidence inventory.

The compact evidence inventory is a digest binding, not an embedded evidence
manifest or payload. A backend must resolve `manifest_digest` to the immutable,
project-authorized evidence manifest before serving evidence or exporting an
approved handoff.

## Lifecycle and lineage

The normal review chain is:

```text
draft → needs_clarification → ready_for_review → approved | rejected
```

An approved or rejected snapshot is never edited. Reopening creates a later
`draft` version. Version one may be `generated`, `split` or `merged`; split and
merge creation always records a human actor. Later versions name exactly one
same-candidate predecessor and use `edited`,
`clarification_answered`, `reviewed`, `approved`, `rejected` or `reopened`.
Atomic split and merge requests use the closed
`candidate-replacement-request.schema.json` boundary. A split binds one exact
current source and two to sixteen distinct new result documents. A merge binds
two to sixteen exact current sources and one new result. The committed response
binds the immutable operation record to every exact source and result digest,
the full first-version draft snapshots, their human actor and creation time.
The portable validator proves request/response consistency; the backend remains
responsible for current-head checks, evidence resolution, the canonical merge
union, idempotency and one-transaction supersession.

Approval is itself a new immutable version derived from the exact
`ready_for_review` snapshot the human saw. It records both the reviewed parent
version/digest and the resulting approved version. Approval is accepted only
when:

- the transition and approval actor are human and agree;
- the parent is `ready_for_review`;
- ticket content and evidence binding did not change during approval;
- every blocking clarification is resolved;
- completed human review is recorded; and
- `authorized_evidence_ids` is exactly the set referenced by the ticket.

The `seal` helper recomputes hashes for fixtures and authoring. It cannot create
an authenticated actor, grant evidence access, or authorize a coding agent.

## Clarification choices

Every clarification offers two to five choices. A choice has short UI copy, a
consequence, an optional note requirement and one closed presentation:

- `text` with bounded display text;
- `evidence_thumbnail` with an internal evidence ID also cited by the choice;
- `color_swatch` with a six-digit hex color; or
- `sf_symbol` with a bounded safe symbol name.

No remote URL, image payload, credential or arbitrary UI object is allowed.
Unresolved questions have no selection. A resolved question selects a declared
choice, and a choice marked `requires_note` also requires a bounded resolution
note. `ready_for_review` and `approved` reject unresolved blocking questions.

## Validate locally

No package installation or network access is required:

```sh
cd contracts/ticket-candidate
python3 -B scripts/ticket_candidate.py validate-chain \
  fixtures/positive/version-1-draft.json \
  fixtures/positive/version-2-needs-clarification.json \
  fixtures/positive/version-3-ready.json \
  fixtures/positive/version-4-approved.json
python3 -B -m unittest discover -s tests -v
```

Regenerate the synthetic canonical fixtures only after an intentional contract
change:

```sh
python3 -B scripts/regenerate_fixtures.py
```

The validator implements the strict JSON Schema subset used here plus semantic
checks for canonical SHA-256 integrity, safe integers/NFC, forbidden NULs, secret-like values,
scope-bound evidence, claim grounding, choice presentation, lifecycle,
chronology, immutable version chains and exact human approval/rejection.
Unknown fields and contract versions fail closed.

## Approved-handoff mapping

An approved candidate is an input to, not a replacement for,
`contracts/approved-handoff`:

- candidate claims map to approved-handoff claims;
- reproduction and acceptance fields map to the approved ticket;
- resolved choices map to clarification question/resolution text;
- the backend resolves and authorizes the full evidence manifest;
- the approved candidate version becomes the exported ticket version; and
- the approved-handoff renderer applies its own strict structural and current
  registry checks.

Structural validation here never permits repository modification, tracker
writes, merge, deployment or external model egress.

## Known limitations

- Storage-level append-only enforcement, authentication, authorization,
  revocation and compare-and-swap concurrency are backend responsibilities.
- This package binds an evidence-manifest digest and inventory but does not
  validate or resolve evidence bytes.
- Replacement validation cannot prove a result differs from source content or
  resolve evidence bytes from source manifest digests. The backend performs
  those checks while holding the atomic storage transaction.
- It does not render Markdown/JSON handoffs; that remains the separately
  versioned approved-handoff contract.
- Runtime DLP must supplement the bundled obvious credential-pattern checks.

All files are synthetic and licensed under the repository's Apache-2.0 license.
