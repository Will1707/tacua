# ADR-014: Atomic processing-result publication

- Status: accepted
- Date: 2026-07-22
- Scope: Tacua V1 backend processing boundary

## Context

Completion creates an immutable, default-deny processing job, but a worker must
not expose a ticket before its evidence and screenshot previews are durable.
Likewise, a crash cannot leave some candidates visible while the job still
claims to be running, or mark a job successful before all of its candidates are
reviewable. Tacua does not yet have a real transcription, research, model, or
connector implementation and must not manufacture model output to demonstrate
this boundary.

## Decision

The backend defines two closed internal result types:

- `PublicationCandidate` contains one contract-valid generated candidate, its
  exact candidate-evidence manifest, and bounded preview inputs.
- `ProcessingResult` has either `candidates_created` with one through 256
  candidate bundles, or the explicit `no_issue_detected` disposition with no
  candidates. It always includes a bounded NFC summary.

An optional injected `ProcessingEngine.process_stage` is the only automatic
runner boundary. No engine is configured by default, normal startup is inert,
and one runner call claims and processes at most one stage. The persisted job
continues to carry the frozen `default_deny`, unauthorized egress policy. This
repository supplies no real engine, model call, connector, or egress grant.
There is no HTTP worker or result-publication route.

An engine exception is recorded as a bounded retryable stage failure. An engine
that returns a terminal result before `generate_tickets`, or returns no terminal
result at that final stage, violates the injected interface and durably fails
the attempt while removing its lease. Invalid output is never left running
until lease expiry.

For a candidate result, publication has two phases under the V1 single-process
critical section:

1. Validate the live `generate_tickets` lease and exact job/session/build
   binding. Every candidate must use a `system` transition actor whose ID is
   the exact lease worker ID, and all generation timestamps must be at or after
   the job request. Persist the evidence manifest and preview through the existing
   crash-safe evidence journal. These rows and files remain invisible to all
   reviewer routes because no candidate head exists. An exact retry adopts the
   already verified immutable evidence.
2. In one SQLite `BEGIN IMMEDIATE` transaction, revalidate the same live lease,
   insert every generated candidate version and head on the caller's
   connection, append the sealed terminal `succeeded` job version with sorted
   unique candidate references and the exact union of evidence references,
   resolve every output back to its candidate, manifest, and verified preview
   bytes, and delete the lease. Any error rolls the entire visible publication
   back.

`no_issue_detected` skips artifact staging but uses the same final transaction.
Its candidate and evidence reference arrays must both be empty, and no
generated candidate may exist for that session.

The ordinary final-stage checkpoint remains forbidden with
`PROCESSING_PUBLICATION_REQUIRED`. The legacy single-candidate
`persist_candidate_bundle` boundary returns the same error before writing any
evidence or candidate state. Only terminal result publication can expose a
generated head. Startup and every successful-job admin read revalidate the
complete job chain and resolve the terminal output population. Missing or
changed candidate rows, manifests, projections, preview metadata, or preview
bytes fail closed. Session deletion removes both published output and unpublished
staged evidence; a crash before the final transaction can therefore leave only
retention-scoped, reviewer-invisible staging.

## Consequences

- Candidate visibility, terminal success, and lease release have one commit
  point, including multi-candidate results.
- A processor crash after evidence staging may require deterministic
  recomputation of the candidate document, but immutable evidence staging is
  safely reusable and deletion remains authoritative.
- The implementation is still single-process and SQLite-backed. It does not
  claim that the evidence filesystem and SQLite share one transaction; the
  evidence journal deliberately closes that gap before visibility.
- Installing a real engine, authorizing external egress, decoding media,
  transcribing narration, resolving repository/observability context, and
  generating grounded candidates remain separate release work.

## Rejected alternatives

- **Insert candidates one at a time:** exposes a partial result and cannot bind
  job success to the complete candidate set.
- **Mark the job successful before evidence publication:** allows a terminal
  job whose output cannot be reviewed.
- **Expose result submission over HTTP:** creates a new authentication and
  untrusted-worker threat boundary that V1 has not designed.
- **Run a demonstration model on startup:** violates inert startup and the
  fixed default-deny egress decision.
- **Treat an empty candidate list as implicit success:** loses the explicit
  distinction between a processor's no-issue conclusion and missing output.
