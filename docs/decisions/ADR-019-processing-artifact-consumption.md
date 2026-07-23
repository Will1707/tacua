# ADR-019: Lease-bound processing artifact consumption

- Status: accepted
- Date: 2026-07-23
- Scope: dormant Tacua processing pipeline 1.1

## Context

Pipeline 1.1 can persist an immutable transcript at the successful
`transcribe` checkpoint. The next stage must receive that transcript without
placing its body in a public job projection, accepting a stale worker result,
or allowing a completed reader slice to drift into the undesigned `correlate`
stage. Local adapter 1.0 is already a frozen internal wire contract used by
the legacy pipeline and cannot silently acquire new fields.

## Decision

Tacua adds explicit opt-in local command, input, and result contracts at
`1.1.0`. Pipeline 1.0 continues to receive and return the exact 1.0 documents.
Pipeline 1.1 may use adapter 1.1 only for `transcribe` and `align` in this
slice. Its input adds `stage_inputs.artifacts`: empty for transcription and
exactly one fully validated `tacua.processing-stage-artifact@1.0.0` transcript
for alignment. The existing input digest therefore binds the complete
transcript artifact to the current job version, job digest, worker and stage.

Artifact input resolution occurs inside the adapter's existing
deletion-excluding critical section and SQLite transaction. The store first
revalidates the exact live lease, completed session, immutable retention
boundary, job chain, artifact row, canonical artifact body and digest. It
returns a deep copy only for the lease-owned alignment stage. The body is put
only in the existing private, read-only, unlinked adapter input file. It is
not added to a job, HTTP response, reviewer route, log, error, or receipt.

Adapter result 1.1 checkpoints contain exact produced artifact drafts and
consumed `{artifact_id, artifact_digest}` references. Transcription must
produce one transcript and consume nothing. Alignment must produce no new
artifact in this deliberately narrow slice and consume the exact transcript
present in its input.

A successful alignment checkpoint atomically appends an immutable artifact
consumption receipt, appends the succeeded alignment job version, and removes
the exact lease. The receipt contains no transcript text. It binds deployment
scope, build, session and job; the source artifact ID, digest and checkpoint;
the consuming running job version, digest and attempt; the successful
checkpoint version and timestamp; and the unchanged derived-data expiry. No
receipt is written on invalid output, engine failure, stale lease, expiry,
deletion, or transaction rollback.

The receipt is the deliberate durable pause before `correlate`. Claim scanning
excludes jobs with a receipt before applying its bounded scan, so a paused
older job cannot starve other eligible work. This is a slice boundary, not a
generic future-stage scheduling rule; the next artifact/output contract must
replace it before correlate is enabled.

Normal backend startup remains inert. Production completion still creates
only `tacua.pipeline@1.0.0` jobs. No checked-in command selects adapter 1.1,
and no model, external egress, HTTP route, SDK contract, reviewer surface, or
Docker default changes. The isolated processor runner remains 1.0-only and
must be evolved separately before a real pipeline-1.1 private pilot.

## Consequences

- Legacy adapter bytes and processing behavior remain unchanged.
- Transcript disclosure requires an exact live alignment lease and remains
  inside the existing retention and deletion exclusion boundary.
- Successful consumption has a crash-safe, append-only lineage record, while
  retries cannot manufacture duplicate or premature receipts.
- Session deletion and retention expiry cascade both the transcript and its
  receipt; backup and restore preserve and startup-revalidate both.
- Pipeline 1.1 intentionally stops after align. This ADR does not define an
  aligned-transcript artifact or authorize correlate.

## Rejected alternatives

- **Add transcript fields to adapter 1.0:** silently breaks a frozen exact
  contract and existing processors.
- **Trust an artifact copied into the claim:** misses the live lease,
  retention and deletion revalidation performed immediately before admission.
- **Record consumption when input is opened:** an engine crash would claim
  successful consumption that never checkpointed.
- **Put the transcript or its digest in public job detail:** leaks derived
  evidence or creates an alternate, incomplete artifact projection.
- **Let correlate claim and fail:** consumes attempts, creates noisy retries,
  and allows paused jobs to interfere with bounded claim ordering.
