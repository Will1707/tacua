<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua runtime contract candidate

This dependency-free package defines the first capture-to-ticket vertical-slice boundary. It is deliberately separate from `contracts/approved-handoff`: a reviewed candidate is still **not** an executable agent authorization. Export and current external authorization remain the approved-handoff boundary.

## Exact V1 artifacts

| Artifact | Contract | Purpose |
|---|---|---|
| Capture/upload manifest | `tacua.capture-upload-manifest@1.0.0` | Recoverable app-only segments, checksums, explicit capture gaps, resumable upload receipts and retention state |
| Diagnostic envelope | `tacua.diagnostic-envelope@1.0.0` | Sanitized SDK events plus reference-only available or explicitly unavailable evidence |
| Processing job | `tacua.processing-job@1.0.0` | Versioned async state, immutable input digests, read-only context availability, default-deny model egress and output references |
| Retired runtime ticket prototype | `tacua.runtime-ticket-candidate@1.0.0` | Compatibility shape for the original four-artifact runtime fixture; it is not the production ticket-candidate contract |

## Ticket contract ownership and compatibility

The exact identity `tacua.ticket-candidate@1.0.0` and media type
`application/vnd.tacua.ticket-candidate+json;version=1.0.0` are owned solely by
the sibling [`contracts/ticket-candidate`](../ticket-candidate/README.md)
package. That production draft has a different shape and stricter lifecycle,
lineage, evidence-manifest, DLP and approval semantics.

An earlier runtime prototype accidentally used the same identity. Its schema is
retained under the distinct
`tacua.runtime-ticket-candidate@1.0.0` /
`application/vnd.tacua.runtime-ticket-candidate+json;version=1.0.0` pair so
existing prototype content can be recovered without continuing an ambiguous
wire contract. Normal runtime validation fails closed with
`CONTRACT_OWNERSHIP_MISMATCH` when it sees the authoritative identity.
`migrate_retired_runtime_ticket` is the only compatibility path: it accepts the
old identity pair, verifies the original prototype's shape and integrity,
rewrites and reseals it, and then validates the result. It therefore refuses
an actual production ticket-candidate artifact or tampered prototype rather
than shape-guessing at runtime.

New processing and reviewer implementations must produce and validate the
authoritative sibling contract. The retired runtime prototype remains only for
the original bundle fixture and must not be accepted as its substitute.

All artifacts carry organization, project, tested build and capture-session scope. All roots and nested typed objects use `additionalProperties: false`. Content, manifests, receipts, envelopes, jobs and candidates use SHA-256 integrity bindings. Unknown or missing evidence is represented as a typed unavailable state, never an invented empty payload.

The legacy fixture's job outputs intentionally reference its runtime prototype
candidate by ID and version, not by its final digest. The prototype then binds
the sealed final job digest. This is retained compatibility behavior, not the
production ticket-candidate provenance model.

The processing-job schema describes one sealed snapshot. The backend adds the
append-only transition policy: version one is exactly queued with every stage
pending at attempt zero; a queued retry also exposes a pending current stage
while its prior immutable version records the failed attempt; each new claim
increments that stage's attempt count; and the configured `max_attempts` is a
hard bound. The frozen schema requires every queued snapshot to have root
`started_at: null`, so the original start remains auditable in earlier versions
and is restored on running snapshots. Pipeline configuration, scope, inputs,
execution policy, and default-deny egress cannot change across a chain.

## Validation

No third-party package or network access is required:

```sh
cd contracts/runtime
python3 scripts/validate.py bundle fixtures/positive
python3 -m unittest discover -s tests -v
```

Regenerate the synthetic bundle after intentional contract changes:

```sh
python3 scripts/regenerate_fixture.py
```

The validator checks the bundled Draft 2020-12 subset plus cross-artifact scope, chronology, sequence, receipt/content checksum, lifecycle, grounding-reference and approval invariants. It rejects unknown contract versions. Consumers must implement exact-version dispatch; future changes require a new version and conformance fixtures rather than silently ignoring fields.

For the V1 narrated-capture boundary, a `complete` capture must contain at
least one verified media segment and declare the microphone stream enabled.
The optional closed `app_audio_accounting` projection is `null` or absent for
legacy schema-3 captures. Schema-4 admission binds every available runtime
segment to its exact append-attempt range and ordered drop indexes/causes,
records any ordered crash-reservation ranges, and seals the aggregate attempt
total plus reserved high-watermark. Semantic validation requires those known
and explicitly unknown ranges to cover every reserved index exactly once.
Raw-media expiry must be after capture start and no later than 30 days after
it; an operator may choose a shorter deployment policy. Receipt object IDs and
receipt digests are unique within a manifest, and every direct or inferred
ticket claim must cite evidence.

## Trust and payload boundary

- Evidence references use internal `tacua-evidence` locators; signed URLs, credentials, raw headers, request bodies and response bodies are not contract fields.
- Artifact digests (`manifest_digest`, `envelope_digest`, and `job_digest`) bind
  canonical contract content with their own digest field omitted. A transport
  may additionally checksum uploaded bytes, but that transport checksum must
  not be substituted for the artifact digest in downstream provenance.
- `unavailable` and capture/collection gaps are first-class and must remain visible to processing and review.
- External model destinations require an explicit default-deny authorization decision. Repository and SaaS context inputs are read-only.
- Human approval binds one exact candidate content digest and version. Editing after approval creates a new draft version; it does not mutate the approved snapshot.
- Successful structural validation never grants permission to modify a repository, write to a tracker, merge or deploy.

The capture, diagnostics and processing-job schemas are candidates for
backend/SDK integration. Production candidate generation and review must use
the sibling ticket-candidate package. Authentication, authorization, DLP,
object resolution, retention deletion and migration remain runtime
responsibilities.
