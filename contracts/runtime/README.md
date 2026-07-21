<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua runtime contract candidate

This dependency-free package defines the first capture-to-ticket vertical-slice boundary. It is deliberately separate from `contracts/approved-handoff`: a reviewed candidate is still **not** an executable agent authorization. Export and current external authorization remain the approved-handoff boundary.

## Exact V1 artifacts

| Artifact | Contract | Purpose |
|---|---|---|
| Capture/upload manifest | `tacua.capture-upload-manifest@1.0.0` | Recoverable app-only segments, checksums, explicit capture gaps, resumable upload receipts and retention state |
| Diagnostic envelope | `tacua.diagnostic-envelope@1.0.0` | Sanitized SDK events plus reference-only available or explicitly unavailable evidence |
| Processing job | `tacua.processing-job@1.0.0` | Versioned async state, immutable input digests, read-only context availability, default-deny model egress and output references |
| Ticket candidate | `tacua.ticket-candidate@1.0.0` | Editable lifecycle with grounded actual/expected behavior, reproduction, acceptance, uncertainty, visualizable clarification choices and human approval |

All artifacts carry organization, project, tested build and capture-session scope. All roots and nested typed objects use `additionalProperties: false`. Content, manifests, receipts, envelopes, jobs and candidates use SHA-256 integrity bindings. Unknown or missing evidence is represented as a typed unavailable state, never an invented empty payload.

Job outputs intentionally reference a generated candidate by ID and version, not by its final digest. The candidate then binds the sealed final job digest. This direction avoids a cryptographic dependency cycle while preserving an auditable provenance chain.

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

The schemas and fixture are candidates for backend/SDK integration. Production authentication, authorization, DLP, object resolution, retention deletion and migration remain runtime responsibilities.
