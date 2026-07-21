# ADR-013: V1 SDK-to-backend transport protocol

- Status: accepted
- Date: 2026-07-21
- Scope: `contracts/sdk-backend-protocol`

## Context

ADR-012 assigns capture, recovery, diagnostics, and upload to the SDK embedded
in the tested QA app. The runtime contracts define durable capture,
diagnostics, job, and candidate artifacts, but do not define how an SDK obtains
a scoped credential, retries uploads after a lost response, proves that the
backend stored exact bytes, or decides when local evidence may be deleted.

Without an exact transport contract, a retry can create duplicate sessions or
jobs, server-generated identifiers can diverge from a manifest, transport-byte
checksums can be confused with semantic artifact digests, and a client can
delete its only recoverable copy before the backend has made evidence durable.

## Decision

Tacua V1 uses `tacua.sdk-backend@1.0.0`, composed with the exact V1 runtime
artifacts. The protocol has these properties:

1. The immutable session scope binds organization, project, internal
   application, tested build identity, explicit app-only consent, and retention
   policy. The tested iOS bundle identifier belongs to the build identity and
   is not overloaded as Tacua's internal application ID. The build identity
   also binds `transport_configuration_digest`, the canonical-JSON digest of
   exactly `backend_origin` and `transport_policy_version`. The origin is
   normalized to a lowercase scheme and host with its default port removed and
   accepts only an empty or root path; a root `/` is normalized away, so the
   canonical origin has no trailing slash. User information, non-root paths,
   queries, and fragments are rejected. QA and production require HTTPS;
   loopback HTTP is local-development only.
2. The QA build pins that normalized backend origin and transport policy. A
   launch deep link supplies only an opaque code and cannot override them. The
   backend independently pins the expected build and transport digests, and the
   SDK rejects redirects rather than forwarding launch or bearer credentials
   to another target.
3. The SDK creates and Keychain-persists its credential before exchanging a
   single-use launch code. The backend stores only a verifier and returns no
   secret. Resume exchanges name the previous credential and durably prove its
   atomic revocation. A resumed receiving session gets an active credential; a
   resumed completed session gets only completion-replay-or-delete capability.
   Deleted sessions cannot resume. The server retains ordered credential
   history, so a rotation does not invalidate receipts accepted earlier under
   the credential that was current at that server acceptance time.
4. Every operation has a client-generated ID and canonical request digest.
   Exact retries return the exact durable receipt; same-ID conflicts fail. The
   backend first verifies the current bearer against its server-owned route,
   session, and scope without comparing the historical body credential ID. It
   then performs durable operation-ID and exact-digest lookup before new-
   operation body-ID equality and capability checks. A current active receiving
   credential may recover an exact upload accepted under an earlier credential
   in the same rotation history without rewriting the stored request or
   receipt. A current completed-session credential may recover only its bound
   exact completion (and delete), never an upload. A lookup miss requires a new
   operation whose body and Authorization both name the current credential.
5. Segment IDs and sequence numbers are SDK-generated and appear in the route,
   intent, durable receipt, and runtime capture manifest. Segment ID, sequence,
   content type, sidecar digest, size, and content digest bind exactly across
   those artifacts. Completion compares keyed sets rather than array arrival
   order. Transport checksums and semantic runtime digests remain explicit and
   separately named.
6. A diagnostic upload contains and validates the full runtime envelope. A
   completion contains the full runtime capture manifest and exact segment and
   diagnostic receipts. Its durable response contains a full queued runtime
   processing job.
7. Completion must use the current credential at the server's acceptance time
   and transitions that same SDK credential to
   `completion_replay_or_delete_only` and returns an exact payload-cleanup
   binding. It permits only exact completion replay or the first SDK deletion.
   Durable deletion revokes all evidence, upload, completion, and processing
   access, then transitions the verifier to `deletion_replay_only`. The backend
   retains that verifier and the exact tombstone response only until the bounded
   tombstone expiry. The deletion tombstone, not completion, authorizes Keychain
   secret removal.
8. JSON is strict, duplicate-key-free, NFC, integer-only canonical UTF-8. The
   repository ships normative Python/Swift digest vectors.
9. Authenticated artifacts carry the credential ID and bind it to their durable
   response and ordered session credential history. Authorization uses only
   server-issued acceptance times and half-open intervals
   `[issued_at, min(expires_at, revoked_at))`: segment runtime-receipt
   `received_at`, diagnostic-receipt `received_at`, completion-receipt
   `accepted_at`, and deletion-tombstone `accepted_at`. Client `requested_at`
   values remain chronology evidence but cannot extend or resurrect a
   credential. First deletion also requires the current completion-replay-or-
   delete credential at server acceptance; `deleted_at` records the later or
   equal durable erasure completion.
10. Launch receipts carry backend `received_at` and `issued_at`; only their
    server-internal ordering is authoritative. After launch, the SDK persists
    `issued_at` with a system-uptime monotonic anchor and derives all new
    lifecycle UTC timestamps from their elapsed delta. Authenticated server
    receipts may advance, but never rewind, that derived clock; resume
    establishes a fresh anchor. If uptime regresses after reboot or recovery
    cannot prove the anchor, the SDK must resume before creating or sending new
    timestamps.
    Launch and resume `requested_at` are non-authoritative because those
    exchanges establish or repair the anchor. Persisted offline requests keep
    their original anchor-derived timestamp for exact retry.

## Consequences

- Lost responses are safe to retry without duplicating durable state.
- Exact replay conformance covers both request content and byte-identical
  canonical persisted response content.
- Local evidence survives until the client can prove the backend has the exact
  manifest, every upload receipt, and a queued processing job.
- The backend must authenticate before accepting large bodies, validate scope
  again at commit, verify durable object integrity on replay, and recover
  interrupted object promotion and deletion.
- A completed-session resume cannot restore upload access, and a deleted session
  retains no capability beyond its bounded exact-deletion replay verifier.
- Partial-upload receipts survive credential rotation without weakening the
  rule that completion and deletion use the current credential.
- Lost upload and completion responses remain recoverable after rotation, but
  the exception cannot authorize a new operation or mutate historical IDs.
- Device wall-clock changes do not participate in authorization or post-launch
  lifecycle chronology.
- A launch code or deep link cannot select a different backend origin, and
  redirects cannot receive launch or bearer secrets.
- The runtime contracts remain the source of truth for artifact semantics;
  transport schemas reference them rather than duplicating them.
- A structurally valid completion or cleanup receipt grants neither ticket
  approval nor agent execution authority.

## Deferred

- Reviewer/admin APIs and candidate transition idempotency are separate
  boundaries.
- The contract does not choose a backend credential-hashing implementation,
  transport-signature scheme, object store, or asynchronous worker runtime.
- Android build identity and capture are deferred; V1 build identity is iOS
  only.
