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
   is not overloaded as Tacua's internal application ID.
2. The SDK creates and Keychain-persists its credential before exchanging a
   single-use launch code. The backend stores only a verifier and returns no
   secret. Resume exchanges rotate credentials.
3. Every operation has a client-generated ID and canonical request digest.
   Exact retries return the exact durable receipt; same-ID conflicts fail.
4. Segment IDs and sequence numbers are SDK-generated and appear in the route,
   intent, durable receipt, and runtime capture manifest. Transport checksums
   and semantic runtime digests remain explicit and separately named.
5. A diagnostic upload contains and validates the full runtime envelope. A
   completion contains the full runtime capture manifest and exact segment and
   diagnostic receipts. Its durable response contains a full queued runtime
   processing job.
6. Completion transitions the SDK credential to replay-only and returns an
   exact local-cleanup binding. The SDK writes a local cleanup tombstone before
   deleting payloads. Backend deletion revokes credentials before erasure and
   returns a bounded minimal tombstone only after erasure is durable.
7. JSON is strict, duplicate-key-free, NFC, integer-only canonical UTF-8. The
   repository ships normative Python/Swift digest vectors.

## Consequences

- Lost responses are safe to retry without duplicating durable state.
- Local evidence survives until the client can prove the backend has the exact
  manifest, every upload receipt, and a queued processing job.
- The backend must authenticate before accepting large bodies, validate scope
  again at commit, verify durable object integrity on replay, and recover
  interrupted object promotion and deletion.
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
