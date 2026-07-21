<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua SDK/backend V1 protocol

This package defines the exact-versioned, dependency-free protocol between a
Tacua SDK embedded in an authorized iOS QA build and one self-hosted Tacua
backend. It composes the sibling `contracts/runtime` artifacts rather than
forking them: diagnostic requests contain a valid diagnostic envelope,
completion requests contain a valid capture manifest, segment receipts contain
the runtime upload receipt, and completion receipts contain a valid queued
processing job.

The protocol version is `tacua.sdk-backend@1.0.0`. Every JSON request and
response carries `protocol_version` and a closed `message_type`; every object
uses `additionalProperties: false`. The segment media request is deliberately
binary, with its canonical `segment_upload_intent` mapped to route and headers.

## Lifecycle

| Boundary | Request / intent | Durable response |
|---|---|---|
| Launch or resume | `launch_exchange_request` | `launch_exchange_receipt` |
| Media segment | `segment_upload_intent` plus raw media | `segment_upload_receipt` |
| SDK diagnostics | `diagnostic_upload_request` | `diagnostic_upload_receipt` |
| Capture completion | `completion_request` | `completion_receipt` containing the queued runtime job |
| Backend erasure | `deletion_request` | `deletion_tombstone` |

`build_identity` distinguishes the internal `application_id` from the actual
iOS `bundle_identifier`, binds native/React Native/Expo and source revisions,
and permits only `development` or `preview` builds. `capture_scope` binds the
organization, project, internal application, exact build identity, explicit
app-only capture consent, and retention policy into `scope_digest`. That scope
is immutable for the session.

The SDK generates `exchange_id`, `credential_id`, and a high-entropy bearer
secret, and writes the secret to iOS Keychain with
`when-unlocked-this-device-only` protection **before** exchanging a launch
code. The backend stores only a one-way credential verifier. It must never log
or persist the request body, launch code, or plaintext secret. A response cannot
contain either secret because the closed receipt schema has no such fields.
An exact retry of a consumed launch code returns the original non-secret
receipt; a conflicting request using the same exchange ID returns `409`.
A `resume_session` exchange issues a new credential and revokes the previous
credential only after the new receipt is durable.

## HTTP mapping

All endpoints require TLS outside loopback development. The first successful
write returns `201`; an exact replay returns `200` with the exact persisted
receipt. Reusing an operation ID with another canonical request digest returns
`409`. Unknown versions, fields, or invalid runtime artifacts return `422`.
Deleted sessions return `410`, except that an exact accepted deletion replay may
return its original tombstone.

| Method and route | JSON or binary contract |
|---|---|
| `POST /v1/sdk/launch-exchanges` | launch request / receipt |
| `PUT /v1/sdk/sessions/{session_id}/segments/{sequence}/{segment_id}` | raw bytes; intent reconstructed from required headers / segment receipt |
| `PUT /v1/sdk/sessions/{session_id}/diagnostics/{upload_id}` | diagnostic request / receipt |
| `PUT /v1/sdk/sessions/{session_id}/completions/{completion_id}` | completion request / receipt |
| `PUT /v1/sdk/sessions/{session_id}/deletions/{deletion_id}` | deletion request / tombstone |

For a segment upload, route fields supply `session_id`, `sequence`, and
`segment_id`. Required headers supply `Tacua-Protocol-Version`,
`Idempotency-Key` (`upload_id`), `Tacua-Scope-Digest`,
`Tacua-Sidecar-Digest`, `Tacua-Intent-Digest`, `Content-Type`,
`Content-Length`, and `Content-Digest`. The server reconstructs and validates
the canonical intent before accepting bytes. It authenticates before reading a
large body, streams to a temporary object while hashing, verifies size/digest,
atomically promotes the object, commits the database row and receipt, and only
then responds. Exact retries re-check the durable object's size and digest.

Every post-exchange request uses the scoped bearer credential. Authentication,
route scope, JSON scope, and persisted session scope must all agree. A
completion atomically creates the full queued `tacua.processing-job@1.0.0`
artifact and transitions the credential to `completion_replay_only`, which can
only replay the same `completion_id` and request digest. The deletion operation
revokes credentials before erasing objects and retains only its bounded,
non-secret tombstone; crash recovery must finish erasure before reporting
success.

## Idempotency and local recovery

Each mutating request has a client-generated operation ID and canonical digest.
The backend persists `(operation ID, request digest, exact response bytes)` in
the same durable boundary as the state change. Same ID/same digest returns the
same response. Same ID/different digest is always a conflict; it never creates
a second session, object, job, or deletion.

The completion receipt is the SDK's local cleanup authority. The SDK may remove
local media and diagnostic payloads only after it:

1. validates and durably stores the completion receipt;
2. verifies that its manifest and every stored segment/diagnostic receipt match
   `local_cleanup` exactly;
3. writes a local cleanup tombstone atomically;
4. removes local payloads and resumes that removal after a crash; and
5. removes the Keychain credential after no authenticated retry remains.

This cleanup authority is not approval to edit a repository, run an agent,
write a tracker, merge, or deploy. Candidate review and agent authorization are
separate contracts.

## Canonical JSON and digests

Before hashing, parsers reject duplicate keys, floats, integers outside
`[-9007199254740991, 9007199254740991]`, and non-NFC strings. Closed schemas
make every property name ASCII. Canonical JSON uses UTF-8 without a BOM, object
properties in ascending order, no insignificant whitespace, unescaped Unicode,
no escaped `/`, and standard shortest JSON escapes for quotes, backslashes, and
control characters. Booleans, null, arrays, and base-10 integers use their JSON
forms. A digest is lowercase `sha256:` plus the SHA-256 hex of those bytes. An
artifact digest omits only its own digest field.

`fixtures/canonical/digest-vectors.json` includes canonical text, exact UTF-8
hex, and hashes suitable for a Swift implementation. `artifact-digests.json`
binds every positive message fixture. These vectors are normative whenever a
platform JSON encoder differs.

## Validation

No third-party dependency or network access is required:

```sh
python3 contracts/sdk-backend-protocol/scripts/validate.py bundle \
  contracts/sdk-backend-protocol/fixtures/positive
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s contracts/sdk-backend-protocol/tests -v
```

Regenerate deterministic fixtures after intentional contract changes:

```sh
python3 contracts/sdk-backend-protocol/scripts/regenerate_fixtures.py
```

The schemas and validator define message integrity and cross-artifact binding.
They do not implement TLS, credential hashing, durable object storage,
transaction recovery, rate limiting, or reviewer/admin authorization. Those
remain mandatory backend responsibilities.
