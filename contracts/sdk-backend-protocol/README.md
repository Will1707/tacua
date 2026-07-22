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
and permits only `development` or `preview` builds. It also binds the exact QA
transport configuration through `transport_configuration_digest`.
`capture_scope` binds the organization, project, internal application, exact
build identity, explicit app-only capture consent, and retention policy into
`scope_digest`. That scope is immutable for the session.

The transport configuration digest is the Tacua canonical-JSON digest of
exactly this closed subject (with the deployment's normalized origin):

```json
{"backend_origin":"https://qa.tacua.example","transport_policy_version":"tacua.sdk-transport@1.0.0"}
```

`backend_origin` is an origin, not a base URL: lowercase the scheme and host,
remove the default port, accept only an empty or root path, normalize the root
`/` to empty, and reject user information, queries, and fragments. The
canonical origin therefore has no trailing slash. Production and QA
configurations require `https`; only local development may use `http` with a
loopback host.
The QA binary pins the normalized origin, policy version, and resulting digest
at build time. Its launch deep link carries only an opaque launch code and
cannot replace that configuration. The backend independently pins the expected
build-identity and transport-configuration digests for the launch authorization
and rejects any mismatch before issuing a session credential.

The SDK generates `exchange_id`, `credential_id`, and a high-entropy bearer
secret, and writes the secret to iOS Keychain with
`when-unlocked-this-device-only` protection **before** exchanging a launch
code. The backend stores only a one-way credential verifier. It must never log
or persist the request body, launch code, or plaintext secret. A response cannot
contain either secret because the closed receipt schema has no such fields.
The launch receipt records server `received_at` and `issued_at`, which are
ordered entirely within the backend clock domain. An exact retry of a consumed
launch code returns the original non-secret receipt; a conflicting request
using the same exchange ID returns `409`.
A `resume_session` request names the previous credential and expected session
state. The durable receipt atomically issues a new credential and records which
previous credential was revoked. A receiving session receives an `active`
credential. A completed session receives only a
`completion_replay_or_delete_only` credential bound to its existing
`completion_id`; resume can never re-enable uploads. Deleted sessions cannot be
resumed and return `410`.

## HTTP mapping

All endpoints require TLS outside loopback development. The SDK rejects HTTP
redirects on launch and authenticated routes; it never forwards a launch code,
bearer secret, or `Authorization` header to a redirect target. The first
successful write returns `201`; an exact replay returns `200` with the exact
persisted receipt. Reusing an operation ID with another canonical request
digest returns `409`. Unknown versions, fields, or invalid runtime artifacts
return `422`. Deleted sessions return `410`, except that an exact accepted
deletion replay may authenticate with the bounded replay verifier and return
its original tombstone until that tombstone expires.

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
`Tacua-Credential-ID`, `Tacua-Sidecar-Digest`, `Tacua-Intent-Digest`,
`Tacua-Requested-At`, `Content-Type`, `Content-Length`, and
`Tacua-Content-Digest`. The private digest header carries Tacua's canonical
lowercase `sha256:<hex>` representation; it deliberately does not overload the
standard HTTP `Content-Digest` field. The server reconstructs and validates the
canonical intent before accepting bytes. It authenticates before reading a
large body, streams to a temporary object while hashing, verifies size/digest,
atomically promotes the object, commits the database row and receipt, and only
then responds. Exact retries re-check the durable object's size and digest.

Every post-exchange request uses a scoped bearer credential. For a new
operation, authentication, the explicit `credential_id`, route scope, JSON
scope, and persisted session scope must all agree with the current credential.
The backend keeps the ordered, server-issued credential history for the
session. Rotation never rewrites an already durable request or receipt: partial
uploads accepted under an earlier credential remain valid when their receipt's
server acceptance time falls inside that credential's validity interval.
V1 retains at most 64 credentials per session, with zero-based ordinals
`0...63`; recovery at that bound returns
`CREDENTIAL_ROTATION_LIMIT_REACHED` and requires a new capture session.
Completion and first deletion must use the single current credential at their
respective server acceptance times. Segment receipts repeat sequence, segment
ID, content type, sidecar digest, byte size, and byte digest. Completion
compares those receipts to available manifest segments as keyed sets, so
arrival order is irrelevant while every field remains exactly bound.

Recovery is the narrow exception to new-operation credential equality. The
backend first verifies the current bearer secret and its server-owned route,
session, and scope, without yet requiring equality with the historical body
credential ID. Only then does it look up a durable operation by operation ID
and exact request digest. When that exact row exists, the current scoped
credential may authenticate retrieval of its byte-identical stored response
even when the persisted request and receipt truthfully name an earlier
credential in the same
rotation history. An active credential for a receiving session may recover an
earlier exact segment or diagnostic receipt. A completed-session credential may
recover only its bound exact completion (and may request or replay deletion);
it can never recover or create an upload. If durable lookup misses, normal
new-operation rules apply: the body and Authorization credential IDs must both
name the current credential, so the SDK creates a new operation under that
credential rather than rewriting the old request.

A completion atomically creates the exact version-one queued
`tacua.processing-job@1.0.0` baseline: it has no predecessor, every ordered
pipeline stage is pending at attempt zero with null timestamps and detail,
root start/completion/output/failure fields are null, and execution remains the
V1 asynchronous three-attempt default-deny policy. It transitions that same credential to
`completion_replay_or_delete_only`. It can replay only the same completion
request or authorize the first SDK deletion; it grants no upload, evidence, or
processing access. Durable deletion erases session data, revokes all such
access, and transitions the same verifier to `deletion_replay_only`. The
backend retains only the replay verifier and exact tombstone response until the
bounded `tombstone_expires_at`; both expire together. Crash recovery must finish
erasure before reporting success.

## Idempotency and local recovery

Each mutating request has a client-generated operation ID and canonical digest.
The backend persists `(operation ID, request digest, exact response bytes)` in
the same durable boundary as the state change. Same ID/same digest returns the
same response. Same ID/different digest is always a conflict; it never creates
a second session, object, job, or deletion. Conformance validates the original
and replayed request/response pair and requires byte-identical canonical
persisted response content.

Credential authorization uses only server-issued times and half-open validity
intervals: `[issued_at, min(expires_at, revoked_at))`. The authoritative times
are the segment runtime receipt's `received_at`, diagnostic receipt's
`received_at`, completion receipt's `accepted_at`, and deletion tombstone's
`accepted_at`. Client timestamps provide chronology evidence but cannot extend
or resurrect a credential.

After a successful start or resume, the SDK derives protocol UTC from the
receipt's server `issued_at` plus elapsed system-uptime monotonic time; it does
not use the mutable device wall clock. It durably stores both the issued-time
anchor and its system-uptime anchor. Each authenticated server receipt may
advance that derived clock to at least its authoritative server timestamp but
must never move it backward; every resume receipt establishes a fresh anchor.
All new SDK lifecycle timestamps—including capture, diagnostics, and
`requested_at`—use that derived clock. If process recovery cannot prove the
anchor or system uptime regresses after a reboot or clock discontinuity, the
SDK must resume and obtain a new anchor before creating or sending a new
lifecycle timestamp. Start and resume `requested_at` are non-authoritative
exceptions because those exchanges establish or repair the anchor; only their
receipt's server `received_at <= issued_at` ordering is normative. An already
persisted offline request retains its original anchored timestamp for exact
retry. If no durable match exists after rotation, the SDK creates a new
operation under the current credential and current anchor.

Within that declared clock model, client-internal capture chronology and
server-internal receipt chronology remain closed: manifest upload completion
cannot predate capture end, completion cannot predate the client-recorded
upload completion, and deletion `deleted_at` cannot predate its server
`accepted_at` transition.

The completion receipt is the SDK's local cleanup authority. The SDK may remove
local media and diagnostic payloads only after it:

1. validates and durably stores the completion receipt;
2. verifies that its manifest and every stored segment/diagnostic receipt match
   `local_cleanup` exactly;
3. writes a local cleanup tombstone atomically;
4. removes local payloads and resumes that removal after a crash.

The SDK keeps the Keychain secret because the completion state still permits a
first deletion. Only a validated, durably stored deletion tombstone carrying
`local_credential_cleanup: authorized_after_durable_tombstone` authorizes the
SDK to delete that secret. A lost deletion response remains retryable until the
tombstone and verifier expire together.

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
