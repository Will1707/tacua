# Tacua self-hosted backend

This service is the Docker-deployable backend for the frozen
`tacua.sdk-backend@1.0.0` transport. It accepts capture data directly from the
SDK embedded in an authorized iOS QA build, keeps exact durable receipts for
recovery, and queues a complete `tacua.processing-job@1.0.0` for the later
analysis worker. Reviewer/admin routes retain session and job observation.

The implementation is Apache-2.0, dependency-free Python using SQLite and the
filesystem. It is intentionally one organization per deployment and does not
implement cross-customer multi-tenancy. Put a bounded TLS reverse proxy in
front of it outside loopback development; authenticated SDK routes and launch
exchange must never be redirected.

## Trust and persistence boundary

- The SDK creates a 32-byte bearer secret and credential ID before launch and
  stores the secret in iOS Keychain. The backend stores only a keyed HMAC
  verifier derived from the mounted deployment secret. It never creates,
  returns, persists, or logs a plaintext SDK secret.
- Admin-created launch codes are 32 random bytes, one-use, short-lived, and
  stored only as keyed verifiers. Launch request bodies are never persisted.
  Exact consumed-code retries are bound by the validated canonical request
  digest and return the original non-secret response bytes.
- The deployment mounts the full sealed SDK-protocol build identity and
  validates its artifact digest and transport configuration at startup. A
  start grant pins that registered artifact plus a static capture-scope policy
  (organization, project, application, build, required consent contract, and
  retention). The SDK supplies `consent.granted_at` and the resulting sealed
  `scope_digest` only after consent inside the tested app.
- Ordered credential history is server-owned. Resume revokes A and issues B in
  one SQLite transaction. An authenticated current credential may recover an
  exact historical receipt, but a missing operation must name the current
  credential. Completed-session credentials can only replay their bound
  completion or request/replay deletion.
- Segment bytes are authenticated before reading, streamed through SHA-256 to
  a temporary file, verified, atomically published, and committed with the
  canonical intent and exact receipt bytes. The wire contract binds a
  `sidecar_digest`; V1 deliberately does **not** upload or expose sidecar bytes.
  Processing may derive media metadata from verified media later.
- Diagnostics persist the canonical runtime envelope. Completion verifies the
  exact keyed sets of stored segment and diagnostic receipts, re-verifies every
  object, durably writes the full request, queues the full processing job, and
  returns the only local payload-cleanup authority.
- SDK, operator, and retention deletion use a two-phase erasure state. The
  first transaction revokes credentials and processing access. Crash recovery
  finishes filesystem erasure before success can be reported. The final
  transaction removes session metadata and retains only the exact tombstone
  plus its keyed replay verifier for the configured period (at most 30 days).
- Audit events have fixed content-free columns. They cannot contain launch
  codes, bearer secrets, Authorization values, or request bodies.

The admin secret also roots launch and credential verifiers. Back it up as a
deployment secret. Rotating it invalidates outstanding launch codes and SDK
credentials; perform that as an explicit deployment reset, not as an ordinary
admin-token rotation.

## Schema reset from the earlier pilot

The old server-generated-token pilot used SQLite schema version 1. Those
credentials cannot be migrated without violating the new client-generated
secret contract. Startup therefore fails closed when it sees schema 1 and asks
the operator to back up and use an empty state directory. Fresh protocol V1
state uses schema version 2. There is no silent or lossy migration.

## Run tests

From the repository root:

```sh
PYTHONWARNINGS=error PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -m unittest discover -s services/backend/tests -v

PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s contracts/sdk-backend-protocol/tests -v
```

The backend suite uses the frozen positive fixtures as lifecycle templates and
covers strict JSON, build/config/scope pins, no-secret persistence, exact
launch and operation replay, atomic rotation, historical receipt recovery,
cross-state capability denial, streamed integrity, completion binding, durable
job creation, erasure recovery, tombstone expiry, retention boundaries, and
the literal HTTP header mapping.

## Run with Docker Compose

```sh
mkdir -p services/backend/local
cp services/backend/config.example.json services/backend/local/config.json
openssl rand -base64 48 > services/backend/local/admin-secret
chmod 600 services/backend/local/admin-secret
docker compose -f services/backend/compose.yaml up --build
```

The example runs as UID/GID `10001`, drops Linux capabilities, uses a read-only
root filesystem, writes only to `/var/lib/tacua`, and binds port 8080 to host
loopback. `backend_origin` is the normalized public origin used by the QA build
(normally the HTTPS reverse-proxy origin), not the container listener address.
Its digest must equal `build_identity.transport_configuration_digest`.

The configuration pins one full sealed `build_identity` artifact for this V1
deployment. Its `transport_configuration_digest` must match `backend_origin`
and the configured transport policy. To authorize another build, deploy a
separately pinned instance or explicitly reset/reconfigure an empty instance.
`raw_retention_days`, `derived_retention_days`, and the capture scope must match
exactly. The in-process retention worker is single-process; do not run multiple
backend replicas over one SQLite/state volume.

## HTTP surface

All SDK JSON requests use strict UTF-8 `application/json` and one
`Content-Length`; chunked bodies, duplicate headers/keys, floats, unsafe
integers, non-NFC strings, queries, fragments, encoded paths, and path aliases
are rejected. First durable writes return `201`; exact recovery returns `200`
with the exact persisted response bytes. ID reuse with another canonical
request digest returns `409`.

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | public | Storage/protocol health |
| `GET` | `/version` | public | Service and protocol version |
| `GET` | `/v1/admin/builds` | admin bearer | List the registered reviewer build projection |
| `POST` | `/v1/admin/launch-codes` | admin bearer | Create a start or resume grant |
| `POST` | `/v1/sdk/launch-exchanges` | launch code in body | Start/resume and issue the client-owned credential |
| `PUT` | `/v1/sdk/sessions/{session}/segments/{sequence}/{segment}` | SDK bearer | Upload/recover media |
| `PUT` | `/v1/sdk/sessions/{session}/diagnostics/{upload}` | SDK bearer | Upload/recover diagnostics |
| `PUT` | `/v1/sdk/sessions/{session}/completions/{completion}` | SDK bearer | Complete and queue processing |
| `PUT` | `/v1/sdk/sessions/{session}/deletions/{deletion}` | SDK bearer | Erase/recover tombstone |
| `GET` | `/v1/admin/sessions[/{session}]` | admin bearer | Observe sessions and receipts |
| `GET` | `/v1/admin/jobs[/{job}]` | admin bearer | Observe full runtime jobs |
| `GET` | `/v1/admin/audit-events` | admin bearer | Observe content-free audit events |
| `DELETE` | `/v1/admin/sessions/{session}` | admin bearer | Operator-requested scoped erasure |

A start launch grant body is:

```json
{
  "exchange_kind": "start_session",
  "build_id": "build_example"
}
```

The backend resolves that ID to the sealed build artifact mounted in
`config.json`; the reviewer does not construct or echo a protocol artifact. A
successful response includes `launch_id`, the one-time `launch_code`,
`build_identity_digest`, `scope_policy_digest`, and `expires_at`. The frozen SDK
exchange remains unchanged and contains the exact registered `build_identity`
plus the SDK's post-consent sealed `scope`.

A resume grant body is
`{"exchange_kind":"resume_session","session_id":"session_..."}`. The
backend snapshots that session's exact build, scope, state, completion binding,
and current credential into the grant. Frozen complete examples live in
`contracts/sdk-backend-protocol/fixtures/positive/`.

The binary segment route reconstructs `segment_upload_intent` from route fields
and these literal required headers:

- `Tacua-Protocol-Version`
- `Idempotency-Key` (`upload_id`)
- `Tacua-Scope-Digest`
- `Tacua-Credential-ID`
- `Tacua-Sidecar-Digest`
- `Tacua-Intent-Digest`
- `Tacua-Requested-At`
- `Tacua-Content-Digest`
- `Content-Type`
- `Content-Length`

`Tacua-Content-Digest` is the private lowercase `sha256:<hex>` field from the
contract; it does not overload HTTP `Content-Digest`.
