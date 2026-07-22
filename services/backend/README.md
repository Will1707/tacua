# Tacua self-hosted backend

This service is the Docker-deployable backend for the frozen
`tacua.sdk-backend@1.0.0` transport. It accepts capture data directly from the
SDK embedded in an authorized iOS QA build, keeps exact durable receipts for
recovery, and queues a complete `tacua.processing-job@1.0.0` for the later
analysis worker. Reviewer/admin routes retain session and job observation.

The implementation is Apache-2.0, dependency-free Python using SQLite and the
filesystem. It is intentionally one organization per deployment and does not
implement cross-customer multi-tenancy. Each current pilot deployment also
pins exactly one project, application, tested build, reviewer identity, and
administrator credential. Those are current implementation limits, not a
narrowing of the [product boundary](../../docs/PRODUCT.md), which permits future
multiple projects and members. Put a bounded TLS reverse proxy in front of it
outside loopback development; authenticated SDK routes and launch exchange
must never be redirected.

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
  `scope_digest` only after consent inside the tested app. Exchange proves the
  consent instant is at or after grant creation and no later than server receipt.
- Ordered credential history is server-owned. Resume revokes A and issues B in
  one SQLite transaction. An authenticated current credential may recover an
  exact historical receipt, but a missing operation must name the current
  credential. If an accepted operation and rotation occupy the same protocol
  second, rotation advances to the next representable second so strict
  half-open authorization history remains replayable. Completed-session
  credentials can only replay their bound completion or request/replay deletion.
  V1 retains at most 64 credentials per session (initial ordinal `0` through
  ordinal `63`). Grant creation preflights that bound and exchange rechecks it
  inside the rotation transaction. A further resume fails with
  `409 CREDENTIAL_ROTATION_LIMIT_REACHED`; delete that session and start a new
  capture rather than growing an unbounded credential history.
  For an authenticated current active credential replaying an exact upload or
  completion that names a revoked credential from this session's history, a durable lookup miss
  returns the bounded canonical `tacua.sdk-backend-error@1.0.0` envelope. It
  binds both credentials and the exact session, operation kind, operation ID, and
  request digest; it does not authorize a replacement operation.
- Segment bytes are authenticated before reading, streamed through SHA-256 to
  a temporary file, verified, atomically published, and committed with the
  canonical intent and exact receipt bytes. The wire contract binds a
  `sidecar_digest`; V1 deliberately does **not** upload or expose sidecar bytes.
  Processing may derive media metadata from verified media later.
- Diagnostics persist the canonical runtime envelope. Completion verifies the
  exact keyed sets of stored segment and diagnostic receipts, re-verifies every
  object, durably writes the full request, queues the full processing job, and
  returns the only local payload-cleanup authority.
- Every queued processing job has an append-only, sealed version chain. The
  existing `jobs.job_json` value is only the verified current-head projection;
  startup and every worker/admin read revalidate that projection, the complete
  contiguous digest chain, immutable scope/inputs/pipeline configuration, and
  its exact lease relationship. Existing valid schema-v2 version-one rows are
  backfilled losslessly. A later head without history, a broken chain, or a
  corrupt projection makes startup fail closed.
- The internal worker boundary is opt-in: normal startup never claims a job,
  runs a model, or changes the fixed default-deny egress policy. The repository
  includes a provider-neutral, shell-free local command adapter but no model,
  API, connector, or command is configured by default. Its exclusive
  [worker CLI](PROCESSING_ADAPTER.md) revalidates one session-bound evidence
  snapshot, exposes only read-only evidence descriptors and a canonical sealed
  input, and accepts an exact bounded result. It shares the state-volume lock,
  so the HTTP service must be stopped while `--run-once` or `--drain` executes.
  There is no HTTP worker or result-publication route. A claim uses one
  SQLite `BEGIN IMMEDIATE` transaction to append the running snapshot and store
  one HMAC-verified opaque lease. The oldest eligible job wins; concurrent
  claimers cannot both own it. Leases last five minutes and a live holder may
  roll them forward by at most five minutes per heartbeat for as long as work
  remains alive. An expired lease is an immutable failed-attempt checkpoint
  before a bounded reclaim; the old token can never checkpoint or renew the new
  attempt.
- An injected engine exception records a bounded retryable failure before the
  runner returns a content-free error. Returning a terminal result on a
  non-final stage, or failing to return one on `generate_tickets`, is an engine
  contract violation and durably fails the attempt without leaving a live lease.
- Version one is exactly `queued` with all five stages `pending`, zero attempts,
  and no timestamps. A retry records a sealed running/failed attempt snapshot,
  then exposes a new `queued` head whose current stage is reset to `pending`,
  retains the attempt count, and has `started_at: null` as required by the frozen
  contract. The next claim increments that count. Non-retryable failure or
  exhaustion of the fixed three attempts is terminal. Checkpoints cover the
  first four exact stages. Final `generate_tickets` success is available only
  through the internal atomic result boundary in
  [ADR-014](../../docs/decisions/ADR-014-atomic-processing-result-publication.md):
  manifests and previews are crash-safely staged while reviewer-invisible, then
  every candidate head/version, the sealed `succeeded` job head, and lease
  removal commit in one SQLite transaction. `no_issue_detected` is an explicit
  terminal result with no candidate or evidence references. Startup and admin
  reads resolve successful outputs back to exact candidate, evidence, and
  preview bytes. The retired single-candidate `persist_candidate_bundle`
  boundary rejects with `PROCESSING_PUBLICATION_REQUIRED` before staging
  anything; no production path reveals a generated head outside the terminal
  transaction. The local adapter still does not invent model output or select
  a model/provider implementation.
- SDK, operator, and retention deletion use a two-phase erasure state. The
  first transaction revokes credentials and processing access. Crash recovery
  finishes filesystem erasure before success can be reported. The final
  transaction removes session metadata and retains only the exact tombstone
  plus its keyed replay verifier for the configured period (at most 30 days).
- Candidate publication, reviewer candidate reads, evidence metadata reads,
  preview byte reads, and deletion acceptance share one process-wide critical
  section. Evidence responses also hold one SQLite `BEGIN IMMEDIATE`
  transaction from the active-session recheck through metadata/byte integrity
  verification. This is part of the V1 single-process invariant: deletion
  cannot be accepted while a reviewer response is still being resolved.
- Reviewer session and candidate lists are fixed 50-item keyset pages. Each
  query reads at most 51 rows with no offset or deployment-wide completion
  scan, and list reads share the deletion critical section. Candidate lists
  validate only the bounded current head documents and their exact persisted
  projections; full candidate detail continues to validate the complete
  immutable version chain.
- Every exported `tacua.approved-handoff@1.1.0` embeds the exact canonical JSON
  of its approved ticket-candidate row, without a trailing newline, plus mirrored
  candidate and content digests. The contract validates that source with the
  authoritative ticket-candidate validator and cross-binds scope, build,
  evidence, approval, and the convenience projection. Persistence then requires
  byte-for-byte equality with `candidate_versions.canonical_json`, so fields not
  displayed in the projected ticket cannot be silently dropped or substituted.
- A candidate evidence view is at most 1.5 MiB of canonical JSON and contains
  at most 512 diagnostic events. Eligible events are sorted by monotonic time,
  sequence, and event ID; the response contains the largest deterministic
  prefix of whole events that fits. The frozen reviewer schema has no
  truncation field, so no out-of-contract indicator is added.
- At the exact raw-media expiry boundary, SDK capability checks and reviewer
  reads fail closed. HTTP SDK preauthorization and reviewer reads attempt
  scoped erasure outside their database transaction; the background worker
  retries at the configured interval (at most 3,600 seconds). A storage failure
  can delay physical erasure until recovery, but expired/deleting session data
  remains inaccessible throughout that retry window.
- Audit events have fixed content-free columns. They cannot contain launch
  codes, bearer secrets, Authorization values, or request bodies.

`deletion_tombstone.erasure.erased_object_count` counts top-level durable
artifacts present when deletion is accepted: segment objects, diagnostic
envelope objects, the completion artifact, processing-job artifacts, and
derived preview revisions that have a non-null physical `relative_path`.
Candidate/evidence binding rows, version heads, membership rows, indexes,
processing-job version/lease rows, content-free audits, credentials, and the
retained tombstone are metadata and are deliberately not counted as separate
erased objects.

The admin secret also roots launch and credential verifiers. Back it up as a
deployment secret. Rotating it invalidates outstanding launch codes and SDK
credentials; perform that as an explicit deployment reset, not as an ordinary
admin-token rotation. The mounted value must be 32–4096 ASCII bytes in the RFC
7235 `token68` alphabet (`A-Z`, `a-z`, `0-9`, `.`, `_`, `~`, `+`, `/`, `-`,
with at most two trailing `=` padding characters); Unicode, controls,
whitespace, and embedded padding are rejected before startup.

## Fail-closed schema adoption

The old server-generated-token pilot used SQLite schema version 1. Those
credentials cannot be migrated without violating the new client-generated
secret contract. Startup therefore fails closed when it sees schema 1 and asks
the operator to back up and use an empty state directory. Fresh protocol V1
state uses schema version 2. There is no silent or lossy migration.

An earlier development schema also used version 2 before the 64-credential
limit was enforced in the `credentials` table DDL. Current startup rejects a
schema-v2 database without the exact `ordinal BETWEEN 0 AND 63` check and
rejects non-contiguous, oversized, orphaned, or multiply-current persisted
credential histories. There is no in-place adoption path for that state:
retain a forensic backup and start the candidate image with an empty state
directory. Do not rewrite SQLite metadata or credential rows to bypass the
check.

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

The processing-job tests additionally cover safe schema-v2 backfill, inert
startup, exact head/list projections, concurrent claims, atomic lease-write
rollback, restart and expiry reclaim, rolling bounded heartbeats, stale-token
denial, retry exhaustion, chain/configuration/storage tampering, a
checkpoint-versus-deletion race, multi-candidate terminal publication, explicit
no-issue success, invisible staging, final-transaction rollback, staged and
published deletion, restart recovery, and preview-integrity failure. Local
adapter tests cover exact argv, no inherited credentials/environment, verified
read-only descriptors, zero- and multi-candidate results, canonical output,
timeouts, stdout/stderr caps, symlink output, tampered evidence, crash cleanup,
and state-lock exclusion.

## Run with Docker Compose

Generate the public deployment config with the secret-free compiler described
in [CONFIGURATION.md](CONFIGURATION.md). The checked-in template compiles
exactly to `config.example.json`.

For a production host, follow the complete
[single-node operations runbook](OPERATIONS.md). It covers resolved-Compose
preflight, digest-pinned images, TLS/no-redirect and firewall invariants,
single-replica enforcement, retention monitoring, atomic offline recovery
bundles, restore, upgrade, and rollback.

```sh
mkdir -p services/backend/local
cp services/backend/config.template.example.json services/backend/local/config.template.json
${EDITOR:-vi} services/backend/local/config.template.json
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.config_tool \
  services/backend/local/config.template.json \
  --output services/backend/local/config.json
openssl rand -base64 48 > services/backend/local/admin-secret
chmod 600 services/backend/local/admin-secret
docker compose -f services/backend/compose.yaml up --build
```

The example runs as UID/GID `10001`, drops Linux capabilities, uses a read-only
root filesystem, writes only to `/var/lib/tacua`, and binds port 8080 to host
loopback. Its `internal: true` Compose network preserves default-deny outbound
connectivity for the service and any explicitly invoked local processor.
`backend_origin` is the normalized public origin used by the QA build
(normally the HTTPS reverse-proxy origin), not the container listener address.
Its digest must equal `build_identity.transport_configuration_digest`.
Do not edit any derived digest: leave all four derive markers in the template
for the compiler. The generated config is public metadata; the admin secret is
the separate mode-`0600` file mounted through Compose.

The configuration pins one full sealed `build_identity` artifact for this V1
deployment. Its `transport_configuration_digest` must match `backend_origin`
and the configured transport policy. To authorize another build, deploy a
separately pinned instance or explicitly reset/reconfigure an empty instance.
It also requires an `approved_handoff` object with exactly `build_identity`,
`authority`, and `registry_revision`. The handoff build identity must be a full
sealed `tacua.build-identity@1.0.0` artifact whose organization, project, build,
mobile app, source revision, distribution, and SDK configuration digest match
the registered SDK build and deployment transport pin. Tacua does not infer a
native binary digest, SDK source revision, backend image, deployment, or source
repository identity: supply measured immutable values, or use the contract's
explicit unavailable backend representation when that identity truly is not
available. The authority is structural handoff scope (`external_writes`,
`merge`, and `deploy` remain false), and its repository allow-list must cover
every source named by the build identity. The registry revision is a bounded
Tacua identifier; it is not an authenticated execution-trust assertion. All
three values are part of the durable deployment pin, so changing any of them
requires an explicit empty-state reset instead of silently reusing state.
`raw_retention_days`, `derived_retention_days`, and the capture scope must match
exactly. V1 requires the raw and derived periods to be equal because erasure is
session-scoped; independently expiring those data classes is not represented as
a capability. The in-process retention worker is single-process; do not run
multiple backend replicas over one SQLite/state volume. The candidate
publication/deletion critical section relies on that same deployment rule;
SQLite write-intent transactions provide an additional fail-closed boundary
for reviewer evidence reads but do not make multi-replica operation supported.

## HTTP surface

All SDK JSON requests use strict UTF-8 `application/json` and one
`Content-Length`; chunked bodies, duplicate headers/keys, floats, unsafe
integers, non-NFC strings, queries, fragments, encoded paths, and path aliases
are rejected. First durable writes return `201`; exact recovery returns `200`
with the exact persisted response bytes. ID reuse with another canonical
request digest returns `409`.

Generic errors remain `application/json`. The only machine-actionable SDK error
is a `403` historical-upload lookup miss emitted as
`application/vnd.tacua.sdk-backend-error+json;version=1.0.0`. Its canonical body
is at most 4 KiB and uses this exact shape:

```json
{
  "contract_version": "tacua.sdk-backend-error@1.0.0",
  "media_type": "application/vnd.tacua.sdk-backend-error+json;version=1.0.0",
  "protocol_version": "tacua.sdk-backend@1.0.0",
  "error": {
    "code": "OPERATION_NOT_AUTHORIZED",
    "message": "new upload requires the current active credential",
    "reconciliation": {
      "outcome": "historical_operation_not_found",
      "session_id": "session_...",
      "operation_kind": "segment",
      "operation_id": "upload_...",
      "request_digest": "sha256:...",
      "request_credential_id": "credential_a",
      "authenticated_credential_id": "credential_b"
    }
  }
}
```

`operation_kind` is `segment`, `diagnostic`, or `completion`; deletion is not a
reconciliation outcome. The SDK rejects this envelope
unless its status, exact media type, canonical schema, size, request digest, and
all request/credential bindings match. A generic JSON error carrying the same
textual code is deliberately not machine actionable. Once validated, the SDK
may rebuild that absent logical operation under the same stable ID, changing
only its credential, requested timestamp, and derived root digest; every other
semantic field and local payload binding remains exact. Segment and diagnostic
misses use the message shown above; a completion miss uses the exact message
`first completion requires the current active credential`. Messages are
validated constants but are never used without the complete machine binding.

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
| `GET` | `/v1/admin/sessions` | admin bearer | List one bounded page of session summaries |
| `GET` | `/v1/admin/sessions/{session}` | admin bearer | Observe one session and its bounded receipt projection |
| `GET` | `/v1/admin/sessions/{session}/candidates` | admin bearer | List one bounded page of current candidate summaries |
| `GET` | `/v1/admin/candidates/{candidate}` | admin bearer | Read the current immutable candidate chain; response `ETag` is its exact head digest |
| `GET` | `/v1/admin/candidates/{candidate}/versions/{version}/evidence` | admin bearer plus exact candidate and manifest digests | Read the exact version's bounded evidence projection |
| `GET` | `/v1/admin/candidates/{candidate}/versions/{version}/evidence/{evidence}/preview` | admin bearer plus exact candidate and manifest digests | Read one integrity-bound preview for the exact version |
| `POST` | `/v1/admin/candidates/{candidate}/transitions` | admin bearer, `If-Match`, idempotency key | Append one immutable transition from the exact current head |
| `POST` | `/v1/admin/candidate-replacements` | admin bearer, idempotency key | Atomically split or merge exact current source heads and supersede them |
| `GET` | `/v1/admin/candidates/{candidate}/supersession` | admin bearer | Read the immutable replacement operation for a superseded source |
| `GET` | `/v1/admin/jobs` | admin bearer | List one bounded page of processing-job summaries |
| `GET` | `/v1/admin/jobs/{job}` | admin bearer | Observe one full, digest-validated runtime job |
| `GET` | `/v1/admin/candidates/{candidate}/handoff.{json,md}` | admin bearer | Download the current exact approved handoff |
| `GET` | `/v1/admin/candidates/{candidate}/versions/{version}/handoff.{json,md}` | admin bearer | Download one immutable approved handoff version |
| `GET` | `/v1/admin/audit-events` | admin bearer | List one bounded page of content-free audit events |
| `DELETE` | `/v1/admin/sessions/{session}` | admin bearer | Operator-requested scoped erasure |

Candidate evidence and preview reads require one quoted candidate digest in
`If-Match` and the exact `Tacua-Evidence-Manifest-Digest`. Candidate transitions
also require `If-Match`; transitions and replacements each require one
`Idempotency-Key`. A replacement request carries every exact source binding, so
it does not use a separate single-candidate `If-Match` header. Candidate lists
exclude superseded sources, while their detail, evidence, previews, and
supersession history remain readable. Attempts to transition, replace, approve,
reject, or export a superseded source fail with the stable
`409 CANDIDATE_SUPERSEDED` conflict and replacement references.

The four admin list routes return exactly one of
`{"sessions":[...],"next_cursor":...}`,
`{"candidates":[...],"next_cursor":...}`,
`{"jobs":[...],"next_cursor":...}`, or
`{"events":[...],"next_cursor":...}`. A page contains at most 50 items.
When `next_cursor` is non-null, send it unchanged as the single
`Tacua-Page-Cursor` request header. Cursors are opaque, bounded to 512
characters, scoped to their list kind, and candidate cursors are also scoped
to the exact session. Empty, duplicate, oversized, non-canonical, cross-kind,
and cross-session cursors fail with `400 PAGE_CURSOR_INVALID`; query strings
remain unsupported.

Job pages contain only the seven-field reviewer summary (`job_id`, fixed
`job_type`, status and three timestamps, plus `failure_code`). Fetch
`/v1/admin/jobs/{job}` for the full immutable-chain-validated runtime job.
Job and audit pages are newest-first keysets, so list responses never
materialize the deployment's full history.

Session detail is intentionally a single response in V1. Its closed shape is
bounded to 2,048 segment receipts plus projections, 2,048 diagnostic receipts
plus projections, 64 credential projections, one job summary, and one
completion receipt. The reviewer therefore uses an explicit 16 MiB byte cap
(the conservative maximum serialized V1 projection is under 10 MiB), instead
of inheriting the generic 2 MiB JSON cap or accepting an unbounded response.

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
and current credential into the grant. A session can contain at most 64
credentials. Once that recovery bound is reached, the admin route returns
`409 CREDENTIAL_ROTATION_LIMIT_REACHED`; delete the session and start a new
capture. Frozen complete examples live in
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
