# Tacua pilot backend

This is a dependency-free, deliberately **non-production** backend vertical
slice. It exercises the real V1 ownership boundary: the embedded SDK exchanges
a reviewer-created launch code, then directly uploads recoverable capture
segments and sanitized diagnostics. The reviewer/admin side can inspect durable
sessions and jobs without ever receiving the SDK upload credential.

The service uses Python's standard library, SQLite, and filesystem media. It is
not an Internet-facing server and must not be treated as one. In particular it
does not yet provide TLS termination, rate limiting, an identity provider,
automatic retention sweeping, media processing, model execution, backups,
migrations beyond schema version 1, or multi-process coordination.

Two protocol/operations blockers are intentionally visible rather than papered
over. First, launch exchange currently creates a server-generated upload token;
if the successful response is lost, the consumed launch code cannot recover
that token. The SDK transport protocol must adopt a client-generated,
pre-Keychain credential (or a separately authorized resume grant) before this
flow is production-ready. Second, retention expiry is metadata only until a
durable sweeper is added. The example also uses a mutable Python base-image tag,
and the standard-library threaded HTTP server has no request deadlines,
concurrency quotas, or rate limits. Pinning the image by digest and placing a
bounded TLS proxy in front are release work, not optional hardening.

## Boundary and persistence

- One configured organization, project, internal Tacua application ID,
  reverse-DNS bundle identifier, build ID, sealed build-identity digest, and
  consent contract are accepted by a deployment.
- Reviewer/admin requests use a bearer secret loaded from a mounted secret
  file. The secret is never persisted by the service.
- A launch code is short-lived, single-use, and stored only as a SHA-256 hash.
- Exchanging it creates a session and returns a distinct short-lived SDK upload
  token exactly once. Only that token's hash is persisted.
- Segment bodies are streamed through SHA-256 verification into a temporary
  file and atomically published only after byte count and digest match.
- Publication fsyncs its directories, and startup removes recognized temporary
  or uncommitted crash orphans while failing closed if committed files vanished.
- Retrying an index with identical content returns the original receipt;
  different content at that index is rejected with `SEGMENT_CONFLICT`.
- SQLite, media, validated diagnostic envelopes, sealed manifests, and upload
  temporary files are all beneath the single configured state directory. In
  the container that directory is `/var/lib/tacua`.
- Every session receives bounded raw-retention metadata with an expiry from 1
  through 30 days after exchange (30 days by default). Automatic expiry is
  intentionally not implemented in this pilot. Scoped admin deletion removes
  media/diagnostics and leaves a durable tombstone plus a completed deletion
  job.
- Completion requires the exact stored diagnostic-envelope set, re-verifies all
  media and diagnostic files, and persists the sealed manifest outside SQLite.
- Starting deletion atomically cancels any active processing snapshot before
  the durable two-phase file deletion begins.
- Audit events have fixed, content-free columns. They cannot contain request
  bodies, diagnostic values, launch codes, upload tokens, or administrator
  secrets.

The pilot advertises the repository runtime contract versions:

- `tacua.capture-upload-manifest@1.0.0`
- `tacua.diagnostic-envelope@1.0.0`
- `tacua.processing-job@1.0.0`

Diagnostic envelopes, sealed capture manifests, and queued processing-job
snapshots are validated by the repository's dependency-free runtime validator.
The semantic `envelope_digest` and `manifest_digest` are kept distinct from the
SHA-256 digest of the HTTP bytes used for transport integrity.

## Run the tests

From the repository root:

```sh
PYTHONWARNINGS=error python3 -m unittest discover -s services/backend/tests -v
```

The tests cover fixed-scope grants, one-time exchange, hash-only credential
storage, admin and SDK authentication, cross-session access, path traversal,
size/digest mismatches, idempotent and conflicting retries, missing completion
segments, restart persistence, bounded diagnostics, durable processing jobs,
and scoped deletion.

## Run in Docker

Create local mounted files; `local/` is ignored by Git and the Docker build:

```sh
mkdir -p services/backend/local
cp services/backend/config.example.json services/backend/local/config.json
openssl rand -base64 48 > services/backend/local/admin-secret
chmod 600 services/backend/local/admin-secret
docker compose -f services/backend/compose.yaml up --build
```

The image runs as UID/GID `10001`, supports a read-only root filesystem, drops
all Linux capabilities in the example Compose deployment, and writes only to
the `tacua-state` volume. Port `8080` is bound to loopback in the example. A
real remote pilot still needs an authenticated TLS reverse proxy and host-level
backup policy before it can receive sensitive QA evidence.

## HTTP surface

All request and response bodies are JSON except segment `PUT` bodies. JSON
requests and segment uploads require one `Content-Length`; chunked transfer is
rejected. Every uploaded object needs an `X-Content-SHA256` header in the form
`sha256:<64 lowercase hex characters>`.

Segment uploads also require one `X-Tacua-Segment-ID` header and a `Content-Type`
of `video/quicktime` or `video/mp4`. The server binds that client-owned ID,
sequence, content type, object ID, byte count, digest, timestamp, and receipt
digest. The SDK copies only the six runtime receipt fields into its
capture manifest; the response-only `idempotent_retry` flag is not a contract
receipt field.

| Method | Path | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/healthz` | public | Health, service version, and contract versions |
| `GET` | `/version` | public | Service version |
| `POST` | `/v1/admin/launch-codes` | admin | Create one scoped launch code |
| `POST` | `/v1/sdk/launch-code-exchanges` | launch code in body | Consume code and receive the SDK token once |
| `PUT` | `/v1/sdk/sessions/{session}/segments/{sequence}` | SDK token | Upload/retry one media segment |
| `PUT` | `/v1/sdk/sessions/{session}/diagnostics/{envelope}` | SDK token | Upload/retry one bounded diagnostic envelope |
| `POST` | `/v1/sdk/sessions/{session}/completion` | SDK token | Verify declarations, close upload, and queue processing |
| `GET` | `/v1/admin/sessions[/{session}]` | admin | Inspect session metadata and receipts |
| `GET` | `/v1/admin/jobs[/{job}]` | admin | Inspect durable processing/deletion jobs |
| `GET` | `/v1/admin/audit-events` | admin | Inspect content-free audit events |
| `DELETE` | `/v1/admin/sessions/{session}` | admin | Run scoped deletion and retain its job/tombstone |

Admin launch creation uses the exact mounted scope:

```json
{
  "scope": {
    "organization_id": "org_example",
    "project_id": "project_example",
    "application_id": "app_example",
    "bundle_identifier": "com.example.app",
    "build_id": "build_example",
    "build_identity_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "consent_contract": "tacua-consent-v1"
  }
}
```

The SDK exchange sends the returned opaque `launch_code` together with that
same scope. A successful response contains a new `session_id`, the one-time
display of `upload_token`, both expiry timestamps, and the retention policy.

Completion wraps a complete, sealed
`tacua.capture-upload-manifest@1.0.0` document as `capture_manifest` and a
non-empty `diagnostic_envelope_ids` array. See
`contracts/runtime/fixtures/positive/capture.json` for the complete manifest
shape; partial manifests are deliberately rejected.

Every uploaded segment must appear once as `available`, and every available
declaration must have a matching stored receipt. `unavailable` declarations are
accepted without content. Completion revokes the upload token and inserts a
durable, contract-valid queued `tacua.processing-job@1.0.0` snapshot for the
later transcription/alignment/research worker. Retrying the exact sealed
manifest after a lost response returns the same job even though normal uploads
have already been revoked. Deletion uses a separate internal resource type and
is a durable, retryable two-phase operation; it never masquerades as a
processing job.
