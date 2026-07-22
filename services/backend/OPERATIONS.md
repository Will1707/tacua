# Single-node self-hosting runbook

Tacua V1 is one process, one organization, one SQLite database, and one local
durable state volume. It is not a clustered service. The backend entrypoint
holds a non-blocking lock in the state volume for its entire lifetime, so a
second compliant process fails before opening SQLite. Docker Compose also
declares exactly one replica; never override it with `--scale`.

This runbook separates repository-enforced checks from infrastructure the
operator must supply. The repository does not install or require a particular
reverse proxy, DNS provider, firewall, container registry, or backup system.

## Operator-supplied infrastructure

Before production use, provide all of the following:

- a domain and DNS records pointing to the intended single host;
- a valid publicly trusted TLS certificate and a reverse proxy listening on
  port 443;
- a host/network firewall that permits the intended administration path and
  TCP 443, denies public TCP 8080, and denies every unused inbound service;
- an immutable image stored under a digest-pinned reference;
- durable local storage that supports SQLite WAL, atomic rename, `fsync`, and
  advisory `flock` semantics (ordinary local block storage, not a shared/NFS
  volume); and
- encrypted, access-controlled, off-host storage for recovery bundles.

Tacua automates validation of the config, secret-file permissions, resolved
Compose model, single-process volume lock, backup byte manifest, SQLite
integrity, non-destructive restore, endpoint origin/status/body bounds,
administrator authentication, and retention health. It cannot validate a
firewall policy, prove DNS ownership, issue a TLS certificate, or move backups
off the host.

## 1. Prepare and seal configuration

Follow [CONFIGURATION.md](CONFIGURATION.md). The production values must use:

- an exact normalized `https://` `backend_origin` with no path;
- `listen_host` `0.0.0.0` and `listen_port` `8080` inside the container;
- `state_directory` `/var/lib/tacua`; and
- one freshly generated high-entropy administrator secret stored separately
  with host mode `0600`.

Never rotate the administrator secret in place. It also roots launch-code and
SDK-credential verifiers. Losing or replacing it invalidates outstanding
capabilities. Recover the exact secret and config together with their state, or
start an explicitly empty deployment.

## 2. Resolve and preflight production Compose

Build only from a clean, verification-green checkout. Before every local image
build, run the same closed Dockerfile/context checks as CI (the repository
workflow pins Node 22.22.2):

```sh
node --test .github/scripts/validate-backend-image-inputs.test.mjs
node .github/scripts/validate-backend-image-inputs.mjs
docker build -f services/backend/Dockerfile -t tacua-backend:<revision> .
```

The validator requires the exact audited Docker instruction sequence, pinned
base-image digest, ignore rules, source/schema file allowlist, regular-file
types, and per-file/aggregate size bounds. A new legitimate runtime file must
be added deliberately to that policy; do not bypass a failed check with a broad
build context.

On an isolated validation host, exercise the complete image boundary with the
same checked-in command used by CI:

```sh
TACUA_CONTAINER_TEST_ID=local-verify \
  bash .github/scripts/verify-backend-container.sh
```

The identifier is at most 32 characters, starts with a lowercase letter or
digit, and otherwise accepts only lowercase letters, digits, and hyphens. The
script refuses pre-existing container, volume, image, or local-input names,
then cleans only the names it created. It verifies hardened startup, the state-volume
single-writer lock, authenticated smoke, backup manifest and retention binding,
non-destructive and applied restore, and candidate-image startup from the
restored state. It is a release-candidate test, not a production deployment.

Publish the validated image through your chosen registry, record its immutable
digest, and set (do not put this in the config or secret file):

```sh
export TACUA_BACKEND_IMAGE='registry.example/tacua@sha256:<64 lowercase hex>'
```

The optional production override removes the local build stanza. Inspect the
fully resolved model, then run the fail-closed preflight:

```sh
docker compose \
  -f services/backend/compose.yaml \
  -f services/backend/compose.production.yaml \
  config --format json > /tmp/tacua-compose.json

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json /tmp/tacua-compose.json
```

Production preflight rejects a mutable image tag or remaining build stanza,
multiple replicas, host networking, non-loopback publication, privileged
operation, added capabilities, missing capability drops, writable root
filesystems, weakened health checks, unbounded container logs, unsafe
config/secret modes, unexpected devices or mounts, and an incorrect
state/config/secret layout. The base development Compose model can be checked
with `validate-compose --allow-mutable-image`.

For an existing stopped deployment, run the preflight from a context where
`/var/lib/tacua` is the mounted state volume and add `--check-state`. That
acquires the same exclusive lock as the backend, verifies service ownership,
rejects non-private permissions, symlinks, special files, or config/state pin
mismatches, and performs a SQLite quick check on a disposable copy. It fails
if the backend is still running and never opens the source database.

## 3. TLS reverse-proxy contract

Compose publishes the backend only on host loopback
`127.0.0.1:8080`. Keep TCP 8080 closed at both host and provider firewalls.
The application listener is Python's `ThreadingHTTPServer`: it starts one
thread per accepted connection and does not provide a bounded worker pool,
connection quota, or socket/header/body read deadlines. It is not safe to
expose directly. The reverse proxy is therefore both the TLS endpoint and the
mandatory slow-client/overload boundary. It may connect to the loopback
listener only while preserving this application contract:

- the configured HTTPS origin terminates with a valid hostname-matching
  certificate and TLS 1.2 or newer;
- HTTPS requests to `/version`, `/healthz`, and every `/v1/...` path return
  directly and are never redirected to another host, scheme, port, slash
  variant, identity portal, or login page;
- methods, paths, request bytes, `Content-Length`, `Content-Type`,
  `Authorization`, `If-Match`, `Idempotency-Key`, and `Tacua-*` headers pass
  through without rewriting or duplication;
- request-body limits are at least the configured Tacua limits and the proxy
  streams bodies with bounded buffers without decompressing, recompressing,
  buffering an entire segment, or otherwise transforming payloads;
- response bodies and binding headers are not transformed or cached; and
- access logs redact `Authorization` and never record request bodies.

Use this conservative initial resource envelope for the single-node pilot;
change it only after a recorded capacity test, and never replace a finite cap
with an unlimited/default setting:

- finish reading request headers within 10 seconds, allow at most 8 KiB for
  the request line, 32 KiB total headers, and 64 header fields;
- close a client whose request body makes no forward progress for 30 seconds;
  use an idle/progress timeout rather than a whole-request deadline that would
  abort a valid maximum-size segment still transferring normally;
- use at most a 15-second client keep-alive idle timeout, a 5-second upstream
  connect timeout, and a 60-second upstream response-idle timeout;
- allow at most 8 simultaneous requests per client address, 32 in-flight
  requests to the backend in total, and 64 pending requests; reject overflow
  with `429` or `503` before opening another upstream connection; and
- enforce both per-source (10 requests/second, burst 20) and global
  (50 requests/second, burst 100) limits, with the admin and launch-code routes
  limited to 2 requests/second per source with burst 5. Count long uploads
  against the concurrency limit for their full lifetime.

Monitor proxy rejections, queue depth, upstream latency, open connections,
backend thread/task count, file descriptors, memory, and SQLite busy failures.
A production promotion must load-test the largest configured segment and the
reviewer response bounds through these exact proxy settings; TLS reachability
alone is not evidence that the resource boundary is safe.

An HTTP-to-HTTPS redirect on an unused port 80 is an infrastructure choice,
but the SDK is configured with HTTPS and never depends on it. Redirects at the
configured HTTPS origin are forbidden because they can change authorization
and idempotency semantics.

After startup, run the exact-origin smoke check from a network representative
of the QA device:

```sh
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  smoke \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret
```

The smoke command uses the configured origin, rejects redirects, performs
normal certificate/hostname verification with TLS 1.2 minimum, bounds every
response, checks the frozen protocol and schema, checks the retention worker's
latest sweep, and authenticates `/v1/admin/builds` with the supplied secret.
The secret is sent only to that exact origin and is never printed. The
`--origin http://127.0.0.1:8080 --allow-loopback-http` escape hatch exists only
for a local container smoke test.

## 4. Start and monitor

```sh
docker compose \
  -f services/backend/compose.yaml \
  -f services/backend/compose.production.yaml \
  up -d --no-build
```

Do not use `--scale`. A second process sharing the state volume exits before
database initialization, but repeatedly starting replicas is still an
operational fault.

Monitor `/healthz` without authentication. Alert when any of these is true:

- `status` is not `ok`;
- `schema_version` is not `2`;
- `pending_deletions` or `retention_last_failed_sessions` is nonzero;
- `retention_worker_running` is not `true`; or
- `retention_last_swept_at` is older than twice
  `retention_sweep_interval_seconds` plus 60 seconds.

The public health response contains counts and timestamps only—never session
IDs, request content, or credentials. Container logs are bounded to three
10 MiB files by the base Compose model. Route logs to longer-lived monitoring
only after applying equivalent secret/body redaction.

## Optional exclusive local processing

The provider-neutral local adapter is disabled during ordinary service
startup. To process queued sessions, follow
[PROCESSING_ADAPTER.md](PROCESSING_ADAPTER.md): stop the backend, invoke the
worker with an explicit canonical command document in `--run-once` or bounded
`--drain` mode, and restart the backend. The worker deliberately acquires the
same state-volume lock, so attempting to run it beside this service fails
before SQLite or evidence is opened. Keep the checked-in `internal: true`
network and do not add provider credentials or egress without a separate
authorization design.

## 5. Crash-consistent backup

Recovery bundles contain the database, WAL and state objects, the exact sealed
public config, and the exact administrator secret. They are deliberately
mode `0700` with mode-`0600` files, but they are not encrypted. The selected
output parent must be a service-user-owned secure mounted backup destination
outside the state volume and must not be group/world writable. Move each
verified bundle to encrypted off-host storage. Verification requires the
bundle to remain owned by that same operator UID with exact private modes;
preserve ownership and permissions when transferring or restoring it.

Backup manifest v2 derives one closed evidence-retention object from every
session row in the copied SQLite/WAL snapshot. It seals the session count and
the earliest raw-or-derived evidence deadline into the canonical backup digest.
Creation verifies that projection before publishing the directory;
`verify-backup` and both restore modes recompute it from a disposable database
copy and refuse at or after the exact deadline. A deployment with no session
rows records `contains_session_evidence: false`, `session_count: 0`, and a null
deadline, so this evidence gate does not invent an expiry. Version-1 bundles
are deliberately rejected because they did not bind any evidence deadline.

Refusal does not erase bytes. Treat every recovery copy, off-host replica, and
restored staging directory as retained evidence and configure the selected
backup system to destroy every copy by the sealed deadline. A no-session bundle
still contains the administrator secret and configuration, so its null evidence
deadline is not a claim that it is non-sensitive or may be retained forever
under the operator's secret-management policy.

Stop the only backend and wait for it to exit before backup:

```sh
docker compose -f services/backend/compose.yaml stop backend

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  backup \
  --config-file /run/tacua/config.json \
  --admin-secret-file /run/secrets/tacua_admin \
  --output /secure-backups/tacua-YYYYMMDDTHHMMSSZ

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  verify-backup /secure-backups/tacua-YYYYMMDDTHHMMSSZ
```

Run those commands either on a host bind-mounted deployment or in a one-off
container using the same image, UID/GID `10001:10001`, stopped state volume,
read-only config/secret mounts, and a writable secure backup mount. The tool
acquires the state lock, so it refuses an online backup. It performs a
SQLite check on a disposable copy, rejects linked, non-private, special, or
foreign-owned state entries, cross-checks the database deployment pin against
the exact recovered config, copies every file with source stability checks and
`fsync`, seals exact file sizes and SHA-256 digests in a canonical manifest,
verifies the staging bundle, and only then atomically publishes the new
directory. It excludes the runtime lock and regenerable SQLite shared-memory
file, while retaining the database WAL when present. It never checkpoints,
rewrites, or deletes source state.

## 6. Verify and restore without overwrite

`restore` verifies only by default and does not create the requested path:

```sh
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  restore /secure-backups/tacua-YYYYMMDDTHHMMSSZ \
  --destination /secure-recovery/tacua-restore
```

After reviewing the result, opt in to writing:

```sh
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  restore /secure-backups/tacua-YYYYMMDDTHHMMSSZ \
  --destination /secure-recovery/tacua-restore \
  --apply
```

Apply requires an absent destination, copies into a private staging directory,
re-verifies every byte and SQLite state, and atomically creates one recovery
root. It never overwrites or merges. The result contains `state/`,
`config.json`, and `admin-secret`; mount those exact recovered artifacts into a
new stopped deployment, re-run preflight with `--check-state`, then start and
smoke-test. Test this process periodically on an isolated host.

## 7. Upgrade and rollback

For every upgrade:

1. Record the running image digest, public config digest, deployment-pin digest,
   and latest verified backup digest from preflight/backup output. Preflight
   deliberately does not emit an administrator-secret digest because that
   would create an offline verifier for secret guesses; keep the exact secret
   only in the authorized secret store and encrypted recovery bundle.
2. When updating the Dockerfile base, resolve the exact current Python patch
   tag and multi-platform OCI index digest from the Docker Official Image,
   review its Python/Debian security changes, and update the Dockerfile and the
   validator's exact base/instruction allow-list together. Review any change to
   the validator's exact runtime source/schema allow-list as a release-boundary
   change, then pass its adversarial tests and the complete image build/smoke
   suite. Never move the digest while retaining a stale tag, or replace the
   digest pin with a floating tag.
3. Resolve the candidate digest-pinned Compose model and run preflight.
4. Stop the backend and create/verify an off-host recovery bundle.
5. Restore that bundle on an isolated host/volume and start the candidate
   image there. This startup compatibility test is required: preflight's
   read-only SQLite quick check does not perform an application migration.
6. Start exactly one production container from the verified digest without
   rebuilding.
7. Run the exact-origin smoke test and monitor at least one retention interval.

Rollback is restore-based. Stop the failed image, retain a separate forensic
copy of its state, restore the pre-upgrade bundle to a new empty volume, and
start the recorded old image digest with the recovered config and secret.
Never point an older image at state that a newer image has opened or migrated.
The current backend accepts only its exact schema/protocol and fails closed on
unknown persisted versions; there is no down-migration command.

Current startup also rejects an earlier schema-v2 `credentials` table that
lacks the database-enforced `ordinal BETWEEN 0 AND 63` constraint, or whose
persisted credential history is not one contiguous bounded chain with one
current tail. That development-era schema was never a supported migration
source. Preserve a forensic backup and use a new empty state directory; do not
edit SQLite DDL or credential rows to force adoption.

## Recovery decisions

- **Lost config, state and secret intact:** recover the exact config from the
  latest verified bundle. A newly invented config will fail its persisted
  deployment pin.
- **Lost administrator secret:** restore the exact secret from a verified
  bundle. If none exists, outstanding launch codes/SDK credentials are not
  recoverable; preserve evidence separately and create an explicitly empty
  deployment with a new secret.
- **Lost/corrupt state:** do not merge individual files. Restore the complete
  verified state directory into a new empty volume.
- **TLS/domain change:** update the measured origin and every dependent build
  pin through the config compiler, then use an empty deployment unless an
  explicitly supported migration exists. A reverse-proxy redirect is not a
  migration.
