# Single-node self-hosting runbook

Tacua V1 is one process, one organization, one SQLite database, and one local
durable state volume. It is not a clustered service. The backend entrypoint
holds a non-blocking lock in the state volume for its entire lifetime, so a
second compliant process fails before opening SQLite. Docker Compose also
declares exactly one replica; never override it with `--scale`.

This runbook separates repository-enforced checks from infrastructure the
operator must supply. The repository does not install or require a particular
reverse proxy, DNS provider, firewall, container registry, or backup system.

For a single-owner test that must remain private to an existing tailnet, use the
separate [tailnet-only private-pilot profile](TAILNET_PRIVATE_PILOT.md). It
deliberately avoids public hosting, but direct Tailscale Serve is not evidence
for the production overload and proxy controls below.

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

Require Docker Engine 28.0.0 or newer and Docker Compose 2.24.4 or newer.
Engine 28 is the minimum because older releases had a documented same-L2
reachability caveat for localhost-published ports. The exact resolved model is
tested with Compose 2.30.3 and 5.1.3. Preflight intentionally rejects
unreviewed renderer output, so record and revalidate every Compose upgrade.
The host and provider firewalls remain mandatory regardless of Docker version.

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
- one freshly generated high-entropy administrator secret stored as a
  mode-`0444` file inside its operator-owned mode-`0700` directory, solely so
  Compose's read-only bind mount is readable by fixed UID `10001`; the public
  config in that same directory is exactly mode `0644`, and the directory's
  resolved operator/root-owned ancestor chain is protected from replacement
  (with only sticky protected shared ancestors allowed).

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

The base model separately pins the Docker Official
`haproxy:3.2.21-alpine3.24` multi-architecture manifest by digest. HAProxy is
GPL-licensed, runs as UID/GID `99`, and is not incorporated into Tacua's
Apache-2.0 backend image. Mirror that exact manifest into an operator-controlled
registry for production if Docker Hub is outside the approved supply chain;
changing its reference or relay configuration requires updating and rerunning
the closed validator.

Run this deployment workflow in Bash. Create a private runtime path in the same
shell and let the shell remove it on every exit:

```bash
set -euo pipefail
project='tacua'
umask 077
runtime_directory="$(mktemp -d "${TMPDIR:-/tmp}/tacua-preflight.XXXXXX")"
chmod 0700 "$runtime_directory"
trap 'rm -rf -- "$runtime_directory"' EXIT HUP INT TERM

docker compose -p "$project" \
  -f services/backend/compose.yaml \
  -f services/backend/compose.production.yaml \
  config --format json > "$runtime_directory/compose.json"

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json"
rm -rf -- "$runtime_directory"
trap - EXIT HUP INT TERM
unset runtime_directory
```

Production preflight rejects a mutable image tag or remaining build stanza,
multiple replicas, host networking, non-loopback publication, privileged
operation, added capabilities, missing capability drops, writable root
filesystems, weakened health checks, unbounded container logs, unsafe
config/secret modes or parent directories, unexpected devices or mounts, and
an incorrect state/config/secret layout. The base development Compose model
can be checked with `validate-compose --allow-mutable-image`.

Config and secret must live in one mode-`0700` directory. Preflight resolves
and checks its complete ancestor chain through `/`; every non-shared ancestor
must be operator- or root-owned and not group/world writable, while a writable
shared ancestor is accepted only when root-owned sticky semantics protect its
entries. Do not assume that changing only the checkout's three nearest
directories repairs an unsafe higher ancestor.

For an existing stopped deployment, run the preflight from a context where
`/var/lib/tacua` is the mounted state volume and add `--check-state`. That
acquires the same exclusive lock as the backend, verifies service ownership,
rejects non-private permissions, symlinks, special files, or config/state pin
mismatches, and performs a SQLite quick check on a disposable copy. It fails
if the backend is still running and never opens the source database.

## 3. TLS reverse-proxy contract

Compose keeps the backend on one egress-denied internal network and publishes
only a digest-pinned, non-root HAProxy TCP relay on host loopback
`127.0.0.1:8080`. The relay has no Tacua config, secret, state, or Docker
socket. It joins one ordinary bridge to support the loopback publication path
operated on the private pilot's rootless mini-PC, and forwards bytes to the
backend's internal service name. Hosted CI exercises this topology on its
standard daemon, so the live pilot is not a general rootless portability
matrix. Keep TCP 8080 closed at both host and provider firewalls.

The relay is deliberately content-blind plumbing, not the required production
HTTP control plane. The application listener is Python's
`ThreadingHTTPServer`: it starts one thread per accepted connection and does
not provide a bounded worker pool, connection quota, or socket/header/body
read deadlines. Neither component is safe to expose directly. The production
reverse proxy is therefore both the TLS endpoint and the mandatory
slow-client/overload boundary. It may connect to the loopback relay only while
preserving this application contract:

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

```bash
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

```bash
set -euo pipefail
project='tacua'
docker compose -p "$project" \
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

Use the exact Compose project name and digest-pinned image of the running
deployment. The following Bash workflow resolves and preflights that project,
stops only its backend, confirms the stopped container's exact named volume,
creates a new empty private backup carrier, and runs backup plus verification
as service UID/GID `10001`. The ingress process remains bound to loopback while
the state owner is stopped:

```bash
set -euo pipefail
project='tacua'
backup_carrier='/secure-backups/tacua-YYYYMMDDTHHMMSSZ'
: "${TACUA_BACKEND_IMAGE:?export the running immutable image}"

repo_root="$(pwd -P)"
config_file="$repo_root/services/backend/local/config.json"
secret_file="$repo_root/services/backend/local/admin-secret"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/tacua-backup.XXXXXX")"
runtime_dir="$(cd "$runtime_dir" && pwd -P)"
chmod 0700 "$runtime_dir"
trap 'rm -rf -- "$runtime_dir"' EXIT HUP INT TERM
compose_json="$runtime_dir/compose.json"
compose_source=(
  docker compose -p "$project"
  -f services/backend/compose.yaml
  -f services/backend/compose.production.yaml
)

"${compose_source[@]}" config --format json > "$compose_json"
chmod 0600 "$compose_json"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file "$config_file" \
  --admin-secret-file "$secret_file" \
  --compose-json "$compose_json"

state_volume="$(
  python3 -B -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["volumes"]["tacua-state"]["name"])
' "$compose_json"
)"
expected_backend_image="$(
  python3 -B -c '
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    image = json.load(stream)["services"]["backend"]["image"]
if not isinstance(image, str) or re.fullmatch(r"\S+@sha256:[a-f0-9]{64}", image) is None:
    raise SystemExit("resolved backend image is not immutable")
print(image)
' "$compose_json"
)"
test "$expected_backend_image" = "$TACUA_BACKEND_IMAGE"
compose=(docker compose -p "$project" -f "$compose_json")

"${compose[@]}" stop backend
if ! backend_output="$("${compose[@]}" ps --no-trunc -aq backend)"; then
  echo 'cannot inspect the stopped backend container' >&2
  exit 1
fi
if [ -z "$backend_output" ] ||
  [ "$(printf '%s\n' "$backend_output" | wc -l)" -ne 1 ]; then
  echo 'expected one stopped backend container' >&2
  exit 1
fi
backend_id="$backend_output"
test "$(docker inspect --format '{{.State.Status}}' "$backend_id")" = exited
test "$(docker inspect --format '{{.Config.Image}}' "$backend_id")" = \
  "$expected_backend_image"
test "$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/tacua"}}{{.Name}}{{end}}{{end}}' \
    "$backend_id"
)" = "$state_volume"

test ! -e "$backup_carrier"
test ! -L "$backup_carrier"
install -d -m 0700 "$backup_carrier"
docker run --rm \
  --user 0:0 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --mount "type=bind,src=$backup_carrier,dst=/backup" \
  --entrypoint /bin/sh \
  "$expected_backend_image" -ceu '
    test -z "$(find /backup -mindepth 1 -print -quit)"
    chown 10001:10001 /backup
    chmod 0700 /backup
  '

docker run --rm \
  --user 10001:10001 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env TMPDIR=/tmp \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001' \
  --mount "type=volume,src=$state_volume,dst=/var/lib/tacua" \
  --mount \
    "type=bind,src=$config_file,dst=/run/tacua/config.json,readonly" \
  --mount \
    "type=bind,src=$secret_file,dst=/run/secrets/tacua_admin,readonly" \
  --mount "type=bind,src=$backup_carrier,dst=/backup" \
  --entrypoint python \
  "$expected_backend_image" -m tacua_backend.operator_tool backup \
    --config-file /run/tacua/config.json \
    --admin-secret-file /run/secrets/tacua_admin \
    --output /backup/bundle

docker run --rm \
  --user 10001:10001 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env TMPDIR=/tmp \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001' \
  --mount "type=bind,src=$backup_carrier,dst=/backup,readonly" \
  --entrypoint python \
  "$expected_backend_image" -m tacua_backend.operator_tool \
    verify-backup /backup/bundle

"${compose[@]}" start backend
rm -rf -- "$runtime_dir"
trap - EXIT HUP INT TERM
unset compose compose_json compose_source runtime_dir
```

The carrier becomes owned by the rootless/container mapping for UID `10001`;
continue to inspect or transfer it through an equivalently isolated helper
rather than weakening its modes. Run the loopback and exact-origin smoke tests
after restarting. The tool
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
`config.json`, and `admin-secret`, all still in their verified private recovery
modes.

Compose file mounts do not remap host ownership. The workflow below uses
`prepare-compose-inputs` to publish exact byte-for-byte config and secret
copies in the modes readable by fixed container UID `10001`, inside a new
owner-only directory. That command verifies the complete recovery set before
and after copying, requires an absent destination with a safe parent,
atomically creates a mode-`0700` directory, and emits only mode-`0644`
`config.json` plus mode-`0444` `admin-secret`. It never modifies the
mode-`0600` recovery artifacts. Keep the prepared secret inside that private
directory.

Use the following closed workflow from a fresh checkout to populate a **new**
Compose project and named volume. Run it in Bash, choose a project name that
will be retained as deployment metadata, and use the already verified
digest-pinned image. It refuses any existing project resource or exact volume,
leaves the backend stopped until copied state passes offline verification, and
does not auto-delete failed recovery evidence:

```bash
set -euo pipefail

project='tacua-restored'
recovery='/secure-recovery/tacua-restore'
: "${TACUA_BACKEND_IMAGE:?export the immutable digest-pinned backend image}"

repo_root="$(pwd -P)"
local_dir="$repo_root/services/backend/local"
config_file="$local_dir/config.json"
secret_file="$local_dir/admin-secret"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/tacua-restore.XXXXXX")"
runtime_dir="$(cd "$runtime_dir" && pwd -P)"
chmod 0700 "$runtime_dir"
compose_json="$runtime_dir/compose.json"
selected_backup_json="$runtime_dir/selected-backup.json"
trap 'rm -rf -- "$runtime_dir"' EXIT HUP INT TERM
compose_source=(
  docker compose -p "$project"
  -f services/backend/compose.yaml
  -f services/backend/compose.production.yaml
)

if ! project_containers="$(
  docker ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$project"
)" || ! project_volumes="$(
  docker volume ls -q --filter "label=com.docker.compose.project=$project"
)" || ! project_networks="$(
  docker network ls -q --filter "label=com.docker.compose.project=$project"
)" || ! volume_names="$(docker volume ls --format '{{.Name}}')" ||
  ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo 'cannot inspect the recovery project safely' >&2
  exit 1
fi
if [ -n "$project_containers$project_volumes$project_networks" ] ||
  printf '%s\n' "$volume_names" |
    grep -Fqx -- "${project}_tacua-state" ||
  printf '%s\n' "$network_names" |
    grep -Fqx -- "${project}_tacua-default-deny" ||
  printf '%s\n' "$network_names" |
    grep -Fqx -- "${project}_tacua-loopback-publish"; then
  echo 'refusing existing recovery project resources' >&2
  exit 1
fi

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  verify-backup "$recovery" > "$selected_backup_json"
chmod 0600 "$selected_backup_json"
expected_backup_digest="$(
  python3 -B -c '
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    digest = json.load(stream).get("backup_digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
    raise SystemExit("verified backup output has no valid digest")
print(digest)
' "$selected_backup_json"
)"

if [ -e "$local_dir" ] || [ -L "$local_dir" ]; then
  test -d "$local_dir"
  test ! -L "$local_dir"
  cmp -s "$recovery/config.json" "$config_file"
  cmp -s "$recovery/admin-secret" "$secret_file"
else
  PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
    prepare-compose-inputs "$recovery" --destination "$local_dir"
fi

"${compose_source[@]}" config --format json > "$compose_json"
chmod 0600 "$compose_json"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file "$config_file" \
  --admin-secret-file "$secret_file" \
  --compose-json "$compose_json"

state_volume="$(
  python3 -B - "$compose_json" "$project" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
if document.get("name") != sys.argv[2]:
    raise SystemExit("resolved Compose project differs from the fixed project")
volume = document.get("volumes", {}).get("tacua-state", {}).get("name")
if (
    not isinstance(volume, str)
    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", volume) is None
):
    raise SystemExit("resolved state volume name is invalid")
print(volume)
PY
)"
expected_backend_image="$(
  python3 -B - "$compose_json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    image = json.load(stream)["services"]["backend"]["image"]
if (
    not isinstance(image, str)
    or re.fullmatch(r"\S+@sha256:[a-f0-9]{64}", image) is None
):
    raise SystemExit("resolved backend image is not immutable")
print(image)
PY
)"
test "$expected_backend_image" = "$TACUA_BACKEND_IMAGE"
compose=(docker compose -p "$project" -f "$compose_json")

if ! project_containers="$(
  docker ps -aq --filter "label=com.docker.compose.project=$project"
)" || ! project_volumes="$(
  docker volume ls -q --filter "label=com.docker.compose.project=$project"
)" || ! project_networks="$(
  docker network ls -q --filter "label=com.docker.compose.project=$project"
)" || ! volume_names="$(docker volume ls --format '{{.Name}}')" ||
  ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo 'cannot repeat the recovery collision checks' >&2
  exit 1
fi
if [ -n "$project_containers$project_volumes$project_networks" ] ||
  printf '%s\n' "$volume_names" | grep -Fqx -- "$state_volume" ||
  printf '%s\n' "$network_names" |
    grep -Fqx -- "${project}_tacua-default-deny" ||
  printf '%s\n' "$network_names" |
    grep -Fqx -- "${project}_tacua-loopback-publish"; then
  echo "recovery project identity changed before creation" >&2
  exit 1
fi

"${compose[@]}" create --no-build backend
if ! backend_output="$("${compose[@]}" ps --no-trunc -aq backend)"; then
  echo 'cannot inspect the created backend container' >&2
  exit 1
fi
if [ -z "$backend_output" ] ||
  [ "$(printf '%s\n' "$backend_output" | wc -l)" -ne 1 ]; then
  echo 'expected one stopped backend container' >&2
  exit 1
fi
backend_id="$backend_output"
test "$(docker inspect --format '{{.State.Status}}' "$backend_id")" = created ||
  { echo 'backend was not left stopped' >&2; exit 1; }
test "$(docker inspect --format '{{.Config.Image}}' "$backend_id")" = \
  "$expected_backend_image"
mounted_volume="$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/tacua"}}{{.Name}}{{end}}{{end}}' \
    "$backend_id"
)"
test "$mounted_volume" = "$state_volume" ||
  { echo 'backend uses the wrong state volume' >&2; exit 1; }
test "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.project"}}' "$state_volume"
)" = "$project"
test "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.volume"}}' "$state_volume"
)" = tacua-state

docker run --rm \
  --user 0:0 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --env "EXPECTED_BACKUP_DIGEST=$expected_backup_digest" \
  --env TMPDIR=/tmp \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,mode=0700' \
  --tmpfs '/candidate:rw,nosuid,nodev,noexec,size=33554432,mode=0700' \
  --mount "type=volume,src=$state_volume,dst=/candidate/state" \
  --mount "type=bind,src=$recovery,dst=/recovery,readonly" \
  --mount "type=bind,src=$config_file,dst=/expected/config.json,readonly" \
  --mount "type=bind,src=$secret_file,dst=/expected/admin-secret,readonly" \
  --entrypoint /bin/sh \
  "$expected_backend_image" -ceu '
    test -d /candidate/state/tmp
    test ! -L /candidate/state/tmp
    test "$(stat -c %u:%g:%a /candidate/state/tmp)" = 10001:10001:700
    test -z "$(find /candidate/state/tmp -mindepth 1 -print -quit)"
    test -z "$(find /candidate/state -mindepth 1 -maxdepth 1 ! -name tmp -print -quit)"
    rmdir /candidate/state/tmp
    test -z "$(find /candidate/state -mindepth 1 -print -quit)"
    chown 0:0 /candidate/state
    chmod 0700 /candidate/state
    cp -a /recovery/manifest.json /recovery/config.json \
      /recovery/admin-secret /candidate/
    cp -a /recovery/state/. /candidate/state/
    chown -R 0:0 /candidate
    find /candidate -type d -exec chmod 0700 {} +
    find /candidate -type f -exec chmod 0600 {} +
    python -m tacua_backend.operator_tool verify-backup \
      /candidate > /tmp/candidate-backup.json
    python -c '"'"'
import json, os
with open("/tmp/candidate-backup.json", encoding="utf-8") as stream:
    actual = json.load(stream).get("backup_digest")
if actual != os.environ["EXPECTED_BACKUP_DIGEST"]:
    raise SystemExit("copied recovery digest differs from the selected backup")
'"'"'
    cmp -s /candidate/config.json /expected/config.json
    cmp -s /candidate/admin-secret /expected/admin-secret
    chown -R 10001:10001 /candidate/state
    sync -f /candidate/state
  '

docker run --rm \
  --user 10001:10001 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env TMPDIR=/tmp \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001' \
  --mount "type=volume,src=$state_volume,dst=/var/lib/tacua" \
  --mount \
    "type=bind,src=$config_file,dst=/run/tacua/config.json,readonly" \
  --entrypoint python \
  "$expected_backend_image" -m tacua_backend.operator_tool verify-compose-state \
    --config-file /run/tacua/config.json \
    --state-directory /var/lib/tacua
```

The image seeds a new named volume with exactly one empty, private `tmp/`
directory. The copier accepts and removes only that exact seed, reconstructs a
temporary complete recovery bundle, verifies every copied byte and SQLite pin,
compares the prepared config and secret, and only then assigns state to UID/GID
`10001`. `verify-compose-state` separately takes the service lock and checks
ownership, modes, SQLite integrity, and the deployment pin as that UID.

During the deliberate cutover, continue in that same Bash shell with the
owner-only resolved Compose file still present. First stop the old deployment
without deleting its volume and ensure its loopback listener is released. For
the tailnet profile, disable and verify removal of Serve before stopping the
old ingress as specified in
[TAILNET_PRIVATE_PILOT.md](TAILNET_PRIVATE_PILOT.md). For a production reverse
proxy that remains configured, only then:

```bash
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file "$config_file" \
  --admin-secret-file "$secret_file" \
  --compose-json "$compose_json"
cmp -s "$recovery/config.json" "$config_file"
cmp -s "$recovery/admin-secret" "$secret_file"

docker run --rm \
  --user 10001:10001 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --env TMPDIR=/tmp \
  --tmpfs '/tmp:rw,nosuid,nodev,noexec,mode=0700,uid=10001,gid=10001' \
  --mount "type=volume,src=$state_volume,dst=/var/lib/tacua" \
  --mount \
    "type=bind,src=$config_file,dst=/run/tacua/config.json,readonly" \
  --entrypoint python \
  "$expected_backend_image" -m tacua_backend.operator_tool verify-compose-state \
    --config-file /run/tacua/config.json \
    --state-directory /var/lib/tacua

private_network="${project}_tacua-default-deny"
publish_network="${project}_tacua-loopback-publish"
if ! project_containers="$(
  docker ps -aq --no-trunc \
    --filter "label=com.docker.compose.project=$project"
)" || ! project_volumes="$(
  docker volume ls -q --filter "label=com.docker.compose.project=$project"
)" || ! project_networks="$(
  docker network ls --format '{{.Name}}' \
    --filter "label=com.docker.compose.project=$project"
)" || ! volume_containers="$(
  docker ps -aq --no-trunc --filter "volume=$state_volume"
)" || ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo 'cannot verify the stopped recovery project before cutover' >&2
  exit 1
fi
if [ "$project_containers" != "$backend_id" ] ||
  [ "$project_volumes" != "$state_volume" ] ||
  [ "$project_networks" != "$private_network" ] ||
  [ "$volume_containers" != "$backend_id" ] ||
  printf '%s\n' "$network_names" | grep -Fqx -- "$publish_network"; then
  echo 'stopped recovery project changed before cutover' >&2
  exit 1
fi
test "$(docker inspect --format '{{.State.Status}}' "$backend_id")" = created
test "$(docker inspect --format '{{.Config.Image}}' "$backend_id")" = \
  "$expected_backend_image"
test "$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/tacua"}}{{.Name}}{{end}}{{end}}' \
    "$backend_id"
)" = "$state_volume"
test "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.project"}}' "$state_volume"
)" = "$project"
test "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.volume"}}' "$state_volume"
)" = tacua-state
test "$(
  docker network inspect --format \
    '{{index .Labels "com.docker.compose.project"}}' "$private_network"
)" = "$project"
test "$(
  docker network inspect --format \
    '{{index .Labels "com.docker.compose.network"}}' "$private_network"
)" = tacua-default-deny

"${compose[@]}" up -d --no-build
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  smoke \
  --config-file "$config_file" \
  --admin-secret-file "$secret_file"
rm -rf -- "$runtime_dir"
trap - EXIT HUP INT TERM
unset compose compose_json compose_source runtime_dir selected_backup_json
```

For the tailnet profile, start with the runbook's loopback smoke, prove Serve is
empty, re-enable its exact listener, validate the resulting Serve document,
and only then run the exact-origin smoke above.

On any failure before startup, leave that stopped project and volume
quarantined and never rerun the copy against it. Inspect it, then either remove
only those exact resources after deciding they contain no needed evidence or
repeat with a new project name; the input step safely reuses the existing local
directory only when both files still match the selected verified recovery
bundle byte-for-byte. Exercise this complete process periodically on an
isolated host.

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
