# ADR-020: Bridge Compose state to the trusted host processor

- Status: accepted
- Date: 2026-07-23
- Scope: Tacua V1 single-host/private-pilot processing

## Context

[ADR-016](ADR-016-local-processor-isolation.md) requires the selected model or
plugin to run behind the trusted host-side isolated runner. The worker that
claims a job must simultaneously own the backend state directory so its
SQLite transaction, retention lock, and evidence descriptors remain
authoritative. In the checked-in deployment that state is a Docker named
volume owned by fixed container UID/GID `10001:10001`; it is not a portable or
safe host path.

Running the worker in the backend image gives it the correct named-volume
view, but mounting the Docker socket into that container would grant host
control and collapse the processor boundary. Copying the state volume to a
host directory and copying it back would introduce a non-atomic database and
object-store replacement path. Resolving and opening Docker's private volume
mountpoint directly would depend on daemon internals, rootless UID mappings,
and host privileges outside the Compose contract.

## Decision

Tacua adds one explicit host-side gate,
`services/backend/scripts/run_compose_isolated_processing.py`, and a narrow
client in `tacua_backend.processing_bridge`. It remains an operator action;
normal backend startup is still inert.

The host gate accepts an already resolved Compose JSON document, an owner-only
durable operation parent, the exact public config and administrator-secret
files, an explicit isolated command, one fixed Compose project, and either
one-stage or bounded-drain mode. Before importing backend code or interrupting
service it:

1. acquires one project-scoped host `flock`, snapshots the closed runtime
   source boundary into the durable operation directory, fsyncs it, and
   re-executes that snapshot with Python `-I -S -B`;
2. runs the existing deployment preflight against the original repository
   build-context root bound by the source manifest;
3. validates the selected processor image/model command, repeats the existing
   rootless-runtime preflight through the isolated runner, and proves the host
   descriptor limit can carry one maximum-size request;
4. requires exactly one healthy running Compose backend whose exact image ID
   and named state-volume mount match the resolved model;
5. checks inside that exact running backend that the combined SQLite database
   and WAL size does not exceed the V1 512 MiB verifier-copy bound;
6. refuses any other container that references that volume; and
7. independently enumerates both runner scripts, every backend Python module,
   and all Python/schema inputs from the approved-handoff, runtime,
   SDK/backend-protocol, and ticket-candidate contracts inside the running
   image with network disabled, then requires the image path set and digest to
   match the already executing snapshot.

Before issuing the stop, the gate atomically publishes and directory-fsyncs a
canonical, SHA-256-sealed journal in one deterministic owner-only operation
directory. The journal binds the project, backend and image IDs, state volume,
Compose and source-bundle digests, original repository root, exact
config/secret inode metadata, worker and verifier identities, arguments, and
conservative lifecycle flags. Every material phase transition is atomically
journaled. An existing operation directory blocks a new run until explicit
recovery clears it.

Container creation has a separate deterministic coordinator. Before either a
verifier or worker can be created, the gate forks a child that inherits the
project `flock` and blocks on a private pipe. The parent first fsyncs the exact
random name and `creating` phase, then releases the child to call
`docker container create`. Before exiting, the child atomically publishes and
directory-fsyncs a private, digest-sealed, content-free receipt bound to the
project, role, purpose, and name. `created` binds the exact returned container
ID, `not_started` proves the pipe was never released and Docker was not called,
and `indeterminate` records that create was authorized but its exact result was
not established. The parent reaps the child before releasing its copy of the
lock. If the parent dies, the child's inherited lock excludes recovery until
the child has durably recorded its outcome or exited without doing so.

Recovery reconciles an interrupted `creating` phase with that receipt and one
direct discovery pass over the exact role, name, and ID; elapsed time and
repeated absence are never treated as proof. A matching `not_started` receipt
and absent candidate can retire the attempt. A matching `created` receipt
supplies the exact durable ID even when the container is already absent. A
missing, torn, mismatched, or `indeterminate` receipt with an absent candidate
is unsafe and leaves every recovery artifact intact. A discovered candidate
must pass exact inspection before removal. One exact post-removal
role/name/ID discovery pass must prove absence before the journal phase and
receipt can be retired. Disagreement, label drift, name collision, or a daemon
query failure leaves the journal intact and fails closed.

The gate stops only that backend and verifies the stopped state offline in a
uniquely named, label-bound, network-none, read-only-root container using the
exact running backend image. Verifier creation and identity are journaled
before it can mount the state volume; success advances the journal only after
the container has exited cleanly and exact removal is proven. The ingress may
remain bound to loopback but cannot reach a live state owner.
The V1 verifier caps the combined SQLite database and WAL at 512 MiB, forces
their disposable validation copy into an exact-inspected 1 GiB noexec `/tmp`
tmpfs, and retains a 4 GiB no-swap memory ceiling. It overrides the backend
image's ordinary state-local `TMPDIR`; interruption can therefore discard only
ephemeral verifier scratch, never strand a database copy in authoritative
state. The gate checks the 512 MiB bound in the exact running backend before
publishing the downtime journal or issuing stop, so a capacity refusal leaves
the previously healthy backend available.
The already validated isolated command is canonicalized into the same durable
operation directory before downtime, so later broker requests cannot select a
different image, model path, model digest, or executable by replacing the
operator input file.

The gate then creates one private host broker socket and one one-shot worker
container. The socket inode is mode `0666` only because rootless container UID
mapping is deployment-specific; its host parent is a newly created mode-`0700`
directory and Docker bind-mounts only that exact socket inode into the one
verified worker. The socket is not a general host API and is removed after the
run. A broker watchdog terminates the broker if its parent gate disappears,
including while one request is in progress.

The one-shot worker:

- uses the backend's exact inspected `sha256:` image ID with pulls disabled;
- runs as `10001:10001` with a read-only root, network and IPC mode `none`, all
  capabilities dropped, no-new-privileges, bounded CPU/memory/PIDs/files, a
  noexec scratch tmpfs, no retained log driver, and an init process;
- mounts the deployment state volume read-write with `volume-nocopy`;
- mounts only the public config, administrator secret, generated adapter
  command, and private bridge socket read-only; and
- never receives a Docker socket, host path to state, model path, provider
  credential, or processor image authority.

The existing adapter still claims the live lease, revalidates state and
retention, opens only admitted evidence read-only, and creates the canonical
input. Its bridge client validates that canonical input and transfers the
already-open input/evidence capabilities over the Unix socket with
`SCM_RIGHTS`. The request body contains only the closed contract version and
the descriptor numbers that must be recreated; recording, diagnostic,
transcript, configuration, and secret bytes are not serialized through the
socket.

The trusted host broker revalidates the stored source manifest and its journal
digest before binding the socket. It accepts at most the selected stage bound, requires
unique descriptors from 3 through 1023, verifies every received capability is
one read-only regular file, maps them to the exact numbers sealed into the
input, and invokes the unchanged `run_isolated_processor.py` boundary. The
selected processor therefore retains ADR-016's rootless-Docker preflight,
network-none container, dedicated UID, read-only payload volume, digest-bound
model/evidence copy, resource budgets, attached-output validation, stale
recovery, and host-exclusive runner lock. Neither the worker nor selected
processor gains Docker control.

The broker returns only the runner-validated canonical result plus sorted,
safe-name preview files under the existing 16 MiB/512-file/64 MiB bounds.
Every body is length- and SHA-256-bound. The client verifies the complete
response and stages every preview before publishing each by atomic rename into
the adapter's private output directory. If any rename fails, it removes all
staged and already-published previews before returning failure. The adapter
then repeats its authoritative candidate/evidence validation and existing
atomic processing-result publication.

After the worker exits, the gate removes and verifies release of the one-shot
container, re-verifies state through a second journal-bound verifier, starts
the same backend container, waits
for its existing health check, and runs loopback authenticated smoke. If a
worker may have touched state, automatic restart is permitted only after that
post-run verifier succeeds and the original backend is again the sole
state-volume consumer. If no worker started, recovery may remove any
interrupted read-only verifier and restart the exact backend that was proven
healthy before downtime without making another offline database copy. The
same binding, sole-consumer, health, and authenticated-smoke checks still
apply. The recovery obligation is cleared only after health and smoke, not
after the start command returns. Failed automatic recovery is a distinct
stable critical error and is never swallowed; the backend then remains stopped
or running-but-unverified for operator recovery. `SIGHUP`, `SIGINT`, and
`SIGTERM` before journaling leave at most a journal-free snapshot; after
journaling they enter the normal recovery path. `SIGKILL`, host loss, or a
second cleanup failure leaves the journal. The explicit, idempotent `recover`
action validates and re-executes the stored source snapshot before local
imports or Docker mutation, revalidates its exact deployment bindings, removes
at most one exact label-bound worker and verifier, retires the parent-watched
socket, conditionally verifies state when a worker may have started, and
restarts and smokes the original backend. It removes the durable directory
only after that entire obligation succeeds. A killed selected processor may
separately leave only the ADR-016 labeled processor recovery artifacts, which
the next authorized isolated-runner invocation handles.

The adapter's 240-second per-stage parent timeout remains the global outer
bound. Each bridge socket operation uses a 225-second inactivity timeout; that
socket setting is not itself a whole-request deadline. The isolated runner
retains its 180-second work and 210-second hard-cleanup budgets. Bounded drain
repeats this one-stage path; it does not create an unattended scheduler.

## Consequences

- The authoritative state volume is never copied, imported, merged, or
  addressed through Docker's private host mountpoint.
- Docker authority remains in a trusted host process. The backend, one-shot
  worker, and selected processor never receive the daemon socket.
- Backend downtime covers pre-verification, every selected stage,
  post-verification, restart, and smoke. This is accepted for the single-owner
  V1 pilot.
- Operators must retain the backend image, config/secret identities, verified
  source snapshot, operation journal, and a current recovery bundle until the
  operation clears. A changed checkout is not imported by an in-flight parent,
  broker, or journaled recovery.
- `tacua.compose-source-manifest@1.0.0` is an in-flight recovery format. Future
  launchers must keep a compatible pre-import reader until every operation of
  that version is recovered or deliberately migrated.
- Unix-domain descriptor passing and a rootless Linux Docker host are required
  for this path. Other container engines or remote daemons are not claimed
  compatible.
- The backend image now includes the small trusted bridge client. This is an
  image-boundary change and remains covered by the closed image-input
  validator.
- No processor image, model, transcription implementation, ticket-generation
  implementation, connector, egress grant, or automatic processing schedule
  is selected by this decision.

## Rejected alternatives

- **Mount the Docker socket in the one-shot worker:** grants host control to a
  container holding state and the administrator secret.
- **Run both worker and isolated runner in one container:** either loses
  Docker authority or recreates the same forbidden socket mount.
- **Copy state out, process it, and copy it back:** creates a crash-vulnerable
  database/object-store replacement and a second retention-scoped evidence
  copy.
- **Open Docker's volume mountpoint from the host:** relies on daemon-private
  paths and rootless UID mappings outside the Compose and backup contracts.
- **Expose a network result-submission endpoint:** adds authentication,
  replay, egress, and untrusted-worker boundaries unnecessary on one host.
- **Pass evidence bodies as JSON/base64 over the bridge:** duplicates up to
  4 GiB of evidence and weakens the existing descriptor-capability boundary.
