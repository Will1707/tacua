# Compose isolated-processing runbook

This runbook advances queued work in one checked-in Compose deployment without
copying its state volume or mounting the Docker socket into a Tacua container.
It implements
[ADR-020](../../docs/decisions/ADR-020-compose-state-processing-bridge.md) on
top of the existing [ADR-016 isolation gate](PROCESSING_ADAPTER.md).

This is an exclusive, operator-triggered maintenance action. The backend is
unavailable while it runs. It does not select a processor image, model,
transcriber, LLM, connector, or egress grant, and it does not enable an
automatic scheduler.

## Preconditions

Start from the exact checkout from which the running backend image was built
and use the exact Compose files that started the deployment. Before importing
backend code or touching Docker, the CLI takes the project lock, copies the
closed bridge source boundary into an owner-only durable snapshot, fsyncs it,
and re-executes that snapshot under Python isolated mode. The boundary contains
both runner scripts, every backend Python module, and every Python/schema file
copied from the approved-handoff, runtime, SDK/backend-protocol, and
ticket-candidate contracts. The verified child independently enumerates the
same boundary inside the exact running image with network disabled and refuses
downtime unless both the path sets and digests match.

Retain the running image, config, secret, operation parent, and recovery bundle
until every durable operation has cleared. Once the snapshot is published,
later parent, broker, and recovery execution comes from it rather than the
current checkout.
`tacua.compose-source-manifest@1.0.0` is a recovery format, not merely a build
artifact. A future bridge release must keep a compatible bootstrap reader for
that format until every V1 operation has been recovered or explicitly
migrated; changing the live inventory constants alone must not strand an older
operation before its stored launcher can execute.

The running backend must be healthy and the only container that references its
named state volume. Create and verify a current recovery bundle before every
maintenance window. The host must satisfy the rootless Docker, cgroup v2,
systemd cgroup-driver, resource-controller, and default-seccomp checks in [the
processing adapter runbook](PROCESSING_ADAPTER.md).
Its hard `RLIMIT_NOFILE` must exceed `2562`; the gate raises the inherited soft
limit to at most `4096` and fails with `BRIDGE_DESCRIPTOR_LIMIT` before
downtime when the hard limit cannot carry the closed 513-file request bound.

Before downtime, the gate checks the combined size of `tacua.sqlite3` and
`tacua.sqlite3-wal` inside the exact running backend and accepts at most
512 MiB. This check emits only a content-free bound result. Exceeding the
ceiling fails closed while the previously healthy backend remains running.
The offline verifier then copies those stopped files only into a dedicated
1 GiB noexec `/tmp` tmpfs inside a 4 GiB, no-swap container. The gate
explicitly overrides and exact-inspects `TMPDIR=/tmp` so verifier scratch can
never use the authoritative state volume. A deployment approaching the
512 MiB database-plus-WAL ceiling must be compacted or moved to a reviewed
larger profile before this maintenance path is used.

Keep all recording, model, command, config, secret, and processor details off
shared terminals and out of the repository. The generated bridge command and
socket contain no provider credential, but their durable operation directory
is still owner-only. It must survive process termination and host restart until
the bridge removes it after verified recovery.

Resolve the deployment model in a private directory. This example uses the
production override; use the exact files that created the running deployment:

```bash
set -euo pipefail
project='tacua'
umask 077
runtime_directory="$(mktemp -d "${TMPDIR:-/tmp}/tacua-processing.XXXXXX")"
chmod 0700 "$runtime_directory"
trap 'rm -rf -- "$runtime_directory"' EXIT HUP INT TERM
operation_parent="${XDG_STATE_HOME:-$HOME/.local/state}/tacua"
install -d -m 0700 "$operation_parent"
operation_parent="$(cd "$operation_parent" && pwd -P)"

docker compose -p "$project" \
  -f services/backend/compose.yaml \
  -f services/backend/compose.production.yaml \
  config --format json > "$runtime_directory/compose.json"
chmod 0600 "$runtime_directory/compose.json"

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json"
```

Do not delete or regenerate `compose.json` while the bridge is running. Do not
delete anything below `operation_parent`; the gate exclusively owns one
`tacua-compose-processing-<project>` child. That child contains the verified
source and source manifest, journal, resolved Compose snapshot, and canonical
isolated command. The gate binds later Docker actions to its project, backend
container, exact running image ID, source digest, original
repository/build-context root, and state volume. Changing the checkout or
supplied command after publication cannot change the parent or broker code,
selected image, model digest, or executable.

## Select and verify the isolated processor

Create the mode-`0600`, operator-owned canonical isolated command described in
[PROCESSING_ADAPTER.md](PROCESSING_ADAPTER.md). It must identify one preloaded
immutable image or exact local image ID, one absolute executable, one regular
model file and exact SHA-256, one model ID, and a timeout no longer than 150
seconds. The repository provides no default.

Resolve and verify the matching topology before processing:

```bash
TACUA_PROCESSOR_IMAGE='operator.example/processor@sha256:…' \
TACUA_PROCESSOR_MODEL_ID='operator-selected-model-id' \
TACUA_PROCESSOR_EXECUTABLE='/absolute/executable/in/image' \
docker compose -f services/backend/compose.processor.yaml \
  --profile private-pilot config --format json \
  > "$runtime_directory/processor-compose.json"
chmod 0600 "$runtime_directory/processor-compose.json"

python3 services/backend/scripts/verify_isolated_processor_profile.py \
  "$runtime_directory/processor-compose.json"
```

The profile is a verification artifact, not an execution command. Never use
`docker compose up` for the processor. The host bridge invokes only the
existing isolated runner, which creates and verifies its randomized
carrier/volume/final-container transaction.

## Run one stage

Run from the repository root and keep the terminal attached:

```bash
python3 -B services/backend/scripts/run_compose_isolated_processing.py \
  --project "$project" \
  --compose-json "$runtime_directory/compose.json" \
  --operation-directory "$operation_parent" \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --isolated-command-file /absolute/operator/path/isolated-command.json \
  --worker-id worker_private_pilot \
  --run-once
```

The unverified launcher only takes the project lock, publishes the bounded
source snapshot, and atomically re-executes it. The verified child validates
the processor selection, repeats the rootless-runtime preflight, checks the
descriptor limit, and proves the database-plus-WAL copy bound before stopping
the backend. Before downtime it fsyncs a digest-sealed journal binding the
exact backend, image, state volume, source bundle, original repository root,
Compose snapshot, config/secret identities, worker settings, and lifecycle
phase.

It then stops only `backend`; creates, journals, and exact-inspects a uniquely
named label-bound offline verifier; starts a parent-watched private host broker
from the same source snapshot; creates and exact-inspects the one-shot state
worker; processes at most one stage; runs a second journaled verifier; restarts
the same backend; waits for health; and runs authenticated loopback smoke.
Verifiers have no network or Docker socket. After forced removal, one exact
role/name/ID discovery pass must report them absent. Stdout is one content-free
canonical summary. Errors print one stable code only.

Each verifier or worker creation uses a deterministic fork-and-pipe
coordinator. The coordinator child inherits the project `flock` and blocks on
the private pipe before it can call `docker container create`. The parent
first fsyncs the exact random name and `creating` phase into the journal, then
releases the child. Before exiting, the child atomically publishes and
directory-fsyncs one mode-`0600`, digest-sealed, content-free create receipt
bound to the project, role, purpose, and name. Its outcome is exactly:

- `created`, with the exact returned container ID;
- `not_started`, proving the pipe was never released and Docker create was not
  called; or
- `indeterminate`, proving create was authorized but its exact result was not
  established.

The parent reaps the child before releasing its copy of the project lock. If
the parent dies, the inherited lock prevents `recover` from entering while the
child is still completing and publishing its receipt.

The one-shot worker has one private application socket mount. It has no Docker
socket, network, state host path, model path, provider credential, or
processor-image setting. Do not add any of those mounts or environment
variables.

## Drain with an explicit bound

Use bounded drain only when the selected processor implements every stage it
will encounter:

```bash
python3 -B services/backend/scripts/run_compose_isolated_processing.py \
  --project "$project" \
  --compose-json "$runtime_directory/compose.json" \
  --operation-directory "$operation_parent" \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --isolated-command-file /absolute/operator/path/isolated-command.json \
  --worker-id worker_private_pilot \
  --drain \
  --max-stages 10
```

Production completion currently creates legacy pipeline-1.0 jobs. The default
adapter command therefore stays
`tacua.local-processing-command@1.0.0`. The explicit
`--adapter-contract tacua.local-processing-command@1.1.0` option exists only
for the dormant transcript/align artifact slice described in
[ADR-019](../../docs/decisions/ADR-019-processing-artifact-consumption.md); it
does not enable pipeline 1.1 or allow processing past its deliberate pause.

`--allow-mutable-image` relaxes only the existing deployment preflight for the
local test Compose model. The gate still binds the worker to the exact
inspected `sha256:` image ID of the running backend and disables pulls. Do not
use that option for a production deployment.

## Failure and recovery

`SIGHUP`, `SIGINT`, and `SIGTERM` become a stable cancellation. Before the
deployment journal exists, cancellation releases the project lock and leaves
at most a bounded journal-free source snapshot for explicit `recover`. After the
verified runtime begins, cancellation runs the same cleanup and recovery path
as an ordinary failure. The detached broker independently watches its parent
and exits immediately if the parent disappears. `SIGKILL`, host loss, daemon
loss, or a second failure during cleanup can still interrupt that path; the
durable journal then makes the unfinished obligation explicit.

The gate restarts automatically after an unsuccessful processing attempt only
when:

- the original backend is the sole remaining state-volume consumer; and
- the offline state verifier succeeds after any worker that may have opened
  state.

The backend was required to be healthy before downtime. If the worker never
started, recovery may remove an interrupted read-only verifier and restart that
exact backend without another offline database copy. It still revalidates the
deployment bindings and sole-consumer invariant, waits for health, and runs
authenticated smoke. Once a worker may have started, successful post-worker
offline verification remains mandatory before restart.

If the command returns `BRIDGE_RECOVERY_REQUIRED`,
`BRIDGE_RECOVERY_FAILED`, or `BRIDGE_CLEANUP_FAILED`, or if it was killed
without returning, do not start a new processing run and do not bypass the gate
with an unconditional `docker compose start`. Keep the image, volume,
containers, config, secret, verified source snapshot, and operation directory.
Run:

```bash
python3 -B services/backend/scripts/run_compose_isolated_processing.py \
  recover \
  --project "$project" \
  --operation-directory "$operation_parent" \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret
```

For a journaled operation, the recovery launcher takes the same project lock,
validates the stored source manifest, and re-executes that source before
importing backend code or issuing Docker commands. Verified recovery validates
the journal and snapshots, proves config/secret identities and image
provenance, and reconciles each `creating` phase with its durable create
receipt plus one direct discovery pass over the exact role, name, and ID. It
never treats elapsed time or repeated absence as proof that create did not
run. A matching `not_started` receipt plus an absent candidate proves Docker
was not called. A matching `created` receipt supplies the exact durable ID.
If the receipt is missing, torn, mismatched, or `indeterminate` while the exact
candidate is absent, recovery retains every artifact and fails closed.

An exact candidate must pass the full worker or verifier inspection before
forced removal. One exact post-removal role/name/ID discovery pass must then
prove absence; a query error, disagreement, or remaining identity leaves the
journal intact. Only after the corresponding journal phase is retired may the
receipt be removed. Recovery then retires the broker socket and, if a worker
may have started, verifies state in a fresh journaled verifier. It restarts the
exact backend, waits for health, and runs authenticated smoke. It is
restartable: another interruption leaves the journal for the next `recover`.
A crash before the initial journal has no deployment side effect; recovery
removes only the bounded partial snapshot and operation directory after
proving that no labeled worker or verifier exists.

If offline state verification fails, stop and restore the complete verified
recovery bundle by the procedure in [OPERATIONS.md](OPERATIONS.md). Never copy
individual SQLite, WAL, object, or derived-evidence files.

The recovery obligation remains active until the exact backend is healthy and
authenticated loopback smoke succeeds; a successful `docker compose start`
alone does not clear it. `BRIDGE_RECOVERY_FAILED` means automatic
state/consumer verification, restart, health, or smoke did not complete and
requires immediate operator recovery. `BRIDGE_CLEANUP_FAILED` means the
broker, one-shot worker, offline verifier, durable operation directory, or host
lock could not be proven cleaned up while recovery evidence still remains.
Neither critical code is suppressed by the earlier processing error. Never
manually delete the journal to clear either code.

After verified backend health and smoke, cleanup unlinks and directory-fsyncs
the journal before removing the immutable source snapshot and other
non-recovery artifacts. An interruption after that commit can therefore leave
only a journal-free partial directory, which `recover` may remove without
touching the deployment. The project lock stays held through directory
removal. If its explicit unlock reports an error only after that removal
commits, process exit still closes the descriptor and the bridge does not
invent a new recovery obligation after deleting its evidence.

A killed selected-processor run can leave only label-bound ADR-016 carrier,
processor, payload-volume, or private staging recovery artifacts. The next
authorized isolated-runner invocation performs its existing fail-closed stale
recovery. Do not remove similarly named Docker resources by pattern.

After a successful run, optionally perform the configured exact-origin smoke
from a device-representative network. The gate's built-in smoke is deliberately
loopback-only so processor maintenance does not alter TLS, DNS, tailnet, or
reverse-proxy configuration.

When finished:

```bash
rm -rf -- "$runtime_directory"
trap - EXIT HUP INT TERM
unset runtime_directory
```

This removal covers only the operator-created preflight documents. A successful
run or `recover` has already removed the project-specific durable operation
directory and one-shot worker. The parent directory remains for later runs.
The bridge does not delete jobs, candidates, evidence, the deployment state
volume, processor model, recovery bundle, or ADR-016 recovery artifacts.
