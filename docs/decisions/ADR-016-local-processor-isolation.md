# ADR-016: Isolate the V1 private-pilot local processor

- Status: accepted
- Date: 2026-07-22
- Scope: Tacua V1 mini-PC/private-pilot processing

## Context

Tacua's shell-free local adapter narrows input and output, but its direct child
runs under the backend UID. That is appropriate for trusted adapter glue, not
for an operator-selected model binary or plugin. A model process must not gain
the backend database, evidence tree, administrator secret, Docker socket,
provider credentials, host network, or unbounded access to mini-PC resources.
The repository must establish this boundary without selecting or downloading a
model, processor image, executable, connector, or provider.

## Decision

The accepted V1 private-pilot execution path is the host-side
`run_isolated_processor.py` gate plus the matching opt-in
`compose.processor.yaml` `private-pilot` profile. Normal backend startup stays
inert. The direct same-UID adapter remains available only for trusted Tacua
boundary code; it is not an approved model/plugin sandbox.

An operator must explicitly provide all of the following in a canonical closed
command document:

- a preloaded repository-digest-pinned processor image or exact local image ID;
- one exact absolute executable and shell-free argument vector;
- one explicit model ID, absolute regular model file, and matching SHA-256;
- the exact input and model placeholders; and
- a container runtime limit from one through 150 seconds.

There is no default image, command, or model, and image pulling is disabled in
the Compose profile. The gate copies only the already bounded evidence exposed
through the adapter's inherited read-only descriptors into a short-lived input
bundle. It verifies the original input digest, preserves it as
`source_input_digest`, rewrites only descriptor paths, and seals the isolated
bundle while rehashing each evidence copy against its declared content digest.
The runner reopens the resolved model without following the final path
component, copies and hashes at most 8 GiB, and rejects any mismatch. It creates
a mode-`0700` empty staging root and immediately creates a randomized labeled
local volume plus stopped carrier and final-processor recovery containers before
placing any evidence or model bytes there. The carrier is never started and has
an inert nonexistent entrypoint; its writable root and sole RW volume mount are
used only by the trusted archive upload API.
The final processor has a read-only root and mounts the same volume RO with
`volume-nocopy`. No host path is bound. After transfer the runner re-inspects
the carrier and volume to prove the carrier is still in its exact never-started
state. The host payload and stopped carrier are then removed and the carrier is
verified absent before the final entrypoint starts. There is no writable output
mount. The selected executable emits exactly one canonical
`tacua.isolated-processing-output@1.0.0` JSON envelope on stdout: one result
object plus its SHA-256 and an ordered list of safe-name previews whose
canonical base64, decoded size, and SHA-256 are bound. Envelope preview entries
must be exactly the unique `body_file` set referenced by the result;
missing or unreferenced bodies are rejected. The runner reads attached
stdout/stderr incrementally while the container is running, kills on the
absolute deadline or stream cap, and validates exact exit/OOM state before
accepting anything. Preview publication occurs atomically only after the whole
envelope and all decoded bytes validate.

The processor container is UID/GID `10002:10002`, distinct from backend
`10001:10001`. It has network mode `none`, a read-only root, default seccomp,
all capabilities dropped, no-new-privileges, no Docker socket, no secret or
config mounts, and no devices. Before creation, the runner explicitly disables
image healthchecks and rejects an image that declares a health command,
implicit volumes, or environment keys beyond locale/PATH, then overrides
locale/PATH and adds only the non-secret model ID; ordinary container runtime
metadata such as hostname is not claimed absent. Before stale recovery or image
inspection, the runner fails closed unless `docker info` proves a rootless
daemon using cgroup v2 with the systemd driver, effective CPU quota, memory and
PID controls, and builtin default seccomp. Limits are two
CPUs, 4 GiB memory with no extra swap, 64 PIDs, 1,024 file descriptors, a
150-second container limit, 256 MiB noexec scratch tmpfs, a 110 MiB attached
transport cap, 64 MiB decoded result/preview aggregate, 16 MiB canonical result,
and 512 evidence files / 4 GiB evidence bytes. The whole runner stops normal work by 180 seconds and finishes bounded
kill/removal by 210 seconds. The ordinary adapter must enforce exactly 240
seconds and exports that actual value to the runner, leaving a 30-second margin
before its process-group kill.

Every carrier, processor, and payload volume carries closed Tacua contract,
instance, staging, role and deadline identity. At the start of the next
authorized run, the gate lists only artifacts with both contract labels and
validates the exact never-started carrier-RW/final-RO volume relationship plus
required no-network and no-host-bind shape and the final processor's read-only
root. It kills and confirms each
container stopped, removes label-bound host staging while a recovery artifact
still exists, removes containers, then removes the sensitive volume last.
Volume-only partial phases remain recoverable; failure to remove staging retains
all artifacts. A malformed match fails closed.

V1 processing is serialized per host. Before stale discovery, the runner takes
a nonblocking advisory `flock` on one fixed mode-`0600`, runner-owned regular
file and holds it through all container and staging cleanup. Process death
releases the lock. An overlapping invocation returns
`PROCESSOR_RUNNER_BUSY` before it can classify or reap any container.

The exclusive worker runs on the trusted host while the HTTP service is stopped
so the runner may operate the host container runtime without ever mounting its
socket into either Tacua container. The Compose profile is a topology and
preflight artifact; direct `docker compose up` is not an approved substitute
for the runner's descriptor translation, model digest check, time kill, and
bounded output retrieval.

## Consequences

- A selected model/plugin is separated from backend state, identity, secrets,
  network, Docker control plane, and unbounded host resources.
- Evidence is briefly copied under a private host directory to cross the
  descriptor-to-container boundary and into a randomized local Docker volume,
  then the host copy is removed before processor start. The volume contains
  only already bounded input and is mounted RO by the processor, but the local
  volume driver has no independent quota. This creates no provider or network
  copy and remains subject to the session retention lock.
- The verified model is also copied into that temporary bundle, eliminating a
  hash race and making restrictive operator file modes compatible with the
  dedicated non-root processor identity at the cost of temporary host disk and
  a pre-start Docker copy.
- The synthetic Docker gate proves UID `10002`, exact created/running inspect
  state, attached-envelope transport, container restrictions, and final-running
  interruption recovery in a daemon that passes the rootless/cgroup/seccomp
  preflight. Carrier-only, post-copy, malformed-output, and cleanup crash phases
  are deterministic unit regressions rather than separate real-Docker kills.
- The selected processor image, model provenance, host container runtime,
  kernel, operator account, and real workload still require deployment review.
- An external provider remains a new credential, destination, retention, and
  egress decision; this ADR grants none.

## Rejected alternatives

- **Run the model as the backend UID:** same-UID filesystem discovery and
  resource exhaustion are not an isolation boundary.
- **Mount the Docker socket into the backend or processor:** socket access is
  effectively host control and would defeat the sandbox.
- **Bind a writable host output directory or copy a stopped tmpfs:** a host bind
  permits pre-validation disk exhaustion, while tmpfs contents disappear on
  stop and are not a valid post-exit copy channel. Output therefore travels
  through the incrementally capped attached stdout envelope while the processor
  is alive.
- **Bundle a sample model or mutable image tag:** silently chooses supply-chain
  and licensing inputs that belong to the operator.
- **Enable network for convenience:** V1 local processing is offline by
  default; any destination requires a separate reviewed egress design.
